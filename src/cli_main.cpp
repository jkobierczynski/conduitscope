// SPDX-License-Identifier: MIT
// cli_main.cpp - command-line interface, built on the vendored CLI11 header.
//
// See docs/MANUAL.md for the full option reference; --help at any level
// (top-level, `decode --help`, `policy validate --help`, ...) is generated
// from the same option definitions below, so the two should never drift
// far apart -- but the manual also explains the *why* behind choices like
// the protocol-detection heuristics, which --help intentionally keeps brief.
#include <CLI11.hpp>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/live_capture.hpp"
#include "conduitscope/output.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"
#include "conduitscope/version.hpp"

namespace {

using namespace conduitscope;

// --------------------------------------------------------------------------------------------
// Live capture plumbing shared by `decode -i` and `policy validate -i`. See live_capture.hpp for
// LiveCapture itself; everything below is CLI-layer glue that lets run_decode/run_policy_validate
// treat an offline pcap file and a live interface as the same kind of packet source, and lets
// Ctrl+C stop a live capture cleanly (finishing the report/summary with whatever was captured so
// far) instead of the process just dying mid-capture.
// --------------------------------------------------------------------------------------------

// Owns exactly one of a PcapReader (offline file) or a LiveCapture (live interface) and forwards
// the small bit of interface run_decode/run_policy_validate actually need from either.
class PacketSource {
public:
    explicit PacketSource(std::unique_ptr<PcapReader> reader) : reader_(std::move(reader)) {}
    explicit PacketSource(std::unique_ptr<LiveCapture> capture) : capture_(std::move(capture)) {}

    PacketSource(const PacketSource&) = delete;
    PacketSource& operator=(const PacketSource&) = delete;
    PacketSource(PacketSource&&) = default;
    PacketSource& operator=(PacketSource&&) = default;

    bool next(PcapPacket& out) { return reader_ ? reader_->next(out) : capture_->next(out); }
    uint32_t linktype() const { return reader_ ? reader_->info().linktype : capture_->info().linktype; }
    // Non-null only when this source is a live capture; used by SigintGuard below. Never call
    // anything on it except stop() from a signal handler.
    LiveCapture* live_ptr() const { return capture_.get(); }

private:
    std::unique_ptr<PcapReader> reader_;
    std::unique_ptr<LiveCapture> capture_;
};

std::atomic<LiveCapture*> g_active_capture{nullptr};
// Counts SIGINT handler invocations currently in progress (0 or 1 on POSIX, since a signal only
// ever interrupts the thread it was delivered to and can't re-enter while already running there;
// see below for why it can briefly be more on Windows). SigintGuard's destructor spin-waits on
// this before letting the guarded LiveCapture be destroyed -- see its own comment for why that
// matters.
std::atomic<int> g_handler_in_flight{0};

extern "C" void handle_sigint(int) {
    g_handler_in_flight.fetch_add(1, std::memory_order_acquire);
    LiveCapture* capture = g_active_capture.load();
    if (capture != nullptr) capture->stop();
    g_handler_in_flight.fetch_sub(1, std::memory_order_release);
}

// RAII guard: while alive, redirects SIGINT (Ctrl+C) to LiveCapture::stop() on `capture` instead
// of the platform default (immediate process termination), so a live capture stops cleanly and
// still prints whatever report/summary it had. A no-op when `capture` is null (offline-file mode
// doesn't need this -- EOF already stops the loop on its own).
//
// Safety note (why this is more than just std::signal() + a flag): on POSIX, a signal handler
// only ever interrupts the same thread that was running when it was delivered -- it can't run
// concurrently with anything else in the process, so restoring the old handler and clearing
// g_active_capture before this guard's LiveCapture is destroyed is enough on its own. Windows'
// console Ctrl+C handling does NOT give that guarantee: per Microsoft's own documentation, a
// CTRL+C interrupt is delivered by spinning up a *new thread* to run the handler, which can
// therefore execute genuinely concurrently with the main thread -- including with this
// destructor tearing down the very LiveCapture the handler is about to call stop() on, which
// would be a real use-after-free race without the g_handler_in_flight wait below. The wait is
// harmless on POSIX (it can only ever see 0, since nothing there can be "in flight" concurrently
// with this destructor) and closes the real race on Windows.
class SigintGuard {
public:
    explicit SigintGuard(LiveCapture* capture) : active_(capture != nullptr) {
        if (active_) {
            g_active_capture.store(capture);
            previous_handler_ = std::signal(SIGINT, handle_sigint);
        }
    }
    ~SigintGuard() {
        if (active_) {
            std::signal(SIGINT, previous_handler_);
            g_active_capture.store(nullptr);
            while (g_handler_in_flight.load(std::memory_order_acquire) > 0) {
                std::this_thread::yield();
            }
        }
    }
    SigintGuard(const SigintGuard&) = delete;
    SigintGuard& operator=(const SigintGuard&) = delete;

private:
    bool active_;
    void (*previous_handler_)(int) = SIG_DFL;
};

// Shared by run_decode/run_policy_validate: exactly one of `input` (offline pcap file, already
// validated to exist by CLI11's ->check(CLI::ExistingFile)) or `interface_name` (live capture) is
// expected to be non-empty -- enforced in main() before either run_* function is called, via
// ->excludes() plus the post-parse "exactly one" check. Throws whatever PcapReader's constructor /
// LiveCapture's constructor throws (ParseError / CaptureError respectively) on failure.
PacketSource open_packet_source(const std::string& input, const std::string& interface_name,
                                 int snaplen, bool promiscuous, const std::string& filter,
                                 int duration_seconds, size_t max_packets) {
    if (!interface_name.empty()) {
        return PacketSource(std::make_unique<LiveCapture>(interface_name, snaplen, promiscuous,
                                                            filter, duration_seconds, max_packets));
    }
    return PacketSource(std::make_unique<PcapReader>(input));
}

std::string link_type_name(uint32_t linktype) {
    switch (linktype) {
        case LINKTYPE_ETHERNET: return "Ethernet";
        case LINKTYPE_RAW: return "Raw IP (no link-layer header)";
        default: return "unsupported/unknown (" + std::to_string(linktype) + ")";
    }
}

std::string version_string() {
    return std::string(kVersion) + "  [" + kCompilerId + ", " + kSystemName + ", " + kBuildType +
           " build, live capture: " + (live_capture_available() ? "libpcap/Npcap" : "not built in") + "]";
}

int run_decode(const std::string& input, const std::string& interface_name, const std::string& filter,
                int duration_seconds, int snaplen, bool promiscuous, const std::string& output,
                const std::string& format, const std::string& protocol, const std::vector<int>& modbus_ports,
                const std::vector<int>& dnp3_ports, const std::vector<int>& s7comm_ports,
                size_t max_packets, bool stats, bool strict, bool quiet, bool no_color, bool force_color,
                std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    DecodeOptions options;
    options.strict = strict;
    options.protocol_filter = (protocol == "modbus")  ? ProtocolFilter::ModbusOnly
                               : (protocol == "dnp3")  ? ProtocolFilter::Dnp3Only
                               : (protocol == "s7comm") ? ProtocolFilter::S7commOnly
                                                        : ProtocolFilter::Auto;
    for (int p : modbus_ports) options.extra_modbus_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dnp3_ports) options.extra_dnp3_ports.push_back(static_cast<uint16_t>(p));
    for (int p : s7comm_ports) options.extra_s7comm_ports.push_back(static_cast<uint16_t>(p));

    try {
        PacketSource source = open_packet_source(input, interface_name, snaplen, promiscuous, filter,
                                                   duration_seconds, max_packets);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);

        std::unique_ptr<OutputWriter> writer;
        StatsWriter stats_writer;
        if (!stats) {
            if (format == "json") writer = std::make_unique<JsonWriter>(*out);
            else if (format == "csv") writer = std::make_unique<CsvWriter>(*out);
            else writer = std::make_unique<TextWriter>(*out, color);
            writer->begin();
        }

        PcapPacket pkt;
        size_t index = 0, decoded_count = 0, warnings = 0;
        while (source.next(pkt)) {
            ++index;
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            if (stats) stats_writer.write_packet(dp);
            else writer->write_packet(dp);
            ++decoded_count;
            if (max_packets != 0 && decoded_count >= max_packets) break;
        }

        if (stats) stats_writer.print_summary(*out);
        else writer->end();

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << decoded_count
                 << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int run_info(const std::string& input, std::ostream& out) {
    try {
        PcapReader reader(input);
        Decoder decoder(DecodeOptions{});
        StatsWriter stats_writer;

        PcapPacket pkt;
        size_t index = 0;
        while (reader.next(pkt)) {
            ++index;
            stats_writer.write_packet(decoder.decode(pkt, reader.info().linktype, index));
        }

        const auto& info = reader.info();
        out << "file:           " << input << "\n";
        out << "pcap version:   " << info.version_major << "." << info.version_minor << "\n";
        out << "link type:      " << link_type_name(info.linktype) << "\n";
        out << "snaplen:        " << info.snaplen << " bytes\n";
        out << "timestamps:     " << (info.nanosecond_ts ? "nanosecond" : "microsecond") << " resolution\n";
        stats_writer.print_summary(out);
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// Exit codes specific to `policy validate` (see man/conduitscope.1's EXIT STATUS and
// docs/MANUAL.md): 0 = compliant (every observed flow was explicitly allowed by a conduit), 1 =
// fatal error (bad arguments, an unreadable/malformed policy or capture file, or a --strict parse
// failure -- same meaning as run_decode's exit 1), 3 = the capture is readable and the policy is
// valid, but PolicyReport::compliant() is false (at least one violation and/or unclassified flow
// was found). 3, not 2, specifically so a script can tell "ran fine, found problems" (3) apart from
// "couldn't even run" (1) without also colliding with 2, which every other exit-status-checking
// caller of this tool has so far only ever seen mean "no fatal error, but nothing to do" (the
// now-retired `policy validate` stub was the only user of 2; nothing currently returns it, but the
// value is left unclaimed rather than reused, in case a future documented-stub command needs it
// again).
constexpr int kExitPolicyNonCompliant = 3;

int run_policy_validate(const std::string& input, const std::string& interface_name,
                         const std::string& filter, int duration_seconds, int snaplen, bool promiscuous,
                         const std::string& policy_path, const std::string& output, const std::string& format,
                         bool strict, bool quiet, std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        Policy policy = parse_policy_file(policy_path);

        DecodeOptions options;
        options.strict = strict;
        // No --max-packets equivalent for policy validate (matching its existing offline-file
        // CLI surface, which never had one either): a live run here relies on --duration and/or
        // Ctrl+C to stop, same as `decode -i` does when --max-packets is left at its default of 0.
        PacketSource source =
            open_packet_source(input, interface_name, snaplen, promiscuous, filter, duration_seconds, 0);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);
        PolicyEngine engine(policy);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (source.next(pkt)) {
            ++index;
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        // The report's "capture:" line identifies what was checked -- for a live run that's the
        // interface (input is empty in that case, having been mutually exclusive with -i), not a
        // file path.
        std::string capture_label = interface_name.empty() ? input : "live:" + interface_name;
        PolicyReport report = engine.finish();
        if (format == "json") {
            write_policy_report_json(*out, report, policy, capture_label, policy_path);
        } else {
            write_policy_report_text(*out, report, policy, capture_label, policy_path);
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        return report.compliant() ? 0 : kExitPolicyNonCompliant;
    } catch (const PolicyError& e) {
        // e.what() is already "<policy_path>:<line>: <message>" (see policy.cpp's fail()) --
        // no need to prefix the path again here.
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

int run_interfaces(std::ostream& out) {
    try {
        std::vector<InterfaceInfo> interfaces = list_interfaces();
        if (interfaces.empty()) {
            out << "(no interfaces found -- this can mean there genuinely are none, or that "
                   "listing them needs more privilege than this process has; try running as "
                   "root/Administrator)\n";
            return 0;
        }
        for (const auto& iface : interfaces) {
            out << iface.name;
            if (iface.loopback) out << "  [loopback]";
            if (!iface.description.empty()) out << "  -- " << iface.description;
            out << "\n";
        }
        return 0;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"conduitscope decodes Modbus/TCP, DNP3, and S7comm/COTP traffic from offline pcap/"
                  "pcapng captures, as a building block for OT/ICS conduit and zone auditing (IEC 62443 / "
                  "NIS2 workflows).",
                  "conduitscope"};
    app.set_version_flag("--version", version_string());
    app.require_subcommand(1);
    app.footer(
        "Run 'conduitscope <command> --help' for command-specific options, or see docs/MANUAL.md\n"
        "in the source tree for the full reference including output-format examples and the\n"
        "current Roadmap.");

    bool quiet = false;
    bool no_color = false;
    std::string log_file;
    app.add_flag("-q,--quiet", quiet, "Suppress non-essential diagnostic/warning output");
    app.add_flag("--no-color", no_color, "Disable ANSI color in text-format output");
    app.add_option("--log-file", log_file,
                    "Write diagnostic/warning messages to this file instead of stderr");

    // --- decode ---------------------------------------------------------
    auto* decode_cmd =
    std::string decode_input, decode_interface, decode_filter, decode_output;
    int decode_duration = 0;
    int decode_snaplen = 65535;
    bool decode_promiscuous = true;
    std::string decode_format = "text";
    std::string decode_protocol = "auto";
    std::vector<int> decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports;
    size_t decode_max_packets = 0;
    bool decode_stats = false, decode_strict = false;

    auto* decode_input_opt =
        decode_cmd->add_option("-r,--read", decode_input,
                                "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* decode_interface_opt = decode_cmd->add_option(
        "-i,--interface", decode_interface,
        "Capture live from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required");
    decode_input_opt->excludes(decode_interface_opt);
    decode_interface_opt->excludes(decode_input_opt);
    decode_cmd->add_option("--filter", decode_filter,
                            "BPF capture filter (tcpdump syntax), only meaningful with -i");
    decode_cmd->add_option("--duration", decode_duration,
                            "Stop a live capture (-i) after this many seconds (0 = unlimited; stop "
                            "with Ctrl+C or --max-packets instead)")
        ->capture_default_str();
    decode_cmd->add_option("--snaplen", decode_snaplen,
                            "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    decode_cmd->add_flag("!--no-promiscuous", decode_promiscuous,
                          "With -i, don't put the interface into promiscuous mode (by default it "
                          "is, since the main use case -- watching a mirrored/SPAN switch port -- "
                          "needs traffic not addressed to this host)");
    decode_cmd->add_option("-o,--output", decode_output, "Write output here instead of stdout");
    decode_cmd->add_option("-f,--format", decode_format, "Output format: text, json, or csv")
        ->transform(CLI::IsMember({"text", "json", "csv"}))
        ->capture_default_str();
    decode_cmd
        ->add_option("--protocol", decode_protocol,
                      "Restrict decoding to one protocol instead of auto-detecting all of them")
        ->transform(CLI::IsMember({"auto", "modbus", "dnp3", "s7comm"}))
        ->capture_default_str();
    decode_cmd->add_option("--modbus-port", decode_modbus_ports,
                            "Additional TCP port to treat as expected for Modbus (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--dnp3-port", decode_dnp3_ports,
                            "Additional TCP port to treat as expected for DNP3 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--s7comm-port", decode_s7comm_ports,
                            "Additional TCP port to treat as expected for COTP/S7comm (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--max-packets", decode_max_packets,
                            "Stop after decoding this many packets (0 = unlimited)")
        ->capture_default_str();
    decode_cmd->add_flag("--stats", decode_stats,
                          "Print an aggregate summary (protocol/function-code histogram) instead of "
                          "one line per packet; ignores --format");
    decode_cmd->add_flag("--strict", decode_strict,
                          "Abort on the first malformed packet instead of reporting it and continuing");

    // --- info -------------------------------------------------------------
    auto* info_cmd = app.add_subcommand(
        "info", "Print pcap file metadata and a protocol histogram, without full per-packet output");
    std::string info_input;
    info_cmd->add_option("-r,--read", info_input, "Input capture file (classic pcap or pcapng, auto-detected)")
        ->required()
        ->check(CLI::ExistingFile);

    // --- interfaces -----------------------------------------------------------
    auto* interfaces_cmd = app.add_subcommand(
        "interfaces", "List network interfaces available for live capture (-i); requires this "
                       "build to have been compiled with libpcap/Npcap support");

    // --- policy validate ----------------------------------------------------
    auto* policy_cmd =
        app.add_subcommand("policy", "Zone/conduit compliance checking against a policy file");
    auto* policy_validate_cmd = policy_cmd->add_subcommand(
        "validate", "Check decoded traffic against a zone/conduit policy file");
    std::string policy_input, policy_interface, policy_filter, policy_file, policy_output;
    int policy_duration = 0;
    int policy_snaplen = 65535;
    bool policy_promiscuous = true;
    std::string policy_format = "text";
    bool policy_strict = false;
    auto* policy_input_opt =
        policy_validate_cmd->add_option("-r,--read", policy_input,
                                         "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* policy_interface_opt = policy_validate_cmd->add_option(
        "-i,--interface", policy_interface,
        "Check live traffic from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required");
    policy_input_opt->excludes(policy_interface_opt);
    policy_interface_opt->excludes(policy_input_opt);
    policy_validate_cmd->add_option("--filter", policy_filter,
                                     "BPF capture filter (tcpdump syntax), only meaningful with -i");
    policy_validate_cmd
        ->add_option("--duration", policy_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")
        ->capture_default_str();
    policy_validate_cmd->add_option("--snaplen", policy_snaplen, "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    policy_validate_cmd->add_flag(
        "!--no-promiscuous", policy_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)");
    policy_validate_cmd
        ->add_option("--policy", policy_file,
                      "Zone/conduit policy file (a restricted YAML subset -- see docs/MANUAL.md's "
                      "POLICY FILE FORMAT section)")
        ->required()
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_option("-o,--output", policy_output, "Write the report here instead of stdout");
    policy_validate_cmd->add_option("-f,--format", policy_format, "Report format: text or json")
        ->transform(CLI::IsMember({"text", "json"}))
        ->capture_default_str();
    policy_validate_cmd->add_flag("--strict", policy_strict,
                                   "Abort on the first malformed packet instead of reporting it and continuing");

    // --- version ------------------------------------------------------------
    app.add_subcommand("version", "Print version and build information");

    CLI11_PARSE(app, argc, argv);

    // -r/-i are mutually exclusive (enforced above via ->excludes()) but neither is individually
    // ->required(), since exactly which one is required depends on the other -- CLI11 has no
    // built-in "exactly one of these two plain options" validator, so it's checked by hand here,
    // once parsing has otherwise succeeded, with a message that names both flags.
    if (decode_cmd->parsed() && decode_input.empty() == decode_interface.empty()) {
        std::cerr << "error: 'decode' needs exactly one of -r/--read (an offline capture file) or "
                     "-i/--interface (a live capture interface)\n";
        return 1;
    }
    if (policy_validate_cmd->parsed() && policy_input.empty() == policy_interface.empty()) {
        std::cerr << "error: 'policy validate' needs exactly one of -r/--read (an offline capture "
                     "file) or -i/--interface (a live capture interface)\n";
        return 1;
    }

    std::ofstream log_stream;
    std::ostream* diag = &std::cerr;
    if (!log_file.empty()) {
        log_stream.open(log_file, std::ios::app);
        if (!log_stream) {
            std::cerr << "error: cannot open log file '" << log_file << "'\n";
            return 1;
        }
        diag = &log_stream;
    }

    if (decode_cmd->parsed()) {
        return run_decode(decode_input, decode_interface, decode_filter, decode_duration, decode_snaplen,
                           decode_promiscuous, decode_output, decode_format, decode_protocol,
                           decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_max_packets,
                           decode_stats, decode_strict, quiet, !no_color, *diag);
    }
    if (info_cmd->parsed()) {
        return run_info(info_input, std::cout);
    }
    if (interfaces_cmd->parsed()) {
        return run_interfaces(std::cout);
    }
    if (policy_validate_cmd->parsed()) {
        return run_policy_validate(policy_input, policy_interface, policy_filter, policy_duration, policy_snaplen,
                                    policy_promiscuous, policy_file, policy_output, policy_format, policy_strict,
                                    quiet, *diag);
    }
    if (policy_cmd->parsed()) {
        std::cerr << "error: 'policy' needs a subcommand (currently only 'validate' exists)\n";
        return 1;
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
