// SPDX-License-Identifier: Apache-2.0
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
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#ifdef _WIN32
#include <io.h>
#else
#include <unistd.h>
#endif

#include "conduitscope/asset_inventory.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/live_capture.hpp"
#include "conduitscope/output.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/version.hpp"

namespace {

using namespace conduitscope;

// True when stdout is connected to an interactive terminal rather than a file or a pipe --
// decides whether "auto" colorization (the default, absent --color/--no-color) turns color on.
// POSIX isatty()/fileno() and Windows' underscore-prefixed equivalents do the same thing; which
// one to call is the only platform difference here.
bool stdout_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

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
        case LINKTYPE_CAN_SOCKETCAN: return "Linux SocketCAN (DeviceNet)";
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
                const std::vector<int>& iec104_ports, const std::vector<int>& enip_ports,
                const std::vector<int>& enip_io_ports, const std::vector<int>& bacnet_ports,
                const std::vector<int>& hartip_ports, const std::vector<int>& opcua_ports,
                const std::vector<int>& mqtt_ports, const std::vector<int>& ffhse_ports,
                const std::vector<int>& dns_ports, const std::vector<int>& mdns_ports,
                const std::vector<int>& llmnr_ports, const std::vector<int>& nbns_ports,
                const std::vector<int>& doh_ports, const std::vector<int>& rip_ports,
                const std::vector<int>& hsrp_ports,
                size_t max_packets,
                bool stats, bool strict, bool quiet,
                bool no_color, bool force_color,
                bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                bool service_names_enabled, const std::string& services_path, std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    bool writing_to_stdout = output.empty();
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    // Three-way resolution, same convention as grep/git/ripgrep: --color always wins (even
    // redirected to a file -- e.g. piping through `less -R`, or deliberately saving colored
    // output, are the user's explicit choice), --no-color always disables, and absent either,
    // color is used only when actually writing to an interactive terminal -- never into a file
    // (-o) or a pipe, so ANSI escapes don't end up littering saved/piped output by default.
    bool color = force_color || (!no_color && writing_to_stdout && stdout_is_terminal());

    DecodeOptions options;
    options.strict = strict;
    options.protocol_filter = (protocol == "modbus")  ? ProtocolFilter::ModbusOnly
                               : (protocol == "dnp3")  ? ProtocolFilter::Dnp3Only
                               : (protocol == "s7comm") ? ProtocolFilter::S7commOnly
                               : (protocol == "mms")    ? ProtocolFilter::MmsOnly
                               : (protocol == "iec104") ? ProtocolFilter::Iec104Only
                               : (protocol == "enip")   ? ProtocolFilter::EnipOnly
                               : (protocol == "profinet") ? ProtocolFilter::ProfinetOnly
                               : (protocol == "goose")  ? ProtocolFilter::GooseOnly
                               : (protocol == "sv")     ? ProtocolFilter::SvOnly
                               : (protocol == "ethercat") ? ProtocolFilter::EthercatOnly
                               : (protocol == "stp")    ? ProtocolFilter::StpOnly
                               : (protocol == "devicenet") ? ProtocolFilter::DevicenetOnly
                               : (protocol == "bacnet") ? ProtocolFilter::BacnetOnly
                               : (protocol == "hartip") ? ProtocolFilter::HartIpOnly
                               : (protocol == "opcua")  ? ProtocolFilter::OpcUaOnly
                               : (protocol == "mqtt")   ? ProtocolFilter::MqttOnly
                               : (protocol == "s7comm-plus") ? ProtocolFilter::S7commPlusOnly
                               : (protocol == "ff-hse") ? ProtocolFilter::FfHseOnly
                               : (protocol == "dns")    ? ProtocolFilter::DnsOnly
                               : (protocol == "mdns")   ? ProtocolFilter::MdnsOnly
                               : (protocol == "llmnr")  ? ProtocolFilter::LlmnrOnly
                               : (protocol == "nbns")   ? ProtocolFilter::NbnsOnly
                               : (protocol == "doh")    ? ProtocolFilter::DohOnly
                               : (protocol == "rip")    ? ProtocolFilter::RipOnly
                               : (protocol == "igmp")   ? ProtocolFilter::IgmpOnly
                               : (protocol == "vrrp")   ? ProtocolFilter::VrrpOnly
                               : (protocol == "hsrp")   ? ProtocolFilter::HsrpOnly
                               : (protocol == "igrp")   ? ProtocolFilter::IgrpOnly
                               : (protocol == "pim")    ? ProtocolFilter::PimOnly
                               : (protocol == "eigrp")  ? ProtocolFilter::EigrpOnly
                               : (protocol == "ospf")   ? ProtocolFilter::OspfOnly
                                                        : ProtocolFilter::Auto;
    for (int p : modbus_ports) options.extra_modbus_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dnp3_ports) options.extra_dnp3_ports.push_back(static_cast<uint16_t>(p));
    for (int p : s7comm_ports) options.extra_s7comm_ports.push_back(static_cast<uint16_t>(p));
    for (int p : iec104_ports) options.extra_iec104_ports.push_back(static_cast<uint16_t>(p));
    for (int p : enip_ports) options.extra_enip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : enip_io_ports) options.extra_enip_io_ports.push_back(static_cast<uint16_t>(p));
    for (int p : bacnet_ports) options.extra_bacnet_ports.push_back(static_cast<uint16_t>(p));
    for (int p : hartip_ports) options.extra_hartip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : opcua_ports) options.extra_opcua_ports.push_back(static_cast<uint16_t>(p));
    for (int p : mqtt_ports) options.extra_mqtt_ports.push_back(static_cast<uint16_t>(p));
    for (int p : ffhse_ports) options.extra_ffhse_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dns_ports) options.extra_dns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : mdns_ports) options.extra_mdns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : llmnr_ports) options.extra_llmnr_ports.push_back(static_cast<uint16_t>(p));
    for (int p : nbns_ports) options.extra_nbns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : doh_ports) options.extra_doh_ports.push_back(static_cast<uint16_t>(p));
    for (int p : rip_ports) options.extra_rip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : hsrp_ports) options.extra_hsrp_ports.push_back(static_cast<uint16_t>(p));

    try {
        // Built once per `decode` invocation, before opening the packet source, so a bad --hosts/
        // --services file (ResolverError -- see resolver.hpp) is reported before this process does
        // anything else, same "fail fast on bad setup" posture as parse_policy_file in
        // run_policy_validate below. Its own advisory notes (e.g. "--resolve with no --hosts
        // file") are printed the same way every other decode-time advisory already is --
        // unconditionally to `diag`, respecting --quiet -- not per-packet, since they describe the
        // whole run's configuration, not any one packet.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled,
                           services_path, resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        PacketSource source = open_packet_source(input, interface_name, snaplen, promiscuous, filter,
                                                   duration_seconds, max_packets);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);

        std::unique_ptr<OutputWriter> writer;
        StatsWriter stats_writer;
        if (!stats) {
            if (format == "json") writer = std::make_unique<JsonWriter>(*out, resolver);
            else if (format == "csv") writer = std::make_unique<CsvWriter>(*out, resolver);
            else writer = std::make_unique<TextWriter>(*out, color, resolver);
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
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
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
                         bool strict, bool quiet,
                         bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                         bool service_names_enabled, const std::string& services_path, std::ostream& diag) {
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

        // Same Resolver, built the same "fail fast before opening the packet source" way, that
        // run_decode above already builds for `decode`'s writers -- see resolver.hpp's file header:
        // this OUI/hostname/service-name annotation now reaches `policy validate`'s report too, not
        // just `decode`'s per-packet output.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled,
                           services_path, resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

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
            write_policy_report_json(*out, report, policy, capture_label, policy_path, resolver);
        } else {
            write_policy_report_text(*out, report, policy, capture_label, policy_path, resolver);
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
    } catch (const ResolverError& e) {
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

// Passive OT asset inventory -- see asset_inventory.hpp's own file header and docs/MANUAL.md's
// ROADMAP item 17. Unlike run_decode/run_policy_validate above, there is no "compliance"/pass-fail
// concept here (nothing is being checked against anything), so this always returns 0 on success --
// see EXIT STATUS.
int run_inventory(const std::string& input, const std::string& interface_name, const std::string& filter,
                   int duration_seconds, int snaplen, bool promiscuous, const std::string& output,
                   const std::string& format, bool strict, bool quiet, uint8_t zone_prefix_len,
                   const std::string& diagram_path, const std::string& diagram_format,
                   const std::string& policy_out_path, bool oui_enabled, bool resolve_hostnames,
                   const std::string& hosts_path, bool service_names_enabled, const std::string& services_path,
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

    try {
        // Same Resolver, built the same fail-fast way run_decode/run_policy_validate already do.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled, services_path,
                           resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        DecodeOptions options;
        options.strict = strict;
        // Same "no --max-packets" posture as run_policy_validate -- see its own comment.
        PacketSource source =
            open_packet_source(input, interface_name, snaplen, promiscuous, filter, duration_seconds, 0);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);
        AssetInventoryEngine engine(zone_prefix_len);

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

        std::string capture_label = interface_name.empty() ? input : "live:" + interface_name;
        AssetInventoryReport report = engine.finish();
        if (format == "json") {
            write_inventory_report_json(*out, report, capture_label, resolver);
        } else {
            write_inventory_report_text(*out, report, capture_label, resolver);
        }

        if (!diagram_path.empty()) {
            std::ofstream diagram_out(diagram_path, std::ios::binary);
            if (!diagram_out) {
                std::cerr << "error: cannot open diagram output file '" << diagram_path << "'\n";
                return 1;
            }
            if (diagram_format == "dot") write_inventory_diagram_dot(diagram_out, report);
            else write_inventory_diagram_mermaid(diagram_out, report);
        }
        if (!policy_out_path.empty()) {
            std::ofstream policy_out(policy_out_path, std::ios::binary);
            if (!policy_out) {
                std::cerr << "error: cannot open policy output file '" << policy_out_path << "'\n";
                return 1;
            }
            write_inventory_policy_yaml(policy_out, report);
            if (report.zones.empty() && !quiet) {
                diag << "note: no asset was observed, so '" << policy_out_path
                     << "' has no 'zones:'/'conduits:' keys and is not a loadable policy file as-is "
                        "-- see the file's own header comment\n";
            }
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        return 0;
    } catch (const ResolverError& e) {
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
    bool force_color = false;
    std::string log_file;
    app.add_flag("-q,--quiet", quiet, "Suppress non-essential diagnostic/warning output");
    auto* no_color_opt =
        app.add_flag("--no-color", no_color, "Disable ANSI color in decode's text-format output");
    auto* force_color_opt = app.add_flag(
        "--color", force_color,
        "Force ANSI color in decode's text-format output, even when not writing to a terminal "
        "(e.g. piping to a pager that supports it). Without either flag, color is used only when "
        "writing directly to an interactive terminal.");
    no_color_opt->excludes(force_color_opt);
    force_color_opt->excludes(no_color_opt);
    app.add_option("--log-file", log_file,
                    "Write diagnostic/warning messages to this file instead of stderr");

    // --- decode ---------------------------------------------------------
    auto* decode_cmd =
        app.add_subcommand("decode", "Decode a pcap/pcapng capture and print each recognized packet");
    std::string decode_input, decode_interface, decode_filter, decode_output;
    int decode_duration = 0;
    int decode_snaplen = 65535;
    bool decode_promiscuous = true;
    std::string decode_format = "text";
    std::string decode_protocol = "auto";
    std::vector<int> decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
        decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
        decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports, decode_mdns_ports,
        decode_llmnr_ports, decode_nbns_ports, decode_doh_ports, decode_rip_ports, decode_hsrp_ports;
    size_t decode_max_packets = 0;
    bool decode_stats = false, decode_strict = false;
    bool decode_oui = true, decode_resolve = false, decode_service_names = true;
    std::string decode_hosts_file, decode_services_file;

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
        ->transform(CLI::IsMember({"auto", "modbus", "dnp3", "s7comm", "mms", "iec104", "enip", "profinet", "goose", "sv", "ethercat", "stp", "devicenet", "bacnet", "hartip", "opcua", "mqtt", "s7comm-plus", "ff-hse", "dns", "mdns", "llmnr", "nbns", "doh", "rip", "igmp", "vrrp", "hsrp", "igrp", "pim", "eigrp", "ospf"}))
        ->capture_default_str();
    decode_cmd->add_option("--modbus-port", decode_modbus_ports,
                            "Additional TCP port to treat as expected for Modbus (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--dnp3-port", decode_dnp3_ports,
                            "Additional TCP port to treat as expected for DNP3 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--s7comm-port", decode_s7comm_ports,
                            "Additional TCP port to treat as expected for COTP/S7comm, MMS, and "
                            "S7comm-Plus (repeatable, shared -- all three ride the identical "
                            "TPKT/COTP transport and TCP port); does not change detection, only "
                            "whether the port is flagged as unexpected");
    decode_cmd->add_option("--iec104-port", decode_iec104_ports,
                            "Additional TCP port to treat as expected for IEC 104 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--enip-port", decode_enip_ports,
                            "Additional TCP port to treat as expected for EtherNet/IP explicit "
                            "messaging (repeatable); does not change detection, only whether the "
                            "port is flagged as unexpected");
    decode_cmd->add_option("--enip-io-port", decode_enip_io_ports,
                            "Additional UDP port to treat as expected for EtherNet/IP CIP I/O "
                            "implicit messaging (repeatable); does not change detection, only "
                            "whether the port is flagged as unexpected");
    decode_cmd->add_option("--bacnet-port", decode_bacnet_ports,
                            "Additional UDP port to treat as expected for BACnet/IP (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--hartip-port", decode_hartip_ports,
                            "Additional TCP or UDP port to treat as expected for HART-IP "
                            "(repeatable); does not change detection, only whether the port is "
                            "flagged as unexpected");
    decode_cmd->add_option("--opcua-port", decode_opcua_ports,
                            "Additional TCP port to treat as expected for OPC UA (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--mqtt-port", decode_mqtt_ports,
                            "Additional TCP port to treat as expected for MQTT (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--ffhse-port", decode_ffhse_ports,
                            "Additional TCP or UDP port to treat as expected for FOUNDATION "
                            "Fieldbus HSE (repeatable, shared across FDA/SM/FMS/LAN Redundancy -- "
                            "the sub-protocol is signaled in-band, not by port); does not change "
                            "detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--dns-port", decode_dns_ports,
                            "Additional UDP port to treat as expected for DNS (repeatable); UNLIKE "
                            "every --*-port option above, this DOES widen detection in Auto mode, "
                            "not just the 'expected port' annotation -- DNS has no self-describing "
                            "wire format at all, so it is normally only attempted on port 53 (see "
                            "docs/MANUAL.md)");
    decode_cmd->add_option("--mdns-port", decode_mdns_ports,
                            "Additional UDP port to treat as expected for Multicast DNS "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 5353");
    decode_cmd->add_option("--llmnr-port", decode_llmnr_ports,
                            "Additional UDP port to treat as expected for LLMNR (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 5355");
    decode_cmd->add_option("--nbns-port", decode_nbns_ports,
                            "Additional UDP port to treat as expected for NetBIOS Name Service/"
                            "NBT-NS (repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 137");
    decode_cmd->add_option("--doh-port", decode_doh_ports,
                            "Additional TCP port to check for a DNS-over-HTTPS TLS ClientHello "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 443. Detection only -- "
                            "see docs/MANUAL.md; the DNS message itself is never visible");
    decode_cmd->add_option("--rip-port", decode_rip_ports,
                            "Additional UDP port to treat as expected for RIP (repeatable); widens "
                            "detection in Auto mode, same caveat as --dns-port -- normally only "
                            "attempted on port 520");
    decode_cmd->add_option("--hsrp-port", decode_hsrp_ports,
                            "Additional UDP port to treat as expected for HSRP (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 1985. IGMP and VRRP need no port option at all "
                            "-- both are dispatched purely by IP protocol number, see docs/"
                            "MANUAL.md");
    decode_cmd->add_option("--max-packets", decode_max_packets,
                            "Stop after decoding this many packets (0 = unlimited)")
        ->capture_default_str();
    decode_cmd->add_flag("--stats", decode_stats,
                          "Print an aggregate summary (protocol/function-code histogram) instead of "
                          "one line per packet; ignores --format");
    decode_cmd->add_flag("--strict", decode_strict,
                          "Abort on the first malformed packet instead of reporting it and continuing");
    decode_cmd->add_flag("!--no-oui", decode_oui,
                          "Disable OUI (MAC vendor) resolution, on by default -- see docs/"
                          "MANUAL.md's OUTPUT FORMATS section");
    decode_cmd->add_flag(
        "--resolve", decode_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts); off by "
        "default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    decode_cmd
        ->add_option("--hosts", decode_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    decode_cmd->add_flag("!--nn", decode_service_names,
                          "Disable service name resolution (built-in table plus --services), on "
                          "by default");
    decode_cmd
        ->add_option("--services", decode_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
        ->check(CLI::ExistingFile);

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
    bool policy_oui = true, policy_resolve = false, policy_service_names = true;
    std::string policy_hosts_file, policy_services_file;
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
    policy_validate_cmd->add_flag("!--no-oui", policy_oui,
                                   "Disable OUI (MAC vendor) resolution in the report, on by default -- "
                                   "see docs/MANUAL.md's OUTPUT FORMATS section");
    policy_validate_cmd->add_flag(
        "--resolve", policy_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    policy_validate_cmd
        ->add_option("--hosts", policy_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_flag("!--nn", policy_service_names,
                                   "Disable service name resolution (built-in table plus --services) "
                                   "in the report, on by default");
    policy_validate_cmd
        ->add_option("--services", policy_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
        ->check(CLI::ExistingFile);

    // --- inventory ------------------------------------------------------------
    auto* inventory_cmd = app.add_subcommand(
        "inventory", "Passive OT asset inventory: infer a first-draft zone/conduit model (asset "
                      "list, communication matrix, proposed zones/conduits) from a capture -- the "
                      "opposite direction from 'policy validate'. See docs/MANUAL.md's ROADMAP "
                      "item 17.");
    std::string inventory_input, inventory_interface, inventory_filter, inventory_output;
    int inventory_duration = 0;
    int inventory_snaplen = 65535;
    bool inventory_promiscuous = true;
    std::string inventory_format = "text";
    bool inventory_strict = false;
    int inventory_zone_prefix = static_cast<int>(kDefaultInventoryZonePrefixLen);
    std::string inventory_diagram_file;
    std::string inventory_diagram_format = "mermaid";
    std::string inventory_policy_out;
    bool inventory_oui = true, inventory_resolve = false, inventory_service_names = true;
    std::string inventory_hosts_file, inventory_services_file;

    auto* inventory_input_opt =
        inventory_cmd->add_option("-r,--read", inventory_input,
                                   "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* inventory_interface_opt = inventory_cmd->add_option(
        "-i,--interface", inventory_interface,
        "Build the inventory from live traffic on this network interface instead of reading a "
        "file (see 'conduitscope interfaces'); requires this build to have been compiled with "
        "libpcap/Npcap support -- exactly one of -r/-i is required");
    inventory_input_opt->excludes(inventory_interface_opt);
    inventory_interface_opt->excludes(inventory_input_opt);
    inventory_cmd->add_option("--filter", inventory_filter,
                               "BPF capture filter (tcpdump syntax), only meaningful with -i");
    inventory_cmd
        ->add_option("--duration", inventory_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")
        ->capture_default_str();
    inventory_cmd->add_option("--snaplen", inventory_snaplen, "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    inventory_cmd->add_flag(
        "!--no-promiscuous", inventory_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)");
    inventory_cmd->add_option("-o,--output", inventory_output, "Write the report here instead of stdout");
    inventory_cmd->add_option("-f,--format", inventory_format, "Report format: text or json")
        ->transform(CLI::IsMember({"text", "json"}))
        ->capture_default_str();
    inventory_cmd->add_flag("--strict", inventory_strict,
                             "Abort on the first malformed packet instead of reporting it and continuing");
    inventory_cmd
        ->add_option("--zone-prefix", inventory_zone_prefix,
                      "CIDR prefix length ([0, 32]) used to group observed asset IPs into "
                      "inferred zones -- see docs/MANUAL.md's ROADMAP item 17")
        ->capture_default_str()
        ->check(CLI::Range(0, 32));
    inventory_cmd->add_option("--diagram", inventory_diagram_file,
                               "Also write a zone/conduit diagram here (see --diagram-format)");
    inventory_cmd
        ->add_option("--diagram-format", inventory_diagram_format,
                      "Diagram format for --diagram: a Mermaid flowchart or Graphviz DOT")
        ->transform(CLI::IsMember({"mermaid", "dot"}))
        ->capture_default_str();
    inventory_cmd->add_option(
        "--policy-out", inventory_policy_out,
        "Also write the inferred zone/conduit model as a policy YAML file here, directly loadable "
        "by 'policy validate --policy' -- closes the discover-then-enforce loop");
    inventory_cmd->add_flag("!--no-oui", inventory_oui,
                             "Disable OUI (MAC vendor) resolution in the report, on by default -- "
                             "see docs/MANUAL.md's OUTPUT FORMATS section");
    inventory_cmd->add_flag(
        "--resolve", inventory_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    inventory_cmd
        ->add_option("--hosts", inventory_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    inventory_cmd->add_flag("!--nn", inventory_service_names,
                             "Disable service name resolution (built-in table plus --services) in "
                             "the report, on by default");
    inventory_cmd
        ->add_option("--services", inventory_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
        ->check(CLI::ExistingFile);

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
    if (inventory_cmd->parsed() && inventory_input.empty() == inventory_interface.empty()) {
        std::cerr << "error: 'inventory' needs exactly one of -r/--read (an offline capture file) "
                     "or -i/--interface (a live capture interface)\n";
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
                           decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
                           decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
                           decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports,
                           decode_mdns_ports, decode_llmnr_ports, decode_nbns_ports, decode_doh_ports,
                           decode_rip_ports, decode_hsrp_ports,
                           decode_max_packets, decode_stats, decode_strict,
                           quiet, no_color, force_color, decode_oui, decode_resolve, decode_hosts_file,
                           decode_service_names, decode_services_file, *diag);
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
                                    quiet, policy_oui, policy_resolve, policy_hosts_file, policy_service_names,
                                    policy_services_file, *diag);
    }
    if (policy_cmd->parsed()) {
        std::cerr << "error: 'policy' needs a subcommand (currently only 'validate' exists)\n";
        return 1;
    }
    if (inventory_cmd->parsed()) {
        return run_inventory(inventory_input, inventory_interface, inventory_filter, inventory_duration,
                              inventory_snaplen, inventory_promiscuous, inventory_output, inventory_format,
                              inventory_strict, quiet, static_cast<uint8_t>(inventory_zone_prefix),
                              inventory_diagram_file, inventory_diagram_format, inventory_policy_out,
                              inventory_oui, inventory_resolve, inventory_hosts_file, inventory_service_names,
                              inventory_services_file, *diag);
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
