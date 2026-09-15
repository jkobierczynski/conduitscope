// SPDX-License-Identifier: MIT
// cli_main.cpp - command-line interface, built on the vendored CLI11 header.
//
// See docs/MANUAL.md for the full option reference; --help at any level
// (top-level, `decode --help`, `policy validate --help`, ...) is generated
// from the same option definitions below, so the two should never drift
// far apart -- but the manual also explains the *why* behind choices like
// the protocol-detection heuristics, which --help intentionally keeps brief.
#include <CLI11.hpp>

#include <cstdint>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/output.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"
#include "conduitscope/version.hpp"

namespace {

using namespace conduitscope;

std::string link_type_name(uint32_t linktype) {
    switch (linktype) {
        case LINKTYPE_ETHERNET: return "Ethernet";
        case LINKTYPE_RAW: return "Raw IP (no link-layer header)";
        default: return "unsupported/unknown (" + std::to_string(linktype) + ")";
    }
}

std::string version_string() {
    return std::string(kVersion) + "  [" + kCompilerId + ", " + kSystemName + ", " + kBuildType +
           " build]";
}

int run_decode(const std::string& input, const std::string& output, const std::string& format,
                const std::string& protocol, const std::vector<int>& modbus_ports,
                const std::vector<int>& dnp3_ports, const std::vector<int>& s7comm_ports,
                size_t max_packets, bool stats, bool strict, bool quiet, bool color, std::ostream& diag) {
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
        PcapReader reader(input);
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
        while (reader.next(pkt)) {
            ++index;
            DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
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

        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
    } catch (const ParseError& e) {
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

int run_policy_validate(const std::string& input, const std::string& policy_path, const std::string& output,
                         const std::string& format, bool strict, bool quiet, std::ostream& diag) {
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
        PcapReader reader(input);
        Decoder decoder(options);
        PolicyEngine engine(policy);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (reader.next(pkt)) {
            ++index;
            DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        PolicyReport report = engine.finish();
        if (format == "json") {
            write_policy_report_json(*out, report, policy, input, policy_path);
        } else {
            write_policy_report_text(*out, report, policy, input, policy_path);
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
    }
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"conduitscope decodes Modbus/TCP, DNP3, and S7comm/COTP traffic from offline pcap "
                  "captures, as a building block for OT/ICS conduit and zone auditing (IEC 62443 / NIS2 "
                  "workflows).",
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
        app.add_subcommand("decode", "Decode a pcap capture and print each recognized packet");
    std::string decode_input, decode_output;
    std::string decode_format = "text";
    std::string decode_protocol = "auto";
    std::vector<int> decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports;
    size_t decode_max_packets = 0;
    bool decode_stats = false, decode_strict = false;

    decode_cmd->add_option("-i,--input", decode_input, "Input pcap file (classic pcap; pcapng is not yet supported)")
        ->required()
        ->check(CLI::ExistingFile);
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
    info_cmd->add_option("-i,--input", info_input, "Input pcap file")->required()->check(CLI::ExistingFile);

    // --- policy validate ----------------------------------------------------
    auto* policy_cmd =
        app.add_subcommand("policy", "Zone/conduit compliance checking against a policy file");
    auto* policy_validate_cmd = policy_cmd->add_subcommand(
        "validate", "Check decoded traffic against a zone/conduit policy file");
    std::string policy_input, policy_file, policy_output;
    std::string policy_format = "text";
    bool policy_strict = false;
    policy_validate_cmd->add_option("-i,--input", policy_input, "Input pcap file (classic pcap)")
        ->required()
        ->check(CLI::ExistingFile);
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
        return run_decode(decode_input, decode_output, decode_format, decode_protocol,
                           decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_max_packets,
                           decode_stats, decode_strict, quiet, !no_color, *diag);
    }
    if (info_cmd->parsed()) {
        return run_info(info_input, std::cout);
    }
    if (policy_validate_cmd->parsed()) {
        return run_policy_validate(policy_input, policy_file, policy_output, policy_format, policy_strict, quiet,
                                    *diag);
    }
    if (policy_cmd->parsed()) {
        std::cerr << "error: 'policy' needs a subcommand (currently only 'validate' exists)\n";
        return 1;
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
