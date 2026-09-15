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

int run_policy_validate_stub(const std::string& input, const std::string& policy) {
    std::cout << "conduitscope: 'policy validate' is not implemented yet in this groundwork release.\n"
                 "This subcommand is scaffolded now so its option surface (--input/--policy) is\n"
                 "stable for scripting against; the zone/conduit evaluation engine itself is the\n"
                 "next phase of this project -- see the Roadmap section of docs/MANUAL.md.\n\n"
                 "inputs given:\n"
                 "  capture: " << input << "\n"
                 "  policy:  " << policy << "\n";
    return 2;
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

    // --- policy validate (documented stub; see docs/MANUAL.md Roadmap) ----
    auto* policy_cmd = app.add_subcommand(
        "policy", "Zone/conduit compliance checking against a policy file [phase 2, see Roadmap]");
    auto* policy_validate_cmd = policy_cmd->add_subcommand(
        "validate",
        "Check decoded traffic against a zone/conduit policy file [not yet implemented -- this "
        "command exists now so its option surface is stable to script against]");
    std::string policy_input, policy_file;
    policy_validate_cmd->add_option("-i,--input", policy_input, "Input pcap file")->required();
    policy_validate_cmd->add_option("--policy", policy_file, "Zone/conduit policy file (YAML)")
        ->required();

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
        return run_policy_validate_stub(policy_input, policy_file);
    }
    if (policy_cmd->parsed()) {
        std::cerr << "error: 'policy' needs a subcommand (currently only 'validate' exists)\n";
        return 1;
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
