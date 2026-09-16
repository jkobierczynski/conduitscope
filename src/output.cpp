// SPDX-License-Identifier: MIT
#include "conduitscope/output.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace conduitscope {

std::string json_escape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c)
                        << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string csv_escape(const std::string& s) {
    bool needs_quotes = s.find_first_of(",\"\n\r") != std::string::npos;
    if (!needs_quotes) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

namespace {
std::string endpoint(const DecodedPacket& p, bool src) {
    if (!p.has_ip) return "-";
    std::string ip = src ? p.src_ip : p.dst_ip;
    if (!p.has_tcp && !p.has_udp) return ip;
    uint16_t port = src ? p.src_port : p.dst_port;
    return ip + ":" + std::to_string(port);
}

// ANSI SGR (Select Graphic Rendition) escape sequences. Only ever emitted when TextWriter::color_
// is true -- see cli_main.cpp's stdout_is_terminal()/--color/--no-color for how that's decided.
constexpr const char* kReset = "\033[0m";
constexpr const char* kDim = "\033[2m";
constexpr const char* kBoldRed = "\033[1;31m";
constexpr const char* kCyan = "\033[36m";
constexpr const char* kMagenta = "\033[35m";
constexpr const char* kBlue = "\033[34m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kBrightCyan = "\033[96m";

// Color for a packet's "[protocol]" tag -- picked so a mixed-protocol capture scans quickly by
// eye, not for any deeper meaning. parse-error is the one exception: it gets the same "something
// is wrong here" red as a Modbus exception response, rather than a plain identification color,
// since it's a problem rather than a protocol match.
const char* protocol_tag_color(const std::string& protocol) {
    if (protocol == "modbus") return kCyan;
    if (protocol == "dnp3") return kMagenta;
    if (protocol == "s7comm") return kBlue;
    if (protocol == "cotp") return kBlue;  // recognized TPKT/COTP framing, no S7comm inside yet
    if (protocol == "iec104") return kGreen;
    if (protocol == "enip") return kYellow;
    if (protocol == "profinet") return kBrightCyan;
    if (protocol == "parse-error") return kBoldRed;
    return kDim;  // tcp / udp / non-tcp / non-ip / unsupported-link: recognized, nothing OT-specific
}
}  // namespace

void TextWriter::write_packet(const DecodedPacket& p) {
    // A parse failure, or a Modbus exception response, is the one piece of a packet line worth
    // drawing the eye to over everything else in a long decode -- both mean "look at this one".
    bool severe = p.protocol == "parse-error" || (p.protocol == "modbus" && p.modbus_is_exception);

    std::ostringstream head;
    head << "#" << p.index << "  " << std::fixed << std::setprecision(6) << p.timestamp << "  "
         << endpoint(p, true) << " -> " << endpoint(p, false) << "  ";
    if (color_) head << protocol_tag_color(p.protocol);
    head << "[" << p.protocol << "]";
    if (color_) head << kReset;
    head << "  ";
    if (color_ && severe) head << kBoldRed;
    head << p.summary;
    if (color_ && severe) head << kReset;
    out_ << head.str() << "\n";

    for (const auto& note : p.notes) {
        out_ << "        ";
        if (color_) out_ << kDim;
        out_ << "note: " << note;
        if (color_) out_ << kReset;
        out_ << "\n";
    }
}

void JsonWriter::begin() { out_ << "[\n"; }

void JsonWriter::write_packet(const DecodedPacket& p) {
    if (wrote_any_) out_ << ",\n";
    wrote_any_ = true;
    out_ << "  {\n";
    out_ << "    \"index\": " << p.index << ",\n";
    out_ << "    \"timestamp\": " << std::fixed << std::setprecision(6) << p.timestamp << ",\n";
    out_ << "    \"captured_len\": " << p.captured_len << ",\n";
    out_ << "    \"original_len\": " << p.original_len << ",\n";
    out_ << "    \"src_ip\": " << (p.has_ip ? ("\"" + json_escape(p.src_ip) + "\"") : "null") << ",\n";
    out_ << "    \"dst_ip\": " << (p.has_ip ? ("\"" + json_escape(p.dst_ip) + "\"") : "null") << ",\n";
    bool has_port = p.has_tcp || p.has_udp;
    out_ << "    \"src_port\": " << (has_port ? std::to_string(p.src_port) : "null") << ",\n";
    out_ << "    \"dst_port\": " << (has_port ? std::to_string(p.dst_port) : "null") << ",\n";
    out_ << "    \"tcp_flags\": " << (p.has_tcp ? ("\"" + json_escape(p.tcp_flags) + "\"") : "null") << ",\n";
    out_ << "    \"protocol\": \"" << json_escape(p.protocol) << "\",\n";
    out_ << "    \"summary\": \"" << json_escape(p.summary) << "\",\n";
    if (p.protocol == "modbus" && p.modbus_is_paired_response) {
        out_ << "    \"modbus_paired_request_index\": " << p.modbus_paired_request_index << ",\n";
    }
    if (p.protocol == "s7comm" && p.s7comm_has_function) {
        out_ << "    \"s7comm_function\": \"" << json_escape(p.s7comm_function_name) << "\",\n";
    }
    if (!p.s7comm_item_tags.empty()) {
        out_ << "    \"s7comm_items\": [";
        for (size_t i = 0; i < p.s7comm_item_tags.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.s7comm_item_tags[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (!p.s7comm_value_summaries.empty()) {
        out_ << "    \"s7comm_values\": [";
        for (size_t i = 0; i < p.s7comm_value_summaries.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.s7comm_value_summaries[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.protocol == "dnp3" && p.dnp3_has_function) {
        out_ << "    \"dnp3_function\": \"" << json_escape(p.dnp3_function_name) << "\",\n";
    }
    if (!p.dnp3_object_headers.empty()) {
        out_ << "    \"dnp3_objects\": [";
        for (size_t i = 0; i < p.dnp3_object_headers.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.dnp3_object_headers[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (!p.dnp3_point_values.empty()) {
        out_ << "    \"dnp3_values\": [";
        for (size_t i = 0; i < p.dnp3_point_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.dnp3_point_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.protocol == "iec104" && p.iec104_has_asdu) {
        out_ << "    \"iec104_asdu_type\": \"" << json_escape(p.iec104_asdu_type_name) << "\",\n";
        out_ << "    \"iec104_cot\": \"" << json_escape(p.iec104_cot_name) << "\",\n";
        out_ << "    \"iec104_common_address\": " << p.iec104_common_address << ",\n";
    }
    if (!p.iec104_object_values.empty()) {
        out_ << "    \"iec104_objects\": [";
        for (size_t i = 0; i < p.iec104_object_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.iec104_object_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.protocol == "enip" && !p.enip_command_name.empty()) {
        // Empty for a CIP I/O (implicit messaging) UDP datagram -- there is no encapsulation
        // command on the wire for that (see enip_has_io below and enip.hpp's file header comment).
        out_ << "    \"enip_command\": \"" << json_escape(p.enip_command_name) << "\",\n";
    }
    if (p.enip_has_cip) {
        out_ << "    \"enip_cip_is_response\": " << (p.enip_cip_is_response ? "true" : "false") << ",\n";
        out_ << "    \"enip_cip_service\": \"" << json_escape(p.enip_cip_service_name) << "\",\n";
        if (!p.enip_cip_path.empty()) {
            out_ << "    \"enip_cip_path\": \"" << json_escape(p.enip_cip_path) << "\",\n";
        }
        if (!p.enip_cip_status_name.empty()) {
            out_ << "    \"enip_cip_status\": \"" << json_escape(p.enip_cip_status_name) << "\",\n";
        }
    }
    if (!p.enip_cip_values.empty()) {
        out_ << "    \"enip_cip_values\": [";
        for (size_t i = 0; i < p.enip_cip_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.enip_cip_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.enip_has_io) {
        std::ostringstream connid;
        connid << "0x" << std::hex << std::uppercase << p.enip_io_connection_id;
        out_ << "    \"enip_io_connection_id\": \"" << connid.str() << "\",\n";
        out_ << "    \"enip_io_sequence_number\": " << p.enip_io_sequence_number << ",\n";
        if (p.enip_io_has_data) {
            out_ << "    \"enip_io_data_length\": " << p.enip_io_data_length << ",\n";
            out_ << "    \"enip_io_data_hex\": \"" << json_escape(p.enip_io_data_hex) << "\",\n";
        }
    }
    if (p.protocol == "profinet") {
        std::ostringstream fid;
        fid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.profinet_frame_id;
        out_ << "    \"profinet_frame_id\": \"" << fid.str() << "\",\n";
        out_ << "    \"profinet_frame_id_name\": \"" << json_escape(p.profinet_frame_id_name) << "\",\n";
    }
    if (p.profinet_has_dcp) {
        out_ << "    \"profinet_dcp_service\": \"" << json_escape(p.profinet_dcp_service_name) << "\",\n";
        out_ << "    \"profinet_dcp_service_type\": \"" << json_escape(p.profinet_dcp_service_type_name) << "\",\n";
        if (!p.profinet_dcp_blocks.empty()) {
            out_ << "    \"profinet_dcp_blocks\": [";
            for (size_t i = 0; i < p.profinet_dcp_blocks.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.profinet_dcp_blocks[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.profinet_has_cyclic_data) {
        out_ << "    \"profinet_cyclic_io_data_length\": " << p.profinet_cyclic_io_data_length << ",\n";
        out_ << "    \"profinet_cyclic_io_data_hex\": \"" << json_escape(p.profinet_cyclic_io_data_hex) << "\",\n";
        out_ << "    \"profinet_cyclic_cycle_counter\": " << p.profinet_cyclic_cycle_counter << ",\n";
        out_ << "    \"profinet_cyclic_data_status\": \"" << json_escape(p.profinet_cyclic_data_status_summary)
             << "\",\n";
        out_ << "    \"profinet_cyclic_transfer_status\": " << static_cast<unsigned>(p.profinet_cyclic_transfer_status)
             << ",\n";
    }
    out_ << "    \"notes\": [";
    for (size_t i = 0; i < p.notes.size(); ++i) {
        if (i != 0) out_ << ", ";
        out_ << "\"" << json_escape(p.notes[i]) << "\"";
    }
    out_ << "]\n";
    out_ << "  }";
}

void JsonWriter::end() { out_ << (wrote_any_ ? "\n]\n" : "]\n"); }

void CsvWriter::begin() {
    out_ << "index,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,summary,notes\n";
}

void CsvWriter::write_packet(const DecodedPacket& p) {
    std::ostringstream notes;
    for (size_t i = 0; i < p.notes.size(); ++i) {
        if (i != 0) notes << " | ";
        notes << p.notes[i];
    }
    bool has_port = p.has_tcp || p.has_udp;
    out_ << p.index << ',' << std::fixed << std::setprecision(6) << p.timestamp << ','
         << (p.has_ip ? csv_escape(p.src_ip) : "") << ',' << (has_port ? std::to_string(p.src_port) : "")
         << ',' << (p.has_ip ? csv_escape(p.dst_ip) : "") << ','
         << (has_port ? std::to_string(p.dst_port) : "") << ',' << csv_escape(p.protocol) << ','
         << csv_escape(p.summary) << ',' << csv_escape(notes.str()) << "\n";
}

void StatsWriter::write_packet(const DecodedPacket& p) {
    total_packets_++;
    protocol_counts_[p.protocol]++;
    if (p.protocol == "modbus") {
        modbus_function_counts_[p.modbus_function_name]++;
        if (p.modbus_is_exception) modbus_exceptions_++;
        if (p.modbus_is_paired_response) modbus_paired_responses_++;
    }
    if (p.protocol == "s7comm" && p.s7comm_has_function) {
        s7comm_function_counts_[p.s7comm_function_name]++;
    }
    if (p.protocol == "dnp3" && p.dnp3_has_function) {
        dnp3_function_counts_[p.dnp3_function_name]++;
    }
    if (p.protocol == "iec104" && p.iec104_has_asdu) {
        iec104_asdu_type_counts_[p.iec104_asdu_type_name]++;
    }
    if (p.protocol == "enip") {
        if (!p.enip_command_name.empty()) enip_command_counts_[p.enip_command_name]++;
        if (p.enip_has_cip) enip_cip_service_counts_[p.enip_cip_service_name]++;
        if (p.enip_has_io) enip_io_datagram_count_++;
    }
    if (p.protocol == "profinet") {
        profinet_frame_id_counts_[p.profinet_frame_id_name]++;
        if (p.profinet_has_dcp) profinet_dcp_count_++;
        if (p.profinet_has_cyclic_data) profinet_cyclic_count_++;
    }
    if (!has_ts_) {
        first_ts_ = last_ts_ = p.timestamp;
        has_ts_ = true;
    } else {
        first_ts_ = std::min(first_ts_, p.timestamp);
        last_ts_ = std::max(last_ts_, p.timestamp);
    }
}

void StatsWriter::print_summary(std::ostream& out) const {
    out << "packets:        " << total_packets_ << "\n";
    if (has_ts_) {
        out << "time span:      " << std::fixed << std::setprecision(3) << (last_ts_ - first_ts_)
            << " s\n";
    }
    out << "protocols:\n";
    for (const auto& [name, count] : protocol_counts_) {
        out << "  " << std::left << std::setw(16) << name << count << "\n";
    }
    if (!modbus_function_counts_.empty()) {
        out << "modbus function codes:\n";
        for (const auto& [name, count] : modbus_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "modbus exception responses: " << modbus_exceptions_ << "\n";
        out << "modbus responses authoritatively paired (transaction ID, not heuristic): "
            << modbus_paired_responses_ << "\n";
    }
    if (!s7comm_function_counts_.empty()) {
        out << "s7comm function codes:\n";
        for (const auto& [name, count] : s7comm_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!dnp3_function_counts_.empty()) {
        out << "dnp3 function codes:\n";
        for (const auto& [name, count] : dnp3_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!iec104_asdu_type_counts_.empty()) {
        out << "iec104 asdu types:\n";
        for (const auto& [name, count] : iec104_asdu_type_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!enip_command_counts_.empty()) {
        out << "enip encapsulation commands:\n";
        for (const auto& [name, count] : enip_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!enip_cip_service_counts_.empty()) {
        out << "enip cip services:\n";
        for (const auto& [name, count] : enip_cip_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (enip_io_datagram_count_ > 0) {
        out << "enip cip i/o (implicit messaging) datagrams: " << enip_io_datagram_count_ << "\n";
    }
    if (!profinet_frame_id_counts_.empty()) {
        out << "profinet frame id types:\n";
        for (const auto& [name, count] : profinet_frame_id_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
        out << "profinet dcp messages: " << profinet_dcp_count_ << "\n";
        out << "profinet cyclic rt io datagrams: " << profinet_cyclic_count_ << "\n";
    }
}

}  // namespace conduitscope
