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
    if (!p.has_tcp) return ip;
    uint16_t port = src ? p.src_port : p.dst_port;
    return ip + ":" + std::to_string(port);
}
}  // namespace

void TextWriter::write_packet(const DecodedPacket& p) {
    std::ostringstream head;
    head << "#" << p.index << "  " << std::fixed << std::setprecision(6) << p.timestamp << "  "
         << endpoint(p, true) << " -> " << endpoint(p, false) << "  [" << p.protocol << "]  " << p.summary;
    out_ << head.str() << "\n";
    for (const auto& note : p.notes) {
        out_ << "        note: " << note << "\n";
    }
    (void)color_;  // reserved: colorized severity highlighting is a documented Roadmap item
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
    out_ << "    \"src_port\": " << (p.has_tcp ? std::to_string(p.src_port) : "null") << ",\n";
    out_ << "    \"dst_port\": " << (p.has_tcp ? std::to_string(p.dst_port) : "null") << ",\n";
    out_ << "    \"tcp_flags\": " << (p.has_tcp ? ("\"" + json_escape(p.tcp_flags) + "\"") : "null") << ",\n";
    out_ << "    \"protocol\": \"" << json_escape(p.protocol) << "\",\n";
    out_ << "    \"summary\": \"" << json_escape(p.summary) << "\",\n";
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
    out_ << p.index << ',' << std::fixed << std::setprecision(6) << p.timestamp << ','
         << (p.has_ip ? csv_escape(p.src_ip) : "") << ',' << (p.has_tcp ? std::to_string(p.src_port) : "")
         << ',' << (p.has_ip ? csv_escape(p.dst_ip) : "") << ','
         << (p.has_tcp ? std::to_string(p.dst_port) : "") << ',' << csv_escape(p.protocol) << ','
         << csv_escape(p.summary) << ',' << csv_escape(notes.str()) << "\n";
}

void StatsWriter::write_packet(const DecodedPacket& p) {
    total_packets_++;
    protocol_counts_[p.protocol]++;
    if (p.protocol == "modbus") {
        modbus_function_counts_[p.modbus_function_name]++;
        if (p.modbus_is_exception) modbus_exceptions_++;
    }
    if (p.protocol == "s7comm" && p.s7comm_has_function) {
        s7comm_function_counts_[p.s7comm_function_name]++;
    }
    if (p.protocol == "dnp3" && p.dnp3_has_function) {
        dnp3_function_counts_[p.dnp3_function_name]++;
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
}

}  // namespace conduitscope
