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
constexpr const char* kBrightGreen = "\033[92m";
constexpr const char* kBrightMagenta = "\033[95m";
constexpr const char* kBrightYellow = "\033[93m";
constexpr const char* kBrightBlue = "\033[94m";
constexpr const char* kBrightWhite = "\033[97m";
constexpr const char* kBrightRed = "\033[91m";
constexpr const char* kBoldBlue = "\033[1;34m";
constexpr const char* kBoldCyan = "\033[1;36m";
constexpr const char* kBoldMagenta = "\033[1;35m";

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
    if (protocol == "goose") return kBrightGreen;
    if (protocol == "sv") return kBrightMagenta;
    if (protocol == "ethercat") return kBrightYellow;
    if (protocol == "bacnet") return kBrightBlue;
    if (protocol == "hartip") return kBrightWhite;
    if (protocol == "opcua") return kBrightRed;
    if (protocol == "mms") return kBoldBlue;  // deliberately close to s7comm's plain blue -- they
                                                // share the same TPKT/COTP transport/port, bold
                                                // distinguishes MMS at a glance
    if (protocol == "s7comm-plus") return kBoldMagenta;  // deliberately NOT a third shade of blue
                                                            // alongside s7comm's plain blue/mms's
                                                            // bold blue (despite sharing their
                                                            // exact TPKT/COTP transport/port) --
                                                            // S7comm-Plus is a wholly different,
                                                            // independent application protocol
                                                            // from classic S7comm (see
                                                            // s7commplus.hpp), and bold magenta
                                                            // stays visually distinct from DNP3's
                                                            // own plain magenta too
    if (protocol == "mqtt") return kBoldCyan;  // bold, vs. Modbus's plain cyan -- deliberately
                                                 // distinct from every other tag color, no shared
                                                 // transport/port with any other decoded protocol
    if (protocol == "ffhse") return kBrightRed;  // deliberately shares opcua's bright red rather
                                                    // than adding a 20th distinct hue -- the two
                                                    // never share a transport/port, so there is no
                                                    // realistic capture where this collision would
                                                    // actually confuse a reader scanning by eye
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
    if (p.protocol == "goose") {
        std::ostringstream appid;
        appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.goose_appid;
        out_ << "    \"goose_appid\": \"" << appid.str() << "\",\n";
        out_ << "    \"goose_is_gse_management\": " << (p.goose_is_gse_management ? "true" : "false") << ",\n";
    }
    if (p.goose_has_pdu) {
        out_ << "    \"goose_simulated\": " << (p.goose_simulated ? "true" : "false") << ",\n";
        out_ << "    \"goose_gocb_ref\": \"" << json_escape(p.goose_gocb_ref) << "\",\n";
        out_ << "    \"goose_dat_set\": \"" << json_escape(p.goose_dat_set) << "\",\n";
        if (!p.goose_go_id.empty()) out_ << "    \"goose_go_id\": \"" << json_escape(p.goose_go_id) << "\",\n";
        out_ << "    \"goose_st_num\": " << p.goose_st_num << ",\n";
        out_ << "    \"goose_sq_num\": " << p.goose_sq_num << ",\n";
        out_ << "    \"goose_conf_rev\": " << p.goose_conf_rev << ",\n";
        out_ << "    \"goose_num_dat_set_entries\": " << p.goose_num_dat_set_entries << ",\n";
        if (!p.goose_all_data.empty()) {
            out_ << "    \"goose_all_data\": [";
            for (size_t i = 0; i < p.goose_all_data.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.goose_all_data[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.protocol == "sv") {
        std::ostringstream appid;
        appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.sv_appid;
        out_ << "    \"sv_appid\": \"" << appid.str() << "\",\n";
        out_ << "    \"sv_simulated\": " << (p.sv_simulated ? "true" : "false") << ",\n";
        out_ << "    \"sv_no_asdu\": " << p.sv_no_asdu << ",\n";
        out_ << "    \"sv_asdu_count\": " << p.sv_asdu_count << ",\n";
        if (p.sv_asdu_count > 0) {
            out_ << "    \"sv_id\": \"" << json_escape(p.sv_id) << "\",\n";
            if (!p.sv_dat_set.empty()) out_ << "    \"sv_dat_set\": \"" << json_escape(p.sv_dat_set) << "\",\n";
            out_ << "    \"sv_smp_cnt\": " << p.sv_smp_cnt << ",\n";
            out_ << "    \"sv_conf_rev\": " << p.sv_conf_rev << ",\n";
            if (!p.sv_smp_synch.empty()) out_ << "    \"sv_smp_synch\": \"" << json_escape(p.sv_smp_synch) << "\",\n";
            if (p.sv_smp_rate != 0) out_ << "    \"sv_smp_rate\": " << p.sv_smp_rate << ",\n";
            if (!p.sv_smp_mod.empty()) out_ << "    \"sv_smp_mod\": \"" << json_escape(p.sv_smp_mod) << "\",\n";
            out_ << "    \"sv_seq_data_length\": " << p.sv_seq_data_length << ",\n";
            out_ << "    \"sv_seq_data_hex\": \"" << json_escape(p.sv_seq_data_hex) << "\",\n";
            if (!p.sv_gmid_hex.empty()) out_ << "    \"sv_gmid_hex\": \"" << json_escape(p.sv_gmid_hex) << "\",\n";
        }
        if (!p.sv_asdus.empty()) {
            out_ << "    \"sv_asdus\": [";
            for (size_t i = 0; i < p.sv_asdus.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.sv_asdus[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.protocol == "ethercat") {
        out_ << "    \"ethercat_frame_type\": " << static_cast<unsigned>(p.ethercat_frame_type) << ",\n";
        out_ << "    \"ethercat_frame_type_name\": \"" << json_escape(p.ethercat_frame_type_name) << "\",\n";
        out_ << "    \"ethercat_declared_length\": " << p.ethercat_declared_length << ",\n";
        out_ << "    \"ethercat_has_datagrams\": " << (p.ethercat_has_datagrams ? "true" : "false") << ",\n";
        if (p.ethercat_has_datagrams) {
            out_ << "    \"ethercat_datagram_count\": " << p.ethercat_datagram_count << ",\n";
            if (p.ethercat_datagram_count > 0) {
                out_ << "    \"ethercat_first_cmd\": " << static_cast<unsigned>(p.ethercat_first_cmd) << ",\n";
                out_ << "    \"ethercat_first_cmd_name\": \"" << json_escape(p.ethercat_first_cmd_name) << "\",\n";
                out_ << "    \"ethercat_first_idx\": " << static_cast<unsigned>(p.ethercat_first_idx) << ",\n";
                if (p.ethercat_first_logical_addressing) {
                    out_ << "    \"ethercat_first_logical_address\": " << p.ethercat_first_logical_address << ",\n";
                } else {
                    out_ << "    \"ethercat_first_adp\": " << p.ethercat_first_adp << ",\n";
                    out_ << "    \"ethercat_first_ado\": " << p.ethercat_first_ado << ",\n";
                }
                out_ << "    \"ethercat_first_data_length\": " << p.ethercat_first_data_length << ",\n";
                out_ << "    \"ethercat_first_data_hex\": \"" << json_escape(p.ethercat_first_data_hex) << "\",\n";
                out_ << "    \"ethercat_first_wkc\": " << p.ethercat_first_wkc << ",\n";
                out_ << "    \"ethercat_first_irq\": " << p.ethercat_first_irq << ",\n";
                out_ << "    \"ethercat_first_circulating\": " << (p.ethercat_first_circulating ? "true" : "false") << ",\n";
            }
            if (!p.ethercat_datagrams.empty()) {
                out_ << "    \"ethercat_datagrams\": [";
                for (size_t i = 0; i < p.ethercat_datagrams.size(); ++i) {
                    if (i != 0) out_ << ", ";
                    out_ << "\"" << json_escape(p.ethercat_datagrams[i]) << "\"";
                }
                out_ << "],\n";
            }
        }
    }
    if (p.protocol == "bacnet") {
        out_ << "    \"bacnet_bvlc_function\": \"" << json_escape(p.bacnet_bvlc_function) << "\",\n";
        out_ << "    \"bacnet_has_npdu\": " << (p.bacnet_has_npdu ? "true" : "false") << ",\n";
        if (p.bacnet_has_npdu) {
            out_ << "    \"bacnet_npdu_version\": " << static_cast<unsigned>(p.bacnet_npdu_version) << ",\n";
            out_ << "    \"bacnet_npdu_is_network_layer_message\": "
                 << (p.bacnet_npdu_is_network_layer_message ? "true" : "false") << ",\n";
            out_ << "    \"bacnet_npdu_expecting_reply\": " << (p.bacnet_npdu_expecting_reply ? "true" : "false")
                 << ",\n";
            out_ << "    \"bacnet_npdu_priority\": " << static_cast<unsigned>(p.bacnet_npdu_priority) << ",\n";
            out_ << "    \"bacnet_npdu_has_dest\": " << (p.bacnet_npdu_has_dest ? "true" : "false") << ",\n";
            if (p.bacnet_npdu_has_dest) out_ << "    \"bacnet_npdu_dnet\": " << p.bacnet_npdu_dnet << ",\n";
            out_ << "    \"bacnet_npdu_has_src\": " << (p.bacnet_npdu_has_src ? "true" : "false") << ",\n";
            if (p.bacnet_npdu_has_src) out_ << "    \"bacnet_npdu_snet\": " << p.bacnet_npdu_snet << ",\n";
            if (p.bacnet_npdu_has_dest)
                out_ << "    \"bacnet_npdu_hop_count\": " << static_cast<unsigned>(p.bacnet_npdu_hop_count)
                     << ",\n";
            if (p.bacnet_npdu_is_network_layer_message) {
                out_ << "    \"bacnet_npdu_message_type\": \"" << json_escape(p.bacnet_npdu_message_type)
                     << "\",\n";
            }
            out_ << "    \"bacnet_has_apdu\": " << (p.bacnet_has_apdu ? "true" : "false") << ",\n";
            if (p.bacnet_has_apdu) {
                out_ << "    \"bacnet_apdu_type\": \"" << json_escape(p.bacnet_apdu_type) << "\",\n";
                if (!p.bacnet_service_name.empty())
                    out_ << "    \"bacnet_service_name\": \"" << json_escape(p.bacnet_service_name) << "\",\n";
                out_ << "    \"bacnet_invoke_id\": " << p.bacnet_invoke_id << ",\n";
                out_ << "    \"bacnet_segmented\": " << (p.bacnet_segmented ? "true" : "false") << ",\n";
                if (!p.bacnet_values.empty()) {
                    out_ << "    \"bacnet_values\": [";
                    for (size_t i = 0; i < p.bacnet_values.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.bacnet_values[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
    }
    if (p.protocol == "hartip") {
        out_ << "    \"hartip_version\": " << static_cast<unsigned>(p.hartip_version) << ",\n";
        out_ << "    \"hartip_message_type\": \"" << json_escape(p.hartip_message_type) << "\",\n";
        out_ << "    \"hartip_message_id\": \"" << json_escape(p.hartip_message_id) << "\",\n";
        out_ << "    \"hartip_status\": " << static_cast<unsigned>(p.hartip_status) << ",\n";
        out_ << "    \"hartip_transaction_id\": " << p.hartip_transaction_id << ",\n";
        out_ << "    \"hartip_msg_length\": " << p.hartip_msg_length << ",\n";
        if (p.hartip_has_session_init) {
            out_ << "    \"hartip_host_type\": \"" << json_escape(p.hartip_host_type_name) << "\",\n";
            out_ << "    \"hartip_inactivity_close_timer\": " << p.hartip_inactivity_close_timer << ",\n";
        }
        if (p.hartip_has_error) {
            out_ << "    \"hartip_error_code\": " << static_cast<unsigned>(p.hartip_error_code) << ",\n";
            out_ << "    \"hartip_error_code_name\": \"" << json_escape(p.hartip_error_code_name) << "\",\n";
        }
        out_ << "    \"hartip_has_pass_through\": " << (p.hartip_has_pass_through ? "true" : "false") << ",\n";
        if (p.hartip_has_pass_through) {
            out_ << "    \"hartip_frame_type\": \"" << json_escape(p.hartip_frame_type) << "\",\n";
            out_ << "    \"hartip_is_response\": " << (p.hartip_is_response ? "true" : "false") << ",\n";
            out_ << "    \"hartip_is_long_address\": " << (p.hartip_is_long_address ? "true" : "false") << ",\n";
            out_ << "    \"hartip_address\": \"" << json_escape(p.hartip_address_hex) << "\",\n";
            out_ << "    \"hartip_command\": " << static_cast<unsigned>(p.hartip_command) << ",\n";
            if (!p.hartip_command_name.empty())
                out_ << "    \"hartip_command_name\": \"" << json_escape(p.hartip_command_name) << "\",\n";
            if (p.hartip_is_response) {
                out_ << "    \"hartip_response_code\": " << static_cast<unsigned>(p.hartip_response_code) << ",\n";
                out_ << "    \"hartip_response_is_comm_error\": "
                     << (p.hartip_response_is_comm_error ? "true" : "false") << ",\n";
                if (!p.hartip_response_code_name.empty())
                    out_ << "    \"hartip_response_code_name\": \"" << json_escape(p.hartip_response_code_name)
                         << "\",\n";
                if (!p.hartip_comm_error_flags.empty()) {
                    out_ << "    \"hartip_comm_error_flags\": [";
                    for (size_t i = 0; i < p.hartip_comm_error_flags.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.hartip_comm_error_flags[i]) << "\"";
                    }
                    out_ << "],\n";
                }
                out_ << "    \"hartip_device_status\": " << static_cast<unsigned>(p.hartip_device_status) << ",\n";
                if (!p.hartip_device_status_flags.empty()) {
                    out_ << "    \"hartip_device_status_flags\": [";
                    for (size_t i = 0; i < p.hartip_device_status_flags.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.hartip_device_status_flags[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
            if (!p.hartip_values.empty()) {
                out_ << "    \"hartip_values\": [";
                for (size_t i = 0; i < p.hartip_values.size(); ++i) {
                    if (i != 0) out_ << ", ";
                    out_ << "\"" << json_escape(p.hartip_values[i]) << "\"";
                }
                out_ << "],\n";
            }
        }
    }
    if (p.protocol == "opcua") {
        out_ << "    \"opcua_message_type\": \"" << json_escape(p.opcua_message_type) << "\",\n";
        out_ << "    \"opcua_chunk_type\": \"" << std::string(1, p.opcua_chunk_type) << "\",\n";
        out_ << "    \"opcua_message_size\": " << p.opcua_message_size << ",\n";
        out_ << "    \"opcua_has_secure_channel\": " << (p.opcua_has_secure_channel ? "true" : "false")
             << ",\n";
        if (p.opcua_has_secure_channel) {
            out_ << "    \"opcua_secure_channel_id\": " << p.opcua_secure_channel_id << ",\n";
            out_ << "    \"opcua_is_asymmetric\": " << (p.opcua_is_asymmetric ? "true" : "false") << ",\n";
            if (p.opcua_is_asymmetric) {
                out_ << "    \"opcua_security_policy_uri\": \"" << json_escape(p.opcua_security_policy_uri)
                     << "\",\n";
                out_ << "    \"opcua_has_sender_certificate\": "
                     << (p.opcua_has_sender_certificate ? "true" : "false") << ",\n";
                if (p.opcua_has_sender_certificate)
                    out_ << "    \"opcua_sender_certificate_length\": " << p.opcua_sender_certificate_length
                         << ",\n";
                out_ << "    \"opcua_has_receiver_certificate_thumbprint\": "
                     << (p.opcua_has_receiver_certificate_thumbprint ? "true" : "false") << ",\n";
            } else {
                out_ << "    \"opcua_token_id\": " << p.opcua_token_id << ",\n";
            }
            out_ << "    \"opcua_sequence_number\": " << p.opcua_sequence_number << ",\n";
            out_ << "    \"opcua_request_id\": " << p.opcua_request_id << ",\n";
        }
        out_ << "    \"opcua_service_recognized\": " << (p.opcua_service_recognized ? "true" : "false")
             << ",\n";
        if (p.opcua_service_recognized) {
            out_ << "    \"opcua_service_name\": \"" << json_escape(p.opcua_service_name) << "\",\n";
        }
        if (p.opcua_service_namespace != 0 || p.opcua_service_type_id != 0 || p.opcua_service_recognized) {
            out_ << "    \"opcua_service_namespace\": " << p.opcua_service_namespace << ",\n";
            out_ << "    \"opcua_service_type_id\": " << p.opcua_service_type_id << ",\n";
        }
        out_ << "    \"opcua_has_header\": " << (p.opcua_has_header ? "true" : "false") << ",\n";
        if (p.opcua_has_header) {
            out_ << "    \"opcua_request_handle\": " << p.opcua_request_handle << ",\n";
            out_ << "    \"opcua_is_response\": " << (p.opcua_is_response ? "true" : "false") << ",\n";
            if (p.opcua_is_response) {
                out_ << "    \"opcua_status_code\": " << p.opcua_status_code << ",\n";
                out_ << "    \"opcua_status_code_name\": \"" << json_escape(p.opcua_status_code_name)
                     << "\",\n";
                out_ << "    \"opcua_status_is_good\": " << (p.opcua_status_is_good ? "true" : "false")
                     << ",\n";
            }
        }
        if (!p.opcua_values.empty()) {
            out_ << "    \"opcua_values\": [";
            for (size_t i = 0; i < p.opcua_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.opcua_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"opcua_body_shown_as_hex\": " << (p.opcua_body_shown_as_hex ? "true" : "false")
             << ",\n";
        if (p.opcua_body_shown_as_hex) {
            out_ << "    \"opcua_body_length\": " << p.opcua_body_length << ",\n";
            out_ << "    \"opcua_body_hex\": \"" << json_escape(p.opcua_body_hex) << "\",\n";
        }
    }
    if (p.protocol == "mms") {
        out_ << "    \"mms_is_bare\": " << (p.mms_is_bare ? "true" : "false") << ",\n";
        if (!p.mms_is_bare) {
            out_ << "    \"mms_session_pdu\": \"" << json_escape(p.mms_session_pdu_name) << "\",\n";
            out_ << "    \"mms_has_presentation\": " << (p.mms_has_presentation ? "true" : "false") << ",\n";
            if (p.mms_has_presentation) {
                if (!p.mms_presentation_context_list.empty()) {
                    out_ << "    \"mms_presentation_contexts\": [";
                    for (size_t i = 0; i < p.mms_presentation_context_list.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mms_presentation_context_list[i]) << "\"";
                    }
                    out_ << "],\n";
                }
                out_ << "    \"mms_presentation_context_id\": " << p.mms_presentation_context_id << ",\n";
                out_ << "    \"mms_presentation_context_is_acse\": "
                     << (p.mms_presentation_context_is_acse ? "true" : "false") << ",\n";
            }
            out_ << "    \"mms_has_acse\": " << (p.mms_has_acse ? "true" : "false") << ",\n";
            if (p.mms_has_acse) {
                out_ << "    \"mms_acse_pdu\": \"" << json_escape(p.mms_acse_pdu_name) << "\",\n";
                if (!p.mms_acse_application_context_name.empty()) {
                    out_ << "    \"mms_acse_application_context_name\": \""
                         << json_escape(p.mms_acse_application_context_name) << "\",\n";
                }
                if (p.mms_acse_has_result) {
                    out_ << "    \"mms_acse_result\": \"" << json_escape(p.mms_acse_result_name) << "\",\n";
                }
                if (!p.mms_acse_values.empty()) {
                    out_ << "    \"mms_acse_values\": [";
                    for (size_t i = 0; i < p.mms_acse_values.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mms_acse_values[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
        out_ << "    \"mms_has_pdu\": " << (p.mms_has_pdu ? "true" : "false") << ",\n";
        if (p.mms_has_pdu) {
            out_ << "    \"mms_pdu\": \"" << json_escape(p.mms_pdu_name) << "\",\n";
            out_ << "    \"mms_is_response\": " << (p.mms_is_response ? "true" : "false") << ",\n";
            if (p.mms_has_invoke_id) {
                out_ << "    \"mms_invoke_id\": " << p.mms_invoke_id << ",\n";
            }
            out_ << "    \"mms_service_recognized\": " << (p.mms_service_recognized ? "true" : "false")
                 << ",\n";
            if (p.mms_service_recognized) {
                out_ << "    \"mms_service\": \"" << json_escape(p.mms_service_name) << "\",\n";
            }
            if (p.mms_has_error) {
                out_ << "    \"mms_error\": \"" << json_escape(p.mms_error_name) << "\",\n";
            }
        }
        if (!p.mms_values.empty()) {
            out_ << "    \"mms_values\": [";
            for (size_t i = 0; i < p.mms_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.mms_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"mms_body_shown_as_hex\": " << (p.mms_body_shown_as_hex ? "true" : "false") << ",\n";
        if (p.mms_body_shown_as_hex) {
            out_ << "    \"mms_body_length\": " << p.mms_body_length << ",\n";
            out_ << "    \"mms_body_hex\": \"" << json_escape(p.mms_body_hex) << "\",\n";
        }
    }
    if (p.protocol == "mqtt") {
        out_ << "    \"mqtt_packet_type\": \"" << json_escape(p.mqtt_packet_type_name) << "\",\n";
        out_ << "    \"mqtt_remaining_length\": " << p.mqtt_remaining_length << ",\n";
        if (!p.mqtt_protocol_version_name.empty()) {
            out_ << "    \"mqtt_protocol_version\": \"" << json_escape(p.mqtt_protocol_version_name) << "\",\n";
        }
        if (p.mqtt_packet_type_name == "PUBLISH") {
            out_ << "    \"mqtt_dup\": " << (p.mqtt_dup ? "true" : "false") << ",\n";
            out_ << "    \"mqtt_qos\": " << static_cast<unsigned>(p.mqtt_qos) << ",\n";
            out_ << "    \"mqtt_retain\": " << (p.mqtt_retain ? "true" : "false") << ",\n";
            out_ << "    \"mqtt_topic\": \"" << json_escape(p.mqtt_topic) << "\",\n";
        }
        if (p.mqtt_has_packet_id) {
            out_ << "    \"mqtt_packet_id\": " << p.mqtt_packet_id << ",\n";
        }
        if (p.mqtt_has_payload) {
            out_ << "    \"mqtt_payload_length\": " << p.mqtt_payload_length << ",\n";
            // Omitted only when a successful Sparkplug B decode cleared it (see mqtt.hpp) -- a
            // genuinely empty payload still renders an empty hex string, same as p.mqtt_payload_length == 0.
            bool hex_cleared_by_sparkplug = p.mqtt_payload_length > 0 && p.mqtt_payload_hex.empty();
            if (!hex_cleared_by_sparkplug) {
                out_ << "    \"mqtt_payload_hex\": \"" << json_escape(p.mqtt_payload_hex) << "\",\n";
            }
        }
        if (!p.mqtt_values.empty()) {
            out_ << "    \"mqtt_values\": [";
            for (size_t i = 0; i < p.mqtt_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.mqtt_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"mqtt_is_sparkplug\": " << (p.mqtt_is_sparkplug ? "true" : "false") << ",\n";
        if (p.mqtt_is_sparkplug) {
            out_ << "    \"mqtt_sparkplug_message_type\": \"" << json_escape(p.mqtt_sparkplug_message_type)
                 << "\",\n";
            out_ << "    \"mqtt_sparkplug_is_state\": " << (p.mqtt_sparkplug_is_state ? "true" : "false")
                 << ",\n";
            if (p.mqtt_sparkplug_is_state) {
                out_ << "    \"mqtt_sparkplug_state_host_id\": \"" << json_escape(p.mqtt_sparkplug_state_host_id)
                     << "\",\n";
                out_ << "    \"mqtt_sparkplug_state_text\": \"" << json_escape(p.mqtt_sparkplug_state_text)
                     << "\",\n";
            } else {
                out_ << "    \"mqtt_sparkplug_group_id\": \"" << json_escape(p.mqtt_sparkplug_group_id) << "\",\n";
                out_ << "    \"mqtt_sparkplug_edge_node_id\": \"" << json_escape(p.mqtt_sparkplug_edge_node_id)
                     << "\",\n";
                if (!p.mqtt_sparkplug_device_id.empty()) {
                    out_ << "    \"mqtt_sparkplug_device_id\": \"" << json_escape(p.mqtt_sparkplug_device_id)
                         << "\",\n";
                }
                out_ << "    \"mqtt_sparkplug_payload_decoded\": "
                     << (p.mqtt_sparkplug_payload_decoded ? "true" : "false") << ",\n";
                if (p.mqtt_sparkplug_has_timestamp) {
                    out_ << "    \"mqtt_sparkplug_timestamp\": " << p.mqtt_sparkplug_timestamp << ",\n";
                }
                if (p.mqtt_sparkplug_has_seq) {
                    out_ << "    \"mqtt_sparkplug_seq\": " << p.mqtt_sparkplug_seq << ",\n";
                }
                if (p.mqtt_sparkplug_has_uuid) {
                    out_ << "    \"mqtt_sparkplug_uuid\": \"" << json_escape(p.mqtt_sparkplug_uuid) << "\",\n";
                }
                if (p.mqtt_sparkplug_has_body) {
                    out_ << "    \"mqtt_sparkplug_body_length\": " << p.mqtt_sparkplug_body_length << ",\n";
                }
                out_ << "    \"mqtt_sparkplug_metric_count\": " << p.mqtt_sparkplug_metric_count << ",\n";
                if (!p.mqtt_sparkplug_metrics.empty()) {
                    out_ << "    \"mqtt_sparkplug_metrics\": [";
                    for (size_t i = 0; i < p.mqtt_sparkplug_metrics.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mqtt_sparkplug_metrics[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
    }
    if (p.protocol == "s7comm-plus") {
        out_ << "    \"s7plus_pdu_type\": \"" << json_escape(p.s7plus_pdu_type_name) << "\",\n";
        if (p.s7plus_is_keepalive) {
            out_ << "    \"s7plus_keepalive_seq\": " << static_cast<unsigned>(p.s7plus_keepalive_seq) << ",\n";
        }
        if (p.s7plus_has_opcode) {
            out_ << "    \"s7plus_opcode\": \"" << json_escape(p.s7plus_opcode_name) << "\",\n";
        }
        if (p.s7plus_has_function) {
            out_ << "    \"s7plus_function\": \"" << json_escape(p.s7plus_function_name) << "\",\n";
            out_ << "    \"s7plus_body_decoded\": " << (p.s7plus_body_decoded ? "true" : "false") << ",\n";
        }
        if (p.s7plus_has_sequence_number) {
            out_ << "    \"s7plus_sequence_number\": " << p.s7plus_sequence_number << ",\n";
        }
        if (p.s7plus_has_session_id) {
            out_ << "    \"s7plus_session_id\": " << p.s7plus_session_id << ",\n";
        }
        if (p.s7plus_has_return_value) {
            out_ << "    \"s7plus_return_code\": " << p.s7plus_return_code << ",\n";
            out_ << "    \"s7plus_return_code_name\": \"" << json_escape(p.s7plus_return_code_name) << "\",\n";
        }
        if (!p.s7plus_item_tags.empty()) {
            out_ << "    \"s7plus_items\": [";
            for (size_t i = 0; i < p.s7plus_item_tags.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_item_tags[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (!p.s7plus_value_summaries.empty()) {
            out_ << "    \"s7plus_values\": [";
            for (size_t i = 0; i < p.s7plus_value_summaries.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_value_summaries[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (!p.s7plus_item_errors.empty()) {
            out_ << "    \"s7plus_item_errors\": [";
            for (size_t i = 0; i < p.s7plus_item_errors.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_item_errors[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (p.s7plus_has_integrity) {
            out_ << "    \"s7plus_integrity_digest_present\": "
                 << (p.s7plus_integrity_digest_present ? "true" : "false") << ",\n";
        }
        out_ << "    \"s7plus_has_trailer\": " << (p.s7plus_has_trailer ? "true" : "false") << ",\n";
    }
    if (p.protocol == "ffhse") {
        out_ << "    \"ffhse_version\": " << static_cast<unsigned>(p.ffhse_version) << ",\n";
        out_ << "    \"ffhse_options\": " << static_cast<unsigned>(p.ffhse_options) << ",\n";
        out_ << "    \"ffhse_protocol\": \"" << json_escape(p.ffhse_protocol_name) << "\",\n";
        out_ << "    \"ffhse_type\": \"" << json_escape(p.ffhse_type_name) << "\",\n";
        out_ << "    \"ffhse_confirmed\": " << (p.ffhse_confirmed ? "true" : "false") << ",\n";
        out_ << "    \"ffhse_service_id\": " << static_cast<unsigned>(p.ffhse_service_id) << ",\n";
        std::ostringstream fda_addr;
        fda_addr << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << p.ffhse_fda_address;
        out_ << "    \"ffhse_fda_address\": \"" << fda_addr.str() << "\",\n";
        out_ << "    \"ffhse_link_id\": " << p.ffhse_link_id << ",\n";
        out_ << "    \"ffhse_message_length\": " << p.ffhse_message_length << ",\n";
        if (p.ffhse_has_message_number) out_ << "    \"ffhse_message_number\": " << p.ffhse_message_number << ",\n";
        if (p.ffhse_has_invoke_id) out_ << "    \"ffhse_invoke_id\": " << p.ffhse_invoke_id << ",\n";
        if (p.ffhse_has_time_stamp) out_ << "    \"ffhse_time_stamp\": " << p.ffhse_time_stamp << ",\n";
        if (p.ffhse_has_extended_control_field)
            out_ << "    \"ffhse_extended_control_field\": " << p.ffhse_extended_control_field << ",\n";
        out_ << "    \"ffhse_message_name\": \"" << json_escape(p.ffhse_message_name) << "\",\n";
        out_ << "    \"ffhse_recognized\": " << (p.ffhse_recognized ? "true" : "false") << ",\n";
        out_ << "    \"ffhse_body_decoded\": " << (p.ffhse_body_decoded ? "true" : "false") << ",\n";
        if (!p.ffhse_values.empty()) {
            out_ << "    \"ffhse_values\": [";
            for (size_t i = 0; i < p.ffhse_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ffhse_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"ffhse_body_shown_as_hex\": " << (p.ffhse_body_shown_as_hex ? "true" : "false") << ",\n";
        if (p.ffhse_body_shown_as_hex) {
            out_ << "    \"ffhse_body_length\": " << p.ffhse_body_length << ",\n";
            out_ << "    \"ffhse_body_hex\": \"" << json_escape(p.ffhse_body_hex) << "\",\n";
        }
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
    if (p.protocol == "goose") {
        if (p.goose_has_pdu) goose_pdu_count_++;
        if (p.goose_is_gse_management) goose_gse_management_count_++;
        if (p.goose_simulated) goose_simulated_count_++;
    }
    if (p.protocol == "sv") {
        sv_frame_count_++;
        sv_asdu_total_ += p.sv_asdu_count;
    }
    if (p.protocol == "ethercat") {
        ethercat_frame_type_counts_[p.ethercat_frame_type_name]++;
        ethercat_datagram_total_ += p.ethercat_datagram_count;
    }
    if (p.protocol == "bacnet") {
        bacnet_bvlc_function_counts_[p.bacnet_bvlc_function]++;
        if (p.bacnet_has_apdu && !p.bacnet_service_name.empty()) {
            bacnet_service_counts_[p.bacnet_service_name]++;
        }
    }
    if (p.protocol == "hartip") {
        hartip_message_type_counts_[p.hartip_message_type]++;
        if (p.hartip_has_pass_through) {
            std::string key = std::to_string(static_cast<unsigned>(p.hartip_command));
            if (!p.hartip_command_name.empty()) key += " (" + p.hartip_command_name + ")";
            hartip_command_counts_[key]++;
        }
    }
    if (p.protocol == "opcua") {
        opcua_message_type_counts_[p.opcua_message_type]++;
        if (p.opcua_service_recognized) {
            opcua_service_counts_[p.opcua_service_name]++;
        }
    }
    if (p.protocol == "mms") {
        if (p.mms_has_pdu) mms_pdu_counts_[p.mms_pdu_name]++;
        if (p.mms_service_recognized) mms_service_counts_[p.mms_service_name]++;
    }
    if (p.protocol == "mqtt") {
        mqtt_packet_type_counts_[p.mqtt_packet_type_name]++;
        if (p.mqtt_is_sparkplug) {
            mqtt_sparkplug_count_++;
            mqtt_sparkplug_message_type_counts_[p.mqtt_sparkplug_message_type]++;
        }
    }
    if (p.protocol == "s7comm-plus") {
        s7plus_pdu_type_counts_[p.s7plus_pdu_type_name]++;
        if (p.s7plus_has_function) {
            s7plus_function_counts_[p.s7plus_function_name]++;
            if (p.s7plus_body_decoded) s7plus_body_decoded_count_++;
        }
    }
    if (p.protocol == "ffhse") {
        ffhse_protocol_counts_[p.ffhse_protocol_name]++;
        if (p.ffhse_recognized) {
            ffhse_message_counts_[p.ffhse_message_name]++;
            if (p.ffhse_body_decoded) ffhse_body_decoded_count_++;
        }
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
    if (goose_pdu_count_ > 0 || goose_gse_management_count_ > 0) {
        out << "goose pdus: " << goose_pdu_count_ << "\n";
        out << "goose gse management pdus (not decoded further): " << goose_gse_management_count_ << "\n";
        out << "goose simulated (S-bit or simulation field set): " << goose_simulated_count_ << "\n";
    }
    if (sv_frame_count_ > 0) {
        out << "sv frames: " << sv_frame_count_ << "\n";
        out << "sv asdus (summed across every frame): " << sv_asdu_total_ << "\n";
    }
    if (!ethercat_frame_type_counts_.empty()) {
        out << "ethercat frame types:\n";
        for (const auto& [name, count] : ethercat_frame_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "ethercat datagrams (summed across every frame): " << ethercat_datagram_total_ << "\n";
    }
    if (!bacnet_bvlc_function_counts_.empty()) {
        out << "bacnet bvlc functions:\n";
        for (const auto& [name, count] : bacnet_bvlc_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!bacnet_service_counts_.empty()) {
        out << "bacnet apdu services:\n";
        for (const auto& [name, count] : bacnet_service_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!hartip_message_type_counts_.empty()) {
        out << "hartip message types:\n";
        for (const auto& [name, count] : hartip_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!hartip_command_counts_.empty()) {
        out << "hartip pass-through commands:\n";
        for (const auto& [name, count] : hartip_command_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!opcua_message_type_counts_.empty()) {
        out << "opcua message types:\n";
        for (const auto& [name, count] : opcua_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!opcua_service_counts_.empty()) {
        out << "opcua services:\n";
        for (const auto& [name, count] : opcua_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!mms_pdu_counts_.empty()) {
        out << "mms pdu types:\n";
        for (const auto& [name, count] : mms_pdu_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!mms_service_counts_.empty()) {
        out << "mms services:\n";
        for (const auto& [name, count] : mms_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!mqtt_packet_type_counts_.empty()) {
        out << "mqtt packet types:\n";
        for (const auto& [name, count] : mqtt_packet_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "mqtt sparkplug b publishes: " << mqtt_sparkplug_count_ << "\n";
    }
    if (!mqtt_sparkplug_message_type_counts_.empty()) {
        out << "mqtt sparkplug b message types:\n";
        for (const auto& [name, count] : mqtt_sparkplug_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!s7plus_pdu_type_counts_.empty()) {
        out << "s7comm-plus pdu types:\n";
        for (const auto& [name, count] : s7plus_pdu_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!s7plus_function_counts_.empty()) {
        out << "s7comm-plus functions:\n";
        for (const auto& [name, count] : s7plus_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "s7comm-plus function bodies fully decoded (Tier 1): " << s7plus_body_decoded_count_ << "\n";
    }
    if (!ffhse_protocol_counts_.empty()) {
        out << "ffhse sub-protocols:\n";
        for (const auto& [name, count] : ffhse_protocol_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!ffhse_message_counts_.empty()) {
        out << "ffhse messages:\n";
        for (const auto& [name, count] : ffhse_message_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
        out << "ffhse message bodies fully decoded (Tier 1): " << ffhse_body_decoded_count_ << "\n";
    }
}

}  // namespace conduitscope
