// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/igmp.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

constexpr size_t kMaxRepeated = 50;  // capped at 50 entries, same convention as elsewhere.

enum IgmpType : uint8_t {
    IGMP_MEMBERSHIP_QUERY = 0x11,
    IGMP_V1_MEMBERSHIP_REPORT = 0x12,
    IGMP_V2_MEMBERSHIP_REPORT = 0x16,
    IGMP_V2_LEAVE_GROUP = 0x17,
    IGMP_V3_MEMBERSHIP_REPORT = 0x22,
};

std::string type_name(uint8_t type) {
    switch (type) {
        case IGMP_MEMBERSHIP_QUERY: return "Membership Query";
        case IGMP_V1_MEMBERSHIP_REPORT: return "Version 1 Membership Report";
        case IGMP_V2_MEMBERSHIP_REPORT: return "Version 2 Membership Report";
        case IGMP_V2_LEAVE_GROUP: return "Version 2 Leave Group";
        case IGMP_V3_MEMBERSHIP_REPORT: return "Version 3 Membership Report";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(type) << ")";
            return out.str();
        }
    }
}

std::string record_type_name(uint8_t record_type) {
    switch (record_type) {
        case 1: return "Mode Is Include";
        case 2: return "Mode Is Exclude";
        case 3: return "Change To Include Mode";
        case 4: return "Change To Exclude Mode";
        case 5: return "Allow New Sources";
        case 6: return "Block Old Sources";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(record_type)) + ")";
    }
}

// RFC 3376 sections 4.1.1 (Max Resp Code) and 4.1.7 (QQIC) share this exact exponential encoding:
// a value below 128 (high bit clear) is used as-is; otherwise bits 6-4 are an exponent and bits
// 3-0 a mantissa, decoded as (mantissa | 0x10) << (exponent + 3).
uint32_t decode_exponential(uint8_t value) {
    if ((value & 0x80) == 0) {
        return value;
    }
    uint32_t exponent = (value >> 4) & 0x07;
    uint32_t mantissa = value & 0x0F;
    return (mantissa | 0x10) << (exponent + 3);
}

}  // namespace

std::optional<IgmpMessage> try_parse_igmp(ByteSpan ip_payload) {
    if (ip_payload.size() < 8) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    uint8_t type = c.u8();
    if (type != IGMP_MEMBERSHIP_QUERY && type != IGMP_V1_MEMBERSHIP_REPORT &&
        type != IGMP_V2_MEMBERSHIP_REPORT && type != IGMP_V2_LEAVE_GROUP &&
        type != IGMP_V3_MEMBERSHIP_REPORT) {
        return std::nullopt;
    }

    IgmpMessage msg;
    msg.type = type;
    msg.type_name = type_name(type);

    uint8_t code_byte = c.u8();
    msg.checksum = c.u16be();

    std::ostringstream out;

    switch (type) {
        case IGMP_V1_MEMBERSHIP_REPORT:
        case IGMP_V2_MEMBERSHIP_REPORT:
        case IGMP_V2_LEAVE_GROUP: {
            msg.version = (type == IGMP_V1_MEMBERSHIP_REPORT) ? 1 : 2;
            msg.group_address = format_ipv4(c.u32be());
            if (code_byte != 0) {
                msg.notes.push_back("reserved/unused byte after Type is 0x" +
                                     [&] {
                                         std::ostringstream hex;
                                         hex << std::hex << static_cast<unsigned>(code_byte);
                                         return hex.str();
                                     }() +
                                     ", not zero");
            }
            out << "IGMPv" << msg.version << " " << msg.type_name << ": group " << msg.group_address;
            break;
        }
        case IGMP_MEMBERSHIP_QUERY: {
            msg.group_address = format_ipv4(c.u32be());
            if (ip_payload.size() < 12) {
                // Exactly 8 bytes: v1 (Code always 0) or v2 (Code is a plain integer, tenths of a
                // second -- NOT the v3 exponential encoding, which only applies inside a v3 Query).
                if (code_byte == 0) {
                    msg.version = 1;
                    msg.max_resp_time_ms = 0;
                } else {
                    msg.version = 2;
                    msg.max_resp_time_ms = static_cast<uint32_t>(code_byte) * 100;
                }
                out << "IGMPv" << msg.version << " Membership Query: group "
                    << (msg.group_address == "0.0.0.0" ? "0.0.0.0 (general query)" : msg.group_address);
                if (msg.version == 2) {
                    out << ", max response time " << msg.max_resp_time_ms << " ms";
                }
                break;
            }

            // 12+ bytes: IGMPv3 Query (RFC 3376 section 4.1).
            msg.version = 3;
            msg.max_resp_time_ms = decode_exponential(code_byte) * 100;
            uint8_t s_qrv = c.u8();
            msg.suppress_router_side_processing = (s_qrv & 0x08) != 0;
            msg.querier_robustness_variable = s_qrv & 0x07;
            uint8_t qqic = c.u8();
            msg.querier_query_interval_sec = decode_exponential(qqic);
            uint16_t num_sources = c.u16be();

            size_t decoded = std::min(static_cast<size_t>(num_sources), kMaxRepeated);
            for (size_t i = 0; i < decoded && c.remaining() >= 4; ++i) {
                msg.query_source_addresses.push_back(format_ipv4(c.u32be()));
            }
            if (static_cast<size_t>(num_sources) > kMaxRepeated) {
                msg.notes.push_back("output capped at " + std::to_string(kMaxRepeated) +
                                     " source address(es); " +
                                     std::to_string(num_sources - kMaxRepeated) +
                                     " more were declared in this packet and were not decoded");
            } else if (msg.query_source_addresses.size() < num_sources) {
                msg.notes.push_back("Number of Sources field (" + std::to_string(num_sources) +
                                     ") exceeds the source addresses actually present -- possible "
                                     "truncation");
            }

            out << "IGMPv3 Membership Query: group "
                << (msg.group_address == "0.0.0.0" ? "0.0.0.0 (general query)" : msg.group_address)
                << ", " << msg.query_source_addresses.size() << " source(s), max response time "
                << msg.max_resp_time_ms << " ms";
            break;
        }
        case IGMP_V3_MEMBERSHIP_REPORT: {
            msg.version = 3;
            // The 4 bytes after Type+Reserved+Checksum are Reserved(2)+Number of Group
            // Records(2); Group Address isn't used at all for v3 Report (the field read as
            // group_address above for the other message shapes doesn't apply here).
            Cursor rc(ip_payload);
            rc.skip(4);  // Type + Reserved + Checksum
            rc.skip(2);  // Reserved
            uint16_t num_records = rc.u16be();

            size_t decoded_records = std::min(static_cast<size_t>(num_records), kMaxRepeated);
            for (size_t i = 0; i < decoded_records; ++i) {
                if (rc.remaining() < 8) {
                    msg.notes.push_back("truncated before the end of the declared group record "
                                         "list");
                    break;
                }
                IgmpGroupRecord rec;
                rec.record_type = rc.u8();
                rec.record_type_name = record_type_name(rec.record_type);
                rec.aux_data_len = rc.u8();
                uint16_t rec_num_sources = rc.u16be();
                rec.multicast_address = format_ipv4(rc.u32be());

                size_t decoded_sources = std::min(static_cast<size_t>(rec_num_sources), kMaxRepeated);
                for (size_t s = 0; s < decoded_sources && rc.remaining() >= 4; ++s) {
                    rec.source_addresses.push_back(format_ipv4(rc.u32be()));
                }
                if (rec_num_sources > kMaxRepeated) {
                    msg.notes.push_back("group record for " + rec.multicast_address +
                                         ": output capped at " + std::to_string(kMaxRepeated) +
                                         " source address(es); " +
                                         std::to_string(rec_num_sources - kMaxRepeated) +
                                         " more were declared");
                }
                size_t aux_bytes = static_cast<size_t>(rec.aux_data_len) * 4;
                if (rc.remaining() >= aux_bytes) {
                    rc.skip(aux_bytes);  // auxiliary data is not decoded
                } else {
                    msg.notes.push_back("group record for " + rec.multicast_address +
                                         ": declared auxiliary data length exceeds remaining "
                                         "packet bytes -- possible truncation");
                    rc.skip(rc.remaining());
                }

                msg.group_records.push_back(std::move(rec));
            }
            if (num_records > kMaxRepeated) {
                msg.group_records_truncated = true;
                msg.notes.push_back("output capped at " + std::to_string(kMaxRepeated) +
                                     " group record(s); " +
                                     std::to_string(num_records - kMaxRepeated) +
                                     " more were declared in this packet and were not decoded");
            }

            out << "IGMPv3 Membership Report: " << msg.group_records.size() << " group record(s)";
            break;
        }
        default:
            break;  // unreachable -- type was validated above
    }

    msg.summary = out.str();
    return msg;
}

}  // namespace conduitscope
