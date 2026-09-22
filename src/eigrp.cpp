// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/eigrp.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxList = resource_limits().max_decoded_objects.value_or(50);
constexpr size_t kHeaderLength = 20;

uint32_t read_u24be(Cursor& c) {
    uint32_t a = c.u8(), b = c.u8(), d = c.u8();
    return (a << 16) | (b << 8) | d;
}

uint64_t read_u48be(Cursor& c) {
    uint64_t v = 0;
    for (int i = 0; i < 6; ++i) v = (v << 8) | c.u8();
    return v;
}

std::string opcode_name(uint8_t opcode, uint32_t acknowledge) {
    if (opcode == 5 && acknowledge != 0) return "Hello (Ack)";
    switch (opcode) {
        case 1: return "Update";
        case 2: return "Request";
        case 3: return "Query";
        case 4: return "Reply";
        case 5: return "Hello";
        case 6: return "IPX/SAP Update";
        case 7: return "Route Probe";
        case 8: return "Hello (Ack)";
        case 9: return "Stub-Info";
        case 10: return "SIA-Query";
        case 11: return "SIA-Reply";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(opcode)) + ")";
    }
}

std::string vrid_meaning(uint16_t vrid) {
    if (vrid == 0x0000) return "(Address-Family)";
    if (vrid == 0x0001) return "(Multi-Cast)";
    if (vrid == 0x8000) return "(Service-Family)";
    return "";
}

std::string tlv_type_name(uint16_t type) {
    switch (type) {
        case 0x0001: return "Parameters";
        case 0x0002: return "Authentication";
        case 0x0003: return "Sequence";
        case 0x0004: return "Software Version";
        case 0x0005: return "Next Multicast Sequence";
        case 0x0006: return "Peer Stub Information";
        case 0x0007: return "Peer Termination";
        case 0x0008: return "Peer Topology ID List";
        case 0x0101: return "Request (IPv4)";
        case 0x0102: return "Internal Route (IPv4)";
        case 0x0103: return "External Route (IPv4)";
        case 0x0104: return "Ext-Community (IPv4)";
        case 0x0401: return "Request (IPv6)";
        case 0x0402: return "Internal Route (IPv6)";
        case 0x0403: return "External Route (IPv6)";
        case 0x0404: return "Ext-Community (IPv6)";
        case 0x0301: return "Request (IPX)";
        case 0x0302: return "Internal Route (IPX)";
        case 0x0303: return "External Route (IPX)";
        case 0x0201: return "Request (ATALK)";
        case 0x0202: return "Internal Route (ATALK)";
        case 0x0203: return "External Route (ATALK)";
        case 0x0204: return "Cable Configuration (ATALK)";
        case 0x00F1: return "Request (MTR)";
        case 0x00F2: return "Internal Route (MTR)";
        case 0x00F3: return "External Route (MTR)";
        case 0x00F4: return "Ext-Community (MTR)";
        case 0x00F5: return "Topology ID List (MTR)";
        case 0x0601: return "Request";
        case 0x0602: return "Internal Route";
        case 0x0603: return "External Route";
        case 0x0604: return "Ext-Community";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << type << ")";
            return out.str();
        }
    }
}

std::string external_protocol_name(uint8_t proto) {
    switch (proto) {
        case 1: return "IGRP";
        case 2: return "EIGRP";
        case 3: return "Static Route";
        case 4: return "RIP";
        case 5: return "Hello";
        case 6: return "OSPF";
        case 7: return "IS-IS";
        case 8: return "EGP";
        case 9: return "BGP";
        case 10: return "IDRP";
        case 11: return "Connected Route";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(proto)) + ")";
    }
}

EigrpClassicMetric decode_classic_metric(Cursor& c) {
    EigrpClassicMetric m;
    m.delay_raw = c.u32be();
    m.unreachable = (m.delay_raw == 0xFFFFFFFFu);
    m.delay_microseconds = m.unreachable ? 0 : m.delay_raw * 10;
    m.bandwidth_raw = c.u32be();
    m.bandwidth_kbps = (m.bandwidth_raw != 0) ? (10000000u / m.bandwidth_raw) : 0;
    m.mtu = read_u24be(c);
    m.hop_count = c.u8();
    m.reliability = c.u8();
    m.load = c.u8();
    m.internal_tag = c.u8();
    uint8_t flags = c.u8();
    m.flag_source_withdraw = (flags & 0x04) != 0;
    m.flag_active = (flags & 0x02) != 0;
    m.flag_replicated = (flags & 0x01) != 0;
    return m;
}

EigrpWideMetric decode_wide_metric(Cursor& c) {
    EigrpWideMetric m;
    m.offset = c.u8();
    m.has_extended_attributes = (m.offset > 0);
    m.priority = c.u8();
    m.reliability = c.u8();
    m.load = c.u8();
    m.mtu = read_u24be(c);
    m.hop_count = c.u8();
    m.delay_raw = read_u48be(c);
    m.unreachable = (m.delay_raw == UINT64_C(0x0000FFFFFFFFFFFF));
    m.bandwidth_kbps = read_u48be(c);
    c.u16be();  // reserved
    c.u16be();  // route flags -- only Active/Replicated/Source-Withdraw are ever set in practice
                 // (same three bits as Classic's flags byte, just in a wider field); not decoded
                 // separately here to keep EigrpWideMetric's shape simple
    return m;
}

EigrpExternalRouteData decode_external_data(Cursor& c) {
    EigrpExternalRouteData e;
    e.originating_router = format_ipv4(c.u32be());
    e.autonomous_system = c.u32be();
    e.route_tag = c.u32be();
    e.external_metric = c.u32be();
    c.u16be();  // reserved
    e.external_protocol = c.u8();
    e.external_protocol_name = external_protocol_name(e.external_protocol);
    uint8_t flags = c.u8();
    e.is_external = (flags & 0x01) != 0;
    e.is_candidate_default = (flags & 0x02) != 0;
    return e;
}

// Destinations are prefix-length-compressed: PrefixLen(1) + ceil(PrefixLen/8) address bytes.
// A single route TLV can carry several of these back-to-back (see eigrp.hpp's header comment).
void decode_destinations(Cursor& c, std::vector<std::string>& out, bool& truncated) {
    while (c.remaining() > 0) {
        uint8_t prefix_len = c.u8();
        if (prefix_len > 32) {
            break;  // not a valid IPv4 prefix length -- stop rather than guess
        }
        size_t addr_bytes = (prefix_len + 7) / 8;
        if (c.remaining() < addr_bytes) {
            break;  // truncated -- stop rather than read past what's there
        }
        uint32_t addr = 0;
        for (size_t i = 0; i < 4; ++i) {
            uint8_t byte_val = (i < addr_bytes) ? c.u8() : 0;
            addr = (addr << 8) | byte_val;
        }
        if (out.size() < kMaxList) {
            out.push_back(format_ipv4(addr) + "/" + std::to_string(static_cast<unsigned>(prefix_len)));
        } else {
            truncated = true;
        }
    }
}

void decode_general_tlv(uint16_t type, ByteSpan value, EigrpMessage& msg) {
    EigrpGeneralTlv tlv;
    tlv.type = type;
    tlv.type_name = tlv_type_name(type);
    tlv.raw_length = static_cast<uint16_t>(value.size() + 4);
    Cursor vc(value);

    switch (type) {
        case 0x0001: {  // Parameters
            if (vc.remaining() >= 8) {
                uint8_t k1 = vc.u8(), k2 = vc.u8(), k3 = vc.u8(), k4 = vc.u8(), k5 = vc.u8();
                vc.u8();  // K6
                uint16_t holdtime = vc.u16be();
                std::ostringstream v;
                v << "K1=" << static_cast<unsigned>(k1) << " K2=" << static_cast<unsigned>(k2)
                  << " K3=" << static_cast<unsigned>(k3) << " K4=" << static_cast<unsigned>(k4)
                  << " K5=" << static_cast<unsigned>(k5) << ", Hold Time=" << holdtime << "s";
                if (k1 == 255 && k2 == 255 && k3 == 255 && k4 == 255 && k5 == 255) {
                    v << " (Peer Termination)";
                }
                tlv.value = v.str();
            }
            break;
        }
        case 0x0002: {  // Authentication
            if (vc.remaining() >= 12) {
                uint16_t auth_type = vc.u16be();
                uint16_t auth_len = vc.u16be();
                vc.u32be();  // Key ID
                vc.u32be();  // Key Sequence
                std::string type_str = (auth_type == 2) ? "MD5" : (auth_type == 3) ? "SHA256" :
                                        (auth_type == 1) ? "TEXT" : "Unknown";
                tlv.value = type_str + " (declared digest length " + std::to_string(auth_len) +
                            " byte(s), not verified)";
            }
            break;
        }
        case 0x0003: {  // Sequence -- a list of peer addresses that must NOT receive the next
                          // multicast (only IPv4 addresses are decoded; 10-byte IPX and 16-byte
                          // IPv6 entries are skipped and counted, matching this project's IPv4-
                          // only posture elsewhere)
            std::vector<std::string> addrs;
            size_t skipped = 0;
            while (vc.remaining() > 0) {
                uint8_t addr_len = vc.u8();
                if (vc.remaining() < addr_len) break;
                if (addr_len == 4) {
                    addrs.push_back(format_ipv4(vc.u32be()));
                } else {
                    vc.skip(addr_len);
                    ++skipped;
                }
            }
            std::ostringstream v;
            v << addrs.size() << " IPv4 peer address(es)";
            for (size_t i = 0; i < addrs.size() && i < 5; ++i) v << (i == 0 ? ": " : ", ") << addrs[i];
            if (skipped > 0) v << " (+" << skipped << " non-IPv4 entrie(s) not decoded)";
            tlv.value = v.str();
            break;
        }
        case 0x0004: {  // Software Version
            if (vc.remaining() >= 4) {
                uint8_t ios_major = vc.u8(), ios_minor = vc.u8();
                uint8_t tlv_major = vc.u8(), tlv_minor = vc.u8();
                std::ostringstream v;
                v << "EIGRP=" << static_cast<unsigned>(ios_major) << "."
                  << static_cast<unsigned>(ios_minor) << ", TLV=" << static_cast<unsigned>(tlv_major)
                  << "." << static_cast<unsigned>(tlv_minor);
                tlv.value = v.str();
            }
            break;
        }
        case 0x0005: {  // Next Multicast Sequence
            if (vc.remaining() >= 4) {
                tlv.value = std::to_string(vc.u32be());
            }
            break;
        }
        default:
            break;  // recognized (named, counted) but not decoded further -- see eigrp.hpp
    }

    if (msg.general_tlvs.size() < kMaxList) {
        msg.general_tlvs.push_back(std::move(tlv));
    } else {
        msg.general_tlvs_truncated = true;
    }
}

// Handles both the Classic (0x0102/0x0103) and Wide-Metric (0x0602/0x0603) IPv4 route TLV shapes
// -- the only difference the caller needs to communicate is `wide` and `external`.
void decode_route_tlv(uint16_t /*type*/, bool wide, bool external, ByteSpan value, EigrpMessage& msg) {
    Cursor vc(value);
    EigrpRoute route;
    route.external = external;
    route.wide_metric_format = wide;

    if (wide) {
        if (vc.remaining() < 8) return;
        route.topology_id = vc.u16be();
        uint16_t afi = vc.u16be();
        route.router_id = format_ipv4(vc.u32be());
        if (afi != 1 /* IPv4 */) {
            msg.notes.push_back("a Wide-Metric route TLV declared AFI " + std::to_string(afi) +
                                 ", not 1 (IPv4) -- not decoded (this decoder has no IPv6/IPX support)");
            return;
        }
        if (vc.remaining() < 24) return;
        route.wide_metric = decode_wide_metric(vc);
        if (vc.remaining() < 4) return;
        route.next_hop = format_ipv4(vc.u32be());
    } else {
        if (vc.remaining() < 4) return;
        route.next_hop = format_ipv4(vc.u32be());
    }

    if (external) {
        if (vc.remaining() < 20) return;
        route.external_data = decode_external_data(vc);
    }

    if (!wide) {
        if (vc.remaining() < 16) return;
        route.classic_metric = decode_classic_metric(vc);
    }

    decode_destinations(vc, route.destinations, route.destinations_truncated);

    std::ostringstream out;
    out << (external ? "External" : "Internal") << " route" << (wide ? " (wide metric)" : "")
        << ": next-hop " << route.next_hop << ", " << route.destinations.size() << " destination(s)";
    if (!route.destinations.empty()) out << " (" << route.destinations.front() << (route.destinations.size() > 1 ? ", ..." : "") << ")";
    route.summary = out.str();

    if (msg.routes.size() < kMaxList) {
        msg.routes.push_back(std::move(route));
    } else {
        msg.routes_truncated = true;
    }
}

}  // namespace

std::optional<EigrpMessage> try_parse_eigrp(ByteSpan ip_payload) {
    if (ip_payload.size() < kHeaderLength) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    EigrpMessage msg;
    msg.version = c.u8();
    msg.opcode = c.u8();
    if (msg.opcode < 1 || msg.opcode > 11) {
        return std::nullopt;
    }
    msg.checksum = c.u16be();
    msg.flags_raw = c.u32be();
    msg.flag_init = (msg.flags_raw & 0x00000001u) != 0;
    msg.flag_conditional_receive = (msg.flags_raw & 0x00000002u) != 0;
    msg.flag_restart = (msg.flags_raw & 0x00000004u) != 0;
    msg.flag_end_of_table = (msg.flags_raw & 0x00000008u) != 0;
    msg.sequence = c.u32be();
    msg.acknowledge = c.u32be();
    msg.virtual_router_id = c.u16be();
    msg.virtual_router_id_meaning = vrid_meaning(msg.virtual_router_id);
    msg.autonomous_system = c.u16be();
    msg.opcode_name = opcode_name(msg.opcode, msg.acknowledge);

    if (msg.opcode == 6) {  // IPX/SAP Update -- entirely different (IPX SAP) payload, not decoded
        msg.notes.push_back("IPX/SAP Update payload is not decoded (IPX is out of scope for this "
                             "project)");
    } else {
        while (c.remaining() >= 4) {
            uint16_t type = c.u16be();
            uint16_t length = c.u16be();
            if (length < 4) {
                msg.notes.push_back("a TLV declared Length " + std::to_string(length) +
                                     ", less than the 4-byte TLV header itself -- stopping TLV "
                                     "parsing here");
                break;
            }
            size_t value_len = length - 4;
            if (c.remaining() < value_len) {
                msg.notes.push_back("a TLV declared " + std::to_string(value_len) +
                                     " byte(s) of value but only " + std::to_string(c.remaining()) +
                                     " remain -- stopping TLV parsing here");
                break;
            }
            ByteSpan value = c.bytes(value_len);

            switch (type) {
                case 0x0102: decode_route_tlv(type, false, false, value, msg); break;
                case 0x0103: decode_route_tlv(type, false, true, value, msg); break;
                case 0x0602: decode_route_tlv(type, true, false, value, msg); break;
                case 0x0603: decode_route_tlv(type, true, true, value, msg); break;
                default: decode_general_tlv(type, value, msg); break;
            }
        }
    }

    std::ostringstream out;
    out << "EIGRP " << msg.opcode_name << ": AS " << msg.autonomous_system;
    if (!msg.routes.empty()) out << ", " << msg.routes.size() << " route(s)";
    if (!msg.general_tlvs.empty()) out << ", " << msg.general_tlvs.size() << " other TLV(s)";
    msg.summary = out.str();

    return msg;
}

std::optional<ProtocolResult> EigrpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_eigrp(payload)) {
        return ProtocolResult::make<EigrpMessage>("eigrp", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& eigrp_decoder() {
    static const EigrpDecoder instance;
    return instance;
}

}  // namespace conduitscope
