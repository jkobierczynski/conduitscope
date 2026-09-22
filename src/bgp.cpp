// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/bgp.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

constexpr size_t kHeaderLength = 19;  // Marker(16) + Length(2) + Type(1)

size_t max_elements() { return resource_limits().max_decoded_objects.value_or(50); }

std::string bgp_type_name(uint8_t type) {
    switch (type) {
        case 1: return "OPEN";
        case 2: return "UPDATE";
        case 3: return "NOTIFICATION";
        case 4: return "KEEPALIVE";
        case 5: return "ROUTE-REFRESH";
        default: return "";
    }
}

// See bgp.hpp's own OPEN paragraph for sourcing -- cross-checked against IANA's "Capability Codes"
// registry and Wireshark's capability_vals[]. Not exhaustive by design (see this file's header
// comment) -- a code not in this table is still shown by its raw numeric value.
std::string capability_code_name(uint8_t code) {
    switch (code) {
        case 1: return "Multiprotocol Extensions";
        case 2: return "Route Refresh";
        case 3: return "Outbound Route Filtering";
        case 5: return "Extended Next Hop Encoding";
        case 6: return "BGP Extended Message";
        case 7: return "BGPsec";
        case 8: return "Multiple Labels";
        case 9: return "BGP Role";
        case 64: return "Graceful Restart";
        case 65: return "4-octet AS Number Support";
        case 67: return "Support for Dynamic Capability";
        case 69: return "ADD-PATH";
        case 70: return "Enhanced Route Refresh";
        case 71: return "Long-Lived Graceful Restart";
        case 73: return "FQDN";
        case 128: return "Route Refresh (Cisco, deprecated)";
        case 130: return "Outbound Route Filtering (Cisco, deprecated)";
        default: return "";
    }
}

// See bgp.hpp's own UPDATE paragraph for sourcing. Not exhaustive by design -- an uncurated type
// code is still named by its raw numeric value, value shown as hex.
std::string path_attribute_type_name(uint8_t code) {
    switch (code) {
        case 1: return "ORIGIN";
        case 2: return "AS_PATH";
        case 3: return "NEXT_HOP";
        case 4: return "MULTI_EXIT_DISC";
        case 5: return "LOCAL_PREF";
        case 6: return "ATOMIC_AGGREGATE";
        case 7: return "AGGREGATOR";
        case 8: return "COMMUNITY";
        case 9: return "ORIGINATOR_ID";
        case 10: return "CLUSTER_LIST";
        case 14: return "MP_REACH_NLRI";
        case 15: return "MP_UNREACH_NLRI";
        case 16: return "EXTENDED_COMMUNITIES";
        case 17: return "AS4_PATH";
        case 18: return "AS4_AGGREGATOR";
        case 22: return "PMSI_TUNNEL";
        case 32: return "LARGE_COMMUNITY";
        case 35: return "OTC";
        default: return "";
    }
}

std::string origin_name(uint8_t v) {
    switch (v) {
        case 0: return "IGP";
        case 1: return "EGP";
        case 2: return "INCOMPLETE";
        default: return "";
    }
}

std::string as_path_segment_type_name(uint8_t t) {
    switch (t) {
        case 1: return "AS_SET";
        case 2: return "AS_SEQUENCE";
        case 3: return "AS_CONFED_SEQUENCE";
        case 4: return "AS_CONFED_SET";
        default: return "";
    }
}

// See bgp.hpp's own COMMUNITY paragraph for exactly why this table is short and deliberately not
// extended with less-certain newer values.
std::string community_name(uint32_t v) {
    switch (v) {
        case 0xFFFFFF01: return "NO_EXPORT";
        case 0xFFFFFF02: return "NO_ADVERTISE";
        case 0xFFFFFF03: return "NO_EXPORT_SUBCONFED";
        case 0xFFFFFF04: return "NOPEER";
        case 0xFFFF029A: return "BLACKHOLE";
        default: return "";
    }
}

std::string error_code_name(uint8_t code) {
    switch (code) {
        case 1: return "Message Header Error";
        case 2: return "OPEN Message Error";
        case 3: return "UPDATE Message Error";
        case 4: return "Hold Timer Expired";
        case 5: return "Finite State Machine Error";
        case 6: return "Cease";
        case 7: return "ROUTE-REFRESH Message Error";
        default: return "";
    }
}

// Curated subcode tables, one per major error code -- see bgp.hpp's own NOTIFICATION paragraph for
// sourcing (RFC 4271/6608/4486/7313/9234). Not claimed exhaustive; an uncurated subcode is still
// shown by its raw numeric value.
std::string error_subcode_name(uint8_t code, uint8_t subcode) {
    switch (code) {
        case 1:  // Message Header Error
            switch (subcode) {
                case 1: return "Connection Not Synchronized";
                case 2: return "Bad Message Length";
                case 3: return "Bad Message Type";
            }
            break;
        case 2:  // OPEN Message Error
            switch (subcode) {
                case 1: return "Unsupported Version Number";
                case 2: return "Bad Peer AS";
                case 3: return "Bad BGP Identifier";
                case 4: return "Unsupported Optional Parameter";
                case 5: return "Authentication Failure (deprecated)";
                case 6: return "Unacceptable Hold Time";
                case 7: return "Unsupported Capability";
                case 8: return "Role Mismatch";
            }
            break;
        case 3:  // UPDATE Message Error
            switch (subcode) {
                case 1: return "Malformed Attribute List";
                case 2: return "Unrecognized Well-known Attribute";
                case 3: return "Missing Well-known Attribute";
                case 4: return "Attribute Flags Error";
                case 5: return "Attribute Length Error";
                case 6: return "Invalid ORIGIN Attribute";
                case 7: return "AS Routing Loop (deprecated)";
                case 8: return "Invalid NEXT_HOP Attribute";
                case 9: return "Optional Attribute Error";
                case 10: return "Invalid Network Field";
                case 11: return "Malformed AS_PATH";
            }
            break;
        case 5:  // Finite State Machine Error
            switch (subcode) {
                case 1: return "Receive Unexpected Message in OpenSent State";
                case 2: return "Receive Unexpected Message in OpenConfirm State";
                case 3: return "Receive Unexpected Message in Established State";
            }
            break;
        case 6:  // Cease
            switch (subcode) {
                case 1: return "Maximum Number of Prefixes Reached";
                case 2: return "Administrative Shutdown";
                case 3: return "Peer De-configured";
                case 4: return "Administrative Reset";
                case 5: return "Connection Rejected";
                case 6: return "Other Configuration Change";
                case 7: return "Connection Collision Resolution";
                case 8: return "Out of Resources";
                case 9: return "Hard Reset";
            }
            break;
        case 7:  // ROUTE-REFRESH Message Error
            if (subcode == 1) return "Invalid Message Length";
            break;
        default:
            break;
    }
    return "";
}

// The shared VLSM-compressed prefix encoding (RFC 4271 section 4.3) used by Withdrawn Routes, NLRI,
// and MP_REACH_NLRI/MP_UNREACH_NLRI's own NLRI fields -- see bgp.hpp's own UPDATE paragraph. Only
// renders an IPv4 address (`value` is assumed to already be the IPv4-only case; a non-IPv4 AFI's
// own prefix list is shown as raw hex by its own caller instead, see decode_mp_reach/decode_mp_unreach).
std::vector<BgpPrefix> parse_ipv4_prefix_list(ByteSpan value, bool& truncated) {
    std::vector<BgpPrefix> prefixes;
    Cursor c(value);
    size_t cap = max_elements();
    while (c.remaining() >= 1 && prefixes.size() < cap) {
        uint8_t bits = c.u8();
        size_t nbytes = (static_cast<size_t>(bits) + 7) / 8;
        if (nbytes > 4 || c.remaining() < nbytes) {
            truncated = true;
            break;
        }
        uint8_t octets[4] = {0, 0, 0, 0};
        for (size_t i = 0; i < nbytes; ++i) octets[i] = c.u8();
        uint32_t addr = (static_cast<uint32_t>(octets[0]) << 24) | (static_cast<uint32_t>(octets[1]) << 16) |
                        (static_cast<uint32_t>(octets[2]) << 8) | octets[3];
        BgpPrefix p;
        p.prefix_length_bits = bits;
        p.address = format_ipv4(addr);
        prefixes.push_back(p);
    }
    if (!c.at_end() && prefixes.size() >= cap) truncated = true;
    return prefixes;
}

std::string render_prefix_list(const std::vector<BgpPrefix>& prefixes) {
    std::ostringstream s;
    for (size_t i = 0; i < prefixes.size(); ++i) {
        if (i != 0) s << ", ";
        s << prefixes[i].address << "/" << static_cast<unsigned>(prefixes[i].prefix_length_bits);
    }
    return s.str();
}

struct AsPathParseResult {
    std::vector<BgpAsPathSegment> segments;
    bool consumed_cleanly = true;
};

AsPathParseResult parse_as_path_with_width(ByteSpan value, bool four_byte) {
    AsPathParseResult result;
    Cursor c(value);
    size_t cap = max_elements();
    size_t as_size = four_byte ? 4 : 2;
    while (c.remaining() >= 2 && result.segments.size() < cap) {
        uint8_t stype = c.u8();
        uint8_t scount = c.u8();
        size_t need = static_cast<size_t>(scount) * as_size;
        if (c.remaining() < need) {
            result.consumed_cleanly = false;
            break;
        }
        BgpAsPathSegment seg;
        seg.segment_type = stype;
        seg.segment_type_name = as_path_segment_type_name(stype);
        for (uint8_t i = 0; i < scount; ++i) {
            uint32_t as_num = four_byte ? c.u32be() : c.u16be();
            seg.as_numbers.push_back(as_num);
        }
        result.segments.push_back(std::move(seg));
    }
    if (!c.at_end()) result.consumed_cleanly = false;
    return result;
}

std::string render_as_path(const std::vector<BgpAsPathSegment>& path) {
    std::ostringstream s;
    for (size_t i = 0; i < path.size(); ++i) {
        if (i != 0) s << " ";
        const BgpAsPathSegment& seg = path[i];
        bool is_set = (seg.segment_type == 1 || seg.segment_type == 4);
        if (is_set) s << "{";
        for (size_t j = 0; j < seg.as_numbers.size(); ++j) {
            if (j != 0) s << " ";
            s << seg.as_numbers[j];
        }
        if (is_set) s << "}";
    }
    return s.str();
}

// Parses an OPEN's Optional Parameters block (see bgp.hpp's own OPEN paragraph), flattening every
// Capabilities (Type 2) parameter's own capabilities into one list.
void parse_open_optional_parameters(ByteSpan params, BgpOpenMessage& open) {
    Cursor c(params);
    size_t cap = max_elements();
    while (c.remaining() >= 2 && open.capabilities.size() < cap) {
        uint8_t ptype = c.u8();
        uint8_t plen = c.u8();
        if (c.remaining() < plen) break;
        ByteSpan pvalue = params.subspan(c.position(), plen);
        for (size_t i = 0; i < plen; ++i) c.u8();

        if (ptype != 2) continue;  // only Capabilities parameters are decoded further

        Cursor cc(pvalue);
        while (cc.remaining() >= 2 && open.capabilities.size() < cap) {
            uint8_t ccode = cc.u8();
            uint8_t clen = cc.u8();
            if (cc.remaining() < clen) break;
            ByteSpan cvalue = pvalue.subspan(cc.position(), clen);
            for (size_t i = 0; i < clen; ++i) cc.u8();

            BgpCapability cap_entry;
            cap_entry.code = ccode;
            cap_entry.code_name = capability_code_name(ccode);
            cap_entry.length = clen;
            if (ccode == 1 && clen == 4) {
                cap_entry.is_multiprotocol = true;
                cap_entry.mp_afi = (static_cast<uint16_t>(cvalue.at(0)) << 8) | cvalue.at(1);
                cap_entry.mp_safi = cvalue.at(3);
            } else if (ccode == 65 && clen == 4) {
                cap_entry.is_four_octet_as = true;
                cap_entry.four_octet_as = (static_cast<uint32_t>(cvalue.at(0)) << 24) |
                                           (static_cast<uint32_t>(cvalue.at(1)) << 16) |
                                           (static_cast<uint32_t>(cvalue.at(2)) << 8) | cvalue.at(3);
                open.has_four_octet_as_capability = true;
            } else {
                cap_entry.raw_hex = "0x" + to_hex(cvalue, "");
            }
            open.capabilities.push_back(cap_entry);
        }
    }
}

std::optional<BgpOpenMessage> parse_open(ByteSpan value) {
    if (value.size() < 10) return std::nullopt;  // Version(1)+MyAS(2)+HoldTime(2)+BgpId(4)+OptParmLen(1)
    Cursor c(value);
    BgpOpenMessage open;
    open.version = c.u8();
    open.my_as = c.u16be();
    open.hold_time = c.u16be();
    open.bgp_identifier = format_ipv4(c.u32be());
    open.opt_parm_len = c.u8();
    size_t remaining = value.size() - c.position();
    size_t take = std::min(static_cast<size_t>(open.opt_parm_len), remaining);
    ByteSpan params = value.subspan(c.position(), take);
    parse_open_optional_parameters(params, open);
    return open;
}

// Renders one path attribute's value into `attr.rendered`, and mirrors curated fields (origin/
// as_path/next_hop/communities) onto `msg` -- see bgp.hpp's own UPDATE paragraph for exactly which
// type codes get this treatment.
void render_path_attribute(BgpPathAttribute& attr, ByteSpan value, bool as_width_authoritative,
                            bool as_width_is_four_octet, BgpUpdateMessage& msg,
                            std::vector<std::string>& notes) {
    switch (attr.type_code) {
        case 1: {  // ORIGIN
            if (value.size() == 1) {
                std::string name = origin_name(value.at(0));
                attr.rendered = name.empty() ? ("unrecognized (" + std::to_string(value.at(0)) + ")") : name;
                if (!name.empty()) {
                    msg.has_origin = true;
                    msg.origin_name = name;
                }
                return;
            }
            break;
        }
        case 2:    // AS_PATH
        case 17: {  // AS4_PATH -- always 4-byte AS numbers regardless of session negotiation
            bool four_byte = (attr.type_code == 17) ? true : as_width_is_four_octet;
            bool authoritative = (attr.type_code == 17) ? true : as_width_authoritative;
            AsPathParseResult first_try = parse_as_path_with_width(value, four_byte);
            if (!authoritative && !first_try.consumed_cleanly) {
                // Heuristic fallback (matches Wireshark's own approach): the assumed width didn't
                // cleanly consume the attribute -- try the other width instead.
                AsPathParseResult retry = parse_as_path_with_width(value, !four_byte);
                if (retry.consumed_cleanly) {
                    first_try = std::move(retry);
                    four_byte = !four_byte;
                }
            }
            attr.rendered = render_as_path(first_try.segments);
            if (attr.type_code == 2) {
                msg.has_as_path = true;
                msg.as_path = first_try.segments;
                msg.as_path_width_authoritative = authoritative;
                if (!authoritative) {
                    notes.push_back(
                        "AS_PATH decoded using a " + std::to_string(four_byte ? 4 : 2) +
                        "-byte-per-AS-number guess (this session's own OPEN wasn't seen, so 4-octet "
                        "AS number support couldn't be confirmed) -- not authoritative");
                }
            }
            return;
        }
        case 3: {  // NEXT_HOP
            if (value.size() == 4) {
                std::string nh = format_ipv4((static_cast<uint32_t>(value.at(0)) << 24) |
                                              (static_cast<uint32_t>(value.at(1)) << 16) |
                                              (static_cast<uint32_t>(value.at(2)) << 8) | value.at(3));
                attr.rendered = nh;
                msg.has_next_hop = true;
                msg.next_hop = nh;
                return;
            }
            break;
        }
        case 4:    // MULTI_EXIT_DISC
        case 5: {  // LOCAL_PREF
            if (value.size() == 4) {
                uint32_t v = (static_cast<uint32_t>(value.at(0)) << 24) | (static_cast<uint32_t>(value.at(1)) << 16) |
                             (static_cast<uint32_t>(value.at(2)) << 8) | value.at(3);
                attr.rendered = std::to_string(v);
                return;
            }
            break;
        }
        case 6: {  // ATOMIC_AGGREGATE -- a flag attribute, no value
            attr.rendered = "(flag attribute, no value)";
            return;
        }
        case 7:    // AGGREGATOR
        case 18: {  // AS4_AGGREGATOR -- always a 4-byte AS number
            bool four_byte = (attr.type_code == 18) ? true : as_width_is_four_octet;
            size_t as_size = four_byte ? 4 : 2;
            if (value.size() == as_size + 4) {
                uint32_t as_num = 0;
                for (size_t i = 0; i < as_size; ++i) as_num = (as_num << 8) | value.at(i);
                uint32_t ip = 0;
                for (size_t i = 0; i < 4; ++i) ip = (ip << 8) | value.at(as_size + i);
                attr.rendered = "AS " + std::to_string(as_num) + " (" + format_ipv4(ip) + ")";
                return;
            }
            break;
        }
        case 8: {  // COMMUNITY
            if (value.size() % 4 == 0 && !value.empty()) {
                std::vector<std::string> names;
                std::ostringstream r;
                for (size_t off = 0; off < value.size(); off += 4) {
                    uint32_t v = (static_cast<uint32_t>(value.at(off)) << 24) |
                                 (static_cast<uint32_t>(value.at(off + 1)) << 16) |
                                 (static_cast<uint32_t>(value.at(off + 2)) << 8) | value.at(off + 3);
                    std::string name = community_name(v);
                    std::ostringstream one;
                    if (!name.empty()) {
                        one << name;
                    } else {
                        one << std::hex << std::uppercase << "0x" << v << std::dec;
                    }
                    if (off != 0) r << ", ";
                    r << one.str();
                    names.push_back(one.str());
                }
                attr.rendered = r.str();
                msg.has_communities = true;
                msg.community_names = names;
                return;
            }
            break;
        }
        case 9: {  // ORIGINATOR_ID
            if (value.size() == 4) {
                attr.rendered = format_ipv4((static_cast<uint32_t>(value.at(0)) << 24) |
                                             (static_cast<uint32_t>(value.at(1)) << 16) |
                                             (static_cast<uint32_t>(value.at(2)) << 8) | value.at(3));
                return;
            }
            break;
        }
        case 10: {  // CLUSTER_LIST
            if (value.size() % 4 == 0 && !value.empty()) {
                std::ostringstream r;
                for (size_t off = 0; off < value.size(); off += 4) {
                    if (off != 0) r << ", ";
                    r << format_ipv4((static_cast<uint32_t>(value.at(off)) << 24) |
                                      (static_cast<uint32_t>(value.at(off + 1)) << 16) |
                                      (static_cast<uint32_t>(value.at(off + 2)) << 8) | value.at(off + 3));
                }
                attr.rendered = r.str();
                return;
            }
            break;
        }
        case 14: {  // MP_REACH_NLRI (RFC 4760)
            if (value.size() < 5) break;
            Cursor mc(value);
            uint16_t afi = mc.u16be();
            uint8_t safi = mc.u8();
            uint8_t nh_len = mc.u8();
            if (mc.remaining() < static_cast<size_t>(nh_len) + 1) break;  // +1 for the Reserved byte
            ByteSpan nh = value.subspan(mc.position(), nh_len);
            for (size_t i = 0; i < nh_len; ++i) mc.u8();
            mc.u8();  // Reserved (SNPA count in the original RFC, always 0 in practice)
            ByteSpan nlri_bytes = value.from(mc.position());
            std::ostringstream r;
            r << "AFI=" << afi << " SAFI=" << static_cast<unsigned>(safi);
            if (afi == 1 && safi == 1) {
                if (nh_len == 4) {
                    r << " nexthop=" << format_ipv4((static_cast<uint32_t>(nh.at(0)) << 24) |
                                                      (static_cast<uint32_t>(nh.at(1)) << 16) |
                                                      (static_cast<uint32_t>(nh.at(2)) << 8) | nh.at(3));
                } else {
                    r << " nexthop=0x" << to_hex(nh, "");
                }
                bool trunc = false;
                auto nlri = parse_ipv4_prefix_list(nlri_bytes, trunc);
                r << " nlri=[" << render_prefix_list(nlri) << "]";
                if (trunc) r << " (truncated)";
            } else {
                r << " (not IPv4 unicast -- nexthop/nlri shown as raw hex) nexthop=0x" << to_hex(nh, "")
                  << " nlri=0x" << to_hex(nlri_bytes, "");
            }
            attr.rendered = r.str();
            return;
        }
        case 15: {  // MP_UNREACH_NLRI (RFC 4760)
            if (value.size() < 3) break;
            Cursor mc(value);
            uint16_t afi = mc.u16be();
            uint8_t safi = mc.u8();
            ByteSpan withdrawn_bytes = value.from(mc.position());
            std::ostringstream r;
            r << "AFI=" << afi << " SAFI=" << static_cast<unsigned>(safi);
            if (afi == 1 && safi == 1) {
                bool trunc = false;
                auto withdrawn = parse_ipv4_prefix_list(withdrawn_bytes, trunc);
                r << " withdrawn=[" << render_prefix_list(withdrawn) << "]";
                if (trunc) r << " (truncated)";
            } else {
                r << " (not IPv4 unicast -- shown as raw hex) withdrawn=0x" << to_hex(withdrawn_bytes, "");
            }
            attr.rendered = r.str();
            return;
        }
        case 35: {  // OTC (RFC 9234)
            if (value.size() == 4) {
                uint32_t as_num = (static_cast<uint32_t>(value.at(0)) << 24) |
                                   (static_cast<uint32_t>(value.at(1)) << 16) |
                                   (static_cast<uint32_t>(value.at(2)) << 8) | value.at(3);
                attr.rendered = std::to_string(as_num);
                return;
            }
            break;
        }
        default:
            break;
    }
    // Either an uncurated type code, or a curated one whose value didn't match the expected shape --
    // fall back to raw hex rather than guess.
    attr.raw_hex = "0x" + to_hex(value, "");
}

std::optional<BgpUpdateMessage> parse_update(ByteSpan value, bool as_width_authoritative,
                                              bool as_width_is_four_octet, std::vector<std::string>& notes) {
    if (value.size() < 4) return std::nullopt;  // WithdrawnRoutesLen(2)+TotalPathAttrLen(2), minimum
    Cursor c(value);
    uint16_t withdrawn_len = c.u16be();
    if (c.remaining() < withdrawn_len) return std::nullopt;
    ByteSpan withdrawn_bytes = value.subspan(c.position(), withdrawn_len);
    for (size_t i = 0; i < withdrawn_len; ++i) c.u8();

    if (c.remaining() < 2) return std::nullopt;
    uint16_t attr_total_len = c.u16be();
    if (c.remaining() < attr_total_len) return std::nullopt;
    ByteSpan attr_bytes = value.subspan(c.position(), attr_total_len);
    for (size_t i = 0; i < attr_total_len; ++i) c.u8();

    ByteSpan nlri_bytes = value.from(c.position());

    BgpUpdateMessage msg;
    msg.withdrawn_routes = parse_ipv4_prefix_list(withdrawn_bytes, msg.withdrawn_routes_truncated);
    msg.nlri = parse_ipv4_prefix_list(nlri_bytes, msg.nlri_truncated);

    Cursor ac(attr_bytes);
    size_t cap = max_elements();
    while (ac.remaining() >= 3 && msg.path_attributes.size() < cap) {
        uint8_t flags = ac.u8();
        uint8_t type_code = ac.u8();
        bool extended_length = (flags & 0x10) != 0;
        size_t len_field_size = extended_length ? 2 : 1;
        if (ac.remaining() < len_field_size) break;
        uint16_t length = extended_length ? ac.u16be() : ac.u8();
        if (ac.remaining() < length) {
            notes.push_back("a path attribute (type " + std::to_string(type_code) +
                             ") declares a " + std::to_string(length) +
                             "-byte value but only " + std::to_string(ac.remaining()) +
                             " byte(s) remain in the attribute block -- stopped decoding further "
                             "attributes");
            break;
        }
        ByteSpan avalue = attr_bytes.subspan(ac.position(), length);
        for (size_t i = 0; i < length; ++i) ac.u8();

        BgpPathAttribute attr;
        attr.flags = flags;
        attr.optional = (flags & 0x80) != 0;
        attr.transitive = (flags & 0x40) != 0;
        attr.partial = (flags & 0x20) != 0;
        attr.extended_length = extended_length;
        attr.type_code = type_code;
        attr.type_name = path_attribute_type_name(type_code);
        attr.length = length;
        render_path_attribute(attr, avalue, as_width_authoritative, as_width_is_four_octet, msg, notes);
        msg.path_attributes.push_back(std::move(attr));
    }

    return msg;
}

std::optional<BgpNotificationMessage> parse_notification(ByteSpan value) {
    if (value.size() < 2) return std::nullopt;
    Cursor c(value);
    BgpNotificationMessage n;
    n.error_code = c.u8();
    n.error_subcode = c.u8();
    n.error_code_name = error_code_name(n.error_code);
    n.error_subcode_name = error_subcode_name(n.error_code, n.error_subcode);
    ByteSpan data = value.from(c.position());
    n.data_hex = "0x" + to_hex(data, "");

    // RFC 8203 shutdown communication: Cease(6)/Administrative Shutdown(2) or Administrative
    // Reset(4), Data begins with a 1-byte length followed by that many bytes of UTF-8 text.
    if (n.error_code == 6 && (n.error_subcode == 2 || n.error_subcode == 4) && !data.empty()) {
        uint8_t text_len = data.at(0);
        if (data.size() >= static_cast<size_t>(1) + text_len) {
            std::string text;
            text.reserve(text_len);
            for (size_t i = 0; i < text_len; ++i) text += static_cast<char>(data.at(1 + i));
            n.has_shutdown_communication = true;
            n.shutdown_communication = text;
        }
    }
    return n;
}

std::optional<BgpRouteRefreshMessage> parse_route_refresh(ByteSpan value) {
    if (value.size() != 4) return std::nullopt;
    Cursor c(value);
    BgpRouteRefreshMessage r;
    r.afi = c.u16be();
    c.u8();  // Reserved
    r.safi = c.u8();
    return r;
}

}  // namespace

std::optional<size_t> bgp_declared_length(ByteSpan payload) {
    if (payload.size() < kHeaderLength) return std::nullopt;
    for (size_t i = 0; i < 16; ++i) {
        if (payload.at(i) != 0xFF) return std::nullopt;
    }
    uint16_t length = (static_cast<uint16_t>(payload.at(16)) << 8) | payload.at(17);
    uint8_t type = payload.at(18);
    if (bgp_type_name(type).empty()) return std::nullopt;
    if (type == 4) {  // KEEPALIVE
        if (length != kHeaderLength) return std::nullopt;
    } else {
        if (length < kHeaderLength) return std::nullopt;
        // Upper bound: RFC 8654 Extended Messages allows up to 65535; this decoder accepts that
        // full range for every type without tracking whether Extended Messages was actually
        // negotiated -- see this file's header comment's documented-imprecision note. uint16_t's
        // own range already caps this at 65535, so there is no further check to make here.
    }
    return length;
}

std::optional<BgpMessage> try_parse_bgp_message(ByteSpan payload, bool as_width_authoritative,
                                                 bool as_width_is_four_octet) {
    auto declared = bgp_declared_length(payload);
    if (!declared || payload.size() < *declared) return std::nullopt;

    BgpMessage msg;
    msg.length = static_cast<uint16_t>(*declared);
    msg.type = payload.at(18);
    msg.type_name = bgp_type_name(msg.type);

    ByteSpan value = payload.subspan(kHeaderLength, *declared - kHeaderLength);

    std::ostringstream s;
    s << "BGP " << msg.type_name;

    if (msg.type == 1) {
        auto open = parse_open(value);
        if (!open) return std::nullopt;
        msg.is_open = true;
        msg.open = *open;
        s << " version=" << static_cast<unsigned>(open->version) << " my_as=" << open->my_as
          << " hold_time=" << open->hold_time << " identifier=" << open->bgp_identifier;
        if (open->has_four_octet_as_capability) s << " [4-octet-AS capable]";
    } else if (msg.type == 2) {
        auto update = parse_update(value, as_width_authoritative, as_width_is_four_octet, msg.notes);
        if (!update) return std::nullopt;
        msg.is_update = true;
        msg.update = *update;
        s << " withdrawn=" << update->withdrawn_routes.size() << " nlri=" << update->nlri.size()
          << " attrs=" << update->path_attributes.size();
        if (update->has_as_path) s << " as_path=[" << render_as_path(update->as_path) << "]";
        if (update->has_next_hop) s << " next_hop=" << update->next_hop;
    } else if (msg.type == 3) {
        auto notif = parse_notification(value);
        if (!notif) return std::nullopt;
        msg.is_notification = true;
        msg.notification = *notif;
        s << " " << (notif->error_code_name.empty() ? std::to_string(notif->error_code) : notif->error_code_name);
        if (!notif->error_subcode_name.empty()) s << "/" << notif->error_subcode_name;
        if (notif->has_shutdown_communication) s << " -- \"" << notif->shutdown_communication << "\"";
    } else if (msg.type == 5) {
        auto rr = parse_route_refresh(value);
        if (!rr) return std::nullopt;
        msg.is_route_refresh = true;
        msg.route_refresh = *rr;
        s << " AFI=" << rr->afi << " SAFI=" << static_cast<unsigned>(rr->safi);
    }
    // type == 4 (KEEPALIVE): no body, nothing further to add to the summary.

    msg.summary = s.str();
    return msg;
}

std::optional<ProtocolResult> BgpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    BgpFlowState& state = ctx.flow_state<BgpFlowState>();

    auto first = try_parse_bgp_message(payload, state.open_seen, state.four_octet_as_negotiated);
    if (!first) return std::nullopt;

    if (first->is_open) {
        state.open_seen = true;
        state.four_octet_as_negotiated = first->open.has_four_octet_as_capability;
    }

    BgpResult result;
    result.summary = first->summary;
    result.first = *first;
    for (const auto& n : first->notes) result.notes.push_back(n);

    // Coalescing loop -- real BGP sessions send frequent small KEEPALIVEs that routinely end up
    // merged with neighboring messages in one TCP segment/reassembled buffer; same pattern
    // OpcUaDecoder::decode already uses (see opcua.hpp/opcua.cpp).
    const size_t kMaxCoalesced = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = first->length;
    size_t message_count = 1;
    while (offset < payload.size() && message_count < kMaxCoalesced) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_bgp_message(rest, state.open_seen, state.four_octet_as_negotiated);
        if (!next) break;
        if (next->is_open) {
            state.open_seen = true;
            state.four_octet_as_negotiated = next->open.has_four_octet_as_capability;
        }
        ++message_count;
        result.notes.push_back("additional BGP message " + std::to_string(message_count) +
                                " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                " (coalesced by the sender/OS): " + next->summary);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->length;
    }
    if (message_count >= kMaxCoalesced) {
        result.notes.push_back("stopped after " + std::to_string(kMaxCoalesced) +
                                " BGP message(s) in this one TCP payload, more may remain (safety cap)");
    }
    result.coalesced_message_count = message_count;

    return ProtocolResult::make<BgpResult>("bgp", std::move(result));
}

const ProtocolDecoder& bgp_decoder() {
    static const BgpDecoder instance;
    return instance;
}

}  // namespace conduitscope
