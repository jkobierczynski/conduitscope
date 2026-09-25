// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/icmpv6.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

namespace conduitscope {

namespace {

enum Icmpv6Type : uint8_t {
    ICMPV6_DEST_UNREACHABLE = 1,
    ICMPV6_PACKET_TOO_BIG = 2,
    ICMPV6_TIME_EXCEEDED = 3,
    ICMPV6_PARAMETER_PROBLEM = 4,
    ICMPV6_ECHO_REQUEST = 128,
    ICMPV6_ECHO_REPLY = 129,
    ICMPV6_MLD_QUERY = 130,
    ICMPV6_MLD_REPORT_V1 = 131,
    ICMPV6_MLD_DONE_V1 = 132,
    ICMPV6_ROUTER_SOLICITATION = 133,
    ICMPV6_ROUTER_ADVERTISEMENT = 134,
    ICMPV6_NEIGHBOR_SOLICITATION = 135,
    ICMPV6_NEIGHBOR_ADVERTISEMENT = 136,
    ICMPV6_REDIRECT = 137,
    ICMPV6_MLD_REPORT_V2 = 143,
};

enum NdpOptionType : uint8_t {
    NDP_OPT_SOURCE_LINK_LAYER = 1,
    NDP_OPT_TARGET_LINK_LAYER = 2,
    NDP_OPT_PREFIX_INFORMATION = 3,
    NDP_OPT_MTU = 5,
    NDP_OPT_ROUTE_INFORMATION = 24,
    NDP_OPT_RDNSS = 25,
};

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. Same "read once, at
// namespace scope" convention icmp.cpp's own kMaxRepeated already uses.
size_t max_options() { return resource_limits().max_decoded_objects.value_or(50); }

std::string hex_u16(uint16_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << v;
    return out.str();
}

std::string type_name(uint8_t type) {
    switch (type) {
        case ICMPV6_DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMPV6_PACKET_TOO_BIG: return "Packet Too Big";
        case ICMPV6_TIME_EXCEEDED: return "Time Exceeded";
        case ICMPV6_PARAMETER_PROBLEM: return "Parameter Problem";
        case ICMPV6_ECHO_REQUEST: return "Echo Request";
        case ICMPV6_ECHO_REPLY: return "Echo Reply";
        case ICMPV6_MLD_QUERY: return "Multicast Listener Query";
        case ICMPV6_MLD_REPORT_V1: return "Multicast Listener Report v1";
        case ICMPV6_MLD_DONE_V1: return "Multicast Listener Done v1";
        case ICMPV6_ROUTER_SOLICITATION: return "Router Solicitation";
        case ICMPV6_ROUTER_ADVERTISEMENT: return "Router Advertisement";
        case ICMPV6_NEIGHBOR_SOLICITATION: return "Neighbor Solicitation";
        case ICMPV6_NEIGHBOR_ADVERTISEMENT: return "Neighbor Advertisement";
        case ICMPV6_REDIRECT: return "Redirect";
        case ICMPV6_MLD_REPORT_V2: return "Multicast Listener Report v2";
        default: {
            std::ostringstream out;
            out << "ICMPv6 type " << static_cast<unsigned>(type);
            return out.str();
        }
    }
}

std::string code_name(uint8_t type, uint8_t code) {
    switch (type) {
        case ICMPV6_DEST_UNREACHABLE:
            switch (code) {
                case 0: return "No route to destination";
                case 1: return "Communication with destination administratively prohibited";
                case 2: return "Beyond scope of source address";
                case 3: return "Address unreachable";
                case 4: return "Port unreachable";
                case 5: return "Source address failed ingress/egress policy";
                case 6: return "Reject route to destination";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        case ICMPV6_TIME_EXCEEDED:
            switch (code) {
                case 0: return "Hop limit exceeded in transit";
                case 1: return "Fragment reassembly time exceeded";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        case ICMPV6_PARAMETER_PROBLEM:
            switch (code) {
                case 0: return "Erroneous header field encountered";
                case 1: return "Unrecognized Next Header type encountered";
                case 2: return "Unrecognized IPv6 option encountered";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        default:
            return "";  // this type has no named codes
    }
}

std::string ndp_option_type_name(uint8_t type) {
    switch (type) {
        case NDP_OPT_SOURCE_LINK_LAYER: return "Source Link-Layer Address";
        case NDP_OPT_TARGET_LINK_LAYER: return "Target Link-Layer Address";
        case NDP_OPT_PREFIX_INFORMATION: return "Prefix Information";
        case NDP_OPT_MTU: return "MTU";
        case NDP_OPT_ROUTE_INFORMATION: return "Route Information";
        case NDP_OPT_RDNSS: return "Recursive DNS Server";
        default: return "NDP option type " + std::to_string(static_cast<unsigned>(type));
    }
}

std::string route_preference_name(uint8_t prf) {
    // RFC 4191 2.1: the 2-bit Prf field, encoded as a signed 2-bit value -- 01 = High, 00 =
    // Medium (the default), 11 = Low, 10 = Reserved (must not be sent/silently ignored).
    switch (prf) {
        case 0b01: return "High";
        case 0b00: return "Medium";
        case 0b11: return "Low";
        default: return "Reserved";
    }
}

Ipv6Address read_ipv6_address(Cursor& c) {
    ByteSpan bytes = c.bytes(16);
    Ipv6Address addr{};
    for (size_t i = 0; i < 16; ++i) addr[i] = bytes.at(i);
    return addr;
}

// RFC 4443 2.3's own pseudo-header checksum -- see icmpv6.hpp's own CHECKSUM section. `message` is
// the ICMPv6 message exactly as captured (checksum field included, same "verify over the bytes
// as-is" convention icmp.cpp's own verify_checksum uses for ICMPv4).
bool verify_icmpv6_checksum(ByteSpan message, const Ipv6Address& src, const Ipv6Address& dst) {
    uint32_t sum = 0;
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint32_t>(src[i]) << 8) | src[i + 1];
    }
    for (size_t i = 0; i < 16; i += 2) {
        sum += (static_cast<uint32_t>(dst[i]) << 8) | dst[i + 1];
    }
    // Upper-Layer Packet Length (4 bytes, big-endian) -- the ICMPv6 message length only, RFC 8200
    // 8.1. Then 3 zero bytes + Next Header (1 byte, always 58 here) -- summed together as two
    // 16-bit words: [0x00,0x00] and [0x00,58].
    uint32_t len = static_cast<uint32_t>(message.size());
    sum += (len >> 16) & 0xFFFF;
    sum += len & 0xFFFF;
    sum += 0;                      // [0x00, 0x00] of the 3 zero bytes' first word
    sum += ICMPV6_IP_PROTOCOL;     // [0x00, 58] -- the second zero byte plus Next Header

    size_t i = 0;
    for (; i + 1 < message.size(); i += 2) {
        sum += (static_cast<uint32_t>(message.at(i)) << 8) | message.at(i + 1);
    }
    if (i < message.size()) {
        sum += static_cast<uint32_t>(message.at(i)) << 8;  // odd trailing byte, padded with 0
    }
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return sum == 0xFFFF;
}

// Walks the NDP option TLV chain (RFC 4861 4.6) starting at the cursor's current position through
// to the end of its span, decoding the option types icmpv6.hpp's own file header documents and
// naming-only every other type. Never throws: a Length == 0 (a protocol violation -- RFC 4861 4.6
// says Length "MUST be greater than zero") stops the walk and sets options_malformed instead of
// looping forever, the same "never trust a length field enough to loop on it unchecked" posture
// every other TLV-walker in this codebase already has.
void decode_ndp_options(Cursor& c, Icmpv6Message& msg) {
    size_t decoded = 0;
    while (c.remaining() >= 2) {
        size_t option_start = c.position();
        uint8_t opt_type = c.u8();
        uint8_t opt_len_units = c.u8();
        if (opt_len_units == 0) {
            msg.options_malformed = true;
            msg.notes.push_back(
                "an NDP option declared Length == 0, which RFC 4861 forbids (a real option is "
                "always at least 8 bytes) -- stopped decoding options for this message rather than "
                "risk an infinite loop on a length field that can never advance the walk");
            return;
        }
        size_t byte_length = static_cast<size_t>(opt_len_units) * 8;
        size_t data_len = byte_length - 2;  // bytes after Type+Length
        if (data_len > c.remaining()) {
            msg.notes.push_back(
                "an NDP option declared a length that runs past the end of this message -- stopped "
                "decoding options");
            return;
        }

        if (++decoded > max_options()) {
            msg.options_truncated = true;
            msg.notes.push_back("output capped at " + std::to_string(max_options()) +
                                 " NDP option(s); this message declared more");
            return;
        }

        NdpOption opt;
        opt.type = opt_type;
        opt.type_name = ndp_option_type_name(opt_type);
        opt.byte_length = byte_length;

        Cursor oc(c.bytes(data_len));
        switch (opt_type) {
            case NDP_OPT_SOURCE_LINK_LAYER:
            case NDP_OPT_TARGET_LINK_LAYER: {
                NdpLinkLayerAddress lla;
                ByteSpan rest = oc.rest();
                lla.address.assign(rest.data(), rest.data() + rest.size());
                opt.link_layer_address = std::move(lla);
                break;
            }
            case NDP_OPT_PREFIX_INFORMATION: {
                if (data_len >= 30) {  // Prefix Length(1)+Flags(1)+Valid(4)+Preferred(4)+Rsvd2(4)+Prefix(16)
                    NdpPrefixInformation pi;
                    pi.prefix_length = oc.u8();
                    uint8_t flags = oc.u8();
                    pi.on_link = (flags & 0x80) != 0;
                    pi.autonomous = (flags & 0x40) != 0;
                    pi.valid_lifetime_sec = oc.u32be();
                    pi.preferred_lifetime_sec = oc.u32be();
                    oc.skip(4);  // Reserved2
                    Ipv6Address prefix_bytes = read_ipv6_address(oc);
                    pi.prefix = format_ipv6(prefix_bytes);
                    opt.prefix_information = std::move(pi);
                }
                break;
            }
            case NDP_OPT_MTU: {
                if (data_len >= 6) {  // Reserved(2)+MTU(4)
                    NdpMtuOption m;
                    oc.skip(2);
                    m.mtu = oc.u32be();
                    opt.mtu = m;
                }
                break;
            }
            case NDP_OPT_RDNSS: {
                if (data_len >= 6) {  // Reserved(2)+Lifetime(4), then N*16-byte addresses
                    NdpRdnssOption r;
                    oc.skip(2);
                    r.lifetime_sec = oc.u32be();
                    while (oc.remaining() >= 16) {
                        r.addresses.push_back(format_ipv6(read_ipv6_address(oc)));
                    }
                    opt.rdnss = std::move(r);
                }
                break;
            }
            case NDP_OPT_ROUTE_INFORMATION: {
                if (data_len >= 6) {  // Prefix Length(1)+Rsvd/Prf(1)+Route Lifetime(4)[+Prefix(0/8/16)]
                    NdpRouteInformation ri;
                    ri.prefix_length = oc.u8();
                    uint8_t rsvd_prf = oc.u8();
                    ri.preference_raw = (rsvd_prf >> 3) & 0x03;
                    ri.preference_name = route_preference_name(ri.preference_raw);
                    ri.route_lifetime_sec = oc.u32be();
                    Ipv6Address prefix_bytes{};
                    ByteSpan prefix_rest = oc.rest();
                    for (size_t i = 0; i < prefix_rest.size() && i < 16; ++i) {
                        prefix_bytes[i] = prefix_rest.at(i);
                    }
                    ri.prefix = format_ipv6(prefix_bytes);
                    opt.route_information = std::move(ri);
                }
                break;
            }
            default:
                break;  // named only -- see icmpv6.hpp's own file header
        }
        msg.options.push_back(std::move(opt));
        (void)option_start;
    }
}

}  // namespace

std::optional<Icmpv6Message> try_parse_icmpv6(ByteSpan ip_payload, const Ipv6Address& pseudo_src,
                                               const Ipv6Address& pseudo_dst) {
    if (ip_payload.size() < 4) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    Icmpv6Message msg;
    msg.type = c.u8();
    msg.code = c.u8();
    msg.checksum = c.u16be();
    msg.type_name = type_name(msg.type);
    msg.code_name = code_name(msg.type, msg.code);
    msg.checksum_valid = verify_icmpv6_checksum(ip_payload, pseudo_src, pseudo_dst);
    if (!msg.checksum_valid) {
        msg.notes.push_back("ICMPv6 checksum mismatch (packet declares " + hex_u16(msg.checksum) +
                             ") -- either a truncated capture, a crafted/corrupted packet, or the "
                             "outer IPv6 source/destination addresses this checksum depends on "
                             "weren't available to validate against");
    }

    std::ostringstream out;
    out << "ICMPv6 " << msg.type_name;
    if (!msg.code_name.empty()) out << " (" << msg.code_name << ")";

    switch (msg.type) {
        case ICMPV6_ECHO_REQUEST:
        case ICMPV6_ECHO_REPLY: {
            if (c.remaining() >= 4) {
                msg.echo_identifier = c.u16be();
                msg.echo_sequence = c.u16be();
                msg.echo_data_length = c.remaining();
            }
            out << ", id=" << msg.echo_identifier << " seq=" << msg.echo_sequence;
            if (msg.echo_data_length > 0) {
                out << ", " << msg.echo_data_length << " byte(s) of data";
            }
            break;
        }
        case ICMPV6_PACKET_TOO_BIG: {
            if (c.remaining() >= 4) {
                msg.packet_too_big_mtu = c.u32be();
                out << ", MTU=" << msg.packet_too_big_mtu;
            }
            break;
        }
        case ICMPV6_PARAMETER_PROBLEM: {
            if (c.remaining() >= 4) {
                msg.parameter_problem_pointer = c.u32be();
                out << ", pointer=" << msg.parameter_problem_pointer;
            }
            break;
        }
        case ICMPV6_DEST_UNREACHABLE:
        case ICMPV6_TIME_EXCEEDED:
            // Unused(4B) precedes the invoking packet, which this decoder does not summarize --
            // see icmpv6.hpp's own OUT OF SCOPE section.
            break;
        case ICMPV6_ROUTER_SOLICITATION: {
            if (c.remaining() >= 4) c.skip(4);  // Reserved
            decode_ndp_options(c, msg);
            out << ", " << msg.options.size() << " option(s)";
            break;
        }
        case ICMPV6_ROUTER_ADVERTISEMENT: {
            if (c.remaining() >= 12) {
                msg.ra_cur_hop_limit = c.u8();
                uint8_t flags = c.u8();
                msg.ra_managed_flag = (flags & 0x80) != 0;  // M -- [SECONDARY-SOURCE], see file header
                msg.ra_other_flag = (flags & 0x40) != 0;    // O
                msg.ra_router_lifetime_sec = c.u16be();
                msg.ra_reachable_time_ms = c.u32be();
                msg.ra_retrans_timer_ms = c.u32be();
                decode_ndp_options(c, msg);
                out << ", lifetime=" << msg.ra_router_lifetime_sec << "s";
                if (msg.ra_managed_flag) out << " M";
                if (msg.ra_other_flag) out << " O";
                out << ", " << msg.options.size() << " option(s)";
                for (const auto& opt : msg.options) {
                    if (opt.prefix_information && opt.prefix_information->autonomous) {
                        out << " (SLAAC prefix " << opt.prefix_information->prefix << "/"
                            << static_cast<unsigned>(opt.prefix_information->prefix_length)
                            << " offered)";
                        break;
                    }
                }
            } else {
                msg.notes.push_back("truncated before the fixed 12-byte Router Advertisement header");
            }
            break;
        }
        case ICMPV6_NEIGHBOR_SOLICITATION: {
            if (c.remaining() >= 20) {
                c.skip(4);  // Reserved
                msg.target_address = format_ipv6(read_ipv6_address(c));
                decode_ndp_options(c, msg);
                out << ", target=" << msg.target_address << ", " << msg.options.size()
                    << " option(s)";
            } else {
                msg.notes.push_back("truncated before the fixed 20-byte Neighbor Solicitation header");
            }
            break;
        }
        case ICMPV6_NEIGHBOR_ADVERTISEMENT: {
            if (c.remaining() >= 20) {
                uint32_t flags_word = c.u32be();
                msg.na_router_flag = (flags_word & 0x80000000u) != 0;     // R
                msg.na_solicited_flag = (flags_word & 0x40000000u) != 0;  // S
                msg.na_override_flag = (flags_word & 0x20000000u) != 0;   // O
                msg.target_address = format_ipv6(read_ipv6_address(c));
                decode_ndp_options(c, msg);
                out << ", target=" << msg.target_address;
                if (msg.na_router_flag) out << " R";
                if (msg.na_solicited_flag) out << " S";
                if (msg.na_override_flag) out << " O";
                out << ", " << msg.options.size() << " option(s)";
            } else {
                msg.notes.push_back("truncated before the fixed 20-byte Neighbor Advertisement header");
            }
            break;
        }
        case ICMPV6_REDIRECT: {
            if (c.remaining() >= 36) {
                c.skip(4);  // Reserved
                msg.target_address = format_ipv6(read_ipv6_address(c));
                msg.redirect_destination_address = format_ipv6(read_ipv6_address(c));
                decode_ndp_options(c, msg);
                out << ", target=" << msg.target_address
                    << ", destination=" << msg.redirect_destination_address << ", "
                    << msg.options.size() << " option(s)";
            } else {
                msg.notes.push_back("truncated before the fixed 36-byte Redirect header");
            }
            break;
        }
        default:
            break;  // Tier 2: named above, no further field decode
    }

    msg.summary = out.str();
    return msg;
}

std::optional<ProtocolResult> Icmpv6Decoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (auto msg = try_parse_icmpv6(payload, ctx.ipv6_src_addr, ctx.ipv6_dst_addr)) {
        return ProtocolResult::make<Icmpv6Message>("icmpv6", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& icmpv6_decoder() {
    static const Icmpv6Decoder instance;
    return instance;
}

}  // namespace conduitscope
