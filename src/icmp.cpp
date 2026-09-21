// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/icmp.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

constexpr size_t kMaxRepeated = 50;  // capped at 50 entries, same convention as elsewhere.

enum IcmpType : uint8_t {
    ICMP_ECHO_REPLY = 0,
    ICMP_DEST_UNREACHABLE = 3,
    ICMP_SOURCE_QUENCH = 4,
    ICMP_REDIRECT = 5,
    ICMP_ECHO_REQUEST = 8,
    ICMP_ROUTER_ADVERTISEMENT = 9,
    ICMP_ROUTER_SOLICITATION = 10,
    ICMP_TIME_EXCEEDED = 11,
    ICMP_PARAMETER_PROBLEM = 12,
    ICMP_TIMESTAMP_REQUEST = 13,
    ICMP_TIMESTAMP_REPLY = 14,
    ICMP_INFO_REQUEST = 15,
    ICMP_INFO_REPLY = 16,
    ICMP_ADDRESS_MASK_REQUEST = 17,
    ICMP_ADDRESS_MASK_REPLY = 18,
    ICMP_TRACEROUTE = 30,
};

std::string hex_u16(uint16_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << v;
    return out.str();
}

std::string type_name(uint8_t type) {
    switch (type) {
        case ICMP_ECHO_REPLY: return "Echo Reply";
        case 1: return "Unassigned";
        case 2: return "Unassigned";
        case ICMP_DEST_UNREACHABLE: return "Destination Unreachable";
        case ICMP_SOURCE_QUENCH: return "Source Quench";
        case ICMP_REDIRECT: return "Redirect";
        case 6: return "Alternate Host Address";
        case ICMP_ECHO_REQUEST: return "Echo Request";
        case ICMP_ROUTER_ADVERTISEMENT: return "Router Advertisement";
        case ICMP_ROUTER_SOLICITATION: return "Router Solicitation";
        case ICMP_TIME_EXCEEDED: return "Time Exceeded";
        case ICMP_PARAMETER_PROBLEM: return "Parameter Problem";
        case ICMP_TIMESTAMP_REQUEST: return "Timestamp Request";
        case ICMP_TIMESTAMP_REPLY: return "Timestamp Reply";
        case ICMP_INFO_REQUEST: return "Information Request";
        case ICMP_INFO_REPLY: return "Information Reply";
        case ICMP_ADDRESS_MASK_REQUEST: return "Address Mask Request";
        case ICMP_ADDRESS_MASK_REPLY: return "Address Mask Reply";
        case ICMP_TRACEROUTE: return "Traceroute";
        default: {
            std::ostringstream out;
            out << "Unknown (" << static_cast<unsigned>(type) << ")";
            return out.str();
        }
    }
}

std::string code_name(uint8_t type, uint8_t code) {
    switch (type) {
        case ICMP_DEST_UNREACHABLE:
            switch (code) {
                case 0: return "Net Unreachable";
                case 1: return "Host Unreachable";
                case 2: return "Protocol Unreachable";
                case 3: return "Port Unreachable";
                case 4: return "Fragmentation Needed and Don't Fragment was Set";
                case 5: return "Source Route Failed";
                case 6: return "Destination Network Unknown";
                case 7: return "Destination Host Unknown";
                case 8: return "Source Host Isolated";
                case 9: return "Communication with Destination Network Administratively Prohibited";
                case 10: return "Communication with Destination Host Administratively Prohibited";
                case 11: return "Destination Network Unreachable for Type of Service";
                case 12: return "Destination Host Unreachable for Type of Service";
                case 13: return "Communication Administratively Prohibited";
                case 14: return "Host Precedence Violation";
                case 15: return "Precedence Cutoff in Effect";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        case ICMP_REDIRECT:
            switch (code) {
                case 0: return "Redirect Datagram for the Network";
                case 1: return "Redirect Datagram for the Host";
                case 2: return "Redirect Datagram for the Type of Service and Network";
                case 3: return "Redirect Datagram for the Type of Service and Host";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        case ICMP_TIME_EXCEEDED:
            switch (code) {
                case 0: return "Time to Live Exceeded in Transit";
                case 1: return "Fragment Reassembly Time Exceeded";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        case ICMP_PARAMETER_PROBLEM:
            switch (code) {
                case 0: return "Pointer Indicates the Error";
                case 1: return "Missing a Required Option";
                case 2: return "Bad Length";
                default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
            }
        default:
            return "";  // this type has no named codes -- code is either always 0 or unused
    }
}

// The classic 16-bit one's-complement Internet checksum (RFC 1071), computed here over the
// message exactly as captured, checksum field included. A message with a correct checksum always
// folds to 0xFFFF this way -- see icmp.hpp's file header for why this is verified rather than just
// surfaced, unlike most other checksums in this codebase.
bool verify_checksum(ByteSpan message) {
    uint32_t sum = 0;
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

// Attempts to summarize the IP datagram an ICMP error message quotes -- see icmp.hpp's file header
// for the "first 8 bytes" guarantee and why this can legitimately come back empty. Never throws:
// a ParseError from parse_ipv4 (too short/malformed) is caught and turned into a note instead.
void decode_embedded_datagram(Cursor& c, IcmpMessage& msg) {
    ByteSpan remaining = c.rest();
    if (remaining.size() < 20) {
        return;  // not even a minimal (no-options) IPv4 header's worth of bytes -- common for a
                  // deliberately short ICMP error, not itself surprising enough to note
    }
    try {
        Ipv4Header inner = parse_ipv4(remaining);
        IcmpEmbeddedDatagram ed;
        ed.src_addr = format_ipv4(inner.src_addr);
        ed.dst_addr = format_ipv4(inner.dst_addr);
        ed.protocol = inner.protocol;
        ed.protocol_name = ip_protocol_name(inner.protocol);
        if ((inner.protocol == IPPROTO_TCP_VALUE || inner.protocol == IPPROTO_UDP_VALUE) &&
            inner.payload.size() >= 4) {
            Cursor pc(inner.payload);
            ed.src_port = pc.u16be();
            ed.dst_port = pc.u16be();
            ed.has_ports = true;
        }
        msg.embedded_datagram = std::move(ed);
    } catch (const ParseError&) {
        msg.notes.push_back("the embedded original datagram could not be decoded (truncated or "
                             "malformed)");
    }
}

void append_embedded_summary(std::ostringstream& out, const IcmpMessage& msg) {
    if (!msg.embedded_datagram) return;
    const auto& ed = *msg.embedded_datagram;
    out << " -- original datagram " << ed.src_addr << "->" << ed.dst_addr;
    if (!ed.protocol_name.empty()) {
        out << " (" << ed.protocol_name;
        if (ed.has_ports) out << " " << ed.src_port << "->" << ed.dst_port;
        out << ")";
    } else {
        out << " (IP protocol " << static_cast<unsigned>(ed.protocol) << ")";
    }
}

}  // namespace

std::optional<IcmpMessage> try_parse_icmp(ByteSpan ip_payload) {
    if (ip_payload.size() < 4) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    IcmpMessage msg;
    msg.type = c.u8();
    msg.code = c.u8();
    msg.checksum = c.u16be();
    msg.type_name = type_name(msg.type);
    msg.code_name = code_name(msg.type, msg.code);
    msg.checksum_valid = verify_checksum(ip_payload);
    if (!msg.checksum_valid) {
        msg.notes.push_back("ICMP checksum mismatch (packet declares " + hex_u16(msg.checksum) +
                             ") -- either a truncated capture or a crafted/corrupted packet");
    }

    std::ostringstream out;
    out << "ICMP " << msg.type_name;
    if (!msg.code_name.empty()) out << " (" << msg.code_name << ")";

    switch (msg.type) {
        case ICMP_ECHO_REPLY:
        case ICMP_ECHO_REQUEST: {
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
        case ICMP_DEST_UNREACHABLE: {
            if (c.remaining() >= 4) {
                if (msg.code == 4) {
                    c.skip(2);  // unused
                    msg.next_hop_mtu = c.u16be();
                } else {
                    c.skip(4);  // unused
                }
            }
            decode_embedded_datagram(c, msg);
            if (msg.next_hop_mtu != 0) out << ", next-hop MTU " << msg.next_hop_mtu;
            append_embedded_summary(out, msg);
            break;
        }
        case ICMP_REDIRECT: {
            if (c.remaining() >= 4) {
                msg.redirect_gateway = format_ipv4(c.u32be());
            }
            decode_embedded_datagram(c, msg);
            if (!msg.redirect_gateway.empty()) out << ", gateway " << msg.redirect_gateway;
            append_embedded_summary(out, msg);
            break;
        }
        case ICMP_TIME_EXCEEDED: {
            if (c.remaining() >= 4) c.skip(4);  // unused
            decode_embedded_datagram(c, msg);
            append_embedded_summary(out, msg);
            break;
        }
        case ICMP_PARAMETER_PROBLEM: {
            if (c.remaining() >= 4) {
                msg.parameter_pointer = c.u8();
                c.skip(3);  // unused
            }
            decode_embedded_datagram(c, msg);
            out << ", pointer=" << static_cast<unsigned>(msg.parameter_pointer);
            append_embedded_summary(out, msg);
            break;
        }
        case ICMP_TIMESTAMP_REQUEST:
        case ICMP_TIMESTAMP_REPLY: {
            if (c.remaining() >= 16) {
                msg.echo_identifier = c.u16be();
                msg.echo_sequence = c.u16be();
                msg.originate_timestamp_ms = c.u32be();
                msg.receive_timestamp_ms = c.u32be();
                msg.transmit_timestamp_ms = c.u32be();
                out << ", id=" << msg.echo_identifier << " seq=" << msg.echo_sequence
                    << ", originate=" << msg.originate_timestamp_ms << "ms";
            } else {
                msg.notes.push_back("truncated before the fixed 16-byte Timestamp body");
            }
            break;
        }
        case ICMP_ADDRESS_MASK_REQUEST:
        case ICMP_ADDRESS_MASK_REPLY: {
            if (c.remaining() >= 8) {
                msg.echo_identifier = c.u16be();
                msg.echo_sequence = c.u16be();
                msg.address_mask = format_ipv4(c.u32be());
                out << ", id=" << msg.echo_identifier << " seq=" << msg.echo_sequence << ", mask "
                    << msg.address_mask;
            } else {
                msg.notes.push_back("truncated before the fixed 8-byte Address Mask body");
            }
            break;
        }
        case ICMP_ROUTER_ADVERTISEMENT: {
            if (c.remaining() >= 4) {
                uint8_t num_addrs = c.u8();
                uint8_t addr_entry_size = c.u8();  // 32-bit words per entry; RFC 1256 says 2
                                                     // (address + preference), but read it rather
                                                     // than assume, in case a real device pads
                msg.router_advertisement_lifetime_sec = c.u16be();

                size_t decoded = std::min(static_cast<size_t>(num_addrs), kMaxRepeated);
                for (size_t i = 0; i < decoded && c.remaining() >= 8; ++i) {
                    IcmpRouterAddress ra;
                    ra.address = format_ipv4(c.u32be());
                    ra.preference = static_cast<int32_t>(c.u32be());
                    msg.router_addresses.push_back(ra);
                    if (addr_entry_size > 2) {
                        size_t extra = (static_cast<size_t>(addr_entry_size) - 2) * 4;
                        if (c.remaining() >= extra) c.skip(extra);
                    }
                }
                if (num_addrs > kMaxRepeated) {
                    msg.router_addresses_truncated = true;
                    msg.notes.push_back("output capped at " + std::to_string(kMaxRepeated) +
                                         " router address(es); " +
                                         std::to_string(num_addrs - kMaxRepeated) +
                                         " more were declared in this packet and were not decoded");
                }
                out << ", " << msg.router_addresses.size() << " router address(es), lifetime "
                    << msg.router_advertisement_lifetime_sec << "s";
            } else {
                msg.notes.push_back("truncated before the fixed 4-byte Router Advertisement header");
            }
            break;
        }
        default:
            break;  // Tier 2: named above, no further field decode
    }

    msg.summary = out.str();
    return msg;
}

}  // namespace conduitscope
