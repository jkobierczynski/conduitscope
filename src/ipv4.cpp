// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ipv4.hpp"

#include <sstream>
#include <vector>

namespace conduitscope {

Ipv4Header parse_ipv4(ByteSpan packet) {
    Cursor c(packet);
    Ipv4Header hdr;

    uint8_t version_ihl = c.u8();
    hdr.version = static_cast<uint8_t>(version_ihl >> 4);
    hdr.ihl_words = static_cast<uint8_t>(version_ihl & 0x0F);
    if (hdr.version != 4) {
        throw ParseError("not an IPv4 packet (version field = " + std::to_string(hdr.version) + ")");
    }
    if (hdr.ihl_words < 5) {
        throw ParseError("IPv4 header length field is impossibly small (" +
                          std::to_string(hdr.ihl_words) + " words)");
    }

    c.u8();  // ToS/DSCP, not needed for protocol decoding
    hdr.total_length = c.u16be();
    c.u16be();  // identification
    c.u16be();  // flags + fragment offset (fragment reassembly is a documented limitation)
    hdr.ttl = c.u8();
    hdr.protocol = c.u8();
    c.u16be();  // header checksum -- not validated; we trust the capture

    hdr.src_addr = c.u32be();
    hdr.dst_addr = c.u32be();

    size_t header_bytes = static_cast<size_t>(hdr.ihl_words) * 4;
    if (header_bytes < c.position()) {
        throw ParseError("IPv4 header length is inconsistent with the fixed fields already read");
    }
    size_t options_len = header_bytes - c.position();
    c.skip(options_len);  // skip IP options; we don't currently interpret any of them

    ByteSpan captured_after_header = c.rest();
    if (hdr.total_length >= header_bytes) {
        size_t declared_payload_len = static_cast<size_t>(hdr.total_length) - header_bytes;
        if (declared_payload_len <= captured_after_header.size()) {
            hdr.payload = captured_after_header.subspan(0, declared_payload_len);
            hdr.trailing_bytes_trimmed = captured_after_header.size() - declared_payload_len;
        } else {
            // total_length claims more than was actually captured (a short snaplen
            // truncated this packet) -- use what we have rather than claim bytes
            // that don't exist.
            hdr.payload = captured_after_header;
        }
    } else {
        // total_length is 0 or smaller than the header itself -- not trustworthy
        // (common on outbound packets with NIC checksum/segmentation offload,
        // which can leave this field unfilled). Fall back to every captured byte.
        hdr.payload = captured_after_header;
    }
    return hdr;
}

std::string ip_protocol_name(uint8_t protocol) {
    switch (protocol) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 9: return "IGRP";
        case 17: return "UDP";
        case 41: return "IPv6-in-IPv4 (6in4)";
        case 47: return "GRE";
        case 50: return "ESP";
        case 51: return "AH";
        case 58: return "ICMPv6";
        case 88: return "EIGRP";
        case 89: return "OSPF";
        case 103: return "PIM";
        case 112: return "VRRP";
        case 132: return "SCTP";
        default: return "";
    }
}

std::string format_ipv4(uint32_t addr) {
    std::ostringstream out;
    out << ((addr >> 24) & 0xFF) << '.' << ((addr >> 16) & 0xFF) << '.' << ((addr >> 8) & 0xFF) << '.'
        << (addr & 0xFF);
    return out.str();
}

std::optional<uint32_t> parse_ipv4_string(const std::string& text) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t dot = text.find('.', start);
        if (dot == std::string::npos) {
            parts.push_back(text.substr(start));
            break;
        }
        parts.push_back(text.substr(start, dot - start));
        start = dot + 1;
    }
    if (parts.size() != 4) {
        return std::nullopt;
    }
    uint32_t result = 0;
    for (const auto& part : parts) {
        if (part.empty() || part.size() > 3) {
            return std::nullopt;
        }
        for (char c : part) {
            if (c < '0' || c > '9') {
                return std::nullopt;
            }
        }
        if (part.size() > 1 && part[0] == '0') {
            // Reject leading zeros ("010") rather than silently guessing whether the author
            // meant decimal or (as some parsers historically treated it) octal -- ambiguous
            // enough in real-world IP tooling that flatly rejecting it is the safer default.
            return std::nullopt;
        }
        int value = std::stoi(part);
        if (value < 0 || value > 255) {
            return std::nullopt;
        }
        result = (result << 8) | static_cast<uint32_t>(value);
    }
    return result;
}

}  // namespace conduitscope
