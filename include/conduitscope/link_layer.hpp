// SPDX-License-Identifier: MIT
// link_layer.hpp - Ethernet II (and single 802.1Q VLAN tag) framing.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;

struct EthernetFrame {
    std::array<uint8_t, 6> dst_mac{};
    std::array<uint8_t, 6> src_mac{};
    uint16_t ethertype = 0;   // the "real" ethertype, after unwrapping one VLAN tag if present
    bool has_vlan_tag = false;
    uint16_t vlan_id = 0;     // only meaningful if has_vlan_tag
    ByteSpan payload;         // everything after the (possibly VLAN-tagged) header
};

// Parses an Ethernet II frame. Understands a single 802.1Q VLAN tag; stacked
// (QinQ) tags are not unwrapped -- the tool will simply fail to recognize the
// inner ethertype and report "unsupported ethertype" for those packets.
// Throws ParseError if `frame` is shorter than a minimal Ethernet header.
EthernetFrame parse_ethernet(ByteSpan frame);

// Handles the pcap LINKTYPE_RAW case (no link-layer header at all, payload is
// straight to an IPv4/IPv6 header). Kept separate from parse_ethernet so the
// decoder can branch on the capture file's declared link type.
struct RawIpFrame {
    ByteSpan payload;
};
RawIpFrame parse_raw_ip(ByteSpan frame);

std::string format_mac(const std::array<uint8_t, 6>& mac);

}  // namespace conduitscope
