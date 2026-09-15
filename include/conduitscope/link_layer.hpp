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

// A small set of other EtherTypes worth naming in output when a non-IPv4 frame is seen --
// deliberately not an exhaustive IEEE EtherType registry, just the ones an OT/ICS capture is
// actually likely to contain: a handful of raw-Ethernet (no IP layer at all) OT protocols this
// tool does not yet decode (see ethertype_name's own comment and docs/MANUAL.md's ROADMAP), plus
// a few generic ones common enough to be worth telling apart from "unrecognized" at a glance.
// Values cross-checked against Wireshark's own epan/etypes.h, not reverse-engineered from a
// single capture.
constexpr uint16_t ETHERTYPE_ARP = 0x0806;
constexpr uint16_t ETHERTYPE_IPV6 = 0x86DD;
constexpr uint16_t ETHERTYPE_PROFINET = 0x8892;   // PROFINET RT (Siemens), raw Ethernet, no IP
constexpr uint16_t ETHERTYPE_ETHERCAT = 0x88A4;   // EtherCAT, raw Ethernet, no IP
constexpr uint16_t ETHERTYPE_IEC61850_GOOSE = 0x88B8;  // IEC 61850-8-1 GOOSE, raw Ethernet, no IP
constexpr uint16_t ETHERTYPE_IEC61850_SV = 0x88BA;     // IEC 61850-9-2 Sampled Values, raw Ethernet, no IP
constexpr uint16_t ETHERTYPE_LLDP = 0x88CC;
constexpr uint16_t ETHERTYPE_PTP = 0x88F7;        // IEEE 1588 Precision Time Protocol
constexpr uint16_t ETHERTYPE_MPLS_UNICAST = 0x8847;
constexpr uint16_t ETHERTYPE_8021AD = 0x88A8;     // 802.1ad "provider bridging" / stacked (QinQ) VLAN tag

// Returns a short human-readable name for a handful of EtherTypes worth calling out by name
// (see the constants above), or an empty string for anything else -- used when reporting a
// non-IPv4 Ethernet frame (protocol "non-ip") so the summary reads as e.g. "ethertype 0x8892
// (PROFINET RT)" instead of a bare hex number. This is naming only, not decoding: none of these
// protocols' own framing is parsed any further by this groundwork release.
std::string ethertype_name(uint16_t ethertype);

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
