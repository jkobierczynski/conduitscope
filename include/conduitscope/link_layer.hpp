// SPDX-License-Identifier: Apache-2.0
// link_layer.hpp - Ethernet II (and single 802.1Q VLAN tag) framing, PLUS (new in this release)
// classic IEEE 802.3 length-framed LLC/SNAP recognition.
//
// Every protocol this tool decoded before this release was reached either through IPv4 or through
// a DIX Ethernet II EtherType (PROFINET RT/EtherCAT/GOOSE/SV -- see the ETHERTYPE_* constants
// below). Spanning Tree Protocol (STP/RSTP/MSTP -- see stp.hpp) is the first one reached neither
// way: BPDUs are carried in classic IEEE 802.3 framing, where the 16-bit field immediately after
// the source MAC (and after any single 802.1Q VLAN tag, exactly as already unwrapped below) is a
// LENGTH, not an EtherType -- IEEE 802.3's own long-standing rule is that a value < 0x0600 (1536
// decimal) there is always a length (the frame is length-framed, classic 802.3/LLC), and a value
// >= 0x0600 is always an EtherType (the frame is DIX Ethernet II) -- there is no ambiguous range,
// the boundary is exact. `parse_ethernet` previously had zero handling for this distinction: it
// unconditionally treated that field as `ethertype`, so a length-framed capture was simply reported
// as an unrecognized "ethertype" (actually a length value) and nothing further happened.
//
// A length-framed 802.3 frame carries a 3-byte LLC header right after the length field: DSAP(1) +
// SSAP(1) + Control(1). STP's own DSAP=SSAP=0x42 (Wireshark's SAP_BPDU, the IEEE "Bridge Group
// Address" SAP -- also, confusingly, shared with GARP/GVRP/GMRP, distinguished only by destination
// MAC, not by DSAP/SSAP -- see stp.hpp's file header comment and stp.cpp's GARP handling) with
// Control=0x03 ("Unnumbered Information", an LLC Type 1 connectionless frame). When DSAP==SSAP==
// 0xAA instead, the LLC payload is itself SNAP-encapsulated (a further 5-byte header: 3-byte OUI +
// 2-byte Protocol ID) -- needed here only to structurally *name* Cisco (R)PVST+ (OUI 00:00:0C)
// without decoding it, see stp.hpp's "out of scope" section. Every field/offset here is cross-
// checked against Wireshark's own `epan/dissectors/packet-llc.c` (SAP_BPDU, SAP_SNAP) and
// `packet-bpdu.c` (`dissector_add_uint("llc.dsap", SAP_BPDU, bpdu_handle)`).
//
// This is small, additive, and structurally has zero collision risk with any existing dispatch
// path: every length-framed frame (ethertype < 0x0600) was previously simply falling into the
// generic "non-ip" ethertype-name-only report with no further handling at all (no existing decoder
// in this codebase ever looked at a sub-0x0600 "ethertype" value), so recognizing and parsing the
// LLC/SNAP header underneath it changes nothing about any DIX Ethernet II (ethertype >= 0x0600)
// frame's own handling.
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t ETHERTYPE_IPV4 = 0x0800;
constexpr uint16_t ETHERTYPE_VLAN = 0x8100;

// IEEE 802.3's exact length-vs-EtherType boundary -- see this file's header comment. A 16-bit value
// strictly below this, in the position where an EtherType would otherwise be, is always a LENGTH
// (classic 802.3/LLC framing); at or above it, always an EtherType (DIX Ethernet II).
constexpr uint16_t ETHERTYPE_MIN_DIX = 0x0600;

// LLC (Logical Link Control, IEEE 802.2) DSAP/SSAP/Control values this codebase cares about -- see
// this file's header comment. LLC_SAP_BPDU is the IEEE "Bridge Group Address" SAP (STP/RSTP/MSTP,
// but also GARP/GVRP/GMRP -- see stp.hpp); LLC_SAP_SNAP marks a SNAP-encapsulated LLC payload
// (needed here only to recognize, by OUI, Cisco (R)PVST+ -- see stp.hpp); LLC_CONTROL_UI is LLC
// Type 1's "Unnumbered Information" control byte, the only Control value STP ever uses.
constexpr uint8_t LLC_SAP_BPDU = 0x42;
constexpr uint8_t LLC_SAP_SNAP = 0xAA;
constexpr uint8_t LLC_CONTROL_UI = 0x03;

// Cisco's IEEE-assigned OUI, as it appears in a SNAP header's 3-byte Organizationally Unique
// Identifier -- the only SNAP OUI this codebase recognizes by name (Cisco (R)PVST+, see stp.hpp).
constexpr std::array<uint8_t, 3> SNAP_OUI_CISCO = {0x00, 0x00, 0x0C};

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

    // Classic IEEE 802.3 LLC framing -- see this file's header comment. Populated only when the
    // 16-bit field read where an EtherType would be is instead a LENGTH (< ETHERTYPE_MIN_DIX).
    // `ethertype` above still holds that raw 16-bit value either way (so it's still visible to a
    // caller that hasn't been updated for this), but a caller MUST check is_llc_length before
    // treating `ethertype` as a real EtherType -- a length-framed frame is never IPv4 or any other
    // DIX-keyed protocol, since every such value is by definition < 0x0800 (ETHERTYPE_IPV4).
    bool is_llc_length = false;
    uint16_t length_field = 0;  // the raw 802.3 Length value: MAC client data length (LLC header +
                                  // its payload), NOT counting any Ethernet minimum-frame-size
                                  // padding that may follow it in the captured bytes -- see llc_payload

    // The 3-byte LLC header (DSAP/SSAP/Control) -- only attempted, and only meaningful, when
    // is_llc_length; fewer than 3 bytes present after the length field just means has_llc stays
    // false (a malformed/tiny frame, not something worth throwing over).
    bool has_llc = false;
    uint8_t llc_dsap = 0;
    uint8_t llc_ssap = 0;
    uint8_t llc_control = 0;

    // SNAP (Subnetwork Access Protocol) header -- only attempted, and only meaningful, when
    // has_llc && llc_dsap == llc_ssap == LLC_SAP_SNAP. Needed only to structurally name Cisco
    // (R)PVST+ without decoding it -- see stp.hpp's "out of scope" section.
    bool has_snap = false;
    std::array<uint8_t, 3> snap_oui{};
    uint16_t snap_protocol_id = 0;

    // The LLC client's own payload: after the 3-byte LLC header, and after the 5-byte SNAP header
    // too when has_snap. Bounded by the 802.3 Length field above when that field is structurally
    // plausible (covers at least the LLC/SNAP header already consumed, and doesn't exceed what was
    // actually captured) -- trimming off any Ethernet minimum-frame-size padding the same way
    // parse_ipv4's own total-length field already trims IP-level padding (see
    // Ipv4Header::trailing_bytes_trimmed and decoder.cpp's own note for that). Falls back to
    // "everything actually captured after the header" when the Length field ISN'T usable that way
    // (too small to even cover the header already consumed, or bigger than what's actually present
    // -- almost always a snaplen-truncated capture, not evidence the Length field itself is wrong).
    ByteSpan llc_payload;
    size_t llc_trailing_bytes_trimmed = 0;  // > 0 only when llc_payload ended up strictly shorter
                                              // than what was actually captured after the header
};

// Parses an Ethernet II frame, OR a classic length-framed IEEE 802.3/LLC frame -- see this file's
// header comment. Understands a single 802.1Q VLAN tag; stacked (QinQ) tags are not unwrapped --
// the tool will simply fail to recognize the inner ethertype/length and report "unsupported
// ethertype" for those packets. Throws ParseError if `frame` is shorter than a minimal Ethernet
// header (14 bytes, or 18 with a VLAN tag).
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
