// SPDX-License-Identifier: Apache-2.0
// mpls.hpp - MPLS (EtherType 0x8847 unicast / 0x8848 multicast, RFC 3032) label-stack decoding.
//
// This is ROADMAP item 18's Tier 5 entry that, like EAPOL (Tier 3) and PPPoE (Tier 4), rides
// directly on raw Ethernet -- no port, no IP layer of its own -- so this file follows their own
// structure: its own dedicated file, its own try_parse_mpls entry point, wired into decoder.cpp's
// EtherType-keyed dispatch chain rather than tunnel_vpn.hpp's port/IP-protocol-number-keyed one, and
// its own dedicated ProtocolFilter::MplsOnly (see decoder.hpp).
//
// Audit framing (see docs/MANUAL.md's ROADMAP item 18): "MPLS/L2VPN/VPLS/pseudowire (label-switched,
// no port at all -- a utility WAN link often carries SCADA over a pseudowire, worth confirming
// encryption and who else shares the same VRF)". Unlike GRE/VXLAN/Geneve above, there is no port or
// header field anywhere in a plain MPLS frame that says what's underneath the label stack -- that is
// controlled entirely by out-of-band LDP/BGP signaling this passive decoder never sees. So this file
// does exactly one real thing: parse the label stack itself (a genuine, fully self-describing
// structure) and name what's visible, without ever guessing at the payload past the Bottom-of-Stack
// label.
//
// Wire format (RFC 3032 section 2.1), a stack of one or more 4-byte label entries:
//   Label (20 bits): the actual MPLS label value. 0-15 are reserved (0 = IPv4 Explicit NULL,
//     1 = Router Alert, 2 = IPv6 Explicit NULL, 3 = Implicit NULL, 4-15 reserved) -- named when seen,
//     otherwise reported as a plain numeric value (real transit labels are overwhelmingly >= 16).
//   Exp/TC (3 bits): originally "Experimental", now "Traffic Class" (RFC 5462) -- used for
//     QoS/ECN marking, surfaced but not interpreted further.
//   S, Bottom of Stack (1 bit): 1 on the last label in the stack, 0 on every label before it -- this
//     is what actually terminates the loop below, not a fixed stack depth.
//   TTL (8 bits): ordinary hop-count TTL, decremented at each label-switching router.
// The stack is walked label-by-label until a Bottom-of-Stack label is found, capped at
// kMaxMplsLabelDepth entries as a sanity bound (a real, non-malformed stack essentially never nests
// this deep) -- a stack that runs out of captured bytes before an S bit is found, or that exceeds the
// cap, is reported as truncated/deep rather than treated as a parse failure, the same tolerant
// posture GOOSE/SV/EtherCAT's own declared-length checks already have.
//
// Payload past the Bottom-of-Stack label: per this ROADMAP item's own wording, an ordinary MPLS-
// switched IP packet and an MPLS pseudowire/L2VPN/VPLS payload (an entire Ethernet frame, optionally
// preceded by a 4-byte all-zero Pseudowire Control Word, RFC 4385) are WIRE-FORMAT IDENTICAL from
// this decoder's own point of view -- both are just "the bytes after the last label". This file does
// not attempt to guess which one it's looking at (a heuristic first-nibble check the way IP-in-IP's
// own does would be far less reliable here: a pseudowire's Control Word is frequently all zero bytes,
// which is indistinguishable from padding or truncation, and an Ethernet destination MAC's own first
// nibble is not remotely constrained the way an IP version nibble is) -- it is named only as "MPLS-
// encapsulated payload, not decoded further (could be IP, an L2VPN/VPLS/pseudowire Ethernet frame, or
// a nested inner label stack)" and left there. See docs/MANUAL.md's LIMITATIONS for the user-facing
// version of this scope boundary.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

// CLI-configurable via --max-recursion-depth -- see resource_limits.hpp. 0/unset keeps the
// literal 16 default this constant always had. An inline function rather than a constexpr/const
// namespace-scope value, since it now reads process-wide configuration; called fresh at each use
// in mpls.cpp.
inline size_t mpls_max_label_depth() { return resource_limits().max_recursion_depth.value_or(16); }

struct MplsLabelEntry {
    uint32_t label = 0;
    std::string label_name;  // "IPv4 Explicit NULL" / "Router Alert" / "IPv6 Explicit NULL" /
                               // "Implicit NULL" for labels 0-3, empty for everything else
                               // (4-15 are reserved-but-unnamed, 16+ are ordinary transit labels)
    uint8_t exp = 0;          // Exp/Traffic Class, 3 bits
    bool bottom_of_stack = false;
    uint8_t ttl = 0;
};

struct MplsFrame {
    std::vector<MplsLabelEntry> labels;  // always at least 1 entry when try_parse_mpls succeeds
    bool stack_truncated = false;   // ran out of captured bytes before a Bottom-of-Stack label
    bool stack_too_deep = false;    // hit kMaxMplsLabelDepth without a Bottom-of-Stack label
    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x8847/0x8848 -- or
// after a single already-unwrapped 802.1Q VLAN tag) as an MPLS label stack. Returns std::nullopt
// (never throws) only when fewer than 4 bytes are available -- not even one whole label entry fits.
// Unlike EAPOL/PPPoE above, there is no Version/Type field to structurally validate here at all: any
// 4-byte-aligned value is syntactically a valid label entry, so (exactly like GRE's own Protocol Type
// sub-cases, or IGMP/VRRP's own IP-protocol-number-only gate) the EtherType itself carries all of the
// confidence that this really is MPLS -- see this file's own header comment.
std::optional<MplsFrame> try_parse_mpls(ByteSpan eth_payload);

}  // namespace conduitscope
