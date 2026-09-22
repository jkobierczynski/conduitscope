// SPDX-License-Identifier: Apache-2.0
// arp.hpp - Address Resolution Protocol (RFC 826, EtherType 0x0806) decoding, plus the RFC 903/
// 1931/2390/2225 opcode extensions (RARP/DRARP/InARP/ATMARP) and the RFC 5227 IPv4 Address
// Conflict Detection special cases (ARP Probe, ARP Announcement) this decoder curates on top.
//
// ARP has no transport layer and no IP layer of its own -- it rides directly on raw Ethernet
// (EtherType 0x0806), the same "no port, no IP layer" shape PROFINET RT/GOOSE/SV/EtherCAT/EAPOL/
// PPPoE/MPLS already have in this codebase (see those files' own header comments), so this file
// follows their own structure: its own dedicated file, its own try_parse_arp entry point, wired
// into decoder.cpp's EtherType-keyed dispatch chain.
//
// Wire format (RFC 826's own base layout, cross-checked against Wireshark's packet-arp.c):
//   HTYPE (2 bytes, big-endian): hardware type. 1 = Ethernet (10Mb), the overwhelming real-world
//     case; a handful of other values are IANA-registered (Experimental Ethernet, IEEE 802
//     Networks, ARCNET, FDDI, ATM, Serial Line, ...) but this decoder only names HTYPE=1 --
//     anything else is shown as a bare numeric value, never guessed at further.
//   PTYPE (2 bytes, big-endian): protocol type -- the same 16-bit space as Ethernet's own EtherType
//     field (RFC 826's own note: "the Ethernet type field for the *IP* protocol is 0x0800"). This
//     decoder only names PTYPE=0x0800 (IPv4), matching this codebase's existing IPv4-only posture
//     everywhere else; any other PTYPE is shown as a bare numeric value.
//   HLEN (1 byte): length in bytes of a hardware address (6 for Ethernet MAC addresses).
//   PLEN (1 byte): length in bytes of a protocol address (4 for IPv4).
//   OPER (2 bytes, big-endian): operation code -- see the curated opcode table in arp.cpp. This
//     decoder's structural gate requires OPER to be one of that table's recognized values; an OPER
//     it doesn't recognize is treated as "not really ARP" and the whole frame is declined (see this
//     file's own "structural detection gate" paragraph below).
//   Then, back-to-back, with NO further headers or padding between them:
//     SHA (HLEN bytes)  -- Sender Hardware Address
//     SPA (PLEN bytes)  -- Sender Protocol Address
//     THA (HLEN bytes)  -- Target Hardware Address
//     TPA (PLEN bytes)  -- Target Protocol Address
//   HLEN/PLEN genuinely drive the layout -- they are NOT hardcoded to 6/4 here, even though every
//   curated field below only has real meaning for the HTYPE=1/PTYPE=0x0800/HLEN=6/PLEN=4 case (the
//   overwhelming real-world case, and the only one this decoder renders SHA/THA as a MAC address
//   and SPA/TPA as a dotted-quad for). Any other HTYPE/PTYPE/HLEN/PLEN combination still gets
//   HTYPE/PTYPE/HLEN/PLEN/OPER decoded and named where possible, with SHA/SPA/THA/TPA shown as raw
//   hex instead of guessing at an address format they don't actually have -- see try_parse_arp's own
//   comment for exactly when the "rendered" vs "raw hex" fields are populated.
//
// Curated fields, matching Wireshark's own exact logic for each (verified against packet-arp.c's
// dissect_arp, not guessed):
//   Gratuitous ARP: OPER is Request(1) or Reply(2), AND SPA == TPA. Framed the same way this
//     codebase already frames VRRP/HSRP failover events -- a gratuitous ARP Reply (SPA==TPA,
//     OPER==Reply) is the standard mechanism a host uses to announce "an IP address moved to a new
//     MAC" after a failover, and unsolicited gratuitous ARP traffic in general is also how a
//     duplicate-IP condition or ARP cache poisoning attempt would look on the wire (this decoder
//     names the condition; it does NOT attempt cross-packet duplicate-IP/spoofing detection -- see
//     "Explicitly out of scope" below).
//   ARP Probe (RFC 5227 section 1.1): OPER == Request(1), SPA == 0.0.0.0. A host uses this before
//     it has claimed an IPv4 address at all, to check whether some other host already has it.
//   ARP Announcement (RFC 5227 section 2.4): OPER == Request(1), SPA == TPA (the newly-claimed
//     address), broadcast after a successful probe phase to update every neighbor's ARP cache. This
//     is wire-identical to a gratuitous ARP Request (SPA==TPA, OPER==Request) -- the two notes are
//     NOT mutually exclusive and commonly appear together on the same frame; "Announcement" is just
//     this specific case's own RFC 5227 name for what a gratuitous Request already covers.
//
// Explicitly out of scope, deliberately: ARP spoofing / duplicate-IP detection (needs cross-packet
// IP-to-MAC history this codebase doesn't track for any protocol, not even VRRP/HSRP's own
// "unexpected master" case -- see those files' own scope notes); RARP/DRARP/InARP/ATMARP/MARS/MAPOS
// opcodes' own reply-body semantics beyond the shared SHA/SPA/THA/TPA layout (they're named by
// opcode only, not further decoded -- see the opcode table in arp.cpp); a non-Ethernet/non-IPv4
// HTYPE/PTYPE's SHA/SPA/THA/TPA content (shown as raw hex only, per above).
//
// Structural detection gate: unlike GOOSE/SV's single-byte outer BER tag (a 1-in-256 match) or
// BGP's forthcoming all-0xFF 16-byte Marker, ARP's own header has no field that's naturally that
// restrictive on its own -- but combining three checks together (payload long enough for the fixed
// 8-byte header AND the HLEN/PLEN-driven variable trailer; OPER matching one of the ~20 curated
// opcodes rather than an arbitrary 16-bit value; done BEFORE this decoder is even reached, since
// EtherType 0x0806 has no collision risk with any other protocol this tool decodes) gives a
// reasonably strong combined gate -- comparably strong to EtherCAT's/EAPOL's own EtherType-carries-
// most-of-the-confidence posture (see those files' own "structural detection gate" paragraphs).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

struct ArpMessage {
    uint16_t htype = 0;
    std::string htype_name;  // "Ethernet" for htype==1, else empty (shown as bare numeric value)
    uint16_t ptype = 0;
    std::string ptype_name;  // "IPv4" for ptype==0x0800, else empty (shown as bare numeric value)
    uint8_t hlen = 0;
    uint8_t plen = 0;
    uint16_t oper = 0;
    std::string oper_name;  // always populated -- try_parse_arp declines the frame entirely if this
                              // would be empty (see this decoder's own structural gate)

    // True only for the well-formed, overwhelmingly common case: htype==1 (Ethernet) && hlen==6 &&
    // ptype==0x0800 (IPv4) && plen==4. Only then are sha_mac/spa_ip/tha_mac/tpa_ip populated
    // (rendered as a MAC/dotted-quad string); otherwise sha_hex/spa_hex/tha_hex/tpa_hex hold the
    // same HLEN/PLEN-driven raw bytes as plain hex instead.
    bool is_ethernet_ipv4 = false;
    std::string sha_mac;
    std::string spa_ip;
    std::string tha_mac;
    std::string tpa_ip;
    uint32_t spa_raw = 0;  // host-order; valid only when is_ethernet_ipv4 -- used for the
                             // gratuitous/probe/announcement checks below
    uint32_t tpa_raw = 0;  // host-order; valid only when is_ethernet_ipv4
    std::string sha_hex;
    std::string spa_hex;
    std::string tha_hex;
    std::string tpa_hex;

    // Curated conditions -- see this file's own header comment for the exact definitions. All three
    // require is_ethernet_ipv4 (SPA/TPA comparison is meaningless for a non-IPv4 protocol address).
    bool is_gratuitous = false;
    bool is_probe = false;
    bool is_announcement = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x0806 -- or after a
// single already-unwrapped 802.1Q VLAN tag) as one ARP message. Returns std::nullopt (never throws)
// when fewer than 8 bytes are present (the fixed HTYPE/PTYPE/HLEN/PLEN/OPER header), when OPER isn't
// one of this decoder's curated opcodes (see arp.cpp's op_name), or when the HLEN/PLEN-driven
// trailer (2*HLEN + 2*PLEN more bytes) doesn't fit in what's left -- see this file's own "structural
// detection gate" paragraph for why OPER recognition is load-bearing here, not just cosmetic.
std::optional<ArpMessage> try_parse_arp(ByteSpan eth_payload);

// Stage 2 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper around
// try_parse_arp above. Like EAPOL/PPPoE/MPLS, EtherType-gated with no cross-packet state, so this
// needs nothing beyond id()/gate_kind()/ethertype()/decode(); see arp.cpp. A brand-new protocol
// built entirely on this interface from inception -- no legacy if-chain to coexist with.
class ArpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "arp"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_ARP; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& arp_decoder();

}  // namespace conduitscope
