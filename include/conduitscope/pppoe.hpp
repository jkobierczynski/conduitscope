// SPDX-License-Identifier: Apache-2.0
// pppoe.hpp - PPPoE (RFC 2516, EtherType 0x8863 Discovery / 0x8864 Session) decoding: the 6-byte
// PPPoE header (Ver/Type/Code/Session ID/Length), plus, for the Session stage only, a shallow look
// at the encapsulated PPP frame's own leading Protocol field (RFC 1661 section 2) -- without
// attempting to parse anything past that field.
//
// This is ROADMAP item 18's Tier 4 entry that, like EAPOL in Tier 3, rides directly on raw Ethernet
// (EtherType 0x8863/0x8864) rather than any TCP/UDP port at all -- the same "no port, no IP layer"
// shape PROFINET RT/GOOSE/SV/EtherCAT/EAPOL already have in this codebase (see those files' own
// header comments), so this file follows their own structure: its own dedicated file, its own
// try_parse_pppoe entry point, wired into decoder.cpp's EtherType-keyed dispatch chain rather than
// it_protocols.hpp's port-based one.
//
// Audit framing (see docs/MANUAL.md's ROADMAP item 18, Tier 4): PPPoE and GTP-U are grouped
// together in this item's own wording as "cellular-backhaul-specific protocols" -- a site's RTU or
// 4G/5G router commonly terminates its own WAN uplink (to a carrier, or to a vendor's "cloud
// gateway") over a PPP session, and PPPoE (RFC 2516's own "PPP over Ethernet") is the most common
// way that PPP session is carried across the last hop from the router to whatever media converter
// or ONT/modem actually reaches the carrier. Seeing PPPoE traffic on or near an OT segment is worth
// exactly the same auditor attention as CAPWAP/LWAPP in this same tier: it names a WAN-facing egress
// path that may bypass an on-prem firewall's own view of the traffic entirely, independent of
// whatever rides inside the resulting PPP session (an IP packet ultimately headed the same place
// GTP-U's own G-PDU packets go). This file only names the PPPoE stage/code and, for Session-stage
// traffic, the encapsulated PPP frame's own Protocol field -- it never follows the PPP session into
// its own IP payload.
//
// Wire format (RFC 2516 section 4, cross-checked against Wireshark's own PPPoE dissector,
// epan/dissectors/packet-pppoe.c):
//   PPPoE header, 6 bytes, immediately after the EtherType (or after a single already-unwrapped
//   802.1Q VLAN tag):
//     Ver (4 bits, high nibble of byte 0): always 1.
//     Type (4 bits, low nibble of byte 0): always 1.
//     Code (1 byte): which of the defined frame kinds this is. In the Discovery stage (EtherType
//       0x8863) one of five values: 0x09 = PADI (Active Discovery Initiation), 0x07 = PADO (Active
//       Discovery Offer), 0x19 = PADR (Active Discovery Request), 0x65 = PADS (Active Discovery
//       Session-confirmation), 0xA7 = PADT (Active Discovery Terminate, can also appear in the
//       Session stage to tear a session down). In the Session stage (EtherType 0x8864), Code is
//       always 0x00 ("Session Data") -- the frame is carrying an encapsulated PPP frame, see below.
//     Session ID (2 bytes, big-endian): 0x0000 during discovery (before a session exists); the
//       server-assigned session identifier once PADS has completed.
//     Length (2 bytes, big-endian): the payload's own length in bytes, following this 6-byte header.
//   Payload (Length bytes): for the Session stage only, this is a PPP frame (RFC 1661 section 2)
//   starting with its own 2-byte Protocol field, cross-checked against RFC 1661/1662 and IANA's own
//   "Point-to-Point Protocol (PPP) Protocol Field Assignments" registry -- a small curated subset is
//   recognized (0x0021 = IP, 0x0057 = IPv6, 0x8021 = IPCP, 0x8057 = IPv6CP, 0xC021 = LCP (Link
//   Control Protocol), 0xC023 = PAP (Password Authentication Protocol), 0xC025 = LQR (Link Quality
//   Report), 0xC223 = CHAP (Challenge Handshake Authentication Protocol), 0xC229 = EAP (over PPP)) --
//   anything else is still reported by its raw numeric value. PAP (0xC023) earns its own note: RFC
//   1334's Password-Authenticate-Request carries the username/password pair in cleartext, the same
//   "worth a note but not credential extraction" treatment LDAP's own bindRequest gets in Tier 3 (see
//   it_protocols.hpp's own Tier 3 comment). No further PPP content (an LCP option list, a CHAP
//   challenge, or anything inside the eventual IP payload once the link comes up) is parsed at all.
//
// Explicitly out of scope, deliberately: the PPP session's own inner IP traffic once the link
// negotiates up (that traffic reaches this decoder separately as an ordinary IPv4/IPv6 frame only if
// it is captured un-encapsulated -- this decoder does not unwrap a PPPoE Session frame's PPP payload
// to feed it back through IPv4/TCP/UDP dispatch, the same "name the tunnel, don't follow it" posture
// GTP-U's own G-PDU takes in it_protocols.hpp); LCP/IPCP/IPv6CP/CCP/EAP's own negotiation content
// past the Protocol field; PAP/CHAP's own credential/challenge bytes (named as a risk, never
// extracted, matching this whole ROADMAP item's name-only posture).
//
// Structural detection gate: like EAPOL (see eapol.hpp's own "structural detection gate" paragraph),
// PPPoE's Ver/Type nibbles are fixed to a single value each (a much looser gate than GOOSE/SV's own
// single-byte outer BER tag), and Code is drawn from a small enumerated set. As with EAPOL, the
// primary source of confidence that a 0x8863/0x8864 frame actually is PPPoE remains the EtherType
// itself, which has no collision risk with any other protocol this tool decodes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

struct PppoeFrame {
    uint8_t version = 0;  // always 1
    uint8_t type = 0;     // always 1
    uint8_t code = 0;
    std::string code_name;  // "PADI"/"PADO"/"PADR"/"PADS"/"PADT"/"Session Data"
    uint16_t session_id = 0;
    uint16_t length = 0;  // PPPoE's own declared payload length
    bool is_session = false;  // true for EtherType 0x8864 (Session stage), false for Discovery (0x8863)
    std::string summary;
    std::vector<std::string> notes;

    // Set only when is_session && the payload carried at least PPP's own 2-byte Protocol field.
    bool has_ppp_protocol = false;
    uint16_t ppp_protocol = 0;
    std::string ppp_protocol_name;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x8863/0x8864 -- or
// after a single already-unwrapped 802.1Q VLAN tag) as one PPPoE frame. `is_session_ethertype` is
// which of the two EtherTypes actually dispatched here (true for 0x8864 Session, false for 0x8863
// Discovery) -- it selects which Code value(s) are valid, since the two stages don't share a Code
// space (see this file's own header comment). Returns std::nullopt (never throws) when the 6-byte
// header itself doesn't fit, Ver/Type aren't both 1, or Code doesn't match the stage the EtherType
// itself claims -- see this file's own "structural detection gate" paragraph for why the EtherType
// carries most of the confidence here, same as EAPOL's own try_parse_eapol.
std::optional<PppoeFrame> try_parse_pppoe(ByteSpan eth_payload, bool is_session_ethertype);

}  // namespace conduitscope
