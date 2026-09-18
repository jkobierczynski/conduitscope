// SPDX-License-Identifier: Apache-2.0
// eapol.hpp - IEEE 802.1X/EAPOL (EtherType 0x888E) decoding: the 4-byte EAPOL header (Version +
// Type + Length), plus a shallow, deliberately bounded look inside the two body shapes worth an OT
// auditor's attention -- an encapsulated EAP packet's own Code/Identifier/Type, and an EAPOL-Key
// frame's Descriptor Type -- without attempting a full EAP state-machine or key-derivation decode.
//
// This is ROADMAP item 18's Tier 3 entry that, unlike NTP/DHCP/LDAP/RADIUS/TACACS+, rides directly
// on raw Ethernet (EtherType 0x888E, IEEE Std 802.1X) rather than any TCP/UDP port at all -- the
// same "no port, no IP layer" shape PROFINET RT/GOOSE/SV/EtherCAT already have in this codebase
// (see those files' own header comments), so this file follows their own structure: its own
// dedicated file, its own try_parse_eapol entry point, wired into decoder.cpp's EtherType-keyed
// dispatch chain rather than it_protocols.hpp's port-based one.
//
// Audit framing (see docs/MANUAL.md's ROADMAP item 18): 802.1X is port-based network access
// control at the switch port itself -- seeing EAPOL on an OT access port is evidence a device had
// to authenticate onto the network before it could pass any other traffic at all, which cuts the
// OPPOSITE way from most of this item's other protocols: here, PRESENCE is reassuring and ABSENCE
// on an OT switch port is often the real finding (anything can plug in and reach the segment
// unauthenticated). This decoder still only names what it sees -- it has no way to observe "802.1X
// is configured but this port's traffic doesn't show it" from a passive capture, only "802.1X
// traffic was or wasn't captured here."
//
// Wire format (IEEE Std 802.1X, cross-checked against Wireshark's own EAPOL dissector,
// epan/dissectors/packet-eapol.c, and IETF RFC 3748 for the encapsulated EAP packet shape):
//   EAPOL header, 4 bytes, immediately after the EtherType (or after a single already-unwrapped
//   802.1Q VLAN tag):
//     Version (1 byte): 1 = IEEE 802.1X-2001, 2 = IEEE 802.1X-2004, 3 = IEEE 802.1X-2010 (also the
//       version MKA, IEEE 802.1X-2010's MACsec Key Agreement extension, uses).
//     Type (1 byte): which of nine defined frame kinds this is --
//         0 = EAP-Packet             -- an encapsulated EAP packet (RFC 3748), see below
//         1 = EAPOL-Start            -- supplicant-initiated; always Length 0
//         2 = EAPOL-Logoff           -- supplicant-initiated; always Length 0
//         3 = EAPOL-Key              -- key material (802.11 4-way handshake, or MACsec/MKA-
//                                       adjacent on wired links); see the Descriptor Type below
//         4 = EAPOL-Encapsulated-ASF-Alert -- legacy, alerting-standard-forum encapsulation
//         5 = EAPOL-MKA              -- IEEE 802.1X-2010 MACsec Key Agreement protocol
//         6 = EAPOL-Announcement (Generic)
//         7 = EAPOL-Announcement (Specific)
//         8 = EAPOL-Announcement-Req
//       Any other Type value (9-255) is not one of the nine the spec defines.
//     Length (2 bytes, big-endian): the body's own length in bytes (0 for EAPOL-Start/Logoff,
//       which carry no body at all).
//   Body (Length bytes, present per Type): this file looks inside exactly two of the nine shapes,
//   both deliberately shallow (see "Explicitly out of scope" below):
//     Type 0 (EAP-Packet): RFC 3748 section 4's own EAP header -- Code (1 byte: 1 = Request,
//       2 = Response, 3 = Success, 4 = Failure), Identifier (1 byte), Length (2 bytes, big-endian,
//       the EAP packet's OWN declared length, not re-validated against EAPOL's outer Length here).
//       For Code Request/Response only, a further Type byte follows (RFC 3748 section 5's EAP
//       Method Type registry, cross-checked against IANA's "Extensible Authentication Protocol
//       (EAP) Registry"): a small curated set worth naming is recognized (1 = Identity,
//       2 = Notification, 3 = Nak, 4 = MD5-Challenge, 6 = Generic Token Card (GTC), 13 = EAP-TLS,
//       21 = EAP-TTLS, 25 = PEAP, 26 = MS-EAP-Authentication (EAP-MSCHAPv2), 43 = EAP-FAST,
//       50 = Expanded Types) -- anything else is still reported, just by its raw numeric value. No
//       further EAP Method-specific content (a TLS ClientHello inside EAP-TLS, an MSCHAPv2
//       challenge, etc.) is parsed at all.
//     Type 3 (EAPOL-Key): only the very first body byte, Descriptor Type (802.1X-2004 section
//       7.4/802.11i's own key-descriptor registry): 1 = RC4 Key Descriptor (legacy, pre-RSN
//       802.11 draft, rarely seen), 2 = IEEE 802.11 Key Descriptor (RSN/WPA2), 254 = WPA Key
//       Descriptor (pre-RSN "WPA1"). Nothing past that one byte (key information flags, nonce, MIC,
//       key data) is parsed.
//
// Explicitly out of scope, deliberately: EAP Method-specific content past the Type byte (this
// decoder never attempts to follow an EAP-TLS handshake, PEAP tunnel, or any credential-bearing
// exchange -- there is no OT-security value in it for this item's own "is 802.1X present" framing,
// and several methods are themselves TLS-encrypted and opaque by design past that point anyway);
// EAPOL-Key's own key-information bitfield, nonce, MIC, and key-data fields; EAPOL-MKA's own MACsec
// Key Agreement PDU body (Type 5, named only by its Type, not parsed further); the three
// Announcement Types' own TLV bodies (Types 6-8, likewise named only).
//
// Structural detection gate: like EtherCAT (see ethercat.hpp's own "structural detection gate"
// paragraph), EAPOL's own header has no field whose value space is naturally self-restricting the
// way GOOSE/SV's single-byte outer BER tag does -- Version admits 3 valid values out of 256 and
// Type admits 9 out of 256, a much looser gate than a 1-in-256 tag match. As with EtherCAT, the
// primary source of confidence that a 0x888E frame actually is EAPOL remains the EtherType itself,
// which has no collision risk with any other protocol this tool decodes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

struct EapolFrame {
    uint8_t version = 0;
    std::string version_name;
    uint8_t type = 0;
    std::string type_name;
    uint16_t length = 0;  // EAPOL's own declared body length
    std::string summary;
    std::vector<std::string> notes;

    // Set only when type == 0 (EAP-Packet) and the body is at least 4 bytes (RFC 3748's own
    // Code/Identifier/Length header).
    bool has_eap = false;
    uint8_t eap_code = 0;
    std::string eap_code_name;
    uint8_t eap_identifier = 0;
    uint16_t eap_declared_length = 0;
    // Set only when has_eap is true AND eap_code is Request(1) or Response(2) AND a further Type
    // byte is present.
    bool has_eap_type = false;
    uint8_t eap_type = 0;
    std::string eap_type_name;

    // Set only when type == 3 (EAPOL-Key) and the body has at least 1 byte.
    bool has_eapol_key_descriptor = false;
    uint8_t eapol_key_descriptor_type = 0;
    std::string eapol_key_descriptor_type_name;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x888E -- or after a
// single already-unwrapped 802.1Q VLAN tag) as one EAPOL frame. Returns std::nullopt (never throws)
// when the 4-byte header itself doesn't fit, or Version/Type aren't one of the spec-defined values
// listed above -- see this file's own "structural detection gate" paragraph for why the EtherType
// carries most of the confidence here, same as EtherCAT's own try_parse_ethercat.
std::optional<EapolFrame> try_parse_eapol(ByteSpan eth_payload);

}  // namespace conduitscope
