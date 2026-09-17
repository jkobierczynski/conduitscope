// SPDX-License-Identifier: Apache-2.0
// hsrp.hpp - HSRP (Hot Standby Router Protocol) v1 (RFC 2281) and v2 (Cisco proprietary)
// decoding.
//
// HSRPv1 is a single fixed-format 20-byte UDP payload (RFC 2281 section 5.1): Version(1) +
// OpCode(1) + State(1) + Hellotime(1, seconds) + Holdtime(1, seconds) + Priority(1) + Group(1) +
// Reserved(1) + Authentication Data(8, cleartext plaintext password) + Virtual IP Address(4).
// HSRPv2 (never formally standardized; Cisco-proprietary, needed for more than 255 groups and for
// IPv6) abandons that fixed layout entirely in favor of a flat TLV chain -- Type(1) + Length(1,
// payload bytes only, excluding these 2 header bytes) + Value -- with no header before the first
// TLV. Four TLV types are defined: 1 Group State, 2 Interface State, 3 Text Authentication, 4 MD5
// Authentication. Only Group State (by far the common case, and the only one carrying the fields
// this decoder's HSRPv1 support already exposes) is decoded field-by-field here; the other three
// are recognized and shown with their raw bytes, not decoded further (see docs/MANUAL.md
// Roadmap).
//
// This decoder tries the HSRPv1 fixed shape first (exactly 20 bytes, Version byte 0, a valid
// OpCode and State) and falls back to parsing the remaining bytes as a v2 TLV chain otherwise --
// see try_parse_hsrp's own comment for the exact structural checks used to tell them apart.
//
// Group State TLV layout (as reverse-engineered from Wireshark's packet-hsrp.c, since Cisco never
// published this format): Version(1) + OpCode(1) + State(1) + IP Version(1, 4 or 6) + Group
// Number(2) + Identifier(6, a MAC-ish per-group identifier) + Priority(4) + Active/Hello
// Timer(4, milliseconds) + Standby/Hold Timer(4, milliseconds) + Virtual IP Address(4 for IPv4,
// 16 for IPv6). For an IPv6 Group State TLV that totals exactly the TLV's declared 40-byte
// length (24 + 16); for IPv4 it only accounts for 28 of the declared 40 bytes, leaving 12 bytes
// of reserved/padding this decoder does not attempt to interpret. This project has no IPv6
// address formatting anywhere (see decoder.hpp/ipv4.hpp), so an IPv6 Group State TLV's Virtual IP
// Address is left undecoded (noted, not guessed at) -- everything else in it still decodes fully.
//
// Cross-checked against Wireshark's own packet-hsrp.c directly (Cisco has never published an
// official HSRPv2 specification).
//
// Security context: like VRRP (see vrrp.hpp), HSRP lets any host on the segment send a
// higher-priority Hello/Coup and take over as the active router -- a gateway-spoofing/MITM
// primitive. HSRPv1's only authentication (an 8-byte plaintext field, conventionally the ASCII
// string "cisco" when "enabled" at all) provides no real protection; this decoder surfaces it
// directly for exactly that reason.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t HSRP_PORT = 1985;  // v1, and v2 over IPv4 (224.0.0.102); v2 over IPv6 uses UDP
                                        // 2029 instead, not handled by this decoder (see this
                                        // file's header comment on the lack of IPv6 support).

struct HsrpTlv {
    uint8_t type = 0;
    std::string type_name;  // "Group State" (1), "Interface State" (2), "Text Authentication"
                              // (3), "MD5 Authentication" (4), or "Unknown (N)"
    uint8_t length = 0;      // declared payload length (Value only, excludes these 2 header bytes)

    // Populated only when type == 1 (Group State) and `length` was large enough to confidently
    // decode at least the IPv4-sized portion of it (24 bytes: everything up to but not including
    // Virtual IP Address) -- see this file's header comment for the exact layout.
    bool group_state_decoded = false;
    uint8_t hsrp_version = 0;
    uint8_t opcode = 0;
    std::string opcode_name;
    uint8_t state = 0;
    std::string state_name;
    uint8_t ip_version = 0;  // 4 or 6, as declared in the TLV
    uint16_t group_number = 0;
    std::string identifier;  // the 6-byte per-group identifier, formatted like a MAC address
    uint32_t priority = 0;
    uint32_t hello_time_ms = 0;
    uint32_t hold_time_ms = 0;
    std::string virtual_ip;  // decoded only when ip_version == 4; empty (with a note) for IPv6 or
                               // a truncated field

    // Populated whenever group_state_decoded is false (any non-Group-State TLV, or a Group State
    // TLV too short to decode): the TLV's Value bytes, verbatim, as hex.
    std::string raw_value_hex;
};

struct HsrpMessage {
    uint8_t version = 0;  // 1 or 2

    // v1 only (RFC 2281) -- a fixed 20-byte message, no TLV framing.
    uint8_t opcode = 0;
    std::string opcode_name;  // "Hello" (0), "Coup" (1), "Resign" (2), "Advertise" (3), or
                                // "Unknown (N)"
    uint8_t state = 0;
    std::string state_name;   // "Initial" (0), "Learn" (1), "Listen" (2), "Speak" (4), "Standby"
                                // (8), "Active" (16), or "Unknown (N)"
    uint8_t hello_time_sec = 0;
    uint8_t hold_time_sec = 0;
    uint8_t priority = 0;
    uint8_t group = 0;
    std::string auth_data;   // 8-byte cleartext authentication field, trailing NUL padding
                               // stripped -- see this file's own Security context note
    std::string virtual_ip;

    // v2 only -- TLV framed, no fixed header before the first TLV.
    std::vector<HsrpTlv> tlvs;  // capped at 50 entries
    bool tlvs_truncated = false;  // true if more than 50 TLVs were present

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as an HSRP message. Tries the HSRPv1 fixed 20-byte shape
// first: exact length 20, Version byte 0, OpCode in {0,1,2,3}, and State in the six values RFC
// 2281 defines. If that doesn't match, tries parsing the whole payload as a flat HSRPv2 TLV chain
// (Type+Length+Value repeated with no gaps or leftover bytes) whose first TLV's type is one of
// the four defined values -- requiring the chain to consume the payload exactly, and requiring a
// recognized first TLV type, keeps an arbitrary non-HSRP UDP payload from being misdetected (HSRP
// has no protocol-identifying magic number of its own in either version). Returns std::nullopt
// (never throws) if neither shape matches. Both shapes are structurally weak signals on their
// own, which is why decoder.cpp only ever tries this on UDP port 1985 in Auto mode (an explicit
// --protocol hsrp bypasses the port gate, same convention as RIP -- see decoder.hpp's
// DecodeOptions::extra_hsrp_ports).
std::optional<HsrpMessage> try_parse_hsrp(ByteSpan udp_payload);

}  // namespace conduitscope
