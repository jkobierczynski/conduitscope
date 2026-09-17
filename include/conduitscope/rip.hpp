// SPDX-License-Identifier: Apache-2.0
// rip.hpp - RIP (Routing Information Protocol) v1 (RFC 1058) and v2 (RFC 2453) decoding.
//
// A RIP message is a 4-byte header (Command, Version, and a 2-byte field that RFC 1058 calls
// "must be zero" and RFC 2453 repurposes as a "Routing Domain" -- neither is decoded any further
// here; it's just shown as a raw value) followed by zero or more 20-byte Route Table Entries
// (RTEs). RIPv1 and RIPv2 share the exact same 20-byte RTE layout on the wire -- RIPv2 simply
// gives meaning to three fields RIPv1 requires to be zero (Route Tag, Subnet Mask, Next Hop) --
// so this decoder reads every RTE the same way regardless of version and flags it as a note when a
// RIPv1 message's own "must be zero" fields aren't (see decode_route below).
//
// Two RTE shapes are NOT ordinary routes and are recognized structurally rather than decoded as an
// address: Address Family Identifier (AFI) 0 with metric 16 is a client's "give me your whole
// table" Request (RFC 1058 section 3.4.1), and AFI 0xFFFF (RIPv2 only) marks an authentication
// entry (RFC 2453 section 4.2, RFC 2082) rather than a route -- see decode_route's own comment for
// exactly what's decoded from each authentication type.
//
// Cross-checked against Wireshark's own packet-rip.c and RFC 1058/2453/2082 directly (RIP's wire
// format has been stable for over three decades, unlike some of this project's more obscure OT
// protocols -- there is no ambiguity here to resolve against a single example capture).
//
// Security context: RIP has no meaningful authentication in practice. RIPv1 has none at all; RIPv2
// "Simple Password" authentication (AuthType 2) sends the password in plaintext on the wire (this
// decoder surfaces it directly -- see decode_route), and even MD5 authentication (AuthType 3, RFC
// 2082) only proves the sender knows a shared key, not who the sender actually is. Seeing RIP
// traffic at all on a segment is itself often worth a second look: it's a legacy, low-security IGP
// that a well-segmented modern network (OT or otherwise) usually shouldn't be running.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t RIP_PORT = 520;

struct RipRoute {
    uint16_t address_family = 0;
    std::string address_family_name;  // "IP" (2), "Request for full table" (0, Request command
                                        // only), "Authentication" (0xFFFF, RIPv2 only), or
                                        // "Unknown (N)"
    bool is_auth_entry = false;       // address_family == 0xFFFF -- the fields below are NOT a
                                        // route at all; see auth_* fields instead
    bool is_full_table_request = false;  // address_family == 0 in a Request message

    // Meaningful only when !is_auth_entry (an ordinary route, or the full-table-request marker
    // entry, which still carries these fields even though they're conventionally all zero).
    uint16_t route_tag = 0;      // RIPv2: redistribution tag; RIPv1: must be zero
    std::string address;         // dotted-quad
    std::string subnet_mask;     // RIPv2 only; RIPv1: must be zero (shown as 0.0.0.0)
    std::string next_hop;        // RIPv2 only, 0.0.0.0 means "use the sender's own address";
                                   // RIPv1: must be zero
    uint32_t metric = 0;         // 1-15 valid, 16 = infinity/unreachable

    // Meaningful only when is_auth_entry -- see RFC 2453 section 4.2 (Simple Password) and RFC
    // 2082 (Keyed MD5). auth_type 2 and 3 are the only two RFC-defined types.
    uint16_t auth_type = 0;
    std::string auth_type_name;   // "Simple Password" (2), "Keyed Message Digest (MD5)" (3), or
                                    // "Unknown (N)"
    std::string auth_password;    // auth_type == 2 only: the cleartext password, trailing NUL
                                    // bytes stripped -- see decode_route's own security-context note
    // auth_type == 3 (MD5) only -- RFC 2082's own auth-header fields, all decoded; the trailing
    // digest value (a SEPARATE 20-byte-ish block appended after every real route RTE) is NOT
    // located or verified -- see this file's own header comment and LIMITATIONS.
    uint16_t md5_packet_length = 0;   // RFC 2082 "RIP-2 Packet Length": byte offset where the
                                        // real header+route data ends (i.e. where this auth header
                                        // itself starts)
    uint8_t md5_key_id = 0;
    uint8_t md5_auth_data_length = 0;  // digest length that follows the packet, typically 16
    uint32_t md5_sequence_number = 0;
};

struct RipMessage {
    uint8_t command = 0;
    std::string command_name;  // "Request" (1), "Response" (2), "Trace On" (3, obsolete -- RFC
                                 // 1058 section 5.1), "Trace Off" (4, obsolete), "Reserved (used by
                                 // Sun Microsystems' routed)" (5, RFC 1058's own historical note),
                                 // or "Unknown (N)"
    uint8_t version = 0;        // 1 or 2

    std::vector<RipRoute> routes;  // capped at 50 entries, same convention as every other
                                     // repeated-element list in this codebase (see s7comm_item_tags
                                     // in decoder.hpp)
    bool routes_truncated = false;  // true if more than 50 route table entries were present

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as a RIP message. Returns std::nullopt (never throws) if the
// payload is shorter than the 4-byte header, `command` isn't one of the five values RFC 1058
// defines, or `version` isn't 1 or 2 -- three real structural constraints, though still a
// deliberately weak gate on their own (a handful of small integers), which is why decoder.cpp only
// ever tries this on UDP port 520 in Auto mode (an explicit --protocol rip bypasses the port gate,
// same convention as DNS/mDNS/LLMNR/NBT-NS -- see decoder.hpp's DecodeOptions::extra_rip_ports).
// A payload whose route-table-entry bytes don't divide evenly into 20-byte chunks is still decoded
// (every complete 20-byte RTE found), with the leftover bytes noted as truncation rather than
// rejecting the whole message.
std::optional<RipMessage> try_parse_rip(ByteSpan udp_payload);

}  // namespace conduitscope
