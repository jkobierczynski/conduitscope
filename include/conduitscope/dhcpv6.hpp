// SPDX-License-Identifier: Apache-2.0
// dhcpv6.hpp - DHCPv6 (RFC 8415) decoding: client/server messages and the RELAY-FORW/RELAY-REPL
// relay-agent message shape, both sharing the same generic option TLV grammar.
//
// This is the second half of roadmap item 45's decode prerequisites (docs/DEVELOPMENT.md) -- no
// DHCPv6 decoder of any kind existed in this codebase before this addition (unlike DHCP(v4), which
// is already recognized, but only as a lightweight message-type-only recognizer -- it_protocols.hpp/
// notable_it_protocols.hpp -- NOT a structural template for this file: DHCPv6 needs real option
// decoding for ipv6_attack_detect.hpp's own exhaustion/rogue-server counting to have anything to
// key distinct clients/servers by). See ipv6_attack_detect.hpp for the curated notes built on top
// of this decoder, and icmpv6.hpp for the other half of roadmap item 45 (SLAAC/rogue-RA).
//
// SOURCING: RFC 8415 throughout -- section 8 (client/server message header), section 9
// (RELAY-FORW/RELAY-REPL header), section 7.3 (the 13 message types), section 7.2 (UDP ports 546/
// 547), section 21 (every option this decoder interprets), section 11 (DUID formats), and RFC 6355
// (DUID-UUID, section 4).
//
// WIRE SHAPES -- two completely different message headers, dispatched on the first byte
// (msg-type) before picking which one to parse:
//   Client/server (RFC 8415 8): msg-type(1B) + transaction-id(3B) + options
//   RELAY-FORW/RELAY-REPL (RFC 8415 9): msg-type(1B) + hop-count(1B) + link-address(16B) +
//     peer-address(16B) + options
// This decoder decodes the RELAY-FORW/RELAY-REPL header fields (hop-count/link-address/
// peer-address) but does NOT recurse into the inner "Relay Message" option's own nested client/
// server message -- see OUT OF SCOPE below.
//
// MESSAGE TYPES (RFC 8415 7.3): 1 SOLICIT, 2 ADVERTISE, 3 REQUEST, 4 CONFIRM, 5 RENEW, 6 REBIND,
// 7 REPLY, 8 RELEASE, 9 DECLINE, 10 RECONFIGURE, 11 INFORMATION-REQUEST, 12 RELAY-FORW,
// 13 RELAY-REPL.
//
// PORTS (RFC 8415 7.2): UDP 546 = client, UDP 547 = server/relay.
//
// OPTION TLV (RFC 8415 21.1) -- option-code(2B) + option-len(2B) + option-data(option-len bytes),
// an EXACT byte length with no padding/rounding, unlike ICMPv6/NDP's own Length-in-8-byte-units
// option shape (icmpv6.hpp) -- do not reuse that walking code for this.
//
// OPTIONS DECODED (RFC 8415 21, section numbers below):
//   1  Client Identifier (21.2) / 2 Server Identifier (21.3) -- option-data is a DUID (see below).
//   3  IA_NA (21.4) -- IAID(4B)+T1(4B,s)+T2(4B,s)+nested options (option-len-12 bytes).
//   4  IA_TA (21.5) -- IAID(4B)+nested options (option-len-4 bytes). No T1/T2, unlike IA_NA.
//   5  IA Address (21.6, nested inside IA_NA/IA_TA) -- address(16B)+preferred-lifetime(4B,s)+
//      valid-lifetime(4B,s)+nested options (option-len-24 bytes).
//   6  Option Request/ORO (21.7) -- requested-option-code[], 2 bytes each.
//   8  Elapsed Time (21.9) -- elapsed-time(2B, CENTISECONDS since transaction start), fixed len=2.
//   13 Status Code (21.13) -- status-code(2B)+status-message(option-len-2 bytes, UTF-8).
//   14 Rapid Commit (21.14) -- zero-length flag option; option-len must be 0.
//   25 IA_PD (21.21) -- mirrors IA_NA exactly: IAID(4B)+T1(4B)+T2(4B)+nested options.
//   26 IA Prefix (21.22, nested inside IA_PD) -- preferred-lifetime(4B)+valid-lifetime(4B)+
//      prefix-length(1B)+IPv6-prefix(16B, [SECONDARY-SOURCE/UNCERTAIN] -- see below)+nested
//      options (option-len-25 bytes).
// Any other option code: name-only "DHCPv6 option code N (M bytes)" fallback -- an unrecognized
// option never fails the whole message, the same graceful-degradation posture icmpv6.hpp's own
// NDP option walk already has.
//
// [SECONDARY-SOURCE, flagged UNCERTAIN]: IA Prefix's own 16-byte fixed IPv6-prefix field size
// follows the same convention every other fixed-size address field in RFC 8415 uses (zero-padded
// beyond the declared prefix-length), but this specific field's exact size was not independently
// re-confirmed against the live RFC 8415 text during this feature's research pass the way most of
// the rest of this file was -- treat it as best-effort, consistent with how this codebase always
// flags a genuinely uncertain field in a file's own header comment (see s7comm.cpp's/fox.cpp's own
// header comments for the house style this follows).
//
// DUID FORMATS (RFC 8415 11), needed to render Client/Server Identifier options -- and, for
// ipv6_attack_detect.hpp's own client/server-exhaustion counting, to KEY "distinct client/server
// identity" by: a DUID (whichever type) is rendered both as a human-readable display string AND as
// its raw wire bytes (Dhcpv6Duid::raw below), which is what that counting actually compares/hashes
// on -- two DUIDs are the same identity if and only if their raw bytes match exactly, regardless of
// type.
//   1 DUID-LLT: DUID-Type(2B)=1 + Hardware type(2B, IANA ARP type code) + Time(4B, seconds since
//     2000-01-01 00:00:00 UTC, mod 2^32) + Link-layer address(remaining bytes).
//   2 DUID-EN:  DUID-Type(2B)=2 + enterprise-number(4B) + identifier(remaining bytes, opaque
//     vendor-defined). Fully decoded (enterprise-number as a plain integer, identifier's own byte
//     length noted) -- cheap and more useful than name-only.
//   3 DUID-LL:  DUID-Type(2B)=3 + Hardware type(2B) + Link-layer address(remaining bytes).
//   4 DUID-UUID (RFC 6355): DUID-Type(2B)=4 + UUID(16B, RFC 4122 format) -- fixed 18 bytes total.
//     Rendered as a standard 8-4-4-4-12 hex-grouped UUID string (this codebase has no existing UUID
//     formatter to reuse elsewhere, so a small local one is used here rather than adding a
//     dependency).
//
// OUT OF SCOPE for this first pass, documented rather than silently missing:
//  - RELAY-FORW/RELAY-REPL's own "Relay Message" option (code 9, RFC 8415 21.10) is recognized
//    structurally ONLY -- its presence and raw byte length are noted, but the client/server message
//    it encapsulates is never decoded through. This means ipv6_attack_detect.hpp's own DHCPv6
//    exhaustion/rogue-server counting only ever sees NON-RELAYED traffic -- a documented scope
//    line, not silently wrong; see that file's own file header. Decoding through relay nesting
//    (which can itself nest RELAY-FORW inside RELAY-FORW, RFC 8415 9.1) is a natural, larger
//    follow-on if ever needed.
//  - Every other RFC 8415 option not listed above (Preference, DNS Recursive Name Server, Domain
//    Search List, SOL_MAX_RT, Vendor Class/Specific Information, Reconfigure Message/Accept, User/
//    Vendor Class, Interface-Id, Auth, Unicast, and the many later RFC extensions) is name-only.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t DHCPV6_CLIENT_PORT = 546;
constexpr uint16_t DHCPV6_SERVER_PORT = 547;

struct Dhcpv6Option;  // forward declaration -- see this file's own header comment for why the
                       // nested IA_NA/IA_TA/IA_PD/IA Address/IA Prefix structs below need it
                       // (mutually recursive with Dhcpv6Option, which holds each of them).

// RFC 8415 21.13, nested inside IA_NA/IA_TA/IA_PD/IA Address/IA Prefix, or top-level.
struct Dhcpv6StatusCode {
    uint16_t status_code = 0;
    std::string status_name;   // "Success", "NoAddrsAvail", etc., or "Unknown (N)"
    std::string status_message;  // UTF-8, not null-terminated on the wire
};

// RFC 8415 21.6, nested inside IA_NA/IA_TA.
struct Dhcpv6IaAddress {
    std::string address;  // format_ipv6
    uint32_t preferred_lifetime_sec = 0;
    uint32_t valid_lifetime_sec = 0;
    std::vector<Dhcpv6Option> options;  // rare in practice (typically a Status Code)
};

// RFC 8415 21.22, nested inside IA_PD. See this file's own [SECONDARY-SOURCE/UNCERTAIN] note above
// for the 16-byte prefix field.
struct Dhcpv6IaPrefix {
    uint32_t preferred_lifetime_sec = 0;
    uint32_t valid_lifetime_sec = 0;
    uint8_t prefix_length = 0;
    std::string prefix;  // format_ipv6 of the (possibly zero-padded) 16-byte field
    std::vector<Dhcpv6Option> options;
};

// RFC 8415 21.4.
struct Dhcpv6IaNa {
    uint32_t iaid = 0;
    uint32_t t1_sec = 0;
    uint32_t t2_sec = 0;
    std::vector<Dhcpv6Option> options;
};

// RFC 8415 21.5. No T1/T2, unlike IA_NA.
struct Dhcpv6IaTa {
    uint32_t iaid = 0;
    std::vector<Dhcpv6Option> options;
};

// RFC 8415 21.21 -- structurally identical to IA_NA (IAID+T1+T2+nested options), just a distinct
// option code and nested-option vocabulary (typically IA Prefix instead of IA Address).
struct Dhcpv6IaPd {
    uint32_t iaid = 0;
    uint32_t t1_sec = 0;
    uint32_t t2_sec = 0;
    std::vector<Dhcpv6Option> options;
};

// RFC 8415 11 -- see this file's own DUID FORMATS section. `raw` is the comparable/hashable value
// ipv6_attack_detect.hpp keys "distinct client/server identity" by.
struct Dhcpv6Duid {
    uint16_t duid_type = 0;
    std::string type_name;  // "DUID-LLT", "DUID-EN", "DUID-LL", "DUID-UUID", or "Unknown (N)"
    uint16_t hardware_type = 0;       // LLT/LL only -- IANA ARP hardware type code
    uint32_t time_raw = 0;            // LLT only -- seconds since 2000-01-01 00:00:00 UTC, mod 2^32,
                                        // NOT converted to a calendar date (no dependency added for
                                        // a display-only nicety)
    uint32_t enterprise_number = 0;   // EN only
    std::vector<uint8_t> link_layer_address;  // LLT/LL only
    std::vector<uint8_t> identifier;          // EN only -- opaque vendor-defined bytes
    std::string uuid_string;                  // UUID only -- 8-4-4-4-12 hex grouping
    std::string display;              // human-readable one-line rendering (used in summaries/JSON)
    std::vector<uint8_t> raw;         // this DUID's raw bytes on the wire, in full
};

// One generic DHCPv6 option (RFC 8415 21.1). At most one of the optional sub-structs below is
// populated, matching `code` -- see dhcpv6.hpp's own file header for exactly which codes this
// decoder interprets further versus names only.
struct Dhcpv6Option {
    uint16_t code = 0;
    std::string code_name;
    size_t data_length = 0;  // option-len -- the option-data byte length, NOT including the 4-byte
                              // option-code/option-len header

    std::optional<Dhcpv6Duid> duid;              // code 1 or 2
    std::optional<Dhcpv6IaNa> ia_na;              // code 3
    std::optional<Dhcpv6IaTa> ia_ta;              // code 4
    std::optional<Dhcpv6IaAddress> ia_address;    // code 5
    std::vector<uint16_t> oro_codes;              // code 6 -- Option Request
    std::optional<uint16_t> elapsed_time_centiseconds;  // code 8
    std::optional<Dhcpv6StatusCode> status_code;  // code 13
    bool is_rapid_commit = false;                 // code 14 (a flag option, no data)
    std::optional<Dhcpv6IaPd> ia_pd;              // code 25
    std::optional<Dhcpv6IaPrefix> ia_prefix;      // code 26
    bool is_relay_message = false;                // code 9 -- structural only, see OUT OF SCOPE
};

struct Dhcpv6Message {
    uint8_t msg_type = 0;
    std::string msg_type_name;
    bool is_relay = false;  // msg_type == 12 (RELAY-FORW) or 13 (RELAY-REPL) -- selects which
                             // header shape was parsed, see this file's own WIRE SHAPES section

    // Client/server message header (RFC 8415 8) -- populated only when !is_relay.
    uint32_t transaction_id = 0;  // the wire's own 3-byte field, held in the low 24 bits

    // RELAY-FORW/RELAY-REPL header (RFC 8415 9) -- populated only when is_relay.
    uint8_t hop_count = 0;
    std::string link_address;
    std::string peer_address;

    std::vector<Dhcpv6Option> options;
    bool options_truncated = false;

    // Convenience extraction for ipv6_attack_detect.hpp's own exhaustion/rogue-server counting:
    // the raw DUID bytes (Dhcpv6Duid::raw) of the Client Identifier (option 1) / Server Identifier
    // (option 2) option, when either is present at the TOP level of this message's own options
    // (never reached inside an undecoded Relay Message, see OUT OF SCOPE) -- empty when absent.
    std::string client_duid_key;
    std::string server_duid_key;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as a DHCPv6 message (either header shape -- see this file's
// own WIRE SHAPES section). Returns std::nullopt (never throws) only if the payload is shorter
// than the smaller of the two fixed headers (4 bytes, the client/server shape) or declares a
// msg_type of 0 (never assigned by RFC 8415) -- decoder.cpp's own UDP-port gate (546/547) is what
// actually keeps this from mis-firing against arbitrary UDP traffic, the same "port gate does the
// real work, the parser itself is lenient" posture dns.hpp's own file header documents for DNS.
std::optional<Dhcpv6Message> try_parse_dhcpv6(ByteSpan udp_payload);

// Thin ProtocolDecoder wrapper around try_parse_dhcpv6 above -- GateKind::UdpPort, the same shape
// DnsDecoder (dns.hpp) already established. udp_port() names the client port (546) for audit-trail
// purposes only; decoder.cpp's own call site checks BOTH 546 and 547 explicitly (the same "one
// filter value, gate lives at the call site" shape DICOM_PORT/DICOM_PORT_ALT already established
// for a two-default-port protocol -- see decoder.hpp's own DicomOnly comment).
class Dhcpv6Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "dhcpv6"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return DHCPV6_CLIENT_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& dhcpv6_decoder();

}  // namespace conduitscope
