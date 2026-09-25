// SPDX-License-Identifier: Apache-2.0
// icmpv6.hpp - ICMPv6 (RFC 4443) decoding, including Neighbor Discovery Protocol / NDP (RFC 4861)
// and the SLAAC-relevant pieces of RFC 4862/RFC 8106/RFC 4191.
//
// ICMPv6 has no transport-layer header of its own -- it rides directly on IP protocol number 58,
// the same "no port, dispatched purely by IP protocol number" shape ICMP(v4)/IGMP/VRRP/IGRP/PIM/
// EIGRP already have over IPv4 (see icmp.hpp's own file header) -- except ICMPv6 is reached
// through decoder.cpp's IPv6 branch specifically: IP protocol number 58 is IANA-exclusive to
// ICMPv6, and a real IPv4 packet never declares it, so there is no dispatch-order collision to
// avoid the way ICMP(v4)'s protocol number 1 sometimes needs (see decoder.cpp's own call site).
//
// This is roadmap item 45's first prerequisite (docs/DEVELOPMENT.md): before this addition,
// ICMPv6 was recognized only by name (ipv4.hpp's ip_protocol_name table), never parsed -- see
// ipv6_attack_detect.hpp for the curated SLAAC/rogue-RA/NDP-spoofing notes built on top of this
// decoder, and dhcpv6.hpp for the other half of that roadmap item.
//
// SOURCING: RFC 4443 (ICMPv6 base -- general header, error-message types 1-4, Echo Request/Reply
// 128/129), RFC 4861 (Neighbor Discovery Protocol -- Router/Neighbor Solicitation/Advertisement,
// Redirect, the generic NDP option TLV shape, and the Source/Target Link-Layer Address, Prefix
// Information, and MTU options), RFC 4862 (SLAAC -- the Prefix Information option's own A/L flags
// this decoder surfaces, not a separate wire format of its own), RFC 8106 (the RDNSS option), and
// RFC 4191 (the Route Information option, RIO). Every RFC-CONFIRMED field layout below was
// checked directly against that RFC text during this feature's research pass; the handful of
// [SECONDARY-SOURCE] items (the M/O and R/S/O flag bit masks on RA/NA, the RDNSS/RIO option byte
// layouts) are well-established (Wireshark/every public NDP reference agrees), just not something
// this pass re-derived from first-principles RFC prose the way the rest of this file was.
//
// SCOPE -- Tier 1 (full field decoding), mirroring icmp.hpp's own Tier 1/Tier 2 split:
//   1   Destination Unreachable  -- code name only (Tier 2, see below); RFC 4443 3.1
//   2   Packet Too Big           -- MTU field
//   3   Time Exceeded            -- code name only (Tier 2)
//   4   Parameter Problem        -- Pointer field, code name
//   128/129 Echo Request/Reply   -- identifier, sequence, data length (same shape as ICMPv4's own
//                                    Echo, RFC 4443 4.1/4.2)
//   133 Router Solicitation      -- options only (RFC 4861 4.1)
//   134 Router Advertisement     -- Cur Hop Limit, M/O flags, Router Lifetime, Reachable Time,
//                                    Retrans Timer, options (RFC 4861 4.2) -- the SLAAC/rogue-RA
//                                    attack surface this feature exists for; see
//                                    ipv6_attack_detect.hpp
//   135 Neighbor Solicitation    -- Target Address, options (RFC 4861 4.3)
//   136 Neighbor Advertisement   -- R/S/O flags, Target Address, options (RFC 4861 4.4)
//   137 Redirect                 -- Target Address, Destination Address, options (RFC 4861 4.5)
// Tier 2 (named, not further decoded): 1/3's own error codes ARE named (they're cheap -- a plain
// switch on `code`), but their own embedded/invoking datagram is NOT summarized the way icmp.hpp's
// IPv4 sibling summarizes ICMPv4 errors -- a deliberate, documented scope cut for this first pass
// (see "OUT OF SCOPE" below), not an oversight. 130/131/132/143 (MLD Query/Report v1/Done v1/
// Report v2) are named only, no decode -- MLD's own membership-record wire format is a distinct
// feature from anything this roadmap item asked for. Anything else falls back to a generic
// "ICMPv6 type N" label, the same posture icmp.hpp's own unknown-type fallback already has.
//
// CHECKSUM: unlike ICMPv4 (a flat sum over the message alone, see icmp.hpp), RFC 4443 section 2.3
// requires ICMPv6's checksum to be computed over the message PREPENDED with a pseudo-header of
// IPv6 header fields (RFC 8200 8.1's shape: 16-byte source + 16-byte destination + 4-byte
// upper-layer packet length + 3 zero bytes + 1-byte Next Header, always 58 here). That pseudo-
// header needs the OUTER IPv6 packet's own source/destination addresses, which this decoder alone
// cannot see (it is only ever handed the ICMPv6 message bytes) -- see try_parse_icmpv6's own
// parameters and DecodeContext::ipv6_src_addr/ipv6_dst_addr (protocol_decoder.hpp), populated by
// decoder.cpp's IPv6 branch before Icmpv6Decoder::decode is ever called. When those addresses are
// not available (nothing in this codebase's own decode_ip_payload IPv6 call site produces that
// today, but a hypothetical future caller might not populate them), the pseudo-header is computed
// against an all-zero address pair, which will legitimately fail to validate against a real
// checksum -- this degrades to checksum_valid=false plus an explanatory note, never a crash or a
// thrown exception, the same posture icmp.hpp's own file header already documents for ICMPv4's
// truncated-capture case.
//
// NDP OPTIONS (RFC 4861 4.6): a generic TLV -- Type(1B) + Length(1B, UNIT = 8 OCTETS, i.e. the
// real byte length is Length*8) + Data. Length == 0 is a protocol violation (RFC 4861 4.6: "MUST
// be greater than zero"); this parser treats it as a parse error and stops the option walk rather
// than looping forever, the same "never trust a length field enough to loop on it unchecked"
// posture every other TLV-walker in this codebase (fox.hpp's tuple grammar, bacnet.hpp's tag
// walk) already has. Decoded option types: 1/2 (Source/Target Link-Layer Address -- raw bytes,
// Length*8-2 of them, NOT hard-coded to Ethernet's usual 6 so this degrades gracefully for other
// link-layer types), 3 (Prefix Information -- the SLAAC A-flag carrier), 5 (MTU), 25 (RDNSS, RFC
// 8106), 24 (Route Information / RIO, RFC 4191). Any other option type is named only ("NDP option
// type N (M bytes)") and walked past by its own Length field -- an unrecognized option never fails
// the whole message, the same graceful-degradation posture every other TLV-walking decoder here
// already has.
//
// OUT OF SCOPE for this first pass, documented rather than silently missing:
//  - The "embedded/invoking datagram" summarization icmp.hpp's own ICMPv4 sibling does for
//    Destination Unreachable/Redirect/Time Exceeded/Parameter Problem (re-parsing the quoted
//    original IPv6 packet that triggered the error) is NOT implemented here -- a nice-to-have, not
//    required by roadmap item 45, and a natural, larger follow-on (this codebase has past
//    precedent for scoping an IPv6 sibling narrower than its IPv4 counterpart on day one -- see
//    docs/DEVELOPMENT.md's own EIGRP/PIM IPv6-support notes).
//  - RDNSS (option 25) and RIO (option 24) are lower-confidence/lower-priority field layouts
//    ([SECONDARY-SOURCE] above) included because they were cheap to add, not because this pass
//    re-verified every byte against the live RFC text with the same rigor as the rest of this
//    file.
//  - SEND (RFC 3971, cryptographically-signed Router Advertisements) is not implemented or
//    recognized in any way -- out of scope, not asked for.
//  - MLD's own Multicast Address Record wire format (types 130-132/143) is not decoded, only
//    named -- a distinct feature from Neighbor Discovery.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ipv6.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t ICMPV6_IP_PROTOCOL = 58;

// One NDP option's Source/Target Link-Layer Address payload (type 1/2, RFC 4861 4.6.1) -- just the
// raw link-layer address bytes after Type+Length, sized by the option's own declared Length rather
// than hard-coded to Ethernet's usual 6 bytes.
struct NdpLinkLayerAddress {
    std::vector<uint8_t> address;
};

// One NDP option's Prefix Information (type 3, RFC 4861 4.6.2 / RFC 4862's own A-flag) -- always a
// fixed 32-byte option (Length == 4) per RFC 4861, but this parser reads the declared Length
// rather than assuming it, the same "trust the wire's own length field, don't assume the common
// case" posture icmp.hpp's Router Advertisement address-entry-size field already established.
struct NdpPrefixInformation {
    uint8_t prefix_length = 0;
    bool on_link = false;     // L flag
    bool autonomous = false;  // A flag -- RFC 4862's own SLAAC signal: set means this prefix is
                               // offered for stateless address autoconfiguration
    uint32_t valid_lifetime_sec = 0;      // 0xFFFFFFFF means infinity
    uint32_t preferred_lifetime_sec = 0;  // 0xFFFFFFFF means infinity
    std::string prefix;  // format_ipv6 of the 16-byte Prefix field
};

// One NDP option's MTU (type 5, RFC 4861 4.6.4).
struct NdpMtuOption {
    uint32_t mtu = 0;
};

// One NDP option's Recursive DNS Server list (type 25, RFC 8106 5.1). [SECONDARY-SOURCE] -- see
// icmpv6.hpp's own file header.
struct NdpRdnssOption {
    uint32_t lifetime_sec = 0;
    std::vector<std::string> addresses;  // format_ipv6 of each 16-byte address
};

// One NDP option's Route Information (type 24, RFC 4191 2.3). [SECONDARY-SOURCE] -- see icmpv6.hpp's
// own file header. `prefix` is zero-padded beyond however many bytes the option's own Length
// field actually carried (0/8/16, per RFC 4191's own Length==1/2/3 cases).
struct NdpRouteInformation {
    uint8_t prefix_length = 0;
    uint8_t preference_raw = 0;   // the 2-bit Prf field, 0=Medium/1=Low(0b11 reserved-as-Low
                                   // per RFC 4191)/2=High/3=Reserved -- see preference_name
    std::string preference_name;  // "Low", "Medium", "High", or "Reserved"
    uint32_t route_lifetime_sec = 0;
    std::string prefix;
};

// One generic NDP option (RFC 4861 4.6). At most one of the optional sub-structs below is
// populated, matching `type` -- see icmpv6.hpp's own file header for exactly which types this
// decoder interprets further versus names only.
struct NdpOption {
    uint8_t type = 0;
    std::string type_name;
    size_t byte_length = 0;  // the option's REAL total byte length (Length field * 8), including
                              // the Type+Length bytes themselves

    std::optional<NdpLinkLayerAddress> link_layer_address;    // type 1 or 2
    std::optional<NdpPrefixInformation> prefix_information;   // type 3
    std::optional<NdpMtuOption> mtu;                          // type 5
    std::optional<NdpRdnssOption> rdnss;                      // type 25
    std::optional<NdpRouteInformation> route_information;     // type 24
};

struct Icmpv6Message {
    uint8_t type = 0;
    uint8_t code = 0;
    std::string type_name;
    std::string code_name;  // empty when this type has no named codes
    uint16_t checksum = 0;       // as seen on the wire
    bool checksum_valid = false; // see icmpv6.hpp's own CHECKSUM section for what false can mean

    // Echo Request/Reply (128/129) only.
    uint16_t echo_identifier = 0;
    uint16_t echo_sequence = 0;
    size_t echo_data_length = 0;

    // Packet Too Big (2) only.
    uint32_t packet_too_big_mtu = 0;

    // Parameter Problem (4) only.
    uint32_t parameter_problem_pointer = 0;

    // Router Advertisement (134) only.
    uint8_t ra_cur_hop_limit = 0;
    bool ra_managed_flag = false;  // M -- "use DHCPv6 for address configuration"
    bool ra_other_flag = false;    // O -- "use DHCPv6 for other configuration information"
    uint16_t ra_router_lifetime_sec = 0;
    uint32_t ra_reachable_time_ms = 0;  // RFC 4861: milliseconds, NOT seconds
    uint32_t ra_retrans_timer_ms = 0;   // RFC 4861: milliseconds, NOT seconds

    // Neighbor Solicitation (135) / Neighbor Advertisement (136) / Redirect (137) only.
    std::string target_address;

    // Neighbor Advertisement (136) only.
    bool na_router_flag = false;     // R
    bool na_solicited_flag = false;  // S
    bool na_override_flag = false;   // O

    // Redirect (137) only.
    std::string redirect_destination_address;

    // Router Solicitation (133) / Router Advertisement (134) / Neighbor Solicitation (135) /
    // Neighbor Advertisement (136) / Redirect (137) only -- every message type RFC 4861 defines
    // options for.
    std::vector<NdpOption> options;
    bool options_truncated = false;  // output capped at max_decoded_objects (resource_limits.hpp)
    bool options_malformed = false;  // an option declared Length == 0 -- the walk stopped early
                                      // rather than looping forever; see icmpv6.hpp's own file
                                      // header

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- ICMPv6 has no transport header)
// as an ICMPv6 message. Returns std::nullopt (never throws) only if the payload is shorter than
// the fixed 4-byte Type+Code+Checksum header. `pseudo_src`/`pseudo_dst` are the OUTER IPv6
// packet's own source/destination addresses, needed for RFC 4443's own checksum pseudo-header --
// see icmpv6.hpp's own CHECKSUM section for what happens when a caller has none to give (an
// all-zero pair, which degrades to checksum_valid=false rather than crashing).
std::optional<Icmpv6Message> try_parse_icmpv6(ByteSpan ip_payload, const Ipv6Address& pseudo_src,
                                               const Ipv6Address& pseudo_dst);

// Thin ProtocolDecoder wrapper around try_parse_icmpv6 above, the same shape IcmpDecoder (icmp.hpp)
// already established for ICMPv4. Stateless, no tcp_declared_length()/FlowStateKeying needed.
// Reads ctx.ipv6_src_addr/ipv6_dst_addr (protocol_decoder.hpp) for the checksum pseudo-header --
// the one thing that makes this decoder unlike every other GateKind::IpProtocol decoder in this
// codebase, all of which parse purely from the IP payload with no header context (IGRP's own
// ctx.ip_src_addr is the only prior exception, for an unrelated reason -- see igrp.hpp).
class Icmpv6Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "icmpv6"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return ICMPV6_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& icmpv6_decoder();

}  // namespace conduitscope
