// SPDX-License-Identifier: Apache-2.0
// bgp.hpp - BGP-4 (RFC 4271, TCP port 179) decoding, plus RFC 4760 (Multiprotocol Extensions),
// RFC 6793 (4-octet AS numbers), RFC 8203 (shutdown communication), and RFC 9234 (Only to Customer)
// as the specific extensions this decoder curates on top of the base RFC 4271 message set.
//
// BGP has no OT-native purpose of its own -- it is included here purely for the same reason
// IGRP/EIGRP/OSPF/PIM are: a well-segmented OT/IT boundary should not have a routing-policy
// protocol crossing it at all, so seeing a genuine BGP session on a segment that shouldn't have one
// is itself the finding, and every OPEN/UPDATE exposes the peer's router ID, AS number, and (via
// AS_PATH) upstream topology in cleartext -- a network-mapping signal any passive observer gets for
// free, the same framing this codebase already gives OSPF/EIGRP/PIM's own "unexpected traffic here"
// posture, just the strongest version of it (a BGP session implies an actual routing-policy boundary
// where none was expected).
//
// Unlike every other TCP-port-independent protocol added to this codebase so far, BGP rides on TCP
// port 179 (GateKind::TcpPortIndependent, same category as Modbus/TwinCAT/MELSEC/FINS/OPC UA/etc.),
// needs declared-length TCP reassembly (its own Length field plays the same role Modbus's MBAP/
// MELSEC's/FINS's own Length fields already do -- see tcp_declared_length() below), needs a
// coalescing loop over the reassembled payload (real sessions send frequent small KEEPALIVEs that
// Nagle/OS buffering routinely merges with neighboring messages into one TCP segment, the same
// posture OPC UA's own decode() already handles -- see opcua.hpp), and needs genuine session-scoped
// state (BgpFlowState below) to track whether 4-octet AS numbers were negotiated.
//
// Wire format -- common 19-byte header (RFC 4271 section 4.1), present on EVERY message:
//   Marker (16 bytes): MUST be all-ones (0xFF * 16) in every deployed implementation (RFC 4271's own
//     text allows it to carry authentication data in principle, but no real deployment or later RFC
//     actually varies it -- BGP MD5/TCP-AO authentication, where used, lives entirely outside this
//     field, at the TCP layer). This decoder hard-gates on it: a 128-bit fixed match, stronger than
//     any other structural gate in this codebase (stronger even than GOOSE/SV's single-byte outer
//     BER tag or OPC UA's own 3-byte magic).
//   Length (2 bytes, big-endian): total message length INCLUDING this 19-byte header. Drives
//     tcp_declared_length() the same role Modbus's MBAP/MELSEC's/FINS's own Length fields play in
//     this codebase's reassemble_tcp_payload cascade.
//   Type (1 byte): 1=OPEN, 2=UPDATE, 3=NOTIFICATION, 4=KEEPALIVE, 5=ROUTE-REFRESH (RFC 2918/7313).
//   Per-type Length bounds this decoder enforces as part of its own structural gate: KEEPALIVE MUST
//   be exactly 19 (RFC 4271 mandates zero body). Every other type must be in [19, 65535] -- RFC 4271
//   nominally caps OPEN/UPDATE/NOTIFICATION/ROUTE-REFRESH at 4096, but RFC 8654 (Extended Messages)
//   allows up to 65535 when negotiated; this decoder deliberately accepts the full RFC 8654 range for
//   every type rather than trying to track whether Extended Messages was actually negotiated for this
//   session -- a documented, deliberate imprecision, the same category as this codebase's existing
//   unverified-auth-digest posture for RIP/EIGRP/OSPF.
//
// OPEN (type 1, RFC 4271 section 4.2): Version(1) + My Autonomous System(2, BE) + Hold Time(2, BE) +
//   BGP Identifier(4, BE, rendered dotted-quad like an IPv4 address) + Opt Parm Len(1) + Optional
//   Parameters(Opt Parm Len bytes: each Parameter Type(1) + Parameter Length(1) + Parameter Value).
//   Only Parameter Type 2 (Capabilities, RFC 5492) is decoded further -- each Capability is itself
//   Capability Code(1) + Capability Length(1) + Capability Value, looped until the parameter's own
//   value is exhausted. Two capability codes get their value decoded: Code 1 (Multiprotocol
//   Extensions, RFC 4760) -- AFI(2, BE) + Reserved(1) + SAFI(1), full decode for AFI=1(IPv4)/
//   SAFI=1(Unicast), name-only for any other AFI/SAFI, matching this codebase's IPv4-only posture
//   elsewhere; Code 65 (Support for 4-octet AS Number, RFC 6793) -- a 4-byte AS number, and THIS is
//   what feeds BgpFlowState (see below). Every other capability code is named from a curated table
//   (see bgp.cpp's capability_code_name) but its value is not further decoded. Any other Optional
//   Parameter Type is named by its numeric type only.
//
// UPDATE (type 2, RFC 4271 section 4.3): Withdrawn Routes Length(2, BE) + Withdrawn Routes (that
//   many bytes of NLRI-encoded prefixes) + Total Path Attribute Length(2, BE) + Path Attributes
//   (that many bytes) + Network Layer Reachability Information (everything left before the header's
//   own declared Length -- NO length field of its own). Withdrawn Routes and NLRI share the same
//   VLSM-compressed prefix encoding: each entry is Length(1, in BITS) + Prefix(ceil(Length/8) bytes,
//   the significant bits only, left-justified) -- the same prefix-length-compression scheme this
//   codebase's own EIGRP decoder already implements for its route TLVs (see eigrp.hpp), reused here
//   as the same mental model, not shared code (different byte layout). Each Path Attribute is
//   Attribute Flags(1) + Attribute Type Code(1) + Attribute Length(1, or 2 BE bytes if the Extended
//   Length flag, bit 0x10 of Flags, is set) + Attribute Value. Attribute type codes this decoder
//   decodes the value of: ORIGIN(1), AS_PATH(2), NEXT_HOP(3), MULTI_EXIT_DISC(4), LOCAL_PREF(5),
//   ATOMIC_AGGREGATE(6), AGGREGATOR(7), COMMUNITY(8, RFC 1997), ORIGINATOR_ID(9, RFC 4456),
//   CLUSTER_LIST(10, RFC 4456), MP_REACH_NLRI(14)/MP_UNREACH_NLRI(15) (RFC 4760, AFI=1/SAFI=1 fully,
//   others named only), AS4_PATH(17)/AS4_AGGREGATOR(18) (RFC 6793), OTC(35, RFC 9234). Every other
//   type code is named from a curated table (see bgp.cpp's path_attribute_type_name) with its raw
//   value shown as hex, not decoded (EXTENDED_COMMUNITIES(16)/LARGE_COMMUNITY(32)/PMSI_TUNNEL(22)/
//   etc.) -- the same "recognized but not exhaustively decoded" posture this codebase already applies
//   elsewhere (FINS's flag words, IEC 104's protection-equipment events).
//
//   AS_PATH/AS4_PATH: a sequence of path segments, each Segment Type(1: 2=AS_SEQUENCE, 1=AS_SET,
//   3=AS_CONFED_SEQUENCE, 4=AS_CONFED_SET) + Segment Length(1, count of AS numbers, NOT bytes) + that
//   many AS numbers, each either 2 or 4 bytes depending on the session's negotiated AS-number width.
//   THIS is where BgpFlowState matters: when this session's own OPEN capability (Code 65) was seen by
//   this decoder, that authoritative fact drives 2-vs-4-byte parsing; otherwise this decoder falls
//   back to Wireshark's own heuristic (try 2-byte width first; accept it only if every segment's
//   declared AS count exactly consumes the attribute's own declared length; otherwise assume 4-byte)
//   and flags the result as non-authoritative in that fallback case -- see try_parse_bgp_update's own
//   comment for the exact mechanics.
//
//   COMMUNITY: a sequence of 4-byte values. This decoder names the handful of well-known values it
//   can confirm precisely rather than risk a wrong name for an uncertain one: NO_EXPORT
//   (0xFFFFFF01), NO_ADVERTISE (0xFFFFFF02), NO_EXPORT_SUBCONFED (0xFFFFFF03), NOPEER (0xFFFFFF04,
//   RFC 7611), and BLACKHOLE (0xFFFF029A / 65535:666, RFC 7999) -- deliberately NOT attempting the
//   newer ACCEPT_OWN family (RFC 8642) or the ROUTE_LEAK community (RFC 9026), whose exact registry
//   values this decoder's own research did not independently confirm to the same confidence.
//
// NOTIFICATION (type 3, RFC 4271 section 4.5, subcodes cross-checked against RFC 4271/RFC 6608 (FSM)
//   /RFC 4486 (Cease)/RFC 7313 (ROUTE-REFRESH)/RFC 9234 (Role Mismatch)): Error Code(1) + Error
//   Subcode(1) + Data (whatever's left). Both code and subcode are named from curated tables (see
//   bgp.cpp) covering every major code (1 Message Header, 2 OPEN, 3 UPDATE, 4 Hold Timer Expired, 5
//   FSM, 6 Cease, 7 ROUTE-REFRESH) and their most commonly seen subcodes. RFC 8203's shutdown
//   communication special case is decoded when Error Code is Cease(6) and Error Subcode is
//   Administrative Shutdown(2) or Administrative Reset(4): Data then begins with a 1-byte length
//   followed by that many bytes of UTF-8 shutdown-reason text -- decoded as readable text when the
//   self-describing length is internally consistent, a genuinely useful "why this session dropped"
//   string no other protocol in this codebase currently surfaces.
//
// KEEPALIVE (type 4): header only, no body -- Length==19 is enforced as part of this decoder's own
//   gate (see above), so there is nothing further to parse.
//
// ROUTE-REFRESH (type 5, RFC 2918/7313): AFI(2, BE) + Reserved(1) + SAFI(1) -- decoded in full
//   (it's only 4 bytes), named the same way MP_REACH_NLRI's own AFI/SAFI is.
//
// Explicitly out of scope, deliberately: any attribute/capability/notification-subcode this file's
// own curated tables don't cover (named by raw numeric value only, never guessed at); BGP
// authentication of any kind -- unlike RIP/OSPF/EIGRP's own "digest present but unverified" framing,
// real-world BGP authentication (RFC 2385 TCP-MD5, RFC 5925 TCP-AO) lives entirely outside the BGP
// message body, invisible to a passive capture at the BGP layer -- so the honest posture here is that
// a decodable BGP session says nothing at all about whether it's authenticated, not that it's
// unauthenticated (this decoder never claims either).
//
// Structural detection gate: the strongest of any protocol in this codebase -- see the Marker
// paragraph above. Combined with Type being one of the five defined values and each type's own
// Length bound, a non-BGP TCP/179 payload (or an arbitrary payload that happens to include this
// port) has essentially no chance of passing this gate by coincidence.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t BGP_PORT = 179;

// A single VLSM-compressed prefix (RFC 4271 section 4.3's NLRI encoding, reused verbatim by
// Withdrawn Routes, NLRI, and MP_REACH_NLRI/MP_UNREACH_NLRI's own NLRI fields).
struct BgpPrefix {
    uint8_t prefix_length_bits = 0;
    std::string address;  // dotted-quad, zero-padded to a full 4 bytes for display -- only valid for
                            // an IPv4 (AFI=1) prefix; MP_REACH_NLRI/MP_UNREACH_NLRI for any other
                            // AFI show raw hex instead (see BgpMpReachNlri/BgpMpUnreachNlri below)
};

// One BGP capability seen inside an OPEN's own Capabilities (Type 2) Optional Parameter.
struct BgpCapability {
    uint8_t code = 0;
    std::string code_name;  // empty if not in this decoder's curated table
    uint8_t length = 0;
    // Populated only for the two codes this decoder decodes the value of -- see this file's own
    // header comment.
    bool is_multiprotocol = false;
    uint16_t mp_afi = 0;
    uint8_t mp_safi = 0;
    bool is_four_octet_as = false;
    uint32_t four_octet_as = 0;
    std::string raw_hex;  // populated when neither of the above applies
};

struct BgpOpenMessage {
    uint8_t version = 0;
    uint16_t my_as = 0;
    uint16_t hold_time = 0;
    std::string bgp_identifier;  // dotted-quad
    uint8_t opt_parm_len = 0;
    std::vector<BgpCapability> capabilities;  // flattened across every Capabilities (Type 2)
                                                // Optional Parameter seen, in order
    bool has_four_octet_as_capability = false;  // convenience flag -- true if any capability above
                                                  // had is_four_octet_as
};

struct BgpAsPathSegment {
    uint8_t segment_type = 0;
    std::string segment_type_name;
    std::vector<uint32_t> as_numbers;
};

struct BgpPathAttribute {
    uint8_t flags = 0;
    bool optional = false;
    bool transitive = false;
    bool partial = false;
    bool extended_length = false;
    uint8_t type_code = 0;
    std::string type_name;  // empty if not in this decoder's curated table
    uint16_t length = 0;
    std::string rendered;  // human-readable rendering, populated for every curated type_code
    std::string raw_hex;   // populated instead of `rendered` for an uncurated type_code
};

struct BgpUpdateMessage {
    std::vector<BgpPrefix> withdrawn_routes;
    bool withdrawn_routes_truncated = false;
    std::vector<BgpPathAttribute> path_attributes;
    std::vector<BgpPrefix> nlri;
    bool nlri_truncated = false;

    // Curated convenience fields, pulled out of path_attributes above for easy access -- mirrors
    // this codebase's usual "curated summary fields alongside the full raw list" shape (see IgrpMessage's
    // routes vs. EthercatFrame's datagrams for the pattern this follows).
    bool has_origin = false;
    std::string origin_name;
    bool has_as_path = false;
    std::vector<BgpAsPathSegment> as_path;
    bool as_path_width_authoritative = false;  // true only when this session's own OPEN capability
                                                 // 65 was observed by this decoder -- see this file's
                                                 // header comment's AS_PATH paragraph
    bool has_next_hop = false;
    std::string next_hop;  // dotted-quad
    bool has_communities = false;
    std::vector<std::string> community_names;  // one entry per 4-byte value -- a recognized
                                                 // well-known name, or "0xAAAABBBB" raw hex
};

struct BgpNotificationMessage {
    uint8_t error_code = 0;
    std::string error_code_name;
    uint8_t error_subcode = 0;
    std::string error_subcode_name;  // empty if not in this decoder's curated table for this code
    // RFC 8203 shutdown communication -- populated only for Cease(6)/Administrative Shutdown(2) or
    // Administrative Reset(4), when the self-describing length prefix is internally consistent.
    bool has_shutdown_communication = false;
    std::string shutdown_communication;
    std::string data_hex;  // the raw Data field, always populated (even when shutdown_communication
                             // was also extracted from it) so nothing is silently dropped
};

struct BgpRouteRefreshMessage {
    uint16_t afi = 0;
    uint8_t safi = 0;
};

// One decoded BGP message -- OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH share this one
// wrapper (rather than five separate top-level structs) because BgpDecoder::decode's own coalescing
// loop (see this file's header comment) needs a single result type to collect a sequence of them
// into.
struct BgpMessage {
    uint16_t length = 0;  // this message's own declared Length, INCLUDING the 19-byte header --
                            // also this message's wire_length for the coalescing loop
    uint8_t type = 0;
    std::string type_name;

    bool is_open = false;
    BgpOpenMessage open;
    bool is_update = false;
    BgpUpdateMessage update;
    bool is_notification = false;
    BgpNotificationMessage notification;
    bool is_route_refresh = false;
    BgpRouteRefreshMessage route_refresh;
    // KEEPALIVE carries no fields of its own -- type_name/is-checks above are all there is to know.

    std::string summary;
    std::vector<std::string> notes;
};

// Session-scoped state: whether 4-octet AS number support (RFC 6793) was seen in either direction's
// OPEN this session. FlowStateKeying::Session (either peer can send the OPEN that establishes this
// for the whole session) -- see kerberos.hpp's own KerberosFlowState for the closest existing
// example of this same keying choice.
class BgpFlowState : public DecoderFlowState {
public:
    bool open_seen = false;  // true once this decoder has processed at least one OPEN on this
                               // session -- makes four_octet_as_negotiated below authoritative
    bool four_octet_as_negotiated = false;
};

// Attempts to interpret the FIRST complete BGP message at the front of `payload` (which may contain
// more than one coalesced message -- callers other than BgpDecoder::decode itself should not assume
// payload.size() == the returned message's own length). `as_width_authoritative`/`as_width_is_four_octet`
// should come from this session's BgpFlowState (`state.open_seen`/`state.four_octet_as_negotiated`)
// when available -- see this file's header comment's AS_PATH paragraph for exactly how a
// non-authoritative caller (as_width_authoritative == false, e.g. this session's OPEN wasn't
// captured) is handled via a length-consistency heuristic instead. declared_length (see below) must
// already have confirmed at least `length` bytes are present. Returns std::nullopt (never throws)
// unless the Marker is exactly 16 bytes of 0xFF, Type is one of the five defined values, and Length
// satisfies this decoder's own per-type bound (see this file's header comment) -- this is the whole
// structural gate; nothing else in this function ever declines an otherwise gate-passing message,
// matching this codebase's usual "decode what's there, note what's odd" style for a message that
// passed its protocol's own structural gate.
std::optional<BgpMessage> try_parse_bgp_message(ByteSpan payload, bool as_width_authoritative,
                                                 bool as_width_is_four_octet);

// Returns the total declared length of the BGP message at the front of `payload` (the Length field,
// INCLUDING the 19-byte header, mirroring Modbus's/MELSEC's/FINS's own tcp_declared_length()
// convention) -- or std::nullopt if fewer than 19 bytes are present yet, the Marker isn't all-0xFF,
// Type isn't one of the five defined values, or Length fails this decoder's own per-type bound. Used
// both as BgpDecoder::tcp_declared_length() (below) and internally by BgpDecoder::decode()'s own
// coalescing loop to find each subsequent message's boundary without re-deciding the whole gate.
std::optional<size_t> bgp_declared_length(ByteSpan payload);

class BgpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "bgp"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return bgp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& bgp_decoder();

// Result of BgpDecoder::decode()'s own coalescing loop -- see opcua.hpp's OpcUaResult for the
// precedent this follows (one fully-decoded `first` message, plus a note per additional coalesced
// message rather than a full struct each, since KEEPALIVE-heavy coalescing would otherwise bloat
// every field this codebase's output writers would need to flatten for very little value).
struct BgpResult {
    std::string summary;
    std::vector<std::string> notes;
    BgpMessage first;
    size_t coalesced_message_count = 1;  // 1 when only `first` was found; higher when the
                                           // coalescing loop found more messages in the same payload
};

}  // namespace conduitscope
