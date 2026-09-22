// SPDX-License-Identifier: Apache-2.0
// ospf.hpp - OSPFv2 (Open Shortest Path First, RFC 2328) decoding.
//
// OSPF has no transport-layer header of its own -- it rides directly on IP protocol number 89
// (IANA-exclusive), so dispatch in decoder.cpp is keyed purely on that protocol number, the same
// posture as IGMP/VRRP/PIM/EIGRP (see OSPF_IP_PROTOCOL below). Only OSPFv2 (IPv4) is decoded;
// OSPFv3 (which carries IPv6 semantics throughout, not just a different address family in an
// otherwise-similar header) is out of scope, matching this project's IPv4-only posture everywhere
// else (see VRRP/HSRP's own equivalent IPv6 gaps) -- an OSPFv3 packet's Version byte (3, not 2)
// is rejected outright rather than guessed at.
//
// Every OSPFv2 packet shares a 24-byte header: Version(1)+Type(1)+PacketLength(2)+RouterID(4)+
// AreaID(4)+Checksum(2)+InstanceID(1)+AuType(1)+Authentication(8). The last two header fields
// reflect RFC 6549's backward-compatible reinterpretation of the classic 16-bit AuType field as
// InstanceID(1)+AuType(1) -- a legacy capture with InstanceID always 0 decodes identically either
// way. Three AuTypes are recognized: 0 (Null, no authentication), 1 (Simple Password, decoded as
// cleartext), and 2 (Cryptographic/MD5 -- this decoder reads the Key ID/Auth Data Length/Sequence
// Number header fields but, like RIP's own Keyed MD5 support, does NOT locate or verify the
// actual digest, which is a separate block appended after the packet's own declared length).
//
// Five packet Types are decoded in full:
//   1 Hello           -- network mask, timers, Options, DR/BDR, and the list of neighbors already
//                         heard from
//   2 DB Description  -- interface MTU, Options, the I/M/MS exchange-state flags, and a list of
//                         LSA headers (the "here's what I have" summary that drives the exchange
//                         -- LSA bodies are never included in a DB Description)
//   3 LS Request       -- a list of (LSA type, Link State ID, Advertising Router) tuples
//                         identifying which LSAs are being requested
//   4 LS Update         -- a list of complete LSAs (header + body); this is the only packet type
//                          that ever carries LSA bodies
//   5 LS Ack            -- a list of LSA headers only, acknowledging receipt
// Every LSA's 20-byte header is always decoded; the body is decoded (when present, i.e. only in
// an LS Update) for LSA types 1 (Router), 2 (Network), 3/4 (Summary/ASBR-Summary, identical
// format), and 5/7 (AS-External/NSSA-External, identical format). Types 6 (Group Membership,
// MOSPF -- essentially unused today) and 8-11 (Opaque, RFC 2370/3630 -- MPLS-TE and other
// extensions) are recognized by type number but their bodies are NOT decoded further, matching
// this codebase's usual posture on genuinely exotic extensions (see HSRPv2/EIGRP's own
// equivalent gaps). A Summary/ASBR-Summary or AS-External/NSSA-External LSA's TOS-specific metric
// blocks beyond the first (TOS 0, i.e. the ordinary non-TOS metric) are likewise not decoded --
// TOS-based routing was never widely deployed and real captures essentially always carry exactly
// one (TOS 0) block per LSA.
//
// Cross-checked against Wireshark's own packet-ospf.c and RFC 2328 directly.
//
// Security context: OSPF traffic on a segment defines that segment's IGP trust domain -- Simple
// Password authentication (AuType 1) sends the password in plaintext, and even Null
// authentication (AuType 0, still the most common real-world setting) means any host that can
// reach the All-OSPF-Routers/All-DR-Routers multicast groups can inject Hello/LSA traffic and
// manipulate routing. Because a rogue OSPF speaker can originate its own Router-LSA claiming
// arbitrary links, unexpected OSPF traffic -- especially from a host that shouldn't itself be a
// router -- is worth a second look.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t OSPF_IP_PROTOCOL = 89;

struct OspfRouterLink {
    std::string link_id;    // dotted-quad; meaning depends on link_type (neighboring router ID for
                              // Point-to-Point/Virtual, Designated Router address for Transit, the
                              // network number for Stub)
    std::string link_data;   // dotted-quad; meaning also depends on link_type (this router's own
                              // interface address, or a subnet mask for a Stub link)
    uint8_t link_type = 0;
    std::string link_type_name;  // "Point-to-Point" (1), "Transit" (2), "Stub" (3), "Virtual" (4),
                                   // or "Unknown (N)"
    uint8_t tos_count = 0;       // additional (non-zero-TOS) metric entries declared; NOT decoded
                                   // further (see this file's header comment)
    uint16_t metric = 0;         // the ordinary (TOS 0) metric
};

struct OspfRouterLsaBody {
    bool flag_border = false;    // "B" bit -- this router is an Area Border Router
    bool flag_external = false;  // "E" bit -- this router is an AS Boundary Router
    bool flag_virtual = false;   // "V" bit -- this router is a virtual-link endpoint
    std::vector<OspfRouterLink> links;  // capped at 50
    bool links_truncated = false;
};

struct OspfNetworkLsaBody {
    std::string network_mask;
    std::vector<std::string> attached_routers;  // dotted-quad Router IDs, capped at 50
    bool attached_routers_truncated = false;
};

// Covers LSA types 3 (Summary) and 4 (ASBR-Summary), which share this exact format -- only the
// LSA header's own `type` distinguishes them.
struct OspfSummaryLsaBody {
    std::string network_mask;
    uint32_t metric = 0;  // the TOS-0 metric only -- see this file's header comment
};

// Covers LSA types 5 (AS-External) and 7 (NSSA-External), which share this exact format.
struct OspfAsExternalLsaBody {
    std::string network_mask;
    bool e_bit = false;  // true = Type 2 external metric (not comparable to internal OSPF cost),
                           // false = Type 1 (directly comparable)
    uint32_t metric = 0;  // the TOS-0 metric only
    std::string forwarding_address;  // 0.0.0.0 means "forward to the ASBR that advertised this"
    uint32_t external_route_tag = 0;
};

struct OspfLsa {
    uint16_t age_sec = 0;      // masked to 15 bits -- see do_not_age
    bool do_not_age = false;   // RFC 1793 DoNotAge bit (the LSA header's Age field's own top bit)
    uint8_t options_raw = 0;
    uint8_t type = 0;
    std::string type_name;  // "Router" (1), "Network" (2), "Summary" (3), "ASBR-Summary" (4),
                              // "AS-External" (5), "Group Membership" (6), "NSSA-External" (7),
                              // "Opaque (Link-Local)" (9), "Opaque (Area-Local)" (10), "Opaque
                              // (AS-Wide)" (11), or "Unknown (N)"
    std::string link_state_id;       // dotted-quad
    std::string advertising_router;  // dotted-quad
    uint32_t sequence_number = 0;
    uint16_t checksum = 0;  // as seen on the wire; NOT verified against the payload
    uint16_t length = 0;    // header + body, as declared on the wire

    // At most one of these is set, per `type` -- see this file's header comment for exactly which
    // types get a decoded body at all, and only when this LSA appeared in an LS Update (a DB
    // Description or LS Ack never carries LSA bodies, so these are always empty there).
    std::optional<OspfRouterLsaBody> router_body;
    std::optional<OspfNetworkLsaBody> network_body;
    std::optional<OspfSummaryLsaBody> summary_body;
    std::optional<OspfAsExternalLsaBody> as_external_body;
};

struct OspfLsRequestEntry {
    uint32_t ls_type = 0;
    std::string ls_type_name;
    std::string link_state_id;
    std::string advertising_router;
};

struct OspfMessage {
    uint8_t version = 0;  // always 2 for any value this function returns
    uint8_t type = 0;
    std::string type_name;  // "Hello" (1), "DB Description" (2), "LS Request" (3), "LS Update"
                              // (4), "LS Ack" (5), or "Unknown (N)"
    uint16_t packet_length = 0;
    std::string router_id;   // dotted-quad
    std::string area_id;     // dotted-quad; 0.0.0.0 is the Backbone area
    uint16_t checksum = 0;   // as seen on the wire; NOT verified against the payload
    uint8_t instance_id = 0;  // RFC 6549; 0 on essentially every real-world capture
    uint8_t auth_type = 0;
    std::string auth_type_name;  // "Null" (0), "Simple password" (1), "Cryptographic" (2), or
                                   // "Unknown (N)"
    std::string auth_simple_password;  // auth_type == 1 only: cleartext, trailing NUL bytes
                                         // stripped -- see this file's own Security context note
    uint8_t auth_crypto_key_id = 0;         // auth_type == 2 only
    uint8_t auth_crypto_data_length = 0;    // auth_type == 2 only -- declared MD5 digest length
    uint32_t auth_crypto_sequence_number = 0;  // auth_type == 2 only

    // Hello (type 1) only.
    std::string hello_network_mask;
    uint16_t hello_interval_sec = 0;
    uint8_t hello_router_priority = 0;
    uint32_t hello_router_dead_interval_sec = 0;
    std::string hello_designated_router;
    std::string hello_backup_designated_router;
    std::vector<std::string> hello_neighbors;  // capped at 50
    bool hello_neighbors_truncated = false;

    // Options byte, decoded once here since Hello and DB Description both carry one with the
    // exact same bit meanings (RFC 2328 A.2, as extended by later RFCs).
    uint8_t options_raw = 0;
    bool option_e = false;    // AS-external-LSA capable (clear inside a stub area)
    bool option_mc = false;   // multicast (MOSPF) capable
    bool option_np = false;   // NSSA capable (RFC 3101)
    bool option_dc = false;   // demand-circuit capable (RFC 1793)
    bool option_o = false;    // Opaque-LSA capable (RFC 2370)
    bool option_dn = false;   // RFC 4576 DN bit (MPLS VPN loop prevention)

    // DB Description (type 2) only.
    uint16_t dbd_interface_mtu = 0;
    bool dbd_flag_init = false;          // "I" bit
    bool dbd_flag_more = false;          // "M" bit
    bool dbd_flag_master = false;        // "MS" bit (set = this speaker is Master)
    uint32_t dbd_sequence_number = 0;
    std::vector<OspfLsa> dbd_lsa_headers;  // headers only, capped at 50
    bool dbd_lsa_headers_truncated = false;

    // LS Request (type 3) only.
    std::vector<OspfLsRequestEntry> ls_requests;  // capped at 50
    bool ls_requests_truncated = false;

    // LS Update (type 4) only.
    uint32_t ls_update_declared_count = 0;
    std::vector<OspfLsa> ls_update_lsas;  // header + body, capped at 50
    bool ls_update_lsas_truncated = false;

    // LS Ack (type 5) only.
    std::vector<OspfLsa> ls_ack_headers;  // headers only, capped at 50
    bool ls_ack_headers_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- OSPF has no transport header) as
// an OSPFv2 message. Returns std::nullopt (never throws) if the payload is shorter than the
// 24-byte header, Version isn't 2, or Type isn't one of the five values RFC 2328 defines (1-5).
// A malformed or truncated LSA/list entry stops decoding of that list at that point (whatever was
// already decoded is still returned, with a note), the same graceful-degradation posture as
// RIP/EIGRP/PIM. Dispatch in decoder.cpp only ever calls this for IP protocol number 89, which is
// IANA-exclusive to OSPF, so no further port-style gating is applied.
std::optional<OspfMessage> try_parse_ospf(ByteSpan ip_payload);

// Migration batch 5 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper
// around try_parse_ospf above, unchanged -- same shape as EigrpDecoder (eigrp.hpp), the original
// GateKind::IpProtocol pilot. Stateless, no tcp_declared_length()/FlowStateKeying needed.
class OspfDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "ospf"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return OSPF_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& ospf_decoder();

}  // namespace conduitscope
