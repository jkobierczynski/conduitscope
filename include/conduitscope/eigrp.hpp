// SPDX-License-Identifier: Apache-2.0
// eigrp.hpp - Cisco EIGRP (Enhanced Interior Gateway Routing Protocol) decoding, now RFC 7868.
//
// EIGRP has no transport-layer header of its own -- it rides directly on IP protocol number 88
// (IANA-exclusive), so dispatch in decoder.cpp is keyed purely on that protocol number, the same
// posture as IGMP/VRRP/PIM/OSPF (see EIGRP_IP_PROTOCOL below).
//
// Every EIGRP packet shares a 20-byte header: Version(1)+Opcode(1)+Checksum(2)+Flags(4)+
// Sequence(4)+Acknowledge(4)+VirtualRouterID(2)+AutonomousSystem(2). A Hello packet (Opcode 5)
// with a nonzero Acknowledge field is conventionally shown as "Ack" rather than "Hello" (matching
// Wireshark's own display convention -- an Ack is really just an empty Hello that piggybacks an
// acknowledgement).
//
// What follows the header is a chain of TLVs (Type(2)+Length(2), Length counting the 4-byte TLV
// header itself), continuing to the end of the packet. This decoder fully decodes:
//   - the general (protocol-independent) TLVs: Parameters (K-values + hold time), Authentication
//     (header fields decoded; the MD5/SHA256 digest itself is shown as raw bytes, not verified --
//     the same "decode the header, don't verify the digest" posture RIP's own Keyed MD5 support
//     already takes), Software Version, Sequence (a list of peer addresses), and Next Multicast
//     Sequence;
//   - both IPv4 route TLV formats: the legacy/"Classic" format (TLV types 0x0102/0x0103,
//     deprecated since EIGRP Release-8 but still what many older devices and lab captures use)
//     and the current "Wide Metric" Multi-Protocol format (TLV types 0x0602/0x0603, RFC 7868)
//     that modern EIGRP "named mode" configurations default to.
// Everything else (Peer Stub Info/Termination/TID List, AppleTalk/IPX/IPv6/MTR route TLVs, IPX
// SAP packets, and any TLV type not listed above) is recognized -- named, counted, and its raw
// byte length shown -- but not decoded further. This mirrors the level of depth this codebase
// already applies elsewhere to a large, multi-variant wire format (see HSRPv2's non-Group-State
// TLVs, OSPF's Opaque LSAs): the common, IPv4-relevant paths are decoded in full; genuinely
// exotic or legacy-and-unused extensions are named but not chased down.
//
// A single Classic or Wide-Metric route TLV can (and in real captures, often does) describe
// MULTIPLE destination prefixes that share one next-hop and one metric -- EIGRP's own compound
// TLV design, not a decoding artifact (see EigrpRoute::destinations below and
// dissect_eigrp_ipv4_addrs in packet-eigrp.c, which loops over remaining TLV bytes for exactly
// this reason). Each destination is stored prefix-length-compressed on the wire (only
// ceil(prefix_len/8) address bytes are actually present) and expanded to a normal dotted-quad
// here.
//
// Cross-checked against Wireshark's own packet-eigrp.c and RFC 7868 directly.
//
// Security context: EIGRP supports MD5 and SHA-256 HMAC authentication (this decoder recognizes
// and decodes the Authentication TLV's own header fields, but does not verify the digest, the
// same posture RIP's Keyed MD5 support already takes), but plenty of real-world EIGRP deployments
// run with no authentication at all, in which case any host on the segment can inject or suppress
// routes. Because EIGRP AS numbers/K-values effectively define a trust domain, seeing multiple
// distinct AS numbers or repeated Parameter-TLV mismatches on one segment is itself worth a
// second look.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t EIGRP_IP_PROTOCOL = 88;

// A general (protocol-independent) TLV -- see this file's header comment for which types get a
// human-rendered `value` and which are merely recognized and named.
struct EigrpGeneralTlv {
    uint16_t type = 0;
    std::string type_name;  // "Parameters" (0x0001), "Authentication" (0x0002), "Sequence"
                              // (0x0003), "Software Version" (0x0004), "Next Multicast Sequence"
                              // (0x0005), "Peer Stub Information" (0x0006), "Peer Termination"
                              // (0x0007), "Peer TID List" (0x0008), or "Unknown (0xNNNN)"
    std::string value;       // human-rendered summary for the five types actually decoded (see
                              // header comment); empty for anything else, which is still
                              // recognized/counted but not decoded further
    uint16_t raw_length = 0;  // the TLV's own declared Length (header + value), always populated
};

struct EigrpClassicMetric {
    uint32_t delay_raw = 0;         // 32-bit, units of 10 microseconds; all-ones = unreachable
    bool unreachable = false;
    uint32_t delay_microseconds = 0;  // delay_raw * 10; meaningless when unreachable
    uint32_t bandwidth_raw = 0;       // 32-bit scaled value
    uint32_t bandwidth_kbps = 0;      // 10,000,000 / bandwidth_raw when nonzero, else 0
    uint32_t mtu = 0;                 // 24-bit
    uint8_t hop_count = 0;
    uint8_t reliability = 0;
    uint8_t load = 0;
    uint8_t internal_tag = 0;  // rarely used in practice; shown raw
    bool flag_active = false;
    bool flag_replicated = false;
    bool flag_source_withdraw = false;
};

struct EigrpWideMetric {
    uint8_t offset = 0;    // nonzero means N*2 bytes of Extended Metric Attributes follow this
                             // fixed 24-byte block -- recognized (see has_extended_attributes)
                             // but not decoded field-by-field
    bool has_extended_attributes = false;
    uint8_t priority = 0;
    uint8_t reliability = 0;
    uint8_t load = 0;
    uint32_t mtu = 0;       // 24-bit
    uint8_t hop_count = 0;
    uint64_t delay_raw = 0;        // 48-bit, nanoseconds per kilobyte; all-ones = unreachable
    bool unreachable = false;
    uint64_t bandwidth_kbps = 0;   // 48-bit, already in kilobytes/second (RFC 7868 6.4.1.4 -- NOT
                                     // scaled the way Classic's bandwidth field is); all-ones =
                                     // unreachable, same convention as delay
};

// Route external-origin data (RFC 7868 6.7) -- present only when EigrpRoute::external is true,
// for both the Classic and Wide-Metric TLV formats (the field layout is identical either way).
struct EigrpExternalRouteData {
    std::string originating_router;  // dotted-quad rendering of the 32-bit "Ext RouterID"/
                                       // "OrigRouterID" -- the EIGRP router that originally
                                       // redistributed this route, NOT necessarily this packet's
                                       // sender
    uint32_t autonomous_system = 0;   // the AS this route was redistributed FROM, if the
                                        // originating protocol had one (0 otherwise)
    uint32_t route_tag = 0;
    uint32_t external_metric = 0;
    uint8_t external_protocol = 0;
    std::string external_protocol_name;  // "IGRP", "EIGRP", "Static Route", "RIP", "Hello",
                                           // "OSPF", "IS-IS", "EGP", "BGP", "IDRP",
                                           // "Connected Route", or "Unknown (N)"
    bool is_external = false;   // EIGRP_OPAQUE_EXT (0x01) -- true for essentially every route
                                  // that reaches this struct at all (that's what put it here);
                                  // kept for fidelity with the wire bit rather than assumed
    bool is_candidate_default = false;  // EIGRP_OPAQUE_CD (0x02)
};

struct EigrpRoute {
    bool external = false;       // Internal (TLV type ...02) or External (TLV type ...03)
    bool wide_metric_format = false;  // true for a 0x06xx (Multi-Protocol/Wide) TLV, false for a
                                        // legacy 0x01xx (Classic) TLV
    uint16_t topology_id = 0;    // Wide-Metric format only; 0 for Classic (which has no TID
                                   // concept -- it always implicitly means the base topology)
    std::string router_id;       // Wide-Metric format only, dotted-quad rendering of the 32-bit
                                   // per-topology Router ID; empty for Classic (no such field)
    std::string next_hop;        // dotted-quad; 0.0.0.0 conventionally means "use the sender's
                                   // own address", the same convention RIPv2/VRRP already use
    std::optional<EigrpClassicMetric> classic_metric;  // set iff !wide_metric_format
    std::optional<EigrpWideMetric> wide_metric;         // set iff wide_metric_format
    std::optional<EigrpExternalRouteData> external_data;  // set iff external

    std::vector<std::string> destinations;  // "a.b.c.d/n", capped at 50 -- see header comment on
                                              // why one route TLV can carry several
    bool destinations_truncated = false;

    std::string summary;  // one-line rendering of this single route, used to build
                            // EigrpMessage::summary and handy on its own in JSON output
};

struct EigrpMessage {
    uint8_t version = 0;
    uint8_t opcode = 0;
    std::string opcode_name;  // "Update", "Request", "Query", "Reply", "Hello", "IPX SAP",
                                // "Probe", "Ack" (a Hello with a nonzero Acknowledge field -- see
                                // this file's header comment), "Stub", "SIA-Query", "SIA-Reply",
                                // or "Unknown (N)"
    uint16_t checksum = 0;     // as seen on the wire; NOT verified against the payload
    uint32_t flags_raw = 0;
    bool flag_init = false;              // "send your full topology table"
    bool flag_conditional_receive = false;
    bool flag_restart = false;           // NSF graceful restart in progress
    bool flag_end_of_table = false;      // marks the end of NSF start-up Updates
    uint32_t sequence = 0;
    uint32_t acknowledge = 0;
    uint16_t virtual_router_id = 0;
    std::string virtual_router_id_meaning;  // "(Address-Family)" (0x0000), "(Multi-Cast)"
                                              // (0x0001), "(Service-Family)" (0x8000), or empty
    uint16_t autonomous_system = 0;

    std::vector<EigrpGeneralTlv> general_tlvs;  // capped at 50
    bool general_tlvs_truncated = false;

    std::vector<EigrpRoute> routes;  // capped at 50 -- Classic and Wide-Metric IPv4 route TLVs
                                       // only (see header comment for everything else)
    bool routes_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- EIGRP has no transport header)
// as an EIGRP message. Returns std::nullopt (never throws) if the payload is shorter than the
// 20-byte header, or if Opcode isn't one of the values RFC 7868/packet-eigrp.c define (1-13,
// skipping none -- see opcode_name in eigrp.hpp). A TLV whose own declared Length is less than 4
// (the TLV header's own size) or that would run past the end of the packet stops TLV parsing at
// that point (whatever was already decoded is still returned, with a note) rather than guessing.
// Dispatch in decoder.cpp only ever calls this for IP protocol number 88, which is IANA-exclusive
// to EIGRP, so no further port-style gating is applied.
std::optional<EigrpMessage> try_parse_eigrp(ByteSpan ip_payload);

// registration-model pilot (Stage 1 -- see protocol_decoder.hpp/protocol_registry.hpp): thin
// ProtocolDecoder wrapper around try_parse_eigrp above, unchanged. EIGRP is the simplest of the
// three pilot protocols -- IP-protocol-number gated, no cross-packet state at all -- so this
// decoder needs nothing beyond id()/gate_kind()/ip_protocol()/decode(); see eigrp.cpp.
class EigrpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "eigrp"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return EIGRP_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

// Function-local static instance (lazily initialized on first call, so no static-init-order risk
// across translation units -- see protocol_registry.hpp's own header comment for why this codebase
// deliberately avoids self-registering globals).
const ProtocolDecoder& eigrp_decoder();

}  // namespace conduitscope
