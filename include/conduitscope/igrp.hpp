// SPDX-License-Identifier: Apache-2.0
// igrp.hpp - Cisco IGRP (Interior Gateway Routing Protocol) decoding.
//
// IGRP predates EIGRP (see eigrp.hpp) and was formally obsoleted by Cisco decades ago -- Cisco
// IOS itself dropped support for it in the mid-2010s. It is included here anyway (alongside
// EIGRP/OSPF/PIM in this same round) purely for completeness: it is still occasionally seen in
// lab/training captures and legacy-equipment audits, and a well-segmented OT/IT network
// shouldn't be running it at all -- seeing it is itself a finding.
//
// IGRP has no transport-layer header of its own -- it rides directly on IP protocol number 9
// ("any private interior gateway protocol", IANA's IGP), so dispatch in decoder.cpp is keyed
// purely on that protocol number, the same posture as IGMP/VRRP/PIM/EIGRP/OSPF (see
// IGRP_IP_PROTOCOL below).
//
// Wire format (RFC-less -- IGRP predates the IETF RFC process for routing protocols and was
// only ever documented by Cisco itself; see packet-igrp.c's own header comment, reproduced here):
// a 12-byte header --
//   4 bits  Version (only 1 is defined)
//   4 bits  Opcode (1 = Update/"Response", 2 = Request)
//   8 bits  Edition (increments each time a full update with routing changes is sent)
//   16 bits Autonomous System number
//   16 bits Number of Interior routes
//   16 bits Number of System routes
//   16 bits Number of Exterior routes
//   16 bits Checksum (NOT verified here)
// followed by (Interior + System + Exterior) 14-byte route vectors, each --
//   24 bits Network (see below -- NOT a plain 3-byte IP address)
//   24 bits Delay (units of 10 microseconds; all-ones = unreachable)
//   24 bits Bandwidth (scaled: kbps = 10,000,000 / raw, when raw != 0)
//   16 bits MTU
//    8 bits Reliability (0-255, 255 = 100%)
//    8 bits Load (0-255, 255 = 100%)
//    8 bits Hop count
//
// IGRP is a CLASSFUL protocol, and its 3-byte "Network" field is encoded accordingly rather
// than being a plain truncated IP address (this is the one genuinely tricky part of an
// otherwise simple format -- see packet-igrp.c's dissect_vektor_igrp for the reference this
// was cross-checked against):
//   Interior route (a subnet of the network the packet was itself sent on): the 3 bytes in the
//     vector are the LOW-order 3 octets, and the missing high-order octet is taken from the
//     *IP source address of the packet carrying this route* -- so decoding an interior route
//     correctly requires the caller to hand try_parse_igrp the packet's own source IP (see
///    below).
//   System or Exterior route (a different major network): the 3 bytes in the vector are the
//     HIGH-order 3 octets, and the missing low-order octet is always 0 (i.e. these can only ever
//     name a class-A/B/C network number, never a specific host).
//
// Cross-checked against Wireshark's own packet-igrp.c.
//
// Security context: IGRP has no authentication of any kind -- any host on the segment can
// inject routes. It is also a distance-vector protocol with no loop-prevention beyond simple
// split-horizon/hold-down, and has been end-of-life for Cisco IOS since 2016; production
// traffic using it at all is a strong signal of unmaintained, legacy infrastructure.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t IGRP_IP_PROTOCOL = 9;

struct IgrpRoute {
    std::string route_kind;  // "Interior", "System", or "Exterior" -- see this file's header
                               // comment for how each is addressed differently on the wire
    std::string address;     // dotted-quad, reconstructed per route_kind (see header comment);
                               // for System/Exterior routes the low-order octet is always 0
                               // since only the network number (not a full host address) is ever
                               // carried
    uint32_t delay_raw = 0;       // 24-bit raw value as seen on the wire
    uint32_t delay_microseconds = 0;  // delay_raw * 10; meaningless when unreachable is true
    bool unreachable = false;         // delay_raw == 0xFFFFFF (RFC-less IGRP's own convention)
    uint32_t bandwidth_raw = 0;       // 24-bit raw value as seen on the wire
    uint32_t bandwidth_kbps = 0;      // 10,000,000 / bandwidth_raw when bandwidth_raw != 0, else 0
    uint16_t mtu = 0;
    uint8_t reliability = 0;
    uint8_t load = 0;
    uint8_t hop_count = 0;
};

struct IgrpMessage {
    uint8_t version = 0;    // only 1 is defined; a value other than 1 is noted but still decoded
                              // the same way (matches Wireshark's own "may be inaccurate" posture)
    uint8_t opcode = 0;
    std::string opcode_name;  // "Response" (an Update carrying routes, opcode 1) or "Request"
                                // (opcode 2, or anything else); matches Wireshark's own naming
                                // exactly (packet-igrp.c calls opcode 1 "Response" even though its
                                // own header-comment spec text calls it "Replay[sic]" -- both mean
                                // the same "here are my routes" Update message)
    uint8_t edition = 0;
    uint16_t autonomous_system = 0;
    uint16_t interior_route_count = 0;  // as declared on the wire, even if truncated below
    uint16_t system_route_count = 0;
    uint16_t exterior_route_count = 0;
    uint16_t checksum = 0;  // as seen on the wire; NOT verified against the payload

    std::vector<IgrpRoute> routes;  // Interior routes first, then System, then Exterior -- capped
                                      // at 50 entries total, same convention as every other
                                      // repeated-element list in this codebase
    bool routes_truncated = false;   // true if interior+system+exterior together declared more
                                       // than 50 routes

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- IGRP has no transport header)
// as an IGRP message. `src_ip` is the IPv4 header's own source address (host-order, as
// Ipv4Header::src_addr already is) -- Interior routes need it to reconstruct their full address
// (see this file's header comment); it is unused for System/Exterior routes and for any message
// this function rejects.
//
// Returns std::nullopt (never throws) if the payload is shorter than the 12-byte header, or if
// the declared route count doesn't leave enough bytes for at least the routes this function can
// see (a message with a plausible header but wildly truncated route data still decodes as many
// complete 14-byte vectors as are actually present, same graceful-degradation posture as RIP/
// EIGRP/OSPF/PIM). Dispatch in decoder.cpp only ever calls this for IP protocol number 9, which
// this decoder treats as IANA-exclusive enough to IGRP in practice (see IGRP_IP_PROTOCOL) that no
// further port-style gating is applied -- IGRP's own header fields (a small Opcode value, a
// plausible route-count/byte-length relationship) are the only structural check performed.
std::optional<IgrpMessage> try_parse_igrp(ByteSpan ip_payload, uint32_t src_ip);

// Migration batch 5 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper
// around try_parse_igrp above, unchanged. IGRP is the one wrinkle in this batch: try_parse_igrp
// needs the packet's own IPv4 source address (see this file's header comment), which decode()'s
// ByteSpan payload alone doesn't carry -- decoder.cpp's IGRP call site populates the new
// DecodeContext::ip_src_addr field (protocol_decoder.hpp) right before calling decode(), and this
// wrapper reads it from there. Otherwise identical in shape to every other GateKind::IpProtocol
// decoder in this batch -- stateless, no tcp_declared_length()/FlowStateKeying needed.
class IgrpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "igrp"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return IGRP_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& igrp_decoder();

}  // namespace conduitscope
