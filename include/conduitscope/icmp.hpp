// SPDX-License-Identifier: Apache-2.0
// icmp.hpp - ICMP (RFC 792, plus RFC 1191/1256 extensions) decoding.
//
// ICMP has no transport-layer header of its own -- it rides directly on IP protocol number 1, the
// same "no port, dispatched purely by IP protocol number" shape as IGMP (2)/VRRP (112)/PIM
// (103)/EIGRP (88)/OSPF (89) elsewhere in this codebase -- see those files' own header comments.
//
// Scope: full field decoding (Tier 1) for the message types that matter for OT network
// diagnostics and security review --
//   0/8   Echo Reply / Echo Request       -- identifier, sequence number, data length
//   3     Destination Unreachable         -- code name (including Fragmentation Needed's Next-Hop
//                                             MTU, RFC 1191), plus a one-line summary of the
//                                             embedded original datagram
//   5     Redirect                        -- code name, gateway address, embedded datagram summary
//   11    Time Exceeded                   -- code name, embedded datagram summary
//   12    Parameter Problem                -- pointer byte, embedded datagram summary
//   13/14 Timestamp Request/Reply          -- identifier, sequence, originate/receive/transmit
//                                             timestamps (RFC 792: milliseconds since UTC midnight)
//   17/18 Address Mask Request/Reply       -- identifier, sequence, address mask
//   9     Router Advertisement (RFC 1256) -- lifetime, one address/preference pair per entry
// Every other IANA-registered ICMP type (1, 2, 6, 10's own Router Solicitation, 15, 16, 30-40) is
// named (Tier 2: "Source Quench", "Router Solicitation", "Information Request", etc.) but not
// decoded further -- most of them are formally deprecated (RFC 6918: Source Quench, Information
// Request/Reply; Redirect codes 2/3) or rare enough in real OT traffic that full decoding wasn't
// worth the added surface yet; see docs/PROTOCOL_COVERAGE.md.
//
// Embedded datagram: RFC 792 guarantees Destination Unreachable/Redirect/Time Exceeded/Parameter
// Problem messages carry the IP header of the offending datagram plus (at least) the first 8 bytes
// of its payload -- for TCP/UDP that's always enough to recover the source/destination ports, even
// though it's rarely enough for a full transport header (a TCP header's Data Offset byte, at byte
// 12, is typically NOT included). This decoder reuses parse_ipv4 (ipv4.hpp) directly against the
// quoted bytes and reads only the first 4 bytes of whatever quoted transport payload follows (src
// port + dst port; the same layout for TCP and UDP), wrapped in a try/catch: a capture can
// legitimately truncate this further still (snaplen, or some paths embed noticeably more per RFC
// 4884 -- not decoded here), so a short or malformed quote degrades to a shorter summary or no
// summary at all, never a decode failure for the ICMP message itself.
//
// Checksum: verified, not just surfaced -- unlike IPv4's own header checksum (see ipv4.cpp's "not
// validated; we trust the capture" comment), a mismatched ICMP checksum is itself a meaningful
// signal worth surfacing: ICMP Redirect/Destination-Unreachable spoofing is a known technique for
// disrupting or man-in-the-middling a flat OT network, and crafted traffic quite often gets this
// wrong. The algorithm is the same 16-bit one's-complement sum IPv4/TCP/UDP all use.
//
// Security context: ICMP has no authentication of any kind. A Redirect can silently retarget a
// host's next-hop for a destination, and any host on the local segment can send Destination
// Unreachable/Time Exceeded messages that most stacks (and some middleboxes) will act on without
// verifying the sender actually saw the offending traffic -- both are long-standing MITM/DoS
// primitives, more consequential on a flat OT network than a segmented, ICMP-filtered IT one.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t ICMP_IP_PROTOCOL = 1;

// A one-line summary of the IP datagram an ICMP error message (Destination Unreachable/Redirect/
// Time Exceeded/Parameter Problem) quotes -- see icmp.hpp's file header. Never the full decoded
// original packet, just enough to identify what triggered the error.
struct IcmpEmbeddedDatagram {
    std::string src_addr;
    std::string dst_addr;
    uint8_t protocol = 0;
    std::string protocol_name;  // via ip_protocol_name (ipv4.hpp); empty if that function doesn't
                                  // recognize the number
    bool has_ports = false;     // true only for protocol 6 (TCP) / 17 (UDP) when at least 4 bytes
                                  // of the quoted transport header were present
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
};

// One address/preference pair from a Router Advertisement (type 9, RFC 1256).
struct IcmpRouterAddress {
    std::string address;
    int32_t preference = 0;  // signed; a large negative value marks a router as least-preferred
};

struct IcmpMessage {
    uint8_t type = 0;
    uint8_t code = 0;
    std::string type_name;
    std::string code_name;  // empty when this type has no named codes (e.g. Echo Request/Reply,
                              // where code is always 0 and carries no distinct meaning of its own)
    uint16_t checksum = 0;       // as seen on the wire
    bool checksum_valid = false; // see icmp.hpp's file header -- false can mean either a genuinely
                                   // bad checksum or a capture truncated before the full ICMP
                                   // message was captured; this decoder cannot always tell the two
                                   // apart, so it reports the mismatch as a note either way rather
                                   // than guessing which

    // Echo Request/Reply (type 8/0) only.
    uint16_t echo_identifier = 0;
    uint16_t echo_sequence = 0;
    size_t echo_data_length = 0;

    // Destination Unreachable (type 3), code 4 "Fragmentation Needed and Don't Fragment was Set"
    // only -- RFC 1191. 0 for every other Destination Unreachable code (and every other type).
    uint16_t next_hop_mtu = 0;

    // Redirect (type 5) only.
    std::string redirect_gateway;

    // Parameter Problem (type 12) only.
    uint8_t parameter_pointer = 0;

    // Destination Unreachable / Redirect / Time Exceeded / Parameter Problem only -- the datagram
    // that triggered this error, when enough of it was present and well-formed to summarize. See
    // icmp.hpp's file header for why this can legitimately be absent even in a well-formed capture.
    std::optional<IcmpEmbeddedDatagram> embedded_datagram;

    // Timestamp Request/Reply (type 13/14) only. Milliseconds since UTC midnight per RFC 792 -- NOT
    // a full timestamp; there is no date component on the wire at all.
    uint32_t originate_timestamp_ms = 0;
    uint32_t receive_timestamp_ms = 0;
    uint32_t transmit_timestamp_ms = 0;

    // Address Mask Request/Reply (type 17/18) only.
    std::string address_mask;

    // Router Advertisement (type 9) only.
    uint16_t router_advertisement_lifetime_sec = 0;
    std::vector<IcmpRouterAddress> router_addresses;  // capped at 50 entries, same convention as
                                                          // elsewhere in this codebase
    bool router_addresses_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- ICMP has no transport header) as
// an ICMP message. Returns std::nullopt (never throws) only if the payload is shorter than the
// fixed 4-byte Type+Code+Checksum header -- unlike IGMP/VRRP/PIM, ICMP's Type byte alone gives no
// useful structural filter (almost every 0-255 value is either a real registered type or renders
// as "Unknown (N)"), so it's dispatch in decoder.cpp calling this unconditionally for IP protocol
// number 1 (IANA-exclusive to ICMP) that actually keeps this from mis-firing, same posture as
// EIGRP's/OSPF's own file header comments describe for themselves.
std::optional<IcmpMessage> try_parse_icmp(ByteSpan ip_payload);

// Migration batch 5 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper
// around try_parse_icmp above, unchanged -- same shape as EigrpDecoder (eigrp.hpp), the original
// GateKind::IpProtocol pilot. Stateless, no tcp_declared_length()/FlowStateKeying needed.
class IcmpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "icmp"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return ICMP_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& icmp_decoder();

}  // namespace conduitscope
