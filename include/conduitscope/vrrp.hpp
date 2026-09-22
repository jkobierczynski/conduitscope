// SPDX-License-Identifier: Apache-2.0
// vrrp.hpp - VRRP (Virtual Router Redundancy Protocol) v2 (RFC 3768) and v3 (RFC 5798) decoding.
//
// VRRP has no transport-layer header of its own -- it rides directly on IP protocol number 112,
// so this decoder is handed the IP payload directly. It is dispatched in decoder.cpp purely by
// that IP protocol number, same as IGMP (2); there is no port concept and nothing to gate in Auto
// mode.
//
// Both versions share an 8-byte fixed header shape before the virtual IP address list, though the
// last 4 bytes of it mean different things per version:
//   Byte 0:    Version (high nibble) | Type (low nibble) -- Type is only ever 1 (Advertisement)
//              in both RFCs; anything else is rejected as a structural mismatch (see
//              try_parse_vrrp).
//   Byte 1:    Virtual Router ID (VRID)
//   Byte 2:    Priority -- 0 means the current master is giving up mastership, 255 means "address
//              owner" (the router whose real interface address IS the virtual IP), 1-254 is an
//              ordinary backup's priority (RFC default 100).
//   Byte 3:    Count of virtual IP addresses that follow.
//   v2 bytes 4-7: Auth Type(1) + Advertisement Interval in whole seconds(1) + Checksum(2).
//   v3 bytes 4-7: Reserved(4 bits) + Max Advertisement Interval in centiseconds(12 bits), packed
//                 into 2 bytes, + Checksum(2). v3 has no authentication fields at all -- RFC 5798
//                 removed them.
// Then Count * 4 bytes of virtual IPv4 addresses (this decoder does not handle VRRP-for-IPv6,
// which uses 16-byte addresses and a different multicast group).
// v2 only: an 8-byte Authentication Data field follows the address list. It is only meaningful
// when Auth Type is 1 (Simple Text Password, decoded as cleartext here); Auth Type 2 (IP
// Authentication Header) was already deprecated by RFC 3768 itself and is not decoded further,
// and Auth Type 254 is a non-standard Cisco MD5 extension seen in the wild, also not decoded
// further -- both are named but shown as unparsed.
//
// Cross-checked against Wireshark's own packet-vrrp.c and RFC 3768/5798 directly.
//
// Security context: like HSRP (see hsrp.hpp), VRRP lets any host on the segment that can send a
// higher-priority Advertisement (or a Priority-0 "I'm stepping down") take over as the virtual
// router -- a straightforward gateway-spoofing/MITM primitive. VRRPv2's only real authentication
// option (Simple Text Password) is sent in cleartext and does nothing to stop a listener from
// replaying it; VRRPv3 removed authentication entirely, relying purely on network-layer
// segmentation (e.g. this project's own conduit/zone policy model) instead.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint8_t VRRP_IP_PROTOCOL = 112;

struct VrrpMessage {
    uint8_t version = 0;      // 2 or 3
    uint8_t type = 0;         // always 1 (Advertisement) for any value try_parse_vrrp returns
    std::string type_name;    // "Advertisement"

    uint8_t virtual_router_id = 0;
    uint8_t priority = 0;
    std::string priority_meaning;  // "address owner" (255), "current master is stopping" (0), or
                                     // "backup" (1-254)
    uint8_t address_count = 0;      // as declared on the wire
    uint16_t checksum = 0;          // as seen on the wire; NOT verified against the payload

    // v2 only.
    uint8_t auth_type = 0;
    std::string auth_type_name;  // "No Authentication" (0), "Simple Text Password" (1), "IP
                                   // Authentication Header" (2, deprecated even by RFC 3768
                                   // itself), "Cisco MD5 (non-standard)" (254), or "Unknown (N)"
    uint8_t advertisement_interval_sec = 0;    // v2: whole seconds
    std::string auth_simple_password;          // auth_type == 1 only: cleartext password, NUL
                                                 // padding stripped -- see this file's own
                                                 // Security context note

    // v3 only.
    uint16_t advertisement_interval_centisec = 0;  // v3: centiseconds (12-bit field)

    std::vector<std::string> ip_addresses;  // virtual IPv4 address(es); capped at 50 entries
    bool ip_addresses_truncated = false;    // true if more than 50 addresses were declared

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- VRRP has no transport header) as
// a VRRP message. Returns std::nullopt (never throws) if the payload is shorter than the 8-byte
// fixed header, the high nibble of the first byte isn't 2 or 3 (Version), or the low nibble isn't
// 1 (Type -- the only value either RFC defines; this is a weak gate on its own, four bits, but
// dispatch in decoder.cpp only ever calls this for IP protocol number 112 in the first place,
// which is IANA-exclusive to VRRP -- see this file's own VRRP_IP_PROTOCOL).
std::optional<VrrpMessage> try_parse_vrrp(ByteSpan ip_payload);

// Migration batch 5 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper
// around try_parse_vrrp above, unchanged -- same shape as EigrpDecoder (eigrp.hpp), the original
// GateKind::IpProtocol pilot. Stateless, no tcp_declared_length()/FlowStateKeying needed.
class VrrpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "vrrp"; }
    GateKind gate_kind() const override { return GateKind::IpProtocol; }
    std::optional<uint8_t> ip_protocol() const override { return VRRP_IP_PROTOCOL; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& vrrp_decoder();

}  // namespace conduitscope
