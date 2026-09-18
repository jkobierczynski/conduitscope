// SPDX-License-Identifier: Apache-2.0
// tunnel_vpn.hpp - Name-only recognition for ROADMAP item 18's Tier 5, "generic tunnel/VPN
// encapsulation" -- the broader problem CAPWAP/GTP-U (Tier 4) are specific instances of: an inner
// VLAN, Modbus session, or entire plant subnet is invisible to every decoder in this codebase, and
// to `policy validate`'s own flow model, until the outer tunnel is stripped off. Merely NAMING the
// outer protocol is already a finding worth surfacing (ROADMAP item 18's own wording) -- this file
// never attempts to strip a tunnel and decode what rides inside it (that would mean re-running this
// tool's entire dispatch chain on the inner bytes, a real second decode pass this "name-only"
// posture doesn't call for, and several of these tunnels are encrypted/opaque past their own header
// anyway), with one narrow, cheap exception: IP-in-IP's inner IPv4 header sits right there in
// plaintext, so its own src/dst addresses (exactly the "entire plant subnet" this item's own wording
// calls out) are surfaced without decoding anything past that header -- see try_recognize_tunnel_vpn
// _ip_proto's own IP-in-IP paragraph below.
//
// Organized, like it_protocols.hpp's own Tiers 1-4, around how each tunnel actually presents on the
// wire rather than the ROADMAP text's own grouping order -- three shapes, three entry points:
//   - IP-protocol-number-keyed (no port at all, same shape IGMP/VRRP/IGRP/PIM/EIGRP/OSPF already
//     have in decoder.cpp): GRE (47, with NVGRE/EoIP as two sub-cases distinguished by GRE's own
//     Protocol Type field), ESP (50), AH (51), IP-in-IP (4), 6in4 (41), and L2TPv3's own direct-IP
//     encapsulation (115) -- see try_recognize_tunnel_vpn_ip_proto.
//   - UDP-port-keyed: IKE (500, and NAT-T on 4500 -- which also disambiguates NAT-T ESP on the same
//     port), L2TP (1701, both v2 and v3-over-UDP), VXLAN (4789), Geneve (6081), WireGuard (51820),
//     OpenVPN (1194), and a generic DTLS-record structural check (no fixed port -- see its own
//     paragraph below) -- see try_recognize_tunnel_vpn_udp.
//   - TCP-port-keyed: OpenVPN's own TCP framing (1194, a 2-byte length prefix ahead of the identical
//     opcode byte UDP OpenVPN uses) and STT (7878) -- see try_recognize_tunnel_vpn_tcp.
// MPLS, ALSO Tier 5 but EtherType-keyed (0x8847 unicast / 0x8848 multicast, no port and no IP layer
// at all), is NOT in this file -- see mpls.hpp and decoder.hpp's own ProtocolFilter::MplsOnly
// comment for why, the same EtherType-keyed split EAPOL/PPPoE already established for Tiers 3-4.
//
// Confidence varies as sharply here as it did across Tiers 1-4, and every summary/note below says so
// honestly:
//   - GRE (IP protocol 47, RFC 2784) has a genuine structural signature in its first 2 bytes: the
//     3-bit Version field (bits 13-15) must be 0 for plain GRE (1 is Enhanced GRE/PPTP, out of scope
//     here -- rejected as a structural mismatch, same as any other unrecognized value). The 16-bit
//     Protocol Type that follows (an EtherType value -- this file reuses link_layer.hpp's own
//     ethertype_name() to name it, rather than re-implementing that lookup) is what actually
//     distinguishes GRE's own sub-cases: Protocol Type 0x6558 (Transparent Ethernet Bridging) with
//     the Key flag set is reported as "nvgre" -- NVGRE (RFC 8926) always uses this Protocol Type with
//     a Key field split into a 24-bit VSID + 8-bit FlowID, but ordinary Ethernet-bridging-over-GRE
//     (a legitimate, non-NVGRE use of the same Protocol Type) is structurally indistinguishable from
//     it without deeper VSID/FlowID semantics this file doesn't attempt -- every "nvgre" match notes
//     this ambiguity explicitly rather than presenting false certainty. Protocol Type 0x6400 is
//     Mikrotik's own EoIP, a genuinely distinct, unambiguous assigned value (in wide practical use,
//     recognized by Wireshark's own dissector, even without a formal IANA/IETF registration) --
//     reported as "eoip" with real confidence. Anything else (most commonly 0x0800, plain IPv4,
//     RFC 2784's own original use case) is reported as plain "gre", naming the inner Protocol Type.
//   - ESP (IP protocol 50, RFC 4303) and AH (IP protocol 51, RFC 4302) are both checked purely by
//     their own IANA-exclusive IP protocol number -- ESP's body (SPI + Sequence Number, then
//     encrypted/authenticated payload) is opaque by design past those first 8 bytes, and AH's own
//     ICV is likewise opaque, so unlike GRE there is no further structural gate to check; the SPI
//     (both) and, for AH, the Next Header field (naming the protocol AH is protecting, via
//     ipv4.hpp's own ip_protocol_name -- AH is the one IPsec mode that leaves the inner header
//     visible) are surfaced. Per this ROADMAP item's own framing ("worth checking whether its
//     traffic selectors dump a whole plant subnet into IT, and whether it's split- or full-tunneled")
//     this file cannot see traffic selectors or tunnel-mode negotiation at all -- that lives in IKE's
//     own (also unparsed-past-its-header) SA negotiation, not in ESP/AH's own per-packet framing.
//   - IP-in-IP (IP protocol 4, RFC 2003) is checked by its IANA-exclusive protocol number AND a real
//     structural signature: the payload's very first nibble must be 4 (IP version), the same check
//     any IPv4 header parse starts with. Uniquely among every protocol in this file, its inner
//     header is read far enough to surface the inner src/dst IPv4 addresses (via ipv4.hpp's own
//     format_ipv4, reading the two address fields directly rather than a full recursive parse_ipv4
//     call) -- this is the one deliberate exception to this file's own "name the tunnel, don't
//     unwrap it" posture, made because the inner header sits in plaintext immediately after the
//     outer one and directly answers this ROADMAP item's own "an entire plant subnet is invisible...
//     until the outer tunnel is stripped off" framing at essentially zero additional cost. Nothing
//     past those two addresses (ports, inner protocol, inner payload) is read.
//   - 6in4 (IP protocol 41, RFC 4213) is checked the same way as IP-in-IP -- IANA-exclusive protocol
//     number plus a real structural signature, the payload's first nibble must be 6 (IPv6 version) --
//     but its own inner addresses are NOT surfaced, unlike IP-in-IP's: this codebase has no IPv6
//     address parser at all (see ipv4.hpp's own file header comment on IPv6 being out of scope), and
//     writing one solely to format two 128-bit addresses for this one case would be real scope creep
//     for a name-only recognition tier -- see this file's own LIMITATIONS cross-reference in
//     docs/MANUAL.md.
//   - L2TPv3's direct-IP encapsulation (IP protocol 115, RFC 3931 section 4.1 -- an extension beyond
//     ROADMAP item 18's own literal text, which only names L2TP/L2TPv3's UDP 1701 form; the same
//     "genuinely reachable but unnamed by the ROADMAP text" addition Tier 1's own Zoom STUN ports
//     precedent already established) is checked by protocol number alone -- its 4-byte Session ID
//     has no structural constraint distinguishing it from arbitrary data, so the IP protocol number
//     itself carries all the confidence here, the same "no further gate available" posture ESP/AH
//     have above. Reported with the shared protocol name "l2tp", unified with the UDP-1701 form
//     below (same wire concept, different transport).
//   - IKE (UDP 500, RFC 7296) has a genuine, multi-field structural signature: an 8-byte Initiator
//     SPI, 8-byte Responder SPI, then Next Payload(1)/Version(1, high nibble Major Version -- 1 for
//     IKEv1, 2 for IKEv2, low nibble Minor Version)/Exchange Type(1)/Flags(1)/Message ID(4)/
//     Length(4, big-endian, checked loosely against the captured payload the same tolerant way
//     GOOSE/SV/EtherCAT's own declared-length checks already are). Gated to port 500 (and 4500, see
//     below) -- not checked opportunistically, the same "not self-describing enough on its own"
//     caution RADIUS/TACACS+/NTP already get in Tier 3, since a constrained-but-not-unique byte
//     pattern like this one risks real false positives on an arbitrary UDP port. Port 4500 (RFC 3948
//     NAT-Traversal) carries EITHER IKE (prefixed by a 4-byte all-zero "non-ESP marker") OR ESP
//     itself (no marker, the raw ESP header directly) -- both are disambiguated by that marker's
//     presence, exactly per RFC 3948 section 2.
//   - L2TP (UDP 1701, RFC 2661 v2 / RFC 3931 v3-over-UDP) has a genuine structural signature for its
//     v2 form only: the first 16 bits are a Flags/Version word whose Version nibble must be 2 and
//     whose two reserved-bit groups must be 0 (RFC 2661 section 3.1) -- checked in full. L2TPv3's own
//     UDP form (RFC 3931 section 4.1) replaces that entire word with an opaque 32-bit Session ID that
//     has no structural constraint at all (the same "no further gate available" shape L2TPv3-over-IP
//     has above) -- a v2 structural mismatch on port 1701 is reported as "l2tp" anyway (the port
//     itself is IANA-registered exclusively for L2TP), but explicitly noted as the WEAK, port-only
//     fallback rather than the stronger v2 match, the same honesty this file's own IGRP/RADIUS-style
//     protocols already practice elsewhere.
//   - VXLAN (UDP 4789, RFC 7348) has a genuine structural signature: an 8-byte header whose Flags
//     byte must have the I bit (0x08, "VNI valid") set and no other bits set, and whose trailing
//     Reserved byte must be 0 -- RFC 7348 section 5's own "MUST be set to zero on transmission,
//     ignored on receipt" wording means real-world deviation is possible, but a clean match is a
//     strong signal. The 24-bit VNI is surfaced; the tunneled Ethernet frame itself is never parsed.
//   - Geneve (UDP 6081, RFC 8926) has a genuine structural signature: the first byte's top 2 bits
//     (Version) must be 0 (the only value RFC 8926 defines), and the second byte's low 6 bits
//     (Reserved) must be 0 (its O/C bits, the top 2, are meaningful and left unconstrained). The
//     16-bit inner Protocol Type (another EtherType, named via link_layer.hpp's ethertype_name() the
//     same way GRE's own Protocol Type is above) and 24-bit VNI are surfaced; option TLVs and the
//     tunneled frame itself are never parsed.
//   - WireGuard (UDP 51820, the protocol's own wire format, not an RFC) has the strongest structural
//     signature in this whole file: a 1-byte Message Type (1 = Handshake Initiation, 2 = Handshake
//     Response, 3 = Cookie Reply, 4 = Transport Data) followed by 3 mandatory zero reserved bytes,
//     and Types 1-3 each have an EXACT, fixed total packet length (148/92/64 bytes respectively) --
//     checked in full, the same "self-describing enough to check port-independently" strength SMB's
//     magic or DHCP's cookie have, though this file still gates it to port 51820 (its IANA-registered
//     default) purely for consistency with every other UDP-side protocol in this file, not because
//     the signature itself needs the gate.
//   - OpenVPN (UDP/TCP 1194, the protocol's own wire format) has a modest structural signature: the
//     first byte's top 5 bits are an Opcode from a small enumerated set (RFC-less, OpenVPN's own
//     source-defined P_* constants: 1/3/4/5/6/7/9/10/11 are the values ever seen on the wire; 0/2/8
//     are never assigned), the bottom 3 bits a Key ID. The TCP form (see try_recognize_tunnel_vpn_tcp)
//     is identical past a 2-byte big-endian length prefix. A five-out-of-32-ish enumerated Opcode
//     byte is a much weaker gate than WireGuard's exact-length match above -- closer to NTP's own
//     LI/VN/Mode gate -- so every match here says so.
//   - A generic DTLS record structural check (no fixed port at all -- ROADMAP item 18's own wording,
//     "443 and odd UDP ports... CAPWAP's own data plane, some vendor AP control channels, and LTE
//     'offload' clients can all ride one") is tried LAST among every UDP check in this file, and
//     checked port-independently rather than gated: DTLS's own record header (RFC 6347 section 4.1)
//     -- ContentType(1 byte, one of exactly four values: 20/21/22/23) + ProtocolVersion(2 bytes, one
//     of exactly three values: 0xFEFF/DTLS1.0, 0xFEFD/DTLS1.2, 0xFEFC/DTLS1.3) + Epoch(2) +
//     SequenceNumber(6) + Length(2, loosely checked against the captured payload) -- is a genuinely
//     strong, multi-field match (a constrained byte plus one of three exact 16-bit values, the same
//     "structural signature overrides the port gate" treatment VNC/SMB/SSH/HTTP/DHCP already get):
//     DTLS's version-major byte (0xFE) never collides with plain TLS's own (0x03), so this never
//     misfires against an ordinary TLS ClientHello either. Reported "dtls-tunnel" -- this file cannot
//     tell CAPWAP's own DTLS data plane, a vendor AP's DTLS control channel, an LTE offload client,
//     or a deliberate DTLS-based VPN apart from each other; naming that SOME encrypted DTLS tunnel is
//     present is the entire audit value here, per this ROADMAP item's own framing.
//   - STT (TCP port 7878) is recognized by port number ALONE -- the weakest gate in this file, the
//     same treatment LWAPP gets in Tier 4: STT's own frame format (a TCP-like header used purely for
//     NIC hardware-offload segmentation, RFC-less, never actually establishing a real TCP connection)
//     has no publicly authoritative specification this file's own research could confirm a structural
//     check against.
//
// Explicitly NOT implemented, with the reasoning documented here rather than silently skipped (the
// same "deliberate non-implementation" posture Tier 3's own DNS paragraph and Tier 4's own SSTP
// self-correction already established) -- see docs/MANUAL.md's LIMITATIONS for the user-facing
// version of all four:
//   - SSTP (TCP port 443) is not a separate protocol value at all: its entire handshake, including
//     the one distinguishing cleartext signal it has (an HTTP "SSTP_DUPLEX_POST" request line), rides
//     INSIDE an already-established TLS session -- SSTP is TLS-first, HTTP-inside, so that string
//     never appears in cleartext on the wire for this decoder (which never decrypts TLS) to see. Even
//     setting that aside, TCP/443 ClientHellos are already unconditionally claimed by the existing
//     HTTPS/DoH early-detection call site (see it_protocols.hpp's own HTTPS paragraph) before this
//     file's own TCP dispatch is ever reached, making a separate SSTP branch dead code regardless --
//     exactly the reasoning that also rules out any generic TCP-side "tls-tunnel" catch-all (redundant
//     with HTTPS's own port-only fallback for the identical reason).
//   - 4in6 and DS-Lite/MAP-E (all IPv6-outer encapsulations) are not reachable at all in this
//     codebase: decoder.cpp only ever parses an IPv4 outer header (see link_layer.hpp's own
//     ETHERTYPE_IPV6 handling, which names IPv6 frames but never parses them) -- there is no call
//     site these could ever be dispatched from.
//   - MPLS's own L2VPN/VPLS/pseudowire use case is not a separate protocol value: an MPLS-encapsulated
//     pseudowire is wire-format-identical to plain MPLS-encapsulated IP (the same label-stack framing,
//     the payload's own shape past the Bottom-of-Stack label is what differs, and that shape is
//     controlled entirely by out-of-band LDP/BGP signaling this decoder never sees) -- see mpls.hpp's
//     own file header comment for how this is folded into a note instead.
//   - CAPWAP's own alternate data-plane path (a wireless LAN controller decapsulating over GRE/L2TP/
//     IP-in-IP instead of native CAPWAP -- ROADMAP item 18's own closing clause) needs no new code at
//     all: GRE/L2TP/IP-in-IP recognition, built for this tier anyway, already names exactly that
//     traffic when it's captured -- the same "needs no new decode work" precedent Tier 3's own DNS
//     paragraph established for Active-Directory DNS correlation.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t GRE_IP_PROTOCOL = 47;      // RFC 2784 -- also NVGRE (RFC 8926) and Mikrotik EoIP,
                                               // both GRE Protocol-Type sub-cases, see this file's
                                               // own header comment
constexpr uint8_t ESP_IP_PROTOCOL = 50;      // RFC 4303 -- also reachable NAT-Traversed over UDP 4500
constexpr uint8_t AH_IP_PROTOCOL = 51;       // RFC 4302
constexpr uint8_t IPIP_IP_PROTOCOL = 4;      // RFC 2003 -- IPv4-in-IPv4
constexpr uint8_t IPV6_6IN4_IP_PROTOCOL = 41;  // RFC 4213 -- IPv6-in-IPv4
constexpr uint8_t L2TPV3_IP_PROTOCOL = 115;  // RFC 3931 section 4.1 -- also reachable over UDP 1701

// GRE's own Protocol Type field (a 16-bit EtherType value) sub-cases -- see this file's own header
// comment for the confidence caveat on nvgre specifically.
constexpr uint16_t GRE_PROTOCOL_TYPE_NVGRE_OR_ETHERNET_BRIDGING = 0x6558;  // RFC 8926 NVGRE, or plain
                                                                             // Ethernet-bridging-over-
                                                                             // GRE -- ambiguous, see
                                                                             // above
constexpr uint16_t GRE_PROTOCOL_TYPE_EOIP = 0x6400;  // Mikrotik EoIP, not IANA-registered but in wide
                                                       // unambiguous practical use

struct TunnelVpnIpProtoMatch {
    std::string protocol;  // "gre" / "nvgre" / "eoip" / "esp" / "ah" / "ip-in-ip" / "6in4" / "l2tp"
    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- none of these six ride on a
// TCP/UDP port) as one of this file's six IP-protocol-number-keyed tunnel/VPN encapsulations.
// `ip_protocol` is the outer IPv4 header's own protocol number (decoder.cpp only ever calls this for
// one of GRE_IP_PROTOCOL/ESP_IP_PROTOCOL/AH_IP_PROTOCOL/IPIP_IP_PROTOCOL/IPV6_6IN4_IP_PROTOCOL/
// L2TPV3_IP_PROTOCOL in the first place, each IANA-exclusive, so no port-based Auto-mode gating is
// needed here, the same posture IGMP/VRRP/IGRP/PIM/EIGRP/OSPF already have). Returns std::nullopt
// (never throws) when a protocol that DOES have a further structural gate (GRE's Version field,
// IP-in-IP's/6in4's own inner-IP-version nibble) fails it -- ESP/AH/L2TPv3-direct have no such gate
// (see this file's own header comment) and are never rejected once `ip_protocol` itself matches.
std::optional<TunnelVpnIpProtoMatch> try_recognize_tunnel_vpn_ip_proto(ByteSpan ip_payload,
                                                                          uint8_t ip_protocol);

constexpr uint16_t IKE_PORT = 500;        // UDP -- RFC 7296, IANA-registered "isakmp"
constexpr uint16_t IKE_NATT_PORT = 4500;  // UDP -- RFC 3948 NAT-Traversal: IKE (behind a 4-byte
                                            // all-zero non-ESP marker) or ESP directly (no marker)

constexpr uint16_t L2TP_PORT = 1701;  // UDP -- RFC 2661/3931, IANA-registered "l2tp"

constexpr uint16_t VXLAN_PORT = 4789;  // UDP -- RFC 7348, IANA-registered "vxlan"

constexpr uint16_t GENEVE_PORT = 6081;  // UDP -- RFC 8926, IANA-registered "geneve"

constexpr uint16_t WIREGUARD_PORT = 51820;  // UDP -- WireGuard's own documented default port

constexpr uint16_t OPENVPN_PORT = 1194;  // UDP or TCP -- IANA-registered "openvpn"

struct TunnelVpnUdpMatch {
    std::string protocol;  // "ike" / "esp" / "l2tp" / "vxlan" / "geneve" / "wireguard" / "openvpn" /
                             // "dtls-tunnel"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of this
// file's eight UDP-side tunnel/VPN protocols. Every one is UDP-only by spec (OpenVPN's own TCP form
// is a genuinely different framing, handled separately by try_recognize_tunnel_vpn_tcp below) so,
// like try_recognize_it_wireless_backhaul in it_protocols.hpp, there is no `is_tcp` parameter at
// all. `extra_ports` extends every one of this file's own default ports EXCEPT dtls-tunnel, which is
// checked port-independently regardless (see this file's own header comment) -- one shared list
// across all eight, the same "one feature toggle" grouping Tiers 1-4 already established.
std::optional<TunnelVpnUdpMatch> try_recognize_tunnel_vpn_udp(ByteSpan payload, uint16_t src_port,
                                                                 uint16_t dst_port,
                                                                 const std::vector<uint16_t>& extra_ports);

constexpr uint16_t STT_PORT = 7878;  // TCP -- STT's own documented default port

struct TunnelVpnTcpMatch {
    std::string protocol;  // "openvpn" / "stt"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match either of this
// file's two TCP-side tunnel/VPN protocols. `extra_ports` is the SAME list try_recognize_tunnel_vpn_
// udp takes (OPENVPN_PORT's own value, 1194, is shared verbatim between the TCP and UDP forms) --
// not a separate TCP-only list, since this is still one feature toggle covering one ROADMAP tier.
std::optional<TunnelVpnTcpMatch> try_recognize_tunnel_vpn_tcp(ByteSpan payload, uint16_t src_port,
                                                                 uint16_t dst_port,
                                                                 const std::vector<uint16_t>& extra_ports);

}  // namespace conduitscope
