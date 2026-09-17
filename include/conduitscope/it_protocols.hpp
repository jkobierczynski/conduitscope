// SPDX-License-Identifier: Apache-2.0
// it_protocols.hpp - Name-only recognition for the "interactive remote control" tier (Tier 1) of
// the "IT protocols an OT auditor flags" family -- see docs/MANUAL.md's ROADMAP item 18. These
// protocols give an attacker a full interactive session with an HMI/engineering station, not just
// a register read/write, which is why an OT auditor treats their mere PRESENCE on a production
// segment as a finding worth its own line item, independent of whether the traffic itself is ever
// decoded. Scoped deliberately narrow, the same "recognized but not decoded" posture ARP/LLDP/ICMP
// already have elsewhere in this decoder (see decoder.cpp's non-ip/non-tcp fallback branches):
// this file identifies WHICH of these five protocols a flow most likely is, from its port and (for
// RDP/VNC) a minimal, cheap structural signature -- it never attempts to parse anything past that,
// since there is no OT-security value in decoding RDP's own bitmap updates or a VNC framebuffer
// update, and most of these are encrypted and structurally opaque by design past their first few
// bytes anyway.
//
// Confidence varies sharply across the five, and every summary/note this file produces says so
// honestly rather than presenting a uniform confidence level:
//   - VNC has a genuinely strong, cleartext structural signature: every RFB (Remote Framebuffer)
//     server sends a 12-byte ASCII protocol-version banner ("RFB 003.008\n") as the very first
//     bytes of a session, unencrypted, before any negotiation happens at all (RFC 6143 section
//     7.1.1). Checked first, port-independently -- a real VNC server behind a nonstandard port is
//     still confidently identified, though the port itself is still reported.
//   - RDP's initial X.224 Connection Request/Confirm rides the IDENTICAL TPKT (RFC 1006) + COTP
//     (ISO 8073) framing this project's own cotp.hpp already implements for S7comm/MMS on TCP port
//     102. That structural check is NOT performed by this file -- it's done directly in
//     decoder.cpp, BEFORE the opportunistic, port-independent COTP/S7comm/MMS dispatch that would
//     otherwise claim a genuine RDP handshake as generic "cotp" traffic first (see decoder.cpp's
//     own comment at that call site for the full reasoning). try_recognize_it_remote_access below
//     only ever sees RDP traffic that ISN'T a Connection Request/Confirm on port 3389 -- i.e. an
//     already-established, encrypted RDP session -- so its own RDP match is port-only, same as
//     TeamViewer/AnyDesk/Zoom's.
//   - TeamViewer, AnyDesk, and Zoom have NO known cleartext structural signature this decoder's own
//     research could confirm -- all three are encrypted or otherwise opaque from their very first
//     byte on the wire. These three are recognized by port number ALONE, the weakest gate in this
//     entire codebase (weaker even than HART-IP's own "loosely-checked header fields" gate --
//     there is no payload check here at all) -- every match this produces for these three says so
//     explicitly, both in its summary and by never claiming a `port_expected` structural
//     confirmation the way VNC/RDP's own matches can.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t RDP_PORT = 3389;  // TCP -- IANA-registered "ms-wbt-server"

// VNC/RFB (RFC 6143): the well-known port is 5900 + display number, conventionally displays 0-6
// (5900-5906) though nothing stops a real deployment from using a display number outside that --
// the RFB banner check above is what actually carries confidence here, not the port.
constexpr uint16_t VNC_PORT_BASE = 5900;
constexpr uint16_t VNC_PORT_MAX_DISPLAY = 6;

constexpr uint16_t TEAMVIEWER_PORT = 5938;  // TCP/UDP -- IANA-registered "teamviewer"

constexpr uint16_t ANYDESK_PORT = 7070;  // TCP/UDP -- AnyDesk's own documented default port

// Zoom's own documented port usage (help.zoom.us network-firewall guidance): TCP/UDP 8801-8810 for
// client media/signaling, plus UDP 3478-3479 for STUN. Zoom's own docs also list TCP 443/80 as a
// fallback, deliberately NOT included here -- those ports are so widely shared with ordinary HTTPS/
// HTTP traffic that treating them as a Zoom signal would be far too weak even by this file's own
// already-loose "port alone" standard for this tier.
constexpr uint16_t ZOOM_PORT_RANGE_START = 8801;
constexpr uint16_t ZOOM_PORT_RANGE_END = 8810;
constexpr uint16_t ZOOM_STUN_PORT_START = 3478;
constexpr uint16_t ZOOM_STUN_PORT_END = 3479;

struct ItRemoteAccessMatch {
    std::string protocol;  // "rdp" / "vnc" / "teamviewer" / "anydesk" / "zoom"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of the five
// protocols this file recognizes. `is_tcp` gates the two protocols with a transport-specific
// structural check (VNC's RFB banner and RDP's TPKT/COTP framing are both TCP-only by spec); the
// three port-only protocols are checked over TCP or UDP alike, since TeamViewer/AnyDesk/Zoom all
// use both in real deployments. `extra_ports` extends every one of this file's own default ports
// (the same "additional configured ports" convention every other protocol in decoder.hpp's
// DecodeOptions already uses) -- one shared list across all five, since this is one feature toggle
// covering one ROADMAP tier, not five independent ones.
std::optional<ItRemoteAccessMatch> try_recognize_it_remote_access(ByteSpan payload, uint16_t src_port,
                                                                    uint16_t dst_port, bool is_tcp,
                                                                    const std::vector<uint16_t>& extra_ports);

}  // namespace conduitscope
