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
//
// ---------------------------------------------------------------------------------------------
// Tier 2 -- "lateral-movement and credential-harvesting protocols that should be absent from a
// production OT segment entirely per most hardening guides" (ROADMAP item 18's own wording): SMB/
// NetBIOS, SSH, HTTP, HTTPS, SNMPv1/v2c, Telnet, FTP, and TFTP -- eight `protocol` values sharing
// one `ProtocolFilter::LateralMovementOnly` toggle and one `extra_lateral_movement_ports` list, the
// same "one feature toggle, several sub-protocols" grouping Tier 1's own RemoteAccessOnly filter
// established (see decoder.hpp). Confidence again varies sharply, and again every summary/note says
// so honestly:
//   - SMB has a genuine cleartext structural signature at connection setup: a 4-byte magic
//     (0xFF"SMB" for SMB1/CIFS, 0xFE"SMB" for SMB2/3, 0xFD"SMB" for an SMB2/3 Transform/encrypted
//     header) either directly at the start of a TCP/445 segment (the modern "direct hosting"
//     convention) or 4 bytes into a NetBIOS Session Service wrapper (RFC 1002 -- a 1-byte message
//     type + 3-byte length) on TCP/139. Direct-hosting magic is checked port-independently, same
//     treatment VNC's RFB banner gets, since it is just as self-describing; the NetBIOS-wrapped form
//     is gated to port 139 (the wrapper's own leading type byte alone is too common a value to check
//     opportunistically). Past connection setup SMB is either further negotiation (still readable)
//     or session-key-encrypted (SMB3 with encryption negotiated) -- this file never looks past the
//     header, so "dialect negotiated" isn't captured, only "this is SMB, some dialect."
//   - SSH has RFC 4253 section 4.2's own version-exchange banner ("SSH-2.0-OpenSSH_9.6" or similar,
//     newline-terminated, ALWAYS the first bytes of a real SSH session in cleartext, by design --
//     this is how client/server negotiate protocol/software versions before any encryption begins).
//     Checked port-independently, same reasoning as VNC/SMB above: SSH deliberately running on a
//     nonstandard port (a common jump-host hardening practice) is still worth flagging just as much
//     as SSH on port 22, arguably more so. Past the banner, SSH is fully encrypted (key exchange
//     completes within the first few packets), so an established session is port-only, same
//     weakest-gate treatment as RDP's own post-handshake fallback.
//   - HTTP has its own genuine cleartext structural signature every single request/response carries:
//     a request-line (`METHOD SP request-target SP "HTTP/"DIGIT"."DIGIT CRLF`, RFC 9112 section 3)
//     or a status-line (`"HTTP/"DIGIT"."DIGIT SP 3DIGIT ...`, RFC 9112 section 4). Checked port-
//     independently and deliberately so -- the entire point of flagging "vendor web UIs" (Siemens
//     WinCC and similar embedded management interfaces) is that they routinely run on whatever port
//     the vendor picked, not just 80/8080/8000.
//   - HTTPS reuses this project's own tls_sni.hpp TLS ClientHello parser (already built for DoH
//     detection) rather than re-implementing TLS record/handshake parsing -- see decoder.cpp's own
//     call site for exactly how this is layered underneath DoH's existing, more specific detection
//     (a DoH match always wins; a ClientHello that ISN'T a known DoH provider's hostname is generic
//     "https" instead). That generic check is NOT in this file (it has to run before this file's own
//     call site, on the single un-reassembled TCP segment, exactly like DoH's own check) -- this
//     file only supplies HTTPS's port-only fallback, for an already-established (fully encrypted, no
//     visible ClientHello) TLS session on a configured HTTPS port.
//   - SNMPv1/v2c has a genuine, if loosely-typed, cleartext structural signature: an ASN.1 BER
//     SEQUENCE wrapping an INTEGER version (0 = v1, 1 = v2c -- v3's very different, USM-authenticated
//     framing is out of scope, since v3 has no cleartext community string to extract in the first
//     place) followed immediately by an OCTET STRING community string. Unlike every other check in
//     this family, this one genuinely extracts and surfaces real payload content (the community
//     string itself) rather than staying purely name-only -- a deliberate, narrow exception: per
//     ROADMAP item 18's own wording, "a cleartext community string sniffed once maps every SNMP-
//     speaking device on the segment," so the whole audit value here is seeing the string itself,
//     not just knowing SNMP was present. Gated to UDP 161/162 (or a configured extra port) --
//     ASN.1's own SEQUENCE/INTEGER/OCTET-STRING tag bytes are common enough elsewhere that checking
//     them opportunistically on every UDP port would risk real false positives, unlike VNC/SSH/SMB/
//     HTTP's much more self-describing signatures above.
//   - Telnet's only structural signal is IAC (0xFF) option-negotiation triplets (IAC + WILL/WONT/DO/
//     DONT + option byte, RFC 854), which real sessions send in a burst right at connection start --
//     but 0xFF alone is too common a byte value in arbitrary binary traffic to check port-
//     independently, so this is gated to TCP port 23 (or a configured extra port) even for the
//     "stronger" structural match; past that initial burst, a Telnet session is unstructured
//     interactive text with no signature at all, so most packets in a real session are the port-only
//     fallback, not the negotiation match.
//   - FTP's control channel (TCP port 21 only -- the ephemeral, dynamically-negotiated data channel
//     that PORT/PASV/EPRT/EPSV set up is explicitly out of scope, since it has no fixed port and no
//     content signature of its own past raw file bytes) has two genuine cleartext signals: a 3-digit
//     reply code (`DDD` + SP or `-` for multiline, RFC 959 section 4.2) from the server, or a known
//     command verb (USER/PASS/RETR/STOR/LIST/PASV/... ) from the client. Gated to port 21, same
//     "too common a byte shape otherwise" reasoning as Telnet above (a 3-digit-number-plus-space
//     shape is not nearly as self-describing as VNC's/SSH's own banners).
//   - TFTP (UDP port 69) has a strong signature for exactly its first two opcodes: RRQ (1) and WRQ
//     (2) are followed by a NUL-terminated filename and a NUL-terminated, well-known mode string
//     ("netascii"/"octet"/"mail" -- RFC 1350 section 5), which this file validates in full. DATA (3),
//     ACK (4), and ERROR (5) -- the rest of a transfer, once under way -- have no comparable
//     signature (a 2-byte opcode plus a 2-byte block number/error code is far too generic to check
//     opportunistically), so those fall to the port-only match, explicitly noted as such.
//
// ---------------------------------------------------------------------------------------------
// Tier 3 -- "individually unremarkable in limited form but worth an auditor's attention for where
// they terminate and whether the OT side blindly trusts enterprise IT for them" (ROADMAP item 18's
// own wording): NTP, DHCP, LDAPS, RADIUS, and TACACS+ -- five `protocol` values sharing one
// `ProtocolFilter::EnterpriseTrustOnly` toggle and one `extra_enterprise_trust_ports` list, the same
// "one feature toggle, several sub-protocols" grouping Tiers 1-2 already established (see
// decoder.hpp). IEEE 802.1X/EAPOL is ALSO Tier 3 but, having no port at all (EtherType 0x888E), is
// NOT in this file -- see eapol.hpp and decoder.hpp's own ProtocolFilter::EapolOnly comment for why.
// Plaintext LDAP is ALSO Tier 3 in spirit but, since the Windows AD suite (see kerberos.hpp's file
// header comment) needed it upgraded to a full ProtocolDecoder with curated attack/monitoring
// detection, it was pulled out into its own dedicated ldap.hpp/`--protocol ldap`, the same "pull one
// protocol out of a shared tier into its own dedicated decoder/CLI surface" move this codebase
// already made once for EAPOL. Only `match_ldap_ber`/`looks_like_ldap_ber` (below) still live here --
// ldap.hpp's own structural gate reuses them rather than duplicating a second BER-envelope reader,
// and decoder.cpp's MQTT-collision carve-out (see `looks_like_ldap_ber`'s own comment) still needs
// them too. LDAPS (LDAP-over-TLS) is UNCHANGED and stays in this file -- it was never more than a
// port-only ClientHello/fallback tag to begin with, see its own bullet below.
// DNS/Active Directory's DNS component needs no new code here either: DNS itself is already decoded
// in full (see this file's own PROTOCOL COVERAGE cross-reference in docs/MANUAL.md) -- this tier is
// about correlating where an OT segment's DNS queries actually terminate (an enterprise domain
// controller vs. a local/isolated resolver), which is a policy/zone-conduit question for
// docs/MANUAL.md and `policy validate` to eventually answer, not a decoding gap.
//   - NTP (UDP port 123 -- gated, unlike VNC/SSH/SMB/HTTP above: NTP's own header has no self-
//     describing byte shape strong enough to check opportunistically on every UDP port, see below)
//     has a genuine, if modest, structural signature in its very first byte: RFC 5905 section 7.3's
//     LI (2 bits, leap indicator) / VN (3 bits, version number, 1-4 for every version actually seen
//     on the wire) / Mode (3 bits, 1-5 for symmetric-active/symmetric-passive/client/server/broadcast,
//     6 for an NTP control message, RFC 1119/5905) fields, plus a minimum 48-byte packet size (the
//     fixed NTPv3/v4 header). This is a much weaker gate than VNC's RFB banner or SSH's version
//     string -- a handful of small integers, not a multi-byte ASCII match -- so it stays port-gated.
//     An OT auditor's actual interest here (per ROADMAP item 18) is less "is this NTP" and more
//     "which server does the OT segment sync its clock against" -- this file only names the protocol
//     and its Mode, it does not attempt to extract/report the actual timestamp fields.
//   - DHCP (UDP port 67 server / 68 client) has a genuine, strong, cleartext structural signature:
//     RFC 2131's fixed 236-byte BOOTP-derived header is ALWAYS followed by a 4-byte magic cookie,
//     `0x63 0x82 0x53 0x63` (RFC 1497/2131 section 3), before the first DHCP option. Checked port-
//     independently, the same "structural signature overrides the port gate" treatment VNC/SMB/SSH/
//     HTTP get above -- a rogue or misconfigured DHCP server answering on an unexpected port is
//     exactly the kind of thing worth catching regardless. When present, option 53 (DHCP Message
//     Type, RFC 2132 section 9.6) is additionally decoded by name (DISCOVER/OFFER/REQUEST/DECLINE/
//     ACK/NAK/RELEASE/INFORM and the RFC 3203/4388 extensions) -- every other DHCP option is left
//     entirely unparsed.
//   - Plain LDAP (TCP port 389, or 3268 for Global Catalog) is NOT recognized by this file anymore --
//     see this file's own header comment above for why it moved to its own dedicated ldap.hpp/
//     `--protocol ldap` (full field decode, curated AD-recon/AS-REP-Roasting/delegation-discovery
//     detection, session correlation), not just name-only recognition.
//   - LDAPS (LDAP-over-TLS, port 636, or 3269 for Global Catalog) reuses this project's own TLS
//     ClientHello parser (tls_sni.hpp, already layered under HTTPS/DoH detection -- see this file's
//     own HTTPS paragraph above) rather than a second TLS implementation: decoder.cpp's existing
//     early ClientHello call site gets one more port-based branch, tagging a ClientHello on port
//     636/3269 "ldaps" instead of generic "https" when ALPN doesn't already confirm HTTP. That check
//     is NOT in this file, exactly like HTTPS's own strong check -- this file only supplies LDAPS's
//     port-only fallback, for an already-established, fully-encrypted session with no visible
//     ClientHello in this particular packet.
//   - RADIUS (UDP port 1812/1813, the RFC 2865/2866-standardized Access/Accounting pair, plus the
//     legacy, still commonly seen 1645/1646 pre-standardization ports) has a genuine structural
//     signature: a 20-byte fixed header (RFC 2865 section 3) -- Code (1 byte, a small enumerated set:
//     1 Access-Request, 2 Access-Accept, 3 Access-Reject, 4 Accounting-Request, 5 Accounting-Response,
//     11 Access-Challenge, 12 Status-Server, 13 Status-Client, 40-45 the RFC 5176 Dynamic
//     Authorization Disconnect-Request/ACK/NAK and CoA-Request/ACK/NAK) -- Identifier (1 byte),
//     Length (2 bytes big-endian, RFC 2865's own "20 <= Length <= 4096" bound), and a 16-byte
//     Authenticator this file never inspects. Gated to port (RADIUS's Code byte alone, one enumerated
//     value out of 256, is not self-describing enough to check opportunistically, the same reasoning
//     TACACS+ and NTP get below). Per ROADMAP item 18's own wording ("cleartext-by-default attribute
//     encoding for anything past the shared secret"), this file deliberately does NOT attempt to walk
//     RADIUS's own Attribute-Value pairs past the fixed header -- User-Name/User-Password/etc. are
//     genuinely present in some of those AVPs, and decoding them would cross this whole ROADMAP
//     item's own "name-only" line (SNMP's community string is the one deliberate, narrow exception
//     already made, and it stays that way).
//   - TACACS+ (TCP port 49 -- used almost exclusively for network-device-administration AAA, RFC
//     8907, formerly a Cisco proprietary protocol) has a genuine structural signature in its 12-byte
//     fixed header: a version byte whose upper nibble is always `0xC` (TAC_PLUS_MAJOR_VERSION) and
//     whose lower nibble is 0x0 or 0x1 (TAC_PLUS_MINOR_VERSION_DEFAULT/_ONE), a Type byte (1
//     Authentication, 2 Authorization, 3 Accounting), a Sequence Number and Flags byte (bit 0x01,
//     TAC_PLUS_UNENCRYPTED_FLAG, is itself worth surfacing -- RFC 8907 section 4.5 calls cleartext
//     TACACS+ body encryption "obfuscation" at best, so an unencrypted session is a real finding, not
//     just a protocol-naming curiosity), a 4-byte Session ID, and a 4-byte body Length. Gated to port
//     49, the same "not self-describing enough on its own" reasoning as RADIUS/NTP above.
//
// ---------------------------------------------------------------------------------------------
// Tier 4 -- "wireless access-point control/data planes and cellular backhaul" (ROADMAP item 18's
// own wording): an AP or wireless LAN controller reachable from (or inside) an OT zone is itself a
// finding, independent of whatever rides inside its tunnel -- CAPWAP control/data, its older,
// Cisco-proprietary predecessor LWAPP, and the cellular-backhaul-specific GTP-U -- five `protocol`
// values sharing one `ProtocolFilter::WirelessBackhaulOnly` toggle and one
// `extra_wireless_backhaul_ports` list, the same "one feature toggle, several sub-protocols"
// grouping Tiers 1-3 already established (see decoder.hpp). PPPoE, ALSO Tier 4 but EtherType-keyed
// (0x8863/0x8864, no port at all -- the same shape EAPOL has in Tier 3), is NOT in this file -- see
// pppoe.hpp and decoder.hpp's own ProtocolFilter::PppoeOnly comment for why.
//   - CAPWAP control (UDP port 5246, RFC 5415) has a genuine, if modest, structural signature: the
//     1-byte Preamble (Version, always 0 -- the only value RFC 5415 ever defines -- and Type, 0 for
//     a plaintext CAPWAP header or 1 for a CAPWAP-over-DTLS header) plus, for a plaintext header,
//     the CAPWAP Transport Header's own HLEN field (the header's declared length in 4-byte words,
//     RFC 5415 section 4.3), sanity-checked against the captured payload. This file does NOT attempt
//     a bit-perfect decode of every transport-header field (RID/WBID and the six flag bits are left
//     unparsed) -- HLEN alone is enough to locate the Control Header that follows, whose own Message
//     Type (a 4-byte enumerated field, RFC 5415 section 4.5 / IANA's "CAPWAP Message Types"
//     registry) is what this file actually names. A CAPWAP-over-DTLS header (Type 1) is recognized
//     by its Preamble alone -- everything past it is an opaque DTLS record, so no Message Type is
//     ever available for that case. Gated to port 5246 -- the Preamble's own Version/Type nibbles
//     are a much looser gate than GOOSE/SV's own single-byte outer BER tag (see eapol.hpp's
//     "structural detection gate" paragraph for the same reasoning applied there), so this stays
//     port-gated rather than checked opportunistically the way DHCP's magic cookie is in Tier 3.
//   - CAPWAP data (UDP port 5247) shares the identical Preamble/Transport-Header shape as CAPWAP
//     control above -- checked the same way -- but its own payload past the header is the actual
//     bridged wireless client frame (802.11, tunneled to the controller for centralized forwarding)
//     rather than a Control Header with a Message Type, so this file names it "capwap-data" and goes
//     no further: per ROADMAP item 18's own framing, the control/data plane's mere PRESENCE is the
//     finding here, independent of whatever client traffic rides inside the tunnel -- decoding the
//     inner 802.11 frame would also require trusting the AP/controller pairing this item is itself
//     questioning.
//   - LWAPP control (UDP port 12222) and LWAPP data (UDP port 12223) are the older, Cisco-
//     proprietary protocol CAPWAP was directly modeled on (and superseded -- RFC 5415's own
//     Introduction) -- unlike CAPWAP, LWAPP was never published as a standards-track RFC (its own
//     IETF draft, draft-ietf-capwap-lwapp, expired unadopted), so this file has no authoritative
//     public wire-format specification to check a structural signature against. Both are recognized
//     by port number ALONE -- the same weakest-gate treatment TeamViewer/AnyDesk/Zoom get in Tier 1
//     (see this file's own Tier 1 paragraph above) -- every match this produces for LWAPP says so
//     explicitly.
//   - GTP-U (UDP port 2152, 3GPP TS 29.281) has a genuine structural signature in its mandatory
//     8-byte header: the first byte's top 4 bits are always Version(3 bits)=1 concatenated with
//     PT(1 bit)=1 for GTP (as opposed to GTP', an unrelated charging protocol sharing the same
//     Version field) -- i.e. always 0x3 -- followed by an enumerated Message Type (1 byte -- 255 =
//     G-PDU, the actual tunneled user-plane packet, is by far the most common in practice; 1/2 =
//     Echo Request/Response are the other frequent ones; the rest are named from TS 29.281's own
//     registry), a Length field (2 bytes, the payload's length AFTER this 8-byte mandatory header,
//     not strictly re-validated against the captured payload -- the same lenient "declares more than
//     was actually captured -- almost always snaplen truncation" tolerance GOOSE/SV/EtherCAT's own
//     declared-length checks already have), and a 4-byte TEID (Tunnel Endpoint Identifier) this file
//     surfaces but does not attempt to correlate across packets. Gated to port 2152, the same "not
//     self-describing enough on its own" reasoning RADIUS/TACACS+/NTP get above, even though the
//     Version/PT check is a real structural signature. Per ROADMAP item 18's own framing ("a
//     well-known way SCADA traffic leaves a site entirely outside any on-prem firewall's view"),
//     this file deliberately does NOT attempt to decode a G-PDU's own inner IP packet -- naming the
//     tunnel itself, and its TEID, is the audit-relevant finding; unwrapping the inner packet would
//     cross into a second decode pass this ROADMAP item's own name-only posture doesn't call for.
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

// ---------------------------------------------------------------------------------------------
// Tier 2 -- see this file's own header comment above for the full per-protocol confidence writeup.

constexpr uint16_t SMB_PORT_445 = 445;               // TCP -- direct SMB-over-TCP hosting (no
                                                       // NetBIOS wrapper), the modern default since
                                                       // Windows 2000
constexpr uint16_t SMB_NETBIOS_SESSION_PORT_139 = 139;  // TCP -- classic NetBIOS Session Service
                                                          // (RFC 1002) wrapper, still seen from
                                                          // legacy Windows/Samba configurations

constexpr uint16_t SSH_PORT = 22;  // TCP -- IANA-registered "ssh"

// HTTP deliberately has no single "the" port in this file -- see the header comment above for why
// its own structural check is port-independent. These three are only a curated "commonly
// configured" set for the "expected port" annotation on the WEAK, no-structural-match fallback.
constexpr uint16_t HTTP_PORT_80 = 80;
constexpr uint16_t HTTP_PORT_8080 = 8080;
constexpr uint16_t HTTP_PORT_8000 = 8000;

// HTTPS's own ClientHello structural check lives in decoder.cpp (see this file's header comment) --
// these two are only this file's own port-only fallback gate.
constexpr uint16_t HTTPS_PORT_443 = 443;   // shared with tls_sni.hpp's own DOH_PORT, deliberately
constexpr uint16_t HTTPS_PORT_8443 = 8443;

constexpr uint16_t SNMP_AGENT_PORT = 161;
constexpr uint16_t SNMP_TRAP_PORT = 162;

constexpr uint16_t TELNET_PORT = 23;

constexpr uint16_t FTP_CONTROL_PORT = 21;  // the data channel is explicitly out of scope -- see
                                             // this file's header comment

constexpr uint16_t TFTP_PORT = 69;

struct ItLateralMovementMatch {
    std::string protocol;  // "smb" / "ssh" / "http" / "https" / "snmp" / "telnet" / "ftp" / "tftp"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of the eight
// Tier 2 protocols this file recognizes. Unlike try_recognize_it_remote_access above, every one of
// these eight has a FIXED transport (SMB/SSH/HTTP/HTTPS/Telnet/FTP are TCP-only, SNMP/TFTP are UDP-
// only) rather than legitimately appearing on both, so `is_tcp` selects which half of this function
// even attempts a match, rather than merely widening a shared port-only fallback the way it does in
// try_recognize_it_remote_access. `extra_ports` extends every one of this file's own default ports,
// one shared list across all eight -- the same "one feature toggle" grouping Tier 1's own
// try_recognize_it_remote_access already established, not eight independent option lists.
std::optional<ItLateralMovementMatch> try_recognize_it_lateral_movement(ByteSpan payload, uint16_t src_port,
                                                                          uint16_t dst_port, bool is_tcp,
                                                                          const std::vector<uint16_t>& extra_ports);

// Exposed narrowly for decoder.cpp's own reassemble_tcp_payload, to resolve a real collision found
// while implementing this: an FTP reply-code line ("220 ...") or command-verb line ("USER ...")
// begins with ASCII bytes that can coincidentally satisfy MQTT's own single-byte "control packet
// type (top nibble) + valid flags (bottom nibble) + a plausible variable-length-encoded remaining
// length" declared-length gate (mqtt.hpp) purely by chance -- MQTT's own opportunistic, port-
// independent reassembly probe (tried before this file's own Tier 2 dispatch, which only runs once
// reassembly completes) would otherwise buffer real FTP control-channel traffic forever waiting for
// bytes that will never arrive. See decoder.cpp's own call site for the full reasoning; true when
// `payload` matches this file's own FTP reply-code/command-verb structural check (the same one
// try_recognize_it_lateral_movement itself uses).
bool looks_like_ftp_control_line(ByteSpan payload);

// ---------------------------------------------------------------------------------------------
// Tier 3 -- see this file's own header comment above for the full per-protocol confidence writeup.
// EAPOL (also Tier 3) is NOT declared here -- see eapol.hpp's own try_parse_eapol.

constexpr uint16_t NTP_PORT = 123;  // UDP -- IANA-registered "ntp"

constexpr uint16_t DHCP_SERVER_PORT = 67;  // UDP -- IANA-registered "bootps"
constexpr uint16_t DHCP_CLIENT_PORT = 68;  // UDP -- IANA-registered "bootpc"

constexpr uint16_t LDAP_PORT = 389;      // TCP -- IANA-registered "ldap"
constexpr uint16_t LDAP_GC_PORT = 3268;  // TCP -- Active Directory Global Catalog, plaintext

// LDAPS's own ClientHello structural check lives in decoder.cpp (see this file's header comment) --
// these two are only this file's own port-only fallback gate.
constexpr uint16_t LDAPS_PORT = 636;      // TCP -- IANA-registered "ldaps"
constexpr uint16_t LDAPS_GC_PORT = 3269;  // TCP -- Active Directory Global Catalog over TLS

constexpr uint16_t RADIUS_AUTH_PORT = 1812;         // UDP -- RFC 2865, current IANA-registered port
constexpr uint16_t RADIUS_ACCT_PORT = 1813;         // UDP -- RFC 2866, current IANA-registered port
constexpr uint16_t RADIUS_AUTH_PORT_LEGACY = 1645;  // UDP -- pre-standardization, still common
constexpr uint16_t RADIUS_ACCT_PORT_LEGACY = 1646;  // UDP -- pre-standardization, still common

constexpr uint16_t TACACS_PLUS_PORT = 49;  // TCP -- IANA-registered "tacacs"

struct ItEnterpriseTrustMatch {
    std::string protocol;  // "ntp" / "dhcp" / "ldaps" / "radius" / "tacacs-plus" -- plain "ldap" moved
                            // to its own dedicated ldap.hpp, see this file's own header comment
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of the five
// port-based Tier 3 protocols this file recognizes (EAPOL, the seventh Tier 3 protocol, has no port
// at all -- see eapol.hpp; plain LDAP, no longer recognized here at all -- see ldap.hpp and this
// file's own header comment). Like try_recognize_it_lateral_movement above, every one of these five
// has a FIXED transport (NTP/DHCP/RADIUS are UDP-only, LDAPS/TACACS+ are TCP-only) so `is_tcp`
// selects which half of this function even attempts a match. `extra_ports` extends every one of this
// file's own default ports, one shared list across all five -- the same "one feature toggle" grouping
// Tiers 1-2 already established, not five independent option lists.
std::optional<ItEnterpriseTrustMatch> try_recognize_it_enterprise_trust(ByteSpan payload, uint16_t src_port,
                                                                          uint16_t dst_port, bool is_tcp,
                                                                          const std::vector<uint16_t>& extra_ports);

// Exposed for two callers now (both narrow, both structural-gate-only uses of this file's own LDAP
// BER envelope check, kept here rather than duplicated a third time -- see this file's own header
// comment): (1) decoder.cpp's reassemble_tcp_payload, to resolve a real collision found while this
// file was first implemented -- LDAP's own LDAPMessage envelope always begins with a BER SEQUENCE
// tag, byte value 0x30 -- bit-for-bit identical to a valid MQTT control-packet-type/flags byte
// (control packet type 3 = PUBLISH, flags all clear), so MQTT's own single-byte opportunistic,
// port-independent declared-length gate (mqtt.hpp) matches every genuine LDAP message purely by
// chance, the same shape of collision Tier 2's own looks_like_ftp_control_line already resolves for
// FTP vs. MQTT (see that function's own comment) -- MQTT's own reassembly probe would otherwise
// buffer real LDAP traffic forever waiting for bytes that will never arrive; and (2) ldap.hpp's own
// LdapTcpDecoder structural gate/tcp_declared_length, reusing this exact three-part check
// (SEQUENCE+length / INTEGER messageID / APPLICATION-class protocolOp) rather than a second,
// duplicated BER-envelope reader -- see ldap.hpp's own file header comment for the full collision
// survey against Kerberos and everything else in the TCP-port-independent cascade.
bool looks_like_ldap_ber(ByteSpan payload);

// ---------------------------------------------------------------------------------------------
// Tier 4 -- see this file's own header comment above for the full per-protocol confidence writeup.
// PPPoE (also Tier 4) is NOT declared here -- see pppoe.hpp's own try_parse_pppoe.

constexpr uint16_t CAPWAP_CONTROL_PORT = 5246;  // UDP -- RFC 5415, IANA-registered "capwap-control"
constexpr uint16_t CAPWAP_DATA_PORT = 5247;     // UDP -- RFC 5415, IANA-registered "capwap-data"

// Cisco-proprietary, no authoritative public RFC -- see this file's own header comment.
constexpr uint16_t LWAPP_CONTROL_PORT = 12222;  // UDP
constexpr uint16_t LWAPP_DATA_PORT = 12223;     // UDP

constexpr uint16_t GTP_U_PORT = 2152;  // UDP -- 3GPP TS 29.281, IANA-registered "gtp-u"

struct ItWirelessBackhaulMatch {
    std::string protocol;  // "capwap-control" / "capwap-data" / "lwapp-control" / "lwapp-data" / "gtp-u"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of the five
// Tier 4 protocols this file recognizes. Unlike every earlier tier in this file, all five are
// UDP-only by spec, so there is no `is_tcp` parameter at all -- see decoder.cpp's own call site,
// which only ever reaches this function from the UDP dispatch path. `extra_ports` extends every one
// of this file's own default ports, one shared list across all five -- the same "one feature toggle"
// grouping Tiers 1-3 already established, not five independent option lists.
std::optional<ItWirelessBackhaulMatch> try_recognize_it_wireless_backhaul(ByteSpan payload, uint16_t src_port,
                                                                            uint16_t dst_port,
                                                                            const std::vector<uint16_t>& extra_ports);

}  // namespace conduitscope
