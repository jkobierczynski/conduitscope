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
// own wording): NTP, DHCP, LDAP/LDAPS, RADIUS, and TACACS+ -- six `protocol` values sharing one
// `ProtocolFilter::EnterpriseTrustOnly` toggle and one `extra_enterprise_trust_ports` list, the same
// "one feature toggle, several sub-protocols" grouping Tiers 1-2 already established (see
// decoder.hpp). IEEE 802.1X/EAPOL is ALSO Tier 3 but, having no port at all (EtherType 0x888E), is
// NOT in this file -- see eapol.hpp and decoder.hpp's own ProtocolFilter::EapolOnly comment for why.
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
//   - LDAP (TCP port 389, or 3268 for Global Catalog) has a genuine cleartext structural signature at
//     the LDAPMessage level (RFC 4511 section 4.1): a BER SEQUENCE wrapping an INTEGER messageID
//     followed immediately by a protocolOp tagged [APPLICATION n] (bindRequest=0, bindResponse=1,
//     unbindRequest=2, searchRequest=3, searchResEntry=4, searchResDone=5, modifyRequest=6,
//     modifyResponse=7, addRequest=8, addResponse=9, delRequest=10, delResponse=11, modDNRequest=12,
//     modDNResponse=13, compareRequest=14, compareResponse=15, abandonRequest=16, searchResRef=19,
//     extendedReq=23, extendedResp=24, intermediateResponse=25). Gated to port 389/3268 (or a
//     configured extra port) even though the check is structurally about as strong as SNMP's own
//     SEQUENCE/INTEGER check above -- the same "ASN.1 tag bytes are common enough elsewhere" caution
//     that keeps SNMP port-gated applies here too. An unencrypted LDAP bind (bindRequest, op 0) is
//     independently worth its own note: it is the one case where this file's "name-only" posture
//     still surfaces something the auditor should look at, a cleartext-credential bind (LDAP simple
//     bind sends the password as plaintext unless started over TLS/StartTLS), without decoding the
//     credential itself.
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
    std::string protocol;  // "ntp" / "dhcp" / "ldap" / "ldaps" / "radius" / "tacacs-plus"
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt if `payload` and the `src_port`/`dst_port` pair don't match any of the six
// port-based Tier 3 protocols this file recognizes (EAPOL, the seventh Tier 3 protocol, has no port
// at all -- see eapol.hpp). Like try_recognize_it_lateral_movement above, every one of these six has
// a FIXED transport (NTP/DHCP/RADIUS are UDP-only, LDAP/LDAPS/TACACS+ are TCP-only) so `is_tcp`
// selects which half of this function even attempts a match. `extra_ports` extends every one of this
// file's own default ports, one shared list across all six -- the same "one feature toggle" grouping
// Tiers 1-2 already established, not six independent option lists.
std::optional<ItEnterpriseTrustMatch> try_recognize_it_enterprise_trust(ByteSpan payload, uint16_t src_port,
                                                                          uint16_t dst_port, bool is_tcp,
                                                                          const std::vector<uint16_t>& extra_ports);

// Exposed narrowly for decoder.cpp's own reassemble_tcp_payload, to resolve a real collision found
// while implementing this: LDAP's own LDAPMessage envelope always begins with a BER SEQUENCE tag,
// byte value 0x30 -- which is bit-for-bit identical to a valid MQTT control-packet-type/flags byte
// (control packet type 3 = PUBLISH, flags all clear), so MQTT's own single-byte opportunistic,
// port-independent declared-length gate (mqtt.hpp) matches every genuine LDAP message purely by
// chance, the same shape of collision Tier 2's own looks_like_ftp_control_line already resolves for
// FTP vs. MQTT (see that function's own comment) -- MQTT's own reassembly probe (tried before this
// file's own Tier 3 dispatch, which only runs once reassembly completes) would otherwise buffer real
// LDAP traffic forever waiting for bytes that will never arrive. See decoder.cpp's own call site for
// the full reasoning; true when `payload` matches this file's own LDAP BER structural check (the
// same one try_recognize_it_enterprise_trust itself uses).
bool looks_like_ldap_ber(ByteSpan payload);

}  // namespace conduitscope
