// SPDX-License-Identifier: Apache-2.0
// rmcp.hpp - RMCP (Remote Management Control Protocol, DMTF/Intel), ASF (Alert Standard Format,
// DMTF), and IPMI (Intelligent Platform Management Interface, Intel/HP/NEC/Dell) -- all three
// decoded from this one file family because RMCP IS the shared UDP-port-623 framing the other two
// ride inside, the same "one family, one file pair" shape docs/PROTOCOL_COVERAGE.md's own
// "RIP / IGMP / VRRP / HSRP" section groups by convention.
//
// WHAT THEY ARE AND WHY THEY'RE IN AN OT/ICS TOOL: these three protocols are the out-of-band (OOB)
// server/BMC ("Baseboard Management Controller") lights-out management stack every rack-mount
// server, and a growing number of industrial rack-mount PCs/edge gateways sitting on the same OT
// network segment as PLCs/HMIs, speaks whether or not anyone asked for it -- a BMC listens on UDP
// port 623 by default, independent of whatever OS or application is running. RMCP is the shared
// 4-byte framing both ASF and IPMI ride inside; ASF is the "is anyone home" discovery/alerting
// layer (Presence Ping/Pong, plus legacy Wake-on-LAN-style power alerts); IPMI is the actual BMC
// management protocol -- remote power control, sensor/event log access, and (via IPMI 2.0/RMCP+)
// an authenticated management session. An OT auditor who finds UDP/623 open on a segment that's
// supposed to be air-gapped from general IT management, or a BMC that accepts IPMI 2.0's infamous
// Cipher Suite 0 (see SECURITY below), has found something worth flagging regardless of what the
// box next to it is actually running.
//
// OUT OF SCOPE, BY THE USER'S OWN EXPLICIT INSTRUCTION FOR THIS PASS: Redfish (DMTF's HTTP/REST
// successor to IPMI, an entirely different transport with no relationship to RMCP framing) and
// vendor-specific lights-out extensions (Dell iDRAC's and HP iLO's own proprietary OEM payloads
// and web UIs) are both explicitly out of scope -- not implemented, not even structurally named
// beyond the generic "RMCP Class: OEM" / IPMI "OEM0-OEM7 payload type" recognition every BMC
// vendor's own traffic would still structurally fall into (see WIRE FORMAT below).
//
// SOURCING: RMCP's own framing (rmcp.c) and ASF's own message-type table (packet-asf.c) are both
// read directly from Wireshark's dissector source
// (github.com/wireshark/wireshark epan/dissectors/packet-rmcp.c, packet-asf.c), which fully
// dissects RMCP's header and ASF's Presence Ping/Pong/message-type enumeration. IPMI's session
// wrapper byte layout (both v1.5 and v2.0/RMCP+) is likewise read directly from
// packet-ipmi-session.c, byte-for-byte (see WIRE FORMAT below for exact offsets, all confirmed
// against that file's own dissect_ipmi_session()). The classic IPMI request/response message shape
// (rsAddr/netFn+rsLUN/checksum1/rqAddr/rqSeq+rqLUN/cmd/data/checksum2) and the curated NetFn/
// Command name tables are read from packet-ipmi.c (do_dissect_ipmb's own byte-by-byte field reads,
// guess_imb_format's own "LAN, no session handle, target-address-only" framing selection -- the
// exact shape a message arrives in once packet-ipmi-session.c has already stripped the session
// wrapper and handed the remainder to the "ipmi" sub-dissector with no bridging context, which is
// what a message riding directly under RMCP/UDP-623 always is) and packet-ipmi-app.c/
// packet-ipmi-chassis.c/packet-ipmi-storage.c/packet-ipmi-transport.c's own `cmd_app`/`cmd_chassis`/
// `cmd_storage`/`cmd_transport` command-name tables.
//
// A GENUINE, DOCUMENTED SOURCING GAP: Wireshark's own packet-ipmi-session.c explicitly declines to
// dissect IPMI 2.0/RMCP+'s own Open Session Request/Response and RAKP Messages 1-4 -- its own
// source comment reads verbatim "All other RMCP+ payload types fall here: session open/close
// requests, RAKP messages, SOL. We cannot parse them yet, thus just output as data." So, UNLIKE
// every other byte layout in this file, this decoder's own Open Session/RAKP field-level breakdown
// (see WIRE FORMAT below) is sourced from the IPMI v2.0 specification directly (Intel/HP/NEC/Dell,
// "IPMI - Intelligent Platform Management Interface Specification, v2.0", sections 13.17/13.18/
// 13.28), the same authoritative-freely-available-standard sourcing tier CoAP's own RFC 7252
// already used in this codebase, cross-checked where possible against two small, stale (and, for
// the Authentication/Integrity Algorithm value_string tables, honestly probably copy-pasted from
// the wrong spec table -- see ALGORITHM VALUES below) fragments that DO survive in packet-asf.c's
// own dissect_asf_open_session_request/response (ASF's OWN, older, now-obsolete "RMCP Security
// Extensions" mechanism, which predates and structurally inspired IPMI 2.0's own Open Session
// design but is NOT the same wire format -- see ASF WIRE FORMAT below for why this decoder does not
// implement ASF's own deprecated Open Session/RAKP-named message types).
//
// ASF's own Presence Pong payload fields (OEM IANA, Supported Entities/Interactions bitmasks) are
// ALSO a sourcing gap in exactly the same shape: packet-asf.c's own dissect_asf() only field-
// decodes Open Session Request/Response (see its own "TODO: Add the rest as captures become
// available to test" comment); every other ASF message type, including Presence Pong, is handed to
// Wireshark's generic hex-dump data dissector. This decoder's own Presence Pong field breakdown is
// therefore sourced from the ASF specification directly (DMTF DSP0136, "Alert Standard Format
// Specification", Section 3.2.4.3), not cross-checked against Wireshark source at all beyond the
// message-type constant (0x40) and the overall 8-byte-header-plus-16-byte-body framing.
//
// SCOPE, DECIDED HERE:
//   - UDP port 623 only. RMCP's own "Secure" variant (RSP, RMCP Security-extensions Protocol, UDP
//     port 664 -- an entirely separate, deprecated 8-byte Session-ID+Sequence wrapper around a
//     second, nested RMCP header, defined in the SAME packet-rmcp.c but registered as its own
//     dissector, "rsp") is named (RMCP_SECURE_UDP_PORT) purely for documentation, the same
//     "named but not decoded" posture coap.hpp's own COAP_DTLS_UDP_PORT already takes for CoAPS --
//     it is rare in real deployments (most IPMI 2.0/RMCP+ implementations use RMCP+'s own
//     session-layer encryption instead of RSP) and out of scope for this pass.
//   - IPMI's own "bridged"/multi-hop framing (a message wrapped inside a Send Message/Get Message
//     command, carrying an extra leading Session Handle byte before the target address -- see
//     guess_imb_format's own IPMI_D_SESSION_HANDLE flag, packet-ipmi.c) is out of scope: every IPMI
//     message this decoder sees arrives directly under an RMCP/IPMI session wrapper with no
//     bridging context (exactly the "channel 0/15, IPMI_E_NONE, IPMI_D_TRG_SA only" shape
//     packet-ipmi-session.c's own handoff to the "ipmi" sub-dissector always produces, confirmed
//     from source), so the classic unbridged 7-byte-header format is the only one this decoder ever
//     needs, or has fixture coverage for.
//   - IPMI 2.0's own confidentiality-encrypted payloads (AES-CBC-128, the algorithm every real
//     Cipher-Suite-3/17 deployment uses) are never decrypted -- this decoder recognizes that a
//     payload is marked Encrypted (the session header's own Payload Type byte, bit 7) and reports
//     its byte length only, the same "leave encrypted payloads opaque" posture this codebase
//     already takes universally (TLS ClientHello-only inspection, WinRM's port 5986, DoH's port
//     443). The Integrity trailer appended to an Authenticated (not necessarily encrypted) IPMI 2.0
//     message is likewise recognized-but-not-verified: its own length depends on the negotiated
//     Integrity Algorithm, itself negotiated once, out-of-band from this decoder's own point of
//     view unless the very Open Session exchange that negotiated it is present in this capture --
//     this decoder does NOT track the negotiated algorithm across a session (see STATEFULNESS
//     below for what it DOES track), so it reports "N trailing byte(s) beyond the declared message
//     length -- likely an Integrity trailer (pad + pad-length + next-header + auth-code), not
//     independently verified" rather than attempting to parse the trailer's own internal shape.
//   - Every NetFn this decoder has EVER seen a real command byte for is at least framed (NetFn
//     name, LUN, raw Command byte); the curated Command-name tables below cover App/Chassis/
//     Storage/Transport only, the exact "curated depth, not exhaustive" posture this codebase's
//     LLDP/CDP TLV tables already established -- any Command byte not in these tables (Bridge,
//     Sensor/Event, Firmware Update, Group, OEM, or an App/Chassis/Storage/Transport command this
//     decoder simply didn't curate) falls back to an honest "NetFn 0xNN, Command 0xNN" numeric
//     rendering, never a guess.
//
// ---------------------------------------------------------------------------------------------
// WIRE FORMAT
//
// RMCP header (packet-rmcp.c dissect_rmcp, byte-for-byte), 4 bytes, immediately at the start of
// every UDP/623 payload:
//   Version(8 bits)   @0  -- 0x06 for every currently-defined RMCP version (ASF/IPMI 2.0 alike;
//                             DSP0136's own numbering carries this fixed value forward from an
//                             earlier pre-standard ASF revision -- there has never been a second
//                             defined value). Wireshark's own dissector does NOT gate on this byte
//                             at all (only the Class nibble below); this decoder deliberately
//                             checks it anyway, as an additional structural constraint -- see
//                             DETECTION/DISPATCH below for the honest strength assessment this
//                             buys.
//   Reserved(8 bits)  @1  -- 0xFF, fixed, per DSP0136. Also checked by this decoder; also not
//                             checked by Wireshark's own dissector.
//   Sequence Number(8 bits) @2 -- an RMCP-layer (not IPMI-session-layer) sequence number, used only
//                             to correlate an RMCP ACK (see Type below) with the message it
//                             acknowledges; not cross-packet-tracked by this decoder (ACKs carry no
//                             payload to correlate against anyway -- see below).
//   byte 3: Type(1 bit, mask 0x80) + reserved(2 bits, mask 0x60, never checked/named) +
//           Class(5 bits, mask 0x1F) -- Type 0 = Normal, 1 = ACK (an ACK carries no data block of
//           its own at all, per dissect_rmcp's own "do not expect a data block for an ACK"
//           comment -- this decoder matches that exactly). Class is RMCP_CLASS_ASF (0x06),
//           RMCP_CLASS_IPMI (0x07), or RMCP_CLASS_OEM (0x08) -- ANY other Class value is, per
//           Wireshark's own dissect_rmcp ("unknown class value; assume it's not RMCP"), NOT RMCP
//           at all, and this decoder's own gate rejects it the same way.
//
// ASF (packet-asf.c dissect_asf), immediately following the 4-byte RMCP header when Class==ASF:
//   IANA Enterprise Number(32 bits, BE) @0 -- 4542 (ASF_RMCP_IANA, DMTF's own number) for every
//                             standard (non-OEM-extended) ASF message.
//   Message Type(8 bits) @4  -- see asf_message_type_name() below for the full, source-confirmed
//                             table (Reset/Power-up/-down/Cycle, Presence Ping/Pong, Capabilities
//                             Request/Response, System State Request/Response, Open/Close Session
//                             Request/Response, and three vestigial "RAKP Message 1/2/3" type
//                             constants -- see ASF's own Open Session/RAKP note below for why these
//                             three are named-only, not the protocol this file's IPMI 2.0/RMCP+
//                             RAKP support decodes).
//   Message Tag(8 bits) @5    -- a client-chosen correlation value for a Ping/Pong pair (echoed by
//                             the Pong); not cross-packet-tracked by this decoder.
//   Reserved(8 bits) @6       -- always 0x00, never checked.
//   Data Length(8 bits) @7    -- byte length of the message-type-specific body immediately
//                             following this 8-byte header.
//
//   ASF Presence Pong (Message Type 0x40) body, 16 bytes (DSP0136 Section 3.2.4.3 -- see the
//   SOURCING note above for why this is spec-sourced, not Wireshark-cross-checked past the type
//   constant): OEM/IANA Enterprise Number(32 bits BE)@0, OEM-defined data(32 bits, opaque)@4,
//   Supported Entities(8 bits)@8 [bit 7 fixed 1 (a DSP0136-mandated marker bit, not a real
//   capability flag), bits 6-4 reserved, bits 3-0 = ASF Version (0001b for ASF 1.0, the only
//   defined value)], Supported Interactions(8 bits)@9 [bit 7 = RMCP Security Extensions (the
//   deprecated RSP mechanism, see SCOPE above) supported, bits 6-0 reserved], Reserved(48 bits,
//   six 0x00 bytes)@10-15.
//
//   ASF's OWN Open Session Request/Response (Message Types 0x83/0x43) and "RAKP Message 1/2/3"
//   (0xC0-0xC2) are ASF's own now-obsolete "RMCP Security Extensions" (RSP) negotiation, a design
//   precursor to -- and wire-format-DISTINCT from -- IPMI 2.0/RMCP+'s own Open Session/RAKP
//   handshake (which rides under RMCP Class=IPMI, IPMI session Payload Types 0x10-0x15, decoded in
//   full below). packet-asf.c's own dissect_asf_open_session_request/response functions DO exist
//   and confirm ASF's own 4-byte Mgt-Console-Session-ID (request) / 1-byte-status+4-byte-Mgt-
//   Console-ID+4-byte-Client-ID (response) framing, but this is a legacy path this decoder does not
//   implement full field decode for -- these six ASF message types are named (asf_message_type_
//   name()) and their raw body bytes are always available, matching Wireshark's own "TODO, not yet
//   captured in the wild" posture for everything past Open Session's outer shape.
//
// IPMI session wrapper (packet-ipmi-session.c dissect_ipmi_session, byte-for-byte), immediately
// following the 4-byte RMCP header when Class==IPMI:
//   Authentication Type(8 bits) @0 -- 0x00 NONE, 0x01 MD2, 0x02 MD5, 0x04 PASSWORD, 0x05 OEM (all
//                             five are IPMI 1.5), 0x06 RMCP+ (IPMI 2.0's own marker value -- any
//                             other value selects the IPMI 1.5 branch below).
//   IPMI 1.5 (AuthType != 0x06): Session Sequence Number(32 bits LE)@1, Session ID(32 bits LE)@5,
//                             [Authentication Code(128 bits/16 bytes, opaque)@9 -- present ONLY
//                             when AuthType != NONE; NEVER rendered by this decoder even when
//                             present, only its presence and fixed 16-byte length noted (matches
//                             CODESYS's own Login-password and LDAP's own bind-password precedent:
//                             a credential-shaped field is a credential-shaped field regardless of
//                             whether it's a literal cleartext password (PASSWORD auth type) or a
//                             computed MD2/MD5 hash (MD2/MD5 auth types) -- this decoder does not
//                             attempt to distinguish the two, since IPMI 1.5's own MD2/MD5 "hash"
//                             is trivially invertible to a session-hijacking-capable value given
//                             the session ID/sequence/challenge also on the wire, so treating it as
//                             equally sensitive is the conservative, correct call], Message
//                             Length(8 bits)@9 or @25 (depending on AuthType, see above), Message
//                             (variable, `Message Length` bytes) immediately following.
//   IPMI 2.0/RMCP+ (AuthType == 0x06): Payload Type(8 bits)@1 [bit 7 = Encrypted, bit 6 =
//                             Authenticated, bits 5-0 = the actual Payload Type value -- see
//                             ipmi_payload_type_name() below for the full table: 0x00 IPMI Message,
//                             0x01 SOL, 0x02 OEM Explicit, 0x10-0x15 the Open Session/RAKP Session-
//                             Setup family this file fully decodes, 0x20-0x27 OEM0-OEM7 (vendor
//                             payloads, out of scope, named only per this file's own top-level
//                             scope note)], then, ONLY when Payload Type == OEM Explicit (0x02):
//                             OEM IANA(32 bits)@2, OEM Payload ID(16 bits)@6 (both shift every
//                             following field 6 bytes later); Session ID(32 bits LE)@2 or @8,
//                             Session Sequence Number(32 bits LE)@6 or @12, Message Length(16 bits
//                             LE)@10 or @16, Message (variable, `Message Length` bytes) immediately
//                             following -- then, iff Authenticated, an Integrity trailer of
//                             unverified length (see SCOPE above).
//
// Classic IPMI request/response message (packet-ipmi.c do_dissect_ipmb, the "LAN, target-address-
// only, no session handle" shape guess_imb_format's own IPMI_D_TRG_SA-only branch selects for a
// message with no bridging context -- exactly what arrives here), 7-byte fixed header + Data +
// 1-byte trailing checksum, immediately as the IPMI session wrapper's own Message region:
//   Responder Address(8 bits) @0    -- "rsAddr"; 0x20 (the BMC's own slave address) on a request.
//   NetFn(6 bits)+Responder LUN(2 bits) @1  -- NetFn's low bit distinguishes Request (even) from
//                             Response (odd, == request NetFn | 1); see netfn_base_name() below.
//   Checksum 1(8 bits) @2    -- two's-complement checksum s.t. (rsAddr + NetFn/rsLUN-byte +
//                             Checksum1) mod 256 == 0 (packet-ipmi.c's own calc_cks -- plain
//                             modular byte summation, verified but never fatal if wrong).
//   Requester Address(8 bits) @3    -- "rqAddr"; the requesting software's own IPMI slave address
//                             (conventionally 0x81 for a remote-console LAN session).
//   RqSeq(6 bits)+Requester LUN(2 bits) @4  -- a request/response correlation sequence number, set
//                             by the requester and echoed by the responder.
//   Command(8 bits) @5       -- see the curated per-NetFn command tables below; NetFn/Command
//                             together select the name.
//   [Completion Code(8 bits) @6, RESPONSES ONLY] -- the first Data byte on a response IS the
//                             completion code (0x00 = success; see ipmi_completion_code_name()
//                             below for the full, source-confirmed standard table); a request has
//                             no completion code at all, Data begins immediately at byte 6.
//   Data(variable)            -- request or response parameter bytes; never protocol-decoded past
//                             the curated command-specific notes this file adds for a small,
//                             named set of commands (Get Channel Authentication Capabilities,
//                             Chassis Control -- see SCOPE above).
//   Checksum 2(8 bits)        -- two's-complement checksum over rqAddr..Data inclusive, same
//                             algorithm as Checksum 1.
//
// IPMI 2.0/RMCP+ Open Session Request (Payload Type 0x10) and Response (0x11), and RAKP Messages
// 1-4 (0x12-0x15) -- see the SOURCING note above for why this whole block is spec-sourced, not
// Wireshark-cross-checked. Every field below is little-endian where multi-byte, matching every
// other multi-byte field in the IPMI 2.0 session wrapper above.
//   Open Session Request: Message Tag(8)@0, Requested Max Privilege Level(4 bits, low nibble)@1,
//     Reserved(24 bits)@2, Remote Console Session ID(32 LE)@4, then three FIXED, always-present,
//     always-in-this-order 8-byte algorithm blocks (Authentication@8, Integrity@16,
//     Confidentiality@24), each shaped Payload Type(8)+Reserved(16)+Payload Length(8,==0x08)+
//     Algorithm(8)+Reserved(24) -- see ALGORITHM VALUES below for the three Payload Type constants
//     (0x00/0x01/0x02) and what each Algorithm byte means. Total 32 bytes, fixed.
//   Open Session Response: Message Tag(8)@0, RMCP+ Status Code(8)@1, Maximum Privilege Level(4 bits
//     low nibble)@2, Reserved(8)@3, Remote Console Session ID(32 LE, echoed)@4, Managed System
//     Session ID(32 LE)@8, then the SAME three fixed 8-byte algorithm blocks @12/@20/@28 -- present
//     only when Status Code == 0 (a failed negotiation has nothing left to agree on); this decoder
//     tolerates a short response (blocks simply absent) rather than treating it as malformed. Total
//     36 bytes when successful.
//   RAKP Message 1: Message Tag(8)@0, Reserved(24)@1, Managed System Session ID(32 LE, echoed from
//     the Response)@4, Remote Console Random Number(128 bits/16 bytes)@8, Requested Max Privilege
//     Level(4 bits low nibble)+Name-Only-Lookup flag(1 bit, mask 0x10)@24, Reserved(16)@25, User
//     Name Length(8)@27, User Name(variable, `User Name Length` bytes, ASCII, NOT a secret -- shown
//     in full, unlike the Auth Code fields elsewhere in this file)@28.
//   RAKP Message 2: Message Tag(8)@0, RMCP+ Status Code(8)@1, Reserved(16)@2, Remote Console
//     Session ID(32 LE, echoed)@4, Managed System Random Number(128 bits)@8, Managed System GUID
//     (128 bits)@24, Key Exchange Authentication Code(variable -- 0/16/20/32 bytes depending on the
//     negotiated Authentication Algorithm; this decoder takes "every byte the session header's own
//     Message Length says remains" rather than tracking the negotiated algorithm across packets,
//     see STATEFULNESS below)@40.
//   RAKP Message 3: Message Tag(8)@0, RMCP+ Status Code(8)@1, Reserved(16)@2, Managed System
//     Session ID(32 LE, echoed)@4, Key Exchange Authentication Code(variable, same rule)@8.
//   RAKP Message 4: Message Tag(8)@0, RMCP+ Status Code(8)@1, Reserved(16)@2, Remote Console
//     Session ID(32 LE, echoed)@4, Integrity Check Value(variable -- 0/12/16 bytes depending on the
//     negotiated Integrity Algorithm, same "take what Message Length says remains" rule)@8.
//
// ALGORITHM VALUES (Open Session Request/Response's own three 8-byte blocks): Payload Type byte is
// 0x00 Authentication / 0x01 Integrity / 0x02 Confidentiality (the fixed order they always appear
// in on the wire; source-confirmed against ipmitool's own widely-mirrored lanplus/rmcp+.h constants
// -- IPMI_AUTHENTICATION_ALGORITHM_PAYLOAD_TYPE/IPMI_INTEGRITY_ALGORITHM_PAYLOAD_TYPE/
// IPMI_CONFIDENTIALITY_ALGORITHM_PAYLOAD_TYPE -- since neither Wireshark's own packet-ipmi-
// session.c nor the IPMI spec text itself was fetchable verbatim by this pass' own tooling; NOT the
// same 0x00/0x01/0x02 meaning as packet-asf.c's own asf_payload_type_vals, which is a DIFFERENT,
// variable-length-list scheme for ASF's own deprecated RSP mechanism, not IPMI 2.0's fixed 3-block
// layout -- see the Open Session Request/Response WIRE FORMAT entries above). Each block's own
// Algorithm byte (see ipmi_auth_algorithm_name()/ipmi_integrity_algorithm_name()/
// ipmi_confidentiality_algorithm_name() below):
//   Authentication: 0x00 RAKP-none, 0x01 RAKP-HMAC-SHA1, 0x02 RAKP-HMAC-MD5, 0x03 RAKP-HMAC-SHA256.
//     0x01 is cross-confirmed from packet-asf.c's own (stale, single-entry) asf_authentication_
//     type_vals table; 0x00/0x02/0x03 are spec-sourced only.
//   Integrity: 0x00 None, 0x01 HMAC-SHA1-96, 0x02 HMAC-MD5-128, 0x03 MD5-128, 0x04
//     HMAC-SHA256-128. 0x01 is likewise cross-confirmed from packet-asf.c's own asf_integrity_
//     type_vals; the rest are spec-sourced only.
//   Confidentiality: 0x00 None, 0x01 AES-CBC-128, 0x02 xRC4-128, 0x03 xRC4-40. Spec-sourced only --
//     packet-asf.c's own tables have no Confidentiality entry at all (ASF's own deprecated RSP
//     predates IPMI 2.0's own encryption support entirely).
//
// SECURITY -- CIPHER SUITE 0 / RAKP-NONE (this decoder's own headline curated finding, matching
// Zerologon for Netlogon/DCSync for DRSUAPI/cleartext creds for LDAP-CONNECT elsewhere in this
// codebase): "Cipher Suite 0" is IPMI 2.0's own name for the algorithm combination Authentication=
// RAKP-none (0x00) + Integrity=None (0x00) + Confidentiality=None (0x00). When a BMC's own Open
// Session RESPONSE accepts an Authentication Algorithm of 0x00 (RAKP-none), NO actual key-exchange
// authentication check ever happens for the rest of that session's own RAKP handshake -- the
// widely-documented CVE-2013-4786-class authentication-bypass finding ("many BMC implementations
// ship with Cipher Suite 0 enabled by default; any password, including one that does not exist,
// authenticates"), because "RAKP-none" is defined BY THE SPEC to mean the Key Exchange
// Authentication Code fields in RAKP Messages 2/3 are simply absent/unchecked, not that a weak
// algorithm is used -- there is no cryptographic check at all. This decoder recognizes it on the
// wire exactly where the spec puts the tell: the Authentication Algorithm byte (0x00) inside either
// the Open Session REQUEST's own Authentication Payload block (a console PROPOSING it) or, more
// significantly, the Open Session RESPONSE's own block (a BMC ACCEPTING it, status code 0 -- the
// actual exploitable condition; a BMC that only ever REJECTS a Cipher-Suite-0 proposal is not
// vulnerable via this path even if a hostile console keeps asking). Both are flagged
// (IpmiFrame::cipher_suite_zero), with the Response-side acceptance called out more strongly in
// this decoder's own summary/notes text -- see try_parse_ipmi's own implementation.
//
// DETECTION/DISPATCH: GateKind::UdpPort, port 623, NOT tried opportunistically on every UDP port in
// Auto mode -- the same conservative, self-determined judgment call CoAP/BSAP already made for
// this codebase, and an honest strength assessment of why: the RMCP header's own gate (Version==
// 0x06 exact byte AND Reserved==0xFF exact byte AND Class-nibble one of exactly 3 values) is
// meaningfully stronger than CoAP's own shortest-message gate (roughly a 1-in-(256*256*(32/3))
// chance of a random 4-byte UDP payload passing by coincidence, versus CoAP's own documented
// roughly 1-in-7) -- comparable in class to BSAP's own "several independently constrained fields"
// gate -- but this decoder is still deliberately NOT tried port-independently: three
// independently-constrained-but-still-single-byte-each fields is a real, if small, false-positive
// surface against an arbitrary 4-byte-or-longer UDP payload on every port in a large capture, and
// RMCP/ASF/IPMI have no other structural property (no magic ASCII string, no protocol-specific
// checksum spanning the whole header) to lean on the way OPC UA's or CODESYS's own multi-field
// magic-plus-length-cross-check gates do. Three separate ProtocolDecoder instances share this one
// port-gated call site (AsfUdpDecoder, IpmiUdpDecoder, RmcpUdpDecoder -- tried in that order, most-
// specific first): AsfUdpDecoder/IpmiUdpDecoder each parse the RMCP header themselves and only
// produce a result when Class matches their own protocol (ASF/IPMI respectively) and Type is
// Normal (not ACK); RmcpUdpDecoder is the generic fallback, producing a result for an RMCP ACK
// (regardless of Class -- an ACK carries no ASF/IPMI payload to hand off to either sibling) or a
// Normal message with Class==OEM (vendor-specific, out of scope past this generic recognition, per
// SCOPE above). No known collision with any other decoder's own UDP port has been found -- 623 is
// not shared with anything else in this codebase.
//
// STATEFULNESS: this decoder uses DecodeContext::flow_state<IpmiFlowState>() (see modbus.hpp's own
// ModbusFlowState / twincat.hpp's own TwinCatFlowState for the established pattern this mirrors),
// keyed by UDP session (direction-independent, the same FlowStateKeying::Session every existing
// flow-state user picks), for exactly ONE thing: remembering, for the rest of that UDP session,
// that an earlier Open Session Request or Response in it proposed/accepted Cipher Suite 0 -- so a
// later RAKP Message 1-4 in the SAME session (which carries no algorithm field of its own to re-
// check) still gets annotated with that same finding, the same way a human reading the whole
// session in order would connect the two. This decoder deliberately does NOT attempt Modbus-
// style/TwinCAT-style authoritative request/response PAIRING for the classic IPMI message level
// (matching a response's own rqSeq/NetFn back to a specific earlier request) -- a documented,
// judgment-call alternative the task itself invites either way: IPMI's own rqSeq/NetFn/Command
// fields are already present directly on every message (unlike Modbus's opaque Transaction ID),
// so a human or a downstream tool reading this decoder's own per-packet output can already
// correlate a request with its response without this decoder doing it for them, and doing so
// properly (tracking outstanding requests, timeouts, NetFn|1 response matching) would add real
// complexity for a correlation an analyst can already do by eye -- unlike Cipher Suite 0's own
// negotiate-once-reference-later shape, which genuinely cannot be recovered from a single packet
// in isolation.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t RMCP_UDP_PORT = 623;
constexpr uint16_t RMCP_SECURE_UDP_PORT = 664;  // RSP -- named for documentation only, see SCOPE.
constexpr uint32_t ASF_RMCP_IANA = 4542;        // DMTF's own IANA Enterprise Number.

// ---------------------------------------------------------------------------------------------
// RMCP

// "ASF" / "IPMI" / "OEM" for the three legal Class values, or nullptr for anything else (an
// unknown Class means the buffer isn't RMCP at all -- see DETECTION/DISPATCH above).
const char* rmcp_class_name(uint8_t class_masked);

struct RmcpHeader {
    uint8_t version_raw = 0;
    uint8_t reserved_raw = 0;
    uint8_t sequence_raw = 0;
    bool is_ack = false;
    uint8_t class_raw = 0;
    const char* class_name = nullptr;
};

// Parses the fixed 4-byte RMCP header only (does not look at anything past it). Returns
// std::nullopt if the buffer is shorter than 4 bytes, Version != 0x06, Reserved != 0xFF, or Class
// is not one of ASF/IPMI/OEM -- see DETECTION/DISPATCH above for why these specific checks.
std::optional<RmcpHeader> try_parse_rmcp_header(ByteSpan udp_payload);

// The generic RMCP result -- an ACK (any Class) or a Normal message with Class==OEM. See
// DETECTION/DISPATCH above for why ASF/IPMI Class values never reach this struct.
struct RmcpFrame {
    RmcpHeader header;
    std::vector<uint8_t> body;  // OEM class only; always empty for an ACK.
    std::string summary;
    std::vector<std::string> notes;
};

class RmcpUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "rmcp"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return RMCP_UDP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};
const ProtocolDecoder& rmcp_udp_decoder();

// ---------------------------------------------------------------------------------------------
// ASF

// The full, source-confirmed ASF Message Type table (packet-asf.c's own asf_type_vals), or nullptr
// for anything else.
const char* asf_message_type_name(uint8_t type_raw);

// ASF Presence Pong's own 16-byte body -- see WIRE FORMAT above for exact byte offsets/sourcing.
struct AsfPresencePong {
    uint32_t oem_iana = 0;
    std::string oem_defined_hex;  // 4 bytes, opaque.
    uint8_t supported_entities_raw = 0;
    uint8_t asf_version = 0;      // low nibble of supported_entities_raw; 1 is the only defined
                                   // value.
    uint8_t supported_interactions_raw = 0;
    bool security_extensions_supported = false;  // bit 7 of supported_interactions_raw.
};

struct AsfFrame {
    uint32_t iana = 0;
    uint8_t message_type_raw = 0;
    const char* message_type_name = nullptr;
    uint8_t message_tag = 0;
    uint8_t data_length = 0;
    std::optional<AsfPresencePong> presence_pong;  // set only for Message Type 0x40.
    std::vector<uint8_t> raw_body;  // every message type's own body bytes, always available --
                                     // fully redundant with presence_pong when that's set, the
                                     // only field available for every other type (see WIRE FORMAT
                                     // above for which types this decoder does vs. doesn't further
                                     // break down).
    std::string summary;
    std::vector<std::string> notes;
};

// Parses `class_payload` (the bytes immediately after RMCP's own 4-byte header) as an ASF message.
// Returns std::nullopt only if `class_payload` is shorter than the fixed 8-byte ASF header itself
// -- a header that parses but whose Data Length overruns the remaining bytes is tolerantly
// truncated with a note, the same "decode what's decodable" posture CoAP's own malformed-option
// handling already established.
std::optional<AsfFrame> try_parse_asf(ByteSpan class_payload);

class AsfUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "asf"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return RMCP_UDP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};
const ProtocolDecoder& asf_udp_decoder();

// ---------------------------------------------------------------------------------------------
// IPMI

const char* ipmi_auth_type_name(uint8_t auth_type_raw);       // IPMI 1.5 session AuthType.
const char* ipmi_payload_type_name(uint8_t payload_type_masked);  // IPMI 2.0 session Payload Type.
const char* ipmi_netfn_base_name(uint8_t netfn_base);          // even (request) NetFn value only.
const char* ipmi_command_name(uint8_t netfn_base, uint8_t command_raw);  // curated App/Chassis/
                                                                          // Storage/Transport only.
const char* ipmi_completion_code_name(uint8_t completion_code);
const char* ipmi_privilege_level_name(uint8_t privilege_raw);  // 4-bit privilege level, shared by
                                                                 // Open Session Request/RAKP1/Get
                                                                 // Channel Auth Capabilities.
const char* ipmi_auth_algorithm_name(uint8_t alg_raw);
const char* ipmi_integrity_algorithm_name(uint8_t alg_raw);
const char* ipmi_confidentiality_algorithm_name(uint8_t alg_raw);
const char* ipmi_rmcpplus_status_code_name(uint8_t status_raw);
const char* ipmi_chassis_control_name(uint8_t control_raw);    // Chassis Control's own low nibble.

struct IpmiSessionHeader {
    uint8_t auth_type_raw = 0;
    const char* auth_type_name = nullptr;
    bool is_v2 = false;  // auth_type_raw == 0x06 (RMCP+).

    // IPMI 2.0/RMCP+ only:
    uint8_t payload_type_raw = 0;
    const char* payload_type_name = nullptr;
    bool payload_encrypted = false;
    bool payload_authenticated = false;
    std::optional<uint32_t> oem_iana;        // Payload Type == OEM Explicit (0x02) only.
    std::optional<uint16_t> oem_payload_id;  // ditto.

    uint32_t session_id = 0;
    uint32_t session_sequence = 0;
    uint32_t message_length = 0;

    // IPMI 1.5 only:
    bool auth_code_present = false;
    size_t auth_code_length = 0;  // NEVER the actual bytes -- see WIRE FORMAT above.

    size_t trailer_length = 0;  // bytes left over after the declared Message region -- an
                                 // Integrity trailer (v2.0, Authenticated) or otherwise-unaccounted
                                 // trailing bytes; never further parsed, see SCOPE above.
};

struct IpmiMessage {
    uint8_t rs_addr = 0;
    uint8_t netfn_raw = 0;
    const char* netfn_name = nullptr;  // from netfn_raw & ~1, see ipmi_netfn_base_name().
    bool is_response = false;          // netfn_raw & 1.
    uint8_t rs_lun = 0;
    uint8_t checksum1_raw = 0;
    bool checksum1_valid = false;
    uint8_t rq_addr = 0;
    uint8_t rq_seq = 0;
    uint8_t rq_lun = 0;
    uint8_t command_raw = 0;
    std::optional<std::string> command_name;
    std::optional<uint8_t> completion_code;  // response only.
    std::optional<std::string> completion_code_name;
    std::vector<uint8_t> data;  // request: all Data bytes; response: Data AFTER the completion
                                 // code byte.
    uint8_t checksum2_raw = 0;
    bool checksum2_valid = false;
};

struct IpmiOpenSessionRequest {
    uint8_t message_tag = 0;
    uint8_t requested_max_privilege_raw = 0;
    std::optional<std::string> requested_max_privilege_name;
    uint32_t remote_console_session_id = 0;
    uint8_t auth_algorithm_raw = 0;
    std::optional<std::string> auth_algorithm_name;
    uint8_t integrity_algorithm_raw = 0;
    std::optional<std::string> integrity_algorithm_name;
    uint8_t confidentiality_algorithm_raw = 0;
    std::optional<std::string> confidentiality_algorithm_name;
    bool is_cipher_suite_zero = false;  // auth_algorithm_raw == 0x00 -- see SECURITY above.
};

struct IpmiOpenSessionResponse {
    uint8_t message_tag = 0;
    uint8_t status_code_raw = 0;
    std::optional<std::string> status_code_name;
    bool algorithms_present = false;  // false when status_code_raw != 0 -- see WIRE FORMAT above.
    uint8_t max_privilege_raw = 0;
    std::optional<std::string> max_privilege_name;
    uint32_t remote_console_session_id = 0;
    uint32_t managed_system_session_id = 0;
    uint8_t auth_algorithm_raw = 0;
    std::optional<std::string> auth_algorithm_name;
    uint8_t integrity_algorithm_raw = 0;
    std::optional<std::string> integrity_algorithm_name;
    uint8_t confidentiality_algorithm_raw = 0;
    std::optional<std::string> confidentiality_algorithm_name;
    bool is_cipher_suite_zero = false;  // algorithms_present && auth_algorithm_raw == 0x00.
};

struct IpmiRakpMessage1 {
    uint8_t message_tag = 0;
    uint32_t managed_system_session_id = 0;
    std::string remote_console_random_number_hex;  // 16 bytes.
    uint8_t requested_max_privilege_raw = 0;
    std::optional<std::string> requested_max_privilege_name;
    bool name_only_lookup = false;
    uint8_t user_name_length = 0;
    std::string user_name;  // NOT a secret -- a username, shown in full; see WIRE FORMAT above.
};

struct IpmiRakpMessage2 {
    uint8_t message_tag = 0;
    uint8_t status_code_raw = 0;
    std::optional<std::string> status_code_name;
    uint32_t remote_console_session_id = 0;
    std::string managed_system_random_number_hex;  // 16 bytes.
    std::string managed_system_guid_hex;            // 16 bytes.
    std::string key_exchange_auth_code_hex;          // variable, see WIRE FORMAT above.
};

struct IpmiRakpMessage3 {
    uint8_t message_tag = 0;
    uint8_t status_code_raw = 0;
    std::optional<std::string> status_code_name;
    uint32_t managed_system_session_id = 0;
    std::string key_exchange_auth_code_hex;
};

struct IpmiRakpMessage4 {
    uint8_t message_tag = 0;
    uint8_t status_code_raw = 0;
    std::optional<std::string> status_code_name;
    uint32_t remote_console_session_id = 0;
    std::string integrity_check_value_hex;
};

struct IpmiFrame {
    IpmiSessionHeader session;
    std::optional<IpmiMessage> message;
    std::optional<IpmiOpenSessionRequest> open_session_request;
    std::optional<IpmiOpenSessionResponse> open_session_response;
    std::optional<IpmiRakpMessage1> rakp1;
    std::optional<IpmiRakpMessage2> rakp2;
    std::optional<IpmiRakpMessage3> rakp3;
    std::optional<IpmiRakpMessage4> rakp4;

    bool cipher_suite_zero = false;  // see SECURITY above and IpmiFlowState below.

    std::string summary;
    std::vector<std::string> notes;
};

// Cross-packet state -- see STATEFULNESS above for exactly what this does and doesn't track.
class IpmiFlowState : public DecoderFlowState {
public:
    bool cipher_suite_zero_seen = false;
};

// Parses `class_payload` (the bytes immediately after RMCP's own 4-byte header) as an IPMI session
// wrapper (+ nested message, when decodable). Returns std::nullopt only if `class_payload` is
// shorter than the shortest legal session header shape (10 bytes: IPMI 1.5, AuthType==NONE). Every
// other structural shortfall (a declared Message Length that overruns the buffer, an unrecognized
// nested payload) is tolerated with a note, matching this codebase's universal "decode what's
// decodable" posture. `flow_state` is optional (nullptr is fine, e.g. from a unit test) -- see
// STATEFULNESS above; when non-null, it is both read (an earlier Cipher-Suite-0 sighting in this
// same session) and updated (a Cipher-Suite-0 sighting THIS call makes).
std::optional<IpmiFrame> try_parse_ipmi(ByteSpan class_payload, IpmiFlowState* flow_state);

class IpmiUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "ipmi"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return RMCP_UDP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};
const ProtocolDecoder& ipmi_udp_decoder();

}  // namespace conduitscope
