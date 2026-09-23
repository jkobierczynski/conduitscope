// SPDX-License-Identifier: Apache-2.0
// winrm.hpp - WS-Management (WinRM) over plaintext HTTP, TCP port 5985. Phase 4 of the Windows
// RPC/remote-management batch (SAMR/LSARPC -> SRVSVC/WKSSVC -> DRSUAPI -> WinRM -> WMI). Unlike
// every protocol in that batch's first three phases, WinRM has NO DCE/RPC involvement at all --
// no dcerpc.hpp, no smb.hpp named pipe, no interface UUID. It is plain SOAP-over-HTTP/1.1: the
// same interactive-remote-shell/remote-management value SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI cover
// for the RPC transport, but for the transport most `Invoke-Command`/`winrs`/`Enter-PSSession`/
// pentest tooling (evil-winrm's plain-CommandLine mode, CrackMapExec's/NetExec's own WinRM module)
// actually uses on the wire today. Built entirely on the ProtocolDecoder registry interface
// (protocol_decoder.hpp) -- no WinRmMessage-shaped dual-write into DecodedPacket's own fields;
// everything rides DecodedPacket::result, the same "zero flat field" shape TwinCAT/Kerberos/LDAP/
// SMB/DRSUAPI already established.
//
// No HTTP parser existed anywhere in this codebase before this file (it_protocols.cpp's own
// match_http is a request-line/status-line SNIFFER only, not a parser -- see that function's own
// comment, now shared into it_protocols.hpp specifically for this file to reuse). This file adds a
// deliberately minimal one: full HTTP/1.1 start-line + header-block parsing (needed to find the
// Content-Length/Transfer-Encoding/Content-Type/Authorization fields this decoder actually cares
// about), but NOT a general-purpose XML parser for the SOAP body -- see "XML EXTRACTION" below.
//
// ---------------------------------------------------------------------------------------------
// WIRE FORMAT
//
// Every WinRM exchange is one HTTP/1.1 request (almost always `POST /wsman HTTP/1.1`) answered by
// one HTTP/1.1 response, both carrying a SOAP 1.2 envelope (`Content-Type: application/soap+xml`)
// as the body -- confirmed empirically against pywinrm (the open-source Python WinRM client;
// installed and read directly -- winrm/protocol.py's Protocol.build_wsman_header/open_shell/
// run_command/etc.) and independently against Microsoft's own MS-WSMV specification (Windows
// Remote Management Protocol, Open Specifications). A single TCP connection is normally reused for
// an entire shell session's worth of exchanges (HTTP keep-alive) -- this decoder is stateless
// regardless (see "STATE" below), since every field this file extracts is self-contained within
// its own message.
//
// The SOAP envelope's header carries `a:Action` (a full URI naming the WS-Transfer/WS-Man
// operation -- e.g. `http://schemas.xmlsoap.org/ws/2004/09/transfer/Create`, or
// `http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command`) and `w:ResourceURI` (which
// remote-management resource the operation targets -- `.../windows/shell/cmd` for a classic
// WinRS cmd.exe shell, a `.../wmi/...`/`.../cim-schema/...` path for a CIM/WMI query, or a
// `.../powershell...` path for PowerShell Remoting -- see "PSRP" below). Once a shell exists, every
// subsequent request addresses it via a `w:SelectorSet/w:Selector Name="ShellId"` header entry
// (the Create RESPONSE returns this same ShellId, also as a `Name="ShellId"` selector, inside its
// own body) -- CommandId, once a command exists, travels differently depending on direction: the
// Command RESPONSE returns it as an element's own text (`<rsp:CommandId>...</rsp:CommandId>`), but
// every later request that references it (Send/Receive/Signal) carries it as an XML ATTRIBUTE
// (`CommandId="..."`) on that request's own body element instead -- two different shapes for the
// same identifier, both handled by this file's own extraction helpers (see winrm.cpp).
//
// A CRITICAL, EMPIRICALLY-CORRECTED DETAIL: this codebase's own original implementation plan
// assumed the CommandLine's Command/Arguments text was base64+UTF-16LE encoded, by analogy with
// other Windows-remoting wire formats already in this codebase (NTLM/SMB2's own UTF-16LE string
// fields). That assumption is WRONG for classic WinRS CommandLine -- verified two independent ways:
// (1) pywinrm's own run_command literally places the command string as plain element text
// (`cmd_line["rsp:Command"] = {"#text": command}`, no encoding step at all); (2) Microsoft's own
// MS-WSMV specification defines the CommandLine type's Command/Arguments fields as plain `xs:string`
// XML Schema elements, with no wire-level encoding beyond ordinary XML text-escaping. This decoder
// therefore XML-unescapes Command/Arguments directly -- no base64 or UTF-16LE decode step exists in
// this file for that field. What genuinely IS base64-encoded per MS-WSMV (verified against the same
// spec section) is I/O STREAM data -- the Send/Receive operations' own `rsp:Stream` element content
// (stdin/stdout/stderr bytes, pre-base64 encoded in the shell's own console codepage, e.g. 437 --
// NOT UTF-16LE either) -- but this decoder deliberately does not decode that content at all; see
// "DELIBERATELY NOT IMPLEMENTED" below for why.
//
// ---------------------------------------------------------------------------------------------
// XML EXTRACTION
//
// The SOAP body is scanned with a handful of small, purpose-built helpers (winrm.cpp, anonymous
// namespace) -- NOT a real XML parser: no element-nesting awareness, no namespace-prefix
// resolution against declared xmlns bindings (a real Windows client's own prefix choices, e.g.
// "a"/"w"/"rsp" vs. pywinrm's own, are irrelevant here -- every lookup matches an element/attribute
// by its LOCAL name only, ignoring whatever prefix precedes the colon), no CDATA/comment handling.
// The same "structural signature, not full grammar" bar this codebase's NTLMSSP token scan
// (ntlm.cpp) and every it_protocols.hpp banner/magic check already accept -- good enough for the
// fixed, small vocabulary of element/attribute names a WS-Man envelope actually uses
// (Action/ResourceURI/Command/Arguments/Filter/Text, and the Name="ShellId"/CommandId="..."
// attribute shapes above). A local-name match requires an exact tag-name boundary (the character
// immediately after the candidate name must be whitespace, '>', or '/') specifically so "Command"
// never accidentally matches inside "CommandId"/"CommandLine"/"CommandState".
//
// ---------------------------------------------------------------------------------------------
// FRAMING / TCP REASSEMBLY
//
// winrm_tcp_declared_length() (winrm.cpp) is a genuinely different shape from every other
// declared-length probe in this codebase's TCP reassembly cascade (Decoder::reassemble_tcp_payload,
// decoder.cpp): Kerberos's 4-byte prefix, LDAP's/SMB's own early length fields, and every other
// protocol here can compute a message's total on-the-wire length from its FIRST few bytes alone.
// HTTP cannot -- the header block's own length is only known once its terminating blank line
// (`\r\n\r\n`) has actually arrived, and a WinRM request's `Authorization: Negotiate <SPNEGO
// token>` header alone can run well past a single ~1460-byte TCP segment (Kerberos/NTLM SPNEGO
// tokens are commonly several KB). So, once the structural gate (a plausible HTTP request-line or
// status-line -- see it_protocols.hpp's own match_http, reused here directly rather than
// duplicated) is satisfied but the header terminator hasn't been seen yet, this function returns
// `candidate.size() + 1` -- a deliberate "ask for exactly one more byte" signal that makes
// Decoder::reassemble_tcp_payload's own generic buffering loop wait for more data and re-probe,
// rather than the nullopt every other protocol here uses to mean "not a match at all". This is
// bounded by that same reassembly loop's existing 16 MiB / 20000-segment safety cap (see
// decoder.cpp's own comment on kMaxBufferedBytes), and by the fact that the very first bytes must
// already look like a genuine HTTP start-line before this decoder ever asks for more -- ordinary
// non-HTTP traffic on a WinRM-configured port is never buffered this way. Once the header block IS
// found: `Transfer-Encoding: chunked` (parsed case-insensitively, matching real-world header
// casing) returns the header block's own length only (the chunked body itself is never
// reassembled -- see "DELIBERATELY NOT IMPLEMENTED"); `Content-Length: N` (also parsed
// case-insensitively) returns header length + N; neither present returns the header length alone
// (an empty-bodied exchange).
//
// ---------------------------------------------------------------------------------------------
// MESSAGE COVERAGE
//
// HTTP layer, every message: method+target (request) or status code+reason (response),
// Content-Type (and whether it's application/soap+xml), Content-Length/chunked framing, and the
// Authorization (request) or WWW-Authenticate (response) header's own auth SCHEME NAME ONLY
// ("Negotiate"/"Basic"/"Kerberos"/"CredSSP") -- the token/credential bytes that follow the scheme
// name are never read into a field at all, so there is no redaction machinery to wire up for this
// one (contrast with command_line below, which genuinely is redacted).
//
// SOAP/WS-Man layer, once a body was actually available to scan (never attempted for a chunked
// message -- see above): Action (full URI) and its own last path segment ("Create"/"CreateResponse"
// /"Command"/"CommandResponse"/"Send"/"Receive"/"Signal"/"Delete"/"Enumerate"/...); ResourceURI, and
// two curated classifications of it (is_cim_query when it names a CIM/WSCIM class path,
// is_psrp when it names a PowerShell Remoting endpoint -- see "PSRP" below); ShellId; CommandId
// (whichever of its two wire shapes -- element text or attribute -- is actually present); the
// CommandLine's own Command+Arguments, joined into one command_line string, XML-unescaped and
// REDACTED BY DEFAULT (see DecodeContext::redact_secrets, decoder.hpp -- `--no-redact` reveals the
// real value, the same opt-in MQTT's own CONNECT password and HSRP's/VRRP's own plaintext auth
// field already established); a WQL Filter string, when an Enumerate operation carries one (the
// literal query text -- a deliberate, narrow exception to "don't decode payload content" for
// exactly the same reason SNMP's own community string is: seeing the query itself is most of this
// feature's audit value, per the plan's "free visibility into modern Get-CimInstance usage"
// framing); and a SOAP Fault's own Reason/Text, when a response is one.
//
// DELIBERATELY NOT IMPLEMENTED, and stated as an honest scope boundary rather than a silent gap
// (the same posture DRSUAPI's own DRS_EXTENSIONS-skipping and DCOM's own planned ResolveOxid note
// already establish elsewhere in this batch):
//   - I/O stream content (stdin bytes sent via Send, stdout/stderr bytes returned via Receive) --
//     genuinely base64-encoded per MS-WSMV (see the correction above), but reassembling it into
//     anything coherent would require correlating potentially many Receive responses across a
//     session, decoding an unspecified console codepage (not UTF-8/UTF-16), and the result is
//     arbitrary command OUTPUT, not the command itself -- out of this pass's scope. This decoder
//     only reports that a Send/Receive happened (with its CommandId), never the stream bytes.
//   - PowerShell Remoting (PSRP, RFC-less, MS-PSRP) -- Invoke-Command/Enter-PSSession/most modern
//     `Get-CimInstance` usage rides an entirely different, deeply nested layered protocol on top of
//     this same WS-Man transport: a ResourceURI naming a PowerShell endpoint, whose body carries
//     its own base64-encoded, binary-framed PSRP fragments (which themselves further encode a
//     .NET-remoting-shaped object stream, with script/command text inside as UTF-16LE -- genuinely
//     the encoding this codebase's original plan mistakenly attributed to plain CommandLine). This
//     decoder recognizes a PSRP-shaped ResourceURI (is_psrp) and says so explicitly, but does not
///    attempt to decode a single byte of the nested PSRP protocol itself.
//   - WS-Man message-level encryption (`Content-Type: multipart/encrypted`, negotiated when the
//     transport auth is NTLM/Kerberos/CredSSP without TLS) -- this decoder still reports the outer
//     HTTP layer (method/status/headers/auth scheme), but the "body" in that case is an encrypted
//     MIME multipart wrapper, not raw SOAP XML, so has_envelope is simply false and no SOAP field
//     is ever populated for it.
//   - Any TLS-wrapped session at all (port 5986) -- out of scope for the same reason RDP/HTTPS's
//     own post-handshake traffic is elsewhere in this codebase; this file only ever sees plaintext
//     HTTP on port 5985.
//
// ---------------------------------------------------------------------------------------------
// CURATED ATTACK/MONITORING NOTES (see winrm.cpp for the exact heuristics)
//   1. Remote shell opened -- fires on a Create RESPONSE that carries a ShellId (not the request,
//      since only a successful response proves a shell actually exists).
//   2. Command executed -- fires on a Command REQUEST that carries a CommandLine (the request is
//      where the command text lives on the wire at all; the response only carries a CommandId).
//      The command_line text in the note is subject to the same redaction as the field itself.
//   3. CIM/WMI query riding WinRM transport -- fires when is_cim_query and a WQL Filter was found.
//   4. PowerShell Remoting endpoint -- fires when is_psrp, stating the scope boundary above.
//   5. HTTP Basic authentication over plaintext WinRM -- fires whenever auth_scheme is "Basic" (this
//      decoder only ever sees plaintext port 5985 traffic in the first place -- see above -- so
//      Basic auth observed here is BY DEFINITION happening in cleartext: base64 is encoding, not
//      encryption, so the credential is trivially reversible to anyone who can see this traffic).
//   6. WS-Man SOAP Fault -- fires whenever has_fault, naming the Reason/Text.
//
// ---------------------------------------------------------------------------------------------
// COLLISION SURVEY / DISPATCH ORDER: WinRM rides ordinary HTTP/1.1 framing, which this codebase's
// own it_protocols.hpp already recognizes name-only, port-independently, as Tier 2's generic "http"
// (try_recognize_it_lateral_movement's own match_http check) -- a genuine collision, confirmed by a
// pinning test (see CMakeLists.txt's winrm_command_not_misdetected_as_generic_http) that this
// traffic decoded as generic "http" before this decoder existed. Resolved by PORT, the same
// resolution this codebase already uses for its other structural-signature-vs-generic-fallback
// collisions (RDP-vs-COTP, FTP/LDAP-vs-MQTT): WinRmTcpDecoder is GateKind::TcpPort (port-gated in
// Auto mode, like DoH -- see protocol_decoder.hpp's own comment on that gate kind), wired into
// decoder.cpp's TCP dispatch chain well ahead of Tier 2's own generic HTTP check, so a real WinRM
// exchange on port 5985 (or a configured extra port) is always claimed by this decoder first;
// ordinary HTTP traffic on any other port is entirely unaffected and still falls through to Tier
// 2's own generic "http" recognition exactly as before.
//
// STATE: none. Every field this file extracts is self-contained within its own HTTP message (a
// ShellId/CommandId that a LATER message references is simply read again from that later message's
// own bytes -- this decoder never needs to remember one message's ShellId to make sense of the
// next), so there is no WinRmFlowState of any kind, unlike DRSUAPI's own bind-bookkeeping map.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// TCP port 5985 -- IANA-registered "wsman", the plaintext WinRM listener. Port 5986 (TLS-wrapped)
// is deliberately out of scope -- see this file's header comment.
constexpr uint16_t WINRM_PORT = 5985;

struct WinRmMessage {
    bool is_response = false;

    // HTTP layer -- always populated (this decoder never returns a result without at least a
    // parsed start-line, see try_parse_winrm_http's own doc comment).
    std::string http_method;       // request only, e.g. "POST"
    std::string http_target;       // request only, e.g. "/wsman"
    uint16_t http_status = 0;      // response only
    std::string http_status_text;  // response only, e.g. "OK" / "Internal Server Error"
    bool has_content_type = false;
    std::string content_type;      // verbatim header value, e.g. "application/soap+xml;charset=UTF-8"
    bool is_soap_xml = false;      // content_type starts with "application/soap+xml" (case-insensitive)
    bool chunked = false;          // Transfer-Encoding: chunked -- body deliberately not reassembled
    bool has_content_length = false;
    size_t declared_content_length = 0;
    bool has_auth_header = false;
    std::string auth_scheme;       // first token of Authorization (request) or WWW-Authenticate
                                    // (response) -- "Negotiate"/"Basic"/"Kerberos"/"CredSSP"/...;
                                    // the token/credential bytes that follow are never read at all

    // SOAP/WS-Man layer -- only ever populated when has_envelope is true (see this file's header
    // comment for exactly when that is).
    bool has_envelope = false;
    std::string wsa_action;        // full Action URI, verbatim
    std::string wsa_action_name;   // its own last '/'-delimited path segment
    std::string resource_uri;
    bool is_cim_query = false;     // resource_uri names a CIM/WSCIM class path
    bool is_psrp = false;          // resource_uri names a PowerShell Remoting endpoint
    bool has_shell_id = false;
    std::string shell_id;
    bool has_command_id = false;
    std::string command_id;
    bool has_command_line = false;
    std::string command_line;      // Command + ' ' + each Arguments value, XML-unescaped, wire
                                    // order; replaced with kRedactedSecretPlaceholder when
                                    // DecodeContext::redact_secrets is true (the default)
    bool has_wql_filter = false;
    std::string wql_filter;        // a WQL Filter element's own text, XML-unescaped
    bool has_fault = false;
    std::string fault_reason;      // a SOAP Fault's own Reason/Text, when present

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `message` as one complete HTTP/1.1 request or response (a start-line, a
// header block, and -- unless chunked -- a Content-Length-bounded body, exactly the shape
// winrm_tcp_declared_length below already measured `message`'s own total length against). Returns
// std::nullopt (never throws) when the very first bytes don't satisfy match_http's own
// request-line/status-line structural check (it_protocols.hpp) -- the same gate
// winrm_tcp_declared_length itself requires before it will even ask decoder.cpp's TCP reassembly to
// keep buffering. `redact`, when true (DecodeContext::redact_secrets's default), masks
// WinRmMessage::command_line with kRedactedSecretPlaceholder both in the field itself and
// everywhere it would otherwise appear in summary/notes text (see protocol_decoder.hpp's
// redact_secret_occurrences).
std::optional<WinRmMessage> try_parse_winrm_http(ByteSpan message, bool redact);

// Returns the total on-the-wire byte count one WinRM/HTTP message declares, or `candidate.size() +
// 1` when more bytes are needed before that can even be determined -- see this file's own "FRAMING
// / TCP REASSEMBLY" header section for the full rationale (a genuinely different shape from every
// other declared-length probe in this codebase). Returns std::nullopt only when `candidate` doesn't
// even begin with a plausible HTTP start-line at all.
std::optional<size_t> winrm_tcp_declared_length(ByteSpan candidate);

// WinRM over TCP/5985 -- id()=="winrm", GateKind::TcpPort (port-gated in Auto mode, like DoH -- see
// protocol_decoder.hpp's own comment on that gate kind and this file's own "COLLISION SURVEY"
// section for why). Stateless (see this file's own "STATE" section) -- ctx is passed only because
// ProtocolDecoder::decode's signature requires one.
class WinRmTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "winrm"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return WINRM_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return winrm_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& winrm_tcp_decoder();

}  // namespace conduitscope
