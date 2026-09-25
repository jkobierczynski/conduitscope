// SPDX-License-Identifier: Apache-2.0
// fox.hpp - Tridium Niagara Fox station protocol (TCP port 1911, cleartext). Port 4911 ("FOXS",
// Fox wrapped in TLS) is a detection-only addition alongside HTTPS/LDAPS -- see this file's own
// "PORT 4911 / FOXS" section below; this file's real decode target is port 1911 only.
//
// WHAT IT IS AND WHY IT'S IN AN OT/ICS TOOL: Niagara (Tridium, a Honeywell subsidiary) is one of
// the most widely deployed building-automation-system (BAS) supervisory platforms -- HVAC,
// lighting, access control, energy metering -- across commercial real estate, government, and
// critical-infrastructure-adjacent facilities. Fox is its native station-to-station/workbench-to-
// station protocol. This protocol has genuine, documented security history: CISA/ICS-CERT
// advisory ICSA-12-228-01A (2012, updated as ICSA-12-228-01A) and an accompanying FBI industry
// warning both center on an unauthenticated system-information-disclosure weakness in the `fox
// hello` exchange (see SECURITY below) -- a weakness a real, publicly available tool
// (`fox-info.nse`, part of Digital Bond's Redpoint Nmap script set) actively exploits today. This
// decoder's whole reason for existing is to make that exchange visible on the wire to a passive
// auditor, the same "make the documented, exploited weakness legible" posture this codebase
// already takes for IPMI's Cipher Suite 0, DICOM's no-identity-negotiation associations, and
// AMQP's cleartext SASL PLAIN credentials.
//
// SOURCING AND CONFIDENCE -- READ THIS BEFORE TRUSTING ANY SPECIFIC BYTE OFFSET BELOW. This
// decoder's wire-format knowledge is condensed from byte-exact analysis of two third-party
// sources, both fetched and read in full for this feature: `fox-info.nse` (Digital Bond Redpoint,
// the tool that actually exploits the `fox hello` weakness against real Niagara stations in the
// wild) and a third-party Wireshark Lua dissector (MartinoTommasini/foxdissector). NEITHER of
// these is the Tridium/Honeywell vendor's own specification (Fox's wire format has never been
// publicly published by Tridium) -- this is reverse-engineered, single-to-double-source material,
// not a standards document. Confidence is marked explicitly at each claim below, and this file
// (and docs/PROTOCOL_COVERAGE.md's own Fox section) preserve that honesty deliberately -- a
// "Medium confidence, single dissector source, not independently cross-checked against a second
// implementation" claim stays marked that way rather than being smoothed into unqualified
// certainty just because it ends up in shipped code:
//   - HIGH confidence, cross-checked by BOTH primary sources: the outer framing (line-oriented
//     ASCII text, terminated by the literal 4-byte sequence `};;\n`, no binary length field
//     anywhere) and the `fox hello` exchange's own real-traffic behavior (SECURITY below).
//   - MEDIUM confidence, single dissector source only, NOT cross-checked against a second
//     independent implementation: the header line's exact field grammar (frame-type char/seq/
//     reply/channel/command) and the tuple value grammar (the eight type-tag encodings: s/i/f/t/
//     z/b/o/m).
//
// FRAMING (HIGH confidence) -- Fox is line-oriented ASCII TEXT, NOT length-prefixed binary. This
// is a genuine departure from every other decoder in this codebase (Modbus/S7comm/DNP3/IEC104/
// EtherNet-IP/... all use an explicit binary length field somewhere in their own outer framing).
// A PDU (frame) looks like:
//   fox <frame-type:1-char> <seq:signed-int> <reply:signed-int> <channel:token> <command:token>\n
//   {\n
//   <zero or more tuple lines, each "key=type:value\n">
//   };;\n
// The terminator is the literal 4-byte sequence `}` `;` `;` `\n` (0x7D 0x3B 0x3B 0x0A). The
// reference Wireshark dissector's own TCP-reassembly strategy -- and this decoder's own
// tcp_declared_length below -- is to scan the accumulating buffer for the 5-byte sequence
// `\n};;\n` (0x0A 0x7D 0x3B 0x3B 0x0A; the leading \n is always present, whether it terminates the
// opening "{\n" line for a zero-tuple frame or the final tuple line) and request more data until
// found.
//
// KNOWN, DOCUMENTED LIMITATION OF THIS FRAMING STRATEGY (inherent to the wire format itself, not
// a bug specific to this decoder -- the reference dissector has the exact same limitation): a
// string-typed (`s:`) tuple value whose own literal content happens to contain the bytes `};;\n`
// would cause a false early terminator match, truncating the frame (and corrupting reassembly of
// whatever legitimate bytes follow) at that point. There is no way to distinguish this from a
// genuine terminator without a proper value-aware parse of every preceding tuple first, which
// tcp_declared_length -- a lightweight, single-pass framing probe reused by
// Decoder::reassemble_tcp_payload for every protocol in this codebase -- deliberately does not
// attempt (see protocol_decoder.hpp's own tcp_declared_length comment: it exists to find PDU
// boundaries cheaply, not to fully parse content). This decoder does not attempt to work around
// this ambiguity with lookahead heuristics beyond what a real implementation would reasonably do;
// it is documented here and in docs/PROTOCOL_COVERAGE.md as an accepted, inherent limitation.
//
// HEADER LINE FIELDS (MEDIUM confidence -- single dissector source):
//   - Frame type (1 char): 'a' Asynchronous, 's' Synchronous, 'k' Keep-alive, 'r' Reply,
//     'e' Error, 'n' F_NULL. Anything else renders as "Unknown (0xNN char)" rather than guessing.
//   - Sequence number: signed decimal integer.
//   - Reply number: signed decimal integer; -1 means "not a reply to anything" (this frame
//     originates an exchange); any other value correlates a reply back to the sequence number it
//     answers. This decoder does NOT attempt cross-packet request/reply pairing by this number --
//     every field this decoder cares about (see SECURITY below) is fully self-contained within a
//     single hello frame, so no flow state is needed at all (this decoder is purely stateless,
//     the same "no DecoderFlowState needed" posture OPC UA/IEC104/BGP already establish).
//   - Channel / command: tokens (e.g. channel "fox", command "hello"). Decoded and shown for
//     every frame; only the "fox"/"hello" pair gets curated, first-class field extraction (see
//     SECURITY below) -- every other channel/command pair (channel/command names observed in the
//     wild beyond "fox"/"hello" are not confirmed by this decoder's own sourcing at all) falls
//     through to the generic tuple decode below, the SAME "decode the structure, don't invent
//     semantics for content that isn't confirmed" posture this codebase already takes for
//     CANopen/POWERLINK SDO object-dictionary values. In particular, `crypto`/
//     `keystore.getCertificates` appears in the reference dissector's own source only as an
//     unverified illustrative code comment, NOT as confirmed real traffic -- this decoder
//     deliberately does not hardcode any special handling for it.
//
// TUPLE VALUE GRAMMAR (MEDIUM confidence -- single dissector source). After the header line and
// the opening "{\n", zero or more `key=type:value\n` tuples, terminated by "};;\n". Type-tag table:
//   s  string   raw text, up to the next '\n'.
//   i  int      decimal digits (optionally signed).
//   f  float    a digit-and-dot run.
//   t  time     hex digits, interpreted as a millisecond count. Rendering below (duration vs.
//               Unix timestamp) is this decoder's own BEST-EFFORT, EXPLICITLY UNCONFIRMED
//               interpretation, not something either source states outright -- see
//               render_fox_time_value's own comment in fox.cpp.
//   z  bool     a single char, 't' or 'f'.
//   b  blob     `<decimal-size>[<raw-bytes>]` -- the raw bytes are never rendered (only their
//               byte count), the same "don't render opaque bytes" posture DICOM's own Pixel Data
//               handling already establishes.
//   o  object   `<type-token> <decimal-size>[<raw-bytes>]` -- likewise, only the type-token and
//               byte count are rendered.
//   m  message  a recursive nested `{\n <tuples> }\n` block (note: closed by a PLAIN "}\n", not
//               the outer PDU's own "};;\n" terminator). Recursion is bounded by
//               resource_limits().max_recursion_depth (default 16, the same default AMQP/LDAP/
//               S7comm-Plus already use for their own unrelated nesting caps) -- reaching the cap
//               honestly stops tuple extraction for the rest of THIS frame (a
//               DicomDataSet::stopped_reason-shaped honesty note, not a guess at what follows) but
//               does not lose the frame's own already-known wire length (found independently by
//               the raw terminator byte-scan both tcp_declared_length and try_parse_fox_pdu use),
//               so coalescing/reassembly of whatever comes after this frame is unaffected.
//   An unrecognized type-tag char cannot be safely skipped (there is no way to know where its
//   value ends without understanding its own framing), so encountering one likewise honestly stops
//   tuple extraction for the rest of the frame, the same "stop, don't guess" posture as the
//   recursion cap above.
//   KNOWN, UNCONFIRMED ASSUMPTION (flagged honestly, single-source material): the blob/object
//   `<decimal-size>` field is read as a run of ASCII '0'-'9' bytes with NO delimiter before the
//   raw bytes that follow -- if a real blob/object's own raw content happens to begin with an
//   ASCII digit, this would misread part of that content as more of the size field. Neither
//   source this decoder was built from specifies a delimiter here; this is this decoder's own
//   best-effort reading of the documented shape, not a confirmed wire detail.
//
// SECURITY -- THE `fox hello` EXCHANGE, THIS DECODER'S CORE VALUE (HIGH confidence, real traffic,
// FBI/CISA-documented, actively exploited by `fox-info.nse` today): a client sends
// `fox a <seq> -1 fox hello` with a payload block describing ITS OWN identity (fox.version, id,
// hostName, hostAddress, app.name, app.version, vm.name, vm.version, os.name, os.version, lang,
// timeZone, hostId, vmUuid, brandId -- all s:/i:-typed). A REAL NIAGARA STATION ANSWERS ANY
// SYNTACTICALLY VALID HELLO FRAME FROM ANY UNAUTHENTICATED TCP PEER WITH A FULL DUMP OF THE SAME
// FIELD SET DESCRIBING ITSELF -- no session, no login, no credential check precedes this. This
// decoder extracts these fourteen named fields into FoxHelloFields (structured, first-class
// output) for ANY frame whose channel/command is exactly "fox"/"hello", in EITHER direction
// (request or reply) -- matching how e.g. this codebase's DICOM A-ASSOCIATE-RQ/AC or its AMQP
// connection.start get first-class treatment while every other message type on the same protocol
// stays generic. Because no authentication mechanism is decoded by this pass AT ALL (see AUTH
// below), every hello exchange this decoder observes IS, by construction, unauthenticated -- the
// simplest reliable signal for this decoder's own headline --stats finding (see
// docs/PROTOCOL_COVERAGE.md and output.cpp's write_packet/print_summary "fox" sections):
//   *** Fox hello exchanges observed (unauthenticated system-identity disclosure) N ***
//
// SECURITY -- SECONDARY, HOSTADDRESS-VS-PEER-IP MISMATCH: a hello frame's own hostAddress field
// describes the address the SENDER believes is its own -- when that differs from the actual TCP
// source IP address this packet was captured carrying, it's a mild internal-topology-leakage
// signal (NAT, multi-homing, or a stale/misconfigured hostAddress). This decoder does NOT compute
// this comparison itself (FoxResult/FoxFrame carry no notion of the carrying packet's own IP
// addresses -- this decoder is handed only the TCP payload bytes, the same scope every
// ProtocolDecoder::decode() call has); decoder.cpp's own Fox call site does the comparison (it
// already has out.src_ip in scope, the same information the DICOM/MELSEC/etc. call sites already
// use for their own "not a configured/standard port" notes) and output.cpp's own stats-counting
// pass does the matching --stats tally, mirroring exactly how DICOM's own dicom_no_identity_count_
// is computed from DecodedPacket-level information rather than inside dicom.cpp itself.
//
// CREDENTIALS / REDACTION: no credential material is confirmed to appear anywhere in the `fox
// hello` exchange -- every field involved is identity/environment metadata (version strings,
// hostnames, OS/JVM info), not a secret -- so this decoder does NOT apply
// redact_secret_occurrences/kRedactedSecretPlaceholder to any hello field, unlike e.g. HSRP/VRRP's
// own plaintext authentication fields. A SEPARATE Fox authentication mechanism (n4digest/
// SCRAM-SHA) is confirmed to EXIST BY NAME in this decoder's own research material, but its
// wire-level frame format could not be sourced from either reference used here -- this decoder
// does NOT attempt to decode or guess at an auth frame's structure; any channel/command that looks
// credential-related, encountered during this feature's own testing, is a generic, undecoded tuple
// frame like any other unrecognized channel/command (see docs/DEVELOPMENT.md's Fox entry for
// whether one was actually observed during this feature's own fixture/testing work).
//
// PORT 4911 / FOXS (Fox wrapped in TLS): NOT a decode target for this decoder at all -- FOXS's
// payload is TLS-encrypted, exactly as opaque to a passive capture as HTTPS/LDAPS-over-TLS already
// are elsewhere in this codebase. decoder.cpp's existing generic TLS-ClientHello recognition call
// site (the same one that already labels port 443 "https" and ports 636/3269 "ldaps") is extended,
// as a small, low-risk addition, to also recognize port 4911 and label it "FOXS/TLS ClientHello" --
// see that call site's own comment for the exact, LDAPS-mirroring shape this takes. FOX_TLS_PORT
// below is that detection's only port constant; it is NOT part of GateKind::TcpPort dispatch (the
// real FoxDecoder below never runs against port 4911 traffic) and has no --extra-fox-tls-ports
// widening of its own, the same "small addition, not a new fully-general feature" scope this file
// keeps throughout.
//
// DETECTION/DISPATCH: GateKind::TcpPort, port-gated in Auto mode (TCP port 1911) -- the same
// posture DICOM/WinRM/DCOM/GE SRTP/AMQP already establish for this gate kind: Fox's own structural
// gate (the literal 4-byte "fox " prefix, checked by tcp_declared_length below before any
// buffering/terminator-scanning is attempted at all) is a real but not magic-constant-strength
// signal on its own (a 4-byte ASCII prefix, unlike e.g. OPC UA's own 3-byte-from-7-fixed-strings
// allowlist or BGP's 128-bit all-0xFF Marker), so trying it opportunistically on every TCP payload
// in Auto mode would risk false-positiving on ordinary text-ish binary traffic elsewhere -- exactly
// the same "port-gate a real-but-not-magic-strength gate in Auto mode" reasoning GE SRTP's own file
// header comment documents for its own comparably-shaped gate. An explicit `--protocol fox` still
// tries it port-independently, the same exception every other GateKind::TcpPort protocol in this
// codebase already has. `--fox-port` (DecodeOptions::extra_fox_ports) widens beyond port 1911, the
// same "additional expected ports" convention every other extra_*_ports list already has.
//
// STATEFULNESS: none. Every field this decoder extracts (generic tuples, and the curated hello
// fields) is fully self-contained within a single frame's own bytes -- there is no cross-packet
// request/reply correlation this decoder needs to perform (the reply/seq numbers are decoded and
// shown, never used to drive any lookup). FoxDecoder is purely stateless, the same posture OPC
// UA/IEC104/BGP already establish for this interface.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t FOX_PORT = 1911;      // Fox cleartext -- this decoder's real, only decode target.
constexpr uint16_t FOX_TLS_PORT = 4911;  // FOXS (Fox-over-TLS) -- detection only, see this file's
                                           // own "PORT 4911 / FOXS" section above; never reaches
                                           // FoxDecoder::decode at all.

// One decoded name=type:value tuple. `nested` is populated only for type_raw=='m' (a recursive
// nested message); `rendered` is populated for every other recognized type and left empty for 'm'
// (the nested tuples ARE the rendering). Both are left at their defaults for a tuple whose own
// type tag this decoder didn't recognize, or one buried past a stopped_reason -- see FoxFrame's
// own stopped_reason.
struct FoxTuple {
    std::string key;
    char type_raw = 0;
    std::string type_name;  // "string"/"int"/"float"/"time"/"bool"/"blob"/"object"/"message", or
                              // "Unknown (0xNN char)" for an unrecognized type tag.
    std::string rendered;
    std::vector<FoxTuple> nested;  // type_raw == 'm' only.
};

// Curated, first-class field extraction for a `fox hello` frame -- see fox.hpp's own SECURITY
// section above. Populated ONLY when FoxFrame::is_hello is true; every field is optional because
// a real hello frame observed during this feature's own scoping does not necessarily carry every
// one of these (this decoder never invents a value for a field that wasn't actually present on
// the wire). Every field is stored as its own rendered string regardless of whether its own wire
// type tag was 's' or 'i' -- these are identity/display fields, not values this decoder does
// arithmetic on.
struct FoxHelloFields {
    std::optional<std::string> fox_version;
    std::optional<std::string> id;
    std::optional<std::string> host_name;
    std::optional<std::string> host_address;
    std::optional<std::string> app_name;
    std::optional<std::string> app_version;
    std::optional<std::string> vm_name;
    std::optional<std::string> vm_version;
    std::optional<std::string> os_name;
    std::optional<std::string> os_version;
    std::optional<std::string> lang;
    std::optional<std::string> time_zone;
    std::optional<std::string> host_id;
    std::optional<std::string> vm_uuid;
    std::optional<std::string> brand_id;
};

struct FoxFrame {
    char frame_type_raw = 0;
    std::string frame_type_name;  // "Asynchronous"/"Synchronous"/"Keep-alive"/"Reply"/"Error"/
                                    // "F_NULL", or "Unknown (0xNN char)".
    int64_t seq = 0;
    int64_t reply = 0;
    bool is_reply = false;  // reply != -1 -- see fox.hpp's own HEADER LINE FIELDS section.
    std::string channel;
    std::string command;
    std::vector<FoxTuple> tuples;  // top-level tuples only; see FoxTuple::nested for 'm' children.
    size_t wire_length = 0;        // this frame's own total byte length, including the "};;\n"
                                     // terminator -- found independently of tuple-level parsing
                                     // (a raw byte scan, same one tcp_declared_length uses), so it
                                     // stays known even when stopped_reason below is set.

    bool is_hello = false;  // channel == "fox" && command == "hello" -- see SECURITY above.
    std::optional<FoxHelloFields> hello;  // set only when is_hello is true.

    // Set when tuple-level extraction stopped early (an unrecognized type tag, or the nested-'m'
    // recursion cap) -- the same DicomDataSet::stopped_reason-shaped honesty this decoder borrows
    // from dicom.hpp: `tuples` holds whatever was successfully decoded before the stop, wire_length
    // is still correct, and this string says why extraction didn't go further.
    std::optional<std::string> stopped_reason;

    std::string summary;
    std::vector<std::string> notes;
};

// One decoded TCP payload's worth of Fox traffic -- `first` is the primary frame this
// DecodedPacket's own summary/notes/JSON fields render from; any further frame coalesced into the
// same TCP payload (back-to-back keep-alives in particular are plausible) is folded into `notes`
// as its own one-line summary, the same DicomResult/MqttResult coalescing-loop shape dicom.hpp/
// mqtt.hpp already establish.
struct FoxResult {
    FoxFrame first;
    std::string summary;
    std::vector<std::string> notes;
};

// Renders a 'v' (frame-type) raw char into its curated name, or "Unknown (0xNN char)" -- never
// nullptr, always succeeds.
std::string fox_frame_type_name(char frame_type_raw);

// Parses exactly ONE Fox frame starting at the beginning of `candidate`. Returns std::nullopt when
// `candidate` doesn't begin with the literal 4-byte "fox " magic, or no "\n};;\n" terminator is
// found anywhere within `candidate` at all (this function is only ever meaningfully called once
// tcp_declared_length has already confirmed a terminator is present within the bytes handed to
// it -- see FoxDecoder::decode), or the header line / tuple structure up to that terminator fails
// to parse. Never throws.
std::optional<FoxFrame> try_parse_fox_pdu(ByteSpan candidate);

// Two-phase declared-length probe (the same shape amqp091_tcp_declared_length/
// dicom_tcp_declared_length already establish) for Decoder::reassemble_tcp_payload's own
// cross-TCP-segment PDU reassembly -- see this file's own FRAMING section for the exact terminator-
// scan strategy this implements. Returns std::nullopt only when `candidate` does not begin with
// the literal "fox " magic (definitely not a Fox frame at all); returns `candidate.size() + 1`
// (the standard "ask for one more byte, keep buffering" idiom this codebase's other declared-
// length probes already use) when the magic matches but no terminator has been found yet; returns
// the exact byte offset immediately past the terminator once one is found.
std::optional<size_t> fox_tcp_declared_length(ByteSpan candidate);

class FoxDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "fox"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return FOX_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return fox_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& fox_tcp_decoder();

}  // namespace conduitscope
