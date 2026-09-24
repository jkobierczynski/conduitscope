// SPDX-License-Identifier: Apache-2.0
// coap.hpp - CoAP (Constrained Application Protocol, RFC 7252) decoding -- UDP port 5683.
//
// WHAT IT IS AND WHY IT'S IN AN OT/ICS TOOL: CoAP is a lightweight, RESTful (GET/POST/PUT/DELETE)
// application protocol designed for constrained devices and lossy networks -- the IoT/IIoT
// analogue of HTTP, over UDP instead of TCP. It shows up in this project's OT/ICS auditing scope
// the same way MQTT already does: as one of the IoT-adjacent protocols an increasing number of
// field sensors, actuators, and building/industrial-automation gateways speak alongside (or
// instead of) classic fieldbus protocols, particularly in newer IIoT and smart-building
// deployments this tool's audience is increasingly asked to assess.
//
// SOURCING: unlike this codebase's recent additions (BSAP, GE SRTP, CODESYS), which all needed
// third-party reverse-engineering because no public vendor spec exists, CoAP is a single,
// authoritative, freely available IETF standard -- RFC 7252 (June 2014) -- cross-checked against
// IANA's own "Constrained RESTful Environments (CoRE) Parameters" registry
// (iana.org/assignments/core-parameters) for the Method/Response Code, Option Number, and
// Content-Format tables. This is a meaningfully stronger sourcing position than CC-Link IE's own
// (which itself was strong enough to decide scope in code rather than ask), so the scope
// decisions below were likewise made and documented here rather than raised as an
// AskUserQuestion.
//
// SCOPE, DECIDED HERE (self-determined, not asked -- see SOURCING above):
//   - UDP only (RFC 7252's own base transport). CoAP-over-TCP/TLS/WebSockets (RFC 8323) uses an
//     entirely different, length-prefixed framing (no fixed 4-byte header, no Message ID, a
//     different Code-class-7 "Signaling" message family for CSM/Ping/Pong/Release/Abort) and is
//     explicitly out of scope for this first pass -- a separate future item if it turns out to
//     matter in practice, not a design constraint of anything below.
//   - CoAPS (DTLS-secured CoAP, conventionally UDP port 5684) is out of scope past generic
//     recognition -- its payload is opaque ciphertext, the same limit this codebase's own
//     TLS-wrapped-port decisions already draw elsewhere (WinRM's port 5986, DoH's port 443).
//     COAP_DTLS_UDP_PORT is named below purely for documentation; this decoder does not attempt
//     to identify DTLS-wrapped CoAP traffic at all.
//   - Every option, Method/Response Code, and Content-Format defined by the base RFC 7252, plus
//     RFC 7641 (Observe) and RFC 7959 (Block1/Block2/Size2 blockwise transfer), is named and,
//     where the option's own Format is string/uint, value-decoded. These two companion RFCs were
//     folded in alongside the base spec because their options are near-ubiquitous in real CoAP
//     deployments (Observe-based subscribe/notify and blockwise transfer of larger payloads are
//     both extremely common), are themselves single-sourced stable IETF standards, and add no
//     real implementation risk (Observe is a 0-3 byte uint; Block1/Block2/Size2 are likewise
//     uint-format options with a well-defined internal bit-packing, decoded below). Every other
//     IANA-registered option not in this set (OSCORE, Hop-Limit, Q-Block1/Q-Block2, EDHOC, Echo,
//     No-Response, Request-Tag, and any future registration) falls back to an honest "option NNN
//     (raw hex, N byte(s))" structural rendering -- the option's own number/length is always
//     decoded correctly (this decoder walks the full option chain regardless of which options it
//     can name), only the value interpretation is left generic, the same "structural fallback for
//     an unrecognized-but-well-formed field" posture MELSEC's own unrecognized-command handling
//     and CC-Link IE's own generic-error-response path already use.
//   - The payload itself (after the 0xFF marker, if present) is never decoded. Content-Format
//     (when present) is named, and the payload's byte length is reported, but the payload BODY is
//     always a separate, generic serialization format (text/plain, JSON, CBOR, link-format,
//     application-specific binary, ...) with no protocol-specific structure of CoAP's own to
//     decode -- the same "declined, too generic, no OT-specific structure" reasoning already
//     applied to OPC Classic (declined outright, docs/DEVELOPMENT.md) and to CC-Link IE's own
//     RWw/RWr/RY/RX fields (reported as raw byte counts, never interpreted as typed device
//     values).
//   - No cross-packet session state. Every CoAP message (request or response) is decoded
//     independently; this decoder does not track Message-ID-based Confirmable/Acknowledgement
//     matching (CoAP's own "Message Layer") or Token-based request/response correlation across
//     packets (CoAP's own "Request/Response Layer") -- an explicit, honestly stated limitation
//     rather than a silent gap, the same stateless posture BSAP's and HART-IP's own decoders
//     already have in this codebase. A future pass could add Token-keyed flow state to annotate a
//     response with which request (method + URI) it answers, the same shape CC-Link IE's own
//     session-scoped response matching already demonstrates -- not built here to keep this first
//     pass' scope tight.
//
// ---------------------------------------------------------------------------------------------
// WIRE FORMAT (RFC 7252 Section 3, cross-checked against the RFC's own byte diagram):
//
// Fixed 4-byte header, immediately at the start of every CoAP UDP payload, all multi-byte fields
// big-endian:
//   Ver(2 bits)   -- CoAP version; RFC 7252 requires this to be exactly 1 (binary 01).
//                     Anything else is rejected outright by this decoder's own structural gate
//                     (see DETECTION/DISPATCH below) -- not a "some other CoAP version" case,
//                     since no other version has ever been defined.
//   Type(2 bits)  -- 0=Confirmable (CON), 1=Non-confirmable (NON), 2=Acknowledgement (ACK),
//                     3=Reset (RST).
//   TKL(4 bits)   -- Token Length, 0-8. Values 9-15 are reserved and, per the RFC, "MUST be
//                     processed as a message format error" -- this decoder rejects the whole
//                     message (falls through to generic [udp]) rather than guessing at a
//                     malformed decode, the same "don't fabricate structure from an invalid
//                     field" posture CODESYS's own Services-header validation already uses.
//   Code(8 bits)  -- split into a 3-bit class and 5-bit detail, conventionally written "c.dd".
//                     Class 0 = a request Method Code (0.00 is reserved as "Empty", used only for
//                     bare CON/NON/ACK/RST keepalive/ping/reset messages with no token, no
//                     options, no payload); classes 2/4/5 = a Response Code (Success/Client
//                     Error/Server Error); class 7 = Signaling (RFC 8323, CoAP-over-TCP only --
//                     out of scope per SCOPE above, shown raw/unnamed if ever seen on UDP, which
//                     would itself be anomalous); classes 1, 3, 6 are reserved by the RFC and
//                     never named.
//   Message ID(16 bits) -- used by the Message Layer to detect duplication and match CON with its
//                     own ACK/RST; not correlated across packets by this decoder (see SCOPE).
//
// Token: TKL bytes immediately following the header, a client-chosen opaque correlation value
// (RFC 7252 Section 5.3.1) -- not secret, not a credential, rendered as hex.
//
// Options: a sequence of Option Delta/Option Length encodings (RFC 7252 Section 3.1). Each
// option starts with one byte split into two 4-bit nibbles:
//   Option Delta nibble  -- added to the running total of all previous option numbers (starting
//                            at 0) to get this option's own Option Number; values 0-12 are the
//                            delta directly, 13 means "read one more byte, an 8-bit unsigned
//                            integer, and add 13 to it", 14 means "read two more bytes, a 16-bit
//                            unsigned integer network byte order, and add 269 to it", and 15 is
//                            reserved -- it is used ONLY as part of the Payload Marker (see
//                            below); any other appearance of nibble value 15 is a message format
//                            error.
//   Option Length nibble -- same 0-12/13/14 extension scheme as the delta nibble (add 13 or 269
//                            respectively) for the option's own value length in bytes; value 15
//                            is reserved and, per the RFC, "MUST be processed as a message format
//                            error" if it appears anywhere other than as part of the Payload
//                            Marker.
// Options MUST appear in strictly increasing Option Number order on the wire (this is how the
// delta encoding works at all) -- this decoder does not re-sort or validate strict increase
// beyond what the delta encoding itself enforces by construction.
//
// Payload Marker: the single byte 0xFF (i.e. both nibbles equal to 1111) appearing where an
// option's own Delta/Length byte would otherwise be expected marks the end of options -- every
// remaining byte is the payload. Per the RFC, a Payload Marker followed by zero further bytes is
// itself a message format error ("MUST be processed as one"), not an empty payload -- this
// decoder stops decoding options and adds a note in that case rather than fabricating an
// empty-payload result.
//
// A malformed option (nibble value 15 used outside the Payload Marker, a declared Option Length
// that overruns the remaining bytes, or any other structural violation of the rules above) stops
// this decoder's own option walk with a note describing what went wrong, but does NOT discard the
// header/token/options already successfully decoded -- the same "decode what's decodable, note
// the anomaly, don't fabricate the rest" posture this codebase's own CODESYS/BACnet/GE-SRTP
// decoders already use for their own malformed-input paths.
//
// ---------------------------------------------------------------------------------------------
// DETECTION/DISPATCH: GateKind::UdpPort, port 5683 (conventional CoAP port), NOT tried
// opportunistically on every UDP port. This is a deliberate, conservative, self-determined
// judgment call: a minimal CoAP message can be as short as 4 bytes (an Empty Code 0.00 message
// with TKL=0, no options, no payload -- used for pings/keepalives and bare ACK/RST), and this
// decoder's own strongest structural checks on such a message (Ver==1, a 2-bit field; TKL<=8, a
// 4-bit field) narrow a random 4-byte UDP payload's chance of a false positive only to roughly
// 1-in-7, nowhere near the "astronomically unlikely by chance" bar CODESYS's and CC-Link IE's own
// UdpPortIndependent gates document for their own multi-independently-constrained-field headers.
// A message carrying options and/or a payload does structurally validate much more strongly (the
// whole remaining buffer must consume exactly, with no leftover bytes, via the option-chain
// walk), but this decoder does not attempt a "port-independent for long messages, port-gated for
// short ones" split -- BSAP/RIP/HSRP/DNS/mDNS/LLMNR/NBT-NS all already draw the same UdpPort line
// for exactly this class of "the header alone is too weak a signal" reasoning, and CoAP's own
// shortest legal messages are weaker still than any of those.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t COAP_UDP_PORT = 5683;
constexpr uint16_t COAP_DTLS_UDP_PORT = 5684;  // named for documentation only -- see SCOPE above.

// Returns the message Type name (CON/NON/ACK/RST) for a 2-bit Type field value (0-3, always
// named -- all four values are defined).
const char* coap_type_name(uint8_t type_raw);

// Returns the Code class name ("Method", "Success", "Client Error", "Server Error", "Signaling",
// or nullptr for a reserved/unused class) for the 3-bit class extracted from a Code byte.
const char* coap_code_class_name(uint8_t code_class);

// Returns the specific named Method/Response Code (e.g. "GET", "Content", "Not Found") for an
// exact Code byte match against the RFC 7252/RFC 7959/RFC 8132/RFC 8516/RFC 8768 tables this
// decoder knows, or nullptr if the Code byte isn't one of them (shown as raw "c.dd" only).
const char* coap_code_name(uint8_t code_raw);

// Returns the Option name (e.g. "Uri-Path", "Content-Format") for a known Option Number, or
// nullptr for one this decoder doesn't name (see SCOPE above) -- always structurally decoded
// (number + length + raw bytes) either way.
const char* coap_option_name(uint16_t option_number);

// Returns the Content-Format media-type string (e.g. "application/json") for a known
// Content-Format numeric ID, or nullptr for one this decoder doesn't name.
const char* coap_content_format_name(uint16_t content_format_id);

// One decoded CoAP option: number/name (name empty if unrecognized), raw value bytes, and --
// only for options this decoder knows the RFC 7252 Section 5.10 Format of -- a decoded string or
// uint rendering. `decoded_text`/`decoded_uint` are both unset for an "opaque" or "empty" format
// option, or for one this decoder doesn't name at all (its raw bytes are always available via
// `value`).
struct CoapOption {
    uint16_t number = 0;
    std::optional<std::string> name;  // unset if `number` isn't in coap_option_name's table.
    std::vector<uint8_t> value;
    std::optional<std::string> decoded_text;   // set for string-format named options.
    std::optional<uint64_t> decoded_uint;      // set for uint-format named options.
};

struct CoapFrame {
    uint8_t version_raw = 0;
    uint8_t type_raw = 0;
    const char* type_name = nullptr;
    uint8_t token_length_raw = 0;
    std::string token_hex;  // empty when token_length_raw == 0.

    uint8_t code_raw = 0;
    uint8_t code_class = 0;
    uint8_t code_detail = 0;
    const char* code_class_name = nullptr;
    std::optional<std::string> code_name;  // set for an exact Code-byte match; "c.dd" always
                                            // available via code_class/code_detail regardless.
    bool is_empty_message = false;         // Code == 0.00 -- see WIRE FORMAT above.

    uint16_t message_id = 0;

    std::vector<CoapOption> options;
    std::optional<uint16_t> content_format_id;      // cross-referenced from a Content-Format
    std::optional<std::string> content_format_name;  // option, if present, for convenience.
    std::optional<uint64_t> observe_value;  // cross-referenced from an Observe option, if
                                             // present -- RFC 7641: value 0 registers a new
                                             // observation, any other value (or the option's mere
                                             // presence on a response) is a notification.
    bool observe_register = false;          // true when observe_value is present and == 0.

    bool payload_present = false;
    size_t payload_length = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as a CoAP message. Returns std::nullopt (never throws) if
// the buffer is shorter than the fixed 4-byte header, if Ver != 1, or if TKL is a reserved value
// (9-15) or the token itself would run past the end of the buffer -- see DETECTION/DISPATCH
// above for why these specific checks (and no stronger ones) are what gates this decoder's own
// UdpPort dispatch. A malformed option chain past a structurally valid header+token does NOT
// return std::nullopt -- see WIRE FORMAT above.
std::optional<CoapFrame> try_parse_coap(ByteSpan udp_payload);

// registration-model ProtocolDecoder wrapper -- no cross-packet state (see SCOPE above), so this
// needs nothing beyond id()/gate_kind()/udp_port()/decode(); see coap.cpp.
class CoapUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "coap"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return COAP_UDP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& coap_udp_decoder();

}  // namespace conduitscope
