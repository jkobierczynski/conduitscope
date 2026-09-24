// SPDX-License-Identifier: Apache-2.0
// amqp091.hpp - AMQP 0-9-1 (Advanced Message Queuing Protocol, the OASIS-adjacent AMQP Working
// Group's own final 0-9-1 revision, popularized and still primarily driven by RabbitMQ) -- TCP
// port 5672 (shared with AMQP 1.0, see amqp_common.hpp for the shared connection-preamble
// detection this file's own per-session dispatch relies on).
//
// WHAT IT IS AND WHY IT'S IN AN OT/ICS TOOL: AMQP 0-9-1 is a general-purpose message-queuing wire
// protocol -- not an OT/ICS protocol on its own -- but it is exactly the class of "IT protocol an OT
// auditor flags" this codebase already builds a whole family around (see it_protocols.hpp's own file
// header comment): a growing number of OT/IT integration layers (MQTT-to-AMQP bridges, historian
// ingestion pipelines, SCADA-to-cloud telemetry relays, modern DCS/MES middleware) move OT data over
// RabbitMQ specifically, and a RabbitMQ broker reachable from an OT segment -- especially one
// accepting cleartext PLAIN/AMQPLAIN credentials, see SECURITY below -- is exactly the kind of finding
// an OT network audit needs surfaced, the same reasoning that put MQTT (mqtt.hpp), WinRM (winrm.hpp),
// and the whole Tier 1-5 "IT protocols an OT auditor flags" arc into this codebase.
//
// SOURCING: every byte value, class/method ID, field layout, and bit-packing rule in this file was
// cross-confirmed directly against Wireshark's own packet-amqp.c dissector source, RabbitMQ's own
// server source (rabbit_reader.erl/rabbit_framing.hrl), and RabbitMQ's own 0-9-1 reference
// documentation, by a dedicated research pass treated as authoritative for this whole feature -- see
// the task's own research notes for the full byte-exact citation trail this implementation follows
// verbatim. One deliberate, source-confirmed departure from the WRITTEN 0-9-1 standard: the
// field-table type-tag assignments below (AMQP_091_TABLE_TYPE_TAGS) follow the INDUSTRY-PRACTICE
// tag values every real broker/client actually sends (per Wireshark's own explicit divergence note
// and RabbitMQ's own errata page), not the written spec's own tag assignment, which no real
// implementation follows.
//
// SCOPE, DECIDED HERE:
//   - Frame types 1 (METHOD), 2 (HEADER/content-header), 3 (BODY/content-body), and 8 (HEARTBEAT)
//     are fully handled. Types 4-7 (OOB_METHOD/OOB_CONTENT_HEADER/OOB_CONTENT_BODY/TRACE) are
//     dead/legacy protocol features with no real-world traffic to validate a decoder against --
//     recognized structurally (frame type name, channel, byte length) but their payload bytes are
//     never further decoded, the same "curated depth, not exhaustive" posture this codebase's
//     LLDP/CDP TLV tables and RMCP/IPMI's own NetFn/Command tables already establish.
//   - Classes fully decoded (argument-level): Connection, Channel, Exchange, Queue, Basic, Tx,
//     Confirm. Classes recognized by name only, arguments never decoded: Access (vestigial,
//     access-control tickets long unused by any real broker), File and Stream (both dead --
//     superseded by Basic before any real deployment used them), Dtx (rare, distributed
//     transactions), Tunnel (dead, an abandoned pre-0-9-1 experiment).
//   - Method ARGUMENTS are only decoded for the exact byte layouts this file's own sourcing pass
//     confirmed byte-for-byte (see WIRE FORMAT below for the full list). A named method whose own
//     argument layout was NOT independently confirmed (e.g. Connection.Secure/Secure-Ok/Redirect/
//     Blocked/Unblocked, Channel.Flow/Flow-Ok, Exchange.Bind/Unbind/Bind-Ok/Unbind-Ok, most Queue
//     methods past Declare/Declare-Ok/Bind/Delete/Delete-Ok, Basic.Cancel/Cancel-Ok/Return/
//     Recover-Async/Recover/Recover-Ok, Confirm.Select/Select-Ok) still gets its correct class/
//     method NAME (every class/method ID IS byte-exact-confirmed -- see WIRE FORMAT below) but its
//     argument bytes are reported as an honest, undecoded byte count/hex blob rather than guessed
//     at -- the same "decode confidently only where the wire format is unambiguous, note anything
//     inferred as inferred" posture CANopen's/J1939's own sourcing-gap writeups (canopen.hpp,
//     j1939.hpp) and RMCP/IPMI's own RAKP sourcing-gap writeup (rmcp.hpp) already establish. A
//     "reserved"/vestigial argument that IS on a confirmed layout (e.g. every `ticket` field) is
//     still parsed to keep cursor offset tracking correct, but not surfaced as a first-class field.
//   - Content-Body frames (type 3) are recognized and their byte LENGTH is reported; the message
//     body bytes themselves are never interpreted (no content-type-driven sub-dissection, e.g.
//     handing a JSON body to a JSON parser) -- explicitly out of scope per this feature's own task
//     description, future work for a later pass, matching this codebase's universal posture of
//     never decoding an application payload it has no protocol-level reason to understand.
//   - No request/response PAIRING is attempted at the classic-message level (matching this
//     codebase's own precedent for IPMI, see rmcp.hpp's STATEFULNESS section for the identical
//     reasoning) -- 0-9-1's METHOD frames are already self-describing per-message (class+method
//     name, channel), so a human or downstream tool reading this decoder's own per-packet output
//     can already correlate a request with its response without this decoder doing it for them.
//     The ONE piece of genuine cross-packet state this file needs is the shared, per-TCP-session
//     AMQP VERSION detection (see amqp_common.hpp's own STATEFULNESS section) -- nothing else.
//   - KNOWN COLLISION, documented rather than "fixed" by reordering: a 0-9-1 HEARTBEAT frame's
//     entire wire representation is a FIXED 8-byte pattern (08 00 00 00 00 00 00 CE -- type=8,
//     channel=0, size=0, frame-end=0xCE) with no variable content at all. Read as a Modbus/TCP
//     MBAP header (transaction-id=0x0800, protocol-id=0x0000, mbap-length=0x0000, unit-id=0x00,
//     function-code=0xCE), this satisfies Modbus's own protocol-id==0 tell AND sets the exception
//     bit on an otherwise-plausible function code -- and, since decoder.cpp tries Modbus well
//     before AMQP in both its TCP-reassembly declared-length cascade and its main decode()
//     dispatch cascade (a long-established ordering this feature deliberately does not disturb,
//     to avoid any risk of regressing Modbus's own extensive existing test suite), a HEARTBEAT
//     frame arriving in Auto mode on a shared/overlapping port can be claimed by Modbus's own
//     decode() first, rendered as an "Unknown (0x4e): malformed exception frame" result, rather
//     than reaching this decoder at all. An explicit `--protocol amqp091` still decodes it
//     correctly (Modbus's own decode() is never tried at all under that filter) -- this is a
//     narrow, honestly-documented Auto-mode ambiguity affecting only this one fixed-byte frame
//     shape, not a general 0-9-1-vs-Modbus collision (every other 0-9-1 frame this file decodes
//     carries a nonzero class-id/method-id or content in its own payload, which Modbus's own
//     function-code-0 guard -- see modbus.cpp's try_parse_modbus_tcp -- already reliably declines).
//
// WIRE FORMAT
//
// Frame: type(1) channel(2,BE) size(4,BE, PAYLOAD-ONLY length, i.e. NOT counting this 7-byte header
// or the 1-byte trailer below) payload(size bytes) frame-end(1, MUST be 0xCE). Total on-the-wire
// frame length = size + 8. Frame types: 1=METHOD, 2=HEADER (content-header), 3=BODY (content-body),
// 8=HEARTBEAT (an empty frame, size==0, channel==0); 4=OOB_METHOD, 5=OOB_CONTENT_HEADER,
// 6=OOB_CONTENT_BODY, 7=TRACE (see SCOPE above -- structural-only).
//
// METHOD frame payload: class-id(2,BE) method-id(2,BE) arguments(class/method-specific, see below).
//
// Classes (id): Connection=10, Channel=20, Access=30, Exchange=40, Queue=50, Basic=60, File=70,
// Stream=80, Confirm=85 (RabbitMQ extension), Tx=90, Dtx=100, Tunnel=110.
//
// Methods (class/method-id) -- every one of these IDs is byte-exact confirmed, regardless of
// whether this file goes on to decode that method's own arguments (see SCOPE above):
//   Connection(10): Start=10, Start-Ok=11, Secure=20, Secure-Ok=21, Tune=30, Tune-Ok=31, Open=40,
//     Open-Ok=41, Redirect=42, Close=50, Close-Ok=51, Blocked=60 (RabbitMQ ext), Unblocked=61
//     (RabbitMQ ext).
//   Channel(20): Open=10, Open-Ok=11, Flow=20, Flow-Ok=21, Close=40, Close-Ok=41 (legacy
//     Resume/Ping/Pong/Ok = 50/60/70/80, structural-only, dead).
//   Exchange(40): Declare=10, Declare-Ok=11, Delete=20, Delete-Ok=21, Bind=30 (RabbitMQ ext),
//     Bind-Ok=31, Unbind=40, Unbind-Ok=51 (deliberately NON-parallel numbering, confirmed exact).
//   Queue(50): Declare=10, Declare-Ok=11, Bind=20, Bind-Ok=21, Purge=30, Purge-Ok=31, Delete=40,
//     Delete-Ok=41, Unbind=50, Unbind-Ok=51.
//   Basic(60): Qos=10, Qos-Ok=11, Consume=20, Consume-Ok=21, Cancel=30, Cancel-Ok=31, Publish=40,
//     Return=50, Deliver=60, Get=70, Get-Ok=71, Get-Empty=72, Ack=80, Reject=90,
//     Recover-Async=100, Recover=110, Recover-Ok=111, Nack=120 (RabbitMQ ext).
//   Tx(90): Select=10, Select-Ok=11, Commit=20, Commit-Ok=21, Rollback=30, Rollback-Ok=31 -- all
//     six confirmed ZERO-ARGUMENT.
//   Confirm(85): Select=10, Select-Ok=11.
//
// Bit-packing: consecutive `bit`-typed method arguments pack into ONE octet, LSB-first in
// declaration order, and the argument cursor advances by exactly 1 byte for the WHOLE run (not per
// bit) -- e.g. Queue.Declare's flags octet = passive(bit0)/durable(bit1)/exclusive(bit2)/
// auto-delete(bit3)/nowait(bit4); Exchange.Declare's = passive/durable/auto-delete/internal/nowait;
// Basic.Publish's = mandatory(bit0)/immediate(bit1).
//
// Field-table type-tag system (table/headers/arguments/server-properties/client-properties): a
// table is a 4-byte BE byte-length followed by that many bytes of back-to-back
// {1-byte name-length, name bytes, 1-byte type-tag, type-specific value} entries, with NO count
// prefix of its own. Type tags, INDUSTRY-PRACTICE column (see this file's own SOURCING note above
// for why, not the written spec's own tag assignment): t=boolean(1B), b=int8(1B), B=uint8(1B),
// s=int16(2B), u=uint16(2B), I=int32(4B), i=uint32(4B), l=int64(8B), f=float32(4B), d=float64(8B),
// D=decimal(1B scale + 4B BE mantissa, value = mantissa/10^scale), S=longstr(4B BE length + UTF-8
// bytes), A=array(4B BE byte-length + back-to-back type-tagged values, no per-element name),
// T=timestamp(8B BE unsigned, POSIX seconds), F=nested field table (4B BE byte-length + recursively
// parsed table), V=void/null(0B), x=opaque binary/RabbitMQ extension(4B BE length + raw bytes). An
// unrecognized type tag is a hard parse-stop (this decoder cannot know how many bytes to skip past
// it) -- the remainder of that table/argument list is reported as undecoded rather than guessed at.
// `shortstr` (most string method ARGUMENTS, NOT `longstr`) = 1-byte length + that many bytes.
//
// See this file's own source (amqp091.cpp) for the exact per-method argument layouts this decoder
// implements -- reproduced there, immediately above each method's own parse function, rather than
// duplicated a second time here; every layout there is the byte-exact one this file header's own
// SOURCING note describes.
//
// Content-Header frame (type=2), offsets from the start of the frame's own payload region (i.e.
// AFTER the 7-byte frame header, so add 7 for an absolute offset from frame start): class-id(2B
// BE, always 60/Basic in real traffic)@0, weight(2B BE, always 0)@2, body-size(8B BE unsigned --
// 64-bit, unlike most 4-byte length fields elsewhere in this protocol)@4, property-flags(2B BE
// bitmask, bit15 = first declared property, down to bit1)@12, property-list(only properties whose
// flag bit is set, in fixed declared order, back-to-back)@14.
//
// Basic class property list, declared bit order (15 down to 2; bit 1 unused/reserved): content-
// type(shortstr,15), content-encoding(shortstr,14), headers(table,13), delivery-mode(octet: 1=non-
// persistent/2=persistent,12), priority(octet,11), correlation-id(shortstr,10), reply-to(shortstr,
// 9), expiration(shortstr -- a numeric STRING of milliseconds, not a native int,8), message-id
// (shortstr,7), timestamp(8B BE u64 POSIX seconds,6), type(shortstr,5), user-id(shortstr,4 -- an
// attribution value RabbitMQ can validate against the authenticated login), app-id(shortstr,3),
// cluster-id(shortstr,2 -- structural-only, always empty in practice).
//
// Content-Body frames (type=3): raw message-body bytes, may span multiple frames on the same
// channel up to the Content-Header's own declared body-size; this decoder reports each Body
// frame's own byte length (and, for the FIRST Body frame on a delivery, the running total against
// the Content-Header's declared body-size when both were seen in this same reassembled payload) --
// it does not attempt cross-payload concatenation of a body split across TCP segments/packets
// beyond what the shared TCP-reassembly layer already buffers for one physical frame.
//
// SECURITY -- CLEARTEXT CREDENTIAL EXCHANGE (this decoder's own headline curated finding, matching
// Cipher Suite 0 for IPMI/Zerologon for Netlogon/DCSync for DRSUAPI elsewhere in this codebase):
// Connection.Start-Ok's own `response` argument carries the client's actual SASL credential bytes.
// For mechanism PLAIN (`\x00` + UTF-8 username + `\x00` + UTF-8 password, RFC 4616-style) and
// AMQPLAIN (RabbitMQ's own extension: a field-table containing exactly LOGIN(longstr) and
// PASSWORD(longstr) entries), this is a literal cleartext credential on the wire -- and, since this
// decoder only ever sees a Start-Ok it can successfully parse as an ordinary 0-9-1 METHOD frame in
// the first place (a TLS-wrapped AMQP session on port 5671 never reaches this decoder at all in
// decodable form, see amqp_common.hpp's own AMQP_TLS_PORT comment), EVERY PLAIN/AMQPLAIN
// Connection.Start-Ok this decoder ever decodes is, by construction, cleartext-on-the-wire. Flagged
// prominently in --stats, the same "*** ... observed: N ***" convention IPMI's own Cipher Suite 0
// and J1939's own DM1 headline already use. The raw `response` bytes are NEVER rendered anywhere in
// this decoder's own output -- see REDACTION below.
//
// REDACTION: reuses kRedactedSecretPlaceholder/redact_secret_occurrences from protocol_decoder.hpp
// exactly as IPMI's Auth Code (rmcp.hpp/rmcp.cpp) and Netlogon's NL_TRUST_PASSWORD
// (netlogon.hpp/netlogon.cpp) already do. Start-Ok's own `response` bytes are never even copied
// into Amqp091Method::sasl_response_hex (unlike IPMI's own "never even read the bytes into the
// struct in the first place" CODESYS-Login-password posture, this decoder DOES need to know the
// response's own byte LENGTH -- itself a useful, non-sensitive signal -- so it reads the length but
// discards the bytes immediately after) -- only mechanism name and response byte length are ever
// surfaced. For PLAIN specifically, the username (NOT the password) is additionally parsed out and
// shown in full when the bytes are well-formed (`\x00<user>\x00<password>`), the same "a username is
// not a secret, only the password is" precedent IPMI's own RAKP Message 1 User Name field already
// establishes (rmcp.hpp) -- the password portion's own byte range is still never read past its own
// length. AMQPLAIN's LOGIN value is likewise surfaced (not a secret); PASSWORD is not.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduitscope/amqp_common.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

const char* amqp091_class_name(uint16_t class_id);
const char* amqp091_method_name(uint16_t class_id, uint16_t method_id);
const char* amqp091_frame_type_name(uint8_t type_raw);  // "METHOD"/"HEADER"/"BODY"/"HEARTBEAT"/
                                                          // "OOB_METHOD"/.../"TRACE", or nullptr.

// One generic, named+rendered field/argument/table-entry value -- see this file's own header
// comment for why method arguments and field-table entries alike are represented this way rather
// than one hand-written C++ struct per method: with ~60 methods sharing the same handful of
// primitive/table/array building blocks, a generic ordered list keeps every method's argument
// decode traceable to this file's own WIRE FORMAT section without duplicating that machinery
// per-method. `name` is empty for an unnamed positional value (a method argument, or an array
// element); populated for a field-table entry.
struct Amqp091Value {
    std::string name;
    std::string rendered;  // human-readable rendering, e.g. "\"text\"", "true", "12345",
                            // "<table: 2 entries>", "<array: 3 entries>".
};

struct Amqp091Method {
    uint16_t class_id = 0;
    uint16_t method_id = 0;
    const char* class_name = nullptr;
    const char* method_name = nullptr;
    bool arguments_decoded = false;  // false when this method's own argument layout was never
                                       // independently confirmed -- see this file's own SCOPE note.
    std::vector<Amqp091Value> fields;  // ordered, empty when !arguments_decoded.
    size_t undecoded_argument_bytes = 0;  // set only when !arguments_decoded.

    // Curated, first-class fields pulled out of `fields` above for structured JSON access and for
    // this file's own curated findings -- see this file's SECURITY section.
    bool is_start_ok = false;
    std::optional<std::string> sasl_mechanism;      // Start-Ok only.
    std::optional<size_t> sasl_response_length;       // Start-Ok only -- NEVER the raw bytes.
    std::optional<std::string> sasl_username;          // Start-Ok, PLAIN/AMQPLAIN only, when parsed.
    bool cleartext_credentials = false;                 // mechanism is PLAIN or AMQPLAIN.

    bool is_close = false;  // Connection.Close or Channel.Close.
    std::optional<uint16_t> reply_code;
    std::optional<std::string> reply_text;

    bool is_basic_publish = false;
    bool publish_immediate = false;

    std::string summary;
    std::vector<std::string> notes;
};

struct Amqp091ContentHeader {
    uint16_t class_id = 0;
    uint16_t weight = 0;
    uint64_t body_size = 0;
    uint16_t property_flags = 0;
    std::vector<Amqp091Value> properties;  // ordered by declared bit order, only those present.
    std::string summary;
    std::vector<std::string> notes;
};

struct Amqp091Frame {
    uint8_t type_raw = 0;
    const char* type_name = nullptr;
    uint16_t channel = 0;
    uint32_t declared_payload_size = 0;
    bool frame_end_valid = false;   // false when the trailing 0xCE octet was checked and mismatched,
                                      // or couldn't be checked at all (truncated).
    bool truncated = false;          // fewer bytes were available than declared_payload_size + 8.
    size_t wire_length = 0;          // total bytes this frame actually consumed from the candidate
                                      // buffer (== declared length when complete; the available byte
                                      // count when truncated) -- used by the coalescing loop below.

    std::optional<Amqp091Method> method;              // type==1 only.
    std::optional<Amqp091ContentHeader> content_header;  // type==2 only.
    std::optional<size_t> body_bytes;                    // type==3 only.

    std::string summary;
    std::vector<std::string> notes;
};

// One decoded TCP payload's worth of AMQP 0-9-1 traffic -- `first` is the primary frame this
// DecodedPacket's own summary/notes/JSON fields are built from; any further frames coalesced into
// the same TCP payload (extremely common -- a Content-Header immediately followed by one or more
// Content-Body frames on the very next write() is the normal shape of a real Basic.Publish) are
// folded into `notes` as one-line summaries each, the same MqttResult/try_parse_mqtt_message
// coalescing-loop shape mqtt.hpp/mqtt.cpp already establish.
struct Amqp091Result {
    Amqp091Frame first;
    std::string summary;
    std::vector<std::string> notes;
};

// Parses exactly ONE frame starting at the beginning of `candidate` (a 0-9-1 frame or the shared
// 8-byte connection preamble is handled separately, see amqp_common.hpp) -- returns std::nullopt
// only when `candidate` is too short even for the fixed 7-byte frame header. No redact_secrets
// parameter, unlike most of this codebase's other secret-bearing decoders (WinRM's command_line,
// HSRP's/VRRP's auth fields) -- Start-Ok's own credential bytes are redacted UNCONDITIONALLY (see
// this file's own REDACTION section: "mandatory", never gated behind --redact/--no-redact), the
// same "never even read the sensitive bytes past their own length" posture IPMI's Auth Code
// (rmcp.hpp) and CODESYS's Login password already establish, so there is nothing here for a
// redact-secrets flag to conditionally toggle. Never throws.
std::optional<Amqp091Frame> try_parse_amqp091_frame(ByteSpan candidate);

// Returns the total on-the-wire byte count ONE 0-9-1 preamble-or-frame declares, or a "need at
// least N more bytes" partial value while the frame's own 7-byte header is still arriving (the
// same two-phase declared-length shape ge_srtp.hpp's own ge_srtp_tcp_declared_length already
// established) -- see amqp091.cpp for the exact structural gate (Type byte in the legal 1-8 range,
// then Channel+Size once available). Returns std::nullopt when `candidate` clearly isn't a 0-9-1
// preamble or frame at all (an out-of-range Type byte, or an "AMQP..." preamble that doesn't match
// either of the two 0-9-1 preamble byte patterns).
std::optional<size_t> amqp091_tcp_declared_length(ByteSpan candidate);

class Amqp091Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "amqp091"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return AMQP_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return amqp091_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& amqp091_tcp_decoder();

}  // namespace conduitscope
