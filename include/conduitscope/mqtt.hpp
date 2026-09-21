// SPDX-License-Identifier: Apache-2.0
// mqtt.hpp - MQTT v3.1.1 and v5.0 decoding, plus Sparkplug B (Eclipse Tahu) topic/payload
// recognition layered on top of MQTT PUBLISH.
//
// Sourcing: MQTT wire format cross-checked against the two OASIS standard texts --
// docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html and .../v5.0/os/mqtt-v5.0-os.html --
// fetched directly for this feature (fixed header/Remaining Length encoding, every packet type's
// variable header and payload shape, the full v5 Properties table, and the reason/return code
// tables). Sparkplug B is cross-checked against the Eclipse Sparkplug 3.0.0 specification PDF
// (sparkplug.eclipse.org/specification/version/3.0/documents/sparkplug-specification-3.0.0.pdf,
// topic namespace/message-type semantics) and the actual Eclipse Tahu .proto schema, fetched raw
// from github.com/eclipse-tahu/tahu/blob/master/sparkplug_b/sparkplug_b.proto (field numbers/types
// for Payload, Metric, DataSet, PropertyValue/PropertySet, MetaData, Template -- the same
// "generated/published by the spec's own maintainers, so it can't have transcribed a field wrong
// without breaking real interop" sourcing standard this codebase already leans on for OPC UA's
// NodeIds.csv/StatusCode.csv and python-opcua's generated bindings -- see opcua.hpp).
//
// ---------------------------------------------------------------------------------------------
// Fixed header (every MQTT packet, both versions): 1 byte (top nibble = Control Packet Type 1-15,
// bottom nibble = flags, whose meaning and allowed values depend on the type -- see below) followed
// by "Remaining Length": a 1-4 byte Variable Byte Integer (VBI) -- 7 payload bits per byte, MSB =
// continuation flag, least-significant byte first -- encoding the byte count of everything that
// follows (variable header + payload), max value 268,435,455 (4 bytes, 0xFF 0xFF 0xFF 0x7F; a 4th
// byte with the continuation bit still set is malformed and rejected). This project's own MQTT5
// Properties length prefix (see below) and Sparkplug B's protobuf field lengths both reuse the same
// "7 bits per byte, MSB continuation" shape -- protobuf's own varint scheme is byte-identical to
// MQTT's VBI in its continuation-bit convention, differing only in the maximum byte count (4 vs 10).
//
// Structural detection gate: HONESTLY WEAK, in the same spirit as this codebase's own HART-IP gate
// (see hartip.hpp's "weakest gate in this codebase" paragraph) -- arguably even weaker on its own,
// since it is a single leading byte (not two). The gate checks that the top nibble is one of the 14
// packet types this codebase decodes (1-14, or 15 for AUTH -- MQTT5-only, 0 is always reserved/
// invalid) AND that the bottom nibble (flags) matches the fixed pattern the spec normatively
// requires for that specific type (MQTT-2.1.3-1): `0000` for every type except PUBLISH (whose DUP/
// QoS/RETAIN bits are genuinely variable, all 16 values valid) and PUBREL/SUBSCRIBE/UNSUBSCRIBE
// (fixed at `0010`). That combined (type, flags) constraint admits only 30 of 256 possible leading
// bytes -- materially narrower than "any byte", but still nowhere near OPC UA's 3-byte ASCII
// magic-string gate. This is then combined with a VBI-validity check (1-4 bytes, no 5th
// continuation byte) and, for TCP-stream reassembly purposes (mqtt_declared_length, mirroring
// opcua_declared_length/hartip_declared_length/enip_declared_length), a plausibility check that the
// declared Remaining Length is consistent with a message this decoder can actually make sense of.
// For CONNECT specifically (the first packet on every real MQTT connection) this decoder goes
// further and requires the Protocol Name string to read as literally "MQTT" (or the pre-OASIS
// "MQIsdp") with a structurally valid Protocol Level byte -- a much stronger, near-OPC-UA-strength
// signal for that one packet type, the same "opportunistic extra validation where the format
// allows it" posture this codebase already applies elsewhere.
//
// Because of this weak gate, MQTT is tried LAST in this codebase's opportunistic TCP dispatch chain
// -- after HART-IP, not before it (see decoder.cpp's own dispatch-order comment) -- on the same
// "weaker signal gets lower priority" principle already established for HART-IP vs. Modbus/DNP3/
// S7comm. No specific byte-for-byte collision with another protocol this codebase decodes was found
// during this feature's own research, but with only 30/256 leading bytes excluded, one is plausible
// on some future protocol's own leading byte -- the same honest posture HART-IP's own header comment
// already takes, not a stronger claim than that.
//
// ---------------------------------------------------------------------------------------------
// Version disambiguation: MQTT v3.1.1 and v5.0 share the same fixed header and packet-type set, but
// several packet types have a DIFFERENT variable-header shape between the two versions (v5 adds an
// optional/conditional Properties section). This decoder does NOT track per-session negotiated
// version state inside mqtt.cpp itself (it is, like every protocol in this codebase, a
// stateless-per-message decoder) but DOES accept an optional `session_version_hint` parameter
// (0=unknown, 4=v3.1.1, 5=v5.0) that Decoder (decoder.cpp) supplies from its own per-TCP-session
// tracking map, populated whenever a CONNECT packet (whose Protocol Level byte states its version
// explicitly, unambiguously) has been seen on that session -- the same "decoder stays stateless,
// Decoder itself owns cross-packet session state" split already used for Modbus transaction pairing
// (ModbusPendingRequest) and DNP3/COTP fragment reassembly.
//
// Most packet types don't actually need this hint at all -- their own Remaining Length is
// self-describing regardless of version, per the spec's own "shortcut" encoding rules:
//   - CONNECT: version is the Protocol Level byte itself, no ambiguity.
//   - CONNACK: Remaining Length == 2 is always the v3.1.1 shape (flags + return code, nothing
//     else); >= 3 is always v5 (flags + reason code + Properties, whose own length prefix occupies
//     at least 1 byte even when zero properties are present) -- v3.1.1 CONNACK is never longer than
//     2 bytes, so this is unambiguous either way.
//   - PUBACK/PUBREC/PUBREL/PUBCOMP: Remaining Length == 2 means implicit Reason Code Success(0) and
//     no Properties (works identically whichever version sent it); == 3 means v5 with an explicit
//     Reason Code and no Properties; >= 4 means v5 with Properties too.
//   - UNSUBACK: v3.1.1 is always exactly 2 bytes (packet id only, no payload at all); v5 is always
//     >= 3 (packet id + Properties + >=1 reason code) -- unambiguous.
//   - DISCONNECT: v3.1.1 is always Remaining Length == 0; a v5 DISCONNECT with nothing to say also
//     encodes as Remaining Length == 0 (implicit Reason Code Success, no Properties) -- genuinely
//     indistinguishable, but also genuinely IDENTICAL in meaning either way, so nothing is lost.
//   - AUTH: packet type 15 does not exist at all in v3.1.1 (reserved), so merely seeing this type is
//     itself an unambiguous version=5 signal.
// Only SUBSCRIBE, SUBACK, and UNSUBSCRIBE are genuinely ambiguous by shape alone: v5 adds an
// unconditional (not shortcut-encoded) Properties section right after the packet identifier, and
// with only Remaining Length to go on, "the next byte is a Properties Length VBI" (v5) vs. "the next
// byte is the start of the first Topic Filter's 2-byte length prefix" (v3.1.1) cannot be told apart
// from shape alone in every case. For these three, this decoder uses `session_version_hint` when
// available (authoritative); when it isn't (e.g. the capture starts mid-session, after CONNECT), it
// falls back to the same "attempt the stronger-evidence parse, validate it is fully self-consistent
// all the way to exactly consuming Remaining Length, fall back otherwise" opportunistic posture this
// codebase already uses for OPC UA's MSG body (see opcua.hpp's "Opportunistic ... body decode")-- and
// always adds a note naming which path (session-tracked vs. heuristic) was used.
//
// ---------------------------------------------------------------------------------------------
// Scope: unlike OPC UA/MMS, MQTT itself has no service body anywhere near as structurally complex as
// ASN.1 BER or a self-describing Variant/DataValue encoding -- every packet type's own variable
// header and payload is a flat, fully-specified sequence of fixed-size integers, VBIs, and
// length-prefixed strings/binary blobs. This decoder therefore does NOT need an OPC-UA/MMS-style
// Tier 1/Tier 2 split at the MQTT layer: every packet type (CONNECT, CONNACK, PUBLISH, PUBACK,
// PUBREC, PUBREL, PUBCOMP, SUBSCRIBE, SUBACK, UNSUBSCRIBE, UNSUBACK, PINGREQ, PINGRESP, DISCONNECT,
// AUTH) is decoded in full, including every v5 Property this decoder's own generic, table-driven
// property decoder recognizes (all 27 Property Identifiers defined in MQTT5 OS Table 2-4 -- decoded
// generically by wire type: Byte/Two-Byte-Integer/Four-Byte-Integer/VBI/UTF-8-String/
// UTF-8-String-Pair/Binary-Data -- so no property needs its own hand-written decoder function). The
// one thing genuinely left as opaque bytes is PUBLISH's actual application Payload -- MQTT carries
// arbitrary application data there by design, the same "raw hex, deliberately not value-decoded"
// posture this codebase already takes for EtherNet/IP CIP I/O data and PROFINET cyclic IO data --
// UNLESS the topic identifies it as Sparkplug B traffic, in which case this decoder attempts the
// Sparkplug-specific decode described below.
//
// Also deliberately NOT implemented, consistent with every other stateless-per-message decoder in
// this codebase (see opcua.hpp's "Deliberately NOT implemented" paragraph for the same posture):
// Topic Alias resolution (a v5 client/server may replace a long topic string with a small integer
// alias after the first PUBLISH that establishes it -- this decoder shows the Topic Alias property
// when present but does not track/resolve it back to the topic string that established it); QoS 1/2
// retransmission and exactly-once delivery state tracking across packets (each PUBACK/PUBREC/
// PUBREL/PUBCOMP is decoded independently, the same posture Modbus's own authoritative-pairing
// feature deliberately goes further than for transaction correlation, which MQTT's own packet
// identifiers would support similarly but this first-pass release does not add); retained-message
// and Will-message delivery semantics (this decoder reports what a CONNECT's Will fields or a
// PUBLISH's RETAIN bit literally say, not what a broker later does with them); and TLS (MQTT over
// 8883 is out of scope entirely -- this decoder, like every other in this codebase, only ever sees
// cleartext capture content).
//
// ---------------------------------------------------------------------------------------------
// Sparkplug B: an Eclipse Tahu specification layering a structured topic namespace and a
// Protocol-Buffers-encoded payload on top of plain MQTT PUBLISH. This decoder recognizes it purely
// from the PUBLISH topic string -- `spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]`
// for NBIRTH/NDEATH/DBIRTH/DDEATH/NDATA/DDATA/NCMD/DCMD (device_id present only for the four
// D-prefixed types), or `spBv1.0/STATE/{host_id}` for the separate STATE namespace -- and, only for
// the non-STATE shape, attempts to parse the PUBLISH payload as a `org.eclipse.tahu.protobuf.Payload`
// protobuf message using a small, hand-rolled protobuf wire-format reader (varint + the three wire
// types Sparkplug's own schema actually uses: 0=varint, 1=64-bit fixed, 2=length-delimited, plus
// 5=32-bit fixed for Metric's `float_value`) -- no external protobuf library, consistent with this
// whole codebase's zero-required-dependency philosophy already applied to hand-rolled ASN.1 BER for
// GOOSE/SV/MMS. STATE payloads are plain UTF-8 JSON text per the spec (not protobuf at all) and are
// captured verbatim as text, not parsed as JSON (this codebase has no JSON parser and doesn't need
// one just to display a small, already-human-readable string back to the user).
//
// Sparkplug field decode covers Payload's own top-level fields (timestamp, seq, uuid, and `body`'s
// presence+length -- `body` is itself documented in the .proto as a bypass/escape hatch, "Bypass
// whole definition above", so this decoder deliberately does not attempt to interpret its contents)
// and, per repeated Metric, name/alias/timestamp/datatype/is_historical/is_transient/is_null plus
// the `oneof value` field appropriate to that Metric's own `datatype` -- covering every scalar
// DataType (Int8-UInt64, Float, Double, Boolean, String, DateTime, Text, UUID). Metric's own
// `metadata`/`properties` sub-messages are structurally skipped (consumed for correct byte
// alignment, the same posture this codebase already takes for OPC UA DiagnosticInfo's optional
// fields) but not surfaced as decoded values; DataSet/Template/PropertySet/PropertySetList/Bytes/
// File and every Array datatype (22-34) are recognized by name only, their own bytes shown only as a
// byte count, not decoded further -- an honest, deliberate scope line drawn in the same place OPC
// UA's own Tier 2 draws it (Variant/DataValue's own recursive, 25-BuiltInType encoding is out of
// scope there for the same "materially more implementation surface than a first pass justifies"
// reason).
//
// One documented, non-obvious wire-format gotcha this decoder deliberately gets right: Sparkplug's
// own .proto declares `int_value` as `uint32` and `long_value` as `uint64` (NOT the protobuf
// `sint32`/`sint64` zigzag-encoded types) -- so a NEGATIVE Int8/Int16/Int32/Int64 metric value is
// carried on the wire as that value's raw two's-complement bit pattern, reinterpreted as unsigned,
// the same convention the Eclipse Tahu reference client libraries themselves use (a well-known
// Sparkplug implementation detail, not a guess this decoder is making up) -- decoded here by
// reading the wire varint into a uint32/uint64 exactly as protobuf's own wire format already
// guarantees (extra high bits beyond the field's declared width are simply not present on the wire
// for a small value, and are discarded on decode for a large one, per the protobuf spec's own
// varint-truncation rule) and then, only for display, reinterpreting that bit pattern as signed
// when the Metric's own `datatype` says the value is one of the signed integer types.
//
// Validation: see this file's own real-capture search record in tests/real_captures/mqtt/
// ATTRIBUTION.md (if present) for the current state of that search.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// The IANA-registered MQTT port -- recorded as an "expected port" annotation only, never a
// detection gate, the same posture every other protocol's own port gets in this codebase.
constexpr uint16_t MQTT_PORT = 1883;

// Renders `millis` (milliseconds since the Unix epoch, Sparkplug's own DateTime/timestamp
// convention -- see mqtt.hpp's file header comment) as an ISO-8601 UTC calendar timestamp,
// "YYYY-MM-DDTHH:MM:SS.mmmZ", via std::gmtime -- or, for a value std::gmtime can't represent (out
// of range for the platform's time_t/tm), a graceful fallback string naming the raw millisecond
// value instead of fabricating a date.
//
// Exposed here (rather than kept mqtt.cpp-local, which is where it originated for Sparkplug B's
// own timestamp fields) specifically so dnp3.cpp can call it directly: DNP3's Group 50 "Time and
// Date" object (and the 48-bit absolute-time trailer on event objects' "with time" variants) is
// the exact same wire shape -- milliseconds since the Unix epoch, as a uint64_t -- so this decoder
// reuses this one function rather than maintaining a second, near-identical copy of the same
// gmtime-based rendering. See dnp3.cpp's decode_absolute_time48 for that reuse, and
// devicenet.cpp's reuse of enip.hpp's cip_service_name for the same kind of cross-file-reuse
// precedent in this codebase.
std::string format_millis_epoch(uint64_t millis);

// One decoded Sparkplug B Metric (Payload.Metric in the Tahu .proto) -- see mqtt.hpp's file header
// comment's "Sparkplug B" section for the full field-by-field decode scope. Not exposed on its own;
// SparkplugPayload::metrics below holds the already-rendered one-line summary this codebase's other
// "list of decoded sub-values" fields use (mirrors OpcUaMessage::values/MmsFrame::values), so this
// struct is purely an mqtt.cpp implementation detail, declared here only because MqttMessage below
// needs to reference SparkplugPayload as a whole.
struct SparkplugPayload {
    bool has_timestamp = false;
    uint64_t timestamp = 0;
    bool has_seq = false;
    uint64_t seq = 0;
    bool has_uuid = false;
    std::string uuid;
    bool has_body = false;
    size_t body_length = 0;

    size_t metric_count = 0;               // every metric found, even past the rendering cap below
    std::vector<std::string> metrics;       // one rendered summary per metric, capped (mqtt.cpp)

    bool parse_ok = false;   // true once the top-level Payload message was structurally readable
                              // (individual metrics can still fail independently -- see metrics'
                              // own "<unparseable, N byte(s)>" fallback entries when that happens)
};

// One decoded MQTT packet -- see mqtt.hpp's file header comment for the full byte layout, version-
// disambiguation strategy, and decode scope.
struct MqttMessage {
    uint8_t packet_type = 0;         // 1-15, the raw Control Packet Type nibble
    std::string packet_type_name;    // "CONNECT"/"PUBLISH"/... -- always set once the gate passes
    uint8_t flags = 0;               // raw bottom nibble of the fixed header's first byte

    // PUBLISH only (meaningful only when packet_type_name == "PUBLISH").
    bool dup = false;
    uint8_t qos = 0;
    bool retain = false;

    uint32_t remaining_length = 0;
    size_t header_length = 0;   // fixed header bytes actually consumed (1 + 1-4 VBI bytes)
    // The full wire length of this one packet (header_length + remaining_length, clamped to what's
    // actually available) -- lets a caller find where the next packet, if any, starts in the same
    // TCP payload, mirroring EnipFrame::wire_length/OpcUaMessage::wire_length's own role.
    size_t wire_length = 0;

    // "3.1.1"/"5.0"/"" (unknown) -- see file header comment's "Version disambiguation" section.
    std::string protocol_version_name;
    // Set only for CONNECT (where the version is stated on the wire, unambiguous) -- Decoder uses
    // this to update its own per-session version-tracking map. 0/4/5, matching the wire Protocol
    // Level byte's own values (4=v3.1.1, 5=v5.0; 3 is accepted and named but is the older,
    // pre-OASIS v3.1 "MQIsdp" revision this decoder does not otherwise specially handle).
    uint8_t connect_discovered_version = 0;

    bool has_packet_id = false;
    uint16_t packet_id = 0;

    std::string topic;   // PUBLISH only

    bool has_payload = false;   // PUBLISH only
    size_t payload_length = 0;
    // Raw application payload, hex-encoded -- "deliberately not value-decoded" (see file header
    // comment), UNLESS Sparkplug B decode below succeeded, in which case this is left EMPTY (the
    // decoded sparkplug fields below are the useful rendering instead, and duplicating potentially
    // large payload bytes as hex serves no purpose once they're already decoded).
    std::string payload_hex;

    // Every other packet-type-specific field (CONNECT's client id/flags/keep-alive, CONNACK's
    // session-present/reason, the ack packets' reason code, SUBSCRIBE/SUBACK/UNSUBSCRIBE/UNSUBACK's
    // filter list and per-filter reason codes, DISCONNECT/AUTH's reason, and every v5 Property
    // decoded generically by this decoder's property table) -- "key=value" strings, mirrors
    // OpcUaMessage::values/BacnetApdu::values/HartIpPassThrough::values' own scheme.
    std::vector<std::string> values;

    // Sparkplug B -- PUBLISH only, set only when the topic matched the spBv1.0 namespace (see file
    // header comment's "Sparkplug B" section).
    bool is_sparkplug = false;
    std::string sparkplug_group_id;      // empty for the STATE topic shape
    std::string sparkplug_message_type;  // "NBIRTH"/.../"DCMD", or "STATE"
    std::string sparkplug_edge_node_id;  // empty for the STATE topic shape
    std::string sparkplug_device_id;     // empty unless this is a D-prefixed message type
    bool sparkplug_is_state = false;     // true for the spBv1.0/STATE/{host_id} topic shape
    std::string sparkplug_state_host_id; // set only when sparkplug_is_state (Sparkplug Host
                                          // Application ID -- "scada_host_id" in older spec prose)
    std::string sparkplug_state_text;    // set only when sparkplug_is_state -- raw JSON text, unparsed
    // Set only when !sparkplug_is_state -- the protobuf Payload decode attempt (see SparkplugPayload
    // above). Always present (even when parse_ok is false) so a failed decode is still visible.
    SparkplugPayload sparkplug_payload;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns this packet's own declared total length (fixed header + Remaining Length) for TCP stream
// reassembly purposes, mirroring opcua_declared_length/hartip_declared_length/enip_declared_length.
// Returns std::nullopt when the structural detection gate (see file header comment) fails, OR when
// there aren't yet enough bytes even to finish decoding the Remaining Length VBI itself (a genuinely
// rare edge case -- a TCP segment boundary landing inside the first 2-5 bytes of a packet -- left
// undetected in this first-pass release rather than adding a second reassembly layer just for a VBI
// that spans a segment boundary; see docs/MANUAL.md's LIMITATIONS for the honestly-scoped gap this
// leaves, mirroring OPC UA's own documented chunking limitation).
std::optional<size_t> mqtt_declared_length(ByteSpan payload);

// Attempts to interpret `payload` (TCP application-layer bytes) as one complete MQTT packet.
// `session_version_hint` is 0 (unknown), 4 (v3.1.1), or 5 (v5.0) -- see file header comment's
// "Version disambiguation" section for how it's used and when it's actually needed. Returns
// std::nullopt (never throws) only when the structural detection gate fails; once past the gate, a
// failure partway through decoding the body falls back to raw hex for whatever remains unparsed
// (the same graceful-degradation posture opcua.cpp's own try_parse_opcua_message already
// establishes), rather than discarding the whole packet.
std::optional<MqttMessage> try_parse_mqtt_message(ByteSpan payload, uint8_t session_version_hint = 0);

// Migration batch 2 (MQTT, Stage 11 -- the last of this batch) -- this protocol's own per-SESSION
// learned version hint (0=unknown, 4=v3.1.1, 5=v5.0; see "Version disambiguation" above), moved
// from the bespoke Decoder::mqtt_session_version_ map into the generic registration-model flow-
// state mechanism, the same generalization Stage 2 (Modbus) already did for
// Decoder::modbus_pending_. Unlike COTP/DNP3 (FlowStateKeying::DirectionalFlow -- see cotp.hpp/
// dnp3.hpp's own comments for why those two genuinely need per-direction state), MQTT's version
// hint is correctly SESSION-scoped: a CONNECT and a later SUBSCRIBE/SUBACK/UNSUBSCRIBE needing
// this hint can travel in either direction relative to each other, so this uses
// DecodeContext::flow_state<T>()'s unchanged default (FlowStateKeying::Session), the same choice
// ModbusFlowState/TwinCatFlowState already made.
class MqttFlowState : public DecoderFlowState {
public:
    uint8_t version_hint = 0;
};

// One decoded MQTT packet, wrapped for the ProtocolDecoder interface. `first` reuses MqttMessage
// verbatim (mirrors EnipResult/HartIpResult's own "first" convention) -- it already carries every
// field the legacy call site dual-wrote, no reduction needed. `notes` accumulates every coalesced
// packet's own notes (see MqttDecoder::decode); `summary` is always the FIRST packet's summary.
struct MqttResult {
    std::string summary;
    std::vector<std::string> notes;
    MqttMessage first;
};

// MQTT over TCP -- id()=="mqtt", GateKind::TcpPortIndependent, tcp_declared_length() drives this
// codebase's usual PDU/frame-level TCP stream reassembly (mirrors opcua_declared_length/
// hartip_declared_length/enip_declared_length). decode() reproduces the legacy `if (want_mqtt)`
// call site's own session-version-hint lookup/learning and same-payload multi-packet coalescing
// loop (small control packets like PINGREQ/PUBACK/SUBACK are commonly coalesced by the sender/OS,
// capped at 50 -- the same shape DNP3/IEC104/OPC UA/EtherNet-IP/HART-IP all already have). The
// FTP-control-line/LDAP-BER port carve-outs stay exactly where they are today -- call-site
// pre-checks deciding *whether* to invoke this decoder at all (see decoder.cpp's own
// `effective_payload_is_ftp_control`/`effective_payload_is_ldap`), not part of this decoder's own
// parsing.
class MqttDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "mqtt"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return mqtt_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& mqtt_decoder();

}  // namespace conduitscope
