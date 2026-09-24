// SPDX-License-Identifier: Apache-2.0
// amqp10.hpp - AMQP 1.0 (ISO/IEC 19464, OASIS Advanced Message Queuing Protocol Version 1.0) --
// TCP port 5672 (shared with AMQP 0-9-1, see amqp_common.hpp for the shared connection-preamble
// detection both this file and amqp091.hpp/.cpp rely on -- the two wire formats are otherwise
// completely independent, see amqp_common.hpp's own file header for why they're two files, not one).
//
// WHAT IT IS: the OASIS-standardized successor wire format most modern brokers actually speak today
// (Apache Qpid, ActiveMQ Artemis, Azure Service Bus, Solace, and RabbitMQ itself via its own
// rabbitmq-amqp1.0 plugin) -- an entirely different byte-level protocol from 0-9-1 despite the
// shared name and port, built on a fully generic, self-describing type system (every value on the
// wire carries its own type constructor) rather than 0-9-1's fixed-per-method argument shapes. See
// amqp091.hpp's own file header for why this OT/ICS tool decodes a general-purpose messaging
// protocol at all (OT/IT integration middleware moving telemetry over an AMQP broker) -- identical
// reasoning applies here.
//
// SOURCING: every byte value, performative/SASL-method code, message-section descriptor, and
// primitive-type constructor in this file was cross-confirmed directly against Wireshark's own
// packet-amqp.c dissector source and the OASIS AMQP 1.0 specification itself, by the same dedicated
// research pass amqp091.hpp's own SOURCING note describes -- treated as authoritative for this
// whole feature.
//
// TYPE SYSTEM -- THE ONE GENERIC WALK EVERYTHING ELSE IS BUILT ON: every value on the wire (a
// performative's own field, a nested source/target/error, a message-section body, an
// application-properties map entry) starts with a 1-byte type CONSTRUCTOR that self-describes both
// the type and, for most primitives, the value's own encoded width -- see amqp10.cpp's own
// read_amqp10_value() for the full constructor table (reproduced there rather than duplicated a
// second time here, immediately above its own switch statement) and Amqp10Value's own comment
// below for the generic result shape every caller (performative-field extraction, nested
// source/target/error, message sections, application-properties) reads from.
//
// DESCRIBED-TYPE FAST PATH vs. GENERAL WALK: every top-level AMQP/SASL performative on the wire
// uses the SAME fixed 3-byte prefix in every real implementation this codebase's own sourcing pass
// found: 0x00 (described-type constructor) 0x53 (smallulong type-constructor) <code> (1 byte), then
// the performative's own fields as a `list`. This decoder hard-codes that exact 3-byte prefix for
// top-level performative/SASL-method dispatch ONLY (matching real traffic, and matching what
// Wireshark's own dissector hard-codes at this exact point per this feature's own sourcing pass) --
// but implements the FULLY GENERAL described-type/primitive-type walk (read_amqp10_value, used
// everywhere else: nested source/target/error, message sections, application-properties map
// entries, array/list elements) so nothing NESTED inside a performative is limited to the fast
// path, only the outermost performative dispatch itself.
//
// SCOPE, DECIDED HERE:
//   - AMQP performatives fully decoded: open, begin, attach, flow, transfer, disposition, detach,
//     end, close -- every field of each, using the generic list-positional walk (a `0x40`/null in a
//     fixed list position means "omitted", per the spec's own gotcha, not an error).
//   - SASL performatives fully decoded: sasl-mechanisms, sasl-init, sasl-response, sasl-challenge,
//     sasl-outcome.
//   - Message sections (inside a `transfer` frame's own body, walked sequentially until the frame
//     body is exhausted): header, properties, and application-properties are fully decoded (the
//     three highest-value sections -- durability/priority/TTL, message identity/routing metadata,
//     and application/OT metadata respectively); delivery-annotations, message-annotations, data,
//     amqp-sequence, amqp-value, and footer are recognized by name and byte-length/rendered-value
//     only (no content-type-driven sub-dissection of a `data` section's own payload -- explicitly
//     out of scope, future work, matching amqp091.hpp's own identical Content-Body scope note).
//   - Delivery-state descriptors (received/accepted/rejected/released/modified, appearing in a
//     transfer's/disposition's own `state` field) and the transaction-extension types
//     (coordinator/declare/discharge/declared/transactional-state) are recognized by descriptor
//     name only, never further decoded -- no OT-specific value has been found in either, the same
//     "curated depth, not exhaustive" posture this codebase's LLDP/CDP TLV tables already establish.
//   - decimal32/64/128 are rendered as opaque hex bytes, NEVER numerically decoded -- an explicit
//     scope decision (matching Wireshark's own, per this feature's own sourcing pass): decimal
//     floating point needs library support most environments lack, and no OT-relevant field in this
//     protocol uses it anyway.
//   - No request/response-style PAIRING is attempted at the AMQP-performative level (matching
//     amqp091.hpp's own identical stance, and rmcp.hpp's IPMI precedent for the same reasoning) --
//     every performative already self-describes its own handle/delivery-id/delivery-tag, so a human
//     or downstream tool reading this decoder's own per-packet output can already correlate a
//     transfer with its own disposition without this decoder doing it for them. The ONE piece of
//     genuine cross-packet state this file needs is the shared, per-TCP-session AMQP VERSION
//     detection (see amqp_common.hpp's own STATEFULNESS section) -- nothing else; heartbeats (empty
//     frames) are recognized per-packet with no cross-packet gap/burst pattern-detection attempted,
//     matching this feature's own explicit "that's a future correlation layer's job" scope note.
//
// WIRE FORMAT
//
// Frame: SIZE(4,BE, TOTAL frame length INCLUDING this 8-byte header -- unlike 0-9-1's own
// payload-only size field) DOFF(1, 4-byte-word count to the body's own start, minimum legal value
// 2) TYPE(1: 0=AMQP frame, 1=SASL frame, 2=TLS frame [should never occur framed this way at this
// layer]) CHANNEL(2,BE) [extended header, present only when DOFF>2, never decoded past its own
// declared length] body. An EMPTY frame (SIZE=8, DOFF=2, zero-length body) is the keepalive --
// there is no distinct heartbeat frame type of its own, just an empty AMQP-type (TYPE=0) frame.
//
// Performative codes (1-byte smallulong descriptor form): open=0x10, begin=0x11, attach=0x12,
// flow=0x13, transfer=0x14, disposition=0x15, detach=0x16, end=0x17, close=0x18.
// SASL performative codes: sasl-mechanisms=0x40, sasl-init=0x41, sasl-challenge=0x42,
// sasl-response=0x43, sasl-outcome=0x44.
// Message-section descriptors: header=0x70, delivery-annotations=0x71, message-annotations=0x72,
// properties=0x73, application-properties=0x74, data=0x75, amqp-sequence=0x76, amqp-value=0x77,
// footer=0x78.
//
// See amqp10.cpp's own source for the exact per-performative/per-section field layouts this
// decoder implements (reproduced there, immediately above each one's own parse code, rather than
// duplicated a second time here) -- every layout there is the byte-exact one this file header's
// own SOURCING note describes.
//
// SECURITY -- CLEARTEXT CREDENTIAL EXCHANGE (this decoder's own headline curated finding, the exact
// AMQP-1.0-side analog of amqp091.hpp's own identical finding): sasl-init's own `initial-response`
// field carries the client's actual SASL credential bytes when mechanism is PLAIN (the same RFC
// 4616 `\x00` + authcid + `\x00` + passwd shape 0-9-1's own Start-Ok uses). Since this decoder only
// ever sees a sasl-init it can successfully parse in the first place on plaintext port 5672
// (amqp_common.hpp's own AMQP_TLS_PORT, 5671, is never decrypted -- see its own comment), every
// PLAIN sasl-init this decoder ever decodes is, by construction, cleartext-on-the-wire. sasl-
// response's own `response` field is ALSO treated as sensitive defensively (redacted the same way)
// even when this decoder cannot positively identify the negotiated mechanism as PLAIN -- a
// mechanism-dependent challenge/response exchange's own content is not something this decoder can
// safely assume is non-credential-bearing.
//
// REDACTION: same kRedactedSecretPlaceholder/redact_secret_occurrences convention as amqp091.hpp
// (see that file's own REDACTION section) -- sasl-init's/sasl-response's own raw bytes are never
// copied past their own length; PLAIN's own username (not the password) is additionally parsed out
// via the SAME shared helper (amqp_extract_plain_username, amqp_common.hpp) amqp091.cpp's own
// Start-Ok handling uses, since the RFC 4616 wire shape is byte-identical between the two protocols'
// own PLAIN mechanism.
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

// One decoded AMQP 1.0 primitive/described/list/map/array value -- the single generic result shape
// every reader in this file (performative fields, nested source/target/error, message sections,
// application-properties entries, array/list elements) produces and consumes. `rendered` is always
// populated (a human-readable text form, safe to place directly into a summary/note/JSON string
// field); the `as_*` accessors are populated only when the underlying primitive naturally fits that
// C++ type, and are how this file's own performative-field extraction pulls a typed value (e.g. a
// `handle` as uint64_t) out of a generically-parsed list position without re-parsing anything.
struct Amqp10Value {
    std::string rendered;
    bool is_null = false;    // constructor was 0x40 -- in a fixed list position, this means
                              // "omitted / use default", per this protocol's own documented gotcha,
                              // NOT malformed input.
    bool is_list = false;
    bool is_map = false;      // `elements` is a FLATTENED key0,value0,key1,value1,... sequence.
    bool is_array = false;    // every element shares ONE constructor, read once up front.
    bool is_described = false;  // `elements[0]` (when non-empty) is the described value itself;
                                  // `descriptor_code` is set when the descriptor was itself a
                                  // smallulong/ulong (the fast-path/performative shape).
    std::optional<int64_t> as_int;
    std::optional<uint64_t> as_uint;
    std::optional<bool> as_bool;
    std::optional<std::string> as_string;  // string/symbol/binary's own raw text/bytes.
    std::optional<uint64_t> descriptor_code;
    std::vector<Amqp10Value> elements;
};

// One named field, rendered -- the AMQP 1.0 analog of amqp091.hpp's own Amqp091Value, used for
// generic field lists (a performative's own declared fields, application-properties' own entries)
// the same "ordered list, not one hand-written struct per shape" reasoning that file's own header
// comment explains applies here too, doubly so given how many more optional/variably-typed fields
// AMQP 1.0's own performatives carry.
struct Amqp10Field {
    std::string name;
    std::string rendered;  // "<omitted>" for an absent/null fixed-position field.
};

const char* amqp10_performative_name(uint64_t code);
const char* amqp10_sasl_performative_name(uint64_t code);
const char* amqp10_message_section_name(uint64_t descriptor_code);
const char* amqp10_delivery_state_name(uint64_t descriptor_code);  // received/accepted/.../error/
                                                                     // the transaction-extension
                                                                     // types -- name-only, see SCOPE.

struct Amqp10Performative {
    uint64_t code = 0;
    const char* name = nullptr;  // performative or SASL-method name; nullptr if this decoder
                                   // doesn't recognize the code (still structurally framed).
    bool is_sasl = false;
    std::vector<Amqp10Field> fields;  // every declared field, in this performative's own order.

    // Curated, first-class fields -- see this file's own SECURITY section and amqp091.hpp's
    // identical-purpose curated fields for the parallel.
    std::optional<std::string> container_id;   // open
    std::optional<std::string> hostname;         // open
    std::optional<uint64_t> handle;               // attach/flow/transfer/disposition/detach
    std::optional<bool> role;                       // attach/disposition (false=sender,true=receiver)
    std::optional<std::string> link_name;            // attach
    std::optional<std::string> source_address;        // attach's own source.address
    std::optional<std::string> target_address;         // attach's own target.address
    std::optional<uint64_t> delivery_id;                 // transfer/disposition
    std::optional<bool> settled;
    std::optional<std::string> error_condition;           // detach/end/close/disposition's own state
    std::optional<std::string> error_description;

    // transfer only -- the message-section walk (see amqp10.hpp's own SCOPE section).
    std::vector<Amqp10Field> message_sections;  // one rendered summary per section encountered.
    std::optional<std::string> message_id;
    std::optional<std::string> correlation_id;
    std::optional<std::string> message_to;
    std::optional<std::string> subject;
    std::optional<std::string> content_type;
    std::vector<Amqp10Field> application_properties;

    // SASL curated fields.
    std::optional<std::string> sasl_mechanism;       // sasl-init.
    std::optional<size_t> sasl_response_length;        // sasl-init/sasl-response -- NEVER raw bytes.
    std::optional<std::string> sasl_username;           // sasl-init, PLAIN only, when parsed.
    bool cleartext_credentials = false;                   // mechanism is PLAIN.
    std::optional<uint8_t> sasl_outcome_code;

    std::string summary;
    std::vector<std::string> notes;
};

struct Amqp10Frame {
    uint32_t size_field = 0;   // total on-the-wire length, INCLUDES this 8-byte header.
    uint8_t doff = 0;
    uint8_t frame_type_raw = 0;
    const char* frame_type_name = nullptr;  // "AMQP" / "SASL" / "TLS", or nullptr.
    uint16_t channel = 0;
    bool is_empty = false;  // the keepalive shape: size_field==8, doff==2, zero-length body.
    bool truncated = false;
    size_t wire_length = 0;  // bytes this frame actually consumed from the candidate buffer.

    std::optional<Amqp10Performative> performative;

    std::string summary;
    std::vector<std::string> notes;
};

struct Amqp10Result {
    Amqp10Frame first;
    std::string summary;
    std::vector<std::string> notes;
};

// Parses exactly ONE frame starting at the beginning of `candidate` (the shared 8-byte connection
// preamble is handled separately, see amqp_common.hpp). Returns std::nullopt only when `candidate`
// is too short even for the fixed 8-byte frame header. Never throws.
std::optional<Amqp10Frame> try_parse_amqp10_frame(ByteSpan candidate);

// Returns the total on-the-wire byte count (the frame's own SIZE field already includes the whole
// frame, unlike 0-9-1's payload-only size) once at least the first 4 bytes are available; returns
// std::nullopt when `candidate` starts with "AMQP" but isn't this version's own preamble pattern
// (letting amqp091's own declared-length probe claim it instead), or when the header's own DOFF/
// TYPE fields (once enough bytes exist to check them) fail their structural gate.
std::optional<size_t> amqp10_tcp_declared_length(ByteSpan candidate);

class Amqp10Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "amqp10"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return AMQP_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return amqp10_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& amqp10_tcp_decoder();

}  // namespace conduitscope
