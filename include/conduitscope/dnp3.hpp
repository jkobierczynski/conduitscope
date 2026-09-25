// SPDX-License-Identifier: Apache-2.0
// dnp3.hpp - DNP3 data link, transport, and application layer decoding.
//
// DNP3 is layered (data link -> transport -> application, with per-16-byte-
// block CRCs and object-group/variation-based application data). This file
// decodes the data link and transport layers, and the application layer for
// a single, already-complete set of application-layer bytes, in a purely
// stateless way -- nothing in this file remembers anything about a
// previously seen packet. A fragment that spans more than one data-link
// frame (transport FIR=1,FIN=0 continuing across frames, each frame
// potentially arriving in its own separate TCP segment/packet) genuinely
// needs state that outlives a single frame -- which flow it belongs to, the
// bytes buffered so far, the next expected sequence number -- and that
// state lives in Dnp3Decoder (this file's own registration-model class,
// migration batch 2 -- see Dnp3ReassemblyState/Dnp3Decoder below). This file
// exposes the two pieces that state machine is built from:
// try_parse_dnp3_link_layer (data link header), reassemble_dnp3_user_data
// (per-frame block-CRC reassembly), and decode_dnp3_application_layer
// (decodes already-assembled application-layer bytes, from one frame or
// concatenated across several -- it has no idea which). The single-frame
// convenience wrapper try_parse_dnp3_transport_and_application below uses
// all three for the common case (a complete fragment in one data-link
// frame) and, for the multi-frame case, only decodes the transport header
// and stops -- it has no flow to buffer against, by design; only
// Dnp3Decoder does the cross-packet buffering. A single data-link frame
// that is itself
// a complete fragment (FIR=1,FIN=1 -- the large majority of real traffic,
// especially requests) gets full application-layer decoding: function code,
// IIN (for responses), and every object header (group/variation/qualifier/
// range). For the group/variation combinations in
// the point-format table (dnp3.cpp) -- covering the object types common in
// real traffic: Binary/Double-bit Binary/Analog/Counter Input and Output,
// CROB commands, absolute time, and Internal Indications -- each point's
// value is decoded too (state, integer, float, or CROB command fields, per
// the standard DNP3 quality-flags-byte layout, cross-checked against the
// Wireshark packet-dnp.c dissector's AL_OBJ_*_FLAG* constants). A
// group/variation outside that table still gets its object data length
// computed and skipped structurally (so later object headers in the same
// fragment stay correctly aligned), just without per-point value decoding.
//
// Data link "user data" (the transport+application bytes) is NOT contiguous
// on the wire: it is split into blocks of up to 16 bytes, each followed by
// its own 2-byte CRC (including a short final block). Dnp3LinkFrame's
// user_data_bytes is the *logical* byte count; the actual wire bytes to
// consume are more than that. try_parse_dnp3_transport_and_application
// reassembles the logical bytes (locating, and now validating, every block
// CRC) before decoding anything -- getting the reassembly itself wrong would
// silently misparse every multi-block fragment, so treat it with the same
// care as the IPv4 total-length clamp fix (see ipv4.cpp). Both the header
// CRC (try_parse_dnp3_link_layer) and every block CRC (reassemble_user_data
// in dnp3.cpp) are now actually calculated and compared against the
// on-the-wire value -- a mismatch never stops decoding (this codebase's
// consistent degrade-gracefully-and-keep-going philosophy), it is only
// recorded via Dnp3LinkFrame's crc fields and a `notes` entry with the
// specific calculated-vs-declared values.
//
// A note on ByteSpan safety: unlike every other protocol decoder here,
// Dnp3ApplicationFragment is NOT allowed to store a ByteSpan/Cursor into the
// reassembled buffer, because that buffer is a transient std::vector local
// to the parse function, not a view into the original, always-alive packet
// buffer (which is what makes ByteSpan fields safe in ModbusFrame/S7CommFrame/
// etc.). Every field below is a plain int/bool/string extracted during
// parsing, never a span over the reassembled bytes.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t DNP3_TCP_PORT = 20000;

struct Dnp3LinkFrame {
    uint8_t length_field = 0;    // raw on-the-wire length byte (control+dest+src+user data, no CRCs)
    uint8_t control = 0;
    uint16_t destination = 0;
    uint16_t source = 0;
    size_t user_data_bytes = 0;  // length_field - 5 (control+dest+src), i.e. transport+application layer size
    std::string summary;

    // Header CRC-16 (over the first 8 bytes of the data-link header: the two start bytes, length,
    // control, destination, source -- everything before the CRC field itself), calculated and
    // compared against the on-the-wire (little-endian) value at parse time by
    // try_parse_dnp3_link_layer -- see dnp3.cpp's dnp3_crc16 for the algorithm. This is the only
    // CRC check that can be done before any user data is even read, and it is the more severe of
    // the two: a bad header CRC means destination/source/control/length on this frame cannot be
    // trusted at all, unlike a bad block CRC below, which only affects that one block's data.
    bool header_crc_valid = false;
    uint16_t header_crc_calculated = 0;
    uint16_t header_crc_on_wire = 0;

    // Block CRC summary, filled in by reassemble_dnp3_user_data once it has actually read the
    // user-data blocks (there is nothing to check yet at try_parse_dnp3_link_layer time). Stays at
    // its default "no blocks" values for a link-layer-only control frame with user_data_bytes == 0
    // -- reassemble_dnp3_user_data is never even called for one, so there is genuinely nothing to
    // report beyond the header check. block_count is how many <=16-byte blocks the frame's user
    // data was split into (0 or more of them may have been impossible to fully read at all, e.g. a
    // capture truncated mid-block -- those count as failures too, see reassemble_user_data in
    // dnp3.cpp); block_crc_failures is how many of those blocks' CRCs did not validate.
    size_t block_count = 0;
    size_t block_crc_failures = 0;

    // True only once every check that could be performed -- the header CRC, and every block CRC
    // reassemble_dnp3_user_data managed to read -- passed. False for any mismatch, AND false for a
    // block whose CRC couldn't even be checked because the capture was truncated first (an
    // unverifiable CRC is never treated as valid). Set to header_crc_valid at parse time (the best
    // information available before any user data has been read -- already the final answer for a
    // frame with no user data at all), then narrowed by reassemble_dnp3_user_data (ANDing in the
    // block result) once/if that runs. Repurposed from always-false in an earlier groundwork
    // release -- see dnp3.cpp's dnp3_crc16 for the actual CRC-16 algorithm (table-driven,
    // reflected, seed 0, final complement -- verified against Wireshark's wsutil/crc16.c and the
    // standard CRC-16/DNP reference test vector via a compile-time static_assert right next to it).
    bool crc_validated = false;
};

// Returns std::nullopt (never throws) if `tcp_payload` does not start with the
// DNP3 data link start bytes (0x05 0x64) or is too short to hold a full data
// link header. Calculates and validates the header CRC (see
// Dnp3LinkFrame::header_crc_valid/crc_validated above), appending a specific
// calculated-vs-declared note to `notes` on a mismatch -- decoding still
// proceeds regardless (this codebase's consistent degrade-gracefully
// philosophy), the mismatch is only recorded, never fatal.
std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload, std::vector<std::string>& notes);

// Returns every canonical DNP3 application-layer function name this decoder can produce for a
// KNOWN function code (every case dnp3.cpp's internal function-code table defines, including the
// three response codes 0x81/0x82/0x83) -- excluding the dynamic "Unknown (0xNN)" fallback used for
// a function code outside that table. Used by policy.cpp to validate a policy file's 'functions:'
// entries for a dnp3-restricted conduit against exactly the strings
// Dnp3ApplicationFragment::function_name/DecodedPacket::dnp3_function_name can actually hold.
// Order is stable across calls (the table's own declaration order) but not alphabetized.
std::vector<std::string> dnp3_known_function_names();

// Total on-the-wire size of one DNP3 data-link frame: the fixed 10-byte header, plus its user
// data broken into <=16-byte blocks, each followed by its own 2-byte block CRC. Used to find
// where the *next* data-link frame (if any) starts within the same TCP payload (Decoder's
// same-payload frame-coalescing loop), and, via dnp3_link_frame_declared_length below, to detect
// a frame truncated across a TCP segment boundary before it's even been fully parsed.
size_t dnp3_frame_wire_length(const Dnp3LinkFrame& link);

// Returns the total on-the-wire byte count one DNP3 data-link frame declares (the same
// computation as dnp3_frame_wire_length, applied to the raw length field) if `payload` has enough
// bytes to read that field (>= 3, i.e. the two start bytes plus the length byte) and starts with
// the DNP3 magic bytes (0x05 0x64) -- regardless of whether `payload` actually holds that many
// bytes yet; that's the point, so a caller can tell a truncated-but-recognized frame from one
// that's actually complete. Returns std::nullopt if there aren't yet enough bytes to tell (< 3) or
// the magic bytes don't match (definitely not DNP3). try_parse_dnp3_link_layer itself is
// unchanged and still requires a full 10-byte header before recognizing a frame at all; this is
// used only for detecting truncation across a TCP segment boundary -- see
// Decoder::reassemble_tcp_payload in decoder.cpp.
std::optional<size_t> dnp3_link_frame_declared_length(ByteSpan payload);

// Reassembles one data-link frame's user data -- transport header byte plus whatever application-
// layer bytes follow it -- locating and validating the per-16-byte-block CRCs described in the
// file header comment. `link` must be the result of a preceding successful try_parse_dnp3_link_layer
// call on the same `tcp_payload`; it is taken by non-const reference because this is also where
// link.block_count/block_crc_failures/crc_validated get their final values (ANDing the block result
// into the header result already set by try_parse_dnp3_link_layer) -- see Dnp3LinkFrame's own
// comment. Returns an empty vector if link.user_data_bytes == 0 (a data-link frame with no user
// data at all) WITHOUT touching link's block_* fields (there is nothing to check -- see
// Dnp3LinkFrame's comment on why that case is fine). Exposed (rather than kept internal to
// try_parse_dnp3_transport_and_application) so Decoder can get at one frame's transport byte and
// application-layer bytes on their own, to buffer them across packets when a fragment spans more
// than one data-link frame -- see the file header comment. Appends to `notes` on truncation and on
// any block CRC mismatch (calculated-vs-declared values), same degrade-gracefully-and-keep-going
// philosophy as every other malformed-input case in this file.
std::vector<uint8_t> reassemble_dnp3_user_data(Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                std::vector<std::string>& notes);

// One decoded point value within an object header's object data.
struct Dnp3PointValue {
    uint32_t index = 0;         // the point/object index this value belongs to
    // True when `index` was read from an explicit index-prefix byte on the wire (qualifier
    // prefix code 1/2/3). False when it's inferred instead -- from range_start+position for a
    // start-stop range (still reliable), or just a 0-based position for a bare explicit-count
    // qualifier with no index prefix (rare on the wire; genuinely not knowable in that case).
    bool index_is_explicit = false;
    std::string value;              // short human-readable rendering, e.g. "1", "23.5", "Close"
    std::vector<std::string> flags;  // decoded quality-flags names, empty if this format has none
};

// One object header from the application layer's object list: group,
// variation, qualifier, the range/count it decodes to, how much object data
// that implies, and -- for a recognized group/variation -- every point's
// decoded value.
struct Dnp3ObjectHeader {
    uint8_t group = 0;
    uint8_t variation = 0;
    std::string group_name;  // e.g. "Binary Input", or "Unknown (group NN)"

    uint8_t qualifier = 0;
    uint8_t prefix_code = 0;  // qualifier >> 4: 0=none, 1/2/3=1/2/4-byte index prefix, 4-7=unsupported
    uint8_t range_code = 0;   // qualifier & 0x0F

    // True when range_code is a start-stop form (0x00/0x01/0x02); range_start/range_stop are
    // then the decoded bounds (inclusive) and point_count = range_stop - range_start + 1.
    bool has_range = false;
    uint32_t range_start = 0;
    uint32_t range_stop = 0;

    // Number of objects/points this header addresses: from range_stop-range_start+1 (start-stop
    // qualifiers), the explicit count field (0x07/0x08/0x09 qualifiers), or 0 for range_code 0x06
    // ("all"/no range, e.g. a Class 0 poll -- carries no object data by definition).
    uint32_t point_count = 0;

    // Bytes of object data (index prefixes + values, combined) this header's objects occupy on
    // the wire -- computed from point_count and a group/variation point-size table, then skipped
    // structurally rather than decoded value-by-value. Only meaningful when `decoded` is true.
    size_t object_data_bytes = 0;

    // False when this header's shape wasn't understood well enough to know how many bytes to
    // skip (unsupported prefix code, unknown group/variation, unsupported range code, a packed
    // format combined with an index prefix, or a declared length exceeding what's left in the
    // fragment) -- in every such case, `note` explains why and no further object headers in this
    // fragment are parsed (the byte offset of anything past this point can no longer be trusted).
    bool decoded = true;
    std::string note;

    // One entry per point once `decoded` is true and point_count > 0, capped (very large batched
    // requests, e.g. thousands of analog points, keep their object_data_bytes fully accounted for
    // but only the first entries get an individual Dnp3PointValue -- see kMaxDecodedPointsPerHeader
    // in dnp3.cpp). Empty when the group/variation isn't in the point-format table -- the object
    // data was still located and skipped by computed length, just not interpreted value-by-value.
    std::vector<Dnp3PointValue> values;
};

struct Dnp3ApplicationFragment {
    // Transport header (1 byte, always present when the data-link frame carries any user data):
    // bit7=FIR, bit6=FIN, bits5-0=SEQ.
    bool has_transport = false;
    bool transport_fir = false;
    bool transport_fin = false;
    uint8_t transport_seq = 0;

    // True once the application-layer bytes -- whether from a single complete data-link frame
    // (transport_fir && transport_fin) or reassembled by Decoder across several (see the file
    // header comment) -- were present and well-formed enough to decode at least the control byte
    // and function code. False while a multi-frame fragment is still incomplete, or for a
    // malformed/truncated one; `notes` explains which.
    bool application_decoded = false;
    uint8_t app_control = 0;
    bool app_fir = false, app_fin = false, app_con = false, app_uns = false;
    uint8_t app_seq = 0;  // bits 3-0 of app_control

    bool has_function = false;
    uint8_t function_code = 0;
    std::string function_name;  // e.g. "Read", "Response", or "Unknown (0xNN)"

    // Only set for a response function code (0x81 Response, 0x82 Unsolicited Response, 0x83
    // Authentication Response), which carry a 2-byte Internal Indications field right after the
    // function code.
    bool has_iin = false;
    uint16_t iin = 0;               // wire value: low byte IIN1, high byte IIN2 (little-endian)
    std::vector<std::string> iin_flags;  // names of every set IIN1/IIN2 bit, empty if iin == 0

    std::vector<Dnp3ObjectHeader> objects;

    std::string summary;
    std::vector<std::string> notes;
};

// Reassembles the data-link frame's user data (locating and validating the per-16-byte-block CRCs
// -- see the file header comment and Dnp3LinkFrame's own comment; `link` is taken by non-const
// reference for the same reason as reassemble_dnp3_user_data's -- its block_count/
// block_crc_failures/crc_validated fields are finalized here), then decodes the transport header
// and, for a complete single-frame fragment, the application layer on top of it via
// decode_dnp3_application_layer. `link` must be the result of a preceding successful
// try_parse_dnp3_link_layer call on the same `tcp_payload`. Returns std::nullopt only when
// link.user_data_bytes == 0 (a data-link frame with no user data at all, e.g. a link-layer-only
// control frame) -- there is nothing above the data link layer to decode in that case (link's
// crc_validated is already final in this case too, set by try_parse_dnp3_link_layer itself). Never
// throws: a reassembly or application-layer shape it cannot make sense of is recorded in `notes` on
// the returned fragment rather than propagated as a ParseError, since the data link layer itself
// was already valid.
//
// This is the single-frame convenience path: for a fragment spanning more than one data-link
// frame (transport_fir && !transport_fin), it decodes only the transport header and stops, same
// as always -- it has no per-flow state to buffer the rest against. Dnp3Decoder (below) uses the
// two functions above/below directly, with its own per-TCP-flow buffering, to reassemble and
// decode that case -- that is the only thing that actually performs cross-packet reassembly in
// this codebase.
std::optional<Dnp3ApplicationFragment> try_parse_dnp3_transport_and_application(Dnp3LinkFrame& link,
                                                                                 ByteSpan tcp_payload);

// Decodes the application layer -- control byte, function code, IIN (for responses), and every
// object header/point value -- from `app_bytes`, which must already be fully assembled: either one
// data-link frame's own bytes after its transport header (the single-frame case), or several
// frames' such bytes concatenated in sequence-number order (a fragment reassembled across multiple
// data-link frames -- see the file header comment; only Decoder builds this concatenation). Writes
// into `frag`'s application-layer fields (app_control, has_function, iin, objects, ...) and appends
// to `frag.notes`; does NOT touch `frag`'s transport_*/has_transport fields, which the caller must
// already have set -- `frag.summary` is set to a summary of only the application layer, which
// callers combine with their own transport-layer summary. Handles `app_bytes.empty()` (a
// transport header with nothing after it) by recording that in `frag.notes` and leaving
// application_decoded false, same as every other malformed-application-layer case. Never throws.
void decode_dnp3_application_layer(ByteSpan app_bytes, Dnp3ApplicationFragment& frag);

// Migration batch 2 (see protocol_decoder.hpp/protocol_registry.hpp): cross-packet DNP3
// application-fragment reassembly state for one directional TCP flow, replacing what used to live
// as decoder.hpp's Dnp3FragmentReassembly struct / Decoder::dnp3_reassembly_ member. Reached via
// DecodeContext::flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow) -- directional,
// not session-keyed, because each TCP direction reassembles its own fragment independently (see
// FlowStateKeying's own comment in protocol_decoder.hpp for why that matters: nothing stops a DNP3
// session from having client->outstation and outstation->client fragments in flight at once).
class Dnp3ReassemblyState : public DecoderFlowState {
public:
    bool in_progress = false;
    std::vector<uint8_t> buffered_app_bytes;  // concatenated post-transport-byte bytes so far
    uint8_t last_seq = 0;                     // transport SEQ of the most recently buffered frame
    size_t frame_count = 0;                   // data-link frames contributed so far
};

// Everything decoder.cpp's DNP3 call site dual-writes into DecodedPacket, gathered from however
// many data-link frames were coalesced in one TCP payload (see Dnp3Decoder::decode below) --
// mirrors exactly what the pre-migration call site computed locally before this batch. `summary`
// and `notes` are the fully-assembled headline summary (data-link + first frame's application
// layer) and note list, in the same order the legacy call site produced them; the four crc/address
// fields reflect only the FIRST data-link frame found in the payload (same "first frame only"
// convention DecodedPacket::dnp3_link_crc_valid's own comment documents), the object-header/point-
// value lists are the same cumulative-across-every-frame-in-the-payload lists the legacy call site
// built, capped at 50 entries each exactly as before.
// One object header's numeric group/variation/range data, the structured twin of the display
// string dnp3_object_headers above already renders ("g1v2 (Binary Input)") -- added for the
// baseline engine (roadmap item 41 phase 2, docs/design/baseline-engine.md), which needs the real
// numbers back, not a string to parse them out of again (see baseline.cpp's extract_dnp3_operations
// for why: reliably regexing a rendered display string is exactly the anti-pattern this codebase
// already rejected for Modbus, see ModbusFrame::start_address/quantity's own comment). Mirrors
// Dnp3ObjectHeader's own group/variation/has_range/range_start/range_stop fields exactly, one entry
// per header in the same order/cap as dnp3_object_headers (see Dnp3Decoder::decode).
struct Dnp3ObjectRange {
    uint8_t group = 0;
    uint8_t variation = 0;
    std::string group_name;
    // True only when this header both used a start-stop range qualifier (Dnp3ObjectHeader::
    // has_range) AND was itself fully decoded (Dnp3ObjectHeader::decoded) -- an object header whose
    // own shape wasn't understood well enough to skip correctly (see Dnp3ObjectHeader::decoded's own
    // comment) has no trustworthy range_start/range_stop, so this stays false for it even if
    // has_range looked set before parsing bailed.
    bool has_range = false;
    uint32_t range_start = 0;
    uint32_t range_stop = 0;  // inclusive, per Dnp3ObjectHeader's own convention
};

struct Dnp3Result {
    std::string summary;
    std::vector<std::string> notes;

    bool dnp3_has_function = false;
    std::string dnp3_function_name;
    std::vector<std::string> dnp3_object_headers;
    std::vector<std::string> dnp3_point_values;
    std::vector<Dnp3ObjectRange> dnp3_objects;  // see Dnp3ObjectRange's own comment above

    bool link_crc_valid = false;
    bool header_crc_valid = false;
    size_t block_count = 0;
    size_t block_crc_failures = 0;
    uint16_t source_address = 0;
    uint16_t destination_address = 0;
};

// id() == "dnp3", gate_kind() == TcpPortIndependent. Wraps try_parse_dnp3_link_layer plus ALL the
// cross-packet fragment-reassembly logic that used to live in decoder.cpp's
// Decoder::process_dnp3_frame (now removed) and the same-payload multi-frame-coalescing loop that
// used to live directly in decoder.cpp's `if (want_dnp3)` call site -- both folded into decode()
// below, so decoder.cpp's own call site is now just: gate, call, dual-write. Returns std::nullopt
// exactly when try_parse_dnp3_link_layer itself would (payload doesn't start with a recognized
// DNP3 data-link header) -- a link-layer-only control frame with no user data still returns a
// result (matching the legacy call site's behavior: it always set out.protocol = "dnp3" once the
// data-link header parsed, regardless of whether there was any user data above it).
class Dnp3Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "dnp3"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return dnp3_link_frame_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;

private:
    // One data-link frame's transport header and, once its fragment is complete, application
    // layer -- buffering across packets via ctx.flow_state<Dnp3ReassemblyState>(DirectionalFlow)
    // when the fragment spans more than one data-link frame (transport FIR=1,FIN=0 on an earlier
    // frame). Exact behavioral transplant of the removed Decoder::process_dnp3_frame -- see
    // dnp3.cpp for the full reassembly state machine and its comments. Same nullopt contract as
    // try_parse_dnp3_transport_and_application: only when link.user_data_bytes == 0. `link` is
    // non-const: this is where link.block_count/block_crc_failures/crc_validated get their final
    // values (see reassemble_dnp3_user_data/Dnp3LinkFrame's own comments above).
    std::optional<Dnp3ApplicationFragment> process_frame(Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                           DecodeContext& ctx) const;
};

const ProtocolDecoder& dnp3_decoder();

}  // namespace conduitscope
