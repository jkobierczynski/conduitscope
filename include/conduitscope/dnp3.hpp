// SPDX-License-Identifier: MIT
// dnp3.hpp - DNP3 data link, transport, and application layer decoding.
//
// DNP3 is layered (data link -> transport -> application, with per-16-byte-
// block CRCs and object-group/variation-based application data). This file
// decodes all three layers with one real scope limit: a fragment that spans
// more than one data-link frame (transport FIR=1,FIN=0 continuing across
// frames) only gets its transport header decoded, not its application layer
// -- reassembling an application fragment across multiple TCP-carried
// data-link frames is out of scope for the same reason whole-stream TCP
// reassembly is (see decoder.hpp): it would require tracking state across
// packets, which this tool deliberately does not do. A single data-link
// frame that is itself a complete fragment (FIR=1,FIN=1 -- the large
// majority of real traffic, especially requests) gets full application-layer
// decoding: function code, IIN (for responses), and every object header
// (group/variation/qualifier/range). For the group/variation combinations in
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
// reassembles the logical bytes (locating and skipping, but not validating,
// every block CRC) before decoding anything -- getting this wrong would
// silently misparse every multi-block fragment, so treat it with the same
// care as the IPv4 total-length clamp fix (see ipv4.cpp).
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

namespace conduitscope {

constexpr uint16_t DNP3_TCP_PORT = 20000;

struct Dnp3LinkFrame {
    uint8_t length_field = 0;    // raw on-the-wire length byte (control+dest+src+user data, no CRCs)
    uint8_t control = 0;
    uint16_t destination = 0;
    uint16_t source = 0;
    size_t user_data_bytes = 0;  // length_field - 5 (control+dest+src), i.e. transport+application layer size
    std::string summary;
    bool crc_validated = false;  // always false in this release -- see notes below
};

// Returns std::nullopt (never throws) if `tcp_payload` does not start with the
// DNP3 data link start bytes (0x05 0x64) or is too short to hold a full data
// link header. Does NOT validate the header CRC -- that is not implemented in
// this groundwork release, and the summary/notes say so explicitly rather
// than silently skipping the check.
std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload);

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

    // True only when transport_fir && transport_fin (a complete, single-frame fragment) and the
    // application-layer bytes were present and well-formed enough to decode at least the control
    // byte and function code. False for a multi-frame-spanning fragment (transport_fin false) --
    // see the file header comment -- or a malformed/truncated one; `notes` explains which.
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

// Reassembles the data-link frame's user data (stripping, not validating, the per-16-byte-block
// CRCs -- see the file header comment), then decodes the transport header and, for a complete
// single-frame fragment, the application layer on top of it. `link` must be the result of a
// preceding successful try_parse_dnp3_link_layer call on the same `tcp_payload`. Returns
// std::nullopt only when link.user_data_bytes == 0 (a data-link frame with no user data at all,
// e.g. a link-layer-only control frame) -- there is nothing above the data link layer to decode
// in that case. Never throws: a reassembly or application-layer shape it cannot make sense of is
// recorded in `notes` on the returned fragment rather than propagated as a ParseError, since the
// data link layer itself was already valid.
std::optional<Dnp3ApplicationFragment> try_parse_dnp3_transport_and_application(const Dnp3LinkFrame& link,
                                                                                 ByteSpan tcp_payload);

}  // namespace conduitscope
