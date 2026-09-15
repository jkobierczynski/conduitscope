// SPDX-License-Identifier: MIT
#include "conduitscope/dnp3.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

namespace conduitscope {

namespace {

std::string hex8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

std::string hex16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setw(4) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

std::string dnp3_function_name(uint8_t fc) {
    switch (fc) {
        case 0x00: return "Confirm";
        case 0x01: return "Read";
        case 0x02: return "Write";
        case 0x03: return "Select";
        case 0x04: return "Operate";
        case 0x05: return "Direct Operate";
        case 0x06: return "Direct Operate No Ack";
        case 0x07: return "Immediate Freeze";
        case 0x08: return "Immediate Freeze No Ack";
        case 0x09: return "Freeze Clear";
        case 0x0A: return "Freeze Clear No Ack";
        case 0x0B: return "Freeze At Time";
        case 0x0C: return "Freeze At Time No Ack";
        case 0x0D: return "Cold Restart";
        case 0x0E: return "Warm Restart";
        case 0x0F: return "Initialize Data";
        case 0x10: return "Initialize Application";
        case 0x11: return "Start Application";
        case 0x12: return "Stop Application";
        case 0x13: return "Save Configuration";
        case 0x14: return "Enable Unsolicited Responses";
        case 0x15: return "Disable Unsolicited Responses";
        case 0x16: return "Assign Classes";
        case 0x17: return "Delay Measurement";
        case 0x18: return "Record Current Time";
        case 0x19: return "Open File";
        case 0x1A: return "Close File";
        case 0x1B: return "Delete File";
        case 0x1C: return "Get File Info";
        case 0x1D: return "Authenticate File";
        case 0x1E: return "Abort File";
        case 0x1F: return "Activate Config";
        case 0x20: return "Authentication Request";
        case 0x21: return "Authentication Error";
        case 0x81: return "Response";
        case 0x82: return "Unsolicited Response";
        case 0x83: return "Authentication Response";
        default: return "Unknown (" + hex8(fc) + ")";
    }
}

bool is_response_function(uint8_t fc) { return fc == 0x81 || fc == 0x82 || fc == 0x83; }

std::string dnp3_group_name(uint8_t group) {
    switch (group) {
        case 1: return "Binary Input";
        case 2: return "Binary Input Event";
        case 3: return "Double-bit Binary Input";
        case 4: return "Double-bit Binary Input Event";
        case 10: return "Binary Output";
        case 11: return "Binary Output Event";
        case 12: return "Binary Output Command (CROB)";
        case 20: return "Counter";
        case 21: return "Frozen Counter";
        case 22: return "Counter Event";
        case 23: return "Frozen Counter Event";
        case 30: return "Analog Input";
        case 31: return "Frozen Analog Input";
        case 32: return "Analog Input Event";
        case 33: return "Frozen Analog Input Event";
        case 34: return "Analog Input Reporting Deadband";
        case 40: return "Analog Output Status";
        case 41: return "Analog Output";
        case 42: return "Analog Output Event";
        case 50: return "Time and Date";
        case 51: return "Time and Date CTO";
        case 52: return "Time Delay";
        case 60: return "Class Objects";
        case 70: return "File Control";
        case 80: return "Internal Indications";
        case 110: return "Octet String";
        case 111: return "Octet String Event";
        default: return "Unknown (group " + std::to_string(group) + ")";
    }
}

// What a group/variation's point data looks like, beyond just its length: which standard
// DNP3 quality-flags-byte family it uses (if any), what the value itself is, and whether a
// 6-byte absolute-time trailer follows it (the standard "with time" event variant shape).
// bits_per_point matches exactly what the structural-skip logic used before per-point value
// decoding existed, so object_data_bytes is unchanged; PointFormat only adds how to interpret
// those same bytes.
enum class Dnp3ValueKind {
    None,            // no interpretable value (e.g. an unrecognized shape -- shown as raw hex)
    PackedBit,       // 1 bit/point: 0 or 1 (or, for group 80, an IIN flag name -- see decode below)
    PackedDoubleBit,       // 2 bits/point: the standard 4-state double-bit-binary enum
    BinaryState,            // state bit embedded in a flags byte (Binary Input/Output w/ flags)
    DoubleBitStateInFlags,  // 2-bit state embedded in a flags byte (Double-bit Binary w/ flags)
    Int16,
    Int32,
    Float32,
    Float64,
    Crob,             // Control Relay Output Block (group 12 var 1)
    AbsoluteTime48,   // 48-bit, little-endian, milliseconds-since-epoch
};

enum class Dnp3FlagFamily { None, BinaryInput, BinaryOutput, Counter, Analog };

struct Dnp3PointFormat {
    uint16_t bits_per_point = 0;
    Dnp3FlagFamily flags = Dnp3FlagFamily::None;
    Dnp3ValueKind value_kind = Dnp3ValueKind::None;
    bool has_time_trailer = false;  // a 6-byte absolute time follows the value (event "w/ time" variants)
};

// Point format for the group/variation combinations common enough in real traffic to decode with
// confidence. A combination not listed here is genuinely out of scope, not a bug -- see the
// "unknown group/variation" bailout in the object-header loop below. bits_per_point < 8 means
// bit-packed (see is_packed below); everything else is a whole number of bytes. Flags-byte bit
// layout and the CROB field layout are cross-checked against the Wireshark packet-dnp.c
// dissector's AL_OBJ_BI_FLAG*/AL_OBJ_CTR_FLAG*/AL_OBJ_AI_FLAG*/AL_OBJCTLC_* constants, not
// reverse-engineered from a single capture -- unlike the S7comm 0xB2 EXPERIMENTAL decode, these
// are the documented, standard DNP3 wire formats.
bool point_format(uint8_t group, uint8_t variation, Dnp3PointFormat& fmt) {
    using VK = Dnp3ValueKind;
    using FF = Dnp3FlagFamily;
    switch ((static_cast<uint16_t>(group) << 8) | variation) {
        case (1u << 8) | 1: fmt = {1, FF::None, VK::PackedBit, false}; return true;
        case (1u << 8) | 2: fmt = {8, FF::BinaryInput, VK::BinaryState, false}; return true;
        case (3u << 8) | 1: fmt = {2, FF::None, VK::PackedDoubleBit, false}; return true;
        case (3u << 8) | 2: fmt = {8, FF::BinaryInput, VK::DoubleBitStateInFlags, false}; return true;
        case (10u << 8) | 1: fmt = {1, FF::None, VK::PackedBit, false}; return true;
        case (10u << 8) | 2: fmt = {8, FF::BinaryOutput, VK::BinaryState, false}; return true;
        case (12u << 8) | 1: fmt = {88, FF::None, VK::Crob, false}; return true;
        case (20u << 8) | 1: fmt = {40, FF::Counter, VK::Int32, false}; return true;
        case (20u << 8) | 2: fmt = {24, FF::Counter, VK::Int16, false}; return true;
        case (20u << 8) | 5: fmt = {32, FF::None, VK::Int32, false}; return true;
        case (20u << 8) | 6: fmt = {16, FF::None, VK::Int16, false}; return true;
        case (21u << 8) | 1: fmt = {40, FF::Counter, VK::Int32, false}; return true;
        case (21u << 8) | 2: fmt = {24, FF::Counter, VK::Int16, false}; return true;
        case (21u << 8) | 5: fmt = {32, FF::None, VK::Int32, false}; return true;
        case (21u << 8) | 6: fmt = {16, FF::None, VK::Int16, false}; return true;
        case (22u << 8) | 1: fmt = {40, FF::Counter, VK::Int32, false}; return true;
        case (22u << 8) | 2: fmt = {24, FF::Counter, VK::Int16, false}; return true;
        case (22u << 8) | 5: fmt = {88, FF::Counter, VK::Int32, true}; return true;
        case (22u << 8) | 6: fmt = {72, FF::Counter, VK::Int16, true}; return true;
        case (23u << 8) | 1: fmt = {40, FF::Counter, VK::Int32, false}; return true;
        case (23u << 8) | 2: fmt = {24, FF::Counter, VK::Int16, false}; return true;
        case (23u << 8) | 5: fmt = {88, FF::Counter, VK::Int32, true}; return true;
        case (23u << 8) | 6: fmt = {72, FF::Counter, VK::Int16, true}; return true;
        case (30u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (30u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (30u << 8) | 3: fmt = {32, FF::None, VK::Int32, false}; return true;
        case (30u << 8) | 4: fmt = {16, FF::None, VK::Int16, false}; return true;
        case (30u << 8) | 5: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (30u << 8) | 6: fmt = {72, FF::Analog, VK::Float64, false}; return true;
        case (31u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (31u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (31u << 8) | 3: fmt = {32, FF::None, VK::Int32, false}; return true;
        case (31u << 8) | 4: fmt = {16, FF::None, VK::Int16, false}; return true;
        case (31u << 8) | 5: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (31u << 8) | 6: fmt = {72, FF::Analog, VK::Float64, false}; return true;
        case (32u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (32u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (32u << 8) | 3: fmt = {88, FF::Analog, VK::Int32, true}; return true;
        case (32u << 8) | 4: fmt = {72, FF::Analog, VK::Int16, true}; return true;
        case (32u << 8) | 5: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (32u << 8) | 7: fmt = {88, FF::Analog, VK::Float32, true}; return true;
        case (33u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (33u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (33u << 8) | 3: fmt = {88, FF::Analog, VK::Int32, true}; return true;
        case (33u << 8) | 4: fmt = {72, FF::Analog, VK::Int16, true}; return true;
        case (33u << 8) | 5: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (33u << 8) | 7: fmt = {88, FF::Analog, VK::Float32, true}; return true;
        case (40u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (40u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (40u << 8) | 3: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (41u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (41u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (41u << 8) | 3: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (42u << 8) | 1: fmt = {40, FF::Analog, VK::Int32, false}; return true;
        case (42u << 8) | 2: fmt = {24, FF::Analog, VK::Int16, false}; return true;
        case (42u << 8) | 3: fmt = {40, FF::Analog, VK::Float32, false}; return true;
        case (50u << 8) | 1: fmt = {48, FF::None, VK::AbsoluteTime48, false}; return true;
        case (80u << 8) | 1: fmt = {1, FF::None, VK::PackedBit, false}; return true;
        default: return false;
    }
    // Group 60 (Class Objects) intentionally has no entries: every real-world use pairs it with
    // range_code 0x06 ("all"/no range), which carries zero object data by definition and never
    // reaches this lookup -- see the range_code handling in the object-header loop.
}

bool is_packed(uint16_t bits_per_point) { return bits_per_point < 8; }

// Standard DNP3 quality-flags byte, bits 0-4 shared across every object family that has one;
// bits 5-6 differ by family (see Dnp3FlagFamily); bit 7 is reserved except for the Binary
// Input/Output families, where it (and, for Double-bit Binary, bit 6 too) carries the point's
// value instead of a flag -- see decode_binary_state/decode_double_bit_state, which read those
// bits directly rather than through this table.
std::vector<std::string> flag_names(uint8_t flags, Dnp3FlagFamily family) {
    std::vector<std::string> names;
    if (flags & 0x01) names.push_back("ONLINE");
    if (flags & 0x02) names.push_back("RESTART");
    if (flags & 0x04) names.push_back("COMM_LOST");
    if (flags & 0x08) names.push_back("REMOTE_FORCED");
    if (flags & 0x10) names.push_back("LOCAL_FORCED");
    switch (family) {
        case Dnp3FlagFamily::BinaryInput:
            if (flags & 0x20) names.push_back("CHATTER_FILTER");
            break;
        case Dnp3FlagFamily::Counter:
            if (flags & 0x20) names.push_back("ROLLOVER");
            if (flags & 0x40) names.push_back("DISCONTINUITY");
            break;
        case Dnp3FlagFamily::Analog:
            if (flags & 0x20) names.push_back("OVER_RANGE");
            if (flags & 0x40) names.push_back("REFERENCE_ERR");
            break;
        default:
            break;
    }
    return names;
}

std::string double_bit_state_name(uint8_t v) {
    switch (v & 0x3) {
        case 0: return "Intermediate";
        case 1: return "DeterminedOff";
        case 2: return "DeterminedOn";
        default: return "Indeterminate";
    }
}

int32_t sign_extend(uint32_t v, unsigned bits) {
    uint32_t m = 1u << (bits - 1);
    return static_cast<int32_t>((v ^ m) - m);
}

// 6-byte, little-endian, milliseconds-since-epoch -- the standard DNP3 absolute time format.
// Rendered as the raw millisecond count rather than a calendar date: converting correctly needs
// UTC-safe 64-bit time handling this tool doesn't otherwise depend on, and the raw count is
// still directly useful (diffable, sortable) without risking a subtly wrong date rendering.
std::string decode_absolute_time48(Cursor& c) {
    uint64_t ms = 0;
    for (int i = 0; i < 6; ++i) ms |= static_cast<uint64_t>(c.u8()) << (8 * i);
    return std::to_string(ms) + "ms-since-epoch";
}

std::string crob_control_code_name(uint8_t code) {
    switch (code) {
        case 0x00: return "NUL";
        case 0x01: return "Pulse On";
        case 0x02: return "Pulse Off";
        case 0x03: return "Latch On";
        case 0x04: return "Latch Off";
        default: return "Unknown (" + hex8(code) + ")";
    }
}

std::string crob_trip_close_name(uint8_t tc) {
    switch (tc) {
        case 0x00: return "NUL";
        case 0x01: return "Close";
        case 0x02: return "Trip";
        default: return "Reserved";
    }
}

// IEEE 1815 Table "Control Status Codes" (cross-checked against Wireshark's packet-dnp.c status
// value strings). Codes not listed are shown as raw hex rather than guessed at.
std::string crob_status_name(uint8_t status) {
    switch (status) {
        case 0x00: return "Success";
        case 0x01: return "Timeout";
        case 0x02: return "No Select";
        case 0x03: return "Format Error";
        case 0x04: return "Not Supported";
        case 0x05: return "Already Active";
        case 0x06: return "Hardware Error";
        case 0x07: return "Local";
        case 0x08: return "Too Many Ops";
        case 0x09: return "Not Authorized";
        case 0x0A: return "Automation Inhibit";
        case 0x0B: return "Processing Limited";
        case 0x0C: return "Out Of Range";
        case 0x7E: return "Non-Participating";
        case 0x7F: return "Undefined Error";
        default: return "Unknown (" + hex8(status) + ")";
    }
}

// Decodes one point's value/flags from `point_bytes` (already sliced to exactly this point's
// value -- no index prefix, no other points). Only called for a `fmt.value_kind` that isn't
// PackedBit/PackedDoubleBit (those are bit-level across the whole object, decoded separately in
// the caller) or None (nothing to decode).
Dnp3PointValue decode_point_value(const Dnp3PointFormat& fmt, ByteSpan point_bytes) {
    Dnp3PointValue pv;
    Cursor c(point_bytes);
    std::ostringstream val;

    if (fmt.flags != Dnp3FlagFamily::None && fmt.value_kind != Dnp3ValueKind::BinaryState &&
        fmt.value_kind != Dnp3ValueKind::DoubleBitStateInFlags) {
        pv.flags = flag_names(c.u8(), fmt.flags);
    }

    switch (fmt.value_kind) {
        case Dnp3ValueKind::BinaryState: {
            uint8_t b = c.u8();
            pv.flags = flag_names(b, fmt.flags);
            val << ((b & 0x80) ? 1 : 0);
            break;
        }
        case Dnp3ValueKind::DoubleBitStateInFlags: {
            uint8_t b = c.u8();
            pv.flags = flag_names(b, fmt.flags);
            val << double_bit_state_name((b >> 6) & 0x3);
            break;
        }
        case Dnp3ValueKind::Int16: {
            val << sign_extend(c.u16le(), 16);
            break;
        }
        case Dnp3ValueKind::Int32: {
            val << sign_extend(c.u32le(), 32);
            break;
        }
        case Dnp3ValueKind::Float32: {
            uint32_t bits = c.u32le();
            float f;
            std::memcpy(&f, &bits, sizeof(f));
            val << f;
            break;
        }
        case Dnp3ValueKind::Float64: {
            uint64_t bits = 0;
            for (int i = 0; i < 8; ++i) bits |= static_cast<uint64_t>(c.u8()) << (8 * i);
            double d;
            std::memcpy(&d, &bits, sizeof(d));
            val << d;
            break;
        }
        case Dnp3ValueKind::AbsoluteTime48: {
            val << decode_absolute_time48(c);
            break;
        }
        case Dnp3ValueKind::Crob: {
            uint8_t control = c.u8();
            uint8_t code = control & 0x0F;
            uint8_t misc = (control >> 4) & 0x03;
            uint8_t tc = (control >> 6) & 0x03;
            uint8_t count = c.u8();
            uint32_t on_time = c.u32le();
            uint32_t off_time = c.u32le();
            uint8_t status = c.u8();
            val << "code=" << crob_control_code_name(code) << " tc=" << crob_trip_close_name(tc)
                << " queue/clear=" << hex8(misc) << " count=" << static_cast<unsigned>(count)
                << " on_time=" << on_time << "ms off_time=" << off_time
                << "ms status=" << crob_status_name(status);
            break;
        }
        case Dnp3ValueKind::PackedBit:
        case Dnp3ValueKind::PackedDoubleBit:
        case Dnp3ValueKind::None:
        default:
            break;
    }

    if (fmt.has_time_trailer && c.remaining() >= 6) {
        val << " @ " << decode_absolute_time48(c);
    }

    pv.value = val.str();
    return pv;
}

struct IinFlag {
    uint16_t mask;
    const char* name;
};

// IIN1 occupies the low byte of the 16-bit field (transmitted first, per the little-endian
// convention DNP3 uses for every multi-byte field), IIN2 the high byte.
constexpr IinFlag kIinFlags[] = {
    {0x0001, "ALL_STATIONS"},        {0x0002, "CLASS_1_EVENTS"},   {0x0004, "CLASS_2_EVENTS"},
    {0x0008, "CLASS_3_EVENTS"},      {0x0010, "NEED_TIME"},        {0x0020, "LOCAL_CONTROL"},
    {0x0040, "DEVICE_TROUBLE"},      {0x0080, "DEVICE_RESTART"},   {0x0100, "FUNC_NOT_SUPPORTED"},
    {0x0200, "OBJECT_UNKNOWN"},      {0x0400, "PARAMETER_ERROR"},  {0x0800, "EVENT_BUFFER_OVERFLOW"},
    {0x1000, "ALREADY_EXECUTING"},   {0x2000, "CONFIG_CORRUPT"},   {0x4000, "RESERVED_2"},
    {0x8000, "RESERVED_1"},
};

std::vector<std::string> iin_flag_names(uint16_t iin) {
    std::vector<std::string> names;
    for (const auto& f : kIinFlags) {
        if (iin & f.mask) names.emplace_back(f.name);
    }
    return names;
}

// Strips (without validating) the 2-byte CRC that follows every 16-byte-or-shorter block of
// DNP3 data-link user data, returning the reassembled logical bytes. `after_header` is
// everything in the TCP payload after the 10-byte data link header; `logical_bytes` is
// Dnp3LinkFrame::user_data_bytes. Stops early -- noting why -- if the capture was truncated
// before every block could be read.
std::vector<uint8_t> reassemble_user_data(ByteSpan after_header, size_t logical_bytes,
                                           std::vector<std::string>& notes) {
    std::vector<uint8_t> out;
    out.reserve(logical_bytes);
    Cursor c(after_header);
    size_t remaining_logical = logical_bytes;

    while (remaining_logical > 0) {
        size_t chunk_len = std::min<size_t>(16, remaining_logical);
        if (c.remaining() < chunk_len) {
            notes.push_back("data-link user data is truncated (capture cut off mid-block): expected " +
                             std::to_string(chunk_len) + " more byte(s) of a block but only " +
                             std::to_string(c.remaining()) +
                             " remain -- transport/application decoding stopped at " +
                             std::to_string(out.size()) + " of " + std::to_string(logical_bytes) +
                             " logical byte(s)");
            ByteSpan tail = c.bytes(c.remaining());
            for (size_t i = 0; i < tail.size(); ++i) out.push_back(tail.at(i));
            return out;
        }
        ByteSpan chunk = c.bytes(chunk_len);
        for (size_t i = 0; i < chunk.size(); ++i) out.push_back(chunk.at(i));
        remaining_logical -= chunk_len;

        if (c.remaining() < 2) {
            notes.push_back("block CRC after a " + std::to_string(chunk_len) +
                             "-byte data block is truncated (capture cut off) -- the block's data bytes "
                             "were still recovered");
            return out;
        }
        c.skip(2);  // block CRC -- present but not validated in this release, same as the header CRC
    }
    return out;
}

}  // namespace

std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload) {
    // Fixed data link header: start(2) + length(1) + control(1) + destination(2) +
    // source(2) + CRC(2) = 10 bytes.
    if (tcp_payload.size() < 10) {
        return std::nullopt;
    }
    if (tcp_payload.at(0) != 0x05 || tcp_payload.at(1) != 0x64) {
        return std::nullopt;
    }

    Cursor c(tcp_payload);
    c.u8();  // start byte 1 (0x05)
    c.u8();  // start byte 2 (0x64)
    uint8_t length_field = c.u8();
    uint8_t control = c.u8();
    uint16_t destination = c.u16le();
    uint16_t source = c.u16le();
    c.u16be();  // header CRC -- present but not validated in this release

    Dnp3LinkFrame frame;
    frame.length_field = length_field;
    frame.control = control;
    frame.destination = destination;
    frame.source = source;
    frame.crc_validated = false;
    frame.user_data_bytes = (length_field >= 5) ? static_cast<size_t>(length_field - 5) : 0;

    std::ostringstream out;
    out << "DNP3 data link frame: source=" << source << " destination=" << destination
        << " control=0x" << std::hex << static_cast<unsigned>(control) << std::dec
        << " user_data=" << frame.user_data_bytes << " byte(s)";
    frame.summary = out.str();

    return frame;
}

size_t dnp3_frame_wire_length(const Dnp3LinkFrame& link) {
    size_t blocks = (link.user_data_bytes + 15) / 16;
    return 10 + link.user_data_bytes + 2 * blocks;
}

std::optional<size_t> dnp3_link_frame_declared_length(ByteSpan payload) {
    if (payload.size() < 3) {
        return std::nullopt;
    }
    if (payload.at(0) != 0x05 || payload.at(1) != 0x64) {
        return std::nullopt;
    }
    uint8_t length_field = payload.at(2);
    size_t user_data_bytes = (length_field >= 5) ? static_cast<size_t>(length_field - 5) : 0;
    size_t blocks = (user_data_bytes + 15) / 16;
    return 10 + user_data_bytes + 2 * blocks;
}

std::vector<uint8_t> reassemble_dnp3_user_data(const Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                std::vector<std::string>& notes) {
    if (link.user_data_bytes == 0) {
        return {};
    }
    ByteSpan after_header = tcp_payload.size() > 10 ? tcp_payload.from(10) : ByteSpan();
    return reassemble_user_data(after_header, link.user_data_bytes, notes);
}

std::optional<Dnp3ApplicationFragment> try_parse_dnp3_transport_and_application(const Dnp3LinkFrame& link,
                                                                                 ByteSpan tcp_payload) {
    if (link.user_data_bytes == 0) {
        return std::nullopt;
    }

    Dnp3ApplicationFragment frag;
    std::vector<uint8_t> logical = reassemble_dnp3_user_data(link, tcp_payload, frag.notes);

    if (logical.empty()) {
        frag.notes.push_back("no transport-layer byte could be recovered for this fragment");
        std::ostringstream s;
        s << "transport/application layer not decoded (no data recovered)";
        frag.summary = s.str();
        return frag;
    }

    // --- Transport header: 1 byte, bit7=FIR, bit6=FIN, bits5-0=SEQ. ---
    uint8_t transport_byte = logical[0];
    frag.has_transport = true;
    frag.transport_fir = (transport_byte & 0x80) != 0;
    frag.transport_fin = (transport_byte & 0x40) != 0;
    frag.transport_seq = transport_byte & 0x3F;

    std::ostringstream summary;
    summary << "transport: FIR=" << (frag.transport_fir ? 1 : 0) << " FIN=" << (frag.transport_fin ? 1 : 0)
            << " SEQ=" << static_cast<unsigned>(frag.transport_seq);

    if (!frag.transport_fir || !frag.transport_fin) {
        frag.notes.push_back(
            "this fragment's transport header has FIR=" + std::to_string(frag.transport_fir ? 1 : 0) +
            " FIN=" + std::to_string(frag.transport_fin ? 1 : 0) +
            " -- it is not a complete single-data-link-frame fragment, and this single-frame "
            "convenience function does not itself buffer bytes across packets, so the application "
            "layer is not decoded here; Decoder does perform that cross-packet reassembly (see "
            "Decoder::process_dnp3_frame in decoder.hpp) and is what the CLI actually uses");
        frag.summary = summary.str();
        return frag;
    }

    ByteSpan app_span = logical.size() > 1 ? ByteSpan(logical.data() + 1, logical.size() - 1) : ByteSpan();
    decode_dnp3_application_layer(app_span, frag);
    if (!frag.summary.empty()) {
        summary << " | " << frag.summary;
    }
    frag.summary = summary.str();
    return frag;
}

void decode_dnp3_application_layer(ByteSpan app_bytes, Dnp3ApplicationFragment& frag) {
    std::ostringstream summary;

    if (app_bytes.empty()) {
        frag.notes.push_back(
            "transport header present but no application control/function-code byte followed it "
            "(truncated fragment)");
        frag.summary.clear();
        return;
    }

    Cursor ac(app_bytes);

    frag.app_control = ac.u8();
    frag.app_fir = (frag.app_control & 0x80) != 0;
    frag.app_fin = (frag.app_control & 0x40) != 0;
    frag.app_con = (frag.app_control & 0x20) != 0;
    frag.app_uns = (frag.app_control & 0x10) != 0;
    frag.app_seq = frag.app_control & 0x0F;

    if (ac.at_end()) {
        frag.notes.push_back("application control byte present but no function code followed it "
                              "(truncated fragment)");
        frag.summary = summary.str();
        return;
    }
    frag.function_code = ac.u8();
    frag.has_function = true;
    frag.function_name = dnp3_function_name(frag.function_code);
    frag.application_decoded = true;

    summary << "application: FIR=" << (frag.app_fir ? 1 : 0) << " FIN=" << (frag.app_fin ? 1 : 0)
            << " CON=" << (frag.app_con ? 1 : 0) << " UNS=" << (frag.app_uns ? 1 : 0)
            << " SEQ=" << static_cast<unsigned>(frag.app_seq) << " function=" << frag.function_name << " ("
            << hex8(frag.function_code) << ")";

    if (is_response_function(frag.function_code)) {
        if (ac.remaining() < 2) {
            frag.notes.push_back(
                "function code " + hex8(frag.function_code) +
                " (" + frag.function_name +
                ") is a response function but fewer than 2 bytes remain for its IIN field "
                "(truncated fragment) -- object headers were not parsed");
            frag.summary = summary.str();
            return;
        }
        frag.iin = ac.u16le();
        frag.has_iin = true;
        frag.iin_flags = iin_flag_names(frag.iin);
        summary << " IIN=" << hex16(frag.iin);
        if (frag.iin_flags.empty()) {
            summary << " [none set]";
        } else {
            summary << " [";
            for (size_t i = 0; i < frag.iin_flags.size(); ++i) {
                if (i != 0) summary << ",";
                summary << frag.iin_flags[i];
            }
            summary << "]";
        }
    }

    // --- Object headers. ---
    constexpr size_t kMaxObjectHeaders = 200;  // safety cap against a pathological/malformed fragment
    size_t header_index = 0;
    while (!ac.at_end() && header_index < kMaxObjectHeaders) {
        if (ac.remaining() < 3) {
            frag.notes.push_back("object header " + std::to_string(header_index) +
                                  " is truncated (fewer than 3 bytes left for group/variation/qualifier)");
            break;
        }
        Dnp3ObjectHeader oh;
        oh.group = ac.u8();
        oh.variation = ac.u8();
        oh.qualifier = ac.u8();
        oh.group_name = dnp3_group_name(oh.group);
        oh.prefix_code = oh.qualifier >> 4;
        oh.range_code = oh.qualifier & 0x0F;

        if (oh.prefix_code >= 4) {
            oh.decoded = false;
            oh.note = "qualifier " + hex8(oh.qualifier) + " has prefix code " + hex8(oh.prefix_code) +
                       " (object-size-prefixed or reserved), which this groundwork release does not "
                       "decode -- stopping object parsing for this fragment";
            frag.objects.push_back(oh);
            frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
            break;
        }

        bool range_ok = true;
        if (oh.range_code <= 0x02) {
            // 8/16/32-bit start-stop range.
            size_t field_bytes = (oh.range_code == 0x00) ? 1 : (oh.range_code == 0x01) ? 2 : 4;
            if (ac.remaining() < field_bytes * 2) {
                range_ok = false;
                oh.note = "range code " + hex8(oh.range_code) + " needs " + std::to_string(field_bytes * 2) +
                           " byte(s) of start/stop fields but only " + std::to_string(ac.remaining()) +
                           " remain -- stopping object parsing for this fragment";
            } else {
                auto read_le = [&](size_t n) -> uint32_t {
                    uint32_t v = 0;
                    for (size_t i = 0; i < n; ++i) v |= static_cast<uint32_t>(ac.u8()) << (8 * i);
                    return v;
                };
                oh.range_start = read_le(field_bytes);
                oh.range_stop = read_le(field_bytes);
                oh.has_range = true;
                if (oh.range_stop < oh.range_start) {
                    range_ok = false;
                    oh.note = "range stop (" + std::to_string(oh.range_stop) + ") is less than range start (" +
                               std::to_string(oh.range_start) + ") -- stopping object parsing for this fragment";
                } else {
                    oh.point_count = oh.range_stop - oh.range_start + 1;
                }
            }
        } else if (oh.range_code == 0x06) {
            // No range ("all") -- by definition carries no object data (e.g. a Class 0 poll).
            oh.point_count = 0;
        } else if (oh.range_code >= 0x07 && oh.range_code <= 0x09) {
            size_t field_bytes = (oh.range_code == 0x07) ? 1 : (oh.range_code == 0x08) ? 2 : 4;
            if (ac.remaining() < field_bytes) {
                range_ok = false;
                oh.note = "range code " + hex8(oh.range_code) + " needs " + std::to_string(field_bytes) +
                           " byte(s) of count field but only " + std::to_string(ac.remaining()) +
                           " remain -- stopping object parsing for this fragment";
            } else {
                uint32_t count = 0;
                for (size_t i = 0; i < field_bytes; ++i) count |= static_cast<uint32_t>(ac.u8()) << (8 * i);
                oh.point_count = count;
            }
        } else {
            range_ok = false;
            oh.note = "range code " + hex8(oh.range_code) +
                       " is not supported -- stopping object parsing for this fragment";
        }

        if (!range_ok) {
            oh.decoded = false;
            frag.objects.push_back(oh);
            frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
            break;
        }

        if (oh.range_code == 0x06 || oh.point_count == 0) {
            oh.object_data_bytes = 0;
        } else {
            Dnp3PointFormat fmt;
            if (!point_format(oh.group, oh.variation, fmt)) {
                oh.decoded = false;
                oh.note = "group " + std::to_string(oh.group) + " variation " + std::to_string(oh.variation) +
                           " (" + oh.group_name +
                           ") is not in the known point-format table -- stopping object parsing for this "
                           "fragment (unknown object length)";
                frag.objects.push_back(oh);
                frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
                break;
            }
            uint16_t bits_per_point = fmt.bits_per_point;
            size_t index_size = (oh.prefix_code == 0) ? 0 : (oh.prefix_code == 1) ? 1
                                 : (oh.prefix_code == 2)                          ? 2
                                                                                   : 4;
            if (is_packed(bits_per_point) && index_size != 0) {
                oh.decoded = false;
                oh.note = "group " + std::to_string(oh.group) + " variation " + std::to_string(oh.variation) +
                           " is a bit-packed format combined with a non-zero index prefix, which is not a "
                           "supported combination -- stopping object parsing for this fragment";
                frag.objects.push_back(oh);
                frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
                break;
            }
            size_t data_bytes;
            if (is_packed(bits_per_point)) {
                data_bytes = (static_cast<size_t>(oh.point_count) * bits_per_point + 7) / 8;
            } else {
                data_bytes = static_cast<size_t>(oh.point_count) * (index_size + bits_per_point / 8);
            }
            if (ac.remaining() < data_bytes) {
                oh.decoded = false;
                oh.note = "declared object data length (" + std::to_string(data_bytes) +
                           " byte(s)) exceeds the " + std::to_string(ac.remaining()) +
                           " byte(s) remaining in this fragment -- stopping object parsing (truncated?)";
                frag.objects.push_back(oh);
                frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
                break;
            }
            ByteSpan block = ac.bytes(data_bytes);
            oh.object_data_bytes = data_bytes;

            constexpr uint32_t kMaxDecodedPointsPerHeader = 200;
            uint32_t points_to_decode = std::min(oh.point_count, kMaxDecodedPointsPerHeader);
            if (is_packed(bits_per_point)) {
                uint8_t mask = static_cast<uint8_t>((1u << bits_per_point) - 1);
                for (uint32_t p = 0; p < points_to_decode; ++p) {
                    size_t bit_offset = static_cast<size_t>(p) * bits_per_point;
                    uint8_t byte_val = block.at(bit_offset / 8);
                    uint8_t raw = (byte_val >> (bit_offset % 8)) & mask;
                    Dnp3PointValue pv;
                    pv.index = oh.has_range ? oh.range_start + p : p;
                    pv.index_is_explicit = false;
                    if (bits_per_point == 2) {
                        pv.value = double_bit_state_name(raw);
                    } else if (oh.group == 80) {
                        // Internal Indications object: point index p is IIN bit p, same bit
                        // ordering as the app-layer IIN field decoded above.
                        pv.value = raw ? "1" : "0";
                        if (raw && p < (sizeof(kIinFlags) / sizeof(kIinFlags[0]))) {
                            pv.flags.push_back(kIinFlags[p].name);
                        }
                    } else {
                        pv.value = raw ? "1" : "0";
                    }
                    oh.values.push_back(pv);
                }
            } else {
                Cursor bc(block);
                size_t bytes_per_value = bits_per_point / 8;
                for (uint32_t p = 0; p < oh.point_count; ++p) {
                    Dnp3PointValue pv;
                    if (index_size > 0) {
                        uint32_t idx = 0;
                        for (size_t b = 0; b < index_size; ++b) idx |= static_cast<uint32_t>(bc.u8()) << (8 * b);
                        pv.index = idx;
                        pv.index_is_explicit = true;
                    } else {
                        pv.index = oh.has_range ? oh.range_start + p : p;
                        pv.index_is_explicit = false;
                    }
                    ByteSpan point_bytes = bc.bytes(bytes_per_value);
                    if (p < points_to_decode) {
                        Dnp3PointValue decoded = decode_point_value(fmt, point_bytes);
                        pv.value = decoded.value;
                        pv.flags = decoded.flags;
                        oh.values.push_back(pv);
                    }
                }
            }
            if (oh.point_count > kMaxDecodedPointsPerHeader) {
                frag.notes.push_back("object header " + std::to_string(header_index) + ": only the first " +
                                      std::to_string(kMaxDecodedPointsPerHeader) + " of " +
                                      std::to_string(oh.point_count) + " point value(s) were decoded (safety cap)");
            }
        }

        oh.decoded = true;
        frag.objects.push_back(oh);
        ++header_index;
    }
    if (header_index >= kMaxObjectHeaders) {
        frag.notes.push_back("stopped after " + std::to_string(kMaxObjectHeaders) +
                              " object header(s), more may remain (safety cap)");
    }

    // Detailed per-object notes (capped, same pattern as the S7comm item notes).
    constexpr size_t kMaxDetailedNotes = 20;
    for (size_t i = 0; i < frag.objects.size() && i < kMaxDetailedNotes; ++i) {
        const auto& oh = frag.objects[i];
        std::ostringstream n;
        n << "object " << i << ": g" << static_cast<unsigned>(oh.group) << "v"
          << static_cast<unsigned>(oh.variation) << " (" << oh.group_name << ") qualifier=" << hex8(oh.qualifier);
        if (oh.has_range) {
            n << " range=" << oh.range_start << "-" << oh.range_stop;
        } else if (oh.range_code == 0x06) {
            n << " range=all";
        } else if (oh.range_code >= 0x07 && oh.range_code <= 0x09) {
            n << " count=" << oh.point_count;
        }
        if (oh.decoded) {
            n << " -- " << oh.point_count << " point(s), " << oh.object_data_bytes << " byte(s) of object data";
            if (!oh.values.empty()) {
                constexpr size_t kMaxBriefValues = 5;
                n << "; values: [";
                for (size_t v = 0; v < oh.values.size() && v < kMaxBriefValues; ++v) {
                    const auto& pv = oh.values[v];
                    if (v != 0) n << ", ";
                    n << "idx=" << pv.index << ": " << pv.value;
                    if (!pv.flags.empty()) {
                        n << " [";
                        for (size_t f = 0; f < pv.flags.size(); ++f) {
                            if (f != 0) n << ",";
                            n << pv.flags[f];
                        }
                        n << "]";
                    }
                }
                if (oh.values.size() > kMaxBriefValues) {
                    n << ", +" << (oh.values.size() - kMaxBriefValues) << " more";
                }
                n << "]";
            }
        } else {
            n << " -- not fully decoded: " << oh.note;
        }
        frag.notes.push_back(n.str());
    }

    // Brief object summary appended to the one-line summary (capped, "+N more" beyond that).
    if (!frag.objects.empty()) {
        summary << " objects: [";
        constexpr size_t kMaxBrief = 3;
        for (size_t i = 0; i < frag.objects.size() && i < kMaxBrief; ++i) {
            const auto& oh = frag.objects[i];
            if (i != 0) summary << ", ";
            summary << "g" << static_cast<unsigned>(oh.group) << "v" << static_cast<unsigned>(oh.variation);
        }
        if (frag.objects.size() > kMaxBrief) {
            summary << ", +" << (frag.objects.size() - kMaxBrief) << " more";
        }
        summary << "]";
    }

    frag.summary = summary.str();
}

}  // namespace conduitscope
