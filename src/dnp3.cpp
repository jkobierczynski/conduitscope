// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/dnp3.hpp"

#include <algorithm>
#include <array>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

#include "conduitscope/mqtt.hpp"
#include "conduitscope/resource_limits.hpp"

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

// DNP3 data-link CRC-16: table-driven, reflected, polynomial 0x3D65 (reflected form 0xA6BC, which
// is where this table comes from), seed 0, final result is the bitwise complement of the running
// CRC register. Used for BOTH the 8-byte data-link header CRC and every <=16-byte user-data block
// CRC -- same algorithm, just applied to different spans (see try_parse_dnp3_link_layer and
// reassemble_user_data below). Cross-checked against Wireshark's own wsutil/crc16.c
// (crc16_0x3D65_seed/crc16_reflected, as used by packet-dnp.c's calculateCRC/calculateCRCtvb) AND
// the independently-known CRC-16/DNP catalogue reference test vector (see the static_assert right
// below the table) -- do not substitute a different DNP3 CRC table/algorithm without re-deriving
// and re-checking it the same way; a subtly wrong table here would make every genuinely valid
// frame's CRC silently (and incorrectly) fail to validate.
constexpr std::array<uint16_t, 256> kDnp3CrcTable = {
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
};

// Core CRC loop, over a raw pointer/length rather than a ByteSpan so it can be used in a
// constexpr/compile-time context (see the static_assert below) as well as at runtime.
constexpr uint16_t dnp3_crc16(const uint8_t* data, size_t len) {
    uint16_t crc = 0;
    for (size_t i = 0; i < len; ++i) {
        crc = static_cast<uint16_t>(kDnp3CrcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8));
    }
    return static_cast<uint16_t>(~crc);
}

// Convenience overload for the ByteSpan chunks this file actually has at both CRC check sites
// (the 8-byte header span, and each <=16-byte user-data block) -- same core loop as above.
uint16_t dnp3_crc16(ByteSpan data) { return dnp3_crc16(data.data(), data.size()); }

// CRC-16/DNP reference test vector: the CRC of ASCII "123456789" must be 0xEA82. Checked at
// COMPILE TIME (not just in a test run) so a broken table transcription, wrong seed, wrong
// update-step bit order, or missing final complement fails the build outright rather than
// shipping a silently-wrong validator -- see kDnp3CrcTable's own comment for how this was
// independently derived and cross-checked before landing here.
constexpr uint8_t kDnp3CrcTestVector[] = {'1', '2', '3', '4', '5', '6', '7', '8', '9'};
static_assert(dnp3_crc16(kDnp3CrcTestVector, sizeof(kDnp3CrcTestVector)) == 0xEA82,
              "DNP3 CRC-16 implementation does not reproduce the CRC-16/DNP reference test vector "
              "(CRC of ASCII \"123456789\" must be 0xEA82) -- check kDnp3CrcTable's transcription, "
              "the seed, the per-byte update step, or the final complement");

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
// Rendered as an ISO-8601 UTC calendar timestamp (primary) plus the raw millisecond count
// (parenthetical), e.g. "2025-09-17T11:54:56.096Z (1758110096096ms-since-epoch)" -- the calendar
// rendering via mqtt.hpp's format_millis_epoch (std::gmtime-based, with a graceful out-of-range
// fallback baked into that function itself, so a value std::gmtime can't represent never risks a
// subtly wrong date), reused directly rather than duplicated because DNP3's absolute time is the
// exact same wire shape (milliseconds since the Unix epoch, uint64_t) as Sparkplug's own
// timestamp fields that function was originally written for -- see mqtt.hpp's own comment on it.
// The raw count is kept alongside it, not dropped: it is still directly useful (diffable,
// sortable), and this is the only place this value is exposed at all, in either text or JSON
// output.
std::string decode_absolute_time48(Cursor& c) {
    uint64_t ms = 0;
    for (int i = 0; i < 6; ++i) ms |= static_cast<uint64_t>(c.u8()) << (8 * i);
    return format_millis_epoch(ms) + " (" + std::to_string(ms) + "ms-since-epoch)";
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

// Aggregated block-CRC-check result across every block reassemble_user_data manages to look at --
// see Dnp3LinkFrame::block_count/block_crc_failures/crc_validated, which reassemble_dnp3_user_data
// copies this into.
struct Dnp3BlockCrcResult {
    size_t block_count = 0;
    size_t block_crc_failures = 0;
    // False on ANY mismatch, and also false the moment a truncation prevents a block (or its CRC)
    // from being fully read -- an unverifiable CRC is never counted as valid. Starts true (the
    // "zero blocks, so nothing failed" case, e.g. logical_bytes == 0) and can only go false.
    bool all_blocks_valid = true;
};

// Locates (and, now, validates) the 2-byte CRC that follows every 16-byte-or-shorter block of
// DNP3 data-link user data, returning the reassembled logical bytes. `after_header` is
// everything in the TCP payload after the 10-byte data link header; `logical_bytes` is
// Dnp3LinkFrame::user_data_bytes. Stops early -- noting why -- if the capture was truncated
// before every block (or its CRC) could be read; a mismatched or unreadable block CRC never stops
// reassembly itself (the block's data bytes are still recovered/appended either way) -- only a
// literal truncation (nothing left to read) does, same as before this feature.
std::vector<uint8_t> reassemble_user_data(ByteSpan after_header, size_t logical_bytes,
                                           std::vector<std::string>& notes, Dnp3BlockCrcResult& block_crc) {
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
            block_crc.all_blocks_valid = false;
            ByteSpan tail = c.bytes(c.remaining());
            for (size_t i = 0; i < tail.size(); ++i) out.push_back(tail.at(i));
            return out;
        }
        ByteSpan chunk = c.bytes(chunk_len);
        for (size_t i = 0; i < chunk.size(); ++i) out.push_back(chunk.at(i));
        remaining_logical -= chunk_len;
        ++block_crc.block_count;

        if (c.remaining() < 2) {
            notes.push_back("block CRC after a " + std::to_string(chunk_len) +
                             "-byte data block is truncated (capture cut off) -- the block's data bytes "
                             "were still recovered, but its CRC could not be checked");
            block_crc.block_crc_failures++;
            block_crc.all_blocks_valid = false;
            return out;
        }
        uint16_t block_crc_on_wire = c.u16le();  // on-the-wire block CRC is little-endian, same as the header CRC
        uint16_t block_crc_calculated = dnp3_crc16(chunk);
        if (block_crc_calculated != block_crc_on_wire) {
            block_crc.block_crc_failures++;
            block_crc.all_blocks_valid = false;
            notes.push_back("block " + std::to_string(block_crc.block_count) + " CRC mismatch (" +
                             std::to_string(chunk_len) + " data byte(s)): calculated " +
                             hex16(block_crc_calculated) + ", frame declares " + hex16(block_crc_on_wire));
        }
    }
    return out;
}

}  // namespace

std::vector<std::string> dnp3_known_function_names() {
    // Calls the same dnp3_function_name(fc) switch above for every possible byte value and keeps
    // only the ones that resolved to a real name rather than the dynamic "Unknown (0x.." fallback
    // -- see dnp3.hpp's own comment on this function for why this reuses dnp3_function_name()
    // instead of a second, separately-maintained list of names.
    std::vector<std::string> out;
    for (int fc = 0; fc <= 0xFF; ++fc) {
        std::string name = dnp3_function_name(static_cast<uint8_t>(fc));
        if (name.rfind("Unknown (0x", 0) != 0) out.push_back(std::move(name));
    }
    return out;
}

std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload, std::vector<std::string>& notes) {
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
    uint16_t header_crc_on_wire = c.u16le();  // on-the-wire header CRC is little-endian

    Dnp3LinkFrame frame;
    frame.length_field = length_field;
    frame.control = control;
    frame.destination = destination;
    frame.source = source;
    frame.user_data_bytes = (length_field >= 5) ? static_cast<size_t>(length_field - 5) : 0;

    // Header CRC covers exactly the 8 bytes before it: the two start bytes, length, control,
    // destination, source.
    frame.header_crc_calculated = dnp3_crc16(tcp_payload.subspan(0, 8));
    frame.header_crc_on_wire = header_crc_on_wire;
    frame.header_crc_valid = (frame.header_crc_calculated == frame.header_crc_on_wire);
    // Best answer available before any user data has been read -- already final for a frame with
    // none at all (reassemble_dnp3_user_data narrows this further, ANDing in the block result, for
    // a frame that actually has user data -- see Dnp3LinkFrame's own comment).
    frame.crc_validated = frame.header_crc_valid;
    if (!frame.header_crc_valid) {
        notes.push_back("header CRC mismatch: calculated " + hex16(frame.header_crc_calculated) +
                         ", frame declares " + hex16(frame.header_crc_on_wire));
    }

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

std::vector<uint8_t> reassemble_dnp3_user_data(Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                std::vector<std::string>& notes) {
    if (link.user_data_bytes == 0) {
        return {};
    }
    ByteSpan after_header = tcp_payload.size() > 10 ? tcp_payload.from(10) : ByteSpan();
    Dnp3BlockCrcResult block_crc;
    std::vector<uint8_t> out = reassemble_user_data(after_header, link.user_data_bytes, notes, block_crc);
    link.block_count = block_crc.block_count;
    link.block_crc_failures = block_crc.block_crc_failures;
    link.crc_validated = link.header_crc_valid && block_crc.all_blocks_valid;
    return out;
}

std::optional<Dnp3ApplicationFragment> try_parse_dnp3_transport_and_application(Dnp3LinkFrame& link,
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
            "layer is not decoded here; Dnp3Decoder does perform that cross-packet reassembly (see "
            "Dnp3Decoder::process_frame in dnp3.hpp) and is what the CLI actually uses");
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
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 200 default.
    const size_t kMaxObjectHeaders = resource_limits().max_decoded_objects.value_or(200);  // safety cap against a pathological/malformed fragment
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

            // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset
            // keeps the literal 200 default.
            const uint32_t kMaxDecodedPointsPerHeader =
                static_cast<uint32_t>(resource_limits().max_decoded_objects.value_or(200));
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
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 20 default.
    const size_t kMaxDetailedNotes = resource_limits().max_decoded_objects.value_or(20);
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
                // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp.
                // 0/unset keeps the literal 5 default.
                const size_t kMaxBriefValues = resource_limits().max_decoded_objects.value_or(5);
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
        // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
        // the literal 3 default.
        const size_t kMaxBrief = resource_limits().max_decoded_objects.value_or(3);
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

// --- Migration batch 2: Dnp3Decoder (registration-model interface) ---------------------------
//
// process_frame below is an exact behavioral transplant of the removed Decoder::process_dnp3_frame
// (decoder.cpp), with dnp3_reassembly_[flow_key] replaced by
// ctx.flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow) -- same state shape, same
// state machine, same notes wording, just reached generically instead of through a Decoder member
// dedicated to DNP3 alone.
std::optional<Dnp3ApplicationFragment> Dnp3Decoder::process_frame(Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                                    DecodeContext& ctx) const {
    if (link.user_data_bytes == 0) {
        return std::nullopt;
    }

    Dnp3ApplicationFragment frag;
    std::vector<uint8_t> logical = reassemble_dnp3_user_data(link, tcp_payload, frag.notes);

    if (logical.empty()) {
        frag.notes.push_back("no transport-layer byte could be recovered for this fragment");
        frag.summary = "transport/application layer not decoded (no data recovered)";
        return frag;
    }

    // --- Transport header: 1 byte, bit7=FIR, bit6=FIN, bits5-0=SEQ. Same as
    // try_parse_dnp3_transport_and_application; the difference starts below, in what happens for
    // a fragment that isn't complete in this one data-link frame. ---
    uint8_t transport_byte = logical[0];
    frag.has_transport = true;
    frag.transport_fir = (transport_byte & 0x80) != 0;
    frag.transport_fin = (transport_byte & 0x40) != 0;
    frag.transport_seq = transport_byte & 0x3F;

    std::ostringstream summary;
    summary << "transport: FIR=" << (frag.transport_fir ? 1 : 0) << " FIN=" << (frag.transport_fin ? 1 : 0)
            << " SEQ=" << static_cast<unsigned>(frag.transport_seq);

    ByteSpan app_bytes_this_frame =
        logical.size() > 1 ? ByteSpan(logical.data() + 1, logical.size() - 1) : ByteSpan();
    Dnp3ReassemblyState& state = ctx.flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow);

    if (frag.transport_fir && frag.transport_fin) {
        // Complete, single-data-link-frame fragment -- the large majority of real traffic. Any
        // reassembly left in progress for this flow is now stale (its FIN=1 will never come from
        // the frame that was supposed to send it -- a fragment that arrived complete on its own
        // took its place instead), so it's abandoned with a note rather than silently forgotten.
        if (state.in_progress) {
            frag.notes.push_back(
                "a complete single-frame DNP3 fragment (FIR=1, FIN=1) arrived on this TCP flow "
                "while a previous multi-frame fragment reassembly was still in progress (" +
                std::to_string(state.buffered_app_bytes.size()) + " byte(s) buffered across " +
                std::to_string(state.frame_count) +
                " frame(s)) -- the earlier, incomplete fragment is abandoned");
            state = Dnp3ReassemblyState{};
        }
        decode_dnp3_application_layer(app_bytes_this_frame, frag);
        if (!frag.summary.empty()) {
            summary << " | " << frag.summary;
        }
        frag.summary = summary.str();
        return frag;
    }

    if (frag.transport_fir) {
        // Begins a fragment that continues in a later data-link frame -- possibly in a later TCP
        // segment/packet entirely. Buffer it per-flow and wait for a continuation; nothing to
        // decode yet.
        if (state.in_progress) {
            frag.notes.push_back(
                "a new DNP3 fragment (FIR=1, FIN=0, SEQ=" + std::to_string(frag.transport_seq) +
                ") began on this TCP flow while a previous fragment reassembly was still in "
                "progress (" + std::to_string(state.buffered_app_bytes.size()) +
                " byte(s) buffered across " + std::to_string(state.frame_count) +
                " frame(s)) -- the earlier, incomplete fragment is abandoned");
        }
        state = Dnp3ReassemblyState{};
        state.in_progress = true;
        state.buffered_app_bytes.assign(app_bytes_this_frame.data(),
                                         app_bytes_this_frame.data() + app_bytes_this_frame.size());
        state.last_seq = frag.transport_seq;
        state.frame_count = 1;
        frag.notes.push_back(
            "beginning a DNP3 fragment that spans multiple data-link frames (FIR=1, FIN=0, SEQ=" +
            std::to_string(frag.transport_seq) + ") -- " +
            std::to_string(state.buffered_app_bytes.size()) +
            " application-layer byte(s) buffered so far for this TCP flow; the application layer "
            "will be decoded once a continuation frame with FIN=1 is seen on the same flow "
            "(reassembly assumes packets are processed in capture order, which conduitscope's "
            "single sequential decode pass guarantees)");
        frag.summary = summary.str();  // transport-only, same rendering as before this fragment began
        return frag;
    }

    // frag.transport_fir is false: a continuation frame.
    if (!state.in_progress) {
        frag.notes.push_back(
            "continuation DNP3 data-link frame (FIR=0, SEQ=" + std::to_string(frag.transport_seq) +
            ") with no fragment reassembly in progress on this TCP flow -- the frame that began it "
            "was never seen (capture may start mid-fragment) or the reassembly was already "
            "completed/abandoned; application layer not decoded");
        frag.summary = summary.str();
        return frag;
    }

    uint8_t expected_seq = (state.last_seq + 1) & 0x3F;
    if (frag.transport_seq != expected_seq) {
        frag.notes.push_back(
            "continuation DNP3 data-link frame's sequence number (" + std::to_string(frag.transport_seq) +
            ") does not follow the previous frame's (expected " + std::to_string(expected_seq) +
            ") -- discarding " + std::to_string(state.buffered_app_bytes.size()) +
            " already-buffered byte(s) and abandoning this fragment reassembly; application layer "
            "not decoded");
        state = Dnp3ReassemblyState{};
        frag.summary = summary.str();
        return frag;
    }

    // Safety caps against a pathological/malformed capture stalling a fragment open forever and
    // growing this flow's reassembly state without bound -- a real fragment is nowhere near either
    // limit.
    // CLI-configurable via --max-reassembly-bytes/--max-reassembly-segments -- see
    // resource_limits.hpp. 0/unset keeps these two literal defaults.
    const size_t kMaxBufferedBytes = resource_limits().max_reassembly_bytes.value_or(65536);
    const size_t kMaxFramesPerFragment = resource_limits().max_reassembly_segments.value_or(500);

    state.buffered_app_bytes.insert(state.buffered_app_bytes.end(), app_bytes_this_frame.data(),
                                     app_bytes_this_frame.data() + app_bytes_this_frame.size());
    state.last_seq = frag.transport_seq;
    ++state.frame_count;

    if (state.buffered_app_bytes.size() > kMaxBufferedBytes || state.frame_count > kMaxFramesPerFragment) {
        frag.notes.push_back(
            "DNP3 fragment reassembly on this TCP flow exceeded its safety cap (" +
            std::to_string(state.buffered_app_bytes.size()) + " byte(s) across " +
            std::to_string(state.frame_count) +
            " frame(s)) -- abandoning it; application layer not decoded");
        state = Dnp3ReassemblyState{};
        frag.summary = summary.str();
        return frag;
    }

    if (!frag.transport_fin) {
        frag.notes.push_back(
            "continuing a DNP3 fragment reassembly on this TCP flow (SEQ=" +
            std::to_string(frag.transport_seq) + "): " + std::to_string(state.buffered_app_bytes.size()) +
            " application-layer byte(s) buffered across " + std::to_string(state.frame_count) +
            " frame(s) so far, still waiting for FIN=1");
        frag.summary = summary.str();
        return frag;
    }

    // FIN=1: the fragment is complete. Decode the concatenated application-layer bytes, then
    // clear the flow's reassembly state -- it's spent either way, whether decoding succeeds or
    // turns up something malformed.
    size_t total_bytes = state.buffered_app_bytes.size();
    size_t total_frames = state.frame_count;
    frag.notes.push_back("completed a " + std::to_string(total_frames) +
                          "-data-link-frame DNP3 fragment reassembled across separate TCP segments (" +
                          std::to_string(total_bytes) + " application-layer byte(s) total)");
    ByteSpan reassembled(state.buffered_app_bytes.data(), state.buffered_app_bytes.size());
    decode_dnp3_application_layer(reassembled, frag);
    state = Dnp3ReassemblyState{};

    summary << " (fragment reassembled across " << total_frames << " data-link frame(s), " << total_bytes
            << " application-layer byte(s) total)";
    if (!frag.summary.empty()) {
        summary << " | " << frag.summary;
    }
    frag.summary = summary.str();
    return frag;
}

// decode() is an exact behavioral transplant of the removed decoder.cpp `if (want_dnp3) { ... }`
// call site's body -- the same-payload multi-data-link-frame coalescing loop (DNP3 frames are
// small, <=255 bytes on the wire, and it's normal for a sender/OS to flush several into one TCP
// segment) plus the merge-application-layer-fields-into-the-result logic, both moved here
// unchanged so decoder.cpp's own call site can shrink to gate+call+dual-write.
std::optional<ProtocolResult> Dnp3Decoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    Dnp3Result result;
    auto d = try_parse_dnp3_link_layer(payload, result.notes);
    if (!d) {
        return std::nullopt;
    }

    result.summary = d->summary;

    // Object headers/point values are capped cumulatively across every data link frame found in
    // this TCP payload, not per frame -- same caps as before, just now shared across however many
    // frames turned up.
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps each
    // literal 50 default.
    const size_t kMaxObjHeaders = resource_limits().max_decoded_objects.value_or(50);
    const size_t kMaxPointValues = resource_limits().max_decoded_objects.value_or(50);
    auto merge_application_layer = [&](const Dnp3ApplicationFragment& app, bool is_first_frame) {
        if (is_first_frame) {
            result.summary += "; " + app.summary;
            result.dnp3_has_function = app.has_function;
            result.dnp3_function_name = app.function_name;
        }
        for (const auto& n : app.notes) result.notes.push_back(n);
        for (size_t i = 0; i < app.objects.size() && result.dnp3_object_headers.size() < kMaxObjHeaders; ++i) {
            const auto& oh = app.objects[i];
            result.dnp3_object_headers.push_back("g" + std::to_string(oh.group) + "v" +
                                                  std::to_string(oh.variation) + " (" + oh.group_name + ")");
        }
        for (const auto& oh : app.objects) {
            if (result.dnp3_point_values.size() >= kMaxPointValues) break;
            std::string tag = "g" + std::to_string(oh.group) + "v" + std::to_string(oh.variation);
            for (const auto& pv : oh.values) {
                if (result.dnp3_point_values.size() >= kMaxPointValues) break;
                std::string entry = tag + " idx=" + std::to_string(pv.index) + ": " + pv.value;
                if (!pv.flags.empty()) {
                    entry += " [";
                    for (size_t f = 0; f < pv.flags.size(); ++f) {
                        if (f != 0) entry += ",";
                        entry += pv.flags[f];
                    }
                    entry += "]";
                }
                result.dnp3_point_values.push_back(entry);
            }
        }
    };

    if (auto app = process_frame(*d, payload, ctx)) {
        merge_application_layer(*app, /*is_first_frame=*/true);
    }
    // Read AFTER process_frame: that call (when it runs -- it doesn't for a link-layer-only
    // control frame with no user data, see its own doc comment) is what finalizes block_count/
    // block_crc_failures/crc_validated on top of the header result try_parse_dnp3_link_layer
    // already set -- see Dnp3LinkFrame's own comment in dnp3.hpp for why. Either way, by this
    // point d's crc fields are final.
    result.link_crc_valid = d->crc_validated;
    result.header_crc_valid = d->header_crc_valid;
    result.block_count = d->block_count;
    result.block_crc_failures = d->block_crc_failures;
    result.source_address = d->source;
    result.destination_address = d->destination;

    // CLI-configurable via --max-coalesced-messages -- see resource_limits.hpp (this cap wasn't
    // in item 7's original inventory -- DNP3/IEC104 turned out to share the exact same "N
    // application messages coalesced per TCP payload" shape as FF-HSE/HART-IP/MQTT/EtherNet-IP/
    // OPC UA, so both were folded into this flag too; see docs/DEVELOPMENT.md's item 7 "Update:
    // implemented" entry). 0/unset keeps the literal 50 default.
    const size_t kMaxDnp3FramesPerPayload = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = dnp3_frame_wire_length(*d);
    size_t frame_count = 1;
    while (offset < payload.size() && frame_count < kMaxDnp3FramesPerPayload) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_dnp3_link_layer(rest, result.notes);
        if (!next) break;  // remaining bytes aren't another DNP3 frame -- stop, don't guess
        ++frame_count;
        std::string note = "additional DNP3 data link frame " + std::to_string(frame_count) +
                            " found in the same TCP payload at byte offset " + std::to_string(offset) +
                            " (coalesced by the sender/OS): " + next->summary;
        if (frame_count == 2) {
            note +=
                " -- only the first frame's function code is reflected in the summary line "
                "above and the dnp3_function field; every frame's own function/objects/values "
                "are still fully decoded and included here and in dnp3_objects/dnp3_values";
        }
        result.notes.push_back(note);
        if (auto next_app = process_frame(*next, rest, ctx)) {
            merge_application_layer(*next_app, /*is_first_frame=*/false);
        }
        offset += dnp3_frame_wire_length(*next);
    }
    if (frame_count >= kMaxDnp3FramesPerPayload) {
        result.notes.push_back("stopped after " + std::to_string(kMaxDnp3FramesPerPayload) +
                                " DNP3 data link frame(s) in this one TCP payload, more may remain "
                                "(safety cap)");
    }

    return ProtocolResult::make<Dnp3Result>("dnp3", std::move(result));
}

const ProtocolDecoder& dnp3_decoder() {
    static const Dnp3Decoder instance;
    return instance;
}

}  // namespace conduitscope
