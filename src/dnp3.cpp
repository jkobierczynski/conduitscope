// SPDX-License-Identifier: MIT
#include "conduitscope/dnp3.hpp"

#include <algorithm>
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

// Bits-per-point for the group/variation combinations common enough in real traffic to skip
// structurally with confidence. A combination not listed here is genuinely out of scope, not a
// bug -- see the "unknown group/variation" bailout in the object-header loop below. Values < 8
// are bit-packed (see is_packed below); everything else is a whole number of bytes.
bool point_size_bits(uint8_t group, uint8_t variation, uint16_t& bits_out) {
    switch ((static_cast<uint16_t>(group) << 8) | variation) {
        case (1u << 8) | 1: bits_out = 1; return true;    // Binary Input, packed
        case (1u << 8) | 2: bits_out = 8; return true;    // Binary Input w/ flags
        case (3u << 8) | 1: bits_out = 2; return true;    // Double-bit Binary Input, packed
        case (3u << 8) | 2: bits_out = 8; return true;    // Double-bit Binary Input w/ flags
        case (10u << 8) | 1: bits_out = 1; return true;   // Binary Output, packed
        case (10u << 8) | 2: bits_out = 8; return true;   // Binary Output w/ flags
        case (12u << 8) | 1: bits_out = 88; return true;  // CROB (11 bytes)
        case (20u << 8) | 1: bits_out = 40; return true;  // Counter, 32-bit w/ flag
        case (20u << 8) | 2: bits_out = 24; return true;  // Counter, 16-bit w/ flag
        case (20u << 8) | 5: bits_out = 32; return true;  // Counter, 32-bit no flag
        case (20u << 8) | 6: bits_out = 16; return true;  // Counter, 16-bit no flag
        case (21u << 8) | 1: bits_out = 40; return true;
        case (21u << 8) | 2: bits_out = 24; return true;
        case (21u << 8) | 5: bits_out = 32; return true;
        case (21u << 8) | 6: bits_out = 16; return true;
        case (22u << 8) | 1: bits_out = 40; return true;  // Counter Event, 32-bit w/ flag+time
        case (22u << 8) | 2: bits_out = 24; return true;  // Counter Event, 16-bit w/ flag+time
        case (22u << 8) | 5: bits_out = 88; return true;
        case (22u << 8) | 6: bits_out = 72; return true;
        case (23u << 8) | 1: bits_out = 40; return true;
        case (23u << 8) | 2: bits_out = 24; return true;
        case (23u << 8) | 5: bits_out = 88; return true;
        case (23u << 8) | 6: bits_out = 72; return true;
        case (30u << 8) | 1: bits_out = 40; return true;  // Analog Input, 32-bit w/ flag
        case (30u << 8) | 2: bits_out = 24; return true;  // Analog Input, 16-bit w/ flag
        case (30u << 8) | 3: bits_out = 32; return true;  // Analog Input, 32-bit no flag
        case (30u << 8) | 4: bits_out = 16; return true;  // Analog Input, 16-bit no flag
        case (30u << 8) | 5: bits_out = 40; return true;  // Analog Input, single-precision float w/ flag
        case (30u << 8) | 6: bits_out = 72; return true;  // Analog Input, double-precision float w/ flag
        case (31u << 8) | 1: bits_out = 40; return true;
        case (31u << 8) | 2: bits_out = 24; return true;
        case (31u << 8) | 3: bits_out = 32; return true;
        case (31u << 8) | 4: bits_out = 16; return true;
        case (31u << 8) | 5: bits_out = 40; return true;
        case (31u << 8) | 6: bits_out = 72; return true;
        case (32u << 8) | 1: bits_out = 40; return true;  // Analog Input Event
        case (32u << 8) | 2: bits_out = 24; return true;
        case (32u << 8) | 3: bits_out = 88; return true;
        case (32u << 8) | 4: bits_out = 72; return true;
        case (32u << 8) | 5: bits_out = 40; return true;
        case (32u << 8) | 7: bits_out = 88; return true;
        case (33u << 8) | 1: bits_out = 40; return true;
        case (33u << 8) | 2: bits_out = 24; return true;
        case (33u << 8) | 3: bits_out = 88; return true;
        case (33u << 8) | 4: bits_out = 72; return true;
        case (33u << 8) | 5: bits_out = 40; return true;
        case (33u << 8) | 7: bits_out = 88; return true;
        case (40u << 8) | 1: bits_out = 40; return true;  // Analog Output Status, 32-bit w/ flag
        case (40u << 8) | 2: bits_out = 24; return true;  // Analog Output Status, 16-bit w/ flag
        case (40u << 8) | 3: bits_out = 40; return true;  // Analog Output Status, single float w/ flag
        case (41u << 8) | 1: bits_out = 40; return true;  // Analog Output (command)
        case (41u << 8) | 2: bits_out = 24; return true;
        case (41u << 8) | 3: bits_out = 40; return true;
        case (42u << 8) | 1: bits_out = 40; return true;  // Analog Output Event
        case (42u << 8) | 2: bits_out = 24; return true;
        case (42u << 8) | 3: bits_out = 40; return true;
        case (50u << 8) | 1: bits_out = 48; return true;  // Time and Date, 6-byte absolute time
        case (80u << 8) | 1: bits_out = 1; return true;   // Internal Indications, packed
        default: return false;
    }
    // Group 60 (Class Objects) intentionally has no entries: every real-world use pairs it with
    // range_code 0x06 ("all"/no range), which carries zero object data by definition and never
    // reaches this lookup -- see the range_code handling in the object-header loop.
}

bool is_packed(uint16_t bits_per_point) { return bits_per_point < 8; }

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

std::optional<Dnp3ApplicationFragment> try_parse_dnp3_transport_and_application(const Dnp3LinkFrame& link,
                                                                                 ByteSpan tcp_payload) {
    if (link.user_data_bytes == 0) {
        return std::nullopt;
    }

    Dnp3ApplicationFragment frag;
    ByteSpan after_header = tcp_payload.size() > 10 ? tcp_payload.from(10) : ByteSpan();
    std::vector<uint8_t> logical = reassemble_user_data(after_header, link.user_data_bytes, frag.notes);

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
            " -- it is not a complete single-data-link-frame fragment, so the application layer is "
            "not decoded in this groundwork release (no multi-data-link-frame reassembly, matching "
            "this tool's no-TCP-stream-reassembly scope; see dnp3.hpp)");
        frag.summary = summary.str();
        return frag;
    }

    if (logical.size() < 2) {
        frag.notes.push_back(
            "transport header present but no application control/function-code byte followed it "
            "(truncated fragment)");
        frag.summary = summary.str();
        return frag;
    }

    // --- Application layer. ---
    ByteSpan app_span(logical.data() + 1, logical.size() - 1);
    Cursor ac(app_span);

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
        return frag;
    }
    frag.function_code = ac.u8();
    frag.has_function = true;
    frag.function_name = dnp3_function_name(frag.function_code);
    frag.application_decoded = true;

    summary << " | application: FIR=" << (frag.app_fir ? 1 : 0) << " FIN=" << (frag.app_fin ? 1 : 0)
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
            return frag;
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
            uint16_t bits_per_point = 0;
            if (!point_size_bits(oh.group, oh.variation, bits_per_point)) {
                oh.decoded = false;
                oh.note = "group " + std::to_string(oh.group) + " variation " + std::to_string(oh.variation) +
                           " (" + oh.group_name +
                           ") is not in the known point-size table -- stopping object parsing for this "
                           "fragment (unknown object length)";
                frag.objects.push_back(oh);
                frag.notes.push_back("object header " + std::to_string(header_index) + ": " + oh.note);
                break;
            }
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
            ac.skip(data_bytes);
            oh.object_data_bytes = data_bytes;
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
    return frag;
}

}  // namespace conduitscope
