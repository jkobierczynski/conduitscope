// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/melsec.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace conduitscope {

namespace {

constexpr uint16_t kSubheader3EReq = 0x5000;
constexpr uint16_t kSubheader3ERes = 0xD000;
constexpr uint16_t kSubheader4EReq = 0x5400;
constexpr uint16_t kSubheader4ERes = 0xD400;

constexpr size_t kCommonHeaderSize = 5;  // network_no(1)+pc_no(1)+io_no(2)+station_no(1)
constexpr size_t k4ESerialSize = 2;

// A real MC Protocol/SLMP request/response realistically never approaches this; guards against a
// coincidentally plausible but wildly large declared length being mistaken for a genuine frame split
// across TCP segments and buffered forever -- same defense-in-depth posture
// modbus.cpp's kMaxPlausibleMbapLength / twincat.cpp's kMaxPlausibleAdsDataLength take.
constexpr uint32_t kMaxPlausibleMelsecDataLength = 8192;

struct MelsecCommandInfo {
    const char* name;
};

// Every command/subcommand pair this decoder recognizes -- see melsec.hpp's file header comment for
// why any other pair is deliberately shown numerically only, never guessed at. Keyed by
// (command << 16 | subcommand).
const std::unordered_map<uint32_t, MelsecCommandInfo>& command_table() {
    static const std::unordered_map<uint32_t, MelsecCommandInfo> table = {
        {(0x0401u << 16) | 0x0000u, {"Batch Read"}},
        {(0x0401u << 16) | 0x0001u, {"Batch Read"}},
        {(0x0401u << 16) | 0x0002u, {"Batch Read"}},
        {(0x0401u << 16) | 0x0003u, {"Batch Read"}},
        {(0x1401u << 16) | 0x0000u, {"Batch Write"}},
        {(0x1401u << 16) | 0x0001u, {"Batch Write"}},
        {(0x1401u << 16) | 0x0002u, {"Batch Write"}},
        {(0x1401u << 16) | 0x0003u, {"Batch Write"}},
        {(0x0403u << 16) | 0x0000u, {"Random Read"}},
        {(0x0403u << 16) | 0x0002u, {"Random Read"}},
        {(0x1402u << 16) | 0x0000u, {"Random Write"}},
        {(0x1402u << 16) | 0x0001u, {"Random Write"}},
        {(0x1402u << 16) | 0x0002u, {"Random Write"}},
        {(0x1402u << 16) | 0x0003u, {"Random Write"}},
        {(0x1001u << 16) | 0x0000u, {"Remote RUN"}},
        {(0x1002u << 16) | 0x0000u, {"Remote STOP"}},
        {(0x1003u << 16) | 0x0000u, {"Remote PAUSE"}},
        {(0x1005u << 16) | 0x0000u, {"Remote LATCH CLEAR"}},
        {(0x1006u << 16) | 0x0000u, {"Remote RESET"}},
        {(0x0101u << 16) | 0x0000u, {"Read CPU Type"}},
        {(0x1630u << 16) | 0x0000u, {"Remote Password UNLOCK"}},
        {(0x1631u << 16) | 0x0000u, {"Remote Password LOCK"}},
        {(0x0619u << 16) | 0x0000u, {"Echo/Loopback Test"}},
    };
    return table;
}

// Device code table -- empirically confirmed via pymcprotocol/mcprotocolconst.py's DeviceConstants
// class (see melsec.hpp's file header comment). `hex_notation` is true for devices conventionally
// typed/read in hexadecimal (X, Y, B, W, SB, SW, DX, DY, ZR, LZ), false for decimal notation.
struct DeviceCodeInfo {
    const char* name;
    bool hex_notation;
};

const std::unordered_map<uint16_t, DeviceCodeInfo>& device_code_table() {
    static const std::unordered_map<uint16_t, DeviceCodeInfo> table = {
        {0x91, {"SM", false}},  {0xA9, {"SD", false}},  {0x9C, {"X", true}},
        {0x9D, {"Y", true}},    {0x90, {"M", false}},   {0x92, {"L", false}},
        {0x93, {"F", false}},   {0x94, {"V", false}},   {0xA0, {"B", true}},
        {0xA8, {"D", false}},   {0xB4, {"W", true}},    {0xC1, {"TS", false}},
        {0xC0, {"TC", false}},  {0xC2, {"TN", false}},  {0xC7, {"SS", false}},
        {0xC6, {"SC", false}},  {0xC8, {"SN", false}},  {0xC4, {"CS", false}},
        {0xC3, {"CC", false}},  {0xC5, {"CN", false}},  {0xA1, {"SB", true}},
        {0xB5, {"SW", true}},   {0xA2, {"DX", true}},   {0xA3, {"DY", true}},
        {0xAF, {"R", false}},   {0xB0, {"ZR", true}},
        // iQ-R-only
        {0x51, {"LTS", false}}, {0x50, {"LTC", false}}, {0x52, {"LTN", false}},
        {0x59, {"LSTS", false}},{0x58, {"LSTC", false}},{0x5A, {"LSTN", false}},
        {0x55, {"LCS", false}}, {0x54, {"LCC", false}}, {0x56, {"LCN", false}},
        {0x62, {"LZ", true}},   {0x2C, {"RD", false}},
    };
    return table;
}

std::string format_device_text(uint16_t code, uint32_t number) {
    auto it = device_code_table().find(code);
    std::ostringstream s;
    if (it == device_code_table().end()) {
        s << "0x" << std::hex << std::uppercase << code << std::dec << ":" << number;
        return s.str();
    }
    s << it->second.name;
    if (it->second.hex_notation) {
        s << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << number << std::dec;
    } else {
        s << number;
    }
    return s.str();
}

MelsecDeviceSpec parse_device_spec(Cursor& c, bool extended) {
    MelsecDeviceSpec spec;
    spec.extended = extended;
    if (extended) {
        uint32_t a = c.u8(), b = c.u8(), cc = c.u8(), d = c.u8();
        spec.device_number = a | (b << 8) | (cc << 16) | (static_cast<uint32_t>(d) << 24);
        spec.device_code = c.u16le();
    } else {
        uint32_t a = c.u8(), b = c.u8(), cc = c.u8();
        spec.device_number = a | (b << 8) | (cc << 16);
        spec.device_code = c.u8();
    }
    spec.device_text = format_device_text(spec.device_code, spec.device_number);
    return spec;
}

// Bit-units packing quirk (see melsec.hpp's file header comment): two bit values per byte, even
// index in bit 4, odd index in bit 0. Decodes as many bit values as fully fit in `data`.
std::vector<uint8_t> unpack_bit_units(ByteSpan data, size_t max_count) {
    std::vector<uint8_t> out;
    size_t available = data.size() * 2;
    size_t count = max_count < available ? max_count : available;
    out.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        uint8_t byte = data.at(i / 2);
        bool even = (i % 2 == 0);
        out.push_back(even ? ((byte >> 4) & 0x1) : (byte & 0x1));
    }
    return out;
}

bool is_bit_subcommand(uint16_t subcommand) { return subcommand == 0x0001 || subcommand == 0x0003; }
bool is_extended_subcommand(uint16_t subcommand) {
    return subcommand == 0x0002 || subcommand == 0x0003;
}

std::string remote_mode_name(uint16_t mode) {
    if (mode == 0x0001) return "normal";
    if (mode == 0x0003) return "force execution";
    std::ostringstream s;
    s << "unrecognized (0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << mode
      << std::dec << ")";
    return s.str();
}

std::string clear_mode_name(uint8_t mode) {
    if (mode == 0) return "no clear";
    if (mode == 1) return "clear except latch";
    if (mode == 2) return "clear all";
    return "unrecognized (" + std::to_string(static_cast<unsigned>(mode)) + ")";
}

std::string end_code_name(uint16_t code) {
    if (code == 0x0000) return "Normal completion";
    if (code == 0xC059) return "Unsupported command";
    std::ostringstream s;
    s << "Error 0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << code
      << std::dec << " (not independently verified against Mitsubishi's own error-code appendix)";
    return s.str();
}

std::string trim_trailing_spaces(const std::string& s) {
    size_t end = s.find_last_not_of(' ');
    return end == std::string::npos ? std::string() : s.substr(0, end + 1);
}

// Decodes the command-specific request/response data (`body`) into frame's own fields plus
// summary/notes. Never throws -- a payload shorter than a command's expected shape is caught
// (ParseError from the bounds-checked Cursor) and reported as a note, mirroring
// twincat.cpp's decode_payload exactly.
void decode_payload(MelsecFrame& frame, uint16_t command, uint16_t subcommand, bool is_response,
                     ByteSpan body) {
    std::ostringstream summary;
    summary << frame.command_name << " " << (is_response ? "response" : "request");
    try {
        Cursor c(body);
        bool extended = is_extended_subcommand(subcommand);
        bool bit_mode = is_bit_subcommand(subcommand);

        switch (command) {
            case 0x0401: {  // Batch Read
                if (!is_response) {
                    frame.devices.push_back(parse_device_spec(c, extended));
                    frame.has_point_count = true;
                    frame.point_count = c.u16le();
                    summary << ": " << frame.devices.back().device_text << ", " << frame.point_count
                            << " point(s), " << (bit_mode ? "bit units" : "word units");
                } else {
                    ByteSpan rest = c.rest();
                    if (bit_mode) {
                        // Point count isn't repeated on the wire in the response -- decode every bit
                        // value the remaining bytes can hold (2 per byte, see the packing quirk).
                        frame.bit_values = unpack_bit_units(rest, rest.size() * 2);
                        summary << ": " << frame.bit_values.size() << " bit value(s)";
                    } else {
                        size_t count = rest.size() / 2;
                        frame.word_values.reserve(count);
                        for (size_t i = 0; i < count; ++i) {
                            frame.word_values.push_back(static_cast<int16_t>(c.u16le()));
                        }
                        summary << ": " << frame.word_values.size() << " word value(s)";
                    }
                }
                frame.notes.push_back(
                    "Batch Read: arbitrary PLC device memory read, no protocol-level access control");
                break;
            }
            case 0x1401: {  // Batch Write
                if (!is_response) {
                    frame.devices.push_back(parse_device_spec(c, extended));
                    frame.has_point_count = true;
                    frame.point_count = c.u16le();
                    if (bit_mode) {
                        ByteSpan rest = c.rest();
                        frame.bit_values = unpack_bit_units(rest, frame.point_count);
                    } else {
                        for (uint16_t i = 0; i < frame.point_count; ++i) {
                            frame.word_values.push_back(static_cast<int16_t>(c.u16le()));
                        }
                    }
                    summary << ": " << frame.devices.back().device_text << ", " << frame.point_count
                            << " point(s), " << (bit_mode ? "bit units" : "word units");
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Batch Write: arbitrary PLC device memory write, no protocol-level access control");
                break;
            }
            case 0x0403: {  // Random Read
                if (!is_response) {
                    uint8_t word_count = c.u8();
                    uint8_t dword_count = c.u8();
                    frame.random_read_word_count = word_count;
                    frame.random_read_dword_count = dword_count;
                    for (uint8_t i = 0; i < word_count; ++i) frame.devices.push_back(parse_device_spec(c, extended));
                    for (uint8_t i = 0; i < dword_count; ++i) frame.devices.push_back(parse_device_spec(c, extended));
                    summary << ": " << static_cast<unsigned>(word_count) << " word device(s), "
                            << static_cast<unsigned>(dword_count) << " dword device(s)";
                } else if (frame.random_read_word_count != 0 || frame.random_read_dword_count != 0) {
                    // Matched to its own request (see melsec.hpp's "RESPONSE DECODING NEEDS SESSION
                    // CONTEXT" comment) -- frame.random_read_word_count/dword_count were carried
                    // forward from that request by decode_with_session_state before this call.
                    for (uint8_t i = 0; i < frame.random_read_word_count; ++i) {
                        frame.word_values.push_back(static_cast<int16_t>(c.u16le()));
                    }
                    for (uint8_t i = 0; i < frame.random_read_dword_count; ++i) {
                        frame.dword_values.push_back(static_cast<int32_t>(c.u32le()));
                    }
                    summary << ": " << frame.word_values.size() << " word value(s), "
                            << frame.dword_values.size() << " dword value(s)";
                } else {
                    ByteSpan rest = c.rest();
                    frame.has_undecoded_response_bytes = true;
                    frame.undecoded_response_byte_count = rest.size();
                    summary << ": " << rest.size()
                            << " byte(s) of data (word/dword split unknown -- no matching request's "
                               "own device counts available, see melsec.hpp)";
                }
                frame.notes.push_back(
                    "Random Read: arbitrary PLC device memory read, no protocol-level access control");
                break;
            }
            case 0x1402: {  // Random Write
                if (!is_response) {
                    if (bit_mode) {
                        uint8_t bit_count = c.u8();
                        for (uint8_t i = 0; i < bit_count; ++i) {
                            frame.devices.push_back(parse_device_spec(c, extended));
                            frame.bit_values.push_back(c.u8());
                        }
                        summary << ": " << static_cast<unsigned>(bit_count) << " bit device(s)";
                    } else {
                        uint8_t word_count = c.u8();
                        uint8_t dword_count = c.u8();
                        for (uint8_t i = 0; i < word_count; ++i) {
                            frame.devices.push_back(parse_device_spec(c, extended));
                            frame.word_values.push_back(static_cast<int16_t>(c.u16le()));
                        }
                        for (uint8_t i = 0; i < dword_count; ++i) {
                            frame.devices.push_back(parse_device_spec(c, extended));
                            frame.dword_values.push_back(static_cast<int32_t>(c.u32le()));
                        }
                        summary << ": " << static_cast<unsigned>(word_count) << " word device(s), "
                                << static_cast<unsigned>(dword_count) << " dword device(s)";
                    }
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Random Write: arbitrary PLC device memory write, no protocol-level access control");
                break;
            }
            case 0x1001: {  // Remote RUN
                if (!is_response) {
                    frame.has_remote_mode = true;
                    frame.remote_mode = c.u16le();
                    frame.remote_mode_name = remote_mode_name(frame.remote_mode);
                    frame.has_clear_mode = true;
                    frame.clear_mode = c.u8();
                    frame.clear_mode_name = clear_mode_name(frame.clear_mode);
                    c.u8();  // reserved
                    summary << ": mode=" << frame.remote_mode_name << ", " << frame.clear_mode_name;
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote RUN: no protocol-level authentication for CPU control -- the direct "
                    "MELSEC analogue of S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x1002: {  // Remote STOP
                if (!is_response) {
                    c.u16le();  // fixed 0x0001
                    summary << " (no arguments)";
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote STOP: no protocol-level authentication for CPU control -- the direct "
                    "MELSEC analogue of S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x1003: {  // Remote PAUSE
                if (!is_response) {
                    frame.has_remote_mode = true;
                    frame.remote_mode = c.u16le();
                    frame.remote_mode_name = remote_mode_name(frame.remote_mode);
                    summary << ": mode=" << frame.remote_mode_name;
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote PAUSE: no protocol-level authentication for CPU control -- the direct "
                    "MELSEC analogue of S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x1005: {  // Remote LATCH CLEAR
                if (!is_response) {
                    c.u16le();  // fixed 0x0001
                    summary << " (no arguments)";
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote LATCH CLEAR: no protocol-level authentication for CPU control -- the "
                    "direct MELSEC analogue of S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x1006: {  // Remote RESET
                if (!is_response) {
                    c.u16le();  // fixed 0x0001
                    summary << " (no arguments)";
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote RESET: no protocol-level authentication for CPU control -- the direct "
                    "MELSEC analogue of S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x0101: {  // Read CPU Type
                if (!is_response) {
                    summary << " (no data)";
                } else {
                    frame.has_cpu_type = true;
                    std::string raw(reinterpret_cast<const char*>(c.bytes(16).data()), 16);
                    frame.cpu_type_name = trim_trailing_spaces(raw);
                    frame.cpu_code = c.u16le();
                    std::ostringstream code;
                    code << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                         << frame.cpu_code << std::dec;
                    summary << ": \"" << frame.cpu_type_name << "\", code=" << code.str();
                }
                frame.notes.push_back(
                    "Read CPU Type: unauthenticated reconnaissance -- reveals PLC hardware/firmware "
                    "family to any network-reachable client");
                break;
            }
            case 0x1630:    // Remote Password UNLOCK
            case 0x1631: {  // Remote Password LOCK
                if (!is_response) {
                    frame.has_remote_password = true;
                    frame.remote_password_length = c.u16le();
                    // Per Jurgen's own decision (NTLM/Netlogon-style redaction): the password value
                    // itself is deliberately never read into frame/summary/notes -- only its length.
                    summary << ": password present (" << frame.remote_password_length
                            << " byte(s), value not decoded -- see melsec.hpp)";
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Remote Password UNLOCK/LOCK: the password itself travels as cleartext ASCII on "
                    "the wire even when this optional protection is enabled (value redacted in this "
                    "decoder's own output, per NTLM/Netlogon-style posture)");
                break;
            }
            case 0x0619: {  // Echo/Loopback Test
                frame.has_echo_data = true;
                uint16_t length = c.u16le();
                ByteSpan data = c.bytes(length);
                frame.echo_data = std::string(reinterpret_cast<const char*>(data.data()), data.size());
                summary << ": " << length << " byte(s) of echo data";
                break;
            }
            default:
                summary << " (no further decode -- unrecognized command)";
                break;
        }
    } catch (const ParseError&) {
        summary.str("");
        summary << frame.command_name << " " << (is_response ? "response" : "request")
                << " (payload shorter than this command's expected shape -- not fully decoded)";
        frame.notes.push_back("payload truncated or malformed relative to " + frame.command_name +
                               "'s expected shape; only the common header was decoded");
    }
    frame.summary = summary.str();
}

// Parses only as much of the header as is needed to read the declared-length field and validate the
// two-part structural gate (subheader magic + declared-length floor), returning the byte offset the
// length field itself starts at and the frame's own shape (is_4e/is_response). Shared by
// try_parse_melsec and melsec_declared_length so both apply the exact same gate.
struct MelsecHeaderPeek {
    bool is_4e = false;
    bool is_response = false;
    size_t bytes_before_length_field = 0;
};

std::optional<MelsecHeaderPeek> peek_header(ByteSpan payload) {
    if (payload.size() < 2) return std::nullopt;
    Cursor c(payload);
    uint16_t subheader = c.u16be();
    MelsecHeaderPeek peek;
    if (subheader == kSubheader3EReq) {
        peek.is_4e = false;
        peek.is_response = false;
    } else if (subheader == kSubheader3ERes) {
        peek.is_4e = false;
        peek.is_response = true;
    } else if (subheader == kSubheader4EReq) {
        peek.is_4e = true;
        peek.is_response = false;
    } else if (subheader == kSubheader4ERes) {
        peek.is_4e = true;
        peek.is_response = true;
    } else {
        return std::nullopt;
    }
    peek.bytes_before_length_field = 2 + (peek.is_4e ? k4ESerialSize : 0) + kCommonHeaderSize;
    return peek;
}

// Re-derives a response frame's own body span from `payload` -- only ever called after
// try_parse_melsec has already validated this exact payload's shape, so every read here is known to
// succeed (peek_header/the length-field read cannot fail on a payload try_parse_melsec accepted).
ByteSpan response_body_span(ByteSpan payload) {
    auto peek = peek_header(payload);
    Cursor c(payload);
    c.skip(peek->bytes_before_length_field + 2);  // header through the length field
    c.u16le();                                     // End Code
    return c.rest();
}

}  // namespace

std::optional<std::string> melsec_command_name(uint16_t command, uint16_t subcommand) {
    auto it = command_table().find((static_cast<uint32_t>(command) << 16) | subcommand);
    if (it == command_table().end()) return std::nullopt;
    return it->second.name;
}

std::optional<size_t> melsec_declared_length(ByteSpan payload) {
    auto peek = peek_header(payload);
    if (!peek) return std::nullopt;
    size_t length_field_offset = peek->bytes_before_length_field;
    if (payload.size() < length_field_offset + 2) return std::nullopt;
    Cursor c(payload);
    c.skip(length_field_offset);
    uint16_t declared_length = c.u16le();
    if (declared_length > kMaxPlausibleMelsecDataLength) return std::nullopt;
    size_t floor = peek->is_response ? 2 : 6;
    if (declared_length < floor) return std::nullopt;
    return length_field_offset + 2 + declared_length;
}

std::optional<MelsecFrame> try_parse_melsec(ByteSpan payload) {
    auto peek = peek_header(payload);
    if (!peek) return std::nullopt;
    try {
        Cursor c(payload);
        c.u16be();  // subheader, already validated by peek_header

        MelsecFrame frame;
        frame.is_4e_frame = peek->is_4e;
        frame.is_response = peek->is_response;
        if (frame.is_4e_frame) {
            frame.serial_number = c.u16le();
        }

        frame.network_no = c.u8();
        frame.pc_no = c.u8();
        frame.request_dest_module_io_no = c.u16le();
        frame.request_dest_module_station_no = c.u8();

        uint16_t declared_length = c.u16le();
        size_t floor = frame.is_response ? 2 : 6;
        if (declared_length < floor || declared_length > kMaxPlausibleMelsecDataLength) {
            return std::nullopt;
        }
        if (payload.size() != peek->bytes_before_length_field + 2 + declared_length) {
            return std::nullopt;
        }

        uint16_t command = 0;
        uint16_t subcommand = 0;
        ByteSpan body;
        if (!frame.is_response) {
            frame.has_monitoring_timer = true;
            frame.monitoring_timer = c.u16le();
            command = c.u16le();
            subcommand = c.u16le();
            body = c.rest();
        } else {
            frame.has_end_code = true;
            frame.end_code = c.u16le();
            frame.end_code_name = end_code_name(frame.end_code);
            body = c.rest();
        }

        // Command/subcommand are only carried on the wire by the REQUEST side -- a response has no
        // command field of its own (just End Code + data). This decoder is stateless (see
        // melsec.hpp), so a response frame has no way to know which command it answers; it is
        // reported structurally (End Code + raw byte count) rather than guessed at.
        if (!frame.is_response) {
            frame.has_command = true;
            frame.command = command;
            frame.subcommand = subcommand;
            auto name = melsec_command_name(command, subcommand);
            frame.command_recognized = name.has_value();
            if (name) {
                frame.command_name = *name;
                decode_payload(frame, command, subcommand, false, body);
            } else {
                std::ostringstream n;
                n << "Unknown command 0x" << std::hex << std::uppercase << std::setw(4)
                  << std::setfill('0') << command << "/0x" << std::setw(4) << std::setfill('0')
                  << subcommand << std::dec;
                frame.command_name = n.str();
                std::ostringstream summary;
                summary << frame.command_name << " request (" << body.size() << " byte(s) of data, "
                        << "not decoded -- unrecognized command)";
                frame.summary = summary.str();
            }
        } else {
            frame.command_name = "response";
            std::ostringstream summary;
            summary << "MELSEC response: " << frame.end_code_name;
            if (!body.empty()) {
                summary << ", " << body.size() << " byte(s) of data";
            }
            frame.summary = summary.str();
            if (!body.empty()) {
                frame.has_undecoded_response_bytes = true;
                frame.undecoded_response_byte_count = body.size();
            }
        }

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

namespace {

// Shared by MelsecTcpDecoder::decode/MelsecUdpDecoder::decode -- session-scoped request/response
// matching, see melsec.hpp's "RESPONSE DECODING NEEDS SESSION CONTEXT" paragraph and
// MelsecFlowState's own comment for the full rationale.
std::optional<ProtocolResult> decode_with_session_state(ByteSpan payload, DecodeContext& ctx) {
    auto parsed = try_parse_melsec(payload);
    if (!parsed) return std::nullopt;
    MelsecFrame frame = std::move(*parsed);

    MelsecFlowState& state = ctx.flow_state<MelsecFlowState>();
    if (!frame.is_response) {
        if (state.pending) {
            frame.notes.push_back(
                "a previous request (" + state.pending->command_name + ", packet #" +
                std::to_string(state.pending->packet_index) +
                ") on this session was never matched with a response before this new request was "
                "sent -- possibly a missed reply, an out-of-order capture, or a client that doesn't "
                "wait for replies; only the most recently sent outstanding request is tracked");
        }
        state.pending = MelsecPendingRequest{frame.command,
                                              frame.subcommand,
                                              frame.command_name,
                                              ctx.packet_index,
                                              frame.random_read_word_count,
                                              frame.random_read_dword_count};
    } else if (state.pending) {
        frame.command_name = state.pending->command_name;
        frame.has_command = true;
        frame.command = state.pending->command;
        frame.subcommand = state.pending->subcommand;
        frame.command_recognized =
            melsec_command_name(state.pending->command, state.pending->subcommand).has_value();
        frame.random_read_word_count = state.pending->random_read_word_count;
        frame.random_read_dword_count = state.pending->random_read_dword_count;
        ByteSpan body = response_body_span(payload);
        decode_payload(frame, state.pending->command, state.pending->subcommand, true, body);
        frame.notes.push_back(
            "matched to the request seen in packet #" + std::to_string(state.pending->packet_index) +
            " (" + state.pending->command_name + ") on this session -- MELSEC responses carry no "
            "command field of their own on the wire, see melsec.hpp");
        state.pending.reset();
    } else {
        frame.notes.push_back(
            "no outstanding request found on this session -- this response's own command is unknown "
            "(MELSEC responses carry no command field of their own on the wire), decoded "
            "structurally only (End Code + raw byte count)");
    }

    return ProtocolResult::make<MelsecFrame>("melsec", std::move(frame));
}

}  // namespace

std::optional<ProtocolResult> MelsecTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_session_state(payload, ctx);
}

std::optional<ProtocolResult> MelsecUdpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_session_state(payload, ctx);
}

const ProtocolDecoder& melsec_tcp_decoder() {
    static const MelsecTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& melsec_udp_decoder() {
    static const MelsecUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
