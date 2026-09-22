// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/hartip.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

#include "conduitscope/resource_limits.hpp"
#include "conduitscope/tunnel_vpn.hpp"  // IKE_NATT_PORT/VXLAN_PORT -- see hartip_udp_excluded_port

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Small formatting helpers.

std::string format_float(double v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

std::string hex_byte(uint8_t b) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(b);
    return s.str();
}

std::string hex_word(uint16_t w) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << static_cast<unsigned>(w);
    return s.str();
}

// Reads a big-endian IEEE 754 single starting at `offset`. Mirrors bacnet.cpp's own Real (tag 4)
// decode: accumulate bytes into a uint32_t, then memcpy-reinterpret -- portable, no UB, no
// platform-specific reinterpret_cast.
std::optional<float> read_float32(ByteSpan span, size_t offset) {
    if (offset + 4 > span.size()) return std::nullopt;
    uint32_t bits = 0;
    for (int i = 0; i < 4; ++i) bits = (bits << 8) | span.at(offset + i);
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// ------------------------------------------------------------------------------------------
// Header-field name lookups -- see hartip.hpp's file header comment for sourcing.

bool is_valid_message_type(uint8_t t) { return t == 0 || t == 1 || t == 2 || t == 3 || t == 15; }

std::string message_type_name(uint8_t t) {
    switch (t) {
        case 0: return "Request";
        case 1: return "Response";
        case 2: return "Publish";
        case 3: return "Error";
        case 15: return "NAK";
        default: return "unknown(" + std::to_string(t) + ")";
    }
}

std::string message_id_name(uint8_t id) {
    switch (id) {
        case 0: return "Session Initiate";
        case 1: return "Session Close";
        case 2: return "Keep Alive";
        case 3: return "Pass Through";
        default: return "unknown(" + std::to_string(id) + ")";
    }
}

std::string host_type_name(uint8_t t) {
    switch (t) {
        case 0: return "Secondary Host";
        case 1: return "Primary Host";
        default: return "unknown(" + std::to_string(t) + ")";
    }
}

// The only 3 values packet-hartip.c's own hartip_error_code_values table defines.
std::string hartip_error_code_name(uint8_t c) {
    switch (c) {
        case 0: return "Session closed";
        case 1: return "Primary session unavailable";
        case 2: return "Service unavailable";
        default: return "unknown(" + std::to_string(c) + ")";
    }
}

std::string frame_type_name(uint8_t ft) {
    switch (ft) {
        case 1: return "BACK";
        case 2: return "STX";
        case 6: return "ACK";
        default: return "unknown(" + std::to_string(ft) + ")";
    }
}

std::string physical_layer_type_name(uint8_t p) {
    switch (p) {
        case 0: return "Asynchronous";
        case 1: return "Synchronous";
        default: return "unknown(" + std::to_string(p) + ")";
    }
}

// The 25 "single-definition" Response Codes (same meaning regardless of which command produced
// them) -- cross-checked against HCF_SPEC-307 "Command Response Code Specification" Rev 6.0. See
// hartip.hpp's file header comment's Response Code section for the full sourcing note and the
// multi-definition/warning classes this decoder deliberately does not attempt.
const std::pair<uint32_t, const char*> kResponseCodeNames[] = {
    {0, "Success"},
    {2, "Invalid Selection"},
    {3, "Passed Parameter Too Large"},
    {4, "Passed Parameter Too Small"},
    {5, "Too Few Data Bytes Received"},
    {6, "Device-Specific Command Error"},
    {7, "In Write Protect Mode"},
    {16, "Access Restricted"},
    {17, "Invalid Device Variable Index"},
    {18, "Invalid Units Code"},
    {19, "Device Variable Index Not Allowed"},
    {20, "Invalid Extended Command Number"},
    {21, "Invalid I/O Card Number"},
    {22, "Invalid Channel Number"},
    {23, "Sub-Device Response Too Long"},
    {32, "Busy"},
    {33, "Delayed Response Initiated"},
    {34, "Delayed Response Running"},
    {35, "Delayed Response Dead"},
    {36, "Delayed Response Conflict"},
    {60, "Payload Too Long"},
    {61, "No Buffers Available"},
    {62, "No Alarm/Event Buffers Available"},
    {63, "Priority Too Low"},
    {64, "Command Not Implemented"},
};

// code7 is the Response Code byte with bit 7 (the comm-error selector) already masked off.
std::string response_code_name(uint8_t code7) {
    for (const auto& e : kResponseCodeNames) {
        if (e.first == code7) return e.second;
    }
    return "command-specific response code " + std::to_string(code7) +
           " (meaning depends on which command produced it -- not decoded)";
}

// bit 7 of the Response Code byte was set -- the low 7 bits are a communication-error bitmask
// (bits 6-1 cross-corroborated across two independent vendor HART references; bit 0's meaning is
// NOT confidently sourced -- see hartip.hpp's Response Code section).
std::vector<std::string> decode_comm_error_flags(uint8_t code) {
    std::vector<std::string> flags;
    if (code & 0x40) flags.push_back("vertical-parity-error");
    if (code & 0x20) flags.push_back("overrun-error");
    if (code & 0x10) flags.push_back("framing-error");
    if (code & 0x08) flags.push_back("longitudinal-parity-error");
    if (code & 0x04) flags.push_back("reserved(bit2)");
    if (code & 0x02) flags.push_back("buffer-overflow");
    if (code & 0x01) flags.push_back("reserved-unconfirmed(bit0)");
    return flags;
}

// Device Status -- cross-corroborated across six independent HART device vendors' own published
// HART reference manuals, which all reproduce this exact 8-bit table verbatim (NOT sourced from
// Wireshark, whose own dissector leaves this byte opaque) -- see hartip.hpp's Device Status
// section.
std::vector<std::string> decode_device_status_flags(uint8_t status) {
    std::vector<std::string> flags;
    if (status & 0x80) flags.push_back("field-device-malfunction");
    if (status & 0x40) flags.push_back("configuration-changed");
    if (status & 0x20) flags.push_back("cold-start");
    if (status & 0x10) flags.push_back("more-status-available");
    if (status & 0x08) flags.push_back("loop-current-fixed");
    if (status & 0x04) flags.push_back("loop-current-saturated");
    if (status & 0x02) flags.push_back("non-primary-variable-out-of-limits");
    if (status & 0x01) flags.push_back("primary-variable-out-of-limits");
    return flags;
}

// ------------------------------------------------------------------------------------------
// HART packed-ASCII: 6 bits/char, 3 input bytes -> 4 output characters. Transform confirmed
// verbatim from Wireshark's dissect_packAscii (packet-hartip.c) -- see hartip.hpp's file header
// comment. Deliberately does NOT trim trailing pad (space, 0x20) characters -- shown exactly as
// present on the wire, the same literal-rendering posture bacnet.cpp's own Character String
// decode already takes.
std::string decode_packed_ascii(ByteSpan bytes) {
    std::string out;
    size_t groups = bytes.size() / 3;
    out.reserve(groups * 4);
    for (size_t g = 0; g < groups; ++g) {
        uint8_t b0 = bytes.at(g * 3), b1 = bytes.at(g * 3 + 1), b2 = bytes.at(g * 3 + 2);
        uint8_t c[4];
        c[0] = static_cast<uint8_t>((b0 >> 2) & 0x3F);
        c[1] = static_cast<uint8_t>(((b0 << 4) | (b1 >> 4)) & 0x3F);
        c[2] = static_cast<uint8_t>(((b1 << 2) | (b2 >> 6)) & 0x3F);
        c[3] = static_cast<uint8_t>(b2 & 0x3F);
        for (int i = 0; i < 4; ++i) {
            if (c[i] < 32) c[i] = static_cast<uint8_t>(c[i] + 64);
            out.push_back(static_cast<char>(c[i]));
        }
    }
    return out;
}

// The trailing 4-byte HART-format timestamp several commands (9, 203) carry: raw units of 1/32
// ms -- see hartip.hpp's Command dispatch section for commands 9/203's own field list, which
// documents this exact conversion.
std::string decode_hart_timestamp(uint32_t raw) {
    uint64_t t = static_cast<uint64_t>(raw) / 32;  // now in whole milliseconds
    uint64_t ms = t % 1000;
    t /= 1000;
    uint64_t sec = t % 60;
    t /= 60;
    uint64_t min = t % 60;
    t /= 60;
    uint64_t hr = t;
    std::ostringstream s;
    s << std::setfill('0') << std::setw(2) << hr << ":" << std::setw(2) << min << ":" << std::setw(2) << sec
      << "." << std::setw(3) << ms;
    return s.str();
}

// ------------------------------------------------------------------------------------------
// Per-command data decoders -- see hartip.hpp's file header comment's "Command dispatch" section
// for the exact byte layout and sourcing of each of these. Each returns true only when the data
// it was given matches the exact length(s) this decoder expects for that command; on a length
// mismatch it returns false without partially filling `pt.values`, and the caller
// (decode_command_data) falls back to showing the data as raw hex -- "not guessed at", the same
// posture this codebase already takes for BACnet's own malformed/unexpected-shape data.

bool decode_cmd_read_unique_id(ByteSpan data, HartIpPassThrough& pt, std::vector<std::string>& notes) {
    if (data.size() != 12 && data.size() != 22) return false;
    uint8_t expansion_code = data.at(0);
    uint16_t expanded_device_type = static_cast<uint16_t>((data.at(1) << 8) | data.at(2));
    uint8_t min_req_preambles = data.at(3);
    uint8_t universal_rev = data.at(4);
    uint8_t device_rev = data.at(5);
    uint8_t software_rev = data.at(6);
    uint8_t hw_sig_byte = data.at(7);
    uint8_t hw_rev = static_cast<uint8_t>(hw_sig_byte >> 3);
    uint8_t signaling_code = static_cast<uint8_t>(hw_sig_byte & 0x07);
    uint8_t flags = data.at(8);

    pt.values.push_back("expansion-code=" + hex_byte(expansion_code));
    pt.values.push_back("expanded-device-type=" + hex_word(expanded_device_type));
    pt.values.push_back("min-request-preambles=" + std::to_string(min_req_preambles));
    pt.values.push_back("universal-command-revision=" + std::to_string(universal_rev));
    pt.values.push_back("device-revision=" + std::to_string(device_rev));
    pt.values.push_back("software-revision=" + std::to_string(software_rev));
    pt.values.push_back("hardware-revision=" + std::to_string(hw_rev));
    pt.values.push_back("physical-signaling-code=" + std::to_string(signaling_code));
    pt.values.push_back("flags=" + hex_byte(flags));
    pt.values.push_back("device-id=" + to_hex(data.subspan(9, 3), ""));

    if (data.size() == 22) {
        uint8_t min_resp_preambles = data.at(12);
        uint8_t max_dev_vars = data.at(13);
        uint16_t config_change_counter = static_cast<uint16_t>((data.at(14) << 8) | data.at(15));
        uint8_t ext_dev_status = data.at(16);
        uint16_t manufacturer_id = static_cast<uint16_t>((data.at(17) << 8) | data.at(18));
        uint16_t private_label = static_cast<uint16_t>((data.at(19) << 8) | data.at(20));
        uint8_t device_profile = data.at(21);

        pt.values.push_back("min-response-preambles=" + std::to_string(min_resp_preambles));
        pt.values.push_back("max-device-variables=" + std::to_string(max_dev_vars));
        pt.values.push_back("configuration-change-counter=" + std::to_string(config_change_counter));
        pt.values.push_back("extended-device-status=" + hex_byte(ext_dev_status));
        pt.values.push_back("manufacturer-id=" + hex_word(manufacturer_id));
        pt.values.push_back("private-label-distributor-code=" + hex_word(private_label));
        pt.values.push_back("device-profile=" + std::to_string(device_profile));
    } else {
        notes.push_back(
            "Read Unique Identifier response is the 12-byte basic form (no Min. Response Preambles/Max. "
            "Device Variables/Configuration Change Counter/Extended Device Status/Manufacturer ID/"
            "Private-Label Distributor code/Device Profile fields)");
    }
    return true;
}

bool decode_cmd_1(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 5) return false;
    uint8_t units = data.at(0);
    auto pv = read_float32(data, 1);
    if (!pv) return false;
    pt.values.push_back("pv-units=" + std::to_string(units));
    pt.values.push_back("pv=" + format_float(*pv));
    return true;
}

bool decode_cmd_2(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 8) return false;
    auto current = read_float32(data, 0);
    auto pct = read_float32(data, 4);
    if (!current || !pct) return false;
    pt.values.push_back("pv-loop-current-ma=" + format_float(*current));
    pt.values.push_back("pv-percent-range=" + format_float(*pct));
    return true;
}

bool decode_cmd_3(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 24) return false;
    auto current = read_float32(data, 0);
    if (!current) return false;
    pt.values.push_back("pv-loop-current-ma=" + format_float(*current));
    static const char* kNames[4] = {"pv", "sv", "tv", "qv"};
    size_t offset = 4;
    for (int i = 0; i < 4; ++i) {
        uint8_t units = data.at(offset);
        auto v = read_float32(data, offset + 1);
        if (!v) return false;
        pt.values.push_back(std::string(kNames[i]) + "-units=" + std::to_string(units));
        pt.values.push_back(std::string(kNames[i]) + "=" + format_float(*v));
        offset += 5;
    }
    return true;
}

// Shared by command 6 (Write Polling Address) and command 7 (Read Loop Configuration) -- see
// hartip.hpp: "identical response shape". Loop Current Mode's own value semantics were not
// confidently sourced during this decoder's own research, so it is surfaced as a raw byte rather
// than an asserted enabled/disabled label.
bool decode_cmd_6_7(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 2) return false;
    uint8_t addr = static_cast<uint8_t>(data.at(0) & 0x3F);
    uint8_t mode = data.at(1);
    pt.values.push_back("poll-address=" + std::to_string(addr));
    pt.values.push_back("loop-current-mode=" + std::to_string(mode));
    return true;
}

bool decode_cmd_8(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 4) return false;
    static const char* kNames[4] = {"pv", "sv", "tv", "qv"};
    for (int i = 0; i < 4; ++i) {
        pt.values.push_back(std::string(kNames[i]) + "-classification=" + std::to_string(data.at(i)));
    }
    return true;
}

bool decode_cmd_9(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() < 1 + 8 + 4) return false;
    size_t remaining = data.size() - 1 - 4;
    if (remaining % 8 != 0) return false;
    size_t n = remaining / 8;
    if (n < 1 || n > 8) return false;

    uint8_t eds = data.at(0);
    pt.values.push_back("extended-device-status=" + hex_byte(eds));
    size_t offset = 1;
    for (size_t i = 0; i < n; ++i) {
        uint8_t code = data.at(offset);
        uint8_t classification = data.at(offset + 1);
        uint8_t units = data.at(offset + 2);
        auto v = read_float32(data, offset + 3);
        if (!v) return false;
        uint8_t status = data.at(offset + 7);
        std::string prefix = "device-variable[" + std::to_string(i) + "]";
        pt.values.push_back(prefix + "-code=" + std::to_string(code));
        pt.values.push_back(prefix + "-classification=" + std::to_string(classification));
        pt.values.push_back(prefix + "-units=" + std::to_string(units));
        pt.values.push_back(prefix + "-value=" + format_float(*v));
        pt.values.push_back(prefix + "-status=" + hex_byte(status));
        offset += 8;
    }
    uint32_t ts_raw = (static_cast<uint32_t>(data.at(offset)) << 24) |
                       (static_cast<uint32_t>(data.at(offset + 1)) << 16) |
                       (static_cast<uint32_t>(data.at(offset + 2)) << 8) | data.at(offset + 3);
    pt.values.push_back("timestamp=" + decode_hart_timestamp(ts_raw));
    return true;
}

// Shared by command 12 (Read Message) and 17 (Write Message).
bool decode_cmd_message(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 24) return false;
    pt.values.push_back("message=" + decode_packed_ascii(data));
    return true;
}

// Shared by command 13 (Read Tag, Descriptor, Date) and 18 (Write Tag, Descriptor, Date).
bool decode_cmd_13_18(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 21) return false;
    pt.values.push_back("tag=" + decode_packed_ascii(data.subspan(0, 6)));
    pt.values.push_back("descriptor=" + decode_packed_ascii(data.subspan(6, 12)));
    uint8_t day = data.at(18), month = data.at(19), year = data.at(20);
    std::ostringstream s;
    s << std::setfill('0') << std::setw(2) << static_cast<unsigned>(month) << "/" << std::setw(2)
      << static_cast<unsigned>(day) << "/" << (1900 + static_cast<unsigned>(year));
    pt.values.push_back("date=" + s.str());
    return true;
}

bool decode_cmd_14(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 16) return false;
    auto upper = read_float32(data, 4);
    auto lower = read_float32(data, 8);
    auto span = read_float32(data, 12);
    if (!upper || !lower || !span) return false;
    pt.values.push_back("transducer-serial-number=" + to_hex(data.subspan(0, 3), ""));
    pt.values.push_back("limit-units=" + std::to_string(data.at(3)));
    pt.values.push_back("upper-transducer-limit=" + format_float(*upper));
    pt.values.push_back("lower-transducer-limit=" + format_float(*lower));
    pt.values.push_back("minimum-span=" + format_float(*span));
    return true;
}

bool decode_cmd_15(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 18) return false;
    auto upper = read_float32(data, 3);
    auto lower = read_float32(data, 7);
    auto damping = read_float32(data, 11);
    if (!upper || !lower || !damping) return false;
    pt.values.push_back("pv-alarm-selection=" + std::to_string(data.at(0)));
    pt.values.push_back("pv-transfer-function=" + std::to_string(data.at(1)));
    pt.values.push_back("range-units=" + std::to_string(data.at(2)));
    pt.values.push_back("upper-range-value=" + format_float(*upper));
    pt.values.push_back("lower-range-value=" + format_float(*lower));
    pt.values.push_back("damping-value=" + format_float(*damping));
    pt.values.push_back("write-protect=" + std::to_string(data.at(15)));
    pt.values.push_back("reserved=" + hex_byte(data.at(16)));
    pt.values.push_back("pv-analog-channel-flags=" + hex_byte(data.at(17)));
    return true;
}

// Shared by command 16 (Read Final Assembly Number) and 19 (Write Final Assembly Number).
bool decode_cmd_16_19(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 3) return false;
    uint32_t v = (static_cast<uint32_t>(data.at(0)) << 16) | (static_cast<uint32_t>(data.at(1)) << 8) |
                 data.at(2);
    pt.values.push_back("final-assembly-number=" + std::to_string(v));
    return true;
}

// Shared by command 20 (Read Long Tag) and 22 (Write Long Tag) -- 32-byte PLAIN (unpacked) ASCII,
// unlike Tag/Descriptor/Message's packed-ASCII encoding.
bool decode_cmd_20_22(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 32) return false;
    pt.values.push_back("long-tag=" + std::string(reinterpret_cast<const char*>(data.data()), data.size()));
    return true;
}

bool decode_cmd_33(ByteSpan data, HartIpPassThrough& pt) {
    if (data.empty() || data.size() % 6 != 0) return false;
    size_t n = data.size() / 6;
    if (n > 4) return false;
    for (size_t i = 0; i < n; ++i) {
        size_t offset = i * 6;
        uint8_t code = data.at(offset);
        uint8_t units = data.at(offset + 1);
        auto v = read_float32(data, offset + 2);
        if (!v) return false;
        std::string prefix = "device-variable[" + std::to_string(i) + "]";
        pt.values.push_back(prefix + "-code=" + std::to_string(code));
        pt.values.push_back(prefix + "-units=" + std::to_string(units));
        pt.values.push_back(prefix + "-value=" + format_float(*v));
    }
    return true;
}

// Reset Configuration Changed Flag: the request carries no data at all; the response carries a
// 2-byte Configuration Change Counter. Both are accepted here (the same command number's request
// and response shapes legitimately differ, unlike every other command pair this file decodes).
bool decode_cmd_38(ByteSpan data, HartIpPassThrough& pt) {
    if (data.empty()) return true;
    if (data.size() != 2) return false;
    uint16_t counter = static_cast<uint16_t>((data.at(0) << 8) | data.at(1));
    pt.values.push_back("configuration-change-counter=" + std::to_string(counter));
    return true;
}

bool decode_cmd_48(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() != 6 && data.size() != 14) return false;
    pt.values.push_back("device-specific-status=" + to_hex(data.subspan(0, 6), ""));
    if (data.size() == 14) {
        pt.values.push_back("extended-device-status=" + hex_byte(data.at(6)));
        pt.values.push_back("device-operating-mode=" + hex_byte(data.at(7)));
        pt.values.push_back("standardized-status-0=" + hex_byte(data.at(8)));
        pt.values.push_back("standardized-status-1=" + hex_byte(data.at(9)));
        pt.values.push_back("standardized-status-2=" + hex_byte(data.at(10)));
        pt.values.push_back("standardized-status-3=" + hex_byte(data.at(11)));
        pt.values.push_back("analog-channel-saturated=" + hex_byte(data.at(12)));
        pt.values.push_back("analog-channel-fixed=" + hex_byte(data.at(13)));
    }
    return true;
}

// Read Discrete Variables (with Status) -- structurally decoded, deliberately NOT given an
// authoritative top-level name (see hartip.hpp's Command dispatch section, command 203 entry).
bool decode_cmd_203(ByteSpan data, HartIpPassThrough& pt) {
    if (data.size() < 8) return false;
    size_t remaining = data.size() - 8;
    if (remaining % 3 != 0) return false;
    size_t n = remaining / 3;
    if (n < 1 || n > 6) return false;

    uint16_t index_first = static_cast<uint16_t>((data.at(0) << 8) | data.at(1));
    uint8_t num_dv = data.at(2);
    uint8_t ext_status = data.at(3);
    uint32_t ts_raw = (static_cast<uint32_t>(data.at(4)) << 24) | (static_cast<uint32_t>(data.at(5)) << 16) |
                       (static_cast<uint32_t>(data.at(6)) << 8) | data.at(7);
    pt.values.push_back("index-of-first-discrete-variable=" + std::to_string(index_first));
    pt.values.push_back("number-of-discrete-variables=" + std::to_string(num_dv));
    pt.values.push_back("extended-device-status=" + hex_byte(ext_status));
    pt.values.push_back("timestamp=" + decode_hart_timestamp(ts_raw));
    for (size_t i = 0; i < n; ++i) {
        size_t offset = 8 + i * 3;
        uint16_t state = static_cast<uint16_t>((data.at(offset) << 8) | data.at(offset + 1));
        uint8_t status = data.at(offset + 2);
        std::string prefix = "discrete-variable[" + std::to_string(i) + "]";
        pt.values.push_back(prefix + "-state=" + std::to_string(state));
        pt.values.push_back(prefix + "-status=" + hex_byte(status));
    }
    return true;
}

// Command 31: a 2-byte big-endian Extended Command Number, then (only when that number is 64386 /
// 0xFB82 -- a pairing directly confirmed in Wireshark's own source) the remaining data decoded as
// command 203. No top-level name is asserted for command 31 itself -- see hartip.hpp.
bool decode_cmd_31(ByteSpan data, HartIpPassThrough& pt, std::vector<std::string>& notes) {
    if (data.size() < 2) return false;
    uint16_t ext_cmd = static_cast<uint16_t>((data.at(0) << 8) | data.at(1));
    pt.values.push_back("extended-command-number=" + std::to_string(ext_cmd));
    ByteSpan rest = data.from(2);
    if (ext_cmd == 64386) {
        if (!decode_cmd_203(rest, pt) && !rest.empty()) {
            notes.push_back(
                "extended command 64386's data does not match the Read Discrete Variables (command 203) "
                "shape this decoder expects -- remaining data shown as raw hex");
            pt.data_shown_as_hex = true;
            pt.data_hex = to_hex(rest, "");
        }
    } else if (!rest.empty()) {
        pt.data_shown_as_hex = true;
        pt.data_hex = to_hex(rest, "");
    }
    return true;
}

// Forward declaration -- commands 77 and 178 (below) both recursively re-dispatch an embedded/
// aggregated command's own data through this same function (via decode_nested_command), the same
// recursive-reuse pattern enip.cpp's own Multiple_Service_Packet/Unconnected_Send decoding uses
// for CIP's structurally similar "one message wraps another message" shapes.
void decode_command_data(HartIpPassThrough& pt, ByteSpan data, std::vector<std::string>& notes);

// Decodes one embedded/aggregated HART command's own request or response data (used by both
// command 77's single embedded command and command 178's list of aggregated commands) by
// re-running it through this file's own top-level command dispatch, rather than duplicating any
// per-command byte layout a second time. `is_response` must be propagated from the caller's own
// outer-frame direction (this decoder has no other way to know it once inside a nested command's
// own Data). Returns the nested HartIpPassThrough so the caller can fold command_recognized/
// command_name/values into its OWN values under whatever prefix it chooses -- this function itself
// does not touch `pt`, only `parent_notes` (so a truncation inside the nested command is reported
// in context rather than silently swallowed).
HartIpPassThrough decode_nested_command(uint8_t command, ByteSpan data, bool is_response,
                                         std::vector<std::string>& parent_notes, const std::string& note_prefix) {
    HartIpPassThrough nested;
    nested.command = command;
    nested.is_response = is_response;
    std::vector<std::string> nested_notes;
    decode_command_data(nested, data, nested_notes);
    for (const auto& n : nested_notes) parent_notes.push_back(note_prefix + n);
    return nested;
}

// Command 77 -- "Send Command to Sub-Device" (name per FieldComm Group's own "HART-IP
// Application, Communication, and Control Analysis" document, section 2.2.2, which names this
// command explicitly as one of the I/O System Commands a HART-IP gateway/Remote I/O supports; the
// byte layout below is cross-checked against Wireshark's own dissect_cmd77). An I/O-card/channel-
// addressed RELAY that wraps another, arbitrary HART command's own request or response to a
// sub-device reachable through a multiplexer's I/O Card/Channel (used when a single HART-IP
// gateway multiplexes several classic wired-HART multidrop segments).
//
// Request shape:  IO Card(1) + Channel(1) + TX Preamble Count(1, request-only) + Embedded Command
//                  Delimiter(1) + Address(1 or 5, by the Embedded Command Delimiter's own bit 7 --
//                  the SAME Address-Type convention as the outer Pass-Through Delimiter, directly
//                  confirmed from Wireshark's own source for this embedded field too) + Embedded
//                  Command Number(1) + Embedded Command Byte Count(1) + embedded request Data
//                  (variable, per the Embedded Command Byte Count).
// Response shape: IO Card(1) + Channel(1) + Embedded Command Delimiter(1) + Address(1 or 5) +
//                  Embedded Command Number(1) + Embedded Command Byte Count(1) + Response Code(1)
//                  + Device Status(1) + embedded response Data(Embedded Command Byte Count - 2 --
//                  the same "Byte Count includes Response Code + Device Status" convention this
//                  file's own outer Pass-Through Byte Count field already uses, confirmed the same
//                  way for this embedded field in Wireshark's own source).
// Wireshark's own dissector does NOT decompose the Embedded Command Delimiter's other bits (frame
// type, physical layer, expansion byte count) for this nested field the way it does for the outer
// Pass-Through Delimiter, so this decoder doesn't assert those sub-fields here either -- only the
// sourced bit 7 (Address Type); the raw delimiter byte is still shown in full.
//
// The embedded command itself is then decoded recursively through this file's own top-level
// command dispatch (decode_nested_command) -- e.g. an embedded command 1 (Read Primary Variable)
// response shows its own decoded PV value under "embedded-pv=...", not just raw bytes.
// A truncation partway through this command's own sequential field layout (after IO Card/Channel
// have already been read) is reported via `notes` and STOPS parsing right there, returning true --
// the same "partial fill, note where it stopped, still recognized" posture decode_pass_through
// itself already takes for the outer frame, and deliberately NOT the "return false, discard
// everything already understood" posture this file's simple fixed-length commands use, since
// falling through to decode_command_data's own generic fallback here would additionally dump the
// ENTIRE original data as raw hex right alongside the fields already decoded above it -- redundant
// and confusing rather than informative.
bool decode_cmd_77(ByteSpan data, HartIpPassThrough& pt, std::vector<std::string>& notes) {
    size_t offset = 0;
    if (offset + 2 > data.size()) return false;
    uint8_t io_card = data.at(offset++);
    uint8_t channel = data.at(offset++);
    pt.values.push_back("io-card=" + std::to_string(io_card));
    pt.values.push_back("channel=" + std::to_string(channel));

    if (!pt.is_response) {
        if (offset >= data.size()) {
            notes.push_back("command 77 is truncated before its TX Preamble Count byte");
            return true;
        }
        uint8_t tx_preambles = data.at(offset++);
        pt.values.push_back("tx-preamble-count=" + std::to_string(tx_preambles));
    }

    if (offset >= data.size()) {
        notes.push_back("command 77 is truncated before its Embedded Command Delimiter byte");
        return true;
    }
    uint8_t emb_delim = data.at(offset++);
    bool emb_long_addr = (emb_delim & 0x80) != 0;
    pt.values.push_back("embedded-command-delimiter=" + hex_byte(emb_delim));

    if (emb_long_addr) {
        if (offset + 5 > data.size()) {
            notes.push_back("command 77 is truncated before its 5-byte long embedded Address");
            return true;
        }
        pt.values.push_back("embedded-address=" + to_hex(data.subspan(offset, 5), ""));
        offset += 5;
    } else {
        if (offset >= data.size()) {
            notes.push_back("command 77 is truncated before its embedded Address byte");
            return true;
        }
        uint8_t short_addr = static_cast<uint8_t>(data.at(offset++) & 0x3F);
        pt.values.push_back("embedded-address=" + std::to_string(short_addr));
    }

    if (offset >= data.size()) {
        notes.push_back("command 77 is truncated before its Embedded Command Number byte");
        return true;
    }
    uint8_t emb_cmd = data.at(offset++);
    pt.values.push_back("embedded-command=" + std::to_string(emb_cmd));

    if (offset >= data.size()) {
        notes.push_back("command 77 is truncated before its Embedded Command Byte Count byte");
        return true;
    }
    uint8_t emb_byte_count = data.at(offset++);

    size_t header_bytes = pt.is_response ? 2 : 0;
    if (pt.is_response) {
        if (offset + 2 > data.size()) {
            notes.push_back(
                "command 77 is truncated before its embedded Response Code/Device Status bytes");
            return true;
        }
        uint8_t emb_response_code = data.at(offset++);
        uint8_t emb_device_status = data.at(offset++);
        if (emb_response_code & 0x80) {
            for (const auto& f : decode_comm_error_flags(emb_response_code)) {
                pt.values.push_back("embedded-response-comm-error-flag=" + f);
            }
            pt.values.push_back("embedded-response-code=" + hex_byte(emb_response_code) + " (communication error)");
        } else {
            pt.values.push_back("embedded-response-code=" + std::to_string(emb_response_code) + " (" +
                                 response_code_name(emb_response_code) + ")");
        }
        for (const auto& f : decode_device_status_flags(emb_device_status)) {
            pt.values.push_back("embedded-device-status-flag=" + f);
        }
        pt.values.push_back("embedded-device-status=" + hex_byte(emb_device_status));
    }

    size_t emb_data_len;
    if (emb_byte_count >= header_bytes) {
        emb_data_len = static_cast<size_t>(emb_byte_count) - header_bytes;
    } else {
        notes.push_back("command 77's Embedded Command Byte Count (" + std::to_string(emb_byte_count) +
                         ") is smaller than the " + std::to_string(header_bytes) +
                         " Response Code/Device Status byte(s) it must include -- embedded Data length "
                         "treated as 0");
        emb_data_len = 0;
    }
    if (offset + emb_data_len > data.size()) {
        notes.push_back("command 77 declares " + std::to_string(emb_data_len) +
                         " embedded Data byte(s) (from its Embedded Command Byte Count) but only " +
                         std::to_string(data.size() - offset) + " are available -- truncated");
        emb_data_len = data.size() - offset;
    }
    ByteSpan emb_data = data.subspan(offset, emb_data_len);
    offset += emb_data_len;

    HartIpPassThrough nested = decode_nested_command(emb_cmd, emb_data, pt.is_response, notes,
                                                       "command 77's embedded command " +
                                                           std::to_string(emb_cmd) + ": ");
    if (nested.command_recognized) {
        if (!nested.command_name.empty()) pt.values.push_back("embedded-command-name=" + nested.command_name);
        for (const auto& v : nested.values) pt.values.push_back("embedded-" + v);
    } else if (!emb_data.empty()) {
        pt.values.push_back("embedded-data=" + to_hex(emb_data, ""));
    }

    if (offset < data.size()) {
        notes.push_back("command 77 has " + std::to_string(data.size() - offset) +
                         " trailing byte(s) after its embedded command's own data -- not decoded");
    }
    return true;
}

// Command 178 -- a BATCH/aggregate wrapper that bundles up to several other commands' own data in
// one message; cross-checked against Wireshark's own dissect_cmd178, which parses this exact shape
// for BOTH directions alike (no request/response branch in its own source, unlike command 77
// above) -- this decoder does the same, regardless of the outer Pass-Through frame's own
// is_response. FieldComm Group's own "HART-IP Application, Communication, and Control Analysis"
// document (Table 5) independently corroborates the per-entry Command Number/Byte Count/Response
// Code/Data shape while framing command 178 as the vehicle for that document's own "Publish"/
// burst-mode feature (bundling commands like 9 and 48 together into one unsolicited message) --
// but it does not give command 178 a name distinct from that use case, and no other source
// consulted gives one either, so, like commands 31 and 203, no top-level NAME is asserted for
// command 178 itself.
//
// Shape: Number of Commands(1), then that many entries of [Command Number(2, big-endian) +
// Command Byte Count(1) + Response Code(1) + Data(Command Byte Count - 1 -- the count includes the
// Response Code byte itself, confirmed directly from Wireshark's own source)]. Unlike command 77,
// there is no separate Device Status field per entry (or at all) in this wrapper -- Wireshark's own
// source has no such field here; a nested command's OWN per-item status bytes (e.g. command 9's
// per-Device-Variable Status byte) are unaffected, since those belong to that command's own
// already-decoded shape. Each entry's Command Number/Data is then decoded recursively through this
// file's own top-level command dispatch (decode_nested_command), the same reuse command 77 above
// uses -- e.g. an aggregated command 9 entry shows its own decoded Device Variables, not just raw
// bytes. A Command Number above 255 cannot match any entry in this file's (1-byte) command dispatch
// table, so it is always left unrecognized/shown as raw hex rather than truncated into a byte.
// The same "partial fill, note where it stopped, still recognized" posture decode_cmd_77 above
// documents applies here too, once Number of Commands (and any earlier entries) have already been
// decoded into pt.values.
bool decode_cmd_178(ByteSpan data, HartIpPassThrough& pt, std::vector<std::string>& notes) {
    size_t offset = 0;
    if (offset >= data.size()) return false;
    uint8_t num_commands = data.at(offset++);
    pt.values.push_back("number-of-commands=" + std::to_string(num_commands));

    for (size_t i = 0; i < num_commands; ++i) {
        std::string prefix = "aggregate[" + std::to_string(i) + "]-";
        if (offset + 2 > data.size()) {
            notes.push_back("command 178 is truncated before entry " + std::to_string(i) +
                             "'s Command Number");
            return true;
        }
        uint16_t cmd_num = static_cast<uint16_t>((data.at(offset) << 8) | data.at(offset + 1));
        offset += 2;
        if (offset >= data.size()) {
            notes.push_back("command 178 is truncated before entry " + std::to_string(i) +
                             "'s Command Byte Count");
            return true;
        }
        uint8_t cmd_byte_count = data.at(offset++);
        pt.values.push_back(prefix + "command=" + std::to_string(cmd_num));

        if (cmd_byte_count < 1) {
            notes.push_back("command 178 entry " + std::to_string(i) + "'s Command Byte Count (" +
                             std::to_string(cmd_byte_count) +
                             ") is smaller than the 1 Response Code byte it must include -- entry's "
                             "Response Code/Data not decoded, remaining entries (if any) skipped");
            return true;
        }
        if (offset >= data.size()) {
            notes.push_back("command 178 is truncated before entry " + std::to_string(i) +
                             "'s Response Code");
            return true;
        }
        uint8_t response_code = data.at(offset++);
        if (response_code & 0x80) {
            for (const auto& f : decode_comm_error_flags(response_code)) {
                pt.values.push_back(prefix + "response-comm-error-flag=" + f);
            }
            pt.values.push_back(prefix + "response-code=" + hex_byte(response_code) + " (communication error)");
        } else {
            pt.values.push_back(prefix + "response-code=" + std::to_string(response_code) + " (" +
                                 response_code_name(response_code) + ")");
        }

        size_t entry_data_len = static_cast<size_t>(cmd_byte_count) - 1;
        if (offset + entry_data_len > data.size()) {
            notes.push_back("command 178 entry " + std::to_string(i) + " declares " +
                             std::to_string(entry_data_len) + " Data byte(s) (from its Command Byte Count) "
                             "but only " + std::to_string(data.size() - offset) + " are available -- truncated");
            entry_data_len = data.size() - offset;
        }
        ByteSpan entry_data = data.subspan(offset, entry_data_len);
        offset += entry_data_len;

        if (cmd_num <= 0xFF) {
            HartIpPassThrough nested = decode_nested_command(static_cast<uint8_t>(cmd_num), entry_data,
                                                               pt.is_response, notes,
                                                               "command 178 entry " + std::to_string(i) + ": ");
            if (nested.command_recognized) {
                if (!nested.command_name.empty()) pt.values.push_back(prefix + "command-name=" + nested.command_name);
                for (const auto& v : nested.values) pt.values.push_back(prefix + v);
                continue;
            }
        }
        if (!entry_data.empty()) pt.values.push_back(prefix + "data=" + to_hex(entry_data, ""));
    }

    if (offset < data.size()) {
        notes.push_back("command 178 has " + std::to_string(data.size() - offset) +
                         " trailing byte(s) after its declared entries -- not decoded");
    }
    return true;
}

// Dispatches a Pass-Through message's command-specific Data to the "first pass" decoders above --
// see hartip.hpp's file header comment's "Command dispatch" section for exactly which command
// numbers this decoder value-decodes (including, now, 77 and 178's own recursive relay/aggregate
// decoding) and which (any command number outside this dispatch table entirely) are left
// named-only/raw-hex.
void decode_command_data(HartIpPassThrough& pt, ByteSpan data, std::vector<std::string>& notes) {
    uint8_t cmd = pt.command;
    bool ok = false;
    switch (cmd) {
        case 0:
        case 11:
        case 21:
            pt.command_name = "Read Unique Identifier";
            ok = decode_cmd_read_unique_id(data, pt, notes);
            break;
        case 1:
            pt.command_name = "Read Primary Variable";
            ok = decode_cmd_1(data, pt);
            break;
        case 2:
            pt.command_name = "Read Loop Current and Percent of Range";
            ok = decode_cmd_2(data, pt);
            break;
        case 3:
            pt.command_name = "Read Dynamic Variables and Loop Current";
            ok = decode_cmd_3(data, pt);
            break;
        case 6:
            pt.command_name = "Write Polling Address";
            ok = decode_cmd_6_7(data, pt);
            break;
        case 7:
            pt.command_name = "Read Loop Configuration";
            ok = decode_cmd_6_7(data, pt);
            break;
        case 8:
            pt.command_name = "Read Dynamic Variable Classifications";
            ok = decode_cmd_8(data, pt);
            break;
        case 9:
            pt.command_name = "Read Device Variables with Status";
            ok = decode_cmd_9(data, pt);
            break;
        case 12:
            pt.command_name = "Read Message";
            ok = decode_cmd_message(data, pt);
            break;
        case 17:
            pt.command_name = "Write Message";
            ok = decode_cmd_message(data, pt);
            break;
        case 13:
            pt.command_name = "Read Tag, Descriptor, Date";
            ok = decode_cmd_13_18(data, pt);
            break;
        case 18:
            pt.command_name = "Write Tag, Descriptor, Date";
            ok = decode_cmd_13_18(data, pt);
            break;
        case 14:
            pt.command_name = "Read Primary Variable Transducer Information";
            ok = decode_cmd_14(data, pt);
            break;
        case 15:
            pt.command_name = "Read Device Information";
            ok = decode_cmd_15(data, pt);
            break;
        case 16:
            pt.command_name = "Read Final Assembly Number";
            ok = decode_cmd_16_19(data, pt);
            break;
        case 19:
            pt.command_name = "Write Final Assembly Number";
            ok = decode_cmd_16_19(data, pt);
            break;
        case 20:
            pt.command_name = "Read Long Tag";
            ok = decode_cmd_20_22(data, pt);
            break;
        case 22:
            pt.command_name = "Write Long Tag";
            ok = decode_cmd_20_22(data, pt);
            break;
        case 31:
            ok = decode_cmd_31(data, pt, notes);
            break;
        case 33:
            pt.command_name = "Read Device Variables";
            ok = decode_cmd_33(data, pt);
            break;
        case 38:
            pt.command_name = "Reset Configuration Changed Flag";
            ok = decode_cmd_38(data, pt);
            break;
        case 48:
            pt.command_name = "Read Additional Device Status";
            ok = decode_cmd_48(data, pt);
            break;
        case 203:
            ok = decode_cmd_203(data, pt);
            break;
        case 77:
            pt.command_name = "Send Command to Sub-Device";
            ok = decode_cmd_77(data, pt, notes);
            break;
        case 178:
            ok = decode_cmd_178(data, pt, notes);
            break;
        default:
            break;
    }
    pt.command_recognized = ok;
    if (!ok && !data.empty()) {
        pt.data_shown_as_hex = true;
        pt.data_hex = to_hex(data, "");
        if (!pt.command_name.empty()) {
            notes.push_back("command " + std::to_string(cmd) + " (" + pt.command_name + ") data (" +
                             std::to_string(data.size()) +
                             " byte(s)) does not match the byte layout this decoder expects -- not "
                             "value-decoded, shown as raw hex");
        } else {
            notes.push_back("command " + std::to_string(cmd) +
                             " is not one of this decoder's first-pass value-decoded commands -- not "
                             "decoded, shown as raw hex");
        }
    }
}

std::string pass_through_summary(const HartIpPassThrough& pt) {
    std::ostringstream s;
    s << pt.frame_type_name << " command=" << static_cast<unsigned>(pt.command);
    if (!pt.command_name.empty()) s << " (" << pt.command_name << ")";
    if (pt.is_response) {
        if (pt.response_is_comm_error) {
            s << " comm-error";
        } else {
            s << " response-code=" << static_cast<unsigned>(pt.response_code) << " (" << pt.response_code_name
              << ")";
        }
    }
    if (!pt.values.empty()) {
        s << " [" << pt.values.front();
        if (pt.values.size() > 1) s << " +" << (pt.values.size() - 1) << " more";
        s << "]";
    }
    return s.str();
}

// Decodes the Pass-Through body -- see hartip.hpp's file header comment's Pass-Through section
// for the full byte-by-byte layout this was cross-checked against (packet-hartip.c's
// dissect_pass_through). Every step is explicitly bounds-checked (rather than relying on a single
// top-level try/catch) so a truncation can be pinpointed in the resulting note, the same posture
// bacnet.cpp's decode_npdu already takes.
void decode_pass_through(ByteSpan body, HartIpPassThrough& pt, std::vector<std::string>& notes) {
    size_t offset = 0;
    size_t size = body.size();

    while (offset < size && body.at(offset) == 0xFF) {
        pt.preamble_count++;
        offset++;
    }

    if (offset >= size) {
        notes.push_back("Pass-Through body truncated before its Delimiter byte");
        return;
    }
    // The longitudinal (XOR) checksum below covers every byte from the Delimiter through the
    // last byte of Data inclusive -- i.e. everything from here (offset now points at the
    // Delimiter, having already skipped any leading Preamble) up to, but not including, the
    // Checksum byte itself.
    size_t checksum_span_start = offset;
    pt.delimiter = body.at(offset++);
    pt.frame_type = static_cast<uint8_t>(pt.delimiter & 0x07);
    pt.frame_type_name = frame_type_name(pt.frame_type);
    pt.is_response = (pt.frame_type == 6 || pt.frame_type == 1);
    pt.physical_layer_type = static_cast<uint8_t>((pt.delimiter >> 3) & 0x03);
    pt.physical_layer_type_name = physical_layer_type_name(pt.physical_layer_type);
    pt.expansion_byte_count = static_cast<uint8_t>((pt.delimiter >> 5) & 0x03);
    pt.is_long_address = (pt.delimiter & 0x80) != 0;

    if (pt.is_long_address) {
        if (offset + 5 > size) {
            notes.push_back("Pass-Through body truncated before its 5-byte long Address");
            return;
        }
        pt.long_address_hex = to_hex(body.subspan(offset, 5), "");
        offset += 5;
    } else {
        if (offset >= size) {
            notes.push_back("Pass-Through body truncated before its Address byte");
            return;
        }
        pt.short_address = static_cast<uint8_t>(body.at(offset++) & 0x3F);
    }

    if (pt.expansion_byte_count > 0) {
        if (offset + pt.expansion_byte_count > size) {
            notes.push_back("Pass-Through body truncated before its Expansion byte(s)");
            return;
        }
        pt.expansion_bytes_hex = to_hex(body.subspan(offset, pt.expansion_byte_count), "");
        offset += pt.expansion_byte_count;
    }

    if (offset >= size) {
        notes.push_back("Pass-Through body truncated before its Command byte");
        return;
    }
    pt.command = body.at(offset++);

    if (offset >= size) {
        notes.push_back("Pass-Through body truncated before its Byte Count byte");
        return;
    }
    pt.byte_count = body.at(offset++);

    size_t header_bytes = pt.is_response ? 2 : 0;
    if (pt.is_response) {
        if (offset + 2 > size) {
            notes.push_back("Pass-Through body truncated before its Response Code/Device Status bytes");
            return;
        }
        pt.response_code = body.at(offset++);
        pt.response_is_comm_error = (pt.response_code & 0x80) != 0;
        if (pt.response_is_comm_error) {
            pt.comm_error_flags = decode_comm_error_flags(pt.response_code);
        } else {
            pt.response_code_name = response_code_name(static_cast<uint8_t>(pt.response_code & 0x7F));
        }
        pt.device_status = body.at(offset++);
        pt.device_status_flags = decode_device_status_flags(pt.device_status);
    }

    size_t data_length;
    if (pt.byte_count >= header_bytes) {
        data_length = static_cast<size_t>(pt.byte_count) - header_bytes;
    } else {
        notes.push_back("Pass-Through Byte Count (" + std::to_string(pt.byte_count) + ") is smaller than the " +
                         std::to_string(header_bytes) +
                         " Response Code/Device Status byte(s) it must include -- Data length treated as 0");
        data_length = 0;
    }

    if (offset + data_length > size) {
        notes.push_back("Pass-Through body declares " + std::to_string(data_length) +
                         " Data byte(s) (from its Byte Count field) but only " + std::to_string(size - offset) +
                         " are available -- truncated");
        data_length = size - offset;
    }

    ByteSpan data = body.subspan(offset, data_length);
    pt.data_length = data_length;
    offset += data_length;

    decode_command_data(pt, data, notes);

    if (offset < size) {
        pt.checksum = body.at(offset);
        uint8_t computed = 0;
        for (size_t i = checksum_span_start; i < offset; ++i) computed ^= body.at(i);
        pt.checksum_valid = (computed == pt.checksum);
        if (!pt.checksum_valid) {
            notes.push_back("longitudinal (XOR) checksum mismatch: calculated " + hex_byte(computed) +
                             ", frame declares " + hex_byte(pt.checksum));
        }
        offset++;
    } else {
        notes.push_back("Pass-Through body truncated before its trailing Checksum byte");
    }

    if (offset < size) {
        notes.push_back(std::to_string(size - offset) +
                         " trailing byte(s) remain after the Checksum -- unexpected, not decoded");
    }
}

std::string frame_summary(const HartIpFrame& frame) {
    std::ostringstream s;
    s << frame.message_type_name << " " << frame.message_id_name;
    if (frame.has_error) {
        s << " error-code=" << static_cast<unsigned>(frame.error_code) << " (" << frame.error_code_name << ")";
    } else if (frame.has_pass_through) {
        s << " " << frame.pass_through.summary;
    } else if (frame.has_session_init) {
        s << " host-type=" << frame.session_init.host_type_name
          << " inactivity-close-timer=" << frame.session_init.inactivity_close_timer << "s";
    }
    return s.str();
}

}  // namespace

std::optional<size_t> hartip_declared_length(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    uint8_t message_type = payload.at(1);
    uint8_t message_id = payload.at(2);
    if (!is_valid_message_type(message_type) || message_id > 3) return std::nullopt;
    uint16_t msg_length = static_cast<uint16_t>((payload.at(6) << 8) | payload.at(7));
    return static_cast<size_t>(msg_length);
}

std::optional<HartIpFrame> try_parse_hartip(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    try {
        uint8_t message_type = payload.at(1);
        uint8_t message_id = payload.at(2);
        if (!is_valid_message_type(message_type) || message_id > 3) return std::nullopt;
        uint16_t msg_length = static_cast<uint16_t>((payload.at(6) << 8) | payload.at(7));
        if (msg_length < 8) return std::nullopt;

        HartIpFrame frame;
        frame.version = payload.at(0);
        frame.message_type = message_type;
        frame.message_type_name = message_type_name(message_type);
        frame.message_id = message_id;
        frame.message_id_name = message_id_name(message_id);
        frame.status = payload.at(3);
        frame.transaction_id = static_cast<uint16_t>((payload.at(4) << 8) | payload.at(5));
        frame.msg_length = msg_length;

        size_t available = payload.size();
        size_t body_end = std::min(static_cast<size_t>(msg_length), available);
        if (static_cast<size_t>(msg_length) > available) {
            frame.notes.push_back("HART-IP message declares MsgLength " + std::to_string(msg_length) +
                                   " but only " + std::to_string(available) +
                                   " byte(s) are available -- truncated");
        }
        frame.wire_length = body_end;
        ByteSpan body = payload.subspan(8, body_end - 8);

        bool is_error = (message_type == 3 || message_type == 15);
        if (is_error) {
            if (body.size() == 1) {
                frame.has_error = true;
                frame.error_code = body.at(0);
                frame.error_code_name = hartip_error_code_name(frame.error_code);
            } else if (!body.empty()) {
                frame.notes.push_back("Error/NAK body is " + std::to_string(body.size()) +
                                       " byte(s), expected exactly 1 -- not decoded: " + to_hex(body, ""));
            } else {
                frame.notes.push_back(
                    "Error/NAK message has an empty body, expected exactly 1 byte (ErrorCode) -- not decoded");
            }
        } else {
            switch (message_id) {
                case 0: {  // Session Initiate
                    if (body.size() == 5) {
                        frame.has_session_init = true;
                        frame.session_init.host_type = body.at(0);
                        frame.session_init.host_type_name = host_type_name(frame.session_init.host_type);
                        frame.session_init.inactivity_close_timer =
                            (static_cast<uint32_t>(body.at(1)) << 24) |
                            (static_cast<uint32_t>(body.at(2)) << 16) |
                            (static_cast<uint32_t>(body.at(3)) << 8) | body.at(4);
                    } else if (!body.empty()) {
                        frame.notes.push_back("Session Initiate body is " + std::to_string(body.size()) +
                                               " byte(s), expected exactly 5 -- not decoded: " +
                                               to_hex(body, ""));
                    } else {
                        frame.notes.push_back(
                            "Session Initiate message has an empty body, expected exactly 5 bytes (HostType "
                            "+ InactivityCloseTimer) -- not decoded");
                    }
                    break;
                }
                case 1:    // Session Close
                case 2: {  // Keep Alive -- both expected EMPTY; see hartip.hpp
                    if (!body.empty()) {
                        frame.notes.push_back(std::string(message_id == 1 ? "Session Close" : "Keep Alive") +
                                               " body is " + std::to_string(body.size()) +
                                               " byte(s), expected 0 (empty) -- not decoded: " + to_hex(body, ""));
                    }
                    break;
                }
                case 3: {  // Pass Through (also covers Publish, MessageType 2)
                    frame.has_pass_through = true;
                    decode_pass_through(body, frame.pass_through, frame.notes);
                    frame.pass_through.summary = pass_through_summary(frame.pass_through);
                    break;
                }
                default:
                    break;  // unreachable -- message_id already validated to be 0-3 above
            }
        }

        frame.summary = frame_summary(frame);
        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // bacnet.cpp/goose.cpp/sv.cpp/profinet.cpp/ethercat.cpp all take.
        return std::nullopt;
    }
}

bool hartip_udp_excluded_port(uint16_t port) {
    return port == IKE_NATT_PORT || port == VXLAN_PORT;
}

std::optional<ProtocolResult> HartIpTcpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_hartip(payload);
    if (!frame) return std::nullopt;

    HartIpResult result;
    result.summary = frame->summary;
    for (const auto& n : frame->notes) result.notes.push_back(n);
    result.first = *frame;

    // Like EtherNet/IP's own encapsulation messages, one HART-IP message is small and it's normal
    // for a sender or the OS to coalesce several into one TCP segment -- exact transplant of the
    // legacy `if (want_hartip)` TCP call site's own coalescing loop.
    // CLI-configurable via --max-coalesced-messages -- see resource_limits.hpp. 0/unset keeps
    // the literal 50 default.
    const size_t kMaxHartIpMessagesPerPayload = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = frame->wire_length;
    size_t message_count = 1;
    while (offset < payload.size() && message_count < kMaxHartIpMessagesPerPayload) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_hartip(rest);
        if (!next) break;  // remaining bytes aren't another HART-IP message -- stop, don't guess
        ++message_count;
        std::string note = "additional HART-IP message " + std::to_string(message_count) +
                            " found in the same TCP payload at byte offset " + std::to_string(offset) +
                            " (coalesced by the sender/OS): " + next->summary;
        result.notes.push_back(note);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
    }
    if (message_count >= kMaxHartIpMessagesPerPayload) {
        result.notes.push_back("stopped after " + std::to_string(kMaxHartIpMessagesPerPayload) +
                                " HART-IP message(s) in this one TCP payload, more may remain "
                                "(safety cap)");
    }

    return ProtocolResult::make<HartIpResult>("hartip", std::move(result));
}

std::optional<ProtocolResult> HartIpUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_hartip(payload);
    if (!frame) return std::nullopt;

    HartIpResult result;
    result.summary = frame->summary;
    for (const auto& n : frame->notes) result.notes.push_back(n);
    result.first = *frame;
    return ProtocolResult::make<HartIpResult>("hartip", std::move(result));
}

const ProtocolDecoder& hartip_tcp_decoder() {
    static const HartIpTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& hartip_udp_decoder() {
    static const HartIpUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
