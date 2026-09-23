// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/fins.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace conduitscope {

namespace {

// A real FINS command/response frame realistically never approaches this; guards against a
// coincidentally plausible but wildly large declared length being mistaken for a genuine frame
// split across TCP segments and buffered forever -- the same defense-in-depth posture
// melsec.cpp's kMaxPlausibleMelsecDataLength takes for its own declared-length field.
constexpr uint32_t kMaxPlausibleFinsTcpLength = 8192;

// The 17 commands this decoder verified (see fins.hpp's file header comment) -- keyed by the
// 2-byte command code (MRC<<8|SRC), names verbatim from Wireshark's own command_code_cv[].
const std::unordered_map<uint16_t, const char*>& command_table() {
    static const std::unordered_map<uint16_t, const char*> table = {
        {0x0101, "Memory Area Read"},
        {0x0102, "Memory Area Write"},
        {0x0103, "Memory Area Fill"},
        {0x0104, "Multiple Memory Area Read"},
        {0x0401, "Run"},
        {0x0402, "Stop"},
        {0x0501, "Controller Data Read"},
        {0x0601, "Controller Status Read"},
        {0x0620, "Cycle Time Read"},
        {0x0701, "Clock Read"},
        {0x0702, "Clock Write"},
        {0x0801, "LOOP-BACK Test"},
        {0x0C01, "Access Right Acquire"},
        {0x0C02, "Access Right Forced Acquire"},
        {0x0C03, "Access Right Release"},
        {0x2101, "Error Clear"},
        {0x2301, "Forced Set/Reset"},
        {0x2302, "Forced Set/Reset Cancel"},
    };
    return table;
}

// Memory area code table -- transcribed from Wireshark's own memory_area_code_cv[]/
// memory_area_code_prefix[] (re-fetched this implementation pass, see fins.hpp's file header
// comment). `prefix` for Timer/Counter/Index-Register/Data-Register/Task-Flag/Clock-Pulses is THIS
// DECODER'S OWN CONVENTION -- Wireshark's own memory_area_code_prefix[] table doesn't cover those
// codes (it shows only the full descriptive name for them); everything else's prefix is verbatim
// from that table.
struct FinsAreaInfo {
    bool is_bit;
};

const std::unordered_map<uint8_t, FinsAreaInfo>& area_code_table() {
    static const std::unordered_map<uint8_t, FinsAreaInfo> table = [] {
        std::unordered_map<uint8_t, FinsAreaInfo> t = {
            {0x30, {"CIO", true}},  {0x31, {"W", true}},   {0x32, {"H", true}},   {0x33, {"A", true}},
            {0x70, {"CIO", true}},  {0x71, {"W", true}},   {0x72, {"H", true}},
            {0xB0, {"CIO", false}}, {0xB1, {"W", false}},  {0xB2, {"H", false}},  {0xB3, {"A", false}},
            {0xF0, {"CIO", false}}, {0xF1, {"W", false}},  {0xF2, {"H", false}},
            {0x02, {"D", true}},    {0x82, {"D", false}},
            {0x09, {"TIM", true}},  {0x49, {"TIM", true}}, {0x89, {"TIM", false}},
            {0xDC, {"IR", false}},  {0xBC, {"DR", false}},
            {0x06, {"TK", true}},   {0x46, {"TK", false}},
            {0x07, {"CF", true}},
        };
        // Expansion DM banks E0-EC: bit (0x20-0x2C) and word (0xA0-0xAC), 13 banks each -- confirmed
        // via Wireshark's own memory_area_code_prefix[] (full "E0_".."EC_" range on both sides).
        for (int bank = 0; bank <= 0x0C; ++bank) {
            std::string prefix = "E" + std::to_string(bank) + "_";
            keep.push_back(prefix);
            t[static_cast<uint8_t>(0x20 + bank)] = {keep.back().c_str(), true};
            keep.push_back(prefix);
            t[static_cast<uint8_t>(0xA0 + bank)] = {keep.back().c_str(), false};
        }
        return t;
    }();
    return table;
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v << std::dec;
    return s.str();
}

FinsMemoryItem make_item(uint8_t area_code, uint16_t address, uint8_t bit_address) {
    FinsMemoryItem item;
    item.area_code = area_code;
    item.address = address;
    item.bit_address = bit_address;
    std::ostringstream s;
    auto it = area_code_table().find(area_code);
    if (it == area_code_table().end()) {
        s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
          << static_cast<int>(area_code) << std::dec << ":" << address;
        if (bit_address != 0) s << "." << static_cast<int>(bit_address);
        item.is_bit = bit_address != 0;  // best-effort guess for an unrecognized area code
        item.device_text = s.str();
        return item;
    }
    item.is_bit = it->second.is_bit;
    s << it->second.prefix << address;
    if (item.is_bit && bit_address != 0) {
        s << "." << std::setw(2) << std::setfill('0') << static_cast<int>(bit_address);
    }
    item.device_text = s.str();
    return item;
}

// End code table -- the full 79-entry table transcribed verbatim from Wireshark's own
// response_codes[] (re-fetched this implementation pass, sourced from the official OMRON FINS
// Commands Reference Manual W227-E1-2).
const std::unordered_map<uint16_t, const char*>& end_code_table() {
    static const std::unordered_map<uint16_t, const char*> table = {
        {0x0000, "Normal completion"},
        {0x0001, "Service was interrupted"},
        {0x0101, "Local node not part of Network"},
        {0x0102, "Token time-out, node number to large"},
        {0x0103, "Number of transmit retries exceeded"},
        {0x0104, "Maximum number of frames exceeded"},
        {0x0105, "Node number setting error (range)"},
        {0x0106, "Node number duplication error"},
        {0x0201, "Destination node not part of Network"},
        {0x0202, "No node with the specified node number"},
        {0x0203, "Third node not part of Network : Broadcasting was specified"},
        {0x0204, "Busy error, destination node busy"},
        {0x0205, "Response time-out"},
        {0x0301, "Error occurred : ERC indicator is lit"},
        {0x0302, "CPU error occurred in the PC at the destination node"},
        {0x0303, "A controller error has prevented a normal response"},
        {0x0304, "Node number setting error"},
        {0x0401, "An undefined command has been used"},
        {0x0402, "Cannot process command because the specified unit model or version is wrong"},
        {0x0501, "Destination node number is not set in the routing table"},
        {0x0502, "Routing table isn't registered"},
        {0x0503, "Routing table error"},
        {0x0504, "Max relay nodes (2) was exceeded"},
        {0x1001, "The command is longer than the max permissible length"},
        {0x1002, "The command is shorter than the min permissible length"},
        {0x1003, "The designated number of data items differs from the actual number"},
        {0x1004, "An incorrect command format has been used"},
        {0x1005, "An incorrect header has been used"},
        {0x1101, "Memory area code invalid or DM is not available"},
        {0x1102, "Access size is wrong in command"},
        {0x1103, "First address in inaccessible area"},
        {0x1104, "The end of specified word range exceeds acceptable range"},
        {0x1106, "A non-existent program number"},
        {0x1109, "The size of data items in command block are wrong"},
        {0x110A, "The IOM break function cannot be executed"},
        {0x110B, "The response block is longer than the max length"},
        {0x110C, "An incorrect parameter code has been specified"},
        {0x2002, "The data is protected"},
        {0x2003, "Registered table does not exist"},
        {0x2004, "Search data does not exist"},
        {0x2005, "Non-existent program number"},
        {0x2006, "Non-existent file"},
        {0x2007, "Verification error"},
        {0x2101, "Specified area is read-only"},
        {0x2102, "The data is protected"},
        {0x2103, "Too many files open"},
        {0x2105, "Non-existent program number"},
        {0x2106, "Non-existent file"},
        {0x2107, "File already exists"},
        {0x2108, "Data cannot be changed"},
        {0x2201, "The mode is wrong (executing)"},
        {0x2202, "The mode is wrong (stopped)"},
        {0x2203, "The PC is in the PROGRAM mode"},
        {0x2204, "The PC is in the DEBUG mode"},
        {0x2205, "The PC is in the MONITOR mode"},
        {0x2206, "The PC is in the RUN mode"},
        {0x2207, "The specified node is not the control node"},
        {0x2208, "The mode is wrong and the step cannot be executed"},
        {0x2301, "The file device does not exist where specified"},
        {0x2302, "The specified memory does not exist"},
        {0x2303, "No clock exists"},
        {0x2401, "Data link table is incorrect"},
        {0x2502, "Parity / checksum error occurred"},
        {0x2503, "I/O setting error"},
        {0x2504, "Too many I/O points"},
        {0x2505, "CPU bus error"},
        {0x2506, "I/O duplication error"},
        {0x2507, "I/O bus error"},
        {0x2509, "SYSMAC BUS/2 error"},
        {0x250A, "Special I/O Unit error"},
        {0x250D, "Duplication in SYSMAC BUS word allocation"},
        {0x250F, "A memory error has occurred"},
        {0x2510, "Terminator not connected in SYSMAC BUS system"},
        {0x2601, "The specified area is not protected"},
        {0x2602, "An incorrect password has been specified"},
        {0x2604, "The specified area is protected"},
        {0x2605, "The service is being executed"},
        {0x2606, "The service is not being executed"},
        {0x2607, "Service cannot be execute from local node"},
        {0x2608, "Service cannot be executed settings are incorrect"},
        {0x2609, "Service cannot be executed incorrect settings in command data"},
        {0x260A, "The specified action has already been registered"},
        {0x260B, "Cannot clear error, error still exists"},
        {0x3001, "The access right is held by another device"},
        {0x4001, "Command aborted with ABORT command"},
    };
    return table;
}

std::string end_code_name(uint16_t code) {
    auto it = end_code_table().find(code);
    if (it != end_code_table().end()) return it->second;
    return "Error " + hex4(code) + " (not independently verified)";
}

std::string status_name(uint8_t status) {
    switch (status) {
        case 0x00: return "Stop";
        case 0x01: return "Run";
        case 0x80: return "CPU on standby";
        default: return "unrecognized (" + std::to_string(static_cast<int>(status)) + ")";
    }
}

std::string ctrl_mode_name(uint8_t mode) {
    switch (mode) {
        case 0x00: return "PROGRAM mode";
        case 0x01: return "DEBUG mode";
        case 0x02: return "MONITOR mode";
        case 0x04: return "RUN mode";
        default: return "unrecognized (" + std::to_string(static_cast<int>(mode)) + ")";
    }
}

// Forced Set/Reset's own "specification" field -- transcribed verbatim from Wireshark's own
// omron_set_reset_specifications[] (re-fetched this implementation pass).
std::string set_reset_specification_name(uint16_t spec) {
    switch (spec) {
        case 0x0000: return "Force-reset (OFF)";
        case 0x0001: return "Force-set (ON)";
        case 0x8000: return "Forced status released and bit turned OFF (0)";
        case 0x8001: return "Forced status released and bit turned ON (1)";
        case 0xFFFF: return "Forced status released";
        default: return "unrecognized (" + hex4(spec) + ")";
    }
}

// FINS/TCP's own tcp_command_cv[]/tcp_error_code_cv[] (re-fetched this implementation pass).
std::string tcp_command_name(uint32_t cmd) {
    switch (cmd) {
        case 0x00: return "Node Address Data Send (Client to Server)";
        case 0x01: return "Node Address Data Send (Server to Client)";
        case 0x02: return "Frame Send";
        case 0x03: return "Frame Send Error Notification";
        case 0x06: return "Connection Confirmation";
        default: return "Unrecognized FINS/TCP command " + hex4(static_cast<uint16_t>(cmd));
    }
}

std::string tcp_error_code_name(uint32_t code) {
    switch (code) {
        case 0x00: return "Normal";
        case 0x01: return "The header is not 'FINS' (ASCII code)";
        case 0x02: return "The data length is too long";
        case 0x03: return "The command is not supported";
        case 0x20: return "All connections are in use";
        case 0x21: return "The specified node is already connected";
        case 0x22: return "Attempt to access a protected node from an unspecified IP address";
        case 0x23: return "The client FINS node address is out of range";
        case 0x24: return "The same FINS node address is being used by the client and server";
        case 0x25: return "All the node addresses available for allocation have been used";
        default: return "unrecognized (0x" + [&] {
            std::ostringstream s; s << std::hex << std::uppercase << code; return s.str();
        }() + ")";
    }
}

uint8_t bcd_to_int(uint8_t v) { return static_cast<uint8_t>(((v >> 4) & 0xF) * 10 + (v & 0xF)); }

std::string trim_trailing(const std::string& s) {
    size_t end = s.find_last_not_of(' ');
    return end == std::string::npos ? std::string() : s.substr(0, end + 1);
}

// Decodes the command-specific request/response data into frame's own fields plus summary/notes.
// Never throws -- a payload shorter than a command's expected shape is caught (ParseError from the
// bounds-checked Cursor) and reported as a note, mirroring melsec.cpp's decode_payload exactly.
// `pending_devices`, when non-null, is the ORIGINAL REQUEST's own device list -- only consumed by
// Memory Area Read (0101) and Multiple Memory Area Read (0104) responses, see fins.hpp's "A GENUINE
// ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph for why every other response decodes without it.
void decode_payload(FinsFrame& frame, uint16_t command, bool is_response, ByteSpan body,
                     const std::vector<FinsMemoryItem>* pending_devices) {
    std::ostringstream summary;
    summary << frame.command_name << " " << (is_response ? "response" : "request");
    try {
        Cursor c(body);
        ByteSpan data;
        if (is_response) {
            frame.has_end_code = true;
            frame.end_code = c.u16be();
            frame.end_code_name = end_code_name(frame.end_code);
            data = c.rest();
        } else {
            data = c.rest();
        }
        Cursor dc(data);

        switch (command) {
            case 0x0101: {  // Memory Area Read
                if (!is_response) {
                    uint8_t area = dc.u8();
                    uint16_t addr = dc.u16be();
                    uint8_t bit_addr = dc.u8();
                    uint16_t num_items = dc.u16be();
                    FinsMemoryItem item = make_item(area, addr, bit_addr);
                    frame.has_point_count = true;
                    frame.point_count = num_items;
                    summary << ": " << item.device_text << ", " << num_items << " item(s), "
                            << (item.is_bit ? "bit" : "word");
                    frame.devices.push_back(std::move(item));
                } else if (pending_devices && pending_devices->size() == 1) {
                    const FinsMemoryItem& req_item = (*pending_devices)[0];
                    if (req_item.is_bit) {
                        for (size_t i = 0; i < data.size(); ++i) frame.bit_values.push_back(dc.u8());
                        summary << ": " << frame.bit_values.size() << " bit value(s)";
                    } else {
                        while (!dc.at_end()) frame.word_values.push_back(static_cast<int16_t>(dc.u16be()));
                        summary << ": " << frame.word_values.size() << " word value(s)";
                    }
                } else {
                    frame.has_undecoded_response_bytes = true;
                    frame.undecoded_response_byte_count = data.size();
                    summary << ": " << data.size()
                            << " byte(s) of data (word/bit split unknown -- no matching request's "
                               "own device available, see fins.hpp)";
                }
                frame.notes.push_back(
                    "Memory Area Read: arbitrary PLC device memory read, no protocol-level access control");
                break;
            }
            case 0x0102: {  // Memory Area Write
                if (!is_response) {
                    uint8_t area = dc.u8();
                    uint16_t addr = dc.u16be();
                    uint8_t bit_addr = dc.u8();
                    uint16_t num_items = dc.u16be();
                    FinsMemoryItem item = make_item(area, addr, bit_addr);
                    frame.has_point_count = true;
                    frame.point_count = num_items;
                    if (item.is_bit) {
                        for (uint16_t i = 0; i < num_items && !dc.at_end(); ++i) frame.bit_values.push_back(dc.u8());
                    } else {
                        for (uint16_t i = 0; i < num_items && dc.remaining() >= 2; ++i) {
                            frame.word_values.push_back(static_cast<int16_t>(dc.u16be()));
                        }
                    }
                    summary << ": " << item.device_text << ", " << num_items << " item(s), "
                            << (item.is_bit ? "bit" : "word");
                    frame.devices.push_back(std::move(item));
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Memory Area Write: arbitrary PLC device memory write, no protocol-level access control");
                break;
            }
            case 0x0103: {  // Memory Area Fill
                if (!is_response) {
                    uint8_t area = dc.u8();
                    uint16_t addr = dc.u16be();
                    uint8_t bit_addr = dc.u8();
                    uint16_t num_items = dc.u16be();
                    FinsMemoryItem item = make_item(area, addr, bit_addr);
                    frame.has_point_count = true;
                    frame.point_count = num_items;
                    frame.word_values.push_back(static_cast<int16_t>(dc.u16be()));
                    summary << ": " << item.device_text << ", " << num_items
                            << " item(s) filled with " << frame.word_values.back();
                    frame.devices.push_back(std::move(item));
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Memory Area Fill: arbitrary PLC device memory write, no protocol-level access control");
                break;
            }
            case 0x0104: {  // Multiple Memory Area Read
                if (!is_response) {
                    while (dc.remaining() >= 4) {
                        uint8_t area = dc.u8();
                        uint16_t addr = dc.u16be();
                        uint8_t bit_addr = dc.u8();
                        frame.devices.push_back(make_item(area, addr, bit_addr));
                    }
                    summary << ": " << frame.devices.size() << " item(s)";
                } else if (pending_devices && !pending_devices->empty()) {
                    for (const FinsMemoryItem& req_item : *pending_devices) {
                        FinsMemoryItem out_item = req_item;
                        if (req_item.is_bit) {
                            out_item.value_text = std::to_string(static_cast<int>(dc.u8()));
                        } else {
                            out_item.value_text = std::to_string(static_cast<int16_t>(dc.u16be()));
                        }
                        frame.devices.push_back(std::move(out_item));
                    }
                    summary << ": " << frame.devices.size() << " value(s)";
                } else {
                    frame.has_undecoded_response_bytes = true;
                    frame.undecoded_response_byte_count = data.size();
                    summary << ": " << data.size()
                            << " byte(s) of data (per-item split unknown -- no matching request's "
                               "own device list available, see fins.hpp)";
                }
                frame.notes.push_back(
                    "Multiple Memory Area Read: arbitrary PLC device memory read, no protocol-level "
                    "access control");
                break;
            }
            case 0x0401: {  // Run
                if (!is_response) {
                    frame.has_program_number = true;
                    frame.program_number = dc.u16be();
                    if (data.size() >= 3) {
                        frame.has_mode_code = true;
                        frame.mode_code = dc.u8();
                    }
                    summary << ": program " << frame.program_number;
                    if (frame.has_mode_code) summary << ", mode " << static_cast<int>(frame.mode_code);
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Run: no protocol-level authentication for CPU control -- the Omron analogue of "
                    "MELSEC's Remote RUN and S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x0402: {  // Stop
                summary << (is_response ? " (no data)" : " (no arguments)");
                frame.notes.push_back(
                    "Stop: no protocol-level authentication for CPU control -- the Omron analogue of "
                    "MELSEC's Remote STOP and S7comm's PLC Control/PLC Stop exposure");
                break;
            }
            case 0x0501: {  // Controller Data Read
                frame.notes.push_back(
                    "Controller Data Read: unauthenticated reconnaissance -- reveals PLC model/"
                    "firmware version to any network-reachable client");
                if (!is_response) {
                    summary << " (no data)";
                } else if (data.size() == 92 || data.size() == 159) {
                    frame.has_controller_info = true;
                    std::string model(reinterpret_cast<const char*>(dc.bytes(20).data()), 20);
                    std::string version(reinterpret_cast<const char*>(dc.bytes(20).data()), 20);
                    frame.controller_model = trim_trailing(model);
                    frame.controller_version = trim_trailing(version);
                    size_t remaining = dc.remaining();
                    summary << ": model=\"" << frame.controller_model << "\", version=\""
                            << frame.controller_version << "\", " << remaining
                            << " byte(s) not decoded further";
                    if (remaining > 0) {
                        frame.has_undecoded_response_bytes = true;
                        frame.undecoded_response_byte_count = remaining;
                    }
                } else {
                    frame.has_undecoded_response_bytes = true;
                    frame.undecoded_response_byte_count = data.size();
                    summary << ": " << data.size() << " byte(s) of data, shown structurally only";
                }
                break;
            }
            case 0x0601: {  // Controller Status Read
                if (!is_response) {
                    summary << " (no data)";
                } else if (data.size() >= 26) {
                    frame.has_status_info = true;
                    frame.status = dc.u8();
                    frame.status_name = status_name(frame.status);
                    frame.ctrl_mode = dc.u8();
                    frame.ctrl_mode_name = ctrl_mode_name(frame.ctrl_mode);
                    frame.fatal_error_flags = dc.u16be();
                    frame.non_fatal_error_flags = dc.u16be();
                    frame.message_flags = dc.u16be();
                    frame.has_fals_number = true;
                    frame.fals_number = dc.u16be();
                    std::string msg(reinterpret_cast<const char*>(dc.bytes(16).data()), 16);
                    frame.error_message = trim_trailing(msg);
                    summary << ": status=" << frame.status_name << ", mode=" << frame.ctrl_mode_name;
                } else {
                    frame.has_undecoded_response_bytes = true;
                    frame.undecoded_response_byte_count = data.size();
                    summary << ": " << data.size() << " byte(s) of data, shown structurally only";
                }
                break;
            }
            case 0x0620: {  // Cycle Time Read
                if (!is_response) {
                    frame.has_cycle_parameter = true;
                    frame.cycle_parameter = dc.u8();
                    summary << ": " << (frame.cycle_parameter == 0 ? "initialize" : "read");
                } else if (data.size() >= 12) {
                    frame.has_cycle_stats = true;
                    frame.cycle_avg_us = dc.u32be();
                    frame.cycle_max_us = dc.u32be();
                    frame.cycle_min_us = dc.u32be();
                    summary << ": avg=" << frame.cycle_avg_us << "us, max=" << frame.cycle_max_us
                            << "us, min=" << frame.cycle_min_us << "us";
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x0701: {  // Clock Read
                if (!is_response) {
                    summary << " (no data)";
                } else if (data.size() >= 7) {
                    frame.has_clock = true;
                    frame.clock_year = bcd_to_int(dc.u8());
                    frame.clock_month = bcd_to_int(dc.u8());
                    frame.clock_date = bcd_to_int(dc.u8());
                    frame.clock_hour = bcd_to_int(dc.u8());
                    frame.clock_minute = bcd_to_int(dc.u8());
                    frame.clock_second = bcd_to_int(dc.u8());
                    frame.clock_day = dc.u8();
                    std::ostringstream ts;
                    ts << "20" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_year)
                       << "-" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_month)
                       << "-" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_date)
                       << " " << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_hour)
                       << ":" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_minute)
                       << ":" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_second);
                    summary << ": " << ts.str();
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x0702: {  // Clock Write
                if (!is_response) {
                    frame.has_clock = true;
                    frame.clock_year = bcd_to_int(dc.u8());
                    frame.clock_month = bcd_to_int(dc.u8());
                    frame.clock_date = bcd_to_int(dc.u8());
                    frame.clock_hour = bcd_to_int(dc.u8());
                    frame.clock_minute = bcd_to_int(dc.u8());
                    if (data.size() >= 7) {
                        frame.clock_second = bcd_to_int(dc.u8());
                        frame.clock_day = dc.u8();
                    }
                    std::ostringstream ts;
                    ts << "20" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_year)
                       << "-" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_month)
                       << "-" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_date)
                       << " " << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_hour)
                       << ":" << std::setw(2) << std::setfill('0') << static_cast<int>(frame.clock_minute);
                    summary << ": " << ts.str();
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x0801: {  // LOOP-BACK Test
                frame.has_echo_data = true;
                frame.echo_data = std::string(reinterpret_cast<const char*>(data.data()), data.size());
                summary << ": " << data.size() << " byte(s) of echo data";
                break;
            }
            case 0x0C01: {  // Access Right Acquire
                if (!is_response) {
                    frame.has_program_number = true;
                    frame.program_number = dc.u16be();
                    summary << ": program " << frame.program_number;
                } else if (data.size() >= 3) {
                    frame.has_access_right_holder = true;
                    frame.access_right_unit_address = dc.u8();
                    frame.access_right_node_number = dc.u8();
                    frame.access_right_network_address = dc.u8();
                    summary << ": already held by network " << static_cast<int>(frame.access_right_network_address)
                            << ", node " << static_cast<int>(frame.access_right_node_number) << ", unit "
                            << static_cast<int>(frame.access_right_unit_address);
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x0C02: {  // Access Right Forced Acquire
                if (!is_response) {
                    frame.has_program_number = true;
                    frame.program_number = dc.u16be();
                    summary << ": program " << frame.program_number;
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Access Right Forced Acquire: lets any client seize exclusive write access away "
                    "from whoever currently holds it, with no credential check at all");
                break;
            }
            case 0x0C03: {  // Access Right Release
                if (!is_response) {
                    frame.has_program_number = true;
                    frame.program_number = dc.u16be();
                    summary << ": program " << frame.program_number;
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x2101: {  // Error Clear
                if (!is_response) {
                    frame.has_fals_number = true;
                    frame.fals_number = dc.u16be();
                    summary << ": FALS number " << frame.fals_number;
                } else {
                    summary << " (no data)";
                }
                break;
            }
            case 0x2301: {  // Forced Set/Reset
                if (!is_response) {
                    uint16_t n = dc.u16be();
                    for (uint16_t i = 0; i < n && dc.remaining() >= 6; ++i) {
                        FinsForceEntry entry;
                        entry.specification = dc.u16be();
                        entry.specification_name = set_reset_specification_name(entry.specification);
                        entry.area_code = dc.u8();
                        uint32_t a = dc.u8(), b = dc.u8(), cc = dc.u8();
                        entry.bit_address = (a << 16) | (b << 8) | cc;
                        FinsMemoryItem item = make_item(entry.area_code, static_cast<uint16_t>(entry.bit_address >> 4),
                                                         static_cast<uint8_t>(entry.bit_address & 0xF));
                        entry.device_text = item.device_text;
                        frame.force_entries.push_back(std::move(entry));
                    }
                    summary << ": " << frame.force_entries.size() << " bit(s)";
                } else {
                    summary << " (no data)";
                }
                frame.notes.push_back(
                    "Forced Set/Reset: overrides live I/O bit values directly, bypassing normal "
                    "program logic");
                break;
            }
            case 0x2302: {  // Forced Set/Reset Cancel
                summary << (is_response ? " (no data)" : " (no arguments)");
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

}  // namespace

std::optional<std::string> fins_command_name(uint16_t command) {
    auto it = command_table().find(command);
    if (it == command_table().end()) return std::nullopt;
    return it->second;
}

std::optional<FinsFrame> try_parse_fins_frame(ByteSpan payload,
                                               const std::vector<FinsMemoryItem>* pending_devices) {
    if (payload.size() < 12) return std::nullopt;
    try {
        Cursor c(payload);
        FinsFrame frame;
        frame.icf = c.u8();
        if ((frame.icf & 0x3E) != 0) return std::nullopt;  // reserved bits must be zero
        frame.rsv = c.u8();
        if (frame.rsv != 0x00) return std::nullopt;
        frame.gct = c.u8();
        frame.dna = c.u8();
        frame.da1 = c.u8();
        frame.da2 = c.u8();
        frame.sna = c.u8();
        frame.sa1 = c.u8();
        frame.sa2 = c.u8();
        frame.sid = c.u8();
        frame.mrc = c.u8();
        frame.src_code = c.u8();
        frame.command = (static_cast<uint16_t>(frame.mrc) << 8) | frame.src_code;
        frame.is_response = (frame.icf & 0x40) != 0;

        auto name = fins_command_name(frame.command);
        frame.command_recognized = name.has_value();
        frame.command_name = name ? *name : ("Unknown command " + hex4(frame.command));

        ByteSpan body = c.rest();
        decode_payload(frame, frame.command, frame.is_response, body, pending_devices);
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> fins_tcp_declared_length(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    if (!(payload.at(0) == 'F' && payload.at(1) == 'I' && payload.at(2) == 'N' && payload.at(3) == 'S')) {
        return std::nullopt;
    }
    Cursor c(payload);
    c.skip(4);
    uint32_t length = c.u32be();
    if (length < 8 || length > kMaxPlausibleFinsTcpLength) return std::nullopt;
    return 8 + static_cast<size_t>(length);
}

namespace {

// Shared by FinsTcpDecoder::decode (unwrapping a Frame Send payload) and FinsUdpDecoder::decode --
// session-scoped request/response matching, see fins.hpp's "A GENUINE ARCHITECTURAL DIFFERENCE FROM
// MELSEC" paragraph and FinsFlowState's own comment for the full rationale. `require_recognized`
// implements the UDP-only "reject unrecognized commands outright" half of the structural gate (see
// fins.hpp) -- false for the TCP path, where the outer "FINS" magic is already a strong-enough gate
// on its own.
std::optional<ProtocolResult> decode_inner_with_session_state(ByteSpan inner_payload, DecodeContext& ctx,
                                                                bool require_recognized) {
    FinsFlowState& state = ctx.flow_state<FinsFlowState>();
    const std::vector<FinsMemoryItem>* pending_ptr = state.pending ? &state.pending->devices : nullptr;

    auto parsed = try_parse_fins_frame(inner_payload, pending_ptr);
    if (!parsed) return std::nullopt;
    FinsFrame frame = std::move(*parsed);

    if (require_recognized && !frame.command_recognized) {
        return std::nullopt;
    }

    if (!frame.is_response) {
        if (state.pending) {
            frame.notes.push_back(
                "a previous request (" + state.pending->command_name + ", packet #" +
                std::to_string(state.pending->packet_index) +
                ") on this session was never matched with a response before this new request was "
                "sent -- possibly a missed reply, an out-of-order capture, or a client that doesn't "
                "wait for replies; only the most recently sent outstanding request is tracked");
        }
        FinsPendingRequest pending;
        pending.command = frame.command;
        pending.command_name = frame.command_name;
        pending.packet_index = ctx.packet_index;
        pending.devices = frame.devices;
        state.pending = std::move(pending);
    } else if (state.pending) {
        frame.notes.push_back("matched to the request seen in packet #" +
                               std::to_string(state.pending->packet_index) + " (" +
                               state.pending->command_name +
                               ") on this session -- SID is present but not treated as an "
                               "authoritative transaction ID, see fins.hpp");
        frame.matched_to_request = true;
        state.pending.reset();
    } else {
        frame.notes.push_back(
            "no outstanding request found on this session -- if this response's own command is "
            "Memory Area Read or Multiple Memory Area Read, its values could not be split (no "
            "matching request's own device list available)");
    }

    return ProtocolResult::make<FinsFrame>("fins", std::move(frame));
}

}  // namespace

std::optional<ProtocolResult> FinsTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (payload.size() < 16) return std::nullopt;
    if (!(payload.at(0) == 'F' && payload.at(1) == 'I' && payload.at(2) == 'N' && payload.at(3) == 'S')) {
        return std::nullopt;
    }
    Cursor c(payload);
    c.skip(4);
    uint32_t length = c.u32be();
    if (length < 8 || length > kMaxPlausibleFinsTcpLength) return std::nullopt;
    if (payload.size() != 8 + static_cast<size_t>(length)) return std::nullopt;
    uint32_t cmd = c.u32be();
    uint32_t error_code = c.u32be();
    ByteSpan data = c.rest();

    if (cmd == 0x02) {  // Frame Send -- unwrap into the shared FINS-frame parser
        return decode_inner_with_session_state(data, ctx, /*require_recognized=*/false);
    }

    FinsFrame frame;
    frame.is_tcp_envelope_only = true;
    frame.tcp_command = cmd;
    frame.tcp_command_name = tcp_command_name(cmd);
    frame.tcp_error_code = error_code;
    frame.tcp_error_code_name = tcp_error_code_name(error_code);
    frame.command_name = frame.tcp_command_name;

    std::ostringstream summary;
    try {
        Cursor dc(data);
        if (cmd == 0x00) {
            frame.has_handshake_client_node = true;
            frame.handshake_client_node = dc.u32be();
            summary << "Node Address Data Send (client->server): requested client node "
                    << frame.handshake_client_node;
        } else if (cmd == 0x01) {
            frame.has_handshake_client_node = true;
            frame.handshake_client_node = dc.u32be();
            frame.has_handshake_server_node = true;
            frame.handshake_server_node = dc.u32be();
            summary << "Node Address Data Send (server->client): client node "
                    << frame.handshake_client_node << ", server node " << frame.handshake_server_node;
        } else if (cmd == 0x03) {
            summary << "Frame Send Error Notification: " << frame.tcp_error_code_name;
        } else if (cmd == 0x06) {
            summary << "Connection Confirmation";
        } else {
            summary << frame.tcp_command_name << " (" << data.size() << " byte(s) of data, not "
                    << "decoded further)";
        }
    } catch (const ParseError&) {
        summary.str("");
        summary << frame.tcp_command_name << " (payload shorter than expected)";
    }
    if (frame.tcp_error_code != 0) {
        summary << " [error: " << frame.tcp_error_code_name << "]";
    }
    frame.summary = summary.str();
    return ProtocolResult::make<FinsFrame>("fins", std::move(frame));
}

std::optional<ProtocolResult> FinsUdpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_inner_with_session_state(payload, ctx, /*require_recognized=*/true);
}

const ProtocolDecoder& fins_tcp_decoder() {
    static const FinsTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& fins_udp_decoder() {
    static const FinsUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
