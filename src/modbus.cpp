// SPDX-License-Identifier: MIT
#include "conduitscope/modbus.hpp"

#include <sstream>

namespace conduitscope {

namespace {

enum FunctionCode : uint8_t {
    FC_READ_COILS = 0x01,
    FC_READ_DISCRETE_INPUTS = 0x02,
    FC_READ_HOLDING_REGISTERS = 0x03,
    FC_READ_INPUT_REGISTERS = 0x04,
    FC_WRITE_SINGLE_COIL = 0x05,
    FC_WRITE_SINGLE_REGISTER = 0x06,
    FC_READ_EXCEPTION_STATUS = 0x07,
    FC_DIAGNOSTICS = 0x08,
    FC_WRITE_MULTIPLE_COILS = 0x0F,
    FC_WRITE_MULTIPLE_REGISTERS = 0x10,
    FC_REPORT_SERVER_ID = 0x11,
    FC_MASK_WRITE_REGISTER = 0x16,
    FC_READ_WRITE_MULTIPLE_REGISTERS = 0x17,
    FC_READ_FIFO_QUEUE = 0x18,
    FC_ENCAPSULATED_INTERFACE_TRANSPORT = 0x2B,
};

std::string function_name(uint8_t fc) {
    switch (fc) {
        case FC_READ_COILS: return "Read Coils";
        case FC_READ_DISCRETE_INPUTS: return "Read Discrete Inputs";
        case FC_READ_HOLDING_REGISTERS: return "Read Holding Registers";
        case FC_READ_INPUT_REGISTERS: return "Read Input Registers";
        case FC_WRITE_SINGLE_COIL: return "Write Single Coil";
        case FC_WRITE_SINGLE_REGISTER: return "Write Single Register";
        case FC_READ_EXCEPTION_STATUS: return "Read Exception Status";
        case FC_DIAGNOSTICS: return "Diagnostics";
        case FC_WRITE_MULTIPLE_COILS: return "Write Multiple Coils";
        case FC_WRITE_MULTIPLE_REGISTERS: return "Write Multiple Registers";
        case FC_REPORT_SERVER_ID: return "Report Server ID";
        case FC_MASK_WRITE_REGISTER: return "Mask Write Register";
        case FC_READ_WRITE_MULTIPLE_REGISTERS: return "Read/Write Multiple Registers";
        case FC_READ_FIFO_QUEUE: return "Read FIFO Queue";
        case FC_ENCAPSULATED_INTERFACE_TRANSPORT: return "Encapsulated Interface Transport";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(fc) << ")";
            return out.str();
        }
    }
}

// Decodes the two-register-field "read" family (coils/discrete inputs/holding/input
// registers), whose request shape is always address(2)+quantity(2) = 4 bytes, and
// whose response shape is always byte_count(1)+byte_count bytes of data. These two
// shapes essentially never collide, which is what makes the length-based heuristic
// reliable in practice.
void decode_read_family(ModbusFrame& frame, ByteSpan data, const char* unit_noun) {
    if (data.size() == 4) {
        Cursor c(data);
        uint16_t address = c.u16be();
        uint16_t quantity = c.u16be();
        std::ostringstream out;
        out << "request: read " << quantity << " " << unit_noun << " starting at address " << address;
        frame.summary = out.str();
        frame.notes.push_back("classified as a request because the PDU is exactly 4 bytes "
                               "(address+quantity); this is a heuristic, not stream tracking");
        return;
    }
    if (!data.empty() && static_cast<size_t>(data.at(0)) + 1 == data.size()) {
        uint8_t byte_count = data.at(0);
        std::ostringstream out;
        out << "response: " << static_cast<unsigned>(byte_count) << " data byte(s) = "
            << to_hex(data.from(1));
        frame.summary = out.str();
        frame.notes.push_back("classified as a response because the PDU starts with a byte-count "
                               "that matches its remaining length; this is a heuristic, not stream tracking");
        return;
    }
    frame.summary = "unrecognized payload shape for " + frame.function_name;
    frame.notes.push_back("expected either a 4-byte request or a byte-count-prefixed response; "
                           "showing raw PDU bytes instead: " + to_hex(data));
}

void decode_write_single(ModbusFrame& frame, ByteSpan data) {
    if (data.size() != 4) {
        frame.summary = "malformed " + frame.function_name + " (expected 4 bytes, got " +
                         std::to_string(data.size()) + ")";
        return;
    }
    Cursor c(data);
    uint16_t address = c.u16be();
    uint16_t value = c.u16be();
    std::ostringstream out;
    out << "address=" << address << " value=0x" << std::hex << value
        << " (request and response share this exact shape per spec)";
    frame.summary = out.str();
}

void decode_write_multiple(ModbusFrame& frame, ByteSpan data, const char* unit_noun) {
    if (data.size() == 4) {
        Cursor c(data);
        uint16_t address = c.u16be();
        uint16_t quantity = c.u16be();
        std::ostringstream out;
        out << "response: wrote " << quantity << " " << unit_noun << " starting at address " << address;
        frame.summary = out.str();
        return;
    }
    if (data.size() >= 5) {
        Cursor c(data);
        uint16_t address = c.u16be();
        uint16_t quantity = c.u16be();
        uint8_t byte_count = c.u8();
        std::ostringstream out;
        out << "request: write " << quantity << " " << unit_noun << " starting at address " << address
            << " (" << static_cast<unsigned>(byte_count) << " data bytes)";
        frame.summary = out.str();
        if (c.remaining() != byte_count) {
            frame.notes.push_back("byte-count field (" + std::to_string(byte_count) +
                                   ") does not match remaining PDU bytes (" +
                                   std::to_string(c.remaining()) + ")");
        } else {
            frame.notes.push_back("values = " + to_hex(c.rest()));
        }
        return;
    }
    frame.summary = "unrecognized payload shape for " + frame.function_name;
    frame.notes.push_back("showing raw PDU bytes instead: " + to_hex(data));
}

}  // namespace

std::string modbus_exception_name(uint8_t code) {
    switch (code) {
        case 0x01: return "Illegal Function";
        case 0x02: return "Illegal Data Address";
        case 0x03: return "Illegal Data Value";
        case 0x04: return "Server Device Failure";
        case 0x05: return "Acknowledge";
        case 0x06: return "Server Device Busy";
        case 0x08: return "Memory Parity Error";
        case 0x0A: return "Gateway Path Unavailable";
        case 0x0B: return "Gateway Target Device Failed to Respond";
        default: {
            std::ostringstream out;
            out << "Unknown Exception (0x" << std::hex << static_cast<unsigned>(code) << ")";
            return out.str();
        }
    }
}

std::optional<ModbusFrame> try_parse_modbus_tcp(ByteSpan tcp_payload) {
    // MBAP header is 7 bytes; a Modbus/TCP frame needs at least that plus one
    // function-code byte to be worth looking at.
    if (tcp_payload.size() < 8) {
        return std::nullopt;
    }

    Cursor c(tcp_payload);
    uint16_t transaction_id = c.u16be();
    uint16_t protocol_id = c.u16be();
    if (protocol_id != 0) {
        // This is the standard tell that a payload is not Modbus/TCP: real Modbus
        // always sets this field to 0. Non-zero here almost certainly means we're
        // looking at some other protocol that happens to share a port.
        return std::nullopt;
    }
    uint16_t mbap_length = c.u16be();
    uint8_t unit_id = c.u8();

    ModbusFrame frame;
    frame.transaction_id = transaction_id;
    frame.protocol_id = protocol_id;
    frame.mbap_length = mbap_length;
    frame.unit_id = unit_id;

    size_t expected_remaining = (mbap_length >= 1) ? (mbap_length - 1) : 0;
    if (expected_remaining != c.remaining()) {
        frame.notes.push_back("MBAP length field implies " + std::to_string(expected_remaining) +
                               " byte(s) after the unit ID, but this packet has " +
                               std::to_string(c.remaining()) +
                               " -- possible truncation, pipelined PDUs, or a non-Modbus payload");
    }

    frame.function_code = c.u8();
    uint8_t raw_fc = frame.function_code;
    frame.is_exception = (raw_fc & 0x80) != 0;
    uint8_t base_fc = raw_fc & 0x7F;
    frame.function_name = function_name(base_fc);
    frame.raw_pdu_data = c.rest();

    if (frame.is_exception) {
        ByteSpan data = c.rest();
        if (!data.empty()) {
            frame.exception_code = data.at(0);
            std::ostringstream out;
            out << "exception response to " << frame.function_name << ": "
                << modbus_exception_name(frame.exception_code);
            frame.summary = out.str();
        } else {
            frame.summary = "malformed exception frame (missing exception code byte)";
        }
        return frame;
    }

    ByteSpan data = c.rest();
    switch (base_fc) {
        case FC_READ_COILS: decode_read_family(frame, data, "coil(s)"); break;
        case FC_READ_DISCRETE_INPUTS: decode_read_family(frame, data, "discrete input(s)"); break;
        case FC_READ_HOLDING_REGISTERS: decode_read_family(frame, data, "holding register(s)"); break;
        case FC_READ_INPUT_REGISTERS: decode_read_family(frame, data, "input register(s)"); break;
        case FC_WRITE_SINGLE_COIL: decode_write_single(frame, data); break;
        case FC_WRITE_SINGLE_REGISTER: decode_write_single(frame, data); break;
        case FC_WRITE_MULTIPLE_COILS: decode_write_multiple(frame, data, "coil(s)"); break;
        case FC_WRITE_MULTIPLE_REGISTERS: decode_write_multiple(frame, data, "register(s)"); break;
        default:
            frame.summary = frame.function_name + " (not decoded in this groundwork release)";
            frame.notes.push_back("raw PDU data: " + to_hex(data));
            break;
    }

    return frame;
}

}  // namespace conduitscope
