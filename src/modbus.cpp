// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/modbus.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// The Modbus Application Protocol spec caps a PDU at 253 bytes, so mbap_length (unit_id + PDU)
// can never legitimately exceed 254 -- found via a real capture: non-Modbus traffic on port 502
// (digitalbond's MODBUS-TestDataPart1, deliberately exercising traffic outside this decoder's
// scope) had two bytes that coincidentally read as protocol_id==0, with a "length" field of
// several thousand. Without this cap, that flow would be mistaken for a genuine Modbus PDU split
// across TCP segments and buffered indefinitely waiting for bytes that would never complete it as
// Modbus -- or, for a payload that already arrived complete in one segment, decoded outright as a
// bogus Modbus frame with a "length mismatch" note instead of being rejected so another protocol's
// decoder gets a turn (seen with a synthetic MQTT CONNACK whose body happened to read as
// protocol_id==0 with a huge bogus mbap_length). A little slack above the strict 254 theoretical
// max is kept in case of a nonstandard/extended real device; 300 is still two orders of magnitude
// below the false positive this guards against. Shared by both modbus_tcp_declared_length (the
// reassembly-side check) and try_parse_modbus_tcp (the final decode gate) so the two stay
// consistent.
constexpr uint16_t kMaxPlausibleMbapLength = 300;

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

std::vector<std::string> modbus_known_function_names() {
    // Calls the same function_name(fc) switch above for every possible byte value and keeps only
    // the ones that resolved to a real name rather than the dynamic "Unknown (0x.." fallback --
    // see modbus.hpp's own comment on this function for why this reuses function_name() instead of
    // a second, separately-maintained list of names.
    std::vector<std::string> out;
    for (int fc = 0; fc <= 0xFF; ++fc) {
        std::string name = function_name(static_cast<uint8_t>(fc));
        if (name.rfind("Unknown (0x", 0) != 0) out.push_back(std::move(name));
    }
    return out;
}

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

std::optional<size_t> modbus_tcp_declared_length(ByteSpan payload) {
    if (payload.size() < 6) {
        return std::nullopt;
    }
    Cursor c(payload);
    c.u16be();  // transaction_id
    uint16_t protocol_id = c.u16be();
    if (protocol_id != 0) {
        return std::nullopt;
    }
    uint16_t mbap_length = c.u16be();
    if (payload.size() >= 8 && payload.at(7) == 0) {
        // Function code 0 is reserved/never assigned -- protocol_id==0 with function_code==0 is
        // almost certainly the same coincidence try_parse_modbus_tcp already guards against, not
        // real Modbus/TCP. Better to say "not recognized" here than to buffer forever waiting for
        // bytes that a non-Modbus flow will never deliver in the shape we'd expect.
        return std::nullopt;
    }
    if (mbap_length > kMaxPlausibleMbapLength) {
        return std::nullopt;
    }
    return 6 + static_cast<size_t>(mbap_length);
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
    if (mbap_length > kMaxPlausibleMbapLength) {
        // Same guard as modbus_tcp_declared_length, applied here too: a payload that already
        // arrived complete in one TCP segment still deserves this check, not just the
        // reassembly-buffering path -- see kMaxPlausibleMbapLength's comment for why.
        return std::nullopt;
    }
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
    uint8_t base_fc = raw_fc & 0x7F;
    if (base_fc == 0) {
        // Function code 0 is reserved and never assigned in the Modbus Application Protocol
        // spec -- no real master or slave ever sends it. Unlike DNP3 (0x05 0x64) or S7comm
        // (0x32/0x72), Modbus/TCP has no magic bytes of its own; protocol_id==0 is its only
        // wire-level tell, and that alone is weak enough that other protocols' bytes can land
        // on it by coincidence (seen in practice: DNP3 traffic on port 20000 misclassified as
        // Modbus this way). A payload that decodes to function code 0 essentially never is
        // Modbus, so bail out here -- the same signal that would otherwise produce a bogus
        // "Unknown (0x0)" result -- and let the caller fall through to try DNP3/S7comm
        // detection instead.
        return std::nullopt;
    }
    frame.is_exception = (raw_fc & 0x80) != 0;
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

std::optional<ProtocolResult> ModbusDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto parsed = try_parse_modbus_tcp(payload);
    if (!parsed) return std::nullopt;
    ModbusFrame mb = std::move(*parsed);

    // Same algorithm as decoder.cpp's old (now removed) Decoder::pair_modbus_transaction, moved
    // here verbatim and adapted to read/write ModbusFlowState via ctx instead of a Decoder member
    // -- see modbus.hpp's own comments on ModbusPendingRequest/ModbusFlowState for why.
    ModbusFlowState& state = ctx.flow_state<ModbusFlowState>();
    auto it = state.pending.find(mb.transaction_id);
    if (it != state.pending.end()) {
        ModbusPendingRequest& pending = it->second;
        if (pending.flow_key != ctx.flow_key) {
            // Opposite direction: authoritatively the response to that specific request.
            mb.paired_response = true;
            mb.paired_request_index = pending.packet_index;
            std::ostringstream s;
            s << "authoritative pairing: response to transaction id " << mb.transaction_id << " (unit "
              << static_cast<unsigned>(mb.unit_id) << ") -- matches the request seen in packet #"
              << pending.packet_index << " (" << pending.function_name << ": " << pending.request_summary
              << "), paired by TCP session + transaction ID, not the payload-shape heuristic above";
            if (pending.unit_id != mb.unit_id) {
                s << " [unit id mismatch: request was unit " << static_cast<unsigned>(pending.unit_id) << "]";
            }
            mb.notes.push_back(s.str());
            state.pending.erase(it);
        } else {
            // Same direction: transaction ID reused before its previous request was ever paired.
            mb.notes.push_back(
                "transaction id " + std::to_string(mb.transaction_id) +
                " reused on this TCP flow before its previous outstanding request (packet #" +
                std::to_string(pending.packet_index) +
                ") was matched with a response -- possibly a retry, an orphaned request, or "
                "out-of-order capture; treating this as a new outstanding request");
            pending = ModbusPendingRequest{ctx.packet_index, ctx.flow_key, mb.function_name, mb.summary,
                                            mb.unit_id};
        }
    } else {
        bool looks_like_response = mb.is_exception || mb.summary.rfind("response:", 0) == 0;
        if (looks_like_response) {
            mb.notes.push_back(
                "no outstanding request found on this TCP session for transaction id " +
                std::to_string(mb.transaction_id) +
                " -- the payload-shape heuristic above classified this packet as a response, "
                "but its request was never seen on this session (capture may have started "
                "after it was sent, or it used a different transaction ID/session)");
        } else {
            // Capacity guard against a pathological/malformed capture leaking memory -- same
            // kMaxTrackedTransactionsPerSession=2000 cap decoder.cpp's own removed
            // pair_modbus_transaction always applied.
            // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp (folded in
            // as the closest fit among the five categories for a per-session state-map cap;
            // see docs/DEVELOPMENT.md's item 7 "Update: implemented" entry). 0/unset keeps the
            // literal 2000 default.
            const size_t kMaxTrackedTransactionsPerSession = resource_limits().max_decoded_objects.value_or(2000);
            if (state.pending.size() < kMaxTrackedTransactionsPerSession) {
                state.pending[mb.transaction_id] =
                    ModbusPendingRequest{ctx.packet_index, ctx.flow_key, mb.function_name, mb.summary,
                                          mb.unit_id};
            }
        }
    }

    return ProtocolResult::make<ModbusFrame>("modbus", std::move(mb));
}

const ProtocolDecoder& modbus_decoder() {
    static const ModbusDecoder instance;
    return instance;
}

}  // namespace conduitscope
