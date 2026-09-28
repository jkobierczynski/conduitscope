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

// Read/Write/Other classification for docs/design/policy-engine-zoning.md's Phase 4 (operation-
// level read/write direction): backs modbus_read_function_names()/modbus_write_function_names(),
// which Policy::parse_policy_text expands a conduit's 'functions: [read]'/'[write]' group keyword
// into (see policy.cpp). Other means "genuinely not a clean read or write, or no data-plane effect
// at all" -- deliberately left out of BOTH groups so a functions:-restricted conduit never silently
// permits or forbids it via the keyword shortcut; it can still be permitted by naming it literally.
// Diagnostics (0x08) mixes read-only sub-functions (Return Query Data, read counters) with ones
// that change device state (Restart Communications Option, Clear Counters, Force Listen Only Mode)
// -- this decoder doesn't distinguish sub-functions (see this file's header comment), so the
// function as a whole can't be honestly called either. Read/Write Multiple Registers (0x17) is
// Other for the same reason at the message level: it reads one register range and writes a
// SEPARATE one in the same request, so "this flow only reads" or "this flow only writes" is neither
// true nor false for it. Mask Write Register (0x16) stays Write despite its own read-modify-write
// implementation: unlike 0x17, the read and write halves target the exact same register, so the
// net, policy-relevant effect is a single write.
enum class ModbusFunctionAccess { Read, Write, Other };

struct ModbusFunctionEntry {
    uint8_t code;
    const char* name;
    ModbusFunctionAccess access;
};

constexpr ModbusFunctionEntry kModbusFunctions[] = {
    {FC_READ_COILS, "Read Coils", ModbusFunctionAccess::Read},
    {FC_READ_DISCRETE_INPUTS, "Read Discrete Inputs", ModbusFunctionAccess::Read},
    {FC_READ_HOLDING_REGISTERS, "Read Holding Registers", ModbusFunctionAccess::Read},
    {FC_READ_INPUT_REGISTERS, "Read Input Registers", ModbusFunctionAccess::Read},
    {FC_WRITE_SINGLE_COIL, "Write Single Coil", ModbusFunctionAccess::Write},
    {FC_WRITE_SINGLE_REGISTER, "Write Single Register", ModbusFunctionAccess::Write},
    {FC_READ_EXCEPTION_STATUS, "Read Exception Status", ModbusFunctionAccess::Read},
    {FC_DIAGNOSTICS, "Diagnostics", ModbusFunctionAccess::Other},
    {FC_WRITE_MULTIPLE_COILS, "Write Multiple Coils", ModbusFunctionAccess::Write},
    {FC_WRITE_MULTIPLE_REGISTERS, "Write Multiple Registers", ModbusFunctionAccess::Write},
    {FC_REPORT_SERVER_ID, "Report Server ID", ModbusFunctionAccess::Read},
    {FC_MASK_WRITE_REGISTER, "Mask Write Register", ModbusFunctionAccess::Write},
    {FC_READ_WRITE_MULTIPLE_REGISTERS, "Read/Write Multiple Registers", ModbusFunctionAccess::Other},
    {FC_READ_FIFO_QUEUE, "Read FIFO Queue", ModbusFunctionAccess::Read},
    {FC_ENCAPSULATED_INTERFACE_TRANSPORT, "Encapsulated Interface Transport", ModbusFunctionAccess::Read},
};

const ModbusFunctionEntry* find_modbus_function(uint8_t fc) {
    for (const auto& entry : kModbusFunctions) {
        if (entry.code == fc) return &entry;
    }
    return nullptr;
}

std::string function_name(uint8_t fc) {
    if (const auto* entry = find_modbus_function(fc)) return entry->name;
    // UMAS (see umas.hpp) isn't a kModbusFunctions entry -- it's a distinct vendor-proprietary
    // protocol layered on this one function code, decoded into its own ModbusFrame::umas sub-
    // frame below, not folded into this table's own name style. Named here too (not just at the
    // switch case that populates frame.umas) so an exception response citing this function code
    // (frame.is_exception, above the switch) also reads as "UMAS" rather than "Unknown (0x5A)".
    if (fc == UMAS_MODBUS_FUNCTION_CODE) return "UMAS";
    std::ostringstream out;
    out << "Unknown (0x" << std::hex << static_cast<unsigned>(fc) << ")";
    return out.str();
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
        // Baseline-engine prerequisite (see ModbusFrame::is_request's own comment, modbus.hpp):
        // the same address/quantity just rendered into `summary` above, also exposed as their own
        // structured fields.
        frame.is_request = true;
        frame.start_address = address;
        frame.quantity = quantity;
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
        // A read response carries no address at all on the wire (just a length-prefixed data
        // blob) -- is_request stays false, start_address/quantity stay unset (see
        // ModbusFrame::is_request's own comment, modbus.hpp).
        frame.is_request = false;
        return;
    }
    frame.summary = "unrecognized payload shape for " + frame.function_name;
    frame.notes.push_back("expected either a 4-byte request or a byte-count-prefixed response; "
                           "showing raw PDU bytes instead: " + to_hex(data));
}

// Deliberately does NOT populate frame.is_request/start_address/quantity: request and response
// share the identical 4-byte wire shape (see the summary text below), so unlike
// decode_read_family/decode_write_multiple above, there is no shape-based signal here to decide
// which side this frame is -- see ModbusFrame::is_request's own comment (modbus.hpp) for the full
// reasoning and why this is a deliberate scope boundary, not an oversight.
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
        // A write-multiple response ECHOES address+quantity back on the wire (real Modbus wire
        // behavior -- see ModbusFrame::is_request's own comment, modbus.hpp) -- populated here even
        // though is_request stays false, so a caller that only wants confirmed values (rather than
        // extracting a baseline operation, which deliberately reads only is_request==true frames)
        // still has them.
        frame.is_request = false;
        frame.start_address = address;
        frame.quantity = quantity;
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
        frame.is_request = true;
        frame.start_address = address;
        frame.quantity = quantity;
        return;
    }
    frame.summary = "unrecognized payload shape for " + frame.function_name;
    frame.notes.push_back("showing raw PDU bytes instead: " + to_hex(data));
}

// Named subset of Diagnostics (function code 0x08) sub-functions -- the five this project's own
// real modbus_test_data_part1.pcap capture exercises (Force Listen Only Mode/Restart Communications
// Option/Clear Counters and Diagnostic Registers -- verified directly against that capture's raw
// bytes -- plus Return Query Data/Return Diagnostic Register, the two most commonly seen in other
// public Modbus captures/documentation). Every other sub-function code still gets read (see
// decode_diagnostics below) but falls back to "Unknown (0xNNNN)", the same style as this file's own
// function_name's fallback for an unrecognized top-level function code.
std::string diagnostics_sub_function_name(uint16_t sub_function) {
    switch (sub_function) {
        case 0x0000: return "Return Query Data";
        case 0x0001: return "Restart Communications Option";
        case 0x0002: return "Return Diagnostic Register";
        case 0x0004: return "Force Listen Only Mode";
        case 0x000A: return "Clear Counters and Diagnostic Registers";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << sub_function << ")";
            return out.str();
        }
    }
}

// Diagnostics (0x08) PDU shape is sub-function-code(2) + data(usually 2 bytes, echoed unchanged
// between request and response for every sub-function this decoder names) -- request and response
// are therefore indistinguishable from payload shape alone, the same situation decode_write_single
// above documents for Write Single Coil/Register; see ModbusFrame::diagnostics_sub_function's own
// comment (modbus.hpp) for why this is a deliberate scope boundary, not an oversight.
void decode_diagnostics(ModbusFrame& frame, ByteSpan data) {
    if (data.size() < 2) {
        frame.summary = "malformed " + frame.function_name + " (missing 2-byte sub-function code)";
        if (!data.empty()) frame.notes.push_back("raw PDU data: " + to_hex(data));
        return;
    }
    Cursor c(data);
    uint16_t sub_function = c.u16be();
    frame.diagnostics_sub_function = sub_function;
    std::ostringstream out;
    // Deliberately does NOT repeat the literal word "Diagnostics" here -- output.cpp's own report
    // writers already render "<function_name>: <summary>" (see e.g. Read Holding Registers' own
    // "request: read ..." summary, decode_read_family above), so a summary starting with the
    // function's own name a second time would print doubled ("Diagnostics: Diagnostics: ...").
    out << diagnostics_sub_function_name(sub_function);
    ByteSpan rest = c.rest();
    if (!rest.empty()) out << " (data: " << to_hex(rest) << ")";
    frame.summary = out.str();
    frame.notes.push_back("request and response share this exact shape per spec (sub-function code "
                           "plus echoed data) -- this decoder does not attempt to distinguish them here, "
                           "same scope boundary as Write Single Coil/Register above");
}

// The two MEI (Modbus Encapsulation Interface) types the Modbus Application Protocol spec currently
// assigns -- see ModbusFrame::mei_type's own comment (modbus.hpp) for the scope boundary (function-
// code/MEI-type-level naming only, no further decode of the Read Device Identification object list).
std::string mei_type_name(uint8_t mei) {
    switch (mei) {
        case 0x0D: return "CANopen General Reference";
        case 0x0E: return "Read Device Identification";
        default: {
            std::ostringstream out;
            out << "Unknown MEI Type (0x" << std::hex << static_cast<unsigned>(mei) << ")";
            return out.str();
        }
    }
}

void decode_encapsulated_interface_transport(ModbusFrame& frame, ByteSpan data) {
    if (data.empty()) {
        frame.summary = "malformed " + frame.function_name + " (missing MEI type byte)";
        return;
    }
    Cursor c(data);
    uint8_t mei = c.u8();
    frame.mei_type = mei;
    std::ostringstream out;
    // Same "don't repeat function_name inside summary" reasoning as decode_diagnostics above.
    out << mei_type_name(mei);
    ByteSpan rest = c.rest();
    if (!rest.empty()) out << " (data: " << to_hex(rest) << ")";
    frame.summary = out.str();
}

}  // namespace

std::vector<std::string> modbus_known_function_names() {
    // Reads straight from kModbusFunctions now (see this file's own header comment on that table) --
    // previously iterated function_name(fc) over every possible byte value and kept the non-
    // "Unknown (0x.." results, which worked but meant "every known code" was only implicit in what
    // the switch happened to handle. The table makes it explicit, and is also what backs
    // modbus_read_function_names()/modbus_write_function_names() below (Phase 4).
    std::vector<std::string> out;
    out.reserve(sizeof(kModbusFunctions) / sizeof(kModbusFunctions[0]));
    for (const auto& entry : kModbusFunctions) out.push_back(entry.name);
    return out;
}

// docs/design/policy-engine-zoning.md's Phase 4: the subset of modbus_known_function_names() this
// decoder classifies as Read (or Write) -- see kModbusFunctions' own access field and this file's
// header comment on ModbusFunctionAccess for exactly which functions land in neither group and why.
// Used by policy.cpp to expand a modbus-restricted conduit's 'functions: [read]'/'[write]' group
// keyword; order matches kModbusFunctions' own declaration order.
std::vector<std::string> modbus_read_function_names() {
    std::vector<std::string> out;
    for (const auto& entry : kModbusFunctions) {
        if (entry.access == ModbusFunctionAccess::Read) out.push_back(entry.name);
    }
    return out;
}

std::vector<std::string> modbus_write_function_names() {
    std::vector<std::string> out;
    for (const auto& entry : kModbusFunctions) {
        if (entry.access == ModbusFunctionAccess::Write) out.push_back(entry.name);
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
    if (raw_fc == 0x00) {
        // Function code 0, NON-exception (the raw byte on the wire is exactly 0x00): reserved
        // and never assigned in the Modbus Application Protocol spec -- no real master or slave
        // ever sends this as an actual function code. Unlike DNP3 (0x05 0x64) or S7comm
        // (0x32/0x72), Modbus/TCP has no magic bytes of its own; protocol_id==0 is its only
        // wire-level tell, and that alone is weak enough that other protocols' bytes can land
        // on it by coincidence (seen in practice: DNP3 traffic on port 20000 misclassified as
        // Modbus this way). A payload that decodes to raw function-code byte 0x00 essentially
        // never is Modbus, so bail out here -- the same signal that would otherwise produce a
        // bogus "Unknown (0x0)" result -- and let the caller fall through to try DNP3/S7comm
        // detection instead.
        //
        // Deliberately NOT extended to raw_fc == 0x80 (base_fc == 0 with the exception bit set)
        // -- an automated tshark-vs-conduitscope comparison across this project's own real-
        // capture corpus (tools/compare_with_tshark.py) found a genuine real device sending
        // exactly that byte as an "Illegal Function" exception response (tests/real_captures/
        // modbus/modbus_test_data_part2.pcap, frames documented in real_modbus_illegal_function_
        // exception_for_function_zero_decoded below): a slave that received a request it
        // considered function code 0 and correctly replied with the standard exception
        // mechanism. tshark's own dissector decodes this the same way ("Unknown Function" /
        // "Illegal function"). Earlier versions of this gate rejected 0x80 the same as 0x00 (via
        // a base_fc==0 check that ignored the exception bit), which silently misclassified this
        // real traffic as HART-IP instead (a coincidental structural-gate collision -- see
        // hartip.hpp's own "Structural detection gate" section) -- a real conduitscope bug this
        // gate itself caused, distinct from and not evidence for the DNP3-port-20000 concern
        // above, which was never observed to produce raw_fc==0x80 specifically. 0x80 is a single
        // specific byte value, not the same broad "byte reads as 0" collision surface as 0x00.
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
        case FC_DIAGNOSTICS: decode_diagnostics(frame, data); break;
        case FC_ENCAPSULATED_INTERFACE_TRANSPORT: decode_encapsulated_interface_transport(frame, data); break;
        case UMAS_MODBUS_FUNCTION_CODE: {
            UmasFrame umas_frame;
            decode_umas(data, umas_frame);
            frame.summary = umas_frame.summary;
            frame.notes.insert(frame.notes.end(), umas_frame.notes.begin(), umas_frame.notes.end());
            frame.umas = std::move(umas_frame);
            break;
        }
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
        bool looks_like_response = mb.is_exception || mb.summary.rfind("response:", 0) == 0 ||
                                    (mb.umas && mb.umas->is_response);
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
