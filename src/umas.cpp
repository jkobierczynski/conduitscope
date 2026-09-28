// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/umas.hpp"

#include <sstream>

namespace conduitscope {

namespace {

struct UmasFunctionEntry {
    uint8_t code;
    const char* name;
};

// See umas.hpp's own header comment for sourcing (yanissec/umas-wireshark-dissector, cross-
// checked against Kaspersky ICS-CERT/Securelist's own account of the function codes it discusses
// directly). Names are the dissector's own constant names, kept upper-snake-case rather than
// title-cased like most of this codebase's other function-name tables, since Schneider's own
// UMAS-derived tooling (and every secondary source describing this protocol) consistently refers
// to them this way -- there is no official spec to prefer a "nicer" rendering from.
constexpr UmasFunctionEntry kUmasFunctions[] = {
    {UMAS_INIT_COMM, "INIT_COMM"},
    {UMAS_READ_ID, "READ_ID"},
    {UMAS_READ_PROJECT_INFO, "READ_PROJECT_INFO"},
    {UMAS_READ_PLC_INFO, "READ_PLC_INFO"},
    {UMAS_READ_CARD_INFO, "READ_CARD_INFO"},
    {UMAS_REPEAT, "REPEAT"},
    {UMAS_TAKE_PLC_RESERVATION, "TAKE_PLC_RESERVATION"},
    {UMAS_RELEASE_PLC_RESERVATION, "RELEASE_PLC_RESERVATION"},
    {UMAS_KEEP_ALIVE, "KEEP_ALIVE"},
    {UMAS_READ_MEMORY_BLOCK, "READ_MEMORY_BLOCK"},
    {UMAS_READ_VARIABLES, "READ_VARIABLES"},
    {UMAS_WRITE_VARIABLES, "WRITE_VARIABLES"},
    {UMAS_READ_COILS_REGISTERS, "READ_COILS_REGISTERS"},
    {UMAS_WRITE_COILS_REGISTERS, "WRITE_COILS_REGISTERS"},
    {UMAS_INITIALIZE_UPLOAD, "INITIALIZE_UPLOAD"},
    {UMAS_UPLOAD_BLOCK, "UPLOAD_BLOCK"},
    {UMAS_END_STRATEGY_UPLOAD, "END_STRATEGY_UPLOAD"},
    {UMAS_INITIALIZE_DOWNLOAD, "INITIALIZE_DOWNLOAD"},
    {UMAS_DOWNLOAD_BLOCK, "DOWNLOAD_BLOCK"},
    {UMAS_END_STRATEGY_DOWNLOAD, "END_STRATEGY_DOWNLOAD"},
    {UMAS_READ_ETH_MASTER_DATA, "READ_ETH_MASTER_DATA"},
    {UMAS_START_PLC, "START_PLC"},
    {UMAS_STOP_PLC, "STOP_PLC"},
    {UMAS_MONITOR_PLC, "MONITOR_PLC"},
    {UMAS_CHECK_PLC, "CHECK_PLC"},
    {UMAS_READ_IO_OBJECT, "READ_IO_OBJECT"},
    {UMAS_WRITE_IO_OBJECT, "WRITE_IO_OBJECT"},
    {UMAS_GET_STATUS_MODULE, "GET_STATUS_MODULE"},
};

const UmasFunctionEntry* find_umas_function(uint8_t code) {
    for (const auto& entry : kUmasFunctions) {
        if (entry.code == code) return &entry;
    }
    return nullptr;
}

}  // namespace

std::string umas_function_name(uint8_t function_code) {
    if (const auto* entry = find_umas_function(function_code)) return entry->name;
    std::ostringstream out;
    out << "Unknown (0x" << std::hex << static_cast<unsigned>(function_code) << ")";
    return out.str();
}

void decode_umas(ByteSpan pdu_data, UmasFrame& frame) {
    // decoder.cpp's own Decoder::decode prepends "UMAS: " (ModbusFrame::function_name) to
    // whatever `frame.summary` reads below -- see the request/response branches' own comment for
    // why these strings never repeat "UMAS" themselves.
    if (pdu_data.empty()) {
        frame.summary = "empty PDU (missing session key)";
        frame.notes.push_back("PDU has zero bytes after the 0x5A function code -- nothing to decode");
        return;
    }
    frame.session_key = pdu_data.at(0);

    if (pdu_data.size() < 2) {
        std::ostringstream out;
        out << "truncated PDU (session key 0x" << std::hex << static_cast<unsigned>(frame.session_key)
            << ", missing function/status byte)";
        frame.summary = out.str();
        frame.notes.push_back("PDU has only 1 byte after the 0x5A function code -- a session key with "
                               "no function/status byte to classify request vs. response from");
        return;
    }

    uint8_t second_byte = pdu_data.at(1);
    frame.data = pdu_data.from(2);

    // Request-vs-response heuristic: a response's second byte is always 0xFE/0xFD (Kaspersky's
    // own account, confirmed by the yanissec dissector); no function code in kUmasFunctions comes
    // anywhere close to that range (0x73 is the highest), so this collides with a real function
    // code only if some undocumented one happens to also be 0xFE/0xFD -- undocumented, since
    // neither of this decoder's two sources lists a function code there. Same "shape tells you
    // which side of the exchange this is" reasoning modbus.cpp's own decode_read_family uses for
    // the read family, called out as a heuristic there too.
    if (second_byte == UMAS_RESPONSE_STATUS_SUCCESS || second_byte == UMAS_RESPONSE_STATUS_FAILURE) {
        frame.is_response = true;
        frame.response_success = (second_byte == UMAS_RESPONSE_STATUS_SUCCESS);
        // decoder.cpp's own Decoder::decode already prepends "UMAS: " (ModbusFrame::function_name,
        // set to "UMAS" for this function code -- see modbus.cpp's own function_name() helper) to
        // whatever this summary reads, mirroring every other Modbus function's "<name>: <summary>"
        // convention -- so this string deliberately doesn't repeat "UMAS" itself.
        std::ostringstream out;
        out << "response (session key 0x" << std::hex << static_cast<unsigned>(frame.session_key)
            << std::dec << "): " << (frame.response_success ? "success" : "failure") << ", "
            << frame.data.size() << " data byte(s)";
        frame.summary = out.str();
        frame.notes.push_back("classified as a response because the byte after the session key is "
                               "0xFE/0xFD; this is a heuristic (see umas.hpp's own header comment), "
                               "not session-key/sequence-number pairing");
        return;
    }

    frame.function_code = second_byte;
    frame.function_name = umas_function_name(second_byte);
    std::ostringstream out;
    out << "request (session key 0x" << std::hex << static_cast<unsigned>(frame.session_key)
        << std::dec << "): " << frame.function_name << ", " << frame.data.size() << " data byte(s)";
    frame.summary = out.str();
    frame.notes.push_back("classified as a request because the byte after the session key is not "
                           "0xFE/0xFD; this is a heuristic, not session-key/sequence-number pairing -- "
                           "data field left undecoded, see umas.hpp's own header comment for why");
}

}  // namespace conduitscope
