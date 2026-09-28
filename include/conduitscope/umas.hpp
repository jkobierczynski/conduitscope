// SPDX-License-Identifier: Apache-2.0
// umas.hpp - UMAS (Unity/M340 Application Services), Schneider Electric's proprietary
// engineering-station protocol for Unity Pro/Control Expert, carried inside Modbus/TCP as
// function code 0x5A (90). Dispatched from modbus.cpp's own function-code switch (try_parse_
// modbus_tcp), the same place every other Modbus function code is recognized -- see this file's
// own header comment on why UMAS rides inside ModbusFrame rather than getting its own top-level
// ProtocolResult variant.
//
// UMAS has NO official public specification -- Schneider has never published one. Every field
// this decoder knows about comes from convergent open-source reverse-engineering, cited by URL
// below; this is this codebase's first protocol decoded entirely from unofficial sources (every
// other decoder here either follows a published standard or a vendor's own public documentation).
// Two independent sources agree on the wire shape used here:
//
//   - Kaspersky ICS-CERT / Securelist, "The secrets of Schneider Electric's UMAS protocol"
//     (https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/,
//     mirrored at https://securelist.com/the-secrets-of-schneider-electrics-umas-protocol/107435/):
//     confirms the session-key byte, the function-code byte, and the 0xFE (success)/0xFD (failure)
//     response-status convention this decoder's request/response heuristic is built on. Also
//     documents the session-key weaknesses (CVE-2020-28212) and the Application Password nonce+
//     SHA-256 mechanism (CVE-2021-22779) -- pure security history, not re-implemented here; see
//     LIMITATIONS in docs/USER_GUIDE.md for why this decoder deliberately doesn't validate or
//     attempt to bypass either.
//   - yanissec/umas-wireshark-dissector (https://github.com/yanissec/umas-wireshark-dissector,
//     umas.lua), an open-source Wireshark dissector -- the source of the fuller function-code
//     table below, the same kind of primary source this project already cites for other
//     protocols' field tables (see e.g. bacnet.hpp's own citation of Wireshark's own dissector
//     tables).
//
// Scope is deliberately shallow: function-code-level naming, session-key extraction, and
// request-vs-response classification only -- the same depth bacnet.hpp's service-choice table
// had before RPM decode existed, or opcua.hpp's own "first pass" scope. The data field AFTER the
// session key + function/status byte is kept as opaque bytes -- this decoder does NOT attempt to
// decode memory addresses, project name strings, or reservation payload contents inside it.
// Without real Unity Pro capture samples to validate field offsets against, and given Kaspersky's
// own account of session-key/version drift across firmware releases, deeper decode here would be
// guesswork this project's own "cite a primary source, verify against real captured output"
// discipline can't support -- see docs/reviews/2026-09-grok-response.md's item 4 discussion and
// docs/design/detection-engine.md for the full scoping record.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// Modbus/TCP function code UMAS rides on -- checked in modbus.cpp's own try_parse_modbus_tcp
// switch, base_fc (exception bit already stripped) == UMAS_MODBUS_FUNCTION_CODE.
constexpr uint8_t UMAS_MODBUS_FUNCTION_CODE = 0x5A;  // 90 decimal

// A response frame's second byte (immediately after the session key) is one of these two status
// values -- Kaspersky's own account, confirmed by the yanissec dissector. Neither value collides
// with any function code in kUmasFunctions (umas.cpp) -- the highest known function code is 0x73
// -- which is what makes the request-vs-response heuristic below reliable in practice, the same
// "shape distinguishes request from response" reasoning modbus.cpp's own decode_read_family uses.
constexpr uint8_t UMAS_RESPONSE_STATUS_SUCCESS = 0xFE;
constexpr uint8_t UMAS_RESPONSE_STATUS_FAILURE = 0xFD;

struct UmasFrame {
    uint8_t session_key = 0;  // first byte of every UMAS PDU, request or response alike

    // Classified by the second byte's value (see UMAS_RESPONSE_STATUS_SUCCESS/FAILURE's own
    // comment above) -- a heuristic, like every other request/response classification in this
    // codebase that isn't backed by session-key/sequence-number pairing.
    bool is_response = false;

    // --- request side (is_response == false) ---------------------------------------------
    uint8_t function_code = 0;    // second byte -- meaningful only when is_response is false
    std::string function_name;    // e.g. "START_PLC" or "Unknown (0x2C)" -- see umas.cpp's table

    // --- response side (is_response == true) ----------------------------------------------
    bool response_success = false;  // true for 0xFE, false for 0xFD -- meaningful only when
                                     // is_response is true

    std::string summary;             // one-line human-readable summary
    std::vector<std::string> notes;  // extra detail lines (heuristics used, truncation, ...) --
                                       // same convention as ModbusFrame::notes
    ByteSpan data;                    // everything after session_key + function/status byte,
                                       // deliberately opaque -- see this file's header comment
};

// Decodes `pdu_data` (the Modbus PDU bytes after the 0x5A function-code byte) into `frame`.
// Always populates `frame` -- even a PDU too short to contain a session key and a function/
// status byte still produces a frame (session_key left at 0, a note explaining the truncation),
// matching this codebase's own "never silently drop a packet that already matched a structural
// gate" convention (see e.g. modbus.cpp's decode_read_family's own "unrecognized payload shape"
// fallback for the same posture on the outer Modbus decode).
void decode_umas(ByteSpan pdu_data, UmasFrame& frame);

// The function-code name table itself, exposed so a caller that only has a raw byte (rather than
// a decoded UmasFrame) can still render a name -- e.g. detect_engine.cpp comparing against a
// specific UmasFunctionCode constant.
std::string umas_function_name(uint8_t function_code);

// The function-code name table itself, exposed for detect_engine.cpp's own always-notable
// wiring (START_PLC/STOP_PLC -> T0858, INITIALIZE_DOWNLOAD/DOWNLOAD_BLOCK/END_STRATEGY_DOWNLOAD
// -> T0843, and so on) without needing its own copy of the raw hex values.
enum UmasFunctionCode : uint8_t {
    UMAS_INIT_COMM = 0x01,
    UMAS_READ_ID = 0x02,
    UMAS_READ_PROJECT_INFO = 0x03,
    UMAS_READ_PLC_INFO = 0x04,
    UMAS_READ_CARD_INFO = 0x06,
    UMAS_REPEAT = 0x0A,
    UMAS_TAKE_PLC_RESERVATION = 0x10,
    UMAS_RELEASE_PLC_RESERVATION = 0x11,
    UMAS_KEEP_ALIVE = 0x12,
    UMAS_READ_MEMORY_BLOCK = 0x20,
    UMAS_READ_VARIABLES = 0x22,
    UMAS_WRITE_VARIABLES = 0x23,
    UMAS_READ_COILS_REGISTERS = 0x24,
    UMAS_WRITE_COILS_REGISTERS = 0x25,
    UMAS_INITIALIZE_UPLOAD = 0x30,
    UMAS_UPLOAD_BLOCK = 0x31,
    UMAS_END_STRATEGY_UPLOAD = 0x32,
    UMAS_INITIALIZE_DOWNLOAD = 0x33,
    UMAS_DOWNLOAD_BLOCK = 0x34,
    UMAS_END_STRATEGY_DOWNLOAD = 0x35,
    UMAS_READ_ETH_MASTER_DATA = 0x39,
    UMAS_START_PLC = 0x40,
    UMAS_STOP_PLC = 0x41,
    UMAS_MONITOR_PLC = 0x50,
    UMAS_CHECK_PLC = 0x58,
    UMAS_READ_IO_OBJECT = 0x70,
    UMAS_WRITE_IO_OBJECT = 0x71,
    UMAS_GET_STATUS_MODULE = 0x73,
};

}  // namespace conduitscope
