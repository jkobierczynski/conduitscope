// SPDX-License-Identifier: MIT
// s7comm.hpp - S7comm (Siemens S7 PLC protocol) header decoding.
//
// S7comm always rides inside a COTP Data (DT) frame's user data (see
// cotp.hpp); this file only decodes the S7comm header itself. Scope, same
// philosophy as the Modbus/DNP3 decoders: the fixed header (protocol id,
// ROSCTR, PDU reference, parameter/data lengths, error info) and the
// function code are always decoded; per-function parameter/data payloads
// (e.g. the item list inside a Read Var / Write Var request, addressing a
// specific DB/input/output/memory area) are shown as raw hex rather than
// fully interpreted, except for Setup Communication, whose fixed-size,
// universal-to-every-session parameter block is simple enough to decode
// fully and valuable enough (it's the first thing every S7 session sends)
// to be worth it. S7comm-Plus (TIA Portal's newer, largely undocumented
// protocol, protocol id 0x72) is detected but not decoded at all.
//
// Reference behavior cross-checked against the Wireshark packet-s7comm.c
// dissector and the Arkime s7comm.c parser (both open source); this is an
// independent implementation, not a port of either.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t S7COMM_PROTOCOL_ID = 0x32;
constexpr uint8_t S7COMM_PLUS_PROTOCOL_ID = 0x72;

struct S7CommFrame {
    bool is_plus = false;  // true if this is S7comm-Plus (0x72) rather than classic S7comm (0x32)

    uint8_t rosctr = 0;
    std::string rosctr_name;  // "Job", "Ack", "Ack_Data", "Userdata", or "Unknown (0xNN)"
    uint16_t pdu_reference = 0;
    uint16_t param_length = 0;
    uint16_t data_length = 0;

    bool has_error = false;  // Ack/Ack_Data only
    uint8_t error_class = 0;
    uint8_t error_code = 0;

    bool has_function = false;
    uint8_t function_code = 0;
    std::string function_name;  // e.g. "Read Var", or "Unknown (0xNN)"

    // Only set for function_code == 0xF0 (Setup Communication), whose
    // parameter block is fixed-size and simple enough to fully decode.
    bool has_setup_comm_details = false;
    uint16_t max_amq_calling = 0;
    uint16_t max_amq_called = 0;
    uint16_t negotiated_pdu_length = 0;

    std::string summary;
    std::vector<std::string> notes;
};

std::string s7comm_rosctr_name(uint8_t rosctr);
std::string s7comm_function_name(uint8_t function_code);

// Attempts to interpret `cotp_user_data` (the payload of a COTP Data frame)
// as an S7comm or S7comm-Plus header. Returns std::nullopt (never throws) if
// the payload is empty or its first byte isn't a recognized S7comm protocol
// id (0x32 or 0x72) -- the standard signal that this COTP Data frame is
// carrying something other than S7comm. Once the protocol id is confirmed,
// a header that's too short to hold the fixed fields throws ParseError
// rather than silently returning a partial result.
std::optional<S7CommFrame> try_parse_s7comm(ByteSpan cotp_user_data);

}  // namespace conduitscope
