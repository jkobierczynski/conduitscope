// SPDX-License-Identifier: MIT
// s7comm.hpp - S7comm (Siemens S7 PLC protocol) header decoding.
//
// S7comm always rides inside a COTP Data (DT) frame's user data (see
// cotp.hpp); this file only decodes the S7comm header itself. Scope, same
// philosophy as the Modbus/DNP3 decoders: the fixed header (protocol id,
// ROSCTR, PDU reference, parameter/data lengths, error info) and the
// function code are always decoded; Setup Communication's fixed-size,
// universal-to-every-session parameter block is fully decoded (it's the
// first thing every S7 session sends); and Read Var / Write Var -- the two
// function codes that make up the overwhelming majority of real S7comm
// traffic -- get full item-level address decoding: which memory area
// (input/output/merker/DB/counter/timer), DB number, byte/bit address, and
// transport size (BIT/BYTE/WORD/DWORD/...) each item addresses, rendered in
// familiar Step 7 notation (e.g. "DB10.DBW100", "I0.0", "MB50", "T5"), plus
// the returned/written values where present. Only the classic S7ANY
// addressing syntax (syntax id 0x10) is decoded this way -- other syntax
// ids are recognized (by id) but shown as raw hex, same as every other
// function code's parameter/data payload. The most common of these in
// practice is 0xB2, S7-1200/1500 "symbolic" addressing (confirmed against
// real traffic and against Wireshark's own S7COMM_SYNTAXID_1200SYM
// constant) -- its item format uses an opaque CRC-like value plus one or
// more "LID" fields to reference a compiled symbol table entry rather than
// a plain byte/bit address, and reconstructing that format with confidence
// from public sources wasn't possible in the time available; it's left as
// a documented stub rather than shipping a guessed decode that could
// silently show a wrong address in a security-auditing tool. See ROADMAP.
// S7comm-Plus (TIA Portal's newer, largely undocumented protocol, protocol
// id 0x72) is detected but not decoded at all.
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

// One address item from a Read Var / Write Var request's parameter block
// (the "which memory location" half -- values themselves travel separately
// in the data block, see S7DataItem below).
struct S7Item {
    uint8_t syntax_id = 0;
    // False if syntax_id isn't 0x10 (S7ANY) -- most commonly seen in
    // practice as 0xB2 (S7-1200/1500 "symbolic" addressing, confirmed
    // against real traffic -- see s7comm.hpp's file comment for why it
    // isn't decoded). When false, every field below except syntax_id is
    // meaningless and `tag` is empty; the item was recognized but not
    // decoded.
    bool syntax_supported = false;

    uint8_t transport_size = 0;       // wire "type" byte: 1=BIT, 2=BYTE, 4=WORD, 6=DWORD, 8=REAL, ...
    std::string transport_size_name;  // e.g. "WORD", or "Unknown (0xNN)"
    uint16_t count = 0;                // number of elements of transport_size requested
    uint16_t db_number = 0;            // only meaningful when area is DB or DI
    uint8_t area = 0;                  // 0x81=I, 0x82=Q, 0x83=M, 0x84=DB, 0x85=DI, 0x86=L, 0x87=V, 0x1C=C, 0x1D=T
    std::string area_name;             // e.g. "Data Block (DB)"

    uint32_t bit_address = 0;   // raw 24-bit address field off the wire (byte_address*8 + bit_offset)
    uint32_t byte_address = 0;  // for counter/timer areas, this is the counter/timer number instead
    uint8_t bit_offset = 0;     // meaningless for counter/timer areas

    // Step 7-style notation, e.g. "DB10.DBW100", "DB10.DBX100.0", "I0.0",
    // "MB50", "T5". Empty when syntax_supported is false or the area code
    // isn't recognized.
    std::string tag;
};

// One data item from a Read Var response's data block, or a Write Var
// request/response's data block (the "value" half). Field meaning differs
// slightly by direction -- see notes on try_parse_s7comm.
struct S7DataItem {
    uint8_t return_code = 0;
    std::string return_code_name;  // e.g. "Success", "Object does not exist"

    // Only set for Read Var responses and Write Var requests (Write Var
    // responses are just a bare return code per item, no transport
    // size/length/data on the wire).
    bool has_value_fields = false;
    uint8_t transport_size = 0;  // wire "transport size" byte, response-side code (3=BIT, 4=BYTE/WORD/DWORD, ...)
    uint16_t length_field = 0;    // raw length field off the wire, before bit/byte-count interpretation
    ByteSpan data;                 // the actual value bytes, best-effort length-clamped to what's available
};

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

    // Only populated for function_code == 0x04 (Read Var) or 0x05 (Write Var):
    //   - Read Var Job (request):    items has the addresses being read; data_items is empty.
    //   - Read Var Ack_Data (response): items is empty; data_items has the returned values.
    //   - Write Var Job (request):   items has the addresses; data_items has the values being written.
    //   - Write Var Ack_Data (response): items is empty; data_items has one bare return code per item
    //     (has_value_fields is false on each, since Write Var confirmations carry no value payload).
    std::vector<S7Item> items;
    std::vector<S7DataItem> data_items;

    std::string summary;
    std::vector<std::string> notes;
};

std::string s7comm_rosctr_name(uint8_t rosctr);
std::string s7comm_function_name(uint8_t function_code);
std::string s7comm_return_code_name(uint8_t return_code);

// Attempts to interpret `cotp_user_data` (the payload of a COTP Data frame)
// as an S7comm or S7comm-Plus header. Returns std::nullopt (never throws) if
// the payload is empty or its first byte isn't a recognized S7comm protocol
// id (0x32 or 0x72) -- the standard signal that this COTP Data frame is
// carrying something other than S7comm. Once the protocol id is confirmed,
// a header that's too short to hold the fixed fields throws ParseError
// rather than silently returning a partial result.
std::optional<S7CommFrame> try_parse_s7comm(ByteSpan cotp_user_data);

}  // namespace conduitscope
