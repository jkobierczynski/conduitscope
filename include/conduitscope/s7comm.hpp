// SPDX-License-Identifier: Apache-2.0
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
// the returned/written values where present. The classic S7ANY addressing
// syntax (syntax id 0x10) is decoded this way with high confidence -- it's
// well-documented and cross-checked against multiple independent open-source
// implementations. 0xB2, S7-1200/1500 "symbolic" addressing -- confirmed to
// be the single most common non-S7ANY syntax in real traffic -- also gets a
// tag (e.g. "M2.0"), but via an EXPERIMENTAL, unverified reconstruction: its
// wire format references a compiled symbol-table entry (an opaque CRC-like
// value plus a "LID" field) rather than a plain address, and no authoritative
// byte-layout documentation was available to confirm it against, only
// public reverse-engineering notes plus internal consistency in real capture
// samples (see the EXPERIMENTAL block in s7comm.cpp for exactly what that
// evidence is and isn't). Every 0xB2 tag is marked EXPERIMENTAL everywhere
// it's shown -- text, notes, and JSON -- specifically so it's never mistaken
// for the S7ANY decode's confidence level; a shape this reconstruction
// doesn't cover (an unrecognized area code, more than one LID entry) falls
// back to raw hex rather than guessing further. Every other syntax id is
// shown as raw hex, same as every other function code's parameter/data
// payload.
//
// Function codes 0x28 (PLC Control -- the general "Program Invocation" (PI-Service) mechanism
// used to start/stop the PLC's own user program, copy RAM to ROM, compress memory and -- most
// security-relevant -- activate or delete logic blocks on a live controller) and 0x29 (PLC Stop
// -- the wire-level mechanism behind the well-known unauthenticated ICS attack that halts an
// S7-300/400 class CPU's execution with no authentication at all) are also decoded: PLC Stop's
// request-side reserved bytes and confirmation string, and PLC Control's PI service name plus --
// for the _INSE/_INS2/_DELE block-activate/delete services and the P_PROGRAM/_MODU/_GARB
// program-control services -- its parameter block (see S7CommFrame's pi_control_* fields). PLC
// Control's PI service name is also looked up against Wireshark's own name table for every other
// PI service, INCLUDING the large family of _N_* Sinumerik/CNC-specific services (login, file
// transfer, tool/magazine management, ...) -- but only for a name+description lookup, never a
// parameter-block decode: those are a different, much larger domain (dozens of per-service
// argument layouts, all specific to CNC machine-tool control rather than ordinary PLC control)
// and are a deliberate, documented scope boundary here, the same honest-scoping convention this
// file already uses for 0xB2's unverified shapes above. A handful of bytes in both 0x28's and
// 0x29's fixed layout are simply unknown/reserved -- Wireshark's own packet-s7comm.c dissector
// doesn't document their meaning either, so this decoder doesn't invent one.
//
// S7comm-Plus (TIA Portal's newer, largely undocumented protocol, protocol id 0x72) is
// a wholly different, independent application protocol that merely shares this same COTP Data /
// TCP port 102 transport -- try_parse_s7comm below deliberately does NOT recognize it (it returns
// std::nullopt for a 0x72 first byte, the same as for any other non-S7comm payload); its own
// decode lives in s7commplus.hpp/try_parse_s7comm_plus, dispatched separately by decoder.cpp.
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
    // True when `tag` was successfully produced, whether from the well-established S7ANY
    // decode (syntax_id 0x10, is_experimental false) or the EXPERIMENTAL 0xB2 reconstruction
    // (is_experimental true -- see the file comment above and the tia1200_* fields below).
    // False for every other syntax id, or a 0xB2 item whose shape the experimental decode
    // doesn't cover -- in both cases `tag` is empty and the item was recognized but not decoded.
    bool syntax_supported = false;

    // transport_size/transport_size_name/count are S7ANY-only fields (0 / empty for a 0xB2 item,
    // which has no equivalent on the wire -- see the file comment above for why).
    uint8_t transport_size = 0;       // wire "type" byte: 1=BIT, 2=BYTE, 4=WORD, 6=DWORD, 8=REAL, ...
    std::string transport_size_name;  // e.g. "WORD", or "Unknown (0xNN)"
    uint16_t count = 0;                // number of elements of transport_size requested (0xB2: unset -- see above)
    uint16_t db_number = 0;            // meaningful when area is DB/DI (S7ANY) or for a DB-area 0xB2 item
    // S7ANY only: 0x81=I, 0x82=Q, 0x83=M, 0x84=DB, 0x85=DI, 0x86=L, 0x87=V, 0x1C=C, 0x1D=T.
    // Left at 0 for a 0xB2 item -- its own area codes are a different, non-overlapping byte
    // value space (see s7comm.cpp), so this field intentionally doesn't try to unify them;
    // area_name is set correctly for both cases and is what to display/compare instead.
    uint8_t area = 0;
    std::string area_name;             // e.g. "Data Block (DB)"

    // byte_address/bit_offset/bit_address ARE populated for a successfully-decoded 0xB2 item
    // (same byte<<3|bit reconstruction as S7ANY's bit-addressable areas), even though they come
    // from a different, EXPERIMENTAL part of the wire format -- see is_experimental.
    uint32_t bit_address = 0;   // raw 24-bit address field off the wire (byte_address*8 + bit_offset)
    uint32_t byte_address = 0;  // for counter/timer areas, this is the counter/timer number instead
    uint8_t bit_offset = 0;     // meaningless for counter/timer areas

    // Step 7-style notation, e.g. "DB10.DBW100", "DB10.DBX100.0", "I0.0",
    // "MB50", "T5". Empty when syntax_supported is false or the area code
    // isn't recognized.
    std::string tag;

    // True for a tag produced by the experimental 0xB2 (S7-1200/1500
    // "symbolic" addressing) decode rather than the well-established S7ANY
    // one -- see the EXPERIMENTAL note in s7comm.cpp for exactly what is and
    // isn't verified about it. Every caller that displays `tag` must check
    // this and mark it, since a wrong address that looks confidently decoded
    // is worse than an honest "not decoded" in a security-auditing tool.
    // The three tia1200_* fields are only set when is_experimental is true.
    bool is_experimental = false;
    uint16_t tia1200_reserved = 0;   // the two bytes between the syntax id and the area field; meaning unconfirmed
    uint32_t tia1200_crc = 0;        // opaque, TIA Portal-computed; not resolvable to a symbol name from the wire
    uint8_t tia1200_lid_flags = 0;   // meaning unconfirmed
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

    // Only populated for function_code == 0x29 (PLC Stop), Job (request) side -- Wireshark's own
    // dissector doesn't decode the Ack/Ack_Data side either (see s7comm.cpp), so neither does this
    // one; a response just falls through to the generic "no special decode" path. Wire layout
    // after the function code byte: 5 unknown/reserved bytes (meaning not documented anywhere,
    // including in Wireshark's own dissector -- not guessed at here) + a 1-byte length + that many
    // ASCII bytes. In real traffic the string is literally "PLC_STOP", but this decodes whatever
    // ASCII text is actually present rather than validating against that specific value.
    std::string plc_stop_message;

    // Only populated for function_code == 0x28 (PLC Control / "PI-Service"). See s7comm.hpp's file
    // header for the wire layout, the six PI services whose parameter blocks are fully decoded
    // (pi_control_argument/pi_control_blocks below), and the deliberate scope boundary around the
    // _N_* Sinumerik/CNC-specific PI services (name+description lookup only, no parameter decode).
    bool has_pi_service = false;              // Job (request) side only
    std::string pi_service_name;              // raw PI service name off the wire, e.g. "_INSE", "P_PROGRAM"
    std::string pi_service_description;       // looked-up human description; empty if pi_service_name
                                               // isn't in the known table (see s7comm.cpp's kPiServiceNames)
    // P_PROGRAM / _MODU / _GARB only, and only when the parameter block was non-empty: its single
    // ASCII argument string, decoded as-is. Deliberately NOT semantically interpreted (e.g. no
    // attempt to claim a given argument means "cold restart" vs. "warm restart") -- see the file
    // header for why: no authoritative documentation of specific argument values was available,
    // and Wireshark's own dissector doesn't interpret them either.
    std::string pi_control_argument;
    // _INSE / _INS2 / _DELE only: one formatted "<type><number> (<destination>)" string per block
    // descriptor in the parameter block, e.g. "DB100 (Passive)", "FC5 (Active)".
    std::vector<std::string> pi_control_blocks;

    // Only populated for function_code == 0x28, Ack_Data (response) side, when the parameter
    // block is at least 2 bytes (function code + the status byte itself): the status byte's two
    // documented flag bits.
    bool has_pi_control_status = false;
    bool pi_control_has_more_data = false;  // 0x01: more data of the block/file can still be retrieved
    bool pi_control_has_error = false;      // 0x02: an error occurred

    std::string summary;
    std::vector<std::string> notes;
};

std::string s7comm_rosctr_name(uint8_t rosctr);
std::string s7comm_function_name(uint8_t function_code);
std::string s7comm_return_code_name(uint8_t return_code);

// Returns every canonical S7comm function name this decoder can produce for a KNOWN function code
// (every entry in s7comm.cpp's function-code table, the same table s7comm_function_name(uint8_t)
// itself looks up) -- excluding the dynamic "Unknown (0xNN)" fallback used for a function code
// outside that table. Used by policy.cpp to validate a policy file's 'functions:' entries for an
// s7comm-restricted conduit against exactly the strings S7CommFrame::function_name/
// DecodedPacket::s7comm_function_name can actually hold. Order is stable across calls (the table's
// own declaration order) but not alphabetized.
std::vector<std::string> s7comm_known_function_names();

// Attempts to interpret `cotp_user_data` (the payload of a COTP Data frame) as a CLASSIC S7comm
// header. Returns std::nullopt (never throws) if the payload is empty or its first byte isn't
// S7COMM_PROTOCOL_ID (0x32) -- the standard signal that this COTP Data frame is carrying
// something other than classic S7comm, INCLUDING S7comm-Plus (0x72, see s7commplus.hpp) or MMS.
// Once the protocol id is confirmed, a header that's too short to hold the fixed fields throws
// ParseError rather than silently returning a partial result.
std::optional<S7CommFrame> try_parse_s7comm(ByteSpan cotp_user_data);

}  // namespace conduitscope
