// SPDX-License-Identifier: MIT
// modbus.hpp - Modbus/TCP (MBAP header + PDU) decoding.
//
// Covers the function codes that make up the overwhelming majority of real
// Modbus/TCP traffic: the four read functions (coils/discrete inputs/holding
// registers/input registers), the two single-write functions, and the two
// multiple-write functions, plus generic exception-response decoding. Less
// common function codes (diagnostics, device identification, mask write,
// read/write multiple) are recognized by name but their payload is shown as
// hex rather than fully decoded -- see docs/MANUAL.md Roadmap.
//
// Request vs. response is not tracked via TCP stream state in this groundwork
// release (that needs the stream reassembly this tool doesn't do yet). Reads
// are disambiguated by payload shape instead (a 4-byte address+quantity looks
// like a request; a byte-count-prefixed blob looks like a response) -- this is
// a heuristic, and it is called out as such in the decoded output.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t MODBUS_TCP_PORT = 502;

struct ModbusFrame {
    uint16_t transaction_id = 0;
    uint16_t protocol_id = 0;
    uint16_t mbap_length = 0;
    uint8_t unit_id = 0;

    uint8_t function_code = 0;    // as seen on the wire, i.e. includes the 0x80 exception bit
    bool is_exception = false;
    uint8_t exception_code = 0;   // only meaningful if is_exception

    std::string function_name;    // e.g. "Read Holding Registers", or "Unknown (0x2C)"
    std::string summary;          // one-line human-readable summary
    std::vector<std::string> notes;  // extra detail lines (warnings, heuristics used, etc.)
    ByteSpan raw_pdu_data;         // the PDU bytes after the function code, for hex fallback/JSON
};

// Attempts to interpret `tcp_payload` as a Modbus/TCP MBAP frame. Returns
// std::nullopt (never throws) if the payload is too short, its protocol-id
// field is not zero (the standard signal that this isn't Modbus/TCP at all),
// or its function code is 0 (reserved/never assigned by the spec -- a
// stronger signal than protocol-id alone, added after real DNP3 traffic was
// seen coincidentally satisfying protocol-id==0 and getting mislabeled as
// Modbus) -- callers use any of these to fall back to "unrecognized" rather
// than aborting the whole packet.
std::optional<ModbusFrame> try_parse_modbus_tcp(ByteSpan tcp_payload);

// Returns the total on-the-wire byte count a Modbus/TCP MBAP message declares -- its 6-byte
// transaction-id+protocol-id+length prefix, plus `length` more bytes (unit id + PDU) -- once
// there are enough bytes to read that declaration (payload.size() >= 6) and protocol-id reads as
// 0 (the standard Modbus/TCP tell -- see try_parse_modbus_tcp). When the function-code byte is
// also available (payload.size() >= 8), the same extra safety check try_parse_modbus_tcp applies
// is applied here too: function code 0 is reserved and never assigned, so protocol-id==0 with
// function-code==0 is almost certainly a coincidence, not real Modbus/TCP (this is the DNP3-on-
// port-20000 collision documented on try_parse_modbus_tcp) -- returns std::nullopt in that case
// even though protocol-id alone looked like a match. Also returns std::nullopt if the declared
// length is wildly implausible for a real Modbus PDU (over 300 bytes -- the spec caps a PDU at
// 253, so mbap_length can never legitimately exceed 254): found via a real capture where
// non-Modbus traffic on port 502 coincidentally satisfied protocol-id==0 with a "length" field of
// several thousand, which without this cap would be mistaken for a genuine PDU split across TCP
// segments and buffered forever. Returns std::nullopt if there aren't yet enough bytes to tell
// (< 6) or protocol-id is nonzero. The returned length may exceed payload.size() -- that's the
// point: it tells a caller how many more bytes to wait for. try_parse_modbus_tcp itself is
// unchanged and still decodes from whatever bytes are actually present; this is used only to
// detect a PDU truncated across a TCP segment boundary -- see Decoder::reassemble_tcp_payload in
// decoder.cpp.
std::optional<size_t> modbus_tcp_declared_length(ByteSpan payload);

std::string modbus_exception_name(uint8_t exception_code);

}  // namespace conduitscope
