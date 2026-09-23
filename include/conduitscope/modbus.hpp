// SPDX-License-Identifier: Apache-2.0
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
// Request vs. response is always disambiguated by payload shape first (a
// 4-byte address+quantity looks like a request; a byte-count-prefixed blob
// looks like a response) -- this is a heuristic, and it is called out as such
// in the decoded output. Decoder::pair_modbus_transaction (decoder.cpp)
// additionally tracks each MBAP transaction ID as an outstanding request per
// TCP session, and authoritatively confirms/overrides that heuristic once a
// matching opposite-direction packet with the same transaction ID is seen on
// the same session -- see docs/MANUAL.md's PROTOCOL DETECTION section. This
// file's own parsing has no notion of TCP session state; that layer lives
// entirely in decoder.cpp, same as PDU/frame-level TCP segment reassembly
// (see modbus_tcp_declared_length below).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

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

    // Only set by ModbusDecoder::decode (registration-model pilot, Stage 2 -- see
    // protocol_decoder.hpp) once it has run the same authoritative MBAP-transaction-ID pairing
    // decoder.cpp's own (now removed) Decoder::pair_modbus_transaction used to perform directly.
    // Mirrors DecodedPacket::modbus_is_paired_response/modbus_paired_request_index exactly -- the
    // decoder.cpp call site just copies these two straight across after unwrapping the
    // ProtocolResult, the same dual-write every other migrated pilot protocol does.
    bool paired_response = false;
    size_t paired_request_index = 0;
};

// Attempts to interpret `tcp_payload` as a Modbus/TCP MBAP frame. Returns
// std::nullopt (never throws) if the payload is too short, its protocol-id
// field is not zero (the standard signal that this isn't Modbus/TCP at all),
// or its raw function-code byte is exactly 0x00, non-exception (reserved/
// never assigned by the spec -- a stronger signal than protocol-id alone,
// added after real DNP3 traffic was seen coincidentally satisfying
// protocol-id==0 and getting mislabeled as Modbus) -- callers use any of
// these to fall back to "unrecognized" rather than aborting the whole
// packet. Deliberately does NOT reject 0x80 (an exception response for
// function code 0, i.e. base function code 0 with the exception bit set) --
// see try_parse_modbus_tcp's own implementation comment for why: a real
// device really does send that byte as a legitimate "Illegal Function"
// exception.
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

// Returns every canonical Modbus function name this decoder can produce for a KNOWN function code
// (every case modbus.cpp's internal function-code table defines) -- excluding the dynamic
// "Unknown (0xNN)" fallback used for a function code outside that table. Used by policy.cpp to
// validate a policy file's 'functions:' entries for a modbus-restricted conduit against exactly
// the strings ModbusFrame::function_name/DecodedPacket::modbus_function_name can actually hold, so
// there is exactly one place ("code N means this name") this is asserted -- the function-code
// table in modbus.cpp -- rather than a second, separately-maintained list. Order is stable across
// calls (the table's own declaration order) but not alphabetized.
std::vector<std::string> modbus_known_function_names();

// registration-model pilot (Stage 2 -- see protocol_decoder.hpp/protocol_registry.hpp). One
// outstanding Modbus request, tracked per TCP SESSION (both directions -- see ModbusFlowState
// below) and keyed further by its MBAP transaction ID, so a later packet on the SAME session
// carrying the SAME transaction ID from the OPPOSITE direction can be authoritatively paired to it
// -- see ModbusDecoder::decode (modbus.cpp). `flow_key` is the *directional* flow the request
// itself was seen on (src->dst), kept so a same-direction repeat of the same transaction ID
// (reused before any response arrived) can be told apart from a genuine opposite-direction reply.
// Replaces decoder.hpp's old (now removed) struct of the same name/shape -- moved here because
// this state now belongs to ModbusFlowState/ModbusDecoder, not to Decoder directly.
struct ModbusPendingRequest {
    size_t packet_index = 0;
    std::string flow_key;
    std::string function_name;
    std::string request_summary;  // the request packet's ModbusFrame::summary, for the response's note
    uint8_t unit_id = 0;
};

// Cross-packet Modbus transaction-pairing state for one TCP SESSION (both directions of one 4-tuple
// -- see DecodeContext::session_key). Replaces decoder.hpp's old (now removed)
// `Decoder::modbus_pending_` bespoke member: this is the same map, just reached generically through
// DecodeContext::flow_state<ModbusFlowState>() (protocol_decoder.hpp) instead of a Decoder member
// dedicated to Modbus alone -- see protocol_registry.hpp's own header comment for why.
class ModbusFlowState : public DecoderFlowState {
public:
    std::unordered_map<uint16_t, ModbusPendingRequest> pending;
};

// Thin ProtocolDecoder wrapper: detection+decode still goes through try_parse_modbus_tcp/
// modbus_tcp_declared_length above, unchanged; decode() additionally performs the transaction
// pairing ModbusPendingRequest/ModbusFlowState describe, writing the outcome into the returned
// ModbusFrame's own paired_response/paired_request_index/notes (the caller -- decoder.cpp -- copies
// those into DecodedPacket exactly as it always has, it just no longer computes them itself). See
// modbus.cpp.
class ModbusDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "modbus"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return modbus_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& modbus_decoder();

}  // namespace conduitscope
