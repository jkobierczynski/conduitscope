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
#include "conduitscope/protocol_decoder.hpp"

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

// Zero-flat-field migration (extra-reader batch): S7comm is the one protocol in this codebase
// whose result CANNOT simply be an unmodified S7CommFrame carried forward on DecodedPacket::result
// the way every other migrated protocol's own struct is. S7DataItem::data (above) is a ByteSpan --
// a non-owning view -- and, when decoder.cpp's own COTP-reassembly call site fed this decoder a
// multi-TPDU-concatenated payload, that view points into CotpReassemblyResult::s7_candidate_storage
// (cotp.hpp), a std::vector<uint8_t> local to that call site's own stack frame. That buffer does
// NOT outlive the decode() call the way every other protocol's own input buffer effectively does,
// so a ByteSpan into it left inside DecodedPacket::result would dangle by the time output.cpp (or
// any other later reader) looked at it -- a real, silent use-after-free, not merely a style
// mismatch with this codebase's usual "just carry the struct forward" migration shape. So this
// wrapper exists specifically to break that dependency: value_summaries below is computed EAGERLY,
// right at decoder.cpp's own call site while s7_candidate_storage is still alive, into a plain
// vector of owned strings -- exactly the same rendering the old dual-write's own
// DecodedPacket::s7comm_value_summaries computed, just relocated into this struct instead of a
// flat field. `items` has no ByteSpan of its own (S7Item is entirely owned scalars/strings -- see
// its own struct above), so unlike data_items it's carried forward unmodified and its own
// display-tag-plus-"[EXPERIMENTAL]" rendering stays in output.cpp's write_s7comm_json_fields, the
// same "transform lives in output.cpp" shape every other zero-flat-field protocol here uses.
struct S7CommResult {
    std::string summary;
    std::vector<std::string> notes;

    bool has_function = false;
    std::string function_name;

    std::vector<S7Item> items;                // safe to defer -- see this struct's own comment
    std::vector<std::string> value_summaries;  // NOT deferred -- see this struct's own comment

    std::string plc_stop_message;

    bool has_pi_service = false;
    std::string pi_service_name;
    std::string pi_service_description;
    std::string pi_control_argument;
    std::vector<std::string> pi_control_blocks;

    bool has_pi_control_status = false;
    bool pi_control_has_more_data = false;
    bool pi_control_has_error = false;
};

std::string s7comm_rosctr_name(uint8_t rosctr);
std::string s7comm_function_name(uint8_t function_code);
std::string s7comm_return_code_name(uint8_t return_code);

// Returns the Step7 area-letter for an S7ANY area code (e.g. "M" for 0x83 Merkers, "DB" for 0x84
// Data Block, "C"/"T" for the Counter/Timer areas), or an empty string for an area code this
// decoder doesn't recognize. This is the same letter table s7comm.cpp's own (file-local) s7_area_name
// already computes as an out-parameter for its own area_name/tag building -- extracted into this
// small shared function (mirroring the canopen_sdo_abort_code_name sharing precedent: pulled out of
// an anonymous-namespace-local function into a small public one, canopen.hpp/canopen.cpp) so
// baseline.cpp's own S7comm operation extraction can get JUST the letter (needed to populate
// Operation::s7_area_letter, baseline.hpp) without a second copy of this table.
std::string s7_area_letter_for_code(uint8_t area);

// Renders a RANGE (not a single address, unlike s7comm.cpp's own file-local s7_build_tag) in Step7
// notation, reusing the identical area-letter/DB-number/suffix conventions s7_build_tag uses for one
// S7Item -- shared so baseline.cpp's `--symbolic-addresses` rendering (write_baseline_check_report_
// text/_json, baseline.cpp) never has to regex a number back out of a rendered operation_key string
// (this codebase's own established anti-pattern, see baseline.cpp's file header comment on Modbus's
// pre-Phase-1 address/quantity gap).
//
// `area_letter` is s7_area_letter_for_code's own output (or "DI" for the Instance Data Block, which
// renders identically to "DB"); `db_number` is meaningful only when area_letter is "DB"/"DI".
// `unit` selects which of three address-unit conventions [start, end) (half-open) is expressed in:
//   - "byte": byte_address units -- MB-always notation (a byte range is exactly expressible in MB
//     terms regardless of whether the underlying accesses were BYTE/WORD/DWORD reads, the common
//     denominator this design deliberately picks over guessing at WORD/DWORD alignment). Renders
//     "MB10" (single byte, DB10-DB19 differ by 1) or "MB10-MB19" (a span); DB-area byte ranges render
//     "DB5.DBB10"/"DB5.DBB10-DB5.DBB19".
//   - "bit": bit_address units (byte_address*8 + bit_offset, see S7Item::bit_address's own comment)
//     -- each endpoint is converted back to byte.bit form. Renders "M10.3" (single bit) or
//     "M10.3-M12.5" (a span); DB-area bit ranges render "DB5.DBX10.3"/"DB5.DBX10.3-DB5.DBX12.5".
//   - "counter_or_timer": the Counter/Timer areas' own raw item-number units (no byte/bit split, no
//     data-size suffix at all -- mirrors s7_build_tag's own counter/timer branch). Renders "T5" or
//     "T5-T9".
// Returns "" when area_letter or unit is empty, or when end <= start (nothing to render).
std::string s7_range_notation(const std::string& area_letter, uint16_t db_number, const std::string& unit,
                               uint32_t start, uint32_t end);

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

// registration-model migration batch 2 (see protocol_decoder.hpp/protocol_registry.hpp). Thin
// ProtocolDecoder wrapper: detection+decode still goes through try_parse_s7comm above, unchanged --
// S7comm is stateless (no request/response pairing across packets), so decode() needs no flow
// state at all. gate_kind() is CotpPayload: this decoder is never gated against raw TCP bytes
// itself, only ever invoked by decoder.cpp's COTP/S7comm-family call site with the bytes a
// CotpDecoder (cotp.hpp) has already framed and cross-packet-reassembled.
class S7CommDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "s7comm"; }
    GateKind gate_kind() const override { return GateKind::CotpPayload; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& s7comm_decoder();

}  // namespace conduitscope
