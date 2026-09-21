// SPDX-License-Identifier: Apache-2.0
// iec104.hpp - IEC 60870-5-104 (APCI + ASDU) decoding.
//
// Unlike DNP3, IEC 104 needs no cross-frame application-fragment reassembly: an I-format APDU
// (the only frame type that carries an ASDU) is always exactly one complete ASDU on the wire --
// there is nothing analogous to DNP3's transport FIR/FIN chaining an application fragment across
// several data-link frames. So this file is purely stateless, and Decoder (decoder.hpp/.cpp) only
// needs it for two things: try_parse_iec104_apci (the fixed 6-byte APCI -- start byte, length,
// 4-byte control field identifying I/S/U-format and, for I/S, the 15-bit send/receive sequence
// numbers) and decode_iec104_asdu (the ASDU that follows an I-format APCI: type ID, variable
// structure qualifier, cause of transmission, common address, and one information object per
// address/point). iec104_apdu_declared_length mirrors modbus_tcp_declared_length/
// dnp3_link_frame_declared_length -- used by Decoder::reassemble_tcp_payload to detect an APDU
// split across a TCP segment boundary before attempting to parse it.
//
// Every multi-byte field on the wire is little-endian (unlike DNP3's link-layer fields, which are
// also little-endian, but unlike Modbus/S7comm's big-endian MBAP/S7 headers) -- this includes the
// 15-bit send/receive sequence numbers (whose low bit is always fixed 0 by the spec), the 3-byte
// Information Object Address (IOA), the 2-byte Common ASDU Address (CASDU), and every numeric
// information-element value (normalized/scaled integers, IEEE-754 short floats, CP24Time2a/
// CP56Time2a time tags).
//
// Decoded ASDU types cover the type IDs that dominate real IEC 104 traffic -- monitoring
// (single/double-point, step position, bitstring-of-32-bit, measured values
// normalized/scaled/short-float, integrated totals, each with and without a CP24Time2a/
// CP56Time2a time tag, plus the normalized-value-without-quality-descriptor variant),
// commands (single/double/regulating-step, bitstring-of-32-bit, set-point
// normalized/scaled/short-float, with and without time tag, delay acquisition, and test command
// with time tag), end-of-initialization, general/counter interrogation, read, clock sync, reset
// process, and parameter loading/activation (normalized/scaled/short-float parameter values and
// parameter activation) -- cross-checked against lib60870-C/lib60870.NET and Wireshark's
// packet-iec104.c dissector for the exact information-element bit layouts. A type ID outside
// that table still gets its ASDU header (type/VSQ/COT/CASDU) decoded, just not its information
// objects -- same "structurally located, not value-decoded" fallback DNP3 applies to an
// unrecognized group/variation.
//
// Deliberately NOT decoded, as a scope decision rather than an oversight: the protection-
// equipment event types (M_EP_TA_1/TB_1/TC_1 and their CP56Time2a-tagged M_EP_TD_1/TE_1/TF_1
// counterparts) pack several named sub-fields -- event state, start/trip phase indicators, output
// circuit indicators -- into a single SEP/SPE/OCI/QDP byte each, and this project holds a higher
// confidence bar for anything describing a protection relay's trip/event semantics than could be
// independently verified this round; M_PS_NA_1 (packed single-point information with status
// change detection) was left out for the same reason, since its SCD field packs 16 points'
// current state and 16 points' change-detected flags into 4 bytes whose bit-to-point ordering
// wasn't independently verified either. The file-transfer ASDU type group (F_FR_NA_1 through
// F_SC_NB_1) is a different kind of gap: file transfer is inherently a multi-frame, stateful
// exchange -- directory listing, section-by-section segment transfer, acknowledgements -- which
// doesn't fit this file's deliberately stateless one-ASDU-at-a-time design (see this file's own
// opening sentence), so it would need a redesign rather than another case in decode_iec104_element,
// left for a future round if it's ever needed. Finally, C_TS_NA_1, the original un-time-tagged
// test command, was skipped because C_TS_TA_1 (its CP56Time2a-tagged successor, which this file
// does decode) supersedes it in every real deployment and the standard itself deprecates 104 in
// favor of 107.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t IEC104_TCP_PORT = 2404;

enum class Iec104FrameType {
    I,  // information transfer -- numbered, carries exactly one ASDU
    S,  // supervisory -- numbered acknowledgement, no payload
    U,  // unnumbered control -- STARTDT/STOPDT/TESTFR act/con
};

struct Iec104Apci {
    Iec104FrameType frame_type = Iec104FrameType::I;

    // Total on-the-wire byte count of this APDU: the 2-byte start+length prefix plus the length
    // field's own value (4-byte control field, plus the ASDU for an I-format APDU). Used by
    // Decoder's same-TCP-payload coalescing loop to find where the next APDU (if any) starts.
    size_t wire_length = 0;

    // I-format only: bytes of ASDU following the 6-byte APCI (wire_length - 6).
    size_t asdu_length = 0;

    // I-format only: N(S)/N(R), the 15-bit send/receive sequence numbers (low bit always 0 on the
    // wire per spec, stripped out of these values). S-format: recv_seq only (send_seq unused).
    uint16_t send_seq = 0;
    uint16_t recv_seq = 0;

    // U-format only: e.g. "STARTDT act", "TESTFR con", or "Unknown (0xNN)" for a control-field byte
    // that has the U-format bit pattern (bits1-2 = 11) but doesn't match one of the six functions
    // the spec defines.
    std::string u_function_name;

    std::string summary;
};

// Returns std::nullopt (never throws) if `tcp_payload` does not look like a well-formed IEC 104
// APCI: fewer than 6 bytes, wrong start byte (0x68), an implausible length field, or a control
// field that doesn't match one of the three frame formats' fixed bit patterns (I-format's N(R)
// low bit, S-format's fixed 0x01/0x00 first two control bytes, U-format's fixed all-zero last
// three control bytes) -- these structural checks make a coincidental match far less likely than
// Modbus/TCP's single protocol-id==0 tell, which matters because IEC 104 detection runs before
// Modbus in Decoder's Auto-mode dispatch specifically to avoid a real collision risk: an I-format
// APDU with N(S)=N(R)=0 (common very early in a session) makes its first four APCI-window bytes
// read as Modbus's protocol-id==0 with mbap_length==0, and the ASDU's type-ID/VSQ bytes can then
// land exactly where Modbus expects unit-id/function-code. For an I-format APDU, does NOT require
// that `tcp_payload` actually contain the full declared ASDU yet -- see iec104_apdu_declared_length
// for the truncation-detection helper Decoder::reassemble_tcp_payload uses to ensure it does before
// this is ever called.
std::optional<Iec104Apci> try_parse_iec104_apci(ByteSpan tcp_payload);

// Returns the total on-the-wire byte count one IEC 104 APDU declares (2-byte start+length prefix
// plus the length field's own value) once there are enough bytes to read that declaration
// (payload.size() >= 2) and the start byte and length field are individually plausible (0x68, and
// length in [4, 253] -- an APDU's control field is always 4 bytes, and the spec caps a whole APDU
// at 255 bytes) -- regardless of whether `payload` actually holds that many bytes yet; that's the
// point, so a caller can tell a truncated-but-recognized APDU from one that's actually complete.
// Returns std::nullopt if there aren't yet enough bytes to tell (< 2), the start byte doesn't
// match, or the length field is out of the plausible range. try_parse_iec104_apci itself is
// unchanged and still requires all 6 APCI bytes (plus, for I-format, the full declared ASDU) to be
// present; this is used only for detecting truncation across a TCP segment boundary -- see
// Decoder::reassemble_tcp_payload in decoder.cpp.
std::optional<size_t> iec104_apdu_declared_length(ByteSpan payload);

// One decoded information object: the point (Information Object Address) it belongs to, a short
// human-readable rendering of its value, and any decoded quality-flag names (empty if this
// element's format carries none of its own, e.g. a command's Select/Execute-only SCO/DCO/RCO).
struct Iec104InformationObject {
    uint32_t ioa = 0;
    std::string value;
    std::vector<std::string> flags;
};

struct Iec104Asdu {
    uint8_t type_id = 0;
    std::string type_name;  // e.g. "M_SP_NA_1 (Single-point information)", or "Unknown (type NN)"
    // Just the mnemonic half of type_name, e.g. "M_SP_NA_1", or "Unknown(NN)" (no space -- see
    // iec104_type_short_name's own comment for why this differs from type_name's unknown-value
    // style). This is the clean, single-token field policy matching uses -- see that function's
    // comment.
    std::string type_short_name;

    bool sq = false;           // VSQ bit8: true = sequential IOAs (one explicit IOA, then +1 each), false = one
                                // explicit IOA per object (discontinuous)
    uint8_t object_count = 0;  // VSQ bits7-1

    uint8_t cot_code = 0;  // Cause of Transmission, bits0-5 of the COT field's first byte
    std::string cot_name;  // e.g. "spontaneous", "activation", "interrogated by group 1 interrogation"
    bool test = false;     // COT field bit8 (Test flag)
    bool negative = false;  // COT field bit7 (P/N: true = negative confirmation)
    uint8_t originator_address = 0;  // COT field's second byte (0 when originator addressing is unused)

    uint16_t common_address = 0;  // Common ASDU Address (station address), 2 bytes, little-endian

    // False when type_id isn't in the decoded-type table (see the file header comment) or the ASDU
    // was too short/malformed to decode its information objects -- `note` explains why, and
    // `objects` is empty in that case (the object data couldn't be reliably located/interpreted, so
    // it is not skipped-and-shown either, unlike DNP3's object-header fallback -- an ASDU has only
    // one type ID for its entire object list, so there is no "later header" to keep aligned for).
    bool decoded = true;
    std::string note;

    // One entry per information object, capped (very large interrogation responses keep object_count
    // accurate but only the first entries get an individual Iec104InformationObject -- see
    // kMaxDecodedObjects in iec104.cpp).
    std::vector<Iec104InformationObject> objects;

    std::string summary;
    std::vector<std::string> notes;
};

// Decodes one ASDU -- type ID, VSQ, COT, common address, and (for a recognized type ID) every
// information object's address and value -- from `asdu_bytes`, which must be exactly the ASDU
// portion of one I-format APDU (i.e. Iec104Apci::asdu_length bytes, right after the 6-byte APCI).
// Never throws: anything it cannot make sense of is recorded in the returned Iec104Asdu's
// notes/note fields rather than propagated as a ParseError, mirroring decode_dnp3_application_layer.
Iec104Asdu decode_iec104_asdu(ByteSpan asdu_bytes);

// Returns just the mnemonic (e.g. "M_SP_NA_1") for a KNOWN ASDU type ID -- the same short_name
// half of the {type_id, short_name, description} table that backs Iec104Asdu::type_name's compound
// "<short_name> (<description>)" rendering (see iec104.cpp) -- or "Unknown(N)" (no space, unlike
// type_name's "Unknown (type N)") for a type ID outside that table, deliberately kept a clean,
// single policy-matchable token distinguishable at a glance from type_name's own unknown-value
// style. This is the field DecodedPacket::iec104_asdu_type_short_name is populated from, and what a
// policy file's 'functions:' entries for an iec104-restricted conduit are validated/matched
// against (see policy.cpp and PolicyEngine) -- type_name's parenthetical description is NOT used
// for policy matching, since it bundles two independent pieces of information into one string.
std::string iec104_type_short_name(uint8_t type_id);

// Returns every canonical ASDU short name (the mnemonic half only, e.g. "M_SP_NA_1") this decoder
// can produce for a KNOWN type ID -- excluding the dynamic "Unknown(N)" fallback used for a type ID
// outside the table. Used by policy.cpp to validate a policy file's 'functions:' entries for an
// iec104-restricted conduit against exactly the strings iec104_type_short_name/
// DecodedPacket::iec104_asdu_type_short_name can actually hold. Order is stable across calls (the
// table's own declaration order) but not alphabetized.
std::vector<std::string> iec104_known_asdu_short_names();

// Migration batch 2 (see protocol_decoder.hpp/protocol_registry.hpp): everything decoder.cpp's
// IEC 104 call site dual-writes into DecodedPacket, gathered from however many APDUs were
// coalesced in one TCP payload (see Iec104Decoder::decode below) -- mirrors exactly what the
// pre-migration call site computed locally. `summary`/`notes` are the fully-assembled headline
// summary (APCI + first I-format APDU's ASDU, if any) and note list, in the same order the legacy
// call site produced them; the five iec104_* fields reflect only the FIRST I-format APDU found in
// the payload (same "first APDU only" convention DecodedPacket's own dnp3_has_function-style
// fields use), and iec104_object_values is the same cumulative-across-every-APDU-in-the-payload
// list the legacy call site built, capped at 50 entries exactly as before.
struct Iec104Result {
    std::string summary;
    std::vector<std::string> notes;

    bool iec104_has_asdu = false;
    std::string iec104_asdu_type_name;
    std::string iec104_asdu_type_short_name;
    std::string iec104_cot_name;
    uint16_t iec104_common_address = 0;
    std::vector<std::string> iec104_object_values;
};

// id() == "iec104", gate_kind() == TcpPortIndependent. Wraps try_parse_iec104_apci/
// decode_iec104_asdu plus the same-TCP-payload multi-APDU-coalescing loop that used to live
// directly in decoder.cpp's `if (want_iec104)` call site -- IEC 104 is purely stateless (see this
// file's own opening comment), so unlike Dnp3Decoder/CotpDecoder there is no per-flow reassembly
// state here at all; decode() just gates, decodes, and merges every APDU it finds into one result.
class Iec104Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "iec104"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return iec104_apdu_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& iec104_decoder();

}  // namespace conduitscope
