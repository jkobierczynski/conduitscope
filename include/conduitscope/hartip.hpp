// SPDX-License-Identifier: Apache-2.0
// hartip.hpp - HART-IP decoding: the fixed 8-byte HART-IP message header, its four session-
// control message shapes (Session Initiate, Session Close, Keep Alive, Error/NAK), and the
// Pass-Through message that tunnels the classic wired-HART token-passing Data-Link PDU (the
// actual HART command/response traffic).
//
// HART-IP rides over EITHER TCP or UDP, conventionally port 5094, the same port number for both
// transports (unlike EtherNet/IP's separate TCP-44818/UDP-2222 split for explicit-vs-implicit
// messaging) -- see try_parse_hartip's own "structural detection gate" paragraph below for how
// this decoder identifies it port-independently on both. Every multi-byte field at every layer
// is big-endian.
//
// Sourcing: this file's HART-IP header/session/Pass-Through-framing wire-format description is
// cross-checked, byte offset by byte offset, against Wireshark's own dissector --
// epan/dissectors/packet-hartip.c -- the same sourcing standard this codebase already applies to
// BACnet/GOOSE/SV/EtherCAT/PROFINET. Wireshark's own dissector does NOT decode two bytes this
// file's Pass-Through layer surfaces (the Response Code and Device Status bytes) into named
// values/bits at all -- it shows them as opaque numbers -- so this decoder's Response Code and
// Device Status tables are instead cross-checked against the actual HART Communication
// Foundation specification (HCF_SPEC-307 "Command Response Code Specification" for the
// standardized response codes) and, for Device Status, cross-corroborated across half a dozen
// independent HART device vendors' own published HART reference manuals (which all reproduce an
// identical 8-bit table) plus FieldComm Group's own HART Application Guide prose -- see the
// Response Code and Device Status sections below for exactly what is and isn't asserted with
// that level of confidence. HART command NAMES (as opposed to their byte layout) are likewise not
// present in Wireshark's source at all (it identifies commands only by number) -- this file's
// command-name table is cross-corroborated across FieldComm Group's own published material and
// multiple independent vendor HART command references; two commands (31 and 203) are
// deliberately left unnamed rather than guessed at -- see "Command dispatch" below.
//
// ---------------------------------------------------------------------------------------------
// HART-IP message header (8 bytes, fixed, immediately at the start of every message on either
// transport -- cross-checked against packet-hartip.c's dissect_hartip_common):
//   Version(1)         -- current HART-IP version; NOT validated by this decoder at all (nor by
//                          Wireshark's own dissector) -- surfaced as-is.
//   MessageType(1)      -- 0=Request, 1=Response, 2=Publish, 3=Error, 15=NAK (Wireshark's own
//                          value_string table renders both 3 and 15 with the identical display
//                          string "Error"; this decoder keeps them as distinct names "Error"/
//                          "NAK" instead, reflecting the C source's own distinct
//                          ERROR_MSG_TYPE/NAK_MSG_TYPE #define names, which is more useful for a
//                          security-auditing tool than collapsing them to one label).
//   MessageID(1)        -- 0=Session Initiate, 1=Session Close, 2=Keep Alive, 3=Pass Through.
//                          Publish (MessageType 2) messages carry MessageID 3 and share Pass
//                          Through's exact body shape -- there is no separate "Publish" MessageID
//                          value; see "Structural detection gate" below.
//   Status(1)           -- present on the wire, surfaced as a raw byte; Wireshark's own
//                          dissector does not decompose it into named bits or values, and no
//                          authoritative bit table for it was found during this decoder's own
//                          research, so neither does this decoder -- shown as a raw byte only.
//   TransactionID(2)    -- big-endian; labeled "Sequence Number" in Wireshark's own UI text, so
//                          this decoder does the same in its own summary text even though the
//                          underlying field/struct name (transaction_id, matching the C source's
//                          own internal name) is transaction_id.
//   MsgLength(2)        -- big-endian; total byte length of this ENTIRE HART-IP message,
//                          INCLUDING this 8-byte header. Used both as this decoder's own
//                          plausibility check and, for TCP, as the declared length that drives
//                          this codebase's usual PDU/frame-level TCP stream reassembly (see
//                          hartip_declared_length below, mirroring enip_declared_length).
//
// Structural detection gate: Wireshark's own dissector accepts a buffer as HART-IP purely on
// MessageType being one of the 5 values {0,1,2,3,15} AND MessageID being one of the 4 values
// {0,1,2,3} -- no check on Version, no magic bytes, no length sanity check at all for
// identification purposes (MsgLength is read but only used for framing/reassembly, not as a
// gate). This decoder applies that same two-byte check (offsets 1 and 2) but additionally
// requires MsgLength to be at least 8 (the header's own fixed size) as a third, modest
// plausibility check beyond what Wireshark itself requires -- cheap insurance against the
// weakest part of this gate (MessageType/MessageID both land on small, common byte values like
// 0-3, giving this decoder's own structural anchor a smaller effective collision space than,
// say, BACnet's Type+Function pair or EtherNet/IP's three independent checks; see PROTOCOL
// DETECTION in docs/MANUAL.md for the full honest comparison). Applied port-independently in
// Auto mode on BOTH TCP and UDP payloads -- UDP port 5094 is recorded as an "expected port"
// annotation only, never a gate, the same posture this codebase already uses for BACnet/IP and
// CIP I/O.
//
// KNOWN, ACCEPTED, DOCUMENTED LIMITATION -- a real Auto-mode detection collision over TCP: a
// HART-IP Session Initiate message's own header (MessageID 0, Status 0 -- the only value ever
// observed in this decoder's own research) reads as a plausible Modbus/TCP MBAP header
// (protocol-id==0, from bytes 2-3; a small, plausible mbap_length, from bytes 4-5 -- HART-IP's
// own TransactionID field), so on TCP it is misclassified as a Modbus/TCP PDU "buffering,
// waiting for more" bytes that will never arrive -- see the full explanation and why it is
// deliberately NOT resolved (reordering HART-IP ahead of Modbus in Auto-mode TCP dispatch was
// tried while scoping this feature and measurably regressed this project's own Modbus/S7comm test
// corpus) on HART-IP's own TCP dispatch block in decoder.cpp's reassemble_tcp_payload/decode, and
// tests/sample_hartip.pcap's own dedicated demonstration packets. HART-IP over UDP is entirely
// unaffected (UDP datagrams have no declared-length reassembly pre-check to collide against);
// Pass-Through messages (MessageID 3) are also unaffected on TCP, since their own MessageID never
// produces the protocol-id==0 collision.
//
// ---------------------------------------------------------------------------------------------
// Session Initiate (MessageID 0) body -- ASHRAE... no, FieldComm Group's own HART-IP spec, cross-
// checked against packet-hartip.c's dissect_session_init -- exactly 5 bytes, ONE shape used for
// both the request and the response (Wireshark's own dissector does not distinguish direction
// here; neither does this decoder):
//   HostType(1)               -- 0=Secondary Host, 1=Primary Host.
//   InactivityCloseTimer(4)   -- big-endian seconds; the server closes the session if it sees no
//                                 traffic for this long.
// A body length other than 5 is shown only as raw hex, not guessed at.
//
// Session Close (MessageID 1) / Keep Alive (MessageID 2) bodies: both expected EMPTY (0 bytes;
// total message = 8 bytes, header only) -- cross-checked against packet-hartip.c's shared
// dissect_empty_body helper, which itself treats a 0-byte body as the *expected*, unremarkable
// case (an informational note, not a warning) and anything else as unexpected. This decoder does
// the same: a non-empty body on either of these two message IDs is shown as raw hex with a note,
// not silently ignored.
//
// Error / NAK (MessageType 3 or 15, checked BEFORE MessageID -- applies regardless of which of
// the 4 MessageID values this message otherwise carries, mirroring packet-hartip.c's own
// dispatch order) body -- exactly 1 byte when present:
//   ErrorCode(1) -- 0=Session closed, 1=Primary session unavailable, 2=Service unavailable (the
//                   only three values packet-hartip.c's own hartip_error_code_values table
//                   defines; anything else is rendered "unknown(N)").
// A body length other than 1 is shown only as raw hex, not guessed at.
//
// ---------------------------------------------------------------------------------------------
// Pass Through (MessageID 3, MessageType 0/1/2 -- i.e. every Request/Response/Publish) body:
// this is the tunneled classic wired-HART token-passing Data-Link PDU, cross-checked byte offset
// by byte offset against packet-hartip.c's dissect_pass_through:
//   Preambles(0..N)       -- optional leading 0xFF bytes (a physical-layer synchronization
//                             artifact from the wired-HART side of a gateway/multiplexer; largely
//                             vestigial once tunneled over IP, but still sometimes present) --
//                             counted and skipped, not otherwise interpreted.
//   Delimiter(1)           -- a bitmask (cross-checked against packet-hartip.c's own delimiter
//                             sub-field hf_register_info entries):
//                               bits 0-2 (0x07) Frame Type    -- 1=BACK (Burst Frame), 2=STX
//                                                                (Master->Field Device, i.e. a
//                                                                request), 6=ACK (Field Device->
//                                                                Master, i.e. a response).
//                               bits 3-4 (0x18) Physical Layer -- 0=Asynchronous, 1=Synchronous.
//                               bits 5-6 (0x60) Expansion Byte Count -- 0-3, a raw count.
//                               bit 7    (0x80) Address Type   -- 0=Polling/short (1-byte
//                                                                address), 1=Unique/long (5-byte
//                                                                address).
//                             Frame Type ACK or BACK is this decoder's own "is_response" signal
//                             (mirroring packet-hartip.c's own `is_rsp = (frame_type==6 ||
//                             frame_type==1)` derivation) -- it decides whether Response Code +
//                             Device Status are present (see below).
//   Address(1 or 5)        -- 1-byte, masked to the low 6 bits (0-63), when Address Type is
//                             Polling; 5 raw bytes when Unique -- shown as raw hex either way
//                             (Wireshark's own source has an explicit TODO noting the top 2 bits
//                             of a long address's first byte are a device-type field it doesn't
//                             bother masking out either; this decoder matches that same
//                             intentionally-unrefined treatment rather than guessing at a device-
//                             type split that isn't confirmed).
//   ExpansionBytes(0-3)    -- present only when the delimiter's expansion-byte-count is nonzero;
//                             shown as raw hex, not interpreted.
//   Command(1)              -- the HART command number -- see "Command dispatch" below.
//   ByteCount(1)             -- byte count of everything that follows, up to but NOT including
//                             the trailing checksum byte.
//   [Response Code(1), Device Status(1)]  -- present ONLY when is_response (see above) -- see
//                             "Response Code" and "Device Status" sections below.
//   Data(ByteCount - [2 if is_response else 0])  -- the command's own request/response data --
//                             see "Command dispatch" below for which command numbers this
//                             decoder value-decodes and which are shown only as raw hex.
//   Checksum(1)             -- the classic wired-HART longitudinal (XOR) checksum byte. HART-IP
//                             encapsulation does NOT strip this legacy byte even though TCP/UDP/
//                             IP already provides its own transport-level integrity -- confirmed
//                             directly from packet-hartip.c, which labels but explicitly never
//                             computes or verifies it (`proto_tree_add_checksum(...,
//                             PROTO_CHECKSUM_NO_FLAGS)`). This decoder does the same: the byte is
//                             surfaced raw, never verified (computing/verifying it would need the
//                             HART XOR algorithm applied across the whole PDU, which is possible
//                             but out of scope for this groundwork release -- see LIMITATIONS).
//
// ---------------------------------------------------------------------------------------------
// Response Code (present only when is_response; cross-checked against HCF_SPEC-307, "Command
// Response Code Specification" Rev 6.0 -- the one table in this file sourced from an actual
// primary FieldComm/HART Communication Foundation specification document, not a vendor
// paraphrase): bit 7 of this byte selects between two entirely different 7-bit tables:
//   bit 7 SET   -- the low 7 bits are a COMMUNICATION-ERROR bitmask (a data-link-layer concept,
//                  not command-specific) -- cross-corroborated across two independent vendor
//                  HART references, agreeing on bits 6-1; bit 0's meaning is NOT confidently
//                  sourced (one reference calls it reserved, another calls it an undefined
//                  overflow flag) and is rendered as "reserved/unconfirmed" rather than guessed:
//                    bit 6 (0x40) Vertical Parity Error (UART parity)
//                    bit 5 (0x20) Overrun Error
//                    bit 4 (0x10) Framing Error
//                    bit 3 (0x08) Longitudinal Parity Error (the HART XOR checksum above didn't
//                                 match, per the responding device's own report -- distinct from
//                                 this decoder's own non-verification of that same checksum byte)
//                    bit 2 (0x04) Reserved
//                    bit 1 (0x02) Buffer Overflow
//                    bit 0 (0x01) reserved/unconfirmed -- not asserted
//   bit 7 CLEAR -- the low 7 bits (0-127) are a command-specific response code. Per HCF_SPEC-307's
//                  own classification, response codes split into three classes: single-definition
//                  (the SAME meaning regardless of which command produced it -- see the table
//                  below), multi-definition (meaning depends on which command produced it -- this
//                  decoder does NOT attempt a per-command lookup table, since doing so honestly
//                  would need every command's own spec, most of which this project doesn't have),
//                  and warnings (also command-dependent). Only the single-definition codes are
//                  named; every other 0-127 value is rendered "command-specific response code N
//                  (meaning depends on which command produced it -- not decoded)":
//                    0 Success (spec text: "No Command-Specific Errors")     32 Busy
//                    2 Invalid Selection                                    33 Delayed Response Initiated
//                    3 Passed Parameter Too Large                          34 Delayed Response Running
//                    4 Passed Parameter Too Small                          35 Delayed Response Dead
//                    5 Too Few Data Bytes Received                        36 Delayed Response Conflict
//                    6 Device-Specific Command Error                       60 Payload Too Long
//                    7 In Write Protect Mode                               61 No Buffers Available
//                   16 Access Restricted                                   62 No Alarm/Event Buffers Available
//                   17 Invalid Device Variable Index                       63 Priority Too Low
//                   18 Invalid Units Code                                  64 Command Not Implemented
//                   19 Device Variable Index Not Allowed
//                   20 Invalid Extended Command Number
//                   21 Invalid I/O Card Number
//                   22 Invalid Channel Number
//                   23 Sub-Device Response Too Long
//
// Device Status (present only when is_response; cross-corroborated across six independent HART
// device vendors' own published HART reference manuals, which all reproduce this exact 8-bit
// table verbatim, plus FieldComm Group's own HART Application Guide prose using equivalent
// wording -- NOT sourced from Wireshark, whose own dissector leaves this byte opaque):
//   bit 7 (0x80) Field Device Malfunction        bit 3 (0x08) Loop Current Fixed
//   bit 6 (0x40) Configuration Changed            bit 2 (0x04) Loop Current Saturated
//   bit 5 (0x20) Cold Start                       bit 1 (0x02) Non-Primary Variable Out of Limits
//   bit 4 (0x10) More Status Available            bit 0 (0x01) Primary Variable Out of Limits
//
// ---------------------------------------------------------------------------------------------
// Command dispatch: HART command NAMES below are cross-corroborated across FieldComm Group's own
// published material and multiple independent HART device vendors' own command references (high
// confidence for every numbered command except 31 and 203 -- see those two entries). Byte layouts
// are cross-checked against packet-hartip.c's own per-command dissection functions
// (dissect_cmd0/1/2/.../203). Wireshark's own per-command functions are command-keyed, not
// direction-keyed -- the SAME byte-offset table is used to decode a write command's REQUEST data
// (the value being written) as decodes the matching read command's RESPONSE data (the value being
// read back), since in practice they carry the identical field shape; this decoder does the same
// rather than maintaining separate request/response tables per command.
//   0, 11, 21  Read Unique Identifier [Associated with Tag (11) / Long Tag (21)] -- device
//              identification: Expansion Code, Expanded Device Type, Min. Request Preambles,
//              Universal/Device/Software revisions, packed Hardware-Rev+Signaling byte, Flags,
//              3-byte Device ID, and (when present) Min. Response Preambles, Max. Device
//              Variables, Configuration Change Counter, Extended Device Status, Manufacturer ID,
//              Private-Label Distributor code, Device Profile -- the richest device-fingerprinting
//              message on the wire, this protocol's analog of BACnet's I-Am / EtherNet/IP's
//              ListIdentity.
//   1          Read Primary Variable -- PV Units(1) + PV(float32).
//   2          Read Loop Current and Percent of Range -- PV Loop Current(float32) + PV % of
//              Range(float32).
//   3          Read Dynamic Variables and Loop Current -- PV Loop Current(float32), then 4x
//              [Units(1) + Value(float32)] for PV/SV/TV/QV.
//   6          Write Polling Address / 7 Read Loop Configuration -- identical response shape,
//              Poll Address(1, masked 0x3F) + Loop Current Mode(1).
//   8          Read Dynamic Variable Classifications -- 4 raw class bytes, PV/SV/TV/QV.
//   9          Read Device Variables with Status -- Extended Device Status(1), then 1-8 slots of
//              [Device Variable code(1) + Classification(1) + Units(1) + Value(float32) + Device
//              Variable Status(1)], then a trailing 4-byte HART-format timestamp (raw units of
//              1/32 ms; ms=t%1000, t/=1000, sec=t%60, t/=60, min=t%60, hr=t/60).
//   12         Read Message / 17 Write Message -- 24-byte packed-ASCII Message field (32 chars).
//   13         Read Tag, Descriptor, Date / 18 Write Tag, Descriptor, Date -- Tag(6-byte packed-
//              ASCII, 8 chars) + Descriptor(12-byte packed-ASCII, 16 chars) + Date(Day/Month/Year,
//              1 byte each).
//   14         Read Primary Variable Transducer Information -- 3-byte Transducer S/N + Limit
//              Units(1) + Upper/Lower Limit(float32 each) + Minimum Span(float32).
//   15         Read Device Information -- PV Alarm Selection, PV Transfer Function, Range Units,
//              Upper/Lower Range(float32), Damping(float32), Write Protect, Reserved, PV Analog
//              Channel Flags.
//   16         Read Final Assembly Number / 19 Write Final Assembly Number -- 3-byte raw number.
//   20         Read Long Tag / 22 Write Long Tag -- 32-byte plain (unpacked) ASCII Long Tag.
//   31         Extended-command-number wrapper -- a 2-byte big-endian Extended Command Number
//              (this field name IS present in Wireshark's own source, unlike a name for command
//              31 as a whole, which this decoder deliberately does NOT assert -- research across
//              FieldComm Group's own material and a dozen vendor HART command references found no
//              authoritative name for command 31 itself, and one source's own description of the
//              Universal/Common-Practice command ranges explicitly excludes 31 from both,
//              suggesting a name was never worth guessing at here). When the extended command
//              number is 64386 (0xFB82), the remaining data is further decoded as command 203
//              (below) -- this specific pairing IS directly confirmed in Wireshark's own source.
//   33         Read Device Variables -- up to 4 slots of [Device Variable code(1) + Units(1) +
//              Value(float32)].
//   38         Reset Configuration Changed Flag -- Configuration Change Counter(uint16) in the
//              response.
//   48         Read Additional Device Status -- 6-byte raw Device-Specific Status, then (when
//              present) Extended Device Status(1), Device Operating Mode(1), Standardized Status
//              0-3(1 each, opaque -- no bit table sourced with confidence, see Device Status
//              above for the one byte this decoder DOES have a sourced table for), Analog Channel
//              Saturated(1)/Fixed(1) (both opaque).
//   203        Read Discrete Variables (with Status) -- structurally decoded (Index of First
//              Discrete Variable(uint16), Number of Discrete Variables(1), Extended Device
//              Status(1), a HART-format timestamp(4), then 1-6 slots of [Discrete Variable
//              State(uint16) + Status(1)]) but, like 31, this decoder deliberately does NOT
//              assert an authoritative NAME for command 203 as a standalone top-level command --
//              every source consulted places numbers >=128 in HART's Device-Specific (i.e.
//              vendor-defined-per-device) range, which by the protocol's own design has no single
//              FieldComm Group name; Wireshark's own dissector decodes this exact shape (strongly
//              suggesting it's a common, if not universal, vendor convention), so this decoder
//              decodes the STRUCTURE with the same confidence Wireshark's own source implies,
//              while being honest that "203" itself is not a name this decoder can vouch for
//              across every device that might emit it.
//
// Explicitly out of scope (deliberately not value-decoded, named only, raw hex shown): commands
// 77 (an I/O-card/channel embedded-command RELAY used by HART multiplexers -- recursively wraps
// another, arbitrary command's own request/response) and 178 (a BATCH/aggregate command that
// recursively wraps up to several other commands' results in one message) -- both are the same
// "nested/nested-command" complexity this codebase already declines elsewhere (BACnet's
// ReadPropertyMultiple/WritePropertyMultiple, EtherNet/IP's structured/UDT CIP types), named via
// the command-number-is-known label but shown only as raw hex. Every command number outside this
// file's dispatch table entirely is likewise named as "command N" (no further name asserted) and
// shown as raw hex.
//
// Validation: see this file's own real-capture search record in tests/real_captures/hartip/
// ATTRIBUTION.md (if present) or this decoder's own Validation paragraph in hartip.cpp for the
// current state of that search.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The IANA-registered HART-IP port (both TCP and UDP) -- recorded as an "expected port"
// annotation only, never a detection gate (this decoder's own structural detection gate is
// port-independent -- see hartip.hpp's file header comment).
constexpr uint16_t HARTIP_PORT = 5094;

// One decoded Pass-Through (tunneled classic-HART) message -- see hartip.hpp's file header
// comment's Pass-Through section for the full byte layout and command dispatch scope.
struct HartIpPassThrough {
    size_t preamble_count = 0;

    uint8_t delimiter = 0;
    uint8_t frame_type = 0;  // 1=BACK, 2=STX, 6=ACK (bits 0-2 of delimiter)
    std::string frame_type_name;
    bool is_response = false;  // true for ACK/BACK, false for STX
    uint8_t physical_layer_type = 0;
    std::string physical_layer_type_name;
    uint8_t expansion_byte_count = 0;  // 0-3
    bool is_long_address = false;      // delimiter bit 7

    uint8_t short_address = 0;      // masked 0x3F -- meaningful only when !is_long_address
    std::string long_address_hex;   // 5 raw bytes as hex -- meaningful only when is_long_address
    std::string expansion_bytes_hex;  // empty when expansion_byte_count == 0

    uint8_t command = 0;
    uint8_t byte_count = 0;  // the wire's own Byte Count field

    // Present only when is_response.
    uint8_t response_code = 0;
    bool response_is_comm_error = false;  // response_code's own bit 7
    std::string response_code_name;       // empty when not one of the single-definition codes
    std::vector<std::string> comm_error_flags;  // set only when response_is_comm_error
    uint8_t device_status = 0;
    std::vector<std::string> device_status_flags;

    // Command-specific data decode -- see hartip.hpp's "Command dispatch" section for exactly
    // which command numbers this decoder value-decodes.
    bool command_recognized = false;  // true if this decoder knows command's byte layout
    std::string command_name;         // best-effort name; empty for commands 31/203 (see header)
    std::vector<std::string> values;  // one entry per decoded field, e.g. "pv=(Real) 72.500000"
    bool data_shown_as_hex = false;   // true when values is empty but there IS data to show
    std::string data_hex;
    size_t data_length = 0;

    uint8_t checksum = 0;  // never verified -- see file header comment

    std::string summary;
    std::vector<std::string> notes;
};

// One decoded Session Initiate body (MessageID 0) -- see hartip.hpp's file header comment.
struct HartIpSessionInit {
    uint8_t host_type = 0;
    std::string host_type_name;
    uint32_t inactivity_close_timer = 0;
};

// One decoded HART-IP message -- see hartip.hpp's file header comment.
struct HartIpFrame {
    uint8_t version = 0;
    uint8_t message_type = 0;
    std::string message_type_name;
    uint8_t message_id = 0;
    std::string message_id_name;
    uint8_t status = 0;
    uint16_t transaction_id = 0;
    uint16_t msg_length = 0;  // this message's own declared total length, header included

    bool has_session_init = false;  // MessageID 0 with a structurally valid 5-byte body
    HartIpSessionInit session_init;

    bool has_error = false;  // MessageType 3 or 15, with a structurally valid 1-byte body
    uint8_t error_code = 0;
    std::string error_code_name;

    bool has_pass_through = false;  // MessageID 3 (covers Request/Response/Publish alike)
    HartIpPassThrough pass_through;

    // The full wire length of this one message (== msg_length when it was trustworthy, else
    // clamped to the bytes actually available) -- lets a caller find where the next message, if
    // any, starts in the same payload (mirroring EnipFrame::wire_length's own role for
    // EtherNet/IP's own coalesced-messages handling).
    size_t wire_length = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns this message's own declared total length (MsgLength, offset 6-7, big-endian) when the
// first 8 bytes structurally look like a HART-IP header (see try_parse_hartip's "structural
// detection gate"), for TCP stream reassembly purposes -- mirrors enip_declared_length. Returns
// std::nullopt when there aren't even 8 bytes, or the two-byte MessageType/MessageID check fails.
std::optional<size_t> hartip_declared_length(ByteSpan payload);

// Attempts to interpret `payload` (TCP or UDP application-layer bytes) as one HART-IP message.
// Returns std::nullopt (never throws) when there aren't even 8 bytes for the header, when
// MessageType isn't one of the 5 values {0,1,2,3,15}, when MessageID isn't one of the 4 values
// {0,1,2,3}, or when MsgLength is implausibly small (< 8) -- see this file's header comment's
// "structural detection gate" paragraph.
std::optional<HartIpFrame> try_parse_hartip(ByteSpan payload);

}  // namespace conduitscope
