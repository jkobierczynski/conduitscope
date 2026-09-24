// SPDX-License-Identifier: Apache-2.0
// ge_srtp.hpp - GE SRTP (Service Request Transport Protocol) decoding, TCP port 18245.
//
// GE SRTP is GE Fanuc/GE Intelligent Platforms' own proprietary PLC communication protocol --
// spoken by the 90-30, 90-70, RX3i, and RX7i PLC families (and, per this decoder's own sourcing,
// FANUC robot controllers that reuse the same transport). It has NEVER been publicly documented by
// GE itself -- every byte-level detail below comes from independent reverse-engineering, not a
// vendor manual, so this decoder is honest about what's verified vs. inferred throughout.
//
// NAMING COLLISION, ADDRESSED DELIBERATELY: "SRTP" is also the well-known Secure Real-time
// Transport Protocol (RFC 3711, media encryption for VoIP/WebRTC) -- a completely unrelated
// protocol. This decoder is named ge_srtp.hpp/GeSrtp* throughout (never bare "srtp"), id() ==
// "ge-srtp" (never "srtp"), specifically so it can never be confused with -- or collide in any
// registry/filter/CLI-flag namespace with -- a hypothetical future real-SRTP decoder. This codebase
// has no real-SRTP support of any kind today (confirmed by search before writing this file).
//
// SOURCING -- four independent sources, all mutually corroborating on every overlapping byte
// field (this project's own two-source bar, exceeded here the same way ICCP/TASE.2's was):
//   1. A Wireshark Lua dissector (Palatis/packet-ge-srtp) -- the primary structural reference.
//   2. An independent from-scratch Python reimplementation (TheMadHatt3r/ge-ethernet-SRTP),
//      written and field-tested (per its own README) against real GE 90/30 and 90/70 PLCs.
//   3. Denton, Karpisek, Breitinger, Baggili, "Leveraging the SRTP protocol for over-the-network
//      memory acquisition of a GE Fanuc Series 90-30", Digital Investigation 22 (2017) S26-S38
//      (DFRWS 2017) -- a peer-reviewed academic paper with its own byte-offset tables (this
//      decoder's Table 2/Table 3 service-request-code and segment-selector vocabularies come
//      directly from it) and real captured hex dumps.
//   4. automayt/ICS-pcap's own GE-SRTP/Notes.txt -- a protocol-fingerprint note (no capture file
//      accompanies it; per this decoder's own research, no public GE SRTP pcap sample exists
//      anywhere, which is exactly why this decoder's own fixture, tools/make_sample_pcap.py's
//      build_ge_srtp_sample(), is synthetic -- see docs/PROTOCOL_COVERAGE.md's own honestly-stated
//      validation-gap paragraph for this protocol). Corroborates the port (see "PORT" below) and
//      supplies a real captured INIT_ACK response: `\x01\x00...\x0f\x00...` (56 bytes, all zero
//      except byte 0 = 0x01 and byte 8 = 0x0f) -- confirms Packet Type 1 == INIT_ACK, and byte 8
//      being genuinely non-zero here is exactly why this decoder does NOT assume INIT_ACK's own
//      body past byte 0 is all-zero or otherwise guess at its meaning (see "EXPLICITLY OUT OF
//      SCOPE" below).
//
// PORT: GE_SRTP_PORT = 18245 -- confirmed by three of the four sources above (the Lua dissector's
// own DEFAULT_GESRTP_PORT, the DFRWS paper's own tool screenshot, and automayt/ICS-pcap's own
// Notes.txt, which also names a secondary port 18246 -- not this decoder's own tcp_port() default,
// but reachable via --ge-srtp-port 18246 the same way any other protocol's own secondary port is).
//
// STRUCTURAL DETECTION GATE, AND WHY THIS IS GateKind::TcpPort (PORT-GATED IN AUTO MODE), NOT
// TcpPortIndependent: unlike Modbus's protocol-id==0 tell or MELSEC's exact 2-byte subheader
// magic, GE SRTP's 56-byte fixed header has no reserved magic-constant field at all -- every byte
// is either a small enumerated value (Packet Type, Message Type) or genuinely free-form
// (sequence number, mailbox addresses, time fields). The strongest available signal is Message
// Type (byte 31) landing on one of 5 known values (0xc0/0xd4/0xd1/0x80/0x94) out of 256, combined
// with Packet Type (bytes 0-1, little-endian) landing on one of {0,1,2,3,8} out of 65536 -- a real
// gate, but nowhere near SMB's/OPC UA's/BGP's own magic-byte strength, so (like WinRM/DCOM before
// it, see winrm.hpp/dcom.hpp's own file header comments) this decoder is deliberately port-gated
// in Auto mode rather than tried opportunistically on every TCP payload; an explicit
// `--protocol ge-srtp` still tries it port-independently, the same exception every other
// GateKind::TcpPort protocol here already has.
//
// THE ONE GENUINELY STRONG SUB-CASE: the connection-initiation INIT message is exactly 56 bytes,
// ALL OF THEM ZERO (GE_SRTP_Messages.py's own INIT_MSG = bytearray(56)) -- this decoder recognizes
// that shape specifically (is_init below) as a much stronger structural match than the general
// case, since 56 all-zero bytes landing on GE SRTP's own conventional port is a highly specific
// coincidence to rule out.
//
// WIRE FORMAT -- the fixed 56-byte header, present on every message, request and response alike
// (byte offsets as verified across all three sources above):
//   0-1   Packet Type (u16 LE): 0=INIT (the connection-initiation handshake, see above; only ever
//         actually 0 as part of the all-zero INIT message -- this decoder does not otherwise treat
//         a bare 0 as meaningful), 1=INIT_ACK (the PLC's own response to INIT -- per the Python
//         client's own initConnection, byte 0 of a valid INIT_ACK is 1; this decoder recognizes
//         the shape structurally only, its own body past byte 0 is not independently verified by
//         any of the three sources), 2=REQ, 3=REQ_ACK, 8=UNKNOWN (named exactly that by the Lua
//         dissector's own svc_type_str -- recognized structurally, never decoded further).
//   2-3   Sequence Number (u16 LE) -- repeated verbatim at byte 30 (low byte only there, see
//         below). UNLIKE MELSEC (melsec.hpp), which has no per-message transaction ID at all, this
//         genuinely is one: the Python client's own comment states the slave copies it into its
//         ack/error response, so this decoder uses it as an AUTHORITATIVE request/response pairing
//         key (GeSrtpFlowState below), the same "real wire-carried transaction ID" tier
//         Modbus's/TwinCAT's own pairing already established -- not MELSEC's/FINS's own weaker
//         "most recent outstanding request" heuristic, which exists only because those two
//         protocols have no such ID to key by.
//   4-5   Text Length (u16 LE) -- decoded and shown, not otherwise validated or cross-checked
//         against the payload (no source establishes a hard relationship to bytes actually
//         present, unlike MELSEC's own Request/Response Data Length field).
//   6-25  20 bytes reserved/unknown -- not decoded (all three sources agree these are typically
//         zero in practice, with a couple of fixed non-zero bytes in the Python client's own
//         BASE_MSG template at offsets 9 and 17, whose meaning is not established by any source).
//   26    Time, seconds. 27 Time, minutes. 28 Time, hours. 29 reserved.
//   30    Msg Seq # -- the low byte of the Sequence Number above, repeated. Decoded and shown but
//         NOT independently used for pairing (the full 16-bit Sequence Number at bytes 2-3 already
//         is, and is strictly more information).
//   31    Message Type (u8): 0xc0=SHORT (request), 0xd4=SHORT_ACK (response, success), 0xd1=
//         SHORT_ERR (response, "Error Nack Mailbox message" per the SNP spec reference the DFRWS
//         paper cites -- the request was rejected), 0x80=EXTENDED (request), 0x94=EXTENDED_ACK
//         (response). This is the primary discriminator for which of the two body shapes below
//         applies -- NOT Packet Type (REQ/REQ_ACK at bytes 0-1 track direction at a coarser level
//         and are shown for completeness, but Message Type alone decides the parse).
//   32-35 Mailbox Source (u32 LE). 36-39 Mailbox Destination (u32 LE). Decoded and shown, not
//         otherwise interpreted (no source establishes what these route to beyond "mailbox").
//   40    Packet #. 41 Total Packet #. Multi-packet responses (Total Packet # > 1) are named but
//         NOT reassembled across packets -- see "EXPLICITLY OUT OF SCOPE" below, matching the Lua
//         dissector's own documented limitation ("no support for multi-packet response message").
//
// BODY, SHORT/SHORT_ACK/SHORT_ERR (bytes 42-55, 14 bytes, no bytes beyond 56 -- this shape is
// always exactly 56 bytes total):
//   Request (Message Type 0xc0): 42 Service Request Code (see table below); 43 Segment Selector
//   (memory-type+access-width selector, see table below); 44-45 Target Index (u16 LE, the 0-based
//   "address - 1" -- e.g. requesting %R40 puts 39 here, per the Python client's own `address - 1`
//   comment); 46-47 Target Count (u16 LE, unit depends on the selector -- bit/byte/word); 48-53 six
//   bytes of inline payload (a small Write's own data fits here directly, no separate framing);
//   54-55 two bytes trailing, not independently verified by any source, decoded as raw hex only.
//   Response (Message Type 0xd4 or 0xd1): 42 Status Code (major -- 0 = no error); 43 Status Code
//   Minor; 44-49 six bytes of Return Data (a small Read's own result fits here directly -- the
//   Python client's own fastDecodeResponseMessage only reads the first 2 of these 6 bytes as its
//   own register_result, calling out in its own comment that this is dangerously narrow for
//   anything wider than one word; this decoder decodes all 6 as raw hex, not just the first 2); 50
//   Control Program Number (0xff = not logged in to a program task, 0x00 = logged in -- per the
//   DFRWS paper); 51 Current Privilege Level; 52-53 Last Sweep Time (u16 LE, microseconds to
//   execute the program task); 54-55 PLC Status word (u16 LE bitfield -- e.g. bit 2 = I/O fault
//   table changed since last read, per the DFRWS paper; decoded and shown as raw hex only, no
//   per-bit decode -- the paper documents this one bit's meaning, not the whole word's).
//
// BODY, EXTENDED REQUEST (bytes 42-55, then whatever trailing bytes are already present in the
// same TCP payload -- see "DECLARED LENGTH" below for why those trailing bytes are NOT
// cross-segment reassembled): 42-47 six bytes unknown, not independently verified by any source;
// 48 Packet # (repeat of byte 40); 49 Total Packet # (repeat of byte 41); 50 Service Request Code;
// 51 Segment Selector; 52-53 Target Index; 54-55 Target Count -- same meanings as the SHORT
// request's own byte 42-47, just shifted 8 bytes later to make room for the unknown prefix. There
// is no inline payload in the fixed 56 bytes here (unlike SHORT) -- any actual bulk data (a Read
// wider than 6 bytes, or a Write wider than 6 bytes) rides as trailing bytes AFTER byte 56, per the
// Lua dissector's own `if (buf_len > 56) then prot_tree:add(fields.payload, buf(56, pkt_len - res))
// end`. This decoder reports the trailing byte count and its own raw hex, structurally, without
// attempting to further interpret it against Target Count's own unit (no source establishes enough
// of the framing to do that safely) -- named "extended_trailing_payload" below, honestly, not
// silently dropped.
//
// BODY, EXTENDED_ACK -- DELIBERATELY NOT DECODED PAST THE COMMON HEADER: none of this decoder's
// three sources shows a worked EXTENDED_ACK example, so whether its own response body repeats
// EXTENDED request's own 8-byte "6 unknown + Packet#/Total Packet# repeated" prefix before a
// SHORT_ACK-shaped status/return-data body, or omits that prefix and starts the status shape
// directly at byte 42 (the way SHORT_ACK does), is genuinely UNVERIFIED. Rather than guess either
// layout, this decoder recognizes EXTENDED_ACK structurally (Message Type 0x94 alone) and reports
// everything from byte 42 onward as an honest, undecoded hex blob (GeSrtpFrame::undecoded_body_hex
// below) -- the same "declared gap, not silent guess" posture this file takes throughout.
//
// DECLARED LENGTH / TCP REASSEMBLY SCOPE: ge_srtp_declared_length (ge_srtp.cpp) declares a fixed 56
// for every shape EXCEPT an EXTENDED REQUEST (Message Type 0x80) -- INIT/INIT_ACK/UNKNOWN/SHORT/
// SHORT_ACK/SHORT_ERR/EXTENDED_ACK all get this codebase's usual cross-TCP-segment reassembly
// (Decoder::reassemble_tcp_payload) if a 56-byte message happens to be split across two segments.
// For an EXTENDED REQUEST specifically, this function returns std::nullopt -- no source establishes
// a reliable field anywhere in the fixed header that states the trailing payload's own total byte
// count (Target Count's unit depends on the selector and is not, on its own, a verified byte-length
// promise), so this decoder does NOT attempt to reassemble an EXTENDED request split across TCP
// segments; it is only recognized when the whole message (56-byte header plus trailing payload)
// already arrived together in one TCP payload, which is decode()'s own direct, no-declared-length
// path (the overwhelmingly common real-world case for a LAN-local PLC conduit). A DOCUMENTED SCOPE
// LIMITATION, not silent data loss -- matching this codebase's own "declared gap over silent gap"
// posture (see HART-IP's own Session-Initiate-over-TCP collision, hartip.hpp, for the precedent).
// EXTENDED_ACK is deliberately declared as a fixed 56 like every other shape, even though its own
// body past byte 42 is undecoded (see "BODY, EXTENDED_ACK" above) -- an earlier version of this
// function also returned nullopt for EXTENDED_ACK, which left `declared` unset at this decoder's
// own decoder.cpp call site and let a weaker, still-opportunistic later gate in that same cascade
// (COTP/TPKT's own version==3/reserved==0 check -- GE SRTP's own Packet Type 3, REQ_ACK, happens to
// supply TPKT's version byte by coincidence) hijack a real EXTENDED_ACK response and corrupt the
// rest of that TCP flow's own reassembly state -- a real, reproducible collision found while
// building this decoder's own fixture, fixed by declaring the ordinary fixed 56 instead.
//
// TWO-PHASE DECLARATION -- ANOTHER FIX FROM THE SAME COLLISION FAMILY: ge_srtp_declared_length only
// needs Packet Type (2 bytes) to already be one of {0,1,2,3,8} before it commits to declaring 56 --
// it does NOT wait for enough bytes to also read Message Type (byte 31) first. This matters because
// decoder.cpp's own reassembly cascade (Decoder::reassemble_tcp_payload) recomputes this function
// fresh, against the whole accumulated candidate, on every new TCP segment for a flow -- so on a
// real GE SRTP message's own FIRST segment, if that segment happens to be shorter than 32 bytes
// (not yet enough to read Message Type), returning std::nullopt would leave `declared` unset on
// THAT call and let the same weaker COTP/TPKT gate above hijack the flow before GE SRTP ever gets a
// second chance -- this decoder's own fixture reproduces exactly this shape too (a SHORT response
// deliberately split right at that boundary). The stronger Message-Type-based check (including the
// EXTENDED-request nullopt above) still runs, and can still change the answer, once a full 56 bytes
// have actually accumulated across segments -- this two-phase behavior only ever widens what gets
// tentatively claimed for GE SRTP's own reassembly early, never what ultimately gets decoded.
//
// SERVICE REQUEST CODES (byte 42 of a SHORT request / byte 50 of an EXTENDED request) -- from the
// DFRWS paper's own Table 2, cross-matched against the Lua dissector's svc_type_str and the Python
// client's own SERVICE_REQUEST_CODE dict (the Python dict only names 10 of these 20; every value
// below is still independently confirmed by at least the Lua dissector and the DFRWS paper):
//   0x00 PLC short status request        0x03 return control program names
//   0x04 read system memory              0x05 read task memory
//   0x06 read program memory             0x07 write system memory
//   0x08 write task memory               0x09 write program block memory
//   0x20 programmer logon                0x21 change PLC CPU privilege level
//   0x22 set control ID (CPU ID)         0x23 set PLC (run vs. stop)
//   0x24 set PLC time/date               0x25 get PLC time/date
//   0x38 get fault table                 0x39 clear fault table
//   0x3f program store (upload from PLC) 0x40 program load (download to PLC)
//   0x43 get controller type and id information
//   0x44 toggle force system memory
// Any other value: shown numerically only ("Unknown service request code 0xNN"), never guessed at
// -- the same "never guess" posture MELSEC's own command table takes.
//
// SEGMENT SELECTORS (byte 43 of a SHORT request / byte 51 of an EXTENDED request) -- memory type
// plus access width, from the DFRWS paper's own Table 3, cross-matched against the Lua dissector's
// selector_type_str:
//   %I  Discrete Inputs:     bit=0x46 byte=0x10        %Q  Discrete Outputs:    bit=0x48 byte=0x12
//   %M  Discrete Internals:  bit=0x4c byte=0x16         %T  Discrete Temporaries:bit=0x4a byte=0x14
//   %SA:                     bit=0x4e byte=0x18         %SB:                    bit=0x50 byte=0x1a
//   %SC:                     bit=0x52 byte=0x1c         %S:                     bit=0x54 byte=0x1e
//   %G  Genius Global Data:  bit=0x56 byte=0x38
//   %AI Analog Inputs (word-only): 0x0a    %AQ Analog Outputs (word-only): 0x0c
//   %R  Registers (word-only):     0x08
// Any other value: shown numerically only ("Unknown segment selector 0xNN"), never guessed at.
// `target_text` combines the resolved memory-area name with the 1-based PLC address (target_index
// + 1, undoing the wire's own 0-based "address - 1" encoding) -- e.g. "%R40" -- the direct GE SRTP
// analogue of MelsecDeviceSpec::device_text (melsec.hpp).
//
// SESSION-SCOPED REQUEST/RESPONSE PAIRING (GeSrtpFlowState, this file, below): keyed by Sequence
// Number (bytes 2-3), AUTHORITATIVE (a genuine wire-carried transaction ID, unlike MELSEC's/FINS's
// own single-outstanding-slot heuristic) -- the same "real ID, real map" tier
// Modbus's/TwinCAT's own pairing already established. A response's own body (status code, return
// data) is always decoded regardless of whether it matches a pending request; matching additionally
// unlocks rendering the ORIGINAL request's own service-request-name/target_text alongside the
// response, since (like MELSEC) a GE SRTP response carries no service-request-code field of its
// own on the wire.
//
// SECURITY CONTEXT (curated notes, see ge_srtp.cpp's decode_payload) -- the DFRWS 2017 paper's own
// field finding, from real GE Fanuc Series 90-30 deployments its authors examined: this protocol
// commonly runs with NO AUTHENTICATION CONFIGURED AT ALL. Privilege levels exist on the wire (byte
// 51 of a response, up to 4 levels, an up-to-8-digit ASCII password per the paper) but the paper's
// own text states they are "rarely activated" in practice -- so a network-reachable client can
// commonly start/stop PLC program execution (Service Request 0x23), upload or download program
// code (0x3f/0x40), or read/write arbitrary PLC memory (0x04-0x09) with zero credentials. This
// decoder surfaces that as a curated note on the relevant service-request codes, the same
// "legitimate protocol design property, not necessarily evidence of an active attack" framing
// MELSEC's own Remote RUN/STOP notes and DRSUAPI's own DRSGetNCChanges/DCSync note already use --
// never a decoded password value (this decoder does not know Programmer Logon's own payload byte
// layout well enough to safely decode one at all, so it isn't attempted; see "EXPLICITLY OUT OF
// SCOPE" below).
//
// EXPLICITLY OUT OF SCOPE (named, not silently skipped): the legacy libopensrtp C implementation
// and the FANUC-robot-specific RobotInterface/RobotIntelface clients (both named in the Lua
// dissector's own References section) were not independently read for this pass -- everything
// above rests on the three sources this file's header already names; multi-packet response
// reassembly (Total Packet # > 1, named but not stitched together -- the Lua dissector's own
// documented limitation too); SNPX (the Lua dissector's own "they're text, anyway" reasoning for
// skipping it, not independently investigated here either); Programmer Logon's (0x20) own payload
// byte layout, including any password field -- not decoded at all, only the service request itself
// is named, precisely BECAUSE no source here establishes its layout well enough to safely redact a
// value that might be in it (unlike MELSEC's own Remote Password field, whose 2-byte-length-prefix
// shape IS independently verified); the EXTENDED-family trailing payload's own further
// interpretation against Target Count's unit (see "BODY, EXTENDED/EXTENDED_ACK" above); and
// INIT_ACK's own body past byte 0 (recognized structurally only, see "WIRE FORMAT" above).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t GE_SRTP_PORT = 18245;

// One resolved memory-area target (SHORT/EXTENDED read or write requests only) -- the GE SRTP
// analogue of MelsecDeviceSpec (melsec.hpp). `target_text` is always set to the conventional
// human-readable rendering (e.g. "%R40") -- an unrecognized selector still renders as
// "0xNN:<index>" rather than being dropped, the same "never drop, name what's unrecognized"
// posture MELSEC's own format_device_text already establishes.
struct GeSrtpTarget {
    uint8_t segment_selector = 0;
    bool selector_recognized = false;
    uint16_t target_index = 0;   // raw wire value (0-based, "address - 1")
    uint16_t target_count = 0;
    std::string target_text;     // e.g. "%R40", or "0x7F:39" if the selector is unrecognized
};

struct GeSrtpFrame {
    uint16_t packet_type = 0;
    std::string packet_type_name;  // "INIT", "INIT_ACK", "REQ", "REQ_ACK", "UNKNOWN", or
                                    // "Unrecognized packet type 0xNNNN"
    bool is_init = false;          // true only for the all-zero 56-byte INIT handshake message

    uint16_t sequence_number = 0;
    uint16_t text_length = 0;
    uint8_t time_seconds = 0, time_minutes = 0, time_hours = 0;
    uint8_t msg_seq = 0;  // byte 30 -- low byte of sequence_number, repeated on the wire

    uint8_t message_type_raw = 0;
    std::string message_type_name;  // "SHORT request", "SHORT_ACK response", "SHORT_ERR response
                                     // (Nack)", "EXTENDED request", "EXTENDED_ACK response", or
                                     // "Unrecognized message type 0xNN"
    bool is_response = false;
    bool is_error = false;      // SHORT_ERR only
    bool is_extended = false;   // EXTENDED/EXTENDED_ACK, as opposed to SHORT/SHORT_ACK/SHORT_ERR

    uint32_t mailbox_source = 0;
    uint32_t mailbox_dest = 0;
    uint8_t packet_num = 0;
    uint8_t total_packet_num = 0;

    // Request-only (SHORT and EXTENDED both carry these, at different byte offsets -- see this
    // file's header comment). On a RESPONSE, these are populated only once matched to the
    // request that carried them (see GeSrtpFlowState below) -- has_service_request stays false on
    // an unmatched response, the same "matched context, not guessed" posture MELSEC's own
    // has_command uses for its own response side.
    bool has_service_request = false;
    uint8_t service_request_code = 0;
    std::string service_request_name;  // "Unknown service request code 0xNN" when unrecognized
    bool service_request_recognized = false;
    bool has_target = false;
    GeSrtpTarget target;

    // SHORT request only: the 6-byte inline payload (bytes 48-53), raw hex -- a Write's own small
    // value fits here directly. Empty for every other shape.
    std::string inline_payload_hex;

    // EXTENDED/EXTENDED_ACK only: whatever bytes are already present in this same TCP payload past
    // byte 56 -- see this file's header comment's "DECLARED LENGTH" section for why this is never
    // cross-segment reassembled. Empty (and has_extended_trailing_payload false) when no such bytes
    // are present in this payload.
    bool has_extended_trailing_payload = false;
    size_t extended_trailing_payload_byte_count = 0;
    std::string extended_trailing_payload_hex;

    // Response-only (SHORT_ACK/SHORT_ERR). EXTENDED_ACK carries the same status/return-data shape
    // at the same byte offsets as SHORT_ACK/SHORT_ERR -- see this file's header comment.
    bool has_status = false;
    uint8_t status_code = 0;
    uint8_t status_code_minor = 0;
    std::string status_code_name;  // "No error" for 0, a named error for a handful of DFRWS-
                                    // documented values, else "Error 0xNN (not independently
                                    // verified against a GE-published error-code appendix)"
    std::string return_data_hex;   // 6 bytes, raw hex (all 6 -- not just the first 2 the Python
                                    // client's own fastDecodeResponseMessage narrowly reads)
    bool has_control_program_number = false;
    uint8_t control_program_number = 0;
    std::string control_program_state;  // "logged in to a program task" / "not logged in to a
                                          // program task" / "unrecognized (0xNN)"
    uint8_t current_privilege_level = 0;
    uint16_t last_sweep_time_us = 0;
    uint16_t plc_status_word = 0;  // raw bitfield, shown as hex -- see file header comment

    // Set for any shape this decoder recognizes structurally (a valid Packet Type/Message Type
    // combination) but does NOT have an independently verified byte layout for past that point --
    // INIT_ACK's own body past byte 0, a bare UNKNOWN (packet type 8) packet, and EXTENDED_ACK
    // specifically (no source used establishes whether its response body repeats EXTENDED's own
    // 8-byte unknown-plus-packet-number prefix before a SHORT_ACK-shaped status/return-data body,
    // or omits it -- see ge_srtp.hpp's file header comment's "BODY, EXTENDED/EXTENDED_ACK"
    // section). Rather than guess either layout, this decoder reports the undecoded bytes
    // honestly, the same "declared gap, not silent guess" posture the rest of this file takes.
    bool has_undecoded_body = false;
    size_t undecoded_body_byte_count = 0;
    std::string undecoded_body_hex;

    // Set once this response was matched to its own request via GeSrtpFlowState (Sequence Number,
    // AUTHORITATIVE -- see file header comment). Unset on a request, and on a response with no
    // matching pending request found on this session (a genuinely orphan response, or a capture
    // that starts mid-session).
    bool matched_to_request = false;
    size_t matched_request_packet_index = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns the canonical name for a recognized service request code (e.g. "read system memory"),
// or std::nullopt if the code isn't one of the 20 values this decoder's own file header table
// covers -- never guessed at.
std::optional<std::string> ge_srtp_service_request_name(uint8_t code);

// Attempts to interpret `payload` as one GE SRTP message (INIT, INIT_ACK, SHORT/SHORT_ACK/
// SHORT_ERR request or response, EXTENDED/EXTENDED_ACK request or response, or a structurally-
// recognized-but-unparsed UNKNOWN packet type). Returns std::nullopt (never throws) if the
// structural detection gate (see this file's header comment) isn't satisfied. Context-free, like
// try_parse_melsec: a request is always fully decoded (its own service request code is right there
// on the wire); a response's own service-request context is only filled in once matched to its
// request by GeSrtpTcpDecoder::decode (ge_srtp.cpp), via GeSrtpFlowState below.
std::optional<GeSrtpFrame> try_parse_ge_srtp(ByteSpan payload);

// One outstanding GE SRTP request, tracked per TCP session, keyed by Sequence Number -- see this
// file's header comment's "SESSION-SCOPED REQUEST/RESPONSE PAIRING" section for why this is a real
// map (unordered_map, like ModbusFlowState/TwinCatFlowState's own transaction-ID/Invoke-ID
// pairing), not MELSEC's/FINS's own single std::optional slot.
struct GeSrtpPendingRequest {
    uint8_t service_request_code = 0;
    std::string service_request_name;
    bool has_target = false;
    GeSrtpTarget target;
    size_t packet_index = 0;
};

class GeSrtpFlowState : public DecoderFlowState {
public:
    std::unordered_map<uint16_t, GeSrtpPendingRequest> pending;
};

// Returns the total on-the-wire byte count one GE SRTP message declares, once there are enough
// bytes to classify its own shape -- mirrors melsec_declared_length's role in decoder.cpp's generic
// TCP reassembly cascade, reached here through GeSrtpTcpDecoder::tcp_declared_length. Returns 56
// for every shape except an EXTENDED REQUEST, for which it returns std::nullopt -- see this file's
// header comment's "DECLARED LENGTH" section for why (including why EXTENDED_ACK is NOT also
// nullopt, unlike an earlier version of this function).
std::optional<size_t> ge_srtp_declared_length(ByteSpan payload);

// GE SRTP over TCP/18245 -- id()=="ge-srtp" (never bare "srtp", see this file's header comment),
// GateKind::TcpPort (port-gated in Auto mode, joining DoH/WinRM/DCOM on that same gate -- see this
// file's header comment's "STRUCTURAL DETECTION GATE" section). Session-scoped state
// (GeSrtpFlowState) for authoritative Sequence-Number-based request/response pairing.
class GeSrtpTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "ge-srtp"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return GE_SRTP_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return ge_srtp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& ge_srtp_tcp_decoder();

}  // namespace conduitscope
