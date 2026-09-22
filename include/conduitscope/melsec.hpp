// SPDX-License-Identifier: Apache-2.0
// melsec.hpp - Mitsubishi Electric MC Protocol / SLMP (MELSEC Communication Protocol) decoding,
// over TCP and UDP.
//
// A brand-new protocol (not a migration), built entirely on the ProtocolDecoder interface from the
// start -- see twincat.hpp's own file header for why that's notable (no DecodedPacket flat fields of
// its own). MELSEC is the first protocol on this interface with a genuine dual TCP+UDP transport
// built from scratch (TwinCAT is TCP-only; Kerberos's own TCP+UDP split shares the same "two
// instances, one id()" pattern reused here -- see MelsecTcpDecoder/MelsecUdpDecoder below).
//
// MC Protocol (MELSEC's own vendor name) / SLMP (Mitsubishi's newer, protocol-neutral name for the
// same wire format) is Mitsubishi Electric's PLC communication protocol -- the direct Mitsubishi
// analogue of Modbus/S7comm: a client reads/writes PLC device memory (inputs, outputs, internal
// relays, data registers, timers, counters) and can remotely RUN/STOP/PAUSE/RESET the CPU, all
// normally with no protocol-level authentication.
//
// Every byte-level structure below was verified two ways: (1) against Mitsubishi's own official SLMP
// Reference Manual and second-source vendor manuals (Kepware/PTC's and Pro-face's own Mitsubishi
// Ethernet driver manuals), and (2) empirically, against pymcprotocol (a small, actively maintained
// pure-Python MC protocol client) read directly during planning -- this caught a real discrepancy in
// one fetched source (wrong subheader size, wrong command/subcommand field width, wrong device code
// for D). See /root/.claude/plans/peppy-wandering-minsky.md (this feature's implementation plan) for
// the full two-way verification writeup.
//
// FRAMING SCOPE, THIS PASS: 3E and 4E frame, BINARY mode only. ASCII-mode framing (every field
// re-encoded as hex-digit ASCII text) and the legacy 1E frame (no network/PC-number addressing,
// older PLCs) are explicitly out of scope -- named but not decoded. Binary 3E frame is the
// overwhelming majority of real MC-protocol/SLMP traffic; 4E is a small variant (adds a 2-byte
// Serial No. purely for a client to disambiguate its own concurrent requests) sharing the exact same
// body shape.
//
// SUBHEADER (2 bytes, big-endian): 0x5000 = 3E request, 0xD000 = 3E response, 0x5400 = 4E request,
// 0xD400 = 4E response. This decoder's primary structural gate (4 exact 16-bit values out of 65536).
//
// 4E FRAME ONLY: immediately after the subheader, a 2-byte Serial No. (little-endian), the client's
// own disambiguation value -- decoded and shown, but NOT used for cross-packet request/response
// pairing (see "Explicitly out of scope" below -- MELSEC is stateless in this pass, like S7comm).
//
// COMMON HEADER (both 3E and 4E, after the subheader/serial-number): Network No.(1) + PC No.(1,
// "Station No.") + Request Destination Module I/O No.(2, little-endian, conventionally 0x3FF for
// "own station") + Request Destination Module Station No.(1, multidrop, usually 0) -- decoded and
// shown, not otherwise validated.
//
// REQUEST TAIL: Request Data Length(2, little-endian, byte count of everything from Monitoring Timer
// to the end of Request Data) + Monitoring Timer(2, little-endian, 250ms units; 0 = wait
// indefinitely) + Command(2, little-endian) + Subcommand(2, little-endian) + Request Data.
//
// RESPONSE TAIL: Response Data Length(2, little-endian, byte count from End Code to the end of
// Response Data) + End Code(2, little-endian, 0x0000 = success) + Response Data.
//
// STRUCTURAL GATE, PART TWO -- declared-length cross-check: payload.size() must equal exactly
// (bytes before the data-length field) + 2 (the length field itself) + declared_length, where
// declared_length >= 6 for a request (Monitoring Timer 2 + Command 2 + Subcommand 2, the floor even
// for a zero-argument command) and declared_length >= 2 for a response (End Code alone). Combined
// with the subheader magic, this is on par with TwinCAT's/HART-IP's own structural gates.
//
// DEVICE SPECIFICATION (used by every Batch/Random Read/Write command): a device number plus a
// device code identifying which PLC memory area. Two wire shapes, disambiguated by the subcommand
// value itself: subcommand 0x0000/0x0001 ("standard") = device number 3 bytes little-endian binary +
// device code 1 byte; subcommand 0x0002/0x0003 ("extended", iQ-R series) = device number 4 bytes
// little-endian binary + device code 2 bytes little-endian. The device number is a plain
// little-endian binary integer (NOT BCD). Devices conventionally notated in decimal (M, D, L, F, V,
// SM, SD, TS, TC, TN, SS, SC, SN, CS, CC, CN, R, and the iQ-R-only LTS/LTC/LTN/LSTS/LSTC/LSTN/LCS/
// LCC/LCN/RD) vs. hexadecimal (X, Y, B, W, SB, SW, DX, DY, ZR, and iQ-R-only LZ) differ only in how a
// human types/reads the number, never in wire encoding.
//
// BIT-UNITS VALUE PACKING (Batch Read/Write bit units, subcommand 0x0001/0x0003): two bit values are
// packed per byte, the even-indexed value in bit 4, the odd-indexed value in bit 0 of the same byte.
//
// COMMANDS DECODED (all empirically verified against pymcprotocol): Batch Read (0x0401), Batch Write
// (0x1401), Random Read (0x0403), Random Write (0x1402), Remote RUN (0x1001), Remote STOP (0x1002),
// Remote PAUSE (0x1003), Remote LATCH CLEAR (0x1005), Remote RESET (0x1006), Read CPU Type (0x0101),
// Remote Password UNLOCK (0x1630) / LOCK (0x1631) -- password value never rendered, only its length,
// NTLM/Netlogon-style redaction (per Jurgen's own decision) -- and Echo/Loopback Test (0x0619). Any
// other command/subcommand pair is shown numerically only ("Unknown command 0xXXXX/0xXXXX"), never
// guessed at. End Code naming is limited to 0x0000 ("Normal completion") and 0xC059 ("Unsupported
// command", the one error code pymcprotocol's own source names explicitly); every other non-zero
// value is shown as raw hex only.
//
// RESPONSE DECODING NEEDS SESSION CONTEXT -- UNLIKE MODBUS/TWINCAT/S7COMM: a MELSEC response frame
// carries NO command field of its own on the wire at all (just End Code + raw response data) --
// every other protocol in this codebase that fully decodes both request and response shapes (Modbus,
// TwinCAT, S7comm) repeats its function code / Command ID on both sides. So decoding a response's
// own command-specific body (word/bit values, CPU type, echoed data, ...) requires knowing which
// request it answers. try_parse_melsec itself stays context-free (mirrors try_parse_twincat exactly
// -- a response it parses alone is decoded structurally only: End Code + raw byte count). The actual
// command-specific response decode happens in MelsecTcpDecoder::decode/MelsecUdpDecoder::decode
// (melsec.cpp), which track, per TCP/UDP session, the single most recently sent, not-yet-answered
// request's command (see MelsecFlowState below) -- real MC Protocol/SLMP traffic is normally strict
// half-duplex request/response per session (poll-then-reply), so one pending slot (not a map keyed
// by a transaction ID -- 3E frames carry none) covers the overwhelming majority of real traffic. This
// is deliberately lighter-weight than Modbus's/TwinCAT's own AUTHORITATIVE transaction-ID/Invoke-ID
// pairing -- there is no unique per-request ID to match against here (the 4E frame's own Serial No.
// is decoded and shown, but deliberately NOT used for this, see below), so a matched response is
// reported as "matched" rather than "authoritatively paired." A new request arriving before its
// predecessor's response is noted, not silently dropped; an orphan response (no pending request on
// this session) decodes structurally only (End Code + raw byte count), the same honest fallback
// try_parse_melsec alone already uses. Random Read is the one command whose response is otherwise
// genuinely ambiguous even WITH the matching request's command known (the word/dword split is only
// in the request's own device-count bytes) -- MelsecPendingRequest carries those two counts forward
// so a matched Random Read response decodes correctly too; an unmatched one falls back to raw byte
// count, same as any other unmatched response.
//
// EXPLICITLY OUT OF SCOPE (named, not silently skipped): ASCII-mode framing; legacy 1E frame; any
// command/subcommand pair outside the verified set above; Monitor Registration/Execution,
// Multiple-Block Batch Read, Memory Read/Write, Extended Unit Read/Write, and any other MC-protocol
// command family; using the 4E frame's own Serial No. for request/response correlation (decoded and
// shown, but this decoder's session-scoped single-pending-slot tracking above never reads it --
// unlike Modbus's MBAP transaction ID or TwinCAT's Invoke ID, there's no confidence a real client's
// Serial No. values are reliably unique/present the way this pass would need to make it
// authoritative); actual verification of the optional password-lock state's effect on other commands
// (no session-state model of "is this PLC currently locked").
//
// SECURITY CONTEXT (curated notes, see melsec.cpp's decode_payload): (1) No protocol-level
// authentication for CPU control -- Remote RUN/STOP/PAUSE/RESET/LATCH CLEAR require no session
// establishment or credential at the wire-protocol level, the direct MELSEC analogue of S7comm's own
// PLC Stop/PLC Control framing. (2) The optional password-lock mechanism is itself a cleartext ASCII
// field -- even when Remote Password protection is enabled, the Unlock/Lock exchange sends the
// password with zero encryption (value itself redacted in this decoder's own output). (3) Arbitrary
// device memory read/write with no built-in access control -- Batch/Random Read and Write let any
// client reach PLC device memory directly, the same framing Modbus's own file header already
// carries. (4) CPU Type Read is unauthenticated reconnaissance -- reveals PLC hardware/firmware
// family to any network-reachable client. These are legitimate protocol design properties, not
// necessarily evidence of an active attack.
//
// PORTS: MELSEC_TCP_PORT = 5001, MELSEC_UDP_PORT = 5000 -- NOT IANA-registered (Mitsubishi's own
// SLMP Reference Manual does not specify a fixed default). Confirmed across three independent
// sources during planning (Kepware/PTC's and Pro-face's own vendor driver manuals, plus the
// community automayt/ICS-pcap collection's own AdditionalNotes.txt), all of which agree --
// documented honestly as "conventional, not authoritative, always user-configured on the PLC's own
// Ethernet module parameters," the same honesty TwinCAT's own "conventional port" framing uses for
// AMS/TCP 48898.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t MELSEC_TCP_PORT = 5001;
constexpr uint16_t MELSEC_UDP_PORT = 5000;

// One device specification (used by Batch Read/Write's single device and Random Read/Write's
// multiple devices). `device_text` is always set to the conventional human-readable rendering (e.g.
// "D1000", "X001A") -- unrecognized device codes still render as "0xNN:<number>" rather than being
// dropped.
struct MelsecDeviceSpec {
    uint16_t device_code = 0;   // raw wire value (1 byte for "standard", 2 bytes for "extended")
    uint32_t device_number = 0;
    bool extended = false;      // true if this came from the 4-byte-number/2-byte-code wire shape
    std::string device_text;    // e.g. "D1000", "X001A", or "0x7F:1234" if the code is unrecognized
};

struct MelsecFrame {
    bool is_4e_frame = false;
    uint16_t serial_number = 0;  // only meaningful when is_4e_frame
    bool is_response = false;

    uint8_t network_no = 0;
    uint8_t pc_no = 0;
    uint16_t request_dest_module_io_no = 0;
    uint8_t request_dest_module_station_no = 0;

    bool has_monitoring_timer = false;  // request only
    uint16_t monitoring_timer = 0;

    // command/subcommand/command_name/command_recognized are meaningful whenever has_command is
    // true: always on the request side (the wire carries them directly); on the response side, only
    // once matched to its own request by MelsecTcpDecoder::decode/MelsecUdpDecoder::decode (see this
    // file's "RESPONSE DECODING NEEDS SESSION CONTEXT" paragraph) -- an unmatched response leaves
    // has_command false and command_name at "response" (try_parse_melsec's own structural-only
    // fallback name).
    bool has_command = false;
    uint16_t command = 0;
    uint16_t subcommand = 0;
    std::string command_name;  // always set -- "Unknown command 0xXXXX/0xXXXX" when unrecognized,
                                // "response" when has_command is false
    bool command_recognized = false;

    bool has_end_code = false;  // response only
    uint16_t end_code = 0;
    std::string end_code_name;  // always set when has_end_code

    // Batch Read/Write: sized 1. Random Read/Write: sized word_device_count+dword_device_count (or
    // bit_device_count for the bit variant). Empty for commands with no device addressing at all.
    std::vector<MelsecDeviceSpec> devices;

    bool has_point_count = false;  // Batch Read/Write requests only
    uint16_t point_count = 0;

    // Decoded values -- which vector(s) are populated depends on the command/subcommand; see
    // melsec.cpp's decode_payload for exactly which combination fills which vector.
    std::vector<int16_t> word_values;
    std::vector<int32_t> dword_values;
    std::vector<uint8_t> bit_values;  // one entry per bit device, value 0 or 1

    // Set on a response this decoder could not decode command-specifically (no matching pending
    // request found on this session, see this file's header comment) -- the raw byte count is all
    // that's shown. Also set for a matched Random Read response whose word/dword counts weren't
    // available for some reason (defense in depth; see melsec.cpp).
    bool has_undecoded_response_bytes = false;
    size_t undecoded_response_byte_count = 0;

    // Random Read only: word/dword device counts carried forward from the ORIGINAL REQUEST once a
    // response is matched to it (see MelsecPendingRequest below) -- MELSEC's own Random Read response
    // has no count fields of its own on the wire, so this is what lets decode_payload split a matched
    // response's word_values/dword_values correctly. 0/0 on the request side itself (there, the
    // counts are already reflected in `devices`'s own layout) and on an unmatched response.
    uint8_t random_read_word_count = 0;
    uint8_t random_read_dword_count = 0;

    // Remote RUN/PAUSE
    bool has_remote_mode = false;
    uint16_t remote_mode = 0;  // 0x0001 normal, 0x0003 force
    std::string remote_mode_name;
    bool has_clear_mode = false;  // Remote RUN only
    uint8_t clear_mode = 0;
    std::string clear_mode_name;

    // Remote Password UNLOCK/LOCK -- value deliberately never decoded/rendered, see file header.
    bool has_remote_password = false;
    uint16_t remote_password_length = 0;

    // Read CPU Type response only
    bool has_cpu_type = false;
    std::string cpu_type_name;
    uint16_t cpu_code = 0;

    // Echo/Loopback Test (request and response both carry this same shape)
    bool has_echo_data = false;
    std::string echo_data;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns the canonical command name (e.g. "Batch Read", "Remote RUN") for a recognized
// command/subcommand pair, or std::nullopt if the pair isn't one of the commands this decoder
// verified against pymcprotocol (see this file's header comment) -- never guessed at.
std::optional<std::string> melsec_command_name(uint16_t command, uint16_t subcommand);

// Attempts to interpret `payload` as one 3E- or 4E-framed, binary-mode MC Protocol/SLMP message
// (request or response). Returns std::nullopt (never throws) if the structural detection gate (see
// this file's header comment) isn't satisfied. Context-free, like try_parse_twincat: a request is
// always fully decoded (its own command/subcommand are right there on the wire); a response is
// decoded structurally only (End Code + raw byte count) -- see this file's "RESPONSE DECODING NEEDS
// SESSION CONTEXT" paragraph above for why a response needs its own MATCHING REQUEST'S command to be
// decoded further, and MelsecTcpDecoder::decode/MelsecUdpDecoder::decode (melsec.cpp) for where that
// session-scoped matching actually happens, the same try_parse_twincat/TwinCatDecoder::decode split.
std::optional<MelsecFrame> try_parse_melsec(ByteSpan payload);

// One outstanding MELSEC request, tracked per TCP/UDP session (single slot, not a map -- see this
// file's "RESPONSE DECODING NEEDS SESSION CONTEXT" paragraph for why). random_read_word_count/
// random_read_dword_count are only meaningful when command == 0x0403 (Random Read).
struct MelsecPendingRequest {
    uint16_t command = 0;
    uint16_t subcommand = 0;
    std::string command_name;
    size_t packet_index = 0;
    uint8_t random_read_word_count = 0;
    uint8_t random_read_dword_count = 0;
};

// Cross-packet session state: the single most recently sent, not-yet-matched request on one
// TCP/UDP session -- see this file's "RESPONSE DECODING NEEDS SESSION CONTEXT" paragraph. Unlike
// ModbusFlowState/TwinCatFlowState (both an unordered_map keyed by a real wire-carried transaction
// ID), this is deliberately a single std::optional slot: 3E frames carry no transaction ID at all,
// and the 4E frame's own Serial No. is deliberately not used for this (see this file's header
// comment) -- so there is nothing to key a map by, only "the most recent still-outstanding request."
class MelsecFlowState : public DecoderFlowState {
public:
    std::optional<MelsecPendingRequest> pending;
};

// Returns the total on-the-wire byte count one MELSEC frame declares, once there are enough bytes to
// read that declaration -- mirrors twincat_declared_length's role in decoder.cpp's generic TCP
// reassembly cascade (Decoder::reassemble_tcp_payload), reached here through
// MelsecTcpDecoder::tcp_declared_length. Re-applies the same structural gate try_parse_melsec uses
// (not just a plausibility cap), the same lesson TwinCAT's own declared-length function learned the
// hard way (see twincat.cpp's header comment on its own bug-fix history).
std::optional<size_t> melsec_declared_length(ByteSpan payload);

class MelsecTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "melsec"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return melsec_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

class MelsecUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "melsec"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& melsec_tcp_decoder();
const ProtocolDecoder& melsec_udp_decoder();

}  // namespace conduitscope
