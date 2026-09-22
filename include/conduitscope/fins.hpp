// SPDX-License-Identifier: Apache-2.0
// fins.hpp - Omron FINS (Factory Interface Network Service) decoding, over TCP and UDP.
//
// A brand-new protocol (not a migration), built entirely on the ProtocolDecoder interface from the
// start -- see melsec.hpp's own file header for why that's notable (no DecodedPacket flat fields of
// its own). FINS is the second protocol on this interface with a genuine dual TCP+UDP transport
// built from scratch (see FinsTcpDecoder/FinsUdpDecoder below, sharing one id(), the same pattern
// MelsecTcpDecoder/MelsecUdpDecoder established first).
//
// FINS is Omron's PLC communication protocol -- the direct Omron analogue of Modbus/S7comm/MELSEC: a
// client reads/writes PLC memory areas (CIO, Work, Holding, Auxiliary, DM, Timer/Counter, Expansion
// DM), can remotely RUN/STOP the CPU, force-set/reset individual I/O bits, and read/write the PLC's
// clock, all normally with no protocol-level authentication.
//
// VERIFIED AGAINST THREE INDEPENDENT SOURCES during planning: aphyt/omron_fins (a small, actively
// maintained pure-Python FINS client library -- fins/fins_common.py, fins/tcp.py, read in full);
// lammertb/libfins (a multi-platform C library -- include/fins.h, read in full, confirming the same
// 10-byte header layout via independently-named #defines and supplying a large independently-sourced
// end-code table); and Wireshark's own packet-omron-fins.c dissector (github.com/wireshark/wireshark,
// epan/dissectors/packet-omron-fins.c), which cites the official "OMRON FINS Commands Reference
// Manual, W227-E1-2" by name -- the single strongest source, re-fetched a second time (this
// implementation pass) to transcribe its response_codes[]/memory_area_code_cv[]/
// memory_area_code_prefix[]/status_codes[]/mode_codes[]/tcp_command_cv[]/tcp_error_code_cv[]/
// command_code_cv[]/omron_set_reset_specifications[] value_string tables verbatim rather than from
// memory. This second pass CAUGHT AND CORRECTED two assumptions from the first planning pass, both
// via a real-world FINS capture this decoder's own real-capture corpus check had originally missed
// (see "REAL-CAPTURE CORPUS CHECK" below): (1) GCT (Gateway Count) is NOT reliably 0x07 -- a real
// FINS/TCP probe embedded in automayt/ICS-pcap's own omrontcp-info.nse Nmap script uses GCT=0x02
// against a real device, so this decoder does not treat 0x07 as anything more than "one commonly
// seen value" and never gates on it; (2) SA2 (source unit address) is NOT reliably confined to the
// documented 0-31 "CPU/SYSMAC-unit/CPU-Bus-unit" range -- that same real probe uses SA2=0xEF, well
// outside it -- so this decoder's own UDP structural gate (see below) decodes and shows DA2/SA2 but
// does NOT gate on their range, unlike an earlier draft of this plan.
//
// REAL-CAPTURE CORPUS CHECK: unlike MELSEC's own equivalent check (which found no real capture),
// automayt/ICS-pcap (linked from ITI/ICS-Security-Tools's own pcaps collection -- Jurgen pointed
// this out directly) DOES contain real Omron FINS traffic: "FINS (OMRON)/omron/omron.pcap", a
// Git-LFS-stored binary this sandbox's own tooling could not download (LFS/raw paths blocked by
// robots.txt here), but its own Zeek conn.log (fetched directly, plain text) confirms a real UDP/9600
// flow (10.4.14.102:58722 -> 10.130.130.130:9600, 245 packets, one-directional, no reply -- consistent
// with a scan/probe tool, not a live paired session) and its own omrontcp-info.nse Nmap script (also
// fetched directly) embeds a real, working FINS/TCP probe against real devices, which is what
// supplied the GCT/SA2 corrections above and independently re-confirmed the FINS/TCP magic bytes,
// big-endian Length field, and the command-code-at-offset-10/11 layout a fourth way.
//
// FINS COMMAND/RESPONSE FRAME (transport-independent; the UDP payload directly, or wrapped inside
// FINS/TCP's "Frame Send"): 10-byte header, all single-byte fields --
//   ICF(1) + RSV(1) + GCT(1) + DNA(1) + DA1(1) + DA2(1) + SNA(1) + SA1(1) + SA2(1) + SID(1)
// followed by MRC(1) + SRC(1) (the 2-byte command code -- genuinely two 1-byte sub-fields, not one
// combined value, confirmed identically by libfins's own #define FINS_MRC 10 / #define FINS_SRC 11
// and by Wireshark's own field-by-field proto_tree_add_item calls), followed by command-specific
// request data, OR (on a response) EndCode(2) + command-specific response data.
//
// ICF (Information Control Field) bit layout: bit7 (0x80, GWB) = gateway-use bit, conventionally 1;
// bit6 (0x40, DTB) = 0=command, 1=response -- THE authoritative command/response discriminator on the
// wire, used directly for dispatch (the FINS analogue of MELSEC's subheader doing double duty); bits
// 5-1 (0x3E) = reserved, must be 0; bit0 (0x01, RSB) = 0=response required, 1=response not required.
//
// RSV is always 0x00. GCT (gateway count) varies by client (0x02 and 0x07 both confirmed in real
// traffic/libraries -- see above), not gated on. DNA/SNA (network address): 0=local, 1-127=remote.
// DA1/SA1: node address. DA2/SA2 (unit address): 0=CPU unit, 1-15=SYSMAC NET/LINK unit, 16-31=CPU Bus
// unit is Wireshark's own documented convention, but NOT reliably followed by real traffic (see
// above) -- decoded and shown, never gated on. SID (Service ID): client-assigned 0-255, echoed back
// on the response.
//
// FINS/TCP FRAMING (the outer envelope, wraps the FINS frame above for TCP transport): 16-byte base
// header (longer for the two handshake commands): Magic("FINS", 4 ASCII bytes, exact) + Length(4, BE,
// byte count of everything after this field) + Command(4, BE) + ErrorCode(4, BE), then command-
// specific data. Length is BIG-ENDIAN -- confirmed by aphyt's own length.to_bytes(4, 'big'),
// Wireshark's own tvb_get_ntohl, AND the real FINS/TCP probe above (Length field 0x00000015 for a
// 0x15=21-byte payload) -- this REFUTES an industrialmonitordirect.com blog fetched during planning,
// which claimed little-endian; that source is not used anywhere in this decoder.
//
// TCP Command values (tcp_command_cv[]): 0x00 = Node Address Data Send, client->server (handshake
// request; 4-byte client-requested node address follows, offset 16-20); 0x01 = Node Address Data
// Send, server->client (handshake response; 4-byte client node address + 4-byte server node address
// follow, offset 16-24); 0x02 = Frame Send (the actual FINS command/response frame follows as data,
// offset 16 onward -- the only command whose payload this decoder unwraps into the shared
// try_parse_fins_frame parser, confirmed by the real probe's own use of Command=0x00000002); 0x03 =
// Frame Send Error Notification; 0x06 = Connection Confirmation (both named/shown, not decoded
// further). TCP-level error codes (tcp_error_code_cv[], offset 12-16): 0x00000000 = "Normal" through
// 0x00000025, 10 total, all named.
//
// TCP declared-length reassembly: total PDU length = 8 + Length-field-value (Wireshark's own
// get_omron_fins_tcp_pdu_len), directly analogous to Modbus's MBAP length field and MELSEC's own
// declared-length cross-check.
//
// STRUCTURAL DETECTION GATES:
//
// TCP: exact "FINS" magic (4 ASCII bytes, 0x46494e53) at offset 0 -- as strong a gate as any protocol
// in this codebase, comparable to OPC UA's own 3-byte ASCII MessageType magic. No further condition
// needed for the outer envelope.
//
// UDP (and the inner "Frame Send" TCP payload, decoded by the same try_parse_fins_frame): FINS has NO
// magic-byte signature at all on this side. Wireshark's own dissector uses a deliberately weak
// single-byte heuristic (payload byte[1] == 0, i.e. RSV==0, plus a 12-byte minimum length). THIS
// DECODER DOES NOT COPY THAT WEAK GATE. Having just shipped MELSEC's own real collision against
// HART-IP's comparably weak UDP gate (see melsec.hpp), this decoder instead builds a multi-field
// gate: (a) minimum length -- 12 bytes (the 10-byte header plus MRC/SRC); a response frame too short
// for its own 2-byte End Code is not gate-rejected on that alone, it falls into the same graceful
// truncation-note fallback every other short/malformed body in this decoder uses (see
// decode_payload's own try/catch in fins.cpp), not a harder floor; (b) ICF reserved bits (0x3E mask)
// exactly zero -- only 8 of 256 ICF byte values pass; (c) RSV byte exactly 0x00; (d) command code
// (MRC+SRC) must EXACTLY MATCH one of the 17 curated verified
// command codes below -- unlike MELSEC's "Unknown command 0xXXXX/0xXXXX" numeric fallback, an
// unrecognized command code here is rejected outright, not accepted structurally, because FINS/UDP
// has no other anchor to fall back on and accepting arbitrary command codes would reopen the same
// weak-gate collision class MELSEC just got bitten by. DELIBERATELY DOES NOT gate on DA2/SA2's range
// -- see the real-capture correction above. Combined, comparable in strength to BACnet's Type+
// Function pair or TwinCAT's five-part check, despite having no magic bytes.
//
// COLLISION SURVEY: grep every other TcpPortIndependent/UdpPortIndependent decoder's own gate logic
// for the literal "FINS" 4-byte anchor -- performed at implementation time (see decoder.cpp's/
// protocol_registry.cpp's own FINS call-site comments for the result). For the UDP gate specifically,
// cross-checked against HART-IP's own weak gate by name (the protocol that caused MELSEC's real
// collision): HART-IP requires payload byte[1] (MessageType) in {0,1,2,3,15} AND byte[2] (MessageID)
// in {0,1,2,3} AND MsgLength(bytes[6:8], BE) >= 8. FINS's own byte[1] is always RSV=0x00 (satisfies
// HART-IP's MessageType==0 condition), and byte[2] is GCT -- THIS IMPLEMENTATION PASS'S OWN REAL-
// CAPTURE CORRECTION MATTERS HERE: a real FINS/TCP probe uses GCT=0x02, which DOES satisfy HART-IP's
// MessageID-in-{0,1,2,3} condition (the first planning pass's "conventionally 0x07" assumption would
// NOT have collided -- this is a materially stronger, now empirically-grounded justification for the
// same defensive decision). FINS's own UDP dispatch is positioned in the same class as MELSEC --
// before HART-IP -- and this is re-verified by the mandatory manual smoke test before delivery.
//
// COMMANDS DECODED (17, byte-offsets/lengths per this feature's own implementation plan, cross-
// checked against Wireshark's dissector during planning; command names verbatim from its own
// command_code_cv[]):
//   Memory Area Read (0101): request = area_code(1)+address(2,BE word)+bit_address(1)+
//     num_items(2,BE) [6 bytes]; response = end_code(2)+values (word or bit, per area code).
//   Memory Area Write (0102): request = same 6-byte address block + write data (variable); response
//     = end_code(2) only.
//   Memory Area Fill (0103): request = 6-byte address block + fill_pattern(2) [8 bytes]; response =
//     end_code(2) only.
//   Multiple Memory Area Read (0104): request = N x [area_code(1)+address(2)+bit_address(1)] (4
//     bytes/item, repeating); response = end_code(2) + N values (word or bit per item's own area).
//   Run (0401): request = program_number(2,BE)[+mode_code(1)]; response = end_code(2) only.
//   Stop (0402): request = no data; response = end_code(2) only.
//   Controller Data Read (0501): request = no data; response = end_code(2) + (when response body is
//     94 or 161 bytes) controller_model(20 ASCII, body offset 2)+controller_version(20 ASCII, body
//     offset 22), remainder shown as "N byte(s), not decoded further"; a 69-byte (CPU-Bus-Unit-only)
//     response body is shown structurally only.
//   Controller Status Read (0601): request = no data; response = end_code(2)+status(1)+mode_code(1)+
//     fatal_error_flags(2,raw)+non_fatal_error_flags(2,raw)+message_flags(2,raw)+fals_number(2,BE)+
//     error_message(16 ASCII) [28 bytes] -- status/mode_code named from Wireshark's own
//     status_codes[]/mode_codes[] (re-fetched and transcribed verbatim this pass).
//   Cycle Time Read (0620): request = parameter(1: 0=initialize,1=read); response = end_code(2) only
//     (body length 2, initialize) or end_code(2)+avg(4,BE)+max(4,BE)+min(4,BE) [14 bytes] (read) --
//     disambiguated purely by response body length, no request context needed.
//   Clock Read (0701): request = no data; response = end_code(2)+year+month+date+hour+minute+
//     second+day (7x1 byte, BCD) [9 bytes].
//   Clock Write (0702): request = year+month+date+hour+minute(5 bytes, BCD)[+second+day(2)]; response
//     = end_code(2) only.
//   LOOP-BACK Test (0801): request = arbitrary echo data (variable); response = end_code(2) + echoed
//     data.
//   Access Right Acquire (0C01): request = program_number(2,BE); response = end_code(2) only, OR
//     end_code(2)+unit_address(1)+node_number(1)+network_address(1) [5 bytes] identifying the current
//     holder when already held elsewhere -- disambiguated by response body length (2 vs 5).
//   Access Right Forced Acquire (0C02): request = program_number(2,BE); response = end_code(2) only.
//     CURATED NOTE: lets ANY client seize exclusive write access away from whoever currently holds
//     it, with no credential check at all.
//   Access Right Release (0C03): request = program_number(2,BE); response = end_code(2) only.
//   Error Clear (2101): request = fals_number(2,BE); response = end_code(2) only.
//   Forced Set/Reset (2301): request = number_of_bits(2,BE) + N x [specification(2,BE)+area_code(1)+
//     bit_address(3,BE)] (6 bytes/entry); response = end_code(2) only. specification is named from
//     Wireshark's own omron_set_reset_specifications[] (re-fetched this pass): 0x0000="Force-reset
//     (OFF)", 0x0001="Force-set (ON)", 0x8000="Forced status released and bit turned OFF (0)",
//     0x8001="Forced status released and bit turned ON (1)", 0xFFFF="Forced status released".
//     CURATED NOTE: overrides live I/O bit values directly, bypassing normal program logic.
//   Forced Set/Reset Cancel (2302): request = no data; response = end_code(2) only.
//
// Any command/subcommand pair outside this curated set is rejected by the UDP structural gate itself
// (see above) rather than shown numerically -- an intentional, documented departure from MELSEC's own
// posture, forced by FINS/UDP having no other structural anchor to lean on. Over TCP, where the
// "FINS" magic is already a strong-enough gate on its own, an unrecognized command/response is still
// shown, but only structurally (command code + raw byte count), the same honest fallback MELSEC's own
// try_parse_melsec uses for an unrecognized command.
//
// MEMORY AREA CODE TABLE: transcribed from Wireshark's own memory_area_code_cv[]/
// memory_area_code_prefix[] (re-fetched this pass) -- CIO/Work/Holding/Auxiliary bit (0x30/31/32/33)
// & word (0xB0/B1/B2/B3), forced-status bit (0x70/71/72) & word (0xF0/F1/F2) [note: Auxiliary has no
// forced-status variant in Wireshark's own table -- three areas, not four], DM bit (0x02) & word
// (0x82), Timer/Counter Completion Flag (0x09) & forced (0x49) & PV (0x89), Expansion DM banks E0-EC
// bit (0x20-0x2C) & word (0xA0-0xAC), Index Register (0xDC), Data Register (0xBC), Task Flag
// (0x06/0x46), Clock Pulses/Condition Flags (0x07). The first group (CIO/Work/Holding/Auxiliary/DM/
// Expansion-DM-E0-E7) uses the exact letter prefix Wireshark's own memory_area_code_prefix[] table
// gives ("CIO"/"W"/"H"/"A"/"D"/"E0_".."EC_"); Timer/Counter/Index-Register/Data-Register/Task-Flag/
// Clock-Pulses are NOT in that convenience table (Wireshark shows only the full descriptive name for
// them) -- this decoder assigns its own short prefixes for those ("TIM"/"IR"/"DR"/"TK"/"CF"),
// documented in fins.cpp as this decoder's own convention, not Wireshark's.
//
// END CODE NAMING: the full 79-entry table transcribed verbatim from Wireshark's own response_codes[]
// (re-fetched this pass, sourced from the official manual) -- 0x0000 = "Normal completion" through
// 0x4001 = "Command aborted with ABORT command". Any code outside this table falls back to raw hex,
// named honestly as "not independently verified".
//
// A GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC: unlike MELSEC, a FINS response frame DOES carry its
// own command code at the same offset (10-11) a request does -- confirmed via Wireshark's own
// command_code = tvb_get_ntohs(tvb, offset+10), read identically regardless of is_command/is_response,
// and via aphyt's own FinsResponseFrame class shape (header(10)+command_code(2)+end_code(2)+text).
// try_parse_fins_frame is therefore able to fully, context-freely decode MOST response bodies (15 of
// the 17 curated commands: every one whose response is either error-status-only, or self-contained
// enough to disambiguate its own shape purely from its own body length -- Cycle Time Read's
// initialize-vs-read variants and Access Right Acquire's already-held variant both work this way).
// THE EXCEPTION: Memory Area Read (0101) and Multiple Memory Area Read (0104) responses carry raw
// values with no repeated area-code/count information of their own -- decoding those two specific
// response bodies still requires knowing the matching request's own device list, the same
// MelsecFlowState-style problem MELSEC has for every one of its own commands, just narrowed here to
// two. FinsFlowState (below) is this decoder's own lightweight, SESSION-SCOPED, NON-AUTHORITATIVE
// answer to that -- single-pending-slot, matching MelsecFlowState's own shape -- used for those two
// commands' response decode AND, uniformly, to produce a "matched to packet #N" note on every
// response (SID is present and echoed, but -- like MELSEC's 4E Serial No. -- no source establishes
// client-side SID uniqueness across concurrent in-flight requests, so this is "matched", never
// "authoritatively paired").
//
// CURATED SECURITY NOTES (see fins.cpp's decode_payload): (1) No protocol-level authentication for
// CPU control -- Run/Stop, the Omron analogue of MELSEC's Remote RUN/STOP note and S7comm's PLC Stop
// framing. (2) Arbitrary device memory read/write with no built-in access control -- Memory Area
// Read/Write/Fill and Multiple Memory Area Read, the same framing MELSEC's own Batch Read/Write note
// and Modbus's own file header already carry. (3) The "Access Right" mechanism is advisory, not
// authentication -- Access Right Forced Acquire lets any client seize exclusive write access with no
// credential check, a genuinely FINS-specific note with no MELSEC equivalent. (4) Forced Set/Reset
// overrides live I/O directly, bypassing normal program logic -- a physical-safety-relevant note. (5)
// Controller Data Read is unauthenticated reconnaissance -- reveals PLC model/firmware version to any
// network-reachable client, the same framing MELSEC's own CPU Type Read note already carries.
//
// PORTS: FINS_TCP_PORT = 9600, FINS_UDP_PORT = 9600 -- the SAME conventional port on both transports
// (unlike MELSEC's split 5001/tcp + 5000/udp) -- not IANA-registered, confirmed via Wireshark's own
// #define OMRON_FINS_TCP_PORT/OMRON_FINS_UDP_PORT (both commented "Not IANA registered"), corroborated
// by automayt/ICS-pcap's own real capture (UDP/9600) and its AdditionalNotes.txt ("Omron / FINS/TCP-
// UDP - 9600/tcp-udp").
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t FINS_TCP_PORT = 9600;
constexpr uint16_t FINS_UDP_PORT = 9600;

// One memory-area addressed item (Memory Area Read/Write/Fill's single device, Multiple Memory Area
// Read's N devices). `device_text` is always set to the conventional human-readable rendering (e.g.
// "D1000", "CIO100.05" for a bit-type address with a nonzero bit_address) -- an unrecognized area
// code still renders as "0xNN:<address>" rather than being dropped, see fins.hpp's file header
// comment. `value_text` is populated only for a decoded Multiple Memory Area Read RESPONSE item
// (each item can be a different type, so a single word_values/bit_values pair can't represent them
// uniformly the way Memory Area Read's own homogeneous response can -- see FinsFrame's own comment).
struct FinsMemoryItem {
    uint8_t area_code = 0;
    uint16_t address = 0;
    uint8_t bit_address = 0;  // meaningful only when is_bit
    bool is_bit = false;
    std::string device_text;
    std::string value_text;
};

// One entry of a Forced Set/Reset request's own repeating block.
struct FinsForceEntry {
    uint16_t specification = 0;
    std::string specification_name;
    uint8_t area_code = 0;
    uint32_t bit_address = 0;  // 3-byte big-endian on the wire
    std::string device_text;
};

struct FinsFrame {
    bool is_response = false;

    // 10-byte common header, present on both request and response.
    uint8_t icf = 0;
    uint8_t rsv = 0;
    uint8_t gct = 0;
    uint8_t dna = 0;
    uint8_t da1 = 0;
    uint8_t da2 = 0;
    uint8_t sna = 0;
    uint8_t sa1 = 0;
    uint8_t sa2 = 0;
    uint8_t sid = 0;

    // Command code -- present on the wire on BOTH request and response (see fins.hpp's "A GENUINE
    // ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph) -- always set once try_parse_fins_frame
    // accepts a frame, unlike MelsecFrame's own has_command.
    uint8_t mrc = 0;
    uint8_t src_code = 0;
    uint16_t command = 0;  // (mrc << 8) | src_code
    std::string command_name;  // curated name, or "Unknown command 0xNNNN" (TCP only -- UDP's own
                                // gate rejects unrecognized commands outright, see fins.hpp)
    bool command_recognized = false;

    bool has_end_code = false;  // response only
    uint16_t end_code = 0;
    std::string end_code_name;

    // Memory Area Read/Write/Fill: sized 1. Multiple Memory Area Read: sized N. Forced Set/Reset
    // uses `force_entries` below instead (its own repeating shape, not a plain device list). Empty
    // for every other command.
    std::vector<FinsMemoryItem> devices;
    bool has_point_count = false;  // Memory Area Read/Write/Fill requests only
    uint16_t point_count = 0;

    // Memory Area Read (0101) response only -- homogeneous values (single area/type from the one
    // request device), the same parallel-vector shape MelsecFrame's own Batch Read uses. Multiple
    // Memory Area Read (0104) response values are per-item instead (devices[i].value_text) since
    // items can differ in type -- see FinsMemoryItem's own comment.
    std::vector<int16_t> word_values;
    std::vector<uint8_t> bit_values;  // one entry per bit device, value 0 or 1 (FINS does NOT nibble-
                                        // pack two bits per byte the way MELSEC's own bit units do --
                                        // each bit value is its own full byte on the wire)

    // Memory Area Write/Fill request only -- Fill's own single repeated fill_pattern value lives in
    // word_values[0] (see fins.cpp's decode_payload); Write's own write data lives in
    // word_values/bit_values per point_count, matching the one device's own area type.

    // Set on a response this decoder could not decode command-specifically -- either genuinely
    // unrecognized (TCP-only fallback) or, for Memory Area Read/Multiple Memory Area Read
    // specifically, no matching pending request found on this session (see fins.hpp's "A GENUINE
    // ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph).
    bool has_undecoded_response_bytes = false;
    size_t undecoded_response_byte_count = 0;

    // Run (0401) request
    bool has_program_number = false;  // also Access Right Acquire/Forced Acquire/Release requests
    uint16_t program_number = 0;
    bool has_mode_code = false;
    uint8_t mode_code = 0;

    // Controller Data Read (0501) response
    bool has_controller_info = false;
    std::string controller_model;
    std::string controller_version;

    // Controller Status Read (0601) response
    bool has_status_info = false;
    uint8_t status = 0;
    std::string status_name;
    uint8_t ctrl_mode = 0;
    std::string ctrl_mode_name;
    uint16_t fatal_error_flags = 0;
    uint16_t non_fatal_error_flags = 0;
    uint16_t message_flags = 0;
    uint16_t fals_number = 0;  // also Error Clear (2101) request
    bool has_fals_number = false;
    std::string error_message;

    // Cycle Time Read (0620)
    bool has_cycle_parameter = false;  // request
    uint8_t cycle_parameter = 0;
    bool has_cycle_stats = false;  // response, "read" variant only
    uint32_t cycle_avg_us = 0;
    uint32_t cycle_max_us = 0;
    uint32_t cycle_min_us = 0;

    // Clock Read (0701) response / Clock Write (0702) request -- all BCD-decoded to plain decimal.
    bool has_clock = false;
    uint8_t clock_year = 0;
    uint8_t clock_month = 0;
    uint8_t clock_date = 0;
    uint8_t clock_hour = 0;
    uint8_t clock_minute = 0;
    uint8_t clock_second = 0;
    uint8_t clock_day = 0;  // day of week, 0=Sunday; only present on Clock Read's own response

    // LOOP-BACK Test (0801) -- request and response both carry this same shape.
    bool has_echo_data = false;
    std::string echo_data;

    // Access Right Acquire (0C01) response, only when already held by another device.
    bool has_access_right_holder = false;
    uint8_t access_right_unit_address = 0;
    uint8_t access_right_node_number = 0;
    uint8_t access_right_network_address = 0;

    // Forced Set/Reset (2301) request
    std::vector<FinsForceEntry> force_entries;

    // FINS/TCP ENVELOPE-ONLY MESSAGES (TCP transport only -- see FinsTcpDecoder::decode in
    // fins.cpp): the Node Address Data Send handshake (TCP command 0x00/0x01), Frame Send Error
    // Notification (0x03), and Connection Confirmation (0x06) all carry no inner 10-byte-header FINS
    // command/response frame at all -- every field above this point is meaningless when
    // `is_tcp_envelope_only` is true. Frame Send (0x02) is the ONLY TCP command that populates the
    // fields above instead, by unwrapping its own payload into the shared try_parse_fins_frame
    // parser -- see fins.hpp's own "TCP Command values" paragraph.
    bool is_tcp_envelope_only = false;
    uint32_t tcp_command = 0;
    std::string tcp_command_name;
    uint32_t tcp_error_code = 0;
    std::string tcp_error_code_name;
    bool has_handshake_client_node = false;  // both handshake directions carry this
    uint32_t handshake_client_node = 0;
    bool has_handshake_server_node = false;  // server->client handshake response only
    uint32_t handshake_server_node = 0;

    // Set on a response frame that decode_inner_with_session_state (fins.cpp) matched to a
    // still-outstanding request on the same session -- the same non-authoritative "session-scoped,
    // not a unique transaction ID" posture FinsFlowState's own comment describes. Mirrors
    // MelsecFrame's own has_command-on-a-response signal, but as its own explicit flag since a FINS
    // response always carries its own command code regardless of matching (see this file's "A
    // GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph) -- has_command isn't available here
    // to double as the "matched" signal the way it is for MELSEC.
    bool matched_to_request = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns the canonical command name (e.g. "Memory Area Read", "Run") for a recognized command code,
// or std::nullopt if it isn't one of the 17 commands this decoder verified (see fins.hpp's file
// header comment) -- never guessed at.
std::optional<std::string> fins_command_name(uint16_t command);

// Attempts to interpret `payload` as one FINS command/response frame (the transport-independent 10-
// byte-header shape -- the UDP payload directly, or the bytes after FINS/TCP's own 16-byte envelope
// for a Frame Send). Returns std::nullopt (never throws) on structural mismatch. UNLIKE
// try_parse_melsec, this is NOT purely context-free for every command -- Memory Area Read (0101) and
// Multiple Memory Area Read (0104) responses need their own matching request's device list to decode
// values (see fins.hpp's "A GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph); when
// `pending_devices` is null (as it always is for a standalone/context-free call), those two
// commands' own responses decode structurally only (end code + raw byte count), same posture
// try_parse_melsec uses for every response. FinsTcpDecoder::decode/FinsUdpDecoder::decode (fins.cpp)
// pass the session's own pending device list through when one is available.
std::optional<FinsFrame> try_parse_fins_frame(ByteSpan payload,
                                               const std::vector<FinsMemoryItem>* pending_devices = nullptr);

// One outstanding FINS request's device list, tracked per TCP/UDP session (single slot, not a map --
// mirrors MelsecPendingRequest's own rationale: FINS carries no unique per-request transaction ID a
// client is guaranteed to use uniquely, see fins.hpp). Only meaningful when `command` is 0x0101 or
// 0x0104 -- every other command's response decodes context-free, see try_parse_fins_frame's own
// comment.
struct FinsPendingRequest {
    uint16_t command = 0;
    std::string command_name;
    size_t packet_index = 0;
    std::vector<FinsMemoryItem> devices;
};

// Cross-packet session state -- see FinsPendingRequest's own comment and fins.hpp's "A GENUINE
// ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph for why this is narrower in scope than
// MelsecFlowState (only 2 of 17 commands' own responses actually consume `pending->devices`), but
// still tracks every request generically so every response can carry a "matched to packet #N" note.
class FinsFlowState : public DecoderFlowState {
public:
    std::optional<FinsPendingRequest> pending;
};

// Returns the total on-the-wire byte count one FINS/TCP PDU declares (the 16-byte base header itself,
// or more for the two handshake commands, plus the Length field's own value) -- mirrors
// melsec_declared_length's role in decoder.cpp's generic TCP reassembly cascade, reached here through
// FinsTcpDecoder::tcp_declared_length. Re-applies the exact-magic structural gate (not just a
// plausibility cap).
std::optional<size_t> fins_tcp_declared_length(ByteSpan payload);

class FinsTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "fins"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return fins_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

class FinsUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "fins"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& fins_tcp_decoder();
const ProtocolDecoder& fins_udp_decoder();

}  // namespace conduitscope
