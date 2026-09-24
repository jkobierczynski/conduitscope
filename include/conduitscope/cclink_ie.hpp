// SPDX-License-Identifier: Apache-2.0
// cclink_ie.hpp - CC-Link IE Field Network Basic (CCIEFB), Mitsubishi Electric / CC-Link Partner
// Association (CLPA) -- UDP port 61450 (cyclic data transmission) and UDP port 61451 (SLMP node
// search / remote IP-address assignment).
//
// Jurgen asked "can you add CC-Link IE?" CC-Link IE is a family, not one protocol -- see the
// SCOPING DECISION section below for which member this decoder covers and why the others are
// out of scope for this pass.
//
// SOURCING: two independent sources, cross-checked, the same two-way bar established for MELSEC
// (melsec.hpp's own header comment): (1) Mitsubishi's own official "CC-Link IE Field Network
// Basic Reference Manual" (confirms UDP port 61450 for cyclic transmission and 61451 for
// automatic device detection); (2) rt-labs' "c-link" -- a real, actively maintained open-source
// C implementation of the full CCIEFB master+slave stack (github.com/rtlabs-com/c-link),
// including its own documentation primer (docs/cciefb-primer.rst) that names the exact official
// CLPA standard document numbers (BAP-C2006-ENG-001/002/003, BAP-C2010-ENG-001 through -006) each
// wire structure below is taken from. Every struct/field name, byte offset, and magic value below
// was read directly from that stack's own packed C structs (src/common/cl_types.h) -- not
// reverse-engineered or guessed. Unlike BSAP (this project's immediately prior protocol
// addition), there is no sourcing gap here: the cyclic data frame, the node-search frame, and the
// set-IP-address frame are all fully, unambiguously documented by source (2) and cross-confirmed
// on ports/framing by source (1).
//
// SCOPING DECISION -- which CC-Link IE variant this decodes: the CC-Link IE family has several
// members (see the c-link primer's own comparison table): CC-Link IE Control and CC-Link IE Field
// (both 1 Gbit/s, requiring dedicated ASIC hardware, NOT running over standard IP/UDP at all --
// no public wire-format documentation was found for either, the same "dedicated hardware, no
// IP/Ethernet framing to capture with a standard NIC" posture this codebase already states for
// PROFIBUS DP in docs/DEVELOPMENT.md's "Protocols not covered at all" section); CC-Link IE TSN
// (IEEE 802.1 TSN-based, also no public UDP/IP-level wire documentation found); and CC-Link IE
// Field Network Basic (CCIEFB) -- the one member explicitly designed to need "no specialized
// hardware", running entirely over standard UDP/IPv4, and the one this decoder implements. This
// mirrors the BSAP/BSAAP naming-resolution precedent (docs/DEVELOPMENT.md item 40): a plain "add
// CC-Link IE" request resolved to the one family member with real, complete, cross-sourced public
// documentation, stated here rather than silently assumed.
//
// WIRE FORMAT
// -----------
// CCIEFB (and the node-search/set-IP-address commands alongside it) are carried inside SLMP
// (Seamless Message Protocol) framing -- the SAME outer envelope this codebase's existing MELSEC
// decoder (melsec.hpp) already parses for Mitsubishi's MC Protocol. CCIEFB's cyclic data uses the
// "3E frame" shape (subheader 0x5000 request / 0xD000 response, MELSEC's own terminology); node
// search and set-IP-address use the "4E frame" shape (0x5400 request / 0xD400 response, which
// additionally carries a 2-byte Serial No. right after the subheader). See melsec.hpp's own file
// header for the general 3E/4E shape this decoder's outer header fields below reuse verbatim.
//
// CCIEFB CYCLIC (command 0x0E70, subcommand 0x0000, UDP port 61450):
//   Request (master -> slave(s), directed broadcast), fixed 67-byte header + 76 bytes per
//   occupied station:
//     req_header (15 bytes): subheader 0x5000 (2, big-endian) + Network No. 0x00 (1) + PC No.
//       0xFF (1) + Request Destination Module I/O No. 0x03FF (2, little-endian) + Request
//       Destination Module Station No. 0x00 (1) + dl/Request Data Length (2, little-endian) +
//       Monitoring Timer 0x0000 (2, little-endian) + Command 0x0E70 (2, little-endian) +
//       Subcommand 0x0000 (2, little-endian) -- byte-for-byte the same 3E-frame request shape
//       melsec.hpp already documents, with every addressing field fixed to its "own station"
//       value and Command/Subcommand fixed to CCIEFB's own values.
//     cyclic_header (20 bytes): Protocol Version (2, LE, 1 or 2) + reserved 0x0000 (2, LE) +
//       cyclic info offset address (2, LE, a self-describing offset the wire always sets to 36 --
//       decoded and shown as-is, not used to locate anything, since this decoder already knows
//       every field's fixed offset from the struct layout itself) + 14 reserved bytes.
//     master_station_notification (12 bytes): Master Local Unit Info (2, LE -- 0x0000 stopped,
//       0x0001 running, 0x0002 stopped-by-user) + reserved 0x0000 (2, LE) + Clock Info (8, LE, a
//       Unix timestamp in milliseconds, 0 if unavailable).
//     cyclic_data_header (20 bytes): Master ID (4, LE, the master's own IPv4 address) + Group No.
//       (1, 1-64) + reserved (1) + Frame Sequence No. (2, LE) + Timeout Value (2, LE,
//       milliseconds) + Parallel Off Timeout Count (2, LE) + Parameter No. (2, LE, increments
//       whenever the master's slave grouping changes) + Slave Total Occupied Station Count (2,
//       LE, how many of the following per-station blocks exist) + Cyclic Transmission State (2,
//       LE, one bit per slave station) + reserved 0x0000 (2, LE).
//     Trailing cyclic I/O data, grouped (not interleaved) into three contiguous arrays, one entry
//     per occupied station: N x Slave ID (4 bytes each, LE IPv4) + N x RWw (64 bytes each, 32
//     little-endian words -- "Remote Word register, write", master-to-slave) + N x RY (8 bytes
//     each, 64 individual output bits -- master-to-slave). See "CYCLIC I/O DATA" below for why
//     this decoder summarizes rather than renders every bit/word.
//
//   Response (slave -> master, unicast), fixed 59-byte header + 72 bytes per occupied station:
//     resp_header (11 bytes): subheader 0xD000 (2, BE) + Network No. 0x00 (1) + PC No. 0xFF (1) +
//       I/O No. 0x03FF (2, LE) + Station No. 0x00 (1) + dl (2, LE) + reserved 0x0000 (2, LE) --
//       NOTE: unlike a generic SLMP/MELSEC response, CCIEFB's own response header carries no End
//       Code of its own; End Code lives one level deeper, inside cyclic_header below.
//     cyclic_header (20 bytes): Protocol Version (2, LE) + End Code (2, LE, see
//       cclink_ie_end_code_name() below -- 0x0000 is success) + cyclic info offset address (2,
//       LE, wire value always 40) + 14 reserved bytes.
//     slave_station_notification (20 bytes): Vendor Code (2, LE) + reserved (2, LE) + Model Code
//       (4, LE) + Equipment Version (2, LE) + reserved (2, LE) + Slave Local Unit Info (2, LE --
//       0 stopped, 1 operating) + Slave Error Code (2, LE, vendor-defined, 0x0000 = none) + Local
//       Management Info (4, LE, vendor-defined).
//     cyclic_data_header (8 bytes): Slave ID (4, LE, this slave's own IPv4 address) + Group No.
//       (1) + reserved (1) + Frame Sequence No. (2, LE, echoes the request's own value).
//     Trailing cyclic I/O data: N x RWr (64 bytes each -- "Remote Word register, read",
//       slave-to-master) + N x RX (8 bytes each -- slave-to-master input bits). UNLIKE the
//       request, the response carries no explicit occupied-station-count field of its own -- N is
//       derived arithmetically from the UDP payload length (payload_len - 59) / 72, with an exact
//       divisibility check, exactly mirroring the rt-labs stack's own
//       cl_calculate_number_of_occupied_stations().
//
// CYCLIC I/O DATA: SUMMARIZED, NOT RENDERED PER-BIT/WORD -- RWw/RY/RWr/RX are raw, un-typed PLC
// I/O values (a customer's own bit/word mapping, described in a CSP+ configuration file this
// decoder never sees) -- rendering all 64 words/bits per occupied station on every single cyclic
// frame (which fires many times per second in real deployments) would be pure noise, the same
// "bulk cyclic I/O gets a byte count, not a byte-by-byte dump" posture this codebase already
// takes for GE SRTP's own EXTENDED request payload (see ge_srtp.hpp). This decoder names the
// occupied-station count and the total cyclic I/O byte count, not each individual point.
//
// SLMP NODE SEARCH (command 0x0E30, subcommand 0x0000, UDP port 61451, 4E frame):
//   Request (master -> broadcast): slmp_req_header (19 bytes: subheader 0x5400 BE + Serial No.
//     2 LE + reserved 0x0000 2 LE + Network No. 0x00 + Unit No. 0xFF + I/O No. 0x03FF LE +
//     Extension 0x00 + Length 2 LE + Timer 0x0000 2 LE + Command 0x0E30 2 LE + Subcommand 0x0000
//     2 LE) + Master MAC (6 bytes, byte-reversed on the wire relative to conventional
//     colon-notation order -- confirmed via the reference stack's own cl_util_copy_mac_reverse()
//     helper, reversed back here before rendering) + Master IP Address Size 0x04 (1) + Master IP
//     Address (4, LE).
//   Response (slave -> master, randomly delayed 0-1500ms to avoid a broadcast storm of replies):
//     slmp_resp_header (15 bytes: subheader 0xD400 BE + Serial No. 2 LE + reserved 2 LE +
//     Network/Unit/I-O/Extension as above + Length 2 LE + End Code 2 LE -- a GENERIC SLMP response
//     header, unlike CCIEFB's own, this one DOES carry its End Code directly) + Master MAC (6,
//     reversed) + Master IP Size+Addr + Slave MAC (6, reversed) + Slave IP Size+Addr + Slave
//     Netmask (4, LE) + Slave Default Gateway (4, LE, always 0xFFFFFFFF on the wire -- "not set")
//     + Slave Hostname Size 0x00 (1, no hostname field follows) + Vendor Code (2, LE) + Model Code
//     (4, LE) + Equipment Version (2, LE) + Target IP Size+Addr (always 0xFFFFFFFF) + Target Port
//     (2, LE, always 0xFFFF) + Slave Status (2, LE, 0x0000 = normal) + Slave Port (2, LE, always
//     61451) + Slave Protocol Settings (1, always 0x01 = UDP).
//
// SLMP SET IP ADDRESS (command 0x0E31, subcommand 0x0000, UDP port 61451, 4E frame) -- a genuine
// attack-relevant operation (remotely reassigns a slave's own IP address/netmask): request shape
// mirrors Node Search's own request/response MAC+IP fields, with the slave's NEW IP/netmask in
// place of its current ones; response is just the header plus an echoed Master MAC (6 bytes).
//
// RESPONSES CARRY NO COMMAND FIELD, AND COLLIDE BYTE-FOR-BYTE WITH GENERIC MELSEC/SLMP RESPONSES
// -- THE KEY DESIGN CONSTRAINT THIS DECODER IS BUILT AROUND: like MELSEC's own 3E/4E responses
// (melsec.hpp's own "RESPONSE DECODING NEEDS SESSION CONTEXT" section), a CCIEFB/node-search/
// set-IP response carries no command code of its own on the wire -- and worse, a SUCCESSFUL
// CCIEFB cyclic response's own outer 11-byte resp_header is byte-for-byte IDENTICAL to a
// successful generic MELSEC 3E-frame response's own 11-byte header (subheader 0xD000 + fixed
// addressing + dl + a trailing 2 reserved/End-Code bytes that are 0x0000 in both cases for
// success) -- there is no header-only signal that can tell them apart. This decoder resolves
// that exactly the way MELSEC resolves its own identical problem: session-scoped tracking of the
// single most recent outstanding request (CclinkIeFlowState, one std::optional pending slot per
// session, mirroring MelsecFlowState precisely) -- a response is only ever attributed to
// "cclink-ie" when THIS decoder's own session state has a matching outstanding request; an
// orphan response (no tracked request -- capture starts mid-stream, or a request this decoder
// never saw) is deliberately NOT claimed, and falls through to the existing MELSEC decoder
// instead, which decodes it as an unattributed generic response exactly as it already does for
// its own orphan responses today -- an honest, disclosed degradation, not a defect (see
// "EXPLICITLY OUT OF SCOPE" below).
//
// DISPATCH ORDER, DECODER.CPP -- MUST RUN BEFORE MELSEC'S OWN UDP CHECK: because MELSEC's own UDP
// decoder (GateKind::UdpPortIndependent, tried on every UDP port in Auto mode) treats ANY
// unrecognized command as a structurally-valid "unrecognized command" MELSEC frame rather than
// rejecting it outright (melsec.cpp's own fallback path), a real CCIEFB/node-search/set-IP
// REQUEST would otherwise be silently swallowed and mislabeled "melsec" (command 0x0E70/0x0E30/
// 0x0E31 is simply an "unknown command" to MELSEC's own decoder, which does not reject on that --
// confirmed empirically, not theoretically, before this decoder's own dispatch position was
// chosen, per this project's mandatory pre-CTest verification discipline). This decoder's own
// request-side gate is strictly MORE specific than MELSEC's own (exact command-code match, not
// just subheader+length-cross-check), and MELSEC's own command table never uses 0x0E70/0x0E30/
// 0x0E31, so placing this decoder immediately before MELSEC's own UDP dispatch block in
// decoder.cpp is safe by construction: every genuine MELSEC command still reaches MELSEC's
// decoder untouched, exactly as it did before this decoder existed.
//
// SECURITY CONTEXT: no authentication/integrity/confidentiality of any kind is documented anywhere
// in either source -- consistent with CC-Link's age and its being, like most legacy fieldbus-
// descended Ethernet protocols this codebase decodes, insecure by design. Set IP Address in
// particular is a genuine attack-relevant operation (remote reconfiguration of a slave's own
// network identity with, per the sources, no credential of any kind) and gets its own curated
// note; Node Search is passive reconnaissance (vendor/model/MAC/IP disclosure of every slave on
// the segment) and also gets a curated note, mirroring GE SRTP's own controller-type-
// reconnaissance note.
//
// EXPLICITLY OUT OF SCOPE: CC-Link IE Control, CC-Link IE Field (full, ASIC-hardware), and
// CC-Link IE TSN (see "SCOPING DECISION" above -- no public UDP/IP wire documentation found for
// any of the three); CSP+ file parsing (the XML configuration format that gives RWw/RY/RWr/RX
// their customer-specific bit/word meaning -- this decoder has no access to it, see "CYCLIC I/O
// DATA" above); the "Communication Setting Get" SLMP service and any other SLMP command besides
// the three named above (port 45237/61550 traffic is not decoded at all); orphan CCIEFB/node-
// search/set-IP responses with no session-tracked request (falls through to the generic MELSEC
// decoder instead of being misattributed -- see "RESPONSES CARRY NO COMMAND FIELD" above); and,
// as ever, any field this decoder does not name above.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t CCLINK_IE_CYCLIC_PORT = 61450;       // CCIEFB cyclic data transmission
constexpr uint16_t CCLINK_IE_NODE_SEARCH_PORT = 61451;  // SLMP node search / set IP address

// The SLMP end-code table (cl_slmp_error_codes_t in the rt-labs reference stack) -- shared by
// every response this decoder recognizes. Returns std::nullopt for a value not in this table
// (rendered as raw hex by the caller, never guessed at).
std::optional<std::string> cclink_ie_end_code_name(uint16_t code);

enum class CclinkIeMessageKind {
    CyclicRequest,
    CyclicResponse,
    NodeSearchRequest,
    NodeSearchResponse,
    SetIpAddressRequest,
    SetIpAddressResponse,
};

struct CclinkIeFrame {
    CclinkIeMessageKind kind = CclinkIeMessageKind::CyclicRequest;
    // True only for a response this decoder matched to a session-tracked outstanding request --
    // see this file's own "RESPONSES CARRY NO COMMAND FIELD" section. Always true for a request.
    bool attributed = true;

    // --- CCIEFB cyclic (command 0x0E70) ---
    uint16_t protocol_ver = 0;
    uint16_t cyclic_info_offset_addr = 0;

    // Cyclic request fields
    std::string master_id;  // formatted IPv4
    uint8_t group_no = 0;
    uint16_t frame_sequence_no = 0;
    uint16_t timeout_value = 0;
    uint16_t parallel_off_timeout_count = 0;
    uint16_t parameter_no = 0;
    uint16_t slave_total_occupied_station_count = 0;
    uint16_t cyclic_transmission_state = 0;
    uint16_t master_local_unit_info = 0;
    std::optional<std::string> master_local_unit_info_name;
    uint64_t clock_info_unix_ms = 0;

    // Cyclic response fields
    std::string slave_id;  // formatted IPv4
    uint16_t end_code = 0;
    std::optional<std::string> end_code_name;
    uint16_t vendor_code = 0;
    uint32_t model_code = 0;
    uint16_t equipment_ver = 0;
    uint16_t slave_local_unit_info = 0;
    std::optional<std::string> slave_local_unit_info_name;
    uint16_t slave_err_code = 0;
    uint32_t local_management_info = 0;
    uint16_t occupied_stations = 0;  // request: wire field; response: derived from payload length

    size_t cyclic_io_byte_count = 0;  // total bytes of RWw+RY (request) or RWr+RX (response)

    // --- SLMP node search / set IP address (4E frame) ---
    uint16_t serial = 0;
    std::string master_mac;
    std::string master_ip;
    std::string slave_mac;
    std::string slave_ip;  // node search: slave's current IP; set-IP request: slave's NEW IP
    std::string slave_netmask;

    std::vector<std::string> notes;
    std::string summary;
};

// Four narrow parse entry points, one per (framing, direction) combination, rather than one
// do-everything function -- because a 3E/4E RESPONSE carries no command field of its own (see
// "RESPONSES CARRY NO COMMAND FIELD" above), the caller (CclinkIeDecoder::decode, which alone has
// access to session state) must already know from its own CclinkIeFlowState which kind of
// response to expect before it can pick the right body shape to parse -- these functions are
// deliberately too narrow to make that decision themselves.
//
// Cyclic (command 0x0E70, subheader 0x5000/0xD000): request and response share no ambiguity
// beyond req-vs-resp, which the subheader alone already settles, so these two need no "expected
// kind" hint.
std::optional<CclinkIeFrame> try_parse_cclink_ie_cyclic_request(ByteSpan udp_payload);
std::optional<CclinkIeFrame> try_parse_cclink_ie_cyclic_response(ByteSpan udp_payload);

// SLMP node search / set IP address (commands 0x0E30 / 0x0E31, subheader 0x5400/0xD400): the
// REQUEST carries its own command field, so it self-determines which of the two it is. The
// RESPONSE does not (both share the exact same 15-byte resp_header) -- `expected_kind` must be
// CclinkIeMessageKind::NodeSearchResponse or ::SetIpAddressResponse, supplied by the caller from
// session state; anything else returns std::nullopt.
std::optional<CclinkIeFrame> try_parse_cclink_ie_slmp_request(ByteSpan udp_payload);
std::optional<CclinkIeFrame> try_parse_cclink_ie_slmp_response(ByteSpan udp_payload,
                                                                 CclinkIeMessageKind expected_kind);

// Cross-packet session state: the single most recently sent, not-yet-matched CC-Link IE request
// on one UDP session -- see this file's own "RESPONSES CARRY NO COMMAND FIELD" section for why
// this is a hard requirement, not an optional enhancement, mirroring MelsecFlowState (melsec.hpp)
// exactly.
struct CclinkIePendingRequest {
    CclinkIeMessageKind kind = CclinkIeMessageKind::CyclicRequest;
    size_t packet_index = 0;
};
class CclinkIeFlowState : public DecoderFlowState {
public:
    std::optional<CclinkIePendingRequest> pending;
};

class CclinkIeDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "cclink-ie"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& cclink_ie_decoder();

}  // namespace conduitscope
