// SPDX-License-Identifier: Apache-2.0
// twincat.hpp - Beckhoff TwinCAT / ADS (Automation Device Specification) decoding, over AMS/TCP.
//
// THE FIRST PROTOCOL IN THIS CODEBASE BUILT ENTIRELY ON THE ProtocolDecoder INTERFACE
// (protocol_decoder.hpp) -- see docs/DEVELOPMENT.md's "registration-model decoder refactor" entry
// for why. Every other protocol here still works the pre-existing way (a free `try_parse_x`
// function plus a hand-written block in decoder.cpp's dispatch chain, its fields flattened
// directly onto DecodedPacket); TwinCAT deliberately does neither -- it has no DecodedPacket
// fields of its own at all, and decoder.cpp's TwinCAT call site only ever reads
// TwinCatFrame::summary/notes (already-rendered strings), never a `twincat_*` field, because there
// are none. This is the proof that a protocol CAN be added without touching decoder.hpp's already-
// 1300-line DecodedPacket struct -- the whole point of building the interface in the first place.
//
// WIRE FORMAT
//
// AMS/TCP framing (TCP port 48898 / 0xBF02, no dedicated UDP framing attempted here -- AMS also
// rides UDP/serial in some Beckhoff setups, but TCP is the common industrial-network case and
// where every other protocol in this codebase starts too): a 6-byte header --
// 2 reserved bytes (conventionally zero on the wire) + a 4-byte little-endian "AMS/TCP Data
// Length" -- directly precedes the AMS header itself. AMS/TCP Data Length is the byte count of
// EVERYTHING that follows (the 32-byte AMS header plus its own payload), so it must always equal
// 32 + the AMS header's own Data Length field below -- this cross-check between two independently
// present length fields is this decoder's strongest structural signal (see the detection gate
// paragraph further down, and try_parse_twincat's own header comment).
//
// AMS header (32 bytes, every multi-byte field little-endian except the two AmsNetId fields,
// which are just 6 raw address bytes each, conventionally rendered dotted-decimal like an IPv4
// address with two extra octets, e.g. "5.62.196.212.1.1"):
//   Target AmsNetId (6) + Target AMS port (2) + Source AmsNetId (6) + Source AMS port (2) +
//   Command ID (2) + State Flags (2) + Data Length (4) + Error Code (4) + Invoke ID (4)
// followed by exactly Data Length more bytes of command-specific payload.
//
// State Flags: bit 2 (0x0004) is the "ADS command" flag, set on every ordinary ADS request/
// response this decoder recognizes (distinguishing it from a handful of rarer, undocumented-here
// AMS router-internal message shapes that don't set it -- rejected, not guessed at); bit 0
// (0x0001) is Response (set) vs. Request (clear).
//
// Command ID (2-byte field): 0x0001 ReadDeviceInfo, 0x0002 Read, 0x0003 Write, 0x0004 ReadState,
// 0x0005 WriteControl, 0x0006 AddDeviceNotification, 0x0007 DeleteDeviceNotification, 0x0008
// DeviceNotification, 0x0009 ReadWrite -- every other value is rejected (unrecognized Command ID
// is one of this decoder's own structural gate checks, see below).
//
// Read/Write/ReadWrite request payloads address a PLC symbol/variable by an IndexGroup (4 bytes)
// + IndexOffset (4 bytes) pair -- conceptually similar to this codebase's own S7comm DB/offset
// item addressing (s7comm.hpp/s7comm.cpp) -- rendered the same "group:offset" style. Every
// request/response payload shape this decoder fully decodes is documented at its own
// decode_*_payload helper in twincat.cpp; DeviceNotification (the one shape genuinely too deep for
// this pass -- see below) is decoded structurally (stamp/sample counts) but not per-sample, the
// same "recognized but not decoded further" posture this codebase already takes for Modbus's rare
// function codes and S7comm-Plus's Tier 2 services.
//
// DELIBERATELY NOT IMPLEMENTED IN THIS PASS: symbolic name resolution (mapping a human-readable
// PLC variable name to an IndexGroup/IndexOffset pair via ADS's own ADSIGRP_SYM_HNDBYNAME/
// symbol-table reads) -- real depth beyond the raw IndexGroup/IndexOffset numbers this decoder
// already renders, and, per docs/DEVELOPMENT.md's own research note, a reasonable follow-up of its
// own once this base decode is validated against real traffic, the same "port-heuristic now,
// tighten later" progression several other protocols here already followed. Per-sample
// DeviceNotification payload decoding (see above) is the other explicitly deferred piece, for the
// same reason: a sample's own bytes have no fixed shape without knowing which symbol's data type
// they represent, which is exactly what symbolic name resolution would provide.
//
// STRUCTURAL DETECTION GATE: (a) at least 38 bytes present (6-byte AMS/TCP header + 32-byte AMS
// header); (b) AMS/TCP Data Length == 32 + AMS header's own Data Length (the cross-check above);
// (c) State Flags bit 2 (0x0004, "ADS command") set; (d) Command ID is one of the nine values
// above; (e) Data Length is not implausibly large for a real ADS payload (capped, mirroring
// Modbus's own mbap_length<=300-style plausibility ceiling -- see try_parse_twincat). Surveyed
// against every other TCP-port-independent protocol this codebase already tries opportunistically
// (see docs/DEVELOPMENT.md's PROTOCOL DETECTION section) before picking this decoder's registry
// position: OPC UA's leading 3 bytes must be one of 7 fixed ASCII MessageType strings -- AMS/TCP's
// own leading 2 bytes are conventionally zero, never ASCII, so no collision. IEC104 requires its
// first byte to be the fixed start byte 0x68 -- AMS/TCP's first byte being conventionally zero
// rules this out. DNP3's data-link layer requires its first two bytes to be the fixed sync 0x0564
// -- same reasoning, no collision. Modbus/TCP's protocol-id==0 check reads what, for an AMS/TCP
// frame, are the low 16 bits of the 4-byte AMS/TCP Data Length field -- for any realistic ADS
// payload size (tens to low thousands of bytes, never an exact multiple of 65536) those 16 bits
// are nonzero, so Modbus's own gate correctly rejects real TwinCAT traffic. TPKT (the S7comm/MMS/
// S7comm-Plus family's shared framing) requires its first byte to be version==3 -- again ruled out
// by AMS/TCP's conventionally-zero leading bytes. HART-IP/MQTT/FF-HSE are all tried well after
// this decoder's own registry position (see protocol_registry.hpp) specifically because their own
// gates are weaker than this one's five-part check, so nothing about their own, separately
// documented weak-gate risk is affected by TwinCAT's addition. Registered directly after Modbus in
// the TCP-port-independent dispatch order (protocol_registry.hpp) -- costs nothing to try there,
// the same "no collision found, so try it as early as its own gate strength justifies" reasoning
// OPC UA/EtherNet/IP's own positions already established.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t TWINCAT_AMS_TCP_PORT = 48898;  // 0xBF02

enum class TwinCatCommand : uint16_t {
    ReadDeviceInfo = 0x0001,
    Read = 0x0002,
    Write = 0x0003,
    ReadState = 0x0004,
    WriteControl = 0x0005,
    AddDeviceNotification = 0x0006,
    DeleteDeviceNotification = 0x0007,
    DeviceNotification = 0x0008,
    ReadWrite = 0x0009,
};

// Returns the canonical Command ID name (e.g. "Read", "AddDeviceNotification") for one of the nine
// values above, or std::nullopt for anything else -- used both by try_parse_twincat's own gate
// check and to render TwinCatFrame::command_name.
std::optional<std::string> twincat_command_name(uint16_t command_id);

struct TwinCatFrame {
    std::string target_ams_net_id;  // "N.N.N.N.N.N" dotted form, see file header comment
    uint16_t target_ams_port = 0;
    std::string source_ams_net_id;
    uint16_t source_ams_port = 0;

    uint16_t command_id = 0;
    std::string command_name;  // always set -- try_parse_twincat rejects an unrecognized command_id

    bool is_response = false;  // State Flags bit 0
    uint32_t error_code = 0;
    uint32_t invoke_id = 0;

    // Only meaningful for Read/Write/ReadWrite requests and responses -- see decode_*_payload in
    // twincat.cpp. Left at 0/empty for command shapes with no IndexGroup/IndexOffset addressing
    // (ReadDeviceInfo, ReadState, WriteControl, Add/DeleteDeviceNotification, DeviceNotification).
    bool has_index_addressing = false;
    uint32_t index_group = 0;
    uint32_t index_offset = 0;

    // Only set on a response frame whose payload includes an ADS Result code (every response
    // shape this decoder recognizes except DeviceNotification, which carries no Result at all --
    // it's an unsolicited push, not a reply to a specific request).
    bool has_ads_result = false;
    uint32_t ads_result = 0;

    // Only set by ADS ReadDeviceInfo/AddDeviceNotification/DeleteDeviceNotification pairing (see
    // TwinCatFlowState below) -- mirrors ModbusFrame's own paired_response/paired_request_index
    // (modbus.hpp) exactly, both carried on their own protocol result struct rather than a
    // DecodedPacket field, per this file's own header comment on why.
    bool paired_response = false;
    size_t paired_request_index = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `tcp_payload` as one AMS/TCP-framed ADS message. Returns std::nullopt
// (never throws) if the structural detection gate (see this file's header comment) isn't
// satisfied. Never performs cross-packet Invoke-ID pairing itself -- see TwinCatDecoder::decode
// (twincat.cpp), which calls this and then applies that layer, the same split
// try_parse_modbus_tcp/ModbusDecoder::decode already established.
std::optional<TwinCatFrame> try_parse_twincat(ByteSpan tcp_payload);

// Returns the total on-the-wire byte count one AMS/TCP frame declares (6-byte AMS/TCP header +
// its own Data Length field), once there are enough bytes to read that declaration (>= 6) --
// mirrors modbus_tcp_declared_length's own role in decoder.cpp's generic TCP reassembly cascade
// (Decoder::reassemble_tcp_payload), reached here through TwinCatDecoder::tcp_declared_length.
std::optional<size_t> twincat_declared_length(ByteSpan payload);

// One outstanding ADS request, tracked per AMS/TCP-over-TCP SESSION (both directions -- see
// DecodeContext::session_key) and keyed further by its 4-byte Invoke ID -- the same role
// modbus.hpp's ModbusPendingRequest plays for MBAP transaction IDs, adapted to ADS's own Invoke ID
// field. `flow_key` is the *directional* flow the request itself was seen on, kept for the same
// same-direction-reuse-vs-opposite-direction-reply distinction ModbusPendingRequest's own comment
// explains.
struct TwinCatPendingRequest {
    size_t packet_index = 0;
    std::string flow_key;
    std::string command_name;
    std::string request_summary;
};

// Cross-packet ADS Invoke-ID pairing state for one AMS/TCP-over-TCP session -- the TwinCAT analog
// of modbus.hpp's ModbusFlowState, proving DecodeContext::flow_state<T>() generalizes to a second,
// independently-designed stateful protocol (not just Modbus's own specific shape).
class TwinCatFlowState : public DecoderFlowState {
public:
    std::unordered_map<uint32_t, TwinCatPendingRequest> pending;
};

class TwinCatDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "twincat"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return twincat_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& twincat_decoder();

}  // namespace conduitscope
