// SPDX-License-Identifier: Apache-2.0
// codesys.hpp - CODESYS V3 protocol decoding (3S-Smart Software Solutions / CODESYS GmbH's PLC
// programming/runtime communication protocol, ridden by dozens of PLC vendors -- WAGO, Festo,
// Eaton, Berghof, and many others -- built on the CODESYS runtime framework). TCP ports 11740
// (CmpChannelServer, direct online-communication channel) and 1217 (CmpRouter's own gateway
// protocol, used by the engineering IDE for remote/routed access), plus UDP ports 1740-1743
// (CmpRouter node discovery/broadcast and channel-index-selected traffic).
//
// SCOPING, DECIDED WITH JURGEN BEFORE ANY CODE WAS WRITTEN (see docs/DEVELOPMENT.md's own entry
// for this decoder for the full record): (1) CODESYS V2 (legacy, TCP port 1200) is explicitly OUT
// OF SCOPE -- research turned up only a port number and an Nmap discovery script for it, no public
// wire-format documentation, unlike V3 below. (2) Beyond the CmpDevice Login/AUTH exchange
// (username + session-ID extraction, both specifically documented -- see PAYLOAD DECODE SCOPE
// below), every other CODESYS service (CmpApp's own program start/stop/download, CmpFileTransfer,
// CmpIecVarAccess's live variable read/write, CmpUserMgr, ...) is STRUCTURAL-ONLY: named by
// component/command ID where a name is confirmed, its payload reported as a byte count only, never
// value-decoded -- the same posture bsap.hpp's own RDB layer takes for the identical reason (see
// its own SOURCING comment): no public source gives a command-ID or tag-field catalog for any of
// those services, only for CmpDevice's own Login/AUTH exchange.
//
// SOURCING: two independent, mutually corroborating sources, neither a vendor specification (none
// was found to be publicly available): (1) a public Wireshark Lua dissector,
// github.com/fridgebuyer/codesys3-dissector (codesys3.lua), whose own working parsing code gives
// byte-exact field offsets for every layer below -- quoted directly, not paraphrased, everywhere
// this file's comments cite an exact offset; (2) Kaspersky ICS-CERT's own published reverse-
// engineering research, "Security research: CODESYS Runtime, a PLC control framework" (Alexander
// Nochvay, parts 1-2, ics-cert.kaspersky.com), which independently names the same four-layer
// architecture, the same magic numbers (expressed in a different byte-order convention -- see WIRE
// FORMAT below), the same channel command IDs, and the same CmpDevice/CmpApp/CmpUserMgr component
// names, plus the one specific worked example (the Login/AUTH tag layout) this decoder's own
// PAYLOAD DECODE SCOPE relies on. Where the two sources' own descriptions diverged or one added
// detail the other didn't corroborate (see the per-field notes below), this decoder takes the more
// conservative reading rather than asserting unconfirmed precision -- the same discipline BSAP's
// own Node Status Byte/Control Byte fields already established ("shown raw -- no further bit
// layout found").
//
// WIRE FORMAT
//
// Four layers, per both sources (Kaspersky's own naming for each): Block Driver (TCP framing
// only), Datagram/Router (CmpRouter, routing + node discovery), Channel (CmpChannelMgr, guaranteed
// delivery/buffering), Services (CmpSrv, command execution). Every multi-byte field below is
// little-endian unless stated otherwise.
//
// BLOCK DRIVER LAYER (TCP only -- UDP has none of this, the Datagram layer starts at UDP payload
// byte 0): 8 bytes -- a 4-byte magic, then a 4-byte Length field covering the ENTIRE wire message
// including these 8 header bytes itself (Kaspersky: "cumulative packet size including these 8
// header bytes"). The magic is the same 4 bytes read two different ways by this decoder's two
// sources: the dissector's own working code checks the raw hex string "000117e8" (i.e. reads the
// four wire bytes E8 17 01 00 and represents them big-endian-style for display); Kaspersky's own
// text instead calls it "0xe8170100". Both describe the identical four wire bytes (E8 17 01 00) --
// this decoder reads them the same way the dissector's own code does, as a little-endian uint32,
// which yields 0x000117E8; CODESYS_TCP_BLOCK_DRIVER_MAGIC below is that value. Kaspersky's own
// stated maximum (520 bytes = 512-byte PDU + 8-byte header) is taken at face value as this
// transport's real per-frame ceiling -- consistent with the Channel layer's own blk_num/
// remaining_data_size fields existing specifically to span a larger transfer across MULTIPLE
// block-driver frames (see SESSION STATE below for why this decoder does not reassemble those).
//
// DATAGRAM/ROUTER LAYER: 6-byte fixed header, always exactly the same on both transports --
// Magic(1, must be exactly 0xC5) + Hops(1, raw, no further bit layout confirmed with confidence --
// see below) + PacketParams(1, raw, same caveat) + ServiceId(1, must be one of 0x01/0x02 "address
// service", 0x03/0x04 "name service", 0x40 "channel service" -- Kaspersky's own naming; anything
// else rejects the frame) + MessageId(1, raw) + AddressLengths(1, must be exactly 0x43 or 0x34).
// Kaspersky's own text additionally describes Hops/PacketParams as themselves bit-packed ("5-bit
// hop count + 3-bit header length", "2-bit priority + signal bit + address type + data block
// size"), but the dissector's own actual working code treats them as two plain whole bytes with no
// further sub-field decode -- since the two sources disagree on whether there IS confirmed
// sub-byte structure here, and only the byte-level layout (not the bit-level one) is corroborated
// by real parsing code, this decoder shows both bytes raw, the same "byte-level confirmed, bit-
// level not" caution BSAP's own Node Status Byte already applies. Then, per the dissector's own
// exact code: AddressLengths == 0x43 means Sender is 6 bytes then Receiver is 8; == 0x34 means
// Sender is 8 then Receiver is 6 -- either way the Datagram layer is exactly 20 bytes total (6
// header + 14 address). A 6-byte address is Port(2) + IPv4(4) -- confirmed by Kaspersky's own
// worked example ("2ddcc0a80058" = port 0x2ddc + IP 0xc0a80058) -- and is decoded and rendered as "ip:port" by
// this decoder; an 8-byte address's own extra 2 bytes have no confirmed meaning in either source,
// so it is shown as raw hex only, never interpreted.
//
// CHANNEL LAYER (only entered when the Datagram layer's own ServiceId == 0x40 "channel service" --
// the address/name service (0x01-0x04) is CmpRouter's own internal routing/discovery traffic, with
// no confirmed body format past the Datagram layer in either source, so it is named and left there,
// the same "recognized but not descended into" posture BSAP's own BSAP-IP-native path takes): 20
// bytes, per the dissector's own exact offsets -- CommandId(1) + Flags(1, shown raw: this decoder's
// two sources describe where the request/response indicator bit lives inconsistently -- Kaspersky
// says a bit within CommandId itself, the dissector's own working code instead reads it from this
// separate adjacent byte -- so it is not asserted with confidence; only CommandId==0x83's own
// distinct, unambiguous value, "response to OPEN_CHANNEL" per the dissector, is named as a
// response) + ChannelId(2) + BlkNum(4) + AckNum(4) + RemainingDataSize(4) + Checksum(4, raw hex --
// a CRC32 per Kaspersky, but its exact polynomial/init/refin/refout is not stated by either source,
// so it is never recomputed/validated here). CommandId values named by both sources: 0xC2
// GET_INFO, 0xC3 OPEN_CHANNEL, 0x83 OPEN_CHANNEL response, 0xC4 CLOSE_CHANNEL, 0x01 BLK (data
// transmission), 0x02 ACK, 0x03 KEEPALIVE; any other value is shown as raw hex, never guessed at.
//
// SERVICES LAYER (only attempted when CommandId == 0x01 "BLK", AND the channel payload's own first
// 20 bytes structurally validate as a real Services header -- see STRUCTURAL VALIDATION, NOT
// STATE-TRACKED REASSEMBLY below for why a validation gate substitutes for real multi-block
// tracking): 20-byte header, per the dissector's own exact offsets -- ProtocolId(2, must be exactly
// 0xCD55 "unencrypted" or 0x7557 "SecureProtocol/encrypted" per Kaspersky, otherwise the header is
// rejected as not a genuine Services message) + HeaderSize(2, raw) + ComponentId(2 -- what the
// dissector's own code calls "service_id"; Kaspersky's own text calls the identical field
// "service_group" -- this decoder uses ComponentId/component_id throughout to sidestep that
// cross-source naming collision entirely) + CommandId(2 -- what the dissector calls "cmd_id";
// Kaspersky calls it "service_id", the SAME NAME it also gives ComponentId above, for a genuinely
// different field -- this decoder's own command_id field is the dissector's cmd_id, never
// confused with the Channel layer's own, unrelated CommandId byte above) + SessionId(4) +
// PayloadSize(4) + AdditionalData(4, raw, no confirmed meaning) + payload_data (PayloadSize bytes,
// clamped to what's actually present). ComponentId is named via a small table both sources
// corroborate (CmpDevice=1, CmpApp=2, CmpUserMgr=0xC per Kaspersky; CmpFileTransfer=0x08,
// CmpIecVarAccess=0x09, CmpTraceMgr=0x0F, CmpMonitor2=0x1B per the dissector) -- any other value is
// shown as a raw number. CommandId (the per-component command/opnum) is named ONLY for the one
// (ComponentId, CommandId) combination both sources independently confirm -- (1, 2), CmpDevice's
// own Login/AUTH exchange (the dissector's own working code literally checks `service_id == 0x01,
// cmd_id == 0x02` for what it names "Login"; Kaspersky's own text separately calls the identical
// combination "CmpDevice AUTH") -- every other combination is left as a bare number, per this
// file's own SCOPING paragraph above.
//
// PAYLOAD DECODE SCOPE: payload_data is a flat sequence of tag-length-value entries -- confirmed
// directly from the dissector's own working parse_tag_to_list/s_tag_decode_int functions: both the
// tag ID and the length are themselves standard 7-bit-per-byte, LSB-first, continuation-bit(0x80)
// varints (byte-identical in shape to a protobuf varint -- see read_codesys_varint below, a small
// local reader kept separate from mqtt.cpp's own read_pb_varint despite the coincidence, since the
// two encodings, while shaped alike, belong to unrelated protocols), followed by exactly that many
// raw value bytes. This decoder walks that flat top-level sequence for EVERY Services message (cheap,
// and the walk itself needs no component/command-specific knowledge), but only interprets a
// specific tag's VALUE for the one documented case: Kaspersky's own worked example states a Login/
// AUTH REQUEST's payload contains a "parent tag 0x81" whose own value is itself a further tag-list
// containing child tag 0x10 (username) and child tag 0x11 ("encrypted" password, per Kaspersky's
// own description) -- so, ONLY when ComponentId==1 (CmpDevice) && CommandId==2 (Login/AUTH) && the
// channel Flags byte's low bit is clear (request, per this decoder's own conservative flags
// reading -- see CHANNEL LAYER above) is tag 0x81's own value additionally walked as a nested
// tag-list, extracting: tag 0x10 as auth_username (rendered as text); tag 0x11's PRESENCE and BYTE
// LENGTH only, never its bytes -- this decoder treats it as secret-shaped regardless of Kaspersky's
// own "encrypted" characterization, the same never-render-a-credential-byte posture this codebase
// already takes for SAMR/NL_TRUST_PASSWORD-style fields, since "encrypted" is not a claim this
// decoder can independently verify and a stronger default (never render) costs nothing. On a Login/
// AUTH RESPONSE, top-level tag 0x21 (per Kaspersky, "session ID for subsequent requests") is read
// directly (not nested under 0x81) as auth_session_id, when its own value is exactly 4 bytes (read
// little-endian, matching every other multi-byte field in this protocol; if its length is anything
// else, its raw byte count is noted instead of guessing an interpretation). A Login/AUTH message
// whose own ProtocolId reads as 0x7557 (SecureProtocol/encrypted) is NOT tag-walked at all -- its
// payload bytes are genuinely ciphertext on the real wire, and this decoder has no access to
// whatever key exchange establishes that encryption (not documented in either of this file's own
// sources), so tag-walking it would misinterpret ciphertext as plausible-looking-but-meaningless
// structure; only a byte count is noted instead. No other component's payload, and no other
// CmpDevice command's payload, is tag-walked for semantic content at all -- see this file's own
// SCOPING paragraph above.
//
// STRUCTURAL VALIDATION, NOT STATE-TRACKED REASSEMBLY: CODESYS's own Channel layer (blk_num/
// ack_num/remaining_data_size) exists to split a larger transfer (a program download via
// CmpFileTransfer, say) across multiple BLK frames -- this decoder does not track that
// reassembly (no DecoderFlowState, no cross-packet correlation at all: every captured TCP/UDP
// payload is decoded independently). Blindly attempting a fresh Services-header parse at the start
// of EVERY BLK frame's own channel payload would misdecode a CONTINUATION block (raw file/program
// bytes, not a new header) as garbage while reporting it with false confidence. This decoder avoids
// that specific failure mode structurally rather than via state: a Services header is only ever
// accepted once its own ProtocolId field reads back as exactly 0xCD55 or 0x7557 (see SERVICES LAYER
// above) -- a continuation block's own leading bytes overwhelmingly will not happen to match either
// value, so it instead falls through to "channel payload present (N bytes), not decoded as a fresh
// Services message -- likely a continuation block of a larger multi-block transfer, or a
// component/command this decoder doesn't parse a header from" rather than emitting a wrong summary.
// This is the same "validate before rendering, decline gracefully rather than guess" posture
// try_parse_enip's own multi-independent-field check and this codebase's whole "never guess a
// numeric fallback" discipline already establish, applied here to a structural (not just numeric)
// ambiguity.
//
// SESSION STATE: none at all (see STRUCTURAL VALIDATION above) -- every packet is decoded
// independently. SessionId (Services layer) is read directly off each packet's own header, not
// correlated across packets by this decoder; a real CODESYS client/server pair uses it to validate
// that a caller authenticated earlier in the same TCP connection, but this decoder has no need to
// track that itself since it never asserts whether a given SessionId IS validly authenticated,
// only what value the wire carries.
//
// DETECTION / DISPATCH: TCP (port 11740 CmpChannelServer, or port 1217 CmpRouter's own gateway
// protocol -- both carry the identical four-layer stack, per both sources; neither is more or less
// "real" CODESYS traffic, so this decoder recognizes either port identically) is
// GateKind::TcpPortIndependent, gated by the Block Driver layer's own 4-byte exact magic plus a
// length-field cross-check (the declared Length must be >= 8 and <= 520, Kaspersky's own stated
// ceiling) -- a two-independently-constrained-field check in the same spirit as try_parse_twincat's
// own AMS/TCP Data Length cross-check, strong enough to try opportunistically. UDP (ports
// 1740-1743, all four sharing identical framing -- Kaspersky's own text: "corresponding to port
// indexes 0-3") is GateKind::UdpPortIndependent: the Datagram layer's own 6-byte header has three
// independently-constrained fields even with no Block Driver wrapper to lean on (Magic exactly
// 0xC5, ServiceId one of five values, AddressLengths exactly 0x43 or 0x34 -- a random 6-byte
// prefix passing all three by chance is astronomically unlikely, the same multi-field-confidence
// reasoning try_parse_enip's own three independent checks already establish for a UDP-side
// decoder), so this is tried opportunistically rather than strictly port-gated -- unlike bsap.hpp's
// own BSAP-IP-native path, which has no comparably strong multi-field UDP-side check and is
// therefore UdpPort-gated instead. CODESYS_UDP_PORTS is still used to annotate a "not a
// standard/configured CODESYS UDP port" note, the same UdpPortIndependent-but-still-port-annotated
// posture cclink_ie.hpp's own CCIEFB cyclic-data path already established.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t CODESYS_TCP_PORT = 11740;          // CmpChannelServer
constexpr uint16_t CODESYS_GATEWAY_TCP_PORT = 1217;   // CmpRouter gateway protocol (engineering IDE)
constexpr uint16_t CODESYS_UDP_PORT_0 = 1740;
constexpr uint16_t CODESYS_UDP_PORT_1 = 1741;
constexpr uint16_t CODESYS_UDP_PORT_2 = 1742;
constexpr uint16_t CODESYS_UDP_PORT_3 = 1743;

// See WIRE FORMAT's own BLOCK DRIVER LAYER paragraph for how this value was derived from the wire
// bytes E8 17 01 00.
constexpr uint32_t CODESYS_TCP_BLOCK_DRIVER_MAGIC = 0x000117E8;
// Kaspersky's own stated real-world ceiling for one Block Driver-framed TCP message (512-byte PDU
// + 8-byte header) -- see WIRE FORMAT above for why this decoder treats it as a real per-frame cap
// rather than merely an observed one.
constexpr size_t CODESYS_TCP_MAX_FRAME_LENGTH = 520;

constexpr uint8_t CODESYS_DATAGRAM_MAGIC = 0xC5;

// Datagram-layer ServiceId values -- see WIRE FORMAT's own DATAGRAM/ROUTER LAYER paragraph.
std::optional<std::string> codesys_datagram_service_name(uint8_t service_id);
// true only for the one ServiceId value (0x40) whose body this decoder descends into further.
bool codesys_datagram_service_is_channel(uint8_t service_id);

// Channel-layer CommandId values -- see WIRE FORMAT's own CHANNEL LAYER paragraph.
std::optional<std::string> codesys_channel_command_name(uint8_t command_id);

// Services-layer ComponentId values -- see WIRE FORMAT's own SERVICES LAYER paragraph.
std::optional<std::string> codesys_component_name(uint16_t component_id);

struct CodesysAddress {
    size_t byte_length = 0;
    std::string hex;                    // always populated, raw bytes
    std::optional<std::string> decoded;  // "ip:port" -- only populated for a 6-byte address (see
                                          // WIRE FORMAT's own DATAGRAM/ROUTER LAYER paragraph)
};

struct CodesysDatagramHeader {
    uint8_t hops_raw = 0;
    uint8_t packet_params_raw = 0;
    uint8_t service_id_raw = 0;
    std::optional<std::string> service_name;
    uint8_t message_id_raw = 0;
    uint8_t address_lengths_raw = 0;  // 0x43 or 0x34
    CodesysAddress sender;
    CodesysAddress receiver;
};

struct CodesysChannelHeader {
    uint8_t command_id_raw = 0;
    std::optional<std::string> command_name;
    uint8_t flags_raw = 0;  // shown raw -- see WIRE FORMAT's own CHANNEL LAYER paragraph
    uint16_t channel_id = 0;
    uint32_t blk_num = 0;
    uint32_t ack_num = 0;
    uint32_t remaining_data_size = 0;
    uint32_t checksum_raw = 0;
};

struct CodesysServicesHeader {
    uint16_t protocol_id = 0;  // 0xCD55 or 0x7557
    bool encrypted = false;    // protocol_id == 0x7557
    uint16_t header_size_raw = 0;
    uint16_t component_id = 0;
    std::optional<std::string> component_name;
    uint16_t command_id = 0;
    std::optional<std::string> command_name;  // only set for the one confirmed (component,command)
                                                // pair -- see WIRE FORMAT's own SERVICES LAYER
                                                // paragraph
    uint32_t session_id = 0;
    uint32_t payload_size = 0;
    uint32_t additional_data_raw = 0;
};

struct CodesysFrame {
    bool is_tcp = false;  // false: UDP (no Block Driver layer)

    CodesysDatagramHeader datagram;

    bool has_channel = true;  // false when datagram.service_id_raw is an address/name-service
                               // value (not "channel service") -- every Channel-layer field below
                               // is default/unset in that case
    CodesysChannelHeader channel;

    bool has_services = false;  // true only once a validated Services header was found inside a
                                 // BLK (CommandId==0x01) frame's own channel payload -- see WIRE
                                 // FORMAT's own STRUCTURAL VALIDATION paragraph
    CodesysServicesHeader services;
    bool services_undecoded_payload_present = false;  // a BLK frame's channel payload didn't
                                                        // validate as a fresh Services header (see
                                                        // above) -- byte count only, in notes
    size_t services_undecoded_payload_length = 0;

    // Login/AUTH-specific decode -- see PAYLOAD DECODE SCOPE above. Only ever set when
    // services.component_id==1 && services.command_id==2.
    bool has_auth_username = false;
    std::string auth_username;
    bool auth_password_present = false;  // tag 0x11's bytes are NEVER rendered -- presence/length
                                          // only, see PAYLOAD DECODE SCOPE above
    size_t auth_password_length = 0;
    bool has_auth_session_id = false;   // response's own top-level tag 0x21
    uint32_t auth_session_id = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `tcp_payload` as one Block Driver-framed CODESYS V3 TCP message. Returns
// std::nullopt (never throws) unless the 4-byte magic and the Length/plausibility cross-check both
// hold -- see this file's own DETECTION / DISPATCH paragraph.
std::optional<CodesysFrame> try_parse_codesys_tcp(ByteSpan tcp_payload);

// Attempts to interpret `udp_payload` as one CODESYS V3 UDP datagram (no Block Driver framing --
// the Datagram/Router layer starts at byte 0). Returns std::nullopt (never throws) unless the
// three-field Datagram-layer check holds -- see this file's own DETECTION / DISPATCH paragraph.
std::optional<CodesysFrame> try_parse_codesys_udp(ByteSpan udp_payload);

// Returns the total on-the-wire byte count one Block Driver-framed TCP message declares (the
// 8-byte header's own Length field, which per Kaspersky's own description already covers those 8
// bytes), once there are enough bytes to read the 8-byte header and the magic matches -- the same
// role modbus_tcp_declared_length/enip_declared_length play for their own protocols. See
// Decoder::reassemble_tcp_payload.
std::optional<size_t> codesys_tcp_declared_length(ByteSpan payload);

// id() == "codesys", gate_kind() == TcpPortIndependent. See this file's own DETECTION / DISPATCH
// paragraph.
class CodesysTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "codesys"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return codesys_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

// id() == "codesys" (shared with CodesysTcpDecoder above, the same deliberate id()-sharing pattern
// EnipTcpDecoder/EnipUdpDecoder established first -- see enip.hpp's own comment on it),
// gate_kind() == UdpPortIndependent. No cross-packet state either (see SESSION STATE above), so
// decode() is a direct pass-through onto try_parse_codesys_udp.
class CodesysUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "codesys"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& codesys_tcp_decoder();
const ProtocolDecoder& codesys_udp_decoder();

}  // namespace conduitscope
