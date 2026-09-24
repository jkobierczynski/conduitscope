// SPDX-License-Identifier: Apache-2.0
// zigbee.hpp - Zigbee NWK (Network) + APS (Application Support Sub-layer) + ZDP (Zigbee Device
// Profile) decoding, riding on the IEEE 802.15.4 MAC framing ieee802154.hpp/.cpp decodes.
//
// try_parse_zigbee below is handed exactly an already-parsed Ieee802154Frame (see ieee802154.hpp) --
// this file has no pcap/capture-format knowledge of its own, the same "one file per layer, each
// handed the layer below it already decoded" shape devicenet.hpp has relative to can_socketcan.hpp.
//
// SOURCING: every field/mask/byte-offset/cluster-payload-shape below is taken directly from a
// from-source research pass over Wireshark's own epan/dissectors/packet-zbee-nwk.c,
// packet-zbee-security.c, packet-zbee-aps.c, packet-zbee-zdp.c, packet-zbee-zdp-discovery.c,
// packet-zbee-zdp-management.c, and packet-zbee-zdp-binding.c -- literal source citations
// (file/function/line) were captured for every claim, including several points where the research
// corrected an initial assumption (the NWK/APS Auxiliary Security Header's Extended Source presence
// being gated by a dedicated Extended Nonce bit rather than by Key Identifier value; APS Frame Type
// 0x03 being named Inter-PAN rather than Reserved; Mgmt_Permit_Joining having a real 0x8036 response
// cluster; Bind/Unbind's Dest Addr Mode having only two legal values, not a generic multi-mode
// scheme). Treated as this codebase's strongest existing sourcing tier (the same standing CC-Link
// IE's own two-source verification has).
//
// USER-CONFIRMED SCOPE this file ships under (see docs/DEVELOPMENT.md's roadmap item for the full
// record):
//   - NWK and APS header fields (addressing, routing, cluster ID, profile ID, security-in-use flags,
//     ...) are decoded STRUCTURALLY ALWAYS -- these fields are unencrypted on the wire even when the
//     payload past them is encrypted (see this file's own "encryption scope" notes on
//     ZigbeeNwkFrame::security / ZigbeeApsFrame::security below).
//   - Full ZDP decode (the clusters listed on ZigbeeZdpFrame below) whenever APS-layer security is
//     NOT in use. When APS security IS in use, the APS header is still decoded (as always) but ZDP
//     is reported as opaque/encrypted -- see ZigbeeFrame::aps_payload_opaque.
//   - When NWK-layer security is in use, the entire NWK payload (including all of APS) is encrypted
//     and structurally invisible -- only the NWK header fields are visible. See
//     ZigbeeFrame::nwk_payload_encrypted.
//   - NO decryption capability at all -- matches this codebase's universal "leave encrypted payloads
//     opaque, never attempt to decrypt" precedent (the same posture TLS/DTLS/IPsec ESP already have
//     elsewhere in this codebase).
//   - NO ZCL (Zigbee Cluster Library, the general application-command framework -- On/Off, Level
//     Control, Color Control, etc.) -- explicitly out of scope, the same kind of "too large and
//     generic, no OT-specific structural value on its own" boundary this codebase already drew for
//     OPC Classic/EtherNet/IP's CIP object model (see docs/DEVELOPMENT.md). Structurally, this falls
//     out naturally: ZDP always rides on APS Profile ID 0x0000; any Data-type APS frame with a
//     DIFFERENT Profile ID is a ZCL/application-profile frame and is reported structurally (cluster
//     ID, profile ID, endpoints -- all already decoded as part of the APS header) but its own payload
//     is not decoded -- see ZigbeeFrame::zdp_absent_reason for this specific case.
//   - Zigbee Green Power (a separate low-power extension sub-protocol, its own NWK Frame Control
//     Field encoding under Protocol Version 3) was never explicitly decided with the user during this
//     task and is treated as OUT OF SCOPE for this first pass -- named here as a deliberate,
//     documented boundary rather than a silent omission. Structurally this decoder still reports the
//     NWK header of a Green Power frame correctly (Protocol Version 3 is just another value of the
//     same version field every other NWK frame carries), but it does not attempt Green Power's own,
//     substantially different NWK-payload command set.
//
// A FURTHER, PRAGMATIC SCOPE DECISION made directly against the research (documented, not silently
// applied): every "2007+ vs pre-2007" conditional field this file implements is implemented ONLY for
// the 2007+ (ZigBee PRO, protocol version 2 -- ZBEE_VERSION_2007 in the reference source) shape,
// which is what essentially all real-world Zigbee 3.0/Home Automation/etc. traffic uses. The
// pre-2007 (ZigBee 2004) alternate encodings the research flagged (1-byte Cluster ID fields in
// APS/ZDP, a different Neighbor Table Entry layout, no APS Counter field at all, ...) are not
// implemented -- the research report's own recommendation ("I'd recommend not bothering unless you
// expect to sniff genuinely ancient ZigBee-2004 gear") is followed directly. A pre-2007 frame is
// still structurally recognized (NWK Protocol Version is always decoded) but ZDP/APS field-presence
// decisions past that point assume 2007+ shapes; a genuinely pre-2007 capture may misparse past the
// NWK header as a result -- flagged here rather than silently risked.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ieee802154.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// Shared shape for BOTH the NWK layer's and the APS layer's own Auxiliary Security Header --
// literally the same function (dissect_zbee_secure) and byte layout in the reference source for
// both layers, and a DIFFERENT, unrelated layout from the IEEE 802.15.4 MAC-layer Auxiliary Security
// Header (ieee802154.hpp's Ieee802154SecurityHeader) despite the similar name. The one field that
// most differs from the MAC-layer header's own shape: Extended Source presence here is gated by a
// dedicated Extended Nonce bit, NOT by the Key Identifier value the way the MAC layer's Key ID Mode
// gates its own Key Source field -- see this file's header comment's sourcing note.
struct ZigbeeSecurityHeader {
    uint8_t security_level = 0;  // bits 0-2 -- same 0-7 numeric meaning as the MAC layer's own field
    uint8_t key_id = 0;          // bits 3-4: 0=Link Key, 1=Network Key, 2=Key-Transport Key,
                                   // 3=Key-Load Key -- only Network Key (1) gates key_seqno below
    bool extended_nonce = false;  // bit 5 -- gates ext_source presence (see file header comment)
    bool verified_frame_counter = false;  // bit 6 (newer/R23 usage) -- decoded for completeness,
                                            // not otherwise used by this decoder

    uint32_t frame_counter = 0;  // always present (4 bytes LE)

    bool has_ext_source = false;  // true iff extended_nonce
    uint64_t ext_source = 0;

    bool has_key_seqno = false;  // true iff key_id == Network Key (1)
    uint8_t key_seqno = 0;

    // Bytes reserved at the tail of the secured region for a MIC, from security_level -- same 0/4/8/
    // 16-byte table the MAC layer's own MIC length uses (numerically identical shape, independently
    // confirmed against the reference source -- see this file's header comment).
    size_t mic_length = 0;
};

// One decoded Zigbee NWK (Network) layer frame -- see this file's header comment for sourcing.
struct ZigbeeNwkFrame {
    uint16_t fcf = 0;
    uint8_t frame_type = 0;  // 0=Data, 1=NWK Command, 3=Inter-PAN (2 has no defined meaning)
    uint8_t version = 0;     // 0=Prototype, 1=2004, 2=2007 (ZigBee PRO), 3=Green Power
    uint8_t discover_route = 0;  // 0=Suppress, 1=Enable, 3=Force (2 undefined)
    bool multicast = false;
    bool security = false;       // gates NWK-layer encryption -- see this file's header comment
    bool source_route = false;
    bool ext_dst = false;
    bool ext_src = false;
    bool end_device_initiator = false;

    bool is_interpan = false;  // frame_type == 3 -- see this file's header comment: Inter-PAN NWK
                                 // "headers" are just the 2-byte FCF, everything past it is a
                                 // ZLL/Inter-PAN application-profile payload this decoder does not
                                 // interpret further

    // Present only when !is_interpan.
    uint16_t dst = 0;
    uint16_t src = 0;
    uint8_t radius = 0;
    uint8_t seqno = 0;

    bool has_ext_dst = false;  // version >= 2007 && ext_dst flag
    uint64_t ext_dst_addr = 0;
    bool has_ext_src = false;  // version >= 2007 && ext_src flag
    uint64_t ext_src_addr = 0;

    bool has_multicast_control = false;  // version >= 2007 && multicast flag
    uint8_t mcast_mode = 0;              // 0=Non-member, 1=Member
    uint8_t mcast_radius = 0;
    uint8_t mcast_max_radius = 0;

    bool has_source_route = false;  // version >= 2007 && source_route flag
    uint8_t relay_count = 0;
    uint8_t relay_index = 0;
    std::vector<uint16_t> relay_list;

    bool has_security = false;  // mirrors `security` above, set once the aux header itself is
                                  // successfully read (may stay false on a truncated frame even
                                  // when `security` is true -- see malformed/notes)
    ZigbeeSecurityHeader security_header;

    bool malformed = false;
    std::vector<std::string> notes;
};

// One decoded Zigbee APS (Application Support Sub-layer) frame.
struct ZigbeeApsFrame {
    uint8_t fcf = 0;
    uint8_t frame_type = 0;      // 0=Data, 1=Command, 2=Ack, 3=Inter-PAN
    uint8_t delivery_mode = 0;   // 0=Unicast, 1=Indirect (pre-2007 only), 2=Broadcast, 3=Group (2007+)
    bool indirect_or_ack_format = false;  // FCF bit 0x10 -- "Indirect Address Mode" pre-2007,
                                            // "Acknowledgement Format" 2007+ (same bit, reinterpreted
                                            // -- see this file's header comment)
    bool security = false;    // gates APS-layer (ZDP) encryption -- see this file's header comment
    bool ack_req = false;
    bool ext_header = false;

    bool has_dst_endpoint = false;
    uint8_t dst_endpoint = 0;
    bool has_group_address = false;
    uint16_t group_address = 0;
    bool has_cluster_profile = false;  // Cluster ID and Profile ID always travel together
    uint16_t cluster_id = 0;
    uint16_t profile_id = 0;
    bool has_src_endpoint = false;
    uint8_t src_endpoint = 0;
    bool has_counter = false;  // version >= 2007 && frame_type != Inter-PAN
    uint8_t counter = 0;

    bool has_ext_header = false;
    uint8_t fragmentation = 0;  // 0=None, 1=First, 2=Middle/subsequent
    bool has_block_number = false;
    uint8_t block_number = 0;
    bool has_frag_ack_bitmask = false;
    uint8_t frag_ack_bitmask = 0;

    bool has_security = false;
    ZigbeeSecurityHeader security_header;

    bool has_command_id = false;  // frame_type == Command
    uint8_t command_id = 0;
    std::string command_name;

    bool malformed = false;
    std::vector<std::string> notes;
};

// One decoded ZDP (Zigbee Device Profile) message -- see this file's header comment's cluster-table
// sourcing note. Field values are rendered as ready-to-display "Name: value" strings in `fields`
// rather than one dedicated struct member per cluster's own payload shape (ZDP has 13 distinct
// request/response payload shapes -- a dedicated field per shape would mean ~13x the struct surface
// for no real gain over a self-describing string list a renderer can just print, the same pattern
// S7comm-Plus's own item_tags/value_summaries already established in this codebase for a similarly
// shaped "one generic operation, many possible typed values" problem -- see s7commplus.hpp).
struct ZigbeeZdpFrame {
    uint8_t seqno = 0;         // Transaction Sequence Number, always the first byte
    uint16_t cluster = 0;      // == the carrying APS frame's own Cluster ID (not repeated on the
                                // wire inside ZDP itself -- see this file's header comment)
    std::string cluster_name;  // e.g. "NWK_addr", "Mgmt_Permit_Joining" -- WITHOUT a Request/Response
                                // suffix; see is_response for that
    bool is_response = false;  // cluster & 0x8000

    // True only for a cluster this decoder actually has a payload parser for (the 13 named in this
    // file's header comment). False means only `cluster`/`cluster_name`/`seqno` above were
    // determined; `fields` stays empty and a note explains the payload itself wasn't decoded (a ZDP
    // cluster the research report didn't cover, or a malformed/too-short payload for a cluster this
    // decoder does recognize).
    bool recognized = false;

    std::string summary;               // one-line human-readable summary of this ZDP message
    std::vector<std::string> fields;   // "Name: value" strings, in wire order
    std::vector<std::string> notes;
};

// One decoded Zigbee frame, all layers -- the type carried by DecodedPacket::result for
// protocol=="zigbee" (see zigbee.cpp's ZigbeeDecoder and decoder.cpp's own LINKTYPE_IEEE802_15_4_*
// branches). Zigbee is a zero-flat-field migrated protocol from the start (like TwinCAT/DeviceNet):
// every field lives here, not on DecodedPacket itself.
struct ZigbeeFrame {
    Ieee802154Frame mac;  // the full MAC-layer decode this frame's NWK layer (if any) rides on

    // True only when frame_type==Data, the MAC layer wasn't malformed, and the MAC payload was at
    // least long enough to read the 2-byte NWK FCF -- the only case every field on `nwk` below is
    // meaningful. See nwk_absent_reason when false.
    bool nwk_present = false;
    std::string nwk_absent_reason;
    ZigbeeNwkFrame nwk;

    // Set instead of aps_present below when nwk.security is true -- the entire NWK payload
    // (including all of APS) is ciphertext; see this file's header comment.
    bool nwk_payload_encrypted = false;
    size_t nwk_encrypted_payload_length = 0;

    bool aps_present = false;
    std::string aps_absent_reason;
    ZigbeeApsFrame aps;

    // Set instead of zdp_present below when aps.security is true -- the APS header itself is still
    // fully decoded (see `aps` above) but everything past its Auxiliary Security Header is
    // ciphertext.
    bool aps_payload_encrypted = false;
    size_t aps_encrypted_payload_length = 0;

    bool zdp_present = false;
    std::string zdp_absent_reason;
    ZigbeeZdpFrame zdp;

    std::string summary;
    std::vector<std::string> notes;
};

// Named accessors used by zigbee.cpp/output.cpp/decoder.cpp alike, so no caller needs its own copy.
const char* zigbee_nwk_frame_type_name(uint8_t frame_type);
const char* zigbee_nwk_version_name(uint8_t version);
const char* zigbee_nwk_discover_route_name(uint8_t discover_route);
const char* zigbee_aps_frame_type_name(uint8_t frame_type);
const char* zigbee_aps_delivery_mode_name(uint8_t delivery_mode);
const char* zigbee_security_key_id_name(uint8_t key_id);
std::string zigbee_aps_command_name(uint8_t command_id);  // includes the raw hex value for an
                                                             // unrecognized id, so this is a
                                                             // std::string, not a const char* like
                                                             // every fully-enumerated table above
const char* zigbee_zdp_status_name(uint8_t status);
// Base (request) cluster id -> name, e.g. 0x0000 or 0x8000 both -> "NWK_addr". Empty string for a
// cluster this decoder doesn't recognize.
std::string zigbee_zdp_cluster_name(uint16_t cluster);

// Attempts to interpret an already-parsed Ieee802154Frame as carrying a Zigbee NWK frame. Returns
// std::nullopt (never throws) when mac.frame_type != Data -- a Beacon/Ack/MAC-Command frame never
// carries a Zigbee NWK payload at all (see ieee802154.hpp), so it is not this decoder's concern;
// decoder.cpp reports those structurally under its own generic non-Zigbee MAC-frame fallback.
// For any Data-type frame, this ALWAYS returns a ZigbeeFrame (never nullopt) -- even one whose NWK
// layer turns out to be inaccessible (MAC-layer security enabled, a malformed MAC header, ...) is
// still "this decoder's concern to explain", the same "recognized, degrade honestly" posture
// devicenet.hpp's own try_parse_devicenet takes for its own unclassified CAN ID range.
std::optional<ZigbeeFrame> try_parse_zigbee(const Ieee802154Frame& mac);

// Zigbee, wrapped for the ProtocolDecoder interface (protocol_decoder.hpp) -- GateKind::LinkType,
// the second protocol on this gate (DeviceNet was the first). See this file's header comment and
// ieee802154.hpp's own file header comment for why Zigbee needs TWO link types
// (LINKTYPE_IEEE802_15_4_WITHFCS and LINKTYPE_IEEE802_15_4_TAP) and the design this codebase chose
// for that: decoder.cpp's own two link-type branches each call the matching
// parse_ieee802154_withfcs/parse_ieee802154_tap entry point directly (ieee802154.hpp) to get an
// Ieee802154Frame, then both converge on calling try_parse_zigbee(...) directly -- NOT through this
// class's own decode() method, which cannot tell WITHFCS bytes from TAP bytes from a bare ByteSpan
// alone (see ieee802154.hpp's header comment for why guessing that from the bytes themselves was
// rejected as a design). ZigbeeDecoder::decode() below still exists and works (assuming its ByteSpan
// argument is WITHFCS-framed, matching link_type()'s own value) so this class remains a fully
// functional, self-contained GateKind::LinkType decoder in the registry (link_type_registry(),
// protocol_registry.hpp) -- it's just not decoder.cpp's own call path for either link type, the same
// "audit-trail-representative-only" posture ProtocolDecoder::link_type()'s own doc comment already
// describes for exactly this situation. link_type() returns LINKTYPE_IEEE802_15_4_WITHFCS
// specifically (not TAP) since it's the more common/simpler of the two capture formats -- an
// arbitrary but documented choice, not a claim that TAP is somehow less supported.
class ZigbeeDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "zigbee"; }
    GateKind gate_kind() const override { return GateKind::LinkType; }
    std::optional<uint32_t> link_type() const override;  // see zigbee.cpp -- returns
                                                            // LINKTYPE_IEEE802_15_4_WITHFCS's numeric
                                                            // value (195) without depending on
                                                            // pcap_reader.hpp from this header
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& zigbee_decoder();

}  // namespace conduitscope
