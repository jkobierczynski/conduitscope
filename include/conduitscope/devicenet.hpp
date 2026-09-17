// SPDX-License-Identifier: MIT
// devicenet.hpp - DeviceNet (ODVA's original CAN-bus-based CIP network) frame decoding.
//
// DeviceNet carries CIP (Common Industrial Protocol) messages directly over a CAN (Controller
// Area Network) bus, using CAN's own 11-bit standard identifiers to encode message routing --
// there is no Ethernet, no IP, no TCP/UDP anywhere in this protocol at all. This file decodes what
// a DeviceNet frame's 11-bit CAN identifier and payload mean; can_socketcan.hpp/.cpp (this
// codebase's second wholly new link layer, see that file's own header comment) decodes the pcap
// capture record and CAN frame header this file is handed. try_parse_devicenet below is given
// exactly a CanSocketcanFrame that decoder.cpp has already obtained from parse_socketcan_frame --
// this file has no pcap/capture-format knowledge of its own.
//
// Sourcing: every message-group boundary, bitmask, and named value below is cross-checked directly
// against Wireshark's own `epan/dissectors/packet-devicenet.c` (fetched and read in full during
// this task's own research phase, including its exact `MESSAGE_GROUP_*_ID`/`*_MASK` `#define`s and
// `devicenet_grp_msg*_vals`/`devicenet_service_code_vals` value-string tables) -- the same sourcing
// standard this codebase already established for STP (packet-bpdu.c, see stp.hpp) and FF-HSE
// (packet-ff.c, see ffhse.hpp). Nothing below is guessed or reverse-engineered from a single
// capture.
//
// Message-group classification (first match wins, checked in this exact order, matching the
// reference dissector's own if/else-if chain -- operates on CanSocketcanFrame::id masked to 11
// bits, i.e. only ever reached at all for a frame with !eff && !rtr && !err, see
// can_socketcan.hpp's EFF/RTR/ERR rejection this file's own try_parse_devicenet mirrors below):
//
//   Group 1 (id <= 0x03FF): a slave device's own I/O data going back to a master/scanner --
//     Source MAC ID = id & 0x003F (bits 0-5), Message ID = id & 0x03C0 (bits 6-9), named
//     0x0300/0x0340/0x0380/0x03C0 (see devicenet.cpp's group1_message_name), anything else in
//     range -> "Other Group 1 Message" (the reference dissector's own fallback string, not a gap in
//     this decoder's own table). Payload is raw I/O data -- shown as hex only, never further
//     decoded, matching the reference dissector exactly (it doesn't decode Group 1 payload bytes
//     either, absent an out-of-band device-behavior configuration this decoder has no equivalent
//     of -- see the reference source's own optional "UAT" device-behavior table, deliberately not
//     ported here).
//
//   Group 2 (0x0400 <= id <= 0x05FF): a master/scanner's own commands to a slave, plus a slave's
//     explicit/unconnected response messages -- Source MAC ID = (id & 0x01F8) >> 3 (bits 3-8),
//     Message ID = id & 0x0007 (bits 0-2), named 0-7 (see devicenet.cpp's group2_message_name).
//     Message ID 0x07 (Duplicate MAC ID Check Messages) additionally decodes its own small fixed
//     payload structure when at least 7 bytes are present and the frame isn't a CAN FD frame (see
//     "CAN FD" scope note below): byte 0's bit 0x80 is the same CIP-style Request/Response bit
//     Group 3's own service byte uses (see below; DUP_MAC_ID_RR_MASK == CIP_SC_RESPONSE_MASK ==
//     0x80 in the reference source, confirmed directly from its own `hf_devicenet_dup_mac_id_rr_
//     bit` field definition), byte 0's bottom 7 bits (mask 0x7F) are a Physical Port Number, bytes
//     1-2 are a little-endian Vendor ID, and bytes 3-6 are a little-endian Serial Number -- see
//     DeviceNetFrame's own dup-mac-id fields below. This is the one piece of "optional polish" this
//     task's own brief flagged as optional; it was implemented here because the reference source
//     was fetched and read in full for the message-group work above anyway, so verifying it
//     directly against source (rather than guessing) cost nothing extra.
//
//   Group 3 (0x0600 <= id <= 0x07BF): Unconnected/Group-2-Only-Unconnected explicit messaging --
//     Source MAC ID = id & 0x3F directly (bits 0-5 of the CAN ID itself, no shift -- unlike Group
//     2's own shifted extraction), Message ID = id & 0x01C0 (bits 6-8), named per
//     devicenet_grp_msg3_vals: 0x000/0x040/0x080/0x0C0/0x100 all "Group 3 Message" (genuinely
//     generic in the reference source too, not a gap here), 0x140 "Unconnected Explicit Response
//     Message", 0x180 "Unconnected Explicit Request Message", 0x1C0 "Invalid Group 3 Message".
//     Unlike every other group, Group 3 ALSO carries structure in its PAYLOAD, not just its CAN ID:
//       byte 0 (first payload byte): bit 0x80 = Fragmentation flag, bit 0x40 = XID flag, bits 0x3F
//         = destination MAC ID (MESSAGE_GROUP_3_FRAG_MASK/_XID_MASK/_MAC_ID_MASK in the reference
//         source).
//       When Fragmentation is set: this is a fragmented message. The reference dissector itself
//         does NOT reassemble fragments -- its own `dissect_devicenet` calls
//         `proto_tree_add_expert_remaining(content_tree, pinfo, &ei_devicenet_frag_not_supported,
//         tvb, offset)` right after a literal `/* TODO: Handle fragmentation */` comment. This
//         decoder deliberately matches that exact gap rather than attempting reassembly of its own
//         invention -- DeviceNetFrame::is_fragmented is set and named, nothing past byte 0 is
//         decoded for a fragmented message, and this is a documented upstream limitation this
//         decoder ports faithfully, not an omission unique to this port.
//       When Fragmentation is clear: byte 1 (second payload byte) is a CIP-style service/request-
//         response byte -- top bit 0x80 (CIP_SC_RESPONSE_MASK in the reference source, and in
//         EtherNet/IP's own CIP explicit messaging, see enip.hpp) = response (vs. request), bottom
//         7 bits (CIP_SC_MASK == 0x7F) = the CIP service code. This is EXACTLY the same request/
//         response-bit-plus-7-bit-service-code convention EtherNet/IP's own CIP layer already
//         uses -- see enip.hpp's CipMessage::is_response/service and cip_service_name, which this
//         file reuses directly rather than duplicating a second copy of the generic CIP service-
//         code name table (see devicenet_service_name in devicenet.cpp). DeviceNet defines four
//         service codes beyond the generic CIP set, all checked BEFORE cip_service_name is ever
//         called (see devicenet_service_name): 0x4B "Open Explicit Message Connection Request",
//         0x4C "Close Connection Request", 0x4D "Device Heartbeat Message", 0x4E "Device Shutdown
//         Message" (SC_OPEN_EXPLICIT_MESSAGE/SC_CLOSE_EXPLICIT_MESSAGE/SC_DEVICE_HEARTBEAT_MESSAGE/
//         SC_DEVICE_SHUTOWN_MESSAGE in the reference source's own `devicenet_service_code_vals`) --
//         note these four codes mean something COMPLETELY DIFFERENT from EtherNet/IP's own
//         Rockwell-tag-addressing use of some of the same numeric values (e.g. 0x4C is Read_Tag
//         under EtherNet/IP's own symbolic addressing, but Close Connection Request under
//         DeviceNet) -- see cip_service_name's own comment in enip.cpp for exactly why calling it
//         with have_path=true/is_symbolic=false/is_conn_mgr=false from here avoids ever picking up
//         that unrelated table by accident. Beyond the service code name itself, this decoder does
//         NOT further decode a Group 3 explicit message's own request path/data -- see the "Out of
//         scope" section below.
//
//   Group 4 (0x07C0 <= id <= 0x07EF): Message ID = id & 0x3F directly, named per
//     devicenet_grp_msg4_vals: 0x2C "Communication Faulted Response Message", 0x2D "Communication
//     Faulted Request Message", 0x2E "Offline Ownership Response Message", 0x2F "Offline Ownership
//     Request Message", anything else in range -> "Reserved Group 4 Message" (the reference
//     dissector's own fallback, not a gap here). No MAC ID extraction is defined for Group 4 in the
//     reference dissector at all, so none is invented here either.
//
//   0x07F0-0x07FF: the reference dissector has NO handling for this range at all -- its own
//     if/else-if chain simply falls through with nothing decoded once id > MESSAGE_GROUP_4_ID
//     (0x07EF). This decoder matches that: DeviceNetFrame::group stays 0 ("Unclassified"), only the
//     raw CAN ID is shown, and a note explains why -- not a guessed fifth message group.
//
// Explicitly out of scope for this release (named/recognized only where structurally cheap,
// matching this codebase's established "recognized but not this release's problem" posture -- see
// e.g. STP's Cisco PVST+/SPB out-of-scope section in stp.hpp):
//   - CAN FD frames (CanSocketcanFrame::fd): DeviceNet as a protocol predates CAN FD entirely and
//     never sets FD Flags' CANFD_FDF bit -- can_socketcan.hpp still recognizes and surfaces the
//     flag structurally (so this decoder never crashes or misreads a CAN FD frame's larger
//     payload), but this decoder does not attempt Group 1 I/O / Group 2 Duplicate-MAC-ID-Check /
//     Group 3 service-byte payload decoding for an FD frame at all -- only the CAN-ID-derived
//     message-group classification (which needs no payload access) is still shown. See
//     DeviceNetFrame::fd below.
//   - Extended (29-bit) IDs, RTR frames, error frames: not valid DeviceNet at all -- rejected the
//     same way the reference dissector's own `dissect_devicenet` rejects them, quite literally: its
//     very first check is `if (can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG | CAN_EFF_FLAG)) return
//     0;`, which try_parse_devicenet below mirrors exactly (returns std::nullopt).
//   - Group 3 fragmentation reassembly: matches the reference dissector's own unimplemented TODO,
//     see above -- not a gap unique to this port.
//   - Full CIP object/class/instance/attribute request-path decoding within a Group 3 explicit
//     message's own payload (beyond the destination MAC ID / service code bytes already decoded
//     above): EtherNet/IP's own enip.cpp has much richer CIP path decoding (CipPath, EPATH logical
//     segments, the ANSI Extended Symbol segment for Rockwell named-tag addressing -- see
//     enip.hpp), none of which this file replicates. The reference DeviceNet dissector itself only
//     partially decodes a handful of specific services' (Open/Close Explicit Message) own small
//     fixed request/response bodies past the service byte (see packet-devicenet.c's own
//     SC_OPEN_EXPLICIT_MESSAGE/SC_CLOSE_EXPLICIT_MESSAGE cases) -- this decoder does not replicate
//     even that: the service code name is decoded, but the bytes following it are shown only as
//     raw hex (via decoder.cpp, the same "structural only" treatment CIP I/O's own assembly data
//     gets in enip.hpp), matching this task's own explicit scope directive that decoding the
//     service code name is sufficient here.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"

namespace conduitscope {

// One decoded DeviceNet frame -- see this file's header comment for the full message-group
// classification and every documented scope decision.
struct DeviceNetFrame {
    uint16_t can_id = 0;  // the masked 11-bit standard CAN identifier (0-0x7FF) this classification
                            // was derived from -- see CanSocketcanFrame::id

    // 1-4 for a classified message group, or 0 for the unclassified 0x07F0-0x07FF range (see this
    // file's header comment's last bullet) -- never any other value.
    int group = 0;
    std::string group_name;         // "Group 1"/"Group 2"/"Group 3"/"Group 4"/"Unclassified (0x07F0-0x07FF)"
    std::string message_type_name;  // per-group named message type -- always set except for the
                                      // unclassified range

    // Groups 1-3 only (Group 4 has no MAC ID extraction defined at all, see file header comment).
    bool has_source_mac_id = false;
    uint8_t source_mac_id = 0;  // 0-63

    // Group 3 only -- decoded from the FIRST PAYLOAD BYTE, not the CAN ID (see file header
    // comment). False when Group 3 was classified by CAN ID but the frame carries no payload byte
    // at all to read this from (a truncated/empty Group 3 frame).
    bool has_group3_header = false;
    bool is_fragmented = false;  // Fragmentation flag (0x80) -- see "Out of scope" above; nothing
                                   // past this byte is decoded when true
    bool is_xid = false;         // XID flag (0x40)
    uint8_t dest_mac_id = 0;     // only meaningful when has_group3_header; bits 0x3F of byte 0

    // Group 3, non-fragmented only -- the CIP-style service/request-response byte (the SECOND
    // payload byte, right after the destination-MAC-ID byte above). See enip.hpp's
    // cip_service_name (reused directly, see devicenet_service_name in devicenet.cpp) and this
    // file's header comment's four DeviceNet-specific service codes (0x4B-0x4E).
    bool has_cip_service = false;
    bool cip_is_response = false;
    uint8_t cip_service = 0;  // as seen on the wire, WITHOUT the 0x80 reply bit (already stripped)
    std::string cip_service_name;

    // Group 2, message ID 0x07 (Duplicate MAC ID Check Messages) only -- see file header comment's
    // Group 2 paragraph. Set only when the frame isn't a CAN FD frame and at least 7 payload bytes
    // are present.
    bool has_dup_mac_id_check = false;
    bool dup_mac_id_is_response = false;  // byte 0 bit 0x80, same RR convention as Group 3's own
    uint8_t dup_mac_id_physical_port_number = 0;  // byte 0 bits 0x7F
    uint16_t dup_mac_id_vendor_id = 0;            // bytes 1-2, little-endian
    uint32_t dup_mac_id_serial_number = 0;        // bytes 3-6, little-endian

    // Mirrors CanSocketcanFrame::fd -- see this file's header comment's CAN FD out-of-scope note.
    // When true, only the CAN-ID-derived fields above (group/group_name/message_type_name/
    // has_source_mac_id/source_mac_id) are populated; every payload-derived field above stays at
    // its default.
    bool fd = false;

    ByteSpan payload;  // the raw payload bytes (I/O data or explicit-message body) -- rendered only
                        // as hex by decoder.cpp; this decoder never value-decodes it beyond the
                        // Group 3 header/service bytes and Group 2 Duplicate-MAC-ID-Check fields above

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret one already-parsed SocketCAN frame as a DeviceNet frame. Returns
// std::nullopt (never throws) when `can.eff || can.rtr || can.err` (not a valid DeviceNet frame
// shape at all -- mirrors the reference dissector's own unconditional rejection of exactly these
// three flags, see this file's header comment's "Out of scope" section) -- this is the ONLY
// rejection condition; every masked 11-bit CAN ID value, including the unclassified 0x07F0-0x07FF
// range, still returns a DeviceNetFrame (with group == 0 for that range), matching the reference
// dissector's own behavior of accepting (col_set_str "DeviceNet") any non-EFF/RTR/ERR standard-ID
// CAN frame on this link, whether or not it recognizes a specific message group within it.
std::optional<DeviceNetFrame> try_parse_devicenet(const CanSocketcanFrame& can);

}  // namespace conduitscope
