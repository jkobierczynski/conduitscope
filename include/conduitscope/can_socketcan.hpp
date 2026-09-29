// SPDX-License-Identifier: Apache-2.0
// can_socketcan.hpp - Linux SocketCAN pcap capture framing (pcap LINKTYPE_CAN_SOCKETCAN == 227).
//
// This is the second wholly new link-layer this codebase has added (the first was classic IEEE
// 802.3/LLC framing for STP -- see link_layer.hpp's file header and stp.hpp). Unlike that one,
// this isn't a variant of Ethernet framing: CAN (Controller Area Network) is a completely separate
// physical/link layer with no Ethernet header, no MAC addresses, no EtherType -- a pcap file
// captured from a CAN bus (e.g. `candump -l`, `tcpdump -i can0`, or Wireshark capturing a SocketCAN
// interface on Linux) carries one small fixed-format record per CAN frame, directly, with nothing
// above it. That is why this lives in its own pair of files rather than inside link_layer.hpp/.cpp:
// it is not additive to Ethernet parsing the way STP's LLC/SNAP recognition was, but an entirely
// parallel, unrelated link type, requiring its own entry in pcap_reader.hpp's LinkType enum and its
// own top-level branch in Decoder::decode (see decoder.cpp), never reached through parse_ethernet.
//
// DeviceNet (see devicenet.hpp) is the only protocol in this codebase that rides on this link layer
// today -- SocketCAN framing itself is protocol-agnostic (any CAN application protocol's frames
// would show up in a capture this way: DeviceNet, CANopen, J1939, or raw CAN traffic with no
// higher-layer protocol at all), but decoding what a given CAN ID/payload actually means is
// entirely DeviceNet's own job in devicenet.cpp; this file only understands the pcap capture record
// shape and CAN frame header/flag bits, nothing about DeviceNet's own message-group semantics.
//
// Sourcing (verified directly against libpcap's and tcpdump.org's own canonical sources, not
// reverse-engineered from a single capture): libpcap's `pcap/can_socketcan.h` header (`struct
// pcap_can_socketcan_hdr`) and the Linux kernel's `Documentation/networking/can.rst` (the in-kernel
// `struct can_frame`/`canid_t` this capture format mirrors byte-for-byte), cross-checked against
// tcpdump.org's LINKTYPE_CAN_SOCKETCAN registry page, which is explicit that "The CAN ID and flags
// field is in big-endian byte order" -- the one easy mistake to make here, since the in-kernel
// `canid_t` itself is a native-endian (host/little-endian-on-x86) 32-bit value; what actually lands
// in a capture file is that same value byte-swapped to big-endian by the capture tooling, not
// written out raw. Every offset/bit below is this task's own from-source derivation, the same
// sourcing standard stp.hpp/ffhse.hpp already established (fetch and read the primary source,
// don't guess from a single observed capture).
//
// Wire format (8-byte fixed header immediately followed by `payload_length` bytes of payload; no
// trailer, no padding beyond what payload_length declares):
//   CAN ID + flags   @0  4 bytes, BIG-ENDIAN  -- see "CAN ID + flags" below
//   Payload Length    @4  1 byte  -- 0-8 for classic CAN, 0-64 when the FD flag (below) is set
//                                     (CAN FD's extended sizes: 0,1,2,...,8,12,16,20,24,32,48,64 --
//                                     not validated against that discrete set, just clamped to
//                                     what was actually captured, see payload/truncated below)
//   FD Flags           @5  1 byte  -- bit 0x04 (CANFD_FDF in the kernel source) marks a CAN FD
//                                      frame vs. classic CAN 2.0; the other bits (CANFD_BRS bit-
//                                      rate-switch, CANFD_ESI error-state-indicator) are read into
//                                      fd_flags but not individually decoded -- DeviceNet predates
//                                      CAN FD and never sets them (see devicenet.hpp's out-of-scope
//                                      note this feeds)
//   Reserved             @6  1 byte  -- always 0 on the wire; read but not surfaced/validated,
//                                        matching this codebase's usual non-verification-of-
//                                        reserved-bytes posture (e.g. EtherNet/IP's Options field,
//                                        see enip.hpp)
//   Reserved              @7  1 byte  -- same as above
//   Payload                @8  `payload_length` bytes
//
// CAN ID + flags (the 4-byte big-endian value @0 above) -- top 3 bits are flags, bottom 29 bits are
// the identifier (masked differently depending on which top bit is set):
//   bit 31 (0x80000000) EFF  -- Extended Frame Format: a 29-bit extended CAN identifier (SAE J1939
//                                and others use this; DeviceNet never does -- see devicenet.hpp's
//                                rejection-matching-Wireshark note). When clear, the frame uses the
//                                classic 11-bit standard identifier instead (mask 0x7FF).
//   bit 30 (0x40000000) RTR  -- Remote Transmission Request: requests data from another node,
//                                carrying no payload regardless of what Payload Length claims. Not
//                                a DeviceNet frame shape either.
//   bit 29 (0x20000000) ERR  -- Error frame: a bus-level error condition, not ordinary data. Not a
//                                DeviceNet frame shape either.
//   bits 28-0 (0x1FFFFFFF)   -- the identifier: only the bottom 11 bits (0x7FF) are meaningful when
//                                EFF is clear (standard ID); all 29 bits when EFF is set (extended
//                                ID). Always read as the full 29-bit masked value into
//                                CanSocketcanFrame::id regardless of EFF, since a caller may want
//                                it even for a frame this decoder won't call valid DeviceNet.
//
// EFF/RTR/ERR are independent bits (in principle more than one could be set on malformed wire
// data), all three surfaced here without judgment -- this file does not decide DeviceNet validity;
// devicenet.hpp's try_parse_devicenet rejects a frame with any of them set, mirroring Wireshark's
// packet-devicenet.c exactly (see that file's header comment for the rejection logic and citation).
//
// Truncation handling: this codebase's established "degrade tolerantly, never crash" posture (see
// parse_ethernet's snaplen-truncation fallback, or stp.hpp's truncated-BPDU notes) applies here
// too. parse_socketcan_frame throws ParseError (Decoder::decode's outer catch turns it into a
// "parse-error" packet, exactly like an undersized Ethernet frame) only when fewer than the fixed
// 8-byte header is present -- there's nothing meaningful left to decode without even the declared
// payload length. When the header IS fully present but fewer than `payload_length` payload bytes
// were actually captured (a snaplen-truncated or otherwise short capture), it does NOT throw: it
// clamps the payload to what's present and sets `truncated`, the same tolerant shape
// EthernetFrame::llc_payload's trimming notes already use elsewhere -- devicenet.cpp surfaces that
// as a note rather than failing the whole packet.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint32_t CAN_EFF_FLAG = 0x80000000;  // Extended Frame Format (29-bit ID) -- see file header
constexpr uint32_t CAN_RTR_FLAG = 0x40000000;  // Remote Transmission Request
constexpr uint32_t CAN_ERR_FLAG = 0x20000000;  // Error frame
constexpr uint32_t CAN_EFF_MASK = 0x1FFFFFFF;  // 29-bit extended identifier mask
constexpr uint32_t CAN_SFF_MASK = 0x000007FF;  // 11-bit standard identifier mask

constexpr uint8_t CANFD_FDF_FLAG = 0x04;  // fd_flags bit marking a CAN FD (vs. classic CAN 2.0) frame

// One decoded SocketCAN pcap capture record -- see this file's header comment for the exact wire
// layout every field below comes from.
struct CanSocketcanFrame {
    uint32_t can_id_raw = 0;  // the full big-endian-on-the-wire 32-bit CAN ID + flags value, as read
    bool eff = false, rtr = false, err = false;  // see "CAN ID + flags" above
    // The identifier, masked by CAN_EFF_MASK when eff, else CAN_SFF_MASK -- always populated
    // regardless of eff/rtr/err, so a caller can inspect it even for a non-DeviceNet frame shape.
    // DeviceNet only cares about this value when !eff && !rtr && !err (see devicenet.hpp): the
    // 11-bit standard CAN identifier its message-group classification operates on.
    uint32_t id = 0;

    uint8_t payload_length_declared = 0;  // the wire's own Payload Length byte, unclamped
    uint8_t fd_flags = 0;                 // the wire's own FD Flags byte, raw
    bool fd = false;                      // fd_flags & CANFD_FDF_FLAG -- see file header comment

    // The payload, clamped to whatever was actually captured -- see file header comment's
    // "Truncation handling" paragraph. size() may be less than payload_length_declared when
    // `truncated` is set; never more.
    ByteSpan payload;
    bool truncated = false;

    std::vector<std::string> notes;
};

// Parses one SocketCAN pcap capture record (the bytes of one pcap packet record, for a capture
// whose declared LINKTYPE_CAN_SOCKETCAN link type this decoder recognizes -- see pcap_reader.hpp).
// Throws ParseError only when fewer than the 8-byte header is present; a header-present-but-
// payload-short frame is handled tolerantly instead -- see "Truncation handling" above.
CanSocketcanFrame parse_socketcan_frame(ByteSpan frame);

}  // namespace conduitscope
