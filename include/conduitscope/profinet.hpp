// SPDX-License-Identifier: Apache-2.0
// profinet.hpp - PROFINET RT (EtherType 0x8892) decoding: FrameID classification, DCP
// (Discovery and Configuration Protocol) request/response decoding, and cyclic real-time I/O
// data framing.
//
// Unlike every other protocol this tool decodes, PROFINET RT rides directly on raw Ethernet --
// there is no IPv4/UDP/TCP layer at all (the same is true of EtherCAT and IEC 61850 GOOSE/SV,
// see link_layer.hpp's ETHERTYPE_* constants). A PROFINET RT frame's payload (immediately after
// the EtherType -- or after a single 802.1Q VLAN tag, already unwrapped by parse_ethernet by the
// time this decoder sees it) begins with a 2-byte FrameID, big-endian, which is the sole
// discriminator for everything that follows -- there is no further common header. Every
// multi-byte field this decoder reads (FrameID, Xid, ResponseDelay, DCPDataLength,
// DCPBlockLength, VendorID/DeviceID, CycleCounter) is big-endian, confirmed against Wireshark's
// own `packet-pn-rt.c`/`packet-pn-dcp.c` dissector sources (tvb_get_ntohs / ENC_BIG_ENDIAN
// throughout) -- unlike EtherNet/IP/CIP (enip.hpp), which is little-endian almost everywhere;
// PROFINET instead matches the big-endian convention this codebase's other protocols already use
// (Modbus, DNP3, IEC 104, S7comm).
//
// FrameID ranges/values (cross-checked against Wireshark's `dissect_pn_rt()` range table in
// `packet-pn-rt.c`, which is itself sourced from the PROFINET spec's own FrameID allocation
// table):
//   - 0xFEFC/0xFEFD/0xFEFE/0xFEFF: DCP Hello/Get-or-Set/Identify-Request/Identify-Response --
//     fully decoded, see the DCP section below.
//   - 0x8000-0xBBFF (RT_CLASS_1 unicast) and 0xBC00-0xBFFF (RT_CLASS_1 multicast): cyclic
//     real-time I/O data -- fully decoded, see the cyclic RT section below.
//   - 0x0100-0x06FF / 0x0700-0x0FFF (RTC3, non-redundant/redundant), 0xC000-0xF7FF / 0xF800-
//     0xFBFF (RT_CLASS_UDP unicast/multicast -- which in practice rides over UDP/IP, not this
//     raw-Ethernet EtherType, but the FrameID range is still named here for completeness),
//     0x0020-0x0021 / 0x0080-0x0081 (Sync), 0xFC01/0xFC41 (Alarm High, plain/with security),
//     0xFE01/0xFE41 (Alarm Low, plain/with security), 0xFE02/0xFE42 (RSI, plain/with security),
//     0xFE03 (SXP), 0xFF00-0xFF01 (PTCP Announce), 0xFF20-0xFF21 (PTCP Follow Up), 0xFF40-0xFF43
//     (Acyclic RT Delay), 0xFF80-0xFF8F (Fragmentation): named only (frame_id_name set, nothing
//     else decoded) -- either genuinely out of this groundwork release's scope (Alarm frames
//     carry their own ASN.1-like block structure this decoder doesn't parse), or, for RT_CLASS_UDP,
//     not actually expected to appear under this EtherType at all.
//   - Anything else (including every reserved range in the table above): not recognized at all --
//     try_parse_profinet returns std::nullopt, and the caller (decoder.cpp) falls back to the
//     generic "non-ip" ethertype-name-only report, same as it always has for 0x8892 traffic.
//
// DCP (Discovery and Configuration Protocol): a device-fingerprinting/configuration exchange --
// the PROFINET analog of EtherNet/IP's ListIdentity (see enip.hpp) -- carried in the four FrameIDs
// above. After the FrameID: ServiceID(1) + ServiceType(1) + Xid(4) + ResponseDelay-or-Reserved(2,
// meaningful only for a multicast Identify Request, not surfaced) + DCPDataLength(2, the byte
// count of the block list that follows -- this makes a DCP PDU self-delimited even if the
// Ethernet frame carries trailing minimum-frame-size padding after it, unlike cyclic RT data
// below). The block list is then Option(1) + Suboption(1) + DCPBlockLength(2) + that many bytes
// of block-specific data, +1 pad byte if DCPBlockLength is odd (word-alignment, confirmed against
// packet-pn-dcp.c's `dissect_PNDCP_Block`) -- repeated until DCPDataLength bytes are consumed.
// ServiceID: Get=3, Set=4, Identify=5, Hello=6. ServiceType: Request=0, Response-Success=1,
// Response-not-supported=5 (cross-checked against packet-pn-dcp.c and the independent open-source
// p-net PROFINET device stack's pf_dcp.c). This groundwork release value-decodes five Option/
// Suboption blocks -- Option 0x01 (IP) Suboption 0x01 (MAC Address) and Suboption 0x02
// (IPParameter: IP + subnet mask + gateway), and Option 0x02 (Device Properties) Suboption 0x02
// (NameOfStation, ASCII), Suboption 0x03 (DeviceID: VendorID + DeviceID), and Suboption 0x04
// (DeviceRole) -- the ones most directly useful for OT asset inventory/fingerprinting from
// passive capture; any other Option/Suboption is named (when recognized) or shown as raw hex
// (when not), never guessed at -- the same "decode confidently only where the wire format is
// unambiguous" philosophy applied throughout this codebase (see enip.hpp's file header comment's
// scoping note).
//
// IMPORTANT wire-format wrinkle, found only by validating against a real device's capture (see
// tests/real_captures/profinet/ATTRIBUTION.md): every Option 0x01/0x02 block above is preceded by
// an extra 2-byte BlockInfo (or, for a Set Request, BlockQualifier) field BEFORE its actual
// content -- but only for specific (ServiceID, direction) combinations: present for an Identify
// Response, a Hello, and a Get Response (BlockInfo); present for a Set Request (BlockQualifier);
// absent for an Identify Request, a Get Request, and a Set Response. Missing this (an earlier
// draft of this decoder did) doesn't crash anything -- it silently decodes a NameOfStation with
// two leading NUL bytes, or declines a DeviceID/IPParameter block as the wrong size, since every
// value-decode path below is already exact-size-gated. Cross-checked against packet-pn-dcp.c's
// `dissect_PNDCP_Suboption_Device`/`dissect_PNDCP_Suboption_IP` (both call
// `dissect_pn_uint16(..., hf_pn_dcp_block_info, ...)` under exactly this condition) AND against a
// real Siemens device's actual Identify Response and Set Request bytes -- see
// dcp_block_prefix_len's comment in profinet.cpp for the exact condition.
//
// Cyclic RT IO data: the real-time, cyclic I/O data exchange between an IO Controller (e.g. a
// PLC) and an IO Device (e.g. a remote I/O module) -- the PROFINET analog of EtherNet/IP's CIP
// implicit messaging (see enip.hpp). Unlike DCP, there is NO length field anywhere in a cyclic RT
// frame: the FrameID is followed directly by the IO data, then a fixed 4-byte trailer at the very
// end of the frame -- CycleCounter(2) + DataStatus(1) + TransferStatus(1) (byte order and field
// order cross-checked against packet-pn-rt.c's `dissect_pn_rt`, which reads these three fields
// from pdu_len-4/pdu_len-2/pdu_len-1 respectively). IO data length is therefore inferred as
// "everything between the FrameID and the last 4 bytes" -- which means, same as every other
// length-implicit protocol, this decoder CANNOT tell real IO data apart from Ethernet minimum-
// frame-size padding if the capture includes any (a cyclic frame below Ethernet's 46-byte minimum
// payload would have padding appended AFTER the trailer by the sending NIC, which this decoder has
// no way to detect or strip): see docs/MANUAL.md's LIMITATIONS section. IO data itself is shown
// only as raw hex, never value-decoded -- same reasoning as CIP I/O's Connected Data Item (see
// enip.hpp): there is no generic self-describing wire-level type for it, and this decoder has no
// GSD/GSDML device description to know an assembly's layout from. DataStatus's bits (cross-checked
// against packet-pn-rt.c's `dissect_DataStatus`): 0x01 State (1=Primary/0=Backup), 0x02 Redundancy
// (context-dependent meaning between Input/Output CRs, not further interpreted here), 0x04
// Data_Valid (1=Valid/0=Invalid), 0x08 reserved, 0x10 Provider_State (1=Run/0=Stop), 0x20
// Station_Problem_Indicator (1=Ok/0=Problem), 0x40 reserved, 0x80 Ignore (1=Ignore/0=Evaluate).
// TransferStatus: 0=OK, nonzero=ignore this frame's data (receiver should discard it).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// One decoded DCP block: Option + Suboption + a rendered value (either a decoded field or, for an
// Option/Suboption pair outside the four this decoder value-decodes, raw hex) -- see this file's
// header comment's DCP section.
struct ProfinetDcpBlock {
    uint8_t option = 0;
    uint8_t suboption = 0;
    std::string name;   // e.g. "NameOfStation", "IPParameter" -- empty when not in this decoder's
                          // known table (value is then raw hex, not guessed at)
    std::string value;  // rendered value, or raw hex when `name` is empty
};

struct ProfinetFrame {
    uint16_t frame_id = 0;
    std::string frame_id_name;  // e.g. "DCP Identify Request", "Cyclic RT IO data (unicast)" --
                                  // always set when try_parse_profinet returns a value at all

    // --- DCP (FrameID 0xFEFC/0xFEFD/0xFEFE/0xFEFF) ---
    bool has_dcp = false;
    uint8_t dcp_service_id = 0;
    std::string dcp_service_name;       // Hello / Get / Set / Identify
    uint8_t dcp_service_type = 0;
    std::string dcp_service_type_name;  // Request / Response-Success / Response-not-supported / ...
    uint32_t dcp_xid = 0;
    std::vector<ProfinetDcpBlock> dcp_blocks;
    // Convenience pull-outs of the blocks most useful for device fingerprinting, when present
    // (the PROFINET analog of EtherNet/IP's ListIdentity fields -- see enip.hpp's EnipFrame).
    std::string dcp_name_of_station;
    std::optional<uint16_t> dcp_device_vendor_id;
    std::optional<uint16_t> dcp_device_id;

    // --- Cyclic RT IO data (FrameID 0x8000-0xBBFF unicast / 0xBC00-0xBFFF multicast) ---
    bool has_cyclic_data = false;
    std::string cyclic_io_data_hex;  // raw hex, deliberately not value-decoded -- see this file's
                                       // header comment's cyclic RT IO data section
    size_t cyclic_io_data_length = 0;
    uint16_t cyclic_cycle_counter = 0;
    uint8_t cyclic_data_status = 0;
    std::string cyclic_data_status_summary;  // e.g. "Primary,Valid,Run,Ok" from the named bits
    uint8_t cyclic_transfer_status = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x8892 -- or after a
// single 802.1Q VLAN tag, already unwrapped by parse_ethernet; see link_layer.hpp) as one
// PROFINET RT frame. Returns std::nullopt (never throws) when there aren't even 2 bytes for a
// FrameID, or when the FrameID doesn't fall into any range/exact value this decoder recognizes
// (see this file's header comment for the full table) -- PROFINET RT's own dedicated EtherType
// (no IP-layer collision risk at all, unlike every UDP/TCP-based protocol in this codebase) means
// the FrameID check is this decoder's only structural detection gate, but it is still applied
// rather than accepting every 0x8892 frame unconditionally, so a frame in a genuinely reserved/
// unrecognized FrameID range is honestly reported as such (falls back to decoder.cpp's generic
// "non-ip" ethertype-name-only report) rather than guessed at.
std::optional<ProfinetFrame> try_parse_profinet(ByteSpan eth_payload);

}  // namespace conduitscope
