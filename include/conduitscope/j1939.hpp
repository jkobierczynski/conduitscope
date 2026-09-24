// SPDX-License-Identifier: Apache-2.0
// j1939.hpp - SAE J1939 (heavy-duty vehicle/off-highway CAN application layer) frame decoding,
// riding raw CAN frames captured via SocketCAN (pcap LINKTYPE_CAN_SOCKETCAN == 227, see
// can_socketcan.hpp/.cpp). Direct sibling of devicenet.hpp/canopen.hpp -- same link layer, same
// ByteSpan/CanSocketcanFrame inputs, same ProtocolDecoder wrapper shape.
//
// J1939 IS THE EASY CASE OF THIS TASK'S TWO ADDITIONS: unlike CANopen (see canopen.hpp's own file
// header for the full DeviceNet-vs-CANopen dispatch-collision analysis), J1939 ALWAYS uses Extended
// (29-bit) CAN identifiers -- `CanSocketcanFrame::eff == true` -- which DeviceNet and CANopen both
// categorically reject outright (each protocol's own reference dissector's literal first check
// rejects any EFF-flagged frame -- see devicenet.hpp's and canopen.hpp's own citations of
// `packet-devicenet.c`'s `if (can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG | CAN_EFF_FLAG)) return 0;`
// and `packet-canopen.c`'s identical check). J1939's own first check
// (`packet-j1939.c`'s `dissect_j1939`: `if ((can_info.id & CAN_ERR_FLAG) || !(can_info.id &
// CAN_EFF_FLAG)) return 0;`) is the exact mirror image -- it requires EFF, DeviceNet/CANopen both
// reject it. This is a genuine, hardware-enforced disjoint gate (not a convention that could
// theoretically be violated by a misbehaving device the way CAN-ID-range conventions can overlap):
// EFF is a real bit in the CAN frame's own arbitration field, set by the transmitting controller's
// own hardware based on which of the two identifier lengths it was told to send. There is no capture
// this task could construct where a legitimate DeviceNet/CANopen frame and a legitimate J1939 frame
// would both structurally match -- so, unlike CANopen, J1939 is tried opportunistically in
// `ProtocolFilter::Auto` right alongside DeviceNet with zero collision risk; see decoder.cpp's own
// LINKTYPE_CAN_SOCKETCAN branch for exactly where `want_j1939` is computed.
//
// ONE FURTHER DIFFERENCE FROM DEVICENET/CANOPEN'S OWN REJECTION, sourced directly from
// `dissect_j1939` itself: J1939 does NOT reject an RTR (Remote Transmission Request) frame the way
// DeviceNet/CANopen both do -- only ERR is rejected, and non-EFF is rejected (see above). An RTR
// frame is still classified by its 29-bit ID exactly like any other J1939 frame; the reference
// source's own comment is explicit that "RTR frames don't have payload" and handles that case
// specially in its own `COL_INFO` formatting rather than refusing the frame outright. This decoder
// mirrors that: `try_parse_j1939` accepts an RTR frame, sets `is_rtr`, and does not attempt any
// payload-derived decode for it (there is none to attempt -- an RTR frame's own Payload Length is
// meaningless per can_socketcan.hpp's own CAN ID + flags documentation).
//
// Sourcing: the 29-bit ID bit layout (priority/EDP/DP/PDU-Format/PDU-Specific/source-address), the
// PDU1-vs-PDU2 (point-to-point vs. broadcast) distinction, and the PGN reconstruction formula below
// are cross-checked directly against Wireshark's own `epan/dissectors/packet-j1939.c` (fetched in
// full from raw.githubusercontent.com/wireshark/wireshark/master during this task's own research
// phase -- its `hf_j1939_priority`/`_pdu_format`/`_pdu_specific`/`_src_addr`/`_dst_addr` field mask
// definitions and its `dissect_j1939` function's own `pgn = (can_info.id & 0x3FFFF00) >> 8;` plus
// PF-vs-240 branch). IMPORTANT HONEST CAVEAT, stated directly rather than glossed over: Wireshark's
// own `packet-j1939.c` is written for J1939's use as NMEA 2000's own transport layer (marine
// electronics) -- its own curated `j1939_pgn_vals` table names marine PGNs ("System Time", "GNSS
// position data", "AIS Class A Position Report", etc.), not the heavy-duty-truck PGNs this task's own
// brief specifically named (EEC1/ET1/CCVS/DM1, all defined in SAE J1939-71/-73, the vehicle/engine
// application layer, a DIFFERENT application-layer document set from the marine NMEA 2000 PGN
// registry that happens to share the exact same underlying J1939 transport/ID structure). Wireshark's
// own dissector implements NO per-PGN payload decoding at all beyond that marine PGN name table and a
// generic `j1939.pgn` subdissector-table hook (`dissector_try_uint_with_data`) that nothing in a
// stock Wireshark build actually registers against -- i.e. it recognizes PGN numbers by name only,
// same as this decoder's own "curated name, structural hex for the rest" posture, but decodes NO
// PGN's payload bytes at all, for either the marine or the vehicle PGN set. The EEC1/ET1/CCVS/DM1
// per-PGN field layouts below (byte offsets, little-endian multi-byte fields, resolution/offset
// scaling, and the DM1 diagnostic-trouble-code SPN/FMI/OC/CM bit-packing) are therefore this task's
// own direct application of the well-established, widely-published SAE J1939-71 (Vehicle Application
// Layer) / SAE J1939-73 (Application Layer - Diagnostics) field definitions -- NOT ported from
// Wireshark source, since no Wireshark source decodes them. This is exactly the kind of "no upstream
// dissector to check against" situation this codebase's own established posture handles by making a
// documented, conservative, structurally-named call rather than guessing wildly -- the DM1
// SPN/FMI/OC/CM bit-packing in particular is called out explicitly below with its own bit-by-bit
// citation, since it is (per this task's own brief) "the single most error-prone part of J1939."
//
// 29-bit CAN identifier structure (`can.id`, already masked to 29 bits by
// can_socketcan.hpp's parse_socketcan_frame since `can.eff` is required to reach this decoder at
// all):
//   bits 28-26 (mask 0x1C000000, `>> 26`)  Priority (0-7, 0 = highest) -- `hf_j1939_priority`'s own
//     mask, confirmed directly from source.
//   bit 25     (mask 0x02000000)            Extended Data Page (EDP) -- `hf_j1939_extended_data_page`.
//   bit 24     (mask 0x01000000)            Data Page (DP) -- `hf_j1939_data_page`. EDP+DP together
//     select which of four possible 8-bit PDU Format pages is in use; this decoder surfaces both bits
//     but does not interpret their combination further (every curated PGN this decoder names uses
//     EDP=DP=0, the overwhelmingly common case for J1939-71's own vehicle PGNs) -- see "Out of scope"
//     below.
//   bits 23-16 (mask 0x00FF0000, `>> 16`)   PDU Format (PF) -- `hf_j1939_pdu_format`. THE field that
//     decides PDU1 vs. PDU2 (see below).
//   bits 15-8  (mask 0x0000FF00, `>> 8`)    PDU Specific (PS) -- `hf_j1939_pdu_specific`, reinterpreted
//     as EITHER a Destination Address OR a PGN Group Extension depending on PF (see below).
//   bits 7-0   (mask 0x000000FF)            Source Address (SA) -- `hf_j1939_src_addr`, always the
//     transmitting node's own address, 0-255 (a curated handful of well-known values are named --
//     `j1939_fmt_address`'s own convention: addresses 128-247 are "Arbitrary" (dynamically
//     assignable), everything outside that range has a fixed, named meaning -- this decoder ports
//     only the handful most useful for an OT/ICS audit context, e.g. 0 "Engine #1", 255 "GLOBAL"/
//     broadcast, 254 "Null Address" -- NOT Wireshark's own full ~90-entry NMEA-2000-flavored address
//     table, which is out of this task's own vehicle-diagnostics scope; see j1939.cpp's
//     `j1939_source_address_name`).
//
// PDU1 vs. PDU2 and PGN reconstruction (`dissect_j1939`'s own `pgn = (can_info.id & 0x3FFFF00) >> 8;`
// then its PF-vs-240 branch, reproduced exactly):
//   The 18-bit value `(EDP<<17) | (DP<<16) | (PF<<8) | PS` (i.e. `(can.id & 0x3FFFF00) >> 8`) is the
//   PGN's own RAW form. Whether PS is actually PART of the PGN, or is instead a separate Destination
//   Address, depends entirely on PF:
//     PF < 240 (0xF0): "PDU1" format -- point-to-point. PS is a Destination Address (a specific
//       node's own Source Address, or 255 == "GLOBAL"/broadcast-to-everyone -- still a legitimate,
//       common value, not an error). The PGN itself is the 18-bit value with its own low byte (the PS
//       bits) FORCED TO ZERO (`pgn &= 0x3FF00` in the reference source) -- i.e. PDU1-format PGNs are
//       always a multiple of 256 by construction, and the actual PS byte on the wire is NEVER part of
//       the PGN's own identity, only ever a destination address.
//     PF >= 240 (0xF0): "PDU2" format -- broadcast. PS is a Group Extension, and IS part of the PGN
//       (the full, un-masked 18-bit value is the PGN). There is no destination address at all for a
//       PDU2 message -- it is inherently broadcast to every node on the bus.
//   `is_pdu1`/`destination_address`/`pgn` below reproduce this exactly. Two of this decoder's own
//   curated PGNs are deliberately PDU1-format (Request, PGN 59904/0xEA00, PF=0xEA=234<240; and
//   Address Claimed, PGN 60928/0xEE00, PF=0xEE=238<240) specifically because the task's own brief
//   asked for "a point-to-point PDU1 example ... proving destination-address extraction" -- see
//   tools/make_sample_pcap.py's `build_j1939_sample`.
//
// Curated PGN table (`j1939_pgn_name` in j1939.cpp) -- SAE J1939-71's own well-known vehicle/engine
// PGNs, named only (structural -- PGN number + raw hex payload) except the four given full field
// decode below, matching this task's own "curated depth, not exhaustive" posture (LLDP's/CDP's own
// TLV-richness judgment calls are the precedent already established in this codebase):
//   59392 (0xE800) Acknowledgment | 59904 (0xEA00) Request (full decode: 3-byte little-endian target
//   PGN) | 60928 (0xEE00) Address Claimed | 61443 (0xF003) EEC2 (Electronic Engine Controller 2) |
//   61444 (0xF004) EEC1 (full decode) | 61445 (0xF005) ETC1 (Electronic Transmission Controller 1) |
//   65226 (0xFECA) DM1 (full decode) | 65227 (0xFECB) DM2 (Previously Active DTCs -- same wire shape
//   as DM1, named only, not separately field-decoded) | 65253 (0xFEE5) Engine Hours, Revolutions |
//   65262 (0xFEEE) ET1 (full decode) | 65263 (0xFEEF) EFL/P1 (Engine Fluid Level/Pressure 1) | 65265
//   (0xFEF1) CCVS (full decode) | 65266 (0xFEF2) LFE (Fuel Economy) | 65276 (0xFEFC) DD (Dash
//   Display). Every other PGN is shown as a bare number, never treated as an error.
//
// EEC1 -- Electronic Engine Controller 1 (PGN 61444/0xF004), SAE J1939-71: byte 2 (0-indexed byte 1)
//   Driver's Demand Engine - Percent Torque (SPN 512), 1%/bit, -125% offset; byte 3 (index 2) Actual
//   Engine - Percent Torque (SPN 513), 1%/bit, -125% offset; bytes 4-5 (index 3-4) Engine Speed (SPN
//   190), little-endian 16-bit, 0.125 rpm/bit, 0 offset. This decoder extracts exactly these three
//   (the headline "what is the engine doing right now" values); the remaining bytes (Engine Torque
//   Mode, Source Address of Controlling Device, Engine Starter Mode, Engine Demand - Percent Torque)
//   are not decoded, matching this task's own curated-depth posture.
//
// ET1 -- Engine Temperature 1 (PGN 65262/0xFEEE), SAE J1939-71: byte 1 (index 0) Engine Coolant
//   Temperature (SPN 110), 1 degC/bit, -40 degC offset; byte 2 (index 1) Fuel Temperature (SPN 174),
//   1 degC/bit, -40 degC offset; bytes 3-4 (index 2-3) Engine Oil Temperature 1 (SPN 175),
//   little-endian 16-bit, 0.03125 degC/bit, -273 degC offset. This decoder extracts these three;
//   Turbo Oil Temperature/Engine Intercooler Temperature/Intercooler Thermostat Opening (the
//   remaining bytes) are not decoded.
//
// CCVS -- Cruise Control/Vehicle Speed (PGN 65265/0xFEF1), SAE J1939-71: bytes 1-2 (index 0-1)
//   Wheel-Based Vehicle Speed (SPN 84), little-endian 16-bit, 1/256 km/h per bit, 0 offset; byte 3
//   (index 2) bits 7-6 (0xC0) Cruise Control Active (SPN 595), a 2-bit status value using the
//   standard SAE J1939 2-bit-status convention this decoder also uses for DM1's own lamp fields (see
//   below): 0 Off/Not Active, 1 On/Active, 2 Reserved/Error, 3 Not Available. This decoder extracts
//   vehicle speed and cruise-control-active status; the remaining switch bits (Parking Brake, Two
//   Speed Axle, Cruise Control Enable/Set/Coast/Resume/Accelerate switches, Clutch/Brake switches)
//   are not decoded.
//
// DM1 -- Active Diagnostic Trouble Codes (PGN 65226/0xFECA), SAE J1939-73: THE headline curated
//   finding for J1939, the same "one headline curated finding per protocol" pattern this codebase's
//   IPMI Cipher-Suite-0 and DRSUAPI DCSync notes already established -- an active DTC is a direct,
//   unambiguous OT-security-relevant fact (something on the vehicle/machine bus is actively faulting),
//   surfaced with its own clearly-labeled `--stats` headline (see output.cpp), never buried in a
//   generic count.
//     Byte 1 (index 0): four 2-bit lamp-status fields, MSB-first -- bits 7-6 Malfunction Indicator
//       Lamp (MIL), bits 5-4 Red Stop Lamp (RSL), bits 3-2 Amber Warning Lamp (AWL), bits 1-0
//       Protect Lamp (PL). Each 2-bit value uses the same standard status convention as CCVS's own
//       Cruise Control Active field above: 0 Off, 1 On, 2 Reserved, 3 Not Available.
//     Byte 2 (index 1): the same four lamps' own Flash status, identical bit layout -- this decoder
//       recognizes the byte exists (`dm1_flash_byte_present`, raw only) but does not individually
//       decode each lamp's flash state, matching this task's own curated-depth posture (the STATUS
//       byte, not the FLASH byte, is the headline finding).
//     Bytes 3 onward (index 2+): zero or more 4-byte packed Diagnostic Trouble Code (DTC) blocks --
//       repeats for as many complete 4-byte groups as the payload actually contains past the first
//       two lamp bytes (a multi-DTC DM1 message, or a DM1 that needed CAN FD's larger payload to fit
//       more than one DTC in a single frame without J1939's own multi-packet Transport Protocol, are
//       both handled the same way: however many complete 4-byte DTC blocks are present are decoded).
//       Each 4-byte DTC block (`dtc[0..3]`, standard programmer bit numbering, bit 7 = MSB):
//         dtc[0]              SPN bits 7-0 (the LEAST significant byte of a 19-bit Suspect
//                              Parameter Number)
//         dtc[1]              SPN bits 15-8 (the MIDDLE byte)
//         dtc[2] bits 7-5     SPN bits 18-16 (the three MOST significant bits -- SPN's own top byte
//                              is never a full byte, only these 3 bits, which is exactly the "19 bits
//                              split across 3 bytes in a specific non-contiguous way" this task's own
//                              brief flagged as the single most error-prone part of J1939)
//         dtc[2] bits 4-0     FMI (Failure Mode Identifier), 5 bits, 0-31
//         dtc[3] bit 7        SPN Conversion Method (CM) -- 0 or 1, selects between two different SPN
//                              numbering conventions (CM has no further semantic decode here beyond
//                              its raw bit value, matching this task's own curated-depth posture)
//         dtc[3] bits 6-0     Occurrence Count (OC), 7 bits, 0-127 (0x7F is reserved to mean
//                              "occurrence count not available"; shown as-is, not specially named)
//       Reconstruction: `spn = dtc[0] | (dtc[1] << 8) | ((dtc[2] >> 5) << 16)`,
//       `fmi = dtc[2] & 0x1F`, `cm = (dtc[3] >> 7) & 0x01`, `oc = dtc[3] & 0x7F`. This exact bit
//       layout is the standard, widely-published SAE J1939-73 DM1/DM2 DTC packing (the same four-
//       field, four-byte structure documented by essentially every third-party J1939 diagnostic
//       toolchain and vehicle-network reverse-engineering writeup this task is aware of) -- flagged
//       here, per this task's own brief, as a "documented, conservative scope call" in the sense that
//       it is a domain-knowledge application rather than a Wireshark-source port (see this file's own
//       "Sourcing" paragraph above for why no such port exists to check against), not in the sense of
//       being uncertain about the bit positions themselves.
//
// Out of scope for this release (matching this codebase's established "recognized but not this
// release's problem" posture):
//   - J1939's own multi-packet Transport Protocol (TP.BAM broadcast / TP.CM+TP.DT connection-mode)
//     for a message whose data spans more than one CAN frame (a DM1 with more DTCs than fit in a
//     single frame's payload, for instance) -- the same class of gap DeviceNet's own Group 3
//     fragmentation and CANopen's own SDO segment/block session tracking already document; this
//     decoder decodes exactly what one CAN frame's own payload contains, never reassembling across
//     frames.
//   - Any PGN beyond the fourteen curated above receiving anything more than its bare PGN number --
//     no attempt at a broader curated table (SAE J1939-71 alone defines well over 100 vehicle PGNs;
//     matching this task's own explicit "you do not need every PGN in existence" scope).
//   - EDP/DP page-selection semantics beyond surfacing the two raw bits -- every curated PGN here
//     uses EDP=DP=0 (see "29-bit CAN identifier structure" above).
//   - DM1's own Flash byte (lamp flash state) field-level decode -- recognized structurally only, see
//     "DM1" above.
//   - The address-claim/NAME arbitration semantics of PGN 60928 (Address Claimed)'s own 8-byte NAME
//     payload (Arbitrary Address Capable bit, Industry Group, Vehicle System, Function, ECU
//     Instance, Manufacturer Code -- a further bit-packed structure of its own) -- this decoder names
//     the PGN and shows its payload as raw hex only, the same "recognized but not this release's
//     problem" posture as everything else on this list.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// One decoded J1939 Diagnostic Trouble Code (DM1/DM2's own 4-byte packed block) -- see j1939.hpp's
// own "DM1" paragraph for the exact bit-packing this was decoded from.
struct J1939Dtc {
    uint32_t spn = 0;               // Suspect Parameter Number, 19 bits (0-0x7FFFF)
    uint8_t fmi = 0;                // Failure Mode Identifier, 5 bits (0-31)
    uint8_t occurrence_count = 0;   // 7 bits (0-127)
    bool conversion_method = false; // SPN Conversion Method bit
};

// One decoded J1939 frame -- see this file's header comment for the full 29-bit ID structure, PGN
// reconstruction, curated PGN table, and every documented scope decision.
struct J1939Frame {
    uint32_t can_id = 0;         // masked 29-bit extended CAN identifier
    uint8_t priority = 0;        // bits 28-26 (0-7, 0 == highest)
    bool extended_data_page = false;  // bit 25 (EDP)
    bool data_page = false;           // bit 24 (DP)
    uint8_t pdu_format = 0;      // PF, bits 23-16
    uint8_t pdu_specific = 0;    // PS, bits 15-8 -- see is_pdu1 for how to interpret this
    uint8_t source_address = 0;  // SA, bits 7-0
    std::string source_address_name;  // curated handful only, empty otherwise -- see file header

    bool is_pdu1 = false;             // pdu_format < 240 -- point-to-point (PS is a destination)
    bool destination_is_broadcast = false;  // only meaningful when is_pdu1: destination_address==255
    uint8_t destination_address = 0;  // only meaningful when is_pdu1 -- see file header

    uint32_t pgn = 0;             // reconstructed 18-bit Parameter Group Number
    std::string pgn_name;         // curated name (e.g. "EEC1"), or empty for an uncurated PGN

    bool is_rtr = false;  // mirrors CanSocketcanFrame::rtr -- see file header: UNLIKE DeviceNet/
                            // CANopen, J1939 does not reject RTR frames; when true, no payload-
                            // derived field below is populated (there is no payload to read).

    // EEC1 (PGN 61444) -- see file header's own "EEC1" paragraph.
    bool has_eec1 = false;
    int eec1_driver_demand_percent_torque = 0;  // signed, -125..+125-ish range
    int eec1_actual_percent_torque = 0;         // signed
    double eec1_engine_speed_rpm = 0.0;

    // ET1 (PGN 65262) -- see file header's own "ET1" paragraph.
    bool has_et1 = false;
    int et1_coolant_temp_c = 0;   // signed, -40 offset
    int et1_fuel_temp_c = 0;      // signed, -40 offset
    bool et1_has_oil_temp = false;
    double et1_oil_temp_c = 0.0;

    // CCVS (PGN 65265) -- see file header's own "CCVS" paragraph.
    bool has_ccvs = false;
    bool ccvs_has_speed = false;
    double ccvs_vehicle_speed_kmh = 0.0;
    bool ccvs_has_cruise_active = false;
    uint8_t ccvs_cruise_active_raw = 0;   // 0-3, see file header's 2-bit status convention
    std::string ccvs_cruise_active_name;  // "Off"/"On"/"Reserved"/"Not Available"

    // Request (PGN 59904) -- see file header's own "PDU1 vs. PDU2" paragraph.
    bool has_request = false;
    bool request_has_target_pgn = false;
    uint32_t request_target_pgn = 0;  // 3-byte little-endian PGN being requested

    // DM1 (PGN 65226) -- see file header's own "DM1" paragraph. Lamp status fields use the shared
    // 2-bit convention (0 Off, 1 On, 2 Reserved, 3 Not Available), rendered into *_name.
    bool has_dm1 = false;
    bool dm1_has_lamp_status = false;
    uint8_t dm1_mil_raw = 0, dm1_rsl_raw = 0, dm1_awl_raw = 0, dm1_pl_raw = 0;
    std::string dm1_mil_name, dm1_rsl_name, dm1_awl_name, dm1_pl_name;
    bool dm1_flash_byte_present = false;  // see file header: recognized, not field-decoded
    std::vector<J1939Dtc> dm1_dtcs;

    bool fd = false;              // mirrors CanSocketcanFrame::fd. UNLIKE DeviceNet/CANopen (see
                                    // devicenet.hpp/canopen.hpp's own CAN FD scope notes, where an
                                    // FD frame's payload is deliberately never decoded), a J1939 FD
                                    // frame's payload IS still decoded normally -- see this file's
                                    // header comment and j1939.cpp's own try_parse_j1939 for why:
                                    // J1939-22 legitimately rides CAN FD, and every curated per-PGN
                                    // decoder here already reads however many bytes are actually
                                    // present, so there is no reason to skip it.
    ByteSpan payload;
    bool payload_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret one already-parsed SocketCAN frame as a J1939 frame. Returns std::nullopt
// (never throws) when `!can.eff || can.err` -- mirrors `dissect_j1939`'s own literal first check
// exactly (see this file's header comment's "ONE FURTHER DIFFERENCE" paragraph for why RTR is NOT a
// rejection condition here, unlike DeviceNet/CANopen).
std::optional<J1939Frame> try_parse_j1939(const CanSocketcanFrame& can);

// J1939, wrapped for the ProtocolDecoder interface -- id()=="j1939", GateKind::LinkType (the THIRD
// protocol on this gate, after DeviceNet and CANopen -- see this file's header comment for why it,
// unlike CANopen, joins DeviceNet in Auto mode with zero collision risk). Same "no separate Result
// wrapper, no coalescing" shape DeviceNetDecoder/CanopenDecoder already established.
//
// Same ONE DELIBERATE DEVIATION DeviceNetDecoder::decode()/CanopenDecoder::decode() both document:
// this can throw ParseError (it calls parse_socketcan_frame(payload) itself).
class J1939Decoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "j1939"; }
    GateKind gate_kind() const override { return GateKind::LinkType; }
    std::optional<uint32_t> link_type() const override { return LINKTYPE_CAN_SOCKETCAN; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& j1939_decoder();

}  // namespace conduitscope
