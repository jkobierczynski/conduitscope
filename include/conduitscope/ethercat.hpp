// SPDX-License-Identifier: Apache-2.0
// ethercat.hpp - EtherCAT (EtherType 0x88A4) decoding: the 2-byte EtherCAT frame header (Length +
// Type), and, for Type 1 ("EtherCAT command") frames, the chained EtherCAT datagram(s) that
// follow -- Cmd/Idx/Address/Len+flags/IRQ header, the datagram's own Data payload, and the
// trailing Working Counter (WKC).
//
// Like PROFINET RT, IEC 61850-8-1 GOOSE, and IEC 61850-9-2 Sampled Values, EtherCAT rides
// directly on raw Ethernet -- there is no IPv4/UDP/TCP layer at all. Unlike those three, though,
// EtherCAT's wire format is plain fixed-binary-layout, little-endian throughout -- there is no
// ASN.1/BER encoding anywhere in it (cross-checked against Wireshark's own EtherCAT plugin,
// `plugins/epan/ethercat/packet-ethercat-frame.c` and `packet-ethercat-datagram.c`, a dissector
// contributed by Beckhoff Automation -- the company that invented EtherCAT -- which this file's
// wire-format description is cross-checked against throughout, byte offset by byte offset).
//
// Frame header (immediately after the EtherType -- or after a single 802.1Q VLAN tag, already
// unwrapped by parse_ethernet by the time this decoder sees it): exactly 2 bytes, one 16-bit
// little-endian word, three bit-fields (cross-checked against packet-ethercat-frame.c's
// `EthercatFrameParserHDR` union and its `hf_ethercat_frame_length/_reserved/_type` masks):
//   bits 0-10  (mask 0x07FF) Length   -- the total byte length of the datagram(s) that follow this
//                                        header (NOT including the header's own 2 bytes) -- see
//                                        the "declared Length" paragraph below for how this
//                                        decoder uses it and why that's trustworthy.
//   bit  11    (mask 0x0800) Reserved -- must be zero per the spec (Wireshark's own
//                                        `ethercat_frame_reserved_vals` literally names 1
//                                        "Invalid"); surfaced only as a note when set, never as a
//                                        rejection -- this decoder still uses the EtherType alone
//                                        as its primary confidence signal (see "structural
//                                        detection gate" below).
//   bits 12-15 (mask 0xF000) Type     -- which of five defined frame kinds this is (cross-checked
//                                        against packet-ethercat-frame.c's `EthercatFrameTypes`):
//                                          1 = "EtherCAT command"  -- the datagram-chain traffic
//                                              this file fully decodes (see below). By far the
//                                              overwhelming majority of real EtherCAT traffic --
//                                              every one of 986 real frames in this decoder's real
//                                              capture fixture (see Validation below) is Type 1.
//                                          2 = "ADS"      -- Beckhoff's ADS protocol tunneled
//                                          3 = "RAW-IO"   -- direct in each other's own frame
//                                          4 = "NV"          shape under this same EtherType --
//                                          5 = "Mailbox"  -- named only, not decoded further (see
//                                              "explicitly out of scope" below); Wireshark's own
//                                              dissector table (`ecatf.type`) only ever registers a
//                                              sub-dissector for Type 1 (`ecat`) and Type 5
//                                              (`ecat_mailbox`) -- Types 2-4 have no dissector at
//                                              all upstream either, decoded generically as data.
//                                        Any other Type value (0, 6-15) is not one of the five the
//                                        spec defines -- this decoder does not recognize the frame
//                                        at all in that case (see "structural detection gate").
//
// Structural detection gate: unlike every other raw-Ethernet protocol this codebase decodes
// (PROFINET RT's FrameID range table, GOOSE/SV's single- or two-value outer BER tag), EtherCAT's
// frame header carries no field whose value space is naturally self-restricting -- Length is an
// 11-bit magnitude with no invalid values, and Type's 4 bits admit 16 possible values of which 5
// are spec-defined, a 5-in-16 (not 1-in-256, as GOOSE's outer tag gives) chance of a coincidental
// match against unrelated traffic. This decoder therefore requires Type to be exactly one of 1-5
// (falling back to the generic "non-ip" ethertype-name-only report otherwise, same as every other
// protocol here) -- the primary source of confidence that a 0x88A4 frame actually is EtherCAT
// remains the EtherType itself, which (like PROFINET RT/GOOSE/SV's) has no collision risk with any
// other protocol this tool decodes; see docs/MANUAL.md's LIMITATIONS for this honestly weaker
// (relative to this codebase's other raw-Ethernet decoders) structural gate.
//
// EtherCAT datagram (Type 1 only; `EcParserHDR` in packet-ethercat-datagram.h, `EcParserHDR_Len`
// == 10): one or more of these are chained back-to-back immediately after the 2-byte frame header,
// every multi-byte field little-endian:
//   Cmd(1)     -- the command; see the table below. Determines how Address(4) is interpreted.
//   Idx(1)     -- an opaque index the sender picks and a responding slave echoes back unchanged --
//                 lets a master match this datagram's eventual effect to the request that caused
//                 it, the EtherCAT analog of Modbus's transaction ID or GOOSE/SV's sqNum, though
//                 with no reassembly semantics of its own (see EthercatDatagram::idx below).
//   Address(4) -- EITHER Adp(2)+Ado(2) -- a 16-bit position/station/broadcast address (Adp) plus a
//                 16-bit register-or-memory offset within that slave's address space (Ado) -- for
//                 every Cmd except LRD/LWR/LRW, OR a single 32-bit logical address for LRD/LWR/LRW
//                 (cmd 10/11/12) -- cross-checked against packet-ethercat-datagram.c's own
//                 `switch (ecHdr.cmd) { case 10: case 11: case 12: /* logical */ default: /* adp+
//                 ado */ }`, which this decoder's decode_ethercat_datagram mirrors exactly
//                 (including ARMW(13)/FRMW(14) falling into the Adp/Ado default case, not logical
//                 addressing, despite their "Read Multiple Write" names).
//   Len(2)     -- another 16-bit little-endian bit-field word (mask layout cross-checked against
//                 packet-ethercat-datagram.c's `hf_ecat_length_len/_r/_c/_m`):
//                   bits 0-10  (0x07FF) Len          -- byte length of the Data field that follows.
//                   bits 11-13 (0x3800) Reserved     -- not surfaced (same posture as the frame
//                                                        header's own truly-reserved bits above).
//                   bit  14    (0x4000) Circulating  -- "frame has circulated once" (a topology/
//                                                        loop-detection signal on ring-wired
//                                                        segments) -- never observed set in this
//                                                        decoder's real capture fixture (see
//                                                        Validation), so this path is synthetic-
//                                                        only.
//                   bit  15    (0x8000) More         -- another datagram immediately follows this
//                                                        one's Data+WKC when set; this is the sole
//                                                        signal this decoder (and Wireshark's own
//                                                        dissector) uses to know when the chain
//                                                        ends -- see "declared Length" below for
//                                                        how far it's trusted to run.
//   Irq(2)     -- an interrupt-request bitmask (one bit per slave in some deployments); shown as a
//                 raw hex value, not decoded further -- no confirmed, universally-applicable bit
//                 layout was found for this field (unlike, say, PROFINET's DataStatus).
//   Data(Len)  -- the datagram's actual payload -- see "Data is deliberately never value-decoded"
//                 below for why this decoder stops here rather than interpreting it.
//   WKC(2)     -- Working Counter, immediately after Data (outside EcParserHDR proper -- cross-
//                 checked against packet-ethercat-datagram.c's `get_wc`, which reads it from
//                 `offset + EcParserHDR_Len + len`): starts at 0 when the master sends the frame,
//                 and every slave that successfully executed the command increments it by an
//                 amount the spec defines per command type (typically +1 for a read or write,
//                 +3 for a combined read-write). This is EtherCAT's primary stream-integrity
//                 signal -- the closest analog to GOOSE's stNum/sqNum or SV's smpCnt -- but
//                 unlike those, this decoder has no slave-count/topology knowledge to know what
//                 WKC value a given command SHOULD produce on a healthy bus, so it surfaces the
//                 raw value only, no verdict. A WKC of 0 on a command that should reach at least
//                 one slave is the field's single unambiguous "something didn't respond" signal
//                 regardless of topology, though -- see EthercatDatagram::wkc below.
//
// Cmd names (cross-checked against packet-ethercat-datagram.c's `EcCmdShort`/`EcCmdLong` value_
// string tables): 0 NOP, 1 APRD (Auto Increment Physical Read), 2 APWR (Auto Increment Physical
// Write), 3 APRW (Auto Increment Physical ReadWrite), 4 FPRD (Configured-address Physical Read),
// 5 FPWR (Configured-address Physical Write), 6 FPRW (Configured-address Physical ReadWrite),
// 7 BRD (Broadcast Read), 8 BWR (Broadcast Write), 9 BRW (Broadcast ReadWrite), 10 LRD (Logical
// Read), 11 LWR (Logical Write), 12 LRW (Logical ReadWrite), 13 ARMW (Auto Increment Physical Read
// Multiple Write), 14 FRMW (Configured-address Physical Read Multiple Write), 255 EXT. Any other
// byte value is rendered "unknown(N)" rather than guessed at, but is still decoded structurally
// (Adp/Ado addressing, per the default case above) -- an unrecognized Cmd doesn't stop the rest of
// this datagram, or the chain, from being decoded.
//
// "Auto increment" (AP*) addressing deserves a specific callout: Adp is interpreted as a *negative
// offset from the sending master*, decremented by 1 at every slave the frame physically passes
// through on its way around the segment -- so an AP command with Adp=0x0000 addresses "whichever
// slave is first on the segment", Adp=0xFFFF (-1) addresses the second, 0xFFFE (-2) the third, and
// so on. This is precisely the pattern this decoder's real capture fixture's topology-discovery
// sequence uses (a master probing Adp=0x0000, then 0xFFFF, 0xFFFE, 0xFFFD, ... in one chained
// frame, right after boot, to enumerate however many slaves are actually present on the segment --
// see Validation below) -- this decoder surfaces Adp as a raw 16-bit value (rendered in hex, since
// its "negative offset" interpretation only matters for AP commands specifically) rather than
// pre-computing a signed offset, since the same field is a plain non-negative station address for
// FP/BRD/BWR/BRW commands.
//
// Chained datagrams / "declared Length": a frame's data-link payload commonly carries more than
// one datagram back-to-back (a master batching several slave register accesses -- or a full
// process-data exchange plus several diagnostic reads -- into one Ethernet frame for efficiency);
// the More bit (above) chains them. This decoder walks the chain until a datagram with More clear,
// a safety cap (kMaxEthercatDatagrams) is hit, or the bytes run out -- but bounds that walk by the
// frame header's own declared Length field (clamped tolerantly to the bytes actually available,
// exactly the same "declared-length-bounds-the-region, note and fall back to available bytes when
// implausible" pattern goose.hpp/sv.hpp already use for their own outer APDU length), rather than
// walking every remaining byte in the Ethernet frame unconditionally the way Wireshark's own
// dissector does. This matters because Ethernet's own minimum-frame-size zero-padding, when
// present, would otherwise parse as a spurious trailing NOP-shaped datagram (Cmd=0, Idx=0, Adp=
// Ado=0, Len=0, WKC=0, all satisfied by an all-zero region) -- exactly the same padding-vs-payload
// ambiguity already documented for PROFINET RT's cyclic IO data (see profinet.hpp), except here it
// is avoidable: this decoder's real capture fixture shows the declared Length field exactly
// matching the actual chained-datagram byte count in all 986 of 986 real frames checked (zero
// mismatches -- see Validation), so trusting it as the chain's authoritative extent is empirically
// well-founded, not just a spec reading. A genuine mismatch between declared Length and the bytes
// the More-bit chain actually consumes is still possible (a malformed/adversarial frame, or a
// spec edge case this decoder's real fixture doesn't happen to exercise) -- noted, not silently
// accepted, the same as GOOSE's numDatSetEntries/SV's noASDU cross-checks.
//
// Data is deliberately never value-decoded: an EtherCAT datagram's Data field is either raw ESC
// (EtherCAT Slave Controller) register content (for AP/FP/BRD/BWR/BRW/ARMW/FRMW commands -- see
// packet-ethercat-datagram.c's own ~150-entry `ecat_esc_registers` table for how deep that rabbit
// hole goes) or raw process-image content at a logical address (for LRD/LWR/LRW) whose actual
// layout is defined entirely by the specific slave devices' ESI/XML descriptions and the master's
// own process-image mapping -- information that exists nowhere on the wire, only in offline
// engineering configuration this decoder has no access to. This is the same "no generic self-
// describing wire-level type" reasoning already applied three times in this codebase (PROFINET
// RT's cyclic IO data, EtherNet/IP's CIP I/O Connected Data Item, IEC 61850-9-2 SV's seqData) --
// Data is shown only as raw hex plus its byte length, never interpreted. Cmd/Idx/Address/Len/IRQ/
// WKC ARE all decoded, though, because every one of those is unambiguous straight from the spec,
// independent of any particular slave's configuration.
//
// Explicitly out of scope: the CoE/SoE/EoE/FoE/AoE "mailbox" protocol family -- SDO access, the
// most common way real EtherCAT configuration/diagnostic traffic actually happens -- is carried
// as ordinary Data (above) inside a ordinary FPRD/FPWR/... datagram addressed to a slave's
// SyncManager mailbox-out/mailbox-in registers, which requires the same per-slave SyncManager
// configuration knowledge this decoder doesn't have to even recognize, let alone decode (packet-
// ecatmb.c, Wireshark's mailbox dissector, is reached only via a slave-configuration-aware
// heuristic this decoder does not replicate). Frame Type 5 ("Mailbox", a distinct, rarer framing
// occasionally used for direct engineering-tool mailbox access over this EtherType without a
// datagram chain at all) is named only, not decoded, for the same reason. Frame Types 2-4 (ADS/
// RAW-IO/NV) are vendor/legacy framings under this same EtherType, also named only. Distributed
// Clock (DC) register semantics (packet-ethercat-datagram.c's own dedicated DC-diff subtree,
// triggered when an FPRD/FPRD-class datagram targets Ado 0x0900) are not specially interpreted --
// DC register reads/writes are decoded exactly like any other Data payload, as raw hex.
//
// Validation: this decoder's understanding of the wire format is cross-checked throughout against
// Wireshark's own EtherCAT plugin (Beckhoff Automation-authored, see above) -- and, unlike IEC
// 61850-9-2 Sampled Values (see sv.hpp), a genuine real capture WAS found: `ICS-Ethercat-001.pcap`
// (986 frames, a master's boot-time slave enumeration and register poll sequence against what
// looks like a small, up-to-five-slave demo segment) -- see tests/real_captures/ethercat/
// ATTRIBUTION.md for full provenance. Every one of its 986 frames is Type 1 with a declared Length
// field exactly matching its actual chained-datagram byte count (see "declared Length" above);
// commands APRD/APWR/FPRD/FPWR/BRD/BWR/LRD/LWR all appear with real, structurally valid bytes,
// including the auto-increment topology-discovery pattern described above and up to 11 chained
// datagrams in a single frame -- but APRW/FPRW/BRW/LRW/ARMW/FRMW/EXT, the Circulating bit, 802.1Q
// VLAN tagging, frame Types other than 1, and every malformed/truncated-input path this decoder
// handles are validated only against the hand-built tests/sample_ethercat.pcap fixture (see
// tools/make_sample_pcap.py's build_ethercat_sample), cross-checked against packet-ethercat-
// datagram.c's source rather than an independent real capture -- the same honest gap this codebase
// already documents for several other protocols' less-common paths (see docs/MANUAL.md's
// LIMITATIONS).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// One decoded EtherCAT datagram -- see ethercat.hpp's file header comment's datagram field table.
struct EthercatDatagram {
    uint8_t cmd = 0;
    std::string cmd_name;  // "APRD"/"LRD"/.../"unknown(N)" -- see the Cmd name table above
    uint8_t idx = 0;

    bool logical_addressing = false;  // true only for LRD/LWR/LRW (cmd 10/11/12)
    uint16_t adp = 0;                 // meaningful only when !logical_addressing
    uint16_t ado = 0;                 // meaningful only when !logical_addressing
    uint32_t logical_address = 0;     // meaningful only when logical_addressing

    uint16_t data_len = 0;      // the Len field's own 11-bit magnitude
    bool circulating = false;   // Len word's Circulating/"round trip" bit (0x4000)
    bool more_follows = false;  // Len word's More bit (0x8000) -- see the chaining paragraph above
    uint16_t irq = 0;           // raw interrupt-request bitmask, not decoded further

    std::string data_hex;  // raw hex -- never value-decoded, see the header comment's "Data is
                             // deliberately never value-decoded" paragraph
    size_t data_length = 0;

    uint16_t wkc = 0;  // Working Counter -- see the header comment's WKC paragraph
};

struct EthercatFrame {
    uint16_t declared_length = 0;  // the frame header's own Length field (11 bits)
    bool reserved_bit_set = false;  // frame header's Reserved bit (0x0800) -- spec says must be 0
    uint8_t frame_type = 0;         // frame header's Type field (4 bits), always 1-5 when this
                                      // struct is returned at all -- see try_parse_ethercat
    std::string frame_type_name;    // "EtherCAT command"/"ADS"/"RAW-IO"/"NV"/"Mailbox" -- always
                                      // set

    bool has_datagrams = false;  // true only when frame_type == 1 -- see the header comment's
                                   // "explicitly out of scope" paragraph for Types 2-5
    std::vector<EthercatDatagram> datagrams;  // every datagram actually decoded, when has_datagrams

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x88A4 -- or after a
// single 802.1Q VLAN tag, already unwrapped by parse_ethernet; see link_layer.hpp) as one EtherCAT
// frame. Returns std::nullopt (never throws) when there aren't even 2 bytes for the frame header,
// or when the header's Type field isn't one of the five values the spec defines (1-5) -- see this
// file's header comment's "structural detection gate" paragraph for why that, plus the dedicated
// EtherType, is this decoder's confidence basis. A frame whose Type IS recognized but isn't 1
// ("EtherCAT command") still returns a value (frame_type/frame_type_name set, has_datagrams
// false) -- named, not decoded further, the same "named only" pattern goose.hpp's GSE Management
// PDU and profinet.hpp's non-DCP/non-cyclic FrameID ranges already use.
std::optional<EthercatFrame> try_parse_ethercat(ByteSpan eth_payload);

}  // namespace conduitscope
