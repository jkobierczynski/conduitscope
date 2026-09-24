// SPDX-License-Identifier: Apache-2.0
// ieee802154.hpp - raw IEEE 802.15.4 radio-capture framing: pcap LINKTYPE_IEEE802_15_4_WITHFCS
// (195) and LINKTYPE_IEEE802_15_4_TAP (283), plus the IEEE 802.15.4 MAC header itself.
//
// This is the THIRD wholly new link-layer this codebase has ever had to add (the first was classic
// IEEE 802.3/LLC framing for STP; the second was Linux SocketCAN for DeviceNet -- see
// can_socketcan.hpp's own file header comment for that precedent, which this file follows directly).
// IEEE 802.15.4 is the low-power wireless radio MAC layer Zigbee (and Thread, and 6LoWPAN, and a
// handful of other stacks this codebase does not attempt) rides on -- a captured frame carries no
// Ethernet header, no MAC-48 addresses, no EtherType at all; it is an entirely separate, unrelated
// link type from everything else in this codebase, requiring its own two entries in pcap_reader.hpp's
// LinkType enum and its own top-level branch(es) in Decoder::decode (see decoder.cpp), never reached
// through parse_ethernet.
//
// Zigbee (see zigbee.hpp) is the only protocol in this codebase that rides on this link layer today
// -- IEEE 802.15.4 framing itself is protocol-agnostic (Thread and 6LoWPAN traffic would show up in a
// capture this same way), but decoding what a given MAC payload actually MEANS at the Zigbee NWK/APS/
// ZDP level is entirely zigbee.hpp/.cpp's own job; this file only understands the pcap capture record
// shape and the 802.15.4 MAC header fields, nothing about Zigbee's own layers.
//
// TWO CAPTURE FORMATS, ONE SHARED MAC-HEADER PARSER: unlike can_socketcan.hpp (one link type, one
// wire format), Zigbee needs BOTH LINKTYPE_IEEE802_15_4_WITHFCS and LINKTYPE_IEEE802_15_4_TAP --
// see the user-confirmed scope this task shipped under, which explicitly excludes the other three
// IEEE 802.15.4 pcap link types (LINUX=191, NONASK_PHY=215, NOFCS=230). Each capture format has its
// own record framing (WITHFCS: no pseudo-header, MAC frame at byte 0, trailing FCS; TAP: a 4-byte
// fixed header + TLVs, then the MAC frame, FCS presence/length given by an FCS_TYPE TLV rather than
// assumed) but BOTH converge on exactly the same 802.15.4 MAC header shape once the pseudo-header (if
// any) is stripped and the FCS length is known -- so this file exposes two small, format-specific
// entry points, parse_ieee802154_withfcs(ByteSpan) and parse_ieee802154_tap(ByteSpan), which each do
// their own format's framing work and then hand off to one shared internal MAC-header parser,
// producing the same Ieee802154Frame either way. See zigbee.hpp's own file header comment for how
// decoder.cpp's two link-type branches use this (each calls the matching entry point directly, then
// both converge on one shared try_parse_zigbee(const Ieee802154Frame&) -- see that file for why this
// shape was chosen over a single ProtocolDecoder::decode() that would have to guess which framing a
// raw ByteSpan uses).
//
// SOURCING: every field/mask/byte-offset below is taken directly from a from-source research pass
// over Wireshark's own epan/dissectors/packet-ieee802154.c (dissect_ieee802154_fcs/_tap/_common,
// dissect_ieee802154_fcf, dissect_ieee802154_aux_sec_header_and_key_with_hf,
// dissect_ieee802154_header_ie), cross-checked against tcpdump.org's own LINKTYPE registry for the
// two pcap framings -- literal source citations (file/function/line) were captured for every claim.
// Treated as this codebase's strongest existing sourcing tier (the same standing CC-Link IE's own
// two-source verification has) -- see docs/DEVELOPMENT.md's roadmap item for this protocol for the
// full citation list.
//
// SCOPE DECISIONS made directly against that research (documented here, not silently applied):
//   - Multipurpose (frame type 0x5), Reserved (0x4), Fragment (0x6), and Extended (0x7) MAC frame
//     types are recognized (the Frame Control Field's Frame Type subfield is always decoded) but
//     nothing past the FCF is decoded for them. Multipurpose frames in particular use an entirely
//     different, non-standard FCF layout (1 or 2 bytes depending on a "Long Frame Control" bit,
//     completely different sub-field positions) that this file does not implement -- Zigbee never
//     uses Multipurpose frames in practice (confirmed by the research pass), so there is no Zigbee-
//     relevant reason to. Beacon/Data/Ack/(ordinary)Command -- the four types Zigbee actually uses --
//     are fully decoded.
//   - The 802.15.4-2003 frame version's own obsolete security trailer (a bare 4-byte Frame
//     Counter + 1-byte Key Sequence Counter placed directly before the payload, used only when
//     2003-era security is enabled and pre-dating the Auxiliary Security Header format entirely) is
//     NOT decoded -- modern Zigbee requires 802.15.4-2006 or later, so a 2003-framed, security-
//     enabled capture is not realistic Zigbee traffic; has_aux_security stays false for such a frame
//     and its payload (including that undecoded trailer) is reported as opaque MAC payload.
//   - Header/Payload Information Elements (802.15.4-2015+, FCF bit 9) are detected and walked ONLY
///    to find where they end (so the true MAC payload start can still be located correctly) -- no
//     individual IE's own contents are decoded or exposed. See has_header_ies/header_ie_bytes/
//     has_payload_ies/payload_ie_bytes below.
//   - The FCS itself is never validated (no CRC recomputation) -- this decoder only needs to know how
//     many trailing bytes to exclude from the MAC payload, exactly the posture can_socketcan.hpp's
//     own file header comment already established for CAN's FD-payload-size validation (read the
//     length, use it, don't second-guess it against a discrete legal set).
//   - LINKTYPE_IEEE802_15_4_WITHFCS's own alternate "CC24xx metadata trailer" FCS variant (a 2-byte
//     RSSI+LQI trailer some TI radios substitute for a real FCS, configurable via a Wireshark
//     preference) is out of scope -- this decoder always assumes the plain 16-bit-CRC case for this
//     link type, which the research pass confirms is "almost always" what LINKTYPE 195 actually
//     carries. A 4-byte-FCS variant of WITHFCS is not assumed either (that is a preference-only choice
//     in Wireshark, not something the capture itself declares) -- fixed at 2 bytes.
//
// TRUNCATION HANDLING -- this codebase's established "degrade tolerantly, never crash" posture (see
// can_socketcan.hpp's own "Truncation handling" paragraph for the precedent this follows). Both entry
// points below throw ParseError only when the format's own smallest possible fixed structure can't be
// read at all: for WITHFCS/TAP alike, that is the 2-byte Frame Control Field itself once any pseudo-
// header has been stripped (TAP additionally throws if its own 4-byte fixed pseudo-header doesn't
// fit -- a record that short has no Length field to even locate the MAC frame with). Every other
// truncation -- a missing address field, a partial Auxiliary Security Header, an overrunning
// Information Element, a too-short declared MIC -- is handled tolerantly: Ieee802154Frame::malformed
// is set, a human-readable note explains exactly what didn't fit, and everything from that point
// onward is reported as opaque mac_payload rather than guessed at or thrown away with the whole
// packet. Also flagged the same tolerant way (not thrown): a Reserved (0x1) Destination/Source
// Addressing Mode value (never valid in any frame version), a Reserved (0x3) Frame Version value, and
// an addressing-mode/PAN-ID-Compression combination with no defined meaning for the frame's version --
// all three make it impossible to reliably know which fields come next, so this decoder stops rather
// than guess, exactly the same "can't determine field presence, stop cleanly" posture the Reserved-
// address-mode case forced on it either way.
//
// ONE DELIBERATE, DOCUMENTED DEPARTURE from Wireshark's own dissector, per the research report's own
// flagged discrepancy: 802.15.4-2015 Table 7-6 rows 9-11 (Short/Short, Short/Extended, Extended/Short
// addressing with PAN ID Compression clear) are implemented per the table's own literal text (Source
// PAN ID Present), NOT per Wireshark's own `ieee802154e_compatibility` preference override (which
// forces Source PAN ID absent for those rows, to interoperate with real-world 802.15.4e/TSCH gear
// that doesn't strictly follow the table). This decoder has no TSCH-interop goal, so it follows the
// strict spec table instead -- see the research report's own "Summary of discrepancies" section,
// item 2, for the full citation.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// Which of the two in-scope pcap capture formats an Ieee802154Frame was parsed from -- purely
// informational (a caller already knows which entry point it called; this just travels with the
// result so a renderer doesn't need to thread that knowledge through separately).
enum class Ieee802154CaptureVariant { WithFcs, Tap };

// The IEEE 802.15.4 MAC-layer Auxiliary Security Header -- a DIFFERENT, unrelated byte layout from
// Zigbee's own NWK/APS Auxiliary Security Header format (see zigbee.hpp's ZigbeeSecurityHeader and
// this file's own header comment). Real-world Zigbee networks essentially never enable MAC-layer
// security at all (Zigbee secures its NWK/APS layers with their own aux headers instead) -- see
// zigbee.hpp's own scope note for how a frame that DOES have this set is handled (its payload is
// ciphertext at the MAC layer, so no NWK-layer parsing is even attempted).
struct Ieee802154SecurityHeader {
    uint8_t security_level = 0;  // 0-7, see zigbee.hpp's security-level table (same numeric shape)
    uint8_t key_id_mode = 0;     // 0=Implicit, 1=KeyIndex, 2=KeyExplicit4, 3=KeyExplicit8
    bool frame_counter_suppressed = false;  // 2015+ only; always false (and thus frame counter
                                              // always present) pre-2015
    bool asn_in_nonce = false;              // 2015+ only, display-only, not otherwise used here

    bool has_frame_counter = false;
    uint32_t frame_counter = 0;

    // 4 bytes when key_id_mode==2, 8 bytes when key_id_mode==3, absent (empty) otherwise.
    bool has_key_source = false;
    std::vector<uint8_t> key_source_bytes;

    bool has_key_index = false;
    uint8_t key_index = 0;
};

// One decoded IEEE 802.15.4 MAC frame, however it was captured -- see this file's header comment for
// the exact field-presence rules every member below comes from.
struct Ieee802154Frame {
    Ieee802154CaptureVariant capture_variant = Ieee802154CaptureVariant::WithFcs;

    // TAP-only bookkeeping (capture_variant == Tap; every field below this point stays at its
    // default for a WithFcs frame).
    bool tap_valid_version = true;       // false if the fixed header's Version byte wasn't 0
    uint16_t tap_declared_length = 0;    // the Length field: byte offset of the MAC frame
    bool tap_fcs_type_tlv_present = false;
    uint8_t tap_fcs_type = 0;            // 0=None, 1=16-bit CRC, 2=32-bit CRC (only meaningful
                                           // when tap_fcs_type_tlv_present; fcs_length below already
                                           // reflects the effective value either way)

    // FCS bookkeeping (both variants) -- the FCS itself was already excluded from every field below
    // by the time this struct is populated; these two fields are purely for a renderer that wants to
    // say "N bytes of FCS were present and stripped".
    bool fcs_present = false;
    size_t fcs_length = 0;  // 0, 2, or 4

    // Frame Control Field (2 bytes, little-endian) -- always present; this is the one part of an
    // Ieee802154Frame guaranteed to be populated no matter how malformed/truncated the rest is (a
    // frame too short even for this throws ParseError instead of producing an Ieee802154Frame at
    // all -- see this file's header comment).
    uint16_t fcf = 0;
    uint8_t frame_type = 0;   // 0-7, see ieee802154_frame_type_name()
    bool security_enabled = false;
    bool frame_pending = false;
    bool ack_request = false;
    bool pan_id_compression = false;
    bool seqno_suppression = false;  // 2015+ only structurally; see this file's header comment for
                                       // how a pre-2015 frame with this bit set is still handled
    bool ie_present = false;         // 2015+ only structurally
    uint8_t dst_addr_mode = 0;       // 0-3, see ieee802154_addr_mode_name()
    uint8_t src_addr_mode = 0;       // 0-3
    uint8_t frame_version = 0;       // 0-3, see ieee802154_version_name()

    // Set whenever this decoder hit a condition it can't safely keep decoding past (an out-of-range
    // Reserved value, an addressing combination with no defined meaning, or a declared field that
    // doesn't fit the captured bytes) -- see this file's header comment's "Truncation handling"
    // paragraph. `notes` always explains why. Every field below this point that this decoder gave up
    // trying to parse is left at its default, and mac_payload holds everything from the point of
    // failure onward, undecoded.
    bool malformed = false;

    bool has_seqno = false;
    uint8_t seqno = 0;

    bool has_dst_pan = false;
    uint16_t dst_pan = 0;
    bool has_dst_addr = false;
    bool dst_addr_extended = false;  // selects dst_addr_ext vs dst_addr_short below
    uint16_t dst_addr_short = 0;
    uint64_t dst_addr_ext = 0;

    // Note: a Source PAN ID that the spec says to treat as "same as Destination PAN ID, so omitted
    // from the wire" is NOT synthesized here as has_src_pan=true -- it genuinely was not on the wire
    // (see this file's header comment's Step 3 citation on this exact point). has_src_pan is true
    // only when a Source PAN ID field was actually present and read.
    bool has_src_pan = false;
    uint16_t src_pan = 0;
    bool has_src_addr = false;
    bool src_addr_extended = false;
    uint16_t src_addr_short = 0;
    uint64_t src_addr_ext = 0;

    bool has_aux_security = false;
    Ieee802154SecurityHeader aux_security;

    // Header/Payload IE presence -- walked only to find where they end (see this file's header
    // comment); no individual IE's contents are exposed, only the total byte span consumed.
    bool has_header_ies = false;
    size_t header_ie_bytes = 0;
    bool has_payload_ies = false;
    size_t payload_ie_bytes = 0;

    // Bytes reserved at the tail of the frame for a MIC (Message Integrity Code), computed from
    // aux_security.security_level when has_aux_security -- already excluded from mac_payload below,
    // kept here only so a renderer can say "N bytes of MIC" structurally.
    size_t mic_length = 0;

    // Everything after FCF/seqno/addressing/aux-security-header/IEs, up to (but excluding) the
    // trailing MIC (if any) and the FCS (already stripped before this struct existed). This is
    // Zigbee's own NWK-layer bytes when frame_type==Data and security_enabled is false -- see
    // zigbee.hpp's own scope note for why a MAC-layer-security-enabled frame's mac_payload is NOT
    // handed to NWK parsing at all (it is ciphertext; Zigbee itself never enables MAC-layer security
    // in practice).
    ByteSpan mac_payload;

    std::vector<std::string> notes;
};

// Human-readable names for the small enumerated fields above -- shared by zigbee.cpp/decoder.cpp/
// output.cpp for consistent rendering, so no caller needs its own copy of these tables.
const char* ieee802154_frame_type_name(uint8_t frame_type);
const char* ieee802154_addr_mode_name(uint8_t addr_mode);
const char* ieee802154_version_name(uint8_t frame_version);

// Parses one LINKTYPE_IEEE802_15_4_WITHFCS (195) pcap capture record: no pseudo-header, the MAC
// frame begins at byte 0, a trailing 2-byte FCS is always assumed and excluded -- see this file's
// header comment. Throws ParseError only when fewer than 2 bytes (the Frame Control Field itself)
// remain once the assumed FCS is excluded.
Ieee802154Frame parse_ieee802154_withfcs(ByteSpan record);

// Parses one LINKTYPE_IEEE802_15_4_TAP (283) pcap capture record: a 4-byte fixed pseudo-header
// (Version/Reserved/Length) followed by TLVs up to the declared Length, then the real 802.15.4 MAC
// frame -- FCS presence/length for that MAC frame comes from the FCS_TYPE TLV (0x0000), defaulting
// to "no FCS" if that TLV is absent, unlike WITHFCS's own always-assume-an-FCS default. Throws
// ParseError only when fewer than 4 bytes (the fixed pseudo-header itself) are present, or when
// fewer than 2 bytes (the Frame Control Field) remain in the located MAC frame region.
Ieee802154Frame parse_ieee802154_tap(ByteSpan record);

}  // namespace conduitscope
