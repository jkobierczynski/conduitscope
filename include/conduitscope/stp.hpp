// SPDX-License-Identifier: Apache-2.0
// stp.hpp - IEEE Spanning Tree Protocol family: STP (802.1D), RSTP (802.1w), and MSTP (802.1s)
// BPDU (Bridge Protocol Data Unit) decoding.
//
// Unlike every other protocol this tool decodes, STP is reached neither through IPv4 nor through a
// DIX Ethernet II EtherType -- it rides classic IEEE 802.3/LLC framing (see link_layer.hpp's file
// header comment for the length-vs-EtherType plumbing this required). A BPDU is carried inside an
// LLC frame whose DSAP == SSAP == 0x42 (LLC_SAP_BPDU, the IEEE "Bridge Group Address" SAP) and
// Control == 0x03 (LLC Type 1 "Unnumbered Information"), conventionally (not exclusively -- see
// below) addressed to the well-known multicast MAC 01:80:C2:00:00:00. try_parse_stp below is given
// exactly the bytes after that 3-byte LLC header (EthernetFrame::llc_payload, SNAP not applicable
// here -- STP is never SNAP-encapsulated; that's Cisco (R)PVST+'s own envelope, see "Out of scope"
// below).
//
// GARP collision (an honest scope note, not a hypothetical): DSAP/SSAP 0x42 is NOT exclusive to
// STP. GARP applications -- GVRP and GMRP -- also register on this exact same LLC SAP pair;
// Wireshark's own `packet-bpdu.c` (`dissect_bpdu`) disambiguates them from STP purely by
// DESTINATION MAC, before looking at a single BPDU byte: addresses 01:80:C2:00:00:0D and
// 01:80:C2:00:00:20-0x2F are GVRP/GMRP, not STP, and get redirected to those dissectors entirely.
// This decoder does the same: decoder.cpp checks the destination MAC against that range BEFORE
// calling try_parse_stp at all, and reports a recognized-but-not-decoded "GARP (GVRP/GMRP)" result
// instead for those addresses -- the one case in this codebase where a fixed address genuinely does
// gate detection (everywhere else, including STP's own Bridge Group Address multicast MAC, this
// codebase prefers a structural check over an address check -- this is the documented exception,
// forced by DSAP/SSAP 0x42 alone being genuinely ambiguous between STP and GARP).
//
// Sourcing: every field offset, length, and quirk below is cross-checked directly against
// Wireshark's own `epan/dissectors/packet-bpdu.c` (fetched and read in full during this task's own
// research phase), the same sourcing standard this codebase already uses throughout (e.g. FF-HSE's
// `packet-ff.c`, see ffhse.hpp). Offsets below are relative to the START of the BPDU body (i.e.
// right after the 3-byte LLC header).
//
// Wire format:
//   Protocol Identifier          @0  2 bytes  -- always 0x0000 when recognized
//   Protocol Version Identifier  @2  1 byte   -- 0=STP(802.1D), 2=RSTP(802.1w), 3=MSTP(802.1s),
//                                                 4=SPB(802.1aq, named-only -- see below)
//   BPDU Type                    @3  1 byte   -- 0x00=Configuration, 0x80=Topology Change
//                                                 Notification (TCN), 0x02=RST BPDU (reused for
//                                                 BOTH RSTP and MSTP -- disambiguated by Protocol
//                                                 Version Identifier, never by BPDU Type alone)
//
// TCN BPDU (Type 0x80): body is ONLY the 4 bytes above -- TC_BPDU_SIZE in the reference source.
// Sent by a bridge upward toward the root when it detects a topology change; no flags, no bridge/
// root IDs, nothing else. This decoder's TCN branch does not gate on the Protocol Version
// Identifier's value at all (the reference source's own version-validity check runs before the TCN
// early-return but never blocks it either -- a TCN with an unusual version byte is still a TCN).
//
// Configuration BPDU (Type 0x00) / RST BPDU (Type 0x02): share an identical 35-byte common body
// (CONF_BPDU_SIZE in the reference source):
//   Flags                        @4   1 byte   -- see "Flags" below
//   Root Identifier              @5   8 bytes  -- see "Bridge/Root Identifier" below
//   Root Path Cost                @13  4 bytes
//   Bridge Identifier             @17  8 bytes  -- see "Bridge/Root Identifier" below
//   Port Identifier                 @25  2 bytes  -- see "Port Identifier" below
//   Message Age                      @27  2 bytes  -- units of 1/256 second
//   Max Age                            @29  2 bytes  -- units of 1/256 second
//   Hello Time                          @31  2 bytes  -- units of 1/256 second
//   Forward Delay                        @33  2 bytes  -- units of 1/256 second
// For Type 0x00 (classic STP, version 0 in practice), the BPDU ends here -- only Flags bits 7 (TCA)
// and 0 (TC) are ever meaningful; this decoder still surfaces every flag bit generically (this
// codebase's usual "show it, note when a field is meaningful only in certain contexts" posture),
// never hides bits 1-6.
//
// For Type 0x02, one more byte follows:
//   Version 1 Length             @35  1 byte   -- always 0x00 for pure RSTP; a nonzero value here
//                                                  (together with version >= 3 and enough captured
//                                                  bytes) is this format's own signal that an MST
//                                                  extension does NOT follow (see MSTP detection
//                                                  below) -- Wireshark's own reference source
//                                                  decodes ANY Type-0x02 BPDU through this same
//                                                  36-byte "RST BPDU" shape regardless of what the
//                                                  Protocol Version Identifier byte actually says
//                                                  (it doesn't require version==2); this decoder
//                                                  matches that tolerant behavior exactly.
//
// MSTP detection (per the reference source's own `dissect_bpdu`, NOT guessed): a Type-0x02 BPDU is
// decoded as a full MST BPDU only when ALL THREE hold: Protocol Version Identifier >= 3, Version 1
// Length == 0, and at least 102 bytes are present in the whole BPDU body. When Type is 0x02 but
// that three-part gate fails (even if version is 3), this decoder falls back to the plain 36-byte
// RST BPDU shape above, exactly as the reference source does -- version alone never overrides that.
//
// MST BPDU body, when the gate above holds:
//   Version 3 Length                  @36  2 bytes
//   MST Config Format Selector         @38  1 byte
//   MST Config Name                     @39  32 bytes  -- ASCII, NUL-padded
//   MST Config Revision Level            @71  2 bytes
//   MST Config Digest                     @73  16 bytes  -- an MD5/HMAC-MD5 digest of the VLAN-to-
//                                                            MSTI mapping table; shown as raw hex,
//                                                            never verified (this codebase's usual
//                                                            non-verification-of-opaque-digests
//                                                            posture, e.g. HART-IP's own checksum)
//   CIST Internal Root Path Cost           @89  4 bytes
//   CIST Bridge Identifier                  @93  8 bytes   -- see "Bridge/Root Identifier" below;
//                                                              this is the CIST regional root's OWN
//                                                              bridge ID, distinct from the outer
//                                                              Root/Bridge Identifier @5/@17 (which
//                                                              describe the CIST at the whole-
//                                                              network level)
//   CIST Remaining Hops                      @101 1 byte
//   MSTI Configuration Message(s)             @102 16 bytes EACH -- see "MSTI Configuration
//                                                                    Message" below
// MST_BPDU_SIZE == 38 (the fixed portion through Version 3 Length) and VERSION_3_STATIC_LENGTH ==
// 64 (MST Config Format Selector through CIST Remaining Hops inclusive: 1+32+2+16+4+8+1 = 64,
// confirmed against the field sizes above) are the reference source's own names for these
// constants, reused here for the same values.
//
// How many MSTI messages follow -- the reference source's own arithmetic, NOT a naive "(Version 3
// Length - 64) / 16":
//   - Version 3 Length != 0: if it's >= 64, total MSTI bytes = Version 3 Length - 64 (the ordinary,
//     documented case). If it's nonzero but < 64, the reference source instead treats it as a COUNT
//     OF MESSAGES rather than bytes (total MSTI bytes = Version 3 Length * 16) -- an explicit
//     work-around in `packet-bpdu.c` for real Cisco C3550 firmware observed sending Version 3
//     Length in units of messages instead of octets, per the IEEE 802.1Q/802.1s standard's own
//     documented ambiguity. This decoder reproduces that exact work-around and notes when it's
//     taken.
//   - Version 3 Length == 0: this is the "Alternative MSTI format" trigger -- see below.
//   The resulting byte count is then clamped to whatever bytes are actually present and to a whole
//   number of 16-byte messages (a partial trailing message is noted, not decoded), and further
//   capped at kMaxStpMstiMessages (see stp.cpp) against a malformed/adversarial capture.
//
// Alternative MSTI format: when Version 3 Length == 0, the reference source checks whether the
// WHOLE BPDU's captured length equals `MST Config Format Selector byte's value + MST_BPDU_SIZE(38)
// + 1` -- if so, it's a different, older per-instance layout (`ALT_MSTI_*` in the reference
// source: MSTID as its own explicit 2-byte field, Bridge Identifier/Root Path Cost in a different
// byte order than the IEEE format above, 26 bytes per message instead of 16). This decoder
// recognizes that trigger condition (structurally, from the same source-confirmed arithmetic) and
// names it (StpFrame::is_alt_msti_format) but does NOT decode its body -- explicitly out of scope
// for this first pass, matching this codebase's honesty convention (better an honest "not decoded"
// than a guessed field layout for a format this decoder has no independent confirmation of). Since
// CIST Bridge Identifier/Root Path Cost genuinely live at different byte offsets in the alternative
// format than in the IEEE one, this decoder does not read them at the IEEE offsets for ANY Version-
// 3-Length-0 frame at all (whether or not the alternative format's own exact-length trigger
// matches) -- see StpFrame::cist_bridge_id's own comment.
//
// MSTI Configuration Message (16 bytes each, MSTI_MESSAGE_SIZE in the reference source, offsets
// relative to the start of each message):
//   MSTI Flags                          @0   1 byte   -- same 8-bit layout as the common Flags
//                                                         byte (the reference source dissects it
//                                                         with the identical `rst_flags` bitmask
//                                                         table)
//   MSTI Regional Root                   @1   8 bytes  -- a 16-bit priority+MSTID value (see below)
//                                                          followed by a 6-byte MAC
//   MSTI Internal Root Path Cost         @9   4 bytes
//   MSTI Bridge Identifier Priority       @13  1 byte  -- see below; NOT the same split this file's
//                                                          own research brief originally assumed
//   MSTI Port Identifier Priority          @14  1 byte  -- same story as the previous field
//   MSTI Remaining Hops                     @15  1 byte
//
// MSTI Regional Root's priority/MSTID split -- confirmed by hand-deriving the reference source's
// own byte-at-a-time arithmetic (`msti_regional_root_priority = (byte0 & 0xf0) << 8;
// msti_regional_root_mstid = ((byte0 & 0x0f) << 8) + byte1`) back into an equivalent 16-bit
// operation: reading the two bytes as one big-endian 16-bit value and masking it with 0xF000
// (priority) / 0x0FFF (MSTID) produces IDENTICAL results to the source's byte-wise version. So this
// field's split is, after all, byte-for-byte the SAME formula as the outer Bridge/Root Identifier's
// own priority/system-ID-extension split below (top nibble * 4096 = priority, bottom 12 bits =
// MSTID) -- this codebase's own research brief for this task flagged this as possibly different
// and asked for it to be double-checked against the source rather than assumed; having done that
// double-check, it is confirmed to be the same split after all, not a different one.
//
// MSTI Bridge/Port Identifier Priority bytes (@13/@14) -- THIS is the field that genuinely deviates
// from a plausible-sounding assumption. The reference source decodes ONLY the top nibble of each
// byte (`tvb_get_uint8(...) >> 4`, rendered as a raw 0-15 value, `hf_bpdu_msti_bridge_identifier_
// priority`/`..._port_identifier_priority`, both plain FT_UINT8/BASE_DEC with no multiplier and no
// bitmask on the low nibble) -- it does NOT split the low nibble out as "part of the MSTI ID" or
// anything else; that nibble is simply never decoded by the reference dissector at all. This
// decoder matches that exactly: MSTI_BRIDGE_IDENTIFIER_PRIORITY's byte>>4 (0-15, NOT multiplied by
// 4096 the way the outer Bridge Identifier's priority nibble is -- Wireshark renders this
// particular field as a bare 0-15 value, unlike every other priority field in this format) is
// surfaced, and the low nibble is left undecoded. (This is the one place this task's own research
// brief explicitly asked to be double-checked against the source rather than assumed, and it turned
// out to disagree with the brief's summary -- the source wins, per this task's own instructions.)
//
// Flags (1 byte, BPDU_FLAGS @4 of the common body, and MSTI Flags @0 of each MSTI message -- same
// bit layout both places):
//   bit 7 (0x80) Topology Change Acknowledgment (TCA)
//   bit 6 (0x40) Agreement           -- RSTP/MSTP only, reserved/0 under classic STP
//   bit 5 (0x20) Forwarding          -- RSTP/MSTP only
//   bit 4 (0x10) Learning            -- RSTP/MSTP only
//   bits 3-2 (0x0C) Port Role        -- RSTP/MSTP only; >> 2, values: 0=Unknown, 1=Alternate/Backup,
//                                       2=Root, 3=Designated (role_vals in the reference source)
//   bit 1 (0x02) Proposal            -- RSTP/MSTP only
//   bit 0 (0x01) Topology Change (TC)
//
// Bridge/Root Identifier (8 bytes, appears at Root Identifier @5, Bridge Identifier @17, and CIST
// Bridge Identifier @93 -- identical packing every time, and identical to MSTI Regional Root's own
// packing, see above): a 2-byte value, top 4 bits (mask 0xF000) = Bridge Priority (displayed value
// is the masked nibble itself, i.e. a multiple of 4096 -- default priority 32768 = nibble 8), bottom
// 12 bits (mask 0x0FFF) = System ID Extension (802.1t; carries a VLAN ID for per-VLAN spanning tree
// variants like PVST+, itself out of scope here -- see below), followed by a 6-byte MAC. This
// decoder renders both the raw 16-bit value and the priority/system-ID-extension split, and the MAC
// via link_layer.hpp's format_mac, matching this codebase's own formatting everywhere else.
//
// Port Identifier (2 bytes @25 of the common body): the reference source's own UI shows this as ONE
// raw 16-bit value with no sub-fields (`hf_bpdu_port_id` alone) -- but the underlying 802.1D spec
// defines it as top 4 bits = Port Priority (a multiple of 16; NOTE this is a DIFFERENT multiplier
// than Bridge/Root Identifier's own priority nibble -- default Port Priority 128 = nibble 8, 8*16 =
// 128, vs. Bridge Priority's nibble*4096) + bottom 12 bits = Port Number. This decoder decodes both
// the raw value and that split, per this codebase's own convention of decoding a field as fully as
// the spec allows even where the reference dissector's UI doesn't bother splitting it (the same
// kind of split Bridge/Root Identifier's own priority/sys-id-ext already gets) -- this split is NOT
// literally present in the reference dissector's own field table, only the underlying spec's own,
// well-established field definition.
//
// Structural detection gate: Protocol Identifier == 0x0000 AND BPDU Type in {0x00, 0x02, 0x80} AND
// (for 0x00/0x02 only -- TCN's own version byte is never checked, see above) Protocol Version
// Identifier in {0, 2, 3, 4} -- version 4 (SPB) is recognized structurally but named-only, never
// body-decoded (see below). This is a considerably STRONGER structural anchor than most of this
// codebase's other detectors: several independent small-valid-domain fields (a fixed 2-byte
// Protocol Identifier, a 3-value BPDU Type enum, and, for two of those three types, a 4-value
// version enum) must all co-occur, the same "multiple independent fields, not one loose length
// check" strength class as OPC UA's own 3-byte ASCII magic-string gate (see opcua.hpp) -- and
// notably stronger than HART-IP's or FF-HSE's own honestly-weaker gates (see hartip.hpp/ffhse.hpp).
// This decoder is deliberately slightly STRICTER here than the reference source itself: Wireshark's
// own dissector accepts (and merely warns on) ANY Protocol Version Identifier byte at all, never
// rejecting a frame outright over it, whereas this decoder returns std::nullopt for a Type-0x00/
// 0x02 BPDU whose version isn't one of {0,2,3,4} -- a deliberate, narrower choice matching this
// task's own specified gate, not a discrepancy this decoder failed to notice.
//
// Explicitly out of scope for this release (named only when structurally recognizable, never
// decoded further, matching this codebase's established "recognized but not this release's
// problem" posture -- see e.g. GOOSE's GSE Management PDU in goose.hpp):
//   - Cisco PVST+ / Rapid-PVST+: a genuinely different wire envelope, not a variant of the format
//     above -- SNAP-encapsulated (LLC DSAP=SSAP=0xAA, not 0x42) with Cisco's OUI (00:00:0C) and its
//     own Protocol-ID-like field, typically addressed to 01:00:0C:CC:CC:CD, with a proprietary TLV
//     (Originating VLAN, type 0) appended after the standard BPDU body -- confirmed directly against
//     the reference source's own `dissect_bpdu_pvst_tlv`/`BPDU_PVST_TLV_ORIGVLAN`/`CISCO_PID_PVSTPP`
//     handling. Recognized structurally (SNAP DSAP/SSAP + Cisco OUI, via link_layer.hpp's
//     EthernetFrame::has_snap/snap_oui) and named "Cisco PVST+ (SNAP-encapsulated, not decoded)" by
//     decoder.cpp, but its body -- including the standard BPDU fields it also nominally carries --
//     is never decoded here, the same treatment R-GOOSE/R-SV get relative to GOOSE/SV (see
//     goose.hpp/sv.hpp) and Alarm frames get relative to PROFINET RT cyclic data (see profinet.hpp).
//     This decoder does not chase this format further; a dedicated research/implementation pass for
//     it, should one ever happen, is a separate, later task.
//   - SPB (Shortest Path Bridging, 802.1aq, Protocol Version Identifier == 4, reusing BPDU Type
//     0x02): named only ("SPB (802.1aq), not decoded -- out of scope"). Note for a future
//     documentation pass: the reference source actually DOES decode part of a version-4 SPB frame
//     (it runs the identical MSTP body-parsing path for version >= 3, then, when version >= 4 and a
//     few more conditions hold, appends its own further "SPT Extension" -- Agreement/MCID data).
//     This decoder deliberately does NOT follow that path -- it treats ANY version-4 frame as
//     named-only from the Protocol Version Identifier byte alone, per this task's own explicit scope
//     directive, not because the reference source lacks the logic to go further.
//   - GARP (GVRP/GMRP): see the "GARP collision" paragraph above.
//   - Any other LLC DSAP/SSAP pair on a classic-802.3-framed packet (there are other well-known
//     ones, e.g. IPX, SNA) is not STP -- decoder.cpp names it generically by its raw DSAP/SSAP
//     values, the same way link_layer.hpp's ethertype_name names a handful of EtherTypes for a
//     non-IPv4 DIX frame, without guessing at what it actually is.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// A decoded "priority + N-bit extension" 16-bit identifier field -- used for Root Identifier,
// Bridge Identifier, CIST Bridge Identifier, and MSTI Regional Root, all of which share the
// identical top-nibble-priority / bottom-12-bits-extension packing (see this file's header comment).
struct StpBridgeId {
    uint16_t raw = 0;         // the raw 16-bit value, unmodified
    uint16_t priority = 0;    // raw & 0xF000 -- already in "multiple of 4096" form (default 32768)
    uint16_t ext = 0;         // raw & 0x0FFF -- System ID Extension (Bridge/Root/CIST Bridge ID) or
                                // MSTID (MSTI Regional Root)
    std::array<uint8_t, 6> mac{};
};

// One decoded MSTI Configuration Message -- see this file's header comment.
struct StpMstiMessage {
    uint8_t flags = 0;
    bool flag_tca = false, flag_agreement = false, flag_forwarding = false, flag_learning = false;
    uint8_t flag_port_role = 0;  // 0-3, see role_vals in this file's header comment
    bool flag_proposal = false, flag_tc = false;

    StpBridgeId regional_root;  // .ext here is the MSTI ID (MSTID), not a VLAN system-id-extension
    uint32_t internal_root_path_cost = 0;

    // See this file's header comment's "MSTI Bridge/Port Identifier Priority bytes" paragraph --
    // ONLY the top nibble (0-15, not multiplied by anything) is ever decoded by the reference
    // source for either of these two bytes; the bottom nibble of each is left undecoded.
    uint8_t bridge_identifier_priority_nibble = 0;
    uint8_t port_identifier_priority_nibble = 0;

    uint8_t remaining_hops = 0;
};

struct StpFrame {
    uint16_t protocol_identifier = 0;  // always 0x0000 when recognized at all
    uint8_t protocol_version = 0;      // 0/2/3/4
    std::string protocol_version_name; // "STP (802.1D)"/"RSTP (802.1w)"/"MSTP (802.1s)"/"SPB (802.1aq)"
    uint8_t bpdu_type = 0;             // 0x00/0x02/0x80
    std::string bpdu_type_name;        // "Configuration"/"Rapid/Multiple Spanning Tree"/
                                         // "Topology Change Notification"

    bool is_tcn = false;   // BPDU Type 0x80 -- nothing else below is ever set
    bool is_spb = false;   // Protocol Version 4 -- named only, nothing else below is ever set

    // --- Common Configuration/RST BPDU body (set when !is_tcn && !is_spb) ---
    bool has_common_body = false;  // false only when truncated before all 35 common bytes fit
    uint8_t flags = 0;
    bool flag_tca = false, flag_agreement = false, flag_forwarding = false, flag_learning = false;
    uint8_t flag_port_role = 0;
    bool flag_proposal = false, flag_tc = false;

    StpBridgeId root_id;
    uint32_t root_path_cost = 0;
    StpBridgeId bridge_id;
    uint16_t port_id_raw = 0;
    uint16_t port_id_priority = 0;  // (raw >> 12) * 16 -- see this file's header comment's "Port
                                      // Identifier" paragraph for why this multiplier differs from
                                      // Bridge/Root Identifier's own
    uint16_t port_id_number = 0;    // raw & 0x0FFF
    double message_age = 0.0, max_age = 0.0, hello_time = 0.0, forward_delay = 0.0;  // seconds

    // --- RST/MST-only trailer (set when has_common_body && bpdu_type == 0x02) ---
    bool has_version1 = false;   // false only when truncated right after the common body
    uint8_t version_1_length = 0;

    // --- Full MST extension (set only when the three-part MSTP detection gate holds -- see this
    // file's header comment) ---
    bool is_mstp = false;
    uint16_t version_3_length = 0;
    uint8_t mst_config_format_selector = 0;
    std::string mst_config_name;             // 32 bytes, NUL-trimmed
    uint16_t mst_config_revision_level = 0;
    std::string mst_config_digest_hex;       // 16 bytes, raw hex, never verified

    // Set ONLY when version_3_length != 0 -- when it's 0 (the legacy/alternative MSTI format's own
    // trigger, see is_alt_msti_format below), CIST Bridge Identifier/Root Path Cost genuinely live
    // at different byte offsets in that format than the fixed IEEE offsets these three fields are
    // read from, so this decoder leaves them at their defaults rather than reading meaningless
    // bytes from the wrong place -- see this file's header comment's "MSTI detection" paragraph.
    uint32_t cist_internal_root_path_cost = 0;
    StpBridgeId cist_bridge_id;
    uint8_t cist_remaining_hops = 0;
    std::vector<StpMstiMessage> msti_messages;  // also empty whenever version_3_length == 0

    bool is_alt_msti_format = false;  // legacy/alternative MSTI layout detected (version_3_length
                                        // == 0 AND the frame's total length matches that format's
                                        // own sizing rule exactly) -- not decoded, see this file's
                                        // header comment. version_3_length == 0 WITHOUT that exact
                                        // match is simply an unrecognized/malformed MST extension --
                                        // also not decoded, but not named as alt-format either (a
                                        // note explains why either way, see try_parse_stp)

    std::string summary;
    std::vector<std::string> notes;
};

// Renders the Port Role sub-field's 2-bit value (0-3, see stp.hpp's file header comment's "Flags"
// paragraph) as a name -- exposed so decoder.cpp can populate DecodedPacket::stp_flag_port_role_name
// without duplicating this table.
std::string stp_port_role_name(uint8_t role);

// Renders one MSTI Configuration Message as a single summary line -- exposed so decoder.cpp can
// populate DecodedPacket::stp_msti_messages without duplicating this formatting.
std::string stp_render_msti_summary(const StpMstiMessage& m);

// Attempts to interpret `llc_payload` (the bytes immediately after a classic-802.3 frame's 3-byte
// LLC header -- see link_layer.hpp's EthernetFrame::llc_payload; the caller is responsible for
// having already checked DSAP == SSAP == LLC_SAP_BPDU, Control == LLC_CONTROL_UI, and that the
// destination MAC is NOT in the GARP range, see this file's header comment) as one STP/RSTP/MSTP
// BPDU. Returns std::nullopt (never throws) when the structural detection gate described in this
// file's header comment isn't met.
std::optional<StpFrame> try_parse_stp(ByteSpan llc_payload);

}  // namespace conduitscope
