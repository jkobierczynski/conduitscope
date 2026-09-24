// SPDX-License-Identifier: Apache-2.0
// bsap.hpp - BSAP (Bristol Standard Asynchronous/Synchronous Protocol, Bristol Babcock /
// Emerson Remote Automation Solutions) decoding -- UDP port 1234.
//
// NAMING: Jurgen asked to add "BSAAP", pointing at
// github.com/EmreEkin/ICS-Pcaps/tree/master/BSAAP. No protocol or acronym named "BSAAP" (with a
// double A) was found anywhere in this research -- every other source (Emerson's own official
// documentation, the CISA/Zeek open-source parser described below, multiple ICS protocol
// catalogs) uses "BSAP". This decoder therefore treats "BSAAP" as that repository's own naming
// variant/typo for BSAP and implements BSAP; if a genuinely distinct "BSAAP" protocol surfaces
// later this should be revisited. Named `bsap`/`Bsap*`/`bsap.hpp` throughout.
//
// WHAT IT IS: BSAP is Bristol Babcock's (now Emerson Remote Automation Solutions') proprietary
// polling protocol for its RTU/flow-computer product lines (ControlWave, 3330/3305, FB1000/
// FB2000 FloBoss/flow computers). It predates Ethernet in this product family -- the original,
// fully-specified wire format is a serial (RS-232/RS-485/radio/leased-line) polling protocol;
// "BSAP-IP" (also called BSAP/IP) is a later, thinly-documented adaptation that either tunnels
// the original serial frames over UDP (through an Ethernet-to-serial tap/gateway device) or uses
// a separate, less-documented native IP framing, on the same UDP port -- see WIRE FORMAT below.
//
// SOURCING: (1) Emerson's own official "BSAP Communications Application Programmer's Reference"
// (D301401X012, www.emerson.com) -- the primary, vendor-authored specification for the *serial*
// wire format (message headers, framing, protocol-level function codes); this document itself
// states it does NOT cover the BSAP-IP/Open BSI 3.0 native IP framing. (2) CISA's own
// open-source Zeek protocol parser, github.com/cisagov/icsnpp-bsap (the successor to the now-
// archived icsnpp-bsap-ip and icsnpp-bsap-serial), whose `src/bsap-protocol.pac` binpac grammar
// and `scripts/icsnpp/bsap/main.zeek` log-record schema independently corroborate the serial
// header layout below field-for-field against source (1), and are the only source found for the
// BSAP-IP-native framing sketch below -- a government-published, actively-referenced tool, but
// itself a third-party reverse-engineering effort, not a vendor specification, for the IP side.
// (3) UDP port 1234 as BSAP-IP's default is independently confirmed by three unrelated sources:
// a Kepware/PTC "Bristol IP Driver" manual, an Automation Control Manager (ACM) user-guide wiki
// page ("ControlWave devices default to UDP port 1234, and it's very uncommon for this default
// to be changed"), and Orange Cyberdefense's community-maintained "awesome-industrial-protocols"
// catalog.
//
// HONESTLY STATED SOURCING GAP -- narrower scope than most other decoders in this codebase: no
// numeric table mapping BSAP's own "RDB" (Remote Database Access) function codes to their
// meanings (point read vs. point write vs. array access, etc.) was found in ANY public source
// during this research, including CISA's own reference Zeek parser -- that parser's own grammar
// captures the raw `func_code` byte and logs it numerically, with no semantic table of its own
// either (confirmed by reading its own grammar file directly: it defines no such enum/table).
// This decoder therefore does the same: RDB is this protocol's dominant traffic (every source
// agrees on that), but its own per-operation function codes are shown as a raw byte only, never
// guessed at -- matching this codebase's own "never guess a numeric fallback" discipline, and, in
// this specific case, matching what the best available public tooling for this protocol already
// does. Separately, the BSAP-IP-native framing's own Request-vs-Response discrimination could not
// be confirmed either (no body-embedded request/response flag was found, unlike e.g. GE SRTP's
// own explicit Message Type byte -- see ge_srtp.hpp) -- so BSAP-IP-native traffic is recognized
// and its outer header decoded, but not descended into a Request/Response/RDB sub-structure; see
// EXPLICITLY OUT OF SCOPE below. This decoder was also built without access to a real BSAP
// capture: the pcap Jurgen pointed at (github.com/EmreEkin/ICS-Pcaps/tree/master/BSAAP) could not
// be browsed by this session's web tools (GitHub's own robots.txt blocks directory-listing
// pages), so `tests/sample_bsap.pcap` is entirely synthetic, built from the sources above.
//
// WIRE FORMAT
//
// Every BSAP payload (serial-tunneled or IP-native) opens with the same 2 bytes, read as a
// little-endian uint16: if that value is exactly 0x0210, the rest of the payload is a
// serial-tunneled frame (below); any other value is IP-native framing, and per CISA's own
// grammar that same 2-byte value is then reused (not re-read) as part of the IP-native header --
// see BSAP-IP-NATIVE FRAMING below for the honestly-flagged ambiguity this creates.
//
// SERIAL-TUNNELED FRAMING (proto == 0x0210): after those 2 bytes, ADDR(1) -- bit 0x80 set means
// a Global-format message follows, clear means Local-format; the low 7 bits are the device's
// local (0-0x7F) address. This single bit is independently confirmed by both sourcing (1) and
// (2): Emerson's own document states "LADD = Local address + 80H" for the global case, and the
// exact byte counts below (7 for Local, 12 for Global, ADDR included) match its own stated
// header sizes exactly.
//   Local header, 6 bytes after ADDR (7 total): SER(1, message serial number) + DFUN(1,
//   destination function code) + SEQ(2, LE, application sequence number) + SFUN(1, source
//   function code) + NSB(1, Node Status Byte, shown raw -- no further bit layout found).
//   Global header, 11 bytes after ADDR (12 total): SER(1) + DADD(2, LE, destination global
//   address) + SADD(2, LE, source global address) + CTL(1, control byte, shown raw) + DFUN(1) +
//   SEQ(2, LE) + SFUN(1) + NSB(1).
// DFUN/SFUN share one protocol-level function-code table (Emerson's own document, the only
// numeric BSAP function codes this research could confirm): 0x85 POLL, 0x86 ACK / DOWN-ACK, 0x87
// ACK-NODATA, 0x8B UP-ACK, 0x95 NAK. Any other value is shown as raw hex, never guessed at --
// these are link-level codes, not the RDB application-level function codes (see the sourcing gap
// above). Whatever bytes follow the header are shown as a byte count and hex dump only; this
// decoder does not attempt to further interpret RDB or any other application-layer body, for the
// reasons given above.
//
// BSAP-IP-NATIVE FRAMING (proto != 0x0210): CISA's own grammar names this leading 2-byte field
// `Num_Messages` in its log schema, but its own binpac source reuses that same field's value,
// minus 6, as the declared byte length of the header's own trailing `data` field -- i.e. the
// same 16 bits appears to serve double duty as both a message count (per the log field name) and
// a length (per the grammar's own arithmetic). This project could not independently resolve that
// apparent overload from a second, independent source, so it is surfaced here honestly as-is
// (named `leading_value` and documented, not asserted to definitively mean "message count"),
// rather than committing to either reading with unwarranted confidence. Followed by
// Message_Func(2, LE, shown raw -- no table found for it either). This decoder recognizes and
// structurally counts the BSAP-IP-native shape (the 4-byte header plus a following data region)
// but does not descend into it further -- see the sourcing gap paragraph above and EXPLICITLY OUT
// OF SCOPE below.
//
// HONESTLY WEAK GATE, BSAP-IP-NATIVE PATH SPECIFICALLY: unlike the serial-tunneled path's own
// 0x0210 magic, this shape has no self-describing bytes of its own at all -- any 4-or-more-byte
// UDP/1234 payload that does NOT start with 0x0210 is accepted as a structurally-recognized (if
// semantically near-empty) BSAP-IP-native message. This is a real, deliberate limitation, not an
// oversight: it was found and confirmed while building this decoder's own test fixture (an
// initial 4-byte "negative control" payload turned out to parse successfully instead of being
// rejected). It stays this way -- like RIP's own "a handful of small integers" gate or HSRP's own
// weak structural checks -- because this codebase's answer to a genuinely weak wire-format signal
// is port-gating (this decoder only runs at all on UDP port 1234 in Auto mode), not fabricating a
// stronger-than-real structural check; see docs/PROTOCOL_COVERAGE.md's BSAP section for how this
// was verified not to regress anything else in this codebase's own dispatch cascade.
//
// SESSION STATE: none. Unlike GE SRTP/MELSEC/FINS/Modbus, this decoder does not attempt
// cross-packet request/response pairing -- BSAP's own SER/SEQ fields look plausibly reusable for
// that (as they are in similar protocols this codebase already pairs authoritatively or
// heuristically), but no source confirms a response actually echoes a request's own SER or SEQ
// value, and guessing a pairing scheme without confirmation would risk fabricating matches that
// aren't real. Left unpaired rather than guessed at.
//
// SECURITY CONTEXT: no source found describes any authentication, integrity, or confidentiality
// mechanism in BSAP at any layer -- consistent with its age (a pre-Ethernet-era polling protocol)
// and with its inclusion among the protocols the 2022 Forescout Vedere Labs "OT:ICEFALL" research
// used to illustrate insecure-by-design practices still common in OT products. This decoder does
// not add a curated "unauthenticated" note to every single frame (that would be true of nearly
// all BSAP traffic and would add noise rather than signal, unlike GE SRTP's per-operation notes
// which distinguish read/write/control/recon risk tiers this decoder cannot yet distinguish for
// BSAP's own RDB traffic -- see the sourcing gap above); this paragraph documents the posture
// instead. A NAK response is still flagged with its own note, since it is a directly observable,
// unambiguous signal (communication/access failure) rather than a guess.
//
// EXPLICITLY OUT OF SCOPE for this first pass: BSAP-IP-native's own Request/Response/RDB
// sub-structure past its 4-byte outer header (no confirmed discriminator field or RDB function
// code value -- see the sourcing gap above); RDB's own per-operation function code semantics on
// EITHER transport (point read vs. write vs. array access, etc. -- shown as raw hex only); the
// Node Status Byte's own bit layout; the Control Byte's own bit layout; cross-packet request/
// response pairing; true serial (RS-232/RS-485/radio) capture framing, as opposed to Ethernet-
// carried BSAP (this decoder, like every other in this codebase, only ever sees Ethernet/IP/UDP
// traffic); and BSAP's own non-RDB message classes (time sync, file transfer, etc.) beyond
// showing that a DFUN/SFUN/leading-value byte was seen.
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t BSAP_PORT = 1234;

// The one confirmed numeric function-code table for BSAP -- Emerson's own document's protocol-
// level (not RDB application-level) codes, shared by both DFUN and SFUN. Returns nullopt for any
// other value (shown as raw hex by the caller, never guessed at).
std::optional<std::string> bsap_link_function_name(uint8_t code);

struct BsapFrame {
    bool is_serial_tunnel = false;  // true: proto == 0x0210 (serial-tunneled); false: BSAP-IP-native

    // --- Serial-tunneled fields (is_serial_tunnel == true) ---
    uint8_t addr_raw = 0;
    bool is_global = false;   // addr_raw & 0x80
    uint8_t local_address = 0;  // addr_raw & 0x7F
    uint8_t ser = 0;
    bool has_global_addressing = false;  // true only when is_global
    uint16_t dadd = 0;
    uint16_t sadd = 0;
    uint8_t ctl = 0;
    uint8_t dfun_raw = 0;
    std::optional<std::string> dfun_name;
    uint16_t seq = 0;
    uint8_t sfun_raw = 0;
    std::optional<std::string> sfun_name;
    uint8_t nsb = 0;

    // --- BSAP-IP-native fields (is_serial_tunnel == false) ---
    uint16_t leading_value = 0;   // see BSAP-IP-NATIVE FRAMING above -- named/documented ambiguity
    uint16_t message_func = 0;

    // --- Shared: whatever bytes follow the decoded header, on either transport ---
    bool has_trailing_data = false;
    size_t trailing_data_byte_count = 0;
    std::string trailing_data_hex;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as a BSAP message (either framing). Returns std::nullopt
// (never throws) if the payload is too short for even the smallest recognized header shape (7
// bytes: serial-tunneled Local). This decoder is intentionally structurally weak on the BSAP-IP-
// native path (no strong magic number of its own -- see WIRE FORMAT above), which is why
// decoder.cpp only tries it on UDP port 1234 in Auto mode, the same UdpPort gating convention
// RIP/HSRP already use for the same reason.
std::optional<BsapFrame> try_parse_bsap(ByteSpan udp_payload);

// registration-model ProtocolDecoder wrapper -- no cross-packet state (see SESSION STATE above),
// so this needs nothing beyond id()/gate_kind()/udp_port()/decode(); see bsap.cpp.
class BsapDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "bsap"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return BSAP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& bsap_decoder();

}  // namespace conduitscope
