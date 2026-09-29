// SPDX-License-Identifier: Apache-2.0
// goose.hpp - IEC 61850-8-1 GOOSE (Generic Object Oriented Substation Event, EtherType 0x88B8)
// decoding: the 8-byte GOOSE APDU header, the ASN.1 BER-encoded GOOSE PDU (gocbRef/datSet/goID/
// timestamp/stNum/sqNum/simulation/confRev/ndsCom/the allData dataset), and, recursively, the
// allData dataset's own self-describing ASN.1 "Data" values.
//
// Like PROFINET RT (see profinet.hpp), GOOSE rides directly on raw Ethernet, with no IPv4/UDP/TCP
// layer at all. A GOOSE frame's payload (immediately after the EtherType, or after a single 802.1Q
// VLAN tag already unwrapped by parse_ethernet -- real GOOSE traffic is commonly priority-tagged,
// see this file's Validation section) begins with an 8-byte fixed header, all fields big-endian
// (cross-checked against Wireshark's `packet-goose.c`, generated from the IEC 61850-8-1 ASN.1
// module by asn2wrs):
//   APPID(2) + Length(2) + Reserved1(2) + Reserved2(2)
// Length is the total byte count of this header plus the ASN.1 APDU that follows (it includes
// itself) -- `dissect_goose` loops `while (offset < length)` from offset 8 and flags `length < 8`
// as bogus. Reserved1's top bit (0x8000, "S-bit") is the header-level "Simulated" flag IEC
// 61850-8-1 Ed.2 defines for a simulated/test frame -- cross-checked against packet-goose.c's
// `hf_goose_reserve1_s_bit` and its `ei_goose_invalid_sim` expert-info check, which flags an
// S-bit-set frame whose PDU-level `simulation` field (see below) is NOT also true as an
// inconsistency worth a note (this decoder does the same; see try_parse_goose's comment). Reserved2
// is not surfaced (no defined meaning in IEC 61850-8-1 Ed.1/Ed.2 as of this writing).
//
// The APDU is ASN.1 BER, IMPLICIT-tagged throughout (confirmed against packet-goose.c's
// `IECGoosePdu_sequence`/`Data_choice`/`GOOSEpdu_choice` tables, and independently against a real
// device's capture bytes -- see this file's Validation section below): a tag byte, a length
// (short-form 0-127 in one byte, or long-form: a byte with the top bit set and the low 7 bits
// giving how many big-endian length bytes follow), then that many content bytes -- constructed
// types (tag bit 0x20 set) nest more TLVs inside their content, primitive types don't. Indefinite-
// length BER (a length byte of 0x80) is not supported: this profile's constructed types always use
// definite-length encoding, and no capture checked ever produced one. Two outer APDU choices exist
// (`GOOSEpdu_choice`):
//   - 0x61 (APPLICATION class, constructed, tag 1): the actual GOOSE PDU -- fully decoded below.
//   - 0xA0 (APPLICATION class, constructed, tag 0): a GSE Management PDU (GetReferenceRequest/
//     GetElementRequest/Response -- an engineering-tool query/response exchange, not GOOSE's actual
//     OT-security-relevant periodic multicast state-change traffic) -- named only
//     (GooseFrame::is_gse_management), not decoded further; out of this groundwork release's scope,
//     the same "recognized but not this release's problem" treatment PROFINET RT gives Alarm/PTCP
//     frames (see profinet.hpp).
// Anything else at that position is not recognized as GOOSE: try_parse_goose returns std::nullopt
// and the caller (decoder.cpp) falls back to the generic "non-ip" ethertype-name-only report, as it
// always has for 0x88B8 traffic that doesn't parse as one of these two tags -- a narrow,
// high-specificity gate (exactly two byte values, both independently confirmed against Wireshark's
// dissector table), deliberately not a generic "Length field looks plausible" heuristic, the same
// design choice PROFINET RT's FrameID range check makes (see profinet.hpp's file header comment): a
// non-GOOSE frame carrying EtherType 0x88B8 (there is no requirement that it does, unlike an IP
// protocol number) should fall back to being named, not guessed at.
//
// This release decodes exactly one GOOSE PDU per Ethernet frame. IEC 61850-8-1's framing technically
// allows several APDUs packed into one frame's declared Length (packet-goose.c's dissect loop is a
// `while`, not an `if`), but no real capture checked while building this decoder ever did this
// (every one carried exactly one APDU per frame; see this file's Validation section), so rather than
// guess at untested multi-APDU handling, try_parse_goose notes leftover bytes inside the declared
// Length after the first APDU and stops there. See docs/MANUAL.md's LIMITATIONS for this and every
// other scope boundary below.
//
// The GOOSE PDU itself (IECGoosePdu_sequence, all IMPLICIT-tagged context-class fields -- tag byte
// = 0x80 | field-number for every primitive-type field below, since IMPLICIT tagging on a
// primitive ASN.1 type keeps the primitive (non-constructed) form; only allData, a SEQUENCE OF, is
// constructed):
//   0x80 gocbRef (VisibleString) -- the GOOSE Control Block reference that produced this frame,
//     e.g. "IEDName/LLN0$GO$gcbName" (IEC 61850's dot/dollar object-reference syntax).
//   0x81 timeAllowedtoLive (INTEGER, milliseconds) -- how long a receiver should consider this
//     state valid before the sender's silence becomes an alarm condition (GOOSE's heartbeat/
//     retransmission mechanism: unchanged state is still retransmitted at an increasing interval,
//     up to this ceiling, precisely so a receiver can detect a dead publisher).
//   0x82 datSet (VisibleString) -- the Data Set object reference whose values allData carries.
//   0x83 goID (VisibleString, OPTIONAL) -- a human-readable GOOSE identifier, often but not always
//     equal to (part of) gocbRef.
//   0x84 t (UtcTime, exactly 8 bytes -- see below) -- when the publisher last changed this state
//     (not a per-retransmission send time).
//   0x85 stNum (INTEGER) -- "state number": increments every time the dataset's *value* changes (a
//     real event), stays constant across pure heartbeat retransmissions. The single most
//     OT-security-relevant field in a GOOSE stream: an unexpected stNum change is a real state
//     change; a stNum that resets/jumps/goes backward without a device restart is a classic GOOSE
//     anomaly-detection signal (misconfiguration or a spoofed/replayed frame).
//   0x86 sqNum (INTEGER) -- "sequence number": resets to 0/1 on every stNum change, then increments
//     on every retransmission of that same state (confirmed against this decoder's real-capture
//     validation: see this file's Validation section). A sqNum that doesn't increment monotonically
//     for an unchanged stNum is the same class of anomaly signal as an unexpected stNum change.
//   0x87 simulation (BOOLEAN, OPTIONAL) -- true when this frame's data was produced by a test/
//     simulation tool rather than the genuine process, per IEC 61850-8-1 Ed.2. Cross-checked
//     against the header's S-bit above; see try_parse_goose's comment for the mismatch note.
//   0x88 confRev (INTEGER) -- the Data Set's configuration revision number; changes only when an
//     engineering tool reconfigures the dataset itself (which attributes/how many), not on every
//     ordinary value change. An unexpected confRev change on a running system is worth flagging on
//     its own merits (an engineering-tool session touched this IED's configuration).
//   0x89 ndsCom (BOOLEAN, OPTIONAL) -- "needs commissioning": true means this GOOSE Control Block
//     is not yet fully configured/tested; real production traffic should essentially never show it.
//   0x8A numDatSetEntries (INTEGER) -- how many Data values allData below is expected to carry
//     (cross-checked against how many were actually decoded -- see decode_goose_pdu in goose.cpp).
//   0xAB allData (SEQUENCE OF Data, constructed) -- the actual dataset values; see below.
//
// UtcTime (the `t` field's encoding, and Data's own `utc-time` choice, tag 0x91 -- both decoded
// identically): a fixed 8 bytes -- Seconds-since-1970-01-01T00:00:00Z (4, big-endian) + Fraction-
// of-second (3, big-endian, scaled the same way packet-goose.c's `dissect_goose_UtcTime` does:
// treated as a 24-bit fixed-point fraction of one second) + TimeQuality (1 byte -- cross-checked
// against Beckhoff's TwinCAT IEC 61850 documentation, which documents this byte's bit layout in
// more detail than Wireshark's dissector does, since packet-goose.c doesn't render it at all): bit
// 0x80 LeapSecondsKnown, bit 0x40 ClockFailure, bit 0x20 ClockNotSynchronized, bits 0x1F
// TimeAccuracy (a 5-bit count of how many bits of the fractional-second field are actually accurate,
// 0-24 meaningful, higher values reserved/unspecified) -- this decoder renders all three flags plus
// the raw accuracy value. This does NOT render the seconds-since-epoch value as a calendar date --
// not because this codebase avoids calendar-date rendering in general (MMS UtcTime, MQTT Sparkplug
// timestamps, OPC UA DateTime, S7comm-Plus timestamps, and DNP3's Group 50/event-"with time"
// absolute time are all rendered as calendar dates via std::gmtime; see each protocol's own file),
// but because IEC 61850's UtcTime is sub-second-precision and used for tight event-sequencing/
// correlation (GOOSE/SV retransmit on every state change, often many times a second), where the raw
// seconds+fractional-nanosecond value has analytical value a calendar-string rendering would
// obscure, not clarify.
//
// allData's values (the ASN.1 `Data` CHOICE, IEC 61850-7-2's basic type list -- tag table
// cross-checked against packet-goose.c's `Data_choice`, and independently against a real device's
// capture bytes, both boolean and bit-string; see this file's Validation section):
//   0xA1 array (SEQUENCE OF Data, constructed) / 0xA2 structure (SEQUENCE OF Data, constructed) --
//     both are nested collections of more Data values (an array's elements share one type, a
//     structure's don't, but the wire encoding is identical) -- decoded recursively, since every
//     element is itself just as self-describing a BER TLV as a top-level one (unlike EtherNet/IP's
//     CIP structured/UDT types, which need an external type description this tool doesn't have --
//     see enip.hpp's LIMITATIONS note; GOOSE's nesting needs no such thing). Recursion is capped
//     (kMaxGooseDataDepth in goose.cpp) against a malformed/adversarial capture nesting arbitrarily
//     deep, and the total flattened value count is capped too (kMaxGooseDataValues) -- the same
//     safety-cap posture as every other repeated/nested structure this codebase decodes (DCP blocks,
//     CIP CPF items, DNP3 points).
//   0x83 boolean -- one byte, 0x00 = false, any other value = true (BER DER strictly requires 0xFF
//     for true; this decoder, like Wireshark's `dissect_ber_boolean`, accepts any nonzero byte,
//     since real devices don't always encode canonically).
//   0x84 bit-string -- BER BIT STRING: first content byte = count of unused bits (0-7) in the last
//     content byte, remaining bytes = the bit data itself, MSB-first. Rendered as both the bit count
//     and a binary-digit string, since a GOOSE dataset's BIT STRING values are almost always a short
//     (2-13 bit), individually-meaningful IEC 61850-7-3 status field (a "quality" attribute is a
//     13-bit BITSTRING; a double-point "dbpos" status is 2 bits) -- real-capture-confirmed for both
//     lengths, see this file's Validation section.
//   0x85 integer / 0x86 unsigned / 0x8D bcd -- all three are decoded identically (packet-goose.c's
//     `Data_choice` table dispatches all three to the same `dissect_ber_integer`-based function --
//     "bcd" is NOT digit-by-digit BCD on the wire, despite the name, matching Wireshark's behavior
//     exactly): an arbitrary-length big-endian two's-complement BER INTEGER, decoded up to 8 bytes
//     into an int64_t (sign-extended from the first content byte's high bit); longer than 8 bytes is
//     shown as raw hex with a note instead of silently truncating (never observed in a real capture
//     -- these are always small counters/enumerations in practice).
//   0x87 floating-point -- IEC 61850-7-2's FloatingPoint type: an OCTET STRING whose first byte is
//     the IEEE 754 exponent width in bits, followed by the value itself, big-endian -- this decoder
//     renders the two combinations IEC 61850 devices actually use: exponent-width byte 8 + 4 more
//     bytes = IEEE 754 binary32 (single precision, matching packet-goose.c's
//     `dissect_goose_FloatingPoint`, Wireshark's only implemented case), and exponent-width byte 11 +
//     8 more bytes = binary64 (double precision, by the identical rule extended to IEC 61850-7-2's
//     other defined width -- NOT confirmed against Wireshark's dissector or a real capture, since no
//     real capture checked used floating-point at all; see this file's Validation section). Any other
//     length/exponent-width combination is shown as raw hex with a note rather than guessed at.
//   0x89 octet-string -- shown as raw hex (no generic self-describing sub-structure, same reasoning
//     as PROFINET RT's cyclic IO data / EtherNet/IP's CIP I/O Connected Data Item).
//   0x8A visible-string / 0x90 mMSString -- rendered as text (byte-for-byte, no charset validation,
//     matching how gocbRef/datSet/goID/NameOfStation-style fields are already rendered elsewhere in
//     this codebase).
//   0x91 utc-time -- see the UtcTime paragraph above.
//   0x88 real (legacy ASN.1 REAL, ISO/IEC 8825 encoding -- effectively never used by a real GOOSE
//     publisher; IEC 61850-7-2 deprecates it in favor of floating-point above) / 0x8C binary-time
//     (TimeOfDay -- no source found to cross-check the exact 4-vs-6-byte encoding rule with the same
//     confidence as every other field here) / 0x8F objId (ASN.1 OBJECT IDENTIFIER, a base-128 varint
//     encoding -- essentially an MMS-ism, not something a GOOSE dataset actually carries in
//     practice): named (type_name set) but shown as raw hex, never value-decoded -- out of this
//     groundwork release's scope, the same "recognized but not guessed at" treatment as PROFINET
//     RT's Alarm frames.
//   Any other tag: shown as raw hex, type_name left empty (unrecognized entirely) -- same "decode
//     confidently only where the wire format is unambiguous" posture as every other protocol in this
//     codebase.
//
// Validation: cross-checked against Wireshark's `packet-goose.c` (generated from IEC 61850-8-1's
// ASN.1 module) throughout, AND against two independent real captures from the same public
// collection PROFINET RT's real fixtures came from (see tests/real_captures/goose/ATTRIBUTION.md)
// -- a hand-verified byte-by-byte BER walk confirmed the 0x80-0x8A/0xAB top-level tag table, the
// allData boolean(0x83)/bit-string(0x84) tags (both lengths described above), multi-byte BER
// INTEGER encoding (a 5-byte timeAllowedtoLive that a naive single/double/four-byte-only reader
// would have mishandled), a VLAN-priority-tagged real frame, and the TimeQuality byte's bit layout
// (a real device's ClockNotSynchronized bit set with a 7-bit accuracy value -- exactly the shape a
// live-but-not-yet-time-synced IED would produce). No real capture exercised: GSE Management PDUs
// (0xA0), array/structure nesting, integer/unsigned/floating-point/octet-string/visible-string/
// real/binary-time/objId/mMSString Data values, a missing optional field (goID/simulation/ndsCom --
// every real frame checked carried all three), a header S-bit/PDU-simulation mismatch, or more than
// one APDU packed into a frame's declared Length -- all of those paths are synthetic-fixture-
// validated only (tools/make_sample_pcap.py's build_goose_sample). See docs/MANUAL.md's LIMITATIONS
// for the complete, current list.
//
// Explicitly out of scope: R-GOOSE (routable GOOSE, IEC 61850-90-5) rides over UDP/IP inside a
// completely different session-layer wrapper (ISO 8602/X.234 connectionless transport, its own SPDU
// framing -- see packet-goose.c's separate `dissect_rgoose`), not this raw-Ethernet EtherType at
// all, so it would never even reach try_parse_goose -- a genuinely different, unimplemented
// protocol, not a gap in this decoder. IEC 61850-9-2 Sampled Values (EtherType 0x88BA, a sibling
// raw-Ethernet OT EtherType -- see link_layer.hpp) is unrelated and also not decoded by this
// release.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// One flattened entry from a decoded allData dataset -- see this file's header comment's allData
// paragraph. `path` is a dotted index path locating this value within allData (e.g. "3" for the
// 4th top-level entry, "6.0"/"6.1" for the two children of a structure/array at top-level index 6)
// -- container entries (array/structure) appear in this list too, immediately before their
// children, with `type_name` set but `value` empty (their "value" is the children that follow).
struct GooseDataValue {
    std::string path;
    std::string type_name;  // e.g. "boolean", "bit-string", "structure" -- empty when unrecognized
                              // (value is then raw hex)
    std::string value;       // rendered value, or raw hex when type_name doesn't describe one
};

struct GooseFrame {
    uint16_t appid = 0;
    uint16_t declared_length = 0;  // the header's own Length field (header + APDU, see above)
    bool header_simulated = false;  // Reserved1's S-bit (0x8000) -- see header comment

    bool is_gse_management = false;  // outer APDU tag 0xA0 -- named only, nothing below is set
    bool has_pdu = false;            // outer APDU tag 0x61 -- IECGoosePdu decoded, fields below set

    // --- IECGoosePdu fields (only when has_pdu) ---
    std::string gocb_ref;
    uint64_t time_allowed_to_live = 0;  // milliseconds
    std::string dat_set;
    std::optional<std::string> go_id;

    bool has_timestamp = false;
    uint32_t t_seconds = 0;
    uint32_t t_fraction_ns = 0;
    bool t_leap_seconds_known = false;
    bool t_clock_failure = false;
    bool t_clock_not_synchronized = false;
    uint8_t t_time_accuracy = 0;  // 5-bit field, 0-24 meaningful (see header comment)

    uint64_t st_num = 0;
    uint64_t sq_num = 0;
    std::optional<bool> simulation;
    uint64_t conf_rev = 0;
    std::optional<bool> nds_com;
    uint64_t num_dat_set_entries = 0;

    std::vector<GooseDataValue> all_data;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes after EtherType 0x88B8, or after a single 802.1Q
// VLAN tag already unwrapped by parse_ethernet; see link_layer.hpp) as one GOOSE frame. Returns
// std::nullopt (never throws) when there aren't at least 8 (header) + 2 (minimal tag+length) bytes,
// or when the byte after the header isn't 0x61 goosePdu or 0xA0 gseMngtPdu -- see this file's header
// comment for why that's a narrow, high-specificity gate rather than a generic heuristic.
std::optional<GooseFrame> try_parse_goose(ByteSpan eth_payload);

// registration-model pilot (Stage 3 -- see protocol_decoder.hpp/protocol_registry.hpp): thin
// ProtocolDecoder wrapper around try_parse_goose above, unchanged. GOOSE is the pilot's
// EtherType-gated case (no port/IP-protocol-number concept applies) and, like EIGRP, has no
// cross-packet state, so like EigrpDecoder it needs nothing beyond
// id()/gate_kind()/ethertype()/decode(); see goose.cpp.
class GooseDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "goose"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_IEC61850_GOOSE; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& goose_decoder();

}  // namespace conduitscope
