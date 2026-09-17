// SPDX-License-Identifier: Apache-2.0
// sv.hpp - IEC 61850-9-2 Sampled Values (SV, EtherType 0x88BA) decoding: the 8-byte SV APDU
// header (identical in shape to GOOSE's, see goose.hpp), the ASN.1 BER-encoded SavPdu (noASDU +
// one or more ASDU elements), and each ASDU's own svID/datSet/smpCnt/confRev/refrTm/smpSynch/
// smpRate/seqData/smpMod/gmidData fields.
//
// Like GOOSE and PROFINET RT, SV rides directly on raw Ethernet -- there is no IPv4/UDP/TCP layer
// at all. In fact SV and GOOSE share their entire link-layer header format: IEC 61850-8-1 Annex A
// defines one common "Ethertype header" both message types use, so this file's header decode is
// deliberately identical to goose.hpp's (cross-checked against Wireshark's own `packet-sv.c`,
// generated from the IEC 61850-9-2 ASN.1 module by asn2wrs, whose `dissect_sv` reads these same
// four fields at the same offsets goose.hpp documents):
//   APPID(2) + Length(2) + Reserved1(2) + Reserved2(2), all big-endian.
// Length is the total byte count of this header PLUS the ASN.1 APDU that follows it (includes
// itself). Reserved1's top bit (0x8000, "S-bit") is the same header-level "Simulated" flag GOOSE
// defines (packet-sv.c's own `hf_sv_reserve1_s_bit`, also named "Simulated") -- unlike GOOSE,
// though, the SV ASDU below has no PDU-level `simulation` field of its own to cross-check the
// S-bit against (see the ASDU field table below), so this decoder surfaces the S-bit alone, with
// no consistency note to make. Reserved2 is not surfaced (no defined meaning, same as GOOSE).
//
// The APDU is ASN.1 BER, IMPLICIT-tagged throughout, cross-checked against packet-sv.c's
// `SavPdu_sequence`/`ASDU_sequence`/`SampledValues_choice` tables. Unlike GOOSE, which offers two
// outer-APDU choices (a real PDU vs. a GSE Management PDU), SV's outer `SampledValues` type is a
// BER CHOICE with exactly one alternative:
//   0x60 (APPLICATION class, constructed, tag 0): `savPdu` -- the only shape SV traffic takes.
// Any other byte at that position is not recognized as SV at all -- try_parse_sv returns
// std::nullopt and the caller falls back to the generic "non-ip" ethertype-name-only report, the
// same narrow, high-specificity single-byte gate GOOSE's outer-tag check and PROFINET RT's FrameID
// range check both use, for the same reason: a non-SV frame that happens to carry EtherType 0x88BA
// (there is no requirement that it does) should fall back to being named, not guessed at.
//
// SavPdu itself (`SavPdu_sequence`, IMPLICIT-tagged context-class fields -- note context tag 1 is
// unused/reserved, unlike GOOSE's tag numbering which has no such gap):
//   0x80 noASDU (INTEGER, 0-65535) -- the declared count of ASDU elements that follow. Cross-
//     checked against how many this decoder actually finds (see decode_sav_pdu in sv.cpp).
//   0xA2 seqASDU (SEQUENCE OF ASDU, constructed, context tag 2) -- one or more ASDU elements, each
//     itself wrapped in a standard ASN.1 UNIVERSAL SEQUENCE tag (0x30 -- `BER_UNI_TAG_SEQUENCE`,
//     `BER_FLAGS_NOOWNTAG` in packet-sv.c's `SEQUENCE_OF_ASDU_sequence_of`, meaning each element
//     keeps its own natural SEQUENCE tag rather than being IMPLICIT-retagged the way SavPdu's own
//     fields are). This is a genuine structural difference from GOOSE's allData, which nests Data
//     TLVs directly with no per-item wrapper tag -- see decode_sav_pdu's comment in sv.cpp.
//
// Each ASDU's fields (`ASDU_sequence`, IMPLICIT-tagged context-class, all primitive -- an ASDU
// carries no constructed sub-fields of its own, unlike GOOSE's PDU which has allData):
//   0x80 svID (VisibleString) -- the Sampled Value Control Block-derived stream identifier, e.g.
//     "IED1/LLN0$MSVCB01" or a plain application-defined string -- the SV analog of GOOSE's
//     gocbRef, identifying which merging unit/stream this ASDU belongs to.
//   0x81 datSet (VisibleString, OPTIONAL) -- the Data Set object reference the sample values in
//     seqData below correspond to, when the publisher chooses to include it.
//   0x82 smpCnt (INTEGER, 0-65535) -- the sample counter: increments once per sample within the
//     current nominal period (typically wrapping at smpRate-1, e.g. 0-3999 for an 80-sample-per-
//     cycle/50Hz stream), then resets to 0 at the start of the next period. This is SV's primary
//     stream-integrity signal, the closest analog to GOOSE's stNum/sqNum pair: a gap or an
//     out-of-sequence value here means a dropped or reordered sample, which matters for protection
//     relay logic downstream that assumes a continuous, in-order sample stream.
//   0x83 confRev (INTEGER, 0-4294967295) -- the Sampled Value Control Block's configuration
//     revision, same meaning and same OT-security relevance as GOOSE's confRev: changes only when
//     an engineering tool reconfigures the stream, not on every sample.
//   0x84 refrTm (UtcTime, exactly 8 bytes, OPTIONAL) -- decoded identically to GOOSE's `t`/
//     `utc-time` fields (see goose.hpp's UtcTime paragraph for the Seconds+Fraction+TimeQuality
//     encoding and its provenance) -- when present, the reference time this ASDU's samples were
//     taken relative to.
//   0x85 smpSynch (INTEGER, OPTIONAL) -- the sample-clock synchronization state: 0 = none (not
//     synchronized), 1 = local (synchronized to a local clock, not a global time reference), 2 =
//     global (synchronized to a global time signal, e.g. PTP/IRIG-B) -- cross-checked against
//     packet-sv.c's `sv_T_smpSynch_vals`. A merging unit reporting anything other than 2 in a
//     system that expects tight time alignment across multiple streams (the entire point of
//     time-synchronized sampling for phasor/differential protection calculations) is a real
//     operational concern, not just a decoding curiosity.
//   0x86 smpRate (INTEGER, 0-65535, OPTIONAL) -- the nominal number of samples per data set period
//     (commonly per power-system cycle) -- when present, tells a consumer how to interpret smpCnt's
//     wraparound point.
//   0x87 seqData (OCTET STRING) -- the actual sample data. NOT value-decoded by this release --
//     see the "seqData" paragraph below for why, and the same reasoning already applied twice in
//     this codebase (PROFINET RT's cyclic IO data, EtherNet/IP's CIP I/O Connected Data Item).
//   0x88 smpMod (INTEGER, OPTIONAL) -- how smpRate above should be interpreted: 0 =
//     samplesPerNormalPeriod, 1 = samplesPerSecond, 2 = secondsPerSample -- cross-checked against
//     packet-sv.c's `sv_T_smpMod_vals`. Absent, per the standard, is equivalent to 0.
//   0x89 gmidData (OCTET STRING, exactly 8 bytes, OPTIONAL) -- an IEC 61850-9-2 Ed.2.1 (2020)
//     amendment field: the EUI-64 identity (vendor OUI + 0xFFFE + card/device ID, the same format
//     PTP grandmaster clock identities use -- cross-checked against packet-sv.c's
//     `dissect_sv_GmidData`, which explicitly checks for the 0xFFFE marker at the expected offset)
//     of the PTP grandmaster clock this stream's time base is derived from. Shown as raw hex; this
//     decoder does not attempt the vendor-OUI-to-manufacturer-name lookup Wireshark's own
//     `tvb_get_manuf_name` does, since that requires bundling or fetching an IEEE OUI database,
//     out of scope for this groundwork release (see docs/MANUAL.md's LIMITATIONS).
//
// seqData: unlike GOOSE's allData, IEC 61850-9-2's base ASN.1 module defines `Data ::= OCTET
// STRING` with no further self-describing structure at all -- there is no generic, standard way to
// know how many channels this OCTET STRING packs or in what order without external configuration
// (a Sampled Value Control Block's data set definition, which this decoder has no access to from
// the wire alone). In practice the great majority of real-world merging units follow the "9-2LE"
// (UCA International Users Group's IEC 61850-9-2 Light Edition implementation guideline) profile:
// exactly 8 channels (IL1/IL2/IL3/IN current, UL1/UL2/UL3/UN voltage, in that order), each a 4-byte
// big-endian signed INT32 instantaneous value immediately followed by a 4-byte big-endian Quality
// bitmask (IEC 61850-8-1 clause 8.2's Quality encoding -- validity/overflow/out-of-range/bad-
// reference/oscillatory/failure/old-data/inconsistent/inaccurate/source/test/operator-blocked bits,
// plus a UCA-guideline-only "derived" bit; packet-sv.c decodes exactly this shape as `PhsMeas1`,
// but only when its own `decode_data_as_phsmeas` preference is explicitly turned on -- it is NOT
// the dissector's default behavior, precisely because 9-2LE is an implementation profile layered on
// top of the base standard, not something the base ASN.1 itself asserts). This decoder follows
// Wireshark's own default and this codebase's established "no generic self-describing type" posture
// exactly: seqData is shown only as raw hex plus its byte length, never value-decoded, the same
// treatment as PROFINET RT's cyclic IO data and EtherNet/IP's CIP I/O Connected Data Item (see
// profinet.hpp and enip.hpp) -- decoding it as 9-2LE PhsMeas pairs by default would mean silently
// assuming an implementation profile this decoder cannot confirm from the wire, which conflicts
// with this codebase's "decode confidently only where the wire format is unambiguous" philosophy.
// See docs/MANUAL.md's ROADMAP for revisiting this if real-world evidence (or an opt-in flag, as
// Wireshark itself uses) ever makes an automatic 9-2LE interpretation defensible.
//
// This release decodes every ASDU declared inside one SavPdu's seqASDU (unlike GOOSE, which
// decodes only the first APDU per frame and notes any leftover bytes) -- IEC 61850-9-2 explicitly
// allows a merging unit to publish more than one ASDU per frame (e.g. one Sampled Value Control
// Block instance combining several logical streams), and packet-sv.c's own `SEQUENCE_OF_ASDU`
// handling decodes all of them unconditionally, with no equivalent of GOOSE's undecoded-multi-APDU
// path. Both the header's Length field and the outer APDU/ASDU TLVs' own declared lengths, when
// they exceed the bytes actually available (a plausibly snaplen-truncated capture), are handled
// tolerantly -- clamped to what's present, with a note -- matching GOOSE's and PROFINET RT's own
// truncation handling exactly (see goose.hpp's file header comment and try_parse_sv's own comment).
//
// Validation: cross-checked against Wireshark's `packet-sv.c` (generated from IEC 61850-9-2's own
// ASN.1 module) throughout. No real SV capture was found despite a genuine search across several
// public ICS pcap collections (the same ones that supplied this codebase's GOOSE/PROFINET RT real
// fixtures -- ITI/ICS-Security-Tools, automayt/ICS-pcap, mrhenrike/PCAPTrafficAnalysis), Wireshark's
// own test-capture tree and SampleCaptures wiki, and several IEC 61850 tooling repositories -- SV's
// naturally high data rate (a merging unit commonly publishes 80-256 samples per power-system
// cycle, i.e. thousands of frames per second) appears to make it far less commonly captured and
// shared in public collections than GOOSE's comparatively low, event-driven rate. This decoder is
// therefore validated only by construction (tests/sample_sv.pcap, see tools/make_sample_pcap.py's
// build_sv_sample) against the wire format as cross-checked against Wireshark's dissector source,
// the same honest gap this codebase already documents for EtherNet/IP's CIP I/O implicit messaging
// (see enip.hpp) and PROFINET RT's cyclic IO data (see profinet.hpp) -- see docs/MANUAL.md's
// LIMITATIONS for the complete, current list.
//
// Explicitly out of scope: R-SV (routable Sampled Values, IEC 61850-90-5) rides over UDP/IP inside
// a completely different session-layer wrapper, the same way R-GOOSE does (see goose.hpp) -- not
// this raw-Ethernet EtherType at all, so it would never reach try_parse_sv. IEC 61850-8-1 GOOSE
// (EtherType 0x88B8, see goose.hpp) and MMS (a TCP-based IEC 61850-8-1 mapping) are unrelated and
// not decoded by this file.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// One decoded ASDU element from a SavPdu's seqASDU -- see sv.hpp's file header comment's ASDU
// field table.
struct SvAsdu {
    std::string sv_id;
    std::optional<std::string> dat_set;
    uint64_t smp_cnt = 0;
    uint64_t conf_rev = 0;

    bool has_refr_tm = false;
    uint32_t refr_tm_seconds = 0;
    uint32_t refr_tm_fraction_ns = 0;
    bool refr_tm_leap_seconds_known = false;
    bool refr_tm_clock_failure = false;
    bool refr_tm_clock_not_synchronized = false;
    uint8_t refr_tm_time_accuracy = 0;

    std::optional<std::string> smp_synch;  // "none"/"local"/"global"/"unknown(N)" -- rendered
                                             // name for the wire value, see header comment
    std::optional<uint64_t> smp_rate;

    std::string seq_data_hex;  // raw hex -- never value-decoded, see header comment's seqData
                                 // paragraph
    size_t seq_data_length = 0;

    std::optional<std::string> smp_mod;  // "samplesPerNormalPeriod"/"samplesPerSecond"/
                                           // "secondsPerSample"/"unknown(N)" -- see header comment
    std::optional<std::string> gmid_hex;  // 8-byte EUI-64 grandmaster identity, raw hex
};

struct SvFrame {
    uint16_t appid = 0;
    uint16_t declared_length = 0;  // the header's own Length field (header + APDU)
    bool header_simulated = false;  // Reserved1's S-bit (0x8000) -- see header comment

    uint64_t no_asdu = 0;       // SavPdu's declared noASDU count
    std::vector<SvAsdu> asdus;  // every ASDU actually decoded from seqASDU

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x88BA -- or after a
// single 802.1Q VLAN tag, already unwrapped by parse_ethernet; see link_layer.hpp) as one SV frame.
// Returns std::nullopt (never throws) when there aren't at least 8 (header) + 2 (a minimal
// tag+length) bytes, or when the byte immediately after the header isn't the one outer APDU tag
// this decoder recognizes (0x60 savPdu -- see this file's header comment for why this is a narrow,
// high-specificity gate, not a generic length-looks-plausible heuristic).
std::optional<SvFrame> try_parse_sv(ByteSpan eth_payload);

}  // namespace conduitscope
