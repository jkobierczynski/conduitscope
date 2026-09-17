// SPDX-License-Identifier: Apache-2.0
// ffhse.hpp - FOUNDATION Fieldbus HSE (High Speed Ethernet) decoding: the fixed 12-byte common
// header shared by all four FF-HSE sub-protocols (FDA, SM, FMS, LAN Redundancy), the optional
// trailer fields it signals, and the request/response/error message bodies each sub-protocol
// carries.
//
// Sourcing: FF-HSE's own official specifications (FF-581/586/588/589/593/803/941, published by
// FieldComm Group) are all paywalled -- no free copy of any of them was available while building
// this decoder. Instead, every byte offset in this file is cross-checked against Wireshark's
// mainline dissector, epan/dissectors/packet-ff.c (15,317 lines) plus packet-ff.h (720 lines),
// protocol short name "FF", first written in 2008 by Yukiyo Akisada (a Yokogawa engineer) directly
// against the official FF-588-1.3 spec ("HSE Field Device Access Agent") with inline spec-clause
// citations throughout its own source comments -- GPL-2.0-or-later, vendor-authored, and spec-
// cited. That gives this file meaningfully HIGHER sourcing confidence than some of this project's
// other decoders (e.g. S7comm-Plus, which relies on a third-party reverse-engineered plugin), but
// it is still secondary (dissector-derived, not primary-spec-derived) -- treat every field name and
// byte offset below as "what Wireshark's own vendor-authored dissector does", not as independently
// verified against FieldComm Group's own text.
//
// A raw copy of packet-ff.c/packet-ff.h (fetched from the Wireshark project's own GitHub mirror
// while building this decoder) was actually available for direct inspection here -- NOT just a
// secondhand transcription of it. That let several details below be pulled EXACTLY from the real
// source rather than approximated per this file's original scope document:
//   - The full ErrorClass name table (11 entries) AND the full, exhaustive per-ErrorClass
//     ErrorCode name tables (val_to_str_err_code and its 11 backing value_string arrays) --
//     every (ErrorClass, ErrorCode) pair Wireshark's own dissector names is named identically
//     here, not just a small confident subset. See "Error body" below.
//   - Every FDA/SM/FMS/LAN Redundancy service name (names_fda_confirmed, names_sm_confirmed/
//     names_sm_unconfirmed, names_fms_confirmed/names_fms_unconfirmed, names_lan_confirmed/
//     names_lan_unconfirmed) and every service-id numeric constant, confirming the values given
//     in this decoder's own design document byte-for-byte.
//   - SM Find Tag Query's QueryType name table (7 entries), NmaConfigurationUse's 2 names,
//     ConnectOption's 3 names (VCR Selector/NMA Access/FBAP Access), the Duplicate Detection
//     State bit layout (bit0=Duplicate Device Index, bit1=Duplicate PD Tag, bits2-7=Reserved --
//     used identically by SM Identify Rsp, SM Device Annunciation, and LAN Diagnostic Message),
//     the DevType bitmask's exact bit positions, and LAN Redundancy's MaxMsgNumDiff 0/1 special
//     case ("Do not detect a fault (N)").
// Every other byte offset/field-width/field-order below still comes from this decoder's original
// design document (itself derived from the same dissector, just not re-verified byte-by-byte a
// second time against the raw source during implementation) -- there is no reason to believe it
// is any less accurate, but it wasn't independently re-confirmed the way the items above were.
//
// ---------------------------------------------------------------------------------------------
// Ports: 1089 (ff-annunc), 1090 (ff-fms -- Wireshark's own default bind), 1091 (ff-sm), 3622
// (ff-lr-port, LAN Redundancy) -- all TCP AND UDP. Unlike a port number picking a sub-protocol,
// FF-HSE signals which of FDA/SM/FMS/LAN Redundancy a given message belongs to IN-BAND, via the
// header's own ProtocolAndType byte (see below) -- so, matching this codebase's existing HART-IP/
// BACnet posture, every one of these four ports is recorded as an "expected port" annotation only,
// NEVER a detection gate. A message can arrive on any of the four (or a fifth, unexpected) port and
// still decode identically.
//
// ---------------------------------------------------------------------------------------------
// Common header (12 bytes, fixed, FDA_MSG_HDR_LENGTH in the reference source, immediately at the
// start of every FF-HSE message on either transport), all big-endian:
//   Version(1)          @0 -- not validated by this decoder (nor by Wireshark's own dissector) --
//                              surfaced as-is.
//   Options(1)           @1 -- a bitmask (see below).
//   ProtocolAndType(1)   @2 -- PROTOCOL_MASK=0xfc selects which of FDA(0x04)/SM(0x08)/FMS(0x0c)/
//                              LAN Redundancy(0x10) this message belongs to (these 4 values are
//                              already pre-shifted -- `byte & 0xfc` yields one of them directly);
//                              TYPE_MASK=0x03 selects Request(0x00)/Response(0x01)/Error(0x02).
//   Service(1)           @3 -- bit7 (0x80) is a Confirmed-service flag, bits0-6 (0x7f) are the
//                              Service Id. This decoder's internal message dispatch key is
//                              conceptually (Protocol, Type, ConfirmedFlag, ServiceId) -- the
//                              confirmed flag genuinely disambiguates real collisions (e.g. FMS
//                              Service Id 1 is "FMS Identify" when confirmed, but "FMS Unsolicited
//                              Status" when unconfirmed -- same Protocol, same Type, same numeric
//                              Service Id, different message entirely).
//   FDA Address(4)       @4 -- a composite address; this decoder only interprets its own upper 16
//                              bits, as "LinkId", and only for the one message shape whose own
//                              body layout depends on it (SM Identify Rsp / SM Device
//                              Annunciation's trailing version-number list -- see the LinkId
//                              branch below, flagged prominently since it is the single trickiest
//                              piece of this whole decoder). The rest of this field is surfaced
//                              raw (as hex) and not otherwise decoded.
//   Message Length(4)    @8 -- this message's OWN total length, INCLUDING this 12-byte header and
//                              any trailer (see below) -- i.e. NOT just the body. Used both as
//                              this decoder's own structural-detection plausibility check and, for
//                              TCP, as the declared length driving this codebase's usual PDU-level
//                              stream reassembly (see ffhse_declared_length, mirroring
//                              enip_declared_length/hartip_declared_length).
//
// Structural detection gate: accept a buffer as FF-HSE when (a) there are at least 12 bytes, (b)
// (ProtocolAndType & 0xfc) is one of the 4 valid protocol values {0x04, 0x08, 0x0c, 0x10}, (c)
// (ProtocolAndType & 0x03) is one of the 3 valid type values {0, 1, 2}, and (d) Message Length is
// at least 12 (it must at least cover its own header). (a)-(c) mirror exactly what a byte-for-byte
// reading of the reference dissector's own dispatch (dissect_ff's own switch on
// proto_and_type & PROTOCOL_MASK, then & TYPE_MASK) requires to identify the protocol at all; (d)
// is this decoder's own extra, modest plausibility check, in the same "cheap extra insurance"
// spirit as HART-IP's own MsgLength >= 8 check (see hartip.hpp) -- beyond what the reference
// dissector itself requires for identification. HONESTLY, this single-byte-at-offset-2 gate (12
// valid values out of 256 possible) is a WEAKER structural anchor than HART-IP's own two-byte gate
// (see hartip.hpp's own comparison), which is itself already this codebase's weakest -- see
// decoder.cpp's own dispatch-order comment for where in this codebase's opportunistic Auto-mode
// chain FF-HSE is deliberately placed as a result (last, after even HART-IP and MQTT), and for
// what that means for FF-HSE-over-TCP's own collision exposure with every earlier-tried protocol's
// gate.
//
// Options byte bitmasks: 0x80=Message-Number-present (4-byte trailer field), 0x40=Invoke-Id-
// present (4-byte trailer field), 0x20=Time-Stamp-present (8-byte trailer field), 0x10=reserved
// (not surfaced), 0x08=Extended-Control-Field-present (4-byte trailer field), 0x07 (low 3 bits) =
// Pad Length (0x00=none, 0x03=pad to a 4-byte boundary, 0x07=pad to an 8-byte boundary). The Pad
// Length sub-field is surfaced (as a raw value) but NOT acted on anywhere in this decoder's own
// length arithmetic -- confirmed directly from the reference source, whose own dissect_ff() never
// consults it either (it is read into a hf_register_info field purely for display, never used to
// adjust an offset) -- so this decoder treats it the same way: decorative/unused, not a real
// framing element, matching (not guessing beyond) the reference implementation's own behavior.
//
// Trailer: present in this fixed, contiguous order at the END of the PDU, but ONLY the fields
// whose own Options bit is set are actually on the wire (skipping any not-present field entirely,
// not leaving a gap for it): Message Number(4B BE, iff Options&0x80), Invoke Id(4B BE, iff
// Options&0x40), Time Stamp(8B BE, iff Options&0x20, raw units -- no epoch/scale confidently
// sourced, surfaced as a raw 64-bit value only), Extended Control Field(4B BE, iff Options&0x08).
//
// Length accounting (exact, reproducing the reference dissect_ff()'s own arithmetic): starting
// from `length` = the header's own Message Length field, each present trailer field's own byte
// count is subtracted from `length` (and separately accumulated into a `trailer_len` running
// total), and finally 12 (this header's own size) is subtracted -- what remains is the BODY
// length alone. The body occupies bytes [12, 12+body_length) of the PDU; the trailer (whichever
// fields are present) occupies the PDU's own trailing `trailer_len` bytes. This decoder guards
// this arithmetic defensively against underflow/malformed lengths (a Message Length too small to
// even cover its own header plus the trailer fields it claims to carry) -- clamped and noted,
// never allowed to throw or produce a negative/garbage body length, matching this codebase's usual
// truncation-handling posture elsewhere (see try_parse_ffhse's own explicit bounds checks below).
//
// ---------------------------------------------------------------------------------------------
// TCP framing: this message's own declared total length (the header's Message Length field, offset
// 8, big-endian) is this protocol's PDU-length-prefix for TCP stream reassembly purposes -- see
// ffhse_declared_length, which mirrors hartip_declared_length/enip_declared_length exactly, and
// decoder.cpp's own reassemble_tcp_payload, which drives generic cross-segment PDU reassembly from
// whichever protocol's *_declared_length function first recognizes the buffered bytes.
//
// UDP framing: UNLIKE every protocol above, a single UDP datagram can (and, per the reference
// source's own comments about coalesced diagnostic/status traffic, sometimes does in practice)
// carry MORE THAN ONE concatenated FF-HSE PDU back-to-back. try_parse_ffhse itself only ever
// parses ONE PDU and reports its own wire_length (mirroring HartIpFrame::wire_length/
// EnipFrame::wire_length's own role) -- walking multiple PDUs out of one UDP datagram is the
// CALLER's job, via the same wire_length-driven while-loop pattern this codebase already uses for
// EtherNet/IP's own coalesced CIP messages and HART-IP's own coalesced messages (see
// decoder.cpp's own dispatch, both its UDP and TCP branches, for exactly where this loop lives for
// FF-HSE). The loop stops (silently, not as an error) the moment a sub-PDU's own declared length is
// implausible (< 12, the header's own minimum) or doesn't fit in the bytes remaining in the
// datagram -- the remaining bytes are simply left undecoded, the same "stop, don't guess" posture
// this codebase's other coalescing loops already take.
//
// ---------------------------------------------------------------------------------------------
// Error body (Type=Error, 20 bytes fixed + any remainder, used by virtually every _err message
// across all four families -- this decoder decodes it via ONE shared function regardless of which
// sub-protocol/service produced it):
//   ErrorClass(1)             @0  -- 1=VFD State, 2=Application Reference, 3=Definition,
//                                     4=Resource, 5=Service, 6=Access, 7=OD, 8=Other, 9=Reject,
//                                     10=H1 SM Reason Code, 11=FMS Initiate. Confidently named --
//                                     this 11-entry table is pulled directly from the reference
//                                     source's own names_err_class array.
//   ErrorCode(1)              @1  -- meaning depends on ErrorClass; looked up via a nested,
//                                     per-class table pulled directly from the reference source's
//                                     own val_to_str_err_code()/names_err_code_* arrays (11 tables,
//                                     one per ErrorClass, together covering every (class, code)
//                                     pair the reference dissector itself names). An unmapped pair
//                                     renders "unknown(N)", never guessed at -- exactly the
//                                     reference dissector's own "Unknown" fallback.
//   AdditionalCode(2)         @2  BE -- surfaced as a raw number; no further meaning sourced.
//   AdditionalDescription(16) @4  -- ASCII; trailing NUL (0x00) bytes are trimmed when rendering,
//                                     but a description that isn't NUL-terminated at all (fills
//                                     the full 16 bytes) is rendered as-is, not treated as an error.
//   [remainder]                @20 -- any bytes beyond this fixed 20-byte shape are shown as raw
//                                     hex, not guessed at.
//
// ---------------------------------------------------------------------------------------------
// Tier-1 (full value decode) vs Tier-2 (named only, raw-hex body) split: the same split this
// codebase already draws for HART-IP's command dispatch, BACnet's service dispatch, MMS's/OPC UA's
// service dispatch, and S7comm-Plus's function dispatch -- decoded WHEN this decoder has a
// confidently-sourced byte layout for a message's body (the great majority of FDA/SM/LAN
// Redundancy messages, plus FMS's own session-lifecycle/status/identify/read/write family), named
// via a lookup table but shown ONLY as raw hex otherwise (FMS's Get OD, Define/Delete Variable
// List, the Download/Upload sequence families, RequestDomainDownload/Upload, the Program
// Invocation lifecycle, AlterEventConditionMonitoring, AcknowledgeEventNotification, the Put OD
// family, the Generic Download sequence family, and unconfirmed EventNotification). FMS Get OD is
// notable among these: even the reference dissector itself leaves OD (Object Dictionary) entries
// undecoded as raw bytes (their own shape depends on Device Description content this decoder has
// no access to) -- good precedent for this decoder's own choice not to guess there either. FMS
// Read/Read with Subindex responses are Tier-2 in a narrower sense: their HEADER is fully decoded
// (Index/Subindex), but their own returned VALUE is deliberately left as raw hex, since an FMS
// value has no self-describing wire type without external Object Dictionary context to interpret
// it against -- the exact same honesty precedent this codebase's EtherNet/IP CIP I/O decoder
// already sets for connected I/O data (see enip.hpp) and S7comm-Plus sets for several datatypes it
// declines to parse further.
//
// UNCONFIRMED WORKING HYPOTHESIS, flagged explicitly as an inference and NOT asserted as fact
// anywhere else in this file or its implementation: no distinct "cyclic Publisher/Subscriber"
// message shape was identified anywhere in the reference source consulted while building this
// decoder. This decoder's own best guess -- again, a guess, not a confirmed fact -- is that HSE's
// cyclic/multicast function-block data reuses the UNCONFIRMED FMS Information Report family (Service
// Ids 0/16/17/18) rather than having any wire shape of its own. A documentation writer covering
// this decoder should present this the same way: as this decoder's own inference, not as an
// established fact about the FF-HSE protocol.
//
// ---------------------------------------------------------------------------------------------
// The LinkId branch (SM Identify Rsp / SM Device Annunciation Req -- both share this exact 108-byte
// fixed shape plus a trailing variable-length version-number list): the single trickiest piece of
// this whole decoder. `LinkId` is computed as the top 16 bits of the 12-byte common HEADER's own
// FDA Address field (`(uint16_t)(header.fda_address >> 16)`), NOT anything inside this message's
// own body. Once NumOfEntriesInVerNumList (`N`, a uint32 at body offset 104) is known:
//   - LinkId != 0: the list is N*2 entries of a 2-byte (H1NodeAddress(1B), VersionNumber(1B)) pair.
//   - LinkId == 0: the list is N entries of a 4-byte (H1LinkId(2B BE), Reserved(1B),
//     VersionNumber(1B)) quad.
// EITHER WAY, the list consumes exactly 4*N total bytes starting at body offset 108 -- only the
// INTERNAL shape of those 4*N bytes (as N*2 2-byte pairs, or N 4-byte quads) depends on LinkId, not
// the total byte count, which is why both branches still land on the same "remainder starts at
// 108+4*N" offset. Getting this branch wrong (e.g. reading N as 4-byte quads when LinkId != 0)
// would silently misinterpret every entry after the first -- this decoder computes LinkId from the
// header exactly once, before entering either message's own body-decode function, and threads it
// through explicitly rather than re-deriving it separately in each.
//
// ---------------------------------------------------------------------------------------------
// Message-family/struct-organization note: unlike this codebase's smaller multi-message-family
// decoders (HART-IP's dozen-ish Pass-Through commands, BACnet's half-dozen first-pass services),
// FF-HSE has substantially more distinct message SHAPES (over 40, across 4 sub-protocols) than any
// existing decoder in this codebase. Rather than one bespoke C++ struct per message shape (which
// would make this header enormous without adding real value over the alternative), every Tier-1
// decoded message's fields are rendered into the SAME generic `values` vector<string> scheme this
// codebase already uses for HART-IP Pass-Through command data, BACnet's first-pass service data,
// and OPC UA's/MMS's Tier-1 service data (see FfhseFrame::values below) -- one "field-name=value"
// string per decoded field, in wire order. This is a deliberate scope/maintainability trade-off,
// not an oversight: the header/trailer DO get their own dedicated structs (FfhseHeader/
// FfhseTrailer below), since those are shared, structurally load-bearing shapes every message
// carries identically; individual message bodies do not, since C++ pattern-matching gains from 40+
// one-off structs would not offset the header-file bulk they'd add.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The 4 IANA-registered FF-HSE ports (all TCP AND UDP) -- recorded as "expected port" annotations
// only, never a detection gate. See ffhse.hpp's own file header comment.
constexpr uint16_t FFHSE_PORT_ANNUNC = 1089;  // ff-annunc
constexpr uint16_t FFHSE_PORT_FMS = 1090;     // ff-fms -- Wireshark's own default bind
constexpr uint16_t FFHSE_PORT_SM = 1091;      // ff-sm
constexpr uint16_t FFHSE_PORT_LAN = 3622;     // ff-lr-port (LAN Redundancy)

// The 12-byte common header -- see ffhse.hpp's file header comment.
struct FfhseHeader {
    uint8_t version = 0;
    uint8_t options = 0;
    bool opt_message_number = false;   // Options bit 0x80
    bool opt_invoke_id = false;        // Options bit 0x40
    bool opt_time_stamp = false;       // Options bit 0x20
    bool opt_extended_control_field = false;  // Options bit 0x08
    uint8_t pad_length = 0;  // Options low 3 bits -- decorative/unused, see file header comment

    uint8_t protocol_and_type = 0;
    uint8_t protocol = 0;  // protocol_and_type & 0xfc -- one of {0x04,0x08,0x0c,0x10}
    std::string protocol_name;  // "FDA Session Management"/"SM"/"FMS"/"LAN Redundancy"
    uint8_t type = 0;  // protocol_and_type & 0x03 -- 0=Request,1=Response,2=Error
    std::string type_name;

    uint8_t service = 0;
    bool confirmed = false;   // Service bit 0x80
    uint8_t service_id = 0;   // Service & 0x7f

    uint32_t fda_address = 0;
    uint16_t link_id = 0;  // fda_address >> 16 -- see the LinkId branch in ffhse.hpp's file header

    uint32_t message_length = 0;  // this PDU's own total declared length, header included
};

// The optional trailer -- see ffhse.hpp's file header comment. Only the fields whose own
// has_/opt_ flag is set are meaningful.
struct FfhseTrailer {
    bool has_message_number = false;
    uint32_t message_number = 0;
    bool has_invoke_id = false;
    uint32_t invoke_id = 0;
    bool has_time_stamp = false;
    uint64_t time_stamp = 0;  // raw 64-bit value -- no epoch/scale confidently sourced
    bool has_extended_control_field = false;
    uint32_t extended_control_field = 0;
};

// One decoded FF-HSE PDU -- see ffhse.hpp's file header comment, especially its
// "Message-family/struct-organization note" for why message bodies are rendered into `values`
// rather than one struct per shape.
struct FfhseFrame {
    FfhseHeader header;
    FfhseTrailer trailer;

    // Best-effort message name, e.g. "FDA Open Session Req", "SM Identify Rsp", "FMS Initiate Err",
    // "LAN Redundancy Get Statistics Rsp" -- always set (even for an unrecognized
    // Protocol/Type/ConfirmedFlag/ServiceId combination, where it names as much as is known, e.g.
    // "SM unconfirmed service 99 (unrecognized)").
    std::string message_name;

    bool recognized = false;      // true once this decoder recognizes the (protocol, type,
                                   // confirmed, service_id) combination at all (Tier 1 OR Tier 2)
    bool body_decoded = false;    // true only for a Tier-1 message whose body matched this
                                   // decoder's expected shape -- see the file header's Tier-1/
                                   // Tier-2 split
    std::vector<std::string> values;  // one "field=value" entry per decoded field, wire order --
                                        // populated only when body_decoded

    // Raw hex fallback -- populated for a Tier-2 message's WHOLE body, OR for the trailing
    // "remainder" bytes past a Tier-1 message's own fixed/variable decoded shape (both can be
    // true for the SAME frame in the remainder case: values holds the decoded fixed part, and
    // body_shown_as_hex/body_hex/body_length describe the undecoded trailing bytes).
    bool body_shown_as_hex = false;
    std::string body_hex;
    size_t body_length = 0;

    // This PDU's own full wire length (header + body + trailer, clamped to the bytes actually
    // available when Message Length overruns them) -- lets a caller find where the next
    // concatenated PDU, if any, starts in the same UDP datagram or TCP payload. Mirrors
    // HartIpFrame::wire_length/EnipFrame::wire_length's own role.
    size_t wire_length = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns this PDU's own declared total length (Message Length, header offset 8, big-endian) when
// the first 12 bytes structurally look like an FF-HSE header (see try_parse_ffhse's own
// "structural detection gate"), for TCP stream reassembly purposes -- mirrors
// hartip_declared_length/enip_declared_length. Returns std::nullopt when there aren't even 12
// bytes, or the ProtocolAndType byte's own two-field check fails.
std::optional<size_t> ffhse_declared_length(ByteSpan payload);

// Attempts to interpret `payload` (TCP or UDP application-layer bytes) as ONE FF-HSE PDU starting
// at its beginning. Returns std::nullopt (never throws) when there aren't even 12 bytes for the
// header, when (ProtocolAndType & 0xfc) isn't one of the 4 valid protocol values, when
// (ProtocolAndType & 0x03) isn't one of the 3 valid type values, or when Message Length is
// implausibly small (< 12) -- see ffhse.hpp's file header comment's "Structural detection gate"
// paragraph. A caller wanting every PDU concatenated into one UDP datagram (or coalesced into one
// TCP payload) walks FfhseFrame::wire_length in a loop, the same pattern decoder.cpp already uses
// for EtherNet/IP's/HART-IP's own coalesced messages -- see this file's own UDP framing paragraph.
std::optional<FfhseFrame> try_parse_ffhse(ByteSpan payload);

}  // namespace conduitscope
