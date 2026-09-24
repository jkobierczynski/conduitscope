// SPDX-License-Identifier: Apache-2.0
// dicom.hpp - DICOM (Digital Imaging and Communications in Medicine, NEMA/ACR PS3.x) Upper Layer
// protocol (PS3.8) plus a curated slice of the DIMSE command/data-set model (PS3.7) it carries --
// TCP ports 104 (IANA-registered "dicom", rare in practice because it needs a privileged bind) and
// 11112 (the de facto real-world default every modern PACS/dcm4che/Orthanc/most vendor imaging
// software actually binds -- weighted here as the COMMON case, not a fallback).
//
// WHAT IT IS AND WHY IT'S IN AN OT/ICS TOOL: NIS2 (the EU's Network and Information Security
// Directive, transposed into national law across member states through 2024-2025) names healthcare
// as a regulated "essential entity" sector alongside energy/water/transport -- the same critical-
// infrastructure posture this codebase already builds toward for classic OT (PLCs/RTUs/SCADA). A
// hospital's imaging network (PACS archives, CT/MR/US/CR modalities, reporting workstations,
// worklist servers) is exactly that kind of regulated network segment, and DICOM Upper Layer is its
// dominant wire protocol -- the direct medical-imaging analog of Modbus/DNP3/S7comm for a hospital
// rather than a factory floor. The target user of this decoder is a security engineer doing network
// visibility/inventory on that segment (which modalities and workstations are talking to which
// PACS, over which SOP classes, with or without any authentication) -- NOT a medical-imaging
// developer building a DICOM application; this file's own scope decisions below are made with that
// audience in mind (curated depth on security-relevant structure -- association setup, identity
// negotiation, DIMSE command flow, a handful of asset-inventory-relevant dataset tags -- rather than
// exhaustive coverage of DICOM's own enormous data dictionary or its image-format internals).
//
// SOURCING: every PDU-type value, fixed-field byte offset, item-type value, item-layout, Command
// Field/Status code, and curated tag/VR pairing below was cross-confirmed directly against the
// DICOM standard itself (PS3.7 Message Exchange, PS3.8 Network Communication Support, PS3.5 Data
// Structures and Encoding, PS3.15 Security and System Management Profiles) AND Wireshark's own
// packet-dcm.c/packet-dcm.h dissector source, by a dedicated research pass treated as authoritative
// for this whole feature -- see the task's own research notes for the full byte-exact citation
// trail this implementation follows verbatim. Two points worth flagging explicitly because they
// corrected an earlier, less careful assumption: the long-form Explicit VR set is OB/OD/OF/OL/OW/
// SQ/UC/UR/UT/UN (ten VRs, not the smaller set a hastier read of the standard might assume -- see
// WIRE FORMAT below), and UI (UID) values are NUL-padded to even length on the wire, not
// space-padded the way AE-titles are.
//
// SCOPE, DECIDED HERE (curated depth for a security-inventory tool, not a DICOM toolkit):
//   - Every PDU type (0x01-0x07) is at least structurally recognized. A-ASSOCIATE-RQ/AC get full
//     variable-item decode (Application Context, every Presentation Context with its Abstract/
//     Transfer Syntax sub-items, User Information including Maximum Length/Implementation Class
//     UID/Version Name/Async Ops Window/Role Selection/User Identity Negotiation). A-ASSOCIATE-RJ
//     and A-ABORT get their full fixed-field decode (this is where the AE-title-enumeration and
//     abort-source findings live). A-RELEASE-RQ/RP carry no content beyond the PDU type itself (4
//     reserved bytes) -- named, nothing further to decode.
//   - P-DATA-TF: every PDV is parsed structurally (length, presentation-context-ID, Command/Data
//     flag, last-fragment flag). The DIMSE Command Set (always Implicit VR Little Endian,
//     independent of the negotiated transfer syntax -- see STATEFULNESS below and PS3.7 section
//     6.3.1) is decoded for a curated set of Command-group (0000,xxxx) elements: Command Field,
//     Message ID (Being Responded To), Data Set Type, Status, Affected/Requested SOP Class/Instance
//     UID, and the four C-MOVE/C-GET sub-operation counters -- this covers every field an analyst
//     needs to read "who asked whom to do what, and how did it go" off the wire. The Data Set
//     (encoded per the negotiated transfer syntax for that presentation context) gets CURATED TAG
//     EXTRACTION ONLY, not a data-dictionary walk: a small, named list of patient-identity and
//     asset-inventory-relevant tags (see REDACTION below for the full list and which are redacted).
//     Every other data element is safely skipped past (its length is enough to do that in every
//     case this decoder handles -- see WIRE FORMAT below for the one honestly-declined exception:
//     an undefined-length element whose own internal shape this decoder can't safely bound). Pixel
//     Data (7FE0,0010) is always skipped as opaque bytes, by tag alone, regardless of VR or length
//     form -- image content is never decoded, an explicit and permanent scope boundary, not a gap.
//   - No ~4,000-entry DICOM data dictionary is implemented, and none is needed for the tags this
//     decoder cares about: for the curated list, this decoder already knows each tag's VR (fixed by
//     the standard for that tag, in EITHER Implicit or Explicit VR) without looking it up; for every
//     other tag, an Implicit VR element's own 4-byte length field is already enough to skip past it
//     correctly with no VR knowledge at all.
//   - SOP Class UID and Transfer Syntax UID both get a small curated name table (a dozen or so of
//     the SOP classes/transfer syntaxes an OT-adjacent imaging-network audit will actually see --
//     Verification/C-ECHO, the common Storage classes, Query/Retrieve, Modality Worklist; Implicit/
//     Explicit VR LE, Deflated Explicit VR LE, Explicit VR BE, plus a compressed-vs-not
//     classification for the whole `1.2.840.10008.1.2.4.*`/`1.2.840.10008.1.2.5` family) -- an
//     unrecognized UID renders as "Unknown SOP Class (<uid>)"/"Unknown Transfer Syntax (<uid>)"
//     rather than a guess. A full enumeration of DICOM's hundreds of registered SOP classes and
//     dozens of transfer syntaxes is explicitly out of scope; the UID itself is always shown either
//     way, so nothing is lost, only unlabeled.
//
// WIRE FORMAT
//
// PDU common header, every PDU, 6 bytes, all multi-byte fields big-endian:
//   PDU-type(1)@0  reserved(1)@1 [==0x00 on the wire in every real implementation, but PS3.8
//     explicitly says NOT to validate this on receive -- this decoder never rejects a PDU solely
//     for a nonzero reserved byte here] PDU-length(4,BE)@2 [length of everything AFTER this 6-byte
//     header -- NOT including it, unlike e.g. AMQP 0-9-1's own frame-size field].
//
// PDU-type table (exactly 7 values, 0x01-0x07, contiguous -- anything outside this range is itself
// a decode-failure signal, the whole structural gate this decoder's port-gated Auto-mode detection
// leans on): 0x01 A-ASSOCIATE-RQ, 0x02 A-ASSOCIATE-AC, 0x03 A-ASSOCIATE-RJ, 0x04 P-DATA-TF,
// 0x05 A-RELEASE-RQ, 0x06 A-RELEASE-RP, 0x07 A-ABORT.
//
// A-ASSOCIATE-RQ (0x01) / A-ASSOCIATE-AC (0x02) -- byte-for-byte IDENTICAL fixed-field layout,
// differing only in their own downstream variable items (offsets from PDU start, i.e. offset 0 is
// the PDU-type byte):
//   Protocol-version(2,BE)@6 [bitmask; "Version 1" = bit0 set, wire value 0x0001] Reserved(2)@8
//   [not validated] Called-AE-title(16, ASCII, space-padded)@10 Calling-AE-title(16, ASCII,
//   space-padded)@26 Reserved(32)@42 [not validated] Variable Items@74 [Application Context Item +
//   one-or-more Presentation Context Items + User Information Item, back to back].
//   HONESTY NOTE: in the AC, Called/Calling-AE-title sit at the same offsets but are NOT
//   semantically authoritative per spec -- real implementations commonly echo the RQ's own values
//   back, but aren't required to. This decoder decodes and displays both AC fields independently,
//   never assuming equality with the RQ's own values.
//
// Variable-item sub-TLV framing (used at every nesting level: top-level items directly under
// A-ASSOCIATE-RQ/AC, AND nested sub-items inside a Presentation Context or User Information item):
//   item-type(1) reserved(1,==0x00) item-length(2,BE) value(item-length bytes).
//
// Item-type table: 0x10 Application Context, 0x20 Presentation Context (RQ), 0x21 Presentation
// Context Reply (AC), 0x30 Abstract Syntax (nested), 0x40 Transfer Syntax (nested), 0x50 User
// Information, 0x51 Maximum Length (nested), 0x52 Implementation Class UID (nested), 0x53
// Asynchronous Operations Window Negotiation (nested), 0x54 SCP/SCU Role Selection (nested), 0x55
// Implementation Version Name (nested), 0x56 SOP Class Extended Negotiation (nested, structural
// only -- low security value), 0x57 SOP Class Common Extended Negotiation (nested, structural only),
// 0x58 User Identity Negotiation (nested, SECURITY-RELEVANT, fully decoded -- see SECURITY below),
// 0x59 User Identity Negotiation Reply (nested, AC only).
//
// Application Context Item (0x10): ASCII UID string value, no null terminator on the wire in the
// item-length-declared bytes themselves (a trailing NUL, if item-length happens to include one for
// even-padding, is stripped). Almost always the single well-known value
// "1.2.840.10008.3.1.1.1" -- decoded and displayed verbatim either way; anything else is flagged as
// a worth-a-note anomaly, not a hard error.
//
// Presentation Context Item, RQ form (0x20): presentation-context-ID(1, odd values 1-255 only --
// this is what a later P-DATA-TF's PDVs reference) reserved(1) reserved(1) reserved(1), then nested
// sub-items: exactly ONE Abstract Syntax Sub-Item (0x30, the SOP Class UID this context proposes)
// followed by ONE-OR-MORE Transfer Syntax Sub-Items (0x40, every encoding the requester will accept
// for this context).
//
// Presentation Context Item, AC form (0x21) -- CONFIRMED ASYMMETRIC vs. the RQ form:
// presentation-context-ID(1, matches the RQ's own chosen ID) reserved(1) result/reason(1) reserved(1),
// then exactly ONE accepted Transfer Syntax Sub-Item (0x40) -- NO Abstract Syntax Sub-Item at all in
// the AC (the context-ID alone ties it back to the RQ's own abstract syntax).
// Result/Reason values: 0 Acceptance, 1 User-rejection, 2 No-reason (provider rejection),
// 3 Abstract-syntax-not-supported, 4 Transfer-syntaxes-not-supported.
//
// User Information Item (0x50) sub-items this decoder reads:
//   0x51 Maximum Length: Maximum-length-received(4,BE uint32).
//   0x52 Implementation Class UID: ASCII UID string -- a useful passive fingerprint (often
//     identifies vendor/toolkit, e.g. dcm4che/GDCM/a specific vendor build).
//   0x55 Implementation Version Name: ASCII string, commonly present alongside 0x52.
//   0x53 Asynchronous Operations Window: Max-Ops-Invoked(2,BE) Max-Ops-Performed(2,BE).
//   0x54 SCP/SCU Role Selection: SOP-Class-UID-length(2,BE)=m SOP-Class-UID(m) SCU-role(1: 0/1)
//     SCP-role(1: 0/1).
//   0x58 User Identity Negotiation -- THE single most security-relevant item here, see SECURITY/
//     REDACTION below: User-Identity-Type(1: 1=username-UTF8, 2=username+passcode-UTF8,
//     3=Kerberos-ticket, 4=SAML-assertion) Positive-response-requested(1: 0/1)
//     Primary-field-length(2,BE) Primary-field(that many bytes) [only if type==2:
//     Secondary-field-length(2,BE) Secondary-field(that many bytes -- THE PASSCODE)].
//   0x59 User Identity Negotiation Reply (AC only): Server-response-length(2,BE)
//     Server-response(that many bytes, may be zero-length).
//   0x56/0x57 (extended negotiation): recognized and skipped past (item-type/length only) --
//     structural-only, low security value, not further decoded.
//
// SOP Class UID / Transfer Syntax UID curated tables and the Command Field / Status tables: see
// dicom.cpp for the exact source-confirmed value lists -- reproduced there, immediately above each
// lookup function, rather than duplicated here.
//
// A-ASSOCIATE-RJ (0x03): reserved(1)@6 Result(1)@7 [1=rejected-permanent, 2=rejected-transient]
// Source(1)@8 [1=DICOM-UL-service-user, 2=DICOM-UL-service-provider(ACSE),
// 3=DICOM-UL-service-provider(Presentation)] Reason/Diag(1)@9 [meaning depends on Source -- see
// dicom.cpp's dicom_rj_reason_name for the full per-source table].
//
// A-ABORT (0x07): reserved(1)@6 reserved(1)@7 Source(1)@8 [0=DICOM-UL-service-user,
// 2=DICOM-UL-service-provider; 1 is unused/reserved] Reason/Diag(1)@9 [only meaningful when
// Source==2 -- see dicom.cpp's dicom_abort_reason_name].
//
// P-DATA-TF (0x04): the PDU body is one-or-more Presentation Data Value (PDV) items:
// item-length(4,BE -- length of everything AFTER this 4-byte field) presentation-context-ID(1)
// message-control-header(1) PDV-data(item-length - 2 bytes). Multiple PDVs can pack into one PDU;
// a single logical Command Set or Data Set can ALSO be fragmented across MULTIPLE P-DATA-TF PDUs --
// see STATEFULNESS below for the two-layer reassembly this needs.
// Message-control-header: only the 2 LSBs are defined (bits 2-7 are always 0 by a conforming sender
// and never checked by a conforming receiver per PS3.8 -- masked with 0x3 here, never a rejection
// reason on their own). bit0(0x01): 1=Command / 0=Data. bit1(0x02): 1=last fragment / 0=more follow.
//
// CRITICAL RULE (confirmed from two independent sources -- PS3.7 section 6.3.1 AND Wireshark's own
// packet-dcm.c, which hardcodes `pdv->syntax = DCM_ILE` for a Command-flagged PDV with the comment
// "Command tags are always little endian"): a Command-flagged PDV is ALWAYS encoded Implicit VR
// Little Endian, completely independent of whatever transfer syntax was negotiated for that
// presentation context. The negotiated transfer syntax applies ONLY to Data-flagged PDVs. This is
// the single most common bug source in a from-scratch DICOM decoder, per this feature's own
// research pass, and is enforced structurally below (DicomDecoder::decode never consults the
// negotiated transfer syntax when decoding a Command-flagged PDV's reassembled bytes).
//
// Command Set element format (always Implicit VR LE): tag = group(2,LE) + element(2,LE),
// length(4,LE unsigned), value(length bytes). Curated command-group (0000,xxxx) tags -- see
// dicom.cpp's decode_dicom_command_set for the full per-tag VR/meaning table: (0000,0000) Group
// Length, (0000,0100) Command Field (the DIMSE operation code -- this decoder's Modbus-function-
// code equivalent), (0000,0110) Message ID, (0000,0120) Message ID Being Responded To, (0000,0800)
// Command Data Set Type (0x0101 == no data set follows), (0000,0900) Status, (0000,0002)/(0000,0003)
// Affected/Requested SOP Class UID, (0000,1000)/(0000,1001) Affected/Requested SOP Instance UID,
// (0000,1020)/(0000,1021)/(0000,1022)/(0000,1023) Number of Remaining/Completed/Failed/Warning
// Sub-operations.
//
// The data set (Data-flagged PDVs) -- CURATED EXTRACTION ONLY, see SCOPE above. Implicit VR
// element: tag(4) + length(4, plain unsigned UNLESS it reads as 0xFFFFFFFF, "undefined length",
// used for Sequences and encapsulated/compressed Pixel Data -- see below) + value. Explicit VR
// element: tag(4) + VR(2 ASCII bytes) + then, depending on VR: SHORT FORM (every VR except the ten
// below) length(2) + value(length bytes); LONG FORM (OB, OD, OF, OL, OW, SQ, UC, UR, UT, UN --
// CONFIRMED as exactly these ten, not a smaller commonly-assumed set) reserved(2,==0x0000)
// length(4) + value(length bytes). Byte order for tag/length follows the negotiated transfer
// syntax: little-endian for Implicit VR LE and Explicit VR LE (the overwhelming majority of real
// traffic), big-endian only for the retired Explicit VR Big Endian
// (1.2.840.10008.1.2.2). Compressed transfer syntaxes only affect Pixel Data's own encoding --
// every curated metadata element stays uncompressed plain short-form regardless, so this decoder
// never needs to understand a JPEG/RLE/JPEG2000 bitstream; it only needs to safely SKIP Pixel Data
// without decoding it (see below).
// Pixel Data (7FE0,0010) is a special, VR-independent case: recognized by tag alone, its value is
// ALWAYS skipped as opaque bytes regardless of length form -- image content is never decoded.
// Undefined-length (0xFFFFFFFF) handling: delimited by generic structural tags recognized by tag
// alone, never dictionary-looked-up: Item (FFFE,E000), Item Delimitation (FFFE,E00D), Sequence
// Delimitation (FFFE,E0DD) (each with its own 4-byte length field, typically 0 for the delimiters).
// This decoder walks a flat sequence of definite-length Items up to the Sequence Delimitation Item
// -- the shape encapsulated (compressed) Pixel Data and the overwhelming majority of real-world
// simple sequences both actually take. If an Item itself ALSO has an undefined length (a genuinely
// nested undefined-length structure), this decoder deliberately does not attempt to bound it further
// -- it STOPS curated-tag extraction for the rest of that data set and emits an honest note
// ("data set extraction stopped: undefined-length element of unrecognized structure encountered")
// rather than risk misparsing subsequent bytes as garbage. A deliberate, honestly-documented scope
// boundary, matching this codebase's universal posture on structures it cannot safely bound.
//
// Curated data-set tags, VRs, and this decoder's redaction posture for each: see REDACTION below
// for the full table (it doubles as this decoder's own scope list for which patient-identity/
// asset-inventory tags are extracted at all).
//
// SECURITY -- ASSOCIATIONS WITH NO IDENTITY NEGOTIATION (this decoder's own headline curated
// finding, matching Cipher Suite 0 for IPMI/cleartext creds for AMQP/LDAP-CONNECT elsewhere in this
// codebase): base DICOM Upper Layer has essentially NO built-in authentication beyond the optional,
// frequently-ABSENT User Identity Negotiation item (0x58) -- an AE-title is a plain, unauthenticated
// string any peer can claim for itself, and PS3.15's own TLS/User-Identity profiles are widely
// under-deployed in real hospital imaging networks (this is the well-documented, common real-world
// case this feature's own research pass confirmed, not a rare edge case worth burying). This
// decoder recognizes it directly at the tell the spec puts it at: an A-ASSOCIATE-RQ with no User
// Identity Negotiation item at all is, by construction, an unauthenticated-trust association --
// flagged prominently in --stats (`*** DICOM associations with no identity negotiation (AE-title-
// only, unauthenticated trust) observed: N ***`), the same "never buried" convention IPMI's own
// Cipher Suite 0 headline already establishes.
//
// SECURITY -- USER IDENTITY NEGOTIATION ITSELF: even when present, type 2 (username+passcode)
// carries the passcode in the clear on the wire -- a second, narrower cleartext-credential finding,
// counted separately in --stats. Types 3/4 (Kerberos ticket / SAML assertion) are credential-
// adjacent material (a different risk category from a bare password, but still sensitive-by-default
// per this decoder's own REDACTION posture below).
//
// SECURITY -- A-ASSOCIATE-RJ PATTERN (AE-title enumeration): repeated RJ with reason=3 (calling-AE-
// title-not-recognized) or reason=7 (called-AE-title-not-recognized) from/to one peer, across many
// distinct AE-titles, in a short window, is the signature real tooling (e.g. `dicom-brute`) uses for
// AE-title enumeration/brute-forcing -- this decoder surfaces a `--stats` breakdown of RJ counts by
// reason code so that pattern is visible at a glance, without this decoder itself attempting any
// cross-packet enumeration-detection heuristic (that judgment call is left to the analyst reading
// the breakdown, the same posture this codebase takes for e.g. LDAP/Kerberos error-code breakdowns).
//
// REDACTION: reuses kRedactedSecretPlaceholder/redact_secret_occurrences from protocol_decoder.hpp
// exactly as IPMI's Auth Code, Netlogon's NL_TRUST_PASSWORD, and AMQP's SASL response already do
// (see rmcp.hpp/netlogon.hpp/amqp091.hpp for the established call-site shape this file follows).
// Two independent redaction sites:
//   1. User Identity Negotiation (item 0x58), type-dependent: type==2's Secondary-field (the
//      passcode) is NEVER rendered -- its bytes are never even copied out of the wire buffer, only
//      its length is read and kept (the same "read the length, discard the bytes immediately after"
//      posture amqp091.hpp's own Start-Ok `response` handling already establishes). Primary-field
//      (the username, type 1/2) IS shown in full -- a username is not a secret, the same "only the
//      password is" precedent IPMI's own RAKP Message 1 User Name field establishes. Types 3/4
//      (Kerberos ticket/SAML assertion) are treated as sensitive-by-default too (presence + length
//      shown, never the raw bytes), since they are credential-adjacent even though a different risk
//      category from a bare password.
//   2. Three curated PHI (Protected Health Information) data-set tags -- direct patient identifiers,
//      redacted BY DEFAULT, revealed only via this codebase's existing --no-redact flag:
//        (0010,0010) Patient's Name (PN)
//        (0010,0020) Patient ID (LO)
//        (0010,0030) Patient's Birth Date (DA)
//      Every OTHER curated data-set tag this decoder extracts is NOT redacted by default:
//        (0010,0040) Patient's Sex (CS) -- DICOM's own de-identification Basic Profile keeps this
//          field by default too; not a direct identifier alone, matching upstream's own risk
//          categorization.
//        (0020,000D) Study Instance UID (UI), (0020,000E) Series Instance UID (UI), (0008,0018) SOP
//          Instance UID (UI), (0008,0050) Accession Number (SH) -- NOT redacted, but see the UID-AS-
//          CORRELATION-KEY caveat immediately below: this is a deliberate trade-off, not an
//          oversight.
//        (0008,0060) Modality (CS), (0008,0080) Institution Name (LO), (0008,1010) Station Name
//          (SH), (0008,0070) Manufacturer (LO), (0008,1090) Manufacturer's Model Name (LO),
//          (0008,0020) Study Date (DA), (0008,1030) Study Description (LO, free text -- can
//          incidentally leak clinical context, noted but not redacted) -- device/workflow-
//          identifying fields an asset-inventory audit needs to see, not patient identifiers.
//   UID-AS-CORRELATION-KEY CAVEAT: Study/Series Instance UID, SOP Instance UID, and Accession
//   Number are NOT blanket-redacted here, but this is a documented trade-off, not a claim that
//   they're harmless. DICOM's own de-identification profile (PS3.15) treats UIDs as needing
//   CONSISTENT REPLACEMENT (a stable, unlinkable substitute) rather than "not sensitive at all" --
//   they are real correlation/linking keys across a patient's imaging history over time, a genuine
//   re-identification/provenance risk. They are shown here, unredacted, because this tool's entire
//   inventory/correlation purpose (seeing which studies/series move across which modalities/
//   workstations on the network) structurally depends on being able to see them; blanket-redacting
//   them would defeat the tool's own reason for decoding DICOM at all. An analyst using --no-redact
//   already accepts the PHI-exposure tradeoff for the three tags that ARE redacted by default; the
//   UID tags are a separate, always-visible tier by deliberate design, documented here and in
//   docs/PROTOCOL_COVERAGE.md so nobody mistakes "not redacted" for "not sensitive."
//
// DETECTION/DISPATCH: GateKind::TcpPort, deliberately PORT-GATED in Auto mode -- the same posture
// WinRM/DCOM/GE SRTP/AMQP already establish for this gate kind. DICOM's own structural gate (a
// PDU-type byte constrained to exactly 7 contiguous values, plus a length field whose declared value
// this decoder can cross-check against the available bytes) is real but not a magic-constant-strength
// signal the way e.g. OPC UA's or SMB's own leading magic bytes are, so trying it opportunistically
// on every TCP payload in Auto mode would risk false-positiving on ordinary binary traffic elsewhere
// -- exactly the reasoning ge_srtp.hpp's own "STRUCTURAL DETECTION GATE" section documents for its
// own comparably-shaped gate. UNLIKE every single-default-port GateKind::TcpPort protocol in this
// codebase, DICOM checks TWO default ports in Auto mode without any CLI flag needed -- mirroring the
// LDAP_PORT/LDAP_GC_PORT precedent (it_protocols.hpp/ldap.hpp, decoder.cpp's own candidate_is_ldap
// checks), not HART-IP's own same-port-both-transports shape (DICOM_PORT and DICOM_PORT_ALT are two
// genuinely DIFFERENT port numbers, both TCP): port 104 (DICOM_PORT, IANA-registered, rare in
// practice) and port 11112 (DICOM_PORT_ALT, the de facto real-world default) are BOTH checked
// automatically, neither one designated "the" default the other merely widens -- see
// decoder.cpp's own DICOM call sites (both the declared-length cascade and the main decode cascade)
// for the exact `port_in(..., DICOM_PORT, extra) || port_in(..., DICOM_PORT_ALT, extra)` shape this
// mirrors from LDAP. `--extra-dicom-ports` (DecodeOptions::extra_dicom_ports) widens beyond both of
// those two, the same "additional expected ports" convention every other extra_*_ports list already
// has. An explicit `--protocol dicom` still tries DICOM port-independently, the same exception every
// other GateKind::TcpPort protocol here already has.
//
// STATEFULNESS -- TWO INDEPENDENT LAYERS, both required, neither optional:
//   1. DicomAssociationState (DecoderFlowState, Session-keyed via
//      DecodeContext::flow_state<DicomAssociationState>() -- the default no-argument overload,
//      Session-scoped like ModbusFlowState/TwinCatFlowState/IpmiFlowState, since an A-ASSOCIATE-RQ
//      and its AC can legitimately be answered from either TCP direction, exactly the shape those
//      three already establish). Built incrementally as the RQ then AC are observed on a session:
//      the RQ populates each presentation context's ABSTRACT SYNTAX (SOP Class UID) keyed by its
//      presentation-context-ID; the AC then fills in the ACCEPTED TRANSFER SYNTAX for whichever IDs
//      it accepts (result==0). This map is THE ONLY way to decode a later P-DATA-TF on the same
//      session: without it, a PDV's own bytes are fundamentally ambiguous (Command-flagged content
//      is always Implicit VR LE regardless, but WHICH SOP Class/instance it concerns still needs the
//      abstract syntax; Data-flagged content additionally needs the negotiated transfer syntax to
//      even know its byte-order/VR-presence convention). A session whose A-ASSOCIATE-RQ/AC exchange
//      was never captured in this capture (a mid-stream-only P-DATA-TF) is handled HONESTLY: this
//      decoder can still recognize "this looks like a DICOM PDU" from the PDU-type/length structural
//      gate alone (weak but real, especially combined with the port hint), but it deliberately does
//      NOT guess a default transfer syntax to decode the PDV content anyway -- it renders a
//      structural note ("P-DATA-TF observed, N PDV(s), association context not captured on this
//      session -- cannot decode content") instead. Even Wireshark's own packet-dcm.c dissector
//      authors call cross-session association tracking a hard, only-partially-solved problem in
//      their own source comments -- this is the honest state of the art, not a shortcut unique to
//      this codebase.
//   2. DicomDimseReassemblyState (DecoderFlowState, DirectionalFlow-keyed via
//      DecodeContext::flow_state<T>(FlowStateKeying::DirectionalFlow) -- the same keying
//      CotpReassemblyState/Dnp3ReassemblyState already use for cross-message fragment reassembly,
//      and for the identical reason: a single logical Command Set or Data Set can be fragmented
//      across MULTIPLE PDVs and MULTIPLE P-DATA-TF PDUs, signaled by the message-control-header's
//      own "last fragment" bit, and this reassembly is inherently per-DIRECTION -- nothing stops a
//      genuine DICOM association from having a client->server fragment and a server->client
//      fragment both in flight at once (this is a GENUINELY SEPARATE layer from #1 above: #1 is
//      "which SOP Class/transfer syntax does this presentation-context-ID mean", #2 is "have I seen
//      every byte of THIS message yet"). Command-flagged and Data-flagged bytes are buffered
//      independently (a Command Set completing does not affect an in-progress Data Set fragment, and
//      vice versa). Bounded by the SAME `--max-reassembly-bytes`/`--max-reassembly-segments` CLI
//      overrides every other cross-message reassembly in this codebase already shares (see
//      resource_limits.hpp) -- no new dedicated CLI flag for this feature. Mirrors
//      CotpReassemblyState's own "abandon and note" behavior on a non-Data PDU/PDV interrupting an
//      in-progress reassembly and on exceeding the safety cap.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t DICOM_PORT = 104;        // IANA-registered "dicom" -- rare in practice (privileged
                                              // bind); see this file's own DETECTION/DISPATCH section.
constexpr uint16_t DICOM_PORT_ALT = 11112;  // the de facto real-world default (PACS/dcm4che/Orthanc/
                                              // most vendor imaging software) -- weighted as the
                                              // COMMON case, not a secondary fallback.

// ---------------------------------------------------------------------------------------------
// Curated name/classification lookups -- see dicom.cpp for the full, source-confirmed tables.

const char* dicom_pdu_type_name(uint8_t pdu_type_raw);      // nullptr outside 0x01-0x07.
const char* dicom_item_type_name(uint8_t item_type_raw);    // nullptr for an unrecognized item type.

// Curated SOP Class UID / Transfer Syntax UID tables (see this file's own SCOPE section for why
// these are curated, not exhaustive). Both return nullptr for an unrecognized UID -- callers render
// "Unknown SOP Class (<uid>)"/"Unknown Transfer Syntax (<uid>)" themselves.
const char* dicom_sop_class_name(const std::string& uid);
const char* dicom_transfer_syntax_name(const std::string& uid);
// True for the well-known compressed-family prefixes (1.2.840.10008.1.2.4.* / .1.2.5) -- see this
// file's own WIRE FORMAT section for why only this coarse classification matters to this decoder
// (compression only ever affects Pixel Data's own encoding, never the curated metadata elements).
bool dicom_transfer_syntax_is_compressed(const std::string& uid);

const char* dicom_command_field_name(uint16_t command_field_raw);  // nullptr if not one of the
                                                                      // curated DIMSE operation codes.

enum class DicomStatusClass { Success, Pending, Warning, Failure, Cancel };
DicomStatusClass dicom_status_class(uint16_t status_raw);  // coarse 3-tier-plus classification, see
                                                              // WIRE FORMAT above -- always succeeds.
const char* dicom_status_name(uint16_t status_raw);          // curated fine-grained name, or nullptr.

const char* dicom_rj_result_name(uint8_t result_raw);
const char* dicom_rj_source_name(uint8_t source_raw);
const char* dicom_rj_reason_name(uint8_t source_raw, uint8_t reason_raw);  // meaning depends on source.

const char* dicom_abort_source_name(uint8_t source_raw);
const char* dicom_abort_reason_name(uint8_t reason_raw);  // only meaningful when source==2.

// ---------------------------------------------------------------------------------------------
// A-ASSOCIATE-RQ/AC structures.

struct DicomTransferSyntax {
    std::string uid;
    std::string name;       // curated name, or "Unknown Transfer Syntax (<uid>)".
    bool compressed = false;
};

struct DicomAbstractSyntax {
    std::string uid;
    std::string name;  // curated SOP Class name, or "Unknown SOP Class (<uid>)".
};

struct DicomPresentationContextRq {
    uint8_t id = 0;
    std::optional<DicomAbstractSyntax> abstract_syntax;
    std::vector<DicomTransferSyntax> transfer_syntaxes;  // one-or-more proposed.
};

struct DicomPresentationContextAc {
    uint8_t id = 0;
    uint8_t result_raw = 0;
    std::string result_name;
    bool accepted = false;  // result_raw == 0.
    std::optional<DicomTransferSyntax> transfer_syntax;  // present only when accepted, per spec.
};

// User Identity Negotiation (item 0x58) -- see this file's own SECURITY/REDACTION sections.
struct DicomUserIdentity {
    uint8_t type_raw = 0;
    std::string type_name;
    bool positive_response_requested = false;
    // Populated ONLY for type 1 (username) / type 2 (username+passcode) -- NOT a secret, shown in
    // full. Left empty for type 3/4 (Kerberos ticket/SAML assertion), which are credential-adjacent
    // and treated as sensitive-by-default -- see primary_field_length for their own byte length.
    std::string primary_field;
    size_t primary_field_length = 0;
    bool secondary_present = false;      // type == 2 only.
    size_t secondary_field_length = 0;   // the passcode's own byte length -- NEVER its bytes.
};

struct DicomUserIdentityReply {
    size_t server_response_length = 0;  // bytes never copied -- length only, matching this file's
                                          // own "length is a useful, non-sensitive signal" posture.
};

struct DicomRoleSelection {
    std::string sop_class_uid;
    std::string sop_class_name;  // curated name, or "Unknown SOP Class (<uid>)".
    bool scu_role = false;
    bool scp_role = false;
};

struct DicomUserInformation {
    std::optional<uint32_t> max_length_received;
    std::optional<std::string> implementation_class_uid;
    std::optional<std::string> implementation_version_name;
    std::optional<uint16_t> max_ops_invoked;
    std::optional<uint16_t> max_ops_performed;
    std::vector<DicomRoleSelection> role_selections;
    std::optional<DicomUserIdentity> user_identity;             // RQ only.
    std::optional<DicomUserIdentityReply> user_identity_reply;  // AC only.
};

struct DicomAssociateRqAc {
    bool is_request = false;  // true == A-ASSOCIATE-RQ, false == A-ASSOCIATE-AC.
    uint16_t protocol_version_raw = 0;
    std::string called_ae_title;
    std::string calling_ae_title;
    std::optional<std::string> application_context_uid;
    bool application_context_is_well_known = false;
    std::vector<DicomPresentationContextRq> presentation_contexts_rq;  // RQ only.
    std::vector<DicomPresentationContextAc> presentation_contexts_ac;  // AC only.
    DicomUserInformation user_information;
    bool has_user_identity = false;  // RQ only -- mirrors user_information.user_identity.has_value(),
                                       // this decoder's own headline-finding tell (see SECURITY above).
};

struct DicomAssociateRj {
    uint8_t result_raw = 0;
    std::string result_name;
    uint8_t source_raw = 0;
    std::string source_name;
    uint8_t reason_raw = 0;
    std::string reason_name;
};

struct DicomAbort {
    uint8_t source_raw = 0;
    std::string source_name;
    uint8_t reason_raw = 0;
    std::string reason_name;  // empty when source != 2 (not meaningful, see WIRE FORMAT above).
};

// ---------------------------------------------------------------------------------------------
// P-DATA-TF / DIMSE structures.

struct DicomPdvInfo {
    uint32_t item_length = 0;
    uint8_t presentation_context_id = 0;
    uint8_t message_control_header_raw = 0;
    bool is_command = false;       // bit0.
    bool is_last_fragment = false; // bit1.
    ByteSpan data;                 // item_length - 2 bytes -- valid only for the lifetime of the
                                     // buffer try_parse_dicom_pdu was called against (same "caller
                                     // keeps it alive as a same-scope local" contract every
                                     // ByteSpan-returning helper in this codebase already has).
};

struct DicomCommandSet {
    std::optional<uint16_t> command_field_raw;
    std::string command_field_name;  // empty when command_field_raw is unset or uncurated.
    std::optional<uint16_t> message_id;
    std::optional<uint16_t> message_id_being_responded_to;
    std::optional<uint16_t> data_set_type_raw;
    std::optional<uint16_t> status_raw;
    std::string status_name;
    DicomStatusClass status_class = DicomStatusClass::Success;
    std::optional<std::string> affected_sop_class_uid;
    std::optional<std::string> requested_sop_class_uid;
    std::optional<std::string> affected_sop_instance_uid;
    std::optional<std::string> requested_sop_instance_uid;
    std::optional<uint16_t> remaining_suboperations;
    std::optional<uint16_t> completed_suboperations;
    std::optional<uint16_t> failed_suboperations;
    std::optional<uint16_t> warning_suboperations;
};

struct DicomDataElement {
    std::string tag_name;   // e.g. "Patient's Name".
    std::string rendered;   // human-readable value, or the redaction placeholder + byte count.
    bool redacted = false;
};

struct DicomDataSet {
    std::vector<DicomDataElement> elements;  // curated tags found, in wire order.
    std::optional<std::string> stopped_reason;  // set when extraction stopped early -- see this
                                                   // file's own WIRE FORMAT "undefined-length" note.
};

struct DicomPDataTf {
    std::vector<DicomPdvInfo> pdvs;
    bool association_captured = false;  // true only when every PDV's own presentation-context-ID is
                                          // known from an earlier-captured RQ/AC on this session --
                                          // see this file's own STATEFULNESS section.
    std::optional<DicomCommandSet> command_set;  // set when a Command fragment completed THIS call.
    std::optional<DicomDataSet> data_set;        // set when a Data fragment completed THIS call.
};

struct DicomFrame {
    uint8_t pdu_type_raw = 0;
    std::string pdu_type_name;
    uint32_t pdu_length = 0;
    size_t wire_length = 0;
    bool truncated = false;

    std::optional<DicomAssociateRqAc> associate;
    std::optional<DicomAssociateRj> reject;
    std::optional<DicomAbort> abort;
    std::optional<DicomPDataTf> p_data;
    // A-RELEASE-RQ/RP (0x05/0x06) carry no further fields -- pdu_type_name alone is the whole
    // decode, matching this file's own SCOPE section.

    std::string summary;
    std::vector<std::string> notes;
};

// One decoded TCP payload's worth of DICOM traffic -- `first` is the primary PDU this
// DecodedPacket's own summary/notes/JSON fields render from; any further PDU coalesced into the
// same TCP payload (P-DATA-TF PDUs in particular are very often sent back-to-back by a real
// implementation) is folded into `notes` as its own one-line summary, the same MqttResult/
// Amqp091Result coalescing-loop shape mqtt.hpp/amqp091.hpp already establish.
struct DicomResult {
    DicomFrame first;
    std::string summary;
    std::vector<std::string> notes;
};

// Decodes a complete, reassembled Command Set (always Implicit VR Little Endian -- see this file's
// own CRITICAL RULE note above). Curated command-group tags only; every other tag is skipped past
// via its own plain 4-byte length field. Never throws.
DicomCommandSet decode_dicom_command_set(ByteSpan bytes);

// Decodes a complete, reassembled Data Set per the negotiated transfer syntax for its presentation
// context -- curated tag extraction only, see this file's own SCOPE/WIRE FORMAT sections.
// `redact_secrets` gates whether the three curated PHI tags (Patient's Name/ID/Birth Date) render
// their real value or the redaction placeholder. Never throws.
DicomDataSet decode_dicom_data_set(ByteSpan bytes, bool explicit_vr, bool big_endian,
                                    bool redact_secrets);

// Parses exactly ONE PDU starting at the beginning of `candidate`. Returns std::nullopt only when
// `candidate` is too short even for the fixed 6-byte common header, or the PDU-type byte isn't one
// of the 7 legal values -- the whole structural gate this decoder's port-gated Auto-mode detection
// relies on (see this file's own DETECTION/DISPATCH section). Does NOT decode Command Set/Data Set
// content for a P-DATA-TF (that needs cross-packet association/reassembly state this free function
// has no access to -- see DicomDecoder::decode) -- it only parses PDV structure (length,
// presentation-context-ID, Command/Data flag, last-fragment flag). Never throws.
std::optional<DicomFrame> try_parse_dicom_pdu(ByteSpan candidate);

// Two-phase declared-length probe (same shape amqp091_tcp_declared_length/ge_srtp_tcp_declared_length
// already establish) for Decoder::reassemble_tcp_payload's own cross-TCP-segment PDU reassembly.
// Returns std::nullopt when `candidate`'s first byte isn't a legal PDU-type value.
std::optional<size_t> dicom_tcp_declared_length(ByteSpan candidate);

// Cross-packet association state -- see this file's own STATEFULNESS section (layer 1).
class DicomAssociationState : public DecoderFlowState {
public:
    struct PresentationContextInfo {
        std::optional<DicomAbstractSyntax> abstract_syntax;    // from the RQ.
        std::optional<DicomTransferSyntax> transfer_syntax;    // from the AC, only when accepted.
        bool accepted = false;
    };
    bool rq_seen = false;
    bool ac_seen = false;
    std::string called_ae_title;
    std::string calling_ae_title;
    std::unordered_map<uint8_t, PresentationContextInfo> presentation_contexts;
};

// Cross-packet DIMSE fragment reassembly state -- see this file's own STATEFULNESS section
// (layer 2). DirectionalFlow-keyed (one instance per TCP direction on a session).
class DicomDimseReassemblyState : public DecoderFlowState {
public:
    bool command_in_progress = false;
    std::vector<uint8_t> command_buffer;
    uint8_t command_pc_id = 0;
    size_t command_fragment_count = 0;

    bool data_in_progress = false;
    std::vector<uint8_t> data_buffer;
    uint8_t data_pc_id = 0;
    size_t data_fragment_count = 0;
};

class DicomDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "dicom"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return DICOM_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return dicom_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& dicom_tcp_decoder();

}  // namespace conduitscope
