// SPDX-License-Identifier: Apache-2.0
// bacnet.hpp - BACnet/IP (Annex J) decoding: BVLC (BACnet Virtual Link Control, the UDP framing
// header) + NPDU (Network Layer PDU) + APDU (Application Layer PDU, the service layer).
//
// Unlike EtherCAT, PROFINET RT, IEC 61850-8-1 GOOSE, and IEC 61850-9-2 Sampled Values, BACnet/IP
// does not ride directly on raw Ethernet -- it rides on UDP, conventionally port 47808 (0xBAC0),
// the same "opportunistic, payload-shape" detection posture as EtherNet/IP CIP I/O (UDP port
// 2222) -- see the "structural detection gate" paragraph below. Every multi-byte field at every
// layer is big-endian (unlike EtherCAT's little-endian, but the same as every other protocol in
// this codebase).
//
// Sourcing: this file's wire-format description is cross-checked, byte offset by byte offset,
// against Wireshark's own BACnet dissectors -- epan/dissectors/packet-bvlc.c (BVLC),
// packet-bacnet.c (NPDU), and packet-bacapp.c (APDU + BACnet's own tag encoding + service value
// decode) -- the same sourcing standard this codebase already applies to GOOSE/SV/EtherCAT/
// PROFINET.
//
// ---------------------------------------------------------------------------------------------
// BVLC (4-byte fixed header, immediately at the start of a UDP/47808 payload -- ASHRAE 135 Annex
// J.2, cross-checked against packet-bvlc.c's dissect_ipv4_bvlc):
//   Type(1)      -- 0x81 for "BACnet/IP (Annex J)", the only BVLC type this decoder recognizes (a
//                    separate value, 0x82, exists for BACnet/SC's WebSocket-based transport, an
//                    entirely different framing this decoder does not attempt) -- see "structural
//                    detection gate" below.
//   Function(1)  -- which of 13 defined BVLC functions this is (0x00-0x0C; cross-checked against
//                    packet-bvlc.c's bvlc_function_names[]):
//                      0x00 BVLC-Result                              0x07 Read-Foreign-Device-Table-Ack
//                      0x01 Write-Broadcast-Distribution-Table       0x08 Delete-Foreign-Device-Table-Entry
//                      0x02 Read-Broadcast-Distribution-Table        0x09 Distribute-Broadcast-To-Network
//                      0x03 Read-Broadcast-Distribution-Table-Ack    0x0A Original-Unicast-NPDU
//                      0x04 Forwarded-NPDU                           0x0B Original-Broadcast-NPDU
//                      0x05 Register-Foreign-Device                  0x0C Secure-BVLL
//                      0x06 Read-Foreign-Device-Table
//   Length(2)    -- total byte length of this BVLC message INCLUDING the 4-byte header, big-
//                    endian (cross-checked against packet-bvlc.c's own bvlc_length/packet_length
//                    cross-check, which this decoder mirrors: Length is trusted only when it is
//                    at least 4 and does not exceed the bytes actually present, falling back to
//                    "use all available bytes" with a note otherwise).
//
// Functions 0x00-0x03 and 0x05-0x08 are BBMD (BACnet Broadcast Management Device) foreign-
// device-table / broadcast-distribution-table management -- routing-level housekeeping between
// BBMDs, carrying no NPDU at all. This decoder decodes their own sub-fields (BVLC-Result's 2-byte
// result code; Write-BDT/Read-BDT-Ack's list of 10-byte BDT entries -- IP(4)+Port(2)+Mask(4);
// Register-Foreign-Device's 2-byte Time-To-Live; Read-FDT-Ack's list of 10-byte FDT entries --
// IP(4)+Port(2)+TTL(2)+Timeout(2); Delete-FDT-Entry's 6-byte IP+Port) but never an NPDU, matching
// packet-bvlc.c's own bvlc_length computation (`bvlc_length = packet_length` for these functions
// -- the whole message is BVLC, nothing left over for an NPDU).
//
// Functions 0x09 (Distribute-Broadcast-To-Network), 0x0A (Original-Unicast-NPDU), 0x0B (Original-
// Broadcast-NPDU), and 0x04 (Forwarded-NPDU) all carry an NPDU immediately after a 4-byte header
// (0x09/0x0A/0x0B) or after a 4-byte header plus a 6-byte "originating device" B/IP address
// (0x04 -- IP(4)+Port(2), the BBMD-forwarded broadcast's actual source, decoded and surfaced
// separately from the UDP/IP headers' own src_ip/src_port) -- this is the traffic this decoder's
// NPDU/APDU decode (below) actually applies to. In real deployments, 0x0A (Original-Unicast-NPDU)
// is by far the most common -- ordinary unicast request/response traffic between a client and a
// single device not going through a BBMD at all.
//
// Function 0x0C (Secure-BVLL) wraps an entire BACnet/SC-style encrypted/signed payload -- this
// decoder does not attempt decryption (no key material exists on the wire), so it is named only,
// the same "no generic self-describing wire-level type" posture this codebase already applies to
// opaque/encrypted or engineering-configuration-dependent payloads (PROFINET cyclic IO data,
// EtherNet/IP CIP I/O Connected Data Item, SV's seqData, EtherCAT's Data field).
//
// Structural detection gate: this decoder requires BVLC Type == 0x81 AND Function to be one of
// the 13 values 0x00-0x0C listed above (falling back to ordinary "udp" groundwork reporting
// otherwise) -- a 2-byte anchor, weaker than a full 4-byte magic but considerably stronger than,
// say, EtherCAT's own Type-nibble-only gate (5-in-16 collision space): Type gives a 1-in-256
// match by itself, and Function narrows a false positive further to 13-in-256 of those. This is
// applied port-independently in Auto mode, the same "opportunistic, payload-shape" posture
// EtherNet/IP CIP I/O's own try_parse_cip_io already uses (see enip.hpp) -- UDP port 47808 is
// recorded as an "expected port" annotation only, never a gate.
//
// ---------------------------------------------------------------------------------------------
// NPDU (Network Layer PDU -- ASHRAE 135 clause 6, cross-checked against packet-bacnet.c's
// dissect_bacnet_npdu):
//   Version(1)  -- always 0x01 ("ASHRAE 135-1995") in every version of the standard published so
//                   far; surfaced as-is, not gated on.
//   Control(1)  -- a bitmask (cross-checked against packet-bacnet.c's BAC_CONTROL_* defines):
//                    bit 7 (0x80) NET     -- this NPDU carries a Network Layer Message (below),
//                                             NOT an APDU, when set.
//                    bit 6 (0x40) reserved
//                    bit 5 (0x20) DEST    -- DNET/DLEN/DADR (and, later, HopCount) are present.
//                    bit 4 (0x10) reserved
//                    bit 3 (0x08) SRC     -- SNET/SLEN/SADR are present.
//                    bit 2 (0x04) EXPECT  -- sender is requesting a reply be routed back
//                                             (segmentation-ACK/data-link confirmation, distinct
//                                             from APDU-layer Confirmed-Request semantics).
//                    bits 1-0     PRIORITY -- 2-bit priority (0=Normal, 1=Urgent, 2=Critical
//                                             Equipment, 3=Life Safety).
//   DNET(2), DLEN(1), DADR(DLEN)  -- present only when DEST is set: destination network number,
//                   MAC address length (0 = broadcast on DNET, 1 = MS/TP or ARCNET MAC, 6 =
//                   Ethernet MAC, otherwise a vendor MAC format), and the MAC address itself.
//   SNET(2), SLEN(1), SADR(SLEN)  -- present only when SRC is set, same shape as DNET/DLEN/DADR
//                   but for the originating network/MAC (used when a BACnet router forwarded this
//                   NPDU from another network -- SADR/SNET identify the ORIGINAL sender, not the
//                   router).
//   HopCount(1) -- present only when DEST is set: decremented by each router the NPDU passes
//                   through, protects against routing loops.
//   MessageType(1) [+ VendorID(2)]  -- present only when NET is set: which Network Layer Message
//                   this is (Who-Is-Router-To-Network/I-Am-Router-To-Network/Initialize-Routing-
//                   Table/.../Network-Number-Is, 0x00-0x13 ASHRAE-defined, 0x14-0x7F reserved,
//                   0x80-0xFF vendor-proprietary -- cross-checked against packet-bacnet.c's
//                   bacnet_msgtype_rvals[]) -- a 2-byte VendorID (big-endian) immediately follows
//                   MessageType only when MessageType is in the vendor-proprietary range (>=
//                   0x80). Network Layer Messages are named only via the range-string table above
//                   -- not value-decoded -- since real-world OT-security-relevant BACnet traffic
//                   is overwhelmingly application-layer (device/object discovery, property
//                   access), not the inter-router control plane; this mirrors this codebase's
//                   existing "first pass" service-scoping precedent (see below).
//
// When NET is clear, everything after the fixed NPDU header above is one complete APDU (below).
//
// ---------------------------------------------------------------------------------------------
// APDU (Application Layer PDU -- ASHRAE 135 clause 20, cross-checked against packet-bacapp.c's
// do_the_dissection/fStartConfirmed/fSegmentAckPDU/fErrorPDU/fRejectPDU/fAbortPDU): the first
// byte's top 4 bits (0-7) select one of 8 PDU types, cross-checked byte offset by byte offset
// against packet-bacapp.c's own dissection functions:
//   0 Confirmed-Request:  byte0 = type<<4 | SEG<<3 | MOR<<2 | SA<<1 | reserved ; byte1 =
//       max-segs-accepted(3 bits)<<5 | max-apdu-len-accepted(4 bits)<<1 | reserved ; invoke-id(1)
//       ; [sequence-number(1) + proposed-window-size(1), only if SEG] ; service-choice(1) ;
//       service-request data (this decoder's "first pass" set, or raw hex -- see below).
//   1 Unconfirmed-Request: byte0 = type<<4 | reserved(4 bits) ; service-choice(1) ; service-
//       request data.
//   2 Simple-ACK: byte0 = type<<4 | reserved ; invoke-id(1) ; service-ACK-choice(1) (no further
//       data -- a Simple-ACK's entire meaning is "that confirmed service succeeded").
//   3 Complex-Ack: byte0 = type<<4 | SEG<<3 | MOR<<2 | reserved ; invoke-id(1) ; [sequence-
//       number(1) + proposed-window-size(1), only if SEG] ; service-ACK-choice(1) ; service-ACK
//       data.
//   4 Segment-ACK: byte0 = type<<4 | reserved(2 bits)<<2 | NAK<<1 | SRV ; original-invoke-id(1) ;
//       sequence-number(1) ; actual-window-size(1) -- exactly 4 bytes total, no further data.
//   5 Error: byte0 = type<<4 | reserved ; original-invoke-id(1) ; error-choice(1) (the confirmed
//       service this error responds to) ; error data -- this decoder value-decodes only the
//       GENERIC error shape (errorClass(1 app-tagged enumerated) + errorCode(1 app-tagged
//       enumerated) -- see fError/fBACnetError) ; several confirmed services (AddListElement,
//       CreateObject, WritePropertyMultiple, ConfirmedPrivateTransfer, VTClose,
//       SubscribeCOVPropertyMultiple, AuthRequest) define their OWN richer, service-specific
//       error structure instead of the generic one (packet-bacapp.c's fBACnetError dispatches on
//       error-choice for exactly these 7 services) -- this decoder does not special-case those,
//       so an error response to one of those 7 services is named (error-choice's service name)
//       but its error body is shown as raw hex, not mis-decoded as a generic errorClass/errorCode
//       pair.
//   6 Reject: byte0 = type<<4 | reserved ; original-invoke-id(1) ; reject-reason(1) (a fixed
//       10-entry ASHRAE table -- no further data).
//   7 Abort: byte0 = type<<4 | reserved(2 bits)<<1 | SRV ; original-invoke-id(1) ; abort-
//       reason(1) (a fixed 12-entry ASHRAE table -- no further data).
// SEG/MOR here are the same Segmented-Message/More-Follows bits BACAPP_SEGMENTED_REQUEST (0x08)
// and BACAPP_MORE_SEGMENTS (0x04) -- when SEG is set, this decoder decodes the sequence-
// number/proposed-window-size header fields but does NOT attempt to value-decode that segment's
// own service-request/service-ACK data: a single UDP datagram carries one segment, not the whole
// reassembled service message, and this decoder (like every other UDP-based protocol in this
// codebase) does no cross-packet reassembly -- decoding one segment's raw bytes as if they were a
// complete, self-contained service request would misrepresent partial data as complete. The
// segment's raw bytes are shown as hex only, with a note explaining why.
//
// Service choice tables (packet-bacapp.c's BACnetConfirmedServiceChoice[]/
// BACnetUnconfirmedServiceChoice[], transcribed in full into bacnet.cpp's kBacnetConfirmed
// ServiceChoice/kBacnetUnconfirmedServiceChoice -- 35 and 15 entries respectively) are used to
// NAME every confirmed/unconfirmed service this decoder sees. Value decode of the service-
// request/service-ACK/service-choice DATA, though, is a deliberate "first pass" subset --
// mirroring this codebase's existing "first pass" precedent (EtherNet/IP CIP explicit messaging's
// own service subset, DNP3's group/variation table, S7comm's classic-syntax-only addressing):
//   - Who-Is (unconfirmed 8):  optional context-tag[0] device-instance-range-low-limit(unsigned)
//     + context-tag[1] ...-high-limit(unsigned) -- both present or neither, per spec.
//   - I-Am (unconfirmed 0):  application-tagged ObjectIdentifier (always a device object) +
//     application-tagged Unsigned (Max-APDU-Length-Accepted) + application-tagged Enumerated
//     (Segmentation-Supported, a 4-entry table) + application-tagged Unsigned (Vendor-ID) -- the
//     single richest device-discovery/fingerprinting message on the wire, the BACnet analog of
//     EtherNet/IP's ListIdentity response.
//   - Who-Has (unconfirmed 7):  optional context-tag[0]/[1] device-instance low/high limit
//     (unsigned, same optional-pair rule as Who-Is), then EITHER context-tag[2] ObjectIdentifier
//     OR context-tag[3] ObjectName (CharacterString) -- a CHOICE, exactly one of the two is
//     present.
//   - I-Have (unconfirmed 1):  application-tagged ObjectIdentifier (the device) + application-
//     tagged ObjectIdentifier (the object found) + application-tagged CharacterString (its
//     Object-Name).
//   - ReadProperty request (confirmed 12):  context-tag[0] ObjectIdentifier + context-tag[1]
//     PropertyIdentifier (named via kBacnetPropertyIdentifier's 539-entry table) + optional
//     context-tag[2] PropertyArrayIndex (unsigned).
//   - ReadProperty ACK (confirmed 12's Complex-Ack):  context-tag[0] ObjectIdentifier + context-
//     tag[1] PropertyIdentifier + optional context-tag[2] PropertyArrayIndex + context-tag[3]
//     PropertyValue, opening/closing-tag-wrapped around exactly one application-tagged primitive
//     value in this decoder's "first pass" (see "Property value decode" below for which
//     primitive types, and what happens for anything richer than one scalar).
//   - WriteProperty request (confirmed 15):  same context-tag[0]/[1]/[2] as ReadProperty request,
//     then context-tag[3] PropertyValue (same opening/closing-tag-wrapped single-primitive
//     decode), then optional context-tag[4] Priority (unsigned, 1-16).
//   - Error (any confirmed service's error response):  generic errorClass+errorCode only, per the
//     PDU-type table above.
// Every OTHER confirmed or unconfirmed service (ReadPropertyMultiple/WritePropertyMultiple/
// SubscribeCOV/AtomicReadFile/DeviceCommunicationControl/ReinitializeDevice/ConfirmedEventNotifi
// cation/UnconfirmedCOVNotification/... -- the large majority of the two tables) is named via the
// service-choice table, but its data is shown only as raw hex + byte length, not value-decoded.
// This "first pass" set was chosen because Who-Is/I-Am/Who-Has/I-Have are collectively the single
// most security-relevant BACnet traffic pattern for passive OT monitoring (unauthenticated device
// and object discovery, the BACnet analog of an ARP sweep or a Modbus/S7comm "what devices exist
// here" probe), and ReadProperty/WriteProperty are the most common property-access pattern
// (ReadPropertyMultiple, deliberately NOT decoded here, is more efficient and increasingly common
// in modern deployments but has a materially more complex nested-list wire shape -- named only,
// like every other out-of-scope service, rather than half-decoded).
//
// Property value decode ("first pass"): a PropertyValue's single application-tagged primitive is
// decoded for application tag numbers 0-12 (cross-checked against packet-bacapp.c's
// BACnetApplicationTagNumber[] and its own fBooleanTag/fUnsignedTag/fSignedTag/fRealTag/
// fDoubleTag/fCharacterStringBase/fBitStringTagVSBase/fDate/fTime/fObjectIdentifier): Null,
// Boolean, Unsigned (1-8 bytes, big-endian), Signed (1-8 bytes, two's-complement big-endian),
// Real (4-byte IEEE 754 single), Double (8-byte IEEE 754 double), Octet-String (raw hex),
// Character-String (1-byte character-set-encoding tag + string bytes -- ANSI X3.4/UTF-8 decoded
// as-is; the other five ASHRAE-defined character sets, including IBM/MS DBCS's extra 2-byte code-
// page field, are recognized and their raw bytes shown, but not transcoded), Bit-String (1-byte
// unused-bit count + bitfield, rendered as a T/F string), Enumerated (1-4 bytes, big-endian, same
// encoding as Unsigned), Date, Time, Object-Identifier. Tag number 13-15 (reserved by ASHRAE --
// an application tag this
// decoder's "first pass" primitive table doesn't cover) or a context-specific/constructed value
// inside the PropertyValue wrapper (an array, a list, or a service-specific structured value) is
// shown as "not decoded" plus raw hex, not misrepresented as one of the primitive types above --
// this is the same "decode confidently only where the wire format is unambiguous" philosophy
// already applied throughout this codebase (see enip.hpp's own SCOPING NOTE).
//
// Object type / property identifier / error class / error code tables (kBacnetObjectType,
// kBacnetPropertyIdentifier, kBacnetErrorClass, kBacnetErrorCode in bacnet.cpp) are transcribed in
// full from packet-bacapp.c's own BACnetObjectType[]/BACnetPropertyIdentifier[]/BACnetErrorClass[]
// /BACnetErrorCode[] value_string tables (65/539/8/230 entries respectively) -- unlike the
// service-choice scoping above, there is no reason to truncate these: they are flat, unambiguous
// lookup tables (an enumerated value's meaning does not depend on which service carries it), and
// property-identifier/object-type names in particular are high-value for OT asset inventory from
// passive capture. A value outside every table (or in the explicitly vendor-proprietary /
// ASHRAE-reserved range some of these enumerations define) is rendered "unknown(N)" or "vendor-
// proprietary(N)"/"reserved(N)" as appropriate, never guessed at.
//
// Explicitly out of scope: BACnet/SC (Secure Connect, WebSocket-based, an entirely different
// transport under a different BVLC Type byte -- 0x82, not 0x81); Secure-BVLL (BVLC function
// 0x0C)'s encrypted payload; every network-layer message's own data (named only, see above);
// every APDU service outside the "first pass" list (named only); ReadPropertyMultiple/
// WritePropertyMultiple's nested list-of-results structure specifically (the most notable
// omission from real-world traffic -- see above); cross-packet APDU segmentation reassembly;
// MS/TP, ARCNET, LonTalk, or BACnet/SC MAC address formats appearing inside DADR/SADR (only their
// raw bytes are shown -- this decoder only ever sees BACnet/IP's own Ethernet/IPv4 framing, so a
// non-6-byte DADR/SADR here would only ever appear on NPDU traffic forwarded from a non-IP BACnet
// network by a router, which this decoder has no way to further interpret without that other
// network's own MAC addressing context).
//
// Validation: a real capture WAS found -- tests/real_captures/bacnet/ICS-OT-Network-001-bacnet-
// excerpt.pcap (54 frames, extracted from a larger mixed-OT-protocol capture -- see that
// directory's ATTRIBUTION.md for full provenance and honest scope). It confirms BVLC Original-
// Unicast-NPDU framing, a plain (no DEST/SRC/Network-Layer-Message) NPDU, and 27 Confirmed-
// Request/Complex-ACK ReadProperty request/response pairs against trend-log objects, with
// Unsigned-typed PropertyValue decode, all byte-for-byte correct with zero crashes or unexpected
// fallbacks -- but it is narrow: everything else described above (Who-Is/I-Am/Who-Has/I-Have,
// WriteProperty, Simple-ACK/Error/Reject/Abort/Segment-ACK, every BVLC function besides Original-
// Unicast-NPDU, NPDU DEST/SRC/Network-Layer-Message, every PropertyValue type besides Unsigned,
// and segmentation) is validated only against the hand-built tests/sample_bacnet.pcap fixture
// (tools/make_sample_pcap.py's build_bacnet_sample) cross-checked against Wireshark's dissector
// source rather than an independent real capture -- see that ATTRIBUTION.md's own "Gaps" section
// for the complete, honest list.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// The IANA-registered BACnet/IP UDP port (0xBAC0) -- recorded as an "expected port" annotation
// only, never a detection gate (this decoder's own structural detection gate is port-
// independent -- see bacnet.hpp's file header comment).
constexpr uint16_t BACNET_UDP_PORT = 47808;

// One decoded BACnet APDU -- see bacnet.hpp's file header comment's APDU section for the full
// per-PDU-type byte layout and "first pass" service-value-decode scope.
struct BacnetApdu {
    uint8_t pdu_type = 0;       // 0-7
    std::string pdu_type_name;  // "Confirmed-Request"/"Unconfirmed-Request"/"Simple-ACK"/
                                  // "Complex-ACK"/"Segment-ACK"/"Error"/"Reject"/"Abort"

    // Confirmed-Request / Complex-ACK only.
    bool segmented = false;
    bool more_follows = false;
    bool segmented_response_accepted = false;  // Confirmed-Request only
    uint8_t sequence_number = 0;                // meaningful only when segmented
    uint8_t proposed_window_size = 0;           // meaningful only when segmented

    // Confirmed-Request / Simple-ACK / Complex-ACK / Error / Reject / Abort / Segment-ACK all
    // carry an invoke-id (called "original-invokeID" for the ACK/error-shaped PDU types) --
    // -1 only for the two PDU types that don't have one at all (there are none -- every PDU type
    // this decoder recognizes has an invoke-id field, unlike, say, an unconfirmed request).
    int invoke_id = -1;

    // Set only for Confirmed-Request/Unconfirmed-Request/Simple-ACK/Complex-ACK -- the service
    // this PDU is about (packet-bacapp.c's BACnetConfirmedServiceChoice/
    // BACnetUnconfirmedServiceChoice).
    bool has_service_choice = false;
    uint8_t service_choice = 0;
    std::string service_choice_name;
    bool is_confirmed_service = false;  // which of the two tables service_choice_name came from

    // Segment-ACK only.
    bool negative_ack = false;
    bool server = false;  // also set on Abort (BAC_CONTROL-style "SRV" bit)
    uint8_t actual_window_size = 0;

    // Error / Reject / Abort only.
    bool has_error_class_code = false;  // generic error shape only -- see header comment
    uint32_t error_class = 0;
    std::string error_class_name;
    uint32_t error_code = 0;
    std::string error_code_name;
    uint8_t reject_reason = 0;
    std::string reject_reason_name;
    uint8_t abort_reason = 0;
    std::string abort_reason_name;

    // Decoded field-by-field summary of the "first pass" services' request/ACK data (see header
    // comment) -- each entry one field, e.g. "object=analog-input,3" or "property=present-value" or
    // "value=(Real) 72.500000". Empty when this PDU's service is outside the first-pass set, or
    // when segmented (see header comment's segmentation paragraph).
    std::vector<std::string> values;

    bool data_shown_as_hex = false;  // true when values is empty but there IS trailing data
    std::string data_hex;
    size_t data_length = 0;

    std::string summary;
};

// One decoded BACnet NPDU -- see bacnet.hpp's file header comment's NPDU section.
struct BacnetNpdu {
    uint8_t version = 0;
    uint8_t control = 0;

    bool is_network_layer_message = false;  // Control NET bit
    bool expecting_reply = false;           // Control EXPECT bit
    uint8_t priority = 0;                   // Control PRIORITY 2-bit field, 0-3

    bool has_dest = false;
    uint16_t dnet = 0;
    uint8_t dlen = 0;
    std::string dadr_hex;  // empty when dlen == 0 ("broadcast on destination network")
    bool has_src = false;
    uint16_t snet = 0;
    uint8_t slen = 0;
    std::string sadr_hex;
    uint8_t hop_count = 0;  // meaningful only when has_dest

    // Network Layer Message -- meaningful only when is_network_layer_message. Named only, not
    // value-decoded -- see header comment.
    uint8_t message_type = 0;
    std::string message_type_name;
    bool has_vendor_id = false;  // message_type >= 0x80
    uint16_t vendor_id = 0;

    // The APDU that follows -- present only when !is_network_layer_message.
    bool has_apdu = false;
    BacnetApdu apdu;

    std::string summary;
    std::vector<std::string> notes;
};

// One decoded BACnet/IP (BVLC) message -- see bacnet.hpp's file header comment's BVLC section.
struct BacnetFrame {
    uint8_t bvlc_type = 0;  // always 0x81 when this struct is returned -- see try_parse_bacnet
    uint8_t bvlc_function = 0;
    std::string bvlc_function_name;
    uint16_t bvlc_length = 0;  // the BVLC message's own declared total length (header included)

    // Present only for BVLC functions that carry one (0x04/0x09/0x0A/0x0B -- see header
    // comment).
    bool has_npdu = false;
    BacnetNpdu npdu;

    // Forwarded-NPDU (0x04) only: the originating device's B/IP address, distinct from this
    // packet's own UDP/IP source (a BBMD forwarded this on the originator's behalf).
    bool has_forwarding_source = false;
    std::string forwarding_source_ip;
    uint16_t forwarding_source_port = 0;

    // BVLC-Result (0x00) only.
    bool has_result_code = false;
    uint16_t result_code = 0;

    // Register-Foreign-Device (0x05) only.
    bool has_registration_ttl = false;
    uint16_t registration_ttl_seconds = 0;

    // Write-Broadcast-Distribution-Table (0x01) / Read-Broadcast-Distribution-Table-Ack (0x03) /
    // Read-Foreign-Device-Table-Ack (0x07) only: each entry rendered as one summary string (see
    // bacnet.cpp).
    std::vector<std::string> table_entries;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as one BACnet/IP (BVLC Annex J) message. Returns
// std::nullopt (never throws) when there aren't even 4 bytes for the BVLC header, when Type
// isn't 0x81, or when Function isn't one of the 13 values 0x00-0x0C the spec defines -- see this
// file's header comment's "structural detection gate" paragraph.
std::optional<BacnetFrame> try_parse_bacnet(ByteSpan udp_payload);

// Migration batch 2 (BACnet/IP, Stage 10) -- id()=="bacnet", GateKind::UdpPortIndependent (tried
// opportunistically regardless of port, the same posture EnipUdpDecoder/HartIpUdpDecoder have --
// see either's own comment in enip.hpp/hartip.hpp). Purely stateless and, unlike EtherNet/IP's
// CIP I/O and HART-IP's own UDP path, needs no wrapper result type at all: BacnetFrame already
// carries everything the legacy call site dual-wrote, so decode() is a direct pass-through onto
// try_parse_bacnet, mirroring EnipUdpDecoder's own "no new result type" shape in enip.hpp/
// enip.cpp. The second, simpler UdpPortIndependent use in this batch -- no shared id(), no
// port-exclusion helper, no coalescing loop.
class BacnetDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "bacnet"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& bacnet_decoder();

}  // namespace conduitscope
