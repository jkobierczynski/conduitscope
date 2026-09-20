// SPDX-License-Identifier: Apache-2.0
// s7commplus.hpp - S7comm-Plus (Siemens TIA Portal / S7-1200/1500 protocol) decoding.
//
// S7comm-Plus rides inside a COTP Data (DT) frame's user data (see cotp.hpp), the SAME TCP port
// 102 transport classic S7comm (s7comm.hpp/S7COMM_PROTOCOL_ID 0x32) and MMS (mms.hpp) share, but
// it is a wholly different, much newer application protocol -- introduced with the S7-1200/1500
// generation of PLCs and TIA Portal, identified by its own protocol id byte (0x72, see
// S7COMM_PLUS_PROTOCOL_ID in s7comm.hpp) rather than any negotiated presentation-context or
// session type. Unlike classic S7comm's fixed-format ROSCTR/function/parameter/data layout,
// S7comm-Plus is object-oriented on the wire: requests and responses name numeric "IDs" (of
// objects, attributes, or symbol references) and carry self-describing typed values, more
// reminiscent of MMS's own Data CHOICE or OPC UA's Variant than of S7ANY's fixed item layout.
//
// UNLIKE EVERY OTHER PROTOCOL THIS DECODER SUPPORTS, S7comm-Plus has never been officially
// published by Siemens: there is no standards document, no ASN.1 module, no XML/CSV table this
// decoder can generate its tag tables from (contrast MMS's ISO 9506-2 module, or OPC UA's own
// NodeIds.csv/StatusCode.csv). Every byte-layout fact this file asserts is instead sourced from
// the open-source Wireshark plugin `packet-s7comm_plus.c`, written by Thomas Wiens -- the SAME
// author as the classic-S7comm Wireshark dissector this codebase already cross-checks s7comm.hpp
// against, and itself the product of years of public, community reverse-engineering effort (it
// has never been merged into mainline Wireshark, unlike classic S7comm's own packet-s7comm.c --
// confirmed by checking mainline Wireshark's own dissectors/CMakeLists.txt, which lists
// packet-s7comm.c and packet-s7comm_szl_ids.c but no S7comm-Plus file at all). This decoder is an
// independent implementation, not a port of that plugin, but it does not claim any confidence
// beyond what that plugin's own source comments claim -- several of them, preserved in this
// file's own comments, are hedged in the original German ("scheint" = "seems to be", "z.Zt.
// unbekannt" = "currently unknown"), and this decoder passes that same honesty through rather
// than rounding it up to false confidence.
//
// Wire structure, outermost to innermost:
//
//   Header (4 bytes): protocol id (0x72) + PDU type (1 byte: Connect/Data/DataFW1_5/KeepAlive)
//     + [KeepAlive only: a 1-byte sequence number, then 1 reserved byte -- header is 4 bytes even
//       here, just laid out differently] or [everything else: a 2-byte big-endian Data Length,
//       the byte count of the "Data" part that follows, NOT counting this header or the trailer]
//   Data part (Connect/Data/DataFW1_5 only; absent for KeepAlive) -- PDU type Data (0x02) only,
//     see the DataFW1_5 paragraph below for why: opcode-led envelope --
//     opcode (1 byte: Request 0x31 / Response 0x32 / Notification 0x33 / Response2 0x02, the
//       last used only for TIA V13+ HMI cyclic-data telegrams) -- a Notification's own body has a
//       completely different shape (a subscribed-variable change-of-value feed) and is
//       structurally recognized but not decoded by this file, see below;
//     reserved(2) + function code (2 bytes big-endian, see S7CommPlusFunctionCode) + reserved(2)
//       + sequence number (2 bytes big-endian, correlates a request to its response within a
//       session, alongside TCP itself);
//     Request only: session id (4 bytes) + 1 reserved byte, then a function-specific request
//       body; Response/Response2: 1 reserved byte, then a function-specific response body;
//     an Integrity part near the end of most Data/Response bodies (an id plus what is presumed to
//       be a SHA-256-sized digest -- 32 bytes -- of the telegram, surfaced but never verified,
//       same posture this codebase already takes toward DNP3/HART-IP checksums) -- DataFW1_5
//       (firmware >= V1.5) moves this SAME id+32-byte-digest shape to the very FRONT of the Data
//       part instead, with no length-prefix byte this time (see decode_integrity_fw1_5 in
//       s7commplus.cpp for what confirms this against a real device);
//   Trailer (4 bytes): protocol id (0x72) + PDU type + Data Length, mirroring the header -- a
//     COMPLETE S7comm-Plus telegram always ends with one. A telegram can be split across several
//     TPKT/COTP frames (a large CreateObject upload or Explore response, mainly); per the
//     reference plugin's own reassembly state machine, that split is signalled by the ABSENCE of
//     this trailer, NOT by COTP's own End-of-TSDU bit -- i.e. a captured COTP Data frame can be a
//     complete, EOT=1 COTP PDU while still carrying only an incomplete S7comm-Plus telegram (no
//     trailer yet). This decoder's usual COTP-level reassembly (decoder.cpp's
//     reassemble_cotp_data_frame, shared with classic S7comm/MMS, keyed on COTP's own EOT bit) is
//     therefore NOT sufficient by itself for S7comm-Plus, and this file does not additionally
//     implement S7comm-Plus's own above-COTP, trailer-based reassembly (a genuinely separate,
//     TCP-session-keyed state machine in the reference plugin) -- a telegram missing its trailer
//     is reported as such (see S7CommPlusFrame::has_trailer) with whatever of the Data part fits
//     in this frame decoded, rather than guessed at across frames it hasn't seen. See LIMITATIONS
//     in docs/MANUAL.md.
//
// Function-specific bodies this file fully decodes (Tier 1, matching this codebase's usual
// "the dominant real-world operations get full item/value decode" standard -- see e.g. MMS's own
// 11-of-78-services split, or OPC UA's Tier 1/Tier 2 split). This applies equally to PDU type
// Data (0x02) and DataFW1_5 (0x03) -- once DataFW1_5's own relocated Integrity part (see the
// wire-structure section above) is consumed, the rest of its Data part has the identical
// opcode-led body layout, so every function below is decoded the same way regardless of which
// of the two PDU types carried it. In real traffic DataFW1_5 is in fact the dominant one -- a
// genuine S7-1212C driven by a Siemens KTP 400 Basic HMI panel sent essentially none of its
// GetMultiVariables/SetMultiVariables/SetVariable traffic as plain PDU type Data:
//   - GetMultiVariables / SetMultiVariables (0x054c / 0x0542): the actual variable read/write
//     traffic that dominates real S7comm-Plus captures, TIA Portal's functional replacement for
//     classic S7comm's Read Var/Write Var. Item addresses are S7comm-Plus's own native symbolic
//     addressing -- a CRC-like hash of the compiled symbol name plus a chain of "LID" (local id)
//     values identifying struct/array members -- decoded via s7commp_decode_item_address's exact
//     byte layout (see S7CommPlusItemAddress below). This is NOT the same thing as classic
//     S7comm's own EXPERIMENTAL 0xB2 "symbolic" syntax (s7comm.hpp) -- that was an unconfirmed
//     reconstruction of a convention embedded inside a DIFFERENT protocol's item syntax; here the
//     CRC+LID layout IS S7comm-Plus's actual native addressing scheme, and the byte-level decode
//     below is not experimental. What IS an inherent, protocol-level limitation (not a decoding
//     uncertainty) is that a LID's or CRC's SYMBOLIC MEANING -- which tag name it refers to --
//     depends on TIA Portal's own compiled project database, which never appears on the wire;
//     this file decodes and renders the numbers faithfully but cannot resolve them to tag names,
//     the same "can't resolve an opaque identifier without out-of-band context" limitation this
//     codebase already accepts for DNP3/IEC104 point indices or OPC UA NodeIds.
//   - SetVariable (0x04f2) and DeleteObject (0x04d4): simple enough (a bare object id, or an id
//     plus one self-describing value) to fully decode both directions.
//   - The self-describing "Value" encoding used throughout (S7CommPlusValue below): a 1-byte
//     datatype-flags/array-kind byte, a 1-byte datatype code, an optional varuint32 array size
//     (or, for a "sparse array", a null-terminated key/value sequence with no upfront count), and
//     then that many typed values -- fixed-width for BOOL/USINT/UINT/SINT/INT/BYTE/WORD/DWORD/
//     LWORD/REAL/LREAL/TIMESTAMP/RID, and a Variable-Length-Quantity ("varuint"/"varint", see
//     below) encoding for UDINT/ULINT/DINT/LINT/TIMESPAN/AID/VARIANT -- every datatype the
//     reference plugin's own switch statement recognizes is decoded here too, INCLUDING nested
//     STRUCT values (recursed, with the same kind of depth cap MMS's own Data-value decoder
//     already uses, for the same reason: an attacker-controlled or corrupt capture must not be
//     able to blow the C++ call stack). S7STRING (datatype 0x19) is the one datatype the
//     reference plugin's own generic value switch does NOT implement (its comment says it is
//     "only for tag-description", a separate, far more complex function this file does not
//     implement -- see "Deliberately not implemented" below) -- shown here as an unrecognized
//     datatype, honestly, rather than guessed at.
//   - The ReturnValue status code every Response/Response2 body starts with: a packed varuint64
//     whose low 16 bits are a signed error code (S7CommPlusErrorCode) -- this file decodes that
//     low 16-bit field with confidence (it is what every response's success/failure hinges on)
//     and surfaces the rest of the 64-bit value as a raw hex note rather than asserting
//     bit-for-bit meaning for OMS-line/error-source/debug-info sub-fields the reference plugin
//     itself only comments on informally.
//
// Function-specific bodies this file recognizes (function code named, session id/sequence number
// decoded, Integrity/Trailer still decoded) but does NOT decode the body of -- shown as raw hex,
// consistent with this codebase's own "named but not decoded" convention for MMS's other 67
// services or OPC UA's Tier 2 services:
//   - CreateObject (0x04ca): the request/response body is a full, deeply nested TIA Portal block
//     definition (an "Object", itself a recursive Attribute/Relation/sub-Object tree keyed by
//     0xA1/0xA2/0xA3/0xA4 element-id bytes) -- genuinely the single most complex shape in this
//     protocol; not attempted here.
//   - Explore (0x04bb), GetLink (0x0524), BeginSequence/EndSequence (0x0556/0x0560), Invoke
//     (0x056b), GetVarSubStreamed (0x0586): each has its own bespoke body shape (Explore's in
//     particular branches per a "class" byte -- IQMCT/UDT/DB/FB/FC/OB/FBT/LIB, each with its own
//     further sub-layout) that this file does not implement.
//   - Notification (opcode 0x33): S7comm-Plus's own cyclic/subscribed variable-change-of-value
//     feed -- a materially different body shape from the Request/Response envelope above (no
//     function code, no session id; a value list keyed by subscription-relative item number
//     instead of the CRC+LID addressing above). Recognized (opcode named) but not decoded.
//   - Connect (PDU type 0x01): the session-establishment handshake, including (per real-world
//     research, not this file's own decode) a random-nonce/session-id exchange used as the basis
//     for later per-message integrity, and, on TIA Portal V13+/firmware-encrypted sessions, a
//     Diffie-Hellman-style key exchange this decoder makes no attempt to parse. Recognized (PDU
//     type named) but not decoded.
//
// Variable-Length Quantity ("varuint"/"varint") encoding: NOT the same bit layout as MQTT's own
// Remaining Length VLQ (mqtt.hpp) -- this one is big-endian/MSB-first (matches the general VLQ
// scheme at https://en.wikipedia.org/wiki/Variable-length_quantity, and the reference plugin's
// own file comment cites exactly that page): each byte contributes its low 7 bits, most
// significant group first, with the top bit (0x80) of every byte except the last set to 1 to
// signal "more bytes follow". varuint32/varint32 top out at 5 bytes (4*7 + 4 leftover bits);
// varuint64/varint64 top out at 9 bytes, where -- per the reference plugin -- the 9th byte (only
// read if the first 8 still had their continuation bit set) contributes a full 8 bits rather than
// 7. The signed forms (varint32/varint64) treat bit 0x40 of the FIRST byte as a sign flag and
// pre-load the accumulator with sign-extended 1s when set, matching two's-complement semantics
// for a value that never grows past its shortest encoding.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// PDU types (the header's second byte).
constexpr uint8_t S7COMMP_PDUTYPE_CONNECT = 0x01;
constexpr uint8_t S7COMMP_PDUTYPE_DATA = 0x02;
constexpr uint8_t S7COMMP_PDUTYPE_DATAFW1_5 = 0x03;
constexpr uint8_t S7COMMP_PDUTYPE_KEEPALIVE = 0xff;

// Opcodes (the Data part's first byte).
constexpr uint8_t S7COMMP_OPCODE_REQUEST = 0x31;
constexpr uint8_t S7COMMP_OPCODE_RESPONSE = 0x32;
constexpr uint8_t S7COMMP_OPCODE_NOTIFICATION = 0x33;
constexpr uint8_t S7COMMP_OPCODE_RESPONSE2 = 0x02;

// Function codes (2 bytes big-endian, present for every non-Notification Data part).
constexpr uint16_t S7COMMP_FUNCTIONCODE_EXPLORE = 0x04bb;
constexpr uint16_t S7COMMP_FUNCTIONCODE_CREATEOBJECT = 0x04ca;
constexpr uint16_t S7COMMP_FUNCTIONCODE_DELETEOBJECT = 0x04d4;
constexpr uint16_t S7COMMP_FUNCTIONCODE_SETVARIABLE = 0x04f2;
constexpr uint16_t S7COMMP_FUNCTIONCODE_GETLINK = 0x0524;
constexpr uint16_t S7COMMP_FUNCTIONCODE_SETMULTIVAR = 0x0542;
constexpr uint16_t S7COMMP_FUNCTIONCODE_GETMULTIVAR = 0x054c;
constexpr uint16_t S7COMMP_FUNCTIONCODE_BEGINSEQUENCE = 0x0556;
constexpr uint16_t S7COMMP_FUNCTIONCODE_ENDSEQUENCE = 0x0560;
constexpr uint16_t S7COMMP_FUNCTIONCODE_INVOKE = 0x056b;
constexpr uint16_t S7COMMP_FUNCTIONCODE_GETVARSUBSTR = 0x0586;

// One S7comm-Plus native item address (see the file header's "GetMultiVariables /
// SetMultiVariables" section for what is and isn't resolvable about it).
struct S7CommPlusItemAddress {
    uint32_t crc_or_rid = 0;      // first varuint32 field: a symbol-name CRC when != 0, else...
    bool is_object_id_style = false;  // ...true when crc_or_rid == 0: the address is object-ID-
                                        // based (area/base_area/LIDs below are then all just an
                                        // "IDs" list instead -- rendered accordingly).
    bool area_recognized = false;      // true when the area value matched a known IQMCT/DB shape
    std::string area_name;             // e.g. "Flags (M)", "Datablock (DB)", or "" if unrecognized
    uint16_t db_number = 0;            // meaningful only when area_name is the DB case
    uint32_t lid_nesting_depth = 0;
    uint32_t base_area = 0;
    std::vector<uint32_t> extra_lids;  // (lid_nesting_depth - 1) further LID values, one per
                                         // nesting level beyond the first -- struct/array member
                                         // chains, e.g. DB10.STRUCT.VAR
    std::string tag;                    // rendered summary, e.g. "SYM-CRC=1a2b3c4d LID=DB10.2.5"
                                         // or "RID=1234, ID=99, ID=5" -- see s7commplus.cpp
};

// One self-describing "Value" (see the file header's own section on this encoding). A STRUCT
// value's members are NOT modeled as a tree here (unlike, say, MMS's recursive BerTlv) -- they
// are flattened into `rendered`, matching this codebase's established "everything ends up as one
// short rendered string per value" convention (see MMS's own decode_data_value in mms.cpp),
// simply because every consumer of this decoder's output (DecodedPacket::s7plus_value_summaries,
// text/JSON/CSV writers) already expects flat per-item strings, not nested structures.
struct S7CommPlusValue {
    bool datatype_recognized = false;
    uint8_t datatype = 0;
    std::string datatype_name;   // e.g. "Int", "DInt", "Struct", or "Unknown (0xNN)"
    bool is_array = false, is_address_array = false, is_sparsearray = false;
    uint32_t array_size = 1;     // 1 for a scalar value; element count for array/address-array;
                                   // number of elements actually found for a sparsearray (no
                                   // upfront count on the wire -- terminated by a null key)
    std::string rendered;         // one-line summary of the whole value, e.g. "(Int) = 42" or
                                   // "(DInt) Array[3] = [1, 2, 3]" or, for a Struct,
                                   // "(Struct) { id=1: (Int) = 5, id=2: (Bool) = 0x01 }"
};

// One {id, value} pair from an id-value-list or itemnumber-value-list (GetMultiVariables'
// response, SetMultiVariables'/SetVariable's request, CreateObject's attribute list, ...).
struct S7CommPlusIdValue {
    uint32_t id = 0;              // an "ID number" (id-value-list) or an "item number"
                                    // (itemnumber-value-list) -- both are plain varuint32s on the
                                    // wire and share the same {id, value} shape, so this file
                                    // doesn't model them as separate types.
    S7CommPlusValue value;
    std::string rendered;          // "id=<id>: <value.rendered>"
};

// One {item number, return value} pair from an itemnumber-errorvalue-list (per-item status in a
// GetMultiVariables/SetMultiVariables response).
struct S7CommPlusItemError {
    uint32_t item_number = 0;
    int16_t error_code = 0;
    std::string error_code_name;
    std::string rendered;  // "item=<n>: <error_code_name> (<error_code>)"
};

struct S7CommPlusFrame {
    // Header, always populated.
    uint8_t pdu_type = 0;
    std::string pdu_type_name;  // "Connect", "Data", "DataFW1_5", "Keep Alive", or "Unknown (0xNN)"
    bool is_fw1_5 = false;      // pdu_type == S7COMMP_PDUTYPE_DATAFW1_5

    bool is_keepalive = false;
    uint8_t keepalive_seq = 0;  // only set when is_keepalive

    // Data part (Connect/Data/DataFW1_5 only -- absent for Keep Alive).
    bool has_data_part = false;
    bool is_notification = false;  // opcode == Notification -- has_function/session/etc. below
                                     // are all left unset in this case; see file header.
    uint8_t opcode = 0;
    std::string opcode_name;  // "Request", "Response", "Notification", "Response2"

    bool has_function = false;
    uint16_t function_code = 0;
    std::string function_name;  // e.g. "GetMultiVariables", or "Unknown (0xNNNN)"

    bool has_sequence_number = false;
    uint16_t sequence_number = 0;

    bool has_session_id = false;  // Request only
    uint32_t session_id = 0;

    // True only for the Tier-1 functions this file fully decodes (see file header) AND when that
    // decode actually ran to completion without falling back early.
    bool body_decoded = false;

    bool has_return_value = false;  // Response/Response2 bodies that carry a ReturnValue
    int16_t return_code = 0;
    std::string return_code_name;

    std::vector<S7CommPlusItemAddress> item_addresses;  // GetMultiVariables/SetMultiVariables
                                                           // request address list
    std::vector<S7CommPlusIdValue> id_values;             // decoded {id, value} pairs -- response
                                                           // values, or values being written
    std::vector<S7CommPlusItemError> item_errors;         // per-item status list

    bool has_integrity = false;
    bool integrity_digest_present = false;  // false for the DataFW1_5 id-only shape
    uint8_t integrity_digest_length = 0;    // expected 32; surfaced, digest bytes never verified

    bool has_trailer = false;

    std::string summary;
    std::vector<std::string> notes;
};

std::string s7commplus_pdu_type_name(uint8_t pdu_type);
std::string s7commplus_opcode_name(uint8_t opcode);
std::string s7commplus_function_name(uint16_t function_code);
std::string s7commplus_error_code_name(int16_t error_code);
std::string s7commplus_datatype_name(uint8_t datatype);

// Attempts to interpret `cotp_user_data` (the payload of a COTP Data frame, already reassembled
// across COTP's own EOT-delimited fragments by decoder.cpp's usual per-flow logic -- see the
// file header above for why that is NOT always the same as one complete S7comm-Plus telegram) as
// an S7comm-Plus telegram. Returns std::nullopt (never throws) if the payload is empty or its first
// byte isn't S7COMM_PLUS_PROTOCOL_ID (0x72, defined in s7comm.hpp) -- the standard signal that
// this COTP Data frame is carrying something other than S7comm-Plus. Once the protocol id is
// confirmed, a header or Data part that's too short to hold its fixed fields throws ParseError
// rather than silently returning a partial result; a Tier-2 (named-but-not-decoded) function's
// body is simply left undecoded rather than treated as an error.
std::optional<S7CommPlusFrame> try_parse_s7comm_plus(ByteSpan cotp_user_data);

}  // namespace conduitscope
