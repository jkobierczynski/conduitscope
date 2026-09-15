// SPDX-License-Identifier: MIT
// enip.hpp - EtherNet/IP encapsulation protocol + CIP (Common Industrial
// Protocol) explicit messaging decoding, TCP port 44818.
//
// EtherNet/IP wraps every message (session management, and CIP itself) in a
// fixed 24-byte encapsulation header: Command (u16), Length (u16, byte count
// of what follows), Session Handle (u32), Status (u32), Sender Context (8
// opaque bytes, echoed verbatim by the target), Options (u32, reserved,
// always 0). Everything on the wire is little-endian -- the one documented
// exception is the embedded "socket address" structure inside a List
// Identity response or a Sockaddr Info CPF item, which uses network
// (big-endian) byte order for its port/address fields, same as a raw BSD
// sockaddr_in; see decode below.
//
// This groundwork release decodes:
//   - every standard encapsulation command by name EXCEPT NOP (ListServices,
//     ListIdentity, ListInterfaces, RegisterSession, UnRegisterSession,
//     SendRRData, SendUnitData, IndicateStatus, Cancel) and the
//     encapsulation-level status code. NOP (command 0x0000) is deliberately
//     not recognized at all -- see enip_command_name's own comment in
//     enip.cpp for why: it is real-capture-confirmed to be too weak a
//     signal (all-zero bytes) to detect safely, and carries essentially no
//     real-world value to detect anyway;
//   - a ListIdentity response's identity item (vendor ID, device type,
//     product code, revision, status, serial number, product name) --
//     valuable for OT asset inventory/fingerprinting from passive capture;
//   - SendRRData (unconnected explicit messaging) and SendUnitData
//     (connected explicit messaging)'s Common Packet Format (CPF) item
//     list, locating the Unconnected Data Item (0x00B2) / Connected Data
//     Item (0x00B1) that carries the actual CIP message; a Connected
//     Address Item (0x00A1)'s 4-byte connection ID is recorded, other CPF
//     item types are named but not further decoded;
//   - the CIP explicit message itself: service code, request path (EPATH:
//     class/instance/attribute logical segments, and the ANSI Extended
//     Symbol segment (0x91) Rockwell Logix5000 controllers use for named-
//     tag addressing), and, for a "first pass" set of services, the
//     request/response data -- see decode_cip_message's header comment in
//     enip.cpp for exactly which services get full value decoding versus
//     being structurally located and named only. Multiple_Service_Packet
//     (0x0A) and Unconnected_Send (0x52, directed at the Connection
//     Manager object) both recurse into their embedded CIP message(s)
//     using this same decoder.
//
// SCOPING NOTE found from real-capture research (see
// tests/real_captures/enip/ATTRIBUTION.md): CIP service codes above 0x32
// are class-specific, not globally reserved -- a real device is free to
// reuse, say, 0x4C for something other than the Rockwell Symbol object's
// "Read Tag Service" if the request path doesn't address the Symbol
// object. This decoder only applies the well-documented Logix5000 named-
// tag (Read Tag / Write Tag / Read Tag Fragmented / Write Tag Fragmented /
// Read Modify Write Tag) semantics when the request path's FIRST segment
// is an ANSI Extended Symbol segment (CipPath::is_symbolic) -- a class/
// instance-addressed request using one of those same service codes is
// shown structurally (service name + path + raw hex), not misdecoded as a
// tag operation. This mirrors s7comm.hpp's EXPERIMENTAL-marking of the
// less-certain S7-1200/1500 symbolic addressing syntax and dnp3.hpp/
// iec104.hpp's "named but not value-decoded outside the known table"
// pattern -- the same "decode confidently only where the wire format is
// unambiguous" philosophy applied throughout this codebase.
//
// No cross-frame reassembly beyond ordinary TCP segment reassembly
// (enip_declared_length, used the same way as modbus_tcp_declared_length/
// iec104_apdu_declared_length/dnp3_link_frame_declared_length/
// tpkt_declared_length -- see Decoder::reassemble_tcp_payload) is needed:
// one encapsulation message is one complete, self-delimited unit on the
// wire (Length says exactly how many bytes follow the header). Multiple
// encapsulation messages coalesced by the sender/OS into one TCP payload
// are handled the same way Decoder already handles that for IEC 104/DNP3 --
// see decoder.cpp's coalescing loop.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t ENIP_TCP_PORT = 44818;

// One CIP explicit-message request path, decoded generically into a
// human-readable summary plus the class/instance/attribute logical-segment
// values when present (used to recognize the well-known objects/services
// below -- e.g. Identity object Get_Attributes_All, or a Connection
// Manager-directed Unconnected_Send).
struct CipPath {
    std::string summary;  // e.g. "Class=0x01 (Identity) Instance=1" or "MyTag.Member[3]"
    // True when the FIRST path segment is an ANSI Extended Symbol segment (0x91) -- the
    // Rockwell Logix5000 "named tag" addressing convention (see the file header comment's
    // scoping note). False for class/instance/attribute-addressed (or empty/unrecognized) paths.
    bool is_symbolic = false;
    std::optional<uint32_t> class_id;
    std::optional<uint32_t> instance_id;
    std::optional<uint32_t> attribute_id;
};

// One decoded CIP explicit message -- a request (client->server) or a response
// (server->client), told apart by the service byte's top bit (0x80), found inside an
// Unconnected Data Item (SendRRData) or Connected Data Item (SendUnitData), or recursively
// inside a Multiple_Service_Packet/Unconnected_Send envelope.
struct CipMessage {
    bool decoded = false;  // false only when there weren't even enough bytes for a service byte
    bool is_response = false;
    uint8_t service = 0;  // as seen on the wire -- for a response this includes the 0x80 reply bit
    std::string service_name;

    CipPath path;  // request only; default-constructed (empty) for a response

    // Response only.
    uint8_t general_status = 0;
    std::string status_name;
    uint8_t additional_status_words = 0;

    // True once this message's service-specific payload (beyond the common service+path or
    // service+status header) was decoded into `values` -- see decode_cip_message in enip.cpp for
    // exactly which services this applies to. False for a request/response whose service is
    // recognized by name but whose payload is shown as structural-only (raw hex in `notes`).
    bool data_decoded = false;
    std::vector<std::string> values;  // e.g. one decoded Read Tag element per entry, or one
                                       // embedded Multiple Service Packet member's own summary
    std::string note;                 // set when this message could not be (fully) decoded
    std::vector<std::string> notes;
    std::string summary;
};

// The 24-byte encapsulation header, common to every EtherNet/IP message.
struct EnipHeader {
    uint16_t command = 0;
    std::string command_name;
    uint16_t length = 0;  // declared byte count of the encapsulated data that follows
    uint32_t session_handle = 0;
    uint32_t status = 0;
    std::string status_name;
    uint64_t sender_context = 0;  // opaque 8 bytes, echoed verbatim by the target; rendered as hex
    uint32_t options = 0;         // reserved, spec-mandated 0 -- see try_parse_enip_header
};

struct EnipFrame {
    EnipHeader header;
    size_t wire_length = 0;  // 24 + header.length -- the total on-the-wire byte count of this one
                              // encapsulation message, for coalescing further messages found in
                              // the same TCP payload (see decoder.cpp)
    bool has_cip = false;    // true once a CIP message was located and decoded (SendRRData/SendUnitData)
    CipMessage cip;
    // Only set for SendUnitData: the Connected Address Item's 4-byte connection ID.
    std::optional<uint32_t> connection_id;
    // Only set for a ListIdentity response whose identity item was decoded.
    bool has_identity = false;
    uint16_t identity_vendor_id = 0;
    uint16_t identity_device_type = 0;
    uint16_t identity_product_code = 0;
    std::string identity_revision;    // "major.minor"
    uint16_t identity_status = 0;
    uint32_t identity_serial_number = 0;
    std::string identity_product_name;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns the total on-the-wire byte count an EtherNet/IP encapsulation message declares (the
// 24-byte header plus `length` more bytes), once there are enough bytes to read the 4-byte
// command+length prefix and `command` is one of the standard encapsulation commands -- the same
// role modbus_tcp_declared_length/iec104_apdu_declared_length play for their own protocols. See
// Decoder::reassemble_tcp_payload.
std::optional<size_t> enip_declared_length(ByteSpan payload);

// Attempts to interpret `tcp_payload` as one EtherNet/IP encapsulation message (header, plus,
// for SendRRData/SendUnitData, its Common Packet Format items and CIP explicit message; for
// ListIdentity, its identity item). Returns std::nullopt (never throws) when the payload is too
// short, `command` is not one of the nine standard encapsulation commands this decoder
// recognizes (deliberately excluding NOP -- see enip_command_name's comment in enip.cpp),
// `options` is nonzero
// (reserved, spec-mandated 0 -- see the struct comment above), or `status` is not 0 or one of the
// documented encapsulation error codes -- together a much stronger structural signal than any
// single field alone (same "several independently-fixed fields" philosophy as
// try_parse_iec104_apci; see that function's header comment in iec104.hpp), which combined with
// this protocol's own dedicated TCP port (44818, no overlap with the other four protocols this
// tool decodes) makes a false-positive collision with Modbus/DNP3/IEC104/S7comm/COTP
// astronomically unlikely -- no evidence of one has been found in any real or synthetic capture
// used to build or test this decoder.
std::optional<EnipFrame> try_parse_enip(ByteSpan tcp_payload);

}  // namespace conduitscope
