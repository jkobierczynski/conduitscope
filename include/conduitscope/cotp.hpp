// SPDX-License-Identifier: MIT
// cotp.hpp - TPKT (RFC 1006) + COTP (ISO 8073 / X.224) framing detection and
// header decoding. This is the transport that S7comm (Siemens S7 PLCs, TCP
// port 102) always rides on, so it's implemented as its own layer rather
// than folded into s7comm.hpp -- COTP Connection Request/Confirm frames
// (session setup, carrying TSAP addressing) don't contain S7comm at all,
// and recognizing them separately from Data frames is itself useful for
// conduit auditing (e.g. seeing which stations establish S7 sessions with
// which PLCs, independent of whether every subsequent Data frame is fully
// decoded).
//
// Reference behavior cross-checked against the Wireshark packet-s7comm.c
// dissector and the Arkime s7comm.c parser (both open source); this is an
// independent implementation, not a port of either.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t COTP_TCP_PORT = 102;  // ISO-TSAP (RFC 1006), what S7comm and COTP/TPKT ride on

enum class CotpPduKind {
    Data,               // DT -- carries the upper-layer (e.g. S7comm) payload
    ConnectionRequest,  // CR -- session setup, carries TSAP parameters
    ConnectionConfirm,  // CC -- session setup response, carries TSAP parameters
    Disconnect,         // DR/DC -- teardown
    Other,              // recognized COTP framing, PDU type not specifically handled
};

struct CotpFrame {
    uint8_t tpkt_version = 0;
    uint16_t tpkt_length = 0;   // as declared in the TPKT header, including the 4-byte header itself
    uint8_t cotp_length_indicator = 0;
    uint8_t cotp_pdu_type_raw = 0;  // full byte, e.g. 0xF0 for DT
    CotpPduKind kind = CotpPduKind::Other;
    std::string pdu_type_name;      // e.g. "Data (DT)", "Connection Request (CR)"

    bool eot = false;  // Data frames only: end-of-TSDU bit (this is the last fragment)

    // Connection Request/Confirm only: raw TSAP parameter bytes, if present
    // (0xC1 = calling TSAP, 0xC2 = called TSAP, per ISO 8073). Shown as hex
    // rather than further interpreted -- the rack/slot encoding Siemens
    // tools embed in these bytes is not decoded in this groundwork release.
    bool has_calling_tsap = false;
    std::string calling_tsap_hex;
    bool has_called_tsap = false;
    std::string called_tsap_hex;

    ByteSpan user_data;  // Data frames only: payload after the COTP header (candidate S7comm data)
    std::string summary;
    std::vector<std::string> notes;
};

// Returns std::nullopt (never throws) if `tcp_payload` does not begin with
// the TPKT signature (version=3, reserved=0) or is too short to plausibly
// hold a TPKT+COTP header, or if the declared TPKT length doesn't fit the
// available payload. Beyond that gate, a structurally invalid COTP header
// (e.g. an implausible length indicator) throws ParseError like the other
// parsers in this project, so the decoder can report it as a per-packet
// warning rather than silently returning something misleading.
std::optional<CotpFrame> try_parse_tpkt_cotp(ByteSpan tcp_payload);

}  // namespace conduitscope
