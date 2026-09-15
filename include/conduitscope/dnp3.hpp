// SPDX-License-Identifier: MIT
// dnp3.hpp - DNP3 data link layer detection and header parsing (stub).
//
// DNP3 is considerably more layered than Modbus (data link -> transport ->
// application, with per-16-byte-block CRCs and object-group/variation-based
// application data), and this groundwork release intentionally does not
// decode past the data link header. What it DOES give you: reliable
// detection of DNP3 traffic (by port 20000 and/or the 0x05 0x64 start
// bytes), the data link header fields (source/destination DNP3 addresses,
// frame length, control byte), and a clear "not decoded yet" marker rather
// than silently misreporting application-layer content. See docs/MANUAL.md
// Roadmap -- this is the natural next protocol to flesh out once you have
// hands-on DNP3 experience (the primer/spec reading path covers exactly
// what's needed to extend this file).
#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t DNP3_TCP_PORT = 20000;

struct Dnp3LinkFrame {
    uint8_t length_field = 0;    // raw on-the-wire length byte (control+dest+src+user data, no CRCs)
    uint8_t control = 0;
    uint16_t destination = 0;
    uint16_t source = 0;
    size_t user_data_bytes = 0;  // length_field - 5 (control+dest+src), i.e. transport+application layer size
    std::string summary;
    bool crc_validated = false;  // always false in this release -- see notes below
};

// Returns std::nullopt (never throws) if `tcp_payload` does not start with the
// DNP3 data link start bytes (0x05 0x64) or is too short to hold a full data
// link header. Does NOT validate the header CRC -- that is not implemented in
// this groundwork release, and the summary/notes say so explicitly rather
// than silently skipping the check.
std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload);

}  // namespace conduitscope
