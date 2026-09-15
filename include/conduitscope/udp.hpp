// SPDX-License-Identifier: MIT
// udp.hpp - minimal UDP header parsing.
//
// This is deliberately the same narrow scope as tcp.hpp: it reads one UDP
// datagram's header and payload as it appears in a single packet. UDP has no
// notion of a stream to reassemble (each datagram is already a complete,
// self-delimited unit -- there is nothing analogous to TCP's segment
// reassembly needed here), so unlike tcp.hpp there is no decoder.cpp-level
// reassembly layered on top of this file.
//
// Groundwork scope: this file recognizes and exposes the UDP header/payload
// split only -- it does not decode any application-layer protocol riding on
// top (e.g. EtherNet/IP's implicit I/O messaging on port 2222). See
// docs/MANUAL.md's ROADMAP for why: that's real follow-on work, not
// groundwork plumbing.
#pragma once

#include <cstdint>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

struct UdpDatagram {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint16_t declared_length = 0;  // the header's own length field: whole datagram, header + payload
    ByteSpan payload;
};

// Throws ParseError if `segment` is shorter than the fixed 8-byte UDP header.
//
// `payload` is clamped to the header's own declared_length field whenever that field is
// trustworthy (>= 8, i.e. at least the header itself, and the payload it implies fits inside
// what was actually captured) -- the same clamp-or-fall-back-to-captured-bytes approach
// parse_ipv4 already uses for IPv4's total_length, for the same reason (a 0 or implausible
// length is most often NIC checksum/segmentation offload leaving the field unfilled on an
// outbound packet, not a real empty datagram).
UdpDatagram parse_udp(ByteSpan segment);

}  // namespace conduitscope
