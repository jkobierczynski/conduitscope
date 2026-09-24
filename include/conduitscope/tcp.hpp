// SPDX-License-Identifier: Apache-2.0
// tcp.hpp - minimal TCP header parsing.
//
// This file itself just reads one TCP segment's header and payload as they
// appear in a single packet -- it has no notion of a flow or session. Every
// layer built on top of that single-segment view (a PDU/frame's own bytes
// split across TCP segments, Modbus request/response pairing, DNP3
// application-fragment reassembly, S7comm message chaining across TPKT/COTP
// frames) lives entirely in decoder.cpp, not here -- see docs/MANUAL.md's
// PROTOCOL DETECTION/PROTOCOL COVERAGE/LIMITATIONS sections for what each of
// those does and doesn't cover.
#pragma once

#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t TCP_FLAG_FIN = 0x01;
constexpr uint8_t TCP_FLAG_SYN = 0x02;
constexpr uint8_t TCP_FLAG_RST = 0x04;
constexpr uint8_t TCP_FLAG_PSH = 0x08;
constexpr uint8_t TCP_FLAG_ACK = 0x10;
constexpr uint8_t TCP_FLAG_URG = 0x20;

struct TcpSegment {
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    uint32_t seq = 0;
    uint32_t ack = 0;
    uint8_t flags = 0;
    uint16_t window = 0;
    // Urgent Pointer (RFC 793) -- always read off the wire regardless of whether TCP_FLAG_URG is
    // set (the field is present in every TCP header, meaningful only when URG is set per RFC 793,
    // but some crafted/attack traffic sets a non-zero value here without also setting URG, or
    // vice versa; see attack_detect.hpp's WinNuke detector, the first real user of this field --
    // the historical WinNuke exploit sent Out-Of-Band data with an urgent pointer Windows 95/NT's
    // TCP/IP stack handled incorrectly).
    uint16_t urgent_pointer = 0;
    ByteSpan payload;
};

// Throws ParseError if `segment` is too short or declares a data offset
// longer than the buffer actually holds.
TcpSegment parse_tcp(ByteSpan segment);

// Renders flags as e.g. "SYN,ACK" for human-readable output.
std::string format_tcp_flags(uint8_t flags);

}  // namespace conduitscope
