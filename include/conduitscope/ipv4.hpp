// SPDX-License-Identifier: MIT
// ipv4.hpp - minimal IPv4 header parsing.
//
// Groundwork scope: IPv4 only. IPv6 is out of scope for this first pass since
// Modbus/DNP3 deployments overwhelmingly run on IPv4 today; see docs/MANUAL.md
// Roadmap for adding it later without disturbing this interface.
#pragma once

#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t IPPROTO_TCP_VALUE = 6;

struct Ipv4Header {
    uint8_t version = 0;
    uint8_t ihl_words = 0;      // header length in 32-bit words, as encoded on the wire
    uint8_t protocol = 0;       // IANA protocol number (6 = TCP)
    uint16_t total_length = 0;
    uint8_t ttl = 0;
    uint32_t src_addr = 0;      // host-order (i.e. already assembled MSB-first)
    uint32_t dst_addr = 0;
    ByteSpan payload;           // clamped to total_length - header size; see trailing_bytes_trimmed

    // Bytes present in the captured frame after the end of this IPv4 datagram
    // (as declared by total_length) that were NOT included in `payload`. On an
    // Ethernet link this is almost always minimum-frame-size padding: frames
    // shorter than 60 bytes get zero-padded by the NIC/driver, and that padding
    // sits right after the IP datagram in the capture. Without this clamp, a
    // short packet's trailing pad bytes get misread as extra TCP payload --
    // most visibly on bare ACKs, which then falsely look like they carry data.
    size_t trailing_bytes_trimmed = 0;
};

// Throws ParseError if `packet` is too short, is not IPv4 (version != 4), or
// declares a header length longer than the buffer actually holds.
//
// `payload` is clamped to the IP header's own total_length field whenever
// that field is trustworthy (header_size <= total_length <= captured bytes
// available). It falls back to "everything captured after the header" when
// total_length is 0 or otherwise implausible (some NIC checksum/segmentation
// offload setups leave it as 0 on outbound packets) or when the capture was
// truncated shorter than the datagram claims to be -- in both cases, using
// total_length would either be meaningless or would hide real captured bytes.
Ipv4Header parse_ipv4(ByteSpan packet);

std::string format_ipv4(uint32_t addr);

}  // namespace conduitscope
