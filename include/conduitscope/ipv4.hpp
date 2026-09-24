// SPDX-License-Identifier: Apache-2.0
// ipv4.hpp - minimal IPv4 header parsing.
//
// Groundwork scope: IPv4 only. IPv6 is out of scope for this first pass since
// Modbus/DNP3 deployments overwhelmingly run on IPv4 today; see docs/MANUAL.md
// Roadmap for adding it later without disturbing this interface.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t IPPROTO_TCP_VALUE = 6;
constexpr uint8_t IPPROTO_UDP_VALUE = 17;

// A small set of other IANA IP protocol numbers worth naming when reporting a non-TCP/non-UDP
// IPv4 payload (protocol "non-tcp") -- these numbers have been stable IANA assignments for
// decades, not something that needed cross-checking against a live source the way a less
// universally fixed value (an EtherType, a CIP service code) would. Returns an empty string for
// anything else.
std::string ip_protocol_name(uint8_t protocol);

struct Ipv4Header {
    uint8_t version = 0;
    uint8_t ihl_words = 0;      // header length in 32-bit words, as encoded on the wire
    uint8_t protocol = 0;       // IANA protocol number (6 = TCP)
    uint16_t total_length = 0;
    uint8_t ttl = 0;
    uint32_t src_addr = 0;      // host-order (i.e. already assembled MSB-first)
    uint32_t dst_addr = 0;

    // Fragmentation fields (RFC 791 section 3.1) -- read but not acted on before
    // attack_detect.hpp's addition (see this repo's own prior comment here: "fragment reassembly
    // is a documented limitation", now narrowly addressed just enough for Teardrop/Ping-of-Death
    // detection, still well short of a full reassembly engine -- see attack_detect.hpp's own file
    // header for the honest scope statement on what this codebase does and does not do with
    // these).
    uint16_t identification = 0;    // Identification field -- correlates fragments of one datagram
    bool flag_df = false;           // Don't Fragment
    bool flag_mf = false;           // More Fragments (false on the last fragment of a fragmented
                                       // datagram, and on a datagram that was never fragmented)
    uint16_t fragment_offset = 0;   // in 8-byte units, exactly as encoded on the wire (13 bits) --
                                       // multiply by 8 for a byte offset into the reassembled
                                       // datagram

    // Raw IP option bytes (kind+length+data, RFC 791 section 3.1), present only when ihl_words > 5
    // -- empty otherwise. Not individually parsed/named here; see
    // ipv4_has_source_route_option() (attack_detect.hpp's one caller so far) for the one option
    // this codebase currently looks for.
    std::vector<uint8_t> options;

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

// The inverse of format_ipv4: parses a strict dotted-quad string ("a.b.c.d",
// each octet 0-255, no leading zeros, no surrounding whitespace, exactly 4
// parts) into a host-order uint32_t. Returns std::nullopt (never throws) for
// anything else -- used by policy.cpp/policy_engine.cpp (see policy.hpp) to
// compare a decoded packet's src_ip/dst_ip strings and a policy file's CIDR
// text against each other as addresses, not strings.
std::optional<uint32_t> parse_ipv4_string(const std::string& text);

}  // namespace conduitscope
