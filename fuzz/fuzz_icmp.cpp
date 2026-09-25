// SPDX-License-Identifier: Apache-2.0
// fuzz_icmp.cpp - libFuzzer harness for ICMP(v4) parsing (icmp.hpp: RFC 792, plus RFC 1191/1256
// extensions). ICMP has no transport-layer header of its own -- it rides directly on IP protocol
// number 1 (GateKind::IpProtocol), so this harness is handed the IP payload directly, exactly the
// shape try_parse_icmp already takes. Unlike the TCP-payload protocols the first two waves of
// harnesses cover, none of these eight GateKind::IpProtocol decoders (icmp/icmpv6/igmp/igrp/ospf/
// pim/vrrp/eigrp) sit behind TCP/UDP reassembly at all, so a dedicated harness here skips even more
// unrelated framing than fuzz_dnp3/fuzz_mqtt already do relative to fuzz_packet_decode.
//
// Worth fuzzing on its own merits: icmp.cpp re-parses an attacker-controlled EMBEDDED datagram
// (the quoted original IP header + first bytes of transport payload RFC 792 guarantees Destination
// Unreachable/Redirect/Time Exceeded/Parameter Problem messages carry) by calling parse_ipv4
// (ipv4.hpp) directly against those quoted bytes -- a second, nested length-field-driven parse
// inside the outer one, and exactly the kind of "parser calling a parser on attacker bytes" shape
// most likely to have an off-by-one this codebase's own unit tests wouldn't stumble on. It also
// verifies (not just surfaces) the ICMP checksum, a flat 16-bit one's-complement sum.
//
// Calls try_parse_icmp directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer/
// try_parse_mqtt_message in the other harnesses. Does not cover IcmpDecoder::decode's own thin
// ProtocolDecoder wrapper (trivial, ctx-independent -- see icmp.hpp) or how decoder.cpp's IPv4
// branch disambiguates ICMP from other IP protocol numbers before ever reaching this parser --
// that dispatch-level behavior is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/icmp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_icmp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
