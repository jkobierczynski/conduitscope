// SPDX-License-Identifier: Apache-2.0
// fuzz_eigrp.cpp - libFuzzer harness for Cisco EIGRP (RFC 7868) parsing (eigrp.hpp). EIGRP has no
// transport-layer header of its own -- it rides directly on IP protocol number 88
// (GateKind::IpProtocol, IANA-exclusive), so this harness is handed the IP payload directly,
// exactly the shape try_parse_eigrp already takes.
//
// Worth fuzzing on its own merits: past the fixed 20-byte header, the rest of an EIGRP packet is a
// TLV chain (Type(2)+Length(2), Length counting its own 4-byte header) continuing to the end of the
// packet -- both the general/protocol-independent TLVs (Parameters, Authentication, Software
// Version, Sequence, Next Multicast Sequence) and BOTH IPv4 route TLV formats (legacy "Classic"
// 0x0102/0x0103 and current Wide-Metric 0x0602/0x0603) are dispatched from this one attacker-driven
// Type/Length walk. A single Classic or Wide-Metric route TLV can itself describe MULTIPLE
// destination prefixes sharing one next-hop/metric, each stored PREFIX-LENGTH-COMPRESSED on the
// wire -- only ceil(prefix_len/8) address bytes are actually present, so the number of bytes
// consumed per destination varies with an attacker-controlled prefix-length byte, then gets
// expanded to a full dotted-quad. That compressed-length-to-full-address expansion, nested inside
// an already-nested TLV walk, is exactly the kind of length arithmetic this fuzzing pass targets.
//
// Calls try_parse_eigrp directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover EigrpDecoder::decode's own thin ProtocolDecoder wrapper (trivial,
// ctx-independent -- see eigrp.hpp) -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/eigrp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_eigrp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
