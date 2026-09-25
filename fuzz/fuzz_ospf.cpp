// SPDX-License-Identifier: Apache-2.0
// fuzz_ospf.cpp - libFuzzer harness for OSPFv2 (RFC 2328) parsing (ospf.hpp). OSPF has no
// transport-layer header of its own -- it rides directly on IP protocol number 89
// (GateKind::IpProtocol, IANA-exclusive), so this harness is handed the IP payload directly,
// exactly the shape try_parse_ospf already takes.
//
// Worth fuzzing on its own merits: this is structurally the most nested parser in this batch of
// eight. A single packet can be an LS Update carrying a LIST of complete LSAs (each with its own
// 20-byte header plus a type-keyed body -- Router/Network/Summary/ASBR-Summary/AS-External/NSSA-
// External, five distinct body layouts sharing one dispatch), or a DB Description/LS Ack carrying a
// list of LSA HEADERS only, or an LS Request carrying a list of (type, Link State ID, Advertising
// Router) tuples -- every one of those lists is driven purely by the 24-byte common header's own
// PacketLength field and each LSA's own declared Length, both fully attacker-controlled. A Router-
// LSA body additionally nests its own sub-list of links, each with a type-dependent number of TOS
// metric entries. This is exactly the "list of variably-shaped variably-counted structures" shape
// most likely to hide a length-arithmetic bug.
//
// Calls try_parse_ospf directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover OspfDecoder::decode's own thin ProtocolDecoder wrapper (trivial,
// ctx-independent -- see ospf.hpp) -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ospf.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ospf(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
