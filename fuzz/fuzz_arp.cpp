// SPDX-License-Identifier: Apache-2.0
// fuzz_arp.cpp - libFuzzer harness for ARP parsing (arp.hpp: RFC 826 base layout plus the RFC 903/
// 1931/2390/2225 opcode extensions -- RARP/DRARP/InARP/ATMARP -- and the RFC 5227 ARP Probe/
// Announcement special cases). ARP rides directly on raw Ethernet (EtherType 0x0806) -- no IP or
// transport layer at all -- and its HLEN/PLEN fields genuinely drive the SHA/SPA/THA/TPA layout
// rather than being hardcoded to 6/4, so a fuzzer-mutated header can walk that layout arbitrarily;
// the OPER-value structural gate (see arp.hpp's own "structural detection gate" paragraph) is the
// other attacker-controlled-shape surface worth stressing here.
//
// Calls try_parse_arp directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan over
// exactly what would be an EtherType-0x0806 Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture --
// that full-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/arp.hpp"
#include "conduitscope/byteio.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_arp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
