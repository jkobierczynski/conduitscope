// SPDX-License-Identifier: Apache-2.0
// fuzz_lldp.cpp - libFuzzer harness for LLDP parsing (lldp.hpp, IEEE 802.1AB): the TLV stream
// itself (each TLV's 2-byte header packing type in the top 7 bits and length in the bottom 9 bits
// of one shared 16-bit word, NOT a byte-split type/length the way most other TLV formats in this
// codebase work), and the two independent, non-parallel Chassis ID/Port ID subtype tables each
// TLV's own leading subtype byte selects between. LLDP rides directly on raw Ethernet (EtherType
// 0x88CC) -- no IP or transport layer at all. The TLV-stream walk (length-driven, terminated by
// either an End-of-LLDPDU TLV or payload exhaustion) is exactly the hand-rolled length/state-
// machine logic this fuzzing pass targets.
//
// Calls try_parse_lldp directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan over
// exactly what would be an EtherType-0x88CC Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture --
// that full-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/lldp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_lldp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
