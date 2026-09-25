// SPDX-License-Identifier: Apache-2.0
// fuzz_vrrp.cpp - libFuzzer harness for VRRP v2 (RFC 3768) and v3 (RFC 5798) parsing (vrrp.hpp).
// VRRP has no transport-layer header of its own -- it rides directly on IP protocol number 112
// (GateKind::IpProtocol), so this harness is handed the IP payload directly, exactly the shape
// try_parse_vrrp already takes.
//
// Worth fuzzing on its own merits: the same 8-byte fixed header shape means two different things
// depending on the Version nibble (v2's Auth Type + 1-byte Advertisement Interval vs. v3's 12-bit
// centisecond interval packed with 4 reserved bits) -- a single byte's top nibble redirects how the
// rest of the fixed header is interpreted before the attacker-controlled Count-of-virtual-IPv4-
// addresses field even gets read. v2 additionally appends an 8-byte Authentication Data field only
// read for Auth Type 1, after Count*4 bytes of address list -- three chained, attacker-controlled
// length decisions (version branch, address count, then a conditional trailing field) is exactly
// the length-arithmetic surface this fuzzing pass targets.
//
// Calls try_parse_vrrp directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover VrrpDecoder::decode's own thin ProtocolDecoder wrapper (trivial,
// ctx-independent -- see vrrp.hpp) -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/vrrp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_vrrp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
