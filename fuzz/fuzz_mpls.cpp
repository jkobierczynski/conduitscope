// SPDX-License-Identifier: Apache-2.0
// fuzz_mpls.cpp - libFuzzer harness for MPLS label-stack parsing (mpls.hpp, RFC 3032). MPLS rides
// directly on raw Ethernet (EtherType 0x8847 unicast / 0x8848 multicast) -- no IP or transport
// layer of its own, and nothing in a plain MPLS frame says what's underneath the label stack (that
// is controlled by out-of-band LDP/BGP signaling this passive decoder never sees), so this file
// does exactly one real thing: walk the label stack itself. That walk is Bottom-of-Stack-bit-
// terminated (not a fixed stack depth) and capped at kMaxMplsLabelDepth as a sanity bound -- a
// fuzzer-mutated stream of labels whose S bit never sets, or that runs out of captured bytes first,
// is exactly the truncated/deep edge case worth stressing here.
//
// Calls try_parse_mpls directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan over
// exactly what would be an EtherType-0x8847/0x8848 Ethernet payload; unlike fuzz_igrp's src_ip
// hint, try_parse_mpls takes no extra context parameter to loop over -- its own EtherType (unicast
// vs. multicast) has no effect on the label-stack decode itself, only on the ProtocolResult's
// wrapping, so a single call already reaches its full parsing surface. Does not cover decoder.cpp's
// own EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real
// capture, nor any attempt to guess at what rides past the Bottom-of-Stack label (mpls.hpp is
// explicit that this is out of scope) -- the full-packet dispatch path is covered by
// fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/mpls.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_mpls(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
