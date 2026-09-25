// SPDX-License-Identifier: Apache-2.0
// fuzz_profinet.cpp - libFuzzer harness for PROFINET RT parsing (profinet.hpp): FrameID
// classification (the sole discriminator for everything that follows -- there is no further common
// header), DCP (Discovery and Configuration Protocol) request/response decoding, and cyclic real-
// time I/O data framing. PROFINET RT rides directly on raw Ethernet (EtherType 0x8892) -- no IP or
// transport layer at all. The FrameID-range dispatch and DCP's own DCPDataLength/DCPBlockLength-
// driven block walk are exactly the hand-rolled length/state-machine logic this fuzzing pass
// targets.
//
// Calls try_parse_profinet directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer
// in fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan
// over exactly what would be an EtherType-0x8892 Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture, nor
// Alarm/PTCP/RT_CLASS_UDP FrameID ranges, which profinet.hpp documents as named-only, not decoded --
// the full-packet dispatch path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/profinet.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_profinet(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
