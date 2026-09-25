// SPDX-License-Identifier: Apache-2.0
// fuzz_nbns.cpp - libFuzzer harness for NBT-NS (NetBIOS Name Service, nbns.hpp) decoding -- UDP
// port 137. NBT-NS reuses the same DNS-message-shaped header/question/resource-record grammar
// dns.hpp's own parser targets, but with its own distinct NAME encoding (a fixed 32-byte
// first-level-encoded name, each byte required to fall in the 'A'-'P' range, nbns.hpp's own
// detection-gate comment) and its own resource-record types -- a separate hand-rolled length-driven
// parser from DNS's, not a thin wrapper around it, and therefore its own fuzzing target.
//
// Calls try_parse_nbns directly on the raw fuzzer bytes, exactly like the other single-entry-point
// harnesses -- no Ethernet/IPv4/UDP framing needed, since it already takes a ByteSpan over what
// would be a UDP payload. No cross-packet state exists for this protocol.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/nbns.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_nbns(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
