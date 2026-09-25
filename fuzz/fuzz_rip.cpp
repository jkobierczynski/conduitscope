// SPDX-License-Identifier: Apache-2.0
// fuzz_rip.cpp - libFuzzer harness for RIP (RFC 1058, rip.hpp) decoding -- UDP port 520.
// try_parse_rip's own route-table-entry walk decodes every complete 20-byte RTE it can find and
// notes any leftover bytes as truncation rather than rejecting the whole message (rip.hpp's own
// comment) -- simple arithmetic, but exactly the kind of "does this length-driven loop terminate
// and stay in-bounds for every possible byte count" question this fuzzing pass exists to answer,
// especially given rip.hpp's own admission that RIP's structural gate (a handful of small integers:
// command in a 5-value set, version 1 or 2) is deliberately weak on its own.
//
// Calls try_parse_rip directly on the raw fuzzer bytes, exactly like the other single-entry-point
// harnesses -- no Ethernet/IPv4/UDP framing needed, since it already takes a ByteSpan over what
// would be a UDP payload. No cross-packet state exists for this protocol.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/rip.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_rip(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
