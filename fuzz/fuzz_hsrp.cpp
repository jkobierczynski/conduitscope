// SPDX-License-Identifier: Apache-2.0
// fuzz_hsrp.cpp - libFuzzer harness for HSRP v1/v2 (hsrp.hpp) decoding -- UDP port 1985.
// try_parse_hsrp tries the HSRPv1 fixed 20-byte shape first, and falls back to walking the
// remaining bytes as a v2 flat TLV chain (Type(1)+Length(1)+Value) otherwise -- both shapes,
// and the decision between them, are exercised by whatever bytes libFuzzer hands this harness.
// The v2 Group State TLV in particular has an IPv4-vs-IPv6-dependent byte layout (hsrp.hpp's own
// comment: IPv6 fully accounts for the declared 40-byte TLV length, IPv4 leaves 12 trailing bytes
// unaccounted for) reverse-engineered from Wireshark rather than an official spec (Cisco never
// published HSRPv2), making its own length bookkeeping a good fuzzing target even though the
// overall structural gate is admittedly weak (hsrp.hpp's own SECURITY CONTEXT section notes this
// decoder's port-gating, like RIP/BSAP, exists precisely because the wire format itself is weak).
//
// Calls try_parse_hsrp directly on the raw fuzzer bytes, exactly like the other single-entry-point
// harnesses -- no Ethernet/IPv4/UDP framing needed, since it already takes a ByteSpan over what
// would be a UDP payload. No cross-packet state exists for this protocol.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/hsrp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_hsrp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
