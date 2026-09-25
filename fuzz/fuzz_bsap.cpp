// SPDX-License-Identifier: Apache-2.0
// fuzz_bsap.cpp - libFuzzer harness for BSAP (Bristol Standard Asynchronous/Synchronous Protocol,
// bsap.hpp) decoding -- UDP port 1234. BSAP is one of this codebase's more structurally fragile
// decoders by its own admission: its serial-tunneled path is only gated by a single 2-byte magic
// (0x0210) before walking a Local-or-Global-addressed header whose exact shape depends on one bit
// of the very next byte, and its BSAP-IP-native path (bsap.hpp's own "HONESTLY WEAK GATE" section)
// has essentially no self-describing structure at all -- any 4-or-more-byte payload that doesn't
// start with 0x0210 is accepted, making the header parsing arithmetic itself (leading_value,
// message_func, and the trailing-data byte-count/hex-dump path) the only thing standing between
// arbitrary bytes and a crash. That combination of "weak structural gate, real byte-offset
// arithmetic on attacker-controlled length fields" is exactly the shape this fuzzing pass targets.
//
// Calls try_parse_bsap directly on the raw fuzzer bytes, exactly like try_parse_dnp3_transport_and_
// application/try_parse_mqtt_message in the other single-entry-point harnesses -- no Ethernet/IPv4/
// UDP framing needed, since it already takes a ByteSpan over what would be a UDP payload. No
// cross-packet state exists for this protocol (bsap.hpp's own "SESSION STATE: none" section), so
// there is nothing else to reach.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/bsap.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_bsap(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
