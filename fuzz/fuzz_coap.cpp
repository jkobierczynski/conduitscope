// SPDX-License-Identifier: Apache-2.0
// fuzz_coap.cpp - libFuzzer harness for CoAP (Constrained Application Protocol, RFC 7252,
// coap.hpp) decoding -- UDP port 5683. CoAP's own Option Delta/Option Length nibble encoding (each
// with a 0-12/13/14-extension/15-reserved scheme, RFC 7252 section 3.1) is real hand-rolled
// variable-length parsing over a running "total option number so far" accumulator, walked once per
// option until either the buffer runs out or the 0xFF Payload Marker is seen -- coap.hpp's own file
// header comment calls out the exact malformed-option cases (a reserved nibble value 15 outside the
// Payload Marker, a declared Option Length that overruns the remaining bytes) this decoder must stop
// on cleanly rather than mis-walk past. That option-chain walk is exactly the kind of length/state
// bookkeeping this fuzzing pass targets.
//
// Calls try_parse_coap directly on the raw fuzzer bytes, exactly like the other single-entry-point
// harnesses (fuzz_bsap.cpp, fuzz_mqtt.cpp) -- no Ethernet/IPv4/UDP framing needed, since it already
// takes a ByteSpan over what would be a UDP payload. No cross-packet session state exists for this
// protocol (coap.hpp's own SCOPE section: "No cross-packet session state" -- Message-ID and Token
// correlation are both explicitly out of scope), so there is nothing else to reach.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/coap.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_coap(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
