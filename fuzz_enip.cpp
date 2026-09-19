// SPDX-License-Identifier: Apache-2.0
// fuzz_enip.cpp - libFuzzer harness for EtherNet/IP + CIP parsing (enip.hpp): explicit messaging
// (try_parse_enip -- the 24-byte encapsulation header, then, for SendRRData/SendUnitData, the
// Common Packet Format item list and the CIP message(s) it carries, including EPATH class/
// instance/attribute and ANSI Extended Symbol segment decoding, with Multiple_Service_Packet and
// Unconnected_Send recursing into their own embedded CIP messages) and implicit (real-time I/O)
// messaging (try_parse_cip_io -- a Sequenced Address Item plus an optional Connected Data Item,
// no encapsulation header). Both are exactly the "hand-rolled length/state-machine logic" the
// original five-target fuzzing plan (docs/DEVELOPMENT.md's "External code review and engineering
// priorities" section) was scoped around, and CIP's own request-path/service-code recursion
// (Multiple_Service_Packet, Unconnected_Send) makes it one of the more structurally complex
// parsers in this codebase. A dedicated harness reaches this parsing logic in far fewer libFuzzer
// iterations than fuzz_packet_decode does, since no unrelated Ethernet/IPv4/TCP-or-UDP header
// bytes need to happen to parse first.
//
// Explicit and implicit messaging are two independent entry points over two different transports
// (TCP port 44818 vs. UDP port 2222) that never see the same bytes in a real capture, but both
// take the same ByteSpan-over-raw-payload shape and neither shares any state with the other --
// running both against the same fuzzer input in one harness doubles this target's coverage per
// input for free, the same "two related entry points, one harness" shape fuzz_dnp3.cpp already
// uses for its own link+transport/application pair. Both are documented never to throw, but this
// still wraps each call in try/catch, the same defensive posture every other harness here takes,
// in case a future edit introduces a throwing code path this comment doesn't yet reflect. Does
// not cover the "more than one EtherNet/IP message coalesced in one TCP payload" loop decoder.cpp
// also has -- that multi-message-per-input path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/enip.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_enip(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::try_parse_cip_io(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
