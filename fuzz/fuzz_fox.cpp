// SPDX-License-Identifier: Apache-2.0
// fuzz_fox.cpp - libFuzzer harness for Fox (Niagara/Tridium Fox protocol), fox.hpp: a text-tagged,
// terminator-delimited framing (the literal five-byte sequence newline-brace-semicolon-semicolon-
// newline, not a length-prefixed field the way most other protocols in this codebase frame their
// own PDUs) carrying a tuple-encoded application protocol. Its own terminator-scan framing (shared
// between tcp_declared_length and try_parse_fox_pdu itself, see fox.hpp own FRAMING section) and
// its self-describing per-tuple type-tag walk (string/int/float/time/hex/boolean/octet/nested
// message tags, including nested-message recursion) are exactly the hand-rolled length/state-machine
// logic this fuzzing pass targets, and the recursive nested-message case in particular gives this
// decoder real depth to explore that a purely flat tag list would not.
//
// Calls the same standalone entry point decoder.cpp itself calls (via FoxDecoder::decode, fox.cpp)
// directly on the raw fuzzer bytes -- try_parse_fox_pdu, which already takes exactly the ByteSpan
// over raw TCP payload shape this harness hands it, no Ethernet/IPv4/TCP framing needed. Documented
// as never throwing in fox.hpp own doc comment -- still wrapped in try/catch below, the same
// defensive posture every harness in this suite takes in case a future edit introduces a throwing
// code path this comment does not yet reflect.
//
// Does not cover: the "more than one Fox frame coalesced in one TCP payload" loop decoder.cpp and
// fox.cpp also has (FoxResult notes coalescing, the same MqttResult/DicomResult shape) -- that
// multi-frame-per-input path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/fox.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_fox_pdu(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
