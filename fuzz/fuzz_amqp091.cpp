// SPDX-License-Identifier: Apache-2.0
// fuzz_amqp091.cpp - libFuzzer harness for AMQP 0-9-1 (the JMS-era, RabbitMQ-popularized wire
// format), amqp091.hpp: a self-describing, type-tagged frame layer (METHOD/HEADER/BODY/HEARTBEAT
// frame types, curated method-ID/class-ID decoding, a full field-table type system for
// Connection.Start-Ok and friends) -- exactly the hand-rolled length/state-machine logic this
// fuzzing pass targets, and TCP port 5672 own second protocol after AMQP 1.0, sharing one
// connection-preamble parser (amqp_common.hpp) between them -- see that decision below.
//
// TWO CALLS, MIRRORING decoder.cpp OWN REAL SHAPE: Amqp091Decoder::decode (amqp091.cpp) calls
// try_parse_amqp_preamble(payload) FIRST on every payload (amqp_common.hpp own 8-byte
// connection-preamble recognizer, shared verbatim with AMQP 1.0 -- see amqp_common.hpp own file
// header for why this exists as one shared function rather than being duplicated per version), and
// only once a session own sticky AmqpFlowState confirms this session already negotiated 0-9-1 does
// it fall through to try_parse_amqp091_frame(payload) for an ordinary frame. This harness calls
// BOTH functions directly against the same raw fuzzer bytes, unconditionally (skipping the
// stateful "which version did this session negotiate" gate, which needs a live DecodeContext this
// standalone harness does not construct) -- the same "one input, more than one independent entry
// point" shape fuzz_enip.cpp own header comment establishes for its own two entry points.
//
// AMQP_COMMON DECISION -- documented here per this batch own instructions: amqp_common.hpp own
// try_parse_amqp_preamble is NOT reachable from try_parse_amqp091_frame or try_parse_amqp10_frame
// themselves (confirmed by reading both -- each own doc comment says the preamble "is handled
// separately"); it is only ever called from INSIDE Amqp091Decoder::decode/Amqp10Decoder::decode,
// the full ProtocolDecoder wrapper, not from either frame-level free function. Since this whole
// fuzzing suite house style calls the small free-function entry points directly rather than the
// full decode() wrapper, a harness built only around try_parse_amqp091_frame/try_parse_amqp10_frame
// would never reach amqp_common.hpp own parsing logic at all. Rather than adding a third, separate
// fuzz_amqp_common.cpp for one small 8-byte-pattern function, this harness (and its amqp10 sibling)
// each call try_parse_amqp_preamble directly on their own raw input first, mirroring the real
// decoder own own call order exactly -- so amqp_common.hpp gets real, dedicated-harness coverage
// from TWO independent corpora/fuzzing campaigns (amqp091 and amqp10) instead of zero, without a
// third harness whose own only job would be one already-covered function.
//
// Both entry points documented as never throwing in their own doc comments -- still wrapped in
// try/catch below, the same defensive posture every harness in this suite takes in case a future
// edit introduces a throwing code path this comment does not yet reflect.
//
// Does not cover: sticky per-session version detection (AmqpFlowState -- which of 0-9-1/1.0 this
// session already negotiated, gating whether an ordinary frame is even attempted at all) or the
// "more than one 0-9-1 frame coalesced in one TCP payload" coalescing loop (Amqp091Result notes,
// the same MqttResult shape) -- both need a live DecodeContext/flow key; that multi-packet,
// stateful path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/amqp091.hpp"
#include "conduitscope/amqp_common.hpp"
#include "conduitscope/byteio.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_amqp_preamble(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    try {
        (void)conduitscope::try_parse_amqp091_frame(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
