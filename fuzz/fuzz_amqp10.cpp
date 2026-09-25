// SPDX-License-Identifier: Apache-2.0
// fuzz_amqp10.cpp - libFuzzer harness for AMQP 1.0 (the OASIS-standardized, ISO/IEC 19464 wire
// format most modern brokers actually speak), amqp10.hpp: a different, wire-incompatible frame
// layer from AMQP 0-9-1 sharing only the connection port and the 8-byte preamble (see amqp091.hpp
// own sibling harness file header for the full amqp_common.hpp sharing rationale, not repeated
// here) -- DOFF/TYPE framing, a rich self-describing AMQP type system, and a performative-keyed
// (open/begin/attach/flow/transfer/disposition/detach/end/close) body walk including a full
// message-section walk for transfer (header/properties/application-properties/data) -- exactly the
// hand-rolled length/state-machine logic this fuzzing pass targets.
//
// TWO CALLS, MIRRORING decoder.cpp OWN REAL SHAPE: Amqp10Decoder::decode (amqp10.cpp) calls
// try_parse_amqp_preamble(payload) FIRST on every payload (the exact same amqp_common.hpp function
// AMQP 0-9-1 uses, see fuzz_amqp091.cpp own header comment for the full AMQP_COMMON DECISION this
// harness and its sibling both implement), and only once a session own sticky AmqpFlowState
// confirms this session already negotiated 1.0 does it fall through to try_parse_amqp10_frame
// (payload) for an ordinary frame. This harness calls BOTH functions directly against the same raw
// fuzzer bytes, unconditionally (skipping the stateful "which version did this session negotiate"
// gate, which needs a live DecodeContext this standalone harness does not construct) -- the same
// "one input, more than one independent entry point" shape fuzz_enip.cpp own header comment
// establishes for its own two entry points.
//
// Both entry points documented as never throwing in their own doc comments -- still wrapped in
// try/catch below, the same defensive posture every harness in this suite takes in case a future
// edit introduces a throwing code path this comment does not yet reflect.
//
// Does not cover: sticky per-session version detection (AmqpFlowState -- which of 0-9-1/1.0 this
// session already negotiated, gating whether an ordinary frame is even attempted at all), the SASL
// layer own own distinct performative table beyond what try_parse_amqp10_frame itself already
// decodes structurally, or the "more than one 1.0 frame coalesced in one TCP payload" coalescing
// loop (Amqp10Result notes, the same MqttResult shape) -- all need a live DecodeContext/flow key;
// that multi-packet, stateful path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/amqp10.hpp"
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
        (void)conduitscope::try_parse_amqp10_frame(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
