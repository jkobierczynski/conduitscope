// SPDX-License-Identifier: Apache-2.0
// fuzz_cclink_ie.cpp - libFuzzer harness for CC-Link IE Field Network Basic (CCIEFB, cclink_ie.hpp)
// decoding -- UDP port 61450 (cyclic data transmission) and UDP port 61451 (SLMP node search /
// set-IP-address). This decoder's cyclic path in particular has real hand-rolled arithmetic on
// attacker-controlled fields (cclink_ie.hpp's own "Trailing cyclic I/O data" section): the request
// walks N occupied-station blocks driven by a wire-declared count, and the response instead DERIVES
// its own occupied-station count arithmetically from the UDP payload length
// (`(payload_len - 59) / 72`, with an exact-divisibility check, mirroring the reference stack's own
// `cl_calculate_number_of_occupied_stations()`) -- exactly the kind of length-driven parsing this
// fuzzing pass exists to stress.
//
// Unlike every other harness in this second wave, CC-Link IE exposes four narrow, non-self-
// determining entry points rather than one (cclink_ie.hpp's own "Four narrow parse entry points"
// comment): a response carries no command field of its own on the wire, so decoder.cpp's real
// CclinkIeDecoder::decode() only knows which body shape to parse by consulting session-scoped
// CclinkIeFlowState (which request, if any, is still outstanding on this UDP session). This harness
// does not carry that cross-packet state (matching every other harness's "no live DecodeContext/
// flow key" scope limit -- see fuzz_dnp3.cpp's own comment), so it instead calls all five concrete
// (parser, expected-kind) combinations unconditionally against the same fuzzer input: the two
// self-determining ones (cyclic request/response, whose own subheader settles req-vs-resp) plus the
// SLMP request (which self-determines Node Search vs. Set IP Address from its own command field)
// plus BOTH SLMP response shapes (which do not self-determine and need the `expected_kind` hint
// decoder.cpp would otherwise supply from session state). This is the "run every reachable entry
// point against one input" shape fuzz_enip.cpp already uses for its own two independent entry
// points, just extended to five here since this protocol's own response ambiguity needs more than
// one hint value tried, the same reason fuzz_mqtt.cpp loops its `session_version_hint` parameter.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cclink_ie.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_cclink_ie_cyclic_request(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::try_parse_cclink_ie_cyclic_response(payload);
    } catch (const conduitscope::ParseError&) {
    }

    try {
        (void)conduitscope::try_parse_cclink_ie_slmp_request(payload);
    } catch (const conduitscope::ParseError&) {
    }

    for (auto expected_kind : {conduitscope::CclinkIeMessageKind::NodeSearchResponse,
                                conduitscope::CclinkIeMessageKind::SetIpAddressResponse}) {
        try {
            (void)conduitscope::try_parse_cclink_ie_slmp_response(payload, expected_kind);
        } catch (const conduitscope::ParseError&) {
        }
    }

    return 0;
}
