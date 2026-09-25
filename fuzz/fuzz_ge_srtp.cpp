// SPDX-License-Identifier: Apache-2.0
// fuzz_ge_srtp.cpp - libFuzzer harness for GE SRTP (GE/Emerson PLC Service Request Transport
// Protocol), ge_srtp.hpp: a fixed-layout binary framing (INIT/INIT_ACK, SHORT/SHORT_ACK/SHORT_ERR,
// EXTENDED/EXTENDED_ACK, and a structurally-recognized-but-unparsed UNKNOWN packet-type fallback)
// carrying a curated, numeric service-request-code-keyed set of memory read/write/control
// operations -- exactly the hand-rolled length/state-machine logic this fuzzing pass targets, and
// per ge_srtp.hpp own file header, one of this codebase least-documented protocols (its own
// SOURCING section leans on a DFRWS 2017 paper and a community Notes.txt rather than a vendor spec),
// making it a comparably high-uncertainty target to s7comm_plus own unofficial reverse-engineered
// object model.
//
// Calls the same standalone, context-free entry point decoder.cpp itself calls (via
// GeSrtpTcpDecoder::decode, ge_srtp.cpp) directly on the raw fuzzer bytes -- try_parse_ge_srtp,
// which already takes exactly the ByteSpan-over-raw-TCP-payload shape this harness hands it, no
// Ethernet/IPv4/TCP framing needed. Context-free like try_parse_melsec (see try_parse_ge_srtp own
// doc comment): a request is always fully decoded from its own bytes alone; only a RESPONSE own
// service-request-code context (GeSrtpFlowState Sequence-Number-keyed pending-request table, a
// live DecodeContext/flow key this free function has no access to) needs cross-packet state, which
// this harness does not attempt to reconstruct -- that multi-packet request/response-pairing path is
// covered by fuzz_packet_decode instead. Documented as never throwing in try_parse_ge_srtp own doc
// comment -- still wrapped in try/catch below, the same defensive posture every harness in this
// suite takes in case a future edit introduces a throwing code path this comment does not yet
// reflect.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ge_srtp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ge_srtp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
