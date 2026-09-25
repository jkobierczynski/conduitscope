// SPDX-License-Identifier: Apache-2.0
// fuzz_melsec.cpp - libFuzzer harness for Mitsubishi MELSEC (3E frame, MC protocol) parsing
// (melsec.hpp), over TCP port 5001 and UDP port 5000. try_parse_melsec is context-free by design
// (mirrors try_parse_twincat exactly, per melsec.hpp's own comment): a request is fully self-
// describing, but a RESPONSE carries no command field of its own on the wire at all -- session-
// scoped request/response matching (MelsecFlowState::pending) is what lets a response actually get
// decoded past "End Code + raw byte count", which is exactly the kind of hand-rolled, context-
// dependent parsing this fuzzing pass targets structurally, even though the standalone
// context-free call this harness makes can only ever reach the structural-only response path.
//
// MELSEC's TCP and UDP entry points are the IDENTICAL free function: MelsecTcpDecoder::decode and
// MelsecUdpDecoder::decode (melsec.cpp) are both a direct one-line pass-through onto the SAME
// shared decode_with_session_state helper, which itself just calls try_parse_melsec -- no framing
// difference between the two transports at all (no length-prefix stripping, no coalescing loop
// either way, unlike FINS's/HART-IP's own asymmetry). So there is only one real entry point to
// call here, not two.
//
// Calls try_parse_melsec directly on the raw fuzzer bytes, exactly like try_parse_twincat/
// try_parse_modbus_tcp in the other single-entry-point harnesses -- no Ethernet/IPv4/TCP-or-UDP
// framing needed, since it already takes a ByteSpan over what would be a TCP or UDP payload. Does
// not cover MelsecFlowState's own cross-packet request/response correlation (the whole reason a
// response's command/subcommand/random-read counts get filled in at all), which needs a live
// DecodeContext and flow key -- that multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/melsec.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_melsec(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
