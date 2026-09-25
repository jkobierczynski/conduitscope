// SPDX-License-Identifier: Apache-2.0
// fuzz_codesys.cpp - libFuzzer harness for CODESYS V3 (3S-Smart/CODESYS GmbH's PLC runtime
// protocol) parsing (codesys.hpp): try_parse_codesys_tcp (TCP ports 11740/1217, Block-Driver-
// framed -- an outer 8-byte magic+length "Block Driver" layer wraps the Datagram/Router/Channel/
// Services layers) and try_parse_codesys_udp (UDP ports 1740-1743, the SAME Datagram/Router/
// Channel/Services layers with no Block Driver framing at all -- see codesys.hpp's own "DATAGRAM/
// ROUTER LAYER" and "BLOCK DRIVER" paragraphs). Both are genuinely distinct free functions --
// try_parse_codesys_tcp strips and validates the Block Driver header itself before delegating to
// the shared inner parser, try_parse_codesys_udp delegates directly -- making CODESYS the cleanest
// case of the six dual TCP+UDP protocols in this wave: two real, independently-callable entry
// points, not one shared function reached from two decoder wrappers. The varint-encoded tag/length
// TLV encoding the Channel/Services layers use (codesys_varint, 7-bit-per-byte LSB-first with a
// continuation bit) is exactly the kind of hand-rolled parsing this fuzzing pass targets.
//
// Explicit TCP and UDP entry points over two different transports that never see the same bytes
// in a real capture, but both take the same ByteSpan-over-raw-payload shape and neither shares any
// state with the other -- running both against the same fuzzer input in one harness doubles this
// target's coverage per input for free, the same "two related entry points, one harness" shape
// fuzz_enip.cpp's own header comment describes for explicit vs. implicit CIP messaging. Does not
// cover CodesysTcpDecoder::decode/CodesysUdpDecoder::decode's own DecodeContext-dependent behavior
// (neither currently tracks cross-packet session state beyond what try_parse_codesys_tcp/udp
// themselves already compute) -- covered, as always, by fuzz_packet_decode for the multi-packet
// TCP-reassembly case.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/codesys.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_codesys_tcp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::try_parse_codesys_udp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
