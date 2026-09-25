// SPDX-License-Identifier: Apache-2.0
// fuzz_hartip.cpp - libFuzzer harness for HART-IP (IEC 62591 / HART-IP) parsing (hartip.hpp), over
// TCP and UDP port 5094 -- see hartip.hpp's own file header for the full "structural detection
// gate" paragraph. HART-IP's own 8-byte header (version/message-type/message-ID/status/byte-count)
// plus its Pass-Through Command body's own device-fieldbus-command nesting is exactly the kind of
// hand-rolled length/state-machine logic this fuzzing pass targets -- and hartip.hpp itself notes
// this decoder already exists specifically because a plausible-looking Modbus/TCP-shaped payload on
// this port needs to be told apart from real HART-IP (modbus.cpp's own try_parse_modbus_tcp/
// modbus_tcp_declared_length reject it first).
//
// Like FF-HSE, HART-IP's single-message parse is the SAME free function on both transports --
// HartIpTcpDecoder::decode and HartIpUdpDecoder::decode (hartip.cpp) both call try_parse_hartip on
// the raw payload with no framing difference at all for one datagram/message's own bytes. The one
// REAL difference between the two -- HartIpTcpDecoder::decode additionally runs a coalescing loop
// over try_parse_hartip for more than one HART-IP message packed into one TCP payload, while
// HartIpUdpDecoder::decode does not (a UDP datagram is one message) -- is exactly the kind of
// per-payload coalescing loop this codebase's own established house style keeps OUT of a dedicated
// harness and leaves to fuzz_packet_decode instead (see fuzz_enip.cpp's own header comment, and
// fuzz_ffhse.cpp's identical reasoning for its sibling protocol). So, at the single-message
// granularity a dedicated harness operates at, TCP's and UDP's entry points converge on one call.
//
// Calls try_parse_hartip directly on the raw fuzzer bytes -- no Ethernet/IPv4/TCP-or-UDP framing
// needed, since it already takes a ByteSpan over what would be a TCP or UDP payload. Does not cover
// the TCP-side coalescing loop or any cross-packet state -- both are fuzz_packet_decode's
// territory, per the house style above.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/hartip.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_hartip(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
