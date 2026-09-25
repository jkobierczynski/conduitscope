// SPDX-License-Identifier: Apache-2.0
// fuzz_ffhse.cpp - libFuzzer harness for FOUNDATION Fieldbus HSE (High Speed Ethernet) parsing
// (ffhse.hpp), over TCP ports 1089-1091 (Annunciation/FMS/SM) and UDP port 3622 (LAN Redundancy) --
// see ffhse.hpp's own file header for the full port list. FF-HSE's own explicit bounds-checked PDU
// framing (try_parse_ffhse's own truncation-handling posture, ffhse.hpp) is exactly the kind of
// hand-rolled length parsing this fuzzing pass targets.
//
// UNLIKE the other five dual TCP+UDP protocols in this wave, FF-HSE's TCP and UDP entry points are
// not just similarly-shaped -- they are the IDENTICAL free function: FfhseTcpDecoder::decode and
// FfhseUdpDecoder::decode (ffhse.cpp) both call try_parse_ffhse on the raw payload and then run the
// SAME coalescing loop (more than one FF-HSE PDU concatenated back-to-back -- ffhse.hpp's "UDP
// framing" paragraph notes this applies to UDP too, unlike HART-IP's own TCP-only coalescing), with
// no framing difference between the two transports at all. This codebase's own established house
// style deliberately keeps a dedicated harness narrower than fuzz_packet_decode by skipping any
// per-payload coalescing loop (see fuzz_enip.cpp's own header comment: "does not cover the 'more
// than one ... message coalesced in one TCP payload' loop ... covered by fuzz_packet_decode
// instead"), so at the single-message granularity these harnesses operate at, calling
// try_parse_ffhse once already exercises everything either FfhseTcpDecoder::decode or
// FfhseUdpDecoder::decode would reach for a single PDU -- a second, identical call would add zero
// additional coverage, unlike codesys.hpp's/kerberos.hpp's own genuinely different TCP vs. UDP
// framing.
//
// Calls try_parse_ffhse directly on the raw fuzzer bytes -- no Ethernet/IPv4/TCP-or-UDP framing
// needed, since it already takes a ByteSpan over what would be a TCP or UDP payload. Does not cover
// the coalescing loop itself or any cross-packet state -- both are fuzz_packet_decode's territory,
// per the house style above.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ffhse.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ffhse(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
