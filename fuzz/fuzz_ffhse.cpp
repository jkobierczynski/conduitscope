// SPDX-License-Identifier: Apache-2.0
// fuzz_ffhse.cpp - libFuzzer harness for FOUNDATION Fieldbus HSE (High Speed Ethernet) parsing
// (ffhse.hpp), over TCP ports 1089-1091 (Annunciation/FMS/SM) and UDP port 3622 (LAN Redundancy) --
// see ffhse.hpp's own file header for the full port list. FF-HSE's own explicit bounds-checked PDU
// framing (try_parse_ffhse's own truncation-handling posture, ffhse.hpp) is exactly the kind of
// hand-rolled length parsing this fuzzing pass targets.
//
// FF-HSE's TCP and UDP entry points both call try_parse_ffhse on the raw payload and then run the
// SAME coalescing loop (more than one FF-HSE PDU concatenated back-to-back -- ffhse.hpp's "UDP
// framing" paragraph notes this applies to UDP too, unlike HART-IP's own TCP-only coalescing).
// UPDATE (after a real UDP false-positive collision was found and fixed): FfhseUdpDecoder::decode
// is NOT quite identical to FfhseTcpDecoder::decode any more -- it now ALSO declines a parsed
// frame outright when its own declared Message Length exceeds the UDP datagram's actual size
// (matching the reference dissector's own dissect_ff_udp() length check; see FfhseUdpDecoder::
// decode's own comment in ffhse.cpp), since a UDP datagram is delivered whole and a PDU claiming
// to be bigger than the datagram it arrived in can never really be "still arriving" the way a
// legitimately-reassembling TCP PDU can. try_parse_ffhse itself is UNCHANGED by that fix (it
// still happily accepts and notes such a payload as truncated) -- so this harness, calling
// try_parse_ffhse directly, does NOT exercise that UDP-specific decline. This is the same
// "decode()-level decision, not single-PDU-parsing" territory fuzz_enip.cpp's own header comment
// already carves out for its own coalescing loop ("does not cover the 'more than one ... message
// coalesced in one TCP payload' loop ... covered by fuzz_packet_decode instead") -- the length-
// vs-datagram-size check is a plain arithmetic comparison with no new bounds-computation surface
// of its own, so it's covered at the CTest/decode() layer (see CMakeLists.txt's
// ffhse_udp_message_length_exceeding_datagram_not_misdetected) rather than duplicated here.
// Outside that one check, calling try_parse_ffhse once still exercises everything else either
// FfhseTcpDecoder::decode or FfhseUdpDecoder::decode reaches for a single PDU -- a second,
// identical call would add zero additional coverage, unlike codesys.hpp's/kerberos.hpp's own
// genuinely different TCP vs. UDP framing.
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
