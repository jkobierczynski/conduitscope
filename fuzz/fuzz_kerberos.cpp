// SPDX-License-Identifier: Apache-2.0
// fuzz_kerberos.cpp - libFuzzer harness for Kerberos (RFC 4120) parsing (kerberos.hpp), over TCP
// and UDP port 88. try_parse_kerberos is a hand-rolled ASN.1 BER/DER reader over EXPLICIT TAGS
// (the opposite convention from LDAP's own IMPLICIT TAGS, per ldap.hpp's own "WIRE FORMAT"
// paragraph) with a two-field structural gate (pvno==5 AND msg-type agreeing with the outer
// APPLICATION tag, per kerberos.cpp's own comment on why that cross-check matters) -- exactly the
// kind of hand-rolled, self-describing parsing this fuzzing pass targets.
//
// try_parse_kerberos itself is the SAME free function on both transports, but TCP and UDP hand it
// genuinely DIFFERENT byte ranges of the same payload -- this is the one real "different framing,
// same parser" case among the six dual TCP+UDP protocols in this wave (see codesys.hpp's own
// header comment for the "two genuinely different functions" case, and ffhse.hpp's/melsec.hpp's
// for the "converges to one call" case). KerberosUdpDecoder::decode (kerberos.cpp) hands
// try_parse_kerberos the raw datagram directly -- UDP carries the raw ASN.1 message with no framing
// of its own. KerberosTcpDecoder::decode strips RFC 4120 SS7.2.2's 4-byte big-endian length prefix
// first (`payload.from(4)`) before handing the de-framed ASN.1 message to the identical shared
// parser -- `payload` there is the full candidate decoder.cpp's TCP reassembly cascade already
// sized against kerberos_tcp_declared_length's own declared length (prefix included). Slicing the
// same fuzzer input both ways and calling try_parse_kerberos on each -- exactly the one-line
// `payload.from(4)` KerberosTcpDecoder::decode itself performs, not a reimplementation of any
// parsing/validation logic -- reaches both real entry points from one input, the same "two related
// entry points, one harness" shape fuzz_enip.cpp's own header comment describes.
//
// Does not cover kerberos_tcp_declared_length itself (reassembly-sizing logic, not application
// parsing) or KerberosFlowState's own cross-packet AS-REQ/TGS-REQ<->AS-REP/TGS-REP correlation
// (including the AS-REP Roasting curated note, which only fires once a request/response pair is
// matched), both of which need a live DecodeContext and flow key -- that multi-packet path is
// covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/kerberos.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    // UDP entry point: no framing of its own, the raw datagram is handed straight to the parser.
    try {
        (void)conduitscope::try_parse_kerberos(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    // TCP entry point: strip the 4-byte big-endian length prefix first, exactly as
    // KerberosTcpDecoder::decode itself does, before reaching the identical parser.
    if (payload.size() >= 5) {
        try {
            (void)conduitscope::try_parse_kerberos(payload.from(4));
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
