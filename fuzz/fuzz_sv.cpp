// SPDX-License-Identifier: Apache-2.0
// fuzz_sv.cpp - libFuzzer harness for IEC 61850-9-2 Sampled Values parsing (sv.hpp): the 8-byte SV
// APDU header (identical in shape to GOOSE's, see goose.hpp/fuzz_goose.cpp), the ASN.1 BER-encoded
// SavPdu (noASDU + one or more ASDU elements), and each ASDU's own svID/datSet/smpCnt/confRev/
// refrTm/smpSynch/smpRate/seqData/smpMod/gmidData fields. SV rides directly on raw Ethernet
// (EtherType 0x88BA) -- no IP or transport layer at all. The BER tag/length walk and the ASDU-list
// walk (SavPdu's own declared noASDU cross-checked against how many ASDU elements are actually
// found) are exactly the kind of hand-rolled, self-describing parsing this fuzzing pass targets.
//
// Calls try_parse_sv directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan over
// exactly what would be an EtherType-0x88BA Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture --
// that full-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/sv.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_sv(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
