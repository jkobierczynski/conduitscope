// SPDX-License-Identifier: Apache-2.0
// fuzz_goose.cpp - libFuzzer harness for IEC 61850-8-1 GOOSE parsing (goose.hpp): the 8-byte GOOSE
// APDU header, and the ASN.1 BER-encoded GOOSE PDU (gocbRef/datSet/goID/timestamp/stNum/sqNum/
// simulation/confRev/ndsCom/the allData dataset), including the allData dataset's own recursive,
// self-describing ASN.1 "Data" value walk. GOOSE rides directly on raw Ethernet (EtherType 0x88B8)
// -- no IP or transport layer at all. The BER tag/length walk (short-form and long-form length
// encoding, constructed-type recursion into nested Data values) is exactly the kind of hand-rolled,
// self-describing parsing this fuzzing pass targets, and this codebase already has a real
// pinning-fixture for pathologically deep nesting (tests/sample_goose_deep_nesting.pcap), whose
// extracted payload is included in this harness's own seed corpus.
//
// Calls try_parse_goose directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan over
// exactly what would be an EtherType-0x88B8 Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture, nor
// the GSE Management PDU (tag 0xA0) body, which goose.hpp documents as named-only -- the full-packet
// dispatch path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/goose.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_goose(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
