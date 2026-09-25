// SPDX-License-Identifier: Apache-2.0
// fuzz_ethercat.cpp - libFuzzer harness for EtherCAT parsing (ethercat.hpp): the 2-byte frame
// header (Length/Reserved/Type bit-fields), and, for Type 1 ("EtherCAT command") frames, the
// chained EtherCAT datagram(s) that follow -- Cmd/Idx/Address/Len+flags/IRQ header, each datagram's
// own Data payload, and the trailing Working Counter. EtherCAT rides directly on raw Ethernet
// (EtherType 0x88A4) -- no IP or transport layer at all -- and, unlike PROFINET/GOOSE/SV, is plain
// fixed-binary little-endian throughout, so the datagram-chain walk (each datagram's own declared
// length driving where the next one starts, More-bit-linked) is exactly the "hand-rolled
// length/state-machine logic" this fuzzing pass targets.
//
// Calls try_parse_ethercat directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer
// in fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it already takes a ByteSpan
// over exactly what would be an EtherType-0x88A4 Ethernet payload. Does not cover decoder.cpp's own
// EtherType-cascade dispatch (ethertype_registry()) that reaches this decoder in a real capture, nor
// Type 2-5 (ADS/RAW-IO/NV/Mailbox) frame bodies, which ethercat.hpp documents as named-only, not
// decoded -- the full-packet dispatch path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ethercat.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ethercat(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
