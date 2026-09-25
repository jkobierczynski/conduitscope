// SPDX-License-Identifier: Apache-2.0
// fuzz_slow_protocols.cpp - libFuzzer harness for IEEE 802.3 "Slow Protocols" parsing
// (slow_protocols.hpp): one EtherType (0x8809), Subtype-multiplexed across three genuinely distinct
// link-layer control protocols told apart by a single Subtype byte right after the EtherType --
// LACP (Subtype 1, three fixed-position TLVs), Marker Protocol (Subtype 2, a TLV whose own Length
// self-describes how much trailing Pad/Reserved to skip), and 802.3 OAM/EFM-OAM (Subtype 3, a
// Code-keyed body: an Information TLV stream for Code 0x00, or a Sequence_Number-then-Event-TLV-
// list for Code 0x01, with four curated, fully-decoded Event TLV types). try_parse_slow_protocols
// is the single entry point for all three subtypes -- the Subtype dispatch happens inside it, not
// at the call site -- so one harness already reaches every subtype's own parsing logic; see
// slow_protocols.hpp's own file header for the full per-subtype wire-format breakdown. Slow
// Protocols rides directly on raw Ethernet -- no IP or transport layer at all.
//
// Calls try_parse_slow_protocols directly on the raw fuzzer bytes, exactly like
// try_parse_dnp3_link_layer in fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it
// already takes a ByteSpan over exactly what would be an EtherType-0x8809 Ethernet payload. Does
// not cover decoder.cpp's own EtherType-cascade dispatch (ethertype_registry()) that reaches this
// decoder in a real capture -- that full-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/slow_protocols.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_slow_protocols(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
