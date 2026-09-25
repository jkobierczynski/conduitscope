// SPDX-License-Identifier: Apache-2.0
// fuzz_powerlink.cpp - libFuzzer harness for Ethernet POWERLINK (EPL, powerlink.hpp) decoding --
// EtherType 0x88AB (raw Ethernet, the cyclic/realtime path) AND UDP port 3819 (the SDO/non-cyclic
// path), dual-gated the way this project's own brief for this task describes. POWERLINK's own
// MessageType-keyed dispatch (SoC/PReq/PRes/SoA/ASnd, each with its own body shape) plus ASnd's own
// nested ServiceID dispatch (SDO in particular carries its own Sequence-Layer bit-packed
// ReceiveSequenceNumber/ReceiveCon/SendSequenceNumber/SendCon fields, powerlink.hpp's own "SDO
// Sequence Layer" section) is real hand-rolled, multi-level, attacker-reachable parsing -- exactly
// what this fuzzing pass targets.
//
// UNLIKE fuzz_enip.cpp's own "two independent entry points" shape (try_parse_enip and
// try_parse_cip_io are two genuinely different functions over two different transports),
// POWERLINK's EtherType and UDP:3819 gates are NOT two entry points at the code level at all:
// powerlink.hpp's own "UDP:3819 SDO variant -- ARCHITECTURE NOTE" section states this outright --
// the reference dissector's own UDP entry point calls the exact same core dissection function the
// raw-Ethernet path uses, and this codebase's own PowerlinkDecoder::decode / PowerlinkSdoUdpDecoder
// ::decode (powerlink.cpp) both call try_parse_powerlink UNCHANGED, with zero decode-logic
// duplication between them. Calling that one function twice against the same bytes would therefore
// add nothing -- so this harness calls it once, and instead gets its "two entry points" coverage
// from the SEED CORPUS: fuzz/corpus/powerlink/ combines real EtherType-0x88AB-sourced frames
// (`eth_*.bin`, from tests/sample_powerlink.pcap and tests/sample_powerlink_rogue_mn.pcap, stripped
// to the EtherType payload via `--layer l2 --ethertype 0x88AB`) AND real UDP:3819-sourced frames
// (`udp_*.bin`, from tests/sample_powerlink.pcap's own SDO traffic, stripped to the UDP payload via
// `--layer l4 --l4-proto udp --port 3819`) -- both flavors seed the SAME mutation corpus against the
// SAME shared entry point, which is the accurate way to mirror "two gates, one parser" rather than
// invoking identical code twice per input.
//
// Calls try_parse_powerlink directly on the raw fuzzer bytes -- no Ethernet/IPv4/UDP framing code
// of this harness's own needed either way, since the function already takes a ByteSpan over exactly
// what's left after whichever gate stripped its own framing (14-byte Ethernet header for the
// EtherType path, Ethernet+IPv4+UDP headers for the UDP path -- see the corpus note above for why
// both already land on the identical byte shape). No cross-packet state exists for this protocol.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/powerlink.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_powerlink(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
