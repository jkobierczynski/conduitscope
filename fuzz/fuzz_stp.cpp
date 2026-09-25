// SPDX-License-Identifier: Apache-2.0
// fuzz_stp.cpp - libFuzzer harness for the IEEE Spanning Tree Protocol family (stp.hpp): STP
// (802.1D), RSTP (802.1w), and MSTP (802.1s) BPDU decoding, including MSTP's own Version 3 Length-
// driven, capped (kMaxStpMstiMessages) walk of trailing MSTI Configuration Messages. Unlike every
// other protocol in this batch, STP is reached neither through IPv4 nor through a DIX Ethernet II
// EtherType -- it rides classic IEEE 802.3/LLC framing (DSAP == SSAP == 0x42, LLC_SAP_BPDU, Control
// == 0x03) -- see stp.hpp's own file header for the GARP-collision disambiguation decoder.cpp
// performs by destination MAC BEFORE ever calling try_parse_stp, which is why this harness (like
// try_parse_stp itself) does not need any destination-MAC context of its own: that gating is
// entirely the caller's responsibility, not something the BPDU body parse depends on.
// try_parse_stp's own parameter is named llc_payload, not eth_payload, for exactly this reason --
// it is given the bytes AFTER the 3-byte LLC header, not a raw EtherType payload (STP is never
// SNAP-encapsulated, so no SNAP header is stripped on top of that).
//
// Calls try_parse_stp directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no further framing needed, since it already takes a ByteSpan over exactly the
// post-LLC-header bytes a real capture would produce. Does not cover decoder.cpp's own is_llc_length/
// has_llc/DSAP/SSAP/Control/GARP-destination-MAC gating that decides whether try_parse_stp is even
// reached in a real capture -- that full-packet path is covered by fuzz_packet_decode instead.
//
// SEED CORPUS: unlike every other harness in this batch, this target's corpus was NOT extracted
// with tools/extract_fuzz_corpus.py's generic --layer l2/--ethertype mode -- STP has no EtherType at
// all, so that mode cannot select it. See fuzz/README.md's own note on this and the one-off
// extraction script used instead (mirrors EthernetFrame::llc_payload's own 12+2+3-byte skip and
// DSAP==SSAP==0x42/Control==0x03 filter directly against link_layer.hpp).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/stp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_stp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
