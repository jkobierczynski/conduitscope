// SPDX-License-Identifier: Apache-2.0
// fuzz_cdp.cpp - libFuzzer harness for Cisco Discovery Protocol parsing (cdp.hpp): the fixed
// Version/TTL/Checksum header, and the TLV stream that follows it (Length counts the 4-byte TLV
// header itself -- a real gotcha cdp.hpp's own header comment calls out and cross-checks against a
// live wireshark.org worked example), including Device ID/Port ID/Platform/Capabilities/Address-
// list/Management-Address-list curated decoding and a safety cap on the number of TLVs rendered.
// Like STP (see fuzz_stp.cpp), CDP is reached neither through IPv4 nor through a DIX Ethernet II
// EtherType -- it rides classic IEEE 802.3 LLC framing, SNAP-encapsulated (LLC DSAP == SSAP == 0xAA,
// under Cisco's own SNAP OUI 00:00:0C), disambiguated from PVST+ and CDP's own SNAP-OUI siblings
// (VTP/DTP/PAgP/UDLD/CGMP) purely by the 2-byte SNAP Protocol ID (0x2000) -- all of which is
// decoder.cpp's own responsibility BEFORE calling try_parse_cdp, not something the TLV-stream parse
// itself depends on. try_parse_cdp's own parameter is named llc_payload for exactly this reason --
// it is given the bytes after BOTH the 3-byte LLC header AND the 5-byte SNAP header (see
// EthernetFrame::llc_payload in link_layer.hpp: "after the 3-byte LLC header, and after the 5-byte
// SNAP header too when has_snap").
//
// Calls try_parse_cdp directly on the raw fuzzer bytes, exactly like try_parse_dnp3_link_layer in
// fuzz_dnp3.cpp -- no further framing needed, since it already takes a ByteSpan over exactly the
// post-LLC/SNAP-header bytes a real capture would produce. Does not cover decoder.cpp's own
// is_llc_length/has_llc/has_snap/snap_oui/snap_protocol_id gating (including the PVST+/CDP SNAP-PID
// disambiguation, docs/DEVELOPMENT.md roadmap item 48) that decides whether try_parse_cdp is even
// reached in a real capture -- that full-packet path is covered by fuzz_packet_decode instead.
//
// SEED CORPUS: like STP, this target's corpus was NOT extracted with tools/extract_fuzz_corpus.py's
// generic --layer l2/--ethertype mode -- CDP has no EtherType at all, so that mode cannot select it.
// See fuzz/README.md's own note on this and the one-off extraction script used instead (mirrors
// EthernetFrame::llc_payload's own 12+2+3+5-byte skip and DSAP==SSAP==0xAA/SNAP-OUI==00:00:0C/
// SNAP-PID==0x2000 filter directly against link_layer.hpp and cdp.hpp's own SNAP_PID_CDP).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cdp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_cdp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
