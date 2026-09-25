// SPDX-License-Identifier: Apache-2.0
// fuzz_ieee802154.cpp - libFuzzer harness for raw IEEE 802.15.4 radio-capture framing and MAC
// header parsing (ieee802154.hpp): pcap LINKTYPE_IEEE802_15_4_WITHFCS (195) and
// LINKTYPE_IEEE802_15_4_TAP (283), the two capture formats this codebase supports (see
// ieee802154.hpp's own file header comment for the three excluded link types: LINUX=191,
// NONASK_PHY=215, NOFCS=230).
//
// Calls both of the real, standalone entry points decoder.cpp itself calls directly
// (parse_ieee802154_withfcs and parse_ieee802154_tap, picked by decoder.cpp's own
// link_type == LINKTYPE_IEEE802_15_4_WITHFCS ? ... : ... branch) on the same raw fuzzer bytes in
// turn, with no Ethernet/IPv4/TCP framing needed: each format's own pcap capture record IS the
// bytes that entry point expects (WITHFCS: no pseudo-header, MAC frame at byte 0; TAP: its own
// 4-byte fixed pseudo-header + TLVs first, handled internally by parse_ieee802154_tap itself).
// This is deliberately narrower than fuzz_packet_decode and does not cover Zigbee's own NWK/APS/
// ZDP layers on top of a Data frame's mac_payload -- that is covered by fuzz_zigbee.cpp instead,
// which drives these same two entry points as ITS OWN harness's first stage, then feeds the
// resulting Ieee802154Frame to try_parse_zigbee (see zigbee.hpp's own file header comment for why
// the two parsers are split this way: try_parse_zigbee cannot tell WITHFCS bytes from TAP bytes
// from a bare ByteSpan, so decoder.cpp -- and this harness -- must pick the entry point first).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ieee802154.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan record(data, size);

    try {
        (void)conduitscope::parse_ieee802154_withfcs(record);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::parse_ieee802154_tap(record);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
