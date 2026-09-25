// SPDX-License-Identifier: Apache-2.0
// fuzz_zigbee.cpp - libFuzzer harness for Zigbee (IEEE 802.15.4 MAC + NWK + APS + ZDP)
// (zigbee.hpp), riding on the raw IEEE 802.15.4 radio-capture link layer (ieee802154.hpp): pcap
// LINKTYPE_IEEE802_15_4_WITHFCS (195) and LINKTYPE_IEEE802_15_4_TAP (283).
//
// try_parse_zigbee does not take raw bytes: it takes an already-parsed Ieee802154Frame (see
// zigbee.hpp's own try_parse_zigbee(const Ieee802154Frame&) signature) -- zigbee.hpp's own file
// header comment says explicitly that both ieee802154.hpp capture-format entry points "converge
// on one shared try_parse_zigbee(const Ieee802154Frame&)" once the MAC layer is parsed, since
// try_parse_zigbee itself cannot tell WITHFCS bytes from TAP bytes from a bare ByteSpan (that
// knowledge deliberately lives only in decoder.cpp's own link-type branch, per zigbee.hpp's
// ZigbeeDecoder class comment). This is therefore a two-stage harness, the same shape
// fuzz_dnp3.cpp/fuzz_cotp_s7comm.cpp use for their own two-stage entry points, and the same shape
// fuzz_dnp3.cpp's sibling harnesses use -- except here BOTH stage-one entry points are exercised
// against the same input (mirroring fuzz_ieee802154.cpp exactly and fuzz_dnp3.cpp's own sibling
// fuzz_cotp_s7comm.cpp's "call both reachable framings" shape, rather than fuzz_dnp3.cpp's single-
// framing shape), since decoder.cpp reaches try_parse_zigbee from either capture format and both
// are in scope. No Ethernet/IPv4/TCP framing needed either way: the raw fuzzer bytes are handed
// to parse_ieee802154_withfcs/parse_ieee802154_tap exactly as their own pcap capture record would
// be (see fuzz_ieee802154.cpp's own header comment for each format's exact framing).
//
// This does not duplicate ieee802154.hpp's own MAC-layer parsing coverage (already exercised
// directly and faster-reaching by fuzz_ieee802154.cpp) -- it exists specifically to reach
// try_parse_zigbee's own NWK/APS/ZDP decoding on whatever mac_payload a fuzzer-mutated MAC frame
// produces, which fuzz_ieee802154.cpp alone never calls.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ieee802154.hpp"
#include "conduitscope/zigbee.hpp"

namespace {

void FuzzOneMac(conduitscope::Ieee802154Frame mac) {
    try {
        (void)conduitscope::try_parse_zigbee(mac);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan record(data, size);

    try {
        FuzzOneMac(conduitscope::parse_ieee802154_withfcs(record));
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome (record too short for even the FCF) -- see fuzz_dnp3.cpp's
        // identical comment.
    }

    try {
        FuzzOneMac(conduitscope::parse_ieee802154_tap(record));
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome (record too short for the TAP pseudo-header or FCF) -- see
        // fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
