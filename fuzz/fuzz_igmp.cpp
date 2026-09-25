// SPDX-License-Identifier: Apache-2.0
// fuzz_igmp.cpp - libFuzzer harness for IGMP v1/v2 (RFC 1112/2236) and v3 (RFC 3376) parsing
// (igmp.hpp). IGMP has no transport-layer header of its own -- it rides directly on IP protocol
// number 2 (GateKind::IpProtocol), so this harness is handed the IP payload directly, exactly the
// shape try_parse_igmp already takes.
//
// Worth fuzzing on its own merits: a single Type byte (0x11 Membership Query) is disambiguated
// across all three IGMP versions purely by length (8 bytes = v1/v2, 12+ bytes = v3 with an
// optional trailing source-address list whose own count is attacker-controlled) -- exactly the
// length-driven branching this fuzzing pass targets. IGMPv3's Max Resp Code and QQIC fields also
// use a shared exponential "floating-point" byte encoding (decode_max_resp_code, igmp.cpp) whose
// bit-shift math is worth stressing directly. IGMPv3 Membership Report additionally carries a list
// of per-group Group Records, each with its own attacker-controlled source-address count and
// auxiliary-data length -- a TLV-like nested-count walk similar in shape to what this pass already
// found real bugs in for BACnet (see fuzz/README.md).
//
// Calls try_parse_igmp directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover IgmpDecoder::decode's own thin ProtocolDecoder wrapper (trivial,
// ctx-independent -- see igmp.hpp) -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/igmp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_igmp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
