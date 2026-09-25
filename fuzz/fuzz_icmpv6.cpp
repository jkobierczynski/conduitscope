// SPDX-License-Identifier: Apache-2.0
// fuzz_icmpv6.cpp - libFuzzer harness for ICMPv6 parsing (icmpv6.hpp: RFC 4443 base + Neighbor
// Discovery Protocol/NDP, RFC 4861, plus the SLAAC-relevant pieces of RFC 4862/8106/4191). ICMPv6
// has no transport-layer header of its own -- it rides directly on IP protocol number 58
// (GateKind::IpProtocol, IANA-exclusive to ICMPv6), the same "no port, dispatched purely by IP
// protocol number" shape as fuzz_icmp.cpp's ICMPv4 sibling.
//
// Worth fuzzing on its own merits: this is the one GateKind::IpProtocol decoder in this batch
// (besides IGRP, see fuzz_igrp.cpp) whose real entry point needs more than a bare ByteSpan --
// try_parse_icmpv6 also takes the outer IPv6 packet's own source/destination addresses, needed for
// RFC 4443's checksum pseudo-header (RFC 8200 8.1's shape). This harness passes two fixed,
// plausible IPv6 addresses (a link-local host and the all-nodes multicast group, the realistic
// src/dst pair for the NDP traffic this parser spends most of its logic on) rather than an
// all-zero pair, so checksum validation actually gets to run against a real pseudo-header instead
// of trivially failing every time -- mirroring how decoder.cpp's own IPv6 branch always has real
// addresses to hand Icmpv6Decoder::decode (see DecodeContext::ipv6_src_addr/ipv6_dst_addr,
// protocol_decoder.hpp). It also exercises the NDP option TLV walk (Type+Length*8+Data, RFC 4861
// 4.6) -- a generic TLV loop over attacker bytes, exactly the "never trust a length field enough to
// loop on it unchecked" surface this fuzzing pass targets elsewhere (fox.hpp/bacnet.hpp).
//
// Calls try_parse_icmpv6 directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover Icmpv6Decoder::decode's own thin ProtocolDecoder wrapper or how
// decoder.cpp's IPv6 branch dispatches to it (including how ctx.ipv6_src_addr/ipv6_dst_addr get
// populated from a real captured packet) -- that is covered by fuzz_packet_decode instead.
#include <array>
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/icmpv6.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    // fe80::1 -- a plausible link-local ICMPv6 source (Router/Neighbor Solicitation, Advertisement).
    static const conduitscope::Ipv6Address pseudo_src = {
        0xfe, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};
    // ff02::1 -- the all-nodes multicast group, a common ICMPv6/NDP destination.
    static const conduitscope::Ipv6Address pseudo_dst = {
        0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01};

    try {
        (void)conduitscope::try_parse_icmpv6(payload, pseudo_src, pseudo_dst);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
