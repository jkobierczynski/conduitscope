// SPDX-License-Identifier: Apache-2.0
// fuzz_igrp.cpp - libFuzzer harness for Cisco IGRP parsing (igrp.hpp, RFC-less -- documented only
// by Cisco and cross-checked against Wireshark's packet-igrp.c). IGRP has no transport-layer
// header of its own -- it rides directly on IP protocol number 9 (GateKind::IpProtocol).
//
// Worth fuzzing on its own merits: try_parse_igrp needs the packet's own IPv4 SOURCE address as a
// second argument, not just a ByteSpan -- IGRP's 3-byte "Network" route-vector field is CLASSFUL
// and encoded relative to that source address for Interior routes (the missing high-order octet is
// taken from the packet's own source IP; see igrp.hpp's file header for the full Interior/System/
// Exterior split). This harness loops the same fuzzer input over two representative fixed source
// addresses -- 10.0.0.1 (a private, plausible IGRP-speaking router) and 0.0.0.0 (the degenerate
// edge case, worth exercising since it's cheap and changes the reconstructed Interior-route network
// byte) -- the same "loop over a small set of representative context values" shape fuzz_mqtt.cpp
// already uses for session_version_hint, since this parameter is real context threaded in by the
// caller (IgrpDecoder::decode reads it from DecodeContext::ip_src_addr, see igrp.cpp) rather than
// something try_parse_igrp derives from the payload itself. The 14-byte-per-route vector walk,
// driven entirely by the header's own Interior+System+Exterior route counts, is the other
// attacker-controlled-length surface this harness reaches.
//
// Calls try_parse_igrp directly on the raw fuzzer bytes plus each fixed source address, exactly
// like try_parse_mqtt_message's hint loop in fuzz_mqtt.cpp. Does not cover IgrpDecoder::decode's
// own thin ProtocolDecoder wrapper or how decoder.cpp's IPv4 branch populates ctx.ip_src_addr from
// a real captured packet -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/igrp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    // 10.0.0.1 and 0.0.0.0, in host byte order -- matching DecodeContext::ip_src_addr's own
    // documented representation (see protocol_decoder.hpp).
    for (uint32_t src_ip : {UINT32_C(0x0a000001), UINT32_C(0x00000000)}) {
        try {
            (void)conduitscope::try_parse_igrp(payload, src_ip);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
