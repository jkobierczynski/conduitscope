// SPDX-License-Identifier: Apache-2.0
// fuzz_pppoe.cpp - libFuzzer harness for PPPoE parsing (pppoe.hpp, RFC 2516): the 6-byte PPPoE
// header (Ver/Type/Code/Session ID/Length), plus, for the Session stage only, a shallow look at the
// encapsulated PPP frame's own leading Protocol field (RFC 1661 section 2). PPPoE rides directly on
// raw Ethernet -- no IP or transport layer at all -- and is carried on two distinct EtherTypes,
// Discovery (0x8863) and Session (0x8864), which decoder.cpp registers as two separate
// ProtocolDecoder instances (PppoeDiscoveryDecoder/PppoeSessionDecoder, see pppoe.cpp) that both
// converge on the exact same try_parse_pppoe entry point with only their `is_session_ethertype`
// argument differing -- real context threaded in by which EtherType matched, not something
// try_parse_pppoe derives from the payload itself, the same "loop over a small set of representative
// context values" shape fuzz_mqtt.cpp's session_version_hint and fuzz_igrp.cpp's src_ip loop
// already use in this codebase. This flag changes which Code values are considered valid and
// whether the PPP-Protocol-field body is even attempted, so both values are real, independently
// reachable parsing paths worth fuzzing separately rather than picking one.
//
// Calls try_parse_pppoe directly on the raw fuzzer bytes at both is_session_ethertype values,
// exactly like try_parse_mqtt_message's hint loop in fuzz_mqtt.cpp -- no Ethernet/IPv4/TCP/UDP
// framing needed, since it already takes a ByteSpan over exactly what would be an EtherType-0x8863/
// 0x8864 Ethernet payload. Does not cover decoder.cpp's own EtherType-cascade dispatch
// (ethertype_registry()) that reaches this decoder in a real capture, nor anything past the PPP
// frame's own Protocol field (pppoe.hpp is explicit that the PPP session's own payload is never
// followed) -- the full-packet dispatch path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/pppoe.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    for (bool is_session_ethertype : {false, true}) {
        try {
            (void)conduitscope::try_parse_pppoe(payload, is_session_ethertype);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
