// SPDX-License-Identifier: Apache-2.0
// fuzz_dhcpv6.cpp - libFuzzer harness for DHCPv6 (RFC 8415, dhcpv6.hpp) decoding -- UDP port 546
// (client) and 547 (server/relay). DHCPv6 has two genuinely different message headers dispatched on
// the first byte alone (client/server's flat option list vs. RELAY-FORW/RELAY-REPL's fixed
// hop-count/link-address/peer-address header, dhcpv6.hpp's own WIRE SHAPES section), and its option
// TLV walk recurses: IA_NA/IA_TA/IA_PD each carry their own nested options (including, for IA_PD, a
// nested IA Prefix, itself carrying a further nested options list) -- real recursive, length-driven
// parsing over attacker-controlled option-len fields at multiple nesting levels, exactly what this
// fuzzing pass targets.
//
// Calls try_parse_dhcpv6 directly on the raw fuzzer bytes, exactly like the other single-entry-point
// harnesses -- no Ethernet/IPv4/UDP framing needed, since it already takes a ByteSpan over what
// would be a UDP payload, and covers BOTH wire shapes (client/server and relay) since the function
// dispatches on the message's own first byte rather than needing a caller-supplied hint. No
// cross-packet state exists for this protocol.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dhcpv6.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_dhcpv6(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
