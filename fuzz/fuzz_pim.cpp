// SPDX-License-Identifier: Apache-2.0
// fuzz_pim.cpp - libFuzzer harness for PIM-SM/PIM-DM v2 (RFC 7761, RFC 3973) parsing (pim.hpp).
// PIM has no transport-layer header of its own -- it rides directly on IP protocol number 103
// (GateKind::IpProtocol, IANA-exclusive), so this harness is handed the IP payload directly,
// exactly the shape try_parse_pim already takes.
//
// Worth fuzzing on its own merits: PIM's own three "Encoded Address" formats (Unicast/Group/
// Source, RFC 7761 4.9) are reused across nearly every message type's body, so a single length or
// Address-Family/Encoding-Type mistake in that shared decoding path can reach many message types at
// once. Register-Stop carries an Encoded-Group + Encoded-Unicast pair; Join/Prune (and Graft/
// Graft-Ack, which share Join/Prune's exact wire format per RFC 3973) carries an upstream-neighbor
// address plus a LIST of (group, joined-sources, pruned-sources) tuples, each inner source/group
// count itself attacker-controlled -- a doubly-nested count-driven walk. Bootstrap carries its own
// list of (group, candidate-RP list) tuples. Register additionally re-extracts the (source, group)
// of an ENCAPSULATED multicast data packet nested inside the PIM message, another "parser reading
// attacker bytes shaped like a different protocol" surface, similar in spirit to what ICMP(v4)'s
// embedded-datagram re-parse does (see fuzz_icmp.cpp).
//
// Calls try_parse_pim directly on the raw fuzzer bytes, exactly like try_parse_icmp in
// fuzz_icmp.cpp. Does not cover PimDecoder::decode's own thin ProtocolDecoder wrapper (trivial,
// ctx-independent -- see pim.hpp) -- that is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/pim.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_pim(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
