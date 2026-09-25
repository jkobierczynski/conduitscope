// SPDX-License-Identifier: Apache-2.0
// fuzz_bgp.cpp - libFuzzer harness for BGP-4 (RFC 4271) parsing (bgp.hpp), plus its curated RFC
// 4760/6793/8203/9234 extensions -- see bgp.hpp's own file header for why a routing protocol is
// decoded here at all (an OT/IT boundary should never carry a live BGP session, so seeing one is
// itself the finding). BGP rides TCP port 179 (GateKind::TcpPortIndependent, same category as
// Modbus/TwinCAT/MELSEC/FINS/OPC UA), needs its own declared-length reassembly (the 19-byte fixed
// header's own Length field), and, per RFC 6793, decodes its AS_PATH attribute differently
// depending on whether this session's own OPEN negotiated 4-octet AS numbers -- exactly the kind
// of hand-rolled length/state-dependent parsing this fuzzing pass targets.
//
// Calls try_parse_bgp_message directly on the raw fuzzer bytes, exactly like
// try_parse_dnp3_transport_and_application/try_parse_s7comm in the other single-entry-point
// harnesses -- no Ethernet/IPv4/TCP framing needed, since it already takes a ByteSpan over what
// would be a TCP payload. `as_width_authoritative`/`as_width_is_four_octet` are exercised at all
// three REACHABLE combinations across separate calls on the same input, the same "loop over extra
// scalar hint values" shape fuzz_mqtt.cpp's own session_version_hint loop uses: (false, false) --
// this session's own OPEN wasn't captured, the non-authoritative length-consistency heuristic
// applies (bgp.hpp's AS_PATH paragraph); (true, false) and (true, true) -- this session's own OPEN
// WAS captured and negotiated 2-byte or 4-octet AS numbers respectively. (false, true) is not a
// real reachable combination (BgpFlowState::four_octet_as_negotiated is only ever meaningful once
// open_seen is true, per bgp.hpp's own BgpFlowState comment), so it is skipped here the same way a
// caller populating these from a real BgpFlowState never produces it either. Does not cover
// BgpDecoder::decode's own coalescing loop (real sessions routinely merge several small KEEPALIVEs
// into one TCP segment) or BgpFlowState's own cross-packet OPEN-negotiation tracking, both of which
// need a live DecodeContext and flow key -- that multi-packet path is covered by
// fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/bgp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    static const bool kCombos[3][2] = {
        {false, false},
        {true, false},
        {true, true},
    };
    for (const auto& combo : kCombos) {
        try {
            (void)conduitscope::try_parse_bgp_message(payload, combo[0], combo[1]);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
