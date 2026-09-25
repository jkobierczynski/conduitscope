// SPDX-License-Identifier: Apache-2.0
// fuzz_twincat.cpp - libFuzzer harness for Beckhoff TwinCAT / ADS (Automation Device Specification)
// parsing (twincat.hpp), over AMS/TCP (TCP port 48898 / 0xBF02, GateKind::TcpPortIndependent --
// tried opportunistically on every TCP port, decoded directly off the TCP payload, per twincat.hpp's
// own file header). The AMS/TCP 6-byte length-prefix framing plus the AMS header's own command-ID-
// keyed ADS data layout (see try_parse_twincat's own gate paragraph, and the
// kMaxPlausibleAdsDataLength plausibility ceiling twincat.hpp mentions, the same defense-in-depth
// posture Modbus's MBAP length and Kerberos's TCP length prefix take) is exactly the "hand-rolled
// length/state-machine logic" this fuzzing pass targets -- and TwinCAT was the first protocol in
// this codebase built entirely on the ProtocolDecoder interface, per twincat.hpp's own file header.
//
// Calls try_parse_twincat directly on the raw fuzzer bytes, exactly like try_parse_modbus_tcp/
// try_parse_melsec in the other single-entry-point harnesses -- no Ethernet/IPv4/TCP framing
// needed, since it already takes a ByteSpan over what would be a TCP payload, the exact call shape
// TwinCatDecoder::decode (twincat.cpp) itself uses before applying request/response pairing. That
// pairing (TwinCatFlowState::pending, cross-packet, session-scoped) needs a live DecodeContext and
// flow key and is therefore NOT covered here -- that multi-packet path is covered by
// fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/twincat.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_twincat(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
