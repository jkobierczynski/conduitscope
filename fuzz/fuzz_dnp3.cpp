// SPDX-License-Identifier: Apache-2.0
// fuzz_dnp3.cpp - libFuzzer harness for DNP3 link/transport/application parsing (dnp3.hpp), one
// of the five parsers docs/DEVELOPMENT.md names as the fuzzing plan's foremost targets. DNP3's
// data-link frame carries its own explicit length and CRC fields, and the transport layer adds a
// FIR/FIN/SEQ reassembly scheme on top -- exactly the "hand-rolled length/state-machine logic"
// this fuzzing pass is meant to stress.
//
// This calls the same two public, standalone entry points decoder.cpp itself calls
// (try_parse_dnp3_link_layer then try_parse_dnp3_transport_and_application) directly on the raw
// fuzzer bytes, with no Ethernet/IPv4/TCP framing needed -- both already take a ByteSpan over
// exactly the bytes a TCP payload would contain. This is deliberately narrower than
// fuzz_packet_decode: it reaches DNP3's own parsing logic in far fewer libFuzzer iterations
// because no unrelated Ethernet/IP/TCP header bytes need to happen to parse first. It does not
// cover cross-packet fragment reassembly (Dnp3Decoder::process_frame / Dnp3ReassemblyState, which
// require a live DecodeContext and flow key) -- that multi-packet path is covered by
// fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dnp3.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);
    std::vector<std::string> notes;

    std::optional<conduitscope::Dnp3LinkFrame> link;
    try {
        link = conduitscope::try_parse_dnp3_link_layer(payload, notes);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }
    if (!link) {
        return 0;
    }

    try {
        // Mirrors decoder.cpp's own call shape: the link frame (mutable -- this is where
        // block_count/crc fields get finalized) plus the same payload the link frame was parsed
        // from, since transport/application parsing reads user data starting after the link
        // header rather than being handed an already-sliced buffer.
        (void)conduitscope::try_parse_dnp3_transport_and_application(*link, payload);
    } catch (const conduitscope::ParseError&) {
        // A per-frame parse failure is an expected, handled outcome (see DecodedPacket's
        // notes-based error reporting) -- not itself a bug for libFuzzer to flag. ASan/UBSan
        // still catch actual memory-safety violations regardless of what gets caught here.
    }

    return 0;
}
