// SPDX-License-Identifier: Apache-2.0
// fuzz_bacnet.cpp - libFuzzer harness for BACnet/IP (BVLC Annex J) parsing (bacnet.hpp). BACnet's
// application layer is a self-describing TLV encoding (ASHRAE 135 clause 20.2.1: a tag byte
// carries context/application class, type, and either an inline length or an extended
// length-of-length-of-length escape sequence), plus several fixed/variable table-entry formats
// for the BVLC Foreign-Device-Table/Broadcast-Distribution-Table messages -- exactly the kind of
// hand-rolled length/tag-driven parsing the original five-target fuzzing plan
// (docs/DEVELOPMENT.md's "External code review and engineering priorities" section) was scoped
// around, and this specific parser already has a confirmed track record: fuzz_packet_decode found
// a real signed-left-shift UB in bacnet.cpp's read_signed64 (fixed; see that fix's own commit/
// patch and decoder.cpp's read_signed64 comment) before this dedicated harness existed. A
// dedicated harness reaches BACnet's own parsing logic in far fewer libFuzzer iterations than
// fuzz_packet_decode does, since no unrelated Ethernet/IPv4/UDP header bytes need to happen to
// parse first.
//
// Calls try_parse_bacnet directly on the raw fuzzer bytes -- it already takes a ByteSpan over
// exactly what a UDP payload would contain, no framing needed (BACnet/IP has no TCP transport).
// try_parse_bacnet is documented never to throw, but this still wraps the call in try/catch, the
// same defensive posture every other harness here takes, in case a future edit introduces a
// throwing code path this comment doesn't yet reflect.
#include <cstdint>
#include <cstddef>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/byteio.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_bacnet(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
