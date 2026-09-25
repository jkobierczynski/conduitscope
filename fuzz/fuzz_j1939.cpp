// SPDX-License-Identifier: Apache-2.0
// fuzz_j1939.cpp - libFuzzer harness for SAE J1939 message classification (j1939.hpp), riding on
// the Linux SocketCAN link layer (pcap LINKTYPE_CAN_SOCKETCAN == 227, see can_socketcan.hpp).
//
// try_parse_j1939 does not take raw bytes: it takes an already-parsed CanSocketcanFrame (see
// j1939.hpp's own try_parse_j1939(const CanSocketcanFrame&) signature) -- the same shape
// devicenet.hpp's try_parse_devicenet and canopen.hpp's try_parse_canopen use. This mirrors
// exactly what J1939Decoder::decode itself does (j1939.cpp) and what decoder.cpp's own
// LINKTYPE_CAN_SOCKETCAN branch does for an EFF (extended 29-bit ID) frame -- the only CAN ID
// shape J1939 legitimately uses, categorically disjoint from DeviceNet/CANopen's own standard-ID
// space (see j1939.hpp's own file header comment): parse_socketcan_frame(payload) first, then
// try_parse_j1939(can) on the result -- a two-stage harness, the same shape fuzz_devicenet.cpp/
// fuzz_canopen.cpp use for their own sibling CAN-bus protocols. No Ethernet/IPv4/TCP framing
// needed either way: the raw fuzzer bytes are handed to parse_socketcan_frame exactly as a
// SocketCAN pcap capture record would be. try_parse_j1939 itself accepts an RTR frame (setting
// is_rtr) rather than rejecting it outright the way DeviceNet/CANopen do -- see j1939.hpp's own
// file header comment and try_parse_j1939's own doc comment for why.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/j1939.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan frame(data, size);

    std::optional<conduitscope::CanSocketcanFrame> can;
    try {
        can = conduitscope::parse_socketcan_frame(frame);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }

    try {
        (void)conduitscope::try_parse_j1939(*can);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
