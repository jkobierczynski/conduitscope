// SPDX-License-Identifier: Apache-2.0
// fuzz_canopen.cpp - libFuzzer harness for CANopen (CiA 301) message classification
// (canopen.hpp), riding on the Linux SocketCAN link layer
// (pcap LINKTYPE_CAN_SOCKETCAN == 227, see can_socketcan.hpp).
//
// try_parse_canopen does not take raw bytes: it takes an already-parsed CanSocketcanFrame
// (see canopen.hpp's own try_parse_canopen(const CanSocketcanFrame&) signature) -- the same
// shape devicenet.hpp's try_parse_devicenet uses. This mirrors exactly what
// CanopenDecoder::decode itself does (canopen.cpp) and what decoder.cpp's own
// LINKTYPE_CAN_SOCKETCAN branch does (under --protocol canopen -- canopen deliberately does not
// join Auto mode, see canopen.hpp's own file header "THE DEVICENET-VS-CANOPEN DISPATCH
// COLLISION" section, which is irrelevant to this harness since it calls try_parse_canopen
// directly and unconditionally): parse_socketcan_frame(payload) first, then
// try_parse_canopen(can) on the result -- a two-stage harness, the same shape fuzz_dnp3.cpp/
// fuzz_cotp_s7comm.cpp use for their own two-stage entry points, and the same shape
// fuzz_devicenet.cpp uses for its sibling CAN-bus protocol. No Ethernet/IPv4/TCP framing needed
// either way: the raw fuzzer bytes are handed to parse_socketcan_frame exactly as a SocketCAN
// pcap capture record would be. This exercises try_parse_canopen's own SDO expedited/segmented
// transfer decoding (see canopen.cpp's try_parse_sdo) as well as NMT/EMCY/PDO/SYNC/TIME/heartbeat
// classification, since all of those live behind this one entry point.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/canopen.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan frame(data, size);

    std::optional<conduitscope::CanSocketcanFrame> can;
    try {
        can = conduitscope::parse_socketcan_frame(frame);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }

    try {
        (void)conduitscope::try_parse_canopen(*can);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
