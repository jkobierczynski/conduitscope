// SPDX-License-Identifier: Apache-2.0
// fuzz_devicenet.cpp - libFuzzer harness for DeviceNet (CAN-bus CIP) message-group
// classification (devicenet.hpp), riding on the Linux SocketCAN link layer
// (pcap LINKTYPE_CAN_SOCKETCAN == 227, see can_socketcan.hpp).
//
// try_parse_devicenet does not take raw bytes: it takes an already-parsed CanSocketcanFrame
// (see devicenet.hpp's own try_parse_devicenet(const CanSocketcanFrame&) signature). This
// mirrors exactly what DeviceNetDecoder::decode itself does (devicenet.cpp) and what
// decoder.cpp's own LINKTYPE_CAN_SOCKETCAN branch does: parse_socketcan_frame(payload) first,
// then try_parse_devicenet(can) on the result -- a two-stage harness, the same shape
// fuzz_dnp3.cpp/fuzz_cotp_s7comm.cpp use for their own two-stage entry points. No Ethernet/
// IPv4/TCP framing needed either way: the raw fuzzer bytes are handed to parse_socketcan_frame
// exactly as a SocketCAN pcap capture record would be.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/devicenet.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan frame(data, size);

    std::optional<conduitscope::CanSocketcanFrame> can;
    try {
        can = conduitscope::parse_socketcan_frame(frame);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }

    try {
        (void)conduitscope::try_parse_devicenet(*can);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
