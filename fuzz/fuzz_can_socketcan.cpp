// SPDX-License-Identifier: Apache-2.0
// fuzz_can_socketcan.cpp - libFuzzer harness for Linux SocketCAN pcap capture framing
// (can_socketcan.hpp, pcap LINKTYPE_CAN_SOCKETCAN == 227): the shared 8-byte fixed CAN frame
// header (big-endian CAN ID + flags, Payload Length, FD Flags, two reserved bytes) every
// CAN-bus protocol in this codebase (DeviceNet, CANopen, J1939) rides on top of.
//
// Calls the single real, standalone entry point decoder.cpp itself calls directly
// (parse_socketcan_frame), and each of the CAN-bus decoders' own decode() methods also call
// internally (see devicenet.cpp/canopen.cpp/j1939.cpp's own DeviceNetDecoder::decode/
// CanopenDecoder::decode/J1939Decoder::decode) -- on the raw fuzzer bytes directly, with no
// Ethernet/IPv4/TCP framing needed: a SocketCAN pcap capture record IS the bytes
// parse_socketcan_frame(ByteSpan) expects, with nothing above it (see can_socketcan.hpp's own
// file header comment: "a pcap file captured from a CAN bus ... carries one small fixed-format
// record per CAN frame, directly, with nothing above it"). This is deliberately narrower than
// fuzz_packet_decode and does not cover any higher CAN-bus protocol's own message semantics --
// that is covered by fuzz_devicenet/fuzz_canopen/fuzz_j1939 instead, each of which also drives
// this same parse_socketcan_frame call as their own harness's first stage.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan frame(data, size);

    try {
        (void)conduitscope::parse_socketcan_frame(frame);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome (fewer than the fixed 8-byte header present) -- see
        // fuzz_dnp3.cpp's identical comment. ASan/UBSan still catch actual memory-safety
        // violations regardless of what gets caught here.
    }

    return 0;
}
