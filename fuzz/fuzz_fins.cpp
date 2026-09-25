// SPDX-License-Identifier: Apache-2.0
// fuzz_fins.cpp - libFuzzer harness for Omron FINS (Factory Interface Network Service) parsing
// (fins.hpp), over TCP and UDP port 9600. try_parse_fins_frame is context-free like
// try_parse_melsec, but FINS has "A GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC" (fins.hpp's own
// section title): Memory Area Read (0101) and Multiple Memory Area Read (0104) responses need
// their own matching request's device list to split values, so this decoder tracks that list, not
// just a command name, in FinsPendingRequest -- when `pending_devices` is null, as it always is
// for this standalone/context-free call, those two commands' responses decode structurally only.
//
// FINS is the one dual TCP+UDP protocol in this wave whose TWO entry points genuinely differ in
// SHAPE, not just in which byte range reaches an identical parser (contrast kerberos.hpp's own
// "same parser, different offset" case): FinsUdpDecoder::decode (fins.cpp) hands
// try_parse_fins_frame the raw datagram directly -- UDP FINS has no envelope of its own. FinsTcpDecoder
// ::decode instead sits behind FINS/TCP's own distinct "FINS" + 4-byte length + 4-byte command +
// 4-byte error-code envelope (fins_tcp_declared_length, fins.hpp, is the exact real production
// function that validates the magic/length half of that envelope, called here unmodified -- no
// validation logic is duplicated); only command 0x02 (Frame Send) unwraps into the SAME
// try_parse_fins_frame on the envelope's trailing data (the 16 bytes after which the FINS-TCP
// header ends, matching FinsTcpDecoder::decode's own Cursor arithmetic exactly: 4 magic + 4 length
// + 4 command + 4 error-code). Every other TCP command (Node Address Data Send, Frame Send Error
// Notification, Connection Confirmation, ...) is envelope-only and never reaches
// try_parse_fins_frame at all -- decoded instead by FinsTcpDecoder::decode's own small per-command
// summary logic, which is not itself hand-rolled length/state-machine parsing and is left to
// fuzz_packet_decode's broader dispatch-pipeline coverage.
//
// Calls try_parse_fins_frame directly on the raw fuzzer bytes for the UDP entry point, and, for the
// TCP entry point, peeks the envelope's own command field (a single real-production-function call
// plus one trivial 4-byte field read, not a reimplementation of the envelope parser) to decide
// whether to unwrap into the same call on the trailing data -- exactly FinsTcpDecoder::decode's own
// dispatch. `pending_devices` is left at its default nullptr on both calls, the same "no live
// FinsFlowState" posture a standalone/context-free caller takes. Does not cover FinsFlowState's own
// cross-packet device-list correlation, or FinsTcpDecoder::decode's own non-Frame-Send envelope
// summary logic -- both are fuzz_packet_decode's territory.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/fins.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    // UDP entry point: no envelope of its own, the raw datagram is handed straight to the parser.
    try {
        (void)conduitscope::try_parse_fins_frame(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    // TCP entry point: real magic+length validation via fins_tcp_declared_length (no logic
    // duplicated), then peek the 4-byte command field FinsTcpDecoder::decode itself reads at the
    // same offset -- only command 0x02 (Frame Send) unwraps into the shared parser.
    if (conduitscope::fins_tcp_declared_length(payload) && payload.size() >= 16) {
        try {
            conduitscope::Cursor c(payload);
            c.skip(8);  // 4-byte "FINS" magic + 4-byte length, already validated above
            uint32_t cmd = c.u32be();
            if (cmd == 0x02) {
                (void)conduitscope::try_parse_fins_frame(payload.from(16));
            }
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
