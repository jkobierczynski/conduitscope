// SPDX-License-Identifier: Apache-2.0
// fuzz_rmcp.cpp - libFuzzer harness for RMCP + ASF + IPMI (rmcp.hpp) decoding, all sharing the same
// UDP port 623. RMCP's own 4-byte header (Version/Reserved/Sequence/Class) is a thin, self-
// describing envelope around three payload classes: an ASF message (class 0x06 -- Presence
// Pong/Pang etc., a fixed 8-byte header plus a Data-Length-driven body), an IPMI session wrapper
// (class 0x07 -- IPMI 1.5's own AuthType-dependent, sometimes password-padded session header, or
// IPMI 2.0/RMCP+'s own Payload-Type-dependent shape, further carrying an IPMI message with its own
// NetFn/Command/Completion-Code framing, RAKP1-4 key-exchange messages, and Get Channel Auth
// Capabilities responses -- rmcp.hpp's own STATEFULNESS section), or a generic OEM/ACK message
// (class 0x08 or the ACK bit, handled by RmcpUdpDecoder alone). This nested, multi-class, multi-
// version structure is exactly the kind of hand-rolled parsing this fuzzing pass targets, and IPMI
// in particular is this harness's richest target: real session/message header parsing plus RAKP
// key-exchange field decoding, all attacker-reachable over one UDP payload.
//
// Mirrors decoder.cpp's real call shape (RmcpUdpDecoder::decode / AsfUdpDecoder::decode /
// IpmiUdpDecoder::decode in rmcp.cpp): try_parse_rmcp_header on the raw payload first, and only if
// that recognizes a 4-byte header, try_parse_asf and try_parse_ipmi on the SAME payload starting
// after that header (`payload.from(4)`) -- exactly like fuzz_cotp_s7comm.cpp only hands S7comm the
// bytes after a recognized COTP header, not the raw payload. try_parse_asf and try_parse_ipmi are
// both called unconditionally once a 4-byte header is recognized, regardless of the header's own
// Class field, the same "run every reachable entry point against one input" shape fuzz_enip.cpp
// already uses for its own two independent entry points -- real production code additionally
// checks Class before calling each one, but that check exists only to pick which protocol_id a
// result gets tagged with, not to protect either parser from unexpected bytes (both already handle
// a mismatched Class by simply finding nothing useful to decode).
//
// IpmiFlowState (rmcp.hpp's own STATEFULNESS section) tracks only a single "Cipher-Suite-0 already
// seen on this session" bool -- real cross-packet session state, like the DNP3 fragment/COTP
// reassembly state fuzz_dnp3.cpp/fuzz_cotp_s7comm.cpp explicitly say they do NOT cover (that needs
// a live DecodeContext/flow key this harness has no access to). A fresh, default-constructed
// IpmiFlowState is passed on every call instead of persisting one across iterations, matching every
// other harness's single-input-at-a-time scope and keeping a crash reproducible from its own
// crash-<hash> file alone (`try_parse_ipmi` documents nullptr as equally valid for a caller with no
// session to track, so this loses no reachable code path -- only the "already saw cipher suite 0
// earlier in this session" branch, which a crash file replayed standalone could never exercise
// either way).
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/rmcp.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    conduitscope::IpmiFlowState flow_state;

    std::optional<conduitscope::RmcpHeader> header;
    try {
        header = conduitscope::try_parse_rmcp_header(payload);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }
    if (!header) {
        return 0;
    }

    conduitscope::ByteSpan class_payload = payload.from(4);

    try {
        (void)conduitscope::try_parse_asf(class_payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::try_parse_ipmi(class_payload, &flow_state);
    } catch (const conduitscope::ParseError&) {
    }

    return 0;
}
