// SPDX-License-Identifier: Apache-2.0
// fuzz_s7comm_plus.cpp - libFuzzer harness for TPKT/COTP framing (cotp.hpp, shared with
// fuzz_cotp_s7comm.cpp) and the S7comm-Plus application layer it carries (s7commplus.hpp).
// S7comm-Plus is object-oriented on the wire -- self-describing typed values keyed by numeric
// object/attribute/symbol IDs, more like MMS's Data CHOICE or OPC UA's Variant than classic
// S7comm's own fixed ROSCTR/function/parameter/data layout -- and, per s7commplus.hpp's own file
// header, it has never been officially published by Siemens: this decoder's entire understanding
// of the wire format comes from independent, community reverse-engineering, which makes it a
// higher-uncertainty, higher-value fuzzing target than a vendor-documented protocol would be.
// Exactly the "hand-rolled length/state-machine logic" the original five-target fuzzing plan
// (docs/DEVELOPMENT.md's "External code review and engineering priorities" section) was scoped
// around, for a sibling protocol classic S7comm/COTP fuzzing (fuzz_cotp_s7comm.cpp) doesn't reach
// -- S7comm-Plus's own protocol id byte (0x72) diverts it onto a completely different parser than
// classic S7comm's (0x32), so the existing harness's mutations essentially never reach this code.
//
// Mirrors decoder.cpp's real call shape for this protocol (see its `want_s7commplus` block):
// try_parse_tpkt_cotp on the raw payload first, and only if that recognizes a Data (DT) frame,
// try_parse_s7comm_plus on ITS user_data -- S7comm-Plus rides inside COTP's user data, not the raw
// TCP payload directly, the identical framing relationship fuzz_cotp_s7comm.cpp already documents
// for classic S7comm. A non-Data COTP frame (CR/CC/DR/etc.) has no user_data to hand onward,
// exactly as decoder.cpp itself only attempts S7comm-Plus for Data frames.
//
// Like fuzz_cotp_s7comm, this is narrower than fuzz_packet_decode by design: it skips
// Ethernet/IPv4/TCP framing entirely and does not cover cross-packet COTP fragment reassembly
// (Decoder::reassemble_cotp_data_frame / cotp_reassembly_, which needs a live Decoder and flow
// key, and which real decoder.cpp dispatch actually goes through before reaching try_parse_s7comm_plus
// -- this harness calls it directly on one COTP Data frame's own user_data instead) -- that
// multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/s7commplus.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    std::optional<conduitscope::CotpFrame> cotp;
    try {
        cotp = conduitscope::try_parse_tpkt_cotp(payload);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }
    if (!cotp || cotp->kind != conduitscope::CotpPduKind::Data) {
        return 0;
    }

    try {
        (void)conduitscope::try_parse_s7comm_plus(cotp->user_data);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
