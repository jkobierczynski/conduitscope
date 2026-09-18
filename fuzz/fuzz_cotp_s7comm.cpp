// SPDX-License-Identifier: Apache-2.0
// fuzz_cotp_s7comm.cpp - libFuzzer harness for TPKT/COTP framing (cotp.hpp) and the S7comm
// application layer it carries (s7comm.hpp) -- two more of the five parsers
// docs/DEVELOPMENT.md's fuzzing plan names as foremost targets. TPKT/COTP is its own
// length-prefixed, multi-frame-chaining framing (see CotpFragmentReassembly in decoder.hpp for
// the cross-frame case this harness does NOT cover -- see below), and S7comm's own item/address
// encoding is exactly the kind of hand-rolled parsing this pass targets.
//
// Mirrors decoder.cpp's real call shape: try_parse_tpkt_cotp on the raw payload first, and only
// if that recognizes a Data (DT) frame, try_parse_s7comm on ITS user_data (S7comm rides inside
// COTP's user data, not the raw TCP payload directly). A non-Data COTP frame (CR/CC/DR/etc.) has
// no user_data to hand onward, exactly as decoder.cpp itself only attempts S7comm for Data
// frames.
//
// Like fuzz_dnp3, this is narrower than fuzz_packet_decode by design: it skips Ethernet/IPv4/TCP
// framing entirely and does not cover cross-packet COTP fragment reassembly
// (Decoder::reassemble_cotp_data_frame / cotp_reassembly_, which needs a live Decoder and flow
// key) -- that multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/s7comm.hpp"

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
        (void)conduitscope::try_parse_s7comm(cotp->user_data);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
