// SPDX-License-Identifier: Apache-2.0
// fuzz_mms.cpp - libFuzzer harness for TPKT/COTP framing (cotp.hpp, shared with
// fuzz_cotp_s7comm.cpp/fuzz_s7comm_plus.cpp) and the MMS (Manufacturing Message Specification,
// ISO 9506) application layer it carries (mms.hpp). MMS rides the exact same TPKT/COTP framing
// classic S7comm and S7comm-Plus do (GateKind::CotpPayload, mms.hpp), and its own ASN.1 BER-
// encoded, self-describing Data CHOICE type (see mms.hpp's "ICCP/TASE.2 recognition" section) is
// closer in spirit to OPC UA's Variant or S7comm-Plus's object model than to classic S7comm's own
// fixed ROSCTR/function/parameter/data layout -- a third, structurally distinct application layer
// riding the same COTP transport fuzz_cotp_s7comm.cpp/fuzz_s7comm_plus.cpp already cover, so this
// harness's mutations reach parsing logic neither of those two exercises.
//
// Mirrors decoder.cpp's real call shape for this protocol (see its CotpPayload dispatch block,
// same as MmsDecoder, gate_kind() == CotpPayload -- protocol_decoder.hpp): try_parse_tpkt_cotp on
// the raw payload first, and only if that recognizes a Data (DT) frame, try_parse_mms on ITS
// user_data -- MMS rides inside COTP's user data, not the raw TCP payload directly, the identical
// framing relationship fuzz_cotp_s7comm.cpp/fuzz_s7comm_plus.cpp already document. A non-Data COTP
// frame (CR/CC/DR/etc.) has no user_data to hand onward, exactly as decoder.cpp itself only
// attempts MMS for Data frames.
//
// Like fuzz_cotp_s7comm/fuzz_s7comm_plus, this is narrower than fuzz_packet_decode by design: it
// skips Ethernet/IPv4/TCP framing entirely and does not cover cross-packet COTP fragment
// reassembly (Decoder::reassemble_cotp_data_frame/cotp_reassembly_, which needs a live Decoder and
// flow key) -- that multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/mms.hpp"

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
        (void)conduitscope::try_parse_mms(cotp->user_data);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
