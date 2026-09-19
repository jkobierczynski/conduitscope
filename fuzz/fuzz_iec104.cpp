// SPDX-License-Identifier: Apache-2.0
// fuzz_iec104.cpp - libFuzzer harness for IEC 60870-5-104 parsing (iec104.hpp): the fixed 6-byte
// APCI (try_parse_iec104_apci: start byte, length, and a 4-byte control field identifying I/S/U
// frame format and, for I/S, the 15-bit send/receive sequence numbers) plus, for an I-format
// frame, the ASDU it carries (decode_iec104_asdu: type ID, variable structure qualifier, cause of
// transmission, common address, and a type-keyed table of information-object encodings) -- the
// same "several independently-fixed structural fields" and "self-describing per-type object
// layout" complexity the original five-target fuzzing plan (docs/DEVELOPMENT.md's "External code
// review and engineering priorities" section) picked DNP3/COTP-S7comm/MQTT for. A dedicated
// harness reaches this parsing logic in far fewer libFuzzer iterations than fuzz_packet_decode
// does, since no unrelated Ethernet/IPv4/TCP header bytes need to happen to parse first.
//
// Mirrors decoder.cpp's real call shape (see its `want_iec104` block): try_parse_iec104_apci on
// the raw payload first, and only for an I-format frame, slice out the declared ASDU span
// (`effective_payload.subspan(6, apci->asdu_length)`) and hand it to decode_iec104_asdu --
// non-I-format frames (S/U) carry no ASDU. `apci->asdu_length` is validated plausible by
// try_parse_iec104_apci itself, but the subspan call can still throw ParseError if it doesn't
// actually fit within `payload` (ByteSpan::subspan is bounds-checked -- see byteio.hpp), so this
// is wrapped in try/catch exactly like decoder.cpp's own equivalent code path relies on the
// caller's outer exception handling for. Does not cover cross-packet reassembly or the "more than
// one APDU coalesced in one TCP payload" loop decoder.cpp also has -- that multi-packet/
// multi-APDU-per-input path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>
#include <optional>

#include "conduitscope/byteio.hpp"
#include "conduitscope/iec104.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    std::optional<conduitscope::Iec104Apci> apci;
    try {
        apci = conduitscope::try_parse_iec104_apci(payload);
    } catch (const conduitscope::ParseError&) {
        return 0;
    }
    if (!apci) {
        return 0;
    }

    if (apci->frame_type == conduitscope::Iec104FrameType::I) {
        try {
            conduitscope::ByteSpan asdu_bytes = payload.subspan(6, apci->asdu_length);
            (void)conduitscope::decode_iec104_asdu(asdu_bytes);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
