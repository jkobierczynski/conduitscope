// SPDX-License-Identifier: Apache-2.0
// fuzz_umas.cpp - libFuzzer harness for UMAS (umas.hpp), the Unity Pro/Control Expert engineering-
// station protocol carried inside Modbus/TCP function code 0x5A. decode_umas is already reachable
// transitively through fuzz_modbus.cpp's own try_parse_modbus_tcp (base_fc == 0x5A dispatches to
// it, modbus.cpp), but that path only ever hands it 0x5A-prefixed PDUs about 1/128th of the time a
// random fuzzer byte happens to land there -- the same "reachable but thinly exercised through a
// generic dispatcher" reasoning fuzz_dnp3.cpp's own header comment gives for having its own
// dedicated harness alongside fuzz_packet_decode. This harness instead calls decode_umas directly
// on the raw fuzzer bytes as the PDU (the exact call shape modbus.cpp's own switch case uses),
// giving every fuzzer iteration a guaranteed hit on UMAS-specific code -- particularly worth doing
// since UMAS is this codebase's first protocol decoded entirely from unofficial, reverse-
// engineered sources (see umas.hpp's own header comment), with no official spec's own edge cases
// to have already anticipated.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/umas.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan pdu_data(data, size);
    conduitscope::UmasFrame frame;

    try {
        conduitscope::decode_umas(pdu_data, frame);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment. decode_umas itself
        // never throws on its own (every branch is bounds-checked via ByteSpan::at/from, which
        // throw ParseError rather than reading out of range -- see byteio.hpp), so this guards
        // only against a future change introducing an unchecked read, not current behavior.
    }

    return 0;
}
