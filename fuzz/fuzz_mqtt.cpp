// SPDX-License-Identifier: Apache-2.0
// fuzz_mqtt.cpp - libFuzzer harness for MQTT message parsing (mqtt.hpp: v3.1/v3.1.1/v5.0,
// including Sparkplug B) -- the last of the five parsers docs/DEVELOPMENT.md's fuzzing plan
// names as foremost targets. MQTT's variable-length "Remaining Length" encoding (a 1-4 byte
// base-128 varint) and its many per-packet-type property/payload layouts are exactly the
// hand-rolled parsing this pass is meant to stress -- and this is also the protocol whose
// version-ambiguity bug CI's very first run already caught (see docs/DEVELOPMENT.md's CI
// section: the Sparkplug B "Bytes"/"File" ternary that only Clang's stricter overload
// resolution rejected), a reminder that this parser specifically has already had at least one
// real, previously-unnoticed defect.
//
// Calls try_parse_mqtt_message directly on the raw fuzzer bytes, exactly like
// try_parse_dnp3_transport_and_application / try_parse_s7comm in the other harnesses -- no
// Ethernet/IPv4/TCP framing needed, since it already takes a ByteSpan over what would be a TCP
// payload. `session_version_hint` is exercised at both its defined values (0 = unknown, and 5 =
// MQTT v5) across separate runs of this same input, rather than picked once, since decoder.cpp
// threads a per-session learned hint through this parameter (see Decoder::mqtt_session_version_)
// and the hint measurably changes how certain ambiguous packet types are parsed -- both are real,
// reachable values for the exact same wire bytes depending on what a CONNECT packet earlier in
// the session declared.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/mqtt.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    for (uint8_t hint : {static_cast<uint8_t>(0), static_cast<uint8_t>(5)}) {
        try {
            (void)conduitscope::try_parse_mqtt_message(payload, hint);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
