// SPDX-License-Identifier: Apache-2.0
// fuzz_opcua.cpp - libFuzzer harness for OPC UA Binary (UA-TCP / OPC UA Secure Conversation)
// parsing (opcua.hpp): the 8-byte UA-TCP connection-protocol messages, the 12-byte
// SecureConversation chunk header (security/sequence headers included), and the service-layer
// Message body's self-describing Variant/DataValue value decoding -- see opcua.hpp's own file
// header. OPC UA's own binary encoding is little-endian throughout (unlike every other protocol
// this codebase decodes except EtherNet/IP/CIP), and its Variant type is a self-describing,
// recursively-typed value encoding in the same spirit as BACnet's own application-layer TLV tags
// or S7comm-Plus's object model -- exactly the kind of hand-rolled, self-describing parsing this
// fuzzing pass targets.
//
// Calls try_parse_opcua_message directly on the raw fuzzer bytes, exactly like try_parse_enip/
// try_parse_bacnet in the other single-entry-point harnesses -- no Ethernet/IPv4/TCP framing
// needed, since it already takes a ByteSpan over what would be a TCP payload, the exact call shape
// OpcUaDecoder::decode (opcua.cpp) itself uses. `redact` is exercised at both its reachable values
// (true/false) across separate calls on the same input, the same "loop over extra scalar hint
// values" shape fuzz_mqtt.cpp's own session_version_hint loop uses -- it gates whether a decoded
// UserName/Password identity token's cleartext value is masked in OpcUaMessage::notes (see
// opcua.cpp's own redact branch), a real, reachable difference in what gets written for the exact
// same wire bytes depending on --redact/--no-redact. Does not cover OpcUaDecoder::decode's own
// coalescing loop (more than one OPC UA message per TCP payload), which needs a live DecodeContext
// -- that multi-message path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/opcua.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    for (bool redact : {true, false}) {
        try {
            (void)conduitscope::try_parse_opcua_message(payload, redact);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
