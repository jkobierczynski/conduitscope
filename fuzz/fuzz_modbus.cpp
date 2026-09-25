// SPDX-License-Identifier: Apache-2.0
// fuzz_modbus.cpp - libFuzzer harness for Modbus/TCP (MBAP header + PDU) parsing (modbus.hpp).
// Somewhat surprisingly, Modbus never had its own dedicated harness before this one -- only
// fuzz_packet_decode (the generic dispatch-pipeline harness) ever reached modbus.cpp directly --
// even though it is one of the most foundational, widely-deployed OT protocols this codebase
// decodes, and its own request/response disambiguation is entirely payload-shape-based heuristics
// (see modbus.hpp's own file header) layered on top of a hand-rolled MBAP length field and an
// eight-way function-code dispatch (four read families, two single-write, two multiple-write,
// plus generic exception decoding) -- exactly the "hand-rolled length/state-machine logic" this
// fuzzing pass targets, the same rationale as DNP3/BACnet/IEC104/S7comm/S7comm-Plus.
//
// Calls try_parse_modbus_tcp directly on the raw fuzzer bytes, exactly like
// try_parse_dnp3_transport_and_application / try_parse_s7comm in the other single-entry-point
// harnesses -- no Ethernet/IPv4/TCP framing needed, since it already takes a ByteSpan over what
// would be a TCP payload, the exact call shape ModbusDecoder::decode (modbus.cpp) itself uses
// before applying MBAP-transaction-ID pairing. That pairing (ModbusFlowState::pending, cross-
// packet, session-scoped) needs a live DecodeContext and flow key and is therefore NOT covered
// here -- that multi-packet path is covered by fuzz_packet_decode instead, the same split
// fuzz_dnp3.cpp's own header comment documents for DNP3 fragment reassembly.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/modbus.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_modbus_tcp(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
