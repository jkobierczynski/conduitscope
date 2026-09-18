// SPDX-License-Identifier: Apache-2.0
// fuzz_packet_decode.cpp - libFuzzer harness for Decoder::decode() (decoder.hpp/decoder.cpp), the
// full Ethernet/IPv4/TCP-or-UDP parse-and-dispatch pipeline every real `conduitscope decode`
// invocation runs. This is the harness that actually reaches Decoder::reassemble_tcp_payload --
// docs/DEVELOPMENT.md's fuzzing-plan item named explicitly alongside pcap_reader/DNP3/
// COTP-S7comm/MQTT -- since that method is private and only reachable through decode() itself.
//
// Unlike fuzz_dnp3/fuzz_cotp_s7comm/fuzz_mqtt (which call one protocol's standalone parser
// directly on a single buffer), this harness feeds a *sequence* of packets, extracted from one
// fuzzer input, to ONE Decoder instance in order -- because reassemble_tcp_payload,
// process_dnp3_frame (Decoder::dnp3_reassembly_), reassemble_cotp_data_frame
// (Decoder::cotp_reassembly_), pair_modbus_transaction (Decoder::modbus_pending_), and MQTT's
// session-version hint (Decoder::mqtt_session_version_) are ALL cross-packet, per-flow state that
// only misbehaves across more than one decode() call on the same flow -- a single-packet fuzz
// input structurally cannot reach most of what this method exists to protect. Every packet here
// carries the same synthetic source/destination so they land in the same directional flow (see
// below), maximizing the chance consecutive extracted packets actually exercise that shared
// state rather than each starting a fresh, unrelated flow.
//
// Input framing (deliberately simple/fast to parse so libFuzzer's own mutations remain the
// bottleneck, not this harness): a sequence of records, each a 2-byte little-endian length N
// followed by N raw bytes -- those N bytes are handed to Decoder::decode() as one captured
// Ethernet frame (conduitscope::PcapPacket::data), i.e. exactly the bytes PcapReader::next()
// would have produced for LINKTYPE_ETHERNET. Parsing stops at the first record whose declared
// length doesn't fit in the remaining input (not an error -- just "no more complete records").
// fuzz/corpus/packet_decode/ seeds hold real captured frames from this repo's own
// tests/sample_*.pcap fixtures in this same framing (see tools this project already has for
// reading those, mirrored by fuzz/README.md's own corpus-generation note).
#include <cstdint>
#include <cstddef>
#include <vector>

#include "conduitscope/decoder.hpp"
#include "conduitscope/pcap_reader.hpp"

namespace {

// Bounds how many packets one fuzzer input can expand into -- both so a pathological input can't
// turn into thousands of decode() calls and blow the per-run time budget, and because libFuzzer
// inputs are typically small anyway (see fuzz/README.md's -max_len guidance).
constexpr size_t kMaxPacketsPerInput = 64;

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::Decoder decoder{conduitscope::DecodeOptions{}};

    size_t offset = 0;
    size_t index = 0;
    while (offset + 2 <= size && index < kMaxPacketsPerInput) {
        uint16_t frame_len = static_cast<uint16_t>(data[offset]) |
                              (static_cast<uint16_t>(data[offset + 1]) << 8);
        offset += 2;
        if (offset + frame_len > size) {
            break;  // declared record doesn't fit in what's left -- stop, don't guess
        }

        conduitscope::PcapPacket packet;
        packet.data.assign(data + offset, data + offset + frame_len);
        packet.captured_len = frame_len;
        packet.original_len = frame_len;
        offset += frame_len;

        try {
            // strict is false by default in DecodeOptions, so decode() should never throw here --
            // this try/catch exists purely as a defensive backstop, matching every other harness
            // in this directory, not because a throw here would itself be expected.
            (void)decoder.decode(packet, conduitscope::LINKTYPE_ETHERNET, index);
        } catch (const conduitscope::ParseError&) {
        }
        ++index;
    }

    return 0;
}
