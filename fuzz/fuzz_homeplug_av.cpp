// SPDX-License-Identifier: Apache-2.0
// fuzz_homeplug_av.cpp - libFuzzer harness for HomePlug AV / HomePlug AV2 powerline networking
// parsing (homeplug_av.hpp): the MME (Management Message Entry) header, MMTYPE's Kind/Category
// bitfields plus the curated message-name table, the MMV/header-size edge cases the spec documents
// (a shorter header for MMV==0x00 Manufacturer-Specific/Vendor-Specific categories), and the
// bounded set of fully field-decoded payload shapes (CC_DISCOVER_LIST.CNF's station/network arrays,
// CM_SET_KEY.REQ's key-exchange fields, CM_BRG_INFO.CNF's bridge/station list). HomePlug AV rides
// directly on raw Ethernet (EtherType 0x88E1) -- no IP or transport layer at all. The header-size
// edge case and the per-message variable-length array walks are exactly the hand-rolled parsing
// this fuzzing pass targets.
//
// Calls try_parse_homeplug_av directly on the raw fuzzer bytes, exactly like
// try_parse_dnp3_link_layer in fuzz_dnp3.cpp -- no Ethernet/IPv4/TCP/UDP framing needed, since it
// already takes a ByteSpan over exactly what would be an EtherType-0x88E1 Ethernet payload. Does
// not cover decoder.cpp's own EtherType-cascade dispatch (ethertype_registry()) that reaches this
// decoder in a real capture, nor DecodeContext::redact_secrets (this cascade's one real reader,
// gating whether CM_SET_KEY.REQ's nw_key field is shown) -- both redaction states are wired through
// unconditionally by decoder.cpp before calling decode(), not something try_parse_homeplug_av
// itself branches on, so a single call here already reaches its full parsing surface; the redaction
// choice itself is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/homeplug_av.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_homeplug_av(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
