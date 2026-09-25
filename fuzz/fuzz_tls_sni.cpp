// SPDX-License-Identifier: Apache-2.0
// fuzz_tls_sni.cpp - libFuzzer harness for the DNS-over-HTTPS detector (tls_sni.hpp): a TLS record/
// handshake header parser (ContentType/version/length, then HandshakeType/length) feeding a TLS
// extension walk (server_name/SNI, ALPN) over a ClientHello body, gated against a curated table of
// known public DoH resolver hostnames -- exactly the hand-rolled length/state-machine logic this
// fuzzing pass targets, and this codebase own only TLS-layer parser, genuinely different in shape
// from every OT/ICS protocol the first two fuzzing waves cover.
//
// TWO ENTRY POINTS, ONE HARNESS -- the same "independent entry points, same input, one harness"
// shape fuzz_enip.cpp own header comment establishes for its own two entry points:
//
//   1. try_detect_doh(tcp_payload) -- the function decoder.cpp itself actually calls (via
//      DohDecoder::decode, tls_sni.cpp): a full 5-byte TLS record header check, then delegates to
//      try_parse_tls_client_hello/try_parse_tls_handshake_client_hello for the handshake body, then
//      matches the resulting SNI against the curated known-DoH-resolver table. Called here directly
//      on the raw fuzzer bytes, mirroring decoder.cpp own real call shape exactly.
//
//   2. try_parse_tls_handshake_client_hello(handshake_msg) -- the inner half try_detect_doh
//      eventually reaches, but ALSO an independently, directly reachable entry point of its own:
//      quic.cpp calls this exact same function directly on a QUIC CRYPTO frame own payload, which
//      starts at the Handshake header itself (HandshakeType + 3-byte length + body) with NO 5-byte
//      TLS record wrapper in front of it at all (QUIC own frame layer supersedes TCP-era record
//      framing, RFC 9001 section 4) -- a genuinely different byte offset/shape from what
//      try_detect_doh own path ever hands it. A fuzzer driving only try_detect_doh would need to
//      first mutate a valid 5-byte record header before ever reaching this handshake-body parsing
//      logic (extension walk, SNI/ALPN extraction) at all; calling this function directly on the
//      same raw input, with no record-header bytes required first, reaches that logic in far fewer
//      iterations -- the same reasoning fuzz_enip.cpp own header comment gives for its own
//      two-entry-point shape.
//
// try_parse_tls_client_hello itself is NOT called separately here: every one of its own bytes
// (record-header check, then full delegation to try_parse_tls_handshake_client_hello) is already
// unconditionally reached by every single call to try_detect_doh above, since try_detect_doh calls
// it first and unconditionally, regardless of whether the eventual SNI match against the DoH
// provider table succeeds or fails.
//
// Both entry points documented as never throwing in their own doc comments -- still wrapped in
// try/catch below, the same defensive posture every harness in this suite takes in case a future
// edit introduces a throwing code path this comment does not yet reflect.
//
// Does not cover: TCP-segment-split TLS records (deliberately never reassembled at all, per
// tls_sni.hpp own file header comment -- a single TCP segment is this whole decoder own scope, not
// a limitation fuzz_packet_decode covers either).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/tls_sni.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_detect_doh(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    try {
        (void)conduitscope::try_parse_tls_handshake_client_hello(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
