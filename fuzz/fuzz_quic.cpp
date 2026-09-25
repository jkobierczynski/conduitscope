// SPDX-License-Identifier: Apache-2.0
// fuzz_quic.cpp - libFuzzer harness for QUIC (RFC 9000/9001, quic.hpp) recognition and Initial-
// packet decryption. This is the most implementation-heavy target in this whole fuzzing pass: it is
// the only decoder in this codebase that runs a real AEAD decryption pipeline (RFC 9001 section 5.2
// Initial-secret derivation via HKDF-Expand-Label, then header-protection removal, then AES-128-GCM
// decryption of the CRYPTO frame) on attacker-controlled bytes, on top of its own hand-rolled
// variable-length integer decoding (QUIC's own 2-bit-prefix varint, RFC 9000 section 16, used
// throughout for Length fields, frame types, and CRYPTO frame Offset/Length) and per-long-header-
// type structural cross-checks. quic.hpp's own file header documents that this exact class of code
// has already had two real, user-reported bugs fixed in it (round one: Handshake/0-RTT/Retry
// recognition originally accepted essentially any long-header byte0 shape, misdetecting a large
// fraction of a busy NBT-NS broadcast segment as QUIC; round two: Retry's own check, and Initial's
// truncation-vs.-impossible-length conflation, were each still too weak) -- see this file's own
// "RFC 9000 17.2.5" Retry Integrity Tag fix specifically, which is exactly the kind of narrow,
// easy-to-get-subtly-wrong structural cross-check this fuzzing pass is best at catching a regression
// in. Unlike every other harness in this codebase, a hostile Initial packet reaches real
// cryptographic primitive code (aes128_gcm.cpp/hkdf.cpp), not just a length-prefixed field walk --
// exactly the kind of target this whole fuzzing pass was built to stress hardest.
//
// try_recognize_quic's own signature is `(ByteSpan udp_payload, uint16_t src_port, uint16_t
// dst_port, const std::vector<uint16_t>& extra_ports)` -- QUIC has no single fixed port the way
// every other harness's protocol does (quic.hpp's own file header: "QUIC has no single standard
// port"), so both port arguments and the extra-ports list are real, meaningfully different inputs
// decoder.cpp threads through from `udp.src_port`/`udp.dst_port`/`options_.extra_lateral_movement_
// ports` at its own call site (see decoder.cpp's own QUIC dispatch comment, just before its HART-IP
// UDP check). This harness loops over a handful of representative (src_port, dst_port, extra_ports)
// combinations against the SAME fuzzer input, the same "try every reachable hint value against one
// input" shape fuzz_mqtt.cpp's own `session_version_hint` loop and fuzz_cclink_ie.cpp's own
// `expected_kind` loop already use:
//   - (443, 51234, {})       -- the conventional QUIC/HTTPS port as dst, ephemeral src, default
//                                (empty) extra-ports list. Long-header packets are recognized here
//                                port-independently regardless (see try_recognize_quic's own doc
//                                comment); this pair also lets a short-header (1-RTT) packet reach
//                                its own port-gated fallback via the port match on 443.
//   - (51234, 8443, {})      -- the "commonly configured alternate" port, other direction, so both
//                                src-side and dst-side port matching get exercised at least once.
//   - (54108, 34567, {})     -- neither port matches anything by default -- this is
//                                tests/sample_quic.pcap packet #9's own real (src, dst) pair (a
//                                short-header packet on a deliberately non-standard port, added to
//                                prove that fallback's own internal port gate rejects it without
//                                `extra_ports`; see CMakeLists.txt's own quic test comments), so
//                                reusing it here exercises the negative case with a real, meaningful
//                                port pair rather than an arbitrary one.
//   - (54108, 34567, {34567}) -- the SAME pair, but with 34567 supplied via `extra_ports` the way
//                                `--lateral-movement-port 34567` does at the CLI -- the positive
//                                counterpart of the case above, proving the short-header fallback's
//                                own port match against a caller-supplied extra port, not just the
//                                two hardcoded defaults.
// No cross-packet state exists for this protocol (quic.hpp documents none -- every packet is
// recognized independently, including Initial-packet decryption, which derives its own keys purely
// from that packet's own Destination Connection ID and a public per-version constant).
#include <cstdint>
#include <cstddef>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/quic.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    static const std::vector<uint16_t> kNoExtraPorts;
    static const std::vector<uint16_t> kExtra34567{34567};

    struct Trial {
        uint16_t src_port;
        uint16_t dst_port;
        const std::vector<uint16_t>& extra_ports;
    };
    const Trial trials[] = {
        {51234, 443, kNoExtraPorts},
        {51234, 8443, kNoExtraPorts},
        {54108, 34567, kNoExtraPorts},
        {54108, 34567, kExtra34567},
    };

    for (const auto& t : trials) {
        // try_recognize_quic is documented never to throw (RFC 9001 decryption failures are
        // handled internally as "recognized but not decrypted", not exceptions), but every other
        // harness in this codebase wraps its own entry point call in try/catch as a defensive
        // posture against a future edit introducing a throwing path this comment doesn't yet
        // reflect -- see fuzz_enip.cpp's identical reasoning.
        try {
            (void)conduitscope::try_recognize_quic(payload, t.src_port, t.dst_port, t.extra_ports);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
