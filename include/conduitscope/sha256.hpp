// SPDX-License-Identifier: Apache-2.0
// sha256.hpp - a minimal, from-scratch SHA-256 (FIPS 180-4) implementation, originally existing for
// exactly one reason: it is the hash function QUIC's Initial-packet key derivation (RFC 9001
// section 5.1, itself built on TLS 1.3's HKDF-Expand-Label, RFC 8446 section 7.1) is defined over
// (see hkdf.hpp for the HMAC-SHA256/HKDF layer built on top of this, and quic.hpp for that
// caller). A second, deliberate caller was added alongside the `evidence` subcommand
// (evidence_report.hpp/.cpp's own sha256_hex): hashing a capture/policy file's raw bytes into an
// evidence pack's own integrity section. Still NOT a general-purpose crypto library -- every caller
// so far needs exactly the one primitive here (a single-shot digest over a contiguous buffer),
// nothing more -- but "no plan to add a second use" no longer holds, so this comment stops claiming
// it.
//
// Correctness matters here in a way it doesn't for most of this codebase's parsers -- a wrong byte
// silently produces a wrong key, which silently produces a failed (not just wrong) decryption, not
// a loud error. See sha256.cpp's own file header for how this is self-tested against FIPS 180-4's
// own published test vectors before it is ever trusted with real QUIC key derivation.
//
// See aes128_gcm.hpp's own file header for this codebase's crypto-subsystem-wide SCOPE BOUNDARY
// (patch295 finding F7; item 139, DEVELOPMENT.md) -- this file is one of the four it covers, and
// the "second, deliberate caller" paragraph above is exactly the kind of same-primitive-new-caller
// growth that boundary welcomes; a genuinely new primitive is the kind it closes the door on.
#pragma once

#include <cstddef>
#include <cstdint>

namespace conduitscope {

// Computes the 32-byte SHA-256 digest of `data[0..len)` into `out[0..32)`.
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

}  // namespace conduitscope
