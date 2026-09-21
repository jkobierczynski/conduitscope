// SPDX-License-Identifier: Apache-2.0
// sha256.hpp - a minimal, from-scratch SHA-256 (FIPS 180-4) implementation, existing for exactly
// one reason: it is the hash function QUIC's Initial-packet key derivation (RFC 9001 section 5.1,
// itself built on TLS 1.3's HKDF-Expand-Label, RFC 8446 section 7.1) is defined over. There is no
// other cryptographic hashing anywhere in this codebase, and no plan to add one for its own sake --
// see hkdf.hpp for the HMAC-SHA256/HKDF layer built on top of this, and quic.hpp for the one
// caller. This is NOT a general-purpose crypto library: it implements exactly the one primitive
// (a single-shot digest over a contiguous buffer) that layer needs, nothing more.
//
// Correctness matters here in a way it doesn't for most of this codebase's parsers -- a wrong byte
// silently produces a wrong key, which silently produces a failed (not just wrong) decryption, not
// a loud error. See sha256.cpp's own file header for how this is self-tested against FIPS 180-4's
// own published test vectors before it is ever trusted with real QUIC key derivation.
#pragma once

#include <cstddef>
#include <cstdint>

namespace conduitscope {

// Computes the 32-byte SHA-256 digest of `data[0..len)` into `out[0..32)`.
void sha256(const uint8_t* data, size_t len, uint8_t out[32]);

}  // namespace conduitscope
