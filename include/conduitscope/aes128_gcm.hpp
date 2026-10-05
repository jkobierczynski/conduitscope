// SPDX-License-Identifier: Apache-2.0
// aes128_gcm.hpp - AEAD_AES_128_GCM (NIST SP 800-38D), DECRYPT direction only, 96-bit ("12-byte")
// IVs/nonces only -- the one AEAD construction and the one nonce length RFC 9001 section 5.2
// mandates for every QUIC Initial packet regardless of the eventual negotiated cipher suite (see
// aes128.hpp's file header for why CTR mode means only AES *encrypt* is ever needed, for both GCM's
// own keystream and this header's decrypt-and-verify operation). See quic.hpp for the one caller,
// and aes128_gcm.cpp's own file header for how this is self-tested against a published NIST GCM
// test vector before ever being trusted with real QUIC ciphertext.
//
// This intentionally has no encrypt counterpart: this codebase is a passive, read-only decoder --
// it never constructs a QUIC packet, only ever decrypts one it observed on the wire (see this
// project's own "never live DNS", "never decrypt anything but a QUIC Initial packet's own
// publicly-derivable keys" posture throughout its documentation).
//
// SCOPE BOUNDARY (docs/reviews/2026-10-chatgpt-security-review-patch295.md finding F7; item 139,
// DEVELOPMENT.md): this file, aes128.hpp, sha256.hpp, and hkdf.hpp together are this codebase's
// ENTIRE home-grown cryptography, and that is deliberately where it stays closed. A new CALLER of
// a primitive already implemented here -- another SHA-256/HMAC-SHA256 integrity-hashing use,
// say -- is fine and already has precedent (item 117's `evidence --sign-key`; see sha256.hpp/
// hkdf.hpp's own file headers). A new PRIMITIVE, cipher, mode, or capability -- anything this
// AES-128/GCM-decrypt-only/SHA-256/HKDF quartet doesn't already implement -- is explicitly NOT to
// be added here: reach for a well-reviewed system/library crypto implementation (OpenSSL, mbedTLS,
// libsodium, ...) instead of extending this hand-rolled subsystem further. This is the review's
// own recommendation, written down as an enforced project convention rather than left as a line in
// a review document nobody is likely to re-read before the next crypto-adjacent change.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace conduitscope {

// Decrypts `ciphertext` (AEAD_AES_128_GCM, 12-byte `iv`, associated data `aad`) into `out`
// (resized to ciphertext_len) and verifies the trailing 16-byte `tag` against the computed one.
// Returns false (out's contents are then undefined and MUST NOT be used) on tag mismatch -- this
// is the one and only integrity check standing between "this really is what a real QUIC endpoint
// sent" and "this decoder is about to hand a caller bytes that happen to LOOK like valid TLS
// framing purely because the CTR-mode keystream/ciphertext XOR landed on plausible-looking bytes
// by chance" -- see quic.hpp's own comment at its one call site for why this check is never
// skipped or treated as advisory.
bool aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t tag[16],
                         std::vector<uint8_t>& out);

}  // namespace conduitscope
