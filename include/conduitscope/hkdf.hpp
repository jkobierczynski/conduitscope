// SPDX-License-Identifier: Apache-2.0
// hkdf.hpp - HMAC-SHA256 (RFC 2104/FIPS 198-1) and HKDF (RFC 5869), plus TLS 1.3's own
// HKDF-Expand-Label wire format (RFC 8446 section 7.1) -- the exact key-derivation stack RFC 9001
// section 5.1 builds QUIC's Initial-packet protection keys from. Every function here operates over
// SHA-256 specifically (QUIC v1/v2 Initial protection is defined only over SHA-256 -- see
// sha256.hpp), never a general hash-agile interface, since that is the one and only case this
// codebase has any use for. See quic.hpp for the one caller, and hkdf.cpp's own file header for
// how this is self-tested against RFC 4231/RFC 5869's own published test vectors.
#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

namespace conduitscope {

// HMAC-SHA256(key, data) -> 32-byte MAC, per RFC 2104.
void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[32]);

// HKDF-Extract(salt, ikm) -> 32-byte PRK, per RFC 5869 section 2.2 (= HMAC-SHA256(salt, ikm), with
// the caller responsible for RFC 5869's own "salt defaults to a zero-filled hash-length string when
// not provided" rule -- QUIC's own initial_secret derivation always supplies an explicit salt, so
// this implementation does not special-case an empty salt).
void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t out_prk[32]);

// HKDF-Expand(prk, info, length) -> `length` bytes, per RFC 5869 section 2.3. `length` must be
// <= 255*32 (RFC 5869's own ceiling); every call this codebase actually makes asks for at most 32
// bytes, far under that.
std::vector<uint8_t> hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t info_len, size_t length);

// TLS 1.3's HKDF-Expand-Label (RFC 8446 section 7.1): wraps `label` (prefixed with the fixed
// "tls13 " string, exactly as every TLS 1.3 and QUIC label is -- RFC 9001's own "quic key"/
// "quic iv"/"quic hp"/"client in"/"server in" labels are no exception, despite reading as
// QUIC-specific strings) and `context` into HKDF-Expand's own `info` parameter, per that RFC
// section's own struct definition (HkdfLabel { uint16 length; opaque label<7..255>; opaque
// context<0..255>; }).
std::vector<uint8_t> hkdf_expand_label(const uint8_t secret[32], const char* label, const uint8_t* context,
                                        size_t context_len, size_t length);

}  // namespace conduitscope
