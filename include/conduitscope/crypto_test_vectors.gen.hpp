// SPDX-License-Identifier: Apache-2.0
// crypto_test_vectors.gen.hpp - GENERATED FILE, do not hand-edit.
//
// Ground-truth test vectors for this codebase's from-scratch SHA-256/HMAC-SHA256/HKDF/
// AES-128/AES-128-GCM primitives (sha256.*, hkdf.*, aes128.*, aes128_gcm.*), computed by
// tools/generate_crypto_test_vectors.py using Python's own standard-library hashlib/hmac
// modules and the third-party `cryptography` package's audited AESGCM implementation --
// deliberately NOT hand-transcribed from a spec's own published hex tables, since a
// transcription slip in a hand-copied 64-character hex string would silently produce a
// self-test that 'validates' a subtly wrong implementation. Regenerate by rerunning that
// script (mirrors oui_table.gen.hpp's own generated-header precedent) whenever a new
// vector is needed -- crypto_selftest.cpp is the one consumer.
#pragma once

namespace conduitscope {
namespace crypto_test_vectors {

constexpr const char* kSha256EmptyInput = "";
constexpr const char* kSha256EmptyInputDigest = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

constexpr const char* kSha256Abc = "abc";
constexpr const char* kSha256AbcDigest = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

constexpr const char* kSha256TwoBlock = "abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
constexpr const char* kSha256TwoBlockDigest = "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1";

constexpr const char* kHmacKeyHex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
constexpr const char* kHmacData = "Hi There";
constexpr const char* kHmacDigest = "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7";

constexpr const char* kHmacLongKeyHex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
constexpr const char* kHmacLongData = "Test With Truncation";
constexpr const char* kHmacLongDigest = "e1bb17adfa21137eeb37c2cb7c216a984b5da357f1f2984c09ffa3312aa69834";

constexpr const char* kHkdfIkmHex = "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b";
constexpr const char* kHkdfSaltHex = "000102030405060708090a0b0c";
constexpr const char* kHkdfInfoHex = "f0f1f2f3f4f5f6f7f8f9";
constexpr const char* kHkdfPrkHex = "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5";
constexpr int kHkdfOkmLen = 42;
constexpr const char* kHkdfOkmHex = "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865";

constexpr const char* kAesKeyHex = "000102030405060708090a0b0c0d0e0f";
constexpr const char* kAesPlaintextHex = "00112233445566778899aabbccddeeff";
constexpr const char* kAesCiphertextHex = "69c4e0d86a7b0430d8cdb78070b4c55a";

constexpr const char* kGcmKeyHex = "ff0cd72c4d23a2edbd737b4a0478538f";
constexpr const char* kGcmIvHex = "51a2ffe486df1c33d5220a2a";
constexpr const char* kGcmAadHex = "6865616465722d61732d6161642d30313233";
constexpr const char* kGcmPlaintextHex = "74686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f672c2031323334353637383930";
constexpr const char* kGcmCiphertextHex = "5ccd374be7a833a9a26ca72c1e19c649304fde6d4c2daa904ac862badecf879b80c9e253a4a71e9f249e805e41572095d2dac6538e40ab";
constexpr const char* kGcmTagHex = "5601726f9e01b814d6a5798e01b10c03";

constexpr const char* kGcmEmptyKeyHex = "6e84f126dcae9e20124686b15c8f6416";
constexpr const char* kGcmEmptyIvHex = "302b6aa5fadb80be093f4c87";
constexpr const char* kGcmEmptyTagHex = "a13b52bc9fe7b2e243a1e874292f412a";

}  // namespace crypto_test_vectors
}  // namespace conduitscope
