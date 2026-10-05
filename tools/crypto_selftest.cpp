// SPDX-License-Identifier: Apache-2.0
// crypto_selftest.cpp - a small, standalone executable (not the `conduitscope` CLI itself) that
// checks this codebase's from-scratch SHA-256/HMAC-SHA256/HKDF/AES-128/AES-128-GCM primitives
// (sha256.*, hkdf.*, aes128.*, aes128_gcm.*) against the ground-truth vectors in
// crypto_test_vectors.gen.hpp (see that file's own header for why those are generated, not
// hand-transcribed). Exists for exactly one reason: quic.cpp trusts these primitives to derive
// real key material and authenticate real ciphertext for a genuine QUIC Initial packet -- a subtle
// bug in any one of them would silently corrupt every QUIC decryption rather than crash loudly, so
// this runs standard-shaped test vectors through each layer BEFORE any of them is ever trusted
// with real capture data. Wired into CMakeLists.txt's "Crypto primitives self-tests" section as
// its own CTest case, run on every build alongside the fixture-based CLI tests, not gated behind
// CONDUITSCOPE_ENABLE_FUZZING or any other opt-in flag -- unlike the fuzz harnesses (which need a
// separate sanitizer toolchain), this is a plain executable any configuration can build and run.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed -- CTest's
// own default "nonzero exit code fails the test" behavior is all the wiring this needs.
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "conduitscope/aes128.hpp"
#include "conduitscope/aes128_gcm.hpp"
#include "conduitscope/crypto_test_vectors.gen.hpp"
#include "conduitscope/hkdf.hpp"
#include "conduitscope/sha256.hpp"

namespace {

int g_failures = 0;

std::vector<uint8_t> from_hex(const std::string& hex) {
    std::vector<uint8_t> out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i + 1 < hex.size(); i += 2) {
        out.push_back(static_cast<uint8_t>(std::stoul(hex.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::string to_hex(const uint8_t* data, size_t len) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kDigits[data[i] >> 4]);
        out.push_back(kDigits[data[i] & 0x0f]);
    }
    return out;
}

void check(const char* name, const std::string& actual_hex, const std::string& expected_hex) {
    if (actual_hex == expected_hex) {
        std::printf("PASS  %s\n", name);
    } else {
        std::printf("FAIL  %s\n      expected: %s\n      actual:   %s\n", name, expected_hex.c_str(),
                     actual_hex.c_str());
        ++g_failures;
    }
}

void check_bool(const char* name, bool ok) {
    if (ok) {
        std::printf("PASS  %s\n", name);
    } else {
        std::printf("FAIL  %s\n", name);
        ++g_failures;
    }
}

}  // namespace

int main() {
    using namespace conduitscope;
    using namespace conduitscope::crypto_test_vectors;

    // --- SHA-256 --------------------------------------------------------------------------
    {
        auto run = [](const char* name, const char* msg, const char* expected) {
            std::string s(msg);
            uint8_t digest[32];
            sha256(reinterpret_cast<const uint8_t*>(s.data()), s.size(), digest);
            check(name, to_hex(digest, 32), expected);
        };
        run("sha256(empty)", kSha256EmptyInput, kSha256EmptyInputDigest);
        run("sha256(\"abc\")", kSha256Abc, kSha256AbcDigest);
        run("sha256(two-block message)", kSha256TwoBlock, kSha256TwoBlockDigest);

        // F8 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 140,
        // DEVELOPMENT.md): "sha256(empty)" above passes std::string::data() on an empty string,
        // which is guaranteed non-null since C++11 -- it never actually exercises the case this
        // finding is about. This codebase deliberately calls sha256 with a genuine null pointer for
        // an empty digest (evidence_report.cpp's own sha256_hex, hashing an empty capture/policy
        // file), so that exact call shape is exercised directly here, confirmed (before the fix)
        // to trip UBSan ("null pointer passed as argument 2, which is declared to never be null")
        // even though it always produced the right digest at runtime.
        uint8_t digest[32];
        sha256(nullptr, 0, digest);
        check("sha256(nullptr, 0, ...) matches sha256(empty)", to_hex(digest, 32), kSha256EmptyInputDigest);
    }

    // --- HMAC-SHA256 ------------------------------------------------------------------------
    {
        auto key = from_hex(kHmacKeyHex);
        std::string data(kHmacData);
        uint8_t mac[32];
        hmac_sha256(key.data(), key.size(), reinterpret_cast<const uint8_t*>(data.data()), data.size(), mac);
        check("hmac_sha256 (RFC 4231-shaped, short key)", to_hex(mac, 32), kHmacDigest);
    }
    {
        auto key = from_hex(kHmacLongKeyHex);
        std::string data(kHmacLongData);
        uint8_t mac[32];
        hmac_sha256(key.data(), key.size(), reinterpret_cast<const uint8_t*>(data.data()), data.size(), mac);
        check("hmac_sha256 (key longer than block size)", to_hex(mac, 32), kHmacLongDigest);
    }
    {
        // F8 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 140,
        // DEVELOPMENT.md): the same nullptr-into-memcpy edge case applies to hmac_sha256's own key
        // handling (hkdf.cpp), and this codebase deliberately calls it with a genuine null,
        // zero-length key -- evidence_report.cpp's own hmac_sha256_hex guards an empty --sign-key
        // vector's own data() with a ternary, specifically because std::vector::data() (unlike
        // std::string::data()) is NOT guaranteed non-null when empty. Expected digest is
        // HMAC-SHA256 with an empty key and empty message, cross-checked against Python's own
        // hmac/hashlib before being hardcoded here.
        uint8_t mac[32];
        hmac_sha256(nullptr, 0, nullptr, 0, mac);
        check("hmac_sha256(nullptr, 0, nullptr, 0, ...) (empty key, empty data)", to_hex(mac, 32),
              "b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad");
    }

    // --- HKDF-Extract / HKDF-Expand ----------------------------------------------------------
    {
        auto ikm = from_hex(kHkdfIkmHex);
        auto salt = from_hex(kHkdfSaltHex);
        auto info = from_hex(kHkdfInfoHex);
        uint8_t prk[32];
        hkdf_extract(salt.data(), salt.size(), ikm.data(), ikm.size(), prk);
        check("hkdf_extract (RFC 5869-shaped)", to_hex(prk, 32), kHkdfPrkHex);

        auto okm = hkdf_expand(prk, info.data(), info.size(), static_cast<size_t>(kHkdfOkmLen));
        check("hkdf_expand (RFC 5869-shaped, 42-byte OKM)", to_hex(okm.data(), okm.size()), kHkdfOkmHex);
    }

    // --- AES-128 single block ----------------------------------------------------------------
    {
        auto key = from_hex(kAesKeyHex);
        auto pt = from_hex(kAesPlaintextHex);
        uint8_t ct[16];
        aes128_encrypt_block(key.data(), pt.data(), ct);
        check("aes128_encrypt_block (FIPS-197-shaped)", to_hex(ct, 16), kAesCiphertextHex);
    }

    // --- AES-128-GCM decrypt, with AAD and plaintext -----------------------------------------
    {
        auto key = from_hex(kGcmKeyHex);
        auto iv = from_hex(kGcmIvHex);
        auto aad = from_hex(kGcmAadHex);
        auto ct = from_hex(kGcmCiphertextHex);
        auto tag = from_hex(kGcmTagHex);
        std::vector<uint8_t> plaintext;
        bool ok = aes128_gcm_decrypt(key.data(), iv.data(), aad.data(), aad.size(), ct.data(), ct.size(),
                                      tag.data(), plaintext);
        check_bool("aes128_gcm_decrypt tag verifies", ok);
        check("aes128_gcm_decrypt recovers plaintext", to_hex(plaintext.data(), plaintext.size()),
              kGcmPlaintextHex);

        // A single flipped tag bit must be rejected, not silently accepted -- this is the one
        // check standing between "genuine QUIC Initial packet" and "1200 bytes of noise that
        // happened to XOR into something plausible", so it is never allowed to pass silently.
        auto bad_tag = tag;
        bad_tag[0] ^= 0x01;
        std::vector<uint8_t> discard;
        bool rejected = !aes128_gcm_decrypt(key.data(), iv.data(), aad.data(), aad.size(), ct.data(), ct.size(),
                                             bad_tag.data(), discard);
        check_bool("aes128_gcm_decrypt rejects a corrupted tag", rejected);

        // F6 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 138,
        // DEVELOPMENT.md): the tag comparison was rewritten from a per-byte `if`/`bool match` into
        // a branchless XOR-accumulate loop (see aes128_gcm.cpp's own comment at the fix). The
        // case above only ever flips byte 0 -- not enough to prove the rewritten loop still
        // examines every one of the 16 bytes rather than stopping early somewhere in the middle,
        // which is exactly the class of bug a loop rewrite like this one could introduce. Flipping
        // only the LAST byte instead is the strongest version of that check: any accumulator loop
        // that silently short-circuits (or has an off-by-one truncating it) before reaching index
        // 15 would wrongly accept this tag.
        auto bad_tag_last_byte = tag;
        bad_tag_last_byte[15] ^= 0x01;
        std::vector<uint8_t> discard_last_byte;
        bool rejected_last_byte = !aes128_gcm_decrypt(key.data(), iv.data(), aad.data(), aad.size(), ct.data(),
                                                        ct.size(), bad_tag_last_byte.data(), discard_last_byte);
        check_bool("aes128_gcm_decrypt rejects a tag corrupted only in its last byte", rejected_last_byte);
    }

    // --- AES-128-GCM decrypt, empty AAD and plaintext (pure-tag edge case) ------------------
    {
        auto key = from_hex(kGcmEmptyKeyHex);
        auto iv = from_hex(kGcmEmptyIvHex);
        auto tag = from_hex(kGcmEmptyTagHex);
        std::vector<uint8_t> plaintext;
        bool ok = aes128_gcm_decrypt(key.data(), iv.data(), nullptr, 0, nullptr, 0, tag.data(), plaintext);
        check_bool("aes128_gcm_decrypt (empty AAD/plaintext edge case)", ok);
        check_bool("aes128_gcm_decrypt (empty AAD/plaintext) yields empty output", plaintext.empty());
    }

    if (g_failures == 0) {
        std::printf("\nAll crypto primitive self-tests passed.\n");
        return 0;
    }
    std::printf("\n%d crypto primitive self-test(s) FAILED.\n", g_failures);
    return 1;
}
