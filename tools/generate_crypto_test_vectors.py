#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Regenerates include/conduitscope/crypto_test_vectors.gen.hpp.

Ground-truth test vectors for this codebase's from-scratch SHA-256/HMAC-SHA256/HKDF/AES-128/
AES-128-GCM primitives (sha256.*, hkdf.*, aes128.*, aes128_gcm.*), computed from Python's own
standard-library hashlib/hmac modules and the third-party `cryptography` package's audited
AESGCM/AES-ECB implementations -- deliberately NOT hand-transcribed from a spec's own published
hex tables, since a transcription slip in a hand-copied 64-character hex string would silently
produce a self-test that "validates" a subtly wrong implementation. crypto_selftest.cpp is the
one consumer; mirrors oui_table.gen.hpp's own generated-header precedent (tools/generate_oui_table.py).

Requires: the `cryptography` package (pip install cryptography). Re-run this script and commit the
regenerated header whenever a new vector is needed -- the header itself is checked in so building
this project never requires Python or `cryptography` at build time, only when regenerating vectors.
"""
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def h(b: bytes) -> str:
    return b.hex()


def hkdf_expand(prk: bytes, info: bytes, length: int) -> bytes:
    t = b""
    okm = b""
    counter = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        okm += t
        counter += 1
    return okm[:length]


def main() -> None:
    lines = [
        "// SPDX-License-Identifier: Apache-2.0",
        "// crypto_test_vectors.gen.hpp - GENERATED FILE, do not hand-edit.",
        "//",
        "// Ground-truth test vectors for this codebase's from-scratch SHA-256/HMAC-SHA256/HKDF/",
        "// AES-128/AES-128-GCM primitives (sha256.*, hkdf.*, aes128.*, aes128_gcm.*), computed by",
        "// tools/generate_crypto_test_vectors.py using Python's own standard-library hashlib/hmac",
        "// modules and the third-party `cryptography` package's audited AESGCM implementation --",
        "// deliberately NOT hand-transcribed from a spec's own published hex tables, since a",
        "// transcription slip in a hand-copied 64-character hex string would silently produce a",
        "// self-test that 'validates' a subtly wrong implementation. Regenerate by rerunning that",
        "// script (mirrors oui_table.gen.hpp's own generated-header precedent) whenever a new",
        "// vector is needed -- crypto_selftest.cpp is the one consumer.",
        "#pragma once",
        "",
        "namespace conduitscope {",
        "namespace crypto_test_vectors {",
        "",
    ]

    for name, msg in [
        ("kSha256EmptyInput", b""),
        ("kSha256Abc", b"abc"),
        ("kSha256TwoBlock", b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
    ]:
        d = hashlib.sha256(msg).digest()
        lines.append(f'constexpr const char* {name} = "{msg.decode()}";')
        lines.append(f'constexpr const char* {name}Digest = "{h(d)}";')
        lines.append("")

    hmac_key = bytes([0x0B] * 20)
    hmac_data = b"Hi There"
    mac = hmac.new(hmac_key, hmac_data, hashlib.sha256).digest()
    lines.append(f'constexpr const char* kHmacKeyHex = "{h(hmac_key)}";')
    lines.append(f'constexpr const char* kHmacData = "{hmac_data.decode()}";')
    lines.append(f'constexpr const char* kHmacDigest = "{h(mac)}";')
    lines.append("")

    # A longer-than-block-size HMAC key exercises the "hash the key down first" RFC 2104 branch.
    long_key = bytes([0x0B] * 100)
    long_data = b"Test With Truncation"
    mac2 = hmac.new(long_key, long_data, hashlib.sha256).digest()
    lines.append(f'constexpr const char* kHmacLongKeyHex = "{h(long_key)}";')
    lines.append(f'constexpr const char* kHmacLongData = "{long_data.decode()}";')
    lines.append(f'constexpr const char* kHmacLongDigest = "{h(mac2)}";')
    lines.append("")

    # HKDF-Extract/Expand, RFC 5869 section 2.3 Test Case 1's own input lengths/shape (values
    # re-derived here via hashlib/hmac directly, not copied from the RFC's own output table).
    ikm = bytes.fromhex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b")
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    okm = hkdf_expand(prk, info, 42)
    lines.append(f'constexpr const char* kHkdfIkmHex = "{h(ikm)}";')
    lines.append(f'constexpr const char* kHkdfSaltHex = "{h(salt)}";')
    lines.append(f'constexpr const char* kHkdfInfoHex = "{h(info)}";')
    lines.append(f'constexpr const char* kHkdfPrkHex = "{h(prk)}";')
    lines.append("constexpr int kHkdfOkmLen = 42;")
    lines.append(f'constexpr const char* kHkdfOkmHex = "{h(okm)}";')
    lines.append("")

    # AES-128 single block, FIPS-197-shaped key/plaintext (re-derived via pyca's ECB mode, not
    # copied from the spec's own appendix table).
    aes_key = bytes.fromhex("000102030405060708090a0b0c0d0e0f")
    aes_pt = bytes.fromhex("00112233445566778899aabbccddeeff")
    enc = Cipher(algorithms.AES(aes_key), modes.ECB()).encryptor()
    aes_ct = enc.update(aes_pt) + enc.finalize()
    lines.append(f'constexpr const char* kAesKeyHex = "{h(aes_key)}";')
    lines.append(f'constexpr const char* kAesPlaintextHex = "{h(aes_pt)}";')
    lines.append(f'constexpr const char* kAesCiphertextHex = "{h(aes_ct)}";')
    lines.append("")

    # AES-128-GCM round trip with non-empty AAD/plaintext, and a second all-empty edge case
    # (tag-only, exercises ciphertext_len == 0 in both GHASH and the CTR keystream loop).
    gcm_key = os.urandom(16)
    gcm_iv = os.urandom(12)
    gcm_aad = b"header-as-aad-0123"
    gcm_pt = b"the quick brown fox jumps over the lazy dog, 1234567890"
    ct_and_tag = AESGCM(gcm_key).encrypt(gcm_iv, gcm_pt, gcm_aad)
    gcm_ct, gcm_tag = ct_and_tag[:-16], ct_and_tag[-16:]
    lines.append(f'constexpr const char* kGcmKeyHex = "{h(gcm_key)}";')
    lines.append(f'constexpr const char* kGcmIvHex = "{h(gcm_iv)}";')
    lines.append(f'constexpr const char* kGcmAadHex = "{h(gcm_aad)}";')
    lines.append(f'constexpr const char* kGcmPlaintextHex = "{h(gcm_pt)}";')
    lines.append(f'constexpr const char* kGcmCiphertextHex = "{h(gcm_ct)}";')
    lines.append(f'constexpr const char* kGcmTagHex = "{h(gcm_tag)}";')
    lines.append("")

    gcm_key2 = os.urandom(16)
    gcm_iv2 = os.urandom(12)
    ct_and_tag2 = AESGCM(gcm_key2).encrypt(gcm_iv2, b"", b"")
    lines.append(f'constexpr const char* kGcmEmptyKeyHex = "{h(gcm_key2)}";')
    lines.append(f'constexpr const char* kGcmEmptyIvHex = "{h(gcm_iv2)}";')
    lines.append(f'constexpr const char* kGcmEmptyTagHex = "{h(ct_and_tag2)}";')
    lines.append("")

    lines.append("}  // namespace crypto_test_vectors")
    lines.append("}  // namespace conduitscope")
    lines.append("")

    out_path = os.path.join(os.path.dirname(__file__), "..", "include", "conduitscope",
                             "crypto_test_vectors.gen.hpp")
    with open(out_path, "w") as f:
        f.write("\n".join(lines))
    print(f"wrote {out_path}")


if __name__ == "__main__":
    main()
