// SPDX-License-Identifier: Apache-2.0
// Textbook NIST SP 800-38D AES-128-GCM: CTR-mode confidentiality (built on aes128.hpp's own
// forward cipher -- see that file's header for why decrypt reuses encrypt) plus GHASH universal
// hashing over GF(2^128) for the authentication tag. The GHASH multiplication below is the
// standard "process X bit-by-bit MSB-first, right-shift-and-reduce V each step" reference
// algorithm (SP 800-38D section 6.3's own algorithm, restated in byte-array form) -- deliberately
// the simple, unoptimized version (no precomputed multiplication tables), since this codebase
// decrypts at most one ~1200-byte QUIC Initial packet at a time, not a bulk data stream.
#include "conduitscope/aes128_gcm.hpp"

#include <cstring>

#include "conduitscope/aes128.hpp"

namespace conduitscope {

namespace {

void xor_block(uint8_t out[16], const uint8_t a[16], const uint8_t b[16]) {
    for (int i = 0; i < 16; ++i) out[i] = static_cast<uint8_t>(a[i] ^ b[i]);
}

// GF(2^128) multiplication of two 128-bit blocks under GCM's own reduction polynomial
// (x^128 + x^7 + x^2 + x + 1, represented as the byte 0xe1 in the top byte of R -- SP 800-38D
// section 6.3). `x` is consumed MSB-first (bit 0 = the top bit of x[0]); `y` is repeatedly
// right-shifted-as-a-128-bit-big-endian-value and conditionally reduced.
void gf128_mul(const uint8_t x[16], const uint8_t y[16], uint8_t out[16]) {
    uint8_t z[16] = {0};
    uint8_t v[16];
    std::memcpy(v, y, 16);
    for (int i = 0; i < 128; ++i) {
        int byte_idx = i / 8;
        int bit_idx = 7 - (i % 8);
        bool x_bit = ((x[byte_idx] >> bit_idx) & 1) != 0;
        if (x_bit) {
            for (int j = 0; j < 16; ++j) z[j] = static_cast<uint8_t>(z[j] ^ v[j]);
        }
        bool lsb = (v[15] & 1) != 0;
        for (int j = 15; j > 0; --j) {
            v[j] = static_cast<uint8_t>((v[j] >> 1) | ((v[j - 1] & 1) << 7));
        }
        v[0] = static_cast<uint8_t>(v[0] >> 1);
        if (lsb) v[0] = static_cast<uint8_t>(v[0] ^ 0xe1);
    }
    std::memcpy(out, z, 16);
}

// GHASH_H(A, C) per SP 800-38D section 6.4: A (associated data) and C (ciphertext) are each
// zero-padded out to a whole number of 16-byte blocks and hashed in sequence, followed by one
// final block holding their two 64-bit big-endian BIT lengths back to back.
void ghash(const uint8_t h[16], const uint8_t* aad, size_t aad_len, const uint8_t* ciphertext,
           size_t ciphertext_len, uint8_t out[16]) {
    uint8_t y[16] = {0};
    auto absorb = [&](const uint8_t* data, size_t len) {
        size_t off = 0;
        while (off < len) {
            uint8_t block[16] = {0};
            size_t take = (len - off < 16) ? (len - off) : 16;
            std::memcpy(block, data + off, take);
            uint8_t xored[16];
            xor_block(xored, y, block);
            gf128_mul(xored, h, y);
            off += take;
        }
    };
    if (aad_len > 0) absorb(aad, aad_len);
    if (ciphertext_len > 0) absorb(ciphertext, ciphertext_len);

    uint8_t len_block[16];
    uint64_t aad_bits = static_cast<uint64_t>(aad_len) * 8;
    uint64_t ct_bits = static_cast<uint64_t>(ciphertext_len) * 8;
    for (int i = 0; i < 8; ++i) len_block[i] = static_cast<uint8_t>(aad_bits >> (8 * (7 - i)));
    for (int i = 0; i < 8; ++i) len_block[8 + i] = static_cast<uint8_t>(ct_bits >> (8 * (7 - i)));
    uint8_t xored[16];
    xor_block(xored, y, len_block);
    gf128_mul(xored, h, y);

    std::memcpy(out, y, 16);
}

// inc32 (SP 800-38D section 6.2): increments only the low-order 32 bits of a 128-bit block,
// wrapping mod 2^32, leaving the top 96 bits untouched. Used to step the CTR-mode counter from J0.
void inc32(uint8_t block[16]) {
    uint32_t ctr = (static_cast<uint32_t>(block[12]) << 24) | (static_cast<uint32_t>(block[13]) << 16) |
                   (static_cast<uint32_t>(block[14]) << 8) | static_cast<uint32_t>(block[15]);
    ctr += 1;
    block[12] = static_cast<uint8_t>(ctr >> 24);
    block[13] = static_cast<uint8_t>(ctr >> 16);
    block[14] = static_cast<uint8_t>(ctr >> 8);
    block[15] = static_cast<uint8_t>(ctr);
}

// GCTR(key, ICB, X) (SP 800-38D section 6.5): the CTR-mode keystream XOR, starting from initial
// counter block ICB. Identical operation whether "encrypting" or "decrypting" -- see aes128.hpp's
// file header.
void gctr(const uint8_t key[16], const uint8_t icb[16], const uint8_t* in, size_t len, uint8_t* out) {
    if (len == 0) return;
    uint8_t counter[16];
    std::memcpy(counter, icb, 16);
    size_t off = 0;
    while (off < len) {
        uint8_t keystream[16];
        aes128_encrypt_block(key, counter, keystream);
        size_t take = (len - off < 16) ? (len - off) : 16;
        for (size_t i = 0; i < take; ++i) out[off + i] = static_cast<uint8_t>(in[off + i] ^ keystream[i]);
        off += take;
        inc32(counter);
    }
}

}  // namespace

bool aes128_gcm_decrypt(const uint8_t key[16], const uint8_t iv[12], const uint8_t* aad, size_t aad_len,
                         const uint8_t* ciphertext, size_t ciphertext_len, const uint8_t tag[16],
                         std::vector<uint8_t>& out) {
    uint8_t zero_block[16] = {0};
    uint8_t h[16];
    aes128_encrypt_block(key, zero_block, h);

    // J0 for a 96-bit IV (SP 800-38D section 7.1 case 1, the only case QUIC/TLS 1.3 ever uses):
    // IV || 0^31 || 1.
    uint8_t j0[16];
    std::memcpy(j0, iv, 12);
    j0[12] = 0;
    j0[13] = 0;
    j0[14] = 0;
    j0[15] = 1;

    out.assign(ciphertext_len, 0);
    if (ciphertext_len > 0) {
        // Plaintext starts at counter block J0+1 (inc32 once before the first keystream block) --
        // the tag itself uses AES(key, J0) directly, un-incremented, computed separately below.
        uint8_t start_counter[16];
        std::memcpy(start_counter, j0, 16);
        inc32(start_counter);
        gctr(key, start_counter, ciphertext, ciphertext_len, out.data());
    }

    uint8_t s[16];
    ghash(h, aad, aad_len, ciphertext, ciphertext_len, s);

    uint8_t tag_mask[16];
    aes128_encrypt_block(key, j0, tag_mask);
    uint8_t computed_tag[16];
    xor_block(computed_tag, s, tag_mask);

    bool match = true;
    for (int i = 0; i < 16; ++i) {
        if (computed_tag[i] != tag[i]) match = false;
    }
    return match;
}

}  // namespace conduitscope
