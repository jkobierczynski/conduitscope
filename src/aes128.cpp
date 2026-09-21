// SPDX-License-Identifier: Apache-2.0
// Textbook FIPS 197 AES-128 forward cipher: the standard S-box, the standard round constants
// (Rcon), Rijndael key expansion (Nk=4 words -> 44 words / 11 round keys), and the standard
// SubBytes/ShiftRows/MixColumns/AddRoundKey round structure (9 full rounds after the initial
// AddRoundKey, then a 10th round with MixColumns omitted, per spec). See aes128.hpp's file header
// for why only the encrypt direction is implemented, and aes128.cpp's own self-test (invoked from
// CMakeLists.txt, see that file's "Crypto primitives self-tests" section) for FIPS 197 Appendix
// B's own published test vector this is checked against before ever being trusted with real QUIC
// key material.
#include "conduitscope/aes128.hpp"

#include <cstring>

namespace conduitscope {

namespace {

// The standard AES S-box (FIPS 197 Figure 7), indexed by byte value.
constexpr uint8_t kSbox[256] = {
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
};

constexpr uint8_t kRcon[10] = {0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36};

inline uint8_t xtime(uint8_t x) {
    // Multiply-by-2 in GF(2^8) with the AES reduction polynomial x^8+x^4+x^3+x+1 (0x11b).
    return static_cast<uint8_t>((x << 1) ^ ((x & 0x80) ? 0x1b : 0x00));
}

// Rijndael key expansion: Nk=4 32-bit words of input key -> Nb*(Nr+1) = 4*11 = 44 words of round
// key material (FIPS 197 section 5.2), written out as 11 consecutive 16-byte round keys.
void expand_key(const uint8_t key[16], uint8_t round_keys[11][16]) {
    uint8_t w[44][4];
    for (int i = 0; i < 4; ++i) {
        w[i][0] = key[4 * i + 0];
        w[i][1] = key[4 * i + 1];
        w[i][2] = key[4 * i + 2];
        w[i][3] = key[4 * i + 3];
    }
    for (int i = 4; i < 44; ++i) {
        uint8_t temp[4] = {w[i - 1][0], w[i - 1][1], w[i - 1][2], w[i - 1][3]};
        if (i % 4 == 0) {
            // RotWord, then SubWord, then XOR the round constant into the first byte.
            uint8_t t0 = temp[0];
            temp[0] = kSbox[temp[1]];
            temp[1] = kSbox[temp[2]];
            temp[2] = kSbox[temp[3]];
            temp[3] = kSbox[t0];
            temp[0] = static_cast<uint8_t>(temp[0] ^ kRcon[i / 4 - 1]);
        }
        for (int j = 0; j < 4; ++j) w[i][j] = static_cast<uint8_t>(w[i - 4][j] ^ temp[j]);
    }
    for (int round = 0; round < 11; ++round) {
        for (int col = 0; col < 4; ++col) {
            for (int row = 0; row < 4; ++row) {
                round_keys[round][4 * col + row] = w[round * 4 + col][row];
            }
        }
    }
}

// state is stored column-major, exactly as FIPS 197 defines it: state[4*col + row].
void add_round_key(uint8_t state[16], const uint8_t round_key[16]) {
    for (int i = 0; i < 16; ++i) state[i] = static_cast<uint8_t>(state[i] ^ round_key[i]);
}

void sub_bytes(uint8_t state[16]) {
    for (int i = 0; i < 16; ++i) state[i] = kSbox[state[i]];
}

void shift_rows(uint8_t state[16]) {
    // Row r (0-indexed) is cyclically left-shifted by r columns. state[4*col + row].
    uint8_t tmp[16];
    std::memcpy(tmp, state, 16);
    for (int row = 0; row < 4; ++row) {
        for (int col = 0; col < 4; ++col) {
            state[4 * col + row] = tmp[4 * ((col + row) % 4) + row];
        }
    }
}

void mix_columns(uint8_t state[16]) {
    for (int col = 0; col < 4; ++col) {
        uint8_t* c = state + 4 * col;
        uint8_t a0 = c[0], a1 = c[1], a2 = c[2], a3 = c[3];
        uint8_t r0 = static_cast<uint8_t>(xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3);
        uint8_t r1 = static_cast<uint8_t>(a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3);
        uint8_t r2 = static_cast<uint8_t>(a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3));
        uint8_t r3 = static_cast<uint8_t>((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3));
        c[0] = r0;
        c[1] = r1;
        c[2] = r2;
        c[3] = r3;
    }
}

}  // namespace

void aes128_encrypt_block(const uint8_t key[16], const uint8_t in[16], uint8_t out[16]) {
    uint8_t round_keys[11][16];
    expand_key(key, round_keys);

    uint8_t state[16];
    std::memcpy(state, in, 16);

    add_round_key(state, round_keys[0]);
    for (int round = 1; round <= 9; ++round) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, round_keys[round]);
    }
    // Final round (10): no MixColumns.
    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, round_keys[10]);

    std::memcpy(out, state, 16);
}

}  // namespace conduitscope
