// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/hkdf.hpp"

#include <algorithm>
#include <cstring>
#include <string>

#include "conduitscope/sha256.hpp"

namespace conduitscope {

void hmac_sha256(const uint8_t* key, size_t key_len, const uint8_t* data, size_t data_len, uint8_t out[32]) {
    // RFC 2104: a key longer than the block size (64 bytes for SHA-256) is itself hashed down to 32
    // bytes first; a shorter key is zero-padded out to 64 bytes. ipad/opad are the fixed 0x36/0x5c
    // bytes XORed across the whole block.
    uint8_t key_block[64] = {0};
    if (key_len > 64) {
        uint8_t hashed[32];
        sha256(key, key_len, hashed);
        std::memcpy(key_block, hashed, 32);
    } else {
        std::memcpy(key_block, key, key_len);
    }

    uint8_t ipad[64];
    uint8_t opad[64];
    for (int i = 0; i < 64; ++i) {
        ipad[i] = static_cast<uint8_t>(key_block[i] ^ 0x36);
        opad[i] = static_cast<uint8_t>(key_block[i] ^ 0x5c);
    }

    // inner = SHA256(ipad || data)
    std::vector<uint8_t> inner_input(64 + data_len);
    std::memcpy(inner_input.data(), ipad, 64);
    if (data_len > 0) std::memcpy(inner_input.data() + 64, data, data_len);
    uint8_t inner_hash[32];
    sha256(inner_input.data(), inner_input.size(), inner_hash);

    // outer = SHA256(opad || inner)
    uint8_t outer_input[64 + 32];
    std::memcpy(outer_input, opad, 64);
    std::memcpy(outer_input + 64, inner_hash, 32);
    sha256(outer_input, sizeof(outer_input), out);
}

void hkdf_extract(const uint8_t* salt, size_t salt_len, const uint8_t* ikm, size_t ikm_len, uint8_t out_prk[32]) {
    hmac_sha256(salt, salt_len, ikm, ikm_len, out_prk);
}

std::vector<uint8_t> hkdf_expand(const uint8_t prk[32], const uint8_t* info, size_t info_len, size_t length) {
    // RFC 5869 section 2.3: T(0) = empty; T(n) = HMAC-Hash(PRK, T(n-1) | info | n), output is the
    // first `length` bytes of T(1) || T(2) || ... . SHA-256's 32-byte output means at most
    // ceil(length/32) rounds.
    std::vector<uint8_t> okm;
    okm.reserve(length);
    std::vector<uint8_t> t;  // T(n-1), empty for n=1
    uint8_t counter = 1;
    while (okm.size() < length) {
        std::vector<uint8_t> input(t.size() + info_len + 1);
        size_t pos = 0;
        if (!t.empty()) {
            std::memcpy(input.data(), t.data(), t.size());
            pos += t.size();
        }
        if (info_len > 0) {
            std::memcpy(input.data() + pos, info, info_len);
            pos += info_len;
        }
        input[pos] = counter;
        uint8_t block[32];
        hmac_sha256(prk, 32, input.data(), input.size(), block);
        t.assign(block, block + 32);
        size_t take = std::min<size_t>(32, length - okm.size());
        okm.insert(okm.end(), t.begin(), t.begin() + static_cast<long>(take));
        ++counter;
    }
    return okm;
}

std::vector<uint8_t> hkdf_expand_label(const uint8_t secret[32], const char* label, const uint8_t* context,
                                        size_t context_len, size_t length) {
    // HkdfLabel wire format (RFC 8446 7.1): uint16 length; opaque label<7..255> (the wire form is
    // itself length-prefixed with a single byte, and always carries the fixed "tls13 " prefix);
    // opaque context<0..255> (also single-byte length-prefixed).
    std::string full_label = std::string("tls13 ") + label;
    std::vector<uint8_t> info;
    info.push_back(static_cast<uint8_t>(length >> 8));
    info.push_back(static_cast<uint8_t>(length & 0xff));
    info.push_back(static_cast<uint8_t>(full_label.size()));
    info.insert(info.end(), full_label.begin(), full_label.end());
    info.push_back(static_cast<uint8_t>(context_len));
    if (context_len > 0) info.insert(info.end(), context, context + context_len);
    return hkdf_expand(secret, info.data(), info.size(), length);
}

}  // namespace conduitscope
