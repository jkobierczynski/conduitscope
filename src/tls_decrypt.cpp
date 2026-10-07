// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/tls_decrypt.hpp"

#include <cstdio>
#include <cstring>

#include "conduitscope/resource_limits.hpp"

#ifdef CONDUITSCOPE_HAVE_OPENSSL
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#endif

namespace conduitscope {

// ===== Cipher suite tables -- available unconditionally (pure lookup tables, no OpenSSL symbol
// touched), since tls_decrypt.hpp declares them with no #ifdef of their own. See this file's own
// header comment's SCOPE section for exactly which wire values are deliberately absent. =====

TlsCipherSuiteInfo lookup_tls13_cipher_suite(uint16_t wire_value) {
    switch (wire_value) {
        case 0x1301: return TlsCipherSuiteInfo{TlsCipherAlgo::Aes128Gcm, "TLS_AES_128_GCM_SHA256", 16, false};
        case 0x1302: return TlsCipherSuiteInfo{TlsCipherAlgo::Aes256Gcm, "TLS_AES_256_GCM_SHA384", 32, true};
        case 0x1303:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Chacha20Poly1305, "TLS_CHACHA20_POLY1305_SHA256", 32, false};
        // 0x1304 (TLS_AES_128_CCM_SHA256) / 0x1305 (TLS_AES_128_CCM_8_SHA256) -- recognized in no
        // table at all, deliberately: this engine has no CCM AEAD path, and a cipher suite this
        // table doesn't recognize is handled identically (Unsupported) whether it's "a suite we
        // chose not to implement" or "a suite that doesn't exist" -- see this file's own SCOPE.
        default:
            return TlsCipherSuiteInfo{};
    }
}

TlsCipherSuiteInfo lookup_tls12_gcm_cipher_suite(uint16_t wire_value) {
    switch (wire_value) {
        // RFC 5288 (RSA/DHE-RSA key exchange) and RFC 5289 (ECDHE-RSA/ECDHE-ECDSA key exchange) --
        // every one of these key-exchanges derives the SAME key_block from the SAME master_secret
        // once the handshake is done (see tls12_prf below), so the key-exchange method itself is
        // irrelevant to this engine; only the bulk cipher (AES-128 vs AES-256-GCM, hence SHA-256 vs
        // SHA-384 as the PRF hash) matters.
        case 0x009C: return TlsCipherSuiteInfo{TlsCipherAlgo::Aes128Gcm, "TLS_RSA_WITH_AES_128_GCM_SHA256", 16, false};
        case 0x009D: return TlsCipherSuiteInfo{TlsCipherAlgo::Aes256Gcm, "TLS_RSA_WITH_AES_256_GCM_SHA384", 32, true};
        case 0x009E:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes128Gcm, "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256", 16, false};
        case 0x009F:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes256Gcm, "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384", 32, true};
        case 0xC02B:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes128Gcm, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256", 16, false};
        case 0xC02C:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes256Gcm, "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384", 32, true};
        case 0xC02F:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes128Gcm, "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256", 16, false};
        case 0xC030:
            return TlsCipherSuiteInfo{TlsCipherAlgo::Aes256Gcm, "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384", 32, true};
        // CBC-mode suites (e.g. 0xC013 TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA) are deliberately absent --
        // see this file's own SCOPE section above.
        default:
            return TlsCipherSuiteInfo{};
    }
}

bool tls_decrypt_build_supported() {
#ifdef CONDUITSCOPE_HAVE_OPENSSL
    return true;
#else
    return false;
#endif
}

#ifdef CONDUITSCOPE_HAVE_OPENSSL

namespace {

// ----- Wire constants (RFC 8446 section B.1 / RFC 5246 section 7.4) -----
constexpr uint8_t kContentTypeChangeCipherSpec = 20;
constexpr uint8_t kContentTypeAlert = 21;
constexpr uint8_t kContentTypeHandshake = 22;
constexpr uint8_t kContentTypeApplicationData = 23;

constexpr uint8_t kHandshakeTypeClientHello = 1;
constexpr uint8_t kHandshakeTypeServerHello = 2;
constexpr uint8_t kHandshakeTypeFinished = 20;
constexpr uint8_t kHandshakeTypeKeyUpdate = 24;

// RFC 8446 section 5.2's own TLSCiphertext.length ceiling (2^14 + 256): the largest a record's
// declared length may legitimately be. Checked immediately against the raw 5-byte header, the same
// "protocol-native field-width bound, enforced at parse time" posture every other decoder's own
// declared-length plausibility check already has -- this is a hard wire-format ceiling, not a
// resource_limits()-tunable category (see resource_limits.hpp's own header comment for that split).
// Also a safe superset of TLS 1.2's own, smaller 2^14+2048 ceiling (RFC 5246 section 6.2.1).
constexpr uint16_t kMaxTlsRecordCiphertext = 16640;

// A secondary, resource_limits()-governed safety net on TOTAL buffered bytes per direction (raw,
// not-yet-a-complete-record bytes, and separately, buffered-but-not-yet-complete handshake message
// bytes) -- see resource_limits.hpp's own max_reassembly_bytes field, which this reuses rather than
// inventing a TLS-specific CLI flag: the same "cross-segment reassembly buffering" category every
// other protocol's own reassembly cap (COTP/DNP3/general TCP) already shares. Falls back to the
// same 16 MiB default decoder.cpp's own general TCP reassembly cap already documents, when the CLI
// flag was never passed.
constexpr size_t kDefaultTlsReassemblyBytes = 16 * 1024 * 1024;

// RFC 8446 section 4.1.3's fixed "this was actually a HelloRetryRequest" ServerHello.random
// constant -- recognized so a retried handshake's real second ClientHello/ServerHello exchange is
// what gets tracked, not the (useless, discarded) first one. See this file's own LEFT OPEN note.
constexpr uint8_t kHelloRetryRequestRandom[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11, 0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E, 0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C,
};

bool is_hello_retry_request_random(const std::array<uint8_t, 32>& r) {
    return std::memcmp(r.data(), kHelloRetryRequestRandom, 32) == 0;
}

std::string hex16(uint16_t v) {
    char buf[8];
    std::snprintf(buf, sizeof(buf), "0x%04x", v);
    return std::string(buf);
}

void write_u64be(uint8_t out[8], uint64_t v) {
    for (int i = 7; i >= 0; --i) {
        out[i] = static_cast<uint8_t>(v & 0xFF);
        v >>= 8;
    }
}

// ----- OpenSSL EVP wrappers -- API shapes verified by standalone test-compilation before being
// written here (see this feature's own ROADMAP entry for the exact test files/commands). -----

// HKDF-Expand (RFC 5869 section 2.3) with no preceding Extract step -- TLS 1.3's own key schedule
// (RFC 8446 section 7.1) always calls HKDF-Expand-Label on an ALREADY-extracted secret (every
// secret a key-log entry hands us is already a proper HKDF PRK, never raw input keying material),
// so this engine never needs HKDF-Extract at all.
std::vector<uint8_t> hkdf_expand(const std::vector<uint8_t>& secret, const std::vector<uint8_t>& info,
                                  size_t out_len, bool sha384) {
    std::vector<uint8_t> out(out_len, 0);
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
    if (!pctx) return out;
    struct Guard {
        EVP_PKEY_CTX* ctx;
        ~Guard() { EVP_PKEY_CTX_free(ctx); }
    } guard{pctx};

    // A failure anywhere in this sequence leaves `out` all-zero, which is never a fallback value a
    // caller trusts silently: the one AEAD decrypt this key material would later feed will simply
    // fail its own tag check (treated as a hard decrypt failure -- see process_one_record's own
    // give_up() call for that case), rather than this function needing its own distinct error type.
    if (EVP_PKEY_derive_init(pctx) <= 0) return out;
    if (EVP_PKEY_CTX_set_hkdf_mode(pctx, EVP_PKEY_HKDEF_MODE_EXPAND_ONLY) <= 0) return out;
    if (EVP_PKEY_CTX_set_hkdf_md(pctx, sha384 ? EVP_sha384() : EVP_sha256()) <= 0) return out;
    if (EVP_PKEY_CTX_set1_hkdf_key(pctx, secret.data(), static_cast<int>(secret.size())) <= 0) return out;
    if (EVP_PKEY_CTX_add1_hkdf_info(pctx, info.data(), static_cast<int>(info.size())) <= 0) return out;
    size_t len = out_len;
    if (EVP_PKEY_derive(pctx, out.data(), &len) <= 0) return out;
    out.resize(len);
    return out;
}

// RFC 8446 section 7.1's HkdfLabel: uint16 length; opaque label<7..255> = "tls13 " + Label;
// opaque context<0..255>. Serialized exactly as any real TLS 1.3 stack would, then handed to
// HKDF-Expand as the `info` parameter.
std::vector<uint8_t> hkdf_expand_label(const std::vector<uint8_t>& secret, const std::string& label,
                                        const std::vector<uint8_t>& context, size_t length, bool sha384) {
    std::string full_label = "tls13 " + label;
    std::vector<uint8_t> info;
    info.reserve(2 + 1 + full_label.size() + 1 + context.size());
    info.push_back(static_cast<uint8_t>((length >> 8) & 0xFF));
    info.push_back(static_cast<uint8_t>(length & 0xFF));
    info.push_back(static_cast<uint8_t>(full_label.size()));
    info.insert(info.end(), full_label.begin(), full_label.end());
    info.push_back(static_cast<uint8_t>(context.size()));
    info.insert(info.end(), context.begin(), context.end());
    return hkdf_expand(secret, info, length, sha384);
}

std::vector<uint8_t> hmac_once(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data, bool sha384) {
    std::vector<uint8_t> out(sha384 ? 48 : 32);
    unsigned int len = 0;
    HMAC(sha384 ? EVP_sha384() : EVP_sha256(), key.data(), static_cast<int>(key.size()), data.data(), data.size(),
         out.data(), &len);
    out.resize(len);
    return out;
}

// RFC 5246 section 5's P_hash, iterated to cover `out_len` bytes -- TLS 1.2's own PRF is
// PRF(secret, label, seed) = P_hash(secret, label + seed). Used for exactly one derivation in this
// engine: master_secret -> key_block (RFC 5246 section 6.3), so `label` is always "key expansion"
// at the one call site, but kept as a parameter for clarity/testability rather than hardcoded here.
std::vector<uint8_t> tls12_prf(const std::vector<uint8_t>& secret, const std::string& label,
                                const std::vector<uint8_t>& seed, size_t out_len, bool sha384) {
    std::vector<uint8_t> label_seed(label.begin(), label.end());
    label_seed.insert(label_seed.end(), seed.begin(), seed.end());

    std::vector<uint8_t> result;
    result.reserve(out_len + (sha384 ? 48 : 32));
    std::vector<uint8_t> a = hmac_once(secret, label_seed, sha384);  // A(1)
    while (result.size() < out_len) {
        std::vector<uint8_t> input = a;
        input.insert(input.end(), label_seed.begin(), label_seed.end());
        std::vector<uint8_t> chunk = hmac_once(secret, input, sha384);
        result.insert(result.end(), chunk.begin(), chunk.end());
        a = hmac_once(secret, a, sha384);  // A(i+1)
    }
    result.resize(out_len);
    return result;
}

// AEAD decrypt-and-verify for exactly the three algorithms TlsCipherAlgo names. `tag` must point at
// 16 bytes (every suite this engine supports uses a 16-byte tag, GCM and Poly1305 alike). Returns
// nullopt on ANY failure -- a bad key/nonce, a corrupted ciphertext, or (far more likely in
// practice, given every secret here comes from a trusted operator-supplied key log) a genuine
// authentication failure, which this function deliberately does not try to distinguish from a
// configuration error: either way, the caller's only correct response is "stop trusting this
// plaintext," not "work out why."
std::optional<std::vector<uint8_t>> aead_decrypt(TlsCipherAlgo algo, const std::vector<uint8_t>& key,
                                                  const uint8_t nonce[12], const uint8_t* aad, int aad_len,
                                                  const uint8_t* ciphertext, int ciphertext_len,
                                                  const uint8_t* tag) {
    const EVP_CIPHER* cipher = nullptr;
    switch (algo) {
        case TlsCipherAlgo::Aes128Gcm: cipher = EVP_aes_128_gcm(); break;
        case TlsCipherAlgo::Aes256Gcm: cipher = EVP_aes_256_gcm(); break;
        case TlsCipherAlgo::Chacha20Poly1305: cipher = EVP_chacha20_poly1305(); break;
        case TlsCipherAlgo::Unsupported: return std::nullopt;
    }
    if (!cipher || key.empty()) return std::nullopt;

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return std::nullopt;
    struct Guard {
        EVP_CIPHER_CTX* ctx;
        ~Guard() { EVP_CIPHER_CTX_free(ctx); }
    } guard{ctx};

    if (EVP_DecryptInit_ex(ctx, cipher, nullptr, nullptr, nullptr) != 1) return std::nullopt;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, nullptr) != 1) return std::nullopt;
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key.data(), nonce) != 1) return std::nullopt;

    int outl = 0;
    if (aad_len > 0 && EVP_DecryptUpdate(ctx, nullptr, &outl, aad, aad_len) != 1) return std::nullopt;

    std::vector<uint8_t> plaintext(static_cast<size_t>(ciphertext_len));
    int total = 0;
    if (ciphertext_len > 0) {
        if (EVP_DecryptUpdate(ctx, plaintext.data(), &outl, ciphertext, ciphertext_len) != 1) return std::nullopt;
        total = outl;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, const_cast<uint8_t*>(tag)) != 1) return std::nullopt;
    int final_len = 0;
    if (EVP_DecryptFinal_ex(ctx, plaintext.data() + total, &final_len) != 1) {
        return std::nullopt;  // tag verification failed
    }
    total += final_len;
    plaintext.resize(static_cast<size_t>(total));
    return plaintext;
}

// ----- Minimal ClientHello/ServerHello field extraction -- written fresh for this file rather than
// reused/modified from tls_sni.hpp (that file's own job -- opportunistic SNI extraction for
// detection-only tagging -- is related but distinct, and this engine needs different fields:
// client_random/server_random/negotiated cipher_suite/version, not the SNI hostname). Every read
// is bounds-checked via ByteSpan::at(), wrapped in try/catch so a truncated or malformed capture
// degrades to "couldn't parse this handshake message" rather than propagating a ParseError out of
// this engine's own, independently-exception-safe call chain. -----

bool parse_client_hello_random(ByteSpan body, std::array<uint8_t, 32>& out) {
    // ClientHello: legacy_version(2) + random(32) + ...
    try {
        if (body.size() < 34) return false;
        for (size_t i = 0; i < 32; ++i) out[i] = body.at(2 + i);
        return true;
    } catch (const ParseError&) {
        return false;
    }
}

// Parses just enough of a ServerHello to learn its random, negotiated cipher_suite, and whether
// this is really a TLS 1.3 handshake (legacy_version is always 0x0303 on the wire for a TLS 1.3
// ServerHello too -- RFC 8446 section 4.1.3 -- so the real signal is the "supported_versions"
// extension, type 0x002b, whose body for a ServerHello is a single 2-byte version).
bool parse_server_hello(ByteSpan body, std::array<uint8_t, 32>& out_random, uint16_t& cipher_suite,
                         bool& is_tls13) {
    is_tls13 = false;
    try {
        size_t pos = 0;
        if (body.size() < 2 + 32 + 1) return false;
        uint16_t legacy_version = (static_cast<uint16_t>(body.at(pos)) << 8) | body.at(pos + 1);
        pos += 2;
        for (size_t i = 0; i < 32; ++i) out_random[i] = body.at(pos + i);
        pos += 32;

        uint8_t session_id_len = body.at(pos);
        pos += 1;
        pos += session_id_len;
        if (pos + 2 > body.size()) return false;
        cipher_suite = (static_cast<uint16_t>(body.at(pos)) << 8) | body.at(pos + 1);
        pos += 2;
        pos += 1;  // compression_method

        bool found_1_3 = false;
        if (pos + 2 <= body.size()) {
            uint16_t ext_total_len = (static_cast<uint16_t>(body.at(pos)) << 8) | body.at(pos + 1);
            pos += 2;
            size_t ext_end = pos + ext_total_len;
            if (ext_end > body.size()) ext_end = body.size();
            while (pos + 4 <= ext_end) {
                uint16_t ext_type = (static_cast<uint16_t>(body.at(pos)) << 8) | body.at(pos + 1);
                uint16_t ext_len = (static_cast<uint16_t>(body.at(pos + 2)) << 8) | body.at(pos + 3);
                pos += 4;
                if (pos + ext_len > ext_end) break;
                if (ext_type == 0x002b && ext_len == 2) {
                    uint16_t ver = (static_cast<uint16_t>(body.at(pos)) << 8) | body.at(pos + 1);
                    if (ver == 0x0304) found_1_3 = true;
                }
                pos += ext_len;
            }
        }
        is_tls13 = found_1_3 || legacy_version == 0x0304;
        return true;
    } catch (const ParseError&) {
        return false;
    }
}

// ----- Key derivation: looks up `state.client_random` in `key_log`, validates the negotiated
// cipher suite is one this engine supports, and (TLS 1.2: from master_secret via the PRF; TLS 1.3:
// from the four HKDF-Expand-Label'd traffic secrets) fills in every one of TlsSessionState's own
// key/IV fields. On any failure, sets state.gave_up/gave_up_reason itself (the one-reason-string
// convention this whole engine follows) and returns false; callers that already hold a `notes`
// reference just need to check state.gave_up afterward, not thread a separate error code through. */
bool resolve_keys_if_possible(TlsSessionState& state, const TlsKeyLog& key_log, std::vector<std::string>& notes) {
    auto give_up = [&](const std::string& reason) {
        state.gave_up = true;
        state.gave_up_reason = reason;
        notes.push_back(reason);
        return false;
    };

    if (!state.have_client_random) {
        return give_up(
            "TLS ServerHello observed without this session's own ClientHello (capture likely starts "
            "mid-session) -- cannot look up a key-log entry");
    }
    const TlsKeyLogEntry* entry = key_log.find(state.client_random);
    if (!entry) {
        return give_up("no matching --tls-keylog/pcapng-DSB entry found for this TLS session's ClientHello random");
    }

    if (state.is_tls13) {
        TlsCipherSuiteInfo info = lookup_tls13_cipher_suite(state.cipher_suite_wire_value);
        if (info.algo == TlsCipherAlgo::Unsupported) {
            return give_up("TLS 1.3 session negotiated a cipher suite this build does not decrypt (" +
                            hex16(state.cipher_suite_wire_value) + ")");
        }
        if (entry->client_handshake_traffic_secret.empty() || entry->server_handshake_traffic_secret.empty() ||
            entry->client_traffic_secret_0.empty() || entry->server_traffic_secret_0.empty()) {
            return give_up("key-log entry for this TLS 1.3 session is missing one or more required traffic secrets");
        }
        bool sha384 = info.hash_is_sha384;
        state.client_hs_write_key =
            hkdf_expand_label(entry->client_handshake_traffic_secret, "key", {}, info.key_len, sha384);
        state.client_hs_write_iv = hkdf_expand_label(entry->client_handshake_traffic_secret, "iv", {}, 12, sha384);
        state.server_hs_write_key =
            hkdf_expand_label(entry->server_handshake_traffic_secret, "key", {}, info.key_len, sha384);
        state.server_hs_write_iv = hkdf_expand_label(entry->server_handshake_traffic_secret, "iv", {}, 12, sha384);
        state.client_app_write_key = hkdf_expand_label(entry->client_traffic_secret_0, "key", {}, info.key_len, sha384);
        state.client_app_write_iv = hkdf_expand_label(entry->client_traffic_secret_0, "iv", {}, 12, sha384);
        state.server_app_write_key = hkdf_expand_label(entry->server_traffic_secret_0, "key", {}, info.key_len, sha384);
        state.server_app_write_iv = hkdf_expand_label(entry->server_traffic_secret_0, "iv", {}, 12, sha384);
        state.keys_derived = true;
        notes.push_back(std::string("TLS session decrypted via key log (TLS 1.3, ") + info.name + ")");
        return true;
    }

    TlsCipherSuiteInfo info = lookup_tls12_gcm_cipher_suite(state.cipher_suite_wire_value);
    if (info.algo == TlsCipherAlgo::Unsupported) {
        return give_up("TLS 1.2 session negotiated a cipher suite this build does not decrypt (" +
                        hex16(state.cipher_suite_wire_value) +
                        ") -- only the RFC 5288/5289 GCM suites are supported");
    }
    if (entry->master_secret.size() != 48) {
        return give_up("key-log entry for this TLS 1.2 session is missing a CLIENT_RANDOM/master_secret line");
    }

    std::vector<uint8_t> seed;
    seed.reserve(64);
    seed.insert(seed.end(), state.server_random.begin(), state.server_random.end());
    seed.insert(seed.end(), state.client_random.begin(), state.client_random.end());
    size_t key_len = info.key_len;
    size_t block_len = 2 * (key_len + 4);  // RFC 5246 section 6.3: no MAC keys for a GCM suite.
    std::vector<uint8_t> key_block = tls12_prf(entry->master_secret, "key expansion", seed, block_len, info.hash_is_sha384);

    size_t off = 0;
    state.client_write_key.assign(key_block.begin() + static_cast<long>(off),
                                   key_block.begin() + static_cast<long>(off + key_len));
    off += key_len;
    state.server_write_key.assign(key_block.begin() + static_cast<long>(off),
                                   key_block.begin() + static_cast<long>(off + key_len));
    off += key_len;
    state.client_write_iv.assign(key_block.begin() + static_cast<long>(off), key_block.begin() + static_cast<long>(off + 4));
    off += 4;
    state.server_write_iv.assign(key_block.begin() + static_cast<long>(off), key_block.begin() + static_cast<long>(off + 4));
    state.keys_derived = true;
    notes.push_back(std::string("TLS session decrypted via key log (TLS 1.2, ") + info.name + ")");
    return true;
}

// Processes exactly one already-length-delimited TLS record (the 5-byte header already consumed by
// the caller). Mutates `state` (handshake identity, derived keys, per-direction sequence
// number/epoch, reassembly buffers) and returns the ApplicationData plaintext this record revealed,
// if any. `gave_up_now` is set to true iff this call is what made state.gave_up become true, so the
// caller's own record loop can stop after flushing whatever plaintext was already produced.
std::optional<std::vector<uint8_t>> process_one_record(uint8_t content_type, ByteSpan body, bool from_client,
                                                        TlsSessionState& state, const TlsKeyLog& key_log,
                                                        std::vector<std::string>& notes, bool& gave_up_now) {
    gave_up_now = false;
    TlsEpoch& epoch = from_client ? state.client_epoch : state.server_epoch;
    std::vector<uint8_t>& handshake_buffer = from_client ? state.client_handshake_buffer : state.server_handshake_buffer;

    auto give_up = [&](const std::string& reason) {
        state.gave_up = true;
        state.gave_up_reason = reason;
        notes.push_back(reason);
        gave_up_now = true;
    };

    if (content_type == kContentTypeChangeCipherSpec) {
        // TLS 1.2: this direction's own switch from cleartext to its negotiated cipher (RFC 5246
        // section 7.1). TLS 1.3: pure middlebox-compatibility noise (RFC 8446 section 5, Appendix
        // D.4) -- the real epoch transition there is Finished-triggered instead (below).
        if (!state.is_tls13) epoch = TlsEpoch::Application;
        return std::nullopt;
    }

    if (content_type == kContentTypeAlert) {
        return std::nullopt;  // Nothing this engine needs from an alert's own contents either way.
    }

    if (content_type == kContentTypeHandshake && epoch == TlsEpoch::Handshake && !state.handshake_resolved) {
        // Cleartext ClientHello/ServerHello hunting -- the one shape that's always sent in the
        // clear by BOTH TLS 1.2 and TLS 1.3 (RFC 8446 section 5.1's "look like application data"
        // wrinkle only starts after ServerHello).
        size_t cap = resource_limits().max_reassembly_bytes.value_or(kDefaultTlsReassemblyBytes);
        if (handshake_buffer.size() + body.size() > cap) {
            give_up("TLS handshake reassembly buffer exceeded resource limit for this direction");
            return std::nullopt;
        }
        handshake_buffer.insert(handshake_buffer.end(), body.data(), body.data() + body.size());

        while (handshake_buffer.size() >= 4 && !state.handshake_resolved) {
            uint8_t hs_type = handshake_buffer[0];
            uint32_t hs_len = (static_cast<uint32_t>(handshake_buffer[1]) << 16) |
                               (static_cast<uint32_t>(handshake_buffer[2]) << 8) | handshake_buffer[3];
            if (handshake_buffer.size() < 4 + hs_len) break;
            ByteSpan hs_body(handshake_buffer.data() + 4, hs_len);

            if (hs_type == kHandshakeTypeClientHello) {
                std::array<uint8_t, 32> cr{};
                if (parse_client_hello_random(hs_body, cr)) {
                    state.client_random = cr;
                    state.have_client_random = true;
                }
            } else if (hs_type == kHandshakeTypeServerHello) {
                std::array<uint8_t, 32> sr{};
                uint16_t cipher_suite = 0;
                bool is_tls13_ext = false;
                if (parse_server_hello(hs_body, sr, cipher_suite, is_tls13_ext)) {
                    if (is_hello_retry_request_random(sr)) {
                        // HRR: this was never the real ServerHello -- discard and keep hunting for
                        // the real, second ClientHello/ServerHello exchange (see this file's own
                        // LEFT OPEN note). Nothing learned from the first ClientHello is wrong
                        // (RFC 8446 section 4.1.4: a HelloRetryRequest doesn't change the client's
                        // own first ClientHello.random), so state.client_random is left as-is.
                        handshake_buffer.erase(handshake_buffer.begin(),
                                                handshake_buffer.begin() + static_cast<long>(4 + hs_len));
                        continue;
                    }
                    state.server_random = sr;
                    state.have_server_random = true;
                    state.cipher_suite_wire_value = cipher_suite;
                    state.is_tls13 = is_tls13_ext;
                    state.handshake_resolved = true;
                }
            }
            handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + static_cast<long>(4 + hs_len));
        }

        if (state.handshake_resolved) {
            // TLS 1.2's own remaining cleartext flight (Certificate/ServerKeyExchange/...) needs
            // nothing further from this buffer; TLS 1.3 will refill it for a different purpose (the
            // decrypted-inner-plaintext Finished hunt below) once handshake-epoch records arrive.
            handshake_buffer.clear();
            resolve_keys_if_possible(state, key_log, notes);
            if (state.gave_up) gave_up_now = true;
        }
        return std::nullopt;
    }

    if (content_type == kContentTypeHandshake && epoch == TlsEpoch::Handshake && state.handshake_resolved) {
        // TLS 1.2 only (TLS 1.3 never reaches here: its post-ServerHello handshake flight is sent
        // under content_type ApplicationData, not Handshake -- see the "ENCRYPTED HANDSHAKE FLIGHT"
        // paragraph in this file's own header comment). The remaining cleartext Certificate/
        // ServerKeyExchange/CertificateRequest/ServerHelloDone/ClientKeyExchange/
        // CertificateVerify messages before this direction's own ChangeCipherSpec -- nothing this
        // engine needs from any of them.
        return std::nullopt;
    }

    if (!(epoch == TlsEpoch::Application || (state.is_tls13 && epoch == TlsEpoch::Handshake))) {
        return std::nullopt;  // Encrypted-shaped traffic arrived before any epoch is active -- stray.
    }
    if (!state.keys_derived) {
        return std::nullopt;  // Encrypted traffic arrived before keys could be resolved -- stray.
    }

    uint64_t& seq = from_client ? state.client_seq : state.server_seq;

    if (!state.is_tls13) {
        // TLS 1.2 GCM (RFC 5288): GenericAEADCipher.fragment = nonce_explicit(8) + { ciphertext ||
        // tag(16) }. Reachable here only once epoch == Application (this direction's own CCS
        // already seen); content_type is still whatever the sender's own TLSPlaintext.type was
        // (Handshake for an encrypted Finished, ApplicationData for real data, Alert for an
        // encrypted alert) -- TLS 1.2 never hides it the way TLS 1.3 does.
        if (body.size() < 8 + 16) {
            give_up("TLS 1.2 record too short to contain a valid GCM explicit-nonce + tag");
            return std::nullopt;
        }
        const std::vector<uint8_t>& salt = from_client ? state.client_write_iv : state.server_write_iv;
        if (salt.size() != 4) {
            give_up("TLS 1.2 write IV salt has an unexpected length");
            return std::nullopt;
        }
        uint8_t nonce[12];
        std::memcpy(nonce, salt.data(), 4);
        std::memcpy(nonce + 4, body.data(), 8);

        size_t ct_len = body.size() - 8 - 16;
        const uint8_t* ciphertext = body.data() + 8;
        const uint8_t* tag = body.data() + 8 + ct_len;

        uint8_t aad[13];
        write_u64be(aad, seq);
        aad[8] = content_type;
        aad[9] = 0x03;
        aad[10] = 0x03;
        aad[11] = static_cast<uint8_t>((ct_len >> 8) & 0xFF);
        aad[12] = static_cast<uint8_t>(ct_len & 0xFF);

        const std::vector<uint8_t>& key = from_client ? state.client_write_key : state.server_write_key;
        TlsCipherSuiteInfo info = lookup_tls12_gcm_cipher_suite(state.cipher_suite_wire_value);
        auto plain = aead_decrypt(info.algo, key, nonce, aad, 13, ciphertext, static_cast<int>(ct_len), tag);
        ++seq;
        if (!plain) {
            give_up("TLS 1.2 record failed AEAD authentication (stale/incorrect keys, or an unsupported record shape)");
            return std::nullopt;
        }
        if (content_type == kContentTypeApplicationData) return plain;
        return std::nullopt;  // Decrypted Finished/Alert -- nothing to hand upward.
    }

    // TLS 1.3 (RFC 8446 section 5.2/5.3): nonce = static per-epoch write_iv XOR'd with the 64-bit
    // sequence number, right-aligned, big-endian. AAD is the 5-byte record header exactly as sent.
    const std::vector<uint8_t>& key = (epoch == TlsEpoch::Handshake)
                                           ? (from_client ? state.client_hs_write_key : state.server_hs_write_key)
                                           : (from_client ? state.client_app_write_key : state.server_app_write_key);
    const std::vector<uint8_t>& iv = (epoch == TlsEpoch::Handshake)
                                          ? (from_client ? state.client_hs_write_iv : state.server_hs_write_iv)
                                          : (from_client ? state.client_app_write_iv : state.server_app_write_iv);
    if (body.size() < 16) {
        give_up("TLS 1.3 record too short to contain a valid AEAD tag");
        return std::nullopt;
    }
    if (iv.size() != 12) {
        give_up("TLS 1.3 write IV has an unexpected length");
        return std::nullopt;
    }
    uint8_t nonce[12];
    std::memcpy(nonce, iv.data(), 12);
    uint8_t seq_be[8];
    write_u64be(seq_be, seq);
    for (int i = 0; i < 8; ++i) nonce[4 + i] ^= seq_be[i];

    size_t ct_len = body.size() - 16;
    const uint8_t* ciphertext = body.data();
    const uint8_t* tag = body.data() + ct_len;

    uint8_t aad[5];
    aad[0] = content_type;  // Always 0x17 on the wire post-ServerHello -- RFC 8446 section 5.1.
    aad[1] = 0x03;
    aad[2] = 0x03;
    aad[3] = static_cast<uint8_t>((body.size() >> 8) & 0xFF);
    aad[4] = static_cast<uint8_t>(body.size() & 0xFF);

    TlsCipherSuiteInfo info = lookup_tls13_cipher_suite(state.cipher_suite_wire_value);
    auto plain = aead_decrypt(info.algo, key, nonce, aad, 5, ciphertext, static_cast<int>(ct_len), tag);
    ++seq;
    if (!plain) {
        give_up(
            "TLS 1.3 record failed AEAD authentication (stale/incorrect keys, an epoch mismatch, or an "
            "unsupported record shape)");
        return std::nullopt;
    }

    // RFC 8446 section 5.4: TLSInnerPlaintext = content || ContentType || zeros* -- strip the zero
    // padding; the last remaining byte is the real inner content type.
    size_t end = plain->size();
    while (end > 0 && (*plain)[end - 1] == 0) --end;
    if (end == 0) {
        give_up("TLS 1.3 record decrypted to an all-zero TLSInnerPlaintext (no real content type byte present)");
        return std::nullopt;
    }
    uint8_t inner_type = (*plain)[end - 1];
    plain->resize(end - 1);

    if (inner_type == kContentTypeApplicationData) {
        // See this file's own header comment: real application data only ever arrives once this
        // direction's own epoch has already flipped to Application (i.e. after its own Finished).
        // Arriving earlier would be a protocol violation this engine doesn't try to make sense of.
        return epoch == TlsEpoch::Application ? plain : std::nullopt;
    }

    if (inner_type == kContentTypeHandshake) {
        // The encrypted handshake flight (EncryptedExtensions/Certificate/CertificateVerify/
        // Finished, and -- post-Finished -- NewSessionTicket/KeyUpdate) hides behind the SAME outer
        // content type as ApplicationData; this is the one place this engine actually looks inside
        // it, purely to find each direction's own Finished message (the epoch-transition trigger)
        // and to recognize (and give up cleanly on) a KeyUpdate. Reuses handshake_buffer -- already
        // emptied once this session's ClientHello/ServerHello hunt concluded -- for exactly the
        // reassembly shape documented in tls_decrypt.hpp: fed by decrypted inner plaintext now,
        // not raw wire bytes.
        size_t cap = resource_limits().max_reassembly_bytes.value_or(kDefaultTlsReassemblyBytes);
        if (handshake_buffer.size() + plain->size() > cap) {
            give_up("TLS 1.3 encrypted-handshake reassembly buffer exceeded resource limit for this direction");
            return std::nullopt;
        }
        handshake_buffer.insert(handshake_buffer.end(), plain->begin(), plain->end());

        while (handshake_buffer.size() >= 4) {
            uint8_t hs_type = handshake_buffer[0];
            uint32_t hs_len = (static_cast<uint32_t>(handshake_buffer[1]) << 16) |
                               (static_cast<uint32_t>(handshake_buffer[2]) << 8) | handshake_buffer[3];
            if (handshake_buffer.size() < 4 + hs_len) break;

            if (hs_type == kHandshakeTypeFinished && epoch == TlsEpoch::Handshake) {
                epoch = TlsEpoch::Application;
                seq = 0;  // RFC 8446 section 5.3: sequence number resets to zero at every key change.
                handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + static_cast<long>(4 + hs_len));
                notes.push_back(std::string(from_client ? "client" : "server") +
                                 " direction of this TLS 1.3 session switched from handshake to application traffic keys");
                continue;
            }
            if (hs_type == kHandshakeTypeKeyUpdate) {
                give_up("TLS 1.3 post-handshake KeyUpdate encountered -- out of scope for this round, session abandoned");
                return std::nullopt;
            }
            // NewSessionTicket, or anything else handshake-shaped once this direction is already in
            // its application epoch -- nothing this engine needs from it.
            handshake_buffer.erase(handshake_buffer.begin(), handshake_buffer.begin() + static_cast<long>(4 + hs_len));
        }
        return std::nullopt;
    }

    return std::nullopt;  // inner Alert, or anything else -- nothing to hand upward.
}

}  // namespace

std::optional<std::vector<uint8_t>> tls_try_decrypt(ByteSpan tcp_payload, bool from_client, TlsSessionState& state,
                                                     const TlsKeyLog& key_log, std::vector<std::string>& notes) {
    if (state.gave_up || tcp_payload.empty()) return std::nullopt;

    std::vector<uint8_t>& raw_buffer = from_client ? state.client_raw_buffer : state.server_raw_buffer;

    size_t cap = resource_limits().max_reassembly_bytes.value_or(kDefaultTlsReassemblyBytes);
    if (raw_buffer.size() + tcp_payload.size() > cap) {
        state.gave_up = true;
        state.gave_up_reason = "TLS record-layer reassembly buffer exceeded resource limit for this direction";
        notes.push_back(state.gave_up_reason);
        return std::nullopt;
    }
    raw_buffer.insert(raw_buffer.end(), tcp_payload.data(), tcp_payload.data() + tcp_payload.size());

    std::vector<uint8_t> output;
    bool produced = false;

    for (;;) {
        if (raw_buffer.size() < 5) break;
        uint8_t content_type = raw_buffer[0];
        uint16_t length = (static_cast<uint16_t>(raw_buffer[3]) << 8) | raw_buffer[4];
        if (length > kMaxTlsRecordCiphertext) {
            state.gave_up = true;
            state.gave_up_reason = "TLS record declared length exceeds RFC 8446 section 5.2's own ceiling";
            notes.push_back(state.gave_up_reason);
            break;
        }
        if (raw_buffer.size() < static_cast<size_t>(5 + length)) break;  // Need more data for this record.

        ByteSpan body(raw_buffer.data() + 5, length);
        bool gave_up_now = false;
        auto result = process_one_record(content_type, body, from_client, state, key_log, notes, gave_up_now);
        if (result) {
            output.insert(output.end(), result->begin(), result->end());
            produced = true;
        }
        raw_buffer.erase(raw_buffer.begin(), raw_buffer.begin() + static_cast<long>(5 + length));
        if (gave_up_now) break;
    }

    return produced ? std::make_optional(std::move(output)) : std::nullopt;
}

#else  // !CONDUITSCOPE_HAVE_OPENSSL

// Stub: this build has no OpenSSL, so no session is ever decryptable -- the three TLS-wrapped call
// sites in decoder.cpp fall straight back to their existing detection-only ClientHello/SNI tagging,
// with zero behavior change versus this feature's absence. See this file's own header comment.
std::optional<std::vector<uint8_t>> tls_try_decrypt(ByteSpan, bool, TlsSessionState& state, const TlsKeyLog&,
                                                     std::vector<std::string>&) {
    state.gave_up = true;
    if (state.gave_up_reason.empty()) {
        state.gave_up_reason = "this build was compiled without OpenSSL support (CONDUITSCOPE_HAVE_OPENSSL) -- "
                                "TLS decryption is unavailable";
    }
    return std::nullopt;
}

#endif  // CONDUITSCOPE_HAVE_OPENSSL

}  // namespace conduitscope
