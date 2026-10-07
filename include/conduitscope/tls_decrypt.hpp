// SPDX-License-Identifier: Apache-2.0
// tls_decrypt.hpp - decrypts a live TLS session's own ApplicationData records, given an
// externally-supplied key-log entry (tls_keylog.hpp) for it, so the plaintext bytes this codebase
// already decodes in cleartext (MQTT on port 1883, Fox on port 1911, WinRM/SOAP on port 5985) can
// also be decoded when the exact same protocol is wrapped in TLS (MQTTS/8883, FOXS/4911, WinRM-
// over-HTTPS/5986 -- see decoder.cpp's own call sites). This is a BRAND NEW, self-contained crypto
// subsystem built entirely on OpenSSL's EVP API -- it shares ZERO code with, and never extends,
// aes128.hpp/aes128_gcm.hpp/sha256.hpp/hkdf.hpp (this codebase's existing hand-rolled QUIC-only
// crypto quartet). That split is deliberate, not incidental: ROADMAP item 139 (patch295 finding
// F7) ratified exactly this boundary -- "if the crypto surface expands, reach for a well-reviewed
// system/library crypto implementation rather than extending the home-grown crypto subsystem" --
// and decrypting real TLS 1.2/1.3 sessions (AES-256-GCM, ChaCha20-Poly1305, the TLS 1.2 PRF, the
// TLS 1.3 HKDF-Expand-Label key schedule, all keyed by operator-supplied secrets rather than
// QUIC's own publicly-derivable Initial keys) is unambiguously "the crypto surface expanding," so
// every new primitive this file needs is reached from OpenSSL (libcrypto, linked only when
// CONDUITSCOPE_HAVE_OPENSSL is defined -- see CMakeLists.txt's own CONDUITSCOPE_ENABLE_TLS_DECRYPT
// option, mirroring CONDUITSCOPE_ENABLE_LIVE_CAPTURE's own optional-dependency precedent exactly).
// When OpenSSL was not found (or the feature was configured off), this entire file compiles to a
// stub that always returns "cannot decrypt" -- the three TLS-wrapped protocols above simply keep
// today's existing detection-only ClientHello/SNI tagging, with zero behavior change, the same
// graceful-degradation posture live_capture.cpp's own stub already establishes for libpcap/Npcap.
//
// WHY THIS IS AN ANNOTATION FEATURE, NOT CRYPTANALYSIS: see tls_keylog.hpp's own matching
// paragraph -- every secret this file ever uses was handed to this tool outright by the operator
// (a --tls-keylog file, or a pcapng capture's own embedded Decryption Secrets Block); nothing here
// derives, brute-forces, or infers a key from ciphertext alone. A session with no matching key-log
// entry stays exactly as opaque as it always was.
//
// SCOPE, DELIBERATELY NARROWED (confirmed with Jurgen via AskUserQuestion before any of this was
// written -- see docs/DEVELOPMENT.md's ROADMAP entry for this item for the full account of every
// option considered and why):
//   - TLS 1.2: GCM cipher suites ONLY (RFC 5288/5289 -- *_AES_128_GCM_SHA256 and
//     *_AES_256_GCM_SHA384, any key-exchange prefix: RSA, ECDHE-RSA, ECDHE-ECDSA all key-derive
//     identically once the master_secret is known, since the key exchange method only affects HOW
//     the master_secret was agreed, never the key_block derivation from it). CBC-mode TLS 1.2
//     suites (the MAC-then-encrypt-with-explicit-IV family, RFC 5246 section 6.2.3.2) are NOT
//     decrypted this round -- a real, deliberately-accepted gap (see LEFT OPEN below), not an
//     oversight: CBC's own explicit-IV-stripping and MAC-verify-after-decrypt order is extra
//     surface this round's confirmed scope didn't ask for, and GCM is both simpler to get right
//     and, on any TLS stack built in roughly the last decade, the common case regardless.
//   - TLS 1.3: the three AEAD cipher suites RFC 8446 Appendix B.4 actually defines for general use
//     (TLS_AES_128_GCM_SHA256, TLS_AES_256_GCM_SHA384, TLS_CHACHA20_POLY1305_SHA256). The two CCM
//     variants (TLS_AES_128_CCM_SHA256, TLS_AES_128_CCM_8_SHA256 -- intended for constrained IoT
//     stacks, not something either general-purpose IT clients or a typical OT appliance's HTTPS/
//     MQTTS stack negotiates in practice) are recognized as valid wire values but not decrypted.
//   - 0-RTT (early) data, Encrypted Client Hello (ECH), session-ticket/PSK-resumption's own
//     distinct 0-RTT key schedule nuances, and post-handshake key updates (RFC 8446 section 4.6.3)
//     are all out of scope -- see LEFT OPEN below for each.
//   - A single logical application-layer message (one MQTT control packet, one WinRM SOAP
//     envelope, one Fox tuple-stream frame) split across MORE THAN ONE TLS record is not
//     reassembled -- each decrypted record's own plaintext is handed to the real decoder
//     independently. In practice this only matters for a message large enough to exceed one TLS
//     record's roughly-16KB ceiling, which is rare for any of these three protocols' typical
//     message sizes; see LEFT OPEN below.
//
// TLS 1.3's OWN "ENCRYPTED HANDSHAKE FLIGHT LOOKS LIKE APPLICATION DATA" WRINKLE (RFC 8446 section
// 5.1): every record after ServerHello carries the SAME outer ContentType (application_data,
// 0x17) regardless of whether it's still part of the handshake (EncryptedExtensions, Certificate,
// CertificateVerify, Finished -- protected under the HANDSHAKE traffic secret) or genuine
// application data (protected under the separate APPLICATION traffic secret, RFC 8446's own
// CLIENT_TRAFFIC_SECRET_0/SERVER_TRAFFIC_SECRET_0). The outer record alone cannot tell these
// apart -- only decrypting it can, by revealing the TLSInnerPlaintext's own real ContentType (RFC
// 8446 section 5.4, the last non-zero-padding byte). This engine tracks, independently per
// direction, which secret currently protects that direction's records (TlsEpoch below), and
// transitions handshake -> application for that direction the moment a decrypted record's inner
// content turns out to BE that direction's own Finished message (HandshakeType 0x14) -- the exact
// boundary RFC 8446 section 7.2 defines ("...the client's first message after the Finished...": no
// state machine beyond "have I seen this direction's Finished yet" is actually needed). Getting
// this transition right is the single most important correctness property this whole file has --
// decrypting a genuine application-data record under the wrong secret doesn't produce an error, it
// produces APPARENTLY-successfully-decrypted garbage that would otherwise be handed straight to
// MqttDecoder/FoxDecoder/WinRmTcpDecoder as if it were real traffic. See tls_decrypt.cpp's own
// "EPOCH TRANSITION" comment for exactly where this is enforced, and this feature's own CTest
// fixtures (built by actually performing this exact derivation independently in Python's
// `cryptography` library, not merely by re-deriving the same values this file's own code computes)
// for how this is verified rather than merely asserted.
//
// LEFT OPEN, documented honestly rather than silently unsupported:
//   - TLS 1.2 CBC-mode cipher suites (see SCOPE above).
//   - TLS 1.3 0-RTT/early data, ECH, PSK/session-ticket resumption's own 0-RTT nuances, and
//     post-handshake key updates (a session that lives long enough to trigger one -- rare for
//     these three protocols' typical connection lifetimes -- silently stops decrypting from that
//     point on, the same "gave up, noted once" posture a HelloRetryRequest or any other
//     unsupported handshake shape already gets; see tls_decrypt.cpp).
//   - HelloRetryRequest (a ServerHello whose random is the fixed RFC 8446 section 4.1.3 constant):
//     recognized and treated as "restart the handshake search," not specially parsed -- the real
//     second ClientHello/ServerHello exchange that follows is what's actually tracked.
//   - A protocol message spanning more than one TLS record (see SCOPE above).
//   - Client-certificate (mutual TLS) authentication: doesn't affect this engine's own key
//     derivation at all (the master_secret/traffic secrets the key log reveals already account
//     for however the handshake was authenticated), so nothing here special-cases it -- named only
//     because a client Certificate/CertificateVerify flight means more handshake-epoch records to
//     skip past before that direction's own Finished arrives, already handled generically by the
//     same "skip any handshake message whose type isn't Finished" loop every other skipped
//     handshake message type already goes through.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"
#include "conduitscope/tls_keylog.hpp"

namespace conduitscope {

// TLS 1.3's own handshake-vs-application secret epoch for ONE direction of ONE session -- see this
// file's own header comment above. Meaningless for a TLS 1.2 session (which has only ever one set
// of write keys, derived once from master_secret and used for the connection's whole lifetime).
enum class TlsEpoch { Handshake, Application };

// Per-TLS-session state, session-keyed (FlowStateKeying::Session, the same keying MqttFlowState
// already uses -- see protocol_decoder.hpp) since a client_random/server_random/cipher_suite/
// derived keys are all properties of the WHOLE session, not of either direction alone; the two
// directions' own independent sequence numbers/epochs/reassembly buffers are plain sibling fields
// on this one object rather than two separate DirectionalFlow-keyed state objects, since they're
// never looked up independently of each other (every call site already knows which direction it's
// processing and just reads/writes that direction's own fields).
class TlsSessionState : public DecoderFlowState {
public:
    // ----- Handshake identity, filled in as ClientHello/ServerHello are observed -----
    bool have_client_random = false;
    std::array<uint8_t, 32> client_random{};
    bool have_server_random = false;
    std::array<uint8_t, 32> server_random{};
    bool is_tls13 = false;       // meaningful only once handshake_resolved is true
    bool handshake_resolved = false;  // true once ServerHello's own cipher_suite/version are known
    uint16_t cipher_suite_wire_value = 0;

    // ----- Outcome of trying to act on the above -----
    // Once true, this session is never attempted again (missing/unsupported key-log entry,
    // unsupported cipher suite, a HelloRetryRequest, a decrypt/tag-verify failure, or any other
    // condition this engine doesn't handle) -- see tls_decrypt.cpp for exactly which note each
    // cause produces. Checked first on every call so a long-lived undecryptable session costs one
    // lookup per packet, not a repeated re-parse attempt.
    bool gave_up = false;
    std::string gave_up_reason;  // already-formatted, ready to become a DecodedPacket note.

    // ----- Derived key material (TLS 1.2: one set; TLS 1.3: two sets, handshake + application) --
    // Populated once, lazily, the first time both handshake_resolved and a matching TlsKeyLogEntry
    // are available -- see tls_decrypt.cpp's own derive_keys().
    bool keys_derived = false;
    std::vector<uint8_t> client_write_key, server_write_key;          // TLS 1.2 only
    std::vector<uint8_t> client_write_iv, server_write_iv;             // TLS 1.2 only (4-byte GCM salt)
    std::vector<uint8_t> client_hs_write_key, server_hs_write_key;     // TLS 1.3 handshake epoch
    std::vector<uint8_t> client_hs_write_iv, server_hs_write_iv;       // TLS 1.3 handshake epoch (12B)
    std::vector<uint8_t> client_app_write_key, server_app_write_key;   // TLS 1.3 application epoch
    std::vector<uint8_t> client_app_write_iv, server_app_write_iv;     // TLS 1.3 application epoch (12B)

    // ----- Per-direction mutable decode state -----
    uint64_t client_seq = 0, server_seq = 0;  // TLS record sequence number, reset to 0 at a TLS 1.3
                                               // epoch transition (RFC 8446 section 5.3)
    TlsEpoch client_epoch = TlsEpoch::Handshake, server_epoch = TlsEpoch::Handshake;  // TLS 1.3 only

    // Raw (still-encrypted, or not-yet-even-a-complete-record) bytes buffered per direction,
    // across TCP segments, until a complete TLS record's own 5-byte header + declared length is
    // satisfiable. See tls_decrypt.cpp's own record-layer loop.
    std::vector<uint8_t> client_raw_buffer, server_raw_buffer;

    // Handshake-message bytes buffered per direction while still hunting for ClientHello/
    // ServerHello (TLS 1.2: fed by raw outer Handshake-ContentType record bytes directly; TLS 1.3:
    // fed by the DECRYPTED inner plaintext of handshake-epoch records instead -- see this file's
    // own "ENCRYPTED HANDSHAKE FLIGHT" paragraph above) -- a single handshake message (ClientHello,
    // ServerHello, Certificate, ...) can itself span more than one record/decrypted-chunk, so this
    // accumulates until one complete message (4-byte header + declared length) is available.
    std::vector<uint8_t> client_handshake_buffer, server_handshake_buffer;
};

// One cipher suite this engine knows how to derive keys for and decrypt -- see this file's own
// SCOPE section above for exactly which wire values map to a real (non-Unsupported) entry.
enum class TlsCipherAlgo { Unsupported, Aes128Gcm, Aes256Gcm, Chacha20Poly1305 };

struct TlsCipherSuiteInfo {
    TlsCipherAlgo algo = TlsCipherAlgo::Unsupported;
    const char* name = "unknown";  // e.g. "TLS_AES_128_GCM_SHA256" -- for notes/diagnostics only
    size_t key_len = 0;            // 16 (AES-128/ChaCha20 key... see tls_decrypt.cpp: ChaCha20 is
                                    // always a 32-byte key despite AES-128's own 16) or 32
    bool hash_is_sha384 = false;   // PRF (TLS 1.2) / HKDF (TLS 1.3) hash: false = SHA-256
};

// Looks up `wire_value` (the 2-byte cipher suite ServerHello negotiated, e.g. 0x1301 for
// TLS_AES_128_GCM_SHA256) against this engine's own curated, deliberately-narrow table (see SCOPE
// above). Returns an entry with algo == Unsupported for anything not in that table -- never throws,
// never guesses a close match.
TlsCipherSuiteInfo lookup_tls13_cipher_suite(uint16_t wire_value);
TlsCipherSuiteInfo lookup_tls12_gcm_cipher_suite(uint16_t wire_value);

// The main entry point, called from decoder.cpp at each of the three TLS-wrapped call sites
// (MQTTS/8883, FOXS/4911, WinRM-over-HTTPS/5986) in place of (ahead of, falling back to on
// failure) the existing detection-only ClientHello/SNI tagging. `tcp_payload` is this one TCP
// segment's own bytes (already whatever same-payload coalescing decoder.cpp's own generic TCP
// reassembly already produced -- this function does its OWN, separate TLS-record-layer
// reassembly on top, independent of and unaware of that outer layer); `from_client` is true when
// this payload travelled from the lower (or configured) port to the higher one, i.e. client ->
// server. Returns the concatenated plaintext of every complete ApplicationData record this call
// newly decrypted (possibly more than one TLS record's worth, if several were coalesced into one
// TCP segment) -- std::nullopt when nothing new was decrypted this call (still buffering a partial
// record, this was handshake/alert/change-cipher-spec traffic, keys aren't available yet, or this
// session already gave up -- see `state.gave_up_reason` for why). A returned vector is never
// empty when the optional is engaged. `notes` receives zero or one human-readable line worth
// appending to the packet's own notes (e.g. "TLS session decrypted via key log (TLS 1.3,
// TLS_AES_128_GCM_SHA256)" the first time a session's keys are derived, or the one-line reason a
// session just gave up) -- callers append whatever comes back, same convention every other
// decoder's own `notes` already follows.
//
// Compiles to an always-nullopt stub when CONDUITSCOPE_HAVE_OPENSSL is not defined -- see this
// file's own header comment.
std::optional<std::vector<uint8_t>> tls_try_decrypt(ByteSpan tcp_payload, bool from_client,
                                                     TlsSessionState& state, const TlsKeyLog& key_log,
                                                     std::vector<std::string>& notes);

// True when this build was compiled with OpenSSL support (CONDUITSCOPE_HAVE_OPENSSL) -- decoder.cpp
// uses this once, to decide whether a `--tls-keylog`/DSB-bearing capture should even attempt the
// session-tracking/record-reassembly machinery above at all, and to shape the one-time startup
// note a builder without OpenSSL sees (mirroring live_capture.cpp's own
// ensure_pcap_runtime_available diagnostic posture for a missing optional dependency).
bool tls_decrypt_build_supported();

}  // namespace conduitscope
