// SPDX-License-Identifier: Apache-2.0
// quic.cpp - see quic.hpp for the design rationale, sourcing note, and deliberate scope limits.
//
// Layered, in the order a real Initial packet is actually unwrapped:
//   1. Long/short header framing (RFC 9000 section 17) -- read_long_header below.
//   2. RFC 9001 section 5.4 header protection removal (AES-128-ECB over a 16-byte ciphertext
//      sample) -- remove_header_protection below.
//   3. RFC 9001 section 5.2 Initial secret derivation (HKDF-Extract/Expand-Label over the packet's
//      own Destination Connection ID and the version's public initial_salt) -- derive_initial_keys
//      below.
//   4. AEAD_AES_128_GCM decryption of the unprotected payload -- this codebase's own
//      aes128_gcm_decrypt (aes128_gcm.hpp).
//   5. A minimal QUIC frame walk (RFC 9000 section 19) looking for one CRYPTO frame at Offset 0,
//      handed to tls_sni.hpp's own try_parse_tls_handshake_client_hello -- extract_sni_from_payload
//      below.
#include "conduitscope/quic.hpp"

#include <cstdio>
#include <cstring>

#include "conduitscope/aes128.hpp"
#include "conduitscope/aes128_gcm.hpp"
#include "conduitscope/hkdf.hpp"
#include "conduitscope/tls_sni.hpp"

namespace conduitscope {

namespace {

bool port_in(uint16_t port, uint16_t default_port, const std::vector<uint16_t>& extra) {
    if (port == default_port) return true;
    for (uint16_t p : extra) {
        if (port == p) return true;
    }
    return false;
}

// RFC 9001 Appendix A.1's own published constant for QUIC version 1 -- see quic.hpp's own
// "Sourcing note" for how this was verified (independently corroborated, and proven correct end
// to end by tests/make_quic_sample_pcap.py's own synthetic Initial packet actually decrypting).
constexpr uint8_t kInitialSaltV1[20] = {0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17,
                                        0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad, 0xcc, 0xbb, 0x7f, 0x0a};

constexpr uint32_t kQuicVersion1 = 0x00000001;

// Reads one QUIC variable-length integer (RFC 9000 section 16): the first byte's top two bits
// select a 1/2/4/8-byte total encoding, and the remaining 6/14/30/62 bits (big-endian across
// however many bytes) are the value. Throws ParseError (via Cursor's own bounds checking) if the
// declared length doesn't fit in what's left of the span -- the same "let the bounds-checked
// primitive do the throwing" idiom every other parser in this codebase already uses.
uint64_t read_varint(Cursor& cur) {
    uint8_t first = cur.u8();
    int len_exponent = first >> 6;  // 0,1,2,3 -> 1,2,4,8 total bytes
    uint64_t value = static_cast<uint64_t>(first & 0x3f);
    int extra_bytes = (len_exponent == 0) ? 0 : (len_exponent == 1) ? 1 : (len_exponent == 2) ? 3 : 7;
    for (int i = 0; i < extra_bytes; ++i) {
        value = (value << 8) | static_cast<uint64_t>(cur.u8());
    }
    return value;
}

// The parsed-but-not-yet-unprotected shape of a long-header packet (RFC 9000 section 17.2), up to
// (but not including) whatever type-specific payload follows the Source Connection ID -- every
// long-header type shares exactly this much framing.
struct LongHeaderPrefix {
    uint8_t byte0 = 0;
    uint32_t version = 0;
    ByteSpan dcid;
    ByteSpan scid;
    size_t header_end = 0;  // byte offset right after the Source Connection ID
};

std::optional<LongHeaderPrefix> read_long_header_prefix(ByteSpan udp_payload) {
    Cursor cur(udp_payload);
    LongHeaderPrefix hdr;
    hdr.byte0 = cur.u8();
    hdr.version = cur.u32be();
    uint8_t dcid_len = cur.u8();
    if (dcid_len > 20) return std::nullopt;  // RFC 9000 17.2's own maximum
    hdr.dcid = cur.bytes(dcid_len);
    uint8_t scid_len = cur.u8();
    if (scid_len > 20) return std::nullopt;
    hdr.scid = cur.bytes(scid_len);
    hdr.header_end = cur.position();
    return hdr;
}

// RFC 9001 section 5.2's own three-step derivation, restricted to the client's own direction
// (QUIC/TLS 1.3's "client in" label) -- this codebase only ever decrypts a client-originated
// Initial packet, see quic.hpp's own file header comment for why that's not a limitation in
// practice. `dcid` is the Initial packet's own Destination Connection ID field.
struct InitialKeys {
    uint8_t key[16];
    uint8_t iv[12];
    uint8_t hp[16];
};

InitialKeys derive_initial_client_keys(ByteSpan dcid) {
    uint8_t initial_secret[32];
    hkdf_extract(kInitialSaltV1, sizeof(kInitialSaltV1), dcid.data(), dcid.size(), initial_secret);

    std::vector<uint8_t> client_secret_v = hkdf_expand_label(initial_secret, "client in", nullptr, 0, 32);
    uint8_t client_secret[32];
    std::memcpy(client_secret, client_secret_v.data(), 32);

    InitialKeys out;
    std::vector<uint8_t> key_v = hkdf_expand_label(client_secret, "quic key", nullptr, 0, 16);
    std::vector<uint8_t> iv_v = hkdf_expand_label(client_secret, "quic iv", nullptr, 0, 12);
    std::vector<uint8_t> hp_v = hkdf_expand_label(client_secret, "quic hp", nullptr, 0, 16);
    std::memcpy(out.key, key_v.data(), 16);
    std::memcpy(out.iv, iv_v.data(), 12);
    std::memcpy(out.hp, hp_v.data(), 16);
    return out;
}

// RFC 9001 section 5.4: removes header protection in place over `packet` (a mutable copy of the
// captured bytes -- the unprotect step genuinely rewrites byte0's low 4 bits and the Packet
// Number field, both of which the AEAD step below needs corrected before it can compute the
// right Associated Data). `pn_offset` is the byte offset where the (still-protected) Packet
// Number field begins, i.e. LongHeaderPrefix::header_end plus however many Token/Length bytes
// (Initial-specific) came before it. Returns the now-unprotected packet number's byte length
// (1-4, RFC 9000 17.1), or std::nullopt if there isn't enough captured data left to sample (the
// sample always needs 16 bytes starting 4 bytes into the Packet Number field, regardless of that
// field's real length -- RFC 9001 section 5.4.2's own "assume 4 bytes" allowance).
std::optional<int> remove_header_protection(std::vector<uint8_t>& packet, size_t pn_offset,
                                             const uint8_t hp_key[16]) {
    size_t sample_offset = pn_offset + 4;
    if (sample_offset + 16 > packet.size()) return std::nullopt;

    uint8_t mask[16];
    aes128_encrypt_block(hp_key, packet.data() + sample_offset, mask);

    packet[0] = static_cast<uint8_t>(packet[0] ^ (mask[0] & 0x0f));  // long header: low 4 bits only
    int pn_length = (packet[0] & 0x03) + 1;
    if (pn_offset + static_cast<size_t>(pn_length) > packet.size()) return std::nullopt;
    for (int i = 0; i < pn_length; ++i) {
        packet[pn_offset + static_cast<size_t>(i)] =
            static_cast<uint8_t>(packet[pn_offset + static_cast<size_t>(i)] ^ mask[1 + i]);
    }
    return pn_length;
}

// Reconstructs the 12-byte AEAD nonce (RFC 9001 section 5.3: iv XOR packet_number, the packet
// number left-padded with zeros to iv's own length). This codebase deliberately does not
// reconstruct a truncated packet number against a "largest acknowledged" value the way a real
// QUIC stack must (RFC 9000 section 17.1) -- it has no connection state to reconstruct against in
// the first place -- and instead uses the unprotected field's own bytes directly as the full
// packet number. This is exactly correct for every Initial packet a real handshake's first flight
// ever sends (packet numbers 0, 1, 2, ... in that space, always small enough to need no
// reconstruction) and is the same "single packet, no cross-packet state" scope limit quic.hpp's
// own file header comment already documents.
void build_nonce(const uint8_t iv[12], const uint8_t* pn_bytes, int pn_length, uint8_t out_nonce[12]) {
    uint8_t padded_pn[12] = {0};
    std::memcpy(padded_pn + (12 - pn_length), pn_bytes, static_cast<size_t>(pn_length));
    for (int i = 0; i < 12; ++i) out_nonce[i] = static_cast<uint8_t>(iv[i] ^ padded_pn[i]);
}

// Walks the decrypted Initial payload's QUIC frames (RFC 9000 section 19) looking for exactly one
// CRYPTO frame (type 0x06) at Offset 0, tolerating PADDING (0x00) and PING (0x01) frames around
// it -- see quic.hpp's own file header comment for why any other frame type stops the walk rather
// than being parsed and skipped. Returns the SNI, or std::nullopt if no usable ClientHello/SNI
// was found (never throws -- a malformed decrypted payload is no more special than a malformed
// captured one anywhere else in this codebase, so this quietly gives up the same way).
std::optional<std::string> extract_sni_from_initial_payload(const std::vector<uint8_t>& plaintext) {
    ByteSpan span(plaintext.data(), plaintext.size());
    Cursor cur(span);
    try {
        while (!cur.at_end()) {
            uint64_t frame_type = read_varint(cur);
            if (frame_type == 0x00 || frame_type == 0x01) continue;  // PADDING / PING: no frame body
            if (frame_type == 0x06) {                                // CRYPTO
                uint64_t offset = read_varint(cur);
                uint64_t length = read_varint(cur);
                ByteSpan data = cur.bytes(static_cast<size_t>(length));
                if (offset != 0) continue;  // not the start of the handshake message -- see this
                                              // file's own "no reassembly" scope limit
                auto hello = try_parse_tls_handshake_client_hello(data);
                if (hello && !hello->sni.empty()) return hello->sni;
                return std::nullopt;
            }
            // An unrecognized frame type: QUIC's own frame encoding has no generic length prefix
            // that would let this be skipped safely, so stop here rather than guess.
            return std::nullopt;
        }
    } catch (const ParseError&) {
        return std::nullopt;
    }
    return std::nullopt;
}

// Builds the "recognized, but not (or not usefully) decrypted" QuicMatch every long-header
// non-decryptable case below falls back to -- Handshake/0-RTT/Retry packets, Version Negotiation,
// unsupported versions, a truncated capture, or a client Initial whose AEAD tag simply didn't
// verify (see quic.hpp's own file header comment for why that last case is expected, not an
// error, for any Initial packet that wasn't the client's own).
QuicMatch name_only_match(const std::string& detail) {
    QuicMatch m;
    m.summary = "QUIC " + detail;
    return m;
}

}  // namespace

std::optional<QuicMatch> try_recognize_quic(ByteSpan udp_payload, uint16_t src_port, uint16_t dst_port,
                                             const std::vector<uint16_t>& extra_ports) {
    if (udp_payload.size() < 7) return std::nullopt;  // byte0 + 4-byte version + 2 length bytes, at minimum

    uint8_t byte0 = udp_payload.at(0);
    if ((byte0 & 0x80) == 0) {
        // Short-header (1-RTT) packet -- see quic.hpp's own file header comment for why this is
        // the weakest-gate, port-only treatment (same as TeamViewer/AnyDesk/LWAPP elsewhere in
        // this codebase): once the handshake completes, nothing in a QUIC packet's own header
        // says "QUIC" any more strongly than the single required Fixed Bit.
        if ((byte0 & 0x40) == 0) return std::nullopt;
        bool port_match = port_in(src_port, QUIC_PORT_443, extra_ports) ||
                           port_in(dst_port, QUIC_PORT_443, extra_ports) ||
                           port_in(src_port, QUIC_PORT_8443, extra_ports) ||
                           port_in(dst_port, QUIC_PORT_8443, extra_ports);
        if (!port_match) return std::nullopt;
        QuicMatch m;
        m.summary = "QUIC short-header (1-RTT) packet -- an established session, not a handshake; "
                    "no version/type field remains once the handshake completes for this decoder "
                    "to check";
        m.notes.push_back(
            "recognized by port alone, the weakest gate this codebase uses (the same treatment "
            "TeamViewer/AnyDesk/LWAPP get) -- any other UDP protocol sharing this port with the "
            "Fixed Bit coincidentally set would look identical");
        return m;
    }

    try {
        auto hdr = read_long_header_prefix(udp_payload);
        if (!hdr) return std::nullopt;

        if (hdr->version == 0) {
            // Version Negotiation (RFC 9000 17.2.1): no Fixed Bit requirement (the rest of byte0
            // is unused by spec), no protected payload of any kind -- what follows is a plain
            // list of the SERVER's own supported versions, cleartext by design. Named only.
            //
            // "Header Form bit set, Version == 0" is, on its own, a genuinely weak signal --
            // found colliding in practice with an unrelated protocol's own deliberately-invalid
            // test fixture (a mostly-zeroed CAPWAP preamble/transport header happened to satisfy
            // it). A real VN packet is never JUST a header, though: it exists specifically to
            // carry the server's list of supported versions, each a 4-byte entry (RFC 9000
            // 17.2.1) -- requiring at least one such entry (and a whole number of them) is a
            // genuine structural check, not a coincidence, and is what actually rejected that
            // collision once added.
            size_t trailing = udp_payload.size() - hdr->header_end;
            if (trailing < 4 || trailing % 4 != 0) return std::nullopt;
            return name_only_match("Version Negotiation packet (" + std::to_string(trailing / 4) +
                                    " supported version(s) offered)");
        }
        if ((byte0 & 0x40) == 0) return std::nullopt;  // Fixed Bit must be 1 for every other long-header type

        uint8_t long_type = (byte0 >> 4) & 0x03;  // RFC 9000 17.2 Table 5: 0=Initial,1=0-RTT,2=Handshake,3=Retry

        // Bug fix (post-release, Jurgen's own report): Header Form + Fixed Bit + long_type alone
        // is NOT a strong enough signal to accept unconditionally, despite this file's own header
        // comment originally claiming otherwise -- those are only 4 bits of byte0 (2 fixed values
        // plus a 2-bit type field), true of roughly 1 in 4 arbitrary UDP payloads whose first byte
        // happens to land that way, port-independently. Confirmed against a real capture: a busy
        // NBT-NS (UDP port 137) broadcast segment, whose 2-byte Transaction ID becomes byte0/
        // byte1 here, was misdetected as QUIC 0-RTT/Handshake packets on a large fraction of the
        // NBT-NS traffic that didn't itself parse as valid NBT-NS. Every OTHER structural gate in
        // this file requires an actual cross-checked, self-consistent field (Version Negotiation's
        // own whole-number-of-4-byte-versions check above; Initial's own Length-field/captured-
        // bytes cross-check below) -- 0-RTT/Handshake/Retry were the one place that check was
        // missing, despite RFC 9000 giving each of them a field to check it against. Fixed by
        // requiring the same kind of self-consistency the other three paths already require:
        //   - 0-RTT (17.2.3) / Handshake (17.2.4) share Initial's own trailing shape minus the
        //     Token field: Length (varint) + Packet Number + protected Payload+Tag. Reading that
        //     Length field and cross-checking `header_end + Length` against what was actually
        //     captured (and that Length is at least large enough for a 1-byte Packet Number plus a
        //     16-byte AEAD tag) is the identical check the Initial branch below already performs --
        //     unlike Initial, a failure here is treated as "not a match" outright rather than a
        //     tolerant "truncated capture" fallback: these two types are never decrypted regardless
        //     of how much was captured, so there is no analytical payoff to weigh against closing
        //     the false-positive gap completely.
        //   - Retry (17.2.5) has no Length/Packet-Number field at all -- what follows SCID is a
        //     variable-length Retry Token immediately followed by a fixed 16-byte Retry Integrity
        //     Tag, nothing else. Requiring at least those 16 trailing bytes is the analogous check.
        // Random bytes satisfying byte0's 4-bit pattern essentially never also satisfy one of these
        // numeric relationships by coincidence, which is what actually rejects the NBT-NS collision
        // (confirmed against the real capture that surfaced this bug -- see
        // quic_0rtt_handshake_reject_non_quic_on_shared_port in CMakeLists.txt).
        // Bug fix, round two (post-release, Jurgen's own second report): the fix above closed
        // 0-RTT/Handshake but left two gaps in the very same real NBT-NS capture that surfaced it --
        // both fixed the same way, by turning an existing tolerant check into a genuine reject:
        //   - Retry (below) had NO structural check at all beyond "16 trailing bytes exist," which
        //     is true of nearly any UDP payload of ordinary size -- not a meaningful check. Retry has
        //     no Length/Packet-Number field to self-check the way 0-RTT/Handshake/Initial do (RFC
        //     9000 17.2.5's Retry Token is unlength-prefixed; only the trailing 16-byte Retry
        //     Integrity Tag is fixed-size), and verifying that tag cryptographically needs the
        //     original connection's own Destination Connection ID, which isn't present in the Retry
        //     packet itself and isn't state this single-packet decoder tracks (see this file's own
        //     "no cross-packet state" scope limit). The one field a Retry packet still carries that
        //     CAN be checked without any of that is Version: real Retry traffic is, in practice,
        //     always QUIC v1 (v2, RFC 9369, remains vanishingly rare in deployment), so requiring an
        //     exact match closes the gap almost completely -- an arbitrary payload's four
        //     byte0-pattern bits landing right is roughly 1-in-4, but its full 32-bit Version field
        //     also landing on exactly 0x00000001 by coincidence is not (confirmed against the real
        //     capture: every misdetected NBT-NS packet's Transaction-ID-derived "version" bytes were
        //     some arbitrary non-1 value). This does mean a genuine, rare QUIC v2 Retry packet is no
        //     longer recognized -- an accepted, documented trade-off, the same kind Initial's own
        //     "only version 1 is decrypted" scope limit already makes elsewhere in this file.
        //   - Initial (below) had a check, but it conflated two different situations into one
        //     tolerant fallback: `length_field < 17` (the field is simply too small to ever hold a
        //     real Initial packet's mandatory 1-byte-minimum Packet Number plus 16-byte AEAD tag --
        //     not a truncation at all, just an inconsistent field) was treated exactly the same as
        //     `pn_offset + length_field > udp_payload.size()` (the field IS plausible, it just wasn't
        //     fully captured -- genuine snaplen truncation). Splitting them so only the second one
        //     still gets the tolerant "truncated capture" match, while the first is rejected outright
        //     -- the same treatment the 0-RTT/Handshake branch's identical check already gets -- is
        //     what actually rejects the NBT-NS collision (its garbage-derived length_field decoded to
        //     0, which the old combined check let through as "truncated," not what it was).
        if (long_type == 3) {
            if (hdr->version != kQuicVersion1) return std::nullopt;
            if (udp_payload.size() < hdr->header_end + 16) return std::nullopt;
            return name_only_match("Retry packet");
        }
        if (long_type == 1 || long_type == 2) {
            Cursor len_cur(udp_payload.from(hdr->header_end));
            uint64_t length_field = read_varint(len_cur);
            size_t pn_offset = hdr->header_end + len_cur.position();
            if (pn_offset + length_field > udp_payload.size() || length_field < 17) return std::nullopt;
            return name_only_match(long_type == 1 ? "0-RTT packet (encrypted under session resumption keys)"
                                                    : "Handshake packet (encrypted under Handshake-level keys)");
        }

        // long_type == 0: Initial.
        Cursor cur(udp_payload.from(hdr->header_end));
        uint64_t token_len = read_varint(cur);
        cur.skip(static_cast<size_t>(token_len));
        uint64_t length_field = read_varint(cur);  // covers Packet Number + protected payload + tag
        size_t pn_offset = hdr->header_end + (cur.position());
        if (length_field < 17) {
            // Too short to possibly hold even a 1-byte Packet Number plus a 16-byte AEAD tag --
            // structurally invalid regardless of how much was captured, not a truncated real Initial
            // packet. Rejected outright (see this branch's own "round two" comment above).
            return std::nullopt;
        }
        if (pn_offset + length_field > udp_payload.size()) {
            // A plausible (>= 17) length_field that just wasn't fully captured -- genuine snaplen
            // truncation, same tolerance GOOSE/SV/EtherCAT's own declared-length checks already have.
            return name_only_match("Initial packet (truncated capture -- not decrypted)");
        }
        if (hdr->version != kQuicVersion1) {
            return name_only_match("Initial packet, version 0x" + [&] {
                char buf[16];
                std::snprintf(buf, sizeof(buf), "%08x", hdr->version);
                return std::string(buf);
            }() + " (only version 1 is decrypted -- see quic.hpp's own file header comment)");
        }

        // From here on, a decrypt failure (bad tag, or a structural surprise inside the
        // now-decrypted frame stream) is expected and unexceptional whenever this packet wasn't
        // actually the client's own Initial -- see quic.hpp's own file header comment -- so every
        // failure path below falls back to a name-only match rather than propagating an error.
        std::vector<uint8_t> packet = udp_payload.to_vector();
        InitialKeys keys = derive_initial_client_keys(hdr->dcid);
        auto pn_length = remove_header_protection(packet, pn_offset, keys.hp);
        if (!pn_length) return name_only_match("Initial packet (too little captured data to sample "
                                                "for header protection removal -- not decrypted)");

        uint8_t nonce[12];
        build_nonce(keys.iv, packet.data() + pn_offset, *pn_length, nonce);

        size_t aad_len = pn_offset + static_cast<size_t>(*pn_length);
        size_t ciphertext_and_tag_len = static_cast<size_t>(length_field) - static_cast<size_t>(*pn_length);
        if (ciphertext_and_tag_len < 16) {
            return name_only_match("Initial packet (declared length too short to hold an AEAD tag -- "
                                    "not decrypted)");
        }
        size_t ciphertext_len = ciphertext_and_tag_len - 16;
        const uint8_t* ciphertext_ptr = packet.data() + aad_len;
        const uint8_t* tag_ptr = ciphertext_ptr + ciphertext_len;

        std::vector<uint8_t> plaintext;
        bool ok = aes128_gcm_decrypt(keys.key, nonce, packet.data(), aad_len, ciphertext_ptr, ciphertext_len,
                                      tag_ptr, plaintext);
        if (!ok) {
            return name_only_match("Initial packet (AEAD tag did not verify -- most likely a server "
                                    "response rather than the client's own first Initial packet; see "
                                    "quic.hpp's own file header comment for why only the latter can be "
                                    "decrypted here)");
        }

        QuicMatch m;
        auto sni = extract_sni_from_initial_payload(plaintext);
        if (sni) {
            m.sni = *sni;
            m.summary = "QUIC Initial packet, decrypted (RFC 9001 publicly-derivable keys) -- ClientHello "
                        "SNI: " +
                        *sni;
        } else {
            m.summary = "QUIC Initial packet, decrypted (RFC 9001 publicly-derivable keys), but no usable "
                        "ClientHello/SNI was found in its CRYPTO frame -- see quic.hpp's own file header "
                        "comment for this file's frame-walk scope limits";
        }
        return m;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

}  // namespace conduitscope
