// SPDX-License-Identifier: Apache-2.0
// quic.hpp - QUIC (RFC 9000/9001) recognition, joining Tier 2 ("lateral-movement and credential-
// harvesting protocols that should be absent from a production OT segment entirely" -- ROADMAP
// item 18's own wording) of the "IT protocols an OT auditor flags" family (see it_protocols.hpp's
// own file header comment) alongside HTTPS: QUIC is HTTP/3's own transport (RFC 9114), so an
// unexpected outbound QUIC session from a production OT segment is the identical finding HTTPS's
// own Tier 2 entry already flags, just carried over UDP instead of TCP -- an auditor cares about
// the destination, not which transport got it there.
//
// Unlike every other protocol in this whole family, QUIC's long-header Initial packets are
// genuinely, PASSIVELY decryptable, with no eavesdropped key exchange or out-of-band secret
// needed at all: RFC 9001 section 5.2 derives Initial-packet protection keys purely from a
// public, per-QUIC-version constant (the "initial salt") and the packet's own cleartext
// Destination Connection ID -- unlike every later QUIC packet (Handshake onward), which genuinely
// IS encrypted under secret, negotiated keys this decoder has no way to obtain (the same
// "recognized but not decoded" posture this whole family already has elsewhere -- e.g. RDP/SSH/
// SMB past their own handshakes). This file uses that one narrow exception to recover the
// identical signal HTTPS's own ClientHello parsing already surfaces (tls_sni.hpp): the Server
// Name Indication (SNI, RFC 6066) of the TLS 1.3 ClientHello a client's Initial packet carries in
// its CRYPTO frame -- QUIC transmits raw TLS Handshake messages with no TLS record-layer wrapper
// at all (RFC 9001 section 4), exactly the shape tls_sni.hpp's own
// try_parse_tls_handshake_client_hello was split out to accept directly (see that file's own
// comment on it).
//
// Sourcing note, in keeping with this codebase's own standard for anything cryptographic (see
// hkdf.cpp's/aes128.cpp's/aes128_gcm.cpp's own file header comments): every constant/algorithm
// quic.cpp uses (the version 1 initial_salt, the HKDF-Expand-Label strings "client in"/"quic
// key"/"quic iv"/"quic hp", the header-protection sampling offset) was cross-checked against more
// than one independent technical source rather than transcribed from memory alone, and the whole
// pipeline is proven end to end by decoding a synthetically constructed, byte-exact QUIC v1
// Initial packet (see tests/make_quic_sample_pcap.py) with a known, chosen SNI baked in -- not
// merely unit-tested primitive by primitive the way sha256.cpp/hkdf.cpp/aes128.cpp/
// aes128_gcm.cpp's own crypto_selftest already are (see that binary's own file header comment).
//
// ---------------------------------------------------------------------------------------------
// Scope, deliberately narrow, mirroring this codebase's existing "give up rather than guess"
// posture (tls_sni.hpp's own file header comment; DoH's single-TCP-segment limit) at every step:
//
//   - Only QUIC version 1 (0x00000001, RFC 9000/9001 -- the version essentially all real-world
//     QUIC/HTTP-3 traffic uses as of this writing) gets decryption attempted. QUIC version 2
//     (0x6b3343cf, RFC 9369) and any other version are named "quic" by their long-header framing
//     alone, with no attempt to decrypt -- v2 uses a genuinely different initial_salt this
//     codebase has not independently built and end-to-end-proven the way v1's is (see the
//     sourcing note above); a real gap in real-world coverage is a reason to add it later with
//     the same rigor, not a reason to ship an unverified second constant now.
//   - Only a genuinely CLIENT-originated Initial packet ever successfully decrypts. RFC 9001's
//     own key derivation uses the Destination Connection ID of the CLIENT's first Initial packet
//     specifically -- for the client's own packet, that's trivially its own DCID field, but for
//     the SERVER's Initial reply, the DCID field is the client's SCID (a different value), which
//     would need remembering across packets this decoder never reassembles (the same "single
//     segment/packet, no cross-packet state" posture tls_sni.hpp's own file header comment
//     documents for TCP). This file does NOT special-case that: it simply attempts decryption
//     with each Initial packet's OWN DCID field unconditionally, which is only ever correct for a
//     client packet -- a server's Initial (or any packet using a genuinely different key) just
//     fails the AEAD tag check and falls back to "recognized, not decrypted", the same graceful
//     degradation an outright-wrong guess gets everywhere else in this codebase. This also,
//     conveniently, loses no real coverage: the server's own Initial carries ServerHello, never
//     another ClientHello, so there was never an SNI to find there regardless.
//   - Only a CRYPTO frame (type 0x06) at Offset 0 is read, optionally preceded/followed by
//     PADDING (0x00) or PING (0x01) frames in the SAME packet -- real client Initial packets are
//     padded to at least 1200 bytes (RFC 9000 section 14.1) and, on the very first flight, carry
//     nothing but the ClientHello's CRYPTO frame plus that padding, so this covers the
//     overwhelming majority of real traffic. Any OTHER frame type (ACK, CONNECTION_CLOSE, ...)
//     stops this file's own frame walk outright, rather than attempting to parse and skip a frame
//     shape it doesn't need to (QUIC's own frame encoding has no generic length prefix that would
//     let an unrecognized frame be skipped safely) -- the same "stop rather than guess" posture as
//     everywhere else in this scope list. A ClientHello split across more than one CRYPTO frame
//     (large ones -- many TLS extensions, a big certificate-compression list) is simply not
//     detected rather than reassembled, the identical tolerance tls_sni.hpp's own file header
//     comment already documents for a ClientHello spanning more than one TCP segment.
//   - Handshake/0-RTT/Retry long-header packets are named "quic" by their own framing alone (see
//     the per-type handling below) -- none of these carry anything this decoder could usefully
//     decrypt even in principle (0-RTT/1-RTT need the connection's own negotiated secrets, which
//     this decoder never has; Retry carries no protected payload at all; Handshake packets carry
//     ServerHello/Certificate/Finished, never another ClientHello). Bug fix (post-release, Jurgen's
//     own report): "framing alone" still means a real structural cross-check for each type (the
//     Length field's own value against how many bytes were actually captured, for 0-RTT/
//     Handshake; the mandatory 16-byte Retry Integrity Tag, for Retry) -- NOT just byte0's Header
//     Form/Fixed Bit/type bits in isolation, which this file originally (incorrectly) treated as
//     sufficient on its own and which a real capture proved is not: those 4 bits alone match
//     roughly 1 in 4 arbitrary UDP payloads port-independently, and were observed misdetecting a
//     large fraction of a busy NBT-NS (UDP port 137) broadcast segment's traffic as QUIC. See
//     try_recognize_quic's own comment in quic.cpp for the fix.
//   - Short-header (1-RTT) packets get the weakest-gate, port-only treatment TeamViewer/AnyDesk/
//     LWAPP already have in this same family (it_protocols.hpp's own Tier 1/Tier 4 comments):
//     once the handshake completes, a QUIC packet's own header carries no version or type field
//     at all to check, only a Fixed Bit and an opaque connection ID/packet number/ciphertext --
//     recognized only on a default/configured QUIC port, with the Fixed Bit as the one structural
//     check available, and says so honestly in its own note.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The conventional QUIC/HTTP-3 UDP port -- shared with tls_sni.hpp's own DOH_PORT/it_protocols.hpp's
// own HTTPS_PORT_443 deliberately, since HTTP/3 and HTTPS/DoH are the same "what's the server"
// question over a different transport. QUIC_PORT_8443 mirrors HTTPS_PORT_8443's own "commonly
// configured alternate" role.
constexpr uint16_t QUIC_PORT_443 = 443;
constexpr uint16_t QUIC_PORT_8443 = 8443;

struct QuicMatch {
    std::string summary;
    std::vector<std::string> notes;
    std::string sni;  // empty unless this was a client Initial packet this file could actually
                       // decrypt AND its ClientHello carried a server_name extension -- see this
                       // file's own header comment for exactly when that is, and isn't, possible.
};

// Returns std::nullopt if `udp_payload` and the `src_port`/`dst_port` pair don't look like QUIC at
// all. Long-header packets (Initial/0-RTT/Handshake/Retry/Version-Negotiation) are recognized by
// their own framing, checked port-independently even in Auto mode -- the same "structural
// signature overrides the port gate" treatment TLS ClientHello framing already gets for HTTPS
// (it_protocols.hpp), since the Header Form bit + Fixed Bit + a per-type structural cross-check
// (the Length field's own value against the captured byte count for Initial/0-RTT/Handshake, the
// mandatory 16-byte Integrity Tag for Retry, a whole number of 4-byte version entries for Version
// Negotiation) together are a strong, self-describing signal, not a coincidence -- byte0's Header
// Form/Fixed Bit/type bits ALONE are not (see this file's Scope section, the Handshake/0-RTT/Retry
// bullet, for the real-world collision that proved it). Short-header (1-RTT) packets are the one
// exception -- see this file's own header comment for why those stay port-gated.
// `extra_ports` extends the default port set the same way every other "IT protocols an OT
// auditor flags" file's own extra_*_ports list does -- here, extra_lateral_movement_ports, since
// QUIC joins Tier 2 alongside HTTPS rather than getting its own feature toggle.
std::optional<QuicMatch> try_recognize_quic(ByteSpan udp_payload, uint16_t src_port, uint16_t dst_port,
                                             const std::vector<uint16_t>& extra_ports);

}  // namespace conduitscope
