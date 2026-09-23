// SPDX-License-Identifier: Apache-2.0
// tls_sni.hpp - a deliberately minimal TLS ClientHello parser, existing for exactly one purpose:
// detecting likely DNS-over-HTTPS (DoH, RFC 8484) traffic by its Server Name Indication (SNI).
//
// DoH carries an ordinary DNS message (RFC 1035, see dns.hpp) inside an HTTPS POST/GET, which
// means it is TLS-encrypted end to end -- this decoder (like the rest of this codebase, see
// resolver.hpp's own "never live DNS" posture) has no decryption keys and never will, so the
// actual query name/answer inside a DoH exchange is fundamentally not visible to a passive
// capture. What IS visible, before TLS 1.3 encryption begins, is the ClientHello -- specifically
// its Server Name Indication extension (RFC 6066), which names the server the client is
// connecting to in plaintext, even under TLS 1.3. This is therefore DETECTION, not decoding: this
// decoder identifies a TCP/443 flow as "likely DoH" when its ClientHello's SNI matches a curated
// table of known public DoH resolver hostnames (kKnownDohProviders in tls_sni.cpp) -- see
// doh_provider_for_hostname's own doc comment for exactly what "matches" means. A flow that is
// ordinary HTTPS to literally anything else (including a PRIVATE/enterprise DoH resolver this
// table doesn't know about) is not flagged -- there is no way to distinguish "HTTPS to some
// server" from "DoH to some server" without either a well-known hostname or the actual decrypted
// HTTP request, and this decoder never has the latter.
//
// Sourcing: cross-checked against RFC 8446 section 4 (TLS 1.3 Handshake Protocol -- the
// ClientHello message shape, unchanged in this respect from TLS 1.2) and RFC 6066 section 3 (the
// server_name extension's own wire format).
//
// ---------------------------------------------------------------------------------------------
// Wire format this decoder reads (every multi-byte field big-endian, as throughout TLS):
//   TLS record header (5 bytes): ContentType(1) [0x16 = Handshake -- the only value this decoder
//     recognizes] + legacy_record_version(2) + length(2).
//   Handshake header (4 bytes): HandshakeType(1) [0x01 = ClientHello -- the only value this
//     decoder recognizes] + length(3, 24-bit).
//   ClientHello body: legacy_version(2) + random(32) + legacy_session_id (1-byte length + bytes)
//     + cipher_suites (2-byte length + bytes) + legacy_compression_methods (1-byte length +
//     bytes) + extensions (2-byte length + a sequence of type(2)+length(2)+data(length) records,
//     present only if bytes remain -- RFC 8446 4.1.2 makes the extensions block itself optional
//     in the grammar, though in practice every modern TLS client sends at least SNI/ALPN/
//     supported_versions).
//   server_name extension (RFC 6066 3, type 0x0000): ServerNameList (2-byte length) of
//     ServerName entries, each NameType(1) [0 = host_name, the only type ever defined] +
//     HostName (2-byte length + ASCII bytes, no trailing dot). This decoder reads only the FIRST
//     entry -- RFC 6066 3 itself says the list "MUST NOT contain more than one name of the same
//     name_type", so a second host_name entry would itself be a protocol violation.
//   application_layer_protocol_negotiation extension (RFC 7301, type 0x0010): a length-prefixed
//     list of length-prefixed protocol-name strings (e.g. "h2", "http/1.1") -- read in full and
//     surfaced (not itself part of DoH detection, just useful corroborating context: DoH over
//     HTTP/2 is the common case, so ALPN offering "h2" is a mild positive signal).
//
// Explicitly out of scope, deliberately: every other TLS content type (ChangeCipherSpec,
// Alert, ApplicationData -- all opaque/encrypted from this decoder's point of view regardless);
// every other handshake message type (ServerHello, Certificate, ...); TLS 1.3's Encrypted
// Client Hello (ECH, still a draft as of this writing) -- when present, the REAL SNI is itself
// encrypted inside an extension, and only a decoy "public name" is visible in cleartext, which
// this decoder has no way to distinguish from a genuine SNI (both simply look like the
// server_name extension) -- see try_parse_tls_client_hello's own doc comment; a ClientHello
// split across more than one TCP segment (this decoder only ever looks at a single segment's
// payload -- see the "Detection" paragraph in doh.hpp-equivalent wiring in decoder.cpp -- most
// real ClientHellos, even TLS 1.3's larger ones, still fit in one segment on an Ethernet-MTU
// capture, but a very extension-heavy one, or one riding a jumbo-frame-unaware fragmenting path,
// will simply not be detected rather than mis-parsed); QUIC's own, entirely different Initial-
// packet-wrapped ClientHello (DNS-over-QUIC, RFC 9250 -- UDP, not this file's problem at all).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// The conventional HTTPS/DoH TCP port -- recorded as an "expected port" annotation only, and (see
// decoder.cpp) also this decoder's actual detection gate, since attempting a TLS ClientHello
// parse against arbitrary TCP traffic on every port would be needless work for a feature that,
// by definition, only ever matches HTTPS.
constexpr uint16_t DOH_PORT = 443;

struct TlsClientHelloInfo {
    std::string sni;  // empty when no server_name extension was present (or it was empty/malformed)
    std::vector<std::string> alpn_protocols;  // empty when no ALPN extension was present
};

// The inner half of try_parse_tls_client_hello below, split out so quic.cpp can reuse it directly:
// `handshake_msg` starts at the Handshake header itself (HandshakeType(1) + length(3) + body), NOT
// a full TLS record -- exactly the shape a QUIC CRYPTO frame's payload has (QUIC carries TLS
// Handshake messages directly, with no 5-byte record-layer wrapper at all, since record framing is
// a TCP-era artifact QUIC's own frame layer already supersedes -- RFC 9001 section 4). Returns
// std::nullopt (never throws) when HandshakeType != ClientHello or the body is truncated within
// `handshake_msg`.
std::optional<TlsClientHelloInfo> try_parse_tls_handshake_client_hello(ByteSpan handshake_msg);

// Attempts to interpret `tcp_payload` (a single TCP segment -- see tls_sni.hpp's file header
// comment for why reassembly isn't attempted) as one TLS ClientHello. Returns std::nullopt (never
// throws) when the record header doesn't match (ContentType != Handshake), or delegates the rest
// to try_parse_tls_handshake_client_hello above. A successful parse does NOT by itself mean "this
// is DoH" -- see try_detect_doh below, which is what decoder.cpp actually calls.
std::optional<TlsClientHelloInfo> try_parse_tls_client_hello(ByteSpan tcp_payload);

// One "likely DoH" detection -- see tls_sni.hpp's file header comment for exactly what this does
// and doesn't establish.
struct DohDetection {
    std::string sni;
    std::vector<std::string> alpn_protocols;
    std::string matched_provider;  // the curated table entry's own label, e.g. "Cloudflare DNS"
    std::string summary;
};

// Calls try_parse_tls_client_hello, and returns a DohDetection only when it succeeded AND the
// resulting SNI matches a known public DoH resolver hostname (doh_provider_for_hostname in
// tls_sni.cpp) -- see tls_sni.hpp's file header comment for exactly what "matches" means and why
// a private/enterprise DoH resolver this table doesn't know about is never flagged.
std::optional<DohDetection> try_detect_doh(ByteSpan tcp_payload);

// Registration-model wrapper around try_detect_doh above -- GateKind::TcpPort's first and so far
// only user (see protocol_decoder.hpp's own comment on that gate kind for why DoH needed a new
// one: it's port-gated in Auto mode, like UdpPort's own protocols, but rides TCP). decode() is
// handed a single TCP segment's payload, never reassembled -- see this file's own header comment
// for why that's a deliberate scope limit, not an oversight. A zero-flat-field migrated protocol
// from the start (like TwinCAT/FF-HSE/DeviceNet): DecodedPacket::result carries the whole
// DohDetection, and output.cpp's write_doh_json_fields reads straight from it.
class DohDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "doh"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return DOH_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& doh_decoder();

}  // namespace conduitscope
