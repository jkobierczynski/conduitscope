// SPDX-License-Identifier: Apache-2.0
// tls_keylog.hpp - parses the SSLKEYLOGFILE format (now standardized as RFC 9850, "The
// SSLKEYLOGFILE Format for TLS") and holds the resulting ClientHello.random -> secret lookup table
// this codebase's TLS decryption engine (tls_decrypt.hpp) needs to derive real record-protection
// keys. This is the externally-supplied-lookup-table shape this codebase already has two
// precedents for (resolver.hpp's --hosts/--services, symbol_table.hpp's --s7plus-symbols) -- a
// raw wire value (here, a TLS session's own ClientHello.random) that only means something once
// matched against a secret an operator's own instrumented TLS stack (a browser/OpenSSL client with
// SSLKEYLOGFILE set, a captured device's own TLS library, Wireshark's own "Export TLS Session
// Keys") wrote down. Just like those two, this tool has no way to derive these secrets on its own
// -- it never attempts key recovery, cryptanalysis, or anything resembling "crack the session";
// see this file's own "WHY THIS IS AN ANNOTATION FEATURE, NOT A CAPABILITY REVERSAL" paragraph
// below for why this is consistent with tls_sni.hpp's own "this decoder has no decryption keys and
// never will" posture rather than a reversal of it.
//
// ONE GENUINE DIFFERENCE FROM RESOLVER/SYMBOL_TABLE: those two are built once, at CLI startup, from
// a single file, and never mutated again -- purely render-time annotation (symbol_table.hpp's own
// "never threaded into ProtocolDecoder::decode()/DecodeContext at all" design note, following
// Resolver's own precedent). This table is different: it feeds tls_decrypt.hpp's engine, which
// genuinely runs INSIDE decode() (producing different plaintext bytes for the real protocol
// decoders -- MqttDecoder/FoxDecoder/WinRmTcpDecoder -- to parse, not just annotating their
// already-decoded output). It is also populated from up to TWO sources, not one: an operator-
// supplied `--tls-keylog FILE` (this class's own parse_file), AND any pcapng Decryption Secrets
// Blocks (DSBs, IANA/Wireshark secrets_type SECRETS_TYPE_TLS = 0x544c534b, "TLS Key Log") the
// capture file itself carries, discovered incrementally while reading packets sequentially (see
// pcap_reader.hpp's own DSB support) -- a DSB's own Secrets Data is itself, byte-for-byte, more
// SSLKEYLOGFILE-format text, so both sources share this exact same line parser
// (TlsKeyLog::ingest). Because DSBs are discovered mid-read rather than all up front, this class is
// a genuinely mutable, incrementally-growing table (unlike Resolver/SymbolTable's "parse once,
// read-only forever after" shape) -- see this file's own "ORDERING" paragraph below for what that
// means in practice.
//
// WHY THIS IS AN ANNOTATION FEATURE, NOT A CAPABILITY REVERSAL: tls_sni.hpp's own file header says
// plainly "this decoder has no decryption keys and never will" -- that sentence is about this
// codebase never attempting to DERIVE or RECOVER a TLS session's keys from the wire alone (the
// thing a passive capture genuinely cannot do, and never should try to). Accepting a secret the
// OPERATOR already possesses, from their own TLS stack's own diagnostic/debug-logging feature
// (every major browser and TLS library -- OpenSSL, BoringSSL, NSS, Go's crypto/tls -- supports
// writing one when SSLKEYLOGFILE is set), is a categorically different thing: it's the same
// "render what an externally-supplied resource reveals, never what this tool derived" shape
// Resolver/SymbolTable already establish, just with the lookup result feeding decode() itself
// instead of only output rendering. Nothing here ever infers, brute-forces, or guesses a secret
// this file wasn't handed outright.
//
// ORDERING: a DSB appearing AFTER the TLS packets it would have decrypted (rare but legal pcapng --
// the spec recommends but does not require a DSB precede the packets needing it) means those
// specific earlier packets are not decrypted, even though the capture genuinely does contain their
// secret -- a single, sequential read pass is this codebase's existing architecture throughout (see
// e.g. dnp3.hpp's forward-only fragment reassembly), and a second pass solely to pre-scan for DSBs
// ahead of the packets that need them was judged not worth the added complexity for what is, in
// practice, a rare capture-tool quirk; see docs/USER_GUIDE.md's LIMITATIONS for this stated
// honestly rather than silently degrading.
//
// Sourcing: RFC 9850 ("The SSLKEYLOGFILE Format for TLS", the IETF's own standardization of the
// de facto format every major TLS stack already wrote informally for over a decade) is this file's
// sole normative reference for the on-disk/in-DSB text format itself; the pcapng DSB framing and
// the SECRETS_TYPE_TLS constant come from the pcapng specification and Wireshark's own
// wiretap/secrets-types.h (the de facto reference implementation for this still-evolving pcapng
// extension) respectively -- see pcap_reader.hpp's own DSB section for those two.
//
// WHAT THIS FILE DOES NOT DO: it does not validate that a loaded secret is actually well-formed for
// the TLS version/cipher suite it will eventually be used with (e.g. a CLIENT_RANDOM line whose
// secret isn't exactly 48 bytes) -- that is tls_decrypt.hpp's own job, at the point it actually
// tries to use one, since this file has no visibility into which cipher suite a given session will
// turn out to negotiate (ClientHello.random is learned long before ServerHello's cipher_suite
// field is). Malformed individual lines (wrong token count, non-hex, a client_random that isn't
// exactly 64 hex characters) are silently skipped, never fatal -- the same tolerant-parsing posture
// parse_hosts_file/parse_services_file/parse_symbol_table_file already establish for every other
// operator-authored reference file in this codebase.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace conduitscope {

// Thrown only for a hard, environment-level failure -- a --tls-keylog path that passed CLI11's
// ->check(CLI::ExistingFile) at parse time could not actually be opened when TlsKeyLog went to read
// it (a TOCTOU race, permissions changing mid-run, or similar). Exactly ResolverError/
// SymbolTableError's own scope and rationale, mirrored here under its own name since all three are
// unrelated types. Never thrown for a malformed line within an otherwise-openable file, and never
// thrown at all for a DSB's own in-capture secrets data (there is no "file" to fail to open there --
// a DSB with an unparseable secrets_data blob simply contributes zero usable entries, the same
// silent-skip posture every malformed line already gets).
class TlsKeyLogError : public std::runtime_error {
public:
    explicit TlsKeyLogError(const std::string& what) : std::runtime_error(what) {}
};

// One TLS 1.3 traffic secret, keyed by its own RFC 9850 label.
enum class TlsKeyLogLabel {
    ClientHandshakeTrafficSecret,
    ServerHandshakeTrafficSecret,
    ClientTrafficSecret0,
    ServerTrafficSecret0,
    // Recognized and stored for completeness (RFC 9850 names them), but never consumed by
    // tls_decrypt.hpp: EARLY_EXPORTER_SECRET/EXPORTER_SECRET are exporter secrets (RFC 8446
    // section 7.5), not record-protection traffic secrets, and CLIENT_EARLY_TRAFFIC_SECRET
    // protects 0-RTT early data, which this round's engine does not attempt to decrypt (see
    // tls_decrypt.hpp's own LEFT OPEN section) -- recording them anyway costs nothing and means a
    // future round extending into either area finds the parsing already done.
    EarlyExporterSecret,
    ExporterSecret,
    ClientEarlyTrafficSecret,
};

// The full set of secrets this codebase's engine can ever possibly use for one TLS session,
// addressed by the session's own ClientHello.random. TLS 1.2 (CLIENT_RANDOM) and TLS 1.3 (the four
// traffic-secret labels) populate disjoint subsets of this struct in practice -- which ones are
// non-empty is itself tls_decrypt.hpp's own signal for which key-derivation path a session uses
// (see that file's own "VERSION INFERENCE FROM AVAILABLE SECRETS" note), not something this class
// decides or tracks itself.
struct TlsKeyLogEntry {
    // RFC 9850's own CLIENT_RANDOM label: TLS 1.2's 48-byte master_secret. Empty (size 0) when no
    // CLIENT_RANDOM line was ever seen for this client_random.
    std::vector<uint8_t> master_secret;

    // RFC 9850's own four TLS 1.3 traffic-secret labels -- each is a raw HKDF secret, (R)Fc 8446's
    // own Hash.length bytes (32 for SHA-256-keyed suites, 48 for SHA-384), NOT yet expanded into a
    // write_key/write_iv (tls_decrypt.hpp's own HKDF-Expand-Label calls do that, once the
    // negotiated cipher suite -- and so the correct hash and output lengths -- is known from
    // ServerHello). Empty (size 0) when that particular label was never logged for this session
    // (a client-only or server-only capture angle, or a TLS stack that doesn't log every label).
    std::vector<uint8_t> client_handshake_traffic_secret;
    std::vector<uint8_t> server_handshake_traffic_secret;
    std::vector<uint8_t> client_traffic_secret_0;
    std::vector<uint8_t> server_traffic_secret_0;
};

// Owns the (possibly empty, possibly incrementally-growing -- see this file's own header comment)
// client_random -> TlsKeyLogEntry table. Cheap to query: a single hash-map probe keyed by the raw
// 32-byte ClientHello.random, no I/O after construction/ingestion.
class TlsKeyLog {
public:
    TlsKeyLog() = default;

    // Reads `path` in full and calls ingest() on its contents. path must already exist and be
    // readable (CLI11's ->check(CLI::ExistingFile) enforces existence before this is ever called
    // from cli_main.cpp) -- TlsKeyLogError is thrown only if it still can't be opened anyway (see
    // TlsKeyLogError's own comment above). Safe to call more than once (e.g. were a future CLI
    // revision to accept --tls-keylog repeatably) -- entries simply accumulate, last-line-wins per
    // (client_random, label) pair, matching parse_symbol_table_file's own override convention.
    void load_file(const std::string& path);

    // Parses `text` as RFC 9850 SSLKEYLOGFILE-format lines (one or more, newline-separated; '#'
    // comments and blank lines ignored; CRLF/CR/LF line endings all accepted per the RFC) and
    // merges every well-formed line into this table. `text` need not be a whole file's contents --
    // it is exactly what a pcapng DSB's own Secrets Data field carries for a SECRETS_TYPE_TLS
    // block (see pcap_reader.hpp), as well as what load_file passes after reading a --tls-keylog
    // file whole. A line that doesn't parse (wrong token count, a non-64-hex-character
    // client_random, odd-length or non-hex secret, an unrecognized label) is silently skipped --
    // see this file's own header comment for why that's deliberate. Returns the number of lines
    // that successfully merged, purely informational (used for an optional "N key-log entries
    // loaded"/"N more entries ingested from this capture's own embedded secrets" note -- never
    // required for correctness).
    size_t ingest(std::string_view text);

    // client_random: the exact 32-byte ClientHello.random this session's ClientHello carried (see
    // tls_sni.hpp's own extended TlsClientHello::random field). Returns nullptr when no entry has
    // ever been ingested for this exact client_random (including when this table is empty/
    // inactive) -- tls_decrypt.hpp treats that as "cannot decrypt this session," never an error.
    const TlsKeyLogEntry* find(const std::array<uint8_t, 32>& client_random) const;

    // Whether at least one entry has ever been ingested (from a file, a DSB, or both) -- exposed so
    // a caller can skip the whole TLS-decryption attempt path entirely when nothing was ever
    // supplied, the same optional-optimization role SymbolTable::active() already plays.
    bool active() const { return !entries_.empty(); }

    // Total number of distinct client_random entries currently held -- purely informational
    // (a decode/inventory run can report "loaded N TLS key-log entries" up front the same way it
    // already reports Resolver's own loaded-table sizes).
    size_t entry_count() const { return entries_.size(); }

private:
    // Keyed by the raw 32 client_random bytes, not a hex string -- this table is looked up once per
    // TLS session (at most a few thousand even on a busy capture), so there's no throughput reason
    // to avoid std::array's own hashing; see tls_keylog.cpp for the hasher.
    struct ClientRandomHash {
        size_t operator()(const std::array<uint8_t, 32>& r) const noexcept;
    };
    std::unordered_map<std::array<uint8_t, 32>, TlsKeyLogEntry, ClientRandomHash> entries_;
};

}  // namespace conduitscope
