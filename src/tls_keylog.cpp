// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/tls_keylog.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

// docs/reviews/2026-10-chatgpt-security-review-patch315.md finding F1: see
// tls_keylog_entries_refused()'s own comment (resource_limits.hpp) for why THIS constructor,
// rather than Decoder's, is the right reset point.
TlsKeyLog::TlsKeyLog() { reset_tls_keylog_entries_refused(); }

// Rough, deliberately approximate per-entry accounting overhead folded into
// max_tls_keylog_bytes' own budget, per the review's own "+ hash-table/container overhead
// allowance" suggestion -- std::unordered_map's own node/bucket overhead plus
// TlsKeyLogEntry's five std::vector<uint8_t> headers are comfortably under this on every
// mainstream STL implementation; this is a conservative accounting constant, not a measured
// figure, exactly like this file's own tolerant-parsing posture elsewhere (good enough to bound
// accumulation, not a promise of exact memory usage).
constexpr size_t kTlsKeyLogEntryOverheadBytes = 256;

size_t TlsKeyLog::ClientRandomHash::operator()(const std::array<uint8_t, 32>& r) const noexcept {
    // FNV-1a over the 32 raw bytes -- this is a hash-table bucketing function, not a cryptographic
    // primitive (nothing security-relevant depends on its distribution quality beyond "spreads
    // real client_random values across buckets reasonably"), so it stays local to this file rather
    // than reaching for sha256.hpp (which would also be the wrong tool: a non-cryptographic,
    // fast-to-compute hash is exactly what an unordered_map bucket function should be).
    size_t h = 1469598103934665603ULL;
    for (uint8_t b : r) {
        h ^= b;
        h *= 1099511628211ULL;
    }
    return h;
}

bool TlsKeyLog::tls_keylog_limit_admits(const std::array<uint8_t, 32>& client_random,
                                         size_t bytes_to_store) {
    const bool is_new_entry = entries_.find(client_random) == entries_.end();
    if (is_new_entry &&
        entries_.size() >= resource_limits().max_tls_keylog_entries.value_or(kDefaultMaxTlsKeyLogEntries)) {
        note_tls_keylog_entry_refused();
        return false;
    }
    const size_t overhead = is_new_entry ? kTlsKeyLogEntryOverheadBytes : 0;
    const size_t prospective_bytes = total_secret_bytes_ + bytes_to_store + overhead;
    if (prospective_bytes > resource_limits().max_tls_keylog_bytes.value_or(kDefaultMaxTlsKeyLogBytes)) {
        note_tls_keylog_entry_refused();
        return false;
    }
    total_secret_bytes_ = prospective_bytes;
    return true;
}

namespace {

// Matches symbol_table.cpp's own strip_comment/trim exactly -- this file's line shape ('#'
// comments, blank lines, whitespace-delimited tokens) is the same small shape, so the same
// deliberately-local helpers apply; see that file's own comment for why this doesn't reach for
// yaml_mini.hpp's shared trim/split machinery.
std::string strip_comment(const std::string& line) {
    size_t hash = line.find('#');
    return hash == std::string::npos ? line : line.substr(0, hash);
}

std::string trim(const std::string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

int hex_nibble(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    return -1;
}

// Decodes an even-length, all-hex-digit string into raw bytes. Returns nullopt for anything else
// (odd length, a non-hex character) -- RFC 9850 section 3's own grammar for every hex field in this
// format ("Hexadecimal strings MAY use uppercase or lowercase letters"), with no partial/best-effort
// decode on a malformed token -- the whole line is skipped one level up instead (see ingest()).
std::optional<std::vector<uint8_t>> hex_decode(const std::string& s) {
    if (s.empty() || s.size() % 2 != 0) return std::nullopt;
    std::vector<uint8_t> out;
    out.reserve(s.size() / 2);
    for (size_t i = 0; i < s.size(); i += 2) {
        int hi = hex_nibble(s[i]);
        int lo = hex_nibble(s[i + 1]);
        if (hi < 0 || lo < 0) return std::nullopt;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
    }
    return out;
}

// RFC 9850 section 2's own label table -- see tls_keylog.hpp's TlsKeyLogLabel for which of these
// this codebase's engine actually consumes vs. merely records.
std::optional<TlsKeyLogLabel> parse_label(const std::string& tok) {
    if (tok == "CLIENT_HANDSHAKE_TRAFFIC_SECRET") return TlsKeyLogLabel::ClientHandshakeTrafficSecret;
    if (tok == "SERVER_HANDSHAKE_TRAFFIC_SECRET") return TlsKeyLogLabel::ServerHandshakeTrafficSecret;
    if (tok == "CLIENT_TRAFFIC_SECRET_0") return TlsKeyLogLabel::ClientTrafficSecret0;
    if (tok == "SERVER_TRAFFIC_SECRET_0") return TlsKeyLogLabel::ServerTrafficSecret0;
    if (tok == "EARLY_EXPORTER_SECRET") return TlsKeyLogLabel::EarlyExporterSecret;
    if (tok == "EXPORTER_SECRET") return TlsKeyLogLabel::ExporterSecret;
    if (tok == "CLIENT_EARLY_TRAFFIC_SECRET") return TlsKeyLogLabel::ClientEarlyTrafficSecret;
    // CLIENT_RANDOM (TLS <= 1.2) and the two ECH_* labels (RFC 9850 section 2.1 -- an Encrypted
    // Client Hello's own separate secret/config, keyed by the OUTER ClientHello's random) are
    // handled by their own literal-string checks at the one call site (ingest()) rather than
    // through this label enum: CLIENT_RANDOM has a dedicated TlsKeyLogEntry field, not an enum
    // case, because its secret is a master_secret, not a traffic secret HKDF-Expand-Label would
    // ever be called on -- a structurally different field, not just a different label name. The
    // ECH_* labels are recognized here (so a line naming them doesn't fall through as
    // "unrecognized label" and get silently skipped for no reason) but have nowhere to be stored
    // -- ECH is out of scope for this round's engine entirely (see tls_decrypt.hpp's own LEFT OPEN
    // section) -- so they are simply not stored, the same "recognized but nothing to do with it
    // yet" posture TlsKeyLogLabel's own EarlyExporterSecret/ExporterSecret/ClientEarlyTrafficSecret
    // cases already have for the traffic-secret side.
    return std::nullopt;
}

}  // namespace

void TlsKeyLog::load_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw TlsKeyLogError("could not open --tls-keylog file: " + path);
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    ingest(buf.str());
}

size_t TlsKeyLog::ingest(std::string_view text) {
    size_t merged = 0;
    std::string remaining(text);
    std::string raw_line;
    // getline on '\n' already handles LF and CRLF (the trailing '\r' is stripped by trim() below);
    // a lone-CR line-ending file (RFC 9850 also allows bare CR) is the one shape getline('\n') alone
    // wouldn't split -- rewrite any bare CR to LF first so every one of the three endings RFC 9850
    // section 2 permits is handled uniformly.
    std::string normalized;
    normalized.reserve(remaining.size());
    for (size_t i = 0; i < remaining.size(); ++i) {
        char c = remaining[i];
        if (c == '\r' && (i + 1 >= remaining.size() || remaining[i + 1] != '\n')) {
            normalized.push_back('\n');
        } else {
            normalized.push_back(c);
        }
    }
    std::istringstream norm_stream(normalized);
    while (std::getline(norm_stream, raw_line)) {
        std::string line = trim(strip_comment(raw_line));
        if (line.empty()) continue;

        std::istringstream tokens(line);
        std::string label_tok, client_random_hex, secret_hex;
        if (!(tokens >> label_tok >> client_random_hex >> secret_hex)) continue;
        // RFC 9850 section 2: "the Label, the Client Random, and the Secret... separated by a
        // single space character" -- exactly three fields, nothing after the third. A line with a
        // trailing fourth token is malformed per that grammar, not a forward-compatible extension
        // this parser should silently tolerate; skip it like any other malformed line.
        std::string extra;
        if (tokens >> extra) continue;

        if (client_random_hex.size() != 64) continue;  // 32 bytes, hex-encoded, per RFC 9850.
        auto client_random_bytes = hex_decode(client_random_hex);
        if (!client_random_bytes || client_random_bytes->size() != 32) continue;
        std::array<uint8_t, 32> client_random{};
        std::copy(client_random_bytes->begin(), client_random_bytes->end(), client_random.begin());

        auto secret_bytes = hex_decode(secret_hex);
        if (!secret_bytes || secret_bytes->empty()) continue;

        if (label_tok == "CLIENT_RANDOM") {
            // RFC 9850 section 2: "the... master secret... 48 bytes". A different length here is
            // either a non-conforming writer or line corruption either way -- not trusted.
            if (secret_bytes->size() != 48) continue;
            // patch315 security review finding F1: enforced AFTER every malformed-line check above
            // (a line this parser would skip anyway costs nothing to reject the ordinary way) but
            // BEFORE entries_[client_random] -- which, being operator[], would create a default
            // entry even for a line this function is about to refuse -- see this file's own
            // tls_keylog_limit_admits() for the shared check both this branch and the
            // traffic-secret branch below use.
            if (!tls_keylog_limit_admits(client_random, secret_bytes->size())) continue;
            entries_[client_random].master_secret = std::move(*secret_bytes);
            ++merged;
            continue;
        }

        auto label = parse_label(label_tok);
        if (!label) continue;  // Unrecognized label, or a recognized-but-unstored one (ECH_*).

        // A recognized-but-unstored label (ECH_*/exporter secrets -- see parse_label's own
        // comment) still costs zero bytes of actual secret material, but would otherwise still
        // create an empty entries_[client_random] slot below -- accounted for as a zero-byte,
        // new-entry-only admission so it still counts against max_tls_keylog_entries (a real map
        // slot is still consumed) without inflating max_tls_keylog_bytes for data never stored.
        const bool label_is_stored = *label == TlsKeyLogLabel::ClientHandshakeTrafficSecret ||
                                      *label == TlsKeyLogLabel::ServerHandshakeTrafficSecret ||
                                      *label == TlsKeyLogLabel::ClientTrafficSecret0 ||
                                      *label == TlsKeyLogLabel::ServerTrafficSecret0;
        if (!tls_keylog_limit_admits(client_random, label_is_stored ? secret_bytes->size() : 0)) continue;

        TlsKeyLogEntry& entry = entries_[client_random];
        switch (*label) {
            case TlsKeyLogLabel::ClientHandshakeTrafficSecret:
                entry.client_handshake_traffic_secret = std::move(*secret_bytes);
                break;
            case TlsKeyLogLabel::ServerHandshakeTrafficSecret:
                entry.server_handshake_traffic_secret = std::move(*secret_bytes);
                break;
            case TlsKeyLogLabel::ClientTrafficSecret0:
                entry.client_traffic_secret_0 = std::move(*secret_bytes);
                break;
            case TlsKeyLogLabel::ServerTrafficSecret0:
                entry.server_traffic_secret_0 = std::move(*secret_bytes);
                break;
            case TlsKeyLogLabel::EarlyExporterSecret:
            case TlsKeyLogLabel::ExporterSecret:
            case TlsKeyLogLabel::ClientEarlyTrafficSecret:
                // Recognized, parsed correctly, deliberately not stored -- see parse_label's own
                // comment. Still counted as "merged" below: ingest()'s return value means "lines
                // this parser successfully understood," not "lines that produced a usable
                // decryption key."
                break;
        }
        ++merged;
    }
    return merged;
}

const TlsKeyLogEntry* TlsKeyLog::find(const std::array<uint8_t, 32>& client_random) const {
    auto it = entries_.find(client_random);
    return it == entries_.end() ? nullptr : &it->second;
}

}  // namespace conduitscope
