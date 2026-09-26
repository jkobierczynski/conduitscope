// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/tls_sni.hpp"

#include <algorithm>
#include <cctype>

namespace conduitscope {

namespace {

bool ends_with(const std::string& s, const std::string& suffix) {
    if (s.size() < suffix.size()) return false;
    return s.compare(s.size() - suffix.size(), suffix.size(), suffix) == 0;
}

std::string lowercase(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(),
                   [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); });
    return s;
}

// Curated table of known public DoH resolver hostnames -- see tls_sni.hpp's file header comment
// for exactly why this is a curated table rather than a heuristic, and why an enterprise/private
// DoH resolver not on this list is never flagged. Each entry is either an exact hostname or a
// "*.suffix" pattern matching that suffix or the bare domain itself (e.g. "*.cloudflare-dns.com"
// matches both "cloudflare-dns.com" and "family.cloudflare-dns.com") -- most providers issue
// per-configuration or per-feature subdomains (family filtering, malware blocking, a per-account
// NextDNS config ID, ...) under one base domain, so a bare exact-match table would miss most real
// traffic to these providers. Sourced from each provider's own published DoH endpoint
// documentation as of this writing.
struct DohProvider {
    const char* pattern;
    const char* label;
};
constexpr DohProvider kKnownDohProviders[] = {
    {"*.cloudflare-dns.com", "Cloudflare DNS"},
    {"one.one.one.one", "Cloudflare DNS"},
    {"*.dns.google", "Google Public DNS"},
    {"dns.google.com", "Google Public DNS"},
    {"*.quad9.net", "Quad9"},
    {"*.opendns.com", "OpenDNS"},
    {"*.adguard-dns.com", "AdGuard DNS"},
    {"*.adguard.com", "AdGuard DNS"},
    {"*.nextdns.io", "NextDNS"},
    {"*.dns.sb", "DNS.SB"},
    {"*.cleanbrowsing.org", "CleanBrowsing"},
    {"*.controld.com", "ControlD"},
    {"*.pi-dns.com", "Pi-DNS"},
    {"*.mullvad.net", "Mullvad DNS"},
    {"*.digitale-gesellschaft.ch", "Digitale Gesellschaft"},
};

std::optional<std::string> doh_provider_for_hostname(const std::string& hostname) {
    std::string h = lowercase(hostname);
    while (!h.empty() && h.back() == '.') h.pop_back();  // a trailing dot is legal, meaningless here
    for (const auto& p : kKnownDohProviders) {
        std::string pattern = p.pattern;
        if (pattern.size() > 2 && pattern[0] == '*' && pattern[1] == '.') {
            std::string suffix = pattern.substr(1);  // ".cloudflare-dns.com"
            std::string bare = pattern.substr(2);    // "cloudflare-dns.com"
            if (h == bare || ends_with(h, suffix)) return std::string(p.label);
        } else if (h == pattern) {
            return std::string(p.label);
        }
    }
    return std::nullopt;
}

}  // namespace

std::optional<TlsClientHelloInfo> try_parse_tls_handshake_client_hello(ByteSpan handshake_msg) {
    if (handshake_msg.size() < 4) return std::nullopt;
    try {
        size_t pos = 0;
        if (handshake_msg.at(pos) != 0x01) return std::nullopt;  // HandshakeType: ClientHello
        uint32_t hs_length = (static_cast<uint32_t>(handshake_msg.at(pos + 1)) << 16) |
                              (static_cast<uint32_t>(handshake_msg.at(pos + 2)) << 8) | handshake_msg.at(pos + 3);
        pos += 4;
        size_t hs_end = pos + hs_length;
        if (hs_end > handshake_msg.size()) return std::nullopt;

        if (pos + 2 + 32 > hs_end) return std::nullopt;
        pos += 2 + 32;  // legacy_version + random

        if (pos >= hs_end) return std::nullopt;
        uint8_t session_id_len = handshake_msg.at(pos);
        pos += 1 + session_id_len;
        if (pos > hs_end) return std::nullopt;

        if (pos + 2 > hs_end) return std::nullopt;
        uint16_t cipher_suites_len =
            static_cast<uint16_t>((handshake_msg.at(pos) << 8) | handshake_msg.at(pos + 1));
        pos += 2 + cipher_suites_len;
        if (pos > hs_end) return std::nullopt;

        if (pos + 1 > hs_end) return std::nullopt;
        uint8_t compression_len = handshake_msg.at(pos);
        pos += 1 + compression_len;
        if (pos > hs_end) return std::nullopt;

        TlsClientHelloInfo info;
        if (pos + 2 <= hs_end) {  // extensions block is optional (RFC 8446 4.1.2)
            uint16_t extensions_len =
                static_cast<uint16_t>((handshake_msg.at(pos) << 8) | handshake_msg.at(pos + 1));
            pos += 2;
            size_t ext_end = pos + extensions_len;
            if (ext_end > hs_end) return std::nullopt;
            while (pos + 4 <= ext_end) {
                uint16_t ext_type = static_cast<uint16_t>((handshake_msg.at(pos) << 8) | handshake_msg.at(pos + 1));
                uint16_t ext_len =
                    static_cast<uint16_t>((handshake_msg.at(pos + 2) << 8) | handshake_msg.at(pos + 3));
                pos += 4;
                if (pos + ext_len > ext_end) return std::nullopt;
                if (ext_type == 0x0000 && ext_len >= 2) {  // server_name (RFC 6066 3)
                    uint16_t list_len =
                        static_cast<uint16_t>((handshake_msg.at(pos) << 8) | handshake_msg.at(pos + 1));
                    size_t p = pos + 2;
                    size_t list_end = std::min<size_t>(pos + 2 + list_len, pos + ext_len);
                    if (p + 3 <= list_end) {
                        uint8_t name_type = handshake_msg.at(p);
                        uint16_t name_len =
                            static_cast<uint16_t>((handshake_msg.at(p + 1) << 8) | handshake_msg.at(p + 2));
                        p += 3;
                        if (name_type == 0 && p + name_len <= list_end) {
                            info.sni =
                                std::string(reinterpret_cast<const char*>(handshake_msg.data() + p), name_len);
                        }
                    }
                } else if (ext_type == 0x0010 && ext_len >= 2) {  // ALPN (RFC 7301)
                    uint16_t list_len =
                        static_cast<uint16_t>((handshake_msg.at(pos) << 8) | handshake_msg.at(pos + 1));
                    size_t p = pos + 2;
                    size_t list_end = std::min<size_t>(pos + 2 + list_len, pos + ext_len);
                    while (p < list_end) {
                        uint8_t proto_len = handshake_msg.at(p);
                        p += 1;
                        if (p + proto_len > list_end) break;
                        info.alpn_protocols.emplace_back(reinterpret_cast<const char*>(handshake_msg.data() + p),
                                                          proto_len);
                        p += proto_len;
                    }
                }
                pos += ext_len;
            }
        }
        return info;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<TlsClientHelloInfo> try_parse_tls_client_hello(ByteSpan payload) {
    if (payload.size() < 9) return std::nullopt;
    try {
        if (payload.at(0) != 0x16) return std::nullopt;  // ContentType: Handshake
        if (payload.at(1) != 0x03) return std::nullopt;  // legacy_record_version major, always 0x03
        uint16_t record_length = static_cast<uint16_t>((payload.at(3) << 8) | payload.at(4));
        if (5 + static_cast<size_t>(record_length) > payload.size()) return std::nullopt;
        return try_parse_tls_handshake_client_hello(payload.from(5));
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<DohDetection> try_detect_doh(ByteSpan tcp_payload) {
    auto hello = try_parse_tls_client_hello(tcp_payload);
    if (!hello || hello->sni.empty()) return std::nullopt;
    auto provider = doh_provider_for_hostname(hello->sni);
    if (!provider) return std::nullopt;

    DohDetection d;
    d.sni = hello->sni;
    d.alpn_protocols = hello->alpn_protocols;
    d.matched_provider = *provider;
    std::string s = "likely DNS-over-HTTPS: TLS ClientHello SNI '" + d.sni + "' matches known DoH resolver (" +
                     d.matched_provider + ")";
    if (!d.alpn_protocols.empty()) {
        s += ", ALPN=[";
        for (size_t i = 0; i < d.alpn_protocols.size(); ++i) {
            if (i != 0) s += ",";
            s += d.alpn_protocols[i];
        }
        s += "]";
    }
    s += " -- query/answer content is TLS-encrypted and not visible to this decoder";
    d.summary = s;
    return d;
}

std::optional<ProtocolResult> DohDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto d = try_detect_doh(payload)) {
        return ProtocolResult::make<DohDetection>("doh", std::move(*d));
    }
    return std::nullopt;
}

const ProtocolDecoder& doh_decoder() {
    static const DohDecoder instance;
    return instance;
}

}  // namespace conduitscope
