// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/resolver.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/oui_table.gen.hpp"

namespace conduitscope {

namespace {

// --------------------------------------------------------------------------------------------
// Small string helpers -- deliberately local/minimal rather than reaching for yaml_mini.hpp's own
// trim/split (those are tied to that file's YAML-subset error reporting, not a fit here); this
// hosts/services parsing is a much simpler line shape and doesn't need any of that machinery.
// --------------------------------------------------------------------------------------------

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

std::vector<std::string> split_ws(const std::string& s) {
    std::vector<std::string> out;
    std::istringstream iss(s);
    std::string tok;
    while (iss >> tok) out.push_back(tok);
    return out;
}

std::string to_lower(std::string s) {
    std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
    return s;
}

// --------------------------------------------------------------------------------------------
// OUI (MAC vendor) lookup -- see oui_table.gen.hpp's own file header for the three tables
// (kOuiTable24/28/36) this searches, and resolver.hpp's file header for why MA-S, then MA-M, then
// MA-L, in that order.
// --------------------------------------------------------------------------------------------

// Parses format_mac's own output ("aa:bb:cc:dd:ee:ff", lowercase, colon-separated, exactly six
// two-digit hex octets) into a right-justified 48-bit value. Returns nullopt for anything that
// doesn't match that exact shape -- this is only ever fed strings this codebase itself produced
// (DecodedPacket::src_mac/dst_mac), so the parse is intentionally strict rather than a general
// "accept any reasonable MAC spelling" parser; being lenient here would just mask a bug elsewhere.
std::optional<uint64_t> parse_format_mac(const std::string& mac) {
    if (mac.size() != 17) return std::nullopt;
    uint64_t value = 0;
    for (size_t i = 0; i < 6; ++i) {
        size_t pos = i * 3;
        if (i != 0 && mac[pos - 1] != ':') return std::nullopt;
        char hi = mac[pos], lo = mac[pos + 1];
        auto hex_digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = hex_digit(hi), l = hex_digit(lo);
        if (h < 0 || l < 0) return std::nullopt;
        value = (value << 8) | (static_cast<uint64_t>(h) << 4) | static_cast<uint64_t>(l);
    }
    return value;
}

// Binary search over one of kOuiTable24/28/36 (each sorted ascending by `prefix`, per
// oui_table.gen.hpp's own guarantee) for an exact match against `prefix`.
template <size_t N>
std::optional<std::string> table_lookup(const detail::OuiEntry (&table)[N], uint64_t prefix) {
    size_t lo = 0, hi = N;
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (table[mid].prefix < prefix) {
            lo = mid + 1;
        } else if (table[mid].prefix > prefix) {
            hi = mid;
        } else {
            return std::string(table[mid].vendor);
        }
    }
    return std::nullopt;
}

// Tries MA-S (36-bit, most specific) first, then MA-M (28-bit), then MA-L (24-bit, the classic
// OUI) -- correct because MA-M/MA-S blocks are IEEE sub-delegations carved out of specific MA-L
// blocks reserved for exactly that purpose, so a given MAC's top bits can legitimately match an
// entry in more than one table at once; the most specific match is always the right answer, the
// same way a longer-prefix-wins rule works for IP routing.
std::optional<std::string> oui_vendor_lookup(uint64_t mac48) {
    if (auto v = table_lookup(detail::kOuiTable36, mac48 >> 12)) return v;
    if (auto v = table_lookup(detail::kOuiTable28, mac48 >> 20)) return v;
    if (auto v = table_lookup(detail::kOuiTable24, mac48 >> 24)) return v;
    return std::nullopt;
}

// --------------------------------------------------------------------------------------------
// Built-in port -> service-name table.
//
// Deliberately small and hand-curated, NOT an IANA/nmap-services dump the way oui_table.gen.hpp
// is a full IEEE registry dump -- there is no single canonical "the" port/service mapping the way
// there is for OUIs (many ports are reused for unrelated purposes across different
// organizations/eras), so pretending to be exhaustive here would just be a confident-looking
// source of wrong answers. This table covers exactly two things: (a) every OT/ICS protocol port
// this project's own decoders already default to (cross-checked against each protocol's own
// MODBUS_TCP_PORT/DNP3_TCP_PORT/etc. constant, or the shared TCP port 102 -- see cotp.hpp's
// COTP_TCP_PORT -- for S7comm/S7comm-Plus/MMS, which don't each have their own named port
// constant since all three share COTP_TCP_PORT), and (b) a modest set of common general IT/OT-
// adjacent ports, purely for surrounding context when auditing a capture that also carries
// ordinary infrastructure traffic (DNS, NTP, RDP, ...) alongside the OT protocols this tool
// actually decodes. `--services FILE` (Unix /etc/services style) is the documented way to extend
// or override this table -- see parse_services_file below and resolver.hpp's own file header.
// --------------------------------------------------------------------------------------------

struct BuiltinService {
    uint16_t port;
    const char* proto;  // "tcp" or "udp"
    const char* name;
};

constexpr BuiltinService kBuiltinServices[] = {
    // OT/ICS protocol ports this project's own decoders default to.
    {102, "tcp", "s7comm"},       // COTP_TCP_PORT (cotp.hpp) -- shared by s7comm/s7comm-plus/mms;
                                    // "iso-tsap" is the IANA-registered name, "s7comm" is more
                                    // useful for this project's own audience -- see also 102/mms
                                    // below (both names appear against the same port on purpose)
    {102, "tcp", "mms"},           // COTP_TCP_PORT, MMS's own application protocol over the same
                                    // transport as s7comm -- see mms.hpp
    {502, "tcp", "modbus"},        // MODBUS_TCP_PORT, modbus.hpp
    {1883, "tcp", "mqtt"},         // MQTT_PORT, mqtt.hpp
    {1089, "udp", "ff-annunc"},    // FFHSE_PORT_ANNUNC, ffhse.hpp
    {1090, "udp", "ff-fms"},       // FFHSE_PORT_FMS, ffhse.hpp
    {1091, "udp", "ff-sm"},        // FFHSE_PORT_SM, ffhse.hpp
    {2222, "udp", "enip-io"},      // ENIP_IO_UDP_PORT, enip.hpp
    {2404, "tcp", "iec104"},       // IEC104_TCP_PORT, iec104.hpp
    {3622, "udp", "ff-lr-port"},   // FFHSE_PORT_LAN, ffhse.hpp
    {4840, "tcp", "opcua"},        // OPCUA_PORT, opcua.hpp
    {5094, "tcp", "hart-ip"},      // HARTIP_PORT, hartip.hpp -- same port both transports
    {5094, "udp", "hart-ip"},      // HARTIP_PORT, hartip.hpp
    {20000, "tcp", "dnp3"},        // DNP3_TCP_PORT, dnp3.hpp
    {44818, "tcp", "enip"},        // ENIP_TCP_PORT, enip.hpp
    {47808, "udp", "bacnet"},      // BACNET_UDP_PORT, bacnet.hpp

    // General IT/OT-adjacent context ports -- common enough on a mixed capture to be worth naming,
    // not an attempt at IANA coverage (see this table's own file-header note above).
    {21, "tcp", "ftp"},
    {22, "tcp", "ssh"},
    {23, "tcp", "telnet"},
    {53, "tcp", "dns"},
    {53, "udp", "dns"},
    {67, "udp", "dhcp"},
    {68, "udp", "dhcp"},
    {69, "udp", "tftp"},
    {80, "tcp", "http"},
    {123, "udp", "ntp"},
    {161, "udp", "snmp"},
    {162, "udp", "snmp-trap"},
    {389, "tcp", "ldap"},
    {443, "tcp", "https"},
    {445, "tcp", "microsoft-ds"},
    {514, "udp", "syslog"},
    {3389, "tcp", "rdp"},
};

uint32_t service_key(uint16_t port, const std::string& proto) {
    return (static_cast<uint32_t>(port) << 1) | (proto == "udp" ? 1u : 0u);
}

// Parses a Unix /etc/hosts-style file into `out` (ip string, canonical via format_ipv4, -> first
// name found for it). Format per line: "IP name [alias...]", '#' starts a comment (whole-line or
// trailing), blank lines skipped, fields whitespace-delimited. Only the FIRST name after the IP is
// kept (aliases ignored), matching /etc/hosts' own convention that the first hostname is the
// canonical one. A line whose address doesn't parse as a strict IPv4 dotted-quad (see
// ipv4.hpp's parse_ipv4_string -- this project is IPv4-only throughout, same as policy.hpp's own
// CIDR parsing) is silently skipped, not an error -- consistent with this codebase's tolerant-
// parsing convention for a config file whose worst-case failure mode is "this one line's mapping
// is simply unavailable", not "the capture can't be decoded". FIRST occurrence of a given IP wins
// when the file has duplicates -- chosen to match a real resolver's own /etc/hosts behavior (the
// first matching line is authoritative), unlike the --services file below, where later lines win
// (see parse_services_file) since that file's whole purpose is deliberately overriding earlier
// entries, including the built-in table.
//
// Throws ResolverError if the file can't be opened at all (see ResolverError's own comment).
void parse_hosts_file(const std::string& path, std::unordered_map<std::string, std::string>& out) {
    std::ifstream in(path);
    if (!in) throw ResolverError("cannot open hosts file '" + path + "'");
    std::string line;
    while (std::getline(in, line)) {
        std::string content = trim(strip_comment(line));
        if (content.empty()) continue;
        std::vector<std::string> tokens = split_ws(content);
        if (tokens.size() < 2) continue;  // need at least IP + one name
        auto addr = parse_ipv4_string(tokens[0]);
        if (!addr) continue;
        std::string canonical_ip = format_ipv4(*addr);
        if (out.find(canonical_ip) != out.end()) continue;  // first occurrence wins
        out[canonical_ip] = tokens[1];
    }
}

// Parses a Unix /etc/services-style file into `out` (seeded beforehand with the built-in table by
// the caller), overwriting/adding entries. Format per line: "name port/proto [alias...]", '#'
// starts a comment, blank lines skipped. A line that doesn't parse as "<uint16 port>/<tcp|udp>" in
// its second field is silently skipped, same tolerant-parsing posture as parse_hosts_file above.
// LAST occurrence in the file wins for a given (port, proto) -- the opposite of parse_hosts_file's
// first-wins rule, deliberately: this file's entire purpose is overriding the built-in table (and
// itself, if it repeats an entry), so top-to-bottom "last write wins" is the least surprising rule
// for a file the operator is actively curating as an override list.
//
// Throws ResolverError if the file can't be opened at all.
void parse_services_file(const std::string& path, std::unordered_map<uint32_t, std::string>& out) {
    std::ifstream in(path);
    if (!in) throw ResolverError("cannot open services file '" + path + "'");
    std::string line;
    while (std::getline(in, line)) {
        std::string content = trim(strip_comment(line));
        if (content.empty()) continue;
        std::vector<std::string> tokens = split_ws(content);
        if (tokens.size() < 2) continue;  // need at least name + port/proto
        const std::string& name = tokens[0];
        size_t slash = tokens[1].find('/');
        if (slash == std::string::npos) continue;
        std::string port_str = tokens[1].substr(0, slash);
        std::string proto = to_lower(tokens[1].substr(slash + 1));
        if (proto != "tcp" && proto != "udp") continue;
        if (port_str.empty() || port_str.find_first_not_of("0123456789") != std::string::npos) continue;
        long port_val;
        try {
            port_val = std::stol(port_str);
        } catch (...) {
            continue;
        }
        if (port_val < 1 || port_val > 65535) continue;
        out[service_key(static_cast<uint16_t>(port_val), proto)] = name;
    }
}

}  // namespace

Resolver::Resolver(bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                    bool service_names_enabled, const std::string& services_path,
                    std::vector<std::string>& notes)
    : oui_enabled_(oui_enabled),
      resolve_hostnames_(resolve_hostnames),
      service_names_enabled_(service_names_enabled) {
    if (resolve_hostnames_) {
        if (hosts_path.empty()) {
            notes.push_back(
                "--resolve was given with no --hosts file; hostname resolution has nothing to "
                "resolve against (this tool never performs live DNS lookups -- see docs/"
                "MANUAL.md's OUTPUT FORMATS section)");
        } else {
            parse_hosts_file(hosts_path, hosts_);
        }
    } else if (!hosts_path.empty()) {
        notes.push_back("--hosts was given without --resolve; hostname resolution is not enabled, "
                         "so this file will not be used");
    }

    if (service_names_enabled_) {
        for (const auto& entry : kBuiltinServices) {
            services_[service_key(entry.port, entry.proto)] = entry.name;
        }
        if (!services_path.empty()) parse_services_file(services_path, services_);
    } else if (!services_path.empty()) {
        notes.push_back("--services was given while --nn disables service name resolution; this "
                         "file will not be used");
    }
}

std::optional<std::string> Resolver::oui_vendor(const std::string& mac) const {
    if (!oui_enabled_) return std::nullopt;
    auto mac48 = parse_format_mac(mac);
    if (!mac48) return std::nullopt;
    return oui_vendor_lookup(*mac48);
}

std::optional<std::string> Resolver::hostname(const std::string& ip) const {
    if (!resolve_hostnames_ || hosts_.empty()) return std::nullopt;
    auto addr = parse_ipv4_string(ip);
    if (!addr) return std::nullopt;
    auto it = hosts_.find(format_ipv4(*addr));
    if (it == hosts_.end()) return std::nullopt;
    return it->second;
}

std::optional<std::string> Resolver::service_name(uint16_t port, const std::string& proto) const {
    if (!service_names_enabled_) return std::nullopt;
    auto it = services_.find(service_key(port, proto));
    if (it == services_.end()) return std::nullopt;
    return it->second;
}

}  // namespace conduitscope
