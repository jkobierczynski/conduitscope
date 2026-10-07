// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/symbol_table.hpp"

#include <fstream>
#include <sstream>

namespace conduitscope {

namespace {

// --------------------------------------------------------------------------------------------
// Small string helpers -- deliberately local/minimal, matching resolver.cpp's own established
// rationale for not reaching for yaml_mini.hpp's shared trim/split machinery: this file's format
// is a much simpler line shape and doesn't need any of that.
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

// "<crc>:<lid>:<lid>:..." -- see SymbolTable::resolve's own comment (symbol_table.hpp) for exactly
// what lid_chain must contain.
std::string make_key(uint32_t crc, const std::vector<uint32_t>& lid_chain) {
    std::ostringstream oss;
    oss << crc;
    for (uint32_t v : lid_chain) oss << ':' << v;
    return oss.str();
}

// Parses one line's first token ("<crc-hex>", optional leading "0x"/"0X", case-insensitive hex
// digits otherwise) into a uint32_t. Returns nullopt for anything that doesn't match that shape or
// doesn't fit in 32 bits -- malformed-line tolerance lives one level up (parse_symbol_table_file
// just skips the whole line on a nullopt here), not a parse error of its own.
std::optional<uint32_t> parse_crc_hex(const std::string& tok) {
    std::string digits = tok;
    if (digits.size() > 2 && digits[0] == '0' && (digits[1] == 'x' || digits[1] == 'X')) {
        digits = digits.substr(2);
    }
    if (digits.empty()) return std::nullopt;
    if (digits.find_first_not_of("0123456789abcdefABCDEF") != std::string::npos) return std::nullopt;
    uint64_t value;
    try {
        value = std::stoull(digits, nullptr, 16);
    } catch (...) {
        return std::nullopt;
    }
    if (value > 0xffffffffULL) return std::nullopt;
    return static_cast<uint32_t>(value);
}

// Parses one line's second token ("<lid-chain>") into an ordered list of uint32_t values. "-" is
// the explicit empty-chain sentinel (a lid_nesting_depth == 1 address, see this file's own header
// comment) and parses to an empty vector -- NOT the same as a malformed line. Otherwise expects
// dot-separated decimal, at least one segment; returns nullopt (the whole line gets skipped) for
// an empty segment (e.g. a stray "2." or ".5"), a non-digit segment, or a segment that doesn't fit
// in 32 bits.
std::optional<std::vector<uint32_t>> parse_lid_chain(const std::string& tok) {
    if (tok == "-") return std::vector<uint32_t>{};
    std::vector<uint32_t> chain;
    std::istringstream iss(tok);
    std::string part;
    while (std::getline(iss, part, '.')) {
        if (part.empty() || part.find_first_not_of("0123456789") != std::string::npos) return std::nullopt;
        unsigned long value;
        try {
            value = std::stoul(part);
        } catch (...) {
            return std::nullopt;
        }
        if (value > 0xffffffffUL) return std::nullopt;
        chain.push_back(static_cast<uint32_t>(value));
    }
    if (chain.empty()) return std::nullopt;  // a bare "." or empty token, not the "-" sentinel
    return chain;
}

// Parses the symbol table file into `out` (seeded empty by the caller) -- see this file's own
// header comment (symbol_table.hpp) for the exact line format, tolerant-parsing rules, and
// last-line-wins override convention. Throws SymbolTableError if the file can't be opened at all.
void parse_symbol_table_file(const std::string& path, std::unordered_map<std::string, std::string>& out) {
    std::ifstream in(path);
    if (!in) throw SymbolTableError("cannot open S7comm-Plus symbol table file '" + path + "'");
    std::string line;
    while (std::getline(in, line)) {
        std::string content = trim(strip_comment(line));
        if (content.empty()) continue;

        std::istringstream iss(content);
        std::string crc_tok, chain_tok;
        if (!(iss >> crc_tok) || !(iss >> chain_tok)) continue;  // need at least crc + lid-chain

        std::string name;
        std::getline(iss, name);
        name = trim(name);
        if (name.empty()) continue;  // need a name too

        auto crc = parse_crc_hex(crc_tok);
        if (!crc) continue;
        auto chain = parse_lid_chain(chain_tok);
        if (!chain) continue;

        out[make_key(*crc, *chain)] = name;  // last occurrence wins -- see header comment
    }
}

}  // namespace

SymbolTable::SymbolTable(const std::string& path) {
    if (!path.empty()) parse_symbol_table_file(path, entries_);
}

std::optional<std::string> SymbolTable::resolve(uint32_t crc, const std::vector<uint32_t>& lid_chain) const {
    if (entries_.empty()) return std::nullopt;
    auto it = entries_.find(make_key(crc, lid_chain));
    if (it == entries_.end()) return std::nullopt;
    return it->second;
}

}  // namespace conduitscope
