// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/packet_range.hpp"

#include <cctype>
#include <stdexcept>

namespace conduitscope {

bool PacketRangeSpec::contains(size_t packet_number) const {
    for (const auto& [start, end] : intervals_) {
        if (packet_number >= start && packet_number <= end) return true;
    }
    return false;
}

namespace {

// Parses a single unsigned decimal token (no sign, no whitespace, not empty) into `out`. Returns
// false on anything else -- empty text, a non-digit character, or a value too large for size_t
// (std::stoull itself throws out_of_range for that, caught below). A leading-zero token like
// "007" is accepted (it round-trips through std::stoull fine, and there's no reason to reject it
// as a packet number any more than editcap or Wireshark's own frame numbers would).
bool parse_unsigned_token(const std::string& text, size_t& out) {
    if (text.empty()) return false;
    for (char c : text) {
        if (!std::isdigit(static_cast<unsigned char>(c))) return false;
    }
    try {
        size_t consumed = 0;
        unsigned long long value = std::stoull(text, &consumed);
        if (consumed != text.size()) return false;
        out = static_cast<size_t>(value);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

}  // namespace

std::optional<PacketRangeSpec> parse_packet_range(const std::string& text) {
    if (text.empty()) return std::nullopt;

    PacketRangeSpec spec;
    size_t pos = 0;
    while (pos <= text.size()) {
        size_t comma = text.find(',', pos);
        std::string token = text.substr(pos, comma == std::string::npos ? std::string::npos : comma - pos);
        if (token.empty()) return std::nullopt;  // leading/trailing/doubled comma, e.g. "5,,10"

        size_t dash = token.find('-');
        if (dash == std::string::npos) {
            size_t n = 0;
            if (!parse_unsigned_token(token, n) || n == 0) return std::nullopt;
            spec.add_interval(n, n);
        } else {
            std::string start_text = token.substr(0, dash);
            std::string end_text = token.substr(dash + 1);
            size_t start = 0, end = 0;
            if (!parse_unsigned_token(start_text, start) || start == 0) return std::nullopt;
            if (!parse_unsigned_token(end_text, end) || end == 0) return std::nullopt;
            if (end < start) return std::nullopt;
            spec.add_interval(start, end);
        }

        if (comma == std::string::npos) break;
        pos = comma + 1;
    }
    return spec;
}

}  // namespace conduitscope
