// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/byteio.hpp"

#include <sstream>
#include <iomanip>

namespace conduitscope {

std::string to_hex(ByteSpan span, const char* separator) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < span.size(); ++i) {
        if (i != 0) out << separator;
        out << std::setw(2) << static_cast<unsigned>(span.at(i));
    }
    return out.str();
}

namespace {
void append_utf8(std::string& out, uint32_t codepoint) {
    if (codepoint <= 0x7F) {
        out += static_cast<char>(codepoint);
    } else if (codepoint <= 0x7FF) {
        out += static_cast<char>(0xC0 | (codepoint >> 6));
        out += static_cast<char>(0x80 | (codepoint & 0x3F));
    } else if (codepoint <= 0xFFFF) {
        out += static_cast<char>(0xE0 | (codepoint >> 12));
        out += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (codepoint & 0x3F));
    } else {
        out += static_cast<char>(0xF0 | (codepoint >> 18));
        out += static_cast<char>(0x80 | ((codepoint >> 12) & 0x3F));
        out += static_cast<char>(0x80 | ((codepoint >> 6) & 0x3F));
        out += static_cast<char>(0x80 | (codepoint & 0x3F));
    }
}
}  // namespace

std::string utf16le_to_utf8(ByteSpan span) {
    std::string out;
    size_t n = span.size() & ~static_cast<size_t>(1);  // drop a trailing odd byte, if any
    for (size_t i = 0; i < n; i += 2) {
        uint32_t unit = static_cast<uint32_t>(span.at(i)) | (static_cast<uint32_t>(span.at(i + 1)) << 8);
        if (unit >= 0xD800 && unit <= 0xDBFF && i + 3 < n) {
            uint32_t low = static_cast<uint32_t>(span.at(i + 2)) | (static_cast<uint32_t>(span.at(i + 3)) << 8);
            if (low >= 0xDC00 && low <= 0xDFFF) {
                uint32_t combined = 0x10000 + ((unit - 0xD800) << 10) + (low - 0xDC00);
                append_utf8(out, combined);
                i += 2;
                continue;
            }
        }
        if (unit >= 0xD800 && unit <= 0xDFFF) {
            append_utf8(out, 0xFFFD);  // unpaired surrogate
            continue;
        }
        append_utf8(out, unit);
    }
    return out;
}

}  // namespace conduitscope
