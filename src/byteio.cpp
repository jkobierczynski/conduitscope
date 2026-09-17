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

}  // namespace conduitscope
