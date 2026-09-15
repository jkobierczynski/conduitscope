// SPDX-License-Identifier: MIT
#include "conduitscope/tcp.hpp"

#include <sstream>

namespace conduitscope {

TcpSegment parse_tcp(ByteSpan segment) {
    Cursor c(segment);
    TcpSegment tcp;

    tcp.src_port = c.u16be();
    tcp.dst_port = c.u16be();
    tcp.seq = c.u32be();
    tcp.ack = c.u32be();

    uint8_t offset_reserved = c.u8();
    uint8_t data_offset_words = static_cast<uint8_t>(offset_reserved >> 4);
    if (data_offset_words < 5) {
        throw ParseError("TCP data offset field is impossibly small (" +
                          std::to_string(data_offset_words) + " words)");
    }
    tcp.flags = c.u8();
    tcp.window = c.u16be();
    c.u16be();  // checksum -- not validated; we trust the capture
    c.u16be();  // urgent pointer -- unused unless URG is set, which we don't currently act on

    size_t header_bytes = static_cast<size_t>(data_offset_words) * 4;
    if (header_bytes < c.position()) {
        throw ParseError("TCP data offset is inconsistent with the fixed fields already read");
    }
    size_t options_len = header_bytes - c.position();
    c.skip(options_len);  // skip TCP options; we don't currently interpret any of them

    tcp.payload = c.rest();
    return tcp;
}

std::string format_tcp_flags(uint8_t flags) {
    std::ostringstream out;
    bool first = true;
    auto add = [&](uint8_t bit, const char* name) {
        if (flags & bit) {
            if (!first) out << ',';
            out << name;
            first = false;
        }
    };
    add(TCP_FLAG_SYN, "SYN");
    add(TCP_FLAG_ACK, "ACK");
    add(TCP_FLAG_FIN, "FIN");
    add(TCP_FLAG_RST, "RST");
    add(TCP_FLAG_PSH, "PSH");
    add(TCP_FLAG_URG, "URG");
    if (first) return "-";
    return out.str();
}

}  // namespace conduitscope
