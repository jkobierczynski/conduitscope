// SPDX-License-Identifier: MIT
#include "conduitscope/dnp3.hpp"

#include <sstream>

namespace conduitscope {

std::optional<Dnp3LinkFrame> try_parse_dnp3_link_layer(ByteSpan tcp_payload) {
    // Fixed data link header: start(2) + length(1) + control(1) + destination(2) +
    // source(2) + CRC(2) = 10 bytes.
    if (tcp_payload.size() < 10) {
        return std::nullopt;
    }
    if (tcp_payload.at(0) != 0x05 || tcp_payload.at(1) != 0x64) {
        return std::nullopt;
    }

    Cursor c(tcp_payload);
    c.u8();  // start byte 1 (0x05)
    c.u8();  // start byte 2 (0x64)
    uint8_t length_field = c.u8();
    uint8_t control = c.u8();
    uint16_t destination = c.u16le();
    uint16_t source = c.u16le();
    c.u16be();  // header CRC -- present but not validated in this release

    Dnp3LinkFrame frame;
    frame.length_field = length_field;
    frame.control = control;
    frame.destination = destination;
    frame.source = source;
    frame.crc_validated = false;
    frame.user_data_bytes = (length_field >= 5) ? static_cast<size_t>(length_field - 5) : 0;

    std::ostringstream out;
    out << "DNP3 data link frame: source=" << source << " destination=" << destination
        << " control=0x" << std::hex << static_cast<unsigned>(control) << std::dec
        << " user_data=" << frame.user_data_bytes
        << " byte(s) [transport/application layer not decoded in this groundwork release]";
    frame.summary = out.str();

    return frame;
}

}  // namespace conduitscope
