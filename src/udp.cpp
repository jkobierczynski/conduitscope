// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/udp.hpp"

namespace conduitscope {

UdpDatagram parse_udp(ByteSpan segment) {
    Cursor c(segment);
    UdpDatagram udp;

    udp.src_port = c.u16be();
    udp.dst_port = c.u16be();
    udp.declared_length = c.u16be();
    c.u16be();  // checksum -- not validated; we trust the capture (0 is also a legal "not
                // computed" value over IPv4, so its absence isn't itself a red flag)

    ByteSpan captured_after_header = c.rest();
    constexpr size_t kHeaderBytes = 8;
    if (udp.declared_length >= kHeaderBytes) {
        size_t declared_payload_len = static_cast<size_t>(udp.declared_length) - kHeaderBytes;
        if (declared_payload_len <= captured_after_header.size()) {
            udp.payload = captured_after_header.subspan(0, declared_payload_len);
        } else {
            // declared_length claims more than was actually captured (a short snaplen
            // truncated this packet) -- use what we have rather than claim bytes that don't
            // exist.
            udp.payload = captured_after_header;
        }
    } else {
        // declared_length is 0 or smaller than the header itself -- not trustworthy (the same
        // NIC checksum/segmentation-offload situation documented on ipv4.cpp's own total_length
        // clamp can leave this field unfilled too). Fall back to every captured byte.
        udp.payload = captured_after_header;
    }
    return udp;
}

}  // namespace conduitscope
