// SPDX-License-Identifier: MIT
#include "conduitscope/link_layer.hpp"

#include <sstream>
#include <iomanip>

namespace conduitscope {

EthernetFrame parse_ethernet(ByteSpan frame) {
    Cursor c(frame);
    EthernetFrame eth;

    for (auto& b : eth.dst_mac) b = c.u8();
    for (auto& b : eth.src_mac) b = c.u8();

    uint16_t ethertype = c.u16be();
    if (ethertype == ETHERTYPE_VLAN) {
        uint16_t tci = c.u16be();
        eth.has_vlan_tag = true;
        eth.vlan_id = tci & 0x0FFF;
        ethertype = c.u16be();  // the real ethertype follows the tag
    }

    eth.ethertype = ethertype;
    eth.payload = c.rest();
    return eth;
}

RawIpFrame parse_raw_ip(ByteSpan frame) {
    RawIpFrame f;
    f.payload = frame;
    return f;
}

std::string format_mac(const std::array<uint8_t, 6>& mac) {
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    for (size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) out << ':';
        out << std::setw(2) << static_cast<unsigned>(mac[i]);
    }
    return out.str();
}

}  // namespace conduitscope
