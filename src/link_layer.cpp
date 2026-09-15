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

std::string ethertype_name(uint16_t ethertype) {
    switch (ethertype) {
        case ETHERTYPE_ARP: return "ARP";
        case ETHERTYPE_IPV6: return "IPv6";
        case ETHERTYPE_VLAN: return "IEEE 802.1Q, likely a stacked/QinQ VLAN tag not unwrapped -- see parse_ethernet's comment";
        case ETHERTYPE_8021AD: return "IEEE 802.1ad (provider bridging / stacked VLAN tag)";
        case ETHERTYPE_PROFINET: return "PROFINET RT";
        case ETHERTYPE_ETHERCAT: return "EtherCAT";
        case ETHERTYPE_IEC61850_GOOSE: return "IEC 61850-8-1 GOOSE";
        case ETHERTYPE_IEC61850_SV: return "IEC 61850-9-2 Sampled Values";
        case ETHERTYPE_LLDP: return "LLDP";
        case ETHERTYPE_PTP: return "IEEE 1588 PTP";
        case ETHERTYPE_MPLS_UNICAST: return "MPLS unicast";
        default: return "";
    }
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
