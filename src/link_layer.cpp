// SPDX-License-Identifier: Apache-2.0
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

    // Classic IEEE 802.3 length-framed LLC recognition -- see this file's header comment.
    if (ethertype < ETHERTYPE_MIN_DIX) {
        eth.is_llc_length = true;
        eth.length_field = ethertype;

        if (eth.payload.size() >= 3) {
            Cursor lc(eth.payload);
            eth.llc_dsap = lc.u8();
            eth.llc_ssap = lc.u8();
            eth.llc_control = lc.u8();
            eth.has_llc = true;
            size_t header_consumed = 3;
            ByteSpan after_llc = lc.rest();

            if (eth.llc_dsap == LLC_SAP_SNAP && eth.llc_ssap == LLC_SAP_SNAP && after_llc.size() >= 5) {
                Cursor sc(after_llc);
                for (auto& b : eth.snap_oui) b = sc.u8();
                eth.snap_protocol_id = sc.u16be();
                eth.has_snap = true;
                header_consumed += 5;
                after_llc = sc.rest();
            }

            // Bound by the 802.3 Length field when it's usable -- see EthernetFrame::llc_payload's
            // comment for the fallback rationale.
            if (eth.length_field >= header_consumed) {
                size_t declared_client_len = eth.length_field - header_consumed;
                if (declared_client_len <= after_llc.size()) {
                    eth.llc_trailing_bytes_trimmed = after_llc.size() - declared_client_len;
                    eth.llc_payload = after_llc.subspan(0, declared_client_len);
                } else {
                    // Declares more than was actually captured -- almost always snaplen truncation,
                    // not evidence the Length field itself is wrong. Decode what's present.
                    eth.llc_payload = after_llc;
                }
            } else {
                // Too small to even cover the LLC/SNAP header already consumed -- implausible,
                // fall back to everything actually captured (mirrors GOOSE/SV/EtherCAT's own
                // tolerant "implausible declared length" fallback -- see e.g. goose.cpp).
                eth.llc_payload = after_llc;
            }
        }
    }

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
        case ETHERTYPE_EAPOL: return "IEEE 802.1X/EAPOL";
        case ETHERTYPE_PPPOE_DISCOVERY: return "PPPoE Discovery";
        case ETHERTYPE_PPPOE_SESSION: return "PPPoE Session";
        case ETHERTYPE_LLDP: return "LLDP";
        case ETHERTYPE_PTP: return "IEEE 1588 PTP";
        case ETHERTYPE_MPLS_UNICAST: return "MPLS unicast";
        case ETHERTYPE_MPLS_MULTICAST: return "MPLS multicast";
        case ETHERTYPE_SLOW_PROTOCOLS: return "IEEE 802.3 Slow Protocols (LACP/Marker/OAM)";
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
