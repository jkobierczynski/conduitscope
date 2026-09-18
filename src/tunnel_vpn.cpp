// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/tunnel_vpn.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/link_layer.hpp"

namespace conduitscope {

namespace {

bool port_matches(uint16_t src_port, uint16_t dst_port, uint16_t expected,
                   const std::vector<uint16_t>& extra_ports) {
    if (src_port == expected || dst_port == expected) return true;
    for (uint16_t p : extra_ports) {
        if (src_port == p || dst_port == p) return true;
    }
    return false;
}

// Shared by GRE and Geneve's own inner Protocol Type field -- both reuse link_layer.hpp's
// ethertype_name rather than re-implementing an EtherType lookup, falling back to a raw hex value
// when it's not one of the EtherTypes this codebase already names.
std::string protocol_type_name(uint16_t protocol_type) {
    std::string name = ethertype_name(protocol_type);
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << protocol_type << std::dec;
    if (protocol_type == ETHERTYPE_IPV4) return s.str() + " (IPv4)";
    if (!name.empty()) return s.str() + " (" + name + ")";
    return s.str();
}

// ---------------------------------------------------------------------------------------------
// GRE (47), with NVGRE/EoIP sub-cases -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnIpProtoMatch> try_recognize_gre(ByteSpan ip_payload) {
    if (ip_payload.size() < 4) return std::nullopt;

    uint8_t b0 = ip_payload.at(0);
    uint8_t b1 = ip_payload.at(1);
    bool checksum_present = (b0 & 0x80) != 0;
    bool key_present = (b0 & 0x20) != 0;
    bool sequence_present = (b0 & 0x10) != 0;
    uint8_t version = b1 & 0x07;  // low 3 bits of the second byte are the Version field
    if (version != 0) return std::nullopt;  // 1 = Enhanced GRE/PPTP, out of scope here

    uint16_t protocol_type = static_cast<uint16_t>((ip_payload.at(2) << 8) | ip_payload.at(3));

    TunnelVpnIpProtoMatch m;
    std::ostringstream s;

    if (protocol_type == GRE_PROTOCOL_TYPE_NVGRE_OR_ETHERNET_BRIDGING && key_present) {
        m.protocol = "nvgre";
        s << "NVGRE (or plain Ethernet-bridging-over-GRE, structurally indistinguishable -- see "
             "tunnel_vpn.hpp's own header comment) tunnel";
        m.notes.push_back("Protocol Type 0x6558 with the Key flag set matches BOTH NVGRE (RFC 8926) "
                           "and ordinary Ethernet-bridging-over-GRE; this decoder cannot tell them "
                           "apart without interpreting the Key field's own VSID/FlowID split");
    } else if (protocol_type == GRE_PROTOCOL_TYPE_EOIP) {
        m.protocol = "eoip";
        s << "Mikrotik EoIP (Ethernet-over-IP) tunnel";
    } else {
        m.protocol = "gre";
        s << "GRE tunnel carrying " << protocol_type_name(protocol_type);
    }

    if (checksum_present) s << ", checksum present";
    if (sequence_present) s << ", sequence number present";
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// ESP (50) and AH (51) -- see tunnel_vpn.hpp's own header comment for why neither has a further
// structural gate past the IP protocol number itself.

std::optional<TunnelVpnIpProtoMatch> try_recognize_esp(ByteSpan ip_payload) {
    TunnelVpnIpProtoMatch m;
    m.protocol = "esp";
    std::ostringstream s;
    s << "IPsec ESP tunnel (RFC 4303)";
    if (ip_payload.size() >= 4) {
        uint32_t spi = (static_cast<uint32_t>(ip_payload.at(0)) << 24) |
                       (static_cast<uint32_t>(ip_payload.at(1)) << 16) |
                       (static_cast<uint32_t>(ip_payload.at(2)) << 8) | ip_payload.at(3);
        std::ostringstream spi_hex;
        spi_hex << "0x" << std::hex << std::uppercase << spi << std::dec;
        s << ", SPI=" << spi_hex.str();
    }
    s << " -- payload is encrypted/authenticated, not decoded further";
    m.summary = s.str();
    return m;
}

std::optional<TunnelVpnIpProtoMatch> try_recognize_ah(ByteSpan ip_payload) {
    TunnelVpnIpProtoMatch m;
    m.protocol = "ah";
    std::ostringstream s;
    s << "IPsec AH tunnel (RFC 4302)";
    if (ip_payload.size() >= 8) {
        uint8_t next_header = ip_payload.at(0);
        std::string name = ip_protocol_name(next_header);
        s << ", protecting ";
        if (!name.empty()) {
            s << name;
        } else {
            s << "IP protocol " << static_cast<unsigned>(next_header);
        }
        uint32_t spi = (static_cast<uint32_t>(ip_payload.at(4)) << 24) |
                       (static_cast<uint32_t>(ip_payload.at(5)) << 16) |
                       (static_cast<uint32_t>(ip_payload.at(6)) << 8) | ip_payload.at(7);
        std::ostringstream spi_hex;
        spi_hex << "0x" << std::hex << std::uppercase << spi << std::dec;
        s << ", SPI=" << spi_hex.str();
    }
    s << " -- ICV not verified, inner payload not decoded further";
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// IP-in-IP (4) and 6in4 (41) -- see tunnel_vpn.hpp's own header comment for why only IP-in-IP's
// inner addresses are surfaced.

std::optional<TunnelVpnIpProtoMatch> try_recognize_ip_in_ip(ByteSpan ip_payload) {
    if (ip_payload.empty()) return std::nullopt;
    uint8_t first_nibble = (ip_payload.at(0) >> 4) & 0x0F;
    if (first_nibble != 4) return std::nullopt;

    TunnelVpnIpProtoMatch m;
    m.protocol = "ip-in-ip";
    std::ostringstream s;
    s << "IP-in-IP tunnel (RFC 2003)";
    if (ip_payload.size() >= 20) {
        uint32_t inner_src = (static_cast<uint32_t>(ip_payload.at(12)) << 24) |
                              (static_cast<uint32_t>(ip_payload.at(13)) << 16) |
                              (static_cast<uint32_t>(ip_payload.at(14)) << 8) | ip_payload.at(15);
        uint32_t inner_dst = (static_cast<uint32_t>(ip_payload.at(16)) << 24) |
                              (static_cast<uint32_t>(ip_payload.at(17)) << 16) |
                              (static_cast<uint32_t>(ip_payload.at(18)) << 8) | ip_payload.at(19);
        s << ", inner " << format_ipv4(inner_src) << " -> " << format_ipv4(inner_dst);
    }
    s << " -- inner payload not decoded past its own header";
    m.summary = s.str();
    return m;
}

std::optional<TunnelVpnIpProtoMatch> try_recognize_6in4(ByteSpan ip_payload) {
    if (ip_payload.empty()) return std::nullopt;
    uint8_t first_nibble = (ip_payload.at(0) >> 4) & 0x0F;
    if (first_nibble != 6) return std::nullopt;

    TunnelVpnIpProtoMatch m;
    m.protocol = "6in4";
    m.summary = "6in4 (IPv6-in-IPv4) tunnel (RFC 4213) -- inner IPv6 header present but not decoded "
                "(this decoder has no IPv6 address parser, see tunnel_vpn.hpp's own header comment)";
    return m;
}

// ---------------------------------------------------------------------------------------------
// L2TPv3 direct-IP encapsulation (115) -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnIpProtoMatch> try_recognize_l2tpv3_ip(ByteSpan ip_payload) {
    TunnelVpnIpProtoMatch m;
    m.protocol = "l2tp";
    std::ostringstream s;
    s << "L2TPv3 tunnel (RFC 3931, direct IP encapsulation, IP protocol 115)";
    if (ip_payload.size() >= 4) {
        uint32_t session_id = (static_cast<uint32_t>(ip_payload.at(0)) << 24) |
                               (static_cast<uint32_t>(ip_payload.at(1)) << 16) |
                               (static_cast<uint32_t>(ip_payload.at(2)) << 8) | ip_payload.at(3);
        std::ostringstream sid_hex;
        sid_hex << "0x" << std::hex << std::uppercase << session_id << std::dec;
        s << ", Session ID=" << sid_hex.str();
    }
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// IKE (500, 4500) and NAT-T ESP (4500) -- see tunnel_vpn.hpp's own header comment.

std::string ike_exchange_type_name(uint8_t t) {
    switch (t) {
        case 34: return "IKE_SA_INIT";
        case 35: return "IKE_AUTH";
        case 36: return "CREATE_CHILD_SA";
        case 37: return "INFORMATIONAL";
        default: return "";
    }
}

std::optional<TunnelVpnUdpMatch> try_recognize_ike(ByteSpan body, bool natt) {
    if (body.size() < 28) return std::nullopt;

    uint8_t version = body.at(17);
    uint8_t major_version = (version >> 4) & 0x0F;
    if (major_version != 1 && major_version != 2) return std::nullopt;

    uint8_t exchange_type = body.at(18);
    uint32_t length = (static_cast<uint32_t>(body.at(24)) << 24) |
                       (static_cast<uint32_t>(body.at(25)) << 16) |
                       (static_cast<uint32_t>(body.at(26)) << 8) | body.at(27);
    if (length < 28) return std::nullopt;  // shorter than the fixed header itself -- implausible

    TunnelVpnUdpMatch m;
    m.protocol = "ike";
    std::ostringstream s;
    s << "IKE" << (major_version == 2 ? "v2" : "v1") << (natt ? " (NAT-T, UDP 4500)" : "");
    std::string ex_name = ike_exchange_type_name(exchange_type);
    if (!ex_name.empty()) {
        s << " " << ex_name;
    } else {
        s << " exchange type " << static_cast<unsigned>(exchange_type);
    }
    if (length > body.size()) {
        m.notes.push_back("IKE header declares a " + std::to_string(length) + "-byte message but only "
                           + std::to_string(body.size()) +
                           " byte(s) are available -- truncated capture");
    }
    m.summary = s.str();
    return m;
}

std::optional<TunnelVpnUdpMatch> try_recognize_natt(ByteSpan payload) {
    // RFC 3948 section 2: a 4-byte all-zero "non-ESP marker" ahead of an IKE header disambiguates
    // IKE from raw ESP on the shared NAT-T port 4500 -- no marker means the rest of the datagram IS
    // an ESP header directly.
    bool has_marker = payload.size() >= 4 && payload.at(0) == 0 && payload.at(1) == 0 &&
                       payload.at(2) == 0 && payload.at(3) == 0;
    if (has_marker) {
        if (auto ike = try_recognize_ike(payload.from(4), /*natt=*/true)) return ike;
        return std::nullopt;
    }
    // No marker -- this is ESP itself, NAT-Traversed. Reuse the IP-protocol-side ESP match (same
    // "SPI, opaque past that" shape) rather than duplicating it, converting its result type.
    if (auto esp = try_recognize_esp(payload)) {
        TunnelVpnUdpMatch m;
        m.protocol = "esp";
        m.summary = esp->summary + " (NAT-Traversed, UDP 4500, no non-ESP marker present)";
        m.notes = esp->notes;
        return m;
    }
    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------
// L2TP over UDP (1701) -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnUdpMatch> try_recognize_l2tp_udp(ByteSpan body) {
    if (body.size() < 2) return std::nullopt;

    uint8_t b0 = body.at(0);
    uint8_t b1 = body.at(1);
    bool type_control = (b0 & 0x80) != 0;
    bool length_present = (b0 & 0x40) != 0;
    bool sequence_present = (b0 & 0x08) != 0;
    bool offset_present = (b0 & 0x02) != 0;
    bool reserved_ok = (b0 & 0x34) == 0 && (b1 & 0xF0) == 0;  // both reserved-bit groups clear
    uint8_t version = b1 & 0x0F;

    TunnelVpnUdpMatch m;
    m.protocol = "l2tp";
    std::ostringstream s;

    if (version == 2 && reserved_ok) {
        s << "L2TPv2 (RFC 2661) " << (type_control ? "control" : "data") << " message";
        if (length_present) s << ", Length field present";
        if (sequence_present) s << ", sequence numbers present";
        if (offset_present) s << ", offset field present";
    } else {
        // Doesn't fit L2TPv2's own structural shape -- almost certainly L2TPv3-over-UDP (RFC 3931
        // section 4.1), whose 32-bit Session ID has no structural constraint at all, the same "port
        // number carries all the confidence" shape L2TPv3-over-IP has above -- see this file's own
        // header comment for the honesty caveat.
        uint32_t session_id = (static_cast<uint32_t>(body.at(0)) << 24) |
                               (static_cast<uint32_t>(body.at(1)) << 16) |
                               (body.size() >= 4 ? (static_cast<uint32_t>(body.at(2)) << 8) : 0) |
                               (body.size() >= 4 ? body.at(3) : 0);
        std::ostringstream sid_hex;
        sid_hex << "0x" << std::hex << std::uppercase << session_id << std::dec;
        s << "L2TP on port 1701, Session ID=" << sid_hex.str()
          << " (did not match L2TPv2's own structural shape -- likely L2TPv3-over-UDP, whose Session "
             "ID has no distinguishing structure of its own; this is the WEAK, port-only fallback)";
    }
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// VXLAN (4789) -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnUdpMatch> try_recognize_vxlan(ByteSpan body) {
    if (body.size() < 8) return std::nullopt;
    uint8_t flags = body.at(0);
    uint8_t reserved2 = body.at(7);
    if (flags != 0x08 || reserved2 != 0x00) return std::nullopt;

    uint32_t vni = (static_cast<uint32_t>(body.at(4)) << 16) |
                   (static_cast<uint32_t>(body.at(5)) << 8) | body.at(6);

    TunnelVpnUdpMatch m;
    m.protocol = "vxlan";
    std::ostringstream s;
    s << "VXLAN tunnel (RFC 7348), VNI=" << vni;
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// Geneve (6081) -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnUdpMatch> try_recognize_geneve(ByteSpan body) {
    if (body.size() < 8) return std::nullopt;
    uint8_t b0 = body.at(0);
    uint8_t version = (b0 >> 6) & 0x03;
    uint8_t opt_len_words = b0 & 0x3F;
    uint8_t b1 = body.at(1);
    if (version != 0) return std::nullopt;
    if ((b1 & 0x3F) != 0) return std::nullopt;  // Reserved bits must be zero

    size_t header_len = 8 + static_cast<size_t>(opt_len_words) * 4;
    if (header_len > body.size()) return std::nullopt;  // declares more options than were captured

    uint16_t protocol_type = static_cast<uint16_t>((body.at(2) << 8) | body.at(3));
    uint32_t vni = (static_cast<uint32_t>(body.at(4)) << 16) |
                   (static_cast<uint32_t>(body.at(5)) << 8) | body.at(6);

    TunnelVpnUdpMatch m;
    m.protocol = "geneve";
    std::ostringstream s;
    s << "Geneve tunnel (RFC 8926), VNI=" << vni << ", inner " << protocol_type_name(protocol_type);
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// WireGuard (51820) -- see tunnel_vpn.hpp's own header comment.

std::optional<TunnelVpnUdpMatch> try_recognize_wireguard(ByteSpan body) {
    if (body.size() < 4) return std::nullopt;
    uint8_t type = body.at(0);
    if (body.at(1) != 0 || body.at(2) != 0 || body.at(3) != 0) return std::nullopt;

    TunnelVpnUdpMatch m;
    m.protocol = "wireguard";
    std::ostringstream s;
    s << "WireGuard ";
    switch (type) {
        case 1:
            if (body.size() != 148) return std::nullopt;
            s << "Handshake Initiation";
            break;
        case 2:
            if (body.size() != 92) return std::nullopt;
            s << "Handshake Response";
            break;
        case 3:
            if (body.size() != 64) return std::nullopt;
            s << "Cookie Reply";
            break;
        case 4:
            if (body.size() < 16) return std::nullopt;
            s << "Transport Data";
            break;
        default:
            return std::nullopt;
    }
    m.summary = s.str();
    return m;
}

// ---------------------------------------------------------------------------------------------
// OpenVPN (1194, UDP and TCP -- see try_recognize_openvpn_opcode's own shared use below).

std::string openvpn_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 1: return "P_CONTROL_HARD_RESET_CLIENT_V1";
        case 3: return "P_CONTROL_SOFT_RESET_V1";
        case 4: return "P_CONTROL_V1";
        case 5: return "P_ACK_V1";
        case 6: return "P_DATA_V1";
        case 7: return "P_CONTROL_HARD_RESET_CLIENT_V2";
        case 9: return "P_DATA_V2";
        case 10: return "P_CONTROL_HARD_RESET_CLIENT_V3";
        case 11: return "P_CONTROL_WKC_V1";
        default: return "";
    }
}

// Shared between the UDP and TCP forms -- `body` is the OpenVPN packet itself (for TCP, AFTER its
// own 2-byte length prefix has already been stripped by the caller).
std::optional<std::string> try_recognize_openvpn_body(ByteSpan body) {
    if (body.empty()) return std::nullopt;
    uint8_t opcode = (body.at(0) >> 3) & 0x1F;
    std::string name = openvpn_opcode_name(opcode);
    if (name.empty()) return std::nullopt;
    return "OpenVPN " + name + " (weak, opcode-only signature -- see tunnel_vpn.hpp's own header "
                                "comment)";
}

// ---------------------------------------------------------------------------------------------
// Generic DTLS record structural check -- see tunnel_vpn.hpp's own header comment for why this is
// checked port-independently, last among every UDP check in this file.

std::optional<TunnelVpnUdpMatch> try_recognize_dtls_tunnel(ByteSpan body) {
    if (body.size() < 13) return std::nullopt;
    uint8_t content_type = body.at(0);
    if (content_type < 20 || content_type > 23) return std::nullopt;

    uint16_t version = static_cast<uint16_t>((body.at(1) << 8) | body.at(2));
    std::string version_name;
    if (version == 0xFEFF) version_name = "DTLS 1.0";
    else if (version == 0xFEFD) version_name = "DTLS 1.2";
    else if (version == 0xFEFC) version_name = "DTLS 1.3";
    else return std::nullopt;

    uint16_t length = static_cast<uint16_t>((body.at(11) << 8) | body.at(12));

    TunnelVpnUdpMatch m;
    m.protocol = "dtls-tunnel";
    std::ostringstream s;
    s << "generic " << version_name << " record (content type " << static_cast<unsigned>(content_type)
      << ") -- an encrypted DTLS-based tunnel of unknown purpose (CAPWAP data plane, a vendor AP "
         "control channel, an LTE offload client, or a deliberate DTLS-based VPN are all "
         "indistinguishable from this header alone)";
    if (13 + static_cast<size_t>(length) > body.size()) {
        m.notes.push_back("DTLS record declares a " + std::to_string(length) +
                           "-byte body but only " + std::to_string(body.size() - 13) +
                           " byte(s) are available -- truncated capture, or more records follow");
    }
    m.summary = s.str();
    return m;
}

}  // namespace

std::optional<TunnelVpnIpProtoMatch> try_recognize_tunnel_vpn_ip_proto(ByteSpan ip_payload,
                                                                          uint8_t ip_protocol) {
    if (ip_protocol == GRE_IP_PROTOCOL) return try_recognize_gre(ip_payload);
    if (ip_protocol == ESP_IP_PROTOCOL) return try_recognize_esp(ip_payload);
    if (ip_protocol == AH_IP_PROTOCOL) return try_recognize_ah(ip_payload);
    if (ip_protocol == IPIP_IP_PROTOCOL) return try_recognize_ip_in_ip(ip_payload);
    if (ip_protocol == IPV6_6IN4_IP_PROTOCOL) return try_recognize_6in4(ip_payload);
    if (ip_protocol == L2TPV3_IP_PROTOCOL) return try_recognize_l2tpv3_ip(ip_payload);
    return std::nullopt;
}

std::optional<TunnelVpnUdpMatch> try_recognize_tunnel_vpn_udp(ByteSpan payload, uint16_t src_port,
                                                                 uint16_t dst_port,
                                                                 const std::vector<uint16_t>& extra_ports) {
    if (port_matches(src_port, dst_port, IKE_PORT, extra_ports)) {
        if (auto m = try_recognize_ike(payload, /*natt=*/false)) return m;
    }
    if (port_matches(src_port, dst_port, IKE_NATT_PORT, extra_ports)) {
        if (auto m = try_recognize_natt(payload)) return m;
    }
    if (port_matches(src_port, dst_port, L2TP_PORT, extra_ports)) {
        if (auto m = try_recognize_l2tp_udp(payload)) return m;
    }
    if (port_matches(src_port, dst_port, VXLAN_PORT, extra_ports)) {
        if (auto m = try_recognize_vxlan(payload)) return m;
    }
    if (port_matches(src_port, dst_port, GENEVE_PORT, extra_ports)) {
        if (auto m = try_recognize_geneve(payload)) return m;
    }
    if (port_matches(src_port, dst_port, WIREGUARD_PORT, extra_ports)) {
        if (auto m = try_recognize_wireguard(payload)) return m;
    }
    if (port_matches(src_port, dst_port, OPENVPN_PORT, extra_ports)) {
        if (auto body = try_recognize_openvpn_body(payload)) {
            TunnelVpnUdpMatch m;
            m.protocol = "openvpn";
            m.summary = *body;
            return m;
        }
    }
    // Tried port-independently, LAST -- see tunnel_vpn.hpp's own header comment.
    if (auto m = try_recognize_dtls_tunnel(payload)) return m;
    return std::nullopt;
}

std::optional<TunnelVpnTcpMatch> try_recognize_tunnel_vpn_tcp(ByteSpan payload, uint16_t src_port,
                                                                 uint16_t dst_port,
                                                                 const std::vector<uint16_t>& extra_ports) {
    if (port_matches(src_port, dst_port, OPENVPN_PORT, extra_ports)) {
        // OpenVPN-over-TCP prepends a 2-byte big-endian length ahead of the identical opcode-byte
        // framing the UDP form uses.
        if (payload.size() >= 3) {
            uint16_t declared_len = static_cast<uint16_t>((payload.at(0) << 8) | payload.at(1));
            if (auto body = try_recognize_openvpn_body(payload.from(2))) {
                TunnelVpnTcpMatch m;
                m.protocol = "openvpn";
                m.summary = *body + " (TCP, 2-byte length prefix)";
                if (static_cast<size_t>(declared_len) + 2 > payload.size()) {
                    m.notes.push_back("OpenVPN-over-TCP declares a " + std::to_string(declared_len) +
                                       "-byte packet but only " + std::to_string(payload.size() - 2) +
                                       " byte(s) are available -- truncated capture, or more of the "
                                       "packet follows in a later TCP segment");
                }
                return m;
            }
        }
    }
    if (port_matches(src_port, dst_port, STT_PORT, extra_ports)) {
        TunnelVpnTcpMatch m;
        m.protocol = "stt";
        m.summary = "STT (Stateless Transport Tunneling) on TCP port 7878 -- recognized by port "
                    "number alone, no authoritative public wire-format specification to check a "
                    "structural signature against (see tunnel_vpn.hpp's own header comment)";
        return m;
    }
    return std::nullopt;
}

}  // namespace conduitscope
