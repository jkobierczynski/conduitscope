// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/arp.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

constexpr size_t kFixedHeaderLength = 8;  // HTYPE(2) + PTYPE(2) + HLEN(1) + PLEN(1) + OPER(2)

// Curated opcode table -- RFC 826 (1/2), RFC 903 (3/4), RFC 1931 (5/6/7), RFC 2390 (8/9), RFC 2225
// (10, ATMARP NAK -- also reused generically as "ARP NAK"), plus IANA's ARP/RARP parameters
// registry for the MARS/MAPOS/Experimental values. Cross-checked against Wireshark's own
// arp_hrd/op_vals table in packet-arp.c. This table IS the structural gate (see arp.hpp's own
// "structural detection gate" paragraph) -- an OPER value not in this table causes try_parse_arp to
// decline the whole frame, so it is deliberately not padded out with speculative/unverified entries.
std::string op_name(uint16_t op) {
    switch (op) {
        case 1: return "ARP Request";
        case 2: return "ARP Reply";
        case 3: return "RARP Request";
        case 4: return "RARP Reply";
        case 5: return "DRARP Request";
        case 6: return "DRARP Reply";
        case 7: return "DRARP Error";
        case 8: return "InARP Request";
        case 9: return "InARP Reply";
        case 10: return "ARP NAK";
        case 11: return "MARS Request";
        case 12: return "MARS Multi";
        case 13: return "MARS MServ";
        case 14: return "MARS Join";
        case 15: return "MARS Leave";
        case 16: return "MARS NAK";
        case 17: return "MARS Unserv";
        case 18: return "MARS SJoin";
        case 19: return "MARS SLeave";
        case 20: return "MARS Grouplist Request";
        case 21: return "MARS Grouplist Reply";
        case 22: return "MARS Redirect Map";
        case 23: return "MAPOS UNARP";
        case 24: return "OP_EXP1 (Experimental)";
        case 25: return "OP_EXP2 (Experimental)";
        default: return "";
    }
}

std::string htype_name(uint16_t htype) {
    if (htype == 1) return "Ethernet";
    return "";
}

std::string ptype_name(uint16_t ptype) {
    if (ptype == 0x0800) return "IPv4";
    return "";
}

}  // namespace

std::optional<ArpMessage> try_parse_arp(ByteSpan eth_payload) {
    if (eth_payload.size() < kFixedHeaderLength) {
        return std::nullopt;
    }

    Cursor c(eth_payload);
    uint16_t htype = c.u16be();
    uint16_t ptype = c.u16be();
    uint8_t hlen = c.u8();
    uint8_t plen = c.u8();
    uint16_t oper = c.u16be();

    std::string oname = op_name(oper);
    if (oname.empty()) {
        // Not a recognized ARP operation -- this is this decoder's primary structural gate (see
        // arp.hpp's own "structural detection gate" paragraph). Declining here, rather than
        // guessing, is what keeps an arbitrary/non-ARP 0x0806 payload from being misclassified.
        return std::nullopt;
    }

    size_t trailer_len = static_cast<size_t>(hlen) * 2 + static_cast<size_t>(plen) * 2;
    if (c.remaining() < trailer_len) {
        return std::nullopt;
    }

    ArpMessage msg;
    msg.htype = htype;
    msg.htype_name = htype_name(htype);
    msg.ptype = ptype;
    msg.ptype_name = ptype_name(ptype);
    msg.hlen = hlen;
    msg.plen = plen;
    msg.oper = oper;
    msg.oper_name = oname;

    ByteSpan sha_span = eth_payload.subspan(kFixedHeaderLength, hlen);
    ByteSpan spa_span = eth_payload.subspan(kFixedHeaderLength + hlen, plen);
    ByteSpan tha_span = eth_payload.subspan(kFixedHeaderLength + hlen + plen, hlen);
    ByteSpan tpa_span = eth_payload.subspan(kFixedHeaderLength + 2 * hlen + plen, plen);

    msg.is_ethernet_ipv4 = (htype == 1 && hlen == 6 && ptype == 0x0800 && plen == 4);
    if (msg.is_ethernet_ipv4) {
        std::array<uint8_t, 6> sha{}, tha{};
        for (size_t i = 0; i < 6; ++i) {
            sha[i] = sha_span.at(i);
            tha[i] = tha_span.at(i);
        }
        msg.sha_mac = format_mac(sha);
        msg.tha_mac = format_mac(tha);

        uint32_t spa = (static_cast<uint32_t>(spa_span.at(0)) << 24) |
                       (static_cast<uint32_t>(spa_span.at(1)) << 16) |
                       (static_cast<uint32_t>(spa_span.at(2)) << 8) | spa_span.at(3);
        uint32_t tpa = (static_cast<uint32_t>(tpa_span.at(0)) << 24) |
                       (static_cast<uint32_t>(tpa_span.at(1)) << 16) |
                       (static_cast<uint32_t>(tpa_span.at(2)) << 8) | tpa_span.at(3);
        msg.spa_raw = spa;
        msg.tpa_raw = tpa;
        msg.spa_ip = format_ipv4(spa);
        msg.tpa_ip = format_ipv4(tpa);

        if ((oper == 1 || oper == 2) && spa == tpa) {
            msg.is_gratuitous = true;
            msg.notes.push_back(
                "Gratuitous ARP (sender and target protocol address match) -- the standard "
                "mechanism for announcing an IP-to-MAC relocation after failover, but also how "
                "duplicate-IP conditions and ARP cache poisoning attempts look on the wire; this "
                "decoder names the condition, it does not attempt cross-packet spoofing detection");
        }
        if (oper == 1 && spa == 0) {
            msg.is_probe = true;
            msg.notes.push_back(
                "ARP Probe (RFC 5227): sender protocol address is 0.0.0.0 -- a host checking "
                "whether another host already holds the target address before claiming it");
        }
        if (oper == 1 && spa == tpa) {
            msg.is_announcement = true;
            msg.notes.push_back(
                "ARP Announcement (RFC 5227): sender and target protocol address both name the "
                "newly-claimed address -- broadcast after a successful probe to update neighbors' "
                "ARP caches; wire-identical to a gratuitous ARP Request, hence both notes here");
        }
    } else {
        msg.sha_hex = to_hex(sha_span);
        msg.spa_hex = to_hex(spa_span);
        msg.tha_hex = to_hex(tha_span);
        msg.tpa_hex = to_hex(tpa_span);
    }

    std::ostringstream s;
    s << oname;
    if (msg.is_ethernet_ipv4) {
        if (oper == 1) {
            s << " -- who has " << msg.tpa_ip << "? tell " << msg.spa_ip << " (" << msg.sha_mac << ")";
        } else if (oper == 2) {
            s << " -- " << msg.spa_ip << " is at " << msg.sha_mac;
        } else {
            s << " sha=" << msg.sha_mac << " spa=" << msg.spa_ip << " tha=" << msg.tha_mac
              << " tpa=" << msg.tpa_ip;
        }
        if (msg.is_probe) s << " [probe]";
        if (msg.is_announcement) s << " [announcement]";
        else if (msg.is_gratuitous) s << " [gratuitous]";
    } else {
        s << " (htype=" << htype << (msg.htype_name.empty() ? "" : " (" + msg.htype_name + ")")
          << ", ptype=0x" << std::hex << ptype << std::dec
          << (msg.ptype_name.empty() ? "" : " (" + msg.ptype_name + ")") << ", hlen=" << (unsigned)hlen
          << ", plen=" << (unsigned)plen << ")";
    }
    msg.summary = s.str();

    return msg;
}

std::optional<ProtocolResult> ArpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_arp(payload)) {
        return ProtocolResult::make<ArpMessage>("arp", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& arp_decoder() {
    static const ArpDecoder instance;
    return instance;
}

}  // namespace conduitscope
