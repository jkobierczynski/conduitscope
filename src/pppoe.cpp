// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/pppoe.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// Discovery-stage Code values (RFC 2516 section 5) -- PADT (0xA7) is the one code shared with the
// Session stage (it tears a session down), so it's deliberately listed in both lookup tables below.
std::string pppoe_discovery_code_name(uint8_t c) {
    switch (c) {
        case 0x09: return "PADI";
        case 0x07: return "PADO";
        case 0x19: return "PADR";
        case 0x65: return "PADS";
        case 0xA7: return "PADT";
        default: return "";
    }
}

// IANA's "Point-to-Point Protocol (PPP) Protocol Field Assignments" registry -- a small curated
// subset, see pppoe.hpp's own file header comment. Anything else is still reported by its raw value.
std::string ppp_protocol_name(uint16_t p) {
    switch (p) {
        case 0x0021: return "IP";
        case 0x0057: return "IPv6";
        case 0x8021: return "IPCP";
        case 0x8057: return "IPv6CP";
        case 0xC021: return "LCP";
        case 0xC023: return "PAP";
        case 0xC025: return "LQR";
        case 0xC223: return "CHAP";
        case 0xC229: return "EAP";
        default: return "";
    }
}

}  // namespace

std::optional<PppoeFrame> try_parse_pppoe(ByteSpan eth_payload, bool is_session_ethertype) {
    if (eth_payload.size() < 6) return std::nullopt;

    uint8_t byte0 = eth_payload.at(0);
    uint8_t version = (byte0 >> 4) & 0x0F;
    uint8_t type = byte0 & 0x0F;
    if (version != 1 || type != 1) return std::nullopt;

    uint8_t code = eth_payload.at(1);
    uint16_t session_id = static_cast<uint16_t>((eth_payload.at(2) << 8) | eth_payload.at(3));
    uint16_t length = static_cast<uint16_t>((eth_payload.at(4) << 8) | eth_payload.at(5));

    PppoeFrame f;
    f.version = version;
    f.type = type;
    f.code = code;
    f.session_id = session_id;
    f.length = length;
    f.is_session = is_session_ethertype;

    if (is_session_ethertype) {
        // Session stage -- Code is always 0x00 ("Session Data") per RFC 2516 section 4.3, except
        // for a mid-session PADT (0xA7) tearing the session down early. Anything else doesn't match
        // this stage's own Code space -- not a confident PPPoE match (see file header comment).
        if (code == 0x00) {
            f.code_name = "Session Data";
        } else if (code == 0xA7) {
            f.code_name = "PADT";
        } else {
            return std::nullopt;
        }
    } else {
        // Discovery stage -- Code must be one of the five defined values.
        std::string dname = pppoe_discovery_code_name(code);
        if (dname.empty()) return std::nullopt;
        f.code_name = dname;
    }

    std::ostringstream s;
    s << "PPPoE " << f.code_name << " (session=0x" << std::hex << session_id << std::dec << ")";

    if (is_session_ethertype && code == 0x00) {
        ByteSpan body = eth_payload.from(6);
        if (body.size() >= 2) {
            uint16_t protocol = static_cast<uint16_t>((body.at(0) << 8) | body.at(1));
            f.has_ppp_protocol = true;
            f.ppp_protocol = protocol;
            f.ppp_protocol_name = ppp_protocol_name(protocol);
            if (!f.ppp_protocol_name.empty()) {
                s << " -- PPP " << f.ppp_protocol_name;
            } else {
                s << " -- PPP protocol 0x" << std::hex << protocol << std::dec << " (unrecognized)";
            }
            if (protocol == 0xC023) {
                f.notes.push_back("PAP (Password Authentication Protocol) observed -- RFC 1334's "
                                   "Authenticate-Request carries the username/password pair in "
                                   "cleartext; this decoder does not inspect the credential itself");
            }
        }
    }

    f.summary = s.str();
    return f;
}

std::optional<ProtocolResult> PppoeDiscoveryDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto pp = try_parse_pppoe(payload, /*is_session_ethertype=*/false)) {
        return ProtocolResult::make<PppoeFrame>("pppoe", std::move(*pp));
    }
    return std::nullopt;
}

std::optional<ProtocolResult> PppoeSessionDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto pp = try_parse_pppoe(payload, /*is_session_ethertype=*/true)) {
        return ProtocolResult::make<PppoeFrame>("pppoe", std::move(*pp));
    }
    return std::nullopt;
}

const ProtocolDecoder& pppoe_discovery_decoder() {
    static const PppoeDiscoveryDecoder instance;
    return instance;
}

const ProtocolDecoder& pppoe_session_decoder() {
    static const PppoeSessionDecoder instance;
    return instance;
}

}  // namespace conduitscope
