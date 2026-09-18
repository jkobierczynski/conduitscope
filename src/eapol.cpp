// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/eapol.hpp"

#include <sstream>

namespace conduitscope {

namespace {

std::string eapol_version_name(uint8_t v) {
    switch (v) {
        case 1: return "802.1X-2001";
        case 2: return "802.1X-2004";
        case 3: return "802.1X-2010";
        default: return "";
    }
}

std::string eapol_type_name(uint8_t t) {
    switch (t) {
        case 0: return "EAP-Packet";
        case 1: return "EAPOL-Start";
        case 2: return "EAPOL-Logoff";
        case 3: return "EAPOL-Key";
        case 4: return "EAPOL-Encapsulated-ASF-Alert";
        case 5: return "EAPOL-MKA";
        case 6: return "EAPOL-Announcement (Generic)";
        case 7: return "EAPOL-Announcement (Specific)";
        case 8: return "EAPOL-Announcement-Req";
        default: return "";
    }
}

std::string eap_code_name(uint8_t c) {
    switch (c) {
        case 1: return "Request";
        case 2: return "Response";
        case 3: return "Success";
        case 4: return "Failure";
        default: return "";
    }
}

// A small curated subset of IANA's EAP Method Type registry -- see eapol.hpp's own file header
// comment for the full sourcing note. Anything not in this set is still reported by its raw value.
std::string eap_type_name(uint8_t t) {
    switch (t) {
        case 1: return "Identity";
        case 2: return "Notification";
        case 3: return "Nak";
        case 4: return "MD5-Challenge";
        case 6: return "Generic Token Card (GTC)";
        case 13: return "EAP-TLS";
        case 21: return "EAP-TTLS";
        case 25: return "PEAP";
        case 26: return "MS-EAP-Authentication (EAP-MSCHAPv2)";
        case 43: return "EAP-FAST";
        case 50: return "Expanded Types";
        default: return "";
    }
}

std::string eapol_key_descriptor_type_name(uint8_t d) {
    switch (d) {
        case 1: return "RC4 Key Descriptor (legacy)";
        case 2: return "IEEE 802.11 Key Descriptor (RSN/WPA2)";
        case 254: return "WPA Key Descriptor (pre-RSN)";
        default: return "";
    }
}

}  // namespace

std::optional<EapolFrame> try_parse_eapol(ByteSpan eth_payload) {
    if (eth_payload.size() < 4) return std::nullopt;

    uint8_t version = eth_payload.at(0);
    std::string vname = eapol_version_name(version);
    if (vname.empty()) return std::nullopt;

    uint8_t type = eth_payload.at(1);
    std::string tname = eapol_type_name(type);
    if (tname.empty()) return std::nullopt;

    uint16_t length = static_cast<uint16_t>((eth_payload.at(2) << 8) | eth_payload.at(3));

    EapolFrame f;
    f.version = version;
    f.version_name = vname;
    f.type = type;
    f.type_name = tname;
    f.length = length;

    ByteSpan body = eth_payload.from(4);
    if (length > body.size()) {
        f.notes.push_back("EAPOL header declares a " + std::to_string(length) +
                           "-byte body but only " + std::to_string(body.size()) +
                           " byte(s) are available -- truncated");
    }

    std::ostringstream s;
    s << "EAPOL v" << static_cast<unsigned>(version) << " (" << vname << ") " << tname;

    if (type == 0 && body.size() >= 4) {
        uint8_t code = body.at(0);
        std::string cname = eap_code_name(code);
        if (!cname.empty()) {
            f.has_eap = true;
            f.eap_code = code;
            f.eap_code_name = cname;
            f.eap_identifier = body.at(1);
            f.eap_declared_length = static_cast<uint16_t>((body.at(2) << 8) | body.at(3));

            s << " -- EAP " << cname << " id=" << static_cast<unsigned>(f.eap_identifier);

            if ((code == 1 || code == 2) && body.size() >= 5) {
                uint8_t eap_type = body.at(4);
                std::string etname = eap_type_name(eap_type);
                f.has_eap_type = true;
                f.eap_type = eap_type;
                f.eap_type_name = etname;
                if (!etname.empty()) {
                    s << ", type=" << etname;
                } else {
                    s << ", type=" << static_cast<unsigned>(eap_type) << " (unrecognized)";
                }
            }
        } else {
            s << " -- EAP code " << static_cast<unsigned>(code) << " (unrecognized)";
        }
    } else if (type == 3 && !body.empty()) {
        uint8_t descriptor = body.at(0);
        std::string dname = eapol_key_descriptor_type_name(descriptor);
        f.has_eapol_key_descriptor = true;
        f.eapol_key_descriptor_type = descriptor;
        f.eapol_key_descriptor_type_name = dname;
        if (!dname.empty()) {
            s << " -- " << dname << " descriptor";
        } else {
            s << " -- descriptor type " << static_cast<unsigned>(descriptor) << " (unrecognized)";
        }
    } else {
        s << " (length=" << length << ")";
    }

    f.summary = s.str();
    return f;
}

}  // namespace conduitscope
