// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/vrrp.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxAddresses = resource_limits().max_decoded_objects.value_or(50);

std::string auth_type_name(uint8_t auth_type) {
    switch (auth_type) {
        case 0: return "No Authentication";
        case 1: return "Simple Text Password";
        case 2: return "IP Authentication Header";
        case 254: return "Cisco MD5 (non-standard)";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(auth_type)) + ")";
    }
}

std::string priority_meaning(uint8_t priority) {
    if (priority == 0) return "current master is stopping";
    if (priority == 255) return "address owner";
    return "backup";
}

std::string strip_trailing_nul(ByteSpan span) {
    size_t len = span.size();
    while (len > 0 && span.at(len - 1) == 0) --len;
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) out.push_back(static_cast<char>(span.at(i)));
    return out;
}

}  // namespace

std::optional<VrrpMessage> try_parse_vrrp(ByteSpan ip_payload) {
    if (ip_payload.size() < 8) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    uint8_t version_type = c.u8();
    uint8_t version = (version_type >> 4) & 0x0F;
    uint8_t type = version_type & 0x0F;
    if (version != 2 && version != 3) {
        return std::nullopt;
    }
    if (type != 1) {
        return std::nullopt;
    }

    VrrpMessage msg;
    msg.version = version;
    msg.type = type;
    msg.type_name = "Advertisement";
    msg.virtual_router_id = c.u8();
    msg.priority = c.u8();
    msg.priority_meaning = priority_meaning(msg.priority);
    msg.address_count = c.u8();

    if (version == 2) {
        msg.auth_type = c.u8();
        msg.auth_type_name = auth_type_name(msg.auth_type);
        msg.advertisement_interval_sec = c.u8();
        msg.checksum = c.u16be();
    } else {
        uint16_t reserved_interval = c.u16be();
        msg.advertisement_interval_centisec = reserved_interval & 0x0FFF;
        msg.checksum = c.u16be();
    }

    size_t decoded = std::min(static_cast<size_t>(msg.address_count), kMaxAddresses);
    for (size_t i = 0; i < decoded && c.remaining() >= 4; ++i) {
        msg.ip_addresses.push_back(format_ipv4(c.u32be()));
    }
    if (static_cast<size_t>(msg.address_count) > kMaxAddresses) {
        msg.ip_addresses_truncated = true;
        msg.notes.push_back("output capped at " + std::to_string(kMaxAddresses) +
                             " virtual IP address(es); " +
                             std::to_string(msg.address_count - kMaxAddresses) +
                             " more were declared in this packet and were not decoded");
    } else if (msg.ip_addresses.size() < msg.address_count) {
        msg.notes.push_back("Count field (" + std::to_string(msg.address_count) +
                             ") exceeds the virtual IP addresses actually present -- possible "
                             "truncation");
    }

    if (version == 2) {
        if (c.remaining() >= 8) {
            ByteSpan auth_data = c.bytes(8);
            if (msg.auth_type == 1) {
                msg.auth_simple_password = strip_trailing_nul(auth_data);
                msg.notes.push_back(
                    "VRRPv2 Simple Text Password authentication (auth_type 1) sends this "
                    "password in cleartext on the wire -- see vrrp.hpp's own Security context "
                    "note");
            }
        } else if (msg.auth_type == 1) {
            msg.notes.push_back("auth_type declares Simple Text Password but the 8-byte "
                                 "Authentication Data field is truncated");
        }
    }

    std::ostringstream out;
    out << "VRRPv" << static_cast<unsigned>(version) << " Advertisement: VRID "
        << static_cast<unsigned>(msg.virtual_router_id) << ", priority "
        << static_cast<unsigned>(msg.priority) << " (" << msg.priority_meaning << "), "
        << msg.ip_addresses.size() << " virtual IP(s)";
    if (!msg.ip_addresses.empty()) {
        out << " (" << msg.ip_addresses.front();
        if (msg.ip_addresses.size() > 1) out << ", ...";
        out << ")";
    }
    msg.summary = out.str();

    return msg;
}

}  // namespace conduitscope
