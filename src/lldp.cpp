// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/lldp.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the literal
// 50 default (same convention as every other repeated-element cap in this codebase).
const size_t kMaxTlvs = resource_limits().max_decoded_objects.value_or(50);

constexpr uint8_t kTlvEnd = 0;
constexpr uint8_t kTlvChassisId = 1;
constexpr uint8_t kTlvPortId = 2;
constexpr uint8_t kTlvTtl = 3;
constexpr uint8_t kTlvPortDescription = 4;
constexpr uint8_t kTlvSystemName = 5;
constexpr uint8_t kTlvSystemDescription = 6;
constexpr uint8_t kTlvSystemCapabilities = 7;
constexpr uint8_t kTlvManagementAddress = 8;
constexpr uint8_t kTlvOrgSpecific = 127;

std::string tlv_type_name(uint8_t type) {
    switch (type) {
        case kTlvEnd: return "End of LLDPDU";
        case kTlvChassisId: return "Chassis ID";
        case kTlvPortId: return "Port ID";
        case kTlvTtl: return "Time To Live";
        case kTlvPortDescription: return "Port Description";
        case kTlvSystemName: return "System Name";
        case kTlvSystemDescription: return "System Description";
        case kTlvSystemCapabilities: return "System Capabilities";
        case kTlvManagementAddress: return "Management Address";
        case kTlvOrgSpecific: return "Organizationally Specific";
        default: return "";
    }
}

// See lldp.hpp's own subtype-table comment: this table and port_id_subtype_name below are
// deliberately NOT shared, even though several numeric values look tempting to unify -- they are
// genuinely different tables per IEEE 802.1AB.
std::string chassis_id_subtype_name(uint8_t subtype) {
    switch (subtype) {
        case 1: return "Chassis component";
        case 2: return "Interface alias";
        case 3: return "Port component";
        case 4: return "MAC address";
        case 5: return "Network address";
        case 6: return "Interface name";
        case 7: return "Locally assigned";
        default: return "";
    }
}

std::string port_id_subtype_name(uint8_t subtype) {
    switch (subtype) {
        case 1: return "Interface alias";
        case 2: return "Port component";
        case 3: return "MAC address";
        case 4: return "Network address";
        case 5: return "Interface name";
        case 6: return "Agent circuit ID";
        case 7: return "Locally assigned";
        default: return "";
    }
}

std::string org_oui_name(uint8_t a, uint8_t b, uint8_t c) {
    if (a == 0x00 && b == 0x80 && c == 0xC2) return "IEEE 802.1";
    if (a == 0x00 && b == 0x12 && c == 0x0F) return "IEEE 802.3";
    if (a == 0x00 && b == 0x12 && c == 0xBB) return "TIA-1057/LLDP-MED";
    if (a == 0x00 && b == 0x0E && c == 0xCF) return "PROFINET";
    return "";
}

// Renders a "MAC address" or "Network address" subtype value common to both Chassis ID and Port ID
// -- the one piece of rendering logic that IS shared, since the wire format (not the meaning) is
// identical for these two subtype kinds regardless of which field they appear in. Falls back to raw
// hex whenever the bytes don't actually fit the expected shape rather than guessing.
std::string render_mac_or_network_address(ByteSpan value, bool is_mac_subtype) {
    if (is_mac_subtype) {
        if (value.size() == 6) {
            std::array<uint8_t, 6> mac{};
            for (size_t i = 0; i < 6; ++i) mac[i] = value.at(i);
            return format_mac(mac);
        }
        return "0x" + to_hex(value, "");
    }
    // Network address: 1 address-family byte + address bytes.
    if (value.size() == 5 && value.at(0) == 1) {  // IANA AFN 1 == IPv4
        uint32_t addr = (static_cast<uint32_t>(value.at(1)) << 24) |
                         (static_cast<uint32_t>(value.at(2)) << 16) |
                         (static_cast<uint32_t>(value.at(3)) << 8) | value.at(4);
        return format_ipv4(addr);
    }
    return "0x" + to_hex(value, "");
}

// Renders a Chassis ID or Port ID value given its own subtype table's name (the caller already
// looked the subtype up in the correct one of the two non-parallel tables -- see lldp.hpp).
std::string render_id_value(const std::string& subtype_name, ByteSpan value) {
    if (subtype_name == "MAC address") return render_mac_or_network_address(value, true);
    if (subtype_name == "Network address") return render_mac_or_network_address(value, false);
    if (subtype_name.empty()) return "0x" + to_hex(value, "");
    // Interface alias / Port component / Interface name / Locally assigned / Chassis component /
    // Agent circuit ID: the remaining bytes cast directly to a string -- matches this codebase's
    // existing convention for a protocol-declared-ASCII field (see profinet.cpp's own
    // NameOfStation handling), no further sanitization.
    std::string text;
    text.reserve(value.size());
    for (size_t i = 0; i < value.size(); ++i) text += static_cast<char>(value.at(i));
    return text;
}

std::string capability_bit_name(int bit) {
    switch (bit) {
        case 0: return "Other";
        case 1: return "Repeater";
        case 2: return "MAC Bridge";
        case 3: return "WLAN Access Point";
        case 4: return "Router";
        case 5: return "Telephone";
        case 6: return "DOCSIS Cable Device";
        case 7: return "Station Only";
        case 8: return "C-VLAN Component";
        case 9: return "S-VLAN Component";
        case 10: return "Two-Port MAC Relay";
        default: return "";
    }
}

std::vector<std::string> capability_names(uint16_t bitmap) {
    std::vector<std::string> names;
    for (int bit = 0; bit < 16; ++bit) {
        if ((bitmap & (1u << bit)) == 0) continue;
        std::string name = capability_bit_name(bit);
        names.push_back(name.empty() ? ("bit " + std::to_string(bit)) : name);
    }
    return names;
}

std::string join(const std::vector<std::string>& items) {
    std::ostringstream s;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i != 0) s << ", ";
        s << items[i];
    }
    return s.str();
}

}  // namespace

std::optional<LldpMessage> try_parse_lldp(ByteSpan eth_payload) {
    // The structural detection gate: the first three TLVs MUST be Chassis ID, Port ID, then a
    // 2-byte TTL, in that exact order -- see this file's own header comment. Read them by hand here
    // (rather than folding them into the generic loop below) so a mismatch can decline immediately.
    // Deliberately uses ONE Cursor over the whole `eth_payload` from start to finish (never rebased
    // via ByteSpan::from) so `c.position()` stays an absolute offset into `eth_payload` throughout --
    // Cursor::position() is relative to whatever span it was constructed over, so reassigning it to
    // a Cursor over an already-advanced sub-span (`eth_payload.from(n)`) would silently reset
    // position() back to 0 at that sub-span's own start, corrupting every subspan() computed against
    // the ORIGINAL `eth_payload` afterward. (Caught during this decoder's own manual verification --
    // worth this explicit comment so it isn't reintroduced.)
    Cursor c(eth_payload);
    if (c.remaining() < 2) return std::nullopt;
    uint16_t h0 = c.u16be();
    uint8_t t0 = static_cast<uint8_t>(h0 >> 9);
    uint16_t l0 = h0 & 0x01FF;
    if (t0 != kTlvChassisId || l0 < 1 || c.remaining() < l0) return std::nullopt;
    ByteSpan chassis_full_value = eth_payload.subspan(c.position(), l0);
    uint8_t chassis_subtype = chassis_full_value.at(0);
    ByteSpan chassis_value = chassis_full_value.from(1);
    for (size_t i = 0; i < l0; ++i) c.u8();  // advance past the value we just read via subspan

    if (c.remaining() < 2) return std::nullopt;
    uint16_t h1 = c.u16be();
    uint8_t t1 = static_cast<uint8_t>(h1 >> 9);
    uint16_t l1 = h1 & 0x01FF;
    if (t1 != kTlvPortId || l1 < 1 || c.remaining() < l1) return std::nullopt;
    ByteSpan port_full_value = eth_payload.subspan(c.position(), l1);
    uint8_t port_subtype = port_full_value.at(0);
    ByteSpan port_value = port_full_value.from(1);
    for (size_t i = 0; i < l1; ++i) c.u8();

    if (c.remaining() < 2) return std::nullopt;
    uint16_t h2 = c.u16be();
    uint8_t t2 = static_cast<uint8_t>(h2 >> 9);
    uint16_t l2 = h2 & 0x01FF;
    if (t2 != kTlvTtl || l2 != 2 || c.remaining() < l2) return std::nullopt;
    uint16_t ttl = c.u16be();

    // Gate passed -- this is confidently LLDP. Build the message, then re-walk every TLV (including
    // these first three, re-parsed from the front) through one shared loop so `tlvs` reflects the
    // whole PDU uniformly and every optional TLV type gets handled in one place.
    LldpMessage msg;
    msg.chassis_id_subtype = chassis_subtype;
    msg.chassis_id_subtype_name = chassis_id_subtype_name(chassis_subtype);
    msg.chassis_id_value = render_id_value(msg.chassis_id_subtype_name, chassis_value);
    msg.port_id_subtype = port_subtype;
    msg.port_id_subtype_name = port_id_subtype_name(port_subtype);
    msg.port_id_value = render_id_value(msg.port_id_subtype_name, port_value);
    msg.ttl_seconds = ttl;
    if (ttl == 0) {
        msg.notes.push_back(
            "TTL is 0 -- this is LLDP's own \"shutting down\" signal, telling neighbors to "
            "immediately invalidate this device's previously-advertised information");
    }

    // Same "one Cursor over the whole span, never rebased" discipline as the gate-check above --
    // see that block's comment for why rebasing via ByteSpan::from would corrupt position().
    Cursor walk(eth_payload);
    size_t decoded = 0;
    bool saw_end = false;
    while (walk.remaining() >= 2 && decoded < kMaxTlvs) {
        size_t tlv_start = walk.position();
        uint16_t header = walk.u16be();
        uint8_t type = static_cast<uint8_t>(header >> 9);
        uint16_t length = header & 0x01FF;
        if (walk.remaining() < length) {
            msg.tlvs_truncated = true;
            msg.notes.push_back(
                "a TLV at byte offset " + std::to_string(tlv_start) + " declares a " +
                std::to_string(length) + "-byte value but only " + std::to_string(walk.remaining()) +
                " byte(s) remain -- stopped decoding further TLVs");
            break;
        }
        ByteSpan value = eth_payload.subspan(walk.position(), length);
        for (size_t i = 0; i < length; ++i) walk.u8();
        ++decoded;

        LldpTlv tlv;
        tlv.type = type;
        tlv.type_name = tlv_type_name(type);
        tlv.length = length;

        if (type == kTlvEnd) {
            tlv.rendered = "";
            msg.tlvs.push_back(tlv);
            saw_end = true;
            break;
        } else if (type == kTlvChassisId) {
            tlv.rendered = msg.chassis_id_value;
        } else if (type == kTlvPortId) {
            tlv.rendered = msg.port_id_value;
        } else if (type == kTlvTtl) {
            tlv.rendered = std::to_string(ttl) + "s";
        } else if (type == kTlvPortDescription) {
            std::string text;
            text.reserve(value.size());
            for (size_t i = 0; i < value.size(); ++i) text += static_cast<char>(value.at(i));
            msg.has_port_description = true;
            msg.port_description = text;
            tlv.rendered = text;
        } else if (type == kTlvSystemName) {
            std::string text;
            text.reserve(value.size());
            for (size_t i = 0; i < value.size(); ++i) text += static_cast<char>(value.at(i));
            msg.has_system_name = true;
            msg.system_name = text;
            tlv.rendered = text;
        } else if (type == kTlvSystemDescription) {
            std::string text;
            text.reserve(value.size());
            for (size_t i = 0; i < value.size(); ++i) text += static_cast<char>(value.at(i));
            msg.has_system_description = true;
            msg.system_description = text;
            tlv.rendered = text;
        } else if (type == kTlvSystemCapabilities && value.size() == 4) {
            Cursor vc(value);
            uint16_t caps = vc.u16be();
            uint16_t enabled = vc.u16be();
            msg.has_system_capabilities = true;
            msg.system_capabilities = caps;
            msg.enabled_capabilities = enabled;
            msg.system_capabilities_names = capability_names(caps);
            msg.enabled_capabilities_names = capability_names(enabled);
            tlv.rendered = "capable=[" + join(msg.system_capabilities_names) + "] enabled=[" +
                            join(msg.enabled_capabilities_names) + "]";
        } else if (type == kTlvManagementAddress && value.size() >= 1) {
            Cursor vc(value);
            uint8_t addr_str_len = vc.u8();  // Address Subtype + Address byte count
            if (addr_str_len >= 1 && vc.remaining() >= static_cast<size_t>(addr_str_len)) {
                uint8_t addr_subtype = vc.u8();
                ByteSpan addr = value.subspan(vc.position(), addr_str_len - 1);
                std::string rendered_addr;
                std::string subtype_name;
                if (addr_subtype == 1 && addr.size() == 4) {
                    subtype_name = "IPv4";
                    rendered_addr = format_ipv4((static_cast<uint32_t>(addr.at(0)) << 24) |
                                                 (static_cast<uint32_t>(addr.at(1)) << 16) |
                                                 (static_cast<uint32_t>(addr.at(2)) << 8) | addr.at(3));
                } else if (addr_subtype == 2) {
                    subtype_name = "IPv6";
                    rendered_addr = "0x" + to_hex(addr, "");
                } else if (addr_subtype == 6) {
                    subtype_name = "802/MAC";
                    rendered_addr = "0x" + to_hex(addr, "");
                } else {
                    rendered_addr = "0x" + to_hex(addr, "");
                }
                if (!msg.has_management_address) {
                    msg.has_management_address = true;
                    msg.management_address_subtype = addr_subtype;
                    msg.management_address_subtype_name = subtype_name;
                    msg.management_address = rendered_addr;
                }
                tlv.rendered = (subtype_name.empty() ? "subtype " + std::to_string(addr_subtype)
                                                      : subtype_name) +
                                " " + rendered_addr;
            } else {
                tlv.raw_hex = "0x" + to_hex(value, "");
            }
        } else if (type == kTlvOrgSpecific && value.size() >= 4) {
            uint8_t a = value.at(0), b = value.at(1), cc = value.at(2), subtype = value.at(3);
            std::string oui = org_oui_name(a, b, cc);
            std::ostringstream r;
            r << "OUI=" << (oui.empty() ? "0x" + to_hex(value.subspan(0, 3), "") : oui)
              << " subtype=" << static_cast<unsigned>(subtype);
            if (value.size() > 4) r << " data=0x" << to_hex(value.subspan(4, value.size() - 4), "");
            tlv.rendered = r.str();
        } else {
            tlv.raw_hex = "0x" + to_hex(value, "");
        }

        msg.tlvs.push_back(tlv);
    }
    if (decoded >= kMaxTlvs && !saw_end) {
        msg.tlvs_truncated = true;
        msg.notes.push_back("output capped at " + std::to_string(kMaxTlvs) +
                             " TLV(s); this PDU may declare more");
    }

    std::ostringstream s;
    s << "LLDP chassis=" << msg.chassis_id_value << " port=" << msg.port_id_value
      << " ttl=" << ttl << "s";
    if (msg.has_system_name) s << " name=\"" << msg.system_name << "\"";
    msg.summary = s.str();

    return msg;
}

std::optional<ProtocolResult> LldpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_lldp(payload)) {
        return ProtocolResult::make<LldpMessage>("lldp", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& lldp_decoder() {
    static const LldpDecoder instance;
    return instance;
}

}  // namespace conduitscope
