// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/cdp.hpp"

#include <iomanip>
#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the literal
// 50 default (same convention every other repeated-element cap in this codebase uses, e.g. LldpTlv's
// own kMaxTlvs, lldp.cpp).
size_t max_decoded_objects() { return resource_limits().max_decoded_objects.value_or(50); }

constexpr uint16_t kTlvDeviceId = 0x0001;
constexpr uint16_t kTlvAddresses = 0x0002;
constexpr uint16_t kTlvPortId = 0x0003;
constexpr uint16_t kTlvCapabilities = 0x0004;
constexpr uint16_t kTlvSoftwareVersion = 0x0005;
constexpr uint16_t kTlvPlatform = 0x0006;
constexpr uint16_t kTlvIpPrefix = 0x0007;
constexpr uint16_t kTlvProtocolHello = 0x0008;
constexpr uint16_t kTlvVtpManagementDomain = 0x0009;
constexpr uint16_t kTlvNativeVlan = 0x000A;
constexpr uint16_t kTlvDuplex = 0x000B;
constexpr uint16_t kTlvVoipVlanReply = 0x000E;
constexpr uint16_t kTlvVoipVlanQuery = 0x000F;
constexpr uint16_t kTlvPowerConsumption = 0x0010;
constexpr uint16_t kTlvMtu = 0x0011;
constexpr uint16_t kTlvTrustBitmap = 0x0012;
constexpr uint16_t kTlvUntrustedPortCos = 0x0013;
constexpr uint16_t kTlvSystemName = 0x0014;
constexpr uint16_t kTlvSystemObjectId = 0x0015;
constexpr uint16_t kTlvManagementAddress = 0x0016;
constexpr uint16_t kTlvLocation = 0x0017;
constexpr uint16_t kTlvExternalPortId = 0x0018;
constexpr uint16_t kTlvPowerRequested = 0x0019;
constexpr uint16_t kTlvPowerAvailable = 0x001A;
constexpr uint16_t kTlvPortUnidirectional = 0x001B;
constexpr uint16_t kTlvEnergyWise = 0x001D;
constexpr uint16_t kTlvSparePoe = 0x001F;

// See cdp.hpp's own "ADDRESS TLV STRUCTURE" header comment -- ISO/IEC TR 9577's registered NLPID for
// IP, confirmed as CDP's own IPv4 convention against a live wiki.wireshark.org worked example.
constexpr uint8_t kNlpidIp = 0xCC;

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string tlv_type_name(uint16_t type) {
    switch (type) {
        case kTlvDeviceId: return "Device ID";
        case kTlvAddresses: return "Addresses";
        case kTlvPortId: return "Port ID";
        case kTlvCapabilities: return "Capabilities";
        case kTlvSoftwareVersion: return "Software Version";
        case kTlvPlatform: return "Platform";
        case kTlvIpPrefix: return "IP Prefix / ODR";
        case kTlvProtocolHello: return "Protocol Hello";
        case kTlvVtpManagementDomain: return "VTP Management Domain";
        case kTlvNativeVlan: return "Native VLAN";
        case kTlvDuplex: return "Duplex";
        case kTlvVoipVlanReply: return "VoIP VLAN Reply";
        case kTlvVoipVlanQuery: return "VoIP VLAN Query";
        case kTlvPowerConsumption: return "Power Consumption";
        case kTlvMtu: return "MTU";
        case kTlvTrustBitmap: return "Trust Bitmap";
        case kTlvUntrustedPortCos: return "Untrusted Port CoS";
        case kTlvSystemName: return "System Name";
        case kTlvSystemObjectId: return "System Object ID";
        case kTlvManagementAddress: return "Management Address";
        case kTlvLocation: return "Location";
        case kTlvExternalPortId: return "External Port ID";
        case kTlvPowerRequested: return "Power Requested";
        case kTlvPowerAvailable: return "Power Available";
        case kTlvPortUnidirectional: return "Port Unidirectional";
        case kTlvEnergyWise: return "EnergyWise";
        case kTlvSparePoe: return "Spare PoE";
        default:
            if (type >= 0x1000 && type <= 0x100D) return "HP-proprietary extension";
            return "";
    }
}

// One capability bit -- see cdp.hpp's own "CAPABILITIES" header comment for the full sourcing.
std::string capability_bit_name(int bit) {
    switch (bit) {
        case 0: return "Router";
        case 1: return "Transparent Bridge";
        case 2: return "Source-Route Bridge";
        case 3: return "Switch";
        case 4: return "Host";
        case 5: return "IGMP capable";
        case 6: return "Repeater";
        case 7: return "VoIP Phone";
        case 8: return "Remotely-Managed Device";
        case 9: return "CVTA / Supports-STP-Dispute";
        case 10: return "Two-Port MAC Relay";
        default: return "";
    }
}

std::vector<std::string> capability_names(uint32_t bitmap) {
    std::vector<std::string> names;
    for (int bit = 0; bit < 32; ++bit) {
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

// Byte buffer to a plain string, no charset validation -- this codebase's usual convention for a
// protocol-declared text field (see lldp.cpp's own identical inline pattern, e.g. for System Name).
std::string bytes_to_string(ByteSpan s) {
    std::string text;
    text.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) text += static_cast<char>(s.at(i));
    return text;
}

// Decodes one Addresses/Management-Address-shaped value (Number of Addresses + repeated entries) --
// see cdp.hpp's own "ADDRESS TLV STRUCTURE" header comment. Tolerant of truncation: stops (without
// throwing) at whichever entry doesn't fully fit, same posture as the outer TLV walk.
std::vector<CdpAddress> parse_addresses(ByteSpan value) {
    std::vector<CdpAddress> out;
    if (value.size() < 4) return out;
    Cursor c(value);
    uint32_t count = c.u32be();
    size_t cap = max_decoded_objects();
    for (uint32_t i = 0; i < count && out.size() < cap; ++i) {
        if (c.remaining() < 2) break;  // Protocol Type + Protocol Length
        uint8_t protocol_type = c.u8();
        uint8_t protocol_length = c.u8();
        if (c.remaining() < protocol_length) break;
        ByteSpan protocol_bytes = c.bytes(protocol_length);
        if (c.remaining() < 2) break;
        uint16_t address_length = c.u16be();
        if (c.remaining() < address_length) break;
        ByteSpan address_bytes = c.bytes(address_length);

        CdpAddress addr;
        addr.protocol_type = protocol_type;
        addr.protocol_type_name = protocol_type == 1   ? "NLPID"
                                   : protocol_type == 2 ? "802.2"
                                                          : ("unknown(" + std::to_string(protocol_type) + ")");
        addr.protocol_length = protocol_length;
        addr.protocol_bytes = protocol_bytes.to_vector();
        addr.address_length = address_length;

        bool is_ip = protocol_type == 1 && protocol_length == 1 && !addr.protocol_bytes.empty() &&
                     addr.protocol_bytes[0] == kNlpidIp && address_length == 4;
        addr.is_ipv4 = is_ip;
        if (is_ip) {
            uint32_t ip = (static_cast<uint32_t>(address_bytes.at(0)) << 24) |
                          (static_cast<uint32_t>(address_bytes.at(1)) << 16) |
                          (static_cast<uint32_t>(address_bytes.at(2)) << 8) | address_bytes.at(3);
            addr.protocol_name = "IP";
            addr.address_rendered = format_ipv4(ip);
        } else {
            addr.protocol_name = protocol_type == 1 && protocol_length == 1 && !addr.protocol_bytes.empty()
                                      ? ("NLPID 0x" + to_hex(protocol_bytes, ""))
                                      : addr.protocol_type_name;
            addr.address_rendered = "0x" + to_hex(address_bytes, "");
        }
        out.push_back(std::move(addr));
    }
    return out;
}

std::string render_address_list(const std::vector<CdpAddress>& addrs) {
    std::vector<std::string> parts;
    for (const auto& a : addrs) parts.push_back(a.protocol_name + " " + a.address_rendered);
    return join(parts);
}

}  // namespace

std::optional<CdpFrame> try_parse_cdp(ByteSpan llc_payload) {
    if (llc_payload.size() < 4) return std::nullopt;

    CdpFrame f;
    try {
        Cursor c(llc_payload);
        f.version = c.u8();
        f.ttl_seconds = c.u8();
        f.checksum = c.u16be();  // never validated -- see cdp.hpp's own "CHECKSUM" header comment

        if (f.version != 1 && f.version != 2) {
            f.notes.push_back("unusual CDP Version byte (" + std::to_string(static_cast<unsigned>(f.version)) +
                               ") -- neither 1 (CDPv1) nor 2 (CDPv2); decoding whatever TLVs follow anyway "
                               "(see cdp.hpp)");
        }

        size_t cap = max_decoded_objects();
        while (c.remaining() >= 4 && f.tlvs.size() < cap) {
            size_t tlv_start = c.position();
            uint16_t type = c.u16be();
            uint16_t length = c.u16be();
            if (length < 4) {
                f.tlvs_truncated = true;
                f.notes.push_back("a TLV at byte offset " + std::to_string(tlv_start) +
                                   " declares an implausible Length (" + std::to_string(length) +
                                   ", less than the 4-byte header it must include) -- stopped decoding "
                                   "further TLVs");
                break;
            }
            size_t value_len = static_cast<size_t>(length) - 4;
            if (c.remaining() < value_len) {
                f.tlvs_truncated = true;
                f.notes.push_back("a TLV at byte offset " + std::to_string(tlv_start) + " declares a " +
                                   std::to_string(value_len) + "-byte value but only " +
                                   std::to_string(c.remaining()) + " byte(s) remain -- stopped decoding "
                                   "further TLVs");
                break;
            }
            ByteSpan value = c.bytes(value_len);

            CdpTlv tlv;
            tlv.type = type;
            tlv.type_name = tlv_type_name(type);
            tlv.length = length;

            if (type == kTlvDeviceId) {
                f.has_device_id = true;
                f.device_id = bytes_to_string(value);
                tlv.rendered = f.device_id;
            } else if (type == kTlvPortId) {
                f.has_port_id = true;
                f.port_id = bytes_to_string(value);
                tlv.rendered = f.port_id;
            } else if (type == kTlvPlatform) {
                f.has_platform = true;
                f.platform = bytes_to_string(value);
                tlv.rendered = f.platform;
            } else if (type == kTlvSoftwareVersion) {
                f.has_software_version = true;
                f.software_version = bytes_to_string(value);
                tlv.rendered = f.software_version;
            } else if (type == kTlvVtpManagementDomain) {
                f.has_vtp_management_domain = true;
                f.vtp_management_domain = bytes_to_string(value);
                tlv.rendered = f.vtp_management_domain;
            } else if (type == kTlvSystemName) {
                f.has_system_name = true;
                f.system_name = bytes_to_string(value);
                tlv.rendered = f.system_name;
            } else if (type == kTlvCapabilities && value.size() == 4) {
                Cursor vc(value);
                f.has_capabilities = true;
                f.capabilities = vc.u32be();
                f.capabilities_names = capability_names(f.capabilities);
                tlv.rendered = "[" + join(f.capabilities_names) + "]";
            } else if (type == kTlvNativeVlan && value.size() == 2) {
                Cursor vc(value);
                f.has_native_vlan = true;
                f.native_vlan = vc.u16be();
                tlv.rendered = std::to_string(f.native_vlan);
            } else if (type == kTlvDuplex && value.size() == 1) {
                f.has_duplex = true;
                f.duplex_full = value.at(0) != 0;
                tlv.rendered = f.duplex_full ? "Full" : "Half";
            } else if (type == kTlvPowerConsumption && value.size() == 2) {
                Cursor vc(value);
                f.has_power_consumption_mw = true;
                f.power_consumption_mw = vc.u16be();
                tlv.rendered = std::to_string(f.power_consumption_mw) + " mW";
            } else if (type == kTlvPowerRequested && value.size() == 4) {
                Cursor vc(value);
                f.has_power_requested_mw = true;
                f.power_requested_mw = vc.u32be();
                tlv.rendered = std::to_string(f.power_requested_mw) + " mW";
            } else if (type == kTlvPowerAvailable && value.size() == 4) {
                Cursor vc(value);
                f.has_power_available_mw = true;
                f.power_available_mw = vc.u32be();
                tlv.rendered = std::to_string(f.power_available_mw) + " mW";
            } else if (type == kTlvAddresses) {
                std::vector<CdpAddress> parsed = parse_addresses(value);
                tlv.rendered = render_address_list(parsed);  // rendered BEFORE the moves below
                for (auto& a : parsed) {
                    if (f.addresses.size() >= cap) break;
                    f.addresses.push_back(std::move(a));
                }
            } else if (type == kTlvManagementAddress) {
                std::vector<CdpAddress> parsed = parse_addresses(value);
                tlv.rendered = render_address_list(parsed);  // rendered BEFORE the moves below
                for (auto& a : parsed) {
                    if (f.management_addresses.size() >= cap) break;
                    f.management_addresses.push_back(std::move(a));
                }
            } else {
                // Structural-only -- see cdp.hpp's own "SCOPE" header comment for the full list of
                // TLV types this covers (including a recognized-but-not-curated type, an
                // HP-proprietary 0x1000+ extension, an unrecognized type, or a curated type whose
                // value didn't match its expected fixed size above).
                tlv.raw_hex = "0x" + to_hex(value, "");
            }
            if (tlv.type_name.empty()) {
                tlv.type_name = "unrecognized (" + hex4(type) + ")";
            }
            f.tlvs.push_back(std::move(tlv));
        }
        if (f.tlvs.size() >= cap && c.remaining() > 0) {
            f.tlvs_truncated = true;
            f.notes.push_back("output capped at " + std::to_string(cap) +
                               " TLV(s); this frame may declare more");
        }
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be unreachable --
        // caught defensively anyway, the same belt-and-suspenders posture lldp.cpp/goose.cpp take.
    }

    std::ostringstream s;
    s << "CDP v" << static_cast<unsigned>(f.version);
    if (f.has_device_id) s << " device=\"" << f.device_id << "\"";
    if (f.has_port_id) s << " port=\"" << f.port_id << "\"";
    if (f.has_platform) s << " platform=\"" << f.platform << "\"";
    if (!f.addresses.empty()) s << " addr=" << f.addresses.front().address_rendered;
    f.summary = s.str();

    return f;
}

std::optional<ProtocolResult> CdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto cdp = try_parse_cdp(payload)) {
        return ProtocolResult::make<CdpFrame>("cdp", std::move(*cdp));
    }
    return std::nullopt;
}

const ProtocolDecoder& cdp_decoder() {
    static const CdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
