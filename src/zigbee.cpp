// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/zigbee.hpp"

#include <iomanip>
#include <sstream>

#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

namespace {

// Same numeric MIC-length table the IEEE 802.15.4 MAC layer uses (see ieee802154.cpp's own
// mic_length_for_level) -- independently confirmed identical in the reference source for Zigbee's
// own NWK/APS security levels (see zigbee.hpp's header comment).
size_t zigbee_mic_length(uint8_t level) {
    return static_cast<size_t>((0x2 << (level & 0x3)) & ~0x3);
}

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string hex_u16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string format_eui64(uint64_t v) {
    std::ostringstream s;
    s << std::hex << std::uppercase << std::setfill('0');
    for (int i = 7; i >= 0; --i) {
        if (i != 7) s << ":";
        s << std::setw(2) << ((v >> (i * 8)) & 0xFF);
    }
    return s.str();
}

std::string join_list(const std::vector<std::string>& items) {
    std::string out = "[";
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ", ";
        out += items[i];
    }
    out += "]";
    return out;
}

// A wire-declared repeat count (an assoc-device list, a cluster list, a Mgmt_Lqi/Mgmt_Rtg table)
// is capped at this many rendered entries, the same "bound an attacker-controlled repeat count"
// posture s7commplus.hpp's own item_tags/value_summaries 50-entry cap already established in this
// codebase for a similarly shaped problem.
constexpr size_t kZdpListCap = 50;

// --- Zigbee NWK/APS shared Auxiliary Security Header --------------------------------------------

bool parse_zigbee_security_header(Cursor& c, ZigbeeSecurityHeader& sec, std::vector<std::string>& notes) {
    if (c.remaining() < 1) {
        notes.push_back(
            "Not enough captured bytes remain for the Zigbee Auxiliary Security Header's Security "
            "Control field");
        return false;
    }
    uint8_t control = c.u8();
    sec.security_level = control & 0x07;
    sec.key_id = static_cast<uint8_t>((control & 0x18) >> 3);
    sec.extended_nonce = (control & 0x20) != 0;
    sec.verified_frame_counter = (control & 0x40) != 0;

    if (c.remaining() < 4) {
        notes.push_back(
            "Not enough captured bytes remain for the Zigbee Auxiliary Security Header's Frame "
            "Counter field");
        return false;
    }
    sec.frame_counter = c.u32le();

    if (sec.extended_nonce) {
        if (c.remaining() < 8) {
            notes.push_back(
                "Not enough captured bytes remain for the Zigbee Auxiliary Security Header's "
                "Extended Source field (Extended Nonce bit is set)");
            return false;
        }
        sec.has_ext_source = true;
        sec.ext_source = c.u64le();
    }
    if (sec.key_id == 1) {  // Network Key
        if (c.remaining() < 1) {
            notes.push_back(
                "Not enough captured bytes remain for the Zigbee Auxiliary Security Header's Key "
                "Sequence Number field (Key Identifier is Network Key)");
            return false;
        }
        sec.has_key_seqno = true;
        sec.key_seqno = c.u8();
    }
    sec.mic_length = zigbee_mic_length(sec.security_level);
    return true;
}

// --- Zigbee NWK layer -----------------------------------------------------------------------

constexpr uint8_t kNwkVersion2007 = 2;

bool parse_nwk(ByteSpan mac_payload, ZigbeeNwkFrame& n, ByteSpan& remaining_for_aps,
               bool& have_remaining) {
    have_remaining = false;
    if (mac_payload.size() < 2) {
        n.malformed = true;
        n.notes.push_back(
            "Not enough captured bytes remain for the Zigbee NWK Frame Control Field itself");
        return false;
    }
    Cursor c(mac_payload);
    n.fcf = c.u16le();
    n.frame_type = static_cast<uint8_t>(n.fcf & 0x0003);
    n.version = static_cast<uint8_t>((n.fcf & 0x003C) >> 2);
    n.discover_route = static_cast<uint8_t>((n.fcf & 0x00C0) >> 6);
    n.multicast = (n.fcf & 0x0100) != 0;
    n.security = (n.fcf & 0x0200) != 0;
    n.source_route = (n.fcf & 0x0400) != 0;
    n.ext_dst = (n.fcf & 0x0800) != 0;
    n.ext_src = (n.fcf & 0x1000) != 0;
    n.end_device_initiator = (n.fcf & 0x2000) != 0;

    auto need = [&](size_t bytes, const char* what) -> bool {
        if (c.remaining() < bytes) {
            n.malformed = true;
            n.notes.push_back(std::string("Not enough captured bytes remain for ") + what);
            return false;
        }
        return true;
    };

    if (n.frame_type == 3) {  // Inter-PAN -- see zigbee.hpp's header comment
        n.is_interpan = true;
        remaining_for_aps = c.rest();
        have_remaining = true;
        return true;
    }

    if (!need(2, "the NWK Destination Address")) return true;
    n.dst = c.u16le();
    if (!need(2, "the NWK Source Address")) return true;
    n.src = c.u16le();
    if (!need(1, "the NWK Radius")) return true;
    n.radius = c.u8();
    if (!need(1, "the NWK Sequence Number")) return true;
    n.seqno = c.u8();

    if (n.version >= kNwkVersion2007 && n.ext_dst) {
        if (!need(8, "the NWK Extended Destination Address")) return true;
        n.has_ext_dst = true;
        n.ext_dst_addr = c.u64le();
    }
    if (n.version >= kNwkVersion2007 && n.ext_src) {
        if (!need(8, "the NWK Extended Source Address")) return true;
        n.has_ext_src = true;
        n.ext_src_addr = c.u64le();
    }
    if (n.version >= kNwkVersion2007 && n.multicast) {
        if (!need(1, "the NWK Multicast Control field")) return true;
        uint8_t mc = c.u8();
        n.has_multicast_control = true;
        n.mcast_mode = mc & 0x03;
        n.mcast_radius = static_cast<uint8_t>((mc & 0x1C) >> 2);
        n.mcast_max_radius = static_cast<uint8_t>((mc & 0xE0) >> 5);
    }
    if (n.version >= kNwkVersion2007 && n.source_route) {
        if (!need(2, "the NWK Source Route Subframe's Relay Count/Relay Index fields")) return true;
        n.has_source_route = true;
        n.relay_count = c.u8();
        n.relay_index = c.u8();
        for (uint8_t i = 0; i < n.relay_count; ++i) {
            if (!need(2, "a NWK Source Route relay address")) return true;
            if (n.relay_list.size() < kZdpListCap) n.relay_list.push_back(c.u16le());
            else c.skip(2);
        }
    }

    if (n.security) {
        n.has_security = parse_zigbee_security_header(c, n.security_header, n.notes);
        if (!n.has_security) {
            n.malformed = true;
            remaining_for_aps = c.rest();
            have_remaining = true;
            return true;
        }
        remaining_for_aps = c.rest();
        have_remaining = true;
        return true;
    }

    remaining_for_aps = c.rest();
    have_remaining = true;
    return true;
}

// --- Zigbee APS layer -----------------------------------------------------------------------

constexpr uint8_t kApsTypeData = 0, kApsTypeCmd = 1, kApsTypeAck = 2, kApsTypeInterPan = 3;
constexpr uint8_t kApsDeliveryUnicast = 0, kApsDeliveryIndirect = 1, kApsDeliveryBroadcast = 2,
                   kApsDeliveryGroup = 3;
constexpr uint8_t kNwkVersion2004 = 1;

bool parse_aps(ByteSpan payload, uint8_t nwk_version, ZigbeeApsFrame& a, ByteSpan& remaining,
               bool& have_remaining) {
    have_remaining = false;
    if (payload.size() < 1) {
        a.malformed = true;
        a.notes.push_back(
            "Not enough captured bytes remain for the Zigbee APS Frame Control Field itself");
        return false;
    }
    Cursor c(payload);
    a.fcf = c.u8();
    a.frame_type = a.fcf & 0x03;
    a.delivery_mode = static_cast<uint8_t>((a.fcf & 0x0C) >> 2);
    a.indirect_or_ack_format = (a.fcf & 0x10) != 0;
    a.security = (a.fcf & 0x20) != 0;
    a.ack_req = (a.fcf & 0x40) != 0;
    a.ext_header = (a.fcf & 0x80) != 0;

    auto need = [&](size_t n_, const char* what) -> bool {
        if (c.remaining() < n_) {
            a.malformed = true;
            a.notes.push_back(std::string("Not enough captured bytes remain for ") + what);
            return false;
        }
        return true;
    };

    // See zigbee.hpp's header comment section 5.2-5.8 for the literal control-flow this traces.
    bool skip_endpoints = (a.frame_type == kApsTypeCmd) ||
                           (a.frame_type == kApsTypeAck && nwk_version >= kNwkVersion2007 &&
                            a.indirect_or_ack_format);

    if (!skip_endpoints) {
        bool src_endpoint_present = false;
        if (a.frame_type != kApsTypeInterPan) {
            bool dst_present = false;
            if (a.delivery_mode == kApsDeliveryUnicast || a.delivery_mode == kApsDeliveryBroadcast) {
                dst_present = true;
                src_endpoint_present = true;
            } else if (a.delivery_mode == kApsDeliveryIndirect && nwk_version <= kNwkVersion2004) {
                dst_present = !a.indirect_or_ack_format;
                src_endpoint_present = a.indirect_or_ack_format;
            } else if (a.delivery_mode == kApsDeliveryGroup && nwk_version >= kNwkVersion2007) {
                dst_present = false;
                src_endpoint_present = true;
            } else {
                a.notes.push_back("APS Delivery Mode (" + std::to_string(a.delivery_mode) +
                                   ") has no defined meaning for this NWK Protocol Version -- "
                                   "endpoint/cluster/profile field presence could not be determined "
                                   "reliably; treating as absent");
            }
            if (dst_present) {
                if (!need(1, "the APS Destination Endpoint")) return true;
                a.has_dst_endpoint = true;
                a.dst_endpoint = c.u8();
            }
        }

        if (a.delivery_mode == kApsDeliveryGroup) {
            if (!need(2, "the APS Group Address")) return true;
            a.has_group_address = true;
            a.group_address = c.u16le();
        }

        if (!need(4, "the APS Cluster ID + Profile ID fields")) return true;
        a.has_cluster_profile = true;
        a.cluster_id = c.u16le();
        a.profile_id = c.u16le();

        if (a.frame_type != kApsTypeInterPan && src_endpoint_present) {
            if (!need(1, "the APS Source Endpoint")) return true;
            a.has_src_endpoint = true;
            a.src_endpoint = c.u8();
        }
    }

    if (nwk_version >= kNwkVersion2007 && a.frame_type != kApsTypeInterPan) {
        if (!need(1, "the APS Counter")) return true;
        a.has_counter = true;
        a.counter = c.u8();
    }

    if (a.ext_header) {
        if (!need(1, "the APS Extended Header's Fragmentation byte")) return true;
        a.has_ext_header = true;
        uint8_t frag_byte = c.u8();
        a.fragmentation = frag_byte & 0x03;
        if (a.fragmentation != 0) {
            if (!need(1, "the APS Extended Header's Block Number")) return true;
            a.has_block_number = true;
            a.block_number = c.u8();
        }
        if (a.fragmentation != 0 && a.frame_type == kApsTypeAck) {
            if (!need(1, "the APS Extended Header's fragmentation ack bitmask")) return true;
            a.has_frag_ack_bitmask = true;
            a.frag_ack_bitmask = c.u8();
        }
    }

    if (a.frame_type == kApsTypeCmd) {
        if (need(1, "the APS Command Identifier")) {
            a.has_command_id = true;
            a.command_id = c.u8();
            a.command_name = zigbee_aps_command_name(a.command_id);
        }
        // No further Command body decode -- out of scope, see zigbee.hpp's header comment.
        remaining = c.rest();
        have_remaining = true;
        return true;
    }

    if (a.security) {
        a.has_security = parse_zigbee_security_header(c, a.security_header, a.notes);
        if (!a.has_security) {
            a.malformed = true;
            remaining = c.rest();
            have_remaining = true;
            return true;
        }
        remaining = c.rest();
        have_remaining = true;
        return true;
    }

    remaining = c.rest();
    have_remaining = true;
    return true;
}

// --- ZDP -----------------------------------------------------------------------------------

void decode_zdp_payload(uint16_t cluster, Cursor& c, ZigbeeZdpFrame& zdp) {
    uint16_t base = cluster & 0x7FFF;
    bool is_response = (cluster & 0x8000) != 0;

    switch (base) {
        case 0x0000:  // NWK_addr
        case 0x0001: {  // IEEE_addr
            zdp.recognized = true;
            const char* op = base == 0x0000 ? "NWK_addr" : "IEEE_addr";
            if (!is_response) {
                if (base == 0x0000) {
                    uint64_t ieee = c.u64le();
                    uint8_t req_type = c.u8();
                    uint8_t start_index = c.u8();
                    zdp.fields.push_back("IEEEAddr: " + format_eui64(ieee));
                    zdp.fields.push_back(std::string("RequestType: ") +
                                          (req_type == 0 ? "Single Device Response"
                                                          : req_type == 1
                                                                ? "Extended Response (include "
                                                                  "associated devices)"
                                                                : "Unknown") +
                                          " (" + hex_u8(req_type) + ")");
                    zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                    zdp.summary = std::string(op) + " request: IEEEAddr=" + format_eui64(ieee);
                } else {
                    uint16_t nwk = c.u16le();
                    uint8_t req_type = c.u8();
                    uint8_t start_index = c.u8();
                    zdp.fields.push_back("NWKAddr: " + hex_u16(nwk));
                    zdp.fields.push_back(std::string("RequestType: ") +
                                          (req_type == 0 ? "Single Device Response"
                                                          : req_type == 1
                                                                ? "Extended Response (include "
                                                                  "associated devices)"
                                                                : "Unknown") +
                                          " (" + hex_u8(req_type) + ")");
                    zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                    zdp.summary = std::string(op) + " request: NWKAddr=" + hex_u16(nwk);
                }
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 10) {
                    uint64_t ieee = c.u64le();
                    uint16_t nwk = c.u16le();
                    zdp.fields.push_back("IEEEAddr: " + format_eui64(ieee));
                    zdp.fields.push_back("NWKAddr: " + hex_u16(nwk));
                    if (c.remaining() >= 2) {
                        uint8_t assoc_count = c.u8();
                        uint8_t start_index = c.u8();
                        zdp.fields.push_back("AssocDeviceCount: " + std::to_string(assoc_count));
                        zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                        std::vector<std::string> addrs;
                        for (uint8_t i = 0; i < assoc_count && c.remaining() >= 2; ++i) {
                            if (addrs.size() < kZdpListCap) addrs.push_back(hex_u16(c.u16le()));
                            else c.skip(2);
                        }
                        zdp.fields.push_back("AssocDeviceList: " + join_list(addrs));
                    }
                    zdp.summary = std::string(op) + " response: Status=SUCCESS IEEEAddr=" +
                                   format_eui64(ieee) + " NWKAddr=" + hex_u16(nwk);
                } else {
                    zdp.summary =
                        std::string(op) + " response: Status=" + zigbee_zdp_status_name(status);
                }
            }
            break;
        }

        case 0x0002: {  // Node_Desc
            zdp.recognized = true;
            if (!is_response) {
                uint16_t nwk = c.u16le();
                zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                zdp.summary = "Node_Desc request: NWKAddrOfInterest=" + hex_u16(nwk);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 2) {
                    uint16_t nwk = c.u16le();
                    zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                    if (c.remaining() >= 13) {
                        uint16_t flags = c.u16le();
                        uint8_t logical_type = flags & 0x07;
                        bool complex_avail = (flags & 0x08) != 0;
                        bool user_avail = (flags & 0x10) != 0;
                        uint8_t cap = c.u8();
                        uint16_t manuf = c.u16le();
                        uint8_t maxbuf = c.u8();
                        uint16_t maxin = c.u16le();
                        uint16_t servermask = c.u16le();
                        uint16_t maxout = c.u16le();
                        uint8_t desccap = c.u8();
                        const char* logical_name = logical_type == 0   ? "Coordinator"
                                                    : logical_type == 1 ? "Router"
                                                    : logical_type == 2 ? "End Device"
                                                                        : "Reserved";
                        zdp.fields.push_back(std::string("LogicalType: ") + logical_name);
                        zdp.fields.push_back(std::string("ComplexDescriptorAvailable: ") +
                                              (complex_avail ? "true" : "false"));
                        zdp.fields.push_back(std::string("UserDescriptorAvailable: ") +
                                              (user_avail ? "true" : "false"));
                        zdp.fields.push_back("MACCapability: " + hex_u8(cap));
                        zdp.fields.push_back("ManufacturerCode: " + hex_u16(manuf));
                        zdp.fields.push_back("MaxBufferSize: " + std::to_string(maxbuf));
                        zdp.fields.push_back("MaxIncomingTransferSize: " + std::to_string(maxin));
                        zdp.fields.push_back("ServerMask: " + hex_u16(servermask));
                        zdp.fields.push_back("MaxOutgoingTransferSize: " + std::to_string(maxout));
                        zdp.fields.push_back("DescriptorCapability: " + hex_u8(desccap));
                        zdp.notes.push_back(
                            "Node Descriptor's frequency-band flag bits (868MHz/900MHz/2400MHz/"
                            "EU-sub-GHz) are not individually decoded");
                        zdp.summary = std::string("Node_Desc response: Status=SUCCESS LogicalType=") +
                                      logical_name;
                    } else {
                        zdp.summary = "Node_Desc response: Status=SUCCESS (descriptor truncated)";
                    }
                } else {
                    zdp.summary = "Node_Desc response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0004: {  // Simple_Desc
            zdp.recognized = true;
            if (!is_response) {
                uint16_t nwk = c.u16le();
                uint8_t ep = c.u8();
                zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                zdp.fields.push_back("Endpoint: " + std::to_string(ep));
                zdp.summary =
                    "Simple_Desc request: NWKAddrOfInterest=" + hex_u16(nwk) + " Endpoint=" +
                    std::to_string(ep);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 3) {
                    uint16_t nwk = c.u16le();
                    uint8_t length = c.u8();
                    zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                    zdp.fields.push_back("Length: " + std::to_string(length));
                    if (c.remaining() >= 8) {
                        uint8_t ep = c.u8();
                        uint16_t profile = c.u16le();
                        uint16_t device = c.u16le();
                        uint8_t devver = c.u8();
                        uint8_t in_count = c.u8();
                        std::vector<std::string> in_list;
                        for (uint8_t i = 0; i < in_count && c.remaining() >= 2; ++i) {
                            if (in_list.size() < kZdpListCap) in_list.push_back(hex_u16(c.u16le()));
                            else c.skip(2);
                        }
                        uint8_t out_count = c.remaining() >= 1 ? c.u8() : 0;
                        std::vector<std::string> out_list;
                        for (uint8_t i = 0; i < out_count && c.remaining() >= 2; ++i) {
                            if (out_list.size() < kZdpListCap) out_list.push_back(hex_u16(c.u16le()));
                            else c.skip(2);
                        }
                        zdp.fields.push_back("Endpoint: " + std::to_string(ep));
                        zdp.fields.push_back("ProfileID: " + hex_u16(profile));
                        zdp.fields.push_back("DeviceID: " + hex_u16(device));
                        zdp.fields.push_back("DeviceVersion: " + std::to_string(devver));
                        zdp.fields.push_back("InClusterList: " + join_list(in_list));
                        zdp.fields.push_back("OutClusterList: " + join_list(out_list));
                        zdp.summary = "Simple_Desc response: Endpoint=" + std::to_string(ep) +
                                       " ProfileID=" + hex_u16(profile) +
                                       " DeviceID=" + hex_u16(device);
                    } else {
                        zdp.summary = "Simple_Desc response: Status=SUCCESS (descriptor truncated)";
                    }
                } else {
                    zdp.summary =
                        "Simple_Desc response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0005: {  // Active_EP
            zdp.recognized = true;
            if (!is_response) {
                uint16_t nwk = c.u16le();
                zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                zdp.summary = "Active_EP request: NWKAddrOfInterest=" + hex_u16(nwk);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 3) {
                    uint16_t nwk = c.u16le();
                    uint8_t count = c.u8();
                    zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                    std::vector<std::string> eps;
                    for (uint8_t i = 0; i < count && c.remaining() >= 1; ++i) {
                        if (eps.size() < kZdpListCap) eps.push_back(std::to_string(c.u8()));
                        else c.skip(1);
                    }
                    zdp.fields.push_back("ActiveEPList: " + join_list(eps));
                    zdp.summary = "Active_EP response: Status=SUCCESS NWKAddrOfInterest=" +
                                  hex_u16(nwk) + " EPCount=" + std::to_string(count);
                } else {
                    zdp.summary =
                        "Active_EP response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0006: {  // Match_Desc
            zdp.recognized = true;
            if (!is_response) {
                uint16_t nwk = c.u16le();
                uint16_t profile = c.u16le();
                uint8_t in_count = c.u8();
                std::vector<std::string> in_list;
                for (uint8_t i = 0; i < in_count && c.remaining() >= 2; ++i) {
                    if (in_list.size() < kZdpListCap) in_list.push_back(hex_u16(c.u16le()));
                    else c.skip(2);
                }
                uint8_t out_count = c.remaining() >= 1 ? c.u8() : 0;
                std::vector<std::string> out_list;
                for (uint8_t i = 0; i < out_count && c.remaining() >= 2; ++i) {
                    if (out_list.size() < kZdpListCap) out_list.push_back(hex_u16(c.u16le()));
                    else c.skip(2);
                }
                zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                zdp.fields.push_back("ProfileID: " + hex_u16(profile));
                zdp.fields.push_back("InClusterList: " + join_list(in_list));
                zdp.fields.push_back("OutClusterList: " + join_list(out_list));
                zdp.summary = "Match_Desc request: NWKAddrOfInterest=" + hex_u16(nwk) +
                              " ProfileID=" + hex_u16(profile);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 3) {
                    uint16_t nwk = c.u16le();
                    uint8_t count = c.u8();
                    zdp.fields.push_back("NWKAddrOfInterest: " + hex_u16(nwk));
                    std::vector<std::string> matches;
                    for (uint8_t i = 0; i < count && c.remaining() >= 1; ++i) {
                        if (matches.size() < kZdpListCap) matches.push_back(std::to_string(c.u8()));
                        else c.skip(1);
                    }
                    zdp.fields.push_back("MatchList: " + join_list(matches));
                    zdp.summary = "Match_Desc response: Status=SUCCESS NWKAddrOfInterest=" +
                                  hex_u16(nwk) + " MatchCount=" + std::to_string(count);
                } else {
                    zdp.summary =
                        "Match_Desc response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0013: {  // Device_annce -- broadcast, no response
            zdp.recognized = true;
            uint16_t nwk = c.u16le();
            uint64_t ieee = c.u64le();
            uint8_t cap = c.u8();
            zdp.fields.push_back("NWKAddr: " + hex_u16(nwk));
            zdp.fields.push_back("IEEEAddr: " + format_eui64(ieee));
            zdp.fields.push_back("Capability: " + hex_u8(cap));
            zdp.summary = "Device_annce (broadcast, no response): NWKAddr=" + hex_u16(nwk) +
                          " IEEEAddr=" + format_eui64(ieee);
            break;
        }

        case 0x0021:    // Bind
        case 0x0022: {  // Unbind -- identical payload shape
            zdp.recognized = true;
            const char* op = base == 0x0021 ? "Bind" : "Unbind";
            if (!is_response) {
                uint64_t src_ieee = c.u64le();
                uint8_t src_ep = c.u8();
                uint16_t cluster_id_field = c.u16le();
                zdp.fields.push_back("SrcIEEE: " + format_eui64(src_ieee));
                zdp.fields.push_back("SrcEndpoint: " + std::to_string(src_ep));
                zdp.fields.push_back("ClusterID: " + hex_u16(cluster_id_field));
                if (c.remaining() >= 1) {
                    uint8_t addr_mode = c.u8();
                    zdp.fields.push_back("DstAddrMode: " + std::to_string(addr_mode) +
                                          (addr_mode == 1 ? " (Group)"
                                                           : addr_mode == 3 ? " (Unicast)" : ""));
                    if (addr_mode == 1 && c.remaining() >= 2) {
                        uint16_t group = c.u16le();
                        zdp.fields.push_back("DstGroupAddr: " + hex_u16(group));
                    } else if (addr_mode == 3 && c.remaining() >= 9) {
                        uint64_t dst_ieee = c.u64le();
                        uint8_t dst_ep = c.u8();
                        zdp.fields.push_back("DstIEEE: " + format_eui64(dst_ieee));
                        zdp.fields.push_back("DstEndpoint: " + std::to_string(dst_ep));
                    } else if (addr_mode != 1 && addr_mode != 3) {
                        zdp.notes.push_back(
                            "Dest Addr Mode " + std::to_string(addr_mode) +
                            " is not one of the two legal values (1=Group, 3=Unicast) -- "
                            "destination address not decoded");
                    }
                }
                zdp.summary = std::string(op) + " request: SrcIEEE=" + format_eui64(src_ieee) +
                              " SrcEndpoint=" + std::to_string(src_ep) +
                              " ClusterID=" + hex_u16(cluster_id_field);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                zdp.summary =
                    std::string(op) + " response: Status=" + zigbee_zdp_status_name(status);
            }
            break;
        }

        case 0x0031: {  // Mgmt_Lqi
            zdp.recognized = true;
            if (!is_response) {
                uint8_t start_index = c.u8();
                zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                zdp.summary = "Mgmt_Lqi request: StartIndex=" + std::to_string(start_index);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 3) {
                    uint8_t total = c.u8();
                    uint8_t start_index = c.u8();
                    uint8_t count = c.u8();
                    zdp.fields.push_back("NeighborTableEntries: " + std::to_string(total));
                    zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                    zdp.fields.push_back("EntryCount: " + std::to_string(count));
                    size_t rendered = 0;
                    for (uint8_t i = 0; i < count && c.remaining() >= 22 && rendered < kZdpListCap;
                         ++i, ++rendered) {
                        uint64_t ext_pan = c.u64le();
                        uint64_t ext_addr = c.u64le();
                        uint16_t nwk_addr = c.u16le();
                        uint8_t packed1 = c.u8();
                        uint8_t permit = c.u8();
                        uint8_t depth = c.u8();
                        uint8_t lqi = c.u8();
                        uint8_t device_type = packed1 & 0x03;
                        uint8_t rx_on_idle = (packed1 >> 2) & 0x03;
                        uint8_t relationship = (packed1 >> 4) & 0x07;
                        const char* dt = device_type == 0   ? "Coordinator"
                                         : device_type == 1 ? "Router"
                                         : device_type == 2 ? "End Device"
                                                             : "Unknown";
                        std::ostringstream entry;
                        entry << "ExtPANID=" << format_eui64(ext_pan)
                              << " ExtAddr=" << format_eui64(ext_addr)
                              << " NWKAddr=" << hex_u16(nwk_addr) << " DeviceType=" << dt
                              << " RxOnWhenIdle=" << static_cast<unsigned>(rx_on_idle)
                              << " Relationship=" << static_cast<unsigned>(relationship)
                              << " PermitJoining=" << static_cast<unsigned>(permit & 0x03)
                              << " Depth=" << static_cast<unsigned>(depth)
                              << " LQI=" << static_cast<unsigned>(lqi);
                        zdp.fields.push_back("NeighborTableEntry[" + std::to_string(i) +
                                              "]: " + entry.str());
                    }
                    zdp.summary = "Mgmt_Lqi response: Status=SUCCESS NeighborTableEntries=" +
                                  std::to_string(total) + " EntryCount=" + std::to_string(count);
                } else {
                    zdp.summary =
                        "Mgmt_Lqi response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0032: {  // Mgmt_Rtg
            zdp.recognized = true;
            if (!is_response) {
                uint8_t start_index = c.u8();
                zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                zdp.summary = "Mgmt_Rtg request: StartIndex=" + std::to_string(start_index);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                if (status == 0x00 && c.remaining() >= 3) {
                    uint8_t total = c.u8();
                    uint8_t start_index = c.u8();
                    uint8_t count = c.u8();
                    zdp.fields.push_back("RoutingTableEntries: " + std::to_string(total));
                    zdp.fields.push_back("StartIndex: " + std::to_string(start_index));
                    zdp.fields.push_back("EntryCount: " + std::to_string(count));
                    size_t rendered = 0;
                    for (uint8_t i = 0; i < count && c.remaining() >= 5 && rendered < kZdpListCap;
                         ++i, ++rendered) {
                        uint16_t dest = c.u16le();
                        uint8_t status_byte = c.u8();
                        uint16_t next_hop = c.u16le();
                        std::ostringstream entry;
                        entry << "Destination=" << hex_u16(dest) << " StatusByte=" << hex_u8(status_byte)
                              << " NextHop=" << hex_u16(next_hop);
                        zdp.fields.push_back("RoutingTableEntry[" + std::to_string(i) +
                                              "]: " + entry.str());
                    }
                    zdp.summary = "Mgmt_Rtg response: Status=SUCCESS RoutingTableEntries=" +
                                  std::to_string(total) + " EntryCount=" + std::to_string(count);
                } else {
                    zdp.summary =
                        "Mgmt_Rtg response: Status=" + std::string(zigbee_zdp_status_name(status));
                }
            }
            break;
        }

        case 0x0034: {  // Mgmt_Leave
            zdp.recognized = true;
            if (!is_response) {
                uint64_t ieee = c.u64le();
                zdp.fields.push_back("DeviceAddress: " + format_eui64(ieee));
                if (c.remaining() >= 1) {
                    uint8_t flags = c.u8();
                    bool remove_children = (flags & 0x80) != 0;
                    bool rejoin = (flags & 0x40) != 0;
                    zdp.fields.push_back(std::string("RemoveChildren: ") +
                                          (remove_children ? "true" : "false"));
                    zdp.fields.push_back(std::string("Rejoin: ") + (rejoin ? "true" : "false"));
                }
                zdp.summary = "Mgmt_Leave request: DeviceAddress=" + format_eui64(ieee);
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                zdp.summary = "Mgmt_Leave response: Status=" + std::string(zigbee_zdp_status_name(status));
            }
            break;
        }

        case 0x0036: {  // Mgmt_Permit_Joining
            zdp.recognized = true;
            if (!is_response) {
                uint8_t duration = c.u8();
                uint8_t tc_sig = c.remaining() >= 1 ? c.u8() : 0;
                std::string duration_desc = duration == 0x00   ? "disable joining"
                                             : duration == 0xFF ? "INDEFINITE (until explicitly disabled)"
                                                                 : (std::to_string(duration) + " second(s)");
                zdp.fields.push_back("PermitDuration: " + std::to_string(duration) + " (" +
                                      duration_desc + ")");
                zdp.fields.push_back("TC_Significance: " + std::to_string(tc_sig));
                zdp.summary = "Mgmt_Permit_Joining request: PermitDuration=" +
                              std::to_string(duration) + " (" + duration_desc + ")";
                // Curated, security-relevant note -- matches this codebase's established pattern for
                // a single named operation worth calling out on its own (e.g. BSAP's Set IP Address,
                // CC-Link IE's Set IP Address -- see bsap.hpp/cclink_ie.hpp).
                if (duration == 0xFF) {
                    zdp.notes.push_back(
                        "Mgmt_Permit_Joining requested for an INDEFINITE duration (0xFF) -- the "
                        "network remains open to new device joins until this is explicitly "
                        "disabled again; an indefinitely-open Zigbee network is a common OT/IoT "
                        "security finding (any device in radio range can attempt to join for as "
                        "long as this stays in effect)");
                } else if (duration == 0x00) {
                    zdp.notes.push_back("Mgmt_Permit_Joining requests joining be DISABLED");
                }
            } else {
                uint8_t status = c.u8();
                zdp.fields.push_back(std::string("Status: ") + zigbee_zdp_status_name(status));
                zdp.summary = "Mgmt_Permit_Joining response: Status=" +
                              std::string(zigbee_zdp_status_name(status));
            }
            break;
        }

        default:
            zdp.notes.push_back(
                "ZDP cluster " + hex_u16(cluster) +
                (zdp.cluster_name.empty() ? " is not recognized by this decoder"
                                          : (" (" + zdp.cluster_name + ") payload is not decoded by "
                                                                        "this release")) +
                " -- only the Transaction Sequence Number and cluster identity were read");
            zdp.summary = "ZDP cluster " + hex_u16(cluster) + ", payload not decoded";
            break;
    }
}

}  // namespace

const char* zigbee_nwk_frame_type_name(uint8_t frame_type) {
    switch (frame_type) {
        case 0: return "Data";
        case 1: return "NWK Command";
        case 3: return "Inter-PAN";
        default: return "Reserved";
    }
}

const char* zigbee_nwk_version_name(uint8_t version) {
    switch (version) {
        case 0: return "Prototype";
        case 1: return "2004";
        case 2: return "2007 (ZigBee PRO)";
        case 3: return "Green Power";
        default: return "Unknown";
    }
}

const char* zigbee_nwk_discover_route_name(uint8_t discover_route) {
    switch (discover_route) {
        case 0: return "Suppress";
        case 1: return "Enable";
        case 3: return "Force";
        default: return "Unused";
    }
}

const char* zigbee_aps_frame_type_name(uint8_t frame_type) {
    switch (frame_type) {
        case 0: return "Data";
        case 1: return "Command";
        case 2: return "Ack";
        case 3: return "Inter-PAN";
        default: return "Unknown";
    }
}

const char* zigbee_aps_delivery_mode_name(uint8_t delivery_mode) {
    switch (delivery_mode) {
        case 0: return "Unicast";
        case 1: return "Indirect";
        case 2: return "Broadcast";
        case 3: return "Group";
        default: return "Unknown";
    }
}

const char* zigbee_security_key_id_name(uint8_t key_id) {
    switch (key_id) {
        case 0: return "Link Key";
        case 1: return "Network Key";
        case 2: return "Key-Transport Key";
        case 3: return "Key-Load Key";
        default: return "Unknown";
    }
}

std::string zigbee_aps_command_name(uint8_t command_id) {
    switch (command_id) {
        case 0x01: return "SKKE-1";
        case 0x02: return "SKKE-2";
        case 0x03: return "SKKE-3";
        case 0x04: return "SKKE-4";
        case 0x05: return "Transport Key";
        case 0x06: return "Update Device";
        case 0x07: return "Remove Device";
        case 0x08: return "Request Key";
        case 0x09: return "Switch Key";
        case 0x0a: return "EA Initiator Challenge";
        case 0x0b: return "EA Responder Challenge";
        case 0x0c: return "EA Initiator MAC";
        case 0x0d: return "EA Responder MAC";
        case 0x0e: return "Tunnel";
        case 0x0f: return "Verify Key";
        case 0x10: return "Confirm Key";
        case 0x11: return "Relay Message Downstream";
        case 0x12: return "Relay Message Upstream";
        default: return "Unknown (" + hex_u8(command_id) + ")";
    }
}

const char* zigbee_zdp_status_name(uint8_t status) {
    switch (status) {
        case 0x00: return "SUCCESS";
        case 0x80: return "INV_REQUESTTYPE";
        case 0x81: return "DEVICE_NOT_FOUND";
        case 0x82: return "INVALID_EP";
        case 0x83: return "NOT_ACTIVE";
        case 0x84: return "NOT_SUPPORTED";
        case 0x85: return "TIMEOUT";
        case 0x86: return "NO_MATCH";
        case 0x88: return "NO_ENTRY";
        case 0x89: return "NO_DESCRIPTOR";
        case 0x8a: return "INSUFFICIENT_SPACE";
        case 0x8b: return "NOT_PERMITTED";
        case 0x8c: return "TABLE_FULL";
        case 0x8d: return "NOT_AUTHORIZED";
        case 0x8e: return "DEVICE_BINDING_TABLE_FULL";
        case 0x8f: return "INVALID_INDEX";
        case 0x90: return "RESPONSE_TOO_LARGE";
        case 0x91: return "MISSING_TLV";
        default: return "Unknown";
    }
}

std::string zigbee_zdp_cluster_name(uint16_t cluster) {
    switch (cluster & 0x7FFF) {
        case 0x0000: return "NWK_addr";
        case 0x0001: return "IEEE_addr";
        case 0x0002: return "Node_Desc";
        case 0x0004: return "Simple_Desc";
        case 0x0005: return "Active_EP";
        case 0x0006: return "Match_Desc";
        case 0x0013: return "Device_annce";
        case 0x0021: return "Bind";
        case 0x0022: return "Unbind";
        case 0x0031: return "Mgmt_Lqi";
        case 0x0032: return "Mgmt_Rtg";
        case 0x0034: return "Mgmt_Leave";
        case 0x0036: return "Mgmt_Permit_Joining";
        default: return "";
    }
}

std::optional<ZigbeeFrame> try_parse_zigbee(const Ieee802154Frame& mac) {
    // Only Data-type MAC frames ever carry a Zigbee NWK payload -- see zigbee.hpp/ieee802154.hpp.
    if (mac.frame_type != 1) return std::nullopt;

    ZigbeeFrame zf;
    zf.mac = mac;

    if (mac.malformed) {
        zf.nwk_present = false;
        zf.nwk_absent_reason =
            "The IEEE 802.15.4 MAC header itself could not be fully decoded (see notes) -- no "
            "Zigbee NWK layer bytes could be reliably located";
        zf.summary = "IEEE 802.15.4 Data frame, malformed MAC header -- no Zigbee NWK layer decoded";
        for (const auto& n : mac.notes) zf.notes.push_back(n);
        return zf;
    }

    if (mac.security_enabled) {
        zf.nwk_present = false;
        zf.nwk_absent_reason =
            "IEEE 802.15.4 MAC-layer security is enabled on this frame -- its payload is ciphertext "
            "at the MAC layer itself. Real-world Zigbee networks essentially never enable this "
            "(they secure the NWK/APS layers instead, using their own distinct Auxiliary Security "
            "Header format); this decoder cannot access the NWK layer without decrypting the MAC "
            "payload, which is out of scope (no decryption capability at all)";
        zf.summary = "IEEE 802.15.4 Data frame, MAC-layer security enabled -- payload is opaque, no "
                     "Zigbee NWK layer decoded (" +
                     std::to_string(mac.mac_payload.size()) +
                     " byte(s) of MAC-layer-encrypted payload)";
        return zf;
    }

    ByteSpan aps_input;
    bool have_aps_input = false;
    bool nwk_ok = parse_nwk(mac.mac_payload, zf.nwk, aps_input, have_aps_input);
    for (const auto& n : zf.nwk.notes) zf.notes.push_back(n);
    if (!nwk_ok) {
        zf.nwk_present = false;
        zf.nwk_absent_reason = "The Zigbee NWK Frame Control Field itself did not fit in the MAC payload";
        zf.summary = "IEEE 802.15.4 Data frame, no Zigbee NWK layer (too short)";
        return zf;
    }
    zf.nwk_present = true;

    if (zf.nwk.malformed) {
        zf.summary = "Zigbee NWK " + std::string(zigbee_nwk_frame_type_name(zf.nwk.frame_type)) +
                     " frame (malformed/truncated -- see notes)";
        return zf;
    }

    if (zf.nwk.is_interpan) {
        zf.aps_present = false;
        zf.aps_absent_reason =
            "NWK Frame Type is Inter-PAN -- ZLL/Inter-PAN application-profile payloads are out of "
            "scope for this decoder";
        zf.summary = "Zigbee NWK Inter-PAN frame (ZLL/Inter-PAN application profile, not decoded)";
        return zf;
    }

    if (zf.nwk.security) {
        size_t len = have_aps_input ? aps_input.size() : 0;
        if (zf.nwk.has_security && len > zf.nwk.security_header.mic_length) {
            len -= zf.nwk.security_header.mic_length;
        } else if (zf.nwk.has_security) {
            len = 0;
        }
        zf.nwk_payload_encrypted = true;
        zf.nwk_encrypted_payload_length = len;
        zf.aps_present = false;
        zf.aps_absent_reason =
            "NWK-layer security is enabled -- the entire NWK payload (including all of APS) is "
            "encrypted and structurally invisible; only the NWK header fields above were decoded";
        zf.summary = "Zigbee NWK " + std::string(zigbee_nwk_frame_type_name(zf.nwk.frame_type)) +
                     " frame, NWK-layer security enabled (" + std::to_string(len) +
                     " byte(s) of NWK-encrypted payload)";
        return zf;
    }

    if (zf.nwk.frame_type == 1) {  // NWK Command
        zf.aps_present = false;
        zf.aps_absent_reason =
            "NWK Frame Type is NWK Command -- Zigbee NWK command payloads (route requests, leave, "
            "rejoin, ...) are out of scope for this decoder; only the NWK header was decoded";
        zf.summary = "Zigbee NWK Command frame (command payload not decoded)";
        return zf;
    }

    if (zf.nwk.frame_type != 0) {  // not Data, not Command, not Inter-PAN -> undefined (0x2)
        zf.aps_present = false;
        zf.aps_absent_reason = "NWK Frame Type " + std::to_string(zf.nwk.frame_type) +
                               " has no defined meaning -- no APS layer attempted";
        zf.summary = "Zigbee NWK frame, undefined Frame Type " + std::to_string(zf.nwk.frame_type);
        return zf;
    }

    // NWK Data frame, no NWK-layer security -- proceed to APS.
    ByteSpan zdp_input;
    bool have_zdp_input = false;
    bool aps_ok = parse_aps(aps_input, zf.nwk.version, zf.aps, zdp_input, have_zdp_input);
    for (const auto& n : zf.aps.notes) zf.notes.push_back(n);
    if (!aps_ok) {
        zf.aps_present = false;
        zf.aps_absent_reason = "The APS Frame Control Field itself did not fit in the NWK payload";
        zf.summary = "Zigbee NWK Data frame, no APS layer (too short)";
        return zf;
    }
    zf.aps_present = true;

    if (zf.aps.malformed) {
        zf.summary = "Zigbee APS " + std::string(zigbee_aps_frame_type_name(zf.aps.frame_type)) +
                     " frame (malformed/truncated -- see notes)";
        return zf;
    }

    if (zf.aps.frame_type == kApsTypeCmd) {
        zf.zdp_present = false;
        zf.zdp_absent_reason = "APS Frame Type is Command -- not a ZDP message";
        zf.summary = "Zigbee APS Command frame: " +
                     (zf.aps.has_command_id ? zf.aps.command_name : std::string("(command id not present)"));
        return zf;
    }
    if (zf.aps.frame_type == kApsTypeAck) {
        zf.zdp_present = false;
        zf.zdp_absent_reason = "APS Frame Type is Ack -- carries no ZDP payload";
        zf.summary = "Zigbee APS Acknowledgement frame";
        return zf;
    }
    if (zf.aps.frame_type == kApsTypeInterPan) {
        zf.zdp_present = false;
        zf.zdp_absent_reason = "APS Frame Type is Inter-PAN -- not a ZDP message";
        zf.summary = "Zigbee APS Inter-PAN frame (not decoded)";
        return zf;
    }

    // APS Data frame.
    if (zf.aps.security) {
        size_t len = have_zdp_input ? zdp_input.size() : 0;
        if (zf.aps.has_security && len > zf.aps.security_header.mic_length) {
            len -= zf.aps.security_header.mic_length;
        } else if (zf.aps.has_security) {
            len = 0;
        }
        zf.aps_payload_encrypted = true;
        zf.aps_encrypted_payload_length = len;
        zf.zdp_present = false;
        zf.zdp_absent_reason =
            "APS-layer security is enabled -- the APS payload (ZDP or application/ZCL data) is "
            "encrypted; the APS header above is still fully decoded";
        zf.summary = "Zigbee APS Data frame, ClusterID=" + hex_u16(zf.aps.cluster_id) +
                     " ProfileID=" + hex_u16(zf.aps.profile_id) +
                     ", APS-layer security enabled (" + std::to_string(len) +
                     " byte(s) of APS-encrypted payload)";
        return zf;
    }

    if (zf.aps.profile_id != 0x0000) {
        zf.zdp_present = false;
        zf.zdp_absent_reason =
            "APS Profile ID is " + hex_u16(zf.aps.profile_id) +
            ", not the ZDP profile (0x0000) -- this is an application-profile (ZCL) frame, which is "
            "out of scope for this decoder (see zigbee.hpp's header comment)";
        zf.summary = "Zigbee APS Data frame, ClusterID=" + hex_u16(zf.aps.cluster_id) +
                     " ProfileID=" + hex_u16(zf.aps.profile_id) +
                     " (application-profile/ZCL payload, not decoded)";
        return zf;
    }

    // ZDP.
    if (!have_zdp_input || zdp_input.size() < 1) {
        zf.zdp_present = false;
        zf.zdp_absent_reason = "No bytes remain for even the 1-byte ZDP Transaction Sequence Number";
        zf.summary = "Zigbee ZDP message, too short (no Transaction Sequence Number)";
        return zf;
    }
    Cursor zc(zdp_input);
    zf.zdp.seqno = zc.u8();
    zf.zdp.cluster = zf.aps.cluster_id;
    zf.zdp.cluster_name = zigbee_zdp_cluster_name(zf.zdp.cluster);
    zf.zdp.is_response = (zf.zdp.cluster & 0x8000) != 0;
    try {
        decode_zdp_payload(zf.zdp.cluster, zc, zf.zdp);
    } catch (const ParseError& e) {
        zf.zdp.notes.push_back(std::string("ZDP payload parse stopped early: ") + e.what());
    }
    zf.zdp_present = true;
    zf.summary =
        zf.zdp.summary.empty() ? ("Zigbee ZDP message, cluster " + hex_u16(zf.zdp.cluster)) : zf.zdp.summary;
    for (const auto& n : zf.zdp.notes) zf.notes.push_back(n);
    return zf;
}

std::optional<uint32_t> ZigbeeDecoder::link_type() const { return LINKTYPE_IEEE802_15_4_WITHFCS; }

std::optional<ProtocolResult> ZigbeeDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    // See zigbee.hpp's own ZigbeeDecoder class comment: this assumes WITHFCS framing (matching
    // link_type() above) -- decoder.cpp's own two link-type branches do NOT call this method (they
    // call parse_ieee802154_withfcs/parse_ieee802154_tap + try_parse_zigbee directly instead, since
    // only they know which of the two capture formats produced `payload`). This method exists so
    // ZigbeeDecoder remains a complete, independently useful GateKind::LinkType decoder for the
    // registry (link_type_registry(), protocol_registry.hpp).
    Ieee802154Frame mac = parse_ieee802154_withfcs(payload);
    if (auto zf = try_parse_zigbee(mac)) {
        return ProtocolResult::make<ZigbeeFrame>("zigbee", std::move(*zf));
    }
    return std::nullopt;
}

const ProtocolDecoder& zigbee_decoder() {
    static const ZigbeeDecoder instance;
    return instance;
}

}  // namespace conduitscope
