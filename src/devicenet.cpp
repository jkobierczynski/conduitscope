// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/devicenet.hpp"

#include <iomanip>
#include <sstream>

#include "conduitscope/enip.hpp"

namespace conduitscope {

namespace {

constexpr uint16_t kGroup1MaxId = 0x03FF;
constexpr uint16_t kGroup2MaxId = 0x05FF;
constexpr uint16_t kGroup3MaxId = 0x07BF;
constexpr uint16_t kGroup4MaxId = 0x07EF;

constexpr uint16_t kGroup1MacIdMask = 0x003F;
constexpr uint16_t kGroup1MsgMask = 0x03C0;
constexpr uint16_t kGroup2MacIdMask = 0x01F8;
constexpr uint16_t kGroup2MsgMask = 0x0007;
constexpr uint8_t kGroup3MacIdMask = 0x3F;
constexpr uint16_t kGroup3MsgMask = 0x01C0;
constexpr uint8_t kGroup3FragMask = 0x80;
constexpr uint8_t kGroup3XidMask = 0x40;
constexpr uint8_t kGroup4MsgMask = 0x3F;

constexpr uint8_t kCipScResponseMask = 0x80;
constexpr uint8_t kCipScMask = 0x7F;

// DeviceNet's own four service codes, beyond the generic CIP common-services set --
// SC_OPEN_EXPLICIT_MESSAGE/SC_CLOSE_EXPLICIT_MESSAGE/SC_DEVICE_HEARTBEAT_MESSAGE/
// SC_DEVICE_SHUTOWN_MESSAGE in the reference source (see devicenet.hpp's file header comment).
// Checked BEFORE cip_service_name (enip.hpp) is ever called for a Group 3 service byte.
std::string devicenet_specific_service_name(uint8_t base) {
    switch (base) {
        case 0x4B: return "Open Explicit Message Connection Request";
        case 0x4C: return "Close Connection Request";
        case 0x4D: return "Device Heartbeat Message";
        case 0x4E: return "Device Shutdown Message";
        default: return "";
    }
}

// Resolves a Group 3 CIP service code to a name -- DeviceNet-specific table first (see above),
// falling back to enip.hpp's own generic CIP common-services table (cip_service_name) reused
// directly rather than duplicated -- see devicenet.hpp's file header comment and cip_service_name's
// own comment in enip.cpp for exactly why have_path=true/is_symbolic=false/is_conn_mgr=false is the
// right combination to reuse from here.
std::string devicenet_service_name(uint8_t base) {
    std::string specific = devicenet_specific_service_name(base);
    if (!specific.empty()) return specific;
    return cip_service_name(base, /*have_path=*/true, /*is_symbolic=*/false, /*is_conn_mgr=*/false);
}

std::string group1_message_name(uint16_t masked) {
    switch (masked) {
        case 0x0300: return "Slave's I/O Multicast Poll Response";
        case 0x0340: return "Slave's I/O Change of State or Cyclic Message";
        case 0x0380: return "Slave's I/O Bit-Strobe Response Message";
        case 0x03C0: return "Slave's I/O Poll Response or COS/Cyclic Ack Message";
        default: return "Other Group 1 Message";
    }
}

std::string group2_message_name(uint16_t masked) {
    switch (masked) {
        case 0x00: return "Master's I/O Bit-Strobe Command Message";
        case 0x01: return "Master's I/O Multicast Poll Group ID";
        case 0x02: return "Master's Change of State or Cyclic Acknowledge Message";
        case 0x03: return "Slave's Explicit/Unconnected Response Messages";
        case 0x04: return "Master's Explicit Request Messages";
        case 0x05: return "Master's I/O Poll Command/COS/Cyclic Messages";
        case 0x06: return "Group 2 Only Unconnected Explicit Request Messages";
        case 0x07: return "Duplicate MAC ID Check Messages";
        default: return "Unknown Group 2 Message";  // unreachable -- masked is always 0-7
    }
}

std::string group3_message_name(uint16_t masked) {
    switch (masked) {
        case 0x000:
        case 0x040:
        case 0x080:
        case 0x0C0:
        case 0x100:
            return "Group 3 Message";  // genuinely generic in the reference source too, see
                                         // devicenet.hpp
        case 0x140: return "Unconnected Explicit Response Message";
        case 0x180: return "Unconnected Explicit Request Message";
        case 0x1C0: return "Invalid Group 3 Message";
        default: return "Unknown Group 3 Message";  // unreachable -- masked is always one of the above
    }
}

std::string group4_message_name(uint8_t masked) {
    switch (masked) {
        case 0x2C: return "Communication Faulted Response Message";
        case 0x2D: return "Communication Faulted Request Message";
        case 0x2E: return "Offline Ownership Response Message";
        case 0x2F: return "Offline Ownership Request Message";
        default: return "Reserved Group 4 Message";
    }
}

std::string hex16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

}  // namespace

std::optional<DeviceNetFrame> try_parse_devicenet(const CanSocketcanFrame& can) {
    // Mirrors the reference dissector's own unconditional, first-thing rejection -- see
    // devicenet.hpp's file header comment.
    if (can.eff || can.rtr || can.err) return std::nullopt;

    DeviceNetFrame f;
    f.can_id = static_cast<uint16_t>(can.id & CAN_SFF_MASK);
    f.fd = can.fd;
    f.payload = can.payload;
    for (const auto& n : can.notes) f.notes.push_back(n);

    if (f.fd) {
        f.notes.push_back(
            "CAN FD frame (fd_flags 0x04 set) -- DeviceNet predates CAN FD and never uses it; the "
            "CAN-ID-derived message-group classification is still shown, but the payload is not "
            "semantically decoded (see devicenet.hpp)");
    }

    std::ostringstream s;
    uint16_t id = f.can_id;

    if (id <= kGroup1MaxId) {
        f.group = 1;
        f.group_name = "Group 1";
        f.has_source_mac_id = true;
        f.source_mac_id = static_cast<uint8_t>(id & kGroup1MacIdMask);
        f.message_type_name = group1_message_name(id & kGroup1MsgMask);

        s << "DeviceNet Group 1 (" << f.message_type_name << "): SrcMAC="
          << static_cast<unsigned>(f.source_mac_id) << " CAN ID=" << hex16(id);
        if (!f.fd) {
            s << " I/O data=" << f.payload.size() << " byte(s) (not decoded further)";
        }
        f.summary = s.str();
        return f;
    }

    if (id <= kGroup2MaxId) {
        f.group = 2;
        f.group_name = "Group 2";
        f.has_source_mac_id = true;
        f.source_mac_id = static_cast<uint8_t>((id & kGroup2MacIdMask) >> 3);
        uint16_t msg_id = id & kGroup2MsgMask;
        f.message_type_name = group2_message_name(msg_id);

        s << "DeviceNet Group 2 (" << f.message_type_name << "): SrcMAC="
          << static_cast<unsigned>(f.source_mac_id) << " CAN ID=" << hex16(id);

        // Duplicate MAC ID Check Messages (message ID 0x07) own small fixed payload structure --
        // see devicenet.hpp's Group 2 paragraph. Optional polish, implemented since the reference
        // source was already fetched and read for the message-group work above.
        if (msg_id == 0x07 && !f.fd && f.payload.size() >= 7) {
            f.has_dup_mac_id_check = true;
            uint8_t byte0 = f.payload.at(0);
            f.dup_mac_id_is_response = (byte0 & kCipScResponseMask) != 0;
            f.dup_mac_id_physical_port_number = static_cast<uint8_t>(byte0 & 0x7F);
            f.dup_mac_id_vendor_id = static_cast<uint16_t>(f.payload.at(1) | (f.payload.at(2) << 8));
            f.dup_mac_id_serial_number = static_cast<uint32_t>(f.payload.at(3)) |
                                          (static_cast<uint32_t>(f.payload.at(4)) << 8) |
                                          (static_cast<uint32_t>(f.payload.at(5)) << 16) |
                                          (static_cast<uint32_t>(f.payload.at(6)) << 24);
            s << " " << (f.dup_mac_id_is_response ? "Response" : "Request") << " PhysicalPort="
              << static_cast<unsigned>(f.dup_mac_id_physical_port_number) << " VendorID=0x"
              << std::hex << std::uppercase << f.dup_mac_id_vendor_id << std::dec
              << " Serial=" << f.dup_mac_id_serial_number;
        } else if (!f.fd) {
            s << " data=" << f.payload.size() << " byte(s) (not decoded further)";
        }
        f.summary = s.str();
        return f;
    }

    if (id <= kGroup3MaxId) {
        f.group = 3;
        f.group_name = "Group 3";
        f.has_source_mac_id = true;
        f.source_mac_id = static_cast<uint8_t>(id & kGroup3MacIdMask);
        uint16_t msg_id = id & kGroup3MsgMask;
        f.message_type_name = group3_message_name(msg_id);

        s << "DeviceNet Group 3 (" << f.message_type_name << "): SrcMAC="
          << static_cast<unsigned>(f.source_mac_id) << " CAN ID=" << hex16(id);

        if (!f.fd && f.payload.size() >= 1) {
            f.has_group3_header = true;
            uint8_t byte0 = f.payload.at(0);
            f.is_fragmented = (byte0 & kGroup3FragMask) != 0;
            f.is_xid = (byte0 & kGroup3XidMask) != 0;
            f.dest_mac_id = static_cast<uint8_t>(byte0 & kGroup3MacIdMask);
            s << " DestMAC=" << static_cast<unsigned>(f.dest_mac_id);
            if (f.is_xid) s << " [XID]";

            if (f.is_fragmented) {
                s << " [Fragmented -- not reassembled, matches upstream's own unimplemented TODO, "
                     "see devicenet.hpp]";
                f.notes.push_back(
                    "Group 3 Fragmentation flag set -- this is a fragmented message; this decoder "
                    "does not reassemble Group 3 fragments, matching Wireshark's own packet-"
                    "devicenet.c, which has never implemented this either (see devicenet.hpp)");
            } else if (f.payload.size() >= 2) {
                uint8_t service_byte = f.payload.at(1);
                f.has_cip_service = true;
                f.cip_is_response = (service_byte & kCipScResponseMask) != 0;
                f.cip_service = static_cast<uint8_t>(service_byte & kCipScMask);
                f.cip_service_name = devicenet_service_name(f.cip_service);
                s << " " << (f.cip_is_response ? "Response" : "Request") << " Service="
                  << f.cip_service_name;
                if (f.payload.size() > 2) {
                    s << " (" << (f.payload.size() - 2) << " byte(s) of request/response data, "
                         "not decoded -- see devicenet.hpp)";
                }
            } else {
                f.notes.push_back(
                    "Group 3 non-fragmented message but the CIP-style service/request-response "
                    "byte (payload offset 1) isn't present -- only the destination MAC ID byte was "
                    "decoded");
            }
        } else if (!f.fd) {
            f.notes.push_back(
                "Group 3 message with no payload at all -- the destination-MAC-ID/fragmentation/"
                "service bytes (all payload-carried, see devicenet.hpp) could not be decoded");
        }
        f.summary = s.str();
        return f;
    }

    if (id <= kGroup4MaxId) {
        f.group = 4;
        f.group_name = "Group 4";
        f.message_type_name = group4_message_name(static_cast<uint8_t>(id & kGroup4MsgMask));
        s << "DeviceNet Group 4 (" << f.message_type_name << "): CAN ID=" << hex16(id);
        if (!f.fd) {
            s << " data=" << f.payload.size() << " byte(s) (not decoded further)";
        }
        f.summary = s.str();
        return f;
    }

    // 0x07F0-0x07FF: the reference dissector has no handling for this range at all -- see
    // devicenet.hpp's file header comment.
    f.group = 0;
    f.group_name = "Unclassified (0x07F0-0x07FF)";
    f.notes.push_back(
        "CAN ID " + hex16(id) + " falls in the 0x07F0-0x07FF range, which Wireshark's own "
        "packet-devicenet.c does not classify into any DeviceNet message group either -- shown "
        "structurally only, no message-group semantics invented");
    s << "DeviceNet frame, unclassified CAN ID range: CAN ID=" << hex16(id);
    f.summary = s.str();
    return f;
}

}  // namespace conduitscope
