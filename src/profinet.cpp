// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/profinet.hpp"

#include <iomanip>
#include <sstream>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/link_layer.hpp"

namespace conduitscope {

namespace {

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

std::string hex8(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return s.str();
}

// --- FrameID classification --------------------------------------------------------------------
// See profinet.hpp's file header comment for the full table and its provenance
// (Wireshark's packet-pn-rt.c `dissect_pn_rt` range checks).

enum class ProfinetFrameKind { Unknown, Dcp, Cyclic, NamedOnly };

struct FrameIdInfo {
    ProfinetFrameKind kind;
    std::string name;
};

std::optional<FrameIdInfo> classify_frame_id(uint16_t id) {
    if (id >= 0x0020 && id <= 0x0021) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Sync (with follow up)"};
    if (id >= 0x0080 && id <= 0x0081) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Sync (without follow up)"};
    if (id >= 0x0100 && id <= 0x06FF) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "RTC3 (non-redundant)"};
    if (id >= 0x0700 && id <= 0x0FFF) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "RTC3 (redundant)"};
    if (id >= 0x8000 && id <= 0xBBFF) return FrameIdInfo{ProfinetFrameKind::Cyclic, "Cyclic RT IO data (RT_CLASS_1, unicast)"};
    if (id >= 0xBC00 && id <= 0xBFFF) return FrameIdInfo{ProfinetFrameKind::Cyclic, "Cyclic RT IO data (RT_CLASS_1, multicast)"};
    if (id >= 0xC000 && id <= 0xF7FF)
        return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Cyclic RT IO data (RT_CLASS_UDP, unicast) -- not decoded (expected over UDP/IP, not raw Ethernet)"};
    if (id >= 0xF800 && id <= 0xFBFF)
        return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Cyclic RT IO data (RT_CLASS_UDP, multicast) -- not decoded (expected over UDP/IP, not raw Ethernet)"};
    if (id == 0xFC01) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Alarm High"};
    if (id == 0xFC41) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Alarm High (with security)"};
    if (id == 0xFE01) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Alarm Low"};
    if (id == 0xFE02) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "RSI (Remote Service Interface)"};
    if (id == 0xFE03) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "SXP via RTAv3"};
    if (id == 0xFE41) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Alarm Low (with security)"};
    if (id == 0xFE42) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "RSI (with security)"};
    if (id == 0xFEFC) return FrameIdInfo{ProfinetFrameKind::Dcp, "DCP Hello"};
    if (id == 0xFEFD) return FrameIdInfo{ProfinetFrameKind::Dcp, "DCP Get/Set"};
    if (id == 0xFEFE) return FrameIdInfo{ProfinetFrameKind::Dcp, "DCP Identify Request"};
    if (id == 0xFEFF) return FrameIdInfo{ProfinetFrameKind::Dcp, "DCP Identify Response"};
    if (id >= 0xFF00 && id <= 0xFF01) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "PTCP Announce"};
    if (id >= 0xFF20 && id <= 0xFF21) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "PTCP Follow Up"};
    if (id >= 0xFF40 && id <= 0xFF43) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Acyclic Real-Time: Delay"};
    if (id >= 0xFF80 && id <= 0xFF8F) return FrameIdInfo{ProfinetFrameKind::NamedOnly, "Fragmentation"};
    return std::nullopt;
}

// --- DCP naming tables --------------------------------------------------------------------------

std::string dcp_service_name(uint8_t service_id) {
    switch (service_id) {
        case 3: return "Get";
        case 4: return "Set";
        case 5: return "Identify";
        case 6: return "Hello";
        default: return "Unknown (" + hex2(service_id) + ")";
    }
}

std::string dcp_service_type_name(uint8_t service_type) {
    switch (service_type) {
        case 0: return "Request";
        case 1: return "Response-Success";
        case 5: return "Response-not-supported";
        default: return "Unknown (" + hex2(service_type) + ")";
    }
}

// --- DataStatus bit decoding ---------------------------------------------------------------------
// See profinet.hpp's file header comment's cyclic RT IO data section for the bit table and its
// provenance (packet-pn-rt.c's `dissect_DataStatus`).

std::string data_status_summary(uint8_t status) {
    std::ostringstream s;
    bool first = true;
    auto add = [&](const char* text) {
        if (!first) s << ",";
        s << text;
        first = false;
    };
    add((status & 0x01) ? "Primary" : "Backup");
    add((status & 0x04) ? "Valid" : "Invalid");
    add((status & 0x10) ? "Run" : "Stop");
    add((status & 0x20) ? "Ok" : "Problem");
    if (status & 0x80) add("Ignore");
    if (status & 0x08) add("reserved-bit-0x08-set");
    if (status & 0x40) add("reserved-bit-0x40-set");
    return s.str();
}

// --- DCP block decoding --------------------------------------------------------------------------

constexpr size_t kMaxDcpBlocks = 30;  // safety cap, same role as enip.cpp's kMaxCipIoCpfItems

// Option 0x01 (IP) and Option 0x02 (Device Properties) blocks are prefixed by a 2-byte BlockInfo
// or BlockQualifier field BEFORE their actual content, but only in specific (ServiceID,
// is_response) combinations -- cross-checked against packet-pn-dcp.c's `dissect_PNDCP_Suboption_
// Device`/`dissect_PNDCP_Suboption_IP` AND confirmed against a real device's wire bytes (see
// tests/real_captures/profinet/ATTRIBUTION.md: a real Identify Response's NameOfStation/DeviceID/
// DeviceRole/IPParameter blocks, and a real Set Request's IPParameter block, all carry this
// prefix -- missing it was caught during this decoder's real-capture validation, before this
// silently produced a station name with two leading NUL bytes). BlockInfo is present for
// Identify Response, Hello, and Get Response; BlockQualifier (same 2-byte size, different
// meaning -- this decoder does not surface either field's value) for Set Request; neither is
// present for Identify Request, Get Request, or Set Response.
size_t dcp_block_prefix_len(uint8_t service_id, bool is_response) {
    bool has_block_info = (service_id == 5 && is_response) ||   // Identify Response
                           (service_id == 6 && !is_response) ||  // Hello
                           (service_id == 3 && is_response);     // Get Response
    bool has_block_qualifier = (service_id == 4 && !is_response);  // Set Request
    return (has_block_info || has_block_qualifier) ? 2 : 0;
}

void decode_dcp_blocks(ByteSpan block_list, uint8_t service_id, bool is_response, ProfinetFrame& frame) {
    size_t prefix_len = dcp_block_prefix_len(service_id, is_response);
    Cursor c(block_list);
    size_t block_count = 0;
    while (c.remaining() >= 4 && block_count < kMaxDcpBlocks) {
        uint8_t option = c.u8();
        uint8_t suboption = c.u8();
        uint16_t block_length = c.u16be();
        if (block_length > c.remaining()) {
            frame.notes.push_back("DCP block option=" + hex2(option) + " suboption=" + hex2(suboption) +
                                   " declares " + std::to_string(block_length) + " byte(s) but only " +
                                   std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan body = c.bytes(block_length);
        ProfinetDcpBlock block;
        block.option = option;
        block.suboption = suboption;

        // Only Option 0x01/0x02 blocks carry the BlockInfo/BlockQualifier prefix -- see
        // dcp_block_prefix_len's comment. `content` is what's actually decoded below;
        // `block.value`'s raw-hex fallback always uses the untouched `body` instead, so a
        // malformed/short block (content.size() < the prefix) is never silently misread.
        bool has_prefix = (option == 0x01 || option == 0x02) && prefix_len > 0 && body.size() >= prefix_len;
        ByteSpan content = has_prefix ? body.from(prefix_len) : body;

        if (option == 0x01 && suboption == 0x01 && content.size() == 6) {
            // MAC Address.
            std::ostringstream s;
            for (size_t i = 0; i < 6; ++i) {
                if (i != 0) s << ":";
                s << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
                  << static_cast<unsigned>(content.at(i));
            }
            block.name = "MACAddress";
            block.value = s.str();
        } else if (option == 0x01 && suboption == 0x02 && content.size() == 12) {
            // IPParameter: IP(4) + SubnetMask(4) + StandardGateway(4), all big-endian.
            Cursor bc(content);
            uint32_t ip = bc.u32be();
            uint32_t mask = bc.u32be();
            uint32_t gw = bc.u32be();
            block.name = "IPParameter";
            block.value = "ip=" + format_ipv4(ip) + " subnet=" + format_ipv4(mask) + " gateway=" + format_ipv4(gw);
        } else if (option == 0x02 && suboption == 0x02) {
            // NameOfStation: ASCII, whole (prefix-stripped) block content.
            std::string text;
            text.reserve(content.size());
            for (size_t i = 0; i < content.size(); ++i) text += static_cast<char>(content.at(i));
            block.name = "NameOfStation";
            block.value = text;
            frame.dcp_name_of_station = text;
        } else if (option == 0x02 && suboption == 0x03 && content.size() == 4) {
            // DeviceID: VendorID(2) + DeviceID(2), big-endian.
            Cursor bc(content);
            uint16_t vendor_id = bc.u16be();
            uint16_t device_id = bc.u16be();
            block.name = "DeviceID";
            block.value = "vendor=" + hex4(vendor_id) + " device=" + hex4(device_id);
            frame.dcp_device_vendor_id = vendor_id;
            frame.dcp_device_id = device_id;
        } else if (option == 0x02 && suboption == 0x04 && content.size() >= 1) {
            // DeviceRole: role(1) + reserved(1).
            Cursor bc(content);
            uint8_t role = bc.u8();
            block.name = "DeviceRole";
            std::ostringstream s;
            s << hex2(role);
            if (role & 0x01) s << " [IO Device]";
            if (role & 0x02) s << " [IO Controller]";
            if (role & 0x04) s << " [IO Multidevice]";
            if (role & 0x08) s << " [PN Supervisor]";
            block.value = s.str();
        } else {
            block.value = to_hex(body);
        }

        frame.dcp_blocks.push_back(block);
        ++block_count;

        if (block_length % 2 != 0 && c.remaining() > 0) {
            c.u8();  // pad byte, word-alignment (see packet-pn-dcp.c's dissect_PNDCP_Block)
        }
    }
    if (block_count >= kMaxDcpBlocks) {
        frame.notes.push_back("stopped after " + std::to_string(kMaxDcpBlocks) + " DCP block(s) (safety cap)");
    }
}

void decode_dcp(ByteSpan payload_after_frame_id, ProfinetFrame& frame) {
    // ServiceID(1) + ServiceType(1) + Xid(4) + ResponseDelay-or-Reserved(2) + DCPDataLength(2) --
    // 10 bytes minimum before any block data (see this file's header comment's DCP section).
    if (payload_after_frame_id.size() < 10) {
        frame.notes.push_back("DCP PDU too short (" + std::to_string(payload_after_frame_id.size()) +
                               " byte(s)) for the fixed 10-byte header -- not decoded further");
        return;
    }
    Cursor c(payload_after_frame_id);
    uint8_t service_id = c.u8();
    uint8_t service_type = c.u8();
    uint32_t xid = c.u32be();
    c.u16be();  // ResponseDelay (Identify Request only) / Reserved -- not surfaced
    uint16_t data_length = c.u16be();

    frame.has_dcp = true;
    frame.dcp_service_id = service_id;
    frame.dcp_service_name = dcp_service_name(service_id);
    frame.dcp_service_type = service_type;
    frame.dcp_service_type_name = dcp_service_type_name(service_type);
    frame.dcp_xid = xid;

    size_t available = c.remaining();
    size_t effective_length = std::min<size_t>(data_length, available);
    if (effective_length < data_length) {
        frame.notes.push_back("DCPDataLength (" + std::to_string(data_length) +
                               ") exceeds the bytes actually available (" + std::to_string(available) +
                               ") -- decoding what's present");
    }
    ByteSpan block_list = c.bytes(effective_length);
    bool is_response = (service_type == 1 || service_type == 5);  // see dcp_block_prefix_len's comment
    decode_dcp_blocks(block_list, service_id, is_response, frame);

    std::ostringstream s;
    s << "DCP " << frame.dcp_service_name << " " << frame.dcp_service_type_name << " xid=" << hex8(xid);
    if (!frame.dcp_name_of_station.empty()) s << " name_of_station=\"" << frame.dcp_name_of_station << "\"";
    if (frame.dcp_device_vendor_id && frame.dcp_device_id) {
        s << " vendor=" << hex4(*frame.dcp_device_vendor_id) << " device=" << hex4(*frame.dcp_device_id);
    }
    frame.summary = s.str();

    for (const auto& block : frame.dcp_blocks) {
        if (block.name.empty()) {
            frame.notes.push_back("DCP block option=" + hex2(block.option) + " suboption=" + hex2(block.suboption) +
                                   " not decoded -- raw hex: " + block.value);
        }
    }
}

// --- Cyclic RT IO data decoding -------------------------------------------------------------------

void decode_cyclic(ByteSpan payload_after_frame_id, ProfinetFrame& frame) {
    // CycleCounter(2) + DataStatus(1) + TransferStatus(1) is a fixed 4-byte trailer at the very
    // end of the frame -- see this file's header comment's cyclic RT IO data section for why
    // there's no explicit length field for the IO data that precedes it.
    if (payload_after_frame_id.size() < 4) {
        frame.notes.push_back("cyclic RT frame too short (" + std::to_string(payload_after_frame_id.size()) +
                               " byte(s)) for the 4-byte CycleCounter/DataStatus/TransferStatus trailer -- "
                               "not decoded further");
        return;
    }
    size_t io_data_length = payload_after_frame_id.size() - 4;
    ByteSpan io_data = payload_after_frame_id.subspan(0, io_data_length);
    ByteSpan trailer = payload_after_frame_id.subspan(io_data_length, 4);
    Cursor tc(trailer);
    uint16_t cycle_counter = tc.u16be();
    uint8_t data_status = tc.u8();
    uint8_t transfer_status = tc.u8();

    frame.has_cyclic_data = true;
    frame.cyclic_io_data_hex = to_hex(io_data, "");
    frame.cyclic_io_data_length = io_data_length;
    frame.cyclic_cycle_counter = cycle_counter;
    frame.cyclic_data_status = data_status;
    frame.cyclic_data_status_summary = data_status_summary(data_status);
    frame.cyclic_transfer_status = transfer_status;

    std::ostringstream s;
    s << frame.frame_id_name << ": " << io_data_length << " byte(s) IO data, cycle_counter=" << cycle_counter
      << " data_status=[" << frame.cyclic_data_status_summary << "] transfer_status="
      << (transfer_status == 0 ? "OK" : "ignore this frame (" + hex2(transfer_status) + ")");
    frame.summary = s.str();

    if (io_data.empty()) {
        frame.notes.push_back("no IO data present (frame is exactly the 4-byte trailer) -- this may be a "
                               "genuinely empty I/O update, or an Ethernet-minimum-frame-padding "
                               "misclassification -- see this decoder's known limitation in profinet.hpp's "
                               "file header comment's cyclic RT IO data section");
    }
}

}  // namespace

std::optional<ProfinetFrame> try_parse_profinet(ByteSpan eth_payload) {
    if (eth_payload.size() < 2) {
        return std::nullopt;
    }
    try {
        Cursor c(eth_payload);
        uint16_t id = c.u16be();
        auto info = classify_frame_id(id);
        if (!info) {
            return std::nullopt;
        }

        ProfinetFrame frame;
        frame.frame_id = id;
        frame.frame_id_name = info->name;

        ByteSpan rest = c.rest();
        if (info->kind == ProfinetFrameKind::Dcp) {
            decode_dcp(rest, frame);
        } else if (info->kind == ProfinetFrameKind::Cyclic) {
            decode_cyclic(rest, frame);
        }

        if (frame.summary.empty()) {
            frame.summary = "PROFINET RT: " + frame.frame_id_name + " (frame_id=" + hex4(id) + ")";
        }
        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // enip.cpp's try_parse_cip_io takes.
        return std::nullopt;
    }
}

}  // namespace conduitscope
