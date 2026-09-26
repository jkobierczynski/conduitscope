// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/cclink_ie.hpp"

#include <array>
#include <sstream>
#include <unordered_map>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/link_layer.hpp"

namespace conduitscope {

namespace {

constexpr uint16_t kCyclicReqMagic = 0x5000;
constexpr uint16_t kCyclicRespMagic = 0xD000;
constexpr uint16_t kSlmpReqMagic = 0x5400;
constexpr uint16_t kSlmpRespMagic = 0xD400;

constexpr uint16_t kCommandCyclic = 0x0E70;
constexpr uint16_t kCommandNodeSearch = 0x0E30;
constexpr uint16_t kCommandSetIpAddress = 0x0E31;

const std::unordered_map<uint16_t, std::string>& end_code_table() {
    static const std::unordered_map<uint16_t, std::string> table = {
        {uint16_t{0x0000}, "success"},
        {uint16_t{0xC059}, "command error"},
        {uint16_t{0xC05C}, "command request message error"},
        {uint16_t{0xC61C}, "request data length mismatch"},
        {uint16_t{0xCCC7}, "CANopen: wrong condition"},
        {uint16_t{0xCCC8}, "CANopen: write only"},
        {uint16_t{0xCCC9}, "CANopen: read only"},
        {uint16_t{0xCCCA}, "CANopen: object not defined"},
        {uint16_t{0xCCCB}, "CANopen: PDO mapping not allowed"},
        {uint16_t{0xCCCC}, "CANopen: PDO data length mismatch"},
        {uint16_t{0xCCD0}, "CANopen: data value number mismatch"},
        {uint16_t{0xCCD1}, "CANopen: data value number too large"},
        {uint16_t{0xCCD2}, "CANopen: data value number too small"},
        {uint16_t{0xCCD3}, "CANopen: subindex does not exist"},
        {uint16_t{0xCCD4}, "CANopen: invalid parameter"},
        {uint16_t{0xCCD5}, "CANopen: value too large"},
        {uint16_t{0xCCD6}, "CANopen: value too small"},
        {uint16_t{0xCCDA}, "CANopen: storing/transmitting impossible"},
        {uint16_t{0xCCFF}, "CANopen: other error"},
        {uint16_t{0xCEE0}, "request busy"},
        {uint16_t{0xCEE1}, "request too large"},
        {uint16_t{0xCEE2}, "response too large"},
        {uint16_t{0xCF00}, "gateway error"},
        {uint16_t{0xCF10}, "server information does not exist"},
        {uint16_t{0xCF20}, "cannot be set"},
        {uint16_t{0xCF30}, "parameter does not exist"},
        {uint16_t{0xCF31}, "parameter writing in wrong state"},
        {uint16_t{0xCF40}, "divided message timeout"},
        {uint16_t{0xCF41}, "divided message duplicate"},
        {uint16_t{0xCF42}, "divided message data error"},
        {uint16_t{0xCF43}, "divided message lost"},
        {uint16_t{0xCF44}, "divided message not supported"},
        {uint16_t{0xCF70}, "communication relay error"},
        {uint16_t{0xCF71}, "communication timeout"},
        {uint16_t{0xCFE0}, "CCIEFB: master station duplication"},
        {uint16_t{0xCFE1}, "CCIEFB: wrong number of occupied stations"},
        {uint16_t{0xCFF0}, "CCIEFB: error in slave station"},
        {uint16_t{0xCFFF}, "CCIEFB: disconnection notification from slave station"},
    };
    return table;
}

std::optional<std::string> local_unit_info_name(uint16_t v) {
    switch (v) {
        case 0x0000: return "stopped";
        case 0x0001: return "running";
        case 0x0002: return "stopped by user";
        default: return std::nullopt;
    }
}

std::optional<std::string> slave_local_unit_info_name(uint16_t v) {
    switch (v) {
        case 0: return "stopped";
        case 1: return "operating";
        default: return std::nullopt;
    }
}

std::string read_mac_reversed(Cursor& c) {
    // The wire stores these 6 bytes in reverse order relative to conventional colon-notation
    // display order -- confirmed via the rt-labs reference stack's own cl_util_copy_mac_reverse()
    // helper (see cclink_ie.hpp's own "SLMP NODE SEARCH" section).
    std::array<uint8_t, 6> raw{};
    for (int i = 0; i < 6; ++i) raw[i] = c.u8();
    std::array<uint8_t, 6> mac{};
    for (int i = 0; i < 6; ++i) mac[i] = raw[5 - i];
    return format_mac(mac);
}

std::string read_ipv4(Cursor& c) { return format_ipv4(c.u32le()); }

}  // namespace

std::optional<std::string> cclink_ie_end_code_name(uint16_t code) {
    const auto& table = end_code_table();
    auto it = table.find(code);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

std::optional<CclinkIeFrame> try_parse_cclink_ie_cyclic_request(ByteSpan udp_payload) {
    if (udp_payload.size() < 15) return std::nullopt;
    try {
        Cursor c(udp_payload);
        if (c.u16be() != kCyclicReqMagic) return std::nullopt;
        c.u8();               // Network No., always 0x00 for CCIEFB -- not gated on
        c.u8();                // PC No., always 0xFF
        c.u16le();             // Request Destination Module I/O No., always 0x03FF
        c.u8();                // Request Destination Module Station No., always 0x00
        uint16_t dl = c.u16le();
        c.u16le();              // Monitoring Timer, always 0x0000 for CCIEFB
        uint16_t command = c.u16le();
        uint16_t subcommand = c.u16le();
        if (command != kCommandCyclic || subcommand != 0x0000) return std::nullopt;

        // Declared-length cross-check, mirroring MELSEC's own (melsec.hpp): dl is defined as the
        // byte count from immediately after the dl field to the end of the payload.
        if (dl != udp_payload.size() - 9) return std::nullopt;

        if (c.remaining() < 20 + 12 + 20) return std::nullopt;
        CclinkIeFrame frame;
        frame.kind = CclinkIeMessageKind::CyclicRequest;

        frame.protocol_ver = c.u16le();
        c.u16le();  // reserved, always 0x0000
        frame.cyclic_info_offset_addr = c.u16le();
        c.skip(14);  // reserved

        frame.master_local_unit_info = c.u16le();
        frame.master_local_unit_info_name = local_unit_info_name(frame.master_local_unit_info);
        c.u16le();  // reserved, always 0x0000
        frame.clock_info_unix_ms = c.u64le();

        frame.master_id = read_ipv4(c);
        frame.group_no = c.u8();
        c.u8();  // reserved
        frame.frame_sequence_no = c.u16le();
        frame.timeout_value = c.u16le();
        frame.parallel_off_timeout_count = c.u16le();
        frame.parameter_no = c.u16le();
        frame.slave_total_occupied_station_count = c.u16le();
        frame.cyclic_transmission_state = c.u16le();
        c.u16le();  // reserved, always 0x0000

        uint16_t n = frame.slave_total_occupied_station_count;
        size_t expected_trailing = static_cast<size_t>(n) * (4 + 64 + 8);
        if (c.remaining() != expected_trailing) return std::nullopt;
        frame.occupied_stations = n;
        frame.cyclic_io_byte_count = expected_trailing;

        std::ostringstream summary;
        summary << "CC-Link IE Field Basic cyclic request: master=" << frame.master_id
                << " group=" << static_cast<unsigned>(frame.group_no)
                << " seq=" << frame.frame_sequence_no << " parameterNo=" << frame.parameter_no
                << " " << n << " occupied station(s), " << frame.cyclic_io_byte_count
                << " byte(s) of cyclic I/O data (slave IDs + RWw + RY, not rendered per-point -- "
                   "see cclink_ie.hpp)";
        frame.summary = summary.str();
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<CclinkIeFrame> try_parse_cclink_ie_cyclic_response(ByteSpan udp_payload) {
    if (udp_payload.size() < 11 + 20 + 20 + 8) return std::nullopt;
    try {
        Cursor c(udp_payload);
        if (c.u16be() != kCyclicRespMagic) return std::nullopt;
        c.u8();       // Network No.
        c.u8();       // PC No.
        c.u16le();    // I/O No.
        c.u8();       // Station No.
        uint16_t dl = c.u16le();
        c.u16le();     // reserved, always 0x0000 (CCIEFB's own response header, unlike generic
                       // SLMP, carries no End Code here -- see cclink_ie.hpp)
        if (dl != udp_payload.size() - 9) return std::nullopt;

        CclinkIeFrame frame;
        frame.kind = CclinkIeMessageKind::CyclicResponse;

        frame.protocol_ver = c.u16le();
        frame.end_code = c.u16le();
        frame.end_code_name = cclink_ie_end_code_name(frame.end_code);
        frame.cyclic_info_offset_addr = c.u16le();
        c.skip(14);

        frame.vendor_code = c.u16le();
        c.u16le();  // reserved
        frame.model_code = c.u32le();
        frame.equipment_ver = c.u16le();
        c.u16le();  // reserved
        frame.slave_local_unit_info = c.u16le();
        frame.slave_local_unit_info_name = slave_local_unit_info_name(frame.slave_local_unit_info);
        frame.slave_err_code = c.u16le();
        frame.local_management_info = c.u32le();

        frame.slave_id = read_ipv4(c);
        frame.group_no = c.u8();
        c.u8();  // reserved
        frame.frame_sequence_no = c.u16le();

        // Unlike the request, the response carries no explicit occupied-station-count field --
        // derived arithmetically from what remains, mirroring the reference stack's own
        // cl_calculate_number_of_occupied_stations(). Must divide evenly; a remainder means this
        // isn't a well-formed CCIEFB response.
        size_t remaining = c.remaining();
        if (remaining % 72 != 0) return std::nullopt;
        uint16_t n = static_cast<uint16_t>(remaining / 72);
        frame.occupied_stations = n;
        frame.cyclic_io_byte_count = remaining;

        std::ostringstream summary;
        summary << "CC-Link IE Field Basic cyclic response: slave=" << frame.slave_id
                << " group=" << static_cast<unsigned>(frame.group_no)
                << " seq=" << frame.frame_sequence_no << " end_code="
                << (frame.end_code_name ? *frame.end_code_name
                                         : ("0x" + std::to_string(frame.end_code)));
        if (frame.end_code == 0) {
            summary << " " << n << " occupied station(s), " << frame.cyclic_io_byte_count
                     << " byte(s) of cyclic I/O data (RWr + RX, not rendered per-point)";
        }
        frame.summary = summary.str();

        if (frame.end_code != 0) {
            frame.notes.push_back("CCIEFB cyclic response reports a non-success end code (" +
                                   (frame.end_code_name ? *frame.end_code_name : "unrecognized") +
                                   ")");
        }
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<CclinkIeFrame> try_parse_cclink_ie_slmp_request(ByteSpan udp_payload) {
    if (udp_payload.size() < 19) return std::nullopt;
    try {
        Cursor c(udp_payload);
        if (c.u16be() != kSlmpReqMagic) return std::nullopt;
        uint16_t serial = c.u16le();
        c.u16le();  // reserved sub2, always 0x0000
        c.u8();     // Network No.
        c.u8();     // Unit No.
        c.u16le();  // I/O No.
        c.u8();     // Extension
        uint16_t length = c.u16le();
        c.u16le();  // Timer, always 0x0000
        uint16_t command = c.u16le();
        uint16_t subcommand = c.u16le();
        if (subcommand != 0x0000) return std::nullopt;
        if (length != udp_payload.size() - 13) return std::nullopt;

        CclinkIeFrame frame;
        frame.serial = serial;

        if (command == kCommandNodeSearch) {
            if (c.remaining() != 11) return std::nullopt;
            frame.kind = CclinkIeMessageKind::NodeSearchRequest;
            frame.master_mac = read_mac_reversed(c);
            c.u8();  // Master IP Address Size, always 4
            frame.master_ip = read_ipv4(c);

            std::ostringstream summary;
            summary << "CC-Link IE / SLMP node search request: master=" << frame.master_mac << " ("
                    << frame.master_ip << ")";
            frame.summary = summary.str();
            frame.notes.push_back(
                "node search: passive asset-discovery broadcast, elicits vendor/model/MAC/IP "
                "disclosure from every slave on the segment");
            return frame;
        } else if (command == kCommandSetIpAddress) {
            if (c.remaining() != 39) return std::nullopt;
            frame.kind = CclinkIeMessageKind::SetIpAddressRequest;
            frame.master_mac = read_mac_reversed(c);
            c.u8();  // Master IP Address Size
            frame.master_ip = read_ipv4(c);
            frame.slave_mac = read_mac_reversed(c);
            c.u8();  // Slave IP Address Size
            frame.slave_ip = read_ipv4(c);  // the slave's NEW IP address being assigned
            frame.slave_netmask = read_ipv4(c);
            c.u32le();  // Slave Default Gateway, always 0xFFFFFFFF
            c.u8();     // Slave Hostname Size, always 0
            c.u8();     // Target IP Address Size
            c.u32le();  // Target IP Address, always 0xFFFFFFFF
            c.u16le();  // Target Port, always 0xFFFF
            c.u8();     // Slave Protocol Settings, always 0x01 (UDP)

            std::ostringstream summary;
            summary << "CC-Link IE / SLMP set IP address request: master=" << frame.master_mac
                    << " target slave=" << frame.slave_mac << " new IP=" << frame.slave_ip
                    << " new netmask=" << frame.slave_netmask;
            frame.summary = summary.str();
            frame.notes.push_back(
                "set IP address: remotely reassigns a slave's own network identity -- no "
                "credential of any kind is documented for this operation in either sourcing "
                "reference, see cclink_ie.hpp's own security-context section");
            return frame;
        }
        return std::nullopt;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<CclinkIeFrame> try_parse_cclink_ie_slmp_response(ByteSpan udp_payload,
                                                                 CclinkIeMessageKind expected_kind) {
    if (expected_kind != CclinkIeMessageKind::NodeSearchResponse &&
        expected_kind != CclinkIeMessageKind::SetIpAddressResponse) {
        return std::nullopt;
    }
    if (udp_payload.size() < 15) return std::nullopt;
    try {
        Cursor c(udp_payload);
        if (c.u16be() != kSlmpRespMagic) return std::nullopt;
        uint16_t serial = c.u16le();
        c.u16le();  // reserved sub2
        c.u8();     // Network No.
        c.u8();     // Unit No.
        c.u16le();  // I/O No.
        c.u8();     // Extension
        uint16_t length = c.u16le();
        uint16_t end_code = c.u16le();
        if (length != udp_payload.size() - 13) return std::nullopt;

        CclinkIeFrame frame;
        frame.kind = expected_kind;
        frame.serial = serial;
        frame.end_code = end_code;
        frame.end_code_name = cclink_ie_end_code_name(end_code);

        if (end_code != 0) {
            // Error path: the reference stack's own error-response shape carries no
            // command-specific body at all (just the echoed addressing fields), so this decoder
            // does not assume the normal success-body shape/length here -- honest, undecoded
            // fallback rather than a guess, the same posture MELSEC/GE SRTP already take for
            // their own error/Nack responses.
            std::ostringstream summary;
            summary << "CC-Link IE / SLMP "
                    << (expected_kind == CclinkIeMessageKind::NodeSearchResponse ? "node search"
                                                                                  : "set IP address")
                    << " response: error end_code="
                    << (frame.end_code_name ? *frame.end_code_name
                                              : ("0x" + std::to_string(end_code)));
            frame.summary = summary.str();
            frame.notes.push_back("non-success end code, response body not decoded");
            return frame;
        }

        if (expected_kind == CclinkIeMessageKind::NodeSearchResponse) {
            if (c.remaining() != 51) return std::nullopt;
            frame.master_mac = read_mac_reversed(c);
            c.u8();
            frame.master_ip = read_ipv4(c);
            frame.slave_mac = read_mac_reversed(c);
            c.u8();
            frame.slave_ip = read_ipv4(c);
            frame.slave_netmask = read_ipv4(c);
            c.u32le();  // Slave Default Gateway, always 0xFFFFFFFF
            c.u8();     // Slave Hostname Size, always 0
            frame.vendor_code = c.u16le();
            frame.model_code = c.u32le();
            frame.equipment_ver = c.u16le();
            c.u8();     // Target IP Address Size
            c.u32le();  // Target IP Address, always 0xFFFFFFFF
            c.u16le();  // Target Port, always 0xFFFF
            uint16_t slave_status = c.u16le();
            c.u16le();  // Slave Port, always 61451
            c.u8();     // Slave Protocol Settings, always 0x01 (UDP)

            std::ostringstream summary;
            summary << "CC-Link IE / SLMP node search response: slave=" << frame.slave_mac << " ("
                    << frame.slave_ip << ", netmask " << frame.slave_netmask
                    << ") vendor=0x" << std::hex << frame.vendor_code << " model=0x"
                    << frame.model_code << std::dec << " equipment_ver=" << frame.equipment_ver;
            frame.summary = summary.str();
            if (slave_status != 0) {
                frame.notes.push_back("slave reports a non-normal status (0x" +
                                       std::to_string(slave_status) + ")");
            }
        } else {
            if (c.remaining() != 6) return std::nullopt;
            frame.master_mac = read_mac_reversed(c);
            std::ostringstream summary;
            summary << "CC-Link IE / SLMP set IP address response: acknowledged to master="
                    << frame.master_mac;
            frame.summary = summary.str();
        }
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> CclinkIeDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (payload.size() < 2) return std::nullopt;
    uint16_t magic;
    try {
        Cursor peek(payload);
        magic = peek.u16be();
    } catch (const ParseError&) {
        return std::nullopt;
    }

    if (magic != kCyclicReqMagic && magic != kCyclicRespMagic && magic != kSlmpReqMagic &&
        magic != kSlmpRespMagic) {
        return std::nullopt;
    }

    CclinkIeFlowState& state = ctx.flow_state<CclinkIeFlowState>();
    std::optional<CclinkIeFrame> frame;

    if (magic == kCyclicReqMagic) {
        frame = try_parse_cclink_ie_cyclic_request(payload);
    } else if (magic == kSlmpReqMagic) {
        frame = try_parse_cclink_ie_slmp_request(payload);
    } else if (magic == kCyclicRespMagic) {
        if (state.pending && state.pending->kind == CclinkIeMessageKind::CyclicRequest) {
            frame = try_parse_cclink_ie_cyclic_response(payload);
        }
        // No tracked pending cyclic request on this session -- deliberately NOT claimed (falls
        // through to the generic MELSEC decoder instead of being guessed at). See cclink_ie.hpp's
        // "RESPONSES CARRY NO COMMAND FIELD" section.
    } else {  // kSlmpRespMagic
        if (state.pending && (state.pending->kind == CclinkIeMessageKind::NodeSearchRequest ||
                               state.pending->kind == CclinkIeMessageKind::SetIpAddressRequest)) {
            CclinkIeMessageKind expected = (state.pending->kind == CclinkIeMessageKind::NodeSearchRequest)
                                                ? CclinkIeMessageKind::NodeSearchResponse
                                                : CclinkIeMessageKind::SetIpAddressResponse;
            frame = try_parse_cclink_ie_slmp_response(payload, expected);
        }
    }

    if (!frame) return std::nullopt;

    bool is_request = frame->kind == CclinkIeMessageKind::CyclicRequest ||
                       frame->kind == CclinkIeMessageKind::NodeSearchRequest ||
                       frame->kind == CclinkIeMessageKind::SetIpAddressRequest;
    if (is_request) {
        if (state.pending) {
            frame->notes.push_back(
                "a previous CC-Link IE request on this session was never matched with a response "
                "before this new request was sent -- only the most recently sent outstanding "
                "request is tracked, mirroring MELSEC's own MelsecFlowState");
        }
        state.pending = CclinkIePendingRequest{frame->kind, ctx.packet_index};
    } else {
        frame->notes.push_back("matched to the request seen in packet #" +
                                std::to_string(state.pending->packet_index) +
                                " on this session -- CC-Link IE responses carry no command field "
                                "of their own on the wire, see cclink_ie.hpp");
        state.pending.reset();
    }

    return ProtocolResult::make<CclinkIeFrame>("cclink-ie", std::move(*frame));
}

const ProtocolDecoder& cclink_ie_decoder() {
    static const CclinkIeDecoder instance;
    return instance;
}

}  // namespace conduitscope
