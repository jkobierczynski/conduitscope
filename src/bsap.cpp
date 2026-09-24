// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/bsap.hpp"

#include <sstream>
#include <unordered_map>

namespace conduitscope {

namespace {

constexpr uint16_t kSerialTunnelMagic = 0x0210;

const std::unordered_map<uint8_t, std::string>& link_function_table() {
    static const std::unordered_map<uint8_t, std::string> table = {
        {0x85, "POLL"},
        {0x86, "ACK / DOWN-ACK"},
        {0x87, "ACK-NODATA"},
        {0x8B, "UP-ACK"},
        {0x95, "NAK"},
    };
    return table;
}

std::string hex(ByteSpan span) { return to_hex(span, ""); }

std::string hex_byte(uint8_t v) { return hex(ByteSpan(&v, 1)); }

}  // namespace

std::optional<std::string> bsap_link_function_name(uint8_t code) {
    const auto& table = link_function_table();
    auto it = table.find(code);
    if (it == table.end()) return std::nullopt;
    return it->second;
}

std::optional<BsapFrame> try_parse_bsap(ByteSpan udp_payload) {
    if (udp_payload.size() < 2) return std::nullopt;

    try {
        Cursor c(udp_payload);
        uint16_t proto = c.u16le();
        BsapFrame frame;

        if (proto == kSerialTunnelMagic) {
            frame.is_serial_tunnel = true;

            // Smallest possible frame: ADDR + Local header (SER+DFUN+SEQ+SFUN+NSB, 6 bytes).
            if (c.remaining() < 6) return std::nullopt;

            frame.addr_raw = c.u8();
            frame.is_global = (frame.addr_raw & 0x80) != 0;
            frame.local_address = frame.addr_raw & 0x7F;
            frame.ser = c.u8();

            if (frame.is_global) {
                // DADD(2) + SADD(2) + CTL(1) + DFUN(1) + SEQ(2) + SFUN(1) + NSB(1) = 10 bytes.
                if (c.remaining() < 10) return std::nullopt;
                frame.has_global_addressing = true;
                frame.dadd = c.u16le();
                frame.sadd = c.u16le();
                frame.ctl = c.u8();
                frame.dfun_raw = c.u8();
                frame.seq = c.u16le();
                frame.sfun_raw = c.u8();
                frame.nsb = c.u8();
            } else {
                // DFUN(1) + SEQ(2) + SFUN(1) + NSB(1) = 5 bytes.
                if (c.remaining() < 5) return std::nullopt;
                frame.dfun_raw = c.u8();
                frame.seq = c.u16le();
                frame.sfun_raw = c.u8();
                frame.nsb = c.u8();
            }
            frame.dfun_name = bsap_link_function_name(frame.dfun_raw);
            frame.sfun_name = bsap_link_function_name(frame.sfun_raw);

            ByteSpan trailing = c.rest();
            frame.has_trailing_data = !trailing.empty();
            frame.trailing_data_byte_count = trailing.size();
            if (frame.has_trailing_data) frame.trailing_data_hex = hex(trailing);

            std::ostringstream summary;
            summary << "BSAP serial-tunneled " << (frame.is_global ? "Global" : "Local")
                    << " message: addr=" << static_cast<unsigned>(frame.local_address) << " ser="
                    << static_cast<unsigned>(frame.ser) << " seq=" << frame.seq << " dfun="
                    << (frame.dfun_name ? *frame.dfun_name : ("0x" + hex_byte(frame.dfun_raw)))
                    << " sfun="
                    << (frame.sfun_name ? *frame.sfun_name : ("0x" + hex_byte(frame.sfun_raw)));
            frame.summary = summary.str();

            if (frame.dfun_raw == 0x95 || frame.sfun_raw == 0x95) {
                frame.notes.push_back(
                    "NAK observed -- a negative acknowledgment at BSAP's own link layer "
                    "(communication or access failure between these two devices)");
            }
        } else {
            frame.is_serial_tunnel = false;
            frame.leading_value = proto;

            if (c.remaining() < 2) return std::nullopt;
            frame.message_func = c.u16le();

            ByteSpan trailing = c.rest();
            frame.has_trailing_data = !trailing.empty();
            frame.trailing_data_byte_count = trailing.size();
            if (frame.has_trailing_data) frame.trailing_data_hex = hex(trailing);

            std::ostringstream summary;
            summary << "BSAP-IP-native message: leading_value=" << frame.leading_value
                    << " message_func=0x" << std::hex << frame.message_func << std::dec;
            if (frame.has_trailing_data) {
                summary << " (" << frame.trailing_data_byte_count
                        << " byte(s) of body, not further decoded -- see bsap.hpp)";
            }
            frame.summary = summary.str();
        }

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> BsapDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_bsap(payload);
    if (!frame) return std::nullopt;
    return ProtocolResult::make<BsapFrame>("bsap", std::move(*frame));
}

const ProtocolDecoder& bsap_decoder() {
    static const BsapDecoder instance;
    return instance;
}

}  // namespace conduitscope
