// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/codesys.hpp"

#include "conduitscope/ipv4.hpp"
#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// --- naming tables -----------------------------------------------------------------------------

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << (v < 16 ? "0" : "") << static_cast<unsigned>(v);
    return s.str();
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << v;
    return s.str();
}

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the literal
// defaults below.
size_t max_codesys_top_level_tags() { return resource_limits().max_decoded_objects.value_or(50); }
size_t max_codesys_nested_tags() { return resource_limits().max_decoded_objects.value_or(20); }

// --- tag-length-value payload walking -------------------------------------------------------
//
// See codesys.hpp's own PAYLOAD DECODE SCOPE paragraph: both the tag ID and the length are
// standard 7-bit-per-byte, LSB-first, continuation-bit(0x80) varints, confirmed directly from the
// dissector's own working parse code. Capped at 5 bytes here (35 bits of payload, comfortably
// covering the full 32-bit range this decoder ever needs) rather than mqtt.cpp's own
// read_pb_varint's 10-byte protobuf cap -- a deliberately smaller, CODESYS-specific limit, not a
// shared function, despite the identical bit-shape (see this file's own header comment on why this
// isn't reused from mqtt.cpp).
uint32_t read_codesys_varint(Cursor& c) {
    uint32_t value = 0;
    for (int i = 0; i < 5; ++i) {
        uint8_t b = c.u8();
        value |= static_cast<uint32_t>(b & 0x7F) << (7 * i);
        if ((b & 0x80) == 0) return value;
    }
    throw ParseError("CODESYS tag/length varint exceeds 5 bytes (malformed)");
}

struct CodesysTag {
    uint32_t id = 0;
    ByteSpan value;
};

// Reads every top-level tag-length-value entry out of `data` -- see codesys.hpp's own PAYLOAD
// DECODE SCOPE paragraph. Never throws: a malformed/truncated trailing tag simply stops the walk
// (returning whatever tags were read cleanly before that point) rather than failing the whole
// decode, since this is only ever called on payload bytes AFTER the Services header itself has
// already been structurally validated.
std::vector<CodesysTag> walk_codesys_tags(ByteSpan data, size_t max_tags) {
    std::vector<CodesysTag> tags;
    Cursor c(data);
    try {
        while (!c.at_end() && tags.size() < max_tags) {
            uint32_t id = read_codesys_varint(c);
            uint32_t len = read_codesys_varint(c);
            ByteSpan value = c.bytes(len);
            tags.push_back(CodesysTag{id, value});
        }
    } catch (const ParseError&) {
        // Truncated/malformed trailing bytes -- keep whatever was cleanly parsed so far.
    }
    return tags;
}

// --- address decode ------------------------------------------------------------------------

CodesysAddress decode_codesys_address(Cursor& c, size_t len) {
    CodesysAddress addr;
    addr.byte_length = len;
    ByteSpan bytes = c.bytes(len);
    addr.hex = to_hex(bytes, "");
    // Only the 6-byte shape (Port(2) + IPv4(4)) is confirmed -- see codesys.hpp's own DATAGRAM/
    // ROUTER LAYER paragraph, including why both fields are read network-byte-order/big-endian
    // (the same documented exception enip.hpp's own embedded sockaddr takes, for the same reason:
    // an address field, unlike the rest of this little-endian protocol, follows ordinary network
    // byte order).
    if (len == 6) {
        Cursor ac(bytes);
        uint16_t port = ac.u16be();
        uint32_t ip = ac.u32be();
        std::ostringstream s;
        s << format_ipv4(ip) << ":" << port;
        addr.decoded = s.str();
    }
    return addr;
}

}  // namespace

std::optional<std::string> codesys_datagram_service_name(uint8_t service_id) {
    switch (service_id) {
        case 0x01:
        case 0x02:
            return "Address Service";
        case 0x03:
        case 0x04:
            return "Name Service";
        case 0x40:
            return "Channel Service";
        default:
            return std::nullopt;
    }
}

bool codesys_datagram_service_is_channel(uint8_t service_id) { return service_id == 0x40; }

std::optional<std::string> codesys_channel_command_name(uint8_t command_id) {
    switch (command_id) {
        case 0xC2: return "GET_INFO";
        case 0xC3: return "OPEN_CHANNEL";
        case 0x83: return "OPEN_CHANNEL response";
        case 0xC4: return "CLOSE_CHANNEL";
        case 0x01: return "BLK";
        case 0x02: return "ACK";
        case 0x03: return "KEEPALIVE";
        default: return std::nullopt;
    }
}

std::optional<std::string> codesys_component_name(uint16_t component_id) {
    switch (component_id) {
        case 0x01: return "CmpDevice";
        case 0x02: return "CmpApp";
        case 0x08: return "CmpFileTransfer";
        case 0x09: return "CmpIecVarAccess";
        case 0x0C: return "CmpUserMgr";
        case 0x0F: return "CmpTraceMgr";
        case 0x1B: return "CmpMonitor2";
        default: return std::nullopt;
    }
}

namespace {

// Shared by both transports -- see codesys.hpp's own file header comment for the full layer-by-
// layer wire format this implements. `l3_bytes` starts at the very first byte of the Datagram/
// Router layer (byte 0 for UDP, byte 8 for TCP -- past the Block Driver header).
std::optional<CodesysFrame> try_parse_codesys_datagram_and_beyond(ByteSpan l3_bytes, bool is_tcp) {
    if (l3_bytes.size() < 6) {
        return std::nullopt;
    }
    Cursor c(l3_bytes);
    uint8_t magic = c.u8();
    if (magic != CODESYS_DATAGRAM_MAGIC) {
        return std::nullopt;
    }
    uint8_t hops_raw = c.u8();
    uint8_t packet_params_raw = c.u8();
    uint8_t service_id_raw = c.u8();
    auto service_name = codesys_datagram_service_name(service_id_raw);
    if (!service_name) {
        return std::nullopt;
    }
    uint8_t message_id_raw = c.u8();
    uint8_t address_lengths_raw = c.u8();
    size_t sender_len, receiver_len;
    if (address_lengths_raw == 0x43) {
        sender_len = 6;
        receiver_len = 8;
    } else if (address_lengths_raw == 0x34) {
        sender_len = 8;
        receiver_len = 6;
    } else {
        return std::nullopt;
    }

    CodesysFrame frame;
    frame.is_tcp = is_tcp;
    frame.datagram.hops_raw = hops_raw;
    frame.datagram.packet_params_raw = packet_params_raw;
    frame.datagram.service_id_raw = service_id_raw;
    frame.datagram.service_name = service_name;
    frame.datagram.message_id_raw = message_id_raw;
    frame.datagram.address_lengths_raw = address_lengths_raw;

    try {
        frame.datagram.sender = decode_codesys_address(c, sender_len);
        frame.datagram.receiver = decode_codesys_address(c, receiver_len);
    } catch (const ParseError&) {
        // Not enough bytes for the addresses this AddressLengths byte declared -- the Datagram
        // layer's own header (the real structural gate) already matched, but there's nothing
        // trustworthy to build a frame from.
        return std::nullopt;
    }

    std::ostringstream summary;
    summary << "CODESYS " << (is_tcp ? "TCP" : "UDP") << " " << *service_name;

    frame.has_channel = codesys_datagram_service_is_channel(service_id_raw);
    if (!frame.has_channel) {
        summary << " (Datagram/Router layer only -- no confirmed body format past this header, "
                    "see codesys.hpp's own file header comment)";
        frame.summary = summary.str();
        return frame;
    }

    if (c.remaining() < 20) {
        frame.notes.push_back("channel service declared but only " + std::to_string(c.remaining()) +
                               " byte(s) remain -- not enough for the 20-byte channel header");
        frame.summary = summary.str();
        return frame;
    }

    CodesysChannelHeader& ch = frame.channel;
    ch.command_id_raw = c.u8();
    ch.command_name = codesys_channel_command_name(ch.command_id_raw);
    ch.flags_raw = c.u8();
    ch.channel_id = c.u16le();
    ch.blk_num = c.u32le();
    ch.ack_num = c.u32le();
    ch.remaining_data_size = c.u32le();
    ch.checksum_raw = c.u32le();

    summary << "; channel " << (ch.command_name ? *ch.command_name : hex2(ch.command_id_raw))
            << " ch=" << ch.channel_id;
    if (!ch.command_name) {
        frame.notes.push_back("channel command id " + hex2(ch.command_id_raw) +
                               " is not one of the values confirmed by this decoder's own sources "
                               "-- shown raw");
    }

    ByteSpan channel_payload = c.rest();
    if (ch.command_id_raw == 0x01 /* BLK */ && !channel_payload.empty()) {
        bool validated = false;
        if (channel_payload.size() >= 20) {
            Cursor sc(channel_payload);
            uint16_t protocol_id = sc.u16le();
            if (protocol_id == 0xCD55 || protocol_id == 0x7557) {
                validated = true;
                CodesysServicesHeader& sv = frame.services;
                sv.protocol_id = protocol_id;
                sv.encrypted = (protocol_id == 0x7557);
                sv.header_size_raw = sc.u16le();
                sv.component_id = sc.u16le();
                sv.command_name = std::nullopt;
                sv.component_name = codesys_component_name(sv.component_id);
                sv.command_id = sc.u16le();
                sv.session_id = sc.u32le();
                sv.payload_size = sc.u32le();
                sv.additional_data_raw = sc.u32le();
                frame.has_services = true;

                bool is_login_auth = (sv.component_id == 0x01 && sv.command_id == 0x02);
                if (is_login_auth) {
                    sv.command_name = "Login (AUTH)";
                }

                summary << "; " << (sv.component_name ? *sv.component_name : hex4(sv.component_id))
                        << "::" << (sv.command_name ? *sv.command_name : hex4(sv.command_id))
                        << " session=" << sv.session_id;
                if (sv.encrypted) {
                    summary << " [encrypted]";
                }

                ByteSpan payload_data = sc.rest();
                if (sv.payload_size < payload_data.size()) {
                    payload_data = payload_data.subspan(0, sv.payload_size);
                } else if (sv.payload_size > payload_data.size() && payload_data.size() > 0) {
                    frame.notes.push_back(
                        "Services payload declares " + std::to_string(sv.payload_size) +
                        " byte(s) but only " + std::to_string(payload_data.size()) +
                        " are present in this captured frame -- decoding what's present");
                }

                if (is_login_auth && sv.encrypted && !payload_data.empty()) {
                    // A genuine SecureProtocol (0x7557) message's payload is encrypted on the wire
                    // -- tag-walking it as if it were the plaintext structure documented for
                    // unencrypted (0xCD55) Login/AUTH would misinterpret ciphertext bytes as real
                    // tag IDs/lengths, producing plausible-looking but meaningless output. This
                    // decoder has no access to whatever key exchange establishes the encryption
                    // (not documented in either of this file's own sources), so it declines
                    // entirely rather than guess.
                    frame.notes.push_back(
                        "Login/AUTH payload (" + std::to_string(payload_data.size()) +
                        " byte(s)) is under SecureProtocol encryption -- not tag-decoded");
                } else if (is_login_auth && !payload_data.empty()) {
                    // See codesys.hpp's own PAYLOAD DECODE SCOPE paragraph: this is the ONLY
                    // component/command combination this decoder tag-walks for semantic content.
                    auto top_tags = walk_codesys_tags(payload_data, max_codesys_top_level_tags());
                    for (const auto& tag : top_tags) {
                        if (tag.id == 0x81) {
                            auto nested = walk_codesys_tags(tag.value, max_codesys_nested_tags());
                            for (const auto& child : nested) {
                                if (child.id == 0x10) {
                                    frame.has_auth_username = true;
                                    frame.auth_username.assign(
                                        reinterpret_cast<const char*>(child.value.data()),
                                        child.value.size());
                                } else if (child.id == 0x11) {
                                    frame.auth_password_present = true;
                                    frame.auth_password_length = child.value.size();
                                }
                            }
                        } else if (tag.id == 0x21) {
                            if (tag.value.size() == 4) {
                                Cursor vc(tag.value);
                                frame.auth_session_id = vc.u32le();
                                frame.has_auth_session_id = true;
                            } else {
                                frame.notes.push_back(
                                    "Login/AUTH response's own session-id tag (0x21) is " +
                                    std::to_string(tag.value.size()) +
                                    " byte(s), not the expected 4 -- not decoded");
                            }
                        }
                    }
                    if (frame.has_auth_username) {
                        summary << " user=\"" << frame.auth_username << "\"";
                    }
                    if (frame.auth_password_present) {
                        frame.notes.push_back(
                            "Login/AUTH request carries a password field (" +
                            std::to_string(frame.auth_password_length) +
                            " byte(s)) -- never rendered by this decoder regardless of whether "
                            "it is genuinely encrypted on the wire");
                    }
                    if (frame.has_auth_session_id) {
                        summary << " new_session=" << frame.auth_session_id;
                    }
                }
            }
        }
        if (!validated) {
            frame.services_undecoded_payload_present = true;
            frame.services_undecoded_payload_length = channel_payload.size();
            frame.notes.push_back(
                "channel payload (" + std::to_string(channel_payload.size()) +
                " byte(s)) present but does not structurally validate as a fresh Services "
                "header -- likely a continuation block of a larger multi-block transfer this "
                "decoder does not reassemble, or a component/command whose payload shape isn't "
                "recognized; see codesys.hpp's own STRUCTURAL VALIDATION paragraph");
        }
    } else if (!channel_payload.empty()) {
        frame.notes.push_back("channel payload (" + std::to_string(channel_payload.size()) +
                               " byte(s)) present for a non-BLK command -- not decoded");
    }

    frame.summary = summary.str();
    return frame;
}

}  // namespace

std::optional<size_t> codesys_tcp_declared_length(ByteSpan payload) {
    if (payload.size() < 8) {
        return std::nullopt;
    }
    Cursor c(payload);
    uint32_t magic = c.u32le();
    if (magic != CODESYS_TCP_BLOCK_DRIVER_MAGIC) {
        return std::nullopt;
    }
    uint32_t length = c.u32le();
    if (length < 8 || length > CODESYS_TCP_MAX_FRAME_LENGTH) {
        return std::nullopt;
    }
    return static_cast<size_t>(length);
}

std::optional<CodesysFrame> try_parse_codesys_tcp(ByteSpan tcp_payload) {
    if (tcp_payload.size() < 8) {
        return std::nullopt;
    }
    Cursor c(tcp_payload);
    uint32_t magic = c.u32le();
    if (magic != CODESYS_TCP_BLOCK_DRIVER_MAGIC) {
        return std::nullopt;
    }
    uint32_t length = c.u32le();
    if (length < 8 || length > CODESYS_TCP_MAX_FRAME_LENGTH) {
        return std::nullopt;
    }
    size_t declared_body = static_cast<size_t>(length) - 8;
    size_t available_body = tcp_payload.size() >= 8 ? tcp_payload.size() - 8 : 0;
    size_t take = std::min(declared_body, available_body);
    ByteSpan l3_bytes = tcp_payload.subspan(8, take);

    auto frame = try_parse_codesys_datagram_and_beyond(l3_bytes, /*is_tcp=*/true);
    if (!frame) {
        return std::nullopt;
    }
    if (take < declared_body) {
        frame->notes.push_back("Block Driver layer declares a " + std::to_string(length) +
                                "-byte message but only " + std::to_string(available_body + 8) +
                                " bytes are present in this captured frame -- decoding what's "
                                "present");
    }
    return frame;
}

std::optional<CodesysFrame> try_parse_codesys_udp(ByteSpan udp_payload) {
    return try_parse_codesys_datagram_and_beyond(udp_payload, /*is_tcp=*/false);
}

std::optional<ProtocolResult> CodesysTcpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_codesys_tcp(payload);
    if (!frame) {
        return std::nullopt;
    }
    return ProtocolResult::make<CodesysFrame>("codesys", std::move(*frame));
}

std::optional<ProtocolResult> CodesysUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_codesys_udp(payload);
    if (!frame) {
        return std::nullopt;
    }
    return ProtocolResult::make<CodesysFrame>("codesys", std::move(*frame));
}

const ProtocolDecoder& codesys_tcp_decoder() {
    static const CodesysTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& codesys_udp_decoder() {
    static const CodesysUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
