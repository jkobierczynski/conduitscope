// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/hsrp.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxTlvs = resource_limits().max_decoded_objects.value_or(50);

std::string v1_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case 0: return "Hello";
        case 1: return "Coup";
        case 2: return "Resign";
        case 3: return "Advertise";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(opcode)) + ")";
    }
}

std::string v1_state_name(uint8_t state) {
    switch (state) {
        case 0: return "Initial";
        case 1: return "Learn";
        case 2: return "Listen";
        case 4: return "Speak";
        case 8: return "Standby";
        case 16: return "Active";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(state)) + ")";
    }
}

std::string tlv_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Group State";
        case 2: return "Interface State";
        case 3: return "Text Authentication";
        case 4: return "MD5 Authentication";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(type)) + ")";
    }
}

std::string strip_trailing_nul(ByteSpan span) {
    size_t len = span.size();
    while (len > 0 && span.at(len - 1) == 0) --len;
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) out.push_back(static_cast<char>(span.at(i)));
    return out;
}

std::string format_identifier(ByteSpan six_bytes) {
    std::ostringstream out;
    out << std::hex << std::uppercase;
    for (size_t i = 0; i < six_bytes.size(); ++i) {
        if (i > 0) out << ":";
        unsigned b = six_bytes.at(i);
        if (b < 16) out << "0";
        out << b;
    }
    return out.str();
}

bool try_parse_hsrp_v1(ByteSpan payload, HsrpMessage& msg) {
    if (payload.size() != 20) return false;
    if (payload.at(0) != 0) return false;
    uint8_t opcode = payload.at(1);
    uint8_t state = payload.at(2);
    if (opcode > 3) return false;
    static const uint8_t kValidStates[] = {0, 1, 2, 4, 8, 16};
    bool state_valid = false;
    for (uint8_t s : kValidStates) {
        if (s == state) { state_valid = true; break; }
    }
    if (!state_valid) return false;

    Cursor c(payload);
    c.u8();  // version, already checked == 0
    msg.version = 1;
    msg.opcode = c.u8();
    msg.opcode_name = v1_opcode_name(msg.opcode);
    msg.state = c.u8();
    msg.state_name = v1_state_name(msg.state);
    msg.hello_time_sec = c.u8();
    msg.hold_time_sec = c.u8();
    msg.priority = c.u8();
    msg.group = c.u8();
    c.u8();  // reserved
    msg.auth_data = strip_trailing_nul(c.bytes(8));
    msg.virtual_ip = format_ipv4(c.u32be());

    if (!msg.auth_data.empty()) {
        msg.notes.push_back(
            "HSRPv1 authentication is a cleartext plaintext field with no real security value -- "
            "see hsrp.hpp's own Security context note");
    }

    std::ostringstream out;
    out << "HSRPv1 " << msg.opcode_name << ": group " << static_cast<unsigned>(msg.group)
        << ", state " << msg.state_name << ", priority " << static_cast<unsigned>(msg.priority)
        << ", virtual IP " << msg.virtual_ip;
    // The literal authentication value is folded into the summary itself (not just a separate
    // field) so it's visible in every output format alike, including the default text dump --
    // HsrpDecoder::decode masks it here (and in this same summary string) when redaction is
    // active, see that function's own comment.
    if (!msg.auth_data.empty()) {
        out << ", auth \"" << msg.auth_data << "\"";
    }
    msg.summary = out.str();
    return true;
}

bool try_parse_hsrp_v2(ByteSpan payload, HsrpMessage& msg) {
    // Parse the whole payload as a flat TLV chain; the chain must consume every byte exactly, and
    // the very first TLV must be one of the four defined types -- see try_parse_hsrp's own
    // comment in hsrp.hpp for why both checks matter for a protocol with no magic number.
    std::vector<HsrpTlv> tlvs;
    size_t pos = 0;
    while (pos < payload.size()) {
        if (pos + 2 > payload.size()) return false;
        uint8_t type = payload.at(pos);
        uint8_t length = payload.at(pos + 1);
        if (pos + 2 + length > payload.size()) return false;
        ByteSpan value = payload.subspan(pos + 2, length);

        HsrpTlv tlv;
        tlv.type = type;
        tlv.type_name = tlv_type_name(type);
        tlv.length = length;

        if (type == 1 && length >= 24) {
            Cursor vc(value);
            tlv.hsrp_version = vc.u8();
            tlv.opcode = vc.u8();
            tlv.opcode_name = v1_opcode_name(tlv.opcode);
            tlv.state = vc.u8();
            tlv.state_name = v1_state_name(tlv.state);
            tlv.ip_version = vc.u8();
            tlv.group_number = vc.u16be();
            tlv.identifier = format_identifier(vc.bytes(6));
            tlv.priority = vc.u32be();
            tlv.hello_time_ms = vc.u32be();
            tlv.hold_time_ms = vc.u32be();
            if (tlv.ip_version == 4 && vc.remaining() >= 4) {
                tlv.virtual_ip = format_ipv4(vc.u32be());
                tlv.group_state_decoded = true;
            } else if (tlv.ip_version == 6) {
                // No IPv6 address formatting exists anywhere in this project -- see hsrp.hpp's
                // header comment. Everything else in the TLV is still fully decoded above.
                tlv.group_state_decoded = true;
                msg.notes.push_back(
                    "Group State TLV for group " + std::to_string(tlv.group_number) +
                    " declares an IPv6 virtual address, which this decoder does not format -- "
                    "not decoded");
            } else {
                msg.notes.push_back("Group State TLV for group " + std::to_string(tlv.group_number) +
                                     " is too short to contain its declared IPv4 virtual address");
            }
        } else if (type == 1) {
            msg.notes.push_back("Group State TLV is shorter than expected (" +
                                 std::to_string(length) + " byte(s)); not decoded");
        }

        if (!tlv.group_state_decoded) {
            tlv.raw_value_hex = to_hex(value);
        }

        tlvs.push_back(std::move(tlv));
        pos += 2 + length;
        if (tlvs.size() >= kMaxTlvs) break;
    }

    if (tlvs.empty()) return false;
    if (tlvs.front().type < 1 || tlvs.front().type > 4) return false;
    if (pos != payload.size()) {
        msg.tlvs_truncated = true;
        msg.notes.push_back("output capped at " + std::to_string(kMaxTlvs) +
                             " TLV(s); this packet declared more");
    }

    msg.version = 2;
    msg.tlvs = std::move(tlvs);

    std::ostringstream out;
    out << "HSRPv2: " << msg.tlvs.size() << " TLV(s)";
    for (const auto& tlv : msg.tlvs) {
        if (tlv.type == 1 && tlv.group_state_decoded) {
            out << " -- " << tlv.opcode_name << " group " << tlv.group_number << " state "
                << tlv.state_name;
            break;
        }
    }
    msg.summary = out.str();
    return true;
}

}  // namespace

std::optional<HsrpMessage> try_parse_hsrp(ByteSpan udp_payload) {
    HsrpMessage msg;
    if (try_parse_hsrp_v1(udp_payload, msg)) {
        return msg;
    }
    msg = HsrpMessage{};
    if (try_parse_hsrp_v2(udp_payload, msg)) {
        return msg;
    }
    return std::nullopt;
}

std::optional<ProtocolResult> HsrpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (auto msg = try_parse_hsrp(payload)) {
        // --redact (on by default -- see DecodeOptions::redact_secrets's own comment, decoder.hpp)
        // masks HSRPv1's own cleartext authentication value with a fixed placeholder in every
        // output format, rather than never decoding it at all -- the field's presence and length
        // are themselves a real, actionable OT-security finding (an HSRP group with authentication
        // "enabled" but no real protection), independent of the literal value. --no-redact shows
        // the real value, for parity with e.g. tshark's own packet-hsrp.c dissector.
        if (ctx.redact_secrets && !msg->auth_data.empty()) {
            msg->summary = redact_secret_occurrences(msg->summary, msg->auth_data);
            msg->auth_data = kRedactedSecretPlaceholder;
        }
        return ProtocolResult::make<HsrpMessage>("hsrp", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& hsrp_decoder() {
    static const HsrpDecoder instance;
    return instance;
}

}  // namespace conduitscope
