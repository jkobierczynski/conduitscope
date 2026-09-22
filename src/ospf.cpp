// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ospf.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxList = resource_limits().max_decoded_objects.value_or(50);
constexpr size_t kHeaderLength = 24;
constexpr size_t kLsaHeaderLength = 20;

std::string strip_trailing_nul(ByteSpan span) {
    size_t len = span.size();
    while (len > 0 && span.at(len - 1) == 0) --len;
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) out.push_back(static_cast<char>(span.at(i)));
    return out;
}

std::string ospf_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Hello";
        case 2: return "DB Description";
        case 3: return "LS Request";
        case 4: return "LS Update";
        case 5: return "LS Ack";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(type)) + ")";
    }
}

std::string auth_type_name(uint8_t auth_type) {
    switch (auth_type) {
        case 0: return "Null";
        case 1: return "Simple password";
        case 2: return "Cryptographic";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(auth_type)) + ")";
    }
}

std::string lsa_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Router";
        case 2: return "Network";
        case 3: return "Summary";
        case 4: return "ASBR-Summary";
        case 5: return "AS-External";
        case 6: return "Group Membership";
        case 7: return "NSSA-External";
        case 9: return "Opaque (Link-Local)";
        case 10: return "Opaque (Area-Local)";
        case 11: return "Opaque (AS-Wide)";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(type)) + ")";
    }
}

std::string router_link_type_name(uint8_t type) {
    switch (type) {
        case 1: return "Point-to-Point";
        case 2: return "Transit";
        case 3: return "Stub";
        case 4: return "Virtual";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(type)) + ")";
    }
}

void decode_options(uint8_t options, OspfMessage& msg) {
    msg.options_raw = options;
    msg.option_e = (options & 0x02) != 0;
    msg.option_mc = (options & 0x04) != 0;
    msg.option_np = (options & 0x08) != 0;
    msg.option_dc = (options & 0x20) != 0;
    msg.option_o = (options & 0x40) != 0;
    msg.option_dn = (options & 0x80) != 0;
}

OspfLsa decode_lsa_header(Cursor& c) {
    OspfLsa lsa;
    uint16_t age_raw = c.u16be();
    lsa.do_not_age = (age_raw & 0x8000) != 0;
    lsa.age_sec = age_raw & 0x7FFF;
    lsa.options_raw = c.u8();
    lsa.type = c.u8();
    lsa.type_name = lsa_type_name(lsa.type);
    lsa.link_state_id = format_ipv4(c.u32be());
    lsa.advertising_router = format_ipv4(c.u32be());
    lsa.sequence_number = c.u32be();
    lsa.checksum = c.u16be();
    lsa.length = c.u16be();
    return lsa;
}

void decode_router_lsa_body(Cursor& c, OspfLsa& lsa) {
    if (c.remaining() < 4) return;
    uint8_t flags = c.u8();
    c.u8();  // unused byte (RFC 2328's own layout leaves this byte unused between Flags and
              // #Links, both historically documented as if #Links were 2 bytes starting here --
              // Wireshark's own dissector notes this same oddity)
    uint16_t link_count = c.u16be();

    OspfRouterLsaBody body;
    body.flag_border = (flags & 0x01) != 0;
    body.flag_external = (flags & 0x02) != 0;
    body.flag_virtual = (flags & 0x04) != 0;

    for (uint16_t i = 0; i < link_count; ++i) {
        if (c.remaining() < 12) {
            break;
        }
        OspfRouterLink link;
        link.link_id = format_ipv4(c.u32be());
        link.link_data = format_ipv4(c.u32be());
        link.link_type = c.u8();
        link.link_type_name = router_link_type_name(link.link_type);
        link.tos_count = c.u8();
        link.metric = c.u16be();

        size_t extra_tos_bytes = static_cast<size_t>(link.tos_count) * 4;
        if (c.remaining() < extra_tos_bytes) {
            extra_tos_bytes = c.remaining();
        }
        c.skip(extra_tos_bytes);  // additional (non-zero-TOS) metrics -- not decoded, see ospf.hpp

        if (body.links.size() < kMaxList) {
            body.links.push_back(std::move(link));
        } else {
            body.links_truncated = true;
        }
    }
    lsa.router_body = std::move(body);
}

void decode_network_lsa_body(Cursor& c, OspfLsa& lsa) {
    if (c.remaining() < 4) return;
    OspfNetworkLsaBody body;
    body.network_mask = format_ipv4(c.u32be());
    while (c.remaining() >= 4) {
        if (body.attached_routers.size() < kMaxList) {
            body.attached_routers.push_back(format_ipv4(c.u32be()));
        } else {
            body.attached_routers_truncated = true;
            c.skip(4);
        }
    }
    lsa.network_body = std::move(body);
}

void decode_summary_lsa_body(Cursor& c, OspfLsa& lsa) {
    if (c.remaining() < 8) return;
    OspfSummaryLsaBody body;
    body.network_mask = format_ipv4(c.u32be());
    c.u8();  // TOS (0 for the ordinary metric entry decoded here)
    uint32_t metric_bytes = (static_cast<uint32_t>(c.u8()) << 16) |
                             (static_cast<uint32_t>(c.u8()) << 8) | c.u8();
    body.metric = metric_bytes;
    lsa.summary_body = body;
    // Any additional TOS-specific metric blocks are not decoded -- see ospf.hpp header comment.
}

void decode_as_external_lsa_body(Cursor& c, OspfLsa& lsa) {
    if (c.remaining() < 16) return;
    OspfAsExternalLsaBody body;
    body.network_mask = format_ipv4(c.u32be());
    uint8_t type_and_tos = c.u8();
    body.e_bit = (type_and_tos & 0x80) != 0;
    uint32_t metric_bytes = (static_cast<uint32_t>(c.u8()) << 16) |
                             (static_cast<uint32_t>(c.u8()) << 8) | c.u8();
    body.metric = metric_bytes;
    body.forwarding_address = format_ipv4(c.u32be());
    body.external_route_tag = c.u32be();
    lsa.as_external_body = body;
    // Any additional TOS-specific forwarding blocks are not decoded -- see ospf.hpp header comment.
}

void decode_lsa_body_by_type(Cursor& c, OspfLsa& lsa) {
    switch (lsa.type) {
        case 1: decode_router_lsa_body(c, lsa); break;
        case 2: decode_network_lsa_body(c, lsa); break;
        case 3:
        case 4: decode_summary_lsa_body(c, lsa); break;
        case 5:
        case 7: decode_as_external_lsa_body(c, lsa); break;
        default: break;  // Group Membership / Opaque -- recognized but not decoded, see ospf.hpp
    }
}

}  // namespace

std::optional<OspfMessage> try_parse_ospf(ByteSpan ip_payload) {
    if (ip_payload.size() < kHeaderLength) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    OspfMessage msg;
    msg.version = c.u8();
    if (msg.version != 2) {
        return std::nullopt;
    }
    msg.type = c.u8();
    if (msg.type < 1 || msg.type > 5) {
        return std::nullopt;
    }
    msg.type_name = ospf_type_name(msg.type);
    msg.packet_length = c.u16be();
    msg.router_id = format_ipv4(c.u32be());
    msg.area_id = format_ipv4(c.u32be());
    msg.checksum = c.u16be();
    msg.instance_id = c.u8();
    msg.auth_type = c.u8();
    msg.auth_type_name = auth_type_name(msg.auth_type);

    if (msg.auth_type == 1) {
        msg.auth_simple_password = strip_trailing_nul(c.bytes(8));
        msg.notes.push_back("AuType 1 (Simple password) sends this password in cleartext on the "
                             "wire -- see ospf.hpp's own Security context note");
    } else if (msg.auth_type == 2) {
        c.u16be();  // reserved, always 0
        msg.auth_crypto_key_id = c.u8();
        msg.auth_crypto_data_length = c.u8();
        msg.auth_crypto_sequence_number = c.u32be();
        msg.notes.push_back("AuType 2 (Cryptographic/MD5) header fields decoded; the digest "
                             "itself is a separate block appended after this packet's own "
                             "declared length and is neither located nor verified here (the same "
                             "posture RIP's own Keyed MD5 support already takes)");
    } else {
        c.skip(8);
    }

    size_t body_end = (msg.packet_length >= kHeaderLength && msg.packet_length <= ip_payload.size())
                           ? msg.packet_length
                           : ip_payload.size();
    if (msg.packet_length < kHeaderLength || msg.packet_length > ip_payload.size()) {
        msg.notes.push_back("declared Packet Length (" + std::to_string(msg.packet_length) +
                             ") is implausible given " + std::to_string(ip_payload.size()) +
                             " captured byte(s) -- decoding the rest of the captured payload anyway");
    }

    switch (msg.type) {
        case 1: {  // Hello
            if (c.remaining() < 20) break;
            msg.hello_network_mask = format_ipv4(c.u32be());
            msg.hello_interval_sec = c.u16be();
            decode_options(c.u8(), msg);
            msg.hello_router_priority = c.u8();
            msg.hello_router_dead_interval_sec = c.u32be();
            msg.hello_designated_router = format_ipv4(c.u32be());
            msg.hello_backup_designated_router = format_ipv4(c.u32be());
            while (c.position() < body_end && c.remaining() >= 4) {
                if (msg.hello_neighbors.size() < kMaxList) {
                    msg.hello_neighbors.push_back(format_ipv4(c.u32be()));
                } else {
                    msg.hello_neighbors_truncated = true;
                    c.skip(4);
                }
            }
            break;
        }
        case 2: {  // DB Description
            if (c.remaining() < 8) break;
            msg.dbd_interface_mtu = c.u16be();
            decode_options(c.u8(), msg);
            uint8_t flags = c.u8();
            msg.dbd_flag_master = (flags & 0x01) != 0;
            msg.dbd_flag_more = (flags & 0x02) != 0;
            msg.dbd_flag_init = (flags & 0x04) != 0;
            msg.dbd_sequence_number = c.u32be();
            while (c.position() < body_end && c.remaining() >= kLsaHeaderLength) {
                if (msg.dbd_lsa_headers.size() < kMaxList) {
                    msg.dbd_lsa_headers.push_back(decode_lsa_header(c));
                } else {
                    msg.dbd_lsa_headers_truncated = true;
                    c.skip(kLsaHeaderLength);
                }
            }
            break;
        }
        case 3: {  // LS Request
            while (c.position() < body_end && c.remaining() >= 12) {
                OspfLsRequestEntry entry;
                entry.ls_type = c.u32be();
                entry.ls_type_name = lsa_type_name(static_cast<uint8_t>(entry.ls_type));
                entry.link_state_id = format_ipv4(c.u32be());
                entry.advertising_router = format_ipv4(c.u32be());
                if (msg.ls_requests.size() < kMaxList) {
                    msg.ls_requests.push_back(std::move(entry));
                } else {
                    msg.ls_requests_truncated = true;
                }
            }
            break;
        }
        case 4: {  // LS Update
            if (c.remaining() < 4) break;
            msg.ls_update_declared_count = c.u32be();
            uint32_t to_decode = std::min<uint32_t>(msg.ls_update_declared_count,
                                                      static_cast<uint32_t>(kMaxList));
            uint32_t decoded_count = 0;
            for (uint32_t i = 0; i < msg.ls_update_declared_count; ++i) {
                if (c.remaining() < kLsaHeaderLength) {
                    msg.notes.push_back("LS Update declared " +
                                         std::to_string(msg.ls_update_declared_count) +
                                         " LSA(s) but ran out of bytes after " +
                                         std::to_string(decoded_count) + " -- stopping here");
                    break;
                }
                OspfLsa lsa = decode_lsa_header(c);
                if (lsa.length < kLsaHeaderLength) {
                    msg.notes.push_back("an LSA declared Length " + std::to_string(lsa.length) +
                                         ", less than its own 20-byte header -- stopping LS Update "
                                         "parsing here");
                    break;
                }
                size_t body_len = lsa.length - kLsaHeaderLength;
                if (c.remaining() < body_len) {
                    msg.notes.push_back("an LSA's declared Length runs past the end of the "
                                         "captured payload -- stopping LS Update parsing here");
                    break;
                }
                ByteSpan body_span = c.bytes(body_len);
                Cursor bc(body_span);
                decode_lsa_body_by_type(bc, lsa);
                if (decoded_count < to_decode) {
                    msg.ls_update_lsas.push_back(std::move(lsa));
                } else {
                    msg.ls_update_lsas_truncated = true;
                }
                ++decoded_count;
            }
            break;
        }
        case 5: {  // LS Ack
            while (c.position() < body_end && c.remaining() >= kLsaHeaderLength) {
                if (msg.ls_ack_headers.size() < kMaxList) {
                    msg.ls_ack_headers.push_back(decode_lsa_header(c));
                } else {
                    msg.ls_ack_headers_truncated = true;
                    c.skip(kLsaHeaderLength);
                }
            }
            break;
        }
        default:
            break;
    }

    std::ostringstream out;
    out << "OSPFv2 " << msg.type_name << ": Router " << msg.router_id << ", Area " << msg.area_id;
    switch (msg.type) {
        case 1:
            out << ", " << msg.hello_neighbors.size() << " neighbor(s)";
            break;
        case 2:
            out << ", " << msg.dbd_lsa_headers.size() << " LSA header(s)";
            break;
        case 3:
            out << ", " << msg.ls_requests.size() << " request(s)";
            break;
        case 4:
            out << ", " << msg.ls_update_lsas.size() << " LSA(s)";
            break;
        case 5:
            out << ", " << msg.ls_ack_headers.size() << " LSA header(s) acknowledged";
            break;
        default:
            break;
    }
    msg.summary = out.str();

    return msg;
}

std::optional<ProtocolResult> OspfDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_ospf(payload)) {
        return ProtocolResult::make<OspfMessage>("ospf", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& ospf_decoder() {
    static const OspfDecoder instance;
    return instance;
}

}  // namespace conduitscope
