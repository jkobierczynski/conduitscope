// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/igrp.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxRoutes = resource_limits().max_decoded_objects.value_or(50);
constexpr size_t kHeaderLength = 12;
constexpr size_t kEntryLength = 14;

uint32_t read_u24be(Cursor& c) {
    uint32_t a = c.u8(), b = c.u8(), d = c.u8();
    return (a << 16) | (b << 8) | d;
}

// Reconstructs the route's address per this file's header comment: an Interior route borrows its
// missing high-order octet from the packet's own source IP; a System/Exterior route's 3 bytes ARE
// the high-order octets, with the low-order octet always 0.
std::string decode_igrp_address(const std::string& kind, uint32_t network_24bit, uint32_t src_ip) {
    uint32_t addr;
    if (kind == "Interior") {
        uint32_t src_octet0 = (src_ip >> 24) & 0xFF;
        addr = (src_octet0 << 24) | network_24bit;
    } else {
        addr = (network_24bit << 8);
    }
    return format_ipv4(addr);
}

IgrpRoute decode_route(Cursor& c, const std::string& kind, uint32_t src_ip) {
    IgrpRoute r;
    r.route_kind = kind;
    uint32_t network_24bit = read_u24be(c);
    r.address = decode_igrp_address(kind, network_24bit, src_ip);

    r.delay_raw = read_u24be(c);
    r.unreachable = (r.delay_raw == 0xFFFFFF);
    r.delay_microseconds = r.unreachable ? 0 : r.delay_raw * 10;

    r.bandwidth_raw = read_u24be(c);
    r.bandwidth_kbps = (r.bandwidth_raw != 0) ? (10000000u / r.bandwidth_raw) : 0;

    r.mtu = c.u16be();
    r.reliability = c.u8();
    r.load = c.u8();
    r.hop_count = c.u8();
    return r;
}

}  // namespace

std::optional<IgrpMessage> try_parse_igrp(ByteSpan ip_payload, uint32_t src_ip) {
    if (ip_payload.size() < kHeaderLength) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    uint8_t ver_and_opcode = c.u8();
    IgrpMessage msg;
    msg.version = (ver_and_opcode >> 4) & 0x0F;
    msg.opcode = ver_and_opcode & 0x0F;
    if (msg.opcode != 1 && msg.opcode != 2) {
        return std::nullopt;
    }
    msg.opcode_name = (msg.opcode == 1) ? "Response" : "Request";
    if (msg.version != 1) {
        msg.notes.push_back("Version field is " + std::to_string(static_cast<unsigned>(msg.version)) +
                             ", not the only defined value (1) -- decoding may be inaccurate "
                             "(matches Wireshark's own posture for this field)");
    }

    msg.edition = c.u8();
    msg.autonomous_system = c.u16be();
    msg.interior_route_count = c.u16be();
    msg.system_route_count = c.u16be();
    msg.exterior_route_count = c.u16be();
    msg.checksum = c.u16be();

    size_t declared_total = static_cast<size_t>(msg.interior_route_count) +
                             static_cast<size_t>(msg.system_route_count) +
                             static_cast<size_t>(msg.exterior_route_count);
    size_t to_decode = std::min(declared_total, kMaxRoutes);

    size_t interior_left = msg.interior_route_count;
    size_t system_left = msg.system_route_count;
    size_t exterior_left = msg.exterior_route_count;
    size_t decoded = 0;

    while (decoded < to_decode && c.remaining() >= kEntryLength) {
        std::string kind;
        if (interior_left > 0) {
            kind = "Interior";
            --interior_left;
        } else if (system_left > 0) {
            kind = "System";
            --system_left;
        } else if (exterior_left > 0) {
            kind = "Exterior";
            --exterior_left;
        } else {
            break;
        }
        msg.routes.push_back(decode_route(c, kind, src_ip));
        ++decoded;
    }

    if (declared_total > kMaxRoutes) {
        msg.routes_truncated = true;
        msg.notes.push_back("output capped at " + std::to_string(kMaxRoutes) + " route(s); " +
                             std::to_string(declared_total - kMaxRoutes) +
                             " more were declared in this packet (across Interior+System+Exterior) "
                             "and were not decoded");
    } else if (msg.routes.size() < declared_total) {
        msg.notes.push_back("Interior+System+Exterior counts declare " +
                             std::to_string(declared_total) + " route(s) but only " +
                             std::to_string(msg.routes.size()) +
                             " complete 14-byte route vector(s) are present -- possible truncation");
    }

    std::ostringstream out;
    out << "IGRP " << msg.opcode_name << ": AS " << msg.autonomous_system << ", "
        << msg.interior_route_count << " interior / " << msg.system_route_count << " system / "
        << msg.exterior_route_count << " exterior route(s)";
    msg.summary = out.str();

    return msg;
}

std::optional<ProtocolResult> IgrpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (auto msg = try_parse_igrp(payload, ctx.ip_src_addr)) {
        return ProtocolResult::make<IgrpMessage>("igrp", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& igrp_decoder() {
    static const IgrpDecoder instance;
    return instance;
}

}  // namespace conduitscope
