// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/mpls.hpp"

#include <sstream>

namespace conduitscope {

namespace {

std::string mpls_label_name(uint32_t label) {
    switch (label) {
        case 0: return "IPv4 Explicit NULL";
        case 1: return "Router Alert";
        case 2: return "IPv6 Explicit NULL";
        case 3: return "Implicit NULL";
        default: return "";
    }
}

}  // namespace

std::optional<MplsFrame> try_parse_mpls(ByteSpan eth_payload) {
    if (eth_payload.size() < 4) return std::nullopt;

    MplsFrame f;
    size_t offset = 0;
    bool found_bottom = false;

    while (offset + 4 <= eth_payload.size()) {
        if (f.labels.size() >= mpls_max_label_depth()) {
            f.stack_too_deep = true;
            break;
        }
        uint32_t word = (static_cast<uint32_t>(eth_payload.at(offset)) << 24) |
                         (static_cast<uint32_t>(eth_payload.at(offset + 1)) << 16) |
                         (static_cast<uint32_t>(eth_payload.at(offset + 2)) << 8) |
                         eth_payload.at(offset + 3);
        MplsLabelEntry entry;
        entry.label = (word >> 12) & 0xFFFFF;
        entry.label_name = mpls_label_name(entry.label);
        entry.exp = static_cast<uint8_t>((word >> 9) & 0x07);
        entry.bottom_of_stack = (word & 0x100) != 0;
        entry.ttl = static_cast<uint8_t>(word & 0xFF);
        f.labels.push_back(entry);
        offset += 4;
        if (entry.bottom_of_stack) {
            found_bottom = true;
            break;
        }
    }

    if (!found_bottom && !f.stack_too_deep) {
        f.stack_truncated = true;
    }

    std::ostringstream s;
    s << "MPLS, " << f.labels.size() << " label" << (f.labels.size() == 1 ? "" : "s");
    if (!f.labels.empty()) {
        const MplsLabelEntry& top = f.labels.front();
        s << " (top: ";
        if (!top.label_name.empty()) {
            s << top.label_name << " (" << top.label << ")";
        } else {
            s << "label=" << top.label;
        }
        s << " exp=" << static_cast<unsigned>(top.exp) << " ttl=" << static_cast<unsigned>(top.ttl) << ")";
    }
    if (f.stack_truncated) {
        s << " -- truncated, no Bottom-of-Stack label found before the captured bytes ran out";
    } else if (f.stack_too_deep) {
        s << " -- stack exceeds " << mpls_max_label_depth() << " labels without a Bottom-of-Stack label, "
             "capped";
    } else {
        s << ", payload not decoded further (could be IP, an L2VPN/VPLS/pseudowire Ethernet frame, "
             "or a nested inner label stack -- see mpls.hpp's own header comment)";
    }
    f.summary = s.str();
    return f;
}

std::optional<ProtocolResult> MplsUnicastDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto mp = try_parse_mpls(payload)) {
        return ProtocolResult::make<MplsFrame>("mpls", std::move(*mp));
    }
    return std::nullopt;
}

std::optional<ProtocolResult> MplsMulticastDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto mp = try_parse_mpls(payload)) {
        return ProtocolResult::make<MplsFrame>("mpls", std::move(*mp));
    }
    return std::nullopt;
}

const ProtocolDecoder& mpls_unicast_decoder() {
    static const MplsUnicastDecoder instance;
    return instance;
}

const ProtocolDecoder& mpls_multicast_decoder() {
    static const MplsMulticastDecoder instance;
    return instance;
}

}  // namespace conduitscope
