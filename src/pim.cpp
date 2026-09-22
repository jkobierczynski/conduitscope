// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/pim.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (same convention as elsewhere).
const size_t kMaxList = resource_limits().max_decoded_objects.value_or(50);

constexpr uint8_t kAfIpv4 = 1;
constexpr uint8_t kEtNative = 0;

std::string pim_type_name(uint8_t type) {
    switch (type) {
        case 0: return "Hello";
        case 1: return "Register";
        case 2: return "Register-Stop";
        case 3: return "Join/Prune";
        case 4: return "Bootstrap";
        case 5: return "Assert";
        case 6: return "Graft";
        case 7: return "Graft-Ack";
        case 8: return "Candidate-RP-Advertisement";
        case 9: return "State Refresh";
        case 10: return "DF Election";
        case 11: return "ECMP Redirect";
        case 12: return "PFM";
        case 13: return "Packed Register";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(type)) + ")";
    }
}

// Encoded-Unicast address (RFC 7761 4.9.1): AF(1)+ET(1)+Addr(4, IPv4 only here) = 6 bytes.
// Returns std::nullopt (having consumed only the AF/ET bytes) if this isn't an IPv4/Native
// address -- see pim.hpp's own header comment on why that's a hard stop rather than a guess.
std::optional<std::string> decode_encoded_unicast(Cursor& c) {
    if (c.remaining() < 2) return std::nullopt;
    uint8_t af = c.u8();
    uint8_t et = c.u8();
    if (af != kAfIpv4 || et != kEtNative || c.remaining() < 4) return std::nullopt;
    return format_ipv4(c.u32be());
}

// Encoded-Group address: AF(1)+ET(1)+Reserved/Flags(1)+MaskLen(1)+Addr(4) = 8 bytes.
std::optional<std::string> decode_encoded_group(Cursor& c) {
    if (c.remaining() < 4) return std::nullopt;
    uint8_t af = c.u8();
    uint8_t et = c.u8();
    c.u8();  // reserved/flags -- not decoded (bidir-PIM's Z bit lives here; rare enough to skip)
    uint8_t mask_len = c.u8();
    if (af != kAfIpv4 || et != kEtNative || c.remaining() < 4) return std::nullopt;
    std::string addr = format_ipv4(c.u32be());
    return addr + "/" + std::to_string(static_cast<unsigned>(mask_len));
}

// Encoded-Source address: AF(1)+ET(1)+Flags(1: bit2=S bit1=W bit0=R)+MaskLen(1)+Addr(4) = 8 bytes.
std::optional<std::string> decode_encoded_source(Cursor& c) {
    if (c.remaining() < 4) return std::nullopt;
    uint8_t af = c.u8();
    uint8_t et = c.u8();
    uint8_t flags = c.u8();
    uint8_t mask_len = c.u8();
    if (af != kAfIpv4 || et != kEtNative || c.remaining() < 4) return std::nullopt;
    std::string addr = format_ipv4(c.u32be());
    std::string out = addr + "/" + std::to_string(static_cast<unsigned>(mask_len));
    if (flags != 0) {
        std::string letters;
        if (flags & 0x04) letters += "S";
        if (flags & 0x02) letters += "W";
        if (flags & 0x01) letters += "R";
        if (!letters.empty()) out += " (" + letters + ")";
    }
    return out;
}

std::string hello_option_name(uint16_t type) {
    switch (type) {
        case 1: return "Hold Time";
        case 2: return "LAN Prune Delay";
        case 19: return "DR Priority";
        case 20: return "Generation ID";
        case 21: return "State Refresh Capable";
        case 24: return "Address List";
        case 65001: return "Address List (old)";
        default: return "Unknown (" + std::to_string(type) + ")";
    }
}

void decode_hello(Cursor& c, PimMessage& msg) {
    while (c.remaining() >= 4) {
        uint16_t opt_type = c.u16be();
        uint16_t opt_len = c.u16be();
        if (c.remaining() < opt_len) {
            msg.notes.push_back("a Hello Option declared " + std::to_string(opt_len) +
                                 " byte(s) of value but only " + std::to_string(c.remaining()) +
                                 " remain -- stopping here");
            break;
        }
        if (msg.hello_options.size() >= kMaxList) {
            msg.hello_options_truncated = true;
            c.skip(opt_len);
            continue;
        }
        PimHelloOption opt;
        opt.option_type = opt_type;
        opt.option_type_name = hello_option_name(opt_type);
        ByteSpan value = c.bytes(opt_len);
        Cursor vc(value);
        switch (opt_type) {
            case 1: {  // Hold Time
                if (vc.remaining() >= 2) {
                    uint16_t ht = vc.u16be();
                    opt.value = (ht == 0xFFFF) ? "infinity" : (std::to_string(ht) + "s");
                }
                break;
            }
            case 2: {  // LAN Prune Delay
                if (vc.remaining() >= 4) {
                    uint16_t t_and_delay = vc.u16be();
                    uint16_t override_ms = vc.u16be();
                    bool t_bit = (t_and_delay & 0x8000) != 0;
                    uint16_t delay_ms = t_and_delay & 0x7FFF;
                    std::ostringstream v;
                    v << "T=" << (t_bit ? 1 : 0) << ", Propagation Delay=" << delay_ms
                      << "ms, Override Interval=" << override_ms << "ms";
                    opt.value = v.str();
                }
                break;
            }
            case 19: {  // DR Priority
                if (vc.remaining() >= 4) opt.value = std::to_string(vc.u32be());
                break;
            }
            case 20: {  // Generation ID
                if (vc.remaining() >= 4) opt.value = std::to_string(vc.u32be());
                break;
            }
            case 21: {  // State Refresh Capable
                if (vc.remaining() >= 2) {
                    uint8_t sr_version = vc.u8();
                    uint8_t interval = vc.u8();
                    opt.value = "version=" + std::to_string(static_cast<unsigned>(sr_version)) +
                                ", interval=" + std::to_string(static_cast<unsigned>(interval)) + "s";
                }
                break;
            }
            case 24:
            case 65001: {  // Address List
                while (vc.remaining() > 0 && opt.addresses.size() < kMaxList) {
                    auto addr = decode_encoded_unicast(vc);
                    if (!addr) break;
                    opt.addresses.push_back(*addr);
                }
                break;
            }
            default:
                break;  // recognized (counted, named) but not decoded further -- see pim.hpp
        }
        msg.hello_options.push_back(std::move(opt));
    }
    if (msg.hello_options_truncated) {
        msg.notes.push_back("output capped at " + std::to_string(kMaxList) +
                             " Hello Option(s); more were present in this packet and were not decoded");
    }
}

void decode_register(Cursor& c, PimMessage& msg) {
    if (c.remaining() < 4) return;
    uint32_t flags = c.u32be();
    msg.register_border_bit = (flags & 0x80000000u) != 0;
    msg.register_null_register_bit = (flags & 0x40000000u) != 0;

    // The encapsulated multicast data packet follows. Whether it's a real IPv4 header or PIM's
    // "Null-Register dummy header" (an all-zero placeholder the same size as a minimal IPv4
    // header), the (Source, Group) address pair sits at the same fixed offsets: +12 (source) and
    // +16 (group/destination) -- see pim.hpp's header comment and packet-pim.c's own handling of
    // both cases at those identical offsets.
    if (c.remaining() < 20) {
        msg.notes.push_back("encapsulated packet is shorter than a minimal 20-byte IPv4 header -- "
                             "its (Source, Group) addresses were not decoded");
        return;
    }
    uint8_t version_nibble = (c.bytes(1).at(0) >> 4) & 0x0F;
    if (version_nibble != 0 && version_nibble != 4) {
        msg.notes.push_back("encapsulated packet's IP version nibble is " +
                             std::to_string(static_cast<unsigned>(version_nibble)) +
                             ", not 0 (Null-Register) or 4 (IPv4) -- its (Source, Group) addresses "
                             "were not decoded (this decoder has no IPv6 support)");
        return;
    }
    // Already consumed 1 of the 20 bytes above; source is at offset 12, group at offset 16 from
    // the start of the encapsulated data, i.e. 11 and 15 bytes further from here.
    ByteSpan rest = c.rest();
    if (rest.size() < 19) return;
    msg.register_inner_src_ip = format_ipv4((static_cast<uint32_t>(rest.at(11)) << 24) |
                                             (static_cast<uint32_t>(rest.at(12)) << 16) |
                                             (static_cast<uint32_t>(rest.at(13)) << 8) |
                                             static_cast<uint32_t>(rest.at(14)));
    msg.register_inner_group_ip = format_ipv4((static_cast<uint32_t>(rest.at(15)) << 24) |
                                               (static_cast<uint32_t>(rest.at(16)) << 16) |
                                               (static_cast<uint32_t>(rest.at(17)) << 8) |
                                               static_cast<uint32_t>(rest.at(18)));
}

void decode_register_stop(Cursor& c, PimMessage& msg) {
    auto group = decode_encoded_group(c);
    if (!group) {
        msg.notes.push_back("Register-Stop's Encoded-Group address was not IPv4/Native -- not decoded");
        return;
    }
    msg.register_stop_group = *group;
    auto source = decode_encoded_unicast(c);
    if (!source) {
        msg.notes.push_back("Register-Stop's Encoded-Unicast source address was not IPv4/Native -- "
                             "not decoded");
        return;
    }
    msg.register_stop_source = *source;
}

// Shared by Join/Prune, Graft, and Graft-Ack (RFC 7761 4.9.5 / RFC 3973) -- identical wire format.
void decode_join_prune(Cursor& c, PimMessage& msg) {
    auto upstream = decode_encoded_unicast(c);
    if (!upstream) {
        msg.notes.push_back("upstream neighbor Encoded-Unicast address was not IPv4/Native -- "
                             "message not decoded further");
        return;
    }
    msg.jp_upstream_neighbor = *upstream;
    if (c.remaining() < 4) return;
    c.u8();  // reserved
    uint8_t num_groups = c.u8();
    msg.jp_holdtime_sec = c.u16be();

    for (uint8_t g = 0; g < num_groups; ++g) {
        auto group = decode_encoded_group(c);
        if (!group) {
            msg.notes.push_back("a group's Encoded-Group address was not IPv4/Native -- stopping "
                                 "here (" + std::to_string(static_cast<unsigned>(num_groups) - g) +
                                 " group(s) not decoded)");
            break;
        }
        if (c.remaining() < 4) break;
        uint16_t num_join = c.u16be();
        uint16_t num_prune = c.u16be();

        PimJoinPruneGroup pg;
        pg.group = *group;
        bool bail = false;
        for (uint16_t j = 0; j < num_join && !bail; ++j) {
            auto src = decode_encoded_source(c);
            if (!src) {
                bail = true;
                break;
            }
            if (pg.joins.size() < kMaxList) pg.joins.push_back(*src);
        }
        for (uint16_t p = 0; p < num_prune && !bail; ++p) {
            auto src = decode_encoded_source(c);
            if (!src) {
                bail = true;
                break;
            }
            if (pg.prunes.size() < kMaxList) pg.prunes.push_back(*src);
        }
        if (msg.jp_groups.size() < kMaxList) {
            msg.jp_groups.push_back(std::move(pg));
        } else {
            msg.jp_groups_truncated = true;
        }
        if (bail) {
            msg.notes.push_back("a Join or Prune source's Encoded-Source address was not "
                                 "IPv4/Native -- stopping here");
            break;
        }
    }
    if (num_groups > kMaxList) msg.jp_groups_truncated = true;
}

void decode_bootstrap(Cursor& c, PimMessage& msg) {
    if (c.remaining() < 4) return;
    msg.bsr_fragment_tag = c.u16be();
    msg.bsr_hash_mask_len = c.u8();
    msg.bsr_priority = c.u8();
    auto bsr_addr = decode_encoded_unicast(c);
    if (!bsr_addr) {
        msg.notes.push_back("BSR Encoded-Unicast address was not IPv4/Native -- not decoded further");
        return;
    }
    msg.bsr_address = *bsr_addr;

    while (c.remaining() > 0) {
        auto group = decode_encoded_group(c);
        if (!group) {
            msg.notes.push_back("a group's Encoded-Group address was not IPv4/Native -- stopping here");
            break;
        }
        if (c.remaining() < 4) break;
        uint8_t rp_count = c.u8();
        uint8_t frp_count = c.u8();
        c.skip(2);  // reserved

        PimBsrGroupRps entry;
        entry.group = *group;
        bool bail = false;
        for (uint8_t j = 0; j < frp_count && !bail; ++j) {
            auto rp = decode_encoded_unicast(c);
            if (!rp || c.remaining() < 4) {
                bail = true;
                break;
            }
            uint16_t holdtime = c.u16be();
            uint8_t priority = c.u8();
            c.u8();  // reserved
            if (entry.candidate_rps.size() < kMaxList) {
                entry.candidate_rps.push_back(*rp + " (holdtime=" + std::to_string(holdtime) +
                                               "s, priority=" + std::to_string(static_cast<unsigned>(priority)) +
                                               ")");
            }
        }
        (void)rp_count;  // RP-Count and Frag-RP-Count are equal except across fragmented Bootstrap
                          // messages, which this decoder (operating on one packet at a time) has
                          // no way to reassemble -- only Frag-RP-Count's entries are ever present
                          // in a single message, so that's what's iterated above.
        if (msg.bsr_groups.size() < kMaxList) {
            msg.bsr_groups.push_back(std::move(entry));
        } else {
            msg.bsr_groups_truncated = true;
        }
        if (bail) {
            msg.notes.push_back("a candidate-RP's Encoded-Unicast address was not IPv4/Native -- "
                                 "stopping here");
            break;
        }
    }
}

void decode_assert(Cursor& c, PimMessage& msg) {
    auto group = decode_encoded_group(c);
    if (!group) {
        msg.notes.push_back("Assert's Encoded-Group address was not IPv4/Native -- not decoded");
        return;
    }
    msg.assert_group = *group;
    auto source = decode_encoded_unicast(c);
    if (!source) {
        msg.notes.push_back("Assert's Encoded-Unicast source address was not IPv4/Native -- not decoded");
        return;
    }
    msg.assert_source = *source;
    if (c.remaining() < 8) return;
    uint32_t rpt_and_pref = c.u32be();
    msg.assert_rpt_bit = (rpt_and_pref & 0x80000000u) != 0;
    msg.assert_metric_preference = rpt_and_pref & 0x7FFFFFFFu;
    msg.assert_metric = c.u32be();
}

void decode_cand_rp_adv(Cursor& c, PimMessage& msg) {
    if (c.remaining() < 4) return;
    msg.crp_prefix_count = c.u8();
    msg.crp_priority = c.u8();
    msg.crp_holdtime_sec = c.u16be();
    auto rp = decode_encoded_unicast(c);
    if (!rp) {
        msg.notes.push_back("Candidate-RP-Advertisement's RP Encoded-Unicast address was not "
                             "IPv4/Native -- not decoded further");
        return;
    }
    msg.crp_rp_address = *rp;

    for (uint8_t i = 0; i < msg.crp_prefix_count; ++i) {
        auto group = decode_encoded_group(c);
        if (!group) {
            msg.notes.push_back("a group's Encoded-Group address was not IPv4/Native -- stopping here");
            break;
        }
        if (msg.crp_groups.size() < kMaxList) {
            msg.crp_groups.push_back(*group);
        } else {
            msg.crp_groups_truncated = true;
        }
    }
}

}  // namespace

std::optional<PimMessage> try_parse_pim(ByteSpan ip_payload) {
    if (ip_payload.size() < 4) {
        return std::nullopt;
    }

    Cursor c(ip_payload);
    uint8_t ver_type = c.u8();
    uint8_t version = (ver_type >> 4) & 0x0F;
    uint8_t type = ver_type & 0x0F;
    if (version != 2 || type > 13) {
        return std::nullopt;
    }

    PimMessage msg;
    msg.version = version;
    msg.type = type;
    msg.type_name = pim_type_name(type);
    c.u8();  // reserved / type-specific second byte -- not decoded (a few types repurpose bits
              // here for their own subtype/flags; none of those are decoded by this project)
    msg.checksum = c.u16be();

    switch (type) {
        case 0: decode_hello(c, msg); break;
        case 1: decode_register(c, msg); break;
        case 2: decode_register_stop(c, msg); break;
        case 3:
        case 6:
        case 7: decode_join_prune(c, msg); break;
        case 4: decode_bootstrap(c, msg); break;
        case 5: decode_assert(c, msg); break;
        case 8: decode_cand_rp_adv(c, msg); break;
        default:
            msg.notes.push_back(msg.type_name + " is recognized but not decoded further (see pim.hpp)");
            break;
    }

    std::ostringstream out;
    out << "PIMv2 " << msg.type_name;
    switch (type) {
        case 0:
            out << ": " << msg.hello_options.size() << " option(s)";
            break;
        case 1:
            out << ": (" << msg.register_inner_src_ip << ", " << msg.register_inner_group_ip << ")";
            if (msg.register_null_register_bit) out << " [Null-Register]";
            if (msg.register_border_bit) out << " [Border]";
            break;
        case 2:
            out << ": group " << msg.register_stop_group << ", source " << msg.register_stop_source;
            break;
        case 3:
        case 6:
        case 7:
            out << ": neighbor " << msg.jp_upstream_neighbor << ", " << msg.jp_groups.size()
                << " group(s)";
            break;
        case 4:
            out << ": BSR " << msg.bsr_address << ", " << msg.bsr_groups.size() << " group(s)";
            break;
        case 5:
            out << ": group " << msg.assert_group << ", source " << msg.assert_source;
            break;
        case 8:
            out << ": RP " << msg.crp_rp_address << ", " << msg.crp_groups.size() << " group(s)";
            break;
        default:
            break;
    }
    msg.summary = out.str();

    return msg;
}

std::optional<ProtocolResult> PimDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_pim(payload)) {
        return ProtocolResult::make<PimMessage>("pim", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& pim_decoder() {
    static const PimDecoder instance;
    return instance;
}

}  // namespace conduitscope
