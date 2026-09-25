// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ipv6_attack_detect.hpp"

#include <algorithm>
#include <sstream>

namespace conduitscope {

namespace {

std::string to_hex_string(const std::vector<uint8_t>& bytes) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

// The Source Link-Layer Address option (NDP option type 1), when this Router Advertisement
// carried one -- empty string if not. Half of an RA identity's own key, see this file's own
// header comment on signature (1).
std::string source_link_layer_mac(const Icmpv6Message& msg) {
    for (const auto& opt : msg.options) {
        if (opt.type == 1 && opt.link_layer_address) {
            return to_hex_string(opt.link_layer_address->address);
        }
    }
    return "";
}

// The Target Link-Layer Address option (NDP option type 2), when this Neighbor Advertisement
// carried one -- empty string if not (RFC 4861 4.4 says it SHOULD be included for a solicited
// unicast NA and MUST for a multicast one, but "should"/"must" are wire-format hopes, not
// guarantees a decoder can lean on).
std::string target_link_layer_mac(const Icmpv6Message& msg) {
    for (const auto& opt : msg.options) {
        if (opt.type == 2 && opt.link_layer_address) {
            return to_hex_string(opt.link_layer_address->address);
        }
    }
    // Fall back to type 1 (Source Link-Layer Address) -- not the RFC-recommended option for an NA,
    // but some real stacks are lax about which of the two they send, and this decoder would rather
    // have SOME link-layer identity to key the spoofing check on than none.
    for (const auto& opt : msg.options) {
        if (opt.type == 1 && opt.link_layer_address) {
            return to_hex_string(opt.link_layer_address->address);
        }
    }
    return "";
}

std::vector<std::string> ra_prefixes(const Icmpv6Message& msg) {
    std::vector<std::string> out;
    for (const auto& opt : msg.options) {
        if (opt.prefix_information) {
            out.push_back(opt.prefix_information->prefix + "/" +
                           std::to_string(static_cast<unsigned>(opt.prefix_information->prefix_length)));
        }
    }
    std::sort(out.begin(), out.end());  // order on the wire doesn't matter for equality
    return out;
}

template <typename MapT>
void evict_if_full(MapT& map, size_t cap) {
    if (map.size() >= cap && !map.empty()) {
        map.erase(map.begin());
    }
}

}  // namespace

void Ipv6AttackDetectionState::observe_icmpv6(const Icmpv6Message& msg, const std::string& src_ip,
                                               std::vector<std::string>& notes) {
    // Signature (2): RA flood -- see this file's own header comment on why this counts whole-link
    // messages rather than per-destination (an RA's real destination is ff02::1, the all-nodes
    // multicast address, not any one host).
    if (msg.type == 134 /* Router Advertisement */) {
        if (++ra_count_ >= flood_threshold && !ra_flood_flagged_) {
            ra_flood_flagged_ = true;
            notes.push_back(
                "Router Advertisement flood suspected: " + std::to_string(ra_count_) +
                " RA messages seen in this capture (threshold: " + std::to_string(flood_threshold) +
                ") -- the structural shape of thc-ipv6's flood_router6 (many RAs in rapid "
                "succession, often with randomized field values); a WHOLE-CAPTURE count, not a "
                "per-second rate, the same simplification attack_detect.hpp's own IPv4 flood "
                "counters use");
        }

        // Signature (1): RA identity collision -- see this file's own header comment for exactly
        // what "conflict" means and why this cannot, and does not, claim to know which (if either)
        // identity is the rogue one.
        std::string mac = source_link_layer_mac(msg);
        std::string identity_key = mac.empty() ? src_ip : (src_ip + "|" + mac);

        RaObservedFields fields;
        fields.router_lifetime_sec = msg.ra_router_lifetime_sec;
        fields.managed_flag = msg.ra_managed_flag;
        fields.other_flag = msg.ra_other_flag;
        fields.prefixes = ra_prefixes(msg);

        if (!ra_collision_flagged_ && fields.router_lifetime_sec > 0) {
            for (const auto& [other_key, other_fields] : ra_identities_) {
                if (other_key == identity_key) continue;  // same identity repeating itself is
                                                             // completely normal, never a collision
                if (other_fields.router_lifetime_sec == 0) continue;  // that identity isn't even
                                                                        // claiming default-router
                                                                        // status
                bool conflict = other_fields.prefixes != fields.prefixes ||
                                 other_fields.managed_flag != fields.managed_flag ||
                                 other_fields.other_flag != fields.other_flag ||
                                 other_fields.router_lifetime_sec != fields.router_lifetime_sec;
                if (conflict) {
                    ra_collision_flagged_ = true;
                    notes.push_back(
                        "multiple Router Advertisement identities observed advertising conflicting "
                        "default-router information (" + identity_key + " vs. " + other_key +
                        ") -- worth investigating: this tool cannot independently confirm which, "
                        "if either, is the legitimate router (RFC 6104 itself states that passive "
                        "observation alone cannot make that determination), and a redundant pair "
                        "of legitimate routers can produce this same structural shape; correlate "
                        "against known network infrastructure before treating this as an attack");
                    break;
                }
            }
        }

        evict_if_full(ra_identities_, kMaxTrackedEntries);
        ra_identities_[identity_key] = fields;
    }

    // Signature (3): NS/NA spoofing -- see this file's own header comment for why identity
    // diversity, not raw NA/NS volume, is the signal kept here.
    if (msg.type == 136 /* Neighbor Advertisement */ && !msg.target_address.empty()) {
        std::string mac = target_link_layer_mac(msg);
        if (!mac.empty()) {
            auto& macs = na_target_link_layer_addresses_[msg.target_address];
            if (std::find(macs.begin(), macs.end(), mac) == macs.end()) {
                evict_if_full(na_target_link_layer_addresses_, kMaxTrackedEntries);
                macs.push_back(mac);
            }
            if (macs.size() >= 2 && !na_spoof_flagged_[msg.target_address]) {
                na_spoof_flagged_[msg.target_address] = true;
                notes.push_back(
                    "Neighbor Advertisement spoofing suspected: " + std::to_string(macs.size()) +
                    " distinct link-layer addresses observed claiming the same target address (" +
                    msg.target_address +
                    ") -- the IPv6 analogue of ARP spoofing (thc-ipv6's parasite6/fake_advertise6, "
                    "or the DAD-DoS tool dos-new-ip6); worth investigating, since a legitimate "
                    "address handoff (e.g. failover) can occasionally produce a brief, one-time "
                    "version of this same structural shape");
            }
        }
    }
}

void Ipv6AttackDetectionState::observe_dhcpv6(const Dhcpv6Message& msg,
                                               std::vector<std::string>& notes) {
    if (msg.is_relay) return;  // never decoded through to the inner message -- see this file's own
                                 // OUT OF SCOPE section; client_duid_key/server_duid_key are only
                                 // ever populated for a non-relay message anyway

    // Signature (4): DHCPv6 exhaustion -- distinct Client DUIDs in SOLICIT/REQUEST, not raw packet
    // volume (one legitimate client retrying, same DUID, must never trip this).
    if ((msg.msg_type == 1 /* SOLICIT */ || msg.msg_type == 3 /* REQUEST */) &&
        !msg.client_duid_key.empty()) {
        if (dhcpv6_client_duids_seen_.size() < kMaxTrackedEntries) {
            dhcpv6_client_duids_seen_.insert(msg.client_duid_key);
        }
        if (dhcpv6_client_duids_seen_.size() >= flood_threshold && !dhcpv6_exhaustion_flagged_) {
            dhcpv6_exhaustion_flagged_ = true;
            notes.push_back(
                "DHCPv6 exhaustion suspected: " + std::to_string(dhcpv6_client_duids_seen_.size()) +
                " DISTINCT Client DUIDs observed sending SOLICIT/REQUEST in this capture "
                "(threshold: " + std::to_string(flood_threshold) +
                ") -- the structural shape of thc-ipv6's flood_dhcpc6 (address-pool starvation via "
                "many spoofed client identities); counted by distinct identity, not raw packet "
                "count, so one legitimate client retrying does not trip this");
        }
    }

    // Signature (5): rogue/multiple DHCPv6 servers -- distinct Server DUIDs in ADVERTISE/REPLY.
    if ((msg.msg_type == 2 /* ADVERTISE */ || msg.msg_type == 7 /* REPLY */) &&
        !msg.server_duid_key.empty()) {
        if (dhcpv6_server_duids_seen_.size() < kMaxTrackedEntries) {
            dhcpv6_server_duids_seen_.insert(msg.server_duid_key);
        }
        if (dhcpv6_server_duids_seen_.size() >= 2 && !dhcpv6_rogue_server_flagged_) {
            dhcpv6_rogue_server_flagged_ = true;
            notes.push_back(
                "multiple DHCPv6 server identities observed (" +
                std::to_string(dhcpv6_server_duids_seen_.size()) +
                " distinct Server DUIDs answering ADVERTISE/REPLY in this capture) -- worth "
                "investigating (thc-ipv6's fake_dhcps6 mirrors MITRE ATT&CK T1557.003's own "
                "detection analytic for DHCP spoofing generally: multiple competing offers from "
                "non-authorized servers), though a legitimate high-availability server pair "
                "produces this same structural shape; correlate against known server inventory "
                "before treating this as an attack");
        }
    }
}

}  // namespace conduitscope
