// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/policy.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <limits>
#include <sstream>
#include <unordered_set>

#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/yaml_mini.hpp"

namespace conduitscope {

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Prefixes `msg` with "<source>:<line>: " (or just "<source>: " when line is 0/unknown) -- the one
// consistent error format every PolicyError thrown from this file uses.
[[noreturn]] void fail(const std::string& source, int line, const std::string& msg) {
    std::ostringstream out;
    out << source << ":";
    if (line > 0) out << line << ": ";
    else out << " ";
    out << msg;
    throw PolicyError(out.str());
}

// One scalar value pulled out of a Node that's either itself a Scalar (treated as a one-element
// list, for ergonomic single-value fields like "ports: 502") or a Sequence of Scalars (a real
// list, whether written in block style or as a flow sequence "[...]" -- yaml_mini::parse already
// normalized both into the same Sequence-of-Scalar shape by the time this sees it).
struct ScalarItem {
    std::string text;
    int line;
};

// Converts `node` into a list of scalars for a field that accepts either a single value or a list
// of them. `field_desc` (e.g. "zone 'plc_zone's networks") names the field in any error thrown,
// consistent with how the rest of this file's errors are worded.
std::vector<ScalarItem> as_scalar_list(const yaml_mini::Node& node, const std::string& source,
                                        const std::string& field_desc) {
    using yaml_mini::NodeType;
    std::vector<ScalarItem> out;
    if (node.type == NodeType::Scalar) {
        out.push_back({node.scalar, node.line});
        return out;
    }
    if (node.type == NodeType::Sequence) {
        for (const auto& item : node.sequence) {
            if (item.type != NodeType::Scalar) {
                fail(source, item.line, field_desc + " must be a plain value or a list of plain values");
            }
            out.push_back({item.scalar, item.line});
        }
        return out;
    }
    fail(source, node.line, field_desc + " must be a plain value or a list of plain values");
}

const Zone* find_zone(const Policy& policy, const std::string& name) {
    for (const auto& z : policy.zones) {
        if (z.name == name) return &z;
    }
    return nullptr;
}

bool equal_ci(const std::string& a, const std::string& b) { return to_lower(a) == to_lower(b); }

// The one place this file maps a resolved single-protocol string ("modbus"/"dnp3"/"s7comm"/
// "iec104"/"enip") to that protocol's own canonical function/service name table -- see each
// *_known_*_names() function's own comment (modbus.hpp/dnp3.hpp/s7comm.hpp/iec104.hpp/enip.hpp)
// for exactly what it returns and why. Never called with "any" or an unresolved protocol string --
// the one-protocol-only 'functions' rule below (see parse_policy_text) is checked first. Returns
// {} for any of the six protocols 'protocols' was more recently widened to accept (bacnet/hartip/
// opcua/mms/mqtt/ffhse -- see ROADMAP) -- none of them has a known-function/service-name table
// yet, and protocol_has_known_function_table below is what actually gates 'functions' for those,
// with an honest error, rather than this function's empty-list return silently rejecting every
// entry one at a time with a confusing "unknown function" message.
std::vector<std::string> known_function_names_for(const std::string& protocol) {
    if (protocol == "modbus") return modbus_known_function_names();
    if (protocol == "dnp3") return dnp3_known_function_names();
    if (protocol == "s7comm") return s7comm_known_function_names();
    if (protocol == "iec104") return iec104_known_asdu_short_names();
    if (protocol == "enip") return enip_known_cip_service_names();
    return {};
}

// docs/design/policy-engine-zoning.md's Phase 4 (operation-level read/write direction): the
// per-protocol Read/Write group-keyword expansions for a conduit's 'functions: [read]'/'[write]'
// entries (see parse_policy_text's own handling below) -- one pair of sibling functions to
// known_function_names_for's own dispatch above, same five protocols, same reasoning for why this
// is a per-protocol table rather than one shared list.
std::vector<std::string> read_function_names_for(const std::string& protocol) {
    if (protocol == "modbus") return modbus_read_function_names();
    if (protocol == "dnp3") return dnp3_read_function_names();
    if (protocol == "s7comm") return s7comm_read_function_names();
    if (protocol == "iec104") return iec104_read_asdu_short_names();
    if (protocol == "enip") return enip_read_cip_service_names();
    return {};
}

std::vector<std::string> write_function_names_for(const std::string& protocol) {
    if (protocol == "modbus") return modbus_write_function_names();
    if (protocol == "dnp3") return dnp3_write_function_names();
    if (protocol == "s7comm") return s7comm_write_function_names();
    if (protocol == "iec104") return iec104_write_asdu_short_names();
    if (protocol == "enip") return enip_write_cip_service_names();
    return {};
}

// True for exactly the five protocols known_function_names_for above returns a non-empty table
// for -- used to give 'functions' on any other protocol (including the six 'protocols' was more
// recently widened to accept -- see parse_policy_text's own validation loop) a clear, specific
// rejection instead of letting every 'functions' entry silently fail with a generic "unknown
// function" message against an empty table.
bool protocol_has_known_function_table(const std::string& protocol) {
    return protocol == "modbus" || protocol == "dnp3" || protocol == "s7comm" ||
           protocol == "iec104" || protocol == "enip";
}

// Case-insensitive Levenshtein edit distance between `a` and `b`, for the 'functions:' "did you
// mean" suggestion below -- deliberately just this (not e.g. a word-token-aware metric): these are
// short, mostly-plain-English function/service names, and a typo (wrong case already handled
// separately, a dropped/doubled/transposed letter) is exactly what plain character-level edit
// distance catches well, without the complexity a fancier metric would add for little real benefit
// here (see the caller for how the result is thresholded).
size_t levenshtein_distance_ci(const std::string& a, const std::string& b) {
    std::string la = to_lower(a), lb = to_lower(b);
    size_t n = la.size(), m = lb.size();
    std::vector<size_t> prev(m + 1), cur(m + 1);
    for (size_t j = 0; j <= m; ++j) prev[j] = j;
    for (size_t i = 1; i <= n; ++i) {
        cur[0] = i;
        for (size_t j = 1; j <= m; ++j) {
            size_t cost = (la[i - 1] == lb[j - 1]) ? 0 : 1;
            cur[j] = std::min({prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost});
        }
        std::swap(prev, cur);
    }
    return prev[m];
}

// Returns the closest name in `candidates` to `given` (by levenshtein_distance_ci) when it's close
// enough to plausibly be a typo of it, or "" when nothing is close enough to be worth suggesting
// (an arbitrary but generous fixed distance threshold -- these are real function/service names, not
// short codes, so a handful of character edits is still clearly "almost this one" rather than "a
// different, unrelated name").
std::string nearest_function_name(const std::string& given, const std::vector<std::string>& candidates) {
    constexpr size_t kMaxSuggestDistance = 5;
    std::string best;
    size_t best_dist = std::numeric_limits<size_t>::max();
    for (const auto& candidate : candidates) {
        size_t dist = levenshtein_distance_ci(given, candidate);
        if (dist < best_dist) {
            best_dist = dist;
            best = candidate;
        }
    }
    if (best_dist <= kMaxSuggestDistance) return best;
    return "";
}

// Validates and canonicalizes a policy file's 'from_macs'/'from_mac' entry into the same
// lowercase, colon-separated form format_mac() (link_layer.cpp) emits for
// DecodedPacket::src_mac/dst_mac -- so PolicyEngine::finish's later comparison against
// EthernetFlowReport::src_mac is a plain string equality check, never case-insensitive. Mirrors
// parse_cidr's own posture toward malformed input: deliberately strict (exactly six
// two-hex-digit octets separated by colons) rather than a general "accept any reasonable MAC
// spelling" parser, since this IS user-typed input (unlike resolver.cpp's own private
// parse_format_mac, which only ever sees this codebase's own decoder-produced strings).
std::optional<std::string> parse_mac_address(const std::string& text) {
    if (text.size() != 17) return std::nullopt;
    std::string out;
    out.reserve(17);
    for (size_t i = 0; i < 6; ++i) {
        size_t pos = i * 3;
        if (i != 0) {
            if (text[pos - 1] != ':') return std::nullopt;
            out += ':';
        }
        auto hex_digit = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        int h = hex_digit(text[pos]);
        int l = hex_digit(text[pos + 1]);
        if (h < 0 || l < 0) return std::nullopt;
        static const char kHexChars[] = "0123456789abcdef";
        out += kHexChars[h];
        out += kHexChars[l];
    }
    return out;
}

}  // namespace

bool cidr_contains(const CidrBlock& block, uint32_t ip) {
    uint32_t mask = block.prefix_len == 0 ? 0u : (0xFFFFFFFFu << (32 - block.prefix_len));
    return (ip & mask) == (block.network & mask);
}

bool cidr_overlaps(const CidrBlock& a, const CidrBlock& b) {
    uint8_t shorter = std::min(a.prefix_len, b.prefix_len);
    uint32_t mask = shorter == 0 ? 0u : (0xFFFFFFFFu << (32 - shorter));
    return (a.network & mask) == (b.network & mask);
}

std::optional<CidrBlock> parse_cidr(const std::string& text) {
    std::string addr_part = text;
    int prefix = 32;
    size_t slash = text.find('/');
    if (slash != std::string::npos) {
        addr_part = text.substr(0, slash);
        std::string plen_text = text.substr(slash + 1);
        if (plen_text.empty()) return std::nullopt;
        for (char c : plen_text) {
            if (c < '0' || c > '9') return std::nullopt;
        }
        if (plen_text.size() > 2) return std::nullopt;  // reject e.g. "/033" outright, not just >32
        prefix = std::stoi(plen_text);
        if (prefix < 0 || prefix > 32) return std::nullopt;
    }
    auto addr = parse_ipv4_string(addr_part);
    if (!addr) return std::nullopt;

    CidrBlock block;
    block.prefix_len = static_cast<uint8_t>(prefix);
    uint32_t mask = block.prefix_len == 0 ? 0u : (0xFFFFFFFFu << (32 - block.prefix_len));
    block.network = *addr & mask;
    block.text = text;
    return block;
}

const Zone* Policy::zone_for(uint32_t ip) const {
    for (const auto& z : zones) {
        for (const auto& n : z.networks) {
            if (cidr_contains(n, ip)) return &z;
        }
    }
    return nullptr;
}

const Zone* Policy::zone_for_vlan(uint16_t vlan_id) const {
    for (const auto& z : zones) {
        if (z.kind != ZoneKind::Vlan) continue;
        for (uint16_t v : z.vlans) {
            if (v == vlan_id) return &z;
        }
    }
    return nullptr;
}

bool Policy::has_vlan_zone() const {
    return std::any_of(zones.begin(), zones.end(), [](const Zone& z) { return z.kind == ZoneKind::Vlan; });
}

const Zone* Policy::zone_for_hostname(const std::string& hostname) const {
    for (const auto& z : zones) {
        if (z.kind != ZoneKind::Hostname) continue;
        for (const auto& h : z.hostnames) {
            if (h == hostname) return &z;
        }
    }
    return nullptr;
}

bool Policy::has_hostname_zone() const {
    return std::any_of(zones.begin(), zones.end(), [](const Zone& z) { return z.kind == ZoneKind::Hostname; });
}

bool Policy::has_udp_eligible_conduit() const {
    return std::any_of(conduits.begin(), conduits.end(), [](const Conduit& c) {
        if (c.kind == ZoneKind::Vlan) return false;
        return std::find(c.protocols.begin(), c.protocols.end(), "bacnet") != c.protocols.end() ||
               std::find(c.protocols.begin(), c.protocols.end(), "enip") != c.protocols.end() ||
               std::find(c.protocols.begin(), c.protocols.end(), "any") != c.protocols.end();
    });
}

Policy parse_policy_text(const std::string& text, const std::string& source_name) {
    using yaml_mini::NodeType;

    yaml_mini::Node root;
    try {
        root = yaml_mini::parse(text);
    } catch (const yaml_mini::YamlError& e) {
        fail(source_name, e.line, e.what());
    }
    if (root.type != NodeType::Mapping) {
        fail(source_name, 0,
             "a policy file must be a top-level mapping with 'zones' and 'conduits' keys");
    }

    Policy policy;

    // --- zones -----------------------------------------------------------
    const yaml_mini::Node* zones_node = root.find("zones");
    if (!zones_node) {
        fail(source_name, 0, "missing required top-level 'zones' key");
    }
    if (zones_node->type != NodeType::Mapping) {
        fail(source_name, zones_node->line, "'zones' must be a mapping of zone name -> zone definition");
    }
    std::unordered_set<std::string> zone_names;
    for (const auto& [zname, zval] : zones_node->mapping) {
        if (zname == "unclassified") {
            fail(source_name, zval.line,
                 "'unclassified' is a reserved zone name (used in reports for traffic matching no "
                 "declared zone) and cannot be declared as a real zone");
        }
        if (!zone_names.insert(zname).second) {
            fail(source_name, zval.line, "duplicate zone name '" + zname + "'");
        }
        if (zval.type != NodeType::Mapping) {
            fail(source_name, zval.line, "zone '" + zname + "' must be a mapping with a 'networks' key");
        }
        Zone zone;
        zone.name = zname;
        zone.line = zval.line;
        if (const auto* desc = zval.find("description")) {
            if (desc->type == NodeType::Scalar) zone.description = desc->scalar;
        }
        if (const auto* purdue = zval.find("purdue_level")) {
            if (purdue->type == NodeType::Scalar) zone.purdue_level = purdue->scalar;
        }
        const yaml_mini::Node* nets = zval.find("networks");
        const yaml_mini::Node* vlans = zval.find("vlans");
        if (!vlans) vlans = zval.find("vlan");  // singular alias, for a one-VLAN zone
        const yaml_mini::Node* hostnames = zval.find("hostnames");
        if (!hostnames) hostnames = zval.find("hostname");  // singular alias, for a one-hostname zone
        int kind_count = (nets ? 1 : 0) + (vlans ? 1 : 0) + (hostnames ? 1 : 0);
        if (kind_count > 1) {
            fail(source_name, zval.line,
                 "zone '" + zname +
                     "' declares more than one of 'networks'/'vlans'/'hostnames' -- a zone is "
                     "exactly one kind (see docs/USER_GUIDE.md's POLICY FILE FORMAT section)");
        }
        if (kind_count == 0) {
            fail(source_name, zval.line,
                 "zone '" + zname + "' has no 'networks', 'vlans', or 'hostnames' key");
        }
        if (nets) {
            auto net_list = as_scalar_list(*nets, source_name, "zone '" + zname + "'s 'networks'");
            if (net_list.empty()) {
                fail(source_name, nets->line, "zone '" + zname + "' declares no networks");
            }
            for (const auto& item : net_list) {
                auto cidr = parse_cidr(item.text);
                if (!cidr) {
                    fail(source_name, item.line,
                         "zone '" + zname + "': '" + item.text +
                             "' is not a valid IPv4 address or CIDR block (expected e.g. '10.10.10.0/24' "
                             "or a bare address)");
                }
                zone.networks.push_back(*cidr);
            }
        } else if (vlans) {
            zone.kind = ZoneKind::Vlan;
            auto vlan_list = as_scalar_list(*vlans, source_name, "zone '" + zname + "'s 'vlans'");
            if (vlan_list.empty()) {
                fail(source_name, vlans->line, "zone '" + zname + "' declares no VLANs");
            }
            for (const auto& item : vlan_list) {
                bool all_digits = !item.text.empty() &&
                                   std::all_of(item.text.begin(), item.text.end(),
                                               [](unsigned char ch) { return std::isdigit(ch); });
                int value = -1;
                if (all_digits) {
                    try {
                        value = std::stoi(item.text);
                    } catch (const std::exception&) {
                        value = -1;
                    }
                }
                if (value < kMinVlanId || value > kMaxVlanId) {
                    fail(source_name, item.line,
                         "zone '" + zname + "': '" + item.text + "' is not a valid VLAN ID (expected " +
                             std::to_string(kMinVlanId) + "-" + std::to_string(kMaxVlanId) +
                             " -- VID 0 is reserved for priority-tagged, non-VLAN-member frames and "
                             "4095 is reserved outright)");
                }
                zone.vlans.push_back(static_cast<uint16_t>(value));
            }
        } else {
            zone.kind = ZoneKind::Hostname;
            auto host_list = as_scalar_list(*hostnames, source_name, "zone '" + zname + "'s 'hostnames'");
            if (host_list.empty()) {
                fail(source_name, hostnames->line, "zone '" + zname + "' declares no hostnames");
            }
            for (const auto& item : host_list) {
                if (item.text.empty()) {
                    fail(source_name, item.line, "zone '" + zname + "': a 'hostnames' entry is empty");
                }
                zone.hostnames.push_back(item.text);
            }
        }
        policy.zones.push_back(std::move(zone));
    }
    if (policy.zones.empty()) {
        fail(source_name, zones_node->line, "'zones' must declare at least one zone");
    }

    // No two zones of the same kind may claim the same address/VLAN/hostname -- an unambiguous
    // zone-per-address(-or-VLAN-or-hostname) model is the whole point of this feature (PolicyEngine
    // has to be able to say definitively which single zone a packet belongs to). Zones of different
    // kinds can never overlap with each other -- they have no addressing scheme in common -- so
    // only same-kind pairs are checked. O(zones^2 * networks^2) is fine for any policy file a person
    // would actually hand-write.
    for (size_t i = 0; i < policy.zones.size(); ++i) {
        for (size_t j = i + 1; j < policy.zones.size(); ++j) {
            const Zone& za = policy.zones[i];
            const Zone& zb = policy.zones[j];
            if (za.kind != zb.kind) continue;
            if (za.kind == ZoneKind::Cidr) {
                for (const auto& a : za.networks) {
                    for (const auto& b : zb.networks) {
                        if (cidr_overlaps(a, b)) {
                            fail(source_name, zb.line,
                                 "zone '" + za.name + "' (" + a.text + ") and zone '" + zb.name + "' (" +
                                     b.text + ") overlap -- each address must belong to at most one zone");
                        }
                    }
                }
            } else if (za.kind == ZoneKind::Vlan) {
                for (uint16_t a : za.vlans) {
                    for (uint16_t b : zb.vlans) {
                        if (a == b) {
                            fail(source_name, zb.line,
                                 "zone '" + za.name + "' and zone '" + zb.name + "' both claim VLAN " +
                                     std::to_string(a) + " -- each VLAN must belong to at most one zone");
                        }
                    }
                }
            } else {  // ZoneKind::Hostname
                for (const auto& a : za.hostnames) {
                    for (const auto& b : zb.hostnames) {
                        if (a == b) {
                            fail(source_name, zb.line,
                                 "zone '" + za.name + "' and zone '" + zb.name + "' both claim hostname '" +
                                     a + "' -- each hostname must belong to at most one zone");
                        }
                    }
                }
            }
        }
    }

    // --- conduits ----------------------------------------------------------
    const yaml_mini::Node* conduits_node = root.find("conduits");
    if (!conduits_node) {
        fail(source_name, 0, "missing required top-level 'conduits' key");
    }
    if (conduits_node->type != NodeType::Sequence) {
        fail(source_name, conduits_node->line, "'conduits' must be a list of conduit definitions");
    }
    std::unordered_set<std::string> conduit_names;
    for (const auto& item : conduits_node->sequence) {
        if (item.type != NodeType::Mapping) {
            fail(source_name, item.line,
                 "each conduit must be a mapping (name/from/to/protocols/ports/...)");
        }
        Conduit c;
        c.line = item.line;

        const auto* name = item.find("name");
        if (!name || name->type != NodeType::Scalar || name->scalar.empty()) {
            fail(source_name, item.line, "a conduit is missing a required 'name'");
        }
        c.name = name->scalar;
        if (!conduit_names.insert(c.name).second) {
            fail(source_name, item.line, "duplicate conduit name '" + c.name + "'");
        }

        const auto* from = item.find("from");
        const auto* to = item.find("to");
        if (!from) {
            fail(source_name, item.line, "conduit '" + c.name + "' is missing a required 'from' zone");
        }
        if (!to) {
            fail(source_name, item.line, "conduit '" + c.name + "' is missing a required 'to' zone");
        }
        auto from_list = as_scalar_list(*from, source_name, "conduit '" + c.name + "'s 'from'");
        if (from_list.empty()) {
            fail(source_name, from->line, "conduit '" + c.name + "' declares no 'from' zones");
        }
        for (const auto& z : from_list) {
            if (!find_zone(policy, z.text)) {
                fail(source_name, item.line,
                     "conduit '" + c.name + "': 'from' zone '" + z.text + "' is not declared in 'zones'");
            }
            c.from_zones.push_back(z.text);
        }
        auto to_list = as_scalar_list(*to, source_name, "conduit '" + c.name + "'s 'to'");
        if (to_list.empty()) {
            fail(source_name, to->line, "conduit '" + c.name + "' declares no 'to' zones");
        }
        for (const auto& z : to_list) {
            if (!find_zone(policy, z.text)) {
                fail(source_name, item.line,
                     "conduit '" + c.name + "': 'to' zone '" + z.text + "' is not declared in 'zones'");
            }
            c.to_zones.push_back(z.text);
        }

        // Every zone this conduit references, on either side, must be the same kind (see
        // policy.hpp's own header comment and Conduit's comment for why zones of different kinds
        // can't mix on one conduit) -- determined here, once, since it drives every kind-specific
        // validation rule below (protocol names, VLAN-only from==to, VLAN-only
        // ports/bidirectional/functions rejection).
        std::vector<ZoneKind> referenced_kinds;
        auto note_kind = [&](ZoneKind k) {
            if (std::find(referenced_kinds.begin(), referenced_kinds.end(), k) == referenced_kinds.end()) {
                referenced_kinds.push_back(k);
            }
        };
        for (const auto& z : c.from_zones) note_kind(find_zone(policy, z)->kind);
        for (const auto& z : c.to_zones) note_kind(find_zone(policy, z)->kind);
        if (referenced_kinds.size() > 1) {
            fail(source_name, item.line,
                 "conduit '" + c.name +
                     "' mixes zones of different kinds (CIDR/VLAN/hostname) in its 'from'/'to' -- "
                     "every zone a conduit references must be the same kind (see "
                     "docs/USER_GUIDE.md's POLICY FILE FORMAT section)");
        }
        c.kind = referenced_kinds.empty() ? ZoneKind::Cidr : referenced_kinds.front();
        bool is_vlan_conduit = (c.kind == ZoneKind::Vlan);

        if (is_vlan_conduit) {
            // A single raw-Ethernet frame carries at most one VLAN tag, so a VLAN-zone conduit
            // can't model a directional flow between two different zones the way an IP-zone
            // conduit does -- see policy.hpp's Conduit::from_zones/to_zones comment. Requiring the
            // exact same SET (not just the same size/order) makes that explicit in the policy file.
            std::vector<std::string> from_sorted = c.from_zones, to_sorted = c.to_zones;
            std::sort(from_sorted.begin(), from_sorted.end());
            std::sort(to_sorted.begin(), to_sorted.end());
            from_sorted.erase(std::unique(from_sorted.begin(), from_sorted.end()), from_sorted.end());
            to_sorted.erase(std::unique(to_sorted.begin(), to_sorted.end()), to_sorted.end());
            if (from_sorted != to_sorted) {
                fail(source_name, item.line,
                     "conduit '" + c.name +
                         "' is a VLAN-zone conduit; 'from' and 'to' must name the exact same VLAN "
                         "zone(s) -- it permits its protocol(s) ON that VLAN zone, not a directional "
                         "flow between two zones (see docs/MANUAL.md's POLICY FILE FORMAT section)");
            }
        }

        const yaml_mini::Node* protos = item.find("protocols");
        if (!protos) protos = item.find("protocol");  // singular alias, for a one-protocol conduit
        if (!protos) {
            fail(source_name, item.line, "conduit '" + c.name + "' is missing required 'protocols'");
        }
        auto proto_list = as_scalar_list(*protos, source_name, "conduit '" + c.name + "'s 'protocols'");
        if (proto_list.empty()) {
            fail(source_name, protos->line, "conduit '" + c.name + "' declares no protocols");
        }
        for (const auto& p : proto_list) {
            std::string lower = to_lower(p.text);
            if (lower != "modbus" && lower != "dnp3" && lower != "s7comm" && lower != "iec104" &&
                lower != "enip" && lower != "bacnet" && lower != "hartip" && lower != "opcua" &&
                lower != "mms" && lower != "mqtt" && lower != "ffhse" && lower != "profinet" &&
                lower != "goose" && lower != "sv" && lower != "ethercat" && lower != "any") {
                fail(source_name, p.line,
                     "conduit '" + c.name + "': unknown protocol '" + p.text +
                         "' (expected one of: modbus, dnp3, s7comm, iec104, enip, bacnet, hartip, "
                         "opcua, mms, mqtt, ffhse, profinet, goose, sv, ethercat, any)");
            }
            bool is_vlan_only_protocol =
                lower == "profinet" || lower == "goose" || lower == "sv" || lower == "ethercat";
            if (is_vlan_conduit && lower != "any" && !is_vlan_only_protocol) {
                fail(source_name, p.line,
                     "conduit '" + c.name + "': protocol '" + p.text +
                         "' rides IPv4/TCP, not raw Ethernet, so it can never appear on a VLAN-zone "
                         "conduit -- only profinet, goose, sv, ethercat, or 'any' can");
            }
            if (!is_vlan_conduit && is_vlan_only_protocol) {
                fail(source_name, p.line,
                     "conduit '" + c.name + "': protocol '" + p.text +
                         "' has no IP layer at all, so it can never appear on a CIDR- or hostname-zone "
                         "conduit -- declare a VLAN zone instead (see docs/USER_GUIDE.md's POLICY FILE "
                         "FORMAT section)");
            }
            c.protocols.push_back(lower);
        }

        if (is_vlan_conduit && item.find("ports")) {
            fail(source_name, item.line,
                 "conduit '" + c.name +
                     "': 'ports' has no meaning on a VLAN-zone conduit -- profinet/goose/sv/ethercat "
                     "have no TCP/UDP layer at all");
        }

        if (const yaml_mini::Node* ports = item.find("ports")) {
            for (const auto& p : as_scalar_list(*ports, source_name, "conduit '" + c.name + "'s 'ports'")) {
                bool all_digits = !p.text.empty() &&
                                   std::all_of(p.text.begin(), p.text.end(), [](unsigned char ch) { return std::isdigit(ch); });
                int value = -1;
                if (all_digits) {
                    try {
                        value = std::stoi(p.text);
                    } catch (const std::exception&) {
                        value = -1;
                    }
                }
                if (value < 1 || value > 65535) {
                    fail(source_name, p.line,
                         "conduit '" + c.name + "': '" + p.text + "' is not a valid TCP port (expected 1-65535)");
                }
                c.ports.push_back(static_cast<uint16_t>(value));
            }
        }  // absent/empty 'ports' means "any port" -- c.ports stays empty, see policy_engine.cpp

        if (const auto* bidir = item.find("bidirectional")) {
            if (bidir->type != NodeType::Scalar) {
                fail(source_name, item.line, "conduit '" + c.name + "': 'bidirectional' must be true or false");
            }
            std::string lower = to_lower(bidir->scalar);
            if (lower == "true" || lower == "yes") {
                c.bidirectional = true;
            } else if (lower == "false" || lower == "no") {
                c.bidirectional = false;
            } else {
                fail(source_name, item.line, "conduit '" + c.name + "': 'bidirectional' must be true or false");
            }
            if (is_vlan_conduit && c.bidirectional) {
                fail(source_name, item.line,
                     "conduit '" + c.name +
                         "': 'bidirectional' has no meaning on a VLAN-zone conduit -- there is no "
                         "client/server session to reverse (its 'from'/'to' already name the same "
                         "zone(s), see above)");
            }
        }

        if (is_vlan_conduit && (item.find("functions") || item.find("function"))) {
            fail(source_name, item.line,
                 "conduit '" + c.name +
                     "': 'functions'/'function' has no meaning on a VLAN-zone conduit -- "
                     "profinet/goose/sv/ethercat have no per-flow function/service name this engine "
                     "tracks yet (see ROADMAP)");
        }

        if (const yaml_mini::Node* funcs = item.find("functions") ? item.find("functions") : item.find("function")) {
            auto func_list = as_scalar_list(*funcs, source_name, "conduit '" + c.name + "'s 'functions'");
            if (!func_list.empty()) {
                // See policy.hpp's Conduit::functions comment and parse_policy_text's own comment
                // for why: the known-function-name table to validate/match against is entirely
                // per-protocol, so 'functions' only makes sense once 'protocols' has resolved to
                // exactly one concrete protocol.
                if (c.protocols.size() != 1 || c.protocols[0] == "any") {
                    fail(source_name, funcs->line,
                         "conduit '" + c.name +
                             "': 'functions' requires exactly one protocol in 'protocols' (not "
                             "'any', and not a list of more than one) -- write one conduit per "
                             "protocol when the allowed functions differ");
                }
                const std::string& proto = c.protocols[0];
                if (!protocol_has_known_function_table(proto)) {
                    fail(source_name, funcs->line,
                         "conduit '" + c.name + "': 'functions' is not yet supported for protocol '" +
                             proto +
                             "' -- only modbus, dnp3, s7comm, iec104, and enip have a known "
                             "function/service name table so far (see ROADMAP); write the conduit "
                             "without 'functions' for now");
                }
                std::vector<std::string> known = known_function_names_for(proto);
                auto add_function_once = [&](const std::string& name) {
                    if (std::find(c.functions.begin(), c.functions.end(), name) == c.functions.end()) {
                        c.functions.push_back(name);
                    }
                };
                for (const auto& f : func_list) {
                    // Reserved group keywords, case-insensitive (docs/design/policy-engine-zoning.md's
                    // Phase 4): 'read'/'write' expand into that protocol's own read/write-classified
                    // function names (see *_read_function_names/*_write_function_names above),
                    // combinable in the same list with literal function names ('functions: [read,
                    // "Diagnostics"]'). These take priority over a literal match -- DNP3 happens to
                    // have its own literal function codes named "Read"/"Write" (0x01/0x02), and the
                    // reserved keyword wins that collision rather than the literal name, so
                    // 'functions: [read]' on a dnp3 conduit means "every DNP3 function this decoder
                    // classifies as a read" (Read + Get File Info), not just the one literal function
                    // called "Read" -- see dnp3.hpp's own comment on dnp3_read_function_names for this
                    // specific, accepted trade-off, and docs/USER_GUIDE.md for the user-facing callout.
                    if (equal_ci(f.text, "read") || equal_ci(f.text, "write")) {
                        bool is_read = equal_ci(f.text, "read");
                        std::vector<std::string> group =
                            is_read ? read_function_names_for(proto) : write_function_names_for(proto);
                        // Defensive, not reachable for today's five protocols (each has at least one
                        // Read- and one Write-classified function) -- but 'functions:' empty means
                        // UNRESTRICTED (see Conduit::functions' own comment), so a keyword that
                        // silently expanded to nothing would leave a 'functions: [read]' conduit
                        // wide open instead of read-only, exactly backwards from what the policy
                        // author wrote. Fail loudly instead of letting that happen silently.
                        if (group.empty()) {
                            fail(source_name, f.line,
                                 "conduit '" + c.name + "': '" + f.text + "' matches no known " + proto +
                                     " function -- this would leave the conduit unrestricted instead "
                                     "of " + (is_read ? "read-only" : "write-only") +
                                     ", so it's rejected rather than silently doing that");
                        }
                        for (const auto& name : group) add_function_once(name);
                        continue;
                    }
                    const std::string* canonical = nullptr;
                    for (const auto& k : known) {
                        if (equal_ci(k, f.text)) {
                            canonical = &k;
                            break;
                        }
                    }
                    if (!canonical) {
                        std::string suggestion = nearest_function_name(f.text, known);
                        std::string msg = "conduit '" + c.name + "': unknown " + proto + " function '" +
                                           f.text + "'";
                        if (!suggestion.empty()) msg += " -- did you mean '" + suggestion + "'?";
                        fail(source_name, f.line, msg);
                    }
                    add_function_once(*canonical);
                }
            }
        }  // absent/empty 'functions'/'function' means "no restriction" -- c.functions stays empty

        if (!is_vlan_conduit && (item.find("from_macs") || item.find("from_mac"))) {
            fail(source_name, item.line,
                 "conduit '" + c.name +
                     "': 'from_macs'/'from_mac' has no meaning on a CIDR- or hostname-zone conduit "
                     "-- source-MAC restriction only applies to a VLAN-zone conduit, which has no "
                     "client/server IP pair to restrict by the way a CIDR-/hostname-zone conduit "
                     "already can (see docs/USER_GUIDE.md's POLICY FILE FORMAT section)");
        }

        if (const yaml_mini::Node* macs = item.find("from_macs") ? item.find("from_macs") : item.find("from_mac")) {
            for (const auto& m : as_scalar_list(*macs, source_name, "conduit '" + c.name + "'s 'from_macs'")) {
                auto parsed = parse_mac_address(m.text);
                if (!parsed) {
                    fail(source_name, m.line,
                         "conduit '" + c.name + "': '" + m.text +
                             "' is not a valid MAC address (expected six colon-separated hex "
                             "octets, e.g. '00:0c:29:11:22:33')");
                }
                if (std::find(c.from_macs.begin(), c.from_macs.end(), *parsed) == c.from_macs.end()) {
                    c.from_macs.push_back(*parsed);
                }
            }
        }  // absent/empty 'from_macs'/'from_mac' means "unrestricted" -- c.from_macs stays empty,
           // see policy_engine.cpp

        if (const auto* type_node = item.find("type")) {
            if (type_node->type != NodeType::Scalar) {
                fail(source_name, item.line, "conduit '" + c.name + "': 'type' must be a plain value");
            }
            std::string lower_type = to_lower(type_node->scalar);
            if (lower_type != "idmz") {
                fail(source_name, type_node->line,
                     "conduit '" + c.name + "': unknown conduit type '" + type_node->scalar +
                         "' (the only recognized value so far is 'idmz')");
            }
            c.conduit_type = lower_type;
            // "Stricter default deny" for a declared IT-OT/iDMZ boundary (see Conduit::conduit_type's
            // own comment): an unrestricted 'any' protocol conduit with no 'functions' allow-list is
            // rejected outright, forcing the policy author to name exactly what may cross it. Every
            // OTHER conduit-level rule (deny-by-default for an unmatched zone pair) already applies
            // identically regardless of 'type' -- this is the one extra tightening 'idmz' adds.
            if (c.protocols.size() == 1 && c.protocols[0] == "any" && c.functions.empty()) {
                fail(source_name, item.line,
                     "conduit '" + c.name +
                         "': an 'idmz'-typed conduit cannot use 'protocols: [any]' with no "
                         "'functions' restriction -- a declared IT-OT/iDMZ crossing must name "
                         "exactly which protocol(s) (and, where supported, functions) it permits");
            }
        }

        if (const auto* desc = item.find("description")) {
            if (desc->type == NodeType::Scalar) c.description = desc->scalar;
        }

        policy.conduits.push_back(std::move(c));
    }
    if (policy.conduits.empty()) {
        fail(source_name, conduits_node->line,
             "'conduits' must declare at least one conduit -- a policy with zones but zero allowed "
             "conduits would flag every classified flow as a violation, which is very unlikely to "
             "be what was intended for a first policy file");
    }

    // --- assets (Phase 6, optional) --------------------------------------
    // A fully optional top-level 'assets:' list of declared multi-homed assets -- see Asset's own
    // header comment (policy.hpp) for what this feature does and why it can never change a
    // FlowVerdict. Omitted entirely (the common case): policy.assets stays empty and every other
    // code path in this function/PolicyEngine is completely unaffected.
    if (const yaml_mini::Node* assets_node = root.find("assets")) {
        if (assets_node->type != NodeType::Sequence) {
            fail(source_name, assets_node->line, "'assets' must be a list of asset definitions");
        }
        std::unordered_set<std::string> asset_names;
        for (const auto& item : assets_node->sequence) {
            if (item.type != NodeType::Mapping) {
                fail(source_name, item.line, "each asset must be a mapping (name/ips/role/...)");
            }
            Asset a;
            a.line = item.line;

            const auto* name = item.find("name");
            if (!name || name->type != NodeType::Scalar || name->scalar.empty()) {
                fail(source_name, item.line, "an asset is missing a required 'name'");
            }
            a.name = name->scalar;
            if (!asset_names.insert(a.name).second) {
                fail(source_name, item.line, "duplicate asset name '" + a.name + "'");
            }

            const auto* ips = item.find("ips");
            if (!ips) {
                fail(source_name, item.line, "asset '" + a.name + "' is missing a required 'ips' list");
            }
            auto ip_list = as_scalar_list(*ips, source_name, "asset '" + a.name + "'s 'ips'");
            if (ip_list.size() < 2) {
                fail(source_name, ips->line,
                     "asset '" + a.name +
                         "' declares fewer than two 'ips' -- an asset must declare at least two IPs "
                         "to be 'multi-homed' in the first place; a single-homed device needs no "
                         "'assets:' entry at all");
            }
            for (const auto& item2 : ip_list) {
                auto cidr = parse_cidr(item2.text);
                if (!cidr) {
                    fail(source_name, item2.line,
                         "asset '" + a.name + "': '" + item2.text +
                             "' is not a valid IPv4 address or CIDR block (expected e.g. "
                             "'10.10.10.0/24' or a bare address)");
                }
                for (const auto& existing : a.ips) {
                    if (existing.text == item2.text) {
                        fail(source_name, item2.line,
                             "asset '" + a.name + "': '" + item2.text +
                                 "' is listed more than once in 'ips'");
                    }
                }
                a.ips.push_back(*cidr);
            }

            if (const auto* role = item.find("role")) {
                if (role->type == NodeType::Scalar) a.role = role->scalar;
            }
            if (const auto* desc = item.find("description")) {
                if (desc->type == NodeType::Scalar) a.description = desc->scalar;
            }

            policy.assets.push_back(std::move(a));
        }
    }

    return policy;
}

Policy parse_policy_file(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw PolicyError("cannot open policy file '" + path + "'");
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    return parse_policy_text(buf.str(), path);
}

}  // namespace conduitscope
