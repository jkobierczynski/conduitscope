// SPDX-License-Identifier: MIT
#include "conduitscope/policy.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <sstream>
#include <unordered_set>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/yaml_mini.hpp"

namespace conduitscope {

namespace {

std::string to_lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
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
        const yaml_mini::Node* nets = zval.find("networks");
        if (!nets) {
            fail(source_name, zval.line, "zone '" + zname + "' has no 'networks' key");
        }
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
        policy.zones.push_back(std::move(zone));
    }
    if (policy.zones.empty()) {
        fail(source_name, zones_node->line, "'zones' must declare at least one zone");
    }

    // No two zones may claim the same address -- an unambiguous zone-per-address model is the
    // whole point of this feature (PolicyEngine has to be able to say definitively which single
    // zone a packet's source/destination belongs to). O(zones^2 * networks^2) is fine for any
    // policy file a person would actually hand-write.
    for (size_t i = 0; i < policy.zones.size(); ++i) {
        for (size_t j = i + 1; j < policy.zones.size(); ++j) {
            for (const auto& a : policy.zones[i].networks) {
                for (const auto& b : policy.zones[j].networks) {
                    if (cidr_overlaps(a, b)) {
                        fail(source_name, policy.zones[j].line,
                             "zone '" + policy.zones[i].name + "' (" + a.text + ") and zone '" +
                                 policy.zones[j].name + "' (" + b.text +
                                 ") overlap -- each address must belong to at most one zone");
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
        if (!from || from->type != NodeType::Scalar || from->scalar.empty()) {
            fail(source_name, item.line, "conduit '" + c.name + "' is missing a required 'from' zone");
        }
        if (!to || to->type != NodeType::Scalar || to->scalar.empty()) {
            fail(source_name, item.line, "conduit '" + c.name + "' is missing a required 'to' zone");
        }
        c.from_zone = from->scalar;
        c.to_zone = to->scalar;
        if (!find_zone(policy, c.from_zone)) {
            fail(source_name, item.line,
                 "conduit '" + c.name + "': 'from' zone '" + c.from_zone + "' is not declared in 'zones'");
        }
        if (!find_zone(policy, c.to_zone)) {
            fail(source_name, item.line,
                 "conduit '" + c.name + "': 'to' zone '" + c.to_zone + "' is not declared in 'zones'");
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
                lower != "enip" && lower != "any") {
                fail(source_name, p.line,
                     "conduit '" + c.name + "': unknown protocol '" + p.text +
                         "' (expected one of: modbus, dnp3, s7comm, iec104, enip, any)");
            }
            c.protocols.push_back(lower);
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
