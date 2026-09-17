// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/policy_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ostream>
#include <sstream>

#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"

namespace conduitscope {

namespace {

std::string session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b, uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

// True for exactly the four protocols with no IP layer at all that PolicyEngine can classify by
// VLAN zone -- see policy.hpp's own header comment and PolicyEngine::observe's comment.
bool is_vlan_zone_eligible_protocol(const std::string& protocol) {
    return protocol == "profinet" || protocol == "goose" || protocol == "sv" || protocol == "ethercat";
}

// Canonical (undirected) key for an L2 flow -- protocol plus a MAC pair in a fixed order, so
// traffic seen from either direction between the same two MACs folds into one EthernetFlowState,
// the same "canonicalize so direction doesn't fragment the flow" idea session_key uses for a TCP
// 4-tuple above (mirrored here at the MAC-address layer since these protocols have no port/session
// concept to canonicalize instead).
std::string ethernet_flow_key(const std::string& protocol, const std::string& mac_a, const std::string& mac_b) {
    return protocol + ":" + ((mac_a < mac_b) ? (mac_a + "<->" + mac_b) : (mac_b + "<->" + mac_a));
}

bool is_known_service_port(uint16_t port) {
    return port == MODBUS_TCP_PORT || port == DNP3_TCP_PORT || port == COTP_TCP_PORT ||
           port == IEC104_TCP_PORT || port == ENIP_TCP_PORT;
}

// Guesses which side of a brand-new flow is the server, when no SYN/SYN-ACK is available to
// decide authoritatively -- see PolicyEngine::observe's doc comment (policy_engine.hpp) for the
// full priority order this implements step 3 of.
bool src_is_client_by_port(uint16_t src_port, uint16_t dst_port) {
    bool src_known = is_known_service_port(src_port);
    bool dst_known = is_known_service_port(dst_port);
    if (dst_known && !src_known) return true;   // dst is the recognized service port -> src is client
    if (src_known && !dst_known) return false;  // src is the recognized service port -> dst is client
    return src_port > dst_port;                 // neither/both known: lower port number is the server
}

std::string protocol_list_text(const std::vector<std::string>& protocols) {
    std::string out;
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (i) out += "+";
        out += protocols[i];
    }
    return out;
}

std::string to_lower_copy(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return std::tolower(c); });
    return out;
}

bool equal_ci(const std::string& a, const std::string& b) { return to_lower_copy(a) == to_lower_copy(b); }

// True if `zone` is one of `zones` -- used to check a flow's client/server zone against a
// conduit's (now list-valued, many-to-many) from_zones/to_zones -- see the matching logic in
// finish() below.
bool zone_list_contains(const std::vector<std::string>& zones, const std::string& zone) {
    return std::find(zones.begin(), zones.end(), zone) != zones.end();
}

// Joins `items` with ", " -- shared by the "functions observed" and "permits only" halves of a
// functions-restricted conduit's violation reason (see the functions-matching block in finish()).
std::string join_comma(const std::vector<std::string>& items) {
    std::string out;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) out += ", ";
        out += items[i];
    }
    return out;
}

std::string verdict_name(FlowVerdict v) {
    switch (v) {
        case FlowVerdict::Allowed: return "allowed";
        case FlowVerdict::Violation: return "violation";
        case FlowVerdict::Unclassified: return "unclassified";
    }
    return "unclassified";
}

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

}  // namespace

void PolicyEngine::observe(const DecodedPacket& dp) {
    ++total_packets_;

    if (is_vlan_zone_eligible_protocol(dp.protocol) && any_vlan_zone_) {
        // See this function's own doc comment (policy_engine.hpp) for why this branch only exists
        // once the policy has opted in by declaring at least one VLAN zone -- backward
        // compatibility for every policy file written before this feature existed.
        std::string key = ethernet_flow_key(dp.protocol, dp.src_mac, dp.dst_mac);
        auto it = ethernet_flows_.find(key);
        if (it == ethernet_flows_.end()) {
            EthernetFlowState es;
            es.protocol = dp.protocol;
            es.mac_a = (dp.src_mac < dp.dst_mac) ? dp.src_mac : dp.dst_mac;
            es.mac_b = (dp.src_mac < dp.dst_mac) ? dp.dst_mac : dp.src_mac;
            es.has_vlan_tag = dp.has_vlan_tag;
            es.vlan_id = dp.vlan_id;
            ethernet_flow_order_.push_back(key);
            it = ethernet_flows_.emplace(key, std::move(es)).first;
        }
        ++it->second.packet_count;
        return;
    }

    if (!dp.has_ip || !dp.has_tcp) {
        ++skipped_non_tcp_;
        return;
    }

    std::string key = session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
    bool is_syn = dp.tcp_flags == "SYN";
    bool is_syn_ack = dp.tcp_flags.rfind("SYN,ACK", 0) == 0;

    auto it = flows_.find(key);
    if (it == flows_.end()) {
        FlowState fs;
        bool src_is_client;
        if (is_syn) {
            src_is_client = true;
            fs.initiator_known = true;
        } else if (is_syn_ack) {
            src_is_client = false;
            fs.initiator_known = true;
        } else {
            src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
        }
        fs.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        fs.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        fs.server_port = src_is_client ? dp.dst_port : dp.src_port;
        flow_order_.push_back(key);
        it = flows_.emplace(key, std::move(fs)).first;
    } else if (!it->second.initiator_known && (is_syn || is_syn_ack)) {
        // A later packet on this flow carries the SYN/SYN-ACK the first packet observed for it
        // didn't -- upgrade from the first-packet port guess to the authoritative answer.
        bool src_is_client = is_syn;
        it->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        it->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        it->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
        it->second.initiator_known = true;
    }

    FlowState& fs = it->second;
    ++fs.packet_count;
    // Each protocol contributes its own already-decoded function/service name field (never more
    // than one of these is ever populated for a given packet, since a packet has exactly one
    // decoded protocol) -- see FlowReport::observed_functions' comment for the full list, and
    // policy.hpp's Conduit::functions comment for how these feed a functions-restricted conduit's
    // matching below (finish()) -- though only the first five below (modbus/dnp3/s7comm/iec104/
    // enip) can actually be restricted by a conduit's own 'functions' list today; the next five
    // (hartip/opcua/mms/mqtt/ffhse -- 'protocols' was widened to accept all six, see ROADMAP) still
    // populate fs.functions purely for FlowReport::observed_functions' own reporting/scripting use.
    // "bacnet" is deliberately NOT handled here even though 'protocols' accepts it: this decoder
    // only ever recognizes BACnet/IP over UDP (see decoder.cpp), and this function already returned
    // above for any packet with !dp.has_tcp, so a dp.protocol == "bacnet" packet can never reach
    // this point -- see policy.hpp's own Conduit::protocols comment and docs/MANUAL.md's POLICY
    // FILE FORMAT "Addressing scope" section for the full explanation.
    if (dp.protocol == "modbus") {
        fs.protocols.insert("modbus");
        if (!dp.modbus_function_name.empty()) fs.functions.insert(dp.modbus_function_name);
    } else if (dp.protocol == "dnp3") {
        fs.protocols.insert("dnp3");
        if (dp.dnp3_has_function && !dp.dnp3_function_name.empty()) fs.functions.insert(dp.dnp3_function_name);
    } else if (dp.protocol == "s7comm" || dp.protocol == "cotp") {
        // "cotp" (TPKT/COTP framing recognized, but not a decoded S7comm message -- e.g. a
        // connection-setup frame) is still legitimately part of an S7comm session on the wire, so
        // it counts toward the same "s7comm" conduit protocol, not a separate one. It never carries
        // a decoded s7comm_function_name of its own, though (dp.protocol == "cotp" means no S7comm
        // message was decoded on this packet at all).
        fs.protocols.insert("s7comm");
        if (dp.protocol == "s7comm" && dp.s7comm_has_function && !dp.s7comm_function_name.empty()) {
            fs.functions.insert(dp.s7comm_function_name);
        }
    } else if (dp.protocol == "iec104") {
        fs.protocols.insert("iec104");
        if (dp.iec104_has_asdu && !dp.iec104_asdu_type_short_name.empty()) {
            fs.functions.insert(dp.iec104_asdu_type_short_name);
        }
    } else if (dp.protocol == "enip") {
        fs.protocols.insert("enip");
        if (dp.enip_has_cip && !dp.enip_cip_service_name.empty()) fs.functions.insert(dp.enip_cip_service_name);
    } else if (dp.protocol == "hartip") {
        fs.protocols.insert("hartip");
        // hartip_message_type ("Request"/"Response"/"Publish"/"Error"/"NAK") is always set when
        // protocol == "hartip" -- see decoder.hpp -- unlike the others above, no separate "was
        // anything decoded at all" guard is needed.
        if (!dp.hartip_message_type.empty()) fs.functions.insert(dp.hartip_message_type);
    } else if (dp.protocol == "opcua") {
        fs.protocols.insert("opcua");
        if (dp.opcua_service_recognized && !dp.opcua_service_name.empty()) {
            fs.functions.insert(dp.opcua_service_name);
        }
    } else if (dp.protocol == "mms") {
        fs.protocols.insert("mms");
        if (dp.mms_service_recognized && !dp.mms_service_name.empty()) {
            fs.functions.insert(dp.mms_service_name);
        }
    } else if (dp.protocol == "mqtt") {
        fs.protocols.insert("mqtt");
        // mqtt_packet_type_name ("CONNECT"/"PUBLISH"/...) is always set when protocol == "mqtt" --
        // see decoder.hpp -- same "no separate guard needed" shape as hartip_message_type above.
        if (!dp.mqtt_packet_type_name.empty()) fs.functions.insert(dp.mqtt_packet_type_name);
    } else if (dp.protocol == "ffhse") {
        fs.protocols.insert("ffhse");
        // ffhse_message_name is always set when protocol == "ffhse" -- see decoder.hpp.
        if (!dp.ffhse_message_name.empty()) fs.functions.insert(dp.ffhse_message_name);
    }
}

PolicyReport PolicyEngine::finish() const {
    PolicyReport report;
    report.total_packets = total_packets_;
    report.skipped_non_tcp = skipped_non_tcp_;

    std::unordered_set<std::string> exercised_conduits;

    for (const auto& key : flow_order_) {
        const FlowState& fs = flows_.at(key);
        FlowReport fr;
        fr.client_ip = fs.client_ip;
        fr.server_ip = fs.server_ip;
        fr.server_port = fs.server_port;
        fr.packet_count = fs.packet_count;
        fr.protocols.assign(fs.protocols.begin(), fs.protocols.end());
        std::sort(fr.protocols.begin(), fr.protocols.end());
        fr.observed_functions.assign(fs.functions.begin(), fs.functions.end());
        std::sort(fr.observed_functions.begin(), fr.observed_functions.end());

        auto client_ip_u32 = parse_ipv4_string(fs.client_ip);
        auto server_ip_u32 = parse_ipv4_string(fs.server_ip);
        const Zone* cz = client_ip_u32 ? policy_.zone_for(*client_ip_u32) : nullptr;
        const Zone* sz = server_ip_u32 ? policy_.zone_for(*server_ip_u32) : nullptr;
        fr.client_zone = cz ? cz->name : "unclassified";
        fr.server_zone = sz ? sz->name : "unclassified";

        if (!cz || !sz) {
            fr.verdict = FlowVerdict::Unclassified;
            std::ostringstream reason;
            reason << "no declared zone contains ";
            if (!cz && !sz) reason << fr.client_ip << " or " << fr.server_ip;
            else if (!cz) reason << fr.client_ip;
            else reason << fr.server_ip;
            fr.reason = reason.str();
        } else if (fs.protocols.empty()) {
            fr.verdict = FlowVerdict::Unclassified;
            fr.reason = "no recognized OT protocol traffic was found on this flow (" +
                         std::to_string(fs.packet_count) + " unrecognized/handshake packet(s) only)";
        } else {
            const Conduit* matched = nullptr;
            bool zone_pair_has_any_conduit = false;
            for (const auto& c : policy_.conduits) {
                bool forward = zone_list_contains(c.from_zones, fr.client_zone) &&
                               zone_list_contains(c.to_zones, fr.server_zone);
                bool reverse = c.bidirectional && zone_list_contains(c.to_zones, fr.client_zone) &&
                               zone_list_contains(c.from_zones, fr.server_zone);
                if (!forward && !reverse) continue;
                zone_pair_has_any_conduit = true;

                if (!c.ports.empty() &&
                    std::find(c.ports.begin(), c.ports.end(), fr.server_port) == c.ports.end()) {
                    continue;
                }
                bool protocols_ok = std::all_of(fs.protocols.begin(), fs.protocols.end(), [&](const std::string& p) {
                    return std::find(c.protocols.begin(), c.protocols.end(), p) != c.protocols.end() ||
                           std::find(c.protocols.begin(), c.protocols.end(), "any") != c.protocols.end();
                });
                if (!protocols_ok) continue;

                matched = &c;
                break;
            }
            if (matched) {
                // A conduit's own 'functions' allow-list (see policy.hpp's Conduit::functions
                // comment) is a further, strict-all restriction on top of the protocol/port/
                // direction match already found above: every distinct function/service name
                // observed on this WHOLE flow must be in the conduit's allow-list, not just some of
                // them -- one disallowed function anywhere on the flow makes the whole flow a
                // Violation, matching this engine's existing flow-level (not per-packet) verdict
                // granularity. An empty allow-list (the common case) means no restriction at all,
                // exactly the behavior before this feature existed.
                std::vector<std::string> disallowed;
                if (!matched->functions.empty()) {
                    for (const auto& fn : fr.observed_functions) {
                        bool ok = std::any_of(matched->functions.begin(), matched->functions.end(),
                                               [&](const std::string& allowed) { return equal_ci(fn, allowed); });
                        if (!ok) disallowed.push_back(fn);
                    }
                }
                if (!disallowed.empty()) {
                    fr.verdict = FlowVerdict::Violation;
                    std::ostringstream reason;
                    reason << (disallowed.size() > 1 ? "functions " : "function ");
                    for (size_t i = 0; i < disallowed.size(); ++i) {
                        if (i) reason << ", ";
                        reason << "'" << disallowed[i] << "'";
                    }
                    reason << " observed; conduit '" << matched->name << "' permits only: "
                           << join_comma(matched->functions);
                    fr.reason = reason.str();
                } else {
                    fr.verdict = FlowVerdict::Allowed;
                    fr.matched_conduit = matched->name;
                    exercised_conduits.insert(matched->name);
                }
            } else {
                fr.verdict = FlowVerdict::Violation;
                std::ostringstream reason;
                if (!zone_pair_has_any_conduit) {
                    reason << "no conduit permits any traffic from zone '" << fr.client_zone << "' to zone '"
                           << fr.server_zone << "'";
                } else {
                    reason << "a conduit exists between zone '" << fr.client_zone << "' and zone '"
                           << fr.server_zone << "', but none permits " << protocol_list_text(fr.protocols)
                           << " traffic on port " << fr.server_port;
                }
                fr.reason = reason.str();
            }
        }
        report.flows.push_back(std::move(fr));
    }

    for (const auto& key : ethernet_flow_order_) {
        const EthernetFlowState& es = ethernet_flows_.at(key);
        EthernetFlowReport er;
        er.protocol = es.protocol;
        er.mac_a = es.mac_a;
        er.mac_b = es.mac_b;
        er.has_vlan_tag = es.has_vlan_tag;
        er.vlan_id = es.vlan_id;
        er.packet_count = es.packet_count;

        const Zone* vz = es.has_vlan_tag ? policy_.zone_for_vlan(es.vlan_id) : nullptr;
        er.vlan_zone = vz ? vz->name : "unclassified";

        if (!vz) {
            er.verdict = FlowVerdict::Unclassified;
            er.reason = es.has_vlan_tag
                            ? ("no declared VLAN zone contains VLAN " + std::to_string(es.vlan_id))
                            : "frame carries no 802.1Q VLAN tag at all";
        } else {
            const Conduit* matched = nullptr;
            for (const auto& c : policy_.conduits) {
                if (!c.is_vlan_conduit) continue;
                if (!zone_list_contains(c.from_zones, er.vlan_zone)) continue;
                bool protocols_ok = std::find(c.protocols.begin(), c.protocols.end(), er.protocol) != c.protocols.end() ||
                                     std::find(c.protocols.begin(), c.protocols.end(), "any") != c.protocols.end();
                if (!protocols_ok) continue;
                matched = &c;
                break;
            }
            if (matched) {
                er.verdict = FlowVerdict::Allowed;
                er.matched_conduit = matched->name;
                exercised_conduits.insert(matched->name);
            } else {
                er.verdict = FlowVerdict::Violation;
                er.reason = "no conduit permits " + er.protocol + " traffic on VLAN zone '" + er.vlan_zone + "'";
            }
        }
        report.ethernet_flows.push_back(std::move(er));
    }

    for (const auto& c : policy_.conduits) {
        if (!exercised_conduits.count(c.name)) report.unexercised_conduits.push_back(c.name);
    }

    return report;
}

size_t PolicyReport::allowed_count() const {
    return static_cast<size_t>(
               std::count_if(flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Allowed; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
}
size_t PolicyReport::violation_count() const {
    return static_cast<size_t>(std::count_if(flows.begin(), flows.end(),
                                              [](const FlowReport& f) { return f.verdict == FlowVerdict::Violation; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
}
size_t PolicyReport::unclassified_count() const {
    return static_cast<size_t>(std::count_if(
               flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Unclassified; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
}

namespace {

void write_flow_group_text(std::ostream& out, const std::vector<const FlowReport*>& group, const char* label) {
    out << label << " (" << group.size() << "):\n";
    if (group.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < group.size(); ++i) {
        const FlowReport& f = *group[i];
        out << "  [" << (i + 1) << "] " << f.client_ip << " -> " << f.server_ip << ":" << f.server_port;
        if (!f.protocols.empty()) out << "  (" << protocol_list_text(f.protocols) << ", " << f.packet_count << " packet(s))";
        else out << "  (" << f.packet_count << " packet(s), no recognized protocol)";
        out << "\n      zones: " << f.client_zone << " -> " << f.server_zone;
        if (f.verdict == FlowVerdict::Allowed) {
            out << ", matched conduit \"" << f.matched_conduit << "\"";
        }
        out << "\n";
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// Same idea as write_flow_group_text, for the L2/VLAN-zone side of the report -- rendered under a
// "MAC_A <-> MAC_B" heading rather than "client -> server", since these protocols have no
// client/server distinction (see EthernetFlowReport's own comment).
void write_ethernet_flow_group_text(std::ostream& out, const std::vector<const EthernetFlowReport*>& group,
                                     const char* label) {
    out << label << " (" << group.size() << "):\n";
    if (group.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < group.size(); ++i) {
        const EthernetFlowReport& f = *group[i];
        out << "  [" << (i + 1) << "] " << f.mac_a << " <-> " << f.mac_b << "  (" << f.protocol << ", "
            << f.packet_count << " packet(s))";
        out << "\n      vlan: " << (f.has_vlan_tag ? std::to_string(f.vlan_id) : std::string("(untagged)"))
            << ", zone: " << f.vlan_zone;
        if (f.verdict == FlowVerdict::Allowed) {
            out << ", matched conduit \"" << f.matched_conduit << "\"";
        }
        out << "\n";
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

}  // namespace

void write_policy_report_text(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path) {
    out << "Zone/conduit policy validation\n";
    out << "  capture: " << capture_path << "\n";
    out << "  policy:  " << policy_path << " (" << policy.zones.size() << " zone(s), " << policy.conduits.size()
        << " conduit(s))\n\n";

    out << "Result: " << (report.compliant() ? "COMPLIANT" : "NON-COMPLIANT");
    if (!report.compliant()) {
        out << " (" << report.violation_count() << " violation(s), " << report.unclassified_count()
            << " unclassified flow(s))";
    }
    out << "\n\n";

    size_t flow_allowed = static_cast<size_t>(
        std::count_if(report.flows.begin(), report.flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
    size_t flow_violation = static_cast<size_t>(std::count_if(
        report.flows.begin(), report.flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
    size_t flow_unclassified = static_cast<size_t>(std::count_if(
        report.flows.begin(), report.flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
    out << "Flows evaluated: " << report.flows.size() << " (" << flow_allowed << " allowed, " << flow_violation
        << " violation(s), " << flow_unclassified << " unclassified)\n";
    out << "  " << report.total_packets << " total packet(s) in capture, " << report.skipped_non_tcp
        << " skipped (non-TCP/non-IP)\n\n";

    std::vector<const FlowReport*> violations, unclassified, allowed;
    for (const auto& f : report.flows) {
        if (f.verdict == FlowVerdict::Violation) violations.push_back(&f);
        else if (f.verdict == FlowVerdict::Unclassified) unclassified.push_back(&f);
        else allowed.push_back(&f);
    }

    write_flow_group_text(out, violations, "VIOLATIONS");
    out << "\n";
    write_flow_group_text(out, unclassified, "UNCLASSIFIED TRAFFIC");
    out << "\n";
    write_flow_group_text(out, allowed, "ALLOWED");
    out << "\n";

    // Only printed at all once a policy declares at least one VLAN zone (see
    // PolicyEngine::observe's own comment) -- a report from a policy with only CIDR zones renders
    // byte-for-byte identically to before this feature existed.
    if (!report.ethernet_flows.empty()) {
        size_t eth_allowed = static_cast<size_t>(std::count_if(
            report.ethernet_flows.begin(), report.ethernet_flows.end(),
            [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
        size_t eth_violation = static_cast<size_t>(std::count_if(
            report.ethernet_flows.begin(), report.ethernet_flows.end(),
            [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
        size_t eth_unclassified = static_cast<size_t>(std::count_if(
            report.ethernet_flows.begin(), report.ethernet_flows.end(),
            [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
        out << "Ethernet flows evaluated: " << report.ethernet_flows.size() << " (" << eth_allowed << " allowed, "
            << eth_violation << " violation(s), " << eth_unclassified << " unclassified)\n";
        out << "  PROFINET RT/GOOSE/Sampled Values/EtherCAT traffic, classified by VLAN zone -- see "
               "docs/MANUAL.md's POLICY FILE FORMAT section\n\n";

        std::vector<const EthernetFlowReport*> eth_violations, eth_unclassified_list, eth_allowed_list;
        for (const auto& f : report.ethernet_flows) {
            if (f.verdict == FlowVerdict::Violation) eth_violations.push_back(&f);
            else if (f.verdict == FlowVerdict::Unclassified) eth_unclassified_list.push_back(&f);
            else eth_allowed_list.push_back(&f);
        }

        write_ethernet_flow_group_text(out, eth_violations, "ETHERNET VIOLATIONS");
        out << "\n";
        write_ethernet_flow_group_text(out, eth_unclassified_list, "ETHERNET UNCLASSIFIED TRAFFIC");
        out << "\n";
        write_ethernet_flow_group_text(out, eth_allowed_list, "ETHERNET ALLOWED");
        out << "\n";
    }

    out << "Conduits never exercised by this capture (" << report.unexercised_conduits.size() << "):\n";
    if (report.unexercised_conduits.empty()) {
        out << "  (none)\n";
    } else {
        for (const auto& name : report.unexercised_conduits) {
            out << "  - " << name << "\n";
        }
    }
}

void write_policy_report_json(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path) {
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(capture_path) << "\",\n";
    out << "  \"policy\": \"" << json_escape(policy_path) << "\",\n";
    out << "  \"zone_count\": " << policy.zones.size() << ",\n";
    out << "  \"conduit_count\": " << policy.conduits.size() << ",\n";

    // Additive per-conduit summary, primarily so a scripted audit pipeline can see each conduit's
    // 'functions' allow-list (empty means unrestricted) without re-parsing the policy YAML itself.
    // Placed here, before "compliant", so it never lands between any of this schema's pre-existing
    // fields -- see docs/MANUAL.md's POLICY FILE FORMAT "JSON report schema" for the full schema.
    out << "  \"conduits\": [\n";
    for (size_t i = 0; i < policy.conduits.size(); ++i) {
        const Conduit& c = policy.conduits[i];
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(c.name) << "\",\n";
        out << "      \"from\": [";
        for (size_t j = 0; j < c.from_zones.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(c.from_zones[j]) << "\"";
        }
        out << "],\n";
        out << "      \"to\": [";
        for (size_t j = 0; j < c.to_zones.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(c.to_zones[j]) << "\"";
        }
        out << "],\n";
        out << "      \"bidirectional\": " << (c.bidirectional ? "true" : "false") << ",\n";
        out << "      \"is_vlan_conduit\": " << (c.is_vlan_conduit ? "true" : "false") << ",\n";
        out << "      \"protocols\": [";
        for (size_t j = 0; j < c.protocols.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(c.protocols[j]) << "\"";
        }
        out << "],\n";
        out << "      \"functions\": [";
        for (size_t j = 0; j < c.functions.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(c.functions[j]) << "\"";
        }
        out << "]\n";
        out << "    }" << (i + 1 < policy.conduits.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"compliant\": " << (report.compliant() ? "true" : "false") << ",\n";
    out << "  \"total_packets\": " << report.total_packets << ",\n";
    out << "  \"skipped_non_tcp\": " << report.skipped_non_tcp << ",\n";
    out << "  \"allowed_count\": " << report.allowed_count() << ",\n";
    out << "  \"violation_count\": " << report.violation_count() << ",\n";
    out << "  \"unclassified_count\": " << report.unclassified_count() << ",\n";

    out << "  \"flows\": [\n";
    for (size_t i = 0; i < report.flows.size(); ++i) {
        const FlowReport& f = report.flows[i];
        out << "    {\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"client_zone\": \"" << json_escape(f.client_zone) << "\",\n";
        out << "      \"server_zone\": \"" << json_escape(f.server_zone) << "\",\n";
        out << "      \"protocols\": [";
        for (size_t j = 0; j < f.protocols.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(f.protocols[j]) << "\"";
        }
        out << "],\n";
        out << "      \"observed_functions\": [";
        for (size_t j = 0; j < f.observed_functions.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(f.observed_functions[j]) << "\"";
        }
        out << "],\n";
        out << "      \"packet_count\": " << f.packet_count << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << "\n";
        out << "    }" << (i + 1 < report.flows.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // Empty exactly when the policy declares no VLAN zone at all (see PolicyEngine::observe's own
    // comment) -- a report from a CIDR-zone-only policy renders this as an empty array, one more
    // field than existed before this feature, but otherwise unchanged from before it.
    out << "  \"ethernet_flows\": [\n";
    for (size_t i = 0; i < report.ethernet_flows.size(); ++i) {
        const EthernetFlowReport& f = report.ethernet_flows[i];
        out << "    {\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"mac_a\": \"" << json_escape(f.mac_a) << "\",\n";
        out << "      \"mac_b\": \"" << json_escape(f.mac_b) << "\",\n";
        out << "      \"has_vlan_tag\": " << (f.has_vlan_tag ? "true" : "false") << ",\n";
        out << "      \"vlan_id\": " << (f.has_vlan_tag ? std::to_string(f.vlan_id) : std::string("null")) << ",\n";
        out << "      \"vlan_zone\": \"" << json_escape(f.vlan_zone) << "\",\n";
        out << "      \"packet_count\": " << f.packet_count << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << "\n";
        out << "    }" << (i + 1 < report.ethernet_flows.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"unexercised_conduits\": [";
    for (size_t i = 0; i < report.unexercised_conduits.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << json_escape(report.unexercised_conduits[i]) << "\"";
    }
    out << "]\n";
    out << "}\n";
}

}  // namespace conduitscope
