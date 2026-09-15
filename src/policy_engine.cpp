// SPDX-License-Identifier: MIT
#include "conduitscope/policy_engine.hpp"

#include <algorithm>
#include <cstdio>
#include <ostream>
#include <sstream>

#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
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

bool is_known_service_port(uint16_t port) {
    return port == MODBUS_TCP_PORT || port == DNP3_TCP_PORT || port == COTP_TCP_PORT ||
           port == IEC104_TCP_PORT;
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
    if (dp.protocol == "modbus") {
        fs.protocols.insert("modbus");
    } else if (dp.protocol == "dnp3") {
        fs.protocols.insert("dnp3");
    } else if (dp.protocol == "s7comm" || dp.protocol == "cotp") {
        // "cotp" (TPKT/COTP framing recognized, but not a decoded S7comm message -- e.g. a
        // connection-setup frame) is still legitimately part of an S7comm session on the wire, so
        // it counts toward the same "s7comm" conduit protocol, not a separate one.
        fs.protocols.insert("s7comm");
    } else if (dp.protocol == "iec104") {
        fs.protocols.insert("iec104");
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
            fr.reason = "no Modbus/DNP3/S7comm traffic was recognized on this flow (" +
                         std::to_string(fs.packet_count) + " unrecognized/handshake packet(s) only)";
        } else {
            const Conduit* matched = nullptr;
            bool zone_pair_has_any_conduit = false;
            for (const auto& c : policy_.conduits) {
                bool forward = (c.from_zone == fr.client_zone && c.to_zone == fr.server_zone);
                bool reverse = c.bidirectional && (c.to_zone == fr.client_zone && c.from_zone == fr.server_zone);
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
                fr.verdict = FlowVerdict::Allowed;
                fr.matched_conduit = matched->name;
                exercised_conduits.insert(matched->name);
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

    for (const auto& c : policy_.conduits) {
        if (!exercised_conduits.count(c.name)) report.unexercised_conduits.push_back(c.name);
    }

    return report;
}

size_t PolicyReport::allowed_count() const {
    return static_cast<size_t>(
        std::count_if(flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
}
size_t PolicyReport::violation_count() const {
    return static_cast<size_t>(std::count_if(flows.begin(), flows.end(),
                                              [](const FlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
}
size_t PolicyReport::unclassified_count() const {
    return static_cast<size_t>(std::count_if(
        flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
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

    out << "Flows evaluated: " << report.flows.size() << " (" << report.allowed_count() << " allowed, "
        << report.violation_count() << " violation(s), " << report.unclassified_count() << " unclassified)\n";
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
        out << "      \"packet_count\": " << f.packet_count << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << "\n";
        out << "    }" << (i + 1 < report.flows.size() ? "," : "") << "\n";
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
