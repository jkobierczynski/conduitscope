// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/policy_engine.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ostream>
#include <sstream>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/notable_it_protocols.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/s7comm.hpp"

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

// UDP counterpart to is_known_service_port/src_is_client_by_port above, for the two UDP-based IP
// protocols PolicyEngine::observe's own UDP-flow branch can evaluate (BACnet/IP, CIP I/O) -- used
// only as the direction fallback when no authoritative content-based answer is available (BACnet
// with no decoded APDU yet, or CIP I/O, which has no content-based answer at all). Deliberately a
// separate small function rather than widening is_known_service_port itself: that function's own
// five ports are all TCP, and mixing a UDP port into the same "known service port" set an ordinary
// TCP flow's own direction guess consults would be a correctness bug waiting to happen (a TCP flow
// coincidentally using port 47808 or 2222 would suddenly be treated as a known OT service port).
bool is_known_udp_service_port(uint16_t port) { return port == BACNET_UDP_PORT || port == ENIP_IO_UDP_PORT; }

bool udp_src_is_client_by_port(uint16_t src_port, uint16_t dst_port) {
    bool src_known = is_known_udp_service_port(src_port);
    bool dst_known = is_known_udp_service_port(dst_port);
    if (dst_known && !src_known) return true;
    if (src_known && !dst_known) return false;
    return src_port > dst_port;
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
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) -> char { return static_cast<char>(std::tolower(c)); });
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

// An IPv6-formatted address (format_ipv6's colon-separated form -- this codebase's zone/CIDR
// matching is IPv4-only throughout, see policy.hpp's parse_cidr) gets its own, honest reason instead
// of the generic "no declared zone contains" text, which would otherwise be indistinguishable from
// an ordinary unclassified IPv4 address -- see docs/USER_GUIDE.md's LIMITATIONS section. Shared by
// the TCP-flow and UDP-flow loops in finish() below, both of which hit exactly this same "at least
// one endpoint matched no declared zone" case and want identical reason text.
std::string describe_unmatched_endpoint(const std::string& ip) {
    if (ip.find(':') != std::string::npos) {
        return ip + " is an IPv6 address; policy zoning does not support IPv6 yet";
    }
    return "no declared zone contains " + ip;
}

// Builds the FlowReport::reason/UdpFlowReport::reason text for the "at least one endpoint didn't
// match any declared zone" case -- `cz`/`sz` are whether the client/server endpoint's zone lookup
// found anything. See describe_unmatched_endpoint's own comment for the IPv6-specific branch.
std::string zone_unclassified_reason(const std::string& client_ip, const std::string& server_ip, bool cz, bool sz) {
    if (!cz && !sz) {
        if (client_ip.find(':') != std::string::npos || server_ip.find(':') != std::string::npos) {
            return describe_unmatched_endpoint(client_ip) + "; " + describe_unmatched_endpoint(server_ip);
        }
        return "no declared zone contains " + client_ip + " or " + server_ip;
    }
    if (!cz) return describe_unmatched_endpoint(client_ip);
    return describe_unmatched_endpoint(server_ip);
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

// Identical dedup rule to BaselineEngine::mark_truncated (baseline.cpp).
void PolicyEngine::mark_truncated(const std::string& reason) {
    truncated_ = true;
    for (const std::string& existing : truncation_reasons_) {
        if (existing == reason) return;
    }
    truncation_reasons_.push_back(reason);
}

bool PolicyEngine::admit_tracked_key(bool already_present, size_t current_map_size, size_t ceiling,
                                      const char* map_name, const char* flag_name) {
    if (already_present) return true;
    if (current_map_size < ceiling) return true;
    mark_truncated(std::string("tracked-key limit (") + std::to_string(ceiling) + ") reached on " + map_name +
                    " -- further new entries are not tracked (" + flag_name + ")");
    return false;
}

void PolicyEngine::record_notable_protocol(const std::string& key, const std::string& protocol,
                                            const std::string& tier, bool has_ip, bool direction_known,
                                            const std::string& client_ip, const std::string& server_ip,
                                            const std::string& mac_a, const std::string& mac_b, bool has_port,
                                            bool is_tcp, uint16_t port) {
    auto it = notable_protocols_.find(key);
    if (!admit_tracked_key(it != notable_protocols_.end(), notable_protocols_.size(),
                            limits_.max_notable_protocols, "notable_protocols_",
                            "--max-policy-notable-protocols")) {
        return;
    }
    if (it == notable_protocols_.end()) {
        NotableProtocolState st;
        st.protocol = protocol;
        st.tier = tier;
        st.has_ip = has_ip;
        st.direction_known = direction_known;
        st.client_ip = client_ip;
        st.server_ip = server_ip;
        st.mac_a = mac_a;
        st.mac_b = mac_b;
        st.has_port = has_port;
        st.is_tcp = is_tcp;
        st.port = port;
        notable_protocol_order_.push_back(key);
        it = notable_protocols_.emplace(key, std::move(st)).first;
    } else if (direction_known && !it->second.direction_known) {
        // A later TCP packet on this same flow captured the SYN/SYN-ACK an earlier one didn't --
        // upgrade from the port-heuristic guess to the authoritative answer, mirroring FlowState's
        // own upgrade rule (PolicyEngine::observe) at this coarser, session-state-free granularity.
        it->second.direction_known = true;
        it->second.client_ip = client_ip;
        it->second.server_ip = server_ip;
    }
    ++it->second.packet_count;
}

void PolicyEngine::observe(const DecodedPacket& dp) {
    ++total_packets_;

    // "IT protocols an OT auditor flags" (ROADMAP item 18) -- see observe()'s own doc comment
    // (policy_engine.hpp) for why this is checked first, unconditionally, before every branch below.
    auto notable_tier = notable_it_protocol_tier(dp.protocol);

    if (notable_tier && !dp.has_ip) {
        // eapol/pppoe/mpls -- the three EtherType-keyed protocols in this family -- are the only
        // ones with has_ip==false (every other notable protocol rides IP, even the IP-protocol-
        // number-keyed Tier 5 tunnels below); keyed by canonical MAC pair, the same no-direction
        // convention EthernetFlowReport::mac_a/mac_b already uses for PROFINET/GOOSE/SV/EtherCAT.
        if (dp.has_ethernet) {
            std::string mac_a = (dp.src_mac < dp.dst_mac) ? dp.src_mac : dp.dst_mac;
            std::string mac_b = (dp.src_mac < dp.dst_mac) ? dp.dst_mac : dp.src_mac;
            std::string key = "eth:" + ethernet_flow_key(dp.protocol, dp.src_mac, dp.dst_mac);
            record_notable_protocol(key, dp.protocol, *notable_tier, /*has_ip=*/false,
                                     /*direction_known=*/false, "", "", mac_a, mac_b, /*has_port=*/false,
                                     /*is_tcp=*/false, 0);
        }
    }

    if (is_vlan_zone_eligible_protocol(dp.protocol) && any_vlan_zone_) {
        // See this function's own doc comment (policy_engine.hpp) for why this branch only exists
        // once the policy has opted in by declaring at least one VLAN zone -- backward
        // compatibility for every policy file written before this feature existed.
        std::string key = ethernet_flow_key(dp.protocol, dp.src_mac, dp.dst_mac);
        auto it = ethernet_flows_.find(key);
        if (!admit_tracked_key(it != ethernet_flows_.end(), ethernet_flows_.size(), limits_.max_ethernet_flows,
                                "ethernet_flows_", "--max-policy-ethernet-flows")) {
            ++skipped_non_tcp_;
            return;
        }
        if (it == ethernet_flows_.end()) {
            EthernetFlowState es;
            es.protocol = dp.protocol;
            es.mac_a = (dp.src_mac < dp.dst_mac) ? dp.src_mac : dp.dst_mac;
            es.mac_b = (dp.src_mac < dp.dst_mac) ? dp.dst_mac : dp.src_mac;
            es.src_mac = dp.src_mac;  // fixed here, at first-insert -- never updated by a later packet
            es.has_vlan_tag = dp.has_vlan_tag;
            es.vlan_id = dp.vlan_id;
            ethernet_flow_order_.push_back(key);
            it = ethernet_flows_.emplace(key, std::move(es)).first;
        }
        ++it->second.packet_count;
        return;
    }

    if (dp.has_udp && any_udp_ip_eligible_conduit_ && (dp.protocol == "bacnet" || dp.protocol == "enip")) {
        // See this function's own doc comment (policy_engine.hpp) for why this branch only exists
        // once the policy has opted in by naming "bacnet"/"enip"/"any" on a CIDR- or hostname-zone
        // conduit -- backward compatibility for every policy file written before this feature
        // existed. Keyed by the same canonical, order-independent session_key() a TCP flow uses (see
        // UdpFlowState's own comment for why), prefixed with the protocol so a BACnet flow and a CIP
        // I/O flow between coincidentally-overlapping endpoints never collide.
        std::string key = dp.protocol + ":" + session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);

        // Direction: BACnet decides authoritatively from its own decoded APDU type when one is
        // present (Confirmed-Request/Unconfirmed-Request -> source is client; every other decoded
        // PDU type -- Simple-ACK/Complex-ACK/Segment-ACK/Error/Reject/Abort -- -> destination is
        // client), exactly mirroring AssetInventoryEngine's own BACnet direction logic
        // (asset_inventory.cpp) since both tools face the identical "no session, no handshake"
        // problem for this protocol. CIP I/O has no request/response concept at all (cyclic
        // producer/consumer traffic) -- always the UDP port-heuristic fallback.
        bool direction_known = false;
        bool src_is_client = false;
        if (dp.protocol == "bacnet" && dp.result) {
            const BacnetFrame& bf = dp.result->as<BacnetFrame>();
            if (bf.has_npdu && bf.npdu.has_apdu && !bf.npdu.apdu.pdu_type_name.empty()) {
                direction_known = true;
                src_is_client = bf.npdu.apdu.pdu_type_name == "Confirmed-Request" ||
                                 bf.npdu.apdu.pdu_type_name == "Unconfirmed-Request";
            }
        }
        if (!direction_known) {
            src_is_client = udp_src_is_client_by_port(dp.src_port, dp.dst_port);
        }

        auto it = udp_flows_.find(key);
        if (!admit_tracked_key(it != udp_flows_.end(), udp_flows_.size(), limits_.max_udp_flows, "udp_flows_",
                                "--max-policy-udp-flows")) {
            ++skipped_non_tcp_;
            return;
        }
        if (it == udp_flows_.end()) {
            UdpFlowState st;
            st.protocol = dp.protocol;
            st.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            st.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            st.server_port = src_is_client ? dp.dst_port : dp.src_port;
            st.direction_source = direction_known ? DirectionSource::Content : DirectionSource::PortHeuristic;
            if (dp.has_ethernet) {
                st.has_mac = true;
                st.client_mac = src_is_client ? dp.src_mac : dp.dst_mac;
                st.server_mac = src_is_client ? dp.dst_mac : dp.src_mac;
            }
            udp_flow_order_.push_back(key);
            it = udp_flows_.emplace(key, std::move(st)).first;
        } else if (direction_known && it->second.direction_source != DirectionSource::Content) {
            // A later packet on this flow carried an authoritative BACnet APDU an earlier one
            // didn't -- upgrade from the port-heuristic guess, mirroring FlowState's own SYN/SYN-ACK
            // upgrade rule above at this coarser, no-handshake granularity.
            it->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            it->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            it->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
            if (dp.has_ethernet) {
                it->second.has_mac = true;
                it->second.client_mac = src_is_client ? dp.src_mac : dp.dst_mac;
                it->second.server_mac = src_is_client ? dp.dst_mac : dp.src_mac;
            }
            it->second.direction_source = DirectionSource::Content;
        }

        UdpFlowState& st = it->second;
        ++st.packet_count;

        if (dp.protocol == "bacnet" && dp.result) {
            const BacnetFrame& bf = dp.result->as<BacnetFrame>();
            if (bf.has_npdu && bf.npdu.has_apdu && !bf.npdu.apdu.service_choice_name.empty()) {
                st.functions.insert(bf.npdu.apdu.service_choice_name);
            }
        }
        // CIP I/O ("enip" with dp.has_udp) has no function/service-name concept at all -- st.functions
        // stays empty for it, same as any protocol with nothing to report here (see
        // UdpFlowReport::observed_functions' own comment for what this means for a conduit's
        // 'functions' restriction).

        return;
    }

    if (!dp.has_ip || !dp.has_tcp) {
        if (notable_tier && dp.has_ip) {
            // UDP (dp.has_udp), or an IP-protocol-number-keyed Tier 5 tunnel (dp.has_udp is also
            // false there -- gre/esp/ah/ip-in-ip/6in4/l2tp's own direct-IP form, see decoder.cpp's
            // own ip.protocol dispatch, all of which leave src_port/dst_port at 0). Neither shape has
            // a session/handshake to decide direction from, so this reuses src_is_client_by_port --
            // this file's own existing TCP-flow port-heuristic fallback -- which, since none of this
            // feature's 43 ports are ever in is_known_service_port's OT-only list, always reduces to
            // "lower port number is the server" for every one of them; for the port-protocol-number
            // shape (src_port == dst_port == 0) that's a meaningless tie-break, so has_port/direction
            // are both left false there and only the canonical address pair is recorded.
            bool has_port = dp.has_udp;
            std::string client_ip, server_ip;
            uint16_t server_port = 0;
            if (has_port) {
                bool src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
                client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
                server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
                server_port = src_is_client ? dp.dst_port : dp.src_port;
            } else {
                client_ip = (dp.src_ip < dp.dst_ip) ? dp.src_ip : dp.dst_ip;
                server_ip = (dp.src_ip < dp.dst_ip) ? dp.dst_ip : dp.src_ip;
            }
            std::string notable_key = "ip:" + *notable_tier + ":" + dp.protocol + ":" +
                                       session_key(dp.src_ip, has_port ? dp.src_port : 0, dp.dst_ip,
                                                    has_port ? dp.dst_port : 0);
            record_notable_protocol(notable_key, dp.protocol, *notable_tier, /*has_ip=*/true,
                                     /*direction_known=*/false, client_ip, server_ip, "", "", has_port,
                                     /*is_tcp=*/false, server_port);
        }
        ++skipped_non_tcp_;
        return;
    }

    std::string key = session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
    bool is_syn = dp.tcp_flags == "SYN";
    bool is_syn_ack = dp.tcp_flags.rfind("SYN,ACK", 0) == 0;

    auto it = flows_.find(key);
    if (!admit_tracked_key(it != flows_.end(), flows_.size(), limits_.max_tcp_flows, "flows_",
                            "--max-policy-tcp-flows")) {
        ++skipped_non_tcp_;
        return;
    }
    if (it == flows_.end()) {
        FlowState fs;
        bool src_is_client;
        if (is_syn) {
            src_is_client = true;
            fs.initiator_known = true;
            fs.direction_source = DirectionSource::Handshake;
        } else if (is_syn_ack) {
            src_is_client = false;
            fs.initiator_known = true;
            fs.direction_source = DirectionSource::Handshake;
        } else {
            src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
            fs.direction_source = DirectionSource::PortHeuristic;
        }
        fs.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        fs.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        fs.server_port = src_is_client ? dp.dst_port : dp.src_port;
        // See FlowState::has_mac's own comment -- only ever set from an Ethernet-linktype packet;
        // left at its default (false, empty) for a raw-IP/cooked-capture flow, exactly like
        // DecodedPacket::src_mac/dst_mac themselves stay meaningless when !has_ethernet.
        if (dp.has_ethernet) {
            fs.has_mac = true;
            fs.client_mac = src_is_client ? dp.src_mac : dp.dst_mac;
            fs.server_mac = src_is_client ? dp.dst_mac : dp.src_mac;
        }
        flow_order_.push_back(key);
        it = flows_.emplace(key, std::move(fs)).first;
    } else if (!it->second.initiator_known && (is_syn || is_syn_ack)) {
        // A later packet on this flow carries the SYN/SYN-ACK the first packet observed for it
        // didn't -- upgrade from the first-packet port guess to the authoritative answer.
        bool src_is_client = is_syn;
        it->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        it->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        it->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
        if (dp.has_ethernet) {
            it->second.has_mac = true;
            it->second.client_mac = src_is_client ? dp.src_mac : dp.dst_mac;
            it->second.server_mac = src_is_client ? dp.dst_mac : dp.src_mac;
        }
        it->second.initiator_known = true;
        it->second.direction_source = DirectionSource::Handshake;
    }

    FlowState& fs = it->second;
    ++fs.packet_count;

    if (notable_tier) {
        // A TCP-based notable protocol (rdp/vnc/smb/ssh/http/https/ldap/ldaps/tacacs-plus/openvpn/
        // stt) reuses this flow's OWN client_ip/server_ip/direction_source -- already decided above,
        // by the same SYN/SYN-ACK-first priority order every other TCP flow gets -- rather than a
        // separate, weaker per-packet guess, so this finding's direction is exactly as authoritative
        // as its own FlowReport's. Keyed by (protocol, session key), NOT the notable protocol alone,
        // so distinct sessions between the same host pair (e.g. two separate SSH connections) still
        // fold into one finding per session the same way flows_ itself does, while a genuinely
        // different notable protocol on an unrelated port between the same two hosts gets its own
        // entry.
        std::string notable_key = "tcp:" + *notable_tier + ":" + dp.protocol + ":" + key;
        record_notable_protocol(notable_key, dp.protocol, *notable_tier, /*has_ip=*/true,
                                 fs.direction_source == DirectionSource::Handshake, fs.client_ip, fs.server_ip, "",
                                 "", /*has_port=*/true, /*is_tcp=*/true, fs.server_port);
    }

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
        if (dp.result) {
            const std::string& name = dp.result->as<ModbusFrame>().function_name;
            if (!name.empty()) fs.functions.insert(name);
        }
    } else if (dp.protocol == "dnp3") {
        fs.protocols.insert("dnp3");
        if (dp.result) {
            const Dnp3Result& dr = dp.result->as<Dnp3Result>();
            if (dr.dnp3_has_function && !dr.dnp3_function_name.empty()) fs.functions.insert(dr.dnp3_function_name);
        }
    } else if (dp.protocol == "s7comm" || dp.protocol == "cotp") {
        // "cotp" (TPKT/COTP framing recognized, but not a decoded S7comm message -- e.g. a
        // connection-setup frame) is still legitimately part of an S7comm session on the wire, so
        // it counts toward the same "s7comm" conduit protocol, not a separate one. It never carries
        // a decoded s7comm_function_name of its own, though (dp.protocol == "cotp" means no S7comm
        // message was decoded on this packet at all).
        fs.protocols.insert("s7comm");
        // Zero-flat-field migration (extra-reader batch): dp.s7comm_has_function/
        // dp.s7comm_function_name are gone -- read from the S7CommResult on dp.result instead, same
        // field names, just no longer flattened onto DecodedPacket itself. dp.result is only ever
        // populated for dp.protocol == "s7comm" (never "cotp"), so the dp.protocol == "s7comm" check
        // above continues to double as the dp.result guard here.
        if (dp.protocol == "s7comm" && dp.result) {
            const S7CommResult& sr = dp.result->as<S7CommResult>();
            if (sr.has_function && !sr.function_name.empty()) fs.functions.insert(sr.function_name);
        }
    } else if (dp.protocol == "iec104") {
        fs.protocols.insert("iec104");
        // Zero-flat-field migration (extra-reader batch): dp.iec104_has_asdu/
        // dp.iec104_asdu_type_short_name are gone -- read from the Iec104Result on dp.result
        // instead, same field names, just no longer flattened onto DecodedPacket itself.
        if (dp.result) {
            const Iec104Result& ir = dp.result->as<Iec104Result>();
            if (ir.iec104_has_asdu && !ir.iec104_asdu_type_short_name.empty()) {
                fs.functions.insert(ir.iec104_asdu_type_short_name);
            }
        }
    } else if (dp.protocol == "enip") {
        fs.protocols.insert("enip");
        // dp.result holds an EnipResult (TCP explicit messaging) or a CipIoFrame (UDP CIP I/O)
        // depending on dp.has_tcp/dp.has_udp -- see write_enip_json_fields's own comment in
        // output.cpp for why "enip" is the one shared-id() protocol with two different result
        // types. CIP I/O has no function-name concept of its own, so only the TCP side matters here.
        if (dp.has_tcp && dp.result) {
            const EnipFrame& ef = dp.result->as<EnipResult>().first;
            if (ef.has_cip && !ef.cip.service_name.empty()) fs.functions.insert(ef.cip.service_name);
        }
    } else if (dp.protocol == "hartip") {
        fs.protocols.insert("hartip");
        // Zero-flat-field migration (extra-reader batch): dp.hartip_message_type is gone -- read
        // from HartIpResult::first on dp.result instead. HartIpFrame::message_type_name
        // ("Request"/"Response"/"Publish"/"Error"/"NAK") is always set once a "hartip" packet
        // decodes at all -- see hartip.hpp -- unlike the others above, no separate "was anything
        // decoded at all" guard is needed beyond dp.result itself.
        if (dp.result) {
            const std::string& mt = dp.result->as<HartIpResult>().first.message_type_name;
            if (!mt.empty()) fs.functions.insert(mt);
        }
    } else if (dp.protocol == "opcua") {
        fs.protocols.insert("opcua");
        // Zero-flat-field migration (extra-reader batch): dp.opcua_service_recognized/
        // dp.opcua_service_name are gone -- read from OpcUaResult::first on dp.result instead, same
        // field names, just no longer flattened onto DecodedPacket itself.
        if (dp.result) {
            const OpcUaMessage& m = dp.result->as<OpcUaResult>().first;
            if (m.service_recognized && !m.service_name.empty()) fs.functions.insert(m.service_name);
        }
    } else if (dp.protocol == "mms") {
        fs.protocols.insert("mms");
        // Zero-flat-field migration (extra-reader batch): dp.mms_service_recognized/
        // dp.mms_service_name are gone -- read from the MmsFrame on dp.result instead, same field
        // names, just no longer flattened onto DecodedPacket itself.
        if (dp.result) {
            const MmsFrame& mf = dp.result->as<MmsFrame>();
            if (mf.service_recognized && !mf.service_name.empty()) fs.functions.insert(mf.service_name);
        }
    } else if (dp.protocol == "mqtt") {
        fs.protocols.insert("mqtt");
        // Zero-flat-field migration (extra-reader batch): dp.mqtt_packet_type_name is gone -- read
        // from MqttResult::first on dp.result instead. MqttMessage::packet_type_name
        // ("CONNECT"/"PUBLISH"/...) is always set once a "mqtt" packet decodes at all -- see
        // mqtt.hpp -- same "no separate guard needed" shape as hartip_message_type above.
        if (dp.result) {
            const std::string& pt = dp.result->as<MqttResult>().first.packet_type_name;
            if (!pt.empty()) fs.functions.insert(pt);
        }
    } else if (dp.protocol == "ffhse") {
        fs.protocols.insert("ffhse");
        // FfhseFrame::message_name is always set when protocol == "ffhse" -- see ffhse.hpp.
        if (dp.result) {
            const std::string& name = dp.result->as<FfhseResult>().first.message_name;
            if (!name.empty()) fs.functions.insert(name);
        }
    }
}

PolicyReport PolicyEngine::finish(const Resolver& resolver) const {
    PolicyReport report;
    report.total_packets = total_packets_;
    report.skipped_non_tcp = skipped_non_tcp_;
    report.observation_truncated = truncated_;
    report.truncation_reasons = truncation_reasons_;

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
        fr.has_mac = fs.has_mac;
        fr.client_mac = fs.client_mac;
        fr.server_mac = fs.server_mac;
        fr.direction_source = fs.direction_source;

        auto client_ip_u32 = parse_ipv4_string(fs.client_ip);
        auto server_ip_u32 = parse_ipv4_string(fs.server_ip);
        const Zone* cz = client_ip_u32 ? policy_.zone_for(*client_ip_u32) : nullptr;
        const Zone* sz = server_ip_u32 ? policy_.zone_for(*server_ip_u32) : nullptr;
        // Hostname-zone fallback: only attempted once a CIDR-zone lookup above missed, and only
        // when the policy declares at least one hostname zone at all (see Policy::has_hostname_zone's
        // own comment) -- a policy with no hostname zone is completely unaffected, the same
        // backward-compatibility posture any_vlan_zone_ already established for VLAN zones. A
        // hostname zone behaves like a CIDR zone for matching purposes (see policy.hpp's own header
        // comment), so it fills in cz/sz exactly the same way, just from a different lookup.
        if (!cz && client_ip_u32 && policy_.has_hostname_zone()) {
            if (auto host = resolver.hostname(fs.client_ip)) cz = policy_.zone_for_hostname(*host);
        }
        if (!sz && server_ip_u32 && policy_.has_hostname_zone()) {
            if (auto host = resolver.hostname(fs.server_ip)) sz = policy_.zone_for_hostname(*host);
        }
        fr.client_zone = cz ? cz->name : "unclassified";
        fr.server_zone = sz ? sz->name : "unclassified";
        fr.client_zone_purdue_level = cz ? cz->purdue_level : std::string();
        fr.server_zone_purdue_level = sz ? sz->purdue_level : std::string();

        if (!cz || !sz) {
            fr.verdict = FlowVerdict::Unclassified;
            fr.reason = zone_unclassified_reason(fr.client_ip, fr.server_ip, cz != nullptr, sz != nullptr);
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
        er.src_mac = es.src_mac;
        er.has_vlan_tag = es.has_vlan_tag;
        er.vlan_id = es.vlan_id;
        er.packet_count = es.packet_count;

        const Zone* vz = es.has_vlan_tag ? policy_.zone_for_vlan(es.vlan_id) : nullptr;
        er.vlan_zone = vz ? vz->name : "unclassified";
        er.vlan_zone_purdue_level = vz ? vz->purdue_level : std::string();

        if (!vz) {
            er.verdict = FlowVerdict::Unclassified;
            er.reason = es.has_vlan_tag
                            ? ("no declared VLAN zone contains VLAN " + std::to_string(es.vlan_id))
                            : "frame carries no 802.1Q VLAN tag at all";
        } else {
            const Conduit* matched = nullptr;
            for (const auto& c : policy_.conduits) {
                if (c.kind != ZoneKind::Vlan) continue;
                if (!zone_list_contains(c.from_zones, er.vlan_zone)) continue;
                bool protocols_ok = std::find(c.protocols.begin(), c.protocols.end(), er.protocol) != c.protocols.end() ||
                                     std::find(c.protocols.begin(), c.protocols.end(), "any") != c.protocols.end();
                if (!protocols_ok) continue;
                matched = &c;
                break;
            }
            if (matched) {
                // A matched conduit's own 'from_macs' allow-list (Phase 5, see policy.hpp's
                // Conduit::from_macs comment) is a further restriction on top of the
                // protocol/VLAN-zone match already found above: only a source MAC in that list may
                // publish, mirroring the same "matched, then a further allow-list check can still
                // turn it into a Violation" shape the TCP-flow 'functions' restriction above uses.
                // An empty 'from_macs' (the common case) means no restriction at all, exactly the
                // behavior before this field existed.
                bool mac_ok = matched->from_macs.empty() ||
                              std::find(matched->from_macs.begin(), matched->from_macs.end(), er.src_mac) !=
                                  matched->from_macs.end();
                if (!mac_ok) {
                    er.verdict = FlowVerdict::Violation;
                    std::ostringstream reason;
                    reason << "source MAC '" << er.src_mac << "' observed; conduit '" << matched->name
                           << "' permits only: " << join_comma(matched->from_macs);
                    er.reason = reason.str();
                } else {
                    er.verdict = FlowVerdict::Allowed;
                    er.matched_conduit = matched->name;
                    exercised_conduits.insert(matched->name);
                }
            } else {
                er.verdict = FlowVerdict::Violation;
                er.reason = "no conduit permits " + er.protocol + " traffic on VLAN zone '" + er.vlan_zone + "'";
            }
        }
        report.ethernet_flows.push_back(std::move(er));
    }

    for (const auto& key : udp_flow_order_) {
        const UdpFlowState& st = udp_flows_.at(key);
        UdpFlowReport ur;
        ur.protocol = st.protocol;
        ur.client_ip = st.client_ip;
        ur.server_ip = st.server_ip;
        ur.server_port = st.server_port;
        ur.packet_count = st.packet_count;
        ur.observed_functions.assign(st.functions.begin(), st.functions.end());
        std::sort(ur.observed_functions.begin(), ur.observed_functions.end());
        ur.has_mac = st.has_mac;
        ur.client_mac = st.client_mac;
        ur.server_mac = st.server_mac;
        ur.direction_source = st.direction_source;

        auto client_ip_u32 = parse_ipv4_string(st.client_ip);
        auto server_ip_u32 = parse_ipv4_string(st.server_ip);
        const Zone* cz = client_ip_u32 ? policy_.zone_for(*client_ip_u32) : nullptr;
        const Zone* sz = server_ip_u32 ? policy_.zone_for(*server_ip_u32) : nullptr;
        // Same CIDR-then-hostname fallback the TCP-flow loop above uses -- see its own comment.
        if (!cz && client_ip_u32 && policy_.has_hostname_zone()) {
            if (auto host = resolver.hostname(st.client_ip)) cz = policy_.zone_for_hostname(*host);
        }
        if (!sz && server_ip_u32 && policy_.has_hostname_zone()) {
            if (auto host = resolver.hostname(st.server_ip)) sz = policy_.zone_for_hostname(*host);
        }
        ur.client_zone = cz ? cz->name : "unclassified";
        ur.server_zone = sz ? sz->name : "unclassified";
        ur.client_zone_purdue_level = cz ? cz->purdue_level : std::string();
        ur.server_zone_purdue_level = sz ? sz->purdue_level : std::string();

        if (!cz || !sz) {
            ur.verdict = FlowVerdict::Unclassified;
            ur.reason = zone_unclassified_reason(ur.client_ip, ur.server_ip, cz != nullptr, sz != nullptr);
        } else {
            const Conduit* matched = nullptr;
            bool zone_pair_has_any_conduit = false;
            for (const auto& c : policy_.conduits) {
                if (c.kind == ZoneKind::Vlan) continue;  // BACnet/CIP I/O are IP-addressed --
                                                           // never matched against a VLAN-zone conduit
                bool forward = zone_list_contains(c.from_zones, ur.client_zone) &&
                               zone_list_contains(c.to_zones, ur.server_zone);
                bool reverse = c.bidirectional && zone_list_contains(c.to_zones, ur.client_zone) &&
                               zone_list_contains(c.from_zones, ur.server_zone);
                if (!forward && !reverse) continue;
                zone_pair_has_any_conduit = true;

                if (!c.ports.empty() &&
                    std::find(c.ports.begin(), c.ports.end(), ur.server_port) == c.ports.end()) {
                    continue;
                }
                bool protocol_ok = std::find(c.protocols.begin(), c.protocols.end(), ur.protocol) != c.protocols.end() ||
                                    std::find(c.protocols.begin(), c.protocols.end(), "any") != c.protocols.end();
                if (!protocol_ok) continue;

                matched = &c;
                break;
            }
            if (matched) {
                // Same functions-restriction logic the TCP-flow loop above uses -- see its own
                // comment. For CIP I/O, ur.observed_functions is always empty (see
                // UdpFlowReport::observed_functions' own comment), so a functions-restricted conduit
                // simply never finds anything disallowed and this always falls through to Allowed --
                // documented there and in docs/design/policy-engine-zoning.md's Phase 3 section, not
                // a silent surprise.
                std::vector<std::string> disallowed;
                if (!matched->functions.empty()) {
                    for (const auto& fn : ur.observed_functions) {
                        bool ok = std::any_of(matched->functions.begin(), matched->functions.end(),
                                               [&](const std::string& allowed) { return equal_ci(fn, allowed); });
                        if (!ok) disallowed.push_back(fn);
                    }
                }
                if (!disallowed.empty()) {
                    ur.verdict = FlowVerdict::Violation;
                    std::ostringstream reason;
                    reason << (disallowed.size() > 1 ? "functions " : "function ");
                    for (size_t i = 0; i < disallowed.size(); ++i) {
                        if (i) reason << ", ";
                        reason << "'" << disallowed[i] << "'";
                    }
                    reason << " observed; conduit '" << matched->name << "' permits only: "
                           << join_comma(matched->functions);
                    ur.reason = reason.str();
                } else {
                    ur.verdict = FlowVerdict::Allowed;
                    ur.matched_conduit = matched->name;
                    exercised_conduits.insert(matched->name);
                }
            } else {
                ur.verdict = FlowVerdict::Violation;
                std::ostringstream reason;
                if (!zone_pair_has_any_conduit) {
                    reason << "no conduit permits any traffic from zone '" << ur.client_zone << "' to zone '"
                           << ur.server_zone << "'";
                } else {
                    reason << "a conduit exists between zone '" << ur.client_zone << "' and zone '"
                           << ur.server_zone << "', but none permits " << ur.protocol << " traffic on port "
                           << ur.server_port;
                }
                ur.reason = reason.str();
            }
        }
        report.udp_flows.push_back(std::move(ur));
    }

    for (const auto& c : policy_.conduits) {
        if (!exercised_conduits.count(c.name)) report.unexercised_conduits.push_back(c.name);
    }

    for (const auto& key : notable_protocol_order_) {
        const NotableProtocolState& ns = notable_protocols_.at(key);
        NotableProtocolFinding nf;
        nf.protocol = ns.protocol;
        nf.tier = ns.tier;
        nf.has_ip = ns.has_ip;
        nf.direction_known = ns.direction_known;
        nf.client_ip = ns.client_ip;
        nf.server_ip = ns.server_ip;
        nf.mac_a = ns.mac_a;
        nf.mac_b = ns.mac_b;
        nf.has_port = ns.has_port;
        nf.is_tcp = ns.is_tcp;
        nf.port = ns.port;
        nf.packet_count = ns.packet_count;
        report.notable_protocols.push_back(std::move(nf));
    }

    // --- Phase 6: multi-homed asset cross-reference (see docs/design/policy-engine-zoning.md) ---
    // Computed purely from policy_ (assets/zones/conduits) -- completely independent of the
    // capture, so this section is identical whether or not a single packet was ever observed.
    // Never touches any FlowVerdict computed above.
    for (const auto& asset : policy_.assets) {
        MultiHomedAssetFinding mf;
        mf.name = asset.name;
        mf.role = asset.role;
        std::vector<std::string> distinct_zones;
        for (const auto& block : asset.ips) {
            mf.ips.push_back(block.text);
            const Zone* z = policy_.zone_for(block.network);
            std::string zname = z ? z->name : "unclassified";
            mf.zones.push_back(zname);
            if (std::find(distinct_zones.begin(), distinct_zones.end(), zname) == distinct_zones.end()) {
                distinct_zones.push_back(zname);
            }
        }
        for (size_t i = 0; i < distinct_zones.size(); ++i) {
            for (size_t j = i + 1; j < distinct_zones.size(); ++j) {
                AssetZonePair pair;
                if (distinct_zones[i] < distinct_zones[j]) {
                    pair.zone_a = distinct_zones[i];
                    pair.zone_b = distinct_zones[j];
                } else {
                    pair.zone_a = distinct_zones[j];
                    pair.zone_b = distinct_zones[i];
                }
                // "Covered" means some conduit's from_zones/to_zones names zone_a on one side and
                // zone_b on the other, in EITHER order, ignoring 'bidirectional' -- the point here
                // is only "is there a declared relationship between these two zones at all", not
                // simulating actual traffic direction the way finish()'s flow-matching above does.
                pair.covered = std::any_of(policy_.conduits.begin(), policy_.conduits.end(), [&](const Conduit& c) {
                    bool fwd = zone_list_contains(c.from_zones, pair.zone_a) &&
                               zone_list_contains(c.to_zones, pair.zone_b);
                    bool rev = zone_list_contains(c.from_zones, pair.zone_b) &&
                               zone_list_contains(c.to_zones, pair.zone_a);
                    return fwd || rev;
                });
                if (!pair.covered) mf.flagged = true;
                mf.zone_pairs.push_back(std::move(pair));
            }
        }
        report.multi_homed_assets.push_back(std::move(mf));
    }

    // --- Phase 6: jump-host flow post-pass ---------------------------------------------------
    // Scans report.flows/report.udp_flows (now fully populated above) for any flow where either
    // endpoint belongs to a role: "jump_host"-tagged asset -- see JumpHostFlowFinding's own
    // comment. Purely additive: never touches any FlowVerdict already computed above. Raw-Ethernet
    // L2 flows (report.ethernet_flows) have no IP addressing at all, so they're never in scope
    // here -- only a TCP or UDP flow can have an endpoint that "belongs to" an IP-addressed asset.
    for (const auto& fr : report.flows) {
        auto client_u32 = parse_ipv4_string(fr.client_ip);
        auto server_u32 = parse_ipv4_string(fr.server_ip);
        for (const auto& asset : policy_.assets) {
            if (!equal_ci(asset.role, "jump_host")) continue;
            bool client_match = client_u32 && std::any_of(asset.ips.begin(), asset.ips.end(),
                                                           [&](const CidrBlock& b) { return cidr_contains(b, *client_u32); });
            bool server_match = !client_match && server_u32 &&
                                 std::any_of(asset.ips.begin(), asset.ips.end(),
                                             [&](const CidrBlock& b) { return cidr_contains(b, *server_u32); });
            if (!client_match && !server_match) continue;
            JumpHostFlowFinding jf;
            jf.asset_name = asset.name;
            jf.jump_host_ip = client_match ? fr.client_ip : fr.server_ip;
            jf.jump_host_is_client = client_match;
            jf.client_ip = fr.client_ip;
            jf.server_ip = fr.server_ip;
            jf.server_port = fr.server_port;
            jf.protocol = join_comma(fr.protocols);
            jf.is_udp = false;
            jf.verdict = fr.verdict;
            jf.matched_conduit = fr.matched_conduit;
            jf.reason = fr.reason;
            report.jump_host_flows.push_back(std::move(jf));
        }
    }
    for (const auto& ur : report.udp_flows) {
        auto client_u32 = parse_ipv4_string(ur.client_ip);
        auto server_u32 = parse_ipv4_string(ur.server_ip);
        for (const auto& asset : policy_.assets) {
            if (!equal_ci(asset.role, "jump_host")) continue;
            bool client_match = client_u32 && std::any_of(asset.ips.begin(), asset.ips.end(),
                                                           [&](const CidrBlock& b) { return cidr_contains(b, *client_u32); });
            bool server_match = !client_match && server_u32 &&
                                 std::any_of(asset.ips.begin(), asset.ips.end(),
                                             [&](const CidrBlock& b) { return cidr_contains(b, *server_u32); });
            if (!client_match && !server_match) continue;
            JumpHostFlowFinding jf;
            jf.asset_name = asset.name;
            jf.jump_host_ip = client_match ? ur.client_ip : ur.server_ip;
            jf.jump_host_is_client = client_match;
            jf.client_ip = ur.client_ip;
            jf.server_ip = ur.server_ip;
            jf.server_port = ur.server_port;
            jf.protocol = ur.protocol;
            jf.is_udp = true;
            jf.verdict = ur.verdict;
            jf.matched_conduit = ur.matched_conduit;
            jf.reason = ur.reason;
            report.jump_host_flows.push_back(std::move(jf));
        }
    }

    return report;
}

size_t PolicyReport::allowed_count() const {
    return static_cast<size_t>(
               std::count_if(flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Allowed; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Allowed; })) +
           static_cast<size_t>(std::count_if(udp_flows.begin(), udp_flows.end(),
                                              [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
}
size_t PolicyReport::violation_count() const {
    return static_cast<size_t>(std::count_if(flows.begin(), flows.end(),
                                              [](const FlowReport& f) { return f.verdict == FlowVerdict::Violation; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Violation; })) +
           static_cast<size_t>(std::count_if(udp_flows.begin(), udp_flows.end(),
                                              [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
}
size_t PolicyReport::unclassified_count() const {
    return static_cast<size_t>(std::count_if(
               flows.begin(), flows.end(), [](const FlowReport& f) { return f.verdict == FlowVerdict::Unclassified; })) +
           static_cast<size_t>(std::count_if(ethernet_flows.begin(), ethernet_flows.end(),
                                              [](const EthernetFlowReport& f) { return f.verdict == FlowVerdict::Unclassified; })) +
           static_cast<size_t>(std::count_if(udp_flows.begin(), udp_flows.end(),
                                              [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
}

namespace {

// One collapsed group of UNCLASSIFIED FlowReport entries that share the same (client_ip,
// server_ip, server_port, protocols, client_zone, server_zone, MAC pair) -- see
// summarize_unclassified_flows below for exactly how the key is built and why those fields (and
// only those) are what defines "the same pattern" for this feature's purposes.
struct UnclassifiedFlowGroup {
    const FlowReport* first = nullptr;  // representative flow, for every field this group's members
                                         // all share (client/server ip/port/zones/protocols/mac) --
                                         // NOT representative of packet_count, which is per-member
    size_t flow_count = 0;
    size_t packet_total = 0;
};

// Groups `group` (already-filtered to FlowVerdict::Unclassified, in first-seen order -- the same
// input write_flow_group_text takes for this same list) by (client_ip, server_ip, server_port,
// protocols, client_zone, server_zone, MAC pair), preserving first-seen GROUP order (not first-seen
// flow order -- irrelevant here, since every member of a group is, by definition, "the same
// pattern"). Two flows between the same hosts on DIFFERENT ports are deliberately kept as separate
// groups (server_port is part of the key) -- see build_summarize_unclassified_sample's own "Pattern
// B" comment (tools/make_sample_pcap.py) for why that distinction matters to an auditor even when
// the client/server pair is identical. MAC pair is included in the key purely for correctness (two
// flows between the same IPs could in principle arrive over different MACs, e.g. after a NIC
// change) even though in practice every member of a real group almost always shares one.
//
// Deliberately does NOT key on FlowReport::reason: exactly one of the two possible reasons a flow
// is Unclassified (see PolicyEngine::finish's own comment on FlowReport::reason) embeds that FLOW's
// own packet count in its text ("no recognized OT protocol traffic was found on this flow (N
// unrecognized/handshake packet(s) only)") -- keying on the literal reason string would silently
// split what should be one group into as many groups as there are distinct packet counts among its
// members. write_unclassified_flow_group_summarized_text below instead re-derives which of the two
// reasons applies (from whether client_zone/server_zone is "unclassified", cheaply, no string
// parsing) and renders a group-safe version of it once per group.
std::vector<UnclassifiedFlowGroup> summarize_unclassified_flows(const std::vector<const FlowReport*>& group) {
    std::vector<UnclassifiedFlowGroup> result;
    std::unordered_map<std::string, size_t> index_of_key;  // key -> position in result
    result.reserve(group.size());
    for (const FlowReport* f : group) {
        std::string key = f->client_ip + ":" + f->server_ip + ":" + std::to_string(f->server_port) + ":" +
                           protocol_list_text(f->protocols) + ":" + f->client_zone + ":" + f->server_zone + ":" +
                           (f->has_mac ? f->client_mac + ">" + f->server_mac : std::string());
        auto it = index_of_key.find(key);
        if (it == index_of_key.end()) {
            index_of_key.emplace(key, result.size());
            result.push_back(UnclassifiedFlowGroup{f, 1, f->packet_count});
        } else {
            UnclassifiedFlowGroup& g = result[it->second];
            ++g.flow_count;
            g.packet_total += f->packet_count;
        }
    }
    return result;
}

// The --summarize-unclassified rendering for UNCLASSIFIED TRAFFIC -- see write_policy_report_text's
// own doc comment (policy_engine.hpp) for when this is used instead of write_flow_group_text, and
// summarize_unclassified_flows above for exactly how `group` is collapsed first.
void write_unclassified_flow_group_summarized_text(std::ostream& out, const std::vector<const FlowReport*>& group,
                                                     const Resolver& resolver) {
    std::vector<UnclassifiedFlowGroup> groups = summarize_unclassified_flows(group);
    out << "UNCLASSIFIED TRAFFIC (" << group.size() << " flow(s), summarized into " << groups.size()
        << " distinct pattern(s) -- rerun without --summarize-unclassified, or with --format json, "
           "for the full per-flow listing):\n";
    if (groups.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < groups.size(); ++i) {
        const UnclassifiedFlowGroup& g = groups[i];
        const FlowReport& f = *g.first;
        out << "  [" << (i + 1) << "] " << f.client_ip;
        if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
        out << " -> " << f.server_ip;
        if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
        out << ":" << f.server_port;
        if (auto s = resolver.service_name(f.server_port, "tcp")) out << " (" << *s << ")";
        if (!f.protocols.empty()) out << "  (" << protocol_list_text(f.protocols) << ")";
        out << "  -- " << g.flow_count << " flow(s), " << g.packet_total << " packet(s) total\n";
        out << "      zones: " << f.client_zone;
        if (!f.client_zone_purdue_level.empty()) out << " (Level " << f.client_zone_purdue_level << ")";
        out << " -> " << f.server_zone;
        if (!f.server_zone_purdue_level.empty()) out << " (Level " << f.server_zone_purdue_level << ")";
        out << "\n";
        if (f.has_mac) {
            out << "      mac: " << f.client_mac;
            if (auto v = resolver.oui_vendor(f.client_mac)) out << " (" << *v << ")";
            out << " -> " << f.server_mac;
            if (auto v = resolver.oui_vendor(f.server_mac)) out << " (" << *v << ")";
            out << "\n";
        }
        // Re-derived, group-safe reason -- see summarize_unclassified_flows's own comment above for
        // why this can't just reuse f.reason verbatim for BOTH possible unclassified reasons (only
        // the zone one is safe to reuse as-is; it never embeds a per-flow packet count).
        bool zone_reason = (f.client_zone == "unclassified" || f.server_zone == "unclassified");
        if (zone_reason) {
            out << "      " << f.reason << "\n";
        } else {
            out << "      no recognized OT protocol traffic was found on any of these flows\n";
        }
    }
}

void write_flow_group_text(std::ostream& out, const std::vector<const FlowReport*>& group, const char* label,
                            const Resolver& resolver) {
    out << label << " (" << group.size() << "):\n";
    if (group.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < group.size(); ++i) {
        const FlowReport& f = *group[i];
        // Hostname/service-name annotations, inline right after the raw value they explain -- same
        // convention as output.cpp's endpoint() helper (see resolver.hpp's file header). A flow's
        // server_port is always a TCP port (PolicyEngine only ever aggregates has_tcp packets into
        // FlowReport -- see PolicyEngine::observe), so "tcp" is hardcoded here, unlike endpoint()'s
        // own tcp/udp branch.
        out << "  [" << (i + 1) << "] " << f.client_ip;
        if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
        out << " -> " << f.server_ip;
        if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
        out << ":" << f.server_port;
        if (auto s = resolver.service_name(f.server_port, "tcp")) out << " (" << *s << ")";
        if (!f.protocols.empty()) out << "  (" << protocol_list_text(f.protocols) << ", " << f.packet_count << " packet(s))";
        else out << "  (" << f.packet_count << " packet(s), no recognized protocol)";
        out << "\n      zones: " << f.client_zone;
        if (!f.client_zone_purdue_level.empty()) out << " (Level " << f.client_zone_purdue_level << ")";
        out << " -> " << f.server_zone;
        if (!f.server_zone_purdue_level.empty()) out << " (Level " << f.server_zone_purdue_level << ")";
        if (f.verdict == FlowVerdict::Allowed) {
            out << ", matched conduit \"" << f.matched_conduit << "\"";
        }
        out << "\n      direction: " << direction_source_name(f.direction_source) << "\n";
        // MAC addressing (with OUI vendor annotations), as its own line -- absent entirely when this
        // flow's link type isn't Ethernet (f.has_mac false; see FlowReport::has_mac's own comment).
        // Mirrors decode's own TextWriter, which prints its "eth ..." line the same way, after the
        // rest of a packet's info rather than folded into it.
        if (f.has_mac) {
            out << "      mac: " << f.client_mac;
            if (auto v = resolver.oui_vendor(f.client_mac)) out << " (" << *v << ")";
            out << " -> " << f.server_mac;
            if (auto v = resolver.oui_vendor(f.server_mac)) out << " (" << *v << ")";
            out << "\n";
        }
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// Same idea as write_flow_group_text, for the L2/VLAN-zone side of the report -- rendered under a
// "MAC_A <-> MAC_B" heading rather than "client -> server", since these protocols have no
// client/server distinction (see EthernetFlowReport's own comment). There is no IP or port here at
// all, so only OUI vendor annotation applies (no hostname/service-name equivalent is possible).
void write_ethernet_flow_group_text(std::ostream& out, const std::vector<const EthernetFlowReport*>& group,
                                     const char* label, const Resolver& resolver) {
    out << label << " (" << group.size() << "):\n";
    if (group.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < group.size(); ++i) {
        const EthernetFlowReport& f = *group[i];
        out << "  [" << (i + 1) << "] " << f.mac_a;
        if (auto v = resolver.oui_vendor(f.mac_a)) out << " (" << *v << ")";
        out << " <-> " << f.mac_b;
        if (auto v = resolver.oui_vendor(f.mac_b)) out << " (" << *v << ")";
        out << "  (" << f.protocol << ", " << f.packet_count << " packet(s))";
        out << "\n      vlan: " << (f.has_vlan_tag ? std::to_string(f.vlan_id) : std::string("(untagged)"))
            << ", zone: " << f.vlan_zone;
        if (!f.vlan_zone_purdue_level.empty()) out << " (Level " << f.vlan_zone_purdue_level << ")";
        if (f.verdict == FlowVerdict::Allowed) {
            out << ", matched conduit \"" << f.matched_conduit << "\"";
        }
        out << "\n      source: " << f.src_mac;
        if (auto v = resolver.oui_vendor(f.src_mac)) out << " (" << *v << ")";
        out << "\n";
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// Ethernet-side analog of UnclassifiedFlowGroup/summarize_unclassified_flows above -- one collapsed
// group of UNCLASSIFIED EthernetFlowReport entries sharing the same (mac_a, mac_b, protocol,
// has_vlan_tag, vlan_id, vlan_zone). Unlike the TCP-flow case, EthernetFlowReport::reason is ALWAYS
// safe to reuse verbatim once grouped: neither of its two possible Unclassified reasons ("no
// declared VLAN zone contains VLAN N" / "frame carries no 802.1Q VLAN tag at all" -- see
// PolicyEngine::finish's own comment) ever embeds a per-flow packet count, so there's no equivalent
// of write_unclassified_flow_group_summarized_text's own "re-derive a group-safe reason" step here.
struct UnclassifiedEthernetGroup {
    const EthernetFlowReport* first = nullptr;
    size_t flow_count = 0;
    size_t packet_total = 0;
};

std::vector<UnclassifiedEthernetGroup> summarize_unclassified_ethernet_flows(
    const std::vector<const EthernetFlowReport*>& group) {
    std::vector<UnclassifiedEthernetGroup> result;
    std::unordered_map<std::string, size_t> index_of_key;
    result.reserve(group.size());
    for (const EthernetFlowReport* f : group) {
        std::string key = f->mac_a + ":" + f->mac_b + ":" + f->protocol + ":" +
                           (f->has_vlan_tag ? std::to_string(f->vlan_id) : std::string("untagged")) + ":" +
                           f->vlan_zone;
        auto it = index_of_key.find(key);
        if (it == index_of_key.end()) {
            index_of_key.emplace(key, result.size());
            result.push_back(UnclassifiedEthernetGroup{f, 1, f->packet_count});
        } else {
            UnclassifiedEthernetGroup& g = result[it->second];
            ++g.flow_count;
            g.packet_total += f->packet_count;
        }
    }
    return result;
}

void write_unclassified_ethernet_flow_group_summarized_text(std::ostream& out,
                                                              const std::vector<const EthernetFlowReport*>& group,
                                                              const Resolver& resolver) {
    std::vector<UnclassifiedEthernetGroup> groups = summarize_unclassified_ethernet_flows(group);
    out << "ETHERNET UNCLASSIFIED TRAFFIC (" << group.size() << " flow(s), summarized into " << groups.size()
        << " distinct pattern(s) -- rerun without --summarize-unclassified, or with --format json, "
           "for the full per-flow listing):\n";
    if (groups.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < groups.size(); ++i) {
        const UnclassifiedEthernetGroup& g = groups[i];
        const EthernetFlowReport& f = *g.first;
        out << "  [" << (i + 1) << "] " << f.mac_a;
        if (auto v = resolver.oui_vendor(f.mac_a)) out << " (" << *v << ")";
        out << " <-> " << f.mac_b;
        if (auto v = resolver.oui_vendor(f.mac_b)) out << " (" << *v << ")";
        out << "  (" << f.protocol << ")  -- " << g.flow_count << " flow(s), " << g.packet_total << " packet(s) total\n";
        out << "      vlan: " << (f.has_vlan_tag ? std::to_string(f.vlan_id) : std::string("(untagged)"))
            << ", zone: " << f.vlan_zone;
        if (!f.vlan_zone_purdue_level.empty()) out << " (Level " << f.vlan_zone_purdue_level << ")";
        out << "\n";
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// UDP-flow analog of write_flow_group_text -- see that function's own comment for the shared
// structure. Server port is always UDP here (PolicyEngine only ever aggregates has_udp packets into
// UdpFlowReport), so "udp" is hardcoded, unlike write_flow_group_text's own "tcp".
void write_udp_flow_group_text(std::ostream& out, const std::vector<const UdpFlowReport*>& group, const char* label,
                                const Resolver& resolver) {
    out << label << " (" << group.size() << "):\n";
    if (group.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < group.size(); ++i) {
        const UdpFlowReport& f = *group[i];
        out << "  [" << (i + 1) << "] " << f.client_ip;
        if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
        out << " -> " << f.server_ip;
        if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
        out << ":" << f.server_port;
        if (auto s = resolver.service_name(f.server_port, "udp")) out << " (" << *s << ")";
        out << "  (" << f.protocol << ", " << f.packet_count << " packet(s))";
        out << "\n      zones: " << f.client_zone;
        if (!f.client_zone_purdue_level.empty()) out << " (Level " << f.client_zone_purdue_level << ")";
        out << " -> " << f.server_zone;
        if (!f.server_zone_purdue_level.empty()) out << " (Level " << f.server_zone_purdue_level << ")";
        if (f.verdict == FlowVerdict::Allowed) {
            out << ", matched conduit \"" << f.matched_conduit << "\"";
        }
        out << "\n      direction: " << direction_source_name(f.direction_source) << "\n";
        if (f.has_mac) {
            out << "      mac: " << f.client_mac;
            if (auto v = resolver.oui_vendor(f.client_mac)) out << " (" << *v << ")";
            out << " -> " << f.server_mac;
            if (auto v = resolver.oui_vendor(f.server_mac)) out << " (" << *v << ")";
            out << "\n";
        }
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// UDP-flow analog of UnclassifiedFlowGroup/summarize_unclassified_flows -- one collapsed group of
// UNCLASSIFIED UdpFlowReport entries sharing the same (client_ip, server_ip, server_port, protocol,
// client_zone, server_zone, MAC pair). UdpFlowReport::reason is always safe to reuse verbatim once
// grouped (unlike the TCP-flow case): every UDP flow this engine creates has a known protocol, so
// there is no "no recognized OT protocol traffic" reason equivalent embedding a per-flow packet
// count here -- the only Unclassified reason a UDP flow can have is the zone one, from
// zone_unclassified_reason, which never embeds a count.
struct UnclassifiedUdpFlowGroup {
    const UdpFlowReport* first = nullptr;
    size_t flow_count = 0;
    size_t packet_total = 0;
};

std::vector<UnclassifiedUdpFlowGroup> summarize_unclassified_udp_flows(const std::vector<const UdpFlowReport*>& group) {
    std::vector<UnclassifiedUdpFlowGroup> result;
    std::unordered_map<std::string, size_t> index_of_key;
    result.reserve(group.size());
    for (const UdpFlowReport* f : group) {
        std::string key = f->client_ip + ":" + f->server_ip + ":" + std::to_string(f->server_port) + ":" +
                           f->protocol + ":" + f->client_zone + ":" + f->server_zone + ":" +
                           (f->has_mac ? f->client_mac + ">" + f->server_mac : std::string());
        auto it = index_of_key.find(key);
        if (it == index_of_key.end()) {
            index_of_key.emplace(key, result.size());
            result.push_back(UnclassifiedUdpFlowGroup{f, 1, f->packet_count});
        } else {
            UnclassifiedUdpFlowGroup& g = result[it->second];
            ++g.flow_count;
            g.packet_total += f->packet_count;
        }
    }
    return result;
}

void write_unclassified_udp_flow_group_summarized_text(std::ostream& out, const std::vector<const UdpFlowReport*>& group,
                                                         const Resolver& resolver) {
    std::vector<UnclassifiedUdpFlowGroup> groups = summarize_unclassified_udp_flows(group);
    out << "UDP UNCLASSIFIED TRAFFIC (" << group.size() << " flow(s), summarized into " << groups.size()
        << " distinct pattern(s) -- rerun without --summarize-unclassified, or with --format json, "
           "for the full per-flow listing):\n";
    if (groups.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < groups.size(); ++i) {
        const UnclassifiedUdpFlowGroup& g = groups[i];
        const UdpFlowReport& f = *g.first;
        out << "  [" << (i + 1) << "] " << f.client_ip;
        if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
        out << " -> " << f.server_ip;
        if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
        out << ":" << f.server_port;
        if (auto s = resolver.service_name(f.server_port, "udp")) out << " (" << *s << ")";
        out << "  (" << f.protocol << ")  -- " << g.flow_count << " flow(s), " << g.packet_total << " packet(s) total\n";
        out << "      zones: " << f.client_zone;
        if (!f.client_zone_purdue_level.empty()) out << " (Level " << f.client_zone_purdue_level << ")";
        out << " -> " << f.server_zone;
        if (!f.server_zone_purdue_level.empty()) out << " (Level " << f.server_zone_purdue_level << ")";
        out << "\n";
        if (f.has_mac) {
            out << "      mac: " << f.client_mac;
            if (auto v = resolver.oui_vendor(f.client_mac)) out << " (" << *v << ")";
            out << " -> " << f.server_mac;
            if (auto v = resolver.oui_vendor(f.server_mac)) out << " (" << *v << ")";
            out << "\n";
        }
        if (!f.reason.empty()) {
            out << "      " << f.reason << "\n";
        }
    }
}

// Renders PolicyReport::notable_protocols -- see that field's own comment for why this is always
// printed (never grouped by, or gated on, Allowed/Violation/Unclassified the way write_flow_group_
// text's three groups are) and NotableProtocolFinding's own comment for exactly what each field
// means for each of the four transport shapes rendered here.
void write_notable_protocols_text(std::ostream& out, const PolicyReport& report, const Resolver& resolver) {
    out << "NOTABLE IT PROTOCOLS (" << report.notable_protocols.size() << "):\n";
    out << "  Protocols an OT auditor would flag as worth attention on their own, independent of\n";
    out << "  whether a conduit permits them -- see docs/MANUAL.md's ROADMAP item 18.\n";
    if (report.notable_protocols.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < report.notable_protocols.size(); ++i) {
        const NotableProtocolFinding& f = report.notable_protocols[i];
        out << "  [" << (i + 1) << "] " << f.protocol << "  (" << f.tier << ")  ";
        if (f.has_ip) {
            out << f.client_ip;
            if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
            out << (f.direction_known ? " -> " : " <-> ") << f.server_ip;
            if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
            if (f.has_port) {
                out << ":" << f.port;
                if (auto s = resolver.service_name(f.port, f.is_tcp ? "tcp" : "udp")) out << " (" << *s << ")";
            }
            if (!f.direction_known) out << "  (direction: port heuristic)";
        } else {
            out << f.mac_a;
            if (auto v = resolver.oui_vendor(f.mac_a)) out << " (" << *v << ")";
            out << " <-> " << f.mac_b;
            if (auto v = resolver.oui_vendor(f.mac_b)) out << " (" << *v << ")";
        }
        out << "  (" << f.packet_count << " packet(s))\n";
    }
}

// Renders the "IT-OT CROSSING CONDUITS" callout -- every conduit tagged `type: idmz` (see
// Conduit::conduit_type's own comment), regardless of allowed/violation/unclassified status,
// listed together so an auditor's eye goes straight there instead of hunting through the general
// conduit list. "exercised"/"unexercised" reuses report.unexercised_conduits (a conduit not in
// that list was matched by at least one Allowed flow/L2 flow) rather than tracking separate state
// -- this is purely a filtered view over data PolicyEngine::finish already computed. Prints
// nothing at all (not even a header) when the policy declares no idmz-typed conduit, so a policy
// that never uses this feature renders byte-for-byte identically to before it existed.
void write_idmz_conduits_text(std::ostream& out, const PolicyReport& report, const Policy& policy) {
    std::vector<const Conduit*> idmz_conduits;
    for (const auto& c : policy.conduits) {
        if (c.conduit_type == "idmz") idmz_conduits.push_back(&c);
    }
    if (idmz_conduits.empty()) return;

    out << "IT-OT CROSSING CONDUITS (" << idmz_conduits.size() << "):\n";
    out << "  Conduits declared 'type: idmz' -- IT/OT or iDMZ boundary crossings, held to a "
           "stricter\n  validation bar (no unrestricted 'protocols: any' with no 'functions' "
           "restriction).\n";
    for (const auto* c : idmz_conduits) {
        bool exercised = std::find(report.unexercised_conduits.begin(), report.unexercised_conduits.end(),
                                    c->name) == report.unexercised_conduits.end();
        out << "  - " << c->name << ": " << (exercised ? "exercised by this capture" : "not exercised by this capture")
            << "\n";
    }
    out << "\n";
}

// Renders PolicyReport::multi_homed_assets (Phase 6) -- see MultiHomedAssetFinding's own comment.
// Prints nothing at all (not even a header) when the policy declares no 'assets:' at all, so a
// policy that never uses this feature renders byte-for-byte identically to before it existed.
void write_multi_homed_assets_text(std::ostream& out, const PolicyReport& report) {
    if (report.multi_homed_assets.empty()) return;
    size_t flagged_count = static_cast<size_t>(std::count_if(
        report.multi_homed_assets.begin(), report.multi_homed_assets.end(),
        [](const MultiHomedAssetFinding& f) { return f.flagged; }));
    out << "MULTI-HOMED ASSETS (" << report.multi_homed_assets.size() << ", " << flagged_count
        << " flagged):\n";
    out << "  Declared assets with 2+ IPs, cross-referenced against this policy's own zones/\n";
    out << "  conduits -- an asset whose IPs span two or more zones with no conduit declared\n";
    out << "  between them is an undocumented cross-zone bridge (OWASP OT Top 10's \"broken zones\n";
    out << "  from dual-homed HMIs\" pattern). Purely advisory: never affects Result above.\n";
    for (const auto& f : report.multi_homed_assets) {
        out << "  - " << f.name;
        if (!f.role.empty()) out << " (role: " << f.role << ")";
        out << ": " << (f.flagged ? "FLAGGED -- undocumented cross-zone bridge" : "ok") << "\n";
        for (size_t i = 0; i < f.ips.size(); ++i) {
            out << "      " << f.ips[i] << " -> zone '" << f.zones[i] << "'\n";
        }
        for (const auto& pair : f.zone_pairs) {
            out << "      zone pair '" << pair.zone_a << "' <-> '" << pair.zone_b << "': "
                << (pair.covered ? "covered by a declared conduit" : "NOT COVERED by any conduit") << "\n";
        }
    }
    out << "\n";
}

// Renders PolicyReport::jump_host_flows (Phase 6) -- see JumpHostFlowFinding's own comment. Prints
// nothing at all when the policy declares no 'role: "jump_host"' asset, or when one is declared
// but no observed flow ever touched it.
void write_jump_host_flows_text(std::ostream& out, const PolicyReport& report, const Resolver& resolver) {
    if (report.jump_host_flows.empty()) return;
    out << "JUMP HOST FLOWS (" << report.jump_host_flows.size() << "):\n";
    out << "  Every TCP/UDP flow where an endpoint belongs to a declared role: \"jump_host\" asset,\n";
    out << "  regardless of that flow's own compliant/violation/unclassified status -- remote\n";
    out << "  access via a jump host is the pattern being watched for here.\n";
    for (size_t i = 0; i < report.jump_host_flows.size(); ++i) {
        const JumpHostFlowFinding& f = report.jump_host_flows[i];
        out << "  [" << (i + 1) << "] asset '" << f.asset_name << "' (" << f.jump_host_ip
            << (f.jump_host_is_client ? " is client): " : " is server): ") << f.client_ip;
        if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
        out << " -> " << f.server_ip;
        if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
        out << ":" << f.server_port << " (" << f.protocol << ", " << (f.is_udp ? "udp" : "tcp") << ")\n";
        out << "      verdict: " << verdict_name(f.verdict);
        if (!f.matched_conduit.empty()) out << " (conduit '" << f.matched_conduit << "')";
        out << "\n";
        if (!f.reason.empty()) out << "      " << f.reason << "\n";
    }
    out << "\n";
}

}  // namespace

void write_policy_report_text(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path,
                               const Resolver& resolver, bool summarize_unclassified) {
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

    // patch257 finding 3 fix: printed even when compliant() is true -- same posture as
    // BaselineCheckReport's own observation_truncated rendering (write_baseline_check_report_text,
    // baseline.cpp): a "COMPLIANT" result here is only ever a partial view once this is true.
    if (report.observation_truncated) {
        out << "*** OBSERVATION INCOMPLETE -- this capture hit at least one of PolicyEngine's "
               "internal limits, so the result above reflects only PART of what the capture "
               "actually contains. Any \"COMPLIANT\" result is NOT trustworthy until this is "
               "resolved (raise the relevant --max-policy-* limit and re-run). ***\n";
        for (const std::string& reason : report.truncation_reasons) {
            out << "  - " << reason << "\n";
        }
        out << "\n";
    }

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

    write_flow_group_text(out, violations, "VIOLATIONS", resolver);
    out << "\n";
    if (summarize_unclassified) {
        write_unclassified_flow_group_summarized_text(out, unclassified, resolver);
    } else {
        write_flow_group_text(out, unclassified, "UNCLASSIFIED TRAFFIC", resolver);
    }
    out << "\n";
    write_flow_group_text(out, allowed, "ALLOWED", resolver);
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

        write_ethernet_flow_group_text(out, eth_violations, "ETHERNET VIOLATIONS", resolver);
        out << "\n";
        if (summarize_unclassified) {
            write_unclassified_ethernet_flow_group_summarized_text(out, eth_unclassified_list, resolver);
        } else {
            write_ethernet_flow_group_text(out, eth_unclassified_list, "ETHERNET UNCLASSIFIED TRAFFIC", resolver);
        }
        out << "\n";
        write_ethernet_flow_group_text(out, eth_allowed_list, "ETHERNET ALLOWED", resolver);
        out << "\n";
    }

    // Only printed at all once the policy opts in by naming "bacnet"/"enip"/"any" on a CIDR- or
    // hostname-zone conduit (see PolicyEngine::observe's own comment) -- a report from a policy that
    // never does renders byte-for-byte identically to before this feature existed.
    if (!report.udp_flows.empty()) {
        size_t udp_allowed = static_cast<size_t>(std::count_if(
            report.udp_flows.begin(), report.udp_flows.end(),
            [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Allowed; }));
        size_t udp_violation = static_cast<size_t>(std::count_if(
            report.udp_flows.begin(), report.udp_flows.end(),
            [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Violation; }));
        size_t udp_unclassified = static_cast<size_t>(std::count_if(
            report.udp_flows.begin(), report.udp_flows.end(),
            [](const UdpFlowReport& f) { return f.verdict == FlowVerdict::Unclassified; }));
        out << "UDP flows evaluated: " << report.udp_flows.size() << " (" << udp_allowed << " allowed, "
            << udp_violation << " violation(s), " << udp_unclassified << " unclassified)\n";
        out << "  BACnet/IP and/or CIP I/O traffic, classified by CIDR/hostname zone -- see "
               "docs/USER_GUIDE.md's POLICY FILE FORMAT section\n\n";

        std::vector<const UdpFlowReport*> udp_violations, udp_unclassified_list, udp_allowed_list;
        for (const auto& f : report.udp_flows) {
            if (f.verdict == FlowVerdict::Violation) udp_violations.push_back(&f);
            else if (f.verdict == FlowVerdict::Unclassified) udp_unclassified_list.push_back(&f);
            else udp_allowed_list.push_back(&f);
        }

        write_udp_flow_group_text(out, udp_violations, "UDP VIOLATIONS", resolver);
        out << "\n";
        if (summarize_unclassified) {
            write_unclassified_udp_flow_group_summarized_text(out, udp_unclassified_list, resolver);
        } else {
            write_udp_flow_group_text(out, udp_unclassified_list, "UDP UNCLASSIFIED TRAFFIC", resolver);
        }
        out << "\n";
        write_udp_flow_group_text(out, udp_allowed_list, "UDP ALLOWED", resolver);
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
    out << "\n";

    write_idmz_conduits_text(out, report, policy);

    write_notable_protocols_text(out, report, resolver);

    write_multi_homed_assets_text(out, report);
    write_jump_host_flows_text(out, report, resolver);
}

void write_policy_report_json(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path,
                               const Resolver& resolver) {
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
        out << "      \"is_vlan_conduit\": " << (c.kind == ZoneKind::Vlan ? "true" : "false") << ",\n";
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
        out << "],\n";
        out << "      \"conduit_type\": " << (c.conduit_type.empty() ? "null" : ("\"" + json_escape(c.conduit_type) + "\"")) << ",\n";
        // The new true-last field within this object (Phase 5, see policy.hpp's Conduit::from_macs
        // comment) -- empty array (not null) when unrestricted, the same convention 'functions'
        // above already uses for its own empty case.
        out << "      \"from_macs\": [";
        for (size_t j = 0; j < c.from_macs.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(c.from_macs[j]) << "\"";
        }
        out << "]\n";
        out << "    }" << (i + 1 < policy.conduits.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"compliant\": " << (report.compliant() ? "true" : "false") << ",\n";
    // Same shape as BaselineCheckReport's own observation_truncated/truncation_reasons JSON fields
    // (write_baseline_check_report_json, baseline.cpp) -- a caller parsing this JSON must check
    // observation_truncated, not "compliant" alone, since "compliant": true alongside
    // "observation_truncated": true means the capture was only PARTLY observed, not confirmed clean.
    out << "  \"observation_truncated\": " << (report.observation_truncated ? "true" : "false") << ",\n";
    out << "  \"truncation_reasons\": [";
    for (size_t i = 0; i < report.truncation_reasons.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << json_escape(report.truncation_reasons[i]) << "\"";
    }
    out << "],\n";
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
        // Resolver-derived annotations (OUI vendor / hostname / service name) plus the base
        // client_mac/server_mac gap-fix -- same grouping/omission convention as output.cpp's
        // JsonWriter (see resolver.hpp's file header): client_mac/server_mac are always present as a
        // string or `null` (null only when this flow's link type isn't Ethernet -- f.has_mac false),
        // while every *_vendor/*_hostname/*_port_service annotation field is OMITTED ENTIRELY on a
        // lookup miss or disabled lookup, never emitted as null.
        out << "      \"client_mac\": " << (f.has_mac ? ("\"" + json_escape(f.client_mac) + "\"") : "null") << ",\n";
        out << "      \"server_mac\": " << (f.has_mac ? ("\"" + json_escape(f.server_mac) + "\"") : "null") << ",\n";
        if (f.has_mac) {
            if (auto v = resolver.oui_vendor(f.client_mac)) {
                out << "      \"client_mac_vendor\": \"" << json_escape(*v) << "\",\n";
            }
            if (auto v = resolver.oui_vendor(f.server_mac)) {
                out << "      \"server_mac_vendor\": \"" << json_escape(*v) << "\",\n";
            }
        }
        if (auto h = resolver.hostname(f.client_ip)) {
            out << "      \"client_hostname\": \"" << json_escape(*h) << "\",\n";
        }
        if (auto h = resolver.hostname(f.server_ip)) {
            out << "      \"server_hostname\": \"" << json_escape(*h) << "\",\n";
        }
        // server_port is always TCP here -- see write_flow_group_text's own comment above.
        if (auto s = resolver.service_name(f.server_port, "tcp")) {
            out << "      \"server_port_service\": \"" << json_escape(*s) << "\",\n";
        }
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
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << ",\n";
        // How client_ip/server_ip above were decided -- "handshake"/"content"/"port-heuristic", see
        // DirectionSource's own comment (decoder.hpp) and docs/MANUAL.md's ROADMAP item 19. Appended
        // last, after every pre-existing field, so no established JSON-shape test anchored on an
        // earlier field's position in this object needs to change.
        out << "      \"direction_source\": \"" << direction_source_name(f.direction_source) << "\"";
        // Purdue-level labels (Zone::purdue_level) -- appended after direction_source, which was
        // the prior last field in this object; omitted entirely (not emitted as null) when the
        // matched zone didn't declare one, same "annotation, miss adds nothing" convention as the
        // Resolver-derived fields above.
        if (!f.client_zone_purdue_level.empty()) {
            out << ",\n      \"client_zone_purdue_level\": \"" << json_escape(f.client_zone_purdue_level) << "\"";
        }
        if (!f.server_zone_purdue_level.empty()) {
            out << ",\n      \"server_zone_purdue_level\": \"" << json_escape(f.server_zone_purdue_level) << "\"";
        }
        out << "\n";
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
        // OUI vendor annotations only -- no IP/port exists on an L2 flow, so no hostname/service-name
        // equivalent applies here (see write_ethernet_flow_group_text's own comment). Omitted
        // entirely on a lookup miss or when --oui was not given, never emitted as null, same convention as above.
        if (auto v = resolver.oui_vendor(f.mac_a)) {
            out << "      \"mac_a_vendor\": \"" << json_escape(*v) << "\",\n";
        }
        if (auto v = resolver.oui_vendor(f.mac_b)) {
            out << "      \"mac_b_vendor\": \"" << json_escape(*v) << "\",\n";
        }
        out << "      \"has_vlan_tag\": " << (f.has_vlan_tag ? "true" : "false") << ",\n";
        out << "      \"vlan_id\": " << (f.has_vlan_tag ? std::to_string(f.vlan_id) : std::string("null")) << ",\n";
        out << "      \"vlan_zone\": \"" << json_escape(f.vlan_zone) << "\",\n";
        out << "      \"packet_count\": " << f.packet_count << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\""));
        // Appended after 'reason' (the prior last field in this object), same omit-on-miss
        // convention as client_zone_purdue_level/server_zone_purdue_level above.
        if (!f.vlan_zone_purdue_level.empty()) {
            out << ",\n      \"vlan_zone_purdue_level\": \"" << json_escape(f.vlan_zone_purdue_level) << "\"";
        }
        // The new true-last field (Phase 5, see policy.hpp's Conduit::from_macs comment) -- the
        // actual transmitting MAC this flow was first observed from, what Conduit::from_macs is
        // checked against; always present (never omitted), unlike the purdue-level field above,
        // since every Ethernet flow has a source MAC by construction.
        out << ",\n      \"src_mac\": \"" << json_escape(f.src_mac) << "\"";
        if (auto v = resolver.oui_vendor(f.src_mac)) {
            out << ",\n      \"src_mac_vendor\": \"" << json_escape(*v) << "\"";
        }
        out << "\n";
        out << "    }" << (i + 1 < report.ethernet_flows.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"unexercised_conduits\": [";
    for (size_t i = 0; i < report.unexercised_conduits.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << json_escape(report.unexercised_conduits[i]) << "\"";
    }
    out << "],\n";

    // "IT protocols an OT auditor flags" (ROADMAP item 18) -- see PolicyReport::notable_protocols'
    // own comment for why this is always populated, independent of "compliant"/every verdict above.
    // Appended last, after every pre-existing field (unexercised_conduits was the prior last field),
    // the same "no established JSON-shape test anchored on an earlier field needs to change"
    // convention every earlier addition to this schema already followed (see direction_source's own
    // comment above, and asset_inventory.cpp's write_inventory_report_json for the identical rule
    // applied there for this same feature).
    out << "  \"notable_protocols\": [\n";
    for (size_t i = 0; i < report.notable_protocols.size(); ++i) {
        const NotableProtocolFinding& f = report.notable_protocols[i];
        out << "    {\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"tier\": \"" << json_escape(f.tier) << "\",\n";
        if (f.has_ip) {
            out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
            out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
            if (auto h = resolver.hostname(f.client_ip)) {
                out << "      \"client_hostname\": \"" << json_escape(*h) << "\",\n";
            }
            if (auto h = resolver.hostname(f.server_ip)) {
                out << "      \"server_hostname\": \"" << json_escape(*h) << "\",\n";
            }
        } else {
            out << "      \"mac_a\": \"" << json_escape(f.mac_a) << "\",\n";
            out << "      \"mac_b\": \"" << json_escape(f.mac_b) << "\",\n";
            if (auto v = resolver.oui_vendor(f.mac_a)) {
                out << "      \"mac_a_vendor\": \"" << json_escape(*v) << "\",\n";
            }
            if (auto v = resolver.oui_vendor(f.mac_b)) {
                out << "      \"mac_b_vendor\": \"" << json_escape(*v) << "\",\n";
            }
        }
        out << "      \"port\": " << (f.has_port ? std::to_string(f.port) : std::string("null")) << ",\n";
        if (f.has_port) {
            if (auto s = resolver.service_name(f.port, f.is_tcp ? "tcp" : "udp")) {
                out << "      \"port_service\": \"" << json_escape(*s) << "\",\n";
            }
        }
        out << "      \"direction_known\": " << (f.direction_known ? "true" : "false") << ",\n";
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }" << (i + 1 < report.notable_protocols.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // "IT-OT CROSSING CONDUITS" -- see write_idmz_conduits_text's own comment (this function's text
    // counterpart) for what this is and how "exercised" is derived. Always present as an array,
    // empty when the policy declares no idmz-typed conduit, so a policy that never uses this
    // feature gets one more (empty) field, same posture ethernet_flows took when it was new.
    std::vector<const Conduit*> idmz_conduits;
    for (const auto& c : policy.conduits) {
        if (c.conduit_type == "idmz") idmz_conduits.push_back(&c);
    }
    out << "  \"idmz_conduits\": [\n";
    for (size_t i = 0; i < idmz_conduits.size(); ++i) {
        const Conduit* c = idmz_conduits[i];
        bool exercised = std::find(report.unexercised_conduits.begin(), report.unexercised_conduits.end(),
                                    c->name) == report.unexercised_conduits.end();
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(c->name) << "\",\n";
        out << "      \"exercised\": " << (exercised ? "true" : "false") << "\n";
        out << "    }" << (i + 1 < idmz_conduits.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // BACnet/IP and/or CIP I/O flows -- see UdpFlowReport's own comment. Appended last, after every
    // pre-existing field (idmz_conduits was the prior last field) -- always present as an array,
    // empty when the policy never opts in (see Policy::has_udp_eligible_conduit), so a policy that
    // never uses this feature gets one more (empty) field, same posture idmz_conduits/ethernet_flows
    // took when each was new.
    out << "  \"udp_flows\": [\n";
    for (size_t i = 0; i < report.udp_flows.size(); ++i) {
        const UdpFlowReport& f = report.udp_flows[i];
        out << "    {\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        // Same annotation/omission conventions write_policy_report_json's own 'flows' array uses --
        // see that block's comment.
        out << "      \"client_mac\": " << (f.has_mac ? ("\"" + json_escape(f.client_mac) + "\"") : "null") << ",\n";
        out << "      \"server_mac\": " << (f.has_mac ? ("\"" + json_escape(f.server_mac) + "\"") : "null") << ",\n";
        if (f.has_mac) {
            if (auto v = resolver.oui_vendor(f.client_mac)) {
                out << "      \"client_mac_vendor\": \"" << json_escape(*v) << "\",\n";
            }
            if (auto v = resolver.oui_vendor(f.server_mac)) {
                out << "      \"server_mac_vendor\": \"" << json_escape(*v) << "\",\n";
            }
        }
        if (auto h = resolver.hostname(f.client_ip)) {
            out << "      \"client_hostname\": \"" << json_escape(*h) << "\",\n";
        }
        if (auto h = resolver.hostname(f.server_ip)) {
            out << "      \"server_hostname\": \"" << json_escape(*h) << "\",\n";
        }
        // server_port is always UDP here -- see write_udp_flow_group_text's own comment above.
        if (auto s = resolver.service_name(f.server_port, "udp")) {
            out << "      \"server_port_service\": \"" << json_escape(*s) << "\",\n";
        }
        out << "      \"client_zone\": \"" << json_escape(f.client_zone) << "\",\n";
        out << "      \"server_zone\": \"" << json_escape(f.server_zone) << "\",\n";
        out << "      \"observed_functions\": [";
        for (size_t j = 0; j < f.observed_functions.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(f.observed_functions[j]) << "\"";
        }
        out << "],\n";
        out << "      \"packet_count\": " << f.packet_count << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << ",\n";
        out << "      \"direction_source\": \"" << direction_source_name(f.direction_source) << "\"";
        if (!f.client_zone_purdue_level.empty()) {
            out << ",\n      \"client_zone_purdue_level\": \"" << json_escape(f.client_zone_purdue_level) << "\"";
        }
        if (!f.server_zone_purdue_level.empty()) {
            out << ",\n      \"server_zone_purdue_level\": \"" << json_escape(f.server_zone_purdue_level) << "\"";
        }
        out << "\n";
        out << "    }" << (i + 1 < report.udp_flows.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // Multi-homed assets (Phase 6) -- see MultiHomedAssetFinding's own comment. Appended last,
    // after every pre-existing field (udp_flows was the prior last field) -- always present as an
    // array, empty when the policy declares no 'assets:' at all, so a policy that never uses this
    // feature gets one more (empty) field, same posture every earlier addition to this schema took
    // when it was new.
    out << "  \"multi_homed_assets\": [\n";
    for (size_t i = 0; i < report.multi_homed_assets.size(); ++i) {
        const MultiHomedAssetFinding& f = report.multi_homed_assets[i];
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(f.name) << "\",\n";
        out << "      \"role\": " << (f.role.empty() ? "null" : ("\"" + json_escape(f.role) + "\"")) << ",\n";
        out << "      \"ips\": [";
        for (size_t j = 0; j < f.ips.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(f.ips[j]) << "\"";
        }
        out << "],\n";
        out << "      \"zones\": [";
        for (size_t j = 0; j < f.zones.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(f.zones[j]) << "\"";
        }
        out << "],\n";
        out << "      \"zone_pairs\": [";
        for (size_t j = 0; j < f.zone_pairs.size(); ++j) {
            const AssetZonePair& p = f.zone_pairs[j];
            if (j) out << ", ";
            out << "{\"zone_a\": \"" << json_escape(p.zone_a) << "\", \"zone_b\": \"" << json_escape(p.zone_b)
                << "\", \"covered\": " << (p.covered ? "true" : "false") << "}";
        }
        out << "],\n";
        out << "      \"flagged\": " << (f.flagged ? "true" : "false") << "\n";
        out << "    }" << (i + 1 < report.multi_homed_assets.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // Jump-host flows (Phase 6) -- see JumpHostFlowFinding's own comment. Appended last, after every
    // pre-existing field (multi_homed_assets was the prior last field) -- always present as an
    // array, empty when the policy declares no 'role: \"jump_host\"' asset (or one is declared but
    // no observed flow ever touched it), so a policy that never uses this feature gets one more
    // (empty) field.
    out << "  \"jump_host_flows\": [\n";
    for (size_t i = 0; i < report.jump_host_flows.size(); ++i) {
        const JumpHostFlowFinding& f = report.jump_host_flows[i];
        out << "    {\n";
        out << "      \"asset_name\": \"" << json_escape(f.asset_name) << "\",\n";
        out << "      \"jump_host_ip\": \"" << json_escape(f.jump_host_ip) << "\",\n";
        out << "      \"jump_host_is_client\": " << (f.jump_host_is_client ? "true" : "false") << ",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"is_udp\": " << (f.is_udp ? "true" : "false") << ",\n";
        out << "      \"verdict\": \"" << verdict_name(f.verdict) << "\",\n";
        out << "      \"matched_conduit\": " << (f.matched_conduit.empty() ? "null" : ("\"" + json_escape(f.matched_conduit) + "\"")) << ",\n";
        out << "      \"reason\": " << (f.reason.empty() ? "null" : ("\"" + json_escape(f.reason) + "\"")) << "\n";
        out << "    }" << (i + 1 < report.jump_host_flows.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

namespace {

constexpr int kPolicyViolationCefSeverity = 8;  // CEF's own High band -- see
                                                 // write_policy_report_cef's own doc comment
                                                 // (policy_engine.hpp) for the full rationale.
constexpr const char* kPolicyViolationEventClassId = "policy-violation";
constexpr const char* kPolicyViolationName = "Zone/Conduit Policy Violation";

std::vector<std::pair<std::string, std::string>> flow_violation_extension_fields(const FlowReport& f) {
    std::vector<std::pair<std::string, std::string>> fields;
    fields.emplace_back("src", f.client_ip);
    fields.emplace_back("dst", f.server_ip);
    if (f.server_port != 0) fields.emplace_back("dpt", std::to_string(f.server_port));
    fields.emplace_back("proto", join_comma(f.protocols));
    fields.emplace_back("cat", kPolicyViolationEventClassId);
    fields.emplace_back("msg", f.reason);
    fields.emplace_back("cs1Label", "Client Zone");
    fields.emplace_back("cs1", f.client_zone);
    fields.emplace_back("cs2Label", "Server Zone");
    fields.emplace_back("cs2", f.server_zone);
    fields.emplace_back("cnt", std::to_string(f.packet_count));
    return fields;
}

std::vector<std::pair<std::string, std::string>> udp_flow_violation_extension_fields(const UdpFlowReport& f) {
    std::vector<std::pair<std::string, std::string>> fields;
    fields.emplace_back("src", f.client_ip);
    fields.emplace_back("dst", f.server_ip);
    if (f.server_port != 0) fields.emplace_back("dpt", std::to_string(f.server_port));
    fields.emplace_back("proto", f.protocol);
    fields.emplace_back("cat", kPolicyViolationEventClassId);
    fields.emplace_back("msg", f.reason);
    fields.emplace_back("cs1Label", "Client Zone");
    fields.emplace_back("cs1", f.client_zone);
    fields.emplace_back("cs2Label", "Server Zone");
    fields.emplace_back("cs2", f.server_zone);
    fields.emplace_back("cnt", std::to_string(f.packet_count));
    return fields;
}

std::vector<std::pair<std::string, std::string>> ethernet_flow_violation_extension_fields(
    const EthernetFlowReport& f) {
    std::vector<std::pair<std::string, std::string>> fields;
    // smac/dmac: CEF's own standard dictionary MAC-address keys. src_mac is this flow's own known
    // transmitting side (see EthernetFlowReport::src_mac's own comment); the other member of the
    // canonicalized mac_a/mac_b pair is its peer -- see write_policy_report_cef's own doc comment.
    fields.emplace_back("smac", f.src_mac);
    fields.emplace_back("dmac", f.src_mac == f.mac_a ? f.mac_b : f.mac_a);
    fields.emplace_back("proto", f.protocol);
    fields.emplace_back("cat", kPolicyViolationEventClassId);
    fields.emplace_back("msg", f.reason);
    fields.emplace_back("cs1Label", "VLAN Zone");
    fields.emplace_back("cs1", f.vlan_zone);
    fields.emplace_back("cnt", std::to_string(f.packet_count));
    return fields;
}

}  // namespace

void write_policy_report_cef(std::ostream& out, const PolicyReport& report) {
    for (const auto& f : report.flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        out << render_cef_line("conduitscope-policy", kPolicyViolationEventClassId, kPolicyViolationName,
                                kPolicyViolationCefSeverity, flow_violation_extension_fields(f))
            << "\n";
    }
    for (const auto& f : report.ethernet_flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        out << render_cef_line("conduitscope-policy", kPolicyViolationEventClassId, kPolicyViolationName,
                                kPolicyViolationCefSeverity, ethernet_flow_violation_extension_fields(f))
            << "\n";
    }
    for (const auto& f : report.udp_flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        out << render_cef_line("conduitscope-policy", kPolicyViolationEventClassId, kPolicyViolationName,
                                kPolicyViolationCefSeverity, udp_flow_violation_extension_fields(f))
            << "\n";
    }
}

void write_policy_report_leef(std::ostream& out, const PolicyReport& report) {
    for (const auto& f : report.flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        auto fields = flow_violation_extension_fields(f);
        fields.emplace_back("sev", std::to_string(kPolicyViolationCefSeverity));
        out << render_leef_line("conduitscope-policy", kPolicyViolationEventClassId, fields) << "\n";
    }
    for (const auto& f : report.ethernet_flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        auto fields = ethernet_flow_violation_extension_fields(f);
        fields.emplace_back("sev", std::to_string(kPolicyViolationCefSeverity));
        out << render_leef_line("conduitscope-policy", kPolicyViolationEventClassId, fields) << "\n";
    }
    for (const auto& f : report.udp_flows) {
        if (f.verdict != FlowVerdict::Violation) continue;
        auto fields = udp_flow_violation_extension_fields(f);
        fields.emplace_back("sev", std::to_string(kPolicyViolationCefSeverity));
        out << render_leef_line("conduitscope-policy", kPolicyViolationEventClassId, fields) << "\n";
    }
}

void write_policy_report_syslog(std::ostream& out, const PolicyReport& report) {
    auto emit = [&out](const std::vector<std::pair<std::string, std::string>>& fields) {
        std::string cef_payload = render_cef_line("conduitscope-policy", kPolicyViolationEventClassId,
                                                    kPolicyViolationName, kPolicyViolationCefSeverity, fields);
        out << render_rfc5424_line(kPolicyViolationCefSeverity, "policy", cef_payload) << "\n";
    };
    for (const auto& f : report.flows) {
        if (f.verdict == FlowVerdict::Violation) emit(flow_violation_extension_fields(f));
    }
    for (const auto& f : report.ethernet_flows) {
        if (f.verdict == FlowVerdict::Violation) emit(ethernet_flow_violation_extension_fields(f));
    }
    for (const auto& f : report.udp_flows) {
        if (f.verdict == FlowVerdict::Violation) emit(udp_flow_violation_extension_fields(f));
    }
}

}  // namespace conduitscope
