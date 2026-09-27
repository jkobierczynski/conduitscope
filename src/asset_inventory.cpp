// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/asset_inventory.hpp"

#include <algorithm>
#include <cstdio>
#include <iomanip>
#include <map>
#include <ostream>
#include <sstream>
#include <tuple>

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
#include "conduitscope/time_format.hpp"

namespace conduitscope {

namespace {

// Undirected canonical key for a TCP session's 4-tuple -- identical in spirit to
// policy_engine.cpp's own session_key (kept separate rather than shared, same "each engine stays
// self-contained" convention noted in this file's own comments below).
std::string tcp_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b, uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

std::string edge_key(const std::string& protocol, const std::string& client_ip, const std::string& server_ip,
                      uint16_t server_port) {
    return protocol + "|" + client_ip + "->" + server_ip + ":" + std::to_string(server_port);
}

// Phase 7 of Grok gap #2 -- see InventoryEdge::top_touched_addresses' own comment
// (asset_inventory.hpp) for the full per-protocol touched-address key design; this function
// implements exactly the modbus bullet there. Returns "" for a function code with no address
// concept at all (an exception response, Diagnostics, Report Server ID, or any function code
// outside the four read/write-multiple families this maps) -- caller skips an empty key, same "no
// signal, don't fabricate one" convention as function_name's own empty-string handling just above
// in observe().
std::string modbus_touch_key(uint8_t function_code, uint16_t start_address, uint16_t quantity) {
    uint8_t base = function_code & 0x7F;  // strip the 0x80 exception bit -- meaningless for addressing
    std::string kind;
    switch (base) {
        case 0x01:  // Read Coils
        case 0x0F:  // Write Multiple Coils
            kind = "coil";
            break;
        case 0x02:  // Read Discrete Inputs
            kind = "discrete";
            break;
        case 0x03:  // Read Holding Registers
        case 0x10:  // Write Multiple Registers
            kind = "hreg";
            break;
        case 0x04:  // Read Input Registers
            kind = "ireg";
            break;
        default:
            return "";
    }
    std::ostringstream oss;
    oss << kind << ":" << std::setw(5) << std::setfill('0') << (static_cast<uint32_t>(start_address) + 1);
    if (quantity > 1) {
        oss << "-" << std::setw(5) << std::setfill('0')
            << (static_cast<uint32_t>(start_address) + quantity);
    }
    return oss.str();
}

// Phase 7 of Grok gap #2 -- the dnp3 bullet of InventoryEdge::top_touched_addresses' own comment.
// "g{group}v{variation}" is the SAME shorthand src/dnp3.cpp's own summary/dnp3_object_headers
// rendering already establishes (see e.g. the "g" << group << "v" << variation shape at multiple
// sites there) -- reused verbatim here for consistency rather than inventing a new notation.
std::string dnp3_touch_key(const Dnp3ObjectRange& obj) {
    std::ostringstream oss;
    oss << "g" << static_cast<unsigned>(obj.group) << "v" << static_cast<unsigned>(obj.variation);
    if (obj.has_range) {
        oss << " idx " << obj.range_start;
        if (obj.range_stop != obj.range_start) oss << "-" << obj.range_stop;
    }
    return oss.str();
}

// The known ports this feature's TCP-based protocols conventionally use, PLUS the two UDP ports
// (BACNET_UDP_PORT/ENIP_IO_UDP_PORT) -- see AssetInventoryEngine::observe's own doc comment
// (asset_inventory.hpp) for the full priority order this feeds into. On the TCP side this is now
// deliberately IDENTICAL to policy_engine.cpp's own is_known_service_port (MODBUS/DNP3/COTP/
// IEC104/ENIP) -- HART-IP/OPC UA/MMS/MQTT/FF-HSE's own conventional ports are intentionally left
// out, matching that same set, so this engine's client/server guess for a flow always agrees with
// PolicyEngine's own guess for the identical flow (see observe()'s own doc comment in the header).
bool is_known_target_port(uint16_t port, bool is_tcp) {
    if (is_tcp) {
        return port == MODBUS_TCP_PORT || port == DNP3_TCP_PORT || port == COTP_TCP_PORT ||
               port == IEC104_TCP_PORT || port == ENIP_TCP_PORT;
    }
    return port == BACNET_UDP_PORT || port == ENIP_IO_UDP_PORT;
}

// Mirrors policy_engine.cpp's own src_is_client_by_port, widened to take is_tcp so it can also
// serve this feature's two UDP-based ports -- see that function's own comment for the priority
// order this implements (known port on one side and not the other decides; otherwise the lower
// port number is assumed to be the server).
bool src_is_client_by_port(uint16_t src_port, uint16_t dst_port, bool is_tcp) {
    bool src_known = is_known_target_port(src_port, is_tcp);
    bool dst_known = is_known_target_port(dst_port, is_tcp);
    if (dst_known && !src_known) return true;
    if (src_known && !dst_known) return false;
    return src_port > dst_port;
}

// Authority ranking for DirectionSource, lowest (most authoritative) first -- Handshake, then
// Content, then PortHeuristic. Used only to merge an InventoryEdge's own direction_source across
// however many distinct TCP sessions (or, for BACnet, individual packets) contribute to it: unlike
// PolicyEngine's FlowReport (one 4-tuple, one FlowState, one direction decision that only ever
// upgrades toward Handshake), one InventoryEdge deliberately aggregates every session between the
// same client/server pair (see InventoryEdge's own comment) -- e.g. a client that reconnects with a
// new ephemeral port mid-capture may have its first session's direction settled by a captured
// SYN/SYN-ACK and a later reconnect's direction only ever settled by the port-heuristic fallback
// (its own handshake never captured). Keeping the most authoritative tier ever observed across all
// of them, never downgrading once a stronger one is seen, mirrors FlowState's own "never downgrade"
// upgrade rule at the per-edge level. Handshake and Content never actually compete for the same
// edge in this codebase today (Content only ever arises for BACnet, which is UDP-only and so never
// shares an edge with a Handshake-eligible TCP session), but the full three-way ranking is kept
// here rather than a two-way PortHeuristic/other check, matching DirectionSource's own "in order of
// authority" definition (decoder.hpp) exactly rather than only the cases that happen to matter yet.
int direction_source_rank(DirectionSource s) {
    switch (s) {
        case DirectionSource::Handshake: return 0;
        case DirectionSource::Content: return 1;
        case DirectionSource::PortHeuristic: return 2;
    }
    return 2;
}

// A deliberately pragmatic, NOT subnet-mask-aware heuristic for "this address is not a real device
// to inventory, it's a broadcast/multicast destination" -- see AssetInventoryEngine::observe's own
// doc comment (asset_inventory.hpp) for why this matters (BACnet's Who-Is/I-Am discovery traffic is
// routinely broadcast). Catches the limited broadcast address (255.255.255.255), all of IPv4
// multicast (224.0.0.0/4), and an address ending in .255 -- the conventional directed-broadcast
// address for the overwhelmingly common case of a /24-or-wider-host-field subnet, even though this
// is a guess, not a calculation: without knowing the network's actual mask (which isn't known until
// AFTER zone inference runs -- a chicken-and-egg problem this heuristic sidesteps entirely), an
// address ending in .255 could theoretically be an ordinary host on a /23 or wider subnet. Given
// this feature's own "first-draft heuristic, not a rigorous calculation" framing throughout, that
// tradeoff is accepted deliberately rather than solved.
bool looks_like_broadcast_or_multicast(const std::string& ip) {
    auto addr = parse_ipv4_string(ip);
    if (!addr) return false;
    uint32_t a = *addr;
    if (a == 0xFFFFFFFFu) return true;
    if ((a >> 24) >= 224 && (a >> 24) <= 239) return true;
    if ((a & 0xFFu) == 0xFFu) return true;
    return false;
}

uint32_t cidr_mask(uint8_t prefix_len) {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFFu;
    return ~uint32_t(0) << (32 - prefix_len);
}

// Deterministic zone name from the network itself, e.g. 192.168.1.0/24 -> "zone_192_168_1_0_24" --
// stable across runs of the same capture (never first-seen-order-dependent), and self-describing
// enough that a human skimming the generated policy YAML or diagram immediately knows which subnet
// each zone means without cross-referencing anything else.
std::string zone_name_for(const CidrBlock& block) {
    std::string addr = format_ipv4(block.network);
    for (char& c : addr) {
        if (c == '.') c = '_';
    }
    return "zone_" + addr + "_" + std::to_string(block.prefix_len);
}

// Renders an epoch-seconds timestamp (InventoryAsset::first_seen/last_seen and InventoryEdge's own
// pair) as a readable UTC date/time, reusing time_format.hpp's own `decode --time-format
// absolute-date` renderer rather than inventing a second one. first_ts/prev_ts (Relative/Delta's
// own bookkeeping) are irrelevant to AbsoluteDate, so `ts` is passed for both -- see
// format_timestamp's own comment (time_format.hpp) for why that's safe.
std::string format_epoch_seconds(double ts) {
    return format_timestamp(ts, TimeFormat::AbsoluteDate, TimeOffset{}, ts, ts);
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

AssetInventoryEngine::AssetInventoryEngine(uint8_t zone_prefix_len) : zone_prefix_len_(zone_prefix_len) {}

void AssetInventoryEngine::update_asset(const std::string& ip, const DecodedPacket& dp, const std::string& protocol,
                                         bool is_client_role) {
    auto it = assets_.find(ip);
    if (it == assets_.end()) {
        asset_order_.push_back(ip);
        it = assets_.emplace(ip, AssetState{}).first;
    }
    AssetState& a = it->second;
    ++a.packet_count;
    a.protocols.insert(protocol);
    if (is_client_role) a.ever_client = true;
    else a.ever_server = true;
    if (!a.has_mac && dp.has_ethernet) {
        a.has_mac = true;
        a.mac = (ip == dp.src_ip) ? dp.src_mac : dp.dst_mac;
    }
    if (!a.has_timestamp) {
        a.has_timestamp = true;
        a.first_seen = dp.timestamp;
        a.last_seen = dp.timestamp;
    } else {
        a.first_seen = std::min(a.first_seen, dp.timestamp);
        a.last_seen = std::max(a.last_seen, dp.timestamp);
    }
}

void AssetInventoryEngine::update_identity(const std::string& ip, const std::string& vendor,
                                            const std::string& product, const std::string& firmware_revision,
                                            const std::string& serial_number,
                                            const std::string& security_posture,
                                            const std::string& plant_identification) {
    auto it = assets_.find(ip);
    if (it == assets_.end()) return;  // see this method's own comment (asset_inventory.hpp)
    AssetState& a = it->second;
    if (a.vendor.empty()) a.vendor = vendor;
    if (a.product.empty()) a.product = product;
    if (a.firmware_revision.empty()) a.firmware_revision = firmware_revision;
    if (a.serial_number.empty()) a.serial_number = serial_number;
    if (a.security_posture.empty()) a.security_posture = security_posture;
    if (a.plant_identification.empty()) a.plant_identification = plant_identification;
}

void AssetInventoryEngine::record_notable_protocol(const std::string& key, const std::string& protocol,
                                                     const std::string& tier, bool has_ip,
                                                     const std::string& client_ip, const std::string& server_ip,
                                                     const std::string& mac_a, const std::string& mac_b,
                                                     bool has_port, bool is_tcp, uint16_t port) {
    auto it = notable_protocols_.find(key);
    if (it == notable_protocols_.end()) {
        NotableProtocolState st;
        st.protocol = protocol;
        st.tier = tier;
        st.has_ip = has_ip;
        st.client_ip = client_ip;
        st.server_ip = server_ip;
        st.mac_a = mac_a;
        st.mac_b = mac_b;
        st.has_port = has_port;
        st.is_tcp = is_tcp;
        st.port = port;
        notable_protocol_order_.push_back(key);
        it = notable_protocols_.emplace(key, std::move(st)).first;
    }
    ++it->second.packet_count;
}

void AssetInventoryEngine::observe(const DecodedPacket& dp) {
    ++total_packets_;

    // "IT protocols an OT auditor flags" (ROADMAP item 18) -- checked first, unconditionally,
    // mirroring PolicyEngine::observe's own identical placement -- see this method's own doc comment
    // (asset_inventory.hpp) for why this never disturbs skipped_packets_ or the eleven-protocol
    // asset/edge model below.
    auto notable_tier = notable_it_protocol_tier(dp.protocol);

    if (!dp.has_ip || (!dp.has_tcp && !dp.has_udp)) {
        if (notable_tier) {
            if (!dp.has_ip) {
                // eapol/pppoe/mpls -- the three EtherType-keyed protocols in this family -- keyed by
                // canonical MAC pair, the same no-direction convention
                // PolicyEngine::EthernetFlowReport::mac_a/mac_b already uses for PROFINET/GOOSE/SV/
                // EtherCAT.
                if (dp.has_ethernet) {
                    std::string mac_a = (dp.src_mac < dp.dst_mac) ? dp.src_mac : dp.dst_mac;
                    std::string mac_b = (dp.src_mac < dp.dst_mac) ? dp.dst_mac : dp.src_mac;
                    std::string key = "eth:" + *notable_tier + ":" + dp.protocol + ":" +
                                       ((dp.src_mac < dp.dst_mac) ? (dp.src_mac + "<->" + dp.dst_mac)
                                                                    : (dp.dst_mac + "<->" + dp.src_mac));
                    record_notable_protocol(key, dp.protocol, *notable_tier, /*has_ip=*/false, "", "", mac_a, mac_b,
                                             /*has_port=*/false, /*is_tcp=*/false, 0);
                }
            } else {
                // An IP-protocol-number-keyed Tier 5 tunnel (gre/esp/ah/ip-in-ip/6in4/l2tp's direct-
                // IP form) -- has_ip but neither has_tcp nor has_udp, so there's no port and no
                // session/handshake to decide direction from; recorded as a canonical (smaller-
                // address-first) pair rather than a client/server guess, same reasoning
                // NotableProtocolFinding's own comment gives for this identical shape in
                // policy_engine.cpp.
                std::string a = (dp.src_ip < dp.dst_ip) ? dp.src_ip : dp.dst_ip;
                std::string b = (dp.src_ip < dp.dst_ip) ? dp.dst_ip : dp.src_ip;
                std::string key = "ip:" + *notable_tier + ":" + dp.protocol + ":" + a + "<->" + b;
                record_notable_protocol(key, dp.protocol, *notable_tier, /*has_ip=*/true, a, b, "", "",
                                         /*has_port=*/false, /*is_tcp=*/false, 0);
            }
        }
        ++skipped_packets_;
        return;
    }

    // Folds a COTP-only session (connection setup with no S7comm payload ever decoded on it) into
    // "s7comm", exactly PolicyEngine::observe's own convention -- see this file's own header
    // comment.
    std::string protocol;
    if (dp.protocol == "modbus") protocol = "modbus";
    else if (dp.protocol == "dnp3") protocol = "dnp3";
    else if (dp.protocol == "s7comm" || dp.protocol == "cotp") protocol = "s7comm";
    else if (dp.protocol == "enip") protocol = "enip";
    else if (dp.protocol == "bacnet") protocol = "bacnet";
    else if (dp.protocol == "iec104") protocol = "iec104";
    else if (dp.protocol == "hartip") {
        // HART-IP rides over either TCP or UDP at the same conventional port (hartip.hpp) -- but
        // PolicyEngine::observe only ever evaluates has_tcp packets, so a UDP HART-IP conduit
        // inferred here could never be checked by `policy validate`. See this file's own header
        // comment for the full rationale; a UDP HART-IP packet is simply skipped, same as any other
        // unrecognized packet.
        if (!dp.has_tcp) {
            ++skipped_packets_;
            return;
        }
        protocol = "hartip";
    } else if (dp.protocol == "opcua") protocol = "opcua";
    else if (dp.protocol == "mms") protocol = "mms";
    else if (dp.protocol == "mqtt") protocol = "mqtt";
    else if (dp.protocol == "s7comm-plus") {
        // A different, independent application protocol from classic S7comm above despite sharing
        // its TCP/102/TPKT/COTP transport -- see this file's own header comment. Flat-field on
        // DecodedPacket (dp.s7plus_*), not carried via dp.result -- see decoder.hpp's own comment
        // for why. Not one of PolicyEngine::observe's own ten protocols (no policy-engine zoning
        // counterpart yet), but Grok gap #2 explicitly asked for it here regardless.
        protocol = "s7comm-plus";
    } else if (dp.protocol == "ffhse") {
        // Same reasoning as hartip above -- FF-HSE is decodable over TCP (decoder.cpp's own
        // opportunistic Auto-mode dispatch tries it there too) but is, in real deployments,
        // fundamentally a UDP protocol (ffhse.hpp), and PolicyEngine::observe never evaluates UDP.
        // In practice this means FF-HSE will almost never appear in an inventory report at all.
        if (!dp.has_tcp) {
            ++skipped_packets_;
            return;
        }
        protocol = "ffhse";
    } else {
        if (notable_tier) {
            // A TCP- or UDP-based notable protocol (every one of this family except eapol/pppoe/mpls/
            // the IP-protocol-number-keyed Tier 5 tunnels, both handled above) -- direction is always
            // the plain port-number heuristic (see InventoryNotableProtocol's own comment for why),
            // reusing this file's own src_is_client_by_port rather than the session/handshake-based
            // tcp_sessions_ machinery below, which only ever tracks this feature's own eleven
            // recognized protocols.
            bool src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port, dp.has_tcp);
            std::string client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            std::string server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            uint16_t server_port = src_is_client ? dp.dst_port : dp.src_port;
            std::string key = "port:" + *notable_tier + ":" + dp.protocol + ":" +
                               tcp_session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
            record_notable_protocol(key, dp.protocol, *notable_tier, /*has_ip=*/true, client_ip, server_ip, "", "",
                                     /*has_port=*/true, dp.has_tcp, server_port);
        }
        ++skipped_packets_;
        return;
    }

    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    DirectionSource direction_source = DirectionSource::PortHeuristic;

    if (dp.has_tcp) {
        std::string skey = tcp_session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
        bool is_syn = dp.tcp_flags == "SYN";
        bool is_syn_ack = dp.tcp_flags.rfind("SYN,ACK", 0) == 0;

        auto it = tcp_sessions_.find(skey);
        if (it == tcp_sessions_.end()) {
            TcpSessionState st;
            bool src_is_client;
            if (is_syn) {
                src_is_client = true;
                st.initiator_known = true;
                st.direction_source = DirectionSource::Handshake;
            } else if (is_syn_ack) {
                src_is_client = false;
                st.initiator_known = true;
                st.direction_source = DirectionSource::Handshake;
            } else {
                src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port, /*is_tcp=*/true);
                st.direction_source = DirectionSource::PortHeuristic;
            }
            st.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            st.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            st.server_port = src_is_client ? dp.dst_port : dp.src_port;
            it = tcp_sessions_.emplace(skey, std::move(st)).first;
        } else if (!it->second.initiator_known && (is_syn || is_syn_ack)) {
            bool src_is_client = is_syn;
            it->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            it->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            it->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
            it->second.initiator_known = true;
            it->second.direction_source = DirectionSource::Handshake;
        }
        client_ip = it->second.client_ip;
        server_ip = it->second.server_ip;
        server_port = it->second.server_port;
        direction_source = it->second.direction_source;
    } else {
        // UDP: no session, no handshake -- see observe()'s own doc comment (asset_inventory.hpp)
        // for the full per-protocol reasoning.
        bool src_is_client;
        // Zero-flat-field migration (extra-reader batch): dp.bacnet_has_apdu/dp.bacnet_apdu_type
        // are gone -- read from the BacnetFrame on dp.result instead (dp.result->has_npdu &&
        // dp.result->npdu.has_apdu is the same condition the old flat dp.bacnet_has_apdu captured
        // -- see BacnetNpdu::has_apdu's own invariant comment in bacnet.hpp).
        if (protocol == "bacnet" && dp.result && dp.result->as<BacnetFrame>().has_npdu &&
            dp.result->as<BacnetFrame>().npdu.has_apdu &&
            !dp.result->as<BacnetFrame>().npdu.apdu.pdu_type_name.empty()) {
            const std::string& apdu_type = dp.result->as<BacnetFrame>().npdu.apdu.pdu_type_name;
            src_is_client = apdu_type == "Confirmed-Request" || apdu_type == "Unconfirmed-Request";
            direction_source = DirectionSource::Content;
        } else {
            src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port, /*is_tcp=*/false);
            direction_source = DirectionSource::PortHeuristic;
        }
        client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        server_port = src_is_client ? dp.dst_port : dp.src_port;
    }

    std::string function_name;
    if (protocol == "modbus" && dp.result && !dp.result->as<ModbusFrame>().function_name.empty()) {
        function_name = dp.result->as<ModbusFrame>().function_name;
    } else if (protocol == "dnp3" && dp.result && dp.result->as<Dnp3Result>().dnp3_has_function &&
               !dp.result->as<Dnp3Result>().dnp3_function_name.empty()) {
        function_name = dp.result->as<Dnp3Result>().dnp3_function_name;
    } else if (protocol == "s7comm" && dp.protocol == "s7comm" && dp.result &&
               dp.result->as<S7CommResult>().has_function &&
               !dp.result->as<S7CommResult>().function_name.empty()) {
        function_name = dp.result->as<S7CommResult>().function_name;
    } else if (protocol == "enip" && dp.has_tcp && dp.result &&
               dp.result->as<EnipResult>().first.has_cip &&
               !dp.result->as<EnipResult>().first.cip.service_name.empty()) {
        function_name = dp.result->as<EnipResult>().first.cip.service_name;
    } else if (protocol == "bacnet" && dp.result && dp.result->as<BacnetFrame>().has_npdu &&
               dp.result->as<BacnetFrame>().npdu.has_apdu &&
               !dp.result->as<BacnetFrame>().npdu.apdu.service_choice_name.empty()) {
        function_name = dp.result->as<BacnetFrame>().npdu.apdu.service_choice_name;
    } else if (protocol == "iec104" && dp.result && dp.result->as<Iec104Result>().iec104_has_asdu &&
               !dp.result->as<Iec104Result>().iec104_asdu_type_short_name.empty()) {
        function_name = dp.result->as<Iec104Result>().iec104_asdu_type_short_name;
    } else if (protocol == "hartip" && dp.result && !dp.result->as<HartIpResult>().first.message_type_name.empty()) {
        // HartIpFrame::message_type_name ("Request"/"Response"/"Publish"/"Error"/"NAK") is always
        // set once a "hartip" packet decodes at all -- see hartip.hpp -- same "no separate guard
        // needed" shape PolicyEngine::observe documents for this same field.
        function_name = dp.result->as<HartIpResult>().first.message_type_name;
    } else if (protocol == "opcua" && dp.result && dp.result->as<OpcUaResult>().first.service_recognized &&
               !dp.result->as<OpcUaResult>().first.service_name.empty()) {
        function_name = dp.result->as<OpcUaResult>().first.service_name;
    } else if (protocol == "mms" && dp.result && dp.result->as<MmsFrame>().service_recognized &&
               !dp.result->as<MmsFrame>().service_name.empty()) {
        function_name = dp.result->as<MmsFrame>().service_name;
    } else if (protocol == "mqtt" && dp.result && !dp.result->as<MqttResult>().first.packet_type_name.empty()) {
        function_name = dp.result->as<MqttResult>().first.packet_type_name;
    } else if (protocol == "ffhse" && dp.result && !dp.result->as<FfhseResult>().first.message_name.empty()) {
        function_name = dp.result->as<FfhseResult>().first.message_name;
    } else if (protocol == "s7comm-plus" && dp.s7plus_has_function && !dp.s7plus_function_name.empty()) {
        function_name = dp.s7plus_function_name;
    }

    // Tag/point/DB touch summarization (Phase 7 of Grok gap #2) -- see
    // InventoryEdge::top_touched_addresses' own comment (asset_inventory.hpp) for the full
    // per-protocol design and exactly which five of this feature's twelve protocols are wired in
    // here. Every address this packet's own already-decoded structures name is collected into
    // `touched_addresses`; the edge-update block below folds each one into that edge's capped
    // internal touch-count map. A packet from an out-of-scope protocol, or one whose payload didn't
    // carry a recognized addressable request/item this pass, simply contributes nothing (the vector
    // stays empty) -- same "no signal, don't fabricate one" posture as function_name's own
    // empty-string default above.
    std::vector<std::string> touched_addresses;
    if (protocol == "modbus" && dp.result) {
        const ModbusFrame& mb = dp.result->as<ModbusFrame>();
        if (mb.start_address.has_value()) {
            std::string key =
                modbus_touch_key(mb.function_code, *mb.start_address, mb.quantity.value_or(1));
            if (!key.empty()) touched_addresses.push_back(std::move(key));
        }
    } else if (protocol == "s7comm" && dp.protocol == "s7comm" && dp.result) {
        // Read Var/Write Var Job (request) only -- S7CommResult::items is empty on the Ack_Data
        // (response) side, see that field's own comment (s7comm.hpp).
        for (const auto& item : dp.result->as<S7CommResult>().items) {
            if (!item.syntax_supported || item.tag.empty()) continue;
            touched_addresses.push_back(item.is_experimental ? ("experimental:" + item.tag) : item.tag);
        }
    } else if (protocol == "dnp3" && dp.result) {
        for (const auto& obj : dp.result->as<Dnp3Result>().dnp3_objects) {
            touched_addresses.push_back(dnp3_touch_key(obj));
        }
    } else if (protocol == "iec104" && dp.result) {
        for (uint32_t ioa : dp.result->as<Iec104Result>().iec104_object_ioas) {
            touched_addresses.push_back("ioa=" + std::to_string(ioa));
        }
    } else if (protocol == "enip" && dp.has_tcp && dp.result && dp.result->as<EnipResult>().first.has_cip) {
        // Explicit messaging only -- never CIP I/O implicit messaging (which shares this same
        // protocol=="enip" string but has no CipPath concept at all, see this file's own header
        // comment). is_symbolic gates out class/instance/attribute-addressed CIP (generic object
        // access, not a named tag -- see InventoryEdge::top_touched_addresses' own comment for why).
        const CipMessage& cip = dp.result->as<EnipResult>().first.cip;
        if (cip.path.is_symbolic && !cip.path.summary.empty()) {
            touched_addresses.push_back(cip.path.summary);
        }
    } else if (protocol == "mqtt" && dp.result) {
        const MqttMessage& mq = dp.result->as<MqttResult>().first;
        if (mq.packet_type_name == "PUBLISH" && !mq.topic.empty()) {
            touched_addresses.push_back(mq.topic);
        }
    }

    // See looks_like_broadcast_or_multicast's own comment, and observe()'s doc comment in
    // asset_inventory.hpp, for why a broadcast/multicast side is never turned into an asset or an
    // edge -- its non-broadcast counterpart (if any) still is.
    bool client_is_bcast = looks_like_broadcast_or_multicast(client_ip);
    bool server_is_bcast = looks_like_broadcast_or_multicast(server_ip);
    if (!client_is_bcast) update_asset(client_ip, dp, protocol, /*is_client_role=*/true);
    if (!server_is_bcast) update_asset(server_ip, dp, protocol, /*is_client_role=*/false);

    // Passively-inferred device identity (Grok gap #2) -- EtherNet/IP CIP Identity, the only
    // protocol wired up so far (see observe()'s own doc comment in asset_inventory.hpp for the
    // others still to come). A ListIdentity response's identity fields describe whichever IP
    // actually SENT this specific packet -- not simply "the server," since it's this exchange
    // itself that's the evidence of which side is the real device -- so this binds to dp.src_ip
    // directly rather than to client_ip/server_ip above. update_identity is a no-op if dp.src_ip
    // has no asset entry (only possible if it were a broadcast source, which a real identity
    // response never is in practice).
    if (protocol == "enip" && dp.result && dp.result->as<EnipResult>().first.has_identity) {
        const EnipFrame& identity = dp.result->as<EnipResult>().first;
        std::ostringstream serial;
        serial << "0x" << std::hex << identity.identity_serial_number;
        update_identity(dp.src_ip, "Vendor ID " + std::to_string(identity.identity_vendor_id),
                         identity.identity_product_name, identity.identity_revision, serial.str());
    } else if (protocol == "opcua" && dp.result && dp.result->as<OpcUaResult>().first.has_identity) {
        // OPC UA's GetEndpointsResponse is sent BY the server being queried (same shape as ENIP's
        // ListIdentity response above) -- see OpcUaMessage::has_identity's own comment (opcua.hpp)
        // for why this is only the FIRST endpoint in that response, not necessarily the one this
        // session actually negotiated.
        const OpcUaMessage& identity = dp.result->as<OpcUaResult>().first;
        std::string posture = "SecurityMode=" + identity.identity_security_mode_name +
                               ", Policy=" + identity.identity_security_policy_uri;
        if (identity.identity_security_mode_name == "None") {
            posture = "SECURITY FINDING: " + posture + " (endpoint accepts no security at all)";
        }
        update_identity(dp.src_ip, identity.identity_application_uri, identity.identity_application_uri,
                         /*firmware_revision=*/"", /*serial_number=*/"", posture);
    } else if (protocol == "s7comm" && dp.protocol == "s7comm" && dp.result &&
               dp.result->as<S7CommResult>().has_userdata_szl &&
               dp.result->as<S7CommResult>().userdata_szl_is_response &&
               dp.result->as<S7CommResult>().szl_return_code == 0xFF) {
        // A Read SZL response is sent BY the CPU being queried, same "identity describes whoever
        // actually sent this packet" reasoning as ENIP/OPC UA above. `product` prefers the real
        // Order Number/MLFB (SZL-ID 0x0011) when present, falling back to the 0x001C family's own
        // CPU-type or module/PLC name fields when it isn't (a real exchange may request only one
        // SZL-ID, not both) -- see S7CommFrame::szl_order_number's own comment (s7comm.hpp) for why
        // these two SZL-IDs are the ones actually carrying a vendor/model-equivalent fact. Module
        // type code/version are deliberately NOT promoted to a field here (see this engine's own doc
        // comment in asset_inventory.hpp) -- folded into an informational note on the packet-derived
        // function-name path instead, downstream in this same observe() call, exactly like every
        // other protocol's PLC Control PI-service scope boundary elsewhere in this file.
        const S7CommResult& szl = dp.result->as<S7CommResult>();
        std::string product = !szl.szl_order_number.empty()   ? szl.szl_order_number
                               : !szl.szl_module_type_name.empty() ? szl.szl_module_type_name
                               : !szl.szl_plc_name.empty()     ? szl.szl_plc_name
                                                                : szl.szl_module_name;
        if (!product.empty() || !szl.szl_serial_number.empty() || !szl.szl_plant_identification.empty()) {
            update_identity(dp.src_ip, /*vendor=*/"", product, /*firmware_revision=*/"",
                             szl.szl_serial_number, /*security_posture=*/"", szl.szl_plant_identification);
        }
    } else if (protocol == "bacnet" && dp.result && dp.result->as<BacnetFrame>().has_npdu &&
               dp.result->as<BacnetFrame>().npdu.has_apdu &&
               dp.result->as<BacnetFrame>().npdu.apdu.has_device_identity) {
        // A ReadProperty/ReadPropertyMultiple Complex-ACK carrying one or more Device-object
        // identity properties (see bacnet.hpp's "Device object identity correlation" paragraph) is
        // sent BY the device being queried, same "identity describes whoever actually sent this
        // packet" reasoning as ENIP/OPC UA/S7comm above. `firmware_revision` prefers the real
        // Firmware-Revision property, falling back to Application-Software-Version only when
        // Firmware-Revision itself wasn't read in this exchange (they are genuinely different
        // properties -- the device's own onboard firmware vs. the specific application/config
        // loaded onto it -- but InventoryAsset has one firmware_revision field, not two, matching
        // this codebase's existing "fold the secondary fact into the closest existing field rather
        // than inventing a narrow new one" posture, e.g. S7comm's own product fallback chain just
        // above).
        const BacnetApdu& apdu = dp.result->as<BacnetFrame>().npdu.apdu;
        std::string firmware = !apdu.device_firmware_revision.empty() ? apdu.device_firmware_revision
                                                                       : apdu.device_application_software_version;
        update_identity(dp.src_ip, apdu.device_vendor_name, apdu.device_model_name, firmware,
                         apdu.device_serial_number);
    } else if (protocol == "dnp3" && dp.result && dp.result->as<Dnp3Result>().dnp3_has_device_identity) {
        // A Device Attributes response carrying one or more of the five recognized identity
        // attributes (see dnp3.hpp's "Device attribute identity correlation" paragraph) is sent BY
        // the outstation being queried, same "identity describes whoever actually sent this
        // packet" reasoning as every other protocol above. `firmware_revision` gets
        // device_software_version (Device Manufacturer's Software Version, variation 242) --
        // device_hardware_version (variation 243) has no InventoryAsset field of its own and is
        // deliberately not promoted here (decoded and available in dnp3_device_hardware_version/
        // dnp3_point_values regardless) -- same "decode it, but don't invent a narrow new field for
        // a secondary fact" posture as S7comm's own module-type-code/version just above.
        const Dnp3Result& dr = dp.result->as<Dnp3Result>();
        update_identity(dp.src_ip, dr.dnp3_device_manufacturer_name, dr.dnp3_device_product_name,
                         dr.dnp3_device_software_version, dr.dnp3_device_serial_number);
    }

    if (client_is_bcast || server_is_bcast) return;

    std::string ekey = edge_key(protocol, client_ip, server_ip, server_port);
    auto eit = edges_.find(ekey);
    if (eit == edges_.end()) {
        EdgeState es;
        es.client_ip = client_ip;
        es.server_ip = server_ip;
        es.protocol = protocol;
        es.server_port = server_port;
        es.direction_source = direction_source;
        edge_order_.push_back(ekey);
        eit = edges_.emplace(ekey, std::move(es)).first;
    } else if (direction_source_rank(direction_source) < direction_source_rank(eit->second.direction_source)) {
        // A more authoritative tier than whatever this edge was already tagged with -- e.g. an
        // earlier-contributing session's handshake was never captured (port-heuristic only), but
        // this packet's own session did capture one. See direction_source_rank's own comment above
        // for why this never downgrades.
        eit->second.direction_source = direction_source;
    }
    ++eit->second.packet_count;
    if (!function_name.empty()) eit->second.functions.insert(function_name);
    // Phase 7 of Grok gap #2 -- fold this packet's own touched_addresses (computed above) into this
    // edge's capped internal touch-count map. kMaxTrackedAddressesPerEdge admits a NEW distinct key
    // only up to the cap; a key already present always keeps incrementing regardless (see that
    // constant's own comment, asset_inventory.hpp, for why this is a pure ceiling with no eviction).
    for (const auto& addr : touched_addresses) {
        auto ait = eit->second.address_touch_counts.find(addr);
        if (ait != eit->second.address_touch_counts.end()) {
            ++ait->second;
        } else if (eit->second.address_touch_counts.size() < kMaxTrackedAddressesPerEdge) {
            eit->second.address_touch_counts.emplace(addr, 1);
        }
    }
    if (!eit->second.has_timestamp) {
        eit->second.has_timestamp = true;
        eit->second.first_seen = dp.timestamp;
        eit->second.last_seen = dp.timestamp;
    } else {
        eit->second.first_seen = std::min(eit->second.first_seen, dp.timestamp);
        eit->second.last_seen = std::max(eit->second.last_seen, dp.timestamp);
    }
}

namespace {

// Phase 6 of Grok gap #2 ("asset inventory: a real OT asset record") -- see
// InventoryAsset::inferred_role's own comment (asset_inventory.hpp) for the full design record;
// this is just the implementation of the table documented there.

// Protocols whose server side is conventionally the physical/embedded field device being polled or
// commanded (a PLC/RTU/IED/field controller) -- see InventoryAsset::inferred_role's own comment for
// why this set doesn't include opcua/mms (ambiguous server-role signal) or mqtt (broker/client
// roles don't map onto this axis at all).
const std::unordered_set<std::string>& role_field_protocols() {
    static const std::unordered_set<std::string> kFieldProtocols = {
        "modbus", "dnp3", "s7comm", "s7comm-plus", "enip", "iec104", "hartip", "bacnet", "ffhse",
    };
    return kFieldProtocols;
}

// Protocols usable as a CLIENT-role signal for "Historian/Data Collector" -- see
// InventoryAsset::inferred_role's own comment for why these two (and only these two) are excluded
// from role_field_protocols() above despite also being spoken natively by field devices.
const std::unordered_set<std::string>& role_data_platform_protocols() {
    static const std::unordered_set<std::string> kDataPlatformProtocols = {"opcua", "mms"};
    return kDataPlatformProtocols;
}

bool any_protocol_in(const std::vector<std::string>& protocols, const std::unordered_set<std::string>& set) {
    for (const auto& p : protocols) {
        if (set.count(p)) return true;
    }
    return false;
}

// `distinct_servers_by_client`: for each IP ever seen as an edge's client_ip, the set of distinct
// server_ip's it was paired with across every edge (any protocol) -- see
// InventoryAsset::inferred_role's own comment for the exact four-way rule table this implements.
std::string infer_asset_role(const InventoryAsset& asset,
                              const std::unordered_map<std::string, std::unordered_set<std::string>>&
                                  distinct_servers_by_client) {
    size_t distinct_servers = 0;
    if (auto it = distinct_servers_by_client.find(asset.ip); it != distinct_servers_by_client.end()) {
        distinct_servers = it->second.size();
    }

    if (asset.ever_server && !asset.ever_client && any_protocol_in(asset.protocols, role_field_protocols())) {
        return "PLC/RTU";
    }
    if (asset.ever_client && !asset.ever_server && distinct_servers >= 2 &&
        any_protocol_in(asset.protocols, role_field_protocols())) {
        return "HMI/Engineering Station";
    }
    if (asset.ever_client && distinct_servers >= 2 &&
        any_protocol_in(asset.protocols, role_data_platform_protocols())) {
        return "Historian/Data Collector";
    }
    return "Unknown";
}

}  // namespace

AssetInventoryReport AssetInventoryEngine::finish() const {
    AssetInventoryReport report;
    report.total_packets = total_packets_;
    report.skipped_packets = skipped_packets_;
    report.zone_prefix_len = zone_prefix_len_;

    // Assets, sorted numerically by address (not first-seen order, not lexicographically -- a
    // lexicographic sort would put "192.168.1.100" before "192.168.1.50") for a report that's
    // deterministic independent of capture order.
    std::vector<std::pair<uint32_t, std::string>> sortable_assets;
    sortable_assets.reserve(asset_order_.size());
    for (const auto& ip : asset_order_) {
        auto addr = parse_ipv4_string(ip);
        sortable_assets.emplace_back(addr.value_or(0), ip);
    }
    std::sort(sortable_assets.begin(), sortable_assets.end());

    for (const auto& [addr, ip] : sortable_assets) {
        const AssetState& as = assets_.at(ip);
        InventoryAsset ia;
        ia.ip = ip;
        ia.has_mac = as.has_mac;
        ia.mac = as.mac;
        ia.protocols.assign(as.protocols.begin(), as.protocols.end());
        std::sort(ia.protocols.begin(), ia.protocols.end());
        ia.ever_client = as.ever_client;
        ia.ever_server = as.ever_server;
        ia.packet_count = as.packet_count;
        ia.first_seen = as.first_seen;
        ia.last_seen = as.last_seen;
        ia.vendor = as.vendor;
        ia.product = as.product;
        ia.firmware_revision = as.firmware_revision;
        ia.serial_number = as.serial_number;
        ia.security_posture = as.security_posture;
        ia.plant_identification = as.plant_identification;
        report.assets.push_back(std::move(ia));
        (void)addr;
    }

    for (const auto& key : edge_order_) {
        const EdgeState& es = edges_.at(key);
        InventoryEdge ie;
        ie.client_ip = es.client_ip;
        ie.server_ip = es.server_ip;
        ie.protocol = es.protocol;
        ie.server_port = es.server_port;
        ie.observed_functions.assign(es.functions.begin(), es.functions.end());
        std::sort(ie.observed_functions.begin(), ie.observed_functions.end());
        ie.packet_count = es.packet_count;
        ie.direction_source = es.direction_source;
        ie.first_seen = es.first_seen;
        ie.last_seen = es.last_seen;

        // Phase 7 of Grok gap #2 -- sort the internal touch-count map (never sorted during observe(),
        // see EdgeState::address_touch_counts' own comment) by count descending, address string
        // ascending as a deterministic tie-break, then truncate to the top
        // kMaxShownTouchedAddressesPerEdge -- the one place this whole feature actually needs
        // sorting/truncation, so it happens once here rather than repeatedly during observation.
        ie.touched_addresses_total_distinct = es.address_touch_counts.size();
        ie.top_touched_addresses.reserve(
            std::min(es.address_touch_counts.size(), kMaxShownTouchedAddressesPerEdge));
        for (const auto& [addr, count] : es.address_touch_counts) {
            ie.top_touched_addresses.push_back(InventoryAddressTouch{addr, count});
        }
        std::sort(ie.top_touched_addresses.begin(), ie.top_touched_addresses.end(),
                  [](const InventoryAddressTouch& a, const InventoryAddressTouch& b) {
                      if (a.count != b.count) return a.count > b.count;
                      return a.address < b.address;
                  });
        if (ie.top_touched_addresses.size() > kMaxShownTouchedAddressesPerEdge) {
            ie.top_touched_addresses.resize(kMaxShownTouchedAddressesPerEdge);
        }
        ie.touched_addresses_truncated = ie.touched_addresses_total_distinct > ie.top_touched_addresses.size();

        report.edges.push_back(std::move(ie));
    }

    // Phase 6 of Grok gap #2 -- InventoryAsset::inferred_role (see that field's own comment for the
    // full heuristic table). Runs as its own pass here, after report.edges above is fully built:
    // the heuristic needs each asset's count of DISTINCT server peers across the whole capture,
    // which only exists once every edge has been deduplicated and aggregated -- it can't be
    // computed incrementally per-packet in observe() the way every other InventoryAsset field is.
    {
        std::unordered_map<std::string, std::unordered_set<std::string>> distinct_servers_by_client;
        for (const auto& ie : report.edges) {
            distinct_servers_by_client[ie.client_ip].insert(ie.server_ip);
        }
        for (auto& ia : report.assets) {
            ia.inferred_role = infer_asset_role(ia, distinct_servers_by_client);
        }
    }

    // Zones: group every asset IP by its zone_prefix_len_-bit network. std::map's own ordering
    // (ascending key) gives zones sorted by network address for free, and each asset IP lands in
    // exactly one zone since sortable_assets (and therefore report.assets, and therefore this loop)
    // is already address-sorted -- member_ips ends up sorted too, with no separate sort needed.
    uint32_t mask = cidr_mask(zone_prefix_len_);
    std::map<uint32_t, std::vector<std::string>> by_network;
    std::unordered_map<uint32_t, std::string> zone_name_for_network;
    for (const auto& ia : report.assets) {
        auto addr = parse_ipv4_string(ia.ip);
        if (!addr) continue;  // can't happen -- every asset IP came from a DecodedPacket::src_ip/
                                // dst_ip, always a valid dotted-quad (format_ipv4's own output)
        by_network[*addr & mask].push_back(ia.ip);
    }
    for (const auto& [network, ips] : by_network) {
        InventoryZone iz;
        auto block = parse_cidr(format_ipv4(network) + "/" + std::to_string(zone_prefix_len_));
        iz.network = block.value_or(CidrBlock{});  // parse_cidr can't actually fail on a value this
                                                      // function itself just formatted and masked
        iz.name = zone_name_for(iz.network);
        iz.member_ips = ips;
        zone_name_for_network[network] = iz.name;
        report.zones.push_back(std::move(iz));
    }

    // Conduits: one per distinct (from_zone, to_zone, protocol, port) tuple at least one edge
    // exercises -- see InventoryConduit's own comment for why this differs from `policy validate`'s
    // "list every declared conduit, exercised or not" convention.
    struct ConduitKey {
        std::string from_zone, to_zone, protocol;
        uint16_t port;
        bool operator<(const ConduitKey& o) const {
            return std::tie(from_zone, to_zone, protocol, port) < std::tie(o.from_zone, o.to_zone, o.protocol, o.port);
        }
    };
    struct ConduitAgg {
        size_t edge_count = 0;
        size_t packet_count = 0;
    };
    std::map<ConduitKey, ConduitAgg> conduit_agg;
    for (const auto& ie : report.edges) {
        auto cip = parse_ipv4_string(ie.client_ip);
        auto sip = parse_ipv4_string(ie.server_ip);
        if (!cip || !sip) continue;  // same "can't actually happen" reasoning as the zone loop above
        ConduitKey key{zone_name_for_network.at(*cip & mask), zone_name_for_network.at(*sip & mask), ie.protocol,
                       ie.server_port};
        ConduitAgg& agg = conduit_agg[key];
        ++agg.edge_count;
        agg.packet_count += ie.packet_count;
    }
    for (const auto& [key, agg] : conduit_agg) {
        InventoryConduit ic;
        ic.from_zone = key.from_zone;
        ic.to_zone = key.to_zone;
        ic.protocol = key.protocol;
        ic.port = key.port;
        ic.edge_count = agg.edge_count;
        ic.packet_count = agg.packet_count;
        std::ostringstream name;
        name << key.from_zone << " -> " << key.to_zone << " (" << key.protocol << "/" << key.port << ")";
        ic.name = name.str();
        report.conduits.push_back(std::move(ic));
    }

    for (const auto& key : notable_protocol_order_) {
        const NotableProtocolState& ns = notable_protocols_.at(key);
        InventoryNotableProtocol nf;
        nf.protocol = ns.protocol;
        nf.tier = ns.tier;
        nf.has_ip = ns.has_ip;
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

    return report;
}

namespace {

std::string role_text(const InventoryAsset& a) {
    if (a.ever_client && a.ever_server) return "client+server";
    if (a.ever_client) return "client";
    return "server";
}

std::string protocol_list_text(const std::vector<std::string>& protocols) {
    std::string out;
    for (size_t i = 0; i < protocols.size(); ++i) {
        if (i) out += ", ";
        out += protocols[i];
    }
    return out;
}

// Renders AssetInventoryReport::notable_protocols -- see that field's own comment for why this is
// always printed, independent of everything else in this report, and InventoryNotableProtocol's own
// comment for exactly what each field means and why client_ip/server_ip here is always a
// best-effort, port-heuristic guess (this file's own write_inventory_report_text's equivalent
// section for `policy validate`, write_notable_protocols_text in policy_engine.cpp, additionally
// distinguishes a handshake-confirmed direction from a heuristic one -- this engine has no
// equivalent per-session state for these 43 protocols to draw that distinction from, so every entry
// here is annotated the same way).
void write_notable_protocols_text(std::ostream& out, const AssetInventoryReport& report, const Resolver& resolver) {
    out << "NOTABLE IT PROTOCOLS (" << report.notable_protocols.size() << "):\n";
    out << "  Protocols an OT auditor would flag as worth attention on their own -- see "
           "docs/MANUAL.md's\n";
    out << "  ROADMAP item 18. Not part of the eleven-protocol scope above; does not count toward "
           "skipped_packets.\n";
    if (report.notable_protocols.empty()) {
        out << "  (none)\n";
        return;
    }
    for (size_t i = 0; i < report.notable_protocols.size(); ++i) {
        const InventoryNotableProtocol& f = report.notable_protocols[i];
        out << "  [" << (i + 1) << "] " << f.protocol << "  (" << f.tier << ")  ";
        if (f.has_ip) {
            out << f.client_ip;
            if (auto h = resolver.hostname(f.client_ip)) out << " (" << *h << ")";
            out << " <-> " << f.server_ip;
            if (auto h = resolver.hostname(f.server_ip)) out << " (" << *h << ")";
            if (f.has_port) {
                out << ":" << f.port;
                if (auto s = resolver.service_name(f.port, f.is_tcp ? "tcp" : "udp")) out << " (" << *s << ")";
                out << "  (direction: port heuristic)";
            }
        } else {
            out << f.mac_a;
            if (auto v = resolver.oui_vendor(f.mac_a)) out << " (" << *v << ")";
            out << " <-> " << f.mac_b;
            if (auto v = resolver.oui_vendor(f.mac_b)) out << " (" << *v << ")";
        }
        out << "  (" << f.packet_count << " packet(s))\n";
    }
}

}  // namespace

void write_inventory_report_text(std::ostream& out, const AssetInventoryReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    out << "OT asset inventory\n";
    out << "  capture: " << capture_path << "\n";
    out << "  scope:   Modbus, DNP3, S7comm, EtherNet/IP, BACnet/IP, IEC 104, HART-IP (TCP only),\n";
    out << "           OPC UA, MMS, MQTT, and S7comm-Plus -- plus FF-HSE (TCP only; rarely\n";
    out << "           applicable, since FF-HSE is fundamentally a UDP protocol) -- see\n";
    out << "           docs/MANUAL.md's ROADMAP item 17\n\n";

    out << report.assets.size() << " asset(s) observed, " << report.total_packets
        << " total packet(s) in capture, " << report.skipped_packets
        << " skipped (not one of the eleven recognized protocols, no IPv4 layer, or HART-IP/FF-HSE "
           "seen over UDP)\n\n";

    out << "ASSETS (" << report.assets.size() << "):\n";
    if (report.assets.empty()) {
        out << "  (none)\n";
    }
    for (const auto& a : report.assets) {
        out << "  " << a.ip;
        if (auto h = resolver.hostname(a.ip)) out << " (" << *h << ")";
        if (a.has_mac) {
            out << "  " << a.mac;
            if (auto v = resolver.oui_vendor(a.mac)) out << " (" << *v << ")";
        }
        out << "  [" << role_text(a) << "]  " << protocol_list_text(a.protocols) << "  (" << a.packet_count
            << " packet(s))\n";
        out << "      first seen: " << format_epoch_seconds(a.first_seen)
            << "  last seen: " << format_epoch_seconds(a.last_seen) << "\n";
        out << "      role: " << a.inferred_role << "  (heuristic, low confidence)\n";
        if (!a.vendor.empty() || !a.product.empty() || !a.firmware_revision.empty() || !a.serial_number.empty()) {
            out << "      identity:";
            if (!a.vendor.empty()) out << "  vendor=" << a.vendor;
            if (!a.product.empty()) out << "  product=\"" << a.product << "\"";
            if (!a.firmware_revision.empty()) out << "  firmware=" << a.firmware_revision;
            if (!a.serial_number.empty()) out << "  serial=" << a.serial_number;
            out << "\n";
        }
        if (!a.security_posture.empty()) out << "      security: " << a.security_posture << "\n";
        if (!a.plant_identification.empty()) {
            out << "      plant identification: " << a.plant_identification << "\n";
        }
    }
    out << "\n";

    out << "COMMUNICATIONS (" << report.edges.size() << "):\n";
    if (report.edges.empty()) {
        out << "  (none)\n";
    }
    for (const auto& e : report.edges) {
        out << "  " << e.client_ip;
        if (auto h = resolver.hostname(e.client_ip)) out << " (" << *h << ")";
        out << " -> " << e.server_ip;
        if (auto h = resolver.hostname(e.server_ip)) out << " (" << *h << ")";
        out << ":" << e.server_port;
        if (auto s = resolver.service_name(e.server_port, "tcp")) out << " (" << *s << ")";
        out << "  " << e.protocol;
        if (!e.observed_functions.empty()) out << "  [" << protocol_list_text(e.observed_functions) << "]";
        out << "  (" << e.packet_count << " packet(s), direction: " << direction_source_name(e.direction_source)
            << ")\n";
        out << "      first seen: " << format_epoch_seconds(e.first_seen)
            << "  last seen: " << format_epoch_seconds(e.last_seen) << "\n";
        // Phase 7 of Grok gap #2 -- see InventoryEdge::top_touched_addresses' own comment
        // (asset_inventory.hpp). Omitted entirely when empty (an out-of-scope protocol, or an
        // in-scope protocol whose traffic this session never carried a recognized addressable
        // request/item on), same "don't print a header for nothing" convention as the identity/
        // security/plant-identification lines above.
        if (!e.top_touched_addresses.empty()) {
            out << "      top touched addresses";
            if (e.touched_addresses_truncated) {
                out << " (top " << e.top_touched_addresses.size() << " of "
                    << e.touched_addresses_total_distinct << " distinct addresses touched, by touch count)";
            } else {
                out << " (" << e.touched_addresses_total_distinct << " distinct address(es) touched)";
            }
            out << ":\n";
            for (const auto& t : e.top_touched_addresses) {
                out << "        " << t.address << "  (" << t.count << " touch(es))\n";
            }
        }
    }
    out << "\n";

    out << "INFERRED ZONES (" << report.zones.size() << ", grouped by observed /"
        << static_cast<int>(report.zone_prefix_len) << " subnet):\n";
    if (report.zones.empty()) {
        out << "  (none)\n";
    }
    for (const auto& z : report.zones) {
        out << "  " << z.name << " (" << z.network.text << "): ";
        for (size_t i = 0; i < z.member_ips.size(); ++i) {
            if (i) out << ", ";
            out << z.member_ips[i];
        }
        out << "\n";
    }
    out << "\n";

    out << "INFERRED CONDUITS (" << report.conduits.size() << "):\n";
    if (report.conduits.empty()) {
        out << "  (none)\n";
    }
    for (const auto& c : report.conduits) {
        out << "  " << c.from_zone << " -> " << c.to_zone << "  (" << c.protocol << "/" << c.port << ")  "
            << c.edge_count << " edge(s), " << c.packet_count << " packet(s)\n";
    }
    out << "\n";

    write_notable_protocols_text(out, report, resolver);
}

void write_inventory_report_json(std::ostream& out, const AssetInventoryReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(capture_path) << "\",\n";
    out << "  \"total_packets\": " << report.total_packets << ",\n";
    out << "  \"skipped_packets\": " << report.skipped_packets << ",\n";

    out << "  \"assets\": [\n";
    for (size_t i = 0; i < report.assets.size(); ++i) {
        const InventoryAsset& a = report.assets[i];
        out << "    {\n";
        out << "      \"ip\": \"" << json_escape(a.ip) << "\",\n";
        if (auto h = resolver.hostname(a.ip)) out << "      \"hostname\": \"" << json_escape(*h) << "\",\n";
        out << "      \"mac\": " << (a.has_mac ? ("\"" + json_escape(a.mac) + "\"") : "null") << ",\n";
        if (a.has_mac) {
            if (auto v = resolver.oui_vendor(a.mac)) out << "      \"mac_vendor\": \"" << json_escape(*v) << "\",\n";
        }
        out << "      \"protocols\": [";
        for (size_t j = 0; j < a.protocols.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(a.protocols[j]) << "\"";
        }
        out << "],\n";
        out << "      \"role\": \"" << role_text(a) << "\",\n";
        out << "      \"packet_count\": " << a.packet_count << ",\n";
        // Appended after packet_count (the prior true-last field), same "no established JSON-shape
        // test anchored on an earlier field needs to change" append-only convention this file's own
        // notable_protocols/direction_source additions already follow. std::fixed/setprecision(6)
        // matches output.cpp's own DecodedPacket::timestamp JSON rendering exactly (its own
        // "timestamp" field) -- otherwise an epoch value this large default-renders in scientific
        // notation (e.g. "1.7e+09"), technically valid JSON but needlessly unreadable.
        out << "      \"first_seen\": " << std::fixed << std::setprecision(6) << a.first_seen << ",\n";
        out << "      \"first_seen_text\": \"" << json_escape(format_epoch_seconds(a.first_seen)) << "\",\n";
        out << "      \"last_seen\": " << a.last_seen << ",\n";
        out << "      \"last_seen_text\": \"" << json_escape(format_epoch_seconds(a.last_seen)) << "\"";
        if (!a.vendor.empty()) out << ",\n      \"vendor\": \"" << json_escape(a.vendor) << "\"";
        if (!a.product.empty()) out << ",\n      \"product\": \"" << json_escape(a.product) << "\"";
        if (!a.firmware_revision.empty()) {
            out << ",\n      \"firmware_revision\": \"" << json_escape(a.firmware_revision) << "\"";
        }
        if (!a.serial_number.empty()) out << ",\n      \"serial_number\": \"" << json_escape(a.serial_number) << "\"";
        if (!a.security_posture.empty()) {
            out << ",\n      \"security_posture\": \"" << json_escape(a.security_posture) << "\"";
        }
        if (!a.plant_identification.empty()) {
            out << ",\n      \"plant_identification\": \"" << json_escape(a.plant_identification) << "\"";
        }
        // Phase 6 of Grok gap #2 -- InventoryAsset::inferred_role's own comment (asset_inventory.hpp)
        // has the full heuristic. Appended after plant_identification (the prior true-last field),
        // same append-only convention as every addition above -- unconditional, unlike
        // vendor/product/etc., since a role is always computed for every asset (see that field's own
        // comment for why "Unknown" is a real conclusion here, not an absence). Named "inferred_role"
        // rather than "role" to avoid colliding with the existing "role" field above (client/server/
        // client+server -- a completely different, already-established concept; see role_text's own
        // comment).
        out << ",\n      \"inferred_role\": \"" << json_escape(a.inferred_role) << "\"";
        out << "\n";
        out << "    }" << (i + 1 < report.assets.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"edges\": [\n";
    for (size_t i = 0; i < report.edges.size(); ++i) {
        const InventoryEdge& e = report.edges[i];
        out << "    {\n";
        out << "      \"client_ip\": \"" << json_escape(e.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(e.server_ip) << "\",\n";
        if (auto h = resolver.hostname(e.client_ip)) out << "      \"client_hostname\": \"" << json_escape(*h) << "\",\n";
        if (auto h = resolver.hostname(e.server_ip)) out << "      \"server_hostname\": \"" << json_escape(*h) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(e.protocol) << "\",\n";
        out << "      \"server_port\": " << e.server_port << ",\n";
        if (auto s = resolver.service_name(e.server_port, "tcp")) {
            out << "      \"server_port_service\": \"" << json_escape(*s) << "\",\n";
        }
        out << "      \"observed_functions\": [";
        for (size_t j = 0; j < e.observed_functions.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(e.observed_functions[j]) << "\"";
        }
        out << "],\n";
        out << "      \"packet_count\": " << e.packet_count << ",\n";
        // How client_ip/server_ip above were decided -- "handshake"/"content"/"port-heuristic", see
        // DirectionSource's own comment (decoder.hpp) and docs/MANUAL.md's ROADMAP item 19.
        // Appended last, after every pre-existing field (packet_count was the prior last field), so
        // no established JSON-shape test anchored on an earlier field's position needs to change --
        // see CMakeLists.txt's inventory_json_report_shape and
        // inventory_json_bacnet_edge_has_no_server_port_service tests in particular, both of which
        // only match fields up through packet_count's predecessors.
        out << "      \"direction_source\": \"" << direction_source_name(e.direction_source) << "\",\n";
        // Appended after direction_source (the prior true-last field) -- same append-only
        // convention as the assets array's own first_seen/last_seen addition above (see that
        // addition's own comment for why std::fixed/setprecision(6) is applied here too).
        out << "      \"first_seen\": " << std::fixed << std::setprecision(6) << e.first_seen << ",\n";
        out << "      \"first_seen_text\": \"" << json_escape(format_epoch_seconds(e.first_seen)) << "\",\n";
        out << "      \"last_seen\": " << e.last_seen << ",\n";
        out << "      \"last_seen_text\": \"" << json_escape(format_epoch_seconds(e.last_seen)) << "\",\n";
        // Phase 7 of Grok gap #2 -- appended after last_seen_text (the prior true-last field), same
        // append-only convention as every addition above. Unconditional (an empty array, not an
        // omitted field) for an edge with nothing to report here, matching observed_functions' own
        // always-present-array convention above rather than vendor/product/etc.'s "omit when empty"
        // one -- see InventoryEdge::top_touched_addresses' own comment (asset_inventory.hpp).
        out << "      \"top_touched_addresses\": [";
        for (size_t j = 0; j < e.top_touched_addresses.size(); ++j) {
            if (j) out << ", ";
            out << "{\"address\": \"" << json_escape(e.top_touched_addresses[j].address) << "\", \"count\": "
                << e.top_touched_addresses[j].count << "}";
        }
        out << "],\n";
        out << "      \"touched_addresses_total_distinct\": " << e.touched_addresses_total_distinct << ",\n";
        out << "      \"touched_addresses_truncated\": " << (e.touched_addresses_truncated ? "true" : "false")
            << "\n";
        out << "    }" << (i + 1 < report.edges.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"zones\": [\n";
    for (size_t i = 0; i < report.zones.size(); ++i) {
        const InventoryZone& z = report.zones[i];
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(z.name) << "\",\n";
        out << "      \"network\": \"" << json_escape(z.network.text) << "\",\n";
        out << "      \"member_ips\": [";
        for (size_t j = 0; j < z.member_ips.size(); ++j) {
            if (j) out << ", ";
            out << "\"" << json_escape(z.member_ips[j]) << "\"";
        }
        out << "]\n";
        out << "    }" << (i + 1 < report.zones.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"conduits\": [\n";
    for (size_t i = 0; i < report.conduits.size(); ++i) {
        const InventoryConduit& c = report.conduits[i];
        out << "    {\n";
        out << "      \"name\": \"" << json_escape(c.name) << "\",\n";
        out << "      \"from_zone\": \"" << json_escape(c.from_zone) << "\",\n";
        out << "      \"to_zone\": \"" << json_escape(c.to_zone) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(c.protocol) << "\",\n";
        out << "      \"port\": " << c.port << ",\n";
        out << "      \"edge_count\": " << c.edge_count << ",\n";
        out << "      \"packet_count\": " << c.packet_count << "\n";
        out << "    }" << (i + 1 < report.conduits.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    // "IT protocols an OT auditor flags" (ROADMAP item 18) -- see AssetInventoryReport::
    // notable_protocols' own comment for why this is always populated, independent of everything
    // above. Appended last, after every pre-existing field (conduits was the prior last field), the
    // same "no established JSON-shape test anchored on an earlier field needs to change" convention
    // policy_engine.cpp's own write_policy_report_json follows for this identical addition there.
    out << "  \"notable_protocols\": [\n";
    for (size_t i = 0; i < report.notable_protocols.size(); ++i) {
        const InventoryNotableProtocol& f = report.notable_protocols[i];
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
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }" << (i + 1 < report.notable_protocols.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

void write_inventory_diagram_mermaid(std::ostream& out, const AssetInventoryReport& report) {
    out << "graph LR\n";
    for (const auto& z : report.zones) {
        out << "  " << z.name << "[\"" << z.name << "<br/>" << z.network.text << "<br/>(" << z.member_ips.size()
            << " asset(s))\"]\n";
    }
    for (const auto& c : report.conduits) {
        out << "  " << c.from_zone << " -->|\"" << c.protocol << "/" << c.port << "\"| " << c.to_zone << "\n";
    }
}

void write_inventory_diagram_dot(std::ostream& out, const AssetInventoryReport& report) {
    out << "digraph inventory {\n";
    out << "  rankdir=LR;\n";
    for (const auto& z : report.zones) {
        out << "  \"" << z.name << "\" [shape=box, label=\"" << z.name << "\\n" << z.network.text << "\\n("
            << z.member_ips.size() << " asset(s))\"];\n";
    }
    for (const auto& c : report.conduits) {
        out << "  \"" << c.from_zone << "\" -> \"" << c.to_zone << "\" [label=\"" << c.protocol << "/" << c.port
            << "\"];\n";
    }
    out << "}\n";
}

void write_inventory_policy_yaml(std::ostream& out, const AssetInventoryReport& report) {
    out << "# Auto-generated by `conduitscope inventory` -- a FIRST-DRAFT zone/conduit policy "
           "inferred from\n";
    out << "# observed traffic, not a hand-authored security policy. Review it -- especially "
           "whether the\n";
    out << "# inferred zones/conduits actually reflect intended segmentation, not just what "
           "happened to be\n";
    out << "# captured -- before using it to gate real `policy validate` runs. See "
           "docs/MANUAL.md's ROADMAP\n";
    out << "# item 17.\n";

    if (report.zones.empty()) {
        // No asset was ever observed (an empty capture, or one with no traffic in this feature's
        // five recognized protocols) -- there is nothing to build even one zone from, and
        // parse_policy_text rejects a policy with an empty (or missing) 'zones' key outright (see
        // policy.hpp), so there is no valid policy file to write at all. Writing comments only,
        // and no 'zones:'/'conduits:' keys, makes that obvious rather than emitting a file that
        // LOOKS like a policy but fails to load with a confusing error.
        out << "#\n";
        out << "# No asset was observed in this capture (0 packets of any of the eleven recognized "
               "protocols --\n";
        out << "# Modbus/DNP3/S7comm/EtherNet-IP/BACnet-IP/IEC104/HART-IP/OPC UA/MMS/MQTT/FF-HSE, "
               "see\n";
        out << "# docs/MANUAL.md's ROADMAP item 17), so there is nothing to infer even one zone "
               "from -- this\n";
        out << "# file intentionally has no\n";
        out << "# 'zones:'/'conduits:' keys and is NOT a loadable policy file as-is.\n";
        return;
    }

    out << "#\n";
    out << "# A conduit inferred from BACnet/IP or EtherNet/IP CIP I/O traffic (both UDP) parses "
           "and validates\n";
    out << "# fine here but cannot yet be exercised by `policy validate`, which only evaluates TCP "
           "flows -- see\n";
    out << "# docs/MANUAL.md's LIMITATIONS.\n";
    out << "zones:\n";
    for (const auto& z : report.zones) {
        out << "  " << z.name << ":\n";
        out << "    description: \"Inferred from observed traffic: " << z.member_ips.size()
            << " asset(s) in " << z.network.text << "\"\n";
        out << "    networks:\n";
        out << "      - " << z.network.text << "\n";
    }
    out << "\n";
    out << "conduits:\n";
    if (report.conduits.empty()) {
        // parse_policy_text rejects an empty 'conduits' list the same way it rejects a missing
        // 'conduits' key at all (see policy.hpp) -- an inventory with zero observed conduits (e.g.
        // every recognized packet was broadcast-only, or every asset was a "lone" one with no
        // counterpart to talk to) would otherwise generate a file that can't actually be loaded, so
        // a single explanatory placeholder conduit stands in instead -- referencing the first zone
        // to itself, which IS always a declared zone at this point (report.zones is non-empty, or
        // this function already returned above), and "any" so it never masks an accidental typo the
        // way a made-up protocol name might.
        out << "  - name: \"placeholder -- no conduits observed, add your own\"\n";
        out << "    from: " << report.zones.front().name << "\n";
        out << "    to: " << report.zones.front().name << "\n";
        out << "    protocols: [any]\n";
        return;
    }
    for (const auto& c : report.conduits) {
        out << "  - name: \"" << c.name << "\"\n";
        out << "    from: " << c.from_zone << "\n";
        out << "    to: " << c.to_zone << "\n";
        out << "    protocols: [" << c.protocol << "]\n";
        out << "    ports: [" << c.port << "]\n";
    }
}

}  // namespace conduitscope
