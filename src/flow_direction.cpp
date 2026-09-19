// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/flow_direction.hpp"

#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/modbus.hpp"

namespace conduitscope {

namespace {

// Canonical (direction-independent) session key for a TCP 4-tuple -- identical in spirit to
// policy_engine.cpp's own session_key and asset_inventory.cpp's own tcp_session_key (kept as a
// third, separate copy rather than shared -- see this file's own header comment, and
// docs/MANUAL.md's ROADMAP item 19's "Why two copies, not one shared implementation", which this
// third copy now follows too).
std::string session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b, uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

// Identical in effect to policy_engine.cpp's own is_known_service_port -- deliberately kept in
// sync (same five IANA-registered OT ports) so `decode`'s own direction guess for a flow always
// agrees with `policy validate`'s guess for the identical flow, the same "same answer, independent
// implementations" property asset_inventory.cpp's own is_known_target_port already documents for
// itself.
bool is_known_service_port(uint16_t port) {
    return port == MODBUS_TCP_PORT || port == DNP3_TCP_PORT || port == COTP_TCP_PORT ||
           port == IEC104_TCP_PORT || port == ENIP_TCP_PORT;
}

// Identical in effect to policy_engine.cpp's own src_is_client_by_port -- see that function's own
// comment for the priority order this implements (a known port on one side and not the other
// decides; otherwise the lower port number is assumed to be the server).
bool src_is_client_by_port(uint16_t src_port, uint16_t dst_port) {
    bool src_known = is_known_service_port(src_port);
    bool dst_known = is_known_service_port(dst_port);
    if (dst_known && !src_known) return true;
    if (src_known && !dst_known) return false;
    return src_port > dst_port;
}

}  // namespace

void FlowDirectionTracker::observe(DecodedPacket& packet) {
    if (!packet.has_ip || !packet.has_tcp) return;

    std::string key = session_key(packet.src_ip, packet.src_port, packet.dst_ip, packet.dst_port);
    bool is_syn = packet.tcp_flags == "SYN";
    bool is_syn_ack = packet.tcp_flags.rfind("SYN,ACK", 0) == 0;

    auto it = flows_.find(key);
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
            src_is_client = src_is_client_by_port(packet.src_port, packet.dst_port);
            fs.direction_source = DirectionSource::PortHeuristic;
        }
        fs.client_ip = src_is_client ? packet.src_ip : packet.dst_ip;
        fs.client_port = src_is_client ? packet.src_port : packet.dst_port;
        fs.server_ip = src_is_client ? packet.dst_ip : packet.src_ip;
        fs.server_port = src_is_client ? packet.dst_port : packet.src_port;
        it = flows_.emplace(key, std::move(fs)).first;
    } else if (!it->second.initiator_known && (is_syn || is_syn_ack)) {
        // A later packet on this flow carries the SYN/SYN-ACK the first packet observed for it
        // didn't -- upgrade from the first-packet port guess to the authoritative answer, exactly
        // PolicyEngine::observe's own upgrade rule.
        bool src_is_client = is_syn;
        it->second.client_ip = src_is_client ? packet.src_ip : packet.dst_ip;
        it->second.client_port = src_is_client ? packet.src_port : packet.dst_port;
        it->second.server_ip = src_is_client ? packet.dst_ip : packet.src_ip;
        it->second.server_port = src_is_client ? packet.dst_port : packet.src_port;
        it->second.initiator_known = true;
        it->second.direction_source = DirectionSource::Handshake;
    }

    const FlowState& fs = it->second;
    packet.has_direction = true;
    packet.direction_client_is_src = (packet.src_ip == fs.client_ip && packet.src_port == fs.client_port);
    packet.direction_source = fs.direction_source;
}

}  // namespace conduitscope
