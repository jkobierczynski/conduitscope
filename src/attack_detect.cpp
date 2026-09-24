// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/attack_detect.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

bool ipv4_has_source_route_option(const std::vector<uint8_t>& options) {
    size_t pos = 0;
    while (pos < options.size()) {
        uint8_t kind = options[pos];
        if (kind == 0x00) break;  // End of Option List
        if (kind == 0x01) {       // No Operation -- single byte, no length field
            ++pos;
            continue;
        }
        if (pos + 1 >= options.size()) break;  // malformed: no room for a length byte
        uint8_t length = options[pos + 1];
        if (length < 2 || pos + length > options.size()) break;  // malformed: length lies
        if (kind == IP_OPT_LOOSE_SOURCE_ROUTE || kind == IP_OPT_STRICT_SOURCE_ROUTE) {
            return true;
        }
        pos += length;
    }
    return false;
}

namespace {

// Smurf/Fraggle's own heuristic -- see attack_detect.hpp's own file header for why this is
// explicitly not a genuine subnet-aware broadcast check.
bool looks_like_broadcast(const std::string& ip) {
    auto addr = parse_ipv4_string(ip);
    if (!addr) return false;
    if (*addr == 0xFFFFFFFFu) return true;          // limited broadcast -- unambiguous
    return (*addr & 0xFFu) == 0xFFu;                  // common /24-style directed-broadcast heuristic
}

}  // namespace

FloodCounters* AttackDetectionState::flood_counters_for(const std::string& dst_ip) {
    if (looks_like_broadcast(dst_ip)) return nullptr;
    auto it = flood_counts_.find(dst_ip);
    if (it != flood_counts_.end()) return &it->second;
    evict_if_full(flood_counts_);
    return &flood_counts_[dst_ip];
}

void AttackDetectionState::observe_ipv4(const Ipv4Header& ip, std::vector<std::string>& notes) {
    if (ipv4_has_source_route_option(ip.options)) {
        notes.push_back(
            "IP Source Route option present (Loose or Strict Source and Record Route) -- lets the "
            "sender dictate this datagram's path, a known technique for bypassing route-based "
            "access controls or masking the traffic's real origin; most networks should be "
            "dropping source-routed packets entirely");
    }

    bool is_fragment = ip.flag_mf || ip.fragment_offset != 0;
    if (!is_fragment) return;

    size_t start = static_cast<size_t>(ip.fragment_offset) * 8;
    size_t end = start + ip.payload.size();

    // Ping of Death: the last fragment of a fragmented IP-protocol-1 (ICMP) datagram whose own
    // declared end position exceeds the 65535-byte maximum IP datagram size. See attack_detect.hpp's
    // own file header for why ICMP type isn't re-confirmed fragment-by-fragment.
    if (!ip.flag_mf && ip.protocol == ICMP_IP_PROTOCOL && end > 65535) {
        notes.push_back("Ping of Death: this fragmented ICMP datagram reassembles to " +
                         std::to_string(end) +
                         " bytes, past the 65535-byte maximum a valid IP datagram can ever "
                         "declare -- the classic oversized-ping crash exploit's structural shape");
    }

    FragmentTrackKey key{ip.src_addr, ip.dst_addr, ip.protocol, ip.identification};
    auto it = fragments_.find(key);
    if (it != fragments_.end()) {
        const FragmentTrackEntry& prev = it->second;
        bool overlaps = start < prev.end && prev.start < end;
        bool identical = (start == prev.start && end == prev.end);
        if (overlaps && !identical) {
            notes.push_back(
                "Teardrop: this IP fragment (bytes " + std::to_string(start) + "-" +
                std::to_string(end) + ") overlaps the previous fragment of the same datagram "
                "(bytes " + std::to_string(prev.start) + "-" + std::to_string(prev.end) +
                ") -- the classic fragment-reassembly crash exploit's structural shape");
        }
    }

    if (!ip.flag_mf) {
        // Last fragment -- presumed reassembly complete, drop the tracker entry so it doesn't
        // linger and get (incorrectly) compared against an unrelated later datagram that happens
        // to reuse the same 16-bit Identification value.
        if (it != fragments_.end()) fragments_.erase(it);
    } else {
        evict_if_full(fragments_);
        fragments_[key] = FragmentTrackEntry{start, end};
    }
}

void AttackDetectionState::observe_tcp(const TcpSegment& tcp, const std::string& src_ip,
                                        const std::string& dst_ip, std::vector<std::string>& notes) {
    if ((tcp.flags & TCP_FLAG_SYN) && src_ip == dst_ip && tcp.src_port == tcp.dst_port) {
        notes.push_back("LAND attack: TCP SYN with identical source and destination (" + src_ip +
                         ":" + std::to_string(tcp.src_port) +
                         ") -- a self-directed connection request, a known DoS primitive against "
                         "stacks that mishandle it");
    }

    if ((tcp.flags & TCP_FLAG_URG) && tcp.urgent_pointer != 0 && !tcp.payload.empty() &&
        (tcp.src_port == 139 || tcp.dst_port == 139)) {
        notes.push_back(
            "WinNuke: Out-of-Band TCP data (URG set, urgent pointer " +
            std::to_string(tcp.urgent_pointer) +
            ") on NetBIOS Session Service port 139 -- the classic Windows OOB-crash exploit's "
            "structural shape (legitimate URG traffic on this port is essentially unheard of; "
            "note this can also false-positive against genuinely rare legitimate URG usage such "
            "as old Telnet/FTP synchronize signaling, though never on port 139 specifically)");
    }

    FloodCounters* counters = flood_counters_for(dst_ip);
    if (!counters) return;  // broadcast-looking destination -- see flood_counters_for's own comment

    bool is_syn_only = (tcp.flags & TCP_FLAG_SYN) && !(tcp.flags & TCP_FLAG_ACK);
    // Bare ACK only (no SYN, no payload) -- matches the sourced ACK-flood description (H3C: "a
    // large number of ACK packets... server must search half-open connections for a match", i.e.
    // idle acknowledgments meant to burn connection-table lookups, not ordinary data traffic).
    // Without the payload.empty() check this would match nearly every packet of any established,
    // perfectly ordinary TCP session (PSH,ACK data segments all carry ACK without SYN) -- found
    // via this codebase's own mandatory before-writing-any-CTest-regex manual verification step,
    // which caught it firing against sample_mqtt.pcap's entirely legitimate PUBLISH traffic.
    bool is_ack_only = (tcp.flags & TCP_FLAG_ACK) && !(tcp.flags & TCP_FLAG_SYN) && tcp.payload.empty();

    if (is_syn_only && ++counters->syn_count >= flood_threshold && !counters->syn_flagged) {
        counters->syn_flagged = true;
        notes.push_back("SYN flood suspected: " + std::to_string(counters->syn_count) +
                         " SYN (no ACK) packets to " + dst_ip +
                         " seen in this capture (threshold: " + std::to_string(flood_threshold) + ")");
    }
    if (is_ack_only && ++counters->ack_count >= flood_threshold && !counters->ack_flagged) {
        counters->ack_flagged = true;
        notes.push_back("ACK flood suspected: " + std::to_string(counters->ack_count) +
                         " ACK (no SYN) packets to " + dst_ip +
                         " seen in this capture (threshold: " + std::to_string(flood_threshold) + ")");
    }
    if (++counters->tcp_count >= flood_threshold && !counters->tcp_flagged) {
        counters->tcp_flagged = true;
        notes.push_back("TCP flood suspected: " + std::to_string(counters->tcp_count) +
                         " TCP packets (any flags) to " + dst_ip +
                         " seen in this capture (threshold: " + std::to_string(flood_threshold) +
                         " -- a broad catch-all bucket, not a single named signature; a SYN or "
                         "ACK flood will typically cross this threshold too)");
    }
}

void AttackDetectionState::observe_udp(const UdpDatagram& udp, const std::string& dst_ip,
                                        std::vector<std::string>& notes) {
    if ((udp.dst_port == 7 || udp.dst_port == 19) && looks_like_broadcast(dst_ip)) {
        notes.push_back(
            "Fraggle attack: UDP " + std::string(udp.dst_port == 7 ? "Echo (port 7)" : "Chargen (port 19)") +
            " request to a broadcast-looking destination (" + dst_ip +
            ") -- amplification/reflection potential, the UDP counterpart to Smurf");
    }

    FloodCounters* counters = flood_counters_for(dst_ip);
    if (!counters) return;  // broadcast-looking destination -- see flood_counters_for's own comment
    if (++counters->udp_count >= flood_threshold && !counters->udp_flagged) {
        counters->udp_flagged = true;
        notes.push_back("UDP flood suspected: " + std::to_string(counters->udp_count) +
                         " UDP datagrams to " + dst_ip +
                         " seen in this capture (threshold: " + std::to_string(flood_threshold) + ")");
    }
}

void AttackDetectionState::observe_icmp(const IcmpMessage& msg, const std::string& dst_ip,
                                         std::vector<std::string>& notes) {
    if (msg.type == 8 && looks_like_broadcast(dst_ip)) {  // Echo Request
        notes.push_back(
            "Smurf attack: ICMP Echo Request to a broadcast-looking destination (" + dst_ip +
            ") -- every host on that segment would reply to whatever source address this packet "
            "claims, the classic ICMP amplification/reflection pattern");
    }
    if (msg.type == 5) {  // Redirect
        notes.push_back(
            "ICMP Redirect observed" +
            (msg.redirect_gateway.empty() ? std::string() : (" (new gateway: " + msg.redirect_gateway + ")")) +
            " -- ICMP has no authentication, so any host on the local segment can send one of "
            "these to silently retarget a victim's next-hop for a destination; a known MITM/route-"
            "poisoning primitive, more consequential on a flat OT network than a segmented one");
    }

    if (msg.type != 8) return;
    FloodCounters* counters = flood_counters_for(dst_ip);
    if (!counters) return;  // broadcast-looking destination -- see flood_counters_for's own comment
    if (++counters->icmp_echo_count >= flood_threshold && !counters->icmp_flagged) {
        counters->icmp_flagged = true;
        notes.push_back("ICMP flood suspected: " + std::to_string(counters->icmp_echo_count) +
                         " Echo Request packets to " + dst_ip +
                         " seen in this capture (threshold: " + std::to_string(flood_threshold) + ")");
    }
}

}  // namespace conduitscope
