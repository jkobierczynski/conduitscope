// SPDX-License-Identifier: Apache-2.0
// attack_detect.hpp - classic network-layer DoS/reconnaissance attack signatures.
//
// Jurgen asked for detection of a specific named list of attacks: LAND, Teardrop, Ping of Death,
// Smurf, Fraggle, ACK Flood, SYN Flood, ICMP Flood, TCP Flood, UDP Flood, ICMP Redirect, IP
// Source Routing ("icmproute"/"routeip" -- he clarified both names refer to the same thing),
// WinNuke, plus "normal" as a label. This exact set of names -- not a standard taxonomy from any
// single RFC or paper -- matches almost one-for-one the built-in "attack protection"/"screen"
// feature lists shipped by several enterprise/SMB firewalls (cross-checked against H3C's
// "Attack detection and prevention configuration" guide and Juniper's Junos "Network DoS Attack"
// and "Attacker Evasion Techniques" documentation, both fetched during this feature's research
// pass): each names LAND, Teardrop, Ping of Death, Smurf, Fraggle, WinNuke, ICMP Redirect, IP
// Source Route Option, and separately meters SYN/ACK/ICMP/UDP flood rates. "TCP Flood" itself is
// not a distinct named signature in either source -- treated here as a deliberate, documented
// catch-all (see FloodCounters below), not a sourced term.
//
// "normal" is not a detector at all -- it's the classification implied by the absence of every
// note this file can emit, the same posture KDD-Cup/NSL-KDD-style attack-type labelings use it
// for; there is no dedicated "normal" function or note anywhere in this codebase.
//
// Two structurally different kinds of attack live here, split by what evidence they need:
//
// SINGLE-PACKET (or single-fragment-pair) STRUCTURAL SIGNATURES -- LAND, WinNuke, ICMP Redirect,
// IP Source Routing, Smurf, Fraggle, Ping of Death, Teardrop -- decodable from one packet (or, for
// Teardrop, one pair of fragments) alone, with no notion of a rate or a threshold. These fire a
// curated note on DecodedPacket::notes every time the signature is observed, exactly like every
// other curated note in this codebase (a BSAP NAK, a DRSGetNCChanges DCSync flag, ...) -- no
// deduplication, no cross-packet state beyond Teardrop's own small fragment tracker below.
//
// VOLUMETRIC/FLOOD SIGNATURES -- SYN/ACK/ICMP/TCP/UDP flood -- fundamentally need to count
// packets of a kind arriving at one destination over the course of the capture; nothing in this
// codebase did that before this addition (every existing stateful decoder tracks one session/flow
// at a time via DecodeContext::flow_state<T>(), never a destination-wide aggregate spanning many
// unrelated sessions). Jurgen was asked how to scope this, given the real vendor-standard
// approach (a true packets-per-second sliding window over real timestamps, e.g. Juniper's
// documented default of 1000 pps for ICMP/UDP floods) would be a genuinely new subsystem, closer
// in size to a new subcommand than a decode-time note, and would rarely fire on anything but a
// large real capture. He chose the simpler alternative: count each category per destination
// across the WHOLE FILE (no time dimension at all) and flag once a fixed count is exceeded --
// coarser than a real per-second rate, but fits this codebase's existing single-pass decode model
// with no new subsystem. He also asked for the threshold itself to be a modest default I pick and
// document as a judgment call, NOT a vendor-sourced number (real vendor defaults, 500-1000pps
// range, would essentially never fire against a modest/synthetic pcap). DEFAULT_FLOOD_THRESHOLD
// below is exactly that -- a small, admittedly-arbitrary illustrative default, overridable via
// --flood-threshold. A flood note fires exactly ONCE per (destination, category) the moment its
// counter first crosses the threshold, not on every subsequent packet -- see FloodCounters'
// *_flagged bools.
//
// IPv4-only. Every signature below is either inherently IPv4-specific (the classic IP Source
// Route option; IP fragmentation fields as this codebase currently reads them) or was simply
// never asked for over IPv6 -- consistent with this codebase's existing, separately-tracked IPv6
// scope gaps (docs/DEVELOPMENT.md ROADMAP item 24). decoder.cpp's IPv6 branch never calls into
// this file.
//
// Explicitly out of scope, an honest limitation rather than an oversight:
//  - Teardrop's fragment tracker compares each new fragment only against the SINGLE most recently
//    seen fragment for the same (src, dst, protocol, identification) key, not a full N-fragment
//    reassembly consistency check across every fragment of a datagram. Sufficient for the classic
//    2-fragment overlap this attack is defined by; a more elaborate multi-fragment overlap pattern
//    spread across 3+ fragments could evade it.
//  - Ping of Death is detected structurally (last fragment's declared end position exceeding the
//    65535-byte maximum IP datagram size, on IP protocol number 1) without re-confirming the
//    first fragment specifically carried an ICMP Echo Request (type 8) header -- doing so would
//    require full cross-fragment reassembly this codebase does not otherwise do. Any IP-protocol-1
//    datagram that reassembles past 65535 bytes is flagged, which covers the historical attack
//    and its structural relatives even though ICMP type isn't re-verified fragment-by-fragment.
//  - Smurf/Fraggle's "destination is a broadcast address" check is a heuristic, not a genuine
//    subnet-aware one: 255.255.255.255 (the limited broadcast) is unambiguous, but a directed
//    broadcast (e.g. 10.0.0.255 on a /24) can only be recognized here by the common last-octet-255
//    convention -- this codebase has no subnet mask for any address it sees, so a /23 or smaller
//    directed broadcast, or a /25 or larger network's own true broadcast, is not detected, and a
//    genuine host address that happens to end in .255 on an unusually large subnet would false-
//    positive. Both cases are flagged with the same note text; the note itself does not claim
//    certainty.
//  - Flood counters are a WHOLE-FILE count, not a rate -- a legitimately busy destination in a
//    long capture can cross the threshold with no actual attack in progress, and a genuinely fast
//    flood compressed into a short capture is exactly as likely to be flagged as a slow trickle of
//    the same total count spread across a long one. This tradeoff was Jurgen's own explicit choice
//    (see above) over building real per-second rate tracking.
//  - No attempt is made to correlate any of this with TCP session completion (a real SYN flood
//    defense checks whether SYNs are ever answered by a completed handshake); every check here is
//    purely structural/volumetric, the same posture as every other curated note in this codebase.
#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/icmp.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/tcp.hpp"
#include "conduitscope/udp.hpp"

// Deliberately does NOT include decoder.hpp: decoder.hpp's own Decoder class holds an
// AttackDetectionState member (see decoder.hpp's attack_state_), so including it back here would
// be circular. Every observe_*() method below takes exactly the fields it needs (a
// src_ip/dst_ip string, a notes vector to append to) rather than the whole DecodedPacket, the
// same narrow-interface posture DecodeContext::ip_src_addr (protocol_decoder.hpp) already
// established for an analogous one-off need.

namespace conduitscope {

// RFC 791 section 3.1 option kind bytes -- Loose Source and Record Route / Strict Source and
// Record Route. Confirmed against Juniper's own "Attacker Evasion Techniques" documentation
// (option 3 = loose, option 9 = strict -- the low-order 5 bits of these two kind bytes,
// consistent with the standard copy=1/class=0 encoding).
constexpr uint8_t IP_OPT_LOOSE_SOURCE_ROUTE = 0x83;
constexpr uint8_t IP_OPT_STRICT_SOURCE_ROUTE = 0x89;

// See this file's own header comment above for why this number is a documented judgment call,
// not a vendor-sourced default -- overridable via DecodeOptions::flood_threshold / the CLI's
// --flood-threshold. Chosen empirically, not arbitrarily: this codebase's own test fixtures
// legitimately pack many distinct request/response exchanges into ONE long-running session against
// two fixed dummy hosts (e.g. sample_samr_lsarpc.pcap sends 79 TCP packets total to one
// destination across several SMB pipes on that one connection; sample_hartip.pcap sends 65 UDP
// packets to one destination, mostly repeated polling from the SAME source port -- a perfectly
// normal HART-IP command/response pattern, not a flood). 100 was picked as the smallest round
// number comfortably clear of every such fixture in this codebase as of this addition, found by
// sweeping every tests/sample_*.pcap file's own per-destination packet counts -- still small
// relative to a genuine flood (hundreds to thousands of packets), but large enough that today's
// legitimate multi-exchange fixtures don't trip it. A future fixture with more packets to one
// destination than this could still collide; --flood-threshold is the escape valve.
constexpr size_t DEFAULT_FLOOD_THRESHOLD = 100;

// Scans raw IP option bytes (Ipv4Header::options) for IP_OPT_LOOSE_SOURCE_ROUTE or
// IP_OPT_STRICT_SOURCE_ROUTE, honoring each option's own length byte so a later option's kind
// byte is never misread as this one. The two single-byte options (0x00 End of Option List, 0x01
// No Operation) are the only kinds with no length byte; every other kind is
// [kind][length][length-2 bytes of data]. Malformed/truncated option bytes (a length byte that
// would run past the end of `options`) stop the scan early and return false rather than throwing
// -- best-effort, matching this codebase's general parse-degrades-gracefully posture elsewhere.
bool ipv4_has_source_route_option(const std::vector<uint8_t>& options);

// Per-destination volumetric counters -- see this file's own header comment for the "whole-file
// count, not a rate" scoping decision. tcp_count increments on every TCP packet regardless of
// flags (a broad catch-all, not a sourced named signature -- see header comment); syn_count/
// ack_count are the flag-specific subsets (SYN-without-ACK / ACK-without-SYN). A real SYN flood
// will therefore also cross tcp_count's own threshold, which is expected overlap, not a bug.
struct FloodCounters {
    size_t syn_count = 0, ack_count = 0, tcp_count = 0, icmp_echo_count = 0, udp_count = 0;
    bool syn_flagged = false, ack_flagged = false, tcp_flagged = false, icmp_flagged = false,
         udp_flagged = false;
};

// One IP datagram's most recently seen fragment, for Teardrop's pairwise overlap check -- see
// this file's own header comment on why only the single most recent fragment (not full
// reassembly state) is kept per key.
struct FragmentTrackEntry {
    size_t start = 0;  // byte offset into the reassembled datagram (fragment_offset * 8)
    size_t end = 0;    // start + this fragment's own payload length
};

struct FragmentTrackKey {
    uint32_t src_addr = 0, dst_addr = 0;
    uint8_t protocol = 0;
    uint16_t identification = 0;
    bool operator==(const FragmentTrackKey& other) const {
        return src_addr == other.src_addr && dst_addr == other.dst_addr &&
               protocol == other.protocol && identification == other.identification;
    }
};

struct FragmentTrackKeyHash {
    size_t operator()(const FragmentTrackKey& k) const {
        size_t h = std::hash<uint32_t>()(k.src_addr);
        h = h * 31 + std::hash<uint32_t>()(k.dst_addr);
        h = h * 31 + std::hash<uint8_t>()(k.protocol);
        h = h * 31 + std::hash<uint16_t>()(k.identification);
        return h;
    }
};

// Owned directly by Decoder (see decoder.hpp's Decoder::attack_state_), NOT a DecoderFlowState --
// unlike every other stateful decoder in this codebase, this state is not scoped to one protocol
// id's own session/flow keying (DecodeContext::flow_state<T>()); it needs to see every IPv4/TCP/
// UDP/ICMP packet regardless of which application-layer protocol eventually claims it, and its
// own two maps are keyed by IP-layer identity (a fragment key, a destination address), not by a
// TCP/UDP session. Both maps are bounded (kMaxTrackedEntries) with the same "evict some existing
// entry, not necessarily the oldest" tradeoff DecodeContext::flow_state<T>()'s own eviction logic
// documents -- see its comment in protocol_decoder.hpp for the identical reasoning.
class AttackDetectionState {
public:
    // Configured from DecodeOptions::flood_threshold once, by Decoder's constructor.
    size_t flood_threshold = DEFAULT_FLOOD_THRESHOLD;

    // Called once per IPv4 packet, right after parse_ipv4() -- before any TCP/UDP/ICMP-specific
    // dispatch. Handles IP Source Routing (single packet), Ping of Death (single packet, last-
    // fragment structural check), and Teardrop (this fragment vs. the one most recently seen for
    // the same datagram). Appends notes directly to `notes`.
    void observe_ipv4(const Ipv4Header& ip, std::vector<std::string>& notes);

    // Called right after parse_tcp() succeeds, before any application-layer TCP dispatch. Handles
    // LAND, WinNuke, and the SYN/ACK/TCP-generic flood counters (keyed by dst_ip).
    void observe_tcp(const TcpSegment& tcp, const std::string& src_ip, const std::string& dst_ip,
                      std::vector<std::string>& notes);

    // Called right after parse_udp() succeeds. Handles Fraggle and the UDP flood counter.
    void observe_udp(const UdpDatagram& udp, const std::string& dst_ip,
                      std::vector<std::string>& notes);

    // Called right after a successful ICMP decode. Handles Smurf, ICMP Redirect, and the ICMP
    // (Echo Request) flood counter.
    void observe_icmp(const IcmpMessage& msg, const std::string& dst_ip,
                       std::vector<std::string>& notes);

private:
    static constexpr size_t kMaxTrackedEntries = 4096;

    std::unordered_map<FragmentTrackKey, FragmentTrackEntry, FragmentTrackKeyHash> fragments_;
    std::unordered_map<std::string, FloodCounters> flood_counts_;  // keyed by destination IP string

    // Shared eviction helper, same "erase whichever entry begin() happens to land on" tradeoff as
    // DecodeContext::flow_state<T>()'s own cap (protocol_decoder.hpp) -- the security/memory-bound
    // property (never exceeds kMaxTrackedEntries) holds regardless of which entry is picked.
    template <typename MapT>
    static void evict_if_full(MapT& map) {
        if (map.size() >= kMaxTrackedEntries && !map.empty()) {
            map.erase(map.begin());
        }
    }

    // Shared by observe_tcp/observe_udp/observe_icmp's own flood-counting tail. Returns nullptr
    // for a broadcast-looking destination (see attack_detect.cpp's looks_like_broadcast) -- a
    // flood, by definition, targets ONE specific host; a broadcast address's packet count instead
    // reflects however many services on the segment happen to legitimately use it (BACnet's own
    // routine BVLC Original-Broadcast-NPDU traffic is exactly this shape, and was the real cause
    // of an early false collision this file's own mandatory manual-verification step caught
    // against sample_bacnet.pcap -- see attack_detect.cpp's own comment). Smurf/Fraggle already
    // cover the "broadcast address is itself the anomaly" case separately.
    FloodCounters* flood_counters_for(const std::string& dst_ip);
};

}  // namespace conduitscope
