// SPDX-License-Identifier: Apache-2.0
// asset_inventory.hpp - passive OT asset inventory: infers a first-draft zone/conduit model from a
// capture, the opposite direction from `policy validate` -- instead of checking observed traffic
// against a hand-written policy, this discovers a plausible one from what was actually seen on the
// wire. See the `inventory` subcommand (cli_main.cpp) and docs/MANUAL.md's ROADMAP item 17 for the
// full rationale and prior art (NSA's abandoned GRASSMARLIN, CISA's much heavier Malcolm).
//
// Scope: originally just five protocols (ROADMAP item 17's first pass), widened to match every
// protocol PolicyEngine::observe itself evaluates over TCP -- ten in total: Modbus, DNP3, S7comm (a
// COTP-only session with no S7comm payload still counts, same "cotp folds into s7comm" convention
// PolicyEngine::observe uses -- see AssetInventoryEngine::observe's own comment), EtherNet/IP (both
// explicit messaging over TCP and CIP I/O implicit messaging over UDP/2222 -- decoder.cpp promotes
// both to protocol=="enip", see decoder.hpp), BACnet/IP, IEC 104, HART-IP, OPC UA, MMS, MQTT, and
// FF-HSE.
//
// TWO of those ten (HART-IP, FF-HSE) are deliberately narrower here than what decoder.cpp itself can
// recognize: both protocols can appear over UDP on the wire (HART-IP conventionally; FF-HSE almost
// always, see ffhse.hpp), but PolicyEngine::observe only ever evaluates has_tcp packets into a
// FlowReport -- a UDP HART-IP/FF-HSE conduit inferred here could never actually be checked by
// `policy validate`. Unlike BACnet and CIP I/O (both UDP-only protocols, counted here anyway with an
// explicit "cannot be exercised" caveat in write_inventory_policy_yaml's generated comment -- see
// that function's own doc comment below), HART-IP and FF-HSE packets are simply skipped (folded into
// skipped_packets, same as any other unrecognized packet) unless dp.has_tcp -- see
// AssetInventoryEngine::observe's own comment for exactly where this guard sits. In practice this
// means FF-HSE will almost never show up in an inventory report at all (real FF-HSE traffic is
// UDP), and only genuinely TCP-carried HART-IP traffic will.
//
// Every other protocol this project decodes (PROFINET RT, GOOSE, Sampled Values, EtherCAT, STP,
// DeviceNet, and the whole DNS/routing-protocol family) is still not counted here -- none of those
// are in PolicyEngine's own ten-protocol IP-flow list either (PROFINET RT/GOOSE/SV/EtherCAT are
// evaluated by VLAN zone instead, a completely different mechanism this feature doesn't model at
// all). Widening further, or adding VLAN-zone-style inventory, is future work (see
// docs/MANUAL.md's ROADMAP), deliberately deferred so this pass's deterministic pcap-to-model
// pipeline stands on its own before anything else (including an LLM-assisted zone-naming suggestion,
// also explicitly out of scope for this pass) is layered on top.
//
// Pipeline, mirroring PolicyEngine's own three-stage shape (observe per packet, finish() once,
// render):
//   1. AssetInventoryEngine::observe() aggregates each recognized packet into an asset (one per
//      distinct IP address) and an edge (one per distinct client-IP/server-IP/protocol/server-port
//      tuple, aggregated across every TCP session or UDP exchange between that pair -- see
//      InventoryEdge's own comment for exactly how this differs from PolicyEngine's own
//      per-TCP-session FlowReport).
//   2. AssetInventoryEngine::finish() groups every observed asset IP into an inferred zone (by
//      observed /zone_prefix_len subnet -- see InventoryZone's own comment for why subnet alone,
//      not protocol, is this first pass's grouping key) and, from the edges, an inferred conduit
//      per distinct (from_zone, to_zone, protocol, port) tuple actually observed.
//   3. write_inventory_report_text/write_inventory_report_json render the full report (assets,
//      edges, zones, conduits); write_inventory_diagram_mermaid/write_inventory_diagram_dot render
//      just the zone/conduit graph as a diagram; write_inventory_policy_yaml renders the inferred
//      zones/conduits directly as a policy file `policy validate --policy` can load, closing the
//      discover-then-enforce loop ROADMAP item 17 describes.
#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "conduitscope/decoder.hpp"
#include "conduitscope/policy.hpp"  // CidrBlock -- InventoryZone::network reuses it verbatim

namespace conduitscope {

// Forward-declared rather than #include "conduitscope/resolver.hpp" here -- see policy_engine.hpp's
// own identical forward declaration and comment for why: only a `const Resolver&` reference is ever
// needed in this header.
class Resolver;

// The CIDR prefix length AssetInventoryEngine groups observed asset IPs by when the caller doesn't
// override it (`inventory --zone-prefix`) -- /24 matches how most flat OT networks are actually
// subnetted per segment in practice, the same assumption docs/MANUAL.md's ROADMAP item 17 itself
// makes ("observed subnet as a first-pass heuristic").
constexpr uint8_t kDefaultInventoryZonePrefixLen = 24;

// One asset: a distinct IP address that appeared in at least one packet of one of this feature's
// ten recognized protocols. AssetInventoryEngine::finish sorts these numerically by address for a
// report that's deterministic independent of capture order.
struct InventoryAsset {
    std::string ip;
    // The FIRST-seen MAC address for this IP (never overwritten by a later packet, same "first
    // frame/occurrence wins" convention DNP3's headline fields and the --hosts file already use in
    // this codebase) -- false only for a non-Ethernet-linktype capture (raw IP, Linux "cooked
    // capture"). Real OT deployments essentially never see an IP address migrate MAC mid-capture
    // (that would mean a NIC swap, a failover, or ARP spoofing mid-run -- all rare, and arguably
    // worth a human's attention rather than silently averaged over), so first-seen is a deliberate,
    // simple choice, not an attempt to detect or reconcile such a change.
    bool has_mac = false;
    std::string mac;
    // sorted, distinct: "modbus"/"dnp3"/"s7comm"/"enip"/"bacnet"/"iec104"/"hartip"/"opcua"/"mms"/
    // "mqtt"/"ffhse" -- see this file's own header comment for the two (hartip/ffhse) that are
    // TCP-only here despite also being decodable over UDP.
    std::vector<std::string> protocols;
    bool ever_client = false;  // acted as the initiator on at least one observed exchange
    bool ever_server = false;  // acted as the responder on at least one observed exchange
    size_t packet_count = 0;   // total packets (either direction) this IP appeared in
};

// One aggregated, directional communication: `client_ip` -> `server_ip`, every packet of ONE
// protocol at ONE server port, aggregated across every TCP session (or, for the two UDP-based
// protocols here, every exchange) between that pair. This is DELIBERATELY coarser than
// PolicyEngine's own FlowReport, which keys by the full 4-tuple (so a client reconnecting with a
// new ephemeral port becomes a separate flow there) -- an inventory answers "does X talk to Y over
// protocol P at all," not "how many separate sessions did X open to Y," which is the session-level
// question `policy validate` already answers. See AssetInventoryEngine::observe's own comment for
// exactly how client/server is decided per protocol: a TCP handshake (SYN/SYN-ACK, falling back to
// a known-port heuristic, same priority order as PolicyEngine::observe) for every TCP-based
// protocol here (modbus/dnp3/s7comm/enip explicit messaging/iec104/hartip/opcua/mms/mqtt/ffhse), and,
// for BACnet specifically, the request/response APDU type -- BACnet's client and
// server both conventionally listen on the SAME port (47808), so the usual "known port vs.
// ephemeral port" heuristic can't distinguish them at all; see observe()'s own comment.
struct InventoryEdge {
    std::string client_ip, server_ip;
    std::string protocol;  // "modbus"/"dnp3"/"s7comm"/"enip"/"bacnet"/"iec104"/"hartip"/"opcua"/"mms"/"mqtt"/"ffhse"
    uint16_t server_port = 0;
    // Distinct, non-empty function/service names observed on this edge, sorted -- the same source
    // fields FlowReport::observed_functions documents (policy_engine.hpp), restricted to this
    // feature's five protocols.
    std::vector<std::string> observed_functions;
    size_t packet_count = 0;
    // Which tier decided client_ip/server_ip above, the most authoritative ever observed across
    // every session (or, for BACnet, packet) this edge aggregates -- see DirectionSource's own
    // comment (decoder.hpp), docs/MANUAL.md's ROADMAP item 19, and direction_source_rank's own
    // comment (asset_inventory.cpp) for exactly how "most authoritative" is decided when more than
    // one contributes.
    DirectionSource direction_source = DirectionSource::PortHeuristic;
};

// One inferred zone: every observed asset IP that falls in the same `network` (a
// /zone_prefix_len CIDR block -- see AssetInventoryEngine's constructor) is grouped into one zone.
// This is the "observed subnet" half of ROADMAP item 17's "grouped by protocol and/or observed
// subnet" heuristic -- see AssetInventoryEngine::finish's own comment for why subnet alone, not
// protocol, is this first pass's grouping key (protocol-based grouping is left as explicitly
// tracked future work, not implemented here).
struct InventoryZone {
    std::string name;      // deterministic, from the network itself: "zone_192_168_1_0_24"
    CidrBlock network;
    std::vector<std::string> member_ips;  // sorted (numeric), the asset IPs inside this zone
};

// One inferred conduit: at least one InventoryEdge was observed from some asset in `from_zone` to
// some asset in `to_zone`, using `protocol` at `port`. AssetInventoryEngine::finish emits one
// InventoryConduit per distinct (from_zone, to_zone, protocol, port) tuple actually exercised --
// UNLIKE `policy validate`'s report, which lists every conduit a hand-written policy declares
// whether or not a capture ever exercised it (PolicyReport::unexercised_conduits exists precisely
// to call that out): there is no hand-written policy here, only what was actually observed, so
// there is nothing to report as "declared but unexercised."
struct InventoryConduit {
    std::string name;  // "<from_zone> -> <to_zone> (<protocol>/<port>)"
    std::string from_zone, to_zone;
    std::string protocol;
    uint16_t port = 0;
    size_t edge_count = 0;    // distinct client/server IP pairs this conduit summarizes
    size_t packet_count = 0;  // total packets across every one of those edges
};

struct AssetInventoryReport {
    std::vector<InventoryAsset> assets;      // sorted by IP address
    std::vector<InventoryEdge> edges;        // first-seen order
    std::vector<InventoryZone> zones;        // sorted by network address
    std::vector<InventoryConduit> conduits;  // sorted by (from_zone, to_zone, protocol, port)
    // The CIDR prefix length zones were grouped by (AssetInventoryEngine's constructor argument),
    // recorded here so report consumers (write_inventory_report_text's "grouped by observed /N
    // subnet" header, in particular) can always show the configured value, even when `zones` is
    // empty and there is no InventoryZone::network to read it from instead.
    uint8_t zone_prefix_len = kDefaultInventoryZonePrefixLen;
    size_t total_packets = 0;
    // Packets that were not one of the ten recognized protocols, had no IPv4 layer at all, or were
    // a HART-IP/FF-HSE packet seen over UDP (deliberately excluded -- see this file's own header
    // comment) -- never part of any asset/edge above. Mirrors PolicyReport::skipped_non_tcp's own role, though
    // the two aren't computed the same way: policy validate only ever looks at TCP; this counts a
    // recognized BACnet/CIP-I/O UDP packet as NOT skipped, unlike PolicyReport::skipped_non_tcp,
    // which would count that same packet as skipped (`policy validate` doesn't evaluate any UDP
    // traffic yet -- see docs/MANUAL.md's LIMITATIONS).
    size_t skipped_packets = 0;
};

class AssetInventoryEngine {
public:
    // zone_prefix_len: the CIDR prefix length ([0, 32]) inferred zones are grouped by -- see
    // InventoryZone's own comment. Not validated here (cli_main.cpp's CLI11 ->check(CLI::Range(0,
    // 32)) enforces the range before this constructor ever runs, the same "CLI validates, the
    // engine trusts" division of responsibility PolicyEngine/Resolver already follow).
    explicit AssetInventoryEngine(uint8_t zone_prefix_len = kDefaultInventoryZonePrefixLen);

    // Folds one already-decoded packet into this engine's asset/edge state. Call once per packet,
    // in capture order (same discipline as Decoder::decode/PolicyEngine::observe). A packet whose
    // protocol isn't one of this feature's ten recognized ones, that has no IPv4 layer at all, or
    // that is a HART-IP/FF-HSE packet seen over UDP (see this file's own header comment), only
    // increments skipped_packets -- see AssetInventoryReport::skipped_packets' own comment.
    //
    // Client (initiator) vs. server, per protocol:
    //   - modbus/dnp3/s7comm (including a COTP-only session)/enip explicit messaging/iec104/hartip
    //     (TCP only)/opcua/mms/mqtt/ffhse (TCP only) -- every TCP-based protocol here: exactly
    //     PolicyEngine::observe's own priority order -- a pure SYN packet authoritatively marks its
    //     source as the client, a SYN-ACK authoritatively marks its DESTINATION as the client, and
    //     otherwise whichever endpoint's port is one of this feature's known protocol ports
    //     (502/20000/102/44818/2404) is assumed to be the server, falling back to "lower port number
    //     is the server" when neither or both are known -- and a later SYN/SYN-ACK on the same TCP
    //     session still upgrades an earlier port-guess to the authoritative answer, the same "(3) is
    //     a first-packet fallback, not a decision stuck with once the engine can do better" rule
    //     PolicyEngine::observe documents. Note that HART-IP/OPC UA/MMS/MQTT/FF-HSE's own
    //     conventional ports (5094/4840/102-shared-with-S7comm/1883/1089-91+3622) are deliberately
    //     NOT part of the known-port set -- mirroring PolicyEngine::observe's own is_known_service_
    //     port, which doesn't recognize them either, so this heuristic's answer stays identical
    //     between the two engines for the same flow.
    //   - enip CIP I/O implicit messaging (UDP/2222): no handshake exists at all for a cyclic
    //     producer/consumer datagram, so every packet is decided independently by the same
    //     known-port heuristic alone (falling back to "lower port is the server" when both or
    //     neither port is 2222, e.g. two peers that both happen to use 2222).
    //   - bacnet (UDP/47808): BACnet's client and server BOTH conventionally listen on port 47808,
    //     so the known-port heuristic above can never distinguish them (it would see 47808 as
    //     "known" on both sides and fall through to the numerically-equal-ports tie-break, which is
    //     meaningless here). Instead, when this PDU carries a decoded APDU
    //     (DecodedPacket::bacnet_has_apdu), its own request/response type decides direction: a
    //     Confirmed-Request or Unconfirmed-Request's SOURCE is the client (it's asking); a
    //     Simple-ACK/Complex-ACK/Segment-ACK/Error/Reject/Abort's DESTINATION is the client (it's
    //     the one who asked, being answered). Only when there's no APDU at all (a bare BVLC
    //     function, or an NPDU-only network-layer message) does this fall back to the same
    //     known-port heuristic the other protocols use -- necessarily low-confidence for BACnet
    //     specifically, since it can't actually distinguish anything when both ports are 47808; see
    //     docs/MANUAL.md's LIMITATIONS for this honestly-documented gap.
    //
    // Each edge's own InventoryEdge::direction_source records which of the above tiers
    // (DirectionSource::Handshake for a captured SYN/SYN-ACK, ::Content for BACnet's APDU-type
    // determination, ::PortHeuristic for the known-port/lower-port-number fallback) actually
    // produced its client_ip/server_ip -- the most authoritative one ever observed across every
    // session/packet the edge aggregates, never downgraded once a stronger one is seen. See
    // DirectionSource's own comment (decoder.hpp) and docs/MANUAL.md's ROADMAP item 19 for the full
    // three-tier design record shared with `decode` and `policy validate`.
    //
    // A destination address that looks like an IPv4 broadcast or multicast address (see
    // looks_like_broadcast_or_multicast in asset_inventory.cpp) is never turned into an asset or an
    // edge's server_ip -- BACnet's Who-Is/I-Am discovery traffic in particular is routinely
    // broadcast, and a broadcast address is not a device to inventory. The packet's other,
    // non-broadcast endpoint is still recorded as an asset (with the role -- client or server --
    // this same direction logic assigned it) even when no edge can be formed for the broadcast side.
    void observe(const DecodedPacket& packet);

    // Produces the final report from everything observed so far. Safe to call more than once (e.g.
    // to print a summary and then a detailed report from the same run); does not reset state.
    AssetInventoryReport finish() const;

private:
    struct AssetState {
        bool has_mac = false;
        std::string mac;
        std::unordered_set<std::string> protocols;
        bool ever_client = false;
        bool ever_server = false;
        size_t packet_count = 0;
    };

    struct EdgeState {
        std::string client_ip, server_ip, protocol;
        uint16_t server_port = 0;
        std::unordered_set<std::string> functions;
        size_t packet_count = 0;
        // See InventoryEdge::direction_source's own comment -- mirrored here verbatim.
        DirectionSource direction_source = DirectionSource::PortHeuristic;
    };

    // TCP-session-level state, exactly mirroring PolicyEngine::FlowState's client/server-only
    // fields -- kept separately from EdgeState because many TCP sessions (distinct ephemeral client
    // ports) can fold into the same coarser InventoryEdge; see InventoryEdge's own comment.
    struct TcpSessionState {
        std::string client_ip, server_ip;
        uint16_t server_port = 0;
        bool initiator_known = false;
        // See InventoryEdge::direction_source's own comment -- this session's own tier, before
        // whatever merging observe() does across sessions when folding into EdgeState.
        DirectionSource direction_source = DirectionSource::PortHeuristic;
    };

    void update_asset(const std::string& ip, const DecodedPacket& dp, const std::string& protocol,
                       bool is_client_role);

    uint8_t zone_prefix_len_;
    std::unordered_map<std::string, AssetState> assets_;
    std::vector<std::string> asset_order_;
    std::unordered_map<std::string, EdgeState> edges_;
    std::vector<std::string> edge_order_;
    std::unordered_map<std::string, TcpSessionState> tcp_sessions_;  // keyed by canonical 4-tuple
    size_t total_packets_ = 0;
    size_t skipped_packets_ = 0;
};

// Renders `report` as a human-readable text report to `out`: the asset list, the communication
// matrix (edges), the inferred zones, and the inferred conduits, in that order. `capture_path` is
// shown in the report header purely for context. `resolver` supplies the same OUI/hostname/
// service-name annotations `decode` and `policy validate` already provide (see resolver.hpp) --
// rendered inline, the same convention `write_policy_report_text` uses.
void write_inventory_report_text(std::ostream& out, const AssetInventoryReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

// Renders `report` as JSON to `out`, for scripting/automation. `resolver`: see
// write_inventory_report_text's own comment -- JSON format follows `write_policy_report_json`'s
// convention of a separate named annotation field per lookup, omitted entirely (never `null`) on a
// miss or a disabled lookup. See docs/MANUAL.md's `inventory` section for the exact schema.
void write_inventory_report_json(std::ostream& out, const AssetInventoryReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

// Renders just the zone/conduit graph (not the asset list or communication matrix) as a Mermaid
// flowchart (`graph LR`) to `out` -- one node per zone, one edge per conduit, labeled
// "<protocol>/<port>". Paste into any Mermaid-rendering surface (this project's own Artifact/docs
// tooling, GitHub Markdown, mermaid.live, ...).
void write_inventory_diagram_mermaid(std::ostream& out, const AssetInventoryReport& report);

// Same graph as write_inventory_diagram_mermaid, rendered as Graphviz DOT instead (`dot -Tpng` and
// similar).
void write_inventory_diagram_dot(std::ostream& out, const AssetInventoryReport& report);

// Renders the inferred zones/conduits as a policy file, in exactly the YAML subset policy.hpp's
// parse_policy_text accepts -- the file `write_inventory_policy_yaml` writes is directly loadable
// by `policy validate --policy`, closing ROADMAP item 17's "discover, then enforce" loop. Does NOT
// include the asset list or communication matrix (neither has a place in the policy file format) --
// use write_inventory_report_text/_json for those. See docs/MANUAL.md's ROADMAP item 17 and
// LIMITATIONS for why a conduit inferred from BACnet or EtherNet/IP CIP I/O traffic (both UDP)
// parses and validates fine here but can never actually be exercised by `policy validate` today
// (it only evaluates TCP flows) -- the generated file's own header comment says so too.
void write_inventory_policy_yaml(std::ostream& out, const AssetInventoryReport& report);

}  // namespace conduitscope
