// SPDX-License-Identifier: Apache-2.0
// policy_engine.hpp - evaluates decoded packets (DecodedPacket, from
// Decoder) against a parsed zone/conduit Policy (policy.hpp), for the
// `policy validate` command.
//
// This is a separate layer built entirely on top of Decoder's already-public
// output -- it doesn't change how packets are decoded, and Decoder/
// DecodedPacket have no knowledge of it. PolicyEngine aggregates the
// decoded-packet stream into TCP flows (one per distinct 4-tuple, direction-
// agnostic) and, once the whole capture has been fed through, checks each
// flow's (client zone, server zone, protocol(s) observed, server port)
// against the policy's conduits. Feed it one DecodedPacket at a time, in
// capture order, via observe(); call finish() once to get the final
// PolicyReport. See docs/MANUAL.md's POLICY FILE FORMAT and 'policy
// validate' sections for the semantics in prose, and cli_main.cpp for how
// this is wired into the command.
#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "conduitscope/decoder.hpp"
#include "conduitscope/policy.hpp"

namespace conduitscope {

// Forward-declared rather than #include "conduitscope/resolver.hpp" here: this header only ever
// needs a `const Resolver&` reference (in the two free function declarations at the bottom), never
// any of its members, so a full include would be an unnecessary compile-time dependency for every
// translation unit that just wants PolicyEngine/PolicyReport. See resolver.hpp's own file header
// for why this OUI/hostname/service-name annotation now reaches `policy validate`'s report too --
// it was originally scoped out there, but the same Resolver instance decode's writers already use
// is now threaded through here as well (see write_policy_report_text/write_policy_report_json).
class Resolver;

enum class FlowVerdict {
    Allowed,        // a conduit permits this flow's protocol(s) at this port, in this direction,
                    // and (if that conduit restricts 'functions') every function/service observed
                    // on the flow
    Violation,      // both endpoints are zone-classified, but no conduit permits this flow -- OR
                    // one does on protocol/port/direction, but restricts 'functions' and at least
                    // one function/service observed on the flow isn't in its allow-list
    Unclassified,   // at least one endpoint matched no declared zone, or no app-layer protocol was
                    // ever recognized on this flow -- there's nothing to check against a conduit
};

// One observed TCP flow (both directions of one 4-tuple, aggregated), summarized for reporting.
// "client"/"server" are PolicyEngine's best determination of which endpoint initiated the
// connection -- see PolicyEngine::observe's doc comment for exactly how that's decided.
struct FlowReport {
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string client_zone, server_zone;  // "unclassified" when Policy::zone_for found nothing
    std::vector<std::string> protocols;    // distinct app protocols observed: "modbus"/"dnp3"/"s7comm"/
                                            // "iec104"/"enip"/"hartip"/"opcua"/"mms"/"mqtt"/"ffhse"
                                            // (never "bacnet" -- see PolicyEngine::observe)
    // Distinct, non-empty function/service names observed on this flow, sorted -- whichever of
    // modbus_function_name/dnp3_function_name/s7comm_function_name/iec104_asdu_type_short_name/
    // enip_cip_service_name/hartip_message_type/opcua_service_name/mms_service_name/
    // mqtt_packet_type_name/ffhse_message_name each contributing packet's own protocol populates
    // (see PolicyEngine::observe). Populated regardless of whether the matched conduit (if any)
    // actually restricts 'functions' -- purely informational/scriptable via the JSON report when it
    // doesn't (see write_policy_report_json), and exactly what a functions-restricted conduit's
    // match (or the reason it didn't match) is computed from when it does -- though today that
    // restriction mechanism (a conduit's own 'functions' list) only ever validates against modbus/
    // dnp3/s7comm/iec104/enip (see policy.cpp's protocol_has_known_function_table); the last five
    // protocols above still populate this field for reporting, just can't be filtered by it yet.
    std::vector<std::string> observed_functions;
    size_t packet_count = 0;
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed: why, for the report

    // Which tier decided client_ip/server_ip above -- see DirectionSource's own comment
    // (decoder.hpp) for the full three-tier definition and docs/MANUAL.md's ROADMAP item 19 for
    // the design record. Set from PolicyEngine::observe's own SYN/SYN-ACK/port-heuristic branching
    // (this flow's protocols are always TCP-based here, so Content never occurs in a FlowReport --
    // BACnet, the only Content case in this codebase, is UDP-only and never reaches PolicyEngine at
    // all, see observe()'s own comment).
    DirectionSource direction_source = DirectionSource::PortHeuristic;

    // client_mac/server_mac: the same Ethernet source addressing decode's own DecodedPacket::
    // src_mac/dst_mac carries, attributed to whichever side PolicyEngine decided is the client/
    // server (see PolicyEngine::observe's doc comment) -- has_mac is false, and both strings stay
    // empty, only for a capture whose link type isn't Ethernet at all (DecodedPacket::has_ethernet
    // false for every packet on this flow; see decoder.hpp), which is rare but not impossible (a
    // raw-IP or Linux "cooked capture" pcap). This is purely a base-value addition (mirroring
    // decode's own src_mac/dst_mac gap-fix in output.cpp), independent of whether OUI resolution is
    // even enabled -- a Resolver is only needed to turn this MAC into a vendor annotation, not to
    // populate it in the first place.
    bool has_mac = false;
    std::string client_mac, server_mac;
};

// One observed raw-Ethernet "L2 flow" -- PROFINET RT, GOOSE, Sampled Values, or EtherCAT traffic
// between one pair of MAC addresses, aggregated the same way FlowReport aggregates a TCP 4-tuple,
// but keyed and evaluated completely differently: there is no port, no client/server distinction
// (no SYN, no session -- these protocols are cyclic/multicast publish traffic, not a connection),
// and the "zone" question is VLAN membership, not IP CIDR membership -- see policy.hpp's own
// header comment for the full "why" and PolicyEngine::observe's comment for exactly when this
// report is even populated at all (only once the policy declares at least one VLAN zone).
struct EthernetFlowReport {
    std::string protocol;         // "profinet"/"goose"/"sv"/"ethercat"
    std::string mac_a, mac_b;     // canonical order (mac_a < mac_b) -- no "source"/"destination"
                                   // distinction is tracked, since neither MAC decides zone
                                   // membership here (see vlan_zone below)
    bool has_vlan_tag = false;
    uint16_t vlan_id = 0;         // meaningful only when has_vlan_tag
    std::string vlan_zone;        // "unclassified" when has_vlan_tag is false, or no declared VLAN
                                   // zone contains vlan_id
    size_t packet_count = 0;
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed: why, for the report
};

// One aggregated observation of a Tier 1-5 "IT protocol an OT auditor flags" (ROADMAP item 18;
// notable_it_protocols.hpp names the exact 43 protocol values and their tier) -- recorded
// independent of, and never affecting, this flow/L2-flow's own Allowed/Violation/Unclassified
// verdict above: an interactive-access or tunneling protocol reaching an OT zone is itself worth
// flagging even inside a technically "compliant" policy that happened to allow it (this item's own
// framing) -- see PolicyEngine::observe's own comment for exactly when this is recorded, and
// PolicyReport::notable_protocols for the aggregation key.
//
// Unlike FlowReport, this needs no per-session state to compute client_ip/server_ip: every one of
// these 43 protocols' own ports are guaranteed to never be "known" to this file's own
// is_known_service_port (that list is exclusively the five core OT protocol ports), so the same
// SYN/SYN-ACK-first, lower-port-number-otherwise priority order PolicyEngine::observe already uses
// for an ordinary TCP flow degenerates, for these protocols, to exactly the same "lower port is
// assumed the server" heuristic asset_inventory.cpp's own src_is_client_by_port independently
// documents for this exact shape -- reused here rather than reimplemented, and, for a TCP-based
// notable protocol, actually computed from the SAME per-session FlowState PolicyEngine::observe was
// going to compute anyway (so a TCP notable protocol's direction is exactly as authoritative as its
// own FlowReport's -- SYN/SYN-ACK when captured, the port heuristic otherwise).
struct NotableProtocolFinding {
    std::string protocol;  // one of notable_it_protocols.hpp's 43 values, e.g. "rdp"/"ssh"/"gre"
    std::string tier;      // "remote-access"/"lateral-movement"/"enterprise-trust"/
                            // "wireless-backhaul"/"tunnel-vpn" -- see notable_it_protocol_tier
    bool has_ip = true;    // false only for eapol/pppoe/mpls (EtherType-keyed, no IP layer at all --
                            // see mac_a/mac_b below instead of client_ip/server_ip)
    bool direction_known = false;  // true only for a TCP-based protocol whose flow captured an
                                    // actual SYN/SYN-ACK (DirectionSource::Handshake) -- see
                                    // client_ip/server_ip's own comment for what this means when
                                    // false
    std::string client_ip, server_ip;  // meaningful only when has_ip. When direction_known is
                                        // false, these are still a best-effort client/server guess
                                        // (the lower-port-number heuristic above), not a confirmed
                                        // direction -- render/consume accordingly (see
                                        // write_policy_report_text/_json's own "(port heuristic)"
                                        // annotation for exactly how this is surfaced)
    std::string mac_a, mac_b;  // meaningful only when !has_ip (eapol/pppoe/mpls) -- canonical order
                                // (mac_a < mac_b), the same no-direction convention
                                // EthernetFlowReport::mac_a/mac_b already uses for these same three
                                // protocols' architectural siblings (PROFINET/GOOSE/SV/EtherCAT)
    bool has_port = false;  // false only for an IP-protocol-number-keyed Tier 5 tunnel (gre/esp/ah/
                             // ip-in-ip/6in4/l2tp's direct-IP form) and for eapol/pppoe/mpls, none of
                             // which have a port at all
    bool is_tcp = false;     // meaningful only when has_port -- which transport `port` was observed
                              // over, so a hostname/service-name annotation (write_policy_report_text/
                              // _json) queries the Resolver with the right protocol string
    uint16_t port = 0;      // meaningful only when has_port
    size_t packet_count = 0;
};

struct PolicyReport {
    std::vector<FlowReport> flows;  // one per observed TCP flow, in first-seen order
    // One per observed raw-Ethernet L2 flow (PROFINET RT/GOOSE/SV/EtherCAT), in first-seen order --
    // only ever non-empty when the policy declares at least one VLAN zone (Zone::is_vlan_zone);
    // otherwise this traffic stays folded into skipped_non_tcp below, exactly as it was before
    // VLAN zones existed (ROADMAP item 15) -- see PolicyEngine::observe's own comment for why.
    std::vector<EthernetFlowReport> ethernet_flows;
    // Conduits declared in the policy that no observed flow ever matched -- informational only
    // (doesn't affect compliant()); useful for pruning a policy file or noticing a conduit that
    // was supposed to be exercised by this capture but wasn't. Spans both `flows` and
    // `ethernet_flows` -- a VLAN-zone conduit no L2 flow ever matched appears here exactly like an
    // IP-zone conduit no TCP flow ever matched.
    std::vector<std::string> unexercised_conduits;
    size_t skipped_non_tcp = 0;  // packets with has_ip==false or has_tcp==false (including UDP),
                                  // and NOT one of PROFINET RT/GOOSE/SV/EtherCAT (see ethernet_flows
                                  // above) -- or one of those four but the policy declares no VLAN
                                  // zone at all: not part of any evaluated flow -- see
                                  // PolicyEngine::observe
    size_t total_packets = 0;

    // "IT protocols an OT auditor flags" (ROADMAP item 18), one entry per distinct (protocol,
    // client/server or MAC pair, port) combination observed, in first-seen order -- ALWAYS
    // populated, spanning every transport shape these 43 protocols use (ordinary TCP flows already
    // counted in `flows` above, UDP, an IP-protocol-number directly on IP, or raw Ethernet by
    // EtherType), and completely independent of `flows`/`ethernet_flows`/`compliant()` above: a
    // notable protocol observed on an otherwise Allowed, Violation, or Unclassified flow is recorded
    // here exactly the same way regardless of that flow's own verdict, and this list's own
    // population never changes that verdict. See NotableProtocolFinding's own comment for the
    // aggregation, and cli_main.cpp's `--strict-it-protocols` flag (policy validate only) for the
    // opt-in way a non-empty list here CAN additionally affect the process exit code, without ever
    // touching compliant() itself -- deliberately kept out of compliant() so a caller of this struct
    // directly (or the JSON report's own "compliant" field) always sees the same protocol/port/
    // conduit-allow-list-only verdict this engine has always computed, per Jurgen's own explicit
    // "always flag, independent of compliance" design choice for this item.
    std::vector<NotableProtocolFinding> notable_protocols;

    // Every count below spans both `flows` and `ethernet_flows` -- an L2 flow's verdict counts
    // exactly like a TCP flow's for compliance purposes; there is no separate "ethernet compliant"
    // notion, one capture is either COMPLIANT or it isn't.
    size_t allowed_count() const;
    size_t violation_count() const;
    size_t unclassified_count() const;
    // True only when every observed flow (TCP or L2) was explicitly Allowed -- any Violation OR any
    // Unclassified flow makes this false, since "traffic between addresses this policy doesn't
    // even classify" is itself a finding worth surfacing in an audit, not something to pass
    // silently. See cli_main.cpp for how this maps to `policy validate`'s exit code.
    bool compliant() const { return violation_count() == 0 && unclassified_count() == 0; }
};

class PolicyEngine {
public:
    explicit PolicyEngine(const Policy& policy)
        : policy_(policy), any_vlan_zone_(policy.has_vlan_zone()) {}

    // Folds one already-decoded packet into this engine's per-flow state. Call once per packet, in
    // capture order (same discipline as Decoder::decode).
    //
    // Packets with protocol == "profinet"/"goose"/"sv"/"ethercat" are folded into an L2 flow
    // (PolicyReport::ethernet_flows) instead of the TCP-flow path below, but ONLY when the policy
    // declares at least one VLAN zone (`any_vlan_zone_`, cached from Policy::has_vlan_zone at
    // construction) -- when it doesn't, this traffic is left in PolicyReport::skipped_non_tcp
    // exactly as it was before VLAN zones existed (ROADMAP item 15), so a policy file written
    // before this feature existed can never have its compliance verdict change just because a
    // capture happens to also contain some raw-Ethernet OT traffic that policy's author never
    // wrote a single conduit to address (see policy.hpp's Policy::has_vlan_zone comment). An L2
    // flow is keyed by (protocol, canonical MAC pair) -- there is no port, and no client/server
    // concept (no SYN, no session; see EthernetFlowReport's own comment) -- and classified by
    // whether its VLAN tag (if any) falls in a declared VLAN zone, not by IP.
    //
    // Every other packet with has_ip==false or has_tcp==false (non-IP, non-TCP -- including UDP,
    // which `decode` now recognizes and reports on but this engine does not yet evaluate against
    // any conduit, see docs/MANUAL.md's ROADMAP -- or a parse-error packet) isn't part of any TCP
    // flow either and is only counted toward PolicyReport::skipped_non_tcp -- this tool only ever
    // checks TCP-based OT protocols (plus, now, VLAN-zoned raw-Ethernet OT protocols) against a
    // policy's conduits, so there's nothing further to evaluate for them yet.
    //
    // Independent of all of the above: a packet whose protocol is one of notable_it_protocols.hpp's
    // 43 "IT protocols an OT auditor flags" (ROADMAP item 18) is ALSO recorded into
    // PolicyReport::notable_protocols, regardless of which branch above it falls into -- a TCP-based
    // one (rdp/vnc/smb/ssh/http/https/ldap/ldaps/tacacs-plus/openvpn/stt) is both folded into this
    // flow's own FlowState exactly as before (still Unclassified there today, see finish()'s
    // fs.protocols.empty() branch) AND recorded as its own NotableProtocolFinding; a UDP/IP-protocol-
    // number/EtherType-keyed one (every other tier-1-5 protocol, none of which this engine's TCP-flow
    // model evaluates at all) is recorded ONLY as a NotableProtocolFinding, with
    // PolicyReport::skipped_non_tcp still incremented for it exactly as before this feature existed
    // -- this is a strictly additive observation, never a change to what skipped_non_tcp/FlowState/
    // EthernetFlowState count. See NotableProtocolFinding's own comment for how client_ip/server_ip
    // (or mac_a/mac_b) get decided for each of these transport shapes.
    //
    // Client (initiator) vs. server is decided, per TCP flow, the first time that flow is seen able
    // to decide it:
    //   1. A pure SYN packet (tcp_flags == "SYN") authoritatively marks its source as the client.
    //   2. A SYN-ACK packet (tcp_flags starts with "SYN,ACK") authoritatively marks its
    //      DESTINATION as the client (it's the server's reply to a SYN this engine may not have
    //      seen, e.g. a capture that starts mid-handshake).
    //   3. Otherwise, whichever endpoint's port is one of the five IANA-registered OT protocol
    //      ports (502/20000/2404/102/44818) is assumed to be the server; if neither or both are, the endpoint
    //      with the lower port number is assumed to be the server (a common networking convention:
    //      ephemeral client ports are almost always higher).
    // If the first packet seen for a flow can't be decided by (1) or (2) and falls back to (3), a
    // LATER packet on the same flow that does carry a SYN/SYN-ACK still upgrades the flow's
    // client/server assignment to the authoritative answer -- (3) is a first-packet fallback, not
    // a decision this engine sticks with once it can do better.
    //
    // FlowState::direction_source (and FlowReport::direction_source in the final report) records
    // which of the three steps above actually decided it: DirectionSource::Handshake for (1)/(2),
    // DirectionSource::PortHeuristic for (3) -- upgraded to Handshake too, the moment a later
    // SYN/SYN-ACK is seen, exactly when client_ip/server_ip themselves are upgraded. See
    // DirectionSource's own comment (decoder.hpp) for the full three-tier definition shared with
    // `decode` and `inventory`, and docs/MANUAL.md's ROADMAP item 19 for the design record.
    void observe(const DecodedPacket& packet);

    // Produces the final report from everything observed so far. Safe to call more than once (e.g.
    // to print a summary and then a detailed report from the same run); does not reset state.
    PolicyReport finish() const;

private:
    struct FlowState {
        std::string client_ip, server_ip;
        uint16_t server_port = 0;
        bool initiator_known = false;  // true once decided by an actual SYN/SYN-ACK, not the port guess
        std::unordered_set<std::string> protocols;
        // Distinct, non-empty function/service names observed on this flow so far -- see
        // FlowReport::observed_functions' comment for exactly which DecodedPacket field feeds this
        // per protocol.
        std::unordered_set<std::string> functions;
        // See FlowReport::direction_source's own comment -- mirrored here verbatim, set/refreshed
        // exactly where client_ip/server_ip are (both the initial-packet guess and the later-SYN
        // upgrade, see PolicyEngine::observe).
        DirectionSource direction_source = DirectionSource::PortHeuristic;
        size_t packet_count = 0;
        // See FlowReport::has_mac/client_mac/server_mac's own comment -- mirrored here verbatim,
        // set/refreshed exactly where client_ip/server_ip are (both the initial-packet guess and the
        // later-SYN upgrade, see PolicyEngine::observe).
        bool has_mac = false;
        std::string client_mac, server_mac;
    };

    // Aggregated state for one L2 flow (protocol + canonical MAC pair) -- see EthernetFlowReport's
    // own comment for why this has neither a port nor a client/server distinction.
    struct EthernetFlowState {
        std::string protocol;
        std::string mac_a, mac_b;
        bool has_vlan_tag = false;
        uint16_t vlan_id = 0;
        size_t packet_count = 0;
    };

    // Aggregated state for one NotableProtocolFinding -- see that struct's own comment (this is its
    // mutable, still-accumulating counterpart, the same "State suffix while observing, Report/Finding
    // suffix once finish() copies it out" convention FlowState/EthernetFlowState already establish).
    struct NotableProtocolState {
        std::string protocol, tier;
        bool has_ip = true;
        bool direction_known = false;
        std::string client_ip, server_ip;
        std::string mac_a, mac_b;
        bool has_port = false;
        bool is_tcp = false;
        uint16_t port = 0;
        size_t packet_count = 0;
    };

    // Folds one notable-protocol observation into notable_protocols_/notable_protocol_order_, keyed
    // by `key` (already canonicalized by the caller -- see observe()'s own three call sites in
    // policy_engine.cpp for exactly how `key` and every other parameter here are computed for each
    // of the TCP/UDP/IP-protocol-number/EtherType transport shapes). Every field except
    // packet_count is fixed at first-insert (mirrors EdgeState's own "decided once, from the first
    // packet that creates this entry" convention in asset_inventory.cpp, rather than FlowState's own
    // "can still be upgraded by a later SYN/SYN-ACK" one -- a plain per-packet heuristic, not a
    // per-session one, has nothing to upgrade from).
    void record_notable_protocol(const std::string& key, const std::string& protocol, const std::string& tier,
                                  bool has_ip, bool direction_known, const std::string& client_ip,
                                  const std::string& server_ip, const std::string& mac_a, const std::string& mac_b,
                                  bool has_port, bool is_tcp, uint16_t port);

    const Policy& policy_;
    bool any_vlan_zone_;  // cached Policy::has_vlan_zone() -- see observe()'s own comment
    std::unordered_map<std::string, FlowState> flows_;  // keyed by canonical session key
    std::vector<std::string> flow_order_;                // session keys, first-seen order
    std::unordered_map<std::string, EthernetFlowState> ethernet_flows_;  // keyed by canonical L2 flow key
    std::vector<std::string> ethernet_flow_order_;                        // L2 flow keys, first-seen order
    std::unordered_map<std::string, NotableProtocolState> notable_protocols_;  // keyed by observe()'s
                                                                                 // own per-shape key
    std::vector<std::string> notable_protocol_order_;  // notable_protocols_ keys, first-seen order
    size_t skipped_non_tcp_ = 0;
    size_t total_packets_ = 0;
};

// Renders `report` as a human-readable, colorless text report to `out`. `capture_path`/
// `policy_path` are shown in the report header purely for context (this function performs no I/O
// of its own). `policy` supplies zone/conduit counts and names referenced in the report.
//
// `resolver` supplies the same OUI (MAC vendor)/hostname/service-name annotations `decode`'s own
// TextWriter already provides (see resolver.hpp) -- a flow's client_ip/server_ip get a hostname
// annotation, server_port gets a service-name annotation, and client_mac/server_mac (when has_mac)
// or an EthernetFlowReport's mac_a/mac_b get an OUI-vendor annotation, all rendered inline right
// after the raw value exactly like decode's own convention: never a replacement, and a lookup miss
// (or a disabled lookup) adds nothing. Pass a default-constructed-equivalent Resolver (all three
// lookups left at their CLI defaults, or all disabled via not passing --oui/--nn with no --resolve) for a
// caller that wants the byte-for-byte pre-annotation report; there is no separate unannotated
// overload, matching decode's own writers, which always take a Resolver too.
//
// `summarize_unclassified` (default false, `--summarize-unclassified` at the CLI layer): when
// true, UNCLASSIFIED TRAFFIC (and, if present, ETHERNET UNCLASSIFIED TRAFFIC) is collapsed --
// flows/L2 flows sharing the same endpoints, port, protocol(s), and zones are grouped into one
// summary line carrying a flow count and total packet count, instead of one full block per
// individual flow. Added after a real, busy capture (a conference-network pcap with well over
// 100,000 distinct TCP flows) produced a text report tens of megabytes and over half a million
// lines long, almost entirely from one reconnecting host pair alone contributing over 16,000
// near-identical entries -- a new TCP flow (and so a new report entry) on every single reconnect,
// even though the underlying PATTERN worth an auditor's attention was the same one repeated. Off by
// default, so nothing about the existing, unsummarized report changes unless this is explicitly
// asked for. VIOLATIONS/ALLOWED (and ETHERNET VIOLATIONS/ETHERNET ALLOWED) are never summarized --
// only the unclassified groups, which is where an uncurated capture's flow count runs away; a
// violation is rare and specific enough that collapsing it would hide, not help. See
// write_unclassified_flow_group_summarized_text's own comment (policy_engine.cpp) for exactly how
// flows are grouped and how each of the two possible unclassified reasons is rendered once grouped.
// Only affects this text renderer -- write_policy_report_json below has no equivalent parameter and
// always lists every flow individually, since JSON output is already structured data a consuming
// script can group/deduplicate itself far more precisely than any fixed grouping key this function
// could choose on its behalf.
void write_policy_report_text(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path,
                               const Resolver& resolver, bool summarize_unclassified = false);

// Renders `report` as JSON to `out`, for scripting/automation (e.g. feeding a NIS2/IEC 62443 audit
// pipeline). See docs/MANUAL.md's POLICY FILE FORMAT section for the exact schema.
//
// `resolver`: see write_policy_report_text's own comment above -- the JSON schema follows decode's
// JsonWriter convention instead of the text convention: each annotation is its own separate named
// field (client_mac_vendor/server_mac_vendor, client_hostname/server_hostname,
// server_port_service, and for ethernet_flows mac_a_vendor/mac_b_vendor) placed alongside the base
// field(s) it annotates, OMITTED ENTIRELY (not emitted as null) on a lookup miss or disabled
// lookup -- see docs/MANUAL.md's POLICY FILE FORMAT "JSON report schema" for the exact field list.
void write_policy_report_json(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path,
                               const Resolver& resolver);

}  // namespace conduitscope
