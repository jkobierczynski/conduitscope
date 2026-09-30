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
#include "conduitscope/security_event_format.hpp"  // write_policy_report_cef/_leef/_syslog

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
    // Purdue Enterprise Reference Architecture level of client_zone/server_zone, exactly as the
    // policy file's own Zone::purdue_level for that zone (see policy.hpp) -- empty when the matched
    // zone didn't declare one, or when the endpoint is "unclassified" (no zone at all). Purely
    // informational, carried through for reporting only -- never read by any matching logic.
    std::string client_zone_purdue_level, server_zone_purdue_level;
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
                                   // distinction is tracked for zone-membership purposes, since
                                   // neither MAC decides VLAN zone membership (see vlan_zone below)
    // The actual transmitting MAC, fixed from the FIRST packet that created this flow's aggregated
    // state (never re-derived per packet) -- unlike a bidirectional TCP session, these are
    // one-directional cyclic publish streams (GOOSE/SV/PROFINET-RT/EtherCAT all work this way), so
    // "the" source is stable and unambiguous for the whole flow, not something that needs a
    // handshake to pin down the way FlowReport::client_ip/server_ip does. Purely additive --
    // doesn't change what mac_a/mac_b already mean (the canonicalized, order-independent pair used
    // for the flow's identity/key); this is the field Conduit::from_macs (Phase 5, see
    // docs/design/policy-engine-zoning.md) is actually checked against in PolicyEngine::finish.
    std::string src_mac;
    bool has_vlan_tag = false;
    uint16_t vlan_id = 0;         // meaningful only when has_vlan_tag
    std::string vlan_zone;        // "unclassified" when has_vlan_tag is false, or no declared VLAN
                                   // zone contains vlan_id
    // Same idea as FlowReport::client_zone_purdue_level -- vlan_zone's own Zone::purdue_level, or
    // empty when unset/unclassified.
    std::string vlan_zone_purdue_level;
    size_t packet_count = 0;
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed: why, for the report
};

// One observed UDP-based IP flow -- BACnet/IP, CIP I/O, HART-IP, or FF-HSE traffic between one
// (client IP, server IP, server port) tuple, aggregated the same way FlowReport aggregates a TCP
// 4-tuple, but WITHOUT a TCP handshake to lean on for client/server direction (see
// PolicyEngine::observe's own comment for exactly how direction is decided per protocol instead).
// Matched against the SAME CIDR/hostname-zone conduits ordinary TCP flows use (see
// PolicyEngine::finish) -- all four are ordinary IP-addressed protocols, just UDP-transported ones,
// so no new zone kind was needed for them (unlike PROFINET RT/GOOSE/SV/EtherCAT, which ride raw
// Ethernet with no IP layer at all and are matched against a VLAN zone instead -- see
// EthernetFlowReport). Only ever populated once the policy opts in by naming
// "bacnet"/"enip"/"hartip"/"ffhse"/"any" on a CIDR- or hostname-zone conduit (see
// Policy::has_udp_eligible_conduit and PolicyEngine::observe's own comment for the full "opt-in per
// conduit" gating rationale) -- a policy that never does stays byte-for-byte unaffected by this
// feature's existence, and this traffic stays folded into PolicyReport::skipped_non_tcp exactly as
// it was before this feature existed. HART-IP and FF-HSE only ever reach this struct over UDP --
// their TCP traffic still folds into an ordinary FlowReport above, exactly like every other
// TCP-based protocol (see PolicyEngine::observe's own dp.has_tcp/dp.has_udp branching).
struct UdpFlowReport {
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string protocol;  // "bacnet", "enip" (CIP I/O), "hartip", or "ffhse" -- never more than one;
                            // see PolicyEngine::observe
    std::string client_zone, server_zone;  // "unclassified" when Policy::zone_for/zone_for_hostname
                                            // found nothing -- see FlowReport::client_zone's own
                                            // comment, matched identically here
    // Same idea as FlowReport::client_zone_purdue_level -- the matched zone's own Zone::purdue_level,
    // or empty when unset/unclassified.
    std::string client_zone_purdue_level, server_zone_purdue_level;
    // Distinct, non-empty function/service names observed on this flow, sorted -- BACnet's own
    // service_choice_name (BacnetApdu::service_choice_name, bacnet.hpp), HART-IP's own
    // message_type_name (HartIpFrame::message_type_name, hartip.hpp), or FF-HSE's own message_name
    // (FfhseFrame::message_name, ffhse.hpp), whichever the flow's protocol is -- populated purely
    // for reporting/scripting use (no conduit can restrict any of these three by 'functions' -- none
    // has a known-function table, see policy.cpp's protocol_has_known_function_table). ALWAYS EMPTY
    // for CIP I/O ("enip" here with server_port == ENIP_IO_UDP_PORT's own traffic shape) -- cyclic
    // producer/consumer I/O has no per-message operation concept at all, so there is nothing to
    // populate; see docs/design/policy-engine-zoning.md's Phase 3 "known limitation" note for what
    // this means for a 'functions'-restricted "enip" conduit that also matches CIP I/O traffic (its
    // restriction simply can't apply to CIP I/O, since there's nothing to check it against -- such a
    // flow is Allowed/Violation purely on protocol+port+zone, same as an unrestricted conduit would
    // produce).
    std::vector<std::string> observed_functions;
    size_t packet_count = 0;
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed: why, for the report

    // Handshake never occurs here (there is no TCP handshake on a UDP flow) -- Content for a flow
    // whose direction was decided from a BACnet Confirmed-/Unconfirmed-Request or ACK/Error/Reject/
    // Abort APDU, a HART-IP Request/Response/Error/NAK message, or an FF-HSE Request/Response/Error
    // frame (see PolicyEngine::observe's own comment), PortHeuristic otherwise (no such content seen
    // yet, a HART-IP Publish/unrecognized-Type FF-HSE frame with nothing authoritative to say, or
    // CIP I/O, which has no request/response concept to decide direction from at all).
    DirectionSource direction_source = DirectionSource::PortHeuristic;

    // Same idea as FlowReport::has_mac/client_mac/server_mac -- mirrored here verbatim.
    bool has_mac = false;
    std::string client_mac, server_mac;
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

// One resolved zone-pair "bridge" a multi-homed asset's declared IPs touch -- see
// MultiHomedAssetFinding's own comment for what this cross-references and why.
struct AssetZonePair {
    std::string zone_a, zone_b;  // canonical order (zone_a < zone_b), deduplicated
    bool covered = false;        // true when some conduit's from_zones/to_zones names zone_a on
                                  // one side and zone_b on the other (either order, ignoring
                                  // 'bidirectional' -- see PolicyEngine::finish's own comment for
                                  // why direction doesn't matter for this check)
};

// One declared multi-homed asset (Phase 6, see policy.hpp's own Asset comment and
// docs/design/policy-engine-zoning.md), cross-referenced against the policy's own declared zones
// and conduits -- computed purely from Policy itself (Policy::assets/zones/conduits), independent
// of any packet capture: PolicyReport::multi_homed_assets is populated identically whether or not
// a single packet was ever observed. Never changes any FlowVerdict -- see PolicyEngine::finish's
// own comment for exactly why this can never turn an otherwise-COMPLIANT capture NON-COMPLIANT.
struct MultiHomedAssetFinding {
    std::string name;
    std::string role;                // exactly Asset::role, verbatim (may be empty)
    std::vector<std::string> ips;    // Asset::ips[i].text, in file order
    std::vector<std::string> zones;  // same index as ips -- resolved zone name, or
                                      // "unclassified" when no declared zone contains that IP
    // Every distinct pair of zones this asset's IPs touch (deduplicated, canonical order),
    // ALWAYS populated -- even when not flagged -- so the report shows this asset's full zone
    // footprint, not just whether something's wrong.
    std::vector<AssetZonePair> zone_pairs;
    // True when this asset's IPs resolve to 2+ distinct zones AND at least one zone_pairs entry
    // is !covered -- an undocumented cross-zone bridge sitting on real equipment (the OWASP OT
    // Top 10 "broken zones from dual-homed HMIs" pattern this feature exists to surface).
    bool flagged = false;
};

// One TCP or UDP flow where either endpoint belongs to a `role: "jump_host"`-tagged asset (Phase
// 6) -- self-contained (duplicates summary data rather than indexing into
// PolicyReport::flows/udp_flows, mirroring NotableProtocolFinding's own convention), and called
// out regardless of that flow's own Allowed/Violation/Unclassified verdict: "remote access via
// jump host" is the pattern being watched for, independent of whether the individual flow happens
// to be policy-compliant. Computed as a post-pass in PolicyEngine::finish, after
// PolicyReport::flows/udp_flows are fully populated.
struct JumpHostFlowFinding {
    std::string asset_name;
    std::string jump_host_ip;      // whichever of client_ip/server_ip belongs to the asset
    bool jump_host_is_client = false;
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string protocol;   // FlowReport::protocols joined with ", ", or UdpFlowReport::protocol
    bool is_udp = false;    // true: this came from PolicyReport::udp_flows; false: ::flows
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed
};

struct PolicyReport {
    std::vector<FlowReport> flows;  // one per observed TCP flow, in first-seen order
    // One per observed raw-Ethernet L2 flow (PROFINET RT/GOOSE/SV/EtherCAT), in first-seen order --
    // only ever non-empty when the policy declares at least one VLAN zone (Zone::kind ==
    // ZoneKind::Vlan);
    // otherwise this traffic stays folded into skipped_non_tcp below, exactly as it was before
    // VLAN zones existed (ROADMAP item 15) -- see PolicyEngine::observe's own comment for why.
    std::vector<EthernetFlowReport> ethernet_flows;
    // One per observed UDP-based IP flow (BACnet/IP, CIP I/O, HART-IP, and/or FF-HSE), in
    // first-seen order -- only ever non-empty when the policy declares at least one CIDR- or
    // hostname-zone conduit naming 'bacnet'/'enip'/'hartip'/'ffhse'/'any' in its 'protocols' (see
    // Policy::has_udp_eligible_conduit and PolicyEngine::observe's own comment for the full "opt-in
    // per conduit" gating rationale); otherwise this traffic stays folded into skipped_non_tcp
    // below, exactly as before this feature existed. Matched against the SAME CIDR/hostname-zone
    // conduits ordinary TCP flows use (never a VLAN-zone conduit -- these are IP-addressed
    // protocols, not raw Ethernet), through the identical ports/bidirectional/protocol matching
    // logic `flows` above uses -- see UdpFlowReport's own comment.
    std::vector<UdpFlowReport> udp_flows;
    // Conduits declared in the policy that no observed flow ever matched -- informational only
    // (doesn't affect compliant()); useful for pruning a policy file or noticing a conduit that
    // was supposed to be exercised by this capture but wasn't. Spans `flows`, `ethernet_flows`, AND
    // `udp_flows` -- a VLAN-zone conduit no L2 flow ever matched appears here exactly like an
    // IP-zone conduit no TCP or UDP flow ever matched.
    std::vector<std::string> unexercised_conduits;
    size_t skipped_non_tcp = 0;  // packets with has_ip==false or has_tcp==false (including UDP),
                                  // and NOT one of PROFINET RT/GOOSE/SV/EtherCAT (see ethernet_flows
                                  // above) or an opted-in BACnet/IP/CIP-I/O packet (see udp_flows
                                  // above) -- or one of those but the policy doesn't opt in (no VLAN
                                  // zone at all for the former, no eligible conduit for the latter):
                                  // not part of any evaluated flow -- see PolicyEngine::observe
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

    // Every declared multi-homed asset (Phase 6, policy.hpp's `assets:`), cross-referenced against
    // this policy's own zones/conduits -- see MultiHomedAssetFinding's own comment. ALWAYS
    // populated (one entry per Policy::assets entry, in file order) whenever the policy declares
    // any assets at all, independent of the capture -- empty only when the policy declares none
    // (the common case today, and the case every policy written before this feature existed is
    // in). Purely additive reporting: nothing here ever changes a FlowVerdict or compliant().
    std::vector<MultiHomedAssetFinding> multi_homed_assets;
    // Every TCP or UDP flow where either endpoint belongs to a `role: "jump_host"`-tagged asset, in
    // first-seen order -- see JumpHostFlowFinding's own comment. Empty whenever the policy declares
    // no `role: "jump_host"` asset (the common case today) -- purely additive reporting, never
    // affects any FlowVerdict or compliant().
    std::vector<JumpHostFlowFinding> jump_host_flows;

    // Every count below spans `flows`, `ethernet_flows`, AND `udp_flows` -- an L2 flow's or a UDP
    // flow's verdict counts exactly like a TCP flow's for compliance purposes; there is no separate
    // "ethernet compliant" or "UDP compliant" notion, one capture is either COMPLIANT or it isn't.
    size_t allowed_count() const;
    size_t violation_count() const;
    size_t unclassified_count() const;
    // True only when every observed flow (TCP, L2, or UDP) was explicitly Allowed -- any Violation OR any
    // Unclassified flow makes this false, since "traffic between addresses this policy doesn't
    // even classify" is itself a finding worth surfacing in an audit, not something to pass
    // silently. See cli_main.cpp for how this maps to `policy validate`'s exit code.
    bool compliant() const { return violation_count() == 0 && unclassified_count() == 0; }

    // patch257 security review finding 3 fix ("protocol state exhaustion remains a central
    // threat") -- true iff this capture's own PolicyEngine hit at least one of its four
    // PolicyEngineLimits growth ceilings, so `flows`/`ethernet_flows`/`udp_flows`/
    // `notable_protocols` above may be an incomplete view of what the capture actually contains.
    // See PolicyEngineLimits' own comment for the refuse-to-grow-further, never-evict admission
    // policy behind this, mirroring BaselineEngine's/AssetInventoryEngine's own
    // observation_truncated.
    bool observation_truncated = false;
    // One human-readable line per DISTINCT ceiling that was hit, each naming the CLI flag that
    // raises it -- same dedup rule as BaselineEngine::mark_truncated. Empty iff observation_truncated
    // is false.
    std::vector<std::string> truncation_reasons;
};

// patch257 finding 3 fix -- PolicyEngine's four accumulating containers (flows_/ethernet_flows_/
// udp_flows_/notable_protocols_) had no growth ceiling at all before this. Same refuse-to-grow-
// further, never-evict, visibly-mark-truncated posture as BaselineEngineLimits/
// AssetInventoryEngineLimits and for the identical reason: every one of these containers feeds
// this engine's own report output (a flow's own compliance verdict), so silently evicting an
// already-tracked flow to make room for a new one could make an already-reported flow's own
// verdict silently stop updating. Sized generously, same "one capture's worth of in-memory state"
// logic as the other two engines' own sizing comments.
inline constexpr size_t kDefaultMaxPolicyTcpFlows = 200000;
inline constexpr size_t kDefaultMaxPolicyUdpFlows = 100000;
inline constexpr size_t kDefaultMaxPolicyEthernetFlows = 100000;
inline constexpr size_t kDefaultMaxPolicyNotableProtocols = 50000;

struct PolicyEngineLimits {
    size_t max_tcp_flows = kDefaultMaxPolicyTcpFlows;
    size_t max_udp_flows = kDefaultMaxPolicyUdpFlows;
    size_t max_ethernet_flows = kDefaultMaxPolicyEthernetFlows;
    size_t max_notable_protocols = kDefaultMaxPolicyNotableProtocols;
};

class PolicyEngine {
public:
    explicit PolicyEngine(const Policy& policy, PolicyEngineLimits limits = PolicyEngineLimits{})
        : policy_(policy), any_vlan_zone_(policy.has_vlan_zone()),
          any_udp_ip_eligible_conduit_(policy.has_udp_eligible_conduit()), limits_(limits) {}

    // True once at least one of limits_'s four growth ceilings refused to track something new at
    // least once -- see PolicyEngineLimits' own comment for why refusal, never eviction. Callers
    // (cli_main.cpp) must surface this rather than let a truncated policy-validate run pass as an
    // ordinary complete one.
    bool truncated() const { return truncated_; }

    // One human-readable line per DISTINCT ceiling that was hit. Empty iff truncated() is false.
    const std::vector<std::string>& truncation_reasons() const { return truncation_reasons_; }

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
    // A packet with protocol == "bacnet"/"enip"/"hartip"/"ffhse" and has_udp (BACnet/IP, CIP I/O,
    // HART-IP, or FF-HSE) is folded into a UDP flow (PolicyReport::udp_flows) instead, but ONLY when
    // the policy opts in by naming "bacnet"/"enip"/"hartip"/"ffhse"/"any" on at least one CIDR- or
    // hostname-zone conduit (`any_udp_ip_eligible_conduit_`, cached from
    // Policy::has_udp_eligible_conduit at construction) -- when it doesn't, this traffic is left in
    // PolicyReport::skipped_non_tcp exactly as it was before this feature existed, so a policy file
    // written before it existed can never have its compliance verdict change just because a capture
    // happens to also contain some of this traffic that policy's author never wrote a conduit to
    // address (see policy.hpp's Policy::has_udp_eligible_conduit comment -- the same
    // backward-compatibility posture any_vlan_zone_ already established for VLAN zones above). A UDP
    // flow is keyed by (protocol, client IP, server IP, server port) -- there is no TCP handshake to
    // lean on for direction, so BACnet reuses its own APDU request/response semantics when a decoded
    // APDU is present (Confirmed-Request/Unconfirmed-Request -> source is client; every other
    // decoded PDU type -- Simple-ACK/Complex-ACK/Segment-ACK/Error/Reject/Abort -- -> destination is
    // client; the same logic AssetInventoryEngine already uses for this same protocol,
    // asset_inventory.cpp), and HART-IP reuses its own MessageType the same way (0=Request -> source
    // is client; 1=Response/3=Error/15=NAK -> destination is client; 2=Publish has no preceding
    // request to reply to, so it's treated like "no content signal yet"), and FF-HSE reuses its own
    // header Type field the same way again (0=Request -> source is client; 1=Response/2=Error ->
    // destination is client) -- falling back to a UDP-known-service-port heuristic
    // (BACNET_UDP_PORT/ENIP_IO_UDP_PORT/HARTIP_PORT/FFHSE_PORT_ANNUNC/FFHSE_PORT_FMS/
    // FFHSE_PORT_SM/FFHSE_PORT_LAN) when no content-based answer is available yet; CIP I/O has no
    // request/response concept at all (cyclic producer/consumer traffic) and is always decided by
    // the port heuristic. See UdpFlowReport's own comment for the full matching model (same
    // CIDR/hostname zones and ports/bidirectional/protocol logic ordinary TCP flows use) and
    // DirectionSource::Content's own comment (decoder.hpp) for why BACnet's/HART-IP's/FF-HSE's case
    // counts as "Content", not "PortHeuristic", when an authoritative message is present.
    //
    // Every other packet with has_ip==false or has_tcp==false (non-IP, non-TCP -- including UDP not
    // covered by the paragraph above, which `decode` recognizes and reports on but this engine still
    // does not evaluate against any conduit -- or a parse-error packet) isn't part of any TCP or UDP
    // flow either and is only counted toward PolicyReport::skipped_non_tcp -- this tool only ever
    // checks TCP-based OT protocols (plus, now, VLAN-zoned raw-Ethernet OT protocols, and opted-in
    // BACnet/IP/CIP-I/O UDP traffic) against a policy's conduits, so there's nothing further to
    // evaluate for them yet.
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
    //
    // `resolver`: only ever consulted when the policy declares at least one hostname zone
    // (Policy::has_hostname_zone) -- a CIDR-zone lookup for a flow's endpoint is always tried
    // first, and the hostname lookup (resolver.hostname(ip)) is attempted only on a miss (see
    // policy.hpp's own header comment for why a hostname zone is matched this way, and
    // resolver.hpp's own file header for why this lookup is file-only, pinned by --hosts, and
    // never live DNS -- the reproducibility a compliance verdict needs). A policy with no hostname
    // zone never calls into `resolver` from here at all, so passing a default-constructed-
    // equivalent Resolver is always safe and behaves exactly as before this parameter existed. This
    // is a different Resolver USE than write_policy_report_text/_json's own (report *annotation*,
    // after verdicts are already final) -- the same Resolver instance is meant to be passed to both.
    PolicyReport finish(const Resolver& resolver) const;

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

    // Aggregated state for one UDP flow (BACnet/IP, CIP I/O, HART-IP, or FF-HSE) -- see
    // UdpFlowReport's own comment. Keyed (in udp_flows_) by protocol plus the SAME canonical,
    // order-independent (ip:port, ip:port) pairing session_key() already computes for a TCP flow --
    // reused here even though this traffic has no session/handshake concept, purely so packets seen
    // from either direction between the same two endpoints fold into one UdpFlowState rather than
    // fragmenting into two directed ones (see PolicyEngine::observe's own UDP-flow branch for exactly
    // how client_ip/server_ip themselves are decided per packet, independent of this key).
    struct UdpFlowState {
        std::string protocol;  // "bacnet", "enip", "hartip", or "ffhse" -- fixed at first-insert, one
                                 // flow key is only ever created by one protocol's own packets (see
                                 // observe())
        std::string client_ip, server_ip;
        uint16_t server_port = 0;
        // Distinct, non-empty function/service names observed on this flow so far -- see
        // UdpFlowReport::observed_functions' own comment (BACnet's service_choice_name, HART-IP's
        // message_type_name, or FF-HSE's message_name; always empty for CIP I/O).
        std::unordered_set<std::string> functions;
        // See UdpFlowReport::direction_source's own comment -- mirrored here verbatim. Starts at
        // PortHeuristic and is upgraded to Content the first time a packet on this flow carries a
        // decoded BACnet APDU, a HART-IP Request/Response/Error/NAK message, or an FF-HSE
        // Request/Response/Error frame (see observe()'s own upgrade logic, mirroring FlowState's own
        // SYN/SYN-ACK upgrade rule at this coarser, no-handshake granularity) -- never downgraded
        // back once upgraded.
        DirectionSource direction_source = DirectionSource::PortHeuristic;
        size_t packet_count = 0;
        // See FlowReport::has_mac/client_mac/server_mac's own comment -- mirrored here verbatim,
        // set/refreshed exactly where client_ip/server_ip are.
        bool has_mac = false;
        std::string client_mac, server_mac;
    };

    // Aggregated state for one L2 flow (protocol + canonical MAC pair) -- see EthernetFlowReport's
    // own comment for why this has neither a port nor a client/server distinction.
    struct EthernetFlowState {
        std::string protocol;
        std::string mac_a, mac_b;
        // Fixed from the first packet that creates this entry, never updated afterward -- see
        // EthernetFlowReport::src_mac's own comment for why a one-directional cyclic publish
        // stream has one stable, unambiguous source unlike a bidirectional TCP session.
        std::string src_mac;
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

    // Identical dedup rule to BaselineEngine::mark_truncated (baseline.cpp).
    void mark_truncated(const std::string& reason);

    // Identical contract to AssetInventoryEngine::admit_tracked_key (asset_inventory.hpp) -- shared
    // by every one of this engine's four growth-capped containers' own "have I seen this key
    // before" check.
    bool admit_tracked_key(bool already_present, size_t current_map_size, size_t ceiling, const char* map_name,
                            const char* flag_name);

    const Policy& policy_;
    bool any_vlan_zone_;  // cached Policy::has_vlan_zone() -- see observe()'s own comment
    bool any_udp_ip_eligible_conduit_;  // cached Policy::has_udp_eligible_conduit() -- see
                                          // observe()'s own comment
    PolicyEngineLimits limits_;
    bool truncated_ = false;
    std::vector<std::string> truncation_reasons_;
    std::unordered_map<std::string, FlowState> flows_;  // keyed by canonical session key
    std::vector<std::string> flow_order_;                // session keys, first-seen order
    std::unordered_map<std::string, UdpFlowState> udp_flows_;  // keyed by protocol + canonical
                                                                 // session key -- see UdpFlowState's
                                                                 // own comment
    std::vector<std::string> udp_flow_order_;  // udp_flows_ keys, first-seen order
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

// Renders every FlowVerdict::Violation in `report` (across flows, ethernet_flows, and udp_flows --
// every kind of violation this engine can produce, not just TCP) as CEF (`policy validate --format
// cef`), one line per violating flow -- see security_event_format.hpp for the shared CEF
// primitives and the full design record. Allowed/Unclassified flows are never rendered: an
// Unclassified flow means "no conduit declared an opinion about this traffic," not a policy
// breach, so it stays out of a curated security-event export the same way `baseline check`'s own
// KnownOperation matches stay out of its findings list. Device Product is "conduitscope-policy";
// Device Event Class ID is the fixed literal "policy-violation" (PolicyReport's own FlowVerdict has
// no finer per-violation type the way DetectionFinding's technique citation does); Severity is a
// fixed 8 (CEF's own High band) for every violation -- a confirmed breach of a declared zone/
// conduit policy is a strong, unconditional signal, deliberately placed below DetectionSeverity::
// Critical's own 9 (which is reserved for a genuine operational-impact event like a PLC stop) but
// above a "new, previously unseen" baseline finding's own weaker signal. Extension fields:
// src/dst/dpt (flows/udp_flows) or smac/dmac (ethernet_flows, CEF's own standard MAC-address keys
// -- smac is the flow's own known transmitting side, dmac its peer)/proto/msg (the flow's own
// `reason`)/cat ("policy-violation") plus cs1/cs1Label="Client Zone" and cs2/cs2Label="Server Zone"
// (flows/udp_flows) or cs1/cs1Label="VLAN Zone" (ethernet_flows)/cnt (packet_count).
void write_policy_report_cef(std::ostream& out, const PolicyReport& report);

// Renders every FlowVerdict::Violation in `report` as LEEF 2.0 (`policy validate --format leef`) --
// same finding-to-field mapping as write_policy_report_cef above, see security_event_format.hpp.
void write_policy_report_leef(std::ostream& out, const PolicyReport& report);

// Renders every FlowVerdict::Violation in `report` as RFC 5424 syslog wrapping a CEF payload
// (`policy validate --format syslog`), one line per violation, MSGID "policy" -- see
// security_event_format.hpp's own render_rfc5424_line for the full header rationale.
void write_policy_report_syslog(std::ostream& out, const PolicyReport& report);

}  // namespace conduitscope
