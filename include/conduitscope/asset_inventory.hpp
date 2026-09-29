// SPDX-License-Identifier: Apache-2.0
// asset_inventory.hpp - passive OT asset inventory: infers a first-draft zone/conduit model from a
// capture, the opposite direction from `policy validate` -- instead of checking observed traffic
// against a hand-written policy, this discovers a plausible one from what was actually seen on the
// wire. See the `inventory` subcommand (cli_main.cpp) and docs/MANUAL.md's ROADMAP item 17 for the
// full rationale and prior art (NSA's abandoned GRASSMARLIN, CISA's much heavier Malcolm).
//
// Scope: originally just five protocols (ROADMAP item 17's first pass), widened to match every
// protocol PolicyEngine::observe itself evaluates over TCP, plus S7comm-Plus (added separately --
// see below) -- eleven in total: Modbus, DNP3, S7comm (a COTP-only session with no S7comm payload
// still counts, same "cotp folds into s7comm" convention PolicyEngine::observe uses -- see
// AssetInventoryEngine::observe's own comment), EtherNet/IP (both explicit messaging over TCP and
// CIP I/O implicit messaging over UDP/2222 -- decoder.cpp promotes both to protocol=="enip", see
// decoder.hpp), BACnet/IP, IEC 104, HART-IP, OPC UA, MMS, MQTT, FF-HSE, and S7comm-Plus.
//
// S7comm-Plus is NOT one of the ten protocols PolicyEngine::observe evaluates (it has no
// policy-engine zoning counterpart yet), but it's a distinct, independently-decoded application
// protocol (s7commplus.hpp/DecodedPacket::s7plus_* -- a flat-field protocol, not one carried via
// DecodedPacket::result) sharing classic S7comm's own TCP/102/TPKT/COTP transport, so it counts
// toward this feature's asset/edge model the same way every other TCP-based protocol here does --
// see AssetInventoryEngine::observe's own comment for exactly where it's dispatched and how its
// function name (DecodedPacket::s7plus_function_name) is surfaced on InventoryEdge::
// observed_functions.
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

// Phase 7 of Grok gap #2 ("which specific tags/points/DBs were touched, not just function-code
// categories") -- see InventoryEdge::top_touched_addresses' own comment for the full design. Two
// separate caps, same "a wide internal ceiling, a narrow shown cutoff" shape
// max_active_flows/max_flow_state_entries already use in resource_limits.hpp for an unrelated
// (decode-time, per-flow) concern -- deliberately NOT wired into that CLI-configurable system: this
// one is AssetInventoryEngine's own post-processing accumulation across a whole capture, a
// different engine and a different concern, with no natural per-decode-call scope to hang a CLI flag
// off of. Both are fixed engineering-judgment constants, not exposed on the CLI, matching this
// codebase's own existing kMaxObjectValues/kMaxDecodedPointsPerHeader-style internal safety caps
// (iec104.cpp/dnp3.cpp) rather than a tunable knob.
//
// kMaxTrackedAddressesPerEdge: once one edge (one client/server/protocol/port tuple) has this many
// DISTINCT addresses in its internal touch-count map, no further new address is admitted -- but
// every address already tracked keeps incrementing normally. Sized generously (4096, the same
// "no legitimate deployment should ever observe this in practice" posture kDefaultMaxActiveFlows'
// own comment takes at 100000) so this ceiling is a pure memory-safety backstop against a
// pathological capture (an aggressive scanner sweeping tens of thousands of distinct register
// addresses against one PLC), never something a real, bounded OT point list would hit.
constexpr size_t kMaxTrackedAddressesPerEdge = 4096;

// kMaxShownTouchedAddressesPerEdge: of whatever was tracked (up to the ceiling above),
// InventoryEdge::top_touched_addresses keeps only the top-N by touch count (descending), address
// string ascending as a deterministic tie-break for reproducible output -- the plan's own suggested
// example ("top 32 most-frequently-touched addresses per edge").
constexpr size_t kMaxShownTouchedAddressesPerEdge = 32;

// One asset: a distinct IP address that appeared in at least one packet of one of this feature's
// eleven recognized protocols. AssetInventoryEngine::finish sorts these numerically by address for
// a report that's deterministic independent of capture order.
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
    // "mqtt"/"ffhse"/"s7comm-plus" -- see this file's own header comment for the two (hartip/ffhse)
    // that are TCP-only here despite also being decodable over UDP.
    std::vector<std::string> protocols;
    bool ever_client = false;  // acted as the initiator on at least one observed exchange
    bool ever_server = false;  // acted as the responder on at least one observed exchange
    size_t packet_count = 0;   // total packets (either direction) this IP appeared in

    // First/last-seen, straight from DecodedPacket::timestamp (seconds since the Unix epoch, from
    // the pcap record header) -- the min/max across every packet this IP appeared in, either role.
    // Grok gap #2's "last-seen" ask (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md) -- free
    // to add since every DecodedPacket already carries this field; no new decode work. Always
    // meaningful once this asset exists (every asset came from at least one packet).
    double first_seen = 0.0;
    double last_seen = 0.0;

    // Passively-inferred device identity (Grok gap #2's vendor/product/firmware/serial ask) --
    // empty/unset unless a protocol's own identity-bearing message positively supplied it (never
    // guessed, never inferred from e.g. an OUI vendor lookup, which is a MAC-address fact, not a
    // device-identity fact, and already rendered separately via Resolver::oui_vendor). First
    // identity response actually seen for this IP wins, same "first occurrence wins" convention
    // has_mac/mac above already use. See AssetInventoryEngine::observe's own comment for exactly
    // which protocols currently populate these and how each one is sourced.
    //
    // `vendor`: for EtherNet/IP, a raw numeric CIP Vendor ID ("Vendor ID 1234 (ODVA-registered,
    // name not resolved)") -- this codebase has no CIP Vendor ID -> name table (ODVA's registry is
    // several thousand entries; adding a full lookup table is out of scope for this pass, and
    // scoped out deliberately rather than silently -- see docs/USER_GUIDE.md's LIMITATIONS).
    std::string vendor;
    std::string product;            // e.g. EtherNet/IP CIP Identity's own product-name string
    std::string firmware_revision;  // e.g. EtherNet/IP CIP Identity's own "major.minor" revision
    std::string serial_number;      // rendered as "0x" + hex, matching this codebase's own existing
                                     // text-summary convention for this exact field (enip.cpp)

    // OPC UA-specific: for OPC UA, `vendor`/`product` above are BOTH set to the same
    // GetEndpointsResponse's first-endpoint ApplicationUri (OPC UA has no separate vendor/model the
    // way CIP Identity or S7 SZL do -- see opcua.hpp's own OpcUaMessage::identity_application_uri
    // comment for why ApplicationUri is this decoder's own stand-in "stable identifier"), and
    // `firmware_revision`/`serial_number` above are left empty (OPC UA's GetEndpoints exchange
    // carries neither). This field instead records that SAME endpoint's own security posture --
    // "SecurityMode=<mode>, Policy=<policy-uri>" -- prefixed "SECURITY FINDING: " when the mode is
    // "None" (an endpoint accepting no security at all), the same "SECURITY FINDING:"-prefixed note
    // convention opcua.cpp's own ActivateSession cleartext-credential check already established --
    // see AssetInventoryEngine::observe's own comment for exactly how this is populated. Empty for
    // every other protocol; first-identity-seen wins here too, same as vendor/product above.
    std::string security_posture;

    // S7comm-specific (Phase 3 of Grok gap #2 -- SZL/"System Status List" decode): the plant tag an
    // S7-300/400/1200/1500 CPU can be configured to carry (SZL-ID 0x001C sub-index 0x0003, "Plant
    // Identification" -- see S7CommFrame::szl_plant_identification's own comment in s7comm.hpp for
    // the wire source). Kept as its own field rather than folded into `product` above: it's a
    // site-assigned tag (e.g. "Line3-Filler"), not a vendor/model fact the way `vendor`/`product`
    // are for every other protocol here, and a real CPU may carry a plant tag but no order number (or
    // vice versa) depending on which SZL sub-records the exchange actually requested. Empty unless a
    // Read SZL response for this IP positively supplied it; first-seen wins, same convention as every
    // other identity field above.
    std::string plant_identification;

    // Phase 6 of Grok gap #2 ("asset inventory: a real OT asset record" -- Grok's original review
    // asked for "PLC/RTU/IED/HMI/historian/engineering-station role classification"): a PASSIVE,
    // LOW-CONFIDENCE, purely INFORMATIONAL guess at this asset's functional role, from a small,
    // explicit heuristic over protocol mix and client/server behavior -- never treated as fact
    // anywhere else in this codebase (kept as informational-only as `PurdueLevel` is in the policy
    // engine, per this feature's own plan), and always rendered with a "(heuristic, low confidence)"
    // qualifier, the same posture `direction_source`'s own `PortHeuristic` tier already takes for an
    // unconfirmed guess (see DirectionSource's own comment, decoder.hpp).
    //
    // Always one of exactly four values -- computed by `AssetInventoryEngine::finish` (needs the
    // final, deduplicated edge list to count each asset's distinct peers, so it can't be computed
    // per-packet in `observe` the way every other field above is):
    //
    //   - "PLC/RTU": `ever_server && !ever_client`, and `protocols` includes at least one of this
    //     engine's nine "field-device protocols" -- modbus/dnp3/s7comm/s7comm-plus/enip/iec104/
    //     hartip/bacnet/ffhse, i.e. every protocol here whose server side is conventionally the
    //     physical/embedded device being polled or commanded, not a supervisory or middleware
    //     component. A device that only ever ANSWERS, never itself initiates an outbound OT-protocol
    //     session of its own, on a classic field-device protocol, is the single cleanest passive
    //     signal this heuristic has: it's essentially always a controller, not a workstation.
    //     Deliberately folds in "IED" (Grok's own separate ask): passively, an IED (a protective
    //     relay, typically DNP3/IEC 104-heavy) and a PLC/RTU (typically Modbus/S7comm/EtherNet/IP-
    //     heavy) produce the exact same server-only signal -- there is no reliable protocol-mix
    //     tie-break between them (a PLC can speak DNP3 as a substation RTU function just as
    //     legitimately as a dedicated IED can), so this heuristic doesn't pretend to split them.
    //   - "HMI/Engineering Station": `ever_client && !ever_server`, `protocols` includes at least one
    //     field-device protocol (same nine as above), AND this asset is a client of at least TWO
    //     distinct server IPs across all edges (any protocol) -- the "one console polling many
    //     PLCs" shape. The >= 2 distinct-peer threshold exists to keep a single one-off session (one
    //     engineer's laptop briefly talking to exactly one PLC -- e.g. a firmware update, or a
    //     one-time diagnostic session) out of this bucket, since one peer alone can't distinguish a
    //     genuine supervisory/engineering workstation from a one-time visitor; that case falls
    //     through to "Unknown" instead. Deliberately folds in "Engineering Station" alongside "HMI"
    //     (Grok's own separate ask): passively, an HMI and an engineering workstation look
    //     identical -- both are a client polling multiple field devices; the difference is purely
    //     which software is installed, which this tool can't observe on the wire, so this heuristic
    //     doesn't pretend to split them either (confirmed with Jurgen before implementing, given
    //     this phase's plan flagged both splits as open questions with no spec to check them
    //     against).
    //   - "Historian/Data Collector": `ever_client`, and this asset is a client of at least TWO
    //     distinct server IPs via at least one of this engine's two "data-platform protocols" --
    //     opcua/mms, i.e. the two protocols that can be spoken natively BY a field device (a PLC's
    //     own embedded OPC UA/MMS server) or by a supervisory/aggregation component, so they're
    //     usable as a CLIENT-role signal here but deliberately NOT added to the field-device-protocol
    //     set above (a server-only OPC UA/MMS asset stays classified by whatever else it does, or
    //     falls to "Unknown" if that's all it does -- promoting an OPC UA/MMS SERVER straight to
    //     "PLC/RTU" would misclassify a real OPC UA aggregation/historian server just as often as it
    //     would correctly identify a PLC's own embedded server). Checked AFTER the HMI/Engineering
    //     Station rule above, and only matches an asset with NO field-device-protocol client
    //     activity at all: an asset that's a client of both a classic field protocol AND OPC UA/MMS
    //     lands as "HMI/Engineering Station" instead, since mixed protocol-client behavior is more
    //     characteristic of an engineering workstation than a dedicated historian (a historian that
    //     ALSO happens to be an OPC UA/MMS SERVER -- e.g. re-exposing its own data to a downstream
    //     MES/ERP system -- can still match this rule; only `ever_server` on a field-device protocol
    //     is excluded by the HMI/Engineering Station rule's own `!ever_server`, not `ever_server` in
    //     general). MQTT is deliberately excluded from both the field-device and data-platform sets:
    //     MQTT's own client/broker roles (a broker is the "server", a publisher/subscriber is the
    //     "client") don't map onto "supervisory client polling field devices" the way every other
    //     protocol here does, so an MQTT-only asset's role stays "Unknown" under this heuristic --
    //     a known, documented gap (see docs/USER_GUIDE.md's LIMITATIONS), not an oversight.
    //   - "Unknown": every asset that doesn't match one of the three rules above -- includes a
    //     dual-role asset (both `ever_client` and `ever_server` on field-device protocols, e.g. a
    //     protocol gateway or a sub-master RTU relaying to further outstations -- genuinely
    //     ambiguous, not guessed at); an asset with too few distinct peers to carry real signal (a
    //     lone one-off client session); an MQTT-only asset (see above); and an asset this engine
    //     observed only via `notable_protocols` or a broadcast/multicast destination that never
    //     formed a real edge at all. Always rendered explicitly as the literal string "Unknown", not
    //     left empty -- unlike `vendor`/`product`/etc. above (which stay empty when no protocol
    //     positively supplied them), a role IS always computed for every asset that exists at all;
    //     "Unknown" is this heuristic's own honest conclusion, not an absence of an attempt.
    //
    // Deliberately NOT used as a signal: raw packet-count/traffic-volume thresholds. Packet count
    // correlates with how long a capture ran and how chatty a given protocol/exchange naturally is,
    // not with a device's functional role, and adding a volume threshold would mean inventing an
    // arbitrary cutoff with even less grounding than the peer-count thresholds above already have --
    // left out of this first pass; revisit only if the peer-count-based rules above prove too coarse
    // in practice.
    std::string inferred_role = "Unknown";
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
// One address this edge's client touched, and how many packets touched it -- Phase 7 of Grok gap
// #2. See InventoryEdge::top_touched_addresses' own comment for the full design and per-protocol
// key format.
struct InventoryAddressTouch {
    std::string address;
    size_t count = 0;
};

struct InventoryEdge {
    std::string client_ip, server_ip;
    // "modbus"/"dnp3"/"s7comm"/"enip"/"bacnet"/"iec104"/"hartip"/"opcua"/"mms"/"mqtt"/"ffhse"/
    // "s7comm-plus"
    std::string protocol;
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

    // First/last-seen across every packet folded into this edge -- see InventoryAsset::first_seen/
    // last_seen's own comment; same source field, same free-to-add reasoning.
    double first_seen = 0.0;
    double last_seen = 0.0;

    // Phase 7 of Grok gap #2 ("asset inventory: a real OT asset record" -- Grok's original review
    // asked which specific tags/points/DBs were touched, not just the function-code categories
    // `observed_functions` above already records): the top kMaxShownTouchedAddressesPerEdge (32)
    // distinct addresses this edge's client touched, by touch count descending, address string
    // ascending as a deterministic tie-break -- sorted and truncated once, in
    // `AssetInventoryEngine::finish`, from an internal per-edge map capped at
    // kMaxTrackedAddressesPerEdge (4096) distinct addresses (see both constants' own comments just
    // above for the two-tier cap design).
    //
    // Populated for exactly five of this feature's twelve protocols -- the ones with an
    // already-decoded, already-structured address/tag field this phase could wire in with NO new
    // protocol decode (confirmed per-protocol during implementation, mirroring vendor/product/
    // firmware_revision's own "reuse, don't newly decode" posture elsewhere in this file):
    //   - modbus: a "<kind>:<1-based address>[-<1-based end address>]" key derived from the
    //     read/write-multiple families' own already-decoded ModbusFrame::function_code + start_address
    //     (+ quantity, when > 1, rendered as an inclusive range) -- kind is "coil" (Read Coils/Write
    //     Multiple Coils), "discrete" (Read Discrete Inputs), "hreg" (Read Holding Registers/Write
    //     Multiple Registers), or "ireg" (Read Input Registers); address is start_address+1 (the
    //     conventional 1-based Modicon reference numbering), zero-padded to 5 digits -- e.g.
    //     "hreg:00001-00010" for a 10-register Read Holding Registers request starting at wire address
    //     0. The `kind` word itself disambiguates register type rather than relying on a Modicon
    //     leading-digit convention (0x/1x/3x/4x), which this key format doesn't otherwise follow.
    //     Write Single Coil/Register never contribute (ModbusFrame::start_address stays nullopt for
    //     that family -- see its own comment, modbus.hpp) -- a documented scope boundary shared with
    //     the baseline engine, not new here.
    //   - s7comm: S7Item::tag verbatim (e.g. "DB10.DBW100", "I0.0", "MB50", "T5") for every item on a
    //     Read Var/Write Var request whose S7Item::syntax_supported is true -- an item decoded via the
    //     EXPERIMENTAL 0xB2/TIA-1200 symbolic path (S7Item::is_experimental) is prefixed
    //     "experimental:" so a reader can't mistake a not-fully-verified address for a
    //     well-established S7ANY one, same "mark it, don't hide it" posture s7comm.hpp's own file
    //     comment already takes for that decode path elsewhere.
    //   - dnp3: "g{group}v{variation}" (Dnp3ObjectRange::group/variation -- the SAME shorthand
    //     src/dnp3.cpp's own summary/dnp3_object_headers rendering already establishes, reused
    //     verbatim for consistency) plus " idx {start}-{stop}" (or " idx {start}" when the range is a
    //     single point) when Dnp3ObjectRange::has_range is true. This is coarser than a genuine
    //     per-point index -- Dnp3Result (the merged, cross-fragment struct this engine actually reads)
    //     only retains Dnp3ObjectRange's own group/variation/range-of-the-header level, not each
    //     individual Dnp3PointValue::index inside it (those exist only at the per-fragment
    //     Dnp3ObjectHeader::values level, which isn't retained past decode) -- a deliberate,
    //     documented scope boundary: exposing true per-point indices here would mean widening
    //     Dnp3Result itself, genuinely new decode-surface work, not the "reuse what's already there"
    //     scope this phase stayed within. A header-level range is still a materially more specific
    //     "what was touched" answer than `observed_functions`' function-name-only view.
    //   - iec104: "ioa={value}" from Iec104Result::iec104_object_ioas (a small, additive field
    //     promoting the same numeric Information Object Address already rendered, stringified, into
    //     iec104_object_values -- see that field's own comment, iec104.hpp -- as its own structured
    //     uint32_t list; zero new parsing, the exact same promotion enip.hpp's own identity_* fields
    //     already got relative to CipMessage's generic values in an earlier phase).
    //   - enip (explicit messaging only, never CIP I/O implicit messaging -- see this file's own
    //     header comment on why the two share one protocol="enip"): CipMessage::path.summary verbatim
    //     (e.g. "MyTag.Member[3]"), only when CipPath::is_symbolic is true -- i.e. only a genuine
    //     Rockwell Logix5000 named-tag path (Read Tag/Write Tag/Read Tag Fragmented/Write Tag
    //     Fragmented/Read Modify Write Tag; see CipPath::is_symbolic's own comment, enip.hpp). A
    //     class/instance/attribute-addressed CIP message (not a named tag at all -- e.g. Identity
    //     object Get_Attributes_All) is deliberately excluded: that's generic CIP object access, not
    //     a "tag/point" in the sense this phase's ask means, and CipPath::summary's own class/instance
    //     rendering isn't a stable per-device address the way a tag name is.
    //   - mqtt: MqttMessage::topic verbatim, PUBLISH packets only (every other MQTT packet type --
    //     CONNECT/SUBSCRIBE/PINGREQ/... -- carries no topic of its own here; MqttMessage::topic is
    //     documented "PUBLISH only", mqtt.hpp). A topic is this protocol's own natural point-address
    //     equivalent -- the specific data channel a publisher/subscriber touches, the direct MQTT
    //     analog of a Modbus register or an S7 DB tag.
    //
    // Explicitly deferred, not attempted, for the other seven protocols (confirmed with Jurgen before
    // implementing, since it changed this phase's scope from the plan's own original, more
    // conservative framing): OPC UA and MMS both address by a genuinely symbolic path (a NodeId; a
    // "domainId/itemId" object reference) that this codebase currently only ever stringifies into a
    // free-text notes/values entry (OpcUaMessage has no structured NodeId field of its own;
    // MmsFrame::values is "key=value" strings, not a structured domain/item field) -- promoting either
    // to a real structured field would be genuinely new decode-surface work, not reuse, so both stay
    // out of scope for this phase. BACnet/HART-IP/FF-HSE/S7comm-Plus carry no per-point/per-tag
    // addressing concept this codebase decodes at all today. See docs/USER_GUIDE.md's LIMITATIONS for
    // this same list in user-facing form.
    std::vector<InventoryAddressTouch> top_touched_addresses;

    // However many distinct addresses this edge actually had tracked (bounded by
    // kMaxTrackedAddressesPerEdge above -- see that constant's own comment for what happens past it),
    // even though only the top kMaxShownTouchedAddressesPerEdge are listed in
    // top_touched_addresses above. 0 for every edge whose protocol isn't one of the five wired in
    // above (top_touched_addresses is then also empty).
    size_t touched_addresses_total_distinct = 0;

    // True when touched_addresses_total_distinct exceeds top_touched_addresses.size() -- i.e. this
    // edge touched more distinct addresses than fit in the shown top-N cutoff, so
    // top_touched_addresses is a genuine subset, not the whole picture. Never true when
    // touched_addresses_total_distinct is 0.
    bool touched_addresses_truncated = false;
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

// One aggregated observation of a Tier 1-5 "IT protocol an OT auditor flags" (ROADMAP item 18;
// notable_it_protocols.hpp names the exact 43 protocol values and their tier) -- completely separate
// from, and never counted toward, this engine's own ten-protocol asset/edge model above: none of
// these 43 protocols are among the ten AssetInventoryEngine::observe otherwise recognizes, so a
// packet that produces one of these also still increments AssetInventoryReport::skipped_packets
// exactly as it always has -- this is a strictly additive finding, not a widening of what counts as
// a "recognized" packet for the rest of this report. See AssetInventoryEngine::observe's own comment
// for exactly when this is recorded, and policy_engine.hpp's own, independently-computed
// NotableProtocolFinding (this feature's twin in `policy validate`) for the analogous struct there --
// kept separate rather than shared, the same "each engine stays self-contained" convention this
// file's own header comment and tcp_session_key (asset_inventory.cpp) already establish.
//
// Unlike InventoryEdge, client_ip/server_ip here is always the SAME plain "lower port number is the
// server" heuristic src_is_client_by_port already provides for this exact shape (this engine's own
// UDP-based protocols, e.g. BACnet, get a real handshake- or content-based direction when they can --
// none of that per-protocol machinery is reused here, since building an equivalent for 43 more
// protocols this file otherwise never decodes at all is far more machinery than a "name the presence"
// finding calls for) -- so it's always a best-effort guess, never upgraded, even for a TCP-based
// notable protocol (rdp/vnc/smb/ssh/http/https/ldap/ldaps/tacacs-plus/openvpn/stt) that a real SYN/
// SYN-ACK could in principle have resolved authoritatively. Render/consume accordingly.
struct InventoryNotableProtocol {
    std::string protocol;  // one of notable_it_protocols.hpp's 43 values, e.g. "rdp"/"ssh"/"gre"
    std::string tier;      // "remote-access"/"lateral-movement"/"enterprise-trust"/
                            // "wireless-backhaul"/"tunnel-vpn"
    bool has_ip = true;    // false only for eapol/pppoe/mpls (EtherType-keyed, no IP layer at all --
                            // see mac_a/mac_b below instead of client_ip/server_ip)
    std::string client_ip, server_ip;  // meaningful only when has_ip -- see this struct's own header
                                        // comment for why this is always the port-heuristic guess,
                                        // never a confirmed direction
    std::string mac_a, mac_b;  // meaningful only when !has_ip -- canonical order (mac_a < mac_b),
                                // the same no-direction convention this file's own InventoryEdge
                                // doesn't need (every one of ITS ten protocols has a real client/
                                // server concept) but PolicyEngine's EthernetFlowReport::mac_a/mac_b
                                // already establishes for PROFINET/GOOSE/SV/EtherCAT
    bool has_port = false;  // false only for an IP-protocol-number-keyed Tier 5 tunnel (gre/esp/ah/
                             // ip-in-ip/6in4/l2tp's direct-IP form) and for eapol/pppoe/mpls
    bool is_tcp = false;     // meaningful only when has_port
    uint16_t port = 0;      // meaningful only when has_port
    size_t packet_count = 0;
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
    // Packets that were not one of the eleven recognized protocols, had no IPv4 layer at all, or were
    // a HART-IP/FF-HSE packet seen over UDP (deliberately excluded -- see this file's own header
    // comment) -- never part of any asset/edge above. Mirrors PolicyReport::skipped_non_tcp's own role, though
    // the two aren't computed the same way: policy validate only ever looks at TCP; this counts a
    // recognized BACnet/CIP-I/O UDP packet as NOT skipped, unlike PolicyReport::skipped_non_tcp,
    // which would count that same packet as skipped (`policy validate` doesn't evaluate any UDP
    // traffic yet -- see docs/MANUAL.md's LIMITATIONS).
    size_t skipped_packets = 0;

    // "IT protocols an OT auditor flags" (ROADMAP item 18), one entry per distinct (protocol,
    // client/server or MAC pair, port) combination observed, in first-seen order -- ALWAYS
    // populated, independent of everything above (see InventoryNotableProtocol's own comment for why
    // this never changes what `skipped_packets` counts, or anything else in `assets`/`edges`/`zones`/
    // `conduits`).
    std::vector<InventoryNotableProtocol> notable_protocols;

    // patch257 security review finding 3 fix ("protocol state exhaustion remains a central
    // threat") -- true iff this capture's own AssetInventoryEngine hit at least one of its four
    // AssetInventoryEngineLimits growth ceilings, so `assets`/`edges`/`conduits`/`notable_protocols`
    // above may be an incomplete view of what the capture actually contains. See
    // AssetInventoryEngineLimits' own comment for the refuse-to-grow-further, never-evict admission
    // policy behind this, mirroring BaselineEngine's own observation_truncated (baseline.hpp).
    bool observation_truncated = false;
    // One human-readable line per DISTINCT ceiling that was hit, each naming the CLI flag that
    // raises it -- same dedup rule as BaselineEngine::mark_truncated. Empty iff observation_truncated
    // is false.
    std::vector<std::string> truncation_reasons;
};

// Item 64-style fix (patch257 finding 3, patch209 finding 1's own precedent for BaselineEngine) --
// AssetInventoryEngine's four accumulating containers (assets_/edges_/tcp_sessions_/
// notable_protocols_) had no growth ceiling at all before this: a spoofed-source flood or an
// engineered capture with unbounded distinct addresses/protocol combinations could grow this
// engine's own per-capture state without bound, exactly the "state allocation must not grow
// without bound per unique address" invariant patch257's finding 3 names. Same refuse-to-grow-
// further, never-evict, visibly-mark-truncated posture as BaselineEngineLimits (baseline.hpp) and
// for the identical reason: every one of these containers feeds this engine's own report output,
// so silently evicting an already-tracked entry to make room for a new one could make an
// already-reported asset/edge's own future updates (last_seen/packet_count) silently stop.
// Sized generously, same "one capture's worth of in-memory state, not a cumulative history" logic
// as BaselineEngineLimits' own sizing comment.
inline constexpr size_t kDefaultMaxInventoryAssets = 200000;
inline constexpr size_t kDefaultMaxInventoryEdges = 200000;
inline constexpr size_t kDefaultMaxInventoryTcpSessions = 50000;
inline constexpr size_t kDefaultMaxInventoryNotableProtocols = 50000;

struct AssetInventoryEngineLimits {
    size_t max_assets = kDefaultMaxInventoryAssets;
    size_t max_edges = kDefaultMaxInventoryEdges;
    size_t max_tcp_sessions = kDefaultMaxInventoryTcpSessions;
    size_t max_notable_protocols = kDefaultMaxInventoryNotableProtocols;
};

class AssetInventoryEngine {
public:
    // zone_prefix_len: the CIDR prefix length ([0, 32]) inferred zones are grouped by -- see
    // InventoryZone's own comment. Not validated here (cli_main.cpp's CLI11 ->check(CLI::Range(0,
    // 32)) enforces the range before this constructor ever runs, the same "CLI validates, the
    // engine trusts" division of responsibility PolicyEngine/Resolver already follow).
    explicit AssetInventoryEngine(uint8_t zone_prefix_len = kDefaultInventoryZonePrefixLen,
                                   AssetInventoryEngineLimits limits = AssetInventoryEngineLimits{});

    // True once at least one of limits_'s four growth ceilings refused to track something new at
    // least once -- see AssetInventoryEngineLimits' own comment for why refusal, never eviction.
    // Callers (cli_main.cpp) must surface this rather than let a truncated inventory run pass as an
    // ordinary complete one -- mirrors DetectEngine::truncated()/BaselineEngine::truncated().
    bool truncated() const { return truncated_; }

    // One human-readable line per DISTINCT ceiling that was hit -- same dedup rule as
    // BaselineEngine::mark_truncated. Empty iff truncated() is false.
    const std::vector<std::string>& truncation_reasons() const { return truncation_reasons_; }

    // Folds one already-decoded packet into this engine's asset/edge state. Call once per packet,
    // in capture order (same discipline as Decoder::decode/PolicyEngine::observe). A packet whose
    // protocol isn't one of this feature's eleven recognized ones, that has no IPv4 layer at all, or
    // that is a HART-IP/FF-HSE packet seen over UDP (see this file's own header comment), only
    // increments skipped_packets -- see AssetInventoryReport::skipped_packets' own comment.
    //
    // Client (initiator) vs. server, per protocol:
    //   - modbus/dnp3/s7comm (including a COTP-only session)/enip explicit messaging/iec104/hartip
    //     (TCP only)/opcua/mms/mqtt/ffhse (TCP only)/s7comm-plus -- every TCP-based protocol here:
    //     exactly PolicyEngine::observe's own priority order -- a pure SYN packet authoritatively marks its
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
    //
    // Independent of all of the above: a packet whose protocol is one of notable_it_protocols.hpp's
    // 43 "IT protocols an OT auditor flags" (ROADMAP item 18) is ALSO recorded into
    // AssetInventoryReport::notable_protocols -- see InventoryNotableProtocol's own comment for why
    // this never disturbs `skipped_packets` or this engine's own eleven-protocol asset/edge model,
    // and policy_engine.hpp's own NotableProtocolFinding for the analogous (independently
    // implemented) finding in `policy validate`.
    //
    // Also independent of all of the above: InventoryAsset::first_seen/last_seen and
    // InventoryEdge::first_seen/last_seen (DecodedPacket::timestamp's min/max across every packet
    // that asset/edge aggregates) are updated for every packet that reaches an update_asset/edge
    // call, regardless of protocol -- see those fields' own comments (asset_inventory.hpp).
    //
    // Passively-inferred device identity (InventoryAsset::vendor/product/firmware_revision/
    // serial_number/security_posture/plant_identification -- Grok gap #2): currently populated for
    // five protocols, all bound to DecodedPacket::src_ip on the specific packet carrying the
    // identity-bearing response (not simply "whichever side this session's handshake/port-heuristic
    // called the server," since that exchange is itself the thing deciding which side is the real
    // device):
    //   - EtherNet/IP, from a decoded ListIdentity response (EnipFrame::has_identity, see enip.hpp).
    //   - OPC UA, from a decoded GetEndpointsResponse's first endpoint (OpcUaMessage::has_identity,
    //     see opcua.hpp) -- `vendor`/`product` both get that endpoint's own ApplicationUri (OPC UA
    //     has no separate vendor/model field the way CIP Identity does), `firmware_revision`/
    //     `serial_number` stay empty, and `security_posture` records that same endpoint's own
    //     SecurityMode/SecurityPolicyUri, "SECURITY FINDING: "-prefixed when SecurityMode is "None"
    //     (an endpoint accepting no security at all) -- see InventoryAsset::security_posture's own
    //     comment.
    //   - S7comm, from a successful Read SZL response (S7CommResult::has_userdata_szl &&
    //     userdata_szl_is_response && szl_return_code == 0xFF, see s7comm.hpp) -- `product` prefers
    //     SZL-ID 0x0011's real Order Number/MLFB when present, falling back to SZL-ID 0x001C's own
    //     CPU-type/module/PLC name fields when it isn't; `serial_number` gets 0x001C's own serial
    //     number; `plant_identification` (a new, S7-specific field -- see its own comment) gets
    //     0x001C's own plant tag; `vendor`/`security_posture` stay unset (S7comm's SZL exchange
    //     carries neither a vendor name nor a security-posture-equivalent fact).
    //   - BACnet, from a ReadProperty/ReadPropertyMultiple ACK carrying one or more Device-object
    //     identity properties (BacnetApdu::has_device_identity, see bacnet.hpp's "Device object
    //     identity correlation" paragraph) -- `vendor`/`product`/`serial_number` get Vendor-Name/
    //     Model-Name/Serial-Number directly; `firmware_revision` prefers Firmware-Revision, falling
    //     back to Application-Software-Version only when Firmware-Revision itself wasn't read in
    //     this exchange; `security_posture`/`plant_identification` stay unset.
    //   - DNP3, from a Device Attributes response carrying one or more of five recognized
    //     attributes (Dnp3Result::dnp3_has_device_identity, see dnp3.hpp's "Device attribute
    //     identity correlation" paragraph) -- `vendor` gets Device Manufacturer's Name,
    //     `product` gets Device Product Name and Model, `serial_number` gets Device Serial Number,
    //     `firmware_revision` gets Device Manufacturer's Software Version (Device Manufacturer's
    //     Hardware Version has no field of its own here -- see dnp3.hpp's own comment on that);
    //     `security_posture`/`plant_identification` stay unset.
    // First-identity-seen wins for every field above, per asset. Every other protocol leaves these
    // fields empty for now.
    //
    // Tag/point/DB touch summarization (InventoryEdge::top_touched_addresses -- Phase 7 of Grok gap
    // #2): for the five protocols wired in (see that field's own comment for the full list and
    // per-protocol key format), every address this packet's own decoded structures name is folded
    // into that edge's internal touch-count map here in observe() -- the same per-packet
    // accumulation shape as `functions`/observed_functions above, just keyed by address instead of
    // function name, and capped (kMaxTrackedAddressesPerEdge) rather than unbounded. The final
    // sort-by-count-descending/truncate-to-top-N step happens once, in `finish()`, not here.
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
        double first_seen = 0.0;
        double last_seen = 0.0;
        bool has_timestamp = false;  // first packet sets both first_seen/last_seen unconditionally;
                                       // guards the min/max comparison on every packet after that
        std::string vendor, product, firmware_revision, serial_number;  // see InventoryAsset's own
                                                                          // comment
        std::string security_posture;       // see InventoryAsset::security_posture's own comment
        std::string plant_identification;   // see InventoryAsset::plant_identification's own comment
    };

    struct EdgeState {
        std::string client_ip, server_ip, protocol;
        uint16_t server_port = 0;
        std::unordered_set<std::string> functions;
        size_t packet_count = 0;
        // See InventoryEdge::direction_source's own comment -- mirrored here verbatim.
        DirectionSource direction_source = DirectionSource::PortHeuristic;
        double first_seen = 0.0;
        double last_seen = 0.0;
        bool has_timestamp = false;  // see AssetState::has_timestamp's own comment

        // Internal accumulation for InventoryEdge::top_touched_addresses -- see that field's own
        // comment (asset_inventory.hpp) for the per-protocol key format and the two-tier cap design.
        // Admission-capped at kMaxTrackedAddressesPerEdge distinct keys in observe() -- once hit, an
        // already-present key keeps incrementing but no new key is added. finish() sorts/truncates
        // this into the final top_touched_addresses list; this map itself is never sorted.
        std::unordered_map<std::string, size_t> address_touch_counts;
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

    // Populates an already-existing asset's identity fields (vendor/product/firmware_revision/
    // serial_number/security_posture) -- first-identity-seen wins, mirroring has_mac/mac's own
    // convention (see AssetState's own comment). A no-op if `ip` has no asset entry yet (can only
    // happen if `ip` was itself a broadcast/multicast address, which update_asset never creates an
    // entry for -- see looks_like_broadcast_or_multicast's own comment; a real device sending its
    // own identity response is never a broadcast source in practice, but this stays defensive rather
    // than assume it). `security_posture`/`plant_identification` default to empty for callers
    // (EtherNet/IP CIP Identity, and S7comm SZL responses that didn't carry a plant tag) that have
    // nothing to say about them.
    void update_identity(const std::string& ip, const std::string& vendor, const std::string& product,
                          const std::string& firmware_revision, const std::string& serial_number,
                          const std::string& security_posture = "",
                          const std::string& plant_identification = "");

    // Aggregated state for one InventoryNotableProtocol -- see that struct's own comment. Folds one
    // observation into notable_protocols_/notable_protocol_order_, keyed by `key` (already
    // canonicalized by the caller -- see observe()'s own three call sites in asset_inventory.cpp).
    struct NotableProtocolState {
        std::string protocol, tier;
        bool has_ip = true;
        std::string client_ip, server_ip;
        std::string mac_a, mac_b;
        bool has_port = false;
        bool is_tcp = false;
        uint16_t port = 0;
        size_t packet_count = 0;
    };
    void record_notable_protocol(const std::string& key, const std::string& protocol, const std::string& tier,
                                  bool has_ip, const std::string& client_ip, const std::string& server_ip,
                                  const std::string& mac_a, const std::string& mac_b, bool has_port, bool is_tcp,
                                  uint16_t port);

    // Appends `reason` to truncation_reasons_ (and sets truncated_) the first time it's seen; a
    // no-op on every later call with the same text -- identical dedup rule to
    // BaselineEngine::mark_truncated (baseline.cpp).
    void mark_truncated(const std::string& reason);

    // Shared by every one of this engine's four growth-capped containers' own "have I seen this key
    // before" check -- identical contract to DetectEngine::admit_tracked_key (detect_engine.hpp):
    // call with `already_present` = whether the caller's own map already contains the key, and
    // `current_map_size` = that same map's own .size(). Returns true when the key is either already
    // tracked or there's room for a new one (admitting it is the CALLER's job right after this
    // returns true); false when it's genuinely new and the map is already at its own ceiling (marks
    // this capture truncated and the caller must skip tracking this key). `map_name` becomes part
    // of the truncation reason text.
    bool admit_tracked_key(bool already_present, size_t current_map_size, size_t ceiling, const char* map_name,
                            const char* flag_name);

    uint8_t zone_prefix_len_;
    AssetInventoryEngineLimits limits_;
    bool truncated_ = false;
    std::vector<std::string> truncation_reasons_;
    std::unordered_map<std::string, AssetState> assets_;
    std::vector<std::string> asset_order_;
    std::unordered_map<std::string, EdgeState> edges_;
    std::vector<std::string> edge_order_;
    std::unordered_map<std::string, TcpSessionState> tcp_sessions_;  // keyed by canonical 4-tuple
    std::unordered_map<std::string, NotableProtocolState> notable_protocols_;
    std::vector<std::string> notable_protocol_order_;
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

// Phase 8 of Grok gap #2 ("turn inventory into a real OT asset record" -- CSV/CMDB export, see
// docs/design/asset-inventory-real-record.md). Renders `report.assets` (ONLY the asset list --
// deliberately asset-centric, not edge-centric: a CMDB import is a device inventory, one row per
// device, matching exactly what Grok's own review asked for; `report.edges`/`zones`/`conduits`
// have no place in a flat asset-per-row shape and are not rendered here at all -- use
// write_inventory_report_text/_json for the full communication-matrix/zone/conduit picture) as
// CSV to `out`, one row per InventoryAsset. `resolver`: see write_inventory_report_text's own
// comment -- `mac_vendor` is populated the same OUI-lookup way in every writer. Columns (in
// order): ip, mac, mac_vendor, vendor, product, firmware_revision, serial_number,
// plant_identification, security_posture, inferred_role, protocols (same comma-joined
// `protocol_list_text` rendering the text/JSON writers already use -- the embedded commas are not
// a problem: `csv_escape` quotes the whole field whenever it contains one, exactly the same as any
// other comma-bearing value, so this reuses the existing helper rather than inventing a second
// join convention just for CSV), ever_client, ever_server, first_seen, last_seen, packet_count.
// Quoting/escaping follows `decode --format csv`'s own
// `csv_escape` rules exactly (RFC 4180: a field is double-quoted only when it contains a comma,
// quote, or newline, with internal quotes doubled) via this file's own local copy of that helper
// (every CSV/JSON writer in this codebase keeps its own local escaper rather than sharing one
// across translation units -- see output.cpp/policy_engine.cpp/baseline.cpp's own `json_escape`
// for the same precedent). first_seen/last_seen render as the same human-readable UTC text
// format_epoch_seconds gives the text/JSON writers' own "_text" fields (not a raw epoch number --
// CSV has one column per fact, unlike JSON's raw+rendered pair, matching `decode --format csv`'s
// own single-"time"-column precedent rather than JSON's two-field one).
void write_inventory_report_csv(std::ostream& out, const AssetInventoryReport& report, const Resolver& resolver);

// Follow-up to Phase 8 above, added after initial delivery at Jurgen's request: a SEPARATE CSV
// export of `report.edges` (the host-to-host communication matrix Phase 8's own asset-centric CSV
// deliberately left out -- see that function's doc comment) to `out`, one row per InventoryEdge.
// `resolver`: same convention as every other writer in this file, with the same asset-CSV precedent
// for what's included -- `server_port_service` (a static /etc/services-style lookup, the same
// spirit as Phase 8's own `mac_vendor` column) is included, but hostname is NOT: DNS-based, and,
// like Phase 8's own asset CSV, deliberately excluded from every CSV export in this file since it
// needs a live resolver this offline pcap-analysis tool rarely has (write_inventory_report_csv
// already omits it for the same reason, even though write_inventory_report_json/`_text` both
// include it).
// Columns (in order): client_ip, server_ip, protocol, server_port, server_port_service,
// observed_functions (comma-joined via `protocol_list_text`, same reuse-not-reinvent posture as
// Phase 8's own `protocols` column), packet_count, direction_source (the exact lowercase,
// hyphenated string `direction_source_name` gives every other writer), first_seen, last_seen (both
// `format_epoch_seconds` text, matching Phase 8's own single-column-per-timestamp CSV convention,
// not JSON's raw+rendered pair). `InventoryEdge::top_touched_addresses` is deliberately NOT a
// column here -- it's a nested, variable-length (up to 32 entries) per-edge list, which doesn't fit
// a flat CSV row without either a second join convention or a second file; use `--format text`/
// `json` for that data. Quoting/escaping: this file's own local `csv_escape`, identical to every
// other CSV writer here.
void write_inventory_edges_csv(std::ostream& out, const AssetInventoryReport& report, const Resolver& resolver);

// Follow-up to Phase 8, added alongside write_inventory_edges_csv above at Jurgen's request: a CSV
// export of `report.conduits` (the inferred zone-to-zone communication summary -- see
// InventoryConduit's own comment) to `out`, one row per InventoryConduit. Columns (in order):
// from_zone, to_zone, protocol, port, port_service (resolver-supplied, same convention as
// write_inventory_edges_csv's own `server_port_service` -- looked up via the conduit's own
// `conduit_is_udp` transport, unlike the edges CSV/JSON's own always-"tcp" lookup, since a conduit
// (unlike an edge) has no client/server TCP-vs-UDP ambiguity left to resolve by the time it's this
// aggregated), edge_count, packet_count. No hostname/MAC lookup applies here at all -- a conduit
// has no IP/MAC of its own, only zone names and a port.
void write_inventory_conduits_csv(std::ostream& out, const AssetInventoryReport& report, const Resolver& resolver);

// Phase 9 of Grok gap #2 ("STIX/TAXII-lite export", docs/design/asset-inventory-real-record.md).
// Renders `report.assets` as a minimal, valid STIX 2.1 bundle to `out` -- ONE `infrastructure` SDO
// per asset (again deliberately asset-only, same posture and same reasoning as
// write_inventory_report_csv above; no edges/zones/conduits object exists in this bundle).
// "Lite" means exactly this: a standalone STIX 2.1 JSON file a human or another tool can hand to a
// TAXII server or any other STIX consumer -- conduitscope itself implements no TAXII client or
// server (that's a transport protocol, out of scope for a passive analysis CLI; confirmed with
// Jurgen before implementing).
//
// `infrastructure_types` is fixed to `["unknown"]` for every object -- STIX 2.1's own open
// vocabulary (`infrastructure-type-ov`) has no ICS/OT-specific value (its members are all
// attacker-infrastructure concepts: botnet, command-and-control, staging, etc.), so "unknown" is
// the only honest choice rather than forcing a mismatch; this asset's actual nature lives in the
// `x_conduitscope_*` custom properties below instead. Each SDO also carries every populated
// InventoryAsset field as an `x_conduitscope_`-prefixed custom property (STIX 2.1 section 3.6
// explicitly permits `x_`-prefixed custom properties on any SDO) -- ip, hostname (if resolved),
// mac/mac_vendor (if has_mac), vendor/product/firmware_revision/serial_number/
// plant_identification/security_posture (each omitted, never emitted empty/null, exactly the
// omit-on-miss convention every other writer in this file already follows), inferred_role
// (always present, same "Unknown is a real conclusion" reasoning as the JSON writer),
// protocols (a real JSON array here, not a joined string -- STIX/JSON has no CSV-style delimiter
// problem to work around), ever_client, ever_server, packet_count.
//
// `id`/`created`/`modified`: STIX requires every SDO id to match `<type>--<UUID>`, and every SDO
// to carry `created`/`modified` timestamps. There is no random-UUID source anywhere in this
// codebase (deliberately -- see below), so ids here are DETERMINISTIC, derived from a
// non-cryptographic FNV-1a hash of a stable per-object key (`"bundle:" + capture_path` for the
// bundle itself, `"infrastructure:" + ip` for each asset) via this file's own local
// `deterministic_uuid` helper -- same capture, re-run twice, produces a byte-identical bundle
// (Grok item 7's "reproducible report" property, applied here even though this phase's own scope
// is item 2, not item 7). Formatted as a real RFC 9562 version-8 ("custom") UUID -- version 8 is
// specifically reserved for implementation-defined deterministic UUIDs like this one, so the
// result is a spec-conformant UUID, just not a spec-required *random* one. Deliberately NOT built
// on sha256.hpp: that module exists for exactly one purpose (QUIC key derivation, see its own file
// header, "NOT a general-purpose crypto library") and a stable identifier has no cryptographic
// requirement at all, so reusing it here would be scope creep on a narrowly-scoped module for no
// benefit. `created`/`modified` render as `first_seen`/`last_seen` through this file's own local
// `format_stix_timestamp` (STIX's required millisecond-precision "T"-separated RFC 3339 shape --
// distinct from every other timestamp renderer in this codebase, which all use
// `time_format.hpp`'s space-separated, microsecond-precision convention instead).
//
// Follow-up, added after initial delivery at Jurgen's request: the bundle's `objects` array (a
// single flat list per STIX 2.1 -- SDOs and SROs share it, there is no second top-level array) also
// carries one `relationship` SRO per InventoryEdge, appended after every `infrastructure` SDO --
// this is what actually links the per-asset `infrastructure` nodes into a graph a STIX consumer can
// traverse; the asset-only bundle above had nothing of the sort. `relationship_type` is the
// producer-defined string `"communicates-with"` -- STIX 2.1's own common-relationships table
// (section 6) has no infrastructure-to-infrastructure entry at all (its entries are almost all
// indicator/malware/threat-actor-centric), so this follows section 3.7.2.4's explicit allowance for
// a producer-defined type when no common one fits, the same "spec-conformant, honestly not one of
// the enumerated standard values" posture `infrastructure_types: ["unknown"]` above already takes.
// Direction is encoded the standard STIX way, not a separate field: `source_ref` is always the
// edge's own `client_ip` (the initiator) and `target_ref` its `server_ip` -- so, read from a given
// `infrastructure` node's own perspective, any relationship where it's `source_ref` is one of ITS
// outgoing edges, and any relationship where it's `target_ref` is one of ITS incoming edges; a STIX
// consumer builds that per-node incoming/outgoing view the normal way, by filtering the bundle's
// relationship objects on that node's own id -- this project doesn't duplicate that view onto the
// infrastructure objects themselves. Each relationship's `id`/`created`/`modified` follow exactly
// the same deterministic-UUID/STIX-timestamp convention as the infrastructure objects above
// (`created`/`modified` from the edge's own `first_seen`/`last_seen`; the id key reuses this file's
// own internal `edge_key(protocol, client_ip, server_ip, server_port)` -- the SAME string that
// already uniquely identifies this exact edge inside the engine itself, rather than inventing a
// second key scheme). `source_ref`/`target_ref` point at the SAME deterministic infrastructure ids
// the asset objects above already use (`"infrastructure:" + ip`), so a relationship always resolves
// to a real object already present in this same bundle. Carries `x_conduitscope_protocol`,
// `_server_port`, `_server_port_service` (if resolved), `_packet_count`, `_direction_source`, and
// `_observed_functions` (if non-empty) as the same kind of `x_`-prefixed custom properties the
// infrastructure objects already carry, plus a plain-English `description` ("<protocol> (port
// <port>)").
void write_inventory_stix_json(std::ostream& out, const AssetInventoryReport& report,
                                const std::string& capture_path, const Resolver& resolver);

// Phase 10 of Grok gap #2 ("firewall ACL draft export", docs/design/asset-inventory-real-record.md)
// -- the one export phase that needs no asset identity fields at all (Grok's own ask here is
// "propose an ACL matching the zones/conduits I already observed," not asset identity), so these
// three renderers draw ONLY from `report.zones`/`report.conduits`, mirroring
// write_inventory_diagram_mermaid/_dot's own "just the zone/conduit graph" scope exactly -- not
// `write_inventory_report_csv`/`_stix_json`'s asset-centric scope.
//
// Each renders the SAME inferred zones-as-address-objects, conduits-as-rules model, one function
// per vendor CLI dialect (Cisco IOS/ASA object-group + extended ACL; FortiGate `config firewall`
// address/service/policy blocks; Palo Alto PAN-OS `set` CLI commands) -- drafted as three separate
// renderers rather than one shared intermediate representation with three back-ends: each
// dialect's own address-object/service-object/rule shape (Cisco's nested object-group syntax vs.
// FortiGate's edit/next numbered-policy blocks vs. Palo Alto's flat `set` command list) differs
// enough that a generic IR would mostly just be re-serialized per format anyway, without
// meaningfully reducing the actual per-dialect logic -- revisit only if a fourth dialect is ever
// requested and the duplication actually starts to hurt.
//
// One address object per InventoryZone (its own CIDR -- `network.text`/`network.network`+
// `prefix_len`, already exactly the group this zone's own member IPs share); one rule per
// InventoryConduit, naming its own zone-pair address objects and (protocol, port). Transport
// (tcp/udp) is derived from the conduit's own `port`, matching exactly which two ports
// AssetInventoryEngine::observe treats as UDP-carrying in the first place (BACNET_UDP_PORT,
// ENIP_IO_UDP_PORT -- see is_known_target_port's own comment) -- every other conduit in this
// report is necessarily TCP, since this engine only ever recognizes those two ports over UDP.
//
// EVERY line of output is explicitly, prominently labeled a first-draft for human review -- never
// something this project claims is ready to deploy -- in both a header comment block (every
// dialect supports `!`/`#`-style comments) and docs/USER_GUIDE.md. An empty `report.zones` (no
// asset was ever observed) renders header comments only, same "don't emit a file that looks
// loadable but isn't" posture write_inventory_policy_yaml already takes for the identical case.
void write_inventory_acl_cisco(std::ostream& out, const AssetInventoryReport& report);
void write_inventory_acl_fortinet(std::ostream& out, const AssetInventoryReport& report);
void write_inventory_acl_paloalto(std::ostream& out, const AssetInventoryReport& report);

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
