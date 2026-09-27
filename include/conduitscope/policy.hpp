// SPDX-License-Identifier: Apache-2.0
// policy.hpp - zone/conduit policy file parsing for `policy validate`.
//
// A policy file declares named zones and named conduits (an allowed
// protocol+port relationship from a set of zones to a set of zones --
// many-to-many, not just one zone to one zone). See docs/MANUAL.md's POLICY
// FILE FORMAT section for the full schema, worked examples, and the
// reasoning behind each validation rule below. PolicyEngine
// (policy_engine.hpp) is what actually evaluates decoded traffic against a
// Policy parsed here; this file only parses and validates the policy
// document itself, independent of any capture.
//
// A zone is built from ONE of three addressing schemes, mutually exclusive
// per zone (ROADMAP item 15, extended by the "match how plants are zoned"
// work -- see docs/DEVELOPMENT.md):
//   - IPv4 CIDR blocks (`networks:`) -- the original, TCP-flow-oriented
//     model, matched against a flow's client/server IP by PolicyEngine.
//   - VLAN membership (`vlans:`) -- for the four protocols with no IP layer
//     at all (PROFINET RT, GOOSE, Sampled Values, EtherCAT -- see
//     docs/USER_GUIDE.md's POLICY FILE FORMAT "Addressing scope" section for why
//     a CIDR zone doesn't apply to them). A VLAN zone answers a genuinely
//     different question than an IP zone does: not "is this flow allowed
//     from zone A to zone B" (there is no router in the picture -- none of
//     these four protocols can ever leave the Ethernet segment/VLAN they
//     were transmitted on, by construction), but "is this protocol's
//     traffic present on the VLAN(s) it's supposed to be on AT ALL" (a
//     mis-patched switch port, an accidentally bridged VLAN, or traffic
//     that isn't VLAN-tagged when the segmentation design assumed it would
//     be). Because a single raw-Ethernet frame carries at most one 802.1Q
//     tag -- there is no "source VLAN" and "destination VLAN" the way a TCP
//     flow has a client IP and a server IP -- a VLAN-zone conduit's `from`
//     and `to` are required to name the exact same zone(s) (see Conduit
//     below and parse_policy_text's validation): the conduit means "this
//     protocol is permitted on this VLAN zone," not a directional flow
//     between two zones. `ports`, `bidirectional`, and `functions` are all
//     rejected on a VLAN-zone conduit -- none of them has a meaning for a
//     protocol with no TCP/UDP layer at all (ports, functions) or no
//     client/server session concept (bidirectional). A VLAN-zone conduit
//     gains its own optional field in exchange, `from_macs:` (Phase 5, see
//     docs/design/policy-engine-zoning.md) -- an allow-list of source MAC
//     addresses permitted to publish this conduit's protocol(s) on the
//     VLAN, meaningless (and rejected) on a CIDR-/hostname-zone conduit,
//     which already has a client/server IP pair to restrict by instead.
//     See PolicyEngine::observe's own comment for how this is evaluated.
//   - Hostnames (`hostnames:`) -- an alternate way to name an IP endpoint, not
//     a fourth kind of traffic: a hostname-zone conduit behaves exactly like
//     a CIDR-zone conduit (ports/bidirectional/functions all meaningful,
//     matched through the same TCP/UDP FlowReport path) and is evaluated
//     ONLY once a CIDR-zone lookup for that flow's endpoint misses (see
//     PolicyEngine::finish). Matching requires a Resolver whose hostname
//     source is a pinned, operator-supplied `--hosts FILE` (never live DNS --
//     see resolver.hpp's own file header for why): `policy validate` fails
//     fast, before evaluating anything, if a policy declares a hostname
//     zone but `--resolve`/`--hosts` were not both given, rather than
//     silently matching nothing. This keeps a compliance verdict
//     reproducible run-to-run, which a live DNS lookup could never be.
//
// `Zone::kind`/`Conduit::kind` (see below) is the explicit discriminator for
// which of the three a given zone/conduit is -- never inferred from which
// vector happens to be non-empty -- so every place that needs to branch on
// zone kind (Conduit validation, PolicyEngine's dispatch) says so plainly.
//
// The file format is YAML-*compatible* but deliberately not general YAML --
// see yaml_mini.hpp for exactly which subset is parsed, and why a purpose-
// built parser rather than a vendored YAML library.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace conduitscope {

// One IPv4 CIDR block, e.g. "10.10.10.0/24" (or a bare "10.10.10.5",
// equivalent to "/32"). `network` is already masked down to `prefix_len`
// bits -- parse_cidr silently clears any host bits in the input rather than
// rejecting them (e.g. "10.10.10.5/24" becomes network 10.10.10.0/24),
// matching how most IP tooling (e.g. `ip route`) treats a host address given
// with a shorter prefix. `text` keeps the original, as-written string for
// error messages and reports.
struct CidrBlock {
    uint32_t network = 0;
    uint8_t prefix_len = 32;
    std::string text;
};

// True if `ip` (host order) falls inside `block`.
bool cidr_contains(const CidrBlock& block, uint32_t ip);

// True if `a` and `b` describe any address in common (used by
// parse_policy_text to reject a policy where the same address could belong
// to two different zones -- see the "each address belongs to at most one
// zone" validation rule below).
bool cidr_overlaps(const CidrBlock& a, const CidrBlock& b);

// Parses "a.b.c.d" or "a.b.c.d/N" (N in [0,32]) into a CidrBlock. Returns
// std::nullopt (never throws) for anything else -- including a bare address
// with no "/", which is accepted and treated as /32, but not e.g. a hostname
// or an IPv6 address (this tool is IPv4-only throughout, matching ipv4.hpp).
std::optional<CidrBlock> parse_cidr(const std::string& text);

// The 802.1Q-usable VLAN ID range a declared zone's `vlans:` entries are validated against. VID 0
// is reserved by the standard for priority-tagged, non-VLAN-member frames (a frame with a "VLAN
// tag" whose 12-bit VID happens to be 0 carries no real VLAN membership at all) and VID 4095 is
// reserved outright -- neither can ever meaningfully be "the VLAN this zone's traffic lives on",
// so neither is accepted here, the same "reject what can't be a real value" posture parse_cidr
// takes toward an out-of-range prefix length.
constexpr int kMinVlanId = 1;
constexpr int kMaxVlanId = 4094;

// Which of the three mutually-exclusive addressing schemes a Zone/Conduit uses -- see this file's
// own header comment for what each means. A bool sufficed while there were only two (Cidr/Vlan);
// this became a proper enum once Hostname was added, so every 2-way branch on the old
// `is_vlan_zone`/`is_vlan_conduit` bool became a 3-way branch on `kind` instead (mechanical,
// zero-behavior-change refactor -- see docs/DEVELOPMENT.md).
enum class ZoneKind { Cidr, Vlan, Hostname };

struct Zone {
    std::string name;
    std::string description;  // optional; empty if not given
    // Exactly one of `networks`/`vlans`/`hostnames` is ever non-empty for a given zone --
    // parse_policy_text rejects a zone declaring more than one or none. `kind` is the explicit
    // discriminator (rather than callers inferring it from which vector is non-empty) so every
    // place that needs to branch on zone kind (Conduit validation, PolicyEngine's dispatch) says so
    // plainly. See this file's own header comment for why a zone is exactly one of the three.
    ZoneKind kind = ZoneKind::Cidr;
    std::vector<CidrBlock> networks;
    std::vector<uint16_t> vlans;
    std::vector<std::string> hostnames;  // ZoneKind::Hostname only -- lowercase not enforced (matched
                                          // case-sensitively against the Resolver's hosts-file entries,
                                          // which themselves preserve the file's own casing)
    // Optional, purely informational Purdue Enterprise Reference Architecture level label (e.g. "0",
    // "1", "2", "3", "3.5", "4") -- never read by any matching logic in PolicyEngine, just carried
    // through to reports so an auditor sees each zone's declared level alongside its name. Empty
    // (the default) when the policy file's zone doesn't set `purdue_level:`.
    std::string purdue_level;
    int line = 0;  // policy-file line the zone was declared on, for PolicyEngine reports
};

// One allowed conduit between a set of zones. `from_zones`/`to_zones` each
// name one or more declared zones (the policy file's `from`/`to` keys accept
// either a single scalar zone name or a list of them -- see as_scalar_list in
// policy.cpp for the shared single-or-list parsing, also used by `networks`,
// `vlans`, `protocols`, and `ports`), and the conduit is many-to-many: it permits
// traffic from ANY zone in `from_zones` to ANY zone in `to_zones`, not just
// one specific pair. This lets e.g. "permit traffic from either the
// corporate zone or the remote-access zone into either of two PLC zones" be
// written as one conduit, instead of one conduit per zone pair. `protocols`
// holds lowercased values from {"modbus", "dnp3", "s7comm", "iec104", "enip",
// "bacnet", "hartip", "opcua", "mms", "mqtt", "ffhse", "profinet", "goose",
// "sv", "ethercat", "any"} (parse_policy_text rejects anything else) -- "any"
// matches every protocol reachable through this conduit's own zone kind (see
// below), not literally every protocol conduitscope recognizes. Of the six
// named after "enip", only hartip/opcua/mms/mqtt/ffhse can ever actually
// match a flow today: `policy validate` only ever evaluates TCP flows (see
// PolicyEngine::observe), and "bacnet" names BACnet/IP, which this decoder
// only ever recognizes over UDP (see decoder.cpp) -- so a conduit naming
// "bacnet" parses and validates fine but can never be exercised by real
// traffic yet; see docs/MANUAL.md's POLICY FILE FORMAT "Addressing scope"
// section. The four newest names (profinet/goose/sv/ethercat -- ROADMAP item
// 15) are a DIFFERENT kind of protocol entirely: they ride raw Ethernet with
// no IP layer at all, so they can only ever appear in a conduit whose
// `from_zones`/`to_zones` are ALL VLAN zones (Zone::kind == ZoneKind::Vlan), never
// mixed with a CIDR or hostname zone, and never alongside any of the TCP-only protocol
// names above (parse_policy_text rejects both combinations) -- see
// policy.hpp's own header comment and Zone's comment for the full VLAN-zone
// model. `ports` is the set of TCP ports this conduit
// covers on the RESPONDING (server) side of the connection; empty means "any
// port" (parse_policy_text allows omitting the field entirely for that) --
// meaningless for a VLAN-zone conduit (there is no TCP/UDP layer to have a
// port at all), so parse_policy_text rejects `ports` there outright rather
// than silently ignoring it.
// `bidirectional` additionally allows the same protocol/port set initiated
// the opposite way (a `to_zones` member -> a `from_zones` member) -- most
// real OT conduits are one-directional (an HMI/engineering zone reaching
// into a control-network zone), which is why this defaults to false; see
// docs/MANUAL.md's POLICY FILE FORMAT section for why direction is modeled
// this way rather than tracked per-packet. Also meaningless for a VLAN-zone
// conduit (there is no client/server session to reverse), and rejected
// outright there the same way `ports` is -- see above.
//
// A VLAN-zone conduit has one further, load-time-enforced requirement not
// shared by an IP-zone conduit: `from_zones` and `to_zones` must name the
// EXACT SAME set of zones. A single raw-Ethernet frame carries at most one
// 802.1Q tag, so it belongs to at most one VLAN zone -- there is no "source
// zone" and "destination zone" the way a TCP flow has a client IP and a
// server IP to classify separately. Requiring from==to makes what the
// conduit actually means explicit in the policy file itself: "this
// protocol is permitted on this VLAN zone," not a directional flow between
// two zones (which no capture could ever exercise for these four protocols
// -- see policy.hpp's own header comment).
struct Conduit {
    std::string name;
    std::string description;
    std::vector<std::string> from_zones;
    std::vector<std::string> to_zones;
    std::vector<std::string> protocols;
    std::vector<uint16_t> ports;
    bool bidirectional = false;
    // The kind shared by every zone in from_zones/to_zones (ZoneKind::Vlan/Cidr/Hostname) -- set
    // once, at parse time, by parse_policy_text's own zone-kind-consistency check, rather than
    // PolicyEngine re-deriving it by looking up each zone name every time a flow is matched against
    // this conduit. parse_policy_text rejects a conduit that mixes kinds, so this is a genuine
    // either/or/or, never ambiguous. A Hostname-zone conduit is matched exactly like a Cidr-zone
    // conduit (see policy.hpp's own header comment) -- `kind` still distinguishes them because
    // Cidr/Hostname zone lookups themselves are different (Policy::zone_for vs.
    // Policy::zone_for_hostname), even though the surrounding conduit-matching logic in
    // PolicyEngine::finish is shared between the two.
    ZoneKind kind = ZoneKind::Cidr;

    // Optional conduit classification, from an optional `type:` key. Only one recognized value
    // today, "idmz" (case-insensitive; stored lowercased) -- marks a conduit as an IT-OT/iDMZ
    // crossing. Purely additive: empty (the default -- no `type:` given) behaves exactly as before
    // this field existed. An "idmz"-tagged conduit gets ONE extra validation rule (see
    // parse_policy_text: 'protocols: [any]' combined with an empty 'functions' list is rejected,
    // forcing an explicit protocol list at a declared IT/OT boundary) and its own "IT-OT CROSSING
    // CONDUITS" report section (see write_policy_report_text/_json) -- never a different runtime
    // default-deny posture, since an unmatched zone pair is already a Violation regardless of this
    // field (see PolicyEngine::finish).
    std::string conduit_type;

    // Optional allow-list of function/service names this conduit permits WITHIN its single
    // protocol -- e.g. only "Read Holding Registers" on an otherwise-permitted Modbus conduit, not
    // "Write Multiple Registers" too. Empty (the default -- omitted, or 'functions'/'function' not
    // given) means fully unrestricted, exactly the behavior before this field existed: every
    // function/service the protocol decodes is permitted. Non-empty only ever appears alongside
    // `protocols` resolving to exactly one concrete protocol (parse_policy_text rejects any other
    // combination -- see its own comment below) -- each string is stored in the CANONICAL casing
    // that protocol's decoder itself emits (modbus_function_name/dnp3_function_name/
    // s7comm_function_name/iec104_type_short_name/enip_cip_service_name -- see each protocol's own
    // *_known_*_names() function), regardless of how the policy file capitalized it, since matching
    // (PolicyEngine) is case-insensitive but display (error messages, report reasons) always uses
    // the decoder's own casing. See docs/MANUAL.md's POLICY FILE FORMAT section for the full
    // schema and PolicyEngine::finish (policy_engine.cpp) for exactly how a flow's observed
    // functions are checked against this list.
    //
    // Two reserved, case-insensitive group keywords are also accepted here: "read" and "write".
    // Each expands at parse time (parse_policy_text) into that protocol's full Read- or
    // Write-classified function/service name set (modbus_read_function_names()/
    // *_write_function_names(), and each protocol's equivalent -- see the *FunctionAccess enum
    // alongside each protocol's own known-function table in modbus/dnp3/s7comm/iec104/enip
    // .hpp/.cpp) and is freely combinable with literal names in the same list, e.g.
    // `functions: [read, "Diagnostics"]`. A literal name already covered by the expanded group is
    // silently deduplicated, never double-stored. The keyword always wins any naming collision
    // with a literal function name (relevant for DNP3, whose own function codes 0x01/0x02 are
    // themselves literally named "Read"/"Write" -- see dnp3.hpp) -- there is no way to select
    // DNP3's literal Read/Write function code alone via this field once its protocol is DNP3;
    // name it as part of a wider `functions:` list only via other means (it can't be isolated).
    // Deliberately NOT expanded into either group: any function/service classified `Other` (has
    // no clean read-or-write data-plane effect, or mixes both) -- it must still be named
    // explicitly if a conduit needs to permit it. For DNP3 specifically, a `read`/`write`-
    // restricted conduit typically also needs "Response" (and/or "Confirm") named explicitly
    // alongside the keyword, since real bidirectional DNP3 exchanges always carry one of those on
    // the reply side and both are Other-classified (no way to tell, from the frame alone, whether
    // a Response answered a read or a write) -- see functions_group_write_dnp3_with_response.yaml.
    std::vector<std::string> functions;

    // Optional allow-list of source MAC addresses this VLAN-zone conduit permits publishing --
    // from an optional `from_macs:` key (singular alias `from_mac:`, for a one-MAC conduit,
    // mirroring every other scalar-or-list conduit field). Empty (the default -- omitted, or
    // 'from_macs'/'from_mac' not given) means unrestricted, exactly the behavior before this field
    // existed: any source may publish. Only ever non-empty on a VLAN-zone conduit
    // (`kind == ZoneKind::Vlan`) -- parse_policy_text rejects it on a CIDR-/hostname-zone conduit,
    // since those already have a client/server IP pair to restrict by (via `from_zones`/`to_zones`
    // and `ports`) and no single stable "the source" for a bidirectional TCP session the way a
    // one-directional cyclic publish stream has one. This is the mechanism that actually restricts
    // WHO may publish GOOSE/Sampled Values/PROFINET-RT/EtherCAT traffic on a VLAN (e.g. "only the
    // real protection relay, not some other device on the same VLAN, may source GOOSE frames") --
    // not a publisher/subscriber pairing, since a multicast destination has no real "subscriber
    // address" to restrict against; see docs/design/policy-engine-zoning.md's Phase 5. Each entry
    // is stored canonicalized to the same lowercase, colon-separated form
    // `format_mac()` (link_layer.cpp) emits for `DecodedPacket::src_mac` (e.g. "00:0c:29:11:22:33"),
    // regardless of how the policy file capitalized it -- parse_policy_text rejects anything that
    // isn't exactly six colon-separated hex octets. See `EthernetFlowReport::src_mac` (
    // policy_engine.hpp) for how the observed source is determined, and `PolicyEngine::finish` for
    // exactly how it's checked against this list.
    std::vector<std::string> from_macs;

    int line = 0;
};

// One declared multi-homed asset (Phase 6, see docs/design/policy-engine-zoning.md) -- a real
// piece of equipment with more than one network interface (a dual-homed HMI, an engineering
// workstation that also has a corporate-network NIC, a jump host bridging two segments), declared
// here as policy-file ground truth rather than something PolicyEngine infers from traffic. A
// fully optional top-level `assets:` section; omitted entirely (the common case today): zero
// effect on anything -- no Asset exists, `PolicyReport::multi_homed_assets`/`jump_host_flows` stay
// empty, and no FlowVerdict anywhere is ever affected by this feature's mere existence (this is an
// advisory, cross-referencing report addition, never a new matching primitive -- see
// PolicyEngine::finish's own comment for exactly what it cross-references and why it can never
// turn an otherwise-COMPLIANT capture NON-COMPLIANT).
struct Asset {
    std::string name;
    // 2 or more IPv4 addresses/CIDR blocks -- what makes this asset "multi-homed" in the first
    // place (parse_policy_text rejects fewer than two: a single-homed asset needs no entry here at
    // all). Parsed by the same `parse_cidr` every zone's own `networks:` list uses, so a bare
    // address is treated as /32 exactly the same way; PolicyEngine::finish looks up each block's
    // own network address (CidrBlock::network) via Policy::zone_for, the same lookup an ordinary
    // flow's client_ip/server_ip already goes through -- there is no new zone-matching mechanism
    // here, just a second thing (an asset) checked against the SAME zones a flow's endpoint would
    // be.
    std::vector<CidrBlock> ips;
    // Optional, purely informational free-form string (e.g. "jump_host", "hmi", "engineering_ws"),
    // from an optional `role:` key -- same posture as Zone::purdue_level: never read by any
    // MATCHING logic (nothing here changes a FlowVerdict). The one exception, and the only string
    // this codebase ever compares against, is checked case-insensitively: an asset whose `role`
    // reads "jump_host" gets its own extra report subsection (PolicyReport::jump_host_flows) --
    // every flow where either endpoint belongs to it is called out regardless of that flow's own
    // compliant/violation/unclassified status, since "remote access via jump host" is the pattern
    // being watched for, independent of whether the individual flow happens to be policy-compliant
    // (see docs/USER_GUIDE.md's "Multi-homed assets and jump hosts" section). Stored exactly as
    // written in the policy file (not lowercased), unlike Conduit::conduit_type's small closed
    // value space -- this field is free text, not a fixed enum.
    std::string role;
    // Optional free-text 'description' key, purely for the policy author's own documentation --
    // mirrors Zone::description/Conduit::description, never read by any matching or reporting
    // logic.
    std::string description;
    int line = 0;
};

struct Policy {
    std::vector<Zone> zones;
    std::vector<Conduit> conduits;
    // Optional top-level `assets:` list of declared multi-homed assets (Phase 6). Empty (the
    // default -- 'assets:' omitted entirely) means zero effect: see Asset's own header comment.
    std::vector<Asset> assets;

    // Returns the zone whose CIDR list contains `ip`, or nullptr if no
    // declared zone does. Because parse_policy_text already rejects any
    // policy where two zones' networks overlap (see cidr_overlaps above), at
    // most one zone can ever match -- this returns the first (only) one.
    const Zone* zone_for(uint32_t ip) const;

    // Same idea for a VLAN zone: returns the zone whose `vlans` list contains `vlan_id`, or
    // nullptr if no declared VLAN zone does (including when the policy declares no VLAN zone at
    // all). parse_policy_text rejects any policy where two VLAN zones share a VLAN ID (mirroring
    // cidr_overlaps' "each address belongs to at most one zone" rule), so at most one zone can
    // ever match here too.
    const Zone* zone_for_vlan(uint16_t vlan_id) const;

    // True if at least one declared zone is a VLAN zone -- PolicyEngine caches this once at
    // construction (see policy_engine.hpp) to decide whether PROFINET RT/GOOSE/Sampled Values/
    // EtherCAT traffic should be evaluated against VLAN zones at all, or left in
    // PolicyReport::skipped_non_tcp exactly as it was before this feature existed. This keeps
    // every policy file written before VLAN zones existed byte-for-byte compatible: a policy with
    // only CIDR zones never evaluates this kind of traffic, so it can never turn an
    // otherwise-COMPLIANT capture NON-COMPLIANT just because it happens to also contain some
    // PROFINET RT/GOOSE/SV/EtherCAT traffic the policy's author never intended to address at all.
    bool has_vlan_zone() const;

    // Same idea again for a hostname zone: returns the zone whose `hostnames` list contains
    // `hostname` (exact, case-sensitive match against the Resolver-supplied name), or nullptr if no
    // declared hostname zone does. parse_policy_text rejects any policy where two hostname zones
    // share a hostname. Never called with an empty string -- see PolicyEngine::finish's own
    // comment for when a hostname lookup even happens.
    const Zone* zone_for_hostname(const std::string& hostname) const;

    // True if at least one declared zone is a hostname zone -- mirrors has_vlan_zone's own
    // backward-compatibility purpose: PolicyEngine only ever attempts a hostname lookup (which
    // requires --resolve/--hosts, see policy.hpp's own header comment) when this is true, so a
    // policy with no hostname zone is entirely unaffected by whether those flags were given.
    bool has_hostname_zone() const;

    // True if at least one CIDR- or hostname-zone conduit (never a VLAN-zone conduit -- see below)
    // names "bacnet", "enip", or "any" in its `protocols:` -- the opt-in gate for evaluating
    // BACnet/IP and CIP I/O traffic (both UDP, both IP-addressed) against a conduit at all, instead
    // of leaving them in PolicyReport::skipped_non_tcp exactly as before this feature existed (see
    // PolicyEngine::observe's own comment, and docs/design/policy-engine-zoning.md's Phase 3). This
    // mirrors has_vlan_zone/has_hostname_zone's own "cached once, at PolicyEngine construction"
    // backward-compatibility posture: a policy that never names these protocols on a CIDR/hostname
    // conduit is byte-for-byte unaffected by this feature's existence. A VLAN-zone conduit naming
    // "enip" or "any" doesn't count here -- it can only ever mean PROFINET RT/GOOSE/SV/EtherCAT (see
    // parse_policy_text's own protocol-vs-zone-kind validation), never BACnet/IP or CIP I/O, both of
    // which are ordinary IP traffic that could never reach a VLAN-zone conduit's matching logic.
    bool has_udp_eligible_conduit() const;
};

struct PolicyError : std::runtime_error {
    explicit PolicyError(const std::string& msg) : std::runtime_error(msg) {}
};

// Parses already-read policy file text into a fully validated Policy.
// `source_name` (typically the file path) is used only to prefix error
// messages, in "<source_name>:<line>: <message>" form when a line number is
// known, else "<source_name>: <message>". Throws PolicyError on:
//   - a YAML-subset syntax problem (propagated from yaml_mini::YamlError)
//   - a missing top-level 'zones' or 'conduits' key, or either being empty
//   - a zone declaring none of 'networks'/'vlans'/'hostnames', or more than
//     one of them -- each zone is exactly one kind (see this file's own
//     header comment)
//   - a zone's 'networks' containing a value that isn't a valid CIDR/address
//   - a zone's 'vlans' containing a value that isn't an integer in
//     [kMinVlanId, kMaxVlanId] ([1, 4094] -- VID 0 and 4095 are reserved,
//     see kMinVlanId/kMaxVlanId's own comment)
//   - a zone's 'hostnames' containing an empty value
//   - two zones of the SAME kind overlapping/duplicating: two CIDR zones
//     whose networks overlap (see cidr_overlaps), two VLAN zones sharing a
//     VLAN ID, or two hostname zones sharing a hostname -- the same "each
//     address/VLAN/hostname belongs to at most one zone" rule, checked
//     separately per zone kind (zones of different kinds can never overlap
//     with each other, having no addressing scheme in common)
//   - a zone literally named "unclassified" -- that name is reserved for
//     traffic PolicyEngine finds matches no declared zone; declaring it
//     explicitly would make that reporting ambiguous
//   - a duplicate zone or conduit name
//   - a conduit missing 'name'/'from'/'to'/'protocols', or whose 'from'/'to'
//     contains a zone name that isn't declared in 'zones' (each entry of a
//     list 'from'/'to' is checked, not just the first)
//   - a conduit's 'from'/'to' list being empty (e.g. 'from: []')
//   - a conduit's 'from'/'to' zones mixing zones of different kinds -- every
//     zone a conduit references, on either side, must be the same kind
//   - a conduit's protocol not in {modbus, dnp3, s7comm, iec104, enip, bacnet, hartip, opcua, mms,
//     mqtt, ffhse, profinet, goose, sv, ethercat, any}
//   - a CIDR- or hostname-zone conduit naming 'profinet'/'goose'/'sv'/'ethercat' (they have no IP
//     layer and can never appear on anything but a VLAN-zone conduit), or a VLAN-zone conduit
//     naming any of the eleven TCP-only protocol names above (they have no VLAN-only wire presence
//     a VLAN-zone conduit could ever match) -- 'any' is accepted on any kind, scoped to whichever
//     protocols that zone kind can actually match
//   - a conduit whose 'type' isn't 'idmz' (the only recognized value so far), or an 'idmz'-typed
//     conduit whose 'protocols' resolves to 'any' while 'functions' is empty/omitted -- an "any
//     protocol, no functions restriction" conduit at a declared IT-OT/iDMZ boundary is rejected,
//     forcing the policy author to be explicit about exactly what may cross it
//   - a VLAN-zone conduit's 'from' and 'to' naming a different set of zones -- see policy.hpp's
//     Conduit::from_zones/to_zones comment for why a VLAN-zone conduit models "permitted on this
//     zone," not a directional flow between two zones
//   - a VLAN-zone conduit giving 'ports', 'bidirectional: true', or 'functions'/'function' at all
//     -- none of them has a meaning for a protocol with no TCP/UDP layer (ports, functions) or no
//     client/server session (bidirectional); see policy.hpp's Conduit comment
//   - a CIDR- or hostname-zone conduit giving 'from_macs'/'from_mac' at all -- source-MAC
//     restriction only has a meaning on a VLAN-zone conduit (Phase 5, see policy.hpp's
//     Conduit::from_macs comment); a CIDR-/hostname-zone conduit already has a client/server IP
//     pair to restrict by instead
//   - a conduit's 'from_macs'/'from_mac' entry that isn't a valid MAC address (exactly six
//     colon-separated hex octets, e.g. '00:0c:29:11:22:33'; hex digits case-insensitive on input,
//     canonicalized to lowercase in Conduit::from_macs)
//   - a conduit's port outside [1, 65535]
//   - a conduit's 'bidirectional' value that isn't a recognizable boolean
//   - a conduit's 'functions'/'function' given while 'protocols'/'protocol' resolves to anything
//     other than exactly one concrete protocol (i.e. it's 'any', or a list of more than one) --
//     the function/service name tables the entries are validated against are entirely separate per
//     protocol (see modbus_known_function_names/dnp3_known_function_names/
//     s7comm_known_function_names/iec104_known_asdu_short_names/enip_known_cip_service_names), so
//     there would be no single table to validate/match against otherwise
//   - a conduit's 'functions'/'function' given for one of the six protocols widened into
//     'protocols' most recently (bacnet/hartip/opcua/mms/mqtt/ffhse) -- none of them has a known-
//     function/service-name table yet (see known_function_names_for in policy.cpp), so there is
//     nothing to validate a 'functions' entry against; write the conduit without 'functions' for
//     now (see ROADMAP)
//   - a conduit's 'functions'/'function' entry that isn't one of its protocol's own known function/
//     service names (case-insensitively) -- the error names the closest known name ("did you mean
//     '...'?") when one is a plausible typo, and omits the suggestion when nothing is close enough
//     (the reserved 'read'/'write' group keywords, see Conduit::functions's own comment, are
//     checked before this lookup and never reach it; a near-miss like "reads" is NOT a keyword and
//     falls straight through to this same unknown-name/suggestion handling)
//   - a conduit's 'read'/'write' functions-group keyword that expands to an empty set for its
//     protocol -- unreachable today (all five function-table protocols have a non-empty Read and
//     Write set), but rejected rather than silently leaving the conduit fully unrestricted, since
//     an empty Conduit::functions list means "no restriction" everywhere else in the engine
Policy parse_policy_text(const std::string& text, const std::string& source_name);

// Reads `path` and calls parse_policy_text with its contents. Throws
// PolicyError (not a filesystem exception) if the file can't be opened,
// applying the same validation as parse_policy_text otherwise.
Policy parse_policy_file(const std::string& path);

}  // namespace conduitscope
