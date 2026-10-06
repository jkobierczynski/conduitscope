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
// A zone is built from ONE of four addressing schemes, mutually exclusive
// per zone (ROADMAP item 15, extended by the "match how plants are zoned"
// work and by ROADMAP item 144's DNP3 link-address zones -- see
// docs/DEVELOPMENT.md):
//   - CIDR blocks (`networks:` for IPv4, `ipv6_networks:` for IPv6 -- ROADMAP
//     item 143 added the latter; the two are NOT mutually exclusive with each
//     other, only with `vlans:`/`hostnames:` below, so a single zone may
//     declare either or both, for a dual-stack zone whose conduits need no
//     duplicating per address family) -- the original, TCP-flow-oriented
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
//     reproducible run-to-run, which a live DNS lookup could never be. Unlike
//     a CIDR zone (both address families now, as of item 143), this fallback
//     stays IPv4-only -- the Resolver's own `--hosts` file parsing is IPv4-
//     dotted-quad-only (a pre-existing, separate limitation, resolver.hpp),
//     so a hostname zone never matches an IPv6 flow today.
//   - DNP3 data-link addresses (`dnp3_link_addresses:`, singular alias
//     `dnp3_link_address:` -- ROADMAP item 144) -- closes the gap ROADMAP
//     item 13 deliberately deferred: "the single most consequential
//     addressing gap in this codebase," since a serial-to-IP DNP3 gateway
//     routinely multiplexes several physically distinct outstations behind
//     ONE IP (and typically one TCP session), which a CIDR zone can never
//     tell apart. A DNP3-link zone's members are plain numeric DNP3
//     data-link addresses (0-65519; 65520-65535/0xFFF0-0xFFFF is reserved by
//     the standard for broadcast variants and the self-address feature, see
//     kMinDnp3LinkAddress/kMaxDnp3LinkAddress below), matched not against a
//     flow's IP but against the DNP3 data-link source/destination address
//     each individual frame already carries (Dnp3Result::source_address/
//     destination_address, dnp3.hpp -- decoded since ROADMAP item 13,
//     unchanged by this item). Unlike a VLAN zone, a DNP3-link-zone conduit
//     IS directional (`from_zones` names the master station zone(s),
//     `to_zones` the outstation zone(s) -- every DNP3 frame unambiguously
//     carries both a source and a destination address, so there's no VLAN-
//     style "no separate source/destination" problem here) and `ports`/
//     `bidirectional`/`functions` all stay fully meaningful (the wire
//     traffic is still ordinary bidirectional TCP, just classified by a
//     different address) -- see Conduit's own comment below. This produces
//     an ADDITIONAL, finer-grained report entry (PolicyEngine's
//     Dnp3LinkFlowReport) layered on top of, never instead of, the ordinary
//     IP-based FlowReport for the same TCP session: a policy declaring zero
//     DNP3-link zones is completely unaffected (see Policy::
//     has_dnp3_link_zone), exactly the backward-compatibility bar every
//     earlier zone-kind addition met.
//
// `Zone::kind`/`Conduit::kind` (see below) is the explicit discriminator for
// which of the four a given zone/conduit is -- never inferred from which
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

#include "conduitscope/ipv6.hpp"  // Ipv6Address -- Ipv6CidrBlock's own network field, below

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
// or an IPv6 address -- this one function is IPv4-only, matching ipv4.hpp;
// see Ipv6CidrBlock/parse_cidr_ipv6 below for a zone's IPv6 side (ROADMAP item
// 143, docs/DEVELOPMENT.md -- a zone's addressing is no longer IPv4-only
// overall, even though this particular parser still only ever produces an
// IPv4 CidrBlock).
std::optional<CidrBlock> parse_cidr(const std::string& text);

// Ipv6CidrBlock's own sibling to CidrBlock above, for a zone's `ipv6_networks:` list (ROADMAP item
// 143) -- same shape and same "network already masked down to prefix_len bits" contract, just over
// a 128-bit Ipv6Address (ipv6.hpp) instead of a host-order uint32_t, since there's no native
// 128-bit integer type to mirror CidrBlock::network's own convenience with (see Ipv6Address's own
// comment, ipv6.hpp, for why it's a plain 16-byte array instead).
struct Ipv6CidrBlock {
    Ipv6Address network{};
    uint8_t prefix_len = 128;
    std::string text;
};

// True if `ip` falls inside `block` -- Ipv6CidrBlock's sibling to cidr_contains above, masking
// byte-by-byte (and, for the one byte straddling a non-multiple-of-8 prefix_len, bit-by-bit within
// that byte) since there's no single native integer wide enough to mask in one shift the way
// cidr_contains does for a uint32_t.
bool cidr_contains_ipv6(const Ipv6CidrBlock& block, const Ipv6Address& ip);

// Ipv6CidrBlock's sibling to cidr_overlaps above -- same "do these two blocks describe any address
// in common" contract, used by the same same-kind-pair overlap check parse_policy_text already
// runs for IPv4 zones (see policy.cpp).
bool cidr_overlaps_ipv6(const Ipv6CidrBlock& a, const Ipv6CidrBlock& b);

// Ipv6CidrBlock's sibling to parse_cidr above: parses "<ipv6>" or "<ipv6>/N" (N in [0,128]) via
// parse_ipv6_string (ipv6.hpp) for the address part. A bare address with no "/" is accepted and
// treated as /128, mirroring parse_cidr's own /32 default for a bare IPv4 address.
std::optional<Ipv6CidrBlock> parse_cidr_ipv6(const std::string& text);

// The 802.1Q-usable VLAN ID range a declared zone's `vlans:` entries are validated against. VID 0
// is reserved by the standard for priority-tagged, non-VLAN-member frames (a frame with a "VLAN
// tag" whose 12-bit VID happens to be 0 carries no real VLAN membership at all) and VID 4095 is
// reserved outright -- neither can ever meaningfully be "the VLAN this zone's traffic lives on",
// so neither is accepted here, the same "reject what can't be a real value" posture parse_cidr
// takes toward an out-of-range prefix length.
constexpr int kMinVlanId = 1;
constexpr int kMaxVlanId = 4094;

// The DNP3/IEEE 1815 data-link address range a declared zone's `dnp3_link_addresses:` entries are
// validated against (ROADMAP item 144). Addresses 65520-65535 (0xFFF0-0xFFFF) are reserved by the
// standard: 65535 (0xFFFF) is the universal broadcast address; 65534/65533 (0xFFFE/0xFFFD) are
// reserved broadcast variants; 65532 (0xFFFC) is the "self-address" feature's own reserved value
// (meaningful only when that feature is enabled on a device); the remainder of that same top-16-
// address block (65520-65531, 0xFFF0-0xFFFB) is reserved outright for future allocation. None of
// these can ever be ONE individually-addressable master or outstation a zone could meaningfully
// classify a single frame's sender/receiver by, so the whole block is rejected wholesale -- the
// same conservative "reject a reserved block outright, don't carve out exceptions for the specific
// values some profiles happen to use" posture kMinVlanId/kMaxVlanId already take toward VID 4095.
constexpr int kMinDnp3LinkAddress = 0;
constexpr int kMaxDnp3LinkAddress = 65519;  // 0xFFEF

// Which of the four mutually-exclusive addressing schemes a Zone/Conduit uses -- see this file's
// own header comment for what each means. A bool sufficed while there were only two (Cidr/Vlan);
// this became a proper enum once Hostname was added, so every 2-way branch on the old
// `is_vlan_zone`/`is_vlan_conduit` bool became a 3-way branch on `kind` instead (mechanical,
// zero-behavior-change refactor -- see docs/DEVELOPMENT.md); ROADMAP item 144 added a fourth value,
// Dnp3Link, the same mechanical way.
enum class ZoneKind { Cidr, Vlan, Hostname, Dnp3Link };

struct Zone {
    std::string name;
    std::string description;  // optional; empty if not given
    // Exactly one of (`networks` and/or `ipv6_networks`)/`vlans`/`hostnames`/`dnp3_link_addresses`
    // is ever non-empty for a given zone -- parse_policy_text rejects a zone declaring more than
    // one of the four or none. `kind` is the explicit discriminator (rather than callers inferring
    // it from which vector is non-empty) so every place that needs to branch on zone kind (Conduit
    // validation, PolicyEngine's dispatch) says so plainly. See this file's own header comment for
    // why a zone is exactly one of the four. `networks`/`ipv6_networks` are NOT mutually exclusive
    // with each other (ROADMAP item 143, docs/DEVELOPMENT.md) -- a single ZoneKind::Cidr zone may
    // declare either, or both, for a true dual-stack zone whose IPv4 and IPv6 ranges are matched by
    // the same conduits with no duplication; see Policy::zone_for/zone_for_ipv6 and PolicyEngine::
    // finish for how a flow's endpoint is checked against whichever of the two actually apply.
    ZoneKind kind = ZoneKind::Cidr;
    std::vector<CidrBlock> networks;
    std::vector<Ipv6CidrBlock> ipv6_networks;  // ZoneKind::Cidr only -- see the comment above
    std::vector<uint16_t> vlans;
    std::vector<std::string> hostnames;  // ZoneKind::Hostname only -- lowercase not enforced (matched
                                          // case-sensitively against the Resolver's hosts-file entries,
                                          // which themselves preserve the file's own casing)
    // ZoneKind::Dnp3Link only (ROADMAP item 144) -- a list of plain numeric DNP3 data-link
    // addresses (see kMinDnp3LinkAddress/kMaxDnp3LinkAddress above for the validated range), used
    // for BOTH a master station zone and an outstation zone -- the zone itself doesn't know or care
    // which role it plays; that's purely a function of which side of a Dnp3Link conduit's
    // from_zones/to_zones it's checked against (see PolicyEngine::finish).
    std::vector<uint16_t> dnp3_link_addresses;
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
// "sv", "ethercat", "powerlink", "twincat", "ge-srtp", "fox", "foxs",
// "s7comm-plus", "melsec", "fins", "codesys", "bsap", "cclink-ie", "udp",
// "any"} (parse_policy_text rejects anything else) -- a `Dnp3Link`-kind
// conduit (ROADMAP item 144) further restricts this to `{"dnp3", "any"}`
// only, since there's nothing else a DNP3-link address could ever classify
// (parse_policy_text rejects any other name there, but a CIDR/hostname-zone
// conduit's own `protocols` is completely unaffected by this -- "dnp3"
// remains valid there exactly as before). "any" matches every
// protocol reachable through this conduit's own zone kind (see below), not
// literally every protocol conduitscope recognizes. "bacnet" names BACnet/IP,
// which this decoder only ever recognizes over UDP (see decoder.cpp), so a
// conduit naming "bacnet" only ever matches once UDP flow evaluation is
// opted into (see Policy::has_udp_eligible_conduit); see docs/USER_GUIDE.md's
// POLICY FILE FORMAT "Addressing scope" section. "udp" (ROADMAP item 103) is
// a generic pseudo-protocol name, not a real decoded protocol: it matches
// UDP traffic this tool's own decoders never assign a specific protocol name
// to at all (DecodedPacket::protocol == "udp", the decoder's own "recognized
// transport, no app-layer match" fallback) -- combine it with `ports` to
// write a firewall-style "this UDP port between these zones is permitted,
// whatever's actually on it" rule for a UDP OT protocol this tool doesn't
// decode by name. `profinet`/`goose`/`sv`/`ethercat`/`powerlink` (ROADMAP
// items 15 and 103) are a DIFFERENT kind of protocol entirely: they ride raw
// Ethernet with no IP layer at all, so they can only ever appear in a
// conduit whose `from_zones`/`to_zones` are ALL VLAN zones (Zone::kind ==
// ZoneKind::Vlan), never mixed with a CIDR or hostname zone, and never
// alongside any of the IP-riding protocol names above (parse_policy_text
// rejects both combinations) -- see policy.hpp's own header comment and
// Zone's comment for the full VLAN-zone model. `ports` is the set of
// TCP/UDP ports this conduit covers on the RESPONDING (server) side of the
// connection; empty means "any port" (parse_policy_text allows omitting the
// field entirely for that) -- meaningless for a VLAN-zone conduit (there is
// no TCP/UDP layer to have a port at all), so parse_policy_text rejects
// `ports` there outright rather than silently ignoring it.
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
// two zones (which no capture could ever exercise for these protocols
// -- see policy.hpp's own header comment). A VLAN-zone conduit can further
// restrict who/what it permits via `from_macs`/`to_macs` (source/destination
// MAC allow-lists) and `ethertypes` (raw EtherType allow-list, ROADMAP item
// 103) -- see each field's own comment on Conduit below for the full design.
//
// A `Dnp3Link`-kind conduit (ROADMAP item 144) is the opposite case: it IS
// directional, exactly like a CIDR-zone conduit (`from_zones` names the
// master station zone(s), `to_zones` the outstation zone(s) -- a DNP3 frame
// unambiguously carries both a source and a destination data-link address,
// unlike a single Ethernet frame's one VLAN tag), and `ports`/
// `bidirectional`/`functions` ALL stay fully meaningful and are matched
// exactly the way a CIDR-zone conduit already matches them (the underlying
// traffic is still ordinary bidirectional TCP, just classified by DNP3
// data-link address instead of IP -- see PolicyEngine::finish's own
// Dnp3Link-conduit matching loop). `from_macs`/`to_macs`/`ethertypes` stay
// rejected on a Dnp3Link conduit, the same as on a CIDR/hostname-zone one --
// those three are VLAN-zone-only.
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

    // Sibling to from_macs above (ROADMAP item 103): an optional allow-list of DESTINATION MAC
    // addresses this VLAN-zone conduit permits -- from an optional `to_macs:` key (singular alias
    // `to_mac:`). Same parsing/canonicalization/VLAN-only restriction as from_macs, same "empty
    // means unrestricted" default. Where from_macs restricts WHO may publish, to_macs restricts
    // WHERE it may go -- e.g. "GOOSE on this VLAN must target multicast group 01:0c:cd:01:00:01,"
    // catching a stray unicast publish or a publish to the wrong multicast group. See
    // `EthernetFlowReport::dst_mac` (policy_engine.hpp) for how the observed destination is
    // determined (fixed from the flow's first packet, same as src_mac), and `PolicyEngine::finish`
    // for exactly how it's checked against this list.
    std::vector<std::string> to_macs;

    // Optional allow-list of raw EtherType values this VLAN-zone conduit permits -- from an
    // optional `ethertypes:` key (singular alias `ethertype:`), ROADMAP item 103. Each entry is a
    // "0x" + 1-4 hex digits string (e.g. "0x88f7"), parsed by parse_ethertype (policy.cpp) and
    // validated to the real EtherType range [0x0600, 0xFFFF] (below 0x0600 is an 802.3 length
    // field, never a real EtherType). Empty (the default) means unrestricted by EtherType --
    // exactly the behavior before this field existed.
    //
    // Unlike `protocols`, this is NOT how a VLAN-zone conduit becomes eligible to match traffic in
    // the first place -- it's a FURTHER restriction on top of an already-protocol-matched conduit,
    // the same relationship from_macs/to_macs already have to protocols. What makes ethertypes
    // actually useful is that `protocols: [any]` already matches ANY traffic PolicyEngine tracks as
    // an Ethernet flow at all -- including a frame whose EtherType this tool's own decoders don't
    // recognize by name (`DecodedPacket::protocol == "non-ip"`, tracked as an Ethernet flow only
    // once some conduit in the policy declares a non-empty `ethertypes` -- see
    // Policy::has_ethertype_eligible_conduit and PolicyEngine::observe's own comment). So
    // `protocols: [any]` + `ethertypes: [0x88f7]` is how a policy governs a vendor-proprietary or
    // otherwise-undecoded L2 protocol this tool has no dedicated decoder for at all: without
    // `ethertypes` narrowing it, `protocols: [any]` on its own would indiscriminately allow every
    // undecoded EtherType on the VLAN zone, which defeats the point. A named-protocol conduit (e.g.
    // `protocols: [goose]`) can also declare `ethertypes` redundantly (GOOSE's own EtherType is
    // already fixed at 0x88b8) -- harmless, just an explicit self-documenting restriction. See
    // `EthernetFlowReport::ethertype` (policy_engine.hpp) for how the observed value is determined
    // (fixed from the flow's first packet), and `PolicyEngine::finish` for exactly how it's checked
    // against this list.
    std::vector<uint16_t> ethertypes;

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

    // Ipv6CidrBlock's sibling to zone_for above (ROADMAP item 143, docs/DEVELOPMENT.md) -- returns
    // the zone whose `ipv6_networks` list contains `ip`, or nullptr if no declared zone does.
    // Deliberately uncached/ungated, unlike has_vlan_zone/has_hostname_zone below: a policy that
    // declares no `ipv6_networks` zone at all simply never matches here (every call returns
    // nullptr), which is exactly the same Unclassified outcome an IPv6 flow already got before this
    // function existed -- there is no previously-nonexistent behavior class to gate against the
    // way VLAN/hostname zones' own caches guard (see PolicyEngine::finish, policy_engine.cpp, for
    // where this is called). Same "parse_policy_text already rejects an overlap, so at most one
    // zone ever matches" guarantee as zone_for -- see the IPv6 sibling of cidr_overlaps' own
    // same-kind-pair check.
    const Zone* zone_for_ipv6(const Ipv6Address& ip) const;

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

    // Dnp3Link sibling to zone_for_vlan above (ROADMAP item 144): returns the zone whose
    // `dnp3_link_addresses` list contains `link_address`, or nullptr if no declared Dnp3Link zone
    // does. Used for BOTH the master-station side and the outstation side of an observed DNP3
    // frame -- which role a given call means is purely a function of which side of a Dnp3Link
    // conduit's `from_zones`/`to_zones` the result is checked against (see PolicyEngine::finish),
    // never baked into the zone itself: the same zone could in principle be referenced as either a
    // `from_zones` or `to_zones` member by different conduits. parse_policy_text rejects any policy
    // where two Dnp3Link zones share an address, so at most one zone can ever match here too.
    const Zone* zone_for_dnp3_link(uint16_t link_address) const;

    // True if at least one declared zone is a Dnp3Link zone -- mirrors has_vlan_zone's own
    // backward-compatibility purpose exactly: PolicyEngine::observe only ever builds its per-
    // outstation (master link address, outstation link address) aggregation map when this is true
    // (see PolicyEngine's own any_dnp3_link_zone_ comment, policy_engine.hpp), so a policy declaring
    // zero Dnp3Link zones is byte-for-byte unaffected by this feature's existence -- DNP3 traffic
    // keeps being classified purely by the ordinary CIDR/hostname zone its IP falls into, exactly as
    // before ROADMAP item 144.
    bool has_dnp3_link_zone() const;

    // True if at least one CIDR- or hostname-zone conduit (never a VLAN-zone conduit -- see below)
    // names "bacnet", "enip", "hartip", "ffhse", "melsec", "fins", "codesys", "bsap", "cclink-ie",
    // "udp", or "any" in its `protocols:` -- the opt-in gate for evaluating UDP traffic (all
    // IP-addressed) against a conduit at all, instead of leaving them in
    // PolicyReport::skipped_non_tcp exactly as before this feature existed (see
    // PolicyEngine::observe's own comment, and docs/design/policy-engine-zoning.md's Phase 3;
    // HART-IP and FF-HSE were added afterward, widening the same opt-in gate rather than
    // introducing a separate one, since both already ride UDP too and this gate's whole point is
    // "does the policy care about any UDP-based IP-addressed OT protocol at all"; ROADMAP item 103
    // widened it again for MELSEC/FINS/CODESYS's own UDP forms, BSAP, CC-Link IE Field Network
    // Basic, and the generic "udp" pseudo-protocol name -- see Conduit's own header comment for
    // what "udp" means). This mirrors has_vlan_zone/has_hostname_zone's own "cached once, at
    // PolicyEngine construction" backward-compatibility posture: a policy that never names these
    // protocols on a CIDR/hostname conduit is byte-for-byte unaffected by this feature's existence.
    // A VLAN-zone conduit naming one of these (or "any") doesn't count here -- it can only ever mean
    // PROFINET RT/GOOSE/SV/EtherCAT/POWERLINK (see parse_policy_text's own protocol-vs-zone-kind
    // validation), never a UDP-based IP protocol, which could never reach a VLAN-zone conduit's
    // matching logic.
    bool has_udp_eligible_conduit() const;

    // True if at least one VLAN-zone conduit declares a non-empty `ethertypes:` (ROADMAP item 103)
    // -- the opt-in gate for tracking an Ethernet flow whose EtherType this tool's own decoders
    // don't recognize by name (DecodedPacket::protocol == "non-ip") as an Ethernet flow at all,
    // instead of leaving it in PolicyReport::skipped_non_tcp. Mirrors has_udp_eligible_conduit's
    // own backward-compatibility posture: a policy that never declares `ethertypes:` is byte-for-
    // byte unaffected by this feature's existence -- every already-named VLAN-eligible protocol
    // (PROFINET RT/GOOSE/SV/EtherCAT/POWERLINK) is tracked exactly as it was before, gated only by
    // has_vlan_zone as always. See Conduit::ethertypes' own comment for the full design.
    bool has_ethertype_eligible_conduit() const;
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
//   - a zone declaring none of ('networks'/'ipv6_networks')/'vlans'/
//     'hostnames'/'dnp3_link_addresses', or more than one of those four
//     groups -- each zone is exactly one kind (see this file's own header
//     comment); 'networks' and 'ipv6_networks' together still count as only
//     ONE occurrence of the CIDR kind (ROADMAP item 143, docs/DEVELOPMENT.md)
//     -- a zone may declare either, or both, for a dual-stack zone
//   - a zone's 'networks' containing a value that isn't a valid IPv4
//     address/CIDR block, or its 'ipv6_networks' containing a value that
//     isn't a valid IPv6 address/CIDR block (ROADMAP item 143)
//   - a zone's 'vlans' containing a value that isn't an integer in
//     [kMinVlanId, kMaxVlanId] ([1, 4094] -- VID 0 and 4095 are reserved,
//     see kMinVlanId/kMaxVlanId's own comment)
//   - a zone's 'hostnames' containing an empty value
//   - a zone's 'dnp3_link_addresses'/'dnp3_link_address' containing a value
//     that isn't an integer in [kMinDnp3LinkAddress, kMaxDnp3LinkAddress]
//     ([0, 65519] -- 65520-65535/0xFFF0-0xFFFF is reserved by the DNP3/IEEE
//     1815 standard for broadcast variants and the self-address feature, see
//     kMinDnp3LinkAddress/kMaxDnp3LinkAddress's own comment -- ROADMAP item
//     144)
//   - two zones of the SAME kind overlapping/duplicating: two CIDR zones
//     whose IPv4 networks overlap (see cidr_overlaps) OR whose IPv6 networks
//     overlap (see cidr_overlaps_ipv6 -- checked independently of the IPv4
//     check; an IPv4 network can never overlap an IPv6 one, disjoint address
//     spaces), two VLAN zones sharing a VLAN ID, two hostname zones sharing a
//     hostname, or two Dnp3Link zones sharing a DNP3 link address (ROADMAP
//     item 144) -- the same "each address/VLAN/hostname/link-address belongs
//     to at most one zone" rule, checked separately per zone kind (zones of
//     different kinds can never overlap with each other, having no
//     addressing scheme in common)
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
//     mqtt, ffhse, twincat, ge-srtp, fox, foxs, s7comm-plus, melsec, fins, codesys, bsap, cclink-ie,
//     udp, profinet, goose, sv, ethercat, powerlink, any} (ROADMAP item 103 added twincat through
//     udp, and powerlink, to this list -- see Conduit's own header comment for what each means)
//   - a CIDR- or hostname-zone conduit naming 'profinet'/'goose'/'sv'/'ethercat'/'powerlink' (they
//     have no IP layer and can never appear on anything but a VLAN-zone conduit), or a VLAN-zone
//     conduit naming any of the IP-riding protocol names above (they have no VLAN-only wire
//     presence a VLAN-zone conduit could ever match) -- 'any' is accepted on any kind, scoped to
//     whichever protocols that zone kind can actually match
//   - a Dnp3Link-zone conduit naming any protocol other than 'dnp3'/'any' (ROADMAP item 144) --
//     a DNP3-link-address zone exists purely to classify DNP3 traffic by data-link address instead
//     of IP, so nothing else can ever appear on it; 'any' is accepted and, on this conduit kind,
//     matches only dnp3 (there's nothing else it could resolve to)
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
//   - a CIDR- or hostname-zone conduit giving 'to_macs'/'to_mac' at all -- ROADMAP item 103, same
//     VLAN-only restriction and same validation as 'from_macs'/'from_mac' above, just restricting
//     the destination MAC instead of the source (see policy.hpp's Conduit::to_macs comment)
//   - a conduit's 'to_macs'/'to_mac' entry that isn't a valid MAC address (same format as
//     'from_macs'/'from_mac' above)
//   - a CIDR- or hostname-zone conduit giving 'ethertypes'/'ethertype' at all -- ROADMAP item 103,
//     raw-EtherType restriction only has a meaning on a VLAN-zone conduit (see policy.hpp's
//     Conduit::ethertypes comment)
//   - a conduit's 'ethertypes'/'ethertype' entry that isn't a valid EtherType ('0x' followed by 1-4
//     hex digits, case-insensitive, in the range [0x0600, 0xffff] -- below 0x0600 is an 802.3
//     length field, never a real EtherType)
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
