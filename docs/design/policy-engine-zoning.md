# Policy engine: match how plants are zoned -- design document

Status: **Prerequisite (`Zone`/`Conduit` kind-enum refactor), Phase 1 (IPv6-flow reason-string
fix, Purdue-level zone labels, `type: idmz` conduits), Phase 2 (hostname zones), and Phase 3
(BACnet/IP + CIP I/O UDP flow evaluation) implemented and shipped.** Phases 4-6
(operation-level read/write direction, MAC-source restriction on VLAN conduits, multi-homed
assets/jump hosts) are approved and scoped below but not yet started. Written in response to
[Grok's ten-point ICS/OT improvement review](../reviews/2026-09-grok-ics-ot-improvement-areas.md)
(item 1) -- see [docs/reviews/2026-09-grok-response.md](../reviews/2026-09-grok-response.md) for
the fact-check of that review against the repository, and `docs/DEVELOPMENT.md`'s ROADMAP items
70-71 for the changelog-style writeup of what shipped and its exact verification numbers.

## Context

Jurgen had an external AI reviewer ("Grok") assess conduitscope and asked to tackle its ten
suggested improvement areas in order, starting with #1 verbatim: *"Make the policy engine match
how plants are zoned"* -- bringing UDP/raw-Ethernet/non-IP conduits into pass/fail evaluation
instead of `skipped_non_tcp`, VLAN/QinQ/MAC/hostname/Purdue-level zones instead of only IPv4 CIDR,
operation-level read/write direction, multi-homed assets and jump hosts as first-class objects, and
iDMZ/IT-OT-crossing as a stricter-by-default conduit type. Items #2 (asset inventory enrichment)
and #3 (baseline behavior extension) are next in Jurgen's own ordering but explicitly out of scope
here.

Research (Explore + Plan subagents, plus direct reads of `policy.hpp`, `policy_engine.hpp/.cpp`,
`resolver.hpp`) found a working precedent to build on: `Zone`/`Conduit` already supported a second,
structurally different addressing scheme (VLAN, added after the original IPv4-CIDR-only design) via
an explicit `is_vlan_zone` discriminator, with `PolicyEngine` caching `has_vlan_zone()` at
construction so a policy with no VLAN zone stays byte-for-byte behaviorally identical to before VLAN
zones existed. Every new mechanism below follows that same "fully inert unless a policy actually
declares it" rule. Research also found: a live bug where a TCP-over-IPv6 flow silently became
`Unclassified` instead of being flagged as an unsupported address family (`parse_ipv4_string` fails
silently on IPv6 strings); that BACnet/IP and CIP I/O were structurally dead code for `policy
validate` (UDP, and `PolicyEngine::observe` returned before `!dp.has_tcp` traffic could ever be
classified); and -- critically -- that `resolver.hpp`'s existing `--hosts FILE` mechanism (file-only,
**never** live DNS, already wired into `policy validate` for report annotation) is exactly the
reproducible, pinned-snapshot hostname source hostname-zone matching needs, so no new CLI flag or
file format was required for that feature.

Jurgen's decisions on the open design questions raised during planning:

- **UDP/non-IP conduit evaluation** is opt-in per conduit (a conduit must itself name `bacnet` or
  UDP-eligible `enip`, or use `any`, before that traffic is evaluated at all) -- so an existing
  policy's compliant/non-compliant result cannot flip on a rebuild alone.
- **Read/write function classification** ships for all five function-table protocols (modbus,
  dnp3, s7comm, iec104, enip), not just Grok's two named examples.
- **Hostname zones AND multi-homed-asset/jump-host modeling are IN scope** for this deliverable
  (Jurgen chose "include both now" over deferring either).
- **GOOSE/SV/PROFINET-RT/EtherCAT publisher restriction** is modeled as a source-MAC allow-list on
  a VLAN conduit (`from_macs:`), not a publisher/subscriber pairing -- matching how multicast L2
  traffic actually behaves on the wire.

Explicitly still deferred (unchanged from the original research): **QinQ** support requires a
decoder-layer double-tag unwrap that doesn't exist yet (`parse_ethernet` only ever strips one
802.1Q tag; `ETHERTYPE_8021AD` is display-only) -- already tracked separately as the continuation of
ROADMAP item 15; building policy-layer QinQ zones on top of an unimplemented decoder feature would
be speculative, so it is not part of this plan.

## Prerequisite: `Zone`/`Conduit` kind refactor (bool -> enum) -- IMPLEMENTED

`Zone::is_vlan_zone` was a bool, sufficient for exactly two kinds. This plan adds a third
(hostname), so the first change was mechanical: `Zone::is_vlan_zone` (bool) became `Zone::kind`
(`enum class ZoneKind { Cidr, Vlan, Hostname }`), and `Conduit::is_vlan_conduit` similarly became
`Conduit::kind` (same enum, since a conduit's kind is still fully determined by its zones' shared
kind -- `parse_policy_text` still rejects mixed-kind conduits, now a 3-way check instead of 2-way).
Every existing call site that branched on the old bool (`policy.cpp`'s zone-kind-consistency check
and VLAN `from==to` enforcement, `policy_engine.cpp`'s `any_vlan_zone_` gate and `observe()`'s VLAN
carve-out) was mechanically updated to compare against `ZoneKind::Vlan` instead of `true`. Verified
zero behavioral change by running the full pre-existing CTest suite before and after the refactor
(1990/1990 both times).

## Phase 1 -- cheap, independent wins -- IMPLEMENTED

- **IPv6 flow misclassification fix**: in `PolicyEngine::finish()`, when
  `parse_ipv4_string(fs.client_ip)`/`(fs.server_ip)` fails, checks for a `:` (an IPv6-formatted
  address, per `format_ipv6`) and sets a distinct `reason` string ("...is an IPv6 address; policy
  zoning does not support IPv6 yet") instead of the generic "no declared zone contains" text.
  `FlowVerdict::Unclassified` itself stays unchanged (a new enum value would ripple into
  `verdict_name()`, every `PolicyReport::*_count()`, and both renderers for little added clarity) --
  this is a reason-string clarification, not a new outcome.
- **Purdue-level zone labels**: `Zone::purdue_level` (`std::string`, optional `purdue_level:` key,
  purely informational, never read by matching logic). Rendered as
  `client_zone_purdue_level`/`server_zone_purdue_level` on each flow entry (JSON: omitted when
  empty, appended after the then-current last field, `notable_protocols`, per this codebase's
  append-only schema convention) and inline on zone names in the text report.
- **iDMZ / IT-OT crossing conduit type**: `Conduit::conduit_type` (small closed value, unset or
  `"idmz"`, from an optional `type:` key). Since the existing deny-by-default behavior (an unlisted
  zone pair is already a `Violation`) means "stricter" has to be a validation tightening rather than
  a runtime default change: rejects `protocols: [any]` combined with an empty `functions` list on an
  `idmz`-tagged conduit, forcing an explicit protocol list at an IT/OT boundary. A distinct "IT-OT
  CROSSING CONDUITS" section was added to both text and JSON reports listing every `idmz`-tagged
  conduit's exercised/unexercised status. Fully inert for any policy that never sets `type: idmz`.

## Phase 2 -- Hostname zones -- IMPLEMENTED

- `Zone::kind` gained `ZoneKind::Hostname`; `Zone::hostnames` (`std::vector<std::string>`) parsed
  from an optional `hostnames:` key, mutually exclusive with `networks:`/`vlans:` (the parser
  rejects any policy zone declaring more than one of the three). `Policy::zone_for_hostname
  (const std::string&)` mirrors `zone_for_vlan`; `Policy::has_hostname_zone()` mirrors
  `has_vlan_zone()`. Validation mirrors the existing "each address belongs to at most one zone"
  rule: rejects two hostname zones sharing a hostname.
- **Behaves like a CIDR zone, not a VLAN zone** -- a hostname is just an alternate way to name an IP
  endpoint, so hostname-zone conduits keep `ports`/`bidirectional`/`functions` fully meaningful
  (unlike VLAN conduits) and are matched through the *same* TCP/UDP `FlowReport` path, never the
  Ethernet path.
- **Matching**: `PolicyEngine::finish()` gained a resolver-aware zone lookup: try `zone_for(ip)`
  (CIDR) first; only if that misses AND `policy_.has_hostname_zone()`, try
  `zone_for_hostname(resolver.hostname(ip))`. This required threading a `const Resolver&` into
  `PolicyEngine::finish()` (previously the resolver was only ever handed to the report writers, at
  render time, well after verdicts were computed) -- a small, additive signature change, not a
  redesign.
- **Reproducibility, not a new mechanism**: `Resolver::hostname()` already returns a value only
  when the flag combination `--resolve --hosts FILE` was given, is file-only, and **never** performs
  live DNS (`resolver.hpp`'s own header comment is explicit that this is a "considered decision, not
  open for reconsideration"). No new CLI flag was needed. `run_policy_validate` gained one load-time
  check: if `policy.has_hostname_zone()` and `--resolve`/`--hosts` were not both given, it fails
  fast with a clear fatal error rather than silently matching nothing.

**Verification bar met for the Prerequisite + Phase 1 + Phase 2 increment**: 2005/2005 (default GCC
build), 1993/1993 (`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`, 12 fewer live-capture-only tests
correctly absent), 2081/2081 (ASan/UBSan build, including all 76 `fuzz_*_corpus_regression` cases),
zero-warning rebuilds across default/no-live-capture/ASan-UBSan/MinGW-w64-cross-compile
configurations, plus an independent clean-room extract-and-rebuild reproducing 2005/2005.
`docs/USER_GUIDE.md`, `docs/DEVELOPMENT.md` (ROADMAP item 70), and `man/conduitscope.1` all updated
in the same increment.

## Phase 3 -- BACnet/IP + CIP I/O UDP flow evaluation -- IMPLEMENTED

- New `UdpFlowState`/`UdpFlowReport` pair (mirrors `FlowState`/`FlowReport`), keyed by (client IP,
  server IP, protocol, server port), matched against the *existing* CIDR/hostname-zone conduits --
  no new zone kind needed, since BACnet and CIP I/O are ordinary IP protocols; the only real gap is
  transport reach and session aggregation, not addressing.
- Direction per protocol (no TCP handshake exists to lean on): BACnet reuses the same APDU
  request/response-type logic `asset_inventory.cpp` already has (Confirmed-/Unconfirmed-Request =>
  source is client; ACK/Error/Reject/Abort => destination is client), falling back to a
  UDP-service-port heuristic when no APDU is present; CIP I/O (cyclic producer/consumer, no
  request/response concept) is port-heuristic only. Both carry the same honestly-low-confidence
  caveat `AssetInventoryEngine` already documents for BACnet.
- **Gating (per Jurgen's decision)**: `Policy::has_udp_eligible_conduit()` -- true only when at
  least one CIDR- or hostname-zone conduit names `bacnet`/`enip`/`any` in its `protocols:` -- cached
  at `PolicyEngine` construction, analogous to `any_vlan_zone_`. `observe()` gets a new branch,
  checked *before* the `!dp.has_ip || !dp.has_tcp` early return, that folds an eligible UDP packet
  into `udp_flows_` only when this cache is true; otherwise it still counts into `skipped_non_tcp`
  exactly as today. A policy that never names these protocols is byte-for-byte unaffected.
- New `PolicyReport::udp_flows` vector, its own "UDP FLOWS EVALUATED" text section (with
  violations/unclassified/allowed subgroups and `--summarize-unclassified` support, mirroring the
  Ethernet-flow section) and JSON array (appended as the new true-last field, after
  `idmz_conduits`). `skipped_non_tcp`'s doc comment updated to describe the new carve-out precisely.
  `unexercised_conduits`, `*_count()`, and `compliant()` all fold in `udp_flows` the same way they
  already fold in `ethernet_flows`.
- **Known limitation, documented rather than silently accepted**: a conduit naming `enip` with a
  `functions:` restriction validates against CIP explicit-messaging service names (TCP); CIP I/O has
  no per-message operation concept at all, so such a conduit's functions restriction cannot
  meaningfully apply to CIP I/O traffic matched by the same conduit -- CIP I/O flows simply have an
  empty `observed_functions` list and are Allowed/Violation purely on protocol+port+zone. This is
  called out explicitly in code comments and the user guide rather than left as a silent surprise,
  and pinned by its own regression fixture (`tests/policies/udp_cip_io_functions_quirk.yaml`) so it
  can't silently regress into something else (e.g. an accidental outright rejection) later.

**Verification bar met for Phase 3**: 2012/2012 (default GCC build), 2000/2000
(`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF`), 2088/2088 (ASan/UBSan build, including all 76
`fuzz_*_corpus_regression` cases), zero-warning rebuilds across default/no-live-capture/ASan-UBSan/
MinGW-w64-cross-compile configurations. `docs/USER_GUIDE.md`, `docs/DEVELOPMENT.md` (ROADMAP item
71), `docs/PROTOCOL_COVERAGE.md`, and `man/conduitscope.1` all updated in the same increment,
including correcting every stale "`policy validate` does not yet evaluate any UDP traffic" claim
left over from before this phase.

## Phase 4 -- Operation-level read/write direction -- IMPLEMENTED

- Added a per-protocol function-access classification (`{Modbus,Dnp3,S7Comm,Iec104,Enip}FunctionAccess`
  -- `Read`/`Write`/`Other`) alongside each protocol's own known-function table (modbus.cpp,
  dnp3.cpp, s7comm.cpp, iec104.cpp, enip.cpp -- Modbus/DNP3 refactored from a plain `switch` to a
  table to carry it, S7comm/IEC104's existing tables extended in place with an `access` field,
  ENIP given a separate name-keyed table since its service names are context-dependent, not
  code-keyed). Each protocol gained `*_read_function_names()`/`*_write_function_names()` (ENIP:
  `enip_read_cip_service_names()`/`enip_write_cip_service_names()`; IEC104:
  `iec104_read_asdu_short_names()`/`iec104_write_asdu_short_names()`), dispatched by
  `policy.cpp`'s new `read_function_names_for()`/`write_function_names_for()`.
- Extended `Conduit::functions` parsing (`parse_policy_text`'s functions-parsing loop) to accept
  two new reserved, case-insensitive group keywords, `read`/`write`, checked *before* the existing
  literal-name lookup so the keyword always wins any naming collision, combinable with literal
  function names in the same list (e.g. `functions: [read, "Diagnostics"]`), expanded at parse time
  into that protocol's full matching function set. A new `add_function_once` dedup guard ensures a
  literal already covered by the expanded group is never stored twice. `write` intentionally does
  NOT implicitly include `Other`-classified functions -- those still need to be named explicitly,
  since silently overlooking an ambiguous function on a "flag writes" policy would be a real,
  security-relevant surprise, not a formatting nicety. A defensive fail-loudly check rejects a
  keyword that would expand to an empty set (unreachable today -- all five protocols have non-empty
  Read and Write sets -- but guards against an empty `functions` silently meaning "unrestricted").
- **DNP3's own literal function names collide with the keywords** (its function codes 0x01/0x02 are
  themselves literally named "Read"/"Write"): resolved by keyword-always-wins semantics, confirmed
  safe against every pre-existing fixture (none relied on selecting DNP3's bare literal
  Read/Write in isolation). Separately, real bidirectional DNP3 exchanges always carry a
  "Response"/"Confirm" on the reply side (Other-classified, since a Response frame's payload can't
  say whether it answered a read or a write) -- documented explicitly, with
  `tests/policies/functions_group_write_dnp3.yaml` pinning the bare-keyword caveat and
  `functions_group_write_dnp3_with_response.yaml` pinning the combined-usage fix
  (`functions: [write, "Response"]`).
- **The classification table itself was the sensitive part** -- a wrong Read/Write/Other call is a
  compliance-correctness bug, not a style choice. Drafted from each protocol's own spec/RFC (this
  project's standard sourcing method), with three borderline calls put in front of Jurgen for a
  sanity check before implementation began: DNP3 Select -> Other (no effect without a following
  Operate); IEC104 read-trigger commands (C_IC_NA_1/C_CI_NA_1/C_RD_NA_1) -> Read despite their `C_`
  prefix; EtherNet/IP connection-management services (Forward_Open/Forward_Close/
  Large_Forward_Open/Unconnected_Send) -> Other. All three confirmed as proposed.

**Verification bar met for Phase 4**: 2023/2023 (default GCC build, 11 new tests, zero regression
against the prior 2012), covering all five protocols' `read`/`write` group keywords, the
combined-literal + dedup parse-level JSON shape, and the near-miss-keyword-falls-through bad path.
`docs/USER_GUIDE.md` (new "Reserved group keywords" subsection under "Function-level restrictions",
full per-protocol classification tables, two new validation-error entries), `docs/DEVELOPMENT.md`
(ROADMAP item 72), and `include/conduitscope/policy.hpp` (`Conduit::functions` and
`parse_policy_text` doc comments) all updated in the same increment.

## Phase 5 -- MAC-source restriction on VLAN conduits (GOOSE/SV/etc.) -- IMPLEMENTED

- Added optional `from_macs:` (singular alias `from_mac:`, parsed by the same `as_scalar_list`
  helper every other scalar-or-list conduit field already uses) to `Conduit`, valid ONLY on a
  VLAN-zone conduit (`parse_policy_text` rejects it outright on a CIDR-/hostname-zone conduit,
  which already has a client/server IP pair to restrict by instead). Empty/omitted (the default):
  unrestricted, identical to before this field existed. Each entry is validated by a new
  `parse_mac_address` helper (policy.cpp, alongside `parse_cidr`) -- exactly six colon-separated
  hex octets, hex digits case-insensitive on input, canonicalized to lowercase on output (the same
  form `format_mac()` emits for `DecodedPacket::src_mac`) -- and deduplicated the same
  `add_function_once`-style guard `functions` already established.
- `EthernetFlowState`/`EthernetFlowReport` gained `src_mac` (the actual transmitting MAC, fixed at
  first-insert from the first packet that creates the flow's aggregated state, never re-derived per
  packet -- these are one-directional cyclic publish streams, so "the" source is stable and
  unambiguous for the whole flow, unlike a bidirectional TCP session) alongside the existing
  canonicalized, order-independent `mac_a`/`mac_b` pair -- purely additive, doesn't change what
  `mac_a`/`mac_b` already mean.
- `finish()`'s Ethernet-flow matching: once a conduit matches on protocol/VLAN-zone (the
  pre-existing logic, unchanged), a non-empty `from_macs` is now a further check -- mirroring the
  exact "matched, then a further allow-list check can still turn it into a Violation" shape the
  TCP-flow `functions` restriction already uses -- requiring `src_mac` to be in that list, else
  `Violation` naming the observed source and the conduit's permitted list (`"source MAC '...'
  observed; conduit '...' permits only: ..."`). This is the mechanism that actually matches
  multicast GOOSE/SV/PROFINET-RT/EtherCAT traffic ("only these sources may publish"), not a
  publisher/subscriber pairing (there is no real subscriber address to restrict against on a
  multicast destination).
- **Reporting**: `src_mac` (and, under `--mac-vendor`, `src_mac_vendor`) appended as the new
  true-last field on `EthernetFlowReport`'s JSON shape, and rendered as a new `source: <mac>` line
  in the text report's per-flow entry (`write_ethernet_flow_group_text`), both alongside the
  existing `mac_a`/`mac_b` fields rather than replacing them. `from_macs` appended as the new
  true-last field on each conduit's own JSON summary object (empty array, not null, when
  unrestricted -- the same convention `functions` already established there).

**Verification bar met for Phase 5**: 2028/2028 (default GCC build, 5 new tests, zero regression
against the prior 2023), covering the compliant case (restricted to the actual observed source),
the violation case (restricted to a MAC that never publishes), the singular-alias/case-insensitive/
dedup parse-level JSON shape, and both new validation-error paths (`from_macs` on a non-VLAN
conduit; a malformed MAC string). `docs/USER_GUIDE.md` (new "`from_macs`: restricting WHO may
publish on a VLAN-zone conduit" subsection, two new "Validation errors" entries, JSON report schema
entries for `from_macs`/`src_mac`/`src_mac_vendor`) and `docs/DEVELOPMENT.md` (ROADMAP item 73)
updated in the same increment.

## Phase 6 -- Multi-homed assets and jump hosts as first-class objects -- IMPLEMENTED

- New, fully optional top-level policy section, `assets:` -- a list of named entries (`Asset`,
  policy.hpp, declared right before `Policy` since `Policy::assets` is a `std::vector<Asset>`
  member), each with `ips:` (2+ IPv4 addresses/CIDRs, parsed by the same `parse_cidr` `networks:`
  uses -- what makes it "multi-homed" in the first place; `parse_policy_text` rejects fewer than
  two, an invalid entry, or a duplicate IP/CIDR within the same asset), an optional `role:`
  (free-form informational string, e.g. `"jump_host"`, `"hmi"`, stored verbatim -- never lowercased,
  unlike `Conduit::conduit_type`'s small closed value space, since this is free text -- same posture
  as `purdue_level` otherwise), and an optional `description:` (mirrors `Zone`/`Conduit`'s own field,
  never read by any logic). Missing/duplicate `name` and missing `ips` are rejected the same way a
  conduit's own `name` is. Omitted entirely: zero effect -- no `Asset` exists, both new report
  sections below stay empty, same "inert unless declared" posture as everything else in this plan.
- **Validation-time cross-reference** (the actual payoff, and the concrete thing OWASP OT Top 10's
  "broken zones from dual-homed HMIs and forgotten remote access" warning is about): computed in
  `PolicyEngine::finish()` purely from `policy_` itself (assets/zones/conduits) -- independent of
  the capture, so it's identical whether or not a single relevant packet was ever observed. For
  each declared asset, every IP's zone is looked up via `Policy::zone_for(block.network)` -- the
  exact same lookup an ordinary flow's `client_ip`/`server_ip` already goes through. If those IPs
  resolve to two or more *different* zones (an IP matching no declared zone resolves to
  `"unclassified"`, same as anywhere else -- and an unclassified/real-zone pair can never be
  "covered", since no conduit ever names the reserved zone `unclassified`, so any asset with one
  unclassified IP among 2+ distinct zones is flagged too), every such zone pair is checked: a pair
  is "covered" when some conduit's `from_zones`/`to_zones` names one zone on one side and the other
  on the other side, in *either* order (`bidirectional` is deliberately ignored here -- the question
  is only "is a relationship between these two zones declared at all", not simulating actual traffic
  direction the way flow-matching does). An asset with any uncovered pair is `flagged`. This
  populates a new "MULTI-HOMED ASSETS" report section (text + JSON,
  `PolicyReport::multi_homed_assets`, a `std::vector<MultiHomedAssetFinding>`) listing every
  declared asset, its IPs, each IP's resolved zone, every distinct zone pair it touches (always
  populated, even when not flagged, so the report shows the asset's full zone footprint) and
  whether each pair is covered. An asset whose IPs all fall in one zone, or whose cross-zone pairs
  are all covered, is still listed, just with `flagged: false` -- this section is never gated on
  the policy declaring any assets in a way that hides "the good ones."
- **`role: "jump_host"` gets extra scrutiny**: a post-pass in `finish()`, run *after*
  `report.flows`/`report.udp_flows` are fully populated, scans both for any flow where `client_ip`
  or `server_ip` falls within a `role: "jump_host"`-tagged asset's declared IPs (via
  `cidr_contains`, checked case-insensitively against `role` via the existing `equal_ci` helper).
  Every match becomes a self-contained `JumpHostFlowFinding` (mirroring `NotableProtocolFinding`'s
  own "duplicate summary data, don't index into `flows`/`udp_flows`" convention) in the new
  `PolicyReport::jump_host_flows` vector, called out in its own "JUMP HOST FLOWS" report section
  (text + JSON) **regardless of that flow's own Allowed/Violation/Unclassified verdict** --
  "remote access via a jump host" is the pattern being watched for, independent of whether the
  individual flow happens to be policy-compliant. Raw-Ethernet L2 flows have no IP addressing at
  all, so they're never in scope for this check.
- This is intentionally an *advisory, cross-referencing* feature layered on top of existing
  zone/flow data, not a new matching primitive -- neither new section ever writes to a
  `FlowReport`/`UdpFlowReport`'s own `verdict`, and `PolicyReport::allowed_count()`/
  `violation_count()`/`unclassified_count()`/`compliant()` all still span only `flows`/
  `ethernet_flows`/`udp_flows`, completely untouched by `multi_homed_assets`/`jump_host_flows` --
  so this feature cannot turn an existing COMPLIANT capture NON-COMPLIANT on its own; it earns its
  keep purely through visibility. (This deliberately does not attempt to model the richer,
  protocol/vendor/firmware-aware asset record that's the actual subject of Grok's item #2, which
  Jurgen has ordered as separate future work -- `assets:` here is policy-file-declared ground truth,
  not something `AssetInventoryEngine` derives from traffic.)
- **Reporting**: `multi_homed_assets`/`jump_host_flows` appended as the new true-last top-level JSON
  fields (`udp_flows` was the prior true-last field, since Phase 3 -- see "JSON report schema" in
  docs/USER_GUIDE.md), and rendered as new "MULTI-HOMED ASSETS"/"JUMP HOST FLOWS" text sections
  (`write_multi_homed_assets_text`/`write_jump_host_flows_text`, policy_engine.cpp), both printing
  nothing at all (not even a header) when the policy declares no `assets:`/no `role: "jump_host"`
  asset that any flow touched -- the same "byte-for-byte unaffected when unused" convention every
  earlier addition to this schema followed (`write_idmz_conduits_text`'s own comment states this
  precedent explicitly).

**Verification bar met for Phase 6**: 2039/2039 (default GCC build, 11 new tests, zero regression
against the prior 2028 -- one pre-existing fixture, `policy_udp_bacnet_cip_io_compliant_json`, had
its `PASS_REGULAR_EXPRESSION` updated to account for the two new trailing JSON fields, the same
"a pre-existing regex anchored on the old true-last field needs to change" maintenance every earlier
phase's own JSON append also required), covering: a multi-homed asset whose cross-zone IPs are
already covered by a declared conduit (not flagged); the same shape with no covering conduit
(flagged, still COMPLIANT overall); a `role: "jump_host"` asset called out on an Allowed flow; the
same asset called out on a Violation flow (proving the report section is independent of verdict);
JSON shape coverage for both the covered-asset and jump-host cases; and five new validation-error
paths (missing asset name, duplicate asset name, fewer than two `ips`, an invalid IP/CIDR, a
duplicate IP/CIDR within one asset). `docs/USER_GUIDE.md` (new "Multi-homed assets and jump hosts"
subsection, schema block addition, two new "Validation errors" entries, new "Multi-homed assets and
jump hosts (JSON)" subsection) and `docs/DEVELOPMENT.md` (ROADMAP item 74) updated in the same
increment. This is the sixth and final phase of this plan -- see this file's own "Context" section
above.

## Testing & fixtures

New `tests/policies/*.yaml` good/bad pairs per new validation rule, following the existing naming
convention. New sample pcaps via `tools/make_sample_pcap.py` as each phase needs them (a BACnet/IP
UDP exchange with both a Confirmed-Request/ACK pair and an APDU-less BVLC-only packet; a CIP I/O
UDP/2222 exchange; a GOOSE capture with a second, disallowed source MAC for Phase 5; a capture where
the same IP appears as both a declared multi-homed jump-host asset and a normal flow endpoint for
Phase 6). `tests/hosts_sample.txt` and `tests/sample_ipv6.pcap` (both pre-existing) were reused for
Phase 1/2's fixtures rather than inventing new ones. New `add_test(NAME policy_...)` entries in the
root `CMakeLists.txt`, `--format text` and `--format json` coverage for each new behavior, plus an
explicit before/after diff proving the Zone-kind-enum refactor and every later phase leave every
*pre-existing* policy fixture's output byte-for-byte unchanged. Full CTest in the default GCC build
after every phase, full verification bar (see below) before each phase is considered done.

## Docs (same phase as the code, per this project's convention)

- `docs/USER_GUIDE.md`: POLICY FILE FORMAT section grows `purdue_level:`, `type: idmz`,
  `hostnames:` (all shipped), then `assets:`, `from_macs:`, and the `read`/`write` function-group
  keywords as Phases 4-6 ship; JSON report schema section gets every new/appended field; LIMITATIONS
  updated to drop BACnet/CIP-IO from "can never be exercised" once Phase 3 ships, and to record the
  QinQ deferral.
- `docs/DEVELOPMENT.md`: a roadmap entry per shipped increment (item 70 covers the Prerequisite +
  Phase 1 + Phase 2 increment), cross-referencing the still-deferred QinQ work under its existing
  item 15 continuation.
- `man/conduitscope.1`: updated for Phase 1/2 (three zone kinds, `purdue_level`/`type: idmz`
  mentioned, hostname-zone gating); update again only if a later phase needs new CLI surface beyond
  the policy-file schema itself.

## Verification bar (every phase, before it's considered done)

Default GCC build + full CTest with the before/after fixture diffs above; ASan/UBSan Clang build
(new aggregation state in Phases 3/5/6 is exactly the kind of code that benefits most from this);
`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` build; MinGW-w64 cross-compile; final clean-room zip
rebuild + full `ctest` pass before delivery via SendUserFile, matching this project's standing
convention.

## Critical files

- `include/conduitscope/policy.hpp` / `src/policy.cpp` -- Zone/Conduit kind enum, hostname zones,
  `purdue_level`, `type: idmz` (all shipped), `from_macs:`, `assets:`, `read`/`write` function
  groups, and their validation rules (Phases 4-6).
- `include/conduitscope/policy_engine.hpp` / `src/policy_engine.cpp` -- `observe()`'s UDP/BACnet/
  CIP-IO carve-out (Phase 3, in progress), `finish()`'s hostname-zone lookup (resolver-aware,
  shipped), MAC-source matching (Phase 5), multi-homed-asset cross-referencing (Phase 6), all new
  report sections in both text/JSON writers.
- `include/conduitscope/resolver.hpp` -- read-only reference; reused as-is for hostname-zone
  matching, no changes needed to this file itself.
- `include/conduitscope/modbus.hpp`, `dnp3.hpp`, `s7comm.hpp`, `iec104.hpp`, `enip.hpp` -- each
  gains its protocol's read/write classification table alongside its existing known-function table
  (Phase 4).
- `src/cli_main.cpp`'s `run_policy_validate` -- threads the `Resolver` into `PolicyEngine::finish()`
  (shipped), adds the hostname-zone-without-`--hosts` fail-fast check (shipped).
- `tools/make_sample_pcap.py`, `CMakeLists.txt`, `tests/policies/*.yaml` -- fixtures and tests per
  phase.
- `docs/USER_GUIDE.md`, `docs/DEVELOPMENT.md`, `man/conduitscope.1`.
