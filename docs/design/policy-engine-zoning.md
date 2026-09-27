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

## Phase 4 -- Operation-level read/write direction

- Add a per-protocol function-access classification (`Read`/`Write`/`Other`) alongside each
  protocol's own known-function table (modbus.hpp, dnp3.hpp, s7comm.hpp, iec104.hpp, enip.hpp --
  same file each table already lives in), for all five function-table protocols.
- Extend `Conduit::functions` parsing to accept two new reserved, case-insensitive group keywords,
  `read`/`write`, combinable with literal function names (e.g. `functions: [read, "Diagnostics"]`),
  expanded at parse time into that protocol's full matching function set. `write` intentionally does
  NOT implicitly include `Other`-classified functions -- those still need to be named explicitly,
  since silently overlooking an ambiguous function on a "flag writes" policy would be a real,
  security-relevant surprise, not a formatting nicety.
- **The classification table itself is the sensitive part** -- a wrong Read/Write/Other call is a
  compliance-correctness bug, not a style choice. Draft it from each protocol's own spec/RFC
  (already this project's standard sourcing method) and put it in front of Jurgen for a sanity check
  before this phase ships, the same way protocol-detection collisions get a pinning test before
  being "fixed."

## Phase 5 -- MAC-source restriction on VLAN conduits (GOOSE/SV/etc.)

- Add optional `from_macs:` (single-or-list, same parsing helper every other scalar-or-list conduit
  field already uses) to a VLAN-zone conduit only. Empty/omitted (default): unrestricted, identical
  to today.
- `EthernetFlowState`/`EthernetFlowReport` gain `src_mac` (the actual transmitting MAC, first-seen
  -- these are one-directional cyclic publish streams, so "the" source is stable and unambiguous,
  unlike a bidirectional TCP session) alongside the existing canonicalized, order-independent
  `mac_a`/`mac_b` pair -- purely additive.
- `finish()`'s Ethernet-flow matching: when a matched conduit has a non-empty `from_macs`,
  additionally requires `src_mac` to be in that list, else `Violation` naming the observed vs.
  permitted source MAC(s). This is the mechanism that actually matches multicast GOOSE/SV/
  PROFINET-RT/EtherCAT traffic ("only these sources may publish"), not a publisher/subscriber
  pairing (there is no real subscriber address to restrict against on a multicast destination).

## Phase 6 -- Multi-homed assets and jump hosts as first-class objects

- New, fully optional top-level policy section, `assets:` -- a list of named entries, each `ips:`
  (2+ IPv4 addresses/CIDRs -- what makes it "multi-homed"), optional `role:` (free-form
  informational string, e.g. `"jump_host"`, `"hmi"`, same posture as `purdue_level`, never read by
  matching logic itself). Omitted entirely: zero effect, same "inert unless declared" posture as
  everything else in this plan.
- **Validation-time cross-reference** (this is the actual payoff, and the concrete thing OWASP OT
  Top 10's "broken zones from dual-homed HMIs and forgotten remote access" warning is about): for
  each declared asset, look up every declared IP's zone via the existing
  `zone_for`/`zone_for_hostname` machinery. If an asset's IPs resolve to two or more *different*
  zones with no conduit declared between those zones for any protocol, that's an undocumented
  cross-zone bridge sitting on real equipment -- flag it in a new "MULTI-HOMED ASSETS" report
  section (text + JSON) listing the asset, its IPs, each IP's resolved zone, and whether a conduit
  already covers the zone pair. An asset whose IPs all fall in one zone, or whose cross-zone pairs
  are already covered by a declared conduit, is reported informationally with no flag.
- **`role: jump_host` gets extra scrutiny**: any `FlowReport`/`UdpFlowReport` where the client or
  server IP belongs to a jump-host-tagged asset is called out in its own report subsection
  regardless of compliant/violation status -- remote-access-via-jump-host is the specific pattern
  being watched for, independent of whether the individual flow happens to be policy-compliant.
- This is intentionally an *advisory, cross-referencing* feature layered on top of existing
  zone/flow data, not a new matching primitive -- it does not change any existing `FlowVerdict`, so
  it cannot turn an existing COMPLIANT capture NON-COMPLIANT on its own; it earns its keep purely
  through visibility. (This deliberately does not attempt to model the richer, protocol/vendor/
  firmware-aware asset record that's the actual subject of Grok's item #2, which Jurgen has ordered
  as separate future work -- `assets:` here is policy-file-declared ground truth, not something
  `AssetInventoryEngine` derives from traffic.)

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
