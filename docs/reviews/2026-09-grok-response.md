# Response to Grok's ten improvement areas, September 2026

The unedited source this responds to is
[2026-09-grok-ics-ot-improvement-areas.md](2026-09-grok-ics-ot-improvement-areas.md).
Jurgen asked to work through its ten points in his own priority order,
starting with items 1, 2, and 3, one at a time. This is a fact-check of
all ten against the actual repository as of this writing (not the
README, and not recollection -- each claim below was checked with a grep
or a direct read of the relevant header/source file), so the priority
order is chosen with an accurate picture of what already exists versus
what's a genuine gap. See
[DEVELOPMENT.md](../DEVELOPMENT.md)'s "External review: Grok's ten
improvement areas" section for how this maps onto the roadmap, and
[docs/design/policy-engine-zoning.md](../design/policy-engine-zoning.md)
for item 1's design document and current implementation status.

## Overall take

Grok's framing -- "good audit CLI" versus "something a plant can run
next to Claroty/Dragos/Nozomi/Malcolm" -- is fair and is the right lens.
The ten items are real gaps relative to a commercial ICS/OT platform, not
padding. But several of them are less urgent than presented because the
underlying capability partially exists already (decode-side IPv6, most of
the six talker protocols in inventory, CI-wired sanitizers and fuzzing,
signed release archives with bundled docs), and a couple describe an
even larger scope than conduitscope's own stated non-goals (continuous
SPAN/TAP sensor mode, becoming a SIEM-adjacent detection product) would
comfortably take on without changing what this tool is for. Item 1 is
correctly identified as "the product" -- the zone/conduit model is this
tool's actual differentiator, and it was the most IPv4/TCP-shaped part of
the codebase by a wide margin, so starting there was the right call.

## Item by item

**1. Make the policy engine match how plants are zoned -- confirmed, and
now underway.** This was accurate without qualification: `policy
validate` only ever evaluated TCP flows and IPv4 CIDR zones, every
UDP/non-IP OT protocol (BACnet/IP, CIP I/O, GOOSE, SV, PROFINET RT,
EtherCAT) fell into `skipped_non_tcp` unconditionally, there was no VLAN
or hostname zone concept, no Purdue-level labeling, no iDMZ conduit type,
and no read/write operation-level direction. See the design document for
the phased plan and current status (as of this document, the zone-kind
model, IPv6-flow reason-string honesty, Purdue-level labels, and
hostname zones are implemented and shipped; UDP/BACnet/CIP-I/O flow
evaluation, operation-level read/write classification, VLAN-conduit
MAC-source restriction, and multi-homed-asset/jump-host modeling are
planned but not yet built).

**2. Turn inventory into a real OT asset record -- confirmed as a real
gap, with one claim now stale.** `InventoryEdge` (`asset_inventory.hpp`)
genuinely has no vendor/product/firmware/serial/rack-slot fields, no
role classification (PLC/RTU/IED/HMI/historian/engineering-station), no
per-tag/point/DB touch tracking, and no STIX/TAXII or firewall-ACL
export -- all real, checked directly against the header. The "grow
beyond the current five talker protocols" claim is stale, though:
`AssetInventoryEngine::observe` already recognizes MMS, OPC UA, MQTT, and
BACnet/IP (`src/asset_inventory.cpp` dispatches all four alongside
Modbus/DNP3/S7comm/EtherNet-IP) as of this repository -- S7comm-Plus is
the one protocol from Grok's own example list still genuinely absent
from `inventory`. This is Jurgen's own item 2, next after item 1.

**3. Baseline process behavior, not just ports -- now fully done (this
paragraph originally read "partially stale" at review time; updated
after the remaining pieces shipped).** The "Modbus + S7 only" framing
describes an early state of the baseline engine, not the current one:
`docs/design/baseline-engine.md`'s own status line shows Phase 2 already
extended `baseline learn`/`baseline check` to EtherNet/IP, DNP3, BACnet,
OPC UA, MELSEC, and FINS, each with its own operation-level tracking
(CIP service/class/instance/attribute, DNP3 function+group/variation,
etc.) and a `--policy`-aware `new-conduit-known-zone` rollup. All five of
Grok's bullet points are now implemented: DNP3 function+group/variation
+point index and EtherNet/IP service+class/instance/attribute were
already done by review time; IEC 104 type/COT/IOA-range tracking, OPC UA
service+NodeId (structured `NodeId`, not just the service name), and S7
PLC Control/PLC Stop (block-download/program-change/cold-restart) as an
always-flag control-plane class shipped as three v0.2.8 follow-ups --
see the design doc's own "Follow-up (v0.2.8, ...)" sections. Grok review
item 3 is now fully closed.

**4. Detection that OT IR teams recognize -- now fully done (this
paragraph originally read "mostly a real gap" at review time; updated
after the feature shipped).** Every genuine gap this bullet originally
named has been closed. A new `detect` subcommand
(`include/conduitscope/detect_engine.hpp`/`src/detect_engine.cpp`, full
design record at `docs/design/detection-engine.md`) now produces a
unified report of engineering-station mode changes, firmware/logic
downloads and device restarts, protocol misuse, and new remote-access
channels, each finding citing exactly one of ten independently-verified
MITRE ATT&CK for ICS techniques (`include/conduitscope/
mitre_attack_ics.hpp`) -- no Dragos-style activity-group attribution,
per Jurgen's own scoping decision (proprietary threat intel this project
has no legitimate data to correlate against). "New remote-access channel
into L2" is now a named, distinguished finding: a Tier-1 remote-access
protocol (RDP/VNC/TeamViewer/AnyDesk/Zoom) reaching a conduit is flagged
only when it's genuinely new -- confirmed absent from an optional
`--baseline-file` (Medium confidence) or first-occurrence-within-this-
capture when none is given (Low confidence, honestly labeled as weaker
evidence) -- exactly the "new" vs. "previously baselined" distinction
this paragraph originally said was missing. Engineering-station
behavioral detection now goes beyond fingerprinting existing protocols'
control-plane traffic (S7 PLC Control/Stop, CIP Forward_Open) to include
a genuine new decoder for Schneider Electric's UMAS protocol (Unity
Pro/Control Expert's own engineering-station protocol, riding Modbus/TCP
function code 0x5A) -- which has no official public specification at
all, reverse-engineered from Kaspersky ICS-CERT's published research and
an open-source Wireshark dissector, both cited by URL. Firmware/
logic-download and restart/mode-change flagging is now its own labeled
category (`FirmwareLogicChange`/`EngineeringStationActivity`), always
High confidence, sourced from S7comm block download, DNP3 Cold/Warm
Restart, IEC 104 Reset Process, BACnet ReinitializeDevice, and UMAS
START_PLC/STOP_PLC/INITIALIZE_DOWNLOAD-DOWNLOAD_BLOCK-
END_STRATEGY_DOWNLOAD. Confidence labeling ("keep the honesty") is a
real structured field (`DetectionConfidence`) on every new finding, not
prose-level hedging -- deliberately scoped to this feature's own new
findings only, not retrofitted onto the pre-existing flood/scan
detectors or `baseline check`'s own findings (a separate, larger effort,
noted as a reasonable future follow-up in the design doc). Grok review
item 4 is now fully closed.

**5. Continuous, safe sensor mode -- now fully done, after a deliberate
scope conversation with Jurgen first.** This paragraph originally flagged
the item as the one most likely to pull conduitscope toward being an
always-on sensor product rather than an assessment/audit CLI, and
recommended a scope conversation before committing to it rather than a
default "yes." That conversation happened (two `AskUserQuestion` rounds,
both answered with the recommended option), and it kept the scope
narrow and consistent with an audit CLI rather than a sensor product: a
**capture-only rotator** -- a new `RotatingPcapWriter` and `capture`
subcommand that rotate live `-i` capture output by size and/or elapsed
packet time and enforce a total-bytes or file-count retention cap, with
no decode/analysis engine running inside the capture process itself
(analysis stays a separate, later, offline pass over the rotated files,
exactly as today) -- and **independent per-tap processes plus a merge
subcommand**, not a multi-tap process: each tap point still runs its own
ordinary single-interface `conduitscope` process, and a new `merge
inventory` subcommand unions N tap points' own inventory reports (by IP,
summing overlapping edges' packet counts, re-deriving zones/conduits
fresh) into one site-wide asset matrix, with no new concurrency anywhere.
Direct source reading before writing any code found that the "zero-traffic
interface" poll-loop limitation this paragraph named specifically was
already solved by the existing `LiveCapture` poll loop, and that a
non-rotating `PcapWriter` already existed as a reusable building block --
so the actual new work was the rotation/retention layer, the `capture`
subcommand, and the merge subcommand, not a rewrite of live capture
itself. `capture` is verified, by grepping for every packet-injection
call across the codebase, to never transmit toward the process network.
Validated on loopback traffic only, not yet against a real mirrored OT
switch, an outstanding caveat carried forward honestly in
`docs/design/sensor-mode.md` and `docs/USER_GUIDE.md` rather than
implied as covered. Grok review item 5 is now fully closed.

**6. Decode depth where the process lives -- mixed; the IPv6 framing is
stale as of item 1's own Phase 1/2 work, and two of the six named
protocol-depth items are now closed.** `decode` itself already recognizes
IPv6 on the wire (has for a while -- see DEVELOPMENT.md's IPv6
attack-detection work), and `policy validate` as of this document's own
item-1 work now at least distinguishes an IPv6 endpoint with an honest
reason string instead of a generic "no declared zone" miss, rather than
the flat "no IPv6 anywhere" gap Grok describes -- though full IPv6 zoning
(CIDR-equivalent v6 zones) is still not built. Of the six specific
protocol-depth items Grok named, each was individually re-verified against
its own decoder rather than taken on faith: OPC UA Variant/DataValue,
EtherCAT CoE SDO mailbox, and MMS/GOOSE dataset members tied to IED names
were confirmed already done (stale claims, not real gaps, by the time this
follow-up check happened); S7 symbolic addressing on real TIA traffic
remains genuinely blocked, not on effort but on access to a real TIA
Portal capture to validate field offsets against (no synthetic fixture can
substitute for that without risking a silently-wrong decode). The
remaining two -- **BACnet ReadPropertyMultiple/segmentation** and
**encrypted-session metadata for MQTTS** -- are now implemented. BACnet
Confirmed-Request/Complex-ACK APDUs whose SEG bit is set are reassembled
across separate UDP datagrams (strict in-order, resource-capped, mirroring
DNP3's own cross-packet reassembly) and re-decoded with the same
value-decoder a non-segmented message gets, including Device-object
identity correlation surviving a segmented ACK; see `bacnet.hpp`'s
"Cross-packet segment reassembly" section and
docs/PROTOCOL_COVERAGE.md's BACnet/IP Segmentation paragraph for the full
design, verified against `bacnet-stack`'s (github.com/stargieg/bacnet-stack)
`apdu_handler()` for the per-segment service-choice-byte wire shape. MQTTS
(port 8883) is now detected the same way this codebase's other
TLS-wrapped OT protocols are (HTTPS/LDAPS/FOXS): a TLS ClientHello on
that port is recognized and its SNI, when present, extracted as session
metadata -- see `mqtt.hpp`'s new "PORT 8883 / MQTTS" section. Encrypted-
session metadata for OPC UA and BACnet/SC remain unimplemented (BACnet/SC
in particular is an entirely different WebSocket-based transport, not a
TLS-ClientHello-on-a-known-port case like MQTTS/HTTPS/LDAPS/FOXS, and
would need its own scoping pass).

**7. Evidence pack for 62443/NIS2/NERC CIP/NIST 800-82 -- confirmed as
not built.** `policy validate`'s report has a zone/conduit violation
list and (as of this document) Purdue-level/iDMZ annotations, but no
mapping of a finding to a specific 62443 FR/SL target or NIS2-style
citation, no CIP-007/CIP-015 "monitoring was in place" framing, and no
signed/reproducible report bundling tool version + policy hash + capture
hash + decoder-confidence notes into one artifact (the JSON report has
none of those fields today). Real gap, not yet scheduled.

**8. Integrate instead of replacing the stack -- mixed, and narrowing.**
The JSON report schema is genuinely append-only and documented
(`docs/USER_GUIDE.md`'s own schema sections, and this project's own strict
"appended last" convention enforced in code review across every recent
feature), which is most of what "stable and versioned" is really asking
for, though there is still no explicit `schema_version` field on the
policy/inventory JSON output itself (baseline's own store file does have
one, `store.schema_version`, so the precedent exists) -- a cheap,
worthwhile addition, not yet done. "Generate firewall rules from this
policy + inventory" turns out to already be a stale claim rather than a
real gap: `inventory --acl-export` already drafts Cisco/Fortinet/Palo Alto
ACL rules from a capture's own inferred conduits (Grok gap #2's own Phase
10, confirmed by direct source read of `write_inventory_acl_cisco`/
`_fortinet`/`_paloalto` in `src/cli_main.cpp`). A Zeek/Malcolm exporter is
now the first of this bullet's remaining two items to ship: `decode -T
zeek` writes a real Zeek `conn.log` (Zeek's own actual field schema and
TSV envelope, not an invented approximation), scoped -- via an
`AskUserQuestion` decision with Jurgen -- to a conn.log-foundation-first
phase rather than the fuller per-protocol ICSNPP-compatible logs a later
phase may add; see `output.hpp`'s `ZeekWriter` class comment and
`docs/USER_GUIDE.md`'s own "Zeek conn.log export" section for the exact
field-by-field scope. CEF/LEEF/syslog one-liner output for existing SOC
pipelines has now shipped too, closing out this bullet's last remaining
item: `policy validate`/`baseline check`/`detect` each accept three more
`-T` values (`cef`/`leef`/`syslog`), rendering their own already-curated
findings (policy violations, baseline anomalies, detect's MITRE-mapped
findings -- never a raw per-packet export) as one line per finding, ready
to feed a SIEM. CEF verified against microfocus.com's own implementation
guide, LEEF against IBM's own LEEF Version 2 guide, and the syslog
transport against RFC 5424 directly -- see `security_event_format.hpp`
and `docs/USER_GUIDE.md`'s own "SECURITY EVENT EXPORT (CEF/LEEF/syslog)"
section for the exact field-by-field scope, including why
`Unclassified` policy flows are deliberately excluded and why the syslog
transport's own TIMESTAMP/HOSTNAME/PROCID stay at RFC 5424's `-` NILVALUE
rather than guess at values this tool has no honest way to report. The
"read the same taps dumpcap/tshark write" half is already true (pcap/pcapng
input, described in USER_GUIDE.md's own "pcap vs pcapng" section). Only
the JSON `schema_version` field noted above remains open on this item.

**9. Trustworthiness of the parser -- mostly already done; the review is
behind the current state.** This is the clearest case of Grok working
from a stale or incomplete picture. `.github/workflows/ci.yml` already
runs an ASan/UBSan-instrumented build with the full CTest suite plus
every fuzz harness's own bounded corpus-regression check on every
push/PR, and a separate `scheduled-fuzz` job runs materially longer
per-harness campaigns nightly (confirmed by reading the workflow file
directly, not assumed) -- this session's own verification runs
independently reproduced 2081/2081 passing under that exact
configuration, including all 76 fuzz-corpus regression tests. Signed
release binaries and a formal SBOM are the one part of this item that's
still missing (the release job produces Linux+Windows archives with
docs/README/LICENSE/man page bundled, but nothing is code-signed and no
SBOM is generated) -- worth doing, but "keep ASan/UBSan in CI" and
"libFuzzer on the high-value parsers" are already standing practice, not
open items.

**10. Product shape, not just features -- partially stale.** One signed
Linux+Windows binary with the man page and docs bundled is *almost*
already true: the release job does build and publish both platforms'
archives with docs/README/LICENSE/man page included, it's just unsigned.
Sample policies for a specific vertical (water plant/discrete
cell/substation) as opposed to the existing generic example policies,
and a guided "pcap -> inventory YAML -> policy validate -> PDF/JSON
pack" tutorial aimed at assessors specifically, are not built. The
"language plant engineers can read" point is already a stated design
value in this codebase (Purdue-level labels and the iDMZ conduit type,
both from item 1's own work, are explicit steps in that direction), and
explicit non-goals (no cloud requirement, no PLC agents, passive-only,
no active probing) are already true of this tool's architecture even
though they aren't written down anywhere as a formal "non-goals"
statement -- that's a cheap documentation fix, not new engineering.
