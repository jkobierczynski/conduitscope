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

**3. Baseline process behavior, not just ports -- partially stale.** The
"Modbus + S7 only" framing describes an earlier state of the baseline
engine, not the current one: `docs/design/baseline-engine.md`'s own
status line shows Phase 2 already extended `baseline learn`/`baseline
check` to EtherNet/IP, DNP3, BACnet, OPC UA, MELSEC, and FINS, each with
its own operation-level tracking (CIP service/class/instance/attribute,
DNP3 function+group/variation, etc.) and a `--policy`-aware
`new-conduit-known-zone` rollup. Two of Grok's five bullet points --
DNP3 function+group/variation+point index, and EtherNet/IP
service+class/instance/attribute -- are already implemented. IEC 104
type/COT/IOA-range tracking, OPC UA service+NodeId (today it's
service-name only, no NodeId), and treating S7 block-download/
program-change as its own high-severity class are the genuinely
remaining pieces. This is Jurgen's own item 3, after item 2.

**4. Detection that OT IR teams recognize -- mostly a real gap.**
`attack_detect.hpp`/`ipv6_attack_detect.hpp` cover flood/scan-shaped
findings (SYN/ACK/UDP/ICMP floods, rogue DHCPv6 servers, and similar),
with exactly one incidental MITRE ATT&CK technique-ID citation found in
the whole codebase (T1557.003, in a comment, not a structured field on
the finding itself) -- there is no systematic ATT&CK-for-ICS or
Dragos-style activity-group mapping across findings. Engineering-station
behavioral detection (TIA Portal/Studio 5000/Unity fingerprinting),
firmware/logic-download and cold-restart flagging as their own category,
and "new remote-access channel into L2" as a named finding (as opposed
to the existing generic "IT protocols an OT auditor flags" tiers, which
already flag RDP/VNC/SSH/etc. reaching a zone but don't yet distinguish
"new" from "previously baselined") are all genuinely not built yet. Fair
point, not yet scheduled in Jurgen's own ordering.

**5. Continuous, safe sensor mode -- confirmed as not built, and worth
flagging as a bigger scope question.** `live_capture.hpp`/`cli_main.cpp`
support `--duration`/`--max-packets`-bounded live capture against one
interface at a time; there is no capture-rotation-to-disk, no
multiple-simultaneous-tap-point stitching into one site-wide matrix, and
no documented handling of the "zero-traffic interface" poll-loop
limitation Grok names specifically. This is real, but it's also the item
most likely to pull conduitscope toward being a always-on sensor product
rather than an assessment/audit CLI -- worth a deliberate scope
conversation with Jurgen before committing to it, not a default "yes."

**6. Decode depth where the process lives -- mixed; the IPv6 framing is
stale as of item 1's own Phase 1/2 work, the rest holds.** `decode`
itself already recognizes IPv6 on the wire (has for a while -- see
DEVELOPMENT.md's IPv6 attack-detection work), and `policy validate` as of
this document's own item-1 work now at least distinguishes an IPv6
endpoint with an honest reason string instead of a generic "no declared
zone" miss, rather than the flat "no IPv6 anywhere" gap Grok describes --
though full IPv6 zoning (CIDR-equivalent v6 zones) is still not built.
The specific protocol-depth items (OPC UA Variant/DataValue, EtherCAT
CoE SDO mailbox, BACnet ReadPropertyMultiple/segmentation, S7 symbolic
addressing on real TIA traffic, MMS/GOOSE dataset members tied to IED
names, and encrypted-session metadata for OPC UA/BACnet-SC/MQTTS) were
not individually re-verified against each decoder for this pass -- they
read as plausible remaining gaps given this project's own documented
"first pass" scoping language in files like `bacnet.hpp` and `opcua.hpp`,
but each deserves its own direct check before being scheduled, not a
blanket "confirmed."

**7. Evidence pack for 62443/NIS2/NERC CIP/NIST 800-82 -- confirmed as
not built.** `policy validate`'s report has a zone/conduit violation
list and (as of this document) Purdue-level/iDMZ annotations, but no
mapping of a finding to a specific 62443 FR/SL target or NIS2-style
citation, no CIP-007/CIP-015 "monitoring was in place" framing, and no
signed/reproducible report bundling tool version + policy hash + capture
hash + decoder-confidence notes into one artifact (the JSON report has
none of those fields today). Real gap, not yet scheduled.

**8. Integrate instead of replacing the stack -- mixed.** The JSON
report schema is genuinely append-only and documented (`docs/USER_GUIDE.md`'s
own schema sections, and this project's own strict "appended last"
convention enforced in code review across every recent feature), which
is most of what "stable and versioned" is really asking for, though there
is no explicit `schema_version` field on the policy/inventory JSON output
itself (baseline's own store file does have one, `store.schema_version`,
so the precedent exists) -- a cheap, worthwhile addition. No Zeek/Malcolm
exporter, no CEF/LEEF/syslog one-liner output, and no
"generate-firewall-rules-from-policy" feature exist. The "read the same
taps dumpcap/tshark write" half is already true (pcap/pcapng input,
described in USER_GUIDE.md's own "pcap vs pcapng" section).

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
