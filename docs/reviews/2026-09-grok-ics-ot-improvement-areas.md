# External review: Grok, "In what areas should conduitscope improve to make headway into ICS / OT Security?", September 2026

This is an unedited, externally produced review (Grok, not ChatGPT -- see
the other files in this directory for those), kept here as a primary
source rather than folded into the main documentation. Jurgen supplied it
as a Word document (`conduitscope_-_areas_to_improve.docx`); the text
below is converted to Markdown from that file with no wording changes.

See [DEVELOPMENT.md](../DEVELOPMENT.md)'s "External review: Grok's ten
improvement areas" section for the response to it -- what checked out
against the actual repository, what was already stale by the time it was
written, and the priority order Jurgen chose to work through it in. Item 1
(the policy engine's zoning model) is the first one being acted on; see
[docs/design/policy-engine-zoning.md](../design/policy-engine-zoning.md)
for that design document and its implementation status.

---

**In what areas is should conduitscope improve to make headway into ICS
/ OT Security?**

ConduitScope already has a sharp niche: honest ICS protocol decode plus
an IEC 62443-style zone/conduit verdict from a pcap. To matter in real
OT security programs, it has to close the gap between "good audit CLI"
and "something a plant can run next to Claroty / Dragos / Nozomi /
Malcolm." Those platforms win on asset depth, continuous monitoring,
process-aware detection, compliance evidence, and air-gap
operations -- not on having one more Modbus parser.

Below is where improvement would actually move the needle.

**1. Make the policy engine match how plants are zoned**

This is the product. Today it is still too IPv4/TCP-shaped for real
Purdue models.

Priority upgrades:

- **UDP, raw Ethernet, and non-IP conduits** so CIP I/O, GOOSE, SV,
  PROFINET RT, EtherCAT, BACnet/IP actually get pass/fail instead of
  skipped_non_tcp.
- **VLAN / QinQ / MAC / hostname / Purdue-level zones**, not only IPv4
  CIDR.
- **Direction at the operation level**: allow Modbus reads, flag
  writes; allow IEC 104 interrogations, flag commands; allow GOOSE
  from a named IED only.
- **Multi-homed assets and jump hosts** as first-class objects (OWASP
  OT Top 10: broken zones often come from dual-homed HMIs and
  forgotten remote access).
- **iDMZ / IT-OT crossing** as a named conduit type with stricter
  default deny.

Until policy can express "this GOOSE publisher may talk to these
subscribers on VLAN 20, nothing else," the compliance story stays
incomplete.

**2. Turn inventory into a real OT asset record**

Buyers score **device discovery ~25%** of an ICS platform. An IP +
OUI + "speaks Modbus" is a start, not CIP-002 / 62443 inventory.

Needed attributes, inferred passively where the protocol allows:

- vendor, product, firmware/revision, serial, rack/slot (CIP Identity,
  S7 SZL, BACnet device object, OPC UA GetEndpoints, DNP3 device
  attributes)
- role: PLC / RTU / IED / HMI / historian / engineering station
- which tags / points / DBs were actually touched
- last-seen and "only seen as client vs server"

Then export into the formats auditors already use: CSV/CMDB,
GRASSMARLIN-style graphs (already started), **STIX/TAXII-lite**, and
firewall ACL drafts (Cisco, Fortinet, Palo Alto object groups).

inventory should also grow beyond the current five talker protocols so
the first-draft policy is not blind to MMS, OPC UA, MQTT, S7comm-Plus,
etc.

**3. Baseline process behavior, not just ports**

Commercial OT NDR is sold on "this PLC started writing coils it never
wrote." ConduitScope's baseline engine is the right idea and too narrow
(Modbus + S7 only).

Extend to:

- EtherNet/IP service + class/instance/attribute
- DNP3 function + group/variation + point index
- IEC 104 type ID + COT + IOA ranges
- OPC UA service + NodeId
- S7 block download / program-change as a high-severity class of its
  own

Output should be **time-bounded**: first seen, last seen, rate, "new
function on known conduit." That is the detection product, not
LAND/Smurf signatures.

**4. Detection that OT IR teams recognize**

Curated classic-attack signatures are fine for a lab. Plants care about:

- engineering-station behavior on the process network (TIA Portal,
  Studio 5000, Unity)
- firmware / logic download and stop/start/cold restart
- new remote-access channel (RDP, TeamViewer, vendor VPN) into L2
- protocol misuse (unsolicited DNP3, unexpected IEC 104 COT, CIP
  Forward Open from a new CIP originator)
- mapping findings to **MITRE ATT&CK for ICS** and Dragos-style
  activity groups at the *technique* level, not a generic "IT protocol
  seen" bucket

Keep the honesty: label confidence. That is a differentiator if the
finding text is written for an incident ticket, not a pcap dump.

**5. Continuous, safe sensor mode**

Offline pcap is perfect for assessments. Programs need a **SPAN/TAP
collector** that:

- runs for weeks on a rugged/air-gapped box
- rotates captures, does not fill the disk
- survives zero-traffic interfaces (the current poll-loop limitation)
- handles multiple tap points and stitches a site-wide matrix
- never transmits toward the process network

Validate on real mirrored OT switches, not loopback. Windows/Npcap and
Linux should be first-class; many engineering laptops are Windows.

**6. Decode depth where the process lives**

Coverage breadth is already competitive for an open tool. Depth still
lags on the protocols that carry **setpoints and logic**:

- OPC UA Variant/DataValue (explicitly the largest remaining UA gap)
- EtherCAT mailbox (CoE SDO) -- that is how slaves are actually
  configured
- BACnet ReadPropertyMultiple and segmentation
- S7 symbolic addressing on real TIA traffic
- IEC 61850 MMS / GOOSE dataset members tied to IED names
- encrypted OPC UA / BACnet/SC / MQTTS: at least session metadata and
  "encrypted conduit present," even without keys

Also finish **IPv6**. New substations and vendors ship it; a
CIDR-v4-only policy engine will age out.

**7. Evidence pack for 62443 / NIS2 / NERC CIP / NIST 800-82**

This is how a small tool displaces a slide in an audit binder.

Produce, from one command:

- zone/conduit diagram + violation list (already close)
- mapping of each finding to **62443 FR 5 (RDF)**, SL target, NIS2
  Article-style "network segmentation evidence"
- optional CIP-007 / CIP-015 style "monitoring was in place for this
  window"
- signed, reproducible report: tool version, policy hash, capture
  hash, decoder confidence notes

Honesty about heuristics belongs *in* that report. Auditors punish
silent overclaim more than "unknown."

**8. Integrate instead of replacing the stack**

Do not try to be a SIEM. Become the OT decode/policy filter that other
tools ingest.

- JSON schema that is stable and versioned (jq is not a product API)
- optional Zeek/Malcolm exporter or Zeek-style TSV
- syslog / CEF / LEEF one-liners for existing SOC pipelines
- "generate firewall rules from this policy + inventory"
- read the same taps dumpcap/tshark already write; do not invent a
  capture ecosystem

That is the path into sites that already standardized on Malcolm,
Elastic, or a commercial sensor.

**9. Trustworthiness of the parser**

OT captures are attacker-controlled bytes. The project's own review
flagged this correctly: sanitizers, fuzzing, and CI matter more than the
next protocol. A CVE in a Modbus parser used on a plant tap kills
adoption faster than missing FINS commands.

Keep:

- ASan/UBSan in CI on every PR
- libFuzzer on pcap reader + TCP reassembly + the high-value ICS
  parsers
- release binaries with docs bundled for air-gapped drop-in
- a clear SBOM and "what this binary will never do" (no callback, no
  active probe)

Active scanning should stay out. Passive-only is a selling point in ICS.

**10. Product shape, not just features**

To get used outside GitHub:

- one signed Linux + Windows binary, man page, sample policies for a
  water plant / discrete cell / substation
- a 30-minute "pcap -> inventory YAML -> policy validate -> PDF/JSON
  pack" tutorial aimed at assessors
- language that plant engineers can read (tag, rack, IED, conduit),
  not only packet fields
- explicit non-goals: no cloud requirement, no agents on PLCs, no
  process disruption

That packaging is what lets a system integrator put it in a NIS2
assessment SOW.
