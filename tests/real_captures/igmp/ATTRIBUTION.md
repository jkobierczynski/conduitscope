# IGMP real-capture attribution

One real IGMP capture, derived (by protocol-filtering trim, not modification of the surviving
frames' bytes) from a source already used elsewhere in this project.

| File in this directory     | Source |
|-----------------------------|--------|
| `plant1_igmp_only.pcap`     | Derived from `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/Combined/Plant1.pcap` by extracting only its IGMP frames (see below) -- the underlying bytes are real, unmodified capture bytes, but the file itself is a trim, not a verbatim copy. |

## How this was found

This project's own routing/redundancy-protocol batch (RIP, IGMP, VRRP, HSRP) searched for real
captures the same way earlier rounds did: `automayt/ICS-pcap`, `ITI/ICS-Security-Tools`, and
`mrhenrike/PCAPTrafficAnalysis` (the three collections this project's other `ATTRIBUTION.md` files
already cite) were each cloned in full and every `.pcap`/`.pcapng` file under all three (498 files
total) was scanned with

```
tshark -r <file> -Y "rip or igmp or vrrp or hsrp" -T fields -e frame.number -e _ws.col.Protocol
```

IGMP traffic turned up in twelve different files across the collections (a mix of IGMPv1, v2, and
v3, mostly incidental multicast-group-membership chatter alongside unrelated ICS protocol traffic
-- EtherNet/IP, CIP, MELSEC, S7comm, C37.118, and a Beckhoff capture). **No RIP, VRRP, or HSRP
traffic was found in any of the 498 files searched** -- see "Search outcome for RIP/VRRP/HSRP"
below.

`ITI/ICS-Security-Tools`'s `pcaps/Combined/Plant1.pcap` was chosen over the other eleven IGMP-
bearing files because this project already draws its STP, PROFINET RT/DCP, and CIP I/O real-
capture fixtures from this exact same file (see the sibling `tests/real_captures/stp/
ATTRIBUTION.md`) -- reusing an already-vetted, already-cited source is preferable to introducing a
fourth external repository into this project's provenance surface for one more fixture. It also
happens to be the richest of the twelve hits (12 frames, two distinct multicast groups, one frame
with two group records in a single report) among files already familiar to this project.

## Why a trim was needed

The original `Plant1.pcap` is 7.6 MB and roughly 55,800 frames -- almost all of it unrelated
traffic, exactly as already noted in `tests/real_captures/stp/ATTRIBUTION.md` for the same file.
It was protocol-filtered down to just its IGMP frames with:

```
tshark -r Plant1.pcap -Y igmp -w plant1_igmp_only.pcap
```

`tshark`'s `-Y`/write path re-serializes matching frames into a new pcapng file without altering
their captured bytes, so every surviving frame's own header/body content is exactly what was
actually on the wire -- only the *set* of frames present, and the container format (pcap ->
pcapng), differ from the original file. This is the same "real bytes, filtered container" trim
already used for this project's STP, PROFINET, and CIP I/O fixtures drawn from this file.

## What this capture actually contains

All 12 frames are IGMPv3 **Membership Report** messages (Type 0x22) from a single host,
`142.81.0.180`, to the all-IGMPv3-routers multicast address `224.0.0.22`, spanning a 3.6-second
window. Eleven frames carry one Group Record each (`Change To Exclude Mode` for group
`224.0.0.252`, the LLMNR multicast address); one frame (packet #9 in the trimmed file, frame 54377
in the original capture) carries **two** Group Records in a single report -- `224.0.0.252` and
`239.255.255.250` (SSDP/UPnP) -- exercising this decoder's multi-record-per-report path against a
genuine multi-group report, not just a hand-built synthetic one.

Every frame's IP header carries a 4-byte **Router Alert option** (IHL=6, 24-byte header instead of
the usual 20), which is standard practice for IGMP traffic (RFC 2113) but a real-world exercise of
this decoder's IPv4-options-aware header-length handling that the synthetic fixture, built with a
plain 20-byte header, does not cover. Every frame is exactly 60 or 62 bytes on the wire (Ethernet's
minimum frame size), so the IP header's declared Total Length is shorter than the captured Ethernet
payload in all but the one 2-record frame -- decoding all eleven single-record frames correctly
produces this decoder's `"N trailing byte(s) ... were trimmed (almost always Ethernet minimum-
frame-size padding, not real payload)"` note, a real-world confirmation of that padding-detection
logic (previously exercised only by hand-built synthetic padding in other protocols' fixtures).

### Cross-validated against Wireshark/tshark's own IGMP dissector

`tshark -V` on each frame confirms this decoder's decode matches Wireshark's own dissector
exactly: IGMP Version 3, Type `Membership Report (0x22)`, Num Group Records (1 or 2), and each
Group Record's Record Type (`Change To Exclude Mode`, i.e. record type 4) and Multicast Address.
This decoder's own `igmp_group_records` JSON field (`"Change To Exclude Mode: 224.0.0.252 (0
source(s))"`) is an independent decode of the same bytes tshark reports as `Group Record :
224.0.0.252  Change To Exclude Mode` / `Record Type: Change To Exclude Mode (4)` -- the same
field-by-field cross-check discipline used for this project's other real captures.

## Search outcome for RIP/VRRP/HSRP

The same 498-file scan across `automayt/ICS-pcap`, `ITI/ICS-Security-Tools`, and
`mrhenrike/PCAPTrafficAnalysis` found **no RIP, VRRP, or HSRP traffic anywhere**. This is not
surprising: all three collections are curated around industrial/ICS protocol traffic and
individual-device captures, not multi-router network topologies where an IGP (RIP), a first-hop-
redundancy protocol (VRRP/HSRP), or router-to-router traffic of any kind would naturally appear.
A further attempt to browse Wireshark's own `SampleCaptures` wiki (migrated to a GitLab wiki page,
`https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures`) for named RIP/VRRP/HSRP sample
files could not be completed within this session (the page's content is served in a way this
session's web-fetch tooling could not retrieve), and downloading arbitrary capture files from
further, less-vetted third-party sites (netresec.com, packetlife.net, and similar aggregators
turned up by a general web search) was judged not worth the provenance risk for what would likely
still be a small, curated addition -- consistent with this project's own precedent (see, e.g.,
`tests/real_captures/*/ATTRIBUTION.md`'s discipline of only trusting a small, already-vetted set of
collections). **RIP, VRRP, and HSRP validation therefore remains synthetic-fixture-only** (RFC-
and Wireshark-dissector-source cross-checked, per each protocol's own header-comment documentation)
-- the same accepted, precedented outcome already documented for this project's FF-HSE and
DeviceNet decoders.

## Search outcome for IGRP/PIM/EIGRP/OSPF

The IGRP/PIM/EIGRP/OSPF round (added alongside RIP/IGMP/VRRP/HSRP's own follow-up work) repeated
this same search against the same three collections -- `automayt/ICS-pcap`, `ITI/ICS-Security-
Tools`, and `mrhenrike/PCAPTrafficAnalysis` -- this time scanning all 1,020 `.pcap`/`.pcapng` files
findable across all local clones of those collections with

```
tshark -r <file> -Y "igrp or eigrp or ospf or pim" -T fields -e frame.number -e frame.protocols
```

**No IGRP, PIM, EIGRP, or OSPF traffic was found in any of the 1,020 files searched.** This mirrors
the RIP/VRRP/HSRP outcome above for exactly the same reason: these are all interior-gateway-
protocol or router-to-router multicast-routing protocols that simply don't appear in single-device
or individual-segment ICS/OT captures the way link-local protocols like IGMP do. **IGRP, PIM,
EIGRP, and OSPF validation therefore remains synthetic-fixture-only** (Wireshark-dissector-source
and RFC-cross-checked, per each protocol's own header-comment documentation) -- the same accepted,
precedented outcome already documented above for RIP/VRRP/HSRP and, before that, for FF-HSE and
DeviceNet.
