# Provenance of these fixtures

One real EtherCAT capture.

| File in this directory       | Source |
|-------------------------------|--------|
| `ICS-Ethercat-001.pcap`       | `https://raw.githubusercontent.com/mrhenrike/PCAPTrafficAnalysis/master/Samples/ICS-Ethercat-001.pcap` -- copied verbatim, unmodified. |

## Why this file, and how it was found

`automayt/ICS-pcap` (the collection several of this project's other real-capture fixtures cite,
directly or via `ITI/ICS-Security-Tools`) also lists a file with this same name, but that
repository stores it via Git LFS, and this sandbox's git proxy explicitly denies LFS access to
repositories outside its authorized set (`git lfs pull` and a raw LFS batch API `POST` both
returned an explicit access-denied error naming the proxy, not a generic network failure) --
per this project's standing policy of never working around an access-control denial, no further
attempt was made against that repository. `mrhenrike/PCAPTrafficAnalysis` (a public ICS-pcap
mirror/collection already used elsewhere for research during this project) turned out to host a
copy of the same file; SHA256 comparison confirms it: this file's hash,
`c2c5699ebed47a578e16558b4932ec941cfb16604ff6de0ee42ff5027a24dd37`, matches the `automayt/ICS-pcap`
LFS pointer's own recorded content hash for `ICS-Ethercat-001.pcap` exactly. This is the same
"different, accessible source, confirmed identical by hash" resolution this project has now used
more than once when a specific upstream host was inaccessible.

## `ICS-Ethercat-001.pcap` (157462 bytes, 986 frames, unmodified)

A master's boot-time slave enumeration and register poll sequence against what looks like a small
(up-to-five-slave) demo EtherCAT segment, captured over a 4.74-second window. Every one of the 986
frames is frame-header Type 1 ("EtherCAT command") -- no ADS/RAW-IO/NV/Mailbox framing appears
anywhere in this file -- and every frame decodes with **zero notes**: no Reserved-bit-set warning,
no implausible-Length fallback, no truncated-chain warning, no unrecognized-tag/field warning of
any kind. In particular, this confirms, across all 986 frames, that the frame header's declared
Length field exactly matches the actual number of bytes the More-bit-chained datagram sequence
consumes -- the empirical basis `ethercat.hpp`'s "declared Length" paragraph cites for bounding the
datagram-chain scan by that field rather than walking every byte physically present in the
Ethernet frame the way Wireshark's own dissector does.

Frame 0 (`BRD idx=2 adp=0x0000 ado=0x0130 len=2 wkc=0`, a broadcast read of every slave's AL Status
register at boot) is reproduced byte-for-byte as `tests/sample_ethercat.pcap`'s own first packet
(see `tools/make_sample_pcap.py`'s `build_ethercat_sample`) -- confirmed, before any CMake test
existed, by hand-building that exact frame and checking the decoded text/JSON output matched this
real frame's own decode exactly.

Datagram chain depth ranges from 1 (2 frames, both early in the capture, likely link-up probes) to
11 (140 frames) -- 8140 datagrams decoded in total across the 986 frames. Cmd distribution: APRD
4920, FPRD 1110, BRD 988, FPWR 970, LRD 62, LWR 62, BWR 18, APWR 10 -- both logical-addressing
commands (LRD/LWR) and multiple auto-increment (AP*) and configured-address (FP*) commands appear
with real, structurally valid bytes, including the auto-increment topology-discovery pattern
`ethercat.hpp`'s "Auto increment addressing" paragraph describes (a master probing Adp=0x0000, then
0xFFFF, 0xFFFF-1, ... in one chained frame at boot, to enumerate however many slaves are actually
on the segment -- visible in this capture's earliest frames). Working Counter values seen: 0
(4071 datagrams -- every request's own first, not-yet-responded-to leg in this master/slave
exchange pattern), 1 (3570), 5 (498, matching a 5-slave segment), and 4 (1, a single datagram where
apparently only 4 of 5 slaves responded). Datagram Data length ranges from 1 to 256 bytes; frame
header declared Length ranges from 14 to 352 bytes.

## Gaps: what this real capture does NOT exercise

Only 8 of the 15 defined Cmd values appear (see above) -- APRW, FPRW, BRW, LRW, ARMW, FRMW, EXT,
and NOP never appear in this file. The Len word's Circulating bit (0x4000) is never set anywhere
in these 986 frames, nor is the frame header's own Reserved bit. No 802.1Q VLAN tagging appears
(unlike this project's GOOSE/SV real captures, which do include VLAN-tagged real frames). No frame
of Type 2-5 (ADS/RAW-IO/NV/Mailbox) appears, so the "named only, not decoded further" path for
those Types is validated only against the hand-built fixture. No malformed, truncated, or
declared-Length-mismatched frame appears either -- unsurprising for a clean packet capture, but it
means every one of this decoder's defensive/fallback paths (the implausible-Length fallback, the
mid-header truncation check, the mid-chain truncation check, the `kMaxEthercatDatagrams` safety
cap) is validated only against `tests/sample_ethercat.pcap` (see `tools/make_sample_pcap.py`'s
`build_ethercat_sample`), cross-checked against `packet-ethercat-datagram.c`'s source rather than
an independent real capture. This mirrors the same honest gap already documented for this
codebase's other protocols' less-common paths (PROFINET RT's cyclic IO data, GOOSE's GSE
Management PDU and optional-field-absence handling, EtherNet/IP's CIP I/O implicit messaging).
