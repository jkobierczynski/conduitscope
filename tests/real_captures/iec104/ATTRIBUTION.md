# Provenance of these fixtures

Six real IEC 60870-5-104 captures, from two different sources with two different licensing
bases.

## Wireshark/ICS-pcap-sourced captures (no explicit license; included as real, non-sensitive
## protocol test vectors, same basis as `tests/real_captures/dnp3/ATTRIBUTION.md`)

| File in this directory          | Source |
|----------------------------------|--------|
| `iec104_wireshark_wiki.pcap`    | `https://media.githubusercontent.com/media/automayt/ICS-pcap/master/IEC%2060870/iec104/iec104.pcap` -- a mirror of the Wireshark wiki's own `SampleCaptures` `iec104.pcap` |
| `iec104_090813_diverse.pcap`    | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC60870-5-104/090813_diverse.pcap` -- a mirror of a 2010 pcapr.net upload, subject of Netresec's 2012 "SCADA Network Forensics with IEC-104" blog post |
| `iec104_test_dissect.pcap`      | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC60870-5-104/TestDissectIec104.pcap` -- traced to Wireshark bug/issue #2840, a 2008 dissector-development test file |

`iec104_wireshark_wiki.pcap` (105 packets, real TCP port 2404 session) is a clean TESTFR/STARTDT
handshake followed by a general interrogation whose response cycles through a wide range of
ASDU type IDs (single/double-point, measured values in all three formats, both with and without
time tags, several type IDs this decoder does not yet cover) -- the highest-confidence primary
fixture, hand-verified byte-for-byte against the researched wire format before this decoder was
written.

`iec104_090813_diverse.pcap` (173 packets) is a simulated hydro-plant floodgate-manipulation
scenario -- real command/setpoint traffic, not just monitoring: single/double commands (types 45,
46, 58, 59), short-floating-point setpoint commands (types 50, 63), and general interrogation
responses with real measured-value/single-point data. This is the fixture that specifically
exercises the command/control decode paths the other two don't happen to cover.

`iec104_test_dissect.pcap` (147 packets) is a purpose-built dissector test file rather than
realistic device traffic (weaker provenance than the other two), but is kept for the type IDs it
uniquely covers here: end-of-initialization (type 70) and clock synchronization (type 103).

## Industroyer2 (Netresec; CC BY 4.0 -- see `LICENSE_Industroyer2_CC-BY.txt` in this directory)

| File in this directory          | Source path in the Netresec release |
|----------------------------------|--------------------------------------|
| `industroyer2_station1.pcap`    | `Industroyer2-StationAddress1.pcap` |
| `industroyer2_station2.pcap`    | `Industroyer2-StationAddress2.pcap` |
| `industroyer2_station3.pcap`    | `Industroyer2-StationAddress3.pcap` |

Obtained from `https://www.netresec.com/files/Industroyer2-Netresec.zip`, published by Netresec
alongside their analysis of the Industroyer2 malware (used against a Ukrainian energy provider in
April 2022, attributed to Sandworm/APT44) -- real, attributed nation-state ICS malware traffic
against a live IEC 104 RTU, not a synthetic or generic test vector. This sandbox's own outbound
network access could not reach netresec.com directly (blocked by the environment's egress proxy
policy); the user downloaded the zip from Netresec themselves and provided it directly for this
feature.

Three raw-IP-linktype (`LINKTYPE_RAW` 101, no Ethernet framing) captures, one per station address
the malware targeted, all on TCP port 2404. Manually decoded (independent of this codebase, via a
small Python script) before this decoder was written, to know what to expect: `station1.pcap`
(140 packets) and `station2.pcap` (86 packets) are dominated by C_DC_NA_1 (double command, type
46) activations -- the malware repeatedly commanding breakers, almost all rejected by the RTU with
a negative activation confirmation; `station3.pcap` (324 packets) adds a large run of C_SC_NA_1
(single command, type 45) activations on top of the same double-command pattern. All three also
carry M_EI_NA_1 (end of initialization) and C_IC_NA_1 (general interrogation) traffic from normal
session bring-up. This is the fixture that most directly matters for this tool's purpose: it is
exactly the kind of real attack traffic an OT security analyst using `conduitscope` would need to
recognize and investigate.

## Why these specific fixtures

`tests/sample_iec104.pcap` (hand-built, see `tools/make_sample_pcap.py`'s `build_iec104_sample`)
covers the APCI/ASDU/information-element decode logic exactly as designed -- useful for pinning
down exact expected byte layouts and values, but it can only ever test what its author thought to
construct. These six real captures exercise the parser against three independent IEC 104 stacks'
actual wire encodings (a live Wireshark-captured session, an independent simulator, and real
attack tooling), and are collectively why the type-ID decode table in `iec104.cpp` covers the set
it does: every type ID these six files actually carry that a "first pass" scope reasonably
includes is decoded, not just skipped-and-shown.

None of these captures happened to contain an APDU split across a TCP segment boundary --
consistent with IEC 104's typically small APDU sizes (each I-format APDU carries exactly one
ASDU, unlike DNP3's multi-data-link-frame fragments). `iec104_apdu_declared_length`'s truncation
handling therefore remains untested against real traffic; see the ROADMAP in `docs/MANUAL.md`.
