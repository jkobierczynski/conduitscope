# BACnet/IP real-capture attribution

`ICS-OT-Network-001-bacnet-excerpt.pcap` (54 packets, 4208 bytes) is a hand-extracted subset of
`ICS-OT-Network-001.pcap`, a 73,075-frame, ~10 MB mixed-OT-protocol capture from
[mrhenrike/PCAPTrafficAnalysis](https://github.com/mrhenrike/PCAPTrafficAnalysis) (MIT-licensed,
"Network packet captures collected in laboratory and controlled environments for educational use
in OT/ICS security research"; commit hash captured at fetch time via the repository's default
branch). This is the same repository this project's `tests/real_captures/ethercat/` real capture
was attributed to (see that directory's own ATTRIBUTION.md) -- it was checked again here because
`automayt/ICS-pcap`'s own `BACNET/` directory (23 files, genuinely the better-populated BACnet
collection) turned out to be Git-LFS pointer files this environment cannot resolve (the same
LFS-access-denial this project has already hit and documented for EtherCAT/GOOSE/SV), and
`kargs.net/captures/` -- BACnet dissector co-author Steve Karg's own capture archive, ~220 files,
almost certainly the single best BACnet source on the public web -- could not be fetched at all
from this environment (the domain is denied by this session's outbound network policy; see
bacnet.hpp's Validation paragraph for what that means for this decoder's own validation scope).

## Why an excerpt, not the whole file

The repository's own README describes `ICS-OT-Network-001.pcap` as "Mixed OT traffic: IEC
60870-5-104, RTSP, SNMP, SMB" -- it does not mention BACnet at all. Running this decoder's own
`--protocol bacnet` filter (a genuine, independent decode, not a grep for a byte pattern) over the
full file found exactly 54 frames it recognizes as BACnet/IP, all falling in one contiguous run
(frame indices 59652-59705 of 73075, 0-indexed 59651-59704) -- a single ReadProperty
request/response polling sequence, nothing else in the file is BACnet/IP. Shipping the full ~10 MB
file for 54 relevant frames would be a poor trade against this project's existing real-capture
fixture sizes (a few KB to ~160 KB, one ~1.5 MB outlier) for no decoding-fidelity benefit, so only
that contiguous 54-frame run was extracted, byte-for-byte, into its own pcap (same global header,
same per-record bytes/timestamps, nothing re-encoded) -- decoding the excerpt produces identical
output to decoding that same slice out of the original file, verified directly before this excerpt
was committed.

## What this excerpt actually contains

Every one of the 54 frames is:
- BVLC function: **Original-Unicast-NPDU** (0x0A) -- ordinary unicast client/server traffic, no
  BBMD/foreign-device routing involved.
- NPDU: Control byte `0x00` throughout -- no DEST, no SRC, no Network Layer Message -- the
  simplest possible NPDU, straight to an APDU.
- APDU: 27 **Confirmed-Request**/**Complex-ACK** pairs, all **readProperty** (service choice 12),
  all against **trend-log** (object type 20) instances 34 through 42 (9 distinct trend-log
  objects, 3 requests each) between `192.168.1.100` (client) and `192.168.1.21` (server), both
  unicast, port 47808 both directions.
- Properties read: **total-record-count** (property 145), **record-count** (property 141),
  **last-notify-record** (property 173) -- 18 of each -- every ReadProperty-ACK's value decoded
  as a plain application-tagged **Unsigned Integer**, with plausible real values (e.g.
  total-record-count 347329, record-count 300, last-notify-record 347280 on trend-log,34) -- this
  reads like a monitoring/historian client polling several trend logs' fill state, a genuine,
  unremarkable real-world BACnet access pattern.
- 27 of the 54 Confirmed-Request frames carry a "1 trailing byte(s) after the IP header's declared
  total length were trimmed" note -- ordinary Ethernet minimum-frame-size padding on a short
  request, the same padding-vs-payload distinction this codebase already documents for several
  other protocols, not a defect in this excerpt or this decoder.

No crash, no unexpected fallback protocol tag, and no parse-error occurred decoding either this
excerpt or the full original 73,075-frame file (confirmed by running plain `conduitscope decode`,
no `--protocol` filter, over the complete original file and checking the per-protocol counts
matched the file's actual contents: 30066 tcp / 21719 modbus / 12143 udp / 4604 iec104 / 2115 enip
/ 1706 non-ip / 664 cotp / 54 bacnet / 4 non-tcp, 73075 total -- the 54 "bacnet" count matches
exactly what `--protocol bacnet` alone finds).

## Gaps -- what this real capture does NOT validate

This excerpt is narrow: it is 100% Original-Unicast-NPDU + plain (Control byte 0x00) NPDU +
Confirmed-Request/Complex-ACK ReadProperty against one property type shape (a scalar Unsigned
value), against one object type (trend-log). Everything else this decoder handles is validated
only against the hand-built `tests/sample_bacnet.pcap` fixture (`tools/make_sample_pcap.py`'s
`build_bacnet_sample`), cross-checked against Wireshark's own dissector source rather than an
independent real capture -- the same honest gap this codebase already documents for several other
protocols' less-common paths (see docs/MANUAL.md's LIMITATIONS). Specifically NOT present in real
traffic here: Who-Is/I-Am/Who-Has/I-Have device/object discovery; WriteProperty; Simple-ACK;
Error/Reject/Abort PDUs; Segment-ACK and segmented APDUs; every BVLC function other than
Original-Unicast-NPDU (BVLC-Result, Write/Read-BDT, Register-Foreign-Device, Read-FDT,
Delete-FDT-Entry, Forwarded-NPDU, Distribute-Broadcast-To-Network, Secure-BVLL); NPDU DEST/SRC
routing fields and HopCount; Network Layer Messages; any PropertyValue type other than Unsigned
(Real, Double, Boolean, CharacterString, BitString, Enumerated, Date, Time, ObjectIdentifier, and
constructed/array values); PropertyArrayIndex; WriteProperty's Priority field; and every APDU
service outside this decoder's "first pass" set. If a real capture exercising any of these turns
up later (kargs.net's archive in particular looks likely to have most of them, if this
environment's network policy ever allows fetching it), it should be added here rather than
replacing this excerpt, the same way this project has grown its other protocols' real-capture
coverage incrementally.
