# Provenance of these fixtures

Two real PROFINET RT/DCP captures, both sourced from the same public collection as the DNP3/
Modbus/EtherNet-IP real fixtures (see the sibling `ATTRIBUTION.md` files in this repo).

| File in this directory                     | Source |
|---------------------------------------------|--------|
| `profinet_rt_identify_requests.pcap`         | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/profinet/PROFINET-RT-DCP/PROFINET-RT.pcap` -- copied verbatim, unmodified. That directory's own `README.txt` attributes it further upstream to `https://www.cloudshark.org/captures/76038eaa4a3b`. |
| `profinet_change_ip_using_dcp.pcap`          | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/profinet/PROFINET-RT-DCP/ChangeIPUsingDCP.pcap` -- copied verbatim, unmodified. No further upstream source is documented in that directory. |

The same two files are also mirrored (byte-identical, confirmed by MD5) under
`mrhenrike/PCAPTrafficAnalysis` as `ICS-Profinet-002.pcap`/`ICS-Profinet-003.pcap`; that repo's own
`ICS-Profinet-001.pcap` was checked too but contains no PROFINET traffic at all despite the name
(LLDP/ARP/ICMPv6/TCP/COTP only) and isn't used here.

## `profinet_rt_identify_requests.pcap` (1032 bytes, 14 packets, unmodified)

Fourteen real DCP Identify Request frames captured on a live PROFINET segment, each targeting one
specific device by NameOfStation (a real device fingerprinting pattern: rather than the broadcast
"All Selector" identify every device answers, these narrow the query with a NameOfStation filter
block, addressed to a specific named device -- `switch1` through `switch7`, `swln3`, `swln4`, and
`pn-io`, each appearing more than once as the segment was repeatedly queried over roughly 70
seconds). This is the fixture that validates `try_parse_profinet`'s FrameID classification and the
DCP header/NameOfStation decode path against several independent real devices' actual FrameID/Xid/
NameOfStation encodings, not just `tests/sample_profinet.pcap`'s hand-constructed bytes -- and,
because these are real DCP Identify *Requests* (not Responses), confirms that no BlockInfo prefix
is present in that direction (see the next fixture, and `dcp_block_prefix_len`'s comment in
`profinet.cpp`, for the direction where one IS present).

## `profinet_change_ip_using_dcp.pcap` (532 bytes, 6 packets, unmodified)

A real DCP Identify Request/Response exchange followed by a real DCP Set Request/Response that
changes the responding device's IP address, plus two unrelated trailing ARP packets. This is by
far the most valuable fixture for this decoder: **it is the capture that caught a real decoding
bug before this feature ever shipped.** An earlier draft of `try_parse_profinet`'s DCP block
decoder assumed every Option 0x01 (IP)/Option 0x02 (Device Properties) block's body was exactly
the value being decoded (a MAC address, an IP+subnet+gateway triple, a VendorID+DeviceID pair, and
so on) -- which is what every independent secondary source consulted during this feature's design
implied, and what the hand-built `tests/sample_profinet.pcap` fixture (written before this real
capture was found) exercised. Decoding this real Identify Response against that draft produced
`name_of_station="  X208-BORD"` -- two leading NUL bytes/spaces that didn't belong -- and left
DeviceID/DeviceRole/IPParameter undecoded entirely (wrong size). Manually walking the packet's own
bytes (`00 02 05 00 1c 00 00 01 01 01 02 02 01 ...`) against Wireshark's own
`packet-pn-dcp.c` source revealed why: a real device prefixes every Option 0x01/0x02 block's
content with an extra 2-byte BlockInfo (or, for a Set Request, BlockQualifier) field, but only for
specific (ServiceID, direction) combinations -- Identify Response, Hello, and Get Response get
BlockInfo; Set Request gets BlockQualifier; Identify Request, Get Request, and Set Response get
neither. This capture single-handedly exercises three of those five combinations for real (Identify
Response and Set Request WITH the prefix; Identify Request WITHOUT it, corroborated by the other
fixture above) -- see `dcp_block_prefix_len`'s comment in `profinet.cpp` for the fix itself, and
`profinet.hpp`'s file header comment's "IMPORTANT wire-format wrinkle" paragraph for the
full writeup. The real device's Identify Response also exercises a DeviceOptions block (Option
0x02 Suboption 0x05) and a Suboption 0x01 block this decoder doesn't value-decode (both correctly
shown as raw hex, BlockInfo-stripped), and its Set Response exercises an Option 0x05 (Control)
Suboption 0x04 block, also correctly left as raw hex (Option 0x05 is never treated as carrying a
BlockInfo/BlockQualifier prefix by this decoder, matching `packet-pn-dcp.c`, which only applies it
to Option 0x01/0x02).

## Cyclic RT IO data: no real capture found

Neither fixture above contains any cyclic real-time IO data frames (FrameID 0x8000-0xBFFF) --
both are DCP-only exchanges (device discovery/configuration, not the actual I/O scan a PLC runs
against a connected I/O device). A real cyclic RT IO data capture was searched for specifically
while building this decoder (`decode_cyclic` in `profinet.cpp`) -- the same public collections
that yielded the two DCP captures above (`ITI/ICS-Security-Tools`, `mrhenrike/PCAPTrafficAnalysis`,
`automayt/ICS-pcap`, the Wireshark SampleCaptures wiki, Netresec/4SICS public datasets) were
checked, none turned one up. This mirrors the same gap already documented for EtherNet/IP's CIP
I/O implicit messaging in `tests/real_captures/enip/ATTRIBUTION.md`, for the same underlying
reason: capturing the cyclic I/O scan itself requires being on the segment during active
PLC-to-I/O-device operation, a narrower window than a DCP discovery/configuration exchange (which
an engineering tool can trigger on demand). `tests/sample_profinet.pcap` (hand-built, see
`tools/make_sample_pcap.py`'s `build_profinet_sample`) is therefore cyclic RT IO data's only test
coverage; its trailer field layout (CycleCounter/DataStatus/TransferStatus) and DataStatus bit
meanings were cross-checked against Wireshark's `packet-pn-rt.c` dissector source before being
implemented (see `profinet.hpp`'s file header comment), the same discipline applied to every
protocol in this codebase, just not additionally validated against an independent real capture
the way DCP now is.
