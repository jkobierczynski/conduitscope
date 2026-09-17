# conduitscope(1) -- Manual

## NAME

conduitscope -- decode Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP, IEC 61850 MMS (Manufacturing Message Specification, ISO 9506), EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP and cyclic real-time IO), IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, EtherCAT, BACnet/IP, HART-IP, and OPC UA Binary traffic from offline pcap captures

## SYNOPSIS

```
conduitscope [-q|--quiet] [--no-color|--color] [--log-file FILE] [--version] [-h|--help] <command> [command options]

conduitscope decode (-r FILE | -i INTERFACE) [-o FILE] [-f text|json|csv] [--protocol NAME]
                     [--modbus-port PORT]... [--dnp3-port PORT]... [--s7comm-port PORT]... [--iec104-port PORT]...
                     [--enip-port PORT]... [--enip-io-port PORT]... [--bacnet-port PORT]... [--hartip-port PORT]... [--opcua-port PORT]... [--mqtt-port PORT]... [--ffhse-port PORT]...
                     [--max-packets N] [--stats] [--strict]
                     [--filter BPF] [--duration SECONDS] [--snaplen BYTES] [--no-promiscuous]

conduitscope info -r FILE

conduitscope interfaces

conduitscope policy validate (-r FILE | -i INTERFACE) --policy FILE [-o FILE] [-f text|json] [--strict]
                              [--filter BPF] [--duration SECONDS] [--snaplen BYTES] [--no-promiscuous]

conduitscope version
```

`-i/--interface`, `conduitscope interfaces`, and the `--filter`/`--duration`/
`--snaplen`/`--no-promiscuous` options are live capture: see LIVE CAPTURE below.
They require this build to have been compiled with libpcap (Linux) / the Npcap
SDK (Windows) found -- an optional, build-time-detected dependency, the one
exception to conduitscope's otherwise zero-dependency design (see BUILDING).

`--protocol NAME` restricts decoding to one protocol instead of the default
`auto`; see PROTOCOL COVERAGE below for the full, current list of valid
protocol names (one per subsection there) -- it's not repeated here so this
list can't drift out of sync as protocols are added.

## DESCRIPTION

conduitscope reads a pcap or pcapng capture file -- or, optionally, a
live network interface (see LIVE CAPTURE below) -- walks each packet's
Ethernet/IPv4/TCP or Ethernet/IPv4/UDP headers, and attempts to recognize
and decode Modbus/TCP, DNP3, IEC 60870-5-104, S7comm (Siemens S7 PLC
protocol, riding on TPKT/COTP), or EtherNet/IP (CIP explicit messaging)
payloads inside the TCP stream, and EtherNet/IP CIP I/O (implicit
messaging) payloads inside the UDP stream. It also recognizes PROFINET RT
frames directly on the wire (EtherType `0x8892`, no IP/TCP/UDP layer at
all) and decodes DCP device discovery/configuration exchanges and cyclic
real-time IO datagrams, and recognizes IEC 61850-8-1 GOOSE frames (EtherType
`0x88B8`, likewise no IP/TCP/UDP layer) and decodes the ASN.1 BER-encoded
GOOSE PDU, recognizes IEC 61850-9-2 Sampled Values frames (EtherType
`0x88BA`, GOOSE's sibling protocol, same header shape and BER encoding) and
decodes the ASN.1 BER-encoded SavPdu, recognizes EtherCAT frames
(EtherType `0x88A4`, likewise no IP/TCP/UDP layer, though plain
fixed-binary-layout rather than ASN.1/BER) and decodes the frame header plus
the chained EtherCAT datagram(s) it carries, and recognizes BACnet/IP frames
(UDP port 47808/0xBAC0, ASHRAE 135 Annex J -- detected by payload shape, not
port, like CIP I/O) and decodes the BVLC framing header, NPDU network layer,
and APDU application layer, including a first-pass set of the most common
BACnet services. It is designed as groundwork for auditing
OT/ICS network traffic against a zone-and-conduit segmentation model (the kind
IEC 62443-3-2 and, by extension, NIS2 risk-assessment work call for): the
protocol-decoding layer (`decode`/`info`) and, now, the zone/conduit
evaluation layer (`policy validate`) both exist -- you write a policy file
describing zones (IP/CIDR ranges) and conduits (the protocol/port traffic
allowed between two zones), point `policy validate` at a capture and that
policy, and get a compliant/non-compliant report naming every flow that
wasn't explicitly permitted. See POLICY FILE FORMAT below for the schema and
LIMITATIONS for exactly what this does and doesn't check.

This is explicitly a groundwork/v0.1.0 release. It favors an honest, narrow
feature set with clearly documented limitations over silently guessing at
things it can't verify. Where the tool is inferring something heuristically
(such as whether a Modbus PDU is a request or a response) rather than tracking
it authoritatively, the output says so.

### Offline pcap files vs. live capture

Reading `.pcap` files is still the primary, always-available way in, and
requires *zero* external dependencies: no libpcap on Linux, no Npcap SDK/driver
on Windows, and no elevated/administrator privileges to build or run. You
capture with whatever is already on your system (tcpdump, dumpcap, Wireshark)
and decode separately -- this remains the only option when conduitscope was
built without live-capture support, and is often still the right choice even
when it wasn't (offline files are easy to archive, diff, and share; a live
capture is not).

Live capture (`-i/--interface`) is also available: an *optional*,
build-time-detected dependency on libpcap (Linux) / the Npcap SDK (Windows).
`-i` for the interface and `-r` for an offline file deliberately mirror
`tcpdump`'s own `-i`/`-r` flags rather than the `-i`/`-I` pairing an earlier
version of this tool used, which read too easily as a typo of itself.
When CMake finds one at configure time, `-i` and `conduitscope interfaces` work;
when it doesn't (or `-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` was passed), the
rest of conduitscope is completely unaffected -- it builds exactly as
dependency-free as before, and those two report the missing support clearly at
runtime instead of not existing at all. See LIVE CAPTURE below for the full
option reference, and BUILDING for how CMake finds libpcap/the Npcap SDK.

### pcap vs. pcapng

conduitscope reads both **classic pcap** (the format tcpdump writes by
default, and what `tshark -F pcap` / Wireshark's "Save As > ... - pcap"
produce) and **pcapng** (the newer block-structured format `dumpcap` and
current Wireshark default to). Which format a given file is gets
auto-detected from its first four bytes -- there is nothing to specify on
the command line, and `-r`/`--read` takes either format interchangeably.

For pcapng specifically, conduitscope understands the Section Header,
Interface Description, Enhanced Packet, and Simple Packet blocks -- between
them, that's every block a mainstream capture tool (dumpcap, Wireshark,
tshark) actually writes, including a capture that mixes more than one
interface (each with its own link type, snaplen, and timestamp resolution)
into a single file, and a file that concatenates more than one capture
section together. Anything else -- the obsolete "Packet Block" pcapng
superseded in the mid-2000s, Interface Statistics Blocks, Name Resolution
Blocks, Decryption Secrets Blocks, or any custom/vendor block type -- is
skipped rather than decoded, per the pcapng spec's own forward-compatibility
rule for unrecognized blocks; see LIMITATIONS for what that means in
practice (in short: it essentially never comes up against a file a current
tool wrote).

A pcapng file that's corrupt -- a bad byte-order magic, a truncated block, a
block-length mismatch between a block's start and end -- is reported with a
specific error naming what's wrong, the same way a truncated classic pcap
file is.

## GLOBAL OPTIONS

These apply regardless of which subcommand is used, and must appear before the
subcommand name on the command line (standard CLI11 behavior).

| Option | Description |
|---|---|
| `-h, --help` | Print help and exit. |
| `--version` | Print version, compiler, platform, and build type, then exit. |
| `-q, --quiet` | Suppress non-essential diagnostic/warning output (e.g. per-packet parse warnings). Decoded output itself is unaffected. |
| `--no-color` | Disable ANSI color in `decode`'s `text`-format output. See COLORIZED OUTPUT below. Mutually exclusive with `--color`. |
| `--color` | Force ANSI color in `decode`'s `text`-format output, even when not writing directly to a terminal (e.g. piping to a pager that understands color, like `less -R`). See COLORIZED OUTPUT below. Mutually exclusive with `--no-color`. |
| `--log-file FILE` | Write diagnostic/warning messages to `FILE` (append mode) instead of stderr. Decoded output (stdout, or `-o`) is unaffected. |

## COMMANDS

### `decode` -- decode a capture and print each recognized packet

```
conduitscope decode (-r FILE | -i INTERFACE) [options]
```

| Option | Default | Description |
|---|---|---|
| `-r, --read FILE` | *(required unless `-i` given)* | Input capture file. Must exist; classic pcap or pcapng, auto-detected. Mutually exclusive with `-i`. |
| `-i, --interface NAME` | *(required unless `-r` given)* | Capture live from this network interface instead of reading a file -- see LIVE CAPTURE below and `conduitscope interfaces`. Requires libpcap/Npcap support to have been built in. Mutually exclusive with `-r`. |
| `--filter BPF` | *(none)* | BPF capture filter (tcpdump syntax, e.g. `"port 502 or port 102"`). Only meaningful with `-i`. |
| `--duration SECONDS` | `0` (unlimited) | Stop a live capture (`-i`) after this many seconds. `0` means rely on `--max-packets` and/or Ctrl+C instead. |
| `--snaplen BYTES` | `65535` | Maximum bytes captured per packet with `-i`. |
| `--no-promiscuous` | off (i.e. promiscuous by default) | With `-i`, don't put the interface into promiscuous mode. Promiscuous is the default because the main live-capture use case -- watching a mirrored/SPAN switch port for zone/conduit traffic -- needs to see traffic that isn't addressed to the capturing host at all. |
| `-o, --output FILE` | stdout | Write decoded output here instead of stdout. |
| `-f, --format {text,json,csv}` | `text` | Output format. See OUTPUT FORMATS below. |
| `--protocol NAME` | `auto` | Restrict decoding to one protocol. See PROTOCOL COVERAGE below for the full, current list of valid protocol names (one per subsection there). `auto` opportunistically tries OPC UA, EtherNet/IP, IEC 104, Modbus, DNP3, S7comm/COTP, S7comm-Plus, MMS, HART-IP, MQTT, and FF-HSE detection on every TCP payload (in that order -- FF-HSE last of all, even after MQTT, see PROTOCOL DETECTION), CIP I/O, BACnet/IP, HART-IP, and FF-HSE detection on every UDP payload (FF-HSE last there too), PROFINET RT (DCP/cyclic) detection on every non-IPv4 Ethernet frame carrying EtherType `0x8892`, GOOSE detection on every non-IPv4 Ethernet frame carrying EtherType `0x88B8`, Sampled Values detection on every non-IPv4 Ethernet frame carrying EtherType `0x88BA`, EtherCAT detection on every non-IPv4 Ethernet frame carrying EtherType `0x88A4`, regardless of port, and Spanning Tree Protocol (STP/RSTP/MSTP) detection on every classic IEEE 802.3 length-framed Ethernet frame whose LLC header is DSAP=SSAP=`0x42` -- a structurally separate dispatch path from every EtherType-keyed protocol above, so there's no ordering/collision question between them (see PROTOCOL DETECTION below). `enip` covers both EtherNet/IP explicit messaging (TCP) and CIP I/O implicit messaging (UDP). `mms` is IEC 61850 MMS (Manufacturing Message Specification, ISO 9506) -- shares S7comm's exact TPKT/COTP transport and TCP port 102, but is a distinct application protocol; see `--s7comm-port` below and PROTOCOL COVERAGE's MMS section. `s7comm-plus` is S7comm-Plus (TIA Portal / S7-1200/1500) -- shares the same TPKT/COTP transport and TCP port 102, disambiguated by its own protocol id byte; see `--s7comm-port` below and PROTOCOL COVERAGE's S7comm-Plus section. `mqtt` is MQTT (v3.1/v3.1.1/v5.0) plus Sparkplug B -- see `--mqtt-port` below and PROTOCOL COVERAGE's MQTT section. `profinet` covers both DCP and cyclic real-time IO. `sv` is IEC 61850-9-2 Sampled Values. `ethercat` is EtherCAT. `bacnet` is BACnet/IP. `hartip` is HART-IP (covers both UDP and TCP). `opcua` is OPC UA Binary (UA-TCP/Secure Conversation, TCP only). `ff-hse` is FOUNDATION Fieldbus HSE (covers FDA/SM/FMS/LAN Redundancy, on both TCP and UDP) -- see `--ffhse-port` below and PROTOCOL COVERAGE's FOUNDATION Fieldbus HSE section. `stp` is Spanning Tree Protocol (STP/RSTP/MSTP) -- no port option, matching GOOSE/SV/EtherCAT/PROFINET's own no-port precedent for a protocol with no port at all; see PROTOCOL COVERAGE's Spanning Tree Protocol section. `devicenet` is DeviceNet (CAN-bus CIP) -- no port option either, the same no-port precedent, but unlike every other value in this list it isn't reached through Ethernet at all: it's gated on the capture's own pcap link type being `LINKTYPE_CAN_SOCKETCAN` (227, standard Linux SocketCAN capture framing -- what `candump -l`/`tcpdump -i can0`/Wireshark itself write capturing a CAN bus), checked before any protocol filter, so `--protocol devicenet` against an ordinary Ethernet-linktype capture simply decodes nothing (every packet still parses at the link layer, just with no application-layer match) rather than erroring; see PROTOCOL COVERAGE's DeviceNet section. |
| `--modbus-port PORT` | *(502 built in)* | Additional TCP port to treat as "expected" for Modbus. Repeatable. Does **not** gate detection -- it only changes whether a decoded Modbus frame is annotated as appearing on an unexpected port, which is itself a useful signal when auditing a conduit. |
| `--dnp3-port PORT` | *(20000 built in)* | Same as `--modbus-port`, for DNP3. Repeatable. |
| `--s7comm-port PORT` | *(102 built in)* | Same as `--modbus-port`, for COTP/S7comm. Repeatable. There is no separate `--mms-port` -- MMS rides the identical TPKT/COTP transport on the identical TCP port 102 S7comm uses (see `mms.hpp`'s file header), so this same option's "expected port" annotation also governs MMS traffic. |
| `--iec104-port PORT` | *(2404 built in)* | Same as `--modbus-port`, for IEC 104. Repeatable. |
| `--enip-port PORT` | *(44818 built in)* | Same as `--modbus-port`, for EtherNet/IP explicit messaging (TCP). Repeatable. |
| `--enip-io-port PORT` | *(2222 built in)* | Same as `--modbus-port`, for EtherNet/IP CIP I/O implicit messaging (UDP). Repeatable. |
| `--bacnet-port PORT` | *(47808 built in)* | Same as `--modbus-port`, for BACnet/IP (UDP). Repeatable. |
| `--hartip-port PORT` | *(5094 built in)* | Same as `--modbus-port`, for HART-IP. Repeatable. Applies to both TCP and UDP, since HART-IP uses the same port number on either transport. |
| `--opcua-port PORT` | *(4840 built in)* | Same as `--modbus-port`, for OPC UA. Repeatable. TCP only -- OPC UA has no UDP mapping. |
| `--mqtt-port PORT` | *(1883 built in)* | Same as `--modbus-port`, for MQTT. Repeatable. TCP only. |
| `--ffhse-port PORT` | *(1089/1090/1091/3622 built in)* | Same as `--modbus-port`, for FOUNDATION Fieldbus HSE. Repeatable. Applies to both TCP and UDP, and shared across FDA/SM/FMS/LAN Redundancy -- the sub-protocol is signaled in-band by the header, not by port. |
| `--max-packets N` | `0` (unlimited) | Stop after decoding this many packets. With `-i`, this also bounds a live capture (in addition to `--duration` and Ctrl+C). |
| `--stats` | off | Print an aggregate summary (protocol counts, Modbus function-code histogram, exception count, capture time span) instead of one line per packet. Ignores `--format`. |
| `--strict` | off | Abort with a nonzero exit status on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a per-packet warning and continuing. Does not affect Modbus/DNP3-level ambiguity, which is always handled by heuristic + note rather than error. |
| `--no-oui` | off (i.e. OUI/MAC-vendor resolution on by default) | Disable OUI (MAC vendor) resolution against the built-in table. See OUTPUT FORMATS' "Name resolution" subsection below. |
| `--resolve` | off | Enable hostname resolution from an explicitly-supplied `--hosts` file. **Never performs live DNS, under any circumstance** -- file-only. See OUTPUT FORMATS' "Name resolution" subsection below. |
| `--hosts FILE` | *(none)* | Unix `/etc/hosts`-style file to resolve IP addresses from, for `--resolve`. Must exist. |
| `--nn` | off (i.e. service-name resolution on by default) | Disable service name (port -> name) resolution, from the built-in table and `--services` alike. Named after the `nc`/`nmap`/`tcpdump`-family `-n`/`-nn` "don't resolve names" convention. See OUTPUT FORMATS' "Name resolution" subsection below. |
| `--services FILE` | *(none)* | Unix `/etc/services`-style file to supplement/override the built-in port->service-name table. Must exist. |

### `info` -- print pcap file metadata and a protocol histogram

```
conduitscope info -r FILE
```

| Option | Default | Description |
|---|---|---|
| `-r, --read FILE` | *(required)* | Input capture file. Classic pcap or pcapng, auto-detected. |

Prints the pcap format version, link type, snaplen, timestamp resolution, and
then the same protocol/function-code histogram as `decode --stats`, without
requiring you to also specify `--stats` explicitly. Useful as a first look at
an unfamiliar capture before deciding whether/how to filter it with `decode`.
`info` currently only works against offline files; there's no live equivalent
(a live capture never ends on its own the way a file does, so "metadata about
the whole thing" doesn't have a natural moment to print) -- use `decode -i
--stats` instead for a live summary, bounded by `--duration`/`--max-packets`/Ctrl+C.

### `interfaces` -- list network interfaces available for live capture

```
conduitscope interfaces
```

Takes no options. Lists every interface libpcap/Npcap can see, one per line,
with a `[loopback]` tag where applicable and a platform-supplied description
where one exists (often absent on Linux). Requires libpcap/Npcap support to
have been built in; unlike opening one for capture, listing them generally
does not require elevated privilege. See LIVE CAPTURE below.

### `policy validate` -- zone/conduit policy check

```
conduitscope policy validate (-r FILE | -i INTERFACE) --policy POLICY_FILE [options]
```

| Option | Default | Description |
|---|---|---|
| `-r, --read FILE` | *(required unless `-i` given)* | Input capture file. Must exist; classic pcap or pcapng, auto-detected. Mutually exclusive with `-i`. |
| `-i, --interface NAME` | *(required unless `-r` given)* | Check live traffic from this network interface instead of reading a file -- see LIVE CAPTURE below. Requires libpcap/Npcap support to have been built in. Mutually exclusive with `-r`. There's no `--max-packets` here (matching this command's offline-file surface, which never had one either); a live run relies on `--duration` and/or Ctrl+C to stop. |
| `--filter BPF` | *(none)* | BPF capture filter (tcpdump syntax). Only meaningful with `-i`. |
| `--duration SECONDS` | `0` (unlimited) | Stop a live capture (`-i`) after this many seconds; `0` means rely on Ctrl+C instead. |
| `--snaplen BYTES` | `65535` | Maximum bytes captured per packet with `-i`. |
| `--no-promiscuous` | off (i.e. promiscuous by default) | Same meaning as `decode --no-promiscuous`. |
| `--policy FILE` | *(required)* | Zone/conduit policy file. Must exist. A restricted YAML subset -- see POLICY FILE FORMAT below. |
| `-o, --output FILE` | stdout | Write the report here instead of stdout. |
| `-f, --format {text,json}` | `text` | Report format. `text` is the human-readable report shown throughout this section; `json` is meant for scripting an audit pipeline -- see POLICY FILE FORMAT's "JSON report schema" below. |
| `--strict` | off | Same meaning as `decode --strict`: abort on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a warning and continuing to evaluate the rest of the capture. |

With `-i`, the report's `capture:` line shows `live:<interface>` in place of a
file path, and Ctrl+C (or `--duration` elapsing) stops the capture and still
evaluates/reports on whatever flows were observed up to that point -- the same
as running `policy validate -r` against a capture file that happens to end at
that moment.

`policy validate` decodes the capture exactly as `decode` would (the same
Modbus/DNP3/IEC104/S7comm detection, TCP reassembly, and authoritative Modbus
pairing all run underneath), then groups the decoded packets into TCP flows
and checks each flow against the policy's conduits. It does not change or
duplicate any decoding logic -- see `PolicyEngine` (`policy_engine.hpp`),
which is built entirely on top of `Decoder`'s already-public
`DecodedPacket` output.

For each observed TCP flow, `policy validate` determines which side
initiated the connection (the "client") and which answered (the "server"),
classifies each side's IP address into a zone via the policy's CIDR blocks,
and looks for a conduit permitting that flow's protocol(s) at the server's
port, in that direction. A flow lands in exactly one of three buckets:

- **Allowed** -- some conduit permits it. The report names which one.
- **Violation** -- both endpoints are zone-classified, but no conduit
  permits this specific protocol/port/direction combination between them.
- **Unclassified** -- at least one endpoint's address matches no declared
  zone at all, or the flow never carried any Modbus/DNP3/IEC104/S7comm traffic
  conduitscope recognized (only a handshake, or payloads that didn't
  decode). There's nothing to check against a conduit in either case, so
  this is reported separately from an outright violation, but it still
  makes the capture non-compliant -- see EXIT STATUS. In practice this is
  usually the more actionable finding for a first pass: it's telling you
  either your zone list is incomplete, or there's traffic on the wire your
  protocol coverage doesn't recognize.

The report additionally lists every conduit the policy declares that no
observed flow ever matched ("unexercised") -- purely informational (it
doesn't affect compliance), but useful for noticing a conduit you expected
this capture to exercise and didn't, or one worth pruning from the policy.

Example, against the committed sample fixtures:

```sh
$ conduitscope policy validate -r tests/sample_modbus.pcap --policy tests/policies/compliant.yaml
Zone/conduit policy validation
  capture: tests/sample_modbus.pcap
  policy:  tests/policies/compliant.yaml (2 zone(s), 3 conduit(s))

Result: COMPLIANT

Flows evaluated: 1 (1 allowed, 0 violation(s), 0 unclassified)
  3 total packet(s) in capture, 0 skipped (non-TCP/non-IP)

VIOLATIONS (0):
  (none)

UNCLASSIFIED TRAFFIC (0):
  (none)

ALLOWED (1):
  [1] 192.168.1.50 -> 192.168.1.10:502  (modbus, 3 packet(s))
      zones: hmi_zone -> plc_zone, matched conduit "HMI polls PLC via Modbus"

Conduits never exercised by this capture (2):
  - HMI polls PLC via DNP3
  - Engineering station S7comm
```

### `version` -- print version and build information

Equivalent to the global `--version` flag; provided as a subcommand as well
for scripts that prefer `conduitscope version` over a flag. Its output includes
`live capture: libpcap/Npcap` or `live capture: not built in`, so a script can
check support without needing to parse an error from `-i`/`interfaces`.

## LIVE CAPTURE

`-i/--interface` (on `decode` and `policy validate`) and `conduitscope
interfaces` capture traffic directly from a network interface instead of
reading an offline pcap file, using libpcap (Linux) / the Npcap SDK (Windows).
This is an *optional*, build-time-detected dependency -- see BUILDING for how
CMake finds it, and "Offline pcap files vs. live capture" above for why it's
optional rather than assumed. `conduitscope version` reports whether a given
binary has it.

### Typical use

```sh
# See what's capturable:
conduitscope interfaces

# Decode live traffic from eth0, limited to Modbus/IEC104/S7comm ports, for 60 seconds:
conduitscope decode -i eth0 --filter "port 502 or port 2404 or port 102" --duration 60

# Check live traffic against a zone/conduit policy until Ctrl+C:
conduitscope policy validate -i eth0 --policy policy.yaml
```

### Stopping a live capture

A live capture stops, and whatever was captured up to that point is still
decoded/reported, on any of:

- `--duration SECONDS` elapsing (both commands).
- `--max-packets N` being reached (`decode` only; `policy validate` has no
  packet-count option -- see its own option table above).
- **Ctrl+C** (SIGINT). This is caught and used to stop the capture cleanly
  (finishing whatever output/report was in progress), not to kill the process
  outright -- so `decode -i eth0` with no `--duration`/`--max-packets` at all is
  a reasonable way to capture "until I say stop", the same way `tcpdump` with no
  `-c`/duration option is.

### Promiscuous mode

Live capture defaults to promiscuous mode (`--no-promiscuous` turns it off).
This matters specifically for the OT/ICS conduit-auditing use case: the
traffic conduitscope needs to see for a meaningful zone/conduit check is
usually flowing *between two other devices* (an HMI and a PLC, say), not to or
from the machine running conduitscope, so the capturing host normally needs to
be plugged into a mirrored/SPAN port and see traffic that isn't addressed to
it at all -- exactly what promiscuous mode is for. Capturing from a host's own
interface while it's a party to the traffic (e.g. running conduitscope
directly on an engineering workstation) doesn't need it, hence the opt-out
rather than requiring an opt-in.

### `--filter` (BPF)

`--filter` takes a Berkeley Packet Filter expression -- the same syntax
`tcpdump`'s own filter argument uses (e.g. `"host 192.168.1.10 and port
502"`). It's applied by libpcap/Npcap itself, before a packet ever reaches
conduitscope's own decoding, so it's a performance/focus tool (capture only
what you care about) rather than a substitute for `--protocol` or the
`--modbus-port`/`--dnp3-port`/`--s7comm-port`/`--iec104-port` options, which operate on
already-captured traffic instead. An invalid filter expression is reported
clearly (`error: invalid capture filter '...'`) and the process exits without
opening the interface.

### Windows / Npcap notes

Live capture on Windows is implemented against the same documented libpcap-
compatible API Npcap provides (`pcap_create`/`pcap_activate`/`pcap_next_ex`/
etc.), the same code path used on Linux -- but, since this project's
development and testing has so far only happened on Linux (see LIMITATIONS),
it has not yet actually been run against a real Windows machine/Npcap
installation. Two things worth knowing going in:

- **Build time vs. run time** are two separate Npcap pieces. The *Npcap SDK*
  (headers + import libraries) is what CMake needs to find to build live
  capture support in at all -- see BUILDING. The *Npcap runtime* (the actual
  driver/service) is a completely separate install, needed on whatever machine
  actually *runs* a conduitscope binary built with live-capture support, even
  if that's the same machine it was built on. A binary built with live-capture
  support still runs fine on a machine with no Npcap runtime installed at
  all -- `-i`/`interfaces` will just fail to open/enumerate anything, the same
  as any other capture-permission failure.
- **Interface names** on Windows (via Npcap) are not simple names like `eth0`
  -- `conduitscope interfaces` is the way to get the exact string to pass to
  `-i` rather than guessing one.

### Enumerating interfaces without capturing

`conduitscope interfaces` (via `pcap_findalldevs`) generally does **not**
require elevated privilege, even though actually opening one for capture
(`-i`) usually does (root/administrator, or an equivalent capability/group
grant -- e.g. Linux's `CAP_NET_RAW`, or membership in the `npcap`/
`wireshark` group on a suitably configured Windows/Npcap install). If
`interfaces` lists nothing at all, that's more likely a privilege issue than
an environment with genuinely zero network interfaces; the command says so.

## POLICY FILE FORMAT

A policy file is YAML-*compatible* but not general YAML: it's parsed by a
small, purpose-built parser (`yaml_mini.hpp`/`.cpp`) that reads exactly the
"block-style YAML" subset a hand-written config file like this actually
needs, rather than vendoring a full YAML library (this project has zero
external dependencies by design -- see the README). Any file staying within
that subset is also valid YAML any editor/linter understands; going outside
it (see "Unsupported YAML constructs" below) is a clear, line-numbered error,
never a silent misparse.

### Schema

Two required top-level keys:

```yaml
zones:
  <zone name>:
    description: "<optional free text>"
    networks:
      - <IPv4 address or CIDR block>
      - <...>
  <zone name>:
    networks: [<address or CIDR>, <...>]   # a flow-style list works too

conduits:
  - name: "<conduit name>"
    description: "<optional free text>"
    from: <zone name or [zone name, ...]>
    to: <zone name or [zone name, ...]>
    protocols: [<modbus | dnp3 | s7comm | iec104 | enip | any>, <...>]
    ports: [<port>, <...>]                  # omit entirely to mean "any port"
    bidirectional: <true | false>           # default: false
    functions: [<function/service name>, <...>]  # optional; see "Function-level restrictions" below
```

**Zones.** Each zone name maps to one or more IPv4 CIDR blocks (`10.10.10.0/24`)
or bare addresses (`10.10.10.5`, treated as `/32`). At least one zone is
required. **No two zones may claim the same address** -- `policy validate`
needs to say definitively which single zone a packet's source/destination
belongs to, so overlapping networks across zones are rejected at load time,
not silently resolved by declaration order. An address matching no declared
zone is reported as the reserved zone name `unclassified` (which you
therefore can't declare yourself -- see "Validation errors" below).

**Conduits.** Each conduit permits one or more protocols, on one or more
ports (or any port, if `ports` is omitted), from a set of one or more zones
to a set of one or more zones. `from`/`to` each accept either a single zone
name (`from: hmi_zone`) or a list of zone names (`from: [corp_zone,
hmi_zone]`), and when either is a list the conduit is many-to-many: it
permits traffic from ANY zone named in `from` to ANY zone named in `to`, not
just one specific zone pair. For example, a conduit permitting Modbus from
either a corporate zone or a remote-access zone, into either of two
redundant PLC zones, can be written as a single conduit --

```yaml
from: [corp_zone, remote_access_zone]
to: [plc_zone_a, plc_zone_b]
protocols: [modbus]
```

-- instead of needing one conduit per zone-pair combination (four, in this
example). At least one conduit is required -- a policy with zones but zero
conduits would flag every zone-classified flow as a violation, which is
almost certainly not what a first policy file intended, so it's rejected
outright rather than silently accepted as an implicit deny-all.

`protocols` uses the same protocol names conduitscope's own decoded output
uses: `modbus`, `dnp3`, `s7comm`, `iec104`, `enip`, plus the wildcard `any`. A COTP session
that never carries a full S7comm message (e.g. only a connection
request/confirm was captured) still counts as `s7comm` traffic for matching
purposes -- see PROTOCOL COVERAGE's S7comm/COTP section for why a "cotp"-
tagged packet and an "s7comm"-tagged one are the same conduit on the wire.
`enip` here only ever means EtherNet/IP explicit messaging (TCP 44818):
conduits are TCP-only (see LIMITATIONS), so there is currently no way to
write a conduit matching CIP I/O (implicit messaging, UDP 2222) traffic,
even though `decode` now decodes it -- see ROADMAP.

`from`/`to` describe a **direction**: which zone(s) initiate the TCP
connection (`from`) and which zone(s) answer it (`to`) -- not which zone
sends which bytes once the connection is up (a Modbus response, for
instance, flows from the server back to the client, but the conduit is
still written `from: <client zone(s)> to: <server zone(s)>`, matching who
dialed whom). A flow matches when its client is in ANY of the `from` zones
and its server is in ANY of the `to` zones. Most real OT conduits are
one-directional this way (an HMI/engineering zone reaching into a
control-network zone). Set `bidirectional: true` on a conduit that should
also permit the same protocol/port set initiated the opposite way (checked
symmetrically against the same zone lists: client in `to`, server in
`from`).

`ports` restricts which TCP port on the **responding** (server) side of the
connection this conduit covers; omit it to allow any port. A `protocol`
singular alias is also accepted for a conduit that only lists one protocol
(`protocol: modbus` instead of `protocols: [modbus]`), and every list-typed
field (`networks`, `protocols`, `ports`, `from`, `to`) also accepts a single
bare value in place of a one-element list, for readability on a short
policy file.

**Worked example.** `tests/policies/multi_from_zones.yaml` declares three
zones (`corp_zone`, `hmi_zone`, `plc_zone`) and one conduit whose `from` is
a list, `[corp_zone, hmi_zone]` -- deliberately listing `hmi_zone` (the zone
that actually matches `tests/sample_modbus.pcap`'s HMI, 192.168.1.50)
second, not first, to prove matching checks every list entry, not just
index 0:

```sh
$ conduitscope policy validate -r tests/sample_modbus.pcap --policy tests/policies/multi_from_zones.yaml
Zone/conduit policy validation
  capture: tests/sample_modbus.pcap
  policy:  tests/policies/multi_from_zones.yaml (3 zone(s), 1 conduit(s))

Result: COMPLIANT

Flows evaluated: 1 (1 allowed, 0 violation(s), 0 unclassified)
  3 total packet(s) in capture, 0 skipped (non-TCP/non-IP)

VIOLATIONS (0):
  (none)

UNCLASSIFIED TRAFFIC (0):
  (none)

ALLOWED (1):
  [1] 192.168.1.50 -> 192.168.1.10:502  (modbus, 3 packet(s))
      zones: hmi_zone -> plc_zone, matched conduit "corp or HMI reaches PLC via Modbus"

Conduits never exercised by this capture (0):
  (none)
```

See also `tests/policies/multi_to_zones.yaml` (the same idea on the `to`
side) and `tests/policies/multi_zone_bidirectional.yaml` (list-widened
`from`/`to` combined with `bidirectional: true` reverse matching).

### Function-level restrictions

`functions` (singular alias `function`, mirroring `protocol`/`protocols`)
narrows a conduit from "this protocol is allowed" down to "only these named
functions/services within this protocol are allowed" -- e.g. a conduit that
permits Modbus reads from an HMI zone into a PLC zone but not writes. It's
optional; omitting it (the default, and the only option before this field
existed) leaves a conduit unrestricted -- every function/service the
protocol decodes is permitted, exactly as before.

**One protocol only.** `functions`/`function` is only valid on a conduit
whose `protocols`/`protocol` resolves to **exactly one concrete protocol**
-- not the wildcard `any`, and not a list of more than one protocol. Each
protocol has its own, entirely separate table of known function/service
names (see below), so there's no single table to validate a multi-protocol
or `any`-protocol conduit's `functions` entries against. A conduit needing
different function allow-lists per protocol should instead be written as one
conduit per protocol. Violating this is a load-time `PolicyError`:

```
error: policy.yaml:N: conduit '<name>': 'functions' requires exactly one protocol in
'protocols' (not 'any', and not a list of more than one) -- write one conduit per
protocol when the allowed functions differ
```

**Exact decoder strings, matched case-insensitively.** Each entry in
`functions` must be one of that protocol's own canonical function/service
names -- the exact strings its decoder already emits, as listed in
`DecodedPacket`'s `modbus_function_name`, `dnp3_function_name`,
`s7comm_function_name`, `iec104_asdu_type_short_name` (the clean mnemonic,
e.g. `"M_SP_NA_1"` -- *not* the more verbose `iec104_asdu_type_name`, which
still exists unchanged for display), and `enip_cip_service_name` fields.
Matching, both at policy-load-time validation and at report time, is
case-insensitive, but a policy file's entries are normalized to the
decoder's own canonical casing for display (error messages, "permits only"
reasons) regardless of how the file spelled them.

Practical tip: rather than guessing at a name or transcribing one from this
manual, run `decode --format json` on a sample capture of the traffic you
want to allow-list and copy the exact string out of its
`modbus_function_name`/`dnp3_function_name`/`s7comm_function_name`/
`iec104_asdu_type_short_name`/`enip_cip_service_name` field -- that guarantees
an exact match.

An entry that isn't a known name for that protocol is rejected at load
time, with a "did you mean" suggestion when a known name is a plausible
typo of it:

```
error: policy.yaml:N: conduit '<name>': unknown modbus function 'Read Holding Registerss'
-- did you mean 'Read Holding Registers'?
```

and without one when nothing is close enough:

```
error: policy.yaml:N: conduit '<name>': unknown modbus function 'Totally Unrelated Nonsense Function'
```

**Matching semantics: flow-level, strict-all.** `functions` is checked at
the same granularity everything else in a conduit is checked at -- the
whole TCP flow (both directions of one 4-tuple, aggregated over the
capture), not per-packet. A flow that otherwise matches a `functions`-
restricted conduit on protocol/port/zone/direction is **Allowed** only if
**every distinct** function/service name observed anywhere on that flow is
in the conduit's allow-list. If even one observed function isn't
permitted, the whole flow is a **Violation** -- the reason names exactly
which observed function(s) weren't permitted and what the conduit does
permit, e.g.:

```
function 'Write Single Register' observed; conduit 'modbus reads only' permits only: Read Holding Registers
```

or, with more than one disallowed function observed on the same flow:

```
functions 'Read', 'Response' observed; conduit 'dnp3 direct operate only' permits only: Direct Operate
```

(functions that *are* permitted but also observed on that same flow are
not named in the reason -- only the disallowed ones are.)

**Worked example.** `tests/sample_modbus_pairing.pcap` carries two separate
Modbus flows: one client (port 51701) issuing only "Read Holding
Registers", another (port 51700) issuing only "Write Single Register".
Against `tests/policies/functions_modbus.yaml`, whose one conduit allows
only `Read Holding Registers`:

```sh
$ conduitscope policy validate -r tests/sample_modbus_pairing.pcap \
    --policy tests/policies/functions_modbus.yaml
Zone/conduit policy validation
  capture: tests/sample_modbus_pairing.pcap
  policy:  tests/policies/functions_modbus.yaml (2 zone(s), 1 conduit(s))

Result: NON-COMPLIANT (1 violation(s), 0 unclassified flow(s))

Flows evaluated: 2 (1 allowed, 1 violation(s), 0 unclassified)
  5 total packet(s) in capture, 0 skipped (non-TCP/non-IP)

VIOLATIONS (1):
  [1] 192.168.1.50 -> 192.168.1.10:502  (modbus, 2 packet(s))
      zones: hmi_zone -> plc_zone
      function 'Write Single Register' observed; conduit 'modbus reads only' permits only: Read Holding Registers

UNCLASSIFIED TRAFFIC (0):
  (none)

ALLOWED (1):
  [1] 192.168.1.50 -> 192.168.1.10:502  (modbus, 3 packet(s))
      zones: hmi_zone -> plc_zone, matched conduit "modbus reads only"

Conduits never exercised by this capture (0):
  (none)
```

Both flows share the same conduit's protocol/port/zone/direction; only
`functions` tells them apart. See the "EXAMPLES" entries below for a
`policy validate` run showing the compliant side of the same conduit.

**Known function/service names.** For reference (and to save a round trip
through `decode --format json` when you just need the list), each
protocol's currently known names, as `modbus_known_function_names()`/
`dnp3_known_function_names()`/`s7comm_known_function_names()`/
`iec104_known_asdu_short_names()`/`enip_known_cip_service_names()` (see
each protocol's own header) enumerate them:

- **Modbus** (15): Read Coils, Read Discrete Inputs, Read Holding
  Registers, Read Input Registers, Write Single Coil, Write Single
  Register, Read Exception Status, Diagnostics, Write Multiple Coils,
  Write Multiple Registers, Report Server ID, Mask Write Register,
  Read/Write Multiple Registers, Read FIFO Queue, Encapsulated Interface
  Transport
- **DNP3** (37): Confirm, Read, Write, Select, Operate, Direct Operate,
  Direct Operate No Ack, Immediate Freeze, Immediate Freeze No Ack, Freeze
  Clear, Freeze Clear No Ack, Freeze At Time, Freeze At Time No Ack, Cold
  Restart, Warm Restart, Initialize Data, Initialize Application, Start
  Application, Stop Application, Save Configuration, Enable Unsolicited
  Responses, Disable Unsolicited Responses, Assign Classes, Delay
  Measurement, Record Current Time, Open File, Close File, Delete File,
  Get File Info, Authenticate File, Abort File, Activate Config,
  Authentication Request, Authentication Error, Response, Unsolicited
  Response, Authentication Response
- **S7comm** (12): CPU services, Read Var, Write Var, Request Download,
  Download Block, Download Ended, Start Upload, Upload, End Upload, PLC
  Control, PLC Stop, Setup Communication
- **IEC 60870-5-104** (51, the short ASDU mnemonic -- matched against
  `iec104_asdu_type_short_name`, not `iec104_asdu_type_name`): M_SP_NA_1,
  M_SP_TA_1, M_SP_TB_1, M_DP_NA_1, M_DP_TA_1, M_DP_TB_1, M_ST_NA_1,
  M_ST_TA_1, M_ST_TB_1, M_BO_NA_1, M_BO_TA_1, M_BO_TB_1, M_ME_NA_1,
  M_ME_TD_1, M_ME_TA_1, M_ME_NB_1, M_ME_TE_1, M_ME_TB_1, M_ME_NC_1,
  M_ME_TF_1, M_ME_TC_1, M_ME_ND_1, M_IT_NA_1, M_IT_TB_1, M_IT_TA_1,
  C_SC_NA_1, C_SC_TA_1, C_DC_NA_1, C_DC_TA_1, C_RC_NA_1, C_RC_TA_1,
  C_SE_NA_1, C_SE_TA_1, C_SE_NB_1, C_SE_TB_1, C_SE_NC_1, C_SE_TC_1,
  C_BO_NA_1, C_BO_TA_1, M_EI_NA_1, C_IC_NA_1, C_CI_NA_1, C_RD_NA_1,
  C_CS_NA_1, C_RP_NA_1, C_CD_NA_1, C_TS_TA_1, P_ME_NA_1, P_ME_NB_1,
  P_ME_NC_1, P_AC_NA_1
- **EtherNet/IP** (31): Read_Tag, Write_Tag, Read_Modify_Write_Tag,
  Read_Tag_Fragmented, Write_Tag_Fragmented, Get_Instance_Attribute_List,
  Unconnected_Send, Forward_Open, Forward_Close, Large_Forward_Open,
  Unconnected_Send/Read_Tag_Fragmented (reply), Forward_Close/
  Read_Modify_Write_Tag (reply), Get_Attributes_All, Set_Attributes_All,
  Get_Attribute_List, Set_Attribute_List, Reset, Start, Stop, Create,
  Delete, Multiple_Service_Packet, Apply_Attributes,
  Get_Attribute_Single, Set_Attribute_Single, Find_Next_Object_Instance,
  Restore, Save, No_Op, Get_Member, Set_Member

**A known, deliberate limitation: EtherNet/IP's ambiguous compound
names.** Two of the EtherNet/IP names above --
`Unconnected_Send/Read_Tag_Fragmented (reply)` and
`Forward_Close/Read_Modify_Write_Tag (reply)` -- are genuinely ambiguous:
CIP encodes a reply's service code in a way that collides between two
different request services when the originating request wasn't itself
seen (e.g. capture started mid-session), so the decoder honestly reports
"it was one of these two" rather than guessing. A `functions:` allow-list
naming only the single request-side name (e.g. `Read_Tag_Fragmented`
alone, without the compound reply form) will never match a flow whose only
evidence is that ambiguous reply -- there is no way to confidently
allow-list a service the decoder itself can't confidently identify. This
is correct, honest behavior, not a bug: an ambiguous service can't be
safely treated as matching a specific allow-listed name. If this matters
for a given conduit, either capture from session start (so the original
request is seen and the reply resolves unambiguously) or list the compound
name itself in `functions`.

### Validation errors

Every rule below is checked when the policy file is loaded, before any
capture is decoded, and reported as `error: <file>:<line>: <message>` (the
line number is omitted when the problem isn't tied to one specific line,
such as a missing top-level key). None of these can be bypassed with
`--strict` or any other flag -- an invalid policy file is always a fatal
error (see EXIT STATUS):

- a missing top-level `zones` or `conduits` key, or either being empty
- a zone with no `networks`, or a network that isn't a valid IPv4
  address/CIDR block
- two zones whose networks overlap
- a zone literally named `unclassified` (reserved -- see "Zones" above)
- a duplicate zone name (a YAML-level error: mapping keys are inherently
  unique) or duplicate conduit name (a policy.cpp-level check: a conduit's
  `name` is a value, not a key, so two conduits genuinely could share one
  without a YAML parser objecting)
- a conduit missing `name`/`from`/`to`/`protocols`, or whose `from`/`to`
  (each a single zone name or a list of them) names a zone that isn't
  declared in `zones` -- every entry of a list `from`/`to` is checked, not
  just the first
- a conduit's `from`/`to` list being empty (e.g. `from: []`)
- a conduit protocol outside `{modbus, dnp3, s7comm, iec104, enip, any}`
- a conduit port outside `[1, 65535]`
- a conduit's `bidirectional` value that isn't a recognizable boolean
  (`true`/`false`/`yes`/`no`)
- a conduit's `functions`/`function` given while `protocols`/`protocol`
  resolves to anything other than exactly one concrete protocol (i.e. it's
  `any`, or a list of more than one) -- see "Function-level restrictions"
  above
- a conduit's `functions`/`function` entry that isn't one of its
  protocol's own known function/service names (case-insensitively) -- the
  error names the closest known name ("did you mean '...'?") when one is a
  plausible typo, and omits the suggestion when nothing is close enough

### Unsupported YAML constructs

Rejected with a clear error rather than silently misparsed, if encountered:
anchors and aliases (`&x`, `*x`), tags (`!!str`), multi-document streams
(`---`, `...`), block scalars (`|`, `>`), flow mappings (`{a: b}`), and tab
characters used for indentation.

### JSON report schema (`-f json`)

`from`/`to` are always rendered as JSON arrays of zone names, even when the
policy file wrote a single zone name for that field -- a conduit's `from`/
`to` can now each hold more than one zone (see "Conduits" above), so the
JSON shape is array-always rather than switching between a bare string and
an array depending on how the policy file happened to write it:

```json
{
  "capture": "capture.pcap",
  "policy": "policy.yaml",
  "zone_count": 2,
  "conduit_count": 3,
  "conduits": [
    {
      "name": "HMI polls PLC via Modbus",
      "from": ["hmi_zone"],
      "to": ["plc_zone"],
      "bidirectional": false,
      "protocols": ["modbus"],
      "functions": []
    }
  ],
  "compliant": true,
  "total_packets": 3,
  "skipped_non_tcp": 0,
  "allowed_count": 1,
  "violation_count": 0,
  "unclassified_count": 0,
  "flows": [
    {
      "client_ip": "192.168.1.50",
      "server_ip": "192.168.1.10",
      "server_port": 502,
      "client_zone": "hmi_zone",
      "server_zone": "plc_zone",
      "protocols": ["modbus"],
      "observed_functions": ["Read Holding Registers"],
      "packet_count": 3,
      "verdict": "allowed",
      "matched_conduit": "HMI polls PLC via Modbus",
      "reason": null
    }
  ],
  "unexercised_conduits": []
}
```

`verdict` is one of `"allowed"`, `"violation"`, `"unclassified"`.
`matched_conduit` is only non-`null` when `verdict` is `"allowed"`; `reason`
is only non-`null` otherwise (a short, human-readable explanation, the same
text the `text` report shows).

Two fields are additive since function-level restrictions were introduced
and appear on every report regardless of whether any conduit actually uses
`functions`:

- **`conduits[]`** -- one entry per conduit declared in the policy (in
  declaration order), summarizing `name`, `from`, `to`, `bidirectional`,
  `protocols`, and `functions` (empty array `[]` when that conduit is
  unrestricted -- the pre-existing default) exactly as the policy file
  declared them. Useful for an audit pipeline that wants to render the
  policy itself alongside its verdicts without re-parsing the YAML.
- **`observed_functions`** (per flow) -- the distinct, non-empty
  function/service names observed on that flow, sorted. Populated for
  every flow regardless of whether the matched conduit (if any) restricts
  `functions` -- purely informational when it doesn't, and exactly what a
  `functions`-restricted conduit's match (or violation reason) was
  computed from when it does.

### Addressing scope: what a zone can (and can't yet) be built from

Every zone in this file is a set of IPv4 CIDR blocks, full stop -- see
"Zones" above and `policy.hpp`'s own `CidrBlock`, a plain 32-bit
host-order integer plus prefix length. There is no IPv6 anywhere in this
tool (see `ipv4.hpp`'s own scope note), and no other layer-3 addressing
scheme of any kind. This section is an honest accounting of what that
means for the protocols `decode` recognizes but a zone can't classify by,
and for the protocols a conduit can't yet name at all -- worth reading
before assuming a conduit covers more than it actually does.

**The `protocols` enum is closed to six values**: `modbus`, `dnp3`,
`s7comm`, `iec104`, `enip`, `any` -- see "Validation errors" below.
`decode` recognizes considerably more than that (BACnet/IP, HART-IP, OPC
UA, MMS, MQTT, FOUNDATION Fieldbus HSE among them), but none of those can
be named in a conduit's `protocols`/`protocol` field -- the closest a
conduit gets to covering their traffic is `any`, which matches every
protocol indiscriminately and can't be scoped down to just one of them.
Concretely: there is no way today to write a conduit that says "only
HART-IP is allowed here" -- only "anything is allowed here" or, by
omission, "none of {modbus, dnp3, s7comm, iec104, enip} is allowed here"
(which becomes a Violation once both endpoints are zone-classified). This
is a straightforward enum-and-dispatch-table widening for the protocols
above, not a design limitation of the engine -- it simply hasn't been
done for them yet (see ROADMAP).

**`policy validate` only ever evaluates TCP flows** (see "`policy
validate`" above and LIMITATIONS) -- so even where a protocol's UDP
traffic is fully decoded by `decode` (BACnet/IP, HART-IP, CIP I/O, FF-HSE),
none of it reaches the policy engine at all yet, independent of the
`protocols`-enum question above. HART-IP's own TCP traffic is the one
partial exception: it's evaluated as a flow like any TCP-based protocol
here, but -- per the previous paragraph -- can currently only ever match
an `any` conduit, never a `protocol: hartip` one.

**For the four protocols with no IP layer at all** -- PROFINET RT, IEC
61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, and EtherCAT (see PROTOCOL
COVERAGE) -- a CIDR-based zone model doesn't apply, and isn't really the
right tool anyway: none of these four can leave the Ethernet segment/VLAN
they were transmitted on, by construction, since there's no IP header for
a router to act on. That's a physical/topological guarantee, not
something `policy validate` needs to verify the way it verifies an IP
conduit. The question worth asking about these four instead is whether
the traffic is on the segment/VLAN it's supposed to be on AT ALL (a
mis-patched switch port, an accidentally bridged VLAN) -- a
VLAN-membership check, not an IPv4-zone check, and not one this tool
implements yet, though the raw material already exists unused: every
packet's 802.1Q tag is decoded generically (`has_vlan_tag`/`vlan_id` in
`DecodedPacket`) regardless of protocol, it's just never consulted by
`PolicyEngine`. Two narrower asterisks worth knowing about: IEC 61850-90-5
defines routable variants of GOOSE and SV (R-GOOSE/R-SV, wrapped in UDP/IP
multicast) that CAN cross routers -- this decoder deliberately doesn't
recognize either (see `goose.hpp`/`sv.hpp`), so that traffic wouldn't even
be identified as GOOSE/SV today, let alone zone-classified. PROFINET has a
similar UDP/IP-routable class (`RT_CLASS_UDP`) this decoder's raw-Ethernet
decode path doesn't walk either (see `profinet.hpp`).

**Every protocol's own addressing, beyond plain IPv4 src/dst, and what
this tool does with it today:**

- **BACnet/IP's NPDU** carries a genuine internetwork addressing scheme
  of its own -- DNET/SNET (destination/source network numbers) and hop
  count, for routing across MS/TP-to-IP internetworks -- and it's fully
  decoded and exposed (`bacnet_npdu_dnet`/`bacnet_npdu_snet`/
  `bacnet_npdu_hop_count`), the closest thing this tool has to a working
  non-IP network-layer address. Not consulted by the zone engine (and
  moot for `policy validate` today regardless, since BACnet/IP is UDP --
  see above). Separately, I-Am's own device Object Identifier (the actual
  "which device is this" answer) is decoded into `bacnet_values` as a
  `device-object=...` string -- readable, but not a structured field a
  policy could reference.
- **DNP3's data-link header** carries its own 2-byte source/destination
  address (the outstation/master address) -- parsed internally
  (`Dnp3LinkFrame::source`/`destination` in `dnp3.hpp`) and now exposed to
  `DecodedPacket`/JSON output as `dnp3_source_address`/
  `dnp3_destination_address` (ROADMAP item 13, done): `decode`'s own
  output can now show which DNP3 address a frame was for, always set
  whenever `protocol == "dnp3"` (even a link-layer-only control frame with
  no user data still has a header carrying both addresses), mirroring the
  first data-link frame found in a TCP payload, same "first frame only"
  convention as `dnp3_link_crc_valid`/`dnp3_header_crc_valid`. Still NOT
  consulted by the zone engine, though: serial-to-IP DNP3 gateways
  routinely multiplex several outstations behind one IP address, so an
  IP-only zone model can under-identify the actual field device on a
  shared gateway in a way none of the other protocols here are exposed
  to -- a zone model keyed on this address (in addition to, or instead
  of, IP) remains open future work. See ROADMAP.
- **IEC 104's ASDU** carries a Common Address (station/sector address)
  and per-point Information Object Addresses, both decoded and exposed
  (`iec104_common_address`, IOAs inline in `iec104_object_values`). Not
  consulted by the zone engine.
- **EtherNet/IP's CIP Path** (class/instance/attribute) is an
  application-layer object address, not a network-layer one -- it still
  rides plain IPv4/TCP underneath. S7comm's TSAP (where Siemens packs
  rack/slot addressing) sits at the COTP/transport boundary, also above
  plain IPv4, but is shown only as raw hex (`calling_tsap_hex`/
  `called_tsap_hex`) -- rack/slot are never decoded out of it.
- **GOOSE/Sampled Values** use IEC 61850's own logical addressing --
  APPID (scopes a stream to a VLAN/segment) plus a GoCB reference or
  `svID` (the actual publisher identity) -- and **EtherCAT** uses ADP/ADO
  (station address + memory offset) to address one slave within a
  segment. Both are decoded and exposed; neither is IP-like, and neither
  reaches the zone engine, consistent with these four protocols having no
  IP layer at all (see above).

None of this changes what's Allowed/Violation/Unclassified today -- every
item above describes information `decode` already surfaces (or, for
DNP3's link address, doesn't yet) that `PolicyEngine` doesn't currently
use for zone classification. See ROADMAP for what's actually planned.

## PROTOCOL DETECTION

In `--protocol auto` (the default), every non-empty TCP payload is tested
against all eleven TCP-capable protocols, independent of port number. **OPC UA is tried
first of all, then EtherNet/IP, then IEC 104**, before Modbus/TCP, and
**HART-IP is tried third-to-last, MQTT second-to-last, with FF-HSE tried
last of all**, after S7comm/COTP, S7comm-Plus, and MMS -- see the notes at
the end of this section for why that specific ordering matters, not just
which protocols are tried:

- **OPC UA**: recognized by its 8-byte UA-TCP common header -- the leading 3
  bytes (MessageType) must be one of exactly 7 fixed ASCII strings (`HEL`,
  `ACK`, `ERR`, `RHE`, `OPN`, `CLO`, `MSG`), the 4th byte (ChunkType) must be
  `'F'`, `'C'`, or `'A'`, and the following 4-byte MessageSize field must be
  at least `8` (the header's own size). A 3-byte ASCII match against 7
  specific strings is a materially stronger structural signal than most of
  this codebase's own gates -- roughly a 1-in-16-million collision space per
  candidate offset before the ChunkType/MessageSize checks even apply -- and
  research checking it byte-by-byte against every other protocol's own
  leading-bytes gate here (Modbus's protocol-id==0, IEC 104's `0x68` start
  byte, TPKT's version==3 byte, DNP3's `0x05 0x64` sync bytes, EtherNet/IP's
  small enumerated command set) found no possible collision, so it costs
  nothing to try first and is the safest place for it -- the opposite
  ordering rationale from HART-IP's own weak-gate "tried last" placement
  below. Applied port-independently; TCP port 4840 is recorded as an
  "expected port" annotation only, the same posture every other protocol
  here uses for its own port. See PROTOCOL COVERAGE's OPC UA section for the
  service-layer decode this unlocks once the UA-TCP/SecureConversation
  framing is recognized.
- **EtherNet/IP**: recognized by its 24-byte encapsulation header -- the
  command field must be one of the nine standard encapsulation commands
  (`ListServices`, `ListIdentity`, `ListInterfaces`, `RegisterSession`,
  `UnRegisterSession`, `SendRRData`, `SendUnitData`, `IndicateStatus`,
  `Cancel` -- NOP, `0x0000`, is deliberately excluded, see below), the status
  field must be `0` or one of the seven documented encapsulation error codes,
  and the reserved `options` field must be exactly `0`. Three independent
  structural checks, on top of this protocol's own dedicated TCP port
  (44818, which none of the other four protocols here use) -- collectively a
  stronger signal than IEC 104's own checks (below), so it's tried first,
  though with its own dedicated port a collision with any of the others is
  not a realistic concern the way IEC-104-vs-Modbus was. NOP is excluded
  because its command value is all-zero bytes -- real-capture testing found
  this made a short run of zero-padded/malformed bytes on unrelated traffic
  (reassembled Modbus test fixture data, in that instance) misdetect as
  EtherNet/IP; see `tests/real_captures/enip/ATTRIBUTION.md` and
  `enip_command_name`'s comment in `src/enip.cpp`. For SendRRData/
  SendUnitData, the encapsulated Common Packet Format items are located and
  the CIP explicit message within is further decoded -- service code,
  request path, and, for the "first pass" set of services this groundwork
  release covers, the request/response data itself; see PROTOCOL COVERAGE
  below for exactly which services get full value decoding.
- **IEC 60870-5-104**: recognized by its APCI structure -- the start byte
  `0x68`, a length field in the plausible range `[4, 253]`, and the 4-byte
  control field matching one of the three frame formats' fixed bit patterns:
  I-format's N(R) low bit fixed 0, S-format's first two control bytes fixed
  `0x01 0x00` (with N(R)'s low bit fixed 0 too), or U-format's last three
  control bytes fixed all-zero (with the first byte matching one of the six
  STARTDT/STOPDT/TESTFR act/con function values, or noted as an unrecognized
  U-format function otherwise). Unlike DNP3 or S7comm, this isn't a single
  fixed magic-byte sequence, but the combination of the start byte with the
  control field's several independently-fixed bits is still a considerably
  stronger signal than Modbus/TCP's single protocol-id==0 tell -- see below.
- **Modbus/TCP**: recognized by its MBAP header shape -- the protocol-id
  field at byte offset 2-3 must be `0x0000` (mandated by the Modbus spec),
  *and* the function-code byte must be non-zero (function code `0x00` is
  reserved and never assigned by the spec). Unlike DNP3 or S7comm, Modbus/TCP
  has no magic bytes of its own, so protocol-id alone is a weaker signal than
  it looks -- a real capture surfaced non-Modbus traffic on port 20000 whose
  bytes coincidentally satisfied protocol-id==0, which the function-code
  check now catches (see LIMITATIONS). If matched, request-vs-response is
  then further disambiguated by PDU shape (a bare 4-byte address+quantity
  looks like a request; a byte-count-prefixed blob looks like a response).
  This shape-based classification is documented in the decoded output as a
  heuristic, and it always runs, unconditionally -- but it is no longer the
  last word: `Decoder::pair_modbus_transaction` (`decoder.cpp`) additionally
  tracks each MBAP transaction ID as an outstanding request per TCP session
  (both directions of one TCP 4-tuple), and when a later packet on that same
  session carries the same transaction ID from the *opposite* direction, it
  is authoritatively that request's response -- regardless of what the shape
  heuristic guessed. This is what resolves Write Single Coil/Register's
  inherent shape ambiguity (request and response are byte-for-byte identical
  per spec): transaction ID + direction doesn't need the shape to differ. A
  paired response gets an extra note naming the exact request packet it
  matches, plus `modbus_paired_request_index` in JSON output; an unpaired
  response (its request never seen on this session -- capture started
  mid-session, or a different session/transaction ID) is noted as an orphan
  instead of silently trusting the heuristic. See LIMITATIONS for exactly
  what this does and doesn't cover. This pairing is a separate thing from
  PDU/frame reassembly across TCP segments, which conduitscope also does --
  see LIMITATIONS' "General TCP stream reassembly" entry.
- **DNP3**: recognized by the data-link-layer start bytes `0x05 0x64`, which
  DNP3 always begins with.
- **S7comm/COTP**: recognized by the TPKT signature (`0x03 0x00` followed by
  a length field that plausibly fits the payload), which every TPKT/COTP
  frame begins with regardless of what it's carrying (S7comm, or bare COTP
  connection setup). If the COTP layer parses as a Data frame and its user
  data starts with the S7comm protocol id (`0x32`, or `0x72` for S7comm-Plus),
  it's reported as `s7comm`; otherwise, if the TPKT/COTP framing itself still
  parsed, it's reported as `cotp` (this is the normal case for COTP
  Connection Request/Confirm frames, which carry TSAP session-setup
  parameters rather than S7comm).
- **MMS (IEC 61850 Manufacturing Message Specification, ISO 9506)**: decoding
  is attempted under the exact same gate as S7comm/COTP above (`want_s7comm
  || want_mms` in `decoder.cpp`, the same TPKT/COTP framing, the same
  default TCP port 102) -- S7comm's own single-byte protocol-id gate
  (`0x32`/`0x72`) is tried first, since it is materially stronger and
  cheaper, and MMS is only attempted once that has already failed. MMS then
  layers its own, separate structural detection gate on top, recognizing
  three distinct shapes in the COTP Data frame's user data: (a) a full
  Session-layer SPDU whose leading SI byte is a plausible ISO 8327-1 SPDU
  type (`1`-`64`, `CLSES_UNIT_DATA(64)` being the highest one-byte type the
  standard defines -- deliberately not the looser `< 0x80` a first pass at
  this used, see PROTOCOL COVERAGE's MMS section for the real-capture-found
  collision that tightened it); (b) a "bare MMS" PDU -- the COTP Data
  frame's user data starts directly with an MMS PDU's own tag byte
  (CONTEXT-class, tag number 0-13: constructed `0xA0`-`0xAD` for 11 of the
  14 `MMSpdu` alternatives, or primitive `0x80`-`0x8D` for the remaining 3 --
  `cancel-RequestPDU`/`cancel-ResponsePDU` and `conclude-RequestPDU`/
  `conclude-ResponsePDU`, the only primitive ones); or (c) "bare
  Presentation" -- the Session layer is skipped entirely but Presentation-
  layer bytes (leading byte `0x31` CP-type/CPA-type, `0x61`
  fully-encoded-data, or `0x60` simply-encoded-data) are still present. If
  none of the three match, this decoder does not claim the traffic as MMS at
  all and falls through to the generic COTP/S7comm handling above. See
  PROTOCOL COVERAGE's MMS section for the full four-layer decode this gate
  unlocks.
- **HART-IP**: recognized by its 8-byte fixed header -- the MessageType byte
  must be one of 5 defined values (`0x00`-`0x03`, `0x0F`) *and* the MessageID
  byte must be one of 4 defined values (`0x00`-`0x03`), plus this decoder's
  own added plausibility check that the declared MsgLength field is at least
  8 (the header's own size). This is honestly the weakest structural gate of
  any protocol in this list -- two adjacent bytes each landing on one of a
  handful of small values, versus e.g. EtherNet/IP's three independent
  checks or IEC 104's multi-bit-pattern APCI -- and it is tried
  **second-to-last** in this chain, deliberately, precisely because of that
  weakness: see "Why HART-IP is tried last" below.
- **MQTT**: recognized by its one-byte fixed header (Control Packet Type in
  the top nibble, flags in the bottom nibble, which must be exactly one
  fixed value for every type except PUBLISH -- see PROTOCOL COVERAGE) plus a
  1-4-byte Variable Byte Integer Remaining Length. This was previously the
  **weakest** structural gate of any protocol in this list, so MQTT was
  tried dead last of all -- until FF-HSE's own gate (below) was found to be
  weaker still, so MQTT now sits second-to-last, after every protocol here
  except FF-HSE (including HART-IP) has declined a payload. CONNECT gets a
  much stronger, version-specific check on top (its own Protocol Name field
  must read literally `"MQTT"` or `"MQIsdp"`), but every other MQTT packet
  type relies on the weak one-byte gate alone. See PROTOCOL COVERAGE's MQTT
  section for the real, demonstrated collisions this weak gate caused
  against this project's own synthetic fixture (both found and fixed) and
  "Why MQTT is tried last" below.
- **FF-HSE**: recognized by a SINGLE byte at header offset 2
  (ProtocolAndType) -- its top 6 bits (`& 0xfc`) must land on one of 4
  valid protocol values and its bottom 2 bits (`& 0x03`) on one of 3 valid
  type values (12 valid byte values out of 256 possible), plus this
  decoder's own added plausibility check that the declared Message Length
  field is at least 12 (the header's own size) -- a check that all but the
  smallest 12 possible 32-bit values already satisfy. This is honestly the
  **weakest structural gate of any protocol in this codebase**, weaker even
  than MQTT's own one-byte-plus-Variable-Byte-Integer gate, so FF-HSE is
  dispatched dead **last** of all, on both TCP and UDP, after every other
  protocol here (including HART-IP and MQTT) has declined a payload. No
  specific byte-for-byte collision with another protocol was found during
  this feature's own scoping, but given how weak this gate is on its own,
  this ordering means any such collision resolves in every other protocol's
  favor, not FF-HSE's -- see `ffhse.hpp`'s own "Structural detection gate"
  paragraph and `decoder.cpp`'s own dispatch-order comment.

Because detection is payload-shape based, traffic running on a non-standard
port is still decoded correctly -- and conduitscope tells you it's on a
non-standard port, via a note in the output. That's not a false positive to
worry about; for conduit auditing it's arguably the *most* interesting signal
conduitscope can currently surface (an ICS protocol appearing somewhere your
segmentation policy didn't expect it).

**Why IEC 104 is tried before Modbus.** This was found while scoping IEC 104
support, before any real capture surfaced it in practice (unlike the DNP3
false-positive noted above, which a real capture did surface): an I-format
APDU with N(S)=N(R)=0 -- the very first data frame of essentially every real
IEC 104 session, since sequence numbers start at zero -- makes its APCI bytes
read as a plausible Modbus/TCP MBAP header purely by coincidence (protocol-id
byte-offset 2-3 reads as `0x0000`, and mbap_length reads as `0`), and the
ASDU's type-ID/VSQ bytes that follow can land exactly where Modbus expects
unit-id/function-code -- often with a non-zero "function code", so Modbus's
own reserved-function-code-0 guard (above) doesn't catch it either. Trying
IEC 104 first resolves this in IEC 104's favor, since its own structural
checks are a stronger signal, without needing to make Modbus's own detection
any stricter -- the same fix already applied once before for the DNP3-vs-
Modbus collision. `tests/sample_iec104_modbus_precedence.pcap` (see
`tools/make_sample_pcap.py`) is a minimal regression fixture pinning this
down.

**Why HART-IP is tried last, and the collision this does NOT resolve.**
Unlike IEC 104 above, this is a collision that was found while scoping
HART-IP support and deliberately left **unresolved**, not fixed by
reordering. A HART-IP Session Initiate message's own header (MessageID `0`,
Status `0` -- the only Status value ever observed in this decoder's own
research) makes its header bytes read as a plausible Modbus/TCP MBAP header
purely by coincidence: bytes 2-3 (Status, still `0x0000`) satisfy Modbus's
protocol-id==0 check, and bytes 4-5 (HART-IP's own TransactionID field) read
as a small, plausible Modbus `mbap_length`. This is the exact same *shape* of
collision already resolved once for IEC 104 above -- but trying HART-IP
first, the same way, was tried while scoping this feature and **measurably
regressed** this project's own existing Modbus/S7comm test corpus (roughly
2% of ordinary Modbus/TCP traffic with a non-zero unit ID also happened to
satisfy HART-IP's own two-byte gate, because that gate, unlike IEC 104's, is
genuinely weak -- see above). So this decoder accepts the collision rather
than resolving it: HART-IP is tried last, and a genuine HART-IP Session
Initiate message riding over TCP with Status `0` is misclassified as
Modbus/TCP (or COTP/S7comm, or left as generic `tcp`) instead. HART-IP over
UDP is entirely unaffected (UDP has no equivalent declared-length
pre-check to collide against), and every other HART-IP message type
(Keep Alive, Session Close, Pass Through) is also unaffected, since their
own MessageID values don't produce the protocol-id==0 collision. See
`include/conduitscope/hartip.hpp`'s "KNOWN, ACCEPTED, DOCUMENTED LIMITATION"
paragraph, the matching comments in `src/decoder.cpp`, and
`tests/sample_hartip.pcap`'s own dedicated demonstration packets (see
`tools/make_sample_pcap.py`) for the full writeup -- and
`tests/real_captures/hartip/ATTRIBUTION.md` for independent confirmation
this collision occurs on genuine field traffic, not just a hand-built
fixture.

**Why MQTT is tried last of all (of the protocols known at the time this
placement was chosen -- FF-HSE, added later, was found to have a still
weaker gate and now sits after it; see "Why FF-HSE is tried last of all"
below).** Dispatched even after HART-IP, for the
same reason as HART-IP's own placement, but for an even weaker gate: this
project's own synthetic MQTT fixture (`tests/sample_mqtt.pcap`) surfaced two
real, demonstrated collisions against earlier-dispatched protocols' gates
while it was being built, both found and fixed rather than left as
theoretical risk. First, a v5 CONNACK whose body (two zero bytes, then an
MQTT5 Properties block) coincidentally satisfied Modbus/TCP's own
protocol-id==0 tell with a large, plausible mbap_length -- caught because
`try_parse_modbus_tcp` (unlike `modbus_tcp_declared_length`, its sibling used
during TCP reassembly) didn't apply the same `kMaxPlausibleMbapLength` (300
bytes) sanity cap; fixed by applying that cap in both places (see
`src/modbus.cpp`). Second, a SUBSCRIBE/UNSUBSCRIBE packet identifier
(`>= 4096` after the fix, originally a small round number) happened to
satisfy HART-IP's own two-byte gate (a "plausible" MessageType/MessageID
pair), absorbing the packet into HART-IP's own TCP-reassembly buffering
instead of ever reaching MQTT -- resolved in the test fixture itself
(picking packet identifiers whose high byte exceeds HART-IP's own
MessageID<=3 check), not by weakening HART-IP's gate, consistent with how
this project has always preferred fixing the *specific* collision over
loosening an otherwise-sound check. Both are documented in
`tools/make_sample_pcap.py`'s own comments at the exact fixture packets that
exercise them. Unlike the IEC-104-vs-Modbus collision above, and like the
HART-IP-vs-Modbus collision, no attempt was made to make MQTT's own gate
stronger to avoid needing to be last -- CONNECT's Protocol Name check aside,
tightening every other MQTT packet type's one-byte gate further isn't
possible without contradicting the MQTT spec itself (the flags nibble really
is unconstrained for PUBLISH, by design).

**Why FF-HSE is tried last of all.** Dispatched even after MQTT, for the
same "weaker signal, lower priority" principle already established for
HART-IP and MQTT above, but with the weakest gate of the three: a SINGLE
byte at header offset 2 (ProtocolAndType) landing on one of 12 valid values
out of 256, plus a Message Length plausibility check that all but the
smallest 12 possible 32-bit values already satisfy -- honestly weaker than
even MQTT's own one-byte-fixed-header-plus-Variable-Byte-Integer-Length
gate, since MQTT's Remaining Length field is itself a meaningful structural
constraint FF-HSE's Message Length check barely is. Unlike the HART-IP-vs-
Modbus and MQTT-vs-{Modbus,HART-IP} collisions above, no specific
byte-for-byte collision against another protocol's own gate was found
during this feature's own scoping -- but that is a narrower claim than "no
collision exists": given how weak this gate is in isolation (roughly a
1-in-21 chance of a random byte at offset 2 alone satisfying it, before the
Message Length check even applies), this decoder does not claim collision-
freedom the way OPC UA or EtherNet/IP's own multi-check gates can. FF-HSE
being dispatched dead last means any such collision, discovered later,
would resolve in every other protocol's favor by default, consistent with
this codebase's established ordering philosophy. This gate applies
identically on UDP (see below) -- unlike the HART-IP-vs-Modbus collision,
which is TCP-only (it depends on Modbus's own declared-length TCP
reassembly pre-check, which has no UDP equivalent), FF-HSE's own weak gate
has no such transport asymmetry, since FF-HSE itself defines no declared-
length pre-check any other protocol here could collide against on UDP
either. See `include/conduitscope/ffhse.hpp`'s own "Structural detection
gate" paragraph and `src/decoder.cpp`'s own dispatch-order comment for the
full detail.

`--protocol modbus`, `--protocol dnp3`, `--protocol s7comm`, `--protocol
mms`, `--protocol mqtt`, `--protocol iec104`, `--protocol enip`,
`--protocol profinet`, `--protocol goose`, `--protocol sv`, `--protocol
ethercat`, `--protocol bacnet`, `--protocol hartip`, `--protocol opcua`,
`--protocol s7comm-plus`, or `--protocol ff-hse`
restrict decoding to only that protocol (useful for large mixed captures, or
for scripting a two-pass analysis). `--protocol enip` covers both EtherNet/IP explicit
messaging (TCP, above) and CIP I/O implicit messaging (UDP, below) --
they're the same overall protocol family. `--protocol mms` restricts to MMS
specifically, distinct from `--protocol s7comm` even though both share the
same TPKT/COTP transport and port. `--protocol hartip` covers both HART-IP
over TCP (above) and over UDP (below) -- HART-IP uses the identical wire
format on either transport. `--protocol opcua` is TCP only -- OPC UA has no
UDP mapping. `--protocol ff-hse` covers all four FF-HSE sub-protocols
(FDA/SM/FMS/LAN Redundancy) on both TCP and UDP (below) -- like HART-IP,
FF-HSE uses the identical wire format on either transport.

**CIP I/O (implicit messaging), UDP port 2222** is tried, port-independently,
against every non-empty UDP payload, the same "opportunistic, payload-shape"
philosophy as the five TCP protocols above: the very first Common Packet
Format item must be a Sequenced Address Item -- type code exactly `0x8002`
*and* declared length exactly `8` bytes (the fixed size ODVA mandates: a
4-byte connection ID plus a 4-byte sequence number). Two independently-fixed
16-bit fields is the same structural-confidence philosophy EtherNet/IP's own
TCP detection and IEC 104's APCI checks already use -- strong enough that a
false-positive match against unrelated UDP traffic is not a realistic
concern, even without a dedicated-port requirement. See PROTOCOL COVERAGE's
EtherNet/IP section for what is and isn't decoded once that anchor matches.

**PROFINET RT, EtherType `0x8892`** is tried, port-independently (there is no
port at all -- this rides directly on raw Ethernet, no IPv4/TCP/UDP layer),
against every non-IPv4 Ethernet frame with that EtherType: the 2-byte
FrameID immediately after the EtherType must fall into one of the named
ranges/values PROTOCOL COVERAGE's PROFINET RT section documents. Unlike
every UDP/TCP-based protocol above, this EtherType has zero collision risk
with any other protocol this tool decodes, so the FrameID check is this
decoder's only structural gate -- but it's still applied rather than
accepting every `0x8892` frame unconditionally: a frame in a genuinely
reserved/unrecognized FrameID range falls back to the generic `non-ip`
ethertype-name-only report, same as before this feature existed.

**IEC 61850-8-1 GOOSE, EtherType `0x88B8`** is tried the same way, port-
independently against every non-IPv4 Ethernet frame with that EtherType:
the 8-byte header's declared Length must be plausible (at least the 8-byte
header itself) and the outer ASN.1 BER APDU tag immediately after the
header must be one of the two named APPLICATION-class tags this protocol
actually uses (`0x61` goosePdu, `0xA0` gseMngtPdu -- see PROTOCOL COVERAGE's
GOOSE section). As with PROFINET RT, this EtherType has zero collision risk
with any other protocol here, so that tag check is the only structural gate;
a frame whose outer tag doesn't match either value falls back to the generic
`non-ip` report. Once the tag matches, header/APDU length mismatches against
the bytes actually available are handled tolerantly -- clamped to what's
present, with a note -- rather than rejected outright, on the theory that a
matched outer tag is already strong enough evidence this is a truncated
capture of real GOOSE traffic, not a false positive (see LIMITATIONS).

**IEC 61850-9-2 Sampled Values, EtherType `0x88BA`** is tried the same way,
port-independently against every non-IPv4 Ethernet frame with that
EtherType: the 8-byte header's declared Length must be plausible (at least
the 8-byte header itself) and the outer ASN.1 BER APDU tag immediately after
the header must be `0x60` (`savPdu`) -- SV's `SampledValues` CHOICE has only
this one alternative, unlike GOOSE's two, so there is exactly one tag to
check (see PROTOCOL COVERAGE's Sampled Values section). As with PROFINET RT
and GOOSE, this EtherType has zero collision risk with any other protocol
here, so that single tag check is the only structural gate; a frame whose
outer tag isn't `0x60` falls back to the generic `non-ip` report. Once the
tag matches, header/APDU length mismatches against the bytes actually
available are handled tolerantly -- clamped to what's present, with a note --
the same as GOOSE.

**EtherCAT, EtherType `0x88A4`** is tried the same way, port-independently
against every non-IPv4 Ethernet frame with that EtherType: the 2-byte frame
header's Type field (bits 12-15) must be one of the five values the spec
defines (1-5 -- see PROTOCOL COVERAGE's EtherCAT section). Unlike PROFINET
RT/GOOSE/SV's own structural gates, this one is honestly weaker: 4 bits admit
16 possible values, of which 5 are spec-defined, a 5-in-16 chance of a
coincidental match against unrelated traffic, versus GOOSE/SV's 1-in-256
outer BER tag or PROFINET's own multi-value FrameID range table. The
EtherType itself remains the primary confidence source -- it has zero
collision risk with any other protocol this tool decodes, the same as
PROFINET RT/GOOSE/SV's own EtherTypes -- and a frame whose Type value isn't
one of the five falls back to the generic `non-ip` report, same as the other
raw-Ethernet protocols here. Once the Type matches and is 1 ("EtherCAT
command"), the frame header's declared Length field is used to bound the
datagram-chain scan (clamped tolerantly to the bytes actually available,
with a note, when implausible) rather than walking every byte physically
present in the frame -- see PROTOCOL COVERAGE's EtherCAT section for why.

**Spanning Tree Protocol (STP/RSTP/MSTP)** is tried against classic IEEE
802.3 length-framed Ethernet frames whose 3-byte LLC header has DSAP ==
SSAP == `0x42` (the Bridge Group Address SAP) and Control == `0x03`
("Unnumbered Information") -- structurally, this dispatch path is entirely
SEPARATE from the EtherType-keyed dispatch chain every protocol above (and
Modbus/DNP3/etc. below) is tried through: a length-framed frame's 16-bit
"ethertype" field is by IEEE 802.3's own definition always `< 0x0600`, so it
can never equal PROFINET RT's `0x8892`, GOOSE's `0x88B8`, Sampled Values'
`0x88BA`, EtherCAT's `0x88A4`, or IPv4's `0x0800` -- there is no ordering or
collision question between STP and any EtherType-keyed protocol here, the
same way there is none between two different EtherTypes. Once that LLC
shape matches, the structural gate is: the BPDU body's Protocol Identifier
`== 0x0000` AND BPDU Type in `{0x00, 0x02, 0x80}` AND, for BPDU Types
`0x00`/`0x02` only (a TCN's own version byte is never checked), Protocol
Version Identifier in `{0, 2, 3, 4}`. This is a considerably STRONGER
structural anchor than several other protocols' gates in this list --
several independent small-valid-domain fields (a fixed 2-byte Protocol
Identifier, a 3-value BPDU Type enum, and, for two of those three types, a
4-value Protocol Version Identifier enum) must all co-occur, the same
"multiple independent fields, not one loose length check" strength class as
OPC UA's own 3-byte ASCII magic-string gate -- and notably stronger than
HART-IP's, FF-HSE's, or EtherCAT's own honestly-weaker gates (above). One
address DOES gate detection here, the sole such case in this codebase: DSAP/
SSAP `0x42` is not exclusive to STP -- GARP (GVRP/GMRP) registers on the
identical LLC SAP pair, and is disambiguated purely by destination MAC
(`01:80:C2:00:00:0D` and `01:80:C2:00:00:20`-`0x2F`), checked BEFORE the BPDU
body is even opened, matching Wireshark's own `dissect_bpdu` exactly -- see
PROTOCOL COVERAGE's Spanning Tree Protocol section for why this one case
needed an address check when every other detector in this codebase prefers
a structural one. See that same section for the full wire format, what's
decoded vs. named-only (Cisco PVST+, SPB, GARP), and the real-capture
validation.

**BACnet/IP, UDP port 47808/0xBAC0 (ASHRAE 135 Annex J)** is tried,
port-independently, against every non-empty UDP payload -- the same
"opportunistic, payload-shape" philosophy CIP I/O above uses, since BACnet/IP
rides over UDP rather than a dedicated EtherType the way PROFINET RT/GOOSE/
SV/EtherCAT do: the BVLC (BACnet Virtual Link Layer) header's Type byte must
be exactly `0x81` (the Annex J value; `0x82` is BACnet Secure Connect, a
different, unrelated protocol this decoder does not attempt) *and* its
Function byte must be one of the 13 values the spec defines (`0x00`-`0x0C`).
Two independently-fixed byte values is the same structural-confidence
philosophy CIP I/O's own Sequenced Address Item check uses; a UDP payload
that doesn't match either check falls back to the generic `udp` report,
regardless of port. `--bacnet-port` only changes whether a decoded frame is
annotated as appearing on an unexpected port (default 47808), the same as
every other per-protocol port option -- it never gates detection. Once the
gate matches, the BVLC header's own declared Length field is checked
tolerantly against the bytes actually available (clamped, with a note, on a
mismatch) rather than rejected outright, the same tolerant-declared-length
posture GOOSE/SV/EtherCAT already take. See PROTOCOL COVERAGE's BACnet/IP
section for exactly what's decoded once the gate matches.

**HART-IP, UDP/TCP port 5094** is tried, port-independently, against every
non-empty UDP payload too, using the same 8-byte-header gate described above
for TCP (MessageType/MessageID/MsgLength) -- HART-IP and FF-HSE (below) are
the only two protocols in this list that opportunistically check both
transports with the identical wire format. Unlike the TCP chain, HART-IP is
tried on UDP payloads alongside CIP I/O and BACnet/IP with no ordering
concern: the Modbus/TCP collision described above is a TCP-only artifact (it
depends on Modbus's own declared-length TCP reassembly pre-check, which has
no UDP equivalent), so HART-IP over UDP is checked and decoded exactly like
any other well-behaved protocol here, with no known collision. `--hartip-port`
only changes whether a decoded frame is annotated as appearing on an
unexpected port (default 5094), the same as every other per-protocol port
option -- it never gates detection. See PROTOCOL COVERAGE's HART-IP section
for exactly what's decoded once the gate matches.

**FF-HSE, ports 1089/1090/1091/3622** is tried, port-independently, against
every non-empty UDP payload too, using the same single-byte-at-offset-2 gate
described above for TCP -- but, unlike HART-IP's own UDP placement, FF-HSE
IS tried last among the UDP protocols here (after CIP I/O and BACnet/IP,
and after HART-IP), the same "weakest gate, lowest priority" placement it
gets on the TCP chain, since this gate's own weakness (see "Why FF-HSE is
tried last of all" above) is a property of the gate itself, not of which
transport it's being checked against. A single UDP datagram can (and,
per the reference dissector's own comments about coalesced diagnostic/
status traffic, sometimes does) carry more than one concatenated FF-HSE PDU
back-to-back; this is walked in a loop, the same coalescing pattern this
codebase already uses for EtherNet/IP's and HART-IP's own coalesced UDP
messages -- see `ffhse.hpp`'s own "UDP framing" paragraph. `--ffhse-port`
only changes whether a decoded frame is annotated as appearing on an
unexpected port (default 1089/1090/1091/3622), the same as every other
per-protocol port option -- it never gates detection. See PROTOCOL
COVERAGE's FOUNDATION Fieldbus HSE section for exactly what's decoded once
the gate matches.

**DeviceNet** is detected completely differently from every protocol above:
not by a structural gate applied to a TCP/UDP payload or an EtherType, but
by the pcap capture's own declared link type. Before any Ethernet parsing is
even attempted, `Decoder::decode` checks whether the capture's link type is
`LINKTYPE_CAN_SOCKETCAN` (227); if it is, every packet is parsed as a
SocketCAN capture record (`parse_socketcan_frame`, see
`can_socketcan.hpp`) and handed to `try_parse_devicenet`, a wholly separate
top-level branch that never calls `parse_ethernet` at all -- there is no
ordering or collision question with any other protocol in this list, the
same way there's none between two different EtherTypes, because DeviceNet
isn't reached through the EtherType-keyed dispatch chain in the first
place. Within that branch, the only rejection is structural and absolute: a
CAN frame with its EFF (extended 29-bit ID), RTR (remote transmission
request), or ERR (error frame) bit set is not a valid DeviceNet frame shape
at all and is reported as `non-ip` (named by which flag is set), mirroring
Wireshark's own `dissect_devicenet`'s literal first check. Every other
standard-11-bit-ID CAN frame on this link type is accepted as `devicenet`
and message-group-classified by its CAN ID -- see PROTOCOL COVERAGE's
DeviceNet section for the full classification. `--protocol devicenet`
restricts decoding to it the same way every other `--protocol` value does,
but since the link-type check runs first regardless of `--protocol`, it has
no effect at all on an ordinary Ethernet-linktype capture (nothing on such a
capture is ever a SocketCAN record to begin with).

## OUTPUT FORMATS

### text (default)

One line per packet: index, timestamp, source and destination `ip:port`,
`[protocol]`, and a summary. Any additional notes (heuristic explanations,
port-mismatch warnings, malformed-field warnings) are printed indented below
the packet line, followed, for an Ethernet-linktype packet, by an `eth`
line showing the raw source/destination MAC addresses.

```
#1  1700000000.000000  192.168.1.50:51000 -> 192.168.1.10:502  [modbus]  Read Holding Registers: request: read 10 holding register(s) starting at address 0
        note: classified as a request because the PDU is exactly 4 bytes (address+quantity); this is a heuristic, not stream tracking
        eth aa:bb:cc:11:22:33 -> aa:bb:cc:44:55:66
```

When name resolution is enabled (see "Name resolution" below), a hostname
and/or a service name are appended in parentheses right after the raw IP or
port they annotate, and a MAC vendor right after each `eth` line's address --
the raw value itself is always shown too, never replaced:

```
#1  1700000000.000000  192.168.1.50 (hmi-01):51000 (hmi-modbus-client) -> 192.168.1.10 (plc-01):502 (custom-modbus)  [modbus]  Read Holding Registers: request: read 10 holding register(s) starting at address 0
        eth aa:bb:cc:11:22:33 (Example Vendor, Inc.) -> aa:bb:cc:44:55:66 (Another Vendor Corp.)
```

#### Color

The `[protocol]` tag is colored per protocol (so a mixed-protocol capture
scans quickly by eye): cyan for Modbus, magenta for DNP3, blue for S7comm and
COTP-without-S7comm, green for IEC 104, yellow for EtherNet/IP, bright cyan
for PROFINET RT, bright green for GOOSE, bright magenta for Sampled Values,
bright yellow for EtherCAT, bright blue for BACnet/IP, bright white for
HART-IP, dim for everything else recognized
but not OT-specific (`tcp`/`udp`/`non-tcp`/`non-ip`/`unsupported-link`). A Modbus
exception response's summary, and a `parse-error` packet's entire line, are
bold red -- both mean "look at this one" over everything else in a long
decode. Notes are printed dim.

Color is used only when actually writing to an interactive terminal by
default (never into a file via `-o`, and never when piped, e.g. into `less`
or `jq` -- so ANSI escapes don't end up littering saved or scripted output
unasked). `--color` forces it on regardless of the destination (e.g. to
pipe into a pager that understands color, like `less -R`); `--no-color`
forces it off. The two are mutually exclusive. None of this applies to
`json`/`csv` output, or to `policy validate`'s text report, which stays
plain text.

### json

A JSON array, one object per packet, with fields `index`, `timestamp`,
`captured_len`, `original_len`, `src_mac`, `dst_mac`, `src_ip`, `dst_ip`,
`src_port`, `dst_port`, `tcp_flags`, `protocol`, `summary`, and `notes` (an
array of strings). Fields that don't apply to a given packet (e.g. `src_ip`
for a non-IP frame, or `src_mac`/`dst_mac` for a non-Ethernet-linktype
capture) are `null`. Intended to be piped into `jq` or read by a future
policy-evaluation layer.

Over a hundred fields are only present (omitted entirely, not `null`) on
packets where they apply:

- `src_mac_vendor` / `dst_mac_vendor`: the OUI (MAC vendor) name for
  `src_mac`/`dst_mac`, from the built-in OUI table (`--no-oui` disables this
  lookup). Present only when `has_ethernet` and the lookup found a match --
  see OUTPUT FORMATS' "Name resolution" subsection below.
- `src_hostname` / `dst_hostname`: the hostname for `src_ip`/`dst_ip`, from
  an explicitly-supplied `--hosts` file (`--resolve` enables this lookup;
  never live DNS). Present only when the lookup is enabled, a `--hosts` file
  was supplied, and it has a matching entry.
- `src_port_service` / `dst_port_service`: the service name for
  `src_port`/`dst_port` and the packet's transport (TCP or UDP), from the
  built-in port->service-name table plus, if given, `--services`. Present
  only when service-name resolution is enabled (`--nn` disables it) and a
  matching entry exists.
- `modbus_paired_request_index`: the `index` of the specific earlier request
  packet this response was authoritatively paired to (by MBAP transaction ID
  + TCP session, not the payload-shape heuristic), when protocol is `modbus`
  and that pairing succeeded -- see PROTOCOL DETECTION.
- `s7comm_function`: the S7comm function name (`"Read Var"`, `"Write Var"`,
  `"Setup Communication"`, ...), when protocol is `s7comm` and a function
  code was decoded.
- `s7comm_items`: an array of Step 7-style item tags (`"DB10.DBW100"`,
  `"I0.0"`, ...), on Read Var / Write Var *request* packets whose item
  addressing was decoded (see PROTOCOL COVERAGE). A tag from the
  EXPERIMENTAL `0xB2` decode has `" [EXPERIMENTAL]"` appended to it (e.g.
  `"M2.0 [EXPERIMENTAL]"`) -- check for that suffix before treating an
  entry as a confirmed address.
- `s7comm_values`: an array of short value renderings (a hex string, `"0"`/
  `"1"` for a decoded bit, or a return-code name like `"Object does not
  exist"`), on Read Var / Write Var *response* packets, and alongside
  `s7comm_items` on Write Var request packets (the values being written).
- `s7comm_plc_stop_message`: the PLC Stop (function `0x29`) request's
  confirmation string (in real traffic, literally `"PLC_STOP"`), on a Job
  (request) packet whose message was decoded. Never set on a response
  packet -- see PROTOCOL COVERAGE.
- `s7comm_pi_service_name` / `s7comm_pi_service_description`: the PLC
  Control (function `0x28`) request's PI service name (e.g. `"_INSE"`,
  `"P_PROGRAM"`, or one of the `_N_*` Sinumerik/CNC names) and, when that
  name is in the known table, its looked-up description (e.g. `"Activates a
  PLC module"`). `s7comm_pi_service_description` is omitted, not `null`,
  when the name isn't in the table -- see PROTOCOL COVERAGE for exactly
  which names that covers.
- `s7comm_pi_control_argument`: `P_PROGRAM`/`_MODU`/`_GARB` only -- the PI
  service's raw ASCII argument string, decoded as-is with no semantic
  interpretation attached (see PROTOCOL COVERAGE for why).
- `s7comm_pi_control_blocks`: `_INSE`/`_INS2`/`_DELE` only -- an array of
  one `"<type><number> (<destination>)"` entry per block descriptor in the
  parameter block, e.g. `"DB100 (Passive)"`, `"FC5 (Active)"`.
- `s7comm_pi_control_has_more_data` / `s7comm_pi_control_has_error`: PLC
  Control Ack_Data (response) packets only -- the two documented
  status-flag bits, present when the response's parameter block was long
  enough to carry them.
- `dnp3_source_address` / `dnp3_destination_address`: the data-link
  header's own 16-bit DNP3 station addresses (`Dnp3LinkFrame::source`/
  `destination` in `dnp3.hpp`) -- NOT IP addresses; the actual outstation/
  master identity, set whenever protocol is `dnp3` (same "needs no
  application-layer decode" scope as the CRC fields above -- even a
  link-layer-only control frame with no user data still has a header
  carrying both addresses). Mirrors the *first* data-link frame found in
  this TCP payload, same "first frame only" convention as the CRC fields
  below; reliability tracks `dnp3_header_crc_valid` -- a bad header CRC
  means these two values cannot be trusted either. This is the field a
  serial-to-IP DNP3 gateway multiplexing several outstations behind one
  shared IP needs to actually tell them apart -- see POLICY FILE FORMAT's
  "Addressing scope" section for why an IP-only zone model can't do that
  on its own, and ROADMAP for the (still open) idea of a zone model keyed
  on this address.
- `dnp3_link_crc_valid` / `dnp3_header_crc_valid` / `dnp3_block_count` /
  `dnp3_block_crc_failures`: data-link CRC-16 validation results, set
  whenever protocol is `dnp3` (unlike `dnp3_function` below, these need no
  application-layer decode -- even a link-layer-only control frame with no
  user data has a header CRC to check). `dnp3_header_crc_valid` is the
  8-byte header CRC alone; `dnp3_block_count`/`dnp3_block_crc_failures` are
  how many <=16-byte user-data blocks this frame had and how many of those
  failed their own CRC; `dnp3_link_crc_valid` is true only when the header
  AND every block validated. All four mirror the *first* data-link frame
  found in this TCP payload, same "first frame only" convention as
  `dnp3_function` below -- an additional coalesced frame's own CRC mismatch
  (if any) still gets a `notes` entry. See PROTOCOL COVERAGE's DNP3
  "Data-link CRC-16 validation" section for the exact semantics and the
  `notes` text a mismatch produces.
- `dnp3_function`: the DNP3 function name (`"Read"`, `"Response"`, ...), when
  protocol is `dnp3` and this fragment's application layer was decoded (see
  PROTOCOL COVERAGE for when that is -- a fragment split across multiple
  data-link frames only gets its transport header decoded, not this).
- `dnp3_objects`: an array of one entry per object header decoded in the
  fragment, e.g. `"g1v2 (Binary Input)"`.
- `dnp3_values`: an array of one entry per decoded point value across every
  object header in the fragment, e.g. `"g1v2 idx=0: 1 [ONLINE]"` or
  `"g12v1 idx=7: code=Latch On tc=Close queue/clear=0x00 count=1
  on_time=1000ms off_time=0ms status=Success"` for a CROB command. Empty for
  an object header outside the point-format table (see PROTOCOL COVERAGE).
- `iec104_asdu_type`: the ASDU type name (e.g. `"C_IC_NA_1 (Interrogation
  command)"`), when protocol is `iec104` and the first APDU found in this
  TCP payload was an I-format APDU with a decoded ASDU (see PROTOCOL
  COVERAGE).
- `iec104_cot`: the cause-of-transmission name (e.g. `"activation"`,
  `"spontaneous"`, `"interrogated by group 1 interrogation"`), alongside
  `iec104_asdu_type`.
- `iec104_common_address`: the ASDU's Common (station) Address, alongside
  `iec104_asdu_type`.
- `iec104_objects`: an array of one entry per decoded information object
  across every ASDU found in the TCP payload (an APDU is small, so several
  commonly coalesce into one TCP segment -- see PROTOCOL COVERAGE), e.g.
  `"ioa=100: ON"` or `"ioa=200: 16384 (0.5000) @ 2024-03-15
  10:30:00.500"` for a time-tagged measured value. Empty for an ASDU type
  outside the decoded-type table (see PROTOCOL COVERAGE).
- `enip_command`: the EtherNet/IP encapsulation command name (e.g.
  `"RegisterSession"`, `"SendRRData"`), when protocol is `enip` AND this is
  an explicit-messaging (TCP) packet. Reflects only the *first* EtherNet/IP
  message found in this TCP payload -- see `notes` for any additional
  coalesced messages (PROTOCOL COVERAGE). Absent for a CIP I/O (implicit
  messaging, UDP) packet -- there is no encapsulation command on that wire
  at all; see `enip_io_connection_id` below instead.
- `enip_cip_is_response`: `true`/`false`, when a CIP explicit message was
  located inside that first EtherNet/IP message (a `SendRRData`/
  `SendUnitData` carrying one).
- `enip_cip_service`: the CIP service name (e.g. `"Read_Tag"`,
  `"Multiple_Service_Packet"`, `"Unknown (0x4C)"` when the service code
  isn't recognized in this request's context), alongside
  `enip_cip_is_response`.
- `enip_cip_path`: the CIP request path summary (e.g. `"Pump1_Speed"` for a
  symbolically-addressed tag, or `"Class=0x01 (Identity) Instance=1"`),
  present on a *request* whose path was decoded and non-empty. Absent on a
  response (a CIP response never repeats the request's path on the wire).
- `enip_cip_status`: the CIP general status name (e.g. `"Success"`,
  `"Object does not exist"`), present on a decoded response.
- `enip_cip_values`: an array of one entry per decoded request/response
  value or Multiple_Service_Packet/Unconnected_Send member summary, e.g.
  `["type=DINT", "42"]` for a Read_Tag response, or `["member 0: Read_Tag
  response: Success"]` for one member of a Multiple_Service_Packet reply.
  See PROTOCOL COVERAGE for exactly which services get full value decoding
  versus a structural-only summary.
- `enip_io_connection_id`: the CIP I/O (implicit messaging) datagram's
  connection ID, as a hex string (e.g. `"0xABCD1234"`), when protocol is
  `enip` and this is a UDP/2222 implicit-messaging packet (see PROTOCOL
  COVERAGE's CIP I/O subsection).
- `enip_io_sequence_number`: the same datagram's rolling sequence number, as
  a plain integer, alongside `enip_io_connection_id`.
- `enip_io_data_length`: the Connected Data Item's byte length, when one was
  present in the datagram (a CIP I/O datagram carrying only a Sequenced
  Address Item and no data segment has neither this nor `enip_io_data_hex`).
- `enip_io_data_hex`: the Connected Data Item's contents as lowercase hex,
  with no separator (e.g. `"deadbeef"`) -- **never value-decoded**, see
  PROTOCOL COVERAGE and LIMITATIONS for why.
- `profinet_frame_id`: the PROFINET RT FrameID, as a 4-hex-digit hex string
  (e.g. `"0xFEFF"`), when protocol is `profinet`. Always present alongside
  `profinet_frame_id_name`.
- `profinet_frame_id_name`: a human-readable name for that FrameID (e.g.
  `"DCP Identify Response"`, `"Cyclic RT IO data (RT_CLASS_1, unicast)"`,
  `"Alarm High"`), alongside `profinet_frame_id`.
- `profinet_dcp_service`: the DCP service name (`"Hello"`/`"Get"`/`"Set"`/
  `"Identify"`), when the FrameID is one of the four DCP FrameIDs.
- `profinet_dcp_service_type`: the DCP service type name (`"Request"`/
  `"Response-Success"`/`"Response-not-supported"`), alongside
  `profinet_dcp_service`.
- `profinet_dcp_blocks`: an array of one entry per decoded DCP block, e.g.
  `"NameOfStation=plc-01"` or `"IPParameter=ip=192.168.1.10
  subnet=255.255.255.0 gateway=192.168.1.1"` for a value-decoded block, or
  `"option=2 suboption=5=<hex>"` for one this decoder doesn't value-decode
  (see PROTOCOL COVERAGE). Capped at 50 entries, same reason as
  `enip_cip_values`.
- `profinet_cyclic_io_data_length`: the cyclic RT IO data's byte length, when
  the FrameID falls in a cyclic RT range (see PROTOCOL COVERAGE).
- `profinet_cyclic_io_data_hex`: the IO data's contents as lowercase hex,
  with no separator -- **never value-decoded**, same reasoning as
  `enip_io_data_hex`.
- `profinet_cyclic_cycle_counter`: the trailer's CycleCounter value, alongside
  `profinet_cyclic_io_data_length`.
- `profinet_cyclic_data_status`: the trailer's DataStatus bits rendered as a
  comma-separated list of named states (e.g. `"Primary,Valid,Run,Ok"`).
- `profinet_cyclic_transfer_status`: the trailer's raw TransferStatus byte as
  a plain integer (`0` = OK, nonzero = ignore this frame's data).
- `goose_appid`: the GOOSE header's APPID, as a 4-hex-digit hex string (e.g.
  `"0x2000"`), when protocol is `goose`. Always present alongside
  `goose_is_gse_management`.
- `goose_is_gse_management`: `true`/`false` -- `true` when the outer APDU tag
  was `0xA0` (GSE Management PDU, named only, not decoded further -- see
  PROTOCOL COVERAGE), `false` for a fully-decoded `0x61` goosePdu. The
  `goose_*` PDU-content fields below are only present when this is `false`
  and a PDU was actually decoded.
- `goose_simulated`: `true`/`false`, present when the PDU content was
  decoded. `true` if either the header's S-bit (Reserved1's top bit) or the
  PDU's own OPTIONAL `simulation` field is set -- a mismatch between the two
  is called out in `notes` (see PROTOCOL COVERAGE).
- `goose_gocb_ref`: the `gocbRef` VisibleString (e.g.
  `"IED4/LLN0$GO$gcb13"`) -- the GOOSE Control Block reference identifying
  the publisher.
- `goose_dat_set`: the `datSet` VisibleString identifying the dataset this
  GOOSE message publishes.
- `goose_go_id`: the OPTIONAL `goID` VisibleString, when present in the PDU.
- `goose_st_num`: the `stNum` (State Number) counter, as a plain integer --
  increments only on a genuine state change; a value that jumps or resets
  outside a publisher restart is a spoofing/replay signal (see PROTOCOL
  COVERAGE).
- `goose_sq_num`: the `sqNum` (Sequence Number) counter, as a plain integer
  -- increments on every retransmission at the current `stNum`, resets to 0
  on the next state change.
- `goose_conf_rev`: the `confRev` (Configuration Revision) counter, as a
  plain integer -- changes only when an engineering tool has touched this
  IED's GOOSE Control Block configuration.
- `goose_num_dat_set_entries`: the PDU's declared `numDatSetEntries`, as a
  plain integer. A mismatch against the actual number of top-level `allData`
  entries decoded is called out in `notes`.
- `goose_all_data`: an array of one entry per top-level `allData` value
  decoded, each a `"path: type=value"` string, e.g. `"0: boolean=true"` or
  `"1: bit-string=13-bit 0b0000000000001"`. A nested `array`/`structure`
  entry's own `value` reads `"(N flattened value(s) follow)"`, with its
  children appearing as subsequent entries under dotted index paths (e.g.
  `"2.0: boolean=false"`) -- see PROTOCOL COVERAGE. Capped at 50 entries,
  same reason as `enip_cip_values`.
- `sv_appid`: the Sampled Values header's APPID, as a 4-hex-digit hex string
  (e.g. `"0x4000"`), when protocol is `sv`. Always present alongside
  `sv_simulated`, `sv_no_asdu`, and `sv_asdu_count`.
- `sv_simulated`: `true`/`false` -- `true` when the shared header's Reserved1
  S-bit is set, marking test/simulated traffic (identical bit to GOOSE's).
- `sv_no_asdu`: the SavPdu's declared `noASDU` count, as a plain integer. A
  mismatch against the number of ASDU elements actually found in `seqASDU`
  is called out in `notes`.
- `sv_asdu_count`: the number of ASDU elements actually decoded from
  `seqASDU` -- unlike GOOSE (which decodes only the first APDU's content),
  every ASDU in the sequence is decoded, since multiple ASDUs per SavPdu is
  core, spec-defined behavior. The `sv_id`/`sv_dat_set`/... fields below
  describe only the *first* ASDU; see `sv_asdus` for a summary of all of
  them.
- `sv_id`: the first ASDU's `svID` VisibleString (e.g. `"IED1/MSVCB01"`) --
  the Sampled Value Control Block reference identifying the publisher.
  Present when `sv_asdu_count` is greater than 0.
- `sv_dat_set`: the first ASDU's OPTIONAL `datSet` VisibleString, when
  present in the PDU.
- `sv_smp_cnt`: the first ASDU's `smpCnt` (Sample Count) counter, as a plain
  integer -- the primary stream-integrity/replay-detection signal, analogous
  to GOOSE's `stNum`/`sqNum`: it increments on every sample and wraps at
  65535.
- `sv_conf_rev`: the first ASDU's `confRev` (Configuration Revision) counter,
  as a plain integer -- changes only when an engineering tool has touched
  this IED's Sampled Value Control Block configuration.
- `sv_smp_synch`: the first ASDU's OPTIONAL `smpSynch` field, rendered as
  `"none"`, `"local"`, `"global"`, or `"unknown(N)"` for any other value,
  when present in the PDU.
- `sv_smp_rate`: the first ASDU's OPTIONAL `smpRate` field, as a plain
  integer, when present and nonzero.
- `sv_smp_mod`: the first ASDU's OPTIONAL `smpMod` field, rendered as
  `"samplesPerNormalPeriod"`, `"samplesPerSecond"`, `"secondsPerSample"`, or
  `"unknown(N)"` for any other value, when present in the PDU.
- `sv_seq_data_length`: the first ASDU's `seqData` OCTET STRING length in
  bytes. Always present when `sv_asdu_count` is greater than 0.
- `sv_seq_data_hex`: the first ASDU's `seqData` payload as raw lowercase hex,
  never value-decoded -- see PROTOCOL COVERAGE's Sampled Values section for
  why.
- `sv_gmid_hex`: the first ASDU's OPTIONAL Ed.2.1 `gmidData` field (an 8-byte
  EUI-64 grandmaster clock identity) as raw lowercase hex, when present.
- `sv_asdus`: an array of one entry per ASDU element decoded from `seqASDU`,
  each a `"svID=\"...\" [datSet=\"...\"] smpCnt=N confRev=N [smpSynch=...]
  [smpRate=N] [smpMod=...] seqData=N byte(s)"` string. Capped at 50 entries,
  same reason as `goose_all_data`.
- `ethercat_frame_type`: the EtherCAT frame header's Type field, as a plain
  integer (1-5), when protocol is `ethercat`. Always present alongside
  `ethercat_frame_type_name` and `ethercat_declared_length`.
- `ethercat_frame_type_name`: `"EtherCAT command"`, `"ADS"`, `"RAW-IO"`,
  `"NV"`, or `"Mailbox"` -- the named meaning of `ethercat_frame_type`.
- `ethercat_declared_length`: the frame header's own Length field (an 11-bit
  magnitude), as a plain integer -- the declared byte length of the
  datagram(s) that follow the header, NOT including the header's own 2
  bytes. See PROTOCOL COVERAGE's EtherCAT section for how this decoder uses
  it to bound the datagram-chain scan.
- `ethercat_has_datagrams`: `true`/`false` -- `true` only when
  `ethercat_frame_type` is 1 ("EtherCAT command"); Types 2-5 are named only,
  not decoded further, so the fields below are absent when this is `false`.
- `ethercat_datagram_count`: the number of EtherCAT datagrams actually
  decoded from the frame's datagram chain.
- `ethercat_first_cmd`: the first decoded datagram's `Cmd` byte, as a plain
  integer. Present when `ethercat_datagram_count` is greater than 0.
- `ethercat_first_cmd_name`: the first datagram's Cmd name (`"APRD"`,
  `"LRD"`, ..., or `"unknown(N)"` for an unrecognized byte value -- see
  PROTOCOL COVERAGE's Cmd table).
- `ethercat_first_idx`: the first datagram's `Idx` byte, as a plain integer
  -- an opaque per-datagram index the sender picks and a responding slave
  echoes back unchanged.
- `ethercat_first_adp` / `ethercat_first_ado`: the first datagram's 16-bit
  position/station/broadcast address and register-or-memory offset, each as
  a plain integer. Present only for non-logical-addressing commands (every
  Cmd except `LRD`/`LWR`/`LRW`).
- `ethercat_first_logical_address`: the first datagram's single 32-bit
  logical address, as a plain integer. Present only for `LRD`/`LWR`/`LRW`
  (in place of `ethercat_first_adp`/`ethercat_first_ado`).
- `ethercat_first_data_length`: the first datagram's `Data` field length in
  bytes.
- `ethercat_first_data_hex`: the first datagram's `Data` payload as raw
  lowercase hex, never value-decoded -- see PROTOCOL COVERAGE's EtherCAT
  section for why.
- `ethercat_first_wkc`: the first datagram's Working Counter, as a plain
  integer -- surfaced raw, with no verdict about whether it's the value a
  healthy bus should produce (this decoder has no slave-count/topology
  knowledge to judge that) -- see PROTOCOL COVERAGE.
- `ethercat_first_irq`: the first datagram's raw interrupt-request bitmask,
  as a plain integer -- not decoded further.
- `ethercat_first_circulating`: `true`/`false` -- the first datagram's Len
  word Circulating bit ("frame has circulated once" on a ring segment).
- `ethercat_datagrams`: an array of one entry per datagram decoded from the
  frame's chain, each a `"CMD idx=N (adp=0xNNNN ado=0xNNNN |
  logAddr=0xNNNNNNNN) len=N wkc=N [irq=0xNNNN] [circulating]"` string (the
  trailing `irq`/`circulating` are shown only when notable, to keep the
  common case uncluttered). Capped at 50 entries, same reason as
  `sv_asdus`/`goose_all_data`.
- `bacnet_bvlc_function`: the BVLC header's Function byte, named (e.g.
  `"Original-Unicast-NPDU"`, `"BVLC-Result"`, `"Write-Broadcast-Distribution-
  Table"`, `"Secure-BVLL"`), when protocol is `bacnet`. Always present.
- `bacnet_has_npdu`: `true`/`false` -- `true` for every BVLC function that
  carries an NPDU (the large majority: Original-Unicast/Broadcast-NPDU,
  Forwarded-NPDU, Distribute-Broadcast-To-Network); `false` for the BBMD/
  foreign-device-table management functions that are pure BVLC (BVLC-Result,
  Write/Read-BDT(-Ack), Register-Foreign-Device, Read/Delete-FDT-Entry) and
  for the opaque Secure-BVLL. The fields below are only present when this is
  `true`.
- `bacnet_npdu_version`: the NPDU header's Version byte, as a plain integer
  (always `1` for any NPDU actually seen on the wire today).
- `bacnet_npdu_is_network_layer_message`: `true`/`false` -- the Control
  byte's NET bit. When `true`, this NPDU carries a Network Layer Message
  (router-to-router traffic such as Who-Is-Router-To-Network) instead of an
  APDU -- `bacnet_npdu_message_type` is set and every `bacnet_has_apdu`/
  `bacnet_apdu_*` field below is absent.
- `bacnet_npdu_expecting_reply`: `true`/`false` -- the Control byte's
  Expecting-Reply bit (network-layer-message traffic only).
- `bacnet_npdu_priority`: the Control byte's 2-bit network priority field
  (0-3), as a plain integer.
- `bacnet_npdu_has_dest`: `true`/`false` -- the Control byte's
  Destination-Specifier bit. When `true`, `bacnet_npdu_dnet` and
  `bacnet_npdu_hop_count` are present (the DADR MAC bytes themselves are
  decoded but not currently promoted to a JSON field).
- `bacnet_npdu_dnet`: the destination network number, as a plain integer.
  Present only when `bacnet_npdu_has_dest` is `true`.
- `bacnet_npdu_has_src`: `true`/`false` -- the Control byte's
  Source-Specifier bit (this NPDU was forwarded from another network by a
  router). When `true`, `bacnet_npdu_snet` is present (the SADR MAC bytes
  themselves are decoded but not currently promoted to a JSON field).
- `bacnet_npdu_snet`: the source network number, as a plain integer. Present
  only when `bacnet_npdu_has_src` is `true`.
- `bacnet_npdu_hop_count`: the NPDU's HopCount byte, as a plain integer.
  Present only when `bacnet_npdu_has_dest` is `true` (HopCount only exists
  when DNET/DLEN/DADR are present).
- `bacnet_npdu_message_type`: the Network Layer Message's named MessageType
  (e.g. `"Who-Is-Router-To-Network"`, or `"vendor-proprietary(128)"` for a
  vendor-proprietary message type, which also carries its own 2-byte Vendor
  ID -- not currently promoted to its own JSON field). Present only when
  `bacnet_npdu_is_network_layer_message` is `true`.
- `bacnet_has_apdu`: `true`/`false` -- `true` only when this NPDU carries an
  APDU (`bacnet_has_npdu` is `true` and
  `bacnet_npdu_is_network_layer_message` is `false`) *and* the APDU itself
  parsed (a truncated or unrecognized APDU type leaves this `false` with a
  note instead). The fields below are only present when this is `true`.
- `bacnet_apdu_type`: the APDU's PDU type, named -- one of
  `"Confirmed-Request"`, `"Unconfirmed-Request"`, `"Simple-ACK"`,
  `"Complex-ACK"`, `"Segment-ACK"`, `"Error"`, `"Reject"`, or `"Abort"`.
- `bacnet_service_name`: the confirmed/unconfirmed service-choice name (e.g.
  `"readProperty"`, `"who-Is"`), when this PDU type carries one (every type
  except Segment-ACK). For Error, this is the *original request's* service
  choice (the one that errored), not a service of the Error PDU itself.
- `bacnet_invoke_id`: the APDU's invoke ID, as a plain integer, or `-1` for
  Segment-ACK's own separately-encoded invoke-id-like field when it wasn't
  otherwise applicable, and for Unconfirmed-Request (which has no invoke ID
  at all).
- `bacnet_segmented`: `true`/`false` -- Confirmed-Request/Complex-ACK's SEG
  bit. When `true`, the service data is a single segment of a larger,
  multi-datagram message; this decoder does no cross-packet APDU
  reassembly, so `bacnet_values` is absent and a note explains the service
  data is shown as raw hex instead (see PROTOCOL COVERAGE's BACnet/IP
  section).
- `bacnet_values`: an array of decoded field/value strings (e.g.
  `"object=analog-input,3"`, `"property=present-value"`,
  `"value=(Real) 72.500000"`, `"priority=8"`), present only for the
  "first-pass" service set this decoder value-decodes (Who-Is, I-Am,
  Who-Has, I-Have, ReadProperty request/ACK, WriteProperty request, generic
  Error) when a single primitive value was actually present to decode --
  absent for every other service (shown as raw hex with a note instead) and
  for a constructed/array PropertyValue (also raw hex with a note -- see
  PROTOCOL COVERAGE).

All array fields are capped at 50 entries for a single heavily-batched
request/response; see PROTOCOL COVERAGE for where the full list still shows
up when a packet has more items than that.

The following fields appear only when `protocol` is `hartip`:

- `hartip_version`: the header's Version byte, as a plain integer. Always
  present.
- `hartip_message_type`: the header's MessageType byte, named -- one of
  `"Request"`, `"Response"`, `"Publish"`, `"Error"`, or `"NAK"`. Always
  present.
- `hartip_message_id`: the header's MessageID byte, named -- one of
  `"Session Initiate"`, `"Session Close"`, `"Keep Alive"`, or
  `"Pass Through"`. Always present.
- `hartip_status`: the header's Status byte, as a plain integer. Always
  present. Every message this decoder's own research and real-capture
  testing has observed carries Status `0` -- see LIMITATIONS.
- `hartip_transaction_id`: the header's TransactionID (a.k.a. Sequence
  Number) field, as a plain integer. Always present.
- `hartip_msg_length`: the header's declared MsgLength field (the body's own
  byte count, not including the 8-byte header), as a plain integer. Always
  present.
- `hartip_host_type`: the Session Initiate body's Host Type byte, named
  (`"Primary Host"` or `"Secondary Host"`). Present only for a
  structurally-valid Session Initiate message (`hartip_message_id` is
  `"Session Initiate"` and the body is exactly 5 bytes).
- `hartip_inactivity_close_timer`: the Session Initiate body's Inactivity
  Close Timer field (seconds), as a plain integer. Present under the same
  condition as `hartip_host_type`.
- `hartip_error_code`: an Error/NAK message's 1-byte error code, as a plain
  integer. Present only for a structurally-valid Error/NAK message
  (`hartip_message_type` is `"Error"` or `"NAK"` and the body is exactly 1
  byte).
- `hartip_error_code_name`: that same error code, named from the 25-entry
  table HCF_SPEC-307 defines (e.g. `"Session closed"`,
  `"Service unavailable"`), or `"unknown(N)"` for a structurally-valid but
  undefined code. Present under the same condition as `hartip_error_code`.
- `hartip_has_pass_through`: `true`/`false` -- `true` when `hartip_message_id`
  is `"Pass Through"` (regardless of whether the wrapped HART Data-Link PDU
  itself parses further). Always present.
- `hartip_frame_type`: the Pass-Through body's Delimiter byte's Frame Type
  field, named (`"STX"`, `"ACK"`, `"BACK"`, or `"unknown(N)"` for an
  undefined value). Present only when `hartip_has_pass_through` is `true`
  and the Delimiter byte itself was present.
- `hartip_is_response`: `true`/`false` -- the Frame Type's field-device-vs-
  master direction (`"ACK"`/`"BACK"` are responses; `"STX"` is a request).
  Present under the same condition as `hartip_frame_type`.
- `hartip_is_long_address`: `true`/`false` -- the Delimiter byte's Address
  Type bit (5-byte Unique/long address vs. 1-byte polling/short address).
  Present under the same condition as `hartip_frame_type`.
- `hartip_address`: the HART Data-Link address itself, as lowercase hex (1
  byte for a short address, e.g. `"01"`; 5 bytes for a long address, e.g.
  `"264e0000d2"`). Present under the same condition as `hartip_frame_type`.
- `hartip_command`: the Pass-Through PDU's Command byte, as a plain integer.
  Present only when the Command byte itself was present (i.e. the body
  wasn't truncated before reaching it -- see LIMITATIONS).
- `hartip_command_name`: that same command number, named from this decoder's
  own command-number table (e.g. `"Read Primary Variable"`), when the number
  is one this decoder recognizes at all (value-decoded or not); absent for a
  command number outside that table (the command is still shown as a bare
  number in `summary` and `hartip_command`). Present only alongside
  `hartip_command`.
- `hartip_response_code`: a response frame's Response Code byte, as a plain
  integer (bit 7 set means this is a comm-error bitmask, not a
  command-specific code -- see `hartip_response_is_comm_error`). Present
  only for a response (`hartip_is_response` is `true`) whose Byte Count was
  large enough to include it.
- `hartip_response_is_comm_error`: `true`/`false` -- the Response Code
  byte's bit 7. Present under the same condition as `hartip_response_code`.
- `hartip_response_code_name`: the Response Code, named from the 25-entry
  single-definition table this decoder uses (e.g. `"Success"`, `"Busy"`), or
  a `"command-specific response code N (meaning depends on which command
  produced it -- not decoded)"` placeholder for a structurally valid but
  unlisted non-comm-error code. Present only when
  `hartip_response_is_comm_error` is `false` (a comm-error code has no
  single meaning to name -- see `hartip_comm_error_flags` instead).
- `hartip_comm_error_flags`: an array of the Response Code byte's individual
  comm-error bit names (e.g. `"vertical-parity-error"`,
  `"longitudinal-parity-error"`). Present only when
  `hartip_response_is_comm_error` is `true`.
- `hartip_device_status`: a response frame's Device Status byte, as a plain
  integer. Present under the same condition as `hartip_response_code`.
- `hartip_device_status_flags`: an array of the Device Status byte's
  individual flag names (e.g. `"field-device-malfunction"`,
  `"configuration-changed"`), present only when at least one flag bit is
  set (an all-zero Device Status omits this field rather than emitting an
  empty array).
- `hartip_values`: an array of decoded field/value strings (e.g.
  `"pv-units=1"`, `"pv=72.500000"`), present only for the "first-pass"
  command set this decoder value-decodes (see PROTOCOL COVERAGE's HART-IP
  section) when the command's data actually matched the byte layout this
  decoder expects -- absent for every out-of-scope or wrong-length command
  (shown as raw hex with a note instead).

The following fields appear only when `protocol` is `opcua`:

- `opcua_message_type`: the UA-TCP common header's MessageType, spelled out
  -- one of `"Hello"`, `"Acknowledge"`, `"Error"`, `"ReverseHello"`,
  `"OpenSecureChannel"`, `"CloseSecureChannel"`, or `"Message"`. Always
  present.
- `opcua_chunk_type`: the ChunkType byte, as a single character -- `"F"`
  (final/only chunk), `"C"` (intermediate chunk -- see LIMITATIONS'
  "Chunking" entry), or `"A"` (abort). Always present.
- `opcua_message_size`: this one chunk's own declared total byte length
  (header included), as a plain integer -- not the reassembled multi-chunk
  message's total length when `opcua_chunk_type` isn't `"F"`. Always
  present.
- `opcua_has_secure_channel`: `true`/`false` -- `true` for OpenSecureChannel/
  CloseSecureChannel/Message (which carry the 12-byte SecureConversation
  header below), `false` for Hello/Acknowledge/Error/ReverseHello (which
  don't). Always present. The fields below are only present when this is
  `true`.
- `opcua_secure_channel_id`: the SecureConversation header's SecureChannelId
  field, as a plain integer (`0` on the very first OpenSecureChannel request
  of a new channel, before the server assigns a real one).
- `opcua_is_asymmetric`: `true`/`false` -- `true` only for OpenSecureChannel
  (Asymmetric Algorithm Security Header), `false` for CloseSecureChannel/
  Message (Symmetric Algorithm Security Header).
- `opcua_security_policy_uri`: the Asymmetric Algorithm Security Header's
  SecurityPolicyUri (e.g.
  `"http://opcfoundation.org/UA/SecurityPolicy#None"`) -- itself a real
  security-audit signal (see PROTOCOL COVERAGE's OPC UA section). Present
  only when `opcua_is_asymmetric` is `true`.
- `opcua_has_sender_certificate` / `opcua_sender_certificate_length`: whether
  a SenderCertificate was present (non-null, non-empty) and, if so, its byte
  length -- the certificate bytes themselves are never surfaced, the same
  posture this decoder already applies to HART-IP's Data-Link Checksum or
  Sampled Values' `seqData`. Present only when `opcua_is_asymmetric` is
  `true`.
- `opcua_has_receiver_certificate_thumbprint`: same, for the
  ReceiverCertificateThumbprint field. Present only when
  `opcua_is_asymmetric` is `true`.
- `opcua_token_id`: the Symmetric Algorithm Security Header's TokenId field,
  as a plain integer -- the previously-negotiated security token this
  message claims to use. Present only when `opcua_is_asymmetric` is
  `false` (i.e. for CloseSecureChannel/Message).
- `opcua_sequence_number` / `opcua_request_id`: the SequenceHeader's own two
  fields, as plain integers. Present alongside every other
  `opcua_has_secure_channel`-gated field above.
- `opcua_service_recognized`: `true`/`false` -- `true` when the Message-layer
  body's own leading NodeId ("TypeId") matched a service this decoder's own
  dispatch table knows (Tier 1 or Tier 2 -- see PROTOCOL COVERAGE). Always
  present for OpenSecureChannel/CloseSecureChannel/Message; absent for
  Hello/Acknowledge/Error/ReverseHello (which have no service TypeId of
  their own).
- `opcua_service_name`: the recognized service's own name (e.g.
  `"CreateSessionRequest"`). Present only when `opcua_service_recognized`
  is `true`.
- `opcua_service_namespace` / `opcua_service_type_id`: the service TypeId
  NodeId's own namespace and numeric identifier, as plain integers -- present
  even when `opcua_service_recognized` is `false`, so an unrecognized
  service is still identifiable by its raw TypeId (see PROTOCOL COVERAGE).
  Absent only when the TypeId itself couldn't be read at all (a
  structurally-invalid NodeId encoding byte -- see LIMITATIONS).
- `opcua_service_body_decoded`: `true`/`false` -- `true` for a Tier 1
  (fully field-decoded) service, `false` for Tier 2 (header only, body
  shown as raw hex) or an unrecognized service. Present only when
  `opcua_service_recognized` is `true`.
- `opcua_has_header`: `true`/`false` -- whether this service's own
  RequestHeader/ResponseHeader was itself decoded (true for both Tier 1 and
  Tier 2 services; false for an unrecognized service, since this decoder
  doesn't guess whether an unknown TypeId's body even starts with a
  RequestHeader or a ResponseHeader shape). Present alongside
  `opcua_service_recognized`.
- `opcua_request_handle`: the RequestHeader/ResponseHeader's own
  RequestHandle field, as a plain integer. Present only when
  `opcua_has_header` is `true`.
- `opcua_is_response`: `true`/`false` -- whether this is the
  ResponseHeader shape (`true`) or RequestHeader shape (`false`). Present
  under the same condition as `opcua_request_handle`.
- `opcua_status_code` / `opcua_status_code_name` / `opcua_status_is_good`:
  a ResponseHeader's own ServiceResult StatusCode -- the raw 32-bit value,
  its name (e.g. `"Good"`, `"BadSessionClosed"`, or a decoded-severity-plus-
  raw-hex fallback like `"Bad (0x80af0000)"` for a code outside this
  decoder's own first-pass ~20-entry named table -- see PROTOCOL COVERAGE),
  and whether its top 2 bits indicate the Good severity. Present only when
  `opcua_is_response` is `true`.
- `opcua_values`: an array of decoded field/value strings (e.g.
  `"security-mode=None"`, `"session-id=ns=1;i=1001"`,
  `"identity=anonymous (policy-id=anonymous)"`) -- present for Hello/
  Acknowledge/Error/ReverseHello (always) and for a Tier 1 service (always
  includes at least the RequestHeader/ResponseHeader's own `timestamp=`/
  `request-handle=`/`service-result=` entries, plus that service's own
  fields); absent for a Tier 2 or unrecognized service (see
  `opcua_body_shown_as_hex` instead).
- `opcua_body_shown_as_hex`: `true`/`false` -- `true` for a Tier 2 service
  (RequestHeader/ResponseHeader decoded into `opcua_values`, but the
  service-specific body shown as raw hex instead -- Variant/DataValue
  encoding is not implemented by this first-pass release, see LIMITATIONS),
  an unrecognized service, a non-`'F'` chunk (see LIMITATIONS' "Chunking"
  entry), or any structural parse failure past the point already decoded.
  Always present when `opcua_has_secure_channel` is `true`.
- `opcua_body_hex` / `opcua_body_length`: the raw hex bytes (space-separated
  octets, e.g. `"00 00 00 00 02 00 00 00"`) and their count. Present only
  when `opcua_body_shown_as_hex` is `true` and at least one byte remained.

Every ActivateSessionRequest whose UserIdentityToken is a UserNameIdentityToken
with an empty EncryptionAlgorithm gets its Password decoded into
`opcua_values` in cleartext (e.g. `"password=Sup3rSecret!1"`), deliberately
-- per OPC 10000-4 7.41 this means the password was placed on the wire
unencrypted, a real OT-security finding this decoder surfaces rather than
hides -- alongside a `notes` entry beginning `"SECURITY FINDING: ..."`. See
PROTOCOL COVERAGE's OPC UA section for the full rationale.

The following fields appear only when `protocol` is `mms`:

- `mms_is_bare`: `true`/`false` -- always present. `true` when the COTP Data
  frame's own user data is a bare MMS PDU with no Session/Presentation/ACSE
  layers at all (see PROTOCOL DETECTION's "bare MMS" shape); when `true`,
  none of the `mms_session_*`/`mms_presentation_*`/`mms_acse_*` fields below
  are present.
- `mms_session_pdu`: the decoded Session SPDU name (e.g. `"CONNECT (CN)"`,
  `"DATA TRANSFER / GIVE TOKENS"`, `"ACCEPT (AC)"`), `"(no Session layer)"`
  for the "bare Presentation" shape (Session skipped, Presentation still
  present), or `"type N"` for an SPDU type this decoder recognizes
  structurally but doesn't name. Present only when `mms_is_bare` is `false`.
- `mms_has_presentation`: `true`/`false` -- whether Session's own user-data
  parameter was present and unwrapped as Presentation's fully-encoded-data
  alternative. Present only when `mms_is_bare` is `false`.
- `mms_presentation_contexts`: an array of strings, each
  `"context N = <OID> (<name>)"` (e.g. `"context 1 = 2.2.1.0.1 (ACSE)"`) --
  present only when the Presentation layer carried its own
  presentation-context-definition-list, which only ever appears on an
  association-establishment frame (CONNECT/ACCEPT), never on an ongoing
  Data-Transfer message.
- `mms_presentation_context_id`: the PDV's own presentation-context-
  identifier, as a plain integer. Present when `mms_has_presentation` is
  `true`.
- `mms_presentation_context_is_acse`: `true`/`false` -- `true` when
  `mms_presentation_context_id` is `1`, per the near-universal "1=ACSE,
  3=MMS" convention this stateless-per-message decoder assumes for an
  ongoing frame with no context-definition-list of its own to resolve
  against (see PROTOCOL COVERAGE's MMS section). Present when
  `mms_has_presentation` is `true`.
- `mms_has_acse`: `true`/`false` -- whether an ACSE APDU was reached
  (association-establishment/release frames only). Present when
  `mms_has_presentation` is `true`.
- `mms_acse_pdu`: one of `"AARQ"`/`"AARE"`/`"RLRQ"`/`"RLRE"`/`"ABRT"`.
  Present when `mms_has_acse` is `true`.
- `mms_acse_application_context_name`: the negotiated application-context
  OID, with a friendly name in parens when recognized (e.g.
  `"1.0.9506.2.3 (MMS)"`). Present when `mms_acse_pdu` is `"AARQ"` or
  `"AARE"`.
- `mms_acse_result`: one of `"accepted"`/`"rejected-permanent"`/
  `"rejected-transient"`/`"unknown(N)"`. Present only on an `"AARE"` that
  carries a result.
- `mms_acse_values`: an array of `"key=value"` strings -- RLRQ/RLRE reason,
  or ABRT source/diagnostic, when present.
- `mms_has_pdu`: `true`/`false` -- always present when `protocol` is `mms`.
  Whether an MMS-layer PDU itself was reached and decoded, whether by
  unwrapping ACSE's own user-information (an association frame), a
  Presentation PDV's MMS-context payload directly (an ongoing Data-Transfer
  frame), or a bare frame (`mms_is_bare`) -- `false` if this decoder reached
  no further than the Session/Presentation/ACSE layers (e.g. an ACSE PDU
  whose own user-information was absent or unrecognized).
- `mms_pdu`: the `MMSpdu` CHOICE alternative name (e.g.
  `"confirmed-RequestPDU"`, `"initiate-ResponsePDU"`, `"rejectPDU"`,
  `"cancel-ErrorPDU"`, `"unconfirmed-PDU (informationReport)"`). Present
  when `mms_has_pdu` is `true`.
- `mms_is_response`: `true`/`false` -- best-effort: `true` for a
  `*ResponsePDU` shape, `false` for a `*RequestPDU` shape. Present under the
  same condition as `mms_pdu`.
- `mms_invoke_id`: the confirmed-Request/Response/ErrorPDU's own invokeID,
  as a plain integer -- this decoder's own closest analog to OPC UA's
  RequestHandle or S7comm's PDU reference, though (see "Deliberately NOT
  implemented" in PROTOCOL COVERAGE's MMS section) never correlated back to
  the request it answers across packets. Present when `mms_has_pdu` is
  `true` and the PDU type carries an invokeID.
- `mms_service_recognized`: `true`/`false` -- `true` when the
  ConfirmedServiceRequest/Response (or unconfirmed-PDU service) CHOICE
  alternative is one of the 78 defined MMS confirmed services this
  decoder's own dispatch table names, regardless of whether this decoder
  goes on to fully decode its body (Tier 1 vs. Tier 2 -- see PROTOCOL
  COVERAGE). Present when `mms_has_pdu` is `true`.
- `mms_service`: the service name (e.g. `"read"`, `"takeControl"`). Present
  when `mms_service_recognized` is `true`.
- `mms_error`: the errorClass category name plus numeric code (e.g.
  `"resource(1)"`), for a `confirmed-ErrorPDU`/`initiate-ErrorPDU`/
  `cancel-ErrorPDU`/`conclude-ErrorPDU`'s own ServiceError. Present only
  when the PDU carries one.
- `mms_values`: an array of decoded `"field=value"` strings, present only
  when non-empty. The exact shape varies by PDU/service -- e.g.
  `"variable=simpleIOGenericIO/LLN0$Events"` (a Read/Write/
  InformationReport ObjectName), `"result[0]=true"` (a decoded Data value
  from a `read` response or report), or `"servicesSupported=[status,
  getNameList,...]"` (initiate-RequestPDU/ResponsePDU's own capability
  negotiation, one entry per SET bit).
- `mms_body_shown_as_hex`: `true`/`false` -- always present when
  `mms_has_pdu` is `true`. `true` for a Tier 2 (recognized-but-not-decoded)
  confirmed service, or any MMS structure this decoder doesn't further
  parse (see PROTOCOL COVERAGE and LIMITATIONS).
- `mms_body_length` / `mms_body_hex`: the raw hex bytes (space-separated
  octets) and their count. Present only when `mms_body_shown_as_hex` is
  `true` and at least one byte remained.
- `mqtt_packet_type`: the MQTT Control Packet Type name (`"CONNECT"`,
  `"PUBLISH"`, ...), always present when `protocol` is `mqtt`.
- `mqtt_remaining_length`: the fixed header's own Remaining Length (Variable
  Byte Integer), always present when `protocol` is `mqtt`.
- `mqtt_protocol_version`: `"3.1"`, `"3.1.1"`, or `"5.0"`, when known for
  this specific message -- either self-describing (CONNECT/CONNACK/
  UNSUBACK/DISCONNECT/AUTH) or resolved via this TCP session's own tracked
  CONNECT or, failing that, the per-packet-type heuristic (SUBSCRIBE/
  SUBACK/UNSUBSCRIBE only -- see PROTOCOL DETECTION). Absent when truly
  unknown (e.g. a PUBLISH on a session whose CONNECT wasn't captured).
- `mqtt_dup` / `mqtt_qos` / `mqtt_retain`: the PUBLISH fixed-header flag
  bits, present only when `mqtt_packet_type` is `"PUBLISH"`.
- `mqtt_topic`: the PUBLISH Topic Name, present only when
  `mqtt_packet_type` is `"PUBLISH"`.
- `mqtt_packet_id`: the Packet Identifier, present on PUBLISH (QoS>0 only),
  PUBACK/PUBREC/PUBREL/PUBCOMP, SUBSCRIBE/SUBACK, and UNSUBSCRIBE/UNSUBACK.
- `mqtt_payload_length`: the PUBLISH application payload's byte count,
  present only when `mqtt_packet_type` is `"PUBLISH"`.
- `mqtt_payload_hex`: the raw application payload as hex (space-free octet
  string), present when `mqtt_payload_length` is present AND greater than
  zero -- EXCEPT left absent when the payload was a Sparkplug B protobuf
  message that this decoder successfully decoded (see `mqtt_is_sparkplug`
  below), in which case the decoded `mqtt_sparkplug_*` fields carry the
  content instead of raw hex.
- `mqtt_values`: an array of decoded `"field=value"` strings, present only
  when non-empty -- CONNECT's own negotiated fields (including, by
  deliberate design, cleartext `Username=`/`Password=` when present -- see
  PROTOCOL COVERAGE's own security note), CONNACK's SessionPresent/Return
  or Reason Code, SUBSCRIBE/UNSUBSCRIBE's topic filters, SUBACK/UNSUBACK's
  reason codes, MQTT5 Properties on any packet type that carries them (one
  `"PropertyName=value"` entry per recognized property; an unrecognized
  property id is still shown, as `"(unknown property id N, K remaining
  properties byte(s) not decoded: <hex>)"`, rather than aborting the whole
  message), and AUTH/DISCONNECT's reason code plus reason string.
- `mqtt_is_sparkplug`: `true`/`false`, always present when
  `mqtt_packet_type` is `"PUBLISH"`. `true` when the topic matches the
  Sparkplug B `spBv1.0/...` namespace (either the protobuf-payload shape or
  the separate `spBv1.0/STATE/{host_id}` JSON-text shape -- see
  `mqtt_sparkplug_is_state`).
- `mqtt_sparkplug_message_type`: `"NBIRTH"`/`"NDEATH"`/`"DBIRTH"`/
  `"DDEATH"`/`"NDATA"`/`"DDATA"`/`"NCMD"`/`"DCMD"`/`"STATE"`. Present when
  `mqtt_is_sparkplug` is `true`.
- `mqtt_sparkplug_is_state`: `true`/`false`, present when `mqtt_is_sparkplug`
  is `true`. `true` for the `spBv1.0/STATE/{host_id}` namespace (a JSON
  text payload, not protobuf); `false` for every other Sparkplug message
  type (an `org.eclipse.tahu.protobuf.Payload`).
- `mqtt_sparkplug_group_id` / `mqtt_sparkplug_edge_node_id` /
  `mqtt_sparkplug_device_id`: the topic's own `{group_id}`/{edge_node_id}`/
  `{device_id}` segments (the last only for D-prefixed message types).
  Present when `mqtt_sparkplug_is_state` is `false`.
- `mqtt_sparkplug_state_host_id` / `mqtt_sparkplug_state_text`: the STATE
  topic's own `{host_id}` segment and the raw JSON text payload (not
  further parsed as JSON -- see LIMITATIONS). Present when
  `mqtt_sparkplug_is_state` is `true`.
- `mqtt_sparkplug_payload_decoded`: `true`/`false`, present when
  `mqtt_sparkplug_is_state` is `false`. `false` when this decoder's
  hand-rolled protobuf reader hit a structural problem partway through
  (truncated/malformed bytes) -- whatever metrics were found before the
  failure are still shown in `mqtt_sparkplug_metrics`, and `notes` explains
  what went wrong.
- `mqtt_sparkplug_timestamp` / `mqtt_sparkplug_seq` / `mqtt_sparkplug_uuid`
  / `mqtt_sparkplug_body_length`: the Sparkplug B `Payload` message's own
  optional top-level fields (proto2 presence semantics -- each is present
  in the JSON output only when the encoder actually set it).
- `mqtt_sparkplug_metric_count`: the total number of `Metric` entries found
  in the `Payload`, present when `mqtt_sparkplug_is_state` is `false` (may
  be `0`, e.g. a DDEATH carrying no metrics).
- `mqtt_sparkplug_metrics`: an array of one rendered string per metric
  (capped at 50), e.g. `"\"Temperature\" type=Float value=21.500000
  ts=2023-11-14T22:13:20.000Z"`, present only when non-empty. A `Bytes`/
  `File`/`DataSet`/`Template` value renders as `"<N byte(s), not decoded
  further>"` (Tier 2 scope -- see PROTOCOL COVERAGE); a null metric
  (`is_null=true`) renders its value as `null`.
- `s7plus_pdu_type`: the S7comm-Plus header's own PDU type name
  (`"Connect"`, `"Data"`, `"DataFW1_5"`, `"Keep Alive"`), always present
  when `protocol` is `s7comm-plus`.
- `s7plus_keepalive_seq`: the Keep Alive PDU's own 1-byte sequence number,
  present only when `s7plus_pdu_type` is `"Keep Alive"`.
- `s7plus_opcode`: `"Request"`/`"Response"`/`"Notification"`/`"Response2"`,
  present when `s7plus_pdu_type` is `"Data"` (or `"DataFW1_5"`'s own -- no,
  DataFW1_5's Data part is not decoded, so this is present only for `"Data"`)
  and an opcode byte was reached.
- `s7plus_function`: the function code's name (e.g. `"GetMultiVariables"`,
  `"Unknown (0xNNNN)"` for an unrecognized code), present when a
  Request/Response/Response2 envelope's function code field was reached
  (i.e. not for a Notification, which carries no function code at all).
- `s7plus_body_decoded`: `true`/`false`, present under the same condition as
  `s7plus_function`. `true` only for the four Tier-1 functions
  (GetMultiVariables/SetMultiVariables/SetVariable/DeleteObject) AND when
  that decode actually ran to completion without falling back early (e.g.
  an array-of-Struct or unrecognized-datatype value partway through still
  leaves this `false`, even for a Tier-1 function -- see PROTOCOL COVERAGE
  and LIMITATIONS).
- `s7plus_sequence_number`: the envelope's own 2-byte sequence number,
  correlating a request to its response within a session (alongside TCP
  itself). Present under the same condition as `s7plus_function`.
- `s7plus_session_id`: the Request envelope's own 4-byte session id.
  Present only on a Request.
- `s7plus_return_code` / `s7plus_return_code_name`: the ReturnValue's
  low-16-bit signed error code, as a plain integer and its name (e.g. `0` /
  `"OK"`, `-12` / `"Object not found"`). Present only on a Response/
  Response2 body this decoder fully decoded (`s7plus_body_decoded: true`)
  that carries a ReturnValue.
- `s7plus_items`: an array of rendered item-address strings (e.g.
  `"SYM-CRC=a9bc66e6, LID=DB3.10"`, `"Delete Object Id=0x0000038a"`, `"by
  IDs: RID=100, ID=500, ID=7"`, `"by subscribed Link-Id=42, ID=1"`),
  present only when non-empty -- GetMultiVariables/SetMultiVariables
  request item addresses, or SetVariable/DeleteObject's own object-id.
- `s7plus_values`: an array of rendered `"id=<id>: (Type) = value"` or
  `"item=<n>: (Type) = value"` strings, present only when non-empty --
  GetMultiVariables response values, or SetMultiVariables/SetVariable
  request values being written. A nested Struct value renders its members
  inline (`"(Struct) Struct { id=315: (UDInt) = 320; ... }"`), flattened to
  one string rather than a nested JSON structure -- see PROTOCOL COVERAGE.
- `s7plus_item_errors`: an array of rendered `"item=<n>: <name> (<code>)"`
  per-item status strings, present only when non-empty -- a
  GetMultiVariables/SetMultiVariables response's own itemnumber-errorvalue
  list.
- `s7plus_integrity_digest_present`: `true`/`false`, present only when an
  Integrity part was reached at all (i.e. only for a Tier-1-decoded body
  with enough remaining bytes -- see PROTOCOL COVERAGE). `true` only when
  the digest length byte read exactly 32 and that many bytes were actually
  present; the digest bytes themselves are never verified either way.
- `s7plus_has_trailer`: `true`/`false`, always present when `protocol` is
  `s7comm-plus`. `false` means this telegram is a fragment awaiting a
  further TPKT/COTP frame this decoder does not reassemble across -- see
  LIMITATIONS.
- `ffhse_version` / `ffhse_options`: the header's raw Version/Options bytes,
  always present when `protocol` is `ffhse`.
- `ffhse_protocol`: `"FDA"`/`"SM"`/`"FMS"`/`"LAN Redundancy"`, always
  present when `protocol` is `ffhse`.
- `ffhse_type`: `"Request"`/`"Response"`/`"Error"`, always present when
  `protocol` is `ffhse`.
- `ffhse_confirmed`: `true`/`false`, the Service byte's own confirmed-
  service flag, always present when `protocol` is `ffhse`.
- `ffhse_service_id`: the Service byte's low 7 bits, always present when
  `protocol` is `ffhse`.
- `ffhse_fda_address`: the full 4-byte FDA Address field as hex (e.g.
  `"0x00010203"`), always present when `protocol` is `ffhse`.
- `ffhse_link_id`: the FDA Address field's own top 16 bits, always present
  when `protocol` is `ffhse` -- see PROTOCOL COVERAGE's FOUNDATION Fieldbus
  HSE section's LinkId branch.
- `ffhse_message_length`: the header's own declared total PDU length,
  always present when `protocol` is `ffhse`.
- `ffhse_message_number` / `ffhse_invoke_id` / `ffhse_time_stamp` /
  `ffhse_extended_control_field`: present only when the corresponding
  trailer Options bit was set. `ffhse_time_stamp` is always the raw 64-bit
  value -- no epoch/scale confidently sourced, never interpreted as a
  calendar date.
- `ffhse_message_name`: a best-effort message name (e.g. `"FDA Open Session
  Req"`, `"SM Identify Rsp"`, `"FMS Initiate Err"`), always present when
  `protocol` is `ffhse`, even for an unrecognized combination (e.g. `"SM
  unconfirmed service 99"`).
- `ffhse_recognized`: `true`/`false`, always present when `protocol` is
  `ffhse` -- whether this decoder recognizes the (Protocol, Type,
  ConfirmedFlag, ServiceId) combination at all (Tier 1 OR Tier 2).
- `ffhse_body_decoded`: `true`/`false`, always present when `protocol` is
  `ffhse` -- `true` only for a Tier-1 message whose body matched this
  decoder's expected shape.
- `ffhse_values`: an array of one `"field-name=value"` string per decoded
  field, wire order (e.g. `"session-index=1"`, `"index=315"`,
  `"error-class=5 (Service)"`), present only when non-empty (a Tier-1-
  decoded body).
- `ffhse_body_shown_as_hex`: `true`/`false`, always present when `protocol`
  is `ffhse` -- `true` for a Tier-2 message's whole body, or for the
  trailing "remainder" bytes past a Tier-1 message's own decoded shape.
- `ffhse_body_length` / `ffhse_body_hex`: present only when
  `ffhse_body_shown_as_hex` is `true` -- the undecoded byte count and its
  hex rendering.
- `stp_protocol_version` / `stp_protocol_version_name`: the Protocol Version
  Identifier byte as a plain integer (0/2/3/4) and its name (`"STP
  (802.1D)"`, `"RSTP (802.1w)"`, `"MSTP (802.1s)"`, `"SPB (802.1aq)"`),
  always present when protocol is `stp`.
- `stp_bpdu_type` / `stp_bpdu_type_name`: the BPDU Type byte as a plain
  integer (`0x00`/`0x02`/`0x80`) and its name (`"Configuration"`, `"Rapid/
  Multiple Spanning Tree"`, `"Topology Change Notification"`), always
  present when protocol is `stp`.
- `stp_is_tcn`: `true`/`false` -- `true` for a Topology Change Notification
  (BPDU Type `0x80`), in which case nothing below is set (a TCN carries no
  further fields). Always present when protocol is `stp`.
- `stp_is_spb`: `true`/`false` -- `true` for a Protocol Version 4 (SPB,
  802.1aq) frame, in which case nothing below is set either -- SPB is
  named only, not decoded. Always present when protocol is `stp`.
- `stp_has_common_body`: `true`/`false`, always present when protocol is
  `stp` and `stp_is_tcn`/`stp_is_spb` are both `false` -- `false` only when
  the frame was truncated before all 35 common Configuration/RST BPDU body
  bytes fit. Every field below through `stp_forward_delay` is present only
  when this is `true`.
- `stp_flags`: the raw 8-bit Flags byte, as a plain integer.
- `stp_flag_tca` / `stp_flag_agreement` / `stp_flag_forwarding` /
  `stp_flag_learning` / `stp_flag_proposal` / `stp_flag_tc`: each `true`/
  `false`, the individual Flags bits (Agreement/Forwarding/Learning/
  Proposal are only ever meaningfully set under RSTP/MSTP, but are surfaced
  for every version).
- `stp_flag_port_role`: the Port Role sub-field's name (`"Unknown"`,
  `"Alternate/Backup"`, `"Root"`, `"Designated"`) -- meaningful only under
  RSTP/MSTP.
- `stp_root_priority` / `stp_root_sys_id_ext` / `stp_root_mac`: the Root
  Identifier's Bridge Priority (already in "multiple of 4096" form),
  System ID Extension, and MAC address.
- `stp_root_path_cost`: the Root Path Cost, as a plain integer.
- `stp_bridge_priority` / `stp_bridge_sys_id_ext` / `stp_bridge_mac`: the
  same split for the (local) Bridge Identifier.
- `stp_port_priority` / `stp_port_number`: the Port Identifier's Port
  Priority (already multiplied by 16 -- a DIFFERENT multiplier than the
  Bridge/Root Identifier's own priority nibble) and Port Number, each a
  plain integer. (There is no `stp_port_id_raw` field -- only this split
  form is emitted.)
- `stp_message_age` / `stp_max_age` / `stp_hello_time` / `stp_forward_delay`:
  each a floating-point number of seconds (the raw 1/256-second field
  divided by 256), fixed at 3 decimal places.
- `stp_has_version1`: `true`/`false`, always present when
  `stp_has_common_body` is `true` -- `false` only when the frame was
  truncated right after the 35-byte common body (before the Version 1
  Length byte, BPDU Type `0x02` only).
- `stp_version_1_length`: the raw Version 1 Length byte, as a plain integer.
  Present only when `stp_has_version1` is `true`.
- `stp_is_mstp`: `true`/`false`, always present when `stp_has_common_body`
  is `true` -- `true` only when the three-part MSTP detection gate holds
  (Protocol Version Identifier >= 3, Version 1 Length == 0, and at least
  102 bytes present -- see PROTOCOL COVERAGE). Every field below is present
  only when this is `true`.
- `stp_version_3_length`: the Version 3 Length field, as a plain integer.
- `stp_mst_config_name`: the 32-byte MST Config Name, NUL-trimmed.
- `stp_mst_config_revision_level`: the MST Config Revision Level, as a
  plain integer.
- `stp_mst_config_digest`: the 16-byte MST Config Digest as raw lowercase
  hex, never verified.
- `stp_cist_internal_root_path_cost`: the CIST Internal Root Path Cost, as
  a plain integer. Only meaningful (and only ever nonzero from real bytes)
  when `stp_version_3_length` is nonzero -- see PROTOCOL COVERAGE's "Version
  3 Length == 0" paragraph for why this and the next three fields are left
  at their defaults otherwise.
- `stp_cist_bridge_priority` / `stp_cist_bridge_sys_id_ext` /
  `stp_cist_bridge_mac`: the CIST Bridge Identifier's own priority/
  extension/MAC split -- the CIST regional root's bridge ID, distinct from
  `stp_bridge_priority`/etc. above.
- `stp_cist_remaining_hops`: the CIST Remaining Hops byte, as a plain
  integer.
- `stp_msti_messages`: an array of one summary string per decoded MSTI
  Configuration Message, each `"MSTID=N RegionalRoot=P/MAC Cost=N
  BridgePrio=N PortPrio=N RemainingHops=N Role=... [TC] [Proposal]
  [Agreement] [Learning] [Forwarding]"` (the bracketed flag suffixes shown
  only when set). Present only when non-empty; absent (not an empty array)
  when `stp_version_3_length` is `0`. Capped at 50 entries, same reason as
  `ethercat_datagrams`/`sv_asdus`/`goose_all_data`.
- `stp_is_alt_msti_format`: `true`/`false`, always present when
  `stp_has_common_body` is `true` -- `true` only when Version 3 Length is
  `0` AND the frame's total length matches the legacy/alternative MSTI
  format's own sizing rule exactly (see PROTOCOL COVERAGE); that format is
  named but not decoded either way.
- `devicenet_can_id`: the masked 11-bit standard CAN identifier as hex
  (e.g. `"0x0305"`), always present when `protocol` is `devicenet`.
- `devicenet_group`: `1`-`4` for a classified message group, or `0` for the
  unclassified `0x07F0`-`0x07FF` range, always present when `protocol` is
  `devicenet`.
- `devicenet_group_name`: `"Group 1"`/`"Group 2"`/`"Group 3"`/`"Group 4"`/
  `"Unclassified (0x07F0-0x07FF)"`, always present when `protocol` is
  `devicenet`.
- `devicenet_message_type`: the per-group named message type (e.g.
  `"Slave's I/O Multicast Poll Response"`, `"Duplicate MAC ID Check
  Messages"`, `"Unconnected Explicit Request Message"`), always present
  when `protocol` is `devicenet` -- see PROTOCOL COVERAGE's DeviceNet
  section for the full per-group name table.
- `devicenet_source_mac_id`: the CAN-ID-derived Source MAC ID (0-63),
  present only for Groups 1-3 -- Group 4 has no MAC ID extraction defined
  at all, in this decoder or the reference dissector it's sourced from.
- `devicenet_dest_mac_id` / `devicenet_is_fragmented` / `devicenet_is_xid`:
  the Group 3 payload header's destination MAC ID (bits `0x3F` of the first
  payload byte) and its Fragmentation (`0x80`)/XID (`0x40`) flags, present
  only for a Group 3 message whose first payload byte was actually
  captured.
- `devicenet_cip_is_response` / `devicenet_cip_service`: the Group 3
  CIP-style service byte's own Request/Response bit and resolved service
  name (e.g. `"Get_Attribute_Single"`, `"Open Explicit Message Connection
  Request"`), present only for a non-fragmented Group 3 message whose
  second payload byte was captured -- see PROTOCOL COVERAGE's DeviceNet
  section for how this reuses EtherNet/IP's own `cip_service_name`.
- `devicenet_dup_mac_id_is_response` / `devicenet_dup_mac_id_physical_port_number`
  / `devicenet_dup_mac_id_vendor_id` / `devicenet_dup_mac_id_serial_number`:
  the Group 2 message-ID-`0x07` (Duplicate MAC ID Check) payload's own
  Request/Response bit, Physical Port Number, and little-endian Vendor
  ID/Serial Number, present only when that payload shape was decoded (not a
  CAN FD frame, and at least 7 payload bytes present).
- `devicenet_fd`: `true`/`false`, always present when `protocol` is
  `devicenet` -- `true` for a CAN FD frame, in which case only the
  CAN-ID-derived fields above are populated; the payload is not
  semantically decoded (see PROTOCOL COVERAGE's DeviceNet section and
  LIMITATIONS).
- `devicenet_payload_truncated`: `true`/`false`, always present when
  `protocol` is `devicenet` -- `true` when the underlying SocketCAN
  record's own payload was shorter than its declared Payload Length (a
  snaplen-truncated or otherwise short capture).
- `devicenet_payload_length` / `devicenet_payload_hex`: the payload's byte
  count and hex rendering (clamped to whatever was actually captured),
  always present when `protocol` is `devicenet` -- this decoder never
  value-decodes the payload beyond the Group 3 header/service bytes and
  Group 2 Duplicate-MAC-ID-Check fields above.

### csv

Header row followed by one row per packet:
`index,timestamp,src_mac,dst_mac,src_mac_vendor,dst_mac_vendor,src_ip,src_hostname,src_port,src_port_service,dst_ip,dst_hostname,dst_port,dst_port_service,protocol,summary,notes`.
Fields are quoted per standard CSV rules when they contain a comma, quote, or
newline; multiple notes are joined with ` | ` inside the single `notes` field.
`src_mac`/`dst_mac` are empty for a non-Ethernet-linktype capture, exactly
like `src_ip`/`dst_ip` are empty for a non-IP packet; every
`*_vendor`/`*_hostname`/`*_service` annotation column is an empty field on a
lookup miss or when that resolution is disabled (never a placeholder like
`"unknown"`) -- see "Name resolution" below.

### Name resolution (OUI / hostname / service name)

`decode` (only -- see LIMITATIONS) can optionally annotate the raw
MAC/IP/port values it decodes with a human-readable name, in all three
output formats: a resolved name is always shown *in addition to* the raw
value, never in place of it, and a lookup that finds nothing adds nothing to
the output (no `"(unknown)"`/`null`/empty-placeholder noise) -- this is a
security/OT auditing tool, so the ground-truth address or port that was
actually observed on the wire stays visible exactly as decoded, always.
There are three independent lookups, each its own flag, each with its own
default:

- **OUI / MAC vendor** (`src_mac_vendor`/`dst_mac_vendor` in JSON, the
  `(vendor)` annotation on `decode`'s text-format `eth` line and CSV's
  `src_mac_vendor`/`dst_mac_vendor` columns) -- **on by default**, disabled
  with `--no-oui`. Looked up against a large table built into the
  `conduitscope` binary itself; no external file, network access, or extra
  flag is needed. This table is generated ahead of time by
  `tools/generate_oui_table.py` from a fetched copy of the nmap project's
  `nmap-mac-prefixes` file (`github.com/nmap/nmap`), which itself aggregates
  the IEEE Registration Authority's three public MAC address block
  registries -- MA-L (the classic 24-bit OUI), MA-M (28-bit), and MA-S
  (36-bit) (`standards.ieee.org/products-programs/regauth`) -- not fetched
  live at build time or run time; refreshing it against a newer IEEE
  registry snapshot is a manual, offline step (rerun that script, commit the
  regenerated `include/conduitscope/oui_table.gen.hpp`).
- **Hostname** (`src_hostname`/`dst_hostname` in JSON and CSV, the
  `(hostname)` annotation after an IP on `decode`'s text-format summary
  line) -- **off by default**, enabled with `--resolve`. **File-only: this
  never performs live DNS resolution of any kind, under any flag
  combination.** The only source of a hostname is an explicitly-supplied
  Unix `/etc/hosts`-style file, given with `--hosts FILE`:
  ```
  # comment
  192.168.1.10   plc-01
  192.168.1.50   hmi-01   hmi-01.plant.example   # aliases after the first name are ignored
  ```
  One IP + at least one name per line, whitespace-separated; `#` starts a
  comment (whole-line or trailing); a line whose address doesn't parse as a
  strict IPv4 dotted-quad is silently skipped (IPv6 hosts entries are not
  supported, matching this whole codebase's IPv4-only scope). Only the first
  name after the address is used; if the file has more than one line for
  the same IP, the first one wins, matching a real `/etc/hosts`' own
  behavior. `--resolve` given with no `--hosts` is a harmless no-op --
  hostname resolution has nothing to resolve against, so no hostname
  annotation is ever produced -- and prints a one-line advisory note (once,
  respecting `--quiet`) rather than being treated as an error, since it's
  more likely an oversight than something worth failing the run over.
  Deliberately never live DNS: an unsolicited DNS query from the analysis
  workstation, reaching an OT segment's own resolver or leaking out to the
  internet while auditing traffic that was very likely captured specifically
  because the network shouldn't be touched carelessly, is exactly the kind
  of side effect an offline forensic/audit tool must not have -- it would
  also make `decode`'s own output non-reproducible run-to-run as DNS records
  change. `--hosts` is a static snapshot the operator supplies and can audit
  themselves, nothing more.
- **Service name** (`src_port_service`/`dst_port_service` in JSON and CSV,
  the `(name)` annotation after a port on `decode`'s text-format summary
  line) -- **on by default**, disabled with `--nn` (named after the
  long-standing `nc`/`nmap`/`tcpdump`-family `-n`/`-nn` "don't resolve
  names" convention). Looked up first against an explicitly-supplied Unix
  `/etc/services`-style file (`--services FILE`, if given), falling back to
  a small, curated table built into the binary:
  ```
  # name          port/proto
  hmi-modbus-client   51000/tcp
  custom-modbus       502/tcp
  ```
  One name + `port/proto` (`tcp` or `udp`) per line, whitespace-separated,
  `#` comments as above; a malformed line is silently skipped. If the file
  repeats an entry for the same port/protocol, the last one in the file
  wins -- unlike the hosts file's first-wins rule, since this file's whole
  purpose is deliberately overriding the built-in table (and itself). The
  built-in table is **deliberately small and hand-curated, not an
  exhaustive IANA services dump** -- there is no single canonical "the"
  port/service mapping the way there is for OUIs (many ports are reused for
  unrelated purposes by different organizations), so pretending to be
  exhaustive here would just be a confident-looking source of wrong answers.
  It covers exactly two things: every OT/ICS protocol port `decode` already
  defaults to (Modbus/DNP3/S7comm/MMS/IEC104/EtherNet/IP/CIP
  I/O/BACnet/HART-IP/OPC UA/MQTT/FF-HSE), and a modest set of common general
  IT/OT-adjacent ports (FTP, SSH, DNS, DHCP, HTTP/HTTPS, NTP, SNMP, RDP, and
  similar) for surrounding context on a capture that mixes OT traffic with
  ordinary infrastructure traffic. `--services` is the documented way to
  extend or override it for anything this table doesn't cover.

Scope: this is `decode`-only. `policy validate`'s report is not (yet)
enriched with any of these annotations -- see LIMITATIONS and ROADMAP.

## PROTOCOL COVERAGE

### Modbus/TCP

Fully decoded: Read Coils (0x01), Read Discrete Inputs (0x02), Read Holding
Registers (0x03), Read Input Registers (0x04), Write Single Coil (0x05), Write
Single Register (0x06), Write Multiple Coils (0x0F), Write Multiple Registers
(0x10), and exception responses (function code with the 0x80 bit set) with
named exception codes (Illegal Function, Illegal Data Address, Illegal Data
Value, Server Device Failure, Acknowledge, Server Device Busy, Memory Parity
Error, Gateway Path Unavailable, Gateway Target Device Failed to Respond).

Recognized by name but shown as raw hex rather than fully decoded: Read
Exception Status (0x07), Diagnostics (0x08), Report Server ID (0x11), Mask
Write Register (0x16), Read/Write Multiple Registers (0x17), Read FIFO Queue
(0x18), Encapsulated Interface Transport (0x2B, which covers Read Device
Identification among other sub-functions).

Every decoded packet also gets authoritative (transaction-ID + TCP-session,
non-heuristic) request/response pairing where its counterpart is present in
the capture, layered on top of the always-on payload-shape heuristic -- see
PROTOCOL DETECTION for exactly how, and LIMITATIONS for what it doesn't
cover.

### DNP3

Detected reliably (via the 0x05 0x64 start bytes) and its data-link-layer
header is decoded: source and destination DNP3 addresses (16-bit DNP3
station addresses, NOT IP addresses -- exposed as `dnp3_source_address`/
`dnp3_destination_address` in JSON output, always set whenever
`protocol == "dnp3"`, even for a link-layer-only control frame with no
user data at all; see JSON OUTPUT FIELDS and POLICY FILE FORMAT's
"Addressing scope" section for why this matters on a serial-to-IP DNP3
gateway multiplexing several outstations behind one shared IP), the raw
control byte, and the frame length field (broken down into the resulting
transport/application-layer byte count), plus the header CRC-16, which is
now genuinely calculated and validated against the on-the-wire value (see
"Data-link CRC-16 validation" below).

On top of the data link layer, conduitscope reassembles the user data (data
link frames split it into <=16-byte blocks, each with its own CRC-16, now
also genuinely calculated and validated per block, not just located and
skipped) and decodes the **transport header** (1 byte: FIR/FIN
fragment-boundary flags and a 6-bit sequence number) for every data-link
frame that carries any user data at all.

DNP3 frames are small (<=255 bytes on the wire), so it's normal for a sender
or the OS to coalesce two or more complete data-link frames into a single TCP
segment before flushing. conduitscope looks for every complete data-link
frame present in a TCP payload, not just the first -- each gets fully
decoded (data link through point values), and if more than one is found, a
note says so and identifies each additional frame; the packet's one-line
summary and its `dnp3_function`/JSON fields still reflect only the *first*
frame's function code, with every frame's objects and values merged into
`dnp3_objects`/`dnp3_values`. This is purely a within-one-TCP-payload framing
fix and doesn't require any cross-packet state.

The **application layer** -- function code, Internal Indications (IIN) on
responses, and every object header's group/variation/qualifier/range -- is
then decoded. For a fragment that is complete within a single data-link
frame (transport FIR=1 and FIN=1, which covers the large majority of real
traffic, especially requests), this happens immediately. For a fragment that
continues across multiple data-link frames (FIR=1 on the first, FIN=0 until
the last), conduitscope buffers each frame's application-layer bytes,
per TCP flow (source and destination IP:port), across however many packets
it takes for the rest to arrive -- including when later frames land in
*separate* TCP segments, not just later in the same one -- and decodes the
full application layer once a frame with FIN=1 completes it. This is real
cross-packet state (unlike the coalescing above): it depends on every
packet in the flow being decoded, in capture order, through the same
`Decoder` instance, which is exactly what the CLI does (see
`Decoder::process_dnp3_frame` in `decoder.hpp`/`decoder.cpp` for the state
machine, and its per-flow buffer caps against a pathological/malformed
capture). It is deliberately narrow, and says so in its notes rather than
guessing, in every case where it can't proceed with confidence: a
continuation frame's sequence number that doesn't follow the previous
frame's discards the in-progress buffer instead of concatenating bytes out
of order; a continuation frame with no matching start (capture begins
mid-fragment, or a start frame was lost) is left transport-header-only; and
a new FIR=1 frame arriving on a flow with an already-in-progress,
never-completed reassembly abandons the stale one rather than merging into
it. This is distinct from -- and independent of -- TCP stream reassembly
for the *link layer itself* (a data-link frame's own header and
CRC-delimited blocks split across TCP segments), which conduitscope does
now also do, via a separate, lower-level mechanism (`Decoder::reassemble_tcp_payload`);
see LIMITATIONS.

Function codes are identified by name across the whole DNP3 function code
table (Confirm, Read, Write, Select/Operate/Direct Operate, the Cold/Warm
Restart and application-control functions, file functions, authentication
functions, and the three response codes 0x81/0x82/0x83). For a response
function code, the 16-bit IIN field is decoded into its individual flag names
(e.g. `DEVICE_RESTART`, `NEED_TIME`, `PARAMETER_ERROR`) rather than shown as
a bare hex value.

Object headers are decoded structurally: group and variation (with a name for
the common object groups -- Binary/Double-bit Binary/Analog/Counter Input and
Output, Class Objects, Internal Indications, and others), the qualifier's
index-prefix and range codes, and the resulting range or explicit count.

For the group/variation combinations in the built-in point-format table --
covering the object types common in real traffic -- every point's **value is
also decoded**, not just its byte length:

- **Binary/Double-bit Binary Input and Output** (groups 1, 3, 10): the point
  state (on/off, or the double-bit Intermediate/DeterminedOff/DeterminedOn/
  Indeterminate enum), plus the standard quality flags (`ONLINE`, `RESTART`,
  `COMM_LOST`, `REMOTE_FORCED`, `LOCAL_FORCED`, `CHATTER_FILTER`) for the
  variations that carry them.
- **Counter and Frozen Counter** (groups 20-23, including their Event
  variants): the 16- or 32-bit value, quality flags (adding `ROLLOVER` and
  `DISCONTINUITY`), and an absolute timestamp for the Event variants that
  carry one.
- **Analog Input, Frozen Analog Input, Analog Output, and their Event
  variants** (groups 30-34, 40-42): the 16-/32-bit integer or 32-/64-bit
  floating-point value, quality flags (adding `OVER_RANGE` and
  `REFERENCE_ERR`), and a timestamp where the variant carries one.
- **CROB, the Control Relay Output Block** (group 12 variation 1) -- the
  object used to issue output commands, so getting this one right matters
  more than most: control code (Pulse On/Off, Latch On/Off), trip/close,
  queue/clear bits, operation count, on-time and off-time in milliseconds,
  and the status code (`Success`, `Timeout`, `Not Authorized`, and the rest
  of the standard IEEE 1815 control-status table).
- **Time and Date** (group 50 variation 1): the 48-bit absolute timestamp,
  rendered as an ISO-8601 UTC calendar date/time (reusing MQTT Sparkplug's
  own `format_millis_epoch`, since both are milliseconds-since-epoch --
  see LIMITATIONS) with the raw millisecond count kept alongside it.
- **Internal Indications as an object** (group 80 variation 1): each point
  decoded against the same IIN flag-name table used for the application
  layer's own IIN field.

The quality-flags byte layout and the CROB field layout are cross-checked
against the Wireshark `packet-dnp.c` dissector's `AL_OBJ_BI_FLAG*`/
`AL_OBJ_CTR_FLAG*`/`AL_OBJ_AI_FLAG*`/`AL_OBJCTLC_*` constants, not
reverse-engineered from a single capture -- these are the documented,
standard DNP3 wire formats, not an EXPERIMENTAL reconstruction like the
S7comm `0xB2` decode.

An object header outside the point-format table still gets its object data
length computed (from a bits-per-point table covering a superset of the
value-decoded groups) and **skipped structurally** rather than value-decoded,
so later object headers in the same fragment stay correctly aligned. Either
way, an object header shape this release doesn't recognize at all -- an
object-size-prefixed or reserved qualifier prefix code, a group/variation
combination outside the lookup table, a bit-packed format paired with a
non-zero index prefix, or a declared object data length that doesn't fit in
what's left of the fragment -- stops object parsing for that fragment with an
explanatory note, rather than guessing at where the next header would start.
A batch of more than 200 points in one object header only gets the first 200
individually decoded (the object's byte length is still fully accounted for
either way); a note says so when it happens.

**Data-link CRC-16 validation:** both CRCs described above -- the 8-byte
header CRC and every <=16-byte user-data block's own CRC -- are now genuinely
calculated and compared against their on-the-wire value, not just located and
skipped as in an earlier release. The header CRC covers the first 8 bytes of
the data-link header (the two start bytes, length, control, destination,
source, i.e. everything before the CRC field itself); each user-data block's
CRC is checked individually, not cumulatively, so a bad CRC on one block of a
multi-block frame doesn't taint the others. Exposed in JSON as
`dnp3_header_crc_valid` (the header CRC alone), `dnp3_block_count` /
`dnp3_block_crc_failures` (how many <=16-byte blocks this frame had, and how
many of those failed), and `dnp3_link_crc_valid` (true only when the header
AND every block validated) -- see OUTPUT FORMATS' JSON field reference below.
A mismatch never stops decoding or drops the frame, consistent with this
tool's degrade-gracefully-and-keep-going philosophy applied elsewhere in this
codebase (a malformed object header, a truncated frame, S7comm-Plus's
array-of-Struct refusal): it's flagged via those fields plus a specific
`notes` entry naming both the calculated and the on-the-wire value, e.g.
`"header CRC mismatch: calculated 0x8aca, frame declares 0x7535"` or
`"block 2 CRC mismatch (7 data byte(s)): calculated 0xdcf9, frame declares
0x2306"`, and decoding proceeds using the on-wire bytes exactly as it did
before this feature existed. The algorithm itself (a reflected CRC-16,
polynomial `0x3D65`, seed 0, with the running register's final bitwise
complement) is cross-checked against Wireshark's own `wsutil/crc16.c`
implementation and against the independently-known CRC-16/DNP catalogue
reference test vector (the CRC of ASCII `"123456789"` must be `0xEA82`) via a
compile-time `static_assert` sitting right next to the CRC table in
`dnp3.cpp` -- a mistranscribed table, wrong seed, or missing final complement
fails the build outright rather than shipping a silently-incorrect
validator.

Real-world confirmation, independent of the synthetic fixture: this tool's
own real DNP3 captures (`dnp3_read.pcap`, and every other fixture in
`tests/real_captures/dnp3/`) exercise this against genuine CRC bytes computed
by independent DNP3 stacks, not just bytes `tools/make_sample_pcap.py`
produced -- and they validate cleanly, a strong end-to-end confirmation the
algorithm/table genuinely matches the DNP3 spec rather than just this
project's own generator. One of those real captures also turned up a
genuinely interesting, honest finding, not a clean pass across the board: the
Request Link Status response frame present in both `dnp3_request_link.pcap`
and `dnp3_request_link_status.pcap` fails header-CRC validation
(`dnp3_header_crc_valid: false`, an on-the-wire CRC of `0x0000` against a
different calculated value) -- and that same frame's own `length_field` is
`0`, which is itself spec-non-conformant (IEEE 1815 requires `length_field >=
5` to cover control+destination+source alone, before any user data at all).
This is pre-existing behavior in the capture that the new validator surfaces,
not something this feature broke or a false positive: the frame was already
structurally odd, and the CRC check is doing exactly its job by calling that
out rather than silently accepting it.

**Security relevance:** on a live serial-to-IP DNP3 link, a bad data-link CRC
can mean either ordinary line noise on the serial leg of a gateway, or
evidence of tampering/injection on the wire -- this decoder surfaces the
mismatch as a fact (which frame, which CRC, calculated vs. declared) rather
than asserting either cause; telling them apart is an analyst judgment call
this tool deliberately doesn't make on your behalf, the same posture this
codebase already takes with every other "flagged, not diagnosed" finding.
**Not wired into `policy validate`:** CRC validity is purely diagnostic/
informational in `decode` output today -- `PolicyEngine` does not factor a
bad DNP3 CRC into a flow's allowed/violation verdict at all. This is a
distinct, separate gap from the DNP3 link-address gap POLICY FILE FORMAT's
"Addressing scope" subsection documents (that one is about the outstation/
master address never reaching the zone engine; this one is about CRC
validity never reaching it either) -- see that subsection and ROADMAP.

Validated against both a large real 4SICS ICS-lab capture and a set of real
(not synthetic) DNP3 captures from independent DNP3 stacks -- real CROB
Select/Operate sequences including a rejected operate (`status=Not
Supported`), a real polling session exercising Binary Input/Output/Counter/
Internal-Indications objects, and a deliberately corrupted/fuzzed capture
that must degrade gracefully rather than crash or fabricate a value. See
`tests/real_captures/dnp3/ATTRIBUTION.md` for exact provenance. None of these
captures happened to contain a fragment split across multiple data-link
frames, so multi-data-link-frame reassembly (see LIMITATIONS and ROADMAP)
remains untested against real traffic.

### S7comm / COTP (Siemens S7 PLCs, TCP port 102)

The TPKT (RFC 1006) and COTP (ISO 8073 / X.224) framing that S7comm always
rides on is decoded in full: the TPKT length, the COTP PDU type (Data,
Connection Request, Connection Confirm, Disconnect Request/Confirm, or an
"other" catch-all), and -- for Connection Request/Confirm, which carry the
TSAP session-setup parameters rather than S7comm itself -- the calling and
called TSAP values. A packet that parses at this level but doesn't turn out
to carry S7comm is reported as protocol `cotp` rather than `s7comm`.

A COTP Data (DT) frame's own EOT (end-of-TSDU) bit is also tracked per TCP
flow (`Decoder::reassemble_cotp_data_frame`, `decoder.cpp`): a single S7comm
message that doesn't fit one negotiated PDU length gets chained across
several *complete* TPKT/COTP frames -- every frame but the last has EOT=0,
the last has EOT=1 -- and this decoder concatenates their user data into one
buffer before attempting the S7comm decode, rather than only ever seeing the
first frame's own bytes. This is a different, higher layer than the general
TCP-segment reassembly described under LIMITATIONS: there, one TPKT frame's
own bytes are split across TCP segments; here, every individual TPKT frame
is itself complete, and it's the *logical S7comm message* inside them that
spans more than one. While a fragment is incomplete, the packet is reported
as protocol `cotp` with a "buffering"/"beginning"/"continuing" note; the
completing packet gets a "reassembled..." note naming how many frames and
bytes were chained. See LIMITATIONS for exactly what this does and doesn't
cover, and for what real-traffic validation this has (and hasn't) had.

Within S7comm itself (protocol id `0x32`): the fixed header is always fully
decoded -- ROSCTR (Job/Ack/Ack_Data/Userdata), PDU reference, parameter and
data lengths, and the error class/code carried by Ack and Ack_Data frames.
The function code (Read Var, Write Var, PLC Control/Stop, Request/Download
Block, Start/End Upload, CPU services, and others, all listed in the source)
is always identified by name. **Setup Communication** (the handshake every S7
session opens with, negotiating the max parallel jobs and PDU size) is fully
decoded, since it's simple, fixed-size, and universal.

**Read Var / Write Var** -- the two function codes that make up the
overwhelming majority of real S7comm traffic (see the traffic mix in the
worked example under EXAMPLES) -- get full item-level address decoding using
the classic S7ANY addressing syntax (syntax id `0x10`): which memory area
(inputs, outputs, merkers/flags, a numbered data block, an instance data
block, local data, counters, or timers), DB number where applicable, byte and
bit address, and transport size (BIT/BYTE/WORD/DWORD/INT/DINT/REAL/...) each
item addresses. This is rendered in familiar Step 7 notation -- `DB10.DBW100`
(word 100 of DB10), `DB10.DBX100.0` (a single bit), `I0.0`, `QB2`, `MW10`,
`T5`, `C3` -- alongside the returned values (Read Var responses) or written
values (Write Var requests) themselves. A request can batch many items in one
PDU (real PLCs commonly do); the summary line shows the first few and the
full list is always in the decoded packet's notes.

**`0xB2`, S7-1200/1500 "symbolic" addressing**, also gets a tag -- confirmed
to be the addressing syntax you're actually most likely to see in real
S7-1200/1500 traffic -- but via an **EXPERIMENTAL, unverified** decode,
clearly labeled `[EXPERIMENTAL]` everywhere it appears (the summary line, the
per-item note, and the JSON `s7comm_items` array). Unlike
S7ANY, this syntax doesn't carry a plain byte/bit address on the wire: TIA
Portal compiles each symbolic tag reference down to an opaque CRC-like value
(not recoverable to the original symbol name from the capture alone) plus a
"LID" (local id) field. No authoritative byte-layout documentation was found
for this syntax -- what's implemented is a reconstruction from Wireshark's
`S7COMM_SYNTAXID_1200SYM` field/area-code constants, cross-checked against
an independent parser's minimum item length, and validated against real
capture traffic for exactly one shape: a single LID entry addressing the
Merker (M) area, where five sequential real requests decoded to `M2.0`
through `M2.4` -- consistent both internally (fixed fields identical across
items, only the address-carrying bytes varying) and with how a real PLC
program would batch a run of related status bits. It has *not* been
confirmed against real DB-area traffic or an item with more than one LID
entry; both of those recognized-but-unconfirmed shapes fall back to raw hex
rather than guessing further. Treat every `[EXPERIMENTAL]` tag as a
plausible reconstruction, not a certainty -- see LIMITATIONS. Every other
syntax id is recognized (by id) but not decoded at all, same as every other
function code's parameter/data payload -- so is the entire Userdata
parameter block used for vendor-specific diagnostics/CPU functions.

**PLC Control (`0x28`) / PLC Stop (`0x29`)** -- two function codes long
recognized only by name (see the function-code table above) -- now get their
parameter blocks decoded too. **PLC Stop** is the wire-level mechanism
behind a well-known, unauthenticated ICS attack: an S7comm session needs no
authentication of its own at the protocol level, so issuing this single
function code against an S7-300/400 class CPU halts its program execution --
the exact technique tools like Metasploit's `s7_stop` module automate. The
request's confirmation string (in real traffic, literally the ASCII text
`"PLC_STOP"`) is decoded and shown as-is, whatever text is actually present;
the Ack/Ack_Data (response) side is deliberately left without a special
decode, matching Wireshark's own `packet-s7comm.c` dissector, which doesn't
special-case it either.

**PLC Control** is the general "Program Invocation" (PI-Service) mechanism
-- one function code covering an entire family of named services, several of
them just as security-relevant as PLC Stop: `_INSE`/`_INS2` activate a
compiled logic block (a DB/FC/FB/OB) on a live controller, and `_DELE`
removes one from the CPU's passive file system -- this is literally how
logic gets pushed to or pulled from a running PLC over the wire, again with
no protocol-level authentication. For these three block-management services,
the full block descriptor list is decoded: one
`"<type><number> (<destination>)"` entry per block in the parameter block
(e.g. `"DB100 (Passive)"`, `"FC5 (Active)"`), naming the block type, number,
and destination filesystem (Passive/Active/both). For `P_PROGRAM` (PLC
Start/Stop), `_MODU` (copy RAM to ROM), and `_GARB` (compress PLC memory),
the raw ASCII argument string is decoded as-is but deliberately **not**
semantically interpreted -- no attempt is made to claim a given argument
value means, say, "cold restart" vs. "warm restart" -- matching the same
restraint the upstream Wireshark dissector (the reference source for this
decoder's wire-layout facts) applies to the identical argument bytes. Every
PI service name, not just these six, is looked up against a name+description
table transcribed from Wireshark's own `pi_service_names[]` array, including
the large `_N_*` Sinumerik/CNC-specific service family (login, file
transfer, tool/magazine management, and more) -- but for that family it's a
name+description lookup only, deliberately with no parameter-block decode:
dozens of per-service argument layouts, all specific to CNC machine-tool
control rather than ordinary PLC control, a scope boundary documented in
`s7comm.hpp`'s file header, the same honest-scoping convention this decoder
already applies to `0xB2`'s unverified shapes above. Only a subset of
Wireshark's own ~65-entry table is transcribed here -- the six PLC-control
services above plus the most commonly-seen/clearly-documented `_N_*`
entries -- since several of Wireshark's own `_N_*` descriptions are
themselves too terse or unclear to transcribe with any confidence, and the
family is out of scope for parameter decoding regardless; a PI service name
outside this subset still gets its raw name shown (never invented or
guessed at), just with an empty description. The Ack_Data (response) side
of PLC Control also gets a small status-flags byte decoded, when the
response's parameter block is long enough to carry it: bit `0x01` ("more
data of the block/file can still be retrieved") and bit `0x02` ("an error
occurred"). A handful of bytes in both function codes' fixed layout are
simply unknown/reserved -- Wireshark's own dissector doesn't document their
meaning either, so this decoder doesn't invent one here either.

The `M2.0`-`M2.4` shape above was later checked against the *entire* 140MB
source capture it came from, not just the five originally spot-checked
requests: over 1 million real `0xB2` items, all through the structural path
with zero fallbacks. That's meaningfully more confidence the structural
shape holds for a full real session, but it's still one real PLC/HMI
session, not several independently different ones -- see
`tests/real_captures/s7comm/ATTRIBUTION.md` for exactly how that traces back
to the same original finding, including a correction of an initial
overclaim (while pulling this data) that it was independent traffic.

**S7comm-Plus** (protocol id `0x72`, the newer, TIA-Portal-native protocol
S7-1200/1500 CPUs use) rides this exact same transport but is a materially
different, object-oriented protocol -- see its own dedicated section below
for the full decode this codebase now gives it.

Also validated against 14 additional real (not synthetic) S7comm captures
from independent sources -- classic S7ANY item decoding up to nearly 9,000
items in one capture, and confirmation that traffic named after S7-1200/1500
HMI hardware in this set actually turned out to be S7comm-Plus, not classic
S7comm, despite its naming (now a real-world validation case for the
S7comm-Plus decoder below, not just a detection-stub regression guard). See
`tests/real_captures/s7comm/ATTRIBUTION.md` for exact provenance and for the
`0xB2` finding described above -- also where the COTP EOT-chaining finding
described below is documented.

The EOT-chaining reassembly described above turned out to have real-traffic
evidence too, though in a narrower shape than originally expected: several of
these real captures precede almost every Read Var response with a zero-byte,
EOT=0 "priming" COTP Data frame immediately before the real EOT=1 frame
carrying the actual message -- confirmed present across multiple independent
devices, not an artifact of one capture. Concatenating zero buffered bytes
with the real frame's own bytes is indistinguishable from not chaining at
all, so this exercises the *reassembly machinery* (buffer-then-complete,
correctly, transparently, without a decode change) but not genuine
multi-frame *content* splitting -- no real capture checked for this project
splits an actual S7comm message's content across the chain. That case is
covered only by the synthetic `tests/sample_s7comm_chaining.pcap` (scenario
A splits real register values mid-byte across the join). See LIMITATIONS.

**Modbus/TCP** is likewise validated against real (not synthetic) captures
now, not just the hand-built fixtures -- a clean Read Holding Registers
session, and traffic exercising several function codes outside current scope
(Diagnostics, Report Server ID, Read Exception Status, and others) that must
degrade to a "not decoded" note rather than be misparsed. See
`tests/real_captures/modbus/ATTRIBUTION.md`. The same capture also confirms
authoritative transaction-ID pairing (see PROTOCOL DETECTION) against a real
request/response session, not just the synthetic fixtures.

### S7comm-Plus (Siemens TIA Portal / S7-1200/1500's newer protocol, TCP port 102, shares TPKT/COTP transport with S7comm)

S7comm-Plus rides inside a COTP Data (DT) frame's user data -- the SAME
TCP port 102, TPKT/COTP transport classic S7comm and MMS share -- but it is
a wholly different, much newer application protocol, introduced with the
S7-1200/1500 generation of PLCs and TIA Portal, identified by its own
protocol id byte (`0x72` vs. classic S7comm's `0x32`) rather than any
negotiated presentation-context or session type. Unlike classic S7comm's
fixed-format ROSCTR/function/parameter/data layout, S7comm-Plus is
object-oriented on the wire: requests and responses name numeric "IDs" (of
objects, attributes, or symbol references) and carry self-describing typed
values, more reminiscent of MMS's own `Data` CHOICE or OPC UA's own Variant
than of S7ANY's fixed item layout.

**Sourcing, and an honesty note.** Unlike every other protocol this codebase
supports, S7comm-Plus has never been officially published by Siemens: there
is no standards document, no ASN.1 module, no XML/CSV table this decoder's
tag tables could be generated from (contrast MMS's own ISO 9506-2 module, or
OPC UA's own `NodeIds.csv`/`StatusCode.csv`). Every byte-layout fact this
decoder asserts is instead sourced from the open-source Wireshark plugin
`packet-s7comm_plus.c`, written by Thomas Wiens -- the SAME author as
classic S7comm's own mainline Wireshark dissector this codebase already
cross-checks `s7comm.cpp` against -- and itself the product of years of
public, community reverse-engineering effort (it has never been merged into
mainline Wireshark, unlike classic S7comm's own `packet-s7comm.c`, confirmed
by checking mainline Wireshark's own `dissectors/CMakeLists.txt`). This
decoder is an independent implementation, not a port of that plugin, but it
does not claim any confidence beyond what that plugin's own source comments
claim -- several of them, hedged in the original German ("*scheint*" =
"seems to be", "*z.Zt. unbekannt*" = "currently unknown"), are carried
through honestly rather than rounded up to false confidence.

#### Wire structure

```
Header (4 bytes)      protocol id (0x72) + PDU type (Connect/Data/DataFW1_5/Keep Alive)
                         + [Keep Alive only: 1-byte sequence number + 1 reserved byte] or
                         [everything else: 2-byte big-endian Data Length]
Data part              (Connect/Data/DataFW1_5 only -- absent for Keep Alive)
  opcode (1 byte)      Request (0x31) / Response (0x32) / Notification (0x33) / Response2 (0x02)
  reserved(2) + function code (2 bytes BE) + reserved(2) + sequence number (2 bytes BE)
  Request only: session id (4 bytes) + 1 reserved byte; Response/Response2: 1 reserved byte
  function-specific body
  Integrity part       near the end of most Data/Response bodies: an id plus what is presumed
                         to be a SHA-256-sized digest (32 bytes) of the telegram -- surfaced,
                         never verified, same posture this codebase already takes toward
                         HART-IP's own checksum (DNP3's data-link CRCs, by contrast, ARE
                         validated -- see PROTOCOL COVERAGE's DNP3 section)
Trailer (4 bytes)      protocol id + PDU type + Data Length, mirroring the header
```

A complete S7comm-Plus telegram always ends with that trailer. A telegram
can be split across several TPKT/COTP frames (a large CreateObject upload or
Explore response, mainly); per the reference plugin's own reassembly state
machine, that split is signalled by the ABSENCE of the trailer, NOT by
COTP's own End-of-TSDU bit -- i.e. a captured COTP Data frame can be a
complete, EOT=1 COTP PDU while still carrying only an incomplete S7comm-Plus
telegram. This decoder's usual COTP-level reassembly (shared with classic
S7comm/MMS, keyed on COTP's own EOT bit) is therefore NOT sufficient by
itself for S7comm-Plus, and this decoder does not additionally implement
S7comm-Plus's own above-COTP, trailer-based reassembly (a genuinely
separate, TCP-session-keyed state machine in the reference plugin) -- a
telegram missing its trailer is reported as such (`"summary": "Data
(fragment, awaiting further data)"`, plus a note) with whatever of the Data
part fits in that one frame decoded, rather than guessed at across frames it
hasn't seen. See LIMITATIONS.

#### Two-tier function coverage

Same two-tier split this codebase already applies to MMS (18 of 78 services)
and OPC UA (Tier 1/Tier 2):

**Tier 1 -- fully decoded, both directions:**

- **GetMultiVariables (`0x054c`) / SetMultiVariables (`0x0542`)** -- the
  actual variable read/write traffic that dominates real S7comm-Plus
  captures, TIA Portal's functional replacement for classic S7comm's Read
  Var/Write Var. Item addresses are S7comm-Plus's own native symbolic
  addressing -- a CRC-like hash of the compiled symbol name plus a chain of
  "LID" (local id) values identifying struct/array members. This is NOT the
  same thing as classic S7comm's own EXPERIMENTAL `0xB2` "symbolic" syntax
  (see above) -- that was an unconfirmed reconstruction of a convention
  embedded inside a DIFFERENT protocol's item syntax; here the CRC+LID
  layout IS S7comm-Plus's actual native addressing scheme, decoded with
  confidence, not experimentally. What IS an inherent, protocol-level
  limitation (not a decoding uncertainty) is that a LID's or CRC's SYMBOLIC
  MEANING -- which tag name it refers to -- depends on TIA Portal's own
  compiled project database, which never appears on the wire; this decoder
  renders the numbers faithfully but cannot resolve them to tag names, the
  same "can't resolve an opaque identifier without out-of-band context"
  limitation this codebase already accepts for DNP3/IEC 104 point indices or
  OPC UA NodeIds. GetMultiVariables also has a second, distinct request
  shape -- a "subscribed link" item-number list, rather than a full item
  address list -- both decoded.
- **SetVariable (`0x04f2`) and DeleteObject (`0x04d4`)** -- simple enough (a
  bare object id, or an id plus one self-describing value) to fully decode
  both directions.
- **The self-describing "Value" encoding** used throughout: a 1-byte
  datatype-flags/array-kind byte (scalar/array/address-array/sparse-array),
  a 1-byte datatype code, an optional array size, and then that many typed
  values -- every datatype the reference plugin's own switch statement
  recognizes is decoded here too (Null/Bool/USInt/UInt/UDInt/ULInt/SInt/
  Int/DInt/LInt/Byte/Word/DWord/LWord/Real/LReal/Timestamp/Timespan/RID/
  AID/Blob/WString/Variant/Struct), INCLUDING nested STRUCT values --
  recursed, with the same kind of depth cap MMS's own `Data`-value decoder
  already uses, for the same reason: an attacker-controlled or corrupt
  capture must not be able to blow the C++ call stack. `S7String` (`0x19`)
  is the one datatype the reference plugin's own generic value switch does
  NOT implement either (its own comment says it is "only for
  tag-description", a separate, far more complex function this decoder does
  not implement) -- shown as an unrecognized datatype, honestly, rather
  than guessed at, and the whole Data part decode degrades gracefully (a
  "decoding stopped" note) rather than losing the whole packet. An
  **array of Struct values** is a real but rare shape this decoder
  deliberately refuses to decode -- delimiting N separate per-element
  nested member lists isn't something this implementation (or, seemingly,
  the reference plugin itself) cleanly supports, so it throws and degrades
  gracefully rather than risk silent byte misalignment.
- **The ReturnValue status code** every Response/Response2 body starts with:
  a packed value whose low 16 bits are a signed error code -- decoded with
  confidence (it is what every response's success/failure hinges on), with
  the rest of the 64-bit value surfaced as a raw note rather than asserted
  bit-for-bit for OMS-line/error-source/debug-info sub-fields the reference
  plugin itself only comments on informally.

**Tier 2 -- recognized (function/PDU type named, session id/sequence number
decoded, Integrity/Trailer still decoded) but body not decoded:**

- **CreateObject (`0x04ca`)** -- the single most complex shape in this
  protocol, a full, deeply nested TIA Portal block definition.
- **Explore (`0x04bb`), GetLink (`0x0524`), BeginSequence/EndSequence
  (`0x0556`/`0x0560`), Invoke (`0x056b`), GetVarSubStreamed (`0x0586`)** --
  each has its own bespoke body shape not implemented here.
- **Notification (opcode `0x33`)** -- S7comm-Plus's own cyclic/subscribed
  variable-change-of-value feed, a materially different body shape from the
  Request/Response envelope above (no function code, no session id).
- **Connect (PDU type `0x01`)** -- the session-establishment handshake,
  including (per real-world research, not this decoder's own decode) a
  random-nonce/session-id exchange and, on TIA Portal V13+/
  firmware-encrypted sessions, a Diffie-Hellman-style key exchange this
  decoder makes no attempt to parse.
- **DataFW1_5 (PDU type `0x03`, firmware >= V1.5)** -- per the reference
  plugin's own source comments, this variant moves the Integrity part from
  the end of the Data part to a different position near the front, in a
  shape the plugin's own author describes as awkward to place in its own
  output tree -- and, critically, the plugin's own byte-accounting for
  where the function-specific body then starts is not something this
  decoder could independently confirm with confidence. Rather than risk a
  wrong offset silently producing a plausible-looking but incorrect decode,
  this decoder decodes ONLY the outer header (PDU type, Data Length,
  trailer presence) for DataFW1_5 and shows its entire Data part as raw
  hex -- a deliberately more conservative scope cut than PDU type Data's
  own Tier 1/Tier 2 split above.

#### Real-world validation

Two real captures -- `s7comm_plus_1511_db3_var1_hmi.pcap` and
`s7comm_plus_1511_opc_request_all_types.pcap`, originally added to this
project only to validate the OLD "detected, not decoded" stub -- were
re-decoded once this full decoder existed. `db3_var1_hmi` is genuinely rich
real HMI traffic: GetMultiVariables (both the symbolic-addressing and
subscribed-link request shapes), SetMultiVariables (including a genuinely
nested Struct-of-Struct value with a `WString` member and a 360-byte
`Blob`), and DeleteObject all exercise Tier-1 decoding correctly, with
Connect and GetVarSubStreamed correctly recognized as Tier-2. It also
repeatedly exercises this decoder's above-COTP, trailer-based reassembly
DETECTION on real traffic (every SetMultiVariables request here arrives
split across 2 TPKT/COTP frames). `opc_request_all_types` lives up to its
name: a single 40-item GetMultiVariables request/response pair walks nearly
every datatype this decoder knows in one call. **Zero per-item decode
errors, zero `ParseError`-triggered fallbacks, in either file.** See
`tests/real_captures/s7comm/ATTRIBUTION.md`'s own S7comm-Plus addendum for
the full writeup, including which shapes (KeepAlive, DataFW1_5,
Notification, CreateObject, Explore, GetLink, BeginSequence/EndSequence,
Invoke, a DeleteObject response, array-of-Struct, Sparsearray) remain
validated only against the synthetic fixture (`tests/sample_s7commplus.pcap`,
built by `tools/make_sample_pcap.py`'s own `build_s7commplus_sample()`) since
neither real capture happened to exercise them.

This project's own code review -- not real-capture validation -- caught two
genuine correctness bugs before this decoder was ever built or tested: the
array-of-Struct misalignment risk described above (now a deliberate,
explicit refusal), and an unsigned-integer-underflow risk in a
truncated-frame length calculation (`data.size() - kHeaderLen` when
`data.size() < kHeaderLen`, fixed by clamping via the already-established
`available_after_header`/`data_take` pattern used elsewhere in `s7comm.cpp`).

### IEC 61850 MMS (Manufacturing Message Specification, ISO 9506, TCP port 102, shares TPKT/COTP transport with S7comm)

MMS always rides inside a COTP Data (DT) frame's own user data on TCP port
102 -- the SAME transport and port S7comm uses -- but it is not S7comm: it
is a full, independent ISO/OSI application built on three more layers
stacked on top of COTP, each with its own ASN.1 BER TLV encoding:

```
COTP Data frame user data
  -> ISO 8327-1 Session Protocol       (one SPDU: type + length + optional parameters)
    -> ISO 8823 Presentation Protocol  (CP-type/CPA-type at association time, or a bare
                                         "fully-encoded-data" wrapper on every later message)
      -> ISO 8650-1 ACSE               (AARQ/AARE/RLRQ/RLRE/ABRT -- association-time only)
        -> MMS (ISO 9506)              (the actual application PDU -- Initiate, Read, Write,
                                         GetNameList, Report, ... -- the payload this decoder exists to reach)
```

This decoder walks all four layers to reach the MMS PDU, decoding enough of
Session/Presentation/ACSE to correctly locate the next layer's bytes and to
surface genuinely useful association-time detail (which abstract
syntaxes/application-context were negotiated, whether the association was
accepted), then gives the MMS PDU itself the deepest decode in this file --
including, unlike this codebase's own OPC UA decoder's Variant/DataValue
gap, MMS's own "Data" value type (see below): this decoder does NOT leave
MMS's actual read/write/report VALUES undecoded. Sourcing was cross-checked
against ISO 8327-1/8823/8650-1's own tables (via Wireshark's
`packet-ses.h`/`packet-pres.c`/`packet-acse.c`, themselves generated
directly from each layer's own ASN.1) and MMS's own ISO 9506-2 ASN.1 module
(via Wireshark's own `mms.asn`, the source its `asn2wrs` compiler consumes
to generate `packet-mms.c`) -- the same "generated from the standard's own
machine-readable grammar" sourcing standard already applied to OPC UA's
`NodeIds.csv`/`StatusCode.csv`. Every tag number was additionally confirmed
byte-for-byte, by hand, against real captured traffic (`tshark -V`/`-x`),
both this decoder's own `libiec61850`-generated fixture traffic and genuine
real-world captures -- see `tests/real_captures/mms/ATTRIBUTION.md`.

#### Structural detection gate: three shapes

Since MMS shares S7comm's exact transport and port, it is only attempted
once S7comm's own, stronger, single-byte protocol-id gate (`0x32`/`0x72`)
has already failed (`want_s7comm || want_mms` in `decoder.cpp`). This
decoder then recognizes three distinct shapes in the COTP Data frame's own
user data:

- **A full Session-layer SPDU** -- the leading SI byte is a plausible ISO
  8327-1 SPDU type (`1`-`64`, `CLSES_UNIT_DATA(64)` being the highest
  one-byte type the standard defines). Every SPDU type this decoder
  recognizes by name (every value ISO 8327-1 and this decoder's own
  real-capture research actually found in IEC 61850 MMS traffic): CONNECT
  (CN, 13), ACCEPT (AC, 14), REFUSE (RF, 12), FINISH (FN, 9), DISCONNECT
  (DN, 10), ABORT (AB, 25), ABORT ACCEPT (AA, 26), and DATA TRANSFER / GIVE
  TOKENS (both genuinely share SPDU type 1 on the wire -- which one an
  implementation "means" is a session-layer token-passing distinction this
  stateless decoder does not track, so it consumes any number of
  consecutive SI=1/LI=0 pairs generically and labels the shape "DATA
  TRANSFER / GIVE TOKENS" rather than confidently picking one). Any other
  SPDU type is still structurally consumed (byte alignment for whatever
  follows stays correct) but shown only by its raw type number.
- **"Bare MMS"** -- the COTP Data frame's own user data begins directly
  with an MMS PDU's own tag byte: CONTEXT-class, tag number 0-13 --
  constructed `0xA0`-`0xAD` for 11 of the 14 `MMSpdu` alternatives
  (`SEQUENCE`-typed, so constructed on the wire), or primitive
  `0x80`-`0x8D` for the remaining 3 (`cancel-RequestPDU`/
  `cancel-ResponsePDU ::= Unsigned32`, `conclude-RequestPDU`/
  `conclude-ResponsePDU ::= NULL`) -- confirmed against real captures (see
  Validation below). Since every valid Session SPDU type is a small number
  (1-64) and every MMS top-level PDU tag is CONTEXT-class with the class+
  constructed-or-not bits at `0x80` or above, there is no ambiguity: this
  decoder checks the Session-SPDU shape first and falls back to bare MMS
  only when that check fails.
- **"Bare Presentation"** -- Session is skipped entirely, but
  Presentation-layer bytes are still present: CP-type/CPA-type (UNIVERSAL
  SET, `0x31`), fully-encoded-data (APPLICATION 1 constructed, `0x61`), or
  simply-encoded-data (APPLICATION 0 primitive, `0x60`). A small number of
  real, independently-encoded stacks omit the Session-layer "ubiquitous
  SI=1" marker(s) entirely on an ongoing Data-Transfer message once an
  association is established.

If none of the three match, this decoder does not claim the traffic as MMS
at all and falls through to the generic COTP/S7comm handling. The upper
SPDU-type bound above is deliberately `64`, not the looser `< 0x80` a first
pass at this decoder used: `0x61` (97 decimal, Presentation's own
fully-encoded-data tag) is less than `0x80` and was genuinely mistaken for a
third, bogus SPDU by that looser check -- a real collision this decoder's
own validation pass found in `iec61850_read.pcap`'s own ongoing
Data-Transfer frames (two concatenated SI=1/LI=0 pairs immediately followed
by Presentation bytes), see "Two real structural-gate bugs" below.

#### Session, Presentation, and ACSE layers

**Session (ISO 8327-1)**: one SPDU = SI (1 byte, the SPDU type) + LI (1
byte -- a plain length, 0-254; `255` is reserved to mean "2-byte extended
length follows", never observed in real traffic and not implemented).
Session parameters use their own nested PGI/PI TLV scheme, not ASN.1 BER;
this decoder walks that list generically for every SPDU type that carries
parameters and specifically extracts PGI 193 ("Session user data") or 194
("Extended user data") when present -- that parameter's own content IS the
next layer's bytes.

**Presentation (ISO 8823)**: at association time, a CP-type/CPA-type SET
containing a presentation-context-definition-list (a SEQUENCE OF
{presentation-context-identifier, abstract-syntax-name OID,
transfer-syntax-name-list}), decoded into "context N = `<OID>` (`<name>`)"
values (e.g. `"context 1 = 2.2.1.0.1 (ACSE)"`, `"context 3 = 1.0.9506.2.1
(mms-abstract-syntax-version1)"`). Every SPDU's own "user-data" CHOICE field
is then unwrapped -- only the "fully-encoded-data" alternative (APPLICATION
1 constructed, `0x61`) is implemented, a SEQUENCE OF PDV-list, each PDV
being {presentation-context-identifier, presentation-data-values CHOICE},
of which only the "single-ASN1-type" alternative (CONTEXT 0, `0xA0`) is
implemented -- the only shape this decoder's own research (spec text and
every capture examined) ever found in practice. "Simply-encoded-data"
(APPLICATION 0) is recognized as a distinct, valid shape but shown as raw
hex, not decoded further.

Resolving which presentation-context-id means ACSE vs. MMS is where this
decoder's stateless-per-message design meets a real limit: it cannot
remember a context-definition-list negotiated in an earlier Connect frame
while decoding a later ongoing Data-Transfer frame that references a
context-id by number alone. In every capture this decoder's own research
examined, the negotiated numbering is identical -- context-id 1 = ACSE,
context-id 3 = MMS -- the de-facto universal convention essentially every
IEC 61850 MMS stack uses. This decoder assumes that convention for any
Data-Transfer PDV whose own frame has no in-message context-definition-list
to resolve against -- an honestly-stated assumption, corroborated by every
real capture checked, not a guess invented for this decoder (see
LIMITATIONS).

**ACSE (ISO 8650-1 / X.227)**: present only on an association-
establishment/release frame, never an ongoing Data-Transfer message (those
carry MMS directly at presentation-context 3). All five top-level ACSE APDU
tags are recognized -- AARQ (APPLICATION 0, `0x60`), AARE (APPLICATION 1,
`0x61` -- the same byte value as Presentation's own fully-encoded-data tag;
disambiguated purely positionally, since ACSE tags are only dispatched on
after Presentation's own content is already unwrapped), RLRQ (APPLICATION
2, `0x62`), RLRE (APPLICATION 3, `0x63`), ABRT (APPLICATION 4, `0x64`) --
and decodes application-context-name (an OID, always `1.0.9506.2.3` for
MMS/IEC 61850 traffic), AARE's own result
(accepted/rejected-permanent/rejected-transient) and result-source-
diagnostic, and, the field this decoder actually needs, user-information
(CONTEXT 30, `0xBE`): a SEQUENCE OF EXTERNAL whose first entry's own
"encoding" CHOICE, when single-ASN1-type (CONTEXT 0, `0xA0` -- the only
alternative implemented, the only one ever observed), contains the MMS PDU
itself (Initiate-RequestPDU inside an AARQ, Initiate-ResponsePDU inside an
AARE). AARQ/AARE's calling/called-AP-title and AE-qualifier fields, when
present, are surfaced as plain OID/integer values without resolving
AP-title-form1 further than "present, structurally skipped" (never observed
in this decoder's own research); the authentication-value field is
structurally skipped, not decoded (never observed either, and safely
skippable per ACSE's own EXPLICIT tagging without losing byte alignment).

#### MMS layer: MMSpdu, Tier 1 vs. Tier 2 services, and the Data value type

`MMSpdu` is a CHOICE of 14 alternatives, each its own CONTEXT-class
constructed tag 0-13 (`0xA0`-`0xAD`): confirmed-RequestPDU(0),
confirmed-ResponsePDU(1), confirmed-ErrorPDU(2), unconfirmed-PDU(3),
rejectPDU(4), cancel-RequestPDU(5), cancel-ResponsePDU(6),
cancel-ErrorPDU(7), initiate-RequestPDU(8), initiate-ResponsePDU(9),
initiate-ErrorPDU(10), conclude-RequestPDU(11), conclude-ResponsePDU(12),
conclude-ErrorPDU(13).

**initiate-RequestPDU/ResponsePDU** -- the MMS analog of this codebase's own
S7comm "Setup Communication" / OPC UA OpenSecureChannel -- are decoded in
full: localDetail(Calling/Called), proposedMaxServOutstanding(Calling/
Called), proposed/negotiatedDataStructureNestingLevel, and the nested
InitRequestDetail/InitResponseDetail's own version number and two BIT
STRING capability fields (ParameterSupportOptions -- str1/str2/vnam/valt/
vadr/vsca/tpy/vlis/real/cei -- and ServiceSupportOptions, one bit per
confirmed service, ~85 bits), with every SET bit surfaced by name.

**confirmed-RequestPDU/ResponsePDU** always carry an invokeID (an
application-chosen correlation number, never itself correlated back to the
request it answers across packets -- see "Deliberately not implemented"
below) and a ConfirmedServiceRequest/Response CHOICE selecting one of 78
defined confirmed services. This decoder's own dispatch table names every
one of the 78 and splits them into two tiers:

- **Tier 1** (full field decode -- 18 services): `status`, `getNameList`,
  `identify`, `read`, `write`, `getVariableAccessAttributes`,
  `defineNamedVariableList`, `getNamedVariableListAttributes`,
  `deleteNamedVariableList`, `getDomainAttributes`, `getCapabilityList`,
  plus the seven file-transfer services `obtainFile`, `fileOpen`,
  `fileRead`, `fileClose`, `fileRename`, `fileDelete`, `fileDirectory` --
  the services this decoder's own research found are (a) universally
  present in real IEC 61850 MMS traffic or (b) the most OT-security-
  relevant of MMS's remaining services (the file-transfer group IEC
  61850's own COMTRADE/disturbance-file-retrieval and firmware/
  configuration-file-transfer workflows ride on -- see ROADMAP item 12),
  and each is (c) simple enough to decode with full confidence. Tier 1
  also covers unconfirmed-PDU's own informationReport (see below) and
  every one of rejectPDU/cancel-*/conclude-* (each small and fully
  specified).
- **Tier 2** (service name + invokeID only, body shown as raw hex): every
  other confirmed service -- `rename`, `defineNamedVariable`,
  `defineScatteredAccess`, `getScatteredAccessAttributes`,
  `deleteVariableAccess`, `defineNamedType`, `getNamedTypeAttributes`,
  `deleteNamedType`, `input`, `output`, `takeControl`,
  `relinquishControl`, every semaphore/event-condition/event-action/
  event-enrollment/journal/program-invocation/domain-download service
  -- genuinely rare in ordinary IEC 61850 process-data traffic (belonging
  more to MMS's original general-purpose industrial-messaging scope than to
  IEC 61850's own narrower profile of it), each with its own, sometimes
  large, request/response grammar this first-pass release does not
  implement field-by-field.

**The file-transfer services** (`obtainFile`/`fileOpen`/`fileRead`/
`fileClose`/`fileRename`/`fileDelete`/`fileDirectory`): `FileName` (a
`SEQUENCE OF GraphicString`) is rendered joined by `"/"`, the same
convention Wireshark's own `packet-mms.c` `dissect_mms_FileName` uses;
`FileAttributes`' own `lastModified` (a `GeneralizedTime` -- an ASCII
`"YYYYMMDDHHMMSS[.fraction][zone]"` text timestamp, NOT the same wire
shape as the Data CHOICE's own binary `utc-time[17]` above) is reformatted
to this codebase's own ISO-8601 convention when it parses, shown verbatim
otherwise; `fileData` (a raw `OCTET STRING`) is rendered as a full,
never-truncated hex dump, the same convention already used for OPC UA's
own `ByteString`. `ObtainFile-Request`'s own `sourceFileServer` (an
`ApplicationReference` -- AP-title/AE-qualifier/invocation-ids, every
field itself OPTIONAL) is structurally recognized but not deep-decoded,
the same posture this decoder's own ACSE AARQ/AARE decode already takes
for AP-title/AE-qualifier elsewhere (see "Deliberately not implemented"
below).

**The Data value type**: unlike this codebase's own OPC UA decoder (which
deliberately leaves Variant/DataValue undecoded), this decoder fully
implements MMS's own "Data" CHOICE (ISO 9506-2's own self-describing value
type, used everywhere an actual read/write/report VALUE appears on the
wire) -- 14 of its 17 defined alternatives: array/structure (recursive
SEQUENCE OF Data, tags 1/2, capped at 32 levels of recursion -- see below),
boolean(3), bit-string(4), integer(5)/unsigned(6) (BER INTEGER, sign-
extended for integer, not for unsigned), floating-point(7) (an OCTET STRING
whose first byte is the IEEE754 exponent width in bits -- 8, the only width
ever found in practice -- followed by the big-endian IEEE754 value itself;
any other declared width is shown as raw hex rather than guessed at),
octet-string(9), visible-string(10), bcd(13), booleanArray(14) (a BIT
STRING whose bits are individually rendered true/false), objId(15) (an
OBJECT IDENTIFIER), mMSString(16, a UTF-8 string -- an IEC 61850 Edition 2
addition), utc-time(17) (an 8-byte OCTET STRING -- 4 bytes
SecondsSinceEpoch + 3 bytes FractionOfSecond + 1 byte leap-seconds-known/
clock-failure/clock-not-synchronized/accuracy flags -- an IEC 61850-8-1
addition). The 3 alternatives NOT decoded, each shown as raw hex, are
real[8] (BER REAL, ISO 9506's own alternative float encoding),
generalized-time[11] (ASN.1 GeneralizedTime), and binary-time[12]
(TimeOfDay) -- none was ever observed in this decoder's own research. This
is a genuine, meaningful strength of this decoder over leaving values
opaque: the actual point values an MMS client reads or writes, and every
value inside an InformationReport, are visible in this decoder's own
output, not merely that a read/write/report happened.

**Recursion depth cap**: Data's own array/structure alternatives are
recursive. This decoder caps recursion at 32 levels -- a real,
independently-reproducible bug was found DURING this decoder's own
validation: `tshark` 4.2.2's own MMS dissector hits an internal
`recursion_depth <= 100` assertion and aborts dissection entirely on
roughly 43 of 224 frames of genuine, non-malicious, independent-stack-
generated report traffic this decoder's own research captured (see
Validation below) -- a concrete, observed reminder that an unbounded-
recursion deeply-nested Data value is a real denial-of-service surface for
any MMS parser, this decoder included were it not for this cap. Past the
cap, this decoder stops descending and shows the remaining bytes as raw hex
rather than recursing further or guessing -- never crashing, never
hanging.

**InformationReport** (unconfirmed-PDU's own [0] alternative) is this
decoder's own MMS analog of its GOOSE decoder, and IEC 61850-8-1's actual
mechanism for Buffered/Unbuffered Report Control Blocks -- decoded in
full: variableAccessSpecification (either a listOfVariable, each entry an
ObjectName rendered the same domain/item `$`-separated-path style as
GetNameList/Read/Write, or a variableListName ObjectName, including the
special, reserved vmd-specific "RPT" name real Report traffic actually
uses to mean "this report's own pre-configured dataset") and
listOfAccessResult (each entry decoded with the same Data-value decoder
used everywhere else in this file). This decoder does NOT attempt to label
which positional value in that list is RptID vs. SeqNum vs. an actual
dataset member's value -- IEC 61850's own optional-fields negotiation
(ReportedOptFlds, decided out-of-band when the Report Control Block was
configured) determines that, information this stateless-per-message
decoder does not have -- the same honest positional-list-without-field-
labels posture this codebase's own GOOSE decoder already takes for
allData.

**ObjectName rendering**: domain-specific (the overwhelmingly common IEC
61850 shape) is rendered `"domainId/itemId"` (e.g.
`"simpleIOGenericIO/LLN0$Events"`, `"simpleIOGenericIO/GGIO1$MX$AnIn1$mag$f"`
-- the itemId's own `$` separators are IEC 61850's own logical-node/
functional-constraint/data-object/data-attribute path convention, left
as-is rather than reinterpreted); vmd-specific and aa-specific are rendered
as their own bare Identifier string.

**ServiceError** (confirmed-ErrorPDU, cancel-ErrorPDU, conclude-ErrorPDU,
initiate-ErrorPDU) decodes into an errorClass category name + numeric code
(e.g. `"access(2)"` for object-non-existent) plus, when present,
additionalCode and additionalDescription -- the MMS analog of this
codebase's own S7comm error-class/error-code or OPC UA StatusCode decode.
`rejectPDU` decodes into its own originalInvokeID (when present) and
rejectReason category + specific reason name.

#### Deliberately not implemented

Stateful association/invocation tracking (correlating a later Data-Transfer
message's presentation-context-id back to an earlier Connect frame's own
context-definition-list, or a confirmed-ResponsePDU's own invokeID back to
the confirmed-RequestPDU that invoked it) -- this decoder is, like every
other protocol in this codebase, a stateless-per-message decoder with
TCP-stream-level reassembly only (COTP's own EOT-based fragment
reassembly, already implemented for S7comm and shared as-is by MMS -- MMS
needs no reassembly mechanism of its own); Presentation-layer context
renegotiation mid-association (ISO 8823's own "presentation-context-
addition-list" extension) -- never observed in real traffic; AARQ/AARE's
own authentication-value field, structurally skipped; and, within the
file-transfer services (now Tier 1 -- see above), `ObtainFile-Request`'s
own `sourceFileServer` (`ApplicationReference`) is structurally recognized
but not deep-decoded. `Address` (non-symbolic variable addressing, one of
VariableSpecification's own two alternatives alongside `name`) is likewise
structurally recognized but shown only as `"address=<Address, not
decoded>"`, not decoded field-by-field, since real IEC 61850 traffic
overwhelmingly addresses variables by symbolic `name` instead.
`TypeSpecification` (part of defineNamedVariableList/
getVariableAccessAttributes-response) is likewise recognized as present but
shown only as `"typeSpecification=<TypeSpecification, not decoded>"`. Both
`Address` and `TypeSpecification` remain open items -- see ROADMAP item 12.

#### Validation

Two real bugs this validation pass caught, both in this decoder's own
first-pass structural detection gate (documented in full, in this
project's own exact framing, in `tests/real_captures/mms/ATTRIBUTION.md` --
summarized here): first, the "bare MMS" gate originally required the
leading byte's constructed bit to be set, reasoning correctly but
incompletely that 11 of the 14 `MMSpdu` alternatives are `SEQUENCE`-typed
and so constructed on the wire -- the remaining 3
(`cancel-RequestPDU`/`cancel-ResponsePDU ::= Unsigned32` and
`conclude-RequestPDU`/`conclude-ResponsePDU ::= NULL`) are primitive, and
`mms-cancelRequest.pcap`'s own genuine `cancel-RequestPDU`/
`conclude-RequestPDU` frames were silently missed (falling back to the
generic `cotp` label) until this pass caught it; fixed by dropping the
constructed-bit requirement entirely, since context-class tag number 0-13
alone is sufficient (no primitive/constructed ambiguity risk -- every
alternative's own shape is fixed by its type, not chosen per-message).
Second, the Session-layer SPDU-walking loop's own "is this byte a plausible
SPDU type" check originally accepted any value below `0x80`; real traffic
in `iec61850_read.pcap`'s own ongoing Data-Transfer frames sends two
concatenated SI=1/LI=0 pairs before Presentation's own bytes begin, and
Presentation's own fully-encoded-data tag (`0x61`, 97 decimal) is less than
`0x80` and was genuinely mistaken for a third, bogus SPDU; fixed by
tightening the bound to the real ISO 8327-1 range (1-64).

Real-capture validation used four files -- three genuine real-world
historical captures from `ITI/ICS-Security-Tools`'s own
`pcaps/IEC61850/MMS - Specific Commands/` directory (the same general
ICS-security resource collection already used for other protocols in this
project), and one this project generated itself:

- **`iec61850_read.pcap`** (20 frames) -- a full association: COTP
  Connection Request/Confirm, a Session `CONNECT (CN)` SPDU carrying an
  ACSE `AARQ` (application-context-name `1.0.9506.2.3 (MMS)`, a
  presentation-context-definition-list decoding into `context 1 =
  2.2.1.0.1 (ACSE)` / `context 3 = 1.0.9506.2.1
  (mms-abstract-syntax-version1)`) wrapping an `initiate-RequestPDU` (full
  capability negotiation), a `read` confirmed-RequestPDU/ResponsePDU pair
  (`variable=mu`, a genuinely zero-length `listOfAccessResult`, hand-
  verified byte-for-byte, not a decode gap), and a
  `conclude-RequestPDU`/response pair. Two frames are genuinely malformed:
  frame 10 (the server's own ACCEPT response) declares a Session-layer
  length that doesn't match the bytes actually remaining -- hand-verified,
  and independently flagged `[Malformed Packet]` by `tshark` 4.2.2 on the
  same frame -- and this decoder degrades gracefully (falls back to the
  generic `cotp` label rather than guessing); frame 18's own
  confirmed-ResponsePDU has its `confirmedServiceResponse` field entirely
  missing after invokeID (7 content bytes total), reported as a note
  rather than guessed at.
- **`mms-takeControl.pcap`** (24 frames) and **`mms-cancelRequest.pcap`**
  (20 frames) are both "bare MMS" -- the real-world shape that motivated
  this decoder's own "Bare MMS" fallback path. `mms-takeControl.pcap`
  contains a bare `initiate-RequestPDU` followed by
  `takeControl`/`relinquishControl` confirmed-RequestPDUs (both Tier 2).
  `mms-cancelRequest.pcap` contains a bare `initiate-RequestPDU`, then a
  genuine `cancel-RequestPDU` (invokeID=1) and `conclude-RequestPDU` --
  both primitive MMSpdu alternatives, which is what caught the first bug
  above. Both files also contain COTP Data frames whose own declared
  length indicator is `0` (genuinely malformed per COTP's own framing
  rules), reported honestly as `parse-error` by this decoder's own
  pre-existing COTP layer (`cotp.cpp`, unmodified by this MMS work) --
  confirmed to be a pre-existing characteristic of the capture files
  themselves, not something this MMS work introduced, by reproducing the
  identical warning with `--protocol s7comm`.

`libiec61850_loopback_capture.pcap` is **not** a found-in-the-wild
capture -- generated by this project itself, building and running
[`mz-automation/libiec61850`](https://github.com/mz-automation/libiec61850)
(commit `96d69e9c`, a real, independent, widely-used open-source IEC 61850
stack) entirely inside this project's own development environment and
capturing the resulting loopback traffic with `tshark -i lo`: a server
running `examples/server_example_basic_io`'s own generic IO model against
four of libiec61850's own bundled example client programs in sequence,
covering model browsing, reads, writes, control operations, and periodic
report generation. Decoding it with `--protocol mms` recognizes **117 of
224 frames** as `mms` (the rest are TCP handshake/ACK-only segments and the
loopback COTP Connection Request/Confirm, correctly reported as `tcp`/
`cotp`) -- **zero parse warnings, zero parse errors, zero crashes** --
across a full association (AARQ/AARE, 8 of each), `read` (24 pairs),
`write` (13 pairs), `getNameList` (3 pairs), `identify` (1 pair),
`getVariableAccessAttributes` (4 pairs), and 17 `informationReport`s
(periodic Report Control Block traffic). One `informationReport` (frame
24) decodes a real, independently-encoded `Data` value of every kind this
decoder implements in one message: `mMSString` (`"Events1"`), `bit-string`
(`bits[1,2,3,4,8]`), `integer`, `binary-time` (correctly shown as raw hex
-- out of this decoder's own documented scope), a domain-qualified
`visible-string` dataset reference (`"simpleIOGenericIO/LLN0$Events"`),
`boolean`s, and further `bit-string`s -- independent, byte-for-byte
confirmation that `decode_data_value`'s own understanding of the `Data`
CHOICE matches a real, independent encoder's output, not only this
decoder's own synthetic fixture. Cross-checking this same capture against
tshark's own MMS dissector for ground truth is also what surfaced the
`recursion_depth <= 100` assertion-failure bug cited above under
"Recursion depth cap" -- see `tests/real_captures/mms/ATTRIBUTION.md` for
the complete writeup of both real bugs this validation pass found. See
`include/conduitscope/mms.hpp`'s file header for the full writeup.

### MQTT (v3.1/v3.1.1/v5.0, conventionally TCP port 1883) and Sparkplug B

MQTT is a general-purpose IIoT/pub-sub transport, not an OT-specific protocol on its own, but it's
increasingly how OT data reaches IT/cloud systems -- and Sparkplug B (Eclipse Tahu), an MQTT topic
and payload convention purpose-built for OT/IIoT telemetry, is squarely in this project's scope.
Both versions of the wire format predating OASIS standardization are handled: MQTT 3.1 (the
original Eclipse/IBM-era "MQIsdp" protocol name, ProtocolLevel 3), MQTT 3.1.1 (OASIS, "MQTT",
level 4), and MQTT 5.0 (OASIS, level 5).

#### Structural detection gate: honestly the weakest in this codebase

MQTT's fixed header is one byte (top nibble = Control Packet Type 1-15, bottom nibble = flags) plus
a 1-4-byte Variable Byte Integer Remaining Length. For most packet types the flags nibble must be
exactly one fixed value (`0x00`, or `0x02` for PUBREL/SUBSCRIBE/UNSUBSCRIBE); PUBLISH alone allows
all 16 values (DUP/QoS/RETAIN bits). This is a weak structural tell on its own -- weaker than
HART-IP's own documented "weakest gate in this codebase" -- so MQTT is dispatched **last** in
`decoder.cpp`'s opportunistic TCP protocol-detection chain, tried only after OPC UA, EtherNet/IP,
IEC 104, Modbus, DNP3, COTP/S7comm/MMS, and HART-IP have all declined a given TCP payload. CONNECT
gets one significant exception: this decoder additionally requires its literal Protocol Name field
to read `"MQTT"` or `"MQIsdp"` before accepting it, a much stronger, version-specific tell that
rejects CONNECT-shaped-but-bogus bytes outright rather than guessing.

This weak gate is a real, demonstrated source of false positives, not a theoretical concern: this
decoder's own synthetic test fixture (`tests/sample_mqtt.pcap`) originally included a v5 CONNACK
whose body bytes coincidentally satisfied Modbus/TCP's own `protocol_id==0` tell with a large,
plausible-looking (if wrong) MBAP length -- caught and fixed by tightening Modbus's own
`kMaxPlausibleMbapLength` cap (300 bytes) to apply to its final decode gate, not just its
TCP-reassembly-length gate (see `src/modbus.cpp`); and a SUBSCRIBE/UNSUBSCRIBE pair whose packet
identifier happened to read as a "plausible" HART-IP message type/id, absorbing it into HART-IP's
own reassembly buffering. Both are documented, fixed collisions between this decoder's own
synthetic MQTT traffic and other, earlier-dispatched protocols' own gates -- not merely a warning
that such collisions are theoretically possible.

#### Version disambiguation

Most MQTT packet types are self-describing from their own bytes alone: CONNECT states its version
explicitly (Protocol Name + Level); CONNACK, PUBACK/PUBREC/PUBREL/PUBCOMP, UNSUBACK, DISCONNECT,
and AUTH all have a version-independent shortcut encoding (e.g. CONNACK's body is exactly 2 bytes
for pre-v5, more for v5's own Properties section). Only **SUBSCRIBE, SUBACK, and UNSUBSCRIBE** are
genuinely ambiguous -- v5 adds an unconditional Properties section (even when empty, still a
1-byte-minimum Property Length of `0`) that 3.1/3.1.1 lack entirely, and nothing else in either
shape rules the other out on its own. This decoder resolves that ambiguity two ways, in order:

1. **Per-TCP-session version tracking** (`Decoder::mqtt_session_version_`, keyed by source/
   destination IP+port pair in either direction -- the same `tcp_session_key` helper Modbus's own
   transaction pairing uses): any CONNECT seen anywhere on a session, in either direction, updates
   that session's tracked version for every later packet on it, including further packets coalesced
   into the very same TCP payload. A CONNECT declaring ProtocolLevel 3 (MQTT 3.1) or 4 (3.1.1) is
   tracked identically -- their SUBSCRIBE/SUBACK/UNSUBSCRIBE/PUBLISH wire shapes are identical, the
   only wire-visible 3.1-vs-3.1.1 difference is in CONNECT's own fields (see the real-capture
   validation finding below, which is exactly what caught this decoder's own gap here).
2. **A per-packet-type heuristic**, used only when no CONNECT was ever seen on this session in this
   capture (e.g. the capture starts mid-session): SUBSCRIBE and UNSUBSCRIBE try parsing both shapes
   and prefer whichever parses to a fully self-consistent result (a valid v5 Properties block
   followed by at least one well-formed topic filter, vs. a clean v3.x-shaped filter list); SUBACK
   is explicitly documented and tested as the **least reliable** of the three, since its own body is
   just a flat list of single reason-code bytes -- almost any byte value looks "valid" whichever
   shape is assumed, so a short or degenerate reason-code list can misresolve (a real, expected
   limitation, not silently hidden -- see `mqtt_version_heuristic_suback_weakest_evidence` in
   `CMakeLists.txt`). A PUBLISH on a session with no known version is decoded assuming no Properties
   section, with an explicit note that a genuine v5 session's own leading Properties block would be
   misread as the start of the application payload in that case.

Every decision -- tracked or heuristic, and which heuristic evidence won -- is recorded in `notes`,
never silently guessed.

#### MQTT5 Properties

A single, generic, table-driven decoder (`decode_properties` in `src/mqtt.cpp`) handles all 27
defined MQTT5 Property Identifiers across every packet type that can carry them (CONNECT, CONNACK,
PUBLISH, PUBACK/PUBREC/PUBREL/PUBCOMP, SUBSCRIBE/SUBACK, UNSUBSCRIBE/UNSUBACK, DISCONNECT, AUTH),
covering all seven of the spec's own property value types (Byte, Two/Four-Byte Integer, Variable
Byte Integer, UTF-8 String, UTF-8 String Pair -- User Property -- and Binary Data). An unrecognized
property identifier doesn't abort the whole message: it's shown as `"(unknown property id N, K
remaining properties byte(s) not decoded: <hex>)"` and decoding continues.

#### Sparkplug B: a hand-rolled Protocol Buffers reader

Sparkplug B's own payload is Google Protocol Buffers (proto2), and this decoder has no external
protobuf dependency (consistent with the whole project's zero-required-dependency design) -- so
`src/mqtt.cpp` implements a small, purpose-built protobuf wire-format reader (varint, tag = field
number + wire type, the four wire types Sparkplug actually uses) against the exact
`org.eclipse.tahu.protobuf.Payload`/`Metric` schema (sourced verbatim from
`github.com/eclipse-tahu/tahu`'s own `sparkplug_b.proto`), not a general-purpose protobuf decoder.
The topic namespace itself (`spBv1.0/{group_id}/{message_type}/{edge_node_id}[/{device_id}]`, or
the separate `spBv1.0/STATE/{host_id}` namespace carrying plain JSON text, not protobuf) is parsed
independently of the MQTT layer above it.

A deliberate Tier 1/Tier 2 split on Sparkplug's own `DataType` enum, mirroring the same pattern this
codebase already uses for OPC UA's/MMS's service coverage: Int8 through UInt64, Float, Double,
Boolean, String, DateTime, Text, and UUID are fully value-decoded (Tier 1) -- including the
non-obvious detail that `int_value`/`long_value` are raw `uint32`/`uint64` wire values, **not**
zigzag-encoded, so a negative signed value must be reinterpreted from its two's-complement bit
pattern (matches Eclipse Tahu's own reference client behavior; see `render_sparkplug_metric`'s own
comment and the `mqtt_sparkplug_nbirth_metrics` test's Int32 `-5` case). Bytes, File, DataSet,
Template, PropertySet/PropertySetList, and every Array variant are Tier 2: recognized and counted,
shown as `"<N byte(s), not decoded further>"` rather than parsed field-by-field. A malformed or
truncated Sparkplug payload degrades gracefully -- whatever metrics parsed before the failure are
still shown, with an honest note about what went wrong, rather than aborting the whole PUBLISH or
crashing (`mqtt_sparkplug_malformed_payload_note` test).

#### A deliberate security finding: CONNECT's cleartext credentials

Like this codebase's OPC UA Identity Token decode, CONNECT's own Username/Password fields (when
present) are decoded and shown in cleartext in `mqtt_values` -- this is a deliberate design choice,
not an oversight: MQTT's own Username/Password fields carry no confidentiality of their own (TLS is
what protects them on the wire, and this decoder doesn't attempt TLS interception), so showing them
plainly is both accurate to what the wire actually carries and directly useful for exactly the kind
of security review this project targets (spotting unencrypted MQTT broker credentials in a
capture).

#### Deliberately not implemented

Retained-message tracking, Will Message delivery correlation, and QoS 2 exactly-once delivery-state
tracking across packets (this decoder is, like every protocol in this codebase, a stateless-per-
message decoder with TCP-stream-level reassembly only -- it decodes each PUBREC/PUBREL/PUBCOMP on
its own, it does not track which QoS 2 flow they belong to); MQTT-SN (the UDP-based MQTT variant for
constrained devices -- an entirely different wire format, out of scope); TLS decryption (as with
every protocol here, this decoder reads whatever bytes are on the wire -- it doesn't strip TLS); and
Sparkplug B's own STATE topic JSON payload is shown as raw text (`mqtt_sparkplug_state_text`), not
further parsed as JSON.

#### Validation

Real-world MQTT traffic was harder to find than this project's usual ICS/OT pcap sources: MQTT is a
general transport, not ICS-specific, so `automayt/ICS-pcap` and `ITI/ICS-Security-Tools` (this
project's usual real-capture sources) have nothing. `pradeesi/MQTT-Wireshark-Capture`, a small
personal repo made for a blog post, supplied a real Eclipse Paho client session (two container
formats, pcap and pcapng, confirmed to decode byte-for-byte identically) plus a third file from the
same source that turned out to be genuinely corrupt from its very first frame (this decoder
correctly rejects it with a clear error rather than misparsing it -- see
`tests/real_captures/mqtt/ATTRIBUTION.md` for the full byte-level analysis of exactly how it's
corrupt).

That real capture caught a genuine bug: every CONNECT in it uses **MQTT 3.1** (`ProtocolLevel=3`,
`ProtocolName="MQIsdp"`) rather than 3.1.1 -- a real, still-encountered wire shape this project's own
synthetic fixture never happened to exercise (`build_mqtt_sample()` only builds ProtocolLevel 4 and
5 CONNECTs). `Decoder`'s session-version-tracking lambda originally only recognized
`connect_discovered_version` 4 or 5, so a real MQTT 3.1 session's own SUBSCRIBE/SUBACK fell back to
the (weaker) heuristic instead of using the CONNECT that was right there, and PUBLISH carried a
spurious "version not known" note despite a CONNECT having been seen. Fixed by tracking level 3
identically to level 4 (their ambiguous-packet-type wire shapes are identical) -- see
`tests/real_captures/mqtt/ATTRIBUTION.md`'s own write-up for the complete before/after decode
output. Sparkplug B itself remains validated only against this project's own synthetic, hand-built
protobuf fixture -- a genuine, real-world Sparkplug B capture was searched for specifically and not
found; see ATTRIBUTION.md's own honest account of that search.

### IEC 60870-5-104 (TCP port 2404)

IEC 104's own layering is APCI (Application Protocol Control Information --
the fixed 6-byte frame envelope) plus, for an I-format frame only, an ASDU
(Application Service Data Unit -- the actual telecontrol data). Unlike DNP3,
an I-format APDU always carries exactly one *complete* ASDU: there is nothing
analogous to DNP3's transport FIR/FIN chaining an application fragment across
several data-link frames, so this decoder needs no cross-frame reassembly
state at all -- only the same TCP-segment-level PDU reassembly every protocol
here gets (see LIMITATIONS).

**APCI** is fully decoded for all three frame formats: **I-format**
(numbered information transfer -- the 15-bit send/receive sequence numbers
N(S)/N(R)), **S-format** (numbered supervisory acknowledgement -- N(R) only,
no payload), and **U-format** (unnumbered control -- STARTDT/STOPDT/TESTFR,
each with an `act` (activate) and `con` (confirm) variant, the six-value
handshake/keepalive vocabulary every real session uses). See PROTOCOL
DETECTION for exactly how each format's fixed control-field bit pattern is
recognized, and why IEC 104 detection specifically runs before Modbus/TCP's.

Like DNP3's small data-link frames, an IEC 104 APDU is small and it's normal
for a sender or the OS to coalesce several into one TCP segment before
flushing (an S-format ack and a U-format TESTFR often arrive alongside an
I-format APDU this way in real traffic). conduitscope looks for every
complete APDU present in a TCP payload, not just the first -- each gets
fully decoded, and if more than one is found, a note says so and identifies
each additional one; the packet's one-line summary and its
`iec104_asdu_type_name`/`iec104_cot_name`/JSON fields still reflect only the
*first* I-format APDU's ASDU, with every APDU's own information objects
merged into `iec104_objects`.

**ASDU decoding**, for an I-format APDU: type ID, the Variable Structure
Qualifier (object count, and whether Information Object Addresses are
sequential -- one explicit address then +1 per object -- or individually
addressed per object), Cause of Transmission (with a name for the standard
COT table -- periodic/cyclic, spontaneous, activation and its confirmation,
interrogated-by-station/group-N-interrogation, and the rest -- plus the Test
and P/N (negative confirmation) flags and the originator address), and the
Common (station) Address.

For the type IDs in the built-in decode table -- covering the type IDs that
dominate real traffic (see the type-ID coverage that shaped this table in
`tests/real_captures/iec104/ATTRIBUTION.md`) -- every information object's
**value is also decoded**, not just its address:

- **Single- and double-point information** (types 1/2/30, 3/4/31): the point
  state (ON/OFF, or the double-point Indeterminate/OFF/ON/Indeterminate
  enum), plus quality flags (`BL` blocked, `SB` substituted, `NT` not
  topical, `IV` invalid) shared with the state byte, and a CP24Time2a or
  CP56Time2a time tag for the `_TA_`/`_TB_` variants that carry one.
- **Step position information** (types 5/6/32): the transducer position as a
  signed 7-bit two's-complement value (`-64..+63`) plus a Transient (`T`)
  flag for a mid-transit reading, a QDS quality byte (the same
  `BL`/`SB`/`NT`/`IV`/`OV` flags measured values use -- VTI/QDS is a layout
  the spec itself shares between step position and measured values), and a
  time tag for the `_TA_`/`_TB_` variants.
- **Bitstring of 32 bit, monitoring and command** (types 7/8/33 monitoring,
  51/64 command): the raw 32-bit pattern rendered as an 8-hex-digit value
  (e.g. `0xDEADBEEF`) -- there's no further per-bit semantic decode without
  point-specific documentation of what each bit means, so the pattern is
  shown as-is rather than guessed at. The monitoring variants add a QDS
  quality byte and a time tag for `_TA_`/`_TB_`; the command variant adds
  only a time tag (`_TA_`) since a BSI command carries no quality byte.
- **Measured values -- normalized, scaled, and short-floating-point** (types
  9/34/10, 11/35/12, 13/36/14): the decoded value (normalized values also
  show the `-1..+1`-range fraction alongside the raw 16-bit integer),
  quality flags (adding `OV` overflow, shared with step position and
  bitstring above), and a time tag for every `_T_` variant -- both the
  original CP56Time2a-tagged ones (34/35/36) and the CP24Time2a-tagged ones
  (10/12/14) that fill the gap between the untagged and CP56Time2a-tagged
  forms. **M_ME_ND_1** (type 21) is the one exception worth calling out
  separately: it's the normalized value with no QDS quality byte at all --
  genuinely absent from the wire, not just unread -- so its decoded value
  carries no quality flags.
- **Integrated totals** (types 15/37/16): the 32-bit counter value, its
  5-bit sequence number, and the `CY`(carry)/`CA`(adjusted)/`IV`(invalid)
  quality bits, plus a time tag for the CP56Time2a-tagged `_TB_` variant and
  the CP24Time2a-tagged `_TA_` variant.
- **Single, double, and regulating-step commands** (types 45/58, 46/59,
  47/60), and **set-point commands -- normalized, scaled, and
  short-floating-point** (types 48/61, 49/62, 50/63) -- the object used to
  issue control actions, so getting this one right matters more than most:
  the command state (ON/OFF, step up/down, or the set-point value), the
  5-bit qualifier (no additional definition / short pulse / long pulse /
  persistent output), the Select/Execute bit, and a time tag for every
  `_T_` variant.
- **End of initialization** (type 70): the cause (local power switch on,
  local manual reset, remote reset) and whether parameters changed.
- **General interrogation** (type 100): station (general) interrogation vs.
  group 1-16 interrogation.
- **Clock synchronization** (type 103): the CP56Time2a timestamp being set.
- **Reset process** (type 105): general reset vs. reset of pending
  time-tagged information.
- **Delay acquisition command** (type 106): a plain millisecond delay
  value -- no qualifier byte, unlike most other command types.
- **Test command with time tag** (type 107): the 16-bit test sequence
  number (shown as hex) and its CP56Time2a timestamp; the untagged
  original, C_TS_NA_1 (type 104), is deliberately not decoded -- see below.
- **Parameter of measured value -- normalized, scaled, and
  short-floating-point** (types 110/111/112), and **parameter activation**
  (type 113): the same value formats as the corresponding measured-value
  types, plus a QPM qualifier byte for 110-112 (KPA "kind of parameter" --
  threshold value / smoothing factor / low limit / high limit for
  transmission, LPC "local parameter change", POP "parameter operation"),
  or a QPA qualifier for 113 (act/deact of previously loaded parameters, of
  the addressed object's own parameter, or of persistent cyclic/periodic
  transmission of the addressed object).

The SIQ/DIQ/QDS quality-bit layout, the SCO/DCO/RCO command-byte layout, and
the CP24Time2a/CP56Time2a time-tag layout are cross-checked against
lib60870-C's own source and Wireshark's `packet-iec104.c` dissector, not
reverse-engineered from a single capture. A type ID outside the decode table
still gets its ASDU header (type/VSQ/COT/common-address) decoded -- just not
its information objects, which aren't skipped-and-shown the way an
unrecognized DNP3 group/variation is (an ASDU has only one type ID for its
whole object list, so there's no "later header" whose alignment needs
preserving the way DNP3's per-header skip does).

**Deliberately not decoded, as a scope decision rather than an oversight:**
the protection-equipment event types (M_EP_TA_1/TB_1/TC_1 and their
CP56Time2a-tagged M_EP_TD_1/TE_1/TF_1 counterparts) pack several named
sub-fields -- event state, start/trip phase indicators, output circuit
indicators -- into a single SEP/SPE/OCI/QDP byte each, and this project
holds a higher confidence bar for anything describing a protection relay's
trip/event semantics than could be independently verified this round;
M_PS_NA_1 (packed single-point information with status change detection)
was left out for the same reason, since its SCD field packs 16 points'
current state and 16 points' change-detected flags into 4 bytes whose
bit-to-point ordering wasn't independently verified either. The
file-transfer ASDU type group (F_FR_NA_1 through F_SC_NB_1) is a different
kind of gap: file transfer is inherently a multi-frame, stateful exchange --
directory listing, section-by-section segment transfer, acknowledgements --
which doesn't fit this decoder's deliberately stateless one-ASDU-at-a-time
design, so it would need a redesign rather than another case in the decode
table, left for a future round if it's ever needed. Finally, C_TS_NA_1, the
original un-time-tagged test command, was skipped because C_TS_TA_1 (its
CP56Time2a-tagged successor, which this decoder does decode) supersedes it
in every real deployment and the standard itself deprecates 104 in favor of
107.

Validated against three independent real IEC 104 stacks' actual wire
encodings: the Wireshark wiki's own sample capture (a clean TESTFR/STARTDT
handshake and general interrogation cycling through a wide range of type
IDs), a simulated hydro-plant floodgate-manipulation scenario (real
command/setpoint traffic, not just monitoring), and -- most significantly for
this tool's purpose -- the public Industroyer2 capture: real, attributed
nation-state ICS malware traffic (used against a Ukrainian energy provider in
April 2022) repeatedly issuing double-command (type 46) breaker-manipulation
commands against a live RTU, almost all of which the RTU refused with a
negative activation confirmation. See
`tests/real_captures/iec104/ATTRIBUTION.md` for exact provenance. None of
these captures happened to split an APDU across a TCP segment boundary, so
that path (see LIMITATIONS) remains untested against real traffic.

**Worked example.** `tests/sample_iec104_extended_types.pcap` exercises all
21 of the newly-decoded type IDs, one spontaneous report or activation
each. Two of them, decoded with `decode --format json`: a step-position
report (type 5) and a parameter-of-measured-value activation (type 110):

```sh
$ conduitscope decode --format json --read tests/sample_iec104_extended_types.pcap
[
  ...
  {
    "summary": "I-format N(S)=0 N(R)=0; M_ST_NA_1 (Step position information) COT=spontaneous CASDU=1 objects=1",
    "iec104_asdu_type": "M_ST_NA_1 (Step position information)",
    "iec104_asdu_type_short": "M_ST_NA_1",
    "iec104_cot": "spontaneous",
    "iec104_common_address": 1,
    "iec104_objects": ["ioa=500: position=-10 [T]"],
    ...
  },
  ...
  {
    "summary": "I-format N(S)=6 N(R)=11; P_ME_NA_1 (Parameter of measured value, normalized value) COT=activation CASDU=1 objects=1",
    "iec104_asdu_type": "P_ME_NA_1 (Parameter of measured value, normalized value)",
    "iec104_asdu_type_short": "P_ME_NA_1",
    "iec104_cot": "activation",
    "iec104_common_address": 1,
    "iec104_objects": ["ioa=900: 16384 (0.5000) KPA=1 (threshold value) [LPC]"],
    ...
  },
  ...
]
```

`ioa=500: position=-10 [T]` is a tap-changer-style transducer caught
mid-transit (the `T` flag) at position -10; `ioa=900: 16384 (0.5000)
KPA=1 (threshold value) [LPC]` is a remote parameter-setting activation
changing IOA 900's threshold-value parameter to 16384 (0.5 in the
`-1..+1` normalized range), itself flagged as a local parameter change.

### EtherNet/IP (CIP explicit messaging, TCP port 44818; CIP I/O implicit messaging, UDP port 2222)

Every EtherNet/IP message is wrapped in a fixed 24-byte encapsulation header
(command, length, session handle, status, an opaque 8-byte sender context
echoed verbatim by the target, and a reserved options field) -- fully
decoded and named for all nine standard commands this groundwork release
recognizes (see PROTOCOL DETECTION for why NOP is deliberately excluded).
Like DNP3/IEC 104's small frames, it's normal for several encapsulation
messages to be coalesced into one TCP segment; conduitscope finds and
decodes every complete one present, not just the first, the same way it
does for those two protocols.

**ListIdentity** responses get their identity item decoded into
device-fingerprinting fields: vendor ID, device type, product code,
revision, status, serial number, and product name -- genuinely useful for
passive OT asset inventory, since a ListIdentity exchange is often the very
first thing an EtherNet/IP scanning tool (or a legitimate engineering
workstation) does on a new connection.

**SendRRData** (unconnected explicit messaging) and **SendUnitData**
(connected explicit messaging) carry their payload in a Common Packet
Format (CPF) item list; conduitscope walks it to locate the Unconnected
Data Item (`0x00B2`) or Connected Data Item (`0x00B1`) that holds the
actual CIP message (a Connected Address Item's 4-byte connection ID is also
recorded; other CPF item types are named but not further decoded).

**The CIP explicit message itself** -- service code, request path (EPATH:
class/instance/attribute logical segments, and the ANSI Extended Symbol
segment `0x91` Rockwell Logix5000 controllers use for named-tag addressing,
e.g. `Pump1_Speed` or `Program:Main.Timer1.ACC`) -- is decoded generically
for every recognized service, with request/response *data* also
value-decoded for a "first pass" set:

- **Generic CIP common services**: `Get_Attribute_List` (request: the
  requested attribute IDs), `Multiple_Service_Packet` (fully recursive --
  each bundled member is decoded with this same logic), and the rest of the
  common-services range (`Get/Set_Attributes_All`, `Reset`, `Start`/`Stop`,
  `Create`/`Delete`, ...) named but not further value-decoded.
- **Connection Manager services** (request path addressing Class `0x06`):
  `Unconnected_Send` -- fully recursive, decoding its embedded CIP message
  and route path -- plus `Forward_Open`/`Forward_Close`/`Large_Forward_Open`,
  named but not further value-decoded.
- **Rockwell Symbol-object tag services** -- but **only** when the request
  path's first segment is that ANSI Extended Symbol segment (i.e. a named
  tag, not a class/instance address): `Read_Tag`/`Read_Tag_Fragmented`
  (element count, and full type+value decoding of the response for the
  common fixed-size numeric elementary types -- BOOL/SINT/INT/DINT/LINT/
  USINT/UINT/UDINT/ULINT/REAL/LREAL/BYTE/WORD/DWORD/LWORD -- plus, now,
  STRING (`0xD0`) and SHORT_STRING (`0xDA`), decoded to plain text (a
  2-byte or 1-byte length prefix respectively, an empty string decoding
  correctly to an empty text entry), and Structured Data Type (any type
  code `>= 0x02A0`, Rockwell's encoding for a UDT-typed or array-of-UDT-
  typed tag) -- see below), `Write_Tag`/`Write_Tag_Fragmented` (type,
  element count, and the values being written -- same type coverage as the
  read side), and `Read_Modify_Write_Tag` (the OR/AND bit masks; its
  success response carries no data, confirmed against a real capture --
  see `tests/real_captures/enip/ATTRIBUTION.md`).

**STRING/SHORT_STRING and Structured Data Type (UDT/array) value decoding.**
STRING (`0xD0`) is a 2-byte length prefix followed by that many bytes of
text; SHORT_STRING (`0xDA`) is the same idea with a 1-byte length prefix --
both decode to plain text embedded directly in `enip_cip_values`, matching
how `bacnet.cpp`'s Character String decode embeds recognized-charset text
directly with no quoting/escaping wrapper of its own (JSON output already
runs every `values[]` entry through `output.cpp`'s own JSON string
escaping). A CIP type code `>= 0x02A0` is Rockwell/ODVA's Structured Data
Type sentinel -- Logix5000's encoding for reading or writing a UDT-typed
(or array-of-UDT-typed) tag: the type code itself carries no size/member
information, only signaling that what follows is a 2-byte Structure
Handle (a fingerprint of the UDT's member layout) then the raw struct
instance bytes. This decoder has no access to the tag's Template
definition (member names/types/offsets) -- that's obtained separately, out
of band, via a `Get_Attribute_List` exchange against the Template object,
not something tracked across packets here -- so it stops at extracting the
Structure Handle and shows the remaining member bytes as hex with an
explicit note, rather than guessing at member boundaries; this also means
an array of struct instances can't be split into one entry per element,
since there's no way to know where one instance ends and the next begins
without that same missing per-instance size information, so the whole
remaining byte range is shown as a single block. **This closes a real gap,
not just an extension**: before this release, `cip_is_plausible_type_code`
(the Read_Tag(_Fragmented) response heuristic -- see below) only accepted
the `0xC1`-`0xDE` elementary-type range, so a genuine UDT tag-read response
was wrongly rejected as "not a Rockwell tag read at all" and fell through
to the generic not-decoded path; the plausibility gate now also accepts
the `>= 0x02A0` structured range. Deliberately still **not** decoded, for
the same reasons documented in `decode_cip_structured_element`'s own
comment in `enip.cpp`: STRING2 (`0xD5`, double-byte character sets),
STRINGN (`0xD9`), STRINGI (`0xDE`, international string), and EPATH/
ENGUNIT (`0xDC`/`0xDD`) as an elementary *value* (as opposed to EPATH
appearing in a request path, already decoded above).

For example, a Read_Tag response for a STRING tag:

```json
"enip_cip_service": "Read_Tag",
"enip_cip_status": "Success",
"enip_cip_values": ["type=STRING", "PumpFault"]
```

and a Read_Tag response for a UDT-typed tag (`type=Structured Data Type
(0x02A0)`, structure handle `0x1234`, 6 bytes of member data that can't be
split further without the tag's Template definition):

```json
"enip_cip_service": "Read_Tag",
"enip_cip_status": "Success",
"enip_cip_values": ["type=Structured Data Type (0x02A0)", "structure_handle=0x1234"],
"notes": ["UDT/structured member data (6 byte(s)) not value-decoded -- this decoder has no access to the tag's Template definition (member names/types/offsets), obtained separately via Get_Attribute_List against the Template object: 01 00 2a 00 00 00"]
```

(both taken from an actual `decode --format json --read
tests/sample_enip_string_and_structured.pcap` run -- see
`tools/make_sample_pcap.py`'s `build_enip_string_and_structured_sample` for
the full six-exchange fixture, including the empty-STRING edge case and a
Write_Tag carrying a Structured Data Type value.)

That symbolic-path gating is the key scoping decision of this groundwork
release, and it's not a simplification for its own sake: several of these
service codes (`0x4C`/`0x4D`/`0x4E`/`0x52`/`0x53`) are only unambiguous in
the Symbol object's context. A real capture used to validate this decoder
shows the *exact same* service code (`0x4C`) meaning `Read_Tag` against one
object and something entirely different against a vendor-specific object
class addressed by `Class`/`Instance` -- see `tests/real_captures/enip/
ATTRIBUTION.md` for the full real-world numbers. A response carries no
request path at all, so the Read_Tag(_Fragmented) reply's disambiguation
uses a payload-shape heuristic instead (does the response data start with a
byte pair that's a plausible CIP elementary type code?), the same kind of
heuristic `modbus_tcp`'s own request/response classification uses.

A request/response whose service is recognized by name but falls outside
this "first pass" value-decoded set (including the still-out-of-scope
STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value CIP data types noted
above, and every service this decoder doesn't have a table entry for at
all) is still shown structurally -- service name and request path,
response status -- with its data shown as raw hex and an explicit note
that this groundwork release doesn't decode it further, never guessed at.

Validated against two real captures: a real Rockwell 1756-ENBT/A
ControlLogix EtherNet/IP bridge module's ListIdentity exchange, and a
larger real industrial-control-system capture dominated by
`Multiple_Service_Packet`/`Unconnected_Send`/`Read_Modify_Write_Tag`
traffic polling a mix of Symbol-object tags and a vendor-specific object
class -- see `tests/real_captures/enip/ATTRIBUTION.md` for exact
provenance, including the real numbers behind the symbolic-path-gating
decision above. Neither capture happened to split an encapsulation message
across a TCP segment boundary, so that path (see LIMITATIONS) remains
untested against real traffic, same as IEC 104's own APDU reassembly.

#### CIP I/O (implicit messaging), UDP port 2222

The real-time, cyclic I/O data exchange a prior Forward_Open (explicit
messaging, above) establishes between an originator and a target -- e.g. a
PLC scanning an I/O module's input/output assembly every few milliseconds.
Unlike explicit messaging, there is **no 24-byte encapsulation header** on
this wire at all: a UDP/2222 payload *is* a Common Packet Format item list
directly (confirmed against Wireshark's own `packet-enip.c` dissector
source -- `dissect_enipio` hands off straight to `dissect_cpf` at offset 0 --
not assumed from ODVA documentation alone; see `tests/real_captures/enip/
ATTRIBUTION.md`).

conduitscope decodes:

- **The Sequenced Address Item** (CPF item `0x8002`) fully: a 4-byte
  connection ID and a 4-byte rolling sequence number, both little-endian.
  This item is also the decoder's structural detection anchor -- see
  PROTOCOL DETECTION.
- **The Connected Data Item** (CPF item `0x00B1`), when present, is
  *located* and its length reported, but its contents are shown only as
  **raw hex, never value-decoded**. Two reasons, both deliberate: assembly/
  I/O data has no generic self-describing wire-level type at all (unlike
  explicit messaging's typed tag reads), and this decoder does not track a
  connection's negotiated transport class (Class 0 vs Class 1/2/3, set by
  the Forward_Open that established it, and not necessarily captured in the
  same pass as the I/O traffic it configures) -- which is specifically what
  would be needed to know whether a leading 16-bit CIP sequence count is
  present inside this data or not. See LIMITATIONS, and `enip.hpp`'s file
  header comment's CIP implicit messaging section, for the full reasoning.
  The CISA `icsnpp-enip` Zeek parser's own `cip_io.log` makes the same call
  (its `io_data` field is the Connected Data Item's contents unsplit) --
  see `tests/real_captures/enip/ATTRIBUTION.md`.
- **Any other CPF item type present** (most commonly Sockaddr Info,
  `0x8000`/`0x8001`) is named in a note but not further decoded -- the same
  "named but not decoded" treatment the TCP-side CPF item walk already gives
  those types.

A datagram whose first item isn't a Sequenced Address Item of exactly this
shape is left as a generic `udp` packet, not guessed at -- see PROTOCOL
DETECTION. Each datagram is decoded entirely independently: there is no
cross-datagram state (e.g. correlating a connection ID back to the
Forward_Open that established it, or tracking expected sequence-number
continuity) in this groundwork release -- see LIMITATIONS and ROADMAP.

No real capture containing genuine CIP I/O traffic was found while building
this decoder (searched across the same public pcap collections that
supplied the two real captures above, plus a couple more -- see
`tests/real_captures/enip/ATTRIBUTION.md` for exactly what was checked);
validated only by construction (`tests/sample_enip_cip_io.pcap`, see
`tools/make_sample_pcap.py`'s `build_enip_cip_io_sample`) against the wire
format as cross-checked against Wireshark's dissector source and the CISA
`icsnpp-enip` Zeek parser, not against an independent real capture the way
explicit messaging is above.

### PROFINET RT (EtherType `0x8892`)

Unlike every protocol above, PROFINET RT rides directly on raw Ethernet --
there is no IPv4/TCP/UDP layer at all. The payload immediately after the
EtherType (or after a single 802.1Q VLAN tag, already unwrapped) begins with
a 2-byte, big-endian FrameID -- the sole discriminator for everything that
follows; there is no other common header. Every multi-byte field this
decoder reads is big-endian (confirmed against Wireshark's own
`packet-pn-rt.c`/`packet-pn-dcp.c` dissector sources), matching this
codebase's other protocols (Modbus, DNP3, IEC 104, S7comm) rather than
EtherNet/IP/CIP's little-endian wire format.

FrameID ranges (cross-checked against `packet-pn-rt.c`'s own range table):

- `0xFEFC`/`0xFEFD`/`0xFEFE`/`0xFEFF` -- DCP Hello/Get-or-Set/Identify-Request/
  Identify-Response -- **fully decoded**, see below.
- `0x8000`-`0xBBFF` (unicast) / `0xBC00`-`0xBFFF` (multicast) -- cyclic
  real-time IO data -- **fully decoded**, see below.
- `0x0100`-`0x0FFF` (RTC3), `0xC000`-`0xFBFF` (RT_CLASS_UDP -- which in
  practice rides over UDP/IP, not this raw-Ethernet EtherType), `0x0020`-
  `0x0081` (Sync), `0xFC01`/`0xFC41` (Alarm High, plain/with security),
  `0xFE01`/`0xFE41` (Alarm Low, plain/with security), `0xFE02`/`0xFE42` (RSI,
  plain/with security), `0xFE03` (SXP), `0xFF00`-`0xFF01` (PTCP Announce),
  `0xFF20`-`0xFF21` (PTCP Follow Up), `0xFF40`-`0xFF43` (Acyclic RT Delay),
  `0xFF80`-`0xFF8F` (Fragmentation) -- **named only**, nothing further
  decoded (Alarm frames carry their own block structure, out of scope for
  this groundwork release).
- Anything else, including every genuinely reserved range in the table
  above -- **not recognized at all**: falls back to the generic `non-ip`
  ethertype-name-only report, exactly as before this feature existed.

#### DCP (Discovery and Configuration Protocol)

The PROFINET analog of EtherNet/IP's ListIdentity -- a device-fingerprinting/
configuration exchange an engineering tool uses to discover and configure
devices on a segment. After the FrameID: `ServiceID`(1) + `ServiceType`(1) +
`Xid`(4) + `ResponseDelay`-or-`Reserved`(2) + `DCPDataLength`(2, the byte
count of the block list that follows -- this makes a DCP PDU
self-delimited even if the Ethernet frame carries trailing minimum-frame-
size padding after it, unlike cyclic RT data below). `ServiceID`: `Get`=3,
`Set`=4, `Identify`=5, `Hello`=6. `ServiceType`: `Request`=0,
`Response-Success`=1, `Response-not-supported`=5.

The block list is `Option`(1) + `Suboption`(1) + `DCPBlockLength`(2) + that
many bytes of block-specific data, +1 pad byte if `DCPBlockLength` is odd
(word-alignment). Five Option/Suboption blocks are value-decoded -- the ones
most useful for OT asset inventory/fingerprinting: Option `0x01` (IP)
Suboption `0x01` (MAC Address) and Suboption `0x02` (IPParameter: IP +
subnet mask + gateway); Option `0x02` (Device Properties) Suboption `0x02`
(NameOfStation, ASCII), Suboption `0x03` (DeviceID: VendorID + DeviceID),
and Suboption `0x04` (DeviceRole). Any other Option/Suboption is shown as
raw hex, never guessed at.

**A real capture caught a genuine bug in this decoder before it ever
shipped.** Every Option `0x01`/`0x02` block above is preceded by an extra
2-byte `BlockInfo` (or, for a Set Request, `BlockQualifier`) field *before*
its actual content -- but only for specific (ServiceID, direction)
combinations: present for an Identify Response, a Hello, and a Get Response
(`BlockInfo`); present for a Set Request (`BlockQualifier`); absent for an
Identify Request, a Get Request, and a Set Response. An earlier draft of
this decoder, built from cross-checking Wireshark's dissector source and
several secondary write-ups, missed this entirely -- it silently produced a
station name with two leading NUL bytes and declined to decode
DeviceID/DeviceRole/IPParameter as the wrong size. Decoding a real DCP
Identify Response/Set Request exchange (see `tests/real_captures/profinet/
ATTRIBUTION.md`) against that draft surfaced the bug immediately; manually
walking the packet's own bytes against `packet-pn-dcp.c`'s
`dissect_PNDCP_Suboption_Device`/`dissect_PNDCP_Suboption_IP` confirmed the
fix. Neither field's own value is surfaced (their meaning isn't needed for
this decoder's scope) -- only their presence/absence and length are used, to
correctly locate each block's real content.

#### Cyclic RT IO data

The real-time, cyclic I/O data exchange between an IO Controller (e.g. a
PLC) and an IO Device (e.g. a remote I/O module) -- the PROFINET analog of
EtherNet/IP's CIP implicit messaging. Unlike DCP, there is **no length
field anywhere** in a cyclic RT frame: the FrameID is followed directly by
the IO data, then a fixed 4-byte trailer at the very end of the frame --
`CycleCounter`(2) + `DataStatus`(1) + `TransferStatus`(1) (field order and
byte order cross-checked against `packet-pn-rt.c`'s `dissect_pn_rt`, which
reads these three fields from `pdu_len-4`/`pdu_len-2`/`pdu_len-1`
respectively). IO data length is therefore inferred as "everything between
the FrameID and the last 4 bytes" -- which means this decoder **cannot**
tell real IO data apart from Ethernet minimum-frame-size padding if the
capture includes any (see LIMITATIONS). IO data itself is shown only as raw
hex, never value-decoded, for the same reason as CIP I/O's Connected Data
Item: no generic self-describing wire-level type, and no GSD/GSDML device
description to know an assembly's layout from.

`DataStatus`'s bits (cross-checked against `packet-pn-rt.c`'s
`dissect_DataStatus`): `0x01` State (1=Primary/0=Backup), `0x02` Redundancy
(context-dependent between Input/Output CRs, not further interpreted here),
`0x04` Data_Valid (1=Valid/0=Invalid), `0x08` reserved, `0x10`
Provider_State (1=Run/0=Stop), `0x20` Station_Problem_Indicator (1=Ok/
0=Problem), `0x40` reserved, `0x80` Ignore (1=Ignore/0=Evaluate).
`TransferStatus`: 0=OK, nonzero=ignore this frame's data.

#### Validation

DCP is validated against two real captures: fourteen real targeted DCP
Identify Requests from several independent devices on a live segment
(confirming FrameID/Xid/NameOfStation decoding against real traffic, not
just hand-built bytes), and a real Identify/Set exchange that both confirms
the decode AND is the capture that caught the BlockInfo/BlockQualifier bug
above -- see `tests/real_captures/profinet/ATTRIBUTION.md` for exact
provenance and the full bug writeup. No real cyclic RT IO data capture was
found (searched across the same public pcap collections that supplied the
DCP captures, for the same underlying reason CIP I/O's own search came up
empty: capturing the cyclic I/O scan itself requires being on the segment
during active PLC-to-I/O-device operation, a narrower window than a DCP
exchange an engineering tool can trigger on demand) -- validated only by
construction (`tests/sample_profinet.pcap`, see `tools/make_sample_pcap.py`'s
`build_profinet_sample`) against the wire format as cross-checked against
Wireshark's dissector source.

### IEC 61850-8-1 GOOSE (EtherType `0x88B8`)

Like PROFINET RT, GOOSE (Generic Object Oriented Substation Event) rides
directly on raw Ethernet -- no IPv4/TCP/UDP layer at all. The payload
immediately after the EtherType (or after a single 802.1Q VLAN tag, already
unwrapped) begins with a fixed 8-byte header, all fields big-endian:
`APPID`(2) + `Length`(2, covers the header **and** the APDU together,
including itself) + `Reserved1`(2) + `Reserved2`(2). `Reserved1`'s top bit
(`0x8000`) is the "S-bit" -- Simulated -- a header-level flag independent of
the PDU's own OPTIONAL `simulation` field below; a real IED must never set
either during normal operation, so either one being set (and especially the
two disagreeing) is itself a signal worth flagging, which this decoder does
via a note (see below).

What follows the header is an ASN.1 BER (Basic Encoding Rules) TLV-encoded
APDU. The outer tag is one of two APPLICATION-class constructed tags
(cross-checked against Wireshark's `packet-goose.c`):

- `0x61` (`goosePdu`) -- the periodic state-change multicast this decoder
  fully decodes, see below.
- `0xA0` (`gseMngtPdu`) -- a GSE Management PDU, an engineering-tool query/
  response rather than the periodic multicast -- **named only, not decoded
  further** (out of scope for this groundwork release).

Any other outer tag falls back to the generic `non-ip` ethertype-name-only
report, exactly as before this feature existed -- see PROTOCOL DETECTION.

#### IECGoosePdu fields

Every scalar field is BER IMPLICIT-tagged context-class and **primitive**
(tags `0x80`-`0x8A`); only `allData` (a SEQUENCE OF, below) is genuinely
**constructed** (`0xAB`). This matters: an initial reading of secondary
sources suggested every field used constructed encoding (`0xA0`-`0xAA`),
which would have been wrong for every field except `allData` -- caught and
corrected before shipping by writing a BER walker from scratch and running
it against real captured bytes; see `tests/real_captures/goose/
ATTRIBUTION.md` for the full writeup.

| Tag | Field | Type | Notes |
|---|---|---|---|
| `0x80` | `gocbRef` | VisibleString | The GOOSE Control Block reference identifying the publisher. |
| `0x81` | `timeAllowedtoLive` | INTEGER (ms) | How long a receiver should consider this state valid without a retransmission. |
| `0x82` | `datSet` | VisibleString | The dataset this message publishes. |
| `0x83` | `goID` | VisibleString | OPTIONAL. |
| `0x84` | `t` | UtcTime (8 bytes) | See below. |
| `0x85` | `stNum` | INTEGER | State Number -- increments only on a genuine state change. The primary anomaly-detection signal for GOOSE spoofing/replay: a value that resets or jumps outside a publisher restart is suspicious. |
| `0x86` | `sqNum` | INTEGER | Sequence Number -- increments on every retransmission at the current `stNum`, resets to 0 on the next state change. |
| `0x87` | `simulation` | BOOLEAN | OPTIONAL. See the S-bit note above. |
| `0x88` | `confRev` | INTEGER | Configuration Revision -- changes only when an engineering tool has touched this IED's GOOSE Control Block configuration. |
| `0x89` | `ndsCom` | BOOLEAN | OPTIONAL ("needs commissioning"). |
| `0x8A` | `numDatSetEntries` | INTEGER | Declared count of top-level `allData` entries; checked against the actual decoded count, mismatch noted. |
| `0xAB` | `allData` | SEQUENCE OF Data (constructed) | See below. |

BER INTEGER fields are decoded as arbitrary-length big-endian two's-
complement, up to 8 bytes with sign extension (`decode_ber_integer`) -- built
specifically because a real capture (`goose_demo_full_fields.pcap`, see
ATTRIBUTION.md) pads several INTEGER fields to 5 bytes rather than the
minimal encoding, which a fixed-width reader would have mishandled.

`t` (UtcTime, always 8 bytes): `Seconds`(4, big-endian uint32) +
`FractionOfSecond`(3 bytes, big-endian, scaled to nanoseconds the same way
Wireshark's `dissect_goose_UtcTime` does) + `TimeQuality`(1 byte, which
Wireshark itself does not decode at all -- this decoder's bit layout is
cross-checked instead against Beckhoff TwinCAT's IEC 61850 documentation and
corroborated against plausible real-world quality values in the real
captures): `0x80` LeapSecondsKnown, `0x40` ClockFailure, `0x20`
ClockNotSynchronized, `0x1F` TimeAccuracy (5-bit field).

#### `allData` (the Data CHOICE)

`allData` is a `SEQUENCE OF Data`, where `Data` is itself a CHOICE over
these tags (cross-checked against `packet-goose.c`'s `Data_choice[]`):

| Tag | Type | Notes |
|---|---|---|
| `0xA1` | `array` (constructed) | Nested `SEQUENCE OF Data` -- recursed into, dotted index path. |
| `0xA2` | `structure` (constructed) | Same as `array`, semantically a fixed-shape record rather than a repeated one. |
| `0x83` | `boolean` | |
| `0x84` | `bit-string` | First content byte = count of unused bits (0-7) in the last byte; remainder is bit data, MSB-first. Rendered as `"N-bit 0bBINARY"`, capped at 256 rendered bits. |
| `0x85` | `integer` | Same BER INTEGER decode as the PDU-level fields above. |
| `0x86` | `unsigned` | Decoded identically to `integer` (unsigned rendering). |
| `0x87` | `floating-point` | IEC 61850-7-2 FloatingPoint: an OCTET STRING whose first byte is the IEEE 754 exponent width -- `8` (single-precision, 4 more bytes) is Wireshark-confirmed; `11` (double-precision, 8 more bytes) follows the same documented rule but is not independently confirmed. Anything else is shown as raw hex with a note. |
| `0x88` | `real` | Shown as raw hex -- not further interpreted (rare/legacy type, no confirmed real-capture or authoritative-source rendering found). |
| `0x89` | `octet-string` | Raw hex. |
| `0x8A` | `visible-string` | ASCII text. |
| `0x8C` | `binary-time` | Shown as raw hex -- not further interpreted. |
| `0x8D` | `bcd` | Decoded identically to `integer` (**not** true packed BCD) -- matches Wireshark's own `dissect_goose_INTEGER` reuse for this tag. |
| `0x8E` | `booleanArray` | Decoded identically to `bit-string`. |
| `0x8F` | `objId` | Shown as raw hex -- not further interpreted. |
| `0x90` | `mMSString` | ASCII text. |
| `0x91` | `utc-time` | Same UtcTime decode as the PDU-level `t` field above. |

A nested `array`/`structure` entry's own rendered `value` reads `"(N
flattened value(s) follow)"`, with its children appearing as subsequent
entries under dotted index paths (e.g. `"2.0: boolean=false"`,
`"2.1: boolean=true"`) -- capped at a recursion depth of 6 and 200 total
values as a safety limit against a maliciously deep/wide capture. An
unrecognized tag inside `allData` is shown as raw hex with a note, rather
than skipped silently.

Multiple APDUs per frame are technically spec-legal (the declared header
`Length` covers as many as fit), but were never observed in any real capture
checked -- this decoder decodes exactly the first APDU and notes any
leftover bytes rather than attempting to decode further ones. Both the
header's `Length` field and the outer APDU TLV's own length, when they
exceed the bytes actually available (a plausibly snaplen-truncated capture),
are handled tolerantly -- clamped to what's present, with a note -- rather
than rejected outright; see PROTOCOL DETECTION.

**Explicitly out of scope**: R-GOOSE (routable GOOSE, IEC 61850-90-5, which
rides over UDP/IP with a completely different session-layer wrapper and
never reaches this EtherType-based dispatch at all) and MMS (a
different, TCP-based IEC 61850-8-1 mapping -- this tool's COTP decoding
stops at the COTP layer, see the S7comm/COTP section above). GOOSE's sibling
protocol, IEC 61850-9-2 Sampled Values (EtherType `0x88BA`), is a separate
decoder -- see the next section.

#### Validation

Validated against four real captures totaling 494 real GOOSE frames from
independent substation protection schemes (a GE F650 relay's retransmission
sequence, a maximally-field-complete single frame, and two bulk captures) --
`gocbRef`/`goID`/`stNum`/`sqNum`/`confRev`/`timeAllowedtoLive`, VLAN-tagged
framing, and the UtcTime quality-byte decode all confirmed against
hand-computed expected values; see `tests/real_captures/goose/
ATTRIBUTION.md` for full provenance and the tag-table-correction writeup.
Every real frame across all four captures happens to use the same narrow
shape, though: every field (including all three OPTIONAL ones) is always
present, and every `allData` value is only ever `boolean` or `bit-string` --
never `integer`/`unsigned`/`floating-point`/`octet-string`/`visible-string`/
`bcd`/`utc-time`, and never a nested `array`/`structure`. So optional-field
**absence**, every other `allData` type, a GSE Management PDU, a header
S-bit/PDU-simulation mismatch, a frame with more than one APDU, and a
truncated/malformed frame are all validated only against the hand-built
`tests/sample_goose.pcap` (see `tools/make_sample_pcap.py`'s
`build_goose_sample`), cross-checked against Wireshark's `packet-goose.c`
source rather than an independent real capture -- the same honest gap
already documented for PROFINET RT's cyclic IO data and EtherNet/IP's CIP
I/O implicit messaging.

### IEC 61850-9-2 Sampled Values (EtherType `0x88BA`)

SV (Sampled Values) is GOOSE's sibling protocol under IEC 61850-8-1's common
"Ethertype header" (Annex A): it rides directly on raw Ethernet -- no
IPv4/TCP/UDP layer at all -- and shares GOOSE's identical 8-byte header
format, all fields big-endian: `APPID`(2) + `Length`(2, covers the header
**and** the APDU together, including itself) + `Reserved1`(2, top-bit
`0x8000` is the S-bit, Simulated) + `Reserved2`(2). Unlike GOOSE, SV has no
PDU-level simulation flag to cross-check the header's S-bit against, so a
set S-bit is simply reported as `sv_simulated: true` with no consistency
note.

What follows the header is an ASN.1 BER TLV-encoded APDU. SV's
`SampledValues` CHOICE has only **one** alternative (cross-checked against
Wireshark's `packet-sv.c`): `0x60` (`savPdu`, APPLICATION class 0,
constructed). Any other outer tag falls back to the generic `non-ip`
ethertype-name-only report, exactly as GOOSE does -- see PROTOCOL DETECTION.

#### SavPdu fields

| Tag | Field | Type | Notes |
|---|---|---|---|
| `0x80` | `noASDU` | INTEGER | Declared count of ASDU elements in `seqASDU`; checked against the actual decoded count, mismatch noted. |
| `0xA2` | `seqASDU` | SEQUENCE OF ASDU (constructed) | See below. Context tag `1` is unused/reserved in the standard -- a genuine gap in the tag numbering, not an omission here. |

Unlike GOOSE's `allData` (which nests `Data`-choice TLVs directly with no
per-item wrapper), each element inside `seqASDU` carries its own standard
ASN.1 UNIVERSAL SEQUENCE tag (`0x30`) wrapping the ASDU's own fields. An
element whose tag isn't `0x30` is skipped with a note rather than
misinterpreted.

#### ASDU fields

Every field is BER IMPLICIT-tagged context-class and **primitive** (tags
`0x80`-`0x89`) -- there is no constructed field inside an ASDU, unlike
GOOSE's `allData`.

| Tag | Field | Type | Notes |
|---|---|---|---|
| `0x80` | `svID` | VisibleString | The Sampled Value Control Block reference identifying the publisher. |
| `0x81` | `datSet` | VisibleString | OPTIONAL. |
| `0x82` | `smpCnt` | INTEGER (0-65535) | Sample Count -- increments on every sample and wraps. The primary stream-integrity/replay-detection signal, analogous to GOOSE's `stNum`/`sqNum`. |
| `0x83` | `confRev` | INTEGER | Configuration Revision -- changes only when an engineering tool has touched this IED's Sampled Value Control Block configuration. |
| `0x84` | `refrTm` | UtcTime (8 bytes) | OPTIONAL. Same encoding as GOOSE's `t` field (see the GOOSE section above); decoded internally but, matching GOOSE's own `t` field, not yet exposed in JSON output (see LIMITATIONS). |
| `0x85` | `smpSynch` | INTEGER (enum) | OPTIONAL. `0`=none, `1`=local, `2`=global, anything else rendered as `"unknown(N)"`. |
| `0x86` | `smpRate` | INTEGER (0-65535) | OPTIONAL. |
| `0x87` | `seqData` | OCTET STRING | Mandatory -- the actual sample payload. See below: shown only as raw hex, never value-decoded. |
| `0x88` | `smpMod` | INTEGER (enum) | OPTIONAL. `0`=samplesPerNormalPeriod, `1`=samplesPerSecond, `2`=secondsPerSample, anything else rendered as `"unknown(N)"`. |
| `0x89` | `gmidData` | OCTET STRING (8 bytes) | OPTIONAL -- an IEC 61850-9-2 Ed.2.1/2020 amendment field: an EUI-64 PTP grandmaster clock identity (vendor OUI + `0xFFFE` + card ID). |

BER INTEGER fields use the same arbitrary-length big-endian two's-complement
decode as GOOSE (`decode_ber_integer`).

#### `seqData` is deliberately never value-decoded

`seqData` is shown only as raw hex plus its byte length, by design --
mirroring the established precedent this decoder already applies to
PROFINET RT's cyclic IO data and EtherNet/IP's CIP I/O Connected Data Item:
there is no generic, self-describing wire-level type to decode it as. The
common "9-2LE" profile (UCA's IEC 61850-9-2 Light Edition: 8 channels of a
4-byte INT32 value + 4-byte Quality bitmask, 64 bytes total) is an
*implementation profile* layered on top of the base standard, not something
the base ASN.1 asserts -- a `seqData` payload can legally be any length and
any internal layout under a different profile or a vendor-specific one.
Wireshark itself gates 9-2LE interpretation behind an opt-in preference
(`decode_data_as_phsmeas`, off by default), which this decoder's philosophy
mirrors exactly: decode confidently only where the wire format is
unambiguous.

#### Multiple ASDUs vs. multiple top-level PDUs

Unlike GOOSE (which decodes only the first APDU per frame, since multiple
APDUs per frame were never observed in any real capture), SV decodes **all**
ASDU elements within one frame's `seqASDU` -- multiple ASDUs per SavPdu is
core, spec-defined, always-relevant functionality (a publisher merging
several sample streams into one multicast), not a rare/untested edge case.
This matches `packet-sv.c`'s own unconditional `SEQUENCE_OF_ASDU` decode.
SV still conservatively decodes only the **first** top-level `SampledValues`
PDU per frame, matching GOOSE's own conservative handling of that separate
(and separately rare) case; both header/APDU length mismatches against the
bytes actually available are handled tolerantly -- clamped to what's
present, with a note -- rather than rejected outright, the same as GOOSE.

**Explicitly out of scope**: R-SV (routable SV, IEC 61850-90-5, a different
UDP/IP session wrapper, the same relationship R-GOOSE has to GOOSE),
IEC 61850-8-1 GOOSE (a separate decoder, see above), and MMS (a different,
TCP-based mapping).

#### Validation

Despite a genuine, multi-source search -- Wireshark's own test-capture tree
and SampleCaptures wiki, the ITI/ICS-Security-Tools, automayt/ICS-pcap, and
mrhenrike/PCAPTrafficAnalysis repositories, several IEC 61850 tooling
projects, a Zenodo substation IDS dataset, and a sample pcap attached to
Wireshark's own original SV-support GitLab issue -- **no real, publicly
downloadable IEC 61850-9-2 Sampled Values capture was found**. Every path in
this decoder is therefore validated only by construction: hand-built against
`packet-sv.c`'s dissection logic and exercised against the synthetic
`tests/sample_sv.pcap` fixture (see `tools/make_sample_pcap.py`'s
`build_sv_sample`), covering full/optional-absent field combinations, both
enumerated fields' full value sets plus their `"unknown(N)"` fallback,
multi-ASDU decoding, VLAN-tagged framing, a `noASDU` mismatch, and every
malformed/truncated-input path this section describes -- the same honest gap
already documented for CIP I/O and (partially) GOOSE. See
`include/conduitscope/sv.hpp`'s file header for the full writeup.

### EtherCAT (EtherType `0x88A4`)

Like PROFINET RT, IEC 61850-8-1 GOOSE, and IEC 61850-9-2 Sampled Values,
EtherCAT rides directly on raw Ethernet -- no IPv4/UDP/TCP layer at all.
Unlike those three, though, EtherCAT's wire format is plain
fixed-binary-layout, little-endian throughout -- there is no ASN.1/BER
encoding anywhere in it. This section, and this decoder, is cross-checked
against Wireshark's own EtherCAT plugin source (`plugins/epan/ethercat/
packet-ethercat-frame.c` and `packet-ethercat-datagram.c`, contributed by
Beckhoff Automation, the company that invented EtherCAT), byte offset by
byte offset.

#### Frame header

Exactly 2 bytes, one 16-bit little-endian word, immediately after the
EtherType (or after a single 802.1Q VLAN tag, already unwrapped):

| Bits | Mask | Field | Notes |
|---|---|---|---|
| 0-10 | `0x07FF` | `Length` | Total byte length of the datagram(s) that follow this header, NOT including the header's own 2 bytes. See "Chained datagrams" below for how this decoder uses it. |
| 11 | `0x0800` | `Reserved` | Must be zero per the spec; surfaced only as a note when set, never as a rejection. |
| 12-15 | `0xF000` | `Type` | Which of five defined frame kinds this is -- see below. |

`Type` values: `1` = "EtherCAT command" (the datagram-chain traffic this
decoder fully decodes -- by far the overwhelming majority of real EtherCAT
traffic, all 986 of 986 real frames in this decoder's real capture fixture),
`2` = "ADS", `3` = "RAW-IO", `4` = "NV" (Beckhoff's ADS protocol and other
vendor/legacy framings tunneled directly in each other's own frame shape
under this same EtherType -- named only, not decoded further), `5` =
"Mailbox" (a distinct, rarer framing occasionally used for direct
engineering-tool mailbox access without a datagram chain at all -- also
named only). Any other `Type` value (`0`, `6`-`15`) is not one of the five
the spec defines -- this decoder does not recognize the frame at all in that
case, falling back to the generic `non-ip` ethertype-name-only report (see
PROTOCOL DETECTION's "structural detection gate" discussion).

#### EtherCAT datagram fields (`Type` 1 only)

One or more of these are chained back-to-back immediately after the 2-byte
frame header, every multi-byte field little-endian:

| Field | Size | Notes |
|---|---|---|
| `Cmd` | 1 | The command -- see the Cmd table below. Determines how `Address` is interpreted. |
| `Idx` | 1 | An opaque index the sender picks and a responding slave echoes back unchanged -- lets a master match this datagram's eventual effect to the request that caused it, the EtherCAT analog of Modbus's transaction ID or GOOSE/SV's `sqNum`. |
| `Address` | 4 | EITHER `Adp`(2)+`Ado`(2) -- a 16-bit position/station/broadcast address plus a 16-bit register-or-memory offset -- for every `Cmd` except `LRD`/`LWR`/`LRW`, OR a single 32-bit logical address for those three. |
| `Len` | 2 | Another bit-field word: bits 0-10 (`0x07FF`) `Len` (byte length of `Data`), bits 11-13 (`0x3800`) Reserved (not surfaced), bit 14 (`0x4000`) `Circulating` ("frame has circulated once" -- a ring-topology loop-detection signal), bit 15 (`0x8000`) `More` (another datagram immediately follows when set -- this is the sole signal this decoder uses to know when the chain ends). |
| `Irq` | 2 | An interrupt-request bitmask (one bit per slave in some deployments); shown as a raw hex value, not decoded further. |
| `Data` | `Len` | The datagram's actual payload -- see "`Data` is deliberately never value-decoded" below. |
| `WKC` | 2 | Working Counter, immediately after `Data` (outside the 10-byte fixed header) -- starts at 0 when the master sends the frame, and every slave that successfully executed the command increments it by an amount the spec defines per command type. This is EtherCAT's primary stream-integrity signal, the closest analog to GOOSE's `stNum`/`sqNum` or SV's `smpCnt` -- but this decoder has no slave-count/topology knowledge to know what value a given command SHOULD produce on a healthy bus, so it surfaces the raw value only, no verdict. |

**Cmd table**: `0` NOP, `1` APRD (Auto Increment Physical Read), `2` APWR
(Auto Increment Physical Write), `3` APRW (Auto Increment Physical
ReadWrite), `4` FPRD (Configured-address Physical Read), `5` FPWR
(Configured-address Physical Write), `6` FPRW (Configured-address Physical
ReadWrite), `7` BRD (Broadcast Read), `8` BWR (Broadcast Write), `9` BRW
(Broadcast ReadWrite), `10` LRD (Logical Read), `11` LWR (Logical Write),
`12` LRW (Logical ReadWrite), `13` ARMW (Auto Increment Physical Read
Multiple Write), `14` FRMW (Configured-address Physical Read Multiple
Write), `255` EXT. Any other byte value is rendered `"unknown(N)"` rather
than guessed at, but is still decoded structurally (Adp/Ado addressing, the
default case) -- an unrecognized `Cmd` doesn't stop the rest of the datagram,
or the chain, from being decoded.

**"Auto increment" (AP\*) addressing**: `Adp` is interpreted as a *negative
offset from the sending master*, decremented by 1 at every slave the frame
physically passes through on its way around the segment -- so an AP command
with `Adp=0x0000` addresses "whichever slave is first on the segment",
`Adp=0xFFFF` (-1) addresses the second, `0xFFFE` (-2) the third, and so on.
This decoder's real capture fixture's own boot-time topology-discovery
sequence uses exactly this pattern (a master probing `Adp=0x0000`, then
`0xFFFF`, `0xFFFE`, `0xFFFD`, ... in one chained frame, right after boot, to
enumerate however many slaves are actually present). `Adp` is surfaced as a
raw 16-bit hex value rather than a pre-computed signed offset, since the
same field is a plain non-negative station address for FP/BRD/BWR/BRW
commands.

#### Chained datagrams / "declared Length"

A frame's data-link payload commonly carries more than one datagram
back-to-back (a master batching several slave register accesses into one
Ethernet frame for efficiency); the `More` bit chains them. This decoder
walks the chain until a datagram with `More` clear, a safety cap (200
datagrams) is hit, or the bytes run out -- but bounds that walk by the frame
header's own declared `Length` field (clamped tolerantly to the bytes
actually available, with a note, when implausible), rather than walking
every remaining byte in the Ethernet frame unconditionally the way
Wireshark's own dissector does. This matters because Ethernet's own
minimum-frame-size zero-padding, when present, would otherwise parse as a
spurious trailing NOP-shaped datagram (`Cmd=0, Idx=0, Adp=Ado=0, Len=0,
WKC=0`, all satisfied by an all-zero region) -- the same padding-vs-payload
ambiguity already documented for PROFINET RT's cyclic IO data, except here
it's avoidable: this decoder's real capture fixture shows the declared
`Length` field exactly matching the actual chained-datagram byte count in
all 986 of 986 real frames checked (zero mismatches -- see Validation
below), so trusting it as the chain's authoritative extent is empirically
well-founded, not just a spec reading.

#### `Data` is deliberately never value-decoded

An EtherCAT datagram's `Data` field is either raw ESC (EtherCAT Slave
Controller) register content (for AP/FP/BRD/BWR/BRW/ARMW/FRMW commands --
Wireshark's own dissector carries a ~150-entry ESC register table for this,
deliberately not replicated here) or raw process-image content at a logical
address (for LRD/LWR/LRW) whose actual layout is defined entirely by the
specific slave devices' ESI/XML descriptions and the master's own
process-image mapping -- information that exists nowhere on the wire, only
in offline engineering configuration this decoder has no access to. This is
the same "no generic self-describing wire-level type" reasoning already
applied to PROFINET RT's cyclic IO data, EtherNet/IP's CIP I/O Connected
Data Item, and IEC 61850-9-2 SV's `seqData` -- `Data` is shown only as raw
hex plus its byte length, never interpreted. `Cmd`/`Idx`/`Address`/`Len`/
`Irq`/`WKC` ARE all decoded, though, because every one of those is
unambiguous straight from the spec, independent of any particular slave's
configuration.

**Explicitly out of scope**: the CoE/SoE/EoE/FoE/AoE "mailbox" protocol
family -- SDO access, the most common way real EtherCAT configuration/
diagnostic traffic actually happens -- is carried as ordinary `Data` (above)
inside an ordinary FPRD/FPWR/... datagram addressed to a slave's SyncManager
mailbox registers, which requires the same per-slave SyncManager
configuration knowledge this decoder doesn't have to even recognize, let
alone decode. Frame Type 5 ("Mailbox") is named only, not decoded, for the
same reason. Frame Types 2-4 (ADS/RAW-IO/NV) are vendor/legacy framings
under this same EtherType, also named only. Distributed Clock (DC) register
semantics are not specially interpreted -- DC register reads/writes are
decoded exactly like any other `Data` payload, as raw hex.

#### Validation

Unlike IEC 61850-9-2 Sampled Values, a genuine real capture WAS found:
`ICS-Ethercat-001.pcap` (986 frames, a master's boot-time slave enumeration
and register poll sequence against what looks like a small, up-to-five-slave
demo segment) -- see `tests/real_captures/ethercat/ATTRIBUTION.md` for full
provenance. Every one of its 986 frames is Type 1 with **zero notes**: no
Reserved-bit warning, no implausible-Length fallback, no truncated-chain
warning -- in particular, the declared `Length` field exactly matches its
actual chained-datagram byte count in all 986 frames. Commands APRD/APWR/
FPRD/FPWR/BRD/BWR/LRD/LWR all appear with real, structurally valid bytes,
including the auto-increment topology-discovery pattern described above and
up to 11 chained datagrams in a single frame -- but APRW/FPRW/BRW/LRW/ARMW/
FRMW/EXT, the `Circulating` bit, 802.1Q VLAN tagging, frame Types other than
1, and every malformed/truncated-input path this decoder handles are
validated only against the hand-built `tests/sample_ethercat.pcap` fixture
(see `tools/make_sample_pcap.py`'s `build_ethercat_sample`), cross-checked
against `packet-ethercat-datagram.c`'s source rather than an independent
real capture -- the same honest gap this codebase already documents for
several other protocols' less-common paths. See
`include/conduitscope/ethercat.hpp`'s file header for the full writeup.

### BACnet/IP (UDP port 47808/0xBAC0, ASHRAE 135 Annex J)

Unlike PROFINET RT, IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, and
EtherCAT, BACnet/IP does not ride directly on raw Ethernet -- it rides on
UDP, conventionally port 47808 (0xBAC0), detected the same "opportunistic,
payload-shape" way EtherNet/IP CIP I/O (UDP port 2222) already is (see
PROTOCOL DETECTION above). Every multi-byte field at every layer is
big-endian (unlike EtherCAT's little-endian, the same as every other
protocol in this codebase). This section, and this decoder, is
cross-checked against Wireshark's own BACnet dissectors --
`epan/dissectors/packet-bvlc.c` (BVLC), `packet-bacnet.c` (NPDU), and
`packet-bacapp.c` (APDU, BACnet's own tag encoding, and service value
decode) -- byte offset by byte offset. Three layers are decoded: BVLC (the
UDP framing header), NPDU (the network layer), and APDU (the application
layer, where BACnet's actual services live).

#### BVLC (4-byte fixed header, ASHRAE 135 Annex J.2)

| Field | Size | Notes |
|---|---|---|
| `Type` | 1 | Must be `0x81` ("BACnet/IP, Annex J") -- the only value this decoder recognizes. A separate value, `0x82`, exists for BACnet/SC (Secure Connect), an entirely different WebSocket-based transport this decoder does not attempt. |
| `Function` | 1 | Which of 13 defined BVLC functions this is -- see the table below. |
| `Length` | 2 | Total byte length of this BVLC message INCLUDING the 4-byte header, big-endian. Trusted only when at least 4 and not exceeding the bytes actually present -- clamped tolerantly to the available bytes, with a note, otherwise. |

**Function table**: `0x00` BVLC-Result, `0x01` Write-Broadcast-
Distribution-Table, `0x02` Read-Broadcast-Distribution-Table, `0x03`
Read-Broadcast-Distribution-Table-Ack, `0x04` Forwarded-NPDU, `0x05`
Register-Foreign-Device, `0x06` Read-Foreign-Device-Table, `0x07`
Read-Foreign-Device-Table-Ack, `0x08` Delete-Foreign-Device-Table-Entry,
`0x09` Distribute-Broadcast-To-Network, `0x0A` Original-Unicast-NPDU,
`0x0B` Original-Broadcast-NPDU, `0x0C` Secure-BVLL.

Functions `0x00`-`0x03` and `0x05`-`0x08` are BBMD (BACnet Broadcast
Management Device) foreign-device-table/broadcast-distribution-table
management -- routing-level housekeeping between BBMDs, carrying no NPDU at
all. Their own sub-fields ARE decoded: BVLC-Result's 2-byte result code;
Write-BDT/Read-BDT-Ack's list of 10-byte BDT entries
(IP(4)+Port(2)+Mask(4)); Register-Foreign-Device's 2-byte Time-To-Live;
Read-FDT-Ack's list of 10-byte FDT entries (IP(4)+Port(2)+TTL(2)+
Timeout(2)); Delete-FDT-Entry's 6-byte IP+Port.

Functions `0x09` (Distribute-Broadcast-To-Network), `0x0A`
(Original-Unicast-NPDU), `0x0B` (Original-Broadcast-NPDU), and `0x04`
(Forwarded-NPDU) all carry an NPDU immediately after the 4-byte BVLC header
(`0x09`/`0x0A`/`0x0B`) or after the header plus a 6-byte "originating
device" B/IP address (`0x04` -- IP(4)+Port(2), the BBMD-forwarded
broadcast's actual source, decoded and surfaced separately from the UDP/IP
headers' own source address/port). In real deployments, `0x0A`
(Original-Unicast-NPDU) is by far the most common -- ordinary unicast
request/response traffic between a client and a single device, not going
through a BBMD at all (all 54 frames in this decoder's real capture fixture
are this function -- see Validation below).

Function `0x0C` (Secure-BVLL) wraps an entire BACnet/SC-style
encrypted/signed payload -- this decoder does not attempt decryption (no
key material exists on the wire), so it is named only, the same "no
generic self-describing wire-level type" posture this codebase already
applies to opaque/encrypted or engineering-configuration-dependent payloads
(PROFINET cyclic IO data, EtherNet/IP CIP I/O's Connected Data Item, SV's
`seqData`, EtherCAT's `Data`).

**Structural detection gate**: BVLC `Type == 0x81` AND `Function` one of
the 13 values above -- a 2-byte anchor (Type gives a 1-in-256 match by
itself, Function narrows a false positive further to 13-in-256 of those),
applied port-independently in Auto mode; UDP port 47808 is recorded as an
"expected port" annotation only, never a gate. See PROTOCOL DETECTION
above.

#### NPDU (Network Layer PDU, ASHRAE 135 clause 6)

| Field | Size | Notes |
|---|---|---|
| `Version` | 1 | Always `0x01` ("ASHRAE 135-1995") in every version of the standard published so far; surfaced as-is, not gated on. |
| `Control` | 1 | A bitmask -- see below. |
| `DNET`, `DLEN`, `DADR` | 2, 1, `DLEN` | Present only when Control's DEST bit is set: destination network number, MAC address length (`0` = broadcast on DNET, `1` = MS/TP or ARCNET MAC, `6` = Ethernet MAC, otherwise a vendor MAC format), and the MAC address itself. |
| `SNET`, `SLEN`, `SADR` | 2, 1, `SLEN` | Present only when Control's SRC bit is set, same shape as DNET/DLEN/DADR but for the originating network/MAC -- used when a BACnet router forwarded this NPDU from another network (SADR/SNET identify the ORIGINAL sender, not the router). |
| `HopCount` | 1 | Present only when DEST is set: decremented by each router the NPDU passes through, protects against routing loops. |
| `MessageType` [+ `VendorID`] | 1 [+2] | Present only when Control's NET bit is set: which Network Layer Message this is. A 2-byte VendorID (big-endian) immediately follows MessageType only when MessageType is in the vendor-proprietary range (>= `0x80`). |

**Control bitmask**: bit 7 (`0x80`) NET -- this NPDU carries a Network
Layer Message, NOT an APDU, when set; bit 6 (`0x40`) reserved; bit 5
(`0x20`) DEST -- DNET/DLEN/DADR (and HopCount) are present; bit 4 (`0x10`)
reserved; bit 3 (`0x08`) SRC -- SNET/SLEN/SADR are present; bit 2 (`0x04`)
EXPECT -- sender is requesting a reply be routed back; bits 1-0 PRIORITY --
2-bit priority (0=Normal, 1=Urgent, 2=Critical Equipment, 3=Life Safety).

Network Layer Messages (Who-Is-Router-To-Network/I-Am-Router-To-Network/
Initialize-Routing-Table/.../Network-Number-Is, `0x00`-`0x13`
ASHRAE-defined, `0x14`-`0x7F` reserved, `0x80`-`0xFF` vendor-proprietary)
are named only via a range-string table, not value-decoded -- real-world
OT-security-relevant BACnet traffic is overwhelmingly application-layer
(device/object discovery, property access), not the inter-router control
plane; this mirrors this codebase's existing "first pass" service-scoping
precedent (below). When Control's NET bit is clear, everything after the
fixed NPDU header is one complete APDU.

#### APDU (Application Layer PDU, ASHRAE 135 clause 20)

The first byte's top 4 bits select one of 8 PDU types:

| Type | Name | Layout |
|---|---|---|
| 0 | Confirmed-Request | byte0 = type\<\<4 \| SEG\<\<3 \| MOR\<\<2 \| SA\<\<1 \| reserved; byte1 = max-segs-accepted(3 bits)\<\<5 \| max-apdu-len-accepted(4 bits)\<\<1 \| reserved; invoke-id(1); [sequence-number(1) + proposed-window-size(1), only if SEG]; service-choice(1); service-request data. |
| 1 | Unconfirmed-Request | byte0 = type\<\<4 \| reserved(4 bits); service-choice(1); service-request data. |
| 2 | Simple-ACK | byte0 = type\<\<4 \| reserved; invoke-id(1); service-ACK-choice(1) -- no further data. |
| 3 | Complex-ACK | byte0 = type\<\<4 \| SEG\<\<3 \| MOR\<\<2 \| reserved; invoke-id(1); [sequence-number(1) + proposed-window-size(1), only if SEG]; service-ACK-choice(1); service-ACK data. |
| 4 | Segment-ACK | byte0 = type\<\<4 \| reserved(2 bits)\<\<2 \| NAK\<\<1 \| SRV; original-invoke-id(1); sequence-number(1); actual-window-size(1) -- exactly 4 bytes total, no further data. |
| 5 | Error | byte0 = type\<\<4 \| reserved; original-invoke-id(1); error-choice(1) (the confirmed service this error responds to); error data. |
| 6 | Reject | byte0 = type\<\<4 \| reserved; original-invoke-id(1); reject-reason(1) (a fixed 10-entry ASHRAE table) -- no further data. |
| 7 | Abort | byte0 = type\<\<4 \| reserved(2 bits)\<\<1 \| SRV; original-invoke-id(1); abort-reason(1) (a fixed 12-entry ASHRAE table) -- no further data. |

A PDU type outside `0`-`7` is not recognized -- the BVLC/NPDU layers still
decode, only the APDU itself is left unrecognized, with a note.

**Segmentation**: SEG/MOR are the Segmented-Message/More-Follows bits.
When SEG is set, this decoder decodes the sequence-number/
proposed-window-size header fields but does NOT attempt to value-decode
that segment's own service data: a single UDP datagram carries one
segment, not the whole reassembled service message, and this decoder (like
every other UDP-based protocol in this codebase) does no cross-packet
reassembly -- the segment's raw bytes are shown as hex only, with a note
explaining why.

**Error PDUs**: this decoder value-decodes only the GENERIC error shape
(errorClass + errorCode, both application-tagged Enumerated). Several
confirmed services (AddListElement, CreateObject, WritePropertyMultiple,
ConfirmedPrivateTransfer, VTClose, SubscribeCOVPropertyMultiple,
AuthRequest) define their OWN richer, service-specific error structure
instead -- an error response to one of those 7 services is named
(error-choice's service name) but its error body is shown as raw hex, not
mis-decoded as a generic errorClass/errorCode pair.

#### Service value decode ("first pass")

Service choice tables (35 confirmed + 15 unconfirmed entries, transcribed
in full from `packet-bacapp.c`'s own `BACnetConfirmedServiceChoice[]`/
`BACnetUnconfirmedServiceChoice[]`) are used to NAME every confirmed/
unconfirmed service this decoder sees. Value decode of the actual
service-request/service-ACK data, though, is a deliberate "first pass"
subset -- mirroring this codebase's existing "first pass" precedent
(EtherNet/IP CIP explicit messaging's own service subset, DNP3's
group/variation table, S7comm's classic-syntax-only addressing):

- **Who-Is** (unconfirmed 8): optional context-tag[0]
  device-instance-range-low-limit(unsigned) + context-tag[1]
  ...-high-limit(unsigned) -- both present or neither, per spec.
- **I-Am** (unconfirmed 0): application-tagged ObjectIdentifier (always a
  device object) + application-tagged Unsigned (Max-APDU-Length-Accepted)
  + application-tagged Enumerated (Segmentation-Supported, a 4-entry
  table) + application-tagged Unsigned (Vendor-ID) -- the single richest
  device-discovery/fingerprinting message on the wire, the BACnet analog
  of EtherNet/IP's ListIdentity response.
- **Who-Has** (unconfirmed 7): optional context-tag[0]/[1] device-instance
  low/high limit (unsigned, same optional-pair rule as Who-Is), then
  EITHER context-tag[2] ObjectIdentifier OR context-tag[3] ObjectName
  (CharacterString) -- a CHOICE, exactly one of the two is present.
- **I-Have** (unconfirmed 1): application-tagged ObjectIdentifier (the
  device) + application-tagged ObjectIdentifier (the object found) +
  application-tagged CharacterString (its Object-Name).
- **ReadProperty request** (confirmed 12): context-tag[0] ObjectIdentifier
  + context-tag[1] PropertyIdentifier (named via a 539-entry table) +
  optional context-tag[2] PropertyArrayIndex (unsigned).
- **ReadProperty ACK** (confirmed 12's Complex-Ack): context-tag[0]
  ObjectIdentifier + context-tag[1] PropertyIdentifier + optional
  context-tag[2] PropertyArrayIndex + context-tag[3] PropertyValue,
  opening/closing-tag-wrapped around exactly one application-tagged
  primitive value in this decoder's "first pass" (see "Property value
  decode" below).
- **WriteProperty request** (confirmed 15): same context-tag[0]/[1]/[2] as
  ReadProperty request, then context-tag[3] PropertyValue (same
  opening/closing-tag-wrapped single-primitive decode), then optional
  context-tag[4] Priority (unsigned, 1-16).
- **Error** (any confirmed service's error response): generic
  errorClass+errorCode only, per the PDU-type table above.

Every OTHER confirmed or unconfirmed service (ReadPropertyMultiple/
WritePropertyMultiple/SubscribeCOV/AtomicReadFile/
DeviceCommunicationControl/ReinitializeDevice/
ConfirmedEventNotification/UnconfirmedCOVNotification/... -- the large
majority of the two tables) is named via the service-choice table, but its
data is shown only as raw hex + byte length, not value-decoded. This
"first pass" set was chosen because Who-Is/I-Am/Who-Has/I-Have are
collectively the single most security-relevant BACnet traffic pattern for
passive OT monitoring (unauthenticated device and object discovery, the
BACnet analog of an ARP sweep or a Modbus/S7comm "what devices exist here"
probe), and ReadProperty/WriteProperty are the most common property-access
pattern (ReadPropertyMultiple, deliberately NOT decoded here, is more
efficient and increasingly common in modern deployments but has a
materially more complex nested-list wire shape -- named only, like every
other out-of-scope service, rather than half-decoded).

**Property value decode**: a PropertyValue's single application-tagged
primitive is decoded for application tag numbers 0-12: Null, Boolean,
Unsigned (1-8 bytes, big-endian), Signed (1-8 bytes, two's-complement
big-endian), Real (4-byte IEEE 754 single), Double (8-byte IEEE 754
double), Octet-String (raw hex), Character-String (1-byte
character-set-encoding tag + string bytes -- ANSI X3.4/UTF-8 decoded
as-is; the other five ASHRAE-defined character sets, including IBM/MS
DBCS's extra 2-byte code-page field, are recognized and their raw bytes
shown, but not transcoded), Bit-String (1-byte unused-bit count + bitfield,
rendered as a T/F string), Enumerated (1-4 bytes, big-endian, same encoding
as Unsigned), Date, Time, Object-Identifier. Tag number 13-15 (reserved by
ASHRAE) or a context-specific/constructed value inside the PropertyValue
wrapper (an array, a list, or a service-specific structured value) is
shown as "not decoded" plus raw hex, not misrepresented as one of the
primitive types above -- the same "decode confidently only where the wire
format is unambiguous" philosophy already applied throughout this
codebase.

Object type / property identifier / error class / error code tables
(65/539/8/230 entries respectively) are transcribed in full from
`packet-bacapp.c`'s own value-string tables -- unlike the service-choice
scoping above, there is no reason to truncate these: they are flat,
unambiguous lookup tables, and property-identifier/object-type names in
particular are high-value for OT asset inventory from passive capture. A
value outside every table (or in an explicitly vendor-proprietary/
ASHRAE-reserved range) is rendered `"unknown(N)"` or
`"vendor-proprietary(N)"`/`"reserved(N)"` as appropriate, never guessed at.

**Explicitly out of scope**: BACnet/SC (Secure Connect, an entirely
different WebSocket-based transport under BVLC Type `0x82`, not `0x81`);
Secure-BVLL's encrypted payload; every Network Layer Message's own data
(named only); every APDU service outside the "first pass" list (named
only); ReadPropertyMultiple/WritePropertyMultiple's nested
list-of-results structure specifically (the most notable omission from
real-world traffic); cross-packet APDU segmentation reassembly; MS/TP,
ARCNET, LonTalk, or BACnet/SC MAC address formats appearing inside
DADR/SADR (only their raw bytes are shown -- this decoder only ever sees
BACnet/IP's own Ethernet/IPv4 framing).

#### Validation

A real capture WAS found: `ICS-OT-Network-001-bacnet-excerpt.pcap` (54
frames, extracted from a larger mixed-OT-protocol capture -- see
`tests/real_captures/bacnet/ATTRIBUTION.md` for full provenance). It
confirms BVLC Original-Unicast-NPDU framing, a plain (no DEST/SRC/
Network-Layer-Message) NPDU, and 27 Confirmed-Request/Complex-ACK
ReadProperty request/response pairs against trend-log objects, with
Unsigned-typed PropertyValue decode, all byte-for-byte correct with zero
crashes or unexpected fallbacks -- but it is narrow: everything else
described above (Who-Is/I-Am/Who-Has/I-Have, WriteProperty, Simple-ACK/
Error/Reject/Abort/Segment-ACK, every BVLC function besides
Original-Unicast-NPDU, NPDU DEST/SRC/Network-Layer-Message, every
PropertyValue type besides Unsigned, and segmentation) is validated only
against the hand-built `tests/sample_bacnet.pcap` fixture (see
`tools/make_sample_pcap.py`'s `build_bacnet_sample`), cross-checked against
Wireshark's dissector source rather than an independent real capture --
see that ATTRIBUTION.md's own "Gaps" section for the complete, honest
list, including the two real-capture sources that were checked and could
not be used (`automayt/ICS-pcap`'s `BACNET/` directory, Git-LFS pointer
stubs unfetchable in this environment; `kargs.net`'s own capture archive,
blocked by this session's network policy). See
`include/conduitscope/bacnet.hpp`'s file header for the full writeup.

### HART-IP (UDP/TCP port 5094, IEC 62591 / HCF_SPEC-151)

Unlike every protocol above, HART-IP genuinely rides on either transport
with the identical wire format -- some deployments run it purely as a
UDP-datagram protocol between a host and a single field device or gateway;
others establish a long-lived TCP session first. Detection is the same
"opportunistic, payload-shape" approach as BACnet/IP and CIP I/O, applied on
both TCP and UDP (see PROTOCOL DETECTION above for the exact gate and the
TCP-only Modbus collision it doesn't resolve). Every multi-byte field is
big-endian.

#### The 8-byte fixed header

Every HART-IP message begins with: Version (1 byte, always `1` in every
message this decoder's own research and every real capture checked so far
carries), MessageType (1 byte -- `0` Request, `1` Response, `2` Publish, `3`
Error, `15`/`0x0F` NAK), MessageID (1 byte -- `0` Session Initiate, `1`
Session Close, `2` Keep Alive, `3` Pass Through), Status (1 byte -- every
message observed so far is `0`; see LIMITATIONS), TransactionID/Sequence
Number (2 bytes), and MsgLength (2 bytes -- the body's own byte count,
*not* including this 8-byte header). Error/NAK is checked before MessageID
(it can apply to a Session Initiate/Close/Keep-Alive/Pass-Through request
alike), then the body is decoded by MessageID:

- **Session Initiate** (5-byte body): Host Type (1 byte -- `0` Primary Host,
  `1` Secondary Host) + Inactivity Close Timer (4 bytes, unsigned, seconds).
- **Session Close** (empty body): no fields.
- **Keep Alive** (empty body): no fields.
- **Error / NAK** (1-byte body): a single Error Code byte, named from a
  25-entry single-definition table transcribed from HCF_SPEC-307 (e.g. `0`
  "Session closed", `2` "Service unavailable"); a structurally valid but
  undefined code is rendered `"unknown(N)"` rather than guessed at.
- **Pass Through** (variable-length body): the classic wired-HART Data-Link
  PDU, described next.

A body that's present but the wrong length for its MessageID (e.g. a
3-byte Session Initiate body) is noted and shown as raw hex rather than
partially decoded or guessed at.

#### The Pass-Through body: classic HART Data-Link PDU

This is where HART-IP earns its name -- it's a thin IP transport wrapping
the same Data-Link PDU wired HART has used since the 1980s, byte for byte:

- **Delimiter** (1 byte): Frame Type (bits 0-2 -- `1` `"BACK"` Burst Frame,
  `2` `"STX"` Master->Field Device/request, `6` `"ACK"` Field Device->
  Master/response; an undefined value is `"unknown(N)"`. Frame Type ACK or
  BACK is this decoder's own `hartip_is_response` signal, deciding whether
  Response Code + Device Status are present at all), Physical Layer Type
  (bits 3-4 -- `0` Asynchronous, `1` Synchronous, named but not further
  interpreted), Expansion Byte Count (bits 5-6, a raw count of trailing
  expansion bytes this decoder counts and skips rather than interprets),
  and Address Type (bit 7 -- `0` Polling/short address, `1` Unique/long
  address).
- **Address** (1 byte, masked to the low 6 bits, for Polling/short; 5 raw
  bytes for Unique/long): shown as lowercase hex.
  Command 0/11/21 (Read Unique Identifier) is the standard way a master
  discovers a device's own long address before switching to addressing it
  that way for every subsequent command -- this decoder's real capture
  (see Validation below) shows exactly that pattern on genuine traffic.
- **Command** (1 byte): the command number, as a plain integer, named from
  this decoder's own command table when recognized (see "Command
  value-decode" below) regardless of whether the data itself was
  value-decoded.
- **Byte Count** (1 byte): declared length of everything from here to (but
  not including) the Checksum -- for a response, this includes the 2
  Response Code/Device Status bytes; a Byte Count too small to even cover
  those 2 bytes is noted and Data length is treated as 0 rather than
  underflowing.
- **Response Code** (1 byte, responses only): bit 7 set means the low 7
  bits are a data-link-layer comm-error bitmask (e.g.
  `"vertical-parity-error"`, `"longitudinal-parity-error"` -- 6 bits
  cross-corroborated across vendor HART references; the low bit's own
  meaning isn't confidently sourced and is deliberately not asserted)
  rather than a command-specific code. Otherwise, per HCF_SPEC-307's own
  three-way classification (single-definition, multi-definition, and
  warning codes), only the single-definition codes -- the ones whose
  meaning is the same regardless of which command produced them -- are
  named (e.g. `0` "Success", `32` "Busy"); every other 0-127 value is
  rendered as an explicit "command-specific response code N (meaning
  depends on which command produced it -- not decoded)" placeholder,
  deliberately not guessed at, since a multi-definition or warning code's
  actual meaning depends on knowing that specific command's own spec text,
  most of which this project doesn't have.
- **Device Status** (1 byte, responses only): an 8-bit flag byte (e.g.
  `"field-device-malfunction"`, `"configuration-changed"`,
  `"more-status-available"`), cross-corroborated across multiple vendor
  command-reference manuals during this decoder's own research.
- **Data** (variable length, per Byte Count minus the 2 Response Code/Device
  Status bytes for a response): the command's own payload -- see "Command
  value-decode" below.
- **Checksum** (1 byte): present but not itself verified (see LIMITATIONS).

A body truncated before its Command byte, before its trailing Checksum
byte, or carrying trailing bytes after the Checksum, is noted explicitly
rather than silently mis-parsed.

#### Command value-decode ("first pass")

Mirroring this codebase's existing "first pass" precedent (BACnet/IP's
service subset, EtherNet/IP CIP explicit messaging's own service subset,
DNP3's group/variation table): a deliberately scoped set of the most common
read/write commands gets full field-level value decoding; everything else
is named (when the command number is recognized at all) but shown as raw
hex.

- **0 / 11 / 21** (Read Unique Identifier, in its short-address/
  long-address/burst-mode forms): both the 12-byte "basic" response form and
  the fuller 22-byte "extended" form (adding Min. Response Preambles, Max.
  Device Variables, Configuration Change Counter, Extended Device Status,
  Manufacturer ID, Private-Label Distributor Code, and Device Profile) are
  recognized by length and decoded accordingly, with a note when the
  shorter basic form was used.
- **1** (Read Primary Variable): PV Units + PV (IEEE-754 float).
- **2** (Read Loop Current and Percent of Range): PV Loop Current (float,
  mA) + PV Percent of Range (float).
- **3** (Read Dynamic Variables and Loop Current): PV Loop Current, then up
  to four Units+Value pairs (PV/SV/TV/QV).
- **6** (Write Polling Address) / **7** (Read Loop Configuration): Poll
  Address + Loop Current Mode.
- **8** (Read Dynamic Variable Classifications): PV/SV/TV/QV Classification
  bytes.
- **9** (Read Device Variables with Status): Extended Device Status, then
  each present Device Variable's Code/Classification/Units/Value/Status,
  then a HART-format Timestamp (see below) -- request and response have
  different shapes (the request names which variables to read; only the
  response's fixed layout is value-decoded, the same request/response
  asymmetry commands 33/203 below also have).
- **12 / 17** (Read/Write Message): a 24-byte packed-ASCII field (see
  below).
- **13 / 18** (Read/Write Tag, Descriptor, Date): packed-ASCII Tag (6 raw
  bytes / 8 characters) + packed-ASCII Descriptor (12 raw bytes / 16
  characters) + a 3-byte Date field.
- **14** (Read Primary Variable Transducer Information): Transducer Serial
  Number + Limit Units + Upper/Lower Transducer Limit (floats) + Minimum
  Span (float).
- **15** (Read Device Information): PV Alarm Selection, PV Transfer
  Function, Range Units, Upper/Lower Range Value (floats), Damping Value
  (float), Write Protect, and the reserved/PV-analog-channel-flags bytes.
- **16 / 19** (Read/Write Final Assembly Number): a 3-byte unsigned integer.
- **20 / 22** (Read/Write Long Tag): a 32-byte field -- unlike Message,
  Tag, and Descriptor above, Long Tag is plain, *unpacked* ASCII (one byte
  per character), not packed-ASCII.
- **31**: the 2-byte Extended Command Number is always decoded. This
  decoder deliberately does not assert an authoritative name for command
  31 as a whole -- research across FieldComm Group's own material and
  multiple vendor HART command references found none, and one source's own
  description of the Universal/Common-Practice command ranges explicitly
  excludes 31 from both. When the Extended Command Number is `64386`
  (`0xFB82`) -- a pairing directly confirmed in Wireshark's own source --
  the rest of the body is further decoded exactly like command 203 below.
- **33** (Read Device Variables): up to 4 Device Variable Code/Units/Value
  triples, per however many codes the request asked for.
- **38** (Reset Configuration Changed Flag): empty request; response
  returns the new Configuration Change Counter.
- **48** (Read Additional Device Status): both the 6-byte "minimal" response
  form and the fuller 14-byte "extended" form (adding Extended Device
  Status, Device Operating Mode, 4 Standardized Status bytes, and
  Analog-Channel-Saturated/Fixed bytes) are recognized by length.
- **203** (Read Discrete Variables (with Status), informally -- like 31,
  no authoritative top-level name is asserted for 203 itself: every source
  consulted places command numbers >=128 in HART's Device-Specific,
  vendor-defined-per-device range, which by the protocol's own design has
  no single FieldComm Group name. Wireshark's own dissector decodes this
  exact shape, strongly suggesting it's at least a common vendor
  convention, so this decoder decodes the *structure* with that same
  confidence while being honest that "203" is not a name it can vouch for
  across every device that might emit it -- see command 31 above for the
  other way this same shape can appear on the wire): Index of First
  Discrete Variable, Number of Discrete Variables, Extended Device Status,
  a HART-format Timestamp, then 1-6 slots of Discrete Variable
  State/Status.

**Packed-ASCII decoding**: HART's own 6-bit character encoding (3 raw bytes
pack 4 characters, each a 6-bit code offset from ASCII `0x20`) is decoded
per HCF_SPEC-307's own table, verified both by hand (Wireshark's own
`dissect_packAscii` cross-checked field-by-field during this decoder's
research) and mathematically (`tools/make_sample_pcap.py`'s own `pack_ascii`
helper is the exact inverse of this decoder's `decode_packed_ascii`, used to
build every packed-ASCII synthetic test fixture).

**HART-format timestamps**: a 4-byte field, raw units of 1/32 millisecond
(the units HCF_SPEC-307 defines), decoded to `hr:min:sec.ms`.

- **77** (Send Command to Sub-Device -- name per FieldComm Group's own
  "HART-IP Application, Communication, and Control Analysis" document,
  section 2.2.2, one of the I/O System Commands a HART-IP gateway/Remote
  I/O supports): an I/O-card/channel-addressed RELAY that wraps another,
  arbitrary HART command's own request or response to a sub-device reached
  through a multiplexer's I/O Card/Channel -- IO Card + Channel + (request
  only) TX Preamble Count + Embedded Command Delimiter (only its own
  Address-Type bit is decoded) + Embedded Address (1 or 5 bytes, by that
  bit) + Embedded Command Number + Embedded Command Byte Count + (response
  only) Embedded Response Code + Embedded Device Status + the embedded
  command's own Data. That embedded command is then decoded *recursively*
  through this same command table (e.g. an embedded command 1 response
  shows its own decoded PV value, prefixed `embedded-`), the same
  recursive-reuse pattern this project's EtherNet/IP CIP decoder already
  uses for Multiple Service Packet/Unconnected Send. Unlike every other
  command here, request and response genuinely have a different field
  shape (like command 38 above).
- **178** (a BATCH/aggregate wrapper -- like 31 and 203, no authoritative
  top-level name is asserted: FieldComm Group's own document frames this
  command as the vehicle for a "Publish"/burst-mode feature bundling e.g.
  commands 9 and 48 together, rather than giving it a standalone name, and
  no other source consulted gives one either): Number of Commands, then
  that many entries of Command Number + Command Byte Count + Response Code
  + Data, decoded the same way regardless of request/response direction
  (cross-checked against Wireshark's own dissector, which does the same).
  Each entry's own Command Number/Data is decoded recursively through this
  same command table too, prefixed `aggregate[i]-`.

Every command number outside the table above (including ones a command 77
or 178 recurses into) is named via the full command-number table when
recognized at all, or shown as a bare number when not -- either way, the
data itself is raw hex with an explanatory note. A recognized command whose
data doesn't match the expected length (a malformed capture, or simply a
command variant this decoder's first pass doesn't cover) falls back to the
same raw-hex-with-note treatment rather than mis-decoding. Commands 77 and
178's own sequential, multi-field layout means a truncation partway through
is instead reported as a note pinpointing exactly which field was
truncated, with every field already decoded still shown (the same "partial
fill" posture the Pass-Through frame itself already takes), rather than
falling back to a whole-message raw-hex dump that would just duplicate the
fields already shown.

#### Validation

A real capture WAS found: a 116-frame, 72-second capture of a WirelessHART
gateway running the same nine-command read sequence over both UDP and TCP
-- see `tests/real_captures/hartip/ATTRIBUTION.md` for full provenance and,
notably, independent cross-validation against Wireshark/tshark's own
HART-IP dissector, field-by-field, on several of the more surprising real
decodes (two genuine IEEE-754 NaN PV Loop Current values, a packed-ASCII
message field that decodes to literal ASCII-table-order text). It also
independently reproduces, on real field traffic, the TCP Session-Initiate-
vs-Modbus/TCP collision PROTOCOL DETECTION above documents as an accepted
limitation, plus a second, previously-undocumented false-positive pattern
where the same weak declared-length gate also matches unrelated background
TCP traffic -- see that ATTRIBUTION.md's own two dedicated sections for
both. It is narrow, though: only 9 of the ~20 value-decoded commands appear
(0, 1, 2, 3, 9, 12, 13, 20, 48), every response is Success with no
comm-error or non-zero command-specific code, Error/NAK and the BACK frame
type never appear, and no malformed/truncated/wrong-length input appears
either -- unsurprising for a clean, successful field-device exchange, but it
means the remaining commands, response-code/comm-error variety, and every
defensive/fallback path are validated only against the hand-built
`tests/sample_hartip.pcap` fixture (see `tools/make_sample_pcap.py`'s
`build_hartip_sample`), cross-checked against HCF_SPEC-307 and Wireshark's
`packet-hart_ip.c` source rather than an independent real capture -- see
that ATTRIBUTION.md's own "Gaps" section for the complete, honest list. See
`include/conduitscope/hartip.hpp`'s file header for the full writeup.

### OPC UA Binary (TCP port 4840, UA-TCP transport / OPC UA Secure Conversation, OPC 10000-6)

Unlike every protocol above, OPC UA rides on TCP only (there is no UDP
mapping in the spec), and unlike every protocol above except EtherNet/IP/
CIP, every multi-byte field is **little-endian** -- a legacy of its DCOM/OLE
lineage predating the pure-Ethernet-fieldbus protocols this codebase
otherwise covers. Sourcing for this section was cross-checked against three
independent sources: the OPC Foundation's own published reference
documentation (Part 4 "Services", Part 6 "Mappings"), the OPC Foundation's
own machine-readable `NodeIds.csv`/`StatusCode.csv`
(`github.com/OPCFoundation/UA-Nodeset`) for every numeric service identifier
and named StatusCode this section asserts, and python-opcua's own
machine-generated protocol bindings (`github.com/FreeOpcUa/python-opcua`,
generated directly from the OPC Foundation's schema) as an independent
cross-check on field order and type.

#### The 8-byte UA-TCP common header

Every message begins with: MessageType (3 bytes, ASCII -- `"HEL"` Hello,
`"ACK"` Acknowledge, `"ERR"` Error, `"RHE"` ReverseHello, `"OPN"`
OpenSecureChannel, `"CLO"` CloseSecureChannel, `"MSG"` Message), ChunkType (1
byte, ASCII -- `'F'` final/only chunk, `'C'` intermediate chunk, `'A'`
abort), and MessageSize (4 bytes, little-endian -- this one chunk's own
total byte length, header included, *not* the reassembled multi-chunk
message's total length -- see "Chunking" below). The first four -- Hello,
Acknowledge, Error, ReverseHello -- are plain UA Connection Protocol
messages: always exactly one `'F'` chunk, body follows the header directly.
The last three -- OpenSecureChannel, CloseSecureChannel, Message -- are OPC
UA Secure Conversation messages, carrying a further SecureChannelId,
security header, and sequence header before their own body (see below).

**Structural detection gate**: MessageType must be one of exactly those 7
fixed 3-byte ASCII strings, ChunkType one of the 3 fixed characters (all
three accepted even on a non-Message message, deliberately more permissive
than the spec's own stricter "always `'F'`" requirement, to stay a pure
detection gate rather than a well-formedness check), plus a MessageSize
plausibility check (`>= 8`, the header's own fixed size). See PROTOCOL
DETECTION above for why this gate is strong enough, and confirmed
collision-free with every other protocol here, to be tried first in the
dispatch chain.

- **Hello** (client->server, always the first message on a new connection):
  ProtocolVersion, ReceiveBufferSize, SendBufferSize, MaxMessageSize,
  MaxChunkCount (4 bytes each, UInt32), then EndpointUrl (a UA String).
- **Acknowledge** (server->client, in reply to Hello): the same 5 UInt32
  fields, no EndpointUrl.
- **Error** (either direction, terminates the connection): a StatusCode (see
  "StatusCode decode" below) + Reason (a UA String).
- **ReverseHello** (used only for the "reverse connect" pattern, where a
  Server initiates the TCP connection to a Client): ServerUri + EndpointUrl
  (both UA Strings).

#### OPC UA Secure Conversation: SecureChannelId, security header, sequence header

Immediately after the 8-byte common header, for OpenSecureChannel/
CloseSecureChannel/Message alike: **SecureChannelId** (4 bytes, UInt32 --
`0` on the very first OpenSecureChannel request of a new channel, before the
server assigns and returns the real one). Then a **security header** whose
shape depends on MessageType:

- **OpenSecureChannel** (Asymmetric Algorithm Security Header):
  SecurityPolicyUri (a UA String, e.g.
  `"http://opcfoundation.org/UA/SecurityPolicy#None"`) + SenderCertificate
  (a ByteString) + ReceiverCertificateThumbprint (a ByteString).
  SecurityPolicyUri is surfaced in full -- it is itself the single most
  useful security-audit signal this decoder can offer (see "Security
  posture is visible even when the body is not" below) -- while the two
  certificate fields are surfaced only as presence + byte length, never the
  certificate bytes themselves (the same posture this codebase already
  applies to HART-IP's Data-Link Checksum or Sampled Values' `seqData`).
- **CloseSecureChannel / Message** (Symmetric Algorithm Security Header):
  TokenId (4 bytes, UInt32) only -- the previously-negotiated security
  token this message claims to use.

Then a **sequence header**, present either way: SequenceNumber + RequestId
(4 bytes each, UInt32).

**Security posture is visible even when the body is not.** This decoder
does not track SecureChannel/Session state across messages (no correlation
table keyed by SecureChannelId -- see "Deliberately not implemented"
below), so it has no way to know, from a Message chunk alone, what
SecurityMode a given TokenId corresponds to. But the OpenSecureChannel
exchange that negotiated that token is, itself, always fully decoded by
this decoder (when readable at all -- see next paragraph), and its own
SecurityPolicyUri + MessageSecurityMode fields are exactly the two values
that determine whether every later Message chunk on that same
SecureChannelId is even readable in the first place. A capture showing
SecurityPolicyUri `"...#None"` and MessageSecurityMode `"None"` on the
OpenSecureChannel exchange is itself the audit finding (an OPC UA endpoint
accepting no security at all) independent of whether this decoder goes on
to successfully read any later Message body -- and this decoder's own real
capture (see Validation below) is exactly that: a genuine, real-world
`"...#None"` OpenSecureChannel exchange, not a hypothetical.

**Opportunistic body decode.** This decoder does not know, a priori,
whether a given OpenSecureChannel/CloseSecureChannel/Message chunk's body
is plaintext (SecurityMode None), signed-but-not-encrypted (Sign -- the
body IS still plaintext, only a trailing signature is added), or genuinely
encrypted (SignAndEncrypt). Rather than tracking channel state to know in
advance, it simply attempts to parse the body as a NodeId-prefixed service
structure (see "Service identification" below) and accepts the result only
if it is fully self-consistent (a structurally valid NodeId encoding byte,
a numeric identifier this decoder recognizes or can at least bounds-check,
and enough remaining bytes for whatever it then tries to read). An
encrypted body's essentially-random leading byte will, in the overwhelming
majority of cases, simply fail the NodeId-encoding-byte check (only 6 of
256 values, plus 2 ExpandedNodeId flag bits, are valid) and fall straight
to "body shown as raw hex, service unrecognized" -- the same honest,
no-hidden-state fallback this decoder already applies to S7comm-Plus's own
Tier-2 (named-but-not-decoded) function bodies elsewhere in this codebase.

#### Primitive encoding

Boolean/SByte/Byte (1 byte), Int16/UInt16 (2), Int32/UInt32 (4), Int64/
UInt64 (8), Float (4, IEEE-754), Double (8, IEEE-754) -- all little-endian.
**String**/**ByteString**: an Int32 length prefix (little-endian); `-1`
means null (no bytes follow); `0` means empty (a distinct, non-null empty
value); otherwise that many bytes follow. **DateTime**: an Int64,
100-nanosecond intervals since 1601-01-01T00:00:00Z (the Win32 FILETIME
epoch), decoded to a calendar date/time the same way this codebase already
renders MMS UtcTime / MQTT Sparkplug timestamps. **Guid**: NOT 16 raw bytes in wire order --
Data1 (UInt32 LE) + Data2 (UInt16 LE) + Data3 (UInt16 LE) + Data4 (8 raw
bytes, network/big-endian order), the same mixed-endianness Microsoft's own
GUID wire format uses. **NodeId**: a 1-byte encoding mask (low 6 bits
selecting the shape; the top 2 bits are ExpandedNodeId-only flags) --
Two-Byte (`0x00`, Identifier as 1 byte, namespace implicitly 0), Four-Byte
(`0x01`, Namespace 1 byte + Identifier UInt16), Numeric (`0x02`, Namespace
UInt16 + Identifier UInt32), String (`0x03`, Namespace UInt16 + Identifier
String), Guid (`0x04`, Namespace UInt16 + Identifier Guid), ByteString
(`0x05`, Namespace UInt16 + Identifier ByteString); any other low-6-bits
value is a structural parse failure (see "Opportunistic body decode"
above). **ExpandedNodeId**: a NodeId whose mask byte may additionally flag
a NamespaceUri String (bit `0x80`) and/or a ServerIndex UInt32 (bit `0x40`)
-- read and skipped for correct byte alignment, but not surfaced as
separate fields (no real capture or service in this decoder's own dispatch
table was found needing either). **QualifiedName**: NamespaceIndex (UInt16)
+ Name (String). **LocalizedText**: a 1-byte mask (bit `0x01` Locale
present, bit `0x02` Text present) + whichever fields that mask flags.
**ExtensionObject**: TypeId (NodeId) + Encoding (1 byte: `0x00` no body,
`0x01` ByteString body, `0x02` XML body) + [Int32 length + body bytes, only
when Encoding != `0x00`] -- used to identify identity-token structures (see
"Identity token decode" below) and otherwise skipped structurally.
**StatusCode** (4 bytes, UInt32): see "StatusCode decode" below. **Arrays**:
an Int32 element count prefix (`-1` = null/absent, distinct from `0` =
present-but-empty) followed by that many encoded elements back-to-back.

#### StatusCode decode

The top 2 bits (`0xC0000000`) are the severity -- `00` Good (`0x00000000`),
`01` Uncertain (`0x40000000`), `10` Bad (`0x80000000`) -- always decodable
regardless of whether the specific value is one this decoder names. The
named table below is a deliberate first pass -- the handful most relevant
to an OT security audit's own concerns (auth/certificate/session/timeout
failures), cross-checked against the OPC Foundation's own published
`StatusCode.csv` (which enumerates ~700 named codes total), not an attempt
at all of them:

`Good`, `Uncertain`, `BadUnexpectedError`, `BadTimeout`,
`BadServiceUnsupported`, `BadCertificateInvalid`, `BadSecurityChecksFailed`,
`BadUserAccessDenied`, `BadIdentityTokenInvalid`,
`BadIdentityTokenRejected`, `BadSecureChannelIdInvalid`,
`BadSessionIdInvalid`, `BadSessionClosed`, `BadNodeIdInvalid`,
`BadNodeIdUnknown`, `BadNotReadable`, `BadNotWritable`,
`BadRequestTypeInvalid`, `BadSecurityPolicyRejected`, `BadTypeMismatch`.

Any other value is rendered as its decoded severity word plus the raw hex
value (e.g. `"Bad (0x80af0000)"`), never guessed at -- this decoder's own
real capture (see Validation below) exercises exactly this fallback, twice,
on two StatusCodes (`BadInternalError`/`0x80020000`,
`BadDecodingError`/`0x80070000`) outside this table.

#### Service identification: Tier 1 (full decode) vs. Tier 2 (header only)

Every OPC UA service request/response, and ServiceFault, begins with its
own NodeId "TypeId" whose numeric identifier is looked up against the OPC
Foundation's own `NodeIds.csv` (specifically, each service's own
`_Encoding_DefaultBinary` entry -- the single most error-prone part of
implementing OPC UA Binary by hand, so this decoder never guesses one).
This decoder's own dispatch table covers two tiers:

- **Tier 1** ("full decode" -- RequestHeader/ResponseHeader plus every
  service-specific field is decoded): the UA Connection Protocol handshake
  (Hello/Acknowledge/Error/ReverseHello, above, which have no TypeId/
  RequestHeader of their own) plus, at the service layer,
  **OpenSecureChannel**, **CloseSecureChannel**, **GetEndpoints**,
  **FindServers**, **CreateSession**, **ActivateSession**,
  **CloseSession**, **ServiceFault**, and -- now that Variant/DataValue
  value decoding (below) exists to give their own service-specific fields
  somewhere to go -- **Read**, **Write**, and **Call**. The lifecycle+
  discovery services were promoted first, in a deliberate first-pass scope
  decision: they are (a) universally present in every real OPC UA capture
  regardless of what the client/server actually do with the connection
  afterward, (b) individually simple enough (no Variant/DataValue encoding
  anywhere in any of them) to decode with full confidence, and (c)
  collectively the highest OT-security-audit value of any OPC UA service
  group -- SecurityPolicyUri/MessageSecurityMode, the full endpoint/server
  inventory (an OPC UA analog of this codebase's existing BACnet I-Am /
  EtherNet/IP ListIdentity / HART-IP Read-Unique-Identifier "device
  fingerprinting" framing), and, deliberately, the UserIdentityToken carried
  in every ActivateSession request (see "Identity token decode" below).
  Read/Write/Call were promoted in a later round, for a different reason:
  they are the three OPC UA services whose entire reason for existing IS
  carrying a Variant or DataValue -- ReadResponse's own Results, WriteRequest's
  own NodesToWrite, and CallRequest/CallResponse's own Input/Output Arguments
  are, respectively, an array of DataValue, an array of DataValue, and arrays
  of Variant. Browse and the subscription/MonitoredItem-management services
  stay at Tier 2 (below) deliberately, even with value decoding now available:
  neither actually carries a Variant/DataValue anywhere in its own body
  (Browse deals in NodeId/BrowseDirection/ReferenceDescription; MonitoredItem
  creation's own MonitoringFilter is an ExtensionObject), so promoting them
  would be a separate, unrelated decode effort. HistoryRead does carry
  DataValue/Variant, but its own HistoryReadDetails ExtensionObject dispatches
  across five different sub-structures -- enough additional scope of its own
  that this first pass leaves it at Tier 2 too.
  - **RequestHeader**: AuthenticationToken (a NodeId -- the session's own
    secret; consumed, not surfaced), Timestamp (DateTime), RequestHandle
    (UInt32), ReturnDiagnostics (a bitmask; consumed, not surfaced),
    AuditEntryId (String; consumed, not surfaced), TimeoutHint (UInt32),
    AdditionalHeader (an ExtensionObject; consumed, not surfaced).
  - **ResponseHeader**: Timestamp, RequestHandle, ServiceResult (a
    StatusCode -- see "StatusCode decode" above), ServiceDiagnostics (a
    DiagnosticInfo; structurally skipped, not surfaced -- see "Deliberately
    not implemented" below), StringTable (an array of String; consumed, not
    surfaced), AdditionalHeader.
  - **Hello/Acknowledge/Error/ReverseHello**: see "The 8-byte UA-TCP common
    header" above.
  - **OpenSecureChannel request**: ClientProtocolVersion, RequestType
    (`"Issue"`/`"Renew"`), SecurityMode (`"None"`/`"Sign"`/
    `"SignAndEncrypt"`), ClientNonce (length only), RequestedLifetime (ms).
  - **OpenSecureChannel response**: ServerProtocolVersion, the newly-
    assigned SecureChannelId + TokenId, when the token was created,
    RevisedLifetime (ms), ServerNonce (length only).
  - **GetEndpoints request**: EndpointUrl (LocaleIds/ProfileUris arrays are
    consumed, not surfaced).
  - **GetEndpoints response**: the full array of EndpointDescription --
    EndpointUrl, ApplicationDescription's own ApplicationUri, SecurityMode,
    SecurityPolicyUri per endpoint (ServerCertificate, UserTokenPolicy
    array, TransportProfileUri, SecurityLevel are consumed, not surfaced).
  - **FindServers request**: EndpointUrl (LocaleIds/ServerUris arrays
    consumed, not surfaced).
  - **FindServers response**: the array of ApplicationDescription --
    ApplicationUri + ApplicationType (`"Server"`/`"Client"`/
    `"ClientAndServer"`/`"DiscoveryServer"`) per server.
  - **CreateSession request**: the client's own ApplicationUri, EndpointUrl,
    SessionName, RequestedSessionTimeout (ms) (ServerUri, ClientNonce,
    ClientCertificate, MaxResponseMessageSize are consumed/named without
    full surfacing, or surfaced as plain numbers).
  - **CreateSession response**: SessionId (a NodeId, rendered e.g.
    `"ns=1;i=1001"`), RevisedSessionTimeout (ms), the count of
    ServerEndpoints returned, MaxRequestMessageSize (AuthenticationToken,
    ServerNonce, ServerCertificate, ServerSoftwareCertificates,
    ServerSignature are consumed, not surfaced -- the endpoint array
    itself, when non-empty, is already surfaced in full by GetEndpoints
    above, so it isn't re-decoded here).
  - **ActivateSession request**: see "Identity token decode" below
    (ClientSignature, ClientSoftwareCertificates, UserTokenSignature are
    consumed, not surfaced; LocaleIds is consumed and counted internally
    only).
  - **ActivateSession response**: the count of result StatusCodes and how
    many were Good (ServerNonce is length-only; DiagnosticInfos array is
    structurally skipped).
  - **CloseSession request**: DeleteSubscriptions (a boolean).
  - **CloseSession response / CloseSecureChannel request+response /
    ServiceFault**: no parameters beyond RequestHeader/ResponseHeader
    itself (confirmed against python-opcua's own generated bindings -- none
    of these four have a Parameters structure of their own at all).
  - **Read request**: MaxAge (ms), TimestampsToReturn, and the full
    NodesToRead array -- NodeId + AttributeId + IndexRange (when non-empty)
    per entry (DataEncoding is consumed, not surfaced).
  - **Read response**: the full Results array, each entry a DataValue (see
    "Variant/DataValue value decoding" below) (DiagnosticInfos array is
    structurally skipped).
  - **Write request**: the full NodesToWrite array -- NodeId + AttributeId +
    IndexRange (when non-empty) + the DataValue being written, per entry.
  - **Write response**: the count of result StatusCodes and how many were
    Good (DiagnosticInfos array is structurally skipped).
  - **Call request**: the full MethodsToCall array -- ObjectId + MethodId +
    InputArguments (each argument its own Variant), per entry.
  - **Call response**: the full Results array -- StatusCode + OutputArguments
    (each its own Variant), per entry (InputArgumentResults/
    InputArgumentDiagnosticInfos are consumed, not individually surfaced --
    the overall call StatusCode is).
- **Tier 2** ("header only" -- RequestHeader/ResponseHeader is decoded
  exactly as in Tier 1, giving at minimum a request handle and, for a
  response, the ServiceResult StatusCode -- but every service-specific
  field after the header is shown only as raw hex): **Cancel**,
  **AddNodes**, **Browse**, **BrowseNext**,
  **TranslateBrowsePathsToNodeIds**, **RegisterNodes**, **UnregisterNodes**,
  **HistoryRead**,
  **CreateMonitoredItems**, **ModifyMonitoredItems**,
  **DeleteMonitoredItems**, **CreateSubscription**,
  **ModifySubscription**, **SetPublishingMode**, **Publish**,
  **Republish**, **DeleteSubscriptions** (request and response pairs for
  each). None of these actually carries a Variant/DataValue anywhere in its
  own body except HistoryRead (see the Tier 1 paragraph above for why each
  one specifically stays here even though Variant/DataValue value decoding
  now exists). Even without their own bodies decoded, this tier is still
  genuinely useful: the service name, request handle, and (for a response)
  whether the overall call succeeded are all visible, often enough to
  answer "is this conduit doing OPC UA browsing/subscriptions at all, and
  are they succeeding" without needing the actual values.

#### Variant/DataValue value decoding

OPC 10000-6 5.2.2.16/5.2.2.17 define two self-describing, recursive value
containers used throughout the OPC UA data model:

- **Variant**: any one of 25 BuiltInTypes (Boolean, SByte, Byte, Int16,
  UInt16, Int32, UInt32, Int64, UInt64, Float, Double, String, DateTime,
  Guid, ByteString, XmlElement, NodeId, ExpandedNodeId, StatusCode,
  QualifiedName, LocalizedText, ExtensionObject, DataValue, Variant,
  DiagnosticInfo -- numeric ids 1-25, 0 reserved as the "Null" sentinel),
  either a scalar or an array, optionally with ArrayDimensions. Wire shape: a
  1-byte EncodingMask (low 6 bits = the BuiltInType numeric id; bit `0x80` =
  an array, not a scalar, follows; bit `0x40` = an ArrayDimensions field
  follows) then either one scalar value or an Int32 ArrayLength plus that
  many elements, then (if the dims bit is set) an Int32 count plus that many
  Int32 dimension sizes. XmlElement is encoded identically to ByteString (a
  UTF-8-serialized XML document), per the spec, and rendered as text rather
  than hex. ExtensionObject, DataValue, and Variant-of-Variant are all valid
  Variant contents; recursion (DataValue-in-Variant-in-DataValue...) is
  bounded to 10 levels deep, mirroring this decoder's own DiagnosticInfo
  recursion guard.
- **DataValue**: a Variant plus up to five optional metadata fields --
  StatusCode, SourceTimestamp, SourcePicoseconds, ServerTimestamp,
  ServerPicoseconds. Wire shape: a 1-byte EncodingMask (bit `0x01` Value,
  `0x02` StatusCode, `0x04` SourceTimestamp, `0x08` ServerTimestamp, `0x10`
  SourcePicoseconds, `0x20` ServerPicoseconds) then whichever fields it
  flags -- in **wire order**, cross-checked against the OPC Foundation's own
  reference documentation and *not* simply ascending bit order:
  SourcePicoseconds (mask bit `0x10`) is encoded **before** ServerTimestamp
  (mask bit `0x08`), even though its own bit is numerically after
  ServerTimestamp's.

A BuiltInType id this decoder does not recognize (0 means "no value" for a
Variant; anything outside 1-25 is not valid at all) is treated as a decode
failure for that Variant -- the same "don't guess" posture this decoder
already takes for an unrecognized NodeId encoding shape.

Two small, closed value tables ride alongside this decoding, following this
codebase's own "don't guess a numeric table entry" discipline:

- **AttributeId** (Read/Write's own attribute selector): the 22 attributes
  defined since OPC UA 1.03 (NodeId through UserExecutable), cross-checked
  against open62541's own published `UA_AttributeId` constants. The four
  attributes 1.04/1.05 later added (DataTypeDefinition, RolePermissions,
  UserRolePermissions, AccessRestrictions, AccessLevelEx) were not
  corroborated with the same confidence and are rendered as a bare number
  (`"attribute-id=N"`) rather than a guessed name.
- **TimestampsToReturn** (Read/HistoryRead's own request parameter):
  `Source`/`Server`/`Both`/`Neither`/`Invalid`, cross-checked against OPC
  10000-4 7.39.

A TypeId this decoder's dispatch table does not recognize at all is
reported by its raw namespace + numeric identifier only (`"service
type-id N, namespace M -- not in this decoder's dispatch table"`); this
decoder does not attempt to guess whether it's even shaped like a Request
or a Response (RequestHeader and ResponseHeader have genuinely different
leading fields -- a NodeId vs. a DateTime -- and blindly assuming one would
risk mis-parsing), so its entire body, RequestHeader/ResponseHeader
included, is shown as raw hex.

#### Identity token decode: a deliberate security finding

ActivateSessionRequest's own UserIdentityToken field is an ExtensionObject
wrapping one of four standard structures, identified by that
ExtensionObject's own TypeId: **AnonymousIdentityToken** (PolicyId only, no
credential of any kind), **UserNameIdentityToken** (PolicyId, UserName,
Password, EncryptionAlgorithm), **X509IdentityToken** (PolicyId +
CertificateData, shown as presence + length only), **IssuedIdentityToken**
(PolicyId + TokenData, shown as presence + length only, + EncryptionAlgorithm).

UserNameIdentityToken is decoded in full, **deliberately, including the
Password field**: per OPC 10000-4 7.41, EncryptionAlgorithm empty/null
means Password was NOT encrypted with the server's public key before being
placed on the wire -- i.e. it is either (a) already plaintext, when the
entire SecureChannel itself is also unencrypted (SecurityMode None -- the
same posture "Security posture is visible even when the body is not" above
already lets this decoder flag), or (b) plaintext regardless of
SecureChannel security, on any implementation that (non-conformantly, but
not rarely) omits password encryption even when a SecurityPolicy is in
use. Either way, an EncryptionAlgorithm-empty UserName+Password pair on the
wire IS a real, actionable, documented OPC UA security finding (credential
exposure via anonymous/no-security ActivateSession), not a hypothetical
this decoder invented -- decoding it plainly serves this whole tool's
stated purpose as an OT-security-auditing decoder (the same reasoning
already applied to this codebase's HART-IP Response-Code naming). When
EncryptionAlgorithm is instead a non-empty string, the Password bytes ARE
genuinely encrypted ciphertext and are shown only as a byte length, never
as hex/text. UserName itself is always decoded as plain text regardless of
EncryptionAlgorithm (the spec never encrypts UserName, only Password),
since a leaked username alone -- even with an encrypted password -- is
still a legitimate account-enumeration finding. See OUTPUT FORMATS above
for the exact `opcua_values`/`notes` shape this produces.

#### Chunking

A single logical Message-layer request/response CAN be split across
multiple Message chunks (ChunkType `'C'` for every chunk but the last,
`'F'` for the last) when it exceeds the negotiated SendBufferSize/
MaxMessageSize -- the OPC UA analog of this codebase's own COTP EOT-bit
reassembly for S7comm, or DNP3's multi-frame application-fragment
reassembly. This first-pass release does NOT implement that cross-chunk
reassembly: only a single, complete `'F'`-chunk message has its service
body decoded (Tier 1) or even attempted (Tier 2/unrecognized); a `'C'`
(intermediate) or `'A'` (abort) chunk is fully decoded at the UA-TCP/
SecureConversation header level (MessageType, ChunkType, SecureChannelId,
security header, sequence header -- everything that doesn't require
knowing the reassembled message boundary) but its own body is always shown
as raw hex, regardless of what service TypeId a fully-reassembled version
of it might carry. In this decoder's own experience building its test
fixture, a chunked message is the exception rather than the rule for the
session/discovery/lifecycle/data-access services Tier 1 targets (their own
bodies are all small, fixed, or short-array-bounded) -- chunking matters
most for the very services (bulk Browse results, large Publish
notifications) this first pass already leaves at Tier 2 raw-hex depth, so
this scope decision costs relatively little of this release's own
practical coverage. This is
a separate mechanism from the general TCP-segment-level reassembly
PROTOCOL DETECTION and LIMITATIONS describe (one Message chunk split
across several TCP *segments* IS reassembled -- this decoder's own real
capture exercises exactly that, twice, across 5 and 6 segments
respectively -- what isn't reassembled is one logical message split across
several OPC UA *chunks*).

#### Deliberately not implemented

Stateful channel/session tracking (correlating a Message chunk's own
TokenId back to the OpenSecureChannel exchange that negotiated it, or a
Request's AuthenticationToken back to the CreateSession response that
issued it) -- this decoder is, like every other protocol in this codebase,
a stateless-per-message decoder with TCP-stream-level reassembly only, not
a full conversation-tracking OPC UA stack; Browse/subscription/
MonitoredItem-management and HistoryRead body decoding (see Tier 2 above --
Variant/DataValue value decoding itself IS implemented; these specific
services simply don't need it, or need additional scope of their own);
multi-level DiagnosticInfo's own optional SymbolicId/
NamespaceUri/LocalizedText/Locale/AdditionalInfo/InnerStatusCode/
InnerDiagnosticInfo fields are structurally skipped (correctly consumed for
byte alignment, but none of the seven is itself surfaced as a decoded
value); and OPC UA's separate PubSub/UADP mapping (an entirely different,
connectionless UDP/MQTT/AMQP-based wire format used for telemetry
publishing, unrelated to the client/server UA-TCP mapping this decoder
covers) is out of scope entirely, not merely undecoded.

#### Validation

A real capture WAS found: two back-to-back OPC UA sessions from Wireshark
Bug 3986's own attachment (a 2009 dissector-freeze reproduction capture --
see `tests/real_captures/opcua/ATTRIBUTION.md` for full provenance),
independently cross-validated field-by-field against Wireshark/tshark's own
OPC UA dissector on every value checked (service TypeIds, SecureChannelId/
SecurityPolicyUri/SequenceNumber, RequestHandle/Timestamp, the full
EndpointDescription array, CreateSessionResponse's own SessionId,
ActivateSessionRequest's own AnonymousIdentityToken, and both sessions' own
Error StatusCodes). Notably, this capture uses a non-standard TCP port
(12001, not 4840) that Wireshark's own *default* configuration doesn't even
recognize as OPC UA (needing an explicit "Decode As" to be dissected at
all) -- this decoder recognizes it without any `--opcua-port` hint, real-
world confirmation of the port-independent detection design PROTOCOL
DETECTION describes. This capture also genuinely exercises TCP-segment-
level reassembly (two responses split across 5 and 6 segments respectively)
and contains two deliberately malformed CallRequest packets (per Wireshark
Bug 3986's own report; one of which triggered Wireshark's own ~2-minute
dissector freeze). When Call was still Tier 2, this decoder's own scope
(never attempting to parse CallRequest's own body at all) was structurally
immune to whatever specific malformation caused that freeze; now that Call
is Tier 1, this decoder's own bounds-checked Variant/DataValue reads
correctly DETECT the malformation instead of merely being immune to it --
hand-verifying both sessions' own bytes confirms session 1's CallRequest
claims a MethodId NodeId with a 262144-byte String identifier when only
~21 bytes are actually present in the captured body, and session 2's
CallRequest has a MethodId NodeId with a structurally-invalid encoding byte
(shape `0x07`, outside the valid `0x00`-`0x05` range) -- both genuinely
malformed fuzz-test payloads, not decode bugs. This decoder falls back to
raw hex for both (`"service type-id 712, ns=0 -- not in this decoder's
dispatch table"`), the same honest fallback an unrecognized TypeId gets,
rather than asserting a "CallRequest" label it was never able to verify.
It is narrow, though: only 9 of the ~21 Tier 1 request/response entries
appear (no FindServers or CloseSession/CloseSecureChannel in either
session, and neither session's own Read/Write happens to appear either),
both sessions use SecurityPolicy `"...#None"` and an Anonymous identity
token (no credential-exposure finding on this particular capture -- that
logic is instead exercised on real bytes only by this decoder's own
synthetic fixture, `tests/sample_opcua.pcap`, packets 13-14), a
well-formed Read/Write/Call exchange is likewise exercised on real bytes
nowhere (both real CallRequest bodies being malformed, as above -- this
decoder's own synthetic fixture is the only real-bytes-adjacent validation
Read/Write/Call's own Variant/DataValue decoding has so far), and no Tier
2 service appears at all -- see that ATTRIBUTION.md's own writeup for the
complete, honest scope. See `include/conduitscope/opcua.hpp`'s file header
for the full writeup.

### FOUNDATION Fieldbus HSE (FDA port 1090, SM port 1091, LAN Redundancy port 3622, ff-annunc port 1089, all TCP AND UDP)

FOUNDATION Fieldbus HSE (High Speed Ethernet, "FF-HSE") is an Ethernet-based
fieldbus protocol built around four sub-protocols sharing one 12-byte common
header: **FDA** (Field Device Access, session management), **SM** (System
Management, device commissioning/discovery), **FMS** (Fieldbus Message
Specification, the actual read/write/report data traffic), and **LAN
Redundancy** (dual-LAN fault detection/switchover). Unlike a port number
picking the sub-protocol the way TCP port 502 picks Modbus, FF-HSE signals
which of the four a given message belongs to IN-BAND, via the header's own
`ProtocolAndType` byte -- so, matching this codebase's existing HART-IP/
BACnet posture, all four ports (1089/1090/1091/3622) are recorded as
"expected port" annotations only, never a detection gate, and a message can
arrive on any of them (or a fifth, unexpected port) and still decode
identically.

**Sourcing, and an honesty note.** FF-HSE's own official specifications
(FF-581/586/588/589/593/803/941, published by FieldComm Group) are all
paywalled -- no free copy of any of them was available while building this
decoder. Instead, every byte offset this decoder asserts is cross-checked
against Wireshark's mainline dissector, `epan/dissectors/packet-ff.c`
(15,317 lines) plus `packet-ff.h` (720 lines), protocol short name "FF",
first written in 2008 by Yukiyo Akisada -- a Yokogawa engineer -- directly
against the official FF-588-1.3 spec, with inline spec-clause citations
throughout its own source comments. GPL-2.0-or-later, vendor-authored, and
spec-cited: that gives this decoder meaningfully **higher** sourcing
confidence than some of this codebase's other decoders (e.g. S7comm-Plus,
which relies on a third-party reverse-engineered plugin never merged into
mainline Wireshark) -- but it is still secondary (dissector-derived, not
primary-spec-derived), so every field name and byte offset below should be
read as "what Wireshark's own vendor-authored dissector does", not as
independently verified against FieldComm Group's own text. A raw copy of
`packet-ff.c`/`packet-ff.h` (fetched from the Wireshark project's own GitHub
mirror) was actually available for direct inspection while building this
decoder -- not just a secondhand transcription of it -- which is what let
the full ErrorClass/ErrorCode name tables (11 ErrorClasses, each with its
own nested ErrorCode table) and every FDA/SM/FMS/LAN Redundancy service name
be pulled byte-for-byte from the reference source rather than approximated.

#### The 12-byte common header

```
Version(1)          @0   not validated (nor is it by the reference dissector) -- surfaced as-is
Options(1)          @1   bitmask: message-number/invoke-id/time-stamp/extended-control-field
                           presence, plus a decorative, unused Pad Length sub-field
ProtocolAndType(1)  @2   PROTOCOL_MASK=0xfc: FDA(0x04)/SM(0x08)/FMS(0x0c)/LAN Redundancy(0x10)
                           TYPE_MASK=0x03: Request(0x00)/Response(0x01)/Error(0x02)
Service(1)          @3   bit7=Confirmed-service flag, bits0-6=Service Id
FDA Address(4)      @4   composite address; only its own top 16 bits ("LinkId") are interpreted,
                           and only for the SM Identify Rsp / SM Device Annunciation shape
Message Length(4)   @8   this PDU's OWN total length, header+body+trailer -- doubles as the
                           TCP declared-length framing field and this decoder's own plausibility check
```

All fields big-endian. The dispatch key this decoder uses internally is
conceptually `(Protocol, Type, ConfirmedFlag, ServiceId)` -- the confirmed
flag genuinely disambiguates real collisions (FMS Service Id 1 is "FMS
Identify" when confirmed, but "FMS Unsolicited Status" when unconfirmed --
same Protocol, same Type, same numeric Service Id, an entirely different
message).

**Structural detection gate**, deliberately the weakest in this codebase --
see PROTOCOL DETECTION's "Why FF-HSE is tried last of all": accept a buffer
as FF-HSE when there are at least 12 bytes, `ProtocolAndType & 0xfc` is one
of the 4 valid protocol values, `ProtocolAndType & 0x03` is one of the 3
valid type values, and Message Length is at least 12. That is a single byte
at offset 2 landing on one of 12 valid values out of 256 possible, plus a
length check that is barely a constraint at all -- honestly weaker even
than HART-IP's own two-adjacent-byte gate, which is itself already this
codebase's previous weakest. FF-HSE is therefore dispatched LAST of all
protocols in Auto mode, on both TCP and UDP, after even HART-IP and MQTT.

**Options byte**: `0x80`=Message-Number-present (4-byte trailer field),
`0x40`=Invoke-Id-present (4-byte trailer field), `0x20`=Time-Stamp-present
(8-byte trailer field, raw 64-bit value -- no epoch/scale confidently
sourced), `0x10`=reserved (not surfaced), `0x08`=Extended-Control-Field-
present (4-byte trailer field), `0x07` (low 3 bits)=Pad Length. Pad Length
is surfaced as a raw value but never acted on in this decoder's own length
arithmetic -- confirmed directly from the reference source, whose own
`dissect_ff()` reads it into a display-only field and never uses it to
adjust an offset either.

**Trailer**: present in this fixed order at the END of the PDU, but only
the fields whose own Options bit is set are actually on the wire (a field
whose bit is clear is skipped entirely, not left as a gap): Message
Number, Invoke Id, Time Stamp, Extended Control Field. This decoder's
length accounting reproduces the reference `dissect_ff()`'s own arithmetic
exactly -- Message Length minus each present trailer field's own byte
count minus 12 (the header) leaves the body length -- and it is guarded
defensively against underflow/malformed lengths, clamped and noted rather
than allowed to throw or produce a negative body length.

**TCP framing**: Message Length (header offset 8) is this protocol's PDU-
length-prefix for TCP stream reassembly, mirroring `hartip_declared_length`/
`enip_declared_length` exactly.

**UDP framing**: unlike every protocol above it in this codebase, a single
UDP datagram can (and, per the reference source's own comments about
coalesced diagnostic/status traffic, sometimes does in practice) carry more
than one concatenated FF-HSE PDU back-to-back -- walked in a loop, the same
`wire_length`-driven pattern this codebase already uses for EtherNet/IP's
and HART-IP's own coalesced messages. The loop stops silently, not as an
error, the moment a sub-PDU's own declared length is implausible or doesn't
fit the bytes remaining in the datagram.

#### Two-tier coverage: Tier-1 (full value decode) vs. Tier-2 (named only, raw-hex body)

The same split this codebase already applies to HART-IP's command dispatch,
BACnet's service dispatch, MMS's/OPC UA's service dispatch, and
S7comm-Plus's function dispatch.

**Tier 1** -- decoded with confidence: the great majority of FDA/SM/LAN
Redundancy messages (Open/Idle/Close Session, Find Tag Query/Reply,
Identify, Device Annunciation, Clear Address, Set/Clear Assignment Info,
Get/Put Info, Get Statistics, Diagnostic Message), plus FMS's own
session-lifecycle/status/identify/read/write family (Initiate, Status,
Identify, Read, Read with Subindex, Write, Write with Subindex,
Information Report and its On-Change/Subindex variants, Unsolicited
Status, Abort). One shared function decodes every Error body (20 bytes
fixed + remainder) regardless of which sub-protocol/service produced it --
ErrorClass (11 named values), ErrorCode (looked up via a nested,
per-ErrorClass table, an unmapped pair rendered `"unknown(N)"` rather than
guessed at), AdditionalCode (raw), and AdditionalDescription (ASCII,
trailing NULs trimmed).

**Tier 2** -- named only, body shown as raw hex: FMS's Get OD, Define/
Delete Variable List, the Download/Upload sequence families,
RequestDomainDownload/Upload, the Program Invocation lifecycle,
AlterEventConditionMonitoring, AcknowledgeEventNotification, the Put OD
family, the Generic Download sequence family, and unconfirmed Event
Notification. FMS Get OD is notable among these: even the reference
Wireshark dissector itself leaves OD (Object Dictionary) entries undecoded
as raw bytes, since their own shape depends on Device Description content
this decoder has no access to either -- good precedent for this decoder's
own choice not to guess there.

FMS Read/Read-with-Subindex responses (and Write/Write-with-Subindex
requests) are Tier-2 in a narrower sense: their HEADER is fully decoded
(Index/Subindex), but their own returned/written VALUE is deliberately left
as raw hex, since an FMS value has no self-describing wire type without
external Object Dictionary context to interpret it against -- the exact
same honesty precedent this codebase's EtherNet/IP CIP I/O decoder already
sets for connected I/O data, and S7comm-Plus sets for several datatypes it
declines to parse further.

#### The LinkId branch: the single trickiest piece of this decoder

SM Identify Rsp and SM Device Annunciation Req share an exact 108-byte
fixed body shape plus a trailing, variable-length version-number list.
`LinkId` is computed as the top 16 bits of the 12-byte common HEADER's own
FDA Address field (`(uint16_t)(header.fda_address >> 16)`) -- NOT anything
inside this message's own body. Once `NumOfEntriesInVerNumList` (`N`, a
uint32 at body offset 104) is known:

- **LinkId != 0**: the list is `N*2` entries of a 2-byte
  (H1NodeAddress(1B), VersionNumber(1B)) pair.
- **LinkId == 0**: the list is `N` entries of a 4-byte (H1LinkId(2B BE),
  Reserved(1B), VersionNumber(1B)) quad.

Either way, the list consumes exactly `4*N` total bytes starting at body
offset 108 -- only the INTERNAL shape of those bytes depends on LinkId, not
the total byte count, which is why both branches land on the same
"remainder starts at `108+4*N`" offset. Getting this branch wrong (e.g.
reading N as 4-byte quads when LinkId != 0) would silently misinterpret
every entry after the first -- this decoder computes LinkId from the header
exactly once, before entering either message's own body-decode function,
and threads it through explicitly rather than re-deriving it separately in
each. See `include/conduitscope/ffhse.hpp`'s file header comment for the
full writeup, including the FDA Address field's own remaining bits (shown
raw, as hex, not otherwise decoded).

#### UNCONFIRMED working hypothesis: cyclic Publisher/Subscriber traffic

No distinct "cyclic Publisher/Subscriber" message shape was identified
anywhere in the reference source consulted while building this decoder.
This decoder's own best guess -- a guess, **not** a confirmed fact -- is
that HSE's cyclic/multicast function-block data reuses the unconfirmed FMS
Information Report family (Service Ids 0/16/17/18) rather than having any
wire shape of its own. This is presented here, and everywhere else this
decoder or its documentation mentions it, as an inference this decoder
makes, never as an established fact about the FF-HSE protocol -- no
independent source (paywalled spec or otherwise) was available to confirm
or refute it.

#### JSON field reference

All fields present only when `protocol` is `ffhse`:

- `ffhse_version`, `ffhse_options`: the header's raw Version/Options bytes.
- `ffhse_protocol`: `"FDA"`/`"SM"`/`"FMS"`/`"LAN Redundancy"`.
- `ffhse_type`: `"Request"`/`"Response"`/`"Error"`.
- `ffhse_confirmed`: `true`/`false`, the Service byte's own confirmed-service flag.
- `ffhse_service_id`: the Service byte's low 7 bits.
- `ffhse_fda_address`: the full 4-byte FDA Address field, as hex (e.g. `"0x00010203"`).
- `ffhse_link_id`: the FDA Address field's own top 16 bits -- see the LinkId branch above.
- `ffhse_message_length`: the header's own declared total PDU length.
- `ffhse_message_number` / `ffhse_invoke_id` / `ffhse_time_stamp` /
  `ffhse_extended_control_field`: present only when the corresponding
  Options bit was set (see the trailer above); `ffhse_time_stamp` is always
  the raw 64-bit value, never interpreted as a calendar date.
- `ffhse_message_name`: a best-effort message name, e.g. `"FDA Open Session
  Req"`, `"SM Identify Rsp"`, `"FMS Initiate Err"`, `"LAN Redundancy Get
  Statistics Rsp"` -- always present, even for an unrecognized combination
  (e.g. `"SM unconfirmed service 99"`, with `ffhse_recognized: false`).
- `ffhse_recognized`: `true`/`false`, whether this decoder recognizes the
  `(Protocol, Type, ConfirmedFlag, ServiceId)` combination at all (Tier 1
  OR Tier 2).
- `ffhse_body_decoded`: `true`/`false`, `true` only for a Tier-1 message
  whose body matched this decoder's expected shape.
- `ffhse_values`: an array of one `"field-name=value"` string per decoded
  field, wire order (e.g. `"session-index=1"`, `"index=315"`,
  `"error-class=5 (Service)"`, `"h1-new-address=0x05"`,
  `"pd-tag=\"TT-101\""`), present only when non-empty (i.e. only for a
  Tier-1-decoded body).
- `ffhse_body_shown_as_hex`: `true`/`false` -- `true` for a Tier-2
  message's whole body, OR for the trailing "remainder" bytes past a
  Tier-1 message's own fixed/variable decoded shape.
- `ffhse_body_length` / `ffhse_body_hex`: present only when
  `ffhse_body_shown_as_hex` is `true` -- the undecoded byte count and its
  hex rendering.

#### Validation

Despite a genuine, multi-source search -- `automayt/ICS-pcap`,
`ITI/ICS-Security-Tools`, the 4SICS GeekLounge/Netresec collections, and
malware-traffic-analysis.net -- **no public real-world FF-HSE capture was
found**. A small synthetic 4-message concatenation test capture referenced
in a Wireshark GitLab bug report was also identified but could not be
retrieved. This decoder's every path is therefore validated only by
construction: hand-built against `packet-ff.c`'s own dissection logic and
exercised against the synthetic `tests/sample_ffhse.pcap` fixture (see
`tools/make_sample_pcap.py`'s `build_ffhse_sample()`), covering every
Tier-1 message family across all four sub-protocols in both directions
(plus Error bodies), both LinkId branches of the SM Identify Rsp / SM
Device Annunciation shape, every trailer-field combination, Pad Length's
decorative non-effect, UDP multi-PDU coalescing, TCP coalescing and
cross-segment reassembly, an unexpected port note, and malformed/truncated-
body fallback to raw hex -- the same honest gap already documented for CIP
I/O, PROFINET RT's cyclic IO data, and Sampled Values, among others in this
codebase. If a real FF-HSE capture becomes available later, it should be
added and this section updated accordingly, the same way this project has
handled every other protocol where independent traffic was eventually
found after an earlier empty search. See `include/conduitscope/ffhse.hpp`'s
file header for the full writeup.

### Spanning Tree Protocol (STP/RSTP/MSTP)

IEEE Spanning Tree Protocol -- classic STP (802.1D), Rapid STP (802.1w), and
Multiple STP (802.1s) -- is the first protocol this tool decodes that is
reached neither through IPv4 nor through a DIX Ethernet II EtherType. A BPDU
(Bridge Protocol Data Unit) rides classic IEEE 802.3 **length**-framed
Ethernet, with a 3-byte LLC header (DSAP/SSAP/Control) immediately after the
length field, conventionally addressed to the well-known multicast MAC
`01:80:C2:00:00:00`. Every field offset, length, and quirk below is
cross-checked directly against Wireshark's own `epan/dissectors/
packet-bpdu.c`, the same sourcing standard this codebase already applies
throughout (e.g. FF-HSE's `packet-ff.c`).

#### The link-layer-plumbing milestone

Every protocol decoded before this release was reached either through IPv4
or through a DIX Ethernet II EtherType (PROFINET RT/EtherCAT/GOOSE/SV all
still use a fixed EtherType, just no IP/TCP/UDP layer underneath). STP needs
neither: `link_layer.hpp`'s `parse_ethernet` now also recognizes IEEE 802.3's
own length-vs-EtherType boundary (a value strictly below `0x0600` in the
position an EtherType would otherwise occupy is always a LENGTH -- classic
802.3/LLC framing; `0x0600` and above is always a DIX EtherType -- the
boundary is exact, never ambiguous) and, when it's a length, opens the
3-byte LLC header (DSAP/SSAP/Control) that follows it, and, when that LLC
header's DSAP/SSAP is `0xAA` (SNAP), the further 5-byte SNAP header (OUI +
Protocol ID) underneath. This is additive groundwork, not a rewrite: every
DIX Ethernet II frame (`ethertype >= 0x0600`) this tool already decoded is
completely unaffected, since no existing dispatch path ever looked at a
sub-`0x0600` "ethertype" value before -- it previously just fell through to
a generic, unhelpful "non-ip" report naming a length as if it were an
EtherType. `EthernetFrame::llc_payload` (the bytes immediately after the
3-byte LLC header) is what `try_parse_stp` is actually handed; SNAP is not
part of STP's own envelope (SNAP is Cisco PVST+'s, see "Out of scope"
below) but the same plumbing is what lets this decoder *name* Cisco PVST+
by its SNAP OUI without decoding it.

#### Wire structure

Offsets below are relative to the start of the BPDU body (right after the
3-byte LLC header):

| Field | Offset | Size | Notes |
|---|---|---|---|
| Protocol Identifier | 0 | 2 | Always `0x0000` when recognized. |
| Protocol Version Identifier | 2 | 1 | `0`=STP (802.1D), `2`=RSTP (802.1w), `3`=MSTP (802.1s), `4`=SPB (802.1aq, named-only, see below). |
| BPDU Type | 3 | 1 | `0x00`=Configuration, `0x80`=Topology Change Notification (TCN), `0x02`=RST BPDU (reused for BOTH RSTP and MSTP, disambiguated by Protocol Version Identifier, never by BPDU Type alone). |

A **TCN BPDU** (Type `0x80`) is only those 4 bytes -- no flags, no bridge/
root IDs, sent by a bridge upward toward the root the instant it detects a
topology change. Its own version byte is never gated on: any version value
still decodes as a plain TCN.

A **Configuration BPDU** (Type `0x00`) and an **RST BPDU** (Type `0x02`)
share an identical 35-byte common body:

| Field | Offset | Size | Notes |
|---|---|---|---|
| Flags | 4 | 1 | See "Flags" below. |
| Root Identifier | 5 | 8 | See "Bridge/Root Identifier" below. |
| Root Path Cost | 13 | 4 | |
| Bridge Identifier | 17 | 8 | See "Bridge/Root Identifier" below. |
| Port Identifier | 25 | 2 | See "Port Identifier" below. |
| Message Age | 27 | 2 | Units of 1/256 second. |
| Max Age | 29 | 2 | Units of 1/256 second. |
| Hello Time | 31 | 2 | Units of 1/256 second. |
| Forward Delay | 33 | 2 | Units of 1/256 second. |

For Type `0x00` (classic STP), the BPDU ends here -- only Flags bits 7 (TCA)
and 0 (TC) are ever meaningful under classic STP, but every flag bit is
still surfaced generically (this codebase's usual "show it, note when it's
meaningful" posture). For Type `0x02`, one more byte follows: **Version 1
Length** (offset 35, 1 byte), always `0x00` for pure RSTP -- a nonzero value
here (together with version `>= 3` and enough captured bytes) signals that
an MST extension does NOT follow (see "MSTP detection gate" below).

**Flags** (1 byte, common body offset 4, and MSTI Flags offset 0 of each
MSTI message -- identical bit layout both places): bit 7 (`0x80`) Topology
Change Acknowledgment (TCA); bit 6 (`0x40`) Agreement (RSTP/MSTP only); bit
5 (`0x20`) Forwarding (RSTP/MSTP only); bit 4 (`0x10`) Learning (RSTP/MSTP
only); bits 3-2 (`0x0C`) Port Role (RSTP/MSTP only, `>> 2`: `0`=Unknown,
`1`=Alternate/Backup, `2`=Root, `3`=Designated); bit 1 (`0x02`) Proposal
(RSTP/MSTP only); bit 0 (`0x01`) Topology Change (TC).

**Bridge/Root Identifier** (8 bytes, appears at Root Identifier, Bridge
Identifier, CIST Bridge Identifier, and MSTI Regional Root -- identical
packing every time): a 2-byte value, top 4 bits (`0xF000`) = Bridge
Priority (rendered as the masked nibble itself, a multiple of 4096 --
default priority 32768 = nibble 8), bottom 12 bits (`0x0FFF`) = System ID
Extension (802.1t, carries a VLAN ID for per-VLAN spanning tree variants
like PVST+, itself out of scope here) or, for MSTI Regional Root, the MSTI
ID (MSTID) instead, followed by a 6-byte MAC. Both the raw 16-bit value and
the priority/extension split are surfaced.

**Port Identifier** (2 bytes, common body offset 25): Wireshark's own UI
shows this as one raw 16-bit value, but the underlying 802.1D spec defines
top 4 bits = Port Priority (a multiple of 16 -- default 128 = nibble 8, a
DIFFERENT multiplier than Bridge/Root Identifier's own priority nibble) +
bottom 12 bits = Port Number. This decoder decodes both the raw value and
that split, per this codebase's own "decode a field as fully as the spec
allows" convention even where the reference dissector's own UI doesn't
bother splitting it.

#### MSTP detection gate and the MST BPDU extension

A Type-`0x02` BPDU is decoded as a full MST BPDU only when ALL THREE hold:
Protocol Version Identifier `>= 3`, Version 1 Length `== 0`, and at least
102 bytes are present in the whole BPDU body. When Type is `0x02` but that
gate fails (even if version is 3), this decoder falls back to the plain
36-byte RST BPDU shape above, exactly matching the reference source.

When the gate holds, the MST BPDU body adds:

| Field | Offset | Size | Notes |
|---|---|---|---|
| Version 3 Length | 36 | 2 | See "How many MSTI messages follow" below. |
| MST Config Format Selector | 38 | 1 | |
| MST Config Name | 39 | 32 | ASCII, NUL-padded. |
| MST Config Revision Level | 71 | 2 | |
| MST Config Digest | 73 | 16 | An MD5/HMAC-MD5 digest of the VLAN-to-MSTI mapping table; shown as raw hex, never verified (this codebase's usual non-verification-of-opaque-digests posture). |
| CIST Internal Root Path Cost | 89 | 4 | Set only when Version 3 Length != 0 -- see below. |
| CIST Bridge Identifier | 93 | 8 | Set only when Version 3 Length != 0 -- the CIST regional root's OWN bridge ID, distinct from the outer Root/Bridge Identifier at offset 5/17. |
| CIST Remaining Hops | 101 | 1 | Set only when Version 3 Length != 0. |
| MSTI Configuration Message(s) | 102 | 16 each | See below. |

**How many MSTI messages follow** -- the reference source's own arithmetic,
not a naive `(Version 3 Length - 64) / 16`: if Version 3 Length is `>= 64`,
total MSTI bytes = Version 3 Length - 64 (the ordinary case). If it's
nonzero but `< 64`, it's instead treated as a COUNT OF MESSAGES rather than
bytes (total MSTI bytes = Version 3 Length * 16) -- a work-around for real
Cisco C3550 firmware observed sending Version 3 Length in units of messages
instead of octets; this decoder reproduces that exactly and notes when it's
taken. The resulting byte count is clamped to whatever bytes are actually
present and to a whole number of 16-byte messages (a partial trailing
message is noted, not decoded), and capped at 64 messages (the reference
source's own documented ceiling) against a malformed/adversarial capture.

**Version 3 Length == 0** is the "Alternative MSTI format" trigger: an
older, per-instance layout with MSTID as its own explicit field, a
different byte order, and 26 bytes per message instead of 16. This decoder
recognizes the trigger condition structurally (`StpFrame::is_alt_msti_format`)
and names it, but does NOT decode its body -- explicitly out of scope for
this release. Since CIST Bridge Identifier/Root Path Cost genuinely live at
different byte offsets in the alternative format, this decoder does not
read them at the IEEE offsets for ANY Version-3-Length-0 frame at all,
whether or not the alternative format's own exact-length trigger matches.

**MSTI Configuration Message** (16 bytes each): MSTI Flags (offset 0, same
8-bit layout as the common Flags byte); MSTI Regional Root (offset 1, 8
bytes, the Bridge/Root Identifier packing above, `.ext` here is the MSTID);
MSTI Internal Root Path Cost (offset 9, 4 bytes); MSTI Bridge Identifier
Priority (offset 13, 1 byte); MSTI Port Identifier Priority (offset 14, 1
byte); MSTI Remaining Hops (offset 15, 1 byte). The two Priority bytes are
the one place this decoder's own research deliberately double-checked an
assumption against the source and found it wrong: the reference dissector
decodes ONLY the top nibble of each byte (`>> 4`), rendered as a bare 0-15
value with NO multiplier (unlike every other priority field in this
format) -- the bottom nibble of each byte is simply never decoded by the
reference dissector at all, and this decoder matches that exactly.

#### Structural detection gate

Protocol Identifier `== 0x0000` AND BPDU Type in `{0x00, 0x02, 0x80}` AND
(for `0x00`/`0x02` only -- a TCN's own version byte is never checked)
Protocol Version Identifier in `{0, 2, 3, 4}` (version 4 is SPB, recognized
structurally but named-only, never body-decoded). This decoder is
deliberately slightly STRICTER here than Wireshark's own dissector, which
accepts (and merely warns on) any Protocol Version Identifier byte at all --
this decoder returns "not STP" for a Type-`0x00`/`0x02` BPDU whose version
isn't one of `{0, 2, 3, 4}`, a deliberate, narrower choice, not a
discrepancy this decoder failed to notice. See PROTOCOL DETECTION below for
how this gate compares in strength to this codebase's other detectors.

#### What's decoded vs. named-only

**Decoded**: classic Configuration BPDUs, TCN BPDUs, RST BPDUs (RSTP and
MSTP's own common 36-byte shape), and the full MST BPDU extension including
every MSTI Configuration Message, up to the safety cap above.

**Named but not decoded further** (matching this codebase's established
"recognized but not this release's problem" posture -- see e.g. GOOSE's own
GSE Management PDU):

- **Cisco PVST+ / Rapid-PVST+**: a genuinely different wire envelope, not a
  variant of the format above -- SNAP-encapsulated (LLC DSAP=SSAP=`0xAA`,
  not `0x42`) with Cisco's OUI (`00:00:0C`), typically addressed to
  `01:00:0C:CC:CC:CD`, with a proprietary Originating-VLAN TLV appended
  after the standard BPDU body. Recognized structurally (SNAP DSAP/SSAP +
  Cisco OUI) and named `"Cisco PVST+ (SNAP-encapsulated, not decoded)"`,
  but its body is never decoded here -- the same treatment R-GOOSE/R-SV get
  relative to GOOSE/SV.
- **SPB** (Shortest Path Bridging, 802.1aq, Protocol Version Identifier
  `== 4`, reusing BPDU Type `0x02`): named only, `"SPB (802.1aq), not
  decoded -- out of scope"`. Wireshark's own dissector actually does decode
  part of a version-4 SPB frame (it runs the identical MSTP body-parsing
  path, then appends its own further "SPT Extension"); this decoder
  deliberately does not follow that path -- ANY version-4 frame is
  named-only from the Protocol Version Identifier byte alone.
- **GARP (GVRP/GMRP)**: shares STP's own LLC DSAP/SSAP pair (`0x42`/`0x42`)
  -- disambiguated ONLY by destination MAC, matching Wireshark's own
  `dissect_bpdu` exactly: addresses `01:80:C2:00:00:0D` and
  `01:80:C2:00:00:20`-`0x2F` are GVRP/GMRP, not STP, and are checked and
  redirected to a `"GARP (GVRP/GMRP) ... not decoded"` report BEFORE
  `try_parse_stp` is even called. This is the one case in this codebase
  where a fixed address genuinely does gate detection -- everywhere else,
  including STP's own Bridge Group Address multicast MAC, this codebase
  prefers a structural check over an address check; this is the documented
  exception, forced by DSAP/SSAP `0x42` alone being genuinely ambiguous
  between STP and GARP.
- **Any other LLC DSAP/SSAP pair** on a classic-802.3-framed packet (e.g.
  IPX, SNA) is named generically by its raw DSAP/SSAP values, never guessed
  at further.

#### Validation

Two real STP-family captures, both from `ITI/ICS-Security-Tools` (the same
public collection this project's PROFINET/GOOSE/SV real fixtures already
cite) -- see `tests/real_captures/stp/ATTRIBUTION.md` for full provenance:

- **`plant1_stp_only.pcap`** (42 frames, trimmed by `tshark -Y stp` from the
  same `Plant1.pcap` this project's PROFINET/CIP-I/O fixtures already draw
  from): 42 real classic Configuration BPDUs, one bridge's steady-state
  Hello traffic over an 82-second window, every one structurally identical
  (`Root=32768/80/64:a0:e7:9a:05:80 Cost=4
  Bridge=32768/80/64:ae:0c:34:a3:80 Port=0x8083`), no TC/TCA ever set.
- **`sample_file_mms_and_goose.pcap`** (the same file this project's own
  GOOSE/MMS real fixtures already use, byte-for-byte): 12 real RSTP RST
  BPDUs (6 back-to-back pairs from bridge ports `0x8010`/`0x8013`, all
  agreeing on the same root and steady-state `Role=Designated [Learning]
  [Forwarding]`), mixed in with unrelated NTP/SMB/MMS/GOOSE traffic.

Both captures confirm periodic Hello-interval BPDU transmission from an
already-converged bridge, and both confirm the LLC padding-trim path
(`llc_trailing_bytes_trimmed`) at two different byte counts (60-byte
frames/8 trailing bytes for Plant1's classic BPDUs, 64-byte frames/7
trailing bytes for the RST BPDUs' one extra Version-1-Length byte).

**Honest gap**: neither real capture contains a TCN BPDU, any MSTP/
MST-extension traffic, or SPB traffic, nor do they exercise the RST Port
Role values Root/Alternate/Backup (only Designated appears), the
Proposal/Agreement flags, the TC/TCA flags on a Configuration/RST BPDU,
Cisco PVST+ framing, or GARP/GVRP/GMRP traffic. Every scan of both
`mrhenrike/PCAPTrafficAnalysis` and `ITI/ICS-Security-Tools` for this
project turned up nothing further along those lines. All of that -- every
RST Port Role and flag combination, TCN under both a classic and RSTP
Protocol Version, the full MST BPDU extension (including the Cisco Version-
3-Length-below-64 work-around and multi-MSTI-message framing), SPB
named-only recognition, PVST+ named-only recognition, and GARP/GVRP/GMRP
disambiguation by destination MAC -- is validated only against the
synthetic `tests/sample_stp.pcap` fixture (see `tools/make_sample_pcap.py`'s
`build_stp_sample`), cross-checked against the reference dissector's source
rather than an independent real capture; packets 1 and 2 of that synthetic
fixture reproduce the two real captures' own first frames byte-for-byte.
This mirrors the same honest gap already documented for this codebase's
other protocols' less-common paths.

### DeviceNet (CAN-bus CIP, pcap link type `LINKTYPE_CAN_SOCKETCAN` == 227)

DeviceNet is ODVA's original CAN-bus-based CIP (Common Industrial Protocol)
network -- the same application protocol family EtherNet/IP's own explicit
messaging uses, but carried directly over a CAN (Controller Area Network)
bus's 11-bit standard identifiers instead of Ethernet/IP/TCP/UDP. There is
no Ethernet, no IP, no TCP/UDP anywhere in this protocol at all. Every
message-group boundary, bitmask, and named value below is cross-checked
directly against Wireshark's own `epan/dissectors/packet-devicenet.c`, the
same sourcing standard this codebase already established for STP
(`packet-bpdu.c`) and FF-HSE (`packet-ff.c`).

#### The second link-layer milestone

STP was this codebase's first addition of a link layer other than plain DIX
Ethernet II framing, but it stayed within classic Ethernet/802.3/LLC
framing underneath -- `parse_ethernet` just learned a second way to read
what follows the source MAC. DeviceNet needs something STP didn't: a pcap
capture of a CAN bus carries no Ethernet header, no MAC addresses, and no
EtherType at all -- just one small fixed-format record per CAN frame,
directly. This is captured under the pcap `LINKTYPE_CAN_SOCKETCAN` (227)
link type -- Linux SocketCAN's own capture framing, what `candump -l`,
`tcpdump -i can0`, or Wireshark itself write when capturing a CAN
interface. Because this is a wholly separate, unrelated link layer from
Ethernet, it does not extend `parse_ethernet`/`link_layer.hpp` the way STP's
LLC/SNAP recognition did; it lives in its own pair of files
(`can_socketcan.hpp`/`.cpp`) with its own entry in `pcap_reader.hpp`'s
`LinkType` enum and its own top-level branch in `Decoder::decode`, checked
before any Ethernet parsing is attempted at all -- see PROTOCOL DETECTION's
own DeviceNet paragraph. `has_ethernet` and `has_ip` both stay `false` for
every DeviceNet packet (`src_mac`/`dst_mac`/`src_ip`/`dst_ip` are all
meaningless here) -- the first protocol in this codebase with neither, a
shape STP's own `has_ip == false` (but `has_ethernet == true`, since STP at
least still rides Ethernet framing) doesn't quite share.

SocketCAN framing itself is protocol-agnostic -- any CAN application
protocol's frames (DeviceNet, CANopen, J1939, or raw CAN traffic with no
higher-layer protocol at all) would show up in a capture this same way.
DeviceNet is the only protocol this codebase currently decodes on top of
it; `can_socketcan.hpp`/`.cpp` only understands the pcap record shape and
CAN frame header/flag bits, nothing about DeviceNet's own message-group
semantics.

#### SocketCAN capture record wire format

An 8-byte fixed header immediately followed by `payload_length` bytes of
payload -- no trailer, no padding beyond what `payload_length` itself
declares:

| Field | Offset | Size | Notes |
|---|---|---|---|
| CAN ID + flags | 0 | 4 | **Big-endian** -- the one easy mistake to make here, since the in-kernel `canid_t` value this mirrors is native-endian; a capture file always stores it byte-swapped to big-endian. See "CAN ID + flags" below. |
| Payload Length | 4 | 1 | 0-8 for a classic CAN frame, 0-64 when the FD flag (below) is set. Not validated against CAN FD's discrete legal size set (0,1,2,...,8,12,16,20,24,32,48,64) -- read as-is, clamped to what was actually captured. |
| FD Flags | 5 | 1 | Bit `0x04` (`CANFD_FDF`) marks a CAN FD frame. The other bits (`CANFD_BRS`/`CANFD_ESI`) are read into `fd_flags` but not individually decoded -- DeviceNet predates CAN FD and never sets them. |
| Reserved | 6 | 1 | Always 0 on the wire; read but not surfaced/validated. |
| Reserved | 7 | 1 | Same. |
| Payload | 8 | `payload_length` | See message-group classification below. |

**CAN ID + flags** (the 4-byte big-endian value at offset 0) -- top 3 bits
are flags, bottom 29 bits are the identifier:

| Bit | Flag | Meaning |
|---|---|---|
| 31 (`0x80000000`) | EFF | Extended Frame Format -- a 29-bit extended identifier (SAE J1939 and others use this; DeviceNet never does). |
| 30 (`0x40000000`) | RTR | Remote Transmission Request -- requests data from another node, carries no payload of its own regardless of what Payload Length claims. |
| 29 (`0x20000000`) | ERR | Error frame -- signals a bus-level error condition, not an ordinary data frame. |
| 28-0 (`0x1FFFFFFF`) | -- | The identifier -- only the bottom 11 bits (`0x7FF`) are meaningful when EFF is clear (standard ID); all 29 bits are meaningful when EFF is set (extended ID). |

**Truncation handling** matches this codebase's usual "degrade tolerantly,
never crash" posture: a capture record with fewer than the fixed 8-byte
header itself present is a parse error (there's nothing meaningful left to
decode without even the declared payload length); a header-present-but-
payload-short record (a snaplen-truncated or otherwise short capture) is
handled tolerantly instead -- the payload is clamped to whatever bytes are
actually present, `devicenet_payload_truncated` is set, and a note explains
it, rather than the whole packet failing.

#### DeviceNet frame validity and message-group classification

`try_parse_devicenet` rejects a CAN frame outright -- the ONLY rejection
condition -- when EFF, RTR, or ERR is set, mirroring
`dissect_devicenet`'s own literal first check
(`if (can_info.id & (CAN_ERR_FLAG | CAN_RTR_FLAG | CAN_EFF_FLAG)) return
0;`) exactly; such a frame is reported as `non-ip`, named by which flag(s)
are set (e.g. `"CAN frame, id=0x1ABCDEF [EFF -- extended 29-bit id] (not a
valid DeviceNet frame shape)"`), not decoded further. Extended (29-bit) IDs,
RTR frames, and error frames simply are not valid DeviceNet at all --
DeviceNet only ever uses standard 11-bit CAN identifiers.

Every other frame -- standard 11-bit ID, no RTR/ERR -- is classified into
one of four message groups purely by where its masked 11-bit CAN ID falls,
checked in this exact order (matching the reference dissector's own
if/else-if chain):

| Group | CAN ID range | Source MAC ID extraction | Message ID extraction |
|---|---|---|---|
| 1 | `id <= 0x03FF` | `id & 0x003F` (bits 0-5) | `id & 0x03C0` (bits 6-9) |
| 2 | `0x0400 <= id <= 0x05FF` | `(id & 0x01F8) >> 3` (bits 3-8) | `id & 0x0007` (bits 0-2) |
| 3 | `0x0600 <= id <= 0x07BF` | `id & 0x3F` (bits 0-5, no shift) | `id & 0x01C0` (bits 6-8) |
| 4 | `0x07C0 <= id <= 0x07EF` | *(none defined)* | `id & 0x3F` |
| Unclassified | `0x07F0 <= id <= 0x07FF` | *(none)* | *(none -- the reference dissector's own if/else-if chain simply falls through here too)* |

Note Group 2's Source MAC ID extraction is right-shifted by 3 (a genuinely
different bit layout from Group 1's and Group 3's own unshifted 6-bit
masks) -- getting this wrong would silently misattribute every Group 2
frame to the wrong MAC ID.

**Group 1** (a slave device's own I/O data going back to a master/scanner):
Message ID `0x0300`/`0x0340`/`0x0380`/`0x03C0` are named ("Slave's I/O
Multicast Poll Response", "...Change of State or Cyclic Message", "...
Bit-Strobe Response Message", "...Poll Response or COS/Cyclic Ack
Message"); anything else in range falls back to "Other Group 1 Message"
(the reference dissector's own fallback, not a gap here). The payload is
raw I/O data, shown only as a byte count -- never further decoded, matching
the reference dissector exactly (it has no decode for Group 1 payload
bytes either, absent an out-of-band device-behavior configuration this
decoder has no equivalent of).

**Group 2** (a master/scanner's own commands to a slave, plus a slave's
explicit/unconnected responses): Message ID 0-7 are all named (e.g.
"Master's I/O Bit-Strobe Command Message", "Slave's Explicit/Unconnected
Response Messages", "Duplicate MAC ID Check Messages" for 7). Message ID 7
(Duplicate MAC ID Check) additionally decodes its own small fixed payload
when at least 7 bytes are present and the frame isn't CAN FD: byte 0 bit
`0x80` is the same CIP-style Request/Response bit Group 3's own service
byte uses, byte 0 bits `0x7F` are a Physical Port Number, bytes 1-2 are a
little-endian Vendor ID, and bytes 3-6 are a little-endian Serial Number.

**Group 3** (Unconnected/Group-2-Only-Unconnected explicit messaging --
CIP explicit messages) is the only group that also carries structure in its
PAYLOAD, not just its CAN ID. Message ID `0x000`/`0x040`/`0x080`/`0x0C0`/
`0x100` are all genuinely generic "Group 3 Message" in the reference source
too; `0x140` is "Unconnected Explicit Response Message", `0x180` is
"Unconnected Explicit Request Message", `0x1C0` is "Invalid Group 3
Message". The first payload byte (when present) carries: bit `0x80`
Fragmentation flag, bit `0x40` XID flag, bits `0x3F` destination MAC ID.
When Fragmentation is set, this is a fragmented message -- Wireshark's own
dissector does NOT reassemble Group 3 fragments either (its own
`dissect_devicenet` has a literal `/* TODO: Handle fragmentation */`
comment immediately before reporting it unhandled), and this decoder
matches that gap faithfully rather than inventing its own reassembly:
nothing past the first payload byte is decoded for a fragmented message.
When Fragmentation is clear and a second payload byte is present, that byte
is a CIP-style service/request-response byte -- top bit `0x80` = response
(vs. request), bottom 7 bits = the CIP service code. This is EXACTLY the
same convention EtherNet/IP's own CIP explicit messaging uses (see
PROTOCOL COVERAGE's EtherNet/IP section), so this decoder reuses
`enip.cpp`'s own `cip_service_name` directly for the generic CIP
common-services set, rather than duplicating a second name table. DeviceNet
additionally defines four of its own service codes, checked BEFORE
`cip_service_name` is ever called: `0x4B` "Open Explicit Message Connection
Request", `0x4C` "Close Connection Request", `0x4D` "Device Heartbeat
Message", `0x4E` "Device Shutdown Message" -- note these four numeric
values mean something COMPLETELY DIFFERENT under EtherNet/IP's own
Rockwell symbolic-tag addressing (e.g. `0x4C` is `Read_Tag` there), which
is exactly why `cip_service_name` is called from here with
`have_path=true`/`is_symbolic=false`/`is_conn_mgr=false` -- the combination
that avoids ever picking up that unrelated table by accident (see
`cip_service_name`'s own comment in `enip.cpp`). Beyond the service code
name itself, a Group 3 explicit message's own request path/data is not
further decoded -- see "Out of scope" below.

**Group 4** (`0x07C0`-`0x07EF`): Message ID `0x2C`/`0x2D`/`0x2E`/`0x2F` are
named ("Communication Faulted Response/Request Message", "Offline
Ownership Response/Request Message"); anything else falls back to
"Reserved Group 4 Message". No MAC ID extraction is defined for Group 4 in
the reference dissector at all, so none is invented here either.

**`0x07F0`-`0x07FF`**: the reference dissector has no handling for this
range at all -- its own if/else-if chain simply falls through with nothing
decoded once the ID exceeds Group 4's own range. This decoder matches that:
`devicenet_group` stays `0` ("Unclassified"), only the raw CAN ID is shown,
and a note explains why -- not a guessed fifth message group.

#### CAN FD

DeviceNet as a protocol predates CAN FD entirely and never sets FD Flags'
`CANFD_FDF` bit. `can_socketcan.hpp` still recognizes and surfaces the flag
structurally (so this decoder never crashes or misreads a CAN FD frame's
larger payload), but for an FD frame, this decoder does not attempt Group 1
I/O / Group 2 Duplicate-MAC-ID-Check / Group 3 service-byte payload
decoding at all -- only the CAN-ID-derived message-group classification
(which needs no payload access) is still shown, with a note.

#### Out of scope for this release

Matching this codebase's established "recognized but not this release's
problem" posture (see e.g. STP's Cisco PVST+/SPB out-of-scope section
above):

- **Extended (29-bit) IDs, RTR frames, error frames** -- not valid
  DeviceNet at all, rejected outright (see above).
- **CAN FD frame payloads** -- recognized structurally, not semantically
  decoded (see above).
- **Group 3 fragmentation reassembly** -- matches Wireshark's own
  dissector's own unimplemented TODO; not a gap unique to this port.
- **Full CIP object/class/instance/attribute request-path decoding**
  within a Group 3 explicit message's own payload, beyond the destination
  MAC ID / service code bytes already decoded. EtherNet/IP's own `enip.cpp`
  has much richer CIP path decoding (`CipPath`, EPATH logical segments, the
  ANSI Extended Symbol segment for Rockwell named-tag addressing), none of
  which this file replicates -- even the reference DeviceNet dissector
  itself only partially decodes a handful of specific services' (Open/
  Close Explicit Message) own small fixed request/response bodies past the
  service byte; this decoder does not replicate even that. The bytes
  following a decoded service code are shown only as raw hex, the same
  "structural only" treatment CIP I/O's own assembly data gets.

#### Why not ControlNet too

ODVA's other original CIP network, ControlNet, is not decoded here, and
this is a structural impossibility for a pcap-based tool, not a scope
choice or something planned for later. ControlNet uses a proprietary
physical layer -- RG-6 coaxial cable, Manchester-coded signaling, and an
implicit token-passing MAC scheme -- that no standard packet capture tool,
including Wireshark itself, can sniff: there is no pcap `LINKTYPE_*` value
for it, and no `packet-controlnet.c` exists anywhere in Wireshark's own
dissector tree. The only way to observe ControlNet traffic in practice is
Rockwell Automation's own proprietary ControlNet Traffic Analyzer hardware/
software, which does not produce a pcap-compatible file format this (or any
other) pcap-decoding tool could read. There is no capture file this tool
could ever be handed that would contain decodable ControlNet traffic --
categorically different from DeviceNet (an ordinary, standard SocketCAN
pcap capture) or even STP (classic Ethernet framing), and the same category
of hard limit as "this tool can't decode encrypted TLS payloads without the
key," not a gap tracked on ROADMAP.

#### Validation

No real public DeviceNet/CAN-bus capture was found during this feature's
research -- searched `ITI/ICS-Security-Tools` (the same collection this
project's PROFINET/GOOSE/SV/STP real fixtures already draw from; its own
`pcaps/README.md` lists no CAN-bus or DeviceNet capture of any kind among
its protocol-organized captures) plus general web search for "DeviceNet
pcap"/"CAN capture", and no other public source turned one up either. This
decoder is therefore validated only against the synthetic
`tests/sample_devicenet.pcap` fixture (33 frames -- see
`tools/make_sample_pcap.py`'s `build_devicenet_sample`), hand-built and
cross-checked against `packet-devicenet.c`'s own source rather than an
independent real capture -- the same honest gap already documented for
this codebase's other synthetic-only protocols (e.g. FOUNDATION Fieldbus
HSE, Sampled Values). The fixture exercises all four message groups and
every named message type within them, the Duplicate MAC ID Check payload
in both directions, all four DeviceNet-specific CIP service codes plus a
generic reused CIP service, the XID flag, a fragmented Group 3 message, a
Group 3 message with no payload and one missing its service byte, the
unclassified `0x07F0`-`0x07FF` range, all three of EFF/RTR/ERR rejection,
a CAN FD frame, and a truncated payload's clamp-and-note path.

### Link/IP-layer plumbing: non-IPv4 Ethernet, and non-TCP IPv4 (including UDP)

Every protocol above rides on Ethernet + IPv4 + TCP. Traffic outside that --
a non-IPv4 Ethernet frame, or a non-TCP IPv4 payload -- was previously
reported only as a bare hex ethertype or protocol number (`non-ip`/
`non-tcp`) and otherwise dropped. It's now additionally **named**, for a
deliberately small, OT-relevant set of values, cross-checked against
Wireshark's own `epan/etypes.h` (EtherTypes) and the long-stable IANA IP
protocol number registry (not reverse-engineered from a single capture):

- **EtherTypes** (`link_layer.hpp`'s `ethertype_name`): ARP, IPv6, LLDP, PTP
  (IEEE 1588), MPLS unicast, and 802.1ad/stacked-VLAN (the QinQ case
  `parse_ethernet`'s own comment already documented as "will simply fail to
  recognize the inner ethertype" -- it's now named as such instead of a bare
  `0x8100`) are named but not decoded further. PROFINET RT (`0x8892`),
  IEC 61850-8-1 GOOSE (`0x88B8`), IEC 61850-9-2 Sampled Values (`0x88BA`),
  and EtherCAT (`0x88A4`) are also named here, but, like CIP I/O below, a
  frame that actually looks like DCP/cyclic IO data, a GOOSE APDU, a SavPdu,
  or an EtherCAT frame header is decoded and reported as
  `profinet`/`goose`/`sv`/`ethercat`, not `non-ip` -- see PROTOCOL COVERAGE's
  PROFINET RT, GOOSE, Sampled Values, and EtherCAT sections.
- **IPv4 protocol numbers** (`ipv4.hpp`'s `ip_protocol_name`): ICMP, IGMP,
  IPv6-in-IPv4, GRE, ESP, AH, ICMPv6, OSPF, SCTP -- alongside TCP and UDP,
  which get their own dedicated handling (below and elsewhere in this
  document) rather than just a name.
- **UDP** (`udp.hpp`, protocol `udp`): the 8-byte UDP header itself
  (source/destination port, declared length, clamped to what was actually
  captured the same way `parse_ipv4` already clamps to IPv4's own
  `total_length` -- see that function's comment) is now opened and reported,
  with source/destination port surfaced the same way TCP's are (`endpoint()`
  in `output.cpp`, and `src_port`/`dst_port` in JSON/CSV). EtherNet/IP's own
  CIP I/O port (2222) is no longer just named here: a UDP payload actually
  shaped like CIP I/O traffic is now decoded and reported as `enip`, not
  `udp` -- see PROTOCOL COVERAGE's EtherNet/IP section. A UDP/2222 payload
  that *doesn't* match that shape still falls through to this plain `udp`
  handling, same as before.

**This is groundwork plumbing, explicitly not a new protocol decoder --**
**except for CIP I/O, PROFINET RT, GOOSE, Sampled Values, and now EtherCAT,**
**which are** (see PROTOCOL COVERAGE's EtherNet/IP, PROFINET RT, GOOSE,
Sampled Values, and EtherCAT sections). With EtherCAT decoded, this project
no longer tracks any named-but-undecoded raw-Ethernet OT protocol of its
own -- ARP/LLDP/PTP/MPLS/stacked-VLAN above are general-purpose Ethernet
framing, not OT-specific. A value outside every table above still shows only
as a bare hex ethertype or decimal protocol number, exactly as before --
nothing is guessed at for an EtherType/protocol/port this tool doesn't
recognize.

`policy validate` does not yet evaluate any of this traffic against a
conduit: it's still counted only in `PolicyReport::skipped_non_tcp`, exactly
as an unrecognized non-TCP packet was counted before this plumbing existed
(see `PolicyEngine::observe`'s doc comment). Opening the policy engine up to
non-TCP/non-IP conduits is real follow-on work, not part of this pass -- see
ROADMAP.

Validated by construction (`tests/sample_link_transport_layers.pcap`, see
`tools/make_sample_pcap.py`'s `build_link_and_transport_layer_sample`) and,
organically, against every existing real capture in this project's test
set: re-running the full real-capture corpus after adding this surfaced
several previously-invisible ARP frames and real UDP traffic (DNS on port
53, NetBIOS on port 138) that used to disappear into an undifferentiated
`non-ip`/`non-tcp` bucket.

## CAPTURED FRAME PADDING

Ethernet requires a minimum frame size (60 bytes, excluding the trailing
CRC, which capture files don't store anyway). A genuinely small packet --
most commonly a bare TCP ACK with no payload -- gets zero-padded by the
NIC/driver to reach that minimum, so the *captured* frame is often a few
bytes longer than the IP datagram it actually contains. conduitscope clamps
the IPv4 payload to the IP header's own `total_length` field specifically to
avoid mistaking that padding for real TCP payload; when it trims some, the
decoded packet gets a note saying how many bytes were dropped and why. If
you ever see a `[tcp]` packet reported as having no payload alongside a
"were trimmed" note, that's expected and not a sign of anything wrong with
the capture -- it's exactly this padding being correctly discarded rather
than misreported as data.

(This clamp was added after a real capture surfaced the bug it fixes: a
handful of ordinary ACKs were being reported as carrying 6 bytes of Modbus/
DNP3/S7comm-shaped TCP payload, which was actually just unclamped Ethernet
padding being handed to the protocol parsers. If `total_length` is 0 or
otherwise implausible -- which can happen on outbound packets with NIC
checksum/segmentation offload -- conduitscope falls back to using every
captured byte, same as before this fix, since there's nothing trustworthy to
clamp to in that case.)

## LIMITATIONS

These are current, not aspirational -- each has a corresponding ROADMAP item.

- **A handful of rare/obsolete pcapng block types are skipped, not decoded.**
  Specifically the obsolete "Packet Block" (superseded by the Enhanced Packet
  Block industry-wide in the mid-2000s), Interface Statistics Blocks, Name
  Resolution Blocks, Decryption Secrets Blocks, and any custom/vendor block
  type. No packets are lost from a file written by any mainstream capture
  tool (dumpcap, Wireshark, tshark all use the Enhanced Packet Block); this
  only matters for a file from an unusual/legacy writer, and even then only
  means `conduitscope info`'s packet count would read lower than an external
  tool's for that specific file. See "pcap vs. pcapng" above.
- **General TCP stream reassembly is implemented, but narrowly scoped.**
  `Decoder::reassemble_tcp_payload` (`decoder.hpp`/`decoder.cpp`) buffers a
  single Modbus MBAP message, DNP3 data-link frame, IEC 104 APDU, EtherNet/IP
  encapsulation message, TPKT/COTP frame, HART-IP message, OPC UA
  UA-TCP/SecureConversation chunk, or MQTT packet's own bytes, per directional
  TCP flow, when it is split across two or more TCP segments -- so a Modbus
  PDU that straddles a segment boundary, a DNP3 data-link frame split
  mid-header, an IEC 104 APDU split mid-APCI/ASDU, an EtherNet/IP
  encapsulation message split mid-header or mid-CIP-message, an S7comm or
  MMS request/response TPKT frame split across segments (the same TPKT/COTP
  reassembly buffers both, since MMS rides the identical framing -- see
  PROTOCOL COVERAGE's MMS section), an OPC UA chunk, or an MQTT packet (whose
  own Remaining Length is honestly the weakest of this whole list's declared-
  length signals -- see PROTOCOL DETECTION's "Why MQTT is tried last")
  split across segments all now get fully
  reassembled and decoded, not just the first segment's worth of bytes.
  Each protocol's own declared length field (the MBAP length, the DNP3
  data-link length byte, the IEC 104 APCI length byte, the EtherNet/IP
  encapsulation header's length field, the TPKT length field, HART-IP's
  MsgLength field, OPC UA's MessageSize field, MQTT's own Remaining Length)
  is what tells the reassembler how many bytes to wait for; a segment
  whose sequence number doesn't extend the buffered bytes contiguously is
  either trimmed (an overlapping retransmission) or, if it's genuinely ahead
  of where expected (a gap -- a segment very likely wasn't captured), causes
  the in-progress reassembly to be abandoned with a note rather than spliced
  together wrong. This resyncs rather than reorders: an out-of-order segment
  that would need to be held and inserted later is treated the same as a
  gap, not buffered for eventual reordering (matching how this tool
  processes packets generally -- one single, strict capture-file-order pass,
  with no out-of-order buffering anywhere else in the codebase either).
  What this does NOT cover: true out-of-order reordering, per the
  resync-not-reorder paragraph above -- an out-of-order segment is treated
  as a gap (abandon and resync), never held and spliced in later. Two
  related but separate things now ARE covered, by their own mechanisms, not
  this one: authoritative (non-heuristic) Modbus request/response pairing by
  transaction ID (`Decoder::pair_modbus_transaction` -- see PROTOCOL
  DETECTION) and chaining a genuine S7comm message across multiple complete
  TPKT/COTP frames via COTP's own EOT bit
  (`Decoder::reassemble_cotp_data_frame` -- see PROTOCOL COVERAGE's S7comm/
  COTP section, and further down in this list). MMS shares this exact
  EOT-based fragment-reassembly mechanism as-is (it needs no mechanism of
  its own -- see PROTOCOL COVERAGE's MMS section), though it has no
  real-capture evidence of ever needing it: every real MMS capture checked
  so far carries its message complete in a single COTP Data frame.

  DNP3 additionally has its own separate, higher-layer reassembly: an
  *application* fragment that spans multiple complete data-link frames
  (transport FIR=1 on the first, FIN=0 until the last) is buffered per TCP
  flow across however many packets it takes and decoded once FIN=1 arrives;
  see PROTOCOL COVERAGE and `Decoder::process_dnp3_frame`. This layer is
  unvalidated against real traffic: every real DNP3 capture checked so far
  (see tests/real_captures/dnp3/ATTRIBUTION.md) used only complete,
  single-data-link-frame fragments, so it has no real-world example to
  confirm against, only the synthetic fixtures in tests/sample_dnp3.pcap.
  The general TCP-segment-level reassembly described above was, for a long
  time, unvalidated against real traffic (every real capture checked kept
  every PDU/frame within one TCP segment, including all six real IEC 104
  captures and both real EtherNet/IP captures -- see
  tests/real_captures/iec104/ATTRIBUTION.md and
  tests/real_captures/enip/ATTRIBUTION.md) -- verified instead by diffing this
  tool's full output against every real fixture before and after adding it
  (byte-for-byte identical), confirming it changes nothing for traffic that
  doesn't need it, and by synthetic fixtures (tests/sample_tcp_reassembly.pcap)
  for the reassembly itself. That changed with OPC UA's own real capture
  (`tests/real_captures/opcua/ATTRIBUTION.md`), which genuinely does split
  multiple messages across TCP segments (a GetEndpointsResponse across 5
  segments, a CreateSessionResponse across 6, a CallRequest across 4) --
  the first real-world confirmation this mechanism gets, all correctly
  reassembled and decoded. It's also distinct from multiple *complete*
  DNP3 data-link frames landing in one TCP segment (common, since DNP3
  frames are small), which conduitscope handles separately -- see PROTOCOL
  COVERAGE's DNP3 section.
- **No IPv6.** Only IPv4 is parsed; an IPv6 packet over Ethernet is reported
  as `non-ip` (named "IPv6" -- see PROTOCOL COVERAGE's link/IP-layer
  plumbing section -- but its own header is not opened), and over a raw-IP
  link type falls through to `parse-error` instead (there is no Ethernet
  ethertype field to name it by in that case).
- **IPv4 fragmentation is not reassembled.** A fragmented IPv4 packet's TCP
  header will very likely fail to parse and be reported as a parse-error on
  the fragments after the first.
- **Non-IPv4 Ethernet frames and non-TCP IPv4 payloads (including UDP) are
  named but not decoded, with six exceptions (CIP I/O, PROFINET RT, GOOSE,
  Sampled Values, EtherCAT, and BACnet/IP).** A deliberately small,
  OT-relevant set of EtherTypes/IP-protocol-numbers is recognized by name
  (ARP, LLDP, ICMP, and the rest -- see PROTOCOL COVERAGE); nothing outside
  that set gets more than a bare hex/decimal number, and even a *named* one
  gets no further parsing of its own framing. The six exceptions are
  EtherNet/IP's CIP I/O traffic on UDP port 2222, PROFINET RT (EtherType
  `0x8892`, DCP and cyclic real-time IO), IEC 61850-8-1 GOOSE (EtherType
  `0x88B8`), IEC 61850-9-2 Sampled Values (EtherType `0x88BA`), EtherCAT
  (EtherType `0x88A4`), and BACnet/IP (UDP port 47808/0xBAC0), all of which
  are now decoded, not just named -- see PROTOCOL COVERAGE's EtherNet/IP,
  PROFINET RT, GOOSE, Sampled Values, EtherCAT, and BACnet/IP sections.
  `policy validate` does not yet evaluate ANY UDP traffic against a conduit,
  decoded or not (it only ever looks at TCP flows -- this applies equally to
  CIP I/O and BACnet/IP), and never evaluates PROFINET RT, GOOSE, Sampled
  Values, or EtherCAT either (all four ride raw Ethernet with no IP/TCP/UDP
  layer at all, so there is no IP-based conduit rule that could match any of
  them) -- see that section and ROADMAP.
- **CIP I/O (implicit messaging) decoding does not value-decode the actual
  I/O data, and has no cross-datagram state.** The Connected Data Item's
  contents are shown only as raw hex -- see PROTOCOL COVERAGE's CIP I/O
  subsection for the two reasons (no generic self-describing type, and not
  tracking a connection's negotiated transport class), and specifically why
  a possible leading 16-bit CIP sequence count is never stripped from that
  hex. Each datagram is also decoded entirely independently: a connection ID
  is not cross-referenced against the Forward_Open that established it (even
  if that exchange is in the same capture), and sequence-number continuity
  across datagrams on the same connection is not tracked or flagged if
  broken. No real capture containing genuine CIP I/O traffic was found to
  validate this decoder against -- see `tests/real_captures/enip/
  ATTRIBUTION.md` for exactly what was searched and what corroborating
  sources (Wireshark's dissector source, the CISA `icsnpp-enip` Zeek parser)
  were used instead.
- **PROFINET RT cyclic IO data has no reliable length, no real-capture
  validation, and DCP request/response pairing isn't cross-checked.** A
  cyclic RT frame (FrameID `0x8000`-`0xBFFF`) has no length field for its IO
  data -- conduitscope infers it as everything between the FrameID and the
  fixed 4-byte CycleCounter/DataStatus/TransferStatus trailer, which is
  indistinguishable from Ethernet minimum-frame-length padding when the
  real IO payload is short; a short IO datagram may therefore show padding
  bytes as if they were IO data (see PROTOCOL COVERAGE's PROFINET RT
  section). No real capture containing cyclic RT IO data was found to
  validate `decode_cyclic` against -- only the hand-built
  `tests/sample_profinet.pcap` exercises it; see `tests/real_captures/
  profinet/ATTRIBUTION.md` for what was searched. DCP decoding itself IS
  validated against two real captures (including one that caught a real
  BlockInfo/BlockQualifier decoding bug before this feature shipped -- see
  that same ATTRIBUTION.md and PROTOCOL COVERAGE), but a DCP Xid is never
  used to authoritatively pair a request to its response the way Modbus
  transaction IDs are (`Decoder::pair_modbus_transaction`) -- each DCP PDU
  is decoded independently. RTC3 and RT_CLASS_UDP FrameID ranges, and
  Alarm/PTCP/fragmentation frames, are recognized and named but their own
  payloads are not further decoded (only DCP and cyclic IO frames are).
- **GOOSE's real-capture validation is narrower than it looks.** All four
  real captures used to validate GOOSE decoding happen to share the same
  shape -- every PDU field (including all three OPTIONAL ones) always
  present, every `allData` value always `boolean` or `bit-string` -- so
  optional-field absence, every other `allData` type (`integer`/`unsigned`/
  `floating-point`/`octet-string`/`visible-string`/`bcd`/`utc-time`/nested
  `array`/`structure`), a GSE Management PDU (outer tag `0xA0`), a header
  S-bit/PDU-simulation mismatch, and a truncated/malformed frame are all
  validated only against the hand-built `tests/sample_goose.pcap`, not an
  independent real capture -- see PROTOCOL COVERAGE's GOOSE section and
  `tests/real_captures/goose/ATTRIBUTION.md`. Only the first APDU in a frame
  is decoded even though the spec technically allows more than one (never
  observed in practice); leftover bytes are noted, not decoded further. No
  GSE Management PDU content is decoded at all (named only). R-GOOSE (IEC
  61850-90-5) is out of scope entirely -- it never reaches this decoder's
  EtherType-based dispatch. GOOSE's sibling protocol, IEC 61850-9-2 Sampled
  Values, is a separate decoder -- see the next bullet.
- **Sampled Values has no real-capture validation at all, for any code
  path.** Unlike GOOSE, every SV path -- the full/optional-absent ASDU field
  decode, both enumerated fields' full value sets, multi-ASDU decoding,
  VLAN-tagged framing, and every malformed/truncated-input path -- is
  validated only against the hand-built `tests/sample_sv.pcap`, despite a
  genuine multi-source search for a real capture that found none (see
  PROTOCOL COVERAGE's Sampled Values section and
  `include/conduitscope/sv.hpp`'s file header for the full search writeup).
  `seqData` (the actual sample payload) is never value-decoded by design --
  shown only as raw hex, since interpreting it requires an implementation
  profile (e.g. "9-2LE") layered on top of the base ASN.1, not something the
  standard itself asserts. `refrTm` is decoded internally but not yet
  exposed in JSON output, matching GOOSE's own `t`-field gap. Only the first
  top-level `SampledValues` PDU in a frame is decoded (matching GOOSE's own
  conservative handling there), though -- unlike GOOSE -- every ASDU *within*
  that PDU's `seqASDU` is decoded, since multiple ASDUs per SavPdu is core,
  spec-defined behavior. R-SV (IEC 61850-90-5) is out of scope entirely.
- **EtherCAT's frame-header structural gate is honestly weaker than this
  codebase's other raw-Ethernet decoders, and real-capture validation, while
  genuine, doesn't cover every Cmd/bit/Type.** The frame header's `Type`
  field is 4 bits admitting 16 possible values, of which 5 are spec-defined
  -- a 5-in-16 chance of a coincidental match against unrelated traffic,
  versus GOOSE/SV's 1-in-256 outer BER tag or PROFINET's own FrameID range
  table; the dedicated, collision-free EtherType remains the primary
  confidence source (see PROTOCOL DETECTION). The 986-frame real capture
  used to validate this decoder (see PROTOCOL COVERAGE's EtherCAT section
  and `tests/real_captures/ethercat/ATTRIBUTION.md`) is genuine and confirms
  the "declared Length bounds the chain" design empirically (zero
  declared-Length-vs-actual-bytes mismatches across all 986 frames), but
  covers only 8 of 15 `Cmd` values (APRD/FPRD/BRD/FPWR/LRD/LWR/BWR/APWR) --
  APRW/FPRW/BRW/LRW/ARMW/FRMW/EXT/NOP, the `Circulating` bit, the frame
  header's `Reserved` bit, 802.1Q VLAN tagging, frame Types other than 1, and
  every malformed/truncated-input path are validated only against the
  hand-built `tests/sample_ethercat.pcap`, cross-checked against
  `packet-ethercat-datagram.c`'s source rather than an independent real
  capture. `Data` is never value-decoded by design (see PROTOCOL COVERAGE),
  and the CoE/SoE/EoE/FoE/AoE mailbox protocol family, Frame Type 5
  ("Mailbox"), Frame Types 2-4 (ADS/RAW-IO/NV), and Distributed Clock
  register semantics are all out of scope entirely.
- **BACnet/IP's service value-decoding is a deliberate first-pass subset,
  and its real-capture validation is narrow.** Only Who-Is/I-Am/Who-Has/
  I-Have/ReadProperty (request+ACK)/WriteProperty (request)/generic-Error
  are value-decoded; every other confirmed/unconfirmed service
  (ReadPropertyMultiple/WritePropertyMultiple/SubscribeCOV/and the rest of
  the 50 service-choice table entries) is named only, its data shown as raw
  hex -- see PROTOCOL COVERAGE's BACnet/IP section for the full rationale.
  A PropertyValue that is constructed (an array/list, or a
  service-specific structured value) rather than a single primitive is
  likewise shown as raw hex with a note, never guessed at. Segmented APDUs
  are decoded only at the header level (sequence-number/
  proposed-window-size); the segment's own service data is never
  value-decoded, since this decoder does no cross-packet APDU reassembly
  (the same posture General TCP stream reassembly's own scope note takes
  for what it does and doesn't cover, just at BACnet's own layer instead of
  TCP's). The 54-frame real capture that validates this decoder (see
  `tests/real_captures/bacnet/ATTRIBUTION.md`) is genuine but narrow: 100%
  Original-Unicast-NPDU, plain (no DEST/SRC/Network-Layer-Message) NPDU,
  Confirmed-Request/Complex-ACK ReadProperty traffic against one property
  shape (a scalar Unsigned value) on one object type (trend-log) -- device
  discovery, WriteProperty, every non-Unsigned PropertyValue type, every
  BVLC function besides Original-Unicast-NPDU, NPDU routing fields, and
  segmentation are all validated only against the hand-built
  `tests/sample_bacnet.pcap`, cross-checked against `packet-bvlc.c`/
  `packet-bacnet.c`/`packet-bacapp.c`'s source rather than an independent
  real capture. Two additional real-capture sources were checked and could
  not be used: `automayt/ICS-pcap`'s `BACNET/` directory (Git-LFS pointer
  stubs, unfetchable in this environment) and `kargs.net`'s own capture
  archive (blocked by this session's network policy) -- see that
  ATTRIBUTION.md for the full search record.
- **HART-IP's own structural detection gate is the weakest in this
  codebase**, and it has a real, deliberately unresolved consequence: a
  genuine HART-IP Session Initiate message riding over TCP is misclassified
  as Modbus/TCP instead (or, less often, COTP/S7comm, or left as generic
  `tcp`) -- see PROTOCOL DETECTION's "Why HART-IP is tried last" for the
  full mechanism and why reordering was tried and rejected. This is
  independently confirmed on genuine field traffic, not just a hand-built
  fixture (see `tests/real_captures/hartip/ATTRIBUTION.md`), which also
  surfaced a second, related false-positive pattern: the same weak gate
  occasionally matches unrelated background TCP traffic that has nothing
  to do with HART-IP at all (a TLS connection and an SMB connection, in
  that capture), reported as "buffering a HART-IP message" that never
  resolves. Both are harmless in the sense that no wrong data is ever
  presented as HART-IP -- the affected traffic is simply reported under
  its own correct protocol (or generic `tcp`) instead -- but a HART-IP
  session's own establishment message can go uncounted in
  `--protocol hartip`/stats output as a result. HART-IP over UDP has no
  equivalent issue.
- **HART-IP's Checksum byte is parsed and located but never verified** --
  unlike DNP3's own data-link CRCs, which now genuinely are validated (see
  above): computing/verifying it would need the HART XOR algorithm applied
  across the whole PDU, out of scope for this groundwork release. A
  corrupted Pass-Through PDU that otherwise still looks structurally valid
  is decoded without any indication the Checksum was wrong.
- **HART-IP's Status header byte is not interpreted at all** -- every
  message this decoder's own research and every real capture checked so
  far carries Status `0`; a non-zero value is passed through as a plain
  integer with no further meaning asserted, since no authoritative source
  consulted during this decoder's research defines one.
- **Commands 31 and 203 have no authoritative top-level name asserted**,
  by design, not oversight -- see PROTOCOL COVERAGE's HART-IP section for
  the full reasoning (both sit outside HART's own Universal/Common-Practice
  numbering, and no source consulted names either one, though Wireshark's
  own dissector decodes the same byte shape this decoder does, which is why
  the *structure* is still decoded with confidence).
- **HART-IP command value-decoding is a deliberate "first pass"**, the same
  scoping precedent this codebase already applies to BACnet/IP's service
  subset, EtherNet/IP CIP explicit messaging's own service subset, and
  DNP3's group/variation table -- see PROTOCOL COVERAGE's HART-IP section
  for the exact command list. Commands 77 and 178 are named but not
  value-decoded; any other unlisted command is shown as a bare number.
  Multi-definition and warning-class Response Codes (as HCF_SPEC-307 itself
  classifies them) are deliberately not resolved to a per-command meaning,
  since doing so honestly would need every command's own spec text, most of
  which this project doesn't have. The 116-frame real capture that
  validates this decoder (see `tests/real_captures/hartip/ATTRIBUTION.md`)
  is genuine, and independently cross-validated field-by-field against
  Wireshark's own HART-IP dissector, but narrow: only 9 of the ~20
  value-decoded commands appear, every response is Success with no
  comm-error or non-zero command-specific code, Error/NAK and the BACK
  frame type never appear, and no malformed/truncated/wrong-length input
  appears either -- the remaining commands, response-code/comm-error
  variety, and every defensive/fallback path are validated only against
  the hand-built `tests/sample_hartip.pcap`, cross-checked against
  HCF_SPEC-307 and Wireshark's `packet-hart_ip.c` source rather than an
  independent real capture.
- **OPC UA's Browse/subscription/MonitoredItem-management/HistoryRead
  services stay Tier 2** -- these are named, and have RequestHeader/
  ResponseHeader decoded, but their own service-specific bodies are shown
  only as raw hex. Unlike the previous limitation here, this is no longer a
  Variant/DataValue gap: that self-describing value encoding IS now fully
  implemented (see PROTOCOL COVERAGE's "Variant/DataValue value decoding"
  section), and Read/Write/Call were promoted to Tier 1 specifically because
  they're the services whose entire reason for existing is carrying one.
  Browse and the subscription/MonitoredItem-management services simply
  don't carry a Variant/DataValue anywhere in their own bodies at all (a
  separate, unrelated decode effort); HistoryRead does, but its own
  HistoryReadDetails ExtensionObject dispatches across five different
  sub-structures, additional scope of its own this first pass leaves for
  later (see ROADMAP). For these services, only that a Browse/Subscribe/
  etc. happened, its request handle, and (for a response) whether it
  succeeded are visible.
- **OPC UA chunk reassembly is not implemented** -- a logical message split
  across multiple `'C'`/`'F'` OPC UA chunks (distinct from ordinary TCP-
  segment-level reassembly, which IS implemented -- see PROTOCOL COVERAGE's
  "Chunking" subsection) has its UA-TCP/SecureConversation header fully
  decoded per chunk, but only a single, complete `'F'` chunk gets its
  service body decoded; a `'C'`/`'A'` chunk's own body is always raw hex.
- **OPC UA has no stateful channel/session tracking** -- a Message chunk's
  own TokenId is never correlated back to the OpenSecureChannel exchange
  that negotiated it, nor a Request's AuthenticationToken back to the
  CreateSession response that issued it. This decoder is, like every other
  protocol in this codebase, a stateless-per-message decoder with
  TCP-stream-level reassembly only, not a full conversation-tracking OPC UA
  stack -- so, for instance, this decoder cannot tell you from a Message
  chunk alone what SecurityMode its own TokenId corresponds to (though the
  OpenSecureChannel exchange that negotiated it is itself always decoded in
  full -- see "Security posture is visible even when the body is not" in
  PROTOCOL COVERAGE).
- **OPC UA's StatusCode table is a deliberate first pass**, the same scoping
  precedent as HART-IP's Response Code table above -- roughly 20 named
  values (auth/certificate/session/timeout failures, the subset most
  relevant to an OT security audit) out of the OPC Foundation's own
  ~700-entry `StatusCode.csv`. Every other value still decodes its
  severity (Good/Uncertain/Bad) correctly from the top 2 bits, shown
  alongside the raw hex value, never guessed at -- this decoder's own real
  capture (see `tests/real_captures/opcua/ATTRIBUTION.md`) exercises this
  exact fallback, twice.
- **OPC UA's real-capture validation is narrow.** The one real capture
  found (`tests/real_captures/opcua/ATTRIBUTION.md`) is genuine OPC UA
  traffic from an independent stack implementation, and it does exercise 9
  of the ~21 Tier 1 request/response entries plus genuine multi-segment TCP
  reassembly --
  but it never exercises FindServers, CloseSession, CloseSecureChannel, any
  Tier 2 service, a non-Anonymous identity token (so the UserName/Password
  cleartext-credential "SECURITY FINDING" logic is validated only against
  this decoder's own synthetic fixture, not real bytes), a non-`'F'` chunk,
  or a structurally-invalid NodeId -- see PROTOCOL COVERAGE's OPC UA
  Validation subsection for the complete, honest scope. Its own CallRequest
  (now Tier 1) turned out to be genuinely malformed in both sessions --
  Achilles Satellite fuzz-test payloads, not well-formed traffic -- so this
  capture still does not validate a well-formed Read/Write/Call exchange
  against real bytes; only this decoder's own synthetic fixtures do that.
- **DNP3 data-link CRCs are now validated** -- both the header CRC and every
  per-block CRC within the user data are genuinely calculated and compared
  against the on-the-wire value (`dnp3_header_crc_valid`/`dnp3_block_count`/
  `dnp3_block_crc_failures`/`dnp3_link_crc_valid`, plus a specific `notes`
  entry on a mismatch) -- see PROTOCOL COVERAGE's DNP3 "Data-link CRC-16
  validation" section. This is purely diagnostic: a mismatch is flagged, but
  decoding is never stopped and the frame is never dropped, and CRC validity
  is **not** wired into `policy validate`/`PolicyEngine` -- a flow with a
  CRC-invalid DNP3 frame gets exactly the same Allowed/Violation verdict it
  would with a valid one. One of this project's own real captures
  (`dnp3_request_link.pcap`/`dnp3_request_link_status.pcap`) has a
  Request Link Status response frame that genuinely fails header-CRC
  validation and also has a spec-non-conformant `length_field` of 0 --
  pre-existing behavior the new validator surfaces, not a bug in this
  feature (see PROTOCOL COVERAGE for the detail).
- **DNP3 point values are decoded only for the group/variation combinations
  in the built-in point-format table** (see PROTOCOL COVERAGE for the full
  list -- it covers the object types common in real traffic). Outside that
  table, an object header's data is still located and skipped by a computed
  byte length (so later headers in the fragment stay aligned), just not
  interpreted value-by-value. A qualifier this release doesn't support (an
  object-size-prefixed qualifier, or a bit-packed format combined with an
  index-prefixed qualifier) stops object-header parsing for that fragment
  entirely, rather than guessing. Only the first 200 points in a single
  object header are individually decoded; a larger batch's object data is
  still fully accounted for byte-wise, with a note that decoding was capped.
- **DNP3 absolute timestamps (Time and Date objects, and event "with time"
  variants) are shown as an ISO-8601 UTC calendar date/time, with the raw
  milliseconds-since-epoch count kept alongside it in parentheses** -- via
  the same `std::gmtime`-based rendering (and the same graceful
  out-of-range fallback to a raw-value string) this codebase already uses
  for MMS UtcTime, MQTT Sparkplug timestamps, OPC UA DateTime, and
  S7comm-Plus timestamps; DNP3 reuses MQTT's own `format_millis_epoch`
  directly rather than a separate copy, since both are milliseconds since
  the Unix epoch.
- **DNP3 32-bit floating-point values decode through a `float`, and 64-bit
  through a `double`** -- correct on any platform where those are IEEE 754
  binary32/binary64 (true of every mainstream compiler this project targets,
  but not guaranteed by the C++ standard itself).
- **A DNP3 fragment spanning multiple data-link frames only gets its
  transport header decoded**, not its application layer, until the final
  (FIN=1) frame arrives -- see the note under "General TCP stream
  reassembly is implemented, but narrowly scoped" above.
- **Modbus request/response classification is heuristic by default, but
  authoritatively paired where the transaction ID allows it.** The
  payload-shape heuristic (see PROTOCOL DETECTION) always runs and always
  produces a classification, even for a capture with only one direction of
  traffic or no session context at all. `Decoder::pair_modbus_transaction`
  layers authoritative, transaction-ID + TCP-session-based pairing on top,
  but only when both the request and its response are actually present, on
  the same TCP session, in this capture -- a response packet still gets the
  heuristic's classification (and, if the heuristic itself called it a
  response, an "orphan" note) when its request wasn't captured, was on a
  different session, or reused a transaction ID a prior, still-outstanding
  request already claimed. Pairing state is tracked per TCP session with a
  2000-outstanding-transaction cap per session against a pathological/
  malformed capture; past the cap, new requests simply stop being recorded
  (silently -- a capacity guard, not a correctness concern for any
  realistic capture). A write-single request whose own first sighting is
  itself an orphaned response (capture starts mid-session) is misrecorded as
  an outstanding request rather than flagged as an orphan, because
  write-single's ambiguous shape gives the heuristic nothing to go on for
  that specific case -- harmless (it will simply never pair, and eventually
  ages out via the cap), just not caught and reported the way an orphan
  read/write-multiple response is.
- **Modbus/TCP detection itself is a heuristic, and can still false-positive
  in principle.** Modbus/TCP has no magic bytes; detection requires
  protocol-id==0 and a non-zero function code, which rules out the false
  positive actually observed in a real capture (non-Modbus traffic on port
  20000) but cannot rule out every possible coincidence -- a payload from
  some other protocol could still, in principle, satisfy both checks. Treat
  an isolated, otherwise-implausible Modbus packet (especially on a
  non-standard port, which is flagged in the output) with appropriate
  skepticism.
- **IEC 104 information objects are decoded only for the type IDs in the
  built-in decode table** (see PROTOCOL COVERAGE for the full list -- it
  covers the type IDs that dominate real traffic). Outside that table, the
  ASDU header (type ID/VSQ/COT/common address) is still decoded, but its
  information objects are not -- there is no structural skip-and-show
  fallback the way DNP3's unrecognized group/variation gets, since an ASDU
  has only one type ID for its whole object list and no "later header"
  whose byte alignment needs preserving. A batch of more than 200
  information objects in one ASDU only gets the first 200 individually
  decoded; a note says so when it happens.
- **EtherNet/IP's CIP explicit-message value decoding is scoped narrowly and
  deliberately.** Full type+value decoding only applies to (a) a "first
  pass" set of generic common services and Connection-Manager services, and
  (b) the Rockwell Symbol-object tag services (Read/Write Tag(
  Fragmented)/Read_Modify_Write_Tag), and only for (b) when the request
  path's first segment is an ANSI Extended Symbol segment -- a
  class/instance-addressed request using one of those same service codes
  (a real, confirmed collision -- see tests/real_captures/enip/
  ATTRIBUTION.md and PROTOCOL COVERAGE) is shown structurally (service name
  + path + raw hex) instead. Within the decoded element types, the
  fixed-size numeric elementary types (BOOL/SINT/INT/DINT/LINT/USINT/UINT/
  UDINT/ULINT/REAL/LREAL/BYTE/WORD/DWORD/LWORD), STRING/SHORT_STRING (text),
  and Structured Data Type (UDT/array, type code `>= 0x02A0`) are all
  value-decoded -- the structured case down to its 2-byte Structure Handle,
  with the remaining member bytes shown as hex, since this decoder has no
  access to the tag's Template definition (member names/types/offsets),
  which would require a separate, out-of-band `Get_Attribute_List` exchange
  against the Template object this decoder doesn't perform. STRING2/
  STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value remain recognized by code but
  shown as raw hex with an explicit note, not guessed at. A bare CIP response's Read_Tag(
  Fragmented) disambiguation from a same-service-code non-tag reply relies
  on a payload-shape heuristic (a plausible CIP elementary type code at the
  start of the response data), same category of heuristic as Modbus's own
  request/response shape classification -- not authoritative tracking.
- **S7comm item-level addressing is fully confident only for the classic
  S7ANY syntax.** `0xB2` (S7-1200/1500 "symbolic" addressing) also gets a
  tag, but it's an EXPERIMENTAL reconstruction from public sources rather
  than confirmed documentation -- see PROTOCOL COVERAGE for exactly what
  evidence backs it and what it doesn't cover (DB-area items, more than one
  LID entry per item). Every `0xB2` tag is marked `[EXPERIMENTAL]`
  everywhere it's shown; treat it as a strong hypothesis, not ground truth,
  until it's cross-checked against a source with real authority (a PLC or
  TIA Portal project you control, ideally). Every syntax id besides `0x10`
  and `0xB2` is recognized but shown as raw hex, not decoded at all. The
  Userdata ROSCTR (vendor-specific diagnostics/CPU functions) is entirely
  unparsed beyond being labeled.
- **PLC Control's `_N_*` Sinumerik/CNC PI services get a name+description
  lookup only, never a parameter-block decode, and `P_PROGRAM`/`_MODU`/
  `_GARB` arguments are shown raw, never semantically interpreted.** Dozens
  of per-service argument layouts, all specific to CNC machine-tool control
  rather than ordinary PLC control, are out of scope entirely (see PROTOCOL
  COVERAGE); only a subset of Wireshark's own ~65-entry PI-service name
  table is transcribed here, so a PI service name outside that subset still
  shows its raw name but with an empty description. `P_PROGRAM` (PLC
  Start/Stop), `_MODU` (copy RAM to ROM), and `_GARB` (compress PLC memory)
  each carry a single ASCII argument string that's decoded as-is with no
  attempt to interpret what a specific value means -- matching the same
  restraint the upstream Wireshark dissector applies to the identical bytes.
- **A few S7comm data-item transport sizes use a best-effort length
  interpretation.** The two overwhelmingly common cases (BIT, and
  BYTE/WORD/DWORD-family reads/writes) are decoded with high confidence
  against the documented wire format; the rarer transport sizes (DINT,
  REAL, OCTET STRING, and a few others) fall back to treating the length
  field as a byte count directly, flagged with a note when it's used.
- **S7comm message chaining across multiple TPKT/COTP frames is implemented,
  via COTP's own EOT bit, but only content-validated by a synthetic
  fixture.** `Decoder::reassemble_cotp_data_frame` concatenates a message
  split across several complete DT frames correctly (verified byte-for-byte
  against `tests/sample_s7comm_chaining.pcap`, which splits real register
  values mid-byte across the join) -- but no real S7comm capture checked for
  this project actually splits a message's *content* this way; the real
  captures that do exercise EOT=0 chaining (see PROTOCOL COVERAGE) all use a
  content-free, zero-byte "priming" frame, so real-world evidence only
  confirms the reassembly is transparent when nothing needs concatenating,
  not that genuine multi-frame content splicing has been seen on the wire.
  The COTP TPDU-NR field is deliberately NOT used to validate fragment
  continuity (unlike DNP3's transport SEQ, which real DNP3 stacks do
  increment reliably) -- every real capture checked shows it staying 0 on
  every DT frame, fragmented or not, so trusting it as a gate would risk
  false "gap" aborts on exactly the real traffic this feature targets; EOT
  alone is what's trusted. A non-Data COTP frame (connection setup/teardown)
  arriving mid-reassembly abandons it with a note rather than merging in
  irrelevant bytes; there is no gap/resync equivalent to TCP-segment
  reassembly's sequence-number check here, since COTP gives no per-fragment
  sequence signal worth trusting for that. Buffering is capped at 1 MiB /
  2000 frames per flow against a pathological/malformed capture.
- **S7comm-Plus (protocol id 0x72) is only Tier-1-decoded for
  GetMultiVariables/SetMultiVariables/SetVariable/DeleteObject.** Every other
  function -- CreateObject, Explore, GetLink, BeginSequence/EndSequence,
  Invoke, GetVarSubStreamed -- and the Notification/Connect PDU shapes are
  recognized (named) but not body-decoded (Tier 2). `DataFW1_5` (firmware >=
  V1.5) gets header-only decode; its entire Data part is shown as raw hex,
  since this decoder could not independently confirm the reference plugin's
  own byte-accounting for where that variant's function-specific body
  actually starts -- see PROTOCOL COVERAGE's S7comm-Plus section.
- **S7comm-Plus's own above-COTP fragmentation (a telegram split across
  multiple TPKT/COTP frames, signalled by the ABSENCE of the trailer, not
  COTP's own EOT bit) is detected and reported but not reassembled.** A
  telegram missing its trailer decodes only as far as the bytes present in
  that one frame; the continuation frame(s) are not stitched back in. This
  is a genuinely separate, TCP-session-keyed state machine in the reference
  plugin that this decoder does not replicate.
- **S7comm-Plus's native symbolic item addressing (CRC + LID chain) decodes
  the numbers faithfully but cannot resolve what they mean.** A LID's or
  CRC's symbolic meaning (which tag name it refers to) depends on TIA
  Portal's own compiled project database, which never appears on the wire --
  the same class of limitation this codebase already accepts for DNP3/IEC
  104 point indices and OPC UA NodeIds.
- **S7comm-Plus does not decode an array of Struct values.** Delimiting N
  separate per-element nested member lists for that shape isn't something
  this implementation (or, seemingly, the reference Wireshark plugin itself)
  cleanly supports; encountering one aborts that Data part's decode with a
  note rather than risk silent byte misalignment.
- **S7comm-Plus's ReturnValue is only decoded down to its low-16-bit signed
  error code.** The remaining OMS-line/error-source/debug-info sub-fields of
  the full 64-bit value are surfaced as a raw note, not asserted
  bit-for-bit -- the reference plugin's own source only comments on their
  meaning informally.
- **Most of MMS's 78 confirmedServices are Tier 2 (name + invokeID only,
  body shown as raw hex).** Only 18 are fully field-decoded (Tier 1):
  `status`, `getNameList`, `identify`, `read`, `write`,
  `getVariableAccessAttributes`, `defineNamedVariableList`,
  `getNamedVariableListAttributes`, `deleteNamedVariableList`,
  `getDomainAttributes`, `getCapabilityList`, and the seven file-transfer
  services `obtainFile`, `fileOpen`, `fileRead`, `fileClose`,
  `fileRename`, `fileDelete`, `fileDirectory` -- see PROTOCOL COVERAGE's
  MMS section for why exactly these 18 and not others. Within the
  file-transfer group, `ObtainFile-Request`'s own `sourceFileServer`
  (`ApplicationReference`) is likewise structurally recognized but not
  deep-decoded.
- **MMS's Session layer only supports the "normal" (one-byte-length-per-
  parameter) SPDU length form ISO 8327-1 defines** -- the extended 2-byte
  length form (LI `0xFF`) is recognized as a distinct, legal encoding but
  not implemented, since it has never been observed in real IEC 61850 MMS
  traffic during this decoder's own research.
- **MMS's `TypeSpecification` and non-symbolic `Address` variable
  addressing are not decoded** -- both are structurally recognized as
  present (shown as e.g. `"address=<Address, not decoded>"` /
  `"typeSpecification=<TypeSpecification, not decoded>"` inside
  `mms_values`) but not decoded field-by-field, since real IEC 61850
  traffic overwhelmingly addresses variables by symbolic `name` instead.
- **MMS's "1=ACSE, 3=MMS" presentation-context convention is an honest
  assumption, not a guarantee.** This decoder is stateless per message, so
  it cannot remember a context-definition-list negotiated on an earlier
  Connect frame while decoding a later, unrelated ongoing Data-Transfer
  frame -- it instead assumes the near-universal convention that
  presentation-context 1 means ACSE and 3 means MMS, the same
  honestly-stated-assumption pattern already used elsewhere in this
  codebase (e.g. HART-IP's Status-byte handling). Every real capture
  checked corroborates this convention, but a hypothetical stack that
  negotiated a different numbering would be misread.
- **Multiple complete MMS/TPKT/COTP frames coalesced into a single TCP
  segment: only the first is decoded.** This is a pre-existing general
  COTP/TPKT framing limitation, not new to MMS -- `try_parse_tpkt_cotp`
  (`cotp.cpp`) clamps parsing to exactly one TPKT frame's own declared
  length so a second, pipelined TPKT frame in the same TCP segment can't be
  misread as part of the first one's payload, and notes how many
  additional bytes remain undecoded rather than guessing at them; it now
  also applies to MMS specifically, since MMS shares this exact TPKT/COTP
  framing with S7comm.
- **Live capture (`-i`) is an optional, build-time-detected feature, not
  always present.** A binary built without libpcap/Npcap found still runs
  everything else identically; `-i`/`interfaces` just report that clearly.
  See LIVE CAPTURE above.
- **Live capture's Windows/Npcap path has not been run on a real Windows
  machine yet** -- implemented against the same documented API used on
  Linux, but this project's development and testing has so far only actually
  happened on Linux (see LIVE CAPTURE's "Windows / Npcap notes"). The Linux
  path has been validated end-to-end against real loopback traffic (capture
  start/stop via `--duration` and Ctrl+C, and decoding real captured
  packets), but not yet against a live production OT network's actual
  switch/SPAN-port behavior.
- **Live capture polls for packets rather than trusting libpcap's own read
  timeout to wake it up.** Observed in this project's own Linux test
  environment: `pcap_next_ex`'s configured read timeout can be ignored
  indefinitely when an interface sees zero traffic during that window
  (rather than reliably returning "nothing yet" so the caller can re-check
  `--duration`/Ctrl+C), so `LiveCapture` instead puts the handle in
  non-blocking mode and sleeps briefly between poll attempts itself (see
  `live_capture.cpp`'s comment by `pcap_setnonblock`). This is slightly less
  CPU-efficient than a well-behaved blocking timeout, immaterial for this
  tool's interactive/bounded use case, but means `--duration`/Ctrl+C
  responsiveness is bounded by that poll interval (200ms), not instant.
- **QinQ (stacked 802.1Q) VLAN tags are not unwrapped**, only a single tag.
- **`policy validate`'s zones are IPv4 CIDR-only** (matching every other
  IPv4-only limitation in this document) and its conduits are TCP-only --
  unlike `decode`, which now also decodes three UDP-based protocols (CIP
  I/O, BACnet/IP, and HART-IP's own UDP traffic, see PROTOCOL COVERAGE). A
  policy can't reference a UDP service, a MAC address, or a hostname, and
  non-TCP/non-IP packets -- including CIP I/O, BACnet/IP, and HART-IP-over-
  UDP traffic -- are counted (`skipped_non_tcp` in the JSON report) but
  never evaluated against any conduit.
- **`policy validate`'s client/server (initiator) determination falls back
  to a port-number heuristic when no SYN/SYN-ACK is captured for a flow**
  (e.g. a capture that starts mid-session): whichever endpoint's port is one
  of the five IANA-registered OT ports (502/20000/2404/102/44818) is assumed to be the
  server, and if neither or both are, the lower port number is. A real
  SYN/SYN-ACK seen on ANY packet in the flow -- not just the first one --
  always overrides this guess once seen (see `PolicyEngine::observe`'s doc
  comment in `policy_engine.hpp`), but a flow whose handshake was never
  captured, on ports neither is a recognized OT port, can still be
  attributed backwards if the true server happens to use the higher port
  number. This heuristic layer is separate from, and doesn't affect, Modbus
  protocol decoding's own request/response classification (see above).
- **A conduit's direction is TCP-connection-initiator-based, not
  per-packet-flow-based** -- see POLICY FILE FORMAT's "Conduits" section for
  exactly what `from`/`to`/`bidirectional` mean. There's no way to permit,
  say, only the request direction of a protocol and flag an unsolicited
  response separately; a conduit either covers the whole
  client-initiates-to-server session or it doesn't.
- **A flow with more than one recognized protocol is treated as needing a
  conduit that covers all of them** -- this would only happen on a capture
  where the same TCP 4-tuple somehow carried, say, both Modbus and DNP3
  traffic (protocol confusion, or two different real sessions coincidentally
  reusing the same ports after one closed, which this tool has no way to
  tell apart from one continuous session -- see the general TCP-reassembly
  limitation above for the same underlying reason). Ordinary real traffic
  never exercises this.
- **MQTT's own structural detection gate is honestly the weakest in this
  codebase, weaker even than HART-IP's** -- see PROTOCOL DETECTION's "Why
  MQTT is tried last" for the two real collisions against this project's own
  synthetic fixture that this weakness caused (both found and fixed, not
  merely theoretical). CONNECT alone gets a materially stronger,
  version-specific check (its own Protocol Name field must read `"MQTT"` or
  `"MQIsdp"`); every other MQTT packet type relies on the one-byte fixed
  header alone.
- **MQTT's SUBACK version-disambiguation heuristic is the least reliable of
  the three ambiguous packet types** (SUBSCRIBE/SUBACK/UNSUBSCRIBE), used
  only when no CONNECT was ever seen on a session in this capture. SUBACK's
  own body is a flat list of single reason-code bytes -- almost any byte
  value looks structurally "valid" whichever shape (v3.x or v5) is assumed,
  so a short or degenerate reason-code list can resolve to the wrong
  version. This is deliberately not hidden: the decoded output always notes
  which of the three evidence tiers (session-tracked, SUBSCRIBE/UNSUBSCRIBE
  heuristic, or SUBACK's own weaker heuristic) produced a given version
  label, and this project's own test suite (`mqtt_version_heuristic_suback_
  weakest_evidence` in `CMakeLists.txt`) pins down a case where it
  misresolves, rather than only testing cases where it happens to get it
  right.
- **MQTT QoS 2 exactly-once delivery state, retained-message tracking, and
  Will Message delivery are not tracked across packets** -- like every
  protocol in this codebase, this decoder is a stateless-per-message decoder
  with TCP-stream-level reassembly only; PUBREC/PUBREL/PUBCOMP are each
  decoded on their own, not correlated into a single logical QoS 2 exchange.
- **Sparkplug B is validated only against this project's own synthetic,
  hand-built protobuf fixture** -- a real-world Sparkplug B capture was
  specifically searched for and not found (see
  `tests/real_captures/mqtt/ATTRIBUTION.md`'s own honest account of that
  search). MQTT itself (the layer underneath Sparkplug B) does have real
  independent validation -- see PROTOCOL COVERAGE's MQTT Validation
  subsection.
- **Sparkplug B's Bytes, File, DataSet, Template, PropertySet/
  PropertySetList, and Array `DataType`s are recognized and counted but not
  value-decoded** (Tier 2, shown as `"<N byte(s), not decoded further>"`) --
  see PROTOCOL COVERAGE's MQTT section for the full Tier 1/Tier 2 split.
  Sparkplug's own STATE topic payload (plain JSON text, not protobuf) is
  likewise shown as raw text, not parsed as JSON.
- **FF-HSE's own structural detection gate is honestly the weakest in this
  codebase** -- a single byte at header offset 2 landing on one of 12 valid
  values out of 256, plus a length check that is barely a constraint at
  all, weaker even than MQTT's own gate. FF-HSE is therefore dispatched
  dead last of every protocol here, on both TCP and UDP -- see PROTOCOL
  DETECTION's "Why FF-HSE is tried last of all".
- **FF-HSE's Tier-2 scope covers FMS's Get OD, Define/Delete Variable
  List, the Download/Upload sequence families, RequestDomainDownload/
  Upload, the Program Invocation lifecycle, AlterEventConditionMonitoring,
  AcknowledgeEventNotification, the Put OD family, the Generic Download
  sequence family, and unconfirmed Event Notification** -- named only,
  body shown as raw hex. FMS Get OD is left undecoded even by the
  reference Wireshark dissector itself, since OD entries depend on Device
  Description content neither has access to.
- **FMS Read/Read-with-Subindex response values, and Write/Write-with-
  Subindex request values, are left as raw hex** -- an FMS value has no
  self-describing wire type without external Object Dictionary context to
  interpret it against, the same honesty precedent this codebase's
  EtherNet/IP CIP I/O decoder and S7comm-Plus already set elsewhere.
- **No real FF-HSE capture could be found anywhere, despite a genuine
  multi-source search** (`automayt/ICS-pcap`, `ITI/ICS-Security-Tools`, the
  4SICS GeekLounge/Netresec collections, and malware-traffic-analysis.net;
  a small synthetic test capture referenced in a Wireshark GitLab bug
  report was identified but could not be retrieved either) -- this decoder
  is therefore validated only against its own synthetic fixture. See
  PROTOCOL COVERAGE's FOUNDATION Fieldbus HSE section's Validation
  subsection.
- **The cyclic Publisher/Subscriber wire shape is an unconfirmed inference,
  not a confirmed fact.** No distinct cyclic Publisher/Subscriber message
  shape was identified in the reference source consulted while building
  this decoder; this decoder's own best guess is that it reuses the
  unconfirmed FMS Information Report family (Service Ids 0/16/17/18), but
  that is a guess -- no independent source was available to confirm or
  refute it. See PROTOCOL COVERAGE's FOUNDATION Fieldbus HSE section.
- **FF-HSE's own Network Management (FF-803) and full HSE Redundancy
  scope are entirely out of scope.** Only basic LAN Redundancy Get Info/
  Put Info/Get Statistics/Diagnostic Message are decoded (LAN Redundancy's
  own Tier-1 message set); Network Management as a whole, and any HSE
  Redundancy behavior beyond that basic message set, are not implemented
  at all -- not even named/Tier-2.
- **The LinkId branch (SM Identify Rsp / SM Device Annunciation Req) is
  the single trickiest piece of this decoder** -- getting it wrong would
  silently misinterpret every version-number-list entry after the first.
  Both branches are covered by the synthetic fixture, but only that
  fixture -- see PROTOCOL COVERAGE's FOUNDATION Fieldbus HSE section.
- **Cisco PVST+/Rapid-PVST+ is named only, not decoded.** It's a genuinely
  different wire envelope (SNAP-encapsulated, Cisco OUI, a proprietary TLV
  appended after the standard BPDU body), not a variant of the format this
  decoder handles -- recognized structurally and named, but its body,
  including the standard BPDU fields it also nominally carries, is never
  opened. See PROTOCOL COVERAGE's Spanning Tree Protocol section.
- **SPB (802.1aq, Protocol Version Identifier 4) is named only, not
  decoded**, even though Wireshark's own dissector actually does decode
  part of a version-4 frame (the identical MSTP body-parsing path plus its
  own further "SPT Extension") -- this decoder deliberately does not follow
  that path; ANY version-4 frame is named-only from the version byte alone.
- **The legacy/alternative MSTI Configuration Message format (Version 3
  Length == 0) is recognized structurally and named, but its body is not
  decoded** -- it uses a different per-instance layout (explicit MSTID
  field, different byte order, 26 bytes per message instead of 16) this
  decoder has no independent confirmation of beyond the reference source's
  own trigger-condition arithmetic.
- **No real TCN BPDU, MSTP/MST-extension traffic, or SPB traffic could be
  found in either real capture used to validate this decoder**, nor do
  those captures exercise the RST Port Role values Root/Alternate/Backup
  (only Designated appears on real bytes), the Proposal/Agreement flags,
  the TC/TCA flags on a Configuration/RST BPDU, Cisco PVST+ framing, or
  GARP/GVRP/GMRP traffic -- every one of those paths is validated only
  against the synthetic `tests/sample_stp.pcap` fixture, cross-checked
  against the reference dissector's source rather than an independent real
  capture. See `tests/real_captures/stp/ATTRIBUTION.md`'s own "Gaps"
  section.
- **GARP (GVRP/GMRP) disambiguation from STP is destination-MAC-based, the
  one case in this codebase where a fixed address genuinely gates
  detection** rather than a structural check -- forced by STP and GARP
  genuinely sharing the identical LLC DSAP/SSAP pair (`0x42`/`0x42`) with
  no other structural distinguisher available at that layer. GARP's own
  body is never decoded, only named.
- **Name resolution (OUI/hostname/service name) is `decode`-only.**
  `policy validate`'s report (text or JSON) is not enriched with any
  vendor/hostname/service-name annotation -- it's a separate, IP/zone-centric
  report format with its own conventions, out of scope for this feature. See
  OUTPUT FORMATS' "Name resolution" subsection and ROADMAP.
- **The built-in service-name table is a small, hand-curated set, not an
  exhaustive IANA services dump.** It covers this project's own OT/ICS
  protocol default ports plus a modest set of common IT/OT-adjacent ports --
  see OUTPUT FORMATS' "Name resolution" subsection for exactly what and why.
  `--services` is the documented way to extend it for anything it doesn't
  cover.
- **Hostname resolution never touches the network, under any flag
  combination.** The only hostname source is an explicitly-supplied
  `--hosts` file; there is no live-DNS code path anywhere in this feature,
  by design -- see OUTPUT FORMATS' "Name resolution" subsection.
- **DeviceNet's Group 3 explicit messages are not reassembled when
  fragmented, and CAN FD frames are not semantically decoded.** A
  fragmented Group 3 message (Fragmentation flag set) is recognized and
  flagged, but nothing past its first payload byte is decoded -- this
  matches Wireshark's own `packet-devicenet.c`, which has never implemented
  fragment reassembly either, not a gap unique to this port. A CAN FD frame
  is recognized structurally (so it's never misread or crashes this
  decoder), but only its CAN-ID-derived message-group classification is
  shown -- DeviceNet as a protocol predates CAN FD and never uses it, so
  there is no real traffic this would apply to anyway. See PROTOCOL
  COVERAGE's DeviceNet section.
- **DeviceNet has no real-capture validation at all.** Despite a genuine
  search (`ITI/ICS-Security-Tools` and general web search), no public
  DeviceNet/CAN-bus capture was found -- validation is against the
  synthetic `tests/sample_devicenet.pcap` fixture only, cross-checked
  against `packet-devicenet.c`'s own source rather than independent real
  bytes. See PROTOCOL COVERAGE's DeviceNet section.
- **ControlNet (ODVA's other original CIP network) cannot be decoded by
  this or any pcap-based tool.** It rides a proprietary physical layer (RG-6
  coax, Manchester coding, implicit token-passing) that no standard capture
  tool -- including Wireshark, which has no ControlNet dissector at all --
  can sniff; the only real-world way to observe it is Rockwell's own
  proprietary ControlNet Traffic Analyzer, which produces no pcap-compatible
  output. This is a structural limitation, not a scope gap: see PROTOCOL
  COVERAGE's DeviceNet section's "Why not ControlNet too" note.

## EXIT STATUS

| Code | Meaning |
|---|---|
| 0 | Success. For `policy validate`: the capture is COMPLIANT (every observed flow was explicitly allowed by a conduit). |
| 1 | A fatal error occurred -- bad arguments, the input file could not be opened, the file is not a recognized capture format (classic pcap or pcapng) or is corrupt, (with `--strict`) a packet failed to parse, or (for `policy validate`) the policy file couldn't be opened or failed validation (see POLICY FILE FORMAT's "Validation errors"). |
| 2 | *(currently unused)* Reserved rather than reused: an earlier groundwork release used this for `policy validate` while it was still a documented stub with no evaluation engine behind it. Nothing returns it now that `policy validate` is fully implemented, but the value is left unclaimed in case a future documented-stub command needs it again. |
| 3 | `policy validate` only: the capture and policy file were both readable and valid, but the capture is NON-COMPLIANT -- `PolicyReport::compliant()` is false (at least one violation and/or unclassified flow was found). Distinct from 1 specifically so a script can tell "ran fine, found problems" apart from "couldn't even run". |

Non-fatal per-packet parse issues (without `--strict`) do not affect the exit
status; they are reported as warnings (to stderr, or `--log-file`) and as
`"protocol": "parse-error"` entries in the decoded output itself (`decode`)
or folded into `policy validate`'s flow evaluation the same way any other
unrecognized packet is.

## EXAMPLES

Decode a capture as human-readable text:

```sh
conduitscope decode -r capture.pcap
```

Get just the aggregate picture of what's in a large capture before deciding
how to filter it:

```sh
conduitscope info -r capture.pcap
```

Pull out only the Modbus exception responses, as JSON, using `jq`:

```sh
conduitscope decode -r capture.pcap --protocol modbus -f json \
  | jq '.[] | select(.summary | test("^Read|^Write") | not)'
```

Note ports that carry Modbus traffic your zone policy doesn't expect on 502:

```sh
conduitscope decode -r capture.pcap --protocol modbus --modbus-port 502 -f text \
  | grep -A1 "not a configured/standard Modbus port"
```

Stop early on a very large capture while you're iterating on a filter:

```sh
conduitscope decode -r capture.pcap --max-packets 500
```

See which S7 sessions get established and what function codes flow over
them, on a capture that mixes S7comm with other traffic:

```sh
conduitscope decode -r capture.pcap --protocol s7comm --stats
```

See exactly which PLC memory addresses are being read and written -- the
item tags conduitscope decoded, one line per Read Var / Write Var packet:

```sh
conduitscope decode -r capture.pcap --protocol s7comm -f json \
  | jq -r '.[] | select(.s7comm_items) | "\(.src_ip) -> \(.dst_ip): \(.s7comm_items | join(", "))"'
```

Spot who's issuing PLC Control / PLC Stop commands against a live S7 PLC --
function codes `0x28`/`0x29`, the mechanism behind the well-known
unauthenticated "PLC Stop" DoS technique and, for `_INSE`/`_INS2`/`_DELE`,
remote logic-block push/removal -- genuinely useful for spotting who's
allowed to issue control commands to a controller on a given conduit:

```sh
conduitscope decode -r capture.pcap --protocol s7comm -f json \
  | jq -r '.[] | select(.s7comm_plc_stop_message or .s7comm_pi_service_name) |
           "\(.src_ip) -> \(.dst_ip): \(.summary)"'
```

See every IEC 61850 MMS read/write/report value decoded on a capture that
shares S7comm's own port 102 -- variable names and their values, one line
per packet that carries any:

```sh
conduitscope decode -r capture.pcap --protocol mms -f json \
  | jq -r '.[] | select(.mms_values) | "\(.src_ip) -> \(.dst_ip): \(.mms_values | join(", "))"'
```

See every S7comm-Plus (TIA Portal S7-1200/1500) variable read/write value
decoded on the same shared port 102 -- item addresses and the values read or
written, one line per GetMultiVariables/SetMultiVariables/SetVariable packet
that carries any:

```sh
conduitscope decode -r capture.pcap --protocol s7comm-plus -f json \
  | jq -r '.[] | select(.s7plus_values) | "\(.src_ip) -> \(.dst_ip): \(.s7plus_values | join(", "))"'
```

See which S7comm-Plus function codes flow over a capture, and how many got
Tier-1 (full value) decoding vs. Tier-2 (name only) -- e.g. to spot
CreateObject/Explore traffic (TIA Portal project uploads/downloads or
online-view browsing) alongside the ordinary GetMultiVariables/
SetMultiVariables read/write traffic:

```sh
conduitscope decode -r capture.pcap --protocol s7comm-plus --stats
```

See which DNP3 function codes and object groups/variations flow over a
capture, e.g. to spot an unsolicited response or a write/operate/direct
operate you weren't expecting on a conduit:

```sh
conduitscope decode -r capture.pcap --protocol dnp3 -f json \
  | jq -r '.[] | select(.dnp3_function) | "\(.src_ip) -> \(.dst_ip): \(.dnp3_function) \(.dnp3_objects // [] | join(", "))"'
```

Find every CROB output command in a capture -- who issued it, and exactly
what it commanded:

```sh
conduitscope decode -r capture.pcap --protocol dnp3 -f json \
  | jq -r '.[] | select(.dnp3_values) | .src_ip as $s | .dst_ip as $d |
           (.dnp3_values[] | select(startswith("g12v1"))) | "\($s) -> \($d): \(.)"'
```

Flag every DNP3 data-link frame whose CRC-16 didn't validate -- line noise on
a serial-to-IP gateway, or possible tampering, worth a closer look either way
(see PROTOCOL COVERAGE's DNP3 "Data-link CRC-16 validation" section):

```sh
conduitscope decode -r capture.pcap --protocol dnp3 -f json \
  | jq -r '.[] | select(.dnp3_link_crc_valid == false) |
           "\(.src_ip) -> \(.dst_ip): header_ok=\(.dnp3_header_crc_valid) blocks=\(.dnp3_block_count) failed=\(.dnp3_block_crc_failures)"'
```

See which IEC 104 ASDU types and causes of transmission flow over a
capture, e.g. to spot an unexpected command or an interrogation response
you weren't expecting on a conduit:

```sh
conduitscope decode -r capture.pcap --protocol iec104 -f json \
  | jq -r '.[] | select(.iec104_asdu_type) | "\(.src_ip) -> \(.dst_ip): \(.iec104_asdu_type) (\(.iec104_cot))"'
```

Find every IEC 104 single/double command issued -- who issued it, to which
Information Object Address, and what it commanded (the kind of query that
matters most for an Industroyer2-style breaker-manipulation investigation):

```sh
conduitscope decode -r capture.pcap --protocol iec104 -f json \
  | jq -r '.[] | select(.iec104_asdu_type | test("^C_SC_NA_1|^C_DC_NA_1")?) |
           .src_ip as $s | .dst_ip as $d |
           (.iec104_objects[]) | "\($s) -> \($d): \(.)"'
```

Fingerprint every EtherNet/IP device that answered a ListIdentity request in
a capture -- useful for passive OT asset inventory:

```sh
conduitscope decode -r capture.pcap --protocol enip -f json \
  | jq -r '.[] | select((.enip_command == "ListIdentity") and (.summary | contains("identity:"))) |
           "\(.src_ip): \(.summary | capture("identity: (?<id>.*)").id)"'
```

Find every Rockwell tag write (Write_Tag) in a capture -- who wrote what, to
which named tag:

```sh
conduitscope decode -r capture.pcap --protocol enip -f json \
  | jq -r '.[] | select((.enip_cip_service == "Write_Tag") and (.enip_cip_is_response == false)) |
           "\(.src_ip) -> \(.dst_ip): \(.enip_cip_path) = \(.enip_cip_values | join(" "))"'
```

Summarize CIP I/O (implicit messaging) traffic by connection -- how many
datagrams and how many bytes of I/O data each connection ID carried, useful
for spotting an active real-time I/O scan a capture wasn't expected to
contain:

```sh
conduitscope decode -r capture.pcap --protocol enip -f json \
  | jq -r '[.[] | select(.enip_io_connection_id != null)] | group_by(.enip_io_connection_id) |
           .[] | "\(.[0].enip_io_connection_id): \(length) datagram(s), \([.[].enip_io_data_length // 0] | add) byte(s) of I/O data"'
```

Build a quick PROFINET device inventory -- every NameOfStation seen in a DCP
exchange, deduplicated, useful as a first pass at what's actually on a
PROFINET segment before writing zone/conduit policy for it:

```sh
conduitscope decode -r capture.pcap --protocol profinet -f json \
  | jq -r '[.[] | select(.profinet_dcp_blocks != null) |
           .profinet_dcp_blocks[] | select(startswith("NameOfStation="))] | unique[]'
```

Summarize PROFINET cyclic RT IO traffic by FrameID -- how many datagrams and
how many bytes of IO data each FrameID (effectively, each IO connection)
carried, and whether any carried a non-OK TransferStatus worth investigating:

```sh
conduitscope decode -r capture.pcap --protocol profinet -f json \
  | jq -r '[.[] | select(.profinet_has_cyclic_data == true)] | group_by(.profinet_frame_id) |
           .[] | "\(.[0].profinet_frame_id): \(length) datagram(s), \([.[].profinet_cyclic_io_data_length // 0] | add) byte(s) of I/O data, \([.[] | select(.profinet_cyclic_transfer_status != 0)] | length) non-OK TransferStatus"'
```

Build a quick GOOSE publisher inventory -- every distinct `gocbRef`/`datSet`
pair seen, useful as a first pass at what's actually publishing GOOSE on a
substation segment before writing zone/conduit policy for it:

```sh
conduitscope decode -r capture.pcap --protocol goose -f json \
  | jq -r '[.[] | select(.goose_gocb_ref != null) | "\(.goose_gocb_ref) (\(.goose_dat_set))"] | unique[]'
```

Spot a GOOSE state-change/retransmission anomaly -- for each publisher,
every distinct `stNum` seen and how many `sqNum` retransmissions followed
it; an `stNum` that resets or jumps outside a publisher restart, or a
`sqNum` that doesn't count cleanly from 1, is the primary spoofing/replay
signal for this protocol:

```sh
conduitscope decode -r capture.pcap --protocol goose -f json \
  | jq -r '[.[] | select(.goose_st_num != null)] | group_by(.goose_gocb_ref) |
           .[] | .[0].goose_gocb_ref as $ref |
           (group_by(.goose_st_num)[] | "\($ref): stNum=\(.[0].goose_st_num) sqNum 1..\([.[].goose_sq_num] | max)")'
```

Build a Sampled Values publisher/stream inventory -- every distinct `svID`
seen, alongside its `smpRate`/`smpMod`, useful as a first pass at what's
actually publishing SV on a substation segment:

```sh
conduitscope decode -r capture.pcap --protocol sv -f json \
  | jq -r '[.[] | select(.sv_id != null) | "\(.sv_id) smpRate=\(.sv_smp_rate // "n/a") smpMod=\(.sv_smp_mod // "n/a")"] | unique[]'
```

Spot a Sampled Values stream-continuity gap -- for each publisher, flag any
consecutive `smpCnt` jump bigger than 1 (accounting for the 0-65535 wrap),
which can indicate dropped samples or a spoofed/replayed stream:

```sh
conduitscope decode -r capture.pcap --protocol sv -f json \
  | jq -r '[.[] | select(.sv_id != null)] | group_by(.sv_id) |
           .[] | .[0].sv_id as $id | [.[].sv_smp_cnt] as $counts |
           range(1; $counts | length) as $i |
           (($counts[$i] - $counts[$i-1] + 65536) % 65536) as $gap |
           select($gap != 1) | "\($id): smpCnt jumped by \($gap) at index \($i)"'
```

Spot an EtherCAT Working Counter anomaly -- every datagram whose `WKC` is 0,
which (outside link-up probes at the very start of a session) usually means
the addressed slave(s) didn't respond, alongside the `Cmd`/address that was
sent:

```sh
conduitscope decode -r capture.pcap --protocol ethercat -f json \
  | jq -r '.[] | select(.ethercat_first_wkc == 0) |
           "\(.index): \(.ethercat_first_cmd_name) adp=\(.ethercat_first_adp // "n/a") ado=\(.ethercat_first_ado // "n/a") logAddr=\(.ethercat_first_logical_address // "n/a")"'
```

Build a register-access inventory -- every distinct `Cmd`+`Ado` combination
seen, useful as a first pass at what an EtherCAT master is actually reading/
writing on a segment before writing zone/conduit policy for it:

```sh
conduitscope decode -r capture.pcap --protocol ethercat -f json \
  | jq -r '[.[] | select(.ethercat_first_ado != null) | "\(.ethercat_first_cmd_name) ado=\(.ethercat_first_ado) (decimal)"] | unique[]'
```

Build a BACnet device inventory -- every distinct device seen announcing
itself via I-Am (unsolicited or in response to a Who-Is sweep), the BACnet
analog of passively fingerprinting hosts from ARP/DHCP traffic:

```sh
conduitscope decode -r capture.pcap --protocol bacnet -f json \
  | jq -r '[.[] | select(.bacnet_service_name == "i-Am") | "\(.src_ip): \(.bacnet_values | join(", "))"] | unique[]'
```

Find every BACnet ReadProperty/WriteProperty exchange naming a specific
object and property, useful for a first pass at what an engineering
workstation or historian is actually polling before writing zone/conduit
policy for it:

```sh
conduitscope decode -r capture.pcap --protocol bacnet -f json \
  | jq -r '.[] | select(.bacnet_service_name | test("^(read|write)Property$")) |
           "\(.src_ip) -> \(.dst_ip): \(.bacnet_service_name) \(.bacnet_values // [] | join(", "))"'
```

Build a HART-IP field-device inventory from every Read Unique Identifier
response seen (commands 0/11/21) -- the long address, expanded device type,
and revision fields are this protocol's own device-fingerprinting message,
the HART analog of BACnet's I-Am:

```sh
conduitscope decode -r capture.pcap --protocol hartip -f json \
  | jq -r '[.[] | select(.hartip_command_name == "Read Unique Identifier" and .hartip_is_response == true) |
           "\(.hartip_address): \(.hartip_values | join(", "))"] | unique[]'
```

Build an OPC UA endpoint/security-posture inventory -- every distinct
endpoint offered by a server's own GetEndpointsResponse, the OPC UA analog
of BACnet's I-Am / EtherNet/IP's ListIdentity / HART-IP's Read-Unique-
Identifier "device fingerprinting" query, useful for spotting an endpoint
still accepting SecurityMode "None":

```sh
conduitscope decode -r capture.pcap --protocol opcua -f json \
  | jq -r '[.[] | select(.opcua_service_name == "GetEndpointsResponse") | .opcua_values[] | select(startswith("endpoint["))] | unique[]'
```

Find every OPC UA ActivateSession request that placed a UserName/Password
credential on the wire in cleartext -- this decoder's own deliberate
"SECURITY FINDING" note (see PROTOCOL COVERAGE's OPC UA "Identity token
decode" section), worth flagging on any conduit that should be running an
authenticated, encrypted OPC UA session:

```sh
conduitscope decode -r capture.pcap --protocol opcua -f json \
  | jq -r '.[] | select(.notes // [] | any(startswith("SECURITY FINDING"))) |
           "\(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port): \(.opcua_values[] | select(startswith("username=") or startswith("password=")))"'
```

Surface TCP flows still stuck "buffering" a Modbus/TCP PDU that never
arrives -- the signature of HART-IP's own documented weak-detection-gate
collision (a real HART-IP Session Initiate message misclassified as
Modbus/TCP, or unrelated background traffic false-positiving against
HART-IP's own gate; see PROTOCOL DETECTION and LIMITATIONS), worth a manual
look on a conduit expected to carry HART-IP:

```sh
conduitscope decode -r capture.pcap -f json \
  | jq -r '[.[] | select(.summary | test("buffering a (Modbus/TCP PDU|HART-IP message)")) | .summary] | unique[]'
```

Find every Modbus write whose response was never authoritatively paired --
either the response wasn't captured, or it used a different session/
transaction ID than expected (worth a closer look on a conduit that should
be a simple, complete request/response session):

```sh
conduitscope decode -r capture.pcap --protocol modbus -f json \
  | jq -r '.[] | select(.summary | test("^Write")) | select(.modbus_paired_request_index | not) |
           "\(.index): \(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port) \(.summary)"'
```

Check a capture against a zone/conduit policy, human-readable:

```sh
conduitscope policy validate -r capture.pcap --policy policy.yaml
```

Same check, but fail a CI pipeline step on any violation or unclassified
traffic (exit status `3`) while still capturing the full report for later
inspection:

```sh
conduitscope policy validate -r capture.pcap --policy policy.yaml -o report.txt
```

List just the violations, as JSON, for a script that only cares about what's
wrong:

```sh
conduitscope policy validate -r capture.pcap --policy policy.yaml -f json \
  | jq -r '.flows[] | select(.verdict == "violation") |
           "\(.client_ip) -> \(.server_ip):\(.server_port) (\(.protocols | join("+"))): \(.reason)"'
```

Check a `functions:`-restricted conduit against a compliant S7comm flow
(`tests/policies/functions_s7comm.yaml` permits only "Read Var"; this
capture's one flow only ever issues Read Var):

```sh
$ conduitscope policy validate -r tests/sample_s7comm_items.pcap \
    --policy tests/policies/functions_s7comm.yaml
Zone/conduit policy validation
  capture: tests/sample_s7comm_items.pcap
  policy:  tests/policies/functions_s7comm.yaml (2 zone(s), 1 conduit(s))

Result: COMPLIANT

Flows evaluated: 1 (1 allowed, 0 violation(s), 0 unclassified)
  1 total packet(s) in capture, 0 skipped (non-TCP/non-IP)

VIOLATIONS (0):
  (none)

UNCLASSIFIED TRAFFIC (0):
  (none)

ALLOWED (1):
  [1] 192.168.1.50 -> 192.168.1.10:102  (s7comm, 1 packet(s))
      zones: hmi_zone -> plc_zone, matched conduit "s7comm read var only"

Conduits never exercised by this capture (0):
  (none)
```

The same conduit against `tests/sample_s7comm.pcap`, whose flow also issues
Setup Communication and Write Var -- a violation, since `functions:`
matching is strict-all (every distinct function observed must be
permitted):

```sh
$ conduitscope policy validate -r tests/sample_s7comm.pcap \
    --policy tests/policies/functions_s7comm.yaml
Zone/conduit policy validation
  capture: tests/sample_s7comm.pcap
  policy:  tests/policies/functions_s7comm.yaml (2 zone(s), 1 conduit(s))

Result: NON-COMPLIANT (1 violation(s), 0 unclassified flow(s))

Flows evaluated: 1 (0 allowed, 1 violation(s), 0 unclassified)
  8 total packet(s) in capture, 0 skipped (non-TCP/non-IP)

VIOLATIONS (1):
  [1] 192.168.1.50 -> 192.168.1.10:102  (s7comm, 8 packet(s))
      zones: hmi_zone -> plc_zone
      functions 'Setup Communication', 'Write Var' observed; conduit 's7comm read var only' permits only: Read Var

UNCLASSIFIED TRAFFIC (0):
  (none)

ALLOWED (0):
  (none)

Conduits never exercised by this capture (1):
  - s7comm read var only
```

A misspelled `functions:` entry is caught at policy-load time, before any
capture is even opened, and offers a correction when one is plausible:

```sh
$ conduitscope policy validate -r tests/sample_modbus.pcap \
    --policy tests/policies/bad_functions_typo.yaml
error: tests/policies/bad_functions_typo.yaml:15: conduit 'unknown function, plausible typo':
unknown modbus function 'Read Holding Registerss' -- did you mean 'Read Holding Registers'?
```

See the "Function-level restrictions" subsection of POLICY FILE FORMAT
above for the one-protocol-only rule, the full list of each protocol's
known function/service names, and the EtherNet/IP ambiguous-compound-name
limitation.

Find MQTT CONNECT packets carrying cleartext credentials -- the same
deliberate security-finding pattern as OPC UA's Identity Token check above,
since MQTT's own Username/Password fields carry no confidentiality of their
own:

```sh
conduitscope decode -r capture.pcap --protocol mqtt -f json \
  | jq -r '.[] | select(.mqtt_values // [] | any(startswith("Username=") or startswith("Password="))) |
           "\(.src_ip):\(.src_port) -> \(.dst_ip):\(.dst_port): \(.mqtt_values[] | select(startswith("Username=") or startswith("Password=")))"'
```

Pull out every decoded Sparkplug B metric across a capture, grouped by
group/edge-node/device:

```sh
conduitscope decode -r capture.pcap --protocol mqtt -f json \
  | jq -r '.[] | select(.mqtt_is_sparkplug and (.mqtt_sparkplug_metrics // [] | length > 0)) |
           "\(.mqtt_sparkplug_group_id)/\(.mqtt_sparkplug_edge_node_id)\(.mqtt_sparkplug_device_id // "" | if . == "" then "" else "/" + . end) \(.mqtt_sparkplug_message_type): \(.mqtt_sparkplug_metrics | join(", "))"'
```

Note MQTT traffic on a port your zone policy doesn't expect on 1883:

```sh
conduitscope decode -r capture.pcap --protocol mqtt --mqtt-port 1883 -f text \
  | grep -B1 "not a configured/standard MQTT port"
```

Summarize FF-HSE traffic by sub-protocol and message name -- a quick way to
see which of FDA/SM/FMS/LAN Redundancy dominates a capture:

```sh
conduitscope decode -r capture.pcap --protocol ff-hse -f json \
  | jq -r '[.[] | select(.ffhse_protocol != null) | "\(.ffhse_protocol) / \(.ffhse_message_name)"] |
           group_by(.) | map("\(length)x \(.[0])") | .[]'
```

Pull every decoded FF-HSE field=value pair (e.g. from FMS Read/Write
traffic, SM device commissioning, or Error bodies), alongside which
message they came from:

```sh
conduitscope decode -r capture.pcap --protocol ff-hse -f json \
  | jq -r '.[] | select(.ffhse_values // [] | length > 0) |
           "\(.src_ip) -> \(.dst_ip): \(.ffhse_message_name): \(.ffhse_values | join(", "))"'
```

Find FF-HSE Error responses, grouped by ErrorClass -- useful for spotting a
device that keeps rejecting a particular class of request:

```sh
conduitscope decode -r capture.pcap --protocol ff-hse -f json \
  | jq -r '.[] | select(.ffhse_type == "Error") |
           (.ffhse_values[] | select(startswith("error-class="))) as $ec |
           "\(.ffhse_message_name): \($ec)"' | sort | uniq -c | sort -rn
```

Build a quick STP bridge/root inventory from Configuration and RST BPDUs --
one line per distinct (Bridge, Root) pair seen, useful for spotting an
unexpected root-bridge change on a conduit that shouldn't have one:

```sh
conduitscope decode -r capture.pcap --protocol stp -f json \
  | jq -r '[.[] | select(.stp_has_common_body) |
           "Bridge=\(.stp_bridge_priority)/\(.stp_bridge_sys_id_ext)/\(.stp_bridge_mac) Root=\(.stp_root_priority)/\(.stp_root_sys_id_ext)/\(.stp_root_mac)"] | unique[]'
```

Find every MSTP BPDU and list its MSTI Configuration Messages, e.g. to spot
which MST instances a region actually carries:

```sh
conduitscope decode -r capture.pcap --protocol stp -f json \
  | jq -r '.[] | select(.stp_is_mstp) |
           "\(.src_ip) -> \(.dst_ip): \(.stp_mst_config_name) \(.stp_msti_messages // [] | join(", "))"'
```

Summarize a DeviceNet (CAN-bus) capture by message group and type -- a
quick passive traffic inventory off a CAN bus, the same grouping pattern
the FF-HSE example above uses:

```sh
conduitscope decode -r capture.pcap --protocol devicenet -f json \
  | jq -r '[.[] | select(.protocol == "devicenet") | "\(.devicenet_group_name) / \(.devicenet_message_type)"] |
           group_by(.) | map("\(length)x \(.[0])") | .[]'
```

Decode a capture with hostnames and service names resolved against your own
site's naming, on top of the OUI vendor lookup that's already on by default
-- never touching live DNS, file-only:

```sh
conduitscope decode -r capture.pcap --resolve --hosts myhosts.txt -f json \
  | jq -r '.[] | "\(.src_ip) (\(.src_hostname // "?")) -> \(.dst_ip) (\(.dst_hostname // "?")): \(.protocol)"'
```

Fingerprint every distinct MAC vendor seen talking on the wire -- a quick
passive asset-inventory pass, without needing `--resolve`/`--hosts` at all
since OUI resolution is on by default:

```sh
conduitscope decode -r capture.pcap -f json \
  | jq -r '[.[] | .src_mac_vendor, .dst_mac_vendor] | map(select(. != null)) | unique[]'
```

## ROADMAP

Rough order, each building on the groundwork this release establishes:

1. **Validate live capture against a real Windows/Npcap install and a real
   OT/mirrored-switch-port network**, not just Linux loopback -- see LIVE
   CAPTURE's "Windows / Npcap notes" and LIMITATIONS.
2. **Confirm or replace the EXPERIMENTAL `0xB2` (S7-1200/1500 "symbolic"
   addressing) decode** against a source with real authority -- a PLC or
   TIA Portal project under your own control, ideally, rather than more
   public reverse-engineering writeups -- and extend it to the shapes it
   currently falls back to raw hex on: DB-area items, and items with more
   than one LID entry (structured/nested symbol access). Promote it out of
   [EXPERIMENTAL] once confirmed.
3. ~~PLC Control/Stop parameter decoding~~ (these send commands that change
   PLC run state -- high security relevance) -- **done**: classic S7comm's
   function codes `0x28` (PLC Control / PI-Service) and `0x29` (PLC Stop) are
   both fully decoded -- see PROTOCOL COVERAGE's S7comm / COTP section's
   "PLC Control (`0x28`) / PLC Stop (`0x29`)" entry and
   `include/conduitscope/s7comm.hpp`'s file header. Still open, and now
   standing on its own now that the PLC Control/Stop half above is done:
   extending S7comm-Plus's own Tier-2 functions (CreateObject, Explore,
   GetLink, BeginSequence/EndSequence, Invoke, GetVarSubStreamed,
   Notification, Connect, and DataFW1_5's Data part) to Tier 1, plus
   S7comm-Plus's own above-COTP, trailer-based reassembly (currently
   detected and reported, not reassembled -- see PROTOCOL COVERAGE's
   S7comm-Plus section, `include/conduitscope/s7commplus.hpp`'s file header,
   and LIMITATIONS).
4. ~~DNP3 CRC validation (both the header CRC and the per-block CRCs), so a
   corrupted frame that still starts with the right magic bytes is flagged
   rather than silently "decoded"~~ -- **done**, see PROTOCOL COVERAGE's DNP3
   "Data-link CRC-16 validation" section and LIMITATIONS. Not yet wired into
   `policy validate`/`PolicyEngine` (purely diagnostic in `decode` output
   today) -- that remains open, and isn't separately tracked as its own
   roadmap item, since no concrete use case has motivated a specific
   verdict-impact design for it yet.
5. ~~DNP3 absolute-time rendering as a calendar date~~ -- **done**, see
   PROTOCOL COVERAGE's DNP3 "Time and Date" entry and LIMITATIONS. Value
   decoding for the group/variation combinations still outside the
   point-format table (double-precision Analog Input Event variants, Octet
   String, File Control, Analog Input Reporting Deadband) remains open and
   isn't separately tracked as its own roadmap item yet.
6. ~~A policy `from`/`to` zone list wider than two endpoints per conduit~~
   (e.g. "any of these three zones may reach this one") -- **done**: a
   conduit's `from`/`to` each accept a single zone name or a list of them,
   and the conduit is many-to-many (any `from` zone to any `to` zone) --
   see POLICY FILE FORMAT's "Schema" section and its "Worked example"
   (`tests/policies/multi_from_zones.yaml`, `multi_to_zones.yaml`, and
   `multi_zone_bidirectional.yaml`). Nothing remains genuinely open about
   this item.
7. ~~Extend IEC 104's information-element decode table~~ to step position
   (types 5/6/32) and bitstring of 32 bit (types 7/8/33, command 51/64) --
   **done**, along with 17 more type IDs in the same pass: the
   CP24Time2a-tagged measured-value/integrated-totals variants (10/12/14/
   16), the normalized-value-without-quality-descriptor variant (21),
   time-tagged regulating-step and scaled-setpoint commands (60/62), delay
   acquisition (106), the time-tagged test command (107), and
   parameter-of-measured-value/parameter-activation (110/111/112/113). See
   PROTOCOL COVERAGE's IEC 60870-5-104 section for the full list and its
   own paragraph on what's deliberately still excluded (the
   protection-equipment event types, M_PS_NA_1 packed single-point with
   status change detection, file transfer, and C_TS_NA_1). Still open and
   not separately tracked as its own roadmap item: full counter-
   interrogation (type 101)/read (102) command decoding -- both are
   recognized, named type IDs, but their information elements aren't
   value-decoded yet, the same "structurally located, not value-decoded"
   state every still-unlisted type ID gets.
8. ~~Extend EtherNet/IP's CIP value decoding to STRING/SHORT_STRING and
   structured (UDT/array) elementary types~~ -- **done**: STRING (`0xD0`)/
   SHORT_STRING (`0xDA`) decode to plain text, and Structured Data Type
   (any type code `>= 0x02A0`) decodes its 2-byte Structure Handle (member
   bytes shown as hex, no Template definition available) -- see PROTOCOL
   COVERAGE's EtherNet/IP section and the "now done" paragraph below. Fixing
   this also fixed a real bug: `cip_is_plausible_type_code` previously only
   accepted the `0xC1`-`0xDE` elementary range, so a genuine UDT Read_Tag
   response was wrongly rejected as "not a Rockwell tag read at all"; it
   now also accepts the `>= 0x02A0` structured range. STRING2/STRINGN/
   STRINGI/EPATH/ENGUNIT-as-a-value remain open and aren't separately
   tracked as their own roadmap item. Still open and worth revisiting once
   real-world evidence exists: whether the symbolic-path-gating gate itself
   (see PROTOCOL COVERAGE) is ever too narrow in practice -- e.g. a real
   device addressing a Symbol-object tag by numeric instance ID rather than
   by name, which this release's gating would currently show structurally
   rather than as a tag read.
9. ~~Decode IEC 61850-9-2 Sampled Values~~ -- **done**, see PROTOCOL
   COVERAGE's Sampled Values subsection and the "now done" paragraph below.
   ~~Decode EtherCAT~~ -- **also done**, see PROTOCOL COVERAGE's EtherCAT
   subsection and its own "now done" paragraph below. That closes out this
   item's original "decode the remaining named-but-undecoded raw-Ethernet OT
   protocol" call-out entirely: CIP I/O, PROFINET RT, GOOSE, Sampled Values,
   and now EtherCAT are all done, and this project no longer tracks any
   named-but-undecoded raw-Ethernet OT protocol of its own. Also, separately:
   validate CIP I/O decoding
   against a real capture (none was found while building it -- see
   `tests/real_captures/enip/ATTRIBUTION.md`) if one ever turns up, and
   consider cross-datagram CIP I/O correlation (connection ID back to its
   Forward_Open, sequence-number continuity/gap detection) -- see
   LIMITATIONS for exactly what's missing there now. Likewise for PROFINET
   RT: a real cyclic RT IO data capture to validate `decode_cyclic` against
   (none found either -- see `tests/real_captures/profinet/
   ATTRIBUTION.md`), and resolving the cyclic-IO-data-vs-Ethernet-padding
   ambiguity if a reliable way to tell them apart ever turns up (see
   LIMITATIONS). And for GOOSE: real-capture validation for optional-field
   absence, every `allData` type beyond boolean/bit-string, and a GSE
   Management PDU, none of which any real capture found so far exercises
   (see `tests/real_captures/goose/ATTRIBUTION.md`). And for Sampled Values:
   real-capture validation for literally every code path, since none was
   found at all despite a genuine multi-source search (see PROTOCOL
   COVERAGE's Sampled Values subsection). And for EtherCAT: real-capture
   validation for the Cmd values (APRW/FPRW/BRW/LRW/ARMW/FRMW/EXT/NOP), the
   `Circulating` bit, VLAN tagging, and non-Type-1 frames the one real
   capture found doesn't happen to exercise (see PROTOCOL COVERAGE's
   EtherCAT subsection and `tests/real_captures/ethercat/ATTRIBUTION.md`),
   and CoE/SoE/EoE/FoE/AoE mailbox decoding, if a reliable way to recognize
   it without per-slave SyncManager configuration knowledge ever turns up.
   And for BACnet/IP: real-capture validation for device discovery
   (Who-Is/I-Am/Who-Has/I-Have), WriteProperty, every PropertyValue type
   besides a scalar Unsigned, every BVLC function besides
   Original-Unicast-NPDU, NPDU DEST/SRC/Network-Layer-Message routing
   fields, and segmentation, none of which the one real capture found so
   far exercises (see PROTOCOL COVERAGE's BACnet/IP subsection and
   `tests/real_captures/bacnet/ATTRIBUTION.md`); extending value decoding
   beyond the "first pass" service set (ReadPropertyMultiple/
   WritePropertyMultiple in particular, since they're increasingly the more
   efficient, more common choice in modern deployments); and revisiting
   `kargs.net`'s own capture archive for a richer real-capture source if
   this project's network access to it is ever unblocked. And widen `policy
   validate` beyond TCP-only conduits, now that there are actual decoded
   non-TCP protocols (CIP I/O, PROFINET RT, GOOSE, Sampled Values, EtherCAT,
   BACnet/IP) worth checking a conduit against -- PROFINET RT, GOOSE,
   Sampled Values, and EtherCAT all ride raw Ethernet with no IP layer at
   all, though, so they would need a conduit-rule shape that isn't
   IP/CIDR-based to ever be covered; CIP I/O, BACnet/IP, and HART-IP's own
   UDP traffic, by contrast, are ordinary IP/UDP traffic, so extending
   `policy validate` to evaluate UDP flows at all (see LIMITATIONS) would
   cover all three at once (HART-IP's own TCP traffic is already covered by
   `policy validate` today, the same as any other TCP-based protocol here).

10. ~~Extend HART-IP's command value-decode table beyond the "first pass"
    set -- commands 77 and 178 in particular~~ -- **done**: command 77
    (Send Command to Sub-Device) and command 178 (the unnamed BATCH/
    aggregate wrapper) are both now value-decoded, including recursively
    decoding whichever command(s) each one wraps through this decoder's own
    existing command table -- see PROTOCOL COVERAGE's Command value-decode
    section. No real capture found so far happens to carry either (see
    `tests/real_captures/hartip/ATTRIBUTION.md`'s own "Gaps" section), so
    this remains synthetic-fixture-only validated, like commands 31/203
    already were.

    Still open: verify the HART Data-Link Checksum (the XOR algorithm
    across the whole PDU, currently surfaced raw and never checked -- see
    LIMITATIONS); resolve multi-definition/warning-class Response Codes to
    their actual per-command meaning, if a reliable source for enough
    individual commands' own spec text ever turns up; and widen real-capture
    validation to Error/NAK messages, the BACK frame type, non-Success
    response codes, and the ten-plus commands (now including 77/178) the
    one real capture found for this feature doesn't happen to exercise.

11. ~~Implement OPC UA's Variant/DataValue self-describing value encoding~~
    (OPC 10000-6 5.2.2.16/5.2.2.17) -- **done**: full Variant/DataValue value
    decoding (all 25 BuiltInTypes, scalar and array, ArrayDimensions, and
    DataValue's own non-bit-numeric wire field order) is now implemented --
    see PROTOCOL COVERAGE's "Variant/DataValue value decoding" section. This
    promoted **Read**, **Write**, and **Call** from header-only (Tier 2) to
    full value decoding (Tier 1) -- the three services whose entire reason
    for existing IS carrying a Variant or DataValue, so this is where the
    actual process/tag values an OPC UA client reads or writes are now
    visible. **Browse** and the subscription/MonitoredItem-management
    services were deliberately left at Tier 2: neither actually carries a
    Variant/DataValue anywhere in its own body, so promoting them is a
    separate, unrelated decode effort. **HistoryRead** does carry
    DataValue/Variant, but its own HistoryReadDetails ExtensionObject
    dispatches across five different sub-structures -- enough additional
    scope of its own that it's left for a later round too. Validated
    against this decoder's own synthetic fixtures (a DataValue with all six
    optional fields set, to regression-test the field-order finding above;
    Float/Null scalars; String/UInt32 Variant arrays, the latter with
    ArrayDimensions) AND, unexpectedly, against the existing real capture:
    promoting Call to Tier 1 revealed that BOTH sessions' own CallRequest in
    that capture are genuinely malformed (Achilles Satellite fuzz-test
    payloads -- one claims a 262144-byte String with ~21 bytes actually
    present, the other has a structurally-invalid NodeId encoding byte) --
    this decoder's own bounds-checked reads now correctly reject them rather
    than the old Tier-2 behavior of labeling them "CallRequest" without ever
    attempting to parse their bodies. Still open: OPC UA chunk reassembly (a
    logical message split across multiple `'C'`/`'F'` chunks -- distinct
    from the already-implemented TCP-segment-level reassembly, see PROTOCOL
    COVERAGE's "Chunking" subsection); widening the StatusCode table past
    its current ~20-entry first pass; promoting Browse/subscriptions/
    HistoryRead to Tier 1 (see above); and widening real-capture validation
    to FindServers, CloseSession, CloseSecureChannel, a non-Anonymous
    identity token, a non-`'F'` chunk, and a well-formed (non-fuzzed) Read/
    Write/Call exchange, if a second real OPC UA capture with that coverage
    ever turns up (see `tests/real_captures/opcua/ATTRIBUTION.md`'s own
    honest scope).
12. ~~**Extend MMS's Tier 2 confirmedServices to full field decoding**~~ --
    **done, scoped to the file-transfer services**: `obtainFile`/
    `fileOpen`/`fileRead`/`fileClose`/`fileRename`/`fileDelete`/
    `fileDirectory` are now Tier 1 (full field decode) -- see PROTOCOL
    COVERAGE's MMS section and mms.hpp's own "File-transfer services"
    paragraph. This was the ROADMAP item's own explicitly-named priority:
    IEC 61850's own COMTRADE/disturbance-file-retrieval and firmware/
    configuration-file-transfer workflows ride on exactly these seven
    services, the most OT-security-relevant of MMS's remaining
    Tier 2 group. `FileName` (a `SEQUENCE OF GraphicString`) is rendered
    joined by "/", matching Wireshark's own `packet-mms.c`
    `dissect_mms_FileName`; `GeneralizedTime` (an ASCII text timestamp,
    distinct from the Data CHOICE's own binary `UtcTime`) is reformatted
    to this codebase's ISO-8601 convention when it parses, shown verbatim
    otherwise; `fileData` is a full, never-truncated hex dump.
    `ObtainFile-Request`'s own `sourceFileServer` (an `ApplicationReference`)
    is structurally recognized but not deep-decoded, the same posture this
    decoder's own ACSE AARQ/AARE decode already takes for AP-title/
    AE-qualifier elsewhere. 60 of the 78 defined confirmed services remain
    Tier 2 (name + invokeID only, body shown as raw hex) -- see PROTOCOL
    COVERAGE's MMS section for the full split. Still open, left for a
    future round: decoding `Address` (non-symbolic variable addressing)
    and `TypeSpecification` (currently both shown only as a structural
    placeholder); implementing the Session layer's extended (2-byte)
    length form, if real traffic using it ever turns up; and widening
    real-capture validation beyond the three small ITI/ICS-Security-Tools
    captures and one self-generated libiec61850 session this decoder
    currently has (see `tests/real_captures/mms/ATTRIBUTION.md`) -- in
    particular, a real capture exercising any Tier 2 service or the new
    file-transfer services specifically, a ServiceError/rejectPDU on real
    traffic (currently synthetic-fixture-validated only), or a stack that
    negotiates a presentation-context numbering other than the assumed
    "1=ACSE, 3=MMS" convention, would meaningfully extend this decoder's
    own confidence.
13. ~~**Expose DNP3's own data-link source/destination address**~~ --
    **done**: `Dnp3LinkFrame::source`/`destination` (already parsed
    internally for the data-link summary line) are now surfaced on
    `DecodedPacket` and in JSON output as `dnp3_source_address`/
    `dnp3_destination_address` -- see JSON OUTPUT FIELDS and POLICY FILE
    FORMAT's "Addressing scope" section, both updated. Set whenever
    `protocol == "dnp3"`, even for a link-layer-only control frame with no
    user data at all (a data-link header carries both addresses
    regardless), mirroring the first data-link frame found in a TCP
    payload, same "first frame only" convention this decoder's own DNP3
    CRC fields already use; reliability tracks `dnp3_header_crc_valid`.
    Still open, left for a future round: the ROADMAP item's own further
    suggestion of "a zone model that can classify by this address in
    addition to (or instead of) IP" -- the single most consequential
    addressing gap in this codebase, since serial-to-IP DNP3 gateways
    routinely multiplex several outstations behind one IP, but a genuinely
    separate scope of its own (policy file format changes, `PolicyEngine`
    matching logic, and its own test/documentation pass) from simply
    exposing the two fields this round completed.
14. **Widen the conduit `protocols` enum** beyond its current
    `{modbus, dnp3, s7comm, iec104, enip, any}` to name the other
    protocols `decode` already recognizes (BACnet/IP, HART-IP, OPC UA,
    MMS, MQTT, FOUNDATION Fieldbus HSE) individually, rather than only
    being reachable through `any` -- a straightforward enum-and-
    dispatch-table widening, not a design change (see POLICY FILE
    FORMAT's "Addressing scope" section).
15. **A VLAN-membership-based conduit/zone model**, as an alternative to
    (not a replacement for) the existing IPv4-CIDR one, for the four
    protocols with no IP layer at all (PROFINET RT, GOOSE, Sampled
    Values, EtherCAT) -- 802.1Q tags are already decoded generically
    (`has_vlan_tag`/`vlan_id`) but never consulted by `PolicyEngine`. Also
    worth reconsidering once DNP3's link address (item 13) is exposed: a
    zone model keyed on that address rather than (or alongside) IP.
16. **Extend `policy validate`'s report with the same OUI/hostname/service-
    name annotations `decode` now has** (see OUTPUT FORMATS' "Name
    resolution" subsection and LIMITATIONS) -- currently `decode`-only,
    deliberately out of scope for this feature's first pass since
    `policy validate`'s report is a separate, IP/zone-centric format with
    its own conventions (`PolicyEngine`/`policy_engine.hpp`) rather than a
    per-packet `DecodedPacket` stream. Would need its own `--no-oui`/
    `--resolve`/`--hosts`/`--nn`/`--services` flags (or to share `decode`'s)
    threaded through to wherever the report renders a MAC/IP/port today.
17. **Passive OT asset inventory: pcap -> zones and conduits.** A new
    subcommand (working name `inventory`) that runs the opposite direction
    from `policy validate` -- instead of checking observed traffic against
    a hand-written zone/conduit policy, it infers a first-draft one from a
    capture. Feed it a pcap from an industrial network and it identifies
    Modbus, S7comm, DNP3, EtherNet/IP, and BACnet/IP talkers (all already
    decoded by this project -- see PROTOCOL COVERAGE), builds an asset list
    (IP/MAC, OUI vendor guess, protocols spoken, client-vs-server role
    inferred from who initiates) and a communication matrix (who talks to
    whom, over which protocol/port), then proposes an IEC 62443 zone/
    conduit model from that matrix -- most likely grouped by protocol
    and/or observed subnet as a first-pass heuristic -- rendered as a
    diagram (Mermaid or Graphviz `.dot`) and, ideally, as a `policy`-format
    YAML file directly loadable by `policy validate` (closing the loop:
    discover, then enforce). NSA's GRASSMARLIN used to occupy this niche
    but is abandoned; CISA's Malcolm covers similar ground but is a heavy
    multi-container Zeek/OpenSearch/Elastic stack, not a lightweight
    single-binary CLI -- a `tshark`/Zeek-log-adjacent tool that's just
    "pcap in, zone/conduit model out" appears to be a genuine gap this
    project's existing decode + `PolicyEngine`/zone infrastructure is
    unusually well positioned to fill. An LLM-assisted zone-assignment
    suggestion (which zone a given device most plausibly belongs in, with
    a short rationale -- e.g. "talks Modbus only to 10.0.1.5, no traffic to
    any other zone: candidate for a dedicated PLC zone") is an optional,
    clearly-labeled enhancement on top of the heuristic grouping above, not
    a prerequisite for it -- the deterministic pcap-to-model pipeline should
    stand on its own first.

**pcapng support** is also now done: both classic pcap and pcapng are read
transparently (auto-detected, no flag needed) -- see "pcap vs. pcapng"
above and LIMITATIONS for the small set of rare/obsolete pcapng block types
that are skipped rather than decoded.

**IEC 60870-5-104 support** is also now done: APCI framing (I/S/U-format),
and, for I-format APDUs, full ASDU decoding for the type IDs that dominate
real traffic -- see PROTOCOL COVERAGE's IEC 60870-5-104 section and item 7
above for the type IDs still outside the decode table. Because one I-format
APDU always carries exactly one complete ASDU, no cross-frame application-
fragment reassembly analogous to DNP3's was needed -- only the same
TCP-segment-level PDU reassembly every protocol here gets. IEC 104 detection
runs before Modbus/TCP's in Auto-mode dispatch specifically to resolve a
detection collision found while scoping this feature -- see PROTOCOL
DETECTION.

**EtherNet/IP (CIP explicit messaging) support** is also now done: the
24-byte encapsulation header, ListIdentity device-fingerprinting fields,
Common Packet Format item parsing, and a "first pass" CIP explicit-message
decode (generic common services, Connection Manager's Unconnected_Send/
Forward_Open/Forward_Close, and, symbolic-path-gated, the Rockwell
Symbol-object tag services, including STRING/SHORT_STRING and Structured
Data Type (UDT/array) value decoding -- see item 8's "done" note) -- see
PROTOCOL COVERAGE's EtherNet/IP section and item 8 above for what's still
out of scope (STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value). EtherNet/IP
detection runs first in Auto-mode dispatch,
ahead of even IEC 104, since its own dedicated port plus three independent
structural checks make it, if anything, a stronger signal -- see PROTOCOL
DETECTION.

**Link/IP-layer plumbing for non-IPv4/non-TCP traffic** is also now done:
non-IPv4 Ethernet frames and non-TCP IPv4 payloads (including UDP) are
recognized and named for a deliberately small, OT-relevant set of
EtherTypes/IP-protocol-numbers (ARP, LLDP, ICMP,
and the rest), rather than just a bare hex/decimal number and nothing else
-- see PROTOCOL COVERAGE's link/IP-layer plumbing section, and `policy
validate` doesn't yet evaluate any non-TCP traffic against a conduit.
PROFINET RT, IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, and
EtherCAT, formerly in
this same named-but-not-decoded set, are decoded now -- see the next four
paragraphs.

**EtherNet/IP CIP I/O (implicit messaging) decoding** is also now done: the
first protocol this tool decodes over UDP, and the direct extension of the
CIP explicit-messaging work above that item 9 originally called out as the
most likely next candidate. The Sequenced Address Item (connection ID +
sequence number) is fully decoded; the Connected Data Item (the actual I/O
data) is located and shown as raw hex, deliberately never value-decoded --
see PROTOCOL COVERAGE's CIP I/O subsection and LIMITATIONS for exactly why,
and item 9 above for what's still open (real-capture validation,
cross-datagram correlation, and widening `policy validate` to cover it).

**PROFINET RT (DCP and cyclic real-time IO) decoding** is also now done:
the first protocol this tool decodes directly over raw Ethernet, with no
IP/TCP/UDP layer at all -- item 9 above's other most likely next
candidate, alongside CIP I/O, and now also done. FrameID-based dispatch
covers DCP (device discovery/configuration -- full PDU header, block
list, and five value-decoded block types) and cyclic real-time IO
datagrams (IO data plus the CycleCounter/DataStatus/TransferStatus
trailer) -- see PROTOCOL COVERAGE's PROFINET RT subsection for the full
FrameID range table and LIMITATIONS for what's still open (cyclic IO
data's length ambiguity, no real cyclic-IO capture to validate against,
and no cross-datagram DCP request/response pairing). Validating this
decoder against two real DCP captures caught a genuine decoding bug before
it ever shipped -- see PROTOCOL COVERAGE's PROFINET RT subsection and
`tests/real_captures/profinet/ATTRIBUTION.md` for the full story.

**IEC 61850-8-1 GOOSE decoding** is also now done: the second protocol this
tool decodes directly over raw Ethernet, alongside PROFINET RT, and the
answer to item 9's original "decode the remaining named-but-undecoded
raw-Ethernet protocol" call-out (now narrowed to just Sampled Values -- see
item 9 above). The 8-byte header (APPID/Length/S-bit) and the full ASN.1
BER-encoded APDU are decoded: every IECGoosePdu field, including the
`stNum`/`sqNum` state-change/retransmission counters that are the primary
GOOSE spoofing/replay signal, and every `allData` value type, recursively
for nested `array`/`structure` values -- see PROTOCOL COVERAGE's GOOSE
subsection for the full field/type tables and LIMITATIONS for what's still
open (optional-field-absence and most `allData` types have no real-capture
validation, GSE Management PDU content isn't decoded, multi-APDU frames
aren't supported). Validating this decoder against real bytes caught a
genuine tag-table error before it ever shipped -- an initial source read
suggested every PDU field used constructed BER encoding, which a
from-scratch BER walker run against a real capture's bytes disproved -- see
PROTOCOL COVERAGE's GOOSE subsection and `tests/real_captures/goose/
ATTRIBUTION.md` for the full story, mirroring the PROFINET RT
BlockInfo/BlockQualifier bug the paragraph above describes.

**IEC 61850-9-2 Sampled Values decoding** is also now done: the third
protocol this tool decodes directly over raw Ethernet, alongside PROFINET RT
and GOOSE, and the final answer to item 9's original "decode the remaining
named-but-undecoded raw-Ethernet protocol" call-out. SV shares GOOSE's
8-byte header format and ASN.1 BER TLV foundation, but has its own distinct
APDU shape: a single-alternative outer CHOICE (`0x60` `savPdu`, vs. GOOSE's
two), and a `SavPdu` wrapping `noASDU` plus a `seqASDU` of one or more
per-item `0x30`-tagged `ASDU` elements -- all of which, unlike GOOSE's
single-APDU-per-frame scope, are decoded (multiple ASDUs per SavPdu is core,
spec-defined behavior, not a rare edge case). Every `ASDU` field is decoded
(`svID`, `datSet`, `smpCnt` -- the primary stream-integrity/replay-detection
signal, analogous to GOOSE's `stNum`/`sqNum` -- `confRev`, `refrTm`,
`smpSynch`, `smpRate`, `smpMod`, and the Ed.2.1 `gmidData` grandmaster-clock
field) except `seqData` (the sample payload itself), which is deliberately
shown only as raw hex and never value-decoded -- interpreting it requires an
implementation profile (e.g. the common "9-2LE" 8-channel layout) layered on
top of the base ASN.1, not something the standard itself asserts, the same
"no generic self-describing wire-level type" reasoning already applied to
PROFINET RT's cyclic IO data and CIP I/O's Connected Data Item -- see
PROTOCOL COVERAGE's Sampled Values subsection for the full field tables and
LIMITATIONS for what's still open. Unlike every other protocol added so far,
no real capture was found for *any* SV code path despite a genuine
multi-source search (Wireshark's own test-capture tree and wiki, several
public ICS-pcap repositories, IEC 61850 tooling projects, and a Wireshark
GitLab issue's attached sample) -- validation here is honestly
synthetic-fixture-only from the start; see `include/conduitscope/sv.hpp`'s
file header for the full search writeup.

**EtherCAT decoding** is also now done: the fourth protocol this tool
decodes directly over raw Ethernet, alongside PROFINET RT/GOOSE/SV, and the
final answer to item 9's original "decode the remaining named-but-undecoded
raw-Ethernet protocol" call-out -- this project no longer tracks any
named-but-undecoded raw-Ethernet OT protocol of its own. Unlike GOOSE/SV's
shared ASN.1-BER foundation, EtherCAT is a plain fixed-binary-layout
protocol with its own distinct framing: a 2-byte frame header (Length/
Reserved/Type) and, for Type 1 ("EtherCAT command") frames, a chain of
EtherCAT datagrams (`Cmd`/`Idx`/`Adp`-`Ado`-or-logical-address/`Len`+flags/
`Irq`/`Data`/Working Counter) -- see PROTOCOL COVERAGE's EtherCAT subsection
for the full field tables and LIMITATIONS for what's still open. `Data` is
deliberately never value-decoded, the fourth application of this codebase's
"no generic self-describing wire-level type" reasoning after PROFINET RT's
cyclic IO data, CIP I/O's Connected Data Item, and SV's `seqData`. One
honest gap unique to this protocol: its frame-header `Type` field is a
genuinely weaker structural detection signal than every other raw-Ethernet
protocol here (5 of 16 possible 4-bit values, vs. GOOSE/SV's 1-in-256 outer
tag or PROFINET's FrameID range table) -- the dedicated EtherType remains
the primary confidence source. Unlike Sampled Values, a real capture WAS
found (986 frames) and directly confirmed a deliberate design choice: this
decoder bounds its datagram-chain scan by the frame header's own declared
Length field, rather than walking every byte physically present in the
frame the way Wireshark's own dissector does, specifically to avoid
misreading Ethernet's minimum-frame-size zero-padding as a spurious
trailing datagram -- all 986 real frames show declared Length exactly
matching the actual chained-datagram byte count, zero mismatches. See
`tests/real_captures/ethercat/ATTRIBUTION.md` for full provenance and
exactly which Cmd values/bits/frame Types that capture does and doesn't
exercise, and `include/conduitscope/ethercat.hpp`'s file header for the
full writeup.

**BACnet/IP decoding** is also now done: the second protocol this tool
decodes over UDP, alongside CIP I/O, using the same port-independent
"opportunistic, payload-shape" detection posture rather than a dedicated
EtherType the way PROFINET RT/GOOSE/SV/EtherCAT get to use. Three layers
are decoded: BVLC (the UDP framing header, including every BBMD/
foreign-device-table management function), NPDU (the network layer,
including DEST/SRC routing fields and Network Layer Messages, named only),
and APDU (the application layer, byte-accurate across all 8 PDU types
including segmentation's SEG/MOR bits). Service value-decoding is a
deliberate "first pass" -- mirroring this codebase's existing service-
scoping precedent for EtherNet/IP CIP explicit messaging and DNP3's
group/variation table -- covering Who-Is/I-Am/Who-Has/I-Have device/object
discovery and ReadProperty/WriteProperty/generic-Error, the two most
security-relevant BACnet traffic patterns for passive OT monitoring; a
constructed/array PropertyValue is the fifth application of this
codebase's "no generic self-describing wire-level type" reasoning, after
PROFINET RT's cyclic IO data, CIP I/O's Connected Data Item, SV's
`seqData`, and EtherCAT's `Data` -- see PROTOCOL COVERAGE's BACnet/IP
subsection for the full field/service tables and LIMITATIONS for what's
still open. A real capture WAS found: 54 frames (a ReadProperty polling
session against trend-log objects) extracted from a larger mixed-OT-
protocol capture whose own README doesn't even mention BACnet -- found
only by actually running this decoder against every file in that
repository. Two better-looking real-capture sources were checked first and
couldn't be used: `automayt/ICS-pcap`'s own `BACNET/` directory (the
better-populated public BACnet collection, but stored via Git LFS, which
this environment cannot resolve -- the same limitation already hit for
this project's EtherCAT/GOOSE/SV real captures) and `kargs.net`'s own
capture archive (BACnet dissector co-author Steve Karg's ~220-file
collection, almost certainly the single best BACnet source on the public
web, but blocked outright by this session's network policy) -- see
`tests/real_captures/bacnet/ATTRIBUTION.md` for the full search record and
`include/conduitscope/bacnet.hpp`'s file header for the full writeup.

**Colorized text output** is also now done: see OUTPUT FORMATS' "Color"
subsection for the scheme and the `--color`/`--no-color`/auto-detection
rules. `policy validate`'s text report stays deliberately plain (an audit
artifact, meant to be diffed/archived/piped without ANSI noise) -- that
remains a considered choice, not an oversight, unless a real use case for
coloring it turns up.

All of what was originally tracked here as "general TCP stream reassembly"
is now done: PDU/frame-level reassembly across TCP segments
(`Decoder::reassemble_tcp_payload`, covering Modbus, DNP3, IEC 104,
EtherNet/IP, and TPKT/COTP alike), authoritative Modbus request/response
pairing by transaction ID (`Decoder::pair_modbus_transaction`), and chaining
an S7comm message across multiple complete TPKT/COTP frames
(`Decoder::reassemble_cotp_data_frame`) -- see LIMITATIONS for each one's
exact scope and remaining caveats. DNP3 *application*-layer fragmentation
across complete data-link frames is a related, already-done special case --
conduitscope reassembles it per TCP flow via its own mechanism -- but it
still awaits validation against a real capture that actually exercises it
(none found so far; see LIMITATIONS).

The **zone/conduit policy engine** behind `policy validate` (`policy.hpp`/
`policy_engine.hpp`) is also now done: a policy file (a restricted YAML
subset -- see POLICY FILE FORMAT) declares zones and conduits, and every
decoded TCP flow is checked against them, producing a compliant/non-compliant
report (text or JSON) suitable for a NIS2/62443 audit trail. S7comm item
tags, decoded DNP3 point values (especially CROB commands), Modbus
address+quantity decoding, and authoritative Modbus request/response pairing
were exactly the concrete decoded facts this was building toward being able
to match a policy against -- see LIMITATIONS for the engine's own remaining
caveats (the SYN-based initiator heuristic's fallback case, IPv4/TCP-only
zones, one-conduit-per-zone-pair direction model).

**Live capture** (`-i/--interface`, `conduitscope interfaces`) is also now
done, as an optional, build-time-detected libpcap (Linux) / Npcap (Windows)
dependency layered on top of everything above without changing any of it --
`decode -i`/`policy validate -i` feed the exact same `PcapPacket` shape into
the same `Decoder`/`PolicyEngine` that offline files do (see
`live_capture.hpp`'s `LiveCapture` and `cli_main.cpp`'s `PacketSource`), so
every protocol-decoding and policy-checking behavior documented throughout
this manual applies identically whether the traffic came from a file or a
live interface. See LIVE CAPTURE above for the full reference and
LIMITATIONS for what's not yet validated (the Windows/Npcap path, and a real
production OT network rather than loopback).

**HART-IP support** is also now done: the 8-byte fixed header, all four
MessageID-selected body shapes (Session Initiate/Close/Keep Alive/Pass
Through), the full byte-by-byte Pass-Through Data-Link PDU, a "first pass"
command value-decode set, packed-ASCII and HART-format-timestamp decoding,
and opportunistic detection on both TCP and UDP -- see PROTOCOL COVERAGE's
HART-IP section. Unlike every protocol added before it, this one surfaced a
genuine, unavoidable detection collision rather than a resolvable one: a
HART-IP Session Initiate message's own header happens to also look like a
plausible Modbus/TCP MBAP header, and unlike the IEC-104-vs-Modbus collision
this project already resolved once by reordering, the same fix measurably
regressed this project's own Modbus/S7comm test corpus when tried here (see
PROTOCOL DETECTION's "Why HART-IP is tried last"). Rather than silently
working around that with an unsafe fix, it's documented as an accepted
limitation, demonstrated in the synthetic fixture, and -- independently --
confirmed to occur on genuine field traffic, not just a hand-built one, by
the real HART-IP capture found for this feature (see
`tests/real_captures/hartip/ATTRIBUTION.md`, which also surfaced a second,
previously-undocumented false-positive pattern against unrelated background
TCP traffic). See LIMITATIONS for the complete list of what's still out of
scope (Checksum verification, per-command Response Code resolution, and
more).

**OPC UA Binary support** is also now done: the 8-byte UA-TCP common
header, the full OpenSecureChannel/CloseSecureChannel/Message
SecureConversation framing (SecureChannelId, security header, sequence
header), and a "first pass" two-tier service decode -- Tier 1 covers the
full connection/channel/session lifecycle plus both discovery services
(15 request/response pairs in all, including ServiceFault), Tier 2 names
every other service and decodes its RequestHeader/ResponseHeader while
leaving the Variant/DataValue-dependent body as raw hex -- see PROTOCOL
COVERAGE's OPC UA section and item 11 above for what's still out of scope.
Unlike HART-IP above, this protocol's own structural detection gate (a
3-byte ASCII MessageType match against 7 fixed strings) is strong enough,
and confirmed collision-free with every other protocol in this dispatch
chain, to be tried FIRST rather than last -- the opposite ordering
rationale from HART-IP's own weak-gate placement, see PROTOCOL DETECTION.
Deliberately, ActivateSessionRequest's own UserName/Password identity token
is decoded including the cleartext Password whenever EncryptionAlgorithm is
empty, flagged with an explicit `"SECURITY FINDING"` note -- a real,
documented OPC UA credential-exposure pattern (OPC 10000-4 7.41), not a
hypothetical, and directly in service of this tool's own stated purpose as
an OT-security-auditing decoder. A real capture was found and validated:
two OPC UA sessions from a well-known, widely-mirrored 2009 Wireshark
dissector-bug reproduction capture, on a non-standard TCP port that
Wireshark's own default configuration doesn't even recognize as OPC UA --
this decoder does, without any port hint, cross-checked field-by-field
against tshark's own OPC UA dissector once pointed at the right port (see
`tests/real_captures/opcua/ATTRIBUTION.md`). That same capture also
happens to be the first real-world confirmation this project's general
TCP-segment-level reassembly mechanism gets (two responses genuinely split
across 5 and 6 TCP segments, both reassembled and decoded correctly), and
contains two deliberately malformed CallRequest packets -- one of which
triggered Wireshark's own ~2-minute dissector freeze -- that this decoder's
own Tier 2 raw-hex scope is structurally immune to, since it never attempts
to parse a malformed CallRequest body at all.

**IEC 61850 MMS support** is also now done: the full four-layer stack
(Session ISO 8327-1 / Presentation ISO 8823 / ACSE ISO 8650-1 / MMS ISO
9506-2) is decoded, sharing S7comm's exact TPKT/COTP transport and TCP port
102 but detected by its own, separate structural gate recognizing three
shapes (a full Session-layer association, "bare MMS", and "bare
Presentation") -- see PROTOCOL COVERAGE's MMS section and item 12 above for
what's still out of scope. Unlike this codebase's own OPC UA decoder, MMS's
own self-describing "Data" value type (14 of 17 alternatives) IS decoded in
full, so the actual read/write/report values an MMS client exchanges are
visible, not just that an exchange happened; a hard-capped 32-level
recursion depth on Data's own array/structure alternatives defends against
a real denial-of-service class this decoder's own validation independently
confirmed -- `tshark` 4.2.2's own MMS dissector hits an internal recursion
assertion and aborts entirely on roughly 43 of 224 frames of genuine,
non-malicious traffic this decoder's own research captured. 18 of MMS's 78
confirmedServices get full field decoding (Tier 1) -- including, as of item
12's own completion, the seven file-transfer services IEC 61850's own
COMTRADE/disturbance-file-retrieval workflow rides on; the rest are named
with invokeID only, body shown as raw hex (Tier 2), the same two-tier
scoping precedent this codebase already applies to OPC UA's own service
dispatch.
Validated against three genuine real-world captures from
`ITI/ICS-Security-Tools` (one a full association with two independently-
confirmed malformed frames, two "bare MMS" -- the shape that caught a real
bug in this decoder's own first-pass bare-MMS structural gate, since 3 of
the 14 `MMSpdu` alternatives are primitive, not constructed, on the wire)
plus a 224-frame capture this project generated itself against a real,
independent open-source stack (`mz-automation/libiec61850`) -- 117 of 224
frames recognized as `mms`, zero parse warnings, zero parse errors, zero
crashes, and a real informationReport frame confirming this decoder's own
`Data`-value decode against an independent encoder byte-for-byte (see
`tests/real_captures/mms/ATTRIBUTION.md` for both structural-gate bugs this
validation pass found and fixed).

**MQTT (v3.1/v3.1.1/v5.0) and Sparkplug B support** is also now done: the
first protocol this tool decodes that isn't OT-specific on its own, but is
squarely in scope for how OT data reaches IT/cloud systems today, plus
Sparkplug B -- an OT/IIoT-focused MQTT topic and payload convention built on
Protocol Buffers -- decoded via a small, purpose-built, hand-rolled protobuf
wire-format reader rather than a general-purpose protobuf dependency
(consistent with this project's zero-required-dependency design). Every MQTT
Control Packet Type is decoded (CONNECT through AUTH), including all 27
MQTT5 Property Identifiers via one generic, table-driven decoder. Version
disambiguation for the three genuinely ambiguous packet types (SUBSCRIBE/
SUBACK/UNSUBSCRIBE) combines authoritative per-TCP-session CONNECT tracking
with an honestly-scoped fallback heuristic, documented as least reliable for
SUBACK specifically -- see PROTOCOL COVERAGE's MQTT section. This decoder's
own structural detection gate is honestly the weakest in the whole codebase
(weaker even than HART-IP's own documented weakest gate), so MQTT is
dispatched dead last in the TCP protocol-detection chain -- a real,
demonstrated design consequence, not a theoretical one: building this
feature's own synthetic test fixture surfaced two genuine collisions against
earlier-dispatched protocols' gates (a v5 CONNACK against Modbus/TCP's own
protocol-id==0 tell, and a SUBSCRIBE/UNSUBSCRIBE packet identifier against
HART-IP's own two-byte gate), both found and fixed, not just noted as
possible. Like this codebase's own OPC UA Identity Token decode, CONNECT's
cleartext Username/Password fields are decoded and shown deliberately, not
by oversight. Validated against a real Eclipse Paho MQTT 3.1 client session
(`pradeesi/MQTT-Wireshark-Capture`, two container formats confirmed to
decode byte-for-byte identically, plus a third file from the same source
found to be genuinely corrupt and correctly rejected with a clear error) --
that validation caught and fixed a real bug in this decoder's own
session-version-tracking logic, which originally only recognized
ProtocolLevel 4/5 CONNECTs, not the pre-OASIS MQTT 3.1 (level 3, "MQIsdp")
shape a real client in the wild still used (see
`tests/real_captures/mqtt/ATTRIBUTION.md` for the complete writeup). A real
Sparkplug B capture was specifically searched for and not found, so
Sparkplug B decoding itself remains validated only against this project's
own synthetic, hand-built protobuf fixture -- see LIMITATIONS.

### Protocols not covered at all

An honest orientation for "does it do X" -- well-known OT/ICS protocols
this tool decodes no part of, and why, as of this release. This is
separate from every still-open item above (all of which name a protocol
this tool DOES decode, at least partially); everything below is a protocol
with zero bytes of it decoded anywhere in this codebase.

- **PROFIBUS DP.** An RS-485 fieldbus, not Ethernet-based -- there is no
  IP/Ethernet framing to capture with a standard NIC at all, only dedicated
  fieldbus-tap hardware this project has no access to and so could not
  validate a decoder against even if one were written. The same structural
  category as ControlNet (see PROTOCOL COVERAGE's DeviceNet section, "Why
  not ControlNet too"): not a scope choice, a hard capture-availability
  wall.
- **CANopen.** The most plausible near-term candidate on this list.
  DeviceNet already rides raw CAN frames captured via SocketCAN
  (`LINKTYPE_CAN_SOCKETCAN`, see PROTOCOL COVERAGE's DeviceNet section) --
  `can_socketcan.hpp`/`.cpp` decode the pcap record and CAN frame header
  generically, and its own file header says outright that "any CAN
  application protocol's frames (DeviceNet, CANopen, J1939, or raw CAN
  traffic with no higher-layer protocol at all) would show up in a capture
  this same way." CANopen would reuse that exact link-layer plumbing
  unchanged; only a CANopen-specific message-group/object-dictionary
  decoder (the equivalent of `devicenet.cpp`) would need to be written. It
  just hasn't been built yet -- a real, reasonably scoped future roadmap
  item, not an exclusion.
- **Modbus RTU/ASCII (serial).** Not to be confused with Modbus/TCP, which
  this tool fully decodes (see PROTOCOL COVERAGE's Modbus/TCP section). The
  serial variants ride RS-232/RS-485 directly, with no equivalent of
  DeviceNet's SocketCAN situation -- there is no established pcap
  link-layer encoding for raw serial traffic this project could build
  against, and this project hasn't investigated any serial-to-pcap capture
  mechanism (a USB-serial sniffer's own vendor format, for instance) that
  might produce one. Unlike CANopen, there is currently no link-layer
  plumbing here to reuse at all.
- **PROFIBUS PA / HART's own 4-20mA analog signal.** Not a packet-capture
  question at all -- this is a physical/analog wire-level signal (current
  loop, or PROFIBUS PA's own bus-powered physical layer), with nothing that
  could ever appear in a pcap file. Distinct from HART-IP (the IP-routable
  gateway encapsulation of HART), which this tool fully decodes -- see
  PROTOCOL COVERAGE's HART-IP section.
- **ICCP/TASE.2 (IEC 60870-6, substation-to-control-center).** A plausible
  future candidate, not a trivial one: this project already decodes MMS in
  full (see PROTOCOL COVERAGE's IEC 61850 MMS section), and TASE.2 is built
  on top of MMS's own Session/Presentation/ACSE/MMS stack, but with its own
  distinct object model (bilateral tables, ICCP-specific object classes)
  that shares transport DNA with MMS, not application-layer semantics.
  Decoding it would be new work built on existing groundwork, not an
  extension of the existing MMS decoder.
- **OPC Classic (DA/HDA/AE, COM/DCOM-based).** Distinct from OPC UA, which
  this tool fully decodes (see PROTOCOL COVERAGE's OPC UA Binary section).
  OPC Classic's wire protocol is COM/DCOM -- MSRPC, a large, generic
  Windows RPC mechanism with no OT-specific structure of its own -- making
  this a substantially larger and less OT-focused undertaking than anything
  else on this list. Likely low priority for that reason.
- **Ethernet POWERLINK (EtherType `0x88AB`) and SERCOS III.** Real-time
  Ethernet motion-control protocols in the same general category as
  PROFINET RT and EtherCAT, both of which this tool already decodes (see
  PROTOCOL COVERAGE's PROFINET RT and EtherCAT sections). No structural
  obstacle here -- these simply haven't been reached yet.
- **WirelessHART.** The RF mesh variant of HART, not the IP-based one --
  distinct from HART-IP (see PROTOCOL COVERAGE's HART-IP section), which
  this tool fully decodes. Like PROFIBUS DP, this is not capturable via a
  standard NIC/pcap at all without dedicated radio-capture hardware.

## BUILDING

See [README.md](../README.md) for full Linux/Windows build instructions. In
short: CMake >= 3.16, a C++17 compiler, no *required* dependencies (CLI11 is
vendored under `third_party/`).

Live capture is the one optional dependency: CMake searches for `pcap.h` and
the libpcap library (Linux, via `find_path`/`find_library`) or the Npcap SDK
(Windows, via `NPCAP_SDK_DIR` or `C:/Npcap-SDK`) and, if found, compiles it
in and links it (`CONDUITSCOPE_HAVE_PCAP`); if not, the build proceeds exactly
as before with live capture simply unavailable at runtime. Pass
`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` to skip the search and guarantee a
dependency-free build regardless of what's installed on the build machine.
CMake's configure-time output states which happened either way (`conduitscope:
live capture ENABLED (found ...)` / `DISABLED (...)`).

## LICENSE

Apache-2.0. See [LICENSE](../LICENSE).
