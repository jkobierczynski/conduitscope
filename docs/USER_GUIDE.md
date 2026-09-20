# conduitscope(1) -- User Guide

This is the operational reference for running `conduitscope`: command
syntax, options, the policy file format, output formats, exit codes, and
worked examples. It assumes you already know *what* conduitscope is (see
the top-level [README.md](../README.md) for the project overview and
quick start).

Two companion documents cover material that got too large to stay in this
one:

- **[PROTOCOL_COVERAGE.md](PROTOCOL_COVERAGE.md)** -- the full per-protocol
  reference: what conduitscope recognizes on the wire, exactly what each
  decoder surfaces, and -- just as important for an audit -- how much
  confidence to place in each detection (a genuine multi-field structural
  match vs. a port-only fallback). Read this before citing a `decode`
  finding in an audit report.
- **[DEVELOPMENT.md](DEVELOPMENT.md)** -- how conduitscope itself is built:
  dispatch order and protocol-collision handling (docs/DEVELOPMENT.md's PROTOCOL DETECTION), the
  codebase architecture, the development roadmap, and engineering notes for
  anyone extending the tool rather than just running it.

This split happened because the single manual this used to be had grown
past 11,000 lines; if you're looking for something that isn't here, it's
almost certainly in one of those two.

## NAME

conduitscope -- decode Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP, IEC 61850 MMS (Manufacturing Message Specification, ISO 9506), EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP and cyclic real-time IO), IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, EtherCAT, BACnet/IP, HART-IP, and OPC UA Binary traffic from offline pcap captures

## SYNOPSIS

```
conduitscope [-q|--quiet] [--no-color|--color] [--log-file FILE] [--version] [-h|--help] <command> [command options]

conduitscope decode (-r FILE | -i INTERFACE) [-o FILE] [-f text|json|csv] [--protocol NAME]
                     [--modbus-port PORT]... [--dnp3-port PORT]... [--s7comm-port PORT]... [--iec104-port PORT]...
                     [--enip-port PORT]... [--enip-io-port PORT]... [--bacnet-port PORT]... [--hartip-port PORT]... [--opcua-port PORT]... [--mqtt-port PORT]... [--ffhse-port PORT]... [--remote-access-port PORT]... [--lateral-movement-port PORT]... [--enterprise-trust-port PORT]... [--wireless-backhaul-port PORT]... [--tunnel-vpn-port PORT]...
                     [--max-packets N] [--stats] [--strict]
                     [--filter BPF] [--duration SECONDS] [--snaplen BYTES] [--no-promiscuous]

conduitscope info -r FILE

conduitscope interfaces

conduitscope policy validate (-r FILE | -i INTERFACE) --policy FILE [-o FILE] [-f text|json] [--strict]
                              [--filter BPF] [--duration SECONDS] [--snaplen BYTES] [--no-promiscuous]

conduitscope inventory (-r FILE | -i INTERFACE) [-o FILE] [-f text|json] [--strict]
                        [--zone-prefix N] [--diagram FILE] [--diagram-format mermaid|dot] [--policy-out FILE]
                        [--filter BPF] [--duration SECONDS] [--snaplen BYTES] [--no-promiscuous]

conduitscope version
```

`-i/--interface`, `conduitscope interfaces`, and the `--filter`/`--duration`/
`--snaplen`/`--no-promiscuous` options are live capture: see LIVE CAPTURE below.
They require this build to have been compiled with libpcap (Linux) / the Npcap
SDK (Windows) found -- an optional, build-time-detected dependency, the one
exception to conduitscope's otherwise zero-dependency design (see BUILDING).

`--protocol NAME` restricts decoding to one protocol instead of the default
`auto`; see docs/PROTOCOL_COVERAGE.md below for the full, current list of valid
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
wasn't explicitly permitted. A third layer, `inventory`, runs the opposite
direction: point it at a capture with no policy file at all, and it infers
a first-draft zone/conduit model -- an asset list, a communication matrix,
and a proposed zone/conduit YAML file directly loadable by `policy
validate` -- closing the loop from passive discovery to active enforcement.
See POLICY FILE FORMAT below for the schema and LIMITATIONS for exactly
what this does and doesn't check.

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
| `-t, --time-format {e,epoch,r,relative,d,delta,a,absolute,ad,absolute-date}` | `e` | How to render each packet's timestamp. Mirrors tshark's own `-t` mnemonics rather than tcpdump's stacking `-t`/`-tt`/`-ttt` convention. See OUTPUT FORMATS' "Timestamps" subsection below. |
| `--time-offset {utc,local,+HH:MM,-HH:MM}` | `utc` | Timezone used to render `--time-format=absolute`/`absolute-date`; ignored by every other `--time-format` value. See OUTPUT FORMATS' "Timestamps" subsection below. |
| `--protocol NAME` | `auto` | Restrict decoding to one protocol. See docs/PROTOCOL_COVERAGE.md below for the full, current list of valid protocol names (one per subsection there). `auto` opportunistically tries OPC UA, EtherNet/IP, IEC 104, Modbus, DNP3, S7comm/COTP, S7comm-Plus, MMS, HART-IP, MQTT, and FF-HSE detection on every TCP payload (in that order -- FF-HSE last of all, even after MQTT, see docs/DEVELOPMENT.md's PROTOCOL DETECTION), CIP I/O, BACnet/IP, HART-IP, and FF-HSE detection on every UDP payload (FF-HSE last there too), PROFINET RT (DCP/cyclic) detection on every non-IPv4 Ethernet frame carrying EtherType `0x8892`, GOOSE detection on every non-IPv4 Ethernet frame carrying EtherType `0x88B8`, Sampled Values detection on every non-IPv4 Ethernet frame carrying EtherType `0x88BA`, EtherCAT detection on every non-IPv4 Ethernet frame carrying EtherType `0x88A4`, regardless of port, and Spanning Tree Protocol (STP/RSTP/MSTP) detection on every classic IEEE 802.3 length-framed Ethernet frame whose LLC header is DSAP=SSAP=`0x42` -- a structurally separate dispatch path from every EtherType-keyed protocol above, so there's no ordering/collision question between them (see docs/DEVELOPMENT.md's PROTOCOL DETECTION below). `enip` covers both EtherNet/IP explicit messaging (TCP) and CIP I/O implicit messaging (UDP). `mms` is IEC 61850 MMS (Manufacturing Message Specification, ISO 9506) -- shares S7comm's exact TPKT/COTP transport and TCP port 102, but is a distinct application protocol; see `--s7comm-port` below and docs/PROTOCOL_COVERAGE.md's MMS section. `s7comm-plus` is S7comm-Plus (TIA Portal / S7-1200/1500) -- shares the same TPKT/COTP transport and TCP port 102, disambiguated by its own protocol id byte; see `--s7comm-port` below and docs/PROTOCOL_COVERAGE.md's S7comm-Plus section. `mqtt` is MQTT (v3.1/v3.1.1/v5.0) plus Sparkplug B -- see `--mqtt-port` below and docs/PROTOCOL_COVERAGE.md's MQTT section. `profinet` covers both DCP and cyclic real-time IO. `sv` is IEC 61850-9-2 Sampled Values. `ethercat` is EtherCAT. `bacnet` is BACnet/IP. `hartip` is HART-IP (covers both UDP and TCP). `opcua` is OPC UA Binary (UA-TCP/Secure Conversation, TCP only). `ff-hse` is FOUNDATION Fieldbus HSE (covers FDA/SM/FMS/LAN Redundancy, on both TCP and UDP) -- see `--ffhse-port` below and docs/PROTOCOL_COVERAGE.md's FOUNDATION Fieldbus HSE section. `stp` is Spanning Tree Protocol (STP/RSTP/MSTP) -- no port option, matching GOOSE/SV/EtherCAT/PROFINET's own no-port precedent for a protocol with no port at all; see docs/PROTOCOL_COVERAGE.md's Spanning Tree Protocol section. `devicenet` is DeviceNet (CAN-bus CIP) -- no port option either, the same no-port precedent, but unlike every other value in this list it isn't reached through Ethernet at all: it's gated on the capture's own pcap link type being `LINKTYPE_CAN_SOCKETCAN` (227, standard Linux SocketCAN capture framing -- what `candump -l`/`tcpdump -i can0`/Wireshark itself write capturing a CAN bus), checked before any protocol filter, so `--protocol devicenet` against an ordinary Ethernet-linktype capture simply decodes nothing (every packet still parses at the link layer, just with no application-layer match) rather than erroring; see docs/PROTOCOL_COVERAGE.md's DeviceNet section. `remote-access` covers Tier 1 of the "IT protocols an OT auditor flags" family (RDP/VNC/TeamViewer/AnyDesk/Zoom, each its own `protocol` value even under this one filter name) -- see `--remote-access-port` below and docs/PROTOCOL_COVERAGE.md's "Tier 1 remote-access protocol recognition" section. `lateral-movement` covers Tier 2 of the same family (SMB/SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP, again each its own `protocol` value under this one filter name) -- see `--lateral-movement-port` below and docs/PROTOCOL_COVERAGE.md's "Tier 2 lateral-movement protocol recognition" section. `enterprise-trust` covers the six port-based protocols of Tier 3 of the same family (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+, again each its own `protocol` value under this one filter name) -- see `--enterprise-trust-port` below and docs/PROTOCOL_COVERAGE.md's "Tier 3 enterprise-trust-boundary protocol recognition" section. `eapol` is Tier 3's seventh protocol, IEEE 802.1X/EAPOL -- EtherType-keyed, no port at all, so it has its own dedicated filter value rather than sharing `enterprise-trust`, the same split GOOSE/SV/EtherCAT/PROFINET's own EtherType-keyed filters already have from every port-based one; no port option exists for it. `wireless-backhaul` covers the five port-based protocols of Tier 4 of the same family (CAPWAP control/data, LWAPP control/data, GTP-U, again each its own `protocol` value under this one filter name) -- see `--wireless-backhaul-port` below and docs/PROTOCOL_COVERAGE.md's "Tier 4 wireless-backhaul-and-cellular protocol recognition" section. `pppoe` is Tier 4's sixth protocol, PPPoE -- EtherType-keyed, no port at all, the same split `eapol` has from `enterprise-trust`; no port option exists for it either. `tunnel-vpn` covers the fourteen port/IP-protocol-number-based protocols of Tier 5 of the same family (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve, WireGuard, OpenVPN, dtls-tunnel, STT, again each its own `protocol` value under this one filter name) -- see `--tunnel-vpn-port` below and docs/PROTOCOL_COVERAGE.md's "Tier 5 generic tunnel/VPN encapsulation recognition" section. `mpls` is Tier 5's sixteenth protocol, MPLS -- EtherType-keyed, no port at all, the same split `eapol`/`pppoe` have from `enterprise-trust`/`wireless-backhaul`; no port option exists for it either. |
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
| `--stats` | off | Print an aggregate summary (protocol counts, a cross-protocol TCP-flow direction-tier breakdown, Modbus function-code histogram, exception count, capture time span) instead of one line per packet. Ignores `--format`. |
| `--strict` | off | Abort with a nonzero exit status on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a per-packet warning and continuing. Does not affect Modbus/DNP3-level ambiguity, which is always handled by heuristic + note rather than error. |
| `--no-vlan` | off (i.e. VLAN ID display on by default) | Disable display of the 802.1Q VLAN ID for a VLAN-tagged packet. See OUTPUT FORMATS below. |
| `--no-direction` | off (i.e. TCP flow direction display on by default) | Disable display of per-packet TCP flow direction (client/server determination and which tier decided it -- handshake/content/port-heuristic). Does not affect `decode --stats`'s own direction-tier breakdown, which has no display toggles of its own (the same way `--no-vlan`/`--no-oui` don't affect it either). See OUTPUT FORMATS below. |
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
| `--no-oui` | off (i.e. OUI/MAC-vendor resolution on by default) | Same meaning as `decode --no-oui`: disable OUI (MAC vendor) resolution against the built-in table, applied to the report's flow MAC addresses. See OUTPUT FORMATS' "Name resolution" subsection. |
| `--resolve` | off | Same meaning as `decode --resolve`: enable hostname resolution from an explicitly-supplied `--hosts` file, applied to the report's flow IP addresses. **Never performs live DNS** -- file-only. |
| `--hosts FILE` | *(none)* | Same meaning as `decode --hosts`: Unix `/etc/hosts`-style file to resolve IP addresses from, for `--resolve`. Must exist. |
| `--nn` | off (i.e. service-name resolution on by default) | Same meaning as `decode --nn`: disable service name (port -> name) resolution, applied to the report's flow server port. |
| `--services FILE` | *(none)* | Same meaning as `decode --services`: Unix `/etc/services`-style file to supplement/override the built-in port->service-name table. Must exist. |

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
  [1] 192.168.1.50 -> 192.168.1.10:502 (modbus)  (modbus, 3 packet(s))
      zones: hmi_zone -> plc_zone, matched conduit "HMI polls PLC via Modbus"
      direction: port-heuristic
      mac: 00:0c:29:11:22:33 (VMware) -> 00:0c:29:aa:bb:cc (VMware)

Conduits never exercised by this capture (2):
  - HMI polls PLC via DNP3
  - Engineering station S7comm
```

The `(modbus)` after `:502` and the `(VMware)` vendor names come from the
same OUI/service-name resolution `decode` has, on by default -- see OUTPUT
FORMATS' "Name resolution" subsection and the option table above. Add
`--resolve --hosts FILE` to also annotate `192.168.1.50`/`192.168.1.10`
with a hostname, exactly as `decode` would.

The `direction:` line is `port-heuristic` here because this sample capture
starts mid-session (no SYN/SYN-ACK was ever captured for it) -- see
LIMITATIONS below for exactly what that means and when it can be wrong, and
docs/DEVELOPMENT.md's ROADMAP item 19 for the full three-tier design
record. A flow whose handshake WAS captured shows `direction: handshake`
instead.

### `inventory` -- passive OT asset inventory: pcap -> zones and conduits

```
conduitscope inventory (-r FILE | -i INTERFACE) [options]
```

Runs the opposite direction from `policy validate`: instead of checking
observed traffic against a hand-written zone/conduit policy, `inventory`
infers a first-draft one from a capture. See docs/DEVELOPMENT.md's ROADMAP item 17 for the full
rationale (prior art, and what this first pass deliberately does and
doesn't cover).

| Option | Default | Description |
|---|---|---|
| `-r, --read FILE` | *(required unless `-i` given)* | Input capture file. Must exist; classic pcap or pcapng, auto-detected. Mutually exclusive with `-i`. |
| `-i, --interface NAME` | *(required unless `-r` given)* | Build the inventory from live traffic on this network interface instead of reading a file -- see LIVE CAPTURE below. Requires libpcap/Npcap support to have been built in. Mutually exclusive with `-r`. |
| `--filter BPF` | *(none)* | BPF capture filter (tcpdump syntax). Only meaningful with `-i`. |
| `--duration SECONDS` | `0` (unlimited) | Stop a live capture (`-i`) after this many seconds; `0` means rely on Ctrl+C instead. |
| `--snaplen BYTES` | `65535` | Maximum bytes captured per packet with `-i`. |
| `--no-promiscuous` | off (i.e. promiscuous by default) | Same meaning as `decode --no-promiscuous`. |
| `-o, --output FILE` | stdout | Write the report here instead of stdout. |
| `-f, --format {text,json}` | `text` | Report format. `text` is the human-readable report shown below; `json` mirrors its structure -- see JSON OUTPUT FIELDS-style output below. |
| `--strict` | off | Same meaning as `decode --strict`: abort on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a warning and continuing. |
| `--zone-prefix N` | `24` | CIDR prefix length (`0`-`32`) inferred zones are grouped by: every observed asset IP is masked to this many bits, and one zone is emitted per distinct resulting network. Narrow it (e.g. `16`) to lump a wider address range into fewer, bigger zones; widen it (e.g. `28`) for finer-grained, smaller zones. |
| `--diagram FILE` | *(none)* | Also write a zone/conduit diagram to this file. Format controlled by `--diagram-format`. |
| `--diagram-format {mermaid,dot}` | `mermaid` | Diagram syntax for `--diagram`: a Mermaid `graph LR` block, or a Graphviz `.dot` `digraph`. |
| `--policy-out FILE` | *(none)* | Also write the inferred zone/conduit model as a `policy`-format YAML file, directly loadable by `policy validate --policy` -- closing the loop: discover, then enforce. See "Closing the loop" below. |
| `--no-oui` | off (i.e. OUI/MAC-vendor resolution on by default) | Same meaning as `decode --no-oui`, applied to the report's asset/edge MAC addresses. |
| `--resolve` | off | Same meaning as `decode --resolve`: enable hostname resolution from an explicitly-supplied `--hosts` file. **Never performs live DNS** -- file-only. |
| `--hosts FILE` | *(none)* | Same meaning as `decode --hosts`: Unix `/etc/hosts`-style file to resolve IP addresses from, for `--resolve`. Must exist. |
| `--nn` | off (i.e. service-name resolution on by default) | Same meaning as `decode --nn`: disable service name (port -> name) resolution, applied to each edge's server port. |
| `--services FILE` | *(none)* | Same meaning as `decode --services`: Unix `/etc/services`-style file to supplement/override the built-in port->service-name table. Must exist. |

Like `policy validate`, `inventory` decodes the capture exactly as `decode`
would and does not change or duplicate any decoding logic -- see
`AssetInventoryEngine` (`asset_inventory.hpp`/`.cpp`), built on the same
already-public `DecodedPacket` output. Ten protocols are counted here --
the SAME ten `PolicyEngine::observe` itself evaluates over TCP for
`policy validate`: **Modbus**, **DNP3**, **S7comm** (a COTP-only session
with no S7comm payload still counts, the same "cotp folds into s7comm"
convention `PolicyEngine::observe` uses), **EtherNet/IP** (both explicit
messaging over TCP and CIP I/O implicit messaging over UDP/2222),
**BACnet/IP**, **IEC 104**, **HART-IP**, **OPC UA**, **MMS**, **MQTT**, and
**FF-HSE**. Every other packet -- including every other protocol this
project decodes -- is counted only in the report's `skipped_packets` total,
never as an asset or an edge.

Two of those ten -- **HART-IP** and **FF-HSE** -- are counted here ONLY
when carried over TCP, even though both can also appear over UDP (HART-IP
conventionally; FF-HSE almost always, in real deployments). `policy
validate` only ever evaluates TCP flows, so a conduit inferred from a UDP
HART-IP or FF-HSE packet could never actually be checked -- unlike BACnet
and CIP I/O (both UDP-only, still counted, with an explicit "cannot be
exercised" note baked into the generated policy YAML, see "Closing the
loop" below), HART-IP/FF-HSE traffic seen over UDP is simply skipped here,
folding into `skipped_packets` like any other unrecognized packet. In
practice this means FF-HSE will rarely, if ever, show up in an inventory
report at all, since real FF-HSE traffic is UDP.

For each recognized packet, `inventory` determines which side is the
client (initiator) and which is the server, exactly as `PolicyEngine::
observe` does for every TCP-based protocol here (SYN/SYN-ACK, falling back
to a known-port heuristic) -- except for BACnet, whose client and server
both conventionally listen on the same UDP port (47808), so the usual
known-port-vs-ephemeral-port heuristic can't tell them apart at all;
instead, the request/response APDU type decides (a Confirmed-Request or
Unconfirmed-Request's source is the client; a Simple-ACK/Complex-ACK/
Segment-ACK/Error/Reject/Abort's *destination* is). A broadcast or
multicast destination (`255.255.255.255`, `224.0.0.0/4`, or any address
ending in `.255` -- a pragmatic, non-subnet-mask-aware heuristic) is never
treated as an asset or edge endpoint, since BACnet's own Who-Is/I-Am
discovery traffic is routinely broadcast and would otherwise pollute the
asset list with the broadcast address itself.

Every observed IP becomes one **asset**: its MAC (and OUI vendor guess,
resolver permitting), every protocol it was seen speaking, whether it was
ever a client, ever a server, or both, and a packet count. Every distinct
`(protocol, client, server, server port)` tuple becomes one **edge** --
deliberately coarser than `policy validate`'s own per-TCP-session
`FlowReport`, since an inventory answers "does X talk to Y over protocol
P," not "how many sessions did X open to Y." Every observed asset IP is
then masked to `--zone-prefix` bits and grouped into a **zone** (one per
distinct resulting network, named `zone_<network>_<prefix>`), and every
edge whose client and server zones (and protocol and port) form a distinct
combination becomes one inferred **conduit** -- unlike `policy validate`'s
report, there is no "declared but never exercised" concept here: only
conduits actually observed on the wire are ever listed, since there is no
hand-written policy to compare against.

Example, against a synthetic two-subnet capture (`tests/sample_inventory.pcap`,
which mixes an in-zone Modbus/BACnet pair with three engineering-workstation
flows reaching across from a separate `/24`, specifically to exercise
cross-zone conduit inference -- see that fixture's own comment in
`tools/make_sample_pcap.py`):

```sh
$ conduitscope inventory -r tests/sample_inventory.pcap
OT asset inventory
  capture: tests/sample_inventory.pcap
  scope:   Modbus, DNP3, S7comm, EtherNet/IP, BACnet/IP, IEC 104, HART-IP (TCP only),
           OPC UA, MMS, and MQTT -- plus FF-HSE (TCP only; rarely applicable, since
           FF-HSE is fundamentally a UDP protocol) -- see docs/MANUAL.md's ROADMAP item 17

9 asset(s) observed, 14 total packet(s) in capture, 0 skipped (not one of the ten recognized protocols, no IPv4 layer, or HART-IP/FF-HSE seen over UDP)

ASSETS (9):
  10.0.5.21  00:0c:29:de:ad:01 (VMware)  [client]  dnp3, s7comm  (6 packet(s))
  10.0.5.22  00:0c:29:de:ad:02 (VMware)  [client]  enip  (4 packet(s))
  192.168.1.10  00:0c:29:aa:bb:cc (VMware)  [server]  modbus  (2 packet(s))
  ...

COMMUNICATIONS (5):
  192.168.1.50 -> 192.168.1.10:502 (modbus)  modbus  [Read Holding Registers]  (2 packet(s), direction: port-heuristic)
  10.0.5.21 -> 192.168.1.11:20000 (dnp3)  dnp3  [Read, Response]  (2 packet(s), direction: port-heuristic)
  ...
  192.168.1.14 -> 192.168.1.15:47808  bacnet  [readProperty]  (2 packet(s), direction: content)

INFERRED ZONES (2, grouped by observed /24 subnet):
  zone_10_0_5_0_24 (10.0.5.0/24): 10.0.5.21, 10.0.5.22
  zone_192_168_1_0_24 (192.168.1.0/24): 192.168.1.10, 192.168.1.11, 192.168.1.12, 192.168.1.14, 192.168.1.15, 192.168.1.16, 192.168.1.50

INFERRED CONDUITS (5):
  zone_10_0_5_0_24 -> zone_192_168_1_0_24  (dnp3/20000)  1 edge(s), 2 packet(s)
  zone_10_0_5_0_24 -> zone_192_168_1_0_24  (enip/44818)  1 edge(s), 4 packet(s)
  zone_10_0_5_0_24 -> zone_192_168_1_0_24  (s7comm/102)  1 edge(s), 4 packet(s)
  zone_192_168_1_0_24 -> zone_192_168_1_0_24  (bacnet/47808)  1 edge(s), 2 packet(s)
  zone_192_168_1_0_24 -> zone_192_168_1_0_24  (modbus/502)  1 edge(s), 2 packet(s)
```

Each COMMUNICATIONS line's trailing `direction: <tier>` is the same
three-tier `direction_source` `policy validate`'s own report carries (see
its own JSON report schema section above), with one addition: `content`
appears here too, for the BACnet edge -- BACnet's client and server both
conventionally listen on the same UDP port, so its direction is decided by
APDU type (request vs. response) instead of a port guess, unlike every
other edge above (`policy validate` never evaluates BACnet at all -- UDP-only,
see LIMITATIONS -- so `content` never appears in *its* report). See
docs/DEVELOPMENT.md's ROADMAP item 19 for the full three-tier design
record and the industry precedent researched before adding this field.

#### Closing the loop

`--policy-out` writes the inferred zones/conduits above as a `policy`-format
YAML file -- headed by a comment block flagging it as an auto-generated,
first-draft policy that should be reviewed (especially whether the inferred
groupings reflect *intended* segmentation, not just what happened to be
captured) before being used to gate real `policy validate` runs. It is
directly loadable:

```sh
$ conduitscope inventory -r tests/sample_inventory.pcap --policy-out /tmp/inferred.yaml -o /dev/null
$ conduitscope policy validate -r tests/sample_inventory.pcap --policy /tmp/inferred.yaml
Result: COMPLIANT
...
Conduits never exercised by this capture (1):
  - zone_192_168_1_0_24 -> zone_192_168_1_0_24 (bacnet/47808)
```

Every TCP-based conduit round-trips cleanly. The one UDP-based conduit here
(BACnet/IP) parses and loads into the policy file fine, but `policy
validate` only ever evaluates TCP flows (see LIMITATIONS), so a UDP-based
inferred conduit always shows up as "never exercised" no matter how much
matching UDP traffic the capture actually has -- not a bug in either
command, just the current, documented edge of `policy validate`'s own
scope (see docs/DEVELOPMENT.md's ROADMAP item 9).

If the capture carries no traffic from any of the ten recognized
protocols at all, there is nothing to infer even one zone from --
`--policy-out`'s file then contains only explanatory comments, no
`zones:`/`conduits:` keys at all (deliberately not a validly-loadable
policy file), and `inventory` prints a note to that effect.

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
    networks:                               # an IPv4 zone --
      - <IPv4 address or CIDR block>        # for modbus/dnp3/s7comm/iec104/enip/
      - <...>                               # bacnet/hartip/opcua/mms/mqtt/ffhse
  <zone name>:
    networks: [<address or CIDR>, <...>]    # a flow-style list works too
  <zone name>:
    vlans: [<VLAN ID 1-4094>, <...>]        # a VLAN zone instead --
                                             # for profinet/goose/sv/ethercat
  <zone name>:
    vlan: <VLAN ID>                         # singular alias, for a one-VLAN zone

conduits:
  - name: "<conduit name>"
    description: "<optional free text>"
    from: <zone name or [zone name, ...]>
    to: <zone name or [zone name, ...]>     # VLAN-zone conduit: must be the exact
                                             # same zone(s) as 'from' -- see "Conduits" below
    protocols: [<modbus | dnp3 | s7comm | iec104 | enip | bacnet | hartip | opcua | mms | mqtt | ffhse | profinet | goose | sv | ethercat | any>, <...>]
    ports: [<port>, <...>]                  # omit entirely to mean "any port"; IPv4-zone conduits only
    bidirectional: <true | false>           # default: false; IPv4-zone conduits only
    functions: [<function/service name>, <...>]  # optional; see "Function-level restrictions" below; IPv4-zone conduits only
```

**Zones.** Each zone name maps to EITHER one or more IPv4 CIDR blocks
(`10.10.10.0/24`) or bare addresses (`10.10.10.5`, treated as `/32`), under
`networks`, OR one or more VLAN IDs (`1`-`4094`), under `vlans` (singular
alias `vlan`, for a one-VLAN zone) -- never both on the same zone, and never
neither. Which kind a zone is drives which protocols a conduit referencing it
can name (see "Conduits" below): `networks` zones classify
modbus/dnp3/s7comm/iec104/enip/bacnet/hartip/opcua/mms/mqtt/ffhse traffic by
IPv4 address, the way this file always has; `vlans` zones classify
profinet/goose/sv/ethercat traffic -- the four protocols with no IP layer at
all -- by which VLAN the frame was tagged with instead (docs/DEVELOPMENT.md's ROADMAP item 15; see
"Addressing scope" below for the full rationale). At least one zone is
required. **No two zones of the same kind may claim the same address or
VLAN** -- `policy validate` needs to say definitively which single zone a
packet belongs to, so overlap within a kind is rejected at load time, not
silently resolved by declaration order (an IPv4 zone and a VLAN zone can
never overlap with each other, having no addressing scheme in common, so
only same-kind pairs are checked). An address or VLAN matching no declared
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
uses: `modbus`, `dnp3`, `s7comm`, `iec104`, `enip`, `bacnet`, `hartip`,
`opcua`, `mms`, `mqtt`, `ffhse`, `profinet`, `goose`, `sv`, `ethercat`, plus
the wildcard `any` (docs/DEVELOPMENT.md's ROADMAP item 14 widened this from the original six --
`modbus`/`dnp3`/`s7comm`/`iec104`/`enip`/`any` -- to name every TCP-capable
protocol `decode` recognizes individually; item 15 then added the four
raw-Ethernet, no-IP-layer protocols -- `profinet`/`goose`/`sv`/`ethercat` --
alongside the new VLAN-zone model below). Every zone a conduit references,
on either side, must be the same kind -- a conduit can't mix an IPv4 zone
and a VLAN zone, since there's no shared addressing scheme to classify a
packet against. That kind, in turn, restricts which protocol names the
conduit can use: `profinet`/`goose`/`sv`/`ethercat` (or `any`) only on a
conduit whose zones are all VLAN zones, and every other protocol name (or
`any`) only on a conduit whose zones are all IPv4 zones -- naming a TCP
protocol on a VLAN-zone conduit, or a VLAN-only protocol on an IPv4-zone
conduit, is a load-time `PolicyError` either way (see "Validation errors"
below). A COTP session
that never carries a full S7comm message (e.g. only a connection
request/confirm was captured) still counts as `s7comm` traffic for matching
purposes -- see docs/PROTOCOL_COVERAGE.md's S7comm/COTP section for why a "cotp"-
tagged packet and an "s7comm"-tagged one are the same conduit on the wire.
`enip` here only ever means EtherNet/IP explicit messaging (TCP 44818):
conduits are TCP-only (see LIMITATIONS), so there is currently no way to
write a conduit matching CIP I/O (implicit messaging, UDP 2222) traffic,
even though `decode` now decodes it -- see docs/DEVELOPMENT.md's ROADMAP. `bacnet` is the one
name among the newly-widened six that can never actually match real
traffic today for the same TCP-only reason: this decoder only ever
recognizes BACnet/IP over UDP (see decoder.cpp), so a `bacnet` conduit
parses and validates fine but is never exercised by `policy validate` --
see "Addressing scope" below. The other five newly-widened names
(`hartip`, `opcua`, `mms`, `mqtt`, `ffhse`) DO match real TCP traffic --
`hartip` specifically only its TCP form, since HART-IP also has a UDP
form this engine doesn't evaluate (see "Addressing scope" below), and
`mms` and `s7comm` share the same TCP port (102) but are still matched as
two entirely separate conduit protocols, one per flow's own actually-
decoded `protocol` tag, never conflated the way "cotp" folds into
`s7comm` above.

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
`from`). None of this applies to a VLAN-zone conduit (see next paragraph):
there is no client/server session to have a direction at all.

**VLAN-zone conduits mean something different.** A single raw-Ethernet
PROFINET RT/GOOSE/SV/EtherCAT frame carries at most one 802.1Q VLAN tag --
unlike a TCP flow, there's no separate "source VLAN" and "destination VLAN"
the way there's a client IP and a server IP. So a VLAN-zone conduit's
`from` and `to` are required to name the **exact same set** of VLAN
zone(s) -- violating this is a load-time `PolicyError` (see "Validation
errors" below). Its meaning is "this protocol is permitted on this VLAN
zone," not a directional flow between two zones. Following from that,
three fields that only make sense for a directional, session-based TCP
flow are rejected outright on a VLAN-zone conduit, also as load-time
errors: `ports` (profinet/goose/sv/ethercat have no TCP/UDP layer at all),
`bidirectional: true` (there's no client/server session to reverse -- `to`
already equals `from`), and `functions`/`function` (these four protocols
have no per-flow function/service name this engine tracks yet).

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

**Worked example, VLAN zones.** `tests/policies/vlan_zone_single_segment.yaml`
declares one VLAN zone (`ot_vlan`, VLAN 100) and one conduit permitting every
raw-Ethernet OT protocol on it. Matched against
`tests/sample_vlan_zones.pcap` (four flows tagged VLAN 100, one GOOSE flow
tagged VLAN 200, and one untagged EtherCAT flow):

```sh
$ conduitscope policy validate -r tests/sample_vlan_zones.pcap --policy tests/policies/vlan_zone_single_segment.yaml
Zone/conduit policy validation
  capture: tests/sample_vlan_zones.pcap
  policy:  tests/policies/vlan_zone_single_segment.yaml (1 zone(s), 1 conduit(s))

Result: NON-COMPLIANT (0 violation(s), 2 unclassified flow(s))

Flows evaluated: 0 (0 allowed, 0 violation(s), 0 unclassified)
  6 total packet(s) in capture, 0 skipped (non-TCP/non-IP)
...
Ethernet flows evaluated: 6 (4 allowed, 0 violation(s), 2 unclassified)
  PROFINET RT/GOOSE/Sampled Values/EtherCAT traffic, classified by VLAN zone -- see docs/MANUAL.md's POLICY FILE FORMAT section

ETHERNET UNCLASSIFIED TRAFFIC (2):
  [1] 00:0c:29:aa:11:22 <-> 00:0c:29:bb:33:44  (goose, 1 packet(s))
      vlan: 200, zone: unclassified
      no declared VLAN zone contains VLAN 200
  [2] 00:0c:29:cc:55:66 <-> 00:0c:29:dd:77:88  (ethercat, 1 packet(s))
      vlan: (untagged), zone: unclassified
      frame carries no 802.1Q VLAN tag at all

ETHERNET ALLOWED (4):
  [1] 00:0c:29:11:22:33 <-> 00:0c:29:aa:bb:cc  (profinet, 1 packet(s))
      vlan: 100, zone: ot_vlan, matched conduit "OT protocols permitted on ot_vlan"
  ...
```

Note the two distinct Ethernet flow sections -- separate from `Flows
evaluated`/`VIOLATIONS`/`UNCLASSIFIED TRAFFIC`/`ALLOWED` above them, which
stay IPv4-zone-only -- and that the VLAN-200 GOOSE traffic and the untagged
EtherCAT traffic are both `Unclassified`, for two different reasons: no
zone covers VLAN 200 at all, versus no VLAN tag to check membership on in
the first place. `tests/policies/vlan_zone_mixed_results.yaml` adds a
second VLAN zone (`office_vlan`, VLAN 200) with its own conduit that
deliberately excludes `goose`, turning that same VLAN-200 traffic into a
`Violation` ("no conduit permits goose traffic on VLAN zone 'office_vlan'")
instead of `Unclassified` -- the "zone exists but no conduit covers this
protocol" case, distinguished from "no zone matches this VLAN at all."

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

**Only five protocols have a known-function table so far.** `functions`
only actually validates against `modbus`, `dnp3`, `s7comm`, `iec104`, and
`enip` -- the five protocols `protocols` originally supported. The six
protocols `protocols` was more recently widened to accept (`bacnet`,
`hartip`, `opcua`, `mms`, `mqtt`, `ffhse` -- see docs/DEVELOPMENT.md's ROADMAP item 14) don't
have one yet, so `functions` on a conduit resolving to one of them is
rejected outright at load time, rather than silently rejecting every entry
one at a time against an empty table:

```
error: policy.yaml:N: conduit '<name>': 'functions' is not yet supported for protocol
'opcua' -- only modbus, dnp3, s7comm, iec104, and enip have a known
function/service name table so far (see docs/DEVELOPMENT.md's ROADMAP); write the conduit without 'functions'
for now
```

Traffic on one of these six protocols is still fully usable in an
unrestricted (no `functions`) conduit, and (for the five of them that
actually reach the policy engine -- see "Addressing scope" below for why
`bacnet` never does) its function/service name is still folded into
`FlowReport::observed_functions` for reporting -- see
`PolicyEngine::observe`'s own comment and `hartip_message_type`/
`opcua_service_name`/`mms_service_name`/`mqtt_packet_type_name`/
`ffhse_message_name` for exactly which field each contributes.

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
- a zone declaring both `networks` and `vlans` (a zone is either an IPv4
  zone or a VLAN zone, never both), or neither
- a zone with no `networks`, or a network that isn't a valid IPv4
  address/CIDR block
- a zone with no `vlans`, or a VLAN ID outside `[1, 4094]` (VID 0 is
  reserved for priority-tagged, non-VLAN-member frames; 4095 is reserved
  outright)
- two zones of the same kind whose networks, or VLANs, overlap (an IPv4
  zone and a VLAN zone can never overlap with each other)
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
- a conduit protocol outside `{modbus, dnp3, s7comm, iec104, enip, bacnet,
  hartip, opcua, mms, mqtt, ffhse, profinet, goose, sv, ethercat, any}`
  (docs/DEVELOPMENT.md's ROADMAP items 14 and 15)
- a conduit's `from`/`to` referencing both an IPv4 zone and a VLAN zone
  (every zone a conduit references must be the same kind -- docs/DEVELOPMENT.md's ROADMAP item 15)
- a conduit naming a TCP/IP protocol (e.g. `modbus`) while its zones are
  VLAN zones, or naming a VLAN-only protocol (`profinet`/`goose`/`sv`/
  `ethercat`) while its zones are IPv4 zones (docs/DEVELOPMENT.md's ROADMAP item 15)
- a VLAN-zone conduit whose `from` and `to` don't name the exact same set
  of VLAN zone(s) (docs/DEVELOPMENT.md's ROADMAP item 15 -- see "Conduits" above for why)
- a VLAN-zone conduit giving `ports`, `bidirectional: true`, or
  `functions`/`function` -- none of these three has a meaning on a
  VLAN-zone conduit (docs/DEVELOPMENT.md's ROADMAP item 15 -- see "Conduits" above)
- a conduit port outside `[1, 65535]`
- a conduit's `bidirectional` value that isn't a recognizable boolean
  (`true`/`false`/`yes`/`no`)
- a conduit's `functions`/`function` given while `protocols`/`protocol`
  resolves to anything other than exactly one concrete protocol (i.e. it's
  `any`, or a list of more than one) -- see "Function-level restrictions"
  above
- a conduit's `functions`/`function` given for `bacnet`, `hartip`, `opcua`,
  `mms`, `mqtt`, or `ffhse` -- none of these six has a known function/
  service name table yet (only `modbus`, `dnp3`, `s7comm`, `iec104`, and
  `enip` do), so the error says which protocol and that `functions` isn't
  supported for it yet rather than silently rejecting every entry against
  an empty table -- see "Function-level restrictions" above
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
      "is_vlan_conduit": false,
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
      "client_mac": "00:0c:29:11:22:33",
      "server_mac": "00:0c:29:aa:bb:cc",
      "client_mac_vendor": "VMware",
      "server_mac_vendor": "VMware",
      "server_port": 502,
      "server_port_service": "modbus",
      "client_zone": "hmi_zone",
      "server_zone": "plc_zone",
      "protocols": ["modbus"],
      "observed_functions": ["Read Holding Registers"],
      "packet_count": 3,
      "verdict": "allowed",
      "matched_conduit": "HMI polls PLC via Modbus",
      "reason": null,
      "direction_source": "handshake"
    }
  ],
  "ethernet_flows": [],
  "unexercised_conduits": []
}
```

`verdict` is one of `"allowed"`, `"violation"`, `"unclassified"`.
`matched_conduit` is only non-`null` when `verdict` is `"allowed"`; `reason`
is only non-`null` otherwise (a short, human-readable explanation, the same
text the `text` report shows). Same for `ethernet_flows[]`'s own `verdict`/
`matched_conduit`/`reason` below.

**`direction_source`** (per flow, appended last -- docs/DEVELOPMENT.md's
ROADMAP item 19) -- which tier decided `client_ip`/`server_ip` above:
`"handshake"` (a SYN and matching SYN-ACK were both observed for this flow
-- authoritative) or `"port-heuristic"` (no handshake was captured, so a
known-service-port/lower-port-number guess was used instead, which CAN be
wrong -- see LIMITATIONS' own discussion of exactly when). Never
`"content"` here -- that tier only applies to BACnet, which `policy
validate` never evaluates at all (UDP-only, see "Addressing scope" below).
`ethernet_flows[]` has no `direction_source` of its own: those protocols
have no client/server concept to begin with (see its own comment just
below).

**Resolver annotations** (`--no-oui`/`--resolve`/`--hosts`/`--nn`/
`--services` -- see the option table above and OUTPUT FORMATS' "Name
resolution" subsection): `client_mac`/`server_mac` are a base-value
addition, present as a string whenever this flow's link type is Ethernet
(`null` only for a non-Ethernet-linktype capture, e.g. raw IP or a Linux
"cooked capture"), independent of whether OUI resolution is even enabled.
`client_mac_vendor`/`server_mac_vendor` (OUI lookup), `client_hostname`/
`server_hostname` (hostname lookup -- absent above since `--resolve` wasn't
given), and `server_port_service` (service-name lookup; `FlowReport` only
ever carries the server's port, not the client's -- see its own comment in
`policy_engine.hpp`) are each OMITTED ENTIRELY, never emitted as `null`, on
a lookup miss or a
disabled lookup (`--no-oui`/`--nn`, or `--resolve` with no matching
`--hosts` entry). Same convention `decode`'s own JSON output uses for its
`src_mac_vendor`/`dst_mac_vendor`/`src_hostname`/`dst_hostname`/
`src_port_service`/`dst_port_service` fields.

**`is_vlan_conduit`** (per conduit, docs/DEVELOPMENT.md's ROADMAP item 15) -- `true` when every
zone this conduit references is a VLAN zone, `false` when every zone is an
IPv4 zone (a conduit can never mix the two -- see "Conduits" above).

**`ethernet_flows[]`** (docs/DEVELOPMENT.md's ROADMAP item 15) -- always present, empty on a
policy that declares no VLAN zones (see "Addressing scope" below), one
entry per "L2 flow": PROFINET RT/GOOSE/Sampled Values/EtherCAT traffic
aggregated by protocol + MAC pair (no port, no client/server distinction --
these protocols have neither):

```json
{
  "protocol": "goose",
  "mac_a": "00:0c:29:11:22:33",
  "mac_b": "00:0c:29:aa:bb:cc",
  "mac_a_vendor": "VMware",
  "mac_b_vendor": "VMware",
  "has_vlan_tag": true,
  "vlan_id": 100,
  "vlan_zone": "ot_vlan",
  "packet_count": 1,
  "verdict": "allowed",
  "matched_conduit": "OT protocols permitted on ot_vlan",
  "reason": null
}
```

`mac_a_vendor`/`mac_b_vendor` are the same OUI-vendor annotation as
`flows[]`'s own `client_mac_vendor`/`server_mac_vendor` above, omitted
entirely (never `null`) on a lookup miss or `--no-oui` -- an L2 flow has no
IP or port at all, so there's no hostname/service-name equivalent here.

`vlan_id` is `null` when `has_vlan_tag` is `false` (the frame carried no
802.1Q tag at all). `vlan_zone` is the declared VLAN zone the frame's tag
falls within, or the reserved name `"unclassified"` when either the tag
matches no declared zone or there's no tag to check at all -- `reason`
distinguishes the two ("no declared VLAN zone contains VLAN N" vs. "frame
carries no 802.1Q VLAN tag at all"). `allowed_count`/`violation_count`/
`unclassified_count` at the top level are the combined totals across both
`flows[]` and `ethernet_flows[]`.

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

**The `protocols` enum names twelve values** (docs/DEVELOPMENT.md's ROADMAP item 14, done):
`modbus`, `dnp3`, `s7comm`, `iec104`, `enip`, `bacnet`, `hartip`, `opcua`,
`mms`, `mqtt`, `ffhse`, `any` -- see "Validation errors" below. This was
previously closed to the first five (plus `any`); `decode` recognized
BACnet/IP, HART-IP, OPC UA, MMS, MQTT, and FOUNDATION Fieldbus HSE
considerably before any of them could be named in a conduit's
`protocols`/`protocol` field -- the closest a conduit could get to
covering their traffic was `any`, which matches every protocol
indiscriminately and can't be scoped down to just one of them. That gap
is closed for all six now: a conduit CAN say "only OPC UA is allowed
here" (`protocol: opcua`), and PolicyEngine's own flow-classification
dispatch (`PolicyEngine::observe`) genuinely recognizes each of them, not
just the policy-file parser -- see the "Widened `protocols` enum" tests
in `CMakeLists.txt` and `tests/policies/widened_protocols.yaml` for
end-to-end confirmation against each protocol's own real sample capture.
One asterisk survives this widening, addressed in the very next
paragraph: `bacnet` parses and validates like any other protocol name,
but BACnet/IP itself can never actually match a flow, for a reason that
has nothing to do with the enum.

**`policy validate` only ever evaluates TCP flows** (see "`policy
validate`" above and LIMITATIONS) -- so even where a protocol's UDP
traffic is fully decoded by `decode` (BACnet/IP, HART-IP, CIP I/O, FF-HSE),
none of it reaches the policy engine at all. This is independent of the
`protocols`-enum widening just described: naming a protocol in
`protocols` only lets a conduit be MATCHED by that protocol's TCP traffic,
it doesn't make UDP traffic suddenly visible to the engine. Concretely,
of the six newly-named protocols: `hartip`, `opcua`, `mms`, `mqtt`, and
`ffhse` all carry genuine TCP traffic this decoder recognizes, so naming
them now does real work (`hartip` specifically only matches its own TCP
form -- HART-IP's UDP form, like BACnet/IP's, still never reaches the
engine). `bacnet` is the one exception with no TCP form to fall back on
at all: this decoder only ever recognizes BACnet/IP over UDP (see
`decoder.cpp`), so `protocol: bacnet` is accepted at policy-load time,
appears in `unexercised_conduits` like any conduit real traffic never
happened to exercise, but can never move out of that list -- there is no
capture this engine could be given that would make it match. Fixing that
needs `policy validate` to evaluate UDP flows at all, a separate,
not-yet-scoped piece of future work this item deliberately didn't take on
(see docs/DEVELOPMENT.md's ROADMAP).

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
VLAN-membership check, not an IPv4-zone check. docs/DEVELOPMENT.md's ROADMAP item 15 implements
exactly that: a zone can declare `vlans: [...]` instead of `networks:
[...]`, and a VLAN-zone conduit is matched against these four protocols'
own traffic, classified by whichever declared VLAN zone (if any) the
frame's own 802.1Q tag falls within -- see "Schema" and "Conduits" above
for the full syntax, and "Validation errors" for what's rejected at load
time. This still isn't a directional, per-flow model the way an IPv4
conduit is: a single frame carries at most one VLAN tag, so there's no
"destination VLAN" to check against a separate "source VLAN" the way an
IPv4 conduit checks a client zone against a server zone -- a VLAN-zone
conduit's `from`/`to` are required to name the same zone set, and it means
"this protocol is permitted on this VLAN zone," full stop. Only a single, ordinary 802.1Q tag (EtherType `0x8100`) is ever recognized
for this -- `parse_ethernet` (`link_layer.cpp`) has no case for a
stacked/QinQ outer tag (EtherType `0x88A8`) at all, so a QinQ-tagged
PROFINET RT/GOOSE/SV/EtherCAT frame isn't even decoded as that protocol in
the first place (the outer `0x88A8` ethertype falls through to the generic
"non-IP ethertype" path instead, before this decoder ever gets to look for
a PROFINET/GOOSE/SV/EtherCAT ethertype underneath) -- see LIMITATIONS.
Two narrower
asterisks worth knowing about: IEC 61850-90-5
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
  `dnp3_destination_address` (docs/DEVELOPMENT.md's ROADMAP item 13, done): `decode`'s own
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
  of, IP) remains open future work. See docs/DEVELOPMENT.md's ROADMAP.
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
  reaches the zone engine (this is still true after docs/DEVELOPMENT.md's ROADMAP item 15: a
  VLAN-zone conduit classifies these four protocols' traffic by their
  802.1Q tag alone, never by APPID/GoCB/`svID`/ADP/ADO -- those remain
  informational, decoded-and-exposed-but-not-zone-classified fields, the
  same as every other application-layer address in this list).

None of this changes what's Allowed/Violation/Unclassified today, item 15
excepted -- every other item above describes information `decode` already
surfaces (or, for DNP3's link address, doesn't yet) that `PolicyEngine`
still doesn't use for zone classification. See docs/DEVELOPMENT.md's ROADMAP for what's actually
planned.

## OUTPUT FORMATS

### text (default)

One line per packet: index, timestamp, source and destination `ip:port`,
`[protocol]`, a summary, and, for a TCP packet, which side of this flow
`decode`'s own per-flow tracking (`FlowDirectionTracker`, independent of
`policy validate`/`inventory`'s own direction tracking) currently believes
is the client (initiator) and whether that came from an observed TCP
handshake or only a port-based guess -- folded into the packet's own head
line itself (`(client <ip> -- <tier>)`, appended last) rather than a
separate line, so it reads alongside the endpoints/protocol/summary it
describes. `--no-direction` suppresses it; it never appears for a UDP/
non-IP/parse-error packet regardless of the flag, since only a TCP flow has
a client/server side to determine in the first place. Any additional notes
(heuristic explanations, port-mismatch warnings, malformed-field warnings)
are printed indented below the packet line, followed, for an
Ethernet-linktype packet, by an `eth` line showing the raw source/
destination MAC addresses. See the `json` output's own `direction_source`/
`direction_client_ip` fields below for the two machine-readable values the
head line's `(client ... -- ...)` annotation renders, and
docs/DEVELOPMENT.md's ROADMAP item 19 for the full design record.

```
#1  1700000000.000000  192.168.1.50:51000 -> 192.168.1.10:502  [modbus]  Read Holding Registers: request: read 10 holding register(s) starting at address 0  (client 192.168.1.50 -- port-heuristic)
        note: classified as a request because the PDU is exactly 4 bytes (address+quantity); this is a heuristic, not stream tracking
        eth aa:bb:cc:11:22:33 -> aa:bb:cc:44:55:66
```

When color is on (see "Color" below), the `(client ... -- ...)` annotation
is colored yellow for the `port-heuristic` tier specifically -- the only one
that can actually be wrong -- and dim (like every other secondary
annotation on the line) for the two authoritative tiers, `handshake` and
`content`. The tier name itself is always printed regardless of color/
`--no-color`, so nothing here is color-only information.

When a packet is 802.1Q VLAN-encapsulated, its VLAN ID is appended to the
`eth` line (`vlan <id>`), on by default -- `--no-vlan` suppresses it:

```
#1  1700000000.000000  - -> -  [goose]  GOOSE IED1/LLN0$GO$gcb01 stNum=1 sqNum=1 confRev=1
        eth aa:bb:cc:11:22:33 -> aa:bb:cc:44:55:66  vlan 100
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
decode. Notes are printed dim. The head line's trailing `(client ... -- ...)`
direction annotation (see above) is yellow for the `port-heuristic` tier and
dim for `handshake`/`content`.

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

Every object also carries a trailing `time` field (always a string): with
`-t`/`--time-format` left at its default, this reproduces `timestamp`'s own
raw-epoch value as text; any other `-t` value changes only `time`, leaving
`timestamp` untouched, so an existing `jq` pipeline reading `timestamp`
never needs to change. See OUTPUT FORMATS' "Timestamps" subsection below.

After `time`, every object also carries `direction_source` and
`direction_client_ip` -- which side of this packet's TCP flow is the client
(initiator), and how that was decided: `"handshake"` (a SYN and matching
SYN-ACK were both observed for this flow -- authoritative), or
`"port-heuristic"` (no handshake was captured, so a known-service-port/
lower-port-number guess was used instead, which CAN be wrong -- see
LIMITATIONS below). Both are `null` for a non-TCP packet -- this tracking
(`FlowDirectionTracker`, a separate layer built on top of `decode`'s own
already-public output, the same way `policy validate`/`inventory` each
track direction for themselves) never runs on one. `--no-direction` omits
both fields entirely (never just `null`) on every packet, the same "omit
outright" convention `--no-vlan` already sets for `has_vlan_tag`/`vlan_id`
above. See
docs/DEVELOPMENT.md's ROADMAP item 19 for the full three-tier design record
and the industry precedent researched before adding this (`"content"`, the
third tier, never appears here -- it only applies to BACnet, which is
UDP-only and stays out of `decode`'s own per-packet direction tracking, see
the `inventory` section below for where it does appear).

Over a hundred fields are only present (omitted entirely, not `null`) on
packets where they apply:

- `src_mac_vendor` / `dst_mac_vendor`: the OUI (MAC vendor) name for
  `src_mac`/`dst_mac`, from the built-in OUI table (`--no-oui` disables this
  lookup). Present only when `has_ethernet` and the lookup found a match --
  see OUTPUT FORMATS' "Name resolution" subsection below.
- `has_vlan_tag` / `vlan_id`: whether this packet is 802.1Q VLAN-encapsulated
  and, if so, its VLAN ID. Unlike the resolver annotations below, these two
  fields aren't omitted individually on a "miss" -- they're present as a pair
  whenever `has_ethernet` is true (`has_vlan_tag: false, vlan_id: null` for
  an untagged packet, `has_vlan_tag: true, vlan_id: <n>` for a tagged one) --
  and omitted as a pair entirely, on every packet, only when `--no-vlan`
  disables display outright.
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
  and that pairing succeeded -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION.
- `s7comm_function`: the S7comm function name (`"Read Var"`, `"Write Var"`,
  `"Setup Communication"`, ...), when protocol is `s7comm` and a function
  code was decoded.
- `s7comm_items`: an array of Step 7-style item tags (`"DB10.DBW100"`,
  `"I0.0"`, ...), on Read Var / Write Var *request* packets whose item
  addressing was decoded (see docs/PROTOCOL_COVERAGE.md). A tag from the
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
  packet -- see docs/PROTOCOL_COVERAGE.md.
- `s7comm_pi_service_name` / `s7comm_pi_service_description`: the PLC
  Control (function `0x28`) request's PI service name (e.g. `"_INSE"`,
  `"P_PROGRAM"`, or one of the `_N_*` Sinumerik/CNC names) and, when that
  name is in the known table, its looked-up description (e.g. `"Activates a
  PLC module"`). `s7comm_pi_service_description` is omitted, not `null`,
  when the name isn't in the table -- see docs/PROTOCOL_COVERAGE.md for exactly
  which names that covers.
- `s7comm_pi_control_argument`: `P_PROGRAM`/`_MODU`/`_GARB` only -- the PI
  service's raw ASCII argument string, decoded as-is with no semantic
  interpretation attached (see docs/PROTOCOL_COVERAGE.md for why).
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
  on its own, and docs/DEVELOPMENT.md's ROADMAP for the (still open) idea of a zone model keyed
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
  (if any) still gets a `notes` entry. See docs/PROTOCOL_COVERAGE.md's DNP3
  "Data-link CRC-16 validation" section for the exact semantics and the
  `notes` text a mismatch produces.
- `dnp3_function`: the DNP3 function name (`"Read"`, `"Response"`, ...), when
  protocol is `dnp3` and this fragment's application layer was decoded (see
  docs/PROTOCOL_COVERAGE.md for when that is -- a fragment split across multiple
  data-link frames only gets its transport header decoded, not this).
- `dnp3_objects`: an array of one entry per object header decoded in the
  fragment, e.g. `"g1v2 (Binary Input)"`.
- `dnp3_values`: an array of one entry per decoded point value across every
  object header in the fragment, e.g. `"g1v2 idx=0: 1 [ONLINE]"` or
  `"g12v1 idx=7: code=Latch On tc=Close queue/clear=0x00 count=1
  on_time=1000ms off_time=0ms status=Success"` for a CROB command. Empty for
  an object header outside the point-format table (see docs/PROTOCOL_COVERAGE.md).
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
  commonly coalesce into one TCP segment -- see docs/PROTOCOL_COVERAGE.md), e.g.
  `"ioa=100: ON"` or `"ioa=200: 16384 (0.5000) @ 2024-03-15
  10:30:00.500"` for a time-tagged measured value. Empty for an ASDU type
  outside the decoded-type table (see docs/PROTOCOL_COVERAGE.md).
- `enip_command`: the EtherNet/IP encapsulation command name (e.g.
  `"RegisterSession"`, `"SendRRData"`), when protocol is `enip` AND this is
  an explicit-messaging (TCP) packet. Reflects only the *first* EtherNet/IP
  message found in this TCP payload -- see `notes` for any additional
  coalesced messages (docs/PROTOCOL_COVERAGE.md). Absent for a CIP I/O (implicit
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
  See docs/PROTOCOL_COVERAGE.md for exactly which services get full value decoding
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
  docs/PROTOCOL_COVERAGE.md and LIMITATIONS for why.
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
  (see docs/PROTOCOL_COVERAGE.md). Capped at 50 entries, same reason as
  `enip_cip_values`.
- `profinet_cyclic_io_data_length`: the cyclic RT IO data's byte length, when
  the FrameID falls in a cyclic RT range (see docs/PROTOCOL_COVERAGE.md).
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
  docs/PROTOCOL_COVERAGE.md), `false` for a fully-decoded `0x61` goosePdu. The
  `goose_*` PDU-content fields below are only present when this is `false`
  and a PDU was actually decoded.
- `goose_simulated`: `true`/`false`, present when the PDU content was
  decoded. `true` if either the header's S-bit (Reserved1's top bit) or the
  PDU's own OPTIONAL `simulation` field is set -- a mismatch between the two
  is called out in `notes` (see docs/PROTOCOL_COVERAGE.md).
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
  `"2.0: boolean=false"`) -- see docs/PROTOCOL_COVERAGE.md. Capped at 50 entries,
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
  never value-decoded -- see docs/PROTOCOL_COVERAGE.md's Sampled Values section for
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
  bytes. See docs/PROTOCOL_COVERAGE.md's EtherCAT section for how this decoder uses
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
  docs/PROTOCOL_COVERAGE.md's Cmd table).
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
  lowercase hex, never value-decoded -- see docs/PROTOCOL_COVERAGE.md's EtherCAT
  section for why.
- `ethercat_first_wkc`: the first datagram's Working Counter, as a plain
  integer -- surfaced raw, with no verdict about whether it's the value a
  healthy bus should produce (this decoder has no slave-count/topology
  knowledge to judge that) -- see docs/PROTOCOL_COVERAGE.md.
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
  data is shown as raw hex instead (see docs/PROTOCOL_COVERAGE.md's BACnet/IP
  section).
- `bacnet_values`: an array of decoded field/value strings (e.g.
  `"object=analog-input,3"`, `"property=present-value"`,
  `"value=(Real) 72.500000"`, `"priority=8"`), present only for the
  "first-pass" service set this decoder value-decodes (Who-Is, I-Am,
  Who-Has, I-Have, ReadProperty request/ACK, WriteProperty request, generic
  Error) when a single primitive value was actually present to decode --
  absent for every other service (shown as raw hex with a note instead) and
  for a constructed/array PropertyValue (also raw hex with a note -- see
  docs/PROTOCOL_COVERAGE.md).

All array fields are capped at 50 entries for a single heavily-batched
request/response; see docs/PROTOCOL_COVERAGE.md for where the full list still shows
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
  command set this decoder value-decodes (see docs/PROTOCOL_COVERAGE.md's HART-IP
  section) when the command's data actually matched the byte layout this
  decoder expects -- absent for every out-of-scope or wrong-length command
  (shown as raw hex with a note instead).
- `hartip_checksum`: the Pass-Through body's own trailing classic
  wired-HART longitudinal (XOR) checksum byte, as a plain integer.
  Unconditionally present whenever `hartip_has_pass_through` is `true`
  (unlike most other Pass-Through fields above, never omitted) -- a `0`
  paired with `hartip_checksum_valid: false` is exactly what a body
  truncated before the Checksum byte also produces (see the accompanying
  note in that case), the same "always present" convention
  `dnp3_header_crc_valid` already established.
- `hartip_checksum_valid`: `true` only when this decoder's own computed
  checksum (XORing every byte from the Delimiter through the last byte of
  Data, inclusive) matched `hartip_checksum`. A mismatch also adds a
  `"longitudinal (XOR) checksum mismatch: calculated 0x.., frame declares
  0x.."` note. See LIMITATIONS for what this validation does and doesn't
  cover.

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
  security-audit signal (see docs/PROTOCOL_COVERAGE.md's OPC UA section). Present
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
  dispatch table knows (Tier 1 or Tier 2 -- see docs/PROTOCOL_COVERAGE.md). Always
  present for OpenSecureChannel/CloseSecureChannel/Message; absent for
  Hello/Acknowledge/Error/ReverseHello (which have no service TypeId of
  their own).
- `opcua_service_name`: the recognized service's own name (e.g.
  `"CreateSessionRequest"`). Present only when `opcua_service_recognized`
  is `true`.
- `opcua_service_namespace` / `opcua_service_type_id`: the service TypeId
  NodeId's own namespace and numeric identifier, as plain integers -- present
  even when `opcua_service_recognized` is `false`, so an unrecognized
  service is still identifiable by its raw TypeId (see docs/PROTOCOL_COVERAGE.md).
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
  decoder's own first-pass ~20-entry named table -- see docs/PROTOCOL_COVERAGE.md),
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
docs/PROTOCOL_COVERAGE.md's OPC UA section for the full rationale.

The following fields appear only when `protocol` is `mms`:

- `mms_is_bare`: `true`/`false` -- always present. `true` when the COTP Data
  frame's own user data is a bare MMS PDU with no Session/Presentation/ACSE
  layers at all (see docs/DEVELOPMENT.md's PROTOCOL DETECTION's "bare MMS" shape); when `true`,
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
  against (see docs/PROTOCOL_COVERAGE.md's MMS section). Present when
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
  implemented" in docs/PROTOCOL_COVERAGE.md's MMS section) never correlated back to
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
  parse (see docs/PROTOCOL_COVERAGE.md and LIMITATIONS).
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
  SUBACK/UNSUBSCRIBE only -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION). Absent when truly
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
  docs/PROTOCOL_COVERAGE.md's own security note), CONNACK's SessionPresent/Return
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
  further>"` (Tier 2 scope -- see docs/PROTOCOL_COVERAGE.md); a null metric
  (`is_null=true`) renders its value as `null`.
- `s7plus_pdu_type`: the S7comm-Plus header's own PDU type name
  (`"Connect"`, `"Data"`, `"DataFW1_5"`, `"Keep Alive"`), always present
  when `protocol` is `s7comm-plus`.
- `s7plus_keepalive_seq`: the Keep Alive PDU's own 1-byte sequence number,
  present only when `s7plus_pdu_type` is `"Keep Alive"`.
- `s7plus_opcode`: `"Request"`/`"Response"`/`"Notification"`/`"Response2"`,
  present when `s7plus_pdu_type` is `"Data"` or `"DataFW1_5"` (DataFW1_5's own
  relocated Integrity part is consumed first -- see docs/PROTOCOL_COVERAGE.md
  -- then the rest of its Data part is opcode-led exactly like plain `"Data"`)
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
  leaves this `false`, even for a Tier-1 function -- see docs/PROTOCOL_COVERAGE.md
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
  one string rather than a nested JSON structure -- see docs/PROTOCOL_COVERAGE.md.
- `s7plus_item_errors`: an array of rendered `"item=<n>: <name> (<code>)"`
  per-item status strings, present only when non-empty -- a
  GetMultiVariables/SetMultiVariables response's own itemnumber-errorvalue
  list.
- `s7plus_integrity_digest_present`: `true`/`false`, present only when an
  Integrity part was reached at all (i.e. only for a Tier-1-decoded body
  with enough remaining bytes -- see docs/PROTOCOL_COVERAGE.md). `true` only when
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
  when `protocol` is `ffhse` -- see docs/PROTOCOL_COVERAGE.md's FOUNDATION Fieldbus
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
  102 bytes present -- see docs/PROTOCOL_COVERAGE.md). Every field below is present
  only when this is `true`.
- `stp_version_3_length`: the Version 3 Length field, as a plain integer.
- `stp_mst_config_name`: the 32-byte MST Config Name, NUL-trimmed.
- `stp_mst_config_revision_level`: the MST Config Revision Level, as a
  plain integer.
- `stp_mst_config_digest`: the 16-byte MST Config Digest as raw lowercase
  hex, never verified.
- `stp_cist_internal_root_path_cost`: the CIST Internal Root Path Cost, as
  a plain integer. Only meaningful (and only ever nonzero from real bytes)
  when `stp_version_3_length` is nonzero -- see docs/PROTOCOL_COVERAGE.md's "Version
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
  format's own sizing rule exactly (see docs/PROTOCOL_COVERAGE.md); that format is
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
  when `protocol` is `devicenet` -- see docs/PROTOCOL_COVERAGE.md's DeviceNet
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
  second payload byte was captured -- see docs/PROTOCOL_COVERAGE.md's DeviceNet
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
  semantically decoded (see docs/PROTOCOL_COVERAGE.md's DeviceNet section and
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
- `dns_transaction_id`: the 16-bit transaction ID as a 4-digit uppercase hex
  string (e.g. `"0x1A2B"`), always present when `protocol` is `dns`, `mdns`,
  or `llmnr` -- these three share one field family, since RFC 6762/4795 both
  reuse RFC 1035's wire format verbatim; the `protocol` string itself is what
  disambiguates them (see docs/PROTOCOL_COVERAGE.md).
- `dns_is_response`: `true`/`false`, the header's QR bit, always present for
  `dns`/`mdns`/`llmnr`.
- `dns_opcode`: the header's Opcode name (e.g. `"Query"`, `"Status"`,
  `"Update"`), always present for `dns`/`mdns`/`llmnr`.
- `dns_header_flags`: a compact rendering of the flavor-specific flag bits
  actually set (e.g. `"AA TC RD RA"` for DNS/mDNS, `"C T"` for LLMNR's own
  Conflict/Tentative bits), or `""` when none are set -- see PROTOCOL
  COVERAGE for exactly which bit occupies which position per flavor.
- `dns_rcode`: the header's Rcode name (e.g. `"NoError"`, `"NXDomain"`,
  `"Refused"`), always present for `dns`/`mdns`/`llmnr`.
- `dns_qdcount` / `dns_ancount` / `dns_nscount` / `dns_arcount`: the header's
  four section counts, as plain integers, always present for
  `dns`/`mdns`/`llmnr` -- these are the header's own DECLARED counts, which
  can exceed the number of entries actually present in a truncated capture;
  see `dns_records_truncated` below.
- `dns_records`: an array of one human-readable summary string per Question/
  Answer/Authority/Additional entry actually parsed, in wire order (e.g.
  `"Q: hmi.plant.example. IN A"`, `"AN: hmi.plant.example. IN A 300s
  192.168.1.50"`), present only when non-empty. RDATA is fully decoded only
  for the "first pass" type set (A/AAAA/NS/CNAME/PTR/MX/SOA/TXT/SRV); other
  types are named (via a table of common values) with their RDATA shown as
  raw hex -- see docs/PROTOCOL_COVERAGE.md. An EDNS0 OPT pseudo-record (type 41)
  renders its repurposed CLASS/TTL fields (UDP payload size, extended-RCODE,
  version, DO bit) rather than misrepresenting them as an ordinary
  class/TTL.
- `dns_records_truncated`: `true`/`false`, always present for
  `dns`/`mdns`/`llmnr` -- `true` when parsing ran out of bytes before
  reaching every entry the header's own counts declared (a genuinely
  truncated capture, not a parse error).
- `nbns_transaction_id`: the 16-bit NAME_TRN_ID as a 4-digit uppercase hex
  string, always present when `protocol` is `nbns`.
- `nbns_is_response`: `true`/`false`, the header's R bit, always present for
  `nbns`.
- `nbns_opcode`: the header's OPCODE name (`"Query"`, `"Registration"`,
  `"Release"`, `"WACK"`, `"Refresh"`), always present for `nbns`.
- `nbns_flags`: a compact rendering of the NM_FLAGS bits actually set (e.g.
  `"AA RA B"`), or `""` when none are set.
- `nbns_rcode`: the header's RCODE name (`"Success"`, `"Format Error"`,
  `"Name Error"`, etc.), always present for `nbns`.
- `nbns_qdcount` / `nbns_ancount` / `nbns_nscount` / `nbns_arcount`: the
  header's four section counts, as plain integers, always present for
  `nbns`.
- `nbns_records`: an array of one summary string per Question/Answer/
  Authority/Additional entry actually parsed, present only when non-empty.
  An NB resource record's summary lists each `NB_ADDRESS` with its Group/
  Unique flag and Node Type (B/P/M-node); an NBSTAT resource record's
  summary lists each entry in the returned name table (name, Microsoft/
  Wireshark-convention suffix name, and ACT/PRM/CNF/DRG flags) followed by
  the responding node's own MAC address (UNIT_ID) -- the STATISTICS
  structure's remaining bytes past UNIT_ID are not further decoded (see
  LIMITATIONS) and are not included in this summary.
- `nbns_records_truncated`: `true`/`false`, always present for `nbns` --
  same meaning as `dns_records_truncated` above.
- `doh_sni`: the TLS ClientHello's Server Name Indication hostname, always
  present when `protocol` is `doh`. This is the plaintext hostname the
  client is connecting to -- the DNS query/answer itself, inside the TLS
  session this ClientHello begins, is never visible to this decoder.
- `doh_matched_provider`: the curated provider label the SNI matched (e.g.
  `"Cloudflare DNS"`, `"Google Public DNS"`, `"NextDNS"`), always present
  when `protocol` is `doh` -- see docs/PROTOCOL_COVERAGE.md for the full provider
  table. A DoH resolver not on this table is never reported as `doh` at all
  (see LIMITATIONS), so this field is never empty when present.
- `doh_alpn_protocols`: an array of the ClientHello's own ALPN-advertised
  protocol strings (e.g. `["h2", "http/1.1"]`), present only when the
  extension was present and non-empty.

### csv

Header row followed by one row per packet:
`index,timestamp,src_mac,dst_mac,src_mac_vendor,dst_mac_vendor,src_ip,src_hostname,src_port,src_port_service,dst_ip,dst_hostname,dst_port,dst_port_service,protocol,summary,notes,vlan_id,time,direction_source,direction_client_ip`.
Fields are quoted per standard CSV rules when they contain a comma, quote, or
newline; multiple notes are joined with ` | ` inside the single `notes` field.
`src_mac`/`dst_mac` are empty for a non-Ethernet-linktype capture, exactly
like `src_ip`/`dst_ip` are empty for a non-IP packet; every
`*_vendor`/`*_hostname`/`*_service` annotation column is an empty field on a
lookup miss or when that resolution is disabled (never a placeholder like
`"unknown"`) -- see "Name resolution" below. `vlan_id` (deliberately not
next to `src_mac`/`dst_mac` where it's conceptually closest, so it never
shifts any other column's position) is likewise an empty field both for an
untagged packet and, regardless of whether the packet is tagged, whenever
`--no-vlan` disables display -- CSV has no way to distinguish "no VLAN tag"
from "not shown" the way JSON's `has_vlan_tag` can, so the column's header
always exists but its value is empty in both cases. `time` is next
(`-t`/`--time-format`'s own rendering of the same timestamp `timestamp`
already carries raw -- see "Timestamps" below), added after `vlan_id`
rather than next to `timestamp` for the same "never shift an existing
column" reasoning. `direction_source`/`direction_client_ip` are now the
trailing two columns, added after `time` for the same reason -- see the
`json` output's own paragraph above for what the two values mean (both
empty here, rather than JSON's `null`, for a non-TCP packet). The column
header pair always exists (CSV can't omit a column conditionally the way
JSON omits a field pair) but both values are also empty, on every packet,
whenever `--no-direction` disables display -- the same "column always
exists, value empty" precedent `vlan_id` already sets above. See
docs/DEVELOPMENT.md's ROADMAP item 19 for the full design record.

### Timestamps

`decode`'s `-t`/`--time-format` controls how each packet's timestamp is
rendered, in all three output formats -- mirroring tshark's own `-t
<mnemonic>` flag rather than tcpdump's stacking `-t`/`-tt`/`-ttt`/`-tttt`/
`-ttttt` convention, since a single flag with a value fits this tool's
existing CLI11-based option style better than a run of same-named repeated
flags:

| Value | Meaning |
|---|---|
| `e` / `epoch` (default) | Raw seconds since the Unix epoch, `%s.ffffff` -- byte-for-byte the same rendering `decode` has always used, so leaving `-t` unset changes nothing about existing output or scripts built against it. |
| `r` / `relative` | Seconds elapsed since the *first* packet in this decode (`0.000000` for that first packet). |
| `d` / `delta` | Seconds elapsed since the *previous* packet in this decode (`0.000000` for the first packet, since it has no previous one). |
| `a` / `absolute` | Wall-clock time of day, `HH:MM:SS.ffffff`. |
| `ad` / `absolute-date` | Wall-clock date and time, `YYYY-MM-DD HH:MM:SS.ffffff`. |

`--time-offset` selects the timezone `absolute`/`absolute-date` render in
(ignored by every other `-t` value): `utc` (the default) appends a literal
`Z` suffix; `local` uses this machine's own system timezone and appends no
suffix at all, deliberately unlabeled, the same way tshark/tcpdump's own
local-time rendering doesn't print a zone name either, since "the analysis
machine's local clock" isn't a fixed value worth printing; or a fixed
`+HH:MM`/`-HH:MM` offset (`+0200`, `-05:30`, and a bare `+2`/`-9` hour count
are all accepted too), which appends that same signed offset as its suffix
-- useful for reading a capture in the timezone of the site it came from,
regardless of where the analysis is actually being run. This offset option
goes beyond what tshark or tcpdump themselves offer (both are UTC-vs-local
only); a malformed `--time-offset` value (out-of-range hours/minutes, a
missing sign, extra characters) is rejected with an error naming the value,
before the capture is even opened.

In `text` output, the timestamp is simply rendered in whichever format was
selected, in the same leading position it has always occupied. In `json`,
selecting anything other than the default `e`/`epoch` does not change the
existing raw-epoch `timestamp` field -- it adds a second field, `time`
(always a string, holding whatever `-t` selected), so a `jq` pipeline or any
other consumer already reading `timestamp` keeps working unmodified. In
`csv`, the same rendered value is appended as a new trailing `time` column,
after `vlan_id` -- deliberately last, not next to `timestamp` where it's
conceptually closest, so it never shifts any other column's position, the
same reasoning `vlan_id` itself already follows (see the `csv` section
above).

A `ts` too far in the past or future for this platform's calendar
representation to compute falls back, for `absolute`/`absolute-date` only,
to the same raw-epoch rendering `epoch` always produces, suffixed with `(raw
epoch value -- out of range for calendar display)` -- `decode` never
fabricates a calendar date it can't actually compute, the same "annotate,
never invent" posture the OUI/hostname/service-name resolver below already
follows.

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

Scope: `decode` and `policy validate` share the exact same three lookups and
CLI flags. `policy validate` takes the identical `--no-oui`/`--resolve`/
`--hosts`/`--nn`/`--services` options and annotates its own report the same
way -- see POLICY FILE FORMAT's "`policy validate`" section for exactly
which report fields get which annotation.

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

These are current, not aspirational -- each has a corresponding docs/DEVELOPMENT.md's ROADMAP item.

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
  docs/PROTOCOL_COVERAGE.md's MMS section), an OPC UA chunk, or an MQTT packet (whose
  own Remaining Length is honestly the weakest of this whole list's declared-
  length signals -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION's "Why MQTT is tried last")
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
  (`Decoder::reassemble_cotp_data_frame` -- see docs/PROTOCOL_COVERAGE.md's S7comm/
  COTP section, and further down in this list). MMS shares this exact
  EOT-based fragment-reassembly mechanism as-is (it needs no mechanism of
  its own -- see docs/PROTOCOL_COVERAGE.md's MMS section), though it has no
  real-capture evidence of ever needing it: every real MMS capture checked
  so far carries its message complete in a single COTP Data frame.

  DNP3 additionally has its own separate, higher-layer reassembly: an
  *application* fragment that spans multiple complete data-link frames
  (transport FIR=1 on the first, FIN=0 until the last) is buffered per TCP
  flow across however many packets it takes and decoded once FIN=1 arrives;
  see docs/PROTOCOL_COVERAGE.md and `Decoder::process_dnp3_frame`. This layer is
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
  as `non-ip` (named "IPv6" -- see docs/PROTOCOL_COVERAGE.md's link/IP-layer
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
  (ARP, LLDP, ICMP, and the rest -- see docs/PROTOCOL_COVERAGE.md); nothing outside
  that set gets more than a bare hex/decimal number, and even a *named* one
  gets no further parsing of its own framing. The six exceptions are
  EtherNet/IP's CIP I/O traffic on UDP port 2222, PROFINET RT (EtherType
  `0x8892`, DCP and cyclic real-time IO), IEC 61850-8-1 GOOSE (EtherType
  `0x88B8`), IEC 61850-9-2 Sampled Values (EtherType `0x88BA`), EtherCAT
  (EtherType `0x88A4`), and BACnet/IP (UDP port 47808/0xBAC0), all of which
  are now decoded, not just named -- see docs/PROTOCOL_COVERAGE.md's EtherNet/IP,
  PROFINET RT, GOOSE, Sampled Values, EtherCAT, and BACnet/IP sections.
  `policy validate` does not yet evaluate ANY UDP traffic against a conduit,
  decoded or not (it only ever looks at TCP flows -- this applies equally to
  CIP I/O and BACnet/IP) -- see that section and docs/DEVELOPMENT.md's ROADMAP. This carries
  straight through to `inventory`: it can infer a CIP I/O or BACnet/IP
  conduit from observed UDP traffic just fine (see COMMANDS' `inventory`
  section), and `--policy-out`'s generated policy file loads that conduit
  without error, but feeding it back into `policy validate` will always
  report that conduit as "never exercised," no matter how much matching UDP
  traffic the capture actually has -- not a bug in either command, just this
  same limitation viewed from the discovery side. PROFINET RT,
  GOOSE, Sampled Values, and EtherCAT are different: all four ride raw
  Ethernet with no IP/TCP/UDP layer at all, so there is no IP-based conduit
  rule that could ever match any of them, but docs/DEVELOPMENT.md's ROADMAP item 15 added a
  VLAN-membership-based conduit/zone model specifically for this case -- see
  POLICY FILE FORMAT's "Addressing scope" section and the VLAN-zone
  LIMITATIONS entries below for exactly what it does and doesn't cover.
- **CIP I/O (implicit messaging) decoding does not value-decode the actual
  I/O data, and has no cross-datagram state.** The Connected Data Item's
  contents are shown only as raw hex -- see docs/PROTOCOL_COVERAGE.md's CIP I/O
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
  bytes as if they were IO data (see docs/PROTOCOL_COVERAGE.md's PROFINET RT
  section). No real capture containing cyclic RT IO data was found to
  validate `decode_cyclic` against -- only the hand-built
  `tests/sample_profinet.pcap` exercises it; see `tests/real_captures/
  profinet/ATTRIBUTION.md` for what was searched. DCP decoding itself IS
  validated against two real captures (including one that caught a real
  BlockInfo/BlockQualifier decoding bug before this feature shipped -- see
  that same ATTRIBUTION.md and docs/PROTOCOL_COVERAGE.md), but a DCP Xid is never
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
  independent real capture -- see docs/PROTOCOL_COVERAGE.md's GOOSE section and
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
  docs/PROTOCOL_COVERAGE.md's Sampled Values section and
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
  confidence source (see docs/DEVELOPMENT.md's PROTOCOL DETECTION). The 986-frame real capture
  used to validate this decoder (see docs/PROTOCOL_COVERAGE.md's EtherCAT section
  and `tests/real_captures/ethercat/ATTRIBUTION.md`) is genuine and confirms
  the "declared Length bounds the chain" design empirically (zero
  declared-Length-vs-actual-bytes mismatches across all 986 frames), but
  covers only 8 of 15 `Cmd` values (APRD/FPRD/BRD/FPWR/LRD/LWR/BWR/APWR) --
  APRW/FPRW/BRW/LRW/ARMW/FRMW/EXT/NOP, the `Circulating` bit, the frame
  header's `Reserved` bit, 802.1Q VLAN tagging, frame Types other than 1, and
  every malformed/truncated-input path are validated only against the
  hand-built `tests/sample_ethercat.pcap`, cross-checked against
  `packet-ethercat-datagram.c`'s source rather than an independent real
  capture. `Data` is never value-decoded by design (see docs/PROTOCOL_COVERAGE.md),
  and the CoE/SoE/EoE/FoE/AoE mailbox protocol family, Frame Type 5
  ("Mailbox"), Frame Types 2-4 (ADS/RAW-IO/NV), and Distributed Clock
  register semantics are all out of scope entirely.
- **BACnet/IP's service value-decoding is a deliberate first-pass subset,
  and its real-capture validation is narrow.** Only Who-Is/I-Am/Who-Has/
  I-Have/ReadProperty (request+ACK)/WriteProperty (request)/generic-Error
  are value-decoded; every other confirmed/unconfirmed service
  (ReadPropertyMultiple/WritePropertyMultiple/SubscribeCOV/and the rest of
  the 50 service-choice table entries) is named only, its data shown as raw
  hex -- see docs/PROTOCOL_COVERAGE.md's BACnet/IP section for the full rationale.
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
  `tcp`) -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION's "Why HART-IP is tried last" for the
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
- **HART-IP's Pass-Through Checksum byte IS now verified** -- the classic
  wired-HART longitudinal (XOR) checksum is computed across Delimiter..Data
  inclusive and compared against the wire's own trailing byte; a mismatch
  is surfaced as a note (`decode --format text`) or
  `hartip_checksum_valid: false` (JSON) -- see `hartip_checksum`/
  `hartip_checksum_valid` in JSON OUTPUT FIELDS and `HartIpPassThrough::
  checksum_valid`'s own doc comment in `hartip.hpp`. Purely diagnostic
  today, the same posture DNP3's own header/block CRC validation has: not
  wired into `policy validate`/`PolicyEngine` (see docs/DEVELOPMENT.md's ROADMAP item 10), and a
  checksum byte that's missing entirely because the body was truncated
  before it is never treated as valid either way, the same
  "unverifiable is not valid" convention `dnp3_header_crc_valid` already
  established.
- **HART-IP's Status header byte is not interpreted at all** -- every
  message this decoder's own research and every real capture checked so
  far carries Status `0`; a non-zero value is passed through as a plain
  integer with no further meaning asserted, since no authoritative source
  consulted during this decoder's research defines one.
- **Commands 31 and 203 have no authoritative top-level name asserted**,
  by design, not oversight -- see docs/PROTOCOL_COVERAGE.md's HART-IP section for
  the full reasoning (both sit outside HART's own Universal/Common-Practice
  numbering, and no source consulted names either one, though Wireshark's
  own dissector decodes the same byte shape this decoder does, which is why
  the *structure* is still decoded with confidence).
- **HART-IP command value-decoding is a deliberate "first pass"**, the same
  scoping precedent this codebase already applies to BACnet/IP's service
  subset, EtherNet/IP CIP explicit messaging's own service subset, and
  DNP3's group/variation table -- see docs/PROTOCOL_COVERAGE.md's HART-IP section
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
  implemented (see docs/PROTOCOL_COVERAGE.md's "Variant/DataValue value decoding"
  section), and Read/Write/Call were promoted to Tier 1 specifically because
  they're the services whose entire reason for existing is carrying one.
  Browse and the subscription/MonitoredItem-management services simply
  don't carry a Variant/DataValue anywhere in their own bodies at all (a
  separate, unrelated decode effort); HistoryRead does, but its own
  HistoryReadDetails ExtensionObject dispatches across five different
  sub-structures, additional scope of its own this first pass leaves for
  later (see docs/DEVELOPMENT.md's ROADMAP). For these services, only that a Browse/Subscribe/
  etc. happened, its request handle, and (for a response) whether it
  succeeded are visible.
- **OPC UA chunk reassembly is not implemented** -- a logical message split
  across multiple `'C'`/`'F'` OPC UA chunks (distinct from ordinary TCP-
  segment-level reassembly, which IS implemented -- see docs/PROTOCOL_COVERAGE.md's
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
  docs/PROTOCOL_COVERAGE.md).
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
  or a structurally-invalid NodeId -- see docs/PROTOCOL_COVERAGE.md's OPC UA
  Validation subsection for the complete, honest scope. Its own CallRequest
  (now Tier 1) turned out to be genuinely malformed in both sessions --
  Achilles Satellite fuzz-test payloads, not well-formed traffic -- so this
  capture still does not validate a well-formed Read/Write/Call exchange
  against real bytes; only this decoder's own synthetic fixtures do that.
- **DNP3 data-link CRCs are now validated** -- both the header CRC and every
  per-block CRC within the user data are genuinely calculated and compared
  against the on-the-wire value (`dnp3_header_crc_valid`/`dnp3_block_count`/
  `dnp3_block_crc_failures`/`dnp3_link_crc_valid`, plus a specific `notes`
  entry on a mismatch) -- see docs/PROTOCOL_COVERAGE.md's DNP3 "Data-link CRC-16
  validation" section. This is purely diagnostic: a mismatch is flagged, but
  decoding is never stopped and the frame is never dropped, and CRC validity
  is **not** wired into `policy validate`/`PolicyEngine` -- a flow with a
  CRC-invalid DNP3 frame gets exactly the same Allowed/Violation verdict it
  would with a valid one. One of this project's own real captures
  (`dnp3_request_link.pcap`/`dnp3_request_link_status.pcap`) has a
  Request Link Status response frame that genuinely fails header-CRC
  validation and also has a spec-non-conformant `length_field` of 0 --
  pre-existing behavior the new validator surfaces, not a bug in this
  feature (see docs/PROTOCOL_COVERAGE.md for the detail).
- **DNP3 point values are decoded only for the group/variation combinations
  in the built-in point-format table** (see docs/PROTOCOL_COVERAGE.md for the full
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
  payload-shape heuristic (see docs/DEVELOPMENT.md's PROTOCOL DETECTION) always runs and always
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
  built-in decode table** (see docs/PROTOCOL_COVERAGE.md for the full list -- it
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
  ATTRIBUTION.md and docs/PROTOCOL_COVERAGE.md) is shown structurally (service name
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
  than confirmed documentation -- see docs/PROTOCOL_COVERAGE.md for exactly what
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
  captures that do exercise EOT=0 chaining (see docs/PROTOCOL_COVERAGE.md) all use a
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
  recognized (named) but not body-decoded (Tier 2). This applies equally
  whether the function arrives in an ordinary PDU type Data (`0x02`) telegram
  or a DataFW1_5 (`0x03`) one: DataFW1_5's own relocated Integrity part
  (confirmed against a real S7-1212C capture -- see
  docs/PROTOCOL_COVERAGE.md's S7comm-Plus section) is consumed first, and the
  Tier-1/Tier-2 split above then applies to its Data part exactly as it does
  for plain Data.
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
  `fileRename`, `fileDelete`, `fileDirectory` -- see docs/PROTOCOL_COVERAGE.md's
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
  I/O, BACnet/IP, and HART-IP's own UDP traffic, see docs/PROTOCOL_COVERAGE.md). A
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
  `inventory`'s own client/server determination (see above) uses the exact
  same fallback, for the exact same reason.
- **Direction/initiator determination is, in general, only ever as good as
  the evidence available for a given flow -- it can't always be established
  with certainty, only approximately.** "Approximately" has one precise
  meaning throughout this codebase: *not backed by an observed TCP
  handshake*. Every direction call this tool makes falls into one of three
  tiers, most authoritative first: (1) **handshake** -- a SYN and matching
  SYN-ACK were both seen for the flow, which is unambiguous by construction
  (TCP's own three-way handshake defines the initiator); (2) **content** --
  no handshake was seen, but the protocol's own application-layer semantics
  settle it without guessing (BACnet is the only case today: a
  Confirmed-Request/Unconfirmed-Request's source is definitionally the
  client, and a response's destination is, since BACnet client and server
  both conventionally listen on the same UDP port 47808 and the port
  heuristic below can't even be attempted -- see `inventory` above); (3)
  **port-heuristic** -- neither of the above, so the known-OT-port/
  lower-port-number guess described in the bullet above is used, and this
  is the only tier that can actually be wrong. This tiering is labeled, not
  just applied silently: `decode` (per packet), `policy validate` (per
  `FlowReport`), and `inventory` (per `InventoryEdge`) each carry a
  `direction_source` field (`"handshake"`/`"content"`/`"port-heuristic"`) --
  `decode`'s own copy of this tracking is `FlowDirectionTracker`
  (`flow_direction.hpp`), a third, independent implementation alongside
  `PolicyEngine::observe`'s and `AssetInventoryEngine::observe`'s own --
  see each command's own OUTPUT FORMATS/JSON report schema entry above for
  the exact field and docs/DEVELOPMENT.md's ROADMAP item 19 for the full
  design record. Industry precedent was surveyed before settling on how to
  name this (Zeek, Suricata, Wireshark): none of the three actually expose
  a labeled confidence/provenance field for this. Wireshark is the closest
  precedent, and not a reassuring one -- its own Conversations table orders
  endpoints by the same "lower port number is probably the server" guess
  this tool falls back to, with a long-open community feature request
  asking it to prefer the handshake's actual direction instead when one
  was captured. `direction_source` is mechanism-based, not
  confidence-based, deliberately -- see ROADMAP item 19 for why a graded
  "confidence" scale (the kind threat-intel writing commonly uses) was
  considered and rejected for this.
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
  codebase, weaker even than HART-IP's** -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION's "Why
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
  independent validation -- see docs/PROTOCOL_COVERAGE.md's MQTT Validation
  subsection.
- **Sparkplug B's Bytes, File, DataSet, Template, PropertySet/
  PropertySetList, and Array `DataType`s are recognized and counted but not
  value-decoded** (Tier 2, shown as `"<N byte(s), not decoded further>"`) --
  see docs/PROTOCOL_COVERAGE.md's MQTT section for the full Tier 1/Tier 2 split.
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
  docs/PROTOCOL_COVERAGE.md's FOUNDATION Fieldbus HSE section's Validation
  subsection.
- **The cyclic Publisher/Subscriber wire shape is an unconfirmed inference,
  not a confirmed fact.** No distinct cyclic Publisher/Subscriber message
  shape was identified in the reference source consulted while building
  this decoder; this decoder's own best guess is that it reuses the
  unconfirmed FMS Information Report family (Service Ids 0/16/17/18), but
  that is a guess -- no independent source was available to confirm or
  refute it. See docs/PROTOCOL_COVERAGE.md's FOUNDATION Fieldbus HSE section.
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
  fixture -- see docs/PROTOCOL_COVERAGE.md's FOUNDATION Fieldbus HSE section.
- **Cisco PVST+/Rapid-PVST+ is named only, not decoded.** It's a genuinely
  different wire envelope (SNAP-encapsulated, Cisco OUI, a proprietary TLV
  appended after the standard BPDU body), not a variant of the format this
  decoder handles -- recognized structurally and named, but its body,
  including the standard BPDU fields it also nominally carries, is never
  opened. See docs/PROTOCOL_COVERAGE.md's Spanning Tree Protocol section.
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
  bytes. See docs/PROTOCOL_COVERAGE.md's DeviceNet section.
- **ControlNet (ODVA's other original CIP network) cannot be decoded by
  this or any pcap-based tool.** It rides a proprietary physical layer (RG-6
  coax, Manchester coding, implicit token-passing) that no standard capture
  tool -- including Wireshark, which has no ControlNet dissector at all --
  can sniff; the only real-world way to observe it is Rockwell's own
  proprietary ControlNet Traffic Analyzer, which produces no pcap-compatible
  output. This is a structural limitation, not a scope gap: see PROTOCOL
  COVERAGE's DeviceNet section's "Why not ControlNet too" note.
- **DNS, mDNS, LLMNR, and NBT-NS are UDP only -- DNS-over-TCP is not
  decoded.** These four protocols do have a TCP form in principle (RFC 1035
  §4.2.2 for DNS itself, used for zone transfers and oversized responses);
  this decoder's own detection and parsing only cover the UDP wire format.
  See docs/PROTOCOL_COVERAGE.md's DNS/mDNS/LLMNR/NBT-NS/DoH section.
- **DoH, DoT, and DNS-over-QUIC content is never visible, and never will
  be, by this or any pcap-based tool without the session's own decryption
  keys.** The actual DNS query and answer travel inside TLS (DoH/DoT) or
  QUIC (DoH-over-QUIC/DoQ), which this project's zero-decryption-keys
  posture cannot and does not attempt to decrypt. Only DoH gets even
  detection-level treatment (via plaintext SNI matching, see below); DoT
  (TCP port 853) and DoQ have no equivalent plaintext signal this decoder
  currently looks for at all, and are not attempted.
- **DoH detection depends entirely on a curated hostname table, and misses
  everything not on it.** A private, enterprise, or simply less-common
  public DoH resolver -- anything whose hostname isn't in the
  `*.suffix`-matched provider table docs/PROTOCOL_COVERAGE.md's DoH subsection
  lists -- is never flagged as `doh`, because there is no wire-format signal
  that distinguishes "DoH to some server" from "any other HTTPS traffic" 
  without either a recognizable hostname or the (unavailable) decrypted
  content. This is a fundamental limitation of SNI-based detection, not a
  table this decoder merely hasn't gotten around to extending yet.
- **DoH detection only looks at a single TCP segment.** A TLS ClientHello
  whose SNI extension happens to land across a TCP segment boundary (large
  cipher-suite lists, or an unusually early MTU-driven split) is not
  detected -- this decoder deliberately reuses the single-segment
  `tcp.payload` here rather than this codebase's general cross-segment TCP
  reassembly (`effective_payload`), since a ClientHello split this way is
  uncommon in practice and reassembling TLS handshakes generically was out
  of scope for a detection-only feature.
- **TLS Encrypted Client Hello (ECH), if in use, defeats DoH detection
  entirely.** ECH encrypts the SNI extension itself (leaving only an
  "outer" ClientHello with a generic placeholder name), which removes the
  one plaintext signal this decoder's DoH detection depends on. ECH is not
  yet widely deployed by the public DoH resolvers this table covers, but
  where it is used, this decoder cannot and does not attempt to see through
  it.
- **None of DNS/mDNS/LLMNR/NBT-NS/DoH are wired into the `policy validate`
  conduit `protocols` classification.** `PolicyEngine::observe()` (see
  POLICY FILE FORMAT) does not yet recognize these five as conduit traffic
  the way it does for e.g. `modbus`/`dnp3`/`bacnet` -- a conduit
  specifically restricted to one of these protocol names in policy YAML
  will not match traffic this decoder itself already decodes as
  `dns`/`mdns`/`llmnr`/`nbns`/`doh`. This was deliberately left out of this
  round's scope (decode/detect only) and is tracked in docs/DEVELOPMENT.md's ROADMAP.
- **RIP's Keyed MD5 (RFC 2082) authentication digest is neither located nor
  verified.** The auth header's own fields (RIP-2 Packet Length, Key ID,
  Auth Data Length, Sequence Number) are fully decoded, but the actual MD5
  digest value -- a separate block appended after the last real route RTE,
  outside the RTE chain -- is not computed or checked, and its trailing
  bytes show up as a generic "trailing byte(s) do not form a full 20-byte
  RTE" note rather than a dedicated digest field. See docs/PROTOCOL_COVERAGE.md's
  RIP section.
- **VRRP-for-IPv6 and HSRPv2-for-IPv6 cannot be decoded.** Neither VRRP nor
  HSRP is IP-version-gated at the transport level, but this project has no
  IPv6 address formatting anywhere in the codebase (see `ipv4.hpp`) -- a
  VRRPv3 message never distinguishes IP version at all on the wire (RFC
  5798 relies entirely on the address list's own byte count, 4 vs. 16 bytes
  per entry, which this decoder does not attempt to disambiguate) and is
  effectively only exercised against IPv4 addresses; an HSRPv2 Group State
  TLV DOES declare its own IP Version field, so that case is at least
  detected and explicitly noted as "not decoded" rather than silently
  misread, per docs/PROTOCOL_COVERAGE.md's HSRP section.
- **None of RIP/IGMP/VRRP/HSRP are wired into the `policy validate` conduit
  `protocols` classification**, for the same reason and with the same
  docs/DEVELOPMENT.md's ROADMAP tracking as the DNS-family bullet above -- a conduit restricted to
  one of these protocol names in policy YAML will not match traffic this
  decoder already decodes as `rip`/`igmp`/`vrrp`/`hsrp`.
- **RIP, VRRP, and HSRP have no real-capture validation at all** -- the same
  honest gap already documented for this codebase's other synthetic-only
  protocols (FF-HSE, DeviceNet); a 498-file search across three public ICS
  pcap collections found no traffic for any of the three (unsurprising for
  collections curated around single-device captures rather than multi-router
  topologies). IGMP is the exception: it has one real capture
  (`tests/real_captures/igmp/plant1_igmp_only.pcap`). See PROTOCOL
  COVERAGE's "RIP / IGMP / VRRP / HSRP" section's own Validation subsection
  and `tests/real_captures/igmp/ATTRIBUTION.md` for the full account.
- **EIGRP's and OSPF's authentication digests are neither located nor
  verified**, the same posture as RIP's own Keyed MD5 support above: EIGRP's
  Authentication TLV and OSPF's Cryptographic/MD5 AuType both have their
  header fields (Auth Type/Key ID/Key Sequence, or Key ID/Auth Data Length/
  Sequence Number) fully decoded, but the actual digest bytes -- appended
  after the packet's own declared length in OSPF's case -- are not computed
  or checked. See docs/PROTOCOL_COVERAGE.md's EIGRP and OSPFv2 sections.
- **PIM has no IPv6 support at all** -- an Encoded Address with Address
  Family `2` (IPv6), or Encoding Type `1` (Native + Join Attribute TLV,
  used by a handful of BIDIR-PIM/MoFRR extensions), stops decoding of that
  message at that point, with a note, rather than being guessed at. See
  docs/PROTOCOL_COVERAGE.md's PIM section.
- **None of IGRP/PIM/EIGRP/OSPF are wired into the `policy validate` conduit
  `protocols` classification**, for the same reason and with the same
  docs/DEVELOPMENT.md's ROADMAP tracking as the DNS-family and RIP/IGMP/VRRP/HSRP bullets above --
  a conduit restricted to one of these protocol names in policy YAML will
  not match traffic this decoder already decodes as
  `igrp`/`pim`/`eigrp`/`ospf`.
- **IGRP, PIM, EIGRP, and OSPF have no real-capture validation at all** --
  the same honest gap already documented above for RIP/VRRP/HSRP; a
  1,020-file search across the same three public ICS pcap collections found
  no traffic for any of the four (unsurprising for collections curated
  around single-device captures rather than multi-router topologies). See
  docs/PROTOCOL_COVERAGE.md's "IGRP / PIM / EIGRP / OSPF" section's own Validation
  subsection and `tests/real_captures/igmp/ATTRIBUTION.md` for the full
  account.
- **VLAN-zone conduits only ever consult a single, outermost 802.1Q tag --
  a stacked/QinQ frame can never be VLAN-zone-classified.** `parse_ethernet`
  (`link_layer.cpp`) only recognizes ordinary 802.1Q (EtherType `0x8100`);
  a QinQ outer tag (EtherType `0x88A8`) has no case at all, so a
  QinQ-tagged PROFINET RT/GOOSE/SV/EtherCAT frame isn't even decoded as
  that protocol in the first place, let alone classified by its inner VLAN
  membership -- see docs/PROTOCOL_COVERAGE.md's link/IP-layer plumbing section and
  POLICY FILE FORMAT's "Addressing scope" section.
- **A VLAN-zone conduit can't restrict WHICH direction a flow was
  initiated, unlike an IPv4-zone conduit.** Its `from`/`to` are required to
  name the exact same VLAN zone(s) (see POLICY FILE FORMAT's "Conduits"
  section for the full rationale: a single raw-Ethernet frame carries at
  most one VLAN tag, so there is no separate "source zone"/"destination
  zone" the way an IPv4 conduit has a client zone and a server zone). This
  is a deliberate design constraint of the VLAN-zone model itself, not
  something planned to be relaxed later.
- **`functions`/per-flow service restriction is not available for
  VLAN-zone conduits.** PROFINET RT/GOOSE/Sampled Values/EtherCAT have no
  per-flow function/service name this engine tracks yet (unlike
  `modbus`/`dnp3`/`s7comm`/`iec104`/`enip`'s own known-function tables --
  see "Function-level restrictions" above) -- `functions`/`function` on a
  VLAN-zone conduit is rejected outright at load time rather than silently
  doing nothing.
- **`policy validate`'s VLAN-zone classification is membership-only, never
  application-layer.** A VLAN-zone conduit's verdict depends solely on the
  frame's own 802.1Q tag; none of GOOSE/SV's APPID or GoCB reference/`svID`,
  or EtherCAT's ADP/ADO station addressing, factor into it at all, even
  though all of them are already decoded and exposed by `decode` -- see
  POLICY FILE FORMAT's "Addressing scope" section for the full list of
  addressing schemes this tool decodes but doesn't (yet, or ever) use for
  zone classification.
- **TeamViewer, AnyDesk, and Zoom are recognized by port number alone --
  the single weakest identification gate anywhere in this codebase.**
  Unlike every other protocol `decode` recognizes, there is no payload
  check whatsoever backing these three matches: a completely unrelated
  service that happens to run on TCP/UDP 5938, 7070, 8801-8810, or
  3478-3479 would be misidentified with total confidence. RDP's port-only
  fallback (traffic on port 3389 that isn't itself a Connection Request/
  Confirm) carries the same weakness. VNC is the one exception -- its RFB
  banner check is a genuine structural signature. See docs/PROTOCOL_COVERAGE.md's
  "Tier 1 remote-access protocol recognition" section and
  `it_protocols.hpp`'s own file header comment for the full reasoning.
- **RDP recognition on TCP port 3389 is scoped to its own Connection
  Request/Confirm only, never a Data frame.** A COTP Data frame arriving
  on port 3389 (which RDP's own handshake never actually produces, since
  RDP itself doesn't ride COTP Data PDUs past the initial X.224 exchange)
  still falls through to the generic, port-independent COTP/S7comm/MMS
  dispatch and is reported as plain `cotp` traffic, the same treatment any
  other off-port TPKT/COTP frame gets -- see docs/PROTOCOL_COVERAGE.md's "Tier 1
  remote-access protocol recognition" section and `decoder.cpp`'s own
  comment at that call site.
- **None of RDP/VNC/TeamViewer/AnyDesk/Zoom/SMB/SSH/HTTP/HTTPS/SNMP/
  Telnet/FTP/TFTP/NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+/EAPOL/CAPWAP control/
  CAPWAP data/LWAPP control/LWAPP data/GTP-U/PPPoE are wired into the
  `policy validate` conduit-matching engine yet** -- this groundwork pass
  only recognizes and names them in `decode` output; a conduit naming
  `rdp`/`vnc`/`smb`/`ssh`/`ntp`/`ldap`/`eapol`/`capwap-control`/`gtp-u`/
  `pppoe`/etc. in its `protocols` list is not yet a supported value (see
  docs/DEVELOPMENT.md's ROADMAP item 18's own "modeling gap" paragraph for what a future pass
  would need).
- **TeamViewer, AnyDesk, Zoom, and (in Tier 2) SNMP/Telnet/FTP/TFTP's own
  port-only fallbacks are all recognized by port number alone**, the
  weakest identification gate in this codebase -- a completely unrelated
  service happening to run on one of these ports would be misidentified
  with total confidence; see docs/PROTOCOL_COVERAGE.md's Tier 1/Tier 2 sections for
  which of each tier's protocols have a genuine structural signature
  (SMB/SSH/HTTP/HTTPS/VNC/RDP's own handshake) versus which don't. Tier 3's
  NTP/RADIUS/TACACS+ each have a genuine, if modest, structural signature
  (see docs/PROTOCOL_COVERAGE.md's Tier 3 section) so their own port-only fallbacks
  are a step above TeamViewer/AnyDesk/Zoom's total absence of one, but
  still weaker than SMB/SSH/HTTP/DHCP's port-independent checks.
- **HTTPS recognition cannot distinguish genuine HTTP-over-TLS from any
  other TLS-wrapped protocol sharing the same ClientHello framing** (MQTT-
  over-TLS, OPC UA over TLS, LDAPS, and similar) unless ALPN explicitly
  offers `http/1.1`/`h2` -- absent that, a standard port is treated as
  good-enough corroboration, but the note says so honestly. The same is
  true in reverse for LDAPS: a ClientHello on port 636/3269 with no ALPN
  confirmation is called `ldaps` on port alone, and could in principle be
  any other TLS-wrapped protocol someone deliberately ran on that port.
  See docs/PROTOCOL_COVERAGE.md's Tier 2/Tier 3 sections.
- **SNMPv3 is not recognized at all** -- its USM-authenticated, optionally
  encrypted framing has no fixed cleartext community string to extract,
  which is this whole check's only signal; a v3 PDU on port 161/162 falls
  to SNMP's own port-only fallback, explicitly noted as possibly v3 rather
  than malformed.
- **FTP's dynamically-negotiated data channel (via PORT/PASV/EPRT/EPSV) is
  never recognized** -- only the control channel on TCP port 21 is; the
  data channel has no fixed port and no content signature of its own past
  raw file bytes, so it's indistinguishable from any other ephemeral-port
  TCP flow.
- **Telnet/FTP/TFTP's own structural checks only fire on port 21/23/69
  (or a configured `--lateral-movement-port`)** -- unlike SMB/SSH/HTTP,
  none of these three are checked port-independently even in Auto mode,
  since their own structural tells (a single `0xFF` byte, a 3-digit
  number, a 2-byte opcode) are too common a shape in arbitrary binary
  traffic to try opportunistically without real false-positive risk.
- **NTP/LDAP/RADIUS/TACACS+'s own structural checks only fire on their own
  configured port (123/389+3268/1812+1813+1645+1646/49, or a configured
  `--enterprise-trust-port`)**, the same reasoning as Telnet/FTP/TFTP
  above -- unlike DHCP's magic cookie or LDAPS's ClientHello, none of these
  four have a signature strong enough to check opportunistically without
  real false-positive risk. One concrete consequence, specific to LDAP: a
  genuine LDAP message on a port this tool doesn't already know about
  (neither 389/3268 nor a configured `--enterprise-trust-port`) is
  misidentified as `mqtt` instead of falling through to a generic `tcp`
  summary, because LDAP's own leading BER `SEQUENCE` tag byte (`0x30`) is
  bit-for-bit identical to a valid MQTT PUBLISH control-packet-type/flags
  byte -- see docs/PROTOCOL_COVERAGE.md's Tier 3 section for the full reasoning and
  the fix once the port is known.
- **EAPOL recognition can only ever report "802.1X traffic was or wasn't
  captured on this link," never "802.1X is configured on this switch port
  but idle."** A passive capture simply has no way to observe the latter
  -- an OT switch port with 802.1X enabled but no fresh authentication
  event during the capture window looks identical, at this decoder's
  level, to one with 802.1X not configured at all. This matters more than
  the equivalent caveat elsewhere in this item, since EAPOL's own audit
  framing is inverted (its *absence* is often the finding) -- see PROTOCOL
  COVERAGE's Tier 3 section.
- **LWAPP control/data are recognized by port number alone (12222/12223),
  the same weakest identification gate as TeamViewer/AnyDesk/Zoom** --
  LWAPP was never published as a standards-track RFC (its own IETF draft
  expired unadopted), so this decoder has no authoritative wire-format
  specification to check any structural signature against; a completely
  unrelated service happening to run on either port would be misidentified
  with total confidence. See docs/PROTOCOL_COVERAGE.md's Tier 4 section.
- **CAPWAP control/data's own structural check only fires on their own
  configured port (5246/5247, or a configured `--wireless-backhaul-port`),
  and does not attempt a bit-perfect decode of the Transport Header** --
  the Preamble's Version/Type nibbles and the HLEN sanity bound are a much
  looser gate than GOOSE/SV/EtherCAT's own single-byte structural checks,
  and RID/WBID/the six flag bits are left entirely unparsed; only HLEN
  itself (needed to locate the Control Header) and, for CAPWAP control, the
  resulting Message Type are actually read. See docs/PROTOCOL_COVERAGE.md's Tier 4
  section.
- **GTP-U's own G-PDU (the actual tunneled user-plane packet) is never
  unwrapped** -- this decoder names the tunnel and surfaces its TEID, but
  does not feed the inner IP packet back through IPv4/TCP/UDP dispatch;
  whatever OT protocol (or anything else) rides inside a G-PDU is entirely
  invisible to every other decoder in this tool. The same is true of
  PPPoE's own Session-stage PPP payload once the link comes up -- only the
  PPP frame's own leading Protocol field is named, never its content. See
  docs/PROTOCOL_COVERAGE.md's Tier 4 section.
- **PPPoE's Session-stage recognition requires Code to be exactly 0x00
  (or 0xA7 for a mid-session PADT)** -- a Session-stage frame with any
  other Code value is not a confident PPPoE match and falls through to the
  generic `non-ip` fallback instead, named only by its EtherType (see
  docs/PROTOCOL_COVERAGE.md's Tier 4 section and `pppoe.hpp`'s own "structural
  detection gate" paragraph for why the EtherType itself, not Code, is
  what actually carries most of the confidence here).
- **None of Tier 5's sixteen tunnel/VPN protocols are wired into the
  `policy validate` conduit-matching engine yet either**, the same
  groundwork-only scope as every protocol in this whole "IT protocols an
  OT auditor flags" family -- see the bullet above.
- **SSTP, 4in6, DS-Lite/MAP-E, MPLS's own L2VPN/VPLS/pseudowire use case,
  and CAPWAP's own alternate data-plane path are deliberately not
  implemented** -- see docs/PROTOCOL_COVERAGE.md's Tier 5 section for the full,
  per-protocol reasoning (SSTP's handshake is TLS-first with nothing
  cleartext for this decoder to see and would collide with the existing
  HTTPS/DoH early-detection call site regardless; 4in6/DS-Lite/MAP-E are
  IPv6-outer encapsulations this codebase has no call site for at all,
  since `decoder.cpp` only ever parses an IPv4 outer header; MPLS's own
  pseudowire payload is wire-format-identical to an ordinary MPLS-switched
  IP packet from this decoder's own point of view, controlled entirely by
  out-of-band LDP/BGP signaling; and CAPWAP's alternate data-plane path
  needed no new code, since GRE/L2TP/IP-in-IP recognition already names
  that traffic when captured).
- **NVGRE cannot be structurally distinguished from plain
  Ethernet-bridging-over-GRE** -- both share the identical GRE Protocol
  Type (`0x6558`) and Key-flag shape; this decoder reports `nvgre` and
  says so honestly rather than guessing further by interpreting the Key
  field's own VSID/FlowID split. See docs/PROTOCOL_COVERAGE.md's Tier 5 section.
- **6in4's inner IPv6 header is recognized but its addresses are never
  surfaced** -- unlike IP-in-IP's own inner IPv4 src/dst extraction, this
  codebase has no IPv6 address parser at all, and adding one solely to
  format two 128-bit addresses for this one case was judged out of scope
  for a name-only recognition tier. See docs/PROTOCOL_COVERAGE.md's Tier 5
  section.
- **The generic dtls-tunnel check cannot tell CAPWAP's own DTLS data
  plane, a vendor AP's DTLS control channel, an LTE offload client, or a
  deliberate DTLS-based VPN apart from each other** -- naming that SOME
  encrypted DTLS tunnel is present, port-independently, is the entire
  audit value this check provides. See docs/PROTOCOL_COVERAGE.md's Tier 5
  section.
- **STT is recognized by port number alone (TCP 7878)**, the same
  weakest identification gate as LWAPP/TeamViewer/AnyDesk/Zoom -- it has
  no publicly authoritative wire-format specification to check a
  structural signature against. See docs/PROTOCOL_COVERAGE.md's Tier 5 section.
- **HART-IP's own opportunistic Auto-mode UDP detection deliberately
  excludes ports 4500 and 4789** (IKE NAT-T and VXLAN) to avoid a
  guaranteed, spec-mandated misclassification -- both protocols' own
  wire formats trivially satisfy HART-IP's loose 2-byte opportunistic
  gate by definition (RFC 3948's all-zero non-ESP marker; RFC 7348's
  all-zero VXLAN Reserved field), unlike the codebase's other, merely
  possible HART-IP/Modbus TCP collision left undocumented-but-accepted.
  An explicit `--protocol hartip` is unaffected by this exclusion and
  still attempts every port. See docs/PROTOCOL_COVERAGE.md's Tier 5 section.

## EXIT STATUS

| Code | Meaning |
|---|---|
| 0 | Success. For `policy validate`: the capture is COMPLIANT (every observed flow was explicitly allowed by a conduit). For `inventory`: the capture was read and a report was produced -- `inventory` has no compliance concept (there's no hand-written policy to be compliant *against*), so it returns 0 on any successful run, even one that observed zero assets. |
| 1 | A fatal error occurred -- bad arguments, the input file could not be opened, the file is not a recognized capture format (classic pcap or pcapng) or is corrupt, (with `--strict`) a packet failed to parse, or (for `policy validate`) the policy file couldn't be opened or failed validation (see POLICY FILE FORMAT's "Validation errors"). |
| 2 | *(currently unused)* Reserved rather than reused: an earlier groundwork release used this for `policy validate` while it was still a documented stub with no evaluation engine behind it. Nothing returns it now that `policy validate` is fully implemented, but the value is left unclaimed in case a future documented-stub command needs it again. |
| 3 | `policy validate` only: the capture and policy file were both readable and valid, but the capture is NON-COMPLIANT -- `PolicyReport::compliant()` is false (at least one violation and/or unclassified flow was found). Distinct from 1 specifically so a script can tell "ran fine, found problems" apart from "couldn't even run". Never returned by `inventory` (see code 0 above). |

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
(see docs/PROTOCOL_COVERAGE.md's DNP3 "Data-link CRC-16 validation" section):

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
"SECURITY FINDING" note (see docs/PROTOCOL_COVERAGE.md's OPC UA "Identity token
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
HART-IP's own gate; see docs/DEVELOPMENT.md's PROTOCOL DETECTION and LIMITATIONS), worth a manual
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

See who's sending LLMNR/NBT-NS broadcast name-resolution queries on an OT
segment -- the fallback-resolution traffic LLMNR/NBT-NS poisoning attacks
(e.g. Responder) exploit, and traffic that arguably shouldn't be present on
a well-segmented OT network at all:

```sh
conduitscope decode -r capture.pcap --protocol llmnr -f json \
  | jq -r '.[] | select(.protocol == "llmnr" and (.dns_is_response | not)) |
           "\(.src_ip): \(.dns_records[0] // "?")"'
```

Flag DNS-over-HTTPS to a known public resolver -- on a well-segmented OT
network this is worth a look either way: it bypasses whatever DNS-based
egress monitoring/filtering the network relies on, whether that's
deliberate (an engineer's laptop dodging a captive portal) or a sign of
malware avoiding detection:

```sh
conduitscope decode -r capture.pcap --protocol doh -f json \
  | jq -r '.[] | "\(.src_ip) -> \(.dst_ip): \(.doh_matched_provider) (SNI \(.doh_sni))"'
```

Build a quick routing table inventory from a passive RIP capture -- every
route advertised, by whom, and at what metric:

```sh
conduitscope decode -r capture.pcap --protocol rip -f json \
  | jq -r '.[] | select(.rip_command == "Response") | .src_ip as $s |
           (.rip_routes[] | select(startswith("authentication:") | not)) | "\($s): \(.)"'
```

See which hosts are joining/leaving which multicast groups over an IGMP
capture -- a passive inventory of who is actually subscribed to
GOOSE/SV-style multicast traffic:

```sh
conduitscope decode -r capture.pcap --protocol igmp -f json \
  | jq -r '.[] | select(.igmp_type | test("Report|Leave")) |
           "\(.src_ip): \(.igmp_type) \(.igmp_group_address)"'
```

Flag VRRP/HSRP traffic that looks like a first-hop-gateway takeover
attempt in progress -- a Priority-0 VRRP "master is stopping" Advertisement
or an HSRP Coup, either of which a legitimate failover can produce but
which is also exactly what a gateway-spoofing/MITM attempt looks like on
the wire (see docs/PROTOCOL_COVERAGE.md's VRRP/HSRP Security context notes):

```sh
conduitscope decode -r capture.pcap -f json \
  | jq -r '.[] | select((.protocol == "vrrp" and .vrrp_priority == 0) or
                         (.protocol == "hsrp" and .hsrp_opcode == "Coup")) |
           "\(.src_ip): \(.summary)"'
```

Inventory every OSPF Router-LSA seen on a segment -- who is originating
routes, and how many links each one claims (a rogue OSPF speaker often
shows up as an unexpected Router ID or an implausible link count):

```sh
conduitscope decode -r capture.pcap --protocol ospf -f json \
  | jq -r '.[] | .ospf_ls_update_lsas[]? | select(startswith("Router")) | .'
```

Check whether any router-to-router IGP traffic (IGRP, EIGRP, or OSPF) is
present at all on a segment that is supposed to be a flat, switched OT
network with no routers on it -- seeing any of it is itself a finding:

```sh
conduitscope decode -r capture.pcap -f json \
  | jq -r '.[] | select(.protocol | test("^(igrp|eigrp|ospf)$")) |
           "\(.src_ip) -> \(.dst_ip): \(.summary)"'
```

Check whether PROFINET RT/GOOSE/Sampled Values/EtherCAT traffic is on the
VLAN it's supposed to be on -- a VLAN-membership zone/conduit policy (see
POLICY FILE FORMAT's "Conduits" and "Addressing scope" sections), reported
as JSON so a pipeline can flag anything that isn't `"allowed"`:

```sh
conduitscope policy validate -r capture.pcap --policy ot_vlans.yaml -f json \
  | jq -r '.ethernet_flows[] | select(.verdict != "allowed") |
           "\(.mac_a) <-> \(.mac_b) (\(.protocol)): \(.reason)"'
```

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
