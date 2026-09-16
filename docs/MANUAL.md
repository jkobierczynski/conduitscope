# conduitscope(1) -- Manual

## NAME

conduitscope -- decode Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP, EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP and cyclic real-time IO), IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values, EtherCAT, BACnet/IP, and HART-IP traffic from offline pcap captures

## SYNOPSIS

```
conduitscope [-q|--quiet] [--no-color|--color] [--log-file FILE] [--version] [-h|--help] <command> [command options]

conduitscope decode (-r FILE | -i INTERFACE) [-o FILE] [-f text|json|csv] [--protocol auto|modbus|dnp3|s7comm|iec104|enip|profinet|goose|sv|ethercat|bacnet|hartip]
                     [--modbus-port PORT]... [--dnp3-port PORT]... [--s7comm-port PORT]... [--iec104-port PORT]...
                     [--enip-port PORT]... [--enip-io-port PORT]... [--bacnet-port PORT]... [--hartip-port PORT]...
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
| `--protocol {auto,modbus,dnp3,s7comm,iec104,enip,profinet,goose,sv,ethercat,bacnet,hartip}` | `auto` | Restrict decoding to one protocol. `auto` opportunistically tries EtherNet/IP, IEC 104, Modbus, DNP3, S7comm/COTP, and HART-IP detection on every TCP payload, CIP I/O, BACnet/IP, and HART-IP detection on every UDP payload, PROFINET RT (DCP/cyclic) detection on every non-IPv4 Ethernet frame carrying EtherType `0x8892`, GOOSE detection on every non-IPv4 Ethernet frame carrying EtherType `0x88B8`, Sampled Values detection on every non-IPv4 Ethernet frame carrying EtherType `0x88BA`, and EtherCAT detection on every non-IPv4 Ethernet frame carrying EtherType `0x88A4`, regardless of port (see PROTOCOL DETECTION below). `enip` covers both EtherNet/IP explicit messaging (TCP) and CIP I/O implicit messaging (UDP). `profinet` covers both DCP and cyclic real-time IO. `sv` is IEC 61850-9-2 Sampled Values. `ethercat` is EtherCAT. `bacnet` is BACnet/IP. `hartip` is HART-IP (covers both UDP and TCP). |
| `--modbus-port PORT` | *(502 built in)* | Additional TCP port to treat as "expected" for Modbus. Repeatable. Does **not** gate detection -- it only changes whether a decoded Modbus frame is annotated as appearing on an unexpected port, which is itself a useful signal when auditing a conduit. |
| `--dnp3-port PORT` | *(20000 built in)* | Same as `--modbus-port`, for DNP3. Repeatable. |
| `--s7comm-port PORT` | *(102 built in)* | Same as `--modbus-port`, for COTP/S7comm. Repeatable. |
| `--iec104-port PORT` | *(2404 built in)* | Same as `--modbus-port`, for IEC 104. Repeatable. |
| `--enip-port PORT` | *(44818 built in)* | Same as `--modbus-port`, for EtherNet/IP explicit messaging (TCP). Repeatable. |
| `--enip-io-port PORT` | *(2222 built in)* | Same as `--modbus-port`, for EtherNet/IP CIP I/O implicit messaging (UDP). Repeatable. |
| `--bacnet-port PORT` | *(47808 built in)* | Same as `--modbus-port`, for BACnet/IP (UDP). Repeatable. |
| `--hartip-port PORT` | *(5094 built in)* | Same as `--modbus-port`, for HART-IP. Repeatable. Applies to both TCP and UDP, since HART-IP uses the same port number on either transport. |
| `--max-packets N` | `0` (unlimited) | Stop after decoding this many packets. With `-i`, this also bounds a live capture (in addition to `--duration` and Ctrl+C). |
| `--stats` | off | Print an aggregate summary (protocol counts, Modbus function-code histogram, exception count, capture time span) instead of one line per packet. Ignores `--format`. |
| `--strict` | off | Abort with a nonzero exit status on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a per-packet warning and continuing. Does not affect Modbus/DNP3-level ambiguity, which is always handled by heuristic + note rather than error. |

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
    from: <zone name>
    to: <zone name>
    protocols: [<modbus | dnp3 | s7comm | iec104 | enip | any>, <...>]
    ports: [<port>, <...>]                  # omit entirely to mean "any port"
    bidirectional: <true | false>           # default: false
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
ports (or any port, if `ports` is omitted), from one zone to another. At
least one conduit is required -- a policy with zones but zero conduits would
flag every zone-classified flow as a violation, which is almost certainly
not what a first policy file intended, so it's rejected outright rather than
silently accepted as an implicit deny-all.

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

`from`/`to` describe a **direction**: which zone initiates the TCP
connection (`from`) and which zone answers it (`to`) -- not which zone sends
which bytes once the connection is up (a Modbus response, for instance,
flows from the server back to the client, but the conduit is still written
`from: <client zone> to: <server zone>`, matching who dialed whom). Most
real OT conduits are one-directional this way (an HMI/engineering zone
reaching into a control-network zone). Set `bidirectional: true` on a
conduit that should also permit the same protocol/port set initiated the
opposite way.

`ports` restricts which TCP port on the **responding** (server) side of the
connection this conduit covers; omit it to allow any port. A `protocol`
singular alias is also accepted for a conduit that only lists one protocol
(`protocol: modbus` instead of `protocols: [modbus]`), and every list-typed
field (`networks`, `protocols`, `ports`) also accepts a single bare value in
place of a one-element list, for readability on a short policy file.

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
  names a zone that isn't declared in `zones`
- a conduit protocol outside `{modbus, dnp3, s7comm, iec104, enip, any}`
- a conduit port outside `[1, 65535]`
- a conduit's `bidirectional` value that isn't a recognizable boolean
  (`true`/`false`/`yes`/`no`)

### Unsupported YAML constructs

Rejected with a clear error rather than silently misparsed, if encountered:
anchors and aliases (`&x`, `*x`), tags (`!!str`), multi-document streams
(`---`, `...`), block scalars (`|`, `>`), flow mappings (`{a: b}`), and tab
characters used for indentation.

### JSON report schema (`-f json`)

```json
{
  "capture": "capture.pcap",
  "policy": "policy.yaml",
  "zone_count": 2,
  "conduit_count": 3,
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

## PROTOCOL DETECTION

In `--protocol auto` (the default), every non-empty TCP payload is tested
against all six protocols, independent of port number. **EtherNet/IP is
tried first, then IEC 104**, before Modbus/TCP, and **HART-IP is tried
last**, after S7comm/COTP -- see the notes at the end of this section for why
that specific ordering matters, not just which protocols are tried:

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
- **HART-IP**: recognized by its 8-byte fixed header -- the MessageType byte
  must be one of 5 defined values (`0x00`-`0x03`, `0x0F`) *and* the MessageID
  byte must be one of 4 defined values (`0x00`-`0x03`), plus this decoder's
  own added plausibility check that the declared MsgLength field is at least
  8 (the header's own size). This is honestly the weakest structural gate of
  any protocol in this list -- two adjacent bytes each landing on one of a
  handful of small values, versus e.g. EtherNet/IP's three independent
  checks or IEC 104's multi-bit-pattern APCI -- and it is tried **last** in
  this chain, deliberately, precisely because of that weakness: see "Why
  HART-IP is tried last" below.

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

`--protocol modbus`, `--protocol dnp3`, `--protocol s7comm`, `--protocol
iec104`, `--protocol enip`, `--protocol profinet`, `--protocol goose`,
`--protocol sv`, `--protocol ethercat`, `--protocol bacnet`, or `--protocol
hartip` restrict decoding to only that protocol (useful for large mixed
captures, or for scripting a two-pass analysis). `--protocol enip` covers
both EtherNet/IP explicit messaging (TCP, above) and CIP I/O implicit
messaging (UDP, below) -- they're the same overall protocol family.
`--protocol hartip` covers both HART-IP over TCP (above) and over UDP
(below) -- HART-IP uses the identical wire format on either transport.

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
for TCP (MessageType/MessageID/MsgLength) -- HART-IP is the only protocol in
this list that opportunistically checks both transports with the identical
wire format. Unlike the TCP chain, HART-IP is tried on UDP payloads alongside
CIP I/O and BACnet/IP with no ordering concern: the Modbus/TCP collision
described above is a TCP-only artifact (it depends on Modbus's own
declared-length TCP reassembly pre-check, which has no UDP equivalent), so
HART-IP over UDP is checked and decoded exactly like any other well-behaved
protocol here, with no known collision. `--hartip-port` only changes whether
a decoded frame is annotated as appearing on an unexpected port (default
5094), the same as every other per-protocol port option -- it never gates
detection. See PROTOCOL COVERAGE's HART-IP section for exactly what's
decoded once the gate matches.

## OUTPUT FORMATS

### text (default)

One line per packet: index, timestamp, source and destination `ip:port`,
`[protocol]`, and a summary. Any additional notes (heuristic explanations,
port-mismatch warnings, malformed-field warnings) are printed indented below
the packet line.

```
#1  1700000000.000000  192.168.1.50:51000 -> 192.168.1.10:502  [modbus]  Read Holding Registers: request: read 10 holding register(s) starting at address 0
        note: classified as a request because the PDU is exactly 4 bytes (address+quantity); this is a heuristic, not stream tracking
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
`captured_len`, `original_len`, `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`tcp_flags`, `protocol`, `summary`, and `notes` (an array of strings). Fields
that don't apply to a given packet (e.g. `src_ip` for a non-IP frame) are
`null`. Intended to be piped into `jq` or read by a future policy-evaluation
layer.

Seventy-three fields are only present (omitted entirely, not `null`) on
packets where they apply:

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

### csv

Header row followed by one row per packet:
`index,timestamp,src_ip,src_port,dst_ip,dst_port,protocol,summary,notes`.
Fields are quoted per standard CSV rules when they contain a comma, quote, or
newline; multiple notes are joined with ` | ` inside the single `notes` field.

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
header is decoded: source and destination DNP3 addresses, the raw control
byte, and the frame length field (broken down into the resulting
transport/application-layer byte count). The header CRC is present in the
frame but **not validated** in this release, same as every other CRC/checksum
in this release.

On top of the data link layer, conduitscope reassembles the user data (data
link frames split it into <=16-byte blocks, each with its own CRC -- also not
validated, but correctly located and skipped so the bytes above them line up)
and decodes the **transport header** (1 byte: FIR/FIN fragment-boundary flags
and a 6-bit sequence number) for every data-link frame that carries any user
data at all.

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
- **Time and Date** (group 50 variation 1): the 48-bit absolute timestamp, as
  a raw milliseconds-since-epoch count (not converted to a calendar date --
  see LIMITATIONS).
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

The `M2.0`-`M2.4` shape above was later checked against the *entire* 140MB
source capture it came from, not just the five originally spot-checked
requests: over 1 million real `0xB2` items, all through the structural path
with zero fallbacks. That's meaningfully more confidence the structural
shape holds for a full real session, but it's still one real PLC/HMI
session, not several independently different ones -- see
`tests/real_captures/s7comm/ATTRIBUTION.md` for exactly how that traces back
to the same original finding, including a correction of an initial
overclaim (while pulling this data) that it was independent traffic.

**S7comm-Plus** (protocol id `0x72`, the newer, largely undocumented protocol
TIA Portal uses to talk to S7-1200/1500 CPUs) is detected and labeled but not
decoded at all -- its structure is materially different from classic S7comm
(object-oriented addressing, an integrity-protected footer) and out of scope
for this groundwork release.

Also validated against 14 additional real (not synthetic) S7comm captures
from independent sources -- classic S7ANY item decoding up to nearly 9,000
items in one capture, and confirmation the S7comm-Plus stub correctly fires
on real S7-1200/1500 HMI traffic that turned out to use that protocol rather
than classic S7comm despite its naming. See
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
- **Measured values -- normalized, scaled, and short-floating-point** (types
  9/34, 11/35, 13/36): the decoded value (normalized values also show the
  `-1..+1`-range fraction alongside the raw 16-bit integer), quality flags
  (adding `OV` overflow, measured-values-only), and a time tag for the
  `_T_` variants.
- **Integrated totals** (types 15/37): the 32-bit counter value, its 5-bit
  sequence number, and the `CY`(carry)/`CA`(adjusted)/`IV`(invalid) quality
  bits, plus a time tag for the `_TB_` variant.
- **Single, double, and regulating-step commands** (types 45/58, 46/59, 47),
  and **set-point commands -- normalized, scaled, and short-floating-point**
  (types 48/61, 49, 50/63) -- the object used to issue control actions, so
  getting this one right matters more than most: the command state
  (ON/OFF, step up/down, or the set-point value), the 5-bit qualifier
  (no additional definition / short pulse / long pulse / persistent
  output), the Select/Execute bit, and a time tag for the `_T_` variants.
- **End of initialization** (type 70): the cause (local power switch on,
  local manual reset, remote reset) and whether parameters changed.
- **General interrogation** (type 100): station (general) interrogation vs.
  group 1-16 interrogation.
- **Clock synchronization** (type 103): the CP56Time2a timestamp being set.
- **Reset process** (type 105): general reset vs. reset of pending
  time-tagged information.

The SIQ/DIQ/QDS quality-bit layout, the SCO/DCO/RCO command-byte layout, and
the CP24Time2a/CP56Time2a time-tag layout are cross-checked against
lib60870-C's own source and Wireshark's `packet-iec104.c` dissector, not
reverse-engineered from a single capture. A type ID outside the decode table
still gets its ASDU header (type/VSQ/COT/common-address) decoded -- just not
its information objects, which aren't skipped-and-shown the way an
unrecognized DNP3 group/variation is (an ASDU has only one type ID for its
whole object list, so there's no "later header" whose alignment needs
preserving the way DNP3's per-header skip does).

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
  USINT/UINT/UDINT/ULINT/REAL/LREAL/BYTE/WORD/DWORD/LWORD), `Write_Tag`/
  `Write_Tag_Fragmented` (type, element count, and the values being
  written), and `Read_Modify_Write_Tag` (the OR/AND bit masks; its success
  response carries no data, confirmed against a real capture -- see
  `tests/real_captures/enip/ATTRIBUTION.md`).

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
this "first pass" value-decoded set (including every STRING/structured/
UDT/array CIP data type, and every service this decoder doesn't have a
table entry for at all) is still shown structurally -- service name and
request path, response status -- with its data shown as raw hex and an
explicit note that this groundwork release doesn't decode it further,
never guessed at.

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

**Explicitly out of scope, named but shown as raw hex**: commands 77 (I/O
Card/Channel embedded-command relay) and 178 (Batch/aggregate command) are
explicitly named (they're common enough in real gateway traffic -- this
decoder's real capture, see Validation below, contains neither, but they
were named proactively from the command-number table during this decoder's
own research) but not value-decoded, since their own data layout is
gateway/vendor-specific rather than a single fixed HART Universal/
Common-Practice shape. Every other command number outside the list above is
named via the full command-number table when recognized at all, or shown
as a bare number when not -- either way, the data itself is always raw hex
with an explanatory note. A recognized command whose data doesn't match
the expected length (a malformed capture, or simply a command variant this
decoder's first pass doesn't cover) falls back to the same raw-hex-with-note
treatment rather than mis-decoding.

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
  encapsulation message, or TPKT/COTP frame's own bytes, per directional TCP
  flow, when it is split across two or more TCP segments -- so a Modbus PDU
  that straddles a segment boundary, a DNP3 data-link frame split
  mid-header, an IEC 104 APDU split mid-APCI/ASDU, an EtherNet/IP
  encapsulation message split mid-header or mid-CIP-message, or an S7comm
  request/response TPKT frame split across segments all now get fully
  reassembled and decoded, not just the first segment's worth of bytes.
  Each protocol's own declared length field (the MBAP length, the DNP3
  data-link length byte, the IEC 104 APCI length byte, the EtherNet/IP
  encapsulation header's length field, the TPKT length field) is what tells
  the reassembler how many bytes to wait for; a segment
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
  COTP section, and further down in this list).

  DNP3 additionally has its own separate, higher-layer reassembly: an
  *application* fragment that spans multiple complete data-link frames
  (transport FIR=1 on the first, FIN=0 until the last) is buffered per TCP
  flow across however many packets it takes and decoded once FIN=1 arrives;
  see PROTOCOL COVERAGE and `Decoder::process_dnp3_frame`. This layer is
  unvalidated against real traffic: every real DNP3 capture checked so far
  (see tests/real_captures/dnp3/ATTRIBUTION.md) used only complete,
  single-data-link-frame fragments, so it has no real-world example to
  confirm against, only the synthetic fixtures in tests/sample_dnp3.pcap.
  The general TCP-segment-level reassembly described above is unvalidated
  against real traffic for the same reason (every real capture checked kept
  every PDU/frame within one TCP segment, including all six real IEC 104
  captures and both real EtherNet/IP captures -- see
  tests/real_captures/iec104/ATTRIBUTION.md and
  tests/real_captures/enip/ATTRIBUTION.md) -- it was verified by diffing this
  tool's full output against every real fixture before and after adding it
  (byte-for-byte identical), confirming it changes nothing for traffic that
  doesn't need it, and by synthetic fixtures (tests/sample_tcp_reassembly.pcap)
  for the reassembly itself. It's also distinct from multiple *complete*
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
  the same "surfaced raw, never checked" posture DNP3's own CRCs get (see
  below): computing/verifying it would need the HART XOR algorithm applied
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
- **DNP3 CRCs are not validated** -- neither the data-link header CRC nor the
  per-block CRCs within the user data. A corrupted DNP3 frame that still
  starts with the right magic bytes will be "decoded" without any indication
  a CRC was wrong; the block CRCs are correctly *located and skipped* (so
  reassembly lines up) but their contents are never checked.
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
  variants) are shown as a raw milliseconds-since-epoch count, not a
  calendar date.** Converting correctly needs UTC-safe 64-bit time handling
  this tool doesn't otherwise depend on, and a subtly wrong date would be
  worse than an honest millisecond count in a security-auditing tool.
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
  + path + raw hex) instead. Within the decoded element types, only the
  fixed-size numeric elementary types (BOOL/SINT/INT/DINT/LINT/USINT/UINT/
  UDINT/ULINT/REAL/LREAL/BYTE/WORD/DWORD/LWORD) are value-decoded --
  STRING/SHORT_STRING and every structured/UDT/array type are recognized by
  code but shown as raw hex with an explicit note, not guessed at (Logix5000's
  exact bit-level convention for distinguishing a structured-type response
  from an elementary one could not be confirmed against authoritative
  documentation during this feature's research, so no special-casing was
  attempted for it -- see the ROADMAP). A bare CIP response's Read_Tag(
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
- **S7comm-Plus (protocol id 0x72) is detected but never decoded.**
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
  unlike `decode`, which now also decodes one UDP-based protocol (CIP I/O,
  see PROTOCOL COVERAGE). A policy can't reference a UDP service, a MAC
  address, or a hostname, and non-TCP/non-IP packets -- including CIP I/O
  traffic -- are counted (`skipped_non_tcp` in the JSON report) but never
  evaluated against any conduit.
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
3. S7comm-Plus decoding, and PLC Control/Stop parameter decoding (these
   send commands that change PLC run state -- high security relevance).
4. **DNP3 CRC validation** (both the header CRC and the per-block CRCs), so a
   corrupted frame that still starts with the right magic bytes is flagged
   rather than silently "decoded".
5. **DNP3 absolute-time rendering as a calendar date** (currently a raw
   milliseconds-since-epoch count -- see LIMITATIONS), and value decoding for
   the group/variation combinations still outside the point-format table
   (double-precision Analog Input Event variants, Octet String, File
   Control, Analog Input Reporting Deadband).
6. **A policy `from`/`to` zone list wider than two endpoints per conduit**
   (e.g. "any of these three zones may reach this one"), if real policy
   files turn out to want that instead of one conduit per zone pair -- kept
   off the schema for now rather than guessed at ahead of a real use case.
7. **Extend IEC 104's information-element decode table** to the type IDs it
   currently only structurally recognizes (ASDU header decoded, objects
   not) -- step position (types 5/32), bitstring (types 7/33), packed
   single-point-with-status-change-detection, parameter-setting commands,
   file transfer, and full counter-interrogation (type 101)/read (102)
   command decoding. The Wireshark wiki sample capture's general
   interrogation response happens to cycle through several of these (see
   `tests/real_captures/iec104/ATTRIBUTION.md`), so real-traffic validation
   for at least step position and bitstring is already sitting there,
   waiting on the decode table catching up.
8. **Extend EtherNet/IP's CIP value decoding to STRING/SHORT_STRING and
   structured (UDT/array) elementary types** -- currently shown as raw hex
   with an explicit note (see PROTOCOL COVERAGE and LIMITATIONS). The
   structured-type case specifically needs confirming Logix5000's exact
   bit-level convention for telling a structured-type Read_Tag response
   apart from an elementary one against authoritative documentation (not
   confirmed during this feature's research -- see LIMITATIONS); STRING/
   SHORT_STRING's wire format is better-documented and could reasonably come
   first. Also worth revisiting once real-world evidence exists: whether the
   symbolic-path-gating gate itself (see PROTOCOL COVERAGE) is ever too
   narrow in practice -- e.g. a real device addressing a Symbol-object tag
   by numeric instance ID rather than by name, which this release's gating
   would currently show structurally rather than as a tag read.
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

10. **Extend HART-IP's command value-decode table** beyond the "first pass"
    set (see PROTOCOL COVERAGE) -- commands 77 and 178 in particular, since
    they're common enough in real gateway traffic to have been named
    proactively even though no real capture found so far happens to carry
    either. Also: verify the HART Data-Link Checksum (the XOR algorithm
    across the whole PDU, currently surfaced raw and never checked -- see
    LIMITATIONS); resolve multi-definition/warning-class Response Codes to
    their actual per-command meaning, if a reliable source for enough
    individual commands' own spec text ever turns up; and widen real-capture
    validation to Error/NAK messages, the BACK frame type, non-Success
    response codes, and the ten-plus commands the one real capture found for
    this feature doesn't happen to exercise (see
    `tests/real_captures/hartip/ATTRIBUTION.md`'s own "Gaps" section).

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
Symbol-object tag services) -- see PROTOCOL COVERAGE's EtherNet/IP section
and item 8 above for what's still out of scope (STRING/structured/UDT/array
value decoding). EtherNet/IP detection runs first in Auto-mode dispatch,
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

MIT. See [LICENSE](../LICENSE).
