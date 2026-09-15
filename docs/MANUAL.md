# conduitscope(1) -- Manual

## NAME

conduitscope -- decode Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP, and EtherNet/IP (CIP explicit messaging) traffic from offline pcap captures

## SYNOPSIS

```
conduitscope [-q|--quiet] [--no-color|--color] [--log-file FILE] [--version] [-h|--help] <command> [command options]

conduitscope decode (-r FILE | -i INTERFACE) [-o FILE] [-f text|json|csv] [--protocol auto|modbus|dnp3|s7comm|iec104|enip]
                     [--modbus-port PORT]... [--dnp3-port PORT]... [--s7comm-port PORT]... [--iec104-port PORT]...
                     [--enip-port PORT]...
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
Ethernet/IPv4/TCP headers, and attempts to recognize and decode Modbus/TCP,
DNP3, IEC 60870-5-104, S7comm (Siemens S7 PLC protocol, riding on
TPKT/COTP), or EtherNet/IP (CIP explicit messaging) payloads inside the TCP stream. It is designed as groundwork for auditing
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
| `--protocol {auto,modbus,dnp3,s7comm,iec104,enip}` | `auto` | Restrict decoding to one protocol. `auto` opportunistically tries EtherNet/IP, IEC 104, Modbus, DNP3, and S7comm/COTP detection on every TCP payload, regardless of port (see PROTOCOL DETECTION below). |
| `--modbus-port PORT` | *(502 built in)* | Additional TCP port to treat as "expected" for Modbus. Repeatable. Does **not** gate detection -- it only changes whether a decoded Modbus frame is annotated as appearing on an unexpected port, which is itself a useful signal when auditing a conduit. |
| `--dnp3-port PORT` | *(20000 built in)* | Same as `--modbus-port`, for DNP3. Repeatable. |
| `--s7comm-port PORT` | *(102 built in)* | Same as `--modbus-port`, for COTP/S7comm. Repeatable. |
| `--iec104-port PORT` | *(2404 built in)* | Same as `--modbus-port`, for IEC 104. Repeatable. |
| `--enip-port PORT` | *(44818 built in)* | Same as `--modbus-port`, for EtherNet/IP. Repeatable. |
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
against all five protocols, independent of port number. **EtherNet/IP is
tried first, then IEC 104**, before Modbus/TCP -- see the notes at the end of
this section for why that specific ordering matters, not just which
protocols are tried:

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

`--protocol modbus`, `--protocol dnp3`, `--protocol s7comm`, `--protocol
iec104`, or `--protocol enip` restrict decoding to only that protocol (useful
for large mixed captures, or for scripting a two-pass analysis).

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
COTP-without-S7comm, green for IEC 104, yellow for EtherNet/IP, dim for everything else recognized but not
OT-specific (`tcp`/`non-tcp`/`non-ip`/`unsupported-link`). A Modbus
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

Seventeen fields are only present (omitted entirely, not `null`) on packets
where they apply:

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
  `"RegisterSession"`, `"SendRRData"`), when protocol is `enip`. Reflects
  only the *first* EtherNet/IP message found in this TCP payload -- see
  `notes` for any additional coalesced messages (PROTOCOL COVERAGE).
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

All array fields are capped at 50 entries for a single heavily-batched
request/response; see PROTOCOL COVERAGE for where the full list still shows
up when a packet has more items than that.

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

### EtherNet/IP (CIP explicit messaging, TCP port 44818)

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

### Link/IP-layer plumbing: non-IPv4 Ethernet, and non-TCP IPv4 (including UDP)

Every protocol above rides on Ethernet + IPv4 + TCP. Traffic outside that --
a non-IPv4 Ethernet frame, or a non-TCP IPv4 payload -- was previously
reported only as a bare hex ethertype or protocol number (`non-ip`/
`non-tcp`) and otherwise dropped. It's now additionally **named**, for a
deliberately small, OT-relevant set of values, cross-checked against
Wireshark's own `epan/etypes.h` (EtherTypes) and the long-stable IANA IP
protocol number registry (not reverse-engineered from a single capture):

- **EtherTypes** (`link_layer.hpp`'s `ethertype_name`): ARP, IPv6, three
  raw-Ethernet (no IP layer at all) OT protocols -- PROFINET RT, EtherCAT,
  IEC 61850-8-1 GOOSE, IEC 61850-9-2 Sampled Values -- plus LLDP, PTP
  (IEEE 1588), MPLS unicast, and 802.1ad/stacked-VLAN (the QinQ case
  `parse_ethernet`'s own comment already documented as "will simply fail to
  recognize the inner ethertype" -- it's now named as such instead of a bare
  `0x8100`).
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
  UDP port (2222, CIP implicit/real-time I/O messaging -- distinct from the
  TCP 44818 explicit messaging this tool decodes) is called out by name in
  the summary when seen.

**This is groundwork plumbing, explicitly not a new protocol decoder.**
None of PROFINET/GOOSE/Sampled Values/EtherCAT/EtherNet-IP-implicit's own
framing is parsed -- these EtherTypes/ports are *named*, not *decoded*, and
the summary says so for UDP ("not decoded in this groundwork release"). A
value outside every table above still shows only as a bare hex ethertype or
decimal protocol number, exactly as before -- nothing is guessed at for an
EtherType/protocol/port this tool doesn't recognize.

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
  named but not decoded.** A deliberately small, OT-relevant set of
  EtherTypes/IP-protocol-numbers/UDP-ports is recognized by name (ARP,
  PROFINET RT, IEC 61850 GOOSE/Sampled Values, ICMP, EtherNet/IP's own UDP
  port for implicit/I-O messaging, and the rest -- see PROTOCOL COVERAGE);
  nothing outside that set gets more than a bare hex/decimal number, and
  even a *named* one gets no further parsing of its own framing. `policy
  validate` does not yet evaluate any of this traffic against a conduit --
  see that section and ROADMAP.
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
  IPv4-only limitation in this document) and, like everything else this tool
  decodes, TCP-only -- a policy can't reference a UDP service, a MAC address,
  or a hostname, and non-TCP/non-IP packets are counted (`skipped_non_tcp` in
  the JSON report) but never evaluated against any conduit.
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
9. **Decode a real protocol over UDP or raw Ethernet**, now that the
   link/IP-layer plumbing to see that traffic at all exists (see PROTOCOL
   COVERAGE's link/IP-layer plumbing section and the "now done" paragraph
   below) -- most likely EtherNet/IP's own implicit (I/O) messaging on UDP
   port 2222, a direct extension of the CIP explicit-messaging work already
   done, or one of the named-but-undecoded raw-Ethernet protocols
   (PROFINET RT, IEC 61850 GOOSE) if real capture availability favors one of
   those first. Each is its own research-and-validate cycle, same as every
   protocol added so far -- naming an EtherType/port is not the same
   groundwork as decoding what rides on it. Also the natural point to widen
   `policy validate` beyond TCP-only conduits, once there's an actual
   decoded non-TCP protocol worth checking a conduit against.

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
EtherTypes/IP-protocol-numbers/UDP-ports (ARP, PROFINET RT, IEC 61850
GOOSE/Sampled Values, ICMP, EtherNet/IP's own UDP implicit-messaging port,
and the rest), rather than just a bare hex/decimal number and nothing else
-- see PROTOCOL COVERAGE's link/IP-layer plumbing section and item 9 above
for what's still out of scope: this is naming, not decoding, of any new
protocol, and `policy validate` doesn't yet evaluate any of it against a
conduit.

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
