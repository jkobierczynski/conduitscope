# conduitscope(1) -- Manual

## NAME

conduitscope -- decode Modbus/TCP and DNP3 traffic from offline pcap captures

## SYNOPSIS

```
conduitscope [-q|--quiet] [--no-color] [--log-file FILE] [--version] [-h|--help] <command> [command options]

conduitscope decode -i FILE [-o FILE] [-f text|json|csv] [--protocol auto|modbus|dnp3|s7comm]
                     [--modbus-port PORT]... [--dnp3-port PORT]... [--s7comm-port PORT]...
                     [--max-packets N] [--stats] [--strict]

conduitscope info -i FILE

conduitscope policy validate -i FILE --policy FILE

conduitscope version
```

## DESCRIPTION

conduitscope reads a classic-format pcap capture file, walks each packet's
Ethernet/IPv4/TCP headers, and attempts to recognize and decode Modbus/TCP,
DNP3, or S7comm (Siemens S7 PLC protocol, riding on TPKT/COTP) payloads
inside the TCP stream. It is designed as groundwork for auditing
OT/ICS network traffic against a zone-and-conduit segmentation model (the kind
IEC 62443-3-2 and, by extension, NIS2 risk-assessment work call for) -- today
it gives you the protocol-decoding layer that such an audit needs; the policy
evaluation layer itself is scaffolded (`policy validate`) but not yet
implemented (see ROADMAP below).

This is explicitly a groundwork/v0.1.0 release. It favors an honest, narrow
feature set with clearly documented limitations over silently guessing at
things it can't verify. Where the tool is inferring something heuristically
(such as whether a Modbus PDU is a request or a response) rather than tracking
it authoritatively, the output says so.

### Why offline pcap files, not live capture

Reading `.pcap` files rather than capturing live traffic means conduitscope has
*zero* external dependencies: no libpcap on Linux, no Npcap SDK/driver on
Windows, and no elevated/administrator privileges to build or run. You capture
with whatever is already on your system (tcpdump, dumpcap, Wireshark) and
decode separately. This was a deliberate sequencing choice for a first release
that has to build cleanly on both Windows and Linux with nothing but a C++17
compiler and CMake. Live capture is a reasonable phase-2 addition once this
groundwork is solid; see ROADMAP.

### pcap vs. pcapng

conduitscope reads **classic pcap** (the format tcpdump writes by default, and
what `tshark -F pcap` / Wireshark's "Save As > Wireshark/tcpdump/... - pcap"
produce). It does **not** yet read **pcapng** (the newer block-structured
format some tools default to, including recent Wireshark). If you point it at
a pcapng file it will tell you so explicitly and suggest the conversion:

```sh
tshark -F pcap -r capture.pcapng -w capture.pcap
```

## GLOBAL OPTIONS

These apply regardless of which subcommand is used, and must appear before the
subcommand name on the command line (standard CLI11 behavior).

| Option | Description |
|---|---|
| `-h, --help` | Print help and exit. |
| `--version` | Print version, compiler, platform, and build type, then exit. |
| `-q, --quiet` | Suppress non-essential diagnostic/warning output (e.g. per-packet parse warnings). Decoded output itself is unaffected. |
| `--no-color` | Disable ANSI color in `text`-format output. (Reserved: color highlighting itself is not yet implemented -- see ROADMAP -- so this currently has no visible effect, but the flag exists now so scripts that set it won't need updating later.) |
| `--log-file FILE` | Write diagnostic/warning messages to `FILE` (append mode) instead of stderr. Decoded output (stdout, or `-o`) is unaffected. |

## COMMANDS

### `decode` -- decode a capture and print each recognized packet

```
conduitscope decode -i FILE [options]
```

| Option | Default | Description |
|---|---|---|
| `-i, --input FILE` | *(required)* | Input pcap file. Must exist; must be classic pcap format. |
| `-o, --output FILE` | stdout | Write decoded output here instead of stdout. |
| `-f, --format {text,json,csv}` | `text` | Output format. See OUTPUT FORMATS below. |
| `--protocol {auto,modbus,dnp3,s7comm}` | `auto` | Restrict decoding to one protocol. `auto` opportunistically tries Modbus, DNP3, and S7comm/COTP detection on every TCP payload, regardless of port (see PROTOCOL DETECTION below). |
| `--modbus-port PORT` | *(502 built in)* | Additional TCP port to treat as "expected" for Modbus. Repeatable. Does **not** gate detection -- it only changes whether a decoded Modbus frame is annotated as appearing on an unexpected port, which is itself a useful signal when auditing a conduit. |
| `--dnp3-port PORT` | *(20000 built in)* | Same as `--modbus-port`, for DNP3. Repeatable. |
| `--s7comm-port PORT` | *(102 built in)* | Same as `--modbus-port`, for COTP/S7comm. Repeatable. |
| `--max-packets N` | `0` (unlimited) | Stop after decoding this many packets. |
| `--stats` | off | Print an aggregate summary (protocol counts, Modbus function-code histogram, exception count, capture time span) instead of one line per packet. Ignores `--format`. |
| `--strict` | off | Abort with a nonzero exit status on the first packet that fails to parse at the Ethernet/IPv4/TCP layer, instead of reporting a per-packet warning and continuing. Does not affect Modbus/DNP3-level ambiguity, which is always handled by heuristic + note rather than error. |

### `info` -- print pcap file metadata and a protocol histogram

```
conduitscope info -i FILE
```

| Option | Default | Description |
|---|---|---|
| `-i, --input FILE` | *(required)* | Input pcap file. |

Prints the pcap format version, link type, snaplen, timestamp resolution, and
then the same protocol/function-code histogram as `decode --stats`, without
requiring you to also specify `--stats` explicitly. Useful as a first look at
an unfamiliar capture before deciding whether/how to filter it with `decode`.

### `policy validate` -- zone/conduit policy check [not yet implemented]

```
conduitscope policy validate -i FILE --policy POLICY_FILE
```

| Option | Default | Description |
|---|---|---|
| `-i, --input FILE` | *(required)* | Input pcap file. |
| `--policy FILE` | *(required)* | Zone/conduit policy file (YAML; format not yet defined). |

This command is intentionally scaffolded now, with its final option names
already in place, even though the evaluation engine behind it does not exist
yet. Running it prints a clear "not implemented" message (and the arguments it
was given, for sanity-checking) and exits with status `2`. The intent is that
anything you script against `policy validate` today (argument names, exit
code semantics) stays stable once phase 2 lands. See ROADMAP.

### `version` -- print version and build information

Equivalent to the global `--version` flag; provided as a subcommand as well
for scripts that prefer `conduitscope version` over a flag.

## PROTOCOL DETECTION

In `--protocol auto` (the default), every non-empty TCP payload is tested
against all three protocols, independent of port number:

- **Modbus/TCP**: recognized by its MBAP header shape -- specifically, the
  protocol-id field at byte offset 2-3 must be `0x0000`, which is mandated by
  the Modbus spec and essentially never appears by coincidence in other
  traffic. If matched, request-vs-response is then further disambiguated by
  PDU shape (a bare 4-byte address+quantity looks like a request; a
  byte-count-prefixed blob looks like a response). This is documented in the
  decoded output as a heuristic -- it is not based on tracking the TCP stream's
  request/response state, since this release does not do stream reassembly.
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

`--protocol modbus`, `--protocol dnp3`, or `--protocol s7comm` restrict
decoding to only that protocol (useful for large mixed captures, or for
scripting a two-pass analysis).

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

### json

A JSON array, one object per packet, with fields `index`, `timestamp`,
`captured_len`, `original_len`, `src_ip`, `dst_ip`, `src_port`, `dst_port`,
`tcp_flags`, `protocol`, `summary`, and `notes` (an array of strings). Fields
that don't apply to a given packet (e.g. `src_ip` for a non-IP frame) are
`null`. Intended to be piped into `jq` or read by a future policy-evaluation
layer.

Three fields are only present (omitted entirely, not `null`) on packets where
they apply:

- `s7comm_function`: the S7comm function name (`"Read Var"`, `"Write Var"`,
  `"Setup Communication"`, ...), when protocol is `s7comm` and a function
  code was decoded.
- `s7comm_items`: an array of Step 7-style item tags (`"DB10.DBW100"`,
  `"I0.0"`, ...), on Read Var / Write Var *request* packets whose item
  addressing was decoded (see PROTOCOL COVERAGE).
- `s7comm_values`: an array of short value renderings (a hex string, `"0"`/
  `"1"` for a decoded bit, or a return-code name like `"Object does not
  exist"`), on Read Var / Write Var *response* packets, and alongside
  `s7comm_items` on Write Var request packets (the values being written).

Both array fields are capped at 50 entries for a single heavily-batched
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

### DNP3

Detected reliably (via the 0x05 0x64 start bytes) and its data-link-layer
header is decoded: source and destination DNP3 addresses, the raw control
byte, and the frame length field (broken down into the resulting
transport/application-layer byte count). The header CRC is present in the
frame but **not validated** in this release. Everything past the data link
layer -- transport-layer segmentation, and the application layer's
object-group/variation/function-code structure that carries the actual
point values -- is explicitly not decoded; the output says so rather than
guessing.

### S7comm / COTP (Siemens S7 PLCs, TCP port 102)

The TPKT (RFC 1006) and COTP (ISO 8073 / X.224) framing that S7comm always
rides on is decoded in full: the TPKT length, the COTP PDU type (Data,
Connection Request, Connection Confirm, Disconnect Request/Confirm, or an
"other" catch-all), and -- for Connection Request/Confirm, which carry the
TSAP session-setup parameters rather than S7comm itself -- the calling and
called TSAP values. A packet that parses at this level but doesn't turn out
to carry S7comm is reported as protocol `cotp` rather than `s7comm`.

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
full list is always in the decoded packet's notes. Other addressing syntaxes
are recognized as items (by syntax id) but not decoded -- shown as raw hex,
same as every other function code's parameter/data payload. The one you're
most likely to actually see is `0xB2`, S7-1200/1500 "symbolic" addressing --
confirmed present in real capture traffic during this feature's development,
and cross-checked against Wireshark's own `S7COMM_SYNTAXID_1200SYM` constant.
Its item format references a compiled symbol-table entry (an opaque CRC-like
value plus one or more "LID" fields) rather than a plain byte/bit address,
and reconstructing that format with real confidence from public sources
wasn't achievable in the time available -- see LIMITATIONS and ROADMAP. So is
the entire Userdata parameter block used for vendor-specific diagnostics/CPU
functions.

**S7comm-Plus** (protocol id `0x72`, the newer, largely undocumented protocol
TIA Portal uses to talk to S7-1200/1500 CPUs) is detected and labeled but not
decoded at all -- its structure is materially different from classic S7comm
(object-oriented addressing, an integrity-protected footer) and out of scope
for this groundwork release.

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

- **pcapng is not supported.** Convert with `tshark -F pcap -r in.pcapng -w out.pcap`.
- **No TCP stream reassembly.** A Modbus or DNP3 PDU split across two TCP
  segments will not be reassembled; each TCP segment is decoded independently.
  In practice this is rare for Modbus (PDUs are small) and more of a concern
  for DNP3 (multi-block application-layer fragments), which is one more reason
  the DNP3 application layer isn't decoded yet.
- **No IPv6.** Only IPv4 is parsed; IPv6 packets are reported as
  `unsupported-link`/`non-ip` depending on where they're detected.
- **IPv4 fragmentation is not reassembled.** A fragmented IPv4 packet's TCP
  header will very likely fail to parse and be reported as a parse-error on
  the fragments after the first.
- **DNP3 CRCs are not validated.** A corrupted DNP3 frame that still starts
  with the right magic bytes will be "decoded" without any indication the CRC
  was wrong.
- **Modbus request/response classification is heuristic**, based on PDU shape
  (see PROTOCOL DETECTION), not on tracking the TCP stream's actual
  request/response pairing. It is reliable in practice for the read/write
  function families this release decodes, but it is not authoritative.
- **S7comm item-level addressing only covers the classic S7ANY syntax.**
  Read Var / Write Var items using other addressing syntaxes -- most
  notably `0xB2` (S7-1200/1500 "symbolic" addressing, which real captures
  during development showed is common) -- are recognized by syntax id but
  shown as raw hex, not decoded into an area/address/transport size. That
  syntax's item format resolves a compiled symbol-table entry (a CRC-like
  value plus "LID" fields) rather than a plain byte/bit address, and doing
  it justice needs firmer sourcing than was available in the time spent on
  it here; see ROADMAP. The Userdata ROSCTR (vendor-specific diagnostics/
  CPU functions) is entirely unparsed beyond being labeled.
- **A few S7comm data-item transport sizes use a best-effort length
  interpretation.** The two overwhelmingly common cases (BIT, and
  BYTE/WORD/DWORD-family reads/writes) are decoded with high confidence
  against the documented wire format; the rarer transport sizes (DINT,
  REAL, OCTET STRING, and a few others) fall back to treating the length
  field as a byte count directly, flagged with a note when it's used.
- **S7comm-Plus (protocol id 0x72) is detected but never decoded.**
- **No live capture.** Offline pcap files only; see the top of this document
  for why, and ROADMAP for the plan to add it.
- **`policy validate` does nothing yet** beyond validating its own arguments
  and printing a placeholder message. See ROADMAP.
- **QinQ (stacked 802.1Q) VLAN tags are not unwrapped**, only a single tag.

## EXIT STATUS

| Code | Meaning |
|---|---|
| 0 | Success. |
| 1 | A fatal error occurred -- bad arguments, the input file could not be opened, the file is not a recognized pcap (including the pcapng case), or (with `--strict`) a packet failed to parse. |
| 2 | The command is a documented stub (`policy validate`) that ran successfully but performed no real work. |

Non-fatal per-packet parse issues (without `--strict`) do not affect the exit
status; they are reported as warnings (to stderr, or `--log-file`) and as
`"protocol": "parse-error"` entries in the decoded output itself.

## EXAMPLES

Decode a capture as human-readable text:

```sh
conduitscope decode -i capture.pcap
```

Get just the aggregate picture of what's in a large capture before deciding
how to filter it:

```sh
conduitscope info -i capture.pcap
```

Pull out only the Modbus exception responses, as JSON, using `jq`:

```sh
conduitscope decode -i capture.pcap --protocol modbus -f json \
  | jq '.[] | select(.summary | test("^Read|^Write") | not)'
```

Note ports that carry Modbus traffic your zone policy doesn't expect on 502:

```sh
conduitscope decode -i capture.pcap --protocol modbus --modbus-port 502 -f text \
  | grep -A1 "not a configured/standard Modbus port"
```

Stop early on a very large capture while you're iterating on a filter:

```sh
conduitscope decode -i capture.pcap --max-packets 500
```

See which S7 sessions get established and what function codes flow over
them, on a capture that mixes S7comm with other traffic:

```sh
conduitscope decode -i capture.pcap --protocol s7comm --stats
```

See exactly which PLC memory addresses are being read and written -- the
item tags conduitscope decoded, one line per Read Var / Write Var packet:

```sh
conduitscope decode -i capture.pcap --protocol s7comm -f json \
  | jq -r 'select(.s7comm_items) | "\(.src_ip) -> \(.dst_ip): \(.s7comm_items | join(", "))"'
```

## ROADMAP

Rough order, each building on the groundwork this release establishes:

1. **DNP3 application layer.** Decode object groups/variations and function
   codes once there's been hands-on time with real DNP3 traffic (see the
   reading list this project's groundwork discussion produced -- the DNP3
   Primer and Wireshark walkthroughs are the natural next reference material).
2. **TCP stream reassembly**, needed for split PDUs, authoritative
   (non-heuristic) Modbus request/response pairing, and multi-segment S7comm
   frames larger than one negotiated PDU length.
3. **Zone/conduit policy engine** behind `policy validate`: a YAML schema
   describing zones (IP/port ranges, expected protocols) and conduits (allowed
   flows between zones), evaluated against decoded traffic, producing a
   pass/fail report suitable for a NIS2/62443 audit trail. S7comm item tags
   and Modbus address+quantity decoding both now give this something concrete
   to match a policy's address ranges against.
4. **Live capture**, via libpcap on Linux and Npcap on Windows, as an
   additional input mode alongside (not replacing) pcap file input.
5. **pcapng support**, once live capture or another concrete need makes it
   worth the added parsing complexity.
6. Colorized text output (the `--no-color` flag is already reserved for this).
7. S7comm-Plus decoding, PLC Control/Stop parameter decoding (these send
   commands that change PLC run state -- high security relevance), and the
   S7-1200/1500 "symbolic" addressing syntax (`0xB2`) that item-level
   decoding currently recognizes but doesn't decode -- worth revisiting
   with more time to pin down its CRC/LID item format from a source firmer
   than public reverse-engineering writeups, since real captures show it's
   common on S7-1200/1500 traffic specifically (i.e. newer PLCs).

## BUILDING

See [README.md](../README.md) for full Linux/Windows build instructions. In
short: CMake >= 3.16, a C++17 compiler, no other dependencies (CLI11 is
vendored under `third_party/`).

## LICENSE

MIT. See [LICENSE](../LICENSE).
