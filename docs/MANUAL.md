# conduitscope(1) -- Manual

## NAME

conduitscope -- decode Modbus/TCP, DNP3, and S7comm/COTP traffic from offline pcap captures

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
  This is documented in the decoded output as a heuristic -- it is not based
  on tracking the TCP stream's request/response state, since this release
  does not do stream reassembly.
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

Five fields are only present (omitted entirely, not `null`) on packets where
they apply:

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

The **application layer** -- function code, Internal Indications (IIN) on
responses, and every object header's group/variation/qualifier/range -- is
then decoded, but only for a fragment that is complete within a single
data-link frame (transport FIR=1 and FIN=1, which covers the large majority
of real traffic, especially requests). A fragment that continues across
multiple data-link frames (FIR=1, FIN=0) gets its transport header decoded
and nothing more -- reassembling application data across several TCP-carried
data-link frames would need the same kind of cross-packet state tracking as
TCP stream reassembly (see LIMITATIONS), which this tool does not do.

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
`0xB2` finding described above.

**Modbus/TCP** is likewise validated against real (not synthetic) captures
now, not just the hand-built fixtures -- a clean Read Holding Registers
session, and traffic exercising several function codes outside current scope
(Diagnostics, Report Server ID, Read Exception Status, and others) that must
degrade to a "not decoded" note rather than be misparsed. See
`tests/real_captures/modbus/ATTRIBUTION.md`.

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
  In practice this is rare for Modbus (PDUs are small); for DNP3, the same
  limitation shows up as an application fragment that spans more than one
  data-link frame (transport FIR=1, FIN=0) getting only its transport header
  decoded, not its application layer -- see PROTOCOL COVERAGE.
- **No IPv6.** Only IPv4 is parsed; IPv6 packets are reported as
  `unsupported-link`/`non-ip` depending on where they're detected.
- **IPv4 fragmentation is not reassembled.** A fragmented IPv4 packet's TCP
  header will very likely fail to parse and be reported as a parse-error on
  the fragments after the first.
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
  transport header decoded**, not its application layer -- see the note
  under "No TCP stream reassembly" above.
- **Modbus request/response classification is heuristic**, based on PDU shape
  (see PROTOCOL DETECTION), not on tracking the TCP stream's actual
  request/response pairing. It is reliable in practice for the read/write
  function families this release decodes, but it is not authoritative.
- **Modbus/TCP detection itself is a heuristic, and can still false-positive
  in principle.** Modbus/TCP has no magic bytes; detection requires
  protocol-id==0 and a non-zero function code, which rules out the false
  positive actually observed in a real capture (non-Modbus traffic on port
  20000) but cannot rule out every possible coincidence -- a payload from
  some other protocol could still, in principle, satisfy both checks. Treat
  an isolated, otherwise-implausible Modbus packet (especially on a
  non-standard port, which is flagged in the output) with appropriate
  skepticism.
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
  | jq -r '.[] | select(.s7comm_items) | "\(.src_ip) -> \(.dst_ip): \(.s7comm_items | join(", "))"'
```

See which DNP3 function codes and object groups/variations flow over a
capture, e.g. to spot an unsolicited response or a write/operate/direct
operate you weren't expecting on a conduit:

```sh
conduitscope decode -i capture.pcap --protocol dnp3 -f json \
  | jq -r '.[] | select(.dnp3_function) | "\(.src_ip) -> \(.dst_ip): \(.dnp3_function) \(.dnp3_objects // [] | join(", "))"'
```

Find every CROB output command in a capture -- who issued it, and exactly
what it commanded:

```sh
conduitscope decode -i capture.pcap --protocol dnp3 -f json \
  | jq -r '.[] | select(.dnp3_values) | .src_ip as $s | .dst_ip as $d |
           (.dnp3_values[] | select(startswith("g12v1"))) | "\($s) -> \($d): \(.)"'
```

## ROADMAP

Rough order, each building on the groundwork this release establishes:

1. **TCP stream reassembly**, needed for split PDUs, authoritative
   (non-heuristic) Modbus request/response pairing, multi-segment S7comm
   frames larger than one negotiated PDU length, and DNP3 application
   fragments that span more than one data-link frame (currently left with
   only their transport header decoded -- see LIMITATIONS).
2. **Zone/conduit policy engine** behind `policy validate`: a YAML schema
   describing zones (IP/port ranges, expected protocols) and conduits (allowed
   flows between zones), evaluated against decoded traffic, producing a
   pass/fail report suitable for a NIS2/62443 audit trail. S7comm item tags,
   decoded DNP3 point values (especially CROB commands), and Modbus
   address+quantity decoding all now give this something concrete to match a
   policy's address ranges and expected-value rules against.
3. **Live capture**, via libpcap on Linux and Npcap on Windows, as an
   additional input mode alongside (not replacing) pcap file input.
4. **pcapng support**, once live capture or another concrete need makes it
   worth the added parsing complexity.
5. Colorized text output (the `--no-color` flag is already reserved for this).
6. **Confirm or replace the EXPERIMENTAL `0xB2` (S7-1200/1500 "symbolic"
   addressing) decode** against a source with real authority -- a PLC or
   TIA Portal project under your own control, ideally, rather than more
   public reverse-engineering writeups -- and extend it to the shapes it
   currently falls back to raw hex on: DB-area items, and items with more
   than one LID entry (structured/nested symbol access). Promote it out of
   [EXPERIMENTAL] once confirmed.
7. S7comm-Plus decoding, and PLC Control/Stop parameter decoding (these
   send commands that change PLC run state -- high security relevance).
8. **DNP3 CRC validation** (both the header CRC and the per-block CRCs), so a
   corrupted frame that still starts with the right magic bytes is flagged
   rather than silently "decoded".
9. **DNP3 absolute-time rendering as a calendar date** (currently a raw
   milliseconds-since-epoch count -- see LIMITATIONS), and value decoding for
   the group/variation combinations still outside the point-format table
   (double-precision Analog Input Event variants, Octet String, File
   Control, Analog Input Reporting Deadband).

## BUILDING

See [README.md](../README.md) for full Linux/Windows build instructions. In
short: CMake >= 3.16, a C++17 compiler, no other dependencies (CLI11 is
vendored under `third_party/`).

## LICENSE

MIT. See [LICENSE](../LICENSE).
