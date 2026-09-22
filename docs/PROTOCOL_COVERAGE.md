# conduitscope -- Protocol Coverage Reference

The full per-protocol reference for `conduitscope`: for every protocol it
recognizes, what wire-format signal is checked, what fields are actually
decoded vs. merely named, and -- honestly stated in every case -- how much
confidence that detection deserves (a genuine multi-field structural match
like DHCP's magic cookie, versus a port-only fallback like LWAPP's, with
everything in between). This is the reference to check before citing a
`decode` finding in an audit report.

See **[USER_GUIDE.md](USER_GUIDE.md)** for command syntax, options, the
policy file format, and output formats -- this document assumes you
already know how to run `conduitscope decode` and just need to know what a
given `[protocol]` tag means and how far to trust it. See
**[DEVELOPMENT.md](DEVELOPMENT.md)** for *why* protocols are tried in the
order they are and how cross-protocol detection collisions are resolved
(docs/DEVELOPMENT.md's PROTOCOL DETECTION), and for what's planned next (docs/DEVELOPMENT.md's ROADMAP).

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
docs/DEVELOPMENT.md's PROTOCOL DETECTION for exactly how, and docs/USER_GUIDE.md's LIMITATIONS for what it doesn't
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

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface (`Dnp3Decoder`,
`dnp3.hpp`/`dnp3.cpp`) -- see `docs/DEVELOPMENT.md`'s "registration-model decoder refactor" entry.
Detection/decode logic and output are unchanged (still dual-writing into this same `DecodedPacket`
struct, same same-TCP-payload multi-frame coalescing, same cross-packet application-fragment
reassembly); this is an internal dispatch/state-management change only -- the reassembly state
that used to live as `Decoder::dnp3_reassembly_` is now `Dnp3ReassemblyState`, reached via
`DecodeContext::flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow)`.

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
see docs/USER_GUIDE.md's LIMITATIONS.

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
  see docs/USER_GUIDE.md's LIMITATIONS) with the raw millisecond count kept alongside it.
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
validity never reaching it either) -- see that subsection and docs/DEVELOPMENT.md's ROADMAP.

Validated against both a large real 4SICS ICS-lab capture and a set of real
(not synthetic) DNP3 captures from independent DNP3 stacks -- real CROB
Select/Operate sequences including a rejected operate (`status=Not
Supported`), a real polling session exercising Binary Input/Output/Counter/
Internal-Indications objects, and a deliberately corrupted/fuzzed capture
that must degrade gracefully rather than crash or fabricate a value. See
`tests/real_captures/dnp3/ATTRIBUTION.md` for exact provenance. None of these
captures happened to contain a fragment split across multiple data-link
frames, so multi-data-link-frame reassembly (see docs/USER_GUIDE.md's LIMITATIONS and docs/DEVELOPMENT.md's ROADMAP)
remains untested against real traffic.

### S7comm / COTP (Siemens S7 PLCs, TCP port 102)

The TPKT (RFC 1006) and COTP (ISO 8073 / X.224) framing that S7comm always
rides on is decoded in full: the TPKT length, the COTP PDU type (Data,
Connection Request, Connection Confirm, Disconnect Request/Confirm, or an
"other" catch-all), and -- for Connection Request/Confirm, which carry the
TSAP session-setup parameters rather than S7comm itself -- the calling and
called TSAP values. A packet that parses at this level but doesn't turn out
to carry S7comm is reported as protocol `cotp` rather than `s7comm`.

**Migration batch 2**: TPKT/COTP framing (`CotpDecoder`, `cotp.hpp`/`cotp.cpp`) and S7comm/
S7comm-Plus/MMS themselves (`S7CommDecoder`/`S7CommPlusDecoder`/`MmsDecoder`) are now built on the
registration-model `ProtocolDecoder` interface -- see `docs/DEVELOPMENT.md`'s "registration-model
decoder refactor" entry. Detection/decode logic and output are unchanged (still dual-writing into
this same `DecodedPacket` struct); this is an internal dispatch/state-management change only.

A COTP Data (DT) frame's own EOT (end-of-TSDU) bit is also tracked per TCP
flow (`CotpDecoder::decode`, `cotp.cpp`): a single S7comm
message that doesn't fit one negotiated PDU length gets chained across
several *complete* TPKT/COTP frames -- every frame but the last has EOT=0,
the last has EOT=1 -- and this decoder concatenates their user data into one
buffer before attempting the S7comm decode, rather than only ever seeing the
first frame's own bytes. This is a different, higher layer than the general
TCP-segment reassembly described under docs/USER_GUIDE.md's LIMITATIONS: there, one TPKT frame's
own bytes are split across TCP segments; here, every individual TPKT frame
is itself complete, and it's the *logical S7comm message* inside them that
spans more than one. While a fragment is incomplete, the packet is reported
as protocol `cotp` with a "buffering"/"beginning"/"continuing" note; the
completing packet gets a "reassembled..." note naming how many frames and
bytes were chained. See docs/USER_GUIDE.md's LIMITATIONS for exactly what this does and doesn't
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
plausible reconstruction, not a certainty -- see docs/USER_GUIDE.md's LIMITATIONS. Every other
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
A splits real register values mid-byte across the join). See docs/USER_GUIDE.md's LIMITATIONS.

**Modbus/TCP** is likewise validated against real (not synthetic) captures
now, not just the hand-built fixtures -- a clean Read Holding Registers
session, and traffic exercising several function codes outside current scope
(Diagnostics, Report Server ID, Read Exception Status, and others) that must
degrade to a "not decoded" note rather than be misparsed. See
`tests/real_captures/modbus/ATTRIBUTION.md`. The same capture also confirms
authoritative transaction-ID pairing (see docs/DEVELOPMENT.md's PROTOCOL DETECTION) against a real
request/response session, not just the synthetic fixtures.

### S7comm-Plus (Siemens TIA Portal / S7-1200/1500's newer protocol, TCP port 102, shares TPKT/COTP transport with S7comm)

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface
(`S7CommPlusDecoder`, `s7commplus.hpp`/`s7commplus.cpp`) -- see the S7comm/COTP section above and
`docs/DEVELOPMENT.md`'s "registration-model decoder refactor" entry. Detection/decode logic and
output are unchanged.

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
  Integrity part       an id plus what is presumed to be a SHA-256-sized digest (32 bytes) of
                         the telegram -- surfaced, never verified, same posture this codebase
                         already takes toward HART-IP's own checksum (DNP3's data-link CRCs, by
                         contrast, ARE validated -- see PROTOCOL COVERAGE's DNP3 section).
                         Near the END of most Data/Response bodies for PDU type Data (0x02);
                         for DataFW1_5 (0x03), this SAME id+digest shape (no length-prefix byte
                         this time) sits at the very FRONT of the Data part instead, ahead of
                         the opcode -- see the DataFW1_5 note under Tier 1 below
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
hasn't seen. See docs/USER_GUIDE.md's LIMITATIONS.

#### Two-tier function coverage

Same two-tier split this codebase already applies to MMS (18 of 78 services)
and OPC UA (Tier 1/Tier 2):

**Tier 1 -- fully decoded, both directions:**

- **DataFW1_5 (PDU type `0x03`, firmware >= V1.5)** -- moves the Integrity part described above
  to the front of the Data part instead of the end; once that's consumed, the rest of the Data
  part has the identical opcode-led body layout as PDU type Data, so every function below is
  decoded from it the same way. Confirmed against a real capture from a physical S7-1212C driven
  by a genuine Siemens KTP 400 Basic HMI panel: consuming exactly id+32-byte-digest at the front
  reliably realigns the remainder onto a valid opcode byte, and the function bodies that then
  decode are internally consistent -- matching request/response sequence numbers, and a
  monotonically climbing value (the HMI panel's own "Cyclic variables number of automatic sent
  telegrams" health counter, object id `0x70400002` variable id `1053`) that tracks the sequence
  number in lock-step across hundreds of consecutive telegrams. In that capture, DataFW1_5 was in
  fact the dominant PDU type -- essentially all real GetMultiVariables/SetMultiVariables/
  SetVariable traffic arrived this way, not as plain PDU type Data. This decode corrects an
  earlier reading of the reference plugin's own comments (which describe DataFW1_5's integrity
  value as shorter and id-only, with no digest bytes) -- either that describes a different
  firmware generation, or the earlier reading was mistaken; either way, this device's own wire
  behavior now governs here, and it's Tier 1, not experimental, on that basis. See
  `tests/real_captures/s7comm/ATTRIBUTION.md`'s S7comm-Plus addendum for the full writeup.
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
errors, zero `ParseError`-triggered fallbacks, in either file.**

A third real capture, from a physical S7-1212C driven by a genuine Siemens
KTP 400 Basic HMI panel over a SPAN-mirrored switch port, is what confirmed
the DataFW1_5 decode described under Tier 1 above -- ~197 seconds, 1,708
S7comm-Plus telegrams, 1,660 of them DataFW1_5. **Zero per-item decode
errors, zero `ParseError`-triggered fallbacks** across the whole capture,
and the request/response sequence-number and system-health-counter
consistency described above. This capture is real-world validation for
DataFW1_5, GetMultiVariables, SetMultiVariables, SetVariable, CreateObject,
DeleteObject, and Notification (recognized, still correctly left
undecoded) all at once.

See `tests/real_captures/s7comm/ATTRIBUTION.md`'s own S7comm-Plus addendum
for the full writeup, including which shapes (KeepAlive, Explore, GetLink,
BeginSequence/EndSequence, Invoke, a DeleteObject response, array-of-Struct,
Sparsearray) remain validated only against the synthetic fixture
(`tests/sample_s7commplus.pcap`, built by `tools/make_sample_pcap.py`'s own
`build_s7commplus_sample()`) since no real capture has exercised them yet.

This project's own code review -- not real-capture validation -- caught two
genuine correctness bugs before this decoder was ever built or tested: the
array-of-Struct misalignment risk described above (now a deliberate,
explicit refusal), and an unsigned-integer-underflow risk in a
truncated-frame length calculation (`data.size() - kHeaderLen` when
`data.size() < kHeaderLen`, fixed by clamping via the already-established
`available_after_header`/`data_take` pattern used elsewhere in `s7comm.cpp`).

### IEC 61850 MMS (Manufacturing Message Specification, ISO 9506, TCP port 102, shares TPKT/COTP transport with S7comm)

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface (`MmsDecoder`,
`mms.hpp`/`mms.cpp`) -- see the S7comm/COTP section above and `docs/DEVELOPMENT.md`'s
"registration-model decoder refactor" entry. Detection/decode logic and output are unchanged.

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
docs/USER_GUIDE.md's LIMITATIONS).

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
  configuration-file-transfer workflows ride on -- see docs/DEVELOPMENT.md's ROADMAP item 12),
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
`Address` and `TypeSpecification` remain open items -- see docs/DEVELOPMENT.md's ROADMAP item 12.

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

**Migration batch 2** (the last protocol in this batch): built on the registration-model
`ProtocolDecoder` interface (`MqttDecoder`, `mqtt.hpp`/`mqtt.cpp`) -- see `docs/DEVELOPMENT.md`'s
"registration-model decoder refactor" entry. Detection/decode logic and output are unchanged
(still dual-writing into this same `DecodedPacket` struct, same same-TCP-payload multi-packet
coalescing); this is an internal dispatch change only. The one piece of cross-packet state this
decoder needs -- its per-session learned protocol version, used only to disambiguate SUBSCRIBE/
SUBACK/UNSUBSCRIBE's genuinely ambiguous v3.1.1-vs-v5 wire shape (see below) -- moved from the
bespoke `Decoder::mqtt_session_version_` map into `MqttFlowState`, reached via the unchanged,
session-keyed `DecodeContext::flow_state<T>()` every other session-scoped stateful decoder in this
codebase already uses (the same generalization Modbus's own `ModbusFlowState` did for
`modbus_pending_`). Unlike COTP/DNP3's fragment reassembly, this state is correctly
session-scoped, not per-direction, since a CONNECT and the SUBSCRIBE/SUBACK/UNSUBSCRIBE that needs
its learned version can travel in either direction relative to each other.

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
here gets (see docs/USER_GUIDE.md's LIMITATIONS).

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface
(`Iec104Decoder`, `iec104.hpp`/`iec104.cpp`) -- see `docs/DEVELOPMENT.md`'s "registration-model
decoder refactor" entry. Detection/decode logic and output are unchanged (still dual-writing into
this same `DecodedPacket` struct, same same-TCP-payload multi-APDU coalescing); this is an internal
dispatch change only -- and, being purely stateless (no cross-frame reassembly, as above), a
simpler one than DNP3's or COTP's: `Iec104Decoder` needs no `DecoderFlowState` subclass at all.

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
that path (see docs/USER_GUIDE.md's LIMITATIONS) remains untested against real traffic.

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
recognizes (see docs/DEVELOPMENT.md's PROTOCOL DETECTION for why NOP is deliberately excluded).
Like DNP3/IEC 104's small frames, it's normal for several encapsulation
messages to be coalesced into one TCP segment; conduitscope finds and
decodes every complete one present, not just the first, the same way it
does for those two protocols.

**Migration batch 2**: both sides are built on the registration-model `ProtocolDecoder` interface
-- explicit messaging (TCP) as `EnipTcpDecoder` and implicit/I/O messaging (UDP) as
`EnipUdpDecoder` (both `enip.hpp`/`enip.cpp`) -- see `docs/DEVELOPMENT.md`'s "registration-model
decoder refactor" entry. Detection/decode logic and output are unchanged (still dual-writing into
this same `DecodedPacket` struct, same same-TCP-payload multi-message coalescing on the TCP side);
this is an internal dispatch change only. Both sides are purely stateless, needing no
`DecoderFlowState` subclass. This is also the first case in this codebase's registration-model
decoders of two separate decoder instances sharing one `id()` ("enip") -- safe because every
output writer already dispatches on the plain `DecodedPacket::protocol` string, never on a
registry lookup requiring `id()` uniqueness.

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
across a TCP segment boundary, so that path (see docs/USER_GUIDE.md's LIMITATIONS) remains
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
  docs/DEVELOPMENT.md's PROTOCOL DETECTION.
- **The Connected Data Item** (CPF item `0x00B1`), when present, is
  *located* and its length reported, but its contents are shown only as
  **raw hex, never value-decoded**. Two reasons, both deliberate: assembly/
  I/O data has no generic self-describing wire-level type at all (unlike
  explicit messaging's typed tag reads), and this decoder does not track a
  connection's negotiated transport class (Class 0 vs Class 1/2/3, set by
  the Forward_Open that established it, and not necessarily captured in the
  same pass as the I/O traffic it configures) -- which is specifically what
  would be needed to know whether a leading 16-bit CIP sequence count is
  present inside this data or not. See docs/USER_GUIDE.md's LIMITATIONS, and `enip.hpp`'s file
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
continuity) in this groundwork release -- see docs/USER_GUIDE.md's LIMITATIONS and docs/DEVELOPMENT.md's ROADMAP.

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
capture includes any (see docs/USER_GUIDE.md's LIMITATIONS). IO data itself is shown only as raw
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
report, exactly as before this feature existed -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION.

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
than rejected outright; see docs/DEVELOPMENT.md's PROTOCOL DETECTION.

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
ethertype-name-only report, exactly as GOOSE does -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION.

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
| `0x84` | `refrTm` | UtcTime (8 bytes) | OPTIONAL. Same encoding as GOOSE's `t` field (see the GOOSE section above); decoded internally but, matching GOOSE's own `t` field, not yet exposed in JSON output (see docs/USER_GUIDE.md's LIMITATIONS). |
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
docs/DEVELOPMENT.md's PROTOCOL DETECTION's "structural detection gate" discussion).

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
docs/DEVELOPMENT.md's PROTOCOL DETECTION above). Every multi-byte field at every layer is
big-endian (unlike EtherCAT's little-endian, the same as every other
protocol in this codebase). This section, and this decoder, is
cross-checked against Wireshark's own BACnet dissectors --
`epan/dissectors/packet-bvlc.c` (BVLC), `packet-bacnet.c` (NPDU), and
`packet-bacapp.c` (APDU, BACnet's own tag encoding, and service value
decode) -- byte offset by byte offset. Three layers are decoded: BVLC (the
UDP framing header), NPDU (the network layer), and APDU (the application
layer, where BACnet's actual services live).

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface
(`BacnetDecoder`, `bacnet.hpp`/`bacnet.cpp`) -- see `docs/DEVELOPMENT.md`'s "registration-model
decoder refactor" entry. Detection/decode logic and output are unchanged (still dual-writing into
this same `DecodedPacket` struct); this is an internal dispatch change only. Purely stateless, and
unlike EtherNet/IP's CIP I/O and HART-IP's own UDP path, needs no wrapper result type at all --
`BacnetFrame` already carried every field the legacy call site dual-wrote, so `decode()` returns
it unwrapped, the same "no new result type" shape `EnipUdpDecoder` has. Its own `id()`
("bacnet"), not shared with anything else -- the simpler of this batch's two
`GateKind::UdpPortIndependent` additions.

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
"expected port" annotation only, never a gate. See docs/DEVELOPMENT.md's PROTOCOL DETECTION
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
both TCP and UDP (see docs/DEVELOPMENT.md's PROTOCOL DETECTION above for the exact gate and the
TCP-only Modbus collision it doesn't resolve). Every multi-byte field is
big-endian.

**Migration batch 2**: both sides are built on the registration-model `ProtocolDecoder` interface
-- `HartIpTcpDecoder` and `HartIpUdpDecoder` (both `hartip.hpp`/`hartip.cpp`), reusing
EtherNet/IP's own two-decoder-instances-sharing-one-`id()` pattern (`"hartip"`), since HART-IP
rides over EITHER transport using the SAME wire format and the SAME `try_parse_hartip` function
rather than EtherNet/IP's two genuinely separate TCP/UDP functions -- see
`docs/DEVELOPMENT.md`'s "registration-model decoder refactor" entry. Detection/decode logic and
output are unchanged (still dual-writing into this same `DecodedPacket` struct, same
same-TCP-payload multi-message coalescing on the TCP side); this is an internal dispatch change
only. Both sides are purely stateless, needing no `DecoderFlowState` subclass. The IKE-NAT-T
(port 4500)/VXLAN (port 4789) UDP exclusion described above moved from an inline check at
decoder.cpp's old UDP call site into a small `hartip_udp_excluded_port(uint16_t)` helper next to
the parser in `hartip.hpp`, same exclusion, same RFC 3948/RFC 7348 rationale.

#### The 8-byte fixed header

Every HART-IP message begins with: Version (1 byte, always `1` in every
message this decoder's own research and every real capture checked so far
carries), MessageType (1 byte -- `0` Request, `1` Response, `2` Publish, `3`
Error, `15`/`0x0F` NAK), MessageID (1 byte -- `0` Session Initiate, `1`
Session Close, `2` Keep Alive, `3` Pass Through), Status (1 byte -- every
message observed so far is `0`; see docs/USER_GUIDE.md's LIMITATIONS), TransactionID/Sequence
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
- **Checksum** (1 byte): present but not itself verified (see docs/USER_GUIDE.md's LIMITATIONS).

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
vs-Modbus/TCP collision docs/DEVELOPMENT.md's PROTOCOL DETECTION above documents as an accepted
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

**Migration batch 2**: built on the registration-model `ProtocolDecoder` interface
(`OpcUaDecoder`, `opcua.hpp`/`opcua.cpp`) -- see `docs/DEVELOPMENT.md`'s "registration-model
decoder refactor" entry. Detection/decode logic and output are unchanged (still dual-writing into
this same `DecodedPacket` struct, same same-TCP-payload multi-chunk coalescing); this is an internal
dispatch change only -- and, being purely stateless (SecureConversation chunking is handled
entirely within `try_parse_opcua_message`/`OpcUaMessage::wire_length`, with no cross-packet
reassembly of its own), a simpler one than DNP3's or COTP's: `OpcUaDecoder` needs no
`DecoderFlowState` subclass at all.

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
docs/DEVELOPMENT.md's PROTOCOL DETECTION and docs/USER_GUIDE.md's LIMITATIONS describe (one Message chunk split
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
see docs/DEVELOPMENT.md's PROTOCOL DETECTION's "Why FF-HSE is tried last of all": accept a buffer
as FF-HSE when there are at least 12 bytes, `ProtocolAndType & 0xfc` is one
of the 4 valid protocol values, `ProtocolAndType & 0x03` is one of the 3
valid type values, and Message Length is between 12 and 16 MiB inclusive.
That is a single byte at offset 2 landing on one of 12 valid values out of
256 possible, plus a length check that -- even with the 16 MiB ceiling --
is barely a constraint at all -- honestly weaker even than HART-IP's own
two-adjacent-byte gate, which is itself already this codebase's previous
weakest. FF-HSE is therefore dispatched LAST of all protocols in Auto
mode, on both TCP and UDP, after even HART-IP and MQTT. The 16 MiB ceiling
itself was added after a real false positive: a UDP/443 QUIC/TLS response's
essentially-random bytes, on a genuine capture, happened to match the
ProtocolAndType byte and decoded a Message Length of 4237566479 -- without
a ceiling this was "detected" as a badly truncated FF-HSE message instead
of correctly falling through to the generic `udp` protocol. See
`kMaxPlausibleMessageLength`'s own comment in `ffhse.cpp` and the
`ffhse_implausible_message_length_not_misdetected` regression test.

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
discrepancy this decoder failed to notice. See docs/DEVELOPMENT.md's PROTOCOL DETECTION below for
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
before any Ethernet parsing is attempted at all -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION's
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
key," not a gap tracked on docs/DEVELOPMENT.md's ROADMAP.

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

### DNS / mDNS / LLMNR / NetBIOS Name Service (NBT-NS) / DNS-over-HTTPS detection

Five name-resolution protocols, covered together because four of them share
one wire format and the fifth (DoH) is detection-only for a fundamentally
different reason (its actual content is TLS-encrypted). Unlike every
protocol above, all five are **port-gated in `--protocol auto`** rather than
tried opportunistically port-independent -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION's own
dedicated paragraph for why, and for exactly how `--dns-port`/`--mdns-port`/
`--llmnr-port`/`--nbns-port`/`--doh-port` widen that gate. This section
covers the wire formats and what is and isn't decoded once a payload passes
its port and structural gates.

#### DNS, mDNS, and LLMNR (shared wire format)

DNS (RFC 1035, UDP port 53), mDNS (RFC 6762, UDP port 5353), and LLMNR (RFC
4795, UDP port 5355) all share one 12-byte header shape plus one Question/
Resource-Record encoding -- RFC 6762 and RFC 4795 both explicitly reuse RFC
1035's message format verbatim, so this decoder implements ONE shared
`DnsMessage` parser for all three, parameterized only by which header-bit
layout and class-field top-bit reinterpretation applies (see below); the
`protocol` string itself (`"dns"`/`"mdns"`/`"llmnr"`) is what disambiguates
them in output, not a different field family.

**Header (12 bytes, all fields big-endian):** a 16-bit transaction ID,
followed by a second 16-bit word whose bit layout differs by flavor --

| Bit(s) | DNS / mDNS (RFC 1035 §4.1.1) | LLMNR (RFC 4795 §2.1.1) |
|---|---|---|
| 0 | QR (query=0/response=1) | QR |
| 1-4 | OPCODE | OPCODE |
| 5 | AA (Authoritative Answer) | C (Conflict) |
| 6 | TC (Truncated) | TC |
| 7 | RD (Recursion Desired) | T (Tentative) |
| 8 | RA (Recursion Available) | reserved (part of Z) |
| 9-11 | Z (reserved, must be 0) | Z (reserved, must be 0 -- 4 bits here, not 3) |
| 12-15 | RCODE | RCODE |

then four 16-bit counts (QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT). LLMNR's own
reserved Z bits are a strong enough tell that this decoder treats a nonzero
value as an outright detection-gate REJECTION (RFC 4795 mandates
implementations zero them, so a real LLMNR sender never sets them) -- DNS's
and mDNS's own reserved bit is only noted, not rejected, since ordinary DNS
resolvers have been observed setting it in the wild.

**Names** use length-prefixed labels (1-63 bytes each, terminated by a
zero-length root label) or a 2-byte compression pointer (RFC 1035 §4.1.4 --
top two bits set, remaining 14 bits an offset from the start of the
message) that redirects decoding elsewhere in the same message; pointer-
following is capped at 128 hops as a loop guard. **Questions** are
NAME+QTYPE(2)+QCLASS(2); **Resource Records** are
NAME+TYPE(2)+CLASS(2)+TTL(4)+RDLENGTH(2)+RDATA(RDLENGTH bytes). A ~38-entry
type table names every commonly-seen RR type (A, NS, CNAME, SOA, PTR, MX,
TXT, AAAA, SRV, NAPTR, DS, RRSIG, DNSKEY, NSEC, TLSA, SVCB/HTTPS, and so on),
but RDATA is only value-decoded for the "first pass" set this decoder
currently covers -- **A, AAAA, NS, CNAME, PTR, MX, SOA, TXT, SRV** -- the
same scoping pattern established for BACnet/DNP3/S7comm/EtherNet-IP
elsewhere in this codebase; every other named type's RDATA is shown as raw
hex rather than misdecoded. An EDNS0 OPT pseudo-record (type 41, RFC 6891)
is specially recognized: its CLASS field is repurposed as the requestor's
UDP payload size and its TTL field is repurposed as extended-RCODE/
version/flags (including the DO -- DNSSEC OK -- bit), and this decoder
renders those repurposed meanings rather than showing them as an ordinary
class/TTL.

**mDNS-specific bit repurposing (RFC 6762 §6.2/§10.2):** the top bit of a
question's QCLASS is the "QU" (unicast-response-requested) bit, and the top
bit of a resource record's CLASS is the "cache-flush" bit. Both are stripped
from the rendered class name and surfaced as their own boolean annotation
rather than corrupting the class value.

**DNS-over-TCP is not decoded** -- only the UDP form of all three flavors.
This project's own `resolver.hpp` (used for the `--resolve`/`--hosts`
hostname-annotation feature elsewhere in this tool) never performs live DNS
lookups of its own; this decoder similarly never resolves anything on the
network, it only decodes DNS-shaped traffic already present in the capture.

#### NetBIOS Name Service (NBT-NS, RFC 1002 §4.2, UDP port 137)

NBT-NS shares RFC 1035's general Header/Question/Resource-Record shape in
spirit but not in wire-level detail -- its own 12-byte header is
`NAME_TRN_ID(2)` + a second word laid out `R(1) OPCODE(4) NM_FLAGS(7)
RCODE(4)`, where NM_FLAGS is itself `AA(1) TC(1) RD(1) RA(1) reserved(2)
B(1)`, followed by the same four 16-bit QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT
counts DNS uses. OPCODE: `0` Query, `5` Registration, `6` Release, `7` WACK,
`8` Refresh. RCODE: `0` Success, `1` Format Error, `2` Server Error, `3`
Name Error, `4` Unsupported Request Error, `5` Refused Error, `6` Active
Error, `7` Name in Conflict Error.

**NetBIOS names use RFC 1002 §4.1's "First-Level Encoding":** a 16-byte raw
NetBIOS name (15 characters padded with spaces, plus a 1-byte suffix) is
encoded on the wire as a length byte -- ALWAYS exactly `0x20` (32) -- followed
by 32 bytes, each raw nibble mapped to `'A' + nibble`. This fixed-length
requirement is this decoder's own strongest structural detection gate (see
docs/DEVELOPMENT.md's PROTOCOL DETECTION): a genuine first-level-encoded name can never be any
length other than exactly 32 bytes, unlike a DNS label's legitimate 1-63
byte range. The 16th (suffix) byte is not part of RFC 1002 itself but is
the near-universal Microsoft/Wireshark convention for what service a name
represents, and is named accordingly wherever this decoder shows a NetBIOS
name (e.g. `0x00` Workstation Service, `0x03` Messenger, `0x1B` Domain
Master Browser/PDC, `0x1C` Domain Controllers, `0x1D` Master Browser, `0x1E`
Browser Election, `0x20` File Server Service, and roughly a dozen more).

**Question types:** `NB` (`0x0020`, "find this name's address(es)") and
`NBSTAT` (`0x0021`, "find this node's full name table"). **NB resource
record RDATA** is a list of `NB_FLAGS(2)+NB_ADDRESS(4)` entries, NB_FLAGS'
top bit being the Group/Unique flag and the next two bits the owning node's
type (B/P/M-node). **NBSTAT resource record RDATA** is `NUM_NAMES(1)`
followed by that many 18-byte entries (a raw, NOT first-level-encoded,
16-byte NetBIOS name plus a 2-byte NAME_FLAGS word -- Group/Unique, node
type, and the DRG/CNF/ACT/PRM bits), then a STATISTICS structure whose
first 6 bytes are the responding node's own MAC address (UNIT_ID). This
decoder deliberately does not hard-code the STATISTICS structure's exact
remaining byte length past UNIT_ID -- conflicting sources give 44 vs. 46
total bytes for the full structure, and re-deriving it byte-by-byte from RFC
1002's own ASCII diagram did not resolve the discrepancy -- so whatever
bytes remain within the record's own declared RDLENGTH after UNIT_ID are
simply hex-dumped rather than asserting a specific structure over them (see
`nbns_records` in the OUTPUT FORMATS json section).

#### DNS-over-HTTPS (DoH) detection (TCP port 443) -- detection only, never decoded

DoH's actual DNS query and answer travel inside a TLS session, which this
project's zero-decryption-keys posture (the same posture `resolver.hpp`
already takes toward live DNS -- see above) can never see regardless of how
this decoder is extended. What CAN be seen, in plaintext, is the TLS
ClientHello that opens the connection -- specifically its Server Name
Indication (SNI, RFC 6066 §3) extension, which names the hostname the
client is connecting to before encryption begins. This decoder parses a
single-segment TLS 1.x record (`0x16` Handshake / `0x01` ClientHello) far
enough to extract the SNI hostname and, if present, the ALPN (RFC 7301)
protocol list, then checks the SNI against a curated table of known public
DoH resolver hostnames (`*.suffix` pattern matching, i.e. exact hostname or
any subdomain of it): Cloudflare (`*.cloudflare-dns.com`, `one.one.one.one`),
Google (`*.dns.google`, `dns.google.com`), Quad9 (`*.quad9.net`), OpenDNS
(`*.opendns.com`), AdGuard (`*.adguard-dns.com`, `*.adguard.com`), NextDNS
(`*.nextdns.io`), DNS.SB (`*.dns.sb`), CleanBrowsing
(`*.cleanbrowsing.org`), ControlD (`*.controld.com`), Pi-DNS
(`*.pi-dns.com`), Mullvad (`*.mullvad.net`), and Digitale Gesellschaft
(`*.digitale-gesellschaft.ch`). Only a ClientHello whose SNI matches this
table is ever reported as `doh` -- everything else, including perfectly
ordinary HTTPS to an unrelated site, falls through untouched (there is
nothing else `--protocol auto` would even attempt against TCP port 443
traffic that doesn't match, since this decoder has no other TLS-content
decoder). See docs/USER_GUIDE.md's LIMITATIONS for what this deliberately cannot detect: a
private or enterprise DoH resolver not on this table, a ClientHello whose
SNI extension spans more than one TCP segment, and TLS Encrypted Client
Hello (ECH), all of which defeat this SNI-matching approach entirely --
there being no available signal at all in those cases, not merely one this
decoder chooses not to pursue.

#### Validation

All five protocols here are validated against `tools/make_sample_pcap.py`'s
own hand-built, RFC/Wireshark-cross-checked fixtures (`tests/sample_dns.pcap`,
`sample_mdns.pcap`, `sample_llmnr.pcap`, `sample_nbns.pcap`,
`sample_doh.pcap`) rather than a real capture -- the same honest gap already
documented for this codebase's other synthetic-only protocols. Each fixture
deliberately exercises both the intended decode paths (ordinary queries and
responses, EDNS0, mDNS's QU/cache-flush bits, LLMNR's Conflict bit, NBT-NS's
NB and NBSTAT record types, DoH's exact-hostname and `*.suffix` matching)
and the negative controls this section's own detection-gating design
depends on: a non-DNS-shaped UDP/53 payload, a deliberately truncated DNS
message, an LLMNR message with nonzero reserved Z bits, a malformed NBT-NS
name whose length byte isn't `0x20`, a ClientHello to an ordinary (non-DoH)
hostname, and a non-TLS TCP/443 payload -- every one of which must fall
through to the generic `udp`/`tcp` report rather than being misdetected.

### ICMP (RFC 792, plus RFC 1191/1256 extensions), IP protocol 1

ICMP rides directly on IP (protocol number 1) -- no UDP or TCP header, and
therefore no port at all. Dispatch in `--protocol auto` is keyed purely on
that protocol number, same shape as IGMP/VRRP/PIM/EIGRP/OSPF below, but with
one real difference worth calling out: ICMP's own Type byte gives almost no
useful structural filter on its own (nearly every 0-255 value is either a
real registered type or renders as `Unknown (N)`), so unlike those other
protocols it is IP protocol number 1 alone -- IANA-exclusive to ICMP -- that
is doing essentially all of the detection work here, not any shape match
within the message itself.

Every ICMP message starts with the same 4-byte fixed header --
Type(1)+Code(1)+Checksum(2) -- decoded and named for every IANA-registered
type. Nine message types get full (Tier 1) field decoding, chosen for OT
network diagnostics and security-review relevance:

- **Echo Reply/Request** (`0`/`8`) -- Identifier, Sequence Number, and the
  length of whatever data follows (the actual bytes are not echoed back in
  the summary, just their count).
- **Destination Unreachable** (`3`) -- all 16 IANA-registered codes named
  (Net/Host/Protocol/Port Unreachable, Fragmentation Needed, Source Route
  Failed, the four Administratively Prohibited variants, and the rest);
  code `4` (Fragmentation Needed and Don't Fragment was Set, RFC 1191) also
  decodes the Next-Hop MTU field a Path MTU Discovery implementation reads
  to shrink its packets.
- **Redirect** (`5`) -- all 4 codes named, plus the Gateway Internet Address
  the sender is being redirected to.
- **Time Exceeded** (`11`) -- both codes named (TTL Exceeded in Transit;
  Fragment Reassembly Time Exceeded).
- **Parameter Problem** (`12`) -- all 3 codes named, plus the Pointer byte
  identifying which offset in the original datagram's header was bad.
- **Timestamp Request/Reply** (`13`/`14`) -- Identifier, Sequence Number,
  and the Originate/Receive/Transmit timestamps. These are milliseconds
  since UTC midnight per RFC 792 -- there is no date component on the wire
  at all, so this is never rendered as a real epoch time.
- **Address Mask Request/Reply** (`17`/`18`) -- Identifier, Sequence Number,
  and the 4-byte subnet mask itself.
- **Router Advertisement** (`9`, RFC 1256) -- Lifetime plus every
  address/preference pair (capped at 50 entries, this codebase's usual
  convention, with a note when a packet declared more).

Every other IANA-registered type (`1`, `2`, `6`, Router Solicitation `10`,
Information Request/Reply `15`/`16`, Traceroute `30`, and any genuinely
unassigned value) is named -- Tier 2 -- but not decoded further; most of
these are formally deprecated (RFC 6918: Source Quench, Information
Request/Reply, and Redirect codes 2/3) or rare enough in real OT traffic
that full decoding wasn't judged worth the added surface yet.

**Embedded datagram.** Destination Unreachable, Redirect, Time Exceeded, and
Parameter Problem messages all quote the original offending datagram --
RFC 792 guarantees at least the IP header plus the first 8 bytes of its
payload. This decoder reuses its own IPv4 parser directly against that
quoted region and reads the first 4 bytes of whatever transport payload
follows (source port + destination port -- the same layout for TCP and UDP,
so this works without needing to know which one it is), surfaced as a
one-line `-- original datagram A->B (protocol[ port->port])` summary
addition. A capture can legitimately truncate this quote further still
(snaplen, or some devices embed more per RFC 4884, not decoded here), so a
short or malformed quote degrades to a shorter summary -- or no embedded-
datagram summary at all -- never a decode failure for the ICMP message
itself.

**Checksum: verified, not just surfaced.** Unlike IPv4's own header checksum
(explicitly *not* validated anywhere in this codebase -- see the Link/IP-
layer plumbing section below), ICMP's checksum genuinely is checked against
the standard RFC 1071 16-bit one's-complement algorithm, and a mismatch is
surfaced as a note (`icmp_checksum_valid: false` in JSON). A mismatch can
mean either a truncated capture or a crafted/corrupted packet -- this
decoder cannot always tell the two apart, so it reports the discrepancy
either way rather than guessing which.

**Security context:** ICMP has no authentication of any kind. A Redirect
can silently retarget a host's next-hop for a destination, and any host on
the local segment can send Destination Unreachable/Time Exceeded messages
that most stacks (and some middleboxes) will act on without verifying the
sender actually saw the offending traffic -- both are long-standing
MITM/DoS primitives, more consequential on a flat OT network than a
segmented, ICMP-filtered IT one. A verified-invalid checksum on a Redirect
or Destination Unreachable message is itself worth flagging in an audit.

### RIP / IGMP / VRRP / HSRP

Four IT routing/redundancy protocols, added alongside this project's OT/ICS
coverage because they routinely share the same segments as GOOSE/SV's own
routable multicast variants and because two of them (VRRP/HSRP) are a
straightforward gateway-spoofing/MITM primitive worth surfacing on their own
merits. RIP and HSRP are **port-gated in `--protocol auto`**, the same
posture as the DNS family above and for the same reason (see PROTOCOL
DETECTION); IGMP and VRRP need no port gate at all -- both are dispatched
purely by their own IANA-exclusive IP protocol number, a strong signal with
no port concept to gate in the first place.

#### RIP (Routing Information Protocol) v1 (RFC 1058) and v2 (RFC 2453), UDP port 520

A RIP message is a 4-byte header -- Command(1) + Version(1) + a 2-byte field
RFC 1058 calls "must be zero" and RFC 2453 repurposes as a "Routing Domain"
(shown as a raw value, not decoded further) -- followed by zero or more
20-byte Route Table Entries (RTEs). Command: `1` Request, `2` Response, `3`
Trace On (obsolete), `4` Trace Off (obsolete), `5` Reserved (RFC 1058's own
note: historically used by Sun Microsystems' `routed`). RIPv1 and RIPv2
share the exact same 20-byte RTE layout on the wire -- RIPv2 simply gives
meaning to three fields RIPv1 requires to be zero (Route Tag, Subnet Mask,
Next Hop) -- so every RTE is read the same way regardless of version, with a
note raised when a supposed-v1 message's own "must be zero" fields aren't.

Two RTE shapes are not ordinary routes and are recognized structurally
rather than decoded as an address: Address Family Identifier (AFI) `0`
marks a "give me your whole table" full-table-request marker entry (RFC
1058 §3.4.1), and AFI `0xFFFF` (RIPv2 only) marks an authentication entry
(RFC 2453 §4.2) rather than a route. Two authentication types are decoded:
**Simple Password** (`AuthType 2`) is a 16-byte cleartext password, NUL-
padded, decoded and surfaced directly; **Keyed MD5** (`AuthType 3`, RFC
2082) has its own auth-header fields (RIP-2 Packet Length, Key ID, Auth Data
Length, Sequence Number) fully decoded, but the actual MD5 digest -- a
SEPARATE block appended after the last real route RTE, outside the RTE
chain itself -- is neither located nor verified (see docs/USER_GUIDE.md's LIMITATIONS); those
trailing digest bytes show up as an explicit "trailing byte(s) ... do not
form a full 20-byte RTE" note rather than being silently consumed or
misread as a bogus route.

**Security context:** RIP has no meaningful authentication in practice.
RIPv1 has none at all; RIPv2 Simple Password sends the password in
plaintext on the wire; even Keyed MD5 only proves the sender knows a shared
key, not who the sender actually is. Seeing RIP traffic at all on a segment
is often worth a second look -- it is a legacy, low-security IGP a
well-segmented modern network usually shouldn't be running.

The detection gate itself is weak on its own (a handful of small integers:
Command in `1..5`, Version `1` or `2`), which is why `--protocol auto` only
tries it on UDP port 520 -- widen this with `--rip-port`, or bypass the gate
entirely with `--protocol rip`.

#### IGMP (Internet Group Management Protocol) v1/v2 (RFC 1112/2236) and v3 (RFC 3376), IP protocol 2

IGMP rides directly on IP (protocol number 2) -- there is no UDP or TCP
header, and therefore no port at all; dispatch in `--protocol auto` is keyed
purely on that protocol number, which is IANA-exclusive to IGMP. Five
message shapes are recognized by a Type byte, with Type `0x11` (Membership
Query) further disambiguated by length since all three IGMP versions share
that one Type value for a query: exactly 8 bytes is IGMPv1 (Max Resp Code
always `0`) or IGMPv2 (Max Resp Code a nonzero plain integer, in tenths of a
second -- NOT the v3 exponential encoding below); 12 or more bytes is an
IGMPv3 Query, adding an S/QRV byte, a QQIC, and an optional source-address
list. `0x12` is a Version 1 Membership Report, `0x16` a Version 2
Membership Report, `0x17` a Version 2 Leave Group, and `0x22` an IGMPv3
Membership Report, which is shaped completely differently from every other
message here: a list of per-group **Group Records** (RFC 3376 §4.2) rather
than one single group address --
RecordType(1)+AuxDataLen(1)+NumSources(2)+MulticastAddress(4)+SourceAddress[N]
(4 each)+AuxData(AuxDataLen 32-bit words, not decoded further). RecordType:
`1` Mode Is Include, `2` Mode Is Exclude, `3` Change To Include Mode, `4`
Change To Exclude Mode, `5` Allow New Sources, `6` Block Old Sources.

IGMPv3's **Max Resp Code** (Query only) and **QQIC** fields share one
exponential "floating-point" encoding (RFC 3376 §4.1.1/§4.1.7): a value
below 128 (high bit clear) is used as-is; otherwise bits 6-4 are an
exponent and bits 3-0 a mantissa, decoded as `(mantissa | 0x10) <<
(exponent + 3)`. Both fields are rendered through this decoding (Max Resp
Code as milliseconds, QQIC as seconds) rather than showing the raw encoded
byte.

**Security context:** IGMP has no authentication at all in any version --
any host on the local segment can claim group membership, and more
seriously, can send Membership Queries and impersonate a multicast router,
which most hosts and IGMP-snooping switches will believe unquestioningly.

Every repeated list here (a v3 Query's source addresses, a v3 Report's
group records, and each group record's own source addresses) is capped at
50 entries, the same convention used throughout this codebase, with a note
when a packet declared more than that.

#### VRRP (Virtual Router Redundancy Protocol) v2 (RFC 3768) and v3 (RFC 5798), IP protocol 112

VRRP also rides directly on IP (protocol number 112, IANA-exclusive) with
no UDP/TCP header and no port concept. Both versions share an 8-byte fixed
header before the virtual IP address list: Version(high nibble)/Type(low
nibble, always `1` -- Advertisement, the only value either RFC defines) +
Virtual Router ID + Priority + a count of virtual IP addresses, then 4
version-specific bytes -- v2: AuthType(1)+AdverInt(1, whole seconds)+
Checksum(2); v3: Reserved(4 bits)+Max Advertisement Interval(12 bits,
centiseconds)+Checksum(2), packed into 2 bytes; v3 removed authentication
entirely. **Priority** `0` means the current master is stepping down, `255`
means "address owner" (the router whose real interface address IS the
virtual IP), and `1`-`254` is an ordinary backup's priority (RFC default
100). After the address list, VRRPv2 (only) carries an 8-byte
Authentication Data field, meaningful only for AuthType `1` (Simple Text
Password -- decoded as cleartext); AuthType `2` (IP Authentication Header,
already deprecated by RFC 3768 itself) and AuthType `254` (a non-standard
Cisco MD5 extension seen in the wild) are named but not decoded further.
This decoder does not handle VRRP-for-IPv6 (16-byte addresses, a different
multicast group, and this project has no IPv6 address formatting anywhere).

**Security context:** any host on the segment that can send a
higher-priority Advertisement (or a Priority-0 "I'm stepping down") can
take over as the virtual router -- a straightforward gateway-spoofing/MITM
primitive. VRRPv2's only authentication option is cleartext and does
nothing to stop a listener from replaying it; VRRPv3 relies purely on
network-layer segmentation instead.

The virtual IP address list is capped at 50 entries, same convention as
elsewhere.

#### HSRP (Hot Standby Router Protocol) v1 (RFC 2281) and v2 (Cisco proprietary), UDP port 1985

HSRPv1 is a single fixed-format 20-byte UDP payload: Version(1, always `0`)
+ OpCode(1) + State(1) + Hellotime(1, seconds) + Holdtime(1, seconds) +
Priority(1) + Group(1) + Reserved(1) + Authentication Data(8, cleartext) +
Virtual IP Address(4). OpCode: `0` Hello, `1` Coup, `2` Resign, `3`
Advertise. State: `0` Initial, `1` Learn, `2` Listen, `4` Speak, `8`
Standby, `16` Active. HSRPv2 (never formally standardized by Cisco; needed
for more than 255 groups and for IPv6) abandons that fixed layout entirely
for a flat TLV chain with no header before the first TLV --
Type(1)+Length(1, Value bytes only)+Value, repeated until the payload is
exactly consumed. Four TLV types are defined: `1` Group State, `2`
Interface State, `3` Text Authentication, `4` MD5 Authentication; only
Group State is decoded field-by-field (Version+OpCode+State+IPVersion+Group
Number+a 6-byte per-group Identifier+Priority+Hello/Hold Timer in
milliseconds+Virtual IP Address), the other three are recognized and shown
with their raw Value bytes, not decoded further. A Group State TLV declares
a 40-byte length regardless of address family: for IPv6 that exactly
accounts for all 40 bytes (24 + a 16-byte address), but for IPv4 it only
accounts for 28 of the 40, leaving 12 reserved/padding bytes this decoder
does not interpret; an IPv6 Group State's own Virtual IP Address is left
undecoded (noted, not guessed at) since this project has no IPv6 address
formatting anywhere.

This decoder tries the HSRPv1 fixed shape first (exact length 20, Version
byte `0`, a valid OpCode/State) and falls back to parsing the payload as a
self-consistent HSRPv2 TLV chain otherwise -- requiring the TLV chain to
consume the payload exactly, with a recognized first TLV type, is what
keeps an arbitrary non-HSRP UDP payload from being misdetected, since HSRP
has no protocol-identifying magic number in either version.

**Security context:** like VRRP, HSRP lets any host on the segment send a
higher-priority Hello/Coup and take over as the active router. HSRPv1's
only authentication (an 8-byte plaintext field, conventionally the ASCII
string `cisco`) provides no real protection and is surfaced directly.

Both HSRPv1's and HSRPv2's own structural checks are weak enough on their
own that `--protocol auto` only tries this decoder on UDP port 1985 --
widen this with `--hsrp-port`, or bypass the gate with `--protocol hsrp`.
**Dispatch-order note:** RIP and HSRP, despite being port-gated, are tried
BEFORE FF-HSE's own fully opportunistic (any-port) check in this decoder's
UDP dispatch chain -- a synthetic HSRPv1 message was found, while building
this feature, to satisfy FF-HSE's own weaker structural gate and get
misdetected as truncated FF-HSE traffic when tried in the other order; once
RIP's/HSRP's own port gate has already matched, that specific check is a
stronger signal than FF-HSE's opportunistic one, so it wins.

#### Validation

All four protocols here are validated against `tools/make_sample_pcap.py`'s
own hand-built, RFC/Wireshark-cross-checked fixtures (`tests/sample_rip.pcap`,
`sample_igmp.pcap`, `sample_vrrp.pcap`, `sample_hsrp.pcap`). Each fixture
exercises both the intended decode paths and the negative controls each
protocol's own detection-gating design depends on: an invalid RIP Command
byte on RIP's own port, an unrecognized IGMP Type byte on IP protocol 2, an
invalid VRRP Type nibble on IP protocol 112, and an HSRP payload that is
neither a valid v1 message nor a self-consistent v2 TLV chain -- every one
of which must fall through to the generic `udp`/`non-tcp` report rather
than being misdetected.

IGMP additionally has one real-world capture: `tests/real_captures/igmp/
plant1_igmp_only.pcap`, 12 genuine IGMPv3 Membership Reports trimmed from
the same `Plant1.pcap` this project's STP/PROFINET/CIP-I/O fixtures already
draw from (see `tests/real_captures/igmp/ATTRIBUTION.md`), cross-checked
field-by-field against `tshark`'s own IGMP dissector. It exercises two
things the synthetic fixture alone does not: a genuine 4-byte IP Router
Alert option (a 24-byte IP header, not the usual 20) on every frame, and a
real occurrence of this decoder's Ethernet-minimum-frame-size padding note.
A 498-file search across `automayt/ICS-pcap`, `ITI/ICS-Security-Tools`, and
`mrhenrike/PCAPTrafficAnalysis` for the same real-capture effort found no
RIP, VRRP, or HSRP traffic anywhere (unsurprising -- those collections are
curated around single-device ICS protocol captures, not multi-router
topologies); those three remain synthetic-fixture-only, the same accepted,
precedented gap already documented for this codebase's FF-HSE and DeviceNet
decoders (see `tests/real_captures/igmp/ATTRIBUTION.md`'s "Search outcome
for RIP/VRRP/HSRP" section for the full account).

### IGRP / PIM / EIGRP / OSPF

Four more routing/multicast-routing protocols, added as a follow-up batch to
RIP/IGMP/VRRP/HSRP above for the same reason (they routinely share segments
with GOOSE/SV's own routable multicast variants, and seeing router-to-router
traffic on a segment that shouldn't have any is itself worth a second look).
All four ride directly on IP with **no port concept at all** -- dispatch in
`--protocol auto` is keyed purely on each protocol's own IANA-exclusive IP
protocol number (9, 103, 88, and 89 respectively), the same posture already
established for IGMP/VRRP above. BGP, the one protocol from this same
follow-up request that rides over TCP (port 179) instead of directly on IP,
is deliberately **not** part of this batch -- it needs TCP stream
reassembly, unlike the four protocols here, and is deferred to its own
future round (see docs/DEVELOPMENT.md's ROADMAP).

#### IGRP (Interior Gateway Routing Protocol), IP protocol 9

Cisco's IGRP predates EIGRP below and was formally end-of-life for Cisco IOS
in 2016 -- it is included here purely for completeness (occasionally still
seen in lab/training captures and legacy-equipment audits), and production
traffic using it at all is itself a strong signal of unmaintained, legacy
infrastructure. IGRP was never assigned its own RFC; it is documented here
only by Cisco's own (long unmaintained) documentation and Wireshark's own
`packet-igrp.c`, which this decoder was cross-checked against directly. A
12-byte header -- Version(4 bits, only `1` is ever defined)/Opcode(4 bits,
`1` Update/"Response", `2` Request) + Edition(1) + Autonomous System(2) +
Interior/System/Exterior route counts (2 each) + Checksum(2, not verified)
-- is followed by that many 14-byte route vectors: Network(3, see below) +
Delay(3, units of 10 microseconds, all-ones = unreachable) + Bandwidth(3,
scaled: kbps = 10,000,000 / raw) + MTU(2) + Reliability(1) + Load(1) + Hop
Count(1).

IGRP is a **classful** protocol, and its 3-byte Network field is the one
genuinely tricky part of an otherwise simple format: an **Interior** route
(a subnet of the network the packet itself was sent on) carries only the
LOW-order 3 octets on the wire, with the missing high-order octet borrowed
from the *IP source address of the packet carrying the route* -- decoding it
correctly therefore requires the packet's own source IP, which is why
`try_parse_igrp` (uniquely among every `try_parse_*` function in this
codebase) takes an extra parameter beyond the raw payload. A **System** or
**Exterior** route (a different major network) instead carries the
HIGH-order 3 octets, with the missing low-order octet always `0` -- these
can only ever name a bare class A/B/C network number, never a specific host.

**Security context:** IGRP has no authentication of any kind, and is a
distance-vector protocol with no loop-prevention beyond simple
split-horizon/hold-down -- any host on the segment can inject routes.

#### PIM (Protocol Independent Multicast) v2, PIM-SM/PIM-DM (RFC 7761/RFC 3973), IP protocol 103

Only PIMv2 is decoded; PIMv1 (a much older, IGMP-framed design Cisco
deprecated long ago) uses an entirely different wire format this decoder
does not recognize. Every PIMv2 message shares a 4-byte common header --
Version(4 bits, always `2`)/Type(4 bits) + a type-specific second byte
(usually reserved) + Checksum(2, not verified) -- and this decoder fully
decodes the six message types actually seen in normal PIM-SM/PIM-DM
operation: `0` Hello (a TLV chain of options -- Hold Time, LAN Prune Delay,
DR Priority, Generation ID, State Refresh Capable, and Address List are all
decoded field-by-field); `1` Register (a Border/Null-Register flags word
plus an encapsulated multicast data packet, whose own (Source, Group) this
decoder extracts from fixed offsets but whose payload it does NOT decode
further -- the same "don't recursively decode a fully independent inner
protocol" posture this project takes elsewhere); `2` Register-Stop; `3`/`6`/
`7` Join/Prune, Graft, and Graft-Ack (PIM-DM only for the latter two --
RFC 3973 -- but all three share this exact wire format: an upstream
neighbor, a holdtime, and a list of (group, joined sources, pruned sources)
tuples); `4` Bootstrap (fragment tag/hash mask length/BSR priority/address,
followed by a list of (group, candidate-RP list) tuples); `5` Assert (a
group + source + a metric used to elect the LAN forwarder); `8`
Candidate-RP-Advertisement. Five rarer types (`9` State-Refresh, `10`
DF-Election, `11` ECMP-Redirect, `12` PFM, `13` Packed-Register) are
recognized by Type value and named, but their bodies are not decoded
further.

PIM's three "Encoded Address" formats (Unicast, Group, Source -- RFC 7761
§4.9) each begin with an Address Family byte and an Encoding Type byte; only
Address Family `1` (IPv4, matching this project's IPv4-only posture
everywhere else) and Encoding Type `0` (the plain "native" encoding) are
supported. Encoding Type `1` (Native encoding with a trailing Join Attribute
TLV chain, used only for a handful of BIDIR-PIM/MoFRR extensions) and
Address Family `2` (IPv6) both stop decoding at that point in the message --
whatever was already decoded is still returned, with a note -- rather than
guessing at a length.

**Security context:** PIM has no authentication in the versions this
decoder recognizes -- any host on a PIM-enabled segment can send Join/
Prune, Assert, or even Bootstrap/Candidate-RP-Advertisement messages and
manipulate multicast forwarding state, including redirecting or
blackholing multicast traffic. Because GOOSE/SV's own routable multicast
variants and IGMP both already ride the same segments this decoder targets,
unexpected PIM traffic -- especially Bootstrap/Candidate-RP-Advertisement
from a host that isn't a legitimate RP/BSR -- is worth a second look.

#### EIGRP (Enhanced Interior Gateway Routing Protocol), now RFC 7868, IP protocol 88

A 20-byte header -- Version(1) + Opcode(1) + Checksum(2, not verified) +
Flags(4: bit0 Init/bit1 Conditional Receive/bit2 Restart/bit3 End Of Table)
+ Sequence(4) + Acknowledge(4) + Virtual Router ID(2) + Autonomous System(2)
-- is followed by a chain of TLVs (Type(2)+Length(2), Length counting the
4-byte TLV header itself) running to the end of the packet. A Hello
(Opcode `5`) with a nonzero Acknowledge field is displayed as `Hello (Ack)`,
matching Wireshark's own convention -- an Ack is really just an empty Hello
piggybacking an acknowledgement.

The general (protocol-independent) TLVs are fully decoded: Parameters
(K1-K6 + Hold Time), Authentication (header fields decoded -- Auth Type,
declared digest length, Key ID, Key Sequence -- but, like RIP's own Keyed
MD5 support, the MD5/SHA-256 digest itself is shown raw and NOT verified),
Sequence (a list of peer addresses, IPv4 only), Software Version, and Next
Multicast Sequence. Both IPv4 route TLV formats are fully decoded: the
legacy **Classic** format (TLV types `0x0102`/`0x0103`, deprecated since
EIGRP Release 8 but still common on older gear and lab captures) and the
current **Wide-Metric**/Multi-Protocol format (TLV types `0x0602`/`0x0603`,
what a modern EIGRP "named mode" configuration defaults to). A single route
TLV of either format can (and in real captures often does) describe
**multiple destination prefixes** sharing one next-hop and one metric --
EIGRP's own compound-TLV design, not a decoding artifact -- with each
destination stored prefix-length-compressed on the wire (only
`ceil(prefix_len/8)` address bytes actually present) and expanded here to a
normal dotted-quad/prefix-length pair. Everything else (Peer Stub
Information/Termination/TID List, AppleTalk/IPX/IPv6/MTR route TLVs, and
IPX SAP packets, i.e. Opcode `6`) is recognized -- named, counted, and its
raw byte length shown -- but not decoded further.

**Security context:** EIGRP supports MD5 and SHA-256 HMAC authentication
(the Authentication TLV's own header fields are decoded, but not the
digest, same posture as RIP's Keyed MD5), but plenty of real-world EIGRP
deployments run with no authentication at all, in which case any host on
the segment can inject or suppress routes. Multiple distinct AS numbers or
repeated Parameter-TLV mismatches on one segment are themselves worth a
second look, since EIGRP AS numbers/K-values effectively define a trust
domain.

#### OSPFv2 (Open Shortest Path First, RFC 2328), IP protocol 89

Only OSPFv2 (IPv4) is decoded; OSPFv3 (which carries IPv6 semantics
throughout, not just a different address family in an otherwise-similar
header) is out of scope, matching this project's IPv4-only posture
everywhere else -- an OSPFv3 packet's Version byte (`3`, not `2`) is
rejected outright. Every OSPFv2 packet shares a 24-byte header --
Version(1) + Type(1) + Packet Length(2) + Router ID(4) + Area ID(4) +
Checksum(2, not verified) + Instance ID(1) + AuType(1) + Authentication(8)
-- reflecting RFC 6549's backward-compatible reinterpretation of the
classic 16-bit AuType field as Instance ID(1)+AuType(1) (a legacy capture
with Instance ID always `0` decodes identically either way). Three AuTypes
are recognized: `0` Null (no authentication), `1` Simple Password (decoded
as cleartext), and `2` Cryptographic/MD5 (Key ID/Auth Data Length/Sequence
Number header fields decoded; like RIP's own Keyed MD5 support, the actual
digest -- a separate block appended after the packet's own declared length
-- is neither located nor verified).

Five packet Types are decoded in full: `1` Hello (network mask, timers,
Options, DR/BDR, and the neighbor list already heard from); `2` DB
Description (interface MTU, Options, the I/M/MS exchange-state flags, and a
list of LSA headers -- never LSA bodies, which a DB Description never
carries); `3` LS Request (a list of (LSA type, Link State ID, Advertising
Router) tuples); `4` LS Update (a list of complete LSAs, header + body --
the only packet type that ever carries LSA bodies); `5` LS Ack (LSA headers
only, acknowledging receipt). Every LSA's 20-byte header is always decoded;
the body is decoded, when present, for LSA types `1` Router (Flags +
per-link LinkID/LinkData/LinkType/Metric list), `2` Network (network mask +
attached-router list), `3`/`4` Summary/ASBR-Summary (identical format:
network mask + TOS-0 metric), and `5`/`7` AS-External/NSSA-External
(identical format: network mask + E-bit + TOS-0 metric + forwarding
address + route tag). Types `6` (Group Membership/MOSPF, essentially unused
today) and `8`-`11` (Opaque, RFC 2370/3630 -- MPLS-TE and other extensions)
are recognized by type number but not decoded further; a Summary/AS-External
LSA's TOS-specific metric blocks beyond the first (ordinary, non-TOS) one
are likewise not decoded -- TOS-based routing was never widely deployed and
real captures essentially always carry exactly one block per LSA.

**Security context:** OSPF traffic on a segment defines that segment's IGP
trust domain -- Simple Password authentication sends the password in
plaintext, and even Null authentication (still the most common real-world
setting) means any host that can reach the All-OSPF-Routers/
All-DR-Routers multicast groups can inject Hello/LSA traffic and manipulate
routing. Because a rogue OSPF speaker can originate its own Router-LSA
claiming arbitrary links, unexpected OSPF traffic -- especially from a host
that shouldn't itself be a router -- is worth a second look.

#### Validation

All four protocols here are validated against `tools/make_sample_pcap.py`'s
own hand-built, RFC/Wireshark-cross-checked fixtures (`tests/sample_igrp.pcap`,
`sample_pim.pcap`, `sample_eigrp.pcap`, `sample_ospf.pcap`), covering both the
decode paths above and the negative control each protocol's detection
depends on: a too-short IGRP payload, an unrecognized PIM Type nibble, a
too-short EIGRP payload, and an OSPFv3 (Version 3) packet -- every one of
which must fall through to the generic `non-tcp` report rather than being
misdetected. IGRP's own graceful-degradation posture (a plausible header
whose declared route count doesn't match the bytes actually present) is
also exercised directly. The same 1,020-file search across `automayt/
ICS-pcap`, `ITI/ICS-Security-Tools`, and `mrhenrike/PCAPTrafficAnalysis`
that found no RIP/VRRP/HSRP traffic (see the previous section's Validation
subsection) also found no IGRP, PIM, EIGRP, or OSPF traffic anywhere; all
four remain synthetic-fixture-only, the same accepted, precedented gap
already documented for RIP/VRRP/HSRP above (see `tests/real_captures/igmp/
ATTRIBUTION.md`'s "Search outcome for IGRP/PIM/EIGRP/OSPF" section for the
full account).

### Tier 1 remote-access protocol recognition (RDP, VNC, TeamViewer, AnyDesk, Zoom)

The first tier of docs/DEVELOPMENT.md's ROADMAP item 18's "IT protocols an OT auditor flags"
family: interactive remote-control tools that, if reachable from an OT
zone, give an attacker a full interactive session with an HMI or
engineering station -- categorically more dangerous than a Modbus/DNP3/
S7comm read/write, since none of those model "an interactive shell" at
all. See `include/conduitscope/it_protocols.hpp`'s own file header comment
for the full confidence-tier reasoning summarized here.

Deliberately name-only recognition, not protocol decoding -- the same
"recognized but not decoded" posture ARP/LLDP/ICMP already have (see "Link/
IP-layer plumbing" below): each of these five is identified from its port
and, for two of them, a minimal structural signature, and reported as its
own `protocol` value (`rdp`/`vnc`/`teamviewer`/`anydesk`/`zoom`) with a
one-line `summary` -- nothing about the traffic past that point is parsed.
Confidence varies sharply and every summary/note says so plainly rather
than presenting one uniform confidence level:

- **VNC** (RFC 6143) has the strongest signal in this tier: every RFB
  server sends a fixed, 12-byte ASCII protocol-version banner (`RFB
  003.008\n`) as the very first bytes of a session, in the clear, before
  any negotiation happens. Checked **port-independently** -- a real VNC
  server on a nonstandard port is still confidently identified (`decode`
  still notes the port itself isn't the conventional 5900-5906 range, but
  that's informational, not a detection gate).
- **RDP** (TCP port 3389, IANA `ms-wbt-server`) is identified from its
  initial X.224 Connection Request/Confirm, which rides the IDENTICAL
  TPKT (RFC 1006) + COTP (ISO 8073) framing this project's `cotp.hpp`
  already implements for S7comm/MMS on TCP port 102 -- reused here, not
  reimplemented. This one genuinely required a dispatch-order fix: since
  the existing S7comm/MMS COTP check runs opportunistically (port-
  independent) elsewhere in `decoder.cpp`, it would otherwise claim a
  genuine RDP handshake on port 3389 as generic `cotp` traffic before this
  check ever ran -- so RDP's own Connection Request/Confirm check on port
  3389 runs BEFORE that opportunistic S7comm/MMS dispatch, deliberately
  narrow (only a Connection Request/Confirm on port 3389 itself is
  intercepted there; see `decoder.cpp`'s own comment at that call site).
  Past that initial handshake, an RDP session is TLS-wrapped and opaque --
  subsequent packets on port 3389 fall back to the same port-only
  recognition the next three protocols get, explicitly noted as such
  (`decode`'s summary says "port match only, not confirmed by an X.224
  Connection Request/Confirm in this packet").
- **TeamViewer** (TCP/UDP port 5938, IANA `teamviewer`) and **AnyDesk**
  (TCP/UDP port 7070, AnyDesk's own documented default) have no known
  cleartext structural signature at all -- both are encrypted from their
  very first byte -- so both are recognized by port number alone, the
  single weakest identification gate in this entire codebase (weaker even
  than HART-IP's own loosely-checked-header gate: there is no payload
  check whatsoever here).
- **Zoom** rides UDP/TCP ports 8801-8810 for client media/signaling, plus
  UDP 3478-3479 for STUN (per Zoom's own documented network-firewall
  guidance) -- also port-only, and the STUN range gets its own explicit
  caveat that it's a shared convention, not exclusive to Zoom (other
  WebRTC-based conferencing tools commonly use the same range). Zoom's own
  documented TCP 443/80 fallback is deliberately NOT recognized: those
  ports are shared with so much ordinary HTTPS/HTTP traffic that treating
  them as a Zoom signal would be far too weak even by this tier's own
  already-loose "port alone" standard.

`--protocol remote-access` isolates this family from the CLI, the same as
every other `--protocol` value; `--remote-access-port` (repeatable) widens
what counts as an "expected" port for all five at once (one shared option,
the same "one feature toggle" grouping `--ffhse-port` already established
for FF-HSE's own four sub-protocols) -- VNC's own RFB banner check is
never port-gated regardless of this option, since it's a genuinely strong,
self-describing signal (see OPTIONS).

Validated against `tests/sample_remote_access.pcap` (8 packets, hand-built
with scapy): a genuine RDP Connection Request on port 3389; RDP port-only
fallback traffic; a genuine VNC RFB banner on both the standard port and a
nonstandard one; TeamViewer, AnyDesk, and both Zoom port ranges. No real
capture of any of these five protocols was sought for this groundwork
pass -- unlike this project's usual "found a real capture, cross-checked
against it" standard for a fully-decoded protocol, that bar doesn't apply
the same way to five protocols this decoder deliberately never looks
inside of; what matters for a name-only recognizer is that the port/
structural gate itself is correct, which the synthetic fixture confirms
directly.

### Tier 2 lateral-movement protocol recognition (SMB, SSH, HTTP, HTTPS, SNMPv1/v2c, Telnet, FTP, TFTP, QUIC)

The second tier of docs/DEVELOPMENT.md's ROADMAP item 18's "IT protocols an OT auditor flags"
family: protocols that "should be absent from a production OT segment
entirely per most hardening guides" (IEC 62443-3-3, NCSC, NIST SP 800-82) --
lateral-movement and credential-harvesting tools, not interactive-session
tools like Tier 1's own RDP/VNC/TeamViewer/AnyDesk/Zoom. See
`include/conduitscope/it_protocols.hpp`'s own file header comment (the Tier
2 half) for the full confidence-tier reasoning summarized here.

Same deliberately name-only posture as Tier 1: each of these nine is
identified from its port and (for most of the nine) a structural signature,
reported as its own `protocol` value (`smb`/`ssh`/`http`/`https`/`snmp`/
`telnet`/`ftp`/`tftp`/`quic`) with a one-line `summary` -- nothing about the
traffic past that point is parsed, with one narrow, deliberate exception
(SNMP's community string, below). Confidence again varies sharply and every
summary/note says so honestly:

- **SMB** (TCP 445 direct-hosting, or TCP 139 over a NetBIOS Session
  Service wrapper, RFC 1002) is identified from its own 4-byte magic
  (`0xFF"SMB"` for SMB1/CIFS, `0xFE"SMB"` for SMB2/3, `0xFD"SMB"` for an
  SMB2/3 Transform/encrypted header) -- direct-hosting is checked
  **port-independently** (a genuinely strong signal, same treatment VNC's
  RFB banner gets); the NetBIOS-wrapped form is gated to port 139, since
  its own leading type byte alone is too common a value to check
  opportunistically.
- **SSH** (TCP port 22, IANA `ssh`) is identified from RFC 4253's own
  version-exchange banner (`SSH-2.0-OpenSSH_9.6`, always the first bytes of
  a real session, in the clear). Checked **port-independently** -- SSH
  deliberately running on a nonstandard port (a common jump-host hardening
  practice) is still worth flagging, arguably more so. Past the banner, SSH
  is fully encrypted; an established session falls back to a port-only
  match, explicitly noted as weaker.
- **HTTP** is identified from its own request-line or status-line (RFC
  9112) -- checked **port-independently and deliberately so**: the entire
  point of flagging vendor web UIs (Siemens WinCC and similar embedded
  management interfaces) is that they routinely run on whatever port the
  vendor picked, not just 80/8080/8000 (a curated "commonly configured" set
  used only for the non-standard-port note, never a detection gate).
- **HTTPS** reuses this project's own TLS ClientHello parser
  (`tls_sni.hpp`, already built for DoH detection -- see that section
  above) rather than re-implementing TLS record/handshake parsing.
  Deliberately layered right after the existing DoH check, on the same
  single, un-reassembled TCP segment: a DoH match always wins (a known
  public DoH resolver hostname is strictly more specific than "generic
  HTTPS"), and a ClientHello that parses but isn't a known DoH provider's
  hostname falls through to `https` instead. This does **not** by itself
  confirm the traffic is specifically HTTP-over-TLS rather than some other
  TLS-wrapped protocol sharing the same port (MQTT-over-TLS, OPC UA over
  TLS, and similar all begin with an identical ClientHello) -- ALPN
  offering `http/1.1`/`h2` is a genuine confirmation when present; absent
  that, a standard HTTPS port (443/8443, or a configured extra port) is
  treated as good-enough corroboration to still call it `https`, but the
  note says so honestly rather than implying a confidence neither signal
  backs up. An already-established, fully-encrypted session with no
  visible ClientHello in a given packet gets the weakest, port-only
  fallback, same treatment RDP's own post-handshake traffic gets in Tier 1.
- **SNMPv1/v2c** (UDP 161 agent / 162 trap) is identified from the fixed
  ASN.1 BER prefix every SNMPv1/v2c PDU shares -- a `SEQUENCE` wrapping an
  `INTEGER` version (0 = v1, 1 = v2c; v3's very different, USM-
  authenticated framing is out of scope, since v3 has no cleartext
  community string to extract in the first place) followed by an `OCTET
  STRING` community string. This is the one deliberate departure from this
  family's usual name-only posture: the community string itself is
  extracted and surfaced in both the `summary` and a dedicated `note`,
  since per this item's own wording, "a cleartext community string sniffed
  once maps every SNMP-speaking device on the segment" -- the audit value
  here IS the string, not just knowing SNMP was present. Gated to port
  161/162 (unlike SMB/SSH/HTTP above), since ASN.1's own tag bytes are
  common enough elsewhere that checking them opportunistically on every UDP
  port would risk real false positives.
- **Telnet** (TCP port 23) is identified from an IAC (`0xFF`) option-
  negotiation triplet (RFC 854), which a real session sends in a burst
  right at connection start. Gated to port 23 even for this structural
  check -- unlike SMB/SSH/HTTP, `0xFF` alone is too common a byte value in
  arbitrary binary traffic to check opportunistically. Most packets past
  that initial burst are the port-only fallback instead.
- **FTP**'s control channel (TCP port 21 only -- the dynamically-negotiated
  data channel PORT/PASV/EPRT/EPSV set up has no fixed port and no content
  signature of its own past raw file bytes, so it's explicitly out of
  scope) is identified from a 3-digit reply code (RFC 959) or a known
  command verb (`USER`/`PASS`/`RETR`/`STOR`/`LIST`/`PASV`/...). Gated to
  port 21, same "too common a byte shape otherwise" reasoning as Telnet.
- **TFTP** (UDP port 69) has a strong signature for exactly its first two
  opcodes -- RRQ (1) and WRQ (2), each followed by a NUL-terminated
  filename and a NUL-terminated, well-known mode string (`netascii`/
  `octet`/`mail`, RFC 1350) -- validated in full. DATA/ACK/ERROR (the rest
  of a transfer, once under way) have no comparable signature and fall to
  the port-only match, explicitly noted as such.
- **QUIC** (UDP 443/8443 by default, RFC 9000/9001) joins this tier
  alongside HTTPS rather than getting its own tier, the same "encrypted
  transport carrying a web/API session" reasoning HTTPS itself is here for
  -- see `include/conduitscope/quic.hpp`'s own file header comment for the
  full writeup. Every long-header packet (RFC 9000 §17.2 -- Header Form bit
  set, `0x80`) is checked **port-independently**, a genuinely strong
  structural signal (Fixed Bit, Long Packet Type, an exact version match);
  a **client** Initial packet (long type 0, version 1) is decrypted in
  full using RFC 9001 §5's publicly-derivable Initial keys (HKDF-Extract/
  Expand over the packet's own Destination Connection ID and a public,
  per-version salt -- no external key material needed, since these keys
  protect the handshake's confidentiality against passive network
  observers, not against anyone who can also read RFC 9001) far enough to
  remove header protection (AES-128-ECB, §5.4) and AEAD-decrypt the
  payload (AES-128-GCM, §5.3), then extracts the ClientHello's SNI from
  the resulting CRYPTO frame the same way the TCP-carried HTTPS check
  above does. This only ever succeeds for the **client's own** first
  Initial packet: a server's reply Initial packet is encrypted under keys
  derived from the client's SCID, a value this decoder doesn't track
  cross-packet, so its AEAD tag simply won't verify -- reported plainly as
  "AEAD tag did not verify", not as an error, since that's the expected,
  unavoidable outcome for exactly half of all Initial-packet traffic.
  Version Negotiation (RFC 9000 §17.2.1, Version field `== 0`, no Fixed
  Bit requirement) is named only, with the count of offered versions
  parsed from its trailing list of 4-byte entries (also this codebase's
  structural guard against a false match: a payload with a zero version
  field but no valid trailing entries is rejected, not reported as Version
  Negotiation). Handshake, 0-RTT, and Retry long-header packets are named
  only -- each is encrypted under key material (Handshake-level keys,
  session resumption secrets, or nothing decryptable at all for Retry)
  this decoder has no way to derive. A short-header (1-RTT) packet, once a
  session is fully established, carries no version or type field at all
  -- the **only** remaining signal is the required Fixed Bit, so this
  falls back to the weakest, port-only match this codebase uses (the same
  treatment TeamViewer/AnyDesk/LWAPP get), explicitly noted as such.

`--protocol lateral-movement` isolates this family from the CLI, the same
as every other `--protocol` value; `--lateral-movement-port` (repeatable)
widens what counts as an "expected" port for all eight at once (one shared
option, the same grouping `--remote-access-port` already established for
Tier 1) -- SMB's direct-hosting magic, SSH's banner, and HTTP's request-
line/status-line are never port-gated regardless of this option, for the
same reason VNC's RFB banner isn't in Tier 1 (see OPTIONS).

One real implementation wrinkle, in the same spirit as Tier 1's RDP/COTP
one: an FTP reply-code or command-verb line's own leading ASCII bytes can,
purely by coincidence, satisfy MQTT's own single-byte opportunistic
detection gate (mqtt.hpp) -- confirmed empirically while building this
tier's own test fixture (an early "220 Welcome..." FTP banner was
mis-parsed as a bogus MQTT PUBLISH message before this was fixed). Unlike
RDP/COTP's genuine shared wire framing, this is pure coincidence, not two
protocols actually sharing a format, so it's resolved by port instead of
by dispatch-order precedence: FTP traffic on its own well-known
control-channel port (21, or a configured `--lateral-movement-port`) that
structurally matches an FTP reply-code/command-verb line is excluded from
MQTT's own opportunistic detection entirely (both its declared-length
reassembly probe and its full message parse), since no real MQTT broker
runs on port 21 -- see `decoder.cpp`'s own comments at both call sites.

Validated against `tests/sample_lateral_movement.pcap` (21 packets,
hand-built with scapy, including scapy's own `SNMP` ASN.1 layer for
correctness): direct-hosting and NetBIOS-wrapped SMB; SSH banners on a
standard and a non-standard port; HTTP request-lines and a status-line
response, standard and vendor-arbitrary ports; ALPN-confirmed and
port-only-confirmed HTTPS ClientHellos plus the port-only fallback; Telnet
with and without an IAC negotiation burst; FTP reply codes, command verbs,
and the port-only fallback (plus a dedicated regression proving the
MQTT-collision fix); SNMPv2c and SNMPv1 with distinct community strings,
plus the port-only fallback for a non-BER UDP/161 packet; and TFTP RRQ,
WRQ, and a DATA-opcode port-only fallback. As with Tier 1, no real capture
of any of these eight was sought for this groundwork pass -- what matters
for a name-only recognizer is that the port/structural gate itself is
correct, which the synthetic fixture confirms directly.

### Tier 3 enterprise-trust-boundary protocol recognition (NTP, DHCP, LDAP, LDAPS, RADIUS, TACACS+, EAPOL)

The third tier of docs/DEVELOPMENT.md's ROADMAP item 18's "IT protocols an OT auditor flags"
family: protocols that are "individually unremarkable in limited form but
worth an auditor's attention for where they terminate and whether the OT
side blindly trusts enterprise IT for them" -- a different question from
Tier 1's interactive-session risk or Tier 2's lateral-movement risk. See
`include/conduitscope/it_protocols.hpp`'s own file header comment (the
Tier 3 half) and `include/conduitscope/eapol.hpp`'s own file header
comment for the full confidence-tier reasoning summarized here.

DNS/Active Directory needed no new decode work: DNS itself is already
fully decoded (see PROTOCOL COVERAGE's DNS section above) -- this tier is
about correlating where an OT segment's DNS queries actually terminate,
which is a policy/zone-conduit question left open for future work, not a
decoding gap.

Six of this tier's seven protocols are identified from a port and a
structural signature, reported as their own `protocol` value (`ntp`/
`dhcp`/`ldap`/`ldaps`/`radius`/`tacacs-plus`) with a one-line `summary`;
the seventh, EAPOL, rides raw Ethernet (EtherType `0x888E`) rather than
any TCP/UDP port at all, and is covered separately below. Confidence
varies, and every summary/note says so honestly:

- **NTP** (UDP port 123, IANA `ntp`) is identified from RFC 5905 section
  7.3's LI/VN/Mode first byte (Version 1-4, Mode 1-6) plus a minimum
  48-byte NTPv3/v4 header -- a modest structural signature, much weaker
  than VNC's or SSH's own banners, so it stays **port-gated** even for
  this check, the same caution RIP/HSRP/SNMP already earn elsewhere in
  this codebase. This decoder only names the protocol and its Mode; it
  does not extract the actual timestamp fields (an auditor's real interest
  here -- which server the OT segment syncs its clock against -- is a
  policy question, not a decoding one).
- **DHCP** (UDP port 67 server / 68 client) is identified from RFC 1497/
  2131's own 4-byte magic cookie (`0x63 0x82 0x53 0x63`), immediately
  after the fixed 236-byte BOOTP-derived header -- a genuine, strong,
  cleartext structural signature, checked **port-independently** even in
  Auto mode (the same treatment SMB/SSH/HTTP get in Tiers 1-2): a rogue or
  misconfigured DHCP server answering on an unexpected port is exactly
  what this check is meant to catch. Option 53 (DHCP Message Type, RFC
  2132) is additionally decoded by name when present (DISCOVER/OFFER/
  REQUEST/DECLINE/ACK/NAK/RELEASE/INFORM and the RFC 3203/4388
  extensions); every other DHCP option is left unparsed.
- **LDAP** (TCP port 389, or 3268 for Active Directory's Global Catalog)
  is identified from RFC 4511 section 4.1's own LDAPMessage envelope -- a
  BER `SEQUENCE` wrapping an `INTEGER` messageID followed by a protocolOp
  tagged `[APPLICATION n]` (bindRequest/bindResponse/unbindRequest/
  searchRequest/searchResEntry/searchResDone/modifyRequest/
  modifyResponse/addRequest/addResponse/delRequest/delResponse/
  modDNRequest/modDNResponse/compareRequest/compareResponse/
  abandonRequest/searchResRef/extendedReq/extendedResp/
  intermediateResponse). Gated to port 389/3268, the same "ASN.1 tag bytes
  are common enough elsewhere" caution SNMP's own BER check earns in
  Tier 2. An observed `bindRequest` (op 0) gets its own note: if it's a
  simple (non-SASL) bind, the credential is sent in cleartext unless the
  session was already upgraded via StartTLS -- the credential itself is
  never inspected, staying within this whole item's name-only posture.
- **LDAPS** (LDAP-over-TLS, port 636, or 3269 for Global Catalog-over-TLS)
  reuses this project's own TLS ClientHello parser (`tls_sni.hpp`, already
  built for DoH detection, and already reused for Tier 2's own HTTPS --
  see that section above) rather than a second TLS implementation.
  Layered into that SAME early ClientHello call site: a ClientHello on
  port 636/3269 is tagged `ldaps` instead of generic `https`, *unless*
  ALPN itself already confirms HTTP (`http/1.1`/`h2`), in which case the
  more specific ALPN signal wins regardless of port -- a TLS-wrapped
  vendor web UI that happens to reuse the LDAPS port is still correctly
  called `https`, not `ldaps`. An already-established, fully-encrypted
  session with no visible ClientHello in a given packet gets the weakest,
  port-only fallback, same treatment HTTPS's own gets in Tier 2.
- **RADIUS** (UDP port 1812/1813, the RFC 2865/2866-standardized Access/
  Accounting pair, plus the legacy, still commonly seen 1645/1646
  pre-standardization ports) is identified from RFC 2865 section 3's own
  fixed 20-byte header: a small enumerated Code (Access-Request/Accept/
  Reject, Accounting-Request/Response, Access-Challenge, Status-Server/
  Client, and the RFC 5176 Disconnect-Request/ACK/NAK and CoA-Request/
  ACK/NAK values), an Identifier, and a `20 <= Length <= 4096` bound. Per
  this item's own wording ("cleartext-by-default attribute encoding for
  anything past the shared secret"), this decoder deliberately does
  **not** walk RADIUS's own Attribute-Value pairs past the fixed header --
  doing so would cross this whole item's name-only line the way SNMP's
  community string is the one, narrow, deliberate exception to (see
  Tier 2). Gated to port, the same "not self-describing enough alone"
  reasoning as NTP/TACACS+.
- **TACACS+** (TCP port 49, RFC 8907, used almost exclusively for
  network-device-administration AAA) is identified from its own 12-byte
  fixed header: a version byte whose upper nibble is always `0xC`
  (`TAC_PLUS_MAJOR_VERSION`) and whose lower nibble is 0 or 1, a Type byte
  (Authentication/Authorization/Accounting), a Sequence Number, a Flags
  byte, a Session ID, and a body Length. The Flags byte's own
  `TAC_PLUS_UNENCRYPTED_FLAG` (bit `0x01`) is additionally surfaced as its
  own note when set, since RFC 8907 itself calls TACACS+'s body
  "encryption" obfuscation at best even when that flag is clear. Gated to
  port 49, same reasoning as NTP/RADIUS above.
- **IEEE 802.1X/EAPOL** (EtherType `0x888E`, `eapol.hpp`) is
  architecturally different from the other six: no TCP/UDP port, no IP
  layer at all -- the same shape PROFINET RT/GOOSE/Sampled Values/
  EtherCAT already have in this codebase, dispatched from the same
  EtherType-keyed region of `decoder.cpp`, with its own dedicated
  `--protocol eapol` value rather than folding into `--protocol
  enterprise-trust`. The 4-byte EAPOL header (Version 1-3, Type 0-8,
  Length) is parsed in full; two of the nine Types get a shallow further
  look -- an encapsulated EAP packet (Type 0: RFC 3748's own Code/
  Identifier/Length, plus, for Request/Response, a curated EAP Method Type
  name such as Identity/MD5-Challenge/EAP-TLS/EAP-TTLS/PEAP/EAP-FAST) and
  an EAPOL-Key frame (Type 3: just the Descriptor Type byte -- RC4/legacy,
  IEEE 802.11 RSN/WPA2, or WPA/pre-RSN). Nothing past those points is
  parsed (no EAP-TLS handshake content, no EAPOL-Key nonce/MIC/key data,
  no EAPOL-MKA or Announcement TLV bodies). EAPOL's own audit framing cuts
  the *opposite* way from every other protocol in this item: its
  **presence** on an OT switch port is reassuring (the device had to
  authenticate onto the network before passing any other traffic at all),
  so its **absence** is often the real finding -- this decoder can only
  ever report "802.1X traffic was or wasn't captured here," not "802.1X
  is configured but idle," an inherent limit of passive capture rather
  than a shortcut taken here.

`--protocol enterprise-trust` isolates the six port-based protocols from
the CLI (EAPOL is reached only via its own `--protocol eapol`, or in Auto
mode alongside everything else); `--enterprise-trust-port` (repeatable)
widens what counts as an "expected" port for those six at once (one
shared option, the same grouping `--lateral-movement-port` already
established for Tier 2) -- DHCP's magic cookie and LDAPS's own ClientHello
check are never port-gated regardless of this option, for the same reason
SMB/SSH/HTTP aren't in Tiers 1-2 (see OPTIONS). EAPOL needs no port option
at all, matching PROFINET/GOOSE/SV/EtherCAT/STP's own no-port precedent.

One real implementation wrinkle, in the same spirit as Tier 2's own
FTP/MQTT one: LDAP's own leading BER `SEQUENCE` tag byte (`0x30`) is
bit-for-bit identical to a valid MQTT PUBLISH control-packet-type/flags
byte, so MQTT's own opportunistic, port-independent detection gate
(`mqtt.hpp`) matches every genuine LDAP message purely by coincidence --
confirmed empirically while building this tier's own test fixture, the
exact same shape of collision as Tier 2's FTP-vs-MQTT one, resolved the
same way: LDAP traffic on its own configured port (389/3268, or a
configured `--enterprise-trust-port`) that structurally matches an
LDAPMessage envelope is excluded from MQTT's own opportunistic detection
entirely (both its declared-length reassembly probe and its full message
parse), since no real MQTT broker runs on port 389 -- see `decoder.cpp`'s
own comments at both call sites. Worth being explicit about the one
direct consequence: an LDAP message on a genuinely arbitrary, unconfigured
port is **not** rescued by this carve-out (LDAP, unlike SMB/SSH/HTTP in
Tiers 1-2, is deliberately kept port-gated, per its own paragraph above)
and is still misidentified as `mqtt` until that specific port is added via
`--enterprise-trust-port` -- an accepted, documented trade-off of this
tier's "port-gated where the structural signature alone is too common
elsewhere" design, not an oversight; the test fixture below exercises both
the collision and the fix.

Validated against `tests/sample_enterprise_trust.pcap` (26 packets,
hand-built with scapy): NTP client/server Mode plus a too-short port-only
fallback; DHCPDISCOVER/DHCPOFFER plus a non-standard-port DHCPREQUEST
(port-independent, noted); LDAP bindRequest (with its cleartext-bind note)
and searchRequest (standard and Global Catalog ports) plus a port-only
fallback; an LDAP message on an unconfigured port demonstrating the
MQTT-collision trade-off above, and the same message recognized correctly
once `--enterprise-trust-port` widens LDAP's own port; LDAPS ClientHellos
on both the standard and Global Catalog-over-TLS ports plus the port-only
fallback, and a dedicated edge case proving ALPN-confirmed HTTPS still
wins over the LDAPS port when both signals are present in the same
packet; RADIUS Access-Request/Accounting-Response on the current standard
ports, an Access-Request on the legacy port, and a port-only fallback;
TACACS+ Authentication (with its unencrypted-flag note) and Authorization,
plus a port-only fallback; and all five distinct EAPOL frame shapes this
decoder recognizes (EAPOL-Start, EAP-Request/Identity, EAP-Response/
Identity, an EAPOL-Key RSN/WPA2 frame, and EAPOL-Logoff). As with Tiers 1
and 2, no real capture of any of these seven was sought for this
groundwork pass -- what matters for a name-only recognizer is that the
port/structural gate itself is correct, which the synthetic fixture
confirms directly.

### Tier 4 wireless-backhaul-and-cellular protocol recognition (CAPWAP, LWAPP, GTP-U, PPPoE)

The fourth tier of docs/DEVELOPMENT.md's ROADMAP item 18's "IT protocols an OT auditor flags"
family: "wireless access-point control/data planes and cellular
backhaul" -- an AP or wireless LAN controller reachable from (or inside)
an OT zone is itself a finding, independent of whatever rides inside its
tunnel, and PPPoE/GTP-U name the cellular-backhaul-specific case: "a
well-known way SCADA traffic leaves a site entirely outside any on-prem
firewall's view, the usual signature of an RTU or 4G/5G router phoning
out through a vendor's 'cloud gateway' SIM." See
`include/conduitscope/it_protocols.hpp`'s own file header comment (the
Tier 4 half) and `include/conduitscope/pppoe.hpp`'s own file header
comment for the full confidence-tier reasoning summarized here.

Five of this tier's six protocols are identified from a port, reported as
their own `protocol` value (`capwap-control`/`capwap-data`/
`lwapp-control`/`lwapp-data`/`gtp-u`) with a one-line `summary`; the
sixth, PPPoE, rides raw Ethernet (EtherType `0x8863` Discovery /
`0x8864` Session) rather than any TCP/UDP port at all, and is covered
separately below. Confidence varies, and every summary/note says so
honestly:

- **CAPWAP control** (UDP port 5246, RFC 5415) is identified from a
  modest, genuine structural signature: the 1-byte Preamble (Version,
  always 0 -- the only value RFC 5415 defines -- and Type, 0 for a
  plaintext header or 1 for a CAPWAP-over-DTLS header) plus, for a
  plaintext header, the Transport Header's own HLEN field (RFC 5415
  section 4.3), sanity-checked against the captured payload. This decoder
  does **not** attempt a bit-perfect decode of every transport-header
  field (RID/WBID and the six flag bits are left unparsed) -- HLEN alone
  is enough to locate the Control Header that follows, whose own Message
  Type (RFC 5415 section 4.5 / IANA's "CAPWAP Message Types" registry --
  Discovery/Join/Configuration Status/Configuration Update/WTP Event/
  Change State Event/Echo/Image Data/Reset/Primary Discovery/Data
  Transfer/Clear Configuration Request-Response pairs, plus Station
  Configuration Request/Response) is what's actually named. A
  CAPWAP-over-DTLS header is recognized by its Preamble alone -- past it
  is an opaque DTLS record, so no Message Type is ever available for that
  case. Gated to port 5246, the same "not self-describing enough alone"
  reasoning NTP/RADIUS/TACACS+ already earn in Tier 3 -- the Preamble's
  Version/Type nibbles are a much looser gate than GOOSE/SV's own
  single-byte outer BER tag.
- **CAPWAP data** (UDP port 5247) shares the identical Preamble/
  Transport-Header shape as CAPWAP control above, checked the same way --
  but its own payload past the header is the actual bridged wireless
  client frame (802.11, tunneled to the controller for centralized
  forwarding) rather than a Control Header with a Message Type, so this
  decoder names it `capwap-data` and goes no further: per this item's own
  framing, the control/data plane's mere presence is the finding here,
  independent of whatever client traffic rides inside the tunnel --
  decoding the inner 802.11 frame would also require trusting the
  AP/controller pairing this item is itself questioning.
- **LWAPP control** (UDP port 12222) and **LWAPP data** (UDP port 12223)
  are the older, Cisco-proprietary protocol CAPWAP was directly modeled
  on (and superseded -- RFC 5415's own Introduction). Unlike CAPWAP,
  LWAPP was never published as a standards-track RFC (its own IETF draft
  expired unadopted), so this decoder has no authoritative public
  wire-format specification to check a structural signature against.
  Both are recognized by **port number alone** -- the same weakest-gate
  treatment TeamViewer/AnyDesk/Zoom get in Tier 1 -- every match says so
  explicitly.
- **GTP-U** (UDP port 2152, 3GPP TS 29.281) is identified from a genuine
  structural signature in its mandatory 8-byte header: the first byte's
  top 4 bits are always Version(3 bits)=1 concatenated with PT(1 bit)=1
  for GTP (as opposed to GTP', an unrelated charging protocol sharing the
  same Version field) -- i.e. always `0x3` -- followed by an enumerated
  Message Type (255 = G-PDU, the actual tunneled user-plane packet, is by
  far the most common in practice; 1/2 = Echo Request/Response are the
  other frequent ones; 26 = Error Indication, 31 = Supported Extension
  Headers Notification, 254 = End Marker round out the rest of this
  decoder's own curated subset), a Length field (not strictly
  re-validated against the captured payload, the same lenient tolerance
  GOOSE/SV/EtherCAT's own declared-length checks already have), and a
  4-byte TEID (Tunnel Endpoint Identifier) this decoder surfaces but does
  not correlate across packets. Gated to port 2152, same reasoning as
  CAPWAP control above. Per this item's own framing, this decoder
  deliberately does **not** attempt to decode a G-PDU's own inner IP
  packet -- naming the tunnel itself, and its TEID, is the audit-relevant
  finding; unwrapping the inner packet would cross into a second decode
  pass this whole item's name-only posture doesn't call for.
- **PPPoE** (RFC 2516, EtherType `0x8863` Discovery / `0x8864` Session,
  `pppoe.hpp`) is architecturally different from the other five: no
  TCP/UDP port, no IP layer at all -- the same shape EAPOL has in Tier 3,
  dispatched from the same EtherType-keyed region of `decoder.cpp`, with
  its own dedicated `--protocol pppoe` value rather than folding into
  `--protocol wireless-backhaul`. docs/DEVELOPMENT.md's ROADMAP item 18's own wording groups
  PPPoE with GTP-U as "cellular-backhaul-specific": a site's RTU or 4G/5G
  router commonly terminates its own WAN uplink over a PPP session, and
  PPPoE is the most common way that session is carried across the last
  hop to whatever media converter or ONT/modem actually reaches the
  carrier. The 6-byte PPPoE header (Ver=1, Type=1, Code, Session ID,
  Length) is parsed in full; for the Session stage, a further, shallow
  look at the encapsulated PPP frame's own leading Protocol field (RFC
  1661 section 2) names it (IP, IPv6, IPCP, IPv6CP, LCP, PAP, LQR, CHAP,
  EAP) without parsing anything past that field. PAP (Password
  Authentication Protocol) earns its own note: RFC 1334's
  Authenticate-Request carries the username/password pair in cleartext,
  the same "worth a note but not credential extraction" treatment LDAP's
  own bindRequest gets in Tier 3 -- the credential itself is never
  inspected. This decoder does **not** unwrap a PPPoE Session frame's own
  PPP payload to feed it back through IPv4/TCP/UDP dispatch -- the same
  "name the tunnel, don't follow it" posture GTP-U's own G-PDU takes
  above.

`--protocol wireless-backhaul` isolates the five port-based protocols
from the CLI (PPPoE is reached only via its own `--protocol pppoe`, or in
Auto mode alongside everything else); `--wireless-backhaul-port`
(repeatable) widens what counts as an "expected" port for those five at
once (one shared option, the same grouping `--enterprise-trust-port`
already established for Tier 3) -- unlike Tier 3, none of this tier's own
structural checks are strong enough to run port-independently, so this
option always gates detection itself, not just the "expected port"
annotation (see OPTIONS). PPPoE needs no port option at all, matching
EAPOL's own no-port precedent.

Validated against `tests/sample_wireless_backhaul.pcap` (23 packets,
hand-built with scapy): CAPWAP control Discovery Request plus a
DTLS-protected variant, a too-short-for-HLEN weak fallback, and a
port-only fallback; CAPWAP data plaintext and DTLS-protected variants
plus a port-only fallback; LWAPP control/data port-only matches; GTP-U
G-PDU (with its tunneled-user-plane-packet note) and Echo Request plus a
port-only fallback; a CAPWAP control packet on a deliberately
non-standard port demonstrating both the "not recognized without
widening" case and the fix once `--wireless-backhaul-port` widens its
expected-port set; all five PPPoE Discovery codes (PADI/PADO/PADR/PADS/
PADT); Session-stage frames carrying LCP, PAP (with its cleartext-
credential note), and IP; a mid-session PADT; and a malformed PPPoE
header that correctly falls through to the generic `non-ip` fallback,
named by its EtherType rather than decoded. As with Tiers 1-3, no real
capture of any of these six was sought for this groundwork pass -- what
matters for a name-only recognizer is that the port/structural gate
itself is correct, which the synthetic fixture confirms directly.

### Tier 5 generic tunnel/VPN encapsulation recognition (GRE, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve, WireGuard, OpenVPN, dtls-tunnel, STT, MPLS)

The fifth and final tier of docs/DEVELOPMENT.md's ROADMAP item 18's "IT protocols an OT auditor
flags" family: "generic tunnel/VPN encapsulation" -- the broader problem
CAPWAP/GTP-U (Tier 4) are specific instances of. An inner VLAN, Modbus
session, or entire plant subnet is invisible to every decoder in this
codebase, and to `policy validate`'s own flow model, until the outer
tunnel is stripped off -- so merely naming the outer protocol is already
a finding worth surfacing. See `include/conduitscope/tunnel_vpn.hpp`'s and
`include/conduitscope/mpls.hpp`'s own file header comments for the full
confidence-tier reasoning summarized here.

Fourteen of this tier's sixteen protocols are identified from either an
IP protocol number or a TCP/UDP port, reported as their own `protocol`
value with a one-line `summary`; the fifteenth, MPLS, rides raw Ethernet
(EtherType `0x8847` unicast / `0x8848` multicast) rather than any port or
IP layer at all, and is covered separately below. Confidence varies
sharply, and every summary/note says so honestly:

- **GRE** (IP protocol 47, RFC 2784) is identified purely by IP protocol
  number plus one real structural check: its 3-bit Version field must be
  0 (1 is Enhanced GRE/PPTP, out of scope here). Its own 16-bit Protocol
  Type field (an EtherType value, named via the same `ethertype_name()`
  lookup `decode`'s own summary lines already use) further splits this
  into three names: **NVGRE** (RFC 8926, Protocol Type `0x6558` with the
  Key flag set -- honestly noted as ambiguous with plain
  Ethernet-bridging-over-GRE, which shares the identical Protocol Type
  and is structurally indistinguishable from it without interpreting the
  Key field's own VSID/FlowID split), **Mikrotik EoIP** (Protocol Type
  `0x6400`, an unambiguous, widely-recognized-if-not-IANA-registered
  value), and plain `gre` for everything else (most commonly IPv4,
  Protocol Type `0x0800`, RFC 2784's own original use case).
- **ESP** (IP protocol 50, RFC 4303) and **AH** (IP protocol 51,
  RFC 4302) are checked purely by their own IANA-exclusive IP protocol
  number -- there is no further structural gate to check, since ESP's
  body is encrypted/authenticated and AH's own ICV is opaque by design.
  ESP surfaces its SPI; AH additionally names the inner protocol it's
  protecting (via its own Next Header field, since AH -- unlike ESP --
  leaves the inner header visible) alongside its own SPI. Per this item's
  own framing ("worth checking whether its traffic selectors dump a whole
  plant subnet into IT, and whether it's split- or full-tunneled"), this
  decoder cannot see traffic selectors or tunnel-mode negotiation at all
  -- that lives in IKE's own SA negotiation, not in ESP/AH's per-packet
  framing.
- **IP-in-IP** (IP protocol 4, RFC 2003) is checked by IP protocol number
  plus a real structural signature (the payload's first nibble must be 4,
  IP version). Uniquely among this entire tier, its inner header is read
  far enough to surface the inner src/dst IPv4 addresses -- the one
  deliberate exception to this tier's own "name the tunnel, don't unwrap
  it" posture, made because the inner header sits in plaintext
  immediately after the outer one and directly answers this item's own
  "an entire plant subnet is invisible... until the outer tunnel is
  stripped off" framing at essentially zero additional cost.
- **6in4** (IP protocol 41, RFC 4213) is checked the same way as IP-in-IP
  -- IP protocol number plus a real structural signature (first nibble
  must be 6, IPv6 version) -- but its own inner addresses are **not**
  surfaced: this codebase has no IPv6 address parser at all, and writing
  one solely to format two 128-bit addresses for this one case would be
  real scope creep for a name-only recognition tier.
- **L2TP/L2TPv3** (UDP port 1701, RFC 2661 v2 / RFC 3931 v3-over-UDP; and
  IP protocol 115, RFC 3931 section 4.1, L2TPv3's own direct-IP
  encapsulation -- an extension beyond this item's own literal text,
  which only names L2TP's UDP 1701 form, the same "genuinely reachable
  but unnamed by the docs/DEVELOPMENT.md's ROADMAP text" addition Tier 1's own Zoom STUN ports
  precedent already established) is identified as `l2tp` from either
  transport. The UDP form has a genuine structural signature for v2 only
  (a Flags/Version word whose Version nibble must be 2 and whose two
  reserved-bit groups must be 0); a v2 structural mismatch on port 1701
  is still reported `l2tp` (the port itself is IANA-registered
  exclusively for L2TP) but explicitly flagged as the WEAK, port-only
  fallback, since L2TPv3's own Session ID (both its UDP and direct-IP
  forms) has no structural constraint distinguishing it from arbitrary
  data -- the IP protocol number or port carries all the confidence
  there.
- **IKE** (UDP port 500, RFC 7296; also port 4500, RFC 3948
  NAT-Traversal) has a genuine, multi-field structural signature: an
  8-byte Initiator SPI, 8-byte Responder SPI, Next Payload/Version(Major/
  Minor nibbles)/Exchange Type/Flags, Message ID, and a Length field
  loosely checked against the captured payload. Port 4500 additionally
  disambiguates IKE from raw NAT-Traversed **ESP** on the same port by
  checking for RFC 3948's own 4-byte all-zero "non-ESP marker" -- present
  means IKE (behind the marker), absent means the datagram IS an ESP
  header directly, reported `esp` with a NAT-Traversed note.
- **VXLAN** (UDP port 4789, RFC 7348) has a genuine structural signature:
  an 8-byte header whose Flags byte must have the I bit (`0x08`, "VNI
  valid") set and no other bits set, and whose trailing Reserved byte
  must be 0. The 24-bit VNI is surfaced; the tunneled Ethernet frame
  itself is never parsed.
- **Geneve** (UDP port 6081, RFC 8926) has a genuine structural
  signature: the first byte's top 2 bits (Version) must be 0, and the
  second byte's low 6 bits (Reserved) must be 0. The 16-bit inner
  Protocol Type (another EtherType, named the same way GRE's own is
  above) and 24-bit VNI are surfaced; option TLVs and the tunneled frame
  itself are never parsed.
- **WireGuard** (UDP port 51820, the protocol's own wire format) has the
  **strongest** structural signature in this entire tier: a 1-byte
  Message Type (1/2/3/4) followed by 3 mandatory zero reserved bytes, and
  Types 1-3 (Handshake Initiation/Response, Cookie Reply) each have an
  EXACT, fixed total packet length (148/92/64 bytes) -- checked in full,
  the same "self-describing enough to check port-independently" strength
  SMB's magic or DHCP's cookie have, though this decoder still gates it
  to port 51820 purely for consistency with every other UDP-side
  protocol in this tier.
- **OpenVPN** (UDP or TCP port 1194, the protocol's own wire format) has
  a modest structural signature: the first byte's top 5 bits are an
  Opcode from a small enumerated set (OpenVPN's own source-defined P_*
  constants), the bottom 3 bits a Key ID -- a much weaker gate than
  WireGuard's exact-length match above, closer to NTP's own LI/VN/Mode
  gate, honestly reflected in every match. The TCP form is identical past
  a 2-byte big-endian length prefix.
- A **generic DTLS-record structural check** (no fixed port at all -- per
  this item's own wording, "443 and odd UDP ports... CAPWAP's own data
  plane, some vendor AP control channels, and LTE 'offload' clients can
  all ride one") is tried **last** among every UDP check in this tier,
  checked **port-independently** rather than gated: DTLS's own record
  header (RFC 6347 -- ContentType, one of exactly four values, plus
  ProtocolVersion, one of exactly three exact 16-bit values) is a
  genuinely strong, multi-field match, the same "structural signature
  overrides the port gate" treatment VNC/SMB/SSH/HTTP/DHCP already get.
  DTLS's version-major byte (`0xFE`) never collides with plain TLS's own
  (`0x03`), so this never misfires against an ordinary TLS ClientHello
  either. Reported `dtls-tunnel` -- this decoder cannot tell CAPWAP's own
  DTLS data plane, a vendor AP's DTLS control channel, an LTE offload
  client, or a deliberate DTLS-based VPN apart from each other; naming
  that SOME encrypted DTLS tunnel is present is the entire audit value
  here.
- **STT** (TCP port 7878) is recognized by **port number alone** -- the
  same weakest-gate treatment LWAPP gets in Tier 4 -- since it has no
  publicly authoritative wire-format specification (it's a TCP-like
  framing used purely for NIC hardware-offload segmentation, never
  actually establishing a real TCP connection) to check a structural
  signature against.
- **MPLS** (RFC 3032, EtherType `0x8847` unicast / `0x8848` multicast,
  `mpls.hpp`) is architecturally different from the other fifteen: no
  TCP/UDP port, no IP layer at all -- the same shape EAPOL/PPPoE have in
  Tiers 3-4, dispatched from the same EtherType-keyed region of
  `decoder.cpp`, with its own dedicated `--protocol mpls` value rather
  than folding into `--protocol tunnel-vpn`. Its own label stack (Label/
  Exp/Bottom-of-Stack/TTL, 4 bytes per label) is genuinely parsed in
  full, walked label-by-label until a Bottom-of-Stack bit is found,
  capped at 16 entries as a sanity bound -- a stack that runs out of
  captured bytes first is reported truncated rather than treated as a
  parse failure. Unlike every other protocol in this whole family, there
  is no Version/Type field to structurally validate here at all: any
  4-byte-aligned value is syntactically a valid label entry, so (exactly
  like GRE's own Protocol Type sub-cases, or IGMP/VRRP's own
  IP-protocol-number-only gate) the EtherType itself carries all of the
  confidence. The payload past the Bottom-of-Stack label is deliberately
  **not** decoded: an ordinary MPLS-switched IP packet and an MPLS
  pseudowire/L2VPN/VPLS payload (an entire Ethernet frame, optionally
  preceded by a 4-byte all-zero Pseudowire Control Word, RFC 4385) are
  wire-format-identical from this decoder's own point of view, controlled
  entirely by out-of-band LDP/BGP signaling a passive decoder never sees
  -- a heuristic guess here would be far less reliable than IP-in-IP's
  own first-nibble check (a pseudowire's Control Word is frequently all
  zero bytes, indistinguishable from padding or truncation).

Four protocols named in docs/DEVELOPMENT.md's ROADMAP item 18's own Tier 5 text are deliberately
**not** implemented, with the reasoning recorded here rather than silently
skipped (the same posture Tier 3's own DNS paragraph and Tier 4's own SSTP
self-correction already established) -- see docs/USER_GUIDE.md's LIMITATIONS for the
user-facing version:

- **SSTP** (TCP port 443) is not a separate `protocol` value at all: its
  entire handshake, including the one distinguishing cleartext signal it
  has (an HTTP `SSTP_DUPLEX_POST` request line), rides *inside* an
  already-established TLS session -- SSTP is TLS-first, HTTP-inside, so
  that string never appears in cleartext on the wire for this decoder
  (which never decrypts TLS) to see. TCP/443 ClientHellos are already
  unconditionally claimed by the existing HTTPS/DoH early-detection call
  site before this tier's own TCP dispatch is ever reached, making a
  separate SSTP branch dead code regardless -- the same reasoning that
  also rules out a generic TCP-side "tls-tunnel" catch-all (redundant
  with HTTPS's own port-only fallback for the identical reason).
- **4in6** and **DS-Lite/MAP-E** (all IPv6-outer encapsulations) are not
  reachable at all in this codebase: `decoder.cpp` only ever parses an
  IPv4 outer header -- there is no call site these could ever be
  dispatched from.
- **MPLS's own L2VPN/VPLS/pseudowire** use case is not a separate
  `protocol` value -- see MPLS's own paragraph above for why it's folded
  into a note instead.
- **CAPWAP's own alternate data-plane path** (a wireless LAN controller
  decapsulating over GRE/L2TP/IP-in-IP instead of native CAPWAP -- this
  item's own closing clause) needed no new code at all: GRE/L2TP/
  IP-in-IP recognition, built for this tier anyway, already names exactly
  that traffic when it's captured -- the same "needs no new decode work"
  precedent Tier 3's own DNS paragraph established for Active-Directory
  DNS correlation.

`--protocol tunnel-vpn` isolates the fourteen IP-protocol-number/
port-based protocols from the CLI (MPLS is reached only via its own
`--protocol mpls`, or in Auto mode alongside everything else);
`--tunnel-vpn-port` (repeatable) widens what counts as an "expected" port
for every port-based protocol here EXCEPT dtls-tunnel (never port-gated,
see above) -- one shared option, the same grouping
`--wireless-backhaul-port` already established for Tier 4.
GRE/ESP/AH/IP-in-IP/6in4/L2TP's own IP-protocol-number-keyed forms, and
MPLS, need no port option at all, the same no-port precedent IGMP/VRRP/
EAPOL/PPPoE already established (see OPTIONS).

This tier hit a real, and more severe, protocol-collision wrinkle than
any earlier one: HART-IP's own opportunistic, port-independent UDP
detection gate (a 2-byte MessageType/MessageID check) is trivially
satisfied not by coincidence but by two Tier 5 protocols' own
**spec-mandated** wire formats -- RFC 3948's IKE NAT-T non-ESP marker (an
all-zero 4-byte prefix by definition) and RFC 7348's VXLAN header (an
all-zero Reserved field at that exact byte range by definition) --
meaning, unlike Tier 2's FTP/MQTT or Tier 3's LDAP/MQTT coincidental
collisions, genuine NAT-T IKE or VXLAN traffic would **always**
misclassify as `hartip` in Auto mode, not merely occasionally. Resolved
by excluding UDP ports 4500 and 4789 from HART-IP's own opportunistic
Auto-mode attempt entirely (an explicit `--protocol hartip` still
attempts every port, unaffected by this exclusion) -- see `decoder.cpp`'s
own comment at that call site for the full reasoning; unlike the
accepted, documented HART-IP/Modbus TCP collision noted in Tier 1's own
writeup, this one was judged too severe (guaranteed rather than merely
possible) to simply document and leave unresolved.

Validated against `tests/sample_tunnel_vpn.pcap` (28 packets, hand-built
with scapy): all three GRE sub-cases (plain, NVGRE/ambiguous, EoIP) plus a
Version-mismatch fallback; ESP and AH over their own IP protocol numbers;
IP-in-IP with its inner-address extraction plus a malformed fallback;
6in4; L2TPv3's direct-IP form; IKEv2 on port 500; IKEv2 NAT-T with the
non-ESP marker on port 4500; NAT-Traversed ESP (no marker) on the same
port; L2TPv2 over UDP plus its own weak/v3 fallback; VXLAN plus a
malformed fallback; Geneve; WireGuard's Handshake Initiation and
Transport Data message types; OpenVPN over both UDP and TCP; STT; a
generic DTLS record on a deliberately non-standard UDP port; and MPLS
unicast/multicast, a two-label stack, and a truncated single-label stack.
As with Tiers 1-4, no real capture of any of these sixteen was sought for
this groundwork pass -- what matters for a name-only recognizer is that
the port/IP-protocol-number/structural gate itself is correct, which the
synthetic fixture confirms directly, including the HART-IP collision
avoidance described above (both the NAT-T-marker and VXLAN packets are
directly asserted to reach their own Tier 5 name rather than `hartip`).

**All five tiers now feed a "notable IT protocols" finding in `policy
validate` and `inventory`, not just `decode`.** This is the second and
final half of ROADMAP item 18: every `protocol` value named across Tiers
1-5 above (43 in total) is, when observed, surfaced as its own finding by
both reports -- `notable_protocols` in JSON, a "NOTABLE IT PROTOCOLS"
section in text -- completely independent of and never affecting either
report's existing compliance/zone-conduit verdict. This is deliberately a
presence finding, not a policy-matching one: it reuses whatever direction
information each engine already has for a given transport shape (a TCP
flow's own tracked session state; a lower-port-is-server heuristic for
UDP and the handful of IP-protocol-number-keyed Tier 5 tunnels that carry
a port at all; a canonical MAC pair, no direction, for the three
EtherType-keyed protocols -- EAPOL, PPPoE, MPLS -- that have neither IP
nor port at all) rather than adding new session-tracking machinery of its
own. See `include/conduitscope/notable_it_protocols.hpp`'s own file
header comment for the shared lookup table this is built on,
docs/DEVELOPMENT.md's ROADMAP item 18 for the full design writeup, and
docs/USER_GUIDE.md's "Notable IT protocols" subsections (under `policy
validate` and `inventory`) for the exact field-by-field output shape and
the opt-in `--strict-it-protocols` flag.

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
  EtherCAT (`0x88A4`), IEEE 802.1X/EAPOL (`0x888E`), and PPPoE Discovery/
  Session (`0x8863`/`0x8864`) are also named here, but, like CIP I/O below,
  a frame that actually looks like DCP/cyclic IO data, a GOOSE APDU, a
  SavPdu, an EtherCAT frame header, an EAPOL header, or a PPPoE header is
  decoded and reported as `profinet`/`goose`/`sv`/`ethercat`/`eapol`/
  `pppoe`, not `non-ip` -- see PROTOCOL COVERAGE's PROFINET RT, GOOSE,
  Sampled Values, EtherCAT, Tier 3 enterprise-trust-boundary, and Tier 4
  wireless-backhaul-and-cellular sections.
- **IPv4 protocol numbers** (`ipv4.hpp`'s `ip_protocol_name`): IPv6-in-IPv4,
  GRE, ESP, AH, ICMPv6, SCTP are named but not decoded further (`tests/
  sample_link_transport_layers.pcap`'s own "recognized-but-not-decoded"
  example packet uses ICMPv6, protocol 58, for exactly this reason -- see
  below). ICMP (protocol 1), IGMP, VRRP, IGRP, PIM, EIGRP, and OSPF
  (protocol numbers 1, 2, 112, 9, 103, 88, and 89) get their own dedicated
  handling instead of just a name -- see PROTOCOL COVERAGE's "ICMP", "RIP /
  IGMP / VRRP / HSRP", and "IGRP / PIM / EIGRP / OSPF" sections -- as do TCP
  and UDP (below and elsewhere in this document). ICMP was originally in
  this named-but-undecoded group too; full ICMP decoding was added later
  (see the dedicated ICMP section above), at which point the fixture
  example here switched to ICMPv6, the nearest still-undecoded analogue, so
  this "named but not decoded" case keeps being exercised at all.
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
docs/DEVELOPMENT.md's ROADMAP.

Validated by construction (`tests/sample_link_transport_layers.pcap`, see
`tools/make_sample_pcap.py`'s `build_link_and_transport_layer_sample`) and,
organically, against every existing real capture in this project's test
set: re-running the full real-capture corpus after adding this surfaced
several previously-invisible ARP frames and real UDP traffic (DNS on port
53, NetBIOS on port 138) that used to disappear into an undifferentiated
`non-ip`/`non-tcp` bucket.

### TwinCAT / ADS (TCP port 48898/0xBF02, Beckhoff's Automation Device Specification over AMS/TCP)

**The first protocol in this codebase built entirely on the
`ProtocolDecoder` interface**, not the older free-`try_parse_x`-function-
plus-hand-written-`decoder.cpp`-block-plus-flat-`DecodedPacket`-fields
pattern every other protocol above still uses -- see
docs/DEVELOPMENT.md's "registration-model decoder refactor" entry for why,
and `include/conduitscope/protocol_decoder.hpp`/`protocol_registry.hpp` for
the interface itself. One concrete, visible consequence: `twincat_*` JSON
fields (below) are rendered by a small dedicated function in `output.cpp`
reading `DecodedPacket::result` (a type-erased `ProtocolResult`), not by a
30-branch `if (p.protocol == "twincat")` chain reading dozens of flat
`DecodedPacket` fields the way `modbus_*`/`dnp3_*`/etc. are -- there are no
`twincat_*` fields on `DecodedPacket` at all.

TwinCAT is Beckhoff's PLC runtime family; ADS (Automation Device
Specification) is its native RPC-style protocol for reading/writing PLC
variables, querying/controlling device state, and subscribing to cyclic
variable-change notifications, carried over **AMS/TCP** (TCP port 48898).
AMS also rides UDP and serial transports in some Beckhoff setups, but TCP
is the common industrial-network case and the only one this decoder
attempts, matching where every other TCP-based protocol in this codebase
starts too.

#### Wire format

A 6-byte AMS/TCP header -- 2 reserved bytes (conventionally zero on the
wire) plus a 4-byte little-endian **AMS/TCP Data Length** -- directly
precedes the 32-byte AMS header itself:

```
Target AmsNetId(6) + Target AMS port(2) + Source AmsNetId(6) + Source AMS port(2) +
Command ID(2) + State Flags(2) + Data Length(4) + Error Code(4) + Invoke ID(4)
```

followed by exactly Data Length more bytes of command-specific payload.
Every multi-byte field is little-endian except the two AmsNetId fields,
which are just 6 raw address bytes rendered dotted-decimal like an IPv4
address with two extra octets (e.g. `5.62.196.212.1.1`). AMS/TCP Data
Length is the byte count of everything that follows (the 32-byte AMS
header plus its own payload), so it must always equal 32 plus the AMS
header's own Data Length field -- this cross-check between two
independently present length fields is this decoder's strongest
structural signal.

**State Flags**: bit 2 (`0x0004`) is the "ADS command" flag, set on every
ordinary ADS request/response this decoder recognizes (distinguishing it
from a handful of rarer, undocumented-here AMS router-internal message
shapes that don't set it -- rejected, not guessed at); bit 0 (`0x0001`) is
Response (set) vs. Request (clear).

**Command ID** (2-byte field), all nine fully decoded (request AND
response shapes): `0x0001` ReadDeviceInfo, `0x0002` Read, `0x0003` Write,
`0x0004` ReadState, `0x0005` WriteControl, `0x0006` AddDeviceNotification,
`0x0007` DeleteDeviceNotification, `0x0008` DeviceNotification, `0x0009`
ReadWrite. Every other value is rejected outright by this decoder's own
structural gate, not guessed at.

Read/Write/ReadWrite request payloads address a PLC symbol/variable by an
IndexGroup (4 bytes) + IndexOffset (4 bytes) pair -- conceptually similar
to this codebase's own S7comm DB/offset item addressing -- rendered the
same "group:offset" style. DeviceNotification (the unsolicited push a PLC
sends for a subscription set up via AddDeviceNotification) is decoded
**structurally only**: stamp count, per-stamp sample count, and total
sample count, never per-sample values -- the same "recognized but not
decoded further" posture this codebase already takes for Modbus's rare
function codes and S7comm-Plus's Tier 2 services (see DELIBERATELY NOT
IMPLEMENTED below for why).

#### Structural detection gate

(a) at least 38 bytes present (6-byte AMS/TCP header + 32-byte AMS
header); (b) AMS/TCP Data Length == 32 + the AMS header's own Data Length
(the cross-check above); (c) State Flags bit 2 (`0x0004`, "ADS command")
set; (d) Command ID is one of the nine values above; (e) Data Length is
not implausibly large for a real ADS payload (capped at 64 KiB, mirroring
Modbus's own `mbap_length<=300`-style plausibility ceiling). Every check
must pass before anything is trusted as real AMS/TCP.

Surveyed against every other TCP-port-independent protocol this codebase
already tries opportunistically before picking this decoder's registry
position: OPC UA's leading 3 bytes must be one of 7 fixed ASCII
MessageType strings -- AMS/TCP's own leading 2 bytes are conventionally
zero, never ASCII, so no collision. IEC104 requires its first byte to be
the fixed start byte `0x68` -- ruled out by AMS/TCP's conventionally-zero
leading bytes. DNP3's data-link layer requires its first two bytes to be
the fixed sync `0x0564` -- same reasoning, no collision. Modbus/TCP's
protocol-id==0 check reads what, for an AMS/TCP frame, are the low 16 bits
of the 4-byte AMS/TCP Data Length field -- for any realistic ADS payload
size (tens to low thousands of bytes, never an exact multiple of 65536)
those 16 bits are nonzero, so Modbus's own gate correctly rejects real
TwinCAT traffic. TPKT (the S7comm/MMS/S7comm-Plus family's shared framing)
requires its first byte to be version==3 -- again ruled out by AMS/TCP's
conventionally-zero leading bytes. HART-IP/MQTT/FF-HSE are all tried well
after this decoder's own registry position specifically because their own
gates are weaker than this one's five-part check. Registered directly
after Modbus in the TCP-port-independent dispatch order -- costs nothing
to try there, the same "no collision found, so try it as early as its own
gate strength justifies" reasoning OPC UA/EtherNet/IP's own positions
already established.

One implementation note this codebase's own reassembly probe (the
lightweight check that decides whether a TCP segment needs buffering
before the full decode runs) had to get right the hard way: an earlier,
weaker version of that probe checked only the 6-byte AMS/TCP prefix
(reserved + Data Length, range-capped), not the full five-part gate above
-- and that weaker check turned out to be a coincidentally-plausible match
for a wide range of unrelated TCP traffic, confirmed empirically as a real
regression (it was mis-buffering MQTT, FF-HSE, SMB, TACACS+, and OpenVPN
test traffic as candidate AMS/TCP frames, starving their own real dispatch
of the bytes it needed). The probe now requires the complete 38-byte
header before declaring a length at all, and re-applies the same three
structural checks the full decoder uses. The accepted cost: a TwinCAT
frame whose 38-byte header is itself split across TCP segments won't be
recognized as needing buffering (a real AMS/TCP frame's full header
realistically always arrives in one TCP segment -- the whole thing is 38
bytes, far under any real MTU -- so this is a narrow, documented gap, not
an open collision).

#### Authoritative request/response pairing

Every request/response pair is paired by Invoke ID plus AMS/TCP-over-TCP
session (both directions), the same authoritative, non-heuristic pairing
Modbus's own MBAP-transaction-ID pairing established -- proving the
registration-model interface's generic flow-state mechanism
(`DecodeContext::flow_state<T>()`) generalizes to a second,
independently-designed stateful protocol, not just Modbus's own specific
shape. A reused Invoke ID before its previous request was ever answered is
noted, not silently overwritten, and pairs to the most recently
outstanding request. An orphan response (no matching request seen on this
session) is noted, not misattributed. DeviceNotification is deliberately
excluded from pairing entirely -- it's an unsolicited push, not a reply to
a specific request.

#### DELIBERATELY NOT IMPLEMENTED in this pass

**Symbolic name resolution**: mapping a human-readable PLC variable name
to an IndexGroup/IndexOffset pair via ADS's own
`ADSIGRP_SYM_HNDBYNAME`/symbol-table reads -- real depth beyond the raw
IndexGroup/IndexOffset numbers this decoder already renders, and a
reasonable follow-up of its own once this base decode is validated
against real traffic, the same "port-heuristic now, tighten later"
progression several other protocols here already followed.
**Per-sample DeviceNotification payload decoding**: a sample's own bytes
have no fixed shape without knowing which symbol's data type they
represent, which is exactly what symbolic name resolution would provide
-- so this pass decodes DeviceNotification's own envelope (stamp/sample
counts) but not the sample payloads themselves.

#### JSON output fields

Rendered only when `protocol == "twincat"`: `twincat_command` (the Command
ID's canonical name), `twincat_is_response`, `twincat_invoke_id`,
`twincat_target_ams_net_id` / `twincat_target_ams_port`,
`twincat_source_ams_net_id` / `twincat_source_ams_port`,
`twincat_error_code` (only when nonzero), `twincat_index_group` /
`twincat_index_offset` (only for Read/Write/ReadWrite/
AddDeviceNotification, which carry IndexGroup/IndexOffset addressing),
`twincat_ads_result` (only on a response carrying an ADS Result code --
every response shape except DeviceNotification, which carries no Result
at all), and `twincat_paired_request_index` (only on an authoritatively
paired response).

#### Validation

No public real-world TwinCAT/ADS capture was identified while building
this decoder (the same honest gap already documented for FF-HSE and
several other protocols above); validated by construction against a
synthetic `tests/sample_twincat.pcap` fixture (see
`tools/make_sample_pcap.py`'s `build_twincat_sample()`), covering all nine
Command IDs in both request and response shapes, authoritative Invoke-ID
pairing (opposite-direction match, same-direction reuse pairing to the
most recent outstanding request, and an orphan response), a
DeviceNotification push excluded from pairing, a payload truncated
relative to its own command's expected shape, all three structural-gate
rejections (unrecognized Command ID, missing ADS command State Flags bit,
and a Data-Length cross-check mismatch), a non-standard AMS/TCP port, and
a frame split across two TCP segments (confirming Invoke-ID pairing still
resolves correctly once the response is fully reassembled). If a real
TwinCAT/ADS capture becomes available later, it should be added and this
section updated accordingly, the same way this project has handled every
other protocol where independent traffic was eventually found after an
earlier empty search. See `include/conduitscope/twincat.hpp`'s file header
for the full writeup.

### Kerberos (RFC 4120, TCP and UDP port 88) -- Windows Active Directory suite, phase 1 of 4

**The first Windows Active Directory protocol in this codebase**, and the
first of a planned four-part AD suite (Kerberos, LDAP, SMB/NTLM,
Netlogon/DCE-RPC -- delivered one protocol at a time; LDAP is phase 2, see
its own section below; SMB/NTLM and Netlogon/DCE-RPC remain separate
future deliveries, not present here). Built entirely on the
`ProtocolDecoder` interface TwinCAT pioneered (see that section above): two
decoder instances, `KerberosTcpDecoder`/`KerberosUdpDecoder`, sharing one
`id() == "kerberos"`, the same "one protocol, one id(), two `GateKind`
instances" split HART-IP established. No `kerberos_*` fields exist on
`DecodedPacket` -- everything rides `DecodedPacket::result` as a
`KerberosMessage`, rendered by `write_kerberos_json_fields` in `output.cpp`.

AD compromise is a standard pivot point into OT environments (AD-joined
engineering workstations, jump hosts), and Kerberos's own message exchange
carries the wire-level shape of two of the most common AD attack
techniques (Kerberoasting, AS-REP Roasting) directly -- no packet capture
of the actual cryptographic attack itself is needed, only visibility into
what the KDC exchange looks like when it's happening. This is the
motivation for this feature's curated attack/monitoring notes (below), a
deliberately narrow, precisely-documented set rather than broad
best-effort anomaly tagging.

#### Wire format

ASN.1 DER (a definite-length-only BER subset), the same encoding family
MMS already established a BER/TLV reader for in this codebase (reused
here as `kerberos.cpp`'s own, self-contained walker -- see this
codebase's established convention of each protocol keeping its own BER
walker rather than sharing one, already documented for
`asset_inventory.cpp`/`policy_engine.cpp`'s own `session_key`
duplication). Every Kerberos message is `[APPLICATION n] SEQUENCE {...}`,
explicitly tagged throughout (every context-tagged field wraps one
fully-tagged nested TLV -- there is no implicit tagging anywhere in this
protocol's ASN.1 module). Over TCP, each message is preceded by a 4-byte
big-endian length prefix (RFC 4120 SS7.2.2); over UDP, the message is the
whole datagram payload with no such prefix.

Seven message types, keyed by the outer APPLICATION tag byte
(`0x60 | msg-type`): **AS-REQ** (10, `0x6A`) / **TGS-REQ** (12, `0x6C`) --
fully decoded: `pvno` (must be 5), `msg-type` (cross-checked against the
outer tag), `padata` (named subset: PA-ENC-TIMESTAMP(2),
PA-ETYPE-INFO(11)/PA-ETYPE-INFO2(19), PA-PAC-REQUEST(128),
PA-FOR-USER(129, S4U2Self shape), else `"padata-type N"`), and
`req-body`'s `kdc-options` (BIT STRING -> named flags: forwardable,
forwarded, proxiable, proxy, allow-postdate, postdated, renewable,
canonicalize, disable-transited-check, renewable-ok, enc-tkt-in-skey,
renew, validate), `cname`/`realm` (AS-REQ only -- TGS-REQ authenticates
via its embedded AP-REQ inside `padata`, not a plaintext `cname`, per RFC
4120's own comment), `sname`, `till` (KerberosTime, rendered ISO-8601),
`nonce`, the offered `etype` list (named subset: des-cbc-crc(1)/
des-cbc-md5(3)/rc4-hmac(23)/rc4-hmac-exp(24)/
aes128-cts-hmac-sha1-96(17)/aes256-cts-hmac-sha1-96(18), else
`"etype N"`), and `additional-tickets` presence (the S4U2Proxy/
constrained-delegation shape). **AS-REP** (11, `0x6B`) / **TGS-REP** (13,
`0x6D`) -- fully decoded: `crealm`/`cname`, the embedded `Ticket`'s own
visible fields (`realm`/`sname`, and its `enc-part`'s `etype` -- NOT the
ciphertext, which needs keys), and the response's own outer `enc-part`
`etype` (also unencrypted on the wire -- this is what actually reveals
RC4-vs-AES for the curated notes below). **KRB-ERROR** (30, `0x7E`) --
fully decoded: `error-code` (named table: KDC_ERR_C_PRINCIPAL_UNKNOWN(6),
KDC_ERR_S_PRINCIPAL_UNKNOWN(7), KDC_ERR_ETYPE_NOSUPP(14),
KDC_ERR_CLIENT_REVOKED(18), KDC_ERR_PREAUTH_FAILED(24),
KDC_ERR_PREAUTH_REQUIRED(25), KRB_AP_ERR_SKEW(37), else `"error N"`),
`cname`/`sname`/`realm` when present, `e-text` when present. **AP-REQ**
(14, `0x6E`) / **AP-REP** (15, `0x6F`) -- structural only: `ap-options`
(BIT STRING -> use-session-key, mutual-required) and, for AP-REQ, the
embedded `Ticket`'s visible `realm`/`sname`/`enc-part` `etype` (the same
downgrade-visibility value as above, and the field a forged/Golden-ticket
`enc-part` etype would show up in); the `Authenticator`/AP-REP `enc-part`
ciphertext itself is opaque without keys and is not decoded (see
DELIBERATELY NOT IMPLEMENTED below).

#### Structural detection gate and collision survey

Outer tag byte must be one of `{0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
0x7E}` (constructed APPLICATION 10/11/12/13/14/15/30 -- Kerberos never
needs tag numbers past 30, so only the ASN.1 low-tag-number form is ever
handled; a high-tag-number form is rejected outright, not mishandled);
the outer SEQUENCE's BER length must fit within the available bytes;
then, on full decode, `pvno` (context `[0]` or `[1]` depending on
message shape -- see `try_parse_kerberos`'s own comment for the exact
position table) must equal 5 **and** `msg-type` must equal the value
implied by the outer APPLICATION tag -- this two-field cross-check, not
just a leading magic byte, is the strong signal, the same "more than one
independent structural check" rigor OPC UA/EtherNet-IP/TwinCAT already
established. `KerberosTcpDecoder::tcp_declared_length()` reads the 4-byte
length prefix **and** peeks at the following byte for one of the same
seven tag values before returning a declared length, so the TCP
reassembly probe is nearly as selective as the full decode gate, not
merely "4+ bytes present."

Surveyed against every protocol already tried port-independently on TCP
and UDP, per this codebase's own convention (see TwinCAT's own survey
above for the shape this follows): OPC UA's 7 fixed ASCII MessageType
strings (none start with the ASCII characters `j`/`k`/`l`/`m`/`n`/`o`
that a `0x6A`-`0x6F` tag byte would render as, if it were ever
misinterpreted as ASCII, which it structurally cannot be here in the
first place); IEC104's fixed `0x68` start byte; DNP3's fixed `0x0564`
sync; Modbus's protocol-id==0 field; TwinCAT's conventionally-zero AMS/TCP
reserved bytes; TPKT's version==3 byte. None collide with a
`0x6A`-`0x6F`/`0x7E` leading tag byte on TCP, or with CIP I/O's exact
CPF-item-type-plus-length check or BACnet's BVLC Type==`0x81` check on
UDP. Registered directly after TwinCAT in the TCP-port-independent chain
(TCP) and directly after HART-IP in the UDP-port-independent chain (UDP)
-- see `protocol_registry.cpp`'s own inline comments for both.

#### Curated attack/monitoring detection

A deliberately narrow set of named findings, each with its own heuristic
and false-positive caveat spelled out in its own note text -- not broad
best-effort tagging (see this feature's own header comment for the
Jurgen's-own-scoping-decision context). Every note surfaces a wire-level
fact and is explicitly worded to avoid asserting detected intent, the
same honest framing S7comm's `plc_stop_message` and TwinCAT's own
deferred-feature notes already use:

1. **AS-REP Roasting** -- two-tier. A **standing, low-severity note** on
   any AS-REQ whose `padata` includes no PA-ENC-TIMESTAMP entry: this
   alone is NOT anomalous (every real Windows client's very first AS-REQ
   in an exchange looks exactly like this, and normally gets
   `KDC_ERR_PREAUTH_REQUIRED` back). The **flagship flag** fires only on
   a **successful** AS-REP (never a KRB-ERROR) that correlates, on the
   same session, to an AS-REQ that had no PA-ENC-TIMESTAMP -- see
   State/correlation below for exactly how that correlation works, and
   its documented limitation.
2. **Kerberoasting** -- on a TGS-REP whose embedded **Ticket's own**
   `enc-part` `etype` is RC4 (23) for an `sname` that isn't `krbtgt`.
   Deliberately keyed off the Ticket's OWN enc-part etype (encrypted to
   the target SERVICE account's long-term key -- the material
   Kerberoasting actually cracks offline), never the response's own
   outer `enc-part` etype (encrypted to the requesting CLIENT's session
   key, which says nothing about the target account and is checked
   separately by the downgrade note below). `krbtgt` tickets are
   excluded -- a normal TGT (re-)request, not a service ticket; flagging
   every RC4 TGT on a mixed-etype domain would be noisy and isn't what
   Kerberoasting targets.
3. **Weak-encryption/downgrade note** (always-on, lower severity, not
   itself attack-specific): on any AS-REQ/TGS-REQ whose offered `etype`
   list includes DES/RC4 with no AES type offered at all -- general
   exposure visibility, useful on its own for an audit even with no
   active exploitation in the capture.
4. **Delegation-shape surfacing** (structural, not an assertion of
   abuse): `kdc-options` flags relevant to delegation
   (forwardable/proxiable/proxy) and `additional-tickets` presence (the
   S4U2Proxy/constrained-delegation shape) rendered as a note --
   surfaces the wire-level shape unconstrained/constrained delegation
   relies on, nothing more.
5. **KRB-ERROR code naming plus `--stats` aggregation** -- not a
   per-packet flag but a passive monitoring aid: named error-code counts
   aggregated across the whole capture (`StatsWriter::kerberos_error_counts_`,
   mirroring `twincat_command_counts_`'s own pattern), so a burst of
   `KDC_ERR_PREAUTH_FAILED`/`KDC_ERR_C_PRINCIPAL_UNKNOWN` -- a
   password-spray/account-enumeration signal -- is visible in `--stats`
   output with no per-session correlation needed at all.

#### State/correlation design and its documented limitation

`KerberosFlowState`, keyed by `FlowStateKeying::Session` (built via
`tcp_session_key(...)`, confirmed transport-agnostic and reused as-is for
both the TCP and UDP call sites -- no new helper needed). Two small maps:
outstanding AS-REQs keyed by `cname` (visible in AS-REQ, unlike TGS-REQ),
and outstanding TGS-REQs keyed by the requested `sname` (more directly
useful for the Kerberoasting correlation than any client-identity key,
since TGS-REQ often omits `cname` entirely). A later request for the same
key overwrites the earlier pending entry -- so a retry (e.g. the ordinary
no-preauth-then-`PREAUTH_REQUIRED`-then-retry-with-preauth sequence a
real Windows client produces) correctly updates what the eventual
response correlates against, rather than latching onto the first
attempt.

**Honest limitation, stated plainly**: this correlates by
session+cname/sname, **not** the `nonce` field RFC 4120 itself defines
for exactly this purpose -- because the nonce echo lives inside the
response's encrypted part and is unreadable without keys from a passive
capture. This is sufficient for realistic single-exchange-at-a-time KDC
traffic; it could misattribute only if the same client had two genuinely
overlapping, unanswered requests on one session, which is rare in
practice.

#### DELIBERATELY NOT IMPLEMENTED in this pass

**KRB-SAFE(20)/KRB-PRIV(21)/KRB-CRED(22)**: rare outside app-level
Kerberos usage (kpasswd and similar), not part of the core AD auth
exchange. **PAC contents**: embedded in the Ticket's encrypted part,
unreadable without the target account's or `krbtgt`'s key from a passive
capture -- no SID/group extraction, no PAC signature validation, ever,
the same honest limit any passive-capture Kerberos analysis has
(Wireshark's own dissector can't decrypt these either without keys).
**The Authenticator (AP-REQ) and AP-REP's own `enc-part` ciphertext**:
opaque without keys, same reasoning. **Symbolic ASN.1 CHOICE
alternatives beyond the padata-type/etype/error-code tables above**:
render as their raw numeric form (`"padata-type N"`/`"etype N"`/
`"error N"`), the same graceful-fallback posture as every existing
named-enum-with-fallback table in this codebase (DNP3's point-format
table, TwinCAT's command-name table). **LDAP** is now implemented -- see
its own section below. **SMB/NTLM, Netlogon/DCE-RPC**: the remaining two
protocols of the planned four-part AD suite -- separate future
deliveries, not present here.

#### JSON output fields

Rendered only when `protocol == "kerberos"`: `kerberos_message_type` /
`kerberos_msg_type_value` / `kerberos_is_response` / `kerberos_pvno`
(always present); `kerberos_padata_types` (array) plus
`kerberos_has_pa_enc_timestamp` (only when `padata` is present);
`kerberos_kdc_options` (array, only when non-empty);
`kerberos_cname`/`kerberos_realm`/`kerberos_sname`/`kerberos_till` (only
when set -- see the wire-format section above for which message types
set which); `kerberos_nonce` (AS-REQ/TGS-REQ only);
`kerberos_etypes` (array, only when non-empty);
`kerberos_has_additional_tickets` (only when true);
`kerberos_crealm` (only when set); `kerberos_ticket_tkt_vno` /
`kerberos_ticket_realm` / `kerberos_ticket_sname` /
`kerberos_ticket_enc_part_etype` (only when an embedded Ticket was
decoded); `kerberos_enc_part_etype` (only when the response's own outer
`enc-part` was decoded); `kerberos_error_code` / `kerberos_error_name` /
`kerberos_error_text` (KRB-ERROR only, `error_text` only when present);
`kerberos_ap_options` (array, only when non-empty); and
`kerberos_correlated_request_index` (only on a response authoritatively
correlated to an earlier request -- see State/correlation above).

#### Validation

No public real-world Kerberos capture was incorporated in this pass (the
same honest gap already documented for TwinCAT and several other
protocols above); validated by construction against synthetic
`tests/sample_kerberos.pcap` (UDP, 15 packets --
`tools/make_sample_pcap.py`'s `build_kerberos_sample()`) and
`tests/sample_kerberos_tcp.pcap` (TCP, 3 packets), covering all six
message types, both curated flagship notes with an explicit correlated
positive case each, three explicit negative cases proving the
curated-not-noisy bar is actually met (a krbtgt-sname TGS-REP excluded
from the Kerberoasting note despite an RC4 ticket, an AES-only TGS-REP
negative control, and the ordinary no-preauth-then-`PREAUTH_REQUIRED`-
then-retry-with-preauth AS-REQ/KRB-ERROR/AS-REQ/AS-REP sequence that must
NOT trigger the AS-REP-Roasting flagship note), the always-on downgrade
note, the delegation-shape structural note, two named KRB-ERROR codes (for
`--stats` aggregation), a non-standard UDP port note, and a TCP frame
both whole and split across two TCP segments (confirming
`KerberosTcpDecoder::tcp_declared_length` reassembly). If a real Kerberos
capture becomes available later, it should be added and this section
updated accordingly, the same way this project has handled every other
protocol where independent traffic was eventually found after an earlier
empty search. See `include/conduitscope/kerberos.hpp`'s file header for
the full writeup.

### LDAP (RFC 4511, TCP/389 and TCP/3268 Global Catalog) -- Windows Active Directory suite, phase 2 of 4

**The second Windows Active Directory protocol in this codebase.** LDAP
already had shallow, name-only recognition (Tier 3's "enterprise-trust"
family, `it_protocols.hpp`/`.cpp`) before this decoder existed; that
recognition is now removed in favor of this full decoder, the same "pull
one protocol out of a shared tier into its own dedicated decoder/CLI
surface" move this codebase already made once for EAPOL --
`match_ldap_ber`/`looks_like_ldap_ber` (`it_protocols.hpp`) are the one
piece kept from that old code, reused as-is by this decoder's own
structural gate rather than duplicated. Built entirely on the
`ProtocolDecoder` interface TwinCAT/Kerberos already use: one decoder
instance, `LdapTcpDecoder`, `id() == "ldap"`, `GateKind::TcpPortIndependent`
-- unlike Kerberos, there is deliberately **no UDP sibling** (CLDAP, RFC
1798, is obsolete/deprecated and not part of mainstream AD traffic). No
`ldap_*` fields exist on `DecodedPacket` -- everything rides
`DecodedPacket::result` as an `LdapMessage`, rendered by
`write_ldap_json_fields` in `output.cpp`.

LDAP reconnaissance (SPN sweeps, `userAccountControl` bit queries) is
literally how a real attacker *finds* the AS-REP-Roasting/Kerberoasting
targets `kerberos.hpp`'s own curated notes already flag, so this phase
completes that story rather than starting a new one -- see the curated
notes below, several of which explicitly point back at the Kerberos
decoder's own findings.

#### Wire format

RFC 4511's ASN.1 module is `DEFINITIONS IMPLICIT TAGS` -- the **opposite**
of Kerberos's (RFC 4120) `EXPLICIT TAGS` convention (confirmed against
the actual ASN.1 module text, not recalled from training). Concretely: a
context/APPLICATION tag **replaces** the underlying type's own tag rather
than wrapping a separately-tagged inner TLV -- there is no "peel one
layer" step anywhere in this decoder's own BER reader (`ldap.cpp`), unlike
`kerberos.cpp`'s own `explicit_child()`. For example, `bindRequest
[APPLICATION 0] BindRequest` where `BindRequest ::= [APPLICATION 0]
SEQUENCE {...}` wire-encodes as ONE tag byte `0x60` whose content bytes
are `version`/`name`/`authentication` directly -- not `0x60` wrapping a
nested `0x30`. The constructed-vs-primitive bit of a tagged field is
likewise NOT uniform -- it depends on the underlying type, checked
per-field (`ldap.cpp`'s own `ldap_op_shape` table): e.g. `AbandonRequest
::= [APPLICATION 16] MessageID` (INTEGER, primitive) wire-encodes as
`0x50`, not `0x70`; `DelRequest ::= [APPLICATION 10] LDAPDN` (OCTET
STRING, primitive) wire-encodes as `0x4A`; `UnbindRequest ::= [APPLICATION
2] NULL` wire-encodes as `0x42`, zero-length content. Every other
`protocolOp` alternative is SEQUENCE- or LDAPResult(SEQUENCE)-typed, hence
constructed. The same rule applies recursively inside `SearchRequest`'s
`Filter` CHOICE (RFC 4511 section 4.5.1) -- see `ldap.cpp`'s own
`decode_filter` for the full per-alternative tag/shape table. LDAP-over-TCP
has no separate length-prefix framing (unlike Kerberos's own 4-byte
prefix): each `LDAPMessage`'s own outer `SEQUENCE`'s BER length **is** the
framing.

Full field decode, scoped to the operations most relevant to
authentication/reconnaissance (matching `kerberos.hpp`'s own "not every
message type needs the same depth" discipline):

- **BindRequest**/**BindResponse**: `version`, `name` (bind DN),
  `authentication` (`simple` -- presence + byte length only, the
  credential bytes themselves are NEVER rendered; `sasl` -- mechanism name
  decoded, credentials presence/length only, same never-rendered
  treatment, since SASL PLAIN carries an `authzid\0authcid\0password`
  triple in that same field). `BindResponse`: `resultCode` (named, full
  RFC 4511 section 4.1.9 table), `matchedDN`, `diagnosticMessage`.
- **UnbindRequest**: presence only (NULL body).
- **SearchRequest**: `baseObject`, `scope`/`derefAliases` (named),
  `sizeLimit`, `timeLimit`, `typesOnly`, `attributes`, and `filter` --
  decoded recursively and rendered in conventional `ldapsearch`-style
  syntax (e.g. `(&(objectClass=user)(servicePrincipalName=*))`).
  Recursion depth capped via `max_ldap_filter_depth()` (wraps
  `resource_limits().max_recursion_depth`, the `mms.cpp`/`goose.cpp`
  pattern).
- **SearchResultEntry**: `objectName`, and its attribute type=value list
  -- values rendered as strings, capped in length, with binary-looking
  values shown as `"(N bytes, binary)"` rather than a guessed string
  decode (this codebase's existing "don't guess at unstructured binary"
  posture).
- **SearchResultDone**/**SearchResultReference**: `resultCode`/
  `matchedDN`/`diagnosticMessage`; referral URIs.
- **CompareRequest**/**CompareResponse**: `entry`, the attribute+value
  compared, and the boolean result.
- **AbandonRequest**: the `messageID` being abandoned.
- **ExtendedRequest**/**ExtendedResponse**: `requestName`/`responseName`
  OID (named for well-known OIDs where confidently known, e.g. StartTLS =
  `1.3.6.1.4.1.1466.20037`); `requestValue`/`responseValue`
  presence/length only, never decoded (opaque per-extension payload).

**STRUCTURAL-ONLY** (recognized, message type + `messageID` named, not
field-decoded): AddRequest/AddResponse, ModifyRequest/ModifyResponse,
DelRequest/DelResponse, ModifyDNRequest/ModifyDNResponse,
IntermediateResponse -- write operations and the rarer response type,
lower pentest/monitoring value for a first pass.

#### Structural detection gate and collision survey

Reused from `it_protocols.hpp`'s own `match_ldap_ber`/`looks_like_ldap_ber`,
not duplicated: (a) outer tag `0x30` (SEQUENCE) with a BER length that
plausibly fits the available bytes; (b) `messageID` INTEGER (1-4 bytes)
immediately inside; (c) `protocolOp`'s own tag byte matches APPLICATION
class (`tag & 0xC0 == 0x40`), tag number one of the 21 valid values
`{0..16, 19, 23, 24, 25}`. `try_parse_ldap` (`ldap.cpp`) adds the
**stronger** per-field check `match_ldap_ber` doesn't: the constructed bit
must ALSO match that specific op number's own underlying-type shape (see
the Wire format section above) -- not a blanket "any APPLICATION tag
passes" check.

**Collision survey**: a real collision was found and resolved during this
decoder's own planning, not left for implementation to discover --
Kerberos's outer APPLICATION tag bytes for AS-REP/TGS-REQ/TGS-REP/AP-REQ/
AP-REP (`0x6B`/`0x6C`/`0x6D`/`0x6E`/`0x6F`) are byte-identical to LDAP's
own `delResponse`/`modDNRequest`/`modDNResponse`/`compareRequest`/
`compareResponse` APPLICATION tags (RFC 4511's module is IMPLICIT TAGS, so
those five LDAP operations -- all LDAPResult- or SEQUENCE-typed, hence
constructed -- produce the exact same tag byte class+number as five of
Kerberos's seven message types). This does NOT actually collide at the
dispatch-gate level: Kerberos's structural gate reads the outer tag of
the ENTIRE de-framed payload (its own message-type tag IS byte 0 there,
after its own 4-byte TCP length prefix is stripped), while every
LDAPMessage's byte 0 is ALWAYS the fixed envelope SEQUENCE tag `0x30` --
LDAP's own per-operation APPLICATION tags only appear several bytes
INSIDE the envelope, as the `protocolOp` field, never as the leading byte
either decoder's own gate inspects. Also unaffected by the pre-existing,
already-solved LDAP-vs-MQTT collision (`0x30` is also a valid MQTT
PUBLISH control-packet-type/flags byte) -- see `it_protocols.hpp`'s
`looks_like_ldap_ber` comment for that carve-out, reused as-is by
`decoder.cpp`'s MQTT call site. No collision found against any other
protocol in the TCP-port-independent cascade (OPC UA/EtherNet-IP/IEC104/
Modbus/TwinCAT/DNP3/COTP/HART-IP/FF-HSE) -- none of their own fixed
leading-byte/magic-string checks match `0x30`. Registered directly after
Kerberos in `tcp_port_independent_registry()`.

#### Curated attack/monitoring detection

Every note is framed as surfacing a wire-level mechanism or shape, never
as an assertion of detected intent -- legitimate directory tooling uses
several of these same filter shapes too:

1. **Anonymous/unauthenticated bind** -- standing note, unconditional:
   simple authentication with no password (RFC 4513 section 5.1.2's own
   anonymous/unauthenticated bind shapes).
2. **Cleartext credential exposure without prior StartTLS** -- a simple
   bind with a non-empty password, or a SASL PLAIN bind, is flagged only
   when no `ExtendedRequest` naming the StartTLS OID has been observed
   earlier on this same TCP session (`LdapFlowState::starttls_seen`). The
   password itself is never rendered.
3. **AD reconnaissance filter shapes** -- a `SearchRequest` filter
   referencing `servicePrincipalName` is the standard Kerberoasting
   target-discovery step (directly upstream of `kerberos.hpp`'s own
   Kerberoasting note); a filter referencing `adminCount` is the standard
   privileged-account sweep.
4. **AS-REP-Roasting target discovery** -- a filter using
   `userAccountControl` with a bitwise `extensibleMatch` (the AD-specific
   `LDAP_MATCHING_RULE_BIT_AND` OID, `1.2.840.113556.1.4.803` -- confirmed
   via Microsoft's own MS-ADTS spec) against the `DONT_REQ_PREAUTH` bit
   (`0x400000` -- confirmed via Microsoft's own troubleshooting doc),
   directly upstream of `kerberos.hpp`'s own AS-REP-Roasting note.
5. **Delegation discovery** -- the same bitwise-match mechanism against
   the `TRUSTED_FOR_DELEGATION` bit (`0x80000`) or a filter referencing
   `msDS-AllowedToDelegateTo` -- the LDAP-side complement of the
   delegation-shape note `kerberos.hpp` already surfaces on the wire.
6. **Bind result-code naming plus `--stats` aggregation** -- the
   LDAP-native analog of Kerberos's own KRB-ERROR count aggregation: named
   `resultCode` counts (`invalidCredentials(49)` above all) aggregated
   across the capture, so a burst of failed binds across many distinct
   bind DNs -- the password-spray signature -- is visible with no
   per-request correlation needed.

#### State/correlation design

`LdapFlowState`, keyed by `FlowStateKeying::Session` (`tcp_session_key`,
reused as-is). Three pieces of state: `starttls_seen` (set on an
`ExtendedRequest` naming the StartTLS OID, never cleared -- a session
doesn't un-upgrade); a pending-bind map (created on `BindRequest`,
matched-and-erased on `BindResponse`, keyed by `messageID`); a
pending-search map (created on `SearchRequest`, **NOT erased** on each
`SearchResultEntry` -- only the running entry count is incremented --
erased with a final "N entries returned" correlation note on
`SearchResultDone`). This last shape -- "keep state across many
responses, close on the terminal one" -- is genuinely new relative to
`kerberos.hpp`'s own 1:1 request/response pairing, since one
`SearchRequest` can have arbitrarily many `SearchResultEntry` responses
before its one `SearchResultDone`.

Worth stating as a genuine **improvement** over Kerberos's own documented
limitation, not another instance of it: LDAP's `messageID` is the
RFC-mandated, always-visible-on-the-wire correlation key (RFC 4511
section 4.1.1.1 requires it to be unique among a connection's outstanding
requests) -- unlike Kerberos, where the real `nonce` correlation field is
unreadably encrypted and `cname`/`sname` had to be used as an honest
substitute.

#### DELIBERATELY NOT IMPLEMENTED in this pass

**CLDAP** (UDP, RFC 1798, obsolete) -- no UDP decoder instance at all.
**SASL/`simple` credential contents** -- never decrypted/decoded, only
presence+length, by design, not a depth gap to close later. **Controls'
`controlValue` payloads** -- OID named when a control is present (e.g.
the well-known Paged Results Control), value bytes not decoded. **LDAPS
full decode** -- needs keys, same limit as TLS everywhere else in this
codebase (see `it_protocols.hpp`'s own LDAPS handling, unaffected by this
decoder). **SMB/NTLM** now has its own dedicated decoder (see below);
**Netlogon/DCE-RPC** remains the fourth and final protocol of the planned
four-part AD suite -- a separate future delivery.

#### JSON output fields

Rendered only when `protocol == "ldap"`: `ldap_message_id` /
`ldap_message_type` / `ldap_op_num` / `ldap_is_response` (always
present); `ldap_bind_version` / `ldap_bind_dn` / `ldap_bind_is_sasl` /
`ldap_bind_auth_mechanism` / `ldap_bind_credential_present` /
`ldap_bind_credential_length` (BindRequest only, `credential_length` only
when a credential is present); `ldap_result_code` /
`ldap_result_code_name` / `ldap_matched_dn` (only when set) /
`ldap_diagnostic_message` (only when set) / `ldap_referral_uris` (only
when non-empty) (BindResponse/SearchResultDone/CompareResponse/
ExtendedResponse); `ldap_search_base_object` / `ldap_search_scope` /
`ldap_search_deref_aliases` / `ldap_search_size_limit` /
`ldap_search_time_limit` / `ldap_search_types_only` /
`ldap_search_filter` / `ldap_search_attributes` (SearchRequest);
`ldap_search_result_object_name` / `ldap_search_result_attributes`
(SearchResultEntry); `ldap_search_entry_count` (SearchResultDone only, see
State/correlation above); `ldap_compare_entry` / `ldap_compare_attribute`
/ `ldap_compare_value` (CompareRequest); `ldap_abandon_message_id`
(AbandonRequest); `ldap_extended_request_name` /
`ldap_extended_request_name_known` (only when a recognized OID) /
`ldap_extended_response_name` / `ldap_extended_value_present` /
`ldap_extended_value_length` (only when a value is present)
(ExtendedRequest/ExtendedResponse); `ldap_control_oids` (only when
non-empty); and `ldap_correlated_request_index` (only on a message
authoritatively correlated to an earlier request -- see State/correlation
above).

#### Validation

No public real-world LDAP capture was incorporated in this pass (the same
honest gap already documented for Kerberos and several other protocols
above); validated by construction against synthetic
`tests/sample_ldap.pcap` (TCP, 62 packets across 17 independent
sessions/flows -- `tools/make_sample_pcap.py`'s `build_ldap_sample()`)
and `tests/sample_ldap_tcp_split.pcap` (TCP, 2 packets: one SearchRequest
split across two segments), covering every message type (full and
structural-only), all six curated notes with an explicit negative case
each (a StartTLS-then-cleartext-bind session proving note 2's suppression,
a SASL GSSAPI bind proving note 2 never fires on a non-PLAIN mechanism, a
bitwise filter against an unrelated `userAccountControl` bit proving
notes 4/5 stay silent, and a deliberately ordinary AND/OR/NOT/equality/
present/approxMatch/greaterOrEqual/lessOrEqual/substrings filter proving
notes 3-5 stay silent on traffic that doesn't touch their trigger
attributes/bits), the "many SearchResultEntry, one SearchResultDone"
correlation with its own entry-count note, a binary-looking attribute
value rendered `"(N bytes, binary)"`, a Paged Results control
(`control_oids` coverage), `--stats` resultCode aggregation (note 6), a
non-standard TCP port (with `--ldap-port` suppressing just the note, not
detection), and a TCP-segment-split reassembly case. All expectations in
`CMakeLists.txt`'s `ldap_*` test family were captured from the actual
built binary's output against these fixtures, not hand-computed. If a
real LDAP capture becomes available later, it should be added and this
section updated accordingly. See `include/conduitscope/ldap.hpp`'s file
header for the full writeup.

### SMB2/NTLM (MS-SMB2, MS-NLMP; TCP/445 and TCP/139) -- Windows Active Directory suite, phase 3 of 4

**The third Windows Active Directory protocol in this codebase.** SMB
already had shallow, name-only recognition (Tier 2's "lateral-movement"
family, `it_protocols.hpp`/`.cpp`) before this decoder existed -- a 4-byte
magic check (`0xFF`/`0xFE`/`0xFD` + `"SMB"`) at offset 0 (direct hosting)
or offset 4 (NetBIOS-wrapped, port 139), nothing decoded past that; that
recognition is now removed in favor of this full decoder, the same "pull
one protocol out of a shared tier into its own dedicated decoder/CLI
surface" move already made for EAPOL and LDAP -- `match_smb_magic`
(`it_protocols.hpp`) is the one piece kept from that old code, reused as-is
by this decoder's own structural gate rather than duplicated. Built on the
`ProtocolDecoder` interface Kerberos/LDAP already use: one decoder
instance, `SmbTcpDecoder`, `id() == "smb"`, `GateKind::TcpPortIndependent`
-- no UDP sibling, SMB has none. NTLM itself (MS-NLMP) has its own small
shared parser, `include/conduitscope/ntlm.hpp`/`src/ntlm.cpp` -- called
from `smb.cpp`, no `ProtocolDecoder`/gate/port of its own, since NTLM only
ever appears embedded inside SMB2's own `SESSION_SETUP` bodies in this
phase's scope and its wire format is byte-identical wherever it appears
(unlike Kerberos/LDAP's own duplicated-per-embedding BER readers, which
exist because those two protocols use genuinely different ASN.1 tagging
conventions -- NTLM has no such variation, so sharing is the correct
application of the same underlying principle, not an exception to it). No
`smb_*`/`ntlm_*` fields exist on `DecodedPacket` -- everything rides
`DecodedPacket::result` as an `SmbFrame`, rendered by `write_smb_json_fields`
in `output.cpp`.

A successful NTLM (or Kerberos) authentication over SMB is exactly what an
attacker does with the credentials Kerberos's/LDAP's own curated notes
already flag (a Kerberoasted/AS-REP-Roasted ticket cracked offline, or
credentials harvested via LDAP recon) -- SMB is where those credentials
get *used*, most often via NTLM relay/pass-the-hash against the
`ADMIN$`/`C$`/`IPC$` administrative shares for lateral movement. This
phase completes that story the same way LDAP's own text framed itself as
completing Kerberos's.

#### Wire format

Fixed-width little-endian fields throughout -- **not** BER/ASN.1 like
Kerberos/LDAP. Every message, on either port 445 or port 139, is preceded
by a 4-byte header ([MS-SMB2] section 2.1's "Direct TCP transport packet
header", structurally identical to RFC 1002 section 4.3.1's NetBIOS
Session Service *SESSION MESSAGE* header): `Zero` (1 byte, MUST be `0x00`)
+ `StreamProtocolLength` (3 bytes, big-endian, the byte count of the
following SMB2 message only). `smb_tcp_declared_length` reads these same 4
bytes on both ports and returns `4 + StreamProtocolLength`. Port 139's own
NBSS session-establishment handshake (`SESSION REQUEST`/`POSITIVE
RESPONSE`/`NEGATIVE RESPONSE`, RFC 1002 4.3.2-4.3.4) is deliberately out of
scope -- the gate simply doesn't fire on those 1-2 handshake packets (their
magic bytes aren't `SMB`), and decoding starts from the first real SMB2
message onward.

The **SMB2 Packet Header** (64 bytes fixed, every message): `ProtocolId`
(the verified `0xFE"SMB"` magic), `StructureSize` (MUST be 64),
`CreditCharge`, `Status` (response only: NTSTATUS, named via a curated
subset -- see curated note 6 below), `Command` (named, all 19 values
`0x00`-`0x12`), `CreditRequest`/`CreditResponse` (read, not rendered),
`Flags` (named: `SERVER_TO_REDIR`/`ASYNC_COMMAND`/`RELATED_OPERATIONS`/
`SIGNED`/`PRIORITY_MASK`/`DFS_OPERATIONS`/`REPLAY_OPERATION`),
`NextCommand` (the compounding chain pointer, see below), `MessageId`
(the wire-mandated correlation key, echoed identically on the matching
response -- the same genuine improvement over Kerberos's own honest
`cname`/`sname` substitute that LDAP's `messageID` already demonstrated),
`Reserved`+`TreeId` (SYNC) or `AsyncId` (ASYNC), `SessionId`, `Signature`
(never verified -- no key material available, the same limit this codebase
applies to every other cryptographic signature/MAC it encounters).

**Compounding** ([MS-SMB2]'s own mechanism for concatenating several SMB2
messages inside one 4-byte-prefixed unit, chained via each header's own
`NextCommand` field) is a genuinely new wrinkle neither Kerberos nor LDAP
had at the wire-format level. `parse_smb2_chain` (`smb.cpp`) walks the
`NextCommand` chain structurally -- every sub-message's header is read and
its command named, and a malformed/overrunning `NextCommand` value stops
the chain (keeping whatever was already parsed) rather than misparsing the
rest as garbage -- capped by both the available bytes running out and a
hard limit on the number of sub-messages
(`resource_limits().max_decoded_objects`).

Full field decode, scoped to authentication/reconnaissance (matching
`kerberos.hpp`'s/`ldap.hpp`'s own "not every message type needs the same
depth" discipline):

- **NEGOTIATE Request/Response**: Request's `Dialects[]` array (every
  offered dialect named -- `0x0202`/`0x0210`/`0x0300`/`0x0302`/`0x0311`,
  plus the pre-SMB2 multi-protocol-negotiate wildcard `0x02FF`, all
  verified against [MS-SMB2]) and `SecurityMode`; Response's negotiated
  `DialectRevision`, `SecurityMode` (named: `SIGNING_ENABLED`/
  `SIGNING_REQUIRED` -- the direct input to curated note 2), `Capabilities`
  (named, all 7 flags -- `DFS`/`LEASING`/`LARGE_MTU`/`MULTI_CHANNEL`/
  `PERSISTENT_HANDLES`/`DIRECTORY_LEASING`/`ENCRYPTION`), `ServerGuid`. The
  SMB 3.1.1 `NegotiateContextList` is structural-only for this pass
  (present/length only, matching LDAP's own `controlValue` posture) --
  it sits in a trailing region of both messages, so skipping it cannot
  corrupt the rest of the parse.
- **SESSION_SETUP Request/Response**: Request's `SecurityMode`,
  `Capabilities`, `PreviousSessionId` (session-binding indicator), and its
  `Buffer` -- scanned for the 8-byte `"NTLMSSP\0"` signature (a pragmatic
  substitute for fully implementing SPNEGO/GSS-API's own ASN.1 grammar
  [RFC 4178] just to unwrap one layer, the same "structural signature, not
  full grammar" bar this codebase already applies elsewhere); when found,
  the NTLM message is parsed via `ntlm.hpp`'s shared parser. Response's
  `SessionFlags` (named: `IS_GUEST`/`IS_NULL`/`ENCRYPT_DATA` -- the direct
  input to curated note 4) and its own `Buffer`, same NTLM-signature scan
  (carries the server's CHALLENGE_MESSAGE). `Status`
  `STATUS_MORE_PROCESSING_REQUIRED` marks a non-terminal leg of a
  multi-leg handshake (see State/correlation below).
- **TREE_CONNECT Request/Response**: Request's share path (UTF-16LE,
  decoded via the shared `utf16le_to_utf8` codec in `byteio.hpp`/`.cpp` --
  the direct input to curated note 5, a path ending in `$`). Response's
  `ShareType` (named: disk/pipe/print) and `ShareFlags`/`Capabilities`
  (named, all values from [MS-SMB2] 2.2.10) -- `ShareType == pipe` plus a
  `$`-suffixed path identifies `IPC$` specifically, the strongest form of
  note 5.
- **LOGOFF**, **TREE_DISCONNECT**: header-only, both directions.

**Structural-only** (recognized, command named, not field-decoded):
CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO,
QUERY_DIRECTORY, CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK -- the
file-I/O-heavy commands, lower pentest/monitoring value for a first pass.
IOCTL is worth calling out explicitly: DCE/RPC-over-named-pipe traffic
(Netlogon chief among it) rides inside CREATE+WRITE+READ/IOCTL against an
`IPC$`-hosted named pipe -- decoding that payload is squarely phase 4's
job, not this one.

##### NTLM message coverage (`ntlm.hpp`/`ntlm.cpp`)

- **NEGOTIATE_MESSAGE** (type 1): `NegotiateFlags` (named, the full 22-bit
  table), `DomainName`/`WorkstationName` (OEM-encoded, present only when
  the corresponding `_SUPPLIED` flag is set).
- **CHALLENGE_MESSAGE** (type 2): `TargetName`, `NegotiateFlags`,
  `ServerChallenge` (8 raw bytes -- a nonce, not a secret, safe to render,
  unlike the credential material below), `TargetInfo` decoded as a proper
  `AV_PAIR` list (every `AvId` named -- `MsvAvEOL`/`MsvAvNbComputerName`/
  `MsvAvNbDomainName`/`MsvAvDnsComputerName`/`MsvAvDnsDomainName`/
  `MsvAvDnsTreeName`/`MsvAvFlags`/`MsvAvTimestamp`/`MsvAvSingleHost`/
  `MsvAvTargetName`/`MsvAvChannelBindings`; string-typed pairs rendered,
  opaque ones byte-length-only), `Version` when present.
- **AUTHENTICATE_MESSAGE** (type 3): `NegotiateFlags`, `DomainName`,
  `UserName`, `WorkstationName` (all UTF-16LE, decoded), `Version`, MIC
  presence (a best-effort heuristic, see `ntlm.cpp`'s own
  `detect_mic_present` comment -- MS-NLMP defines no dedicated flag bit for
  it). **`LmChallengeResponse` and `NtChallengeResponse` are never rendered
  beyond presence + byte length** -- this is the actual proof-of-possession
  /hash material (the entire point of an NTLM relay or an offline NTLMv2
  crack), and rendering it would make this decoder itself a
  credential-harvesting tool; the same "credential itself is never
  inspected" posture LDAP's own bind-password handling established now
  gets its sharpest application yet. `EncryptedRandomSessionKey` is the
  same: presence/length only. In practice `output.cpp`'s own JSON writer
  goes further still and never surfaces even the presence/length of these
  three fields -- only `ntlm_user_name`/`ntlm_domain_name` (identity, not
  proof-of-possession material) are rendered for an AUTHENTICATE_MESSAGE.

#### Structural detection gate

Reused from `it_protocols.hpp`'s own `match_smb_magic`, not duplicated:
the 4-byte `0xFF`/`0xFE`/`0xFD` + `"SMB"` signature, already registered
and proven collision-free in `tcp_port_independent_registry()`. This phase
only changed what happens *after* the gate fires (full decode instead of
magic-only recognition), not the gate itself. `try_parse_smb` additionally
requires the 4-byte Zero+StreamProtocolLength prefix ahead of that magic
on BOTH ports -- stricter than the old Tier 2 heuristic, which incorrectly
allowed a magic-at-offset-0 form with no prefix at all (see Validation
below for a real-world consequence of this fix). Registered directly
after LDAP in `tcp_port_independent_registry()`.

#### Curated attack/monitoring detection

Every note is framed as surfacing a wire-level mechanism, never an
assertion of detected intent -- legitimate admin tooling routinely uses
several of these same shapes too:

1. **SMB1 traffic present** -- standing, fires once per session (a sticky
   flag, not a per-message repeat): the `0xFF` magic byte, distinct from
   SMB2/3's `0xFE`. SMB1 is the EternalBlue/WannaCry-class legacy dialect;
   its mere presence on a network, OT segments especially, is a
   commonly-checked finding on its own.
2. **SMB signing not required** -- from the NEGOTIATE Response's
   `SecurityMode`: `SIGNING_ENABLED` set, `SIGNING_REQUIRED` **not** set.
   The precondition every NTLM-relay tool (`ntlmrelayx` and equivalents)
   checks for before attempting a relay attack -- the SMB-side analog of
   LDAP's own StartTLS-awareness note.
3. **NTLM negotiated for this session** -- a `SESSION_SETUP` request or
   response whose `Buffer` contains the `"NTLMSSP\0"` signature. A
   downgrade/relay-friendly signal on its own (Kerberos is preferred by
   policy in a well-run AD environment) -- the SMB-side complement of the
   Kerberos and LDAP decoders' own notes, completing the "this is how the
   earlier phases' targets get used" story from the introduction above.
4. **Anonymous or guest session established** -- the `SESSION_SETUP`
   Response's `SessionFlags`: `IS_GUEST` or `IS_NULL` set. A well-known
   misconfiguration (null-session enumeration), in the same family as
   LDAP's own anonymous-bind note.
5. **Administrative/hidden share access** -- a `TREE_CONNECT` request path
   ending in `$` (`ADMIN$`, `C$`, and above all `IPC$`), correlated
   against the response's own `ShareType` once available to confirm
   `IPC$` specifically via `ShareType == pipe`. `IPC$` access is very
   often the literal next step after a successful authentication in a
   real lateral-movement chain (named-pipe-based remote service control --
   PsExec and equivalents), the SMB-side analog of LDAP's SPN-sweep note's
   own "the next step after auth" framing.
6. **Repeated authentication failure across a capture** -- the SMB-side
   analog of Kerberos's KRB-ERROR counts and LDAP's resultCode counts:
   named `Status` values from `SESSION_SETUP` responses aggregated in
   `--stats` -- `STATUS_SUCCESS`, `STATUS_MORE_PROCESSING_REQUIRED`
   (the non-terminal NTLM handshake leg, counted separately from a true
   failure), `STATUS_LOGON_FAILURE`, `STATUS_ACCESS_DENIED`,
   `STATUS_WRONG_PASSWORD`, `STATUS_PASSWORD_EXPIRED`,
   `STATUS_ACCOUNT_DISABLED`, `STATUS_ACCOUNT_LOCKED_OUT` (`0xC0000234`,
   independently confirmed at implementation time), with any other
   `Status` value reported numerically rather than guessed at. A burst of
   `STATUS_LOGON_FAILURE` across many distinct usernames on one session is
   the SMB-side password-spray signature.

#### State/correlation design

`SmbFlowState`, keyed by `FlowStateKeying::Session` (`tcp_session_key`,
reused as-is). Two pieces of state, because this phase introduces a
correlation shape neither Kerberos nor LDAP needed: a simple
`MessageId`-keyed `pending_requests` map (1:1 request/response pairing for
NEGOTIATE, TREE_CONNECT, LOGOFF, and TREE_DISCONNECT -- the plain
Kerberos-style shape); and a `SessionId`-keyed `pending_ntlm_handshakes`
map (**genuinely new**: NTLM's own negotiate/challenge/authenticate
exchange is a multi-leg handshake spanning *two separate* `SESSION_SETUP`
request/response pairs, each with its own `MessageId`, tied together only
by the `SessionId` the server assigns in the first response
(`STATUS_MORE_PROCESSING_REQUIRED`) and the client echoes in the second
request -- opened on that response, closed with a single coherent "NTLM
handshake for `domain`, {succeeded|failed}" correlation note on the
terminal `SESSION_SETUP` response for that `SessionId`). This is the
SMB-side equivalent of LDAP's own "keep across many responses, close on
the terminal one" pattern, just keyed by `SessionId` instead of a single
message's own `messageID`, because the *thing* being correlated here is a
multi-message handshake rather than a one-to-many search. Both maps capped
by `resource_limits().max_decoded_objects`, the same guard Kerberos's and
LDAP's own pending-request maps use.

#### DELIBERATELY NOT IMPLEMENTED in this pass

SMB1/CIFS's own full command set (SMB1 traffic is *recognized* -- curated
note 1 -- but not decoded past that). NBSS session-establishment (RFC 1002
4.3.2-4.3.4 -- named NetBIOS computer names, no authentication/recon
value). SMB 3.x message **signing verification** and **encryption**
(`0xFD`-prefixed `TRANSFORM_HEADER` messages are recognized and named,
never decrypted -- the same limit this codebase applies to every encrypted
protocol it meets). The SMB 3.1.1 `NegotiateContextList`. Full SPNEGO/
GSS-API ASN.1 decode (the `NTLMSSP\0` signature scan is the deliberate
substitute -- a Kerberos-mechanism SPNEGO blob is simply not matched by
that scan). **DCE/RPC-over-named-pipe payloads, Netlogon chief among
them** -- explicitly phase 4, the final protocol of the planned four-part
AD suite. Every file-I/O command's own field-level content.

#### JSON output fields

Rendered only when `protocol == "smb"`: `smb_envelope_kind` /
`smb_compounded` / `smb_messages` (always present, `smb_messages` possibly
empty for SMB1/SMB2_TRANSFORM traffic). Per message in `smb_messages`:
`command` / `command_value` / `is_response` / `message_id` / `session_id`
/ `tree_id` (or `async_id`) (always present); `status` / `status_name`
(response only); `header_flags` (only when non-empty); `compounded_next`
(only when this sub-message chains to another); `negotiate_dialects`
(NEGOTIATE request only); `negotiated_dialect` / `server_guid` /
`security_mode` / `capabilities` (NEGOTIATE response only);
`previous_session_id` (SESSION_SETUP request only); `session_flags`
(SESSION_SETUP response only, when non-empty); `ntlm_message_type` /
`ntlm_target_name` (when non-empty) / `ntlm_user_name` (when non-empty) /
`ntlm_domain_name` (when non-empty) (only when NTLM was found in this
message's own buffer -- see the credential-material note above for what is
deliberately NOT rendered); `tree_connect_path` (TREE_CONNECT request
only); `share_type` / `share_flags` (only when non-empty) (TREE_CONNECT
response only); `ntlm_handshake_summary` (only on the SESSION_SETUP
response that closes a multi-leg handshake); `correlated_request_index`
(only on a message authoritatively correlated to an earlier request).

#### Validation

No public real-world SMB2/NTLM capture with a full authentication
handshake was incorporated in this pass; validated by construction against
synthetic `tests/sample_smb.pcap` (TCP, 26 packets across 7 independent
sessions/flows A-G -- `tools/make_sample_pcap.py`'s `build_smb_sample()`)
and `tests/sample_smb_tcp_split.pcap` (TCP, 2 packets: one NEGOTIATE
Request split across two segments), covering every message type (full and
structural-only), all six curated notes with an explicit negative case
each, the full NTLM negotiate/challenge/authenticate handshake and its own
multi-leg correlation (both a succeeded and a failed outcome), compounding
(NEGOTIATE chained to SESSION_SETUP via `NextCommand`), `--stats` Status
aggregation (note 6), a non-standard TCP port (with `--smb-port`
suppressing just the note, not detection), and a TCP-segment-split
reassembly case. Every byte offset and note-trigger condition was first
independently smoke-tested against a hand-built synthetic exchange,
decoded and inspected in both `--format text` and `--format json`, BEFORE
this fixture (and the `CMakeLists.txt` `smb_*` test family reading it)
were written -- the same verification discipline Kerberos's/LDAP's own
deliveries were held to.

One genuine real-world data point did emerge as a side effect of this
decoder's stricter framing check: `tests/real_captures/hartip/hart_ip.pcapng`
(the HART-IP real-capture fixture) contains an incidental SMB1 connection
in its background traffic that used to be misreported as an unresolved
HART-IP weak-gate false positive; it is now correctly recognized and
decoded as `[smb]` with curated note 1, the first real-world confirmation
of this decoder's own SMB1 magic-byte detection gate -- see
`tests/real_captures/hartip/ATTRIBUTION.md`'s own updated section for the
detail. If a real capture containing a full SMB2/NTLM authentication
handshake becomes available later, it should be added and this section
updated accordingly. See `include/conduitscope/smb.hpp`'s and
`include/conduitscope/ntlm.hpp`'s file headers for the full writeup.

