# Provenance of these fixtures

14 of these 15 files are real S7comm/COTP captures pulled from
<https://github.com/automayt/ICS-pcap> (commit
`13b7ae335529146b40535c2d7aa756886040d8ad`, 2026-09-15), under its `S7/`
directory -- see `tests/real_captures/dnp3/ATTRIBUTION.md` for the general
notes on that source project (no explicit license accompanies it; included
here as real, non-sensitive protocol test vectors, on the same basis).

| File in this directory                       | Source path in automayt/ICS-pcap |
|------------------------------------------------|-----------------------------------|
| `s7comm_varservice_read_db1dbd0.pcap`          | `S7/1-S7comm-VarService-Read-DB1DBD0/...` |
| `s7comm_varservice_cyclicdata_1s.pcap`         | `S7/2-S7comm-VarService-CyclicData-1s/...` |
| `s7comm_vat_mb100_mw200_md300_m400.pcap`       | `S7/3-S7comm-VAT_MB100_MW200_MD300_M400-0/...` |
| `s7comm_download_db1_with_password_request.pcap` | `S7/4-S7comm-Download-DB1-with-password-request/...` |
| `s7comm_1200_uploading_ob1_tiav12.pcap`        | `S7/S7-1200-Uploading-OB1-TIAV12/...` |
| `s7comm_plus_1511_opc_request_all_types.pcap`  | `S7/S7-1511-opc-request-all-types/...` |
| `s7comm_plus_1511_db3_var1_hmi.pcap`           | `S7/S7-1511_db3_var1_HMI/...` |
| `s7comm_1200_hmi.pcap`                         | `S7/s7-1200-hmi/...` |
| `s7comm_downloading_block_db1.pcap`            | `S7/s7comm_downloading_block_db1/...` |
| `s7comm_program_blocklist_onlineview.pcap`     | `S7/s7comm_program_blocklist_onlineview/...` |
| `s7comm_reading_plc_status.pcap`               | `S7/s7comm_reading_plc_status/...` |
| `s7comm_reading_setting_plc_time.pcap`         | `S7/s7comm_reading_setting_plc_time/...` |
| `s7comm_varservice_libnodavedemo_bench.pcap`   | `S7/s7comm_varservice_libnodavedemo_bench/...` |
| `s7comm_varservice_libnodavedemo.pcap`         | `S7/s7comm_varservice_libnodavedemo/...` |

Two other files at that path (`S7-1511_db2_var1_HMI`, `S7-1511_db6w0_HMI`)
are pcapng despite their `.pcap` extension and were skipped -- conduitscope
correctly detects and rejects them with a conversion hint rather than
misparsing them, which is itself covered by the `rejects_pcapng` CTest case
against a synthetic fixture. Two `.pcapng`-named files in that folder
(`V13_1200_TP1200sim_*`) were skipped outright for the same reason.

Notably, none of these classic-S7comm captures contain `0xB2` (S7-1200/1500
"symbolic") addressing, despite several being named after S7-1200/1500
hardware -- the four with real `Read Var`/`Write Var` item traffic
(`s7comm_varservice_read_db1dbd0`, `s7comm_varservice_cyclicdata_1s` with
1373 items, `s7comm_varservice_libnodavedemo`, and
`s7comm_varservice_libnodavedemo_bench` with nearly 9000 items) all use
classic S7ANY addressing. The `S7-1511_*`/`s7-1200-hmi`/`S7-1200-*`-named
captures turned out to be **S7comm-Plus** (a different, newer TIA-Portal-native
protocol -- see the dedicated addendum below for how conduitscope's full
S7comm-Plus decoder now performs against the two `s7comm_plus_*` files) or
block upload/download traffic that doesn't use Read/Write Var. So this set
is good additional real-world regression coverage for the classic S7ANY
item-decode path and, since the addendum below, genuine Tier-1 S7comm-Plus
decoding too, but it does **not** touch the `0xB2` EXPERIMENTAL decode --
see below for where real `0xB2` traffic actually came from.

## `s7comm_1200sym_real_polling.pcap` -- separate provenance, and a correction

This one file is **not** from the `S7/` directory above. It's a 40-packet
slice (the first 40 packets of one TCP stream) manually extracted from
`Additional Captures/4SICS-GeekLounge-151021/4SICS-GeekLounge-151021.pcap`
in the same `automayt/ICS-pcap` repository -- itself a copy of a public
4SICS/netresec ICS-lab capture (see
<https://www.netresec.com/?page=PCAP4SICS>). That source file is 140MB
(1,253,100 packets) and overwhelmingly S7comm, so the whole thing isn't kept
here; this slice is a representative sample of a real, repeating Read Var /
Ack_Data poll cycle.

**Important caveat, not caught until after this was first written up**: this
is almost certainly *not* an independent new capture. Its packet count
("1.25M") and the exact items it decodes to -- `M2.0` through `M2.4`, with
the identical CRC values (`0xea2db0d9`, `0x78041f0f`, `0x6b1223fc`,
`0xf93b8c2a`, `0x4d3e5a1a`) -- match the pre-existing "validated against real
capture traffic for exactly one shape... five sequential real requests
decoded to `M2.0` through `M2.4`" note already in `docs/MANUAL.md`'s S7comm
section, which was based on a large real 4SICS capture supplied earlier in
this project's development. This is, to a very high degree of confidence,
the same real PLC/HMI session (or the same TIA Portal project running
continuously across the multi-day 4SICS show floor) that finding already
came from -- reached here via a different path (the `automayt/ICS-pcap`
mirror) rather than a genuinely separate deployment. So this is *not* a new
independent real-world data point the way the DNP3 and Modbus real fixtures
are.

What *is* new: the original note was based on spot-checking five sequential
requests. Decoding the **entire** 140MB source file found **over 1 million**
real `0xB2` items from that same session, every one of them going through
the structural decode path with **zero** fallbacks (no "unrecognized area1",
no "multi-LID" bailout) across the whole file -- meaningfully more
confidence that the structural shape holds for the full duration of one real
session, even though it's still one session's worth of traffic, not several
independent ones. It does *not* prove the CRC-to-symbol-name mapping is
correct -- that's inherently unresolvable without the originating TIA Portal
project file, which is why the decode stays marked `[EXPERIMENTAL]`
regardless. This 40-packet slice keeps a permanent, small regression fixture
for that finding even though the multi-hundred-megabyte source can't
reasonably live in this repository.

## S7comm-Plus: what the two real captures actually contain, decoded

Both `s7comm_plus_1511_db3_var1_hmi.pcap` and
`s7comm_plus_1511_opc_request_all_types.pcap` were originally added to this
project only to validate the old "S7comm-Plus detected, not decoded" stub.
Once full S7comm-Plus decoding existed (see `include/conduitscope/s7commplus.hpp`
for the wire-format research and Tier-1/Tier-2 split), both were re-decoded
with `--format text`, `--format json`, and `--stats` to see what real TIA
Portal S7-1511 traffic actually looks like through the new decoder, before
writing a single new CTest assertion against them.

**`s7comm_plus_1511_db3_var1_hmi.pcap`** (an HMI polling/writing a single DB,
`DB3`) is genuinely rich real-world traffic: across its ~50 S7comm-Plus PDUs
it exercises three of the four Tier-1 functions --

- `GetMultiVariables` request/response, both the native symbolic addressing
  form (`SYM-CRC=a9bc66e6, LID=DB3.10`) and a simple `(Byte) = 0x02` scalar
  response value, with `s7plus_integrity_digest_present: true` on the
  response (the Integrity part's digest length/id decode correctly; the
  digest bytes themselves are surfaced, never verified, matching this
  project's established checksum-surfaced-not-verified convention).
- `SetMultiVariables` request/response (three items per call, repeated
  identically across three separate TCP sessions/HMI reconnects), whose
  request values are the richest real data either file provides: a
  `Struct` with a `WString` member (`"1;6ES7 511-1AK00-0AB0;V1.0"`, an
  order-code/version string), an `Addressarray` of `UInt`, and a
  **Struct-of-Struct** -- `id=1803`/`id=1804` are each themselves a nested
  `Struct` containing a `ULInt`/two `UDInt` members, alongside a 360-byte
  `Blob` member (`id=1805`) -- real-world confirmation that this decoder's
  recursive `decode_value_element` genuinely handles nested structs, not
  just the flat case exercised by the synthetic fixture.
- `DeleteObject` request (`Delete Object Id=0x0000038a`, twice, with
  different object IDs) -- always followed only by a bare TCP ACK/RST in
  this capture, so no `DeleteObject` *response* PDU is present here (the
  synthetic fixture covers that side).

It also exercises two Tier-2 (named, not body-decoded) shapes on real
traffic: `Connect` (the session-establishment handshake, PDU type `0x01`,
seen twice per TCP session) and `GetVarSubStreamed` request/response (one
pair). Both are correctly recognized and labeled, with the expected
"recognized but not decoded" note and no attempt at a body decode. The file
also repeatedly exercises this decoder's above-COTP, trailer-absence-based
reassembly (not COTP's own EOT bit) on real traffic -- every
`SetMultiVariables` request here arrives split across 2 TPKT/COTP frames
(419 user-data bytes reassembled each time), confirming that path against
genuine TIA Portal fragmentation, not just the synthetic fixture's
hand-built split.

**`s7comm_plus_1511_opc_request_all_types.pcap`** lives up to its name: one
`GetMultiVariables` request/response pair (`seq=9`) asks for and receives
**40 items in a single call**, walking nearly the entire datatype table this
decoder knows -- `Bool`, `USInt`, `Byte`, `Word`, `UDInt`, `UInt`, `DInt`,
`DWord`, `Int`, `Timestamp` (renders as `1970-01-01T00:00:00.000.000.000Z`,
i.e. a zero/epoch timestamp -- these are default/uninitialized PLC values,
not a decode bug: the raw 12-byte TIMESTAMP field genuinely is all zero),
`LInt`, `LReal`, `Timespan` (`0 ns`), `ULInt`, `LWord`, `Real`, `SInt`, plus
two `USInt` arrays (`Array[8]` and `Array[256]`, the latter correctly
truncated for display per this project's established long-value truncation
convention). The same file also repeats the smaller `GetMultiVariables`
(single-item), `SetMultiVariables` (three-item, identical nested-struct
shape to the other file), and `Connect`/`GetVarSubStreamed` PDUs seen in
`db3_var1_hmi`, each pair sent twice (once per of two near-identical TCP
sessions in the capture).

**No per-item decode errors, no `ParseError`-triggered "decoding stopped"
notes, and no unrecognized-datatype fallbacks occurred anywhere in either
file** -- both real captures decode cleanly end to end with this
implementation (see the `real_s7comm_plus_*_no_item_errors` CTest cases).
Unlike the MQTT validation pass, inspecting these two real files did not
turn up any decoder bug; the bugs this implementation did have (an
array-of-struct misalignment risk and an unsigned-underflow risk) were both
caught and fixed during initial code review, before either file was ever
decoded against it -- see the commit history / development notes for that.

**What these two files do *not* exercise**, and so remain validated only
against the synthetic fixture (`tools/make_sample_pcap.py`'s
`build_s7commplus_sample()`) rather than real traffic: `KeepAlive` PDUs,
`Notification` (opcode `0x33`), `CreateObject`, `Explore`,
`GetLink`, `BeginSequence`/`EndSequence`, `Invoke`, a `DeleteObject`
*response*, array-of-struct (deliberately unsupported -- throws `ParseError`
rather than risk silent misalignment), and a `SparseArray`-encoded value.
None of these happened to appear in either real capture. (`DataFW1_5` used to
be on this list too -- see the addendum immediately below for why it no
longer is.)

## S7comm-Plus addendum: DataFW1_5, confirmed against a real S7-1212C

The capture behind this addendum (`s5comm_S71200-1212.pcapng`, not checked
into this repository -- see the note at the end of this section) was
originally collected for a different purpose entirely: confirming or fixing
the classic-S7comm `0xB2` "symbolic addressing" decode discussed above, using
a real S7-1200 (a 1212C CPU) driven by a genuine Siemens KTP 400 Basic HMI
panel, captured over a managed switch's SPAN/mirror port. It turned out this
pairing doesn't exercise `0xB2` at all: a KTP 400 Basic talking to an
S7-1200/1500 CPU through TIA Portal's own configuration uses **S7comm-Plus**,
not classic S7comm -- the very first payload byte on every telegram is `0x72`,
not `0x32`. So this capture is not real-world validation for `0xB2` (that
question is still open -- see LIMITATIONS -- and would need a client that
deliberately speaks classic S7comm symbolic addressing to an S7-1200/1500,
such as Snap7 or node-s7, rather than a TIA-Portal-ecosystem HMI).

What it turned out to validate instead was more valuable: ~197 seconds and
1,708 S7comm-Plus telegrams, of which **1,660 (97%) were `DataFW1_5`** (PDU
type `0x03`) -- the HMI panel's firmware sends almost none of its
`GetMultiVariables`/`SetMultiVariables`/`SetVariable` traffic as plain PDU
type `Data` (`0x02`). Before this capture, `DataFW1_5` was believed, per the
reference plugin's own source comments, to carry a shorter, id-only Integrity
value with no digest bytes, and was deliberately left undecoded (Tier 2) on
that basis. Reconstructing the wire bytes directly from this real traffic
(stripping TPKT/COTP headers, locating the S7comm-Plus header, then hand-
aligning on the next valid opcode byte -- `0x31`/`0x32`/`0x33`/`0x02`) showed
a consistent, different shape across every sample: DataFW1_5's own Integrity
value sits at the very *front* of the Data part rather than the end, as the
same varuint32 id followed directly by a fixed 32-byte digest -- the same
shape PDU type Data's own trailing Integrity uses, just relocated, and with
no length-prefix byte this time (unlike the trailing form, which has an
explicit `digest_len` byte, normally `32`). See `decode_integrity_fw1_5` in
`src/s7commplus.cpp` for the implementation and the same writeup in code.

This is now a Tier-1 (not experimental) decode, on real-device evidence, not
a byte-layout guess: consuming exactly `id + 32 bytes` at the front of every
DataFW1_5 Data part reliably realigned the remainder onto a valid opcode
byte and a body that decoded consistently across all 1,660 real frames --
**zero per-item decode errors and zero `ParseError`-triggered fallbacks** in
the whole capture. Two independent semantic-coherence checks back this up
beyond "it didn't crash": request/response pairs correctly correlate by
`s7plus_sequence_number` with plausible decoded values throughout, and the
HMI panel's own repeated `SetVariable` telegrams reporting its health back to
the CPU (well-known object id `0x70400002`, variable id `1053`, "Cyclic
variables number of automatic sent telegrams") show a value that climbs
monotonically in lock-step with the telegram sequence number across hundreds
of consecutive samples -- exactly the behavior a genuine live counter would
produce, not something a misaligned decode would coincidentally reproduce.

Once this relocated Integrity block is consumed, DataFW1_5's Data part has
the identical opcode-led body layout as ordinary PDU type Data, so every
Tier-1 function this decoder already knew (`GetMultiVariables`,
`SetMultiVariables`, `SetVariable`, `CreateObject`, `DeleteObject`) decodes
DataFW1_5 traffic the same way, with no separate per-function work needed.
This capture is real-world validation for all of those, plus `Notification`
(recognized, still correctly left undecoded), all riding on DataFW1_5.

This third capture is not checked into this repository the way the two
`s7comm_plus_1511_*.pcap` files above are -- unlike those, it was supplied
directly during development rather than sourced from a redistributable public
collection, so it's kept only as the private evidence behind this finding
and the synthetic fixture update (`tools/make_sample_pcap.py`'s DataFW1_5
packet now prepends a realistic leading integrity block, and
`tests/sample_s7commplus.pcap`/the `s7commplus_datafw1_5_*` CTest cases were
updated to match), not reproduced here byte-for-byte.
