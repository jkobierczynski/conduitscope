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
protocol conduitscope already detects and correctly reports as an undecoded
stub, not classic S7comm at all) or block upload/download traffic that
doesn't use Read/Write Var. So this set is good additional real-world
regression coverage for the classic S7ANY item-decode path and the
S7comm-Plus detection stub, but it does **not** touch the `0xB2` EXPERIMENTAL
decode -- see below for where real `0xB2` traffic actually came from.

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
