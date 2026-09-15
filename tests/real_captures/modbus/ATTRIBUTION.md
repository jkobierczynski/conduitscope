# Provenance of these fixtures

Real Modbus/TCP captures pulled from <https://github.com/automayt/ICS-pcap>
(commit `13b7ae335529146b40535c2d7aa756886040d8ad`, 2026-09-15), under its
`MODBUS/` directory -- see `tests/real_captures/dnp3/ATTRIBUTION.md` for the
general notes on that source project (no explicit license accompanies it;
included here as real, non-sensitive protocol test vectors, on the same
basis).

| File in this directory                | Source path in automayt/ICS-pcap |
|-----------------------------------------|-----------------------------------|
| `modbus_read_holding_registers.pcap`   | `MODBUS/Modbus/Modbus.pcap` |
| `modbus_test_data_part1.pcap`          | `MODBUS/MODBUS-TestDataPart1/MODBUS-TestDataPart1.pcap` (byte-identical to `MODBUS/digitalbond pcaps/modbus_test_data_part1/...`, kept once) |
| `modbus_test_data_part2.pcap`          | `MODBUS/MODBUS-TestDataPart2/MODBUS-TestDataPart2.pcap` (byte-identical to `MODBUS/digitalbond pcaps/modbus_test_data_part2/...`, kept once) |

Until now, Modbus/TCP decoding (fully implemented -- read 1-4, write-single
5-6, write-multiple 15-16, plus exception responses) had no real-world
regression fixture at all, only synthetic ones from
`tools/make_sample_pcap.py`. `modbus_read_holding_registers.pcap` is a clean
real Read Holding Registers request/response session. The two
`modbus_test_data_part*.pcap` files exercise real traffic using several
function codes outside current scope (Diagnostics, Report Server ID, Read
Exception Status, and a few reserved/unassigned codes), which must degrade
to a "not decoded in this groundwork release" note rather than being
misparsed -- a useful real-world check that the fallback path holds up
against traffic it wasn't built to fully decode, not just synthetic
traffic constructed to hit that path deliberately.
