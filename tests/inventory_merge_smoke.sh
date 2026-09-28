#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# inventory_merge_smoke.sh -- the CTest case (see CMakeLists.txt's
# inventory_merge_combines_two_reports_into_one_site_wide_matrix) that exercises `merge inventory`
# end to end against two REAL `inventory --format json` reports, rather than a hand-authored JSON
# fixture: this project's own standing rule is that every CTest assertion is written only after
# manually running the real CLI binary and inspecting its actual output, never hand-authored (see
# docs/DEVELOPMENT.md) -- generating the two input reports with the CLI itself, here, keeps that
# rule true for `merge` too, and keeps this test immune to the inventory JSON schema evolving
# elsewhere (a hand-authored/checked-in fixture would silently rot the moment a field's name or
# shape changed).
#
# tests/sample_inventory.pcap (9 assets: 10.0.5.21/.22, 192.168.1.10/.11/.12/.14/.15/.16/.50 -- see
# CMakeLists.txt's own inventory_* tests for the full per-asset/edge breakdown already verified
# against this fixture) and tests/sample_modbus.pcap (192.168.1.10 client-facing HMI at .50, the
# SAME .10 server IP sample_inventory.pcap's own Modbus edge already uses -- see build_modbus_
# sample/tools/make_sample_pcap.py) are used specifically because they overlap on IP 192.168.1.10:
# this exercises the actual "union by IP" merge path (inventory_merge.hpp's own
# merge_inventory_reports), not just two disjoint asset sets sitting side by side.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_inventory.pcap" --format json -o "$SCRATCH/site1.json"
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_modbus.pcap" --format json -o "$SCRATCH/site2.json"

MERGED_TEXT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/site1.json" "$SCRATCH/site2.json")"
echo "$MERGED_TEXT"

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# sample_inventory.pcap alone has 9 assets; sample_modbus.pcap alone has 2 (192.168.1.10 and
# 192.168.1.50), but .10 is already one of the 9 -- so the union is 9 assets, not 11. This is the
# single most direct proof the merge actually unions by IP rather than just concatenating.
echo "$MERGED_TEXT" | grep -q "^ASSETS (9):" || fail "expected the merged report to union 192.168.1.10 across both inputs, not double-count it (9 assets total, not 11)"

# sample_inventory.pcap's own Modbus edge (192.168.1.50 -> 192.168.1.10:502) carries 2 packets;
# sample_modbus.pcap's identical edge (same client/server/protocol/port) carries 3 (see
# build_modbus_sample) -- the merged edge's packet_count must be their SUM (5), proving edges are
# unioned by key and summed, not just deduplicated or left as two separate rows.
echo "$MERGED_TEXT" | grep -q "192.168.1.50 -> 192.168.1.10:502 (modbus)  modbus  \[Read Holding Registers\]  (5 packet(s)" \
    || fail "expected the merged Modbus edge's packet_count to be the SUM of both inputs' own counts (2 + 3 = 5)"

# Zones/conduits are freshly re-derived from the merged assets/edges, not copied from either input
# -- both zones this pair of fixtures should produce must still be present.
echo "$MERGED_TEXT" | grep -q "zone_10_0_5_0_24 (10.0.5.0/24)" || fail "expected the 10.0.5.0/24 zone to survive re-derivation"
echo "$MERGED_TEXT" | grep -q "zone_192_168_1_0_24 (192.168.1.0/24)" || fail "expected the 192.168.1.0/24 zone to survive re-derivation"

echo "OK: merge inventory unioned overlapping assets/edges across 2 real reports and re-derived zones/conduits correctly"
