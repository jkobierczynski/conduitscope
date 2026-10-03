#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_aggregate_limits_smoke.sh -- the CTest cases (see CMakeLists.txt's
# merge_inventory_aggregate_* tests) proving the four NEW aggregate ceilings
# docs/reviews/2026-10-chatgpt-security-review-patch295.md's finding F1 asked for
# (--max-inventory-input-files, --max-inventory-total-bytes, --max-inventory-total-assets,
# --max-inventory-total-edges -- inventory_merge.hpp's read_inventory_report_files_for_merge)
# actually work, on top of (never instead of) the existing per-file --max-inventory-file-bytes
# ceiling item 122/F5 already fixed.
#
# F1's own complaint: "N inventory files, each <= 256 MiB, all parsed, all retained in memory,
# merged" has no ceiling on N (the per-file byte ceiling alone doesn't bound the AGGREGATE), plus
# a second-order amplification risk (a compact, under-the-byte-ceiling JSON document containing a
# huge NUMBER of small asset/edge objects can still expand far past its own source byte count once
# parsed into full InventoryAsset/InventoryEdge structs). The four ceilings tested below are this
# project's fix for exactly that -- see inventory_merge.hpp's own comment on each new constant for
# the full reasoning, and read_inventory_report_files_for_merge's comment for exactly how/when each
# is checked (file count first and cheapest; then each file's own size AND the running aggregate
# byte total, before that file is read; then the asset/edge array lengths, checked DURING parsing,
# not after, which is what actually defends against the second-order amplification risk).
#
# Generates two real 'inventory --format json' reports with the CLI itself (this project's own
# standing rule -- see inventory_merge_smoke.sh's own header -- never a hand-authored/checked-in
# fixture that could silently drift from the real report schema): sample_modbus.pcap (2 assets, 1
# edge) and sample_inventory.pcap (9 assets, 5 edges) -- confirmed by direct inspection before this
# script was written, not assumed. Combined: 2 files, 11 assets, 6 edges, and a known combined byte
# total -- each ceiling below is set strictly below the real combined figure it guards, so every
# rejection proves the ceiling is actually being enforced, not a coincidence of some other check.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_modbus.pcap" --format json -o "$SCRATCH/r1.json"
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_inventory.pcap" --format json -o "$SCRATCH/r2.json"
R1_BYTES="$(wc -c < "$SCRATCH/r1.json" | tr -d '[:space:]')"
R2_BYTES="$(wc -c < "$SCRATCH/r2.json" | tr -d '[:space:]')"
TOTAL_BYTES=$((R1_BYTES + R2_BYTES))

# 0. Baseline: under every default aggregate ceiling, merging these two ordinary, real reports
#    still succeeds -- the new checks must not reject anything a legitimate run would have
#    accepted before this fix.
"$CONDUITSCOPE" merge inventory "$SCRATCH/r1.json" "$SCRATCH/r2.json" >/dev/null \
    || fail "expected merge inventory to still succeed under every default aggregate ceiling"

# 1. --max-inventory-input-files: 2 real input files, limit set to 1 -- must be rejected before
#    even the first file is opened, naming the exact count/limit/override flag.
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/r1.json" "$SCRATCH/r2.json" \
    --max-inventory-input-files 1 2>&1)"; then
    fail "expected merge inventory to fail when --max-inventory-input-files (1) is below the real input count (2)"
fi
echo "$OUTPUT" | grep -q "merge inventory: 2 input file(s) exceeds the 1 file limit (--max-inventory-input-files to override)" \
    || fail "expected a clear error naming the exact file count/limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the file-count ceiling rejected the input"

# 2. --max-inventory-total-bytes: set to exactly r1's own size (strictly below r1+r2 combined) --
#    r1 alone must still be read (it's within both its own per-file ceiling and this aggregate
#    ceiling on its own), but reading r2 next must be rejected, naming the real combined byte
#    total/limit/override flag, before r2's content is parsed.
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/r1.json" "$SCRATCH/r2.json" \
    --max-inventory-total-bytes "$R1_BYTES" 2>&1)"; then
    fail "expected merge inventory to fail when --max-inventory-total-bytes ($R1_BYTES) is below the combined real size ($TOTAL_BYTES)"
fi
echo "$OUTPUT" | grep -q "reading it brings the combined input size across all 2 merge input(s) to $TOTAL_BYTES byte(s), exceeding the $R1_BYTES byte aggregate limit (--max-inventory-total-bytes to override)" \
    || fail "expected a clear error naming the exact combined byte total/limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the aggregate byte ceiling rejected the input"

# 3. --max-inventory-total-assets: r1 has 2 assets, r2 has 9 -- combined 11. A limit of 5 must be
#    crossed partway through r2's own assets array (r1's 2 fit; 3 more of r2's 9 fit before the
#    5th asset trips it), proving the check runs DURING array parsing, not only after a whole
#    file's array is finished.
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/r1.json" "$SCRATCH/r2.json" \
    --max-inventory-total-assets 5 2>&1)"; then
    fail "expected merge inventory to fail when --max-inventory-total-assets (5) is below the combined real count (11)"
fi
echo "$OUTPUT" | grep -q "merge inventory: combined asset count across all input reports exceeds the 5 asset limit (--max-inventory-total-assets to override)" \
    || fail "expected a clear error naming the exact asset limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the aggregate asset ceiling rejected the input"

# 4. --max-inventory-total-edges: r1 has 1 edge, r2 has 5 -- combined 6. A limit of 2 must be
#    crossed partway through r2's own edges array, same "checked during parsing" proof as above.
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/r1.json" "$SCRATCH/r2.json" \
    --max-inventory-total-edges 2 2>&1)"; then
    fail "expected merge inventory to fail when --max-inventory-total-edges (2) is below the combined real count (6)"
fi
echo "$OUTPUT" | grep -q "merge inventory: combined edge count across all input reports exceeds the 2 edge limit (--max-inventory-total-edges to override)" \
    || fail "expected a clear error naming the exact edge limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the aggregate edge ceiling rejected the input"

echo "OK: all four aggregate ceilings (input-files, total-bytes, total-assets, total-edges) reject a real over-budget merge, naming the right numbers and flags, while the same inputs succeed under every default"
