#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_oversize_smoke.sh -- the CTest case (see CMakeLists.txt's
# merge_inventory_oversize_rejected_before_read) proving --max-inventory-file-bytes
# (inventory_merge.hpp's kDefaultMaxInventoryFileBytes / read_inventory_report_file_for_merge)
# actually rejects an oversized input report BEFORE it's read into memory, fixing
# docs/reviews/2026-09-chatgpt-security-review-patch282.md's finding 5 (item 122,
# docs/DEVELOPMENT.md) -- the same shape item 68 already fixed for the baseline engine's own
# --max-baseline-file-bytes, against a different, earlier review (patch209 finding 5).
#
# Generates one real 'inventory --format json' report with the CLI itself (matching this
# project's own standing rule, see inventory_merge_smoke.sh's own header, that every CTest
# assertion is written only after manually running the real binary and inspecting its actual
# output -- never a hand-authored/checked-in fixture that could silently drift from the real
# report schema), then measures that report's own real byte size so the "too small a limit"
# case below is set relative to a real, just-produced file rather than a guessed constant.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_modbus.pcap" --format json -o "$SCRATCH/report.json"
REPORT_BYTES="$(wc -c < "$SCRATCH/report.json" | tr -d '[:space:]')"
[ "$REPORT_BYTES" -gt 0 ] || fail "expected the generated report to be non-empty"

# 1. Under the default (256 MiB) ceiling, merging this ordinary, real report still succeeds --
#    the new size check must not reject anything a legitimate run would have accepted before.
"$CONDUITSCOPE" merge inventory "$SCRATCH/report.json" >/dev/null \
    || fail "expected merge inventory to still succeed under the default --max-inventory-file-bytes ceiling"

# 2. A --max-inventory-file-bytes set one byte below this report's own real size must be
#    rejected -- with a clear error naming the byte count, the limit, and the override flag --
#    and must exit non-zero, never printing any "merged:"/report output.
TOO_SMALL=$((REPORT_BYTES - 1))
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/report.json" --max-inventory-file-bytes "$TOO_SMALL" 2>&1)"; then
    fail "expected merge inventory to fail when --max-inventory-file-bytes ($TOO_SMALL) is below the report's own size ($REPORT_BYTES)"
fi
echo "$OUTPUT"
echo "$OUTPUT" | grep -q "report file '$SCRATCH/report.json': $REPORT_BYTES byte(s) exceeds the $TOO_SMALL byte limit (--max-inventory-file-bytes to override)" \
    || fail "expected a clear error naming the exact byte count/limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the size ceiling rejected the input"

echo "OK: merge inventory accepted a real report under the default ceiling and rejected it before reading once --max-inventory-file-bytes was set below its own size"
