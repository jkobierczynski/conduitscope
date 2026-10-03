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
#
# NOTE on the error-message assertion below: it deliberately does NOT include the report
# file's own path in the matched pattern, even though the real error message does name it.
# On Windows CI, this script runs under Git Bash/MSYS2, which silently translates the
# POSIX-style $SCRATCH path into its Windows-native form (e.g. "/tmp/xyz/report.json" ->
# "C:/Users/RUNNER~1/AppData/Local/Temp/xyz/report.json") when passing it as an argument to
# the native conduitscope.exe -- so the exe's own error message legitimately echoes back the
# translated, Windows-native path, while this script's own $SCRATCH variable still holds the
# original, untranslated form. A grep pattern that embeds $SCRATCH therefore mismatches on
# Windows even though the production error message is completely correct. Matching only the
# platform-independent suffix (byte count / limit / override flag -- the actual substance this
# test cares about, per the comment below) avoids that false positive while still proving the
# error names the right numbers and the right flag.
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
# Deliberately not matching the report file's own path here -- see the NOTE in this script's
# header comment: Git Bash on Windows CI translates it before conduitscope.exe ever sees it.
echo "$OUTPUT" | grep -q ": $REPORT_BYTES byte(s) exceeds the $TOO_SMALL byte limit (--max-inventory-file-bytes to override)" \
    || fail "expected a clear error naming the exact byte count/limit/override flag, got: $OUTPUT"
echo "$OUTPUT" | grep -q "^merged:" && fail "expected no merged-report output once the size ceiling rejected the input"

echo "OK: merge inventory accepted a real report under the default ceiling and rejected it before reading once --max-inventory-file-bytes was set below its own size"
