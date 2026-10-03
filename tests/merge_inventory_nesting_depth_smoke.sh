#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_nesting_depth_smoke.sh -- the CTest case (see CMakeLists.txt's
# merge_inventory_nesting_depth_bounded) proving
# docs/reviews/2026-10-chatgpt-security-review-patch295.md's finding F3 fix (item 135,
# docs/DEVELOPMENT.md): inventory_merge.cpp's tolerant JSON parser now bounds how deeply nested a
# value it's skipping (JsonCursor::skip_value, the one recursive function in this parser) is
# allowed to be, independent of the existing 256 MiB per-file byte ceiling (item 122/F5).
#
# F3's own point, confirmed by testing against the real pre-fix binary before this fix was
# written: "256 MiB file-size limit != bounded parser recursion" -- a tiny, compact file shaped
# like {"x":{"x":{"x": ... }}} stays far under the byte ceiling no matter how many levels deep it
# goes, but skip_value() recursed once per level with no depth tracking at all. A 12 MB file (far
# under the ceiling) with 2,000,000 nesting levels crashed the whole process outright (a real
# stack overflow, confirmed SIGSEGV), not a clean rejection.
#
# DELIBERATE DEVIATION from this project's own "generate every fixture with the real CLI" rule --
# see merge_inventory_semantic_validation_smoke.sh's own header for the identical reasoning: a
# deeply-nested-JSON fixture isn't something the real CLI can ever produce (write_inventory_
# report_json never emits an unrecognized, deeply-nested field at all), so these fixtures are
# built with a short Python snippet instead, the same way the fix itself was first confirmed.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# make_nested_report DEPTH PATH -- writes a well-formed, otherwise-empty inventory report whose
# one unrecognized top-level field ("evil") is nested DEPTH levels deep -- exactly the shape
# skip_value() has to recurse through, and the only field this merge doesn't itself interpret
# (so it's guaranteed to reach skip_value() rather than any of the dedicated field parsers).
make_nested_report() {
    local depth="$1" path="$2"
    python3 -c "
depth = $depth
s = '{\"x\":' * depth + '0' + '}' * depth
with open('$path', 'w') as f:
    f.write('{\"total_packets\":0,\"skipped_packets\":0,\"assets\":[],\"edges\":[],\"evil\":')
    f.write(s)
    f.write('}')
"
}

# 1. The exact crash repro (2,000,000 levels, ~12 MB, far under the 256 MiB per-file ceiling) must
#    now fail CLEANLY -- non-zero exit, a clear error naming the nesting-depth limit -- never crash
#    (SIGSEGV would show up here as a non-zero exit too, but with no output at all; distinguish by
#    requiring the specific error text).
make_nested_report 2000000 "$SCRATCH/deep.json"
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/deep.json" 2>&1)"; then
    fail "expected merge inventory to reject a 2,000,000-level-deep input, but it succeeded: $OUTPUT"
fi
if ! echo "$OUTPUT" | grep -q "JSON nesting is deeper than the 128-level limit this parser allows"; then
    fail "expected a clear nesting-depth-limit error (not a crash/empty output), got: $OUTPUT"
fi

# 2. Exactly AT the 128-level limit must still succeed -- the ceiling must not be off-by-one
#    against legitimate (if unusual) input.
make_nested_report 128 "$SCRATCH/at_limit.json"
if ! "$CONDUITSCOPE" merge inventory "$SCRATCH/at_limit.json" >/dev/null 2>&1; then
    fail "expected merge inventory to accept a JSON value nested exactly at the 128-level limit"
fi

# 3. One level past the limit (129) must be rejected, with the same clean error as case 1.
make_nested_report 129 "$SCRATCH/over_limit.json"
if OUTPUT="$("$CONDUITSCOPE" merge inventory "$SCRATCH/over_limit.json" 2>&1)"; then
    fail "expected merge inventory to reject a 129-level-deep input (one past the limit), but it succeeded: $OUTPUT"
fi
if ! echo "$OUTPUT" | grep -q "JSON nesting is deeper than the 128-level limit this parser allows"; then
    fail "expected a clear nesting-depth-limit error for the 129-level case, got: $OUTPUT"
fi

# 4. Regression guard: a real, CLI-generated report (whose own JSON nests only a few levels at
#    most) must still merge successfully -- the new ceiling must never reject genuine data.
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_inventory.pcap" --format json -o "$SCRATCH/real.json"
"$CONDUITSCOPE" merge inventory "$SCRATCH/real.json" >/dev/null \
    || fail "expected a real, CLI-generated inventory report to still merge successfully under the new F3 nesting-depth ceiling"

echo "OK: merge inventory now bounds JSON nesting depth at 128 levels (crash repro rejected cleanly, boundary exact at 128/129, real reports unaffected)"
