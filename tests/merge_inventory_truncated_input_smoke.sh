#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_truncated_input_smoke.sh -- the CTest case (see CMakeLists.txt's
# merge_inventory_truncated_input_does_not_crash_and_unions_categories) for a crash bug found
# while verifying docs/reviews/2026-09-chatgpt-security-review-patch282.md's finding 6 (item 123,
# docs/DEVELOPMENT.md).
#
# ROOT CAUSE: AssetInventoryEngine's own assets_/edges_ containers are capped INDEPENDENTLY (two
# separate growth ceilings -- see AssetInventoryEngineLimits' own comment, asset_inventory.hpp),
# so a TRUNCATED AssetInventoryReport's own edges array can legitimately name a client_ip/
# server_ip that never made it into that SAME report's own (also-truncated) assets array.
# merge_inventory_reports' own zone/conduit-rederivation step (inventory_merge.cpp) used to look
# up each edge's endpoint zone with unordered_map::at (rather than find()-and-skip, the pattern
# AssetInventoryEngine::finish's own original version of this exact grouping, asset_inventory.cpp,
# already uses) -- so ANY truncated report fed through `merge inventory`, even a single one (merge's
# own one-input "just re-derive zones" legal use -- see merge_inventory_cmd's own --help text),
# threw std::out_of_range and crashed the whole process (SIGABRT), not just the merge's own JSON/
# text output.
#
# This matters because `merge` is explicitly described (inventory_merge.hpp's own file header,
# docs/reviews/2026-09-chatgpt-security-review-patch282.md's finding 5 -- see item 122) as an
# analysis boundary where an operator may feed in reports from other systems/tap points/teams, not
# only ones they just generated themselves -- so a crash reachable by an entirely ordinary action
# (run `inventory` with a tight --max-inventory-* limit, then `merge` the result) is a real,
# unauthenticated DoS on that boundary, not a contrived edge case.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# Report 1: assets_ truncated (--max-inventory-assets), categorized resource_limit. `inventory`
# itself exits kExitObservationIncomplete (6) whenever observation_truncated is set -- expected
# and intentional here (that's the whole point of this fixture), so `|| true` under this script's
# own `set -e` rather than letting it abort the script.
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_inventory.pcap" --max-inventory-assets 2 --format json \
    -o "$SCRATCH/resource_limit_truncated.json" || true

# 1. A SINGLE truncated report, merged alone (legal -- re-deriving zones at a possibly different
#    --zone-prefix than it was generated with), must not crash.
if ! MERGED_SINGLE="$("$CONDUITSCOPE" merge inventory "$SCRATCH/resource_limit_truncated.json" --format json 2>&1)"; then
    fail "merge inventory crashed (or exited non-zero) merging a single truncated report -- got: $MERGED_SINGLE"
fi
echo "$MERGED_SINGLE" | grep -q '"observation_reasons": \["resource_limit"\]' \
    || fail "expected the single-input merge to carry forward observation_reasons [\"resource_limit\"], got: $MERGED_SINGLE"

# Report 2: a DIFFERENT truncation category -- flow_state_eviction, from the dedicated resource-
# exhaustion fixture (build_resource_exhaustion_flow_state_sample, tools/make_sample_pcap.py)
# already used by the detect_flow_state_eviction_* tests above.
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_resource_exhaustion_flow_state.pcap" --max-flow-state-entries 1 \
    --format json -o "$SCRATCH/flow_state_eviction_truncated.json" || true

# 2. Merging the two DIFFERENTLY-truncated reports together must not crash either, and must union
#    both distinct categories (not just re-report one of them) -- the actual patch282 finding 6
#    behavior this script was written to verify in the first place.
if ! MERGED_BOTH="$("$CONDUITSCOPE" merge inventory "$SCRATCH/resource_limit_truncated.json" \
    "$SCRATCH/flow_state_eviction_truncated.json" --format json 2>&1)"; then
    fail "merge inventory crashed (or exited non-zero) merging two differently-truncated reports -- got: $MERGED_BOTH"
fi
echo "$MERGED_BOTH" | grep -q '"observation_reasons": \["resource_limit", "flow_state_eviction"\]' \
    || fail "expected the merged report to union BOTH categories (in first-seen-across-inputs order), got: $MERGED_BOTH"

echo "OK: merge inventory no longer crashes on a truncated input, and unions distinct observation_incomplete categories across inputs"
