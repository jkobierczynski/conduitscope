#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_semantic_validation_smoke.sh -- the CTest case (see CMakeLists.txt's
# merge_inventory_semantic_validation_rejects_crafted_values) proving
# docs/reviews/2026-10-chatgpt-security-review-patch295.md's finding F2 fix (item 134,
# docs/DEVELOPMENT.md): `merge inventory`'s JSON parser (inventory_merge.cpp) now validates
# several fields SEMANTICALLY, not just syntactically, before trusting their value.
#
# F2's own point: before this fix, a crafted inventory report could carry values that are
# perfectly well-formed JSON but nonsensical for the field they're in -- e.g. "packet_count": -1,
# which the old unguarded `static_cast<size_t>(c.parse_integer())` silently turned into
# 18446744073709551615 (SIZE_MAX), or "server_port": -1, silently turned into 65535 -- and merge
# inventory would happily fold that corrupted value into real security conclusions rather than
# refusing it. Confirmed exactly as described, by testing against the real pre-fix binary, before
# this fix was written.
#
# DELIBERATE DEVIATION from this project's own standing rule (see e.g. inventory_merge_smoke.sh's
# own header) that every CTest fixture is generated with the real CLI, never hand-authored: by
# definition, every value this script proves gets REJECTED is one the real CLI can never itself
# produce (a legitimate `inventory --format json` report never writes a negative packet_count, an
# out-of-range port, a malformed IP string, or last_seen before first_seen) -- there is no "run the
# CLI and capture its output" path to a crafted-adversarial fixture. Each JSON literal below is
# intentionally minimal (empty assets/edges unless the field under test needs otherwise) rather
# than a full realistic report, so each case tests exactly one field in isolation.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# assert_rejected JSON GREP_PATTERN DESCRIPTION -- writes JSON to a fresh file, merges it alone,
# and requires: a non-zero exit, an error matching GREP_PATTERN, and no "merged:" report output.
assert_rejected() {
    local json="$1" pattern="$2" description="$3"
    local f="$SCRATCH/case.json"
    printf '%s' "$json" > "$f"
    local output
    if output="$("$CONDUITSCOPE" merge inventory "$f" 2>&1)"; then
        fail "expected merge inventory to reject $description, but it succeeded: $output"
    fi
    if ! echo "$output" | grep -q -- "$pattern"; then
        fail "expected the error for $description to match '$pattern', got: $output"
    fi
    # NOTE: written as an if/fi, not `grep ... && fail ...` as a bare statement -- under this
    # script's own `set -e`, the expected/success outcome here is grep finding NO match (exit 1),
    # and a bare `A && B` statement's own exit status is A's when it short-circuits, which would
    # trip `set -e` and silently abort the whole script right after the FIRST case, even though
    # that's the correct, intended outcome. Confirmed this bug the hard way while writing this
    # script, before switching every such check in this file to the if/fi form.
    if echo "$output" | grep -q "^merged:"; then
        fail "expected no merged-report output when $description"
    fi
}

# 1. Negative asset packet_count: the finding's own headline example -- must not silently wrap to
#    SIZE_MAX.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":-1}],"edges":[]}' \
    'asset packet_count must not be negative, got -1' \
    'a negative asset packet_count'

# 2. Negative edge packet_count.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[],"edges":[{"client_ip":"10.0.0.1","server_ip":"10.0.0.2","protocol":"modbus","server_port":502,"packet_count":-3}]}' \
    'edge packet_count must not be negative, got -3' \
    'a negative edge packet_count'

# 3. Negative server_port: the finding's own second headline example -- must not silently wrap to
#    65535.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[],"edges":[{"client_ip":"10.0.0.1","server_ip":"10.0.0.2","protocol":"modbus","server_port":-1,"packet_count":2}]}' \
    'edge server_port must be a port number in \[0, 65535\], got -1' \
    'a negative server_port'

# 4. Out-of-range (too large) server_port.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[],"edges":[{"client_ip":"10.0.0.1","server_ip":"10.0.0.2","protocol":"modbus","server_port":70000,"packet_count":2}]}' \
    'edge server_port must be a port number in \[0, 65535\], got 70000' \
    'an out-of-range server_port'

# 5. Negative total_packets / skipped_packets (top-level fields).
assert_rejected \
    '{"total_packets":-5,"skipped_packets":0,"assets":[],"edges":[]}' \
    'total_packets must not be negative, got -5' \
    'a negative total_packets'
assert_rejected \
    '{"total_packets":5,"skipped_packets":-2,"assets":[],"edges":[]}' \
    'skipped_packets must not be negative, got -2' \
    'a negative skipped_packets'

# 6. Malformed IP addresses -- the "ideally validate" half of the finding's recommendation.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"not-an-ip","packet_count":2}],"edges":[]}' \
    "asset 'ip' is not a syntactically valid IPv4 address: 'not-an-ip'" \
    'a malformed asset ip'
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[],"edges":[{"client_ip":"999.999.999.999","server_ip":"10.0.0.2","protocol":"modbus","server_port":502,"packet_count":2}]}' \
    "edge 'client_ip' is not a syntactically valid IPv4 address" \
    'a malformed edge client_ip'

# 7. first_seen after last_seen -- the other "ideally validate" item, for both assets and edges.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"first_seen":100.0,"last_seen":10.0}],"edges":[]}' \
    'first_seen (100.000000) after last_seen (10.000000)' \
    'an asset with first_seen after last_seen'
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[],"edges":[{"client_ip":"10.0.0.1","server_ip":"10.0.0.2","protocol":"modbus","server_port":502,"packet_count":2,"first_seen":50.0,"last_seen":1.0}]}' \
    'first_seen (50.000000) after last_seen (1.000000)' \
    'an edge with first_seen after last_seen'

# 8. An integer literal too large to fit a C++ `long long` -- a crash found incidentally (SIGABRT,
#    uncaught std::out_of_range from std::stoll) while hardening parse_integer() for this same
#    finding, confirmed against the real pre-fix binary and fixed in the same pass. Must now fail
#    cleanly, never abort the process.
assert_rejected \
    '{"total_packets":99999999999999999999999999999999,"skipped_packets":0,"assets":[],"edges":[]}' \
    "integer literal '99999999999999999999999999999999' is out of range" \
    'an out-of-range integer literal'

# 9. Regression guard: a real, CLI-generated report must still merge successfully under every one
#    of the new checks above -- none of them should ever reject genuine data.
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_inventory.pcap" --format json -o "$SCRATCH/real.json"
"$CONDUITSCOPE" merge inventory "$SCRATCH/real.json" >/dev/null \
    || fail "expected a real, CLI-generated inventory report to still merge successfully under the new F2 semantic checks"

echo "OK: merge inventory now rejects crafted negative counts, out-of-range ports, malformed IPs, inverted first/last-seen, and an out-of-range integer literal (no crash), while a real report still merges cleanly"
