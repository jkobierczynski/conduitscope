#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# merge_inventory_json_strictness_smoke.sh -- the CTest case (see CMakeLists.txt's
# merge_inventory_json_strictness_enforced) proving
# docs/reviews/2026-10-chatgpt-security-review-patch295.md's finding F5 fix (item 137,
# docs/DEVELOPMENT.md): inventory_merge.cpp's tolerant JSON parser (JsonCursor::parse_string) is
# now strict about two things RFC 8259 itself requires, instead of silently accepting the
# malformed shape or corrupting the value:
#
#   1. An unescaped control character (U+0000-U+001F) appearing literally inside a JSON string
#      is now rejected -- it must be escaped (\n, \t, \u0000, ...) instead. Before this fix, the
#      byte was silently copied into the resulting string verbatim.
#   2. A \uXXXX escape is now properly UTF-16-decoded (including surrogate pairs for codepoints
#      above the Basic Multilingual Plane) and UTF-8-encoded, instead of being truncated to
#      `static_cast<char>(code & 0xFF)` -- which produced a single raw byte that usually wasn't
#      even valid UTF-8 on its own. A lone/unpaired surrogate (a high surrogate not immediately
#      followed by a low one, or a low surrogate with no preceding high one) is rejected rather
#      than silently producing a nonsense byte for it.
#
# F5's own framing: this is a data-integrity/canonicalization concern, not a memory-safety one --
# these inventory fields (vendor/product/serial/security_posture/plant_identification/...)
# eventually become asset-identity data a human or downstream tool trusts, so a value that's
# technically malformed JSON silently becoming an accepted internal string is the actual risk.
#
# DELIBERATE DEVIATION from this project's own "generate every fixture with the real CLI" rule --
# the same reasoning as merge_inventory_semantic_validation_smoke.sh/merge_inventory_nesting_
# depth_smoke.sh's own headers: none of the malformed cases below (an unescaped control byte, an
# unpaired surrogate) are something `inventory --format json` can ever itself produce, so there's
# no "run the CLI and capture its output" path to these fixtures. Built with printf instead,
# keeping each case a minimal, single-field JSON literal.
set -eu

CONDUITSCOPE="$1"
SAMPLES_DIR="$2"

SCRATCH="$(mktemp -d)"
trap 'rm -rf "$SCRATCH"' EXIT

fail() {
    echo "FAIL: $1" >&2
    exit 1
}

# assert_rejected JSON GREP_PATTERN DESCRIPTION -- writes JSON to a fresh file (raw bytes, via
# printf so a literal control character in JSON survives untouched), merges it alone, and
# requires: a non-zero exit, an error matching GREP_PATTERN, and no "merged:" report output.
# Same shape (and the same `if`/`fi` form, for the same `set -e` reason) as
# merge_inventory_semantic_validation_smoke.sh's own assert_rejected helper.
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
    if echo "$output" | grep -q "^merged:"; then
        fail "expected no merged-report output when $description"
    fi
}

# assert_accepted JSON GREP_PATTERN DESCRIPTION -- writes JSON to a fresh file, merges it alone in
# --format json, and requires: a zero exit and the decoded output containing GREP_PATTERN (the
# correctly-decoded value this case is proving).
assert_accepted() {
    local json="$1" pattern="$2" description="$3"
    local f="$SCRATCH/case.json"
    printf '%s' "$json" > "$f"
    local output
    if ! output="$("$CONDUITSCOPE" merge inventory --format json "$f" 2>&1)"; then
        fail "expected merge inventory to accept $description, but it failed: $output"
    fi
    if ! echo "$output" | grep -q -- "$pattern"; then
        fail "expected the decoded output for $description to contain '$pattern', got: $output"
    fi
}

# 1. An unescaped literal 0x01 byte inside a string -- must be rejected, not silently copied in.
#    (printf's own %b-less %s leaves a raw \x01 byte in the file untouched; the JSON text around
#    it is otherwise well-formed.)
assert_rejected \
    "$(printf '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"bad\x01value"}],"edges":[]}')" \
    'unescaped control character 0x01 in string literal' \
    'an unescaped control character in a string'

# 2. A different control byte (0x1F, the top of the forbidden range) -- confirms the check is a
#    range, not a single hardcoded byte.
assert_rejected \
    "$(printf '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"bad\x1fvalue"}],"edges":[]}')" \
    'unescaped control character 0x1F in string literal' \
    'a different unescaped control character (0x1F) in a string'

# 3. A   (space, just OUTSIDE the forbidden control-character range) still works fine, and so
#    does an ordinary printable \u escape (é, 'e'-acute) -- now correctly UTF-8 encoded as its
#    real 2-byte sequence (0xC3 0xA9, "\xc3\xa9" below) instead of the old single truncated byte
#    0xE9. A regression guard against being too strict, and the headline "F5 fix" case itself.
assert_accepted \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"café corp"}],"edges":[]}' \
    "$(printf 'caf\xc3\xa9 corp')" \
    'a é escape correctly UTF-8 encoded'

# 4. A UTF-16 surrogate pair (😀, U+1F600 "grinning face") -- above the Basic
#    Multilingual Plane, so it only has a valid UTF-8 encoding once the pair is combined into one
#    codepoint; the old truncating code could never have produced this correctly at all. Expected
#    bytes: 0xF0 0x9F 0x98 0x80.
assert_accepted \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"grin 😀 corp"}],"edges":[]}' \
    "$(printf 'grin \xf0\x9f\x98\x80 corp')" \
    'a UTF-16 surrogate pair correctly combined and UTF-8 encoded'

# 5. A lone high surrogate (\ud83d) not followed by a low surrogate -- rejected, not silently
#    turned into a nonsense byte.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"bad \ud83d end"}],"edges":[]}' \
    'unpaired UTF-16 high surrogate' \
    'an unpaired UTF-16 high surrogate'

# 6. A lone low surrogate (\ude00) with no preceding high surrogate -- also rejected.
assert_rejected \
    '{"total_packets":5,"skipped_packets":0,"assets":[{"ip":"10.0.0.1","packet_count":2,"vendor":"bad \ude00 end"}],"edges":[]}' \
    'unpaired UTF-16 low surrogate' \
    'an unpaired UTF-16 low surrogate'

# 7. Regression guard: a real, CLI-generated inventory report (no exotic escapes, no control
#    bytes -- every string in it is whatever the decoder/resolver itself produced) still merges
#    successfully, proving neither check is too strict against ordinary, legitimate input.
REGRESSION_REPORT="$SCRATCH/regression_report.json"
"$CONDUITSCOPE" inventory --read "$SAMPLES_DIR/sample_modbus.pcap" --format json > "$REGRESSION_REPORT"
REGRESSION_OUTPUT="$("$CONDUITSCOPE" merge inventory "$REGRESSION_REPORT" 2>&1)" ||
    fail "expected a real, CLI-generated inventory report to still merge successfully, got: $REGRESSION_OUTPUT"
echo "$REGRESSION_OUTPUT" | grep -q "merged:" ||
    fail "expected merged-report output for a real, CLI-generated inventory report, got: $REGRESSION_OUTPUT"

echo "OK: merge_inventory_json_strictness_smoke.sh"
