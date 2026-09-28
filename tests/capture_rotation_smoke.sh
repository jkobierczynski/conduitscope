#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# capture_rotation_smoke.sh -- the one CTest case (see CMakeLists.txt's
# capture_rotation_and_retention_with_real_traffic) that exercises the `capture` subcommand's
# rotation AND retention against REAL loopback traffic, rather than synthetic packets
# (tools/rotating_pcap_writer_selftest.cpp already covers RotatingPcapWriter's own byte-exact
# rotation/retention boundaries deterministically -- see that tool's own file header for why a
# dedicated executable is the right place for that) or an idle interface (every other live-capture
# CTest deliberately relies on "lo" carrying no traffic during the run, for determinism -- see this
# project's own live_capture_duration_stops_cleanly_with_no_traffic and friends). This script
# proves the whole `capture` subcommand end to end: it actually opens "lo", actually rotates on
# real captured packets (not just a timer), actually evicts old files down to the configured
# --max-files cap, and leaves behind real, valid, decodable classic-pcap files.
#
# --rotate-bytes 1 (smaller than even one packet record) forces every file to hold exactly one
# packet -- see rotating_pcap_writer.hpp's own RotationPolicy::rotate_bytes comment on always
# writing at least one packet per file regardless of how small the configured cap is -- which turns
# --max-packets 4 into a deterministic "exactly 4 files ever opened" scenario, the same
# make-the-boundary-exact trick tools/rotating_pcap_writer_selftest.cpp's own check 3 uses.
# --max-files 2 then means exactly 2 of those 4 files should still be on disk once this exits: the
# active (4th) file plus the one closed file retention didn't get around to evicting yet.
set -eu

CONDUITSCOPE="$1"

SCRATCH="$(mktemp -d)"
OUT="$(mktemp)"
trap 'rm -rf "$SCRATCH" "$OUT"' EXIT

"$CONDUITSCOPE" capture --interface lo --directory "$SCRATCH" --prefix smoketest \
    --max-packets 4 --rotate-bytes 1 --max-files 2 --duration 30 >"$OUT" 2>&1 &
CAP_PID=$!

# Give conduitscope a moment to open the interface before generating traffic.
sleep 1

# Two bare TCP connect-then-close attempts to an almost-certainly-closed local port, each producing
# a SYN and a SYN-ACK-or-RST on loopback -- 4 real captured packets total, matching --max-packets 4
# above. Same technique tests/live_capture_max_packets_smoke.sh already uses; see its own comment.
(exec 3<>/dev/tcp/127.0.0.1/18503) 2>/dev/null || true
exec 3>&- 2>/dev/null || true
(exec 3<>/dev/tcp/127.0.0.1/18504) 2>/dev/null || true
exec 3>&- 2>/dev/null || true

wait "$CAP_PID"
STATUS=$?

cat "$OUT"

if [ "$STATUS" -ne 0 ]; then
    echo "FAIL: conduitscope exited $STATUS" >&2
    exit 1
fi

if ! grep -q "4 packet(s) captured across 4 file(s)" "$OUT"; then
    echo "FAIL: expected 4 real packets to have opened exactly 4 rotated files (--rotate-bytes 1 " \
         "forces one packet per file)" >&2
    exit 1
fi

# Exactly 2 files should remain on disk: --max-files 2 evicts everything older than that as each
# rotation happens. Glob rather than `find`/`ls -1 | wc -l` piping -- POSIX glob expansion alone is
# enough here and keeps this portable to a minimal bash without relying on external tool quirks.
remaining=("$SCRATCH"/smoketest_*.pcap)
remaining_count=${#remaining[@]}
if [ "$remaining_count" -ne 2 ]; then
    echo "FAIL: expected exactly 2 rotated files to survive --max-files 2, found $remaining_count:" >&2
    printf '  %s\n' "${remaining[@]}" >&2
    exit 1
fi

# Every surviving file must be a real, valid, decodable classic-pcap file with exactly the one
# packet --rotate-bytes 1 should have given it -- not a truncated/corrupt leftover from a rotation
# or eviction race. Summing "#1" lines across both surviving files should give exactly 2 (one per
# file); a stray "#2" in either file's own output would mean more than one packet landed in a file
# that should only ever hold one.
total_packets=0
for f in "${remaining[@]}"; do
    decoded="$("$CONDUITSCOPE" decode --read "$f" --format text)"
    packet_lines=$(printf '%s\n' "$decoded" | grep -c '^#1 ')
    if [ "$packet_lines" -ne 1 ]; then
        echo "FAIL: $f did not decode as exactly one packet:" >&2
        printf '%s\n' "$decoded" >&2
        exit 1
    fi
    if printf '%s\n' "$decoded" | grep -q '^#2 '; then
        echo "FAIL: $f unexpectedly holds more than one packet" >&2
        exit 1
    fi
    total_packets=$((total_packets + 1))
done
if [ "$total_packets" -ne 2 ]; then
    echo "FAIL: expected 2 total packets across the 2 surviving files, got $total_packets" >&2
    exit 1
fi

echo "OK: capture rotated 4 real packets into 4 files and retained exactly the 2 --max-files allows, each a valid single-packet capture"
