#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# capture_rotation_failure_smoke.sh -- the one CTest case (see CMakeLists.txt's
# capture_rotation_failure_reports_incomplete_with_real_traffic) that proves the `capture`
# subcommand's patch257 security-review finding 2 hardening end to end, against a REAL running
# `capture` process and REAL loopback traffic, rather than RotatingPcapWriter's own class-level
# exception-safety/recovery guarantees (already covered deterministically and much faster by
# tools/rotating_pcap_writer_selftest.cpp's own checks 12-14 -- see that tool's own file header for
# why a dedicated executable is the right place for exact byte-level/exception-safety proof). What's
# left to prove here is the CLI wiring itself: that a real, running, unattended `capture` process
# actually reports capture loss prominently and returns the new dedicated exit code, rather than
# silently looking like a normal Ctrl+C/--duration stop.
#
# Technique: `--rotate-bytes 1` (smaller than any real packet record, same trick
# capture_rotation_smoke.sh's own header comment explains) means every packet after the first
# attempts a rotation. RotatingPcapWriter opens its FIRST file synchronously at construction time,
# before this process has captured a single packet -- so by the time this script renames the
# scratch directory away, that first file already exists and is already open; the still-open file
# descriptor keeps working (POSIX renaming a directory doesn't affect anything already open inside
# it), but a NEW open() against the now-missing directory does not. The first real packet captured
# after the rename therefore still writes successfully (no rotation needed yet -- a freshly opened
# file always accepts at least one packet, see rotating_pcap_writer.hpp's own
# RotationPolicy::rotate_bytes comment); the second one forces a rotation attempt that genuinely
# fails, deterministically, without needing an actually-full disk or a non-root privilege level.
set -eu

CONDUITSCOPE="$1"

SCRATCH="$(mktemp -d)"
MOVED="${SCRATCH}_moved"
OUT="$(mktemp)"
trap 'rm -rf "$SCRATCH" "$MOVED" "$OUT"' EXIT

"$CONDUITSCOPE" capture --interface lo --directory "$SCRATCH" --prefix failtest \
    --rotate-bytes 1 --duration 30 >"$OUT" 2>&1 &
CAP_PID=$!

# Give conduitscope a moment to open its first file (RotatingPcapWriter's own constructor does
# this synchronously, before any packet is captured) before pulling the directory out from under it.
sleep 1
mv "$SCRATCH" "$MOVED"

# Two bare TCP connect-then-close attempts to an almost-certainly-closed local port, each producing
# a SYN and a SYN-ACK-or-RST on loopback -- same technique capture_rotation_smoke.sh already uses.
# The first captured packet still writes fine (no rotation needed for a file's first packet); the
# second forces a rotation attempt against the now-missing directory.
(exec 3<>/dev/tcp/127.0.0.1/18505) 2>/dev/null || true
exec 3>&- 2>/dev/null || true
(exec 3<>/dev/tcp/127.0.0.1/18506) 2>/dev/null || true
exec 3>&- 2>/dev/null || true


# `set -e` treats a nonzero `wait` result as script failure just like any other command -- and
# since the whole point of this script is that the capture process is EXPECTED to exit 7, not 0,
# a bare `wait` would abort the script right here, before STATUS=$? ever ran, without giving any
# of the checks below a chance to run or report anything useful. Disable -e for just this one
# call, the standard idiom for capturing an expected-nonzero exit status under `set -e`.
set +e
wait "$CAP_PID"
STATUS=$?
set -e

cat "$OUT"

if [ "$STATUS" -ne 7 ]; then
    echo "FAIL: expected exit code 7 (kExitCaptureIncomplete), got $STATUS" >&2
    exit 1
fi

if ! grep -q '\*\*\* CAPTURE INCOMPLETE' "$OUT"; then
    echo "FAIL: expected a prominent '*** CAPTURE INCOMPLETE' banner on failure" >&2
    exit 1
fi

if ! grep -q 'rotation failed' "$OUT"; then
    echo "FAIL: expected the underlying rotation failure to be named in the output" >&2
    exit 1
fi

# The first file (opened before the directory was moved away) must still be intact -- not lost, not
# corrupted -- exactly the "every already-rotated/already-open file up to this point is intact"
# claim the CAPTURE INCOMPLETE banner itself makes.
first_file=("$MOVED"/failtest_*.pcap)
if [ ! -e "${first_file[0]}" ]; then
    echo "FAIL: expected the first file (opened before the directory moved) to still exist under $MOVED" >&2
    exit 1
fi

decoded="$("$CONDUITSCOPE" decode --read "${first_file[0]}" --format text)"
if ! printf '%s\n' "$decoded" | grep -q '^#1 '; then
    echo "FAIL: the surviving first file did not decode as a valid capture with at least one packet:" >&2
    printf '%s\n' "$decoded" >&2
    exit 1
fi

echo "PASS: capture reported CAPTURE INCOMPLETE, returned exit 7, and preserved its first file intact"
