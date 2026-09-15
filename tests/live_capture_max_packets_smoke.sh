#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# live_capture_max_packets_smoke.sh -- the one CTest case (see CMakeLists.txt's
# live_capture_max_packets_stops_capture_early_with_real_traffic) that actually exercises live
# capture against REAL loopback traffic rather than an idle interface. Every other live-capture
# CTest deliberately relies on "lo" carrying no traffic during the run, for determinism -- which
# means none of them prove `--max-packets` actually bounds a live capture (its mechanism,
# LiveCapture::Impl::packets_seen in live_capture.cpp, is only ever exercised once a packet
# actually arrives) or that a live capture decodes something real, not just that it opens/closes
# cleanly. This script closes that gap: it starts `conduitscope decode --interface lo
# --max-packets 2 --duration 30 --format text` in the background, generates one real loopback TCP
# handshake (a SYN and a SYN-ACK -- 2 packets) via a plain bash-builtin /dev/tcp connection (no
# external tool/interpreter needed beyond a POSIX-ish shell, consistent with this block already
# being gated to UNIX only), then waits for conduitscope to exit.
#
# --max-packets is set to 2 (matching the handshake) and --duration to a generous 30s specifically
# so that if --max-packets did NOT work, this script would hang until CTest's own TIMEOUT kills it
# (a clear, unambiguous failure) rather than silently passing for the wrong reason.
set -eu

CONDUITSCOPE="$1"

OUT="$(mktemp)"
trap 'rm -f "$OUT"' EXIT

"$CONDUITSCOPE" decode --interface lo --max-packets 2 --duration 30 --format text >"$OUT" 2>&1 &
CAP_PID=$!

# Give conduitscope a moment to open the interface before generating traffic.
sleep 1

# A bare TCP connect-then-close to an almost-certainly-closed local port is enough to generate a
# SYN and a SYN-ACK-or-RST on loopback -- either way, 2 real captured packets. Failure to connect
# (e.g. something is actually listening and behaves differently) doesn't matter: what's under test
# is that *some* traffic stops the capture early, not the connection's own outcome.
(exec 3<>/dev/tcp/127.0.0.1/18502) 2>/dev/null || true
exec 3>&- 2>/dev/null || true

wait "$CAP_PID"
STATUS=$?

cat "$OUT"

if [ "$STATUS" -ne 0 ]; then
    echo "FAIL: conduitscope exited $STATUS" >&2
    exit 1
fi

if ! grep -q "capture on 'lo' stopped (2 packet(s) captured)" "$OUT"; then
    echo "FAIL: expected --max-packets to stop the capture at exactly 2 packets" >&2
    exit 1
fi

echo "OK: --max-packets stopped a live capture after real traffic, well before --duration"
