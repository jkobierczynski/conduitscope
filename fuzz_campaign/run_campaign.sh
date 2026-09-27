#!/bin/bash
# Resumable fuzzing campaign driver. Each invocation runs exactly ONE pending
# pair of fuzz_* harnesses (2-wide, this sandbox has 2 cores) to completion,
# appends its result to campaign_status.log, and exits -- designed to be
# invoked repeatedly in the FOREGROUND (never backgrounded/nohup'd), because
# this sandbox suspends between turns and kills detached background jobs
# outright. Each call is bounded well under the Bash tool's 600s hard cap.
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
CAMPAIGN_DIR="$ROOT/fuzz_campaign"
CRASH_DIR="$CAMPAIGN_DIR/crashes"
STATUS_LOG="$CAMPAIGN_DIR/campaign_status.log"
RAW_LOG_DIR="$CAMPAIGN_DIR/raw_logs"
mkdir -p "$CRASH_DIR" "$RAW_LOG_DIR"

PER_HARNESS_SECS=540   # kept safely under the Bash tool's 600s per-call cap

mapfile -t ALL_HARNESSES < <(ls build-fuzz/fuzz_* 2>/dev/null | grep -v '\.' | sort)
TOTAL=${#ALL_HARNESSES[@]}

# Harnesses already completed (have a "rc=" result line in the status log).
mapfile -t DONE_NAMES < <(grep -oE '  fuzz_[a-zA-Z0-9_]+  rc=' "$STATUS_LOG" 2>/dev/null | awk '{print $1}')
declare -A DONE_SET
for n in "${DONE_NAMES[@]:-}"; do [ -n "$n" ] && DONE_SET["$n"]=1; done

PENDING=()
for h in "${ALL_HARNESSES[@]}"; do
    name="$(basename "$h")"
    [ -z "${DONE_SET[$name]:-}" ] && PENDING+=("$h")
done

if [ ${#PENDING[@]} -eq 0 ]; then
    echo "$(date -u +%FT%TZ)  === Campaign finished: all $TOTAL harnesses done ===" >> "$STATUS_LOG"
    touch "$CAMPAIGN_DIR/DONE"
    echo "ALL_DONE"
    exit 0
fi

run_one() {
    local bin="$1"
    local name; name="$(basename "$bin")"
    local proto="${name#fuzz_}"
    local corpus="$ROOT/fuzz/corpus/$proto"
    mkdir -p "$corpus"
    local raw_log="$RAW_LOG_DIR/${name}.log"
    local start_ts; start_ts=$(date +%s)
    "$bin" -max_total_time="$PER_HARNESS_SECS" -artifact_prefix="$CRASH_DIR/${name}_" \
        "$corpus" > "$raw_log" 2>&1
    local rc=$?
    local end_ts; end_ts=$(date +%s)
    local execs; execs=$(grep -oE '#[0-9]+' "$raw_log" | tail -1 | tr -d '#'); execs=${execs:-unknown}
    local crashes; crashes=$(ls "$CRASH_DIR"/${name}_* 2>/dev/null | wc -l)
    echo "$(date -u +%FT%TZ)  $name  rc=$rc  elapsed=$((end_ts-start_ts))s  last_exec_marker=$execs  crash_artifacts=$crashes" >> "$STATUS_LOG"
}

a="${PENDING[0]}"
b="${PENDING[1]:-}"
if [ -n "$b" ]; then
    run_one "$a" &
    p1=$!
    run_one "$b" &
    p2=$!
    wait "$p1" "$p2"
    just_did=2
else
    run_one "$a"
    just_did=1
fi

done_count=$(( TOTAL - ${#PENDING[@]} + just_did ))
echo "$(date -u +%FT%TZ)  progress: $done_count/$TOTAL harnesses done" >> "$STATUS_LOG"
echo "PAIR_DONE"
