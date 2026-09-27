#!/bin/bash
# Local fuzzing campaign: run all fuzz_* harnesses under build-fuzz/ with
# WORKERS continuously-busy worker slots for a total wall-clock budget of
# BUDGET_SECS, round-robin through the harness list (wrapping around and
# re-fuzzing from the top if time remains after one full pass).
#
# Run this from your repo root, with a fuzzing-enabled build already built:
#   cmake -S . -B build-fuzz -DCMAKE_BUILD_TYPE=Debug -DCONDUITSCOPE_ENABLE_FUZZING=ON
#   cmake --build build-fuzz -j"$(nproc)"
#
# Then, to survive closing the terminal:
#   nohup ./fuzz_campaign/run_local_campaign.sh > fuzz_campaign/driver.log 2>&1 &
#   disown
#
# Progress:  fuzz_campaign/status.log        (one line per harness run)
# Crashes:   fuzz_campaign/crashes/           (libFuzzer artifact files, if any)
# Raw logs:  fuzz_campaign/logs/<harness>.<ts>.log
set -u
cd "$(dirname "$0")/.."
ROOT="$(pwd)"

BUILD_DIR="build-fuzz"          # adjust if your fuzz build lives elsewhere
CORPUS_ROOT="fuzz/corpus"
CAMPAIGN_DIR="$ROOT/fuzz_campaign"
CRASH_DIR="$CAMPAIGN_DIR/crashes"
LOG_DIR="$CAMPAIGN_DIR/logs"
STATUS_LOG="$CAMPAIGN_DIR/status.log"
mkdir -p "$CRASH_DIR" "$LOG_DIR"

WORKERS=6
TOTAL_BUDGET_SECS=$((3 * 3600))   # 3 hours; edit freely
PER_RUN_SECS=300                  # each worker spends up to 5 min per harness,
                                   # then moves on to the next -- keeps any one
                                   # harness from hogging a slot for the whole
                                   # run and gives broader coverage per pass

mapfile -t HARNESSES < <(ls "$ROOT/$BUILD_DIR"/fuzz_* 2>/dev/null | grep -v '\.' | sort)
NUM=${#HARNESSES[@]}
if [ "$NUM" -eq 0 ]; then
    echo "No fuzz_* binaries found under $BUILD_DIR/ -- build with -DCONDUITSCOPE_ENABLE_FUZZING=ON first." >&2
    exit 1
fi

END_TIME=$(( $(date +%s) + TOTAL_BUDGET_SECS ))
echo "$(date -u +%FT%TZ)  campaign start: $NUM harnesses, $WORKERS workers, ${TOTAL_BUDGET_SECS}s budget" | tee -a "$STATUS_LOG"

run_one() {
    local bin="$1"
    local name; name="$(basename "$bin")"
    local proto="${name#fuzz_}"
    local corpus="$ROOT/$CORPUS_ROOT/$proto"
    mkdir -p "$corpus"

    local now; now=$(date +%s)
    local remaining=$(( END_TIME - now ))
    [ "$remaining" -le 0 ] && return 1
    local dur=$PER_RUN_SECS
    [ "$remaining" -lt "$dur" ] && dur=$remaining
    [ "$dur" -le 0 ] && return 1

    local log="$LOG_DIR/${name}.$(date +%s).log"
    "$bin" -max_total_time="$dur" -artifact_prefix="$CRASH_DIR/${name}_" "$corpus" > "$log" 2>&1
    local rc=$?
    local execs; execs=$(grep -oE '#[0-9]+' "$log" | tail -1 | tr -d '#'); execs=${execs:-unknown}
    local crashes; crashes=$(ls "$CRASH_DIR/${name}_"* 2>/dev/null | wc -l)
    echo "$(date -u +%FT%TZ)  $name  rc=$rc  ran=${dur}s  last_exec=$execs  crash_artifacts=$crashes" >> "$STATUS_LOG"
    return 0
}

worker_loop() {
    local slot="$1"
    local i="$slot"
    while [ "$(date +%s)" -lt "$END_TIME" ]; do
        run_one "${HARNESSES[$((i % NUM))]}" || break
        i=$((i + WORKERS))
    done
}

for w in $(seq 0 $((WORKERS - 1))); do
    worker_loop "$w" &
done
wait

echo "$(date -u +%FT%TZ)  campaign finished (deadline reached or all workers exited)" | tee -a "$STATUS_LOG"
echo "Crash artifacts (if any): $CRASH_DIR"
