# Continuous, safe sensor mode -- design record

Status: **implemented.** Written to scope Grok review item 5
(`docs/reviews/2026-09-grok-ics-ot-improvement-areas.md`) into something buildable, after items 1-4
(zoning, asset inventory, baseline process behavior, detection that OT IR teams recognize) were
already fully closed -- see `docs/DEVELOPMENT.md`'s "External review: Grok's ten improvement areas"
section for where this sits among the ten. The `capture` subcommand
(`include/conduitscope/rotating_pcap_writer.hpp`, `src/rotating_pcap_writer.cpp`, `run_capture` in
`src/cli_main.cpp`) and the `merge inventory` subcommand
(`include/conduitscope/inventory_merge.hpp`, `src/inventory_merge.cpp`, `run_merge_inventory` in
`src/cli_main.cpp`) now exist and are covered by CTest, exactly as scoped below.

## The pitch, restated

Grok's own text for item 5:

> Offline pcap is perfect for assessments. Programs need a **SPAN/TAP collector** that:
> - runs for weeks on a rugged/air-gapped box
> - rotates captures, does not fill the disk
> - survives zero-traffic interfaces (the current poll-loop limitation)
> - handles multiple tap points and stitches a site-wide matrix
> - never transmits toward the process network
>
> Validate on real mirrored OT switches, not loopback. Windows/Npcap and Linux should be first-class;
> many engineering laptops are Windows.

This project's own prior fact-check (`docs/reviews/2026-09-grok-response.md`) flagged this item
specifically, unlike items 1-4: "confirmed as not built, and worth flagging as a bigger scope
question... the item most likely to pull conduitscope toward being a always-on sensor product
rather than an assessment/audit CLI -- worth a deliberate scope conversation with Jurgen before
committing to it, not a default 'yes.'" That flag is why this feature started with two
`AskUserQuestion` calls, not a design doc.

## Two findings from direct source reading, before any scoping conversation

Before asking Jurgen anything, the codebase itself was read to separate what Grok's own text
assumed from what's actually true today:

- **The "zero-traffic interface" poll-loop limitation Grok names is already solved.**
  `LiveCapture::next()` (`src/live_capture.cpp`) already blocks internally via a 200ms
  non-blocking-`pcap_next_ex`-plus-sleep retry loop until a packet arrives, `stop()` is called, or
  `--duration`/`--max-packets` triggers -- it does not busy-poll, and it does not need traffic to
  return control promptly. The review-response document's own earlier "no documented handling" note
  was itself stale by the time this item was picked up.
- **A reusable single-file pcap writer already exists.** `PcapWriter` (`include/conduitscope/
  pcap_writer.hpp`, used by `decode -w/--write`) already writes a real, reopenable classic-pcap
  file from a `PcapPacket` stream -- but with no rotation, retention, or disk-bound concept of its
  own: `decode -i -w FILE` writes one ever-growing file for as long as the process runs, which is
  exactly the "fills the disk over weeks" failure mode this item exists to close. `RotatingPcapWriter`
  below is a composition wrapper around this existing class, not a new pcap-writing mechanism.

## Two scoping decisions (`AskUserQuestion`)

Both architectural forks below were genuinely large -- each "yes" answer would have meant a
different codebase shape, not just more code -- so both were asked directly, with a recommended
option grounded in Jurgen's own immediately-prior instruction on the four-axis detection redesign
("keep the protocol decoding and rule execution mechanisms simple and deterministic"). Jurgen chose
the recommended option both times.

1. **Should the rotating capture-to-disk sensor also run detect/inventory/policy/baseline analysis
   continuously inside the same process, or does "continuous sensor mode" mean the capture side
   stays safe-and-bounded while analysis stays a separate offline pass over the rotated files,
   exactly like today?**

   Chosen: **capture-only rotator.** A rotation-capable writer hooks into `-i` live capture,
   rotating by size/time and evicting oldest files against a disk cap; **no engine**
   (`PolicyEngine`/`AssetInventoryEngine`/`DetectEngine`/`BaselineEngine`) runs inside it -- analysis
   stays a separate offline pass over rotated files, exactly as today, via `decode`/`policy
   validate`/`inventory`/`detect`/`baseline` run afterward against whichever rotated file(s) an
   analyst chooses.

   Rejected: continuous in-process analysis with periodic report snapshots. Every one of this
   codebase's four analysis engines has a `observe()`-many/`finish()`-once shape, built and tested
   around running exactly once per capture -- making any of them produce a periodic snapshot mid-run
   (rather than a single final report) would mean redesigning each engine's own lifecycle, a far
   larger undertaking than "add rotation to a pcap writer," and one with no clear single right answer
   (snapshot how often? cumulative or windowed? does a `DetectEngine` new-vs-known judgment reset
   each window or carry state across weeks?) that Jurgen's own "keep it simple and deterministic"
   instruction argued against opening up at all.

2. **For "multiple-simultaneous-tap-point stitching into one site-wide matrix," should each tap
   point run its own independent `conduitscope` process (own rotation, own analysis), combined
   afterward by a new merge/stitch subcommand -- or should one process open all tap interfaces at
   once with shared live state?**

   Chosen: **independent per-tap processes + merge subcommand.** Each tap point runs its own
   independent `conduitscope` process (own `capture` instance, own later analysis pass); a new
   `merge inventory` subcommand combines N of their `inventory --format json` reports into one
   site-wide asset/communications/zone/conduit matrix. No new concurrency anywhere in this codebase.

   Rejected: one process opening all tap interfaces concurrently with shared live engine state. This
   codebase has exactly one `std::thread` use anywhere today (`resource_limits_selftest.cpp`'s own
   check 4, a test proving `ResourceLimits` is thread-local-safe -- see that file's own header
   comment) and zero production code that runs more than one `LiveCapture`/engine instance per
   process. Multi-tap-in-one-process would mean new thread-safety work across every engine
   (`AssetInventoryEngine`, `PolicyEngine`, `DetectEngine`, `BaselineEngine` are none of them
   currently required to tolerate concurrent `observe()` calls from different threads), a
   substantially larger and riskier undertaking than N independent single-threaded processes plus a
   report-level merge.

This establishes the confirmed scope carried through the rest of this document: (1) a new
rotation/retention-bounded pcap-capture mechanism wired into live capture, with **no** decode/
analysis running inside it; (2) each tap point is its own independent single-interface
`conduitscope` process; (3) a new merge mechanism to stitch multiple tap points' **inventory**
reports into one site-wide matrix, built as a separate step over already-produced JSON reports.

## `RotatingPcapWriter` design

`include/conduitscope/rotating_pcap_writer.hpp`/`src/rotating_pcap_writer.cpp` -- a thin composition
wrapper around `PcapWriter` (see that class's own file header for the classic-pcap-format contract
this class inherits unchanged): every byte written to disk still goes through an ordinary
`PcapWriter` instance, one per rotated file. `RotatingPcapWriter`'s own job is purely bookkeeping --
deciding when to close the current file and open a new one, what to name each file, and which
already-closed files to delete to stay under a configured disk budget.

`RotationPolicy` is four plain byte/second counts (`rotate_bytes`, `rotate_seconds`,
`max_total_bytes`, `max_files`), each `0` meaning "this trigger/cap is off" -- the same convention
`--max-baseline-file-bytes`/`--max-packets` already established elsewhere in this CLI. The one
combination the constructor refuses (throws `ParseError`, before opening any file): a retention cap
with **no** rotation trigger configured at all -- with no rotation there is only ever one file, which
is always the active file, and the active file is **never** evicted (this is the one invariant that
actually keeps `capture` safe to run unattended: nothing this class does can ever delete the file
currently being written), so a retention cap alone could never actually bound disk use. This check is
duplicated, deliberately, in `cli_main.cpp`'s own post-parse validation (`main()`), so the CLI
reports it before this process ever opens a live interface at all -- the same "fail fast on a bad
setup" posture every other constructor-time check in this codebase already has, just checked twice
because opening `RotatingPcapWriter` itself happens only after `LiveCapture` has already been opened
successfully (it needs the live capture's own linktype).

Two design choices worth being explicit about, since each could plausibly have gone the other way:

- **Rotation-by-time is checked against each packet's own capture timestamp, not wall-clock.** This
  keeps rotation fully deterministic for `tools/rotating_pcap_writer_selftest.cpp`'s own synthetic-
  timestamp tests (no real-time sleeping needed to prove a multi-hour rotation policy actually
  rotates) and means a real `capture` run rotates on the wall-clock time the *traffic itself* was
  seen, which is the more useful forensic property ("this file covers roughly this time window").
- **File NAMING uses wall-clock time instead**, mirroring `dumpcap`'s/`tcpdump`'s own ring-buffer
  naming convention (`-w trace-%Y%m%d%H%M%S.pcap`) -- a filename is purely a label, and naming it by
  when the writer opened the file (not by the first packet's own timestamp) means the very first
  file's name is knowable immediately at construction, before any packet has arrived, which matters
  for `RotatingPcapWriter`'s own fail-fast-at-construction posture.

Retention eviction always operates oldest-first, and always exempts the file currently being
written -- `RotationPolicy::max_files` counts every file this writer has **including** the active
one (so `--max-files 1` means "delete the file that was just closed, immediately, every rotation");
`max_total_bytes` likewise never counts the active file's own size against itself when deciding
whether IT can be evicted, only against whether an older, already-closed file should be. A delete
failure (e.g. another process holding a rotated file open) is reported via an `on_warning` callback,
never thrown -- a `capture` run meant to survive unattended for weeks should keep running and report
the problem, not crash over one file it couldn't remove.

Tested by `tools/rotating_pcap_writer_selftest.cpp` (39 checks against synthetic packets -- exact
byte-boundary rotation, time-boundary rotation, out-of-order-timestamp handling, both retention
mechanisms, the "active file is never evicted even if it alone exceeds the cap" invariant, both
construction-time validation refusals, and the bad-directory fail-fast path), the same "small
standalone executable, not the CLI itself" pattern `tools/resource_limits_selftest.cpp` already
established for logic that's far easier and more exact to exercise directly against the library API
than by timing real captured traffic through the CLI.

## `capture` subcommand design

A new, dedicated subcommand (`src/cli_main.cpp`'s `run_capture`) -- deliberately **not** an
extension of `decode -i -w`, for two reasons: `decode` always fully decodes and prints every packet
to stdout, wasted CPU and output for an unattended, weeks-long sensor nobody is watching live; and
`decode -w` has no rotation of its own at all (see `PcapWriter`'s own file header) -- reusing it
would mean adding a rotation flag to a subcommand whose entire other purpose (decoding and
formatting) is irrelevant to a sensor run. `capture` skips decode entirely: it opens `LiveCapture`,
wraps a `RotatingPcapWriter` around its own detected linktype, and writes every raw packet
unmodified -- the same "raw bytes, unmodified" contract `decode -w` already has, just with rotation
underneath.

Live-interface-only: `-i/--interface` is `->required()`, and there is no `-r/--read` at all --
rotating an already-finite offline file has no "does not fill the disk over weeks" problem to solve
in the first place (`tools/rotating_pcap_writer_selftest.cpp` is where rotation logic itself is
validated offline, deterministically, against synthetic packets). Every other live-capture flag
(`--filter`, `--duration`, `--snaplen`, `--no-promiscuous`, `-c/--max-packets`) is reused verbatim
from `decode`'s own option set, for consistency. New flags: `-d/--directory` (must already exist --
this subcommand never creates it, matching `PcapWriter`'s own "just open the path" posture),
`--prefix` (defaults to `-i/--interface`'s own name, sanitized -- see below), `--rotate-bytes`/
`--rotate-seconds`/`--max-total-bytes`/`--max-files` (straight passthroughs to `RotationPolicy`).

**Filename sanitization.** `-i/--interface`'s own value is not always filename-safe: Npcap interface
names on Windows are GUID-style device paths (e.g. `\Device\NPF_{4E2E1911-...}`) containing `\`,
`{`, `}`. `cli_main.cpp`'s own `sanitize_filename_component` replaces every character outside
`[A-Za-z0-9._-]` with `_` before it's ever used as a rotated-file prefix -- `RotatingPcapWriter`
itself takes the caller's word for it (see that class's own constructor comment); the CLI layer is
what actually guarantees it.

**"Never transmits toward the process network."** Grepped directly, this session: no
`pcap_sendpacket`/`pcap_inject`/any packet-send-or-inject capability exists anywhere in this
codebase, in `capture` or otherwise -- `LiveCapture` only ever calls `pcap_next_ex` (receive),
`PcapWriter`/`RotatingPcapWriter` only ever write to a local file. This assurance was true before
this feature existed and remains true after it; `capture`'s own subcommand help text and this
document both state it plainly rather than leaving it implicit.

Tested by 6 CTest cases covering argument validation (missing `-i`, the retention-without-rotation-
trigger refusal for both `--max-total-bytes` and `--max-files`, a nonexistent `--directory`), the
`CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` stub path, an idle-loopback `--duration` smoke test, and
`tests/capture_rotation_smoke.sh` -- the one test that generates REAL loopback traffic (mirroring
`tests/live_capture_max_packets_smoke.sh`'s own technique) specifically to prove rotation AND
retention eviction both work against real captured packets, not just synthetic ones: `--rotate-bytes
1` forces exactly one packet per file, `--max-packets 4` then deterministically opens exactly 4
files, and `--max-files 2` is checked to have left exactly 2 valid, independently-decodable
single-packet files on disk once the run exits.

**Validated so far only against loopback traffic in this sandbox** (as documented for the rest of
this codebase's live-capture support -- see `docs/MANUAL.md`'s LIVE CAPTURE section), not a real
mirrored OT switch port -- Grok's own text specifically asked for that validation ("Validate on real
mirrored OT switches, not loopback"), which is outside what this sandbox can do. Windows/Npcap
support is, as with every other live-capture code path in this codebase, exercised only by the
argument-parsing tests and the `CONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` stub path -- see
`docs/MANUAL.md`'s own "Windows path... validated only by the argument-parsing and bad-interface-name
tests" caveat, which applies here identically and is not a new gap this feature introduces.

## `merge inventory` design

A new group subcommand (`merge`) with one sub-subcommand so far (`inventory`), mirroring `baseline`'s
own group-plus-sub-subcommand shape. `include/conduitscope/inventory_merge.hpp`'s own file header has
the complete field-by-field merge semantics and every deliberately-out-of-scope simplification; the
short version:

- **Scoped to inventory reports only.** A site's `policy validate`/`detect`/`baseline` reports are
  each a structurally different merge problem -- a policy report is pass/fail against a shared,
  already site-wide policy file, not a per-tap discovery; a detect/baseline report's "new vs. known"
  judgment doesn't obviously compose across taps that each saw only part of a conversation. Each is a
  reasonable, structurally similar follow-up, deliberately not attempted in this same pass.
- **Assets are unioned by IP, edges by (client_ip, server_ip, protocol, server_port).** Packet counts
  sum; first/last-seen take the min/max across every input that observed that asset/edge;
  `direction_source` keeps the most authoritative value across inputs (Handshake beats Content beats
  PortHeuristic), a genuine recomputation, not just "first input wins" -- a later tap's own more-
  authoritative observation of the same edge should win regardless of input order.
- **Zones and conduits are always freshly re-derived** from the merged asset/edge set, using
  whatever `--zone-prefix` the merge itself is given (independent of whatever prefix each individual
  input report used) -- never merged from the inputs' own `zones`/`conduits` JSON arrays, which are
  ignored entirely. This reuses `AssetInventoryEngine::finish`'s own exact grouping logic,
  reimplemented against already-parsed data rather than shared, since `merge_inventory_reports`
  operates on parsed JSON, not a live engine instance.
- **`InventoryEdge::top_touched_addresses` is never merged** -- a per-edge top-N by touch count;
  merging two already-truncated top-N lists into a correct combined top-N would need each input's
  own FULL per-address touch-count map, which the JSON report never carries (only the top N plus a
  total-distinct count). A merged edge's own `top_touched_addresses` is always empty; read each
  input's own report directly for that detail.
- **`InventoryAsset::inferred_role` is kept, not recomputed globally** -- the first non-"Unknown"
  value across inputs wins for a given IP. Recomputing the same heuristic globally, across every
  tap's combined edges, is a reasonable follow-up, not attempted here.
- **`notable_protocols` (ROADMAP item 18) is never merged** -- always empty in a merged report; each
  input's own report still has its own list.

The parser (`inventory_merge.cpp`'s own `JsonCursor`) is deliberately TOLERANT of fields it doesn't
recognize -- unlike `baseline.cpp`'s own JSON reader (which rejects anything outside its one
self-authored schema, since a baseline file has exactly one writer), an inventory report can
legitimately carry extra, purely resolver-derived fields (`hostname`/`mac_vendor`/
`server_port_service`/etc., present only when the report that produced it was run with `--resolve`/
`--mac-vendor`/`--services`) that this merge has no use for and must simply skip over, not reject.

Tested by 4 argument/error-path CTest cases (missing input, a nonexistent report file, a genuinely
malformed-JSON input, the `merge` group's own "needs a subcommand" fallback) plus
`tests/inventory_merge_smoke.sh`, which -- per this project's standing rule that every CTest
assertion is written only after manually running the real CLI binary, never hand-authored -- GENERATES
its own two input reports with the CLI itself (`inventory --format json` against
`tests/sample_inventory.pcap` and `tests/sample_modbus.pcap`, which deliberately share one asset IP,
192.168.1.10) rather than checking in a hand-authored or pre-generated JSON fixture, so the test stays
correct even if the inventory JSON schema evolves elsewhere. It confirms the union is real (9 assets
merged, not 11 -- the shared IP is not double-counted) and that packet counts on the shared edge are
genuinely summed (2 + 3 = 5), not just deduplicated.

## Explicitly out of scope (this pass)

- In-process continuous analysis (see scoping decision 1 above).
- Concurrent multi-interface capture in one process (see scoping decision 2 above).
- Merging `policy validate`/`detect`/`baseline` reports across tap points (see `merge inventory`
  design above) -- `merge`'s own group-subcommand shape leaves room for `merge policy`/`merge
  detect`/`merge baseline` later without a breaking CLI change.
- `InventoryEdge::top_touched_addresses` merging, and globally recomputed `inferred_role` (see
  `merge inventory` design above).
- Validation against a real mirrored OT switch port (see `capture` subcommand design above) --
  outside what this sandbox can do; flagged to Jurgen rather than silently assumed equivalent to
  loopback validation.
- pcapng output from `capture`/rotation -- `RotatingPcapWriter` writes classic pcap only, the same
  scope boundary `PcapWriter` itself already has (see that class's own file header).
