# ICS communication-baseline analysis at the protocol-operation level -- design draft

Status: **Phase 1 (S7comm + Modbus) implemented, v0.2.5.** Written at Jurgen's request to scope
roadmap item 41 (`docs/DEVELOPMENT.md`) into something buildable, starting with S7comm and
Modbus. `BaselineEngine` (`include/conduitscope/baseline.hpp`, `src/baseline.cpp`) and the
`baseline learn`/`baseline check` subcommand pair now exist and are covered by CTest, exactly as
scoped below -- see "Phased build plan" at the bottom for what remains for later phases (zone-
level rollup, statistical thresholds, and protocols beyond S7comm/Modbus are all still out of
scope, unchanged from the original draft).

## The pitch, restated

Today `inventory` and `policy validate` both stop at (client, server, protocol, port): they can
say a PLC talks Modbus/TCP to three hosts, or that a conduit is compliant because it only ever
saw an allowed protocol on an allowed port. Neither says anything about *what those hosts are
actually doing to the PLC* -- which function codes, which registers, which memory ranges. An OT
security engineer doesn't get much from "TCP/502 detected." They get a lot from "this PLC has
only ever received FC03 (Read Holding Registers) from these three engineering-workstation IPs;
FC16 (Write Multiple Registers) has never once been observed on this conduit; this capture just
saw one." That's the differentiator: baselining at the *operation* level, not the flow level, and
flagging deviation from it.

## What already exists, and why it isn't this

- `AssetInventoryEngine` (`asset_inventory.hpp`) infers a zone/conduit model from a single
  capture: one `InventoryEdge` per (client IP, server IP, protocol, server port) tuple, with a
  list of distinct function/service names observed on it (`InventoryEdge::observed_functions`).
  That's already function-code-level, but it's a **set of names seen**, not a baseline with a
  notion of "expected" vs. "new" -- and it's single-capture: run it again on a different pcap and
  you get an unrelated report, nothing carried forward.
- `PolicyEngine` (`policy_engine.hpp`) checks flows against a hand-written policy, and a
  conduit's `functions:` allow-list is the closest thing to an operation-level check today --
  but it's a list a human wrote, evaluated per-packet against a fixed policy file, not a baseline
  the tool builds from observed traffic and updates over time.
- Neither engine has any notion of a *target* within an operation -- a register address, a DB
  number, a memory range. `InventoryEdge::observed_functions` is "Read Holding Registers was seen
  on this conduit," never "...at addresses 40001-40010."
- Neither engine persists anything. Every subcommand in this codebase today is a single-pass,
  stateless pipeline: read a pcap, produce a report, exit. A baseline that's worth anything has to
  survive between runs -- that's new plumbing this project doesn't have yet.

So this is a new engine, not an extension of either -- though it deliberately reuses their
conduit-identity concept (client IP, server IP, protocol, server port) rather than inventing a
fourth one.

## Per-protocol data readiness (checked directly against the code, not assumed)

This determines what Phase 1 can actually promise for each of the two protocols in scope.

**S7comm -- ready today, no new decode work needed.** `S7Item` (`s7comm.hpp`) already carries
`area`/`area_name`, `db_number`, `byte_address`/`bit_offset`/`bit_address`, `transport_size`, and
`count` as real struct fields for every item in a Read Var/Write Var job, for both classic S7ANY
addressing and the experimental S7-1200/1500 symbolic form. `S7CommFrame::function_code` /
`rosctr` give the operation. Everything a baseline needs is already structured data -- this is
exactly the MB/MW/DB example Jurgen gave, and it's a data-extraction exercise against existing
fields, not new parsing.

**Modbus -- the operation (function code) is ready; the target (address/quantity) is not.**
`ModbusFrame::function_code`/`function_name` are real fields. But the address and quantity for
every function that has them (Read Holding Registers, Write Single Register, Write Multiple
Registers, ...) are parsed locally inside `modbus.cpp`'s per-function-code branches and rendered
straight into the free-text `summary` string (`"request: read 10 holding registers starting at
address 40001"`) -- they never reach `ModbusFrame` as their own fields. A baseline engine can't
reliably regex a human-readable summary string for its numbers (the wording differs by function,
and it's explicitly documented as prose, not a data contract). **Prerequisite work, not yet
started:** add `std::optional<uint16_t> start_address` and `std::optional<uint16_t> quantity` (or
a small `ModbusAddressRange` struct, mirroring `S7Item`'s shape) to `ModbusFrame`, populated by
the same branches that already compute these values for `summary` today. This is a small,
self-contained change to `modbus.hpp`/`modbus.cpp` and a natural first step of Phase 1 before the
baseline engine itself can consume Modbus target ranges -- function-code-only baselining for
Modbus could ship without it, target-range baselining can't.

(For context, since the earlier research this design builds on already checked: MELSEC's
`device_code`, FINS's `FinsMemoryItem`, EtherNet/IP's `CipPath`, DNP3's `Dnp3ObjectHeader`/
`Dnp3PointValue`, BACnet's ReadProperty/WriteProperty decode, and OPC UA's Tier-1 Read/Write/Call
are all already structured the way S7 is -- each would need the same "extract the existing
fields into an Operation" work S7 does, not new decode work, whenever they're taken up. CODESYS's
`CmpIecVarAccess` is the one confirmed real gap -- its live-variable read/write is structural-only
today, named but not value-decoded, so it can't feed a register-level baseline until that's built.
None of that is in scope for this design; it's recorded here only so the "which architectures
could follow S7/Modbus, and in what order" question has a real answer when it comes up.)

## Core data model

```
struct Operation {
    std::string protocol;           // "s7comm" | "modbus" (Phase 1)
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string operation_key;      // S7: "<rosctr>/<function_name>/<area_name>[/DB<n>]"
                                     // Modbus: "<function_name>"
    bool has_target_range = false;  // false for Modbus until the prerequisite lands, and for
                                     // any S7 job with no item list (e.g. a plain PLC-stop request)
    uint32_t range_start = 0, range_end = 0;   // half-open [start, end); S7: byte_address units
                                                // within area+DB; Modbus: register/coil address
                                                // units within the function's own address space
};
```

`operation_key` is deliberately a per-protocol *string*, not a shared enum -- item 41's own open
question ("what counts as 'the operation' is inherently per-protocol") doesn't get resolved by
picking one shared schema; it gets sidestepped by keeping the key opaque to the engine and letting
each protocol's own extraction function decide what distinguishes one operation from another. The
engine only ever compares keys for equality and groups by them; it never interprets them. Adding a
third protocol later means writing one `extract_operations(const DecodedPacket&) ->
std::vector<Operation>` function for it, not touching the engine.

Conduit identity reuses exactly `AssetInventoryEngine`/`PolicyEngine`'s own tuple: (client_ip,
server_ip, protocol, server_port). No zone-level rollup in Phase 1 -- see "Explicitly out of
scope" below.

## Baseline state and persistence

```
struct ConduitBaseline {
    std::string client_ip, server_ip, protocol;
    uint16_t server_port = 0;
    size_t packet_count = 0;
    std::string first_seen_capture, last_seen_capture;  // filenames, for a human reading the file
    // one entry per distinct operation_key ever observed on this conduit
    struct OperationBaseline {
        std::string operation_key;
        size_t packet_count = 0;
        bool has_target_range = false;
        // sorted, non-overlapping, coalesced [start,end) intervals -- every range() ever
        // observed for this operation on this conduit, merged. A handful of intervals per
        // operation in practice (real PLC programs read/write a small, stable set of ranges),
        // so a plain sorted vector with linear merge-on-insert is enough; no interval tree.
        std::vector<std::pair<uint32_t,uint32_t>> observed_ranges;
    };
    std::vector<OperationBaseline> operations;
};

struct BaselineStore {
    int schema_version = 1;
    std::vector<ConduitBaseline> conduits;
};
```

Serialized as JSON to a file path the caller names (`--baseline-file`, no default location --
this project doesn't write anywhere the user didn't ask it to). `baseline learn` reads the file if
it exists, unions in everything newly observed (new conduit -> appended; existing conduit -> its
counters/ranges extended, never reset), and writes it back. This is how "baseline built from
multiple captures over time" is satisfied without inventing a database: the file *is* the state,
plain text, diffable, reviewable, exactly this project's existing conventions for the policy YAML
and every other artifact it produces.

## CLI shape

Two subcommands under a new `baseline` group, mirroring `policy`'s own `validate` sub-subcommand
shape:

- `conduitscope baseline learn --baseline-file <path> <pcap...>` -- always absorbs, never flags
  anything as anomalous. Running it against N captures over N days is how a real baseline gets
  built. Exit code reflects only parse/IO errors, never "this looked unusual" -- that's not
  `learn`'s job.
- `conduitscope baseline check --baseline-file <path> --format text|json <pcap>` -- read-only
  against the baseline file (never writes it), reports every operation in this capture that the
  baseline doesn't already cover. Exit code non-zero on any anomaly (mirrors `policy validate`'s
  own compliant()-driven exit code), for CI/cron use.

Splitting `learn`/`check` into two explicit, separate commands -- rather than one command with an
auto-detected "still training" mode -- is a deliberate choice: it means there is never a moment
where the tool has to guess whether the operator wants this capture absorbed into trust or judged
against it, which is exactly the kind of silent heuristic this project avoids elsewhere (see e.g.
Modbus's own request/response heuristic, always explicitly called out rather than presented as
certain). The operator always says which one they mean.

## Anomaly model

```
enum class BaselineVerdict { KnownOperation, NewConduit, NewOperation, NewTargetRange };

struct BaselineFinding {
    BaselineVerdict verdict;
    std::string client_ip, server_ip, protocol;
    uint16_t server_port = 0;
    std::string operation_key;
    // set only for NewTargetRange: the specific range this capture exercised, and (for context in
    // the report) the nearest ranges the baseline already had for this same operation_key
    uint32_t observed_start = 0, observed_end = 0;
    std::vector<std::pair<uint32_t,uint32_t>> baseline_ranges;
    size_t packet_count = 0;  // how many packets in THIS capture hit this finding
};
```

`NewConduit` subsumes "a new client talked to this server" -- since conduit identity already
includes `client_ip`, a previously-unseen client naturally produces a `NewConduit` finding rather
than needing its own verdict. `NewOperation` fires when the conduit is known but this
`operation_key` never was (the FC03-baseline/FC16-never-seen example). `NewTargetRange` only fires
when `has_target_range` is true and the observed `[start,end)` isn't fully contained in the union
of the baseline's own `observed_ranges` for that operation -- e.g. MW100 read on a conduit whose
baseline only ever saw MW0-MW50. `check`'s text/JSON report lists findings grouped by conduit,
same shape as `write_policy_report_text`/`_json`, with a summary count per verdict.

## Explicitly out of scope for Phase 1

- **Zone-level baselines.** Everything above is per-IP-pair. Rolling this up to "this baseline
  applies to any host in the Engineering zone" would reuse `Policy::zone_for` the same way
  `PolicyEngine` does, but that's a real design question of its own (does a new IP in an already-
  trusted zone count as `NewConduit` or not?) and doesn't need to be answered before S7/Modbus at
  IP granularity ships.
- **Statistical/confidence thresholds.** No "flag only if this deviates from a 30-day rolling
  average," no minimum-sample-size gate before `check` starts flagging. Phase 1's model is exact
  set/interval membership: seen before (in the baseline file) or not. This is deliberately the
  simplest thing that could be useful, and matches this project's existing "heuristic, honestly
  labeled, no invented confidence score" posture elsewhere (e.g. the Modbus request/response
  disambiguation, the BACnet direction-source ranking).
- **Baseline poisoning is a real, named risk, not a solved problem.** `learn` absorbs whatever a
  capture contains, with no judgment. Learning from a capture that already contains a malicious
  write baselines the attack as normal. This design doesn't attempt to solve that (no anomaly
  detection *during* learn, no "does this look suspicious even for a first sighting" heuristic) --
  it's a documented operational caveat for whoever runs this: `learn` only from captures already
  trusted to be clean, the same way any baselining tool in this space has to be seeded carefully.
  Worth a prominent callout in the eventual `--help` text and docs, not just here.
- **Protocols beyond S7comm and Modbus.** Per Jurgen's own scoping ("starting including S7 and
  Modbus"). The `extract_operations()` per-protocol seam above is specifically shaped so adding
  DNP3/EtherNet/IP/BACnet/OPC UA later is additive, not a rework.

## Testing plan (once this is built)

Reuse `tests/sample_s7comm.pcap` and `tests/sample_modbus.pcap` as the "known-good" baseline
seed, plus new fixtures/CTest entries for: `learn` producing the expected JSON baseline file from
a fixture with known operations/ranges; `check` against an unmodified copy of the same fixture
producing zero findings; `check` against a mutated fixture introducing one new function code and
one new address range producing exactly `NewOperation` + `NewTargetRange` (not both, not neither);
`learn` run twice (two separate captures merged into one baseline file) correctly unions ranges
rather than the second run clobbering the first; a two-conduit fixture proving a finding on one
conduit never leaks into another conduit's report; and, for Modbus specifically, a CTest pinning
`ModbusFrame::start_address`/`quantity` for every address-bearing function code once that
prerequisite field lands, the same way every other struct field in this codebase gets a dedicated
regex check.

## Phased build plan

1. **Prerequisite:** add structured `start_address`/`quantity` (or equivalent) fields to
   `ModbusFrame`, populated from the existing per-function-code parsing in `modbus.cpp`. Zero
   behavior change to any existing output -- purely additive fields, verified against the full
   existing Modbus CTest suite for zero regression, same discipline as every other change in this
   project.
2. **`include/conduitscope/baseline.hpp`/`.cpp`:** `Operation`, `extract_operations()` for
   S7comm and Modbus, `ConduitBaseline`/`BaselineStore`, JSON (de)serialization, the merge-on-
   `learn` logic, `BaselineEngine::check()` producing `BaselineFinding`s.
3. **`src/cli_main.cpp`:** the `baseline learn`/`baseline check` subcommands.
4. **`src/output.cpp`:** text/JSON report writers for `check`, mirroring
   `write_policy_report_text`/`_json`'s conventions.
5. **Fixtures, CTest, docs** (`PROTOCOL_COVERAGE.md`, `DEVELOPMENT.md` roadmap item 41 updated
   from "not started" to "in progress"/"done", `README.md`, `man/conduitscope.1`) -- same
   same-phase discipline as every other feature in this project, not deferred to the end.

**Phase 1 (steps 1-5 above) is done, v0.2.5.** One implementation detail differs from this plan's
step 4: the text/JSON report writers for `check` (`write_baseline_check_report_text`/`_json`)
ended up living in `baseline.cpp` itself alongside the engine, not in `output.cpp` -- `output.cpp`
formats `DecodedPacket` fields for `info`/`decode`, and a baseline check report isn't one of
those, so keeping it next to `BaselineEngine` (which already owns `Operation`/`BaselineStore`/
`BaselineFinding`) kept the report writer next to the types it renders, matching how
`policy_engine.cpp` and `asset_inventory.cpp` each own their own report writers rather than
routing through `output.cpp`.

Not started for later phases: zone-level baselines, statistical/confidence thresholds, and any
protocol beyond S7comm/Modbus -- see "Explicitly out of scope" above, unchanged.
