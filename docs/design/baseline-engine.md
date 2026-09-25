# ICS communication-baseline analysis at the protocol-operation level -- design draft

Status: **Phase 1 (S7comm + Modbus) and Phase 2 (EtherNet/IP, DNP3, BACnet, OPC UA, MELSEC, FINS)
implemented, v0.2.5.** Written at Jurgen's request to scope roadmap item 41 (`docs/DEVELOPMENT.md`)
into something buildable, starting with S7comm and Modbus. `BaselineEngine`
(`include/conduitscope/baseline.hpp`, `src/baseline.cpp`) and the `baseline learn`/`baseline check`
subcommand pair now exist and are covered by CTest, exactly as scoped below. Phase 2 extended
protocol breadth to the six protocols named above -- Jurgen said `learn`/`check` "felt short" for
determining traffic based on host and tech stack, since a host running any of those six was
invisible to the baseline even though `inventory`/`policy` already see it fine, and confirmed
protocol breadth (not zone-level rollup, not statistical thresholds) as the direction -- see
"Per-protocol data readiness" below for what was actually found for each of the six, and "Phased
build plan" at the bottom for what remains out of scope even now (zone-level rollup, statistical
thresholds, and CODESYS's `CmpIecVarAccess`, unchanged from the original draft).

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

**Phase 2 (v0.2.5, same release) -- what was ACTUALLY found for each of the six, checked directly
against the real decoder code, replacing the speculative notes above.** The original research this
design built on predicted all six would be "already structured the way S7 is." That held for three
of them; the other three needed either a small additive prerequisite (the same shape Modbus's own
Phase 1 prerequisite took) or turned out to have no genuine linear range at all -- both real,
honestly-scoped findings, not failures:

- **DNP3 -- full range-tracking, but needed its own small prerequisite first.**
  `Dnp3ObjectHeader` (`dnp3.hpp`) does carry real `group`/`variation`/`has_range`/`range_start`/
  `range_stop` fields, exactly as predicted -- but `Dnp3Result` (`dnp3.hpp`), the type actually
  reachable from `DecodedPacket::result` (the same one `extract_operations()` reads, see this
  file's own "Core data model" section below), only carried those headers as ALREADY-RENDERED
  display strings (`"g1v2 (Binary Input)"`) -- the real numbers never reached `DecodedPacket` at
  all. Fixed the same way Modbus's own Phase 1 gap was: a new, purely additive
  `Dnp3Result::dnp3_objects` field (`dnp3.hpp`/`dnp3.cpp`), a structured mirror of that same list.
  `operation_key` is `"<function_name>/<group_name>/v<variation>"`. One deliberate divergence from
  every other protocol here: extraction is NOT request-side only. DNP3's own `function_name`
  already tells request and response apart (`Read`/`Write`/`Direct Operate`/... vs. `Response`/
  `Unsolicited Response`), so there is no operation_key collision risk the way Modbus's write-echo
  problem has -- and, unlike Modbus, a DNP3 Read response's own object headers are NOT an echo of
  the request (a real Read request very often polls with an "all points"/Class-0 qualifier and no
  range at all; the RESPONSE is where the outstation's actual reported range appears), so
  restricting to requests would leave range-tracking nearly inert for the single most common DNP3
  traffic pattern. See `extract_dnp3_operations`'s own comment (`baseline.cpp`) for the full
  reasoning, including why control operations (Select/Operate/Direct Operate) naturally stay
  key-only when their own CROB/analog-output objects use an index-prefixed qualifier rather than a
  start-stop range (has_range simply comes back false there, nothing is forced).

- **MELSEC -- full range-tracking for Batch Read/Write, confirmed exactly as predicted.**
  `MelsecDeviceSpec::device_code`/`device_number` plus `MelsecFrame::point_count` (`melsec.hpp`)
  give a single device + a real count, architecturally identical to S7's own
  `byte_address`+`count` shape -- and, unlike S7's own BIT-transport-size exclusion, no unit-
  mismatch caveat is needed: a bit-type `device_number` is already a flat, one-per-bit address
  space on its own `device_code` (the wire's "two bit values packed per byte" is purely how
  response VALUE bytes are packed, not how the address itself is encoded). `operation_key` is
  `"<command_name>/0x<device_code>"`. Random Read/Write's own non-contiguous device list has no
  genuine linear range (the design's own prediction was specifically about Batch Read/Write) and
  is recorded key-only instead, one Operation per distinct `device_code` seen.

- **FINS -- full range-tracking for Memory Area Read/Write, with one real unit-mismatch caveat.**
  `FinsMemoryItem::area_code`/`address` plus `FinsFrame::point_count` (`fins.hpp`) give the same
  device+count shape as MELSEC -- EXCEPT for bit-addressed items (`FinsMemoryItem::is_bit`):
  FINS's own `address` field only advances once every 16 bits (`bit_address` rolls 0-15 within one
  `address` first), so `address` alone under-counts a bit-granularity range's true span -- the
  exact same unit-mismatch problem S7's own BIT-transport-size items have, and excluded from
  range-tracking the identical way (key-only instead). `operation_key` is
  `"<command_name>/0x<area_code>"`. Memory Area Fill has no explicit item-count field on the wire
  at all (so no range, even for a single, otherwise-clean address); Multiple Memory Area Read
  addresses a non-contiguous list (same reasoning as MELSEC's Random Read) and is key-only, one
  Operation per distinct `area_code`.

- **EtherNet/IP (CIP) -- key-only, a genuine and honestly-scoped gap, not a forced fit.**
  `CipPath` (`enip.hpp`) does carry real `class_id`/`instance_id`/`attribute_id` fields (folded
  into `operation_key` alongside the CIP service name, the same "bounded addressing dimension in
  the key" precedent S7's own DB-number inclusion sets), confirming that half of the original
  prediction. But CIP's only genuinely LINEAR addressing -- Read_Tag_Fragmented/
  Write_Tag_Fragmented's own `byte_offset`, used to read/write a tag element-by-element -- is
  computed by `enip.cpp`'s `decode_cip_request_data`/`decode_write_tag_request` and rendered
  straight into `CipMessage::values` as free text (`"element_count=10 byte_offset=1234"`), never a
  structured field the way `S7Item::byte_address` or `ModbusFrame::start_address` are. This is
  EXACTLY Modbus's own pre-Phase-1 problem (address/quantity rendered into `summary` text only) --
  but unlike Modbus, this design does not fix it here: `has_target_range` stays false for every
  EtherNet/IP operation in this pass. A genuine follow-up exists (add a structured
  `byte_offset`/`element_count` field to `CipMessage`, the same small, self-contained shape
  Modbus's own prerequisite took), just not taken up in this phase.

- **BACnet -- key-only, confirmed (not assumed) to have no linear range at all.** ReadProperty/
  WriteProperty's own object-instance + property-identifier (`bacnet.cpp`'s
  `decode_object_property_reference`) are BACnet's only two address-bearing "first pass" services
  -- but a BACnet object instance number is an opaque identifier (ASHRAE 135's own 22-bit instance
  space), never a "read this many consecutive addresses" operation the way an S7 byte range or a
  DNP3 point-index start-stop is, exactly as this design doc originally guessed. `operation_key` is
  `"<service>/<object-type>/<property-name>"`, parsed out of `BacnetApdu::values`' own
  `"object="`/`"property="` entries (a fixed, single-code-path "key=value" token, not a prose
  summary sentence -- a materially different, lower-stakes case than the free-text-scraping
  anti-pattern this design doc rejects for Modbus, since a parsing miss here only costs a
  cosmetically wrong key component, never a wrong range boundary the way DNP3's own numeric fields
  would).

- **OPC UA -- key-only, an honest call given genuinely ambiguous NodeId semantics.** Read/Write/
  Call's own NodeId list (`opcua.cpp`'s `decode_read_request_params`/`decode_write_request_params`/
  `decode_call_request_params`) is, like EtherNet/IP's byte_offset, rendered straight into
  `OpcUaMessage::values` as display strings, with no structured NodeId field to read a numeric
  identifier back out of. But even a successfully parsed NUMERIC NodeId wouldn't be a genuine
  `[start,end)` range the way a register block is: a single Read/Write targets ONE NodeId, not a
  count of consecutive addresses, and OPC UA NodeIds are legally String/Guid/ByteString
  identifiers too (not always numeric at all) -- so this design doesn't force a single-point-range
  model onto something that isn't really one. Every Tier 1 AND Tier 2 recognized service (not just
  Read/Write/Call) is still recorded key-only, `operation_key` = the service name alone.

CODESYS's `CmpIecVarAccess` remains the one confirmed real gap among the protocols surveyed for
this feature -- its live-variable read/write is structural-only today, named but not value-decoded,
so it can't feed a register-level baseline until that's built. Not in scope for either phase; it's
recorded here only so the "which architecture could follow next" question has a real answer when
it comes up.

## Core data model

```
struct Operation {
    std::string protocol;           // "s7comm" | "modbus" (Phase 1); "enip" | "dnp3" | "bacnet" |
                                     // "opcua" | "melsec" | "fins" (Phase 2) -- each spelled exactly
                                     // as that protocol's own ProtocolDecoder::id() returns it
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string operation_key;      // S7: "<rosctr>/<function_name>/<area_name>[/DB<n>]"
                                     // Modbus: "<function_name>"
                                     // EtherNet/IP: "<service>[/Class0x<n>][/Instance<n>][/Attr<n>]"
                                     // DNP3: "<function_name>/<group_name>/v<variation>"
                                     // BACnet: "<service>/<object-type>/<property-name>"
                                     // OPC UA: "<service_name>" alone
                                     // MELSEC/FINS: "<command_name>/0x<device_or_area_code>"
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
- **Protocols beyond S7comm and Modbus.** Per Jurgen's own original scoping ("starting including S7
  and Modbus"). **Since resolved by Phase 2 (v0.2.5, same release):** EtherNet/IP, DNP3, BACnet,
  OPC UA, MELSEC, and FINS were added exactly the additive way this bullet predicted -- one new
  `extract_<protocol>_operations()` function each, dispatched from the same `extract_operations()`
  seam, with zero changes to `merge_baseline_observations()`/`check_baseline()`/the JSON schema/the
  verdict model. See "Per-protocol data readiness" above for what was actually found for each of
  the six. Zone-level rollup and statistical/confidence thresholds (the other two bullets above)
  remain unresolved -- Jurgen's own Phase 2 request was specifically protocol breadth, not those.

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

**Phase 2 (EtherNet/IP, DNP3, BACnet, OPC UA, MELSEC, FINS) is done, v0.2.5, same release.** Same
shape as Phase 1's own step 2: one `extract_<protocol>_operations()` function per protocol added to
`baseline.cpp`, dispatched from the same `extract_operations()` seam, with zero changes to
`merge_baseline_observations()`/`check_baseline()`/the JSON schema/the verdict model (`Operation`,
`ConduitBaseline`, `BaselineStore`, `BaselineFinding`, `BaselineVerdict` are all byte-for-byte
unchanged in shape). Two differences from a pure "just add six functions" read of step 2:
- **DNP3 needed its own small prerequisite first**, the same shape as step 1's Modbus prerequisite:
  `Dnp3Result::dnp3_objects` (`dnp3.hpp`/`dnp3.cpp`), a purely additive structured field -- see
  "Per-protocol data readiness" above for why.
- **`BaselineEngine::observe` (step 2's own `.cpp` file) needed widening to track UDP conduits**,
  not just TCP: BACnet has no TCP form at all, and FINS/MELSEC can run over either transport. This
  is the one place Phase 2 touched code inside `BaselineEngine` itself (not just
  `extract_operations()`'s own dispatch) -- direction determination for UDP mirrors
  `AssetInventoryEngine::observe`'s own established pattern (BACnet's Confirmed-Request/
  Unconfirmed-Request APDU type as content-based signal, known-port heuristic fallback otherwise)
  rather than inventing a second convention for the same decision.

Step 5 (fixtures/CTest/docs) for Phase 2: no new fixtures -- every one of the six protocols' own
existing sample pcaps (`tests/sample_enip.pcap`, `sample_dnp3.pcap`, `sample_bacnet.pcap`,
`sample_opcua.pcap`, `sample_melsec.pcap`, `sample_fins.pcap`) already had enough real operation
diversity to exercise `learn`/`check` directly. 21 new `baseline_*` CTest entries (3 per protocol,
plus a 4th for the three range-tracking protocols) -- see `CMakeLists.txt`'s own "Phase 2" comment
block for the full test-shape rationale, including why `NewTargetRange` verification uses a
`sed`-shrunk already-learned baseline file rather than a second mutated pcap fixture (baseline
files are meant to be hand-edited/reviewed, per this design's own "Baseline state and persistence"
section above). `DEVELOPMENT.md` roadmap item 41, `README.md`, and `man/conduitscope.1` all updated
in the same pass -- see item 41's own Phase 2 entry for the full test-count/rebuild verification
record.

Not started for later phases: zone-level baselines and statistical/confidence thresholds -- see
"Explicitly out of scope" above, unchanged. CODESYS's `CmpIecVarAccess` remains the one confirmed
real decode gap among protocols surveyed for this feature (structural-only today, no value decode).
