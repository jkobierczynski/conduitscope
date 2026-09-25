# ICS communication-baseline analysis at the protocol-operation level -- design draft

Status: **Phase 1 (S7comm + Modbus) and Phase 2 (EtherNet/IP, DNP3, BACnet, OPC UA, MELSEC, FINS)
implemented, v0.2.5; a small follow-up (S7comm bit-level range tracking + `baseline check
--symbolic-addresses`) also implemented, v0.2.5, same release.** Written at Jurgen's request to
scope roadmap item 41 (`docs/DEVELOPMENT.md`) into something buildable, starting with S7comm and
Modbus. `BaselineEngine` (`include/conduitscope/baseline.hpp`, `src/baseline.cpp`) and the
`baseline learn`/`baseline check` subcommand pair now exist and are covered by CTest, exactly as
scoped below. Phase 2 extended protocol breadth to the six protocols named above -- Jurgen said
`learn`/`check` "felt short" for determining traffic based on host and tech stack, since a host
running any of those six was invisible to the baseline even though `inventory`/`policy` already see
it fine, and confirmed protocol breadth (not zone-level rollup, not statistical thresholds) as the
direction -- see "Per-protocol data readiness" below for what was actually found for each of the
six, and "Phased build plan" at the bottom for what remains out of scope even now (zone-level
rollup, statistical thresholds, and CODESYS's `CmpIecVarAccess`, unchanged from the original draft).
The follow-up is documented in its own section near the bottom of this file, "Follow-up (v0.2.5,
same release): S7comm bit-level range tracking + `--symbolic-addresses`".

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
  `byte_address`+`count` shape -- and, unlike S7's own BIT-transport-size unit split (as it stood at
  Phase 2 time -- see the "Follow-up" section near the bottom of this file for how S7 later tracked
  bit-unit ranges too, under their own distinct operation_key, without needing this MELSEC caveat at
  all), no unit-mismatch caveat is needed here: a bit-type `device_number` is already a flat, one-per-bit address
  space on its own `device_code` (the wire's "two bit values packed per byte" is purely how
  response VALUE bytes are packed, not how the address itself is encoded). `operation_key` is
  `"<command_name>/0x<device_code>"`. Random Read/Write's own non-contiguous device list has no
  genuine linear range (the design's own prediction was specifically about Batch Read/Write) and
  is recorded key-only instead, one Operation per distinct `device_code` seen.

- **FINS -- full range-tracking for Memory Area Read/Write, with one real unit-mismatch caveat.**
  `FinsMemoryItem::area_code`/`address` plus `FinsFrame::point_count` (`fins.hpp`) give the same
  device+count shape as MELSEC -- EXCEPT for bit-addressed items (`FinsMemoryItem::is_bit`):
  FINS's own `address` field only advances once every 16 bits (`bit_address` rolls 0-15 within one
  `address` first), so `address` alone under-counts a bit-granularity range's true span -- the same
  bit-vs-byte unit-mismatch problem that motivated S7's own original BIT-transport-size exclusion
  (as it stood at Phase 2 time -- see the "Follow-up" section near the bottom of this file), except
  FINS's own version can't be fixed the same "give it a distinct operation_key" way S7's later was:
  the wire's `address` field itself under-counts, not merely "the wrong unit for the existing range
  vector," so there is no usable per-bit address to key a range on at all here. Excluded from
  range-tracking (key-only instead). `operation_key` is
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

## Follow-up (v0.2.5, same release): S7comm bit-level range tracking + `--symbolic-addresses`

Jurgen asked why a learned baseline entry could show up like this, with no range at all:
```json
{"operation_key": "Write Var/Merkers/Flags (M)", "packet_count": 100,
 "has_target_range": false, "observed_ranges": []}
```
The answer was exactly Phase 1's own documented BIT-transport-size exclusion (see
`extract_s7comm_operations`'s header comment, as it stood before this follow-up): a BIT item's
natural address unit is bits (`S7Item::bit_address`, already computed on the decode side), not
bytes, and mixing bit-granularity numbers into the same `observed_ranges` vector as byte-granularity
ones would corrupt the interval-containment math this whole feature depends on. Jurgen confirmed two
follow-ups: (1) track BIT items' ranges for real instead of excluding them, and (2) an opt-in way to
render a range in Step7 byte/word/bit notation ("MB", "MW", "M10.3") rather than bare numbers.

**Part 1: bit-level range tracking, via a distinct operation_key, not a widened range model.** The
core constraint carried over unchanged from Phase 1: bit-unit and byte-unit ranges must never be
compared, merged, or unioned against each other, even for "the same" function+area. Rather than
widen `Operation`/`OperationBaseline`'s single `[range_start, range_end)` pair to somehow hold two
incompatible units at once (which is exactly the corruption to avoid), a BIT-transport-size S7 item
now gets the SAME base operation_key every other item in its area+DB would get, with a trailing
`/bit` appended (a separator no legitimate `area_name` or `DB<n>` suffix can ever produce, so it
never collides) -- and `has_target_range`/`range_start`/`range_end` are populated in `bit_address`
units under THAT key. This needed zero changes to `merge_baseline_observations`, `check_baseline`,
the verdict model, or the JSON schema -- exactly Phase 2's own "operation_key is deliberately opaque
to the engine" precedent (see "Core data model" above), just applied one level down (splitting one
protocol's own operation into two sub-operations by addressing granularity, not by function or area).
A conduit that both reads MB bytes and writes M#.# bits from/to the same area now correctly produces
TWO `OperationBaseline` rows, not one with mixed-unit ranges -- confirmed directly against a learned
baseline JSON file exercising exactly this (Merkers byte-read + Merkers bit-write on one conduit),
see `tests/sample_baseline_s7comm_symbolic.pcap`.

`item.count`'s real BIT-item semantics were verified against the decode path (`s7comm.cpp`'s
`parse_s7_item`), not assumed: the wire's "number of elements" field is read identically for every
transport size, with no BIT-specific special-casing. Every BIT item this project's own fixture
generator and every real capture seen so far uses `count == 1` (Step7/TIA Portal/snap7 all address
one bit per item; S7ANY has no "N consecutive bits in one item" idiom the way byte-oriented areas
have "N consecutive words"). Nothing on the wire actually forbids `count > 1`, though, so the range
math treats it the same "one unit per element" way the existing Counter/Timer branch already does
(`range_end = bit_address + count`) rather than silently assuming 1 -- correct either way, and the
overwhelmingly common `count == 1` case degenerates to exactly the single-bit range expected.

**Part 2: `baseline check --symbolic-addresses`, S7comm only, default off.** Reuses
`s7comm.cpp`'s existing `s7_build_tag` notation conventions rather than duplicating them: its
area-letter table was extracted into a small shared `s7_area_letter_for_code(uint8_t)` function
(`s7comm.hpp`/`s7comm.cpp`), the same "pull a file-local helper out into a small shared public one"
shape the POWERLINK work already established for `canopen_sdo_abort_code_name`. A new shared
`s7_range_notation(area_letter, db_number, unit, start, end)` function (also `s7comm.hpp`/`s7comm.cpp`)
renders a RANGE (not a single address, unlike `s7_build_tag`) in the same notation: `unit` is
`"byte"` (MB-always -- a byte range is exactly expressible in MB terms regardless of whether the
underlying accesses were BYTE/WORD/DWORD reads, satisfying Jurgen's own "summarize in bytes like MB,
MW" phrasing without guessing at WORD/DWORD alignment), `"bit"` (converts each endpoint back to
byte.bit form), or `"counter_or_timer"` (no data-size suffix at all, mirroring `s7_build_tag`'s own
Counter/Timer branch). A single-unit range (start/end differ by exactly 1) renders as one address,
not a degenerate "X-X" span.

Of the two structured-vs-string-parsing approaches this follow-up considered, the chosen shape is a
hybrid: `Operation` (the per-packet extraction struct) DOES gain three new structured fields
(`s7_area_letter`, `s7_db_number`, `s7_range_unit`), populated once in `extract_s7comm_operations`
alongside `operation_key` itself -- structured fields, not regexing a rendered string back apart,
matching this codebase's own established discipline (the same one that motivated Modbus's Phase 1
`start_address`/`quantity` prerequisite and DNP3's Phase 2 `dnp3_objects` one). But these three
fields are deliberately **not** added to the persisted `BaselineStore`/`OperationBaseline` JSON
schema: `write_baseline_store_json`/`parse_baseline_store_json` are untouched, so `learn`'s own
output for every existing S7comm byte/word/dword operation is byte-for-byte unchanged by this
follow-up. This works because `--symbolic-addresses` rendering only ever needs these fields off the
CHECKED capture's own freshly-extracted "observed" `Operation`/`OperationBaseline` (always available
live, every `check` run) -- never off the loaded baseline file on disk, since `operation_key` already
determines area+DB+unit deterministically for S7comm, so the observed side's own fields are enough to
render notation for the baseline's own ranges too (`BaselineFinding` carries the same three fields,
copied from the observed side in `check_baseline`, and used only when `symbolic_addresses` is true
and `protocol == "s7comm"`). No version bump, no schema migration question, and zero risk to every
other protocol's rendering or to any already-written baseline file.

CLI: `baseline check --symbolic-addresses` (default off). Adds `observed_range_symbolic`/
`baseline_ranges_symbolic` fields (JSON) or `observed range (symbolic)`/`baseline ranges (symbolic)`
lines (text) alongside the existing raw numeric fields, for `NewTargetRange` findings with
`protocol == "s7comm"` only -- every other protocol's/verdict's rendering is completely unaffected,
flag on or off.

**Part 3 (same follow-up, found from Jurgen's own real capture): 0xB2 (TIA1200SYM) items were
still excluded, for a different reason than Part 1's BIT items were.** After Part 1 shipped,
Jurgen ran `learn` against a real capture (`4SICS-GeekLounge-151021.pcap`, the well-known public
4SICS/netresec ICS-lab dataset) and got 36 Merker-write packets back as `{"operation_key": "Write
Var/Merkers/Flags (M)", "has_target_range": false, "observed_ranges": []}` -- no `/bit` suffix at
all, meaning these packets never even reached Part 1's own bit-tracking branch. Root cause,
confirmed directly against the decode side rather than guessed at: `extract_s7comm_operations`
checks `item.is_experimental` (true for a successfully-decoded 0xB2 item) *before* it checks
`transport_size == 0x01`, and the `is_experimental` branch did nothing at all -- `item.count` is
unconditionally unset (0) for every 0xB2 item, since `try_decode_tia1200_sym` (s7comm.cpp) never
sets it (0xB2's wire format has no count field the way S7ANY's does -- see `S7Item::count`'s own
comment). This project's own `tests/sample_s7comm_1200sym.pcap` fixture is itself built from real
item bytes pulled out of a 4SICS GeekLounge capture during that decoder's own development (see
`build_s7comm_1200sym_sample`'s own docstring, `tools/make_sample_pcap.py`) -- strong evidence
Jurgen's own capture is exercising this exact addressing mode.

Unlike a classic BIT item, a 0xB2 item genuinely has no `count` to build a real `[start, end)` span
from -- there is no way to know from the current decode how many bytes/bits beyond the starting
LID address a given 0xB2 access actually touches, and inventing one would be exactly the kind of
guess this project's `is_experimental` marking exists to warn readers away from
(`S7Item::is_experimental`'s own comment: unverified against real DB-area traffic, no confirmed
support for more than one LID entry per item). What *is* known is exactly where the access
*starts*: `item.bit_address`, the same `byte_address*8 + bit_offset` LID reconstruction a classic
BIT item's own `bit_address` already is. So a successfully-decoded 0xB2 item now gets a
**single-point** `[bit_address, bit_address + 1)` observation -- "an access was seen starting
here," not "this many bits were touched from here" -- under yet another distinct operation_key
suffix, `/bit-symbolic` (not `/bit`): a confirmed classic-BIT range (real `item.count`) and a
best-effort 0xB2 single-point reconstruction must never share a key, or an unconfirmed
reconstruction could silently backstop a `NewTargetRange` verdict that should only ever rest on
confirmed data. Multiple single-point observations for the same key still coalesce the normal way
(`OperationBaseline::observed_ranges` is a merged, sorted interval set by design) -- five items
addressing five adjacent bits (M2.0-M2.4, as in the real capture behind
`sample_s7comm_1200sym.pcap`) legitimately merge into one `[16, 21)` row, the same as five adjacent
single-bit classic accesses would.

One more real gap surfaced while wiring this up, not papered over: `s7_area_letter_for_code(item.
area)` -- the same lookup every other branch in `extract_s7comm_operations` already uses --
can't be reused for a 0xB2 item. `item.area` is left at its struct default (0) for a 0xB2 item
(`S7Item::area`'s own comment: "its own area codes are a different, non-overlapping byte value
space ... this field intentionally doesn't try to unify them"), confirmed by reading
`try_decode_tia1200_sym` end to end -- it never touches `item.area`. Calling
`s7_area_letter_for_code(0)` would silently return `""` (empty area letter) for every symbolic
finding, breaking `--symbolic-addresses` rendering for exactly the data this follow-up exists to
add. Fixed with a second, 0xB2-specific lookup (`s7_area_letter_for_tia1200sym_item`,
`baseline.cpp`) keyed off `item.area_name` instead, which `try_decode_tia1200_sym` DOES set
reliably -- using the exact same literal strings (`"Merkers/Flags (M)"`, `"Data Block (DB)"`, ...)
`s7_area_name` uses for the equivalent S7ANY area. This is an exact match against a small, closed,
six-string vocabulary this codebase itself produces, not the free-text/number-scraping anti-pattern
this design rejects elsewhere -- there's no number hiding in `area_name` to parse wrong, only which
of six fixed labels it is. A related, smaller gap in the same family: `item.area` also being unset
meant a DB-area 0xB2 item's own `db_number` was never folded into the base operation_key the way a
classic DB/DI item's already is (`s7_area_has_db_number(item.area)` is always false for a 0xB2
item) -- left as-is, two 0xB2 items addressing different DBs would have collided onto one
`.../Data Block (DB)/bit-symbolic` key, merging their single-point ranges together. Fixed the same
way: a DB-area 0xB2 item's `db_number` (which `try_decode_tia1200_sym` *does* set) is folded into
the key whenever `item.is_experimental && item.area_name == "Data Block (DB)"`, alongside the
existing `s7_area_has_db_number(item.area)` check for classic items.

No changes were needed anywhere else: `merge_baseline_observations`, `check_baseline`, the verdict
model, the JSON schema, and `--symbolic-addresses`'s own rendering machinery (`s7_range_notation`)
all already treat `operation_key`/`s7_range_unit` as opaque strings, so reusing the existing `"bit"`
unit tag for a `/bit-symbolic` observation renders it in identical `Mx.y`/`DBn.DBXx.y` notation with
zero code changes there -- verified directly against a learned+checked baseline, not assumed.
