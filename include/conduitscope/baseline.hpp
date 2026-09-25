// SPDX-License-Identifier: Apache-2.0
// baseline.hpp - ICS communication-baseline analysis at the protocol-operation level (roadmap
// item 41, docs/DEVELOPMENT.md; full design at docs/design/baseline-engine.md, which is
// authoritative for the data model, persistence format, CLI shape, and scope boundaries this file
// implements -- read that first if anything below seems under-motivated).
//
// `inventory` and `policy validate` both stop at (client, server, protocol, port): they can say a
// PLC talks Modbus/TCP to three hosts, but never say anything about WHAT those hosts are actually
// doing to it -- which function codes, which registers, which memory ranges. This engine baselines
// at the *operation* level instead, across multiple captures over time (a persisted JSON file, not
// a single-capture report like AssetInventoryEngine/PolicyEngine), and flags deviation from it:
// `baseline learn` absorbs a capture's operations into the baseline file (never flags anything);
// `baseline check` compares a capture against an existing baseline file (never writes it) and
// reports every operation the baseline doesn't already cover.
//
// Phase 1 scope, per the design doc: S7comm and Modbus only (the two protocols whose operation-
// level data -- S7's `S7Item`, Modbus's newly-added `ModbusFrame::start_address`/`quantity`, see
// modbus.hpp -- is already structured, not scraped from free text), IP-pair conduit granularity
// (no zone-level rollup), and exact set/interval membership (no statistical/confidence
// thresholds). See the design doc's own "Explicitly out of scope" section for the full list and
// reasoning, including the named (not solved here) baseline-poisoning caveat for `learn`: this
// engine absorbs whatever a capture contains with no judgment at all, so `learn` should only ever
// be run against captures already trusted to be clean.
//
// Shaped the same three-stage way AssetInventoryEngine/PolicyEngine already are (see their own
// file headers): observe() per packet in capture order, finish() once per capture, then either
// merge_baseline_observations() (learn) or check_baseline() (check) does something with the
// result -- plus persistence (load_baseline_store/save_baseline_store) and report rendering
// (write_baseline_check_report_text/_json), which neither of those two engines needs at all.
#pragma once

#include <cstdint>
#include <iosfwd>
#include <optional>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "conduitscope/decoder.hpp"

namespace conduitscope {

// One S7comm or Modbus operation extracted from a single decoded packet -- see
// extract_operations()'s own comment below for exactly how `operation_key`/`has_target_range`/
// `range_start`/`range_end` are computed per protocol. `protocol`/`client_ip`/`server_ip`/
// `server_port` are filled in by BaselineEngine::observe (the conduit-identity tuple it already
// tracks the same SYN/SYN-ACK-first, known-port-fallback way PolicyEngine::observe/
// AssetInventoryEngine::observe do -- see BaselineEngine::observe's own comment), NOT by
// extract_operations() itself: a single DecodedPacket carries no cross-packet TCP-session
// direction state of its own, so extract_operations() only ever computes the parts genuinely
// derivable from THIS packet's own decoded protocol frame (operation_key, target range), and
// leaves protocol/client_ip/server_ip/server_port at their defaults for the caller to fill in.
struct Operation {
    std::string protocol;              // "s7comm" | "modbus" (Phase 1)
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string operation_key;         // S7: "<function_name>/<area_name>[/DB<n>][/bit|/bit-symbolic]"
                                        // -- the trailing "/bit" is appended only for a classic S7ANY
                                        // BIT-transport-size item; "/bit-symbolic" only for a
                                        // successfully-decoded 0xB2 (TIA1200SYM) item (see
                                        // extract_s7comm_operations' own comment for why each gets its
                                        // own distinct operation_key rather than sharing one with
                                        // byte-addressed accesses to the same area+DB, or with each
                                        // other -- a confirmed classic-BIT range and a best-effort
                                        // single-point 0xB2 reconstruction must never back the same
                                        // NewTargetRange verdict).
                                        // Modbus: "<function_name>" alone (Phase 1: one address
                                        // space per function, see the design doc)
    // false for: Modbus (always, until a future phase widens the range model), an S7 item with an
    // unrecognized transport size or a zero element count, or a Modbus operation whose function code
    // has no address concept (diagnostics, exception responses, ...). A BIT-transport-size S7 item
    // DOES get a range (bit_address units, under its own "/bit"-suffixed operation_key), and so does a
    // successfully-decoded 0xB2 item (a single-point [bit_address, bit_address+1) range -- item.count
    // is never available for one, so this is "an access was observed starting here," not a confirmed
    // span -- under its own "/bit-symbolic"-suffixed key) -- see extract_s7comm_operations' own
    // comment for why bit-, byte-, and bit-symbolic-unit ranges are never compared/merged despite
    // superficially sharing "the same" function+area.
    bool has_target_range = false;
    // Half-open [range_start, range_end). S7: byte_address units within this item's own area+DB (or,
    // for the Counter/Timer areas, counter/timer-number units; or, for a "/bit"- or "/bit-symbolic"-
    // suffixed operation_key, bit_address units -- see extract_s7comm_operations' own comment for all
    // four). Modbus: register/coil address units within the function's own address space.
    uint32_t range_start = 0, range_end = 0;

    // S7comm only (left at their defaults -- "", 0, "" -- for every other protocol, and for an
    // S7comm operation with has_target_range false): the raw pieces s7_range_notation (s7comm.hpp)
    // needs to render range_start/range_end in Step7 notation, carried as structured fields rather
    // than parsed back out of operation_key (this codebase's own established "structured field, not
    // string-scraping" discipline -- see extract_modbus_operations' own header comment and this
    // file's Phase 2 section on the EtherNet/IP byte_offset gap this deliberately avoids
    // reintroducing). Populated once, alongside operation_key itself, in extract_s7comm_operations.
    //
    // Deliberately NOT part of the persisted BaselineStore/OperationBaseline JSON schema (see
    // OperationBaseline's own comment on this) -- only Operation (this struct) and the in-memory
    // BaselineFinding a `check` run builds ever carry them; `--symbolic-addresses` rendering always
    // has a freshly-extracted "observed" Operation on hand (the capture being checked), never needs
    // to read these back out of a possibly-years-old baseline file on disk.
    std::string s7_area_letter;   // e.g. "M", "I", "Q", "DB", "DI", "L", "V", "C", "T"
    uint16_t s7_db_number = 0;    // meaningful only when s7_area_letter is "DB" or "DI"
    std::string s7_range_unit;    // "byte" | "bit" | "counter_or_timer" -- see s7_range_notation's
                                   // own comment (s7comm.hpp) for why all three need telling apart
};

// Extracts every Operation this single decoded packet contributes, or an empty vector when
// `packet` isn't an in-scope request packet at all -- dispatches on DecodedPacket::protocol,
// exactly one function per in-scope protocol (see extract_modbus_operations/
// extract_s7comm_operations below), pulling the already-decoded ModbusFrame/S7CommResult out of
// `packet.result` the same `->as<T>()` way output.cpp's own write_modbus_json_fields/
// write_s7comm_json_fields already do -- this is the one, single place this codebase retrieves
// either struct from a DecodedPacket; nothing here invents a second mechanism.
//
// Deliberately request-side only, for both protocols -- see extract_modbus_operations/
// extract_s7comm_operations' own comments for exactly what "request" means for each, and why: a
// response side either carries no address at all (Modbus reads, S7 Ack_Data) or would double-count
// the very same operation its own paired request already contributed (Modbus writes, whose
// response echoes address+quantity back -- see ModbusFrame::is_request's own comment, modbus.hpp).
std::vector<Operation> extract_operations(const DecodedPacket& packet);

// One operation ever observed on one conduit, across however many `learn` captures contributed to
// it -- see ConduitBaseline's own comment for the conduit this belongs to.
struct OperationBaseline {
    std::string operation_key;
    size_t packet_count = 0;  // total packets (across every learn capture) that contributed this
                               // operation_key on this conduit
    bool has_target_range = false;
    // Sorted, non-overlapping, coalesced half-open [start, end) intervals -- every range() ever
    // observed for this operation on this conduit, merged on insert (merge_range_into, baseline.cpp).
    // A plain sorted vector with linear merge-on-insert, per the design doc: a handful of intervals
    // per operation in practice (real PLC programs read/write a small, stable set of ranges), so no
    // interval tree is needed at this scale.
    std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;

    // Mirrors Operation::s7_area_letter/s7_db_number/s7_range_unit's own comment (this struct's dual
    // per-capture/persisted-store role, above, means these are meaningful only in the per-capture
    // role -- BaselineEngine::finish()'s own output -- where they're copied straight from the
    // Operation that produced this entry). write_baseline_store_json/parse_baseline_store_json
    // deliberately do NOT serialize these three: a baseline file loaded back off disk always leaves
    // them at their defaults, which is fine, since check_baseline only ever reads them off the
    // freshly-extracted "observed" side (the capture being checked), never off a loaded baseline --
    // see Operation's own comment for why. Leaving the persisted schema untouched also means every
    // existing S7comm byte/word/dword operation's own `learn`/`check` JSON output is byte-for-byte
    // unchanged by this (this file's own review discipline: don't touch what doesn't need touching).
    std::string s7_area_letter;
    uint16_t s7_db_number = 0;
    std::string s7_range_unit;
};

// One conduit's baseline: every distinct operation_key ever observed on this (client_ip, server_ip,
// protocol, server_port) tuple, across every `learn` capture that ever exercised it. Conduit
// identity reuses exactly AssetInventoryEngine/PolicyEngine's own tuple (see BaselineEngine::
// observe's own comment) -- no zone-level rollup in Phase 1, see this file's own header comment.
//
// Also doubles as BaselineEngine::finish()'s own per-capture OUTPUT shape (one ConduitBaseline per
// conduit this ONE capture exercised, before it's either merged into a persisted BaselineStore by
// merge_baseline_observations, or compared against one by check_baseline) -- rather than a second,
// near-identical struct, since the two shapes are otherwise identical field-for-field. In that
// per-capture role, first_seen_capture/last_seen_capture are left empty (meaningless until a
// caller actually merges this into a store and knows the capture's own filename).
struct ConduitBaseline {
    std::string client_ip, server_ip, protocol;
    uint16_t server_port = 0;
    size_t packet_count = 0;  // total in-scope packets (across every learn capture) on this conduit
    std::string first_seen_capture, last_seen_capture;  // filenames, for a human reading the file --
                                                          // see this struct's own comment above for
                                                          // when these are meaningfully populated
    std::vector<OperationBaseline> operations;
};

// The persisted baseline file's whole content -- see this file's own header comment for the
// learn/check lifecycle, and load_baseline_store/save_baseline_store below for the JSON
// (de)serialization.
struct BaselineStore {
    int schema_version = 1;
    std::vector<ConduitBaseline> conduits;
};

// Thrown by parse_baseline_store_json/load_baseline_store on a malformed or unreadable baseline
// file -- mirrors PolicyError's own shape (policy.hpp): a plain runtime_error with a human-readable
// message, no separate error code, since the CLI layer's own catch block just prints what() and
// exits non-zero (see run_baseline_learn/run_baseline_check, cli_main.cpp).
struct BaselineStoreError : std::runtime_error {
    explicit BaselineStoreError(const std::string& msg) : std::runtime_error(msg) {}
};

// Serializes `store` as JSON to `out` -- the exact schema parse_baseline_store_json below reads
// back. Field-for-field mirror of BaselineStore/ConduitBaseline/OperationBaseline; see
// baseline.cpp's own "JSON (de)serialization" section for the fixed shape (this is a small,
// purpose-built writer/reader for exactly this schema, not a general JSON library -- this codebase
// has none, see baseline.cpp's own comment on why one isn't needed here, the same "purpose-built,
// not general" posture yaml_mini.hpp already takes for the policy file format).
void write_baseline_store_json(std::ostream& out, const BaselineStore& store);

// Parses `text` (an already-read baseline file's contents) into a BaselineStore. Throws
// BaselineStoreError on anything that doesn't match the fixed schema write_baseline_store_json
// produces -- this parser is deliberately not tolerant of hand-edits outside that shape (a
// baseline file is a generated artifact meant to be diffed/reviewed, not hand-authored, unlike the
// policy YAML file yaml_mini.hpp parses).
BaselineStore parse_baseline_store_json(const std::string& text);

// Reads and parses the baseline file at `path`. Returns a fresh, empty BaselineStore
// (schema_version 1, no conduits) when `path` does not exist yet -- `learn`'s own "reads the file
// if present, merges, always writes it back" contract (see this file's own header comment) needs a
// first-run starting point that isn't an error. Throws BaselineStoreError if `path` exists but
// can't be opened, or its content doesn't parse (see parse_baseline_store_json), and
// BaselineStoreError as well (not a separate error type) if the file declares a schema_version this
// build doesn't understand (only 1 exists today).
BaselineStore load_baseline_store(const std::string& path);

// Writes `store` to `path` as JSON (write_baseline_store_json). Throws BaselineStoreError if the
// file can't be opened for writing.
void save_baseline_store(const std::string& path, const BaselineStore& store);

// Merges `observed` -- one capture's own BaselineEngine::finish() output -- into `store` in place:
// a conduit in `observed` not yet in `store` is appended (first_seen_capture = last_seen_capture =
// `capture_filename`); an existing conduit has its packet_count added to, last_seen_capture
// overwritten to `capture_filename` (the most recent learn run to touch it), and its own operations
// merged the same way one level down (a new operation_key appended; an existing one's packet_count
// added to and observed_ranges merged via merge_range_into, coalescing on insert -- see
// OperationBaseline's own comment). Counters and ranges are only ever extended, never reset --
// this is what makes `learn` run against N captures over N days converge on one cumulative
// baseline rather than each run replacing the last one's state.
void merge_baseline_observations(BaselineStore& store, const std::vector<ConduitBaseline>& observed,
                                  const std::string& capture_filename);

// One of the three ways a checked capture's operation can diverge from an existing baseline, plus
// the "everything matched" case (KnownOperation) -- see check_baseline's own comment for exactly
// when each fires.
enum class BaselineVerdict { KnownOperation, NewConduit, NewOperation, NewTargetRange };

// Renders a BaselineVerdict as the exact lowercase-with-hyphens string this codebase's own
// DirectionSource/FlowVerdict rendering convention uses elsewhere (direction_source_name,
// decoder.hpp; verdict_name, policy_engine.cpp) -- used by both the text and JSON report writers so
// the two never drift on spelling.
const char* baseline_verdict_name(BaselineVerdict verdict);

// One anomaly `check` found: a specific (conduit, operation_key) pair in the checked capture that
// this baseline doesn't already cover, or (NewTargetRange) covers only partially. Never constructed
// for a KnownOperation match -- see BaselineCheckReport::findings' own comment for why a report
// only ever LISTS anomalies, even though KnownOperation is a real enum value.
struct BaselineFinding {
    BaselineVerdict verdict;
    std::string client_ip, server_ip, protocol;
    uint16_t server_port = 0;
    std::string operation_key;
    // Set only for NewTargetRange: the specific range this capture exercised (observed_start/end),
    // and, for context in the report, the baseline's own already-known ranges for this same
    // operation_key on this same conduit (baseline_ranges) -- both left at their defaults
    // (0/0/empty) for NewConduit/NewOperation, where there is no baseline range to compare against
    // at all yet.
    uint32_t observed_start = 0, observed_end = 0;
    std::vector<std::pair<uint32_t, uint32_t>> baseline_ranges;
    size_t packet_count = 0;  // how many packets in THIS capture hit this finding

    // Copied from the checked capture's own (freshly-extracted) Operation/OperationBaseline entry
    // -- see Operation::s7_area_letter's own comment (above) for why these are sourced from the
    // "observed" side rather than the loaded baseline file. Empty/0/"" for every non-S7comm finding.
    // Used only by write_baseline_check_report_text/_json's own `symbolic_addresses` rendering.
    std::string s7_area_letter;
    uint16_t s7_db_number = 0;
    std::string s7_range_unit;
};

// `check`'s full result for one capture against one baseline: every anomaly found
// (BaselineCheckReport::findings), plus enough summary counts to render a "N operation(s) matched
// the baseline, M did not" header the way write_baseline_check_report_text does.
struct BaselineCheckReport {
    std::string capture_path;
    // Only ever NewConduit/NewOperation/NewTargetRange entries -- see the design doc's own CLI
    // shape comment ("reports every operation in this capture that the baseline doesn't already
    // cover"): a KnownOperation match is exactly the case that ISN'T worth listing one-by-one, so
    // it's folded into known_operation_count below instead, not omitted silently -- the report's
    // own summary line still says how many operations matched cleanly.
    std::vector<BaselineFinding> findings;
    size_t known_operation_count = 0;      // distinct (conduit, operation_key) pairs that matched
    size_t conduits_observed = 0;          // distinct conduits this capture exercised at all
    size_t operations_observed = 0;        // distinct (conduit, operation_key) pairs this capture
                                            // exercised (== known_operation_count + the conduit/
                                            // operation-level findings' own count, NewTargetRange
                                            // excluded since that's a known operation_key with an
                                            // unfamiliar range, not an unfamiliar operation_key)

    // True only when `findings` is empty -- mirrors PolicyReport::compliant()'s own role (the CLI
    // layer's exit-code decision, see run_baseline_check in cli_main.cpp), named identically for
    // the same reason FlowVerdict/BaselineVerdict share a naming convention: so a reader who
    // already knows one of this codebase's report structs recognizes the other's shape immediately.
    bool compliant() const { return findings.empty(); }
};

// Compares `observed` (one capture's own BaselineEngine::finish() output) against `baseline` and
// produces the findings/summary counts described above. Per-(conduit, operation_key) verdict:
//   - the conduit (client_ip, server_ip, protocol, server_port) isn't in `baseline` at all ->
//     NewConduit, one finding per operation_key this capture observed on that unseen conduit (the
//     conduit itself is what's new; operation_key is still carried on each finding so the report
//     says WHICH operation(s) the new conduit was seen doing, per the design doc's own "NewConduit
//     subsumes 'a new client talked to this server'" framing).
//   - the conduit is known, but this operation_key was never recorded on it -> NewOperation (the
//     FC03-baseline/FC16-never-seen example from the design doc).
//   - the conduit and operation_key are both known, has_target_range is true, and at least one of
//     this capture's own observed sub-ranges for that operation_key isn't fully contained in one
//     of the baseline's own observed_ranges -> NewTargetRange, observed_start/end set to the union
//     of only the NOT-already-covered sub-range(s) (not every observed sub-range -- a capture can
//     observe one already-known range and one new one for the same operation_key in the same run,
//     and the report must not claim bytes as "observed" that fell only in the gap between two
//     disjoint sub-ranges), baseline_ranges set to the baseline's own (for report context).
//   - otherwise (has_target_range false, or the range IS fully covered) -> KnownOperation --
//     tallied into known_operation_count, no BaselineFinding constructed (see
//     BaselineCheckReport::findings' own comment for why).
BaselineCheckReport check_baseline(const BaselineStore& baseline, const std::vector<ConduitBaseline>& observed,
                                    const std::string& capture_path);

class BaselineEngine {
public:
    // Folds one already-decoded packet into this engine's per-conduit, per-operation state for
    // THIS capture. Call once per packet, in capture order (same discipline as
    // PolicyEngine::observe/AssetInventoryEngine::observe). A non-TCP packet, or one whose protocol
    // isn't "modbus"/"s7comm", or one extract_operations() returns nothing for (a response packet,
    // a Setup Communication/PLC Stop/PLC Control S7 job with no Read/Write Var item, a Modbus
    // exception response, ...) contributes nothing.
    //
    // Client (initiator) vs. server is decided per TCP session exactly the same SYN/SYN-ACK-first,
    // known-port-fallback way PolicyEngine::observe/AssetInventoryEngine::observe already do (see
    // either's own doc comment for the full priority order) -- reimplemented here rather than
    // shared, the same "each engine stays self-contained" convention asset_inventory.cpp's own
    // header comment already establishes for its relationship to policy_engine.cpp, narrowed to
    // just this feature's two known ports (MODBUS_TCP_PORT, COTP_TCP_PORT -- S7comm's own port,
    // since a "cotp"-only session with no S7comm payload never reaches extract_operations() anyway,
    // see extract_s7comm_operations' own comment).
    void observe(const DecodedPacket& packet);

    // Produces this ONE capture's own observed conduits/operations, one ConduitBaseline per
    // distinct conduit this capture exercised (see ConduitBaseline's own comment for its dual role
    // as both the persisted-store shape and this per-capture output shape). Safe to call more than
    // once; does not reset state.
    std::vector<ConduitBaseline> finish() const;

private:
    struct OperationState {
        bool has_target_range = false;
        std::vector<std::pair<uint32_t, uint32_t>> observed_ranges;
        size_t packet_count = 0;
        // Mirrors Operation::s7_area_letter/s7_db_number/s7_range_unit -- see that struct's own
        // comment above. Copied straight from the first Operation that contributes this
        // operation_key (stable across every subsequent packet for the same key, since operation_key
        // itself already encodes area+DB+unit for S7comm).
        std::string s7_area_letter;
        uint16_t s7_db_number = 0;
        std::string s7_range_unit;
    };
    struct ConduitState {
        std::string client_ip, server_ip, protocol;
        uint16_t server_port = 0;
        size_t packet_count = 0;
        std::unordered_map<std::string, OperationState> operations;
        std::vector<std::string> operation_order;  // operation_key, first-seen order
    };
    struct TcpSessionState {
        std::string client_ip, server_ip;
        uint16_t server_port = 0;
        bool initiator_known = false;
    };

    std::unordered_map<std::string, ConduitState> conduits_;
    std::vector<std::string> conduit_order_;  // conduit keys, first-seen order
    std::unordered_map<std::string, TcpSessionState> tcp_sessions_;  // keyed by canonical 4-tuple
};

// Renders `report` as a human-readable text report to `out` -- findings grouped by conduit, with a
// summary count per verdict, mirroring write_policy_report_text/write_inventory_report_text's own
// conventions (this project's standing "each engine's report reads like every other engine's
// report" posture).
//
// `symbolic_addresses` (default off, the `baseline check --symbolic-addresses` CLI flag): when true,
// also renders a Step7-notation line (s7_range_notation, s7comm.hpp) alongside a NewTargetRange
// finding's existing raw numeric observed/baseline ranges, for `protocol == "s7comm"` findings only
// -- every other protocol's rendering is completely unaffected, on or off. Off by default so
// existing output/tests are unaffected unless a caller opts in.
void write_baseline_check_report_text(std::ostream& out, const BaselineCheckReport& report,
                                       bool symbolic_addresses = false);

// Renders `report` as JSON to `out`, for scripting/automation -- omits a field entirely (never
// `null`) when it doesn't apply, exactly like write_policy_report_json/write_inventory_report_json.
// `symbolic_addresses`: see write_baseline_check_report_text's own comment above -- adds
// "observed_range_symbolic"/"baseline_ranges_symbolic" fields alongside the existing numeric ones,
// s7comm NewTargetRange findings only, omitted entirely (not merely empty) when off or inapplicable.
void write_baseline_check_report_json(std::ostream& out, const BaselineCheckReport& report,
                                       bool symbolic_addresses = false);

}  // namespace conduitscope
