// SPDX-License-Identifier: Apache-2.0
// inventory_merge.hpp - combines N separately-produced `inventory --format json` reports (one per
// tap point of a multi-tap site) into one site-wide asset/conduit matrix. The `merge` subcommand's
// implementation (cli_main.cpp) -- see docs/design/sensor-mode.md for the full design record:
// this is the "multiple-simultaneous-tap-point stitching into one site-wide matrix" half of Grok
// review item 5 (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md), scoped, per Jurgen's
// "independent per-tap processes + merge subcommand" decision, to combining N independent
// `inventory` reports produced by N independent, single-interface `capture`/`inventory` runs --
// never one process holding multiple live captures open at once (see rotating_pcap_writer.hpp's
// file header for the capture-side half of that same decision).
//
// SCOPE: inventory reports only. A site's `policy validate`/`detect`/`baseline` reports are each a
// structurally different merge problem (a policy report is pass/fail against a shared, already
// site-wide policy file, not a per-tap discovery; a detect/baseline report's "new vs. known"
// judgment doesn't obviously compose across taps that each saw only part of a conversation) --
// each is a reasonable, structurally similar follow-up, deliberately not attempted in this same
// pass, the same "explicit, stated boundary, not a silent gap" convention this codebase uses
// throughout (e.g. asset_inventory.hpp's file header on which protocols it does and doesn't
// count).
//
// FURTHER SCOPE, within inventory merging itself, kept deliberately simple and deterministic (see
// docs/design/sensor-mode.md for why, tracing back to Jurgen's "keep the mechanisms simple and
// deterministic" instruction from an earlier session):
//   - InventoryEdge::top_touched_addresses (a per-edge top-N by touch count) is NOT merged --
//     merging two truncated top-N lists into a correct combined top-N would need each input's own
//     FULL per-address touch-count map, which the JSON report never carries (only the already-
//     truncated top N plus a total-distinct count) -- there is no way to reconstruct the true
//     merged ranking from that alone. A merged edge's top_touched_addresses is always empty
//     (touched_addresses_total_distinct 0, touched_addresses_truncated false); read each input's
//     own report directly for that detail.
//   - InventoryAsset::inferred_role is NOT recomputed globally from the merged, site-wide edge set
//     -- each input's already-computed role (from InventoryAsset::inferred_role, first non-
//     "Unknown" occurrence across inputs winning for a given IP) is kept as-is. Recomputing the
//     same heuristic (asset_inventory.cpp's infer_asset_role, not exported from that
//     translation unit) globally, across every tap's combined edges, is a reasonable follow-up,
///    not attempted here.
//   - AssetInventoryReport::notable_protocols (ROADMAP item 18's "IT protocols an OT auditor
//     flags") is NOT merged -- always empty in a merged report. Each input's own report still has
//     its own list; this is the same kind of explicitly-out-of-scope simplification as the two
//     above, not an oversight.
//   - InventoryAsset::ever_client/ever_server are NOT read from the input JSON (write_inventory_
//     report_json never emits them -- only the derived "role"/"inferred_role" text fields) --
//     recomputed instead from the merged, deduplicated edge set itself (an IP is ever_client if it
//     is any merged edge's client_ip, ever_server if it is any merged edge's server_ip), which is
//     both correct and strictly simpler than trying to recover them from report text.
#pragma once

#include <stdexcept>
#include <string>
#include <vector>

#include "conduitscope/asset_inventory.hpp"

namespace conduitscope {

// Thrown by parse_inventory_report_json_for_merge on anything that isn't a well-formed JSON
// document, or is missing a field this merge actually needs (ip/client_ip/server_ip/protocol/
// server_port) -- distinct from BaselineStoreError/PolicyError, matching this codebase's
// per-feature exception-type convention (each parseable file format gets its own error type).
// Also thrown by read_inventory_report_file_for_merge below on a file I/O or size-ceiling
// failure -- a plain "which file broke" error, not a dedicated sub-type, matching
// BaselineStoreError's own precedent of folding its load_baseline_store's I/O errors into the
// same type as its parse errors.
class InventoryMergeError : public std::runtime_error {
public:
    explicit InventoryMergeError(const std::string& message) : std::runtime_error(message) {}
};

// Compiled-in default for read_inventory_report_file_for_merge's own max_file_bytes parameter
// below. Fixes docs/reviews/2026-09-chatgpt-security-review-patch282.md's finding 5 (item 122,
// docs/DEVELOPMENT.md): before this, `merge inventory`'s file-reading loop (run_merge_inventory,
// cli_main.cpp) read each input completely into memory -- `std::ostringstream buf; buf <<
// in.rdbuf();` -- with no ceiling at all, exactly the same shape item 68 (patch209 finding 5)
// already fixed for the baseline engine's own load_baseline_store. An inventory JSON report is,
// like a baseline file, a local trust boundary rather than wire-reachable the way a pcap is (the
// operator explicitly names these files on the command line) -- but merge is explicitly an
// analysis boundary where an operator may be asked to combine reports generated by OTHER systems/
// teams/tap points, not only ones this build itself produced, so a corrupted, truncated, or
// maliciously substituted input should still be rejected before allocation rather than exhaust
// memory first. Reuses the exact same 256 MiB figure as kDefaultMaxBaselineFileBytes
// (baseline.hpp) for the same reason that constant gives: generous enough that no legitimate
// report -- even a large, multi-thousand-asset, multi-tap site's -- should ever approach it, so
// only a file engineered or corrupted to be far larger should ever hit it.
inline constexpr size_t kDefaultMaxInventoryFileBytes = 256u * 1024u * 1024u;  // 256 MiB

// Reads the file at `path` and parses it the same way parse_inventory_report_json_for_merge
// does, but checks its size against `max_file_bytes` BEFORE reading it into memory -- mirroring
// load_baseline_store's own size-ceiling-before-read pattern (baseline.hpp/.cpp) exactly. Throws
// InventoryMergeError if `path` can't be opened, its size can't be determined, its size exceeds
// `max_file_bytes` (the error names the exact byte count, the limit, and the
// --max-inventory-file-bytes override flag), a read error occurs, or its content doesn't parse
// (see parse_inventory_report_json_for_merge). Unlike load_baseline_store, a missing file is
// always an error here, never a fresh-empty-report fallback -- `merge inventory` has no
// equivalent "reads the file if present" first-run contract to preserve, and the CLI layer
// itself already requires every input to exist (CLI::ExistingFile) before this is ever called.
AssetInventoryReport read_inventory_report_file_for_merge(const std::string& path,
                                                           size_t max_file_bytes = kDefaultMaxInventoryFileBytes);

// Reads back only what a merge actually needs from one `inventory --format json` report:
// total_packets/skipped_packets, and, per asset/edge, every field merge_inventory_reports below
// combines -- see this header's file comment for the fields deliberately NOT read (zones/
// conduits are ignored entirely and always re-derived; notable_protocols is ignored; top_touched_
// addresses is ignored). Tolerant of any OTHER key inside an asset/edge/top-level object it
// doesn't recognize (silently skipped) -- unlike baseline.cpp's JsonCursor-based parser, which
// deliberately rejects an unrecognized field because a baseline file is this codebase's own sole
// writer's exact fixed schema: an inventory report can legitimately carry extra, purely
// resolver-derived fields (hostname/mac_vendor/server_port_service/client_hostname/
// server_hostname/port_service -- see write_inventory_report_json's comments) depending on
// whether the report that produced it was run with --resolve/--mac-vendor/--services, none of
// which this merge needs back. Throws InventoryMergeError on malformed JSON or a missing field
// this merge actually needs.
AssetInventoryReport parse_inventory_report_json_for_merge(const std::string& text);

// Combines `reports` (already parsed, in the order they should be considered for "first occurrence
// wins" tie-breaking -- see this header's file comment) into one site-wide AssetInventoryReport:
//   - assets: unioned by IP. protocols: unioned, sorted. packet_count: summed. first_seen: earliest
//     across every input that observed this IP; last_seen: latest. mac/vendor/product/
//     firmware_revision/serial_number/security_posture/plant_identification/inferred_role: first
//     non-empty ("Unknown" counts as empty for inferred_role specifically) value across inputs, in
//     input order, wins -- an IP seen by more than one tap (uncommon, but not invalid: e.g. a
//     shared historian both taps can see) keeps whichever input happened to observe/report that
//     identity detail first, rather than trying to adjudicate a conflict between two taps' own
//     passive observations.
//   - edges: unioned by (client_ip, server_ip, protocol, server_port). observed_functions: unioned,
//     sorted. packet_count: summed. first_seen/last_seen: earliest/latest. direction_source: the
//     MOST AUTHORITATIVE of every input's value for this edge (Handshake beats Content beats
//     PortHeuristic -- see DirectionSource's comment, decoder.hpp) -- a genuine, if partial,
//     recomputation, not just "first wins", since a later tap's more-authoritative observation
//     of the SAME edge (e.g. one tap caught the TCP handshake, another only saw mid-session
//     traffic) should win regardless of input order.
//   - ever_client/ever_server, zones, and conduits are entirely RE-DERIVED from the merged
//     assets/edges above, using `zone_prefix_len` (independent of whatever --zone-prefix value, if
//     any, each individual input report was generated with) -- the exact same grouping
//     AssetInventoryEngine::finish itself uses (asset_inventory.cpp), reimplemented here against
//     already-merged data rather than shared, since this operates on parsed JSON, not a live
//     AssetInventoryEngine instance.
//   - total_packets/skipped_packets: summed across every input.
// `reports` may be empty (returns a report with everything empty/zero) -- the CLI layer itself
// requires at least one input file, but this function imposes no such requirement of its own.
AssetInventoryReport merge_inventory_reports(const std::vector<AssetInventoryReport>& reports,
                                              uint8_t zone_prefix_len);

}  // namespace conduitscope
