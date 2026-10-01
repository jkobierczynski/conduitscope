// SPDX-License-Identifier: Apache-2.0
// evidence_report.hpp - the `evidence` subcommand's own report assembly: Jurgen's direct request
// for an audit-binder-ready "evidence pack" produced from one command, covering IEC 62443 FR5
// (Restricted Data Flow)/SL-T, NIS2 Article 21(2) segmentation evidence, an optional NERC CIP-007
// R4/CIP-015-style monitoring-coverage section, and a signed, reproducible integrity record (tool
// version, capture/policy file hashes, an optional HMAC-SHA256 stamp) -- his own words: "Honesty
// about heuristics belongs in that report. Auditors punish silent overclaim more than 'unknown.'"
//
// DELIBERATE DESIGN CHOICE: this does not reimplement zone/conduit/violation/finding rendering.
// `inventory`/`policy validate`/`detect`/`baseline check` already produce exactly this content,
// each independently proven and already covered by its own extensive test suite -- reimplementing
// any of it here would be pure duplication risk for zero new capability. write_evidence_report_text/
// _json instead ASSEMBLE already-existing report-writer output (write_inventory_diagram_mermaid,
// write_policy_report_text/_json, write_detection_report_text/_json, write_baseline_check_report_
// text/_json) behind new compliance-framing language and a new integrity/signature section -- see
// cli_main.cpp's run_evidence for how each sub-report is produced (independent decode passes, one
// per engine, mirroring every other subcommand's own existing per-engine loop; `evidence` is
// offline-capture-only -- no -i/--interface -- since hashing the capture file and running more than
// one independent pass over it both require a static, already-complete file, not a live stream).
//
// FRAMEWORK MAPPING HONESTY (the one area with real overclaim risk -- see Jurgen's own quote
// above): every FR5/SL-T/NIS2/CIP label this file emits is explicitly presented as this tool's own
// interpretive cross-reference, never an official conformance/compliance determination. SL-T
// specifically is NEVER computed from traffic -- IEC 62443-3-2 defines a Security Level TARGET as
// an organizational risk-assessment output, something this passive-monitoring tool has no basis to
// infer; EvidenceReportInputs::sl_target is operator-supplied (--sl-target) and only ever echoed
// back verbatim for cross-referencing, never derived. NERC CIP (North American bulk electric
// system) and NIST SP 800-82 are deliberately NOT mapped here at all -- NIST 800-82 is high-level
// guidance with no discrete numbered-requirement list the way 62443/CIP have, and honestly mapping
// either needs its own separate design pass; CIP-007 R4/CIP-015 get exactly one narrow, literal
// thing this tool CAN honestly state (the capture's own time coverage), behind an explicit opt-in
// flag (cip_monitoring_window) and an equally explicit caveat that capture coverage is not proof of
// continuous monitoring infrastructure uptime. See docs/DEVELOPMENT.md's ROADMAP item for the full
// design record and docs/USER_GUIDE.md's `evidence` section for the user-facing walkthrough.
#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <vector>

#include "conduitscope/asset_inventory.hpp"
#include "conduitscope/baseline.hpp"
#include "conduitscope/detect_engine.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"

namespace conduitscope {

class Resolver;

// SHA-256 of `data`, returned as 64 lowercase hex characters -- a thin wrapper gluing sha256.hpp's
// own from-scratch digest primitive to byteio.hpp's existing to_hex, for hashing a capture or
// policy file's raw bytes into the evidence pack's own integrity section (EvidenceReportInputs
// below). sha256.hpp's own file header previously said it existed for exactly one reason (QUIC
// Initial-packet key derivation) and had "no plan to add one for its own sake" -- this is that
// second, deliberate use: the primitive itself needed no change, only its header comment's own
// "one caller" claim, updated alongside this addition.
std::string sha256_hex(const std::vector<uint8_t>& data);

// Everything write_evidence_report_text/_json need, gathered by run_evidence (cli_main.cpp) from
// up to four independent decode passes (inventory always; policy/baseline each only when the
// corresponding file was supplied) plus whatever file-level metadata (hashes, operator-supplied
// SL-T) doesn't come from decoding at all. Every pointer here is non-owning and must outlive the
// write_evidence_report_* call -- mirrors every other report writer in this codebase (e.g.
// write_detection_report_text's own `const DetectionReport&`), just bundled into one struct since
// this is the one report writer with this many independent sub-reports to assemble at once.
struct EvidenceReportInputs {
    std::string tool_version;        // "conduitscope X.Y.Z" -- see version_string() (cli_main.cpp)
    std::string generated_at_utc;    // this report's own generation time, already formatted (see
                                      // run_evidence's use of format_timestamp/TimeFormat::AbsoluteDate)
    std::string capture_path;
    std::string capture_sha256_hex;  // of the capture file's raw bytes, not of any decoded content
    std::string policy_path;         // empty iff no --policy was given
    std::string policy_sha256_hex;   // empty iff no --policy was given
    std::string sl_target;           // operator-supplied --sl-target, verbatim; empty if not given --
                                      // see this file's own header comment for why this is NEVER
                                      // computed from traffic
    bool cip_monitoring_window = false;  // --cip-monitoring-window: include the CIP-007 R4/CIP-015-
                                          // style capture-coverage section (see this file's header)

    // Capture-wide timing, gathered during the inventory pass (run_evidence) since it already walks
    // every packet in capture order -- the other (optional) passes don't redundantly re-track this.
    double capture_first_ts = 0.0;
    double capture_last_ts = 0.0;
    size_t total_packets = 0;
    size_t parse_error_packets = 0;   // dp.protocol == "parse-error" count, from that same pass --
                                       // decoding is deterministic over the same bytes, so this is
                                       // the same count every other pass would also produce
    double max_inter_packet_gap_seconds = 0.0;   // 0.0 when total_packets < 2
    double max_inter_packet_gap_at_ts = 0.0;     // meaningless when the field above is 0.0

    const AssetInventoryReport* inventory = nullptr;  // always populated by run_evidence
    std::string inventory_diagram_mermaid;            // pre-rendered (write_inventory_diagram_mermaid)

    const Policy* policy = nullptr;             // nullptr iff no --policy was given
    const PolicyReport* policy_report = nullptr; // nullptr iff no --policy was given (always
                                                  // non-null together with `policy` above)

    const DetectionReport* detection = nullptr;  // always populated by run_evidence

    const BaselineCheckReport* baseline = nullptr;  // nullptr iff no --baseline-file was given

    const Resolver* resolver = nullptr;  // always populated -- the same OUI/hostname/service-name
                                          // annotation every other report writer in this codebase
                                          // already threads through
};

// Renders `in` as the full evidence pack, human-readable, to `out`. `sign_key` is the raw bytes of
// the file --sign-key named (read once by run_evidence); an empty vector means no signing was
// requested, in which case the report's own Integrity section says so explicitly rather than
// omitting the section -- see this file's own header comment on honesty over silent omission.
// When non-empty, HMAC-SHA256(sign_key, <this report's own content from its first line through the
// line immediately above the Signature line, inclusive of the final newline before it>) is computed
// and appended as a hex-encoded Signature line, with a one-line recipe for how to independently
// recompute and compare it -- see hkdf.hpp's own hmac_sha256, now a second caller alongside QUIC's.
void write_evidence_report_text(std::ostream& out, const EvidenceReportInputs& in,
                                 const std::vector<uint8_t>& sign_key);

// Same content as write_evidence_report_text, as one JSON object, for a scripted audit pipeline.
// Each sub-report is embedded verbatim as already-produced by its own existing JSON writer (e.g.
// the "policy_compliance" key's value is exactly what write_policy_report_json itself emits) --
// never re-derived from the text rendering, so this can never drift from those writers' own,
// independently-tested schemas. "signed" is always present (true/false), never omitted or null --
// see this file's own header comment on honesty over silent omission; when true, "signature_hex" is
// the same HMAC-SHA256 described above, computed over this object's own serialized bytes up to
// (not including) the "signed"/"signature_hex" keys themselves.
void write_evidence_report_json(std::ostream& out, const EvidenceReportInputs& in,
                                 const std::vector<uint8_t>& sign_key);

}  // namespace conduitscope
