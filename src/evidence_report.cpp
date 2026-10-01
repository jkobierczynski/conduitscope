// SPDX-License-Identifier: Apache-2.0
// evidence_report.cpp - see evidence_report.hpp's own file header for the full design record
// (Jurgen's request, the "assemble, don't reimplement" decision, and the framework-mapping honesty
// posture this file exists to uphold).
#include "conduitscope/evidence_report.hpp"

#include <cstdio>
#include <ostream>
#include <sstream>

#include "conduitscope/byteio.hpp"
#include "conduitscope/hkdf.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/sha256.hpp"
#include "conduitscope/time_format.hpp"

namespace conduitscope {

std::string sha256_hex(const std::vector<uint8_t>& data) {
    uint8_t digest[32];
    sha256(data.empty() ? nullptr : data.data(), data.size(), digest);
    return to_hex(ByteSpan(digest, 32), "");
}

namespace {

// Each report writer in this codebase keeps its own local json_escape/format_epoch_seconds rather
// than sharing one across translation units -- see detect_engine.cpp's own identical pair and its
// own comment on why.
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string format_epoch_seconds(double ts) {
    return format_timestamp(ts, TimeFormat::AbsoluteDate, TimeOffset{}, ts, ts);
}

// HMAC-SHA256(key, data), hex-encoded -- the second caller of hkdf.hpp's hmac_sha256 (the first,
// and until now the only one, is QUIC's Initial-packet key derivation; see this file's own header
// comment and hkdf.hpp's updated file header).
std::string hmac_sha256_hex(const std::vector<uint8_t>& key, const std::string& data) {
    uint8_t mac[32];
    hmac_sha256(key.empty() ? nullptr : key.data(), key.size(),
                reinterpret_cast<const uint8_t*>(data.data()), data.size(), mac);
    return to_hex(ByteSpan(mac, 32), "");
}

// This tool's own interpretive cross-reference from a DetectionCategory to IEC 62443-3-3
// Foundational Requirements -- NEVER an official conformance determination (see this file's own
// header comment, and the fixed legend text write_evidence_report_text prints immediately before
// using this). FR5 (Restricted Data Flow) is the primary mapping for all four categories, since
// every finding this engine produces is, at bottom, evidence about what crossed which zone boundary
// -- this tool's entire domain. The secondary FR, where one applies, is a deliberately narrow,
// defensible addition, not an attempt to cover every FR a sufuciently motivated reading could argue
// for.
const char* secondary_fr_for_category(DetectionCategory category) {
    switch (category) {
        case DetectionCategory::EngineeringStationActivity:
            return "FR2 (Use Control), SR 2.1 -- secondary: this tool cannot itself verify the "
                   "action was authorized, only that it reached this zone";
        case DetectionCategory::FirmwareLogicChange:
            return "FR3 (System Integrity), SR 3.4 -- secondary: software/configuration integrity";
        case DetectionCategory::RemoteAccessChannel:
            return nullptr;  // FR5 alone is already the direct, primary case here -- a new
                              // remote-access session IS a zone-boundary crossing; no secondary FR
                              // adds anything a reader doesn't already get from FR5 itself.
        case DetectionCategory::ProtocolMisuse:
            return "FR3 (System Integrity) -- secondary";
    }
    return nullptr;
}

void write_scope_and_honesty_note(std::ostream& out) {
    out << "SCOPE & HONESTY NOTE\n";
    out << "  This report assembles already-validated conduitscope output (zone/conduit topology, "
           "policy\n";
    out << "  compliance, detection findings, and, optionally, a baseline check) into one package, "
           "plus\n";
    out << "  hashes/timestamps for reproducibility and, optionally, an HMAC-SHA256 integrity "
           "stamp. It is\n";
    out << "  evidence FOR an audit, not a certification, a compliance determination, or a "
           "substitute for a\n";
    out << "  qualified assessor's own judgment. Specifically:\n";
    out << "    - Every finding below already states its own evidence basis (Confirmed = read "
           "directly off\n";
    out << "      the wire; Heuristic = partly inferred, could be wrong) and, where applicable, "
           "novelty\n";
    out << "      (Confirmed New vs. First Occurrence) -- see each section for what those mean.\n";
    out << "    - Framework mappings (FR5/SL-T, NIS2, CIP) below are this tool's own interpretive "
           "cross-\n";
    out << "      references, never official conformance determinations.\n";
    out << "    - \"OBSERVATION INCOMPLETE\"/truncation notes below mean this analysis only "
           "partially\n";
    out << "      observed the capture -- treat those sections as a floor, not a ceiling, on what "
           "actually\n";
    out << "      happened.\n";
    out << "    - Absence of a finding is not proof of absence of the underlying activity -- it "
           "means\n";
    out << "      nothing in this tool's own recognized protocol/pattern set flagged it in this "
           "capture.\n\n";
}

}  // namespace

void write_evidence_report_text(std::ostream& out, const EvidenceReportInputs& in,
                                 const std::vector<uint8_t>& sign_key) {
    // Built into a local buffer, not `out` directly -- the optional HMAC signature below must be
    // computed over exactly this content, so the whole report is assembled first and streamed to
    // `out` (plus the Signature section) only at the very end. See this function's own header
    // comment (evidence_report.hpp) for the "sign everything above the Signature line" convention.
    std::ostringstream body;

    body << "ConduitScope Evidence Pack\n";
    body << "  generated: " << in.generated_at_utc << " UTC\n";
    body << "  tool version: " << in.tool_version << "\n\n";

    write_scope_and_honesty_note(body);

    body << "CAPTURE\n";
    body << "  file: " << in.capture_path << "\n";
    body << "  SHA-256: " << in.capture_sha256_hex << "\n";
    if (in.total_packets > 0) {
        body << "  window: " << format_epoch_seconds(in.capture_first_ts) << " to "
             << format_epoch_seconds(in.capture_last_ts) << " UTC\n";
    }
    body << "  packets: " << in.total_packets << " (" << in.parse_error_packets
         << " could not be decoded at all)\n";
    if (!in.sl_target.empty()) {
        body << "  operator-declared SL target: " << in.sl_target
             << " (echoed verbatim -- see SL-T note below; never computed by this tool)\n";
    } else {
        body << "  operator-declared SL target: (none supplied -- pass --sl-target to have one "
                "echoed here for\n";
        body << "    audit cross-referencing; this tool never computes a Security Level target "
                "from traffic --\n";
        body << "    IEC 62443-3-2 defines SL-T as an organizational risk-assessment output)\n";
    }
    body << "\n";

    // --- Section 1: observed zone/conduit topology -------------------------------------------
    body << "1. OBSERVED ZONE/CONDUIT TOPOLOGY (ground truth from this capture)\n";
    body << "  " << in.inventory->zones.size() << " zone(s), " << in.inventory->conduits.size()
         << " conduit(s), " << in.inventory->assets.size() << " asset(s) observed\n";
    if (in.inventory->observation_truncated) {
        body << "  *** OBSERVATION INCOMPLETE -- this capture hit at least one inventory limit; "
                "the topology\n";
        body << "      below reflects only PART of what the capture actually contains. ***\n";
        for (const std::string& reason : in.inventory->truncation_reasons) body << "    - " << reason << "\n";
    }
    body << "\n  Mermaid diagram (render with any Mermaid-compatible viewer, e.g. "
            "mermaid.live):\n\n";
    {
        std::istringstream diagram(in.inventory_diagram_mermaid);
        std::string line;
        while (std::getline(diagram, line)) body << "    " << line << "\n";
    }
    body << "\n";

    // --- Section 2: policy compliance / FR5 / NIS2 --------------------------------------------
    body << "2. POLICY COMPLIANCE -- IEC 62443 FR5 (Restricted Data Flow) / NIS2 Segmentation "
            "Evidence\n";
    body << "  IEC 62443-3-3 FR5 legend (this tool's own interpretive mapping, not an official "
            "conformance\n";
    body << "  determination -- a qualified assessor must make that call):\n";
    body << "    policy violation below           -> FR5 (RDF), SR 5.1/5.2: a flow crossed a zone "
            "boundary\n";
    body << "                                         this policy does not permit\n";
    body << "  NIS2 Directive (EU) 2022/2555, Article 21(2) cybersecurity risk-management "
            "measures: the\n";
    body << "  topology above and the compliance evidence below are offered as supporting "
            "technical evidence\n";
    body << "  for the network-segmentation/access-control measures an Article 21 risk-management "
            "assessment\n";
    body << "  may rely on. This tool does not determine NIS2 compliance -- confirm which "
            "specific sub-\n";
    body << "  point(s) of Article 21(2) your assessment relies on against your own legal/"
            "compliance guidance.\n\n";
    if (in.policy_report == nullptr) {
        body << "  (no --policy supplied -- no compliance verdict is included; the topology in "
                "Section 1\n";
        body << "   above is still a valid observed-traffic evidence artifact on its own)\n\n";
    } else {
        body << "  policy file: " << in.policy_path << " (" << in.policy->zones.size() << " zone(s), "
             << in.policy->conduits.size() << " conduit(s))\n";
        body << "  SHA-256: " << in.policy_sha256_hex << "\n";
        body << "  result: " << (in.policy_report->compliant() ? "COMPLIANT" : "NON-COMPLIANT") << " ("
             << in.policy_report->violation_count() << " violation(s), "
             << in.policy_report->unclassified_count() << " unclassified flow(s), "
             << in.policy_report->allowed_count() << " allowed)\n";
        if (in.policy_report->observation_truncated) {
            body << "  *** OBSERVATION INCOMPLETE -- see Decoder Confidence section below. A "
                    "COMPLIANT result\n";
            body << "      here is NOT trustworthy until this is resolved. ***\n";
        }
        body << "\n  Full policy validate report follows (flows, violations, unclassified "
                "traffic):\n\n";
        std::ostringstream policy_text;
        write_policy_report_text(policy_text, *in.policy_report, *in.policy, in.capture_path,
                                  in.policy_path, *in.resolver, /*summarize_unclassified=*/true);
        std::istringstream lines(policy_text.str());
        std::string line;
        while (std::getline(lines, line)) body << "    " << line << "\n";
        body << "\n";
    }

    // --- Section 3: detection findings ----------------------------------------------------------
    body << "3. DETECTION FINDINGS -- IEC 62443 FR Mapping\n";
    body << "  Every finding below cites one MITRE ATT&CK for ICS technique and never asserts "
            "malicious\n";
    body << "  intent on its own (see each finding's own evidence/novelty/severity, already "
            "printed below).\n";
    body << "  FR5 (Restricted Data Flow) is this tool's own primary mapping for every category "
            "below, since\n";
    body << "  every finding here is, at bottom, evidence about what crossed which zone boundary. "
            "Secondary FR,\n";
    body << "  where one applies (interpretive, not a conformance determination):\n";
    for (DetectionCategory category : {DetectionCategory::EngineeringStationActivity,
                                        DetectionCategory::FirmwareLogicChange,
                                        DetectionCategory::RemoteAccessChannel,
                                        DetectionCategory::ProtocolMisuse}) {
        const char* secondary = secondary_fr_for_category(category);
        body << "    " << detection_category_name(category) << " -> FR5 (RDF) primary";
        if (secondary) body << "; " << secondary;
        body << "\n";
    }
    body << "\n";
    if (in.detection->observation_truncated) {
        body << "  *** OBSERVATION INCOMPLETE -- see Decoder Confidence section below. ***\n\n";
    }
    body << "  Full detect report follows:\n\n";
    {
        std::ostringstream detect_text;
        write_detection_report_text(detect_text, *in.detection, in.capture_path, *in.resolver);
        std::istringstream lines(detect_text.str());
        std::string line;
        while (std::getline(lines, line)) body << "    " << line << "\n";
        body << "\n";
    }

    // --- Section 4: baseline anomalies (optional) ------------------------------------------------
    body << "4. BASELINE ANOMALIES";
    if (in.baseline == nullptr) {
        body << "\n  (no --baseline-file supplied -- this section is intentionally empty, not "
                "silently\n";
        body << "   omitted: no baseline-deviation claim is being made either way)\n\n";
    } else {
        body << " (" << (in.baseline->compliant() ? "no deviations" : "deviations found") << ")\n";
        if (in.baseline->observation_truncated) {
            body << "  *** OBSERVATION INCOMPLETE -- see Decoder Confidence section below. ***\n";
        }
        body << "\n";
        std::ostringstream baseline_text;
        write_baseline_check_report_text(baseline_text, *in.baseline);
        std::istringstream lines(baseline_text.str());
        std::string line;
        while (std::getline(lines, line)) body << "    " << line << "\n";
        body << "\n";
    }

    // --- Section 5: CIP-007/CIP-015-style monitoring coverage (opt-in) ---------------------------
    // Always print the section 5 header -- matching section 4's own "always number it, explain an
    // absence rather than silently skipping it" convention -- so the report's own section numbering
    // never jumps straight from 4 to 6, which in an audit binder reads like a missing page rather
    // than a section nobody asked for.
    body << "5. CONTINUOUS MONITORING COVERAGE (NERC CIP-007 R4 / CIP-015-style evidence)\n";
    if (!in.cip_monitoring_window) {
        body << "  (not requested -- pass --cip-monitoring-window to add this section; it applies "
                "only to\n";
        body << "   the North American bulk electric system, so most captures have no reason to "
                "carry it)\n\n";
    } else {
        if (in.total_packets >= 2) {
            body << "  capture window: " << format_epoch_seconds(in.capture_first_ts) << " to "
                 << format_epoch_seconds(in.capture_last_ts) << " UTC\n";
            body << "  packets observed: " << in.total_packets << "\n";
            body << "  largest gap between consecutive packets: " << in.max_inter_packet_gap_seconds
                 << "s (ending at " << format_epoch_seconds(in.max_inter_packet_gap_at_ts) << " UTC)\n";
        } else {
            body << "  fewer than 2 packets in this capture -- no meaningful coverage window or "
                    "gap to report\n";
        }
        body << "  This reflects COVERAGE OF THIS CAPTURE FILE ONLY -- it is not, by itself, "
                "proof of\n";
        body << "  continuous monitoring infrastructure uptime, sensor placement adequacy, or "
                "collection-\n";
        body << "  pipeline availability over any period not represented in this file. Treat it "
                "as one input\n";
        body << "  to a CIP-007 R4 / CIP-015 evidence package, not the whole of it.\n\n";
    }

    // --- Section 6: decoder confidence / data-quality notes ---------------------------------------
    body << "6. DECODER CONFIDENCE & DATA-QUALITY NOTES\n";
    body << "  packets in capture: " << in.total_packets << "\n";
    body << "  packets this tool could not decode at all (parse errors): " << in.parse_error_packets;
    if (in.total_packets > 0) {
        double pct = 100.0 * static_cast<double>(in.parse_error_packets) /
                     static_cast<double>(in.total_packets);
        char buf[32];
        std::snprintf(buf, sizeof(buf), " (%.1f%%)", pct);
        body << buf;
    }
    body << "\n";
    {
        size_t heuristic = in.detection->summary.heuristic_evidence;
        size_t total_findings = in.detection->summary.total;
        body << "  detection findings based on partial/heuristic evidence (not read directly off "
                "the wire): "
             << heuristic << " of " << total_findings << "\n";
    }
    bool any_truncation = in.inventory->observation_truncated ||
                           (in.policy_report && in.policy_report->observation_truncated) ||
                           in.detection->observation_truncated ||
                           (in.baseline && in.baseline->observation_truncated);
    if (!any_truncation) {
        body << "  no engine hit a resource/complexity ceiling during this analysis\n";
    } else {
        body << "  at least one engine hit a resource/complexity ceiling -- see that section's own "
                "OBSERVATION\n";
        body << "  INCOMPLETE note above for which one(s) and the specific CLI flag to raise\n";
    }
    body << "\n";

    // --- Section 7: integrity ----------------------------------------------------------------------
    body << "7. INTEGRITY\n";
    body << "  tool version: " << in.tool_version << "\n";
    body << "  report generated: " << in.generated_at_utc << " UTC\n";
    body << "  capture file: " << in.capture_path << "\n";
    body << "    SHA-256: " << in.capture_sha256_hex << "\n";
    if (!in.policy_path.empty()) {
        body << "  policy file: " << in.policy_path << "\n";
        body << "    SHA-256: " << in.policy_sha256_hex << "\n";
    } else {
        body << "  policy file: (none supplied)\n";
    }

    out << body.str();
    if (!sign_key.empty()) {
        std::string signature = hmac_sha256_hex(sign_key, body.str());
        out << "  signature: HMAC-SHA256 " << signature << "\n";
        out << "    verify: recompute HMAC-SHA256, with the same --sign-key file, over this "
               "report's own\n";
        out << "    content from its first line through the line immediately above this "
               "\"signature:\" line\n";
        out << "    (inclusive of that line's own trailing newline), and compare hex digests\n";
    } else {
        out << "  signature: none (no --sign-key given -- this report's own integrity can only be "
               "checked by\n";
        out << "    recomputing the capture/policy hashes above against the original files, not "
               "by verifying\n";
        out << "    this report text itself was unaltered)\n";
    }
}

void write_evidence_report_json(std::ostream& out, const EvidenceReportInputs& in,
                                 const std::vector<uint8_t>& sign_key) {
    std::ostringstream body;
    body << "{\n";
    body << "  \"tool_version\": \"" << json_escape(in.tool_version) << "\",\n";
    body << "  \"generated_at_utc\": \"" << json_escape(in.generated_at_utc) << "\",\n";
    body << "  \"capture\": {\n";
    body << "    \"path\": \"" << json_escape(in.capture_path) << "\",\n";
    body << "    \"sha256\": \"" << in.capture_sha256_hex << "\",\n";
    body << "    \"total_packets\": " << in.total_packets << ",\n";
    body << "    \"parse_error_packets\": " << in.parse_error_packets << ",\n";
    if (in.total_packets > 0) {
        body << "    \"window_start_utc\": \"" << format_epoch_seconds(in.capture_first_ts) << "\",\n";
        body << "    \"window_end_utc\": \"" << format_epoch_seconds(in.capture_last_ts) << "\"\n";
    } else {
        body << "    \"window_start_utc\": null,\n";
        body << "    \"window_end_utc\": null\n";
    }
    body << "  },\n";
    if (!in.sl_target.empty()) {
        body << "  \"operator_declared_sl_target\": \"" << json_escape(in.sl_target) << "\",\n";
    } else {
        body << "  \"operator_declared_sl_target\": null,\n";
    }
    body << "  \"sl_target_note\": \"SL-T is never computed by this tool from traffic -- IEC "
            "62443-3-2 defines it as an organizational risk-assessment output; when non-null above, "
            "it is the operator's own --sl-target value, echoed verbatim\",\n";

    body << "  \"zone_conduit_topology\": {\n";
    body << "    \"zone_count\": " << in.inventory->zones.size() << ",\n";
    body << "    \"conduit_count\": " << in.inventory->conduits.size() << ",\n";
    body << "    \"asset_count\": " << in.inventory->assets.size() << ",\n";
    body << "    \"observation_truncated\": " << (in.inventory->observation_truncated ? "true" : "false")
         << ",\n";
    body << "    \"diagram_mermaid\": \"" << json_escape(in.inventory_diagram_mermaid) << "\"\n";
    body << "  },\n";

    body << "  \"policy_compliance\": ";
    if (in.policy_report == nullptr) {
        body << "null,\n";
    } else {
        body << "{\n";
        body << "    \"iec62443_fr_mapping_note\": \"this tool's own interpretive cross-reference, "
                "not an official conformance determination: a policy violation below maps to FR5 "
                "(Restricted Data Flow), SR 5.1/5.2\",\n";
        body << "    \"nis2_note\": \"supporting technical evidence for NIS2 Directive (EU) "
                "2022/2555 Article 21(2) network-segmentation/access-control measures; this tool "
                "does not determine NIS2 compliance\",\n";
        body << "    \"report\": ";
        std::ostringstream policy_json;
        write_policy_report_json(policy_json, *in.policy_report, *in.policy, in.capture_path,
                                  in.policy_path, *in.resolver);
        body << policy_json.str();
        body << "  },\n";
    }

    body << "  \"detection_findings\": {\n";
    body << "    \"iec62443_fr_mapping_note\": \"this tool's own interpretive cross-reference, not "
            "an official conformance determination: FR5 (Restricted Data Flow) is the primary "
            "mapping for every category; EngineeringStationActivity also maps to FR2 (Use Control) "
            "secondary, FirmwareLogicChange and ProtocolMisuse also map to FR3 (System Integrity) "
            "secondary, RemoteAccessChannel is FR5 alone\",\n";
    body << "    \"report\": ";
    std::ostringstream detect_json;
    write_detection_report_json(detect_json, *in.detection, in.capture_path, *in.resolver);
    body << detect_json.str();
    body << "  },\n";

    body << "  \"baseline_anomalies\": ";
    if (in.baseline == nullptr) {
        body << "null,\n";
    } else {
        std::ostringstream baseline_json;
        write_baseline_check_report_json(baseline_json, *in.baseline);
        body << baseline_json.str();
        body << ",\n";
    }

    body << "  \"cip_monitoring_coverage\": ";
    if (!in.cip_monitoring_window) {
        body << "null,\n";
    } else {
        body << "{\n";
        body << "    \"note\": \"coverage of this capture file only -- not proof of continuous "
                "monitoring infrastructure uptime, sensor placement adequacy, or collection-"
                "pipeline availability over any period not represented in this file\",\n";
        if (in.total_packets >= 2) {
            body << "    \"max_inter_packet_gap_seconds\": " << in.max_inter_packet_gap_seconds << ",\n";
            body << "    \"max_inter_packet_gap_at_utc\": \""
                 << format_epoch_seconds(in.max_inter_packet_gap_at_ts) << "\"\n";
        } else {
            body << "    \"max_inter_packet_gap_seconds\": null,\n";
            body << "    \"max_inter_packet_gap_at_utc\": null\n";
        }
        body << "  },\n";
    }

    body << "  \"decoder_confidence\": {\n";
    body << "    \"heuristic_evidence_findings\": " << in.detection->summary.heuristic_evidence << ",\n";
    body << "    \"total_findings\": " << in.detection->summary.total << ",\n";
    bool any_truncation = in.inventory->observation_truncated ||
                           (in.policy_report && in.policy_report->observation_truncated) ||
                           in.detection->observation_truncated ||
                           (in.baseline && in.baseline->observation_truncated);
    body << "    \"any_engine_observation_truncated\": " << (any_truncation ? "true" : "false") << "\n";
    body << "  },\n";

    if (!in.policy_path.empty()) {
        body << "  \"policy_file\": {\"path\": \"" << json_escape(in.policy_path) << "\", \"sha256\": \""
             << in.policy_sha256_hex << "\"}\n";
    } else {
        body << "  \"policy_file\": null\n";
    }

    // Everything above this point, plus one closing "}\n", is exactly what gets signed when
    // signing is requested -- a complete, valid JSON object with every key EXCEPT signed/
    // signature_algorithm/signature_hex/signature_verification_note themselves (a document can't
    // sign over its own signature). Computed the identical way whether or not signing was actually
    // requested, so a caller who adds --sign-key later gets a signature that verifies against the
    // same bytes an unsigned run would have produced up to this point. Mirrors
    // write_evidence_report_text's identical "sign everything above the Signature line" convention.
    std::string content_to_sign = body.str() + "}\n";
    if (!sign_key.empty()) {
        std::string signature = hmac_sha256_hex(sign_key, content_to_sign);
        body << ",\n  \"signed\": true,\n";
        body << "  \"signature_algorithm\": \"HMAC-SHA256\",\n";
        body << "  \"signature_hex\": \"" << signature << "\",\n";
        body << "  \"signature_verification_note\": \"recompute HMAC-SHA256, with the same "
                "--sign-key file, over this exact JSON object serialized with every key up to and "
                "including policy_file plus one closing brace and newline -- i.e. this document "
                "with the signed/signature_algorithm/signature_hex/signature_verification_note keys "
                "removed entirely -- and compare hex digests\"\n";
    } else {
        body << ",\n  \"signed\": false\n";
    }
    body << "}\n";

    out << body.str();
}

}  // namespace conduitscope
