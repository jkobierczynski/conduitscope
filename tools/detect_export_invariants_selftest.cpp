// SPDX-License-Identifier: Apache-2.0
// detect_export_invariants_selftest.cpp - a small, standalone executable (not the `conduitscope`
// CLI itself), modeled directly on tools/live_capture_stats_selftest.cpp's own shape, that
// exercises the four-axis detection finding model's (evidence/novelty/severity/category --
// detect_engine.hpp's own "THREE INDEPENDENT DIMENSIONS..." header comment) cross-export-format
// invariants: docs/reviews/2026-09-chatgpt-security-review-patch257.md section 3.B, "Four-axis
// detection model: preserve the separation of evidence and judgment". Jurgen's own task wording:
// "Test the four-axis finding model's invariants across every export format... what's not yet
// tested is that a JSON to CEF/LEEF/syslog conversion can never silently upgrade a heuristic
// finding into a confirmed one or change its severity." Exact review wording this directly
// implements: "establish explicit invariants in the finding data model and test them across JSON,
// CEF, LEEF, syslog, and any future output formats. In particular, verify that a format conversion
// cannot silently upgrade a heuristic finding into a confirmed finding or change the underlying
// severity judgment."
//
// WHY THIS EXISTS AS ITS OWN TOOL, RATHER THAN MORE PCAP-FIXTURE CTest PASS_REGULAR_EXPRESSION
// ENTRIES (this project's existing convention for `detect --format cef/leef/syslog` coverage --
// see CMakeLists.txt's detect_sample_detect_cef_format/_leef_format/_syslog_format and their own
// sibling comment): those tests already pin real, format-specific snapshots against real captures,
// but every one of them is independently regex-matched per format -- nothing CROSS-CHECKS that
// what JSON says for a given finding is the SAME thing CEF/LEEF/syslog say for that same finding,
// and no single real capture exercises the full cross-product of (evidence x novelty x severity)
// this engine's type system allows (2 x 3 x 3 = 18 combinations) -- real captures only ever
// produce the combinations this codebase's own finding sources happen to construct (e.g. the one
// Heuristic-evidence source, RemoteAccessChannel, only ever carries Moderate severity today), so a
// pcap-fixture-only test can never prove the OTHER 17 combinations stay correctly separated. This
// tool instead constructs a synthetic DetectionReport covering the full cross-product directly
// (DetectionFinding has no construction dependency on packet decoding at all) and calls this
// codebase's own write_detection_report_json/_cef/_leef/_syslog functions on it, then parses each
// rendered format back apart and cross-checks every finding's evidence/novelty/severity against
// what was actually set on the C++ struct (the ground truth) -- not against each other, so a bug
// that moved the same wrong value into every format at once would still be caught.
//
// WHAT THIS AUDIT CONFIRMED ABOUT THE EXISTING ARCHITECTURE (not a defect, but worth recording):
// evidence and novelty are already structurally drift-proof by construction -- JSON's "evidence"/
// "novelty" fields and CEF/LEEF's cs1/cs2 extension fields all call the exact same
// detection_evidence_name()/detection_novelty_name() functions (detect_engine.cpp;
// detection_finding_extension_fields(), the one field-list builder shared by CEF and LEEF, is what
// makes this true for those two formats specifically). There is no second, independent mapping a
// future edit could update inconsistently for those two axes. SEVERITY is the one axis with a
// real, if currently correct, architectural seam: write_detection_report_json (via
// detection_severity_name()) and write_detection_report_cef/_leef/_syslog (via the separate
// detection_severity_to_cef() 0-10 mapping, detect_engine.cpp) are two genuinely independent
// functions over the same DetectionSeverity enum, and detection_severity_to_cef()'s own switch
// falls through to a default `return 2` (Informational's own value) for anything unhandled -- so a
// future DetectionSeverity enumerator added without updating that switch would silently render as
// Informational in CEF/LEEF/syslog while JSON correctly showed its real (new) name: a real, if
// narrow, way severity could silently change across formats. This tool's severity checks are
// therefore the sharpest test here, and are pinned against this codebase's own documented mapping
// (detect_engine.hpp's own write_detection_report_cef doc comment: Critical -> 9, Moderate -> 5,
// Informational -> 2) plus the syslog PRI that mapping produces via
// cef_severity_to_rfc5424_severity() (security_event_format.cpp), rather than against
// detection_severity_to_cef() itself (an anonymous-namespace function this tool cannot call
// directly) -- so a regression in that function's own mapping is exactly what this tool would
// catch, not something it could paper over by re-deriving the same (possibly wrong) answer.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as every other *_selftest tool in this project; wired into CMakeLists.txt's own
// "Detect export-format invariants self-test" section as its own CTest case.
#include <cstdio>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#include "conduitscope/detect_engine.hpp"
#include "conduitscope/resolver.hpp"

namespace {

int g_failures = 0;

void check_bool(const std::string& name, bool ok) {
    if (ok) {
        std::printf("PASS  %s\n", name.c_str());
    } else {
        std::printf("FAIL  %s\n", name.c_str());
        ++g_failures;
    }
}

using conduitscope::DetectionCategory;
using conduitscope::DetectionEvidence;
using conduitscope::DetectionFinding;
using conduitscope::DetectionNovelty;
using conduitscope::DetectionReport;
using conduitscope::DetectionSeverity;

// This codebase's own documented CEF/LEEF severity mapping (detect_engine.hpp's own
// write_detection_report_cef doc comment) -- the independent ground truth this tool checks CEF/
// LEEF/syslog's ACTUAL rendered numbers against, deliberately not read from the production code's
// own (anonymous-namespace, uncallable from here) detection_severity_to_cef().
int expected_cef_severity(DetectionSeverity s) {
    switch (s) {
        case DetectionSeverity::Critical: return 9;
        case DetectionSeverity::Moderate: return 5;
        case DetectionSeverity::Informational: return 2;
    }
    return -1;
}

// security_event_format.cpp's own documented cef_severity_to_rfc5424_severity() mapping, folded
// into the fixed facility-13 PRI render_rfc5424_line() always uses -- see that file's own header
// comment for the facility choice. Independently re-derived here, same reasoning as
// expected_cef_severity() above.
int expected_rfc5424_pri(int cef_severity_0_10) {
    constexpr int kFacilityLogAudit = 13;
    int rfc5424_severity;
    if (cef_severity_0_10 >= 9) {
        rfc5424_severity = 2;
    } else if (cef_severity_0_10 >= 7) {
        rfc5424_severity = 3;
    } else if (cef_severity_0_10 >= 4) {
        rfc5424_severity = 4;
    } else {
        rfc5424_severity = 5;
    }
    return kFacilityLogAudit * 8 + rfc5424_severity;
}

// Returns the N-th (0-based) occurrence of a `"field": "value"` string field in a JSON blob --
// deliberately a tiny hand-rolled scan rather than a real JSON parser: this tool controls the
// exact output of write_detection_report_json (this codebase's own, not a third-party library),
// so a literal-substring scan is both sufficient and keeps this tool dependency-free, matching
// every other *_selftest tool's own self-contained style.
std::string nth_json_string_field(const std::string& json, int occurrence_0_based, const std::string& field) {
    std::string needle = "\"" + field + "\": \"";
    size_t pos = 0;
    for (int i = 0; i <= occurrence_0_based; ++i) {
        pos = json.find(needle, pos);
        if (pos == std::string::npos) return "<missing>";
        pos += needle.size();
        if (i < occurrence_0_based) {
            size_t end = json.find('"', pos);
            if (end == std::string::npos) return "<missing>";
            pos = end + 1;
        }
    }
    size_t end = json.find('"', pos);
    if (end == std::string::npos) return "<missing>";
    return json.substr(pos, end - pos);
}

std::vector<std::string> non_empty_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty()) lines.push_back(line);
    }
    return lines;
}

// Parses CEF/LEEF extension fields by KEY MARKER, not by blindly splitting on the space/tab
// separator -- deliberately, because two of this engine's own real field values contain internal
// spaces ("Confirmed New", "First Occurrence", detection_novelty_name()), and CEF's own spec does
// not escape spaces inside extension values (cef_extension_escape(), security_event_format.cpp,
// only escapes backslash/equals/CR/LF). A naive space-split would wrongly cut "cs2=Confirmed New"
// into two broken tokens; a real downstream CEF/LEEF parser has to scan for the NEXT "<key>="
// marker to find each value's true end, exactly as this function does -- `ordered_keys` is the
// exact, fixed field order this codebase's own detection_finding_extension_fields()
// (detect_engine.cpp) always emits (plus LEEF's own trailing "sev"), so each key's marker is
// searched for strictly after the previous one's, and a value runs up to (but not including) the
// next key's marker.
std::map<std::string, std::string> parse_known_fields(const std::string& extension,
                                                        const std::vector<std::string>& ordered_keys) {
    std::map<std::string, std::string> result;
    std::vector<size_t> positions;
    size_t search_from = 0;
    for (const auto& key : ordered_keys) {
        std::string marker = key + "=";
        size_t pos = extension.find(marker, search_from);
        positions.push_back(pos);
        if (pos != std::string::npos) search_from = pos + marker.size();
    }
    for (size_t i = 0; i < ordered_keys.size(); ++i) {
        if (positions[i] == std::string::npos) continue;
        size_t value_start = positions[i] + ordered_keys[i].size() + 1;
        size_t value_end = extension.size();
        for (size_t j = i + 1; j < ordered_keys.size(); ++j) {
            if (positions[j] != std::string::npos) {
                value_end = positions[j];
                break;
            }
        }
        std::string value = extension.substr(value_start, value_end - value_start);
        // Trim exactly the trailing separator (one space for CEF, one tab for LEEF) that precedes
        // the next key, if a next key followed.
        while (!value.empty() && (value.back() == ' ' || value.back() == '\t')) value.pop_back();
        result[ordered_keys[i]] = value;
    }
    return result;
}

// The exact, fixed extension-field order detection_finding_extension_fields() (detect_engine.cpp)
// emits -- shared by both CEF and LEEF, since that one function builds both formats' field lists.
const std::vector<std::string>& cef_leef_field_order() {
    static const std::vector<std::string> kOrder = {"src",      "dst", "dpt",   "proto", "cat",
                                                      "msg",      "cs1Label", "cs1", "cs2Label",
                                                      "cs2",      "cnt", "start", "end"};
    return kOrder;
}

struct ParsedCef {
    int severity = -1;
    std::map<std::string, std::string> ext;
};

// Splits one CEF line ("CEF:0|conduitscope|<dp>|<ver>|<devid>|<name>|<sev>|<ext...>") into its
// numeric severity and its space-separated extension-field map. Deliberately stops splitting on
// '|' after the 7th one (the header's own field count) rather than continuing -- the extension
// string itself is never split on '|' beyond that point, in case a value happened to contain one
// (none of this tool's own synthetic values do, but the real cef_extension_escape() doesn't escape
// '|' either, so this mirrors how a real downstream CEF parser must behave).
ParsedCef parse_cef_line(const std::string& line) {
    ParsedCef result;
    std::vector<std::string> header_fields;
    size_t start = 0;
    for (int i = 0; i < 7; ++i) {
        size_t pipe = line.find('|', start);
        if (pipe == std::string::npos) {
            header_fields.push_back(line.substr(start));
            start = line.size();
            break;
        }
        header_fields.push_back(line.substr(start, pipe - start));
        start = pipe + 1;
    }
    if (header_fields.size() == 7) {
        try {
            result.severity = std::stoi(header_fields[6]);
        } catch (...) {
            result.severity = -1;
        }
    }
    result.ext = parse_known_fields(line.substr(start), cef_leef_field_order());
    return result;
}

// Same idea for one LEEF line ("LEEF:2.0|conduitscope|<dp>|<ver>|<event_id>|<ext...>", tab-
// separated extension) -- 5 header fields, no positional severity (LEEF carries it only as the
// `sev` extension key, already covered by parse_fields below).
std::map<std::string, std::string> parse_leef_line(const std::string& line) {
    size_t start = 0;
    for (int i = 0; i < 4; ++i) {
        size_t pipe = line.find('|', start);
        if (pipe == std::string::npos) return {};
        start = pipe + 1;
    }
    std::vector<std::string> keys = cef_leef_field_order();
    keys.push_back("sev");  // LEEF's own trailing field, appended after detection_finding_
                             // extension_fields()'s shared list (write_detection_report_leef,
                             // detect_engine.cpp)
    return parse_known_fields(line.substr(start), keys);
}

struct ParsedSyslog {
    int pri = -1;
    ParsedCef cef;
};

// "<PRI>1 - - conduitscope - detect - <cef_payload>" -- extracts PRI and re-parses the embedded
// CEF payload with parse_cef_line above, so a syslog line's own evidence/novelty/severity get the
// exact same cross-check as a standalone CEF line's.
ParsedSyslog parse_syslog_line(const std::string& line) {
    ParsedSyslog result;
    if (line.empty() || line[0] != '<') return result;
    size_t close = line.find('>');
    if (close == std::string::npos) return result;
    try {
        result.pri = std::stoi(line.substr(1, close - 1));
    } catch (...) {
        result.pri = -1;
    }
    size_t cef_pos = line.find("CEF:0|", close);
    if (cef_pos == std::string::npos) return result;
    result.cef = parse_cef_line(line.substr(cef_pos));
    return result;
}

}  // namespace

int main() {
    using conduitscope::detection_evidence_name;
    using conduitscope::detection_novelty_name;
    using conduitscope::detection_severity_name;
    using conduitscope::mitre_t0858_change_operating_mode;
    using conduitscope::Resolver;
    using conduitscope::write_detection_report_cef;
    using conduitscope::write_detection_report_json;
    using conduitscope::write_detection_report_leef;
    using conduitscope::write_detection_report_syslog;

    const DetectionEvidence evidences[] = {DetectionEvidence::Confirmed, DetectionEvidence::Heuristic};
    const DetectionNovelty novelties[] = {DetectionNovelty::NotApplicable, DetectionNovelty::ConfirmedNew,
                                           DetectionNovelty::FirstOccurrence};
    const DetectionSeverity severities[] = {DetectionSeverity::Critical, DetectionSeverity::Moderate,
                                             DetectionSeverity::Informational};

    // Build one finding per (evidence x novelty x severity) combination -- the full 2x3x3 = 18-
    // member cross-product this engine's type system allows, regardless of whether any real
    // finding source in this codebase happens to produce that exact combination today (see this
    // file's own header comment for why that matters).
    DetectionReport report;
    std::vector<DetectionEvidence> combo_evidence;
    std::vector<DetectionNovelty> combo_novelty;
    std::vector<DetectionSeverity> combo_severity;
    int idx = 0;
    for (DetectionEvidence e : evidences) {
        for (DetectionNovelty n : novelties) {
            for (DetectionSeverity s : severities) {
                DetectionFinding f;
                f.category = DetectionCategory::ProtocolMisuse;
                f.technique = mitre_t0858_change_operating_mode();
                f.evidence = e;
                f.novelty = n;
                f.severity = s;
                f.client_ip = "10.0.0." + std::to_string(idx);
                f.server_ip = "10.0.1." + std::to_string(idx);
                f.protocol = "synthetic";
                f.server_port = 502;
                f.description = "synthetic cross-format invariant check combination " + std::to_string(idx);
                f.first_seen = 1700000000.0 + idx;
                f.last_seen = 1700000000.0 + idx;
                f.packet_count = 1;
                report.findings.push_back(f);
                combo_evidence.push_back(e);
                combo_novelty.push_back(n);
                combo_severity.push_back(s);
                ++idx;
            }
        }
    }
    const int kComboCount = idx;  // 18

    std::vector<std::string> notes;
    Resolver resolver(/*oui_enabled=*/false, /*resolve_hostnames=*/false, /*hosts_path=*/"",
                       /*service_names_enabled=*/false, /*services_path=*/"", notes);

    std::ostringstream json_stream, cef_stream, leef_stream, syslog_stream;
    write_detection_report_json(json_stream, report, "synthetic", resolver);
    write_detection_report_cef(cef_stream, report);
    write_detection_report_leef(leef_stream, report);
    write_detection_report_syslog(syslog_stream, report);
    std::string json_text = json_stream.str();
    std::vector<std::string> cef_lines = non_empty_lines(cef_stream.str());
    std::vector<std::string> leef_lines = non_empty_lines(leef_stream.str());
    std::vector<std::string> syslog_lines = non_empty_lines(syslog_stream.str());

    check_bool("CEF renders exactly one line per finding (no dropped/duplicated findings)",
               static_cast<int>(cef_lines.size()) == kComboCount);
    check_bool("LEEF renders exactly one line per finding (no dropped/duplicated findings)",
               static_cast<int>(leef_lines.size()) == kComboCount);
    check_bool("syslog renders exactly one line per finding (no dropped/duplicated findings)",
               static_cast<int>(syslog_lines.size()) == kComboCount);
    if (static_cast<int>(cef_lines.size()) != kComboCount || static_cast<int>(leef_lines.size()) != kComboCount ||
        static_cast<int>(syslog_lines.size()) != kComboCount) {
        std::printf("\nFATAL: line counts don't match finding count -- aborting before an out-of-bounds "
                    "access rather than risk a false PASS below\n");
        return 1;
    }

    // The headline invariant, checked once up front in its own unambiguous form (patch257's own
    // wording: "cannot silently upgrade a heuristic finding into a confirmed finding"): across
    // every one of the 9 Heuristic-evidence combinations, CEF's and LEEF's own cs1 field must say
    // "Heuristic", literally never "Confirmed" -- and symmetrically for every Confirmed-evidence
    // combination.
    bool any_heuristic_shown_as_confirmed = false;
    bool any_confirmed_shown_as_heuristic = false;
    bool any_severity_silently_changed = false;
    for (int i = 0; i < kComboCount; ++i) {
        std::string expected_evidence = detection_evidence_name(combo_evidence[i]);
        std::string expected_novelty = detection_novelty_name(combo_novelty[i]);
        std::string expected_severity_name = detection_severity_name(combo_severity[i]);
        int expected_sev_num = expected_cef_severity(combo_severity[i]);
        int expected_pri = expected_rfc5424_pri(expected_sev_num);

        std::string json_evidence = nth_json_string_field(json_text, i, "evidence");
        std::string json_novelty = nth_json_string_field(json_text, i, "novelty");
        std::string json_severity = nth_json_string_field(json_text, i, "severity");

        ParsedCef cef = parse_cef_line(cef_lines[i]);
        std::map<std::string, std::string> leef = parse_leef_line(leef_lines[i]);
        ParsedSyslog syslog = parse_syslog_line(syslog_lines[i]);

        if (combo_evidence[i] == DetectionEvidence::Heuristic &&
            (cef.ext["cs1"] == "Confirmed" || leef["cs1"] == "Confirmed" || syslog.cef.ext["cs1"] == "Confirmed")) {
            any_heuristic_shown_as_confirmed = true;
        }
        if (combo_evidence[i] == DetectionEvidence::Confirmed &&
            (cef.ext["cs1"] == "Heuristic" || leef["cs1"] == "Heuristic" || syslog.cef.ext["cs1"] == "Heuristic")) {
            any_confirmed_shown_as_heuristic = true;
        }
        if (cef.severity != expected_sev_num || syslog.pri != expected_pri) {
            any_severity_silently_changed = true;
        }

        std::string label = "combination " + std::to_string(i) + " (" + expected_evidence + "/" +
                             expected_novelty + "/" + expected_severity_name + ")";
        bool ok = json_evidence == expected_evidence && json_novelty == expected_novelty &&
                  json_severity == expected_severity_name && cef.ext["cs1"] == expected_evidence &&
                  cef.ext["cs2"] == expected_novelty && cef.severity == expected_sev_num &&
                  leef["cs1"] == expected_evidence && leef["cs2"] == expected_novelty &&
                  leef["sev"] == std::to_string(expected_sev_num) && syslog.pri == expected_pri &&
                  syslog.cef.ext["cs1"] == expected_evidence && syslog.cef.ext["cs2"] == expected_novelty &&
                  syslog.cef.severity == expected_sev_num;
        check_bool("JSON/CEF/LEEF/syslog agree on evidence+novelty+severity for " + label, ok);
    }

    check_bool(
        "no Heuristic-evidence finding is ever rendered as cs1=Confirmed in CEF/LEEF/syslog, across all 9 "
        "Heuristic combinations",
        !any_heuristic_shown_as_confirmed);
    check_bool(
        "no Confirmed-evidence finding is ever rendered as cs1=Heuristic in CEF/LEEF/syslog, across all 9 "
        "Confirmed combinations",
        !any_confirmed_shown_as_heuristic);
    check_bool(
        "no finding's severity is ever rendered differently in CEF's numeric severity or syslog's PRI than "
        "this codebase's own documented Critical=9/Moderate=5/Informational=2 mapping, across all 18 "
        "combinations",
        !any_severity_silently_changed);

    // One more targeted check in the review's own exact words: an Informational-severity finding
    // (the "weakest" band) must never render with a CEF/LEEF severity number, or a syslog PRI,
    // that a downstream SIEM would read as more urgent than Critical or Moderate findings' own
    // numbers -- i.e. severity ordering itself survives every format, not just each individual
    // value.
    bool severity_ordering_preserved = true;
    for (int i = 0; i < kComboCount; ++i) {
        ParsedCef cef = parse_cef_line(cef_lines[i]);
        if (combo_severity[i] == DetectionSeverity::Informational && cef.severity >= expected_cef_severity(DetectionSeverity::Moderate)) {
            severity_ordering_preserved = false;
        }
        if (combo_severity[i] == DetectionSeverity::Moderate && cef.severity >= expected_cef_severity(DetectionSeverity::Critical)) {
            severity_ordering_preserved = false;
        }
    }
    check_bool("severity ordering (Informational < Moderate < Critical) survives CEF's numeric encoding",
               severity_ordering_preserved);

    std::printf("\n%s\n", g_failures == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return g_failures == 0 ? 0 : 1;
}
