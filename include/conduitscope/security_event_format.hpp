// SPDX-License-Identifier: Apache-2.0
// security_event_format.hpp - shared CEF/LEEF/syslog line-rendering primitives for the three
// report engines that export curated security findings: `policy validate` (policy_engine.hpp),
// `baseline check` (baseline.hpp), and `detect` (detect_engine.hpp). Grok gap #8's own "Integrate
// instead of replacing the stack" ask (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md item
// 8), the second half after the Zeek conn.log export (output.hpp's own ZeekWriter): curated-
// findings-only one-liners, never a per-packet export -- Jurgen's own AskUserQuestion scoping
// decision, exactly mirroring what ZeekWriter's own header comment says about itself NOT being a
// general packet-export format either.
//
// A small, standalone header (mirroring mitre_attack_ics.hpp/notable_it_protocols.hpp's own "a
// handful of free functions multiple engines share, nothing more" posture) rather than living in
// output.hpp: policy_engine.cpp/baseline.cpp/detect_engine.cpp each keep their OWN local copy of
// the trivial json_escape/csv_escape helpers rather than including output.hpp at all (see those
// files' own json_escape definitions, and asset_inventory.hpp's own comment on the same
// convention) -- output.hpp is the per-packet OutputWriter module, a different layer these three
// report engines have deliberately never depended on. CEF/RFC-5424 framing is genuinely more
// involved than a one-off escaper, and getting it subtly wrong in three independently-diverging
// local copies is exactly the kind of silent-drift risk this project's own discipline avoids
// elsewhere -- so this one shared header is a deliberate, narrow exception, not a reversal of that
// convention: it adds no dependency on output.hpp or on any packet-decoding type, only <string>/
// <utility>/<vector>.
//
// Three per-engine `write_..._report_cef/_leef/_syslog` functions are declared alongside each
// engine's own existing `write_..._report_text/_json` (policy_engine.hpp, baseline.hpp,
// detect_engine.hpp) -- deliberately NOT a new cross-cutting "SecurityEvent" adapter type here,
// since the three report shapes (DetectionFinding/FlowReport-family/BaselineFinding) already carry
// everything each format needs, and forcing them through one intermediate struct would just be a
// second, redundant field mapping to keep in sync with the first.
//
// Every format/field choice below was verified against a primary source before implementation,
// matching this project's standing "cite a primary source, verify before implementing" discipline
// for every wire/file format it produces:
//   - CEF: microfocus.com's own "Implementing ArcSight Common Event Format (CEF)" documentation
//     (Chapter 1, header field definitions, escaping rules, and the Severity 0-10 band table).
//   - LEEF: IBM's own "IBM Security QRadar Log Event Extended Format (LEEF) Version 2" guide
//     (header field order, the five-pipe-field form, the default tab extension delimiter).
//   - syslog transport: RFC 5424, https://www.rfc-editor.org/rfc/rfc5424.html (HEADER field order,
//     PRI = facility*8+severity, the facility table -- facility 13 is literally named "log audit"
//     -- NILVALUE "-", and the MSGID field's own stated filtering purpose), fetched directly this
//     session; the "syslog prefix + CEF payload" real-world transport pattern itself cross-checked
//     against NXLog's own CEF-over-syslog integration guide, which shows exactly that shape.
//
// CEF header: "CEF:0|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|
// Severity|Extension" (pipe-delimited through Severity, then space-separated key=value extension
// pairs). Device Vendor is always "conduitscope" (this project names itself the way an open-source
// tool like Zeek or Suricata would); Device Version is conduitscope::kVersion (version.hpp,
// generated from the build's own CONDUITSCOPE_REPORTED_VERSION); Device Product differs per
// subcommand ("conduitscope-detect"/"conduitscope-policy"/"conduitscope-baseline") so a SIEM can
// build one parser/dashboard per subcommand without parsing Device Event Class ID first. Severity
// is CEF's own documented 0-10 integer scale (0-3=Low, 4-6=Medium, 7-8=High, 9-10=Very-High) -- see
// each engine's own write_..._report_cef comment for exactly which finding fields decide it.
//
// LEEF header: "LEEF:2.0|Vendor|Product|Version|EventID|" (five pipe-delimited fields, no explicit
// custom-delimiter sixth field -- this renderer always uses LEEF 2.0's own documented default
// separator, a tab, so the sixth field is omitted exactly as IBM's own guide shows is valid when
// the default is used), then tab-separated key=value extension pairs. LEEF has no standard
// numeric-severity extension key of its own the way CEF does -- `sev` is a de facto QRadar
// convention (0-10, the same scale CEF's own Severity uses, reused here rather than inventing a
// second scale) -- see IBM's own LEEF Version 2 guide.
//
// syslog transport: CEF, never LEEF (see render_rfc5424_line's own comment for why), wrapped in an
// RFC 5424 header: PRI fixed at facility 13 ("log audit" -- the one facility value whose own
// documented meaning is exactly "a curated security/audit finding," this exporter's entire scope)
// combined with a severity derived from the same CEF 0-10 number every other renderer here uses
// (cef_severity_to_rfc5424_severity); VERSION "1"; TIMESTAMP/HOSTNAME/PROCID/STRUCTURED-DATA all
// left at RFC 5424's own NILVALUE "-" (this tool analyzes a capture file, live or offline, with no
// meaningful "device clock" or "device hostname" more honest than the capture's own per-finding
// timestamp -- which, for the two report shapes with no timestamp field at all, PolicyReport/
// BaselineCheckReport, doesn't exist to report; rather than populate TIMESTAMP for `detect` alone
// and NILVALUE it for the other two, this renderer stays consistent and honest across all three
// subcommands, leaving real event timing inside the CEF payload's own start/end extension keys
// where `detect` already has it); APP-NAME fixed "conduitscope"; MSGID the emitting subcommand's
// own name ("detect"/"policy"/"baseline" -- RFC 5424's own stated MSGID purpose, "used to provide
// filtering of messages on a relay or collector," fits per-subcommand routing exactly).
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace conduitscope {

// Escapes a CEF HEADER field (Device Vendor/Product/Version/Device Event Class ID/Name): backslash
// and pipe are each escaped with a backslash, per the CEF spec's own header-escaping table (equals
// signs and spaces need no escaping in header fields).
std::string cef_header_escape(const std::string& s);

// Escapes a CEF EXTENSION value (a key=value pair's value half): backslash and equals sign are each
// escaped with a backslash, and embedded newlines/carriage returns become the two-character literal
// "\n"/"\r" -- per the CEF spec's own extension-escaping table (pipes need no escaping there, unlike
// in header fields -- the two escaping rules are genuinely different, not a copy-paste of one
// another). LEEF's own extension values reuse this same function (its guide documents no escaping
// rules of its own beyond "the delimiter must not appear unescaped," and this tab-delimited
// renderer's chosen delimiter -- see render_leef_line -- never collides with any value this project
// ever produces, so the CEF rule is applied for backslash-safety parity and nothing more).
std::string cef_extension_escape(const std::string& s);

// Maps a CEF/LEEF 0-10 severity integer onto an RFC 5424 0-7 syslog severity, per the CEF spec's own
// documented band boundaries (0-3=Low, 4-6=Medium, 7-8=High, 9-10=Very-High) -- this tool computes
// exactly one severity judgment per finding (each engine's own write_..._report_cef comment says
// how) and derives every format's own scale from that single judgment rather than maintaining a
// second, independently-tunable syslog severity per finding, which could silently drift out of sync
// with the CEF number sitting right next to it in the same line. Never Emergency(0)/Alert(1) (this
// tool never claims an event needs immediate all-hands escalation) and never Informational(6)/
// Debug(7) (everything reaching this exporter already cleared this project's own "curated findings
// only" bar, so even its own Low band is still Notice(5), not mere chatter): Very-High->Critical(2),
// High->Error(3), Medium->Warning(4), Low->Notice(5).
int cef_severity_to_rfc5424_severity(int cef_severity_0_10);

// Renders one CEF line (no trailing newline): "CEF:0|conduitscope|<device_product>|<version>|
// <device_event_class_id>|<name>|<severity>|<space-separated key=value extension pairs>".
// `device_event_class_id`/`name` are escaped with cef_header_escape; `extension_fields`' values are
// escaped with cef_extension_escape (keys are always this project's own fixed ASCII identifiers --
// see each engine's own write_..._report_cef, never packet-derived -- so keys are never escaped).
std::string render_cef_line(const std::string& device_product, const std::string& device_event_class_id,
                             const std::string& name, int severity_0_10,
                             const std::vector<std::pair<std::string, std::string>>& extension_fields);

// Renders one LEEF 2.0 line (no trailing newline): "LEEF:2.0|conduitscope|<device_product>|
// <version>|<event_id>|<tab-separated key=value extension pairs>" (the default tab delimiter, no
// explicit sixth delimiter-override field -- see this file's own header comment). `event_id` is
// escaped with cef_header_escape (LEEF's own guide states no header-escaping rules of its own;
// reused for the same backslash/pipe safety CEF's header fields need); extension values are escaped
// with cef_extension_escape (see that function's own comment for why LEEF reuses it).
std::string render_leef_line(const std::string& device_product, const std::string& event_id,
                              const std::vector<std::pair<std::string, std::string>>& extension_fields);

// Wraps `cef_payload` (a render_cef_line result) in an RFC 5424 syslog header -- never LEEF, which
// has no standard syslog-transport convention of its own the way CEF's real-world usage does (IBM's
// own LEEF guide describes LEEF as a QRadar-specific *file* format with syslog as one OPTIONAL
// transport among several, with no documented header-field convention the way CEF's own ecosystem
// has converged on; CEF's is the one this project can cite a primary, verifiable convention for --
// see this file's own header comment). `severity_0_10` uses the same CEF 0-10 scale every other
// renderer here does, translated via cef_severity_to_rfc5424_severity; `msgid` is the emitting
// subcommand's own name ("detect"/"policy"/"baseline").
std::string render_rfc5424_line(int severity_0_10, const std::string& msgid, const std::string& cef_payload);

}  // namespace conduitscope
