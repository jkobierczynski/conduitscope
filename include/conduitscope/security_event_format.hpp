// SPDX-License-Identifier: Apache-2.0
// security_event_format.hpp - shared CEF/LEEF/syslog line-rendering primitives for the three
// report engines that export curated security findings: `policy validate` (policy_engine.hpp),
// `baseline check` (baseline.hpp), and `detect` (detect_engine.hpp). Grok gap #8's own "Integrate
// instead of replacing the stack" ask (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md item
// 8), the second half after the Zeek conn.log export (output.hpp's own ZeekWriter): curated-
// findings-only one-liners, never a per-packet export -- Jurgen's own AskUserQuestion scoping
// decision.
//
// A small, standalone header (mirroring mitre_attack_ics.hpp/notable_it_protocols.hpp's "a
// handful of free functions multiple engines share" posture) rather than living in output.hpp:
// policy_engine.cpp/baseline.cpp/detect_engine.cpp each keep their own local copy of the trivial
// json_escape/csv_escape helpers rather than including output.hpp (the per-packet OutputWriter
// module, a layer these three report engines have deliberately never depended on). CEF/RFC-5424
// framing is more involved than a one-off escaper, and three independently-diverging local copies
// risk silent drift -- so this one shared header is a deliberate, narrow exception to that
// convention, adding no dependency on output.hpp or any packet-decoding type.
//
// Three per-engine `write_..._report_cef/_leef/_syslog` functions are declared alongside each
// engine's own existing `write_..._report_text/_json` -- deliberately not a cross-cutting
// "SecurityEvent" adapter type, since the three report shapes already carry everything each
// format needs, and an intermediate struct would just be a second, redundant field mapping.
//
// Every format/field choice below was verified against a primary source before implementation:
//   - CEF: microfocus.com's "Implementing ArcSight Common Event Format (CEF)" documentation
//     (header field definitions, escaping rules, the Severity 0-10 band table).
//   - LEEF: IBM's "IBM Security QRadar Log Event Extended Format (LEEF) Version 2" guide
//     (header field order, the five-pipe-field form, the default tab extension delimiter).
//   - syslog transport: RFC 5424 (header field order, PRI = facility*8+severity, the facility
//     table -- facility 13 is literally named "log audit" -- NILVALUE "-", MSGID's stated
//     filtering purpose); the "syslog prefix + CEF payload" transport pattern cross-checked
//     against NXLog's own CEF-over-syslog integration guide.
//
// CEF header: "CEF:0|Device Vendor|Device Product|Device Version|Device Event Class ID|Name|
// Severity|Extension". Device Vendor is always "conduitscope"; Device Version is
// conduitscope::kVersion; Device Product differs per subcommand
// ("conduitscope-detect"/"conduitscope-policy"/"conduitscope-baseline") so a SIEM can build one
// parser/dashboard per subcommand without parsing Device Event Class ID first.
//
// LEEF header: "LEEF:2.0|Vendor|Product|Version|EventID|", then tab-separated key=value pairs --
// LEEF 2.0's own default delimiter, so no explicit sixth delimiter-override field. LEEF has no
// standard severity key of its own; `sev` is a de facto QRadar convention reusing CEF's 0-10
// scale rather than inventing a second one.
//
// syslog transport: CEF, never LEEF (LEEF's own guide describes it as a QRadar-specific file
// format with syslog as one optional transport among several, with no documented header
// convention the way CEF's real-world ecosystem has converged on). PRI fixed at facility 13
// ("log audit"); TIMESTAMP/HOSTNAME/PROCID/STRUCTURED-DATA all RFC 5424's own NILVALUE "-" (this
// tool has no device clock or hostname more honest to report for an offline capture-file
// analysis, and two of the three report shapes carry no per-finding timestamp at all -- `detect`'s
// own timing still lives in the CEF payload's own start/end extension keys); APP-NAME fixed
// "conduitscope"; MSGID the emitting subcommand's own name.
//
// See each function's own comment below for exact severity-scale and field-mapping details.
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace conduitscope {

// Escapes a CEF HEADER field (Device Vendor/Product/Version/Device Event Class ID/Name):
// backslash and pipe are each escaped with a backslash, per the CEF spec's header-escaping table
// (equals signs and spaces need no escaping in header fields).
std::string cef_header_escape(const std::string& s);

// Escapes a CEF EXTENSION value: backslash and equals sign are each escaped with a backslash,
// and embedded newlines/carriage returns become the literal "\n"/"\r" -- per the CEF spec's
// extension-escaping table (pipes need no escaping here, unlike in header fields). CEF's own
// extension delimiter is a space, which this function deliberately leaves unescaped (CEF's spec
// doesn't require it); use leef_extension_escape below for LEEF's tab-delimited extension values
// instead of this function -- see that function's own comment for why they're no longer the same
// escaper.
std::string cef_extension_escape(const std::string& s);

// Escapes a LEEF 2.0 EXTENSION value: same four cases as cef_extension_escape (backslash, equals,
// newline, carriage return) plus a fifth this function adds -- an embedded horizontal tab becomes
// the literal "\t" -- because LEEF's default extension delimiter (render_leef_line's own field
// separator) IS a literal tab, unlike CEF's space. An unescaped tab inside a value would corrupt
// a downstream SIEM's field boundaries (patch257 security review, finding 1 -- confirmed against
// this project's own source: cef_extension_escape had no tab case at all, and
// PolicyEngine::client_zone/server_zone -- operator-authored zone names straight from the policy
// YAML, unsanitized beyond a uniqueness check -- are exactly the kind of free-text value LEEF's
// "msg"/cs1/cs2 extension fields carry through unchanged).
//
// LEEF's own guide documents no escaping convention of its own for a delimiter appearing inside a
// value -- verified this session against IBM's LEEF Version 2 guide, NXLog's LEEF integration
// guide ("the documentation does not address what should happen if a delimiter character appears
// within a value itself"), and IBM's own QRadar app framework "Generating LEEF events" tutorial
// (documents a header-level DelimiterCharacter override, i.e. picking a delimiter unlikely to
// collide, but no value-escaping rule). Absent a citable spec convention, this function extends
// this project's own already-established CEF-style backslash-letter escaping with one more case,
// rather than inventing an unrelated scheme -- CEF itself is intentionally left untouched
// (cef_extension_escape keeps exactly matching its own spec) since CEF's space delimiter was never
// the vulnerable part.
std::string leef_extension_escape(const std::string& s);

// Maps a CEF/LEEF 0-10 severity onto an RFC 5424 0-7 syslog severity, per CEF's own band
// boundaries (0-3=Low, 4-6=Medium, 7-8=High, 9-10=Very-High). Derived from the same severity
// judgment CEF/LEEF already carry, rather than a second, independently-tunable number that could
// drift out of sync. Never Emergency(0)/Alert(1) (no finding here needs immediate escalation) or
// Informational(6)/Debug(7) (everything here already cleared the "curated findings only" bar):
// Very-High->Critical(2), High->Error(3), Medium->Warning(4), Low->Notice(5).
int cef_severity_to_rfc5424_severity(int cef_severity_0_10);

// Renders one CEF line (no trailing newline): "CEF:0|conduitscope|<device_product>|<version>|
// <device_event_class_id>|<name>|<severity>|<space-separated key=value extension pairs>".
// `device_event_class_id`/`name` are escaped with cef_header_escape; extension values with
// cef_extension_escape (extension keys are this project's own fixed ASCII identifiers, never
// packet-derived, so they're never escaped).
std::string render_cef_line(const std::string& device_product, const std::string& device_event_class_id,
                             const std::string& name, int severity_0_10,
                             const std::vector<std::pair<std::string, std::string>>& extension_fields);

// Renders one LEEF 2.0 line (no trailing newline): "LEEF:2.0|conduitscope|<device_product>|
// <version>|<event_id>|<tab-separated key=value extension pairs>" -- LEEF 2.0's default tab
// delimiter, no explicit sixth delimiter field. `event_id` is escaped with cef_header_escape
// (LEEF documents no header-escaping rules of its own); extension values with
// leef_extension_escape (not cef_extension_escape -- see that function's own comment for why an
// embedded tab needs LEEF-specific handling CEF's own escaper doesn't provide).
std::string render_leef_line(const std::string& device_product, const std::string& event_id,
                              const std::vector<std::pair<std::string, std::string>>& extension_fields);

// Wraps `cef_payload` in an RFC 5424 syslog header -- never LEEF (see this file's own header
// comment for why CEF is the one format with a citable syslog-transport convention).
// `severity_0_10` uses the same CEF 0-10 scale, translated via cef_severity_to_rfc5424_severity;
// `msgid` is the emitting subcommand's own name ("detect"/"policy"/"baseline").
std::string render_rfc5424_line(int severity_0_10, const std::string& msgid, const std::string& cef_payload);

}  // namespace conduitscope
