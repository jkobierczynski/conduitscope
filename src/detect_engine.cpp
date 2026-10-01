// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/detect_engine.hpp"

#include <algorithm>
#include <cmath>
#include <cstdio>
#include <initializer_list>
#include <ostream>
#include <set>
#include <sstream>
#include <utility>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/fins.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/notable_it_protocols.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/resource_limits.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/time_format.hpp"

namespace conduitscope {

const char* detection_category_name(DetectionCategory category) {
    switch (category) {
        case DetectionCategory::EngineeringStationActivity: return "Engineering-Station Activity";
        case DetectionCategory::FirmwareLogicChange: return "Firmware/Logic Change";
        case DetectionCategory::RemoteAccessChannel: return "Remote-Access Channel";
        case DetectionCategory::ProtocolMisuse: return "Protocol Misuse";
    }
    return "Unknown";
}

const char* detection_evidence_name(DetectionEvidence evidence) {
    switch (evidence) {
        case DetectionEvidence::Confirmed: return "Confirmed";
        case DetectionEvidence::Heuristic: return "Heuristic";
    }
    return "Unknown";
}

const char* detection_novelty_name(DetectionNovelty novelty) {
    switch (novelty) {
        case DetectionNovelty::NotApplicable: return "N/A";
        case DetectionNovelty::ConfirmedNew: return "Confirmed New";
        case DetectionNovelty::FirstOccurrence: return "First Occurrence";
    }
    return "Unknown";
}

const char* detection_severity_name(DetectionSeverity severity) {
    switch (severity) {
        case DetectionSeverity::Critical: return "Critical";
        case DetectionSeverity::Moderate: return "Moderate";
        case DetectionSeverity::Informational: return "Informational";
    }
    return "Unknown";
}

namespace {

// Each writer in this codebase keeps its own local json_escape/format_epoch_seconds rather than
// sharing one across translation units -- see asset_inventory.cpp's own identical pair and its own
// comment on why (this file's header comment references the same convention).
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

// `finding_kind` (e.g. "s7-plc-stop", "s7-plc-control") is a plain source-tag discriminator, NOT
// derived from category/technique: two different finding sources can share the same category and
// technique (S7 PLC Stop and PLC Control both map to EngineeringStationActivity/T0858) while still
// being two genuinely different things to report -- without this tag, the second one observed on
// the same conduit would silently collapse into the first one's own existing finding (packet_count/
// last_seen updated, its own distinct description lost entirely). Caught during this feature's own
// manual verification pass against sample_s7comm_pi_control.pcap, which legitimately contains both
// PLC Stop and PLC Control traffic on the same conduit -- only PLC Stop's own finding was surviving
// before this tag was added.
std::string always_notable_key(const char* finding_kind, const std::string& client_ip,
                                const std::string& server_ip, const std::string& protocol,
                                uint16_t server_port) {
    std::ostringstream k;
    k << finding_kind << '|' << client_ip << '|' << server_ip << '|' << protocol << '|' << server_port;
    return k.str();
}

std::string new_conduit_key(const std::string& client_ip, const std::string& server_ip,
                             const std::string& protocol, uint16_t server_port, const char* source_tag) {
    std::ostringstream k;
    k << client_ip << '|' << server_ip << '|' << protocol << '|' << server_port << '|' << source_tag;
    return k.str();
}

// A small local copy of baseline.cpp's own merge_range_into (same linear-scan-then-sort-and-
// coalesce approach, same "a handful of intervals per operation in practice, no interval tree
// needed" reasoning) -- used by the Modbus write-without-prior-read pattern below to decide whether
// a write's range is fully covered by the union of everything read so far on the same conduit/
// table, even when the reads themselves arrived as several separate, now-adjacent/overlapping
// requests. Kept as its own copy rather than exported from baseline.cpp/.hpp, matching this file's
// own established per-translation-unit-copy convention for small helpers (see json_escape/
// format_epoch_seconds above).
void modbus_merge_range_into(std::vector<std::pair<uint32_t, uint32_t>>& ranges,
                              std::pair<uint32_t, uint32_t> r) {
    if (r.first >= r.second) return;  // empty/invalid range -- nothing to add
    ranges.push_back(r);
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    merged.reserve(ranges.size());
    for (const auto& cur : ranges) {
        if (!merged.empty() && cur.first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, cur.second);
        } else {
            merged.push_back(cur);
        }
    }
    ranges = std::move(merged);
}

// True iff [start, end) is fully contained in one single already-coalesced entry of `ranges` --
// same "no need to union multiple entries, they're already coalesced" reasoning as baseline.cpp's
// own range-containment check.
bool modbus_range_fully_read(const std::vector<std::pair<uint32_t, uint32_t>>& ranges, uint32_t start,
                              uint32_t end) {
    for (const auto& r : ranges) {
        if (r.first <= start && end <= r.second) return true;
    }
    return false;
}

// BACnet Who-Is flood/enumeration-sweep threshold -- deliberately the SAME small, admittedly-
// arbitrary illustrative default attack_detect.hpp's own DEFAULT_FLOOD_THRESHOLD already documents
// (100), for consistency across this codebase's two independent flood-shaped detectors, not because
// 100 is a vendor-sourced or researched number for Who-Is specifically -- see that constant's own
// comment (attack_detect.hpp) for the full reasoning this reuses.
constexpr size_t kBacnetWhoIsFloodThreshold = 100;

// S7comm Setup Communication probing threshold -- a small, documented judgment-call default (NOT
// vendor-sourced, matching kBacnetWhoIsFloodThreshold/DEFAULT_FLOOD_THRESHOLD's own precedent):
// low enough that a handful of repeated bare handshakes with no real S7comm function ever following
// them is still caught, high enough that a single truncated capture (one legitimate Setup
// Communication, then the capture simply ends before the engineering tool's next request) doesn't
// trip it on its own.
constexpr size_t kS7SetupCommProbeThreshold = 3;

// Download-then-restart composite window, seconds -- another small, documented judgment-call
// default, not vendor-sourced: long enough to cover a realistic "download, then a deliberate pause
// before activating it" gap, short enough that two genuinely unrelated findings against the same
// server hours apart aren't linked together as if they were one event.
constexpr double kCompositeWindowSeconds = 300.0;

// Modbus repeated exception-code response burst threshold/window (Batch 1 item 6,
// docs/research/2026-09-detect-pattern-candidates-batch2.md) -- generalizes Quickdraw-Snort's own
// SIDs 1111010/1111011 ("Slave Device Busy Exception Code Delay"/"Acknowledge Exception Code
// Delay"), both `threshold: count 3-5, seconds 60`. The low end of that count range is used here
// (3), the same "small, documented judgment-call default" posture as kS7SetupCommProbeThreshold
// above -- Quickdraw's own rule ships as a vendor-sourced primary reference for the SHAPE of this
// pattern (same exception code repeated to the same client within about a minute), not for the
// exact count/window values, which Snort deployments commonly tune per site.
constexpr size_t kModbusExceptionBurstThreshold = 3;
constexpr double kModbusExceptionBurstWindowSeconds = 60.0;

// DNP3 object-group/variation enumeration sweep threshold/window (Batch 2 item 9, docs/research/
// 2026-09-detect-pattern-candidates-batch2.md) -- another small, documented judgment-call default,
// not vendor-sourced: Quickdraw's own SIDs 1111213/1111214 (which this generalizes) use `threshold:
// count 3-5, seconds 30-60` on a differently-shaped condition (repeated EXCEPTION RESPONSES), so
// their exact numbers don't transplant directly. 5 distinct object group/variation combinations
// within 60 seconds is picked as "wide spread" -- high enough that one ordinary integrity poll
// (typically a handful of Class 0/1/2/3 object headers, or often just one or two) doesn't trip it,
// low enough that an engineering tool genuinely walking the outstation's supported object types
// still does -- same window as kModbusExceptionBurstWindowSeconds, for consistency across this
// file's two windowed detectors.
constexpr size_t kDnp3EnumerationSweepThreshold = 5;
constexpr double kDnp3EnumerationSweepWindowSeconds = 60.0;

// Port scan threshold/window (Batch 5 item 24, docs/research/2026-09-detect-pattern-candidates-
// batch2.md's own Batch 5 section) -- a small, documented judgment-call default, not vendor-sourced
// (unlike every prior batch, this pattern has no single Snort/Suricata rule to transplant a count/
// window from -- MITRE's own T0846.001 description names nmap/netcat/Advanced Port Scanner generically
// without a specific threshold). 10 distinct destination ports reached via pure-SYN packets within 60
// seconds is picked as "clearly a sweep" -- high enough that an ordinary engineering client opening a
// small handful of well-known ports against one device (S7/102, Modbus/502, an HTTP management UI)
// doesn't trip it, low enough that a real port scan against a modest/synthetic capture still does. Same
// 60s window as this file's other windowed detectors, for consistency.
constexpr size_t kPortScanDistinctPortThreshold = 10;
constexpr double kPortScanWindowSeconds = 60.0;

// Write-burst threshold/window (Batch 5 item 26, "Brute Force I/O"/T0806) -- reuses
// kModbusExceptionBurstThreshold/kModbusExceptionBurstWindowSeconds's own values and reasoning
// (a small, documented judgment-call default: 3 WRITE-classified requests to the same outstation
// within 60 seconds), the same low end of Quickdraw's own count-3-to-5 range Batch 1 item 6 already
// picked, applied here to write volume instead of exception-response volume.
constexpr size_t kWriteBurstThreshold = 3;
constexpr double kWriteBurstWindowSeconds = 60.0;

// Byte-exact match against a fixed expected sequence -- used by the Batch 2 Modbus scanner-tool
// fingerprints (items 10/11, detect_engine.cpp's own DNP3-block-sibling Modbus block below). Every
// byte these fingerprints check is already available as an individually-decoded ModbusFrame field
// (transaction_id/protocol_id/mbap_length/unit_id/function_code) or via raw_pdu_data (already
// exposed "for hex fallback/JSON", modbus.hpp, covering the PDU bytes after the function code) -- no
// new decode work or raw-frame-byte exposure was needed for this batch.
bool raw_pdu_matches(const ByteSpan& span, std::initializer_list<uint8_t> expected) {
    if (span.size() != expected.size()) return false;
    size_t i = 0;
    for (uint8_t b : expected) {
        if (span.at(i) != b) return false;
        ++i;
    }
    return true;
}

}  // namespace

// Identical dedup rule to BaselineEngine::mark_truncated (baseline.cpp) -- see this method's own
// doc comment (detect_engine.hpp) for why.
void DetectEngine::mark_truncated(const std::string& reason) {
    truncated_ = true;
    for (const std::string& existing : truncation_reasons_) {
        if (existing == reason) return;
    }
    truncation_reasons_.push_back(reason);
}

bool DetectEngine::admit_tracked_key(bool already_present, size_t current_map_size, const char* map_name) {
    if (already_present) return true;
    if (current_map_size < limits_.max_tracked_keys_per_map) return true;
    mark_truncated(std::string("tracked-key limit (") + std::to_string(limits_.max_tracked_keys_per_map) +
                    ") reached on " + map_name +
                    " -- further new keys are not tracked (--max-detect-tracked-keys-per-map)");
    return false;
}

bool DetectEngine::admit_originator(const std::vector<std::string>& originators, const std::string& originator,
                                     const char* map_name) {
    for (const std::string& existing : originators) {
        if (existing == originator) return true;
    }
    if (originators.size() < limits_.max_originators_per_server) return true;
    mark_truncated(std::string("originators-per-server limit (") +
                    std::to_string(limits_.max_originators_per_server) + ") reached on " + map_name +
                    " -- further new originators are not tracked (--max-detect-originators-per-server)");
    return false;
}

bool DetectEngine::admit_finding_slot(size_t current_size, const char* what) {
    if (current_size < limits_.max_findings) return true;
    mark_truncated(std::string("finding limit (") + std::to_string(limits_.max_findings) + ") reached on " +
                    what + " -- further new " + what + " are not recorded (--max-detect-findings)");
    return false;
}

void DetectEngine::observe(const DecodedPacket& dp) {
    ++total_packets_;
    if (!dp.has_ip) return;

    // `severity` defaults to Critical -- most always-notable sources are a real control/restart/
    // download action, where Critical is the right "if genuine" impact call (see each call site's own
    // comment for the handful of deliberate exceptions: dnp3-unsolicited-misuse and
    // iec104-unexpected-cot pass Moderate, bacnet-who-is-flood and modbus-write-without-read pass
    // Informational). `evidence` defaults to Confirmed -- every always-notable source reads a decoded
    // protocol field directly, no source here needs Heuristic. Neither parameter says anything about
    // "new vs. known" -- every always-notable finding gets DetectionNovelty::NotApplicable
    // unconditionally, since no such judgment is ever made for this kind of finding (see this file's
    // header comment, detect_engine.hpp).
    auto record_always_notable = [&](const char* finding_kind, DetectionCategory category,
                                      const MitreAttackTechnique& technique, const std::string& client_ip,
                                      const std::string& server_ip, const std::string& protocol,
                                      uint16_t server_port, const std::string& description,
                                      DetectionSeverity severity = DetectionSeverity::Critical,
                                      DetectionEvidence evidence = DetectionEvidence::Confirmed) {
        // `decode`'s own live "always-notable highlighting" hook (AlwaysNotableHit, detect_engine.hpp)
        // -- fired unconditionally, on EVERY packet that reaches this lambda, before either of the two
        // branches below (which govern only always_notable_'s own report-facing dedup/ceiling
        // admission). A caller that wants to know about every individual occurrence live -- not just
        // the first one ever seen for this (category, technique, client/server, protocol, port)
        // combination, and not gated on whether this engine's own max_findings ceiling still had room
        // -- gets exactly that: this packet genuinely matched, on the wire, right now, independent of
        // what this engine's own report will eventually contain.
        if (on_always_notable_hit_) {
            AlwaysNotableHit hit;
            hit.finding_kind = finding_kind;
            hit.category = category;
            hit.technique = technique;
            hit.severity = severity;
            hit.evidence = evidence;
            hit.client_ip = client_ip;
            hit.server_ip = server_ip;
            hit.protocol = protocol;
            hit.server_port = server_port;
            hit.description = description;
            hit.timestamp = dp.timestamp;
            on_always_notable_hit_(hit);
        }
        std::string key = always_notable_key(finding_kind, client_ip, server_ip, protocol, server_port);
        auto it = always_notable_.find(key);
        if (it == always_notable_.end()) {
            if (!admit_finding_slot(always_notable_.size(), "findings")) return;
            DetectionFinding f;
            f.category = category;
            f.technique = technique;
            f.evidence = evidence;
            f.novelty = DetectionNovelty::NotApplicable;
            f.severity = severity;
            f.client_ip = client_ip;
            f.server_ip = server_ip;
            f.protocol = protocol;
            f.server_port = server_port;
            f.description = description;
            f.first_seen = f.last_seen = dp.timestamp;
            f.packet_count = 1;
            always_notable_.emplace(key, std::move(f));
            always_notable_order_.push_back(key);
        } else {
            DetectionFinding& f = it->second;
            if (dp.timestamp < f.first_seen || f.packet_count == 0) f.first_seen = dp.timestamp;
            if (dp.timestamp > f.last_seen) f.last_seen = dp.timestamp;
            ++f.packet_count;
        }
    };

    // `severity`/`evidence` are recorded on the CANDIDATE here and carried straight through onto the
    // eventual finding in finish() -- finish() only ever decides `novelty` (see NewConduitCandidate's
    // own comment, detect_engine.hpp). `severity` defaults to Moderate -- a new engineering/remote-
    // access originator is a real but not immediately control-affecting event (unlike, say, a PLC
    // Stop) for most sources here; umas-new-originator-discovery (read-only enumeration) is the one
    // deliberate Informational exception, see its own call site. `evidence` defaults to Confirmed;
    // the RemoteAccessChannel source is this engine's one deliberate Heuristic exception (port-only
    // Tier-1 identification plus a port-comparison direction guess, neither a decoded field) -- see
    // its own call site and this file's header comment.
    auto record_new_conduit_candidate = [&](DetectionCategory category, const MitreAttackTechnique& technique,
                                             bool is_remote_access, const std::string& client_ip,
                                             const std::string& server_ip, const std::string& protocol,
                                             uint16_t server_port, const char* source_tag,
                                             DetectionSeverity severity = DetectionSeverity::Moderate,
                                             DetectionEvidence evidence = DetectionEvidence::Confirmed) {
        std::string key = new_conduit_key(client_ip, server_ip, protocol, server_port, source_tag);
        auto it = new_conduit_candidates_.find(key);
        if (it == new_conduit_candidates_.end()) {
            if (!admit_finding_slot(new_conduit_candidates_.size(), "new-conduit candidates")) return;
            NewConduitCandidate c;
            c.category = category;
            c.technique = technique;
            c.evidence = evidence;
            c.severity = severity;
            c.is_remote_access = is_remote_access;
            c.client_ip = client_ip;
            c.server_ip = server_ip;
            c.protocol = protocol;
            c.server_port = server_port;
            c.first_seen = c.last_seen = dp.timestamp;
            c.packet_count = 1;
            c.source_tag = source_tag;
            new_conduit_candidates_.emplace(key, std::move(c));
            new_conduit_order_.push_back(key);
        } else {
            NewConduitCandidate& c = it->second;
            if (dp.timestamp > c.last_seen) c.last_seen = dp.timestamp;
            ++c.packet_count;
        }
    };

    // --- Port Scan (Batch 5 item 24, T0846.001) -- no protocol decode at all, the first DetectEngine
    // finding not gated on any specific ICS protocol. Pure-SYN (no-ACK) packets from one source to one
    // destination, sweeping across an unusually wide spread of distinct destination ports within a
    // short window -- the same windowed-SET-of-distinct-values shape dnp3_enumeration_sweep_state_
    // uses below, applied to raw TCP ports instead of DNP3 object group/variations. dp.tcp_flags ==
    // "SYN" is the exact same pure-SYN check asset_inventory.cpp/baseline.cpp/flow_direction.cpp
    // already use for handshake tracking -- a SYN,ACK (a response, not a scan attempt) never matches.
    // Deliberately TCP-only: see this file's own header comment for why a UDP equivalent is left for a
    // future pass rather than guessed at now.
    if (dp.has_tcp && dp.tcp_flags == "SYN") {
        std::string pkey = dp.src_ip + "|" + dp.dst_ip;
        auto pit = port_scan_state_.find(pkey);
        if (admit_tracked_key(pit != port_scan_state_.end(), port_scan_state_.size(), "port_scan_state_")) {
        if (pit == port_scan_state_.end()) pit = port_scan_state_.emplace(pkey, PortScanState{}).first;
        PortScanState& pst = pit->second;
        if (pst.distinct_ports.empty() || (dp.timestamp - pst.window_start) > kPortScanWindowSeconds) {
            pst.window_start = dp.timestamp;
            pst.distinct_ports.clear();
        }
        pst.distinct_ports.insert(dp.dst_port);
        if (pst.distinct_ports.size() >= kPortScanDistinctPortThreshold) {
            record_always_notable(
                "port-scan", DetectionCategory::ProtocolMisuse, mitre_t0846_001_port_scan(), dp.src_ip,
                dp.dst_ip, "tcp", dp.dst_port,
                "This source reached " + std::to_string(pst.distinct_ports.size()) +
                    " distinct destination ports on this host via pure-SYN packets within " +
                    std::to_string(static_cast<long>(kPortScanWindowSeconds)) +
                    "s -- a port-scan-shaped sweep rather than an ordinary engineering client opening "
                    "a small handful of well-known ports",
                DetectionSeverity::Moderate);
        }
        }  // admit_tracked_key(port_scan_state_)
    }

    // --- S7comm: PLC Control/PLC Stop (mode change), block download (firmware/logic change) -------
    // NOT gated on has_function alone: unlike has_pi_service/plc_stop_message (Job-side only, per
    // baseline.cpp's own extract_s7comm_operations comment), S7CommResult::has_function/
    // function_name are populated on BOTH the Job (request, rosctr 0x01) AND Ack_Data (response,
    // rosctr 0x03) sides -- confirmed directly against src/s7comm.cpp's own decode (the function-code
    // byte is read whenever frame.rosctr == 0x01 || frame.rosctr == 0x03), and caught during this
    // feature's own manual verification pass (sample_s7comm_pi_control.pcap's PLC Control ACK
    // initially produced a finding with client/server reversed and the PLC's own ephemeral-port-side
    // as the "target"). S7CommResult carries no rosctr field of its own to check directly (a
    // zero-flat-field migrated type that dropped it), so the request side is instead identified the
    // same way this codebase's own "known port" direction heuristic already does elsewhere: a Job
    // request is addressed TO the PLC's S7comm port (dst_port == 102); the Ack_Data response comes
    // FROM it (src_port == 102, dst_port an ephemeral client port). A non-standard-port S7comm session
    // (unusual but not rejected by this decoder) would be silently skipped by this check -- an honest,
    // documented limitation, not a crash risk.
    if (dp.protocol == "s7comm" && dp.result && dp.dst_port == 102) {
        const S7CommResult& sr = dp.result->as<S7CommResult>();
        if (sr.has_function) {
            if (sr.function_name == "PLC Stop") {
                record_always_notable("s7-plc-stop", DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm PLC Stop command -- CPU commanded to STOP from the process "
                                       "network");
            } else if (sr.function_name == "PLC Control") {
                record_always_notable("s7-plc-control", DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm PLC Control (PI-Service) command -- an engineering-station-"
                                       "class program invocation issued to the CPU");
            } else if (sr.function_name == "Request Download" || sr.function_name == "Download Block" ||
                       sr.function_name == "Download Ended") {
                record_always_notable("s7-download", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0843_program_download(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm block download (" + sr.function_name +
                                           ") -- a program/logic block is being written TO the CPU from an "
                                           "engineering station");
            } else if (sr.function_name == "Start Upload" || sr.function_name == "Upload" ||
                       sr.function_name == "End Upload") {
                // Batch 5 item 23 (T0845, Program Upload) -- the mirror of s7-download above: pulling
                // logic OFF the CPU rather than pushing it on. The request that STARTS the sequence
                // (Start Upload) is still sent by the engineering station TO the PLC (function access
                // is classified Read because the data itself flows PLC->station once underway, per
                // s7comm.cpp's own comment on this trio -- see this block's own dp.dst_port == 102
                // gate, which already only matches Job-side requests addressed to the PLC).
                record_always_notable("s7-upload", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0845_program_upload(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm block upload (" + sr.function_name +
                                           ") -- a program/logic block is being read FROM the CPU by an "
                                           "engineering station");
            }

            // Setup Communication (0xF0) probing state -- see s7_setup_comm_state_'s own comment
            // (detect_engine.hpp) for why this is only TRACKED here and resolved later, in finish().
            // Every branch of this whole if/else-if chain above (including the three not otherwise
            // named here) counts as "some other function was seen" except Setup Communication itself
            // -- a genuine engineering-station session does real work beyond the initial handshake.
            std::string s7key = dp.src_ip + "|" + dp.dst_ip;
            auto s7it = s7_setup_comm_state_.find(s7key);
            if (admit_tracked_key(s7it != s7_setup_comm_state_.end(), s7_setup_comm_state_.size(),
                                   "s7_setup_comm_state_")) {
                if (s7it == s7_setup_comm_state_.end()) {
                    s7it = s7_setup_comm_state_.emplace(s7key, S7SetupCommProbeState{}).first;
                }
                if (sr.function_name == "Setup Communication") {
                    S7SetupCommProbeState& st = s7it->second;
                    if (st.setup_comm_count == 0) st.first_seen = dp.timestamp;
                    st.last_seen = dp.timestamp;
                    ++st.setup_comm_count;
                } else {
                    s7it->second.other_function_seen = true;
                }
            }
        }

        // --- S7 Read SZL enumeration from a new originator (engineering-station reconnaissance,
        // --- Batch 4 item 19) ---------------------------------------------------------------------
        // Quickdraw-Snort's own s7.rules SIDs 1111301/1111302 name this exact shape ("S7 Enumerate
        // Redpoint NSE Request CPU Function Read SZL attempt"), matching the Read SZL request
        // structurally (any SZL-ID), not a tool-specific byte fingerprint. Already decoded and named
        // by this codebase's own src/s7comm.cpp before this batch (has_userdata_szl/
        // userdata_szl_is_response) -- zero new decode work. A separate rosctr (Userdata, 0x07) from
        // the has_function branch above (Job/Ack_Data, rosctr 0x01/0x03), so this is a sibling check,
        // not folded into that if/else-if chain. Request side only (!userdata_szl_is_response); like
        // the pre-existing CIP-List*/UMAS/FINS engineering-tool-enumeration sources, only a SECOND,
        // DIFFERENT originator querying the SAME PLC within this capture is flagged.
        if (sr.has_userdata_szl && !sr.userdata_szl_is_response) {
            auto szlit = s7_szl_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(szlit != s7_szl_originators_by_server_.end(),
                                   s7_szl_originators_by_server_.size(), "s7_szl_originators_by_server_")) {
                if (szlit == s7_szl_originators_by_server_.end()) {
                    szlit = s7_szl_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{}).first;
                }
                std::vector<std::string>& originators = szlit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen && admit_originator(originators, dp.src_ip, "s7_szl_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(
                            DetectionCategory::EngineeringStationActivity,
                            mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "s7comm", dp.dst_port,
                            "s7-szl-new-originator", DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        }
    }

    // --- DNP3: Cold/Warm Restart (firmware/logic change), unsolicited misuse (protocol misuse) -----
    // Cold/Warm Restart/Enable/Disable Unsolicited Responses are all MASTER -> OUTSTATION request
    // function codes (dp.src_ip issues them, dp.dst_ip is the outstation acting on them); Unsolicited
    // Response (0x82) is the one function here sent OUTSTATION -> MASTER unprompted, so its own
    // client/server roles are the reverse of every other DNP3 function this engine reads -- see this
    // file's own header comment and dnp3_unsolicited_enabled_'s own doc comment (detect_engine.hpp)
    // for the consistent "<master>|<outstation>" key ordering used on both sides of that tracking.
    if (dp.protocol == "dnp3" && dp.result) {
        const Dnp3Result& dr = dp.result->as<Dnp3Result>();
        if (dr.dnp3_has_function) {
            if (dr.dnp3_function_name == "Cold Restart" || dr.dnp3_function_name == "Warm Restart") {
                record_always_notable("dnp3-restart", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "dnp3",
                                       dp.dst_port,
                                       "DNP3 " + dr.dnp3_function_name +
                                           " request -- an outstation is being commanded to restart");
            } else if (dr.dnp3_function_name == "Stop Application") {
                // Batch 2 item 7 (docs/research/2026-09-detect-pattern-candidates-batch2.md) --
                // distinct from Cold/Warm Restart above: this halts the outstation's application
                // layer without a full device restart (function 0x12, already named in dnp3.cpp's own
                // function-code table before this batch -- pure wiring, no decode-layer change).
                record_always_notable("dnp3-stop-application", DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "dnp3",
                                       dp.dst_port,
                                       "DNP3 Stop Application request -- an outstation's application "
                                       "layer is being halted without a full device restart");
            } else if (dr.dnp3_function_name == "Read") {
                // Batch 2 item 9: object-group/variation enumeration sweep -- a single master's Read
                // requests against one outstation span an unusually wide spread of distinct object
                // group/variation combinations within a short window. WINDOWED (unlike
                // bacnet_who_is_count_by_source_'s own whole-capture running count) -- see
                // dnp3_enumeration_sweep_state_'s own comment (detect_engine.hpp) for why this
                // deliberately departs from the research doc's own readiness note, which suggested
                // reusing that unwindowed mechanism. A SET of (group, variation) pairs, not a count --
                // the signal is DIVERSITY of what's being read, so re-reading the same handful of
                // object types repeatedly within the window must never trip this on repetition alone.
                std::string ekey = dp.src_ip + "|" + dp.dst_ip;
                auto eit = dnp3_enumeration_sweep_state_.find(ekey);
                if (admit_tracked_key(eit != dnp3_enumeration_sweep_state_.end(),
                                       dnp3_enumeration_sweep_state_.size(), "dnp3_enumeration_sweep_state_")) {
                    if (eit == dnp3_enumeration_sweep_state_.end()) {
                        eit = dnp3_enumeration_sweep_state_.emplace(ekey, Dnp3EnumerationSweepState{}).first;
                    }
                    Dnp3EnumerationSweepState& est = eit->second;
                    if (est.distinct_group_variations.empty() ||
                        (dp.timestamp - est.window_start) > kDnp3EnumerationSweepWindowSeconds) {
                        est.window_start = dp.timestamp;
                        est.distinct_group_variations.clear();
                    }
                    for (const auto& obj : dr.dnp3_objects) {
                        est.distinct_group_variations.emplace(obj.group, obj.variation);
                    }
                    if (est.distinct_group_variations.size() >= kDnp3EnumerationSweepThreshold) {
                        record_always_notable(
                            "dnp3-enumeration-sweep", DetectionCategory::EngineeringStationActivity,
                            mitre_t0861_point_and_tag_identification(), dp.src_ip, dp.dst_ip, "dnp3",
                            dp.dst_port,
                            "DNP3 Read requests from this master spanned " +
                                std::to_string(est.distinct_group_variations.size()) +
                                " distinct object group/variation combinations against this outstation "
                                "within " +
                                std::to_string(static_cast<long>(kDnp3EnumerationSweepWindowSeconds)) +
                                "s -- an engineering-tool-shaped enumeration sweep rather than routine "
                                "periodic polling",
                            DetectionSeverity::Moderate);
                    }
                }
            } else if (dr.dnp3_function_name == "Enable Unsolicited Responses") {
                std::string ukey = dp.src_ip + "|" + dp.dst_ip;
                auto uit = dnp3_unsolicited_enabled_.find(ukey);
                if (admit_tracked_key(uit != dnp3_unsolicited_enabled_.end(), dnp3_unsolicited_enabled_.size(),
                                       "dnp3_unsolicited_enabled_")) {
                    dnp3_unsolicited_enabled_[ukey] = true;
                }
            } else if (dr.dnp3_function_name == "Disable Unsolicited Responses") {
                std::string ukey = dp.src_ip + "|" + dp.dst_ip;
                auto uit = dnp3_unsolicited_enabled_.find(ukey);
                if (admit_tracked_key(uit != dnp3_unsolicited_enabled_.end(), dnp3_unsolicited_enabled_.size(),
                                       "dnp3_unsolicited_enabled_")) {
                    dnp3_unsolicited_enabled_[ukey] = false;
                }
            } else if (dr.dnp3_function_name == "Unsolicited Response") {
                // Reverse roles: dp.src_ip is the outstation reporting unprompted, dp.dst_ip is the
                // master. Only master IPs actually seen ENABLING unsolicited responses on this exact
                // conduit are trusted; a master this engine has never seen enable it (including one
                // this capture simply starts after -- an honest limitation, not a false-positive fix)
                // makes the report say so plainly rather than silently assume it was enabled offscreen.
                std::string ukey = dp.dst_ip + "|" + dp.src_ip;
                auto it = dnp3_unsolicited_enabled_.find(ukey);
                if (it == dnp3_unsolicited_enabled_.end() || !it->second) {
                    record_always_notable(
                        "dnp3-unsolicited-misuse", DetectionCategory::ProtocolMisuse,
                        mitre_t0855_unauthorized_command_message(), dp.dst_ip, dp.src_ip, "dnp3", dp.src_port,
                        "DNP3 Unsolicited Response from an outstation this capture never saw a master "
                        "enable unsolicited responses on (Enable Unsolicited Responses, function 0x14) -- "
                        "either enabled before this capture began, or genuinely unexpected",
                        DetectionSeverity::Moderate);
                }
            } else if (dr.dnp3_function_name == "Select") {
                std::string skey = dp.src_ip + "|" + dp.dst_ip;
                auto seit = dnp3_select_seen_.find(skey);
                if (admit_tracked_key(seit != dnp3_select_seen_.end(), dnp3_select_seen_.size(),
                                       "dnp3_select_seen_")) {
                    dnp3_select_seen_[skey] = true;
                }
            } else if (dr.dnp3_function_name == "Operate") {
                // Direct Operate (0x05) is deliberately NOT checked here at all -- see
                // dnp3_select_seen_'s own comment (detect_engine.hpp) for why flagging it would be
                // wrong. Only a plain Operate (0x04, the second half of the Select-before-Operate
                // pair) with no Select EVER recorded for this exact master/outstation pair in this
                // capture is the misuse-shaped case -- an outstation genuinely accepting a bare
                // Operate with no prior Select is either misconfigured (accepting Operate without
                // requiring SBO) or the master skipped straight to Operate, either way worth an
                // analyst's attention. Coarse by design (per-pair, not per-object-index) -- see
                // dnp3_select_seen_'s own comment for why.
                std::string skey = dp.src_ip + "|" + dp.dst_ip;
                auto it = dnp3_select_seen_.find(skey);
                if (it == dnp3_select_seen_.end() || !it->second) {
                    record_always_notable(
                        "dnp3-operate-without-select", DetectionCategory::ProtocolMisuse,
                        mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip, "dnp3",
                        dp.dst_port,
                        "DNP3 Operate (0x04) with no matching Select (0x03) ever seen for this master/"
                        "outstation pair in this capture -- either the Select happened before this "
                        "capture began, or the outstation is accepting Operate without requiring "
                        "Select-before-Operate first (not the same thing as Direct Operate 0x05, "
                        "which this engine never flags -- Direct Operate is a legitimate, "
                        "intentional bypass of Select-before-Operate, not a violation of it)");
                }
            }

            // Batch 2 item 8: a write/operate command addressed to one of DNP3's three reserved
            // broadcast destination addresses (0xFFFF general reserved broadcast, 0xFFFE unconfirmed
            // broadcast, 0xFFFD confirmed broadcast -- all three per the DNP3 spec) reaches every
            // outstation on the segment at once. Deliberately a SEPARATE check, not folded into the
            // function-name chain above -- a broadcast Cold Restart or Stop Application should still
            // produce BOTH its own function-specific finding above AND this one, not just one or the
            // other. Gated to Write-classified function codes only (dnp3_write_function_names(),
            // dnp3.hpp -- the exact same read/write classification Policy::parse_policy_text's own
            // 'functions: [write]' keyword expansion already uses), matching the pattern's own "a
            // write/operate command" framing -- every Write-classified function is inherently
            // master-issued (Confirm/Select/Response/Unsolicited Response are all Other, never
            // Write), so no extra direction gating is needed here.
            // patch257 section 4.5 (this engine's own false-positive validation pass, see
            // detect_snort_patterns_all_findings/detect_batch2_*_findings for the fixtures this
            // reasoning is proven against): the audit for that pass flagged this finding as
            // directly relevant to the "redundant-controller behavior" legitimate scenario --
            // a standby master resyncing every outstation right after a failover, or an operator
            // re-enabling unsolicited reporting plant-wide during commissioning/maintenance, both
            // produce this exact wire shape (a write/operate command to the reserved broadcast
            // address). The finding still fires at the same severity either way -- a broadcast
            // write genuinely does reach every outstation at once regardless of who sent it or
            // why -- this only adds the honest alternative explanation to the description text.
            static const std::vector<std::string> kDnp3WriteFunctionNames = dnp3_write_function_names();
            bool is_dnp3_write = std::find(kDnp3WriteFunctionNames.begin(), kDnp3WriteFunctionNames.end(),
                                            dr.dnp3_function_name) != kDnp3WriteFunctionNames.end();
            if (is_dnp3_write && (dr.destination_address == 0xFFFF || dr.destination_address == 0xFFFE ||
                                   dr.destination_address == 0xFFFD)) {
                std::ostringstream d;
                d << "DNP3 " << dr.dnp3_function_name << " addressed to reserved broadcast destination "
                     "address 0x" << std::hex << dr.destination_address << std::dec
                  << " -- reaches every outstation on the segment at once, a single message with "
                     "plant-wide blast radius; can also be a redundant/standby master issuing a "
                     "legitimate resync broadcast after a failover, or a commissioning/maintenance "
                     "broadcast re-enabling unsolicited reporting plant-wide -- treat as a prompt to "
                     "confirm which master should be active and why a broadcast was used, not "
                     "confirmed misuse";
                record_always_notable("dnp3-broadcast-command", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "dnp3", dp.dst_port, d.str());
            }

            // Batch 5 items 25/26 (T0848 Rogue Master, T0806 Brute Force I/O) -- the DNP3 analog of
            // the Modbus block above, reusing the same is_dnp3_write classification already computed
            // for the broadcast check above. See modbus_write_originators_by_server_/
            // write_burst_state_'s own comments (detect_engine.hpp) for the full reasoning; both
            // trackers are per-protocol (a separate dnp3_write_originators_by_server_ map, and the
            // same write_burst_state_ map keyed with a "dnp3|" prefix instead of "modbus|"), so a
            // Modbus writer and a DNP3 writer to the same IP address are never evidence about each
            // other.
            if (is_dnp3_write) {
                auto dwit = dnp3_write_originators_by_server_.find(dp.dst_ip);
                if (admit_tracked_key(dwit != dnp3_write_originators_by_server_.end(),
                                       dnp3_write_originators_by_server_.size(),
                                       "dnp3_write_originators_by_server_")) {
                    if (dwit == dnp3_write_originators_by_server_.end()) {
                        dwit = dnp3_write_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{})
                                   .first;
                    }
                    std::vector<std::string>& writers = dwit->second;
                    bool already_writer = false;
                    for (const auto& w : writers) {
                        if (w == dp.src_ip) {
                            already_writer = true;
                            break;
                        }
                    }
                    if (!already_writer &&
                        admit_originator(writers, dp.src_ip, "dnp3_write_originators_by_server_")) {
                        if (!writers.empty()) {
                            record_new_conduit_candidate(DetectionCategory::ProtocolMisuse,
                                                           mitre_t0848_rogue_master(),
                                                           /*is_remote_access=*/false, dp.src_ip, dp.dst_ip,
                                                           "dnp3", dp.dst_port, "dnp3-rogue-master",
                                                           DetectionSeverity::Critical);
                        }
                        writers.push_back(dp.src_ip);
                    }
                }

                std::string wkey = "dnp3|" + dp.src_ip + "|" + dp.dst_ip;
                auto wbit = write_burst_state_.find(wkey);
                if (admit_tracked_key(wbit != write_burst_state_.end(), write_burst_state_.size(),
                                       "write_burst_state_")) {
                    if (wbit == write_burst_state_.end()) {
                        wbit = write_burst_state_.emplace(wkey, WriteBurstState{}).first;
                    }
                    WriteBurstState& wst = wbit->second;
                    if (wst.count == 0 || (dp.timestamp - wst.window_start) > kWriteBurstWindowSeconds) {
                        wst.window_start = dp.timestamp;
                        wst.count = 0;
                    }
                    ++wst.count;
                    if (wst.count >= kWriteBurstThreshold) {
                        record_always_notable(
                            "dnp3-write-burst", DetectionCategory::ProtocolMisuse,
                            mitre_t0806_brute_force_io(), dp.src_ip, dp.dst_ip, "dnp3", dp.dst_port,
                            "This master issued at least " + std::to_string(kWriteBurstThreshold) +
                                " write-classified DNP3 requests to this outstation within " +
                                std::to_string(static_cast<long>(kWriteBurstWindowSeconds)) +
                                "s -- a repetitive I/O-point-value-change burst, though a legitimate "
                                "fast-polling engineering tool doing rapid setpoint adjustment during "
                                "commissioning can trigger this too",
                            DetectionSeverity::Moderate);
                    }
                }
            }
        }
    }

    // --- IEC 104: a genuinely anomalous COT (protocol misuse), Reset Process (device restart) ------
    // Deliberately does NOT flag ordinary General/Station Interrogation (C_IC_NA_1) on its own --
    // periodic interrogation is routine SCADA master polling, and unconditionally flagging it would
    // be pure noise, not a real finding; see docs/design/detection-engine.md's own scoping note. The
    // COT values 44-47 ("unknown type identification"/"unknown cause of transmission"/"unknown
    // common address of ASDU"/"unknown information object address" -- iec104_cot_name's own table,
    // iec104.cpp) are the outstation itself flagging the exchange as malformed/unexpected, a
    // genuinely anomalous signal regardless of ASDU type -- matched on the rendered name's own
    // "unknown " prefix rather than a raw COT code (Iec104Result exposes no numeric COT field, only
    // the rendered name -- see Iec104AsduInfo's own comment, iec104.hpp).
    if (dp.protocol == "iec104" && dp.result) {
        const Iec104Result& ir = dp.result->as<Iec104Result>();
        if (ir.iec104_has_asdu) {
            if (ir.iec104_cot_name.rfind("unknown ", 0) == 0) {
                record_always_notable("iec104-unexpected-cot", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "iec104", dp.dst_port,
                                       "IEC 104 ASDU with cause-of-transmission \"" + ir.iec104_cot_name +
                                           "\" (type " + ir.iec104_asdu_type_short_name +
                                           ") -- the receiving end's own reported COT is one of IEC "
                                           "60870-5-101/104's four error codes",
                                       DetectionSeverity::Moderate);
            }
            // C_RP_NA_1's own type ID is shared by the command itself (COT 6, "activation") and its
            // own confirmation/termination ASDUs sent back the OTHER direction (COT 7/10) -- IEC 104
            // reuses one type ID across a command and its acknowledgments, unlike DNP3's separate
            // request/response function codes. Gated on COT "activation" specifically so this finding
            // is always the actual command, correctly directed master -> outstation, never double-
            // counted (once per direction) off the same exchange's own ack/termination ASDUs.
            if (ir.iec104_asdu_type_short_name == "C_RP_NA_1" && ir.iec104_cot_name == "activation") {
                record_always_notable("iec104-reset-process", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "iec104",
                                       dp.dst_port,
                                       "IEC 104 Reset Process command (C_RP_NA_1) -- a controlling station "
                                       "commanded a process reset");
            }

            // --- General Interrogation addressed to the broadcast Common Address (protocol misuse,
            // --- Batch 3 item 18) ---------------------------------------------------------------
            // The IEC 60870-5-101/104 standard itself reserves Common Address of ASDU 0xFFFF as the
            // global/broadcast address -- a General Interrogation (C_IC_NA_1, COT "activation", the
            // same gating the Reset Process check above uses to isolate the actual command from its
            // own confirmation/termination ASDUs) addressed there forces EVERY RTU on the segment to
            // report full state at once: a single message with the same kind of outsized blast radius
            // as this engine's own DNP3 broadcast-command finding (Batch 2 item 8), but for IEC 104.
            // iec104_common_address is already decoded and tracked per-ASDU (Iec104AsduInfo, item 3's
            // own type/COT/IOA-range work) -- pure wiring, no new decode work. Deliberately a SEPARATE
            // finding from iec104-unexpected-cot/iec104-reset-process above -- a distinct wire
            // condition, not a variant of either.
            // patch257 section 4.5: same "redundant-controller behavior" relevance as the DNP3
            // broadcast-command finding just above -- a standby SCADA master resynchronizing full
            // plant state right after a failover, or a legitimate commissioning-time full poll,
            // both produce this exact wire shape. Severity is unchanged (a broadcast GI genuinely
            // does force every RTU to report at once, whoever sent it); only the description gets
            // the honest alternative explanation.
            if (ir.iec104_asdu_type_short_name == "C_IC_NA_1" && ir.iec104_cot_name == "activation" &&
                ir.iec104_common_address == 0xFFFF) {
                record_always_notable(
                    "iec104-broadcast-interrogation", DetectionCategory::ProtocolMisuse,
                    mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip, "iec104",
                    dp.dst_port,
                    "IEC 104 General Interrogation (C_IC_NA_1) addressed to the broadcast Common "
                    "Address of ASDU (0xFFFF) -- forces every RTU on the segment to report full state "
                    "at once; can also be a redundant/standby master resynchronizing full plant state "
                    "after a failover, or a legitimate commissioning-time full poll -- treat as a "
                    "prompt to confirm which master should be active, not confirmed misuse");
            }
        }
    }

    // --- BACnet: reinitializeDevice (restart), deviceCommunicationControl (misuse) ------------------
    // Confirmed-Request side only (pdu_type_name == "Confirmed-Request") -- the ACK carries no
    // repeatable "what was requested" signal of its own worth a second finding, the exact same
    // "request side only" posture this engine already takes for S7/DNP3/IEC104 above. Service names
    // are lower-camelCase (kBacnetConfirmedServiceChoice, bacnet_tables.inc, transcribed from
    // Wireshark's own BACnetConfirmedServiceChoice value_string table) -- "reinitializeDevice"/
    // "deviceCommunicationControl", NOT PascalCase; confirmed directly against that table during
    // this feature's own manual verification pass after an initial PascalCase guess matched nothing.
    if (dp.protocol == "bacnet" && dp.result) {
        const BacnetFrame& bf = dp.result->as<BacnetFrame>();
        if (bf.has_npdu && bf.npdu.has_apdu && bf.npdu.apdu.pdu_type_name == "Confirmed-Request") {
            const std::string& svc = bf.npdu.apdu.service_choice_name;
            if (svc == "reinitializeDevice") {
                record_always_notable("bacnet-reinitialize", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "bacnet",
                                       dp.dst_port,
                                       "BACnet ReinitializeDevice request -- a device is being commanded to "
                                       "restart or change its reinitialization state");
            } else if (svc == "deviceCommunicationControl") {
                record_always_notable("bacnet-devicecommcontrol", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "bacnet", dp.dst_port,
                                       "BACnet DeviceCommunicationControl request -- a device's own "
                                       "communication can be silenced or re-enabled by this service");
            } else if (svc == "readProperty") {
                // Batch 2 item 12: known BACnet scanner-tool fingerprint (nmap-shaped) -- CyberICS
                // SIDs 101563265-101563273 (docs/research/2026-09-detect-pattern-candidates-batch2.md
                // flagged this item as needing one more research pass before implementation; that
                // pass ran as part of this batch and found NINE SIDs, not the eight the original
                // pass estimated from the repo's rule count alone -- Vendor-Name/SID 101563273 was
                // missed the first time). Every one of the nine rules is byte-identical except its
                // final property-identifier byte -- |81 0a 00 11 01 04 00 05 01 0c 0c 02 3f ff ff 19
                // <property>| -- decoded field by field: BVLC-Original-Unicast-NPDU, NPDU version 1, a
                // Confirmed-Request ReadProperty (service 12) whose ObjectIdentifier is object type 8
                // (device) instance 0x3FFFFF (4194303, BACnet's own 22-bit-all-ones "any device"
                // wildcard instance -- a real, spec-legal convention for addressing a device without
                // already knowing its real instance number, but one a legitimate operator who already
                // knows their own devices' instance numbers has no routine reason to use), asking for
                // one of nine standard identity properties. Every byte this fingerprint needs is
                // already available as rendered BacnetApdu::values entries
                // ("object=device,4194303"/"property=<name>") -- unlike the Modbus fingerprints
                // above, no raw-byte matching was needed here at all.
                bool is_wildcard_device = false;
                std::string matched_property;
                for (const auto& v : bf.npdu.apdu.values) {
                    if (v == "object=device,4194303") {
                        is_wildcard_device = true;
                    } else if (v.rfind("property=", 0) == 0) {
                        matched_property = v.substr(9);
                    }
                }
                static const std::set<std::string> kNmapBacnetFingerprintProperties = {
                    "application-software-version", "description",       "firmware-revision",
                    "location",                     "model-name",        "object-identifier",
                    "object-name",                  "vendor-identifier", "vendor-name"};
                if (is_wildcard_device && kNmapBacnetFingerprintProperties.count(matched_property)) {
                    record_always_notable(
                        "bacnet-scanner-nmap", DetectionCategory::ProtocolMisuse,
                        mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip,
                        "bacnet", dp.dst_port,
                        "BACnet ReadProperty request byte-exact matches a known nmap-shaped scanner "
                        "fingerprint (CyberICS scada-scan.rules) -- Device object wildcard instance "
                        "4194303 queried for '" +
                            matched_property +
                            "', a pattern a legitimate operator who already knows their own devices' "
                            "real instance numbers has no routine reason to use",
                        DetectionSeverity::Informational);
                }
            }
        }

        // --- BACnet Who-Is flood / device-enumeration sweep (protocol misuse) --------------------
        // Who-Is (unconfirmed service choice 8, "who-Is") is routinely sent as a BACnet/IP
        // broadcast, so this is grouped by SOURCE ip alone -- see
        // bacnet_who_is_count_by_source_'s own comment (detect_engine.hpp) for why destination is
        // deliberately not part of the key. Fires exactly once, the moment a source's own running
        // count reaches kBacnetWhoIsFloodThreshold (mirroring attack_detect.hpp's own
        // DEFAULT_FLOOD_THRESHOLD "fires exactly once" behavior) -- record_always_notable's own
        // dedup-by-key handles every count past the threshold as an ordinary last_seen/packet_count
        // update to that same finding, so nothing extra is needed here for that.
        if (bf.has_npdu && bf.npdu.has_apdu && bf.npdu.apdu.pdu_type_name == "Unconfirmed-Request" &&
            bf.npdu.apdu.service_choice_name == "who-Is" &&
            admit_tracked_key(bacnet_who_is_count_by_source_.count(dp.src_ip) != 0,
                               bacnet_who_is_count_by_source_.size(), "bacnet_who_is_count_by_source_")) {
            size_t count = ++bacnet_who_is_count_by_source_[dp.src_ip];
            if (count >= kBacnetWhoIsFloodThreshold) {
                // Batch 5 re-mapping: T0846.002 (Broadcast Discovery) fits this finding better than
                // the T0888 (Remote System Information Discovery) it cited before Batch 5 -- MITRE's
                // own T0846.002 description names "Building Automation and Control Network (BACnet)
                // Who-Is requests" as a canonical example BY NAME, not an inference. Zero behavior
                // change otherwise -- same threshold, same severity, same everything else.
                record_always_notable(
                    "bacnet-who-is-flood", DetectionCategory::ProtocolMisuse,
                    mitre_t0846_002_broadcast_discovery(), dp.src_ip, dp.dst_ip, "bacnet",
                    dp.dst_port,
                    "BACnet Who-Is flood/device-enumeration sweep from this source -- at least " +
                        std::to_string(kBacnetWhoIsFloodThreshold) +
                        " Who-Is requests observed in this capture (destination shown is only the "
                        "most recent one -- Who-Is is routinely broadcast, so this source may have "
                        "targeted several destinations)",
                    DetectionSeverity::Informational);
            }
        }

        // --- BACnet foreign-device/broadcast-distribution-table reconnaissance and misuse (Batch 4
        // --- item 21) --------------------------------------------------------------------------
        // Quickdraw-Snort bacnet.rules, 9 SIDs (1111701-1111709) collapsing into three wire-level
        // shapes -- see this file's own header comment (detect_engine.hpp) for the full mapping.
        // These are BVLC-level functions, carrying no NPDU of their own at all (bacnet.hpp's own
        // file header comment), so unlike who-Is above these are NOT gated on bf.has_npdu -- checked
        // directly against bf.bvlc_function/has_result_code/result_code instead, all already decoded
        // before this batch.
        if (bf.bvlc_function == 0x05) {
            // (a) Register-Foreign-Device request -- a device asking this BBMD to relay broadcasts
            // to it from off its local subnet; a network-topology change, not a data read. Same
            // "second-plus originator to a given server is new, first is not" mechanism as the
            // pre-existing CIP/UMAS/S7/FINS engineering-tool sources.
            auto fdit = bacnet_foreign_device_register_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(fdit != bacnet_foreign_device_register_originators_by_server_.end(),
                                   bacnet_foreign_device_register_originators_by_server_.size(),
                                   "bacnet_foreign_device_register_originators_by_server_")) {
                if (fdit == bacnet_foreign_device_register_originators_by_server_.end()) {
                    fdit = bacnet_foreign_device_register_originators_by_server_
                               .emplace(dp.dst_ip, std::vector<std::string>{})
                               .first;
                }
                std::vector<std::string>& originators = fdit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen && admit_originator(originators, dp.src_ip,
                                                       "bacnet_foreign_device_register_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(
                            DetectionCategory::EngineeringStationActivity,
                            mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "bacnet", dp.dst_port,
                            "bacnet-foreign-device-register-new-originator", DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        } else if (bf.bvlc_function == 0x06 || bf.bvlc_function == 0x02) {
            // (b) Read-Foreign-Device-Table or Read-Broadcast-Distribution-Table request --
            // reconnaissance against the BBMD's own routing configuration. Both functions folded
            // into one finding/one tracking map -- see this file's own header comment for why.
            auto bbit = bacnet_bbmd_table_read_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(bbit != bacnet_bbmd_table_read_originators_by_server_.end(),
                                   bacnet_bbmd_table_read_originators_by_server_.size(),
                                   "bacnet_bbmd_table_read_originators_by_server_")) {
                if (bbit == bacnet_bbmd_table_read_originators_by_server_.end()) {
                    bbit = bacnet_bbmd_table_read_originators_by_server_
                               .emplace(dp.dst_ip, std::vector<std::string>{})
                               .first;
                }
                std::vector<std::string>& originators = bbit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen && admit_originator(originators, dp.src_ip,
                                                       "bacnet_bbmd_table_read_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(
                            DetectionCategory::EngineeringStationActivity,
                            mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "bacnet", dp.dst_port,
                            "bacnet-bbmd-table-read-new-originator", DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        } else if (bf.bvlc_function == 0x00 && bf.has_result_code &&
                   (bf.result_code == 0x0030 || bf.result_code == 0x0020 || bf.result_code == 0x0040)) {
            // (c) BVLC-Result NAK for one of the three request shapes above -- a real refusal, worth
            // an always-notable finding regardless of who sent the original request (unlike (a)/(b),
            // this needs no "new vs. known" judgment: the device's own explicit denial is the
            // evidence). Codes verified directly against Wireshark's own packet-bvlc.c
            // bvlc_result_names table this session, not assumed.
            const char* reason = bf.result_code == 0x0030   ? "Register-Foreign-Device NAK"
                                  : bf.result_code == 0x0020 ? "Read-Broadcast-Distribution-Table NAK"
                                                              : "Read-Foreign-Device-Table NAK";
            // Reverse roles, same convention as dnp3-unsolicited-misuse above: dp.src_ip is the BBMD
            // sending the NAK, dp.dst_ip is the original requester it's refusing.
            record_always_notable(
                "bacnet-bbmd-nak", DetectionCategory::ProtocolMisuse,
                mitre_t0855_unauthorized_command_message(), dp.dst_ip, dp.src_ip, "bacnet", dp.src_port,
                std::string("BACnet BVLC-Result ") + reason +
                    " -- this client's own foreign-device or broadcast-distribution-table request was "
                    "explicitly refused by the BBMD",
                DetectionSeverity::Moderate);
        }
    }

    // --- OMRON FINS: Controller Data Read from a new originator (engineering-station reconnaissance,
    // --- Batch 4 item 22) -------------------------------------------------------------------------
    // Quickdraw-Snort omron.rules SIDs 1111401-1111404 (TCP/9600 and UDP/9600, command code 0x0501,
    // "Controller Data Read" -- already decoded and named by this codebase's own src/fins.cpp before
    // this batch, zero new decode work). Pulls the target PLC's model/version identification off the
    // wire -- the FINS analog of Modbus Read Device Identification/CIP List Identity/S7 Read SZL/
    // UMAS READ_ID. Both TCP and UDP FINS are already decoded by this codebase (unlike EtherNet/IP's
    // own UDP gap, item 20 above), so no UDP scope limitation applies here. Request side only
    // (!ff.is_response); same "second-plus originator to this PLC is new, first is not" mechanism as
    // every other engineering-tool-enumeration source in this engine.
    if (dp.protocol == "fins" && dp.result) {
        const FinsFrame& ff = dp.result->as<FinsFrame>();
        if (!ff.is_response && ff.command == 0x0501) {
            auto fit = fins_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(fit != fins_originators_by_server_.end(), fins_originators_by_server_.size(),
                                   "fins_originators_by_server_")) {
                if (fit == fins_originators_by_server_.end()) {
                    fit = fins_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{}).first;
                }
                std::vector<std::string>& originators = fit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen && admit_originator(originators, dp.src_ip, "fins_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(
                            DetectionCategory::EngineeringStationActivity,
                            mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "fins", dp.dst_port,
                            "fins-new-originator-discovery", DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        }
    }

    // --- OPC UA: weak-session pattern -- SecurityPolicy=None channel, or anonymous session identity
    // --- (protocol misuse, Batch 3 item 15) -----------------------------------------------------
    // Grounded in Claroty Team82's own published OPC UA hardening guidance, which names
    // SecurityPolicy=None and anonymous UserIdentityToken authentication as the two most
    // consequential network-observable OPC UA misconfigurations. Two independent, deliberately
    // SEPARATE checks rather than one combined finding: this decoder is stateless-per-message (no
    // channel/session correlation -- see opcua.hpp's own "Deliberately NOT implemented" paragraph),
    // so there is no reliable way to confirm a given ActivateSession's own SecureChannel actually
    // used SecurityPolicy=None without adding real cross-message state tracking this codebase has
    // for no protocol today -- each condition is independently a real, citable OPC UA security
    // finding on its own regardless (Claroty's own guidance treats them as two separate checks too).
    // Both use mitre_t0886_remote_services() unconditionally -- deliberately WITHOUT the T0822
    // zone-crossing upgrade the RemoteAccessChannel new-vs-known source gets below, since that
    // upgrade lives entirely inside finish()'s own new-conduit-candidate/baseline resolution and
    // these two findings are always-notable (a weak configuration is worth flagging every time it's
    // seen, not just the first) -- see this file's own header comment (detect_engine.hpp) for the
    // full reasoning behind this scope departure. Needed no new decode work: security_policy_uri
    // (asymmetric OpenSecureChannel messages) and the "identity=anonymous" values entry
    // (ActivateSessionRequest) were both already exposed by opcua.hpp/opcua.cpp before this batch.
    if (dp.protocol == "opcua" && dp.result) {
        const OpcUaResult& our = dp.result->as<OpcUaResult>();
        const OpcUaMessage& msg = our.first;
        if (msg.service_name == "OpenSecureChannelRequest" && msg.is_asymmetric &&
            msg.security_policy_uri == "http://opcfoundation.org/UA/SecurityPolicy#None") {
            record_always_notable(
                "opcua-weak-securechannel", DetectionCategory::ProtocolMisuse,
                mitre_t0886_remote_services(), dp.src_ip, dp.dst_ip, "opcua", dp.dst_port,
                "OPC UA OpenSecureChannel request negotiating SecurityPolicy=None -- this channel "
                "carries no encryption or message signing at all",
                DetectionSeverity::Moderate);
        }
        if (msg.service_name == "ActivateSessionRequest") {
            for (const auto& v : msg.values) {
                if (v.rfind("identity=anonymous", 0) == 0) {
                    record_always_notable(
                        "opcua-anonymous-session", DetectionCategory::ProtocolMisuse,
                        mitre_t0886_remote_services(), dp.src_ip, dp.dst_ip, "opcua", dp.dst_port,
                        "OPC UA ActivateSession request using an anonymous identity token -- no real "
                        "authentication for this engineering session",
                        DetectionSeverity::Moderate);
                    break;
                }
            }
        }
    }

    // --- EtherNet/IP: CIP Forward_Open/Large_Forward_Open from a new originator (protocol misuse) --
    // Request side only (CipMessage::is_response == false) -- the response carries no originator
    // identity of its own to track. The FIRST originator ever seen opening a connection to a given
    // server is deliberately NOT flagged (nothing to be "new" relative to within this capture); a
    // SECOND, DIFFERENT originator to the SAME server is what finish() may turn into a finding --
    // see this file's own header comment and cip_originators_by_server_'s own doc comment
    // (detect_engine.hpp).
    if (dp.protocol == "enip" && dp.has_tcp && dp.result) {
        const EnipFrame& ef = dp.result->as<EnipResult>().first;
        if (ef.has_cip && !ef.cip.is_response &&
            (ef.cip.service_name == "Forward_Open" || ef.cip.service_name == "Large_Forward_Open")) {
            auto cipit = cip_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(cipit != cip_originators_by_server_.end(), cip_originators_by_server_.size(),
                                   "cip_originators_by_server_")) {
                if (cipit == cip_originators_by_server_.end()) {
                    cipit = cip_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{}).first;
                }
                std::vector<std::string>& originators = cipit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen && admit_originator(originators, dp.src_ip, "cip_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(DetectionCategory::ProtocolMisuse,
                                                      mitre_t0855_unauthorized_command_message(),
                                                      /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "enip",
                                                      dp.dst_port, "cip-new-originator");
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        }

        // --- CIP Identity Object write (protocol misuse) -----------------------------------------
        // Any Set_Attribute_Single (0x10) or Set_Attributes_All (0x02) WRITE (request side --
        // response carries no path at all, see CipMessage::path's own comment) addressed at CIP
        // class 0x01 (the Identity object -- every CIP device has one, ODVA Vol.1 Ch.5-2). Scoped
        // deliberately BROAD -- "any write to the Identity object" -- rather than a specific
        // run/program/remote-mode attribute number: the real-world precedent for this pattern
        // (Digital Bond's "Basecamp"-era ControlLogix remote-mode-change research) uses an
        // undocumented Rockwell mechanism with no citable primary source for the exact wire format
        // (attribute ID/value), and this codebase's own standing discipline is to not hardcode a
        // guessed wire-format detail -- Jurgen's own explicit scoping choice when this ambiguity was
        // raised (docs/design/detection-engine.md has the full record). The Identity object's own
        // writable attributes are narrow in practice (mostly vendor-specific/configuration, not
        // routine process-data attributes any legitimate HMI/SCADA polling loop would ever touch),
        // so "any write here" is still a meaningfully narrow, genuinely-suspicious signal even
        // without pinning down which attribute a mode change actually uses.
        if (ef.has_cip && !ef.cip.is_response &&
            (ef.cip.service_name == "Set_Attribute_Single" || ef.cip.service_name == "Set_Attributes_All") &&
            ef.cip.path.class_id && *ef.cip.path.class_id == 0x01) {
            record_always_notable(
                "cip-identity-write", DetectionCategory::ProtocolMisuse,
                mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip, "enip", dp.dst_port,
                "CIP " + ef.cip.service_name +
                    " write to the Identity object (class 0x01) -- broadened-scope stand-in for a "
                    "ControlLogix-style remote run/program/remote mode change: this engine cannot "
                    "confirm which specific Identity attribute was written (no citable primary source "
                    "for that wire format), so every write to this object is flagged rather than "
                    "guessing at one");
        }

        // --- CIP Identity Object Reset (firmware/logic change, Batch 3 item 16) -------------------
        // CIP service 0x05 ("Reset"), addressed at the Identity object (class 0x01, ODVA Vol.1
        // Ch.5-2) -- already decoded and named by this codebase's own src/enip.cpp
        // (cip_service_name's own case 0x05 -> "Reset", already classified a Write-access service)
        // before this batch. A direct CIP-native analog to DNP3 Cold Restart / S7 PLC Stop / UMAS
        // STOP_PLC -- zero new decode work needed. Request side only (response carries no path at
        // all, same as cip-identity-write above).
        if (ef.has_cip && !ef.cip.is_response && ef.cip.service_name == "Reset" &&
            ef.cip.path.class_id && *ef.cip.path.class_id == 0x01) {
            record_always_notable(
                "cip-identity-reset", DetectionCategory::FirmwareLogicChange,
                mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "enip", dp.dst_port,
                "CIP Reset service addressed at the Identity object (class 0x01) -- the target "
                "device is being power-cycled or reset from the process network");
        }

        // --- CIP List Identity/Services/Interfaces from a new originator (engineering-station
        // --- reconnaissance, Batch 3 item 17) ------------------------------------------------------
        // Léargas Security's own ruleset description names this exact recon shape ("List Identity/
        // Services/Interfaces recon"). Already decoded and named by this codebase's own src/enip.cpp
        // (enip_command_name's own case 0x0004/0x0063/0x0064) before this batch -- zero new decode
        // work. This is exactly how legitimate engineering tools (RSLinx, Studio 5000) discover CIP
        // devices on a segment, and exactly how a scanner enumerates one too -- so, like the CIP
        // Forward_Open pattern above, only a SECOND, DIFFERENT originator querying the SAME target
        // within this capture is flagged (the first originator ever seen has nothing to be "new"
        // relative to). Deliberately outside the `ef.has_cip` condition -- these three encapsulation
        // commands carry no CIP message of their own at all (EnipFrame::has_cip stays false for
        // them), so checking has_cip first would silently skip every one. Scope note: this only sees
        // these commands when carried over TCP, since this codebase's own EtherNet/IP UDP path
        // (enip_udp_decoder()) covers CIP I/O implicit messaging only, not encapsulation commands --
        // see this file's own header comment (detect_engine.hpp) and docs/USER_GUIDE.md's LIMITATIONS.
        if (ef.header.command_name == "ListServices" || ef.header.command_name == "ListIdentity" ||
            ef.header.command_name == "ListInterfaces") {
            auto elit = enip_list_discovery_originators_by_server_.find(dp.dst_ip);
            if (admit_tracked_key(elit != enip_list_discovery_originators_by_server_.end(),
                                   enip_list_discovery_originators_by_server_.size(),
                                   "enip_list_discovery_originators_by_server_")) {
                if (elit == enip_list_discovery_originators_by_server_.end()) {
                    elit = enip_list_discovery_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{})
                               .first;
                }
                std::vector<std::string>& originators = elit->second;
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen &&
                    admit_originator(originators, dp.src_ip, "enip_list_discovery_originators_by_server_")) {
                    if (!originators.empty()) {
                        record_new_conduit_candidate(
                            DetectionCategory::EngineeringStationActivity,
                            mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "enip", dp.dst_port,
                            "enip-new-originator-discovery", DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        }

        // --- EtherNet/IP List Identity via the Redpoint Nmap NSE script (protocol misuse, Batch 4
        // --- item 20) --------------------------------------------------------------------------
        // Quickdraw-Snort enip.rules SID 1111517 (TCP/44818): a genuine byte-exact TOOL fingerprint,
        // distinct from the generic new-originator finding above -- Redpoint's own NSE script
        // hardcodes a fixed 4-byte value (wire bytes C1 DE BE D1) at offset 16 of the 24-byte
        // encapsulation header, which falls inside the 8-byte Sender Context field (offset 12-19).
        // EnipHeader::sender_context is decoded little-endian (read_u64le, enip.cpp: first byte read
        // is the LSB), so those four wire bytes at offsets 16-19 land in the TOP 32 bits of the
        // decoded uint64_t -- (sender_context >> 32) == 0xD1BEDEC1 is the equivalent check, verified
        // against this batch's own synthetic fixture's real decode JSON output before being written
        // here, not derived from byte-order reasoning alone. Request side only
        // (!ef.has_identity -- the target echoes the Sender Context verbatim in its own response per
        // EnipHeader::sender_context's own comment, so without this gate the same probe would
        // produce a second finding with client/server swapped). SID 1111518's own UDP variant is
        // deliberately not implemented -- see this file's own header comment (detect_engine.hpp) for
        // why.
        if (ef.header.command_name == "ListIdentity" && !ef.has_identity &&
            (ef.header.sender_context >> 32) == uint64_t{0xD1BEDEC1}) {
            record_always_notable(
                "enip-list-identity-redpoint-fingerprint", DetectionCategory::ProtocolMisuse,
                mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip, "enip",
                dp.dst_port,
                "EtherNet/IP ListIdentity request byte-exact matches the Redpoint Nmap NSE script's "
                "own fixed Sender Context fingerprint (Quickdraw-Snort enip.rules SID 1111517)",
                DetectionSeverity::Informational);
        }
    }

    // --- UMAS (umas.hpp): START_PLC/STOP_PLC (mode change), download sequence (firmware/logic
    // --- change), and a new engineering-station originator issuing TAKE_PLC_RESERVATION or a
    // --- read-only discovery command (protocol misuse / engineering-station activity) -----------
    // Grok gap #4 Phase 6 -- UMAS is Modbus/TCP at the wire level (dp.protocol is "modbus", never
    // "umas"; see umas.hpp's own header comment), so this is gated on dp.protocol == "modbus" plus
    // mb.umas being set (function code 0x5A), exactly the same shape baseline.cpp's own
    // extract_modbus_operations UMAS branch uses. Request side only for all four (mb.umas->
    // is_response == false) -- a UMAS response carries no function code at all to match against
    // (see umas.hpp), so there is nothing repeatable to extract a finding from on that side, the
    // same "request side only" posture S7/DNP3/IEC104/BACnet above all take.
    if (dp.protocol == "modbus" && dp.result) {
        const ModbusFrame& mb = dp.result->as<ModbusFrame>();

        // --- Modbus: MBAP declared-length anomaly (CVE-2017-16740-grounded, Batch 3 item 13) -------
        // CVE-2017-16740 (NVD) is a real, published Rockwell Allen-Bradley MicroLogix buffer overflow
        // triggered by a crafted Modbus/TCP MBAP header length field. mbap_length is already decoded
        // (ModbusFrame::mbap_length), and this decoder's own kMaxPlausibleMbapLength (modbus.cpp)
        // already rejects anything above 300 outright -- such a frame never even reaches DetectEngine
        // -- so the only anomalous-but-decoded window this check can ever see is 255-300: past the
        // Modbus Application Protocol spec's own true 254-byte ceiling (253-byte max PDU + 1-byte unit
        // ID) but under the decoder's own generous "maybe a nonstandard/extended real device" slack. A
        // length field genuinely inconsistent with the packet's own actual remaining byte count (mb.
        // notes already carries this as a "MBAP length field implies ... but this packet has ..." note,
        // see try_parse_modbus_tcp) is flagged the same way -- both are the same underlying wire-
        // condition (a client's declared MBAP length disagreeing with reality), so they share one
        // finding_kind rather than two. Request side only (mb.is_request, the same payload-shape
        // heuristic every other request-side check in this file already relies on) -- CVE-2017-16740's
        // own threat model is a crafted CLIENT request reaching the device, not a server's own
        // response framing.
        if (mb.is_request) {
            bool length_mismatch = false;
            for (const auto& note : mb.notes) {
                if (note.rfind("MBAP length field implies", 0) == 0) {
                    length_mismatch = true;
                    break;
                }
            }
            if (mb.mbap_length > 254 || length_mismatch) {
                record_always_notable(
                    "modbus-mbap-length-anomaly", DetectionCategory::ProtocolMisuse,
                    mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip, "modbus",
                    dp.dst_port,
                    length_mismatch
                        ? "Modbus MBAP length field (" + std::to_string(mb.mbap_length) +
                              ") does not match this packet's own actual remaining byte count -- the "
                              "same wire-level anomaly shape as CVE-2017-16740 (Rockwell Allen-Bradley "
                              "MicroLogix, crafted MBAP length triggering a buffer overflow)"
                        : "Modbus MBAP length field (" + std::to_string(mb.mbap_length) +
                              ") exceeds the Modbus Application Protocol spec's own 254-byte maximum "
                              "(253-byte PDU + 1-byte unit ID) -- the same wire-level anomaly shape as "
                              "CVE-2017-16740 (Rockwell Allen-Bradley MicroLogix, crafted MBAP length "
                              "triggering a buffer overflow)",
                    DetectionSeverity::Moderate);
            }
        }

        // --- Modbus: read/write quantity exceeds its own function's spec maximum (CVE-2021-22659-
        // --- grounded, Batch 3 item 14) -------------------------------------------------------------
        // CVE-2021-22659 (NVD) is a real, published Rockwell MicroLogix 1400 buffer overflow from an
        // out-of-spec Read/Write Multiple Coils/Registers quantity value. The Modbus Application
        // Protocol Specification V1.1b3 defines a hard per-function maximum quantity (2000 Read
        // Coils/Discrete Inputs, 125 Read Holding/Input Registers, 1968 Write Multiple Coils, 123
        // Write Multiple Registers) -- a request's own already-decoded `quantity` field
        // (ModbusFrame::quantity) exceeding its OWN function's maximum is a spec violation regardless
        // of what any specific device's firmware actually does with it, so this fires unconditionally
        // (no baseline needed), unlike the pre-existing "write outside every range ever read" pattern
        // below, which is baseline-relative. Request side only (mb.is_request && mb.quantity) --
        // quantity is populated on both read requests and write-multiple requests/responses
        // (ModbusFrame's own comment), but only the REQUEST's quantity is the attacker/client-
        // controlled value CVE-2021-22659's own threat model is about.
        if (mb.is_request && mb.quantity) {
            uint8_t base_fc = mb.function_code & 0x7F;
            std::optional<uint16_t> max_quantity;
            const char* function_label = nullptr;
            switch (base_fc) {
                case 0x01:
                    max_quantity = uint16_t{2000};
                    function_label = "Read Coils";
                    break;
                case 0x02:
                    max_quantity = uint16_t{2000};
                    function_label = "Read Discrete Inputs";
                    break;
                case 0x03:
                    max_quantity = uint16_t{125};
                    function_label = "Read Holding Registers";
                    break;
                case 0x04:
                    max_quantity = uint16_t{125};
                    function_label = "Read Input Registers";
                    break;
                case 0x0F:
                    max_quantity = uint16_t{1968};
                    function_label = "Write Multiple Coils";
                    break;
                case 0x10:
                    max_quantity = uint16_t{123};
                    function_label = "Write Multiple Registers";
                    break;
                default:
                    break;
            }
            if (max_quantity && *mb.quantity > *max_quantity) {
                bool is_write = (base_fc == 0x0F || base_fc == 0x10);
                record_always_notable(
                    "modbus-quantity-out-of-spec", DetectionCategory::ProtocolMisuse,
                    is_write ? mitre_t0831_manipulation_of_control()
                             : mitre_t0855_unauthorized_command_message(),
                    dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    std::string("Modbus ") + function_label + " request with quantity " +
                        std::to_string(*mb.quantity) +
                        ", exceeding this function's own Modbus Application Protocol Specification "
                        "V1.1b3 maximum of " +
                        std::to_string(*max_quantity) +
                        " -- the same wire-level anomaly shape as CVE-2021-22659 (Rockwell MicroLogix "
                        "1400, out-of-spec quantity triggering a buffer overflow)",
                    DetectionSeverity::Critical);
            }
        }

        if (mb.umas && !mb.umas->is_response) {
            uint8_t fc = mb.umas->function_code;
            if (fc == UMAS_START_PLC || fc == UMAS_STOP_PLC) {
                record_always_notable(fc == UMAS_START_PLC ? "umas-start-plc" : "umas-stop-plc",
                                       DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "modbus",
                                       dp.dst_port,
                                       "UMAS " + mb.umas->function_name +
                                           " command -- an engineering station changed the PLC's own "
                                           "run/stop mode");
            } else if (fc == UMAS_INITIALIZE_DOWNLOAD || fc == UMAS_DOWNLOAD_BLOCK ||
                       fc == UMAS_END_STRATEGY_DOWNLOAD) {
                record_always_notable("umas-download", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0843_program_download(), dp.src_ip, dp.dst_ip, "modbus",
                                       dp.dst_port,
                                       "UMAS " + mb.umas->function_name +
                                           " -- a program/logic block is being transferred to/from the "
                                           "PLC from an engineering station");
            } else if (fc == UMAS_INITIALIZE_UPLOAD || fc == UMAS_UPLOAD_BLOCK ||
                       fc == UMAS_END_STRATEGY_UPLOAD) {
                // Batch 5 item 23 (T0845, Program Upload) -- the mirror of umas-download above, one
                // function-code trio over in UMAS's own table (0x30/0x31/0x32 vs. the already-wired
                // 0x33/0x34/0x35). Pulling logic OFF the PLC rather than pushing it on.
                record_always_notable("umas-upload", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0845_program_upload(), dp.src_ip, dp.dst_ip, "modbus",
                                       dp.dst_port,
                                       "UMAS " + mb.umas->function_name +
                                           " -- a program/logic block is being read FROM the PLC by an "
                                           "engineering station");
            } else if (fc == UMAS_TAKE_PLC_RESERVATION || fc == UMAS_READ_ID ||
                       fc == UMAS_READ_PROJECT_INFO || fc == UMAS_READ_PLC_INFO) {
                // Same "second-plus originator to a given server is new, first is not" mechanism as
                // the CIP Forward_Open branch above (cip_originators_by_server_), generalized
                // across all four of these UMAS commands via one shared per-server originator set
                // (umas_engineering_originators_by_server_) rather than one map per command -- see
                // that member's own comment (detect_engine.hpp) for why a client already credited
                // via one command isn't re-flagged for later issuing a different one.
                auto umasit = umas_engineering_originators_by_server_.find(dp.dst_ip);
                if (admit_tracked_key(umasit != umas_engineering_originators_by_server_.end(),
                                       umas_engineering_originators_by_server_.size(),
                                       "umas_engineering_originators_by_server_")) {
                    if (umasit == umas_engineering_originators_by_server_.end()) {
                        umasit = umas_engineering_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{})
                                     .first;
                    }
                    std::vector<std::string>& originators = umasit->second;
                    bool already_seen = false;
                    for (const auto& o : originators) {
                        if (o == dp.src_ip) {
                            already_seen = true;
                            break;
                        }
                    }
                    if (!already_seen && admit_originator(originators, dp.src_ip,
                                                           "umas_engineering_originators_by_server_")) {
                        if (!originators.empty()) {
                            bool is_reservation = (fc == UMAS_TAKE_PLC_RESERVATION);
                            // TAKE_PLC_RESERVATION actually claims exclusive engineering access -- a real
                            // (if not immediately destructive) control-plane event, so it keeps the
                            // record_new_conduit_candidate default of Moderate severity. The three
                            // READ_ID/READ_PROJECT_INFO/READ_PLC_INFO commands are read-only enumeration
                            // with no control effect at all if genuine, so they're deliberately
                            // Informational instead -- the same "evidence stays Confirmed, only severity
                            // drops" posture as the Modbus write-without-read pattern above.
                            record_new_conduit_candidate(
                                is_reservation ? DetectionCategory::ProtocolMisuse
                                               : DetectionCategory::EngineeringStationActivity,
                                is_reservation ? mitre_t0855_unauthorized_command_message()
                                               : mitre_t0888_remote_system_information_discovery(),
                                /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                                is_reservation ? "umas-new-originator-reservation"
                                               : "umas-new-originator-discovery",
                                is_reservation ? DetectionSeverity::Moderate : DetectionSeverity::Informational);
                        }
                        originators.push_back(dp.src_ip);
                    }
                }
            }
        }

        // --- Modbus: Rogue Master (Batch 5 item 25, T0848) + Brute Force I/O (Batch 5 item 26, T0806)
        // Both reuse the same WRITE classification: mb.function_name matched against
        // modbus_write_function_names() (modbus.hpp), the exact same read/write classification
        // Policy::parse_policy_text's own 'functions: [write]' keyword expansion already uses.
        // UMAS traffic is naturally excluded here with no extra guard needed: modbus_function_name()
        // (modbus.cpp) special-cases function code 0x5A to return the literal string "UMAS" rather
        // than pulling a name from kModbusFunctions' own table, so mb.function_name == "UMAS" never
        // matches anything modbus_write_function_names() returns -- confirmed by reading modbus.cpp
        // this session, not assumed. See this file's own header comment for why UMAS write traffic is
        // deliberately scoped out of both patterns below (its own write-shaped functions already fire
        // their own always-notable finding on every occurrence).
        if (mb.is_request) {
            static const std::vector<std::string> kModbusWriteFunctionNames = modbus_write_function_names();
            bool is_modbus_write = std::find(kModbusWriteFunctionNames.begin(), kModbusWriteFunctionNames.end(),
                                              mb.function_name) != kModbusWriteFunctionNames.end();
            if (is_modbus_write) {
                // Rogue Master: a second, different client issuing a write-classified request against
                // an outstation that already has an established write-capable master --
                // modbus_write_originators_by_server_'s own comment (detect_engine.hpp) has the full
                // reasoning for why this is its own tracker, distinct from every read-only
                // new-originator finding elsewhere in this file.
                auto mwit = modbus_write_originators_by_server_.find(dp.dst_ip);
                if (admit_tracked_key(mwit != modbus_write_originators_by_server_.end(),
                                       modbus_write_originators_by_server_.size(),
                                       "modbus_write_originators_by_server_")) {
                    if (mwit == modbus_write_originators_by_server_.end()) {
                        mwit = modbus_write_originators_by_server_.emplace(dp.dst_ip, std::vector<std::string>{})
                                   .first;
                    }
                    std::vector<std::string>& writers = mwit->second;
                    bool already_writer = false;
                    for (const auto& w : writers) {
                        if (w == dp.src_ip) {
                            already_writer = true;
                            break;
                        }
                    }
                    if (!already_writer &&
                        admit_originator(writers, dp.src_ip, "modbus_write_originators_by_server_")) {
                        if (!writers.empty()) {
                            record_new_conduit_candidate(DetectionCategory::ProtocolMisuse,
                                                           mitre_t0848_rogue_master(),
                                                           /*is_remote_access=*/false, dp.src_ip, dp.dst_ip,
                                                           "modbus", dp.dst_port, "modbus-rogue-master",
                                                           DetectionSeverity::Critical);
                        }
                        writers.push_back(dp.src_ip);
                    }
                }

                // Brute Force I/O: a burst of write-classified requests against the same outstation
                // within a short window -- write_burst_state_'s own comment (detect_engine.hpp) has
                // the full reasoning; same windowed-count shape as modbus_exception_burst_state_
                // above (Batch 1 item 6), reused here for write volume instead of exception volume.
                std::string wkey = "modbus|" + dp.src_ip + "|" + dp.dst_ip;
                auto mwbit = write_burst_state_.find(wkey);
                if (admit_tracked_key(mwbit != write_burst_state_.end(), write_burst_state_.size(),
                                       "write_burst_state_")) {
                    if (mwbit == write_burst_state_.end()) {
                        mwbit = write_burst_state_.emplace(wkey, WriteBurstState{}).first;
                    }
                    WriteBurstState& wst = mwbit->second;
                    if (wst.count == 0 || (dp.timestamp - wst.window_start) > kWriteBurstWindowSeconds) {
                        wst.window_start = dp.timestamp;
                        wst.count = 0;
                    }
                    ++wst.count;
                    if (wst.count >= kWriteBurstThreshold) {
                        record_always_notable(
                            "modbus-write-burst", DetectionCategory::ProtocolMisuse,
                            mitre_t0806_brute_force_io(), dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                            "This client issued at least " + std::to_string(kWriteBurstThreshold) +
                                " write-classified Modbus requests to this server within " +
                                std::to_string(static_cast<long>(kWriteBurstWindowSeconds)) +
                                "s -- a repetitive I/O-point-value-change burst, though a legitimate "
                                "fast-polling engineering tool doing rapid setpoint adjustment during "
                                "commissioning can trigger this too",
                            DetectionSeverity::Moderate);
                    }
                }
            }
        }

        // --- Modbus: write to a range never covered by a prior read on this conduit (protocol
        // --- misuse, deliberately Informational severity) ------------------------------------------
        // Only the two write-multiple functions carry a structured, request-confirmed
        // start_address/quantity at all (mb.is_request && mb.start_address && mb.quantity) -- Write
        // Single Coil/Register are excluded, see modbus_read_ranges_by_conduit_table_'s own comment
        // (detect_engine.hpp) for why. Deliberately Informational severity unconditionally, via
        // record_always_notable's own severity parameter -- unlike every other always-notable source
        // in this file, "write without a matching prior read" is a genuinely weak signal on its own:
        // plenty of legitimate deployments write setpoints/commands without ever reading them back,
        // especially in a short single-pcap capture that may simply not include the read traffic that
        // exists elsewhere in the plant's normal polling cycle. Evidence stays Confirmed -- the write
        // and the absence of a prior read genuinely were observed exactly as described; it's the
        // SEVERITY of that observation, not its reliability, that's deliberately low, a distinction
        // the old single confidence field couldn't make (see this file's own header comment,
        // detect_engine.hpp). Two separate address tables (coils vs. holding registers), never
        // cross-checked against each other -- see modbus_read_ranges_by_conduit_table_'s own comment.
        if (mb.is_request && mb.start_address && mb.quantity &&
            (mb.function_name == "Read Coils" || mb.function_name == "Read Holding Registers" ||
             mb.function_name == "Write Multiple Coils" || mb.function_name == "Write Multiple Registers")) {
            bool is_coils_table =
                (mb.function_name == "Read Coils" || mb.function_name == "Write Multiple Coils");
            std::string conduit_key = dp.src_ip + "|" + dp.dst_ip + "|" + std::to_string(dp.dst_port) + "|" +
                                       (is_coils_table ? "coils" : "holding_registers");
            uint32_t start = *mb.start_address;
            uint32_t end = start + static_cast<uint32_t>(*mb.quantity);
            if (mb.function_name == "Read Coils" || mb.function_name == "Read Holding Registers") {
                auto rit = modbus_read_ranges_by_conduit_table_.find(conduit_key);
                if (admit_tracked_key(rit != modbus_read_ranges_by_conduit_table_.end(),
                                       modbus_read_ranges_by_conduit_table_.size(),
                                       "modbus_read_ranges_by_conduit_table_")) {
                    if (rit == modbus_read_ranges_by_conduit_table_.end()) {
                        rit = modbus_read_ranges_by_conduit_table_
                                  .emplace(conduit_key, std::vector<std::pair<uint32_t, uint32_t>>{})
                                  .first;
                    }
                    modbus_merge_range_into(rit->second, {start, end});
                }
            } else {
                // Read-only check -- deliberately uses find(), not operator[], so a conduit/table this
                // engine has never seen a READ for is treated as "no prior read" (an empty ranges list)
                // without inserting a spurious empty entry into the map on the write path alone.
                auto rit = modbus_read_ranges_by_conduit_table_.find(conduit_key);
                static const std::vector<std::pair<uint32_t, uint32_t>> kEmptyModbusReadRanges;
                const std::vector<std::pair<uint32_t, uint32_t>>& read_ranges =
                    (rit != modbus_read_ranges_by_conduit_table_.end()) ? rit->second : kEmptyModbusReadRanges;
                if (!modbus_range_fully_read(read_ranges, start, end)) {
                    record_always_notable(
                        mb.function_name == "Write Multiple Coils" ? "modbus-write-without-read-coils"
                                                                    : "modbus-write-without-read-registers",
                        DetectionCategory::ProtocolMisuse, mitre_t0831_manipulation_of_control(), dp.src_ip,
                        dp.dst_ip, "modbus", dp.dst_port,
                        "Modbus " + mb.function_name + " to address range [" + std::to_string(start) + ", " +
                            std::to_string(end) +
                            ") not fully covered by any prior read (same conduit, same address table) in "
                            "this capture -- a genuinely weak signal on its own (many legitimate "
                            "deployments write setpoints without reading them back first): treat as a "
                            "prompt to check this range's purpose, not as confirmed misuse",
                        DetectionSeverity::Informational);
                }
            }
        }

        // --- Modbus Diagnostics (function 0x08): Force Listen Only Mode, Restart Communications
        // --- Option, Clear Counters and Diagnostic Registers (Batch 1 items 1-3, docs/research/
        // --- 2026-09-detect-pattern-candidates-batch2.md) -----------------------------------------
        // All three sourced from Digital Bond's Quickdraw-Snort modbus.rules, and all three verified
        // against this project's own real modbus_test_data_part1.pcap capture, which happens to
        // contain genuine examples of exactly these three sub-functions (see
        // real_modbus_diagnostics_force_listen_only_mode_decoded and its sibling CTest cases,
        // CMakeLists.txt). Request and response share the identical wire shape for Diagnostics (see
        // ModbusFrame::diagnostics_sub_function's own comment, modbus.hpp), so -- exactly like
        // S7comm's own detect wiring above (dp.dst_port == 102) -- direction is decided by "the
        // destination is the well-known Modbus port," not a decoded field: gates every branch below
        // to the request side only, so an always-notable finding isn't recorded twice (once per
        // direction) for a sub-function whose response happens to echo the request unchanged.
        if (dp.dst_port == MODBUS_TCP_PORT && mb.diagnostics_sub_function) {
            uint16_t sub = *mb.diagnostics_sub_function;
            if (sub == 0x0004) {
                // Force Listen Only Mode -- per spec the target sends NO response to this command at
                // all (confirmed against the real capture above: every 0x0004 request there has no
                // matching reply), so its own silence afterward is the expected, correct behavior,
                // not evidence of a fault.
                record_always_notable(
                    "modbus-force-listen-only", DetectionCategory::EngineeringStationActivity,
                    mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    "Modbus Diagnostics Force Listen Only Mode (sub-function 0x0004) -- the target "
                    "device is being commanded to stop responding to requests entirely (per spec it "
                    "sends no reply to this command itself, so its silence afterward is expected, "
                    "not a fault)");
            } else if (sub == 0x0001) {
                record_always_notable(
                    "modbus-restart-comm", DetectionCategory::FirmwareLogicChange,
                    mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    "Modbus Diagnostics Restart Communications Option (sub-function 0x0001) -- the "
                    "target device's own communication event log and interfaces are being "
                    "reinitialized on command");
            } else if (sub == 0x000A) {
                // T0872 (Indicator Removal on Host) -- the one Batch 1 pattern needing a MITRE
                // technique this codebase didn't already cite; see mitre_attack_ics.hpp's own header
                // comment for its own separate attack.mitre.org verification. ProtocolMisuse is the
                // closest fit of this engine's four categories -- clearing diagnostic counters is
                // neither a mode change, a firmware/logic change, nor a remote-access event, but it
                // is an ICS protocol command that can be used to erase evidence of prior errors or
                // probing, the same "protocol command doing something it's not routinely used for"
                // shape ProtocolMisuse already covers elsewhere in this file. Moderate, not Critical
                // -- clearing counters has no direct control-plane effect on the process itself.
                record_always_notable(
                    "modbus-clear-counters", DetectionCategory::ProtocolMisuse,
                    mitre_t0872_indicator_removal_on_host(), dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    "Modbus Diagnostics Clear Counters and Diagnostic Registers (sub-function 0x000A) "
                    "-- the target device's own diagnostic counters and event log are being reset, "
                    "which (alongside legitimate maintenance use) can also mask evidence of prior "
                    "communication errors or probing",
                    DetectionSeverity::Moderate);
            }
        }

        // --- Modbus Read Device Identification (function 0x2B, MEI type 0x0E) / Report Server ID
        // --- (function 0x11) from a new client (Batch 1 items 4-5) ---------------------------------
        // Both are engineering-tool-shaped reconnaissance (a device-identity/vendor-info query), and
        // -- per this project's own research doc -- deliberately resolved as NEW-VS-KNOWN candidates
        // (record_new_conduit_candidate, baseline-or-first-occurrence novelty) rather than as
        // always-notable findings the way Quickdraw's own rules treat them: any single such query is
        // ordinary engineering-tool behavior, and only its NOVELTY (a client not seen doing this
        // before, or genuinely absent from a supplied baseline) is the honestly-supportable signal
        // here -- see this engine's own header comment on the always-notable-vs-new-vs-known split.
        // Informational severity, matching umas-new-originator-discovery's own posture above: this is
        // read-only enumeration with no control-plane effect if genuine. Same request-side-only
        // direction gate as the Diagnostics block above, for the same reason (Report Server ID's own
        // response is a longer, differently-shaped byte-count-prefixed reply in practice, but this
        // decoder does not parse deep enough to rely on that shape difference -- the well-known-port
        // heuristic is simpler and matches this file's own existing precedent).
        if (dp.dst_port == MODBUS_TCP_PORT) {
            if (mb.mei_type && *mb.mei_type == 0x0E) {
                record_new_conduit_candidate(
                    DetectionCategory::EngineeringStationActivity,
                    mitre_t0888_remote_system_information_discovery(),
                    /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    "modbus-new-originator-read-device-id", DetectionSeverity::Informational);
            } else if (mb.function_name == "Report Server ID") {
                record_new_conduit_candidate(
                    DetectionCategory::EngineeringStationActivity,
                    mitre_t0888_remote_system_information_discovery(),
                    /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                    "modbus-new-originator-report-server-id", DetectionSeverity::Informational);
            }
        }

        // --- Modbus: repeated exception-code response burst (Batch 1 item 6) -----------------------
        // A server returning the SAME exception code 3+ times to the SAME client within roughly 60
        // seconds -- see kModbusExceptionBurstThreshold/kModbusExceptionBurstWindowSeconds' own
        // comment above for the Quickdraw-Snort SIDs this generalizes. Windowed (unlike
        // bacnet_who_is_count_by_source_'s own whole-capture running count above): a burst genuinely
        // needs to be CLOSE TOGETHER in time to mean anything, so the window resets whenever the gap
        // since its own first occurrence exceeds kModbusExceptionBurstWindowSeconds, rather than
        // counting every exception across an entire multi-hour capture as one running total. This is
        // the exception RESPONSE itself (mb.is_exception, sent server -> client), so dp.src_ip is the
        // server and dp.dst_ip is the client here -- the reverse of every other Modbus finding source
        // in this file, the same direction-reversal dnp3-unsolicited-misuse's own comment above
        // documents for DNP3 Unsolicited Response.
        if (mb.is_exception) {
            std::string key =
                dp.dst_ip + "|" + dp.src_ip + "|" + std::to_string(static_cast<unsigned>(mb.exception_code));
            auto ebit = modbus_exception_burst_state_.find(key);
            if (admit_tracked_key(ebit != modbus_exception_burst_state_.end(), modbus_exception_burst_state_.size(),
                                   "modbus_exception_burst_state_")) {
                if (ebit == modbus_exception_burst_state_.end()) {
                    ebit = modbus_exception_burst_state_.emplace(key, ModbusExceptionBurstState{}).first;
                }
                ModbusExceptionBurstState& st = ebit->second;
                if (st.count == 0 || (dp.timestamp - st.window_start) > kModbusExceptionBurstWindowSeconds) {
                    st.window_start = dp.timestamp;
                    st.count = 0;
                }
                ++st.count;
                if (st.count >= kModbusExceptionBurstThreshold) {
                    std::ostringstream d;
                    d << "Modbus server returned exception code " << modbus_exception_name(mb.exception_code)
                      << " to the same client at least " << kModbusExceptionBurstThreshold << " times within "
                      << static_cast<long>(kModbusExceptionBurstWindowSeconds)
                      << "s -- a real, if weak, probing/instability signal (an engineering tool or a "
                         "scanner repeatedly hitting a function the device can't currently service), but "
                         "legitimate retry/backoff logic can trigger this too";
                    record_always_notable("modbus-exception-burst", DetectionCategory::ProtocolMisuse,
                                           mitre_t0855_unauthorized_command_message(), dp.dst_ip, dp.src_ip,
                                           "modbus", dp.src_port, d.str(), DetectionSeverity::Moderate);
                }
            }
        }

        // --- Modbus: known scanner-tool byte-exact fingerprints (Batch 2 items 10-11) --------------
        // Gated to the request side (dp.dst_port == MODBUS_TCP_PORT), same convention as the
        // Diagnostics/Read-Device-ID/Report-Server-ID blocks above -- every fingerprint below is a
        // fixed, tool-generated PROBE, which only ever travels client -> server. Every byte each
        // fingerprint checks is already an individually-decoded ModbusFrame field (transaction_id/
        // protocol_id/mbap_length/unit_id/function_code) or raw_pdu_data (already exposed "for hex
        // fallback/JSON", modbus.hpp, covering the PDU bytes after the function code) -- no new
        // decode work or raw-frame-byte exposure was needed for this batch, resolving what the
        // research doc's own readiness note had flagged as a possible open architecture question.
        if (dp.dst_port == MODBUS_TCP_PORT) {
            // Item 10: Metasploit's scada/modbus_findunitid / modbus_detect auxiliary modules' own
            // fixed Read Holding Registers probe -- CyberICS SID 101563260, exact byte match
            // |21 00 00 00 00 06 01 04 00 01 00 00|. Broken down: transaction_id=0x2100,
            // protocol_id=0x0000, mbap_length=6, unit_id=1, function_code=0x04 (Read Holding
            // Registers), PDU data (raw_pdu_data) = start_address 0x0001, quantity 0x0000 -- a
            // request asking for ZERO registers, which has no legitimate purpose and is fixed only by
            // the module's own hardcoded probe framing. Moderate, not Informational (unlike the nmap
            // fingerprints below): Metasploit is exploit-adjacent tooling, not pure reconnaissance --
            // see the research doc's own "Informational-to-Moderate" call.
            if (mb.transaction_id == 0x2100 && mb.protocol_id == 0x0000 && mb.mbap_length == 6 &&
                mb.unit_id == 1 && mb.function_code == 0x04 &&
                raw_pdu_matches(mb.raw_pdu_data, {0x00, 0x01, 0x00, 0x00})) {
                record_always_notable(
                    "modbus-scanner-metasploit", DetectionCategory::ProtocolMisuse,
                    mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip, "modbus",
                    dp.dst_port,
                    "Modbus request byte-exact matches Metasploit's scada/modbus_findunitid / "
                    "modbus_detect auxiliary modules' own fixed probe framing (a Read Holding "
                    "Registers request for zero registers, transaction ID 0x2100) -- an automated "
                    "scanner/exploit-framework fingerprint, not ordinary engineering-tool traffic",
                    DetectionSeverity::Moderate);
            }

            // Item 11: nmap's modbus-discover.nse -- CyberICS SIDs 101563263/101563264, independently
            // cross-checked against nmap's own published source during this project's original
            // research pass. Two distinct fixed probes, the SAME function codes as Batch 1 items 4/5's
            // generic new-vs-known findings, but nmap's own fixed framing is a distinct, higher-
            // confidence, tool-specific signal worth its own finding rather than folding into the
            // generic one -- two separate finding_kind tags (not one shared tag) so a conduit hit by
            // BOTH nmap probes gets two findings, not one silently overwriting the other's own
            // description (see always_notable_key's own comment on why finding_kind exists at all).
            if (mb.transaction_id == 0x0000 && mb.protocol_id == 0x0000 && mb.mbap_length == 2 &&
                mb.unit_id == 1 && mb.function_code == 0x11 && mb.raw_pdu_data.empty()) {
                // Report Server ID (0x11) -- |00 00 00 00 00 02 01 11|, no PDU data beyond the
                // function code itself.
                record_always_notable(
                    "modbus-scanner-nmap-report-server-id", DetectionCategory::ProtocolMisuse,
                    mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip, "modbus",
                    dp.dst_port,
                    "Modbus Report Server ID request byte-exact matches nmap's modbus-discover.nse own "
                    "fixed probe framing (transaction ID 0x0000, unit ID 1) -- reconnaissance tooling, "
                    "not ordinary engineering-tool traffic",
                    DetectionSeverity::Informational);
            }
            if (mb.transaction_id == 0x0000 && mb.protocol_id == 0x0000 && mb.mbap_length == 5 &&
                mb.unit_id == 1 && mb.function_code == 0x2B &&
                raw_pdu_matches(mb.raw_pdu_data, {0x0E, 0x01, 0x00})) {
                // Read Device Identification (0x2B, MEI 0x0E) -- |00 00 00 00 00 05 01 2b 0e 01 00|:
                // MEI type 0x0E, Read Device ID code 0x01 ("Read Device ID (basic)"), object ID 0x00.
                record_always_notable(
                    "modbus-scanner-nmap-read-device-id", DetectionCategory::ProtocolMisuse,
                    mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip, "modbus",
                    dp.dst_port,
                    "Modbus Read Device Identification request byte-exact matches nmap's "
                    "modbus-discover.nse own fixed probe framing (transaction ID 0x0000, unit ID 1, "
                    "MEI type 0x0E, Read Device ID code 0x01) -- reconnaissance tooling, not ordinary "
                    "engineering-tool traffic",
                    DetectionSeverity::Informational);
            }
        }
    }

    // --- Notable IT protocols: a Tier-1 remote-access protocol reaching a conduit (RemoteAccessChannel)
    // Every one of this feature's five Tier-1 protocols (rdp/vnc/teamviewer/anydesk/zoom,
    // notable_it_protocols.hpp) is IP-based, so dp.has_ip already guards this whole function; the
    // usual port-heuristic "lower port is the server" guess (mirroring
    // AssetInventoryEngine::observe's own InventoryNotableProtocol posture, since building real
    // per-protocol direction detection for these five is out of this feature's scope) decides
    // client/server here -- see write_detection_report_text/_json for how that's caveated.
    if (auto tier = notable_it_protocol_tier(dp.protocol); tier && *tier == "remote-access") {
        // "Lower port number is the server" -- default assumes dst_ip/dst_port is the server (true
        // whenever dst_port <= src_port); swapped only when src_port is actually the LOWER of the
        // two, meaning src_ip is the real server. Caught and fixed during this feature's own manual
        // verification pass: an earlier version of this condition had the comparison backwards
        // (swapping exactly when the default was already correct), which silently reported every
        // RDP/VNC/... finding with client and server reversed.
        std::string client_ip = dp.src_ip, server_ip = dp.dst_ip;
        uint16_t server_port = dp.dst_port;
        if (dp.has_tcp && dp.src_port < dp.dst_port) {
            client_ip = dp.dst_ip;
            server_ip = dp.src_ip;
            server_port = dp.src_port;
        }
        // Heuristic evidence (not Confirmed, the default) -- Tier-1 identification here is
        // notable_it_protocols.hpp's own weakest, port-only tier, and client/server direction is the
        // "lower port number is the server" guess above, neither a field actually decoded off the
        // wire. Severity stays the record_new_conduit_candidate default (Moderate) -- a new
        // remote-access session is a real but not immediately control-affecting event.
        record_new_conduit_candidate(DetectionCategory::RemoteAccessChannel, mitre_t0886_remote_services(),
                                      /*is_remote_access=*/true, client_ip, server_ip, dp.protocol,
                                      server_port, "remote-access", DetectionSeverity::Moderate,
                                      DetectionEvidence::Heuristic);
    }
}

DetectionReport DetectEngine::finish(const Policy* policy, const BaselineStore* baseline) const {
    DetectionReport report;
    report.total_packets = total_packets_;
    report.observation_truncated = truncated_;
    report.truncation_reasons = truncation_reasons_;
    // F4 fix (patch282 security review): fold in any flow-state evictions from this run -- see
    // append_flow_state_eviction_reason's own comment (resource_limits.hpp). truncated_/
    // truncation_reasons_ above only ever reflect this engine's own three DetectEngineLimits
    // growth ceilings; flow-state eviction is a decode()-layer condition this engine has no direct
    // visibility into otherwise.
    if (append_flow_state_eviction_reason(report.truncation_reasons)) report.observation_truncated = true;

    auto in_baseline = [&](const std::string& client_ip, const std::string& server_ip,
                            const std::string& protocol, uint16_t server_port) {
        if (!baseline) return false;
        for (const auto& cb : baseline->conduits) {
            if (cb.client_ip == client_ip && cb.server_ip == server_ip && cb.protocol == protocol &&
                cb.server_port == server_port) {
                return true;
            }
        }
        return false;
    };

    for (const auto& key : always_notable_order_) {
        report.findings.push_back(always_notable_.at(key));
    }

    for (const auto& key : new_conduit_order_) {
        const NewConduitCandidate& c = new_conduit_candidates_.at(key);
        if (in_baseline(c.client_ip, c.server_ip, c.protocol, c.server_port)) continue;  // not new

        DetectionFinding f;
        f.category = c.category;
        f.evidence = c.evidence;
        f.novelty = baseline ? DetectionNovelty::ConfirmedNew : DetectionNovelty::FirstOccurrence;
        f.severity = c.severity;
        f.client_ip = c.client_ip;
        f.server_ip = c.server_ip;
        f.protocol = c.protocol;
        f.server_port = c.server_port;
        f.first_seen = c.first_seen;
        f.last_seen = c.last_seen;
        f.packet_count = c.packet_count;

        if (c.is_remote_access) {
            // T0886 (Remote Services, no zone crossing) by default -- see this function's own doc
            // comment (detect_engine.hpp) for exactly when this upgrades to T0822 (External Remote
            // Services).
            f.technique = mitre_t0886_remote_services();
            bool crosses_zone = false;
            if (policy) {
                auto client_u32 = parse_ipv4_string(c.client_ip);
                auto server_u32 = parse_ipv4_string(c.server_ip);
                if (client_u32 && server_u32) {
                    const Zone* cz = policy->zone_for(*client_u32);
                    const Zone* sz = policy->zone_for(*server_u32);
                    if (cz && sz && cz->name != sz->name) crosses_zone = true;
                }
            }
            if (crosses_zone) f.technique = mitre_t0822_external_remote_services();
            std::ostringstream d;
            d << "New " << c.protocol << " (remote-access) session " << c.client_ip << " -> " << c.server_ip
              << ":" << c.server_port
              << (crosses_zone ? " -- crosses a declared zone boundary" : "");
            if (!baseline) {
                d << " -- first occurrence within this capture; no --baseline-file was supplied, so this "
                     "may already be a normal, previously-established channel -- rerun with "
                     "--baseline-file for a stronger signal";
            } else {
                d << " -- confirmed absent from the supplied baseline";
            }
            f.description = d.str();
        } else {
            f.technique = c.technique;
            std::ostringstream d;
            // source_tag picks the description template -- see NewConduitCandidate::source_tag's
            // own comment (detect_engine.hpp) for why this can't just be inferred from category/
            // technique alone (umas-new-originator-reservation shares ProtocolMisuse/T0855 with
            // cip-new-originator, but is a different UMAS command, not CIP).
            if (c.source_tag == "umas-new-originator-reservation") {
                d << "UMAS TAKE_PLC_RESERVATION from a new engineering-station originator " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen issuing an engineering-station "
                     "command to this PLC in this capture";
            } else if (c.source_tag == "umas-new-originator-discovery") {
                d << "UMAS read-only discovery command (READ_ID/READ_PROJECT_INFO/READ_PLC_INFO) from a "
                     "new engineering-station originator "
                  << c.client_ip << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen issuing an engineering-station "
                     "command to this PLC in this capture";
            } else if (c.source_tag == "modbus-new-originator-read-device-id") {
                // Batch 1 item 4 (docs/research/2026-09-detect-pattern-candidates-batch2.md) -- unlike
                // the CIP/UMAS sources above, this is NOT gated on "second-plus originator to this
                // server" (no per-server originator-set tracking of its own): every occurrence becomes
                // its own candidate, resolved purely by baseline-or-first-occurrence, matching the
                // research doc's own explicit proposal for this pattern (see detect_engine.cpp's own
                // call-site comment).
                d << "Modbus Read Device Identification (function 0x2B, MEI type 0x0E) from " << c.client_ip
                  << " to " << c.server_ip
                  << " -- an engineering-tool-shaped device-identity/vendor-info query";
            } else if (c.source_tag == "modbus-new-originator-report-server-id") {
                d << "Modbus Report Server ID (function 0x11) from " << c.client_ip << " to " << c.server_ip
                  << " -- an engineering-tool-shaped device-identity query";
            } else if (c.source_tag == "enip-new-originator-discovery") {
                // Batch 3 item 17 -- List Identity/Services/Interfaces from a second, different
                // originator (enip_list_discovery_originators_by_server_, detect_engine.hpp).
                // Deliberately its own branch, not folded into the cip-new-originator fallback below:
                // these three encapsulation commands carry no CIP message at all (no Forward_Open of
                // any kind), so that description would be actively wrong here.
                d << "EtherNet/IP List Identity/Services/Interfaces from a new originator " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen querying this target's own "
                     "device identity/services/interfaces in this capture";
            } else if (c.source_tag == "s7-szl-new-originator") {
                // Batch 4 item 19 -- S7 Read SZL enumeration from a second, different originator
                // (s7_szl_originators_by_server_, detect_engine.hpp).
                d << "S7 Read SZL request from a new originator " << c.client_ip << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen enumerating this PLC's own "
                     "identity/version information in this capture";
            } else if (c.source_tag == "fins-new-originator-discovery") {
                // Batch 4 item 22 -- FINS Controller Data Read from a second, different originator
                // (fins_originators_by_server_, detect_engine.hpp).
                d << "FINS Controller Data Read from a new originator " << c.client_ip << " to "
                  << c.server_ip
                  << " -- a different client than the one(s) already seen reading this PLC's own "
                     "model/version identification in this capture";
            } else if (c.source_tag == "bacnet-foreign-device-register-new-originator") {
                // Batch 4 item 21a -- Register-Foreign-Device from a second, different originator
                // (bacnet_foreign_device_register_originators_by_server_, detect_engine.hpp).
                d << "BACnet Register-Foreign-Device request from a new originator " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different device than the one(s) already seen registering as a foreign "
                     "device with this BBMD in this capture";
            } else if (c.source_tag == "bacnet-bbmd-table-read-new-originator") {
                // Batch 4 item 21b -- Read-Foreign-Device-Table/Read-Broadcast-Distribution-Table
                // from a second, different originator (bacnet_bbmd_table_read_originators_by_server_,
                // detect_engine.hpp).
                d << "BACnet Read-Foreign-Device-Table/Read-Broadcast-Distribution-Table request from "
                     "a new originator "
                  << c.client_ip << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen reading this BBMD's own "
                     "routing configuration in this capture";
            } else if (c.source_tag == "modbus-rogue-master") {
                // Batch 5 item 25 -- a second, different client issuing a write-classified Modbus
                // request against an outstation that already has an established write-capable master
                // (modbus_write_originators_by_server_, detect_engine.hpp). patch257 section 4.5's own
                // false-positive validation pass (docs/DEVELOPMENT.md) flagged this as the single
                // highest-risk finding in this engine for a redundant-controller failover: a standby
                // master becoming active and issuing its own writes to outstations the primary was
                // already writing to is EXACTLY this wire shape, and "Rogue Master" reads as
                // unambiguously hostile with no hedge -- hence the added clause below, matching this
                // file's own established pattern (dnp3-operate-without-select, modbus/dnp3-write-burst)
                // of naming a specific, plausible legitimate cause rather than leaving a Critical,
                // ambiguously-named finding to speak for itself.
                d << "Modbus write-classified request from a second write-capable master " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen issuing write-classified "
                     "requests to this outstation in this capture; can also be a redundant/standby "
                     "controller becoming active during a failover, not necessarily an unauthorized "
                     "master -- treat as a prompt to confirm which controller should be active, not "
                     "confirmed misuse";
            } else if (c.source_tag == "dnp3-rogue-master") {
                // Batch 5 item 25 -- the DNP3 analog of modbus-rogue-master above
                // (dnp3_write_originators_by_server_, detect_engine.hpp). Same patch257 4.5 hedge as
                // modbus-rogue-master above -- see that branch's own comment.
                d << "DNP3 write-classified request from a second write-capable master " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different master than the one(s) already seen issuing write-classified "
                     "requests to this outstation in this capture; can also be a redundant/standby "
                     "controller becoming active during a failover, not necessarily an unauthorized "
                     "master -- treat as a prompt to confirm which controller should be active, not "
                     "confirmed misuse";
            } else {
                // "cip-new-originator" -- the remaining, original non-remote-access source (the
                // fallback here, not because it's the only other one, but because it was this
                // engine's first such source and every branch above already covers the rest by name).
                d << "CIP Forward_Open from a new originator " << c.client_ip << " to " << c.server_ip
                  << " -- a different engineering/control client than the one(s) already seen opening a "
                     "connection to this target in this capture";
            }
            if (!baseline) {
                d << " (first occurrence within this capture; no --baseline-file was supplied)";
            } else {
                d << " (confirmed absent from the supplied baseline)";
            }
            f.description = d.str();
        }
        report.findings.push_back(std::move(f));
    }

    // --- S7comm Setup Communication probing (EngineeringStationActivity/T0888) -- resolved HERE,
    // not in observe(), because "no other S7comm function was ever seen for this pair" can only be
    // confirmed once the whole capture has been read (see s7_setup_comm_state_'s own comment,
    // detect_engine.hpp). Collected into a vector and sorted by key before appending, so the report
    // stays deterministic independent of s7_setup_comm_state_'s own unordered_map iteration order --
    // the same discipline always_notable_order_/new_conduit_order_ already established for
    // observe()-time findings above.
    {
        std::vector<std::pair<std::string, S7SetupCommProbeState>> qualifying;
        for (const auto& entry : s7_setup_comm_state_) {
            if (entry.second.setup_comm_count >= kS7SetupCommProbeThreshold && !entry.second.other_function_seen) {
                qualifying.emplace_back(entry.first, entry.second);
            }
        }
        std::sort(qualifying.begin(), qualifying.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        for (const auto& entry : qualifying) {
            const std::string& key = entry.first;
            const S7SetupCommProbeState& st = entry.second;
            size_t sep = key.find('|');
            std::string client_ip = sep == std::string::npos ? key : key.substr(0, sep);
            std::string server_ip = sep == std::string::npos ? "" : key.substr(sep + 1);
            DetectionFinding f;
            f.category = DetectionCategory::EngineeringStationActivity;
            f.technique = mitre_t0888_remote_system_information_discovery();
            f.evidence = DetectionEvidence::Confirmed;
            f.novelty = DetectionNovelty::NotApplicable;
            // Informational, not Critical/Moderate -- probing (repeated handshake, nothing else) is
            // reconnaissance-shaped with no direct control action, the same posture as
            // bacnet-who-is-flood/modbus-write-without-read above.
            f.severity = DetectionSeverity::Informational;
            f.client_ip = client_ip;
            f.server_ip = server_ip;
            f.protocol = "s7comm";
            f.server_port = 102;
            f.first_seen = st.first_seen;
            f.last_seen = st.last_seen;
            f.packet_count = st.setup_comm_count;
            std::ostringstream d;
            d << "S7comm Setup Communication (function 0xF0) seen " << st.setup_comm_count << " times from "
              << client_ip << " to " << server_ip
              << " with no other S7comm function ever observed between them in this capture -- consistent "
                 "with connection/session probing rather than genuine engineering-station use (a real "
                 "engineering session does more than repeat the handshake)";
            f.description = d.str();
            report.findings.push_back(std::move(f));
        }
    }

    // --- Composite: a Program Download (T0843) and a restart/mode-change (T0858/T0816) finding both
    // against the same server within kCompositeWindowSeconds -- the classic "download then activate"
    // attack sequence, not necessarily two unrelated events. A post-pass over this SAME finish()
    // call's own already-produced findings (everything pushed to report.findings above, from every
    // source: always-notable, resolved new-conduit, S7 probing) -- needs no new observe()-time
    // tracking of its own. At most ONE composite per server_ip (the closest-in-time download/restart
    // pair), so a server with several downloads and restarts doesn't spam several overlapping
    // composites for what's realistically one incident.
    {
        std::unordered_map<std::string, std::vector<const DetectionFinding*>> downloads_by_server;
        std::unordered_map<std::string, std::vector<const DetectionFinding*>> restarts_by_server;
        for (const auto& f : report.findings) {
            if (f.technique.id == "T0843") {
                downloads_by_server[f.server_ip].push_back(&f);
            } else if (f.technique.id == "T0858" || f.technique.id == "T0816") {
                restarts_by_server[f.server_ip].push_back(&f);
            }
        }
        std::vector<DetectionFinding> composites;
        for (const auto& entry : downloads_by_server) {
            const std::string& server_ip = entry.first;
            const std::vector<const DetectionFinding*>& downloads = entry.second;
            auto rit = restarts_by_server.find(server_ip);
            if (rit == restarts_by_server.end()) continue;
            const DetectionFinding* best_download = nullptr;
            const DetectionFinding* best_restart = nullptr;
            double best_gap = -1.0;
            for (const auto* d : downloads) {
                for (const auto* r : rit->second) {
                    double gap = std::fabs(d->first_seen - r->first_seen);
                    if (gap <= kCompositeWindowSeconds && (best_gap < 0.0 || gap < best_gap)) {
                        best_gap = gap;
                        best_download = d;
                        best_restart = r;
                    }
                }
            }
            if (!best_download || !best_restart) continue;
            DetectionFinding f;
            f.category = DetectionCategory::FirmwareLogicChange;
            f.technique = mitre_t0831_manipulation_of_control();
            f.evidence = DetectionEvidence::Confirmed;
            f.novelty = DetectionNovelty::NotApplicable;
            f.severity = DetectionSeverity::Critical;  // the classic "install then activate" sequence
            f.client_ip = best_download->client_ip;
            f.server_ip = server_ip;
            f.protocol = best_download->protocol;
            f.server_port = best_download->server_port;
            f.first_seen = std::min(best_download->first_seen, best_restart->first_seen);
            f.last_seen = std::max(best_download->last_seen, best_restart->last_seen);
            f.packet_count = best_download->packet_count + best_restart->packet_count;
            std::ostringstream d;
            // patch257 section 4.5's own false-positive validation pass (docs/DEVELOPMENT.md) flagged
            // this composite as the single highest-risk finding in this engine for a legitimate
            // firmware/logic upgrade: stop-or-download-then-restart is not just plausibly triggered by
            // a routine, authorized upgrade -- it's the literal, universal shape of one. The caveat
            // below says so explicitly, alongside (not instead of) the attack-pattern framing, matching
            // this file's own "name the plausible legitimate cause, let severity reflect impact not
            // intent" convention used elsewhere (dnp3/modbus-rogue-master, dnp3-operate-without-select).
            d << "Composite finding: a firmware/logic download (" << best_download->technique.id << " "
              << best_download->technique.name << ", " << best_download->protocol
              << ") and a restart/mode-change (" << best_restart->technique.id << " "
              << best_restart->technique.name << ", " << best_restart->protocol << ") both observed against "
              << server_ip << " within " << static_cast<long>(kCompositeWindowSeconds)
              << "s of each other -- consistent with a download-then-activate attack pattern, but this is "
                 "also the exact shape of a routine, authorized firmware/logic upgrade (stop or download, "
                 "then restart to activate it); severity reflects the operational impact of this sequence "
                 "if unauthorized, not a determination that it was -- see the individual findings above "
                 "for each event's own detail";
            f.description = d.str();
            composites.push_back(std::move(f));
        }
        std::sort(composites.begin(), composites.end(),
                  [](const DetectionFinding& a, const DetectionFinding& b) { return a.server_ip < b.server_ip; });
        for (auto& c : composites) report.findings.push_back(std::move(c));
    }

    for (const auto& f : report.findings) {
        ++report.summary.total;
        switch (f.severity) {
            case DetectionSeverity::Critical: ++report.summary.critical; break;
            case DetectionSeverity::Moderate: ++report.summary.moderate; break;
            case DetectionSeverity::Informational: ++report.summary.informational; break;
        }
        switch (f.evidence) {
            case DetectionEvidence::Confirmed: ++report.summary.confirmed_evidence; break;
            case DetectionEvidence::Heuristic: ++report.summary.heuristic_evidence; break;
        }
        switch (f.category) {
            case DetectionCategory::EngineeringStationActivity: ++report.summary.engineering_station_activity; break;
            case DetectionCategory::FirmwareLogicChange: ++report.summary.firmware_logic_change; break;
            case DetectionCategory::RemoteAccessChannel: ++report.summary.remote_access_channel; break;
            case DetectionCategory::ProtocolMisuse: ++report.summary.protocol_misuse; break;
        }
    }
    return report;
}

void write_detection_report_text(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    (void)resolver;  // reserved for a future service-name annotation pass, matching every other
                      // report writer's Resolver parameter -- not yet used, see LIMITATIONS
    out << "=== conduitscope detect report ===\n";
    out << "capture: " << capture_path << "\n";
    out << "total packets: " << report.total_packets << "\n";
    out << "findings: " << report.summary.total << " (Critical " << report.summary.critical << ", Moderate "
        << report.summary.moderate << ", Informational " << report.summary.informational << ")\n";
    out << "  evidence: Confirmed " << report.summary.confirmed_evidence << ", Heuristic "
        << report.summary.heuristic_evidence << "\n";
    out << "  Engineering-Station Activity: " << report.summary.engineering_station_activity << "\n";
    out << "  Firmware/Logic Change: " << report.summary.firmware_logic_change << "\n";
    out << "  Remote-Access Channel: " << report.summary.remote_access_channel << "\n";
    out << "  Protocol Misuse: " << report.summary.protocol_misuse << "\n";
    out << "note: evidence/novelty/severity never assert malicious intent -- see USER_GUIDE.md's DETECT\n";
    out << "      section. That judgment belongs to the human analyst reading this report.\n";

    // patch257 finding 3 fix: printed even when findings is empty -- an empty/short finding list here
    // is only ever a partial view once this is true (see DetectEngineLimits' own comment,
    // detect_engine.hpp), and the CLI layer already refuses to let this exit cleanly
    // (kExitObservationIncomplete, cli_main.cpp), so the text report must say so plainly too.
    if (report.observation_truncated) {
        out << "\n*** OBSERVATION INCOMPLETE -- this capture hit at least one of DetectEngine's "
               "internal limits, so the findings above reflect only PART of what the capture "
               "actually contains. Any \"no findings\" result is NOT trustworthy until this is "
               "resolved (raise the relevant --max-detect-* limit and re-run). ***\n";
        for (const std::string& reason : report.truncation_reasons) {
            out << "  - " << reason << "\n";
        }
    }

    if (report.findings.empty()) {
        out << "\nno findings\n";
        return;
    }

    out << "\n--- findings (first-seen order) ---\n";
    for (const auto& f : report.findings) {
        out << "\n[" << detection_category_name(f.category) << "] " << f.technique.id << " ("
            << f.technique.name << ")\n";
        out << "  evidence: " << detection_evidence_name(f.evidence)
            << "  novelty: " << detection_novelty_name(f.novelty)
            << "  severity: " << detection_severity_name(f.severity) << "\n";
        out << "  " << f.client_ip << " -> " << f.server_ip;
        if (f.server_port != 0) out << ":" << f.server_port;
        out << " (" << f.protocol << ")\n";
        out << "  " << f.description << "\n";
        out << "  first seen: " << format_epoch_seconds(f.first_seen)
            << "  last seen: " << format_epoch_seconds(f.last_seen) << "  packets: " << f.packet_count
            << "\n";
    }
}

void write_detection_report_json(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    (void)resolver;
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(capture_path) << "\",\n";
    out << "  \"total_packets\": " << report.total_packets << ",\n";
    out << "  \"summary\": {\n";
    out << "    \"total\": " << report.summary.total << ",\n";
    out << "    \"critical\": " << report.summary.critical << ",\n";
    out << "    \"moderate\": " << report.summary.moderate << ",\n";
    out << "    \"informational\": " << report.summary.informational << ",\n";
    out << "    \"confirmed_evidence\": " << report.summary.confirmed_evidence << ",\n";
    out << "    \"heuristic_evidence\": " << report.summary.heuristic_evidence << ",\n";
    out << "    \"engineering_station_activity\": " << report.summary.engineering_station_activity << ",\n";
    out << "    \"firmware_logic_change\": " << report.summary.firmware_logic_change << ",\n";
    out << "    \"remote_access_channel\": " << report.summary.remote_access_channel << ",\n";
    out << "    \"protocol_misuse\": " << report.summary.protocol_misuse << "\n";
    out << "  },\n";
    out << "  \"note\": \"evidence/novelty/severity never assert malicious intent -- that judgment "
           "belongs to the human analyst reading this report\",\n";
    // Same shape as BaselineCheckReport's own observation_truncated/truncation_reasons JSON fields
    // (write_baseline_check_report_json, baseline.cpp) -- a caller parsing this JSON must check
    // observation_truncated, not just an empty findings array, to know the report is complete.
    out << "  \"observation_truncated\": " << (report.observation_truncated ? "true" : "false") << ",\n";
    out << "  \"truncation_reasons\": [";
    for (size_t i = 0; i < report.truncation_reasons.size(); ++i) {
        if (i) out << ", ";
        out << "\"" << json_escape(report.truncation_reasons[i]) << "\"";
    }
    out << "],\n";

    out << "  \"techniques_referenced\": [\n";
    auto techniques = all_mitre_attack_ics_techniques();
    for (size_t i = 0; i < techniques.size(); ++i) {
        out << "    {\"id\": \"" << json_escape(techniques[i].id) << "\", \"name\": \""
            << json_escape(techniques[i].name) << "\"}" << (i + 1 < techniques.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"findings\": [";
    bool first = true;
    for (const auto& f : report.findings) {
        out << (first ? "\n" : ",\n");
        first = false;
        out << "    {\n";
        out << "      \"category\": \"" << json_escape(detection_category_name(f.category)) << "\",\n";
        out << "      \"technique_id\": \"" << json_escape(f.technique.id) << "\",\n";
        out << "      \"technique_name\": \"" << json_escape(f.technique.name) << "\",\n";
        out << "      \"evidence\": \"" << json_escape(detection_evidence_name(f.evidence)) << "\",\n";
        out << "      \"novelty\": \"" << json_escape(detection_novelty_name(f.novelty)) << "\",\n";
        out << "      \"severity\": \"" << json_escape(detection_severity_name(f.severity)) << "\",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"description\": \"" << json_escape(f.description) << "\",\n";
        out << "      \"first_seen\": " << f.first_seen << ",\n";
        out << "      \"first_seen_text\": \"" << json_escape(format_epoch_seconds(f.first_seen)) << "\",\n";
        out << "      \"last_seen\": " << f.last_seen << ",\n";
        out << "      \"last_seen_text\": \"" << json_escape(format_epoch_seconds(f.last_seen)) << "\",\n";
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }";
    }
    out << (first ? "" : "\n") << "  ]\n";
    out << "}\n";
}

namespace {

// Middle-of-band CEF 0-10 severity for each DetectionSeverity -- see write_detection_report_cef's
// own doc comment (detect_engine.hpp) for why the middle of the band, not an edge.
int detection_severity_to_cef(DetectionSeverity severity) {
    switch (severity) {
        case DetectionSeverity::Critical: return 9;
        case DetectionSeverity::Moderate: return 5;
        case DetectionSeverity::Informational: return 2;
    }
    return 2;
}

// Builds one finding's own CEF/LEEF extension field list -- shared by write_detection_report_cef
// and write_detection_report_leef so the two never drift on which fields each finding carries.
std::vector<std::pair<std::string, std::string>> detection_finding_extension_fields(const DetectionFinding& f) {
    std::vector<std::pair<std::string, std::string>> fields;
    fields.emplace_back("src", f.client_ip);
    fields.emplace_back("dst", f.server_ip);
    if (f.server_port != 0) fields.emplace_back("dpt", std::to_string(f.server_port));
    fields.emplace_back("proto", f.protocol);
    fields.emplace_back("cat", detection_category_name(f.category));
    fields.emplace_back("msg", f.description);
    fields.emplace_back("cs1Label", "Evidence");
    fields.emplace_back("cs1", detection_evidence_name(f.evidence));
    fields.emplace_back("cs2Label", "Novelty");
    fields.emplace_back("cs2", detection_novelty_name(f.novelty));
    fields.emplace_back("cnt", std::to_string(f.packet_count));
    // CEF's own standard dictionary keys "start"/"end": milliseconds since epoch. LEEF's guide
    // documents the same two keys with the same meaning, so this one field list serves both.
    fields.emplace_back("start", std::to_string(static_cast<long long>(f.first_seen * 1000.0)));
    fields.emplace_back("end", std::to_string(static_cast<long long>(f.last_seen * 1000.0)));
    return fields;
}

}  // namespace

void write_detection_report_cef(std::ostream& out, const DetectionReport& report) {
    // F4 fix: see observation_incomplete_extension_fields's own comment (security_event_format.hpp)
    // for why this sentinel line must come first, unconditionally on observation_truncated alone --
    // a truncated run with zero findings would otherwise emit nothing here at all.
    if (report.observation_truncated) {
        out << render_cef_line("conduitscope-detect", "ObservationIncomplete", "Observation incomplete",
                                kObservationIncompleteCefSeverity,
                                observation_incomplete_extension_fields(report.truncation_reasons))
            << "\n";
    }
    for (const auto& f : report.findings) {
        out << render_cef_line("conduitscope-detect", f.technique.id, f.technique.name,
                                detection_severity_to_cef(f.severity), detection_finding_extension_fields(f))
            << "\n";
    }
}

void write_detection_report_leef(std::ostream& out, const DetectionReport& report) {
    if (report.observation_truncated) {
        out << render_leef_line("conduitscope-detect", "ObservationIncomplete",
                                 observation_incomplete_extension_fields(report.truncation_reasons))
            << "\n";
    }
    for (const auto& f : report.findings) {
        auto fields = detection_finding_extension_fields(f);
        fields.emplace_back("sev", std::to_string(detection_severity_to_cef(f.severity)));
        out << render_leef_line("conduitscope-detect", f.technique.id, fields) << "\n";
    }
}

void write_detection_report_syslog(std::ostream& out, const DetectionReport& report) {
    if (report.observation_truncated) {
        std::string cef_payload =
            render_cef_line("conduitscope-detect", "ObservationIncomplete", "Observation incomplete",
                             kObservationIncompleteCefSeverity,
                             observation_incomplete_extension_fields(report.truncation_reasons));
        out << render_rfc5424_line(kObservationIncompleteCefSeverity, "detect", cef_payload) << "\n";
    }
    for (const auto& f : report.findings) {
        int cef_severity = detection_severity_to_cef(f.severity);
        std::string cef_payload = render_cef_line("conduitscope-detect", f.technique.id, f.technique.name,
                                                    cef_severity, detection_finding_extension_fields(f));
        out << render_rfc5424_line(cef_severity, "detect", cef_payload) << "\n";
    }
}

}  // namespace conduitscope
