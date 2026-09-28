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
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/notable_it_protocols.hpp"
#include "conduitscope/resolver.hpp"
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
        std::string key = always_notable_key(finding_kind, client_ip, server_ip, protocol, server_port);
        auto it = always_notable_.find(key);
        if (it == always_notable_.end()) {
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
            }

            // Setup Communication (0xF0) probing state -- see s7_setup_comm_state_'s own comment
            // (detect_engine.hpp) for why this is only TRACKED here and resolved later, in finish().
            // Every branch of this whole if/else-if chain above (including the three not otherwise
            // named here) counts as "some other function was seen" except Setup Communication itself
            // -- a genuine engineering-station session does real work beyond the initial handshake.
            if (sr.function_name == "Setup Communication") {
                S7SetupCommProbeState& st = s7_setup_comm_state_[dp.src_ip + "|" + dp.dst_ip];
                if (st.setup_comm_count == 0) st.first_seen = dp.timestamp;
                st.last_seen = dp.timestamp;
                ++st.setup_comm_count;
            } else {
                s7_setup_comm_state_[dp.src_ip + "|" + dp.dst_ip].other_function_seen = true;
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
                Dnp3EnumerationSweepState& est = dnp3_enumeration_sweep_state_[ekey];
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
            } else if (dr.dnp3_function_name == "Enable Unsolicited Responses") {
                dnp3_unsolicited_enabled_[dp.src_ip + "|" + dp.dst_ip] = true;
            } else if (dr.dnp3_function_name == "Disable Unsolicited Responses") {
                dnp3_unsolicited_enabled_[dp.src_ip + "|" + dp.dst_ip] = false;
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
                dnp3_select_seen_[dp.src_ip + "|" + dp.dst_ip] = true;
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
            static const std::vector<std::string> kDnp3WriteFunctionNames = dnp3_write_function_names();
            bool is_dnp3_write = std::find(kDnp3WriteFunctionNames.begin(), kDnp3WriteFunctionNames.end(),
                                            dr.dnp3_function_name) != kDnp3WriteFunctionNames.end();
            if (is_dnp3_write && (dr.destination_address == 0xFFFF || dr.destination_address == 0xFFFE ||
                                   dr.destination_address == 0xFFFD)) {
                std::ostringstream d;
                d << "DNP3 " << dr.dnp3_function_name << " addressed to reserved broadcast destination "
                     "address 0x" << std::hex << dr.destination_address << std::dec
                  << " -- reaches every outstation on the segment at once, a single message with "
                     "plant-wide blast radius";
                record_always_notable("dnp3-broadcast-command", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "dnp3", dp.dst_port, d.str());
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
            bf.npdu.apdu.service_choice_name == "who-Is") {
            size_t count = ++bacnet_who_is_count_by_source_[dp.src_ip];
            if (count >= kBacnetWhoIsFloodThreshold) {
                record_always_notable(
                    "bacnet-who-is-flood", DetectionCategory::ProtocolMisuse,
                    mitre_t0888_remote_system_information_discovery(), dp.src_ip, dp.dst_ip, "bacnet",
                    dp.dst_port,
                    "BACnet Who-Is flood/device-enumeration sweep from this source -- at least " +
                        std::to_string(kBacnetWhoIsFloodThreshold) +
                        " Who-Is requests observed in this capture (destination shown is only the "
                        "most recent one -- Who-Is is routinely broadcast, so this source may have "
                        "targeted several destinations)",
                    DetectionSeverity::Informational);
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
            auto& originators = cip_originators_by_server_[dp.dst_ip];
            bool already_seen = false;
            for (const auto& o : originators) {
                if (o == dp.src_ip) {
                    already_seen = true;
                    break;
                }
            }
            if (!already_seen) {
                if (!originators.empty()) {
                    record_new_conduit_candidate(DetectionCategory::ProtocolMisuse,
                                                  mitre_t0855_unauthorized_command_message(),
                                                  /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "enip",
                                                  dp.dst_port, "cip-new-originator");
                }
                originators.push_back(dp.src_ip);
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
            } else if (fc == UMAS_TAKE_PLC_RESERVATION || fc == UMAS_READ_ID ||
                       fc == UMAS_READ_PROJECT_INFO || fc == UMAS_READ_PLC_INFO) {
                // Same "second-plus originator to a given server is new, first is not" mechanism as
                // the CIP Forward_Open branch above (cip_originators_by_server_), generalized
                // across all four of these UMAS commands via one shared per-server originator set
                // (umas_engineering_originators_by_server_) rather than one map per command -- see
                // that member's own comment (detect_engine.hpp) for why a client already credited
                // via one command isn't re-flagged for later issuing a different one.
                auto& originators = umas_engineering_originators_by_server_[dp.dst_ip];
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen) {
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
                            is_reservation ? "umas-new-originator-reservation" : "umas-new-originator-discovery",
                            is_reservation ? DetectionSeverity::Moderate : DetectionSeverity::Informational);
                    }
                    originators.push_back(dp.src_ip);
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
                modbus_merge_range_into(modbus_read_ranges_by_conduit_table_[conduit_key], {start, end});
            } else {
                const auto& read_ranges = modbus_read_ranges_by_conduit_table_[conduit_key];
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
            ModbusExceptionBurstState& st = modbus_exception_burst_state_[key];
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
            } else {
                // "cip-new-originator" -- the only other non-remote-access source this engine has.
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
            d << "Composite finding: a firmware/logic download (" << best_download->technique.id << " "
              << best_download->technique.name << ", " << best_download->protocol
              << ") and a restart/mode-change (" << best_restart->technique.id << " "
              << best_restart->technique.name << ", " << best_restart->protocol << ") both observed against "
              << server_ip << " within " << static_cast<long>(kCompositeWindowSeconds)
              << "s of each other -- consistent with a download-then-activate attack pattern, not "
                 "necessarily two unrelated findings; see the individual findings above for each event's "
                 "own detail";
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

}  // namespace conduitscope
