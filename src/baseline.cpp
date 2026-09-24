// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/baseline.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <optional>
#include <ostream>
#include <sstream>

#include "conduitscope/modbus.hpp"
#include "conduitscope/s7comm.hpp"

namespace conduitscope {

namespace {

// --------------------------------------------------------------------------------------------
// extract_operations() -- one function per in-scope protocol, see baseline.hpp's own comment.
// --------------------------------------------------------------------------------------------

// Modbus: operation_key is the function name alone (Phase 1 has exactly one address space per
// function, per the design doc), range is [start_address, start_address + quantity) when both are
// set. Deliberately reads ONLY mb.is_request == true frames: a read response carries no address at
// all (nothing to extract), and a write response ECHOES address+quantity back on the wire -- were
// this to also extract from is_request == false, a single write would be double-counted once from
// its request and once from its own paired response echo. See ModbusFrame::is_request's own
// comment (modbus.hpp) for the full per-function-family reasoning, including why Write Single
// Coil/Register never contributes an operation here at all (is_request is never true for that
// family -- see decode_write_single's own comment, modbus.cpp).
std::vector<Operation> extract_modbus_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const ModbusFrame& mb = dp.result->as<ModbusFrame>();
    if (!mb.is_request || mb.function_name.empty()) return ops;

    Operation op;
    op.protocol = "modbus";
    op.operation_key = mb.function_name;
    if (mb.start_address && mb.quantity) {
        op.has_target_range = true;
        op.range_start = *mb.start_address;
        op.range_end = static_cast<uint32_t>(*mb.start_address) + static_cast<uint32_t>(*mb.quantity);
    }
    ops.push_back(std::move(op));
    return ops;
}

// The wire-byte width of one element of S7ANY transport_size `ts`, or std::nullopt for a
// transport size this baseline doesn't know a fixed byte width for (BIT is handled separately by
// the caller, never reaches this function; every other unrecognized/reserved code falls through to
// std::nullopt, same "not decoded further" posture s7comm.cpp's own s7_transport_size_name takes
// for an unrecognized code). Mirrors the wire values s7comm.cpp's own s7_transport_size_name
// documents (BYTE/CHAR=1, WORD/INT/DATE=2, DWORD/DINT/REAL/TOD/TIME=4, DATE_AND_TIME=8) -- kept
// here rather than added to that function, since "how many bytes does this occupy" is a baseline-
// specific question s7comm.cpp's own display-name table has no other reason to answer.
std::optional<uint32_t> s7_transport_size_byte_width(uint8_t ts) {
    switch (ts) {
        case 0x02: return 1;  // BYTE
        case 0x03: return 1;  // CHAR
        case 0x04: return 2;  // WORD
        case 0x05: return 2;  // INT
        case 0x09: return 2;  // DATE
        case 0x06: return 4;  // DWORD
        case 0x07: return 4;  // DINT
        case 0x08: return 4;  // REAL
        case 0x0A: return 4;  // TOD
        case 0x0B: return 4;  // TIME
        case 0x0E: return 8;  // DATE_AND_TIME
        default: return std::nullopt;
    }
}

// True for the two S7ANY area codes (s7comm.hpp: 0x84 Data Block, 0x85 Instance Data Block) whose
// db_number is meaningful -- see S7Item::db_number's own comment ("meaningful when area is DB/DI").
bool s7_area_has_db_number(uint8_t area) { return area == 0x84 || area == 0x85; }

// True for the two S7ANY area codes (0x1C Counters, 0x1D Timers) whose wire address field is the
// counter/timer NUMBER itself, not a byte<<3|bit encoding -- see S7Item::byte_address's own comment
// ("for counter/timer areas, this is the counter/timer number instead").
bool s7_area_is_counter_or_timer(uint8_t area) { return area == 0x1C || area == 0x1D; }

// S7comm: one Operation per S7Item in a Read Var/Write Var Job's item list (a single Job can carry
// several items at different addresses; each is its own operation for baselining purposes, all
// sharing the same conduit -- see baseline.hpp's own header comment). Deliberately reads ONLY the
// Job (request) side: S7CommFrame::items (s7comm.hpp) is populated ONLY for function_code 0x04
// (Read Var) or 0x05 (Write Var) on the Job side -- the Ack_Data (response) side's own `items` is
// always empty (it carries `data_items`, values/return codes, never addresses) -- so `!sr.items.
// empty()` alone is already an authoritative "this is a request" signal, with nothing on the
// response side to double-count against in the first place (unlike Modbus writes, which need the
// explicit is_request check above).
//
// operation_key: "<function_name>/<area_name>[/DB<n>]" -- db_number is only appended for the two
// area codes it's actually meaningful for (s7_area_has_db_number); function_name alone already
// distinguishes Read Var from Write Var, so there's no need to also carry S7comm's own rosctr
// (which S7CommResult doesn't even expose -- see s7comm.hpp's own comment on why S7CommResult
// can't simply be an unmodified S7CommFrame).
//
// Range unit decision (transport_size BIT): a BIT-addressed item's natural address unit is BITS
// (bit_address), not bytes -- mixing bit-granularity and byte-granularity ranges under the same
// operation_key's observed_ranges would corrupt the interval math (a "bit 3" observation and a
// "byte 3" observation are not comparable numbers at all). Rather than give BIT items their own
// separate unit space (which would need transport_size baked into operation_key just for this one
// case, complicating every other area/transport-size combination that DOESN'T have this problem),
// this baseline folds BIT items into has_target_range = false: the operation itself (e.g. "Write
// Var/Merkers/Flags (M)") is still recorded and still participates in NewOperation detection --
// only its specific bit address is never range-checked. Documented explicitly here, per this
// file's own review instructions, rather than silently choosing one unit and hoping it's obvious.
std::vector<Operation> extract_s7comm_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const S7CommResult& sr = dp.result->as<S7CommResult>();
    if (!sr.has_function || sr.items.empty()) return ops;

    for (const S7Item& item : sr.items) {
        Operation op;
        op.protocol = "s7comm";
        std::ostringstream key;
        key << sr.function_name << "/" << item.area_name;
        if (s7_area_has_db_number(item.area)) {
            key << "/DB" << item.db_number;
        }
        op.operation_key = key.str();

        if (s7_area_is_counter_or_timer(item.area)) {
            // byte_address IS the counter/timer number here (see s7_area_is_counter_or_timer's own
            // comment); each element requested is one more counter/timer number, the same
            // "one unit per element" shape byte-granularity areas have, just with a fixed width of
            // 1 rather than a transport-size-dependent one.
            if (item.count > 0) {
                op.has_target_range = true;
                op.range_start = item.byte_address;
                op.range_end = item.byte_address + static_cast<uint32_t>(item.count);
            }
        } else if (item.is_experimental) {
            // 0xB2 (S7-1200/1500 symbolic addressing) items carry no transport_size/count at all
            // (see S7Item's own comment) -- nothing to build a byte range from; has_target_range
            // stays false.
        } else if (item.transport_size == 0x01) {
            // BIT -- see this function's own header comment above for why this is deliberately
            // excluded from range tracking rather than given a mismatched unit.
        } else if (auto width = s7_transport_size_byte_width(item.transport_size); width && item.count > 0) {
            op.has_target_range = true;
            op.range_start = item.byte_address;
            op.range_end = item.byte_address + static_cast<uint32_t>(item.count) * (*width);
        }
        // Any other case (an unrecognized transport size the byte-width table above doesn't know,
        // or count == 0) leaves has_target_range at its default false -- the operation is still
        // recorded, just without a range to check.

        ops.push_back(std::move(op));
    }
    return ops;
}

}  // namespace

std::vector<Operation> extract_operations(const DecodedPacket& packet) {
    if (packet.protocol == "modbus") return extract_modbus_operations(packet);
    if (packet.protocol == "s7comm") return extract_s7comm_operations(packet);
    return {};
}

// --------------------------------------------------------------------------------------------
// Interval merge-on-insert -- see OperationBaseline::observed_ranges' own comment (baseline.hpp).
// --------------------------------------------------------------------------------------------

// Merges half-open range `r` into the already-sorted, already-coalesced `ranges`, keeping it
// sorted and coalesced (adjacent or overlapping intervals combined into one). Linear scan, per the
// design doc: a handful of intervals per operation in practice, so no interval tree is needed here.
void merge_range_into(std::vector<std::pair<uint32_t, uint32_t>>& ranges, std::pair<uint32_t, uint32_t> r) {
    if (r.first >= r.second) return;  // empty/invalid range -- nothing to add
    ranges.push_back(r);
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    merged.reserve(ranges.size());
    for (const auto& cur : ranges) {
        // "<=" (not "<") so touching intervals coalesce too, e.g. [0,10) and [10,20) -> [0,20) --
        // see OperationBaseline::observed_ranges' own "coalesce adjacent/overlapping" comment.
        if (!merged.empty() && cur.first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, cur.second);
        } else {
            merged.push_back(cur);
        }
    }
    ranges = std::move(merged);
}

// True iff [start, end) is fully contained in one single entry of `ranges` -- since `ranges` is
// always already coalesced (merge_range_into's own invariant), a range spanning what were once two
// adjacent/overlapping baseline observations has already been merged into one entry, so checking
// each entry independently (rather than trying to union multiple entries together here) is
// sufficient and correct.
bool range_fully_covered(const std::vector<std::pair<uint32_t, uint32_t>>& ranges, uint32_t start, uint32_t end) {
    for (const auto& r : ranges) {
        if (r.first <= start && end <= r.second) return true;
    }
    return false;
}

// --------------------------------------------------------------------------------------------
// BaselineEngine -- per-capture observation, mirroring PolicyEngine::observe/
// AssetInventoryEngine::observe's own TCP-session client/server determination (see
// BaselineEngine::observe's own doc comment, baseline.hpp, for why this is reimplemented here
// rather than shared).
// --------------------------------------------------------------------------------------------

namespace {

std::string tcp_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b, uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

std::string conduit_key(const std::string& protocol, const std::string& client_ip, const std::string& server_ip,
                         uint16_t server_port) {
    return protocol + "|" + client_ip + "->" + server_ip + ":" + std::to_string(server_port);
}

// Just this feature's two in-scope ports -- Modbus/TCP and COTP (S7comm's own transport) -- the
// narrowed version of PolicyEngine::observe's/AssetInventoryEngine::observe's own is_known_service_
// port, restricted to the two protocols this engine ever extracts operations from.
bool is_known_baseline_port(uint16_t port) { return port == MODBUS_TCP_PORT || port == COTP_TCP_PORT; }

bool src_is_client_by_port(uint16_t src_port, uint16_t dst_port) {
    bool src_known = is_known_baseline_port(src_port);
    bool dst_known = is_known_baseline_port(dst_port);
    if (dst_known && !src_known) return true;
    if (src_known && !dst_known) return false;
    return src_port > dst_port;
}

}  // namespace

void BaselineEngine::observe(const DecodedPacket& dp) {
    if (!dp.has_ip || !dp.has_tcp) return;
    if (dp.protocol != "modbus" && dp.protocol != "s7comm") return;

    std::vector<Operation> ops = extract_operations(dp);
    if (ops.empty()) return;

    // Client/server direction: SYN/SYN-ACK first, known-port fallback otherwise -- see this
    // method's own doc comment (baseline.hpp) for why this mirrors PolicyEngine::observe/
    // AssetInventoryEngine::observe rather than sharing code with either.
    std::string skey = tcp_session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
    bool is_syn = dp.tcp_flags == "SYN";
    bool is_syn_ack = dp.tcp_flags.rfind("SYN,ACK", 0) == 0;

    auto sit = tcp_sessions_.find(skey);
    if (sit == tcp_sessions_.end()) {
        TcpSessionState st;
        bool src_is_client;
        if (is_syn) {
            src_is_client = true;
            st.initiator_known = true;
        } else if (is_syn_ack) {
            src_is_client = false;
            st.initiator_known = true;
        } else {
            src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
        }
        st.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        st.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        st.server_port = src_is_client ? dp.dst_port : dp.src_port;
        sit = tcp_sessions_.emplace(skey, std::move(st)).first;
    } else if (!sit->second.initiator_known && (is_syn || is_syn_ack)) {
        bool src_is_client = is_syn;
        sit->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        sit->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        sit->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
        sit->second.initiator_known = true;
    }
    const std::string& client_ip = sit->second.client_ip;
    const std::string& server_ip = sit->second.server_ip;
    uint16_t server_port = sit->second.server_port;

    std::string ckey = conduit_key(dp.protocol, client_ip, server_ip, server_port);
    auto cit = conduits_.find(ckey);
    if (cit == conduits_.end()) {
        ConduitState cs;
        cs.client_ip = client_ip;
        cs.server_ip = server_ip;
        cs.protocol = dp.protocol;
        cs.server_port = server_port;
        conduit_order_.push_back(ckey);
        cit = conduits_.emplace(ckey, std::move(cs)).first;
    }
    ConduitState& cs = cit->second;
    ++cs.packet_count;

    for (const Operation& op : ops) {
        auto oit = cs.operations.find(op.operation_key);
        if (oit == cs.operations.end()) {
            cs.operation_order.push_back(op.operation_key);
            oit = cs.operations.emplace(op.operation_key, OperationState{}).first;
        }
        OperationState& os = oit->second;
        ++os.packet_count;
        if (op.has_target_range) {
            os.has_target_range = true;
            merge_range_into(os.observed_ranges, {op.range_start, op.range_end});
        }
    }
}

std::vector<ConduitBaseline> BaselineEngine::finish() const {
    std::vector<ConduitBaseline> result;
    result.reserve(conduit_order_.size());
    for (const auto& ckey : conduit_order_) {
        const ConduitState& cs = conduits_.at(ckey);
        ConduitBaseline cb;
        cb.client_ip = cs.client_ip;
        cb.server_ip = cs.server_ip;
        cb.protocol = cs.protocol;
        cb.server_port = cs.server_port;
        cb.packet_count = cs.packet_count;
        for (const auto& okey : cs.operation_order) {
            const OperationState& os = cs.operations.at(okey);
            OperationBaseline ob;
            ob.operation_key = okey;
            ob.packet_count = os.packet_count;
            ob.has_target_range = os.has_target_range;
            ob.observed_ranges = os.observed_ranges;
            cb.operations.push_back(std::move(ob));
        }
        result.push_back(std::move(cb));
    }
    return result;
}

// --------------------------------------------------------------------------------------------
// merge_baseline_observations() -- `learn`'s own merge-into-store logic (baseline.hpp).
// --------------------------------------------------------------------------------------------

namespace {

// Finds `key`'s ConduitBaseline inside `store.conduits`, or nullptr -- linear scan (a real
// baseline file has, in practice, a handful to a few dozen conduits, matching every other engine's
// own "linear scan is fine at this scale" posture in this codebase).
ConduitBaseline* find_conduit(BaselineStore& store, const std::string& client_ip, const std::string& server_ip,
                               const std::string& protocol, uint16_t server_port) {
    for (auto& c : store.conduits) {
        if (c.client_ip == client_ip && c.server_ip == server_ip && c.protocol == protocol &&
            c.server_port == server_port) {
            return &c;
        }
    }
    return nullptr;
}

const ConduitBaseline* find_conduit_const(const BaselineStore& store, const std::string& client_ip,
                                           const std::string& server_ip, const std::string& protocol,
                                           uint16_t server_port) {
    for (const auto& c : store.conduits) {
        if (c.client_ip == client_ip && c.server_ip == server_ip && c.protocol == protocol &&
            c.server_port == server_port) {
            return &c;
        }
    }
    return nullptr;
}

OperationBaseline* find_operation(ConduitBaseline& conduit, const std::string& operation_key) {
    for (auto& op : conduit.operations) {
        if (op.operation_key == operation_key) return &op;
    }
    return nullptr;
}

const OperationBaseline* find_operation_const(const ConduitBaseline& conduit, const std::string& operation_key) {
    for (const auto& op : conduit.operations) {
        if (op.operation_key == operation_key) return &op;
    }
    return nullptr;
}

}  // namespace

void merge_baseline_observations(BaselineStore& store, const std::vector<ConduitBaseline>& observed,
                                  const std::string& capture_filename) {
    for (const ConduitBaseline& obs_conduit : observed) {
        ConduitBaseline* conduit =
            find_conduit(store, obs_conduit.client_ip, obs_conduit.server_ip, obs_conduit.protocol,
                         obs_conduit.server_port);
        if (!conduit) {
            ConduitBaseline fresh;
            fresh.client_ip = obs_conduit.client_ip;
            fresh.server_ip = obs_conduit.server_ip;
            fresh.protocol = obs_conduit.protocol;
            fresh.server_port = obs_conduit.server_port;
            fresh.first_seen_capture = capture_filename;
            store.conduits.push_back(std::move(fresh));
            conduit = &store.conduits.back();
        }
        conduit->packet_count += obs_conduit.packet_count;
        conduit->last_seen_capture = capture_filename;

        for (const OperationBaseline& obs_op : obs_conduit.operations) {
            OperationBaseline* op = find_operation(*conduit, obs_op.operation_key);
            if (!op) {
                conduit->operations.push_back(OperationBaseline{obs_op.operation_key, 0, false, {}});
                op = &conduit->operations.back();
            }
            op->packet_count += obs_op.packet_count;
            if (obs_op.has_target_range) {
                op->has_target_range = true;
                for (const auto& r : obs_op.observed_ranges) {
                    merge_range_into(op->observed_ranges, r);
                }
            }
        }
    }
}

// --------------------------------------------------------------------------------------------
// check_baseline() -- `check`'s own comparison logic (baseline.hpp).
// --------------------------------------------------------------------------------------------

const char* baseline_verdict_name(BaselineVerdict verdict) {
    switch (verdict) {
        case BaselineVerdict::KnownOperation: return "known-operation";
        case BaselineVerdict::NewConduit: return "new-conduit";
        case BaselineVerdict::NewOperation: return "new-operation";
        case BaselineVerdict::NewTargetRange: return "new-target-range";
    }
    return "known-operation";
}

BaselineCheckReport check_baseline(const BaselineStore& baseline, const std::vector<ConduitBaseline>& observed,
                                    const std::string& capture_path) {
    BaselineCheckReport report;
    report.capture_path = capture_path;
    report.conduits_observed = observed.size();

    for (const ConduitBaseline& obs_conduit : observed) {
        const ConduitBaseline* base_conduit = find_conduit_const(
            baseline, obs_conduit.client_ip, obs_conduit.server_ip, obs_conduit.protocol, obs_conduit.server_port);

        for (const OperationBaseline& obs_op : obs_conduit.operations) {
            ++report.operations_observed;
            const OperationBaseline* base_op =
                base_conduit ? find_operation_const(*base_conduit, obs_op.operation_key) : nullptr;

            BaselineVerdict verdict;
            // For NewTargetRange specifically, track only the sub-range(s) of THIS capture's own
            // observed_ranges that the baseline does NOT already cover -- not the outer bounds of
            // every observed sub-range (covered or not). A single operation_key can legitimately
            // have observed several disjoint ranges in one capture (e.g. one already-known range
            // plus one genuinely new one, exactly the scenario
            // sample_baseline_modbus_mutated.pcap's own packet 3 exercises); reporting the union of
            // ALL of them, covered or not, would claim bytes were "observed" that this capture
            // never actually touched (the gap between two disjoint ranges). uncovered_start/end
            // instead only ever widens across ranges that individually failed
            // range_fully_covered, so the report says exactly what wasn't already known -- nothing
            // more.
            bool any_uncovered = false;
            uint32_t uncovered_start = 0, uncovered_end = 0;
            if (!base_conduit) {
                verdict = BaselineVerdict::NewConduit;
            } else if (!base_op) {
                verdict = BaselineVerdict::NewOperation;
            } else if (obs_op.has_target_range) {
                for (const auto& r : obs_op.observed_ranges) {
                    if (!range_fully_covered(base_op->observed_ranges, r.first, r.second)) {
                        if (!any_uncovered) {
                            uncovered_start = r.first;
                            uncovered_end = r.second;
                            any_uncovered = true;
                        } else {
                            uncovered_start = std::min(uncovered_start, r.first);
                            uncovered_end = std::max(uncovered_end, r.second);
                        }
                    }
                }
                verdict = any_uncovered ? BaselineVerdict::NewTargetRange : BaselineVerdict::KnownOperation;
            } else {
                verdict = BaselineVerdict::KnownOperation;
            }

            if (verdict == BaselineVerdict::KnownOperation) {
                ++report.known_operation_count;
                continue;
            }

            BaselineFinding finding;
            finding.verdict = verdict;
            finding.client_ip = obs_conduit.client_ip;
            finding.server_ip = obs_conduit.server_ip;
            finding.protocol = obs_conduit.protocol;
            finding.server_port = obs_conduit.server_port;
            finding.operation_key = obs_op.operation_key;
            finding.packet_count = obs_op.packet_count;
            if (verdict == BaselineVerdict::NewTargetRange) {
                finding.observed_start = uncovered_start;
                finding.observed_end = uncovered_end;
                // baseline_ranges gives the reader what the baseline already had, for context, so
                // they can see how far outside it this capture went.
                finding.baseline_ranges = base_op->observed_ranges;
            }
            report.findings.push_back(std::move(finding));
        }
    }
    return report;
}

// --------------------------------------------------------------------------------------------
// JSON (de)serialization -- a small, purpose-built writer/reader for exactly the BaselineStore
// schema above, not a general JSON library: this codebase has none (CLI11 is the only vendored
// third-party code, see CMakeLists.txt), and a full general-purpose JSON parser is not necessary
// for a schema this simple and fixed-shape -- the same "purpose-built, not general" posture
// yaml_mini.hpp/yaml_mini.cpp already take for the policy YAML file, just for JSON instead of YAML
// (this baseline file's own persisted format, per the design doc, rather than reusing the YAML
// subset the policy file uses -- a baseline is generated/diffed data, not hand-authored config, so
// JSON's own "the writer and reader agree on one exact shape" fit is a better match here than
// YAML's more permissive, human-authoring-oriented syntax).
// --------------------------------------------------------------------------------------------

namespace {

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

}  // namespace

void write_baseline_store_json(std::ostream& out, const BaselineStore& store) {
    out << "{\n";
    out << "  \"schema_version\": " << store.schema_version << ",\n";
    out << "  \"conduits\": [\n";
    for (size_t i = 0; i < store.conduits.size(); ++i) {
        const ConduitBaseline& c = store.conduits[i];
        out << "    {\n";
        out << "      \"client_ip\": \"" << json_escape(c.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(c.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(c.protocol) << "\",\n";
        out << "      \"server_port\": " << c.server_port << ",\n";
        out << "      \"packet_count\": " << c.packet_count << ",\n";
        out << "      \"first_seen_capture\": \"" << json_escape(c.first_seen_capture) << "\",\n";
        out << "      \"last_seen_capture\": \"" << json_escape(c.last_seen_capture) << "\",\n";
        out << "      \"operations\": [\n";
        for (size_t j = 0; j < c.operations.size(); ++j) {
            const OperationBaseline& op = c.operations[j];
            out << "        {\n";
            out << "          \"operation_key\": \"" << json_escape(op.operation_key) << "\",\n";
            out << "          \"packet_count\": " << op.packet_count << ",\n";
            out << "          \"has_target_range\": " << (op.has_target_range ? "true" : "false") << ",\n";
            out << "          \"observed_ranges\": [";
            for (size_t k = 0; k < op.observed_ranges.size(); ++k) {
                if (k) out << ", ";
                out << "[" << op.observed_ranges[k].first << ", " << op.observed_ranges[k].second << "]";
            }
            out << "]\n";
            out << "        }" << (j + 1 < c.operations.size() ? "," : "") << "\n";
        }
        out << "      ]\n";
        out << "    }" << (i + 1 < store.conduits.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

namespace {

// A tiny hand-rolled JSON reader, purpose-built for exactly write_baseline_store_json's own output
// shape above -- not a general JSON parser (no comments, no unicode surrogate-pair escapes beyond
// what's needed to round-trip json_escape's own output, no tolerance for a document that doesn't
// match this exact schema). Throws BaselineStoreError with a byte-offset-free but otherwise
// human-readable message on anything unexpected -- this file is a generated artifact meant to be
// diffed, not hand-edited, so a precise line/column tracker (the way yaml_mini.hpp's own parser has
// for the hand-authored policy file) isn't worth the complexity here.
class JsonCursor {
public:
    explicit JsonCursor(const std::string& text) : text_(text) {}

    void skip_ws() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    }

    char peek() {
        skip_ws();
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    void expect(char c) {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != c) {
            fail(std::string("expected '") + c + "'");
        }
        ++pos_;
    }

    // True and consumes `c` if it's next (after whitespace); false and consumes nothing otherwise.
    bool consume_if(char c) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    std::string parse_string() {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != '"') fail("expected a string");
        ++pos_;
        std::string out;
        while (true) {
            if (pos_ >= text_.size()) fail("unterminated string");
            char c = text_[pos_++];
            if (c == '"') break;
            if (c == '\\') {
                if (pos_ >= text_.size()) fail("unterminated string escape");
                char esc = text_[pos_++];
                switch (esc) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        if (pos_ + 4 > text_.size()) fail("truncated \\u escape");
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = text_[pos_++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                            else fail("invalid \\u escape digit");
                        }
                        // Only the control-character range write_baseline_store_json's own
                        // json_escape ever emits via \u -- a plain byte-for-byte reproduction is
                        // enough here, no UTF-16 surrogate-pair decoding.
                        out += static_cast<char>(code & 0xFF);
                        break;
                    }
                    default: fail("unrecognized string escape");
                }
            } else {
                out += c;
            }
        }
        return out;
    }

    long long parse_integer() {
        skip_ws();
        size_t start = pos_;
        if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
        size_t digits_start = pos_;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        if (pos_ == digits_start) fail("expected a number");
        return std::stoll(text_.substr(start, pos_ - start));
    }

    bool parse_bool() {
        skip_ws();
        if (text_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            return true;
        }
        if (text_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            return false;
        }
        fail("expected true or false");
        return false;  // unreachable
    }

    [[noreturn]] void fail(const std::string& what) {
        throw BaselineStoreError("baseline file: malformed JSON (" + what + ", at byte offset " +
                                  std::to_string(pos_) + ")");
    }

private:
    const std::string& text_;
    size_t pos_ = 0;
};

std::vector<std::pair<uint32_t, uint32_t>> parse_ranges(JsonCursor& c) {
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    c.expect('[');
    if (c.consume_if(']')) return ranges;
    while (true) {
        c.expect('[');
        auto a = c.parse_integer();
        c.expect(',');
        auto b = c.parse_integer();
        c.expect(']');
        ranges.emplace_back(static_cast<uint32_t>(a), static_cast<uint32_t>(b));
        if (c.consume_if(',')) continue;
        c.expect(']');
        break;
    }
    return ranges;
}

OperationBaseline parse_operation(JsonCursor& c) {
    OperationBaseline op;
    bool have_key = false, have_packet_count = false, have_has_range = false, have_ranges = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "operation_key") {
                op.operation_key = c.parse_string();
                have_key = true;
            } else if (key == "packet_count") {
                op.packet_count = static_cast<size_t>(c.parse_integer());
                have_packet_count = true;
            } else if (key == "has_target_range") {
                op.has_target_range = c.parse_bool();
                have_has_range = true;
            } else if (key == "observed_ranges") {
                op.observed_ranges = parse_ranges(c);
                have_ranges = true;
            } else {
                c.fail("unrecognized operation field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_key || !have_packet_count || !have_has_range || !have_ranges) {
        c.fail("operation object missing a required field (operation_key/packet_count/"
               "has_target_range/observed_ranges)");
    }
    return op;
}

ConduitBaseline parse_conduit(JsonCursor& c) {
    ConduitBaseline conduit;
    bool have_client = false, have_server = false, have_protocol = false, have_port = false,
         have_packet_count = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "client_ip") {
                conduit.client_ip = c.parse_string();
                have_client = true;
            } else if (key == "server_ip") {
                conduit.server_ip = c.parse_string();
                have_server = true;
            } else if (key == "protocol") {
                conduit.protocol = c.parse_string();
                have_protocol = true;
            } else if (key == "server_port") {
                conduit.server_port = static_cast<uint16_t>(c.parse_integer());
                have_port = true;
            } else if (key == "packet_count") {
                conduit.packet_count = static_cast<size_t>(c.parse_integer());
                have_packet_count = true;
            } else if (key == "first_seen_capture") {
                conduit.first_seen_capture = c.parse_string();
            } else if (key == "last_seen_capture") {
                conduit.last_seen_capture = c.parse_string();
            } else if (key == "operations") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        conduit.operations.push_back(parse_operation(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else {
                c.fail("unrecognized conduit field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_client || !have_server || !have_protocol || !have_port || !have_packet_count) {
        c.fail("conduit object missing a required field (client_ip/server_ip/protocol/server_port/"
               "packet_count)");
    }
    return conduit;
}

}  // namespace

BaselineStore parse_baseline_store_json(const std::string& text) {
    JsonCursor c(text);
    BaselineStore store;
    bool have_schema_version = false, have_conduits = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "schema_version") {
                store.schema_version = static_cast<int>(c.parse_integer());
                have_schema_version = true;
            } else if (key == "conduits") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        store.conduits.push_back(parse_conduit(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
                have_conduits = true;
            } else {
                c.fail("unrecognized top-level field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_schema_version || !have_conduits) {
        c.fail("missing required top-level field (schema_version/conduits)");
    }
    if (store.schema_version != 1) {
        throw BaselineStoreError("baseline file: unrecognized schema_version " +
                                  std::to_string(store.schema_version) + " (this build only understands 1)");
    }
    return store;
}

// --------------------------------------------------------------------------------------------
// load/save -- file I/O around the (de)serialization above.
// --------------------------------------------------------------------------------------------

BaselineStore load_baseline_store(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        // "reads the file if present" -- a missing file is a fresh, empty baseline, not an error
        // (see this function's own comment, baseline.hpp).
        return BaselineStore{};
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    if (!in.good() && !in.eof()) {
        throw BaselineStoreError("baseline file '" + path + "': read error");
    }
    return parse_baseline_store_json(buf.str());
}

void save_baseline_store(const std::string& path, const BaselineStore& store) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw BaselineStoreError("baseline file '" + path + "': cannot open for writing");
    }
    write_baseline_store_json(out, store);
    if (!out) {
        throw BaselineStoreError("baseline file '" + path + "': write error");
    }
}

// --------------------------------------------------------------------------------------------
// check report rendering -- mirrors write_policy_report_text/_json's own conventions (see this
// file's own header comment, baseline.hpp).
// --------------------------------------------------------------------------------------------

namespace {

std::string ranges_text(const std::vector<std::pair<uint32_t, uint32_t>>& ranges) {
    std::ostringstream out;
    for (size_t i = 0; i < ranges.size(); ++i) {
        if (i) out << ", ";
        out << "[" << ranges[i].first << ", " << ranges[i].second << ")";
    }
    if (ranges.empty()) out << "(none)";
    return out.str();
}

}  // namespace

void write_baseline_check_report_text(std::ostream& out, const BaselineCheckReport& report) {
    out << "ICS communication-baseline check\n";
    out << "  capture: " << report.capture_path << "\n\n";

    out << "Result: " << (report.compliant() ? "CLEAN" : "ANOMALIES FOUND");
    if (!report.compliant()) {
        out << " (" << report.findings.size() << " finding(s))";
    }
    out << "\n\n";

    out << report.conduits_observed << " conduit(s) observed, " << report.operations_observed
        << " distinct operation(s) observed, " << report.known_operation_count
        << " matched the baseline, " << report.findings.size() << " did not\n\n";

    out << "FINDINGS (" << report.findings.size() << "):\n";
    if (report.findings.empty()) {
        out << "  (none)\n";
    }
    for (size_t i = 0; i < report.findings.size(); ++i) {
        const BaselineFinding& f = report.findings[i];
        out << "  [" << (i + 1) << "] " << baseline_verdict_name(f.verdict) << "  " << f.client_ip << " -> "
            << f.server_ip << ":" << f.server_port << "  " << f.protocol << "  operation=\"" << f.operation_key
            << "\"  (" << f.packet_count << " packet(s))\n";
        if (f.verdict == BaselineVerdict::NewTargetRange) {
            out << "      observed range: [" << f.observed_start << ", " << f.observed_end << ")\n";
            out << "      baseline ranges: " << ranges_text(f.baseline_ranges) << "\n";
        }
    }
}

void write_baseline_check_report_json(std::ostream& out, const BaselineCheckReport& report) {
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(report.capture_path) << "\",\n";
    out << "  \"compliant\": " << (report.compliant() ? "true" : "false") << ",\n";
    out << "  \"conduits_observed\": " << report.conduits_observed << ",\n";
    out << "  \"operations_observed\": " << report.operations_observed << ",\n";
    out << "  \"known_operation_count\": " << report.known_operation_count << ",\n";
    out << "  \"findings\": [\n";
    for (size_t i = 0; i < report.findings.size(); ++i) {
        const BaselineFinding& f = report.findings[i];
        out << "    {\n";
        out << "      \"verdict\": \"" << baseline_verdict_name(f.verdict) << "\",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"operation_key\": \"" << json_escape(f.operation_key) << "\",\n";
        if (f.verdict == BaselineVerdict::NewTargetRange) {
            out << "      \"observed_start\": " << f.observed_start << ",\n";
            out << "      \"observed_end\": " << f.observed_end << ",\n";
            out << "      \"baseline_ranges\": [";
            for (size_t k = 0; k < f.baseline_ranges.size(); ++k) {
                if (k) out << ", ";
                out << "[" << f.baseline_ranges[k].first << ", " << f.baseline_ranges[k].second << "]";
            }
            out << "],\n";
        }
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }" << (i + 1 < report.findings.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

}  // namespace conduitscope
