// SPDX-License-Identifier: Apache-2.0
// resource_limits.cpp - implementation of the thread-local ResourceLimits accessor declared in
// resource_limits.hpp. See that header's comment for why this is a global accessor rather than a
// parameter threaded through DecodeContext/ProtocolDecoder, and why it's thread_local plus
// scoped per decode() call via ScopedResourceLimits (docs/reviews/2026-09-chatgpt-security-
// review-patch160.md, finding 5).
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// Meyers-singleton-style function-local static, the same pattern this codebase already uses for
// every *_decoder() accessor (hartip_tcp_decoder(), bacnet_decoder(), mqtt_decoder(), etc.) --
// here holding mutable, thread-local state instead of an immutable, process-wide decoder
// instance. `thread_local` (rather than a plain `static`) is what gives each thread its own
// independent copy -- a set_resource_limits() call on one thread can never be observed by, or
// race with, another thread's resource_limits() read or set_resource_limits() call.
ResourceLimits& mutable_resource_limits() {
    static thread_local ResourceLimits limits;
    return limits;
}

// F4 fix: the same Meyers-singleton-style thread_local pattern as mutable_resource_limits() above,
// for the same reason -- see flow_state_evictions()'s own comment (resource_limits.hpp).
size_t& mutable_flow_state_eviction_count() {
    static thread_local size_t count = 0;
    return count;
}

// patch315 security review finding F1: the same Meyers-singleton-style thread_local pattern as
// mutable_flow_state_eviction_count() above, for the same reason -- see
// tls_keylog_entries_refused()'s own comment (resource_limits.hpp) for why THIS counter is reset
// by TlsKeyLog's own constructor rather than Decoder's.
size_t& mutable_tls_keylog_entries_refused_count() {
    static thread_local size_t count = 0;
    return count;
}

}  // namespace

const ResourceLimits& resource_limits() { return mutable_resource_limits(); }

void set_resource_limits(const ResourceLimits& limits) {
    // Security fix (finding 3, docs/reviews/2026-09-chatgpt-security-review-patch209.md,
    // "--max-active-flows 0 can cause invalid iterator erasure"): normalize a literal 0 for
    // max_active_flows/max_flow_state_entries (and, ROADMAP item 102, max_active_fragment_groups --
    // the identical "evict to cap a COUNT" shape) to std::nullopt HERE, the single point every caller
    // of this function (Decoder's constructor, ScopedResourceLimits, and any direct library/API
    // caller) ends up going through -- so neither Decoder::reassemble_tcp_payload's nor
    // DecodeContext::flow_state<T>()'s own enforcement code (decoder.cpp / protocol_decoder.hpp)
    // can ever observe a cap of exactly 0, regardless of how the ResourceLimits value reaching
    // this function was built. Both fields' own comments (resource_limits.hpp) explain why 0 is
    // defined this way rather than literally enforced: each is enforced by evicting an EXISTING
    // entry to make room for a new one, which cannot be given a sensible "evict something" meaning
    // when zero entries may ever exist -- and, for max_active_flows specifically, the old code
    // tried anyway, erasing tcp_reassembly_.begin() from an already-empty map, which is undefined
    // behavior. cli_main.cpp's build_resource_limits already treated a `--max-active-flows 0` /
    // `--max-flow-state-entries 0` CLI argument as "flag not passed" for exactly this reason; this
    // makes that the same, single, library-wide contract for every caller, not only the CLI, per
    // the review's own recommended fix ("never pass a zero-valued optional cap into the
    // enforcement code"). Every other ResourceLimits field keeps its literal value unchanged --
    // this normalization is specific to these two "evict to cap a COUNT" fields; it has no
    // equivalent meaning for the five "cap a single COST" fields above them.
    ResourceLimits normalized = limits;
    if (normalized.max_active_flows && *normalized.max_active_flows == 0) {
        normalized.max_active_flows.reset();
    }
    if (normalized.max_flow_state_entries && *normalized.max_flow_state_entries == 0) {
        normalized.max_flow_state_entries.reset();
    }
    if (normalized.max_active_fragment_groups && *normalized.max_active_fragment_groups == 0) {
        normalized.max_active_fragment_groups.reset();
    }
    mutable_resource_limits() = normalized;
}

size_t flow_state_evictions() { return mutable_flow_state_eviction_count(); }

void note_flow_state_eviction() { ++mutable_flow_state_eviction_count(); }

void reset_flow_state_evictions() { mutable_flow_state_eviction_count() = 0; }

const char* observation_incomplete_reason_name(ObservationIncompleteReason reason) {
    switch (reason) {
        case ObservationIncompleteReason::ResourceLimit: return "resource_limit";
        case ObservationIncompleteReason::FlowStateEviction: return "flow_state_eviction";
        case ObservationIncompleteReason::CaptureWriteFailure: return "capture_write_failure";
        case ObservationIncompleteReason::CapturePermissionFailure: return "capture_permission_failure";
        case ObservationIncompleteReason::UnsupportedProtocol: return "unsupported_protocol";
        case ObservationIncompleteReason::PacketTruncation: return "packet_truncation";
    }
    return "resource_limit";  // unreachable -- every enumerator handled above; a defensive
                               // fallback return rather than falling off the end, matching this
                               // codebase's own enum-to-string precedent (e.g. detect_engine.cpp's
                               // detection_evidence_name/detection_novelty_name).
}

std::string join_observation_incomplete_reason_names(const std::vector<ObservationIncompleteReason>& categories) {
    std::string out;
    for (size_t i = 0; i < categories.size(); ++i) {
        if (i) out += ", ";
        out += observation_incomplete_reason_name(categories[i]);
    }
    return out;
}

std::optional<ObservationIncompleteReason> parse_observation_incomplete_reason_name(const std::string& name) {
    if (name == "resource_limit") return ObservationIncompleteReason::ResourceLimit;
    if (name == "flow_state_eviction") return ObservationIncompleteReason::FlowStateEviction;
    if (name == "capture_write_failure") return ObservationIncompleteReason::CaptureWriteFailure;
    if (name == "capture_permission_failure") return ObservationIncompleteReason::CapturePermissionFailure;
    if (name == "unsupported_protocol") return ObservationIncompleteReason::UnsupportedProtocol;
    if (name == "packet_truncation") return ObservationIncompleteReason::PacketTruncation;
    return std::nullopt;
}

void append_observation_incomplete_reason(std::vector<ObservationIncompleteReason>& categories,
                                           ObservationIncompleteReason category) {
    for (ObservationIncompleteReason existing : categories) {
        if (existing == category) return;
    }
    categories.push_back(category);
}

bool append_flow_state_eviction_reason(std::vector<std::string>& reasons,
                                        std::vector<ObservationIncompleteReason>& categories) {
    const size_t n = flow_state_evictions();
    if (n == 0) return false;
    reasons.push_back(
        "flow-state eviction limit reached -- " + std::to_string(n) + " state entr" + (n == 1 ? "y" : "ies") +
        " evicted during this capture (--max-flow-state-entries); an evicted session's next packet looks "
        "exactly like a brand-new one, so detection/baseline/policy results for affected sessions may be "
        "incomplete or misclassified");
    append_observation_incomplete_reason(categories, ObservationIncompleteReason::FlowStateEviction);
    return true;
}

size_t tls_keylog_entries_refused() { return mutable_tls_keylog_entries_refused_count(); }

void note_tls_keylog_entry_refused() { ++mutable_tls_keylog_entries_refused_count(); }

void reset_tls_keylog_entries_refused() { mutable_tls_keylog_entries_refused_count() = 0; }

bool append_tls_keylog_limit_reason(std::vector<std::string>& reasons,
                                     std::vector<ObservationIncompleteReason>& categories) {
    const size_t n = tls_keylog_entries_refused();
    if (n == 0) return false;
    reasons.push_back(
        "TLS key-log/DSB entry limit reached -- " + std::to_string(n) + " well-formed key-log line" +
        (n == 1 ? "" : "s") + " refused during this run (--max-tls-keylog-entries/--max-tls-keylog-bytes); "
        "a TLS session whose secret arrived after this ceiling was reached stays exactly as opaque as if "
        "no key had ever been supplied for it at all");
    append_observation_incomplete_reason(categories, ObservationIncompleteReason::ResourceLimit);
    return true;
}

}  // namespace conduitscope
