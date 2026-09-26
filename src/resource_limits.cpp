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

}  // namespace

const ResourceLimits& resource_limits() { return mutable_resource_limits(); }

void set_resource_limits(const ResourceLimits& limits) {
    // Security fix (finding 3, docs/reviews/2026-09-chatgpt-security-review-patch209.md,
    // "--max-active-flows 0 can cause invalid iterator erasure"): normalize a literal 0 for
    // max_active_flows/max_flow_state_entries to std::nullopt HERE, the single point every caller
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
    mutable_resource_limits() = normalized;
}

}  // namespace conduitscope
