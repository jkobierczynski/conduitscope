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

void set_resource_limits(const ResourceLimits& limits) { mutable_resource_limits() = limits; }

}  // namespace conduitscope
