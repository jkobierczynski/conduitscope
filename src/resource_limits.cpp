// SPDX-License-Identifier: Apache-2.0
// resource_limits.cpp - implementation of the process-wide ResourceLimits accessor declared in
// resource_limits.hpp. See that header's comment for why this is a plain global accessor rather
// than a parameter threaded through DecodeContext/ProtocolDecoder.
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// Meyers-singleton-style function-local static, the same pattern this codebase already uses for
// every *_decoder() accessor (hartip_tcp_decoder(), bacnet_decoder(), mqtt_decoder(), etc.) --
// here holding mutable process-wide state instead of an immutable decoder instance.
ResourceLimits& mutable_resource_limits() {
    static ResourceLimits limits;
    return limits;
}

}  // namespace

const ResourceLimits& resource_limits() { return mutable_resource_limits(); }

void set_resource_limits(const ResourceLimits& limits) { mutable_resource_limits() = limits; }

}  // namespace conduitscope
