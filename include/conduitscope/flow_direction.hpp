// SPDX-License-Identifier: Apache-2.0
// flow_direction.hpp - `decode`'s own per-TCP-flow client/server (initiator) direction tracking.
//
// This is a separate layer built entirely on top of Decoder's already-public output -- it doesn't
// change how packets are decoded, and Decoder/DecodedPacket have no knowledge of it, the same
// boundary PolicyEngine (policy_engine.hpp) and AssetInventoryEngine (asset_inventory.hpp) each
// already keep for themselves (see policy_engine.hpp's own file header). FlowDirectionTracker is
// `decode`'s own third, independent copy of the same SYN/SYN-ACK/port-heuristic direction logic
// those two engines each maintain separately -- see docs/MANUAL.md's ROADMAP item 19's "Why two
// copies, not one shared implementation" for why a third copy, not a shared one, is this project's
// deliberate convention here too, not an oversight.
//
// Feed it one DecodedPacket at a time, in capture order (same discipline as Decoder::decode/
// PolicyEngine::observe/AssetInventoryEngine::observe), via observe() -- cli_main.cpp's run_decode
// loop calls this right after Decoder::decode() returns and before the packet reaches any output
// writer, so it can fill in that same DecodedPacket's has_direction/direction_client_is_src/
// direction_source fields (decoder.hpp) in place before they're rendered. `decode`'s other three
// sibling commands (`info`, `policy validate`, `inventory`) don't use this at all: `policy
// validate`/`inventory` already have their own direction-tracking (PolicyEngine/
// AssetInventoryEngine), and `info` never reports per-packet detail in the first place.
#pragma once

#include <cstdint>
#include <string>
#include <unordered_map>

#include "conduitscope/decoder.hpp"

namespace conduitscope {

class FlowDirectionTracker {
public:
    // Fills in `packet`'s has_direction/direction_client_is_src/direction_source fields
    // (decoder.hpp) when packet.has_ip && packet.has_tcp; otherwise leaves has_direction false and
    // touches nothing else. Uses the exact same three-step priority order PolicyEngine::observe
    // documents (policy_engine.hpp): (1) a pure SYN packet authoritatively marks its own source as
    // the client; (2) a SYN-ACK authoritatively marks its own destination as the client; (3)
    // otherwise, a known-service-port/lower-port-number guess (DirectionSource::PortHeuristic),
    // upgraded to the authoritative answer (DirectionSource::Handshake) the moment a later packet
    // on the same flow carries a SYN/SYN-ACK this tracker hadn't already seen for it -- (3) is a
    // first-packet fallback, not a decision this tracker sticks with once it can do better, exactly
    // like PolicyEngine::observe's own upgrade rule.
    void observe(DecodedPacket& packet);

private:
    // One entry per distinct TCP 4-tuple ever seen, keyed by a canonicalized (direction-
    // independent) session string -- see flow_direction.cpp's own session_key. client_ip/
    // client_port/server_ip/server_port are the resolved endpoints (not "src"/"dst", which are
    // packet-relative and can flip between packets on the same flow); observe() compares each new
    // packet's own src_ip/src_port against client_ip/client_port to decide, for THAT packet,
    // whether its source is the client or the server side.
    struct FlowState {
        std::string client_ip, server_ip;
        uint16_t client_port = 0;
        uint16_t server_port = 0;
        bool initiator_known = false;  // true once decided by an actual SYN/SYN-ACK, not the port guess
        DirectionSource direction_source = DirectionSource::PortHeuristic;
    };

    std::unordered_map<std::string, FlowState> flows_;
};

}  // namespace conduitscope
