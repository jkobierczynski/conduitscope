// SPDX-License-Identifier: Apache-2.0
// protocol_decoder.hpp - the registration-model decoder interface: a ProtocolDecoder abstract
// base, plus the small pieces of context (DecodeContext/DecoderFlowState/ProtocolResult) it needs
// to fit alongside decoder.cpp's existing, much larger hand-ordered dispatch chain.
//
// THIS IS A PILOT, NOT A REPLACEMENT (see docs/DEVELOPMENT.md's "registration-model decoder
// refactor" entry for the full staged plan). decoder.cpp's ~44-protocol ordered if-chain and
// DecodedPacket's ~449 protocol-prefixed flat fields are UNCHANGED by this file's existence --
// every protocol keeps working exactly as it did before. Only a handful of protocols (one per
// structural "gate shape" this codebase has, chosen to prove the interface actually covers all of
// them, plus Beckhoff TwinCAT/ADS as the first protocol built ONLY on this interface) are wired
// through it. The other ~48 stay on the legacy path indefinitely, until/unless a future pass
// migrates them -- there is no timeline commitment for that here.
//
// WHY A NEW ABSTRACTION AT ALL, GIVEN HOW SMALL ITS FOOTPRINT IS RIGHT NOW: every protocol added
// to this codebase before TwinCAT required touching ProtocolFilter (decoder.hpp), DecodedPacket
// (decoder.hpp, another ~10-20 new fields), Decoder::decode's dispatch chain (decoder.cpp), and
// every output writer's own protocol-specific branch (output.cpp) -- four separate places, in
// lockstep, for one new protocol. This interface's whole point is that TwinCAT (and any future
// protocol built on it) instead implements ONE class (ProtocolDecoder) and is done -- no new
// DecodedPacket fields, no new writer branches (see protocol_registry.hpp's TwinCAT rendering
// note). Proving that end-to-end, on a real protocol, is worth more than the abstraction's line
// count suggests.
//
// COEXISTENCE RULE: a migrated protocol's call site in decoder.cpp still sits at EXACTLY the same
// textual position its old `if (want_x) { if (auto y = try_parse_x(...)) {...} }` block used to
// occupy -- migrating a protocol changes WHAT runs at that line, never WHICH LINE it runs at. This
// is what keeps every documented collision-avoidance ordering (see docs/DEVELOPMENT.md's PROTOCOL
// DETECTION section, e.g. "IEC104 before Modbus") true regardless of which of the two protocols
// involved has migrated -- the guarantee comes from decoder.cpp still being one linear sequence of
// statements, not from anything in this file.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <type_traits>
#include <unordered_map>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// Which of decoder.cpp's four existing dispatch cascades (EtherType, IP-protocol-number, TCP
// port-independent, UDP port) a protocol belongs to -- mirrors the four cascades exactly, so
// nothing about how a packet gets routed to a candidate payload changes; this only describes it.
enum class GateKind {
    EtherType,          // e.g. GOOSE, SV, PROFINET, EtherCAT, STP, EAPOL, PPPoE, MPLS
    IpProtocol,          // e.g. ICMP, IGMP, VRRP, IGRP, PIM, EIGRP, OSPF -- gated by ip.protocol
    TcpPortIndependent,  // e.g. OPC UA, EtherNet/IP, IEC104, Modbus, DNP3, S7comm family, HART-IP,
                         // MQTT, FF-HSE -- tried opportunistically regardless of port, per
                         // docs/DEVELOPMENT.md's PROTOCOL DETECTION section
    UdpPort,             // e.g. DNS/mDNS/LLMNR/NBT-NS/HSRP/RIP -- the few protocols this codebase
                         // gates by port because they lack self-describing bytes of their own
};

// Base class for a protocol's own cross-packet state (Modbus's outstanding-transaction table,
// TwinCAT's outstanding-Invoke-ID table, ...). Stateless protocols (the majority -- EIGRP, GOOSE,
// and every other protocol with no request/response notion) never need a subclass of this at all.
class DecoderFlowState {
public:
    virtual ~DecoderFlowState() = default;
};

// Owned by Decoder (see decoder.hpp's Decoder::registry_flow_state_); one generic map replacing
// what used to require a bespoke `unordered_map<...> x_pending_` member on Decoder for every
// stateful protocol (Decoder::modbus_pending_ is the pre-existing example this generalizes).
// Outer key: protocol id ("modbus", "twincat", ...). Inner key: whatever session/flow key that
// protocol's own DecodeContext::session_key or flow_key carries for it (each protocol picks
// whichever of the two matches its own pairing semantics -- Modbus/TwinCAT both use session_key,
// mirroring Decoder::modbus_pending_'s own pre-existing choice of session over directional flow).
using FlowStateMap = std::unordered_map<std::string, std::unordered_map<std::string, std::unique_ptr<DecoderFlowState>>>;

// Passed by decoder.cpp into every registry-based ProtocolDecoder::decode call. `protocol_id` is
// filled in by the small call-site helper (see decoder.cpp's registry call sites) right before the
// call, from the specific decoder instance being invoked -- a decoder never needs to state its own
// id twice.
struct DecodeContext {
    std::string flow_key;     // directional "src_ip:src_port->dst_ip:dst_port", when applicable
    std::string session_key;  // direction-independent session key (decoder.cpp's tcp_session_key),
                               // when applicable -- e.g. Modbus/TwinCAT transaction/Invoke-ID pairing
    size_t packet_index = 0;
    std::string protocol_id;
    FlowStateMap* flow_states = nullptr;  // non-null whenever a stateful decoder might be called

    // Returns this protocol's flow state for `session_key`, default-constructing a fresh T the
    // first time a given session is seen. Only ever called by a stateful decoder's own decode()
    // (e.g. ModbusDecoder), which alone knows T -- see modbus.cpp/twincat.cpp for the pattern this
    // replaces (a bespoke `Decoder::x_pending_[session_key]` lookup).
    template <typename T>
    T& flow_state() const {
        static_assert(std::is_base_of<DecoderFlowState, T>::value, "T must derive from DecoderFlowState");
        auto& per_key = (*flow_states)[protocol_id];
        auto it = per_key.find(session_key);
        if (it == per_key.end()) {
            it = per_key.emplace(session_key, std::make_unique<T>()).first;
        }
        return static_cast<T&>(*it->second);
    }
};

// Type-erased holder for a protocol's own result struct (ModbusFrame, EigrpMessage, GooseFrame,
// TwinCatFrame, ...) -- deliberately NOT a std::variant of every migrated protocol's type, so
// migrating one more protocol never means touching every other migrated protocol's own header to
// extend a shared variant. `data` is a `shared_ptr<const void>` (not `unique_ptr`) specifically
// because DecodedPacket -- which will hold a ProtocolResult once a protocol is fully rendered
// through this path (see TwinCAT) -- is copied around by value today (decoder.cpp returns it by
// value, cli_main.cpp/output.cpp pass it by const&, but nothing here assumes that never changes);
// a shared_ptr keeps that copy cheap without adding a copy constructor to every protocol's own
// result struct.
struct ProtocolResult {
    std::string protocol_id;
    std::shared_ptr<const void> data;

    template <typename T>
    static ProtocolResult make(std::string id, T value) {
        return ProtocolResult{std::move(id), std::make_shared<const T>(std::move(value))};
    }

    // Caller's responsibility to pass the right T for this result's protocol_id -- exactly the
    // same contract DecodedPacket's own `protocol == "x"`-gated field access already has today,
    // just centralized in one accessor instead of one `if` per read site.
    template <typename T>
    const T& as() const {
        return *static_cast<const T*>(data.get());
    }
};

// One protocol's detection+decode, fused into one call just like every existing free-function
// try_parse_X(ByteSpan) -> std::optional<XFrame> this replaces -- never throws, returns nullopt on
// no match. Every method below keeps using ByteSpan/Cursor (byteio.hpp) unchanged; nothing here
// introduces a new parsing primitive.
class ProtocolDecoder {
public:
    virtual ~ProtocolDecoder() = default;

    virtual std::string_view id() const = 0;
    virtual GateKind gate_kind() const = 0;

    // Only one of these two is ever meaningful for a given decoder, matching its gate_kind().
    virtual std::optional<uint16_t> ethertype() const { return std::nullopt; }
    virtual std::optional<uint8_t> ip_protocol() const { return std::nullopt; }

    // Only overridden by TcpPortIndependent decoders that participate in decoder.cpp's generic TCP
    // reassembly cascade (Decoder::reassemble_tcp_payload) -- the registry-based equivalent of
    // today's free-standing `x_declared_length(ByteSpan) -> optional<size_t>` functions (e.g.
    // modbus_tcp_declared_length). A decoder whose protocol is never split across TCP segments (or
    // whose gate_kind isn't TcpPortIndependent at all) leaves this at its default.
    virtual std::optional<size_t> tcp_declared_length(ByteSpan /*candidate*/) const { return std::nullopt; }

    // The fused gate+decode call. `ctx.protocol_id` is already this decoder's own id() by the time
    // this is called (see decoder.cpp's call-site helper) -- a stateful decoder pulls its own
    // DecoderFlowState subclass out of `ctx.flow_state<T>()` and updates it in place, the same
    // cross-packet-state contract Decoder::pair_modbus_transaction had before Modbus migrated.
    virtual std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const = 0;
};

}  // namespace conduitscope
