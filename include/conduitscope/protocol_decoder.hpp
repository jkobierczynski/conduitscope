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
// through it. The other ~37 (and shrinking, batch by batch -- see docs/DEVELOPMENT.md's item 3
// "Update" paragraphs for the running count) stay on the legacy path indefinitely, until/unless a
// future pass migrates them -- there is no timeline commitment for that here. NOT counted in that
// figure, and never a migration candidate at all: the 43 name-only "IT protocols an OT auditor
// flags" recognitions (it_protocols.hpp/tunnel_vpn.hpp/eapol.hpp/pppoe.hpp/mpls.hpp/quic.hpp,
// ROADMAP item 18) -- decided directly, see that item's own "Architectural scope note" in
// docs/DEVELOPMENT.md: none of them decode a typed struct into DecodedPacket flat fields in the
// first place (by design -- they're deliberately recognized, not decoded), so there is no
// dual-write for this interface to retire there, and nothing to gain by wrapping them in it.
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
    TcpPortIndependent,  // e.g. OPC UA, EtherNet/IP, IEC104, Modbus, DNP3, COTP, HART-IP,
                         // MQTT, FF-HSE -- tried opportunistically regardless of port, per
                         // docs/DEVELOPMENT.md's PROTOCOL DETECTION section
    UdpPort,             // e.g. DNS/mDNS/LLMNR/NBT-NS/HSRP/RIP -- the few protocols this codebase
                         // gates by port because they lack self-describing bytes of their own
    // Migration batch addition: TcpPort, the TCP-side mirror of UdpPort above, added specifically
    // because DoH detection needed it and none of the existing six GateKinds fit -- see
    // tls_sni.hpp's DohDecoder. UNLIKE TcpPortIndependent (tried opportunistically on every TCP
    // port in Auto mode, relying on a strong structural gate to avoid false positives), a
    // TcpPort decoder is port-gated in Auto mode, the same "no strong enough self-describing byte
    // shape to check opportunistically" reasoning UdpPort's own protocols share -- DoH's own gate
    // (a TLS ClientHello whose SNI matches a curated known-DoH-provider table) is strong on
    // content but still only checked on the configured HTTPS/DoH port(s) in Auto mode, to avoid
    // spending a TLS ClientHello parse on every TCP payload in the capture for a feature this
    // narrow (an explicit `--protocol doh` still tries it port-independently, same override
    // UdpPort's own protocols already have).
    TcpPort,
    // Migration batch 2 additions (see docs/DEVELOPMENT.md's "registration-model decoder refactor"
    // entry for the batch this landed in):
    UdpPortIndependent,  // the UDP-side mirror of TcpPortIndependent above -- e.g. BACnet/IP,
                         // HART-IP's own UDP path, EtherNet/IP's own CIP I/O UDP path -- tried
                         // opportunistically regardless of port, unlike UdpPort's own
                         // gates-by-port-because-there's-no-self-describing-signal protocols.
    CotpPayload,         // S7comm, S7comm-Plus, MMS -- NOT gated against raw TCP bytes at all.
                         // Only ever invoked with the bytes a CotpDecoder (gate_kind() ==
                         // TcpPortIndependent, see cotp.hpp) has already framed and cross-packet-
                         // reassembled. A CotpPayload decoder is meaningless in isolation; it is
                         // always reached through decoder.cpp's own COTP/S7comm-family call site,
                         // never through a generic TcpPortIndependent iteration -- see
                         // protocol_registry.hpp's cotp_payload_registry() for why this is its own
                         // gate kind rather than being (mis)categorized as TcpPortIndependent.
    // Migration batch addition: gated by the pcap capture's own link-layer type (PcapPacket's
    // `link_type`, see pcap_reader.hpp's LINKTYPE_* constants), not by anything inside the
    // packet's own bytes -- a genuinely different dispatch shape from every kind above, all four
    // of which assume an Ethernet/IP/TCP/UDP frame already exists to gate against. DeviceNet (CAN-
    // bus CIP, see devicenet.hpp) is this kind's first and so far only user: it is reached only
    // for LINKTYPE_CAN_SOCKETCAN captures, which have no MAC addresses, no IP layer, no ports at
    // all -- see decoder.cpp's own LINKTYPE_CAN_SOCKETCAN branch.
    LinkType,
};

// Base class for a protocol's own cross-packet state (Modbus's outstanding-transaction table,
// TwinCAT's outstanding-Invoke-ID table, ...). Stateless protocols (the majority -- EIGRP, GOOSE,
// and every other protocol with no request/response notion) never need a subclass of this at all.
class DecoderFlowState {
public:
    virtual ~DecoderFlowState() = default;
};

// Fixed placeholder substituted for a decoded cleartext secret when redaction is active -- see
// DecodeContext::redact_secrets below and DecodeOptions::redact_secrets's own comment
// (decoder.hpp) for the full rationale and decode's own --redact/--no-redact CLI flag. The literal
// string a JSON/CSV/text consumer should read as "a secret was here, --no-redact to see it", not
// as a real credential value that happens to be short.
inline constexpr const char* kRedactedSecretPlaceholder = "[REDACTED]";

// Replaces every occurrence of `secret` inside `text` with kRedactedSecretPlaceholder. Used by
// every decoder that places a literal cleartext credential into its own summary/notes text (HSRP's/
// VRRP's own plaintext routing-protocol authentication fields -- see hsrp.hpp/vrrp.hpp) once
// redaction is active, since the same value sometimes appears in more than one place (e.g. a note
// that names it as well as the summary line). A precise substring replacement, not a general-
// purpose secret-scrubbing heuristic -- the exact value is already known at every call site (it IS
// the value that was just decoded), so there is nothing to guess at. A no-op for an empty secret
// (nothing was ever decoded, so nothing to find).
inline std::string redact_secret_occurrences(std::string text, const std::string& secret) {
    if (secret.empty()) return text;
    const std::string placeholder = kRedactedSecretPlaceholder;
    size_t pos = 0;
    while ((pos = text.find(secret, pos)) != std::string::npos) {
        text.replace(pos, secret.size(), placeholder);
        pos += placeholder.size();
    }
    return text;
}

// Migration batch 2 addition: which of DecodeContext's two keys (below) a stateful decoder's state
// is scoped to. Session is right for request/response pairing that can legitimately be answered
// from either direction of one TCP session (Modbus's transaction ID, TwinCAT's Invoke ID, MQTT's
// learned protocol version -- every existing DecodeContext::flow_state<T>() caller before this
// batch). DirectionalFlow is for state that is NOT session-wide -- COTP/TPKT fragment reassembly
// and DNP3 application-fragment reassembly each reassemble ONE DIRECTION's bytes independently;
// conflating both directions into one session-keyed buffer would corrupt reassembly the moment both
// directions had an in-progress fragment at once (nothing stops a COTP session from having
// client->server and server->client fragments in flight simultaneously).
enum class FlowStateKeying { Session, DirectionalFlow };

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

    // Migration batch 5 addition: the packet's own IPv4 source address, in host byte order -- IGRP's
    // only user (see igrp.hpp's file header comment: IGRP's 3-byte classful Network field needs the
    // missing high octet reconstructed from the carrying packet's own source address, a genuinely
    // different need from every other GateKind::IpProtocol decoder, all of which parse purely from
    // the IP payload with no header context). Left at 0 (a real, if unlikely, address -- callers that
    // don't populate this simply never asked a decoder that reads it) for every other decoder; only
    // decoder.cpp's IGRP call site ever sets it. Same category of small, narrowly-scoped interface
    // extension as FlowStateKeying/udp_port() were for their own one-time needs.
    uint32_t ip_src_addr = 0;

    // Whether this decode() call should mask a cleartext secret (a plaintext authentication field,
    // a password) with a fixed placeholder rather than including its literal value -- see
    // DecodeOptions::redact_secrets's own comment (decoder.hpp) for the full rationale and
    // decode's own --redact/--no-redact CLI flag. Defaults to true (redact), matching that
    // option's own default, so a decode() call built without wiring this up at all -- true for
    // every protocol except the handful that actually place a literal secret on the wire -- stays
    // safe by construction rather than silently unredacted. Only decoder.cpp's HSRP/VRRP/OPC UA/
    // MQTT call sites ever read or override it from the real DecodeOptions; every other decoder's
    // DecodeContext just carries the unused default, the same "only the one real user populates
    // it" shape ip_src_addr above already established for IGRP.
    bool redact_secrets = true;

    // Returns this protocol's flow state for `session_key`, default-constructing a fresh T the
    // first time a given session is seen. Only ever called by a stateful decoder's own decode()
    // (e.g. ModbusDecoder), which alone knows T -- see modbus.cpp/twincat.cpp for the pattern this
    // replaces (a bespoke `Decoder::x_pending_[session_key]` lookup).
    template <typename T>
    T& flow_state() const { return flow_state<T>(FlowStateKeying::Session); }

    // Migration batch 2 addition: same lookup, but explicit about which key (see FlowStateKeying's
    // own comment above) this decoder's state is scoped to.
    template <typename T>
    T& flow_state(FlowStateKeying keying) const {
        static_assert(std::is_base_of<DecoderFlowState, T>::value, "T must derive from DecoderFlowState");
        const std::string& key = (keying == FlowStateKeying::Session) ? session_key : flow_key;
        auto& per_key = (*flow_states)[protocol_id];
        auto it = per_key.find(key);
        if (it == per_key.end()) {
            it = per_key.emplace(key, std::make_unique<T>()).first;
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

    // Only one of these three is ever meaningful for a given decoder, matching its gate_kind().
    virtual std::optional<uint16_t> ethertype() const { return std::nullopt; }
    virtual std::optional<uint8_t> ip_protocol() const { return std::nullopt; }
    // Migration batch 4 addition: a GateKind::UdpPort decoder's own default/well-known port (e.g.
    // DNS_PORT for DnsDecoder) -- the accessor UdpPort never needed until it had a real user (see
    // udp_port_registry()'s own doc comment in protocol_registry.hpp). Like ethertype()/
    // ip_protocol() above, this is audit-trail documentation, not what drives the actual port
    // check at decoder.cpp's own call site: Auto mode's "only port-gate when Auto, not when the
    // protocol is named explicitly via --protocol" policy depends on CLI state (ProtocolFilter)
    // this interface's decode() call has no access to, so that decision -- and any
    // --extra-X-ports widening -- stays at the call site exactly as it did before migration, the
    // same "gating logic doesn't move into the class" posture StpDecoder's own comment documents.
    virtual std::optional<uint16_t> udp_port() const { return std::nullopt; }

    // The TcpPort mirror of udp_port() immediately above -- same audit-trail-only posture, same
    // "gating logic doesn't move into the class" reasoning (Auto-mode port-gating and
    // --extra-X-ports widening both stay at decoder.cpp's own call site). DohDecoder is this
    // GateKind's first and so far only user, returning DOH_PORT (tls_sni.hpp).
    virtual std::optional<uint16_t> tcp_port() const { return std::nullopt; }

    // Only overridden by a GateKind::LinkType decoder -- its own expected PcapPacket link_type
    // value (e.g. LINKTYPE_CAN_SOCKETCAN for DeviceNet). A plain uint32_t rather than pcap_
    // reader.hpp's own LinkType enum, the same "audit-trail documentation, not a new enum
    // dependency" posture ip_protocol()/udp_port() above already take with uint8_t/uint16_t.
    virtual std::optional<uint32_t> link_type() const { return std::nullopt; }

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
