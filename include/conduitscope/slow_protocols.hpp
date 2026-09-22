// SPDX-License-Identifier: Apache-2.0
// slow_protocols.hpp -- IEEE 802.3 "Slow Protocols" (EtherType 0x8809), Subtype-multiplexed: this
// one EtherType carries three genuinely distinct link-layer control protocols, told apart by a
// single Subtype byte right after the EtherType, matching this codebase's existing "one gate,
// several message shapes" precedent (BGP's OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH, see
// bgp.hpp) rather than the "one gate, one message shape" precedent (ARP/LLDP). No transport layer,
// no IP layer -- raw Ethernet, same "EtherType carries most of the confidence" shape as GOOSE/SV/
// EtherCAT/EAPOL/PPPoE/MPLS/ARP/LLDP.
//
// Subtype 1 = LACP (Link Aggregation Control Protocol, IEEE 802.1AX clause 6 / originally 802.3ad
//   clause 43): a LACPDU exchanged every ~1-30s between two link-aggregation-capable ports to
//   negotiate and maintain which physical links bundle into one logical channel (a "port channel"/
//   "EtherChannel"/"bond"). Every field this decoder exposes is cross-checked against Wireshark's
//   own packet-slowprotocols.c (LACPDU_* offset/mask #defines) -- byte-exact, not reconstructed
//   from a written spec description:
//     Subtype(1)=0x01, Version(1), then three fixed-size, fixed-position TLVs (no walking needed --
//     unlike LLDP's variable-order TLV stream, real LACPDU producers place these at exactly the
//     same offsets every time, and this decoder's structural gate depends on that):
//       Actor Information TLV:    Type(1)=0x01, Length(1)=20, System_Priority(2,BE),
//                                  System(6, MAC), Key(2,BE), Port_Priority(2,BE), Port(2,BE),
//                                  State(1, bitmap -- see LacpStateFlags below), Reserved(3)
//       Partner Information TLV:  Type(1)=0x02, Length(1)=20, same 20-byte body shape as Actor
//       Collector Information TLV: Type(1)=0x03, Length(1)=16, Max_Delay(2,BE), Reserved(12)
//       Terminator TLV:           Type(1)=0x00, Length(1)=0
//     (then Reserved padding to a fixed PDU size in real captures -- not required to be present or
//     zero here; this decoder only requires the four TLVs above, matching the same "don't demand
//     trailing padding that adds no information" posture ARP/LLDP already take with their own
//     trailing bytes.)
//   State bitmap (Actor_State/Partner_State, IEEE 802.1AX Table 6-16, confirmed via Wireshark's own
//   LACPDU_FLAGS_* #defines): 0x01 Activity (Active/Passive), 0x02 Timeout (Short/Long), 0x04
//   Aggregation (Aggregatable/Individual), 0x08 Synchronization (In Sync/Out of Sync), 0x10
//   Collecting (Enabled/Disabled), 0x20 Distributing (Enabled/Disabled), 0x40 Defaulted (whether
//   this side is using default, not LACPDU-learned, partner information), 0x80 Expired.
//
// Subtype 2 = Marker Protocol (IEEE 802.1AX clause 6.5, "Marker Responder"): used to verify, during
//   a load-balancing re-hash across an aggregated link's member ports, that no frames are still
//   in flight on the old port before conversations move to a new one -- a Marker (TLV type 0x01,
//   "Marker Information") sent down a port is safe to treat as "drained" once the corresponding
//   Marker Response (TLV type 0x02, "Marker Response Information", identical body, echoed back)
//   is seen. Wireshark's own marker_vals[] table confirms these two TLV type values and the
//   Terminator TLV (type 0x00) that follows either one; unlike LACP's Actor/Partner Information
//   TLVs, this codebase could not independently confirm an exact byte offset table for the
//   Marker(-Response) Information TLV's own internal fields (Wireshark's own dissector computes
//   them inline rather than via named offset constants) -- see try_parse_slow_protocols' own
//   comment for how this decoder stays honest about that gap: it decodes the three fields every
//   real implementation agrees on (Requester_Port, Requester_System, Requester_Transaction_ID) from
//   the TLV's own fixed 12-byte prefix, then uses the TLV's own self-describing Length to skip any
//   trailing Pad/Reserved bytes rather than assuming their exact count.
//
// Subtype 3 = 802.3 OAM / "Ethernet in the First Mile" link-level OAM (IEEE 802.3 clause 57,
//   originally 802.3ah): a passive listener on an EFM-OAM-enabled link segment gets, for free and
//   in cleartext, a continuously-refreshed picture of that link's health (fault/dying-gasp/critical
//   flags, negotiated capabilities, vendor OUI) -- the same "unsolicited broadcast device fingerprint"
//   angle this codebase already frames LLDP around (see lldp.hpp), though OAM is a point-to-point
//   discovery/keepalive exchange rather than a broadcast. Confirmed byte-exact against Wireshark's
//   own OAMPDU_* #defines (see slow_protocols.cpp's own citation comment for the full constant
//   list this decoder was built from):
//     Subtype(1)=0x03, Flags(2,BE, bitmap -- see OamMessage below), Code(1), then Code-specific body:
//       Code=0x00 Information: a TLV stream (Type(1)+Length(1)+body) -- Local Information TLV
//         (type 0x01) and/or Remote Information TLV (type 0x02), each body: OAM_Version(1),
//         Revision(2,BE), State(1, NOT further decoded here -- see this file's own honesty note
//         below), OAM_Configuration(1, bitmap: 0x01 Mode Active/Passive, 0x02 Unidirectional
//         support, 0x04 Remote Loopback support, 0x08 Link Events support, 0x10 Variable Retrieval
//         support), OAMPDU_Configuration(2,BE, commonly called "Max OAMPDU Size" -- shown as its
//         raw 16-bit wire value, since this codebase could not independently confirm which of its
//         16 bits are reserved vs. significant), OUI(3), Vendor_Specific(4) -- 14 value bytes, an
//         Organization Specific Information TLV (type 0xFE, raw hex only), and a terminator (type
//         0x00) end either stream.
//       Code=0x01 Event Notification: Sequence_Number(2,BE), then one or more Event TLVs, each
//         Type(1)+Length(1)+Timestamp(2,BE)+type-specific counters. Four curated, fully-decoded
//         event types (Wireshark's own OAMPDU_EVENT_TYPE_* -- note these are NOT the same as this
//         PDU's own Link-Fault/Dying-Gasp/Critical-Event Flags bits above; those are always-present
//         urgent status flags, these are separate threshold-crossing counter events):
//           0x01 Errored Symbol Period Event: Window(8), Threshold(8), Errors(8), Error_Running_
//             Total(8), Event_Running_Total(4)
//           0x02 Errored Frame Event: Window(2), Threshold(4), Errors(4), Error_Running_Total(8),
//             Event_Running_Total(4)
//           0x03 Errored Frame Period Event: Window(4), Threshold(4), Errors(4), Error_Running_
//             Total(8), Event_Running_Total(4)
//           0x04 Errored Frame Seconds Summary Event: Window(2), Threshold(2), Errors(2), Error_
//             Running_Total(4), Event_Running_Total(4)
//         plus 0xFE Organization Specific Event (raw hex only, not further decoded).
//       Code=0x02 Variable Request / Code=0x03 Variable Response: named only (this decoder does not
//         walk the Variable Descriptor Branch/Object/Package/Attribute/Binding structure -- low
//         real-world diagnostic value for an OT/ICS capture review, matching this codebase's
//         existing "recognized but not exhaustively decoded" posture for deep sub-structures
//         elsewhere, e.g. BGP's own uncurated path attributes, FINS's flag words).
//       Code=0x04 Loopback Control: a single command byte, 0x01=Enable / 0x02=Disable (NOT the
//         0x00/0x01 pattern this codebase's own boolean flags might suggest -- confirmed via
//         Wireshark's own OAMPDU_LPBK_ENABLE/OAMPDU_LPBK_DISABLE #defines).
//       Code=0xFE Organization Specific: named only, raw hex.
//   Flags bitmap (OAMPDU_FLAGS_*, confirmed via Wireshark's own #defines): 0x01 Link Fault, 0x02
//   Dying Gasp (an urgent "about to lose power" signal -- see this codebase's own framing appeal
//   below), 0x04 Critical Event, 0x08 Local Evaluating, 0x10 Local Stable, 0x20 Remote Evaluating,
//   0x40 Remote Stable (bits 7-15 reserved, not decoded).
//
// HONESTY NOTE on what this decoder deliberately does NOT assert, matching this codebase's own
// established practice of naming a gap rather than guessing past it (see e.g. IEC 61850-9-2's own
// "no real capture found despite genuine multi-source search" note, BGP's own "never claims
// authenticated or unauthenticated" framing): repeated attempts to independently verify (a) the
// Information TLV's own State byte's Parser-Action/Multiplexer-Action bit split and (b) the exact
// reserved-bit layout of the 2-byte OAMPDU_Configuration/"Max OAMPDU Size" field, against a primary
// source, were not successful in this environment (the IEEE 802.3 standard text itself, and a
// second-source mirror of Wireshark's packet-oampdu.c beyond the one this file's other constants
// were confirmed against, were both unreachable). Both are therefore shown as their raw wire value
// only, not bit-decoded -- the same choice this codebase makes whenever it can name a field but
// not confidently assert everything inside it.
//
// Deliberately out of scope (per Jurgen's own confirmed scoping): IEEE 802.1ag/Y.1731 Connectivity
// Fault Management (CFM) uses its own EtherType (0x8902), not 0x8809, and is not covered here;
// ESMC/G.8264 (Slow Protocols subtype 0x0A) and MEF E-LMI (subtype 0x0B) are recognized as distinct
// possible subtypes but not decoded by this file -- an unrecognized subtype simply declines (falls
// back to the existing generic "recognized ethertype, not decoded" ethernet_name fallback), exactly
// like every other structural-gate failure in this codebase.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// LACP Actor/Partner State bitmap -- see this file's own header comment for the exact bit table.
struct LacpStateFlags {
    uint8_t raw = 0;
    bool activity = false;         // 0x01 -- true = Active, false = Passive
    bool timeout = false;          // 0x02 -- true = Short Timeout, false = Long Timeout
    bool aggregation = false;      // 0x04 -- true = Aggregatable, false = Individual
    bool synchronization = false;  // 0x08 -- true = In Sync, false = Out of Sync
    bool collecting = false;       // 0x10
    bool distributing = false;     // 0x20
    bool defaulted = false;        // 0x40 -- true = using default (not LACPDU-learned) partner info
    bool expired = false;          // 0x80
    std::string rendered;          // human-readable one-line rendering of all eight bits
};

struct LacpMessage {
    uint8_t version = 0;

    uint16_t actor_system_priority = 0;
    std::string actor_system;  // MAC
    uint16_t actor_key = 0;
    uint16_t actor_port_priority = 0;
    uint16_t actor_port = 0;
    LacpStateFlags actor_state;

    uint16_t partner_system_priority = 0;
    std::string partner_system;  // MAC
    uint16_t partner_key = 0;
    uint16_t partner_port_priority = 0;
    uint16_t partner_port = 0;
    LacpStateFlags partner_state;

    uint16_t collector_max_delay = 0;

    std::string summary;
    std::vector<std::string> notes;
};

struct MarkerMessage {
    bool is_response = false;  // false = Marker Information (request), true = Marker Response Information
    uint16_t requester_port = 0;
    std::string requester_system;  // MAC
    uint32_t requester_transaction_id = 0;
    std::string summary;
    std::vector<std::string> notes;
};

// A Local or Remote Information TLV inside an OAM Information OAMPDU. See this file's own header
// comment for why state_raw/oampdu_config_raw are shown as raw wire values rather than bit-decoded.
struct OamInformationTlv {
    std::string which;  // "Local" or "Remote"
    uint8_t oam_version = 0;
    uint16_t revision = 0;
    uint8_t state_raw = 0;
    uint8_t config_raw = 0;
    bool config_mode_active = false;          // 0x01 -- true = Active, false = Passive
    bool config_unidirectional = false;       // 0x02
    bool config_remote_loopback = false;      // 0x04
    bool config_link_events = false;          // 0x08
    bool config_variable_retrieval = false;   // 0x10
    uint16_t oampdu_config_raw = 0;            // "Max OAMPDU Size", raw 16-bit wire value
    std::string oui_hex;
    std::string vendor_specific_hex;
    std::string rendered;
};

// One event TLV inside an Event Notification OAMPDU. For the four curated types (see this file's
// own header comment), window/threshold/errors/error_running_total/event_running_total are
// populated and fields_decoded is true; for anything else (Organization Specific, or a type this
// decoder doesn't recognize), only type/type_name/timestamp are populated and raw_hex holds the
// rest of the TLV's declared-length body verbatim.
struct OamEvent {
    uint8_t type = 0;
    std::string type_name;
    uint16_t timestamp = 0;
    bool fields_decoded = false;
    uint64_t window = 0;
    uint64_t threshold = 0;
    uint64_t errors = 0;
    uint64_t error_running_total = 0;
    uint32_t event_running_total = 0;
    std::string raw_hex;  // only populated when !fields_decoded
    std::string rendered;
};

struct OamMessage {
    uint16_t flags_raw = 0;
    bool flag_link_fault = false;
    bool flag_dying_gasp = false;
    bool flag_critical_event = false;
    bool flag_local_evaluating = false;
    bool flag_local_stable = false;
    bool flag_remote_evaluating = false;
    bool flag_remote_stable = false;

    uint8_t code = 0;
    std::string code_name;

    bool is_information = false;
    std::optional<OamInformationTlv> local_info;
    std::optional<OamInformationTlv> remote_info;
    bool has_organization_specific_info_tlv = false;

    bool is_event_notification = false;
    uint16_t event_sequence = 0;
    std::vector<OamEvent> events;
    bool events_truncated = false;

    bool is_variable_request = false;
    bool is_variable_response = false;

    bool is_loopback_control = false;
    std::optional<bool> loopback_enable;  // true = Enable(0x01), false = Disable(0x02)

    bool is_organization_specific = false;

    std::string summary;
    std::vector<std::string> notes;
};

struct SlowProtocolsMessage {
    uint8_t subtype = 0;
    std::string subtype_name;  // always populated -- try_parse_slow_protocols declines the frame
                                 // entirely for an unrecognized/unsupported subtype (see this
                                 // file's own "deliberately out of scope" paragraph)

    bool is_lacp = false;
    std::optional<LacpMessage> lacp;

    bool is_marker = false;
    std::optional<MarkerMessage> marker;

    bool is_oam = false;
    std::optional<OamMessage> oam;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x8809 -- or after a
// single already-unwrapped 802.1Q VLAN tag) as one Slow Protocols PDU. Returns std::nullopt (never
// throws) when the Subtype byte isn't 1/2/3, or when that subtype's own structural gate (LACP's
// Actor/Partner/Collector/Terminator TLV type+length match, Marker's TLV type match, OAM's Code
// value match) fails -- see this file's own header comment for each subtype's exact gate.
std::optional<SlowProtocolsMessage> try_parse_slow_protocols(ByteSpan eth_payload);

// Stage (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper around
// try_parse_slow_protocols above, following ARP's/LLDP's own EtherType-gated, stateless shape --
// see slow_protocols.cpp.
class SlowProtocolsDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "slow-protocols"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_SLOW_PROTOCOLS; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& slow_protocols_decoder();

}  // namespace conduitscope
