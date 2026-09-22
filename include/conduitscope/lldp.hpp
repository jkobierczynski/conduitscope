// SPDX-License-Identifier: Apache-2.0
// lldp.hpp - Link Layer Discovery Protocol (IEEE 802.1AB, EtherType 0x88CC) decoding.
//
// LLDP has no transport layer and no IP layer of its own -- it rides directly on raw Ethernet
// (EtherType 0x88CC), the same "no port, no IP layer" shape ARP/EAPOL/PPPoE/MPLS/PROFINET RT/GOOSE/
// SV/EtherCAT already have in this codebase (see arp.hpp's own header comment for the most recent
// example of this shape), so this file follows their own structure: its own dedicated file, its own
// try_parse_lldp entry point, wired into decoder.cpp's EtherType-keyed dispatch chain.
//
// Wire format (IEEE Std 802.1AB, cross-checked against Wireshark's packet-lldp.c): a sequence of
// Type-Length-Value elements ("TLVs"), each a single 2-byte big-endian header packed as
// `type = header >> 9` (top 7 bits) and `length = header & 0x1FF` (bottom 9 bits, 0-511), followed
// by exactly `length` bytes of value -- NOT a byte-split type/length the way some other TLV formats
// in this codebase work; both fields share one 16-bit word. The sequence is terminated by an
// End-of-LLDPDU TLV (type 0, length 0) or by payload exhaustion.
//
// TLV type table (IEEE 802.1AB clause 8, cross-checked against packet-lldp.c's tlv_types[]):
//   0   End of LLDPDU
//   1   Chassis ID       -- MANDATORY, must be the first TLV in the PDU
//   2   Port ID          -- MANDATORY, must be the second TLV in the PDU
//   3   Time To Live     -- MANDATORY, must be the third TLV in the PDU, fixed 2-byte value
//   4   Port Description
//   5   System Name
//   6   System Description
//   7   System Capabilities
//   8   Management Address
//   127 Organizationally Specific
//   (9-126 are reserved by the standard; this decoder names them only if actually seen)
//
// Chassis ID (type 1) and Port ID (type 2) each carry their own leading subtype byte, then a value
// whose format depends on that subtype -- and these are TWO INDEPENDENT SUBTYPE TABLES, NOT
// PARALLEL, a real gotcha worth calling out explicitly (verified directly against packet-lldp.c's
// own chassis_id_subtype_vals[] and port_id_subtype_vals[] -- they are genuinely different tables,
// not the same table reused):
//   Chassis ID subtype (IEEE 802.1AB Table 8-2):        Port ID subtype (IEEE 802.1AB Table 8-3):
//     1 Chassis component                                 1 Interface alias
//     2 Interface alias                                   2 Port component
//     3 Port component                                    3 MAC address
//     4 MAC address                                        4 Network address
//     5 Network address                                   5 Interface name
//     6 Interface name                                    6 Agent circuit ID
//     7 Locally assigned                                  7 Locally assigned
//   Subtype 4 is "MAC address" for Chassis ID but "Network address" for Port ID; subtype 3 is "Port
//   component" for Chassis ID but "MAC address" for Port ID -- these are NOT the same meaning at the
//   same numeric value, and treating them as if they were is exactly the gotcha this comment exists
//   to prevent (see try_parse_lldp's own render-by-subtype logic, which keeps the two tables and the
//   two render functions entirely separate rather than sharing one).
//   Rendering, common to both fields: "MAC address" -> raw 6 bytes rendered as a MAC (format_mac);
//   "Network address" -> 1 address-family byte (IANA Address Family Numbers) + address bytes, IPv4
//   (family 1) rendered dotted-quad, anything else shown as raw hex; "Interface alias"/"Interface
//   name"/"Port component"/"Locally assigned"/"Chassis component"/"Agent circuit ID" -> the
//   remaining bytes cast directly to a string (matching this codebase's existing convention for a
//   protocol-declared-ASCII field -- see profinet.cpp's own NameOfStation handling, which does the
//   same direct byte-to-char cast without further sanitization); a malformed/too-short MAC or
//   Network-address value falls back to raw hex rather than guessing.
//
// TTL (type 3): a fixed 2-byte big-endian seconds value -- how long the receiver should keep this
// PDU's information valid. A TTL of 0 is itself meaningful (RFC/spec-defined "shutdown" signal,
// telling neighbors to immediately invalidate this device's info) and is noted, not just decoded.
//
// System Capabilities (type 7): a fixed 4-byte value -- a 2-byte "System Capabilities" bitmap
// (which capabilities this device is capable of) followed by a 2-byte "Enabled Capabilities" bitmap
// (which of those are actually turned on), both big-endian. Bit table (IEEE 802.1AB Table 8-4,
// cross-checked against packet-lldp.c's tlv_sys_cap_vals[]): bit 0 Other, 1 Repeater, 2 MAC Bridge,
// 3 WLAN Access Point, 4 Router, 5 Telephone, 6 DOCSIS Cable Device, 7 Station Only, 8 C-VLAN
// Component, 9 S-VLAN Component, 10 Two-Port MAC Relay (TPMR). Any bit beyond 10 is named only by
// its bit number.
//
// Management Address (type 8, IEEE 802.1AB clause 8.5.9, cross-checked against packet-lldp.c's
// dissect_lldp_management_address_tlv): Management Address String Length (1 byte, the byte count of
// the following Address Subtype + Address Address together) + Address Subtype (1 byte, IANA Address
// Family Numbers -- 1 = IPv4, 2 = IPv6, 6 = 802 media/MAC) + Management Address (variable, the
// remaining bytes of the string-length-declared span) + Interface Numbering Subtype (1 byte: 1 =
// Unknown, 2 = ifIndex, 3 = System port number) + Interface Number (4 bytes, big-endian) + OID
// String Length (1 byte) + Object Identifier (variable, that many bytes, shown as raw hex -- this
// decoder does not attempt to translate an OID into dotted notation). Only the first Management
// Address TLV seen is curated onto LldpMessage's own top-level fields; every Management Address TLV
// (including a repeat) still appears in the raw `tlvs` list.
//
// Organizationally Specific (type 127, IEEE 802.1AB clause 9): OUI (3 bytes) + organizationally
// defined Subtype (1 byte) + organizationally defined value (the rest). This decoder names the OUI
// when recognized (IEEE 802.1, IEEE 802.3, LLDP-MED/TIA-1057, and PROFINET's own OUI -- this
// codebase already decodes PROFINET DCP, see profinet.hpp) and shows the sub-TLV's own Subtype byte
// plus its remaining payload as raw hex; it does not decode any vendor extension's own sub-TLV
// structure.
//
// Structural detection gate, the strongest of any raw-Ethernet protocol in this codebase (stronger
// than EAPOL's/EtherCAT's own "EtherType carries most of the confidence" posture -- see their own
// "structural detection gate" paragraphs): IEEE 802.1AB itself mandates the first three TLVs appear
// in fixed order -- Chassis ID (type 1), then Port ID (type 2), then TTL (type 3, exactly 2 bytes)
// -- and this decoder enforces exactly that: any deviation (wrong type in one of the first three
// slots, or a TLV whose declared length doesn't fit the remaining payload) declines the whole frame
// back to the generic ethertype fallback rather than guessing.
//
// Audit framing: LLDP is broadcast unsolicited roughly every 30 seconds with zero access control of
// any kind -- unlike PROFINET DCP (an active Identify Request/Response an engineering tool has to
// send), any passive listener on the segment gets a continuously-refreshed device inventory (System
// Name/Description, Chassis/Port identity, Management Address) for free, with no interaction
// required at all. This is the strongest passive asset-inventory signal of any protocol in this
// codebase.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// One TLV as it appeared on the wire, in order. `rendered` holds this file's own best-effort
// human-readable rendering of the value (matching whichever curated field, if any, this TLV also
// populated on LldpMessage below); `raw_hex` is populated instead for a TLV type/subtype this
// decoder doesn't further interpret.
struct LldpTlv {
    uint8_t type = 0;
    std::string type_name;
    uint16_t length = 0;
    std::string rendered;
    std::string raw_hex;
};

struct LldpMessage {
    // Chassis ID (TLV type 1) -- mandatory, always the first TLV; see this file's own subtype-table
    // comment for why chassis_id_subtype and port_id_subtype are NOT looked up in the same table.
    uint8_t chassis_id_subtype = 0;
    std::string chassis_id_subtype_name;
    std::string chassis_id_value;  // rendered per subtype -- MAC, dotted-quad/hex, or raw string

    // Port ID (TLV type 2) -- mandatory, always the second TLV.
    uint8_t port_id_subtype = 0;
    std::string port_id_subtype_name;
    std::string port_id_value;

    // TTL (TLV type 3) -- mandatory, always the third TLV, exactly 2 bytes.
    uint16_t ttl_seconds = 0;

    // Optional TLVs -- populated only if that TLV type was actually seen (has_* guards each).
    bool has_port_description = false;
    std::string port_description;
    bool has_system_name = false;
    std::string system_name;
    bool has_system_description = false;
    std::string system_description;

    bool has_system_capabilities = false;
    uint16_t system_capabilities = 0;
    uint16_t enabled_capabilities = 0;
    std::vector<std::string> system_capabilities_names;
    std::vector<std::string> enabled_capabilities_names;

    bool has_management_address = false;  // only the FIRST Management Address TLV seen is curated
                                            // here -- see this file's own header comment
    uint8_t management_address_subtype = 0;
    std::string management_address_subtype_name;
    std::string management_address;  // dotted-quad for IPv4 (subtype 1), else raw hex

    // Every TLV seen, in wire order, including the three mandatory ones above -- capped at
    // resource_limits().max_decoded_objects (default 50), the same convention as every other
    // repeated-element list in this codebase.
    std::vector<LldpTlv> tlvs;
    bool tlvs_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x88CC -- or after a
// single already-unwrapped 802.1Q VLAN tag) as one LLDP PDU. Returns std::nullopt (never throws)
// unless the first three TLVs are exactly Chassis ID, Port ID, then a 2-byte TTL, each fitting the
// available payload -- see this file's own "structural detection gate" paragraph. Once that gate
// passes, a later TLV whose declared length doesn't fit what remains ends the TLV loop gracefully
// (tlvs_truncated is set and a note is added) rather than rejecting the whole PDU, matching this
// codebase's usual graceful-degradation posture for other multi-element formats (IGRP's routes,
// EtherCAT's datagrams).
std::optional<LldpMessage> try_parse_lldp(ByteSpan eth_payload);

// Stage 2 (see protocol_decoder.hpp/protocol_registry.hpp): thin ProtocolDecoder wrapper around
// try_parse_lldp above. Like ARP/EAPOL/PPPoE/MPLS, EtherType-gated with no cross-packet state, so
// this needs nothing beyond id()/gate_kind()/ethertype()/decode(); see lldp.cpp. A brand-new
// protocol built entirely on this interface from inception -- no legacy if-chain to coexist with.
class LldpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "lldp"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_LLDP; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& lldp_decoder();

}  // namespace conduitscope
