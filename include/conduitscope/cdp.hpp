// SPDX-License-Identifier: Apache-2.0
// cdp.hpp - Cisco Discovery Protocol (CDP) decoding.
//
// Like STP (see stp.hpp), CDP has no EtherType of its own -- but unlike STP, it isn't LLC-SAP-keyed
// either. CDP rides classic IEEE 802.3 LLC framing, SNAP-encapsulated (LLC DSAP == SSAP == 0xAA,
// see link_layer.hpp's LLC_SAP_SNAP), under Cisco's own IEEE-assigned SNAP OUI (00:00:0C,
// link_layer.hpp's SNAP_OUI_CISCO) -- the exact same envelope shape Cisco (R)PVST+ uses (see
// stp.hpp's "Out of scope" section) -- disambiguated from PVST+, and from CDP's own SNAP-OUI
// siblings (VTP/DTP/PAgP/UDLD/CGMP), purely by the 2-byte SNAP Protocol ID (PID) field.
//
// SOURCING (verified directly against Wireshark's own dissector source during this task's research
// phase, the same "verified source before implementation" discipline Zigbee/CoAP/CODESYS already
// used in this codebase -- see their own file header comments): `epan/dissectors/packet-cdp.c`
// (header layout, checksum quirk, TLV format, TLV type table) and `epan/dissectors/
// packet-cisco-oui.c` (the `cisco_pid_vals[]` SNAP-Protocol-ID-to-name table -- the actual source of
// truth for which PID belongs to which Cisco protocol; there is no separate `packet-cisco-pid.h` in
// the current tree, a name this task's own brief floated as a possibility that turned out not to
// exist). Cross-checked against the CDP page on wiki.wireshark.org (a live worked example --
// "Device ID (0x0001) Length: 13" containing a 9-character value -- confirms Length counts the
// 4-byte TLV header itself, see "TLV FORMAT" below) and, for the Capabilities bitmask (this task's
// fetch tooling could name every capability field Wireshark defines, and their wire order, but could
// not pull the dissector's own literal bitmask-constant lines out of its >1500-line source), two
// independent secondary sources (a Cisco-MIB-derived SNMP::Info::CDP Perl module's own documented
// bit table, and an independent CDP protocol writeup) that agree with each other AND with Wireshark's
// own field names/order -- see "CAPABILITIES" below for the full citation.
//
// SNAP PROTOCOL ID (the actual dispatch key -- see decoder.cpp's SNAP call site and CdpDecoder's own
// comment below): CDP registers under SNAP PID 0x2000 (`CDP` in cisco_pid_vals[]). Confirmed
// genuinely distinct from every SNAP-OUI-Cisco sibling this codebase's own SNAP dispatch cares
// about: PVSTP+ (Cisco (R)PVST+, stp.hpp's own "Out of scope" protocol) is 0x010B
// (`CISCO_PID_PVSTPP`) -- NOT 0x2000, confirming the pre-existing PVST+-mislabeling collision this
// release's own roadmap item fixes was real and precisely fixable (see decoder.cpp's own comment at
// its SNAP dispatch call site for how this was proven before the fix). Also confirmed distinct, for
// completeness/documentation even though this codebase doesn't decode any of them: VTP is 0x2003,
// DTP is 0x2004, CGMP is 0x2001, PAgP is 0x0104, UDLD is 0x0111.
//
// HEADER (4 bytes, immediately after the 5-byte SNAP header -- i.e. link_layer.hpp's
// EthernetFrame::llc_payload, when has_snap && snap_oui == SNAP_OUI_CISCO && snap_protocol_id ==
// SNAP_PID_CDP):
//   Version   @0  1 byte   -- 1 (CDPv1) or 2 (CDPv2); CDPv2 added several TLVs (System Name, VTP
//                             Management Domain, Native VLAN, Duplex, and the power/trust/EnergyWise
//                             family) that a CDPv1 sender never emits. This decoder does not reject
//                             an unusual version byte (the SNAP Protocol ID match at the call site is
//                             already this frame's own strong structural gate -- see CdpDecoder's own
//                             comment below) -- it decodes whatever TLVs are actually present
//                             regardless of the declared version, and only notes when the version
//                             byte is neither 1 nor 2.
//   TTL       @1  1 byte   -- seconds a receiver should keep this announcement's information valid
//                             (Cisco's own default is 180s, refreshed roughly every 60s).
//   Checksum  @2  2 bytes, big-endian -- see "CHECKSUM" below: NOT validated by this decoder.
//   TLVs      @4  onward   -- see "TLV FORMAT" below.
//
// CHECKSUM: Wireshark's own dissector carries an explicit comment (paraphrased here, not quoted
// verbatim) that CDP's checksum does NOT follow RFC 1071 section 2(B) correctly -- Cisco's own
// original implementation assumed a big-endian platform when padding an odd-length payload for the
// ones'-complement sum, so instead of appending a zero PAD byte at the end (RFC 1071's own rule), it
// folds the last real octet into the high byte of the final 16-bit word, a documented, real-world
// implementation quirk any from-scratch validator has to special-case to avoid flagging every
// odd-length real CDP packet as corrupt. This decoder does NOT compute or validate the checksum at
// all: per this task's own research question, TLV walking depends ONLY on each TLV's own declared
// Length field (see "TLV FORMAT" below), never on checksum correctness -- there is nothing checksum-
// dependent anywhere in this decoder's control flow, so skipping validation costs nothing structural
// and avoids re-implementing Cisco's own documented quirk for a value this decoder never acts on
// anyway (the same "shown as raw hex, never verified" posture this codebase already takes for STP's
// own MST Config Digest and HART-IP's own checksum -- see stp.hpp/hartip.hpp).
//
// TLV FORMAT: Type (2 bytes, big-endian) + Length (2 bytes, big-endian) + Length-minus-4 bytes of
// value. Length counts the 4-byte Type+Length header ITSELF, not just the value that follows it --
// confirmed against a live Wireshark-rendered example (wiki.wireshark.org/CDP): a Device ID TLV
// shown as "Length: 13" carries a 9-character device-ID string (13 - 4 == 9). A TLV whose declared
// Length is less than 4, or whose value would extend past what remains in the frame, ends the TLV
// walk gracefully (this decoder's usual tolerant-degrade posture for a multi-element format -- see
// LLDP's own tlvs_truncated, lldp.hpp) rather than rejecting the whole frame.
//
// TLV TYPE TABLE (numeric IDs verified against packet-cdp.c's own TYPE_* constants):
//   0x0001 Device ID                 -- string. Full decode.
//   0x0002 Addresses                 -- see "ADDRESS TLV STRUCTURE" below. Full decode (IPv4 only;
//                                        any other NLPID/protocol-type is named, not rendered).
//   0x0003 Port ID                   -- string. Full decode.
//   0x0004 Capabilities              -- 4-byte bitmask. Full decode, see "CAPABILITIES" below.
//   0x0005 Software Version          -- string (often multi-line, e.g. a full IOS banner). Full decode.
//   0x0006 Platform                  -- string. Full decode.
//   0x0007 IP Prefix / ODR           -- one or more (address+prefix-length) pairs, used by On-Demand
//                                        Routing. Structural only (name + raw hex) -- not OT/IT-
//                                        relevant enough on its own to earn a curated field decode in
//                                        this pass, matching this codebase's "decode what's relevant,
//                                        name the rest" posture (see this file's own SCOPE note at
//                                        the bottom).
//   0x0008 Protocol Hello            -- Cisco cluster-management "Hello" sub-protocol, its own nested
//                                        TLV-ish structure. Structural only.
//   0x0009 VTP Management Domain     -- string. Full decode. (CDPv2+ in practice.)
//   0x000A Native VLAN               -- 2 bytes, big-endian VLAN ID. Full decode. (CDPv2+.)
//   0x000B Duplex                    -- 1 byte: 0 = Half, 1 = Full. Full decode. (CDPv2+.)
//   0x000E VoIP VLAN Reply           -- structural only.
//   0x000F VoIP VLAN Query           -- structural only.
//   0x0010 Power Consumption         -- 2 bytes, big-endian, milliwatts. Full decode.
//   0x0011 MTU                       -- 4 bytes, big-endian. Structural only (named + raw value shown
//                                        via raw_hex like every other structural-only TLV -- not
//                                        curated onto CdpFrame's own top-level fields, since it isn't
//                                        in this pass's curated list; see SCOPE below).
//   0x0012 Trust Bitmap              -- 1 byte. Structural only.
//   0x0013 Untrusted Port CoS        -- 1 byte. Structural only.
//   0x0014 System Name               -- string. Full decode. (CDPv2+.)
//   0x0015 System Object ID          -- an SNMP OID, shown as raw hex (this decoder does not attempt
//                                        dotted-OID translation, the same posture LLDP's own
//                                        Management Address OID gets -- see lldp.hpp). Structural only.
//   0x0016 Management Address        -- same NLPID+address repeated structure as Addresses (0x0002)
//                                        above. Full decode (IPv4 only, same rule as Addresses).
//   0x0017 Location                  -- structural only.
//   0x0018 External Port ID          -- structural only.
//   0x0019 Power Requested           -- see "POWER REQUESTED / POWER AVAILABLE" below. Full decode
//                                        of the simple (single 4-byte value) shape; structural
//                                        fallback for anything longer.
//   0x001A Power Available           -- same shape/decode rule as Power Requested.
//   0x001B Port Unidirectional       -- structural only.
//   0x001D EnergyWise                -- structural only (a large, Cisco-proprietary sub-structure --
//                                        encrypted payload + sequence numbers + model/hardware/serial
//                                        fields per packet-cdp.c -- genuinely out of scope for a
//                                        first pass, the same "recognized, not decoded further"
//                                        treatment this codebase gives MMS's other 67 services or
//                                        OPC UA's Tier 2 services).
//   0x001F Spare PoE                 -- structural only.
//   0x1000-0x100D  HP-proprietary extensions (HP/Aruba's own wireless-AP-property TLVs, riding
//                                        CDP's own TLV format on HP/Aruba gear) -- structural only,
//                                        by design: this codebase decodes CDP's own OWN TLV set
//                                        richly and names a vendor extension's TYPE + LENGTH + raw
//                                        bytes without attempting its own internal structure, the
//                                        exact "curated depth, not exhaustive value-decode" posture
//                                        lldp.hpp's own Organizationally-Specific TLV handling
//                                        already established for LLDP's vendor extensions.
//   Anything else                    -- structural only, named "unrecognized (0xNNNN)".
//
// ADDRESS TLV STRUCTURE (0x0002 Addresses, and 0x0016 Management Address -- byte-for-byte identical
// structure, confirmed against packet-cdp.c and a live wiki.wireshark.org worked example): Number of
// Addresses (4 bytes, big-endian) followed by that many address entries, each: Protocol Type
// (1 byte: 1 = NLPID, 2 = 802.2/OUI-keyed) + Protocol Length (1 byte) + Protocol (that many bytes --
// for Protocol Type 1/NLPID, this is a single NLPID byte; RFC 1700 / ISO/IEC TR 9577's own registered
// NLPID for IP is 0xCC, confirmed as CDP's own IPv4 convention by the wiki.wireshark.org worked
// example, which shows "Protocol type: NLPID, Protocol length: 1, Protocol: IP, Address length: 4, IP
// address: <dotted-quad>") + Address Length (2 bytes, big-endian) + Address (that many bytes). This
// decoder renders an entry as a dotted-quad IPv4 address only when Protocol Type == 1 (NLPID),
// Protocol Length == 1, the protocol byte == 0xCC (IP), and Address Length == 4; every other
// NLPID/protocol-type/length combination (IPv6's own NLPID 0x8E, CLNP, IPX, or a malformed/truncated
// entry) is named by its protocol type/NLPID value and shown as raw hex -- this is deliberately the
// one CDP TLV this codebase decodes richest, matching this task's own explicit scope steer ("the one
// CDP TLV most worth decoding").
//
// CAPABILITIES (0x0004, exactly 4 bytes when fully decoded -- a shorter value is shown structurally
// instead of guessing at missing bytes): a 32-bit bitmask, MSB-first bit-name order matching
// Wireshark's own `hf_cdp_capabilities_*` field table (whose literal bitmask constants this task's
// fetch tooling could not pull out of the underlying >1500-line source directly, see this file's own
// SOURCING note above) -- cross-checked against two independent secondary sources instead (a
// Cisco-CDP-MIB-derived Perl module, SNMP::Info::CDP, and an independent CDP protocol writeup,
// rhyshaden.com/cdp.htm), both of which agree with each other on every bit value AND agree with
// Wireshark's own field name/order:
//   0x001  Router                     -- performs L3 routing for at least one network-layer protocol
//   0x002  Transparent Bridge         -- performs L2 transparent bridging
//   0x004  Source-Route Bridge        -- performs L2 source-route bridging
//   0x008  Switch                     -- performs L2 switching
//   0x010  Host                       -- sends/receives packets for at least one network-layer
//                                         protocol (i.e. "is a host", not a pure L2/L3 forwarder)
//   0x020  IGMP capable               -- Wireshark's own field name; both secondary sources describe
//                                         the underlying bit as "does not forward IGMP Report
//                                         packets" (an IGMP-snooping-adjacent behavior, not literally
//                                         "can speak IGMP") -- this decoder uses Wireshark's own
//                                         field name for consistency with its own display-filter
//                                         vocabulary, and states this nuance here rather than
//                                         silently picking one description over the other.
//   0x040  Repeater                   -- provides L1 (repeater) functionality
//   0x080  VoIP Phone
//   0x100  Remotely-Managed Device
//   0x200  CVTA / Supports-STP-Dispute -- also documented elsewhere as "CAST Phone Port"; Wireshark's
//                                         own field name is `cvta`, used here.
//   0x400  Two-Port MAC Relay
// Any bit beyond 0x400 (bits 11-31) is unnamed by any source this decoder could find and is surfaced
// only as "bit N" -- the same "name what's confirmed, number the rest" posture LLDP's own
// capability_bit_name takes for its own System Capabilities TLV (lldp.cpp).
//
// POWER REQUESTED (0x0019) / POWER AVAILABLE (0x001A): Wireshark's own display-filter reference
// (dfref) lists both as a single "Unsigned integer, 32 bits" field each -- this decoder follows that
// shape for the common case: when the TLV's value is exactly 4 bytes, it is read as one big-endian
// 32-bit milliwatt value, the same unit Power Consumption (0x0010) uses. Real Cisco UPOE gear is
// known to sometimes negotiate power in a longer, multi-value extended form (informally documented
// around a leading Request-ID/Management-ID pair followed by one or more repeated power values) --
// this task's own fetch tooling could not pull a literal, source-confirmed byte layout for that
// longer form out of packet-cdp.c (a referenced Wireshark bug report, #2189, tracks exactly this gap
// in Wireshark's own historical support for these two TLV types), so rather than guess at an
// unconfirmed sub-structure, this decoder falls back to structural-only (name + raw hex) for any
// Power Requested/Available value that ISN'T exactly 4 bytes -- the same "an unconfirmed sub-format
// is named, not guessed at" discipline stp.hpp's own legacy/alternative MSTI format gets.
//
// SCOPE (decided and documented here, per this task's own explicit delegation of these calls for a
// stable, single-vendor, well-documented protocol with no genuine architectural ambiguity -- the
// same "decide in code, document the rationale" pattern this codebase used for CC-Link IE):
//   Full field decode: Device ID, Port ID, Platform, Software Version, Capabilities (every bit
//   named), Native VLAN, Duplex, Addresses (IPv4 only, richest decode), Management Address (same),
//   VTP Management Domain, System Name, Power Consumption, and Power Requested/Available's simple
//   4-byte shape.
//   Structural-only (TLV type name + raw Length + raw hex value): every other recognized type
//   (IP Prefix/ODR, Protocol Hello, VoIP VLAN Reply/Query, MTU, Trust Bitmap, Untrusted Port CoS,
//   System Object ID, Location, External Port ID, Port Unidirectional, EnergyWise, Spare PoE, any
//   HP-proprietary 0x1000+ extension, and Power Requested/Available's own longer/unconfirmed shape),
//   plus any wholly unrecognized TLV type.
//   No checksum validation -- see "CHECKSUM" above for why this is safe and not secretly load-bearing
//   for TLV walking.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// CDP's own SNAP Protocol ID -- the actual dispatch key decoder.cpp's SNAP call site checks (see
// this file's own header comment's "SNAP PROTOCOL ID" section). Defined here (CDP-specific), not in
// link_layer.hpp, the same "the generic LLC/SNAP header fields live in link_layer.hpp; a specific
// riding protocol's own magic constants live in its own file" split stp.hpp's own constants (e.g.
// LLC_SAP_BPDU stays in link_layer.hpp since STP/GARP both use it, but STP's own BPDU-body constants
// live in stp.cpp) already established.
constexpr uint16_t SNAP_PID_CDP = 0x2000;

// Cisco (R)PVST+'s own SNAP Protocol ID (CISCO_PID_PVSTPP in Wireshark's packet-cisco-oui.c) --
// defined here, alongside CDP's own, specifically so decoder.cpp's SNAP dispatch can distinguish the
// two precisely (see this file's own header comment and decoder.cpp's own SNAP call site comment for
// the collision this constant's addition fixes). stp.hpp itself never needed this value by name
// before now -- it only ever checked SNAP_OUI_CISCO generically, naming every Cisco-OUI SNAP frame
// "PVST+" regardless of PID, which is exactly the bug this release fixes.
constexpr uint16_t SNAP_PID_PVSTPP = 0x010B;

// One decoded NLPID+address entry, shared by the Addresses (0x0002) and Management Address (0x0016)
// TLVs -- see this file's own "ADDRESS TLV STRUCTURE" header comment.
struct CdpAddress {
    uint8_t protocol_type = 0;       // 1 = NLPID, 2 = 802.2/OUI-keyed
    std::string protocol_type_name;  // "NLPID" / "802.2" / "unknown(N)"
    uint8_t protocol_length = 0;
    std::vector<uint8_t> protocol_bytes;  // the Protocol field itself, raw (usually 1 byte: the NLPID)
    bool is_ipv4 = false;   // protocol_type==1 && protocol_length==1 && protocol_bytes[0]==0xCC (IP)
                              // && address_length==4 -- see this file's own header comment
    std::string protocol_name;  // "IP" when is_ipv4, else "NLPID 0xNN" / "802.2" / "unknown"
    uint16_t address_length = 0;
    std::string address_rendered;  // dotted-quad when is_ipv4, else raw hex of the address bytes
};

// One TLV as it appeared on the wire, in order -- the same "every TLV, curated where possible,
// structural otherwise" shape LldpTlv (lldp.hpp) already established for this codebase's other
// TLV-walking Layer-2 protocol.
struct CdpTlv {
    uint16_t type = 0;
    std::string type_name;
    uint16_t length = 0;       // the RAW on-the-wire Length value -- includes the 4-byte header
                                 // itself, see this file's own "TLV FORMAT" header comment
    std::string rendered;       // populated for a TLV this decoder curates further
    std::string raw_hex;        // populated instead for a structural-only TLV (the VALUE bytes only,
                                 // i.e. length-4 bytes -- never the 4-byte header itself)
};

struct CdpFrame {
    uint8_t version = 0;         // 1 (CDPv1) or 2 (CDPv2) -- see this file's header comment
    uint8_t ttl_seconds = 0;
    uint16_t checksum = 0;       // never validated -- see this file's own "CHECKSUM" header comment

    // Curated fields -- populated only when that TLV type was actually seen (has_* guards each,
    // the same convention lldp.hpp's own LldpMessage already uses).
    bool has_device_id = false;
    std::string device_id;
    bool has_port_id = false;
    std::string port_id;
    bool has_platform = false;
    std::string platform;
    bool has_software_version = false;
    std::string software_version;

    bool has_capabilities = false;
    uint32_t capabilities = 0;
    std::vector<std::string> capabilities_names;  // see this file's own "CAPABILITIES" header comment

    bool has_native_vlan = false;
    uint16_t native_vlan = 0;
    bool has_duplex = false;
    bool duplex_full = false;   // true = Full, false = Half -- only meaningful when has_duplex

    bool has_vtp_management_domain = false;
    std::string vtp_management_domain;
    bool has_system_name = false;  // CDPv2+ in practice
    std::string system_name;

    bool has_power_consumption_mw = false;
    uint16_t power_consumption_mw = 0;
    // See this file's own "POWER REQUESTED / POWER AVAILABLE" header comment -- only set for the
    // simple, exactly-4-byte shape; a longer value is left structural-only (see `tlvs` below) with
    // has_power_requested_mw/has_power_available_mw staying false.
    bool has_power_requested_mw = false;
    uint32_t power_requested_mw = 0;
    bool has_power_available_mw = false;
    uint32_t power_available_mw = 0;

    // Every Addresses (0x0002) TLV's own entries, concatenated in wire order across however many
    // Addresses TLVs actually appeared (conventionally exactly one) -- capped at
    // resource_limits().max_decoded_objects, the same convention every other repeated-element list
    // in this codebase uses.
    std::vector<CdpAddress> addresses;
    // Same, but for Management Address (0x0016) -- kept separate from `addresses` since the two TLV
    // types mean different things (an interface's own address vs. the device's management address)
    // even though they share byte-for-byte the same on-wire structure.
    std::vector<CdpAddress> management_addresses;

    // Every TLV seen, in wire order -- capped at resource_limits().max_decoded_objects, same
    // convention as LldpMessage::tlvs (lldp.hpp).
    std::vector<CdpTlv> tlvs;
    bool tlvs_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `llc_payload` (the bytes immediately after a classic-802.3 SNAP-encapsulated
// frame's 5-byte SNAP header -- see link_layer.hpp's EthernetFrame::llc_payload; the caller is
// responsible for having already confirmed has_snap && snap_oui == SNAP_OUI_CISCO &&
// snap_protocol_id == SNAP_PID_CDP, see decoder.cpp's own SNAP call site) as one CDP announcement.
// Returns std::nullopt (never throws) only when fewer than 4 bytes are present -- too short to even
// read the fixed Version/TTL/Checksum header -- the same "throw/decline only when even the fixed
// minimum can't be read" tolerance can_socketcan.hpp's and ieee802154.hpp's own parsers already use.
// Once those 4 bytes are available, this always returns a CdpFrame (an unusual version byte is noted,
// not rejected -- the SNAP Protocol ID match at the call site is already this frame's own strong
// structural gate, see this file's header comment); individual TLV truncation degrades gracefully
// (tlvs_truncated is set and a note is added), the same posture try_parse_lldp already established.
std::optional<CdpFrame> try_parse_cdp(ByteSpan llc_payload);

// registration-model wrapper around try_parse_cdp above, following STP's own precedent (stp.hpp) for
// a non-EtherType-keyed protocol rather than LLDP's own EtherType-keyed shape: CDP has no EtherType
// of its own at all (it's SNAP-Protocol-ID-keyed, not EtherType-keyed), so ethertype() is
// deliberately left at ProtocolDecoder's own std::nullopt default. gate_kind() is still
// GateKind::EtherType, the same bucket that enum's own doc comment already places STP in (see
// protocol_decoder.hpp's GateKind::EtherType comment, which now also lists CDP) -- decoder.cpp's own
// call site retains full responsibility for CDP's actual structural gate (SNAP OUI + exact SNAP
// Protocol ID, see this file's own "SNAP PROTOCOL ID" header comment) before ever reaching decode()
// below, exactly the same "gate lives at the call site, not in the class" shape StpDecoder's own
// comment documents.
class CdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "cdp"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& cdp_decoder();

}  // namespace conduitscope
