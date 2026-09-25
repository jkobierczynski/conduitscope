// SPDX-License-Identifier: Apache-2.0
// homeplug_av.hpp - HomePlug AV / HomePlug AV2 powerline networking (EtherType 0x88E1) decoding:
// the MME (Management Message Entry) header, MMTYPE's Kind/Category bitfields plus a curated
// message-name table, the MMV/header-size edge cases the spec below documents in detail, and a
// bounded set of fully field-decoded payload shapes (CC_DISCOVER_LIST.CNF's station/network
// arrays, CM_SET_KEY.REQ's key-exchange fields, CM_BRG_INFO.CNF's bridge/station list).
//
// devolo's own "dLAN" product line (the 200/500/650/1200-series, AVmini/AVsmart+, ...) is NOT a
// separate protocol -- devolo is a founding HomePlug Powerline Alliance member, and its dLAN
// adapters are HomePlug AV or HomePlug AV2 devices on the wire; devolo's own "dLAN Cockpit"
// configuration tool, and third-party tools like `faifa`/`dlanlist`/`dlanpasswd`, talk to them
// using the standard HomePlug AV management protocol decoded here, not a devolo-specific one --
// see docs/DEVELOPMENT.md ROADMAP item 26 for the full framing.
//
// SOURCING: every byte offset, bit mask, and named MMTYPE value below is cross-checked directly
// against the Wireshark HomePlug AV dissector source -- both the mainline `packet-homeplug-av.c`
// and the independent standalone `homeplug-av.lua` -- both fetched and read directly during this
// task's own research phase, not taken from a secondhand description. Confidence in the MME
// header shape (including its MMV/category-dependent size, below) and the MMTYPE Kind/Category
// bit masks is HIGH; the curated MMTYPE name table is a SMALL, DELIBERATELY NON-EXHAUSTIVE subset
// (the dissector's own `mmtype_names` table has 100+ entries, many of them chipset-vendor-specific
// -- e.g. a distinct `mmtype_qualcomm` extension table this file does not attempt to enumerate) --
// see this file's own "CURATED MMTYPE NAME TABLE" section below for exactly what's covered.
//
// WIRE FORMAT -- the MME header, immediately after the Ethernet header (or after a single already-
// unwrapped 802.1Q VLAN tag), the same "EtherType-gated, no IP layer" shape PROFINET RT/EtherCAT/
// GOOSE/EAPOL already have in this codebase (see eapol.hpp's own file header comment, this file's
// closest structural template):
//
//     offset 0       MMV      1 byte   Management Message Version
//     offset 1-2     MMTYPE   2 bytes  little-endian
//     offset 3       FMI      1 byte   high nibble (0xF0) = NF_MI (fragment count),
//                                      low nibble (0x0F) = FN_MI (this fragment's index)
//     offset 4       FMSN     1 byte   Fragmentation Message Sequence Number
//     offset 5+      --                MME payload, type-specific
//
// HEADER-SIZE EDGE CASE (confirmed against the dissector source -- the one genuinely surprising
// wrinkle in this whole wire format, and the reason this decoder cannot just always assume the
// 5-byte layout above):
//   - MMV == 0x00 (AV 1.0) AND MMTYPE's Category (see below) is Manufacturer-Specific (0x04) or
//     Vendor-Specific (0x05): the header is only 3 bytes (MMV + MMTYPE) -- there is NO FMI/FMSN on
//     the wire at all -- and a 3-byte OUI immediately follows at offset 3-5, then payload at
//     offset 6.
//   - Every other case (MMV == 0x00 non-vendor/manufacturer, or MMV == 0x01/AV1.1, or MMV == 0x02/
//     AV2, or an unrecognized MMV -- see below): the full 5-byte header above is present. For
//     MMV >= 0x01 vendor/manufacturer-category messages SPECIFICALLY, an ADDITIONAL 3-byte OUI
//     follows the 5-byte header (offset 5-7), then payload at offset 8.
//   MMV values 0x00/0x01/0x02 are named "1.0"/"1.1"/"2.0" (AV2); anything else is an unrecognized
//   MMV -- this decoder still attempts the 5-byte-header parse for it (matching the mainline
//   dissector's own `mmv ? 5 : 3` fallback) but flags it as unrecognized in a note rather than
//   silently mislabeling it as one of the three known versions.
//
// MMTYPE bit layout (masks confirmed exact from source, against the full 16-bit little-endian
// value once decoded):
//   Kind (mask 0x0003): 0x00 = Request, 0x01 = Confirm, 0x02 = Indication, 0x03 = Response.
//   Category (mask 0xE000, shift right 13): 0x00 = "STA - Central Coordinator",
//     0x01 = "Proxy Coordinator", 0x02 = "Central Coordinator - Central Coordinator",
//     0x03 = "STA - STA", 0x04 = "Manufacturer Specific", 0x05 = "Vendor Specific",
//     0x06 = "Reserved", 0x07 = "Unknown".
//   The middle bits (mask 0x1FFC) have no further standalone bitfield meaning -- the full 16-bit
//   MMTYPE value is used as the lookup key into the curated name table below instead.
//
// CURATED MMTYPE NAME TABLE: a small, deliberately non-exhaustive subset -- discovery
// (CC_DISCOVER_LIST.REQ/CNF/IND), bridging (CM_BRG_INFO.REQ/CNF), encryption/key management
// (CM_ENCRYPTED_PAYLOAD.IND/RSP, CM_SET_KEY.REQ/CNF, CM_GET_KEY.REQ/CNF,
// CM_UNASSOCIATED_STA.IND), network/link stats (CM_NW_INFO.REQ/CNF, CM_NW_STATS.REQ/CNF,
// CM_LINK_STATS.REQ/CNF), and CCo election/management (CC_BACKUP_APPOINT, CC_ASSOC, CC_WHO_RU,
// CC_LEAVE, CC_HANDOVER, CP_PROXY_APPOINT, NN_INL, NN_NEW_NET) -- see homeplug_av.cpp's own
// mmtype_name_table() for the exact value-by-value list. Any MMTYPE not in this table gets a
// generic fallback name ("MMTYPE 0xNNNN (kind=..., category=...)") rather than a decode failure --
// this table is NOT a detection gate, just a naming convenience.
//
// BOUNDED PAYLOAD DECODE: only three message bodies get a full fixed-stride field decode this
// pass -- CC_DISCOVER_LIST.CNF (0x0015, the station/network record arrays -- the station MAC list
// is the highest-value field here, the actual list of devices seen on the powerline network),
// CM_SET_KEY.REQ (0x6008, the 38-byte key-exchange payload -- see REDACTION below), and
// CM_BRG_INFO.CNF (0x6021, the bridge/station list). Everything else is classified by MMTYPE name
// only; its payload is reported by length plus a short capped hex preview, never field-decoded --
// the dissector's own complexity past this set rises sharply into tone-maps/TLV bodies/100+-byte
// vendor structures, explicitly out of scope for this first pass (matching DHCPv6's own
// RELAY-FORW inner-message "structural only" precedent, dhcpv6.hpp).
//
// VENDOR/MANUFACTURER OUI: when Category is Manufacturer-Specific (0x04) or Vendor-Specific
// (0x05), the 3-byte OUI at the offset the MMV rule above determines is decoded and, for the two
// OUIs independently confirmed this pass, named: 0x00B052 "Qualcomm Atheros" (also covers the
// historical Intellon lineage this chipset family descends from) and 0x0080E1 "ST/IoTecha". Any
// other OUI is still rendered as raw hex, just unnamed -- this is its own small local table (see
// homeplug_av.cpp's own oui_vendor_name()), like every other protocol-specific vendor/manufacturer
// code table in this codebase (e.g. dcerpc.hpp/melsec.hpp's own small curated tables) rather than
// a reuse of the generic MAC-vendor OUI lookup (oui_table.gen.hpp) -- that table is a MAC-address
// vendor lookup keyed by a different value space entirely, not this protocol's own enumeration.
// The vendor-specific payload itself, past the OUI, is never decoded -- only the vendor is named.
//
// REDACTION: CM_SET_KEY.REQ's own 16-byte nw_key field carries actual HomePlug AV key material
// (a DAK/NMK/NEK/TEK/Hash Key depending on key_type) and is masked with
// DecodeContext::redact_secrets/kRedactedSecretPlaceholder by default, exactly like VRRP's own
// cleartext Simple Text Password (vrrp.hpp) -- --no-redact reveals the real bytes. key_type and
// peks (metadata about the exchange, not the secret itself) are always rendered unredacted.
//
// CURATED SECURITY NOTE (Jurgen's own choice, see docs/DEVELOPMENT.md ROADMAP item 26's "Done"
// writeup): this is consumer/SOHO-grade powerline networking gear, not itself OT/ICS equipment --
// but its mere presence on a network segment is still a worthwhile audit finding (a potential
// unmanaged bridge extending network reach through building wiring, plus HomePlug AV's own
// well-known history of weak default enrollment secrets and, for devolo's gear specifically,
// separately-documented weak management-plane authentication -- see homeplug_av.cpp's own curated
// note text for the full, honest framing, including what this wire protocol genuinely CANNOT see).
// Fired on every recognized frame (bare presence is the finding, per Jurgen's own framing -- not
// gated to only the key-exchange message), no deduplication, matching this codebase's general
// curated-note posture (e.g. BSAP's own NAK note, bsap.cpp). A second, more specific note fires
// additionally when a CM_SET_KEY.REQ carrying key_type DAK or NMK is decoded.
//
// STRUCTURAL DETECTION GATE: unlike GOOSE/SV's single-byte outer BER tag or VMware's 4-byte fixed
// magic number, HomePlug AV's own header has no magic constant at all -- just a version byte and a
// 2-bit Kind field, both fully populated across their whole value range (no "reserved, never
// legitimately seen" values to reject on). The confidence this really is HomePlug AV therefore
// rests almost entirely on the EtherType itself (0x88E1, IANA/IEEE-exclusive, no collision risk
// with any other protocol this tool decodes), the same weaker-gate posture EtherCAT/EAPOL already
// document in their own "structural detection gate" paragraphs (ethercat.hpp/eapol.hpp) -- worth
// being honest about here too, rather than implying a stronger signature than actually exists.
#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// CC_DISCOVER_LIST.CNF (0x0015) -- one 12-byte station record. The packed sub-byte fields
// (network-kind/SNID, status/capability bits, signal level, bit-loading estimate) are surfaced
// only as raw bytes -- not further decoded, see this file's own header comment's BOUNDED PAYLOAD
// DECODE section -- the station's MAC address (the actual audit-relevant content: which devices
// this capture observed on the powerline network) is the one field genuinely decoded here.
struct HomePlugAvStationRecord {
    std::array<uint8_t, 6> mac{};
    uint8_t tei = 0;
    uint8_t same_network_raw = 0;
    uint8_t network_kind_snid_raw = 0;   // packed, not further decoded
    uint8_t status_raw = 0;              // packed BCCo/PCo/CCo bits, not further decoded
    uint8_t signal_level_raw = 0;
    uint8_t avg_bitloading_raw = 0;      // packed mantissa/exponent, not further decoded
};

// CC_DISCOVER_LIST.CNF (0x0015) -- one 13-byte network record.
struct HomePlugAvNetworkRecord {
    std::array<uint8_t, 7> nid{};        // Network ID
    uint8_t network_kind_snid_raw = 0;   // packed, not further decoded
    uint8_t hybrid_mode_raw = 0;
    uint8_t beacon_slots_raw = 0;
    uint8_t coordinating_status_raw = 0;
    uint16_t beacon_offset = 0;
};

// CC_DISCOVER_LIST.CNF (0x0015) -- the whole decoded body.
struct HomePlugAvDiscoverListCnf {
    uint8_t num_stas_declared = 0;
    std::vector<HomePlugAvStationRecord> stations;
    bool stations_truncated = false;  // fewer station records fit than num_stas_declared claimed
    uint8_t num_networks_declared = 0;
    std::vector<HomePlugAvNetworkRecord> networks;
    bool networks_truncated = false;
};

// CM_SET_KEY.REQ (0x6008) -- the fixed 38-byte key-exchange payload. nw_key_hex is redacted (see
// this file's own header comment's REDACTION section) to kRedactedSecretPlaceholder by
// HomePlugAvDecoder::decode when DecodeContext::redact_secrets is active (the default);
// try_parse_homeplug_av itself always decodes the real bytes, matching VrrpDecoder::decode's own
// "parse first, redact at the decode() boundary" split (vrrp.hpp/vrrp.cpp).
struct HomePlugAvSetKeyReq {
    uint8_t key_type_raw = 0;   // masked 0x07
    std::string key_type_name;  // "DAK"/"NMK"/"NEK"/"TEK"/"Hash Key"/"Nonce only (no key)"/"" if unrecognized
    uint32_t my_nonce = 0;
    uint32_t your_nonce = 0;
    uint8_t pid = 0;
    uint16_t prn = 0;
    uint8_t pmn = 0;
    uint8_t cco_cap = 0;
    std::array<uint8_t, 7> nid{};
    uint8_t peks = 0;
    std::string nw_key_hex;     // 32 lowercase hex chars, or kRedactedSecretPlaceholder once redacted
    bool nw_key_redacted = false;
};

// CM_BRG_INFO.CNF (0x6021).
struct HomePlugAvBrgInfoCnf {
    uint8_t bridging_flag = 0;
    bool is_bridging = false;
    uint8_t bridge_tei = 0;
    uint8_t num_stas_declared = 0;
    std::vector<std::array<uint8_t, 6>> station_macs;
    bool stations_truncated = false;
};

struct HomePlugAvFrame {
    uint8_t mmv = 0;
    std::string mmv_name;   // "1.0"/"1.1"/"2.0", empty when mmv_recognized is false
    bool mmv_recognized = false;

    uint16_t mmtype = 0;    // the full, raw 16-bit little-endian MMTYPE value
    uint8_t mmtype_kind_raw = 0;       // mask 0x0003
    std::string mmtype_kind_name;      // always populated -- all 4 values are named
    uint8_t mmtype_category_raw = 0;   // mask 0xE000 >> 13
    std::string mmtype_category_name;  // always populated -- all 8 values are named
    std::string mmtype_name;           // curated name, or a generic "MMTYPE 0xNNNN (...)" fallback
    bool mmtype_recognized = false;    // true only when mmtype matched the curated table

    // Present only for the full 5-byte-header case (see this file's own header comment's
    // HEADER-SIZE EDGE CASE section) -- absent for MMV==0x00 Manufacturer/Vendor-Specific's own
    // 3-byte header.
    bool has_fmi_fmsn = false;
    uint8_t nf_mi = 0;
    uint8_t fn_mi = 0;
    uint8_t fmsn = 0;

    // Present when Category is Manufacturer-Specific (0x04) or Vendor-Specific (0x05) AND enough
    // bytes were captured to reach it -- see this file's own header comment's HEADER-SIZE EDGE
    // CASE section for exactly where this sits.
    bool has_oui = false;
    std::string oui_hex;         // 6 lowercase hex chars, no separator
    std::string oui_vendor_name; // "Qualcomm Atheros"/"ST/IoTecha", or empty if unmatched

    size_t header_size = 0;   // total bytes consumed by MMV+MMTYPE+(FMI/FMSN)+(OUI), for the record
    size_t payload_length = 0;

    // At most one of these three is populated, per this file's own header comment's BOUNDED
    // PAYLOAD DECODE section -- gated on mmtype matching the corresponding curated value AND the
    // payload actually being long enough for that fixed-stride shape.
    bool has_discover_list_cnf = false;
    HomePlugAvDiscoverListCnf discover_list_cnf;
    bool has_set_key_req = false;
    HomePlugAvSetKeyReq set_key_req;
    bool has_brg_info_cnf = false;
    HomePlugAvBrgInfoCnf brg_info_cnf;

    // Populated only when none of the three has_* flags above is set -- a short, capped hex
    // preview of the opaque payload, matching this codebase's other "structural-only" decoders'
    // own preview convention (see homeplug_av.cpp's kMaxOpaquePayloadPreviewBytes).
    std::string opaque_payload_hex_preview;
    bool opaque_payload_preview_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `eth_payload` (the bytes immediately after EtherType 0x88E1 -- or after a
// single already-unwrapped 802.1Q VLAN tag) as one HomePlug AV MME. Returns std::nullopt (never
// throws) only when fewer than 3 bytes are present (not even MMV+MMTYPE fit) -- see this file's
// own header comment's STRUCTURAL DETECTION GATE paragraph for why there is little more to gate
// on than that. Every curated note (including the always-on presence note) is already populated
// on the returned frame; HomePlugAvDecoder::decode below only additionally applies redaction.
std::optional<HomePlugAvFrame> try_parse_homeplug_av(ByteSpan eth_payload);

// registration-model wrapper around try_parse_homeplug_av above, applying redaction to
// CM_SET_KEY.REQ's own nw_key field at the decode() boundary -- same "parse first, redact after"
// split VrrpDecoder::decode uses (vrrp.hpp/vrrp.cpp). EtherType-gated with no cross-packet state,
// like EAPOL/PROFINET RT/EtherCAT/GOOSE/POWERLINK, so this needs nothing beyond
// id()/gate_kind()/ethertype()/decode(); see homeplug_av.cpp.
class HomePlugAvDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "homeplug-av"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_HOMEPLUG_AV; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& homeplug_av_decoder();

}  // namespace conduitscope
