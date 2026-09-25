// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/homeplug_av.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>
#include <unordered_map>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

// A short, capped hex preview of a payload this decoder does not field-decode -- matching this
// codebase's other "structural-only" decoders' own preview convention (e.g. DHCPv6's RELAY-FORW
// inner-message, dhcpv6.cpp, which reports presence/length only, not a full hex dump).
constexpr size_t kMaxOpaquePayloadPreviewBytes = 32;

// MMV -- Management Message Version (offset 0). Only 0x00/0x01/0x02 are named; see this file's own
// "unrecognized MMV" handling in try_parse_homeplug_av.
std::string mmv_name(uint8_t mmv) {
    switch (mmv) {
        case 0x00: return "1.0";
        case 0x01: return "1.1";
        case 0x02: return "2.0";
        default: return "";
    }
}

// MMTYPE Kind (mask 0x0003) -- all 4 values are defined, so this is always populated.
std::string mmtype_kind_name(uint8_t kind) {
    switch (kind) {
        case 0x00: return "Request";
        case 0x01: return "Confirm";
        case 0x02: return "Indication";
        case 0x03: return "Response";
        default: return "";  // unreachable -- kind is masked to 2 bits
    }
}

// MMTYPE Category (mask 0xE000, shift 13) -- all 8 values are defined (0x06/0x07 are themselves
// named "Reserved"/"Unknown" per the dissector source), so this is always populated too.
std::string mmtype_category_name(uint8_t category) {
    switch (category) {
        case 0x00: return "STA - Central Coordinator";
        case 0x01: return "Proxy Coordinator";
        case 0x02: return "Central Coordinator - Central Coordinator";
        case 0x03: return "STA - STA";
        case 0x04: return "Manufacturer Specific";
        case 0x05: return "Vendor Specific";
        case 0x06: return "Reserved";
        case 0x07: return "Unknown";
        default: return "";  // unreachable -- category is masked to 3 bits
    }
}

// Curated MMTYPE name table -- see homeplug_av.hpp's own file header comment's CURATED MMTYPE NAME
// TABLE section for the full sourcing note and scope caveat (a small, deliberately non-exhaustive
// subset of the dissector's own 100+-entry table). Keyed by the full 16-bit MMTYPE value, matching
// this codebase's other small curated code tables (e.g. fins.cpp's command_table()).
const std::unordered_map<uint16_t, const char*>& mmtype_name_table() {
    static const std::unordered_map<uint16_t, const char*> table = {
        // Discovery
        {0x0014, "CC_DISCOVER_LIST.REQ"},
        {0x0015, "CC_DISCOVER_LIST.CNF"},
        {0x0016, "CC_DISCOVER_LIST.IND"},
        // Bridging
        {0x6020, "CM_BRG_INFO.REQ"},
        {0x6021, "CM_BRG_INFO.CNF"},
        // Encryption/key management (security-relevant)
        {0x6006, "CM_ENCRYPTED_PAYLOAD.IND"},
        {0x6007, "CM_ENCRYPTED_PAYLOAD.RSP"},
        {0x6008, "CM_SET_KEY.REQ"},
        {0x6009, "CM_SET_KEY.CNF"},
        {0x600C, "CM_GET_KEY.REQ"},
        {0x600D, "CM_GET_KEY.CNF"},
        {0x6002, "CM_UNASSOCIATED_STA.IND"},
        // Network/link stats
        {0x6038, "CM_NW_INFO.REQ"},
        {0x6039, "CM_NW_INFO.CNF"},
        {0x6048, "CM_NW_STATS.REQ"},
        {0x6049, "CM_NW_STATS.CNF"},
        {0x604C, "CM_LINK_STATS.REQ"},
        {0x604D, "CM_LINK_STATS.CNF"},
        // CCo election/management
        {0x0004, "CC_BACKUP_APPOINT.REQ"},
        {0x0005, "CC_BACKUP_APPOINT.CNF"},
        {0x0030, "CC_ASSOC.REQ"},
        {0x0031, "CC_ASSOC.CNF"},
        {0x002C, "CC_WHO_RU.REQ"},
        {0x002D, "CC_WHO_RU.CNF"},
        {0x0034, "CC_LEAVE.REQ"},
        {0x0035, "CC_LEAVE.CNF"},
        {0x0036, "CC_LEAVE.IND"},
        {0x0037, "CC_LEAVE.RSP"},
        {0x000C, "CC_HANDOVER.REQ"},
        {0x000D, "CC_HANDOVER.CNF"},
        {0x2000, "CP_PROXY_APPOINT.REQ"},
        {0x2001, "CP_PROXY_APPOINT.CNF"},
        {0x4000, "NN_INL.REQ"},
        {0x4001, "NN_INL.CNF"},
        {0x4004, "NN_NEW_NET.REQ"},
        {0x4005, "NN_NEW_NET.CNF"},
        {0x4006, "NN_NEW_NET.IND"},
    };
    return table;
}

// The two HomePlug AV vendor/manufacturer OUIs independently confirmed this pass -- see
// homeplug_av.hpp's own file header comment's VENDOR/MANUFACTURER OUI section for why this is its
// own small local table rather than a reuse of the generic MAC-vendor OUI lookup
// (oui_table.gen.hpp), the same "small local table, not the generic lookup" convention this
// codebase's other protocol-specific vendor/manufacturer code tables already follow.
std::string oui_vendor_name(uint32_t oui) {
    switch (oui) {
        case 0x00B052: return "Qualcomm Atheros";  // also covers the historical Intellon lineage
                                                     // this chipset family descends from
        case 0x0080E1: return "ST/IoTecha";
        default: return "";
    }
}

// CM_SET_KEY.REQ's key_type field (mask 0x07, offset 0 of the 38-byte payload).
std::string key_type_name(uint8_t key_type) {
    switch (key_type) {
        case 0x00: return "DAK";
        case 0x01: return "NMK";
        case 0x02: return "NEK";
        case 0x03: return "TEK";
        case 0x04: return "Hash Key";
        case 0x05: return "Nonce only (no key)";
        default: return "";
    }
}

template <size_t N>
std::array<uint8_t, N> to_array(ByteSpan span) {
    std::array<uint8_t, N> out{};
    for (size_t i = 0; i < N; ++i) out[i] = span.at(i);
    return out;
}

void decode_discover_list_cnf(HomePlugAvFrame& f, ByteSpan payload) {
    Cursor pc(payload);
    HomePlugAvDiscoverListCnf dl;
    dl.num_stas_declared = pc.u8();

    const size_t cap = resource_limits().max_decoded_objects.value_or(256);
    size_t want_stas = std::min<size_t>(dl.num_stas_declared, cap);
    for (size_t i = 0; i < want_stas; ++i) {
        if (pc.remaining() < 12) {
            dl.stations_truncated = true;
            break;
        }
        HomePlugAvStationRecord rec;
        rec.mac = to_array<6>(pc.bytes(6));
        rec.tei = pc.u8();
        rec.same_network_raw = pc.u8();
        rec.network_kind_snid_raw = pc.u8();
        rec.status_raw = pc.u8();
        rec.signal_level_raw = pc.u8();
        rec.avg_bitloading_raw = pc.u8();
        dl.stations.push_back(rec);
    }
    if (dl.stations.size() < dl.num_stas_declared) dl.stations_truncated = true;

    if (pc.remaining() >= 1) {
        dl.num_networks_declared = pc.u8();
        size_t want_nets = std::min<size_t>(dl.num_networks_declared, cap);
        for (size_t i = 0; i < want_nets; ++i) {
            if (pc.remaining() < 13) {
                dl.networks_truncated = true;
                break;
            }
            HomePlugAvNetworkRecord nrec;
            nrec.nid = to_array<7>(pc.bytes(7));
            nrec.network_kind_snid_raw = pc.u8();
            nrec.hybrid_mode_raw = pc.u8();
            nrec.beacon_slots_raw = pc.u8();
            nrec.coordinating_status_raw = pc.u8();
            nrec.beacon_offset = pc.u16le();
            dl.networks.push_back(nrec);
        }
        if (dl.networks.size() < dl.num_networks_declared) dl.networks_truncated = true;
    }

    f.has_discover_list_cnf = true;
    f.discover_list_cnf = std::move(dl);
}

// Fixed 38-byte payload -- see homeplug_av.hpp's own HomePlugAvSetKeyReq comment. Always decodes
// the real nw_key bytes; HomePlugAvDecoder::decode (below) redacts them afterward when
// DecodeContext::redact_secrets is active, the same "parse first, redact at the decode() boundary"
// split vrrp.cpp's own VrrpDecoder::decode uses.
void decode_set_key_req(HomePlugAvFrame& f, ByteSpan payload) {
    Cursor pc(payload);
    HomePlugAvSetKeyReq sk;
    uint8_t kt = pc.u8();
    sk.key_type_raw = kt & 0x07;
    sk.key_type_name = key_type_name(sk.key_type_raw);
    sk.my_nonce = pc.u32le();
    sk.your_nonce = pc.u32le();
    sk.pid = pc.u8();
    sk.prn = pc.u16le();
    sk.pmn = pc.u8();
    sk.cco_cap = pc.u8();
    sk.nid = to_array<7>(pc.bytes(7));
    sk.peks = pc.u8();
    sk.nw_key_hex = to_hex(pc.bytes(16), "");

    f.has_set_key_req = true;
    f.set_key_req = std::move(sk);
}

void decode_brg_info_cnf(HomePlugAvFrame& f, ByteSpan payload) {
    Cursor pc(payload);
    HomePlugAvBrgInfoCnf bi;
    bi.bridging_flag = pc.u8();
    bi.is_bridging = bi.bridging_flag != 0;

    if (bi.is_bridging) {
        if (pc.remaining() >= 2) {
            bi.bridge_tei = pc.u8();
            bi.num_stas_declared = pc.u8();
            const size_t cap = resource_limits().max_decoded_objects.value_or(256);
            size_t want = std::min<size_t>(bi.num_stas_declared, cap);
            for (size_t i = 0; i < want; ++i) {
                if (pc.remaining() < 6) {
                    bi.stations_truncated = true;
                    break;
                }
                bi.station_macs.push_back(to_array<6>(pc.bytes(6)));
            }
            if (bi.station_macs.size() < bi.num_stas_declared) bi.stations_truncated = true;
        } else {
            f.notes.push_back(
                "CM_BRG_INFO.CNF declares bridging active but the payload is too short for its own "
                "bridge_tei/num_stas fields -- truncated");
        }
    }

    f.has_brg_info_cnf = true;
    f.brg_info_cnf = std::move(bi);
}

}  // namespace

std::optional<HomePlugAvFrame> try_parse_homeplug_av(ByteSpan eth_payload) {
    // The only true structural gate: MMV + MMTYPE (3 bytes) must actually fit -- see this file's
    // own header comment's STRUCTURAL DETECTION GATE paragraph for why there is little more to
    // gate on than that. Everything past this point degrades gracefully (notes, not a decode
    // failure), matching this codebase's "never fail the decode over an unrecognized value" posture
    // for every curated-but-not-exhaustive lookup table.
    if (eth_payload.size() < 3) return std::nullopt;

    HomePlugAvFrame f;
    f.mmv = eth_payload.at(0);
    f.mmtype = static_cast<uint16_t>(eth_payload.at(1) | (static_cast<uint16_t>(eth_payload.at(2)) << 8));

    f.mmv_name = mmv_name(f.mmv);
    f.mmv_recognized = !f.mmv_name.empty();

    f.mmtype_kind_raw = static_cast<uint8_t>(f.mmtype & 0x0003);
    f.mmtype_kind_name = mmtype_kind_name(f.mmtype_kind_raw);
    f.mmtype_category_raw = static_cast<uint8_t>((f.mmtype >> 13) & 0x07);
    f.mmtype_category_name = mmtype_category_name(f.mmtype_category_raw);

    auto curated = mmtype_name_table().find(f.mmtype);
    if (curated != mmtype_name_table().end()) {
        f.mmtype_name = curated->second;
        f.mmtype_recognized = true;
    } else {
        f.mmtype_name = "MMTYPE " + hex4(f.mmtype) + " (kind=" + f.mmtype_kind_name +
                          ", category=" + f.mmtype_category_name + ")";
        f.mmtype_recognized = false;
    }

    const bool is_vendor_or_mfg = (f.mmtype_category_raw == 0x04 || f.mmtype_category_raw == 0x05);
    // HEADER-SIZE EDGE CASE -- see this file's own header comment for the full writeup. Only
    // MMV==0x00 (AV 1.0) Manufacturer/Vendor-Specific gets the short, 3-byte, no-FMI/FMSN header;
    // every other case (including an unrecognized MMV, matching the mainline dissector's own
    // `mmv ? 5 : 3` fallback) gets the full 5-byte header.
    const bool short_header = (f.mmv == 0x00) && is_vendor_or_mfg;

    size_t offset = 3;
    if (short_header) {
        f.header_size = 3;
    } else {
        if (eth_payload.size() < 5) {
            f.notes.push_back(
                "frame declares only " + std::to_string(eth_payload.size()) +
                " byte(s), too short for the 5-byte MME header this MMV/category combination "
                "requires -- FMI/FMSN and any payload not decoded");
            f.header_size = eth_payload.size();
            offset = eth_payload.size();
        } else {
            uint8_t fmi = eth_payload.at(3);
            f.has_fmi_fmsn = true;
            f.nf_mi = static_cast<uint8_t>((fmi >> 4) & 0x0F);
            f.fn_mi = static_cast<uint8_t>(fmi & 0x0F);
            f.fmsn = eth_payload.at(4);
            offset = 5;
            f.header_size = 5;
        }
    }

    // OUI -- present for Manufacturer/Vendor-Specific category regardless of MMV, at whichever
    // offset the header-size rule above landed on (3 for the short-header case, 5 for every other
    // MMV>=0x01 vendor/manufacturer case -- see this file's own header comment).
    if (is_vendor_or_mfg && offset < eth_payload.size()) {
        if (eth_payload.size() - offset >= 3) {
            ByteSpan oui_span = eth_payload.subspan(offset, 3);
            f.has_oui = true;
            f.oui_hex = to_hex(oui_span, "");
            uint32_t oui_val = (static_cast<uint32_t>(oui_span.at(0)) << 16) |
                                (static_cast<uint32_t>(oui_span.at(1)) << 8) | oui_span.at(2);
            f.oui_vendor_name = oui_vendor_name(oui_val);
            offset += 3;
            f.header_size = offset;
        } else {
            f.notes.push_back(
                "Manufacturer/Vendor-Specific category declared but only " +
                std::to_string(eth_payload.size() - offset) +
                " byte(s) remain for the 3-byte OUI field -- OUI not decoded");
        }
    }

    ByteSpan payload = (offset <= eth_payload.size()) ? eth_payload.from(offset) : ByteSpan();
    f.payload_length = payload.size();

    // BOUNDED PAYLOAD DECODE -- see this file's own header comment's BOUNDED PAYLOAD DECODE
    // section. Each is gated on the curated MMTYPE match AND the payload actually being long
    // enough for that fixed-stride shape; anything shorter falls through to the opaque preview
    // below rather than reading past the end.
    if (f.mmtype == 0x0015 && payload.size() >= 1) {
        decode_discover_list_cnf(f, payload);
    } else if (f.mmtype == 0x6008 && payload.size() >= 38) {
        decode_set_key_req(f, payload);
    } else if (f.mmtype == 0x6021 && payload.size() >= 1) {
        decode_brg_info_cnf(f, payload);
    }

    if (!f.has_discover_list_cnf && !f.has_set_key_req && !f.has_brg_info_cnf && !payload.empty()) {
        size_t preview_len = std::min(payload.size(), kMaxOpaquePayloadPreviewBytes);
        f.opaque_payload_hex_preview = to_hex(payload.subspan(0, preview_len), "");
        f.opaque_payload_preview_truncated = payload.size() > preview_len;
    }

    // Summary.
    std::ostringstream s;
    s << "HomePlug AV";
    if (f.mmv_recognized) {
        s << " v" << f.mmv_name;
    } else {
        s << " " << hex2(f.mmv) << " (unrecognized version)";
    }
    s << " " << f.mmtype_name;
    if (f.mmtype_recognized) s << " (" << f.mmtype_kind_name << ")";
    if (f.has_oui) {
        s << " OUI=" << f.oui_hex;
        if (!f.oui_vendor_name.empty()) s << " (" << f.oui_vendor_name << ")";
    }
    if (f.has_discover_list_cnf) {
        s << ": " << f.discover_list_cnf.stations.size() << " station(s), "
          << f.discover_list_cnf.networks.size() << " network(s)";
    } else if (f.has_set_key_req) {
        s << ": key_type=" << (f.set_key_req.key_type_name.empty()
                                     ? hex2(f.set_key_req.key_type_raw)
                                     : f.set_key_req.key_type_name);
    } else if (f.has_brg_info_cnf) {
        s << ": bridging=" << (f.brg_info_cnf.is_bridging ? "yes" : "no");
        if (f.brg_info_cnf.is_bridging) {
            s << " (" << f.brg_info_cnf.station_macs.size() << " station(s))";
        }
    }
    f.summary = s.str();

    if (!f.mmv_recognized) {
        f.notes.push_back("MMV " + hex2(f.mmv) +
                           " is not one of the three recognized HomePlug AV versions (1.0/1.1/2.0) "
                           "-- attempted the standard 5-byte MME header anyway, same fallback the "
                           "reference dissector itself uses for an unknown version");
    }

    // Curated security note (Jurgen's own choice -- see docs/DEVELOPMENT.md ROADMAP item 26's
    // "Done" writeup): fires on EVERY recognized HomePlug AV/dLAN frame, not just the key-exchange
    // message -- bare presence on the segment is itself the finding here, per that writeup. No
    // deduplication, matching this codebase's general curated-note posture (e.g. BSAP's own NAK
    // note, bsap.cpp, and SMB's own DCSync note, smb.cpp).
    f.notes.push_back(
        "Consumer/SOHO-grade powerline networking equipment (HomePlug AV/AV2; devolo dLAN and "
        "equivalents) observed on this network segment -- not itself OT/ICS equipment, but worth "
        "noting: (1) a potential unmanaged bridge extending network reach through building wiring, "
        "often outside IT's own inventory; (2) HomePlug AV historically ships with a well-known "
        "default/weak enrollment secret (the 'HomePlugAV' passphrase, or a Device Access Key "
        "sometimes derived from the device's own MAC address rather than a genuinely random "
        "secret) that is frequently left unchanged in the field, making passive MAC-address "
        "harvesting off the powerline segment a plausible path toward network-key recovery; "
        "devolo's own gear additionally has a documented history (EuroSec 2019, 'Security Analysis "
        "of Devolo HomePlug Devices') of unauthenticated/weakly-authenticated web and telnet "
        "management interfaces on the same physical devices -- neither of those management-plane "
        "weaknesses is visible in this wire protocol itself, this note only means the underlying "
        "hardware class is present.");

    // Second, more specific note -- only for an actual key-exchange/enrollment event (DAK or NMK),
    // additionally to the general presence note above.
    if (f.has_set_key_req &&
        (f.set_key_req.key_type_raw == 0x00 || f.set_key_req.key_type_raw == 0x01)) {
        f.notes.push_back(
            "HomePlug AV network key exchange observed (key_type=" + f.set_key_req.key_type_name +
            ") -- see this codebase's own general redaction posture for why the key bytes "
            "themselves are masked by default (--no-redact to see them).");
    }

    return f;
}

std::optional<ProtocolResult> HomePlugAvDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    if (auto f = try_parse_homeplug_av(payload)) {
        // --redact (on by default -- see DecodeOptions::redact_secrets's own comment, decoder.hpp)
        // masks CM_SET_KEY.REQ's own nw_key field -- the actual HomePlug AV key material -- with a
        // fixed placeholder, the same "parse the real value, redact at the decode() boundary" split
        // VrrpDecoder::decode uses for its own cleartext password (vrrp.hpp/vrrp.cpp). key_type/peks
        // stay unredacted -- they're metadata about the exchange, not the secret itself.
        if (ctx.redact_secrets && f->has_set_key_req && !f->set_key_req.nw_key_hex.empty()) {
            f->summary = redact_secret_occurrences(f->summary, f->set_key_req.nw_key_hex);
            f->set_key_req.nw_key_hex = kRedactedSecretPlaceholder;
            f->set_key_req.nw_key_redacted = true;
        }
        return ProtocolResult::make<HomePlugAvFrame>("homeplug-av", std::move(*f));
    }
    return std::nullopt;
}

const ProtocolDecoder& homeplug_av_decoder() {
    static const HomePlugAvDecoder instance;
    return instance;
}

}  // namespace conduitscope
