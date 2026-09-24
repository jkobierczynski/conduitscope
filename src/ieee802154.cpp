// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ieee802154.hpp"

#include <algorithm>

namespace conduitscope {

namespace {

constexpr uint16_t kFcfTypeMask = 0x0007;
constexpr uint16_t kFcfSecEn = 0x0008;
constexpr uint16_t kFcfFramePending = 0x0010;
constexpr uint16_t kFcfAckReq = 0x0020;
constexpr uint16_t kFcfPanIdCompression = 0x0040;
constexpr uint16_t kFcfSeqnoSuppression = 0x0100;
constexpr uint16_t kFcfIePresent = 0x0200;
constexpr uint16_t kFcfDaddrMask = 0x0C00;
constexpr uint16_t kFcfVersionMask = 0x3000;
constexpr uint16_t kFcfSaddrMask = 0xC000;

constexpr uint8_t kAddrModeNone = 0;
constexpr uint8_t kAddrModeReserved = 1;
constexpr uint8_t kAddrModeShort = 2;
constexpr uint8_t kAddrModeExtended = 3;

constexpr uint8_t kVersion2003 = 0;
constexpr uint8_t kVersion2006 = 1;
constexpr uint8_t kVersion2015 = 2;
constexpr uint8_t kVersionReserved = 3;

constexpr uint8_t kFrameTypeBeacon = 0;
constexpr uint8_t kFrameTypeData = 1;
constexpr uint8_t kFrameTypeAck = 2;
constexpr uint8_t kFrameTypeCmd = 3;

constexpr uint8_t kAuxSecLevelMask = 0x07;
constexpr uint8_t kAuxKeyIdModeMask = 0x18;
constexpr uint8_t kAuxFrameCounterSuppressionMask = 0x20;
constexpr uint8_t kAuxAsnInNonceMask = 0x40;

constexpr uint16_t kHeaderIeIdMask = 0x7F80;
constexpr uint16_t kHeaderIeLengthMask = 0x007F;
constexpr uint8_t kHeaderIeHt1 = 0x7e;
constexpr uint8_t kHeaderIeHt2 = 0x7f;

constexpr uint16_t kPayloadIeIdMask = 0x7800;
constexpr uint16_t kPayloadIeLengthMask = 0x07FF;
constexpr uint8_t kPayloadIeTermination = 0xF;

// IEEE802154_MIC_LENGTH(level): 0/4/8/16 bytes for security level 0-3 (and identically for 4-7,
// the "with encryption" mirror of the same four MIC lengths) -- see this file's header comment's
// sourcing note.
size_t mic_length_for_level(uint8_t level) {
    return static_cast<size_t>((0x2 << (level & 0x3)) & ~0x3);
}

uint16_t peek_u16le(ByteSpan span, size_t offset) {
    return static_cast<uint16_t>(span.at(offset)) | (static_cast<uint16_t>(span.at(offset + 1)) << 8);
}

// The one MAC-header parser both parse_ieee802154_withfcs and parse_ieee802154_tap converge on --
// see this file's header comment. `no_fcs` is the MAC frame with any pseudo-header already stripped
// and the trailing FCS already excluded; `fcs_length`/`fcs_present` are passed through purely for
// Ieee802154Frame's own bookkeeping fields.
Ieee802154Frame parse_mac_common(ByteSpan no_fcs, size_t fcs_length, Ieee802154CaptureVariant variant) {
    Ieee802154Frame f;
    f.capture_variant = variant;
    f.fcs_length = fcs_length;
    f.fcs_present = fcs_length > 0;

    if (no_fcs.size() < 2) {
        throw ParseError(
            "IEEE 802.15.4 MAC frame is shorter than the 2-byte Frame Control Field itself");
    }
    Cursor c(no_fcs);
    f.fcf = c.u16le();
    f.frame_type = static_cast<uint8_t>(f.fcf & kFcfTypeMask);
    f.security_enabled = (f.fcf & kFcfSecEn) != 0;
    f.frame_pending = (f.fcf & kFcfFramePending) != 0;
    f.ack_request = (f.fcf & kFcfAckReq) != 0;
    f.pan_id_compression = (f.fcf & kFcfPanIdCompression) != 0;
    f.seqno_suppression = (f.fcf & kFcfSeqnoSuppression) != 0;
    f.ie_present = (f.fcf & kFcfIePresent) != 0;
    f.dst_addr_mode = static_cast<uint8_t>((f.fcf & kFcfDaddrMask) >> 10);
    f.frame_version = static_cast<uint8_t>((f.fcf & kFcfVersionMask) >> 12);
    f.src_addr_mode = static_cast<uint8_t>((f.fcf & kFcfSaddrMask) >> 14);

    // Small helper: bails out of the rest of this parse the moment a declared field doesn't fit the
    // remaining captured bytes, tolerantly (note + opaque remainder), never by throwing -- see this
    // file's header comment's "Truncation handling" paragraph. Returns false on failure so call
    // sites can `if (!need(...)) return f;`.
    auto need = [&](size_t n, const char* what) -> bool {
        if (c.remaining() < n) {
            f.malformed = true;
            f.notes.push_back(std::string("Not enough captured bytes remain for ") + what +
                               " -- stopped decoding here; everything remaining is reported as "
                               "opaque MAC payload");
            f.mac_payload = c.rest();
            return false;
        }
        return true;
    };

    // Multipurpose/Reserved/Fragment/Extended frame types: out of scope, not malformed -- see this
    // file's header comment.
    if (f.frame_type != kFrameTypeBeacon && f.frame_type != kFrameTypeData &&
        f.frame_type != kFrameTypeAck && f.frame_type != kFrameTypeCmd) {
        f.notes.push_back(std::string("MAC frame type ") + ieee802154_frame_type_name(f.frame_type) +
                           " is out of scope for this decoder (Zigbee never uses it; Multipurpose "
                           "frames in particular use an entirely different Frame Control Field "
                           "layout this decoder does not implement) -- nothing past the Frame "
                           "Control Field is decoded");
        f.mac_payload = c.rest();
        return f;
    }

    if (f.dst_addr_mode == kAddrModeReserved || f.src_addr_mode == kAddrModeReserved) {
        f.malformed = true;
        f.notes.push_back(
            "Destination and/or Source Addressing Mode is the Reserved value (0x1), which is never "
            "valid in any 802.15.4 frame version -- cannot reliably determine field presence past "
            "this point, so nothing further is decoded");
        f.mac_payload = c.rest();
        return f;
    }

    if (f.frame_version == kVersionReserved) {
        f.malformed = true;
        f.notes.push_back(
            "Frame Version is the Reserved value (0x3) -- cannot reliably determine addressing "
            "field presence past this point, so nothing further is decoded");
        f.mac_payload = c.rest();
        return f;
    }

    // Sequence Number -- present unless Sequence Number Suppression is set. This decoder reads the
    // bit regardless of frame version, exactly as the reference dissector does: a pre-2015 frame
    // with the bit set is flagged (it has no defined meaning there) but the sequence number is still
    // treated as absent, matching the wire bit literally rather than silently overriding it.
    if (f.seqno_suppression) {
        if (f.frame_version != kVersion2015) {
            f.notes.push_back(
                std::string("Sequence Number Suppression bit is set on a pre-2015 frame (Frame "
                             "Version ") +
                ieee802154_version_name(f.frame_version) +
                ") -- this bit is only defined for 802.15.4-2015+; treating the sequence number as "
                "absent anyway, matching the wire bit literally");
        }
    } else {
        if (!need(1, "the Sequence Number")) return f;
        f.has_seqno = true;
        f.seqno = c.u8();
    }

    // Addressing field presence -- see this file's header comment for the full pre-2015/2015+ logic
    // this reproduces.
    bool dst_pan_present = false, src_pan_present = false;
    bool addressing_valid = true;
    if (f.frame_version == kVersion2003 || f.frame_version == kVersion2006) {
        bool has_dst = f.dst_addr_mode != kAddrModeNone;
        bool has_src = f.src_addr_mode != kAddrModeNone;
        if (has_dst && has_src) {
            dst_pan_present = true;
            src_pan_present = !f.pan_id_compression;
        } else if (f.pan_id_compression) {
            addressing_valid = false;  // invalid: compression requires both addresses present
        } else if (has_dst) {
            dst_pan_present = true;
        } else if (has_src) {
            src_pan_present = true;
        }
        // else: neither address present -- both PAN ID flags stay false, valid.
    } else {  // kVersion2015 -- literal Table 7-6, strict-spec rows 9-11 (see file header comment)
        uint8_t d = f.dst_addr_mode, s = f.src_addr_mode;
        bool comp = f.pan_id_compression;
        if (d == kAddrModeNone && s == kAddrModeNone && !comp) {
            dst_pan_present = false;
            src_pan_present = false;
        } else if (d == kAddrModeNone && s == kAddrModeNone && comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else if (d != kAddrModeNone && s == kAddrModeNone && !comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else if (d != kAddrModeNone && s == kAddrModeNone && comp) {
            dst_pan_present = false;
            src_pan_present = false;
        } else if (d == kAddrModeNone && s != kAddrModeNone && !comp) {
            dst_pan_present = false;
            src_pan_present = true;
        } else if (d == kAddrModeNone && s != kAddrModeNone && comp) {
            dst_pan_present = false;
            src_pan_present = false;
        } else if (d == kAddrModeExtended && s == kAddrModeExtended && !comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else if (d == kAddrModeExtended && s == kAddrModeExtended && comp) {
            dst_pan_present = false;
            src_pan_present = false;
        } else if (d == kAddrModeShort && s == kAddrModeShort && !comp) {
            dst_pan_present = true;
            src_pan_present = true;
        } else if (d == kAddrModeShort && s == kAddrModeExtended && !comp) {
            dst_pan_present = true;
            src_pan_present = true;
        } else if (d == kAddrModeExtended && s == kAddrModeShort && !comp) {
            dst_pan_present = true;
            src_pan_present = true;
        } else if (d == kAddrModeShort && s == kAddrModeExtended && comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else if (d == kAddrModeExtended && s == kAddrModeShort && comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else if (d == kAddrModeShort && s == kAddrModeShort && comp) {
            dst_pan_present = true;
            src_pan_present = false;
        } else {
            addressing_valid = false;
        }
    }

    if (!addressing_valid) {
        f.malformed = true;
        f.notes.push_back(
            "Addressing Mode / PAN ID Compression combination has no defined meaning for this "
            "frame's Frame Version -- cannot reliably determine field presence past this point, so "
            "nothing further is decoded");
        f.mac_payload = c.rest();
        return f;
    }

    if (dst_pan_present) {
        if (!need(2, "the Destination PAN ID")) return f;
        f.has_dst_pan = true;
        f.dst_pan = c.u16le();
    }
    if (f.dst_addr_mode == kAddrModeShort) {
        if (!need(2, "the Destination Address (short)")) return f;
        f.has_dst_addr = true;
        f.dst_addr_extended = false;
        f.dst_addr_short = c.u16le();
    } else if (f.dst_addr_mode == kAddrModeExtended) {
        if (!need(8, "the Destination Address (extended)")) return f;
        f.has_dst_addr = true;
        f.dst_addr_extended = true;
        f.dst_addr_ext = c.u64le();
    }

    if (src_pan_present) {
        if (!need(2, "the Source PAN ID")) return f;
        f.has_src_pan = true;
        f.src_pan = c.u16le();
    }
    // else: no synthetic fill even when the spec's own "same as Destination PAN ID" convenience
    // applies -- see this file's header comment; that is not itself a wire field.
    if (f.src_addr_mode == kAddrModeShort) {
        if (!need(2, "the Source Address (short)")) return f;
        f.has_src_addr = true;
        f.src_addr_extended = false;
        f.src_addr_short = c.u16le();
    } else if (f.src_addr_mode == kAddrModeExtended) {
        if (!need(8, "the Source Address (extended)")) return f;
        f.has_src_addr = true;
        f.src_addr_extended = true;
        f.src_addr_ext = c.u64le();
    }

    // Auxiliary Security Header -- MAC-layer format, absent for 802.15.4-2003 even when
    // security_enabled is set (see this file's header comment's 2003 scope note).
    if (f.security_enabled && f.frame_version != kVersion2003) {
        f.has_aux_security = true;
        Ieee802154SecurityHeader& sec = f.aux_security;
        if (!need(1, "the Auxiliary Security Header's Security Control field")) return f;
        uint8_t control = c.u8();
        sec.security_level = control & kAuxSecLevelMask;
        sec.key_id_mode = static_cast<uint8_t>((control & kAuxKeyIdModeMask) >> 3);
        if (f.frame_version == kVersion2015) {
            sec.frame_counter_suppressed = (control & kAuxFrameCounterSuppressionMask) != 0;
            sec.asn_in_nonce = (control & kAuxAsnInNonceMask) != 0;
        }
        if (!sec.frame_counter_suppressed) {
            if (!need(4, "the Auxiliary Security Header's Frame Counter field")) return f;
            sec.has_frame_counter = true;
            sec.frame_counter = c.u32le();
        }
        size_t key_source_len = 0;
        if (sec.key_id_mode == 2) key_source_len = 4;
        else if (sec.key_id_mode == 3) key_source_len = 8;
        if (key_source_len > 0) {
            if (!need(key_source_len, "the Auxiliary Security Header's Key Source field")) return f;
            sec.has_key_source = true;
            ByteSpan ks = c.bytes(key_source_len);
            sec.key_source_bytes.assign(ks.data(), ks.data() + ks.size());
        }
        if (sec.key_id_mode != 0) {
            if (!need(1, "the Auxiliary Security Header's Key Index field")) return f;
            sec.has_key_index = true;
            sec.key_index = c.u8();
        }
    }

    // Header/Payload Information Elements -- detected and walked only to find where they end, never
    // decoded -- see this file's header comment's IE section. Bounded so the walk never consumes
    // into the trailing MIC region.
    if (f.ie_present) {
        size_t mic_reserve = f.has_aux_security ? mic_length_for_level(f.aux_security.security_level) : 0;
        size_t ie_region_limit = (c.remaining() > mic_reserve) ? (c.remaining() - mic_reserve) : 0;

        size_t consumed = 0;
        bool saw_ht1 = false;
        while (consumed + 2 <= ie_region_limit) {
            uint16_t hdr = peek_u16le(no_fcs, c.position() + consumed);
            uint8_t id = static_cast<uint8_t>((hdr & kHeaderIeIdMask) >> 7);
            uint16_t length = hdr & kHeaderIeLengthMask;
            if (consumed + 2 + length > ie_region_limit) {
                f.notes.push_back(
                    "A Header IE's declared length overruns the remaining frame -- stopped walking "
                    "Header IEs early");
                break;
            }
            consumed += 2 + length;
            if (id == kHeaderIeHt1 || id == kHeaderIeHt2) {
                saw_ht1 = (id == kHeaderIeHt1);
                break;
            }
        }
        f.has_header_ies = true;
        f.header_ie_bytes = consumed;
        c.skip(consumed);

        if (saw_ht1) {
            size_t p_limit = (c.remaining() > mic_reserve) ? (c.remaining() - mic_reserve) : 0;
            size_t p_consumed = 0;
            while (p_consumed + 2 <= p_limit) {
                uint16_t hdr = peek_u16le(no_fcs, c.position() + p_consumed);
                uint8_t group_id = static_cast<uint8_t>((hdr & kPayloadIeIdMask) >> 11);
                uint16_t length = hdr & kPayloadIeLengthMask;
                if (p_consumed + 2 + length > p_limit) {
                    f.notes.push_back(
                        "A Payload IE's declared length overruns the remaining frame -- stopped "
                        "walking Payload IEs early");
                    break;
                }
                p_consumed += 2 + length;
                if (group_id == kPayloadIeTermination) break;
            }
            f.has_payload_ies = true;
            f.payload_ie_bytes = p_consumed;
            c.skip(p_consumed);
        }
    }

    // MAC payload: everything remaining, minus the trailing MIC (if security is enabled).
    size_t mic_len = f.has_aux_security ? mic_length_for_level(f.aux_security.security_level) : 0;
    size_t remaining = c.remaining();
    if (mic_len > remaining) {
        f.notes.push_back(
            "Declared MIC length (" + std::to_string(mic_len) +
            " byte(s), from the Auxiliary Security Header's Security Level) is larger than the "
            "bytes actually remaining in the captured frame -- treating the whole remainder as "
            "payload rather than guessing where a truncated MIC would start");
        mic_len = 0;
    }
    f.mic_length = mic_len;
    f.mac_payload = c.bytes(remaining - mic_len);
    return f;
}

}  // namespace

const char* ieee802154_frame_type_name(uint8_t frame_type) {
    switch (frame_type) {
        case 0: return "Beacon";
        case 1: return "Data";
        case 2: return "Ack";
        case 3: return "MAC Command";
        case 4: return "Reserved";
        case 5: return "Multipurpose";
        case 6: return "Fragment";
        case 7: return "Extended";
        default: return "Unknown";
    }
}

const char* ieee802154_addr_mode_name(uint8_t addr_mode) {
    switch (addr_mode) {
        case 0: return "None";
        case 1: return "Reserved";
        case 2: return "Short (16-bit)";
        case 3: return "Extended (64-bit)";
        default: return "Unknown";
    }
}

const char* ieee802154_version_name(uint8_t frame_version) {
    switch (frame_version) {
        case 0: return "802.15.4-2003";
        case 1: return "802.15.4-2006";
        case 2: return "802.15.4-2015";
        case 3: return "Reserved";
        default: return "Unknown";
    }
}

Ieee802154Frame parse_ieee802154_withfcs(ByteSpan record) {
    // This link type always assumes a trailing FCS is present -- see this file's header comment for
    // why this decoder fixes it at the plain 16-bit-CRC case (2 bytes) rather than the CC24xx
    // metadata or 4-byte-CRC variants (both Wireshark-preference-only choices, not something the
    // capture itself ever declares).
    constexpr size_t kFcsLength = 2;
    bool have_full_fcs = record.size() >= kFcsLength;
    ByteSpan no_fcs = have_full_fcs ? record.subspan(0, record.size() - kFcsLength) : record;
    Ieee802154Frame f =
        parse_mac_common(no_fcs, have_full_fcs ? kFcsLength : 0, Ieee802154CaptureVariant::WithFcs);
    if (!have_full_fcs) {
        f.notes.push_back(
            "Captured record (" + std::to_string(record.size()) +
            " byte(s)) is shorter than the 2-byte trailing FCS this link type always carries -- "
            "treating the whole record as FCS-less rather than guessing");
    }
    return f;
}

Ieee802154Frame parse_ieee802154_tap(ByteSpan record) {
    if (record.size() < 4) {
        throw ParseError("IEEE 802.15.4 TAP record is shorter than its own 4-byte fixed header");
    }
    Cursor c(record);
    uint8_t version = c.u8();
    c.u8();  // Reserved -- not validated, matching this codebase's usual posture
    uint16_t length = c.u16le();
    bool valid_version = (version == 0);

    // Walk the TLV region [4, length) purely to find the FCS_TYPE TLV (0x0000) -- every other TLV
    // type is skipped generically (4-byte header + declared length + zero-padding to the next
    // 4-byte boundary), never decoded -- see this file's header comment.
    uint8_t fcs_type = 0;  // default None, per the TAP spec (unlike WITHFCS's own always-assume-FCS
                             // default)
    bool fcs_type_tlv_present = false;
    size_t tlv_end = std::min<size_t>(length, record.size());
    size_t offset = 4;
    while (offset + 4 <= tlv_end) {
        uint16_t type = peek_u16le(record, offset);
        uint16_t tlv_len = peek_u16le(record, offset + 2);
        size_t value_off = offset + 4;
        if (type == 0x0000 && tlv_len >= 1 && value_off < tlv_end) {
            fcs_type = record.at(value_off);
            fcs_type_tlv_present = true;
        }
        size_t pad = (4 - (tlv_len % 4)) % 4;
        size_t advance = 4 + static_cast<size_t>(tlv_len) + pad;
        if (advance == 0 || offset + advance > tlv_end) break;  // malformed TLV -- stop scanning
        offset += advance;
    }

    size_t fcs_length = 0;
    if (fcs_type == 1) fcs_length = 2;
    else if (fcs_type == 2) fcs_length = 4;

    size_t mac_start = std::min<size_t>(length, record.size());
    ByteSpan mac_region = record.from(mac_start);
    bool have_full_fcs = mac_region.size() >= fcs_length;
    ByteSpan no_fcs =
        have_full_fcs ? mac_region.subspan(0, mac_region.size() - fcs_length) : mac_region;

    Ieee802154Frame f =
        parse_mac_common(no_fcs, have_full_fcs ? fcs_length : 0, Ieee802154CaptureVariant::Tap);
    f.tap_valid_version = valid_version;
    f.tap_declared_length = length;
    f.tap_fcs_type_tlv_present = fcs_type_tlv_present;
    f.tap_fcs_type = fcs_type;

    if (!valid_version) {
        f.notes.push_back("TAP fixed header's Version byte is " + std::to_string(version) +
                           ", not the only defined value (0) -- continuing best-effort using the "
                           "declared Length field anyway");
    }
    if (length > record.size()) {
        f.notes.push_back("TAP fixed header declares Length=" + std::to_string(length) +
                           " (the byte offset where the 802.15.4 MAC frame begins) but only " +
                           std::to_string(record.size()) +
                           " byte(s) were captured -- clamped to the captured record's own size");
    }
    if (!have_full_fcs) {
        f.notes.push_back("TAP MAC frame region (" + std::to_string(mac_region.size()) +
                           " byte(s)) is shorter than the " + std::to_string(fcs_length) +
                           "-byte FCS the FCS_TYPE TLV declares -- treating the whole region as "
                           "FCS-less rather than guessing");
    }
    return f;
}

}  // namespace conduitscope
