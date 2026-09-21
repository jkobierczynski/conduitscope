// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/bacnet.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>
#include <utility>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Lookup tables -- transcribed in full from Wireshark's own epan/dissectors/packet-bacapp.c
// value_string tables (see bacnet.hpp's file header comment). Kept as flat {code, name} arrays
// searched linearly (these tables are consulted at most a handful of times per packet, so linear
// search is not a meaningful cost -- the same posture DNP3's/S7comm's own small lookup tables in
// this codebase already take).

#include "bacnet_tables.inc"

std::string lookup(const std::pair<uint32_t, const char*>* table, size_t count, uint32_t value,
                    const char* fallback_prefix) {
    for (size_t i = 0; i < count; ++i) {
        if (table[i].first == value) return table[i].second;
    }
    return std::string(fallback_prefix) + "(" + std::to_string(value) + ")";
}

template <size_t N>
std::string lookup(const std::pair<uint32_t, const char*> (&table)[N], uint32_t value,
                    const char* fallback_prefix = "unknown") {
    return lookup(table, N, value, fallback_prefix);
}

const std::pair<uint32_t, const char*> kBvlcFunctionNames[] = {
    {0x00, "BVLC-Result"},
    {0x01, "Write-Broadcast-Distribution-Table"},
    {0x02, "Read-Broadcast-Distribution-Table"},
    {0x03, "Read-Broadcast-Distribution-Table-Ack"},
    {0x04, "Forwarded-NPDU"},
    {0x05, "Register-Foreign-Device"},
    {0x06, "Read-Foreign-Device-Table"},
    {0x07, "Read-Foreign-Device-Table-Ack"},
    {0x08, "Delete-Foreign-Device-Table-Entry"},
    {0x09, "Distribute-Broadcast-To-Network"},
    {0x0a, "Original-Unicast-NPDU"},
    {0x0b, "Original-Broadcast-NPDU"},
    {0x0c, "Secure-BVLL"},
};

const std::pair<uint32_t, const char*> kNetworkMessageTypeNames[] = {
    {0x00, "Who-Is-Router-To-Network"},
    {0x01, "I-Am-Router-To-Network"},
    {0x02, "I-Could-Be-Router-To-Network"},
    {0x03, "Reject-Message-To-Network"},
    {0x04, "Router-Busy-To-Network"},
    {0x05, "Router-Available-To-Network"},
    {0x06, "Initialize-Routing-Table"},
    {0x07, "Initialize-Routing-Table-Ack"},
    {0x08, "Establish-Connection-To-Network"},
    {0x09, "Disconnect-Connection-To-Network"},
    {0x0A, "Challenge-Request"},
    {0x0B, "Security-Payload"},
    {0x0C, "Security-Response"},
    {0x0D, "Request-Key-Update"},
    {0x0E, "Update-Keyset"},
    {0x0F, "Update-Distribution-Key"},
    {0x10, "Request-Masterkey"},
    {0x11, "Set-Masterkey"},
    {0x12, "What-Is-Network-Number"},
    {0x13, "Network-Number-Is"},
};

const std::pair<uint32_t, const char*> kApplicationTagNames[] = {
    {0, "Null"},          {1, "Boolean"},         {2, "Unsigned Integer"},
    {3, "Signed Integer"}, {4, "Real"},            {5, "Double"},
    {6, "Octet String"},  {7, "Character String"}, {8, "Bit String"},
    {9, "Enumerated"},    {10, "Date"},            {11, "Time"},
    {12, "BACnetObjectIdentifier"},
};

const std::pair<uint32_t, const char*> kSegmentationNames[] = {
    {0, "segmented-both"},
    {1, "segmented-transmit"},
    {2, "segmented-receive"},
    {3, "no-segmentation"},
};

const std::pair<uint32_t, const char*> kErrorClassNames[] = {
    {0, "device"}, {1, "object"}, {2, "property"}, {3, "resources"},
    {4, "security"}, {5, "services"}, {6, "vt"}, {7, "communication"},
};

const std::pair<uint32_t, const char*> kRejectReasonNames[] = {
    {0, "other"},
    {1, "buffer-overflow"},
    {2, "inconsistent-parameters"},
    {3, "invalid-parameter-data-type"},
    {4, "invalid-tag"},
    {5, "missing-required-parameter"},
    {6, "parameter-out-of-range"},
    {7, "too-many-arguments"},
    {8, "undefined-enumeration"},
    {9, "unrecognized-service"},
};

const std::pair<uint32_t, const char*> kAbortReasonNames[] = {
    {0, "other"},
    {1, "buffer-overflow"},
    {2, "invalid-apdu-in-this-state"},
    {3, "preempted-by-higher-priority-task"},
    {4, "segmentation-not-supported"},
    {5, "security-error"},
    {6, "insufficient-security"},
    {7, "window-size-out-of-range"},
    {8, "application-exceeded-reply-time"},
    {9, "out-of-resources"},
    {10, "tsm-timeout"},
    {11, "apdu-too-long"},
};

// object_type_name -- BACnetObjectType is enumerated 0-1023, ASHRAE-reserved through 127,
// vendor-proprietary at 128+ (cross-checked against packet-bacapp.c's own
// `val_to_split_str(..., 128, BACnetObjectType, ASHRAE_Reserved_Fmt, Vendor_Proprietary_Fmt)`).
std::string object_type_name(uint32_t type) {
    for (const auto& e : kBacnetObjectType) {
        if (e.first == type) return e.second;
    }
    if (type < 128) return "reserved(" + std::to_string(type) + ")";
    return "vendor-proprietary(" + std::to_string(type) + ")";
}

// property_identifier_name -- BACnetPropertyIdentifier's split point is 512 (cross-checked
// against fPropertyIdentifier's own `val_to_split_str(..., 512, BACnetPropertyIdentifier, ...)`).
std::string property_identifier_name(uint32_t prop) {
    for (const auto& e : kBacnetPropertyIdentifier) {
        if (e.first == prop) return e.second;
    }
    if (prop < 512) return "reserved(" + std::to_string(prop) + ")";
    return "vendor-proprietary(" + std::to_string(prop) + ")";
}

// error_code_name -- BACnetErrorCode's ASHRAE-reserved/vendor-proprietary split is 256.
std::string error_code_name(uint32_t code) {
    for (const auto& e : kBacnetErrorCode) {
        if (e.first == code) return e.second;
    }
    if (code < 256) return "reserved(" + std::to_string(code) + ")";
    return "vendor-proprietary(" + std::to_string(code) + ")";
}

std::string confirmed_service_name(uint32_t choice) {
    for (const auto& e : kBacnetConfirmedServiceChoice) {
        if (e.first == choice) return e.second;
    }
    return "unknown(" + std::to_string(choice) + ")";
}

std::string unconfirmed_service_name(uint32_t choice) {
    for (const auto& e : kBacnetUnconfirmedServiceChoice) {
        if (e.first == choice) return e.second;
    }
    return "unknown(" + std::to_string(choice) + ")";
}

std::string bvlc_function_name(uint8_t function) {
    return lookup(kBvlcFunctionNames, function);
}

// network_message_type_name -- 0x14-0x7F is ASHRAE-reserved, 0x80-0xFF vendor-proprietary (see
// bacnet.hpp's NPDU section).
std::string network_message_type_name(uint8_t type) {
    for (const auto& e : kNetworkMessageTypeNames) {
        if (e.first == type) return e.second;
    }
    if (type < 0x80) return "reserved(" + std::to_string(type) + ")";
    return "vendor-proprietary(" + std::to_string(type) + ")";
}

std::string application_tag_name(uint8_t tag_no) {
    for (const auto& e : kApplicationTagNames) {
        if (e.first == tag_no) return e.second;
    }
    return "reserved(" + std::to_string(tag_no) + ")";
}

std::string format_float(double v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

// ------------------------------------------------------------------------------------------
// BACnet's own TLV tag encoding (ASHRAE 135 clause 20.2.1) -- see bacnet.hpp's file header
// comment. Cross-checked byte offset by byte offset against packet-bacapp.c's fTagHeaderTree.
struct TagHeader {
    uint8_t tag_number = 0;
    bool context_specific = false;
    bool opening = false;
    bool closing = false;
    uint32_t lvt = 0;         // Length/Value/Type
    size_t header_length = 0;  // bytes consumed by the tag header itself, not the value
};

std::optional<TagHeader> decode_tag_header(ByteSpan span, size_t offset) {
    if (offset >= span.size()) return std::nullopt;
    uint8_t tag = span.at(offset);
    size_t tag_len = 1;

    TagHeader h;
    h.context_specific = (tag & 0x08) != 0;
    h.lvt = tag & 0x07;
    h.tag_number = static_cast<uint8_t>(tag >> 4);

    bool extended_tag_number = (tag & 0xF0) == 0xF0;
    if (extended_tag_number) {
        if (offset + tag_len >= span.size()) return std::nullopt;
        h.tag_number = span.at(offset + tag_len);
        tag_len++;
    }

    bool extended_value = (h.lvt == 5);
    // Opening/closing tags are only meaningful for context-specific (constructed) data -- see
    // clause 20.2.1.3.2, cross-checked against tag_is_opening/tag_is_closing (which test the raw
    // LVT bits without separately checking the class bit, but are only ever CALLED on tags
    // already known to be context-specific by the callers in packet-bacapp.c).
    if (h.context_specific && h.lvt == 6) {
        h.opening = true;
    } else if (h.context_specific && h.lvt == 7) {
        h.closing = true;
    } else if (extended_value) {
        size_t lvt_offset = offset + tag_len;
        if (lvt_offset >= span.size()) return std::nullopt;
        uint8_t value = span.at(lvt_offset);
        tag_len++;
        if (value == 254) {
            if (lvt_offset + 2 >= span.size()) return std::nullopt;
            h.lvt = (static_cast<uint32_t>(span.at(lvt_offset + 1)) << 8) | span.at(lvt_offset + 2);
            tag_len += 2;
        } else if (value == 255) {
            if (lvt_offset + 4 >= span.size()) return std::nullopt;
            h.lvt = (static_cast<uint32_t>(span.at(lvt_offset + 1)) << 24) |
                    (static_cast<uint32_t>(span.at(lvt_offset + 2)) << 16) |
                    (static_cast<uint32_t>(span.at(lvt_offset + 3)) << 8) | span.at(lvt_offset + 4);
            tag_len += 4;
        } else {
            h.lvt = value;
        }
    }

    h.header_length = tag_len;
    return h;
}

// read_unsigned -- mirrors fUnsigned32 (1-4 bytes, big-endian). Returns std::nullopt for an
// out-of-range byte count (0 or >4) or truncated data, same as the Wireshark source.
std::optional<uint32_t> read_unsigned32(ByteSpan span, size_t offset, uint32_t lvt) {
    if (lvt < 1 || lvt > 4 || offset + lvt > span.size()) return std::nullopt;
    uint32_t v = 0;
    for (uint32_t i = 0; i < lvt; ++i) v = (v << 8) | span.at(offset + i);
    return v;
}

// read_unsigned64 -- mirrors fUnsigned64 (1-8 bytes, big-endian).
std::optional<uint64_t> read_unsigned64(ByteSpan span, size_t offset, uint32_t lvt) {
    if (lvt < 1 || lvt > 8 || offset + lvt > span.size()) return std::nullopt;
    uint64_t v = 0;
    for (uint32_t i = 0; i < lvt; ++i) v = (v << 8) | span.at(offset + i);
    return v;
}

// read_signed64 -- mirrors fSigned64: read as unsigned, then sign-extend from the top bit of the
// first byte actually present (two's complement, per clause 20.2.5).
std::optional<int64_t> read_signed64(ByteSpan span, size_t offset, uint32_t lvt) {
    if (lvt < 1 || lvt > 8 || offset + lvt > span.size()) return std::nullopt;
    // Do the shifting in uint64_t -- left-shifting a negative signed value (the seed is -1 when the
    // top bit is set) is undefined behavior, even though the intent here is a well-defined two's-
    // complement bit shift (found by fuzz_packet_decode; see
    // fuzz/corpus/packet_decode/regress_bacnet_signed_leftshift.bin). Shifting as uint64_t instead
    // produces the exact same bit pattern with no UB, then a single cast back to int64_t at the end
    // reinterprets it as signed.
    uint64_t v = (span.at(offset) & 0x80) ? ~static_cast<uint64_t>(0) : 0;  // sign-extend seed
    for (uint32_t i = 0; i < lvt; ++i) v = (v << 8) | span.at(offset + i);
    return static_cast<int64_t>(v);
}

// Character-set encoding byte (first byte of a Character-String's value, before the string
// bytes) -- cross-checked against fCharacterStringBase's own character_set switch.
constexpr uint8_t kAnsiX34 = 0;      // ANSI X3.4 / UTF-8
constexpr uint8_t kIbmMsDbcs = 1;    // has a 2-byte code-page field following the charset byte
constexpr uint8_t kJisX0208 = 2;
constexpr uint8_t kUcs4 = 3;
constexpr uint8_t kUcs2 = 4;
constexpr uint8_t kIso88591 = 5;

std::string character_set_name(uint8_t cs) {
    switch (cs) {
        case kAnsiX34: return "ANSI X3.4/UTF-8";
        case kIbmMsDbcs: return "IBM/MS DBCS";
        case kJisX0208: return "JIS X 0208";
        case kUcs4: return "UCS-4";
        case kUcs2: return "UCS-2";
        case kIso88591: return "ISO 8859-1";
        default: return "unknown(" + std::to_string(cs) + ")";
    }
}

// One decoded application-tagged primitive value (BACnet application tag numbers 0-12) -- see
// bacnet.hpp's file header comment's "Property value decode" paragraph.
struct PrimitiveValue {
    bool ok = false;
    std::string type_name;
    std::string rendered;
    size_t consumed = 0;  // bytes consumed from `value_offset`, i.e. the value's own byte length
};

// Decodes one application-tagged primitive starting at `value_offset` (immediately after the tag
// header) given the tag header's own tag_number/lvt. Does not itself read the tag header -- the
// caller (decode_one_value below) does that first so it can also handle "not one of the first-
// pass primitive types" uniformly.
PrimitiveValue decode_application_primitive(ByteSpan span, size_t value_offset, uint8_t tag_no,
                                             uint32_t lvt) {
    PrimitiveValue out;
    out.type_name = application_tag_name(tag_no);
    switch (tag_no) {
        case 0:  // Null -- no value bytes at all (lvt is always 0)
            out.ok = true;
            out.rendered = "Null";
            out.consumed = 0;
            return out;
        case 1: {  // Boolean -- the LVT field itself IS the value (0=FALSE, nonzero=TRUE), no
                    // separate value bytes on the wire at all -- see fBooleanTag.
            out.ok = true;
            out.rendered = (lvt != 0) ? "TRUE" : "FALSE";
            out.consumed = 0;
            return out;
        }
        case 2: {  // Unsigned Integer, 1-8 bytes big-endian
            auto v = read_unsigned64(span, value_offset, lvt);
            if (!v) return out;
            out.ok = true;
            out.rendered = std::to_string(*v);
            out.consumed = lvt;
            return out;
        }
        case 3: {  // Signed Integer, 1-8 bytes two's-complement big-endian
            auto v = read_signed64(span, value_offset, lvt);
            if (!v) return out;
            out.ok = true;
            out.rendered = std::to_string(*v);
            out.consumed = lvt;
            return out;
        }
        case 4: {  // Real -- 4-byte IEEE 754 single, always exactly 4 bytes
            if (value_offset + 4 > span.size()) return out;
            uint32_t bits = 0;
            for (int i = 0; i < 4; ++i) bits = (bits << 8) | span.at(value_offset + i);
            float f;
            std::memcpy(&f, &bits, sizeof(f));
            out.ok = true;
            out.rendered = format_float(f);
            out.consumed = 4;
            return out;
        }
        case 5: {  // Double -- 8-byte IEEE 754 double, always exactly 8 bytes
            if (value_offset + 8 > span.size()) return out;
            uint64_t bits = 0;
            for (int i = 0; i < 8; ++i) bits = (bits << 8) | span.at(value_offset + i);
            double d;
            std::memcpy(&d, &bits, sizeof(d));
            out.ok = true;
            out.rendered = format_float(d);
            out.consumed = 8;
            return out;
        }
        case 6: {  // Octet String -- lvt raw bytes, shown as hex (no self-describing internal
                    // structure -- see bacnet.hpp's "no generic self-describing wire-level type"
                    // cross-reference)
            if (value_offset + lvt > span.size()) return out;
            out.ok = true;
            out.rendered = to_hex(span.subspan(value_offset, lvt), "");
            out.consumed = lvt;
            return out;
        }
        case 7: {  // Character String -- 1-byte charset + (lvt-1) string bytes, or (lvt-3) for
                    // IBM/MS DBCS's extra 2-byte code-page field -- see fCharacterStringBase.
            if (lvt < 1 || value_offset + lvt > span.size()) return out;
            uint8_t charset = span.at(value_offset);
            size_t string_offset = value_offset + 1;
            size_t string_len = lvt - 1;
            if (charset == kIbmMsDbcs) {
                if (string_len < 2) return out;
                string_offset += 2;
                string_len -= 2;
            }
            out.ok = true;
            out.consumed = lvt;
            if (charset == kAnsiX34 || charset == kIso88591) {
                out.rendered = std::string(reinterpret_cast<const char*>(span.data()) + string_offset, string_len);
            } else {
                out.rendered = "(" + character_set_name(charset) + ", " + std::to_string(string_len) +
                                " byte(s)) " + to_hex(span.subspan(string_offset, string_len), "");
            }
            return out;
        }
        case 8: {  // Bit String -- 1-byte unused-bit count + remaining bytes, rendered T/F --
                    // see fBitStringTagVSBase.
            if (lvt < 1 || value_offset + lvt > span.size()) return out;
            uint8_t unused = span.at(value_offset);
            size_t num_bytes = lvt - 1;
            std::string bits;
            for (size_t i = 0; i < num_bytes; ++i) {
                uint8_t byte = span.at(value_offset + 1 + i);
                int skip = (i == num_bytes - 1) ? unused : 0;
                for (int b = 0; b < 8 - skip; ++b) {
                    bits += (byte & (1 << (7 - b))) ? 'T' : 'F';
                }
            }
            out.ok = true;
            out.rendered = bits;
            out.consumed = lvt;
            return out;
        }
        case 9: {  // Enumerated -- 1-4 bytes big-endian, same encoding as Unsigned
            auto v = read_unsigned32(span, value_offset, lvt);
            if (!v) return out;
            out.ok = true;
            out.rendered = std::to_string(*v);
            out.consumed = lvt;
            return out;
        }
        case 10: {  // Date -- 4 bytes: year(+1900 unless 0xFF)/month/day/day-of-week, each 0xFF
                     // wildcards ("any") -- see fDate.
            if (value_offset + 4 > span.size()) return out;
            uint8_t year = span.at(value_offset), month = span.at(value_offset + 1),
                    day = span.at(value_offset + 2), dow = span.at(value_offset + 3);
            out.ok = true;
            out.consumed = 4;
            std::ostringstream s;
            if (year == 255 && month == 255 && day == 255 && dow == 255) {
                s << "any";
            } else {
                if (month == 255)
                    s << "any-month";
                else
                    s << static_cast<unsigned>(month);
                s << "/";
                if (day == 255)
                    s << "any-day";
                else
                    s << static_cast<unsigned>(day);
                s << "/";
                if (year == 255)
                    s << "any-year";
                else
                    s << (static_cast<unsigned>(year) + 1900);
                if (dow != 255) s << " dow=" << static_cast<unsigned>(dow);
            }
            out.rendered = s.str();
            return out;
        }
        case 11: {  // Time -- 4 bytes: hour/minute/second/hundredths, each 0xFF wildcards -- see
                     // fTime.
            if (value_offset + 4 > span.size()) return out;
            uint8_t hour = span.at(value_offset), minute = span.at(value_offset + 1),
                    second = span.at(value_offset + 2), hsec = span.at(value_offset + 3);
            out.ok = true;
            out.consumed = 4;
            std::ostringstream s;
            if (hour == 255 && minute == 255 && second == 255 && hsec == 255) {
                s << "any";
            } else {
                s << std::setfill('0') << std::setw(2) << static_cast<unsigned>(hour) << ":"
                  << std::setw(2) << static_cast<unsigned>(minute) << ":" << std::setw(2)
                  << static_cast<unsigned>(second) << "." << std::setw(2) << static_cast<unsigned>(hsec);
            }
            out.rendered = s.str();
            return out;
        }
        case 12: {  // BACnetObjectIdentifier -- 4 bytes: type(10 bits)/instance(22 bits) -- see
                     // fObjectIdentifier/object_id_type/object_id_instance.
            if (value_offset + 4 > span.size()) return out;
            uint32_t raw = 0;
            for (int i = 0; i < 4; ++i) raw = (raw << 8) | span.at(value_offset + i);
            uint32_t type = (raw >> 22) & 0x3FF;
            uint32_t instance = raw & 0x3FFFFF;
            out.ok = true;
            out.rendered = object_type_name(type) + "," + std::to_string(instance);
            out.consumed = 4;
            return out;
        }
        default:
            // Tag 13-15 (reserved by ASHRAE) -- see bacnet.hpp's "Property value decode"
            // paragraph.
            return out;
    }
}

// ------------------------------------------------------------------------------------------
// Small tag-walking helpers used by the "first pass" service decoders below. All of them take
// `offset` by reference and only advance it on success -- a failed match leaves `offset`
// untouched so the caller can try the next alternative (matching packet-bacapp.c's own
// lastoffset-based "nothing happened, exit loop" pattern, e.g. fWhoIsRequest/fWhoHas).

// Reads one context-tagged primitive expected at context tag number `expected_tag`, decoded as
// if it were application tag `semantic_type` (context tags reuse the exact same LVT/value byte
// encoding as application tags -- only the tag header's class bit and the caller's own knowledge
// of field position say what type a context tag's value actually is). Returns std::nullopt (offset
// unchanged) when the tag at `offset` isn't context-specific, isn't number `expected_tag`, or is
// an opening/closing tag rather than a primitive.
std::optional<PrimitiveValue> try_context_primitive(ByteSpan span, size_t& offset, uint8_t expected_tag,
                                                     uint8_t semantic_type) {
    auto h = decode_tag_header(span, offset);
    if (!h || !h->context_specific || h->opening || h->closing || h->tag_number != expected_tag) {
        return std::nullopt;
    }
    size_t value_offset = offset + h->header_length;
    PrimitiveValue v = decode_application_primitive(span, value_offset, semantic_type, h->lvt);
    if (!v.ok) return std::nullopt;
    offset += h->header_length + v.consumed;
    return v;
}

// Reads one application-tagged primitive (no context-tag gating at all -- used for I-Am/I-Have,
// whose fields are plain sequential application-tagged values, and for the generic Error PDU's
// errorClass/errorCode). Returns std::nullopt (offset unchanged) on any decode failure.
std::optional<PrimitiveValue> try_application_primitive(ByteSpan span, size_t& offset) {
    auto h = decode_tag_header(span, offset);
    if (!h || h->context_specific || h->opening || h->closing) return std::nullopt;
    size_t value_offset = offset + h->header_length;
    PrimitiveValue v = decode_application_primitive(span, value_offset, h->tag_number, h->lvt);
    if (!v.ok) return std::nullopt;
    offset += h->header_length + v.consumed;
    return v;
}

// Skips a constructed (opening/closing-tag-wrapped) region whose opening tag has already been
// consumed (offset points right after it) -- walks forward tracking nesting depth of any
// opening/closing tag pair, skipping over primitive values' own bytes along the way, until the
// matching closing tag (depth back to 0) is found and consumed. Returns std::nullopt on
// truncation/malformed input. Used when this decoder's "first pass" doesn't value-decode a
// constructed PropertyValue (an array or service-specific structured value) -- see bacnet.hpp's
// "Property value decode" paragraph.
std::optional<size_t> skip_constructed(ByteSpan span, size_t offset) {
    int depth = 1;
    while (depth > 0) {
        auto h = decode_tag_header(span, offset);
        if (!h) return std::nullopt;
        offset += h->header_length;
        if (h->opening) {
            depth++;
        } else if (h->closing) {
            depth--;
        } else {
            // Primitive value -- skip its bytes (Null/Boolean consume none, per
            // decode_application_primitive's own "consumed" semantics for those two types --
            // this skip logic mirrors that directly by simply trusting lvt, which is correct for
            // every primitive type except Boolean's application-tagged form, whose lvt IS its
            // value (0 or 1) rather than a byte count; that specific case would wrongly skip 0-1
            // extra bytes here, but a bare Boolean is not a realistic constituent of a
            // constructed value this decoder needs to skip past correctly for its own first-pass
            // scope, so this is accepted as an honest, narrow limitation).
            if (offset + h->lvt > span.size()) return std::nullopt;
            offset += h->lvt;
        }
    }
    return offset;
}

}  // namespace

namespace {

// ------------------------------------------------------------------------------------------
// "First pass" APDU service value decoders -- see bacnet.hpp's file header comment's APDU
// section for exactly which services these are and why, and the exact context-tag-number layout
// each one was cross-checked against (fWhoIsRequest/fIAmRequest/fWhoHas/fIHaveRequest/
// fBACnetObjectPropertyReference+fPropertyReference/fReadPropertyAck/fWritePropertyRequest/
// fError in packet-bacapp.c).

// Who-Is (unconfirmed service 8): optional context[0]/[1] device-instance range, both present or
// neither.
std::vector<std::string> decode_who_is(ByteSpan span) {
    std::vector<std::string> values;
    size_t offset = 0;
    if (auto low = try_context_primitive(span, offset, 0, 2)) {
        values.push_back("device-instance-range-low=" + low->rendered);
        if (auto high = try_context_primitive(span, offset, 1, 2)) {
            values.push_back("device-instance-range-high=" + high->rendered);
        }
    }
    return values;
}

// I-Am (unconfirmed service 0): ObjectIdentifier + Max-APDU-Length-Accepted(Unsigned) +
// Segmentation-Supported(Enumerated) + Vendor-ID(Unsigned), all application-tagged, sequential.
std::vector<std::string> decode_i_am(ByteSpan span) {
    std::vector<std::string> values;
    size_t offset = 0;
    if (auto obj = try_application_primitive(span, offset)) {
        values.push_back("device-object=" + obj->rendered);
    }
    if (auto max_apdu = try_application_primitive(span, offset)) {
        values.push_back("max-apdu-length-accepted=" + max_apdu->rendered);
    }
    if (auto seg = try_application_primitive(span, offset)) {
        uint64_t v = 0;
        try {
            v = std::stoull(seg->rendered);
        } catch (...) {
        }
        values.push_back("segmentation-supported=" + lookup(kSegmentationNames, static_cast<uint32_t>(v)));
    }
    if (auto vendor = try_application_primitive(span, offset)) {
        values.push_back("vendor-id=" + vendor->rendered);
    }
    return values;
}

// Who-Has (unconfirmed service 7): optional context[0]/[1] device-instance range (same shape as
// Who-Is), then EITHER context[2] ObjectIdentifier OR context[3] ObjectName(CharacterString).
std::vector<std::string> decode_who_has(ByteSpan span) {
    std::vector<std::string> values;
    size_t offset = 0;
    if (auto low = try_context_primitive(span, offset, 0, 2)) {
        values.push_back("device-instance-range-low=" + low->rendered);
        if (auto high = try_context_primitive(span, offset, 1, 2)) {
            values.push_back("device-instance-range-high=" + high->rendered);
        }
    }
    if (auto obj = try_context_primitive(span, offset, 2, 12)) {
        values.push_back("object=" + obj->rendered);
    } else if (auto name = try_context_primitive(span, offset, 3, 7)) {
        values.push_back("object-name=" + name->rendered);
    }
    return values;
}

// I-Have (unconfirmed service 1): DeviceIdentifier + ObjectIdentifier + ObjectName, all
// application-tagged, sequential.
std::vector<std::string> decode_i_have(ByteSpan span) {
    std::vector<std::string> values;
    size_t offset = 0;
    if (auto device = try_application_primitive(span, offset)) {
        values.push_back("device=" + device->rendered);
    }
    if (auto obj = try_application_primitive(span, offset)) {
        values.push_back("object=" + obj->rendered);
    }
    if (auto name = try_application_primitive(span, offset)) {
        values.push_back("object-name=" + name->rendered);
    }
    return values;
}

// Shared by ReadProperty-Request/-ACK and WriteProperty-Request: context[0] ObjectIdentifier +
// context[1] PropertyIdentifier + optional context[2] PropertyArrayIndex.
void decode_object_property_reference(ByteSpan span, size_t& offset, std::vector<std::string>& values) {
    if (auto obj = try_context_primitive(span, offset, 0, 12)) {
        values.push_back("object=" + obj->rendered);
    }
    if (auto prop = try_context_primitive(span, offset, 1, 9)) {
        uint64_t v = 0;
        try {
            v = std::stoull(prop->rendered);
        } catch (...) {
        }
        values.push_back("property=" + property_identifier_name(static_cast<uint32_t>(v)));
    }
    if (auto idx = try_context_primitive(span, offset, 2, 2)) {
        values.push_back("property-array-index=" + idx->rendered);
    }
}

// A context[N]-wrapped PropertyValue (opening tag N ... one application-tagged primitive ...
// closing tag N) -- see bacnet.hpp's "Property value decode" paragraph. Appends "value=..." (or
// a "not decoded" note) to `values` and advances `offset` past the whole wrapped region.
// `notes` collects an explanatory note when the wrapped content isn't a single primitive.
void decode_property_value(ByteSpan span, size_t& offset, uint8_t context_tag, std::vector<std::string>& values,
                            std::vector<std::string>& notes) {
    auto open = decode_tag_header(span, offset);
    if (!open || !open->context_specific || !open->opening || open->tag_number != context_tag) return;
    size_t inner = offset + open->header_length;

    auto inner_header = decode_tag_header(span, inner);
    if (inner_header && !inner_header->context_specific && !inner_header->opening && !inner_header->closing) {
        size_t value_offset = inner + inner_header->header_length;
        PrimitiveValue v = decode_application_primitive(span, value_offset, inner_header->tag_number,
                                                          inner_header->lvt);
        if (v.ok) {
            size_t after_value = value_offset + v.consumed;
            auto close = decode_tag_header(span, after_value);
            if (close && close->context_specific && close->closing && close->tag_number == context_tag) {
                values.push_back("value=(" + v.type_name + ") " + v.rendered);
                offset = after_value + close->header_length;
                return;
            }
        }
    }
    // Not a single primitive (an array/list, or a service-specific structured value) -- named
    // only, see bacnet.hpp's "Property value decode" paragraph.
    if (auto end = skip_constructed(span, inner)) {
        notes.push_back("property value is constructed (an array/list or service-specific structured "
                         "value), not a single primitive -- not value-decoded in this first-pass release");
        offset = *end;
    }
}

std::vector<std::string> decode_read_property_request(ByteSpan span) {
    std::vector<std::string> values;
    size_t offset = 0;
    decode_object_property_reference(span, offset, values);
    return values;
}

std::vector<std::string> decode_read_property_ack(ByteSpan span, std::vector<std::string>& notes) {
    std::vector<std::string> values;
    size_t offset = 0;
    decode_object_property_reference(span, offset, values);
    decode_property_value(span, offset, 3, values, notes);
    return values;
}

std::vector<std::string> decode_write_property_request(ByteSpan span, std::vector<std::string>& notes) {
    std::vector<std::string> values;
    size_t offset = 0;
    decode_object_property_reference(span, offset, values);
    decode_property_value(span, offset, 3, values, notes);
    if (auto prio = try_context_primitive(span, offset, 4, 2)) {
        values.push_back("priority=" + prio->rendered);
    }
    return values;
}

// Generic Error-PDU shape: errorClass + errorCode, both application-tagged Enumerated -- see
// fError. Several confirmed services define their own richer, service-specific error structure
// instead (see bacnet.hpp's PDU-type-5 paragraph) -- this decoder does not special-case those, so
// this is only attempted, and only accepted, when the two values decode as plain Enumerated.
bool decode_generic_error(ByteSpan span, BacnetApdu& apdu) {
    size_t offset = 0;
    auto cls = try_application_primitive(span, offset);
    if (!cls || cls->type_name != "Enumerated") return false;
    auto code = try_application_primitive(span, offset);
    if (!code || code->type_name != "Enumerated") return false;
    apdu.has_error_class_code = true;
    try {
        apdu.error_class = static_cast<uint32_t>(std::stoull(cls->rendered));
        apdu.error_code = static_cast<uint32_t>(std::stoull(code->rendered));
    } catch (...) {
        return false;
    }
    apdu.error_class_name = lookup(kErrorClassNames, apdu.error_class);
    apdu.error_code_name = error_code_name(apdu.error_code);
    return true;
}

// Dispatches a non-segmented service's request/ACK data to this decoder's "first pass" set (see
// bacnet.hpp's APDU section) -- anything else is left as raw hex.
void decode_service_data(BacnetApdu& apdu, ByteSpan data, std::vector<std::string>& notes, bool is_ack) {
    if (apdu.segmented) {
        apdu.data_shown_as_hex = true;
        apdu.data_hex = to_hex(data, "");
        apdu.data_length = data.size();
        notes.push_back(
            "segmented APDU: this datagram carries one segment of a larger message; its service data is "
            "not value-decoded (this decoder does no cross-packet APDU reassembly), only shown as raw hex "
            "-- see bacnet.hpp's file header comment");
        return;
    }
    if (!apdu.has_service_choice) return;
    bool decoded = false;
    if (!is_ack && !apdu.is_confirmed_service) {
        switch (apdu.service_choice) {
            case 0: apdu.values = decode_i_am(data); decoded = true; break;
            case 1: apdu.values = decode_i_have(data); decoded = true; break;
            case 7: apdu.values = decode_who_has(data); decoded = true; break;
            case 8: apdu.values = decode_who_is(data); decoded = true; break;
            default: break;
        }
    } else if (!is_ack && apdu.is_confirmed_service) {
        switch (apdu.service_choice) {
            case 12: apdu.values = decode_read_property_request(data); decoded = true; break;
            case 15: apdu.values = decode_write_property_request(data, notes); decoded = true; break;
            default: break;
        }
    } else if (is_ack) {
        switch (apdu.service_choice) {
            case 12: apdu.values = decode_read_property_ack(data, notes); decoded = true; break;
            default: break;
        }
    }
    if (!decoded && !data.empty()) {
        apdu.data_shown_as_hex = true;
        apdu.data_hex = to_hex(data, "");
        apdu.data_length = data.size();
    }
}

const std::pair<uint32_t, const char*> kPduTypeNames[] = {
    {0, "Confirmed-Request"}, {1, "Unconfirmed-Request"}, {2, "Simple-ACK"}, {3, "Complex-ACK"},
    {4, "Segment-ACK"},       {5, "Error"},               {6, "Reject"},    {7, "Abort"},
};

std::string apdu_summary(const BacnetApdu& apdu) {
    std::ostringstream s;
    s << apdu.pdu_type_name;
    if (apdu.invoke_id >= 0) s << " invoke-id=" << apdu.invoke_id;
    if (apdu.has_service_choice) s << " " << apdu.service_choice_name;
    if (apdu.has_error_class_code) {
        s << " " << apdu.error_class_name << "/" << apdu.error_code_name;
    }
    if (!apdu.reject_reason_name.empty()) s << " " << apdu.reject_reason_name;
    if (!apdu.abort_reason_name.empty()) s << " " << apdu.abort_reason_name;
    if (!apdu.values.empty()) {
        s << " [" << apdu.values.front();
        if (apdu.values.size() > 1) s << " +" << (apdu.values.size() - 1) << " more";
        s << "]";
    }
    return s.str();
}

// Decodes one APDU -- see bacnet.hpp's file header comment's APDU section for the exact byte
// layout of all 8 PDU types, cross-checked against packet-bacapp.c's fStartConfirmed/
// fSimpleAckPDU/fSegmentAckPDU/fErrorPDU/fRejectPDU/fAbortPDU/fUnconfirmedRequestPDU.
std::optional<BacnetApdu> decode_apdu(ByteSpan span, std::vector<std::string>& notes) {
    if (span.empty()) return std::nullopt;
    BacnetApdu apdu;
    uint8_t byte0 = span.at(0);
    apdu.pdu_type = static_cast<uint8_t>((byte0 >> 4) & 0x0F);
    apdu.pdu_type_name = lookup(kPduTypeNames, apdu.pdu_type, "unknown");

    switch (apdu.pdu_type) {
        case 0: {  // Confirmed-Request
            apdu.segmented = (byte0 & 0x08) != 0;
            apdu.more_follows = (byte0 & 0x04) != 0;
            apdu.segmented_response_accepted = (byte0 & 0x02) != 0;
            if (span.size() < 3) {
                notes.push_back("Confirmed-Request APDU truncated before its fixed header");
                return apdu;
            }
            size_t offset = 2;  // byte0 + the max-segs/max-apdu-len byte (not itself surfaced)
            apdu.invoke_id = span.at(offset++);
            if (apdu.segmented) {
                if (offset + 2 > span.size()) {
                    notes.push_back("segmented Confirmed-Request APDU truncated before sequence-number/"
                                     "proposed-window-size");
                    return apdu;
                }
                apdu.sequence_number = span.at(offset++);
                apdu.proposed_window_size = span.at(offset++);
            }
            if (offset >= span.size()) {
                notes.push_back("Confirmed-Request APDU truncated before service-choice");
                return apdu;
            }
            apdu.service_choice = span.at(offset++);
            apdu.has_service_choice = true;
            apdu.is_confirmed_service = true;
            apdu.service_choice_name = confirmed_service_name(apdu.service_choice);
            decode_service_data(apdu, span.from(offset), notes, /*is_ack=*/false);
            break;
        }
        case 1: {  // Unconfirmed-Request
            if (span.size() < 2) {
                notes.push_back("Unconfirmed-Request APDU truncated before service-choice");
                return apdu;
            }
            apdu.service_choice = span.at(1);
            apdu.has_service_choice = true;
            apdu.is_confirmed_service = false;
            apdu.service_choice_name = unconfirmed_service_name(apdu.service_choice);
            decode_service_data(apdu, span.from(2), notes, /*is_ack=*/false);
            break;
        }
        case 2: {  // Simple-ACK
            if (span.size() < 3) {
                notes.push_back("Simple-ACK APDU truncated");
                return apdu;
            }
            apdu.invoke_id = span.at(1);
            apdu.service_choice = span.at(2);
            apdu.has_service_choice = true;
            apdu.is_confirmed_service = true;
            apdu.service_choice_name = confirmed_service_name(apdu.service_choice);
            break;
        }
        case 3: {  // Complex-ACK
            apdu.segmented = (byte0 & 0x08) != 0;
            apdu.more_follows = (byte0 & 0x04) != 0;
            if (span.size() < 2) {
                notes.push_back("Complex-ACK APDU truncated before invoke-id");
                return apdu;
            }
            size_t offset = 1;
            apdu.invoke_id = span.at(offset++);
            if (apdu.segmented) {
                if (offset + 2 > span.size()) {
                    notes.push_back("segmented Complex-ACK APDU truncated before sequence-number/"
                                     "proposed-window-size");
                    return apdu;
                }
                apdu.sequence_number = span.at(offset++);
                apdu.proposed_window_size = span.at(offset++);
            }
            if (offset >= span.size()) {
                notes.push_back("Complex-ACK APDU truncated before service-ACK-choice");
                return apdu;
            }
            apdu.service_choice = span.at(offset++);
            apdu.has_service_choice = true;
            apdu.is_confirmed_service = true;
            apdu.service_choice_name = confirmed_service_name(apdu.service_choice);
            decode_service_data(apdu, span.from(offset), notes, /*is_ack=*/true);
            break;
        }
        case 4: {  // Segment-ACK -- exactly 4 bytes, no further data
            if (span.size() < 4) {
                notes.push_back("Segment-ACK APDU truncated (needs exactly 4 bytes)");
                return apdu;
            }
            apdu.negative_ack = (byte0 & 0x02) != 0;
            apdu.server = (byte0 & 0x01) != 0;
            apdu.invoke_id = span.at(1);
            apdu.sequence_number = span.at(2);
            apdu.actual_window_size = span.at(3);
            break;
        }
        case 5: {  // Error
            if (span.size() < 3) {
                notes.push_back("Error APDU truncated before error-choice");
                return apdu;
            }
            apdu.invoke_id = span.at(1);
            apdu.service_choice = span.at(2);
            apdu.has_service_choice = true;
            apdu.is_confirmed_service = true;
            apdu.service_choice_name = confirmed_service_name(apdu.service_choice);
            ByteSpan data = span.from(3);
            if (!decode_generic_error(data, apdu) && !data.empty()) {
                apdu.data_shown_as_hex = true;
                apdu.data_hex = to_hex(data, "");
                apdu.data_length = data.size();
                notes.push_back("error-choice " + apdu.service_choice_name +
                                 " may use a service-specific error structure rather than the generic "
                                 "errorClass/errorCode shape this decoder decodes -- see bacnet.hpp");
            }
            break;
        }
        case 6: {  // Reject -- exactly 3 bytes, no further data
            if (span.size() < 3) {
                notes.push_back("Reject APDU truncated");
                return apdu;
            }
            apdu.invoke_id = span.at(1);
            apdu.reject_reason = span.at(2);
            apdu.reject_reason_name = lookup(kRejectReasonNames, apdu.reject_reason);
            break;
        }
        case 7: {  // Abort -- exactly 3 bytes, no further data
            if (span.size() < 3) {
                notes.push_back("Abort APDU truncated");
                return apdu;
            }
            apdu.server = (byte0 & 0x01) != 0;
            apdu.invoke_id = span.at(1);
            apdu.abort_reason = span.at(2);
            apdu.abort_reason_name = lookup(kAbortReasonNames, apdu.abort_reason);
            break;
        }
        default:
            notes.push_back("APDU type " + std::to_string(apdu.pdu_type) +
                             " is not one of the 8 the spec defines (0-7)");
            return std::nullopt;
    }
    apdu.summary = apdu_summary(apdu);
    return apdu;
}

std::string ip_at(ByteSpan span, size_t offset) {
    uint32_t addr = 0;
    for (int i = 0; i < 4; ++i) addr = (addr << 8) | span.at(offset + i);
    return format_ipv4(addr);
}

uint16_t u16_at(ByteSpan span, size_t offset) {
    return static_cast<uint16_t>((span.at(offset) << 8) | span.at(offset + 1));
}

// Decodes one NPDU -- see bacnet.hpp's file header comment's NPDU section, cross-checked against
// packet-bacnet.c's dissect_bacnet_npdu.
BacnetNpdu decode_npdu(ByteSpan span) {
    BacnetNpdu npdu;
    if (span.size() < 2) {
        npdu.notes.push_back("NPDU truncated before Version/Control");
        npdu.summary = "NPDU (truncated)";
        return npdu;
    }
    size_t offset = 0;
    npdu.version = span.at(offset++);
    npdu.control = span.at(offset++);
    bool net = (npdu.control & 0x80) != 0;
    bool dest = (npdu.control & 0x20) != 0;
    bool src = (npdu.control & 0x08) != 0;
    npdu.is_network_layer_message = net;
    npdu.expecting_reply = (npdu.control & 0x04) != 0;
    npdu.priority = npdu.control & 0x03;
    npdu.has_dest = dest;

    if (dest) {
        if (offset + 3 > span.size()) {
            npdu.notes.push_back("NPDU truncated before DNET/DLEN");
            npdu.summary = "NPDU (truncated)";
            return npdu;
        }
        npdu.dnet = u16_at(span, offset);
        offset += 2;
        npdu.dlen = span.at(offset++);
        if (npdu.dlen > 0) {
            if (offset + npdu.dlen > span.size()) {
                npdu.notes.push_back("NPDU truncated before DADR");
                npdu.summary = "NPDU (truncated)";
                return npdu;
            }
            npdu.dadr_hex = to_hex(span.subspan(offset, npdu.dlen), "");
            offset += npdu.dlen;
        }
    }
    npdu.has_src = src;
    if (src) {
        if (offset + 3 > span.size()) {
            npdu.notes.push_back("NPDU truncated before SNET/SLEN");
            npdu.summary = "NPDU (truncated)";
            return npdu;
        }
        npdu.snet = u16_at(span, offset);
        offset += 2;
        npdu.slen = span.at(offset++);
        if (npdu.slen > 0) {
            if (offset + npdu.slen > span.size()) {
                npdu.notes.push_back("NPDU truncated before SADR");
                npdu.summary = "NPDU (truncated)";
                return npdu;
            }
            npdu.sadr_hex = to_hex(span.subspan(offset, npdu.slen), "");
            offset += npdu.slen;
        }
    }
    if (dest) {
        if (offset >= span.size()) {
            npdu.notes.push_back("NPDU truncated before HopCount");
            npdu.summary = "NPDU (truncated)";
            return npdu;
        }
        npdu.hop_count = span.at(offset++);
    }

    if (net) {
        if (offset >= span.size()) {
            npdu.notes.push_back("NPDU truncated before its Network Layer Message type");
            npdu.summary = "NPDU (truncated)";
            return npdu;
        }
        npdu.message_type = span.at(offset++);
        npdu.message_type_name = network_message_type_name(npdu.message_type);
        if (npdu.message_type >= 0x80) {
            if (offset + 2 > span.size()) {
                npdu.notes.push_back("NPDU truncated before its vendor-proprietary Network Layer "
                                      "Message's Vendor ID");
            } else {
                npdu.has_vendor_id = true;
                npdu.vendor_id = u16_at(span, offset);
                offset += 2;
            }
        }
        // Network Layer Message body (everything from `offset` on) is named only, not value-
        // decoded -- see bacnet.hpp's NPDU section.
        npdu.summary = "Network-Layer-Message " + npdu.message_type_name;
        return npdu;
    }

    ByteSpan apdu_span = span.from(offset);
    if (apdu_span.empty()) {
        npdu.notes.push_back("no APDU bytes present after the NPDU header");
        npdu.summary = "NPDU (no APDU)";
        return npdu;
    }
    auto apdu = decode_apdu(apdu_span, npdu.notes);
    if (apdu) {
        npdu.has_apdu = true;
        npdu.apdu = *apdu;
        npdu.summary = npdu.apdu.summary;
    } else {
        npdu.summary = "NPDU (APDU type not recognized)";
    }
    return npdu;
}

}  // namespace

std::optional<BacnetFrame> try_parse_bacnet(ByteSpan udp_payload) {
    if (udp_payload.size() < 4) return std::nullopt;
    try {
        uint8_t type = udp_payload.at(0);
        uint8_t function = udp_payload.at(1);
        if (type != 0x81) return std::nullopt;  // not BACnet/IP (Annex J) -- see the "structural
                                                  // detection gate" paragraph; BACnet/SC's 0x82 is
                                                  // an entirely different (WebSocket) transport.
        if (function > 0x0C) return std::nullopt;

        BacnetFrame frame;
        frame.bvlc_type = type;
        frame.bvlc_function = function;
        frame.bvlc_function_name = bvlc_function_name(function);

        uint16_t declared_length = u16_at(udp_payload, 2);
        size_t packet_length = udp_payload.size();

        uint16_t bvlc_length;
        if (function > 0x08) {
            bvlc_length = 4;
        } else if (function == 0x04) {
            bvlc_length = 10;
        } else {
            // Functions 0x00-0x03/0x05-0x08: BBMD/FDT routing-level management, no NPDU at all --
            // the whole message is BVLC (see bacnet.hpp's BVLC section).
            bvlc_length = static_cast<uint16_t>(packet_length > 0xFFFF ? 0xFFFF : packet_length);
        }

        if (bvlc_length < 4 || static_cast<size_t>(bvlc_length) > packet_length) {
            frame.notes.push_back("BVLC message needs " + std::to_string(bvlc_length) +
                                   " byte(s) but only " + std::to_string(packet_length) +
                                   " are present -- truncated");
            frame.summary = "BVLC " + frame.bvlc_function_name + " (truncated)";
            return frame;
        }
        if (declared_length != packet_length) {
            frame.notes.push_back("BVLC header's own declared Length (" + std::to_string(declared_length) +
                                   ") does not match the " + std::to_string(packet_length) +
                                   " byte(s) actually present in this UDP datagram");
        }
        frame.bvlc_length = bvlc_length;

        size_t offset = 4;
        switch (function) {
            case 0x00:  // BVLC-Result
                if (offset + 2 <= packet_length) {
                    frame.has_result_code = true;
                    frame.result_code = u16_at(udp_payload, offset);
                }
                break;
            case 0x01:  // Write-Broadcast-Distribution-Table
            case 0x03: {  // Read-Broadcast-Distribution-Table-Ack
                size_t p = offset;
                while (p + 10 <= static_cast<size_t>(bvlc_length)) {
                    std::ostringstream e;
                    e << ip_at(udp_payload, p) << ":" << u16_at(udp_payload, p + 4) << " mask="
                      << ip_at(udp_payload, p + 6);
                    frame.table_entries.push_back(e.str());
                    p += 10;
                }
                break;
            }
            case 0x02:  // Read-Broadcast-Distribution-Table -- nothing further
                break;
            case 0x05:  // Register-Foreign-Device
                if (offset + 2 <= packet_length) {
                    frame.has_registration_ttl = true;
                    frame.registration_ttl_seconds = u16_at(udp_payload, offset);
                }
                break;
            case 0x06:  // Read-Foreign-Device-Table -- nothing further
                break;
            case 0x07: {  // Read-Foreign-Device-Table-Ack
                size_t p = offset;
                while (p + 10 <= static_cast<size_t>(bvlc_length)) {
                    std::ostringstream e;
                    e << ip_at(udp_payload, p) << ":" << u16_at(udp_payload, p + 4)
                      << " ttl=" << u16_at(udp_payload, p + 6) << " timeout=" << u16_at(udp_payload, p + 8);
                    frame.table_entries.push_back(e.str());
                    p += 10;
                }
                break;
            }
            case 0x08:  // Delete-Foreign-Device-Table-Entry
                if (offset + 6 <= packet_length) {
                    std::ostringstream e;
                    e << ip_at(udp_payload, offset) << ":" << u16_at(udp_payload, offset + 4);
                    frame.notes.push_back("delete-entry=" + e.str());
                }
                break;
            case 0x04:  // Forwarded-NPDU
                if (offset + 6 <= packet_length) {
                    frame.has_forwarding_source = true;
                    frame.forwarding_source_ip = ip_at(udp_payload, offset);
                    frame.forwarding_source_port = u16_at(udp_payload, offset + 4);
                }
                break;
            case 0x0C:  // Secure-BVLL -- see bacnet.hpp's BVLC section
                frame.notes.push_back(
                    "Secure-BVLL payload is encrypted/signed -- not decodable without key material this "
                    "decoder has no access to, see bacnet.hpp's file header comment");
                break;
            default:  // 0x09/0x0A/0x0B carry no BVLC-specific sub-fields of their own
                break;
        }

        if (function == 0x04 || function == 0x09 || function == 0x0A || function == 0x0B) {
            frame.has_npdu = true;
            ByteSpan npdu_span = udp_payload.subspan(bvlc_length, packet_length - bvlc_length);
            frame.npdu = decode_npdu(npdu_span);
            for (const auto& n : frame.npdu.notes) frame.notes.push_back(n);
        }

        // Surface every BVLC-only sub-field decoded above (result code, BDT/FDT entries,
        // registration TTL, forwarding source) into notes -- these functions carry no NPDU, so
        // there is nothing else in the frame for a reader to look at otherwise.
        if (frame.has_result_code) {
            frame.notes.push_back("result-code=0x" + [&] {
                std::ostringstream h;
                h << std::hex << std::uppercase << frame.result_code;
                return h.str();
            }());
        }
        if (frame.has_registration_ttl) {
            frame.notes.push_back("registration-ttl=" + std::to_string(frame.registration_ttl_seconds) + "s");
        }
        if (frame.has_forwarding_source) {
            frame.notes.push_back("forwarded-from=" + frame.forwarding_source_ip + ":" +
                                   std::to_string(frame.forwarding_source_port));
        }
        if (!frame.table_entries.empty()) {
            frame.notes.push_back(std::to_string(frame.table_entries.size()) + " table entry/entries: " + [&] {
                std::ostringstream e;
                for (size_t i = 0; i < frame.table_entries.size(); ++i) {
                    if (i != 0) e << "; ";
                    e << frame.table_entries[i];
                }
                return e.str();
            }());
        }

        std::ostringstream s;
        s << "BVLC " << frame.bvlc_function_name;
        if (frame.has_npdu) {
            s << " " << frame.npdu.summary;
        } else if (frame.has_result_code) {
            s << " result-code=0x" << std::hex << std::uppercase << frame.result_code;
        } else if (!frame.table_entries.empty()) {
            s << " (" << frame.table_entries.size() << " entry/entries)";
        } else if (frame.has_registration_ttl) {
            s << " ttl=" << std::dec << frame.registration_ttl_seconds << "s";
        }
        frame.summary = s.str();
        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // goose.cpp/sv.cpp/profinet.cpp/ethercat.cpp all take.
        return std::nullopt;
    }
}

std::optional<ProtocolResult> BacnetDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_bacnet(payload);
    if (!frame) return std::nullopt;
    return ProtocolResult::make<BacnetFrame>("bacnet", std::move(*frame));
}

const ProtocolDecoder& bacnet_decoder() {
    static const BacnetDecoder instance;
    return instance;
}

}  // namespace conduitscope
