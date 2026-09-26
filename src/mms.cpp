// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/mms.hpp"

#include "conduitscope/portable_time.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// ==============================================================================================
// Small formatting helpers (mirrors opcua.cpp's/hartip.cpp's own style).

std::string format_float(float v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

float bits_to_float(uint32_t bits) {
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// seconds: since 1970-01-01T00:00:00Z -- see mms.hpp's "UtcTime encoding" section.
std::string format_utc_time(uint32_t seconds, uint32_t fraction24, uint8_t flags) {
    std::time_t tt = static_cast<std::time_t>(seconds);
    std::tm tm_utc{};
    std::ostringstream s;
    if (portable_gmtime(tt, tm_utc)) {
        // fraction24 is a 24-bit fixed-point fraction of a second; render to milliseconds.
        int ms = static_cast<int>((static_cast<uint64_t>(fraction24) * 1000) / (1u << 24));
        s << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms
          << 'Z';
    } else {
        s << seconds << "s (out of range for calendar display)";
    }
    std::vector<std::string> flag_names;
    if (flags & 0x80) flag_names.push_back("leap-seconds-known");
    if (flags & 0x40) flag_names.push_back("clock-failure");
    if (flags & 0x20) flag_names.push_back("clock-not-synchronized");
    int accuracy = flags & 0x1F;
    s << " [";
    for (size_t i = 0; i < flag_names.size(); ++i) {
        if (i) s << ",";
        s << flag_names[i];
    }
    if (!flag_names.empty()) s << ",";
    s << "accuracy=" << accuracy << "bit]";
    return s.str();
}

// ==============================================================================================
// BER (ASN.1 Basic Encoding Rules) TLV reading -- the shared low-level primitive every layer
// above Session uses. This decoder implements only the specific, small subset MMS/ACSE/
// Presentation actually need (definite-length only -- never observed otherwise in this
// decoder's own research; the high-tag-number multi-byte tag form IS implemented, since MMS's
// own ConfirmedServiceRequest/Response CHOICE has 78 alternatives, some numbered beyond 30).

struct BerTlv {
    uint8_t tag_byte = 0;    // the full first byte: class + constructed bit + low tag bits
    uint32_t tag_number = 0;  // the decoded tag number (handles the multi-byte form)
    bool constructed = false;
    ByteSpan content;
    size_t total_len = 0;  // tag + length + content, i.e. how far to advance past this whole TLV
};

uint8_t ber_class(uint8_t tag_byte) { return tag_byte & 0xC0; }
constexpr uint8_t kBerClassUniversal = 0x00;
constexpr uint8_t kBerClassApplication = 0x40;
constexpr uint8_t kBerClassContext = 0x80;

// Reads one TLV starting at `buf`'s own beginning. Throws ParseError if there aren't enough
// bytes for a tag+length, or the declared length doesn't fit in what remains.
BerTlv read_ber_tlv(ByteSpan buf) {
    if (buf.size() < 2) throw ParseError("BER TLV: need at least 2 bytes for tag+length");
    Cursor c(buf);
    BerTlv tlv;
    tlv.tag_byte = c.u8();
    tlv.constructed = (tlv.tag_byte & 0x20) != 0;
    uint32_t tag_low = tlv.tag_byte & 0x1F;
    if (tag_low == 0x1F) {
        // High-tag-number form: subsequent bytes, 7 bits each, high bit = continuation.
        uint32_t tag_number = 0;
        int guard = 0;
        uint8_t b;
        do {
            if (++guard > 5) throw ParseError("BER TLV: tag number too long");
            b = c.u8();
            tag_number = (tag_number << 7) | (b & 0x7F);
        } while (b & 0x80);
        tlv.tag_number = tag_number;
    } else {
        tlv.tag_number = tag_low;
    }
    uint8_t len_byte = c.u8();
    size_t length;
    if (len_byte & 0x80) {
        uint8_t num_octets = len_byte & 0x7F;
        if (num_octets == 0) throw ParseError("BER TLV: indefinite length not supported");
        if (num_octets > 4) throw ParseError("BER TLV: length field implausibly wide");
        length = 0;
        for (uint8_t i = 0; i < num_octets; ++i) length = (length << 8) | c.u8();
    } else {
        length = len_byte;
    }
    tlv.content = c.bytes(length);
    tlv.total_len = c.position();
    return tlv;
}

// Splits `buf` into its top-level TLVs only (does not recurse). Throws ParseError if any TLV is
// malformed; a caller decoding a SET/SEQUENCE whose own remaining bytes don't cleanly divide
// into whole TLVs has genuinely malformed input, not merely an unrecognized shape.
std::vector<BerTlv> ber_children(ByteSpan buf) {
    std::vector<BerTlv> out;
    size_t offset = 0;
    while (offset < buf.size()) {
        BerTlv tlv = read_ber_tlv(buf.from(offset));
        out.push_back(tlv);
        offset += tlv.total_len;
    }
    return out;
}

// BER INTEGER content -> int64_t, sign-extended per the two's-complement, big-endian, minimal-
// length encoding BER requires. Accumulates in uint64_t, not int64_t: left-shifting a negative
// signed value is undefined behavior (C++17; C++20 defines it, but this codebase doesn't rely on
// that), and the sign-extension fill below sets exactly that up on the very first shift for any
// negative-valued BER INTEGER (an ordinary, unremarkable encoding, not a contrived edge case).
// Shifting an unsigned value is always well-defined (modulo 2^64 wraparound) regardless of bit
// pattern, and produces the identical bit pattern a two's-complement signed shift would have on
// every real target anyway -- so this changes definedness, not behavior. The final cast to
// int64_t is implementation-defined but universally two's-complement in practice, and
// standardized outright as of C++20. ber_unsigned right below was already unsigned throughout and
// never had this problem.
int64_t ber_integer(ByteSpan content) {
    if (content.empty()) return 0;
    uint64_t v = (content.at(0) & 0x80) ? ~uint64_t{0} : 0;  // sign-extend from the leading byte
    for (size_t i = 0; i < content.size(); ++i) v = (v << 8) | content.at(i);
    return static_cast<int64_t>(v);
}

uint64_t ber_unsigned(ByteSpan content) {
    uint64_t v = 0;
    for (size_t i = 0; i < content.size(); ++i) v = (v << 8) | content.at(i);
    return v;
}

std::string ber_visible_string(ByteSpan content) {
    return std::string(reinterpret_cast<const char*>(content.data()), content.size());
}

// OBJECT IDENTIFIER content -> dotted string, per X.690 8.19.
std::string decode_oid(ByteSpan content) {
    if (content.empty()) return "";
    std::ostringstream s;
    uint8_t first = content.at(0);
    s << (first / 40) << "." << (first % 40);
    uint64_t value = 0;
    for (size_t i = 1; i < content.size(); ++i) {
        uint8_t b = content.at(i);
        value = (value << 7) | (b & 0x7F);
        if (!(b & 0x80)) {
            s << "." << value;
            value = 0;
        }
    }
    return s.str();
}

// A small set of well-known OIDs this decoder actually expects to see in real MMS/IEC 61850
// traffic -- see mms.hpp's own "Sourcing" paragraph. Any other OID is shown numerically only.
std::string oid_name(const std::string& oid) {
    if (oid == "2.2.1.0.1") return "ACSE";
    if (oid == "1.0.9506.2.1") return "mms-abstract-syntax-version1";
    if (oid == "1.0.9506.2.2") return "mms-abstract-syntax-version2";
    if (oid == "1.0.9506.2.3") return "MMS";
    if (oid == "2.1.1") return "basic-encoding";
    return "";
}

std::string oid_with_name(const std::string& oid) {
    std::string name = oid_name(oid);
    return name.empty() ? oid : (oid + " (" + name + ")");
}

// BIT STRING content (first byte = unused-bit count, remaining bytes = the bits, MSB-first) ->
// the set bit INDEXES (0-based from the start of the bit string), for a caller with a name table
// to map against. Returns {} for an empty/malformed BIT STRING rather than throwing -- a
// capability bitstring this decoder can't further interpret is still shown as raw hex by the
// caller.
std::vector<int> bitstring_set_bits(ByteSpan content) {
    std::vector<int> bits;
    if (content.empty()) return bits;
    uint8_t unused = content.at(0);
    for (size_t byte_i = 1; byte_i < content.size(); ++byte_i) {
        uint8_t b = content.at(byte_i);
        int bit_count = 8;
        if (byte_i == content.size() - 1) bit_count = 8 - unused;
        for (int bit = 0; bit < bit_count; ++bit) {
            if (b & (0x80 >> bit)) bits.push_back(static_cast<int>((byte_i - 1) * 8 + bit));
        }
    }
    return bits;
}

std::string hex_of(ByteSpan span) { return to_hex(span, ""); }

}  // namespace

// ==============================================================================================
// The MMS "Data" value type (ISO 9506-2's own self-describing value encoding) -- see mms.hpp's
// own "The Data value type" section for the full tag table and rationale. `depth` guards against
// unbounded recursion on a deeply-nested array/structure -- see "Recursion depth cap" in
// mms.hpp; a real, independently-reproducible bug in tshark 4.2.2's own MMS dissector (see
// tests/real_captures/mms/ATTRIBUTION.md) is this decoder's own concrete motivation for capping
// rather than trusting well-formedness.
namespace {

// CLI-configurable via --max-recursion-depth -- see resource_limits.hpp. 0/unset keeps the
// literal 32 default. A function rather than a constexpr/const namespace-scope value, since it
// now reads process-wide configuration; called fresh on each recursive invocation below.
int max_data_recursion_depth() {
    return static_cast<int>(resource_limits().max_recursion_depth.value_or(32));
}

std::string decode_data_value(const BerTlv& tlv, int depth) {
    if (depth > max_data_recursion_depth()) {
        return "<recursion depth limit reached, " + std::to_string(tlv.content.size()) +
               " byte(s) not further decoded: " + hex_of(tlv.content) + ">";
    }
    switch (tlv.tag_number) {
        case 1: {  // array -- SEQUENCE OF Data
            auto items = ber_children(tlv.content);
            std::ostringstream s;
            s << "[";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) s << ", ";
                s << decode_data_value(items[i], depth + 1);
            }
            s << "]";
            return s.str();
        }
        case 2: {  // structure -- SEQUENCE OF Data
            auto items = ber_children(tlv.content);
            std::ostringstream s;
            s << "{";
            for (size_t i = 0; i < items.size(); ++i) {
                if (i) s << ", ";
                s << decode_data_value(items[i], depth + 1);
            }
            s << "}";
            return s.str();
        }
        case 3:  // boolean
            return (!tlv.content.empty() && tlv.content.at(0) != 0) ? "true" : "false";
        case 4: {  // bit-string -- shown as the set bit indexes, plus raw hex for anything this
                    // decoder's caller can't further name (Data's own bit-string has no fixed
                    // meaning at this generic level -- MMS quality/status bitstrings are named by
                    // the IEC 61850 dataset semantics this decoder doesn't have access to, the
                    // same "show the wire value, don't guess the meaning" posture as elsewhere).
            auto bits = bitstring_set_bits(tlv.content);
            std::ostringstream s;
            s << "bits[";
            for (size_t i = 0; i < bits.size(); ++i) {
                if (i) s << ",";
                s << bits[i];
            }
            s << "]";
            return s.str();
        }
        case 5:  // integer
            return std::to_string(ber_integer(tlv.content));
        case 6:  // unsigned
            return std::to_string(ber_unsigned(tlv.content));
        case 7: {  // floating-point -- exponent-width-prefixed IEEE754, see mms.hpp
            if (tlv.content.size() == 5 && tlv.content.at(0) == 8) {
                uint32_t bits = 0;
                for (int i = 1; i <= 4; ++i) bits = (bits << 8) | tlv.content.at(static_cast<size_t>(i));
                return format_float(bits_to_float(bits));
            }
            return "<floating-point, unsupported exponent width: " + hex_of(tlv.content) + ">";
        }
        case 8:  // real (BER REAL, ISO 9506's own alternative float encoding) -- never observed
                  // in this decoder's own research; shown as raw hex rather than guessed at.
            return "<real: " + hex_of(tlv.content) + ">";
        case 9:  // octet-string
            return hex_of(tlv.content);
        case 10:  // visible-string
            return "\"" + ber_visible_string(tlv.content) + "\"";
        case 12: {  // binary-time -- TimeOfDay, never observed in this decoder's own research
            return "<binary-time: " + hex_of(tlv.content) + ">";
        }
        case 13:  // bcd
            return "bcd:" + hex_of(tlv.content);
        case 14: {  // booleanArray -- a BIT STRING whose bits are individually true/false
            auto bits = bitstring_set_bits(tlv.content);
            std::ostringstream s;
            s << "boolArray(true-bits=[";
            for (size_t i = 0; i < bits.size(); ++i) {
                if (i) s << ",";
                s << bits[i];
            }
            s << "])";
            return s.str();
        }
        case 15:  // objId
            return decode_oid(tlv.content);
        case 16:  // mMSString -- UTF-8 (IEC 61850 Edition 2 addition)
            return "\"" + ber_visible_string(tlv.content) + "\"";
        case 17: {  // utc-time -- IEC 61850-8-1 addition, see mms.hpp
            if (tlv.content.size() == 8) {
                uint32_t seconds = static_cast<uint32_t>(ber_unsigned(tlv.content.subspan(0, 4)));
                uint32_t fraction24 = static_cast<uint32_t>(ber_unsigned(tlv.content.subspan(4, 3)));
                uint8_t flags = tlv.content.at(7);
                return format_utc_time(seconds, fraction24, flags);
            }
            return "<utc-time, unexpected length: " + hex_of(tlv.content) + ">";
        }
        default:
            return "<Data tag " + std::to_string(tlv.tag_number) + ": " + hex_of(tlv.content) + ">";
    }
}

}  // namespace

// ==============================================================================================
// ObjectName / VariableSpecification / VariableAccessSpecification -- see mms.hpp's own
// "ObjectName rendering" section.
namespace {

// `tlv` is the ObjectName CHOICE's own alternative TLV (vmd-specific[0]/domain-specific[1]/
// aa-specific[2]).
std::string decode_object_name(const BerTlv& tlv) {
    if (tlv.tag_number == 0) {  // vmd-specific -- a bare Identifier (VisibleString)
        return ber_visible_string(tlv.content);
    }
    if (tlv.tag_number == 1) {  // domain-specific -- SEQUENCE{domainId, itemId}, both VisibleString
        auto items = ber_children(tlv.content);
        if (items.size() >= 2) {
            return ber_visible_string(items[0].content) + "/" + ber_visible_string(items[1].content);
        }
        return "<malformed domain-specific ObjectName>";
    }
    if (tlv.tag_number == 2) {  // aa-specific -- a bare Identifier
        return ber_visible_string(tlv.content);
    }
    return "<unrecognized ObjectName alternative " + std::to_string(tlv.tag_number) + ">";
}

// `tlv` is VariableSpecification's own chosen alternative TLV. Only name[0] (wrapping an
// ObjectName, itself EXPLICITLY tagged -- see mms.hpp) is decoded to a readable tag; every other
// alternative (address/variableDescription/scatteredAccessDescription/invalidated) is rare in
// real IEC 61850 traffic and shown structurally only.
std::string decode_variable_specification(const BerTlv& tlv) {
    if (tlv.tag_number == 0) {  // name -- EXPLICIT wrap around ObjectName's own alternative
        auto inner = ber_children(tlv.content);
        if (!inner.empty()) return decode_object_name(inner[0]);
        return "<empty name>";
    }
    if (tlv.tag_number == 4) return "invalidated";
    return "<VariableSpecification alternative " + std::to_string(tlv.tag_number) + ", not decoded>";
}

// Decodes a VariableAccessSpecification CHOICE TLV into a flat list of human-readable variable
// references -- either every entry of a listOfVariable[0], or a single variableListName[1]
// (itself an ObjectName, EXPLICITLY wrapped -- see mms.hpp).
std::vector<std::string> decode_variable_access_specification(const BerTlv& tlv) {
    std::vector<std::string> out;
    if (tlv.tag_number == 0) {  // listOfVariable -- SEQUENCE OF SEQUENCE{variableSpecification, ...}
        auto entries = ber_children(tlv.content);
        for (const auto& entry : entries) {
            auto fields = ber_children(entry.content);
            if (!fields.empty()) out.push_back(decode_variable_specification(fields[0]));
        }
    } else if (tlv.tag_number == 1) {  // variableListName -- EXPLICIT wrap around ObjectName
        auto inner = ber_children(tlv.content);
        if (!inner.empty()) out.push_back("list:" + decode_object_name(inner[0]));
    }
    return out;
}

// AccessResult CHOICE -- failure[0] DataAccessError, or success Data (untagged -- see mms.hpp,
// confirmed empirically: Data's own natural tag appears directly, no extra wrap).
std::string decode_access_result(const BerTlv& tlv) {
    if (tlv.tag_number == 0 && ber_class(tlv.tag_byte) == kBerClassContext) {
        // Ambiguous with Data's own array/structure tags (1/2) only if class differed; failure
        // is specifically tag 0, which Data's own CHOICE reserves ("-- context tag 0 is reserved
        // for AccessResult" -- see mms.asn), so this check is unambiguous by design.
        return "<failure: DataAccessError " + std::to_string(ber_integer(tlv.content)) + ">";
    }
    return decode_data_value(tlv, 0);
}

}  // namespace


// ==============================================================================================
// ObjectName decode helper for fields whose ASN.1 declares them IMPLICIT over an underlying
// CHOICE type (GetNamedVariableListAttributes-Request ::= ObjectName, and similar) -- ASN.1
// X.680 formally forces IMPLICIT tagging of a CHOICE to behave as EXPLICIT (a single implicit
// tag cannot represent "which alternative"), and this decoder's own cross-checking against real
// captures (see mms.hpp/ATTRIBUTION.md) confirms real encoders follow that override. This helper
// tries the EXPLICIT interpretation first (one child, itself a recognized ObjectName alternative
// tag), and falls back to treating `tlv` as the alternative directly for the rare/legacy encoder
// that truly emitted it IMPLICIT.
namespace {

std::string decode_object_name_flexible(const BerTlv& tlv) {
    if (tlv.constructed) {
        auto inner = ber_children(tlv.content);
        if (inner.size() == 1 && ber_class(inner[0].tag_byte) == kBerClassContext && inner[0].tag_number <= 2) {
            return decode_object_name(inner[0]);
        }
    }
    return decode_object_name(tlv);
}

}  // namespace

// ==============================================================================================
// Session layer (ISO 8327-1) -- see mms.hpp's own "Session layer" section for the full byte
// layout. Cross-checked against Wireshark's packet-ses.h/.c (SPDU type numbers, PGI/PI parameter
// codes, and the specific real behavior that User_Data(193)/Extended_User_Data(194) are NEVER
// themselves further PGI/PI-structured -- their own content is simply the next layer's bytes --
// while Connection_Identifier(1)/Connect_Accept_Item(5)/Linking_Information(33) genuinely are
// nested parameter groups, confirmed via packet-ses.c's own dissect_parameters()).
namespace {

std::string session_pdu_name(uint8_t type) {
    switch (type) {
        case 1: return "DATA TRANSFER / GIVE TOKENS";
        case 2: return "PLEASE TOKENS (PT)";
        case 9: return "FINISH (FN)";
        case 10: return "DISCONNECT (DN)";
        case 12: return "REFUSE (RF)";
        case 13: return "CONNECT (CN)";
        case 14: return "ACCEPT (AC)";
        case 25: return "ABORT (AB)";
        case 26: return "ABORT ACCEPT (AA)";
        default: return "";
    }
}

// Recurses only into the genuine Parameter Group Indicator codes (1/5/33); captures the first
// User_Data(193)/Extended_User_Data(194) parameter's own raw content as `user_data` (the next
// layer's bytes) without recursing into it.
void walk_session_parameters(ByteSpan buf, std::optional<ByteSpan>& user_data, int depth) {
    if (depth > 6) return;
    size_t offset = 0;
    while (offset + 2 <= buf.size()) {
        uint8_t code = buf.at(offset);
        uint8_t len = buf.at(offset + 1);
        if (offset + 2 + len > buf.size()) break;  // trailing malformed parameter -- stop quietly
        ByteSpan content = buf.subspan(offset + 2, len);
        if (code == 193 || code == 194) {
            if (!user_data) user_data = content;
        } else if (code == 1 || code == 5 || code == 33) {
            walk_session_parameters(content, user_data, depth + 1);
        }
        offset += 2 + len;
    }
}

}  // namespace

// ==============================================================================================
// Presentation layer (ISO 8823) -- see mms.hpp's own "Presentation layer" section. Cross-checked
// byte-for-byte against Wireshark's packet-pres.c dissector tables (CP_type_set/CPA_PPDU_set,
// T_normal_mode_parameters_sequence, Context_list_item_sequence, PDV_list_sequence,
// Fully_encoded_data_sequence_of, T_presentation_data_values_choice).
namespace {

struct PresentationDecode {
    bool recognized = false;
    std::vector<std::string> context_list;
    bool has_context_id = false;
    int64_t context_id = 0;
    bool has_payload = false;
    ByteSpan payload;  // single-ASN1-type's own content -- ready for ACSE/MMS dispatch
    bool simply_encoded = false;
    ByteSpan simply_encoded_bytes;
};

void collect_context_list(ByteSpan content, std::vector<std::string>& out) {
    for (const auto& item : ber_children(content)) {
        auto fields = ber_children(item.content);
        if (fields.size() < 2) continue;
        int64_t ctx_id = ber_integer(fields[0].content);
        std::string oid = decode_oid(fields[1].content);
        out.push_back("context " + std::to_string(ctx_id) + " = " + oid_with_name(oid));
    }
}

struct PdvEntry {
    bool has_context_id = false;
    int64_t context_id = 0;
    bool has_payload = false;
    ByteSpan payload;
    bool simply_encoded = false;
    ByteSpan simply_encoded_bytes;
};

// Decodes one PDV-list element: {transfer-syntax-name OPTIONAL, presentation-context-identifier,
// presentation-data-values}. `tlv` is the whole PDV-list element TLV (a plain SEQUENCE, 0x30).
PdvEntry decode_pdv_list_entry(const BerTlv& tlv) {
    PdvEntry out;
    for (const auto& child : ber_children(tlv.content)) {
        if (ber_class(child.tag_byte) == kBerClassUniversal && !child.constructed && child.tag_number == 6) {
            continue;  // transfer-syntax-name OID, optional, not needed here
        }
        if (ber_class(child.tag_byte) == kBerClassUniversal && !child.constructed && child.tag_number == 2) {
            out.has_context_id = true;
            out.context_id = ber_integer(child.content);
            continue;
        }
        if (ber_class(child.tag_byte) == kBerClassContext && child.constructed && child.tag_number == 0) {
            // single-ASN1-type: EXPLICIT wrap (flags=0 in packet-pres.c) -- content IS the next
            // layer's own TLV bytes directly.
            out.has_payload = true;
            out.payload = child.content;
            continue;
        }
        if (ber_class(child.tag_byte) == kBerClassContext && child.tag_number == 1) {
            out.simply_encoded = true;
            out.simply_encoded_bytes = child.content;
        }
        // tag 2 (arbitrary, a BIT STRING) -- never observed in this decoder's own research, not
        // decoded.
    }
    return out;
}

void apply_pdv(const PdvEntry& pdv, PresentationDecode& out) {
    out.has_context_id = pdv.has_context_id;
    out.context_id = pdv.context_id;
    if (pdv.has_payload) {
        out.has_payload = true;
        out.payload = pdv.payload;
    } else if (pdv.simply_encoded) {
        out.simply_encoded = true;
        out.simply_encoded_bytes = pdv.simply_encoded_bytes;
    }
}

// Decodes `buf` as either a CP-type/CPA-type SET (association time) or a bare fully-encoded-data/
// simply-encoded-data User-data CHOICE (an ongoing Data-Transfer message -- see mms.hpp). Throws
// ParseError only for a malformed TLV; an unrecognized top-level shape returns `recognized=false`
// rather than throwing (this decoder's own structural gate already confirmed the SESSION layer,
// so a Presentation-layer shape it doesn't recognize is shown as "not decoded", not treated as a
// parse failure).
PresentationDecode decode_presentation(ByteSpan buf) {
    PresentationDecode out;
    if (buf.empty()) return out;
    BerTlv top = read_ber_tlv(buf);

    // CP-type/CPA-type: UNIVERSAL SET (tag 17), constructed.
    if (ber_class(top.tag_byte) == kBerClassUniversal && top.constructed && top.tag_number == 17) {
        out.recognized = true;
        for (const auto& field : ber_children(top.content)) {
            if (ber_class(field.tag_byte) != kBerClassContext || !field.constructed || field.tag_number != 2) {
                continue;  // only normal-mode-parameters (context 2) is implemented -- mode-
                           // selector/x410-mode-parameters are skipped, never observed in
                           // practice for IEC 61850 MMS traffic
            }
            for (const auto& sub : ber_children(field.content)) {
                if (ber_class(sub.tag_byte) == kBerClassContext && sub.constructed && sub.tag_number == 4) {
                    collect_context_list(sub.content, out.context_list);
                } else if (ber_class(sub.tag_byte) == kBerClassApplication && sub.constructed && sub.tag_number == 1) {
                    // user-data CHOICE, fully-encoded-data alternative -- own natural tag, no wrap
                    auto pdvs = ber_children(sub.content);
                    if (!pdvs.empty()) apply_pdv(decode_pdv_list_entry(pdvs[0]), out);
                } else if (ber_class(sub.tag_byte) == kBerClassApplication && !sub.constructed && sub.tag_number == 0) {
                    out.simply_encoded = true;
                    out.simply_encoded_bytes = sub.content;
                }
            }
        }
        return out;
    }

    // Bare fully-encoded-data (ongoing Data-Transfer message, no CP-type/CPA-type wrapper).
    if (ber_class(top.tag_byte) == kBerClassApplication && top.constructed && top.tag_number == 1) {
        out.recognized = true;
        auto pdvs = ber_children(top.content);
        if (!pdvs.empty()) apply_pdv(decode_pdv_list_entry(pdvs[0]), out);
        return out;
    }

    // Bare simply-encoded-data.
    if (ber_class(top.tag_byte) == kBerClassApplication && !top.constructed && top.tag_number == 0) {
        out.recognized = true;
        out.simply_encoded = true;
        out.simply_encoded_bytes = top.content;
        return out;
    }

    return out;
}

}  // namespace

// ==============================================================================================
// ACSE layer (ISO 8650-1) -- see mms.hpp's own "ACSE layer" section. Cross-checked against
// acse.asn (AARQ-apdu/AARE-apdu/RLRQ-apdu/RLRE-apdu/ABRT-apdu field numbers) -- every PDU type
// shares the SAME user-information tag (30), and result (AARE only) is EXPLICIT-tagged context 2.
namespace {

struct AcseDecode {
    bool recognized = false;
    std::string pdu_name;
    std::string application_context_name;
    bool has_result = false;
    std::string result_name;
    std::vector<std::string> values;
    bool has_user_information = false;
    ByteSpan user_information_payload;
};

std::string associate_result_name(int64_t v) {
    switch (v) {
        case 0: return "accepted";
        case 1: return "rejected-permanent";
        case 2: return "rejected-transient";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// Unwraps user-information's own Association-data (SEQUENCE OF EXTERNAL, IMPLICIT so no extra
// wrap over the SEQUENCE OF itself) down to the first EXTERNAL's own single-ASN1-type content --
// the actual next-layer (MMS) PDU bytes. Returns std::nullopt for any EXTERNAL alternative this
// decoder doesn't implement (octet-aligned/arbitrary -- never observed in practice).
std::optional<ByteSpan> unwrap_association_data(ByteSpan content) {
    auto externals = ber_children(content);
    if (externals.empty()) return std::nullopt;
    for (const auto& field : ber_children(externals[0].content)) {
        if (ber_class(field.tag_byte) == kBerClassContext && field.constructed && field.tag_number == 0) {
            return field.content;  // single-ASN1-type -- EXPLICIT wrap, content is the raw PDU bytes
        }
    }
    return std::nullopt;
}

AcseDecode decode_acse(const BerTlv& top) {
    AcseDecode out;
    switch (top.tag_number) {
        case 0: out.pdu_name = "AARQ"; break;
        case 1: out.pdu_name = "AARE"; break;
        case 2: out.pdu_name = "RLRQ"; break;
        case 3: out.pdu_name = "RLRE"; break;
        case 4: out.pdu_name = "ABRT"; break;
        default: return out;
    }
    out.recognized = true;
    for (const auto& field : ber_children(top.content)) {
        if (ber_class(field.tag_byte) != kBerClassContext) continue;
        if (field.tag_number == 1 && field.constructed && (top.tag_number == 0 || top.tag_number == 1)) {
            // aSO-context-name -- EXPLICIT wrap around an OBJECT IDENTIFIER (AARQ/AARE only).
            auto inner = ber_children(field.content);
            if (!inner.empty()) out.application_context_name = oid_with_name(decode_oid(inner[0].content));
        } else if (field.tag_number == 2 && field.constructed && top.tag_number == 1) {
            // result -- AARE only, EXPLICIT wrap around an INTEGER.
            auto inner = ber_children(field.content);
            if (!inner.empty()) {
                out.has_result = true;
                out.result_name = associate_result_name(ber_integer(inner[0].content));
            }
        } else if (field.tag_number == 30) {
            // user-information -- present on every PDU type, IMPLICIT Association-data.
            if (auto payload = unwrap_association_data(field.content)) {
                out.has_user_information = true;
                out.user_information_payload = *payload;
            }
        } else if (field.tag_number == 0 && !field.constructed && (top.tag_number == 2 || top.tag_number == 3)) {
            out.values.push_back("reason=" + std::to_string(ber_integer(field.content)));
        } else if (field.tag_number == 0 && !field.constructed && top.tag_number == 4) {
            out.values.push_back("abort-source=" + std::to_string(ber_integer(field.content)));
        } else if (field.tag_number == 1 && !field.constructed && top.tag_number == 4) {
            out.values.push_back("abort-diagnostic=" + std::to_string(ber_integer(field.content)));
        }
        // AP-title/AE-qualifier and every other optional field: structurally skipped -- see
        // mms.hpp's own "Deliberately NOT implemented" section.
    }
    return out;
}

}  // namespace

// ==============================================================================================
// MMS layer (ISO 9506-2) -- the payload this whole file exists to reach. See mms.hpp's own "MMS
// layer" section for the full MMSpdu tag table, the Tier1/Tier2 confirmed-service split, and the
// capability-negotiation bit tables below (cross-checked against mms.asn's own
// ParameterSupportOptions/ServiceSupportOptions BIT STRING definitions).
namespace {

// ConfirmedServiceRequest/Response CHOICE tags 0-77 -- see mms.hpp's own Tier1/Tier2 list.
constexpr const char* kConfirmedServiceNames[78] = {
    "status", "getNameList", "identify", "rename", "read", "write",
    "getVariableAccessAttributes", "defineNamedVariable", "defineScatteredAccess",
    "getScatteredAccessAttributes", "deleteVariableAccess", "defineNamedVariableList",
    "getNamedVariableListAttributes", "deleteNamedVariableList", "defineNamedType",
    "getNamedTypeAttributes", "deleteNamedType", "input", "output", "takeControl",
    "relinquishControl", "defineSemaphore", "deleteSemaphore", "reportSemaphoreStatus",
    "reportPoolSemaphoreStatus", "reportSemaphoreEntryStatus", "initiateDownloadSequence",
    "downloadSegment", "terminateDownloadSequence", "initiateUploadSequence", "uploadSegment",
    "terminateUploadSequence", "requestDomainDownload", "requestDomainUpload",
    "loadDomainContent", "storeDomainContent", "deleteDomain", "getDomainAttributes",
    "createProgramInvocation", "deleteProgramInvocation", "start", "stop", "resume", "reset",
    "kill", "getProgramInvocationAttributes", "obtainFile", "defineEventCondition",
    "deleteEventCondition", "getEventConditionAttributes", "reportEventConditionStatus",
    "alterEventConditionMonitoring", "triggerEvent", "defineEventAction", "deleteEventAction",
    "getEventActionAttributes", "reportEventActionStatus", "defineEventEnrollment",
    "deleteEventEnrollment", "alterEventEnrollment", "reportEventEnrollmentStatus",
    "getEventEnrollmentAttributes", "acknowledgeEventNotification", "getAlarmSummary",
    "getAlarmEnrollmentSummary", "readJournal", "writeJournal", "initializeJournal",
    "reportJournalStatus", "createJournal", "deleteJournal", "getCapabilityList", "fileOpen",
    "fileRead", "fileClose", "fileRename", "fileDelete", "fileDirectory",
};

const char* confirmed_service_name(uint32_t tag) {
    return (tag < 78) ? kConfirmedServiceNames[tag] : nullptr;
}

// ServiceSupportOptions BIT STRING names, bits 0-84 -- its own naming occasionally differs
// slightly from ConfirmedServiceRequest's own field names above (e.g. bit 56
// "reportActionStatus" vs. the CHOICE field "reportEventActionStatus") -- both spellings are
// mms.asn's own, not a bug in this decoder.
constexpr const char* kServiceSupportOptionNames[85] = {
    "status", "getNameList", "identify", "rename", "read", "write",
    "getVariableAccessAttributes", "defineNamedVariable", "defineScatteredAccess",
    "getScatteredAccessAttributes", "deleteVariableAccess", "defineNamedVariableList",
    "getNamedVariableListAttributes", "deleteNamedVariableList", "defineNamedType",
    "getNamedTypeAttributes", "deleteNamedType", "input", "output", "takeControl",
    "relinquishControl", "defineSemaphore", "deleteSemaphore", "reportSemaphoreStatus",
    "reportPoolSemaphoreStatus", "reportSemaphoreEntryStatus", "initiateDownloadSequence",
    "downloadSegment", "terminateDownloadSequence", "initiateUploadSequence", "uploadSegment",
    "terminateUploadSequence", "requestDomainDownload", "requestDomainUpload",
    "loadDomainContent", "storeDomainContent", "deleteDomain", "getDomainAttributes",
    "createProgramInvocation", "deleteProgramInvocation", "start", "stop", "resume", "reset",
    "kill", "getProgramInvocationAttributes", "obtainFile", "defineEventCondition",
    "deleteEventCondition", "getEventConditionAttributes", "reportEventConditionStatus",
    "alterEventConditionMonitoring", "triggerEvent", "defineEventAction", "deleteEventAction",
    "getEventActionAttributes", "reportActionStatus", "defineEventEnrollment",
    "deleteEventEnrollment", "alterEventEnrollment", "reportEventEnrollmentStatus",
    "getEventEnrollmentAttributes", "acknowledgeEventNotification", "getAlarmSummary",
    "getAlarmEnrollmentSummary", "readJournal", "writeJournal", "initializeJournal",
    "reportJournalStatus", "createJournal", "deleteJournal", "getCapabilityList", "fileOpen",
    "fileRead", "fileClose", "fileRename", "fileDelete", "fileDirectory", "unsolicitedStatus",
    "informationReport", "eventNotification", "attachToEventCondition", "attachToSemaphore",
    "conclude", "cancel",
};

struct BitName {
    int index;
    const char* name;
};

// ParameterSupportOptions -- note index 9 is unused/undefined in mms.asn itself.
constexpr BitName kParameterSupportOptionNames[] = {
    {0, "str1"}, {1, "str2"}, {2, "vnam"}, {3, "valt"}, {4, "vadr"},
    {5, "vsca"}, {6, "tpy"}, {7, "vlis"}, {8, "real"}, {10, "cei"},
};

std::string bitstring_names(ByteSpan content, const BitName* table, size_t table_len) {
    std::vector<std::string> names;
    for (int bit : bitstring_set_bits(content)) {
        const char* found = nullptr;
        for (size_t i = 0; i < table_len; ++i) {
            if (table[i].index == bit) {
                found = table[i].name;
                break;
            }
        }
        names.push_back(found ? found : ("bit" + std::to_string(bit)));
    }
    std::ostringstream s;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) s << ",";
        s << names[i];
    }
    return s.str();
}

std::string service_support_names(ByteSpan content) {
    std::vector<std::string> names;
    for (int bit : bitstring_set_bits(content)) {
        names.push_back((bit >= 0 && bit < 85) ? kServiceSupportOptionNames[bit]
                                                 : ("bit" + std::to_string(bit)));
    }
    std::ostringstream s;
    for (size_t i = 0; i < names.size(); ++i) {
        if (i) s << ",";
        s << names[i];
    }
    return s.str();
}

// ---- Initiate-RequestPDU/ResponsePDU -- identical field layout for both, see mms.hpp.
void decode_initiate(const BerTlv& top, bool is_response, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = is_response ? "initiate-ResponsePDU" : "initiate-RequestPDU";
    frame.is_response = is_response;
    for (const auto& field : ber_children(top.content)) {
        if (ber_class(field.tag_byte) != kBerClassContext) continue;
        switch (field.tag_number) {
            case 0:
                frame.values.push_back((is_response ? "localDetailCalled=" : "localDetailCalling=") +
                                        std::to_string(ber_integer(field.content)));
                break;
            case 1:
                frame.values.push_back((is_response ? "negotiatedMaxServOutstandingCalling="
                                                     : "proposedMaxServOutstandingCalling=") +
                                        std::to_string(ber_unsigned(field.content)));
                break;
            case 2:
                frame.values.push_back((is_response ? "negotiatedMaxServOutstandingCalled="
                                                     : "proposedMaxServOutstandingCalled=") +
                                        std::to_string(ber_unsigned(field.content)));
                break;
            case 3:
                frame.values.push_back((is_response ? "negotiatedDataStructureNestingLevel="
                                                     : "proposedDataStructureNestingLevel=") +
                                        std::to_string(ber_unsigned(field.content)));
                break;
            case 4:
                for (const auto& sub : ber_children(field.content)) {
                    if (ber_class(sub.tag_byte) != kBerClassContext) continue;
                    switch (sub.tag_number) {
                        case 0:
                            frame.values.push_back(
                                (is_response ? "negotiatedVersionNumber=" : "proposedVersionNumber=") +
                                std::to_string(ber_unsigned(sub.content)));
                            break;
                        case 1:
                            frame.values.push_back(
                                "parameterCBB=[" +
                                bitstring_names(sub.content, kParameterSupportOptionNames,
                                                sizeof(kParameterSupportOptionNames) / sizeof(BitName)) +
                                "]");
                            break;
                        case 2:
                            frame.values.push_back("servicesSupported=[" + service_support_names(sub.content) +
                                                    "]");
                            break;
                        default:
                            break;
                    }
                }
                break;
            default:
                break;
        }
    }
    frame.service_body_decoded = true;
}

// ---- Small VisibleString-list rendering helper shared by several Tier1 decoders below.
std::string join_visible_strings(ByteSpan seq_of_content) {
    std::vector<std::string> items;
    for (const auto& c : ber_children(seq_of_content)) items.push_back(ber_visible_string(c.content));
    std::ostringstream s;
    for (size_t i = 0; i < items.size(); ++i) {
        if (i) s << ",";
        s << items[i];
    }
    return s.str();
}

// ---- Tier 1 confirmed-service field decoders. `body` is the ConfirmedServiceRequest/Response
// CHOICE's own chosen alternative TLV (already at its own context tag 0-77).

void decode_status_request(const BerTlv& body, MmsFrame& frame) {
    bool toggle = !body.content.empty() && body.content.at(0) != 0;
    frame.values.push_back(std::string("togglePeripheralData=") + (toggle ? "true" : "false"));
}

void decode_status_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("vmdLogicalStatus=" + std::to_string(ber_integer(f.content)));
        else if (f.tag_number == 1)
            frame.values.push_back("vmdPhysicalStatus=" + std::to_string(ber_integer(f.content)));
    }
}

void decode_getnamelist_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 1) {  // objectScope -- EXPLICIT wrap around the ObjectScope CHOICE
            auto inner = ber_children(f.content);
            if (!inner.empty()) {
                const auto& scope = inner[0];
                if (scope.tag_number == 0) frame.values.push_back("objectScope=vmd");
                else if (scope.tag_number == 1)
                    frame.values.push_back("objectScope=domain:" + ber_visible_string(scope.content));
                else if (scope.tag_number == 2)
                    frame.values.push_back("objectScope=aa");
            }
        } else if (f.tag_number == 2) {
            frame.values.push_back("continueAfter=" + ber_visible_string(f.content));
        }
    }
}

void decode_getnamelist_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0)
            frame.values.push_back("listOfIdentifier=[" + join_visible_strings(f.content) + "]");
        else if (f.tag_number == 1)
            frame.values.push_back(std::string("moreFollows=") + (ber_integer(f.content) != 0 ? "true" : "false"));
    }
}

void decode_identify_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("vendorName=" + ber_visible_string(f.content));
        else if (f.tag_number == 1) frame.values.push_back("modelName=" + ber_visible_string(f.content));
        else if (f.tag_number == 2) frame.values.push_back("revision=" + ber_visible_string(f.content));
        else if (f.tag_number == 3) {
            std::vector<std::string> oids;
            for (const auto& o : ber_children(f.content)) oids.push_back(oid_with_name(decode_oid(o.content)));
            std::ostringstream s;
            for (size_t i = 0; i < oids.size(); ++i) {
                if (i) s << ",";
                s << oids[i];
            }
            frame.values.push_back("listOfAbstractSyntaxes=[" + s.str() + "]");
        }
    }
}

void decode_read_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            frame.values.push_back(std::string("specificationWithResult=") +
                                    (ber_integer(f.content) != 0 ? "true" : "false"));
        } else if (f.tag_number == 1) {  // variableAccessSpecification -- EXPLICIT wrap (flags != NOOWNTAG)
            auto inner = ber_children(f.content);
            if (!inner.empty())
                for (auto& v : decode_variable_access_specification(inner[0])) frame.values.push_back("variable=" + v);
        }
    }
}

void decode_read_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {  // variableAccessSpecification -- EXPLICIT wrap, optional
            auto inner = ber_children(f.content);
            if (!inner.empty())
                for (auto& v : decode_variable_access_specification(inner[0])) frame.values.push_back("variable=" + v);
        } else if (f.tag_number == 1) {  // listOfAccessResult -- IMPLICIT SEQUENCE OF, no extra wrap
            int idx = 0;
            for (const auto& r : ber_children(f.content))
                frame.values.push_back("result[" + std::to_string(idx++) + "]=" + decode_access_result(r));
        }
    }
}

void decode_write_request(const BerTlv& body, MmsFrame& frame) {
    auto children = ber_children(body.content);
    if (children.empty()) return;
    for (auto& v : decode_variable_access_specification(children[0])) frame.values.push_back("variable=" + v);
    if (children.size() > 1) {
        int idx = 0;
        for (const auto& d : ber_children(children[1].content))
            frame.values.push_back("value[" + std::to_string(idx++) + "]=" + decode_data_value(d, 0));
    }
}

void decode_write_response(const BerTlv& body, MmsFrame& frame) {
    int idx = 0;
    for (const auto& item : ber_children(body.content)) {
        if (ber_class(item.tag_byte) == kBerClassContext && item.tag_number == 0) {
            frame.values.push_back("result[" + std::to_string(idx) +
                                    "]=failure(DataAccessError " + std::to_string(ber_integer(item.content)) + ")");
        } else {
            frame.values.push_back("result[" + std::to_string(idx) + "]=success");
        }
        idx++;
    }
}

void decode_getvariableaccessattributes_request(const BerTlv& body, MmsFrame& frame) {
    auto inner = ber_children(body.content);
    if (inner.empty()) return;
    const auto& choice = inner[0];
    if (choice.tag_number == 0) frame.values.push_back("name=" + decode_object_name_flexible(choice));
    else if (choice.tag_number == 1) frame.values.push_back("address=<Address, not decoded>");
}

void decode_getvariableaccessattributes_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0)
            frame.values.push_back(std::string("mmsDeletable=") + (ber_integer(f.content) != 0 ? "true" : "false"));
        else if (f.tag_number == 2)
            frame.values.push_back("typeSpecification=<TypeSpecification, not decoded>");
    }
}

void decode_definenamedvariablelist_request(const BerTlv& body, MmsFrame& frame) {
    auto children = ber_children(body.content);
    if (children.empty()) return;
    frame.values.push_back("variableListName=" + decode_object_name_flexible(children[0]));
    if (children.size() > 1) {
        int idx = 0;
        for (const auto& entry : ber_children(children[1].content)) {
            auto fields = ber_children(entry.content);
            if (!fields.empty())
                frame.values.push_back("member[" + std::to_string(idx++) + "]=" + decode_variable_specification(fields[0]));
        }
    }
}

void decode_definenamedvariablelist_response(MmsFrame& frame) {
    frame.values.push_back("result=success");  // DefineNamedVariableList-Response ::= NULL
}

void decode_getnamedvariablelistattributes_request(const BerTlv& body, MmsFrame& frame) {
    frame.values.push_back("variableListName=" + decode_object_name_flexible(body));
}

void decode_getnamedvariablelistattributes_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            frame.values.push_back(std::string("mmsDeletable=") + (ber_integer(f.content) != 0 ? "true" : "false"));
        } else if (f.tag_number == 1) {
            int idx = 0;
            for (const auto& entry : ber_children(f.content)) {
                auto fields = ber_children(entry.content);
                if (!fields.empty())
                    frame.values.push_back("member[" + std::to_string(idx++) +
                                            "]=" + decode_variable_specification(fields[0]));
            }
        }
    }
}

void decode_deletenamedvariablelist_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("scopeOfDelete=" + std::to_string(ber_integer(f.content)));
        else if (f.tag_number == 1) {
            int idx = 0;
            for (const auto& n : ber_children(f.content))
                frame.values.push_back("listOfVariableListName[" + std::to_string(idx++) +
                                        "]=" + decode_object_name_flexible(n));
        } else if (f.tag_number == 2) {
            frame.values.push_back("domainName=" + ber_visible_string(f.content));
        }
    }
}

void decode_deletenamedvariablelist_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("numberMatched=" + std::to_string(ber_unsigned(f.content)));
        else if (f.tag_number == 1) frame.values.push_back("numberDeleted=" + std::to_string(ber_unsigned(f.content)));
    }
}

void decode_getcapabilitylist_request(const BerTlv& body, MmsFrame& frame) {
    auto children = ber_children(body.content);
    if (!children.empty()) frame.values.push_back("continueAfter=" + ber_visible_string(children[0].content));
}

void decode_getcapabilitylist_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0)
            frame.values.push_back("listOfCapabilities=[" + join_visible_strings(f.content) + "]");
        else if (f.tag_number == 1)
            frame.values.push_back(std::string("moreFollows=") + (ber_integer(f.content) != 0 ? "true" : "false"));
    }
}

void decode_getdomainattributes_request(const BerTlv& body, MmsFrame& frame) {
    frame.values.push_back("domainName=" + ber_visible_string(body.content));
}

void decode_getdomainattributes_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 0:
                frame.values.push_back("listOfCapabilities=[" + join_visible_strings(f.content) + "]");
                break;
            case 1:
                frame.values.push_back("state=" + std::to_string(ber_integer(f.content)));
                break;
            case 2:
                frame.values.push_back(std::string("mmsDeletable=") +
                                        (ber_integer(f.content) != 0 ? "true" : "false"));
                break;
            case 3:
                frame.values.push_back(std::string("sharable=") + (ber_integer(f.content) != 0 ? "true" : "false"));
                break;
            case 4:
                frame.values.push_back("listOfProgramInvocations=[" + join_visible_strings(f.content) + "]");
                break;
            case 5:
                frame.values.push_back("uploadInProgress=" + std::to_string(ber_integer(f.content)));
                break;
            default:
                break;
        }
    }
}

// ---- File-transfer services (ISO 9506-2's own "FILES" section, mms.asn's ObtainFile-Request
// through FileDirectory-Response) -- promoted from Tier 2 to Tier 1 as the most OT-security-
// relevant of this decoder's previously-undecoded confirmed services: IEC 61850's own COMTRADE/
// disturbance-file-retrieval workflow, and firmware/configuration-file transfer more broadly,
// rides on exactly these seven services (obtainFile, fileOpen, fileRead, fileClose, fileRename,
// fileDelete, fileDirectory) -- see ROADMAP in docs/MANUAL.md. Every field's IMPLICIT/EXPLICIT
// tagging below was read directly off mms.asn's own text (this module declares no module-level
// AUTOMATIC/IMPLICIT TAGS, so a field with no explicit "IMPLICIT" keyword is EXPLICIT-tagged --
// an extra wrapper TLV around the field's own universal-tagged encoding -- the same convention
// already established by this file's own Read-Request/Read-Response decoders, e.g.
// variableAccessSpecification's own "EXPLICIT wrap" comment above); FileDirectory-Response's own
// listOfDirectoryEntry is the one EXPLICIT-tagged field in this whole section (every other field
// here is IMPLICIT).

// FileName ::= SEQUENCE OF GraphicString -- rendered joined by "/", the same convention
// Wireshark's own packet-mms.c dissect_mms_FileName uses for a real filesystem-style path.
// GraphicString content is treated identically to VisibleString/MMSString elsewhere in this file
// (raw content bytes, no ISO 2022 character-set-escape interpretation -- the same "hand-roll the
// specific subset actually needed" posture this decoder already takes for every other string
// type).
std::string decode_file_name(ByteSpan seq_of_content) {
    std::vector<std::string> parts;
    for (const auto& c : ber_children(seq_of_content)) parts.push_back(ber_visible_string(c.content));
    std::ostringstream s;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i) s << "/";
        s << parts[i];
    }
    return s.str();
}

// GeneralizedTime (ASN.1 UNIVERSAL 24) -- an ASCII text timestamp "YYYYMMDDHHMMSS[.fraction][Z]"
// (X.690 imposes further restrictions for strict DER, but this decoder accepts the more general
// BER form and reformats it to this codebase's own ISO-8601 convention, matching format_utc_time
// above, whenever it matches the expected 14-digit shape; anything else is shown verbatim rather
// than guessed at). Used only by FileAttributes' own lastModified field below.
std::string format_generalized_time(ByteSpan content) {
    std::string raw(reinterpret_cast<const char*>(content.data()), content.size());
    if (raw.size() < 14) return raw;
    for (int i = 0; i < 14; ++i) {
        if (raw[static_cast<size_t>(i)] < '0' || raw[static_cast<size_t>(i)] > '9') return raw;
    }
    std::string frac;
    size_t pos = 14;
    if (pos < raw.size() && (raw[pos] == '.' || raw[pos] == ',')) {
        size_t start = pos + 1;
        size_t end = start;
        while (end < raw.size() && raw[end] >= '0' && raw[end] <= '9') end++;
        frac = raw.substr(start, end - start);
        pos = end;
    }
    std::string zone = raw.substr(pos);  // "Z", "+HHMM", "-HHMM", or empty (local time -- rare and
                                           // non-conformant in practice, shown verbatim either way)
    std::ostringstream s;
    s << raw.substr(0, 4) << "-" << raw.substr(4, 2) << "-" << raw.substr(6, 2) << "T" << raw.substr(8, 2)
      << ":" << raw.substr(10, 2) << ":" << raw.substr(12, 2);
    if (!frac.empty()) s << "." << frac;
    s << zone;
    return s.str();
}

// FileAttributes ::= SEQUENCE { sizeOfFile [0] IMPLICIT Unsigned32, lastModified [1] IMPLICIT
// GeneralizedTime OPTIONAL } -- shared by FileOpen-Response and DirectoryEntry below.
std::string decode_file_attributes(ByteSpan content) {
    std::string size_str = "?";
    std::string modified_str;
    bool has_modified = false;
    for (const auto& f : ber_children(content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            size_str = std::to_string(ber_unsigned(f.content));
        } else if (f.tag_number == 1) {
            modified_str = format_generalized_time(f.content);
            has_modified = true;
        }
    }
    std::ostringstream s;
    s << "{sizeOfFile=" << size_str;
    if (has_modified) s << ", lastModified=" << modified_str;
    s << "}";
    return s.str();
}

// ObtainFile-Request ::= SEQUENCE { sourceFileServer [0] IMPLICIT ApplicationReference OPTIONAL,
// sourceFile [1] IMPLICIT FileName, destinationFile [2] IMPLICIT FileName }. sourceFileServer is
// an ApplicationReference (AP-title/AE-qualifier/invocation-ids, every field itself OPTIONAL) --
// structurally recognized but not deep-decoded, the same posture this file's own ACSE AARQ/AARE
// decode already takes for AP-title/AE-qualifier elsewhere (see mms.hpp's "Deliberately NOT
// implemented" section). ObtainFile-Response ::= NULL, nothing to decode.
void decode_obtainfile_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("sourceFileServer=<ApplicationReference, not decoded>");
        else if (f.tag_number == 1) frame.values.push_back("sourceFile=" + decode_file_name(f.content));
        else if (f.tag_number == 2) frame.values.push_back("destinationFile=" + decode_file_name(f.content));
    }
}

// FileOpen-Request ::= SEQUENCE { fileName [0] IMPLICIT FileName, initialPosition [1] IMPLICIT
// Unsigned32 }.
void decode_fileopen_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("fileName=" + decode_file_name(f.content));
        else if (f.tag_number == 1) frame.values.push_back("initialPosition=" + std::to_string(ber_unsigned(f.content)));
    }
}

// FileOpen-Response ::= SEQUENCE { frsmID [0] IMPLICIT Integer32, fileAttributes [1] IMPLICIT
// FileAttributes } -- frsmID (File Read/write State Machine ID) is the handle every later
// fileRead/fileClose on this file uses.
void decode_fileopen_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("frsmID=" + std::to_string(ber_integer(f.content)));
        else if (f.tag_number == 1) frame.values.push_back("fileAttributes=" + decode_file_attributes(f.content));
    }
}

// FileRead-Request ::= Integer32 -- a bare primitive alternative (IMPLICIT at the
// ConfirmedServiceRequest CHOICE level), so `body.content` IS the frsmID's own integer bytes
// directly, the same shape as cancel-RequestPDU's own bare Unsigned32 elsewhere in this file.
void decode_fileread_request(const BerTlv& body, MmsFrame& frame) {
    frame.values.push_back("frsmID=" + std::to_string(ber_integer(body.content)));
}

// FileRead-Response ::= SEQUENCE { fileData [0] IMPLICIT OCTET STRING, moreFollows [1] IMPLICIT
// BOOLEAN DEFAULT TRUE }.
void decode_fileread_response(const BerTlv& body, MmsFrame& frame) {
    bool more_follows = true;  // ASN.1 DEFAULT TRUE -- absent on the wire means "more data follows"
    size_t data_len = 0;
    std::string data_hex;
    bool has_data = false;
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            has_data = true;
            data_len = f.content.size();
            data_hex = hex_of(f.content);
        } else if (f.tag_number == 1) {
            more_follows = ber_integer(f.content) != 0;
        }
    }
    if (has_data) frame.values.push_back("fileData=" + std::to_string(data_len) + " byte(s): " + data_hex);
    frame.values.push_back(std::string("moreFollows=") + (more_follows ? "true" : "false"));
}

// FileClose-Request ::= Integer32 -- same bare-primitive shape as FileRead-Request above.
void decode_fileclose_request(const BerTlv& body, MmsFrame& frame) {
    frame.values.push_back("frsmID=" + std::to_string(ber_integer(body.content)));
}
// FileClose-Response ::= NULL, nothing to decode.

// FileRename-Request ::= SEQUENCE { currentFileName [0] IMPLICIT FileName, newFileName [1]
// IMPLICIT FileName }.
void decode_filerename_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("currentFileName=" + decode_file_name(f.content));
        else if (f.tag_number == 1) frame.values.push_back("newFileName=" + decode_file_name(f.content));
    }
}
// FileRename-Response ::= NULL, nothing to decode.

// FileDelete-Request ::= FileName -- a bare (IMPLICIT-at-the-CHOICE-level) FileName, so
// `body.content` IS the SEQUENCE OF GraphicString content directly (constructed, unlike
// FileRead/FileClose's bare-INTEGER shape above, since FileName's own underlying type is
// constructed).
void decode_filedelete_request(const BerTlv& body, MmsFrame& frame) {
    frame.values.push_back("fileName=" + decode_file_name(body.content));
}
// FileDelete-Response ::= NULL, nothing to decode.

// FileDirectory-Request ::= SEQUENCE { fileSpecification [0] IMPLICIT FileName OPTIONAL,
// continueAfter [1] IMPLICIT FileName OPTIONAL }.
void decode_filedirectory_request(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) frame.values.push_back("fileSpecification=" + decode_file_name(f.content));
        else if (f.tag_number == 1) frame.values.push_back("continueAfter=" + decode_file_name(f.content));
    }
}

// FileDirectory-Response ::= SEQUENCE { listOfDirectoryEntry [0] SEQUENCE OF DirectoryEntry
// (EXPLICIT -- no IMPLICIT keyword in the ASN.1, see this section's own header comment),
// moreFollows [1] IMPLICIT BOOLEAN DEFAULT FALSE }. DirectoryEntry ::= SEQUENCE { filename [0]
// IMPLICIT FileName, fileAttributes [1] IMPLICIT FileAttributes }.
void decode_filedirectory_response(const BerTlv& body, MmsFrame& frame) {
    for (const auto& f : ber_children(body.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            auto inner = ber_children(f.content);  // EXPLICIT wrap around SEQUENCE OF DirectoryEntry
            if (inner.empty()) continue;
            int idx = 0;
            for (const auto& entry : ber_children(inner[0].content)) {
                std::string filename, attrs;
                for (const auto& ef : ber_children(entry.content)) {
                    if (ber_class(ef.tag_byte) != kBerClassContext) continue;
                    if (ef.tag_number == 0) filename = decode_file_name(ef.content);
                    else if (ef.tag_number == 1) attrs = decode_file_attributes(ef.content);
                }
                frame.values.push_back("listOfDirectoryEntry[" + std::to_string(idx++) + "]=" + filename +
                                        " " + attrs);
            }
        } else if (f.tag_number == 1) {
            frame.values.push_back(std::string("moreFollows=") + (ber_integer(f.content) != 0 ? "true" : "false"));
        }
    }
}

// ---- InformationReport (unconfirmed-PDU's own [0] alternative) -- the MMS analog of this
// codebase's own GOOSE decoder, see mms.hpp.
void decode_information_report(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "unconfirmed-PDU (informationReport)";
    frame.service_recognized = true;
    frame.service_name = "informationReport";
    auto children = ber_children(top.content);
    if (!children.empty()) {
        for (auto& v : decode_variable_access_specification(children[0])) frame.values.push_back("variable=" + v);
        if (children.size() > 1) {
            int idx = 0;
            for (const auto& r : ber_children(children[1].content))
                frame.values.push_back("result[" + std::to_string(idx++) + "]=" + decode_access_result(r));
        }
    }
    frame.service_body_decoded = true;
}

void decode_unconfirmed_pdu(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    auto children = ber_children(top.content);
    if (children.empty()) {
        frame.pdu_name = "unconfirmed-PDU";
        return;
    }
    const BerTlv& svc = children[0];
    if (ber_class(svc.tag_byte) == kBerClassContext && svc.tag_number == 0) {
        decode_information_report(svc, frame);
    } else if (ber_class(svc.tag_byte) == kBerClassContext && svc.tag_number == 1) {
        frame.pdu_name = "unconfirmed-PDU (unsolicitedStatus)";
        frame.service_recognized = true;
        frame.service_name = "unsolicitedStatus";
        decode_status_response(svc, frame);
        frame.service_body_decoded = true;
    } else {
        frame.pdu_name = "unconfirmed-PDU";
        if (ber_class(svc.tag_byte) == kBerClassContext && svc.tag_number == 2) {
            frame.service_recognized = true;
            frame.service_name = "eventNotification";
        }
        frame.body_shown_as_hex = true;
        frame.body_hex = hex_of(svc.content);
        frame.body_length = svc.content.size();
    }
}

// ---- ServiceError (confirmed-ErrorPDU/cancel-ErrorPDU/conclude-ErrorPDU/initiate-ErrorPDU).
std::string errorclass_category_name(int idx) {
    static const char* names[] = {"vmd-state",     "application-reference", "definition",
                                   "resource",      "service",               "service-preempt",
                                   "time-resolution", "access",              "initiate",
                                   "conclude",      "cancel",                "file",
                                   "others"};
    if (idx >= 0 && idx < 13) return names[idx];
    return "unknown";
}

std::string decode_service_error(const BerTlv& seq, std::vector<std::string>* extra_notes) {
    std::string error_name;
    for (const auto& f : ber_children(seq.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {  // errorClass -- EXPLICIT wrap around the category CHOICE
            auto inner = ber_children(f.content);
            if (!inner.empty()) {
                error_name = errorclass_category_name(static_cast<int>(inner[0].tag_number)) + "(" +
                             std::to_string(ber_integer(inner[0].content)) + ")";
            }
        } else if (f.tag_number == 1 && extra_notes) {
            extra_notes->push_back("additionalCode=" + std::to_string(ber_integer(f.content)));
        } else if (f.tag_number == 2 && extra_notes) {
            extra_notes->push_back("additionalDescription=" + ber_visible_string(f.content));
        }
    }
    return error_name;
}

// ---- RejectPDU.
std::string reject_reason_category_name(int idx) {
    static const char* names[] = {"",
                                   "confirmed-requestPDU",
                                   "confirmed-responsePDU",
                                   "confirmed-errorPDU",
                                   "unconfirmedPDU",
                                   "pdu-error",
                                   "cancel-requestPDU",
                                   "cancel-responsePDU",
                                   "cancel-errorPDU",
                                   "conclude-requestPDU",
                                   "conclude-responsePDU",
                                   "conclude-errorPDU"};
    if (idx >= 1 && idx <= 11) return names[idx];
    return "unknown";
}

void decode_reject_pdu(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "rejectPDU";
    for (const auto& f : ber_children(top.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0 && !f.constructed) {
            frame.has_invoke_id = true;
            frame.invoke_id = static_cast<uint32_t>(ber_unsigned(f.content));
        } else if (!f.constructed) {
            frame.values.push_back("rejectReason=" + reject_reason_category_name(static_cast<int>(f.tag_number)) +
                                    "(" + std::to_string(ber_integer(f.content)) + ")");
        }
    }
    frame.service_body_decoded = true;
}

// ---- Cancel-*/Conclude-* PDUs.
void decode_cancel_request(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "cancel-RequestPDU";
    frame.has_invoke_id = true;
    frame.invoke_id = static_cast<uint32_t>(ber_unsigned(top.content));
    frame.values.push_back("originalInvokeID=" + std::to_string(frame.invoke_id));
    frame.service_body_decoded = true;
}

void decode_cancel_response(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "cancel-ResponsePDU";
    frame.is_response = true;
    frame.has_invoke_id = true;
    frame.invoke_id = static_cast<uint32_t>(ber_unsigned(top.content));
    frame.values.push_back("originalInvokeID=" + std::to_string(frame.invoke_id));
    frame.service_body_decoded = true;
}

void decode_cancel_error(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "cancel-ErrorPDU";
    frame.is_response = true;
    for (const auto& f : ber_children(top.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            frame.has_invoke_id = true;
            frame.invoke_id = static_cast<uint32_t>(ber_unsigned(f.content));
        } else if (f.tag_number == 1) {
            frame.has_error = true;
            frame.error_name = decode_service_error(f, &frame.notes);
        }
    }
    frame.service_body_decoded = true;
}

void decode_conclude_request(MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "conclude-RequestPDU";
    frame.service_body_decoded = true;
}

void decode_conclude_response(MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "conclude-ResponsePDU";
    frame.is_response = true;
    frame.service_body_decoded = true;
}

void decode_conclude_error(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "conclude-ErrorPDU";
    frame.is_response = true;
    frame.has_error = true;
    frame.error_name = decode_service_error(top, &frame.notes);
    frame.service_body_decoded = true;
}

void decode_confirmed_error(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "confirmed-ErrorPDU";
    frame.is_response = true;
    for (const auto& f : ber_children(top.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 0) {
            frame.has_invoke_id = true;
            frame.invoke_id = static_cast<uint32_t>(ber_unsigned(f.content));
        } else if (f.tag_number == 1) {
            frame.values.push_back("modifierPosition=" + std::to_string(ber_unsigned(f.content)));
        } else if (f.tag_number == 2) {
            frame.has_error = true;
            frame.error_name = decode_service_error(f, &frame.notes);
        }
    }
    frame.service_body_decoded = true;
}

void decode_initiate_error(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "initiate-ErrorPDU";
    frame.is_response = true;
    frame.has_error = true;
    frame.error_name = decode_service_error(top, &frame.notes);
    frame.service_body_decoded = true;
}

// ---- ConfirmedServiceRequest/Response dispatch -- Tier 1 (full decode) vs. Tier 2 (name +
// invokeID only, body shown as hex) -- see mms.hpp's own Tier1/Tier2 list.
void dispatch_confirmed_service(const BerTlv& svc, MmsFrame& frame, bool is_response) {
    if (ber_class(svc.tag_byte) != kBerClassContext) return;
    uint32_t tag = svc.tag_number;
    const char* name = confirmed_service_name(tag);
    if (!name) {
        frame.body_shown_as_hex = true;
        frame.body_hex = hex_of(svc.content);
        frame.body_length = svc.content.size();
        return;
    }
    frame.service_recognized = true;
    frame.service_name = name;
    bool decoded = true;
    if (!is_response) {
        switch (tag) {
            case 0: decode_status_request(svc, frame); break;
            case 1: decode_getnamelist_request(svc, frame); break;
            case 2: break;  // identify-Request ::= NULL -- nothing to decode
            case 4: decode_read_request(svc, frame); break;
            case 5: decode_write_request(svc, frame); break;
            case 6: decode_getvariableaccessattributes_request(svc, frame); break;
            case 11: decode_definenamedvariablelist_request(svc, frame); break;
            case 12: decode_getnamedvariablelistattributes_request(svc, frame); break;
            case 13: decode_deletenamedvariablelist_request(svc, frame); break;
            case 37: decode_getdomainattributes_request(svc, frame); break;
            case 46: decode_obtainfile_request(svc, frame); break;
            case 71: decode_getcapabilitylist_request(svc, frame); break;
            case 72: decode_fileopen_request(svc, frame); break;
            case 73: decode_fileread_request(svc, frame); break;
            case 74: decode_fileclose_request(svc, frame); break;
            case 75: decode_filerename_request(svc, frame); break;
            case 76: decode_filedelete_request(svc, frame); break;
            case 77: decode_filedirectory_request(svc, frame); break;
            default: decoded = false; break;
        }
    } else {
        switch (tag) {
            case 0: decode_status_response(svc, frame); break;
            case 1: decode_getnamelist_response(svc, frame); break;
            case 2: decode_identify_response(svc, frame); break;
            case 4: decode_read_response(svc, frame); break;
            case 5: decode_write_response(svc, frame); break;
            case 6: decode_getvariableaccessattributes_response(svc, frame); break;
            case 11: decode_definenamedvariablelist_response(frame); break;
            case 12: decode_getnamedvariablelistattributes_response(svc, frame); break;
            case 13: decode_deletenamedvariablelist_response(svc, frame); break;
            case 37: decode_getdomainattributes_response(svc, frame); break;
            case 46: break;  // ObtainFile-Response ::= NULL -- nothing to decode
            case 71: decode_getcapabilitylist_response(svc, frame); break;
            case 72: decode_fileopen_response(svc, frame); break;
            case 73: decode_fileread_response(svc, frame); break;
            case 74: break;  // FileClose-Response ::= NULL -- nothing to decode
            case 75: break;  // FileRename-Response ::= NULL -- nothing to decode
            case 76: break;  // FileDelete-Response ::= NULL -- nothing to decode
            case 77: decode_filedirectory_response(svc, frame); break;
            default: decoded = false; break;
        }
    }
    if (decoded) {
        frame.service_body_decoded = true;
    } else {
        frame.body_shown_as_hex = true;
        frame.body_hex = hex_of(svc.content);
        frame.body_length = svc.content.size();
    }
}

void decode_confirmed_request(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "confirmed-RequestPDU";
    auto children = ber_children(top.content);
    size_t idx = 0;
    if (idx < children.size() && ber_class(children[idx].tag_byte) == kBerClassUniversal &&
        children[idx].tag_number == 2) {
        frame.has_invoke_id = true;
        frame.invoke_id = static_cast<uint32_t>(ber_unsigned(children[idx].content));
        idx++;
    }
    if (idx < children.size() && ber_class(children[idx].tag_byte) == kBerClassUniversal &&
        children[idx].tag_number == 16) {
        idx++;  // optional listOfModifier -- never observed in practice, skipped
    }
    if (idx >= children.size()) {
        frame.notes.push_back("confirmedServiceRequest field missing (malformed or truncated PDU)");
        return;
    }
    dispatch_confirmed_service(children[idx], frame, /*is_response=*/false);
}

void decode_confirmed_response(const BerTlv& top, MmsFrame& frame) {
    frame.has_pdu = true;
    frame.pdu_name = "confirmed-ResponsePDU";
    frame.is_response = true;
    auto children = ber_children(top.content);
    size_t idx = 0;
    if (idx < children.size() && ber_class(children[idx].tag_byte) == kBerClassUniversal &&
        children[idx].tag_number == 2) {
        frame.has_invoke_id = true;
        frame.invoke_id = static_cast<uint32_t>(ber_unsigned(children[idx].content));
        idx++;
    }
    if (idx >= children.size()) {
        frame.notes.push_back("confirmedServiceResponse field missing (malformed or truncated PDU)");
        return;
    }
    dispatch_confirmed_service(children[idx], frame, /*is_response=*/true);
}

// ---- Top-level MMSpdu dispatch -- see mms.hpp's own 14-alternative tag table.
void decode_mms_pdu(const BerTlv& top, MmsFrame& frame) {
    if (ber_class(top.tag_byte) != kBerClassContext) {
        frame.body_shown_as_hex = true;
        frame.body_hex = hex_of(top.content);
        frame.body_length = top.content.size();
        return;
    }
    switch (top.tag_number) {
        case 0: decode_confirmed_request(top, frame); break;
        case 1: decode_confirmed_response(top, frame); break;
        case 2: decode_confirmed_error(top, frame); break;
        case 3: decode_unconfirmed_pdu(top, frame); break;
        case 4: decode_reject_pdu(top, frame); break;
        case 5: decode_cancel_request(top, frame); break;
        case 6: decode_cancel_response(top, frame); break;
        case 7: decode_cancel_error(top, frame); break;
        case 8: decode_initiate(top, false, frame); break;
        case 9: decode_initiate(top, true, frame); break;
        case 10: decode_initiate_error(top, frame); break;
        case 11: decode_conclude_request(frame); break;
        case 12: decode_conclude_response(frame); break;
        case 13: decode_conclude_error(top, frame); break;
        default:
            frame.body_shown_as_hex = true;
            frame.body_hex = hex_of(top.content);
            frame.body_length = top.content.size();
            break;
    }
}

std::string mms_summary(const MmsFrame& frame) {
    std::ostringstream s;
    s << (frame.is_bare ? "MMS (bare)" : ("MMS/" + (frame.session_pdu_name.empty() ? "session" : frame.session_pdu_name)));
    if (frame.has_acse) {
        s << " " << frame.acse_pdu_name;
        if (frame.acse_has_result) s << " (" << frame.acse_result_name << ")";
    }
    if (frame.has_pdu) {
        s << " " << frame.pdu_name;
        if (frame.service_recognized) s << " " << frame.service_name;
        if (frame.has_invoke_id) s << " invokeID=" << frame.invoke_id;
        if (frame.has_error) s << " error=" << frame.error_name;
    }
    return s.str();
}

// ---- Structural detection gate -- see mms.hpp's own "Bare MMS" and "Structural detection gate"
// sections. Session SPDU types are always in 1-64 (CLSES_UNIT_DATA(64) is the highest one-byte
// type ISO 8327-1 defines); every bare MMS top-level PDU tag is CONTEXT-class 0xA0-0xAD (11 of
// the 14 MMSpdu alternatives are SEQUENCE-typed and so constructed) or 0x80-0x8D (the 3 that are
// not: cancel-RequestPDU/cancel-ResponsePDU ::= Unsigned32, and conclude-RequestPDU/
// conclude-ResponsePDU ::= NULL, all primitive -- confirmed against real captures, see
// ATTRIBUTION.md). No overlap with Session's own SPDU type range either way. The upper bound is
// deliberately 64, not the looser 0x80 a first pass at this used -- 0x61 (97, the Presentation
// layer's own fully-encoded-data tag) is less than 0x80 and was genuinely mistaken for a valid
// SPDU type by that looser check on real capture traffic (two concatenated SI=1/LI=0 pairs
// immediately followed by Presentation bytes -- see ATTRIBUTION.md).
bool looks_like_session_spdu(ByteSpan buf) {
    if (buf.size() < 2) return false;
    uint8_t si = buf.at(0);
    if (si == 0 || si > 64) return false;
    uint8_t li = buf.at(1);
    if (li == 0xFF) return false;  // extended (2-byte) length form -- not supported
    return 2u + li <= buf.size();
}

bool looks_like_bare_mms_pdu(ByteSpan buf) {
    if (buf.empty()) return false;
    uint8_t b = buf.at(0);
    return ber_class(b) == kBerClassContext && (b & 0x1F) <= 13;
}

// A small number of real, independently-encoded stacks omit the Session-layer "ubiquitous SI=1"
// marker(s) entirely on an ongoing Data-Transfer message once an association is established --
// the COTP Data frame's user data goes straight to Presentation-layer bytes (see mms.hpp's own
// "Bare MMS" section for the analogous, more common "skip everything down to the MMS PDU itself"
// shape this decoder already handled before this one was found; this one skips only Session,
// confirmed via real-capture research -- see ATTRIBUTION.md). Recognized by the Presentation
// layer's own three top-level tags: CP-type/CPA-type (UNIVERSAL SET, 0x31), fully-encoded-data
// (APPLICATION 1 constructed, 0x61), simply-encoded-data (APPLICATION 0 primitive, 0x60).
bool looks_like_bare_presentation(ByteSpan buf) {
    if (buf.size() < 2) return false;
    uint8_t b = buf.at(0);
    return b == 0x31 || b == 0x61 || b == 0x60;
}

// Finishes decoding from Presentation-layer bytes onward (Presentation -> ACSE-or-MMS) -- shared
// by both entry shapes that reach this point: a Session SPDU's own User Data parameter, or (see
// looks_like_bare_presentation above) Presentation bytes with no Session wrapper at all.
void finish_from_presentation(ByteSpan presentation_bytes, MmsFrame& frame) {
    PresentationDecode pres = decode_presentation(presentation_bytes);
    if (!pres.recognized) {
        frame.notes.push_back("Presentation layer: unrecognized shape, not decoded further");
        frame.summary = mms_summary(frame);
        return;
    }
    frame.has_presentation = true;
    frame.presentation_context_list = pres.context_list;
    if (pres.has_context_id) frame.presentation_context_id = static_cast<uint32_t>(pres.context_id);

    if (pres.simply_encoded) {
        frame.body_shown_as_hex = true;
        frame.body_hex = hex_of(pres.simply_encoded_bytes);
        frame.body_length = pres.simply_encoded_bytes.size();
        frame.notes.push_back("Presentation user-data: simply-encoded-data (not decoded)");
        frame.summary = mms_summary(frame);
        return;
    }
    if (!pres.has_payload) {
        frame.notes.push_back(
            "Presentation-data-values: alternative not decoded (only single-ASN1-type implemented)");
        frame.summary = mms_summary(frame);
        return;
    }

    // Resolve which context this PDV belongs to -- an in-message context-definition-list is only
    // ever present on the association frame itself; every ongoing frame relies on the
    // near-universal 1=ACSE/3=MMS convention -- an honestly-stated assumption, not a guess
    // invented for this decoder, see mms.hpp.
    frame.presentation_context_is_acse = (frame.presentation_context_id == 1);

    if (pres.payload.empty()) {
        frame.summary = mms_summary(frame);
        return;
    }
    BerTlv next_top = read_ber_tlv(pres.payload);

    bool treat_as_acse = frame.presentation_context_is_acse ||
                          (ber_class(next_top.tag_byte) == kBerClassApplication && next_top.tag_number <= 4);
    if (treat_as_acse) {
        AcseDecode acse = decode_acse(next_top);
        if (acse.recognized) {
            frame.has_acse = true;
            frame.acse_pdu_name = acse.pdu_name;
            frame.acse_application_context_name = acse.application_context_name;
            frame.acse_has_result = acse.has_result;
            frame.acse_result_name = acse.result_name;
            frame.acse_values = acse.values;
            if (acse.has_user_information && !acse.user_information_payload.empty()) {
                BerTlv mms_top = read_ber_tlv(acse.user_information_payload);
                decode_mms_pdu(mms_top, frame);
            }
        } else {
            frame.notes.push_back("ACSE layer: unrecognized top-level tag, not decoded further");
        }
        frame.summary = mms_summary(frame);
        return;
    }

    // Ongoing Data-Transfer message: MMS directly at the resolved (or conventional) context.
    decode_mms_pdu(next_top, frame);
    frame.summary = mms_summary(frame);
}

}  // namespace

// ==============================================================================================
// ICCP/TASE.2 (IEC 60870-6-802) recognition -- see docs/DEVELOPMENT.md's own writeup for the
// full sourcing/scope discussion; this is a summary of the same reasoning.
//
// TASE.2 is NOT a distinct wire protocol from this decoder's own point of view: per IEC 60870-6's
// own architecture (and confirmed independently below), it rides the exact same COTP/Session/
// Presentation/ACSE/MMS stack this file already decodes in full, reuses the SAME 14 MMSpdu CHOICE
// alternatives, and -- per this decoder's own research -- does not appear to negotiate a distinct
// ACSE application-context-name OID from ordinary MMS (every independent source and reference
// implementation this decoder's own research found associates over the plain MMS application
// context). What TASE.2 actually adds is a STANDARDIZED OBJECT-NAMING PROFILE on top of generic
// MMS: a small set of reserved, spec-defined VCC-scope and domain-scope variable names every
// conformant TASE.2 stack reads/writes to identify itself, negotiate its Bilateral Table, and
// manage Data Set Transfer Sets -- ordinary MMS Read/Write/GetNameList/DefineNamedVariableList
// traffic, already fully and correctly decoded by everything above in this file, using object
// names this decoder's own generic ObjectName renderer already surfaces verbatim.
//
// This means there is no new wire-format parsing risk here at all: this is a pure post-decode
// SIGNATURE match over MmsFrame::values (already-decoded ObjectName strings, exactly the same
// "structural signature, not full grammar" posture this codebase already applies to NTLMSSP's own
// scan and WinRM's SOAP tag-local-name extraction -- see winrm.hpp), not a new protocol decoder,
// not a new GateKind, not a new `--protocol` value. A frame whose already-decoded object names
// include one of TASE.2's own reserved names is flagged with a curated note; nothing else about
// how this frame is decoded, labeled, or counted changes -- exactly the same "free extra
// visibility riding an existing decoder's own already-correct output" posture this codebase's own
// WinRM decoder already takes for a CIM/WMI query riding WinRM transport.
//
// Sourcing for the reserved-name vocabulary below (cross-checked against two independent
// sources, the same two-source bar this file's own header comment already applies elsewhere):
// MZ Automation's own published libtase2 protocol library developer guide (a commercial TASE.2
// stack's own documentation, naming "Bilateral_Table_ID"/"Supported_Features" as VCC-scope
// objects and the "_SBO"/"_TAG" suffixes as protocol-reserved), and the independent open-source
// FreeTase2 Python client (github.com/aklira/FreeTase2, built directly on this project's own
// already-used libiec61850 MMS stack), whose own source additionally confirms "TASE2_Version"
// (a VCC-scope two-element major/minor structure) and the domain-scope
// "Transfer_Set_Name"/"Transfer_Set_Time_Stamp"/"DSConditions_Detected"/"Next_DSTransfer_Set"
// trio/quartet a DSTransferSet's own system variables use. Both sources independently agree on
// every name below; neither is treated as authoritative alone.
//
// Honestly stated validation gap (this codebase's own established disclosure norm for a
// first-pass addition -- see e.g. LDAP/BGP's own "no real-world capture corpus" notes): unlike
// most other protocols in this codebase, there is no public, independently buildable, full
// TASE.2 client/server stack this decoder's own research could actually run to generate genuine
// TASE.2 wire traffic to validate against (FreeTase2 itself is an early-stage wrapper around
// libiec61850's own MMS API, not a standalone ASN.1 implementation, and its own source has
// unresolved bugs noted inline). This decoder's own fixture is therefore synthetic MMS traffic,
// built with this project's own already-validated MMS PDU encoder, carrying the reserved object
// names sourced above -- validated by construction against that cross-checked vocabulary, not
// against a real ICCP capture or an independently generated one. If a real ICCP/TASE.2 capture or
// a genuinely independent open-source stack becomes available later, this note (and
// tests/real_captures/mms/ATTRIBUTION.md) should be updated accordingly, the same way this
// project has handled every other protocol where independent traffic was eventually found after
// an earlier empty search.
namespace {

// Whole-token substring match: `name` must appear in `haystack` bounded on both sides by a
// non-identifier character (or string start/end) so a reserved name can't accidentally match as
// part of some longer, unrelated identifier that merely contains it as a substring.
bool contains_reserved_token(const std::string& haystack, const std::string& name) {
    size_t pos = 0;
    while ((pos = haystack.find(name, pos)) != std::string::npos) {
        bool left_ok = (pos == 0) || !(std::isalnum(static_cast<unsigned char>(haystack[pos - 1])) ||
                                        haystack[pos - 1] == '_');
        size_t end = pos + name.size();
        bool right_ok = (end >= haystack.size()) ||
                        !(std::isalnum(static_cast<unsigned char>(haystack[end])) || haystack[end] == '_');
        if (left_ok && right_ok) return true;
        pos += 1;
    }
    return false;
}

// TASE.2's own reserved VCC-scope and domain-scope system-variable names -- see this section's
// own header comment above for the two-source sourcing behind every entry.
constexpr const char* kIccpReservedNames[] = {
    "Bilateral_Table_ID", "TASE2_Version",       "Supported_Features",   "Transfer_Set_Name",
    "Transfer_Set_Time_Stamp", "DSConditions_Detected", "Event_Code_Detected", "Next_DSTransfer_Set",
};

// A write whose own itemId ends in one of these reserved suffixes is TASE.2's own
// Select-Before-Operate handle or tag-control variable (see this section's own header comment) --
// a genuine device-control action, not merely a name that happens to be enumerated.
bool has_reserved_control_suffix(const std::string& object_name) {
    size_t item_start = object_name.find_last_of('/');
    std::string item = (item_start == std::string::npos) ? object_name : object_name.substr(item_start + 1);
    auto ends_with = [&item](const char* suffix) {
        size_t n = std::strlen(suffix);
        return item.size() >= n && item.compare(item.size() - n, n, suffix) == 0;
    };
    return ends_with("_SBO") || ends_with("_TAG");
}

void apply_iccp_recognition(MmsFrame& frame) {
    if (frame.values.empty()) return;
    std::string haystack;
    for (const auto& v : frame.values) {
        haystack += v;
        haystack += '\n';
    }
    for (const char* name : kIccpReservedNames) {
        if (contains_reserved_token(haystack, name)) {
            frame.notes.push_back(
                std::string("ICCP/TASE.2 well-known object '") + name +
                "' observed -- this MMS traffic is very likely IEC 60870-6 ICCP/TASE.2, not IEC "
                "61850 (see mms.hpp's own ICCP/TASE.2 recognition section for the reserved-name "
                "vocabulary this is matched against)");
            break;  // one flagging note per frame is enough; the specific name is named above
        }
    }
    // Device control: only on an actual write (the request that DOES the writing, not a mere
    // enumeration elsewhere) targeting a reserved-suffix variable.
    if (frame.service_recognized && frame.service_name == "write" && !frame.is_response) {
        for (const auto& v : frame.values) {
            size_t eq = v.find('=');
            if (eq == std::string::npos || v.compare(0, eq, "variable") != 0) continue;
            std::string object_name = v.substr(eq + 1);
            if (has_reserved_control_suffix(object_name)) {
                frame.notes.push_back("ICCP/TASE.2 device control: write targets '" + object_name +
                                       "' (Select-Before-Operate / tag-setting reserved suffix)");
                break;
            }
        }
    }
}

}  // namespace

std::optional<MmsFrame> try_parse_mms(ByteSpan cotp_user_data) {
    if (cotp_user_data.empty()) return std::nullopt;

    if (looks_like_bare_mms_pdu(cotp_user_data) && !looks_like_session_spdu(cotp_user_data)) {
        BerTlv top = read_ber_tlv(cotp_user_data);
        MmsFrame frame;
        frame.is_bare = true;
        decode_mms_pdu(top, frame);
        frame.summary = mms_summary(frame);
        apply_iccp_recognition(frame);
        return frame;
    }

    if (!looks_like_session_spdu(cotp_user_data)) {
        if (!looks_like_bare_presentation(cotp_user_data)) return std::nullopt;
        MmsFrame frame;
        frame.session_pdu_name = "(no Session layer)";
        finish_from_presentation(cotp_user_data, frame);
        apply_iccp_recognition(frame);
        return frame;
    }

    MmsFrame frame;
    size_t offset = 0;
    std::optional<ByteSpan> user_data;
    std::string last_pdu_name;
    uint8_t last_type = 0;
    int guard = 0;

    // Consumes one or more SPDUs -- handles both a full CONNECT/ACCEPT (one SPDU, its own User
    // Data parameter) and the "ubiquitous SI=1" ongoing-message shape (one or more SI=1/LI=0
    // markers followed directly by Presentation-layer bytes with no Session parameter at all).
    // Each candidate SI byte must be a plausible ISO 8327-1 SPDU type (1-64 -- CLSES_UNIT_DATA(64)
    // is the highest one-byte type the standard defines) before being consumed as one: this
    // matters because the Presentation layer's own fully-encoded-data tag (0x61 == 97) would
    // otherwise pass a looser "< 0x80" check and be mistaken for a third bogus SPDU -- a genuine
    // real-capture-found collision (see ATTRIBUTION.md) between two concatenated SI=1/LI=0 pairs
    // immediately followed by Presentation bytes.
    while (offset < cotp_user_data.size()) {
        if (++guard > 8) throw ParseError("MMS/Session: too many concatenated SPDUs");
        ByteSpan remaining = cotp_user_data.from(offset);
        if (remaining.size() < 2) break;
        uint8_t si = remaining.at(0);
        if (si == 0 || si > 64) break;  // not a plausible SPDU type -- presentation bytes start here
        uint8_t li = remaining.at(1);
        if (li == 0xFF) throw ParseError("MMS/Session: extended SPDU length form not supported");
        if (2u + li > remaining.size()) {
            if (offset == 0) throw ParseError("MMS/Session: SPDU length exceeds available bytes");
            break;
        }
        last_type = si;
        last_pdu_name = session_pdu_name(si);
        if (li > 0) walk_session_parameters(remaining.subspan(2, li), user_data, 0);
        offset += 2 + li;
        if (user_data) break;  // Session's own User Data parameter found -- its content IS the
                                // Presentation-layer bytes, not whatever follows on the wire
        if (si != 1) break;    // a non-DATA-TRANSFER SPDU with no user-data: nothing more to reach
    }
    frame.session_spdu_type = last_type;
    frame.session_pdu_name = last_pdu_name.empty() ? ("type " + std::to_string(last_type)) : last_pdu_name;

    ByteSpan presentation_bytes;
    if (user_data) {
        presentation_bytes = *user_data;
    } else if (offset < cotp_user_data.size()) {
        presentation_bytes = cotp_user_data.from(offset);
    } else {
        frame.summary = mms_summary(frame);
        return frame;  // Session-only frame (e.g. a bare DISCONNECT/ABORT with no user data)
    }

    finish_from_presentation(presentation_bytes, frame);
    apply_iccp_recognition(frame);
    return frame;
}

std::optional<ProtocolResult> MmsDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto parsed = try_parse_mms(payload);
    if (!parsed) return std::nullopt;
    return ProtocolResult::make<MmsFrame>("mms", std::move(*parsed));
}

const ProtocolDecoder& mms_decoder() {
    static const MmsDecoder instance;
    return instance;
}

}  // namespace conduitscope
