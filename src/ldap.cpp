// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ldap.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <sstream>

namespace conduitscope {

namespace {

// ==============================================================================================
// BER (ASN.1 Basic Encoding Rules) TLV reading -- adapted from kerberos.cpp's own BerTlv/
// read_ber_tlv/ber_children/ber_integer, kept as a separate, self-contained copy per this
// codebase's established "each protocol keeps its own BER walker" convention (see this file's own
// header comment). UNLIKE kerberos.cpp, there is no explicit_child()-style "peel one layer"
// function here at all -- RFC 4511 uses IMPLICIT tagging throughout (see ldap.hpp's own Wire
// format section), so every TLV's own `content` already IS the field's value (for a primitive tag)
// or its children (for a constructed one); there is never a nested, separately-tagged TLV to peel
// first. LDAP also only ever needs the low-tag-number form (every tag number used in this file is
// <= 25), so, like kerberos.cpp, the high-tag-number multi-byte form is rejected rather than
// supported.

struct BerTlv {
    uint8_t tag_byte = 0;
    bool constructed = false;
    ByteSpan content;
    size_t total_len = 0;
};

constexpr uint8_t kBerClassUniversal = 0x00;
constexpr uint8_t kBerClassApplication = 0x40;
constexpr uint8_t kBerClassContext = 0x80;

uint8_t ber_class(uint8_t tag_byte) { return tag_byte & 0xC0; }
uint8_t ber_tag_number(uint8_t tag_byte) { return tag_byte & 0x1F; }

BerTlv read_ber_tlv(ByteSpan buf) {
    if (buf.size() < 2) throw ParseError("LDAP BER TLV: need at least 2 bytes for tag+length");
    Cursor c(buf);
    BerTlv tlv;
    tlv.tag_byte = c.u8();
    tlv.constructed = (tlv.tag_byte & 0x20) != 0;
    if ((tlv.tag_byte & 0x1F) == 0x1F) {
        // High-tag-number form -- never actually used by any LDAP field this decoder reads, but
        // rejected explicitly (rather than silently misparsed) if ever encountered.
        throw ParseError("LDAP BER TLV: high-tag-number form not supported (not used by RFC 4511)");
    }
    uint8_t len_byte = c.u8();
    size_t length;
    if (len_byte & 0x80) {
        uint8_t num_octets = len_byte & 0x7F;
        if (num_octets == 0) throw ParseError("LDAP BER TLV: indefinite length not supported (DER forbids it)");
        if (num_octets > 4) throw ParseError("LDAP BER TLV: length field implausibly wide");
        length = 0;
        for (uint8_t i = 0; i < num_octets; ++i) length = (length << 8) | c.u8();
    } else {
        length = len_byte;
    }
    tlv.content = c.bytes(length);
    tlv.total_len = c.position();
    return tlv;
}

// Splits `buf` into its top-level TLVs only (does not recurse) -- used both for a SEQUENCE's own
// fields and, since IMPLICIT tagging never wraps a "SET/SEQUENCE OF" element in its own per-element
// tag, for scanning a repeated element list (attribute values, referral URIs, AND/OR filter
// operands, ...) the same way.
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

int64_t ber_integer(ByteSpan content) {
    if (content.empty()) return 0;
    // Accumulate in uint64_t, not int64_t: left-shifting a negative signed value is undefined
    // behavior (C++17; C++20 defines it, but this codebase doesn't rely on that), and the sign-
    // extension fill below sets exactly that up on the very first shift for any negative-valued
    // BER INTEGER (an ordinary, unremarkable encoding, not a contrived edge case). Shifting an
    // unsigned value is always well-defined (modulo 2^64 wraparound) regardless of bit pattern,
    // and produces the identical bit pattern a two's-complement signed shift would have on every
    // real target anyway -- so this changes definedness, not behavior. The final cast to int64_t
    // is implementation-defined but universally two's-complement in practice, and standardized
    // outright as of C++20.
    uint64_t v = (content.at(0) & 0x80) ? ~uint64_t{0} : 0;
    for (size_t i = 0; i < content.size(); ++i) v = (v << 8) | content.at(i);
    return static_cast<int64_t>(v);
}

std::string ber_octet_string(ByteSpan content) {
    return std::string(reinterpret_cast<const char*>(content.data()), content.size());
}

bool ber_boolean(ByteSpan content) { return !content.empty() && content.at(0) != 0; }

// CLI-configurable via --max-recursion-depth -- see resource_limits.hpp. The mms.cpp/goose.cpp
// "max_x_depth() wraps resource_limits()" pattern, LDAP's own instance of it: bounds SearchRequest
// filter AND/OR/NOT nesting (RFC 4511 section 4.5.1's own Filter CHOICE is recursive with no fixed
// depth of its own).
int max_ldap_filter_depth() { return static_cast<int>(resource_limits().max_recursion_depth.value_or(16)); }

// ==============================================================================================
// Named lookup tables -- every one falls back to a raw numeric rendering for anything not listed,
// the same graceful-degradation posture kerberos.cpp's own tables take.

// RFC 4511 section 4.1.9's full resultCode ENUMERATED table.
std::string ldap_result_code_name(int32_t code) {
    switch (code) {
        case 0: return "success";
        case 1: return "operationsError";
        case 2: return "protocolError";
        case 3: return "timeLimitExceeded";
        case 4: return "sizeLimitExceeded";
        case 5: return "compareFalse";
        case 6: return "compareTrue";
        case 7: return "authMethodNotSupported";
        case 8: return "strongerAuthRequired";
        case 10: return "referral";
        case 11: return "adminLimitExceeded";
        case 12: return "unavailableCriticalExtension";
        case 13: return "confidentialityRequired";
        case 14: return "saslBindInProgress";
        case 16: return "noSuchAttribute";
        case 17: return "undefinedAttributeType";
        case 18: return "inappropriateMatching";
        case 19: return "constraintViolation";
        case 20: return "attributeOrValueExists";
        case 21: return "invalidAttributeSyntax";
        case 32: return "noSuchObject";
        case 33: return "aliasProblem";
        case 34: return "invalidDNSyntax";
        case 36: return "aliasDereferencingProblem";
        case 48: return "inappropriateAuthentication";
        case 49: return "invalidCredentials";
        case 50: return "insufficientAccessRights";
        case 51: return "busy";
        case 52: return "unavailable";
        case 53: return "unwillingToPerform";
        case 54: return "loopDetect";
        case 64: return "namingViolation";
        case 65: return "objectClassViolation";
        case 66: return "notAllowedOnNonLeaf";
        case 67: return "notAllowedOnRDN";
        case 68: return "entryAlreadyExists";
        case 69: return "objectClassModsProhibited";
        case 71: return "affectsMultipleDSAs";
        case 80: return "other";
        default: return "resultCode " + std::to_string(code);
    }
}

std::string ldap_scope_name(int64_t scope) {
    switch (scope) {
        case 0: return "baseObject";
        case 1: return "singleLevel";
        case 2: return "wholeSubtree";
        default: return "scope " + std::to_string(scope);
    }
}

std::string ldap_deref_aliases_name(int64_t v) {
    switch (v) {
        case 0: return "neverDerefAliases";
        case 1: return "derefInSearching";
        case 2: return "derefFindingBaseObj";
        case 3: return "derefAlways";
        default: return "derefAliases " + std::to_string(v);
    }
}

// Well-known LDAP extended-operation OIDs -- named where confidently, independently verified (see
// ldap.hpp's own header comment), else left as the bare OID string.
std::string ldap_known_extended_oid_name(const std::string& oid) {
    if (oid == "1.3.6.1.4.1.1466.20037") return "StartTLS";
    return "";
}

// The AD-specific "bitwise AND" matching-rule OID (Microsoft MS-ADTS, not in RFC 4511 itself) --
// confirmed via Microsoft's own spec, see ldap.hpp's header comment.
const char* kAdBitwiseAndMatchingRuleOid = "1.2.840.113556.1.4.803";
// userAccountControl bit values -- confirmed via Microsoft's own troubleshooting doc, see ldap.hpp's
// header comment.
constexpr int64_t kUacDontReqPreauthBit = 0x400000;      // 4194304
constexpr int64_t kUacTrustedForDelegationBit = 0x80000;  // 524288

bool ieq(const std::string& a, const std::string& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i])))
            return false;
    }
    return true;
}

bool icontains(const std::string& haystack, const std::string& needle) {
    if (needle.empty()) return false;
    std::string h = haystack, n = needle;
    std::transform(h.begin(), h.end(), h.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    std::transform(n.begin(), n.end(), n.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return h.find(n) != std::string::npos;
}

// RFC 4515-style filter value escaping -- '*', '(', ')', '\' and any non-printable byte rendered as
// "\XX" hex, so attacker-controlled filter bytes never corrupt this file's own rendered "(attr=val)"
// syntax or an output writer's own text/JSON framing.
std::string escape_filter_value(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        if (c == '*' || c == '(' || c == ')' || c == '\\' || c < 0x20 || c > 0x7e) {
            char buf[4];
            std::snprintf(buf, sizeof(buf), "\\%02x", c);
            out << buf;
        } else {
            out << static_cast<char>(c);
        }
    }
    return out.str();
}

// Attribute-value rendering for SearchResultEntry -- capped in length, with binary-looking content
// shown as "(N bytes, binary)" rather than a guessed string decode, the same "don't guess at
// unstructured binary" posture this codebase already has elsewhere (e.g. OPC UA's own body_hex
// fallback).
std::string render_attribute_value(ByteSpan content) {
    constexpr size_t kMaxRenderLen = 200;
    bool printable = true;
    size_t check_len = std::min(content.size(), kMaxRenderLen);
    for (size_t i = 0; i < check_len; ++i) {
        uint8_t c = content.at(i);
        if (c < 0x20 || c > 0x7e) {
            printable = false;
            break;
        }
    }
    if (!printable) {
        return "(" + std::to_string(content.size()) + " bytes, binary)";
    }
    std::string s(reinterpret_cast<const char*>(content.data()), check_len);
    if (content.size() > kMaxRenderLen) {
        s += "...(" + std::to_string(content.size()) + " bytes total)";
    }
    return s;
}

// Populated while decode_filter (below) walks a SearchRequest's filter tree -- see ldap.hpp's own
// header comment's curated-notes section for notes 3-5, all keyed off these flags.
struct FilterAnalysis {
    bool has_spn = false;
    bool has_admin_count = false;
    bool has_asrep_roast_bit = false;
    bool has_delegation_shape = false;
};

void record_attribute_seen(FilterAnalysis& analysis, const std::string& attr) {
    if (icontains(attr, "serviceprincipalname")) analysis.has_spn = true;
    if (icontains(attr, "admincount")) analysis.has_admin_count = true;
    if (icontains(attr, "msds-allowedtodelegateto")) analysis.has_delegation_shape = true;
}

// extensibleMatch's own AD-bitwise-AND recon shapes (curated notes 4/5) -- `match_value` is the
// wire's own AssertionValue bytes, which for this specific matching rule is the ASCII decimal
// string of the bitmask being tested (e.g. "4194304"), not a raw binary integer -- confirmed
// against real-world AD query examples using this OID.
void analyze_extensible_match(FilterAnalysis& analysis, const std::string& matching_rule,
                               const std::string& type, const std::string& match_value) {
    if (matching_rule != kAdBitwiseAndMatchingRuleOid) return;
    if (!ieq(type, "userAccountControl")) return;
    int64_t bits = 0;
    try {
        bits = std::stoll(match_value);
    } catch (...) {
        return;
    }
    if (bits & kUacDontReqPreauthBit) analysis.has_asrep_roast_bit = true;
    if (bits & kUacTrustedForDelegationBit) analysis.has_delegation_shape = true;
}

// Recursive Filter CHOICE decoder (RFC 4511 section 4.5.1) -- see ldap.hpp's own header comment for
// the per-alternative tag/shape table this switches on. Renders conventional ldapsearch-style
// syntax. Depth-capped via max_ldap_filter_depth(); a filter deeper than the cap renders a
// placeholder rather than throwing, the same non-throwing "nesting exceeds max depth" posture
// goose.cpp's own Data-value recursion takes (a malformed/adversarial depth is a decode-quality
// issue, not grounds for discarding the whole message).
std::string decode_filter(const BerTlv& node, int depth, FilterAnalysis& analysis) {
    if (depth > max_ldap_filter_depth()) {
        return "(...nesting exceeds max depth " + std::to_string(max_ldap_filter_depth()) + "...)";
    }
    if (ber_class(node.tag_byte) != kBerClassContext) {
        return "(unrecognized-filter-element)";
    }
    uint8_t tag_num = ber_tag_number(node.tag_byte);
    switch (tag_num) {
        case 0:   // and [0] SET SIZE (1..MAX) OF filter Filter
        case 1: {  // or [1] SET SIZE (1..MAX) OF filter Filter
            std::ostringstream s;
            s << "(" << (tag_num == 0 ? "&" : "|");
            for (const auto& child : ber_children(node.content)) {
                s << decode_filter(child, depth + 1, analysis);
            }
            s << ")";
            return s.str();
        }
        case 2: {  // not [2] Filter
            if (node.content.empty()) return "(!)";
            BerTlv inner = read_ber_tlv(node.content);
            return "(!" + decode_filter(inner, depth + 1, analysis) + ")";
        }
        case 3:   // equalityMatch [3] AttributeValueAssertion
        case 5:   // greaterOrEqual [5] AttributeValueAssertion
        case 6:   // lessOrEqual [6] AttributeValueAssertion
        case 8: {  // approxMatch [8] AttributeValueAssertion
            auto parts = ber_children(node.content);
            std::string attr = parts.size() >= 1 ? ber_octet_string(parts[0].content) : "";
            std::string val = parts.size() >= 2 ? ber_octet_string(parts[1].content) : "";
            record_attribute_seen(analysis, attr);
            const char* op = (tag_num == 3) ? "=" : (tag_num == 5) ? ">=" : (tag_num == 6) ? "<=" : "~=";
            return "(" + attr + op + escape_filter_value(val) + ")";
        }
        case 4: {  // substrings [4] SubstringFilter
            auto parts = ber_children(node.content);
            std::string attr = parts.size() >= 1 ? ber_octet_string(parts[0].content) : "";
            record_attribute_seen(analysis, attr);
            std::string initial, final_part;
            std::vector<std::string> anys;
            if (parts.size() >= 2) {
                for (const auto& sub : ber_children(parts[1].content)) {
                    std::string v = ber_octet_string(sub.content);
                    uint8_t sub_tag = ber_tag_number(sub.tag_byte);
                    if (sub_tag == 0) initial = v;
                    else if (sub_tag == 1) anys.push_back(v);
                    else if (sub_tag == 2) final_part = v;
                }
            }
            std::ostringstream s;
            s << "(" << attr << "=" << escape_filter_value(initial) << "*";
            for (const auto& a : anys) s << escape_filter_value(a) << "*";
            s << escape_filter_value(final_part) << ")";
            return s.str();
        }
        case 7: {  // present [7] AttributeDescription -- context-PRIMITIVE, content is the raw
                   // attribute name bytes directly (see ldap.hpp's own Wire format section)
            std::string attr = ber_octet_string(node.content);
            record_attribute_seen(analysis, attr);
            return "(" + attr + "=*)";
        }
        case 9: {  // extensibleMatch [9] MatchingRuleAssertion
            auto parts = ber_children(node.content);
            std::string matching_rule, type, match_value;
            bool dn_attrs = false;
            for (const auto& f : parts) {
                if (ber_class(f.tag_byte) != kBerClassContext) continue;
                switch (ber_tag_number(f.tag_byte)) {
                    case 1: matching_rule = ber_octet_string(f.content); break;
                    case 2: type = ber_octet_string(f.content); break;
                    case 3: match_value = ber_octet_string(f.content); break;
                    case 4: dn_attrs = ber_boolean(f.content); break;
                    default: break;
                }
            }
            if (!type.empty()) record_attribute_seen(analysis, type);
            analyze_extensible_match(analysis, matching_rule, type, match_value);
            std::ostringstream s;
            s << "(" << type;
            if (dn_attrs) s << ":dn";
            if (!matching_rule.empty()) s << ":" << matching_rule;
            s << ":=" << escape_filter_value(match_value) << ")";
            return s.str();
        }
        default:
            return "(unrecognized-filter-choice-" + std::to_string(tag_num) + ")";
    }
}

// Shared LDAPResult decode -- BindResponse/SearchResultDone/CompareResponse/ExtendedResponse are
// all literally "[APPLICATION n] LDAPResult" (or a COMPONENTS OF it), see ldap.hpp's own struct
// comment. `seq_content` is the protocolOp TLV's own content (its first 3 children are always
// resultCode/matchedDN/diagnosticMessage in that fixed order; any remaining child, e.g. a
// referral[3], is optional and scanned by tag).
struct LdapResultFields {
    int32_t result_code = 0;
    std::string result_code_name;
    std::string matched_dn;
    std::string diagnostic_message;
    std::vector<std::string> referral_uris;
};

LdapResultFields decode_ldap_result(ByteSpan seq_content) {
    LdapResultFields r;
    auto fields = ber_children(seq_content);
    if (fields.size() >= 1) {
        r.result_code = static_cast<int32_t>(ber_integer(fields[0].content));
        r.result_code_name = ldap_result_code_name(r.result_code);
    }
    if (fields.size() >= 2) r.matched_dn = ber_octet_string(fields[1].content);
    if (fields.size() >= 3) r.diagnostic_message = ber_octet_string(fields[2].content);
    const size_t kMaxReferrals = resource_limits().max_decoded_objects.value_or(50);
    for (size_t i = 3; i < fields.size(); ++i) {
        const BerTlv& f = fields[i];
        if (ber_class(f.tag_byte) == kBerClassContext && ber_tag_number(f.tag_byte) == 3) {
            for (const auto& uri : ber_children(f.content)) {
                if (r.referral_uris.size() >= kMaxReferrals) break;
                r.referral_uris.push_back(ber_octet_string(uri.content));
            }
        }
    }
    return r;
}

void apply_result_fields(LdapMessage& msg, const LdapResultFields& r) {
    msg.has_result = true;
    msg.result_code = r.result_code;
    msg.result_code_name = r.result_code_name;
    msg.matched_dn = r.matched_dn;
    msg.diagnostic_message = r.diagnostic_message;
    msg.referral_uris = r.referral_uris;
}

// BindRequest ::= [APPLICATION 0] SEQUENCE { version INTEGER, name LDAPDN,
// authentication AuthenticationChoice }.
void decode_bind_request(LdapMessage& msg, ByteSpan seq_content) {
    auto fields = ber_children(seq_content);
    if (fields.size() >= 1) msg.bind_version = static_cast<uint8_t>(ber_integer(fields[0].content));
    if (fields.size() >= 2) msg.bind_dn = ber_octet_string(fields[1].content);
    if (fields.size() >= 3) {
        const BerTlv& auth = fields[2];
        if (ber_class(auth.tag_byte) == kBerClassContext && ber_tag_number(auth.tag_byte) == 0) {
            // simple [0] OCTET STRING -- context-PRIMITIVE, content is the password bytes DIRECTLY,
            // no OCTET-STRING wrapper tag to peel first (see ldap.hpp's own Wire format section --
            // this is exactly the field where reflexive Kerberos-style "peel a layer" muscle memory
            // would silently misread the boundary).
            msg.bind_auth_mechanism = "simple";
            msg.bind_credential_present = !auth.content.empty();
            msg.bind_credential_length = auth.content.size();
        } else if (ber_class(auth.tag_byte) == kBerClassContext && ber_tag_number(auth.tag_byte) == 3) {
            // sasl [3] SaslCredentials ::= SEQUENCE { mechanism LDAPString,
            // credentials OCTET STRING OPTIONAL } -- context-constructed, its own two children are
            // plain, unwrapped OCTET STRINGs (SaslCredentials has no further tagging of its own
            // fields).
            msg.bind_is_sasl = true;
            auto sasl_fields = ber_children(auth.content);
            if (!sasl_fields.empty()) msg.bind_auth_mechanism = ber_octet_string(sasl_fields[0].content);
            if (sasl_fields.size() >= 2) {
                msg.bind_credential_present = !sasl_fields[1].content.empty();
                msg.bind_credential_length = sasl_fields[1].content.size();
            }
        }
    }
}

// SearchRequest ::= [APPLICATION 3] SEQUENCE { baseObject LDAPDN, scope ENUMERATED,
// derefAliases ENUMERATED, sizeLimit INTEGER, timeLimit INTEGER, typesOnly BOOLEAN, filter Filter,
// attributes AttributeSelection } -- all 8 fields mandatory, in this fixed order (no OPTIONAL
// markers in RFC 4511's own ASN.1 for this type), so positional access is safe.
void decode_search_request(LdapMessage& msg, ByteSpan seq_content) {
    auto fields = ber_children(seq_content);
    if (fields.size() < 8) throw ParseError("LDAP SearchRequest: expected 8 fields, got fewer");
    msg.search_base_object = ber_octet_string(fields[0].content);
    msg.search_scope = ldap_scope_name(ber_integer(fields[1].content));
    msg.search_deref_aliases = ldap_deref_aliases_name(ber_integer(fields[2].content));
    msg.search_size_limit = static_cast<int32_t>(ber_integer(fields[3].content));
    msg.search_time_limit = static_cast<int32_t>(ber_integer(fields[4].content));
    msg.search_types_only = ber_boolean(fields[5].content);

    FilterAnalysis analysis;
    msg.search_filter = decode_filter(fields[6], 0, analysis);
    msg.search_filter_has_spn = analysis.has_spn;
    msg.search_filter_has_admin_count = analysis.has_admin_count;
    msg.search_filter_has_asrep_roast_bit = analysis.has_asrep_roast_bit;
    msg.search_filter_has_delegation_shape = analysis.has_delegation_shape;

    const size_t kMaxAttrs = resource_limits().max_decoded_objects.value_or(100);
    for (const auto& a : ber_children(fields[7].content)) {
        if (msg.search_attributes.size() >= kMaxAttrs) break;
        msg.search_attributes.push_back(ber_octet_string(a.content));
    }
}

// SearchResultEntry ::= [APPLICATION 4] SEQUENCE { objectName LDAPDN,
// attributes PartialAttributeList (SEQUENCE OF PartialAttribute) }. Each PartialAttribute is a
// PLAIN SEQUENCE (0x30) -- it is a SEQUENCE OF element, not itself context-tagged -- of
// { type AttributeDescription, vals SET OF AttributeValue }, `vals` a plain SET (0x31) of plain
// OCTET STRING values.
void decode_search_result_entry(LdapMessage& msg, ByteSpan seq_content) {
    auto fields = ber_children(seq_content);
    if (fields.size() < 2) throw ParseError("LDAP SearchResultEntry: expected 2 fields, got fewer");
    msg.search_result_object_name = ber_octet_string(fields[0].content);
    const size_t kMaxAttrs = resource_limits().max_decoded_objects.value_or(100);
    for (const auto& pa : ber_children(fields[1].content)) {
        if (msg.search_result_attributes.size() >= kMaxAttrs) break;
        auto pa_fields = ber_children(pa.content);
        std::string type = pa_fields.size() >= 1 ? ber_octet_string(pa_fields[0].content) : "";
        std::vector<std::string> values;
        if (pa_fields.size() >= 2) {
            for (const auto& v : ber_children(pa_fields[1].content)) {
                values.push_back(render_attribute_value(v.content));
            }
        }
        std::ostringstream line;
        line << type << "=";
        for (size_t i = 0; i < values.size(); ++i) {
            if (i) line << ",";
            line << values[i];
        }
        msg.search_result_attributes.push_back(line.str());
    }
}

// CompareRequest ::= [APPLICATION 14] SEQUENCE { entry LDAPDN,
// ava AttributeValueAssertion (a plain, untagged nested SEQUENCE -- `ava` carries no context tag
// of its own here, unlike a Filter's own equalityMatch[3]) }.
void decode_compare_request(LdapMessage& msg, ByteSpan seq_content) {
    auto fields = ber_children(seq_content);
    if (fields.size() < 2) throw ParseError("LDAP CompareRequest: expected 2 fields, got fewer");
    msg.compare_entry = ber_octet_string(fields[0].content);
    auto ava = ber_children(fields[1].content);
    if (ava.size() >= 1) msg.compare_attribute = ber_octet_string(ava[0].content);
    if (ava.size() >= 2) msg.compare_value = ber_octet_string(ava[1].content);
}

// ExtendedRequest ::= [APPLICATION 23] SEQUENCE { requestName [0] LDAPOID,
// requestValue [1] OCTET STRING OPTIONAL } -- both context-PRIMITIVE, content bytes directly (same
// "no wrapper tag to peel" shape as BindRequest's own simple[0] above).
void decode_extended_request(LdapMessage& msg, ByteSpan seq_content) {
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (ber_tag_number(f.tag_byte)) {
            case 0: msg.extended_request_name = ber_octet_string(f.content); break;
            case 1:
                msg.extended_value_present = !f.content.empty();
                msg.extended_value_length = f.content.size();
                break;
            default: break;
        }
    }
    msg.extended_request_name_known = ldap_known_extended_oid_name(msg.extended_request_name);
}

// ExtendedResponse ::= [APPLICATION 24] SEQUENCE { COMPONENTS OF LDAPResult,
// responseName [10] LDAPOID OPTIONAL, responseValue [11] OCTET STRING OPTIONAL }.
void decode_extended_response(LdapMessage& msg, ByteSpan seq_content) {
    apply_result_fields(msg, decode_ldap_result(seq_content));
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (ber_tag_number(f.tag_byte)) {
            case 10: msg.extended_response_name = ber_octet_string(f.content); break;
            case 11:
                msg.extended_value_present = !f.content.empty();
                msg.extended_value_length = f.content.size();
                break;
            default: break;
        }
    }
}

// op_num -> {display name (matching the capitalized style this file's own summary/JSON use, e.g.
// "BindRequest" not the ASN.1 module's own lowerCamelCase "bindRequest"), expected constructed bit}.
// The expected-constructed-bit half of this table is the STRONGER structural check
// it_protocols.hpp's own match_ldap_ber does NOT perform -- see ldap.hpp's own header comment's Wire
// format section for the full per-alternative reasoning (SEQUENCE/LDAPResult-typed => constructed,
// NULL/INTEGER/OCTET-STRING-typed => primitive).
struct LdapOpShape {
    const char* display_name;
    bool constructed;
};

std::optional<LdapOpShape> ldap_op_shape(uint8_t op_num) {
    switch (op_num) {
        case 0: return LdapOpShape{"BindRequest", true};
        case 1: return LdapOpShape{"BindResponse", true};
        case 2: return LdapOpShape{"UnbindRequest", false};
        case 3: return LdapOpShape{"SearchRequest", true};
        case 4: return LdapOpShape{"SearchResultEntry", true};
        case 5: return LdapOpShape{"SearchResultDone", true};
        case 6: return LdapOpShape{"ModifyRequest", true};
        case 7: return LdapOpShape{"ModifyResponse", true};
        case 8: return LdapOpShape{"AddRequest", true};
        case 9: return LdapOpShape{"AddResponse", true};
        case 10: return LdapOpShape{"DelRequest", false};
        case 11: return LdapOpShape{"DelResponse", true};
        case 12: return LdapOpShape{"ModifyDNRequest", true};
        case 13: return LdapOpShape{"ModifyDNResponse", true};
        case 14: return LdapOpShape{"CompareRequest", true};
        case 15: return LdapOpShape{"CompareResponse", true};
        case 16: return LdapOpShape{"AbandonRequest", false};
        case 19: return LdapOpShape{"SearchResultReference", true};
        case 23: return LdapOpShape{"ExtendedRequest", true};
        case 24: return LdapOpShape{"ExtendedResponse", true};
        case 25: return LdapOpShape{"IntermediateResponse", true};
        default: return std::nullopt;
    }
}

bool ldap_op_is_response(uint8_t op_num) {
    switch (op_num) {
        case 1: case 4: case 5: case 7: case 9: case 11: case 13: case 15: case 19: case 24: case 25:
            return true;
        default:
            return false;
    }
}

// Builds the human-readable summary/curated notes once every field is decoded -- split out of
// try_parse_ldap so every curated note's non-correlated trigger condition is visible in one place,
// the same organization kerberos.cpp's own build_summary_and_notes uses. Session-correlated notes
// (note 2's StartTLS check, note 6's implicit --stats aggregation, and the SearchResultDone entry-
// count note) are NOT added here -- those need cross-packet flow state and are added by
// LdapTcpDecoder::decode after this function returns.
void build_summary_and_notes(LdapMessage& msg) {
    std::ostringstream s;
    s << msg.message_type << " id=" << msg.message_id;

    if (msg.message_type == "BindRequest") {
        s << " version=" << static_cast<int>(msg.bind_version) << " dn=\""
          << (msg.bind_dn.empty() ? "(anonymous)" : msg.bind_dn) << "\"";
        if (msg.bind_is_sasl) {
            s << " auth=SASL(" << msg.bind_auth_mechanism << ")";
        } else {
            s << " auth=simple";
        }
        s << " credential=" << (msg.bind_credential_present
                                     ? (std::to_string(msg.bind_credential_length) + " byte(s), not decoded")
                                     : "(none)");
        // Curated note 1 -- anonymous/unauthenticated bind (RFC 4513 section 5.1.2), standing,
        // unconditional: simple authentication with no password. Deliberately does not require an
        // empty DN too -- RFC 4513's own "unauthenticated bind" shape (a non-empty name, empty
        // password) is exactly as much of a finding as a fully anonymous one, since a server that
        // honors it still grants an authenticated-looking session with no real credential check.
        if (!msg.bind_is_sasl && !msg.bind_credential_present) {
            msg.notes.push_back(
                "anonymous or unauthenticated bind (simple authentication with an empty password) -- "
                "a well-known, commonly-checked AD misconfiguration if this DSA honors it with "
                "anything beyond the most restricted anonymous access");
        }
    } else if (msg.message_type == "BindResponse") {
        s << " resultCode=" << msg.result_code_name;
    } else if (msg.message_type == "UnbindRequest") {
        // nothing further to render
    } else if (msg.message_type == "SearchRequest") {
        s << " base=\"" << msg.search_base_object << "\" scope=" << msg.search_scope
          << " filter=" << msg.search_filter;
        // Curated note 3 -- AD reconnaissance filter shapes (SPN sweep / adminCount sweep).
        if (msg.search_filter_has_spn) {
            msg.notes.push_back(
                "filter references servicePrincipalName -- the standard Kerberoasting target-"
                "discovery step (directly upstream of this capture's own Kerberos decoder's "
                "Kerberoasting note, if a matching TGS-REQ/TGS-REP follows); legitimate directory "
                "tooling uses this same filter shape too, this only names the technique");
        }
        if (msg.search_filter_has_admin_count) {
            msg.notes.push_back(
                "filter references adminCount -- the standard privileged-account enumeration sweep "
                "(AD sets adminCount=1 on accounts ever protected by AdminSDHolder); legitimate "
                "directory tooling uses this same filter shape too, this only names the technique");
        }
        // Curated note 4 -- AS-REP-Roasting target discovery.
        if (msg.search_filter_has_asrep_roast_bit) {
            msg.notes.push_back(
                "filter uses a bitwise match against userAccountControl's DONT_REQ_PREAUTH bit "
                "(0x400000) -- the standard AS-REP-Roasting target-discovery query, directly upstream "
                "of this capture's own Kerberos decoder's AS-REP-Roasting note if a matching AS-REQ/"
                "AS-REP follows; not itself proof of an attack tool");
        }
        // Curated note 5 -- delegation discovery.
        if (msg.search_filter_has_delegation_shape) {
            msg.notes.push_back(
                "filter surfaces a delegation-relevant shape (a bitwise match against "
                "userAccountControl's TRUSTED_FOR_DELEGATION bit, and/or a reference to "
                "msDS-AllowedToDelegateTo) -- the LDAP-side complement of the delegation-shape "
                "surfacing this capture's own Kerberos decoder already does on the wire; not itself "
                "proof of abuse");
        }
    } else if (msg.message_type == "SearchResultEntry") {
        s << " object=\"" << msg.search_result_object_name << "\" ("
          << msg.search_result_attributes.size() << " attribute(s))";
    } else if (msg.message_type == "SearchResultDone") {
        s << " resultCode=" << msg.result_code_name;
    } else if (msg.message_type == "SearchResultReference") {
        s << " (" << msg.referral_uris.size() << " uri(s))";
    } else if (msg.message_type == "CompareRequest") {
        s << " entry=\"" << msg.compare_entry << "\" " << msg.compare_attribute << "="
          << escape_filter_value(msg.compare_value);
    } else if (msg.message_type == "CompareResponse") {
        s << " result=" << msg.result_code_name;
    } else if (msg.message_type == "AbandonRequest") {
        s << " target-messageID=" << msg.abandon_message_id;
    } else if (msg.message_type == "ExtendedRequest") {
        s << " name="
          << (msg.extended_request_name_known.empty()
                  ? msg.extended_request_name
                  : msg.extended_request_name_known + " (" + msg.extended_request_name + ")");
    } else if (msg.message_type == "ExtendedResponse") {
        s << " resultCode=" << msg.result_code_name;
        if (!msg.extended_response_name.empty()) s << " name=" << msg.extended_response_name;
    }
    // else: IntermediateResponse and the nine structural-only write operations (AddRequest/
    // AddResponse, ModifyRequest/ModifyResponse, DelRequest/DelResponse, ModifyDNRequest/
    // ModifyDNResponse) render only "<MessageType> id=<n>" -- see ldap.hpp's own STRUCTURAL-ONLY
    // list for why these aren't field-decoded in this pass.

    msg.summary = s.str();
}

}  // namespace

std::optional<LdapMessage> try_parse_ldap(ByteSpan message) {
    if (message.size() < 7) return std::nullopt;
    try {
        BerTlv outer = read_ber_tlv(message);
        if (outer.tag_byte != 0x30) return std::nullopt;  // LDAPMessage's own fixed envelope tag

        std::vector<BerTlv> top = ber_children(outer.content);
        if (top.size() < 2) return std::nullopt;

        if (top[0].tag_byte != 0x02) return std::nullopt;  // messageID INTEGER
        int64_t message_id = ber_integer(top[0].content);
        if (message_id < 0) return std::nullopt;

        const BerTlv& op = top[1];
        if (ber_class(op.tag_byte) != kBerClassApplication) return std::nullopt;
        uint8_t op_num = ber_tag_number(op.tag_byte);
        auto shape = ldap_op_shape(op_num);
        if (!shape) return std::nullopt;
        // The stronger, per-field structural check match_ldap_ber (it_protocols.hpp) does NOT
        // perform -- see this file's own header comment's STRUCTURAL DETECTION GATE section.
        if (op.constructed != shape->constructed) return std::nullopt;

        LdapMessage msg;
        msg.message_id = message_id;
        msg.message_type = shape->display_name;
        msg.op_num = op_num;
        msg.is_response = ldap_op_is_response(op_num);

        // Optional controls [0] Controls -- OID only, controlValue never decoded (see ldap.hpp's
        // own DELIBERATELY NOT IMPLEMENTED list).
        if (top.size() >= 3 && ber_class(top[2].tag_byte) == kBerClassContext &&
            ber_tag_number(top[2].tag_byte) == 0) {
            const size_t kMaxControls = resource_limits().max_decoded_objects.value_or(50);
            for (const auto& c : ber_children(top[2].content)) {
                if (msg.control_oids.size() >= kMaxControls) break;
                auto cf = ber_children(c.content);
                if (!cf.empty()) msg.control_oids.push_back(ber_octet_string(cf[0].content));
            }
        }

        if (msg.message_type == "BindRequest") {
            decode_bind_request(msg, op.content);
        } else if (msg.message_type == "BindResponse") {
            apply_result_fields(msg, decode_ldap_result(op.content));
        } else if (msg.message_type == "SearchRequest") {
            decode_search_request(msg, op.content);
        } else if (msg.message_type == "SearchResultEntry") {
            decode_search_result_entry(msg, op.content);
        } else if (msg.message_type == "SearchResultDone") {
            apply_result_fields(msg, decode_ldap_result(op.content));
        } else if (msg.message_type == "SearchResultReference") {
            // SearchResultReference ::= [APPLICATION 19] SEQUENCE SIZE (1..MAX) OF uri LDAPURL --
            // APPLICATION 19 replaces the outer "SEQUENCE OF" tag itself, so op.content is a flat,
            // unwrapped list of OCTET STRING URIs directly (the same shape AND/OR's own filter list
            // has, not a nested SEQUENCE to peel first).
            const size_t kMaxUris = resource_limits().max_decoded_objects.value_or(50);
            for (const auto& u : ber_children(op.content)) {
                if (msg.referral_uris.size() >= kMaxUris) break;
                msg.referral_uris.push_back(ber_octet_string(u.content));
            }
        } else if (msg.message_type == "CompareRequest") {
            decode_compare_request(msg, op.content);
        } else if (msg.message_type == "CompareResponse") {
            apply_result_fields(msg, decode_ldap_result(op.content));
        } else if (msg.message_type == "AbandonRequest") {
            // AbandonRequest ::= [APPLICATION 16] MessageID -- context-PRIMITIVE (INTEGER), content
            // is the target messageID's own integer bytes directly.
            msg.abandon_message_id = ber_integer(op.content);
        } else if (msg.message_type == "ExtendedRequest") {
            decode_extended_request(msg, op.content);
        } else if (msg.message_type == "ExtendedResponse") {
            decode_extended_response(msg, op.content);
        }
        // else: UnbindRequest (NULL body, nothing to decode) and the structural-only ops --
        // recognized above via message_type/op_num/message_id alone, no field decode attempted.

        build_summary_and_notes(msg);
        return msg;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> ldap_tcp_declared_length(ByteSpan payload) {
    // Reuses it_protocols.hpp's own three-part structural check (SEQUENCE+length / INTEGER
    // messageID / APPLICATION-class protocolOp with a recognized op number) rather than
    // duplicating a second BER-envelope reader -- see ldap.hpp's own header comment.
    if (!looks_like_ldap_ber(payload)) return std::nullopt;
    if (payload.size() < 2) return std::nullopt;
    uint8_t len_byte = payload.at(1);
    size_t header_len;
    size_t content_len;
    if ((len_byte & 0x80) == 0) {
        header_len = 2;
        content_len = len_byte;
    } else {
        uint8_t num_octets = len_byte & 0x7F;
        if (num_octets == 0 || num_octets > 4) return std::nullopt;
        if (payload.size() < static_cast<size_t>(2 + num_octets)) return std::nullopt;
        content_len = 0;
        for (uint8_t i = 0; i < num_octets; ++i) content_len = (content_len << 8) | payload.at(2 + i);
        header_len = 2 + num_octets;
    }
    // A real LDAPMessage realistically never approaches this; same defense-in-depth posture
    // kerberos_tcp_declared_length's own kMaxPlausibleKerberosMessageLength takes. CLI-configurable
    // via --max-reassembly-bytes -- see resource_limits.hpp. 0/unset keeps the literal 1 MiB default.
    const size_t kMaxPlausibleLdapMessageLength = resource_limits().max_reassembly_bytes.value_or(1 << 20);
    if (content_len == 0 || content_len > kMaxPlausibleLdapMessageLength) return std::nullopt;
    return header_len + content_len;
}

namespace {

// Shared correlation layer, applied on top of a successfully try_parse_ldap'd message -- the same
// "try_parse_X then XDecoder::decode applies flow-state" split kerberos.cpp's own
// decode_with_correlation established. See ldap.hpp's header comment's STATE/CORRELATION section.
std::optional<ProtocolResult> decode_with_correlation(ByteSpan payload, DecodeContext& ctx) {
    auto parsed = try_parse_ldap(payload);
    if (!parsed) return std::nullopt;
    LdapMessage msg = std::move(*parsed);

    LdapFlowState& state = ctx.flow_state<LdapFlowState>();
    const size_t kMaxTrackedPerSession = resource_limits().max_decoded_objects.value_or(2000);

    if (msg.message_type == "ExtendedRequest" && msg.extended_request_name_known == "StartTLS") {
        state.starttls_seen = true;
    }

    if (msg.message_type == "BindRequest") {
        // Curated note 2 -- cleartext credential exposure without a prior StartTLS on this session.
        // A SASL PLAIN bind carries an authzid\0authcid\0password triple in the same credentials
        // field as `simple`'s own password -- treated identically here; any other SASL mechanism
        // (GSSAPI/DIGEST-MD5/EXTERNAL/...) is a negotiated, non-cleartext exchange and is not
        // flagged. The credential itself is never rendered (see ldap.hpp's own Wire format section).
        bool cleartext_credential_bind =
            msg.bind_credential_present &&
            (!msg.bind_is_sasl || ieq(msg.bind_auth_mechanism, "PLAIN"));
        if (cleartext_credential_bind && !state.starttls_seen) {
            msg.notes.push_back(
                "credential sent in cleartext (" +
                std::string(msg.bind_is_sasl ? "SASL PLAIN" : "simple") +
                " bind with a non-empty password) with no prior StartTLS ExtendedRequest observed on "
                "this session -- the credential itself is not inspected, but its exposure on the wire "
                "is");
        }
        if (state.pending_binds.size() < kMaxTrackedPerSession) {
            state.pending_binds[msg.message_id] = LdapPendingBind{ctx.packet_index};
        }
    } else if (msg.message_type == "BindResponse") {
        auto it = state.pending_binds.find(msg.message_id);
        if (it != state.pending_binds.end()) {
            msg.correlated_request_seen = true;
            msg.correlated_request_index = it->second.packet_index;
            state.pending_binds.erase(it);
        }
    } else if (msg.message_type == "SearchRequest") {
        if (state.pending_searches.size() < kMaxTrackedPerSession) {
            state.pending_searches[msg.message_id] = LdapPendingSearch{ctx.packet_index, 0};
        }
    } else if (msg.message_type == "SearchResultEntry") {
        auto it = state.pending_searches.find(msg.message_id);
        if (it != state.pending_searches.end()) {
            it->second.entry_count++;
            msg.correlated_request_seen = true;
            msg.correlated_request_index = it->second.packet_index;
        }
    } else if (msg.message_type == "SearchResultDone") {
        // The "keep across many responses, close on the terminal one" shape -- see ldap.hpp's own
        // header comment's STATE/CORRELATION section for why this differs from Kerberos's own
        // strict 1:1 pairing.
        auto it = state.pending_searches.find(msg.message_id);
        if (it != state.pending_searches.end()) {
            msg.correlated_request_seen = true;
            msg.correlated_request_index = it->second.packet_index;
            msg.search_entry_count = it->second.entry_count;
            msg.notes.push_back(
                std::to_string(it->second.entry_count) +
                " SearchResultEntry message(s) returned for this SearchRequest (packet #" +
                std::to_string(it->second.packet_index) + ")");
            state.pending_searches.erase(it);
        }
    }

    return ProtocolResult::make<LdapMessage>("ldap", std::move(msg));
}

}  // namespace

std::optional<ProtocolResult> LdapTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_correlation(payload, ctx);
}

const ProtocolDecoder& ldap_tcp_decoder() {
    static const LdapTcpDecoder instance;
    return instance;
}

}  // namespace conduitscope
