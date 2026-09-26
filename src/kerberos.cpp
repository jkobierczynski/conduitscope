// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/kerberos.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// ==============================================================================================
// BER (ASN.1 Basic Encoding Rules) TLV reading -- adapted from mms.cpp's own BerTlv/
// read_ber_tlv/ber_children/ber_integer, kept as a separate, self-contained copy per this
// codebase's established convention (see this file's own header comment). Kerberos only ever
// needs the low-tag-number form (every tag number used here is <= 30), so the high-tag-number
// multi-byte form mms.cpp's own reader supports is trimmed out here as genuinely unneeded, not
// merely unused.

struct BerTlv {
    uint8_t tag_byte = 0;
    uint32_t tag_number = 0;
    bool constructed = false;
    ByteSpan content;
    size_t total_len = 0;
};

uint8_t ber_class(uint8_t tag_byte) { return tag_byte & 0xC0; }
constexpr uint8_t kBerClassContext = 0x80;

BerTlv read_ber_tlv(ByteSpan buf) {
    if (buf.size() < 2) throw ParseError("Kerberos BER TLV: need at least 2 bytes for tag+length");
    Cursor c(buf);
    BerTlv tlv;
    tlv.tag_byte = c.u8();
    tlv.constructed = (tlv.tag_byte & 0x20) != 0;
    uint32_t tag_low = tlv.tag_byte & 0x1F;
    if (tag_low == 0x1F) {
        // High-tag-number form -- never actually used by any Kerberos field this decoder reads,
        // but rejected explicitly (rather than silently misparsed) if ever encountered.
        throw ParseError("Kerberos BER TLV: high-tag-number form not supported (not used by RFC 4120)");
    }
    tlv.tag_number = tag_low;
    uint8_t len_byte = c.u8();
    size_t length;
    if (len_byte & 0x80) {
        uint8_t num_octets = len_byte & 0x7F;
        if (num_octets == 0) throw ParseError("Kerberos BER TLV: indefinite length not supported (DER forbids it)");
        if (num_octets > 4) throw ParseError("Kerberos BER TLV: length field implausibly wide");
        length = 0;
        for (uint8_t i = 0; i < num_octets; ++i) length = (length << 8) | c.u8();
    } else {
        length = len_byte;
    }
    tlv.content = c.bytes(length);
    tlv.total_len = c.position();
    return tlv;
}

// Splits `buf` into its top-level TLVs only (does not recurse).
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

// Peels one layer of explicit tagging: given a context tag's own content (e.g. `pvno [1]
// INTEGER`'s content, which under explicit tagging is itself a nested, fully-formed TLV -- here
// the UNIVERSAL INTEGER tag+length+value, not the raw integer bytes directly), returns that
// nested TLV. Every context-tagged field in this file goes through this once before its value is
// decoded, since RFC 4120's ASN.1 module uses ordinary (explicit) tagging throughout, not
// IMPLICIT -- confirmed against real Kerberos wire captures, which always show a nested
// UNIVERSAL-class tag (0x02 INTEGER, 0x1B GeneralString, 0x03 BIT STRING, 0x18 GeneralizedTime,
// 0x30 SEQUENCE, or another APPLICATION tag for an embedded Ticket) immediately inside a
// context tag's own content, never the bare value.
BerTlv explicit_child(ByteSpan content) { return read_ber_tlv(content); }

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
    // outright as of C++20. Mirrors ber_unsigned just below, which was already unsigned throughout
    // and never had this problem.
    uint64_t v = (content.at(0) & 0x80) ? ~uint64_t{0} : 0;
    for (size_t i = 0; i < content.size(); ++i) v = (v << 8) | content.at(i);
    return static_cast<int64_t>(v);
}

std::string ber_visible_string(ByteSpan content) {
    return std::string(reinterpret_cast<const char*>(content.data()), content.size());
}

// BIT STRING content (first byte = unused-bit count, remaining bytes = the bits, MSB-first) ->
// the set bit INDEXES (0-based) -- adapted from mms.cpp's own bitstring_set_bits.
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

// KerberosTime (ASN.1 GeneralizedTime, UNIVERSAL 24) -- adapted from mms.cpp's own
// format_generalized_time; the underlying ASN.1 type and RFC 4120's own restriction to the
// strict "YYYYMMDDHHMMSSZ" DER form make this identical logic to MMS's FileAttributes timestamp.
std::string format_kerberos_time(ByteSpan content) {
    std::string raw(reinterpret_cast<const char*>(content.data()), content.size());
    if (raw.size() < 14) return raw;
    for (int i = 0; i < 14; ++i) {
        if (raw[static_cast<size_t>(i)] < '0' || raw[static_cast<size_t>(i)] > '9') return raw;
    }
    std::string zone = raw.substr(14);  // "Z" per RFC 4120's own restriction, shown verbatim either way
    std::ostringstream s;
    s << raw.substr(0, 4) << "-" << raw.substr(4, 2) << "-" << raw.substr(6, 2) << "T" << raw.substr(8, 2)
      << ":" << raw.substr(10, 2) << ":" << raw.substr(12, 2) << zone;
    return s.str();
}

// ==============================================================================================
// Named lookup tables -- every one falls back to a raw numeric rendering for anything not listed,
// the same graceful-degradation posture every existing named-enum table in this codebase takes.

std::string padata_type_name(int64_t type) {
    switch (type) {
        case 1: return "PA-TGS-REQ";
        case 2: return "PA-ENC-TIMESTAMP";
        case 3: return "PA-PW-SALT";
        case 11: return "PA-ETYPE-INFO";
        case 19: return "PA-ETYPE-INFO2";
        case 128: return "PA-PAC-REQUEST";
        case 129: return "PA-FOR-USER";  // S4U2Self -- see this file's delegation-shape note
        case 167: return "PA-PAC-OPTIONS";
        default: return "padata-type " + std::to_string(type);
    }
}

std::string etype_name(int64_t etype) {
    switch (etype) {
        case 1: return "des-cbc-crc";
        case 3: return "des-cbc-md5";
        case 17: return "aes128-cts-hmac-sha1-96";
        case 18: return "aes256-cts-hmac-sha1-96";
        case 23: return "rc4-hmac";
        case 24: return "rc4-hmac-exp";
        default: return "etype " + std::to_string(etype);
    }
}

bool etype_is_weak(const std::string& name) {
    return name == "des-cbc-crc" || name == "des-cbc-md5" || name == "rc4-hmac" || name == "rc4-hmac-exp";
}

bool etype_is_aes(const std::string& name) {
    return name == "aes128-cts-hmac-sha1-96" || name == "aes256-cts-hmac-sha1-96";
}

std::string kdc_error_name(int64_t code) {
    switch (code) {
        case 6: return "KDC_ERR_C_PRINCIPAL_UNKNOWN";
        case 7: return "KDC_ERR_S_PRINCIPAL_UNKNOWN";
        case 14: return "KDC_ERR_ETYPE_NOSUPP";
        case 18: return "KDC_ERR_CLIENT_REVOKED";
        case 24: return "KDC_ERR_PREAUTH_FAILED";
        case 25: return "KDC_ERR_PREAUTH_REQUIRED";
        case 37: return "KRB_AP_ERR_SKEW";
        default: return "error " + std::to_string(code);
    }
}

// KDCOptions/KDC-REQ-BODY's own flags (KerberosFlags, a BIT STRING) -- named subset relevant to
// the delegation-shape note; every other bit renders as "bit N" via the fallback below.
std::string kdc_option_flag_name(int bit) {
    switch (bit) {
        case 1: return "forwardable";
        case 2: return "forwarded";
        case 3: return "proxiable";
        case 4: return "proxy";
        case 5: return "allow-postdate";
        case 6: return "postdated";
        case 8: return "renewable";
        case 15: return "canonicalize";
        case 26: return "disable-transited-check";
        case 27: return "renewable-ok";
        case 28: return "enc-tkt-in-skey";
        case 30: return "renew";
        case 31: return "validate";
        default: return "bit " + std::to_string(bit);
    }
}

std::string ap_option_flag_name(int bit) {
    switch (bit) {
        case 1: return "use-session-key";
        case 2: return "mutual-required";
        default: return "bit " + std::to_string(bit);
    }
}

std::vector<std::string> render_flags(ByteSpan bitstring_content, std::string (*name_fn)(int)) {
    std::vector<std::string> names;
    for (int bit : bitstring_set_bits(bitstring_content)) names.push_back(name_fn(bit));
    return names;
}

// PrincipalName ::= SEQUENCE { name-type [0] Int32, name-string [1] SEQUENCE OF KerberosString }
// -- rendered "component/component/..." (name-type itself isn't rendered; it distinguishes
// NT-PRINCIPAL/NT-SRV-INST/NT-ENTERPRISE/etc., none of which change how this decoder uses the
// name). `wrapped_content` is a context field's own content (still explicitly-tagged) -- callers
// pass e.g. `field.content` for a `cname [1] PrincipalName` field.
std::string decode_principal_name(ByteSpan wrapped_content) {
    BerTlv seq = explicit_child(wrapped_content);  // peel to the PrincipalName SEQUENCE itself
    std::vector<std::string> components;
    for (const auto& f : ber_children(seq.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        if (f.tag_number == 1) {  // name-string
            BerTlv name_string_seq = explicit_child(f.content);
            for (const auto& component : ber_children(name_string_seq.content)) {
                components.push_back(ber_visible_string(component.content));
            }
        }
    }
    std::ostringstream s;
    for (size_t i = 0; i < components.size(); ++i) {
        if (i) s << "/";
        s << components[i];
    }
    return s.str();
}

// Realm ::= KerberosString -- a single GeneralString, not wrapped in a further SEQUENCE.
std::string decode_realm(ByteSpan wrapped_content) {
    BerTlv str = explicit_child(wrapped_content);
    return ber_visible_string(str.content);
}

// etype [8] SEQUENCE OF Int32 -- each element is a plain, unwrapped INTEGER (SEQUENCE OF
// elements carry no per-element context tag, unlike structure fields).
std::vector<std::string> decode_etype_list(ByteSpan wrapped_content) {
    BerTlv seq = explicit_child(wrapped_content);
    std::vector<std::string> names;
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 50 default (mirrors this codebase's other "N items per message" caps, e.g. HART-IP/
    // MQTT/OPC UA's own kMax*MessagesPerPayload defaults).
    const size_t kMaxEtypesRendered = resource_limits().max_decoded_objects.value_or(50);
    for (const auto& elem : ber_children(seq.content)) {
        if (names.size() >= kMaxEtypesRendered) break;
        names.push_back(etype_name(ber_integer(elem.content)));
    }
    return names;
}

// EncryptedData ::= SEQUENCE { etype [0] Int32, kvno [1] UInt32 OPTIONAL, cipher [2] OCTET
// STRING } -- only etype is ever read here; the ciphertext is opaque without keys (see this
// file's header comment).
std::string decode_encrypted_data_etype(ByteSpan wrapped_content) {
    BerTlv seq = explicit_child(wrapped_content);
    for (const auto& f : ber_children(seq.content)) {
        if (ber_class(f.tag_byte) == kBerClassContext && f.tag_number == 0) {
            BerTlv etype_tlv = explicit_child(f.content);
            return etype_name(ber_integer(etype_tlv.content));
        }
    }
    return "";
}

// Ticket ::= [APPLICATION 1] SEQUENCE { tkt-vno [0] INTEGER, realm [1] Realm,
// sname [2] PrincipalName, enc-part [3] EncryptedData } -- Ticket carries its own APPLICATION
// tag (baked into its own ASN.1 definition), so this peels TWO layers: the caller's context
// wrapper, then Ticket's own APPLICATION tag, before reaching the inner SEQUENCE's fields.
struct DecodedTicket {
    uint8_t tkt_vno = 0;
    std::string realm;
    std::string sname;
    std::string enc_part_etype;
};

DecodedTicket decode_ticket(ByteSpan wrapped_content) {
    BerTlv app_tag = explicit_child(wrapped_content);      // peel the caller's context wrapper
    BerTlv seq = explicit_child(app_tag.content);           // peel Ticket's own [APPLICATION 1]
    DecodedTicket t;
    for (const auto& f : ber_children(seq.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 0: {
                BerTlv v = explicit_child(f.content);
                t.tkt_vno = static_cast<uint8_t>(ber_integer(v.content));
                break;
            }
            case 1: t.realm = decode_realm(f.content); break;
            case 2: t.sname = decode_principal_name(f.content); break;
            case 3: t.enc_part_etype = decode_encrypted_data_etype(f.content); break;
            default: break;
        }
    }
    return t;
}

}  // namespace

std::optional<std::string> kerberos_message_type_name(uint8_t msg_type) {
    switch (static_cast<KerberosMessageType>(msg_type)) {
        case KerberosMessageType::AsReq: return "AS-REQ";
        case KerberosMessageType::AsRep: return "AS-REP";
        case KerberosMessageType::TgsReq: return "TGS-REQ";
        case KerberosMessageType::TgsRep: return "TGS-REP";
        case KerberosMessageType::ApReq: return "AP-REQ";
        case KerberosMessageType::ApRep: return "AP-REP";
        case KerberosMessageType::KrbError: return "KRB-ERROR";
    }
    return std::nullopt;
}

namespace {

// The outer APPLICATION tag byte for each of the seven recognized message types is 0x60
// (class=Application, constructed) OR'd with the message-type value, since every value here fits
// the ASN.1 low-tag-number form (0-30) -- hence the fixed 7-value table below rather than a
// computed check against every possible msg_type.
bool is_recognized_outer_tag(uint8_t tag_byte) {
    static const uint8_t kRecognized[] = {0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x7E};
    for (uint8_t t : kRecognized) {
        if (tag_byte == t) return true;
    }
    return false;
}

// Decodes req-body's own fields (KDC-REQ-BODY, see this file's header comment for the full tag
// layout) into `msg`. `wrapped_content` is the req-body field's own content (still
// explicitly-tagged).
void decode_req_body(KerberosMessage& msg, ByteSpan wrapped_content, bool is_as_req) {
    BerTlv seq = explicit_child(wrapped_content);
    for (const auto& f : ber_children(seq.content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 0: {  // kdc-options
                BerTlv v = explicit_child(f.content);
                msg.kdc_options = render_flags(v.content, kdc_option_flag_name);
                break;
            }
            case 1:  // cname -- AS-REQ only per RFC 4120's own comment
                if (is_as_req) msg.cname = decode_principal_name(f.content);
                break;
            case 2: msg.realm = decode_realm(f.content); break;
            case 3: msg.sname = decode_principal_name(f.content); break;
            case 5: {  // till
                BerTlv v = explicit_child(f.content);
                msg.till = format_kerberos_time(v.content);
                break;
            }
            case 7: {  // nonce
                BerTlv v = explicit_child(f.content);
                msg.nonce = static_cast<uint32_t>(ber_integer(v.content));
                break;
            }
            case 8:  // etype
                msg.etypes = decode_etype_list(f.content);
                break;
            case 11:  // additional-tickets
                msg.has_additional_tickets = true;
                break;
            default: break;
        }
    }
}

// Decodes padata (SEQUENCE OF PA-DATA, each element itself a SEQUENCE { padata-type [1] Int32,
// padata-value [2] OCTET STRING } -- SEQUENCE OF elements carry no per-element context tag, so
// each is read as a plain SEQUENCE directly) into `msg.padata_types`/`msg.has_pa_enc_timestamp`.
void decode_padata(KerberosMessage& msg, ByteSpan wrapped_content) {
    BerTlv seq = explicit_child(wrapped_content);
    const size_t kMaxPadataRendered = resource_limits().max_decoded_objects.value_or(50);
    for (const auto& entry : ber_children(seq.content)) {
        if (msg.padata_types.size() >= kMaxPadataRendered) break;
        int64_t type = -1;
        for (const auto& f : ber_children(entry.content)) {
            if (ber_class(f.tag_byte) == kBerClassContext && f.tag_number == 1) {
                BerTlv v = explicit_child(f.content);
                type = ber_integer(v.content);
            }
        }
        if (type < 0) continue;
        msg.padata_types.push_back(padata_type_name(type));
        if (type == 2) msg.has_pa_enc_timestamp = true;
    }
}

// Decodes ticket [5] Ticket + enc-part [6] EncryptedData -- shared shape for KDC-REP's own
// crealm/cname/ticket/enc-part fields.
void decode_kdc_rep(KerberosMessage& msg, ByteSpan seq_content) {
    // CLI-configurable recursion-depth-style guard isn't needed here -- KDC-REP's own nesting is
    // shallow and spec-fixed (crealm/cname/ticket/enc-part, no recursive structure), unlike
    // MMS's genuinely open-ended Data CHOICE. Kept flat, matching KRB-ERROR/AP-REQ/AP-REP below.
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 2: decode_padata(msg, f.content); break;
            case 3: msg.crealm = decode_realm(f.content); break;
            case 4: msg.cname = decode_principal_name(f.content); break;
            case 5: {
                DecodedTicket t = decode_ticket(f.content);
                msg.has_ticket = true;
                msg.ticket_tkt_vno = t.tkt_vno;
                msg.ticket_realm = t.realm;
                msg.ticket_sname = t.sname;
                msg.ticket_enc_part_etype = t.enc_part_etype;
                break;
            }
            case 6:
                msg.has_enc_part = true;
                msg.enc_part_etype = decode_encrypted_data_etype(f.content);
                break;
            default: break;
        }
    }
}

void decode_krb_error(KerberosMessage& msg, ByteSpan seq_content) {
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 6: {  // error-code
                BerTlv v = explicit_child(f.content);
                msg.error_code = static_cast<uint32_t>(ber_integer(v.content));
                msg.error_name = kdc_error_name(msg.error_code);
                break;
            }
            case 8: msg.cname = decode_principal_name(f.content); break;
            case 9: msg.realm = decode_realm(f.content); break;
            case 10: msg.sname = decode_principal_name(f.content); break;
            case 11: msg.error_text = decode_realm(f.content); break;  // e-text -- same KerberosString shape
            default: break;
        }
    }
}

void decode_ap_req(KerberosMessage& msg, ByteSpan seq_content) {
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) != kBerClassContext) continue;
        switch (f.tag_number) {
            case 2: {  // ap-options
                BerTlv v = explicit_child(f.content);
                msg.ap_options = render_flags(v.content, ap_option_flag_name);
                break;
            }
            case 3: {  // ticket
                DecodedTicket t = decode_ticket(f.content);
                msg.has_ticket = true;
                msg.ticket_tkt_vno = t.tkt_vno;
                msg.ticket_realm = t.realm;
                msg.ticket_sname = t.sname;
                msg.ticket_enc_part_etype = t.enc_part_etype;
                break;
            }
            case 4:  // authenticator -- EncryptedData, only its etype is ever read (see header comment)
                msg.has_enc_part = true;
                msg.enc_part_etype = decode_encrypted_data_etype(f.content);
                break;
            default: break;
        }
    }
}

void decode_ap_rep(KerberosMessage& msg, ByteSpan seq_content) {
    for (const auto& f : ber_children(seq_content)) {
        if (ber_class(f.tag_byte) == kBerClassContext && f.tag_number == 2) {  // enc-part
            msg.has_enc_part = true;
            msg.enc_part_etype = decode_encrypted_data_etype(f.content);
        }
    }
}

// Builds the human-readable summary/curated notes once every field is decoded. Split out of
// try_parse_kerberos so it's easy to see, in one place, exactly what each curated
// attack/monitoring note's trigger condition is -- see this file's header comment for the
// rationale behind each one. Session-correlated notes (the AS-REP-Roasting/Kerberoasting
// flagship flags) are NOT added here -- those need cross-packet state and are added by
// KerberosTcpDecoder::decode/KerberosUdpDecoder::decode after this function returns.
void build_summary_and_notes(KerberosMessage& msg) {
    std::ostringstream s;
    s << msg.message_type;
    bool is_request = (msg.message_type == "AS-REQ" || msg.message_type == "TGS-REQ");
    if (is_request) {
        s << " cname=" << (msg.cname.empty() ? "(none)" : msg.cname) << " sname=" << msg.sname
          << " realm=\"" << msg.realm << "\"";
        if (!msg.etypes.empty()) {
            s << " etype=[";
            for (size_t i = 0; i < msg.etypes.size(); ++i) {
                if (i) s << ",";
                s << msg.etypes[i];
            }
            s << "]";
        }

        // Note 1 (standing half) -- AS-REP Roasting request shape. See header comment.
        if (msg.message_type == "AS-REQ" && !msg.has_pa_enc_timestamp) {
            msg.notes.push_back(
                "AS-REQ has no PA-ENC-TIMESTAMP pre-authentication data -- AS-REP-Roasting-style "
                "request shape; the KDC will either reject this with a preauth-required error, or -- "
                "if this account has pre-authentication disabled -- return a working, crackable "
                "AS-REP (see the AS-REP if/when it arrives)");
        }

        // Note 3 -- weak-encryption/downgrade visibility, always-on, not attack-specific.
        bool any_weak = false, any_aes = false;
        for (const auto& e : msg.etypes) {
            if (etype_is_weak(e)) any_weak = true;
            if (etype_is_aes(e)) any_aes = true;
        }
        if (any_weak && !any_aes) {
            msg.notes.push_back(
                "offered encryption types are DES/RC4 only, no AES type offered -- weak-encryption "
                "exposure, worth confirming this client/account isn't unnecessarily restricted to "
                "legacy crypto");
        }

        // Note 4 -- delegation-shape surfacing, structural only.
        std::vector<std::string> delegation_flags;
        for (const auto& f : msg.kdc_options) {
            if (f == "forwardable" || f == "proxiable" || f == "proxy") delegation_flags.push_back(f);
        }
        if (!delegation_flags.empty() || msg.has_additional_tickets) {
            std::ostringstream d;
            d << "delegation-relevant shape:";
            for (const auto& f : delegation_flags) d << " " << f;
            if (msg.has_additional_tickets) d << " additional-tickets-present (S4U2Proxy shape)";
            d << " -- surfaces the wire-level shape unconstrained/constrained delegation relies on, "
                 "not an assertion of abuse";
            msg.notes.push_back(d.str());
        }
    } else if (msg.message_type == "AS-REP" || msg.message_type == "TGS-REP") {
        s << " cname=" << msg.cname << " ticket-sname=" << msg.ticket_sname << " enc-part-etype="
          << msg.enc_part_etype;

        // Note 2 -- Kerberoasting. See header comment. Keys off the embedded Ticket's OWN
        // enc-part etype (ticket_enc_part_etype), not the response's own outer enc-part etype
        // (enc_part_etype, checked separately by the downgrade note in build_summary_and_notes)
        // -- the outer enc-part is encrypted to the REQUESTING CLIENT's session key and says
        // nothing about the target service account, while the Ticket's enc-part is encrypted to
        // the target service's own long-term key, which is exactly the material Kerberoasting
        // cracks offline. krbtgt tickets are excluded (that's a normal TGT, not a service ticket
        // -- flagging every RC4 TGT on a mixed-etype domain would be noisy and not what
        // Kerberoasting actually targets).
        if (msg.message_type == "TGS-REP" && msg.has_ticket && etype_is_weak(msg.ticket_enc_part_etype) &&
            msg.ticket_sname.rfind("krbtgt", 0) != 0) {
            msg.notes.push_back(
                "this service ticket's encrypted part uses " + msg.ticket_enc_part_etype +
                " -- crackable offline if this SPN's account is compromised via Kerberoasting; a "
                "fully AES-only domain would not produce this (reflects the target account's "
                "configured encryption types, not proof an attack tool was used)");
        }
    } else if (msg.message_type == "KRB-ERROR") {
        s << " error=" << msg.error_name;
        if (!msg.error_text.empty()) s << " (\"" << msg.error_text << "\")";
        if (!msg.sname.empty()) s << " sname=" << msg.sname;
    } else if (msg.message_type == "AP-REQ") {
        s << " ticket-sname=" << msg.ticket_sname;
        if (!msg.ap_options.empty()) {
            s << " ap-options=[";
            for (size_t i = 0; i < msg.ap_options.size(); ++i) {
                if (i) s << ",";
                s << msg.ap_options[i];
            }
            s << "]";
        }
    } else if (msg.message_type == "AP-REP") {
        s << " enc-part-etype=" << msg.enc_part_etype;
    }
    msg.summary = s.str();
}

}  // namespace

std::optional<KerberosMessage> try_parse_kerberos(ByteSpan message) {
    if (message.size() < 2) return std::nullopt;
    try {
        BerTlv outer = read_ber_tlv(message);
        if (!is_recognized_outer_tag(outer.tag_byte)) return std::nullopt;
        uint8_t msg_type_from_tag = static_cast<uint8_t>(outer.tag_byte & 0x1F);
        // 0x7E's low 5 bits are 0x1E==30, matching KRB-ERROR's own message-type value directly --
        // no special-casing needed despite KRB-ERROR's tag number (30) exceeding the other six.
        auto name = kerberos_message_type_name(msg_type_from_tag);
        if (!name) return std::nullopt;

        BerTlv seq = explicit_child(outer.content);  // peel to the inner UNIVERSAL SEQUENCE

        bool is_kdc_req = (msg_type_from_tag == 10 || msg_type_from_tag == 12);
        // KDC-REQ's own pvno/msg-type sit at context [1]/[2]; every other shape (KDC-REP/
        // KRB-ERROR/AP-REQ/AP-REP) uses [0]/[1] -- a real, RFC-4120-mandated difference between
        // request and response ASN.1 modules, not an inconsistency in this decoder.
        uint8_t pvno_tag = is_kdc_req ? 1 : 0;
        uint8_t msg_type_tag = is_kdc_req ? 2 : 1;

        std::optional<uint8_t> pvno;
        std::optional<uint8_t> msg_type_field;
        std::vector<BerTlv> top_fields = ber_children(seq.content);
        for (const auto& f : top_fields) {
            if (ber_class(f.tag_byte) != kBerClassContext) continue;
            if (f.tag_number == pvno_tag && !pvno) {
                BerTlv v = explicit_child(f.content);
                pvno = static_cast<uint8_t>(ber_integer(v.content));
            } else if (f.tag_number == msg_type_tag && !msg_type_field) {
                BerTlv v = explicit_child(f.content);
                msg_type_field = static_cast<uint8_t>(ber_integer(v.content));
            }
        }
        // Structural gate's strong half: pvno must be 5, AND msg-type must agree with the outer
        // APPLICATION tag -- see this file's header comment for why this two-field cross-check
        // (not just the leading tag byte) is what actually makes this gate collision-resistant.
        if (!pvno || *pvno != 5) return std::nullopt;
        if (!msg_type_field || *msg_type_field != msg_type_from_tag) return std::nullopt;

        KerberosMessage msg;
        msg.message_type = *name;
        msg.msg_type_value = msg_type_from_tag;
        msg.pvno = *pvno;
        msg.is_response = (msg.message_type != "AS-REQ" && msg.message_type != "TGS-REQ" &&
                            msg.message_type != "AP-REQ");

        if (is_kdc_req) {
            bool is_as_req = (msg_type_from_tag == 10);
            for (const auto& f : top_fields) {
                if (ber_class(f.tag_byte) != kBerClassContext) continue;
                if (f.tag_number == 3) decode_padata(msg, f.content);
                if (f.tag_number == 4) decode_req_body(msg, f.content, is_as_req);
            }
        } else if (msg.message_type == "AS-REP" || msg.message_type == "TGS-REP") {
            decode_kdc_rep(msg, seq.content);
        } else if (msg.message_type == "KRB-ERROR") {
            decode_krb_error(msg, seq.content);
        } else if (msg.message_type == "AP-REQ") {
            decode_ap_req(msg, seq.content);
        } else if (msg.message_type == "AP-REP") {
            decode_ap_rep(msg, seq.content);
        }

        build_summary_and_notes(msg);
        return msg;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> kerberos_tcp_declared_length(ByteSpan payload) {
    if (payload.size() < 5) return std::nullopt;  // 4-byte length prefix + >=1 byte to peek at
    Cursor c(payload);
    uint32_t declared = c.u32be();
    // A real Kerberos-over-TCP message realistically never approaches this; guards against a
    // coincidentally plausible but wildly large declared length being mistaken for a genuine
    // frame split across TCP segments and buffered forever -- same defense-in-depth posture
    // modbus.cpp's own kMaxPlausibleMbapLength/twincat.cpp's kMaxPlausibleAdsDataLength take.
    // CLI-configurable via --max-reassembly-bytes -- see resource_limits.hpp. 0/unset keeps the
    // literal 1 MiB default.
    const size_t kMaxPlausibleKerberosMessageLength = resource_limits().max_reassembly_bytes.value_or(1 << 20);
    if (declared == 0 || declared > kMaxPlausibleKerberosMessageLength) return std::nullopt;
    if (!is_recognized_outer_tag(c.u8())) return std::nullopt;
    return 4 + static_cast<size_t>(declared);
}

namespace {

// Shared by both KerberosTcpDecoder::decode/KerberosUdpDecoder::decode -- applies session-scoped
// AS-REQ/TGS-REQ<->AS-REP/TGS-REP correlation on top of a successfully try_parse_kerberos'd
// message, the same "try_parse_X then XDecoder::decode applies flow-state" split
// TwinCAT/Modbus/HART-IP already established. See kerberos.hpp's header comment's
// STATE/CORRELATION section for the design and its documented limitation.
std::optional<ProtocolResult> decode_with_correlation(ByteSpan payload, DecodeContext& ctx) {
    auto parsed = try_parse_kerberos(payload);
    if (!parsed) return std::nullopt;
    KerberosMessage msg = std::move(*parsed);

    KerberosFlowState& state = ctx.flow_state<KerberosFlowState>();
    // Same capacity guard TwinCAT/Modbus apply to their own pending-request maps.
    const size_t kMaxTrackedRequestsPerSession = resource_limits().max_decoded_objects.value_or(2000);

    if (msg.message_type == "AS-REQ" && !msg.cname.empty()) {
        if (state.pending_as_req.size() < kMaxTrackedRequestsPerSession) {
            state.pending_as_req[msg.cname] = KerberosPendingRequest{ctx.packet_index, !msg.has_pa_enc_timestamp};
        }
    } else if (msg.message_type == "AS-REP") {
        auto it = state.pending_as_req.find(msg.cname);
        if (it != state.pending_as_req.end()) {
            msg.correlated_request_seen = true;
            msg.correlated_request_index = it->second.packet_index;
            // Flagship flag (Note 1's correlated half) -- a SUCCESSFUL AS-REP (this is one, or
            // try_parse_kerberos wouldn't have returned a KerberosMessage with message_type ==
            // "AS-REP" at all -- a KRB-ERROR is a structurally different message) answering an
            // AS-REQ that had no PA-ENC-TIMESTAMP. See kerberos.hpp header comment.
            if (it->second.had_no_preauth) {
                msg.notes.push_back(
                    "AS-REP Roasting: this is a successful, crackable AS-REP answering an AS-REQ "
                    "(packet #" + std::to_string(it->second.packet_index) +
                    ") that included no pre-authentication proof -- the target account likely has "
                    "Kerberos pre-authentication disabled");
            }
            state.pending_as_req.erase(it);
        }
    } else if (msg.message_type == "TGS-REQ" && !msg.sname.empty()) {
        if (state.pending_tgs_req.size() < kMaxTrackedRequestsPerSession) {
            state.pending_tgs_req[msg.sname] = KerberosPendingRequest{ctx.packet_index, false};
        }
    } else if (msg.message_type == "TGS-REP") {
        auto it = state.pending_tgs_req.find(msg.ticket_sname);
        if (it != state.pending_tgs_req.end()) {
            msg.correlated_request_seen = true;
            msg.correlated_request_index = it->second.packet_index;
            state.pending_tgs_req.erase(it);
        }
    }

    return ProtocolResult::make<KerberosMessage>("kerberos", std::move(msg));
}

}  // namespace

std::optional<ProtocolResult> KerberosTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    // Strip the 4-byte big-endian length prefix (RFC 4120 SS7.2.2) before handing the de-framed
    // ASN.1 message to the shared correlation logic below -- `payload` here is the full candidate
    // decoder.cpp's TCP reassembly cascade already sized against kerberos_tcp_declared_length's
    // own declared length (prefix included), unlike UDP's decode() just below, which receives the
    // raw datagram with no framing of its own to strip.
    if (payload.size() < 5) return std::nullopt;
    return decode_with_correlation(payload.from(4), ctx);
}

std::optional<ProtocolResult> KerberosUdpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_correlation(payload, ctx);
}

const ProtocolDecoder& kerberos_tcp_decoder() {
    static const KerberosTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& kerberos_udp_decoder() {
    static const KerberosUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
