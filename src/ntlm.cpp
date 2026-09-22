// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ntlm.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// Full NegotiateFlags table (MS-NLMP's own NEGOTIATE structure table), verified during planning --
// see ntlm.hpp's file header comment and smb.hpp's own plan-provenance note. Rendered in this fixed
// bit order, low bit to high bit, not in wire order (NegotiateFlags is one 4-byte field, there is no
// wire order to preserve).
struct NegotiateFlagEntry {
    uint32_t mask;
    const char* name;
};

const std::vector<NegotiateFlagEntry>& negotiate_flag_table() {
    static const std::vector<NegotiateFlagEntry> table = {
        {0x00000001, "NTLMSSP_NEGOTIATE_UNICODE"},
        {0x00000002, "NTLM_NEGOTIATE_OEM"},
        {0x00000004, "NTLMSSP_REQUEST_TARGET"},
        {0x00000010, "NTLMSSP_NEGOTIATE_SIGN"},
        {0x00000020, "NTLMSSP_NEGOTIATE_SEAL"},
        {0x00000040, "NTLMSSP_NEGOTIATE_DATAGRAM"},
        {0x00000080, "NTLMSSP_NEGOTIATE_LM_KEY"},
        {0x00000200, "NTLMSSP_NEGOTIATE_NTLM"},
        {0x00000800, "NTLMSSP_NEGOTIATE_ANONYMOUS"},
        {0x00001000, "NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED"},
        {0x00002000, "NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED"},
        {0x00008000, "NTLMSSP_NEGOTIATE_ALWAYS_SIGN"},
        {0x00010000, "NTLMSSP_TARGET_TYPE_DOMAIN"},
        {0x00020000, "NTLMSSP_TARGET_TYPE_SERVER"},
        {0x00080000, "NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY"},
        {0x00100000, "NTLMSSP_NEGOTIATE_IDENTIFY"},
        {0x00400000, "NTLMSSP_REQUEST_NON_NT_SESSION_KEY"},
        {0x00800000, "NTLMSSP_NEGOTIATE_TARGET_INFO"},
        {0x02000000, "NTLMSSP_NEGOTIATE_VERSION"},
        {0x20000000, "NTLMSSP_NEGOTIATE_128"},
        {0x40000000, "NTLMSSP_NEGOTIATE_KEY_EXCH"},
        {0x80000000, "NTLMSSP_NEGOTIATE_56"},
    };
    return table;
}

std::vector<std::string> named_negotiate_flags(uint32_t flags) {
    std::vector<std::string> out;
    for (const auto& e : negotiate_flag_table()) {
        if (flags & e.mask) out.push_back(e.name);
    }
    return out;
}

const char* av_id_name(uint16_t id) {
    switch (id) {
        case 0: return "MsvAvEOL";
        case 1: return "MsvAvNbComputerName";
        case 2: return "MsvAvNbDomainName";
        case 3: return "MsvAvDnsComputerName";
        case 4: return "MsvAvDnsDomainName";
        case 5: return "MsvAvDnsTreeName";
        case 6: return "MsvAvFlags";
        case 7: return "MsvAvTimestamp";
        case 8: return "MsvAvSingleHost";
        case 9: return "MsvAvTargetName";
        case 10: return "MsvAvChannelBindings";
        default: return nullptr;
    }
}

bool av_id_is_string(uint16_t id) {
    return id == 1 || id == 2 || id == 3 || id == 4 || id == 5 || id == 9;
}

// One [Len, MaxLen, Offset] field descriptor, MS-NLMP sections 2.2.1.1-2.2.1.3 -- 8 bytes: 2-byte
// Len, 2-byte MaxLen (always equal to Len in practice, never rendered by this file), 4-byte
// little-endian Offset from the start of the enclosing NTLM message.
struct FieldDescriptor {
    uint16_t len = 0;
    uint32_t offset = 0;
};

FieldDescriptor read_field_descriptor(Cursor& c) {
    FieldDescriptor f;
    f.len = c.u16le();
    c.u16le();  // MaxLen -- read and discarded, see struct comment
    f.offset = c.u32le();
    return f;
}

// Bounds-checked: returns an empty span (never throws) if the descriptor's own [offset, offset+len)
// range doesn't fit inside `message` -- a malformed/truncated NTLM blob shouldn't abort the whole
// decode over one bad field, the same leniency this codebase's other embedded-payload parsers use.
ByteSpan field_bytes(ByteSpan message, const FieldDescriptor& f) {
    if (f.len == 0) return ByteSpan();
    if (static_cast<size_t>(f.offset) > message.size() ||
        static_cast<size_t>(f.len) > message.size() - f.offset) {
        return ByteSpan();
    }
    return message.subspan(f.offset, f.len);
}

// OEM strings (NEGOTIATE_MESSAGE's own DomainName/WorkstationName, and any type 2/3 field when
// NTLMSSP_NEGOTIATE_UNICODE is NOT set) are single-byte -- rendered as-is, one byte per char, the
// same "don't guess at a code page" posture applied everywhere else non-ASCII bytes might appear.
std::string oem_string(ByteSpan span) {
    std::string out;
    out.reserve(span.size());
    for (size_t i = 0; i < span.size(); ++i) out += static_cast<char>(span.at(i));
    return out;
}

std::string decoded_string(ByteSpan span, bool unicode) {
    return unicode ? utf16le_to_utf8(span) : oem_string(span);
}

// Best-effort MIC-presence heuristic for AUTHENTICATE_MESSAGE, per MS-NLMP section 2.2.1.3's own
// note that the MIC field is present "if... a version of NTLM that supports MIC is negotiated" --
// there is no dedicated flag bit for it. The common heuristic (also used by independent NTLM
// implementations, e.g. Wireshark's own dissector) is: MIC occupies a fixed 16-byte slot
// immediately after the fixed AUTHENTICATE_MESSAGE header (and after Version, when present) if the
// lowest payload offset among this message's own variable fields leaves a 16-byte gap unaccounted
// for. This is explicitly a heuristic, not an independently spec-confirmed structural read the way
// every other field in this file is -- see this file's header comment.
bool detect_mic_present(uint32_t header_end, const std::vector<uint32_t>& payload_offsets) {
    uint32_t min_offset = 0;
    bool have_min = false;
    for (uint32_t off : payload_offsets) {
        if (off == 0) continue;  // an absent field's own offset is often 0 -- not a real payload start
        if (!have_min || off < min_offset) {
            min_offset = off;
            have_min = true;
        }
    }
    if (!have_min) return false;
    if (min_offset < header_end) return false;  // malformed/overlapping -- don't guess
    return (min_offset - header_end) >= 16;
}

std::optional<NtlmMessage> parse_negotiate(ByteSpan message, Cursor& c) {
    NtlmMessage m;
    m.message_type_value = 1;
    m.message_type = "NEGOTIATE_MESSAGE";
    m.negotiate_flags = c.u32le();
    m.negotiate_flag_names = named_negotiate_flags(m.negotiate_flags);

    FieldDescriptor domain = read_field_descriptor(c);
    FieldDescriptor workstation = read_field_descriptor(c);

    bool has_domain = (m.negotiate_flags & 0x00001000) != 0;   // OEM_DOMAIN_SUPPLIED
    bool has_workstation = (m.negotiate_flags & 0x00002000) != 0;  // OEM_WORKSTATION_SUPPLIED
    if (has_domain) m.domain_name = oem_string(field_bytes(message, domain));
    if (has_workstation) m.workstation_name = oem_string(field_bytes(message, workstation));

    if ((m.negotiate_flags & 0x02000000) != 0 && c.remaining() >= 8) {  // NEGOTIATE_VERSION
        m.has_version = true;
        m.version_major = c.u8();
        m.version_minor = c.u8();
        m.version_build = c.u16le();
        c.skip(3);  // Reserved
        m.version_ntlm_revision = c.u8();
    }

    std::ostringstream s;
    s << "NTLM NEGOTIATE_MESSAGE";
    if (has_domain || has_workstation) {
        s << " (";
        if (has_workstation) s << m.workstation_name;
        if (has_domain && has_workstation) s << "\\";
        if (has_domain) s << m.domain_name;
        s << ")";
    }
    m.summary = s.str();
    return m;
}

std::optional<NtlmMessage> parse_challenge(ByteSpan message, Cursor& c) {
    NtlmMessage m;
    m.message_type_value = 2;
    m.message_type = "CHALLENGE_MESSAGE";

    FieldDescriptor target_name = read_field_descriptor(c);
    m.negotiate_flags = c.u32le();
    m.negotiate_flag_names = named_negotiate_flags(m.negotiate_flags);

    if (c.remaining() < 8) return std::nullopt;  // ServerChallenge
    ByteSpan challenge = c.bytes(8);
    m.has_server_challenge = true;
    m.server_challenge_hex = to_hex(challenge, "");

    if (c.remaining() < 8) return std::nullopt;  // Reserved
    c.skip(8);

    FieldDescriptor target_info = read_field_descriptor(c);

    if ((m.negotiate_flags & 0x02000000) != 0 && c.remaining() >= 8) {  // NEGOTIATE_VERSION
        m.has_version = true;
        m.version_major = c.u8();
        m.version_minor = c.u8();
        m.version_build = c.u16le();
        c.skip(3);
        m.version_ntlm_revision = c.u8();
    }

    bool unicode = (m.negotiate_flags & 0x00000001) != 0;
    ByteSpan target_name_bytes = field_bytes(message, target_name);
    if (!target_name_bytes.empty()) m.target_name = decoded_string(target_name_bytes, unicode);

    ByteSpan target_info_bytes = field_bytes(message, target_info);
    if (!target_info_bytes.empty()) {
        Cursor ic(target_info_bytes);
        // Capped the same way every other bounded-repeat decode in this codebase is -- an
        // AV_PAIR list terminates on MsvAvEOL, but a malformed/hostile blob could omit it, so the
        // loop is also bounded by the span running out (Cursor::remaining) rather than trusting
        // the terminator alone.
        while (ic.remaining() >= 4) {
            uint16_t id = ic.u16le();
            uint16_t len = ic.u16le();
            if (id == 0) break;  // MsvAvEOL
            if (len > ic.remaining()) break;  // malformed -- stop rather than throw past this loop
            ByteSpan value = ic.bytes(len);
            NtlmAvPair pair;
            pair.av_id = id;
            const char* name = av_id_name(id);
            pair.av_id_name = name ? name : ("AvId " + std::to_string(id));
            pair.byte_length = len;
            if (av_id_is_string(id)) {
                pair.is_string = true;
                pair.string_value = utf16le_to_utf8(value);
            } else if (id == 6 && len == 4) {
                Cursor fc(value);
                pair.has_flags_value = true;
                pair.flags_value = fc.u32le();
            }
            m.target_info.push_back(std::move(pair));
        }
    }

    std::ostringstream s;
    s << "NTLM CHALLENGE_MESSAGE";
    if (!m.target_name.empty()) s << " (target " << m.target_name << ")";
    m.summary = s.str();
    return m;
}

std::optional<NtlmMessage> parse_authenticate(ByteSpan message, Cursor& c) {
    NtlmMessage m;
    m.message_type_value = 3;
    m.message_type = "AUTHENTICATE_MESSAGE";

    FieldDescriptor lm_response = read_field_descriptor(c);
    FieldDescriptor nt_response = read_field_descriptor(c);
    FieldDescriptor domain = read_field_descriptor(c);
    FieldDescriptor user = read_field_descriptor(c);
    FieldDescriptor workstation = read_field_descriptor(c);
    FieldDescriptor session_key;
    bool has_session_key_field = c.remaining() >= 8;
    if (has_session_key_field) session_key = read_field_descriptor(c);
    if (c.remaining() < 4) return std::nullopt;
    m.negotiate_flags = c.u32le();
    m.negotiate_flag_names = named_negotiate_flags(m.negotiate_flags);

    uint32_t header_end = static_cast<uint32_t>(c.position());
    if ((m.negotiate_flags & 0x02000000) != 0 && c.remaining() >= 8) {  // NEGOTIATE_VERSION
        m.has_version = true;
        m.version_major = c.u8();
        m.version_minor = c.u8();
        m.version_build = c.u16le();
        c.skip(3);
        m.version_ntlm_revision = c.u8();
        header_end = static_cast<uint32_t>(c.position());
    }

    m.mic_present = detect_mic_present(
        header_end, {lm_response.offset, nt_response.offset, domain.offset, user.offset,
                      workstation.offset, session_key.offset});

    bool unicode = (m.negotiate_flags & 0x00000001) != 0;
    ByteSpan domain_bytes = field_bytes(message, domain);
    ByteSpan user_bytes = field_bytes(message, user);
    ByteSpan workstation_bytes = field_bytes(message, workstation);
    if (!domain_bytes.empty()) m.auth_domain_name = decoded_string(domain_bytes, unicode);
    if (!user_bytes.empty()) m.user_name = decoded_string(user_bytes, unicode);
    if (!workstation_bytes.empty()) m.auth_workstation_name = decoded_string(workstation_bytes, unicode);

    // Credential/keying material -- presence + byte length ONLY, see this file's header comment.
    m.lm_challenge_response_present = lm_response.len > 0;
    m.lm_challenge_response_length = lm_response.len;
    m.nt_challenge_response_present = nt_response.len > 0;
    m.nt_challenge_response_length = nt_response.len;
    if (has_session_key_field) {
        m.encrypted_random_session_key_present = session_key.len > 0;
        m.encrypted_random_session_key_length = session_key.len;
    }

    std::ostringstream s;
    s << "NTLM AUTHENTICATE_MESSAGE";
    if (!m.user_name.empty()) {
        s << " (";
        if (!m.auth_domain_name.empty()) s << m.auth_domain_name << "\\";
        s << m.user_name << ")";
    }
    m.summary = s.str();
    return m;
}

}  // namespace

std::optional<NtlmMessage> try_parse_ntlm(ByteSpan message) {
    try {
        if (message.size() < 12) return std::nullopt;
        for (size_t i = 0; i < 8; ++i) {
            if (message.at(i) != static_cast<uint8_t>(kNtlmSignature[i])) return std::nullopt;
        }
        Cursor c(message);
        c.skip(8);
        uint32_t message_type = c.u32le();
        switch (message_type) {
            case 1:
                return parse_negotiate(message, c);
            case 2:
                return parse_challenge(message, c);
            case 3:
                return parse_authenticate(message, c);
            default:
                return std::nullopt;
        }
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

}  // namespace conduitscope
