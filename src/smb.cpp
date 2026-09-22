// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/smb.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// ---------------------------------------------------------------------------------------------
// Named tables -- every value below was verified against Microsoft's own [MS-SMB2] Open
// Specification during this decoder's planning (see smb.hpp's own file header comment for the full
// provenance note); STATUS_ACCOUNT_LOCKED_OUT (0xC0000234) was independently confirmed at
// implementation time, per the plan's own flag on that one value.

struct NamedValue {
    uint32_t value;
    const char* name;
};

const char* command_name(uint16_t command) {
    switch (command) {
        case 0x00: return "NEGOTIATE";
        case 0x01: return "SESSION_SETUP";
        case 0x02: return "LOGOFF";
        case 0x03: return "TREE_CONNECT";
        case 0x04: return "TREE_DISCONNECT";
        case 0x05: return "CREATE";
        case 0x06: return "CLOSE";
        case 0x07: return "FLUSH";
        case 0x08: return "READ";
        case 0x09: return "WRITE";
        case 0x0A: return "LOCK";
        case 0x0B: return "IOCTL";
        case 0x0C: return "CANCEL";
        case 0x0D: return "ECHO";
        case 0x0E: return "QUERY_DIRECTORY";
        case 0x0F: return "CHANGE_NOTIFY";
        case 0x10: return "QUERY_INFO";
        case 0x11: return "SET_INFO";
        case 0x12: return "OPLOCK_BREAK";
        default: return nullptr;
    }
}

// Curated NT_STATUS subset -- see smb.hpp's own curated note 6. Any other Status value is rendered
// numerically rather than guessed at.
const char* status_name(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0xC0000016: return "STATUS_MORE_PROCESSING_REQUIRED";
        case 0xC000006D: return "STATUS_LOGON_FAILURE";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0xC000006A: return "STATUS_WRONG_PASSWORD";
        case 0xC0000071: return "STATUS_PASSWORD_EXPIRED";
        case 0xC0000072: return "STATUS_ACCOUNT_DISABLED";
        case 0xC0000234: return "STATUS_ACCOUNT_LOCKED_OUT";  // confirmed at implementation time,
                                                                  // see this file's own header note
        default: return nullptr;
    }
}

std::string named_status(uint32_t status) {
    if (const char* n = status_name(status)) return n;
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << status;
    return s.str();
}

std::string named_dialect(uint16_t dialect) {
    switch (dialect) {
        case 0x0202: return "SMB 2.0.2";
        case 0x0210: return "SMB 2.1";
        case 0x0300: return "SMB 3.0";
        case 0x0302: return "SMB 3.0.2";
        case 0x0311: return "SMB 3.1.1";
        case 0x02FF: return "SMB 2.??? (multi-protocol negotiate wildcard)";
        default: {
            std::ostringstream s;
            s << "0x" << std::hex << std::uppercase << dialect;
            return s.str();
        }
    }
}

std::vector<std::string> named_header_flags(uint32_t flags) {
    std::vector<std::string> out;
    if (flags & 0x00000001) out.push_back("SERVER_TO_REDIR");
    if (flags & 0x00000002) out.push_back("ASYNC_COMMAND");
    if (flags & 0x00000004) out.push_back("RELATED_OPERATIONS");
    if (flags & 0x00000008) out.push_back("SIGNED");
    if (flags & 0x00000070) out.push_back("PRIORITY_MASK");
    if (flags & 0x10000000) out.push_back("DFS_OPERATIONS");
    if (flags & 0x20000000) out.push_back("REPLAY_OPERATION");
    return out;
}

// NEGOTIATE's own SecurityMode is a 2-byte field (Request and Response alike); SESSION_SETUP's own
// is a 1-byte field with the identical two low bits -- both share this table.
std::vector<std::string> named_security_mode(uint32_t mode) {
    std::vector<std::string> out;
    if (mode & 0x01) out.push_back("SIGNING_ENABLED");
    if (mode & 0x02) out.push_back("SIGNING_REQUIRED");
    return out;
}

std::vector<std::string> named_negotiate_capabilities(uint32_t caps) {
    std::vector<std::string> out;
    if (caps & 0x00000001) out.push_back("DFS");
    if (caps & 0x00000002) out.push_back("LEASING");
    if (caps & 0x00000004) out.push_back("LARGE_MTU");
    if (caps & 0x00000008) out.push_back("MULTI_CHANNEL");
    if (caps & 0x00000010) out.push_back("PERSISTENT_HANDLES");
    if (caps & 0x00000020) out.push_back("DIRECTORY_LEASING");
    if (caps & 0x00000040) out.push_back("ENCRYPTION");
    return out;
}

std::vector<std::string> named_session_flags(uint16_t flags) {
    std::vector<std::string> out;
    if (flags & 0x0001) out.push_back("IS_GUEST");
    if (flags & 0x0002) out.push_back("IS_NULL");
    if (flags & 0x0004) out.push_back("ENCRYPT_DATA");
    return out;
}

std::string named_share_type(uint8_t type) {
    switch (type) {
        case 0x01: return "disk";
        case 0x02: return "pipe";
        case 0x03: return "print";
        default: return "type " + std::to_string(type);
    }
}

std::vector<std::string> named_share_flags(uint32_t flags) {
    std::vector<std::string> out;
    switch (flags & 0x00000030) {  // the 2-bit caching sub-field
        case 0x00000000: out.push_back("MANUAL_CACHING"); break;
        case 0x00000010: out.push_back("AUTO_CACHING"); break;
        case 0x00000020: out.push_back("VDO_CACHING"); break;
        case 0x00000030: out.push_back("NO_CACHING"); break;
    }
    if (flags & 0x00000001) out.push_back("DFS");
    if (flags & 0x00000002) out.push_back("DFS_ROOT");
    if (flags & 0x00000100) out.push_back("RESTRICT_EXCLUSIVE_OPENS");
    if (flags & 0x00000200) out.push_back("FORCE_SHARED_DELETE");
    if (flags & 0x00000400) out.push_back("ALLOW_NAMESPACE_CACHING");
    if (flags & 0x00000800) out.push_back("ACCESS_BASED_DIRECTORY_ENUM");
    if (flags & 0x00001000) out.push_back("FORCE_LEVELII_OPLOCK");
    if (flags & 0x00002000) out.push_back("ENABLE_HASH_V1");
    if (flags & 0x00004000) out.push_back("ENABLE_HASH_V2");
    if (flags & 0x00008000) out.push_back("ENCRYPT_DATA");
    if (flags & 0x00040000) out.push_back("IDENTITY_REMOTING");
    if (flags & 0x00100000) out.push_back("COMPRESS_DATA");
    if (flags & 0x00200000) out.push_back("ISOLATED_TRANSPORT");
    return out;
}

std::vector<std::string> named_share_capabilities(uint32_t caps) {
    std::vector<std::string> out;
    if (caps & 0x00000008) out.push_back("DFS");
    if (caps & 0x00000010) out.push_back("CONTINUOUS_AVAILABILITY");
    if (caps & 0x00000020) out.push_back("SCALEOUT");
    if (caps & 0x00000040) out.push_back("CLUSTER");
    if (caps & 0x00000080) out.push_back("ASYMMETRIC");
    if (caps & 0x00000100) out.push_back("REDIRECT_TO_OWNER");
    return out;
}

// ---------------------------------------------------------------------------------------------
// Field-descriptor style variable-length payload access, the SMB2 analog of ntlm.cpp's own
// FieldDescriptor/field_bytes -- SMB2's own offset/length fields are relative to the start of the
// SUB-MESSAGE (its own SMB2 header), not the start of the enclosing compound chain or the 4-byte
// TCP prefix, per [MS-SMB2] (e.g. SESSION_SETUP Response's SecurityBufferOffset is documented as
// "The offset, in bytes, from the beginning of the SMB2 header to the security buffer").
ByteSpan bounded(ByteSpan message, size_t offset, size_t len) {
    if (len == 0) return ByteSpan();
    if (offset > message.size() || len > message.size() - offset) return ByteSpan();
    return message.subspan(offset, len);
}

// NTLM's own signature scan of a SESSION_SETUP Buffer -- a deliberate substitute for full SPNEGO/
// GSS-API ASN.1 unwrapping, see smb.hpp's own file header comment. Scans for the 8-byte "NTLMSSP\0"
// signature anywhere in `buffer` (a Kerberos-mechanism SPNEGO blob simply won't match) and, if
// found, hands everything from that offset onward to ntlm.hpp's own parser.
std::optional<NtlmMessage> scan_for_ntlm(ByteSpan buffer) {
    if (buffer.size() < 8) return std::nullopt;
    for (size_t i = 0; i + 8 <= buffer.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < 8; ++j) {
            if (buffer.at(i + j) != static_cast<uint8_t>(kNtlmSignature[j])) { match = false; break; }
        }
        if (match) return try_parse_ntlm(buffer.from(i));
    }
    return std::nullopt;
}

// Parses one SMB2 sub-message starting at offset 0 of `sub` (a view already narrowed to exactly
// this sub-message's own bytes -- see parse_smb2_chain below for how compounding narrows this).
// Never throws past its own boundary; a malformed sub-message still yields a header-only
// SmbMessage rather than aborting the whole chain, the same per-item leniency this codebase's other
// bounded-repeat decodes already use.
SmbMessage parse_one_smb2_message(ByteSpan sub) {
    SmbMessage m;
    Cursor c(sub);
    c.skip(4);  // ProtocolId -- already verified by the caller's own gate
    m.structure_size = c.u16le();
    m.credit_charge = c.u16le();
    m.status = c.u32le();
    m.command_value = c.u16le();
    c.u16le();  // CreditRequest/CreditResponse -- not rendered, no OT-security value
    uint32_t flags = c.u32le();
    m.is_response = (flags & 0x00000001) != 0;
    m.is_async = (flags & 0x00000002) != 0;
    m.header_flags = named_header_flags(flags);
    m.next_command = c.u32le();
    m.message_id = c.u64le();
    if (m.is_async) {
        m.async_id = c.u64le();
    } else {
        c.u32le();  // Reserved
        m.tree_id = c.u32le();
    }
    m.session_id = c.u64le();
    c.skip(16);  // Signature -- never verified, see smb.hpp's own DELIBERATELY NOT IMPLEMENTED list

    if (const char* cn = command_name(m.command_value)) {
        m.command_name = cn;
    } else {
        m.command_name = "command " + std::to_string(m.command_value);
    }
    if (m.is_response) m.status_name = named_status(m.status);

    ByteSpan body = sub.from(std::min(sub.size(), static_cast<size_t>(64)));

    std::ostringstream summary;
    summary << "SMB2 " << m.command_name << (m.is_response ? " Response" : " Request");

    try {
        switch (m.command_value) {
            case 0x00: {  // NEGOTIATE
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 36) {
                        bc.u16le();  // StructureSize
                        uint16_t dialect_count = bc.u16le();
                        uint16_t sec_mode = bc.u16le();
                        m.negotiate_request_security_mode = named_security_mode(sec_mode);
                        bc.u16le();  // Reserved
                        bc.u32le();  // Capabilities -- client-side, not rendered (server's own
                                     // negotiated Capabilities in the Response is what matters for
                                     // this decoder's own scope)
                        bc.skip(16);  // ClientGuid
                        bc.skip(8);   // ClientStartTime / NegotiateContextOffset+Count+Reserved2
                        const size_t kMaxDialects = resource_limits().max_decoded_objects.value_or(64);
                        for (uint16_t i = 0; i < dialect_count && i < kMaxDialects && bc.remaining() >= 2; ++i) {
                            m.negotiate_dialects.push_back(named_dialect(bc.u16le()));
                        }
                    }
                } else {
                    Cursor bc(body);
                    if (bc.remaining() >= 64) {
                        bc.u16le();  // StructureSize
                        uint16_t sec_mode = bc.u16le();
                        m.negotiate_response_security_mode = named_security_mode(sec_mode);
                        uint16_t dialect_revision = bc.u16le();
                        m.negotiated_dialect = named_dialect(dialect_revision);
                        bc.u16le();  // NegotiateContextCount/Reserved
                        ByteSpan guid = bc.bytes(16);
                        m.server_guid_hex = to_hex(guid, "");
                        uint32_t caps = bc.u32le();
                        m.negotiate_capabilities = named_negotiate_capabilities(caps);
                        bc.skip(4 + 4 + 4);  // MaxTransactSize/MaxReadSize/MaxWriteSize
                        bc.skip(8 + 8);      // SystemTime/ServerStartTime
                        bc.u16le();          // SecurityBufferOffset -- Response carries no NTLM of
                                              // its own interest here (that's SESSION_SETUP's job)
                        bc.u16le();          // SecurityBufferLength
                        m.has_negotiate_response = true;
                    }
                }
                if (!m.is_response && !m.negotiate_dialects.empty()) {
                    summary << " (dialects: ";
                    for (size_t i = 0; i < m.negotiate_dialects.size(); ++i) {
                        if (i) summary << ", ";
                        summary << m.negotiate_dialects[i];
                    }
                    summary << ")";
                } else if (m.is_response && m.has_negotiate_response) {
                    summary << " (" << m.negotiated_dialect << ")";
                }
                break;
            }
            case 0x01: {  // SESSION_SETUP
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 24) {
                        bc.u16le();  // StructureSize
                        bc.u8();     // Flags (binding, not rendered)
                        uint8_t sec_mode = bc.u8();
                        m.session_setup_security_mode = named_security_mode(sec_mode);
                        uint32_t caps = bc.u32le();
                        // SESSION_SETUP's own Capabilities is a 1-bit DFS-only field in current
                        // dialects -- named generically via the same helper for consistency; any
                        // higher bits (reserved/must-be-zero) are simply not named.
                        if (caps & 0x00000001) m.session_setup_capabilities.push_back("DFS");
                        bc.u32le();  // Channel -- reserved
                        uint16_t sec_buf_offset = bc.u16le();
                        uint16_t sec_buf_len = bc.u16le();
                        m.previous_session_id = bc.u64le();
                        ByteSpan buf = bounded(sub, sec_buf_offset, sec_buf_len);
                        if (auto ntlm = scan_for_ntlm(buf)) {
                            m.has_ntlm = true;
                            m.ntlm = std::move(*ntlm);
                        }
                        m.has_session_setup_request = true;
                    }
                } else {
                    Cursor bc(body);
                    if (bc.remaining() >= 8) {
                        bc.u16le();  // StructureSize
                        uint16_t sflags = bc.u16le();
                        m.session_flags = named_session_flags(sflags);
                        uint16_t sec_buf_offset = bc.u16le();
                        uint16_t sec_buf_len = bc.u16le();
                        ByteSpan buf = bounded(sub, sec_buf_offset, sec_buf_len);
                        if (auto ntlm = scan_for_ntlm(buf)) {
                            m.has_ntlm = true;
                            m.ntlm = std::move(*ntlm);
                        }
                        m.has_session_setup_response = true;
                    }
                }
                if (m.has_ntlm) summary << " (" << m.ntlm.message_type << ")";
                break;
            }
            case 0x02:    // LOGOFF
            case 0x04: {  // TREE_DISCONNECT
                // Header-only -- see smb.hpp's own MESSAGE COVERAGE list.
                break;
            }
            case 0x03: {  // TREE_CONNECT
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 8) {
                        bc.u16le();  // StructureSize
                        bc.u16le();  // Flags/Reserved -- SMB 3.1.1's own extension flag not decoded
                        uint16_t path_offset = bc.u16le();
                        uint16_t path_len = bc.u16le();
                        ByteSpan path_bytes = bounded(sub, path_offset, path_len);
                        m.tree_connect_path = utf16le_to_utf8(path_bytes);
                        m.has_tree_connect_request = true;
                    }
                } else {
                    Cursor bc(body);
                    if (bc.remaining() >= 16) {
                        bc.u16le();  // StructureSize
                        uint8_t share_type = bc.u8();
                        m.share_type = named_share_type(share_type);
                        bc.u8();  // Reserved
                        uint32_t sflags = bc.u32le();
                        m.share_flags = named_share_flags(sflags);
                        uint32_t caps = bc.u32le();
                        m.share_capabilities = named_share_capabilities(caps);
                        bc.u32le();  // MaximalAccess -- not rendered, no OT-security value in this
                                     // decoder's own curated scope
                        m.has_tree_connect_response = true;
                    }
                }
                if (!m.is_response && !m.tree_connect_path.empty()) {
                    summary << " (" << m.tree_connect_path << ")";
                } else if (m.is_response && m.has_tree_connect_response) {
                    summary << " (" << m.share_type << ")";
                }
                break;
            }
            default:
                // Structural-only -- see smb.hpp's own STRUCTURAL-ONLY list. Command already named
                // in the summary above; nothing else to decode.
                break;
        }
    } catch (const ParseError&) {
        // A malformed command body doesn't invalidate the header this function already parsed --
        // the same per-item leniency noted in this function's own doc comment.
    }

    if (m.is_response) summary << " [" << m.status_name << "]";
    m.summary = summary.str();
    return m;
}

// NextCommand lives at a fixed offset (20) within every SMB2 header -- see smb.cpp's own header
// field-offset table in parse_one_smb2_message. Peeked directly, without a full header parse, so
// parse_smb2_chain below can size each sub-message's own span before handing it to
// parse_one_smb2_message.
uint32_t peek_next_command(ByteSpan sub) {
    Cursor c(sub);
    c.skip(20);
    return c.u32le();
}

// Walks the NextCommand chain, per this file's own COMPOUNDING paragraph (smb.hpp). `smb2_area` is
// everything after the 4-byte TCP prefix. Capped both by the available bytes running out and by a
// hard limit on the number of sub-messages, so a malformed/hostile NextCommand chain (e.g. one that
// doesn't advance, or advances by less than a header's worth of bytes) can't loop unboundedly.
std::vector<SmbMessage> parse_smb2_chain(ByteSpan smb2_area) {
    std::vector<SmbMessage> messages;
    const size_t kMaxCompounded = resource_limits().max_decoded_objects.value_or(64);
    size_t offset = 0;
    while (offset + 64 <= smb2_area.size() && messages.size() < kMaxCompounded) {
        // Every sub-message after the first must also carry the ProtocolId magic -- verified here
        // rather than assumed, so a malformed NextCommand offset that lands mid-body is rejected
        // (the chain simply stops, keeping whatever was already parsed) instead of misparsed.
        if (!match_smb_magic(smb2_area, offset)) break;

        size_t remaining_from_here = smb2_area.size() - offset;
        ByteSpan sub_full = smb2_area.subspan(offset, remaining_from_here);
        uint32_t next_command = peek_next_command(sub_full);

        size_t this_extent = remaining_from_here;
        bool is_last = true;
        if (next_command != 0) {
            if (next_command < 64 || next_command > remaining_from_here) {
                // Malformed -- either the offset doesn't leave room for even a header, or it
                // overruns the buffer. Parse this one sub-message using everything that's left
                // (the same leniency parse_one_smb2_message itself uses for a malformed body) and
                // stop the chain rather than compound further on bad data.
                next_command = 0;
            } else {
                this_extent = next_command;
                is_last = false;
            }
        }

        ByteSpan sub = smb2_area.subspan(offset, this_extent);
        messages.push_back(parse_one_smb2_message(sub));

        if (is_last) break;
        offset += next_command;
    }
    return messages;
}

bool ends_with_dollar(const std::string& s) { return !s.empty() && s.back() == '$'; }

}  // namespace

std::optional<SmbFrame> try_parse_smb(ByteSpan payload) {
    try {
        if (payload.size() < 8) return std::nullopt;
        if (payload.at(0) != 0x00) return std::nullopt;  // Zero byte of the 4-byte prefix
        if (!match_smb_magic(payload, 4)) return std::nullopt;

        uint8_t b0 = payload.at(4);
        ByteSpan smb2_area = payload.from(4);

        SmbFrame frame;
        if (b0 == 0xFF) {
            frame.envelope_kind = "SMB1";
            frame.summary = "SMB1 (CIFS) message";
            return frame;
        }
        if (b0 == 0xFD) {
            frame.envelope_kind = "SMB2_TRANSFORM";
            frame.summary = "SMB2/SMB3 Transform (encrypted) header";
            return frame;
        }

        frame.envelope_kind = "SMB2";
        frame.messages = parse_smb2_chain(smb2_area);
        if (frame.messages.empty()) return std::nullopt;

        std::ostringstream s;
        for (size_t i = 0; i < frame.messages.size(); ++i) {
            if (i != 0) s << " + ";
            s << frame.messages[i].summary;
        }
        if (frame.messages.size() > 1) s << " (compounded)";
        frame.summary = s.str();
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> smb_tcp_declared_length(ByteSpan candidate) {
    if (candidate.size() < 8) return std::nullopt;
    if (candidate.at(0) != 0x00) return std::nullopt;
    if (!match_smb_magic(candidate, 4)) return std::nullopt;
    uint32_t len = (static_cast<uint32_t>(candidate.at(1)) << 16) |
                    (static_cast<uint32_t>(candidate.at(2)) << 8) | static_cast<uint32_t>(candidate.at(3));
    // A real SMB2 message realistically never approaches this; same defense-in-depth posture
    // kerberos_tcp_declared_length's/ldap_tcp_declared_length's own analogous caps take.
    // CLI-configurable via --max-reassembly-bytes -- see resource_limits.hpp.
    const size_t kMaxPlausibleSmbMessageLength = resource_limits().max_reassembly_bytes.value_or(1 << 20);
    if (len == 0 || len > kMaxPlausibleSmbMessageLength) return std::nullopt;
    return 4 + static_cast<size_t>(len);
}

namespace {

// Shared correlation layer, applied on top of a successfully try_parse_smb'd frame -- the same
// "try_parse_X then XDecoder::decode applies flow-state" split kerberos.cpp's/ldap.cpp's own
// decode_with_correlation established. See smb.hpp's header comment's STATE/CORRELATION section.
std::optional<ProtocolResult> decode_with_correlation(ByteSpan payload, DecodeContext& ctx) {
    auto parsed = try_parse_smb(payload);
    if (!parsed) return std::nullopt;
    SmbFrame frame = std::move(*parsed);

    SmbFlowState& state = ctx.flow_state<SmbFlowState>();
    const size_t kMaxTrackedPerSession = resource_limits().max_decoded_objects.value_or(2000);

    if (frame.envelope_kind == "SMB1") {
        // Curated note 1 -- fires once per session, a sticky flag not a per-message repeat, see
        // smb.hpp's own header comment.
        if (!state.smb1_seen) {
            state.smb1_seen = true;
            frame.notes.push_back(
                "SMB1 (CIFS) traffic observed on this session -- SMB1 is a legacy dialect with known, "
                "serious vulnerabilities (the EternalBlue/WannaCry family chief among them) and is "
                "disabled by default on current Windows/Samba versions; its mere presence on a "
                "production segment is commonly treated as a finding on its own");
        }
        return ProtocolResult::make<SmbFrame>("smb", std::move(frame));
    }
    if (frame.envelope_kind == "SMB2_TRANSFORM") {
        return ProtocolResult::make<SmbFrame>("smb", std::move(frame));
    }

    for (SmbMessage& m : frame.messages) {
        switch (m.command_value) {
            case 0x00:  // NEGOTIATE
                if (m.is_response && m.has_negotiate_response) {
                    bool signing_enabled = false, signing_required = false;
                    for (const auto& f : m.negotiate_response_security_mode) {
                        if (f == "SIGNING_ENABLED") signing_enabled = true;
                        if (f == "SIGNING_REQUIRED") signing_required = true;
                    }
                    if (signing_enabled && !signing_required) {
                        m.notes.push_back(
                            "SMB signing is enabled but NOT required on this session -- the "
                            "precondition every NTLM-relay tool (ntlmrelayx and equivalents) checks "
                            "for before attempting a relay attack; legitimate deployments with "
                            "signing off by policy also produce this");
                    }
                }
                if (!m.is_response) {
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        state.pending_requests[m.message_id] =
                            SmbPendingRequest{ctx.packet_index, m.command_value, ""};
                    }
                } else {
                    auto it = state.pending_requests.find(m.message_id);
                    if (it != state.pending_requests.end() && it->second.command_value == m.command_value) {
                        m.correlated_request_seen = true;
                        m.correlated_request_index = it->second.packet_index;
                        state.pending_requests.erase(it);
                    }
                }
                break;

            case 0x01: {  // SESSION_SETUP
                if (m.has_ntlm) {
                    // Curated note 3 -- NTLM negotiated for this session, a downgrade/relay-friendly
                    // signal on its own -- see smb.hpp's own header comment.
                    m.notes.push_back(
                        "NTLM authentication in use for this session (" + m.ntlm.message_type +
                        ") -- Kerberos is preferred by policy in a well-run AD environment; NTLM "
                        "appearing at all is often a legacy client, a non-domain host, or an attacker "
                        "deliberately forcing NTLM to enable a relay attack");
                }
                if (m.is_response && m.has_session_setup_response) {
                    bool is_guest = false, is_null = false;
                    for (const auto& f : m.session_flags) {
                        if (f == "IS_GUEST") is_guest = true;
                        if (f == "IS_NULL") is_null = true;
                    }
                    if (is_guest || is_null) {
                        // Curated note 4.
                        m.notes.push_back(
                            std::string("session established as ") +
                            (is_null ? "anonymous (null session)" : "guest") +
                            " -- a well-known misconfiguration (null-session enumeration) when seen "
                            "against a production share");
                    }

                    // NTLM multi-leg handshake correlation -- see smb.hpp's own STATE/CORRELATION
                    // section for why this is a genuinely new shape relative to Kerberos's/LDAP's own
                    // 1:1/keep-until-terminal pairings.
                    if (m.status == 0xC0000016 /* STATUS_MORE_PROCESSING_REQUIRED */ && m.has_ntlm &&
                        m.ntlm.message_type == "CHALLENGE_MESSAGE") {
                        if (state.pending_ntlm_handshakes.size() < kMaxTrackedPerSession) {
                            state.pending_ntlm_handshakes[m.session_id] =
                                PendingNtlmHandshake{ctx.packet_index, m.ntlm.target_name};
                        }
                    } else {
                        auto it = state.pending_ntlm_handshakes.find(m.session_id);
                        if (it != state.pending_ntlm_handshakes.end()) {
                            m.ntlm_handshake_closed = true;
                            bool succeeded = (m.status == 0x00000000);
                            std::ostringstream hs;
                            hs << "NTLM handshake for ";
                            hs << (it->second.domain_name.empty() ? "(unknown target)" : it->second.domain_name);
                            hs << ", " << (succeeded ? "succeeded" : "failed (" + m.status_name + ")");
                            m.ntlm_handshake_summary = hs.str();
                            m.notes.push_back(m.ntlm_handshake_summary);
                            state.pending_ntlm_handshakes.erase(it);
                        }
                    }
                }
                // SESSION_SETUP is deliberately NOT tracked in the simple MessageId pending_requests
                // map -- see smb.hpp's own STATE/CORRELATION section; its own correlation is entirely
                // the SessionId-keyed handshake map above.
                break;
            }

            case 0x03: {  // TREE_CONNECT
                if (!m.is_response && m.has_tree_connect_request) {
                    if (ends_with_dollar(m.tree_connect_path)) {
                        // Curated note 5 (preliminary -- confirmed as IPC$ specifically on the
                        // matching response below, once ShareType is known).
                        m.notes.push_back("administrative/hidden share access attempted: \"" +
                                           m.tree_connect_path +
                                           "\" -- legitimate admin tooling uses ADMIN$/C$/IPC$ "
                                           "routinely too, this does not by itself indicate an attack");
                    }
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        state.pending_requests[m.message_id] =
                            SmbPendingRequest{ctx.packet_index, m.command_value, m.tree_connect_path};
                    }
                } else if (m.is_response) {
                    auto it = state.pending_requests.find(m.message_id);
                    if (it != state.pending_requests.end() && it->second.command_value == m.command_value) {
                        m.correlated_request_seen = true;
                        m.correlated_request_index = it->second.packet_index;
                        if (ends_with_dollar(it->second.tree_connect_path) && m.share_type == "pipe") {
                            m.notes.push_back(
                                "confirmed named-pipe (IPC$-style) access to \"" +
                                it->second.tree_connect_path +
                                "\" -- often the next step after authentication in a lateral-movement "
                                "chain (named-pipe-based remote service control, e.g. PsExec-style "
                                "tooling); legitimate admin tooling also uses IPC$ routinely");
                        }
                        state.pending_requests.erase(it);
                    }
                }
                break;
            }

            case 0x02:    // LOGOFF
            case 0x04: {  // TREE_DISCONNECT
                if (!m.is_response) {
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        state.pending_requests[m.message_id] =
                            SmbPendingRequest{ctx.packet_index, m.command_value, ""};
                    }
                } else {
                    auto it = state.pending_requests.find(m.message_id);
                    if (it != state.pending_requests.end() && it->second.command_value == m.command_value) {
                        m.correlated_request_seen = true;
                        m.correlated_request_index = it->second.packet_index;
                        state.pending_requests.erase(it);
                    }
                }
                break;
            }

            default:
                break;  // structural-only commands -- no correlation attempted
        }
    }

    for (const SmbMessage& m : frame.messages) {
        for (const auto& n : m.notes) frame.notes.push_back(n);
    }

    return ProtocolResult::make<SmbFrame>("smb", std::move(frame));
}

}  // namespace

std::optional<ProtocolResult> SmbTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_correlation(payload, ctx);
}

const ProtocolDecoder& smb_tcp_decoder() {
    static const SmbTcpDecoder instance;
    return instance;
}

}  // namespace conduitscope
