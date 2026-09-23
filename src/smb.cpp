// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/smb.hpp"

#include <algorithm>
#include <cctype>
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

// True iff `hay`'s first `needle.size()` bytes equal `needle`, byte-by-byte, ASCII-case-
// insensitively -- pipe names are ASCII by construction (they're Win32 device-namespace names),
// so no locale/Unicode-aware comparison is needed.
bool starts_with_ci(const std::string& hay, const char* needle) {
    size_t n = std::char_traits<char>::length(needle);
    if (hay.size() < n) return false;
    for (size_t i = 0; i < n; ++i) {
        if (std::tolower(static_cast<unsigned char>(hay[i])) !=
            std::tolower(static_cast<unsigned char>(needle[i]))) {
            return false;
        }
    }
    return true;
}

// Normalizes a CREATE request's own decoded Name field into a bare, lowercase pipe name for
// comparison against "netlogon" -- strips one leading "\PIPE\", "PIPE\", or "\" prefix
// (case-insensitively, in that priority order so "\PIPE\netlogon" isn't left with a stray "PIPE\"
// after only the leading "\" is stripped), then lowercases the remainder. Named-pipe opens
// arrive with one of these prefixes depending on the client; a plain file path (no prefix at all)
// simply won't match "netlogon" after normalization, which is exactly the desired behavior -- see
// smb.hpp's own STATE/CORRELATION section for why only this one exact pipe name is ever tracked.
std::string strip_pipe_prefix_lower(const std::string& name) {
    std::string s = name;
    if (starts_with_ci(s, "\\PIPE\\")) {
        s = s.substr(6);
    } else if (starts_with_ci(s, "PIPE\\")) {
        s = s.substr(5);
    } else if (starts_with_ci(s, "\\")) {
        s = s.substr(1);
    }
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Parses one SMB2 sub-message starting at offset 0 of `sub` (a view already narrowed to exactly
// this sub-message's own bytes -- see parse_smb2_chain below for how compounding narrows this).
// Never throws past its own boundary; a malformed sub-message still yields a header-only
// SmbMessage rather than aborting the whole chain, the same per-item leniency this codebase's other
// bounded-repeat decodes already use.
//
// `tracked_rpc_pipe_file_ids` -- see try_parse_smb's own doc comment (smb.hpp) for what this
// pointer is and, more importantly, is NOT: a read-only lookup used solely to decide whether a
// WRITE/READ/IOCTL message's own payload is worth copying into dcerpc_raw_payload at all. This
// function never mutates it and never itself decides what the bytes mean, nor which interface (if
// any) a tracked FileId belongs to -- that's decode_with_correlation's/dispatch_dcerpc_payload's
// job, once this whole chain has returned.
SmbMessage parse_one_smb2_message(
    ByteSpan sub,
    const std::unordered_set<SmbFileId, SmbFileIdHash>* tracked_rpc_pipe_file_ids) {
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
            case 0x05: {  // CREATE
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 48) {
                        bc.skip(44);  // jump to NameOffset (structure offset 44, body-relative)
                        uint16_t name_offset = bc.u16le();
                        uint16_t name_length = bc.u16le();
                        ByteSpan name_bytes = bounded(sub, name_offset, name_length);
                        m.create_name = strip_pipe_prefix_lower(utf16le_to_utf8(name_bytes));
                        m.has_create_request = true;
                    }
                } else {
                    Cursor bc(body);
                    if (bc.remaining() >= 80) {
                        bc.skip(64);  // jump to FileId (structure offset 64, body-relative)
                        uint64_t persistent = bc.u64le();
                        uint64_t vol = bc.u64le();
                        m.file_id = SmbFileId{persistent, vol};
                        m.has_file_id = true;
                        m.has_create_response = true;
                    }
                }
                if (!m.is_response && !m.create_name.empty()) {
                    summary << " (" << m.create_name << ")";
                }
                break;
            }
            case 0x06: {  // CLOSE
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 24) {
                        bc.skip(8);  // StructureSize/Flags/Reserved
                        uint64_t persistent = bc.u64le();
                        uint64_t vol = bc.u64le();
                        m.file_id = SmbFileId{persistent, vol};
                        m.has_file_id = true;
                    }
                }
                break;
            }
            case 0x08: {  // READ
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 32) {
                        bc.skip(16);  // StructureSize/Padding/Flags/Length/Offset
                        uint64_t persistent = bc.u64le();
                        uint64_t vol = bc.u64le();
                        m.file_id = SmbFileId{persistent, vol};
                        m.has_file_id = true;
                    }
                } else {
                    Cursor bc(body);
                    if (bc.remaining() >= 8) {
                        bc.u16le();  // StructureSize
                        uint8_t data_offset = bc.u8();
                        bc.u8();  // Reserved
                        uint32_t data_length = bc.u32le();
                        // READ's own Response carries no FileId of its own (MS-SMB2) -- unlike
                        // WRITE/IOCTL below, this function has no way to gate this copy by FileId
                        // at all; decode_with_correlation resolves the FileId (via the matching
                        // READ request's own MessageId) and drops this again immediately if it
                        // turns out not to be a tracked pipe -- see smb.hpp's own doc comment on
                        // dcerpc_raw_payload. Gated coarsely here on "is any RPC pipe tracked in
                        // this session at all", to avoid the copy entirely for the overwhelmingly
                        // common case of a session with no tracked pipe open.
                        if (tracked_rpc_pipe_file_ids != nullptr &&
                            !tracked_rpc_pipe_file_ids->empty()) {
                            ByteSpan payload_bytes = bounded(sub, data_offset, data_length);
                            m.dcerpc_raw_payload = payload_bytes.to_vector();
                        }
                    }
                }
                break;
            }
            case 0x09: {  // WRITE
                if (!m.is_response) {
                    Cursor bc(body);
                    if (bc.remaining() >= 32) {
                        bc.u16le();  // StructureSize
                        uint16_t data_offset = bc.u16le();
                        uint32_t length = bc.u32le();
                        bc.skip(8);  // Offset
                        uint64_t persistent = bc.u64le();
                        uint64_t vol = bc.u64le();
                        m.file_id = SmbFileId{persistent, vol};
                        m.has_file_id = true;
                        if (tracked_rpc_pipe_file_ids != nullptr &&
                            tracked_rpc_pipe_file_ids->count(m.file_id) != 0) {
                            ByteSpan payload_bytes = bounded(sub, data_offset, length);
                            m.dcerpc_raw_payload = payload_bytes.to_vector();
                        }
                    }
                }
                // WRITE Response carries no payload of its own interest -- Count/Remaining only.
                break;
            }
            case 0x0B: {  // IOCTL
                Cursor bc(body);
                if (bc.remaining() >= 32) {
                    bc.u16le();  // StructureSize
                    bc.u16le();  // Reserved
                    uint32_t ctl_code = bc.u32le();
                    uint64_t persistent = bc.u64le();
                    uint64_t vol = bc.u64le();
                    m.file_id = SmbFileId{persistent, vol};
                    m.has_file_id = true;
                    uint32_t input_offset = bc.u32le();
                    uint32_t input_count = bc.u32le();
                    bool is_pipe_transceive = (ctl_code == 0x0011C017);  // FSCTL_PIPE_TRANSCEIVE
                    bool tracked = tracked_rpc_pipe_file_ids != nullptr &&
                                    tracked_rpc_pipe_file_ids->count(m.file_id) != 0;
                    if (!m.is_response) {
                        if (bc.remaining() >= 12) {
                            bc.u32le();  // MaxInputResponse
                            bc.u32le();  // OutputOffset -- the caller's own output buffer size
                            bc.u32le();  // OutputCount    hint, not a payload location; unused here
                        }
                        if (is_pipe_transceive && tracked) {
                            ByteSpan payload_bytes = bounded(sub, input_offset, input_count);
                            m.dcerpc_raw_payload = payload_bytes.to_vector();
                        }
                    } else {
                        if (bc.remaining() >= 8) {
                            uint32_t output_offset = bc.u32le();
                            uint32_t output_count = bc.u32le();
                            if (is_pipe_transceive && tracked) {
                                ByteSpan payload_bytes = bounded(sub, output_offset, output_count);
                                m.dcerpc_raw_payload = payload_bytes.to_vector();
                            }
                        }
                    }
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
// `tracked_rpc_pipe_file_ids` is threaded straight through to parse_one_smb2_message -- see that
// function's own doc comment.
std::vector<SmbMessage> parse_smb2_chain(
    ByteSpan smb2_area,
    const std::unordered_set<SmbFileId, SmbFileIdHash>* tracked_rpc_pipe_file_ids) {
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
        messages.push_back(parse_one_smb2_message(sub, tracked_rpc_pipe_file_ids));

        if (is_last) break;
        offset += next_command;
    }
    return messages;
}

bool ends_with_dollar(const std::string& s) { return !s.empty() && s.back() == '$'; }

}  // namespace

std::optional<SmbFrame> try_parse_smb(
    ByteSpan payload,
    const std::unordered_set<SmbFileId, SmbFileIdHash>* tracked_rpc_pipe_file_ids) {
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
        frame.messages = parse_smb2_chain(smb2_area, tracked_rpc_pipe_file_ids);
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

// Applies dcerpc.hpp's own PDU-chain parse to `raw_payload`, then netlogon.hpp's own opnum decode
// for any PDU whose own context is confirmed bound to the Netlogon interface (per `pipe_state`'s
// own sticky state) -- populates m.dcerpc_messages/m.netlogon_calls and folds curated notes 1-5
// into `m.notes` as they fire. See smb.hpp's own STATE/CORRELATION section for the two-layer
// (bind<->bind_ack, then request<->response/fault) correlation this performs, both keyed by
// DCE/RPC's own wire-mandated call_id (dcerpc.hpp's own DceRpcMessage::call_id).
void decode_dcerpc_and_netlogon(SmbMessage& m, NetlogonPipeState& pipe_state,
                                 const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (dm.has_bind) {
                for (const DceRpcContextElement& ctx_elem : dm.bind_contexts) {
                    if (is_netlogon_interface_uuid(ctx_elem.abstract_syntax_uuid)) {
                        pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{0, ctx_elem.context_id};
                        break;
                    }
                }
            } else if (dm.has_bind_ack) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t candidate_context_id = it->second.context_id;
                    for (const DceRpcContextResult& result : dm.bind_ack_results) {
                        if (result.result_name == "acceptance") {
                            pipe_state.bound_context_is_netlogon = true;
                            pipe_state.netlogon_context_id = candidate_context_id;
                            break;
                        }
                    }
                    pipe_state.pending_calls.erase(it);
                }
            } else if (dm.has_request) {
                if (pipe_state.bound_context_is_netlogon &&
                    dm.request_context_id == pipe_state.netlogon_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    NetlogonCall call = try_parse_netlogon_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.netlogon_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    NetlogonCall call = try_parse_netlogon_response(dm.call_id, opnum, dm.sealed, stub);
                    m.netlogon_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            } else if (dm.has_fault) {
                pipe_state.pending_calls.erase(dm.call_id);
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain -- the
            // same per-item leniency parse_one_smb2_message's own command bodies already use.
        }
    }

    for (const NetlogonCall& call : m.netlogon_calls) {
        if (!call.is_response && call.has_request_fields) {
            if (!call.primary_name.empty()) pipe_state.last_primary_name = call.primary_name;
            if (!call.account_name.empty()) pipe_state.last_account_name = call.account_name;
            if (!call.computer_name.empty()) pipe_state.last_computer_name = call.computer_name;

            // Curated note 2 -- Zerologon-pattern all-zero client challenge/credential. The single
            // highest-value note in this file: a real challenge/credential is an 8-byte random
            // nonce, so an all-zero value essentially never occurs in benign traffic. Presence
            // alone is not proof of a completed compromise.
            if (call.client_credential_is_all_zero && call.opnum == 4 &&
                !pipe_state.zero_challenge_seen) {
                pipe_state.zero_challenge_seen = true;
                m.notes.push_back(
                    "Netlogon ClientChallenge is all-zero bytes -- the wire signature of "
                    "CVE-2020-1472 (\"Zerologon\"); a real challenge is an 8-byte random nonce, so "
                    "this essentially never occurs in benign traffic, though presence alone does "
                    "not prove a completed compromise");
            }
            if (call.client_credential_is_all_zero &&
                (call.opnum == 5 || call.opnum == 15 || call.opnum == 26) &&
                !pipe_state.zero_credential_seen) {
                pipe_state.zero_credential_seen = true;
                m.notes.push_back(
                    "Netlogon ClientCredential is all-zero bytes -- the wire signature of "
                    "CVE-2020-1472 (\"Zerologon\"); a real credential is derived from an 8-byte "
                    "random nonce, so this essentially never occurs in benign traffic, though "
                    "presence alone does not prove a completed compromise");
            }

            // Curated note 3 -- legacy/downgraded Netlogon authentication method.
            if ((call.opnum == 5 || call.opnum == 15) && !pipe_state.legacy_authenticate_seen) {
                pipe_state.legacy_authenticate_seen = true;
                m.notes.push_back(
                    "legacy Netlogon authentication method used (" + call.opnum_name +
                    ") instead of the modern NetrServerAuthenticate3 -- often just a legacy client "
                    "or a downlevel trust, but also the method some downgrade-style attacks "
                    "deliberately force");
            }

            // Curated note 4 -- machine-account naming mismatch.
            if (call.has_secure_channel_type &&
                (call.secure_channel_type_value == 2 /* WorkstationSecureChannel */ ||
                 call.secure_channel_type_value == 6 /* ServerSecureChannel */) &&
                !call.account_name.empty() && call.account_name.back() != '$' &&
                !pipe_state.account_name_mismatch_seen) {
                pipe_state.account_name_mismatch_seen = true;
                m.notes.push_back(
                    "Netlogon AccountName \"" + call.account_name +
                    "\" does not end in \"$\" despite claiming a machine secure channel type (" +
                    call.secure_channel_type_name +
                    ") -- machine accounts conventionally end in \"$\"; a wire-visible anomaly "
                    "worth investigating, not proof of impersonation on its own");
            }

            // Curated note 5 -- machine account password reset via Netlogon. Deliberately not
            // sticky, see NetlogonPipeState's own doc comment -- each occurrence is meaningful.
            if (call.opnum == 30) {
                m.notes.push_back(
                    "NetrServerPasswordSet2 observed on this pipe for account \"" +
                    call.account_name +
                    "\" -- resets that machine account's own password; the literal next step "
                    "after a forged Netlogon secure channel (e.g. following a Zerologon-style "
                    "attack), though also routine periodic machine-password rotation in benign "
                    "traffic");
            }
        }

        // Curated note 1 -- Netlogon secure channel established/failed, a closing correlation
        // note on the terminal Authenticate* response, the direct Netlogon-side analog of this
        // file's own NTLM-handshake-correlation note.
        if (call.is_response && call.has_status &&
            (call.opnum == 5 || call.opnum == 15 || call.opnum == 26)) {
            bool succeeded = (call.status == 0);
            const std::string& who = !pipe_state.last_account_name.empty()
                                          ? pipe_state.last_account_name
                                          : pipe_state.last_computer_name;
            std::ostringstream note;
            note << "Netlogon secure channel " << (succeeded ? "established" : "failed");
            if (!who.empty()) note << " for " << who;
            note << " (" << call.opnum_name << ", status=" << call.status_name << ")";
            m.notes.push_back(note.str());
        }
    }
}

// SAMR's own bind/bind_ack/request/response/fault bookkeeping -- unlike decode_dcerpc_and_netlogon
// (written before Phase 0's resolve_dcerpc_bind_bookkeeping template existed, and kept exactly as-is
// per this codebase's own "existing behavior byte-identical" bar), this is the template's first real
// caller: the mechanical bind/bind_ack/fault half is factored out to dcerpc.hpp, leaving only the
// SAMR-specific request/response decode and this interface's own curated notes here.
void decode_dcerpc_and_samr(SmbMessage& m, SamrPipeState& pipe_state, SmbFlowState& state,
                             const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (resolve_dcerpc_bind_bookkeeping(dm, pipe_state, is_samr_interface_uuid)) {
                continue;
            }
            if (dm.has_request) {
                if (pipe_state.bound_context_is_interface &&
                    dm.request_context_id == pipe_state.interface_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    SamrCall call = try_parse_samr_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.samr_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    SamrCall call = try_parse_samr_response(dm.call_id, opnum, dm.sealed, stub);
                    m.samr_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain.
        }
    }

    // Curated note -- SAMR account/group enumeration observed. Fires once per pipe conversation, on
    // the request side of the first opnum this file treats as a recon call (SamrEnumerateUsersIn-
    // Domain/AliasesInDomain, SamrLookupNamesInDomain/LookupIdsInDomain, SamrGetAliasMembership).
    for (const SamrCall& call : m.samr_calls) {
        if (call.is_response) continue;
        bool is_recon_opnum = (call.opnum == 13 || call.opnum == 15 || call.opnum == 16 ||
                                call.opnum == 17 || call.opnum == 18);
        if (!is_recon_opnum || pipe_state.enumeration_note_seen) continue;
        pipe_state.enumeration_note_seen = true;
        std::string note =
            "SAMR account/group enumeration observed (" + call.opnum_name +
            ") -- the wire signature of directory-enumeration tooling (enum4linux, BloodHound's "
            "SharpHound collector, PowerView, rpcclient); also routine for legitimate AD "
            "administration and directory-aware applications";
        if (state.null_or_guest_session_seen) {
            note += "; this session was established as anonymous/guest -- null-session SAM "
                    "enumeration, a well-known high-value misconfiguration";
        }
        m.notes.push_back(note);

        // Cross-interface note -- SAMR + LSARPC enumeration on the same session, only possible
        // because Phase 0 put both maps on the same SmbFlowState. Fires once, whichever interface's
        // own enumeration note happens to fire second.
        if (!state.lsarpc_pipes.empty() && !state.samr_lsarpc_cross_interface_note_seen) {
            state.samr_lsarpc_cross_interface_note_seen = true;
            m.notes.push_back(
                "SAMR and LSARPC enumeration both observed on this session -- the pattern "
                "enum4linux/BloodHound-style collectors actually use (RID/name resolution plus SID "
                "translation together), not two coincidental calls");
        }
    }
}

// LSARPC's own bookkeeping -- same shape as decode_dcerpc_and_samr above.
void decode_dcerpc_and_lsarpc(SmbMessage& m, LsarpcPipeState& pipe_state, SmbFlowState& state,
                               const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (resolve_dcerpc_bind_bookkeeping(dm, pipe_state, is_lsarpc_interface_uuid)) {
                continue;
            }
            if (dm.has_request) {
                if (pipe_state.bound_context_is_interface &&
                    dm.request_context_id == pipe_state.interface_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    LsarCall call = try_parse_lsarpc_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.lsarpc_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    LsarCall call = try_parse_lsarpc_response(dm.call_id, opnum, dm.sealed, stub);
                    m.lsarpc_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain.
        }
    }

    // Curated note -- LSARPC SID/name translation or account/trust enumeration observed. Same
    // sticky-once-per-pipe posture as SAMR's own note above.
    for (const LsarCall& call : m.lsarpc_calls) {
        if (call.is_response) continue;
        bool is_recon_opnum = (call.opnum == 11 || call.opnum == 13 || call.opnum == 14 ||
                                call.opnum == 15);
        if (!is_recon_opnum || pipe_state.enumeration_note_seen) continue;
        pipe_state.enumeration_note_seen = true;
        std::string note =
            "LSARPC SID/name translation or enumeration observed (" + call.opnum_name +
            ") -- the wire signature of directory-enumeration tooling (enum4linux, BloodHound's "
            "SharpHound collector, rpcclient's own lsalookupsids/lsalookupnames); also routine for "
            "legitimate AD administration and directory-aware applications";
        if (state.null_or_guest_session_seen) {
            note += "; this session was established as anonymous/guest -- null-session LSA "
                    "enumeration, a well-known high-value misconfiguration";
        }
        m.notes.push_back(note);

        if (!state.samr_pipes.empty() && !state.samr_lsarpc_cross_interface_note_seen) {
            state.samr_lsarpc_cross_interface_note_seen = true;
            m.notes.push_back(
                "SAMR and LSARPC enumeration both observed on this session -- the pattern "
                "enum4linux/BloodHound-style collectors actually use (RID/name resolution plus SID "
                "translation together), not two coincidental calls");
        }
    }
}

// SRVSVC's own bind/bind_ack/request/response/fault bookkeeping -- same shape as
// decode_dcerpc_and_samr above (Phase 0's resolve_dcerpc_bind_bookkeeping template, no cross-interface
// note -- see srvsvc.hpp's own header comment for why SRVSVC/WKSSVC don't get one the way SAMR/LSARPC
// do).
void decode_dcerpc_and_srvsvc(SmbMessage& m, SrvsvcPipeState& pipe_state,
                               const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (resolve_dcerpc_bind_bookkeeping(dm, pipe_state, is_srvsvc_interface_uuid)) {
                continue;
            }
            if (dm.has_request) {
                if (pipe_state.bound_context_is_interface &&
                    dm.request_context_id == pipe_state.interface_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    SrvsvcCall call = try_parse_srvsvc_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.srvsvc_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    SrvsvcCall call = try_parse_srvsvc_response(dm.call_id, opnum, dm.sealed, stub);
                    m.srvsvc_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain.
        }
    }

    // Curated note -- a share was added or deleted. Fires on every occurrence, not sticky (each
    // add/delete is its own meaningful event, the same posture netlogon.hpp's own
    // NetrServerPasswordSet2 note already establishes).
    for (const SrvsvcCall& call : m.srvsvc_calls) {
        if (call.is_response) continue;
        if (call.opnum == 14) {
            m.notes.push_back(
                "SRVSVC share created (NetrShareAdd) -- new attack surface potentially opened; also "
                "routine for legitimate share administration");
        } else if (call.opnum == 18) {
            m.notes.push_back(
                "SRVSVC share deleted (NetrShareDel) -- also routine for legitimate share "
                "administration");
        }
    }
}

// WKSSVC's own bookkeeping -- same shape as decode_dcerpc_and_srvsvc above.
void decode_dcerpc_and_wkssvc(SmbMessage& m, WkssvcPipeState& pipe_state,
                               const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (resolve_dcerpc_bind_bookkeeping(dm, pipe_state, is_wkssvc_interface_uuid)) {
                continue;
            }
            if (dm.has_request) {
                if (pipe_state.bound_context_is_interface &&
                    dm.request_context_id == pipe_state.interface_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    WkssvcCall call = try_parse_wkssvc_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.wkssvc_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    WkssvcCall call = try_parse_wkssvc_response(dm.call_id, opnum, dm.sealed, stub);
                    m.wkssvc_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain.
        }
    }

    // Curated note -- a domain join/unjoin operation was observed. Fires on every occurrence, not
    // sticky, same posture as SRVSVC's own NetrShareAdd/NetrShareDel notes above.
    for (const WkssvcCall& call : m.wkssvc_calls) {
        if (call.is_response) continue;
        if (call.opnum == 22) {
            m.notes.push_back(
                "WKSSVC domain join observed (NetrJoinDomain2) -- carries encrypted domain-join "
                "credential material, never decoded by this codebase; also routine for legitimate "
                "machine provisioning");
        } else if (call.opnum == 23) {
            m.notes.push_back(
                "WKSSVC domain unjoin observed (NetrUnjoinDomain2) -- carries encrypted credential "
                "material, never decoded by this codebase; also routine for legitimate machine "
                "de-provisioning");
        }
    }
}

// DRSUAPI's own bookkeeping -- same shape as decode_dcerpc_and_srvsvc/decode_dcerpc_and_wkssvc above.
// See drsuapi.hpp's own header comment for this interface's empirically-discovered transport scope
// caveat: this function only ever runs against DRSUAPI traffic that happens to also ride an SMB
// named pipe, which is not DRSUAPI's own default real-world transport (that rides a dynamically
// negotiated raw TCP connection this codebase does not decode).
void decode_dcerpc_and_drsuapi(SmbMessage& m, DrsuapiPipeState& pipe_state,
                                const std::vector<uint8_t>& raw_payload) {
    if (raw_payload.empty()) return;
    ByteSpan payload_span(raw_payload.data(), raw_payload.size());
    m.dcerpc_messages = parse_dcerpc_chain(payload_span);

    for (const DceRpcMessage& dm : m.dcerpc_messages) {
        try {
            if (resolve_dcerpc_bind_bookkeeping(dm, pipe_state, is_drsuapi_interface_uuid)) {
                continue;
            }
            if (dm.has_request) {
                if (pipe_state.bound_context_is_interface &&
                    dm.request_context_id == pipe_state.interface_context_id) {
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    DrsuapiCall call = try_parse_drsuapi_request(dm.call_id, dm.opnum, dm.sealed, stub);
                    pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, 0};
                    m.drsuapi_calls.push_back(std::move(call));
                }
            } else if (dm.has_response) {
                auto it = pipe_state.pending_calls.find(dm.call_id);
                if (it != pipe_state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    ByteSpan stub = payload_span.subspan(dm.stub_offset, dm.stub_length);
                    DrsuapiCall call = try_parse_drsuapi_response(dm.call_id, opnum, dm.sealed, stub);
                    m.drsuapi_calls.push_back(std::move(call));
                    pipe_state.pending_calls.erase(it);
                }
            }
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain.
        }
    }

    // Curated note -- DRSGetNCChanges observed, the DCSync wire signature. Fires on every
    // occurrence, not sticky, same posture as SRVSVC's/WKSSVC's own per-occurrence notes above.
    // See drsuapi.hpp's own OPNUM COVERAGE note for why this codebase cannot independently confirm
    // DC status either way.
    for (const DrsuapiCall& call : m.drsuapi_calls) {
        if (call.is_response) continue;
        if (call.opnum == 3) {
            m.notes.push_back(
                "DRSGetNCChanges observed -- the wire signature DCSync-style tooling (e.g. Mimikatz's "
                "lsadump::dcsync) uses to pull replicated directory data, including secret material, "
                "by impersonating a domain controller; also routine, high-volume traffic between real "
                "domain controllers during ordinary AD replication. This decoder cannot independently "
                "confirm whether the calling host is actually a domain controller -- correlate "
                "against known DC inventory before treating this as suspicious.");
        }
    }
}

// Dispatches a WRITE request / READ response / IOCTL request-or-response's own dcerpc_raw_payload
// to whichever per-interface pipe-state map `file_id` is tracked in, if any -- one FileId is
// tracked in at most one map by construction (the CREATE-response handler below inserts into
// exactly one arm's map per pipe name), so this is a plain mutually-exclusive dispatch, not a
// priority order. `file_id` is taken explicitly rather than read off `m` because READ's own
// Response carries no FileId of its own (MS-SMB2) -- the caller resolves it from the matching
// READ request instead (see decode_with_correlation's own READ case) without ever setting
// m.has_file_id/m.file_id on the response message itself, which would otherwise render a
// "smb_file_id" field in output.cpp that this codebase's prior behavior never emitted for a READ
// response.
void dispatch_dcerpc_payload(SmbMessage& m, SmbFlowState& state, const SmbFileId& file_id) {
    auto nit = state.netlogon_pipes.find(file_id);
    if (nit != state.netlogon_pipes.end()) {
        decode_dcerpc_and_netlogon(m, nit->second, m.dcerpc_raw_payload);
        return;
    }
    auto sit = state.samr_pipes.find(file_id);
    if (sit != state.samr_pipes.end()) {
        decode_dcerpc_and_samr(m, sit->second, state, m.dcerpc_raw_payload);
        return;
    }
    auto lit = state.lsarpc_pipes.find(file_id);
    if (lit != state.lsarpc_pipes.end()) {
        decode_dcerpc_and_lsarpc(m, lit->second, state, m.dcerpc_raw_payload);
        return;
    }
    auto svit = state.srvsvc_pipes.find(file_id);
    if (svit != state.srvsvc_pipes.end()) {
        decode_dcerpc_and_srvsvc(m, svit->second, m.dcerpc_raw_payload);
        return;
    }
    auto wkit = state.wkssvc_pipes.find(file_id);
    if (wkit != state.wkssvc_pipes.end()) {
        decode_dcerpc_and_wkssvc(m, wkit->second, m.dcerpc_raw_payload);
        return;
    }
    auto drit = state.drsuapi_pipes.find(file_id);
    if (drit != state.drsuapi_pipes.end()) {
        decode_dcerpc_and_drsuapi(m, drit->second, m.dcerpc_raw_payload);
        return;
    }
}

// Shared correlation layer, applied on top of a successfully try_parse_smb'd frame -- the same
// "try_parse_X then XDecoder::decode applies flow-state" split kerberos.cpp's/ldap.cpp's own
// decode_with_correlation established. See smb.hpp's header comment's STATE/CORRELATION section.
std::optional<ProtocolResult> decode_with_correlation(ByteSpan payload, DecodeContext& ctx) {
    SmbFlowState& state = ctx.flow_state<SmbFlowState>();
    auto parsed = try_parse_smb(payload, &state.tracked_rpc_pipe_file_ids);
    if (!parsed) return std::nullopt;
    SmbFrame frame = std::move(*parsed);

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
                        SmbPendingRequest pending;
                        pending.packet_index = ctx.packet_index;
                        pending.command_value = m.command_value;
                        state.pending_requests[m.message_id] = pending;
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
                        state.null_or_guest_session_seen = true;  // consulted by SAMR's/LSARPC's
                                                                     // own enumeration notes below
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
                        SmbPendingRequest pending;
                        pending.packet_index = ctx.packet_index;
                        pending.command_value = m.command_value;
                        pending.tree_connect_path = m.tree_connect_path;
                        state.pending_requests[m.message_id] = pending;
                    }
                } else if (m.is_response) {
                    // TreeId -> is_pipe_share, persisted per-session -- see smb.hpp's own
                    // STATE/CORRELATION section; this is what lets a later CREATE on this same
                    // TreeId (a separate packet, possibly much later) know whether its own Name
                    // is even worth checking against "netlogon" at all.
                    if (m.has_tree_connect_response && state.pipe_shares.size() < kMaxTrackedPerSession) {
                        state.pipe_shares[m.tree_id] = (m.share_type == "pipe");
                    }
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

            case 0x05: {  // CREATE -- the "drsuapi" pipe-name match below (see drsuapi.hpp's own
                // header comment) is this codebase's own synthetic gate name, matching this batch's
                // established per-interface convention (netlogon/samr/lsarpc/srvsvc/wkssvc all gate
                // on their own interface name as the pipe name); MS-DRSR itself names no well-known
                // named pipe at all, since its own default transport is raw TCP, not a named pipe --
                // this gate only ever matches a server that happens to also expose DRSUAPI over a
                // pipe literally named "drsuapi".
                if (!m.is_response && m.has_create_request) {
                    bool is_pipe = false;
                    auto pit = state.pipe_shares.find(m.tree_id);
                    if (pit != state.pipe_shares.end()) is_pipe = pit->second;
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        SmbPendingRequest pending;
                        pending.packet_index = ctx.packet_index;
                        pending.command_value = m.command_value;
                        pending.create_name = is_pipe ? m.create_name : "";
                        state.pending_requests[m.message_id] = pending;
                    }
                } else if (m.is_response && m.has_create_response && m.has_file_id) {
                    auto it = state.pending_requests.find(m.message_id);
                    if (it != state.pending_requests.end() && it->second.command_value == m.command_value) {
                        m.correlated_request_seen = true;
                        m.correlated_request_index = it->second.packet_index;
                        if (it->second.create_name == "netlogon" &&
                            state.netlogon_pipes.size() < kMaxTrackedPerSession) {
                            state.netlogon_pipes[m.file_id] = NetlogonPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        } else if (it->second.create_name == "samr" &&
                                   state.samr_pipes.size() < kMaxTrackedPerSession) {
                            state.samr_pipes[m.file_id] = SamrPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        } else if (it->second.create_name == "lsarpc" &&
                                   state.lsarpc_pipes.size() < kMaxTrackedPerSession) {
                            state.lsarpc_pipes[m.file_id] = LsarpcPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        } else if (it->second.create_name == "srvsvc" &&
                                   state.srvsvc_pipes.size() < kMaxTrackedPerSession) {
                            state.srvsvc_pipes[m.file_id] = SrvsvcPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        } else if (it->second.create_name == "wkssvc" &&
                                   state.wkssvc_pipes.size() < kMaxTrackedPerSession) {
                            state.wkssvc_pipes[m.file_id] = WkssvcPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        } else if (it->second.create_name == "drsuapi" &&
                                   state.drsuapi_pipes.size() < kMaxTrackedPerSession) {
                            state.drsuapi_pipes[m.file_id] = DrsuapiPipeState{};
                            state.tracked_rpc_pipe_file_ids.insert(m.file_id);
                        }
                        state.pending_requests.erase(it);
                    }
                }
                break;
            }

            case 0x06: {  // CLOSE
                if (!m.is_response && m.has_file_id) {
                    state.netlogon_pipes.erase(m.file_id);
                    state.samr_pipes.erase(m.file_id);
                    state.lsarpc_pipes.erase(m.file_id);
                    state.srvsvc_pipes.erase(m.file_id);
                    state.wkssvc_pipes.erase(m.file_id);
                    state.drsuapi_pipes.erase(m.file_id);
                    state.tracked_rpc_pipe_file_ids.erase(m.file_id);
                }
                break;
            }

            case 0x08: {  // READ
                if (!m.is_response && m.has_file_id) {
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        SmbPendingRequest pending;
                        pending.packet_index = ctx.packet_index;
                        pending.command_value = m.command_value;
                        pending.has_file_id = true;
                        pending.file_id = m.file_id;
                        state.pending_requests[m.message_id] = pending;
                    }
                } else if (m.is_response) {
                    auto it = state.pending_requests.find(m.message_id);
                    if (it != state.pending_requests.end() && it->second.command_value == m.command_value) {
                        m.correlated_request_seen = true;
                        m.correlated_request_index = it->second.packet_index;
                        if (it->second.has_file_id) {
                            dispatch_dcerpc_payload(m, state, it->second.file_id);
                        }
                        state.pending_requests.erase(it);
                    }
                }
                m.dcerpc_raw_payload.clear();
                m.dcerpc_raw_payload.shrink_to_fit();
                break;
            }

            case 0x09: {  // WRITE
                if (!m.is_response && m.has_file_id) {
                    dispatch_dcerpc_payload(m, state, m.file_id);
                }
                m.dcerpc_raw_payload.clear();
                m.dcerpc_raw_payload.shrink_to_fit();
                break;
            }

            case 0x0B: {  // IOCTL
                if (m.has_file_id) {
                    dispatch_dcerpc_payload(m, state, m.file_id);
                }
                m.dcerpc_raw_payload.clear();
                m.dcerpc_raw_payload.shrink_to_fit();
                break;
            }

            case 0x02:    // LOGOFF
            case 0x04: {  // TREE_DISCONNECT
                if (!m.is_response) {
                    if (state.pending_requests.size() < kMaxTrackedPerSession) {
                        SmbPendingRequest pending;
                        pending.packet_index = ctx.packet_index;
                        pending.command_value = m.command_value;
                        state.pending_requests[m.message_id] = pending;
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
