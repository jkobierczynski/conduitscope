// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/dcerpc.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

// Renders a 16-byte NDR-marshalled GUID (Data1 4 bytes LE, Data2 2 bytes LE, Data3 2 bytes LE, Data4
// 8 bytes byte-order-preserved) as the standard dashed lowercase hex string, e.g.
// "12345678-1234-abcd-ef00-01234567cffb" -- the same mixed-endian convention every Microsoft GUID on
// the wire uses, verified against the bind PDU bytes impacket's own NDR marshalling produced during
// planning (see this file's own header comment). Exposed at namespace scope (not kept anonymous-
// namespace-local, as it was before) once drsuapi.cpp needed it too, for DRSBind's own
// puuidClientDsa field -- the exact "shared primitive once a second consumer needs it" move this
// file's own header comment already documents for ndr_align4/read_ndr_string/read_ndr_unique_string.
std::string guid_to_string(ByteSpan guid) {
    std::ostringstream s;
    s << std::hex << std::setfill('0');
    uint32_t data1 = static_cast<uint32_t>(guid.at(0)) | (static_cast<uint32_t>(guid.at(1)) << 8) |
                      (static_cast<uint32_t>(guid.at(2)) << 16) | (static_cast<uint32_t>(guid.at(3)) << 24);
    uint16_t data2 = static_cast<uint16_t>(guid.at(4) | (guid.at(5) << 8));
    uint16_t data3 = static_cast<uint16_t>(guid.at(6) | (guid.at(7) << 8));
    s << std::setw(8) << data1 << "-" << std::setw(4) << data2 << "-" << std::setw(4) << data3 << "-";
    for (size_t i = 8; i < 10; ++i) s << std::setw(2) << static_cast<unsigned>(guid.at(i));
    s << "-";
    for (size_t i = 10; i < 16; ++i) s << std::setw(2) << static_cast<unsigned>(guid.at(i));
    return s.str();
}

namespace {

// PTYPE table -- all 20 defined values, cross-checked against impacket's own rpcrt.py MSRPC_* constants
// during planning (see dcerpc.hpp's own file header comment). The five connectionless-only codes
// (ping/working/nocall/reject/ack/cl_cancel/fack/cancel_ack) are named for completeness even though
// this codebase only ever sees connection-oriented PDUs over a named pipe.
const char* ptype_name(uint8_t ptype) {
    switch (ptype) {
        case 0: return "request";
        case 1: return "ping";
        case 2: return "response";
        case 3: return "fault";
        case 4: return "working";
        case 5: return "nocall";
        case 6: return "reject";
        case 7: return "ack";
        case 8: return "cl_cancel";
        case 9: return "fack";
        case 10: return "cancel_ack";
        case 11: return "bind";
        case 12: return "bind_ack";
        case 13: return "bind_nak";
        case 14: return "alter_context";
        case 15: return "alter_context_resp";
        case 16: return "auth3";
        case 17: return "shutdown";
        case 18: return "co_cancel";
        case 19: return "orphaned";
        default: return nullptr;
    }
}

std::vector<std::string> named_pfc_flags(uint8_t flags) {
    std::vector<std::string> out;
    if (flags & 0x01) out.push_back("PFC_FIRST_FRAG");
    if (flags & 0x02) out.push_back("PFC_LAST_FRAG");
    if (flags & 0x04) out.push_back("PFC_PENDING_CANCEL");
    // 0x08 is reserved -- not named, see dcerpc.hpp's own MESSAGE COVERAGE list.
    if (flags & 0x10) out.push_back("PFC_CONC_MPX");
    if (flags & 0x20) out.push_back("PFC_DID_NOT_EXECUTE");
    if (flags & 0x40) out.push_back("PFC_MAYBE");
    if (flags & 0x80) out.push_back("PFC_OBJECT_UUID");
    return out;
}

const char* context_result_name(uint16_t result) {
    switch (result) {
        case 0: return "acceptance";
        case 1: return "user_rejection";
        case 2: return "provider_rejection";
        case 3: return "negotiate_ack";
        default: return nullptr;
    }
}

// RPC_C_AUTHN_LEVEL_* (MS-RPCE 2.2.1.1.8), values 1-6. `sealed` in DceRpcMessage keys off exactly
// PKT_PRIVACY (6) -- see dcerpc.hpp's own file header comment.
const char* auth_level_name(uint8_t level) {
    switch (level) {
        case 1: return "RPC_C_AUTHN_LEVEL_NONE";
        case 2: return "RPC_C_AUTHN_LEVEL_CONNECT";
        case 3: return "RPC_C_AUTHN_LEVEL_CALL";
        case 4: return "RPC_C_AUTHN_LEVEL_PKT";
        case 5: return "RPC_C_AUTHN_LEVEL_PKT_INTEGRITY";
        case 6: return "RPC_C_AUTHN_LEVEL_PKT_PRIVACY";
        default: return nullptr;
    }
}

constexpr const char* kNdr32TransferSyntaxUuid = "8a885d04-1ceb-11c9-9fe8-08002b104860";
constexpr uint32_t kNdr32TransferSyntaxVersionMajor = 2;

// Reads one p_cont_elem_t (context_id, transfer syntax list, only the first transfer syntax kept --
// see dcerpc.hpp's own DceRpcContextElement comment). Returns std::nullopt if not enough bytes remain
// for even the fixed portion -- the caller stops walking the context list rather than guessing.
std::optional<DceRpcContextElement> read_context_element(Cursor& c) {
    if (c.remaining() < 4 + 16 + 4) return std::nullopt;
    DceRpcContextElement e;
    e.context_id = c.u16le();
    uint8_t n_transfer_syn = c.u8();
    c.u8();  // reserved
    ByteSpan abstract_uuid = c.bytes(16);
    e.abstract_syntax_uuid = guid_to_string(abstract_uuid);
    e.abstract_syntax_version_major = c.u16le();
    e.abstract_syntax_version_minor = c.u16le();
    for (uint8_t i = 0; i < n_transfer_syn; ++i) {
        if (c.remaining() < 16 + 4) break;
        ByteSpan xfer_uuid = c.bytes(16);
        uint32_t xfer_ver_major = c.u16le();
        uint32_t xfer_ver_minor = c.u16le();
        if (i == 0) {
            e.transfer_syntax_uuid = guid_to_string(xfer_uuid);
            e.transfer_syntax_version = (xfer_ver_major << 16) | xfer_ver_minor;
            e.is_ndr32_transfer_syntax =
                (e.transfer_syntax_uuid == kNdr32TransferSyntaxUuid) && (xfer_ver_major == kNdr32TransferSyntaxVersionMajor);
        }
    }
    return e;
}

// Reads one p_result_t (24 bytes: result(2)+reason(2)+transfer_syntax{uuid(16)+version(4)}).
std::optional<DceRpcContextResult> read_context_result(Cursor& c) {
    if (c.remaining() < 2 + 2 + 16 + 4) return std::nullopt;
    DceRpcContextResult r;
    r.result_value = c.u16le();
    if (const char* n = context_result_name(r.result_value)) {
        r.result_name = n;
    } else {
        r.result_name = "result " + std::to_string(r.result_value);
    }
    c.u16le();  // reason -- not rendered, no OT-security value beyond the result itself
    ByteSpan xfer_uuid = c.bytes(16);
    r.transfer_syntax_uuid = guid_to_string(xfer_uuid);
    uint32_t ver_major = c.u16le();
    uint32_t ver_minor = c.u16le();
    r.transfer_syntax_version = (ver_major << 16) | ver_minor;
    return r;
}

}  // namespace

std::optional<DceRpcMessage> try_parse_dcerpc(ByteSpan pdu) {
    try {
        if (pdu.size() < 16) return std::nullopt;
        Cursor c(pdu);
        DceRpcMessage m;
        m.rpc_vers = c.u8();
        m.rpc_vers_minor = c.u8();
        if (m.rpc_vers != 5) return std::nullopt;  // only DCE 1.1 connection-oriented RPC is in scope
        m.ptype_value = c.u8();
        if (const char* n = ptype_name(m.ptype_value)) {
            m.ptype_name = n;
        } else {
            m.ptype_name = "ptype " + std::to_string(m.ptype_value);
        }
        uint8_t pfc_flags_byte = c.u8();
        m.pfc_flags = named_pfc_flags(pfc_flags_byte);
        m.is_first_frag = (pfc_flags_byte & 0x01) != 0;
        m.is_last_frag = (pfc_flags_byte & 0x02) != 0;
        c.skip(4);  // packed_drep -- not rendered, this codebase only ever reads little-endian ASCII
                    // wire bytes anyway and every real-world capture uses that representation
        m.frag_length = c.u16le();
        m.auth_length = c.u16le();
        m.call_id = c.u32le();

        if (m.frag_length < 16 || m.frag_length > pdu.size()) return std::nullopt;
        // Everything from here on is bounded by frag_length, not pdu.size() -- a chain-walked PDU's
        // own `pdu` span may extend past this one PDU's declared length (see parse_dcerpc_chain).
        ByteSpan body = pdu.subspan(16, m.frag_length - 16);
        Cursor bc(body);

        size_t stub_start = 0;  // relative to `pdu` (i.e. body's own 16-byte offset already added)
        bool have_stub_start = false;

        switch (m.ptype_value) {
            case 11:    // bind
            case 14: {  // alter_context -- identical body shape to bind
                if (bc.remaining() >= 8) {
                    m.has_bind = true;
                    m.bind_max_xmit_frag = bc.u16le();
                    m.bind_max_recv_frag = bc.u16le();
                    bc.u32le();  // assoc_group_id -- not rendered, no OT-security value
                    if (bc.remaining() >= 4) {
                        uint8_t n_context_elem = bc.u8();
                        bc.skip(3);  // reserved/reserved2
                        const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
                        for (uint8_t i = 0; i < n_context_elem && m.bind_contexts.size() < kMax; ++i) {
                            auto elem = read_context_element(bc);
                            if (!elem) break;
                            m.bind_contexts.push_back(std::move(*elem));
                        }
                    }
                }
                break;
            }
            case 12:    // bind_ack
            case 15: {  // alter_context_resp -- identical body shape to bind_ack
                if (bc.remaining() >= 8) {
                    m.has_bind_ack = true;
                    m.bind_ack_max_xmit_frag = bc.u16le();
                    m.bind_ack_max_recv_frag = bc.u16le();
                    bc.u32le();  // assoc_group_id
                    if (bc.remaining() >= 2) {
                        uint16_t sec_addr_len = bc.u16le();
                        if (bc.remaining() >= sec_addr_len) bc.skip(sec_addr_len);
                        // pad2 -- align to a 4-byte boundary relative to the start of the PDU (offset
                        // 16 + however far bc has advanced), per this file's own MESSAGE COVERAGE note.
                        size_t abs_pos = 16 + bc.position();
                        size_t pad = (4 - (abs_pos % 4)) % 4;
                        if (bc.remaining() >= pad) bc.skip(pad);
                        if (bc.remaining() >= 4) {
                            uint8_t n_results = bc.u8();
                            bc.skip(3);  // reserved
                            const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
                            for (uint8_t i = 0; i < n_results && m.bind_ack_results.size() < kMax; ++i) {
                                auto res = read_context_result(bc);
                                if (!res) break;
                                m.bind_ack_results.push_back(std::move(*res));
                            }
                        }
                    }
                }
                break;
            }
            case 0: {  // request
                if (bc.remaining() >= 8) {
                    m.has_request = true;
                    bc.u32le();  // alloc_hint -- not rendered, purely a marshalling size hint
                    m.request_context_id = bc.u16le();
                    m.opnum = bc.u16le();
                    if ((pfc_flags_byte & 0x80) != 0 && bc.remaining() >= 16) {
                        bc.skip(16);  // object UUID -- recognized via PFC_OBJECT_UUID, not itself
                                      // decoded, see dcerpc.hpp's own MESSAGE COVERAGE note
                    }
                    stub_start = 16 + bc.position();
                    have_stub_start = true;
                }
                break;
            }
            case 2: {  // response
                if (bc.remaining() >= 8) {
                    m.has_response = true;
                    bc.u32le();  // alloc_hint
                    m.response_context_id = bc.u16le();
                    bc.u8();  // cancel_count
                    bc.u8();  // reserved
                    stub_start = 16 + bc.position();
                    have_stub_start = true;
                }
                break;
            }
            case 3: {  // fault
                if (bc.remaining() >= 12) {
                    m.has_fault = true;
                    bc.u32le();  // alloc_hint
                    bc.u16le();  // p_cont_id -- not separately rendered for a fault
                    bc.u8();     // cancel_count
                    bc.u8();     // reserved
                    m.fault_status = bc.u32le();
                    if (bc.remaining() >= 4) bc.skip(4);  // reserved2
                    stub_start = 16 + bc.position();
                    have_stub_start = true;
                }
                break;
            }
            default:
                break;  // every other PTYPE is header-only for this codebase's own scope
        }

        // sec_trailer, present whenever auth_length > 0 -- see dcerpc.hpp's own MESSAGE COVERAGE note.
        // Located at frag_length - auth_length - 8 (the trailer's own 8-byte fixed header), with
        // auth_value occupying the trailing auth_length bytes.
        if (m.auth_length > 0 && m.frag_length >= static_cast<size_t>(m.auth_length) + 8) {
            size_t trailer_start = m.frag_length - m.auth_length - 8;
            if (trailer_start + 8 <= pdu.size() && (!have_stub_start || trailer_start >= stub_start)) {
                Cursor tc(pdu.subspan(trailer_start, 8));
                m.has_sec_trailer = true;
                m.auth_type = tc.u8();
                m.auth_level = tc.u8();
                tc.u8();   // auth_pad_length -- recognized structurally only, see dcerpc.hpp's header
                tc.u8();   // auth_reserved
                tc.u32le();  // auth_context_id -- not rendered, no OT-security value on its own
                if (const char* n = auth_level_name(m.auth_level)) m.auth_level_name = n;
                m.sealed = (m.auth_level == 6);  // RPC_C_AUTHN_LEVEL_PKT_PRIVACY
                if (have_stub_start && trailer_start > stub_start) {
                    m.stub_offset = stub_start;
                    m.stub_length = trailer_start - stub_start;
                }
            } else if (have_stub_start) {
                m.stub_offset = stub_start;
                m.stub_length = (m.frag_length > stub_start) ? (m.frag_length - stub_start) : 0;
            }
        } else if (have_stub_start) {
            m.stub_offset = stub_start;
            m.stub_length = (m.frag_length > stub_start) ? (m.frag_length - stub_start) : 0;
        }

        std::ostringstream s;
        s << "DCE/RPC " << m.ptype_name;
        if (m.has_request) s << " (opnum " << m.opnum << ")";
        m.summary = s.str();
        return m;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------------------------
// Shared NDR primitives -- see this file's own header comment (dcerpc.hpp) for provenance. These
// are byte-for-byte the same implementations netlogon.cpp used locally before more than one
// interface needed them.
// ---------------------------------------------------------------------------------------------

void ndr_align4(Cursor& c) {
    size_t pad = (4 - (c.position() % 4)) % 4;
    if (pad > 0) c.skip(pad);
}

std::string read_ndr_string(Cursor& c) {
    ndr_align4(c);  // a conformant array's own MaxCount is a 4-byte field
    (void)c.u32le();  // MaxCount -- structurally present, not itself meaningful here
    (void)c.u32le();  // Offset -- likewise
    uint32_t actual_count = c.u32le();
    ByteSpan chars = c.bytes(static_cast<size_t>(actual_count) * 2);
    std::string s = utf16le_to_utf8(chars);
    if (!s.empty() && s.back() == '\0') {
        s.pop_back();
    }
    size_t pad = (4 - (c.position() % 4)) % 4;
    if (pad > 0) {
        c.skip(pad);
    }
    return s;
}

std::string read_ndr_unique_string(Cursor& c) {
    ndr_align4(c);  // the referent ID itself is a 4-byte field
    uint32_t referent_id = c.u32le();
    if (referent_id == 0) {
        return std::string();
    }
    return read_ndr_string(c);
}

std::string read_ndr_sid(Cursor& c) {
    (void)c.u32le();  // hoisted MaximumCount -- structurally present, SubAuthorityCount (below) is
                       // what this codebase actually trusts for how many sub-authorities follow.
    uint8_t revision = c.u8();
    uint8_t sub_authority_count = c.u8();
    uint64_t identifier_authority = 0;
    for (int i = 0; i < 6; ++i) {
        identifier_authority = (identifier_authority << 8) | c.u8();
    }
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::ostringstream oss;
    oss << "S-" << static_cast<unsigned>(revision) << "-" << identifier_authority;
    for (uint8_t i = 0; i < sub_authority_count && i < kMax; ++i) {
        oss << "-" << c.u32le();
    }
    return oss.str();
}

std::vector<std::string> read_ndr_sid_pointer_array(Cursor& c) {
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> referents;
    for (uint32_t i = 0; i < maximum_count && referents.size() < kMax; ++i) {
        referents.push_back(c.u32le());
    }
    std::vector<std::string> sids;
    sids.reserve(referents.size());
    for (uint32_t referent : referents) {
        sids.push_back(referent != 0 ? read_ndr_sid(c) : std::string());
    }
    return sids;
}

std::vector<std::string> read_ndr_unicode_string_array(Cursor& c) {
    (void)c.u32le();  // MaxCount
    (void)c.u32le();  // Offset
    uint32_t actual_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> referents;
    referents.reserve(actual_count < kMax ? actual_count : kMax);
    for (uint32_t i = 0; i < actual_count && referents.size() < kMax; ++i) {
        (void)c.u16le();  // Length
        (void)c.u16le();  // MaximumLength
        referents.push_back(c.u32le());
    }
    std::vector<std::string> names;
    names.reserve(referents.size());
    for (uint32_t referent : referents) {
        names.push_back(referent != 0 ? read_ndr_string(c) : std::string());
    }
    return names;
}

std::vector<uint32_t> read_ndr_ulong_conformant_varying_array(Cursor& c) {
    (void)c.u32le();  // MaxCount
    (void)c.u32le();  // Offset
    uint32_t actual_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> values;
    values.reserve(actual_count < kMax ? actual_count : kMax);
    for (uint32_t i = 0; i < actual_count && values.size() < kMax; ++i) {
        values.push_back(c.u32le());
    }
    return values;
}

std::vector<uint32_t> read_ndr_count_and_ptr_ulong_array(Cursor& c) {
    (void)c.u32le();  // Count -- self-describing MaximumCount below is trusted instead
    uint32_t referent = c.u32le();
    if (referent == 0) {
        return {};
    }
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> values;
    values.reserve(maximum_count < kMax ? maximum_count : kMax);
    for (uint32_t i = 0; i < maximum_count && values.size() < kMax; ++i) {
        values.push_back(c.u32le());
    }
    return values;
}

std::vector<DceRpcMessage> parse_dcerpc_chain(ByteSpan payload) {
    std::vector<DceRpcMessage> messages;
    const size_t kMaxChain = resource_limits().max_decoded_objects.value_or(64);
    size_t offset = 0;
    while (offset + 16 <= payload.size() && messages.size() < kMaxChain) {
        ByteSpan remaining = payload.from(offset);
        auto msg = try_parse_dcerpc(remaining);
        if (!msg) break;
        // Rebase this PDU's own (locally-relative) stub_offset to be absolute within `payload`, per
        // this file's own parse_dcerpc_chain doc comment.
        if (msg->stub_length > 0) msg->stub_offset += offset;
        size_t frag_len = msg->frag_length;
        messages.push_back(std::move(*msg));
        if (frag_len < 16) break;  // defensive -- try_parse_dcerpc already rejects this, but never loop
        offset += frag_len;
    }
    return messages;
}

}  // namespace conduitscope
