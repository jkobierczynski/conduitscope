// SPDX-License-Identifier: Apache-2.0
// srvsvc.cpp - implementation of srvsvc.hpp. See that file's own header comment for the full design
// rationale, verification methodology, and opnum coverage table; this file follows it exactly.
#include "conduitscope/srvsvc.hpp"

#include <cstdio>

#include "conduitscope/dcerpc.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

const char* srvsvc_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 8: return "NetrConnectionEnum";
        case 9: return "NetrFileEnum";
        case 12: return "NetrSessionEnum";
        case 14: return "NetrShareAdd";
        case 15: return "NetrShareEnum";
        case 16: return "NetrShareGetInfo";
        case 18: return "NetrShareDel";
        default: return nullptr;
    }
}

// SRVSVC's own ErrorCode fields are Win32/WERROR codes, a distinct numbering space from the NTSTATUS
// values netlogon.cpp's/samr.cpp's own status tables name -- own small table per this codebase's
// established per-file convention.
std::string srvsvc_status_name(uint32_t status) {
    switch (status) {
        case 0: return "NERR_Success";
        case 5: return "ERROR_ACCESS_DENIED";
        case 123: return "ERROR_INVALID_NAME";
        case 2114: return "NERR_BufTooSmall";
        case 2310: return "NERR_NetNameNotFound";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// shi1_type (MS-SRVS 2.2.2.4 SHARE_TYPE) -- base value in the low bits, STYPE_SPECIAL (0x80000000)
// as a standalone top-bit flag marking an administrative/hidden share (C$/ADMIN$/IPC$/print$).
std::string srvsvc_share_type_name(uint32_t type) {
    uint32_t base = type & 0x7FFFFFFFu;
    std::string name;
    switch (base) {
        case 0: name = "disk"; break;
        case 1: name = "print_queue"; break;
        case 2: name = "device"; break;
        case 3: name = "ipc"; break;
        default: {
            char buf[24];
            std::snprintf(buf, sizeof(buf), "type %u", base);
            name = buf;
            break;
        }
    }
    if (type & 0x80000000u) {
        name += " (special)";
    }
    return name;
}

// Reads one SHARE_INFO_1 (MS-SRVS 2.2.4.23): shi1_netname(LPWSTR unique) / shi1_type(DWORD) /
// shi1_remark(LPWSTR unique) -- the cursor must already be at this struct's own fixed part (i.e. the
// caller has already confirmed a nonzero pointer referent to it, whether from a top-level SHARE_INFO
// union arm or an array element). This struct is reached via a pointer, so -- like every other NESTED
// constructed type in this codebase (see samr.cpp's own header comment on the general rule) -- it uses
// the "batched" shape, NOT the eager per-field shape read_ndr_unique_string alone would give: both
// pointer referents (netname, remark) are written as part of this struct's own fixed part, BEFORE
// either one's own deferred string data, empirically confirmed during planning by marshalling a real
// NetrShareGetInfoResponse through impacket and hex-dumping the actual bytes (see srvsvc.hpp's own
// header comment).
SrvsvcShareEntry read_share_info_1(Cursor& c) {
    SrvsvcShareEntry entry;
    uint32_t netname_referent = c.u32le();
    entry.type = c.u32le();
    entry.type_name = srvsvc_share_type_name(entry.type);
    uint32_t remark_referent = c.u32le();
    entry.net_name = netname_referent != 0 ? read_ndr_string(c) : std::string();
    entry.remark = remark_referent != 0 ? read_ndr_string(c) : std::string();
    return entry;
}

// Reads the BODY of one SHARE_INFO_1_ARRAY (MS-SRVS 2.2.4.23) -- the cursor must already be positioned
// at the array's own conformant header (a nonzero pointer to it already confirmed by the caller). Wire
// shape, empirically confirmed during planning (see srvsvc.hpp's own header comment): a hoisted
// MaximumCount(4), then MaximumCount x this struct's own fixed part (netname-referent(4)/type(4)/
// remark-referent(4), 12 bytes/element -- NOT the full read_share_info_1 shape yet, since the array's
// own elements are themselves an NDR "batched" shape, see samr.cpp's own header comment on the same
// distinction for SAMPR_RID_ENUMERATION), then -- for every element, in order -- that element's own
// deferred string data (netname first, then remark, matching each element's own declared field order).
std::vector<SrvsvcShareEntry> read_share_info_1_array(Cursor& c) {
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> netname_referents;
    std::vector<uint32_t> types;
    std::vector<uint32_t> remark_referents;
    for (uint32_t i = 0; i < maximum_count && netname_referents.size() < kMax; ++i) {
        netname_referents.push_back(c.u32le());
        types.push_back(c.u32le());
        remark_referents.push_back(c.u32le());
    }
    std::vector<SrvsvcShareEntry> entries;
    entries.reserve(netname_referents.size());
    for (size_t i = 0; i < netname_referents.size(); ++i) {
        SrvsvcShareEntry entry;
        entry.net_name = netname_referents[i] != 0 ? read_ndr_string(c) : std::string();
        entry.type = types[i];
        entry.type_name = srvsvc_share_type_name(entry.type);
        entry.remark = remark_referents[i] != 0 ? read_ndr_string(c) : std::string();
        entries.push_back(std::move(entry));
    }
    return entries;
}

// ---------------------------------------------------------------------------------------------
// Request-side parse functions.
// ---------------------------------------------------------------------------------------------

// NetrShareEnum (15) request -- ServerName(PSRVSVC_HANDLE unique) + InfoStruct{Level(u32),
// ShareInfo:SHARE_ENUM_UNION{tag(u32, duplicate of Level, discarded), Level1:pointer (always NULL on
// a client's own enumeration request -- structurally legal to be non-NULL, but this file cannot
// safely skip an unverified arm's own deferred content, so parsing simply stops there if it ever is)}
// + PreferedMaximumLength + ResumeHandle -- neither of the latter two is rendered.
SrvsvcCall parse_share_enum_request(uint32_t call_id, ByteSpan stub) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = 15;
    call.opnum_name = srvsvc_opnum_name(15);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        call.level = c.u32le();
        call.has_level = true;
        (void)c.u32le();  // ShareInfo.tag -- duplicate of Level, discarded
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " level=" + std::to_string(call.level);
    return call;
}

// NetrShareGetInfo (16) request -- ServerName(PSRVSVC_HANDLE unique) + NetName(WSTR, embedded
// conformant-varying string, NOT behind a pointer) + Level(u32).
SrvsvcCall parse_share_get_info_request(uint32_t call_id, ByteSpan stub) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = 16;
    call.opnum_name = srvsvc_opnum_name(16);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        call.net_name = read_ndr_string(c);
        call.level = c.u32le();
        call.has_level = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " net_name=" + call.net_name;
    return call;
}

// NetrConnectionEnum(8)/NetrFileEnum(9)/NetrSessionEnum(12) request -- ServerName(PSRVSVC_HANDLE
// unique), then `extra_unique_strings` more [unique] LPWSTR filter fields this file does not itself
// render (Qualifier for ConnectionEnum; BasePath+UserName for FileEnum; ClientName+UserName for
// SessionEnum -- see srvsvc.hpp's own OPNUM COVERAGE note on why only ServerName/Level are decoded),
// then the enumeration's own InfoStruct.Level (+ its union's own duplicate tag, discarded, same shape
// as NetrShareEnum's own InfoStruct above).
SrvsvcCall parse_enum_header_only_request(uint32_t call_id, uint16_t opnum, int extra_unique_strings,
                                           ByteSpan stub) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = srvsvc_opnum_name(opnum);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        for (int i = 0; i < extra_unique_strings; ++i) {
            (void)read_ndr_unique_string(c);
        }
        call.level = c.u32le();
        call.has_level = true;
        (void)c.u32le();  // InfoStruct's own union tag -- duplicate of Level, discarded
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " level=" + std::to_string(call.level);
    return call;
}

SrvsvcCall parse_admin_action_request(uint32_t call_id, uint16_t opnum) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = srvsvc_opnum_name(opnum);
    call.is_response = false;
    call.summary = call.opnum_name;
    return call;
}

// ---------------------------------------------------------------------------------------------
// Response-side parse functions.
// ---------------------------------------------------------------------------------------------

// NetrShareEnum (15) response -- InfoStruct{Level(u32), ShareInfo:SHARE_ENUM_UNION{tag(u32,
// duplicate, discarded), Level1:pointer to SHARE_INFO_1_CONTAINER{EntriesRead(u32, discarded --
// TotalEntries below is authoritative/rendered instead), Buffer:pointer to SHARE_INFO_1_ARRAY}}},
// TotalEntries(u32), ResumeHandle(pointer, discarded), ErrorCode(u32). Non-level-1 responses (Level
// != 1) are left with an empty shares vector -- this file does not attempt any other SHARE_INFO_N
// shape (see srvsvc.hpp's own OPNUM COVERAGE note).
SrvsvcCall parse_share_enum_response(uint32_t call_id, ByteSpan stub) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = 15;
    call.opnum_name = srvsvc_opnum_name(15);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.level = c.u32le();
        call.has_level = true;
        uint32_t tag = c.u32le();
        uint32_t container_referent = c.u32le();
        if (call.level == 1 && tag == 1 && container_referent != 0) {
            (void)c.u32le();  // EntriesRead -- TotalEntries (below) is authoritative/rendered instead
            uint32_t array_referent = c.u32le();
            if (array_referent != 0) {
                call.shares = read_share_info_1_array(c);
            }
        }
        call.total_entries = c.u32le();
        call.has_total_entries = true;
        uint32_t resume_referent = c.u32le();
        if (resume_referent != 0) {
            (void)c.u32le();  // ResumeHandle's own deferred value -- not itself rendered
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = srvsvc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response shares=" + std::to_string(call.shares.size()) +
                   " total=" + std::to_string(call.total_entries) + " status=" + call.status_name;
    return call;
}

// NetrShareGetInfo (16) response -- InfoStruct: SHARE_INFO union{tag(u32), ShareInfo1: pointer to a
// single SHARE_INFO_1 (NOT a container -- GetInfo returns exactly one share, not an array)},
// ErrorCode(u32). Non-level-1 responses are left with an empty shares vector, same posture as
// NetrShareEnum's own response above.
SrvsvcCall parse_share_get_info_response(uint32_t call_id, ByteSpan stub) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = 16;
    call.opnum_name = srvsvc_opnum_name(16);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        uint32_t tag = c.u32le();
        call.level = tag;
        call.has_level = true;
        uint32_t info_referent = c.u32le();
        if (tag == 1 && info_referent != 0) {
            call.shares.push_back(read_share_info_1(c));
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = srvsvc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response shares=" + std::to_string(call.shares.size()) +
                   " status=" + call.status_name;
    return call;
}

SrvsvcCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = srvsvc_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

SrvsvcCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    SrvsvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = srvsvc_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

}  // namespace

bool is_srvsvc_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kSrvsvcInterfaceUuid;
}

std::string srvsvc_opnum_name(uint16_t opnum) {
    const char* name = srvsvc_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

SrvsvcCall try_parse_srvsvc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 15:
            return parse_share_enum_request(call_id, stub);
        case 16:
            return parse_share_get_info_request(call_id, stub);
        case 8:
            return parse_enum_header_only_request(call_id, opnum, 1, stub);
        case 9:
            return parse_enum_header_only_request(call_id, opnum, 2, stub);
        case 12:
            return parse_enum_header_only_request(call_id, opnum, 2, stub);
        case 14:
        case 18:
            return parse_admin_action_request(call_id, opnum);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

SrvsvcCall try_parse_srvsvc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 15:
            return parse_share_enum_response(call_id, stub);
        case 16:
            return parse_share_get_info_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
