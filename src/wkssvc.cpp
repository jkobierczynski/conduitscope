// SPDX-License-Identifier: Apache-2.0
// wkssvc.cpp - implementation of wkssvc.hpp. See that file's own header comment for the full design
// rationale, verification methodology, and opnum coverage table; this file follows it exactly.
#include "conduitscope/wkssvc.hpp"

#include <cstdio>

#include "conduitscope/dcerpc.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

const char* wkssvc_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 0: return "NetrWkstaGetInfo";
        case 2: return "NetrWkstaUserEnum";
        case 5: return "NetrWkstaTransportEnum";
        case 22: return "NetrJoinDomain2";
        case 23: return "NetrUnjoinDomain2";
        default: return nullptr;
    }
}

// WKSSVC's own ErrorCode fields are Win32/WERROR codes -- own small table, same posture as
// srvsvc.cpp's own srvsvc_status_name (a distinct numbering space from netlogon.cpp's/samr.cpp's own
// NTSTATUS tables).
std::string wkssvc_status_name(uint32_t status) {
    switch (status) {
        case 0: return "NERR_Success";
        case 5: return "ERROR_ACCESS_DENIED";
        case 1355: return "ERROR_NO_SUCH_DOMAIN";
        case 2224: return "NERR_UserExists";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// Reads the BODY of one WKSTA_USER_INFO_1_ARRAY (MS-WKST 2.2.5.10/2.2.5.13) -- the cursor must
// already be positioned at the array's own conformant header (a nonzero pointer to it already
// confirmed by the caller). Wire shape, empirically confirmed during planning (see wkssvc.hpp's own
// header comment): a hoisted MaximumCount(4), then MaximumCount x this struct's own fixed part
// (username/logon_domain/oth_domains/logon_server -- four 4-byte pointer referents, 16 bytes/
// element), then -- for every element, in order -- that element's own four deferred strings, in the
// same declared field order.
std::vector<WkssvcUserEntry> read_wksta_user_info_1_array(Cursor& c) {
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    struct Referents {
        uint32_t username = 0;
        uint32_t logon_domain = 0;
        uint32_t oth_domains = 0;
        uint32_t logon_server = 0;
    };
    std::vector<Referents> referents;
    for (uint32_t i = 0; i < maximum_count && referents.size() < kMax; ++i) {
        Referents r;
        r.username = c.u32le();
        r.logon_domain = c.u32le();
        r.oth_domains = c.u32le();
        r.logon_server = c.u32le();
        referents.push_back(r);
    }
    std::vector<WkssvcUserEntry> entries;
    entries.reserve(referents.size());
    for (const Referents& r : referents) {
        WkssvcUserEntry entry;
        entry.username = r.username != 0 ? read_ndr_string(c) : std::string();
        entry.logon_domain = r.logon_domain != 0 ? read_ndr_string(c) : std::string();
        entry.oth_domains = r.oth_domains != 0 ? read_ndr_string(c) : std::string();
        entry.logon_server = r.logon_server != 0 ? read_ndr_string(c) : std::string();
        entries.push_back(std::move(entry));
    }
    return entries;
}

// ---------------------------------------------------------------------------------------------
// Request-side parse functions.
// ---------------------------------------------------------------------------------------------

// NetrWkstaGetInfo (0) request -- ServerName(LPWKSSVC_IDENTIFY_HANDLE unique) + Level(u32), directly,
// no union on the request side (unlike SRVSVC's own NetrShareEnum/NetrShareGetInfo, WKSTA_INFO's own
// union only appears in the response).
WkssvcCall parse_get_info_request(uint32_t call_id, ByteSpan stub) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = 0;
    call.opnum_name = wkssvc_opnum_name(0);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        call.level = c.u32le();
        call.has_level = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " level=" + std::to_string(call.level);
    return call;
}

// NetrWkstaUserEnum (2) request -- ServerName(LPWKSSVC_IDENTIFY_HANDLE unique) + UserInfo{Level(u32),
// WkstaUserInfo:WKSTA_USER_ENUM_UNION{tag(u32, duplicate of Level, discarded), Level1:pointer (always
// NULL on a client's own enumeration request, same posture as srvsvc.hpp's own SHARE_ENUM_UNION)}} +
// PreferredMaximumLength + ResumeHandle -- neither of the latter two is rendered.
WkssvcCall parse_user_enum_request(uint32_t call_id, ByteSpan stub) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = 2;
    call.opnum_name = wkssvc_opnum_name(2);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        call.level = c.u32le();
        call.has_level = true;
        (void)c.u32le();  // WkstaUserInfo.tag -- duplicate of Level, discarded
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " level=" + std::to_string(call.level);
    return call;
}

// NetrWkstaTransportEnum (5) request -- ServerName(LPWKSSVC_IDENTIFY_HANDLE unique) +
// TransportInfo{Level(u32), TransportInfo:union{tag, ...}} + PreferredMaximumLength + ResumeHandle --
// same header-only shape/reasoning as srvsvc.hpp's own NetrConnectionEnum/NetrFileEnum/
// NetrSessionEnum request parsing (see wkssvc.hpp's own OPNUM COVERAGE note for why the response side
// is not decoded at all).
WkssvcCall parse_transport_enum_request(uint32_t call_id, ByteSpan stub) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = 5;
    call.opnum_name = wkssvc_opnum_name(5);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
        call.level = c.u32le();
        call.has_level = true;
        (void)c.u32le();  // TransportInfo's own union tag -- duplicate of Level, discarded
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " level=" + std::to_string(call.level);
    return call;
}

WkssvcCall parse_join_action_request(uint32_t call_id, uint16_t opnum) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = wkssvc_opnum_name(opnum);
    call.is_response = false;
    call.summary = call.opnum_name;
    return call;
}

// ---------------------------------------------------------------------------------------------
// Response-side parse functions.
// ---------------------------------------------------------------------------------------------

// NetrWkstaGetInfo (0) response -- WkstaInfo: WKSTA_INFO union{tag(u32), WkstaInfo100: pointer to a
// nested WKSTA_INFO_100 struct}, ErrorCode(u32). Non-level-100 responses are left with
// has_wksta_info == false -- see wkssvc.hpp's own OPNUM COVERAGE note.
WkssvcCall parse_get_info_response(uint32_t call_id, ByteSpan stub) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = 0;
    call.opnum_name = wkssvc_opnum_name(0);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        uint32_t tag = c.u32le();
        call.level = tag;
        call.has_level = true;
        uint32_t info_referent = c.u32le();
        if (tag == 100 && info_referent != 0) {
            // WKSTA_INFO_100's own fixed part, then its own deferred string data, in declared order
            // (see this file's own header comment).
            call.platform_id = c.u32le();
            uint32_t computername_referent = c.u32le();
            uint32_t langroup_referent = c.u32le();
            call.ver_major = c.u32le();
            call.ver_minor = c.u32le();
            call.computername = computername_referent != 0 ? read_ndr_string(c) : std::string();
            call.langroup = langroup_referent != 0 ? read_ndr_string(c) : std::string();
            call.has_wksta_info = true;
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = wkssvc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   (call.has_wksta_info ? " response computername=" + call.computername : " response") +
                   " status=" + call.status_name;
    return call;
}

// NetrWkstaUserEnum (2) response -- UserInfo{Level(u32), WkstaUserInfo:WKSTA_USER_ENUM_UNION{tag(u32,
// duplicate, discarded), Level1:pointer to WKSTA_USER_INFO_1_CONTAINER{EntriesRead(u32, discarded --
// TotalEntries below is authoritative/rendered instead), Buffer:pointer to
// WKSTA_USER_INFO_1_ARRAY}}}, TotalEntries(u32), ResumeHandle(a plain ULONG VALUE here, not a
// pointer -- empirically confirmed during planning, unlike SRVSVC's own NetrShareEnum response, whose
// ResumeHandle IS a pointer), ErrorCode(u32).
WkssvcCall parse_user_enum_response(uint32_t call_id, ByteSpan stub) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = 2;
    call.opnum_name = wkssvc_opnum_name(2);
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
                call.logged_on_users = read_wksta_user_info_1_array(c);
            }
        }
        call.total_entries = c.u32le();
        call.has_total_entries = true;
        (void)c.u32le();  // ResumeHandle -- a plain value here, not itself rendered
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = wkssvc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response users=" + std::to_string(call.logged_on_users.size()) +
                   " total=" + std::to_string(call.total_entries) + " status=" + call.status_name;
    return call;
}

WkssvcCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = wkssvc_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

WkssvcCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    WkssvcCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = wkssvc_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

}  // namespace

bool is_wkssvc_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kWkssvcInterfaceUuid;
}

std::string wkssvc_opnum_name(uint16_t opnum) {
    const char* name = wkssvc_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

WkssvcCall try_parse_wkssvc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 0:
            return parse_get_info_request(call_id, stub);
        case 2:
            return parse_user_enum_request(call_id, stub);
        case 5:
            return parse_transport_enum_request(call_id, stub);
        case 22:
        case 23:
            return parse_join_action_request(call_id, opnum);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

WkssvcCall try_parse_wkssvc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 0:
            return parse_get_info_response(call_id, stub);
        case 2:
            return parse_user_enum_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
