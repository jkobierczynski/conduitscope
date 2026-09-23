// SPDX-License-Identifier: Apache-2.0
// samr.cpp - implementation of samr.hpp. See that file's own header comment for the full design
// rationale, verification methodology, and opnum coverage table; this file follows it exactly.
//
// NDR DEFERRED-POINTER ORDERING, empirically derived (see samr.hpp's own header comment on why this
// needed an empirical pass beyond just reading the spec): a DCE/RPC call's own TOP-LEVEL request/
// response fields resolve EAGERLY -- each field, in declared order, is fully written (including
// chasing any pointer it holds all the way down) before the next top-level field begins. A NESTED
// constructed type -- anything reached only via a pointer's own deferred data, one or more levels
// down from the top level -- instead uses the textbook NDR "batched" shape: every field of that one
// nested struct is written in order first (scalars by value, pointers as a bare referent ID), and
// only once the whole struct's own field list is exhausted does its own pointers' deferred data
// follow, in the same declared order. An ARRAY (a repeated run of same-typed elements, at ANY
// nesting depth) always uses the batched shape for ITS OWN elements regardless of which rule
// produced the array in the first place: every element's fixed part first, then every element's
// deferred data, in element order -- this is why dcerpc.hpp's own read_ndr_unicode_string_array/
// read_ndr_sid_pointer_array/read_ndr_ulong_conformant_varying_array are safe to call unconditionally
// once a pointer to one has been confirmed non-null, whether that pointer was itself a top-level
// field or several levels deep.
#include "conduitscope/samr.hpp"

#include <cstdio>

#include "conduitscope/dcerpc.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

const char* samr_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 0: return "SamrConnect";
        case 1: return "SamrClose";
        case 7: return "SamrOpenDomain";
        case 13: return "SamrEnumerateUsersInDomain";
        case 15: return "SamrEnumerateAliasesInDomain";
        case 16: return "SamrGetAliasMembership";
        case 17: return "SamrLookupNamesInDomain";
        case 18: return "SamrLookupIdsInDomain";
        case 19: return "SamrOpenGroup";
        case 27: return "SamrOpenAlias";
        case 34: return "SamrOpenUser";
        case 37: return "SamrSetInformationUser";
        case 38: return "SamrChangePasswordUser";
        case 54: return "SamrOemChangePasswordUser2";
        case 57: return "SamrConnect2";
        case 62: return "SamrConnect4";
        case 64: return "SamrConnect5";
        default: return nullptr;
    }
}

// A small, locally-scoped NTSTATUS subset -- own table per this codebase's established per-file
// convention (see netlogon.cpp's own netlogon_status_name).
std::string samr_status_name(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0x00000103: return "STATUS_MORE_ENTRIES";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Request-side parse functions. Each wrapped in try/catch: a malformed/truncated stub yields
// whatever fields were decoded before the truncation was hit, the same per-field leniency
// netlogon.cpp's own parse functions already establish.
// ---------------------------------------------------------------------------------------------

// SamrConnect/2/4/5 (0/57/62/64) -- only ServerName is decoded uniformly across all four variants;
// see samr.hpp's own OPNUM COVERAGE note on why the trailing fields (which differ per variant,
// including Connect5's own not-independently-verified InRevisionInfo union) are not.
SamrCall parse_connect_request(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = false;
    try {
        Cursor c(stub);
        call.server_name = read_ndr_unique_string(c);
        call.has_server_name = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + (call.server_name.empty() ? "" : " server=" + call.server_name);
    return call;
}

// SamrOpenDomain (7) -- ServerHandle(20) + DesiredAccess(u32) + DomainId (RPC_SID, embedded by
// value, no separate pointer referent -- empirically confirmed during planning: a top-level [ref]
// SID parameter, like netlogon.hpp's own top-level [ref] wchar_t* strings, carries no referent ID).
SamrCall parse_open_domain_request(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 7;
    call.opnum_name = samr_opnum_name(7);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        call.desired_access = c.u32le();
        call.open_domain_sid = read_ndr_sid(c);
        call.has_open_target = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " domain=" + call.open_domain_sid;
    return call;
}

// SamrOpenUser/OpenAlias/OpenGroup (34/27/19) -- identical shape: DomainHandle(20) +
// DesiredAccess(u32) + a plain u32 RID (UserId/AliasId/GroupId, same field position either way).
SamrCall parse_open_rid_request(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        call.desired_access = c.u32le();
        call.open_rid = c.u32le();
        call.has_open_rid = true;
        call.has_open_target = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " rid=" + std::to_string(call.open_rid);
    return call;
}

// SamrLookupNamesInDomain (17) request -- DomainHandle(20) + Count(u32) + Names (a top-level
// embedded conformant-varying array of RPC_UNICODE_STRING -- no separate pointer, empirically
// confirmed: NDR passes a top-level array parameter by value, not behind a referent).
SamrCall parse_lookup_names_request(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 17;
    call.opnum_name = samr_opnum_name(17);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        (void)c.u32le();  // Count -- the array's own ActualCount (below) is self-describing
        call.lookup_names = read_ndr_unicode_string_array(c);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " names=" + std::to_string(call.lookup_names.size());
    return call;
}

// SamrLookupIdsInDomain (18) request -- DomainHandle(20) + Count(u32) + RelativeIds (a top-level
// embedded conformant-varying array of plain ULONG).
SamrCall parse_lookup_ids_request(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 18;
    call.opnum_name = samr_opnum_name(18);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        (void)c.u32le();  // Count
        call.lookup_rids = read_ndr_ulong_conformant_varying_array(c);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " rids=" + std::to_string(call.lookup_rids.size());
    return call;
}

// SamrEnumerateUsersInDomain (13) / SamrEnumerateAliasesInDomain (15) request -- identical leading
// shape (DomainHandle + EnumerationContext), Users alone carries an extra UserAccountControl filter
// field before PreferedMaximumLength; neither filter nor PreferedMaximumLength itself is rendered
// (informational only, no recon value beyond "an enumeration was attempted").
SamrCall parse_enumerate_request(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        call.enumeration_context = c.u32le();
        call.has_enumeration_context = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name;
    return call;
}

// SamrGetAliasMembership (16) request -- DomainHandle(20) + SidArray{Count(u32),
// Sids: pointer to a conformant array of pointer-to-RPC_SID}.
SamrCall parse_get_alias_membership_request(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 16;
    call.opnum_name = samr_opnum_name(16);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        (void)c.u32le();  // SidArray.Count
        uint32_t referent = c.u32le();
        if (referent != 0) {
            call.membership_query_sids = read_ndr_sid_pointer_array(c);
        }
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " sids=" + std::to_string(call.membership_query_sids.size());
    return call;
}

// ---------------------------------------------------------------------------------------------
// Response-side parse functions.
// ---------------------------------------------------------------------------------------------

// SamrConnect/2/4 (0/57/62) response -- ServerHandle(20) + ErrorCode(u32), directly from the stub's
// own start; Connect5 (64) is NOT routed here -- see samr.hpp's own OPNUM COVERAGE note (its
// response carries an OutVersion/OutRevisionInfo union ahead of the handle whose own size this file
// does not independently verify, so Connect5's response falls through to structural_only instead).
SamrCall parse_connect_response(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_result_handle = true;
        call.result_handle_hex = to_hex(h, "");
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// SamrOpenDomain/OpenUser/OpenAlias/OpenGroup response -- identical shape: the opened handle(20) +
// ErrorCode(u32).
SamrCall parse_open_response(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_result_handle = true;
        call.result_handle_hex = to_hex(h, "");
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// SamrLookupNamesInDomain (17) response -- RelativeIds:SAMPR_ULONG_ARRAY, Use:SAMPR_ULONG_ARRAY
// (discarded -- SID_NAME_USE per-name is not itself rendered, only whether resolution succeeded),
// ErrorCode(u32). Each of the two top-level struct fields resolves eagerly (see this file's own
// header comment) via dcerpc.hpp's shared read_ndr_count_and_ptr_ulong_array.
SamrCall parse_lookup_names_response(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 17;
    call.opnum_name = samr_opnum_name(17);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.resolved_rids = read_ndr_count_and_ptr_ulong_array(c);
        (void)read_ndr_count_and_ptr_ulong_array(c);  // Use -- SID_NAME_USE per name, not rendered
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response resolved=" + std::to_string(call.resolved_rids.size()) +
                   " status=" + call.status_name;
    return call;
}

// SamrLookupIdsInDomain (18) response -- Names:SAMPR_RETURNED_USTRING_ARRAY{Count,
// Element:pointer-to-array-of-RPC_UNICODE_STRING}, Use:SAMPR_ULONG_ARRAY (discarded, same reasoning
// as LookupNamesInDomain's own Use), ErrorCode(u32).
SamrCall parse_lookup_ids_response(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 18;
    call.opnum_name = samr_opnum_name(18);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        (void)c.u32le();  // Names.Count
        uint32_t referent = c.u32le();
        if (referent != 0) {
            call.resolved_names = read_ndr_unicode_string_array(c);
        }
        (void)read_ndr_count_and_ptr_ulong_array(c);  // Use
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response resolved=" + std::to_string(call.resolved_names.size()) +
                   " status=" + call.status_name;
    return call;
}

// SamrEnumerateUsersInDomain (13) / SamrEnumerateAliasesInDomain (15) response -- identical shape:
// EnumerationContext(u32), Buffer:pointer-to-SAMPR_ENUMERATION_BUFFER{EntriesRead(u32),
// Buffer:pointer-to-array-of-SAMPR_RID_ENUMERATION{RelativeId(u32), Name:RPC_UNICODE_STRING}},
// CountReturned(u32), ErrorCode(u32) -- CountReturned/ErrorCode are top-level fields declared AFTER
// the Buffer pointer, so (per this file's own header comment on eager top-level resolution) they
// are written only once Buffer's own nested content is fully resolved, not immediately after
// Buffer's bare referent -- empirically confirmed during planning by round-tripping hand-built bytes
// with distinct EntriesRead/CountReturned values through impacket's own unmarshaller.
SamrCall parse_enumerate_response(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.enumeration_context = c.u32le();
        call.has_enumeration_context = true;
        uint32_t buffer_referent = c.u32le();
        if (buffer_referent != 0) {
            (void)c.u32le();  // EntriesRead -- CountReturned (below) is authoritative/rendered instead
            uint32_t inner_referent = c.u32le();
            if (inner_referent != 0) {
                uint32_t maximum_count = c.u32le();
                const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
                std::vector<uint32_t> rids;
                std::vector<uint32_t> name_referents;
                for (uint32_t i = 0; i < maximum_count && rids.size() < kMax; ++i) {
                    rids.push_back(c.u32le());
                    (void)c.u16le();  // Name.Length
                    (void)c.u16le();  // Name.MaximumLength
                    name_referents.push_back(c.u32le());
                }
                for (size_t i = 0; i < rids.size(); ++i) {
                    call.enumerated_rids.push_back(rids[i]);
                    call.enumerated_names.push_back(name_referents[i] != 0 ? read_ndr_string(c)
                                                                             : std::string());
                }
            }
        }
        (void)c.u32le();  // CountReturned -- not itself rendered, enumerated_rids.size() is authoritative
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response entries=" + std::to_string(call.enumerated_rids.size()) +
                   " status=" + call.status_name;
    return call;
}

// SamrGetAliasMembership (16) response -- Membership:SAMPR_ULONG_ARRAY, ErrorCode(u32).
SamrCall parse_get_alias_membership_response(uint32_t call_id, ByteSpan stub) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = 16;
    call.opnum_name = samr_opnum_name(16);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.membership_rids = read_ndr_count_and_ptr_ulong_array(c);
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = samr_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response members=" + std::to_string(call.membership_rids.size()) +
                   " status=" + call.status_name;
    return call;
}

SamrCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

SamrCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    SamrCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = samr_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

}  // namespace

bool is_samr_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kSamrInterfaceUuid;
}

std::string samr_opnum_name(uint16_t opnum) {
    const char* name = samr_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

SamrCall try_parse_samr_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 0:
        case 57:
        case 62:
        case 64:
            return parse_connect_request(call_id, opnum, stub);
        case 7:
            return parse_open_domain_request(call_id, stub);
        case 19:
        case 27:
        case 34:
            return parse_open_rid_request(call_id, opnum, stub);
        case 13:
        case 15:
            return parse_enumerate_request(call_id, opnum, stub);
        case 16:
            return parse_get_alias_membership_request(call_id, stub);
        case 17:
            return parse_lookup_names_request(call_id, stub);
        case 18:
            return parse_lookup_ids_request(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

SamrCall try_parse_samr_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 0:
        case 57:
        case 62:
            return parse_connect_response(call_id, opnum, stub);
        case 7:
        case 19:
        case 27:
        case 34:
            return parse_open_response(call_id, opnum, stub);
        case 13:
        case 15:
            return parse_enumerate_response(call_id, opnum, stub);
        case 16:
            return parse_get_alias_membership_response(call_id, stub);
        case 17:
            return parse_lookup_names_response(call_id, stub);
        case 18:
            return parse_lookup_ids_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
