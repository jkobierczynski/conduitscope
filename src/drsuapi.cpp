// SPDX-License-Identifier: Apache-2.0
// drsuapi.cpp - implementation of drsuapi.hpp. See that file's own header comment for the full design
// rationale, the empirically-discovered transport scope caveat, verification methodology, and opnum
// coverage table.
#include "conduitscope/drsuapi.hpp"

#include <cstdio>

#include "conduitscope/dcerpc.hpp"

namespace conduitscope {

namespace {

const char* drsuapi_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 0: return "DRSBind";
        case 1: return "DRSUnbind";
        case 3: return "DRSGetNCChanges";
        case 12: return "DRSCrackNames";
        default: return nullptr;
    }
}

// A small curated Win32-error subset -- DRSBind/DRSUnbind's own ErrorCode is a plain DWORD Win32
// error code (MS-DRSR's own convention for both calls), not an NTSTATUS value, so this mirrors
// srvsvc.hpp's/wkssvc.hpp's own status-table shape (small curated table + "0x%08X" fallback) rather
// than lsarpc.hpp's/samr.hpp's own NTSTATUS-named one.
std::string drsuapi_status_name(uint32_t status) {
    switch (status) {
        case 0: return "ERROR_SUCCESS";
        case 5: return "ERROR_ACCESS_DENIED";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// Skips one DRS_EXTENSIONS blob (MS-DRSR 5.41) reached via the caller's own already-read nonzero
// pointer referent -- empirically confirmed wire shape (impacket's own DRS_EXTENSIONS marshalling,
// hex-dumped during planning, including a deliberately non-4-byte-aligned 3-byte payload to confirm
// the trailing padding below): a hoisted MaximumCount (4 bytes, the conformant cb/rgb structure's
// own array bound -- discarded, since cb itself, read next, is self-describing and authoritative,
// the same "trust the inner count over the hoisted/outer one" posture read_ndr_string's own
// MaxCount/Offset-vs-ActualCount already establishes), then cb(4 bytes), then cb bytes of raw
// capability-flag data (never rendered -- this file has no reason to decode DRS_EXTENSIONS' own
// bitfields, only to skip past the blob to reach whatever field follows it), padded to the next
// 4-byte boundary via dcerpc.hpp's own ndr_align4.
void skip_drs_extensions(Cursor& c) {
    uint32_t referent = c.u32le();
    if (referent == 0) return;
    (void)c.u32le();  // MaximumCount -- see this function's own doc comment
    uint32_t cb = c.u32le();
    c.skip(cb);
    ndr_align4(c);
}

DrsuapiCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = drsuapi_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

DrsuapiCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = drsuapi_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

// DRSBind (0) request -- puuidClientDsa: a [unique] pointer (referent(4), then the 16-byte GUID iff
// nonzero) decoded via dcerpc.hpp's own guid_to_string; pextClient (the DRS_EXTENSIONS capability
// blob) is deliberately not chased at all on the request side -- see drsuapi.hpp's own OPNUM
// COVERAGE note for why the header-only tier draws its line here.
DrsuapiCall parse_bind_request(uint32_t call_id, ByteSpan stub) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = 0;
    call.opnum_name = drsuapi_opnum_name(0);
    call.is_response = false;
    try {
        Cursor c(stub);
        uint32_t referent = c.u32le();
        if (referent != 0) {
            ByteSpan guid = c.bytes(16);
            call.client_dsa_guid = guid_to_string(guid);
            call.has_client_dsa_guid = true;
        }
        // pextClient's own referent follows here on the wire but is deliberately not read -- this
        // function stops decoding once puuidClientDsa is resolved, per this file's own header
        // comment.
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   (call.has_client_dsa_guid ? " client_dsa=" + call.client_dsa_guid : "");
    return call;
}

// DRSBind (0) response -- ppextServer (skipped via skip_drs_extensions above), phDrs (the bound
// context handle, hex, purely informational -- see DrsuapiCall::handle_hex's own doc comment),
// ErrorCode.
DrsuapiCall parse_bind_response(uint32_t call_id, ByteSpan stub) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = 0;
    call.opnum_name = drsuapi_opnum_name(0);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        skip_drs_extensions(c);
        ByteSpan h = c.bytes(20);
        call.handle_hex = to_hex(h, "");
        call.has_handle = true;
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = drsuapi_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// DRSUnbind (1) request -- phDrs, the handle being released. Unlike every other handle this batch
// of interfaces decodes, DRS_HANDLE here is NOT reached via a pointer at all -- it's an [in, out]
// context-handle parameter, marshalled as its own raw 20 bytes directly at the top of the stub (no
// referent to check), confirmed via impacket's own DRSUnbind marshalling during planning.
DrsuapiCall parse_unbind_request(uint32_t call_id, ByteSpan stub) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = 1;
    call.opnum_name = drsuapi_opnum_name(1);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.handle_hex = to_hex(h, "");
        call.has_handle = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name;
    return call;
}

// DRSUnbind (1) response -- phDrs (zeroed on success by MS-DRSR's own convention, but this codebase
// renders whatever bytes are actually on the wire rather than suppressing a field because its
// expected value is "uninteresting" -- the same posture every other handle field here already
// takes), ErrorCode.
DrsuapiCall parse_unbind_response(uint32_t call_id, ByteSpan stub) {
    DrsuapiCall call;
    call.call_id = call_id;
    call.opnum = 1;
    call.opnum_name = drsuapi_opnum_name(1);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.handle_hex = to_hex(h, "");
        call.has_handle = true;
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = drsuapi_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

}  // namespace

bool is_drsuapi_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kDrsuapiInterfaceUuid;
}

std::string drsuapi_opnum_name(uint16_t opnum) {
    const char* name = drsuapi_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

DrsuapiCall try_parse_drsuapi_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 0:
            return parse_bind_request(call_id, stub);
        case 1:
            return parse_unbind_request(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

DrsuapiCall try_parse_drsuapi_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 0:
            return parse_bind_response(call_id, stub);
        case 1:
            return parse_unbind_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
