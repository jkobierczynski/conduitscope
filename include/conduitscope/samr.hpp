// SPDX-License-Identifier: Apache-2.0
// samr.hpp - SAMR (MS-SAMR, Security Account Manager Remote Protocol) opnum decoding, carried over
// DCE/RPC (dcerpc.hpp) on the \PIPE\samr named pipe -- the first of the four remaining DCE/RPC
// interfaces Jurgen asked for on top of the Netlogon/DCE-RPC pilot (see smb.hpp's own file header
// comment for the full plan-level context: this is phase 1 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI
// batch, bundled with lsarpc.hpp for the cross-interface note the two together enable). SAMR is the
// interface every account/group/domain enumeration tool (net.exe, PowerView, BloodHound's own
// SharpHound collector, enum4linux, rpcclient) actually drives -- RID<->name resolution and user/
// alias/group enumeration are the direct wire-level signature of AD reconnaissance.
//
// Split from dcerpc.hpp the exact same way netlogon.hpp is: dcerpc.hpp decodes the envelope every RPC
// interface shares; this file owns everything specific to the SAMR interface itself (its UUID, its
// opnum table, its own structures). `smb.cpp` calls into this file directly, only for a DCE/RPC
// message dcerpc.hpp has already parsed on a context whose bind negotiated THIS interface's own UUID
// (`is_samr_interface_uuid`, below) -- see smb.hpp's own STATE/CORRELATION section for exactly how
// that gate is tracked per FileId, via the Phase-0-generalized `resolve_dcerpc_bind_bookkeeping`
// template (dcerpc.hpp) and this file's own `SamrPipeState` (smb.hpp).
//
// Every byte-level structure below was verified two ways during planning: against Microsoft's own
// [MS-SAMR] Open Specification (opnum numbers/field names), and EMPIRICALLY, by installing impacket
// in the planning sandbox and calling its real NDR marshalling AND unmarshalling code against
// hand-built bytes -- see dcerpc.hpp's own header comment for why this phase's shared array/SID
// primitives (read_ndr_sid, read_ndr_sid_pointer_array, read_ndr_unicode_string_array,
// read_ndr_ulong_conformant_varying_array, read_ndr_count_and_ptr_ulong_array) needed that empirical
// pass: NDR's own "deferred pointer data" placement rule is genuinely ambiguous from prose alone once
// more than one pointer is in play (e.g. a struct with two independent pointer-typed sibling fields
// defers each one immediately after that field's own fixed part, NOT batched at the end the way an
// ARRAY of pointer-containing elements defers all of them together after the whole array's fixed
// part) -- both shapes are exercised by this file's own full-decode opnums below, and both were
// confirmed by round-tripping hand-built bytes through impacket's own unmarshaller, not just reading
// its marshaller's output.
//
// OPNUM COVERAGE:
//   - Full field decode (request + response): SamrLookupNamesInDomain(17)/SamrLookupIdsInDomain(18)
//     (RID<->name resolution -- the single highest-value recon call pair on this interface),
//     SamrEnumerateUsersInDomain(13), SamrEnumerateAliasesInDomain(15), SamrGetAliasMembership(16),
//     and the SamrConnect family (0/2=57/4=62/5=64, decoded uniformly -- see SamrCall's own doc
//     comment for exactly which fields, since the four variants' own trailing request fields differ
//     and only ServerName's own leading position is common to all four).
//   - Header-level decode only (the target being opened, not a tracked handle<->name table -- this
//     codebase does not track SAMR handles across calls, the same "no handle-level state" posture
//     Netlogon itself never needed a handle for at all): SamrOpenDomain(7) decodes the target
//     DomainId SID; SamrOpenUser(34)/SamrOpenAlias(27)/SamrOpenGroup(19) decode the target RID.
//     Every one of these four also decodes DesiredAccess. Response: the opened handle (20 bytes,
//     rendered as hex, purely informational -- not correlated against later calls) + status.
//   - Structural-only, opnum named, NO field decode at all -- these three opnums are where SAMR's own
//     password-material calls live (SamrSetInformationUser can carry a plaintext or NT-hashed new
//     password in one of its many INFORMATION_CLASS variants; SamrChangePasswordUser/
//     SamrOemChangePasswordUser2 exist for no other reason than to change a password), so this file
//     never even attempts to parse their stub -- not presence/length-only the way Netlogon's own
//     NL_TRUST_PASSWORD gets, but zero decode whatsoever, the most conservative posture in this
//     codebase for anything credential-shaped: SamrChangePasswordUser(38),
//     SamrOemChangePasswordUser2(54), SamrSetInformationUser(37). Any opnum outside this file's own
//     curated table (including SamrClose(1), never itself carrying anything worth decoding) is
//     reported numerically via the same "opnum N" fallback netlogon.hpp already established.
//
// SEALING: identical posture to netlogon.hpp -- `try_parse_samr_request`/`_response` take `sealed`
// directly from the caller and skip field decode entirely when true, the same "never decrypt a
// cipher this codebase doesn't hold the key for" limit applied everywhere else here. Unlike Netlogon
// (which only seals AFTER its own session-key-establishing calls), a SAMR bind is commonly sealed
// from its very first request if the underlying SMB session itself negotiated signing/sealing at a
// lower layer -- this file makes no assumption either way, purely reading DceRpcMessage::sealed.
//
// DELIBERATELY NOT IMPLEMENTED: any RPC interface other than SAMR/Netlogon (lsarpc is this same
// phase's own separate file; srvsvc/wkssvc/drsuapi remain future phases); SAMR handle-level state
// tracking (opening a domain/user/alias/group handle is decoded per-call, but this file never
// remembers "handle X refers to user RID 1105" for a later call that reuses it -- the same posture
// this codebase already accepts for every other handle-correlated protocol it doesn't fully model);
// every SAMR opnum this file's own OPNUM COVERAGE list doesn't name (dozens exist -- e.g. group
// membership management, alias membership management, domain policy queries/sets -- reported
// numerically, never guessed at); DCE/RPC PDU fragmentation reassembly (dcerpc.hpp's own scope limit,
// inherited here); decoding a sealed call's stub data.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The SAMR interface UUID, verified against [MS-SAMR] Appendix A's own IDL header and impacket's own
// MSRPC_UUID_SAMR constant (both agree). Compared as a plain string against
// DceRpcContextElement::abstract_syntax_uuid (dcerpc.hpp), which is already rendered lowercase.
constexpr const char* kSamrInterfaceUuid = "12345778-1234-abcd-ef00-0123456789ac";

// True iff `abstract_syntax_uuid` names the SAMR interface -- smb.cpp calls this once per bind
// context element the same way it calls is_netlogon_interface_uuid, via
// resolve_dcerpc_bind_bookkeeping (dcerpc.hpp).
bool is_samr_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "SamrLookupNamesInDomain"), or "opnum N" if it isn't
// one of the values this file's own OPNUM COVERAGE list names.
std::string samr_opnum_name(uint16_t opnum);

// One decoded (or, for an opnum outside this file's own curated full-decode set, minimally
// structural) SAMR call -- either the request or the response side of one DCE/RPC request/response
// pair. Fields not meaningful for this call's own opnum/direction are left at their default and
// never rendered -- the same convention NetlogonCall already establishes.
struct SamrCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    // SamrConnect/2/4/5 request -- only ServerName is decoded (see this file's own OPNUM COVERAGE
    // note on why the trailing fields, which differ across the four variants, are not).
    bool has_server_name = false;
    std::string server_name;

    // SamrOpenDomain/OpenUser/OpenAlias/OpenGroup request.
    bool has_open_target = false;
    uint32_t desired_access = 0;
    std::string open_domain_sid;   // SamrOpenDomain only
    bool has_open_rid = false;     // SamrOpenUser/OpenAlias/OpenGroup only
    uint32_t open_rid = 0;

    // SamrLookupNamesInDomain / SamrEnumerateUsersInDomain / SamrEnumerateAliasesInDomain /
    // SamrGetAliasMembership request -- the handle every one of these opens against. Rendered as
    // hex, purely informational (see this file's own header comment on why handles are never
    // tracked across calls).
    bool has_handle = false;
    std::string handle_hex;

    // SamrLookupNamesInDomain request.
    std::vector<std::string> lookup_names;
    // SamrLookupIdsInDomain request.
    std::vector<uint32_t> lookup_rids;

    // SamrEnumerateUsersInDomain / SamrEnumerateAliasesInDomain request.
    bool has_enumeration_context = false;
    uint32_t enumeration_context = 0;

    // SamrGetAliasMembership request -- the SIDs whose alias membership is being queried.
    std::vector<std::string> membership_query_sids;

    // Response-side fields.
    bool has_response_fields = false;
    bool has_result_handle = false;  // SamrConnect family / SamrOpenDomain / OpenUser / OpenAlias /
                                       // OpenGroup response
    std::string result_handle_hex;
    // SamrLookupNamesInDomain response: RID resolved per input name, "0 (not found)" left as 0 when
    // Use == 0 (SidTypeUnknown, the not-found signal MS-SAMR itself defines).
    std::vector<uint32_t> resolved_rids;
    // SamrLookupIdsInDomain response: name resolved per input RID, empty when not found.
    std::vector<std::string> resolved_names;
    // SamrEnumerateUsersInDomain / SamrEnumerateAliasesInDomain response -- RID+name pairs, in
    // lockstep two vectors rather than a nested struct (matches this codebase's own flat-field
    // convention elsewhere in ProtocolDecoder result types).
    std::vector<uint32_t> enumerated_rids;
    std::vector<std::string> enumerated_names;
    // SamrGetAliasMembership response -- the alias RIDs the queried SIDs are members of.
    std::vector<uint32_t> membership_rids;

    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;

    std::string summary;
};

// Decodes the request side of one SAMR call. `call_id`/`opnum`/`sealed` come straight from the
// DceRpcMessage the caller already has (dcerpc.hpp's own DceRpcMessage::call_id/opnum/sealed). `stub`
// is the request PDU's own stub bytes, re-sliced by the caller. Never throws; a malformed/truncated
// stub yields whatever fields were decoded before the truncation was hit, the same per-field leniency
// netlogon.cpp's own parse functions already establish.
SamrCall try_parse_samr_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart -- see try_parse_samr_request's own doc comment.
SamrCall try_parse_samr_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
