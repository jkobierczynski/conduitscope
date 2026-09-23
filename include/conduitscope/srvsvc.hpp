// SPDX-License-Identifier: Apache-2.0
// srvsvc.hpp - SRVSVC (MS-SRVS, Server Service Remote Protocol) opnum decoding, carried over DCE/RPC
// (dcerpc.hpp) on the \PIPE\srvsvc named pipe -- phase 2 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI
// batch, bundled with wkssvc.hpp for scope parity (see smb.hpp's own file header comment for the full
// plan-level context; unlike SAMR+LSARPC, SRVSVC and WKSSVC have no cross-interface curated note --
// they are bundled purely because they land in the same phase, not because one call informs the
// other). SRVSVC is the interface `net view \\host` and every share/session/connection enumeration
// tool actually drives -- NetrShareEnum's own request/response pair is the direct wire-level signature
// of share-discovery recon (the step that finds a writable or interesting share before anything else
// happens), and it is also completely routine, unauthenticated-by-default traffic on most Windows
// networks.
//
// Split from dcerpc.hpp the exact same way netlogon.hpp/samr.hpp/lsarpc.hpp are. `smb.cpp` calls into
// this file directly, only for a DCE/RPC message dcerpc.hpp has already parsed on a context whose bind
// negotiated THIS interface's own UUID (`is_srvsvc_interface_uuid`, below) -- see smb.hpp's own
// STATE/CORRELATION section for exactly how that gate is tracked per FileId, via the
// `resolve_dcerpc_bind_bookkeeping` template (dcerpc.hpp) and this file's own `SrvsvcPipeState`
// (smb.hpp).
//
// A GENUINELY NEW WRINKLE relative to SAMR/LSARPC: SRVSVC_HANDLE (the "ServerName" parameter almost
// every opnum below opens with) is NOT a real DCE/RPC context handle -- MS-SRVS 2.2.2.1 defines it as
// a plain [unique] wchar_t* string (the server's own name, or usually just NULL/empty since the target
// is implicit in the already-established SMB session), the exact same shape netlogon.hpp's own
// ComputerName top-level parameter already uses. So, unlike SAMR/LSARPC (which decode+render a 20-byte
// opaque handle), this file decodes it with dcerpc.hpp's existing read_ndr_unique_string -- no new
// primitive needed, and (correctly) nothing here ever treats it as a correlation key.
//
// Every byte-level structure below was verified two ways during planning: against Microsoft's own
// [MS-SRVS] Open Specification (opnum numbers/field names, read directly from impacket's own srvs.py,
// which mirrors the spec's own IDL), and EMPIRICALLY, by installing impacket in the planning sandbox
// and marshalling real NetrShareEnum/NetrShareGetInfo request/response objects, then hex-dumping the
// actual bytes. That pass confirmed two things prose alone leaves ambiguous: (1) SHARE_ENUM_STRUCT's
// embedded SHARE_ENUM_UNION carries its OWN 4-byte tag/discriminant on the wire, immediately after the
// struct's own Level field -- i.e. the level is redundantly present twice (Level, then the union's own
// tag, both equal) even though a real decoder could infer the tag from Level alone; this file reads
// (and discards) the duplicate rather than assuming it away. (2) SHARE_INFO_1_ARRAY (the per-share
// element array inside a NetrShareEnum response) follows the exact same NDR "batched" array shape
// samr.cpp's own header comment already documents for SAMPR_RID_ENUMERATION: every element's fixed
// part (netname-pointer, type, remark-pointer) first, for every element, THEN every element's deferred
// string data, in element order -- confirmed byte-for-byte against impacket's own marshalled output
// for a synthetic two-share response with deliberately distinct field values.
//
// OPNUM COVERAGE:
//   - Full field decode (request + response): NetrShareEnum(15) (the "net view" enumeration itself --
//     the single highest-value recon call on this interface), NetrShareGetInfo(16). Both are scoped to
//     LEVEL 1 ONLY (shi1_netname/shi1_type/shi1_remark -- netname, share-type flags, and the share's
//     own descriptive remark, exactly what `net view` itself displays); every other level (0/2/501/502/
//     503) is reported by its own numeric level only, never guessed at -- those levels carry
//     permissions/path/password/security-descriptor fields this file's own empirical pass did not
//     independently verify, and several (502/503) can even carry a share's own local filesystem path,
//     which this codebase's own "never decode anything credential/secret-shaped" posture treats with
//     the same caution as a real secret even though a share path isn't literally one.
//   - Header-level decode only, REQUEST SIDE ONLY (ServerName + the enumeration's own Level; the
//     request's own Qualifier/ClientName/UserName/BasePath filter fields are NOT decoded -- this
//     file's own three-tier philosophy draws the header-only line at "confirms an enumeration was
//     attempted and at what level" the same way samr.hpp's own SamrOpenDomain/OpenUser tier draws it
//     at "confirms a target was opened", not at full content): NetrConnectionEnum(8), NetrFileEnum(9),
//     NetrSessionEnum(12). The RESPONSE side for these three is deliberately structural-only instead
//     (opnum name + status, no TotalEntries) -- unlike NetrShareEnum's own SHARE_INFO_1 array, each of
//     these three carries a LEVEL-DEPENDENT info struct (CONNECTION_INFO_0/1, FILE_INFO_2/3,
//     SESSION_INFO_0/1/2/10/502) ahead of TotalEntries in the wire's own top-level field order, and
//     per this file's own empirically-confirmed "top-level fields resolve eagerly" NDR rule, reaching
//     TotalEntries at all means fully walking that array first -- none of those per-level element
//     shapes were independently verified during planning, so rather than guess at how many bytes to
//     skip (risking silent misalignment of every field read afterward, including the response's own
//     ErrorCode), this file stops at the opnum/status level for these three responses. NetrShareEnum's
//     own response avoids this problem entirely by being scoped to exactly one level (see above).
//   - Structural-only, opnum named, no field decode, but WITH a curated note firing on every
//     occurrence (not sticky -- each add/delete is its own meaningful event, the same posture
//     netlogon.hpp's own NetrServerPasswordSet2 note already establishes): NetrShareAdd(14) (a new
//     share created, potentially opening fresh attack surface), NetrShareDel(18) (a share removed).
//     Any opnum outside this file's own curated table (including NetrShareGetInfo's own SetInfo/Del-
//     Sticky siblings, and NetrShareEnumSticky(36) itself -- structurally identical to NetrShareEnum
//     but never independently exercised during planning, so left unguessed) is reported numerically.
//
// SEALING: identical posture to netlogon.hpp/samr.hpp/lsarpc.hpp.
//
// DELIBERATELY NOT IMPLEMENTED: wkssvc is this same phase's own separate file; drsuapi remains a
// future phase; SRVSVC opnum levels other than 1 for NetrShareEnum/NetrShareGetInfo (see OPNUM
// COVERAGE above); every SRVSVC opnum this file's own OPNUM COVERAGE list doesn't name (NetrFileGet-
// Info/Close, NetrSessionDel, NetrShareSetInfo/DelSticky/EnumSticky, the NetrServerX statistics/
// transport family, and more); DCE/RPC PDU fragmentation reassembly; decoding a sealed call's stub
// data.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The SRVSVC interface UUID, verified against [MS-SRVS] Appendix A's own IDL header and impacket's own
// MSRPC_UUID_SRVS constant (both agree). NOTE: SRVSVC's own interface version is 3.0, not the 1.0
// every other interface in this codebase negotiates -- irrelevant to this function (only the UUID
// string is compared, the same posture is_samr_interface_uuid/is_lsarpc_interface_uuid already take;
// a bind's own version mismatch is not independently validated by any interface module here), but
// worth flagging since the fixture-building side (tools/make_sample_pcap.py) must pass it explicitly.
constexpr const char* kSrvsvcInterfaceUuid = "4b324fc8-1670-01d3-1278-5a47bf6ee188";

// True iff `abstract_syntax_uuid` names the SRVSVC interface -- see is_samr_interface_uuid's own doc
// comment (samr.hpp) for how smb.cpp calls this.
bool is_srvsvc_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "NetrShareEnum"), or "opnum N" if it isn't one of the
// values this file's own OPNUM COVERAGE list names.
std::string srvsvc_opnum_name(uint16_t opnum);

// One SHARE_INFO_1 entry (MS-SRVS 2.2.4.23) -- shi1_type rendered both numerically and named (the
// STYPE_* base value 0/1/2/3, plus a trailing " (special)" suffix when the top bit, STYPE_SPECIAL, is
// set -- the flag that marks an administrative/hidden share like C$/ADMIN$/IPC$).
struct SrvsvcShareEntry {
    std::string net_name;
    uint32_t type = 0;
    std::string type_name;  // "disk" / "print_queue" / "device" / "ipc", + " (special)" suffix
    std::string remark;
};

// One decoded (or, for an opnum outside this file's own curated full-decode set, minimally
// structural) SRVSVC call -- see SamrCall's own doc comment (samr.hpp) for the shared conventions.
struct SrvsvcCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    // Present on nearly every request -- SRVSVC_HANDLE/PSRVSVC_HANDLE, NOT a real context handle (see
    // this file's own header comment) -- decoded via dcerpc.hpp's read_ndr_unique_string, empty when
    // the pointer was NULL (indistinguishable from an actually-empty string at this decode depth, the
    // same limit read_ndr_unique_string's own doc comment already states).
    bool has_server_name = false;
    std::string server_name;

    // NetrShareEnum/NetrShareGetInfo request, and the three header-only enumeration opnums' own
    // InfoStruct.Level.
    bool has_level = false;
    uint32_t level = 0;

    // NetrShareGetInfo request -- the specific share being queried.
    std::string net_name;

    // NetrShareEnum/NetrShareGetInfo response -- one entry for GetInfo (level 1 only, per this file's
    // own OPNUM COVERAGE note), zero-or-more for ShareEnum. Empty when the response's own level wasn't
    // 1, or the pointer chain resolved to NULL.
    std::vector<SrvsvcShareEntry> shares;

    // NetrShareEnum/NetrConnectionEnum/NetrFileEnum/NetrSessionEnum response.
    bool has_total_entries = false;
    uint32_t total_entries = 0;

    bool has_response_fields = false;
    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;

    std::string summary;
};

// Decodes the request side of one SRVSVC call -- see try_parse_samr_request's own doc comment
// (samr.hpp) for the shared calling convention.
SrvsvcCall try_parse_srvsvc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart.
SrvsvcCall try_parse_srvsvc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
