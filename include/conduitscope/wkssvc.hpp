// SPDX-License-Identifier: Apache-2.0
// wkssvc.hpp - WKSSVC (MS-WKST, Workstation Service Remote Protocol) opnum decoding, carried over
// DCE/RPC (dcerpc.hpp) on the \PIPE\wkssvc named pipe -- srvsvc.hpp's own bundled sibling for this
// batch's phase 2 (see srvsvc.hpp's own header comment for why the two ship together despite having
// no cross-interface note between them, and smb.hpp's own file header comment for the full plan-level
// context). WKSSVC is the interface that answers "what is this machine, and who is logged into it" --
// NetrWkstaGetInfo names the OS build/domain a workstation reports about itself, and NetrWkstaUserEnum
// is the direct wire signature of interactive-logon reconnaissance (`net config workstation` / `net
// sessions`-style tooling enumerating which users are currently logged on a target host), both
// genuinely useful lateral-movement targeting signals and completely routine management traffic.
//
// Split from dcerpc.hpp the exact same way netlogon.hpp/samr.hpp/lsarpc.hpp/srvsvc.hpp are. `smb.cpp`
// calls into this file directly, only for a DCE/RPC message dcerpc.hpp has already parsed on a context
// whose bind negotiated THIS interface's own UUID (`is_wkssvc_interface_uuid`, below) -- see smb.hpp's
// own STATE/CORRELATION section for exactly how that gate is tracked per FileId, via the
// `resolve_dcerpc_bind_bookkeeping` template (dcerpc.hpp) and this file's own `WkssvcPipeState`
// (smb.hpp).
//
// ServerName across nearly every opnum below (LPWKSSVC_IDENTIFY_HANDLE, LPWKSSVC_IMPERSONATE_HANDLE,
// or -- for NetrJoinDomain2/UnjoinDomain2 -- a bare LPWSTR) is, like SRVSVC_HANDLE (see srvsvc.hpp's
// own header comment), NOT a real DCE/RPC context handle -- every one of these three MS-WKST type
// names is defined as a plain [unique] wchar_t*, so this file decodes all of them uniformly with
// dcerpc.hpp's existing read_ndr_unique_string, same as srvsvc.hpp, and never treats it as a
// correlation key.
//
// Every byte-level structure below was verified two ways during planning: against Microsoft's own
// [MS-WKST] Open Specification (opnum numbers/field names, read directly from impacket's own wkst.py),
// and EMPIRICALLY, by installing impacket in the planning sandbox, marshalling real NetrWkstaGetInfo
// and NetrWkstaUserEnum request/response objects, and hex-dumping the actual bytes. That pass
// confirmed WKSTA_INFO_100 (reached via a nested pointer from the WKSTA_INFO union's own arm) follows
// the textbook NDR "nested struct batches its own pointers" shape samr.cpp's own header comment
// already documents (wki100_platform_id/computername-referent/langroup-referent/ver_major/ver_minor
// all written first as this one struct's own fixed part, THEN computername's deferred string data,
// THEN langroup's, in that declared order) -- and that WKSTA_USER_INFO_1_ARRAY follows the exact same
// per-element "batched array" shape SHARE_INFO_1_ARRAY does (srvsvc.hpp's own header comment): every
// element's four pointer referents (username/logon_domain/oth_domains/logon_server) first, for every
// element, THEN every element's own four deferred strings in that same declared order, per element in
// array order.
//
// OPNUM COVERAGE:
//   - Full field decode (request + response): NetrWkstaGetInfo(0), scoped to LEVEL 100 ONLY
//     (wki100_platform_id/computername/langroup/ver_major/ver_minor -- the basic "what is this
//     machine" identity level; every other level -- 101/102/502/1013/1018/1046 -- is reported by its
//     own numeric level only, the same "never guess at an unverified shape" posture srvsvc.hpp already
//     establishes for SHARE_INFO); NetrWkstaUserEnum(2), scoped to LEVEL 1 ONLY (wkui1_username/
//     logon_domain/oth_domains/logon_server -- who is logged on, and from which domain/server, the
//     directly recon-relevant field set; level 0, wkui0_username alone, is reported by level number
//     only rather than duplicating the same decode path for strictly less information).
//   - Header-level decode only, REQUEST SIDE ONLY (ServerName + the enumeration's own Level; see
//     srvsvc.hpp's own OPNUM COVERAGE note for why the response side is deliberately NOT decoded for
//     an enumeration opnum whose own per-level info struct wasn't independently verified -- the same
//     reasoning applies here verbatim): NetrWkstaTransportEnum(5).
//   - Structural-only, opnum named, no field decode, but WITH a curated note firing on every
//     occurrence (not sticky, same posture srvsvc.hpp's own NetrShareAdd/NetrShareDel note
//     establishes): NetrJoinDomain2(22)/NetrUnjoinDomain2(23) -- both carry a
//     PJOINPR_ENCRYPTED_USER_PASSWORD field (an encrypted domain-join credential) this file never
//     attempts to parse, the same "never decode anything credential/secret-shaped" posture samr.hpp's
//     own SamrChangePasswordUser/SamrSetInformationUser opnums already establish -- distinguished from
//     SAMR's own fully silent posture only by the curated note firing here (a domain join/unjoin is a
//     rarer, higher-signal administrative event worth flagging even without decoding its payload, the
//     same reasoning netlogon.hpp's own NetrServerPasswordSet2 note already applies). Any opnum
//     outside this file's own curated table (NetrWkstaSetInfo, the NetrUse* family, NetrWkstaTransport
//     Add, NetrWorkstationStatisticsGet, NetrGetJoinInformation, and more) is reported numerically.
//
// SEALING: identical posture to netlogon.hpp/samr.hpp/lsarpc.hpp/srvsvc.hpp.
//
// DELIBERATELY NOT IMPLEMENTED: srvsvc is this same phase's own separate file; drsuapi remains a
// future phase; WKSTA_INFO levels other than 100, WKSTA_USER_INFO levels other than 1 (see OPNUM
// COVERAGE above); NetrWkstaTransportEnum's own response array; every WKSSVC opnum this file's own
// OPNUM COVERAGE list doesn't name; DCE/RPC PDU fragmentation reassembly; decoding a sealed call's
// stub data; decoding NetrJoinDomain2/UnjoinDomain2's own encrypted password material.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The WKSSVC interface UUID, verified against [MS-WKST] Appendix A's own IDL header and impacket's own
// MSRPC_UUID_WKST constant (both agree) -- version 1.0, the same version every other interface in this
// codebase negotiates (unlike SRVSVC's own version 3.0 -- see srvsvc.hpp's own header comment).
constexpr const char* kWkssvcInterfaceUuid = "6bffd098-a112-3610-9833-46c3f87e345a";

// True iff `abstract_syntax_uuid` names the WKSSVC interface -- see is_samr_interface_uuid's own doc
// comment (samr.hpp) for how smb.cpp calls this.
bool is_wkssvc_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "NetrWkstaGetInfo"), or "opnum N" if it isn't one of the
// values this file's own OPNUM COVERAGE list names.
std::string wkssvc_opnum_name(uint16_t opnum);

// One WKSTA_USER_INFO_1 entry (MS-WKST 2.2.5.10) -- who is logged on, from which domain, plus the
// legacy oth_domains field (other domains this user is also logged into, per MS-WKST -- usually
// empty) and the logon server that authenticated them.
struct WkssvcUserEntry {
    std::string username;
    std::string logon_domain;
    std::string oth_domains;
    std::string logon_server;
};

// One decoded (or, for an opnum outside this file's own curated full-decode set, minimally
// structural) WKSSVC call -- see SamrCall's own doc comment (samr.hpp) for the shared conventions.
struct WkssvcCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    // Present on nearly every request -- see this file's own header comment on why this is never a
    // real context handle, decoded via dcerpc.hpp's read_ndr_unique_string.
    bool has_server_name = false;
    std::string server_name;

    // NetrWkstaGetInfo/NetrWkstaUserEnum/NetrWkstaTransportEnum request Level.
    bool has_level = false;
    uint32_t level = 0;

    // NetrWkstaGetInfo response, level 100 only.
    bool has_wksta_info = false;
    uint32_t platform_id = 0;
    std::string computername;
    std::string langroup;
    uint32_t ver_major = 0;
    uint32_t ver_minor = 0;

    // NetrWkstaUserEnum response, level 1 only.
    std::vector<WkssvcUserEntry> logged_on_users;

    // NetrWkstaUserEnum response.
    bool has_total_entries = false;
    uint32_t total_entries = 0;

    bool has_response_fields = false;
    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;

    std::string summary;
};

// Decodes the request side of one WKSSVC call -- see try_parse_samr_request's own doc comment
// (samr.hpp) for the shared calling convention.
WkssvcCall try_parse_wkssvc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart.
WkssvcCall try_parse_wkssvc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
