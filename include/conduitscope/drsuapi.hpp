// SPDX-License-Identifier: Apache-2.0
// drsuapi.hpp - DRSUAPI (MS-DRSR, "Directory Replication Service (DRS) Remote Protocol") opnum
// decoding, carried over DCE/RPC (dcerpc.hpp) -- phase 3 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI
// batch (see smb.hpp's file header comment for the full plan-level context), and the last of this
// batch's interfaces to land alone rather than bundled: its risk/value shape genuinely differs
// from every interface before it. DRSUAPI is the interface domain controllers use to replicate
// directory data to each other -- and DRSGetNCChanges specifically is the wire-level signature of
// DCSync (Mimikatz's `lsadump::dcsync`, and every tool built on the same technique): pulling
// replicated secret material (password hashes, Kerberos keys) for arbitrary accounts by
// impersonating a domain controller, without ever touching LSASS memory on a real one.
//
// A CRITICAL, EMPIRICALLY-DISCOVERED SCOPE CAVEAT -- read this before trusting this file's
// coverage for DCSync detection: every other interface in this batch (Netlogon, SAMR, LSARPC,
// SRVSVC, WKSSVC) rides a well-known STATIC named pipe over the already-decoded SMB transport
// (smb.cpp's CREATE-response gate), so wiring each into smb.cpp's existing pipe-tracking
// infrastructure was enough to see essentially all of that interface's real-world traffic. DRSUAPI
// is different: [MS-DRSR]'s own "RPC Transport" section states plainly that "this protocol uses
// the following RPC protocol sequence: RPC over TCP... A client SHOULD attempt to connect using
// the RPC-over-TCP protocol sequence" -- no static named pipe is named anywhere in that section.
// Independently confirmed during planning: every real DCSync implementation examined (impacket's
// `secretsdump.py` and `ntlmrelayx`'s `dcsyncclient.py`) resolves DRSUAPI's endpoint via
// `epm.hept_map(..., protocol='ncacn_ip_tcp')` -- the RPC endpoint mapper on TCP/135 -- then binds
// directly over a DYNAMICALLY NEGOTIATED raw TCP port, never touching SMB or a named pipe. This
// codebase has no endpoint-mapper decode and no raw-TCP/dynamic-port DCE/RPC framing (that
// infrastructure, if it's ever built, also serves the still-unbuilt WMI/DCOM decoder, which faces
// the identical "dynamically negotiated data channel" problem -- see smb.hpp's file header
// comment). So: THIS FILE ONLY SEES DRSUAPI TRAFFIC THAT HAPPENS TO ALSO RIDE AN SMB NAMED PIPE
// (MS-DRSR's own "a server MAY listen on additional RPC protocol sequences" allowance) -- a real
// DC's default DCSync-relevant traffic, predominantly RPC-over-TCP, is NOT covered by this
// decoder. Stated plainly, not silently: DCSync detection is this phase's entire purpose, and this
// codebase's coverage claims should be honest about how narrow that coverage actually is.
//
// Split from dcerpc.hpp the same way netlogon.hpp/samr.hpp/lsarpc.hpp/srvsvc.hpp/wkssvc.hpp are.
// `smb.cpp` calls into this file directly, only for a DCE/RPC message dcerpc.hpp has already
// parsed on a context whose bind negotiated THIS interface's UUID (`is_drsuapi_interface_uuid`,
// below) -- see smb.hpp's STATE/CORRELATION section for how that gate is tracked per FileId, via
// the `resolve_dcerpc_bind_bookkeeping` template (dcerpc.hpp) and this file's `DrsuapiPipeState`
// (smb.hpp).
//
// Every byte-level structure below was verified two ways during planning: against Microsoft's
// [MS-DRSR] Open Specification (opnum numbers/field names, cross-checked against impacket's
// `drsuapi.py` numeric `opnum = N` constants, all four agree), and EMPIRICALLY, by installing
// impacket in the planning sandbox and marshalling real DRSBind/DRSBindResponse/DRSUnbind/
// DRSUnbindResponse objects, then hex-dumping the actual bytes -- including a DRS_EXTENSIONS
// payload with deliberately non-4-byte-aligned content, to confirm skip_drs_extensions' padding
// behavior byte-for-byte.
//
// OPNUM COVERAGE -- deliberately the NARROWEST curated table of any interface in this codebase,
// reflecting this file's reduced scope relative to SAMR/LSARPC/SRVSVC/WKSSVC:
//   - Header-level decode only: DRSBind(0) request decodes puuidClientDsa (the calling client's
//     self-identifying GUID, when its [unique] pointer is non-NULL) and stops there -- pextClient
//     (the DRS_EXTENSIONS capability-negotiation blob) is deliberately not chased, the same
//     "decode what's cheap and meaningful, stop before the complex part" line srvsvc.hpp's
//     NetrConnectionEnum/NetrFileEnum/NetrSessionEnum request tier already draws. DRSBind(0)
//     response skips ppextServer (via skip_drs_extensions, below -- capability bitflags are never
//     rendered, only skipped past to reach what follows) and decodes phDrs (the bound context
//     handle, hex, purely informational, never tracked across calls -- the same posture
//     lsarpc.hpp's LsarOpenPolicy/OpenPolicy2 handle decode already establishes) + the return
//     status. DRSUnbind(1) request/response both decode phDrs directly (no pointer indirection --
//     see this file's header comment at parse_unbind_request) + response status.
//   - Structural-only, opnum named, WITH an unconditional curated note on every occurrence (not
//     sticky -- each call is its own meaningful event, the same posture srvsvc.hpp's
//     NetrShareAdd/NetrShareDel notes already establish): DRSGetNCChanges(3), the DCSync call
//     itself. This codebase has no notion anywhere of "is this host a domain controller" (confirmed:
//     asset_inventory.hpp tracks no AD role of any kind), so the note states that honestly rather
//     than inventing a heuristic -- it flags the call, notes it is also routine, high-volume
//     traffic between real domain controllers during ordinary AD replication, and says this
//     decoder cannot independently confirm DC status either way.
//   - Structural-only, opnum named, no note: DRSCrackNames(12) (name-format translation -- also a
//     real recon step, but not the secret-material-carrying call DRSGetNCChanges is, so it doesn't
//     earn the same unconditional-note treatment).
//   - Any opnum outside this file's four-entry table (including DRSReplicaSync/Add/Del/Modify,
//     DRSVerifyNames, DRSGetNT4ChangeLog, DRSDomainControllerInfo, DRSGetMemberships/2,
//     DRSInterDomainMove, DRSAddSidHistory, DRSWriteSPN, DRSRemoveDsServer/Domain, DRSExecuteKCC,
//     DRSGetReplInfo -- MS-DRSR's full opnum set is considerably larger than the four this file
//     names) is reported numerically, never guessed at -- the scope caveat above already concedes
//     this decoder's coverage is narrow, and guessing additional opnum names on top of that would
//     only compound the risk of a wrong claim.
//
// SEALING: identical posture to netlogon.hpp/samr.hpp/lsarpc.hpp/srvsvc.hpp/wkssvc.hpp.
//
// DELIBERATELY NOT IMPLEMENTED: raw-TCP/dynamic-port DCE/RPC framing and the RPC endpoint-mapper
// decode that would be needed to actually follow DRSUAPI's default transport (see the SCOPE CAVEAT
// above -- explicitly deferred, not silently dropped); DRS_EXTENSIONS' capability-flag content
// (skipped, never rendered); every DRSUAPI opnum the OPNUM COVERAGE list above doesn't name;
// DCE/RPC PDU fragmentation reassembly; decoding a sealed call's stub data; DRSUAPI handle-level
// state tracking (same posture every prior interface in this batch already establishes for its
// own handles).
#pragma once

#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The DRSUAPI interface UUID (e3514235-4b06-11d1-ab04-00c04fc2dcd2, version 4.0), verified against
// [MS-DRSR] Appendix A's IDL header and impacket's MSRPC_UUID_DRSUAPI constant (both agree).
// Compared as a plain string against DceRpcContextElement::abstract_syntax_uuid (dcerpc.hpp),
// which is already rendered lowercase.
constexpr const char* kDrsuapiInterfaceUuid = "e3514235-4b06-11d1-ab04-00c04fc2dcd2";

// True iff `abstract_syntax_uuid` names the DRSUAPI interface -- see is_samr_interface_uuid's doc
// comment (samr.hpp) for how smb.cpp calls this.
bool is_drsuapi_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "DRSGetNCChanges"), or "opnum N" if it isn't one of
// the four values the OPNUM COVERAGE list above names.
std::string drsuapi_opnum_name(uint16_t opnum);

// One decoded (or, for an opnum outside this file's curated table, minimally structural) DRSUAPI
// call -- see SamrCall's doc comment (samr.hpp) for the shared conventions (fields not meaningful
// for this call's opnum/direction left at default and never rendered).
struct DrsuapiCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    // DRSBind request only -- the calling client's self-identifying GUID (puuidClientDsa), decoded
    // when its [unique] pointer was non-NULL. Rendered as a standard dashed GUID string via
    // dcerpc.hpp's guid_to_string -- the same wire format an interface UUID uses.
    bool has_client_dsa_guid = false;
    std::string client_dsa_guid;

    // DRSBind response's phDrs (out) / DRSUnbind request's phDrs (in) / DRSUnbind response's phDrs
    // (out, zeroed on success but still rendered as-is) -- one opaque 20-byte DRS_HANDLE, hex,
    // purely informational, never tracked across calls -- see OPNUM COVERAGE above.
    bool has_handle = false;
    std::string handle_hex;

    bool has_response_fields = false;
    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;  // small curated Win32-error subset -- see drsuapi.cpp

    std::string summary;
};

// Decodes the request side of one DRSUAPI call -- see try_parse_samr_request's doc comment
// (samr.hpp) for the shared calling convention.
DrsuapiCall try_parse_drsuapi_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart.
DrsuapiCall try_parse_drsuapi_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
