// SPDX-License-Identifier: Apache-2.0
// lsarpc.hpp - LSARPC (MS-LSAD "Local Security Authority (Domain Policy)" + MS-LSAT "...(Translation
// Methods)", the two specifications that together define one wire interface) opnum decoding, carried
// over DCE/RPC (dcerpc.hpp) on the \PIPE\lsarpc named pipe -- bundled with samr.hpp as this batch's
// own Phase 1 (see smb.hpp's own file header comment for the full plan-level context, and samr.hpp's
// own header comment for why these two ship together: the cross-interface note below is only
// possible because both interfaces' own pipe-state maps live on the same SmbFlowState). LSARPC is the
// interface SID<->name translation and trust-domain/account enumeration ride on -- the direct
// complement to SAMR's own RID<->name resolution, and (together with SAMR) the wire-level signature
// of tools like BloodHound's SharpHound collector, enum4linux, and rpcclient's own lsalookupsids/
// lsalookupnames commands.
//
// Split from dcerpc.hpp the exact same way netlogon.hpp/samr.hpp are. `smb.cpp` calls into this file
// directly, only for a DCE/RPC message dcerpc.hpp has already parsed on a context whose bind
// negotiated THIS interface's own UUID (`is_lsarpc_interface_uuid`, below) -- see smb.hpp's own
// STATE/CORRELATION section for exactly how that gate is tracked per FileId, via the Phase-0-
// generalized `resolve_dcerpc_bind_bookkeeping` template (dcerpc.hpp) and this file's own
// `LsarpcPipeState` (smb.hpp).
//
// Every byte-level structure below was verified two ways during planning: against Microsoft's own
// [MS-LSAD]/[MS-LSAT] Open Specifications (opnum numbers/field names), and EMPIRICALLY -- see
// samr.hpp's own header comment for the methodology and dcerpc.hpp's own header comment for the
// shared array/SID primitives this file reuses directly. One LSARPC-specific wrinkle the empirical
// pass caught: LSAPR_REFERENCED_DOMAIN_LIST (the domain-name+SID list every successful lookup
// response carries) is reached via an extra layer of pointer indirection beyond SAMR's own
// structures -- confirmed by round-tripping a hand-built two-domain response through impacket's own
// unmarshaller with deliberately distinct field values at every position, the only way to pin down
// NDR's own "nested constructed types batch their deferred pointer data; only the outermost
// request/response parameter list resolves pointers eagerly, interleaved with later parameters"
// distinction with real confidence (see samr.cpp's own header comment for the exact rule this
// pinned down).
//
// OPNUM COVERAGE:
//   - Full field decode (request + response): LsarLookupNames(14)/LsarLookupSids(15) (SID<->name
//     translation -- the single highest-value recon call pair on this interface, LSARPC's own
//     direct analog of SAMR's LookupNamesInDomain/LookupIdsInDomain), LsarEnumerateAccounts(11)
//     (every local account SID visible to the caller), LsarEnumerateTrustedDomains(13) (every
//     trusted-domain name+SID pair -- the direct wire signature of trust-relationship enumeration,
//     e.g. mapping an AD forest's trust topology before a cross-domain attack).
//   - Header-level decode only (no ObjectAttributes field decode at all -- see this file's own
//     comment at parse_open_policy_request for why that structure's own pointer-heavy shape was
//     judged not worth the risk/reward here): LsarOpenPolicy(6)/LsarOpenPolicy2(44). Response: the
//     opened policy handle (20 bytes, hex, purely informational, never tracked across calls -- same
//     "no handle-level state" posture samr.hpp already establishes) + status.
//   - Structural-only, opnum named, no field decode: LsarClose(0), LsarQueryInformationPolicy(7)
//     (its own response is a large tagged union this file does not attempt), LsarEnumerate-
//     TrustedDomainsEx(50) (a richer per-entry element shape than LsarEnumerateTrustedDomains' own
//     LSAPR_TRUST_INFORMATION, not independently verified during planning -- flagged rather than
//     guessed at, the same posture this codebase's own "verify, don't recall" bar requires
//     everywhere), and the _2/_3/_4 LookupNames/LookupSids variants (LsarLookupNames2(58)/
//     LsarLookupNames3(68)/LsarLookupNames4(77)/LsarLookupSids2(57)/LsarLookupSids3(76)) -- each
//     adds its own extra trailing request fields and a richer per-entry response element (an added
//     Flags field, or -- LookupNames3/4 specifically -- a full SID in place of a bare RID) that this
//     file's own empirical pass did not independently confirm byte-for-byte, so these opnums are
//     named but not field-decoded rather than risking a silent misdecode on an unverified shape;
//     LookupNames4/LookupSids3 additionally drop the PolicyHandle field entirely (the anonymous/
//     pre-bind pipe variant), a further reason not to share the base opnums' own parse functions.
//     Any opnum outside this file's own curated table is reported numerically.
//
// SEALING: identical posture to netlogon.hpp/samr.hpp.
//
// DELIBERATELY NOT IMPLEMENTED: srvsvc/wkssvc/drsuapi remain future phases; LSARPC handle-level
// state tracking (same posture samr.hpp already establishes for its own handles); every LSARPC
// opnum this file's own OPNUM COVERAGE list doesn't name; DCE/RPC PDU fragmentation reassembly;
// decoding a sealed call's stub data.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The LSARPC interface UUID, verified against [MS-LSAD]/[MS-LSAT] Appendix A's own IDL header and
// impacket's own MSRPC_UUID_LSARPC constant (both agree). Compared as a plain string against
// DceRpcContextElement::abstract_syntax_uuid (dcerpc.hpp), which is already rendered lowercase.
constexpr const char* kLsarpcInterfaceUuid = "12345778-1234-abcd-ef00-0123456789ab";

// True iff `abstract_syntax_uuid` names the LSARPC interface -- see is_samr_interface_uuid's own doc
// comment (samr.hpp) for how smb.cpp calls this.
bool is_lsarpc_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "LsarLookupNames"), or "opnum N" if it isn't one of the
// values this file's own OPNUM COVERAGE list names.
std::string lsarpc_opnum_name(uint16_t opnum);

// One resolved domain (name + SID) from a LSAPR_REFERENCED_DOMAIN_LIST -- every successful
// LsarLookupNames/LsarLookupSids response carries one of these per distinct domain its own
// translated entries reference; LsarEnumerateTrustedDomains reuses the exact same pair shape for its
// own per-trust entries (both wire types are LSAPR_TRUST_INFORMATION -- see lsarpc.cpp).
struct LsarDomainEntry {
    std::string name;
    std::string sid;
};

// One decoded (or, for an opnum outside this file's own curated full-decode set, minimally
// structural) LSARPC call -- see SamrCall's own doc comment (samr.hpp) for the shared conventions
// (fields not meaningful for this call's own opnum/direction left at default and never rendered).
struct LsarCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    // LsarLookupNames/LookupSids/EnumerateAccounts/EnumerateTrustedDomains request -- the policy
    // handle every one of these operates against. Rendered as hex, purely informational (see this
    // file's own header comment on why handles are never tracked across calls).
    bool has_handle = false;
    std::string handle_hex;

    // LsarLookupNames request.
    std::vector<std::string> lookup_names;
    // LsarLookupSids request -- the SIDs being translated.
    std::vector<std::string> lookup_sids;

    // LsarEnumerateAccounts / LsarEnumerateTrustedDomains request.
    bool has_enumeration_context = false;
    uint32_t enumeration_context = 0;

    // Response-side fields.
    bool has_response_fields = false;
    bool has_result_handle = false;  // LsarOpenPolicy/OpenPolicy2 response
    std::string result_handle_hex;

    // LsarLookupNames/LookupSids response -- the domains any translated entry below references
    // (ReferencedDomainList), by index (translated_domain_index[i] indexes into this vector, -1 --
    // MS-LSAD's own convention for "unknown domain" -- when not applicable).
    std::vector<LsarDomainEntry> referenced_domains;
    // LsarLookupNames response -- one entry per input name, in the same order; a name that did not
    // resolve carries relative_id 0 (SidTypeUnknown territory) with an empty/absent name (see below).
    std::vector<uint32_t> translated_rids;
    // LsarLookupSids response -- one entry per input SID, in the same order.
    std::vector<std::string> translated_names;

    // LsarEnumerateAccounts response -- one SID per enumerated account.
    std::vector<std::string> enumerated_sids;
    // LsarEnumerateTrustedDomains response -- one name+SID pair per trusted domain.
    std::vector<LsarDomainEntry> enumerated_trusted_domains;

    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;

    std::string summary;
};

// Decodes the request side of one LSARPC call -- see try_parse_samr_request's own doc comment
// (samr.hpp) for the shared calling convention.
LsarCall try_parse_lsarpc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart.
LsarCall try_parse_lsarpc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
