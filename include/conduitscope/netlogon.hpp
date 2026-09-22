// SPDX-License-Identifier: Apache-2.0
// netlogon.hpp - Netlogon (MS-NRPC) opnum decoding, carried over DCE/RPC (dcerpc.hpp) on the
// \PIPE\netlogon named pipe -- the fourth and final piece of the planned Windows AD suite (Kerberos,
// LDAP, SMB/NTLM, and this file). See smb.hpp's own file header comment for the full plan-level
// context: Netlogon is the protocol a domain-joined machine (or an attacker impersonating one)
// establishes a "Netlogon Secure Channel" with a domain controller through, and is where CVE-2020-1472
// ("Zerologon") lives -- this file's own curated note 2 detects that vulnerability's exact wire
// pattern.
//
// Split from dcerpc.hpp the same way ntlm.hpp is split from smb.hpp: dcerpc.hpp decodes the envelope
// every RPC interface shares; this file owns everything specific to the Netlogon interface itself
// (its UUID, its opnum table, its own structures) -- see dcerpc.hpp's own file header comment for why
// that split matters (a future lsarpc/samr/srvsvc pass, explicitly not this one, could reuse dcerpc.hpp
// without touching this file). `smb.cpp` calls into this file directly, only for a DCE/RPC message
// dcerpc.hpp has already parsed on a context whose bind negotiated THIS interface's own UUID
// (`is_netlogon_interface_uuid`, below) -- see smb.hpp's own STATE/CORRELATION section for exactly how
// that gate is tracked per FileId.
//
// Every byte-level structure below was verified two ways during planning, not recalled from training:
// against Microsoft's own [MS-NRPC] Open Specification (including its own Appendix A Full IDL), and
// EMPIRICALLY, by installing `impacket` in the planning sandbox and calling its real NDR marshalling
// code to produce actual PDU bytes for known field values, then hand-verifying every byte offset
// against the spec-derived expectation -- see smb.hpp's own plan-provenance note for the two things
// this caught that prose alone would not have (ref-vs-unique top-level pointer marshalling, and
// SecureChannelType's 16-bit wire width). Every opnum below was cross-checked a third way: it matches
// impacket's own `nrpc.py` numeric `opnum = N` constants.
//
// OPNUM COVERAGE:
//   - Full field decode (request + response), the calls with the highest curated-note value:
//     NetrServerReqChallenge (4), NetrServerAuthenticate/2/3 (5/15/26 -- decoded uniformly, since 15
//     and 26 only add trailing fields onto 5's shape). See NetlogonCall below for exactly which
//     fields.
//   - Header-level decode only, credential material never rendered (mirrors ntlm.hpp's own
//     LmChallengeResponse/NtChallengeResponse posture): NetrServerPasswordSet2 (30) -- PrimaryName/
//     AccountName/SecureChannelType/ComputerName decoded when unsealed; the Authenticator and the
//     encrypted new-password blob (NL_TRUST_PASSWORD) are presence/length only, NEVER their bytes --
//     this is the literal password material, the whole point of this call, and rendering it would
//     make this decoder a credential-harvesting tool. (NL_TRUST_PASSWORD's own exact trailing byte
//     offset was not independently empirically cross-checked the way ReqChallenge/Authenticate3 were
//     -- see netlogon.cpp's own comment at that one call site; a misread there fails closed, via the
//     same try/catch every other field-level decode in this file already uses, rather than
//     misreporting anything.)
//   - Structural-only, opnum named from a verified curated table, nothing else decoded: NetrLogonUas-
//     Logon(0), NetrLogonUasLogoff(1), NetrLogonSamLogon(2), NetrLogonGetCapabilities(21), NetrLogon-
//     GetDomainInfo(29), NetrServerPasswordSet(6, the legacy pre-Set2 variant), NetrServerPasswordGet
//     (31), NetrServerTrustPasswordsGet(42), NetrLogonSamLogonEx(39), NetrLogonSamLogonWithFlags(45),
//     NetrServerAuthenticateKerberos(59). Any opnum outside this table is reported numerically, never
//     guessed at.
//
// SEALING: Windows enforces "Full Secure Channel" for Netlogon -- NetrServerReqChallenge/
// NetrServerAuthenticate* run over an unauthenticated bind (nothing to seal with yet, since they
// ESTABLISH the session key), while later calls on the same pipe (NetrServerPasswordSet2 chief among
// what this file decodes) are normally sent RPC-layer-sealed (auth_level == RPC_C_AUTHN_LEVEL_PKT_
// PRIVACY, dcerpc.hpp's own DceRpcMessage::sealed) once that key exists -- meaning their stub data is
// ciphertext this codebase has no key for. `try_parse_netlogon_request`/`_response` take `sealed`
// directly from the caller (smb.cpp, reading it off the DceRpcMessage dcerpc.hpp already parsed) and,
// when true, skip field decode entirely rather than trying to parse ciphertext as plaintext NDR --
// the same "never decrypt a cipher this codebase doesn't hold the key for" limit applied everywhere
// else here.
//
// DELIBERATELY NOT IMPLEMENTED: lsarpc, samr, srvsvc, wkssvc, or any RPC interface other than
// Netlogon, even over the same IPC$ share (explicitly deferred -- see smb.hpp's own DELIBERATELY NOT
// IMPLEMENTED list); actual Netlogon Secure Channel cryptographic verification (session-key
// derivation, the AES-CFB8 credential-chain computation) -- only the WIRE PATTERN (an all-zero
// ClientChallenge/ClientCredential) is recognized, never verified as a successful forgery; decoding a
// sealed call's stub data (see above); DCE/RPC PDU fragmentation reassembly across multiple WRITE/READ
// pairs (dcerpc.hpp's own scope limit, inherited here).
#pragma once

#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The Netlogon interface UUID (12345678-1234-abcd-ef00-01234567cffb, version 1.0) -- verified against
// [MS-NRPC] Appendix A's own IDL header, impacket's own MSRPC_UUID_NRPC constant, and the actual bytes
// impacket's own bind-PDU marshalling produced during planning (all three agree). Compared as a plain
// string against DceRpcContextElement::abstract_syntax_uuid (dcerpc.hpp), which is already rendered
// lowercase -- see is_netlogon_interface_uuid below.
constexpr const char* kNetlogonInterfaceUuid = "12345678-1234-abcd-ef00-01234567cffb";

// True iff `abstract_syntax_uuid` (as rendered by dcerpc.cpp's own guid_to_string, always lowercase)
// names the Netlogon interface. smb.cpp calls this once per bind context element to decide which
// context_id (if any) on a tracked FileId is trusted for the opnum decode below -- see smb.hpp's own
// STATE/CORRELATION section.
bool is_netlogon_interface_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated name for `opnum` (e.g. "NetrServerAuthenticate3"), or "opnum N" if it isn't one
// of the values this file's own OPNUM COVERAGE list names -- exposed so output.cpp's own --stats
// opnum-count block (the netlogon-side analog of smb.hpp's own status-count block) can use the same
// names try_parse_netlogon_request/_response already render.
std::string netlogon_opnum_name(uint16_t opnum);

// One decoded (or, for an opnum outside this file's own curated full-decode set, minimally
// structural) Netlogon call -- either the request or the response side of one DCE/RPC request/
// response pair (dcerpc.hpp's own DceRpcMessage::call_id ties the two together, see NetlogonCall::
// call_id below). Fields not meaningful for this call's own opnum/direction are left at their default
// and never rendered -- the same convention SmbMessage/NtlmMessage/DceRpcMessage already establish.
struct NetlogonCall {
    uint32_t call_id = 0;
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;  // true iff this side arrived RPC-layer-sealed -- see this file's own
                            // SEALING paragraph; every field below is left unset when true

    // Request-side fields (NetrServerReqChallenge / NetrServerAuthenticate family /
    // NetrServerPasswordSet2's own header -- see this file's own OPNUM COVERAGE list).
    bool has_request_fields = false;
    std::string primary_name;
    std::string account_name;     // NetrServerAuthenticate*/NetrServerPasswordSet2 only
    std::string computer_name;
    bool has_secure_channel_type = false;
    uint16_t secure_channel_type_value = 0;
    std::string secure_channel_type_name;  // named 8-value NETLOGON_SECURE_CHANNEL_TYPE table
    bool has_client_credential = false;    // ClientChallenge (ReqChallenge) or ClientCredential
                                             // (Authenticate family) -- same 8-byte NETLOGON_CREDENTIAL
                                             // shape either way, one field for both
    std::string client_credential_hex;
    bool client_credential_is_all_zero = false;  // the direct Zerologon-pattern (curated note 2) input
    bool has_negotiate_flags = false;
    uint32_t negotiate_flags = 0;  // NetrServerAuthenticate2/3 request only (opnum 5 has none)

    // NetrServerPasswordSet2 request only -- presence/length ONLY, see this file's own header comment
    // and OPNUM COVERAGE note.
    bool has_authenticator = false;
    bool has_clear_new_password = false;
    size_t clear_new_password_length = 0;

    // Response-side fields.
    bool has_response_fields = false;
    bool has_server_credential = false;  // ServerChallenge (ReqChallenge resp) or ServerCredential
                                           // (Authenticate resp) -- same shape, same field
    std::string server_credential_hex;
    bool has_account_rid = false;  // NetrServerAuthenticate3 response only
    uint32_t account_rid = 0;
    bool has_status = false;
    uint32_t status = 0;
    std::string status_name;  // small curated NTSTATUS subset, own table -- see netlogon.cpp

    std::string summary;
};

// Decodes the request side of one Netlogon call. `call_id` is dcerpc.hpp's own DceRpcMessage::call_id
// (copied in verbatim, not re-derived); `opnum` and `sealed` likewise come straight from the
// DceRpcMessage the caller already has. `stub` is the request PDU's own stub bytes (dcerpc.hpp's own
// stub_offset/stub_length, re-sliced by the caller -- see dcerpc.hpp's own STUB DATA paragraph for why
// this file never receives a DceRpcMessage directly). Never throws; a malformed/truncated stub yields
// whatever fields were decoded before the truncation was hit, the same per-field leniency
// parse_one_smb2_message's own command bodies already use.
NetlogonCall try_parse_netlogon_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

// The response-side counterpart -- see try_parse_netlogon_request's own doc comment.
NetlogonCall try_parse_netlogon_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub);

}  // namespace conduitscope
