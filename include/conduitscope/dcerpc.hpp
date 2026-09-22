// SPDX-License-Identifier: Apache-2.0
// dcerpc.hpp - generic DCE/RPC (MS-RPCE) connection-oriented PDU envelope decoding, shared by
// netlogon.hpp's own opnum-level Netlogon decode (the only interface this codebase decodes past the
// envelope today -- see netlogon.hpp's own file header comment) and, structurally, by any other RPC
// interface a DCE/RPC bind might negotiate on a tracked named pipe.
//
// PART OF THE NETLOGON/DCE-RPC DECODER (AD suite, phase 4 of 4, the final piece) -- see smb.hpp's own
// file header comment for the full plan-level context. This file exists separately from netlogon.hpp/
// netlogon.cpp, the same way ntlm.hpp is split from smb.hpp: the PDU envelope this file decodes
// (rpc_vers/PTYPE/pfc_flags/frag_length/call_id, bind/bind_ack context negotiation, request/response/
// fault headers, the sec_trailer) is IDENTICAL regardless of which interface (Netlogon, lsarpc, samr,
// srvsvc, ...) is riding inside it -- only Netlogon is decoded past this envelope in this pass (see
// netlogon.hpp's own DELIBERATELY NOT IMPLEMENTED list), but keeping the envelope itself
// interface-agnostic here is what would let a future pass reuse it rather than re-deriving it.
// `smb.cpp` calls into this file directly, the same way it calls into ntlm.hpp today; this file has no
// `ProtocolDecoder`, gate, or port of its own -- DCE/RPC-over-named-pipe traffic only exists as bytes
// inside an already-classified SMB2 WRITE/IOCTL/READ body (see smb.hpp's own STATE/CORRELATION section
// for exactly which FileIds this is ever invoked for).
//
// WIRE FORMAT: every connection-oriented DCE/RPC PDU begins with a 16-byte common header --
// rpc_vers(1)/rpc_vers_minor(1)/PTYPE(1)/pfc_flags(1)/packed_drep(4)/frag_length(2)/auth_length(2)/
// call_id(4) -- verified against the Open Group's own DCE 1.1 RPC specification (chapter 12, "RPC PDU
// Encodings"), the primary, vendor-neutral source [MS-RPCE] itself is built on, and cross-checked a
// second way during planning: every PTYPE/context-result/auth-level numeric constant below was
// independently confirmed against `impacket`'s own `rpcrt.py` constants (see smb.hpp's own
// plan-provenance note for why this phase adds a real-implementation cross-check on top of the written
// -source cross-checking every prior phase already did). `call_id` is the wire-mandated correlation
// key between a request/bind and its response/bind_ack -- reused here, not reinvented, the same
// "genuine correlation field, not a heuristic" bar SMB2's own MessageId and LDAP's own messageID
// already met.
//
// MESSAGE COVERAGE:
//   - Common header: full decode, every PTYPE named (all 20 values 0-19, e.g. request/response/bind/
//     bind_ack/bind_nak/fault/alter_context/alter_context_resp/auth3/shutdown/co_cancel/orphaned; the
//     five connectionless-only codes this codebase never sees over a named pipe -- ping/working/nocall
//     /reject/ack/cl_cancel/fack/cancel_ack -- are still named for completeness), pfc_flags (named:
//     PFC_FIRST_FRAG/PFC_LAST_FRAG/PFC_PENDING_CANCEL/PFC_CONC_MPX/PFC_DID_NOT_EXECUTE/PFC_MAYBE/
//     PFC_OBJECT_UUID; the one reserved bit is not named).
//   - bind/alter_context: max_xmit_frag/max_recv_frag, the context-element list (context_id,
//     n_transfer_syn, abstract syntax UUID+version -- rendered as a standard dashed GUID string, see
//     dcerpc.cpp's own guid_to_string -- and, for the single transfer syntax this codebase ever
//     expects, whether it is the well-known NDR transfer syntax UUID `8a885d04-1ceb-11c9-9fe8-
//     08002b104860` v2.0). Recognizing WHICH interface a context's abstract syntax names (e.g.
//     Netlogon) is deliberately NOT this file's job -- see netlogon.hpp's own is_netlogon_interface_
//     uuid, called by smb.cpp after this file hands back the raw UUID string, keeping this envelope
//     module interface-agnostic.
//   - bind_ack/alter_context_resp: max_xmit_frag/max_recv_frag, the per-context result list (Result
//     named: acceptance/user_rejection/provider_rejection/negotiate_ack, [MS-RPCE] 2.2.1.4 cross-
//     checked against impacket's own MSRPC_CONT_RESULT_* constants during planning -- the gate for
//     whether a subsequent request/response pair on that context_id is trusted as the interface its
//     own bind claimed at all).
//   - request: alloc_hint, context_id (p_cont_id), opnum. Object UUID (present only when
//     PFC_OBJECT_UUID is set) is recognized (via the flag) but not itself decoded -- no interface this
//     codebase decodes uses it.
//   - response: alloc_hint, context_id, cancel_count.
//   - fault: alloc_hint, context_id, cancel_count, the fault status (reported numerically -- RPC fault
//     codes are a distinct numbering space from Windows NTSTATUS, and this codebase's "flag rather
//     than guess" bar applies here too).
//   - sec_trailer (present whenever auth_length > 0, MS-RPCE 2.2.2.11): auth_type (reported
//     numerically -- see smb.hpp's own plan-provenance note on why RPC_C_AUTHN_NETLOGON's numeric
//     value is deliberately NOT asserted here), auth_level (named via the 6-value RPC_C_AUTHN_LEVEL_*
//     table -- this is the one field this decoder actually branches on: `sealed` is true exactly when
//     auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY (6), meaning the stub data that follows is ciphertext
//     this codebase has no key for -- see netlogon.hpp's own header comment for how a sealed call is
//     handled). auth_pad_length/auth_context_id/auth_value itself are recognized (their presence and
//     the trailer's own boundary are what let stub_length be computed correctly) but never rendered --
//     auth_value is either a signature or the key material behind one.
//
// STUB DATA: `stub_offset`/`stub_length` locate the PDU's own payload (whatever comes after the fixed
// request/response/fault header, up to the sec_trailer boundary if one is present) as a pair of plain
// offsets into the SAME ByteSpan passed to try_parse_dcerpc/parse_dcerpc_chain -- deliberately NOT a
// ByteSpan member of DceRpcMessage itself, since every result struct in this codebase (SmbMessage,
// NtlmMessage, ...) is fully owned data with no borrowed spans that could outlive the packet buffer
// they were read from; the caller re-slices the still-in-scope original span immediately, the same
// bounded()-style re-slice smb.cpp already does for its own offset/length fields.
//
// DELIBERATELY NOT IMPLEMENTED: PDU fragmentation reassembly across multiple WRITE/READ pairs (a
// fragmented call -- PFC_FIRST_FRAG set without PFC_LAST_FRAG, or vice versa -- is named via the flags
// but its stub is left exactly as this one fragment's own bytes, never reassembled across separate
// SMB2 WRITE/READ calls; see netlogon.hpp's own header comment for scope); decrypting/verifying a
// sealed PDU's stub data or its sec_trailer's auth_value (no key material is ever available to this
// codebase, the same limit applied to every other signed/encrypted protocol here); any RPC interface's
// OWN opnum semantics (that is netlogon.hpp's job, or a future interface-specific module's).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// One p_cont_elem_t from a bind/alter_context's own context list (MS-RPCE 2.2.1.1).
struct DceRpcContextElement {
    uint16_t context_id = 0;
    std::string abstract_syntax_uuid;          // dashed GUID string, e.g. "12345678-1234-abcd-..."
    uint16_t abstract_syntax_version_major = 0;
    uint16_t abstract_syntax_version_minor = 0;
    std::string transfer_syntax_uuid;           // only the first offered transfer syntax is decoded --
                                                  // every real-world bind this codebase has verified
                                                  // offers exactly one
    uint32_t transfer_syntax_version = 0;
    bool is_ndr32_transfer_syntax = false;       // true iff transfer_syntax_uuid is the well-known NDR
                                                  // constant 8a885d04-1ceb-11c9-9fe8-08002b104860 v2.0
};

// One p_result_t from a bind_ack/alter_context_resp's own result list (MS-RPCE 2.2.1.4).
struct DceRpcContextResult {
    uint16_t result_value = 0;
    std::string result_name;  // "acceptance" / "user_rejection" / "provider_rejection" /
                                // "negotiate_ack", or "result N" if some other value
    std::string transfer_syntax_uuid;
    uint32_t transfer_syntax_version = 0;
};

// One connection-oriented DCE/RPC PDU. Fields not meaningful for this PDU's own PTYPE are left at
// their default and never rendered -- the same convention SmbMessage/NtlmMessage already establish.
struct DceRpcMessage {
    uint8_t rpc_vers = 0;
    uint8_t rpc_vers_minor = 0;
    uint8_t ptype_value = 0;
    std::string ptype_name;
    std::vector<std::string> pfc_flags;
    bool is_first_frag = false;
    bool is_last_frag = false;
    uint16_t frag_length = 0;
    uint16_t auth_length = 0;
    uint32_t call_id = 0;

    // bind / alter_context.
    bool has_bind = false;
    uint16_t bind_max_xmit_frag = 0;
    uint16_t bind_max_recv_frag = 0;
    std::vector<DceRpcContextElement> bind_contexts;

    // bind_ack / alter_context_resp.
    bool has_bind_ack = false;
    uint16_t bind_ack_max_xmit_frag = 0;
    uint16_t bind_ack_max_recv_frag = 0;
    std::vector<DceRpcContextResult> bind_ack_results;

    // request.
    bool has_request = false;
    uint16_t request_context_id = 0;
    uint16_t opnum = 0;

    // response.
    bool has_response = false;
    uint16_t response_context_id = 0;

    // fault.
    bool has_fault = false;
    uint32_t fault_status = 0;

    // sec_trailer -- see this file's header comment for why auth_type is never named and auth_value
    // is never rendered.
    bool has_sec_trailer = false;
    uint8_t auth_type = 0;
    uint8_t auth_level = 0;
    std::string auth_level_name;  // named 1-6 RPC_C_AUTHN_LEVEL_* table, or "" if out of range
    bool sealed = false;          // auth_level == RPC_C_AUTHN_LEVEL_PKT_PRIVACY (6)

    // Stub data location -- see this file's own STUB DATA paragraph. Both 0 (with stub_length == 0)
    // when this PTYPE carries no stub of its own (bind/bind_ack/... ).
    size_t stub_offset = 0;
    size_t stub_length = 0;

    std::string summary;
};

// Attempts to interpret `pdu` -- which must start at byte 0 of one DCE/RPC PDU's own 16-byte common
// header -- as one DceRpcMessage. All offsets in the returned message (stub_offset above) are relative
// to `pdu` itself. Returns std::nullopt (never throws) if the common header doesn't fit, rpc_vers
// isn't 5, or frag_length doesn't fit inside `pdu`.
std::optional<DceRpcMessage> try_parse_dcerpc(ByteSpan pdu);

// Walks zero or more PDUs packed back-to-back in one buffer (a single SMB2 WRITE/IOCTL request or
// READ/IOCTL response can carry more than one DCE/RPC PDU this way -- e.g. a bind immediately followed
// by a request), via each PDU's own frag_length, the same "self-describing length, not the buffer
// running out" chain-walk smb.cpp's own parse_smb2_chain already uses for SMB2 compounding. Every
// returned message's stub_offset/stub_length are ABSOLUTE offsets into `payload` (not relative to that
// individual PDU), so the caller can re-slice `payload` directly regardless of which PDU in the chain a
// given message came from. Capped by resource_limits().max_decoded_objects, the same guard
// parse_smb2_chain's own kMaxCompounded uses.
std::vector<DceRpcMessage> parse_dcerpc_chain(ByteSpan payload);

}  // namespace conduitscope
