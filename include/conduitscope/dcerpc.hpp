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
//
// SHARED NDR PRIMITIVES (added when the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI interfaces were built on
// top of Netlogon's own pilot): ndr_align4/read_ndr_string/read_ndr_unique_string below were
// originally netlogon.cpp-local (netlogon.hpp's own header comment still describes the two
// empirically-confirmed wrinkles they depend on -- a top-level wchar_t* defaulting to [ref] even
// under pointer_default(unique), and needing re-alignment after a non-4-byte-aligned scalar field
// like a 16-bit enum). They are pure NDR-wire-format primitives, not Netlogon-specific, so every
// interface built after Netlogon shares these exact copies rather than re-deriving them -- moved
// here for that reason, verified not to change netlogon.cpp's own output at all when the move
// landed (byte-diffed against every existing netlogon_*/smb_* test's own --format json output).
//
// SHARED BIND/BIND_ACK/FAULT BOOKKEEPING: resolve_dcerpc_bind_bookkeeping below factors out the
// mechanical, interface-agnostic half of what smb.cpp's own decode_dcerpc_and_netlogon still does
// inline (kept that way on purpose -- see smb.hpp's own STATE/CORRELATION section) -- tracking
// which context_id a bind negotiated this interface on, confirming it via bind_ack, and clearing
// pending state on fault. Every interface after Netlogon (starting with SAMR/LSARPC) uses this
// instead of re-deriving the same bind/bind_ack/fault logic per file.
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

// Renders a 16-byte NDR-marshalled GUID (Data1 4 bytes LE, Data2 2 bytes LE, Data3 2 bytes LE,
// Data4 8 bytes byte-order-preserved) as the standard dashed lowercase hex string, e.g.
// "12345678-1234-abcd-ef00-01234567cffb" -- the same mixed-endian convention every Microsoft GUID
// on the wire uses. This file's own bind/bind_ack context-element decode uses it internally;
// exposed here (not dcerpc.cpp-local) once drsuapi.cpp needed it too, for DRSBind's own
// puuidClientDsa field -- see this file's own SHARED NDR PRIMITIVES paragraph for the general
// "shared once a second consumer needs it" convention.
std::string guid_to_string(ByteSpan guid);

// ---------------------------------------------------------------------------------------------
// Shared NDR primitives -- see this file's own header comment. Every interface module past
// Netlogon (samr.hpp/lsarpc.hpp/srvsvc.hpp/wkssvc.hpp/drsuapi.hpp) uses these exact copies.
// ---------------------------------------------------------------------------------------------

// NDR aligns every scalar/array to its own natural alignment (1 for a byte array, 2 for a 16-bit
// field, 4 for a 32-bit field or a conformant array's own MaxCount). Re-aligns the cursor to the
// next 4-byte boundary -- a no-op if it's already aligned. Call before reading a conformant
// array's own MaxCount (itself a 4-byte field) whenever a preceding scalar field might have left
// the cursor unaligned (e.g. a 16-bit enum immediately before a string).
void ndr_align4(Cursor& c);

// Reads one NDR conformant-varying string: MaxCount(4)/Offset(4)/ActualCount(4), all u32le, then
// ActualCount*2 bytes of UTF-16LE character data (the wire's own ActualCount includes the
// terminating NUL), then pads to the next 4-byte boundary. MaxCount/Offset are structurally
// required to be present but are never meaningful for this codebase's own read-only decode (every
// string any interface module here ever sees is a single, unfragmented conformant array), so
// neither is validated against ActualCount -- a malformed relationship still yields whatever
// ActualCount itself says, and any resulting truncation is caught by the caller's own try/catch.
std::string read_ndr_string(Cursor& c);

// Reads one NDR [unique] string pointer: a 4-byte referent ID, then (only if nonzero) the same
// conformant-varying string read_ndr_string reads for a [ref] pointer. Returns an empty string for
// a NULL pointer (referent ID == 0) -- indistinguishable, at this decode depth, from an empty
// string that was actually sent.
std::string read_ndr_unique_string(Cursor& c);

// ---------------------------------------------------------------------------------------------
// Additional shared NDR primitives, added for SAMR/LSARPC (both interfaces' own wire structures
// lean heavily on RPC_SID and conformant arrays of RPC_UNICODE_STRING/ULONG/SID-pointer -- these
// are pure NDR-wire-format shapes, not SAMR/LSARPC-specific, so future interfaces reuse them too).
// Every shape below was verified empirically during planning, the same way ndr_align4's own two
// wrinkles were: by installing impacket in the planning sandbox, calling its real NDR marshalling
// code (and, for a few cases, its unmarshalling code against hand-built bytes) to nail down field
// order and the exact "deferred pointer data" placement NDR's own rules leave otherwise ambiguous
// on paper -- not recalled from training. See samr.cpp's/lsarpc.cpp's own file header comments for
// which specific opnums exercise each of these.
// ---------------------------------------------------------------------------------------------

// Reads one RPC_SID (MS-DTYP 2.4.2.2) from `c`, which must already be positioned at its own
// deferred data (i.e. the caller has already confirmed a nonzero pointer referent elsewhere) --
// NEVER at a bare embedded [ref] SID, since every SID this codebase's own SAMR/LSARPC opnums ever
// see arrives behind a pointer (PRPC_SID). Wire shape, empirically confirmed: a hoisted
// MaximumCount (4 bytes, NDR's own conformant-structure convention for a struct whose last member
// is itself a conformant array -- SubAuthority below) that is consumed but not itself validated
// against the SubAuthorityCount that follows; then Revision(1)/SubAuthorityCount(1)/
// IdentifierAuthority(6, big-endian 48-bit value)/SubAuthority(SubAuthorityCount x 4-byte
// little-endian). Renders as the standard "S-<rev>-<authority>-<sub>-<sub>-..." string form.
// Capped at resource_limits().max_decoded_objects sub-authorities, the same DoS-guard idiom
// dcerpc.cpp's own bind_contexts/bind_ack_results loops already use.
std::string read_ndr_sid(Cursor& c);

// Reads the BODY of one NDR conformant array of pointer-to-RPC_SID (e.g. SAMR's
// SAMPR_PSID_ARRAY.Sids, LSARPC's LSAPR_SID_ENUM_BUFFER.SidInfo / LSAPR_ACCOUNT_ENUM_BUFFER.
// Information) -- the cursor must already be positioned at the array's own conformant header
// (i.e. the caller has already read this array's own Count and pointer-referent fields, found the
// referent nonzero, and is now at the pointed-to array itself). Wire shape, empirically confirmed:
// a hoisted MaximumCount (4 bytes), then MaximumCount x one 4-byte pointer-referent per element,
// then -- for every element whose own referent was nonzero, in element order -- that element's
// deferred RPC_SID data (read_ndr_sid above). An element whose referent was 0 (a NULL SID pointer,
// never observed in practice but structurally legal) yields an empty string at that position, so
// the returned vector's own size always equals MaximumCount even when some entries are empty.
std::vector<std::string> read_ndr_sid_pointer_array(Cursor& c);

// Reads the BODY of one NDR conformant-varying array of RPC_UNICODE_STRING, EMBEDDED DIRECTLY as a
// struct/parameter field (not behind an extra pointer) -- e.g. SAMR's SamrLookupNamesInDomain.Names,
// LSARPC's LsarLookupNames.Names. The cursor must already be positioned at the array's own
// conformant-varying header. Wire shape, empirically confirmed: MaxCount(4)/Offset(4)/
// ActualCount(4), then ActualCount x this codebase's own RPC_UNICODE_STRING fixed part (Length(2)/
// MaximumLength(2)/referent(4), 8 bytes/entry), then -- for every entry whose own referent was
// nonzero, in entry order -- that entry's deferred string data (read_ndr_string's own exact shape,
// reused directly since it is byte-identical). An entry whose referent was 0 yields an empty
// string at that position (same convention as read_ndr_sid_pointer_array above).
std::vector<std::string> read_ndr_unicode_string_array(Cursor& c);

// Reads the BODY of one NDR conformant-varying array of plain ULONG, embedded directly as a
// struct/parameter field (e.g. SAMR's SamrLookupIdsInDomain.RelativeIds request field) -- the
// cursor must already be positioned at the array's own conformant-varying header. Wire shape:
// MaxCount(4)/Offset(4)/ActualCount(4), then ActualCount x 4-byte little-endian ULONG, no deferred
// data (ULONG is never a pointer).
std::vector<uint32_t> read_ndr_ulong_conformant_varying_array(Cursor& c);

// Reads one full "Count + pointer-to-conformant-array-of-ULONG" field pair, e.g. SAMR's
// SAMPR_ULONG_ARRAY (RelativeIds/Use/Membership response fields across several opnums) -- Count
// (4 bytes, read and discarded; the deferred array's own MaximumCount is trusted instead, the same
// "self-describing data over an external count" convention read_ndr_string already applies to
// ActualCount vs MaxCount/Offset), then a 4-byte pointer referent, then -- only if nonzero --
// deferred: a hoisted MaximumCount(4) followed by MaximumCount x 4-byte little-endian ULONG.
// Returns an empty vector for a NULL pointer.
std::vector<uint32_t> read_ndr_count_and_ptr_ulong_array(Cursor& c);

// One outstanding DCE/RPC bind or request PDU on a tracked pipe, keyed by call_id -- DCE/RPC's own
// wire-mandated correlation field (DceRpcMessage::call_id above), the same "genuine correlation
// field, not a heuristic" bar SMB2's own MessageId and LDAP's own messageID already met. Does
// double duty for the two kinds of pending pairing one pipe conversation needs: context_id is
// meaningful for a bind PDU awaiting its own bind_ack (the candidate interface context_id offered,
// not yet confirmed accepted); opnum is meaningful for a request PDU awaiting its own
// response/fault (so the response side, which carries no opnum of its own, can still be decoded
// with the right one). Moved here from smb.hpp once more than one interface needed it.
struct PendingDceRpcCall {
    uint16_t opnum = 0;
    uint16_t context_id = 0;
};

// Resolves the mechanical, interface-agnostic half of one DceRpcMessage against `pipe_state`:
// bind (stash a pending bind keyed by call_id, for whichever context element's abstract syntax
// `is_interface_uuid` recognizes), bind_ack (confirm the interface's own context_id once its
// pending bind is accepted), and fault (clear the pending call). Returns true iff `dm` was one of
// these three PTYPEs (fully handled here); false means the caller must still handle
// has_request/has_response itself -- this function deliberately does NOT touch those, since
// request/response decoding is each interface's own opnum-specific semantics (see this file's own
// header comment). `PipeState` must expose `pending_calls` (unordered_map<uint32_t,
// PendingDceRpcCall>), `bound_context_is_interface` (bool), and `interface_context_id` (uint16_t)
// -- see e.g. SamrPipeState/LsarpcPipeState (smb.hpp) for the exact shape every interface's own
// per-FileId state struct follows.
template <typename PipeState>
bool resolve_dcerpc_bind_bookkeeping(const DceRpcMessage& dm, PipeState& pipe_state,
                                      bool (*is_interface_uuid)(const std::string&)) {
    if (dm.has_bind) {
        for (const DceRpcContextElement& ctx_elem : dm.bind_contexts) {
            if (is_interface_uuid(ctx_elem.abstract_syntax_uuid)) {
                pipe_state.pending_calls[dm.call_id] = PendingDceRpcCall{0, ctx_elem.context_id};
                break;
            }
        }
        return true;
    }
    if (dm.has_bind_ack) {
        auto it = pipe_state.pending_calls.find(dm.call_id);
        if (it != pipe_state.pending_calls.end()) {
            uint16_t candidate_context_id = it->second.context_id;
            for (const DceRpcContextResult& result : dm.bind_ack_results) {
                if (result.result_name == "acceptance") {
                    pipe_state.bound_context_is_interface = true;
                    pipe_state.interface_context_id = candidate_context_id;
                    break;
                }
            }
            pipe_state.pending_calls.erase(it);
        }
        return true;
    }
    if (dm.has_fault) {
        pipe_state.pending_calls.erase(dm.call_id);
        return true;
    }
    return false;
}

}  // namespace conduitscope
