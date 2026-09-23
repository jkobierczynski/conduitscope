// SPDX-License-Identifier: Apache-2.0
// smb.hpp - SMB2/SMB3 (MS-SMB2) decoding, over TCP/445 (direct hosting) and TCP/139 (NetBIOS
// Session Service), with embedded NTLM (MS-NLMP, see ntlm.hpp) authentication decoding.
//
// THIRD OF THE PLANNED FOUR-PROTOCOL WINDOWS AD SUITE (Kerberos, then LDAP, then SMB/NTLM -- this
// file -- then Netlogon/DCE-RPC, each delivered separately). SMB is where the credentials Kerberos's
// and LDAP's own curated notes already flag get USED: a cracked Kerberoasted/AS-REP-Roasted ticket,
// or a set of credentials harvested via LDAP recon, is most often put to work over SMB via NTLM
// relay or pass-the-hash against the ADMIN$/C$/IPC$ administrative shares for lateral movement --
// this phase completes that story the same way item 23's own text framed LDAP as completing item
// 22's. Netlogon/DCE-RPC remains phase 4, deliberately out of scope here even though it rides inside
// SMB (see DELIBERATELY NOT IMPLEMENTED below).
//
// SMB already had SHALLOW, name-only recognition in this codebase before this file existed (Tier 2's
// "lateral-movement" family, it_protocols.hpp/.cpp): `match_smb_magic()` checks the 4-byte
// 0xFF/0xFE/0xFD + "SMB" magic and names which SMB generation/framing it is, nothing more. That
// recognition is now REMOVED from Tier 2 (see it_protocols.hpp's own file header comment) in favor
// of this full decoder -- the same "pull one protocol out of a shared tier into its own dedicated
// decoder" move this codebase already made for EAPOL and, most recently, LDAP. `match_smb_magic()`
// itself is kept and reused as-is by this file's own structural gate, exactly as LDAP's plan reused
// `match_ldap_ber()`.
//
// NTLM itself has zero recognition anywhere in this codebase before this file. It appears embedded
// inside SMB2's own SESSION_SETUP request/response Buffer fields, wrapped in a SPNEGO/GSS-API
// security blob per MS-SPNG -- this file locates it with a plain "NTLMSSP\0" signature scan of that
// Buffer (a deliberate substitute for fully implementing SPNEGO/GSS-API's own ASN.1 grammar just to
// unwrap one layer, the same "structural signature, not full grammar" bar WireGuard's exact-length
// match and the VMware magic-number check already earn elsewhere in this codebase), then calls
// ntlm.hpp's shared parser -- see that file's own header comment for why NTLM gets one shared parser
// rather than being duplicated per-embedding.
//
// FRAMING: every SMB message, on either port, is preceded by a 4-byte header -- one Zero byte (MUST
// be 0x00) + a 3-byte big-endian StreamProtocolLength (the byte count of the following message only,
// not including these 4 bytes). [MS-SMB2] section 2.1 documents this as the Direct TCP transport
// packet header for port 445; it is structurally identical to RFC 1002 section 4.3.1's NetBIOS
// Session Service SESSION MESSAGE packet header with TYPE fixed at 0x00 and the 17th (high-order)
// length bit never set in practice -- so smb_tcp_declared_length() reads the same 4 bytes on both
// ports and returns 4 + StreamProtocolLength; SmbTcpDecoder::decode does the same before dispatching
// on the magic byte that follows. Port 139's own NBSS session-establishment handshake (SESSION
// REQUEST/POSITIVE RESPONSE/NEGATIVE RESPONSE, RFC 1002 4.3.2-4.3.4) is deliberately out of scope --
// see DELIBERATELY NOT IMPLEMENTED; those 1-2 packets simply don't match this decoder's own magic
// byte, the same "let the gate fail naturally" posture used everywhere else in this codebase.
//
// COMPOUNDING: MS-SMB2's own mechanism for concatenating several SMB2 messages inside one 4-byte-
// prefixed unit, chained via each header's own NextCommand field (the offset, from THAT message's
// own start, of the next one) -- a genuinely new wrinkle neither Kerberos nor LDAP had at the wire-
// format level. try_parse_smb2_chain (smb.cpp) walks this chain structurally so a compounded unit is
// never misparsed as one message plus trailing garbage; every sub-message's header is read and its
// command named, with the same "full decode for auth/recon commands, structural-only for file-I/O
// commands" depth rule (below) applied per sub-message.
//
// MESSAGE COVERAGE (every byte-level structure below was verified against Microsoft's own
// [MS-SMB2]/[MS-NLMP] Open Specifications, cross-checked against independent open-source
// implementations, during this decoder's planning -- not recalled from training, the same "verify,
// don't just recall" bar item 23's own StartTLS-OID and AD-bitwise-match-OID call-outs held
// themselves to):
//   - SMB2 Packet Header (every message, SYNC and ASYNC forms): full decode -- see SmbMessage below.
//   - NEGOTIATE Request/Response: Dialects[] (named, including the pre-SMB2 multi-protocol-negotiate
//     wildcard 0x02FF, confirmed against [MS-SMB2] during planning) and SecurityMode (Request);
//     negotiated DialectRevision, SecurityMode (named SIGNING_ENABLED/SIGNING_REQUIRED -- the direct
//     input to curated note 2), Capabilities (named, all 7 SMB2_GLOBAL_CAP_* flags), ServerGuid
//     (Response). The SMB 3.1.1 NegotiateContextList is structural-only (not field-decoded).
//   - SESSION_SETUP Request/Response: Request's SecurityMode, Capabilities, PreviousSessionId, and
//     its Buffer (NTLM-signature-scanned, see above); Response's SessionFlags (named IS_GUEST/
//     IS_NULL/ENCRYPT_DATA -- the direct input to curated note 4) and its own Buffer, same scan.
//   - TREE_CONNECT Request/Response: Request's share path (UTF-16LE, decoded via byteio.hpp's
//     utf16le_to_utf8) -- the direct input to curated note 5; Response's ShareType (named disk/pipe/
//     print) and ShareFlags/Capabilities (named).
//   - LOGOFF, TREE_DISCONNECT: header-only.
//
// STRUCTURAL-ONLY: CREATE, CLOSE, FLUSH, READ, WRITE, LOCK, IOCTL, CANCEL, ECHO, QUERY_DIRECTORY,
// CHANGE_NOTIFY, QUERY_INFO, SET_INFO, OPLOCK_BREAK -- command named, not field-decoded. IOCTL in
// particular: DCE/RPC-over-named-pipe traffic (Netlogon chief among it) rides inside CREATE+WRITE+
// READ/IOCTL against an IPC$-hosted named pipe -- decoding that payload is squarely phase 4's job.
//
// DELIBERATELY NOT IMPLEMENTED: SMB1/CIFS's own full command set (SMB1 traffic is RECOGNIZED -- see
// curated note 1 -- but not decoded past its own magic byte); NBSS session-establishment; SMB 3.x
// message signing verification and encryption (0xFD-prefixed TRANSFORM_HEADER messages are
// recognized and named, never decrypted -- the same limit this codebase already applies to every
// encrypted protocol it meets); the SMB 3.1.1 NegotiateContextList; full SPNEGO/GSS-API ASN.1
// decode (the NTLMSSP\0 signature scan is the deliberate substitute); DCE/RPC-over-named-pipe
// payloads (explicitly phase 4); every file-I/O command's own field-level content.
//
// STRUCTURAL DETECTION GATE: reuses it_protocols.hpp's existing match_smb_magic() as-is, applied to
// the 4 bytes immediately following the 4-byte Zero+StreamProtocolLength prefix (offset 4) -- the
// same magic already proven collision-free in tcp_port_independent_registry() today; this file only
// changes what happens after the gate fires.
//
// CURATED ATTACK/MONITORING NOTES (see smb.cpp for the exact heuristics; every one is framed as
// surfacing a wire-level mechanism, never as an assertion of detected intent -- legitimate admin
// tooling uses ADMIN$/IPC$ and NTLM fallback routinely):
//   1. SMB1 traffic present -- standing, unconditional, fires once per session (a sticky flag).
//   2. SMB signing not required -- NEGOTIATE Response SecurityMode: SIGNING_ENABLED set,
//      SIGNING_REQUIRED not set. The precondition every NTLM-relay tool checks for.
//   3. NTLM negotiated for this session -- a SESSION_SETUP request or response Buffer containing the
//      NTLMSSP\0 signature. A downgrade/relay-friendly signal, the SMB-side complement of the
//      Kerberos and LDAP decoders' own notes.
//   4. Anonymous or guest session established -- SESSION_SETUP Response SessionFlags IS_GUEST or
//      IS_NULL.
//   5. Administrative/hidden share access -- a TREE_CONNECT request path ending in "$", correlated
//      against the response's own ShareType == pipe to confirm IPC$ specifically.
//   6. Repeated STATUS_LOGON_FAILURE across a capture -- named Status values from SESSION_SETUP
//      responses aggregated in --stats (see output.cpp).
//
// STATE/CORRELATION: SmbFlowState (below), keyed by FlowStateKeying::Session (tcp_session_key).
// Two pieces of state: a simple MessageId-keyed 1:1 pending-request map (NEGOTIATE/TREE_CONNECT/
// LOGOFF/TREE_DISCONNECT), and a genuinely new SessionId-keyed PendingNtlmHandshake map, because
// NTLM's own negotiate/challenge/authenticate exchange spans TWO separate SESSION_SETUP
// request/response pairs (each its own MessageId) tied together only by the SessionId the server
// assigns in the first response (STATUS_MORE_PROCESSING_REQUIRED) -- opened there, closed with one
// coherent correlation note on the terminal SESSION_SETUP response for that SessionId.
#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dcerpc.hpp"
#include "conduitscope/it_protocols.hpp"  // SMB_PORT_445/SMB_NETBIOS_SESSION_PORT_139, match_smb_magic
#include "conduitscope/lsarpc.hpp"
#include "conduitscope/netlogon.hpp"
#include "conduitscope/ntlm.hpp"
#include "conduitscope/protocol_decoder.hpp"
#include "conduitscope/samr.hpp"

namespace conduitscope {

// One SMB2 FileId (MS-SMB2 2.2.14.1: Persistent + Volatile, 8 bytes each) -- the handle-scoped
// correlation key WRITE/READ/IOCTL/CLOSE all reference back to the CREATE that opened it. A
// plain, fully-owned, hashable value type (not a ByteSpan) so it can key SmbFlowState's own
// netlogon_pipes map below -- the same "no borrowed spans in a long-lived structure" rule
// dcerpc.hpp's own stub_offset/stub_length design already follows.
struct SmbFileId {
    uint64_t persistent = 0;
    uint64_t volatile_id = 0;
    bool operator==(const SmbFileId& other) const {
        return persistent == other.persistent && volatile_id == other.volatile_id;
    }
};
struct SmbFileIdHash {
    size_t operator()(const SmbFileId& id) const {
        return std::hash<uint64_t>()(id.persistent) ^
               (std::hash<uint64_t>()(id.volatile_id) * 0x9E3779B97F4A7C15ULL);
    }
};

// One SMB2 sub-message (almost always the only one -- see this file's own COMPOUNDING paragraph for
// when there is more than one). Fields not meaningful for a given command are left at their default
// (empty/false/0) and never rendered -- the same convention KerberosMessage/LdapMessage/TwinCatFrame
// already establish.
struct SmbMessage {
    // Header -- always set.
    uint16_t structure_size = 0;
    uint16_t credit_charge = 0;
    uint32_t status = 0;
    std::string status_name;  // named (curated NT_STATUS subset), only meaningful/rendered for a
                                // response -- see smb.cpp's status_name()
    uint16_t command_value = 0;
    std::string command_name;
    bool is_response = false;
    bool is_async = false;
    std::vector<std::string> header_flags;  // named: SERVER_TO_REDIR/ASYNC_COMMAND/
                                              // RELATED_OPERATIONS/SIGNED/PRIORITY_MASK/
                                              // DFS_OPERATIONS/REPLAY_OPERATION
    uint32_t next_command = 0;
    uint64_t message_id = 0;
    uint32_t tree_id = 0;    // SYNC only
    uint64_t async_id = 0;   // ASYNC only
    uint64_t session_id = 0;

    // NEGOTIATE Request.
    std::vector<std::string> negotiate_dialects;       // e.g. "0x0311 (SMB 3.1.1)"
    std::vector<std::string> negotiate_request_security_mode;

    // NEGOTIATE Response.
    bool has_negotiate_response = false;
    std::string negotiated_dialect;  // named, e.g. "SMB 3.1.1"
    std::vector<std::string> negotiate_response_security_mode;  // SIGNING_ENABLED/SIGNING_REQUIRED
    std::vector<std::string> negotiate_capabilities;             // named SMB2_GLOBAL_CAP_* flags
    std::string server_guid_hex;

    // SESSION_SETUP Request.
    bool has_session_setup_request = false;
    std::vector<std::string> session_setup_security_mode;
    std::vector<std::string> session_setup_capabilities;
    uint64_t previous_session_id = 0;

    // SESSION_SETUP Response.
    bool has_session_setup_response = false;
    std::vector<std::string> session_flags;  // named IS_GUEST/IS_NULL/ENCRYPT_DATA

    bool has_ntlm = false;
    NtlmMessage ntlm;

    // TREE_CONNECT Request.
    bool has_tree_connect_request = false;
    std::string tree_connect_path;

    // TREE_CONNECT Response.
    bool has_tree_connect_response = false;
    std::string share_type;  // "disk" / "pipe" / "print", or "type N"
    std::vector<std::string> share_flags;
    std::vector<std::string> share_capabilities;

    // CREATE Request -- the Name field, prefix-stripped of a leading "\"/"PIPE\"/"\PIPE\"
    // (case-insensitively) and lowercased -- see smb.cpp's own strip_pipe_prefix_lower. Empty
    // when Name was absent/empty or this codebase simply didn't need to look at it further (only
    // a "netlogon"-named pipe is ever tracked past this point -- see this file's own
    // STATE/CORRELATION section).
    bool has_create_request = false;
    std::string create_name;

    // CREATE Response.
    bool has_create_response = false;

    // FileId -- carried by CREATE's own Response and by every WRITE/READ/IOCTL/CLOSE request
    // that references an already-open handle (READ's own RESPONSE carries no FileId of its own,
    // per MS-SMB2 -- see smb.cpp's own READ handling for how that response is still correlated
    // back to its FileId). has_file_id is set whenever any of those decoded one.
    bool has_file_id = false;
    SmbFileId file_id;

    // DCE/RPC-over-named-pipe raw payload bytes -- INTERNAL ONLY, never rendered to JSON/text
    // output (see output.cpp). Populated by parse_one_smb2_message (smb.cpp) for a WRITE
    // request, READ response, or IOCTL(FSCTL_PIPE_TRANSCEIVE) request/response, then consumed
    // and cleared by decode_with_correlation (smb.cpp) once it has resolved which FileId (and
    // therefore which, if any, tracked NetlogonPipeState) this message belongs to -- the
    // stateless parse layer owns the bytes, the stateful correlation layer decides what they
    // mean, the same split this file's other correlation-derived fields already follow.
    std::vector<uint8_t> dcerpc_raw_payload;

    // DCE/RPC PDUs found in dcerpc_raw_payload (populated by decode_with_correlation) -- empty
    // unless this message targeted a FileId tracked as the "netlogon" named pipe.
    std::vector<DceRpcMessage> dcerpc_messages;
    // Netlogon-level decode of dcerpc_messages, ONLY for a PDU whose own context was confirmed
    // bound to the Netlogon interface (see this file's own STATE/CORRELATION section) -- a
    // bind/bind_ack/fault PDU, or a request/response on a non-Netlogon context, has no
    // corresponding entry here; correlate by NetlogonCall::call_id, not by index.
    std::vector<NetlogonCall> netlogon_calls;
    // SAMR-level / LSARPC-level decode of dcerpc_messages, same convention as netlogon_calls above
    // (only for a PDU whose own context was confirmed bound to that interface -- see this file's own
    // STATE/CORRELATION section). A given SmbMessage populates at most one of netlogon_calls/
    // samr_calls/lsarpc_calls, since one FileId is tracked in at most one per-interface pipe-state
    // map by construction (see dispatch_dcerpc_payload, smb.cpp).
    std::vector<SamrCall> samr_calls;
    std::vector<LsarCall> lsarpc_calls;

    // Correlation-derived -- filled by SmbTcpDecoder::decode, not try_parse_smb2_chain.
    bool correlated_request_seen = false;
    size_t correlated_request_index = 0;
    // Set on the terminal SESSION_SETUP response of a multi-leg NTLM handshake -- see this file's
    // header comment's STATE/CORRELATION section.
    bool ntlm_handshake_closed = false;
    std::string ntlm_handshake_summary;  // "NTLM handshake for DOMAIN\\user, succeeded/failed"

    std::string summary;
    std::vector<std::string> notes;
};

// One TCP payload's worth of decoded SMB traffic. For SMB2 (the normal case), `messages` holds one
// entry per sub-message in a possibly-compounded chain (see COMPOUNDING above) -- almost always
// exactly one. For SMB1 or the SMB2 TRANSFORM (encrypted) header, `messages` is empty -- see this
// file's own DELIBERATELY NOT IMPLEMENTED list; only `envelope_kind`/`summary`/`notes` are set.
struct SmbFrame {
    std::string envelope_kind;  // "SMB2" / "SMB1" / "SMB2_TRANSFORM"
    std::vector<SmbMessage> messages;
    std::string summary;              // combined, top-level (e.g. lists every compounded command)
    std::vector<std::string> notes;   // combined from every sub-message plus any frame-level note
                                        // (e.g. curated note 1, SMB1 traffic present)
};

// PendingDceRpcCall (one outstanding DCE/RPC bind or request PDU on a tracked pipe, keyed by
// call_id) now lives in dcerpc.hpp alongside resolve_dcerpc_bind_bookkeeping -- it was always
// interface-agnostic wire-format bookkeeping, not netlogon-specific. See that struct's own doc
// comment there for the full rationale (short version: context_id is meaningful for a bind PDU
// awaiting its own bind_ack; opnum is meaningful for a request PDU awaiting its own
// response/fault, so the response side, which carries no opnum of its own, can still be decoded
// with the right one).

// Per-FileId state for a tracked "netlogon" named pipe -- see this file's own STATE/CORRELATION
// section for why this is a genuinely new, two-layer correlation shape (SMB2 handle -> DCE/RPC
// bind -> DCE/RPC call) relative to every prior phase's own state. Created at CREATE response
// only when the request's own TreeId was already confirmed a pipe share AND the CREATE request's
// own Name (prefix-stripped) equals "netlogon"; erased on the matching CLOSE request.
struct NetlogonPipeState {
    // Short-lived: immediate bind<->bind_ack and request<->response/fault PDU pairing on this
    // pipe's own DCE/RPC calls, keyed by call_id -- see PendingDceRpcCall's own doc comment.
    std::unordered_map<uint32_t, PendingDceRpcCall> pending_calls;

    // Longer-lived, sticky for this pipe conversation's own lifetime.
    bool bound_context_is_netlogon = false;  // true once a bind_ack accepted a context whose own
                                                // bind negotiated the Netlogon interface UUID
    uint16_t netlogon_context_id = 0;          // that context's own context_id, once known
    std::string last_primary_name;
    std::string last_account_name;
    std::string last_computer_name;
    bool zero_challenge_seen = false;          // curated note 2's own sticky flag (ReqChallenge)
    bool zero_credential_seen = false;         // curated note 2's own sticky flag (Authenticate*)
    bool legacy_authenticate_seen = false;     // curated note 3's own sticky flag
    bool account_name_mismatch_seen = false;   // curated note 4's own sticky flag
    // Curated note 5 (NetrServerPasswordSet2 observed) is deliberately NOT sticky -- each
    // occurrence is its own meaningful event, see smb.cpp's own decode_dcerpc_and_netlogon.
};

// Per-FileId state for a tracked "samr" named pipe -- see NetlogonPipeState's own doc comment for
// the general shape (created at CREATE response, erased at CLOSE). `pending_calls`/
// `bound_context_is_interface`/`interface_context_id` follow the exact field-naming contract
// dcerpc.hpp's own resolve_dcerpc_bind_bookkeeping template requires (see that template's own doc
// comment) -- unlike NetlogonPipeState (written before that template existed, so it still spells
// these out as netlogon_context_id/bound_context_is_netlogon), every interface after Netlogon uses
// this shared template instead of re-deriving the same bind/bind_ack/fault logic per file.
struct SamrPipeState {
    std::unordered_map<uint32_t, PendingDceRpcCall> pending_calls;
    bool bound_context_is_interface = false;
    uint16_t interface_context_id = 0;
    // Curated note (SAMR account/group enumeration observed) -- sticky per pipe conversation, the
    // same "fires once, not once per call" posture NetlogonPipeState's own notes already establish.
    bool enumeration_note_seen = false;
};

// Per-FileId state for a tracked "lsarpc" named pipe -- see SamrPipeState's own doc comment; the
// same shape, same field-naming contract, same sticky-note posture.
struct LsarpcPipeState {
    std::unordered_map<uint32_t, PendingDceRpcCall> pending_calls;
    bool bound_context_is_interface = false;
    uint16_t interface_context_id = 0;
    bool enumeration_note_seen = false;
};

// Attempts to interpret `payload` -- which must start with the 4-byte Zero+StreamProtocolLength
// prefix (see this file's own FRAMING paragraph) -- as one SMB frame. Returns std::nullopt (never
// throws) if match_smb_magic doesn't recognize the 4 bytes following that prefix.
//
// `tracked_rpc_pipe_file_ids`, when non-null, is a read-only view of the calling SmbFlowState's own
// tracked_rpc_pipe_file_ids set (below) -- the union of every FileId tracked in ANY of its per-
// interface pipe-state maps (netlogon_pipes today; samr_pipes/lsarpc_pipes/srvsvc_pipes/
// wkssvc_pipes/drsuapi_pipes as each interface's own phase adds it) -- consulted only to decide
// whether a WRITE/READ/IOCTL message's own FileId is worth copying dcerpc_raw_payload for at all
// (see SmbMessage's own doc comment on that field); nothing here mutates it or interprets its
// contents, nor does it need to know WHICH interface a given FileId belongs to -- that finer-
// grained dispatch is decode_with_correlation's own job (see dispatch_dcerpc_payload, smb.cpp),
// once try_parse_smb has returned. A plain set, not a map, since membership is literally all this
// layer ever needed from it (was a NetlogonPipeState-typed map before more than one interface
// existed to track). Omitted (nullptr), no WRITE/READ/IOCTL message ever gets a populated
// dcerpc_raw_payload, which is exactly correct for any caller (e.g. a future direct/test caller)
// that isn't tracking any RPC pipe at all.
std::optional<SmbFrame> try_parse_smb(
    ByteSpan payload,
    const std::unordered_set<SmbFileId, SmbFileIdHash>* tracked_rpc_pipe_file_ids = nullptr);

// Returns the total on-the-wire byte count one SMB frame declares (4-byte prefix + its own declared
// StreamProtocolLength) -- mirrors kerberos_tcp_declared_length's/ldap_tcp_declared_length's own
// role in decoder.cpp's generic TCP reassembly cascade, reached here through
// SmbTcpDecoder::tcp_declared_length.
std::optional<size_t> smb_tcp_declared_length(ByteSpan candidate);

// One outstanding NEGOTIATE/TREE_CONNECT/LOGOFF/TREE_DISCONNECT request, tracked per SMB SESSION
// (both directions), keyed by MessageId -- the plain Kerberos-style 1:1 shape.
struct SmbPendingRequest {
    size_t packet_index = 0;
    uint16_t command_value = 0;
    std::string tree_connect_path;  // set only for a pending TREE_CONNECT request -- lets the
                                      // matching response confirm curated note 5's own IPC$-specific
                                      // shape (a "$"-suffixed path whose response ShareType == pipe)
                                      // without re-deriving the path from the response alone, which
                                      // doesn't carry it
    std::string create_name;        // set only for a pending CREATE request, and only when its own
                                      // TreeId was already confirmed a pipe share -- "" otherwise,
                                      // including when the request targeted a non-pipe share; lets
                                      // the matching response's own FileId be tracked as the
                                      // netlogon pipe without re-deriving the name, which the
                                      // response alone doesn't carry
    bool has_file_id = false;       // set only for a pending READ request -- READ's own response
                                      // carries no FileId of its own (MS-SMB2), so it is threaded
                                      // through here instead, the same "carry forward what the
                                      // response alone won't have" shape create_name above uses
    SmbFileId file_id;
};

// One outstanding multi-leg NTLM handshake, tracked per SMB SESSION, keyed by SessionId -- see this
// file's header comment's STATE/CORRELATION section for why this is a genuinely new correlation
// shape relative to Kerberos's/LDAP's own. Opened when a SESSION_SETUP response returns
// STATUS_MORE_PROCESSING_REQUIRED with an NTLM CHALLENGE_MESSAGE in its buffer; closed on the
// terminal SESSION_SETUP response for that SessionId.
struct PendingNtlmHandshake {
    size_t packet_index = 0;        // the packet carrying the CHALLENGE_MESSAGE leg
    std::string domain_name;        // from the CHALLENGE_MESSAGE's own TargetName, best-effort label
};

class SmbFlowState : public DecoderFlowState {
public:
    bool smb1_seen = false;  // curated note 1's own sticky flag -- fires once per session
    std::unordered_map<uint64_t, SmbPendingRequest> pending_requests;         // keyed by MessageId
    std::unordered_map<uint64_t, PendingNtlmHandshake> pending_ntlm_handshakes;  // keyed by SessionId
    std::unordered_map<uint64_t, bool> pipe_shares;  // TreeId -> is_pipe_share, set at TREE_CONNECT
                                                        // response from its own already-computed
                                                        // ShareType, simply persisted per-TreeId
    std::unordered_map<SmbFileId, NetlogonPipeState, SmbFileIdHash> netlogon_pipes;  // keyed by
                                                                                        // FileId
    std::unordered_map<SmbFileId, SamrPipeState, SmbFileIdHash> samr_pipes;
    std::unordered_map<SmbFileId, LsarpcPipeState, SmbFileIdHash> lsarpc_pipes;

    // The union of every FileId tracked in netlogon_pipes/samr_pipes/lsarpc_pipes above (and, as
    // each is added, every future per-interface pipe-state map this struct gains -- srvsvc_pipes/
    // wkssvc_pipes/drsuapi_pipes) -- kept in lockstep by the CREATE-response/CLOSE handlers
    // (smb.cpp) with whichever per-interface map an insert/erase also touches. try_parse_smb
    // (smb.hpp) only ever needs membership, not which interface, to decide whether a WRITE/READ/
    // IOCTL message's payload is worth copying into dcerpc_raw_payload at all -- see
    // try_parse_smb's own doc comment.
    std::unordered_set<SmbFileId, SmbFileIdHash> tracked_rpc_pipe_file_ids;

    // Curated-note sticky flags that span more than one per-interface pipe-state map, so they
    // cannot live on any single one of them -- see smb.cpp's own decode_dcerpc_and_samr/
    // decode_dcerpc_and_lsarpc for where each fires.
    bool null_or_guest_session_seen = false;         // set alongside this file's own existing
                                                        // curated note 4 (SESSION_SETUP response
                                                        // IS_GUEST/IS_NULL), consulted by SAMR's/
                                                        // LSARPC's own enumeration notes to add a
                                                        // "null-session enumeration" escalation
    bool samr_lsarpc_cross_interface_note_seen = false;  // SAMR + LSARPC enumeration on the same
                                                            // session -- fires once, the first time
                                                            // both samr_pipes and lsarpc_pipes are
                                                            // simultaneously non-empty at the point
                                                            // either interface's own enumeration
                                                            // note fires
};

// SMB over TCP/445 (direct hosting) and TCP/139 (NetBIOS Session Service) -- id()=="smb",
// GateKind::TcpPortIndependent. No UDP sibling -- SMB has none.
class SmbTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "smb"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return smb_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& smb_tcp_decoder();

}  // namespace conduitscope
