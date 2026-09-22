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
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/it_protocols.hpp"  // SMB_PORT_445/SMB_NETBIOS_SESSION_PORT_139, match_smb_magic
#include "conduitscope/ntlm.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

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

// Attempts to interpret `payload` -- which must start with the 4-byte Zero+StreamProtocolLength
// prefix (see this file's own FRAMING paragraph) -- as one SMB frame. Returns std::nullopt (never
// throws) if match_smb_magic doesn't recognize the 4 bytes following that prefix.
std::optional<SmbFrame> try_parse_smb(ByteSpan payload);

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
