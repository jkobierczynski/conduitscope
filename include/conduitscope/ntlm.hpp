// SPDX-License-Identifier: Apache-2.0
// ntlm.hpp - NTLM (MS-NLMP) authentication message decoding, shared by smb.hpp's own SMB2
// SESSION_SETUP handling (the only place NTLM appears in this codebase's current scope -- see
// smb.hpp's file header comment).
//
// PART OF THE SMB2/NTLM DECODER (AD suite, phase 3 of 4) -- see smb.hpp's own file header comment
// for the full plan-level context (why SMB/NTLM is phase 3, what it completes). This file exists
// separately from smb.hpp/smb.cpp, rather than being folded inline, because NTLM's own wire format
// is BYTE-IDENTICAL wherever it is embedded (there is no per-embedding tagging-convention variance
// the way Kerberos's EXPLICIT vs. LDAP's IMPLICIT ASN.1 tagging differ) -- sharing one parser here
// is the correct application of this codebase's "each protocol keeps its own copy of low-level wire
// readers" convention, not an exception to it. `smb.cpp` calls into this file directly; NTLM has no
// `ProtocolDecoder`, gate, or port of its own on the wire (see protocol_decoder.hpp's COEXISTENCE
// RULE -- this file participates in no registry cascade at all).
//
// WIRE FORMAT: every NTLM message begins with the fixed 8-byte signature "NTLMSSP\0", followed by a
// 4-byte little-endian MessageType (1 = NEGOTIATE_MESSAGE, 2 = CHALLENGE_MESSAGE, 3 =
// AUTHENTICATE_MESSAGE). Every variable-length field beyond that fixed prefix is addressed by an
// 8-byte "field descriptor" (2-byte Len, 2-byte MaxLen -- always equal to Len in practice and never
// rendered, 4-byte little-endian Offset from the start of this NTLM message), per [MS-NLMP]
// sections 2.2.1.1-2.2.1.3. Every structure below was verified against Microsoft's own [MS-NLMP]
// Open Specification and cross-checked against the `hirochachacha/go-smb2` Go package's own NTLM
// implementation during this decoder's planning (see smb.hpp's own plan-provenance note).
//
// MESSAGE COVERAGE (see smb.hpp's own DELIBERATELY NOT IMPLEMENTED list for what this file does
// NOT do, above all: LmChallengeResponse/NtChallengeResponse/EncryptedRandomSessionKey are NEVER
// rendered beyond presence + byte length -- this is the actual proof-of-possession/hash material,
// the entire point of an NTLM relay or an offline NTLMv2 crack, and rendering it would make this
// decoder itself a credential-harvesting tool):
//   - NEGOTIATE_MESSAGE (type 1): NegotiateFlags (named, all 22 defined bits), DomainName/
//     WorkstationName (OEM-encoded single-byte strings, present only when the corresponding
//     _SUPPLIED flag is set).
//   - CHALLENGE_MESSAGE (type 2): TargetName, NegotiateFlags, ServerChallenge (8 raw bytes -- a
//     nonce, not a secret, safe to render unlike the credential material above), TargetInfo decoded
//     as a proper AV_PAIR list (every AvId named; string-typed pairs rendered, opaque ones
//     presence/length only), Version when present.
//   - AUTHENTICATE_MESSAGE (type 3): NegotiateFlags, DomainName, UserName, WorkstationName (all
//     UTF-16LE when NTLMSSP_NEGOTIATE_UNICODE is set, OEM single-byte otherwise -- decoded via
//     byteio.hpp's utf16le_to_utf8 for the Unicode case), Version, a best-effort MIC-presence
//     heuristic (see ntlm.cpp's own comment -- this one field is NOT independently spec-confirmed
//     the way everything else in this file is, since [MS-NLMP] itself documents MIC's presence as
//     implementation/negotiation dependent rather than a fixed structural slot).
//
// Malformed/truncated NTLM bytes never abort the enclosing SMB2 decode -- try_parse_ntlm returns
// std::nullopt (never throws past its own boundary; smb.cpp wraps the call in the same try/catch
// discipline every other protocol's own embedded-payload parse already uses), and the enclosing
// SESSION_SETUP message is still rendered with everything decoded above the NTLM blob.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// The 8-byte NTLM signature, "NTLMSSP\0" -- exposed so smb.cpp can scan a SESSION_SETUP Buffer for
// it (a pragmatic substitute for full SPNEGO/GSS-API ASN.1 unwrapping, see smb.hpp's own comment).
constexpr const char kNtlmSignature[9] = "NTLMSSP\0";  // 8 significant bytes + the array's own NUL

// One decoded AV_PAIR (MS-NLMP section 2.2.2.1), part of a CHALLENGE_MESSAGE's TargetInfo list.
struct NtlmAvPair {
    uint16_t av_id = 0;
    std::string av_id_name;    // "MsvAvNbComputerName", or "AvId N" if unrecognized
    bool is_string = false;    // true for the six string-typed AvIds -- see av_string_value
    std::string string_value;  // set only when is_string is true (UTF-16LE-decoded)
    uint32_t flags_value = 0;  // set only for MsvAvFlags (av_id == 6) -- the one non-string,
                                // non-opaque, small-integer AvId worth rendering directly
    bool has_flags_value = false;
    size_t byte_length = 0;  // the AV_PAIR's own AvLen -- always set, including for string/flags
                              // pairs, so a caller can tell an empty string from "not present"
};

struct NtlmMessage {
    uint32_t message_type_value = 0;  // 1, 2, or 3
    std::string message_type;         // "NEGOTIATE_MESSAGE" / "CHALLENGE_MESSAGE" / "AUTHENTICATE_MESSAGE"

    uint32_t negotiate_flags = 0;
    std::vector<std::string> negotiate_flag_names;  // named, in the fixed table order -- see
                                                       // ntlm.cpp's kNegotiateFlagTable

    // NEGOTIATE_MESSAGE.
    std::string domain_name;       // OEM-decoded, present only if NTLMSSP_NEGOTIATE_OEM_DOMAIN_SUPPLIED
    std::string workstation_name;  // OEM-decoded, present only if
                                     // NTLMSSP_NEGOTIATE_OEM_WORKSTATION_SUPPLIED

    // CHALLENGE_MESSAGE.
    std::string target_name;
    bool has_server_challenge = false;
    std::string server_challenge_hex;  // 8 raw bytes, rendered as hex -- a nonce, safe to show
    std::vector<NtlmAvPair> target_info;

    // AUTHENTICATE_MESSAGE.
    std::string auth_domain_name;
    std::string user_name;
    std::string auth_workstation_name;
    bool lm_challenge_response_present = false;
    size_t lm_challenge_response_length = 0;  // byte length ONLY -- see this file's header comment;
                                                // the credential material itself is never read out
    bool nt_challenge_response_present = false;
    size_t nt_challenge_response_length = 0;   // same treatment
    bool encrypted_random_session_key_present = false;
    size_t encrypted_random_session_key_length = 0;  // same treatment
    bool mic_present = false;  // best-effort heuristic -- see ntlm.cpp's own comment

    // Version (NEGOTIATE_MESSAGE/CHALLENGE_MESSAGE/AUTHENTICATE_MESSAGE all share this shape,
    // present only when NTLMSSP_NEGOTIATE_VERSION is set and enough bytes remain for it).
    bool has_version = false;
    uint8_t version_major = 0;
    uint8_t version_minor = 0;
    uint16_t version_build = 0;
    uint8_t version_ntlm_revision = 0;

    std::string summary;
};

// Attempts to interpret `message` as one NTLM message -- `message` must start at the "NTLMSSP\0"
// signature itself (smb.cpp locates that offset via a signature scan of the enclosing
// SESSION_SETUP Buffer field first; this function does not search for it). Returns std::nullopt
// (never throws) if the signature/message-type prefix doesn't match one of the three recognized
// types, or if the fixed-size header for that type doesn't fit in `message`.
std::optional<NtlmMessage> try_parse_ntlm(ByteSpan message);

}  // namespace conduitscope
