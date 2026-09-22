// SPDX-License-Identifier: Apache-2.0
// netlogon.cpp - implementation of netlogon.hpp. See that file's own header comment for the full
// design rationale, verification methodology, and opnum coverage table; this file follows it exactly.
#include "conduitscope/netlogon.hpp"

#include <cstdio>

namespace conduitscope {

namespace {

// ---------------------------------------------------------------------------------------------
// NDR string helpers (conformant-varying wchar_t* strings, MS-RPCE 14.3.4.2 / NDR "string" IDL
// attribute). Every string field this file decodes is one of these two shapes:
//   - a [ref] string: no referent ID, the conformant-varying header + chars start immediately.
//   - a [unique] string: a 4-byte referent ID first (0 == NULL, no string data follows at all;
//     nonzero == "string data follows", the referent ID's own value is otherwise meaningless here).
// See netlogon.hpp's own file header comment for the two empirically-confirmed wrinkles this
// depends on: a top-level wchar_t* without an explicit [unique]/[ref] attribute defaults to [ref]
// even under pointer_default(unique), and NETLOGON_SECURE_CHANNEL_TYPE is a 16-bit NDR enum.
// ---------------------------------------------------------------------------------------------

// NDR aligns every scalar/array to its own natural alignment (1 for a byte array, 2 for a 16-bit
// field, 4 for a 32-bit field or a conformant array's own MaxCount) -- most of this file's own
// field sequences happen to stay 4-aligned throughout simply because every field is itself a
// multiple of 4 bytes (a referent ID, a conformant string padded to 4 on its own way out, an
// 8-byte credential), but NETLOGON_SECURE_CHANNEL_TYPE is a 16-bit field (see this file's own
// SecureChannelType comment) and is immediately followed, in every opnum this file decodes, by a
// 4-byte-aligned conformant string (ComputerName) -- align4 re-aligns for exactly that one
// wrinkle. Called at the start of read_ndr_string/read_ndr_unique_string below (a conformant
// array's own MaxCount is itself a 4-byte field) rather than after every scalar read, so it's a
// no-op everywhere the cursor is already aligned and only actually skips bytes at the one place
// this file's own field sequences need it.
void align4(Cursor& c) {
    size_t pad = (4 - (c.position() % 4)) % 4;
    if (pad > 0) c.skip(pad);
}

// Reads one NDR conformant-varying string: MaxCount(4)/Offset(4)/ActualCount(4), all u32le, then
// ActualCount*2 bytes of UTF-16LE character data (the wire's own ActualCount includes the
// terminating NUL), then pads to the next 4-byte boundary. MaxCount/Offset are structurally
// required to be present but are never meaningful for this codebase's own read-only decode (every
// string this file ever sees is a single, unfragmented conformant array), so neither is validated
// against ActualCount -- a malformed relationship between them still yields whatever ActualCount
// itself says, and any resulting truncation is caught by the caller's own try/catch the same way
// every other malformed-field case in this codebase already is.
std::string read_ndr_string(Cursor& c) {
    align4(c);  // a conformant array's own MaxCount is a 4-byte field -- see align4's own comment
    (void)c.u32le();  // MaxCount -- structurally present, not itself meaningful here
    (void)c.u32le();  // Offset -- likewise
    uint32_t actual_count = c.u32le();
    ByteSpan chars = c.bytes(static_cast<size_t>(actual_count) * 2);
    std::string s = utf16le_to_utf8(chars);
    if (!s.empty() && s.back() == '\0') {
        s.pop_back();
    }
    size_t pad = (4 - (c.position() % 4)) % 4;
    if (pad > 0) {
        c.skip(pad);
    }
    return s;
}

// Reads one NDR [unique] string pointer: a 4-byte referent ID, then (only if nonzero) the same
// conformant-varying string read_ndr_string reads for a [ref] pointer. Returns an empty string for
// a NULL pointer (referent ID == 0) -- indistinguishable, at this decode depth, from an empty
// string that was actually sent; this codebase does not track "was this field present at all"
// separately from "was it empty," the same posture already taken for optional strings elsewhere.
std::string read_ndr_unique_string(Cursor& c) {
    align4(c);  // the referent ID itself is a 4-byte field
    uint32_t referent_id = c.u32le();
    if (referent_id == 0) {
        return std::string();
    }
    return read_ndr_string(c);
}

bool all_zero(ByteSpan b) {
    for (size_t i = 0; i < b.size(); ++i) {
        if (b.at(i) != 0) {
            return false;
        }
    }
    return true;
}

// NETLOGON_SECURE_CHANNEL_TYPE, [MS-NRPC] Appendix A's own IDL (all 8 named values).
std::string secure_channel_type_name(uint16_t v) {
    switch (v) {
        case 0: return "NullSecureChannel";
        case 1: return "MsvApSecureChannel";
        case 2: return "WorkstationSecureChannel";
        case 3: return "TrustedDnsDomainSecureChannel";
        case 4: return "TrustedDomainSecureChannel";
        case 5: return "UasServerSecureChannel";
        case 6: return "ServerSecureChannel";
        case 7: return "CdcServerSecureChannel";
        default: return "type " + std::to_string(v);
    }
}

// A small, locally-scoped NTSTATUS subset -- own table per this codebase's established per-file
// convention (status_name in smb.cpp is not shared here, the same way smb.cpp's own table isn't
// shared with any other file). Only the two values actually useful for Netlogon call outcomes are
// named; everything else falls back to hex, the same "flag rather than guess" bar every unnamed
// status value in this codebase already gets.
std::string netlogon_status_name(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// The curated opnum-name table -- see netlogon.hpp's own OPNUM COVERAGE list for which tier each
// belongs to. Returns nullptr for anything outside this table; netlogon_opnum_name (the public,
// header-declared wrapper) supplies the "opnum N" fallback.
const char* netlogon_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 0: return "NetrLogonUasLogon";
        case 1: return "NetrLogonUasLogoff";
        case 2: return "NetrLogonSamLogon";
        case 4: return "NetrServerReqChallenge";
        case 5: return "NetrServerAuthenticate";
        case 6: return "NetrServerPasswordSet";
        case 15: return "NetrServerAuthenticate2";
        case 21: return "NetrLogonGetCapabilities";
        case 26: return "NetrServerAuthenticate3";
        case 29: return "NetrLogonGetDomainInfo";
        case 30: return "NetrServerPasswordSet2";
        case 31: return "NetrServerPasswordGet";
        case 39: return "NetrLogonSamLogonEx";
        case 42: return "NetrServerTrustPasswordsGet";
        case 45: return "NetrLogonSamLogonWithFlags";
        case 59: return "NetrServerAuthenticateKerberos";
        default: return nullptr;
    }
}

// ---------------------------------------------------------------------------------------------
// Request-side parse functions. Each is wrapped internally in try/catch: a malformed/truncated
// stub yields whatever fields were decoded before the truncation was hit rather than aborting the
// whole call's decode, the same per-field leniency parse_one_smb2_message's own command bodies and
// ntlm.cpp's own parse_negotiate/parse_challenge/parse_authenticate already establish.
// ---------------------------------------------------------------------------------------------

NetlogonCall parse_req_challenge_request(uint32_t call_id, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = 4;
    call.opnum_name = netlogon_opnum_name(4);
    call.is_response = false;
    call.has_request_fields = true;
    try {
        Cursor c(stub);
        call.primary_name = read_ndr_unique_string(c);
        call.computer_name = read_ndr_string(c);
        ByteSpan cred = c.bytes(8);
        call.has_client_credential = true;
        call.client_credential_hex = to_hex(cred, "");
        call.client_credential_is_all_zero = all_zero(cred);
    } catch (const ParseError&) {
        // Leave whatever fields were already set -- see this section's own header comment.
    }
    call.summary = call.opnum_name + " computer=" + call.computer_name +
                   (call.client_credential_is_all_zero ? " challenge=ALL-ZERO" : "");
    return call;
}

NetlogonCall parse_authenticate_request(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = netlogon_opnum_name(opnum);
    call.is_response = false;
    call.has_request_fields = true;
    try {
        Cursor c(stub);
        call.primary_name = read_ndr_unique_string(c);
        call.account_name = read_ndr_string(c);
        call.secure_channel_type_value = c.u16le();
        call.has_secure_channel_type = true;
        call.secure_channel_type_name = secure_channel_type_name(call.secure_channel_type_value);
        call.computer_name = read_ndr_string(c);
        ByteSpan cred = c.bytes(8);
        call.has_client_credential = true;
        call.client_credential_hex = to_hex(cred, "");
        call.client_credential_is_all_zero = all_zero(cred);
        if (opnum != 5) {
            call.negotiate_flags = c.u32le();
            call.has_negotiate_flags = true;
        }
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " account=" + call.account_name +
                   (call.client_credential_is_all_zero ? " credential=ALL-ZERO" : "");
    return call;
}

// NetrServerPasswordSet2 request. See netlogon.hpp's own file header comment for the explicit
// caveat that NL_TRUST_PASSWORD's own exact trailing byte layout (the 512-byte buffer + 4-byte
// Length that follows the Authenticator) was not independently empirically cross-checked the way
// ReqChallenge/Authenticate3 were during planning -- a misread here fails closed via the same
// try/catch every other field-level decode in this file already uses, never guessing at bytes
// that were never actually verified.
NetlogonCall parse_password_set2_request(uint32_t call_id, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = 30;
    call.opnum_name = netlogon_opnum_name(30);
    call.is_response = false;
    call.has_request_fields = true;
    try {
        Cursor c(stub);
        call.primary_name = read_ndr_unique_string(c);
        call.account_name = read_ndr_string(c);
        call.secure_channel_type_value = c.u16le();
        call.has_secure_channel_type = true;
        call.secure_channel_type_name = secure_channel_type_name(call.secure_channel_type_value);
        call.computer_name = read_ndr_string(c);
        // NETLOGON_AUTHENTICATOR: Credential(8) + Timestamp(4) = 12 bytes. Presence only -- never
        // rendered, see this file's own header comment and netlogon.hpp's own OPNUM COVERAGE note.
        if (c.remaining() >= 12) {
            c.skip(12);
            call.has_authenticator = true;
        }
        // NL_TRUST_PASSWORD: a 512-byte opaque buffer followed by a 4-byte little-endian Length --
        // presence + declared length only, NEVER the buffer's own bytes. See this function's own
        // header comment for the confidence caveat on this specific layout.
        if (c.remaining() >= 516) {
            c.skip(512);
            call.clear_new_password_length = c.u32le();
            call.has_clear_new_password = true;
        }
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " account=" + call.account_name;
    return call;
}

// ---------------------------------------------------------------------------------------------
// Response-side parse functions.
// ---------------------------------------------------------------------------------------------

NetlogonCall parse_req_challenge_response(uint32_t call_id, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = 4;
    call.opnum_name = netlogon_opnum_name(4);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan cred = c.bytes(8);
        call.has_server_credential = true;
        call.server_credential_hex = to_hex(cred, "");
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = netlogon_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

NetlogonCall parse_authenticate_response(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = netlogon_opnum_name(opnum);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan cred = c.bytes(8);
        call.has_server_credential = true;
        call.server_credential_hex = to_hex(cred, "");
        if (opnum != 5) {
            call.negotiate_flags = c.u32le();
            call.has_negotiate_flags = true;
        }
        if (opnum == 26) {
            call.account_rid = c.u32le();
            call.has_account_rid = true;
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = netlogon_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// NetrServerPasswordSet2 response -- ReturnAuthenticator (presence only, same posture as the
// request's own Authenticator) + trailing status. Not declared in netlogon.hpp (no caller needs
// it separately -- try_parse_netlogon_response's own opnum==30 case below calls this directly),
// kept file-local the same way this file's other small helpers are.
NetlogonCall parse_password_set2_response(uint32_t call_id, ByteSpan stub) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = 30;
    call.opnum_name = netlogon_opnum_name(30);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        if (c.remaining() >= 12) {
            c.skip(12);
            call.has_authenticator = true;
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = netlogon_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// The minimal, structural-only NetlogonCall built for any opnum outside this file's own curated
// full-decode set -- opnum named from netlogon_opnum_name_raw's own table when it's in it,
// otherwise reported purely numerically. No field decode is ever attempted.
NetlogonCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = netlogon_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

// The "sealed, not decoded" fallback -- see netlogon.hpp's own SEALING paragraph. Every field
// besides the common ones is deliberately left unset: this codebase never attempts to parse
// ciphertext as if it were plaintext NDR.
NetlogonCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    NetlogonCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = netlogon_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

}  // namespace

bool is_netlogon_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kNetlogonInterfaceUuid;
}

std::string netlogon_opnum_name(uint16_t opnum) {
    const char* name = netlogon_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

NetlogonCall try_parse_netlogon_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 4:
            return parse_req_challenge_request(call_id, stub);
        case 5:
        case 15:
        case 26:
            return parse_authenticate_request(call_id, opnum, stub);
        case 30:
            return parse_password_set2_request(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

NetlogonCall try_parse_netlogon_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 4:
            return parse_req_challenge_response(call_id, stub);
        case 5:
        case 15:
        case 26:
            return parse_authenticate_response(call_id, opnum, stub);
        case 30:
            return parse_password_set2_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
