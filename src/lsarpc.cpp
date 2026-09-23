// SPDX-License-Identifier: Apache-2.0
// lsarpc.cpp - implementation of lsarpc.hpp. See that file's own header comment for the full design
// rationale, verification methodology, and opnum coverage table; see samr.cpp's own header comment
// for the general NDR deferred-pointer ordering rule both files rely on.
#include "conduitscope/lsarpc.hpp"

#include <cstdio>

#include "conduitscope/dcerpc.hpp"
#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

const char* lsarpc_opnum_name_raw(uint16_t opnum) {
    switch (opnum) {
        case 0: return "LsarClose";
        case 6: return "LsarOpenPolicy";
        case 7: return "LsarQueryInformationPolicy";
        case 11: return "LsarEnumerateAccounts";
        case 13: return "LsarEnumerateTrustedDomains";
        case 14: return "LsarLookupNames";
        case 15: return "LsarLookupSids";
        case 44: return "LsarOpenPolicy2";
        case 50: return "LsarEnumerateTrustedDomainsEx";
        case 57: return "LsarLookupSids2";
        case 58: return "LsarLookupNames2";
        case 68: return "LsarLookupNames3";
        case 76: return "LsarLookupSids3";
        case 77: return "LsarLookupNames4";
        default: return nullptr;
    }
}

std::string lsarpc_status_name(uint32_t status) {
    switch (status) {
        case 0x00000000: return "STATUS_SUCCESS";
        case 0xC0000022: return "STATUS_ACCESS_DENIED";
        case 0x00000107: return "STATUS_SOME_NOT_MAPPED";
        case 0xC0000073: return "STATUS_NONE_MAPPED";
        default: {
            char buf[16];
            std::snprintf(buf, sizeof(buf), "0x%08X", status);
            return std::string(buf);
        }
    }
}

// Reads one LSAPR_REFERENCED_DOMAIN_LIST via the caller's own already-read outer pointer referent
// (`outer_referent`) -- LsarLookupNames'/LsarLookupSids' own ReferencedDomains field, and, with a
// different outer field name but the identical element type, LsarEnumerateTrustedDomains' own
// EnumerationBuffer.Information. NESTED (reached only via a pointer, never a top-level RPC
// parameter itself), so its own three fields (Entries/Domains-pointer/MaxEntries) are written in
// the textbook NDR "batched" order -- all three fixed parts first, THEN the Domains array's own
// deferred content -- unlike a top-level field, which would interleave (see samr.cpp's own header
// comment for the full rule and how this was empirically pinned down for this exact structure).
std::vector<LsarDomainEntry> read_referenced_domain_list(Cursor& c, uint32_t outer_referent) {
    if (outer_referent == 0) {
        return {};
    }
    (void)c.u32le();               // Entries -- Domains' own MaximumCount (below) is authoritative
    uint32_t domains_referent = c.u32le();
    (void)c.u32le();               // MaxEntries -- not itself meaningful for a read-only decode
    if (domains_referent == 0) {
        return {};
    }
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> name_referents;
    std::vector<uint32_t> sid_referents;
    for (uint32_t i = 0; i < maximum_count && name_referents.size() < kMax; ++i) {
        (void)c.u16le();  // Name.Length
        (void)c.u16le();  // Name.MaximumLength
        name_referents.push_back(c.u32le());
        sid_referents.push_back(c.u32le());
    }
    std::vector<LsarDomainEntry> domains;
    domains.reserve(name_referents.size());
    for (size_t i = 0; i < name_referents.size(); ++i) {
        LsarDomainEntry entry;
        if (name_referents[i] != 0) entry.name = read_ndr_string(c);
        if (sid_referents[i] != 0) entry.sid = read_ndr_sid(c);
        domains.push_back(std::move(entry));
    }
    return domains;
}

// Reads one LSAPR_TRANSLATED_SIDS array body (LsarLookupNames' own response field) -- each
// LSA_TRANSLATED_SID entry is Use(u32, SID_NAME_USE, not rendered -- mirrors samr.cpp's own
// LookupNamesInDomain Use-discard), RelativeId(u32, kept), DomainIndex(i32, not rendered -- indexing
// into referenced_domains is left to the reader of this codebase's own JSON/text output rather than
// resolved here, the same "flat, self-describing fields" posture the rest of this codebase already
// follows). No pointers in this entry shape at all, so no deferred data.
std::vector<uint32_t> read_translated_sids(Cursor& c) {
    (void)c.u32le();  // Entries
    uint32_t referent = c.u32le();
    if (referent == 0) {
        return {};
    }
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> rids;
    for (uint32_t i = 0; i < maximum_count && rids.size() < kMax; ++i) {
        (void)c.u32le();  // Use
        rids.push_back(c.u32le());
        (void)c.u32le();  // DomainIndex
    }
    return rids;
}

// Reads one LSAPR_TRANSLATED_NAMES array body (LsarLookupSids' own response field) -- each
// LSA_TRANSLATED_NAME entry is Use(u32, not rendered), Name(RPC_UNICODE_STRING, embedded, kept),
// DomainIndex(i32, not rendered) -- 16 bytes fixed/entry (array rule: all entries' fixed parts
// first, then all deferred names, batched).
std::vector<std::string> read_translated_names(Cursor& c) {
    (void)c.u32le();  // Entries
    uint32_t referent = c.u32le();
    if (referent == 0) {
        return {};
    }
    uint32_t maximum_count = c.u32le();
    const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
    std::vector<uint32_t> name_referents;
    for (uint32_t i = 0; i < maximum_count && name_referents.size() < kMax; ++i) {
        (void)c.u32le();  // Use
        (void)c.u16le();  // Name.Length
        (void)c.u16le();  // Name.MaximumLength
        name_referents.push_back(c.u32le());
        (void)c.u32le();  // DomainIndex
    }
    std::vector<std::string> names;
    names.reserve(name_referents.size());
    for (uint32_t referent2 : name_referents) {
        names.push_back(referent2 != 0 ? read_ndr_string(c) : std::string());
    }
    return names;
}

// ---------------------------------------------------------------------------------------------
// Request-side parse functions.
// ---------------------------------------------------------------------------------------------

// The minimal, structural-only LsarCall built for any opnum outside this file's own curated
// full-decode set -- see lsarpc.hpp's own OPNUM COVERAGE list for which opnums land here, including
// LsarOpenPolicy/OpenPolicy2 (6/44) *requests* specifically: both lead with SystemName (a pointer)
// immediately followed by ObjectAttributes, a 6-field structure three of whose fields are themselves
// pointers (RootDirectory/ObjectName/SecurityDescriptor, normally NULL in practice but not
// structurally guaranteed to be) plus a normally-populated pointer to a small fixed
// SECURITY_QUALITY_OF_SERVICE block -- skipping past this safely requires chasing every one of those
// pointers correctly, and this file's own empirical pass did not independently pin down
// SECURITY_QUALITY_OF_SERVICE's own exact field layout with the same confidence as this file's other
// structures. Rather than risk a silent misdecode on an unverified structure this deep in a pointer
// chain, this codebase reports the opnum only for that request side -- the response side (see
// parse_open_policy_response below) is unaffected, since it starts fresh from its own stub.
LsarCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response);

LsarCall parse_enumerate_request(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = lsarpc_opnum_name(opnum);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        call.enumeration_context = c.u32le();
        call.has_enumeration_context = true;
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name;
    return call;
}

// LsarLookupNames (14) request -- PolicyHandle(20) + Count(u32) + Names (top-level embedded
// conformant-varying array of RPC_UNICODE_STRING). The trailing TranslatedSids placeholder/
// LookupLevel/MappedCount fields carry nothing this codebase renders, so this file stops decoding
// once Names is read.
LsarCall parse_lookup_names_request(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 14;
    call.opnum_name = lsarpc_opnum_name(14);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        (void)c.u32le();  // Count
        call.lookup_names = read_ndr_unicode_string_array(c);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " names=" + std::to_string(call.lookup_names.size());
    return call;
}

// LsarLookupSids (15) request -- PolicyHandle(20) + SidEnumBuffer{Entries(u32),
// SidInfo:pointer-to-array-of-pointer-to-RPC_SID}. Trailing TranslatedNames/LookupLevel/MappedCount
// not decoded, same reasoning as LookupNames above.
LsarCall parse_lookup_sids_request(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 15;
    call.opnum_name = lsarpc_opnum_name(15);
    call.is_response = false;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_handle = true;
        call.handle_hex = to_hex(h, "");
        (void)c.u32le();  // SidEnumBuffer.Entries
        uint32_t referent = c.u32le();
        if (referent != 0) {
            call.lookup_sids = read_ndr_sid_pointer_array(c);
        }
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " sids=" + std::to_string(call.lookup_sids.size());
    return call;
}

// ---------------------------------------------------------------------------------------------
// Response-side parse functions.
// ---------------------------------------------------------------------------------------------

LsarCall parse_open_policy_response(uint32_t call_id, uint16_t opnum, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = lsarpc_opnum_name(opnum);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        ByteSpan h = c.bytes(20);
        call.has_result_handle = true;
        call.result_handle_hex = to_hex(h, "");
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = lsarpc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response status=" + call.status_name;
    return call;
}

// LsarEnumerateAccounts (11) response -- EnumerationContext(u32) [top-level, eager] +
// EnumerationBuffer{EntriesRead(u32), Information:pointer-to-array-of-pointer-to-RPC_SID}
// [top-level struct field, resolved before ErrorCode] + ErrorCode(u32).
LsarCall parse_enumerate_accounts_response(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 11;
    call.opnum_name = lsarpc_opnum_name(11);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.enumeration_context = c.u32le();
        call.has_enumeration_context = true;
        (void)c.u32le();  // EnumerationBuffer.EntriesRead
        uint32_t information_referent = c.u32le();
        if (information_referent != 0) {
            call.enumerated_sids = read_ndr_sid_pointer_array(c);
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = lsarpc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response accounts=" + std::to_string(call.enumerated_sids.size()) +
                   " status=" + call.status_name;
    return call;
}

// LsarEnumerateTrustedDomains (13) response -- identical top-level shape to EnumerateAccounts, but
// EnumerationBuffer.Information points to an array of LSAPR_TRUST_INFORMATION{Name,Sid} (the same
// element shape LookupNames'/LookupSids' own ReferencedDomains uses) rather than a bare SID pointer.
LsarCall parse_enumerate_trusted_domains_response(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 13;
    call.opnum_name = lsarpc_opnum_name(13);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        call.enumeration_context = c.u32le();
        call.has_enumeration_context = true;
        (void)c.u32le();  // EnumerationBuffer.EntriesRead
        uint32_t information_referent = c.u32le();
        if (information_referent != 0) {
            uint32_t maximum_count = c.u32le();
            const size_t kMax = resource_limits().max_decoded_objects.value_or(64);
            std::vector<uint32_t> name_referents;
            std::vector<uint32_t> sid_referents;
            for (uint32_t i = 0; i < maximum_count && name_referents.size() < kMax; ++i) {
                (void)c.u16le();  // Name.Length
                (void)c.u16le();  // Name.MaximumLength
                name_referents.push_back(c.u32le());
                sid_referents.push_back(c.u32le());
            }
            for (size_t i = 0; i < name_referents.size(); ++i) {
                LsarDomainEntry entry;
                if (name_referents[i] != 0) entry.name = read_ndr_string(c);
                if (sid_referents[i] != 0) entry.sid = read_ndr_sid(c);
                call.enumerated_trusted_domains.push_back(std::move(entry));
            }
        }
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = lsarpc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name + " response domains=" +
                   std::to_string(call.enumerated_trusted_domains.size()) +
                   " status=" + call.status_name;
    return call;
}

// LsarLookupNames (14) response -- ReferencedDomains(top-level pointer, nested target) +
// TranslatedSids(top-level struct field) + MappedCount(u32, discard) + ErrorCode(u32).
LsarCall parse_lookup_names_response(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 14;
    call.opnum_name = lsarpc_opnum_name(14);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        uint32_t referenced_domains_referent = c.u32le();
        call.referenced_domains = read_referenced_domain_list(c, referenced_domains_referent);
        call.translated_rids = read_translated_sids(c);
        (void)c.u32le();  // MappedCount
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = lsarpc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response translated=" + std::to_string(call.translated_rids.size()) +
                   " status=" + call.status_name;
    return call;
}

// LsarLookupSids (15) response -- ReferencedDomains(same as LookupNames') + TranslatedNames(top-level
// struct field) + MappedCount(discard) + ErrorCode(u32).
LsarCall parse_lookup_sids_response(uint32_t call_id, ByteSpan stub) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = 15;
    call.opnum_name = lsarpc_opnum_name(15);
    call.is_response = true;
    call.has_response_fields = true;
    try {
        Cursor c(stub);
        uint32_t referenced_domains_referent = c.u32le();
        call.referenced_domains = read_referenced_domain_list(c, referenced_domains_referent);
        call.translated_names = read_translated_names(c);
        (void)c.u32le();  // MappedCount
        call.status = c.u32le();
        call.has_status = true;
        call.status_name = lsarpc_status_name(call.status);
    } catch (const ParseError&) {
        // Leave whatever fields were already set.
    }
    call.summary = call.opnum_name +
                   " response translated=" + std::to_string(call.translated_names.size()) +
                   " status=" + call.status_name;
    return call;
}

LsarCall structural_only(uint32_t call_id, uint16_t opnum, bool is_response) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = lsarpc_opnum_name(opnum);
    call.is_response = is_response;
    call.summary = call.opnum_name;
    return call;
}

LsarCall sealed_fallback(uint32_t call_id, uint16_t opnum, bool is_response, size_t stub_len) {
    LsarCall call;
    call.call_id = call_id;
    call.opnum = opnum;
    call.opnum_name = lsarpc_opnum_name(opnum);
    call.is_response = is_response;
    call.sealed = true;
    call.summary = "sealed, " + std::to_string(stub_len) + " bytes, not decoded";
    return call;
}

}  // namespace

bool is_lsarpc_interface_uuid(const std::string& abstract_syntax_uuid) {
    return abstract_syntax_uuid == kLsarpcInterfaceUuid;
}

std::string lsarpc_opnum_name(uint16_t opnum) {
    const char* name = lsarpc_opnum_name_raw(opnum);
    if (name != nullptr) {
        return std::string(name);
    }
    return "opnum " + std::to_string(opnum);
}

LsarCall try_parse_lsarpc_request(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/false, stub.size());
    }
    switch (opnum) {
        case 11:
        case 13:
            return parse_enumerate_request(call_id, opnum, stub);
        case 14:
            return parse_lookup_names_request(call_id, stub);
        case 15:
            return parse_lookup_sids_request(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/false);
    }
}

LsarCall try_parse_lsarpc_response(uint32_t call_id, uint16_t opnum, bool sealed, ByteSpan stub) {
    if (sealed) {
        return sealed_fallback(call_id, opnum, /*is_response=*/true, stub.size());
    }
    switch (opnum) {
        case 6:
        case 44:
            return parse_open_policy_response(call_id, opnum, stub);
        case 11:
            return parse_enumerate_accounts_response(call_id, stub);
        case 13:
            return parse_enumerate_trusted_domains_response(call_id, stub);
        case 14:
            return parse_lookup_names_response(call_id, stub);
        case 15:
            return parse_lookup_sids_response(call_id, stub);
        default:
            return structural_only(call_id, opnum, /*is_response=*/true);
    }
}

}  // namespace conduitscope
