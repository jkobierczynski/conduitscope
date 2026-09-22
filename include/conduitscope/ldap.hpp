// SPDX-License-Identifier: Apache-2.0
// ldap.hpp - Windows Active Directory LDAP (RFC 4511) decoding, over TCP/389 and TCP/3268 (Global
// Catalog).
//
// SECOND OF THE PLANNED FOUR-PROTOCOL WINDOWS AD SUITE (Kerberos, then LDAP -- this file -- then
// SMB/NTLM, then Netlogon/DCE-RPC, each delivered separately). LDAP recon (SPN sweeps,
// userAccountControl bit queries) is literally how a real attacker *finds* the AS-REP-Roasting/
// Kerberoasting targets kerberos.hpp's own curated notes already flag, so this phase completes that
// story rather than starting a new one -- see this file's own curated-notes section below. Built
// entirely on the ProtocolDecoder registry interface (protocol_decoder.hpp) that TwinCAT/Kerberos
// already use -- no DecodedPacket fields of its own, everything rides DecodedPacket::result as an
// LdapMessage.
//
// LDAP already had SHALLOW, name-only recognition in this codebase before this file existed (Tier 3's
// "enterprise-trust" family, it_protocols.hpp/.cpp): that recognition is now REMOVED (see
// it_protocols.hpp's own file header comment) in favor of this full decoder -- the same "pull one
// protocol out of a shared tier into its own dedicated decoder/CLI surface" move this codebase already
// made once for EAPOL. `match_ldap_ber`/`looks_like_ldap_ber` (it_protocols.hpp) are the one piece kept
// from that old code, reused as-is by this file's own structural gate rather than duplicated.
//
// WIRE FORMAT: RFC 4511's ASN.1 module is `DEFINITIONS IMPLICIT TAGS` -- the OPPOSITE of Kerberos's
// (RFC 4120) `EXPLICIT TAGS` convention (confirmed against the actual ASN.1 module text, not recalled
// from training). Concretely: a context/APPLICATION tag REPLACES the underlying type's own tag rather
// than wrapping a separately-tagged inner TLV -- there is NO "peel one layer" step anywhere in this
// file's own BER reader (ldap.cpp), unlike kerberos.cpp's own explicit_child(). E.g. `bindRequest
// [APPLICATION 0] BindRequest` where `BindRequest ::= [APPLICATION 0] SEQUENCE {...}` wire-encodes as
// ONE tag byte 0x60 whose content bytes are version/name/authentication directly -- not 0x60 wrapping
// a nested 0x30. The constructed-vs-primitive bit of a tagged field is likewise NOT uniform -- it
// depends on the underlying type, checked per-field (ldap.cpp's own ldap_op_shape table): e.g.
// AbandonRequest ::= [APPLICATION 16] MessageID (INTEGER, primitive) wire-encodes as 0x50, not 0x70;
// DelRequest ::= [APPLICATION 10] LDAPDN (OCTET STRING, primitive) wire-encodes as 0x4A;
// UnbindRequest ::= [APPLICATION 2] NULL wire-encodes as 0x42, zero-length content. Every other
// protocolOp alternative is SEQUENCE- or LDAPResult(SEQUENCE)-typed, hence constructed. The same rule
// applies recursively inside SearchRequest's Filter CHOICE (RFC 4511 section 4.5.1) -- see ldap.cpp's
// own decode_filter for the full per-alternative tag/shape table.
//
// MESSAGE COVERAGE
//
// Full field decode (the operations most relevant to authentication/reconnaissance -- matching
// kerberos.hpp's own "not every message type needs the same depth" discipline):
//   - BindRequest/BindResponse: version, name (bind DN), authentication (simple -- presence + byte
//     length only, the credential bytes themselves are NEVER rendered; sasl -- mechanism name decoded,
//     credentials presence/length only, same never-rendered treatment, since SASL PLAIN carries an
//     authzid\0authcid\0password triple in that same field). BindResponse: resultCode (named, full RFC
//     4511 section 4.1.9 table), matchedDN, diagnosticMessage.
//   - UnbindRequest: presence only (NULL body).
//   - SearchRequest: baseObject, scope/derefAliases (named), sizeLimit, timeLimit, typesOnly,
//     attributes, and filter -- decoded recursively and rendered in conventional ldapsearch-style
//     syntax (e.g. "(&(objectClass=user)(servicePrincipalName=*))"). Recursion depth capped via
//     max_ldap_filter_depth() (wraps resource_limits().max_recursion_depth, the mms.cpp/goose.cpp
//     pattern).
//   - SearchResultEntry: objectName, and its attribute type=value list -- values rendered as strings,
//     capped in length, with binary-looking values shown as "(N bytes, binary)" rather than a guessed
//     string decode (this codebase's existing "don't guess at unstructured binary" posture).
//   - SearchResultDone/SearchResultReference: resultCode/matchedDN/diagnosticMessage; referral URIs.
//   - CompareRequest/CompareResponse: entry, the attribute+value compared, and the boolean result.
//   - AbandonRequest: the messageID being abandoned.
//   - ExtendedRequest/ExtendedResponse: requestName/responseName OID (named for well-known OIDs where
//     confidently known, e.g. StartTLS = 1.3.6.1.4.1.1466.20037 -- confirmed via LDAPWiki, not just
//     recalled); requestValue/responseValue presence/length only, never decoded (opaque per-extension
//     payload).
//
// STRUCTURAL-ONLY (recognized, message type + messageID named, not field-decoded): AddRequest/
// AddResponse, ModifyRequest/ModifyResponse, DelRequest/DelResponse, ModifyDNRequest/ModifyDNResponse,
// IntermediateResponse -- write operations and the rarer response type, lower pentest/monitoring value
// for a first pass.
//
// DELIBERATELY NOT IMPLEMENTED: CLDAP (UDP, RFC 1798, obsolete -- no UDP decoder instance at all, see
// LdapTcpDecoder below); SASL/`simple` credential *contents* (never decrypted/decoded, only
// presence+length, by design, not a depth gap to close later); Controls' controlValue payloads (OID
// named when a control is present, e.g. the well-known Paged Results Control, value bytes not
// decoded); LDAPS full decode (needs keys, same limit as TLS everywhere else in this codebase -- see
// it_protocols.hpp's own LDAPS handling, unaffected by this file).
//
// STRUCTURAL DETECTION GATE (reused from it_protocols.hpp's own match_ldap_ber/looks_like_ldap_ber,
// not duplicated): (a) outer tag 0x30 (SEQUENCE) with a BER length that plausibly fits the available
// bytes; (b) messageID INTEGER (1-4 bytes) immediately inside; (c) protocolOp's own tag byte matches
// APPLICATION class (tag & 0xC0 == 0x40), tag number one of the 21 valid values {0..16, 19, 23, 24,
// 25}. This file's own decode (ldap.cpp's try_parse_ldap) adds the STRONGER per-field check
// match_ldap_ber doesn't: the constructed bit must ALSO match that specific op number's own
// underlying-type shape (see the Wire format section above) -- not a blanket "any APPLICATION tag
// passes" check.
//
// COLLISION SURVEY: a real collision WAS found and resolved during this decoder's own planning, not
// left for implementation to discover -- Kerberos's outer APPLICATION tag bytes for AS-REP/TGS-REQ/
// TGS-REP/AP-REQ/AP-REP (0x6B/0x6C/0x6D/0x6E/0x6F) are byte-identical to LDAP's own delResponse/
// modDNRequest/modDNResponse/compareRequest/compareResponse APPLICATION tags (RFC 4511's module is
// IMPLICIT TAGS, so those five LDAP operations -- all LDAPResult- or SEQUENCE-typed, hence
// constructed -- produce the exact same tag byte class+number as five of Kerberos's seven message
// types). This does NOT actually collide at the dispatch-gate level: Kerberos's structural gate reads
// the outer tag of the ENTIRE de-framed payload (its own message-type tag IS byte 0 there, after its
// own 4-byte TCP length prefix is stripped), while every LDAPMessage's byte 0 is ALWAYS the fixed
// envelope SEQUENCE tag 0x30 -- LDAP's own per-operation APPLICATION tags only appear several bytes
// INSIDE the envelope, as the protocolOp field, never as the leading byte either decoder's own gate
// inspects. Also unaffected by the pre-existing, already-solved LDAP-vs-MQTT collision (0x30 is also a
// valid MQTT PUBLISH control-packet-type/flags byte) -- see it_protocols.hpp's looks_like_ldap_ber
// comment for that carve-out, reused as-is by decoder.cpp's MQTT call site. No collision found against
// any other protocol in the TCP-port-independent cascade (OPC UA/EtherNet-IP/IEC104/Modbus/TwinCAT/
// DNP3/COTP/HART-IP/FF-HSE) -- none of their own fixed leading-byte/magic-string checks match 0x30.
// Registered directly after Kerberos in tcp_port_independent_registry() -- see protocol_registry.cpp.
//
// CURATED ATTACK/MONITORING NOTES (see ldap.cpp for the exact heuristics; every one is framed as
// surfacing a wire-level mechanism or shape, never as an assertion of detected intent -- legitimate
// directory tooling uses several of these same filter shapes too):
//   1. Anonymous/unauthenticated bind -- standing note, unconditional: simple authentication with no
//      password (RFC 4513 section 5.1.2's own anonymous/unauthenticated bind shapes).
//   2. Cleartext credential exposure without prior StartTLS -- a simple bind with a non-empty
//      password, or a SASL PLAIN bind, is flagged only when no ExtendedRequest naming the StartTLS OID
//      has been observed earlier on this same TCP session (LdapFlowState::starttls_seen). The password
//      itself is never rendered (see Wire format above).
//   3. AD reconnaissance filter shapes -- a SearchRequest filter referencing servicePrincipalName is
//      the standard Kerberoasting target-discovery step (directly upstream of kerberos.hpp's own
//      Kerberoasting note); a filter referencing adminCount is the standard privileged-account sweep.
//   4. AS-REP-Roasting target discovery -- a filter using userAccountControl with a bitwise
//      extensibleMatch (the AD-specific LDAP_MATCHING_RULE_BIT_AND OID, 1.2.840.113556.1.4.803 --
//      confirmed via Microsoft's own MS-ADTS spec) against the DONT_REQ_PREAUTH bit (0x400000 --
//      confirmed via Microsoft's own troubleshooting doc), directly upstream of kerberos.hpp's own
//      AS-REP-Roasting note.
//   5. Delegation discovery -- the same bitwise-match mechanism against the TRUSTED_FOR_DELEGATION bit
//      (0x80000) or a filter referencing msDS-AllowedToDelegateTo -- the LDAP-side complement of the
//      delegation-shape note kerberos.hpp already surfaces on the wire.
//   6. Bind result-code naming plus --stats aggregation (output.cpp) -- the LDAP-native analog of
//      Kerberos's own KRB-ERROR count aggregation: named resultCode counts (invalidCredentials(49)
//      above all) aggregated across the capture, so a burst of failed binds across many distinct bind
//      DNs -- the password-spray signature -- is visible with no per-request correlation needed.
//
// STATE/CORRELATION: LdapFlowState (below), keyed by FlowStateKeying::Session (tcp_session_key,
// reused as-is). Three pieces of state: `starttls_seen` (set on an ExtendedRequest naming the StartTLS
// OID, never cleared -- a session doesn't un-upgrade); a pending-bind map (created on BindRequest,
// matched-and-erased on BindResponse, keyed by messageID); a pending-search map (created on
// SearchRequest, NOT erased on each SearchResultEntry -- only the running entry count is incremented --
// erased with a final "N entries returned" correlation note on SearchResultDone). This last shape --
// "keep state across many responses, close on the terminal one" -- is genuinely new relative to
// kerberos.hpp's own 1:1 request/response pairing, since one SearchRequest can have arbitrarily many
// SearchResultEntry responses before its one SearchResultDone. Worth stating as a genuine IMPROVEMENT
// over Kerberos's own documented limitation, not another instance of it: LDAP's messageID is the
// RFC-mandated, always-visible-on-the-wire correlation key (RFC 4511 section 4.1.1.1 requires it to be
// unique among a connection's outstanding requests) -- unlike Kerberos, where the real nonce
// correlation field is unreadably encrypted and cname/sname had to be used as an honest substitute.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/it_protocols.hpp"  // LDAP_PORT/LDAP_GC_PORT, looks_like_ldap_ber
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

struct LdapMessage {
    int64_t message_id = 0;
    std::string message_type;  // "BindRequest", "SearchResultEntry", ... -- always set; try_parse_ldap
                                // rejects an unrecognized/malformed protocolOp entirely
    uint8_t op_num = 0;        // the raw protocolOp APPLICATION tag number (0-16, 19, 23-25)
    bool is_response = false;

    // BindRequest.
    uint8_t bind_version = 0;
    std::string bind_dn;
    bool bind_is_sasl = false;
    std::string bind_auth_mechanism;  // "simple", or the SASL mechanism name (GSSAPI/DIGEST-MD5/
                                       // PLAIN/EXTERNAL/...)
    bool bind_credential_present = false;
    size_t bind_credential_length = 0;  // byte length ONLY -- see this file's header comment; the
                                         // credential itself is never read out of the wire bytes

    // LDAPResult-shaped fields, shared by BindResponse/SearchResultDone/CompareResponse/
    // ExtendedResponse (all four are literally "[APPLICATION n] LDAPResult" or a COMPONENTS OF it).
    bool has_result = false;
    int32_t result_code = 0;
    std::string result_code_name;  // named (RFC 4511 section 4.1.9), or "resultCode N"
    std::string matched_dn;
    std::string diagnostic_message;
    std::vector<std::string> referral_uris;  // LDAPResult's own referral[3], or a bare
                                              // SearchResultReference's own URI list

    // SearchRequest.
    std::string search_base_object;
    std::string search_scope;          // named: baseObject/singleLevel/wholeSubtree
    std::string search_deref_aliases;  // named
    int32_t search_size_limit = 0;
    int32_t search_time_limit = 0;
    bool search_types_only = false;
    std::string search_filter;  // rendered ldapsearch-style, e.g. "(&(objectClass=user)(...))"
    std::vector<std::string> search_attributes;
    // Curated-note trigger flags, set while decode_filter (ldap.cpp) walks the filter tree -- see
    // this file's header comment's curated-notes section for notes 3-5.
    bool search_filter_has_spn = false;
    bool search_filter_has_admin_count = false;
    bool search_filter_has_asrep_roast_bit = false;
    bool search_filter_has_delegation_shape = false;

    // SearchResultEntry.
    std::string search_result_object_name;
    std::vector<std::string> search_result_attributes;  // rendered "type=value[,value...]", capped by
                                                          // resource_limits().max_decoded_objects

    // SearchResultDone's own correlation-derived field -- filled in by LdapTcpDecoder::decode (not
    // try_parse_ldap), see this file's header comment's STATE/CORRELATION section.
    size_t search_entry_count = 0;

    // CompareRequest.
    std::string compare_entry;
    std::string compare_attribute;
    std::string compare_value;

    // AbandonRequest.
    int64_t abandon_message_id = 0;

    // ExtendedRequest/ExtendedResponse.
    std::string extended_request_name;        // raw OID
    std::string extended_request_name_known;  // "StartTLS", or empty if not a recognized OID
    bool extended_value_present = false;
    size_t extended_value_length = 0;
    std::string extended_response_name;

    // LDAPMessage's own optional controls[0] -- OID only (see this file's DELIBERATELY NOT
    // IMPLEMENTED list above; controlValue is never decoded).
    std::vector<std::string> control_oids;

    // Filled in by LdapTcpDecoder::decode (not try_parse_ldap) once cross-packet correlation is
    // applied -- see this file's header comment's STATE/CORRELATION section.
    bool correlated_request_seen = false;
    size_t correlated_request_index = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `message` as one LDAPMessage (a full TCP payload candidate -- LDAP-over-TCP
// has no length-prefix framing of its own; the outer SEQUENCE's own BER length IS the framing, see
// ldap_tcp_declared_length below). Returns std::nullopt (never throws) if the structural detection
// gate (see this file's header comment) isn't satisfied. Never performs cross-packet correlation
// itself -- see LdapTcpDecoder::decode, which calls this and then applies that layer, the same split
// try_parse_kerberos/KerberosTcpDecoder::decode already established.
std::optional<LdapMessage> try_parse_ldap(ByteSpan message);

// Returns the total on-the-wire byte count one LDAPMessage declares (its own outer SEQUENCE tag +
// BER length + declared content length), once the structural gate (looks_like_ldap_ber, reused from
// it_protocols.hpp) is satisfied -- mirrors kerberos_tcp_declared_length's/twincat_declared_length's
// own role in decoder.cpp's generic TCP reassembly cascade (Decoder::reassemble_tcp_payload), reached
// here through LdapTcpDecoder::tcp_declared_length.
std::optional<size_t> ldap_tcp_declared_length(ByteSpan payload);

// One outstanding BindRequest, tracked per LDAP SESSION (both directions -- see
// DecodeContext::session_key), keyed by messageID.
struct LdapPendingBind {
    size_t packet_index = 0;
};

// One outstanding SearchRequest, tracked the same way, but NOT erased until its terminal
// SearchResultDone arrives -- see this file's header comment's STATE/CORRELATION section for why this
// "keep across many responses" shape is new relative to Kerberos's own 1:1 pairing.
struct LdapPendingSearch {
    size_t packet_index = 0;
    size_t entry_count = 0;  // incremented on each correlated SearchResultEntry
};

class LdapFlowState : public DecoderFlowState {
public:
    bool starttls_seen = false;  // set on an ExtendedRequest naming the StartTLS OID, never cleared
    std::unordered_map<int64_t, LdapPendingBind> pending_binds;      // keyed by messageID
    std::unordered_map<int64_t, LdapPendingSearch> pending_searches;  // keyed by messageID
};

// LDAP over TCP/389 (and TCP/3268, Global Catalog) -- id()=="ldap", GateKind::TcpPortIndependent.
// Unlike Kerberos, there is deliberately NO UDP sibling instance -- LDAP's historical connectionless
// variant (CLDAP, RFC 1798) is obsolete/deprecated and not part of mainstream AD traffic, see this
// file's header comment's DELIBERATELY NOT IMPLEMENTED list.
class LdapTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "ldap"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return ldap_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& ldap_tcp_decoder();

}  // namespace conduitscope
