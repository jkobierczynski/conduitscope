// SPDX-License-Identifier: Apache-2.0
// kerberos.hpp - Windows Active Directory Kerberos (RFC 4120) decoding, over UDP/88 and TCP/88.
//
// FIRST OF A PLANNED FOUR-PROTOCOL WINDOWS AD SUITE (Kerberos, then LDAP, then SMB/NTLM, then
// Netlogon/DCE-RPC -- each delivered as its own separate addition; this file covers Kerberos
// only). Unlike every other protocol in this codebase, Kerberos is not OT/ICS or general-
// networking -- it's added because AD compromise is a standard pivot point into OT environments
// (AD-joined engineering workstations, jump hosts), so visibility into it fits conduitscope's
// NIS2/IEC 62443 audit angle directly. Built entirely on the ProtocolDecoder registry interface
// (protocol_decoder.hpp) that TwinCAT/ADS (twincat.hpp) pioneered -- no DecodedPacket fields of
// its own, everything rides DecodedPacket::result as a KerberosMessage; see twincat.hpp's own
// file header comment for why that shape was chosen in the first place.
//
// WIRE FORMAT
//
// ASN.1 DER (a strict subset of BER -- definite-length only, no indefinite-length encoding,
// which this decoder's BER TLV reader below already assumes throughout, following mms.cpp's own
// BerTlv/read_ber_tlv/ber_children -- adapted here rather than shared, per this codebase's
// established "each protocol keeps its own self-contained BER walker" convention, the same
// posture already documented for the session_key duplication between asset_inventory.cpp/
// policy_engine.cpp).
//
// Every top-level message is `[APPLICATION n] SEQUENCE {...}` -- an APPLICATION-class,
// constructed tag (whose low 5 bits ARE the message-type number, since every value used here is
// 0-30 and fits the ASN.1 low-tag-number form with no high-tag-number bytes needed) wrapping an
// explicitly-tagged UNIVERSAL SEQUENCE (0x30), whose own children are the message's
// context-tagged fields:
//   AS-REQ    tag 10 (0x6A)   TGS-REQ   tag 12 (0x6C)     -- KDC-REQ shape
//   AS-REP    tag 11 (0x6B)   TGS-REP   tag 13 (0x6D)     -- KDC-REP shape
//   AP-REQ    tag 14 (0x6E)   AP-REP    tag 15 (0x6F)     -- their own shapes
//   KRB-ERROR tag 30 (0x7E)                                -- its own shape
// Over UDP/88 (the common KDC-exchange case) each datagram carries exactly one such message.
// Over TCP/88 (RFC 4120 SS7.2.2), each message is preceded by a 4-byte big-endian length field
// (the byte count of the message that follows, not counting the 4-byte field itself) -- the same
// "outer framing layer hands a clean inner ByteSpan to a shared parser" shape as
// COTP-wrapping-S7comm, not DNP3's own multi-frame reassembly state machine.
//
// MESSAGE COVERAGE
//
// Full field decode (these carry every field the curated attack/monitoring notes below need):
//   - AS-REQ/TGS-REQ (KDC-REQ): pvno, msg-type (cross-checked against the outer APPLICATION
//     tag), padata (named subset: PA-ENC-TIMESTAMP(2)/PA-ETYPE-INFO(11)/PA-ETYPE-INFO2(19)/
//     PA-PAC-REQUEST(128)/PA-FOR-USER(129, S4U2Self shape), else "padata-type N"), and
//     req-body's own kdc-options (BIT STRING -> named flags), cname/realm (AS-REQ only --
//     TGS-REQ authenticates via its embedded AP-REQ, not a plaintext cname), sname, till
//     (KerberosTime), nonce, etype list (named subset: des-cbc-crc(1)/des-cbc-md5(3)/
//     rc4-hmac(23)/rc4-hmac-exp(24)/aes128-cts-hmac-sha1-96(17)/aes256-cts-hmac-sha1-96(18),
//     else "etype N"), and additional-tickets presence (S4U2Proxy/constrained-delegation shape).
//   - AS-REP/TGS-REP (KDC-REP): crealm/cname, the embedded Ticket's own visible realm/sname/
//     enc-part etype (NOT the ciphertext, which needs keys), and the response's own outer
//     enc-part etype (also unencrypted -- this is what actually reveals RC4-vs-AES for the
//     roasting/downgrade notes below).
//   - KRB-ERROR: error-code (named table: KDC_ERR_C_PRINCIPAL_UNKNOWN(6)/
//     KDC_ERR_S_PRINCIPAL_UNKNOWN(7)/KDC_ERR_ETYPE_NOSUPP(14)/KDC_ERR_CLIENT_REVOKED(18)/
//     KDC_ERR_PREAUTH_FAILED(24)/KDC_ERR_PREAUTH_REQUIRED(25)/KRB_AP_ERR_SKEW(37), else
//     "error N"), cname/sname/realm when present, e-text when present.
// Structural-only decode (common traffic, but their bodies are mostly opaque ciphertext without
// keys):
//   - AP-REQ/AP-REP: ap-options (BIT STRING -> use-session-key/mutual-required), the embedded
//     Ticket's visible realm/sname/enc-part etype for AP-REQ (same downgrade-visibility value as
//     above, and the field a forged/Golden-ticket enc-part etype would show up in), and the
//     Authenticator's/AP-REP's own enc-part etype. The Authenticator/AP-REP enc-part CIPHERTEXT
//     is never decoded -- DELIBERATELY OUT OF SCOPE, the same honest limit any passive-capture
//     Kerberos analysis has (Wireshark's own dissector can't decrypt these without keys either).
//
// DELIBERATELY NOT IMPLEMENTED IN THIS PASS: KRB-SAFE(20)/KRB-PRIV(21)/KRB-CRED(22) -- rare
// outside app-level Kerberos usage (kpasswd and similar), not part of the core AD auth exchange;
// PAC contents (embedded in the Ticket's encrypted part, unreadable without the target account's
// or krbtgt's key -- no SID/group extraction, no PAC signature validation, ever, from a passive
// capture); any ASN.1 CHOICE alternative beyond the padata-type/etype/error-code tables above
// renders as its raw numeric form ("padata-type N"/"etype N"/"error N"), the same graceful-
// fallback posture every existing named-enum-with-fallback table in this codebase already takes
// (DNP3's point-format table, TwinCAT's command-name table).
//
// STRUCTURAL DETECTION GATE: (a) outer tag byte is one of {0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F,
// 0x7E} (constructed APPLICATION 10/11/12/13/14/15/30 -- the only values Kerberos ever wraps a
// top-level message in); (b) the BER length of the outer SEQUENCE fits within the available
// bytes; (c) inside, pvno (context [0] for KDC-REP/KRB-ERROR/AP-REQ/AP-REP, context [1] for
// KDC-REQ -- the tag position genuinely differs between request and response shapes per RFC
// 4120's own ASN.1 module) must equal 5, AND msg-type (the field immediately after pvno) must
// equal the message-type value implied by the outer APPLICATION tag. This two-independent-field
// cross-check -- not just a leading magic byte -- is the strong signal, the same "more than one
// independent structural check" rigor OPC UA/EtherNet-IP/TwinCAT already established. TCP's
// tcp_declared_length() reads the 4-byte length prefix AND peeks at the following byte for one
// of the same 7 tag values before returning a length, so it's nearly as selective as the full
// decode gate, not merely "4+ bytes present" -- this matters because decoder.cpp's TCP
// declared-length cascade is order-sensitive and the first plausible answer wins.
//
// COLLISION SURVEY (checked against every protocol already tried opportunistically on TCP and
// UDP -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION section for the full writeup): OPC UA's 7
// fixed ASCII MessageType strings (0x6A='j', 0x6B='k', 0x6C='l', 0x6D='m', 0x6E='n', 0x6F='o',
// 0x7E='~' -- none of OPC UA's actual strings, "HEL"/"ACK"/"ERR"/"RHE"/"OPN"/"CLO"/"MSG", start
// with any of those); IEC104's fixed 0x68 start byte; DNP3's fixed 0x0564 sync; Modbus's
// protocol-id==0 field; TwinCAT's conventionally-zero AMS/TCP reserved bytes; TPKT's version==3
// byte. None collide with a 0x6A-0x6F/0x7E leading tag byte, nor with a raw 4-byte big-endian
// length prefix on the TCP side. Registered directly after the existing TCP-port-independent
// chain (alongside TwinCAT/HART-IP) for TCP, and alongside BACnet/CIP-I/O for UDP.
//
// CURATED ATTACK/MONITORING NOTES (see kerberos.cpp for the exact heuristics; every one is
// framed as surfacing a wire-level mechanism or shape, never as an assertion of detected
// intent -- the same honest posture S7comm's plc_stop_message field already established for
// "the wire-level mechanism behind a well-known attack"):
//   1. AS-REP Roasting -- two-tier: a standing low-severity note on any AS-REQ with no
//      PA-ENC-TIMESTAMP padata entry (NOT itself anomalous -- every real Windows client's first
//      AS-REQ looks like this), plus the actual flagship flag only on a correlated, SUCCESSFUL
//      AS-REP (not a KRB-ERROR) answering such a request on the same session.
//   2. Kerberoasting -- on a TGS-REP whose Ticket's enc-part etype is RC4 for a non-krbtgt sname.
//   3. Weak-encryption/downgrade note -- any AS-REQ/TGS-REQ offering DES/RC4 with no AES etype.
//   4. Delegation-shape surfacing -- forwardable/proxiable/proxy kdc-options flags and
//      additional-tickets presence, structural only, no abuse asserted.
//   5. KRB-ERROR code naming plus --stats aggregation (output.cpp) for passive burst/enumeration
//      visibility (no per-session correlation needed for this one).
//
// STATE/CORRELATION: KerberosFlowState (below), keyed by FlowStateKeying::Session (built via
// decoder.cpp's own tcp_session_key helper -- confirmed transport-agnostic despite its name,
// reused as-is from both the new UDP and TCP Kerberos call sites). Outstanding AS-REQs are
// tracked by cname (visible in AS-REQ, unlike TGS-REQ); outstanding TGS-REQs are tracked by
// requested sname (the SPN itself -- more directly useful for the Kerberoasting correlation than
// any client-identity key would be, since TGS-REQ often omits cname). Documented limitation:
// this is session+cname/sname correlation, NOT the nonce field RFC 4120 defines for exactly this
// purpose -- the nonce echo lives inside the response's encrypted part and is unreadable without
// keys. Sufficient for realistic single-exchange-at-a-time KDC traffic; could misattribute if the
// same client had two genuinely overlapping unanswered requests on one session, which is rare in
// practice.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t KERBEROS_PORT = 88;  // same port number, both UDP and TCP -- HART-IP's exact shape

enum class KerberosMessageType : uint8_t {
    AsReq = 10,
    AsRep = 11,
    TgsReq = 12,
    TgsRep = 13,
    ApReq = 14,
    ApRep = 15,
    KrbError = 30,
};

// Returns the canonical message-type name ("AS-REQ", "TGS-REP", ...) for one of the seven values
// above, or std::nullopt for anything else -- used both by try_parse_kerberos's own gate check
// and to render KerberosMessage::message_type.
std::optional<std::string> kerberos_message_type_name(uint8_t msg_type);

struct KerberosMessage {
    std::string message_type;  // always set -- try_parse_kerberos rejects an unrecognized msg-type
    uint8_t msg_type_value = 0;
    bool is_response = false;  // AS-REP/TGS-REP/AP-REP/KRB-ERROR
    uint8_t pvno = 0;

    // KDC-REQ (AS-REQ/TGS-REQ) req-body fields -- see this file's header comment.
    std::vector<std::string> padata_types;  // named padata-type strings present, wire order
    bool has_pa_enc_timestamp = false;      // derived convenience flag, see padata_types
    std::vector<std::string> kdc_options;   // named KDCOptions flags set (forwardable, ...)
    std::string cname;                      // AS-REQ only -- TGS-REQ typically omits it
    std::string realm;
    std::string sname;      // requested SPN -- AS-REQ (usually krbtgt) or TGS-REQ (real target)
    std::string till;       // KerberosTime, rendered ISO-8601
    uint32_t nonce = 0;
    std::vector<std::string> etypes;  // offered/accepted etype list, named, wire order
    bool has_additional_tickets = false;

    // KDC-REP (AS-REP/TGS-REP) fields.
    std::string crealm;
    // `cname` above doubles as the response's own cname field (a message is never both a request
    // and a response, so there is no ambiguity in sharing the one field).
    bool has_ticket = false;
    uint8_t ticket_tkt_vno = 0;
    std::string ticket_realm;
    std::string ticket_sname;
    std::string ticket_enc_part_etype;  // the embedded Ticket's own enc-part etype
    bool has_enc_part = false;
    std::string enc_part_etype;  // the RESPONSE's own outer enc-part etype (AS-REP/TGS-REP/AP-REP)
                                  // -- the field the roasting/downgrade notes actually key off of

    // KRB-ERROR fields.
    uint32_t error_code = 0;
    std::string error_name;  // named, or "error N"
    std::string error_text;  // e-text, if present

    // AP-REQ/AP-REP.
    std::vector<std::string> ap_options;  // named APOptions flags set (use-session-key, ...)

    // Filled in by KerberosDecoder::decode (not try_parse_kerberos) once cross-packet
    // correlation is applied -- see this file's header comment's STATE/CORRELATION section.
    bool correlated_request_seen = false;
    size_t correlated_request_index = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `message` as one Kerberos message (the de-framed ASN.1 bytes -- TCP's
// 4-byte length prefix, if any, already stripped by the caller). Returns std::nullopt (never
// throws) if the structural detection gate (see this file's header comment) isn't satisfied.
// Never performs cross-packet correlation itself -- see KerberosUdpDecoder::decode/
// KerberosTcpDecoder::decode, which call this and then apply that layer, the same split
// try_parse_twincat/TwinCatDecoder::decode already established.
std::optional<KerberosMessage> try_parse_kerberos(ByteSpan message);

// Returns the total on-the-wire byte count one TCP-framed Kerberos message declares (the 4-byte
// length prefix plus its own declared length), once there are enough bytes to read that
// declaration (>= 5, since this also peeks at the first byte of the framed message itself for
// one of the seven recognized tag values -- see this file's header comment) -- mirrors
// twincat_declared_length's own role in decoder.cpp's generic TCP reassembly cascade
// (Decoder::reassemble_tcp_payload), reached here through KerberosTcpDecoder::tcp_declared_length.
std::optional<size_t> kerberos_tcp_declared_length(ByteSpan payload);

// One outstanding AS-REQ or TGS-REQ, tracked per Kerberos SESSION (both directions -- see
// DecodeContext::session_key) -- see this file's header comment's STATE/CORRELATION section for
// why AS-REQ is keyed by cname and TGS-REQ by sname.
struct KerberosPendingRequest {
    size_t packet_index = 0;
    bool had_no_preauth = false;  // AS-REQ only -- see the AS-REP Roasting note's two-tier design
};

class KerberosFlowState : public DecoderFlowState {
public:
    std::unordered_map<std::string, KerberosPendingRequest> pending_as_req;   // keyed by cname
    std::unordered_map<std::string, KerberosPendingRequest> pending_tgs_req;  // keyed by sname
};

// Kerberos over TCP/88 -- id()=="kerberos", GateKind::TcpPortIndependent, tcp_declared_length()
// drives this codebase's usual TCP reassembly cascade for the 4-byte length prefix.
class KerberosTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "kerberos"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return kerberos_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

// Kerberos over UDP/88 -- id()=="kerberos" (deliberately shared with KerberosTcpDecoder above,
// the same two-instance-shared-id() pattern EnipTcpDecoder/EnipUdpDecoder and
// HartIpTcpDecoder/HartIpUdpDecoder already established -- see either pair's own comments for why
// sharing one id() is safe: every output writer dispatches on the plain DecodedPacket::protocol
// string, never on registry id() uniqueness). GateKind::UdpPortIndependent (tried
// opportunistically regardless of port, the same posture BACnet/CIP-I/O/HART-IP's own UDP path
// already have). Rides the SAME try_parse_kerberos as the TCP side -- UDP carries the raw ASN.1
// message directly, with no framing of its own to strip first.
class KerberosUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "kerberos"; }
    GateKind gate_kind() const override { return GateKind::UdpPortIndependent; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& kerberos_tcp_decoder();
const ProtocolDecoder& kerberos_udp_decoder();

}  // namespace conduitscope
