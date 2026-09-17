// SPDX-License-Identifier: Apache-2.0
// dns.hpp - DNS (RFC 1035) message decoding, shared by three protocols that all reuse the exact
// same question/resource-record wire format: classic DNS (UDP port 53), Multicast DNS / mDNS
// (RFC 6762, UDP port 5353), and Link-Local Multicast Name Resolution / LLMNR (RFC 4795, UDP
// port 5355). See DnsFlavor below for exactly what differs between the three -- it is a handful
// of header-bit reinterpretations and two class-field top-bit repurposings, never the underlying
// name/question/RR encoding, which RFC 6762 section 1 and RFC 4795 section 2 both state
// explicitly reuse RFC 1035 verbatim. One shared parser (try_parse_dns_message) therefore covers
// all three; decoder.cpp calls it once per flavor with the port to match.
//
// Sourcing: cross-checked field-by-field against the RFC text itself -- RFC 1035 section 4
// (message header/question/RR format, name compression), RFC 3596 (AAAA), RFC 2782 (SRV), RFC
// 6762 sections 6.2 ("QU" unicast-response bit) and 10.2 (cache-flush bit), RFC 4795 section 2.1
// (LLMNR's own header bit layout).
//
// ---------------------------------------------------------------------------------------------
// Header (12 bytes, identical shape across all three flavors -- RFC 1035 4.1.1):
//   ID(2), then a second 16-bit word whose bit-5/bit-7/bit-8 positions mean different things
//   depending on flavor (bit-6, TC, is the one bit that means "truncated" in every flavor):
//     DNS / mDNS (RFC 1035 4.1.1, unmodified by RFC 6762):
//       QR(1) OPCODE(4) AA(1) TC(1) RD(1) RA(1) Z(3, must be zero) RCODE(4)
//     LLMNR (RFC 4795 2.1.1):
//       QR(1) OPCODE(4)  C(1) TC(1)  T(1) Z(4, must be zero)       RCODE(4)
//       -- C ("Conflict") replaces AA's bit position, T ("Tentative") replaces RD's, and RA's bit
//       position folds into LLMNR's wider 4-bit reserved Z field.
//   Then QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT, 16 bits each, all three flavors alike.
//
// Question section (RFC 1035 4.1.2), one per QDCOUNT: QNAME (below) + QTYPE(2) + QCLASS(2).
// mDNS only (RFC 6762 6.2): QCLASS's top bit is the "QU" bit ("I will accept a unicast reply"),
// stripped from the class value shown and surfaced separately as unicast_response_requested.
//
// Resource record (RFC 1035 4.1.3), one per ANCOUNT/NSCOUNT/ARCOUNT (answer/authority/additional
// sections, identical shape in all three): NAME + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) +
// RDATA(RDLENGTH). mDNS only (RFC 6762 10.2): CLASS's top bit is the cache-flush bit, stripped
// and surfaced separately as cache_flush. TYPE 41 (OPT, RFC 6891 EDNS0) repurposes CLASS as the
// requestor's UDP payload size and TTL as (extended-RCODE(8) | version(8) | flags(16), top flags
// bit = "DO"/DNSSEC-OK) -- this decoder recognizes that shape rather than mis-rendering OPT's
// CLASS/TTL as an ordinary class name and TTL-in-seconds; RDATA (the EDNS options list) is shown
// as hex only, not further decoded.
//
// NAME/QNAME encoding (RFC 1035 4.1.2/4.1.4): a sequence of length-prefixed labels (length octet
// 0-63, top two bits clear) terminated by a zero-length label (the root), OR a two-octet
// compression pointer (top two bits set, remaining 14 bits an offset from the start of the whole
// message) that redirects decoding elsewhere in the message -- used both to terminate a label
// sequence early and as an entire name by itself. This decoder follows pointer chains with a
// hop-count cap (128) purely as a decompression-bomb/loop guard; RFC 1035 permits pointers to
// chain (a pointer may point at bytes that are themselves label(s) followed by another pointer).
//
// RDATA "first pass" value decode (mirrors this codebase's existing "first pass" precedent --
// BACnet's service/property scoping, DNP3's group/variation table): A (RFC 1035, 4-byte IPv4),
// AAAA (RFC 3596, 16-byte IPv6), NS/CNAME/PTR (RFC 1035, a single compressible domain name), MX
// (RFC 1035, 16-bit preference + domain name), SOA (RFC 1035, MNAME + RNAME domain names +
// SERIAL/REFRESH/RETRY/EXPIRE/MINIMUM, 32 bits each), TXT (RFC 1035, one or more length-prefixed
// character-strings), SRV (RFC 2782, 16-bit PRIORITY + WEIGHT + PORT + a domain name TARGET, not
// itself compressible per RFC 2782 but decoded with the same name-reader regardless -- a real
// implementation MUST NOT compress it when writing one, but nothing stops this decoder from
// reading one correctly if some encoder did anyway). Every other RDATA type this decoder sees
// (SIG/KEY/DNSKEY/RRSIG/NSEC/NSEC3/DS/NAPTR/SVCB/HTTPS/CERT/... and anything unrecognized) is
// named via the TYPE table below but its RDATA is shown as raw hex only, not value-decoded.
//
// Explicitly out of scope: DNS-over-TCP (RFC 1035 4.2.2's 2-byte length prefix + the cross-
// segment reassembly it implies) -- this decoder only ever looks at a single UDP datagram, the
// overwhelming majority of real-world DNS/mDNS/LLMNR traffic; a large (EDNS-exceeding or zone-
// transfer) response that falls back to TCP is not decoded, left for future work (see ROADMAP).
// DNS-over-HTTPS/TLS/QUIC (see doh.hpp's own scope note -- fundamentally not this file's problem,
// since the DNS message itself is TLS-encrypted on the wire and never directly visible here).
// EDNS0 option values inside an OPT record's RDATA (shown as hex only, see above). DNS Update
// (RFC 2136) and zone-transfer (AXFR/IXFR) semantics -- named via the OPCODE/TYPE tables, not
// otherwise interpreted.
//
// Detection: unlike almost every other protocol in this codebase, a DNS-family message has no
// magic number, no self-describing framing byte, nothing structurally unique at all -- every
// field in the 12-byte header is a plausible value under some legitimate traffic pattern, and the
// question/RR sections are just as unopinionated. Port-independent opportunistic detection (this
// codebase's usual "structural detection gate" posture -- see bacnet.hpp/hartip.hpp/ffhse.hpp)
// would therefore false-positive constantly on arbitrary UDP payloads that happen to look like 12
// bytes of header plus a few length-prefixed strings. decoder.cpp deliberately does NOT try
// try_parse_dns_message opportunistically the way it tries BACnet/HART-IP/FF-HSE -- it is gated
// on the packet actually arriving on the flavor's own UDP port (53/5353/5355, or a configured
// --dns-port/--mdns-port/--llmnr-port) in Auto mode, and skips that gate only when the user
// explicitly names the protocol (--protocol dns/mdns/llmnr). try_parse_dns_message itself still
// performs a real structural sanity check on top of that port match (declared QDCOUNT/ANCOUNT/
// NSCOUNT/ARCOUNT must not imply more bytes than the smallest possible encoding of that many
// questions/RRs could fit in the payload actually present, and -- LLMNR only -- the header's
// reserved Z bits are checked, not merely noted, since RFC 4795 says implementations MUST zero
// them) so a payload that merely arrived on the right port but is obviously not a DNS-shaped
// message is still rejected rather than mis-decoded.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint16_t DNS_PORT = 53;
constexpr uint16_t MDNS_PORT = 5353;
constexpr uint16_t LLMNR_PORT = 5355;

// Which of the three DNS-message-shaped protocols a given try_parse_dns_message call is for --
// see dns.hpp's file header comment for exactly which header bits/semantics differ between them.
enum class DnsFlavor { Dns, Mdns, Llmnr };

// One decoded question-section entry (RFC 1035 4.1.2).
struct DnsQuestionEntry {
    std::string name;  // dot-separated labels; the root name renders as "."
    uint16_t qtype = 0;
    std::string qtype_name;
    uint16_t qclass = 0;  // mDNS's QU top bit already stripped -- see unicast_response_requested
    std::string qclass_name;
    bool unicast_response_requested = false;  // mDNS's "QU" bit (RFC 6762 6.2) only; always false
                                                // for Dns/Llmnr flavors
    std::string summary;
};

// One decoded resource-record entry (RFC 1035 4.1.3) -- the identical wire shape is reused for
// the answer, authority, and additional sections alike.
struct DnsResourceRecordEntry {
    std::string name;
    uint16_t rtype = 0;
    std::string rtype_name;
    bool is_opt_pseudo_record = false;  // rtype == 41 (EDNS0 OPT, RFC 6891) -- class/ttl are
                                          // repurposed, see dns.hpp's file header comment
    uint16_t rclass = 0;   // mDNS's cache-flush top bit already stripped; when
                            // is_opt_pseudo_record this is instead the requestor's UDP payload
                            // size, not a class value at all -- rclass_name is empty in that case
    std::string rclass_name;
    bool cache_flush = false;  // mDNS's cache-flush bit (RFC 6762 10.2) only; always false for
                                 // Dns/Llmnr flavors and for an OPT pseudo-record
    uint32_t ttl = 0;  // when is_opt_pseudo_record: (extended_rcode<<24)|(version<<16)|flags, not
                         // a seconds value -- see opt_extended_rcode/opt_version/opt_dnssec_ok
    uint8_t opt_extended_rcode = 0;  // is_opt_pseudo_record only -- combines with the base 4-bit
                                       // RCODE in DnsMessage to form the real 12-bit extended RCODE
    uint8_t opt_version = 0;         // is_opt_pseudo_record only -- EDNS version, 0 in every
                                       // deployment this decoder is likely to see
    bool opt_dnssec_ok = false;      // is_opt_pseudo_record only -- the flags field's top "DO" bit
    uint16_t rdlength = 0;
    // Field-by-field decode of the "first pass" RDATA types (A/AAAA/NS/CNAME/PTR/MX/SOA/TXT/SRV)
    // -- one "field=value" entry per field, e.g. "address=93.184.216.34" or "priority=0 weight=100
    // port=389 target=dc01.example.com." -- mirrors bacnet_values'/ffhse_values' scheme. Empty
    // when rtype is outside this "first pass" set, or is_opt_pseudo_record.
    std::vector<std::string> values;
    bool rdata_decoded = false;
    std::string rdata_hex;  // always populated, decoded or not, for ground truth
    std::string summary;
};

struct DnsMessage {
    DnsFlavor flavor = DnsFlavor::Dns;
    uint16_t transaction_id = 0;
    bool is_response = false;  // QR bit
    uint8_t opcode = 0;
    std::string opcode_name;
    // Comma-separated set-flag names in wire order, e.g. "AA,RD" (Dns/Mdns) or "C,T" (Llmnr); "TC"
    // renders the same way under every flavor. Empty when no flags are set. Only meaningful
    // together with `flavor` -- the same bit position carries a different name (and, for
    // RD/RA-vs-T, a different meaning entirely) depending on it; see dns.hpp's file header
    // comment.
    std::string header_flags;
    bool reserved_bits_nonzero = false;  // the Z field (3 bits Dns/Mdns, 4 bits Llmnr) wasn't all
                                           // zero -- RFC-required to be zero; noted, not fatal,
                                           // except that try_parse_dns_message's own detection
                                           // gate treats a nonzero Llmnr Z as a rejection (see
                                           // dns.hpp's file header comment's "Detection" paragraph)
    uint8_t rcode = 0;
    std::string rcode_name;
    // As DECLARED in the header -- may exceed what's actually present/parseable in a truncated or
    // malformed message; see records_truncated.
    uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    std::vector<DnsQuestionEntry> questions;
    std::vector<DnsResourceRecordEntry> answers;
    std::vector<DnsResourceRecordEntry> authorities;
    std::vector<DnsResourceRecordEntry> additionals;
    bool records_truncated = false;  // stopped early -- declared counts implied more
                                       // questions/records than the payload actually had room for

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as one DNS-family message under the given flavor. Returns
// std::nullopt (never throws) when there aren't even 12 bytes for the header, when the header's
// OPCODE is outside the 0-5 range this decoder recognizes as plausible (RFC 1035's own table only
// defines 0-2; 3-5 are later-RFC values -- see dns.cpp's opcode table), when (Llmnr flavor only)
// the reserved Z bits aren't all zero, or when the declared QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT imply
// more bytes than the smallest possible encoding of that many entries could fit in the payload
// actually present -- see dns.hpp's file header comment's "Detection" paragraph for why this gate
// exists and how it's used (port-gated in Auto mode, port-independent only when the protocol is
// named explicitly).
std::optional<DnsMessage> try_parse_dns_message(ByteSpan udp_payload, DnsFlavor flavor);

}  // namespace conduitscope
