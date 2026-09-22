// SPDX-License-Identifier: Apache-2.0
// nbns.hpp - NetBIOS Name Service (NBNS, RFC 1002 section 4.2 -- almost universally called
// "NBT-NS" in practice, since it is the Name Service part of "NetBIOS over TCP/IP"/NBT) decoding.
// UDP port 137. A legacy (pre-DNS, pre-Active-Directory) Windows name-resolution protocol that
// still runs, unauthenticated and unencrypted, on essentially every Windows host with NetBIOS
// over TCP/IP enabled (the default) -- security-relevant for OT engineering workstations for the
// same reason LLMNR is (see llmnr's own detection wiring in decoder.cpp): both are classic
// unauthenticated broadcast/multicast name-resolution poisoning targets (the "Responder" tool's
// two primary protocols), and an NBSTAT response in particular hands a passive listener a
// device's real NetBIOS hostname and MAC address for free.
//
// Sourcing: cross-checked field-by-field against RFC 1002 section 4.2 (NAME_SERVICE packets) --
// 4.2.1.1 (header), 4.2.1.2 (question), 4.2.1.3 (NB resource record / NB_FLAGS), 4.2.6/4.2.14
// (RCODE tables), 4.2.18 (NBSTAT resource record / NAME_FLAGS / STATISTICS). The per-suffix-byte
// service-name table (below) is NOT part of RFC 1002 at all -- RFC 1002 only defines the 16-byte
// NetBIOS name as an opaque, locally-scoped identifier -- it is Microsoft's own convention
// (documented in Microsoft's NetBIOS Suffixes KB and reproduced by every packet analyzer,
// including Wireshark's packet-nbns.c own netbios_names[] table), included here because it is the
// single highest-value piece of information an NBT-NS capture offers for OT asset inventory (a
// suffix of 0x20 means "this is the File Server Service name," 0x1B means "this is a Domain
// Master Browser/PDC," etc.) despite not being part of the wire protocol's own specification.
//
// ---------------------------------------------------------------------------------------------
// Header (12 bytes, RFC 1002 4.2.1.1): NAME_TRN_ID(2), then a second 16-bit word: R(1) OPCODE(4)
// NM_FLAGS(7) RCODE(4). NM_FLAGS is itself AA(1) TC(1) RD(1) RA(1) reserved(2) B(1) (Broadcast),
// then QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT, 16 bits each -- the same overall 12-byte shape as DNS
// (see dns.hpp), but the flags/opcode subdivision is NBT-NS's own. OPCODE: 0=query,
// 5=registration, 6=release, 7=WACK (Wait for Acknowledgement), 8=refresh (RFC 1002 4.2.1.1);
// other values are named "reserved(N)" only. RCODE (RFC 1002 4.2.6/4.2.14): 0=success,
// 1=FMT_ERR, 2=SRV_ERR, 3=NAM_ERR, 4=IMP_ERR, 5=RFS_ERR, 6=ACT_ERR, 7=CFT_ERR.
//
// NetBIOS "compressed name" encoding (RFC 1002 4.1, "first-level encoding"): every NBT-NS NAME
// field (question and resource-record alike) is a 1-byte length (always 0x20/32 for a
// well-formed encoded name -- this decoder's own detection gate, see below), followed by 32
// encoded bytes, followed by zero or more further length-prefixed labels for an optional
// NetBIOS "scope ID" (almost always absent in real deployments -- a bare zero-length/0x00 label
// immediately follows in that case), terminated the same way an ordinary DNS name is (RFC 1002
// explicitly permits DNS-style compression pointers here too, per 4.1's own reference to RFC
// 883; this decoder does NOT follow a pointer inside a scope ID -- see "Explicitly out of scope"
// below). The 32 encoded bytes decode back to the original 16 raw bytes by splitting each
// encoded byte pair's two nibbles and reversing 'A'+nibble (RFC 1002 4.1's own worked "FRED "
// example): the first 15 decoded bytes are the name itself (space-padded, trailing spaces
// trimmed here for readability), and the 16th is the "suffix" byte -- see kNetbiosSuffixName
// in nbns.cpp for the Microsoft/Wireshark-convention table of what common suffix values mean.
//
// Question section (RFC 1002 4.2.1.2): NAME (above) + QUESTION_TYPE(2) [0x0020 NB, 0x0021
// NBSTAT] + QUESTION_CLASS(2) [always 0x0001, IN].
//
// Resource record: NAME + RR_TYPE(2) + RR_CLASS(2) + TTL(4) + RDLENGTH(2) + RDATA(RDLENGTH), the
// same outer shape as DNS, but RDATA's own meaning depends entirely on RR_TYPE:
//   NB (0x0020, RFC 1002 4.2.1.3): RDATA is one or more 6-byte entries, each NB_FLAGS(2) +
//     NB_ADDRESS(4, an IPv4 address) -- NB_FLAGS is G(1, Group-name flag) + ONT(2, Owner Node
//     Type: 0=B-node,1=P-node,2=M-node,3=reserved) + reserved(13). Real deployments occasionally
//     return more than one address for a genuinely multi-homed or group name; this decoder
//     decodes every entry RDLENGTH/6 implies.
//   NBSTAT (0x0021, RFC 1002 4.2.18): RDATA is NUM_NAMES(1), then NUM_NAMES entries of
//     NETBIOS_NAME(16 RAW bytes -- NOT first-level-encoded here, unlike the outer NAME field) +
//     NAME_FLAGS(2) [G(1) ONT(2) DRG(1,Deregister) CNF(1,Conflict) ACT(1,Active) PRM(1,Permanent)
//     reserved(9)], then a 46-byte STATISTICS structure whose first 6 bytes are UNIT_ID (the
//     responding node's own MAC address -- the single highest-value field an NBSTAT response
//     carries for passive asset inventory) followed by JUMPERS/TEST_RESULT/VERSION_NUMBER/traffic
//     counters this decoder does not further break out (shown as raw hex) -- see "first pass"
//     scoping note below.
//   Anything else: named via a small type table, RDATA shown as raw hex only.
//
// "First pass" scoping (mirrors this codebase's existing precedent -- BACnet's service scoping,
// DNS's own RDATA type list): NB and NBSTAT are decoded because they are, respectively, the
// ordinary unicast-response-to-a-name-query shape and the device/hostname/MAC-fingerprinting
// shape -- together the overwhelming majority of real NBT-NS response traffic. NBSTAT's
// STATISTICS traffic-counter fields beyond UNIT_ID are shown as raw hex rather than individually
// broken out (see the 46-byte layout above) -- none of them are security- or inventory-relevant
// the way UNIT_ID/hostnames are, and RFC 1002 itself notes several are implementation-defined.
//
// Explicitly out of scope: the NAME_SERVICE opcodes 5/6/7/8 (registration/release/WACK/refresh)
// request bodies beyond the header + question they already share with a query (this decoder
// still decodes those, since they use the exact same question/RR shapes -- what's out of scope
// is any opcode-specific semantic validation, e.g. checking a registration's OWNER_NAME/TTL
// pairing rules); a compression pointer appearing inside a NetBIOS scope ID (named/shown as "not
// decoded" rather than followed -- scope IDs are vanishingly rare in modern captures, and RFC
// 1002 permits but does not require an encoder to ever produce one there); SESSION SERVICE (TCP
// port 139) and DATAGRAM SERVICE (UDP port 138), RFC 1002's other two NetBIOS-over-TCP/IP
// services -- entirely different packet formats, carrying SMB traffic rather than name
// resolution, not attempted here at all.
//
// Detection: the exact same "no magic number, no self-describing framing" problem as DNS (see
// dns.hpp's file header comment's "Detection" paragraph) applies here too, so this decoder uses
// the identical posture -- port-gated in Auto mode (UDP port 137, or a configured --nbns-port),
// port-independent only when --protocol nbns is named explicitly -- plus its own structural
// sanity check on top: the outer NAME field's length byte must be exactly 0x20 (a first-level-
// encoded NetBIOS name is ALWAYS exactly 32 bytes -- unlike a DNS label, which can legitimately
// be anywhere from 1 to 63 bytes, this is a single fixed value, a meaningfully stronger gate than
// DNS's own "plausible byte-count" check), and every byte of those 32 must be in the 'A'-'P'
// range the encoding produces (RFC 1002 4.1 -- any other byte value there is definitionally not
// a first-level-encoded name).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t NBNS_PORT = 137;

// One decoded NB_ADDRESS entry (RFC 1002 4.2.1.3) -- an RR_TYPE==NB record's RDATA is one or
// more of these back to back.
struct NbnsAddressEntry {
    bool is_group_name = false;   // NB_FLAGS' G bit
    uint8_t owner_node_type = 0;  // NB_FLAGS' ONT field: 0=B-node,1=P-node,2=M-node,3=reserved
    std::string owner_node_type_name;
    std::string address;  // dotted-decimal IPv4
};

// One decoded NBSTAT node-name-table entry (RFC 1002 4.2.18).
struct NbnsNodeName {
    std::string name;    // the 15-character name portion, trailing spaces trimmed
    uint8_t suffix = 0;   // the 16th byte -- see kNetbiosSuffixName in nbns.cpp
    std::string suffix_name;
    bool is_group_name = false;
    uint8_t owner_node_type = 0;
    std::string owner_node_type_name;
    bool deregister = false;
    bool conflict = false;
    bool active = false;
    bool permanent = false;
};

// One decoded question-section entry.
struct NbnsQuestionEntry {
    std::string name;       // 15-char decoded name, trailing spaces trimmed
    uint8_t suffix = 0;
    std::string suffix_name;
    uint16_t qtype = 0;      // 0x0020 NB, 0x0021 NBSTAT
    std::string qtype_name;
    uint16_t qclass = 0;     // always 1 (IN) in every capture this decoder is likely to see
    std::string summary;
};

// One decoded resource-record entry.
struct NbnsResourceRecordEntry {
    std::string name;
    uint8_t suffix = 0;
    std::string suffix_name;
    uint16_t rtype = 0;
    std::string rtype_name;
    uint16_t rclass = 0;
    uint32_t ttl = 0;

    // RR_TYPE == NB (0x0020) only.
    std::vector<NbnsAddressEntry> addresses;

    // RR_TYPE == NBSTAT (0x0021) only.
    std::vector<NbnsNodeName> node_names;
    bool has_unit_id = false;
    std::string unit_id_mac;         // the responding node's own MAC address, colon-hex
    std::string statistics_tail_hex; // everything in STATISTICS after UNIT_ID, raw hex

    // Neither NB nor NBSTAT: raw hex only.
    std::string rdata_hex;

    std::string summary;
};

struct NbnsMessage {
    uint16_t transaction_id = 0;
    bool is_response = false;  // R bit
    uint8_t opcode = 0;
    std::string opcode_name;
    std::string flags;  // comma-separated set-flag names, e.g. "AA,RD,B" -- wire order AA,TC,RD,RA,B
    uint8_t rcode = 0;
    std::string rcode_name;
    uint16_t qdcount = 0, ancount = 0, nscount = 0, arcount = 0;
    std::vector<NbnsQuestionEntry> questions;
    std::vector<NbnsResourceRecordEntry> answers;
    std::vector<NbnsResourceRecordEntry> authorities;
    std::vector<NbnsResourceRecordEntry> additionals;
    bool records_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `udp_payload` as one NBT-NS NAME_SERVICE message. Returns std::nullopt
// (never throws) when there aren't even 12 bytes for the header, when the outer NAME field's
// first-level-encoding length byte isn't exactly 0x20 or its 32 bytes aren't all in the 'A'-'P'
// range the encoding produces, or when the declared QDCOUNT/ANCOUNT/NSCOUNT/ARCOUNT imply more
// bytes than the payload actually has room for -- see nbns.hpp's file header comment's
// "Detection" paragraph.
std::optional<NbnsMessage> try_parse_nbns(ByteSpan udp_payload);

// registration-model migration (batch 4 -- see protocol_decoder.hpp/protocol_registry.hpp): thin
// ProtocolDecoder wrapper around try_parse_nbns above, unchanged. GateKind::UdpPort's second real
// user (after DNS/mDNS/LLMNR -- see dns.hpp's own comment). No cross-packet state, so this needs
// nothing beyond id()/gate_kind()/udp_port()/decode(); see nbns.cpp. Auto mode's own port-gating
// policy stays at decoder.cpp's own call site, unchanged by migration -- see udp_port()'s own
// comment in protocol_decoder.hpp for why.
class NbnsDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "nbns"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return NBNS_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& nbns_decoder();

}  // namespace conduitscope
