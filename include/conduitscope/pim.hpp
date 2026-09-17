// SPDX-License-Identifier: Apache-2.0
// pim.hpp - PIM-SM/PIM-DM (Protocol Independent Multicast) v2 decoding (RFC 7761, RFC 3973).
//
// PIM has no transport-layer header of its own -- it rides directly on IP protocol number 103
// (IANA-exclusive), so dispatch in decoder.cpp is keyed purely on that protocol number, the same
// posture as IGMP/VRRP/EIGRP/OSPF (see PIM_IP_PROTOCOL below). Only PIMv2 is decoded; PIMv1 (a
// much older, IGMP-framed design Cisco deprecated long ago) uses an entirely different wire
// format this decoder does not recognize at all.
//
// Every PIMv2 message shares a 4-byte common header: Version(4 bits, always 2 for anything this
// decoder returns)/Type(4 bits) + a type-specific second byte (usually Reserved) + Checksum(2,
// NOT verified here). What follows depends on Type -- this decoder fully decodes the six message
// types actually seen in normal PIM-SM/PIM-DM operation:
//   0  Hello                    -- a TLV chain of Hello Options (see PimHelloOption)
//   1  Register                 -- a 4-byte flags word (Border/Null-Register bits) + an
//                                   encapsulated multicast data packet, whose own (source, group)
//                                   this decoder extracts but whose payload it does NOT decode
//                                   further (matches this codebase's general "don't recursively
//                                   decode a fully independent inner protocol" posture elsewhere)
//   2  Register-Stop            -- an Encoded-Group + an Encoded-Unicast address
//   3  Join/Prune                -- an upstream neighbor + a holdtime + a list of (group, joined
//   6  Graft (PIM-DM only)          sources, pruned sources) tuples; Graft and Graft-Ack share
//   7  Graft-Ack (PIM-DM only)      this exact same wire format with Join/Prune (RFC 3973)
//   4  Bootstrap                 -- fragment tag/hash mask length/BSR priority/BSR address,
//                                    followed by a list of (group, candidate-RP list) tuples
//   5  Assert                    -- a group + source + a metric (used to elect the forwarder on a
//                                    multi-access LAN)
//   8  Candidate-RP-Advertisement -- prefix count/priority/holdtime/RP address + a group list
// Five rarer message types (9 State-Refresh, 10 DF-Election, 11 ECMP-Redirect, 12 PFM, 13 Packed-
// Register) are recognized by their Type value and named in `type_name`, but their bodies are
// NOT decoded further -- the same "recognized but not decoded further" posture this codebase
// already takes for HSRPv2's non-Group-State TLVs and EIGRP's non-route TLVs.
//
// PIM's three "Encoded Address" formats (Unicast, Group, Source -- RFC 7761 section 4.9) all
// begin with an Address Family byte and an Encoding Type byte; this decoder only supports Address
// Family 1 (IPv4, matching this codebase's IPv4-only posture everywhere else) and Encoding Type 0
// (the plain "native" encoding). Encoding Type 1 (Native encoding with a trailing Join Attribute
// TLV chain, used only for a handful of BIDIR-PIM/MoFRR extensions) and Address Family 2 (IPv6)
// are both real, standards-defined possibilities this decoder does NOT support -- encountering
// either stops decoding at that point in the message (whatever was already decoded is still
// returned, with a note explaining why the rest is missing), rather than guessing at a length.
//
// Cross-checked against Wireshark's own packet-pim.c and RFC 7761/RFC 3973 directly.
//
// Security context: PIM has no authentication in the versions this decoder recognizes (later
// extensions add IPsec, essentially never deployed) -- any host on a PIM-enabled segment can send
// Join/Prune, Assert, or even Bootstrap/Candidate-RP-Advertisement messages and manipulate
// multicast forwarding state, including redirecting or blackholing multicast traffic. Because
// GOOSE/SV's own routable multicast variants and IGMP both already ride the same segments this
// decoder targets, unexpected PIM traffic -- especially Bootstrap/Candidate-RP-Advertisement
// messages from a host that isn't a legitimate RP/BSR -- is worth a second look.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t PIM_IP_PROTOCOL = 103;

struct PimHelloOption {
    uint16_t option_type = 0;
    std::string option_type_name;  // "Hold Time" (1), "LAN Prune Delay" (2), "DR Priority" (19),
                                     // "Generation ID" (20), "State Refresh Capable" (21),
                                     // "Address List" (24, or legacy 65001), or "Unknown (N)"
    std::string value;              // human-rendered value for the option types actually decoded
                                     // (Hold Time, LAN Prune Delay, DR Priority, Generation ID,
                                     // State Refresh Capable); empty for Address List (see
                                     // addresses below) and for any option type not in that list,
                                     // which is still recognized and counted but not decoded
                                     // further (raw length only)
    std::vector<std::string> addresses;  // Address List option (24/65001) only; capped at 50
};

struct PimJoinPruneGroup {
    std::string group;                   // "a.b.c.d/n"
    std::vector<std::string> joins;      // Encoded-Source addresses, capped at 50
    std::vector<std::string> prunes;     // Encoded-Source addresses, capped at 50
};

struct PimBsrGroupRps {
    std::string group;                       // "a.b.c.d/n"
    std::vector<std::string> candidate_rps;  // "a.b.c.d (holdtime=Ns, priority=P)", capped at 50
};

struct PimMessage {
    uint8_t version = 0;  // always 2 for any value this function returns
    uint8_t type = 0;
    std::string type_name;
    uint16_t checksum = 0;  // as seen on the wire; NOT verified against the payload

    // Hello (type 0) only.
    std::vector<PimHelloOption> hello_options;  // capped at 50
    bool hello_options_truncated = false;

    // Register (type 1) only.
    bool register_border_bit = false;
    bool register_null_register_bit = false;
    std::string register_inner_src_ip;   // the encapsulated packet's own source (its multicast
                                           // Source) -- empty if not decodable (see header comment)
    std::string register_inner_group_ip;  // the encapsulated packet's own destination (its
                                            // multicast Group)

    // Register-Stop (type 2) only.
    std::string register_stop_group;
    std::string register_stop_source;

    // Join/Prune, Graft, and Graft-Ack (types 3, 6, 7) only -- all three share this exact shape.
    std::string jp_upstream_neighbor;
    uint16_t jp_holdtime_sec = 0;
    std::vector<PimJoinPruneGroup> jp_groups;  // capped at 50
    bool jp_groups_truncated = false;

    // Bootstrap (type 4) only.
    uint16_t bsr_fragment_tag = 0;
    uint8_t bsr_hash_mask_len = 0;
    uint8_t bsr_priority = 0;
    std::string bsr_address;
    std::vector<PimBsrGroupRps> bsr_groups;  // capped at 50
    bool bsr_groups_truncated = false;

    // Assert (type 5) only.
    std::string assert_group;
    std::string assert_source;
    bool assert_rpt_bit = false;         // "this route is via the RPT, not the SPT"
    uint32_t assert_metric_preference = 0;
    uint32_t assert_metric = 0;

    // Candidate-RP-Advertisement (type 8) only.
    uint8_t crp_prefix_count = 0;
    uint8_t crp_priority = 0;
    uint16_t crp_holdtime_sec = 0;
    std::string crp_rp_address;
    std::vector<std::string> crp_groups;  // "a.b.c.d/n", capped at 50
    bool crp_groups_truncated = false;

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- PIM has no transport header) as
// a PIMv2 message. Returns std::nullopt (never throws) if the payload is shorter than the 4-byte
// common header, the Version nibble isn't 2, or the Type nibble is above 13 (the highest type
// RFC 7761/3973/5015/6754/8364/9465 collectively define at the time this was written). Dispatch
// in decoder.cpp only ever calls this for IP protocol number 103, which is IANA-exclusive to PIM,
// so no further port-style gating is applied.
std::optional<PimMessage> try_parse_pim(ByteSpan ip_payload);

}  // namespace conduitscope
