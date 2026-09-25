// SPDX-License-Identifier: Apache-2.0
// ipv6_attack_detect.hpp - curated SLAAC/rogue-Router-Advertisement and DHCPv6 (spoofing,
// exhaustion, misconfiguration) detection notes, built on top of icmpv6.hpp/dhcpv6.hpp.
//
// This is roadmap item 45's own curated-notes layer (docs/DEVELOPMENT.md) -- the IPv6-SPECIFIC
// sibling of attack_detect.hpp, NOT an extension of it. Read attack_detect.hpp's own file header
// and class in full before this one: it states outright that it is IPv4-only by design and that
// decoder.cpp's IPv6 branch never calls into it -- THAT STAYS TRUE. This file is a brand-new,
// separately-owned module (AttackDetectionState there, Ipv6AttackDetectionState here -- two
// distinct classes, two distinct Decoder members, see decoder.hpp's own ipv6_attack_state_), wired
// into decoder.cpp's IPv6-reachable ICMPv6/DHCPv6 call sites only, exactly mirroring how
// attack_state_.observe_icmp(...) is called right after ICMP(v4)'s own successful decode.
//
// WHY A NEW MODULE RATHER THAN EXTENDING attack_detect.hpp: SLAAC/RA and DHCPv6 have no IPv4
// equivalent at all (IPv4 has no router/address-autoconfiguration-advertisement mechanism
// analogous to Router Advertisement, and DHCP/DHCPv6 are different enough on the wire that they
// already have entirely separate decoders -- dhcp is name-only in it_protocols.hpp, DHCPv6 has its
// own real decoder, dhcpv6.hpp) -- there is no shared signature list to extend, unlike, say,
// Smurf/Fraggle, which are genuinely the same idea over two different protocols. See
// docs/DEVELOPMENT.md's own roadmap item 45 entry for the full "why a new module" record.
//
// ============================================================================================
// HONESTY ABOUT WHAT THIS CAN AND CANNOT DETERMINE -- read this before reading any note text
// this file emits.
// ============================================================================================
//
// Rogue-vs-legitimate router/server is NOT something passive packet observation can answer with
// certainty, and this file never claims otherwise. RFC 6104 ("Rogue IPv6 Router Advertisement
// Problem Statement") states this explicitly -- its own section 5.4 recommends monitoring tools
// "observe and report" rather than attribute, citing NDPMon as prior art for exactly that
// "flag for human review" posture, not an automated verdict. Every note this file emits about a
// router-identity or DHCPv6-server-identity conflict is worded as "worth investigating" / "observed
// co-occurrence", mirroring the exact honest-limitation tone this codebase already established for
// DRSUAPI's own DCSync note (grep "cannot independently confirm" in smb.cpp/drsuapi.hpp) -- this
// tool cannot independently confirm which (if either) side of a conflict is the attacker, and never
// says "attacker detected" or equivalent anywhere in its own note text, comments, or docs. A real
// deployment can have more than one legitimate router (HSRP/VRRP-style redundancy, though IPv6
// itself doesn't strictly need it the way IPv4 does) or more than one legitimate DHCPv6 server (an
// HA pair) -- both are structurally indistinguishable from a rogue one using only what a passive
// capture shows, which is exactly why every note below stops at "here is a structural conflict",
// never "here is an attack".
//
// ============================================================================================
// FOUR SIGNATURES, EACH GROUNDED IN A REAL PUBLICLY-DOCUMENTED TOOL/TECHNIQUE:
// ============================================================================================
//
// 1) RA IDENTITY COLLISION (thc-ipv6's `fake_router6`, the rogue-RA half of RFC 6104's own
//    problem statement). An "RA-advertising identity" is (source IPv6 address, and -- when present
//    -- the Source Link-Layer Address option's own MAC). Two identities CONFLICT when: both have
//    Router Lifetime > 0 (both claiming default-router status) AND (they differ in advertised
//    Prefix Information prefixes, OR differ in M/O flags, OR differ in Router Lifetime value).
//    Deliberately simple and structural, per this feature's own design brief -- not a
//    sophisticated anomaly model. Fires once per capture (the first conflicting pair found), not
//    once per repeated RA -- a rogue router broadcasting its RA every few seconds would otherwise
//    flood this file's own notes with the same finding restated dozens of times.
//
// 2) RA FLOOD (thc-ipv6's `flood_router6`: many RAs in rapid succession with randomized field
//    values). UNLIKE attack_detect.hpp's own per-destination flood counters, an RA flood's real
//    "target" is the WHOLE LINK, not one host -- RAs go to the all-nodes multicast address
//    ff02::1, so per-destination counting doesn't fit this signature at all. This counts TOTAL RA
//    messages observed in the capture (whole-file, no time dimension -- reusing exactly the same
//    "coarser than a real per-second rate, but fits this codebase's single-pass decode model"
//    tradeoff attack_detect.hpp's own file header already documents and justifies for its IPv4
//    flood counters) and flags once DEFAULT_FLOOD_THRESHOLD (attack_detect.hpp, shared rather than
//    inventing a second threshold concept -- see --flood-threshold) is crossed.
//
// 3) NS/NA SPOOFING (thc-ipv6's `parasite6`/`fake_advertise6`, and the DAD-DoS tool
//    `dos-new-ip6`). The IPv6 analogue of classic ARP spoofing: multiple DISTINCT source
//    link-layer addresses (from the Target/Source Link-Layer Address option) sending Neighbor
//    Advertisements that claim the SAME Target Address. Tracked by Target Address; flags once 2+
//    distinct advertising link-layer addresses are seen for the same target within the capture.
//    This is a genuinely more structural signal than a raw NA-count-per-target threshold would be
//    (a busy, perfectly legitimate target can answer many NS with many NAs from the SAME MAC with
//    no anomaly at all) -- so, deliberately, no separate raw-volume NA/NS counter is kept; the
//    identity-conflict signal alone is the more honest one.
//
// 4) DHCPv6 EXHAUSTION (thc-ipv6's `flood_dhcpc6`; corroborated by a 2024 IEEE paper on
//    DHCPv6-starvation-via-DUID-spoofing). The real signature is many DISTINCT Client DUIDs
//    sending SOLICIT/REQUEST in one capture -- a raw packet count alone would misclassify one
//    legitimate client retrying (the same DUID, resending) as exhaustion. Tracks distinct Client
//    DUID VALUES seen in SOLICIT/REQUEST messages (whole-file, the same volumetric-counting
//    simplification item 43's own flood counters already established, but counting distinct
//    identities rather than raw packets, since identity-diversity -- not volume -- is what
//    actually signals exhaustion here). Flags once the DISTINCT-DUID count crosses
//    DEFAULT_FLOOD_THRESHOLD.
//
// 5) ROGUE/MULTIPLE DHCPv6 SERVERS (thc-ipv6's `fake_dhcps6`; MITRE ATT&CK T1557.003's own
//    detection analytic names "multiple competing DHCP OFFER/ACK messages... from non-authorized
//    servers" as its detection heuristic for DHCP spoofing generally). Tracks distinct Server DUID
//    values seen in ADVERTISE/REPLY messages; flags once 2+ distinct server identities are
//    observed. Same honest "worth investigating, not confirmed rogue" framing as (1) above -- an
//    HA pair of legitimate DHCPv6 servers is a real, common, non-malicious cause of this same
//    structural shape.
//
// ============================================================================================
// EXPLICITLY OUT OF SCOPE (documented limitations, the same "honest, not an oversight" posture
// attack_detect.hpp's own file header already establishes for its IPv4 signatures):
// ============================================================================================
//  - DHCPv6's RELAY-FORW/RELAY-REPL inner messages are NOT decoded through (see dhcpv6.hpp's own
//    OUT OF SCOPE section) -- exhaustion/rogue-server counting here ONLY ever sees NON-RELAYED
//    client/server traffic. A capture where every client sits behind a relay agent will
//    under-count (or entirely miss) both signatures. This is a documented scope line, not silently
//    wrong.
//  - No SEND (RFC 3971) awareness -- a cryptographically-signed, entirely legitimate multi-router
//    deployment using SEND would still structurally "conflict" under signature (1) above exactly
//    like an unsigned rogue one would; this file has no notion of RA authentication at all.
//  - No real per-second rate limiting/timestamps anywhere in this file -- whole-file counting only,
//    the same explicitly-chosen simplification attack_detect.hpp's own file header documents for
//    its own flood counters (see signature 2/4 above).
//  - No attempt to correlate DHCPv6 REQUEST/CONFIRM/RENEW/REBIND against an actual completed
//    SOLICIT/ADVERTISE exchange, or NS against a genuine prior ARP/NDP cache miss -- every check
//    here is purely structural/volumetric, the same posture every other curated note in this
//    codebase already has.
#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "conduitscope/attack_detect.hpp"  // DEFAULT_FLOOD_THRESHOLD -- shared, not reinvented; see
                                            // this file's own signature (2)/(4) comments above
#include "conduitscope/dhcpv6.hpp"
#include "conduitscope/icmpv6.hpp"

// Deliberately does NOT include decoder.hpp -- same circular-include avoidance
// attack_detect.hpp's own file header already documents (Decoder holds an
// Ipv6AttackDetectionState member, so including decoder.hpp back here would be circular).

namespace conduitscope {

// One RA's worth of the fields signature (1) above compares between identities.
struct RaObservedFields {
    uint16_t router_lifetime_sec = 0;
    bool managed_flag = false;
    bool other_flag = false;
    std::vector<std::string> prefixes;  // "address/prefix-length" strings, from every Prefix
                                          // Information option this RA carried, in the order seen
};

// Owned directly by Decoder (see decoder.hpp's Decoder::ipv6_attack_state_), the IPv6-specific
// sibling of AttackDetectionState (attack_detect.hpp) -- NOT a DecoderFlowState, for the identical
// reason attack_detect.hpp's own class comment gives: this state needs to see every ICMPv6/DHCPv6
// packet regardless of which TCP/UDP session (DHCPv6 has none -- UDP is sessionless here) or
// protocol id claims it, keyed by IP/NDP/DHCPv6 identity rather than one flow. Every map below is
// bounded (kMaxTrackedEntries) with the same "evict some existing entry, not necessarily the
// oldest" tradeoff DecodeContext::flow_state<T>()'s own eviction logic documents (protocol_
// decoder.hpp) -- see attack_detect.hpp's own AttackDetectionState::evict_if_full for the identical
// reasoning, mirrored here rather than shared (this class has no other dependency on that one).
class Ipv6AttackDetectionState {
public:
    // Configured from DecodeOptions::flood_threshold once, by Decoder's constructor -- the SAME
    // shared threshold attack_detect.hpp's own AttackDetectionState::flood_threshold uses, not a
    // second, IPv6-specific concept (see this file's own header comment on signatures (2)/(4)).
    size_t flood_threshold = DEFAULT_FLOOD_THRESHOLD;

    // Called right after a successful ICMPv6 decode (icmpv6.hpp). Handles RA identity collision
    // (1), the RA flood counter (2), and NS/NA spoofing (3). `src_ip` is the packet's own outer
    // IPv6 source address (format_ipv6), used both as half of an RA identity's key and, for a
    // Neighbor Advertisement with no Target Link-Layer Address option of its own, as a fallback
    // "who sent this" identity (see ipv6_attack_detect.cpp's own comment on that fallback).
    void observe_icmpv6(const Icmpv6Message& msg, const std::string& src_ip,
                         std::vector<std::string>& notes);

    // Called right after a successful DHCPv6 decode (dhcpv6.hpp). Handles the DHCPv6 exhaustion
    // counter (4, distinct Client DUIDs in SOLICIT/REQUEST) and rogue/multiple-server detection
    // (5, distinct Server DUIDs in ADVERTISE/REPLY). A no-op for a relayed message's own
    // RELAY-FORW/RELAY-REPL header (dhcpv6.hpp does not decode through to the inner message -- see
    // this file's own OUT OF SCOPE section) since Dhcpv6Message::client_duid_key/server_duid_key
    // are only ever populated for a non-relay message in the first place.
    void observe_dhcpv6(const Dhcpv6Message& msg, std::vector<std::string>& notes);

private:
    static constexpr size_t kMaxTrackedEntries = 4096;

    // Signature (1): keyed by "src_ip" or "src_ip|slla_mac_hex" (see ipv6_attack_detect.cpp's own
    // ra_identity_key). Value is the most recently observed RA fields for that identity.
    std::unordered_map<std::string, RaObservedFields> ra_identities_;
    bool ra_collision_flagged_ = false;  // fires once per capture, not once per repeated RA -- see
                                          // this file's own header comment on signature (1)

    // Signature (2): total RA messages seen, whole-file (no per-destination keying -- an RA
    // targets the whole link, see this file's own header comment).
    size_t ra_count_ = 0;
    bool ra_flood_flagged_ = false;

    // Signature (3): keyed by Target Address (format_ipv6); value is every distinct advertising
    // link-layer address (hex string) seen claiming that target.
    std::unordered_map<std::string, std::vector<std::string>> na_target_link_layer_addresses_;
    std::unordered_map<std::string, bool> na_spoof_flagged_;  // per-target, so a second, third,
                                                                // ... conflicting NA for the SAME
                                                                // target doesn't re-flag, but a
                                                                // conflict on a DIFFERENT target
                                                                // still gets its own note

    // Signature (4): distinct Client DUID raw-byte values seen in SOLICIT/REQUEST.
    std::unordered_set<std::string> dhcpv6_client_duids_seen_;
    bool dhcpv6_exhaustion_flagged_ = false;

    // Signature (5): distinct Server DUID raw-byte values seen in ADVERTISE/REPLY.
    std::unordered_set<std::string> dhcpv6_server_duids_seen_;
    bool dhcpv6_rogue_server_flagged_ = false;
};

}  // namespace conduitscope
