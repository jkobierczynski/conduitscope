// SPDX-License-Identifier: Apache-2.0
// igmp.hpp - IGMP (Internet Group Management Protocol) v1/v2 (RFC 1112/2236) and v3 (RFC 3376)
// decoding.
//
// IGMP has no transport-layer header of its own -- it rides directly on IP protocol number 2, so
// this decoder is handed the IP payload directly (there is no concept of an IGMP port). It is
// dispatched in decoder.cpp purely by that IP protocol number, same as VRRP (112); unlike RIP/HSRP
// there is no port-based Auto-mode gating to worry about here.
//
// Five message shapes are recognized by their Type byte, and (for Type 0x11, Membership Query)
// further disambiguated by length, since all three IGMP versions share the same Type value for a
// query:
//   0x11 Membership Query   -- exactly 8 bytes: IGMPv1 (Max Resp Code always 0) or IGMPv2 (Max
//                               Resp Code nonzero, plain integer, NOT the v3 floating encoding);
//                               12+ bytes: IGMPv3 Query, with the S/QRV byte, QQIC, and an
//                               optional source-address list.
//   0x12 Version 1 Membership Report -- 8 bytes, IGMPv1 only.
//   0x16 Version 2 Membership Report -- 8 bytes, IGMPv2 only.
//   0x17 Version 2 Leave Group       -- 8 bytes, IGMPv2 only.
//   0x22 Version 3 Membership Report -- IGMPv3 only, a list of per-group Group Records rather
//                                        than a single group address.
//
// IGMPv3's Max Resp Code (Query only) and QQIC fields use the same exponential "floating-point"
// encoding when their high bit is set (RFC 3376 section 4.1.1/4.1.7): value = (mantissa | 0x10)
// << (exponent + 3), where exponent is bits 6-4 and mantissa is bits 3-0 of the byte; a value
// below 128 (high bit clear) is used as-is. decode_max_resp_code (igmp.cpp) implements this once
// and is used for both fields.
//
// Cross-checked against Wireshark's own packet-igmp.c and RFC 1112/2236/3376 directly.
//
// Security context: IGMP has no authentication at all in any version -- any host on the local
// segment can claim group membership, and (more seriously) can send Membership Queries and
// impersonate a multicast router, which most hosts and switches (via IGMP snooping) will believe
// unquestioningly. Combined with GOOSE/SV's own routable multicast variants, unexpected IGMP
// traffic -- especially Queries from a host that isn't the segment's actual router -- is worth a
// second look.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

constexpr uint8_t IGMP_IP_PROTOCOL = 2;

struct IgmpGroupRecord {
    uint8_t record_type = 0;
    std::string record_type_name;  // "Mode Is Include" (1), "Mode Is Exclude" (2), "Change To
                                     // Include Mode" (3), "Change To Exclude Mode" (4), "Allow New
                                     // Sources" (5), "Block Old Sources" (6), or "Unknown (N)"
    uint8_t aux_data_len = 0;      // length of trailing auxiliary data, in 32-bit words
    std::string multicast_address;
    std::vector<std::string> source_addresses;  // capped at 50 entries
};

struct IgmpMessage {
    uint8_t type = 0;
    std::string type_name;  // "Membership Query", "Version 1 Membership Report", "Version 2
                              // Membership Report", "Version 2 Leave Group", "Version 3
                              // Membership Report", or "Unknown (0xNN)"
    int version = 0;         // 1, 2, or 3 -- 0 only if this couldn't be determined (never happens
                              // for a value try_parse_igmp actually returns)
    uint16_t checksum = 0;   // as seen on the wire; NOT verified against the payload

    // Query (type 0x11) and v1/v2 Report/Leave (0x12/0x16/0x17) share this field: the group being
    // queried/reported/left. For a v3 General Query this is 0.0.0.0.
    std::string group_address;

    // Query (0x11) only.
    uint32_t max_resp_time_ms = 0;  // decoded response time in milliseconds: always 0 for v1;
                                      // v2's Max Resp Code is a plain integer in tenths of a
                                      // second (*100 here); v3's Max Resp Code uses the
                                      // exponential encoding described in this file's header
                                      // comment (also *100 here for a common unit)
    // v3 Query (0x11 with 12+ bytes) only.
    bool suppress_router_side_processing = false;  // the S flag
    uint8_t querier_robustness_variable = 0;       // QRV; 0 means "use the querier's default"
    uint32_t querier_query_interval_sec = 0;       // decoded QQIC, in seconds
    std::vector<std::string> query_source_addresses;  // capped at 50 entries

    // v3 Report (0x22) only.
    std::vector<IgmpGroupRecord> group_records;  // capped at 50 entries
    bool group_records_truncated = false;  // true if more than 50 group records were declared

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `ip_payload` (the IP payload directly -- IGMP has no transport header) as
// an IGMP message. Returns std::nullopt (never throws) if the payload is shorter than 8 bytes, or
// its Type byte isn't one of the five values listed in this file's header comment -- IGMP's wire
// format otherwise gives no stronger structural signal than that, but dispatch in decoder.cpp
// only ever calls this for IP protocol number 2 in the first place, which is IANA-exclusive to
// IGMP (see igmp.hpp's own IGMP_IP_PROTOCOL), so no port-based Auto-mode gating is needed here.
std::optional<IgmpMessage> try_parse_igmp(ByteSpan ip_payload);

}  // namespace conduitscope
