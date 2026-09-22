// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/rip.hpp"

#include "conduitscope/resource_limits.hpp"

#include <sstream>

#include "conduitscope/ipv4.hpp"

namespace conduitscope {

namespace {

constexpr size_t kRteSize = 20;
// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps
// the literal 50 default (matching the rest of the codebase).
const size_t kMaxRoutes = resource_limits().max_decoded_objects.value_or(50);

std::string command_name(uint8_t command) {
    switch (command) {
        case 1: return "Request";
        case 2: return "Response";
        case 3: return "Trace On";
        case 4: return "Trace Off";
        case 5: return "Reserved (used by Sun Microsystems' routed)";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(command)) + ")";
    }
}

std::string address_family_name(uint16_t afi) {
    switch (afi) {
        case 0: return "Request for full table";
        case 2: return "IP";
        case 0xFFFF: return "Authentication";
        default: return "Unknown (" + std::to_string(afi) + ")";
    }
}

std::string auth_type_name(uint16_t auth_type) {
    switch (auth_type) {
        case 2: return "Simple Password";
        case 3: return "Keyed Message Digest (MD5)";
        default: return "Unknown (" + std::to_string(auth_type) + ")";
    }
}

// Strips trailing NUL padding from a fixed-width cleartext field (RIPv2's 16-byte Simple
// Password is NUL-padded, not length-prefixed).
std::string strip_trailing_nul(ByteSpan span) {
    size_t len = span.size();
    while (len > 0 && span.at(len - 1) == 0) --len;
    std::string out;
    out.reserve(len);
    for (size_t i = 0; i < len; ++i) out.push_back(static_cast<char>(span.at(i)));
    return out;
}

// Decodes one 20-byte Route Table Entry. `rte` must be exactly 20 bytes -- callers only ever
// hand this complete RTEs (see try_parse_rip's own loop), so there's nothing left to bounds-check
// here beyond what Cursor already does.
RipRoute decode_route(ByteSpan rte, uint8_t version, std::vector<std::string>& message_notes) {
    RipRoute route;
    Cursor c(rte);
    route.address_family = c.u16be();
    route.address_family_name = address_family_name(route.address_family);

    if (route.address_family == 0xFFFF) {
        // Authentication entry (RIPv2 only, RFC 2453 section 4.2) -- not a route at all.
        route.is_auth_entry = true;
        route.auth_type = c.u16be();
        route.auth_type_name = auth_type_name(route.auth_type);
        if (route.auth_type == 2) {
            // Simple Password: the remaining 16 bytes are the cleartext password, NUL-padded.
            route.auth_password = strip_trailing_nul(c.rest());
            message_notes.push_back(
                "RIPv2 Simple Password authentication (auth_type 2) sends this password in "
                "cleartext on the wire -- see rip.hpp's own Security context note");
        } else if (route.auth_type == 3) {
            // Keyed MD5 (RFC 2082): RIP-2 Packet Length(2) + Key ID(1) + Auth Data Len(1) +
            // Sequence Number(4) + 8 bytes reserved (must be zero, not decoded further). The
            // actual MD5 digest is a SEPARATE block appended after the last real route RTE --
            // this decoder does not locate or verify it; see rip.hpp's file header comment.
            route.md5_packet_length = c.u16be();
            route.md5_key_id = c.u8();
            route.md5_auth_data_length = c.u8();
            route.md5_sequence_number = c.u32be();
            // 8 reserved bytes follow; not decoded.
        }
        // Unknown auth types: nothing further to decode -- the 16 type-specific bytes are left
        // unparsed, same conservative "don't guess" approach used elsewhere in this codebase.
        return route;
    }

    if (route.address_family == 0) {
        route.is_full_table_request = true;
    }

    route.route_tag = c.u16be();
    route.address = format_ipv4(c.u32be());
    route.subnet_mask = format_ipv4(c.u32be());
    route.next_hop = format_ipv4(c.u32be());
    route.metric = c.u32be();

    if (version == 1) {
        // RIPv1 requires Route Tag, Subnet Mask, and Next Hop to all be zero; RIPv2 gives them
        // meaning. Flag it (rather than silently ignoring it) when a supposed-v1 message doesn't
        // honor that -- it's either a mislabeled RIPv2 packet or a nonconformant sender.
        if (route.route_tag != 0 || route.subnet_mask != "0.0.0.0" || route.next_hop != "0.0.0.0") {
            message_notes.push_back(
                "route to " + route.address + " declares version 1 but has a nonzero Route "
                "Tag/Subnet Mask/Next Hop field (those are RIPv2-only) -- possible mislabeled "
                "RIPv2 traffic or a nonconformant sender");
        }
    }

    return route;
}

}  // namespace

std::optional<RipMessage> try_parse_rip(ByteSpan udp_payload) {
    if (udp_payload.size() < 4) {
        return std::nullopt;
    }

    Cursor c(udp_payload);
    uint8_t command = c.u8();
    if (command < 1 || command > 5) {
        return std::nullopt;
    }
    uint8_t version = c.u8();
    if (version != 1 && version != 2) {
        return std::nullopt;
    }
    uint16_t must_be_zero = c.u16be();  // RFC 1058 "must be zero" / RFC 2453 "Routing Domain".

    RipMessage msg;
    msg.command = command;
    msg.command_name = command_name(command);
    msg.version = version;

    if (version == 1 && must_be_zero != 0) {
        msg.notes.push_back("header's \"must be zero\" field is 0x" +
                             [&] {
                                 std::ostringstream out;
                                 out << std::hex << must_be_zero;
                                 return out.str();
                             }() +
                             ", not zero, in a version-1 message");
    }

    size_t total_remaining = c.remaining();
    size_t full_rte_count = total_remaining / kRteSize;
    size_t leftover_bytes = total_remaining % kRteSize;

    size_t decoded_count = full_rte_count < kMaxRoutes ? full_rte_count : kMaxRoutes;
    msg.routes.reserve(decoded_count);
    for (size_t i = 0; i < decoded_count; ++i) {
        ByteSpan rte = c.bytes(kRteSize);
        msg.routes.push_back(decode_route(rte, version, msg.notes));
    }

    if (full_rte_count > kMaxRoutes) {
        msg.routes_truncated = true;
        msg.notes.push_back("output capped at " + std::to_string(kMaxRoutes) +
                             " route table entries; " +
                             std::to_string(full_rte_count - kMaxRoutes) +
                             " more were present in this packet and were not decoded");
    }
    if (leftover_bytes > 0) {
        msg.notes.push_back(std::to_string(leftover_bytes) +
                             " trailing byte(s) after the last complete route table entry do not "
                             "form a full 20-byte RTE -- possible truncation");
    }

    std::ostringstream out;
    out << "RIPv" << static_cast<unsigned>(version) << " " << msg.command_name;
    if (msg.routes.size() == 1 && msg.routes[0].is_full_table_request) {
        out << ": full routing table requested";
    } else {
        out << ": " << msg.routes.size() << " route(s)";
        size_t auth_entries = 0;
        for (const auto& r : msg.routes) {
            if (r.is_auth_entry) ++auth_entries;
        }
        if (auth_entries > 0) {
            out << " (" << auth_entries << " authentication entry/entries)";
        }
    }
    msg.summary = out.str();

    return msg;
}

}  // namespace conduitscope
