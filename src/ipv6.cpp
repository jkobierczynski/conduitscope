// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ipv6.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/tunnel_vpn.hpp"  // ESP_IP_PROTOCOL, AH_IP_PROTOCOL -- shared IANA protocol
                                        // numbers, not IPv4-specific despite that file's name; see
                                        // this file's own header comment on why AH is walked past
                                        // and ESP is not.

namespace conduitscope {

namespace {
constexpr uint8_t kHopByHop = 0;
constexpr uint8_t kRouting = 43;
constexpr uint8_t kFragment = 44;
constexpr uint8_t kDestinationOptions = 60;

// Defensive cap on how many extension headers one parse_ipv6 call will walk through. Each one
// consumes at least 8 real captured bytes forward (the smallest valid length any of Hop-by-Hop/
// Routing/Destination-Options/Fragment/AH can declare), so the walk is already bounded by the
// packet's own captured size -- this is not the unbounded-growth shape finding 1
// (docs/reviews/2026-09-chatgpt-security-review-patch160.md) closed elsewhere in this codebase.
// The cap exists purely so a pathological chain of many minimum-size extension headers fails with
// one clear ParseError instead of silently walking dozens of headers deep for no real protocol
// reason; no real IPv6 stack sends anywhere near this many.
constexpr int kMaxExtensionHeaders = 16;
}  // namespace

Ipv6Header parse_ipv6(ByteSpan packet) {
    Cursor c(packet);
    Ipv6Header hdr;

    uint8_t version_and_tc_hi = c.u8();
    hdr.version = static_cast<uint8_t>(version_and_tc_hi >> 4);
    if (hdr.version != 6) {
        throw ParseError("not an IPv6 packet (version field = " + std::to_string(hdr.version) + ")");
    }
    c.u8();     // low nibble of Traffic Class + high nibble of Flow Label -- not needed for
                // protocol decoding
    c.u16be();  // rest of Flow Label
    uint16_t payload_length = c.u16be();
    uint8_t next_header = c.u8();
    hdr.hop_limit = c.u8();

    ByteSpan src_bytes = c.bytes(16);
    ByteSpan dst_bytes = c.bytes(16);
    std::copy(src_bytes.data(), src_bytes.data() + 16, hdr.src_addr.begin());
    std::copy(dst_bytes.data(), dst_bytes.data() + 16, hdr.dst_addr.begin());

    size_t base_header_bytes = c.position();  // always 40 by construction (4+2+2+1+1+16+16)

    // Walk the RFC 8200 extension-header chain far enough to reach the real upper-layer protocol
    // -- see this file's own header comment for exactly which header types are walked past
    // (Hop-by-Hop/Routing/Destination Options, all sharing one generic 8-byte-unit length format;
    // AH, which has its own different 4-byte-unit length format but -- unlike ESP -- doesn't
    // encrypt, so walking past it is both possible and worthwhile) versus stopped at (Fragment,
    // skipped structurally but not reassembled; ESP, deliberately never walked past at all since
    // its payload is encrypted -- it simply becomes this parse's own final next_header, the same
    // as if it had arrived as an IPv4 packet's own top-level protocol number).
    int extension_headers_seen = 0;
    while (true) {
        if (next_header == kHopByHop || next_header == kRouting || next_header == kDestinationOptions) {
            if (++extension_headers_seen > kMaxExtensionHeaders) {
                throw ParseError("IPv6 extension header chain exceeds " +
                                  std::to_string(kMaxExtensionHeaders) + " headers; refusing to walk further");
            }
            uint8_t inner_next = c.u8();
            uint8_t hdr_ext_len = c.u8();
            // RFC 8200 S4.3/4.4/4.6: total header length in bytes is (Hdr Ext Len + 1) * 8; the
            // two fields just read account for the first 2 of those bytes.
            size_t remaining_this_header = (static_cast<size_t>(hdr_ext_len) + 1) * 8 - 2;
            c.skip(remaining_this_header);
            next_header = inner_next;
            continue;
        }
        if (next_header == AH_IP_PROTOCOL) {
            if (++extension_headers_seen > kMaxExtensionHeaders) {
                throw ParseError("IPv6 extension header chain exceeds " +
                                  std::to_string(kMaxExtensionHeaders) + " headers; refusing to walk further");
            }
            uint8_t inner_next = c.u8();
            uint8_t payload_len_words = c.u8();
            // RFC 4302 S2.2: AH's own "Payload Len" is the header's total length in 32-bit words,
            // MINUS 2 -- a different unit AND a different offset convention from the generic
            // Hop-by-Hop/Routing/Destination-Options length field above; total header length in
            // bytes is (Payload Len + 2) * 4. The two fields just read account for the first 2 of
            // those bytes.
            size_t remaining_this_header = (static_cast<size_t>(payload_len_words) + 2) * 4 - 2;
            c.skip(remaining_this_header);
            next_header = inner_next;
            continue;
        }
        if (next_header == kFragment) {
            if (++extension_headers_seen > kMaxExtensionHeaders) {
                throw ParseError("IPv6 extension header chain exceeds " +
                                  std::to_string(kMaxExtensionHeaders) + " headers; refusing to walk further");
            }
            uint8_t inner_next = c.u8();
            // Fixed 8 bytes total, no length field of its own: Next Header(1, just read) +
            // Reserved(1) + Fragment Offset/flags(2) + Identification(4) = 8. See this file's own
            // header comment on why a non-first fragment's bytes past here are not reassembled --
            // the same documented limitation ipv4.hpp's own fragment-offset field already has.
            c.skip(7);
            next_header = inner_next;
            continue;
        }
        break;  // not a recognized extension header -- this is the real upper-layer protocol
    }
    hdr.next_header = next_header;

    size_t extension_headers_bytes = c.position() - base_header_bytes;
    ByteSpan captured_after_headers = c.rest();
    if (static_cast<size_t>(payload_length) >= extension_headers_bytes) {
        size_t declared_upper_layer_len = static_cast<size_t>(payload_length) - extension_headers_bytes;
        if (declared_upper_layer_len <= captured_after_headers.size()) {
            hdr.payload = captured_after_headers.subspan(0, declared_upper_layer_len);
            hdr.trailing_bytes_trimmed = captured_after_headers.size() - declared_upper_layer_len;
        } else {
            // payload_length claims more than was actually captured (a short snaplen truncated
            // this packet) -- use what we have, mirroring parse_ipv4's own identical fallback.
            hdr.payload = captured_after_headers;
        }
    } else {
        // payload_length is smaller than the extension headers this parse already walked past --
        // not trustworthy (a jumbogram declaring its real length via a Hop-by-Hop option this
        // parse doesn't specifically interpret leaves the base header's own payload_length at 0;
        // see this file's own header comment). Fall back to every captured byte after the last
        // extension header walked, mirroring parse_ipv4's own identical fallback for a zero/
        // implausible total_length.
        hdr.payload = captured_after_headers;
    }
    return hdr;
}

std::string format_ipv6(const Ipv6Address& addr) {
    std::array<uint16_t, 8> groups{};
    for (size_t i = 0; i < 8; ++i) {
        groups[i] = static_cast<uint16_t>((static_cast<uint16_t>(addr[i * 2]) << 8) | addr[i * 2 + 1]);
    }

    // RFC 5952 S4.2.2: the longest run of two-or-more consecutive all-zero groups is replaced by
    // "::"; the leftmost run wins a length tie; a lone zero group is never compressed.
    int zero_run_start = -1, zero_run_len = 0;
    for (int i = 0; i < 8;) {
        if (groups[i] != 0) {
            ++i;
            continue;
        }
        int start = i;
        while (i < 8 && groups[i] == 0) ++i;
        int len = i - start;
        if (len > zero_run_len) {
            zero_run_len = len;
            zero_run_start = start;
        }
    }
    if (zero_run_len < 2) zero_run_start = -1;

    std::ostringstream out;
    out << std::hex;  // lowercase by default (no std::uppercase set) -- RFC 5952 S4.3
    bool need_colon = false;
    for (int i = 0; i < 8;) {
        if (i == zero_run_start) {
            out << "::";
            i += zero_run_len;
            need_colon = false;
            continue;
        }
        if (need_colon) out << ':';
        out << groups[i];
        need_colon = true;
        ++i;
    }
    return out.str();
}

}  // namespace conduitscope
