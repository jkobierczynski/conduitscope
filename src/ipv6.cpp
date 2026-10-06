// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ipv6.hpp"

#include <algorithm>
#include <optional>
#include <sstream>
#include <vector>

#include "conduitscope/tunnel_vpn.hpp"  // ESP_IP_PROTOCOL, AH_IP_PROTOCOL -- shared IANA protocol
                                        // numbers, not IPv4-specific despite that file's name; see
                                        // this file's own header comment on why AH is walked past
                                        // and ESP is not.

namespace conduitscope {

namespace {

// Splits `text` on ':' the way parse_ipv6_string needs: an empty input yields zero groups (not one
// empty-string group) -- the caller relies on this to distinguish "nothing on this side of the ::"
// from "an empty group," which must be rejected. A non-empty input with no ':' at all yields one
// group (the whole string). Every group, including an empty one from a stray/doubled ':', is
// returned verbatim for the caller to validate -- this function only splits, it doesn't judge.
std::vector<std::string> split_on_colon(const std::string& text) {
    std::vector<std::string> parts;
    if (text.empty()) return parts;
    size_t start = 0;
    while (true) {
        size_t colon = text.find(':', start);
        if (colon == std::string::npos) {
            parts.push_back(text.substr(start));
            break;
        }
        parts.push_back(text.substr(start, colon - start));
        start = colon + 1;
    }
    return parts;
}

// Parses one IPv6 address group: 1-4 hex digits (case-insensitive), no leading-zero restriction
// (unlike parse_ipv4_string's decimal octets -- see parse_ipv6_string's own comment on why hex
// leading zeros are fine). std::nullopt for anything else, including an empty string (a stray or
// doubled ':') or a group longer than 4 hex digits.
std::optional<uint16_t> parse_hex_group(const std::string& group) {
    if (group.empty() || group.size() > 4) return std::nullopt;
    uint16_t value = 0;
    for (char c : group) {
        int digit;
        if (c >= '0' && c <= '9') {
            digit = c - '0';
        } else if (c >= 'a' && c <= 'f') {
            digit = c - 'a' + 10;
        } else if (c >= 'A' && c <= 'F') {
            digit = c - 'A' + 10;
        } else {
            return std::nullopt;
        }
        value = static_cast<uint16_t>((value << 4) | static_cast<unsigned>(digit));
    }
    return value;
}

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

    // Set only inside the kFragment branch below, to the cursor position (and captured raw bytes)
    // immediately after the Fragment header's own fixed 8 bytes -- BEFORE any further extension-
    // header walking that may happen for the offset-0 fragment specifically. See the comment where
    // hdr.fragment_raw_payload is computed (after the walk loop) for why this can't just reuse
    // hdr.payload.
    size_t position_after_fragment_header = 0;
    ByteSpan raw_bytes_after_fragment_header;

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
            // Fixed 8 bytes total, no length field of its own: Next Header(1, just read) +
            // Reserved(1) + Fragment Offset(13 bits)/Reserved(2 bits)/M flag(1 bit)(2) +
            // Identification(4) = 8. See this file's own header comment for the full RFC 8200
            // S4.5 field layout and the decoder.cpp reassembly engine (Decoder::
            // reassemble_ip_fragment) these fields feed.
            uint8_t inner_next = c.u8();
            c.u8();                                  // Reserved -- unused
            uint16_t offset_res_m = c.u16be();
            uint32_t identification = c.u32be();
            hdr.has_fragment_header = true;
            hdr.fragment_offset = static_cast<uint16_t>(offset_res_m >> 3);
            hdr.fragment_more = (offset_res_m & 0x1) != 0;
            hdr.fragment_identification = identification;
            // RFC 8200 S4.5: the Fragment header's own Next Header byte "identifies the initial
            // header type of the Fragmentable Part of the original packet" -- a property of the
            // ORIGINAL, unfragmented datagram, not of this one fragment, so it is required to be
            // byte-identical across every fragment of the same datagram regardless of arrival
            // order or offset. Capture it here, unconditionally, before the offset-0-only walk
            // decision below can touch `next_header` -- decoder.cpp's Decoder::reassemble_ip_fragment
            // keys its reassembly groups on THIS field (fragment_next_header), not on
            // hdr.next_header below, precisely because hdr.next_header is only ever resolved all
            // the way to the true upper-layer protocol on the offset-0 fragment (see its own
            // comment above) -- keying on it would put fragments of the same datagram into
            // different groups whenever an extension header (e.g. Destination Options) sits
            // between Fragment and the upper layer, since only the offset-0 fragment's copy of
            // that value ever gets walked past. Found via this feature's own manual verification
            // pass (ROADMAP item 102): a hand-built two-fragment IPv6 datagram with a Destination
            // Options header after Fragment reassembled only when this fix was in place; before
            // it, the two fragments silently landed in different groups and reassembly never
            // completed.
            hdr.fragment_next_header = inner_next;
            // Snapshot the raw, uninterpreted bytes right here -- immediately after the Fragment
            // header's own 8 bytes, before the offset-0-only branch below potentially walks (and
            // thereby consumes/interprets away) a further Destination Options header. See
            // hdr.fragment_raw_payload's own computation below for why this snapshot -- not
            // hdr.payload -- is what decoder.cpp's fragment reassembly must use.
            position_after_fragment_header = c.position();
            raw_bytes_after_fragment_header = c.rest();
            if (hdr.fragment_offset != 0) {
                // RFC 8200: only the offset-0 fragment carries a real, further-walkable extension-
                // header chain after Fragment -- on any other fragment, everything past this point
                // is that fragment's own opaque continuation payload, not more structured extension
                // headers. Stop walking here (do NOT `next_header = inner_next; continue;` -- that
                // would misinterpret raw fragment bytes as a header type/length pair, a real bug
                // found and fixed as part of ROADMAP item 102). `next_header` (and therefore
                // `hdr.next_header` below) is left as this fragment's own Fragment-header
                // `inner_next` byte -- unused for actual transport dispatch on a non-first fragment
                // (decoder.cpp's Decoder::reassemble_ip_fragment always intercepts before that could
                // happen), but harmless to leave set rather than inventing a sentinel value.
                next_header = inner_next;
                break;
            }
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

    if (hdr.has_fragment_header) {
        // decoder.cpp's Decoder::reassemble_ip_fragment needs the RAW, uninterpreted bytes of the
        // Fragmentable Part starting at THIS fragment's own declared offset -- not hdr.payload
        // above, which for the offset-0 fragment specifically has had any further extension
        // headers (a Destination Options header is the one RFC 8200 actually permits here) walked
        // past and their bytes consumed/discarded, same as hdr.next_header being resolved past
        // them. Using hdr.payload for reassembly would silently drop those consumed bytes from the
        // reassembled datagram (and misalign every byte after them) whenever an offset-0 fragment
        // carries one -- a real bug found via this feature's own manual IPv6 verification pass
        // (ROADMAP item 102): the completed reassembly came up short by exactly the walked
        // extension header's own length, and the bytes that WERE written landed at the wrong
        // offset. Computed the same way hdr.payload is above, but relative to
        // position_after_fragment_header (captured before any such further walking could happen)
        // instead of the post-walk cursor position.
        size_t fragment_header_prefix_bytes = position_after_fragment_header - base_header_bytes;
        if (static_cast<size_t>(payload_length) >= fragment_header_prefix_bytes) {
            size_t declared_len = static_cast<size_t>(payload_length) - fragment_header_prefix_bytes;
            if (declared_len <= raw_bytes_after_fragment_header.size()) {
                hdr.fragment_raw_payload = raw_bytes_after_fragment_header.subspan(0, declared_len);
            } else {
                hdr.fragment_raw_payload = raw_bytes_after_fragment_header;
            }
        } else {
            hdr.fragment_raw_payload = raw_bytes_after_fragment_header;
        }
    }
    return hdr;
}

Ipv6FragmentResolution resolve_ipv6_fragment_upper_layer(uint8_t first_header_type, ByteSpan reassembled_data) {
    Ipv6FragmentResolution result;
    // Last known-good position: the start of `first_header_type`'s own header, before this walk
    // has consumed anything at all. Updated only once a header is FULLY, successfully walked past
    // (mirroring parse_ipv6's own loop below) -- so if a read throws partway through a header
    // (truncated/malformed data), the catch block below can fall back to treating everything from
    // this last-good point on as opaque payload of last-good's own type, exactly the same terminal
    // fallback parse_ipv6 uses for an unrecognized next_header value.
    uint8_t next_header = first_header_type;
    size_t last_good_position = 0;
    uint8_t last_good_header_type = first_header_type;
    Cursor c(reassembled_data);
    int extension_headers_seen = 0;
    try {
        while (true) {
            if (next_header == kHopByHop || next_header == kRouting || next_header == kDestinationOptions) {
                if (++extension_headers_seen > kMaxExtensionHeaders) {
                    break;  // same terminal fallback as parse_ipv6's own cap -- see this function's
                             // own declaration comment (never throws)
                }
                uint8_t inner_next = c.u8();
                uint8_t hdr_ext_len = c.u8();
                size_t remaining_this_header = (static_cast<size_t>(hdr_ext_len) + 1) * 8 - 2;
                c.skip(remaining_this_header);
                next_header = inner_next;
                last_good_position = c.position();
                last_good_header_type = next_header;
                continue;
            }
            if (next_header == AH_IP_PROTOCOL) {
                if (++extension_headers_seen > kMaxExtensionHeaders) {
                    break;
                }
                uint8_t inner_next = c.u8();
                uint8_t payload_len_words = c.u8();
                size_t remaining_this_header = (static_cast<size_t>(payload_len_words) + 2) * 4 - 2;
                c.skip(remaining_this_header);
                next_header = inner_next;
                last_good_position = c.position();
                last_good_header_type = next_header;
                continue;
            }
            // Anything else -- a real upper-layer protocol, ESP, or (should never legitimately
            // happen -- see this function's own declaration comment) another Fragment header --
            // is the terminal case: stop here, this is the resolved upper-layer protocol.
            last_good_position = c.position();
            last_good_header_type = next_header;
            break;
        }
    } catch (const ParseError&) {
        // A header claimed a length longer than what's actually present -- fall back to the last
        // point this walk fully understood (see the comment on last_good_position/
        // last_good_header_type above).
    }
    result.upper_protocol = last_good_header_type;
    result.upper_payload = reassembled_data.from(last_good_position);
    return result;
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

std::optional<Ipv6Address> parse_ipv6_string(const std::string& text) {
    if (text.empty()) return std::nullopt;
    // '.' is rejected implicitly by parse_hex_group below (never a hex digit) wherever it appears
    // in a group -- including an embedded IPv4-mapped dotted-decimal tail like "::ffff:1.2.3.4",
    // out of scope per this file's own header comment -- so no separate check for it is needed
    // here.
    size_t first_run = text.find("::");
    std::vector<std::string> groups;
    if (first_run == std::string::npos) {
        // No "::" at all -- every one of the 8 groups must be written out explicitly.
        groups = split_on_colon(text);
        if (groups.size() != 8) return std::nullopt;
    } else {
        std::string left = text.substr(0, first_run);
        std::string right = text.substr(first_run + 2);
        if (right.find("::") != std::string::npos) {
            // A second "::" -- ambiguous (which run is the elided one?), rejected outright.
            return std::nullopt;
        }
        std::vector<std::string> left_groups = split_on_colon(left);
        std::vector<std::string> right_groups = split_on_colon(right);
        size_t written = left_groups.size() + right_groups.size();
        // "::" must stand in for at least one elided group -- a written count of all 8 would mean
        // it elided nothing, which RFC 4291 doesn't sanction and real tooling never emits.
        if (written >= 8) return std::nullopt;
        groups = std::move(left_groups);
        groups.resize(groups.size() + (8 - written), "0");
        groups.insert(groups.end(), right_groups.begin(), right_groups.end());
    }

    Ipv6Address addr{};
    for (size_t i = 0; i < 8; ++i) {
        auto value = parse_hex_group(groups[i]);
        if (!value) return std::nullopt;
        addr[i * 2] = static_cast<uint8_t>(*value >> 8);
        addr[i * 2 + 1] = static_cast<uint8_t>(*value & 0xFF);
    }
    return addr;
}

}  // namespace conduitscope
