// SPDX-License-Identifier: Apache-2.0
// ipv6.hpp - minimal IPv6 header parsing, mirroring ipv4.hpp's own shape and scope discipline.
//
// Groundwork scope (docs/DEVELOPMENT.md ROADMAP item 24, "IPv6 support"): a fixed 40-byte base
// header, plus RFC 8200's extension-header chain walked far enough to reach the real upper-layer
// protocol -- Hop-by-Hop Options (0), Routing (43), Destination Options (60), and AH (51, RFC 4302
// -- authentication only, doesn't encrypt, so walking past it to the real upper-layer protocol is
// both possible and worthwhile) are all skipped over structurally; Fragment (44) is skipped
// structurally too (its own fixed 8 bytes), but -- exactly like ipv4.hpp's own "flags + fragment
// offset (fragment reassembly is a documented limitation)" comment -- a non-first fragment's bytes
// are NOT reassembled, so what looks like "the real upper-layer payload" after a Fragment header on
// a non-first fragment is actually just that fragment's own raw continuation bytes, which can be
// misread as a valid protocol header exactly the same way IPv4 already accepts for its own
// unreassembled fragments. ESP (50, RFC 4303) is NOT walked past -- its payload is encrypted, the
// same opaque-regardless-of-IP-version limit ESP already has over IPv4 (see decoder.cpp's shared
// GRE/ESP/AH/IPIP/6in4/L2TPv3 recognition, tunnel_vpn.hpp) -- so an ESP extension header simply
// becomes this parse's own final `next_header`, exactly as if it had arrived as an IPv4 packet's
// own top-level protocol number; the existing IPv4-side recognition of protocol 50 already handles
// it from there with no new code needed. None of Hop-by-Hop/Routing/Destination Options' own
// options, or a Routing header's own route data, are interpreted -- only walked past to find their
// length.
//
// Out of scope for this first pass, same as ipv4.hpp draws its own lines: fragment reassembly (see
// above); jumbograms (RFC 2675, a Hop-by-Hop option this parse doesn't specifically recognize --
// falls back the same way an implausible/zero IPv4 total_length does, see parse_ipv6's own
// comment); the Mobility (135)/HIP (139)/Shim6 (140) extension headers (rare enough in real OT/IT
// traffic, and structurally identical to Hop-by-Hop/Routing/Destination Options' own
// next-header+length-in-8-byte-units shape, to add later with no redesign needed); parsing an
// IPv6 address back out of user-typed text (parse_ipv4_string's own mirror) -- not needed until
// IPv6 is wired into `policy validate`'s own conduit/zone model, which is its own, separately
// scoped follow-on (see ROADMAP item 24's own "out of scope" paragraph).
#pragma once

#include <array>
#include <cstdint>
#include <string>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// A 128-bit IPv6 address, stored exactly as it appears on the wire (network byte order, 16 raw
// bytes) -- unlike Ipv4Header's own src_addr/dst_addr (a host-order uint32_t, since a 32-bit
// address fits comfortably in a native integer type and benefits from being one, e.g. for
// arithmetic CIDR masking in policy.cpp), there's no equivalent native-integer convenience at 128
// bits without pulling in a bignum type this codebase has no other use for, and nothing here needs
// the address as an integer anyway -- only ever formatted for display (see format_ipv6 below).
using Ipv6Address = std::array<uint8_t, 16>;

struct Ipv6Header {
    uint8_t version = 0;
    uint8_t next_header = 0;   // the IANA protocol number of the REAL upper-layer payload, after
                                // walking every extension header this parse knows how to skip past
                                // (see this file's own header comment for exactly which ones)
    uint8_t hop_limit = 0;     // IPv6's own name for what IPv4 calls TTL; same wire size and role
    Ipv6Address src_addr{};
    Ipv6Address dst_addr{};
    ByteSpan payload;          // clamped to the base header's payload_length field minus every
                                // extension header's own length, when that arithmetic is
                                // trustworthy; see parse_ipv6's own comment for the fallback
    size_t trailing_bytes_trimmed = 0;  // mirrors Ipv4Header's own field -- see its comment
};

// Throws ParseError if `packet` is too short for the fixed 40-byte base header, is not IPv6
// (version != 6), or an extension header this parse walks past declares a length longer than the
// buffer actually holds. `payload` is clamped to the base header's own payload_length field the
// same way parse_ipv4 clamps to total_length -- trustworthy range checked, falling back to
// "everything captured after the last extension header this parse walked past" when it isn't (a
// zero or implausible payload_length, e.g. a jumbogram declaring its real length via a Hop-by-Hop
// option this parse doesn't specifically interpret, or a capture truncated shorter than the
// datagram claims to be).
Ipv6Header parse_ipv6(ByteSpan packet);

// RFC 5952 canonical form: lowercase hex, no leading zeros within a group, and the single longest
// run of two-or-more consecutive all-zero 16-bit groups replaced by "::" (the leftmost run wins a
// length tie; a lone zero group is never compressed) -- reused everywhere an address currently
// only has IPv4 formatting (see ROADMAP item 24's own list: VRRPv3/HSRPv2-for-IPv6 address-list
// rendering, PIM's IPv6 Encoded Address support, 6in4's inner address extraction), not just this
// file's own src_addr/dst_addr. Does not special-case an IPv4-mapped address (::ffff:a.b.c.d) into
// dotted-quad-suffixed form the way some tools do -- out of scope for this first pass; plain RFC
// 5952 output is what every consumer of this function gets today.
std::string format_ipv6(const Ipv6Address& addr);

}  // namespace conduitscope
