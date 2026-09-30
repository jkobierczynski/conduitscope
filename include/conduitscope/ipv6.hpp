// SPDX-License-Identifier: Apache-2.0
// ipv6.hpp - minimal IPv6 header parsing, mirroring ipv4.hpp's own shape and scope discipline.
//
// Groundwork scope (docs/DEVELOPMENT.md ROADMAP item 24, "IPv6 support"): a fixed 40-byte base
// header, plus RFC 8200's extension-header chain walked far enough to reach the real upper-layer
// protocol -- Hop-by-Hop Options (0), Routing (43), Destination Options (60), and AH (51, RFC 4302
// -- authentication only, doesn't encrypt, so walking past it to the real upper-layer protocol is
// both possible and worthwhile) are all skipped over structurally. Fragment (44) is parsed (not
// just skipped): its own fields -- fragment offset, M flag, 32-bit identification -- are exposed on
// Ipv6Header (has_fragment_header/fragment_offset/fragment_more/fragment_identification, mirroring
// Ipv4Header's own identical fields) for decoder.cpp's Decoder::reassemble_ip_fragment (ROADMAP
// item 102) to reassemble across packets -- this file itself stays a pure single-packet parser with
// no cross-packet state, same discipline as ipv4.hpp. One correctness detail specific to a
// fragmented datagram: only the OFFSET-0 fragment's extension-header chain continues past the
// Fragment header per RFC 8200 (it alone carries the real Destination-Options-then-upper-layer
// structure); on any other fragment (fragment_offset != 0), this parse stops walking immediately
// after the Fragment header's own 8 bytes and treats everything remaining as that fragment's own
// opaque continuation payload -- NOT further extension headers to interpret (see parse_ipv6's own
// comment on the kFragment branch for exactly where this is enforced; a bug where this parse
// blindly kept walking regardless of offset was found and fixed as part of item 102). ESP (50, RFC
// 4303) is NOT walked past -- its payload is encrypted, the same opaque-regardless-of-IP-version
// limit ESP already has over IPv4 (see decoder.cpp's shared GRE/ESP/AH/IPIP/6in4/L2TPv3 recognition,
// tunnel_vpn.hpp) -- so an ESP extension header simply becomes this parse's own final `next_header`,
// exactly as if it had arrived as an IPv4 packet's own top-level protocol number; the existing
// IPv4-side recognition of protocol 50 already handles it from there with no new code needed. None
// of Hop-by-Hop/Routing/Destination Options' own options, or a Routing header's own route data, are
// interpreted -- only walked past to find their length.
//
// Out of scope for this first pass, same as ipv4.hpp draws its own lines: jumbograms (RFC 2675, a
// Hop-by-Hop option this parse doesn't specifically recognize -- falls back the same way an
// implausible/zero IPv4 total_length does, see parse_ipv6's own comment); the Mobility (135)/HIP
// (139)/Shim6 (140) extension headers (rare enough in real OT/IT traffic, and structurally
// identical to Hop-by-Hop/Routing/Destination Options' own next-header+length-in-8-byte-units
// shape, to add later with no redesign needed); parsing an IPv6 address back out of user-typed text
// (parse_ipv4_string's own mirror) -- not needed until IPv6 is wired into `policy validate`'s own
// conduit/zone model, which is its own, separately scoped follow-on (see ROADMAP item 24's own
// "out of scope" paragraph).
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
                                // (see this file's own header comment for exactly which ones) --
                                // on a non-first fragment (fragment_offset != 0 below) this is NOT
                                // trustworthy as the real upper-layer protocol (RFC 8200: only the
                                // offset-0 fragment carries the true post-Fragment chain); callers
                                // must not dispatch on it directly for such a fragment -- see
                                // decoder.cpp's reassemble_ip_fragment (its upper_protocol_trustworthy
                                // parameter), which only ever captures a group's real upper-layer
                                // protocol from the offset-0 fragment's copy of this field. Also NOT
                                // to be used as a fragment-reassembly group key (fragments of one
                                // datagram can disagree on it, since it's fully resolved only for
                                // the offset-0 fragment) -- fragment_next_header below is the
                                // field that's stable across a datagram's fragments.
    uint8_t hop_limit = 0;     // IPv6's own name for what IPv4 calls TTL; same wire size and role
    Ipv6Address src_addr{};
    Ipv6Address dst_addr{};
    ByteSpan payload;          // clamped to the base header's payload_length field minus every
                                // extension header's own length, when that arithmetic is
                                // trustworthy; see parse_ipv6's own comment for the fallback

    // Fragment (44) extension header fields (RFC 8200 S4.5), mirroring Ipv4Header's own
    // identification/flag_mf/fragment_offset fields -- see decoder.cpp's Decoder::
    // reassemble_ip_fragment for the actual reassembly engine that consumes these; this struct
    // only exposes what's on the wire, same "read but not acted on here" discipline as
    // Ipv4Header's own comment. has_fragment_header is false when no Fragment header was present
    // at all (the overwhelming common case) -- every field below is meaningless when it's false.
    bool has_fragment_header = false;
    uint32_t fragment_identification = 0;  // 32 bits on IPv6, vs. IPv4's 16 -- RFC 8200 S4.5
    uint16_t fragment_offset = 0;          // in 8-byte units, same convention/units as
                                             // Ipv4Header::fragment_offset -- multiply by 8 for a
                                             // byte offset into the reassembled datagram
    bool fragment_more = false;             // false on the last fragment of a fragmented datagram
    uint8_t fragment_next_header = 0;       // the Fragment header's OWN "next header" byte, read
                                             // directly and unconditionally -- RFC 8200 S4.5
                                             // guarantees this is identical across every fragment
                                             // of one datagram (it names the fragmentable part's
                                             // initial header type, a property of the original,
                                             // unfragmented datagram). Deliberately distinct from
                                             // next_header above, which for the offset-0 fragment
                                             // gets walked further to the true upper-layer
                                             // protocol and so is NOT stable across fragments
                                             // whenever an extension header (e.g. Destination
                                             // Options) sits between Fragment and the upper layer.
                                             // decoder.cpp's Decoder::reassemble_ip_fragment keys
                                             // its reassembly groups on this field for exactly that
                                             // reason -- see its own comment and parse_ipv6's own
                                             // comment on the kFragment branch.
    ByteSpan fragment_raw_payload;          // the RAW, uninterpreted bytes of the Fragmentable Part
                                             // starting at this fragment's own declared offset --
                                             // what decoder.cpp's Decoder::reassemble_ip_fragment
                                             // must use as this fragment's contribution, NOT
                                             // `payload` above. For a non-offset-0 fragment the two
                                             // are identical (no further walking ever happens); for
                                             // the offset-0 fragment they can differ, because
                                             // `payload` has had any further extension header (a
                                             // Destination Options header, the only one RFC 8200
                                             // permits here) walked past and its bytes consumed --
                                             // reassembly needs those bytes preserved at their real
                                             // wire offset instead. Only meaningful when
                                             // has_fragment_header is true.

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

// The result of resolve_ipv6_fragment_upper_layer below: the real upper-layer protocol and payload
// found by walking a fully-reassembled IPv6 datagram's Fragmentable Part.
struct Ipv6FragmentResolution {
    uint8_t upper_protocol = 0;
    ByteSpan upper_payload;
};

// Called once a fragmented IPv6 datagram is fully reassembled (decoder.cpp's Decoder::
// reassemble_ip_fragment returning true on the IPv6 path) to find the real upper-layer protocol and
// payload from the complete, raw Fragmentable Part bytes (`reassembled_data`) -- deliberately NOT
// using any single fragment's own (possibly not fully resolved) Ipv6Header::next_header, since the
// fragment that happens to complete a reassembly is not necessarily the offset-0 one and every other
// fragment's own next_header is just the Fragment header's immediate byte, not the walked-through
// protocol (see Ipv6Header::next_header's own comment). `first_header_type` must be
// Ipv6Header::fragment_next_header (RFC 8200-guaranteed identical across every fragment of the
// datagram) -- the type of the very first byte of `reassembled_data`.
//
// Walks Hop-by-Hop/Routing/Destination Options/AH exactly like parse_ipv6's own inner loop (kept in
// sync deliberately -- RFC 8200 permits a Destination Options header here specifically, to carry
// options meant only for the final destination; the others are walked too for robustness against a
// non-conformant/adversarial capture, though real traffic essentially never puts them after
// Fragment). Unlike parse_ipv6, does NOT handle Fragment or ESP specially -- a reassembled datagram
// cannot legitimately contain a second Fragment header (a datagram is fragmented at most once), and
// if the walk nonetheless encounters one (or ESP, or anything else unrecognized), it simply stops
// there and reports that byte's value as upper_protocol with everything from that point on as
// upper_payload, the same terminal case parse_ipv6 itself falls back to for an unrecognized
// next_header value. Never throws -- a chain that would exceed parse_ipv6's own kMaxExtensionHeaders
// limit, or a header claiming a length longer than what's actually present, simply stops the walk at
// that point (same terminal fallback), since by this stage the caller has no fragment left to blame
// a ParseError on and abandoning a fully-reassembled datagram over its own upper-layer parsing is
// decode_ip_payload's job (via its own ParseError handling), not this function's.
Ipv6FragmentResolution resolve_ipv6_fragment_upper_layer(uint8_t first_header_type, ByteSpan reassembled_data);

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
