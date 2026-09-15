// SPDX-License-Identifier: MIT
#include "conduitscope/pcap_reader.hpp"

#include <algorithm>
#include <array>
#include <cmath>

namespace conduitscope {

namespace {

constexpr size_t kGlobalHeaderSize = 24;
constexpr size_t kRecordHeaderSize = 16;
// Sanity ceiling for a single captured packet. Real captures are far smaller than
// this; a value beyond it almost always means the file is truncated/corrupt rather
// than that a packet is genuinely that large, so we fail fast with a clear message
// instead of attempting a huge allocation.
constexpr uint32_t kMaxPlausiblePacketBytes = 16u * 1024u * 1024u;

uint32_t read_u32(const std::array<uint8_t, 4>& b, bool little_endian) {
    if (little_endian) {
        return (static_cast<uint32_t>(b[3]) << 24) | (static_cast<uint32_t>(b[2]) << 16) |
               (static_cast<uint32_t>(b[1]) << 8) | b[0];
    }
    return (static_cast<uint32_t>(b[0]) << 24) | (static_cast<uint32_t>(b[1]) << 16) |
           (static_cast<uint32_t>(b[2]) << 8) | b[3];
}

uint16_t read_u16(const std::array<uint8_t, 2>& b, bool little_endian) {
    if (little_endian) {
        return static_cast<uint16_t>((static_cast<uint16_t>(b[1]) << 8) | b[0]);
    }
    return static_cast<uint16_t>((static_cast<uint16_t>(b[0]) << 8) | b[1]);
}

// -----------------------------------------------------------------------------------------
// PCAPNG SECTIONS, BLOCKS, AND WHAT THIS READER SUPPORTS
//
// pcapng (https://ietf-opsawg-wg.github.io/draft-ietf-opsawg-pcap/) is a block-based format:
// the whole file is a sequence of self-delimiting blocks, each shaped
//
//     Block Type (4 bytes) | Block Total Length (4 bytes) | Block Body (variable, 4-byte
//     padded) | Block Total Length again (4 bytes)
//
// A file is one or more *sections*, each opening with a Section Header Block (SHB) that
// fixes the byte order for every block until the next SHB (or EOF). Interface IDs used by
// packet blocks are section-scoped -- they index into the Interface Description Blocks
// (IDBs) seen *since the current section's SHB*, in the order they appeared.
//
// Blocks this reader understands:
//   - Section Header Block (0x0A0D0D0A): establishes byte order (see the endianness
//     bootstrap in read_section_header_block()) and starts a new section.
//   - Interface Description Block (0x00000001): declares one interface's link type,
//     snaplen, and (via the if_tsresol option) timestamp resolution. Interface IDs are
//     assigned by arrival order within the section, starting at 0.
//   - Enhanced Packet Block (0x00000006): one captured packet, tagged with the interface
//     that captured it and a 64-bit timestamp in that interface's own resolution. This is
//     what every modern pcapng writer (dumpcap, Wireshark, tshark) actually emits.
//   - Simple Packet Block (0x00000003): a minimal packet record with no interface ID or
//     timestamp -- always implicitly interface 0, per spec. Rare in practice (only a
//     handful of minimal/embedded writers use it) but cheap to support.
//
// Deliberately NOT supported, and skipped like any other unrecognized block type (per the
// spec's own forward-compatibility rule: an unknown Block Type must be skipped using Block
// Total Length, not treated as an error):
//   - The legacy "Packet Block" (0x00000002), obsoleted by the Enhanced Packet Block since
//     the mid-2000s. No maintained tool has written this in a very long time; if one really
//     is encountered, its packets are silently skipped rather than decoded. `conduitscope
///    info` will show a packet count lower than an external tool's if this happens -- see
//     docs/MANUAL.md's LIMITATIONS section.
//   - Interface Statistics Blocks, Name Resolution Blocks, Decryption Secrets Blocks,
//     custom/experimental blocks, and anything else with a Block Type this reader doesn't
//     special-case above: none of these carry packet data, so skipping them costs nothing.
// -----------------------------------------------------------------------------------------

constexpr uint32_t kShbBlockType = 0x0A0D0D0Au;
constexpr uint32_t kIdbBlockType = 0x00000001u;
constexpr uint32_t kSpbBlockType = 0x00000003u;
constexpr uint32_t kEpbBlockType = 0x00000006u;
constexpr uint32_t kByteOrderMagic = 0x1A2B3C4Du;

// Every pcapng block is at least Block Type(4) + Block Total Length(4) + Block Total
// Length again(4) = 12 bytes, even with a zero-length body.
constexpr uint32_t kMinBlockBytes = 12;
// A Section Header Block additionally always carries Byte-Order Magic(4) + Major(2) +
// Minor(2) + Section Length(8) before any options, so its minimum is 28.
constexpr uint32_t kMinShbBytes = 28;
// Same rationale/ceiling as kMaxPlausiblePacketBytes, applied to a whole block (a block
// holds at most one packet plus a little metadata, so the same ceiling is a reasonable fit).
constexpr uint32_t kMaxPlausibleBlockBytes = 16u * 1024u * 1024u;

// Decodes an Interface Description Block's if_tsresol option (option code 9): a single byte
// where, per the pcapng spec, the high bit selects the base (0 = decimal/10^-n, 1 =
// binary/2^-n) and the low 7 bits give the exponent n. Absent the option, pcapng defaults to
// microsecond resolution (as if if_tsresol were 6). Malformed/truncated options are ignored
// (falling back to the default) rather than treated as fatal -- the timestamp resolution
// isn't essential to decoding, so a slightly-off options list shouldn't block reading
// packets.
double parse_if_tsresol_option(const std::vector<uint8_t>& body, size_t options_start, bool little_endian) {
    size_t pos = options_start;
    while (pos + 4 <= body.size()) {
        uint16_t opt_code = read_u16({body[pos], body[pos + 1]}, little_endian);
        uint16_t opt_len = read_u16({body[pos + 2], body[pos + 3]}, little_endian);
        pos += 4;
        if (opt_code == 0) break;  // opt_endofopt
        if (pos + opt_len > body.size()) break;  // truncated option list -- stop, keep default
        if (opt_code == 9 && opt_len >= 1) {
            uint8_t v = body[pos];
            if (v & 0x80) {
                return std::pow(2.0, static_cast<double>(v & 0x7F));
            }
            return std::pow(10.0, static_cast<double>(v));
        }
        pos += (static_cast<size_t>(opt_len) + 3) & ~static_cast<size_t>(3);  // options are 4-byte padded too
    }
    return 1e6;  // default: microsecond resolution
}

// Converts a pcapng Enhanced Packet Block's raw 64-bit timestamp (a tick count in units of
// 1/units_per_second seconds since the epoch) into PcapPacket's ts_sec/ts_frac/
// nanosecond_ts_hint fields, which were designed around classic pcap's two resolutions
// (microsecond and nanosecond). The common resol==6 (microsecond) and resol==9 (nanosecond)
// cases convert exactly with no floating point; any other declared resolution (rare -- seen
// mostly from custom/embedded capture tools) is normalized to nanoseconds.
void fill_pcapng_timestamp(PcapPacket& out, double units_per_second, uint64_t ts_raw) {
    uint64_t units = static_cast<uint64_t>(units_per_second + 0.5);
    if (units == 0) units = 1;
    uint64_t sec = ts_raw / units;
    uint64_t remainder = ts_raw % units;

    if (units == 1'000'000ull) {
        out.ts_frac = static_cast<uint32_t>(remainder);
        out.nanosecond_ts_hint = false;
    } else if (units == 1'000'000'000ull) {
        out.ts_frac = static_cast<uint32_t>(remainder);
        out.nanosecond_ts_hint = true;
    } else {
        long double frac_seconds = static_cast<long double>(remainder) / static_cast<long double>(units);
        out.ts_frac = static_cast<uint32_t>(frac_seconds * 1'000'000'000.0L + 0.5L);
        out.nanosecond_ts_hint = true;
    }
    out.ts_sec = static_cast<uint32_t>(sec);
}

}  // namespace

PcapReader::PcapReader(const std::string& path) : path_(path) {
    stream_.open(path, std::ios::binary);
    if (!stream_) {
        throw ParseError("cannot open '" + path + "' for reading");
    }

    std::array<uint8_t, kGlobalHeaderSize> header{};
    stream_.read(reinterpret_cast<char*>(header.data()), 4);
    if (stream_.gcount() != 4) {
        throw ParseError("'" + path + "' is too short to be a pcap file (truncated header)");
    }

    // pcapng's Section Header Block starts with the byte-order-independent magic
    // 0A 0D 0D 0A (a palindrome, so it reads the same regardless of the file's eventual
    // byte order). Detect it before assuming classic pcap's fixed-layout global header.
    if (header[0] == 0x0A && header[1] == 0x0D && header[2] == 0x0D && header[3] == 0x0A) {
        read_section_header_block();
        return;
    }

    // Not pcapng -- read the rest of classic pcap's 24-byte global header (the first 4
    // bytes, already in `header`, are its magic number).
    stream_.read(reinterpret_cast<char*>(header.data()) + 4, static_cast<std::streamsize>(header.size() - 4));
    if (stream_.gcount() != static_cast<std::streamsize>(header.size() - 4)) {
        throw ParseError("'" + path + "' is too short to be a pcap file (truncated global header)");
    }

    std::array<uint8_t, 4> magic_bytes{header[0], header[1], header[2], header[3]};
    uint32_t magic_le = read_u32(magic_bytes, /*little_endian=*/true);

    bool file_le;
    bool nanosecond;
    switch (magic_le) {
        case 0xa1b2c3d4u: file_le = true;  nanosecond = false; break;
        case 0xa1b23c4du: file_le = true;  nanosecond = true;  break;
        case 0xd4c3b2a1u: file_le = false; nanosecond = false; break;
        case 0x4d3cb2a1u: file_le = false; nanosecond = true;  break;
        default:
            throw ParseError("'" + path + "' does not start with a recognized pcap magic number "
                              "(not a classic pcap or pcapng capture file)");
    }

    info_.byte_swapped = !file_le;  // relative to nothing in particular; kept for --format json/info display
    info_.nanosecond_ts = nanosecond;
    info_.version_major = read_u16({header[4], header[5]}, file_le);
    info_.version_minor = read_u16({header[6], header[7]}, file_le);
    info_.thiszone = static_cast<int32_t>(read_u32({header[8], header[9], header[10], header[11]}, file_le));
    // header[12..15] is "sigfigs", historically always 0 and unused by every real tool.
    info_.snaplen = read_u32({header[16], header[17], header[18], header[19]}, file_le);
    info_.linktype = read_u32({header[20], header[21], header[22], header[23]}, file_le);

    // Stash the endianness decision on the instance via a small trick: we keep it
    // implicit by always re-deriving `file_le` from info_.byte_swapped in next().
}

void PcapReader::read_section_header_block() {
    // Precondition: the caller has already consumed this block's 4-byte Block Type field
    // (the 0A 0D 0D 0A magic) from stream_. Everything from Block Total Length onward
    // follows.
    //
    // Endianness bootstrap: we don't yet know the file's byte order, so Block Total Length
    // can't be interpreted yet either -- read it as raw bytes first, then read Byte-Order
    // Magic (also raw) and try both interpretations; whichever equals 0x1A2B3C4D tells us
    // the byte order, which we then apply retroactively to the Block Total Length bytes
    // already in hand.
    std::array<uint8_t, 4> len_raw{};
    stream_.read(reinterpret_cast<char*>(len_raw.data()), 4);
    if (stream_.gcount() != 4) {
        throw ParseError("'" + path_ + "' ends mid Section Header Block");
    }

    std::array<uint8_t, 4> bom_raw{};
    stream_.read(reinterpret_cast<char*>(bom_raw.data()), 4);
    if (stream_.gcount() != 4) {
        throw ParseError("'" + path_ + "' ends mid Section Header Block");
    }

    if (read_u32(bom_raw, /*little_endian=*/true) == kByteOrderMagic) {
        pcapng_little_endian_ = true;
    } else if (read_u32(bom_raw, /*little_endian=*/false) == kByteOrderMagic) {
        pcapng_little_endian_ = false;
    } else {
        throw ParseError("'" + path_ +
                          "' has a Section Header Block with an unrecognized byte-order magic "
                          "(corrupt pcapng file)");
    }

    uint32_t block_total_length = read_u32(len_raw, pcapng_little_endian_);
    if (block_total_length < kMinShbBytes || block_total_length % 4 != 0) {
        throw ParseError("'" + path_ + "' has an invalid Section Header Block length (" +
                          std::to_string(block_total_length) + " bytes)");
    }
    if (block_total_length > kMaxPlausibleBlockBytes) {
        throw ParseError("'" + path_ + "' reports an implausible Section Header Block length (" +
                          std::to_string(block_total_length) +
                          " bytes) -- the file is likely truncated or corrupt");
    }

    // Remaining on-disk bytes: Major(2)+Minor(2)+Section Length(8)+Options(variable)+
    // trailing Block Total Length(4). We've already read Block Type(4)+len_raw(4)+bom_raw(4)
    // = 12 of the block's total_length bytes.
    uint32_t remaining = block_total_length - 12;
    std::vector<uint8_t> rest(remaining);
    if (remaining > 0) {
        stream_.read(reinterpret_cast<char*>(rest.data()), static_cast<std::streamsize>(remaining));
        if (stream_.gcount() != static_cast<std::streamsize>(remaining)) {
            throw ParseError("'" + path_ + "' ends mid Section Header Block");
        }
    }
    // block_total_length >= kMinShbBytes (28) guarantees remaining >= 16 here (12 for
    // major/minor/section-length + 4 for the trailing length field), so the indexing below
    // is always in range.

    uint32_t trailing_length =
        read_u32({rest[rest.size() - 4], rest[rest.size() - 3], rest[rest.size() - 2], rest[rest.size() - 1]},
                 pcapng_little_endian_);
    if (trailing_length != block_total_length) {
        throw ParseError("'" + path_ + "' has a corrupt Section Header Block (length mismatch: " +
                          std::to_string(block_total_length) + " at the start, " +
                          std::to_string(trailing_length) + " at the end)");
    }

    is_pcapng_ = true;
    info_.byte_swapped = !pcapng_little_endian_;
    info_.thiszone = 0;
    info_.version_major = read_u16({rest[0], rest[1]}, pcapng_little_endian_);
    info_.version_minor = read_u16({rest[2], rest[3]}, pcapng_little_endian_);
    // A new section restarts interface numbering from 0 (Enhanced/Simple Packet Block
    // interface IDs are section-scoped per the pcapng spec). linktype/snaplen/nanosecond_ts
    // are left as whatever the previous section's last packet set them to, until this
    // section's own first packet updates them -- consistent with info()'s documented
    // "reflects the most recently seen packet's interface" behavior.
    pcapng_interfaces_.clear();
}

bool PcapReader::next_pcapng(PcapPacket& out) {
    for (;;) {
        std::array<uint8_t, 4> type_raw{};
        stream_.read(reinterpret_cast<char*>(type_raw.data()), 4);
        std::streamsize got = stream_.gcount();
        if (got == 0) {
            return false;  // clean end of file, between blocks
        }
        if (got != 4) {
            throw ParseError("'" + path_ + "' ends with a truncated pcapng block header");
        }

        if (type_raw[0] == 0x0A && type_raw[1] == 0x0D && type_raw[2] == 0x0D && type_raw[3] == 0x0A) {
            // A later Section Header Block -- pcapng allows concatenating multiple captures
            // (potentially with a different byte order each) into one file.
            read_section_header_block();
            continue;
        }

        uint32_t block_type = read_u32(type_raw, pcapng_little_endian_);

        std::array<uint8_t, 4> len_raw{};
        stream_.read(reinterpret_cast<char*>(len_raw.data()), 4);
        if (stream_.gcount() != 4) {
            throw ParseError("'" + path_ + "' ends mid pcapng block header");
        }
        uint32_t block_total_length = read_u32(len_raw, pcapng_little_endian_);
        if (block_total_length < kMinBlockBytes || block_total_length % 4 != 0) {
            throw ParseError("'" + path_ + "' has an invalid pcapng block length (" +
                              std::to_string(block_total_length) + " bytes)");
        }
        if (block_total_length > kMaxPlausibleBlockBytes) {
            throw ParseError("'" + path_ + "' reports an implausible pcapng block length (" +
                              std::to_string(block_total_length) +
                              " bytes) -- the file is likely truncated or corrupt");
        }

        uint32_t body_len = block_total_length - kMinBlockBytes;
        std::vector<uint8_t> body(body_len);
        if (body_len > 0) {
            stream_.read(reinterpret_cast<char*>(body.data()), body_len);
            if (stream_.gcount() != static_cast<std::streamsize>(body_len)) {
                throw ParseError("'" + path_ + "' ends mid pcapng block body");
            }
        }

        std::array<uint8_t, 4> trailing_raw{};
        stream_.read(reinterpret_cast<char*>(trailing_raw.data()), 4);
        if (stream_.gcount() != 4) {
            throw ParseError("'" + path_ + "' ends before its pcapng block's trailing length field");
        }
        uint32_t trailing_length = read_u32(trailing_raw, pcapng_little_endian_);
        if (trailing_length != block_total_length) {
            throw ParseError("'" + path_ + "' has a corrupt pcapng block (length mismatch: " +
                              std::to_string(block_total_length) + " at the start, " +
                              std::to_string(trailing_length) + " at the end)");
        }

        switch (block_type) {
            case kIdbBlockType: {
                if (body.size() < 8) {
                    throw ParseError("'" + path_ + "' has a truncated Interface Description Block");
                }
                PcapNgInterface iface;
                iface.linktype = read_u16({body[0], body[1]}, pcapng_little_endian_);
                iface.snaplen = read_u32({body[4], body[5], body[6], body[7]}, pcapng_little_endian_);
                iface.units_per_second = parse_if_tsresol_option(body, 8, pcapng_little_endian_);
                pcapng_interfaces_.push_back(iface);
                continue;
            }
            case kEpbBlockType: {
                if (body.size() < 20) {
                    throw ParseError("'" + path_ + "' has a truncated Enhanced Packet Block");
                }
                uint32_t iface_id = read_u32({body[0], body[1], body[2], body[3]}, pcapng_little_endian_);
                uint32_t ts_hi = read_u32({body[4], body[5], body[6], body[7]}, pcapng_little_endian_);
                uint32_t ts_lo = read_u32({body[8], body[9], body[10], body[11]}, pcapng_little_endian_);
                uint32_t cap_len = read_u32({body[12], body[13], body[14], body[15]}, pcapng_little_endian_);
                uint32_t orig_len = read_u32({body[16], body[17], body[18], body[19]}, pcapng_little_endian_);

                if (cap_len > kMaxPlausiblePacketBytes) {
                    throw ParseError("'" + path_ + "' reports an implausible captured length (" +
                                      std::to_string(cap_len) +
                                      " bytes) -- the file is likely truncated or corrupt");
                }
                if (20u + cap_len > body.size()) {
                    throw ParseError("'" + path_ + "' Enhanced Packet Block's captured length (" +
                                      std::to_string(cap_len) + ") exceeds the block's own size");
                }
                if (iface_id >= pcapng_interfaces_.size()) {
                    throw ParseError("'" + path_ + "' Enhanced Packet Block references undeclared interface " +
                                      std::to_string(iface_id));
                }

                const PcapNgInterface& iface = pcapng_interfaces_[iface_id];
                uint64_t ts_raw = (static_cast<uint64_t>(ts_hi) << 32) | ts_lo;
                fill_pcapng_timestamp(out, iface.units_per_second, ts_raw);
                out.captured_len = cap_len;
                out.original_len = orig_len;
                out.data.assign(body.begin() + 20, body.begin() + 20 + cap_len);

                info_.linktype = iface.linktype;
                info_.snaplen = iface.snaplen;
                info_.nanosecond_ts = out.nanosecond_ts_hint;
                return true;
            }
            case kSpbBlockType: {
                if (body.size() < 4) {
                    throw ParseError("'" + path_ + "' has a truncated Simple Packet Block");
                }
                if (pcapng_interfaces_.empty()) {
                    throw ParseError("'" + path_ +
                                      "' has a Simple Packet Block before any Interface Description Block");
                }
                uint32_t orig_len = read_u32({body[0], body[1], body[2], body[3]}, pcapng_little_endian_);
                const PcapNgInterface& iface = pcapng_interfaces_[0];  // SPB always means interface 0
                uint32_t limit = iface.snaplen != 0 ? std::min(iface.snaplen, orig_len) : orig_len;
                uint32_t available = static_cast<uint32_t>(body.size() - 4);
                uint32_t cap_len = std::min(limit, available);

                // Simple Packet Blocks carry no timestamp at all.
                out.ts_sec = 0;
                out.ts_frac = 0;
                out.nanosecond_ts_hint = false;
                out.captured_len = cap_len;
                out.original_len = orig_len;
                out.data.assign(body.begin() + 4, body.begin() + 4 + cap_len);

                info_.linktype = iface.linktype;
                info_.snaplen = iface.snaplen;
                info_.nanosecond_ts = false;
                return true;
            }
            default:
                // Unrecognized/unsupported block type -- skip it. Covers the obsolete Packet
                // Block (0x2), Interface Statistics Blocks, Name Resolution Blocks,
                // Decryption Secrets Blocks, and any custom/future block type. See the
                // PCAPNG SECTIONS, BLOCKS, AND WHAT THIS READER SUPPORTS note above.
                continue;
        }
    }
}

bool PcapReader::next(PcapPacket& out) {
    if (is_pcapng_) {
        return next_pcapng(out);
    }

    const bool file_le = !info_.byte_swapped;

    std::array<uint8_t, kRecordHeaderSize> rec{};
    stream_.read(reinterpret_cast<char*>(rec.data()), static_cast<std::streamsize>(rec.size()));
    std::streamsize got = stream_.gcount();
    if (got == 0) {
        return false;  // clean end of file
    }
    if (got != static_cast<std::streamsize>(rec.size())) {
        throw ParseError("'" + path_ + "' ends with a truncated packet record header");
    }

    uint32_t ts_sec = read_u32({rec[0], rec[1], rec[2], rec[3]}, file_le);
    uint32_t ts_frac = read_u32({rec[4], rec[5], rec[6], rec[7]}, file_le);
    uint32_t incl_len = read_u32({rec[8], rec[9], rec[10], rec[11]}, file_le);
    uint32_t orig_len = read_u32({rec[12], rec[13], rec[14], rec[15]}, file_le);

    if (incl_len > kMaxPlausiblePacketBytes) {
        throw ParseError("'" + path_ + "' reports an implausible captured length (" +
                          std::to_string(incl_len) + " bytes) -- the file is likely truncated or corrupt");
    }

    std::vector<uint8_t> data(incl_len);
    if (incl_len > 0) {
        stream_.read(reinterpret_cast<char*>(data.data()), static_cast<std::streamsize>(incl_len));
        if (stream_.gcount() != static_cast<std::streamsize>(incl_len)) {
            throw ParseError("'" + path_ + "' ends mid-packet (captured length says " +
                              std::to_string(incl_len) + " bytes but the file has fewer)");
        }
    }

    out.ts_sec = ts_sec;
    out.ts_frac = ts_frac;
    out.captured_len = incl_len;
    out.original_len = orig_len;
    out.data = std::move(data);
    out.nanosecond_ts_hint = info_.nanosecond_ts;
    return true;
}

}  // namespace conduitscope
