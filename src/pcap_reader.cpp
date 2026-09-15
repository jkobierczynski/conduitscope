// SPDX-License-Identifier: MIT
#include "conduitscope/pcap_reader.hpp"

#include <array>

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

}  // namespace

PcapReader::PcapReader(const std::string& path) : path_(path) {
    stream_.open(path, std::ios::binary);
    if (!stream_) {
        throw ParseError("cannot open '" + path + "' for reading");
    }

    std::array<uint8_t, kGlobalHeaderSize> header{};
    stream_.read(reinterpret_cast<char*>(header.data()), static_cast<std::streamsize>(header.size()));
    if (stream_.gcount() != static_cast<std::streamsize>(header.size())) {
        throw ParseError("'" + path + "' is too short to be a pcap file (truncated global header)");
    }

    // pcapng's Section Header Block starts with the byte-order-independent magic
    // 0A 0D 0D 0A. Detect it explicitly so the error message tells the user exactly
    // what is wrong (wrong format, not a generic corruption) and how to fix it.
    if (header[0] == 0x0A && header[1] == 0x0D && header[2] == 0x0D && header[3] == 0x0A) {
        throw ParseError(
            "'" + path +
            "' looks like a pcapng file, which this groundwork release does not parse yet "
            "(only classic pcap is supported). Convert it first, e.g.:\n"
            "  tshark -F pcap -r " + path + " -w " + path + ".pcap");
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
                              "(not a classic pcap capture file)");
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

bool PcapReader::next(PcapPacket& out) {
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
