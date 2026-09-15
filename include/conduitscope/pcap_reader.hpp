// SPDX-License-Identifier: MIT
// pcap_reader.hpp - reader for classic libpcap capture files.
//
// Groundwork scope: this reads offline .pcap files (the format tcpdump / `tshark -F pcap`
// / Wireshark's "File > Save As > .pcap" write) rather than capturing live traffic. That
// keeps the whole tool dependency-free (no libpcap on Linux, no Npcap SDK on Windows,
// no elevated privileges) which matters a lot for "clones and builds cleanly on both
// platforms". Live capture is a natural phase-2 addition once this groundwork is in
// place; see docs/MANUAL.md's Roadmap section.
//
// Modern pcapng (the newer block-based format some tools default to) is deliberately
// NOT supported here yet -- see the note in pcap_reader.cpp. Converting a pcapng file to
// classic pcap with `tshark -F pcap -r in.pcapng -w out.pcap` is a one-line workaround.
#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// Well-known pcap link-layer type values (from the tcpdump LINKTYPE_ registry) that
// this tool understands. Anything else is reported per-packet as "unsupported link
// type" rather than treated as a fatal error, so a mixed-capability capture can still
// be partially decoded.
enum LinkType : uint32_t {
    LINKTYPE_ETHERNET = 1,
    LINKTYPE_RAW = 101,
};

struct PcapFileInfo {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    int32_t thiszone = 0;
    uint32_t snaplen = 0;
    uint32_t linktype = 0;
    bool byte_swapped = false;   // capture file endianness differs from this host
    bool nanosecond_ts = false;  // 0xa1b23c4d / 0x4d3cb2a1 magic variant
};

struct PcapPacket {
    uint32_t ts_sec = 0;
    uint32_t ts_frac = 0;  // microseconds, or nanoseconds if info().nanosecond_ts
    uint32_t captured_len = 0;
    uint32_t original_len = 0;
    std::vector<uint8_t> data;

    double timestamp_seconds() const {
        double frac = ts_frac / (nanosecond_ts_hint ? 1e9 : 1e6);
        return static_cast<double>(ts_sec) + frac;
    }

    bool nanosecond_ts_hint = false;  // set by PcapReader::next()
};

// Reads one classic-format pcap file. Not thread-safe; one reader per file.
class PcapReader {
public:
    explicit PcapReader(const std::string& path);

    const PcapFileInfo& info() const { return info_; }

    // Reads the next packet into `out`. Returns false at a clean end of file.
    // Throws ParseError if the file is truncated mid-record (a corrupt/partial
    // capture), so callers can decide whether that is fatal.
    bool next(PcapPacket& out);

    const std::string& path() const { return path_; }

private:
    std::string path_;
    std::ifstream stream_;
    PcapFileInfo info_;
};

}  // namespace conduitscope
