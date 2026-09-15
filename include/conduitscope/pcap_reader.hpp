// SPDX-License-Identifier: MIT
// pcap_reader.hpp - reader for offline capture files: both classic pcap and pcapng.
//
// This reads offline capture files (what tcpdump/Wireshark/`tshark -w` write) rather than
// capturing live traffic; live capture is a separate, optional feature -- see
// live_capture.hpp. Reading offline files needs no libpcap/Npcap at all, which matters a
// lot for "clones and builds cleanly on both platforms with zero required dependencies".
//
// Both classic pcap (the single-global-header format tcpdump has always written) and
// pcapng (the newer block-based format Wireshark/dumpcap default to today) are supported,
// auto-detected from the first four bytes of the file. Which one a given file is stays an
// internal implementation detail -- PcapReader's public interface (this header) does not
// change based on it. See pcap_reader.cpp for the pcapng block-parsing internals and for
// exactly which pcapng block types are understood.
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

// Reads one offline capture file -- classic pcap or pcapng, auto-detected. Not
// thread-safe; one reader per file.
//
// info() reflects classic pcap's single, file-wide header for a classic pcap file. pcapng
// has no such single header: link type, snaplen, and timestamp resolution are declared per
// *interface* (an Interface Description Block), and a capture can legitimately contain more
// than one interface (e.g. dumpcap capturing two NICs into one file) with different values
// for each. So for a pcapng file, info() reflects whichever interface most recently owned a
// packet returned by next() -- initially the first interface declared in the file, updated
// on every next() call after that. Every call site in this codebase already re-reads
// info().linktype fresh on each iteration of its packet loop (rather than caching it once
// before the loop) for exactly this reason, so per-packet/per-interface accuracy falls out
// automatically without those call sites needing to know or care which format is in play.
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
    // Per-interface state accumulated from pcapng Interface Description Blocks. Interface
    // IDs referenced by Enhanced Packet Blocks are indices into this, scoped to the current
    // section (see PCAPNG SECTIONS note in pcap_reader.cpp).
    struct PcapNgInterface {
        uint32_t linktype = 1;         // LINKTYPE_ETHERNET, pcapng's own default absent an IDB
        uint32_t snaplen = 0;          // 0 means "no limit declared"
        double units_per_second = 1e6;  // from the if_tsresol option; default is microseconds
    };

    // pcapng-only: reads the Section Header Block at the reader's current stream position,
    // bootstrapping (or re-bootstrapping, for a later section) byte order from the
    // byte-order-magic field, and resets per-section interface state. Called once from the
    // constructor for the file's first section and again from next() whenever a later
    // Section Header Block is encountered (pcapng permits concatenating multiple captures,
    // potentially with different byte order, into one file).
    void read_section_header_block();
    // pcapng-only: the block loop driving next() for a pcapng file -- walks blocks from the
    // current stream position, updating interface_/info_ state as it goes, until it has a
    // packet to return (true) or reaches a clean end of file (false).
    bool next_pcapng(PcapPacket& out);

    std::string path_;
    std::ifstream stream_;
    PcapFileInfo info_;

    bool is_pcapng_ = false;
    bool pcapng_little_endian_ = true;
    std::vector<PcapNgInterface> pcapng_interfaces_;
};

}  // namespace conduitscope
