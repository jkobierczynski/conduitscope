// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/rotating_pcap_writer.hpp"

#include <cstdio>   // std::remove
#include <ctime>

#include "conduitscope/byteio.hpp"
#include "conduitscope/pcap_writer.hpp"

namespace conduitscope {

namespace {

// Classic pcap's own fixed global-header size (magic/version/thiszone/sigfigs/snaplen/linktype),
// see pcap_writer.cpp's own PcapWriter::PcapWriter -- every file this class opens starts with
// exactly this many bytes before any packet record.
constexpr uint64_t kPcapGlobalHeaderBytes = 24;
// Classic pcap's own fixed per-packet record header size (ts_sec/ts_usec/incl_len/orig_len), see
// pcap_writer.cpp's own PcapWriter::write_packet.
constexpr uint64_t kPcapRecordHeaderBytes = 16;

// Filesystem-safe, sortable filename timestamp -- YYYYMMDDTHHMMSSZ, always UTC (std::gmtime, never
// std::localtime: a sensor's rotated files should sort and compare consistently regardless of the
// host's own configured timezone, and avoid any DST-transition ambiguity). Deliberately NOT
// time_format.hpp's own formatters -- those are built for human-readable report text (e.g.
// "2023-11-15 03:46:40.000000Z", containing a colon and a space, both invalid in a Windows
// filename) rather than a filename component. Named by WALL-CLOCK time (the moment this process
// actually opened the file), not by any packet's own capture timestamp -- deliberately mirroring
// dumpcap's/tcpdump's own ring-buffer file-naming convention (`-w trace-%Y%m%d%H%M%S.pcap`), which
// likewise names a rotated file by when the writer opened it, not by anything in the traffic
// itself. RotationPolicy::rotate_seconds (rotating_pcap_writer.hpp) is deliberately the opposite --
// checked against packet timestamps, not wall-clock -- for the reasons documented on that field;
// the two are independent design choices, not in tension: this is purely a label, while
// rotate_seconds is the actual trigger deciding when a new label is needed at all.
std::string wall_clock_filename_timestamp() {
    std::time_t now = std::time(nullptr);
    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &now);
#else
    gmtime_r(&now, &tm_utc);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02dT%02d%02d%02dZ", tm_utc.tm_year + 1900,
                  tm_utc.tm_mon + 1, tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec);
    return std::string(buf);
}

std::string zero_pad(size_t value, int width) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%0*zu", width, value);
    return std::string(buf);
}

}  // namespace

RotatingPcapWriter::RotatingPcapWriter(const std::string& directory, const std::string& prefix,
                                        uint32_t linktype, uint32_t snaplen,
                                        const RotationPolicy& policy,
                                        std::function<void(const std::string&)> on_warning)
    : directory_(directory),
      prefix_(prefix),
      linktype_(linktype),
      snaplen_(snaplen),
      policy_(policy),
      on_warning_(std::move(on_warning)) {
    if ((policy_.max_total_bytes != 0 || policy_.max_files != 0) && policy_.rotate_bytes == 0 &&
        policy_.rotate_seconds == 0) {
        throw ParseError(
            "RotatingPcapWriter: a retention cap (max_total_bytes/max_files, i.e. --max-total-"
            "bytes/--max-files) requires at least one rotation trigger (rotate_bytes/rotate_seconds, "
            "i.e. --rotate-bytes/--rotate-seconds) to be configured too -- with no rotation trigger "
            "there is only ever one file, which is always the active file, and the active file is "
            "never evicted, so a retention cap alone could never actually bound disk use");
    }
    open_new_file();  // fail fast on a bad `directory`, same posture as PcapWriter's own constructor
}

RotatingPcapWriter::~RotatingPcapWriter() = default;

void RotatingPcapWriter::open_new_file() {
    std::string path = directory_ + "/" + prefix_ + "_" + wall_clock_filename_timestamp() + "_" +
                        zero_pad(files_opened_, 6) + ".pcap";
    writer_ = std::make_unique<PcapWriter>(path, linktype_, snaplen_);
    current_path_ = path;
    current_bytes_ = kPcapGlobalHeaderBytes;
    current_packet_count_ = 0;
    current_file_first_ts_sec_ = 0;
    ++files_opened_;
}

bool RotatingPcapWriter::needs_rotation(const PcapPacket& pkt) const {
    // Always write at least one packet into a freshly-opened file -- otherwise a single packet
    // larger than rotate_bytes, or a rotate_seconds of 0 seconds, would rotate forever without ever
    // making progress. See this class's own RotationPolicy field comments.
    if (current_packet_count_ == 0) return false;
    if (policy_.rotate_bytes != 0) {
        uint64_t record_bytes = kPcapRecordHeaderBytes + pkt.data.size();
        if (current_bytes_ + record_bytes > policy_.rotate_bytes) return true;
    }
    if (policy_.rotate_seconds != 0) {
        // A packet timestamped before the current file's first packet (out-of-order replay, or a
        // live capture's clock stepping backward) never triggers rotation on its own -- see
        // RotationPolicy::rotate_seconds's own comment.
        if (pkt.ts_sec >= current_file_first_ts_sec_ &&
            static_cast<uint64_t>(pkt.ts_sec - current_file_first_ts_sec_) >= policy_.rotate_seconds) {
            return true;
        }
    }
    return false;
}

void RotatingPcapWriter::rotate() {
    // The file being closed becomes eligible for eviction (evict_as_needed(), called from
    // write_packet() right after this) -- but never itself: this push happens BEFORE open_new_file()
    // makes a different path the active one, so closed_files_ never contains the currently-active
    // file's own path.
    closed_files_.push_back(RotatingPcapWriterFile{current_path_, current_bytes_});
    writer_.reset();  // close the old file's handle before opening the new one
    open_new_file();
}

void RotatingPcapWriter::evict_as_needed() {
    auto evict_oldest = [this]() {
        const RotatingPcapWriterFile& victim = closed_files_.front();
        if (std::remove(victim.path.c_str()) != 0) {
            if (on_warning_) {
                on_warning_("failed to delete rotated capture file '" + victim.path +
                            "' while enforcing the configured retention cap -- it was left on disk "
                            "and will no longer count toward that cap, so actual disk use may exceed "
                            "what was configured until it is removed some other way");
            }
        }
        closed_files_.erase(closed_files_.begin());
    };

    if (policy_.max_files != 0) {
        // max_files counts EVERY file this writer has, including the one currently being written --
        // see RotationPolicy::max_files's own comment.
        while (closed_files_.size() + 1 > policy_.max_files && !closed_files_.empty()) {
            evict_oldest();
        }
    }
    if (policy_.max_total_bytes != 0) {
        auto total_bytes = [this]() {
            uint64_t sum = current_bytes_;
            for (const auto& f : closed_files_) sum += f.bytes;
            return sum;
        };
        while (total_bytes() > policy_.max_total_bytes && !closed_files_.empty()) {
            evict_oldest();
        }
    }
}

void RotatingPcapWriter::write_packet(const PcapPacket& pkt) {
    if (needs_rotation(pkt)) rotate();

    writer_->write_packet(pkt);
    if (current_packet_count_ == 0) current_file_first_ts_sec_ = pkt.ts_sec;
    current_bytes_ += kPcapRecordHeaderBytes + pkt.data.size();
    ++current_packet_count_;

    if (policy_.max_total_bytes != 0 || policy_.max_files != 0) evict_as_needed();
}

}  // namespace conduitscope
