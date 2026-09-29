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

std::string RotatingPcapWriter::build_new_path() {
    return directory_ + "/" + prefix_ + "_" + wall_clock_filename_timestamp() + "_" +
           zero_pad(files_opened_, 6) + ".pcap";
}

// Purely constructs a PcapWriter at `path` -- touches no member state at all, so a caller can
// freely try this and handle failure before committing to anything. Split out of open_new_file()
// (which still does the constructor's own "open the very first file, then adopt it" job) so
// rotate() below can use the identical open logic while keeping the whole "close the old file /
// adopt the new one" transition atomic from an external observer's point of view -- see
// write_packet()'s own doc comment (rotating_pcap_writer.hpp) for the exact guarantee this buys.
std::unique_ptr<PcapWriter> RotatingPcapWriter::open_writer(const std::string& path) const {
    return std::make_unique<PcapWriter>(path, linktype_, snaplen_);
}

void RotatingPcapWriter::open_new_file() {
    std::string path = build_new_path();
    writer_ = open_writer(path);  // throws ParseError on failure; nothing below has run yet
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
    // patch257 security review finding 2's own exception-safety fix: open the REPLACEMENT file
    // FIRST, before touching any of this object's own state. Before this fix, the old file was
    // closed and pushed into closed_files_ unconditionally, THEN a new one was opened -- so a
    // failure to open the new file (disk full, the directory itself disappearing mid-run, a
    // permission change) left `writer_` null while current_path_/current_bytes_/etc. still
    // described the file that had JUST been pushed into closed_files_, violating this class's own
    // "closed_files_ never contains the currently-active file's own path" invariant and leaving the
    // next write_packet() call to dereference a null writer_ -- a crash, not a second clean
    // ParseError, the first time any caller tried to recover from a transient rotation failure
    // (e.g. retrying once whatever blocked the new file resolves itself). Opening first instead
    // means a failure here throws with the OLD file/state completely untouched: still open, still
    // active, still fully usable on the next call. See write_packet()'s own doc comment
    // (rotating_pcap_writer.hpp) for the exact guarantee this buys callers.
    std::string new_path = build_new_path();
    std::unique_ptr<PcapWriter> new_writer;
    try {
        new_writer = open_writer(new_path);
    } catch (const ParseError& e) {
        throw ParseError(
            "RotatingPcapWriter: rotation failed -- could not open a new capture file ('" +
            new_path +
            "'): " + e.what() +
            " -- the file already being written ('" + current_path_ +
            "') is untouched and this writer is still writing into it; capture coverage from this "
            "point on may be incomplete until the underlying problem (disk space, permissions, the "
            "directory itself) is resolved");
    }

    // The new file opened successfully -- now it's safe to commit: the file being closed becomes
    // eligible for eviction (evict_as_needed(), called from write_packet() right after this), but
    // never itself, since this push only ever happens once a DIFFERENT path is about to become the
    // active one.
    closed_files_.push_back(RotatingPcapWriterFile{current_path_, current_bytes_});
    writer_ = std::move(new_writer);
    current_path_ = new_path;
    current_bytes_ = kPcapGlobalHeaderBytes;
    current_packet_count_ = 0;
    current_file_first_ts_sec_ = 0;
    ++files_opened_;
}

void RotatingPcapWriter::evict_as_needed() {
    auto evict_oldest = [this]() {
        const RotatingPcapWriterFile& victim = closed_files_.front();
        if (std::remove(victim.path.c_str()) != 0) {
            // See uneviction_failed_bytes()/uneviction_failed_files()'s own comment
            // (rotating_pcap_writer.hpp) for why this writer stops counting the file against its
            // OWN retention accounting (bounded by design) while still tracking the running total
            // separately, for a caller/log watcher to notice actual on-disk usage silently drifting
            // above the configured cap over an unattended, weeks-long run.
            uneviction_failed_bytes_ += victim.bytes;
            ++uneviction_failed_files_;
            if (on_warning_) {
                on_warning_("failed to delete rotated capture file '" + victim.path +
                            "' while enforcing the configured retention cap -- it was left on disk "
                            "and will no longer count toward that cap, so actual disk use may exceed "
                            "what was configured until it is removed some other way (running total "
                            "this writer has failed to evict: " +
                            std::to_string(uneviction_failed_files_) + " file(s), " +
                            std::to_string(uneviction_failed_bytes_) + " byte(s))");
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
