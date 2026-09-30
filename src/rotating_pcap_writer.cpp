// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/rotating_pcap_writer.hpp"

#include <chrono>
#include <cstdio>   // std::remove
#include <cstring>  // std::strerror
#include <ctime>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>  // CreateFileA/CloseHandle/GetCurrentProcessId -- see
                       // try_create_exclusive_file()'s own comment for why this needs them.
#else
#include <cerrno>
#include <fcntl.h>     // open(), O_CREAT|O_EXCL
#include <unistd.h>    // close(), getpid()
#endif

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

// Filesystem-safe, sortable filename timestamp -- YYYYMMDDTHHMMSSffffffZ (microsecond resolution),
// always UTC (std::gmtime, never std::localtime: a sensor's rotated files should sort and compare
// consistently regardless of the host's own configured timezone, and avoid any DST-transition
// ambiguity). Deliberately NOT time_format.hpp's own formatters -- those are built for human-
// readable report text (e.g. "2023-11-15 03:46:40.000000Z", containing a colon and a space, both
// invalid in a Windows filename) rather than a filename component. Named by WALL-CLOCK time (the
// moment this process actually opened the file), not by any packet's own capture timestamp --
// deliberately mirroring dumpcap's/tcpdump's own ring-buffer file-naming convention (`-w
// trace-%Y%m%d%H%M%S.pcap`), which likewise names a rotated file by when the writer opened it, not
// by anything in the traffic itself. RotationPolicy::rotate_seconds (rotating_pcap_writer.hpp) is
// deliberately the opposite -- checked against packet timestamps, not wall-clock -- for the reasons
// documented on that field; the two are independent design choices, not in tension: this is purely
// a label, while rotate_seconds is the actual trigger deciding when a new label is needed at all.
//
// patch-282 security review finding F1: this used to be second-resolution only (YYYYMMDDTHHMMSSZ).
// The microsecond field added here is part of F1's fix, but -- on its own -- is NOT what actually
// closes the vulnerability: even microsecond resolution is finite, and two independent capture
// processes (or one process restarting fast enough) could still, in principle, land in the same
// microsecond. It exists to make an ACTUAL collision astronomically unlikely in the first place, so
// try_create_exclusive_file()'s retry loop below almost never has to do any work; the collision loop
// itself, not this timestamp's precision, is what makes the fix correct even in the worst case.
// `now` is always std::chrono::system_clock::now() for every real caller -- see build_candidate_
// path() below, the only caller -- EXCEPT when a test supplies a fixed value through
// RotatingPcapWriter's own TEST-ONLY now_source_ member (see that member's doc comment in
// rotating_pcap_writer.hpp) to deterministically reproduce patch-282 finding F1's exact collision
// scenario without depending on real-time timing luck.
std::string wall_clock_filename_timestamp(std::chrono::system_clock::time_point now) {
    // std::chrono::system_clock is the portable source of sub-second wall-clock time this codebase
    // otherwise has no need for (every other wall-clock read here, and in time_format.hpp, only
    // ever needed second resolution) -- no new platform-specific API needed for this half of the
    // fix, unlike the exclusive-create half below.
    std::time_t now_sec = std::chrono::system_clock::to_time_t(now);
    std::int64_t epoch_micros =
        std::chrono::duration_cast<std::chrono::microseconds>(now.time_since_epoch()).count();
    // epoch_micros is never negative for any real wall-clock time (this process didn't exist before
    // 1970), so plain modulo is safe here -- no sign-correction dance needed.
    auto micros_within_second = static_cast<long>(epoch_micros % 1000000);

    std::tm tm_utc{};
#ifdef _WIN32
    gmtime_s(&tm_utc, &now_sec);
#else
    gmtime_r(&now_sec, &tm_utc);
#endif
    char buf[64];
    std::snprintf(buf, sizeof(buf), "%04d%02d%02dT%02d%02d%02d%06ldZ", tm_utc.tm_year + 1900,
                  tm_utc.tm_mon + 1, tm_utc.tm_mday, tm_utc.tm_hour, tm_utc.tm_min, tm_utc.tm_sec,
                  micros_within_second);
    return std::string(buf);
}

std::string zero_pad(size_t value, int width) {
    char buf[32];
    std::snprintf(buf, sizeof(buf), "%0*zu", width, value);
    return std::string(buf);
}

// patch-282 security review finding F1's second ingredient: this process's own OS process ID,
// embedded in every filename this writer generates. Two capture processes that happen to share a
// --prefix and start within the same wall-clock microsecond (vanishingly unlikely, but see this
// file's own try_create_exclusive_file() comment for why "unlikely" is never good enough here on
// its own) still generate different filenames, since no two processes ever share a PID at the same
// time -- and, purely as an operational bonus, an operator staring at a directory full of rotated
// files can tell at a glance which ones came from which capture process without cross-referencing
// logs.
std::string current_process_id_string() {
#ifdef _WIN32
    return std::to_string(::GetCurrentProcessId());
#else
    return std::to_string(::getpid());
#endif
}

// Result of one attempt to atomically claim a filename -- see try_create_exclusive_file() below.
enum class ExclusiveCreateResult {
    kCreated,    // path did not exist a moment ago; now it does, empty, owned solely by this
                 // process -- safe for the caller to immediately hand to PcapWriter's own
                 // trunc-opening constructor, since there is nothing there yet to truncate away.
    kCollision,  // path was already taken. NOT an error -- see open_writer()'s own retry loop.
};

// The actual fix for F1's core vulnerability. Before this, a freshly-generated candidate filename
// was handed straight to PcapWriter's own std::ios::trunc-opening constructor -- correct and
// necessary for `decode -w`'s explicit, user-named output file (matching tcpdump's own `-w FILE`
// semantics: overwriting a file you named yourself is expected), but wrong here, where the name was
// never chosen by a human -- it was GENERATED, and generated names are exactly the ones that can
// collide: a second-resolution timestamp plus a per-process-instance counter that resets to 0 on
// every restart is not guaranteed unique across a sensor restarting within the same second, or two
// independent capture processes sharing a --prefix and starting within the same second. Either way,
// a second process's trunc-open of that same generated name would silently destroy the first
// process's already-written evidence -- exactly the "rotating capture can overwrite existing
// evidence" finding this function exists to close.
//
// A std::filesystem::exists()-then-open() check has the identical race in the opposite direction:
// two processes could both observe "does not exist" and both proceed to truncate-open the same name
// microseconds apart, since nothing stops a second check-then-open from interleaving with the first
// between its check and its open. This function instead calls straight into the one OS-level
// primitive that is actually atomic with respect to file creation -- POSIX O_CREAT|O_EXCL (the
// open() call itself fails with EEXIST if the name is already there; there is no window between
// "check" and "create" for another process to land in, because there is no separate check) and
// Windows' own CREATE_NEW disposition (identical guarantee). Whichever of two racing processes gets
// there first wins the name outright; the other sees a clean, well-defined collision and is
// expected to retry with a different candidate (open_writer() below does exactly that) rather than
// ever touching the winner's file.
//
// This codebase deliberately has no <filesystem> dependency (see baseline.cpp's own comment on
// why), so this reaches for the narrower <fcntl.h>/<windows.h> primitives directly instead -- the
// same "plain #ifdef _WIN32, no wide-string/UTF-16 conversion layer" posture cli_main.cpp's own
// stdout_is_terminal()/write_raw_color_reset_to_stdout() and this file's own
// wall_clock_filename_timestamp() already use for their own Windows-vs-POSIX primitive pairs --
// CreateFileA (the ANSI/narrow-string entry point) rather than CreateFileW, since every path this
// class ever builds is itself a narrow std::string already (`directory`/`prefix` come straight from
// CLI11 argv parsing, never a wide string anywhere in this codebase).
ExclusiveCreateResult try_create_exclusive_file(const std::string& path) {
#ifdef _WIN32
    HANDLE h = ::CreateFileA(path.c_str(), GENERIC_WRITE,
                              0,  // no sharing -- this process alone owns it until closed below
                              nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) {
        DWORD err = ::GetLastError();
        if (err == ERROR_FILE_EXISTS || err == ERROR_ALREADY_EXISTS) {
            return ExclusiveCreateResult::kCollision;
        }
        throw ParseError("cannot create '" + path + "' for writing (Windows error " +
                          std::to_string(err) + ")");
    }
    ::CloseHandle(h);
    return ExclusiveCreateResult::kCreated;
#else
    int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0644);
    if (fd < 0) {
        if (errno == EEXIST) {
            return ExclusiveCreateResult::kCollision;
        }
        throw ParseError("cannot create '" + path + "' for writing: " + std::strerror(errno));
    }
    ::close(fd);
    return ExclusiveCreateResult::kCreated;
#endif
}

}  // namespace

RotatingPcapWriter::RotatingPcapWriter(
    const std::string& directory, const std::string& prefix, uint32_t linktype, uint32_t snaplen,
    const RotationPolicy& policy, std::function<void(const std::string&)> on_warning,
    std::function<std::chrono::system_clock::time_point()> now_source)
    : directory_(directory),
      prefix_(prefix),
      linktype_(linktype),
      snaplen_(snaplen),
      policy_(policy),
      on_warning_(std::move(on_warning)),
      now_source_(std::move(now_source)) {
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

std::string RotatingPcapWriter::build_candidate_path(unsigned collision_attempt) const {
    // See now_source_'s own doc comment (rotating_pcap_writer.hpp) -- real callers never set it, so
    // this is std::chrono::system_clock::now() for every production writer.
    std::chrono::system_clock::time_point now =
        now_source_ ? now_source_() : std::chrono::system_clock::now();
    std::string name = prefix_ + "_" + wall_clock_filename_timestamp(now) + "_" +
                        current_process_id_string() + "_" + zero_pad(files_opened_, 6);
    // Only appended on an actual retry (see open_writer()'s own comment on when this can happen at
    // all) -- the ordinary, overwhelmingly common case has no "-N" suffix, keeping the documented
    // "<prefix>_<timestamp>_<pid>_<counter>.pcap" shape exact.
    if (collision_attempt != 0) {
        name += "-" + std::to_string(collision_attempt);
    }
    return directory_ + "/" + name + ".pcap";
}

// See this function's own doc comment in rotating_pcap_writer.hpp for the full "why" (patch-282
// security review finding F1). Touches no member state at all -- open_new_file()/rotate() below
// decide what to do with the result, including on failure.
std::pair<std::string, std::unique_ptr<PcapWriter>> RotatingPcapWriter::open_writer() const {
    // Bounded, not unbounded: an unbounded retry loop driven entirely by filenames this process
    // itself just generated would only ever loop this many times in a genuine adversarial scenario
    // (something else in the same directory deliberately pre-creating every candidate name this
    // process could possibly generate within one microsecond+PID+counter combination, which is not
    // a realistic accident) -- 1000 attempts is generous headroom over the "two processes, one
    // restart" collisions this fix actually targets (which resolve on attempt 1) while still
    // guaranteeing this never hangs a `capture` process that's supposed to run unattended for weeks.
    constexpr unsigned kMaxCollisionAttempts = 1000;
    for (unsigned attempt = 0; attempt < kMaxCollisionAttempts; ++attempt) {
        std::string candidate = build_candidate_path(attempt);
        if (try_create_exclusive_file(candidate) == ExclusiveCreateResult::kCollision) {
            continue;  // someone else already owns this exact name -- try the next candidate
        }
        // This process now exclusively owns `candidate`, empty, on disk -- nothing else could have
        // written to it first (see try_create_exclusive_file()'s own comment). PcapWriter's own
        // std::ios::trunc open immediately below is therefore safe: there is nothing to truncate
        // away. If PcapWriter itself then fails (e.g. a permission change in the instant between our
        // claim and this reopen -- exceedingly unlikely, but not impossible), clean up the empty
        // file we claimed rather than leaving inexplicable litter behind for the next collision scan
        // to trip over, then let the failure propagate exactly like any other open failure.
        try {
            return {candidate, std::make_unique<PcapWriter>(candidate, linktype_, snaplen_)};
        } catch (...) {
            std::remove(candidate.c_str());  // best-effort; failure here doesn't change the outcome
            throw;
        }
    }
    throw ParseError(
        "RotatingPcapWriter: could not claim a unique capture filename under '" + directory_ +
        "' after " + std::to_string(kMaxCollisionAttempts) +
        " attempts -- every generated candidate name was already taken, which is not expected "
        "under normal operation; check for something else pre-creating files in this directory");
}

void RotatingPcapWriter::open_new_file() {
    auto [path, writer] = open_writer();  // throws ParseError on failure; nothing below has run yet
    writer_ = std::move(writer);
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
    std::string new_path;
    std::unique_ptr<PcapWriter> new_writer;
    try {
        auto opened = open_writer();
        new_path = std::move(opened.first);
        new_writer = std::move(opened.second);
    } catch (const ParseError& e) {
        throw ParseError(
            "RotatingPcapWriter: rotation failed -- could not open a new capture file: " +
            std::string(e.what()) +
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
