// SPDX-License-Identifier: Apache-2.0
// rotating_pcap_writer_selftest.cpp - a small, standalone executable (not the `conduitscope` CLI
// itself), modeled directly on tools/resource_limits_selftest.cpp's own shape, that exercises
// RotatingPcapWriter's (rotating_pcap_writer.hpp) rotation/retention bookkeeping directly against
// synthetic packets rather than a real capture.
//
// WHY THIS EXISTS AS ITS OWN TOOL, RATHER THAN A PCAP FIXTURE PLUS A CLI-DRIVEN CTest CASE: the
// `capture` subcommand's own CTest coverage (CMakeLists.txt) proves the CLI wiring end-to-end
// against a handful of real packets on the loopback interface, the same way tests/live_capture_
// max_packets_smoke.sh already does for --max-packets. But rotation/retention correctness is a
// question of exact byte counts and exact rotation boundaries across MANY packets and MANY
// combinations of triggers/caps -- reliably constructing "exactly 5 packets, each landing in its
// own file, with a retention cap that keeps exactly 2 of them" out of real captured traffic (timing
// each packet's arrival, its exact wire size, waiting out real wall-clock seconds for a
// --rotate-seconds test) would be slow and flaky in a way a CTest run should never be. Constructing
// synthetic PcapPacket values directly, with an exact chosen size and an exact chosen timestamp,
// makes every one of these scenarios exact and instant -- the same reason resource_limits_selftest
// constructs its own Decoder instances directly rather than trying to coax the CLI into the same
// scenario.
//
// Writes real files to a scratch directory (CMakeLists.txt creates it via file(MAKE_DIRECTORY ...)
// before this test runs, and passes its path as argv[1]) -- this codebase deliberately has no
// <filesystem> dependency (see baseline.cpp's own comment on why), so this test never lists a
// directory's contents; it only ever opens a path it already knows (via RotatingPcapWriter's own
// current_path()/files() accessors) with a plain std::ifstream, to confirm a file that should still
// be on disk opens, and a file that should have been evicted no longer does.
//
// Every success-path check below also asserts on_warning is NEVER called on that path, which is
// itself a real check (a spurious warning during ordinary, correctly-configured operation would be
// a bug). Checks 12-14 (patch257 security review finding 2, "continuous capture: disk exhaustion
// and rotation-boundary behavior") go further and force GENUINE failures deterministically, without
// needing an actually-full disk or a non-root privilege level this sandbox doesn't have (see e.g.
// unlink()'s own "only checks the containing directory's write permission, not the file's own"
// behavior, which defeats a chmod-based approach when running as root, as this sandbox does):
// check 13 deletes a rotated file out from under the writer BEFORE retention eviction runs, so
// std::remove() on it genuinely fails with ENOENT regardless of privilege; check 14 renames the
// writer's own target directory away between packets (POSIX-only -- see that check's own comment
// for why), so opening a REPLACEMENT file during rotation genuinely fails with ENOENT the same way
// a disk-full or permission-revoked condition would from this class's own point of view, without
// needing to actually exhaust real disk space.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as resource_limits_selftest/protocol_result_selftest/crypto_selftest.
#include <chrono>
#include <cstdio>
#include <fstream>
#include <iterator>
#include <string>

#ifndef _WIN32
#include <sys/stat.h>
#include <sys/types.h>
#endif
#include <vector>

#include "conduitscope/rotating_pcap_writer.hpp"

namespace {

int g_failures = 0;

void check_bool(const std::string& name, bool ok) {
    if (ok) {
        std::printf("PASS  %s\n", name.c_str());
    } else {
        std::printf("FAIL  %s\n", name.c_str());
        ++g_failures;
    }
}

conduitscope::PcapPacket make_packet(uint32_t ts_sec, size_t payload_len, uint8_t fill = 0x41) {
    conduitscope::PcapPacket pkt;
    pkt.ts_sec = ts_sec;
    pkt.ts_frac = 0;
    pkt.data.assign(payload_len, fill);
    pkt.captured_len = static_cast<uint32_t>(payload_len);
    pkt.original_len = static_cast<uint32_t>(payload_len);
    return pkt;
}

bool file_exists(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return in.good();
}

// Reads a whole file's raw bytes -- used only by the F1 collision checks below to prove a
// surviving file's CONTENT (not just its existence/size) is exactly what its own writer put there,
// never contaminated by a second writer that raced for the same generated name.
std::vector<char> read_file_bytes(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    return std::vector<char>((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

}  // namespace

int main(int argc, char** argv) {
    using namespace conduitscope;

    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <scratch directory, already created and writable>\n", argv[0]);
        return 1;
    }
    const std::string scratch_dir = argv[1];

    constexpr uint32_t kLinkType = 1;  // LINKTYPE_ETHERNET (pcap_reader.hpp) -- arbitrary, unused
                                        // by RotatingPcapWriter itself, just forwarded to PcapWriter.
    constexpr size_t kPayloadLen = 10;
    // Every synthetic packet below has this exact on-disk record size (16-byte classic-pcap record
    // header + kPayloadLen bytes of payload -- see pcap_writer.cpp's own write_packet), and every
    // file starts with the classic-pcap format's own fixed 24-byte global header (same file) --
    // both mirrored here as named constants so every check below's expected byte counts are
    // self-documenting rather than magic numbers.
    constexpr uint64_t kRecordBytes = 16 + kPayloadLen;
    constexpr uint64_t kHeaderBytes = 24;

    // 1. No rotation policy at all (RotationPolicy{}, every field 0): behaves like a single
    // ever-growing file, exactly like a plain PcapWriter would -- never rotates, whatever the
    // caller does with on_warning.
    {
        int warnings = 0;
        RotatingPcapWriter writer(scratch_dir, "test1", kLinkType, 65535, RotationPolicy{},
                                   [&](const std::string&) { ++warnings; });
        writer.write_packet(make_packet(1000, kPayloadLen));
        writer.write_packet(make_packet(1001, kPayloadLen));
        writer.write_packet(make_packet(1002, kPayloadLen));
        check_bool("no policy: never rotates across 3 packets", writer.rotation_count() == 0);
        check_bool("no policy: current_bytes() reflects header + 3 records",
                   writer.current_bytes() == kHeaderBytes + 3 * kRecordBytes);
        check_bool("no policy: files() (closed files) stays empty", writer.files().empty());
        check_bool("no policy: current file is actually on disk and openable",
                   file_exists(writer.current_path()));
        check_bool("no policy: on_warning is never called on the ordinary success path",
                   warnings == 0);
    }

    // 2. Size-based rotation only, no retention cap: rotate_bytes set to exactly one record's worth
    // past the global header, so every packet after the first in a file immediately rotates -- each
    // of 3 packets lands in its own file.
    {
        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + kRecordBytes;  // exactly one record fits per file
        int warnings = 0;
        RotatingPcapWriter writer(scratch_dir, "test2", kLinkType, 65535, policy,
                                   [&](const std::string&) { ++warnings; });
        writer.write_packet(make_packet(2000, kPayloadLen));  // file 1 (no rotation check yet)
        std::string file1_path = writer.current_path();
        writer.write_packet(make_packet(2001, kPayloadLen));  // rotates to file 2, then writes
        std::string file2_path = writer.current_path();
        writer.write_packet(make_packet(2002, kPayloadLen));  // rotates to file 3, then writes

        check_bool("size rotation: 3 packets each triggering their own file rotate twice",
                   writer.rotation_count() == 2);
        check_bool("size rotation: file 1 and file 2 both closed and tracked",
                   writer.files().size() == 2);
        check_bool("size rotation: file 1 got exactly one record's worth of bytes",
                   writer.files()[0].path == file1_path &&
                       writer.files()[0].bytes == kHeaderBytes + kRecordBytes);
        check_bool("size rotation: file 2 got exactly one record's worth of bytes",
                   writer.files()[1].path == file2_path &&
                       writer.files()[1].bytes == kHeaderBytes + kRecordBytes);
        check_bool("size rotation: the active (3rd) file also has exactly one record's worth so far",
                   writer.current_bytes() == kHeaderBytes + kRecordBytes);
        check_bool("size rotation: no retention cap configured, so nothing was ever deleted -- "
                   "file 1 is still on disk",
                   file_exists(file1_path));
        check_bool("size rotation: file 2 is still on disk too",
                   file_exists(file2_path));
        check_bool("size rotation: on_warning is never called with no retention cap configured",
                   warnings == 0);
    }

    // 3. A single packet larger than rotate_bytes still gets written (never an infinite rotate
    // loop) -- see RotationPolicy::rotate_bytes's own comment on always writing at least one packet
    // per file.
    {
        RotationPolicy policy;
        policy.rotate_bytes = 10;  // smaller than even one record
        RotatingPcapWriter writer(scratch_dir, "test3", kLinkType, 65535, policy);
        writer.write_packet(make_packet(3000, kPayloadLen));
        check_bool("size rotation smaller than one record: the oversized packet is still written, "
                   "not silently dropped or looped forever",
                   writer.current_bytes() == kHeaderBytes + kRecordBytes);
        check_bool("size rotation smaller than one record: still only the one file so far "
                   "(rotation only happens before the NEXT packet)",
                   writer.rotation_count() == 0);
        writer.write_packet(make_packet(3001, kPayloadLen));
        check_bool("size rotation smaller than one record: the second oversized packet does force "
                   "a rotation (the file already had one record in it)",
                   writer.rotation_count() == 1);
    }

    // 4. Time-based rotation only: packets within the window stay in one file; a packet at/after
    // the window's own duration past the file's first packet rotates.
    {
        RotationPolicy policy;
        policy.rotate_seconds = 10;
        RotatingPcapWriter writer(scratch_dir, "test4", kLinkType, 65535, policy);
        writer.write_packet(make_packet(1000, kPayloadLen));  // file 1's first packet
        writer.write_packet(make_packet(1005, kPayloadLen));  // +5s, stays in file 1
        writer.write_packet(make_packet(1009, kPayloadLen));  // +9s, stays in file 1
        check_bool("time rotation: 3 packets within the 10s window stay in one file",
                   writer.rotation_count() == 0);
        writer.write_packet(make_packet(1010, kPayloadLen));  // +10s from file 1's first -- rotates
        check_bool("time rotation: a packet exactly at the window boundary rotates",
                   writer.rotation_count() == 1);
        check_bool("time rotation: the file that just closed has exactly the first 3 packets",
                   writer.files().back().bytes == kHeaderBytes + 3 * kRecordBytes);
        writer.write_packet(make_packet(1015, kPayloadLen));  // +5s from file 2's own first -- stays
        check_bool("time rotation: a packet within the new file's own window doesn't rotate again",
                   writer.rotation_count() == 1);
        check_bool("time rotation: the active file now has the last 2 packets",
                   writer.current_bytes() == kHeaderBytes + 2 * kRecordBytes);
    }

    // 5. An out-of-order (backward-in-time) packet never triggers time-based rotation on its own.
    {
        RotationPolicy policy;
        policy.rotate_seconds = 10;
        RotatingPcapWriter writer(scratch_dir, "test5", kLinkType, 65535, policy);
        writer.write_packet(make_packet(2000, kPayloadLen));  // file 1's first packet
        writer.write_packet(make_packet(1000, kPayloadLen));  // earlier than file 1's first packet
        check_bool("time rotation: a packet timestamped before the file's own first packet never "
                   "rotates on its own",
                   writer.rotation_count() == 0);
        check_bool("time rotation: that out-of-order packet is still written into the same file",
                   writer.current_bytes() == kHeaderBytes + 2 * kRecordBytes);
    }

    // 6. Retention by max_files: keeps at most N files TOTAL (closed files + the active one).
    {
        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + kRecordBytes;  // one packet per file, as in check 2
        policy.max_files = 2;                               // 1 closed + 1 active, at most
        int warnings = 0;
        RotatingPcapWriter writer(scratch_dir, "test6", kLinkType, 65535, policy,
                                   [&](const std::string&) { ++warnings; });
        std::vector<std::string> paths;
        for (uint32_t i = 0; i < 5; ++i) {
            writer.write_packet(make_packet(4000 + i, kPayloadLen));
            paths.push_back(writer.current_path());
        }
        check_bool("max_files retention: 5 packets opened 5 files total (4 rotations)",
                   writer.rotation_count() == 4);
        check_bool("max_files retention: only 1 closed file is kept (2 total including active)",
                   writer.files().size() == 1);
        check_bool("max_files retention: the one kept closed file is the MOST RECENTLY closed one "
                   "(file 4, not file 1)",
                   writer.files()[0].path == paths[3]);
        check_bool("max_files retention: the earliest 3 files were actually deleted from disk",
                   !file_exists(paths[0]) && !file_exists(paths[1]) && !file_exists(paths[2]));
        check_bool("max_files retention: the kept closed file is still really on disk",
                   file_exists(paths[3]));
        check_bool("max_files retention: the active (5th) file is still on disk",
                   file_exists(paths[4]));
        check_bool("max_files retention: on_warning never fires when every delete succeeds",
                   warnings == 0);
    }

    // 7. Retention by max_total_bytes, independent of max_files (byte-cap-only branch).
    {
        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + kRecordBytes;         // one packet per file
        policy.max_total_bytes = 2 * (kHeaderBytes + kRecordBytes);  // room for ~2 files, not 3+
        RotatingPcapWriter writer(scratch_dir, "test7", kLinkType, 65535, policy);
        std::vector<std::string> paths;
        for (uint32_t i = 0; i < 4; ++i) {
            writer.write_packet(make_packet(5000 + i, kPayloadLen));
            paths.push_back(writer.current_path());
        }
        check_bool("max_total_bytes retention: only enough closed files are kept to stay under the "
                   "byte cap (1 closed + 1 active, same shape as the max_files case above)",
                   writer.files().size() == 1 && writer.files()[0].path == paths[2]);
        check_bool("max_total_bytes retention: the earliest 2 files were deleted",
                   !file_exists(paths[0]) && !file_exists(paths[1]));
        check_bool("max_total_bytes retention: the kept closed file and the active file remain",
                   file_exists(paths[2]) && file_exists(paths[3]));
    }

    // 8. The active file is NEVER evicted, even if it alone already exceeds max_total_bytes (a
    // deliberately pathological config: a huge rotate_bytes combined with a tiny max_total_bytes).
    {
        RotationPolicy policy;
        policy.rotate_bytes = 100000;  // large enough that these packets never rotate on size
        policy.max_total_bytes = 1;    // smaller than even the global header alone
        RotatingPcapWriter writer(scratch_dir, "test8", kLinkType, 65535, policy);
        writer.write_packet(make_packet(6000, kPayloadLen));
        writer.write_packet(make_packet(6001, kPayloadLen));
        check_bool("active file is exempt from eviction: still the only file (no rotation "
                   "happened, nothing to evict)",
                   writer.rotation_count() == 0 && writer.files().empty());
        check_bool("active file is exempt from eviction: it is still on disk despite exceeding "
                   "max_total_bytes on its own",
                   file_exists(writer.current_path()));
    }

    // 9. Both triggers configured together: whichever fires first rotates (OR, not AND).
    {
        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + 2 * kRecordBytes;  // room for 2 records per file
        policy.rotate_seconds = 100;                            // generous, shouldn't fire first here
        RotatingPcapWriter writer(scratch_dir, "test9", kLinkType, 65535, policy);
        writer.write_packet(make_packet(7000, kPayloadLen));
        writer.write_packet(make_packet(7001, kPayloadLen));
        check_bool("combined triggers: 2 packets still fit in one file (size cap not yet hit)",
                   writer.rotation_count() == 0);
        writer.write_packet(make_packet(7002, kPayloadLen));  // 3rd record -- size cap fires first
        check_bool("combined triggers: the size trigger fires before the generous time trigger "
                   "would have",
                   writer.rotation_count() == 1);
    }

    // 10. Construction-time validation: a retention cap with no rotation trigger at all is refused.
    {
        RotationPolicy policy;
        policy.max_files = 5;  // rotate_bytes/rotate_seconds both left at 0
        bool threw = false;
        try {
            RotatingPcapWriter writer(scratch_dir, "test10", kLinkType, 65535, policy);
            (void)writer;
        } catch (const ParseError&) {
            threw = true;
        }
        check_bool("construction refuses max_files with no rotation trigger configured", threw);
    }
    {
        RotationPolicy policy;
        policy.max_total_bytes = 1000;  // rotate_bytes/rotate_seconds both left at 0
        bool threw = false;
        try {
            RotatingPcapWriter writer(scratch_dir, "test10b", kLinkType, 65535, policy);
            (void)writer;
        } catch (const ParseError&) {
            threw = true;
        }
        check_bool("construction refuses max_total_bytes with no rotation trigger configured", threw);
    }
    {
        // The mirror image: a rotation trigger with NO retention cap at all is perfectly legal
        // (check 2 above already covers this implicitly, but a dedicated non-throwing check here
        // documents it explicitly as a deliberate, not merely untested, allowance).
        RotationPolicy policy;
        policy.rotate_bytes = 1000;
        bool threw = false;
        try {
            RotatingPcapWriter writer(scratch_dir, "test10c", kLinkType, 65535, policy);
            (void)writer;
        } catch (const ParseError&) {
            threw = true;
        }
        check_bool("construction allows a rotation trigger with no retention cap at all", !threw);
    }

    // 11. Construction-time validation: a bad directory is reported immediately (fail fast), the
    // same posture as PcapWriter's own constructor.
    {
        bool threw = false;
        try {
            RotatingPcapWriter writer(scratch_dir + "/this-directory-does-not-exist", "test11",
                                       kLinkType, 65535, RotationPolicy{});
            (void)writer;
        } catch (const ParseError&) {
            threw = true;
        }
        check_bool("construction against a nonexistent directory throws immediately", threw);
    }

    // 12. patch257 security review finding 2's own recommendation: "define and test the maximum
    // overshoot explicitly." Checks 2/3 above already demonstrate an oversized packet is written
    // rather than dropped/looped; this quantifies exactly how far over rotate_bytes a file's real
    // size can go -- never more than the one packet that pushed it over, whatever that packet's own
    // size is.
    {
        constexpr uint64_t kPcapRecordHeaderBytes = 16;  // matches pcap_writer.cpp's own constant

        RotationPolicy policy;
        policy.rotate_bytes = 50;  // deliberately much smaller than one ordinary record
        RotatingPcapWriter writer(scratch_dir, "test12", kLinkType, 65535, policy);
        writer.write_packet(make_packet(8000, kPayloadLen));  // first packet, always written
        uint64_t overshoot = writer.current_bytes() - policy.rotate_bytes;
        check_bool("overshoot bound: an ordinary-sized packet's file never exceeds rotate_bytes by "
                   "more than exactly that one packet's own record size",
                   overshoot == kHeaderBytes + kRecordBytes - policy.rotate_bytes);

        // A second, much larger packet on a fresh file: the overshoot scales with THAT packet's own
        // size, still by exactly one packet's worth, never more -- proving the bound isn't a
        // coincidence of the specific small size chosen above.
        RotatingPcapWriter writer2(scratch_dir, "test12b", kLinkType, 65535, policy);
        constexpr size_t kHugePayload = 9000;
        writer2.write_packet(make_packet(8000, kHugePayload));
        uint64_t overshoot2 = writer2.current_bytes() - policy.rotate_bytes;
        check_bool("overshoot bound: scales with one oversized packet's own size, never more than "
                   "exactly that packet's own record size, however large",
                   overshoot2 == kHeaderBytes + kPcapRecordHeaderBytes + kHugePayload - policy.rotate_bytes);
    }

    // 13. A genuine eviction failure, forced deterministically and portably: rather than a
    // chmod-based permission trick (unlink() on POSIX only checks the containing directory's write
    // permission, not the file's own, and root -- which this sandbox runs as -- bypasses permission
    // checks outright, so that approach can't be forced at all here, see this tool's own file
    // header), this deletes a rotated file's bytes out from under the writer BEFORE retention
    // eviction ever gets to it, so std::remove() on it genuinely fails with ENOENT regardless of
    // privilege -- exactly the same failure shape as another process/tool having already removed
    // it, or a permission change on a lower-privilege deployment.
    {
        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + kRecordBytes;  // one packet per file
        policy.max_files = 2;                                // 1 closed + 1 active
        int warnings = 0;
        std::string last_warning;
        RotatingPcapWriter writer(scratch_dir, "test13", kLinkType, 65535, policy,
                                   [&](const std::string& msg) {
                                       ++warnings;
                                       last_warning = msg;
                                   });
        writer.write_packet(make_packet(9000, kPayloadLen));  // file 1
        std::string file1_path = writer.current_path();
        writer.write_packet(make_packet(9001, kPayloadLen));  // rotates: file 1 closes, file 2 active
        check_bool("eviction-failure setup: file 1 closed and tracked, not yet evicted (max_files=2 "
                   "allows 1 closed + 1 active)",
                   writer.files().size() == 1 && writer.files()[0].path == file1_path);
        check_bool("eviction-failure setup: no warning yet -- nothing has failed so far",
                   warnings == 0);

        // Delete file 1 ourselves, out from under the writer, before it ever tries to evict it.
        check_bool("eviction-failure setup: file 1 actually removed out from under the writer",
                   std::remove(file1_path.c_str()) == 0);

        // Rotates again: file 2 closes, file 3 becomes active -- retention now tries to evict file
        // 1 (already gone) to stay at max_files=2.
        writer.write_packet(make_packet(9002, kPayloadLen));

        check_bool("eviction failure: on_warning fires exactly once for the missing file",
                   warnings == 1);
        check_bool("eviction failure: the warning names the missing file and reports a running "
                   "total of 1 file failed so far",
                   last_warning.find(file1_path) != std::string::npos &&
                       last_warning.find("1 file(s)") != std::string::npos);
        check_bool("eviction failure: uneviction_failed_files()/uneviction_failed_bytes() reflect "
                   "that same running total directly, not just in the warning text",
                   writer.uneviction_failed_files() == 1 &&
                       writer.uneviction_failed_bytes() == kHeaderBytes + kRecordBytes);
        check_bool("eviction failure: the writer's own bookkeeping still drops the file from "
                   "files() either way, so it is never retried on every subsequent packet forever",
                   writer.files().size() == 1 && writer.files()[0].path != file1_path);
    }

#ifndef _WIN32
    // 14. Rotation failure is exception-safe (patch257 finding 2's own core fix). If opening the
    // REPLACEMENT file fails mid-rotation -- here, because this writer's own target directory has
    // been renamed away, simulating a disk-full/permission-revoked/directory-disappeared condition
    // without needing an actually-full disk or a non-root privilege level -- the writer must be
    // left fully intact and still usable against the file it was already writing: not null, not
    // double-tracked in files(), not crashed on the very next call. POSIX-only: renaming a
    // directory containing an open file handle behaves differently on Windows (share-mode
    // restrictions can block the rename outright), so this specific reproduction technique isn't
    // portable there -- the underlying fix itself (rotating_pcap_writer.cpp's own rotate()) is
    // platform-independent and applies everywhere regardless.
    {
        std::string dir_a = scratch_dir + "/test14_dir";
        std::string dir_moved = scratch_dir + "/test14_dir_moved";
        ::mkdir(dir_a.c_str(), 0755);

        RotationPolicy policy;
        policy.rotate_bytes = kHeaderBytes + kRecordBytes;  // one packet per file
        int warnings = 0;
        RotatingPcapWriter writer(dir_a, "test14", kLinkType, 65535, policy,
                                   [&](const std::string&) { ++warnings; });
        writer.write_packet(make_packet(10000, kPayloadLen));  // file 1, still open
        std::string file1_path = writer.current_path();

        check_bool("rotation-failure setup: renaming the directory away succeeds even with an open "
                   "file inside it (POSIX)",
                   std::rename(dir_a.c_str(), dir_moved.c_str()) == 0);

        bool threw = false;
        std::string message;
        try {
            writer.write_packet(make_packet(10001, kPayloadLen));  // triggers rotation -> fails
        } catch (const ParseError& e) {
            threw = true;
            message = e.what();
        }
        check_bool("rotation failure: attempting to rotate into a now-missing directory throws",
                   threw);
        check_bool("rotation failure: the exception names both the failed rotation and the still-"
                   "usable old file",
                   message.find("rotation failed") != std::string::npos &&
                       message.find(file1_path) != std::string::npos);
        check_bool("rotation failure: the writer's own state is untouched -- still on file 1, not "
                   "double-tracked as also already closed",
                   writer.current_path() == file1_path && writer.files().empty() &&
                       writer.rotation_count() == 0);
        check_bool("rotation failure: current_bytes() still reflects only the one packet that was "
                   "actually written -- the failed packet was never counted",
                   writer.current_bytes() == kHeaderBytes + kRecordBytes);

        // Move the directory back -- the underlying problem is "resolved" -- and prove the writer
        // recovers completely rather than staying wedged in whatever partial state the failure left
        // it in.
        check_bool("rotation-failure recovery setup: moving the directory back succeeds",
                   std::rename(dir_moved.c_str(), dir_a.c_str()) == 0);

        threw = false;
        try {
            writer.write_packet(make_packet(10002, kPayloadLen));  // rotation retried, now succeeds
        } catch (const ParseError&) {
            threw = true;
        }
        check_bool("rotation-failure recovery: retrying once the directory is back succeeds cleanly",
                   !threw);
        check_bool("rotation-failure recovery: file 1 is now properly closed and tracked, exactly "
                   "once -- no duplicate entry left over from the failed attempt",
                   writer.files().size() == 1 && writer.files()[0].path == file1_path &&
                       writer.rotation_count() == 1);
        check_bool("rotation-failure recovery: file 1 is still readable on disk with its one "
                   "packet intact",
                   file_exists(file1_path));
        check_bool("rotation failure: on_warning is never called for a rotation failure -- that's a "
                   "fatal-to-this-attempt ParseError the caller must see directly, not a background "
                   "warning",
                   warnings == 0);
    }
#endif  // !_WIN32

    // 15-17. patch-282 security review finding F1 ("Rotating capture can overwrite existing
    // evidence"): a second-resolution timestamp plus a per-process-instance counter that resets to
    // 0 on every restart is not guaranteed unique across a sensor restarting within the same
    // second, or two independent capture processes sharing a --prefix and starting within the same
    // second -- and the OLD code handed every generated filename straight to PcapWriter's own
    // std::ios::trunc-opening constructor, so the second writer would silently destroy the first
    // writer's already-captured evidence. The fix: an atomic OS-level exclusive-create claim
    // (O_CREAT|O_EXCL/CREATE_NEW) before ever opening a generated name, retrying with a "-N" suffix
    // on an actual collision.
    //
    // Reproducing that exact collision deterministically -- without depending on real callers
    // happening to land in the same wall-clock microsecond, which would make this check flaky --
    // uses the TEST-ONLY now_source constructor parameter (rotating_pcap_writer.hpp) to give two
    // writer instances, already guaranteed the same PID (same test process) and the same
    // prefix/directory, an IDENTICAL fake "now": their very first generated candidate filename is
    // then an EXACT STRING MATCH, a real collision at the OS level, every single run.
    {
        // An arbitrary, fixed instant -- its actual value never matters, only that both writers
        // below are given the identical one.
        auto fixed_now = []() -> std::chrono::system_clock::time_point {
            return std::chrono::system_clock::time_point(std::chrono::seconds(1700000000));
        };

        auto contains_byte = [](const std::vector<char>& bytes, unsigned char needle) {
            for (char c : bytes) {
                if (static_cast<unsigned char>(c) == needle) return true;
            }
            return false;
        };

        // 15. "Two simultaneous writers" (patch-282's own named scenario): writer1 is deliberately
        // kept OPEN (not destroyed) while writer2 is constructed, simulating two capture processes
        // that are both genuinely running at once, not merely one after the other -- the collision
        // itself (writer2's construction discovering writer1's file already claimed) genuinely
        // happens while both are live. Both are held via unique_ptr, not a plain local, purely so
        // this test can explicitly .reset() (close/flush) them before reading their content back --
        // std::ofstream buffers writes in-process, so a raw re-read through a second, independent
        // std::ifstream handle while the writing stream is still open is not guaranteed to see
        // everything written yet, matching every real caller too (capture_rotation_smoke.sh, the
        // CLI-level end-to-end test, likewise only ever decodes a rotated file after the whole
        // `capture` process -- and therefore every PcapWriter inside it -- has already exited).
        auto writer1 = std::make_unique<RotatingPcapWriter>(scratch_dir, "collision", kLinkType,
                                                             65535, RotationPolicy{}, nullptr,
                                                             fixed_now);
        writer1->write_packet(make_packet(20000, kPayloadLen, 0xAA));  // "writer1's own evidence"
        std::string path1 = writer1->current_path();

        int warnings2 = 0;
        auto writer2 = std::make_unique<RotatingPcapWriter>(
            scratch_dir, "collision", kLinkType, 65535, RotationPolicy{},
            [&](const std::string&) { ++warnings2; }, fixed_now);
        writer2->write_packet(make_packet(20001, kPayloadLen, 0xBB));  // "writer2's own evidence"
        std::string path2 = writer2->current_path();

        check_bool("F1 fix: two writers with identical prefix/pid/timestamp inputs (a real, "
                   "guaranteed collision on their first candidate name) still land on two "
                   "DIFFERENT files -- the exclusive-create retry actually fired",
                   path1 != path2);
        check_bool("F1 fix: the second writer's own path carries the documented \"-1\" collision "
                   "suffix, not a silently-different unrelated name",
                   path2 == path1.substr(0, path1.size() - 5) + "-1.pcap");  // strip ".pcap", add "-1.pcap"
        check_bool("F1 fix: on_warning is never called for an ordinary, successfully-resolved "
                   "filename collision -- it is handled entirely internally, not surfaced as a "
                   "caller-visible problem",
                   warnings2 == 0);

        writer1.reset();  // close/flush both -- see this check's own comment above on why
        writer2.reset();

        // The critical assertion -- not just "different paths", but that writer1's own file still
        // holds EXACTLY writer1's own bytes: never truncated, never contaminated with writer2's.
        check_bool("F1 fix: writer1's evidence file still contains its OWN packet bytes (0xAA)",
                   contains_byte(read_file_bytes(path1), 0xAA));
        check_bool("F1 fix: writer1's evidence file was never contaminated with writer2's packet "
                   "bytes (0xBB) -- no cross-writer overwrite occurred",
                   !contains_byte(read_file_bytes(path1), 0xBB));
        check_bool("F1 fix: writer2's own file likewise holds only its own bytes (0xBB), not "
                   "writer1's (0xAA) -- both files are fully intact, independent evidence",
                   contains_byte(read_file_bytes(path2), 0xBB) &&
                       !contains_byte(read_file_bytes(path2), 0xAA));

        // 16. "Restart within the same second" (patch-282's own other named scenario) plus "a stale
        // file already present": writer3 is closed BEFORE writer4 is even constructed, simulating
        // the original process having already fully exited, the way a genuine restart would --
        // proving the fix holds even with no second live writer racing at the OS level at all, just
        // an ordinary stale file already sitting on disk from a finished previous run.
        auto writer3 = std::make_unique<RotatingPcapWriter>(scratch_dir, "restart", kLinkType,
                                                             65535, RotationPolicy{}, nullptr,
                                                             fixed_now);
        writer3->write_packet(make_packet(20002, kPayloadLen, 0xCC));
        std::string path3 = writer3->current_path();
        writer3.reset();  // the "original process" has now fully exited

        auto writer4 = std::make_unique<RotatingPcapWriter>(scratch_dir, "restart", kLinkType,
                                                             65535, RotationPolicy{}, nullptr,
                                                             fixed_now);
        writer4->write_packet(make_packet(20003, kPayloadLen, 0xDD));
        std::string path4 = writer4->current_path();
        writer4.reset();

        check_bool("F1 fix: a \"restarted\" writer (same prefix/pid/timestamp as a stale previous "
                   "run's own file) also lands on a different file rather than colliding",
                   path3 != path4);
        check_bool("F1 fix: the stale file left by the original run still holds only its own bytes "
                   "(0xCC), untouched by the restarted process's own write (0xDD)",
                   contains_byte(read_file_bytes(path3), 0xCC) &&
                       !contains_byte(read_file_bytes(path3), 0xDD));

        // 17. The retry loop itself, not just its single "-1" fallback: pre-claim BOTH the
        // attempt-0 and the attempt-1 ("-1") names before ever constructing a writer, proving the
        // loop keeps advancing (to "-2") rather than only ever handling exactly one collision.
        auto writer5 = std::make_unique<RotatingPcapWriter>(scratch_dir, "multicollision", kLinkType,
                                                             65535, RotationPolicy{}, nullptr,
                                                             fixed_now);
        writer5->write_packet(make_packet(20004, kPayloadLen, 0xEE));
        std::string path5 = writer5->current_path();
        writer5.reset();
        std::string path5_suffix1 = path5.substr(0, path5.size() - 5) + "-1.pcap";
        // Manually pre-claim the "-1" candidate too, exactly as if a THIRD racing writer had already
        // taken it -- plain std::ofstream is fine here, this is test setup, not the code under test.
        {
            std::ofstream pre(path5_suffix1, std::ios::binary);
            pre << "pre-existing-1";
        }

        auto writer6 = std::make_unique<RotatingPcapWriter>(scratch_dir, "multicollision", kLinkType,
                                                             65535, RotationPolicy{}, nullptr,
                                                             fixed_now);
        writer6->write_packet(make_packet(20005, kPayloadLen, 0xFF));
        std::string path6 = writer6->current_path();
        writer6.reset();

        check_bool("F1 fix: with BOTH the plain name and its \"-1\" retry already taken, a third "
                   "writer advances to \"-2\" rather than failing or looping forever",
                   path6 == path5.substr(0, path5.size() - 5) + "-2.pcap");
        check_bool("F1 fix: the manually pre-claimed \"-1\" file (simulating yet another racing "
                   "writer) was never touched by writer6's own open attempt",
                   read_file_bytes(path5_suffix1) ==
                       std::vector<char>{'p', 'r', 'e', '-', 'e', 'x', 'i', 's', 't', 'i', 'n', 'g',
                                         '-', '1'});
    }

    std::printf("\n%d check(s) failed\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
