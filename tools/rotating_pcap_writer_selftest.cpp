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
// Deliberately does NOT attempt to exercise a genuine eviction FAILURE (on_warning actually firing)
// -- reliably constructing an undeletable-but-still-writable file is OS/privilege-dependent (e.g.
// unlink() on POSIX only checks the containing directory's write permission, not the file's own,
// so this often can't be forced at all when running as root, which this sandbox does). Every
// success-path check below still asserts on_warning is NEVER called, which is itself a real check
// (a spurious warning during ordinary, correctly-configured operation would be a bug), just not a
// direct test of the failure branch itself -- flagged here rather than silently absent.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as resource_limits_selftest/protocol_result_selftest/crypto_selftest.
#include <cstdio>
#include <fstream>
#include <string>
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

    std::printf("\n%d check(s) failed\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
