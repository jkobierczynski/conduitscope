// SPDX-License-Identifier: Apache-2.0
// rotating_pcap_writer.hpp - a disk-bounded, rotation-capable pcap writer for the `capture`
// subcommand's continuous/unattended sensor mode (Grok review item 5, docs/reviews/2026-09-grok-
// ics-ot-improvement-areas.md: "runs for weeks on a rugged/air-gapped box", "rotates captures,
// does not fill the disk" -- see docs/design/sensor-mode.md for the full design record, including
// why this stays capture-only with no analysis running inside it and why multi-tap sites are
// handled as N independent single-interface processes plus a later merge step, not one process
// with shared live state).
//
// This is a thin composition wrapper around PcapWriter (pcap_writer.hpp), not a replacement for
// it: every actual byte written to disk still goes through an ordinary PcapWriter instance, one
// per rotated file, with the exact same classic-pcap-format/microsecond-resolution contract
// documented there. RotatingPcapWriter's own job is entirely bookkeeping -- deciding WHEN to close
// the current PcapWriter and open a new one, what to name each file, and which already-closed
// files to delete to stay under a configured disk budget -- so a caller (the `capture` subcommand)
// only ever calls write_packet() in a loop and never has to think about any of that itself.
//
// Deliberately does NOT decode or inspect packet contents in any way -- see this header's own
// scope note on RotationPolicy below and docs/design/sensor-mode.md's "capture-only rotator"
// scoping decision: every packet handed to write_packet() is written verbatim, in the same "raw
// bytes, unmodified" spirit PcapWriter's own header comment already documents for `decode -w`.
// Nothing in this file, or anywhere else in this codebase (grepped, confirmed empty), can transmit
// a packet onto the wire -- this class, like PcapWriter, only ever writes to a local file.
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <vector>

#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

class PcapWriter;

// Every field is a plain byte/second count -- no unit-suffix parsing (no "500MB"/"1h"), matching
// this codebase's existing --max-baseline-file-bytes/--max-* convention (cli_main.cpp) -- and every
// field's zero value means "this particular trigger/cap is off", also matching that convention (see
// --max-packets' own "0 = unlimited" precedent). All four fields off (the default-constructed
// RotationPolicy{}) is a legal, if unusual, configuration: RotatingPcapWriter then behaves exactly
// like a single ever-growing PcapWriter, never rotating and never evicting anything -- callers who
// want that degenerate behavior can just use PcapWriter directly instead, but it costs this class
// nothing to allow it.
//
// The one combination this class's constructor REJECTS (throws ParseError, before opening any
// file): a retention cap (max_total_bytes and/or max_files nonzero) with BOTH rotation triggers off
// (rotate_bytes == 0 && rotate_seconds == 0). With no rotation trigger there is only ever one file,
// which is always "the active file" and therefore -- per this class's own "never evict the active
// file" invariant, the one thing that actually keeps `capture` safe to point at a live decode
// process's own output directory -- can never be evicted either. Accepting that combination would
// silently defeat the entire "does not fill the disk" point of this class, so it is refused up
// front rather than quietly doing nothing.
struct RotationPolicy {
    // Rotate to a new file once the CURRENT file's written bytes (global header + every packet
    // record written so far) plus the next packet's own record would exceed this many bytes.
    // Checked before writing each packet, the same "check, then possibly rotate, then always
    // write" order tcpdump's/dumpcap's own -C uses -- so a file's real size can exceed this value
    // by up to one packet's worth (never by more), and a file always gets at least one packet
    // regardless of this value, even a packet whose own size already exceeds it -- otherwise a
    // single jumbo packet larger than rotate_bytes would rotate forever without ever making
    // progress. 0 = no size-based rotation.
    uint64_t rotate_bytes = 0;

    // Rotate to a new file once a packet's own capture timestamp (PcapPacket::ts_sec) is at least
    // this many seconds past the FIRST packet written into the current file. Deliberately checked
    // against each packet's own timestamp, not wall-clock/std::time -- this keeps rotation fully
    // deterministic for offline replay and for tools/rotating_pcap_writer_selftest.cpp's own
    // synthetic-timestamp tests (no real-time sleeping needed to prove a multi-hour rotation
    // policy actually rotates), and means a `capture` run reading real live traffic rotates on the
    // wall-clock time the traffic itself was seen, which is what a forensic reviewer actually wants
    // out of "this file covers roughly this time window" -- not whichever instant this process
    // happened to be scheduled to poll libpcap. A packet whose timestamp is BEFORE the current
    // file's first packet (a live capture is expected to be monotonic, but an offline replay or a
    // clock adjustment mid-capture might not be) never triggers rotation on its own; the file
    // simply keeps accumulating until a later, forward-in-time packet crosses the threshold. 0 = no
    // time-based rotation.
    uint64_t rotate_seconds = 0;

    // Retention, applied after every write_packet() call, oldest-file-first, and NEVER touching the
    // file currently being written (see this struct's own header comment on why that file is
    // always exempt): once the combined size of every OTHER rotated file this writer still has on
    // disk exceeds this many bytes, the oldest is deleted, repeated until back under the cap (or
    // only the active file is left, whichever comes first -- see write_packet()'s own comment on
    // what happens when the active file alone already exceeds this on its own). 0 = no size-based
    // retention cap.
    uint64_t max_total_bytes = 0;

    // Retention, applied the same way as max_total_bytes, by COUNT instead of size: once this
    // writer has more than this many files on disk IN TOTAL (every already-rotated file plus the
    // one currently being written), the oldest already-rotated file is deleted, repeated until at
    // or under the cap. A value of 1 keeps only the file currently being written -- every rotation
    // immediately deletes the file that was just closed. 0 = no count-based retention cap.
    uint64_t max_files = 0;
};

// One already-rotated (closed, fully written) file this writer still has on disk, oldest first --
// see RotatingPcapWriter::files() below. Never includes the file currently being written.
struct RotatingPcapWriterFile {
    std::string path;
    uint64_t bytes = 0;
};

// Not thread-safe, matching PcapWriter's own "one writer per file" contract -- one
// RotatingPcapWriter per capturing process, matching docs/design/sensor-mode.md's own "independent
// per-tap processes, no new concurrency anywhere" scoping decision for multi-tap sites.
class RotatingPcapWriter {
public:
    // directory: where every rotated file is written; must already exist (this class never creates
    //   it -- same "the caller's job to set up its own filesystem location" posture as PcapWriter's
    //   own constructor, which likewise never creates parent directories). Throws ParseError
    //   immediately (before returning) if the very first file can't be opened there, e.g. because
    //   the directory doesn't exist or isn't writable -- the same fail-fast-on-bad-setup posture
    //   every other constructor in this codebase that opens a file up front already has.
    // prefix: a filename prefix for every rotated file this writer creates (e.g. the tap point's
    //   interface name) -- passed through into the filename verbatim, so the caller is responsible
    //   for it already being filesystem-safe. cli_main.cpp's `capture` subcommand sanitizes
    //   -I/--interface (which on Windows/Npcap can itself contain '\', '{', '}' -- e.g.
    //   \Device\NPF_{GUID}) or an explicit --prefix before passing it here; this class does not
    //   re-validate it.
    // linktype/snaplen: forwarded to every PcapWriter this class opens internally -- same meaning
    //   as PcapWriter's own constructor parameters.
    // policy: see RotationPolicy above.
    // on_warning: called (never thrown) for a NON-fatal problem this writer encounters after
    //   startup -- currently only a failed eviction (e.g. another process holds the file open, or a
    //   permission problem). A `capture` run is meant to survive unattended for weeks; a single
    //   eviction failure should be reported, not crash a sensor that is otherwise working fine and
    //   will likely succeed at evicting that same file (or a later one) on its next attempt. Never
    //   called from within write_packet() for anything ELSE -- a failure to open/write the ACTIVE
    //   file (disk full, active file's own directory disappeared) still throws ParseError, the same
    //   as PcapWriter's own write_packet() does, since there is nothing this writer could usefully
    //   do instead of surfacing that to its caller. May be nullptr (the default) to discard
    //   warnings silently -- unusual for `capture` itself, which always supplies one, but harmless
    //   for e.g. tools/rotating_pcap_writer_selftest.cpp's own simpler checks.
    RotatingPcapWriter(const std::string& directory, const std::string& prefix, uint32_t linktype,
                        uint32_t snaplen, const RotationPolicy& policy,
                        std::function<void(const std::string&)> on_warning = nullptr);
    ~RotatingPcapWriter();

    RotatingPcapWriter(const RotatingPcapWriter&) = delete;
    RotatingPcapWriter& operator=(const RotatingPcapWriter&) = delete;

    // Rotates first if `pkt` crosses a configured trigger (see RotationPolicy above), then writes
    // it to whichever file is active afterward -- same "raw bytes, unmodified" contract as
    // PcapWriter::write_packet, which this delegates to. Then, if a retention cap is configured,
    // evicts oldest already-rotated files until back under cap (see RotationPolicy's own comments)
    // -- an eviction failure calls `on_warning` and otherwise stops counting that file against
    // future retention decisions (it is dropped from files() either way, so this writer does not
    // retry deleting the same file on every subsequent packet forever; the file itself is left in
    // place on disk when the delete itself failed).
    //
    // Throws ParseError if the active file can no longer be written to (see this class's own
    // on_warning comment for why that is NOT reported via on_warning instead).
    void write_packet(const PcapPacket& pkt);

    // Introspection, e.g. for `capture --stats`/end-of-run summaries.
    const std::string& current_path() const { return current_path_; }
    uint64_t current_bytes() const { return current_bytes_; }
    // Number of times this writer has rotated away from a previous file (0 while still on the
    // first file it ever opened).
    size_t rotation_count() const { return files_opened_ > 0 ? files_opened_ - 1 : 0; }
    // Every already-rotated file this writer still has on disk, oldest first. Never includes the
    // file current_path() names.
    const std::vector<RotatingPcapWriterFile>& files() const { return closed_files_; }

private:
    void open_new_file();
    bool needs_rotation(const PcapPacket& pkt) const;
    void rotate();
    void evict_as_needed();

    std::string directory_;
    std::string prefix_;
    uint32_t linktype_ = 0;
    uint32_t snaplen_ = 0;
    RotationPolicy policy_;
    std::function<void(const std::string&)> on_warning_;

    std::unique_ptr<PcapWriter> writer_;
    std::string current_path_;
    uint64_t current_bytes_ = 0;  // includes the 24-byte classic-pcap global header
    uint64_t current_packet_count_ = 0;
    uint32_t current_file_first_ts_sec_ = 0;
    size_t files_opened_ = 0;

    std::vector<RotatingPcapWriterFile> closed_files_;  // oldest first
};

}  // namespace conduitscope
