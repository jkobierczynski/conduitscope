// SPDX-License-Identifier: Apache-2.0
// packet_range.hpp - `decode`'s own `--range` option: select which packets get decoded by their
// real position in the capture FILE, distinct from `-c,--max-packets` (which already covers "the
// first N") and `-f,--filter` (which already covers "matching this BPF expression"). See
// docs/DEVELOPMENT.md's ROADMAP item 78 for the research this design is based on: neither tshark
// nor tcpdump has an equivalent of their own -- tshark's own `-c` is "maximum packets to read,
// always from the start" (exactly what this codebase's `-c,--max-packets` already mirrors), and
// tcpdump has no notion of a stored, numbered packet list to select from at all. The actual prior
// art lives in a separate Wireshark-suite tool, `editcap`, whose own manual page documents
// trailing positional arguments -- "individual packet numbers separated by whitespace and/or
// ranges of packet numbers ... specified as start-end" -- used as a pre-processing pass to shrink
// a capture before handing it to tshark. `--range` is a direct decode-time equivalent of that same
// selection syntax, applied during decoding itself rather than requiring a separate tool and pass.
//
// Packet numbers are 1-based and count the packet's REAL position in the capture file -- the same
// numbering Wireshark's own frame list and this tool's own `decode` text output ("#<n>") already
// use -- never a position renumbered among whatever else also matched (`-f/--filter`, if combined).
// See PacketSource::next()'s own comment (cli_main.cpp) for why this codebase already treats "real
// file position" as the numbering worth preserving under a filter: the same reasoning applies here.
// Offline-only (`-r`), like editcap itself -- excluded from `-i` (live capture) at the CLI-option
// level (cli_main.cpp's `->excludes()`), since "select packet #N" presupposes a finished, numbered
// file to select from, not a still-arriving stream.
#pragma once

#include <cstddef>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace conduitscope {

// A parsed --range spec: a set of inclusive [start, end] intervals (1-based, start <= end),
// stored in the order they were written and NOT merged or deduplicated -- an overlapping or
// adjacent pair like "5-10,8-15" is kept as two separate intervals rather than coalesced.
// contains() gives the same answer either way, and merging would only matter for something like
// counting distinct packet numbers, which this type has no need to do.
class PacketRangeSpec {
public:
    // True if `packet_number` (1-based, real file position) falls inside any interval.
    bool contains(size_t packet_number) const;

    void add_interval(size_t start, size_t end) { intervals_.emplace_back(start, end); }

private:
    std::vector<std::pair<size_t, size_t>> intervals_;
};

// Parses a --range value: a comma-separated list of individual 1-based packet numbers and/or
// inclusive "start-end" ranges, e.g. "5,10-20,30-40" (see this file's header comment for the full
// syntax rationale). Returns std::nullopt on anything malformed -- an empty string, an empty
// token (a leading/trailing/doubled comma), a non-numeric token, a packet number of 0 (there is no
// packet #0 -- numbering is 1-based, matching Wireshark/editcap), or a "start-end" pair with
// end < start -- so the CLI layer can report a clear error instead of silently treating a typo as
// "select nothing" or "select everything".
std::optional<PacketRangeSpec> parse_packet_range(const std::string& text);

}  // namespace conduitscope
