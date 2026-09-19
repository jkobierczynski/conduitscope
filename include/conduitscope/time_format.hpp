// SPDX-License-Identifier: Apache-2.0
// time_format.hpp - the `decode` command's own per-packet timestamp rendering (`-t`/
// --time-format, --time-offset), as opposed to format_millis_epoch (mqtt.hpp/mqtt.cpp), which
// renders a timestamp *value decoded from inside a protocol's own payload* (Sparkplug B/DNP3
// Group 50) and is unrelated to this file.
//
// Mirrors tshark's own `-t <fmt>` mnemonics (see `tshark -h`'s "-t ad|a|r|d|dd|e|u|ud" list) for
// the subset that maps cleanly onto a single-flow-at-a-time CLI decoder with no display-filter
// concept of its own (so `dd`, tshark's "delta from the previously *displayed*, rather than
// captured, packet", has no equivalent here -- every packet this decoder emits already went
// through the same one --protocol/--filter gate, so "displayed" and "captured" never diverge):
//   e   / epoch          -- raw seconds.microseconds since the Unix epoch (today's existing/
//                            default rendering, byte-for-byte unchanged)
//   r   / relative       -- seconds.microseconds elapsed since the first packet in this decode
//   d   / delta          -- seconds.microseconds elapsed since the previous packet (0.000000 for
//                            the very first packet, matching tshark/tcpdump's own convention)
//   a   / absolute       -- HH:MM:SS.ffffff (no date), per --time-offset
//   ad  / absolute-date  -- YYYY-MM-DD HH:MM:SS.ffffff, per --time-offset
// --time-offset is this decoder's own extension beyond tshark/tcpdump (neither offers anything
// past UTC-vs-local) -- accepts "utc" (default), "local" (the analysis machine's own system
// timezone, DST-aware), or a fixed "+HH:MM"/"-HH:MM" offset, so a capture can be read in the
// timezone of the site it came from regardless of where it's being analyzed. Applies only to
// `absolute`/`absolute-date`; every other format is offset-independent by definition.
#pragma once

#include <optional>
#include <string>

namespace conduitscope {

enum class TimeFormat {
    Epoch,
    Relative,
    Delta,
    Absolute,
    AbsoluteDate,
};

// Parses a --time-format value -- either tshark's own short mnemonic (e/r/d/a/ad) or this
// decoder's own longer synonym (epoch/relative/delta/absolute/absolute-date), case-sensitive
// (CLI11's ->transform(CLI::IsMember(...)) at the call site already normalizes/validates before
// this ever runs -- see cli_main.cpp). Returns std::nullopt only if called directly with
// something CLI11 wouldn't have accepted in the first place.
std::optional<TimeFormat> parse_time_format(const std::string& text);

// This decoder's own extension of tshark/tcpdump's UTC-vs-local choice (see this file's header
// comment) -- `use_local_tz` selects the analysis machine's system timezone (std::localtime,
// DST-aware) when true; otherwise `offset_seconds` (east-of-UTC, 0 for plain UTC) is added to the
// raw epoch value before rendering via std::gmtime, the same "shift then render as UTC" trick
// this codebase has no prior need for (every existing gmtime-based renderer -- format_millis_epoch
// et al. -- is UTC-only) but which generalizes it to an arbitrary fixed zone.
struct TimeOffset {
    bool use_local_tz = false;
    int offset_seconds = 0;  // ignored when use_local_tz is true
};

// Parses a --time-offset value: "utc" (the default -- TimeOffset{false, 0}), "local"
// (TimeOffset{true, 0}), or a fixed signed offset -- "+HH:MM"/"-HH:MM" (also accepts "+HHMM"/
// "-HHMM" and a bare "+H"/"-H" hour count). Returns std::nullopt on anything else so the CLI
// layer can report a clear error instead of silently falling back to UTC.
std::optional<TimeOffset> parse_time_offset(const std::string& text);

// Renders one packet's timestamp (seconds since the Unix epoch, from the pcap record header --
// DecodedPacket::timestamp) as text, per `format`/`offset` -- see this file's header comment for
// what each TimeFormat/TimeOffset does. `first_ts`/`prev_ts` are this decode's first-seen and
// previous-packet timestamps (both equal to `ts` itself on the very first packet, which is what
// makes Relative/Delta both correctly read 0.000000 there -- see TimeFormatter below, which
// tracks this bookkeeping so callers never have to).
//
// Absolute/AbsoluteDate fall back to the raw epoch value with an explanatory suffix, never a
// fabricated date, for a `ts` too far in the past/future for std::gmtime/std::localtime to
// represent -- the same graceful-fallback convention format_millis_epoch (mqtt.hpp/mqtt.cpp)
// already established elsewhere in this codebase.
std::string format_timestamp(double ts, TimeFormat format, const TimeOffset& offset, double first_ts,
                              double prev_ts);

// Small per-writer bookkeeping wrapper around format_timestamp: remembers this stream's
// first-seen and previous-packet timestamps across successive calls so every OutputWriter that
// renders a timestamp (TextWriter/JsonWriter/CsvWriter -- see output.hpp) just calls format(ts)
// once per packet, in packet order, without re-implementing the first-packet/previous-packet
// bookkeeping itself.
class TimeFormatter {
public:
    TimeFormatter(TimeFormat format = TimeFormat::Epoch, TimeOffset offset = TimeOffset{})
        : format_(format), offset_(offset) {}

    std::string format(double ts) {
        if (!seen_) {
            first_ts_ = ts;
            prev_ts_ = ts;
            seen_ = true;
        }
        std::string rendered = format_timestamp(ts, format_, offset_, first_ts_, prev_ts_);
        prev_ts_ = ts;
        return rendered;
    }

private:
    TimeFormat format_;
    TimeOffset offset_;
    bool seen_ = false;
    double first_ts_ = 0.0;
    double prev_ts_ = 0.0;
};

}  // namespace conduitscope
