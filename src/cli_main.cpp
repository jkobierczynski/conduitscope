// SPDX-License-Identifier: Apache-2.0
// cli_main.cpp - command-line interface, built on the vendored CLI11 header.
//
// See docs/MANUAL.md for the full option reference; --help at any level
// (top-level, `decode --help`, `policy validate --help`, ...) is generated
// from the same option definitions below, so the two should never drift
// far apart -- but the manual also explains the *why* behind choices like
// the protocol-detection heuristics, which --help intentionally keeps brief.
#include <CLI11.hpp>

#include <algorithm>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <csignal>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <iterator>
#include <memory>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX  // Keep windows.h from defining min()/max() macros that would shadow std::min/max
                   // in every header included below -- none of them use it today, but this is the
                   // standard defensive guard for pulling windows.h into a project that wasn't
                   // written expecting it, same reasoning live_capture.cpp already has for its own
                   // (unguarded, since it's the only Windows-specific header it needs) windows.h use.
#endif
#include <io.h>
#include <windows.h>  // SetConsoleCtrlHandler -- see SigintGuard's own comment for why
#else
#include <sys/ioctl.h>  // ioctl(TIOCGWINSZ) -- see terminal_width() below
#include <unistd.h>
#endif

#include "conduitscope/asset_inventory.hpp"
#include "conduitscope/baseline.hpp"
#include "conduitscope/detect_engine.hpp"
#include "conduitscope/bpf_filter.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/display_filter.hpp"
#include "conduitscope/evidence_report.hpp"
#include "conduitscope/flow_direction.hpp"
#include "conduitscope/inventory_merge.hpp"
#include "conduitscope/live_capture.hpp"
#include "conduitscope/output.hpp"
#include "conduitscope/packet_range.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/pcap_writer.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/rotating_pcap_writer.hpp"
#include "conduitscope/time_format.hpp"
#include "conduitscope/version.hpp"

namespace {

using namespace conduitscope;

// True when stdout is connected to an interactive terminal rather than a file or a pipe --
// decides whether "auto" colorization (the default, absent --color/--no-color) turns color on.
// POSIX isatty()/fileno() and Windows' underscore-prefixed equivalents do the same thing; which
// one to call is the only platform difference here.
bool stdout_is_terminal() {
#ifdef _WIN32
    return _isatty(_fileno(stdout)) != 0;
#else
    return isatty(fileno(stdout)) != 0;
#endif
}

// --------------------------------------------------------------------------------------------
// Friendlier --help: word-wrapping and option grouping.
//
// Jurgen's direct request -- "make the output of --help way more friendlier to read" -- after
// which this file was audited to find out WHY it wasn't: CLI11's own stock help formatter
// (detail::format_help in CLI11.hpp) never word-wraps an option's description to any width at
// all. It only re-indents a LITERAL '\n' already embedded in the description string (there are
// none in this file -- every description here is deliberately one complete, long prose
// paragraph, matching docs/USER_GUIDE.md's own depth, see this file's own top-of-file comment);
// with no embedded newline, the whole description prints as one single unbroken line that simply
// runs off the right edge of whatever terminal is showing it. The second readability problem is
// structural, not textual: every option in a subcommand was registered into CLI11's single
// default "Options" group, so `decode --help` alone dumped ~190 options (counting the ~45
// `--*-port` protocol-port overrides most users will never touch) in one flat, undifferentiated
// list, with no visual separation between "you'll use this every time" (-r/-i/-f/-o/-T) and
// "advanced, rarely needed" (the port overrides, the dozen `--max-*` resource-limit flags).
//
// Both are fixed here without touching a single description's own wording (no information is
// lost, nothing here changes WHAT --help says, only how it's laid out):
//   1. terminal_width() + wrap_text() + WrappingHelpFormatter below replace CLI11's stock
//      line-assembly step with one that actually wraps long text to the real terminal width (or
//      a generous fallback when not a terminal -- --help piped to a pager or redirected to a
//      file is at least as common as --help read directly off an 80-column terminal).
//   2. Every add_option()/add_flag() call across every subcommand below was given an explicit
//      ->group("...") (see the many ->group(...) calls throughout this file) sorting it into one
//      of a small, consistent set of named sections -- "Input/output", "Filtering", "Output
//      format", "Protocol port overrides (rarely needed)", "Resource limits (advanced)", "Name
//      resolution", and so on, reused identically across subcommands wherever the same kind of
//      option recurs. CLI11 buckets and prints each group as its own labeled, blank-line-
//      separated section (Formatter::make_groups) automatically once options declare different
//      group names -- no further plumbing needed beyond tagging each option with the right one.
// --------------------------------------------------------------------------------------------

// MSVC flags std::getenv with C4996 ("this function or variable may be unsafe") and recommends
// _dupenv_s instead -- a narrower concern than e.g. std::gmtime's own genuine shared-static-buffer
// data race (portable_time.hpp's own portable_gmtime/portable_localtime, added for that reason):
// std::getenv's own returned pointer could only actually go stale if another thread concurrently
// called putenv/_putenv_s, and this process spawns no threads anywhere (std::this_thread::yield()
// below is the only <thread> use in this file, not a real thread), so there's no real race here
// today. The bounded, owning _dupenv_s replacement costs nothing and removes the question entirely
// regardless, the same "currently unexercised, but free to fix" reasoning already applied to
// portable_time.hpp -- kept local to this one call site (unlike portable_time.hpp, which has six
// call sites across five files) rather than promoted to a shared header.
#ifdef _MSC_VER
std::optional<std::string> portable_getenv(const char* name) {
    char* buf = nullptr;
    size_t len = 0;
    if (_dupenv_s(&buf, &len, name) != 0 || buf == nullptr) return std::nullopt;
    std::string result(buf);
    free(buf);
    return result;
}
#else
std::optional<std::string> portable_getenv(const char* name) {
    const char* value = std::getenv(name);
    if (value == nullptr) return std::nullopt;
    return std::string(value);
}
#endif

// The column width used to word-wrap --help's option descriptions: the real terminal width when
// stdout is an interactive terminal (ioctl(TIOCGWINSZ) on POSIX, GetConsoleScreenBufferInfo on
// Windows -- the same stdout_is_terminal() platform split just above decides which path runs),
// an explicit COLUMNS environment variable override when stdout is NOT a terminal at all (--help
// | less, --help > file.txt -- the same variable most shells export and the one coreutils/git/
// etc. already honor in this situation), and a generous fixed fallback (100) when neither is
// available -- --help piped or redirected is read at least as often as --help typed straight at
// an interactive terminal, and 100 columns reads far better than defaulting to a cautious 80.
// Clamped to [60, 200] so a pathological or misreported terminal size (0, or some environment's
// idea of 20000) can never collapse the help text into an unreadable sliver or balloon back into
// the single-unbroken-line problem this whole mechanism exists to fix.
unsigned terminal_width() {
    constexpr unsigned kMinWidth = 60;
    constexpr unsigned kMaxWidth = 200;
    constexpr unsigned kFallbackWidth = 100;

    unsigned width = 0;
    if (stdout_is_terminal()) {
#ifdef _WIN32
        CONSOLE_SCREEN_BUFFER_INFO info;
        if (GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &info)) {
            width = static_cast<unsigned>(info.srWindow.Right - info.srWindow.Left + 1);
        }
#else
        struct winsize ws {};
        if (ioctl(STDOUT_FILENO, TIOCGWINSZ, &ws) == 0 && ws.ws_col > 0) {
            width = static_cast<unsigned>(ws.ws_col);
        }
#endif
    }
    if (width == 0) {
        if (auto columns_env = portable_getenv("COLUMNS")) {
            int parsed = std::atoi(columns_env->c_str());
            if (parsed > 0) width = static_cast<unsigned>(parsed);
        }
    }
    if (width == 0) width = kFallbackWidth;
    return std::min(kMaxWidth, std::max(kMinWidth, width));
}

// Greedy word-wrap: break `text` into lines of at most `width` characters, breaking only at
// whitespace (never splitting a single word/token, even one longer than `width` -- rare in
// practice here, and an over-wide single line for one pathological token is a far smaller
// readability problem than silently corrupting the token by hyphen-splitting it mid-word). This
// is the one piece of logic the stock CLI11 formatter has no equivalent of at all -- everything
// else WrappingHelpFormatter below does is just re-arranging CLI11's own existing building
// blocks (make_option_name/make_option_opts/make_option_desc, get_column_width()).
std::vector<std::string> wrap_text(const std::string& text, std::size_t width) {
    std::vector<std::string> lines;
    std::string current;
    std::istringstream words(text);
    std::string word;
    while (words >> word) {
        if (current.empty()) {
            current = word;
        } else if (current.size() + 1 + word.size() <= width) {
            current += ' ';
            current += word;
        } else {
            lines.push_back(current);
            current = word;
        }
    }
    if (!current.empty() || lines.empty()) lines.push_back(current);
    return lines;
}

// Same idea as wrap_text, but for the NAME/OPTS column instead of the description column --
// e.g. `--protocol TEXT:{auto,modbus,dnp3,...,homeplug-av} [auto]`, whose `{...}` choice list
// (CLI11's own rendering of a CLI::IsMember validator, built from make_option_opts()) is nearly
// 500 characters with no whitespace anywhere in it, so wrap_text()'s own whitespace-only
// breaking can't help at all -- it would stay one giant unbroken token. This loosens exactly
// that one case by treating ", " as an equally valid break point alongside plain spaces (a comma
// not already followed by a space first gets one inserted, which also makes a long enum list
// read better even on a wide terminal, not just a wrapped one), while leaving every other
// character of the name/opts string untouched.
std::vector<std::string> wrap_name_opts(const std::string& text, std::size_t width) {
    std::string loosened;
    loosened.reserve(text.size());
    for (std::size_t i = 0; i < text.size(); ++i) {
        loosened += text[i];
        if (text[i] == ',' && (i + 1 >= text.size() || text[i + 1] != ' ')) loosened += ' ';
    }
    return wrap_text(loosened, width);
}

// Replaces CLI11's own Formatter::make_option AND make_subcommand (the two places
// detail::format_help -- see CLI11.hpp -- assembles one printed line with no word-wrapping at
// all: one for an option's own name/opts + description, the other for a subcommand's own name +
// description under a "Subcommands:" heading, e.g. `baseline --help`'s "learn"/"check" entries)
// with a version that wraps both the name/opts column and the description column to
// terminal_width(), while reusing every other CLI11 building block (make_option_name/
// make_option_opts/make_option_desc, get_column_width() for the aligned left column) completely
// unchanged. Everything else this class doesn't override -- grouping, usage line, footer,
// positionals -- is exactly CLI11's own stock behavior.
class WrappingHelpFormatter : public CLI::Formatter {
public:
    std::string make_option(const CLI::Option* opt, bool is_positional) const override {
        return wrap_help_line(make_option_name(opt, is_positional) + make_option_opts(opt), make_option_desc(opt));
    }

    // CLI11's own stock Formatter::make_subcommand (CLI11.hpp) has the exact same no-wrapping
    // problem make_option does above -- it also goes through detail::format_help directly -- and
    // this codebase's own subcommand descriptions (`baseline learn`'s/`baseline check`'s own, in
    // particular) are just as long as the longest option descriptions, so `baseline --help`'s
    // "Subcommands:" listing needs the identical fix.
    std::string make_subcommand(const CLI::App* sub) const override {
        return wrap_help_line(sub->get_display_name(true) + (sub->get_required() ? " " + get_label("REQUIRED") : ""),
                               sub->get_description());
    }

    // The one line of free text at the very top of any --help (this codebase's own App/
    // subcommand descriptions, e.g. decode's "Decode a pcap/pcapng capture and print each
    // recognized packet" or baseline's considerably longer one) has the same no-wrapping
    // problem as make_option/make_subcommand above, but isn't in the two-column name+desc
    // layout those share -- it's a single block of text with no left column to align under, so
    // it gets its own override wrapping to the FULL terminal_width() rather than desc_width
    // (which is sized to leave room for get_column_width()'s left column -- irrelevant here).
    // The REQUIRED/min-max suffix logic below is copied verbatim from CLI11's own stock
    // Formatter::make_description (CLI11.hpp) -- this project never actually uses
    // require_option_min/max at the App level (only require_subcommand), so it's dead code for
    // every --help this binary prints today, but kept for correctness rather than assuming that
    // never changes.
    std::string make_description(const CLI::App* app) const override {
        std::string desc = app->get_description();
        const std::size_t min_options = app->get_require_option_min();
        const std::size_t max_options = app->get_require_option_max();
        if (app->get_required()) {
            desc += " " + get_label("REQUIRED") + " ";
        }
        if ((max_options == min_options) && (min_options > 0)) {
            if (min_options == 1) {
                desc += " \n[Exactly 1 of the following options is required]";
            } else {
                desc += " \n[Exactly " + std::to_string(min_options) + " options from the following list are required]";
            }
        } else if (max_options > 0) {
            if (min_options > 0) {
                desc += " \n[Between " + std::to_string(min_options) + " and " + std::to_string(max_options) +
                        " of the follow options are required]";
            } else {
                desc += " \n[At most " + std::to_string(max_options) + " of the following options are allowed]";
            }
        } else if (min_options > 0) {
            desc += " \n[At least " + std::to_string(min_options) + " of the following options are required]";
        }
        if (desc.empty()) return {};
        // Split on any literal '\n' first (the REQUIRED/min-max suffix above can add one) and
        // wrap each resulting paragraph independently -- wrap_text()'s own whitespace tokenizer
        // would otherwise treat an embedded '\n' as just another space and silently collapse a
        // deliberate line break into the ordinary wrapped flow.
        std::ostringstream out;
        std::string paragraph;
        std::istringstream paragraphs(desc);
        while (std::getline(paragraphs, paragraph, '\n')) {
            for (const std::string& line : wrap_text(paragraph, terminal_width())) {
                out << line << "\n";
            }
        }
        return out.str();
    }

private:
    // Shared by make_option and make_subcommand above -- both are "a name/opts column, aligned
    // to get_column_width(), followed by a word-wrapped description" with nothing else
    // different between them, so this is the one place the actual wrapping/alignment logic
    // lives.
    std::string wrap_help_line(const std::string& name, const std::string& desc) const {
        const std::size_t col = get_column_width();
        const unsigned term_width = terminal_width();
        // Leave at least 40 columns for the description even on a narrow terminal where `col`
        // alone would otherwise eat nearly the whole line -- 40 is still enough for real prose
        // to wrap sensibly rather than degenerating into a near-one-word-per-line column.
        const std::size_t desc_width =
            (term_width > col + 40) ? static_cast<std::size_t>(term_width) - col : 40;

        std::ostringstream out;
        // Wrap the UN-indented name/opts text first -- wrap_text/wrap_name_opts tokenize on
        // whitespace via istringstream's own operator>>, which silently eats any leading
        // whitespace it's given, so baking the indent into the string before wrapping would
        // just lose it off the front of the first line. Indentation is added back below, after
        // wrapping: "  " (matching CLI11's own stock indent) on the first line, a fixed "    "
        // on every later fragment -- still "the option itself" overflowing (e.g. a long
        // `{a,b,c,...}` choice list), not the aligned description column, so it gets its own
        // light indent rather than lining up under get_column_width().
        const std::size_t name_wrap_width = (term_width > 6) ? static_cast<std::size_t>(term_width) - 2 : 40;
        std::vector<std::string> name_lines = (name.size() + 2 > term_width)
                                                   ? wrap_name_opts(name, name_wrap_width)
                                                   : std::vector<std::string>{name};
        std::string last_name_line;
        for (std::size_t i = 0; i < name_lines.size(); ++i) {
            std::string line = (i == 0 ? "  " : "    ") + name_lines[i];
            if (i + 1 < name_lines.size()) {
                out << line << "\n";
            } else {
                last_name_line = line;
            }
        }
        out << std::left << std::setw(static_cast<int>(col)) << last_name_line;
        if (!desc.empty()) {
            if (last_name_line.size() >= col) out << "\n" << std::setw(static_cast<int>(col)) << "";
            bool first_line = true;
            for (const std::string& line : wrap_text(desc, desc_width)) {
                if (!first_line) out << std::setw(static_cast<int>(col)) << "";
                out << line << "\n";
                first_line = false;
            }
        } else {
            out << "\n";
        }
        return out.str();
    }
};

// --------------------------------------------------------------------------------------------
// Live capture plumbing shared by `decode -i` and `policy validate -i`. See live_capture.hpp for
// LiveCapture itself; everything below is CLI-layer glue that lets run_decode/run_policy_validate
// treat an offline pcap file and a live interface as the same kind of packet source, and lets
// Ctrl+C stop a live capture cleanly (finishing the report/summary with whatever was captured so
// far) instead of the process just dying mid-capture.
// --------------------------------------------------------------------------------------------

// Owns exactly one of a PcapReader (offline file) or a LiveCapture (live interface) and forwards
// the small bit of interface run_decode/run_policy_validate actually need from either.
class PacketSource {
public:
    explicit PacketSource(std::unique_ptr<PcapReader> reader) : reader_(std::move(reader)) {}
    explicit PacketSource(std::unique_ptr<LiveCapture> capture) : capture_(std::move(capture)) {}

    PacketSource(const PacketSource&) = delete;
    PacketSource& operator=(const PacketSource&) = delete;
    PacketSource(PacketSource&&) = default;
    PacketSource& operator=(PacketSource&&) = default;

    // Only ever set for an offline PcapReader source (see open_packet_source below) -- a live
    // capture already has its own BPF filter applied by libpcap at capture time, via
    // pcap_setfilter() inside LiveCapture's own constructor, so there's nothing left to filter
    // here even if this were called for one (and open_packet_source never does).
    void set_file_filter(std::unique_ptr<BpfFilter> filter) { file_filter_ = std::move(filter); }

    // `decode`'s own `--range` (packet_range.hpp) -- only ever set for an offline PcapReader
    // source, same as set_file_filter above, and for the same reason: there is no live-capture
    // equivalent of "select packet #N" (the CLI layer excludes --range from -i entirely, so this
    // is never called for a live source in practice either). Takes the spec by value/move rather
    // than a pointer, unlike set_file_filter's unique_ptr<BpfFilter> -- PacketRangeSpec has no
    // virtual interface to own polymorphically, it's just data.
    void set_range_filter(PacketRangeSpec range) { range_filter_ = std::move(range); }

    // For a filtered offline source, skips non-matching packets transparently -- callers see
    // exactly the same "false at EOF" contract either way, they just see fewer packets in
    // between. reader_->info().linktype is re-read fresh per packet (not cached once before the
    // loop) for the same multi-interface-pcapng reason pcap_reader.hpp's own file header already
    // documents for every other call site that reads it.
    //
    // `index_` is set here, on every packet this call returns true for, to that packet's actual
    // position in the underlying source -- for an offline file, its 1-based position in the FILE
    // (`file_position_`, incremented for every packet read off disk, matched or not), not the
    // count of packets that have passed the filter so far. This is what makes a filtered `-r`
    // read behave like Wireshark's own display filter (frame numbers are stable positions in the
    // capture) rather than a capture filter (which renumbers from 1, because the discarded
    // packets were genuinely never captured at all) -- an earlier version of this class did the
    // latter, which made cross-referencing a filtered run's "#N" packets back against the same
    // file opened unfiltered (or in Wireshark) needlessly hard, since the same packet could carry
    // two different numbers depending only on which filter, if any, was given. Live capture keeps
    // the old "count what was actually received" numbering (`live_position_`) -- and rightly so:
    // libpcap's own pcap_setfilter() already discards non-matching packets before this process
    // ever sees them, so there is no "original position" to preserve even in principle, the same
    // reason Wireshark's own capture-filter (-f) numbering renumbers too. --range's own packet
    // numbers are checked against this exact same `file_position_`, matching packet_range.hpp's
    // own documented "real file position, not renumbered among matches" contract -- and checked
    // BEFORE file_filter_, so a packet excluded by --range never even reaches BPF matching (pure
    // ordering choice, not an observable difference either way: both must pass for next() to
    // return true regardless of which is checked first).
    bool next(PcapPacket& out) {
        if (reader_) {
            while (reader_->next(out)) {
                ++file_position_;
                if (range_filter_ && !range_filter_->contains(file_position_)) continue;
                if (!file_filter_ || file_filter_->matches(out, reader_->info().linktype)) {
                    index_ = file_position_;
                    return true;
                }
            }
            return false;
        }
        if (!capture_->next(out)) return false;
        index_ = ++live_position_;
        return true;
    }
    // The index the most recent successful next() should be decoded/reported under -- see next()'s
    // own comment for what this means for a filtered offline read specifically. 0 until the first
    // next() call succeeds.
    size_t index() const { return index_; }
    uint32_t linktype() const { return reader_ ? reader_->info().linktype : capture_->info().linktype; }
    // Non-null only when this source is a live capture; used by SigintGuard below. Never call
    // anything on it except stop() from a signal handler.
    LiveCapture* live_ptr() const { return capture_.get(); }

private:
    std::unique_ptr<PcapReader> reader_;
    size_t file_position_ = 0;
    size_t live_position_ = 0;
    size_t index_ = 0;
    std::unique_ptr<LiveCapture> capture_;
    std::unique_ptr<BpfFilter> file_filter_;
    std::optional<PacketRangeSpec> range_filter_;
};

std::atomic<LiveCapture*> g_active_capture{nullptr};
// Whether the run currently under a SigintGuard has ANSI color output enabled -- set by
// SigintGuard's constructor from `decode`'s own `color` (see run_decode), so handle_sigint below
// knows whether it needs to restore the terminal's default colors. Only `decode` ever passes
// true here; `policy validate`/`inventory` have no colorized text output to restore.
std::atomic<bool> g_color_active{false};
// Set by run_sigint_cleanup, checked at the top of run_decode/run_policy_validate/
// run_inventory's own `while (source.next(pkt))` loop, alongside LiveCapture's own internal
// stop_requested (live_capture.cpp) rather than instead of it. The two aren't redundant:
// LiveCapture::next() can block *inside* a single call (waiting on pcap_next_ex()), so it needs
// its own internal flag to unblock promptly; but PcapReader (an offline `-r` file read) has no
// such per-call blocking and no stop flag of its own at all -- reading a large file is simply a
// tight loop with nothing to interrupt it early. Without this, a run reading from a file just
// keeps reading to EOF regardless of Ctrl+C -- harmless for `decode`'s own color reset (which
// still happens either way, from this same handler's immediate write and/or the authoritative
// end-of-run one below), but means Ctrl+C doesn't actually shorten a long offline read the way it
// does a live capture, which isn't what "stop cleanly on Ctrl+C" ought to mean for either source.
std::atomic<bool> g_stop_requested{false};
// Counts SIGINT handler invocations currently in progress (0 or 1 on POSIX, since a signal only
// ever interrupts the thread it was delivered to and can't re-enter while already running there;
// see below for why it can briefly be more on Windows). SigintGuard's destructor spin-waits on
// this before letting the guarded LiveCapture be destroyed -- see its own comment for why that
// matters.
std::atomic<int> g_handler_in_flight{0};

// Writes the ANSI "reset all attributes" sequence directly to stdout's file descriptor -- NOT via
// std::cout -- and used everywhere this program resets the terminal's colors on exit, both from
// run_sigint_cleanup below and from run_decode's own end-of-run reset. Deliberately low-level for
// two independent reasons, one per caller:
//
// - run_sigint_cleanup calls this from a signal/console-ctrl handler that can run concurrently
//   with main() (see SigintGuard's own comment) -- std::cout's buffered iostream state is not
//   something a concurrently-running handler can safely touch, so a raw write()/_write() is used
//   instead: a essentially-immediate primitive with no shared buffering state to race with.
// - run_decode's own end-of-run reset calls this instead of `*out << "\033[0m"` for a different
//   reason: a large decode (especially an offline file read start-to-finish, which -- unlike live
//   capture -- has no natural per-packet pacing and can print its entire output in one enormous
//   burst) can leave a very large amount of text sitting in std::cout's own buffer, all flushed in
//   a single big write. Windows consoles are documented to sometimes mishandle a single very large
//   WriteConsole call (silently short/truncated), and losing exactly the last few bytes of that
//   one big write would lose our reset specifically -- something a real report of the terminal
//   occasionally still being left colored after an ordinary (non-interrupted) offline decode
//   pointed at. Flushing whatever's already buffered in `out` FIRST, then writing this reset as
//   its own small, separate, unbuffered write, keeps it decoupled from that risk regardless of how
//   much came before it.
void write_raw_color_reset_to_stdout() {
    static const char kResetSequence[] = "\033[0m";
#ifdef _WIN32
    _write(_fileno(stdout), kResetSequence, sizeof(kResetSequence) - 1);
#else
    ssize_t written = ::write(STDOUT_FILENO, kResetSequence, sizeof(kResetSequence) - 1);
    (void)written;  // Best-effort: nothing meaningful to do with a short/failed write here.
#endif
}

// Shared body for both platforms' entry points below: restores the terminal's default colors (if
// this run had any active) and stops whatever live capture is currently guarded. Split out on its
// own so POSIX's handle_sigint and Windows' console_ctrl_handler -- two entry points with
// different signatures and different registration mechanisms, see SigintGuard's own comment for
// why Windows needs its own -- don't duplicate the actual cleanup logic.
//
// Restoring color is done FIRST, before anything else: without this, Ctrl+C during a colorized
// live `decode` leaves the terminal showing whatever ANSI color the most recently printed line
// happened to end in (e.g. a yellow "note" or red "malformed" line) -- that state then bleeds into
// the shell prompt and everything typed afterward, until the user notices and runs `reset`/`tput
// sgr0` themselves.
void run_sigint_cleanup() {
    if (g_color_active.load(std::memory_order_acquire)) {
        write_raw_color_reset_to_stdout();
    }
    // Always set, regardless of source kind -- LiveCapture::stop() below already handles the live
    // case (and can unblock a call already in progress inside LiveCapture::next()); this is what
    // an offline `-r` read's packet loop checks instead, since PcapReader has no stop of its own.
    g_stop_requested.store(true, std::memory_order_release);
    LiveCapture* capture = g_active_capture.load();
    if (capture != nullptr) capture->stop();
}

#ifdef _WIN32
// Windows' own console control handler (SetConsoleCtrlHandler), NOT std::signal(SIGINT, ...) --
// see SigintGuard's own comment for why the portable signal() API isn't good enough here. Runs on
// a Windows-spawned handler thread, same as the CRT's own SIGINT translation would, so the same
// g_handler_in_flight bookkeeping SigintGuard's destructor waits on still applies.
BOOL WINAPI console_ctrl_handler(DWORD ctrl_type) {
    g_handler_in_flight.fetch_add(1, std::memory_order_acquire);
    run_sigint_cleanup();
    g_handler_in_flight.fetch_sub(1, std::memory_order_release);
    if (ctrl_type == CTRL_C_EVENT || ctrl_type == CTRL_BREAK_EVENT) {
        // TRUE: this event is fully handled -- stops Windows from running any further handler in
        // the chain (there are none here) and, critically, from falling back to ITS OWN default
        // action of terminating the process. That default-action fallback is exactly the failure
        // mode std::signal(SIGINT, ...) can't reliably prevent on Windows (see SigintGuard's own
        // comment), so returning TRUE here -- and staying registered for as long as this guard is
        // alive, unlike a one-shot signal() handler -- is what actually fixes it.
        return TRUE;
    }
    // CTRL_CLOSE_EVENT/CTRL_LOGOFF_EVENT/CTRL_SHUTDOWN_EVENT: the console window is closing, the
    // user is logging off, or the system is shutting down -- Windows gives every registered
    // handler only a few seconds (historically ~5s, sometimes less) before terminating the process
    // regardless of what any handler returns. The best-effort cleanup above still ran; returning
    // FALSE here lets Windows' own default handling (and any other process in the same console's
    // handler chain) proceed too, rather than this process claiming an event it can't meaningfully
    // stop.
    return FALSE;
}
#else
extern "C" void handle_sigint(int) {
    g_handler_in_flight.fetch_add(1, std::memory_order_acquire);
    run_sigint_cleanup();
    g_handler_in_flight.fetch_sub(1, std::memory_order_release);
}
#endif

// RAII guard: while alive, redirects Ctrl+C to LiveCapture::stop() on `capture` instead of the
// platform default (immediate process termination), so a live capture stops cleanly and still
// prints whatever report/summary it had. A no-op when `capture` is null (offline-file mode doesn't
// need this -- EOF already stops the loop on its own).
//
// POSIX uses std::signal(SIGINT, ...); Windows uses SetConsoleCtrlHandler, NOT std::signal --
// deliberately, after a real report that the color-restore above wasn't taking effect reliably on
// Windows. Two distinct, well-documented Windows gotchas motivate this, both from Microsoft's own
// documentation of console Ctrl+C handling: (1) a CTRL+C interrupt is delivered by spinning up a
// *new thread* to run whatever's registered, which can therefore execute genuinely concurrently
// with the main thread -- including with this destructor tearing down the very LiveCapture the
// handler is about to call stop() on, which would be a real use-after-free race without the
// g_handler_in_flight wait below (harmless on POSIX, where a signal handler only ever interrupts
// the same thread it was delivered to and can't run concurrently with anything else in the
// process, so this can only ever see 0 there); this part std::signal() + a flag already handled
// correctly on both platforms. (2) What std::signal()-registered handlers on Windows do NOT
// reliably guarantee is that the OS's own default action (killing the process) stays suppressed
// for as long as our handler is installed -- SetConsoleCtrlHandler's HandlerRoutine returning TRUE
// is the actual, durable way to prevent that, is the mechanism Microsoft's own docs recommend for
// exactly this "clean up terminal state before a Ctrl+C-driven exit" scenario, and is what
// console_ctrl_handler above does.
class SigintGuard {
public:
    // `color` should be whatever this run already resolved for its own colorized output (e.g.
    // run_decode's `color` local) -- default false covers callers (policy validate, inventory)
    // that have no colorized text output for the cleanup above to need to reset.
    //
    // Active -- i.e. actually installs a handler at all -- whenever EITHER `capture` is non-null
    // (there's a live capture that needs stopping cleanly) OR `color` is true (there's colored
    // output that needs resetting cleanly), not just the first. A real report caught the gap this
    // closes: for an offline `-r` decode, `capture` is always null (there's no LiveCapture at all
    // to guard -- see open_packet_source), so with the OLD `active_(capture != nullptr)` this
    // guard installed NO handler whatsoever, on any platform, for that case. Ctrl+C during a
    // colorized offline decode therefore fell straight through to the OS's own default
    // Ctrl+C-kills-the-process action, with none of the cleanup below ever running -- explaining
    // why the terminal was still left colored even after both the SetConsoleCtrlHandler switch and
    // the end-of-run reset in run_decode below, neither of which matters if no handler is even
    // registered to reach them. `run_sigint_cleanup`'s own `capture != nullptr` null check already
    // makes it safe to call with a null `g_active_capture` (nothing to stop, just the color reset).
    explicit SigintGuard(LiveCapture* capture, bool color = false)
        : active_(capture != nullptr || color) {
        if (active_) {
            g_active_capture.store(capture);
            g_color_active.store(color, std::memory_order_release);
            g_stop_requested.store(false, std::memory_order_release);
#ifdef _WIN32
            ::SetConsoleCtrlHandler(console_ctrl_handler, TRUE);
#else
            previous_handler_ = std::signal(SIGINT, handle_sigint);
#endif
        }
    }
    ~SigintGuard() {
        if (active_) {
#ifdef _WIN32
            ::SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
#else
            std::signal(SIGINT, previous_handler_);
#endif
            g_active_capture.store(nullptr);
            g_color_active.store(false, std::memory_order_release);
            g_stop_requested.store(false, std::memory_order_release);
            while (g_handler_in_flight.load(std::memory_order_acquire) > 0) {
                std::this_thread::yield();
            }
        }
    }
    SigintGuard(const SigintGuard&) = delete;
    SigintGuard& operator=(const SigintGuard&) = delete;

private:
    bool active_;
#ifndef _WIN32
    void (*previous_handler_)(int) = SIG_DFL;
#endif
};

// Shared by run_decode/run_policy_validate/run_inventory: exactly one of `input` (offline pcap
// file, already validated to exist by CLI11's ->check(CLI::ExistingFile)) or `interface_name`
// (live capture) is expected to be non-empty -- enforced in main() before any run_* function is
// called, via ->excludes() plus the post-parse "exactly one" check. Throws whatever PcapReader's
// constructor / LiveCapture's constructor / BpfFilter's constructor throws (ParseError /
// CaptureError / CaptureError respectively) on failure.
//
// `filter` is meaningful for BOTH source kinds, not just -i: for -i it's handed to LiveCapture,
// which applies it via libpcap's pcap_setfilter() at capture time (see live_capture.cpp); for -r
// it's compiled once here (BpfFilter, bpf_filter.hpp) and applied to each packet PcapReader reads
// off disk, since an offline file has no equivalent "at capture time" hook of its own. Either
// way, `filter` given but this build having no libpcap/Npcap support surfaces the same clear
// CaptureError -- for -i via LiveCapture's own stub, for -r via BpfFilter's own stub.
PacketSource open_packet_source(const std::string& input, const std::string& interface_name,
                                 int snaplen, bool promiscuous, const std::string& filter,
                                 int duration_seconds, size_t max_packets) {
    if (!interface_name.empty()) {
        return PacketSource(std::make_unique<LiveCapture>(interface_name, snaplen, promiscuous,
                                                            filter, duration_seconds, max_packets));
    }
    auto reader = std::make_unique<PcapReader>(input);
    uint32_t reader_linktype = reader->info().linktype;
    uint32_t reader_snaplen = reader->info().snaplen;
    PacketSource source(std::move(reader));
    if (!filter.empty()) {
        source.set_file_filter(std::make_unique<BpfFilter>(filter, reader_linktype, reader_snaplen));
    }
    return source;
}

// patch257 security review section 4, "Detection completeness": "Packet loss... must be
// distinguishable from a clean capture with no findings." A live capture's own OS/driver-level
// drop counters (LiveCaptureStats, live_capture.hpp) are the one "observation incomplete" cause
// none of this codebase's existing engines can ever detect on their own -- a dropped packet never
// reaches Decoder::decode() at all, so there is nothing for AssetInventoryEngine/PolicyEngine/
// DetectEngine to notice. This is the one shared place that checks for it and folds a
// human-readable reason into whatever `reasons` vector a caller's own Report struct already
// exposes (PolicyReport::truncation_reasons, AssetInventoryReport::truncation_reasons,
// DetectionReport::truncation_reasons -- see each one's own observation_truncated/
// truncation_reasons comment), reusing that SAME existing "observation incomplete" machinery
// (report text/json already render truncation_reasons unconditionally, and the CLI layer's
// existing kExitObservationIncomplete handling already takes priority over every other exit code)
// rather than inventing a parallel "packet loss" concept -- matching this file's own
// append_flow_state_eviction_reason precedent (resource_limits.hpp), which folds a different
// capture-wide concern into the same vector the same way.
//
// A no-op for an offline source (source.live_ptr() == nullptr) or a live source that reported
// zero drops -- returns false in both cases, leaving `reasons` untouched; `decode`, which has no
// Report/truncation_reasons of its own, calls LiveCapture::stats() directly instead (see
// run_decode) rather than through this helper.
bool append_live_capture_drop_reason(const PacketSource& source, std::vector<std::string>& reasons,
                                      std::vector<ObservationIncompleteReason>& categories) {
    LiveCapture* live = source.live_ptr();
    if (live == nullptr) return false;
    std::optional<std::string> reason = format_live_capture_drop_reason(live->stats());
    if (!reason) return false;
    reasons.push_back(*reason);
    // patch282 finding 6 fix (item 123, docs/DEVELOPMENT.md): categorized as ResourceLimit, not a
    // new category of its own -- libpcap/Npcap's own ring buffer filling up before this process
    // could read it out is a capacity/resource condition in exactly the same sense an engine's own
    // tracked-key ceiling is, even though the resource being exceeded (the OS/driver's capture
    // buffer) sits below this codebase's own code. See ObservationIncompleteReason's own comment
    // (resource_limits.hpp) for why this is deliberately NOT categorized as PacketTruncation --
    // that name is reserved for an individual packet's own bytes being cut off, which is a
    // different condition this codebase doesn't detect this way.
    append_observation_incomplete_reason(categories, ObservationIncompleteReason::ResourceLimit);
    return true;
}

std::string link_type_name(uint32_t linktype) {
    switch (linktype) {
        case LINKTYPE_ETHERNET: return "Ethernet";
        case LINKTYPE_RAW: return "Raw IP (no link-layer header)";
        case LINKTYPE_CAN_SOCKETCAN: return "Linux SocketCAN (DeviceNet)";
        case LINKTYPE_IEEE802_15_4_WITHFCS: return "IEEE 802.15.4 with FCS (Zigbee)";
        case LINKTYPE_IEEE802_15_4_TAP: return "IEEE 802.15.4 TAP (Zigbee)";
        default: return "unsupported/unknown (" + std::to_string(linktype) + ")";
    }
}

std::string version_string() {
    return std::string(kVersion) + "  [" + kCompilerId + ", " + kSystemName + ", " + kBuildType +
           " build, live capture: " + (live_capture_available() ? "libpcap/Npcap" : "not built in") + "]";
}

// --------------------------------------------------------------------------------------------
// The five new --max-* resource-limit flags (docs/DEVELOPMENT.md's "External code review and
// engineering priorities" item 7 -- see resource_limits.hpp for the full rationale). Registered
// identically on all three of decode_cmd/policy_validate_cmd/inventory_cmd (unlike the
// --modbus-port-style port-list flags above, which remain decode-only -- a pre-existing,
// out-of-scope gap, not something this feature inherits), so this one small struct plus the two
// helpers below keep the five add_option calls and their help text from being tripled by hand.
//
// Each field is a plain size_t, default 0 -- the same "(0 = unlimited)" sentinel convention
// --max-packets already established -- meaning "flag not given, this category keeps every
// site's own compile-time default." build_resource_limits() below turns that sentinel into
// std::nullopt.
struct ResourceLimitCliVars {
    size_t max_reassembly_bytes = 0;
    size_t max_reassembly_segments = 0;
    size_t max_recursion_depth = 0;
    size_t max_decoded_objects = 0;
    size_t max_coalesced_messages = 0;
    // Added for docs/reviews/2026-09-chatgpt-security-review-patch160.md's finding 1 -- a
    // different category from the five above (which bound the cost of any ONE flow/reassembly/
    // message): these bound how many DISTINCT flows/sessions can be tracked at once. See
    // resource_limits.hpp's own comments on max_active_flows/max_flow_state_entries.
    size_t max_active_flows = 0;
    size_t max_flow_state_entries = 0;
    // ROADMAP item 102: same "evict to cap a COUNT of distinct in-progress groups" shape as the
    // two fields above, for IP fragment reassembly (decoder.cpp's ip_fragment_reassembly_) instead
    // of TCP flows/protocol session state. See resource_limits.hpp's own comment on
    // max_active_fragment_groups.
    size_t max_active_fragment_groups = 0;
};

void add_resource_limit_options(CLI::App* cmd, ResourceLimitCliVars& vars) {
    cmd->add_option(
           "--max-reassembly-bytes", vars.max_reassembly_bytes,
           "Override every cross-segment payload-buffering byte cap at once: the general TCP "
           "reassembly path (default 16 MiB), DNP3 fragment reassembly (default 64 KiB), COTP "
           "TSDU reassembly (default 1 MiB), OPC UA's/FF-HSE's own declared-length plausibility "
           "ceiling (default 16 MiB each), and IPv4/IPv6 fragment reassembly's own per-datagram "
           "ceiling (default 65,535 bytes). 0 = leave every site at its own default (see "
           "docs/DEVELOPMENT.md item 7 for the full constant-by-constant mapping)")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-reassembly-segments", vars.max_reassembly_segments,
           "Override every cross-segment frame/segment-count cap at once: the general TCP "
           "reassembly path (default 20,000 segments), DNP3 fragment reassembly (default 500 "
           "frames), COTP TSDU reassembly (default 2,000 frames), and IPv4/IPv6 fragment "
           "reassembly's own per-datagram fragment-count ceiling (default 8,192 fragments). 0 = "
           "leave every site at its own default")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-recursion-depth", vars.max_recursion_depth,
           "Override every recursive-decode depth cap at once: MMS Data-value nesting (default "
           "32), EtherNet/IP CIP Multiple_Service_Packet/Unconnected_Send nesting (default 4), "
           "MPLS label-stack depth (default 16), S7comm-Plus struct/item nesting (default 16), "
           "and GOOSE Data ASN.1 nesting (default 6). 0 = leave every site at its own default")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-decoded-objects", vars.max_decoded_objects,
           "Override every per-message decoded-object/value/list-entry cap at once (~43 "
           "individually-named constants across DNP3/IEC104/GOOSE/EtherNet-IP/S7comm-Plus/MQTT/"
           "decoder.cpp's own summary lists, plus the 9 duplicated 50-entry list caps shared by "
           "EIGRP/OSPF/PIM/IGMP/ICMP/IGRP/RIP/VRRP/HSRP). 0 = leave every site at its own "
           "default; too many constants to enumerate here -- see docs/DEVELOPMENT.md item 7 for "
           "the full mapping")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-coalesced-messages", vars.max_coalesced_messages,
           "Override every 'N application-layer messages found coalesced in one TCP/UDP "
           "payload' cap at once: FF-HSE, HART-IP, MQTT, EtherNet/IP, and OPC UA (all default "
           "50). 0 = leave every site at its own default")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-active-flows", vars.max_active_flows,
           "Cap the number of distinct TCP flows the general cross-segment reassembly path "
           "(decoder.cpp) tracks state for at once, regardless of how many distinct flows the "
           "capture contains -- an existing flow's own state being updated never counts against "
           "this. 0 (the default) applies the built-in default of 100,000; a flow that never "
           "needs reassembly at all is never tracked in the first place either way (see "
           "docs/DEVELOPMENT.md's security review write-up)")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-flow-state-entries", vars.max_flow_state_entries,
           "Cap the TOTAL number of distinct sessions/flows tracked at once across every "
           "protocol's own state (SMB pipes, DCE/RPC interfaces, Kerberos, LDAP, WinRM, DCOM, "
           "Modbus/TwinCAT/MELSEC/MQTT, DNP3/COTP reassembly, and more), combined. 0 (the "
           "default) applies the built-in default of 250,000")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-active-fragment-groups", vars.max_active_fragment_groups,
           "Cap the number of distinct in-progress IP fragment reassembly groups (decoder.cpp) "
           "tracked at once, regardless of how many distinct fragmented datagrams the capture "
           "contains -- an existing group's own state being updated never counts against this. "
           "0 (the default) applies the built-in default of 5,000")->group("Resource limits (advanced)")
        ->capture_default_str();
}

ResourceLimits build_resource_limits(const ResourceLimitCliVars& vars) {
    ResourceLimits limits;
    if (vars.max_reassembly_bytes != 0) limits.max_reassembly_bytes = vars.max_reassembly_bytes;
    if (vars.max_reassembly_segments != 0) limits.max_reassembly_segments = vars.max_reassembly_segments;
    if (vars.max_recursion_depth != 0) limits.max_recursion_depth = vars.max_recursion_depth;
    if (vars.max_decoded_objects != 0) limits.max_decoded_objects = vars.max_decoded_objects;
    if (vars.max_coalesced_messages != 0) limits.max_coalesced_messages = vars.max_coalesced_messages;
    if (vars.max_active_flows != 0) limits.max_active_flows = vars.max_active_flows;
    if (vars.max_flow_state_entries != 0) limits.max_flow_state_entries = vars.max_flow_state_entries;
    if (vars.max_active_fragment_groups != 0) limits.max_active_fragment_groups = vars.max_active_fragment_groups;
    return limits;
}

// Item 64 fix (docs/reviews/2026-09-chatgpt-security-review-patch209.md, finding 1): the four
// BaselineEngine growth ceilings' own CLI options, registered only on 'baseline learn'/'baseline
// check' (not folded into add_resource_limit_options/ResourceLimitCliVars above) -- same reasoning
// as --max-baseline-file-bytes' own (baseline.hpp's kDefaultMaxBaselineFileBytes comment): these
// bound BaselineEngine's own per-capture state, a conceptually distinct kind of limit from the
// decode-time budgets add_resource_limit_options covers, which every one of 'decode'/'policy
// validate'/'inventory'/both baseline subcommands shares. Same "0 = leave every site at its own
// default" convention as every other --max-* flag in this file.
void add_baseline_engine_limit_options(CLI::App* cmd, size_t& max_tcp_sessions, size_t& max_conduits,
                                         size_t& max_operations_per_conduit, size_t& max_ranges_per_operation) {
    cmd->add_option(
           "--max-baseline-tcp-sessions", max_tcp_sessions,
           "Cap the number of distinct TCP sessions BaselineEngine tracks per capture for "
           "client/server direction inference (default 50,000). 0 = leave it at its own default; "
           "past this, further new sessions fall back to the known-port heuristic instead of "
           "SYN/SYN-ACK tracking and the baseline is marked incomplete (see docs/DEVELOPMENT.md's "
           "security review write-up)")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-baseline-conduits", max_conduits,
           "Cap the number of distinct conduits (client, server, protocol, port) BaselineEngine "
           "records per capture (default 20,000). 0 = leave it at its own default; past this, "
           "further new conduits observed in the capture are not recorded and the baseline is "
           "marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-baseline-operations-per-conduit", max_operations_per_conduit,
           "Cap the number of distinct operation keys BaselineEngine records per conduit (default "
           "5,000). 0 = leave it at its own default; past this, further new operations on that "
           "conduit are not recorded and the baseline is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-baseline-ranges-per-operation", max_ranges_per_operation,
           "Cap the number of distinct (coalesced) target-address ranges BaselineEngine records "
           "per operation (default 1,000). 0 = leave it at its own default; past this, further "
           "new, disjoint ranges for that operation are not recorded and the baseline is marked "
           "incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
}

// Resolves the four raw CLI values (0 = unset) into a real BaselineEngineLimits, applying the
// compiled defaults exactly where the CLI parsing layer applies every other 0-sentinel default in
// this file -- BaselineEngine's own constructor always receives a fully-resolved struct, never a
// sentinel.
BaselineEngineLimits resolve_baseline_engine_limits(size_t max_tcp_sessions, size_t max_conduits,
                                                      size_t max_operations_per_conduit,
                                                      size_t max_ranges_per_operation) {
    BaselineEngineLimits limits;
    if (max_tcp_sessions != 0) limits.max_tracked_tcp_sessions = max_tcp_sessions;
    if (max_conduits != 0) limits.max_conduits = max_conduits;
    if (max_operations_per_conduit != 0) limits.max_operations_per_conduit = max_operations_per_conduit;
    if (max_ranges_per_operation != 0) limits.max_ranges_per_operation = max_ranges_per_operation;
    return limits;
}

// patch257 security review finding 3 ("protocol state exhaustion remains a central threat"),
// invariants 3/5 -- DetectEngine's own three growth ceilings' CLI options, registered only on
// `detect` (same reasoning as add_baseline_engine_limit_options above: these bound DetectEngine's
// own per-capture state, not the decode-time budgets add_resource_limit_options covers). Same
// "0 = leave every site at its own default" convention as every other --max-* flag in this file.
void add_detect_engine_limit_options(CLI::App* cmd, size_t& max_findings, size_t& max_tracked_keys_per_map,
                                       size_t& max_originators_per_server) {
    cmd->add_option(
           "--max-detect-findings", max_findings,
           "Cap the number of distinct findings (always-notable findings and new-conduit "
           "candidates, checked independently) DetectEngine records per capture (default "
           "20,000). 0 = leave it at its own default; past this, further genuinely new findings "
           "of that kind are not recorded and the observation is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-detect-tracked-keys-per-map", max_tracked_keys_per_map,
           "Cap the number of distinct keys DetectEngine tracks in any one of its per-source/"
           "per-server novelty/burst-tracking maps (default 50,000, applied identically and "
           "independently to each map). 0 = leave it at its own default; past this, further new "
           "keys in that map are not tracked and the observation is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-detect-originators-per-server", max_originators_per_server,
           "Cap the number of distinct originator IPs DetectEngine tracks per server key inside "
           "its nine per-server originator/writer maps (default 2,000). 0 = leave it at its own "
           "default; past this, further new originators for that server are not tracked and the "
           "observation is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
}

// Resolves the three raw CLI values (0 = unset) into a real DetectEngineLimits, same "always a
// fully-resolved struct, never a sentinel" convention as resolve_baseline_engine_limits above.
DetectEngineLimits resolve_detect_engine_limits(size_t max_findings, size_t max_tracked_keys_per_map,
                                                  size_t max_originators_per_server) {
    DetectEngineLimits limits;
    if (max_findings != 0) limits.max_findings = max_findings;
    if (max_tracked_keys_per_map != 0) limits.max_tracked_keys_per_map = max_tracked_keys_per_map;
    if (max_originators_per_server != 0) limits.max_originators_per_server = max_originators_per_server;
    return limits;
}

// patch257 security review finding 3 fix -- AssetInventoryEngine's own four growth ceilings' CLI
// options, registered only on `inventory` (same reasoning as add_baseline_engine_limit_options/
// add_detect_engine_limit_options above). Same "0 = leave every site at its own default"
// convention as every other --max-* flag in this file.
void add_inventory_engine_limit_options(CLI::App* cmd, size_t& max_assets, size_t& max_edges,
                                          size_t& max_tcp_sessions, size_t& max_notable_protocols) {
    cmd->add_option(
           "--max-inventory-assets", max_assets,
           "Cap the number of distinct IP addresses AssetInventoryEngine records as assets per "
           "capture (default 200,000). 0 = leave it at its own default; past this, further new "
           "assets observed in the capture are not recorded and the inventory is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-inventory-edges", max_edges,
           "Cap the number of distinct (client, server, protocol, port) edges AssetInventoryEngine "
           "records per capture (default 200,000). 0 = leave it at its own default; past this, "
           "further new edges observed in the capture are not recorded and the inventory is marked "
           "incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-inventory-tcp-sessions", max_tcp_sessions,
           "Cap the number of distinct TCP sessions AssetInventoryEngine tracks per capture for "
           "client/server direction inference (default 50,000). 0 = leave it at its own default; "
           "past this, further new sessions fall back to the known-port heuristic instead of "
           "SYN/SYN-ACK tracking and the inventory is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-inventory-notable-protocols", max_notable_protocols,
           "Cap the number of distinct notable-IT-protocol observations (ROADMAP item 18) "
           "AssetInventoryEngine records per capture (default 50,000). 0 = leave it at its own "
           "default; past this, further new combinations are not recorded and the inventory is "
           "marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
}

// Resolves the four raw CLI values (0 = unset) into a real AssetInventoryEngineLimits, same
// "always a fully-resolved struct, never a sentinel" convention as resolve_baseline_engine_limits
// above.
AssetInventoryEngineLimits resolve_inventory_engine_limits(size_t max_assets, size_t max_edges,
                                                              size_t max_tcp_sessions,
                                                              size_t max_notable_protocols) {
    AssetInventoryEngineLimits limits;
    if (max_assets != 0) limits.max_assets = max_assets;
    if (max_edges != 0) limits.max_edges = max_edges;
    if (max_tcp_sessions != 0) limits.max_tcp_sessions = max_tcp_sessions;
    if (max_notable_protocols != 0) limits.max_notable_protocols = max_notable_protocols;
    return limits;
}

// patch257 security review finding 3 fix -- PolicyEngine's own four growth ceilings' CLI options,
// registered only on `policy validate` (same reasoning as add_baseline_engine_limit_options/
// add_detect_engine_limit_options/add_inventory_engine_limit_options above). Same "0 = leave every
// site at its own default" convention as every other --max-* flag in this file.
void add_policy_engine_limit_options(CLI::App* cmd, size_t& max_tcp_flows, size_t& max_udp_flows,
                                       size_t& max_ethernet_flows, size_t& max_notable_protocols) {
    cmd->add_option(
           "--max-policy-tcp-flows", max_tcp_flows,
           "Cap the number of distinct TCP flows PolicyEngine tracks per capture (default "
           "200,000). 0 = leave it at its own default; past this, further new flows observed in "
           "the capture are not evaluated and the result is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-policy-udp-flows", max_udp_flows,
           "Cap the number of distinct UDP flows (BACnet/IP, CIP I/O, HART-IP, FF-HSE) PolicyEngine "
           "tracks per capture (default 100,000). 0 = leave it at its own default; past this, "
           "further new flows observed in the capture are not evaluated and the result is marked "
           "incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-policy-ethernet-flows", max_ethernet_flows,
           "Cap the number of distinct raw-Ethernet L2 flows (PROFINET RT/GOOSE/SV/EtherCAT) "
           "PolicyEngine tracks per capture (default 100,000). 0 = leave it at its own default; "
           "past this, further new flows observed in the capture are not evaluated and the result "
           "is marked incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-policy-notable-protocols", max_notable_protocols,
           "Cap the number of distinct notable-IT-protocol observations (ROADMAP item 18) "
           "PolicyEngine records per capture (default 50,000). 0 = leave it at its own default; "
           "past this, further new combinations are not recorded and the result is marked "
           "incomplete")->group("Resource limits (advanced)")
        ->capture_default_str();
}

// Resolves the four raw CLI values (0 = unset) into a real PolicyEngineLimits, same "always a
// fully-resolved struct, never a sentinel" convention as resolve_baseline_engine_limits above.
PolicyEngineLimits resolve_policy_engine_limits(size_t max_tcp_flows, size_t max_udp_flows,
                                                  size_t max_ethernet_flows, size_t max_notable_protocols) {
    PolicyEngineLimits limits;
    if (max_tcp_flows != 0) limits.max_tcp_flows = max_tcp_flows;
    if (max_udp_flows != 0) limits.max_udp_flows = max_udp_flows;
    if (max_ethernet_flows != 0) limits.max_ethernet_flows = max_ethernet_flows;
    if (max_notable_protocols != 0) limits.max_notable_protocols = max_notable_protocols;
    return limits;
}

// `info`-only now (its `-z conv,ip`/`-z endpoints,ip`/`-z conv,eth`/`-z endpoints,eth` -- see that
// option's own help text just above its registration) -- hands these straight to StatsWriter's own
// constructor (output.hpp/output.cpp), which resolves 0 into kDefaultMaxConversationEntries/
// kDefaultMaxEndpointEntries the same "0 = leave it at its own default" convention as
// add_policy_engine_limit_options above. Conversations/Endpoints tables (tshark's own
// `-z conv,ip`/`-z endpoints,ip` as design precedent) are the one part of StatsWriter's output
// keyed by attacker-controlled, effectively unbounded-cardinality identity (IP/MAC addresses),
// unlike every other StatsWriter table (a small fixed vocabulary of protocol/function names) --
// see output.hpp's own comment on this.
void add_conversation_stats_options(CLI::App* cmd, size_t& max_conversations, size_t& max_endpoints) {
    cmd->add_option(
           "--max-conversations", max_conversations,
           "Cap the number of distinct address-pair conversations tracked for the "
           "Conversations tables (IPv4 and Ethernet, each capped independently; default "
           "200,000). 0 = leave it at its own default; past this, a packet between a new, "
           "not-yet-seen address pair is dropped from these tables only (every other -z/info "
           "counter is unaffected), and a warning line is printed")->group("Resource limits (advanced)")
        ->capture_default_str();
    cmd->add_option(
           "--max-endpoints", max_endpoints,
           "Cap the number of distinct addresses tracked for the Endpoints tables (IPv4 and "
           "Ethernet, each capped independently; default 200,000). 0 = leave it at its own "
           "default; past this, a packet naming a new, not-yet-seen address is dropped from "
           "these tables only, and a warning line is printed")->group("Resource limits (advanced)")
        ->capture_default_str();
}

// ROADMAP item 108 ("Follow stream as a first-class object") -- validates one `-z` value for
// `info` (that option's own help text, below, lists the full accepted set). Returns "" when
// valid, else an error message CLI11 prefixes with the option's own name (CLI11.hpp's
// Option::_validate_results -- the printed line ends up "... -- --stat: <this message>"). A
// custom ->check() rather than the original four conv,ip/endpoints,ip/conv,eth/endpoints,eth
// values' own CLI::IsMember, because 'follow,tcp,stream,<N>'/'follow,udp,stream,<N>' carry a
// variable numeric suffix IsMember's fixed-set membership test can't express -- the same "no
// CLI11 declarative validator fits, so parse it by hand" posture -d/--decode-as's own
// parse_decode_as_rules (above) already established for a different variable-shaped value. Only
// validates SHAPE here; run_info re-parses the numeric suffix with std::stoull (its own range/
// overflow check) rather than duplicating that here -- this function's only job is to reject
// anything CLI11 shouldn't even hand to run_info as one of its four fixed strings or a
// well-shaped follow,<tcp|udp>,stream,<N>.
std::string validate_stat_value(const std::string& value) {
    static const std::vector<std::string> kFixedValues = {
        "conv,ip", "endpoints,ip", "conv,eth", "endpoints,eth", "conv,tcp",
    };
    for (const auto& fixed : kFixedValues) {
        if (value == fixed) return "";
    }
    for (const char* prefix : {"follow,tcp,stream,", "follow,udp,stream,"}) {
        const std::string p = prefix;
        if (value.rfind(p, 0) != 0) continue;
        const std::string suffix = value.substr(p.size());
        bool all_digits = !suffix.empty();
        for (char c : suffix) {
            if (c < '0' || c > '9') { all_digits = false; break; }
        }
        if (!all_digits) {
            return "'" + value + "' must end with a non-negative integer stream index (e.g. '" + p + "0')";
        }
        return "";
    }
    return "'" + value +
           "' not in {conv,ip, endpoints,ip, conv,eth, endpoints,eth, conv,tcp, "
           "follow,tcp,stream,<N>, follow,udp,stream,<N>}";
}

// -------------------------------------------------------------------------------------------
// `-d`/`--decode-as` (Wireshark/tshark-style "force a decoder onto traffic that wouldn't
// otherwise be recognized as it") -- see decoder.hpp's own comment on DecodeAsRule/
// DecodeOptions::decode_as for the full design and its deliberate scope: PORT-GATED protocols
// only, not the ~40 opportunistic ICS protocols (already tried on every port by structural
// signature -- forcing them onto a port is meaningless) and not the tunnel-vpn tier's
// IP-protocol-number-gated names (gre/nvgre/eoip/esp/ah/ip-in-ip/6in4 -- a
// `tcp.port==`/`udp.port==` selector can't express those; a future `ip.proto==` selector is the
// natural follow-on, not silently supported here).
//
// Two different resolution mechanisms sit behind the identical `<tcp|udp>.port==<port>,<name>`
// CLI syntax (a deliberate SUBSET of tshark's own much larger `-d` selector grammar --
// `ether.type==`/`tcp.port==`/`udp.port==`/etc. -- only the latter two are supported here):
//
//   - "Group A" names already have their own dedicated --X-port option and CLI-local port
//     vector (e.g. --dns-port / decode_dns_ports) that this decoder consults directly -- see
//     decoder.cpp's own per-protocol dispatch. Resolving a Group A `-d` rule is nothing more
//     than pushing its port into that SAME vector: zero decoder.cpp changes, and identical
//     effect to having passed --dns-port <port> directly.
//   - "Group B/C" names are the ~30 protocol names packed into 5 shared "IT protocol" tiers
//     (remote-access/lateral-movement/enterprise-trust/wireless-backhaul/tunnel-vpn), where
//     today only the WHOLE TIER can be widened via one shared extra_X_ports list -- there is no
//     existing mechanism to force one SPECIFIC name within a tier onto a port (whichever name's
//     own check happens to come first in that tier's if/else chain wins). These resolve into a
//     DecodeAsRule appended to `*out_group_bc_rules`, which the caller threads into
//     DecodeOptions::decode_as -- consulted only as each tier's own LAST RESORT, after every
//     existing structural/port check in that tier has already failed to match anything (see
//     it_protocols.hpp/tunnel_vpn.hpp's own `decode_as_hint` parameter comments) -- so a `-d`
//     rule never overrides a stronger, already-correct match.
struct DecodeAsGroupATarget {
    const char* name;
    bool is_tcp;               // the ONE transport this name's own decoder actually gates on
    std::vector<int>* ports;   // the CLI-local vector this name's own --X-port option fills
};

// Every Group B/C name this release supports: which tier it belongs to (for error messages
// only -- DecodeAsRule itself doesn't carry a tier), and which transport(s) that name's own code
// actually reaches (see it_protocols.cpp/tunnel_vpn.cpp) -- so a transport/name mismatch (e.g.
// `udp.port==636,ldaps` -- LDAPS is TCP-only) is caught HERE, at parse time, with a clear error,
// rather than silently building a DecodeAsRule no call site will ever match.
struct DecodeAsGroupBName {
    const char* name;
    const char* tier;
    bool valid_tcp;
    bool valid_udp;
};

// Parses and validates every `-d`/`--decode-as` rule given on the CLI. On success, returns true
// having (1) pushed each Group A rule's port into its own --X-port CLI vector, via `group_a` --
// the exact targets this build offers, one entry per Group A name -- and (2) appended one
// DecodeAsRule to `*out_group_bc_rules` per Group B/C rule. On any malformed rule, unrecognized
// name, or transport/name mismatch, prints a clear "error: -d/--decode-as ..." message to
// std::cerr and returns false -- rules earlier in the list may already have been applied, the
// same "process in order, fail fast" posture the rest of this file's CLI validation uses (e.g.
// --time-format/--time-offset in run_decode below).
bool parse_decode_as_rules(const std::vector<std::string>& raw,
                            const std::vector<DecodeAsGroupATarget>& group_a,
                            std::vector<DecodeAsRule>* out_group_bc_rules) {
    static const std::vector<DecodeAsGroupBName> kGroupBNames = {
        {"rdp", "remote-access", true, true},
        {"vnc", "remote-access", true, true},
        {"teamviewer", "remote-access", true, true},
        {"anydesk", "remote-access", true, true},
        {"zoom", "remote-access", true, true},
        {"ssh", "lateral-movement", true, false},
        {"http", "lateral-movement", true, false},
        {"https", "lateral-movement", true, false},
        {"telnet", "lateral-movement", true, false},
        {"ftp", "lateral-movement", true, false},
        {"snmp", "lateral-movement", false, true},
        {"tftp", "lateral-movement", false, true},
        {"ntp", "enterprise-trust", false, true},
        {"dhcp", "enterprise-trust", false, true},
        {"radius", "enterprise-trust", false, true},
        {"ldaps", "enterprise-trust", true, false},
        {"tacacs-plus", "enterprise-trust", true, false},
        {"capwap-control", "wireless-backhaul", false, true},
        {"capwap-data", "wireless-backhaul", false, true},
        {"lwapp-control", "wireless-backhaul", false, true},
        {"lwapp-data", "wireless-backhaul", false, true},
        {"gtp-u", "wireless-backhaul", false, true},
        {"ike", "tunnel-vpn", false, true},
        {"l2tp", "tunnel-vpn", false, true},
        {"vxlan", "tunnel-vpn", false, true},
        {"geneve", "tunnel-vpn", false, true},
        {"wireguard", "tunnel-vpn", false, true},
        {"openvpn", "tunnel-vpn", true, true},
        {"dtls-tunnel", "tunnel-vpn", false, true},
        {"stt", "tunnel-vpn", true, false},
    };

    for (const std::string& rule_text : raw) {
        bool is_tcp;
        if (rule_text.rfind("tcp.port==", 0) == 0) {
            is_tcp = true;
        } else if (rule_text.rfind("udp.port==", 0) == 0) {
            is_tcp = false;
        } else {
            std::cerr << "error: -d/--decode-as '" << rule_text
                       << "' must start with 'tcp.port==' or 'udp.port==' (e.g. "
                          "-d tcp.port==8443,ldaps)\n";
            return false;
        }
        // "tcp.port==" and "udp.port==" are both exactly 10 characters -- either prefix's length
        // works here.
        std::string rest = rule_text.substr(std::string("tcp.port==").size());
        size_t comma = rest.find(',');
        if (comma == std::string::npos) {
            std::cerr << "error: -d/--decode-as '" << rule_text
                       << "' is missing the ',<name>' part (e.g. -d tcp.port==8443,ldaps)\n";
            return false;
        }
        std::string port_text = rest.substr(0, comma);
        std::string name = rest.substr(comma + 1);
        if (name.empty()) {
            std::cerr << "error: -d/--decode-as '" << rule_text << "' has an empty protocol name\n";
            return false;
        }
        int port_value = -1;
        try {
            size_t consumed = 0;
            port_value = std::stoi(port_text, &consumed);
            if (consumed != port_text.size()) port_value = -1;
        } catch (...) {
            port_value = -1;
        }
        if (port_value < 1 || port_value > 65535) {
            std::cerr << "error: -d/--decode-as '" << rule_text << "' has an invalid port '"
                       << port_text << "' (expected an integer 1-65535)\n";
            return false;
        }
        uint16_t port = static_cast<uint16_t>(port_value);

        bool resolved = false;
        for (const auto& target : group_a) {
            if (name == target.name) {
                if (target.is_tcp != is_tcp) {
                    std::cerr << "error: -d/--decode-as '" << rule_text << "': '" << name << "' is a "
                               << (target.is_tcp ? "TCP" : "UDP") << "-only protocol, not "
                               << (is_tcp ? "TCP" : "UDP") << "\n";
                    return false;
                }
                target.ports->push_back(port);
                resolved = true;
                break;
            }
        }
        if (resolved) continue;

        bool found_group_b = false;
        for (const auto& gb : kGroupBNames) {
            if (name == gb.name) {
                found_group_b = true;
                bool ok = is_tcp ? gb.valid_tcp : gb.valid_udp;
                if (!ok) {
                    std::cerr << "error: -d/--decode-as '" << rule_text << "': '" << name << "' (tier \""
                               << gb.tier << "\") is " << (gb.valid_tcp ? "TCP" : "UDP")
                               << "-only, not " << (is_tcp ? "TCP" : "UDP") << "\n";
                    return false;
                }
                out_group_bc_rules->push_back(DecodeAsRule{is_tcp, port, name});
                break;
            }
        }
        if (found_group_b) continue;

        std::cerr << "error: -d/--decode-as '" << rule_text << "': unrecognized protocol name '" << name
                   << "' -- see 'conduitscope decode --help's -d/--decode-as entry for the full list "
                      "of supported names (port-gated protocols only; the opportunistic ICS "
                      "protocols and the tunnel-vpn tier's IP-protocol-number-gated names are out "
                      "of scope for -d in this release)\n";
        return false;
    }
    return true;
}

int run_decode(const std::string& input, const std::string& interface_name, const std::string& filter,
                int duration_seconds, int snaplen, bool promiscuous, const std::string& output,
                const std::string& format, const std::string& protocol, const std::vector<int>& modbus_ports,
                const std::vector<int>& dnp3_ports, const std::vector<int>& s7comm_ports,
                const std::vector<int>& iec104_ports, const std::vector<int>& enip_ports,
                const std::vector<int>& enip_io_ports, const std::vector<int>& bacnet_ports,
                const std::vector<int>& hartip_ports, const std::vector<int>& kerberos_ports,
                const std::vector<int>& ldap_ports, const std::vector<int>& smb_ports,
                const std::vector<int>& melsec_ports,
                const std::vector<int>& fins_ports,
                const std::vector<int>& bgp_ports,
                const std::vector<int>& opcua_ports,
                const std::vector<int>& mqtt_ports, const std::vector<int>& ffhse_ports,
                const std::vector<int>& dns_ports, const std::vector<int>& mdns_ports,
                const std::vector<int>& llmnr_ports, const std::vector<int>& nbns_ports,
                const std::vector<int>& doh_ports, const std::vector<int>& rip_ports,
                const std::vector<int>& hsrp_ports, const std::vector<int>& remote_access_ports,
                const std::vector<int>& lateral_movement_ports,
                const std::vector<int>& enterprise_trust_ports,
                const std::vector<int>& wireless_backhaul_ports,
                const std::vector<int>& tunnel_vpn_ports,
                const std::vector<int>& winrm_ports,
                const std::vector<int>& dcom_ports,
                const std::vector<int>& ge_srtp_ports,
                const std::vector<int>& bsap_ports,
                const std::vector<int>& cclink_ie_ports,
                const std::vector<int>& codesys_ports,
                const std::vector<int>& coap_ports,
                const std::vector<int>& rmcp_ports,
                const std::vector<int>& amqp_ports,
                const std::vector<int>& dicom_ports,
                const std::vector<int>& fox_ports,
                const std::vector<int>& powerlink_sdo_ports,
                const std::vector<int>& dhcpv6_ports,
                const std::vector<DecodeAsRule>& decode_as_rules,
                size_t flood_threshold,
                size_t max_packets,
                const std::string& range_text,
                const ResourceLimitCliVars& limit_vars,
                bool strict, bool quiet,
                bool no_color, bool force_color,
                bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                bool service_names_enabled, const std::string& services_path, bool show_vlan,
                const std::string& time_format, const std::string& time_offset,
                std::ostream& diag, bool show_direction, bool show_mac,
                const std::vector<std::string>& fields, const std::string& write_path, bool hex_dump,
                bool verbose, bool details, bool redact, bool detect_highlight,
                const std::optional<CompiledDisplayFilter>& display_filter) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    bool writing_to_stdout = output.empty();
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    // Three-way resolution, same convention as grep/git/ripgrep: --color always wins (even
    // redirected to a file -- e.g. piping through `less -R`, or deliberately saving colored
    // output, are the user's explicit choice), --no-color always disables, and absent either,
    // color is used only when actually writing to an interactive terminal -- never into a file
    // (-o) or a pipe, so ANSI escapes don't end up littering saved/piped output by default.
    bool color = force_color || (!no_color && writing_to_stdout && stdout_is_terminal());

    // Both already validated for a legal *set of values* by CLI11 -- -t/--time-format via
    // CLI::IsMember, so parse_time_format below can never actually see an unrecognized mnemonic --
    // but --time-offset's "+HH:MM"/"-HHMM"/bare-hour syntax is open-ended and CLI11 has no
    // validator for it, so parse_time_offset's std::nullopt is the only place a malformed
    // --time-offset value is ever caught. Parsed once, up front, before opening the packet source
    // or resolver -- same "fail fast on bad setup" posture the Resolver construction below already
    // follows -- so a typo like --time-offset=+25:00 is reported immediately rather than after
    // capture has already started.
    std::optional<TimeFormat> parsed_time_format = parse_time_format(time_format);
    if (!parsed_time_format) {
        std::cerr << "error: invalid --time-format value '" << time_format << "'\n";
        return 1;
    }
    std::optional<TimeOffset> parsed_time_offset = parse_time_offset(time_offset);
    if (!parsed_time_offset) {
        std::cerr << "error: invalid --time-offset value '" << time_offset
                   << "' (expected 'utc', 'local', or a fixed offset like '+02:00'/'-0530')\n";
        return 1;
    }

    // --range (packet_range.hpp) -- an empty range_text means the option wasn't given at all
    // (parsed_range stays std::nullopt, and PacketSource::next() below skips nothing extra), not
    // "select nothing"; a non-empty string that fails to parse is reported here, same "fail fast
    // on bad setup" posture as the two time-format checks just above, before opening the packet
    // source. -i already excludes --range at the CLI-option level (see main() below), so
    // range_text is never non-empty when interface_name is -- no need to check that combination
    // again here.
    std::optional<PacketRangeSpec> parsed_range;
    if (!range_text.empty()) {
        parsed_range = parse_packet_range(range_text);
        if (!parsed_range) {
            std::cerr << "error: invalid --range value '" << range_text
                       << "' (expected comma-separated 1-based packet numbers and/or inclusive "
                          "start-end ranges, e.g. '5,10-20,30-40')\n";
            return 1;
        }
    }

    // -T fields (mirrors tshark's own -T fields/-e) needs at least one -e/--field to have
    // anything to print -- caught here, before opening the packet source, same "fail fast on bad
    // setup" posture as the two time-format checks just above. Conversely, -e given without
    // -T fields is a no-op this codebase would rather flag than silently ignore -- it almost
    // always means the user meant to also pass -T fields.
    if (format == "fields" && fields.empty()) {
        std::cerr << "error: --format fields (-T fields) needs at least one -e/--field\n";
        return 1;
    }
    if (format != "fields" && !fields.empty() && !quiet) {
        diag << "note: -e/--field only applies with --format fields (-T fields); ignoring\n";
    }

    DecodeOptions options;
    options.strict = strict;
    options.redact_secrets = redact;
    options.limits = build_resource_limits(limit_vars);
    options.protocol_filter = (protocol == "modbus")  ? ProtocolFilter::ModbusOnly
                               : (protocol == "dnp3")  ? ProtocolFilter::Dnp3Only
                               : (protocol == "s7comm") ? ProtocolFilter::S7commOnly
                               : (protocol == "mms")    ? ProtocolFilter::MmsOnly
                               : (protocol == "iec104") ? ProtocolFilter::Iec104Only
                               : (protocol == "enip")   ? ProtocolFilter::EnipOnly
                               : (protocol == "profinet") ? ProtocolFilter::ProfinetOnly
                               : (protocol == "goose")  ? ProtocolFilter::GooseOnly
                               : (protocol == "sv")     ? ProtocolFilter::SvOnly
                               : (protocol == "ethercat") ? ProtocolFilter::EthercatOnly
                               : (protocol == "stp")    ? ProtocolFilter::StpOnly
                               : (protocol == "devicenet") ? ProtocolFilter::DevicenetOnly
                               : (protocol == "canopen") ? ProtocolFilter::CanopenOnly
                               : (protocol == "j1939")   ? ProtocolFilter::J1939Only
                               : (protocol == "bacnet") ? ProtocolFilter::BacnetOnly
                               : (protocol == "hartip") ? ProtocolFilter::HartIpOnly
                               : (protocol == "opcua")  ? ProtocolFilter::OpcUaOnly
                               : (protocol == "mqtt")   ? ProtocolFilter::MqttOnly
                               : (protocol == "s7comm-plus") ? ProtocolFilter::S7commPlusOnly
                               : (protocol == "ff-hse") ? ProtocolFilter::FfHseOnly
                               : (protocol == "dns")    ? ProtocolFilter::DnsOnly
                               : (protocol == "mdns")   ? ProtocolFilter::MdnsOnly
                               : (protocol == "llmnr")  ? ProtocolFilter::LlmnrOnly
                               : (protocol == "nbns")   ? ProtocolFilter::NbnsOnly
                               : (protocol == "doh")    ? ProtocolFilter::DohOnly
                               : (protocol == "rip")    ? ProtocolFilter::RipOnly
                               : (protocol == "icmp")   ? ProtocolFilter::IcmpOnly
                               : (protocol == "igmp")   ? ProtocolFilter::IgmpOnly
                               : (protocol == "vrrp")   ? ProtocolFilter::VrrpOnly
                               : (protocol == "hsrp")   ? ProtocolFilter::HsrpOnly
                               : (protocol == "igrp")   ? ProtocolFilter::IgrpOnly
                               : (protocol == "pim")    ? ProtocolFilter::PimOnly
                               : (protocol == "eigrp")  ? ProtocolFilter::EigrpOnly
                               : (protocol == "ospf")   ? ProtocolFilter::OspfOnly
                               : (protocol == "remote-access") ? ProtocolFilter::RemoteAccessOnly
                               : (protocol == "lateral-movement") ? ProtocolFilter::LateralMovementOnly
                               : (protocol == "enterprise-trust") ? ProtocolFilter::EnterpriseTrustOnly
                               : (protocol == "eapol")  ? ProtocolFilter::EapolOnly
                               : (protocol == "wireless-backhaul") ? ProtocolFilter::WirelessBackhaulOnly
                               : (protocol == "pppoe")  ? ProtocolFilter::PppoeOnly
                               : (protocol == "tunnel-vpn") ? ProtocolFilter::TunnelVpnOnly
                               : (protocol == "mpls")   ? ProtocolFilter::MplsOnly
                               : (protocol == "arp")    ? ProtocolFilter::ArpOnly
                               : (protocol == "lldp")   ? ProtocolFilter::LldpOnly
                               : (protocol == "twincat") ? ProtocolFilter::TwinCatOnly
                               : (protocol == "kerberos") ? ProtocolFilter::KerberosOnly
                               : (protocol == "ldap")   ? ProtocolFilter::LdapOnly
                               : (protocol == "smb")    ? ProtocolFilter::SmbOnly
                               : (protocol == "melsec") ? ProtocolFilter::MelsecOnly
                               : (protocol == "fins")   ? ProtocolFilter::FinsOnly
                               : (protocol == "bgp")    ? ProtocolFilter::BgpOnly
                               : (protocol == "slow-protocols") ? ProtocolFilter::SlowProtocolsOnly
                               : (protocol == "winrm")  ? ProtocolFilter::WinRmOnly
                               : (protocol == "dcom")   ? ProtocolFilter::DcomOnly
                               : (protocol == "ge-srtp") ? ProtocolFilter::GeSrtpOnly
                               : (protocol == "bsap")   ? ProtocolFilter::BsapOnly
                               : (protocol == "cclink-ie") ? ProtocolFilter::CclinkIeOnly
                               : (protocol == "codesys") ? ProtocolFilter::CodesysOnly
                               : (protocol == "coap")   ? ProtocolFilter::CoapOnly
                               : (protocol == "zigbee") ? ProtocolFilter::ZigbeeOnly
                               : (protocol == "cdp")    ? ProtocolFilter::CdpOnly
                               : (protocol == "asf")    ? ProtocolFilter::AsfOnly
                               : (protocol == "ipmi")   ? ProtocolFilter::IpmiOnly
                               : (protocol == "rmcp")   ? ProtocolFilter::RmcpOnly
                               : (protocol == "amqp091") ? ProtocolFilter::Amqp091Only
                               : (protocol == "amqp10") ? ProtocolFilter::Amqp10Only
                               : (protocol == "dicom")  ? ProtocolFilter::DicomOnly
                               : (protocol == "powerlink") ? ProtocolFilter::PowerlinkOnly
                               : (protocol == "fox")    ? ProtocolFilter::FoxOnly
                               : (protocol == "icmpv6") ? ProtocolFilter::Icmpv6Only
                               : (protocol == "dhcpv6") ? ProtocolFilter::Dhcpv6Only
                               : (protocol == "homeplug-av") ? ProtocolFilter::HomeplugAvOnly
                                                        : ProtocolFilter::Auto;
    for (int p : modbus_ports) options.extra_modbus_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dnp3_ports) options.extra_dnp3_ports.push_back(static_cast<uint16_t>(p));
    for (int p : s7comm_ports) options.extra_s7comm_ports.push_back(static_cast<uint16_t>(p));
    for (int p : iec104_ports) options.extra_iec104_ports.push_back(static_cast<uint16_t>(p));
    for (int p : enip_ports) options.extra_enip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : enip_io_ports) options.extra_enip_io_ports.push_back(static_cast<uint16_t>(p));
    for (int p : bacnet_ports) options.extra_bacnet_ports.push_back(static_cast<uint16_t>(p));
    for (int p : hartip_ports) options.extra_hartip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : kerberos_ports) options.extra_kerberos_ports.push_back(static_cast<uint16_t>(p));
    for (int p : ldap_ports) options.extra_ldap_ports.push_back(static_cast<uint16_t>(p));
    for (int p : smb_ports) options.extra_smb_ports.push_back(static_cast<uint16_t>(p));
    for (int p : melsec_ports) options.extra_melsec_ports.push_back(static_cast<uint16_t>(p));
    for (int p : fins_ports) options.extra_fins_ports.push_back(static_cast<uint16_t>(p));
    for (int p : bgp_ports) options.extra_bgp_ports.push_back(static_cast<uint16_t>(p));
    for (int p : opcua_ports) options.extra_opcua_ports.push_back(static_cast<uint16_t>(p));
    for (int p : mqtt_ports) options.extra_mqtt_ports.push_back(static_cast<uint16_t>(p));
    for (int p : ffhse_ports) options.extra_ffhse_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dns_ports) options.extra_dns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : mdns_ports) options.extra_mdns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : llmnr_ports) options.extra_llmnr_ports.push_back(static_cast<uint16_t>(p));
    for (int p : nbns_ports) options.extra_nbns_ports.push_back(static_cast<uint16_t>(p));
    for (int p : doh_ports) options.extra_doh_ports.push_back(static_cast<uint16_t>(p));
    for (int p : rip_ports) options.extra_rip_ports.push_back(static_cast<uint16_t>(p));
    for (int p : hsrp_ports) options.extra_hsrp_ports.push_back(static_cast<uint16_t>(p));
    for (int p : remote_access_ports) options.extra_remote_access_ports.push_back(static_cast<uint16_t>(p));
    for (int p : lateral_movement_ports) options.extra_lateral_movement_ports.push_back(static_cast<uint16_t>(p));
    for (int p : enterprise_trust_ports) options.extra_enterprise_trust_ports.push_back(static_cast<uint16_t>(p));
    for (int p : wireless_backhaul_ports) options.extra_wireless_backhaul_ports.push_back(static_cast<uint16_t>(p));
    for (int p : tunnel_vpn_ports) options.extra_tunnel_vpn_ports.push_back(static_cast<uint16_t>(p));
    for (int p : winrm_ports) options.extra_winrm_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dcom_ports) options.extra_dcom_ports.push_back(static_cast<uint16_t>(p));
    for (int p : ge_srtp_ports) options.extra_ge_srtp_ports.push_back(static_cast<uint16_t>(p));
    for (int p : bsap_ports) options.extra_bsap_ports.push_back(static_cast<uint16_t>(p));
    for (int p : cclink_ie_ports) options.extra_cclink_ie_ports.push_back(static_cast<uint16_t>(p));
    for (int p : codesys_ports) options.extra_codesys_ports.push_back(static_cast<uint16_t>(p));
    for (int p : coap_ports) options.extra_coap_ports.push_back(static_cast<uint16_t>(p));
    for (int p : rmcp_ports) options.extra_rmcp_ports.push_back(static_cast<uint16_t>(p));
    for (int p : amqp_ports) options.extra_amqp_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dicom_ports) options.extra_dicom_ports.push_back(static_cast<uint16_t>(p));
    for (int p : fox_ports) options.extra_fox_ports.push_back(static_cast<uint16_t>(p));
    for (int p : powerlink_sdo_ports) options.extra_powerlink_sdo_ports.push_back(static_cast<uint16_t>(p));
    for (int p : dhcpv6_ports) options.extra_dhcpv6_ports.push_back(static_cast<uint16_t>(p));
    options.decode_as = decode_as_rules;
    if (flood_threshold > 0) options.flood_threshold = flood_threshold;

    try {
        // Built once per `decode` invocation, before opening the packet source, so a bad --hosts/
        // --services file (ResolverError -- see resolver.hpp) is reported before this process does
        // anything else, same "fail fast on bad setup" posture as parse_policy_file in
        // run_policy_validate below. Its own advisory notes (e.g. "--resolve with no --hosts
        // file") are printed the same way every other decode-time advisory already is --
        // unconditionally to `diag`, respecting --quiet -- not per-packet, since they describe the
        // whole run's configuration, not any one packet.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled,
                           services_path, resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        PacketSource source = open_packet_source(input, interface_name, snaplen, promiscuous, filter,
                                                   duration_seconds, max_packets);
        // --range is `decode`-only for now (see packet_range.hpp's own file header comment) --
        // open_packet_source itself stays unaware of it, same as it stays unaware of anything
        // else that's decode-specific, since it's also shared by `policy validate`/`inventory`.
        if (parsed_range) source.set_range_filter(std::move(*parsed_range));
        // `color` here (not a literal false) is what makes handle_sigint restore the terminal's
        // default colors on Ctrl+C -- see SigintGuard's own comment.
        SigintGuard sigint_guard(source.live_ptr(), color);
        Decoder decoder(options);

        std::unique_ptr<OutputWriter> writer;
        if (format == "json") {
            writer = std::make_unique<JsonWriter>(*out, resolver, show_vlan, *parsed_time_format,
                                                    *parsed_time_offset, show_direction);
        } else if (format == "csv") {
            writer = std::make_unique<CsvWriter>(*out, resolver, show_vlan, *parsed_time_format,
                                                   *parsed_time_offset, show_direction);
        } else if (format == "fields") {
            writer = std::make_unique<FieldsWriter>(*out, resolver, fields, show_vlan, *parsed_time_format,
                                                      *parsed_time_offset, show_direction);
        } else if (format == "zeek") {
            writer = std::make_unique<ZeekWriter>(*out);
        } else if (details) {
            // -V/--details: only meaningful for the default text output -- see its own help text
            // ("ignored under --format json/csv/fields/zeek"), the same posture -x/--hex already
            // has, so this branch only exists inside the `format` "else" (text) case.
            writer = std::make_unique<DetailWriter>(*out, color, resolver, show_vlan, *parsed_time_format,
                                                      *parsed_time_offset, show_direction);
        } else {
            writer = std::make_unique<TextWriter>(*out, color, resolver, show_vlan, *parsed_time_format,
                                                    *parsed_time_offset, show_direction, show_mac, verbose);
        }
        writer->begin();

        // -w (mirrors tshark/tcpdump's own -w): a real, reopenable classic-pcap file of every raw
        // packet that reaches this loop -- for a live capture (-i) that's everything seen on the
        // wire; for an offline read (-r) combined with --filter, --filter already narrowed what
        // PacketSource::next() hands back, so this naturally captures "the filtered subset" for
        // free without -w needing to know anything about filtering itself. Built from the loop-local
        // PcapPacket (raw bytes + real captured/original lengths + real per-packet timestamp), not
        // from DecodedPacket, which never retains raw bytes -- see pcap_writer.hpp. Opened here, once,
        // before the main loop -- same "fail fast on bad setup" posture as the Resolver/PacketSource
        // construction just above -- so a bad -w path (unwritable directory, etc.) is reported before
        // any capture/read work happens rather than mid-run.
        std::unique_ptr<PcapWriter> pcap_writer;
        if (!write_path.empty()) {
            pcap_writer = std::make_unique<PcapWriter>(write_path, source.linktype());
        }

        // Separate layer on top of Decoder's already-public output (see flow_direction.hpp's own
        // file header) -- fills in each TCP packet's has_direction/direction_client_is_src/
        // direction_source fields (decoder.hpp) in place, right after decode() and before the
        // packet reaches any writer, mirroring how PolicyEngine/AssetInventoryEngine each track
        // direction for `policy validate`/`inventory`. One instance per `decode` invocation, fed in
        // strict capture order, the same discipline `decoder` itself follows.
        FlowDirectionTracker direction_tracker;

        // `--detect-highlight`'s own live "always-notable highlighting" (see docs/USER_GUIDE.md's
        // own subsection under `decode`, and DetectEngine::AlwaysNotableHit's own comment,
        // detect_engine.hpp). `pending_hit` is a scratch slot the callback writes into and this
        // loop reads back immediately after each observe() call, right before the packet reaches
        // any writer -- observe() calls the callback synchronously and at most once per packet (see
        // that lambda's own admission logic, detect_engine.cpp), so there is never more than one
        // pending hit outstanding at a time. Constructed with DetectEngine's own compiled-default
        // DetectEngineLimits (kDefaultMaxDetect*, detect_engine.hpp) -- the exact same growth
        // ceilings `detect` itself uses -- so a long-running `decode -i` can't accumulate unbounded
        // internal tracking state any more than a long-running `detect -i` already can't (patch257
        // finding 3); decode exposes no --max-detect-* flags of its own to keep this feature's own
        // CLI surface small, since decode's own report (the printed packets) never grows unbounded
        // the way detect's own findings list does regardless. Only constructed at all when
        // detect_highlight is true -- --no-detect-highlight skips DetectEngine entirely, for zero
        // overhead when the feature isn't wanted.
        std::optional<AlwaysNotableHit> pending_hit;
        std::unique_ptr<DetectEngine> detect_engine;
        if (detect_highlight) {
            detect_engine = std::make_unique<DetectEngine>(
                DetectEngineLimits{}, [&pending_hit](const AlwaysNotableHit& hit) { pending_hit = hit; });
        }

        PcapPacket pkt;
        size_t decoded_count = 0, warnings = 0;
        try {
            while (!g_stop_requested.load(std::memory_order_acquire) && source.next(pkt)) {
                // source.index() -- not a locally incremented counter -- so a `--filter`ed offline
                // read reports each surviving packet under its real position in the file (matching
                // Wireshark's own display-filter numbering), rather than renumbering from 1 within
                // just the matches; see PacketSource::next()'s own comment.
                size_t index = source.index();
                // -w/--write passthrough stays PRE-filter, deliberately: it is raw capture
                // passthrough governed by -f/--filter only (see that flag's own doc text above),
                // not by -Y/--display-filter -- a decode-fidelity-dependent, later-stage concept.
                // Making -w depend on -Y would mean a display-filter expression referencing a field
                // this decoder can't parse could silently drop packets from the raw pcap output, a
                // surprising failure mode for a "give me the raw bytes" flag. Matches tshark's own
                // one-pass (non -2) behavior, where -w combined with a display filter still writes
                // everything captured.
                if (pcap_writer) pcap_writer->write_packet(pkt);
                DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
                // -Y/--display-filter gate: a non-matching packet is invisible to everything below
                // -- direction tracking, detect-highlighting, the output writer, -x hex dump, and
                // (via `continue`, before ++decoded_count) --max-packets counting -- matching
                // Wireshark's own display-filter semantics. A parse-error packet always still counts
                // as a warning below, regardless of the filter (a decode-quality signal, orthogonal
                // to whatever the filter is selecting FOR -- see docs/USER_GUIDE.md's Display
                // filters subsection for this and the -w/--max-packets interaction, both stated
                // explicitly there).
                if (display_filter && dp.protocol != "parse-error" && !display_filter->matches(dp)) {
                    continue;
                }
                direction_tracker.observe(dp);
                if (detect_engine) {
                    pending_hit.reset();
                    detect_engine->observe(dp);
                    if (pending_hit) {
                        dp.has_detect_finding = true;
                        dp.detect_finding_kind = pending_hit->finding_kind ? pending_hit->finding_kind : "";
                        dp.detect_finding_technique =
                            pending_hit->technique.id + " (" + pending_hit->technique.name + ")";
                        dp.detect_finding_description = pending_hit->description;
                    }
                }
                if (dp.protocol == "parse-error") {
                    ++warnings;
                    if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
                }
                writer->write_packet(dp);
                // -x (mirrors tshark's own -x): a hex+ASCII dump of this packet's raw bytes, printed
                // alongside the normal decode -- text format only (matching tshark, whose -x is a
                // human-reading aid, not a structured field).
                if (hex_dump && format != "json" && format != "csv" && format != "fields") {
                    write_hex_ascii_dump(*out, ByteSpan(pkt.data.data(), pkt.data.size()));
                }
                ++decoded_count;
                if (max_packets != 0 && decoded_count >= max_packets) break;
            }
        } catch (const ParseError& e) {
            // A fatal parse error partway through an offline read (a corrupt/truncated capture
            // discovered only after some earlier packets were already decoded and printed) must
            // still leave whatever structured output format is active (json/csv/fields)
            // syntactically well-formed -- an exception unwinding straight past this whole
            // function to main()'s own top-level catch used to skip writer->end() entirely,
            // leaving (for --format json specifically) an array with no closing ']' on stdout.
            // Found via an automated tshark-vs-conduitscope comparison
            // (tools/compare_with_tshark.py) against tests/real_captures/mqtt/
            // mqtt_packets_RedHat61_tcpdump.pcap, a real, deliberately-corrupt fixture (see its
            // own ATTRIBUTION.md) that already has a dedicated test for this exact error message
            // under --format text, where the missing terminator has no effect -- --format json's
            // own version of the same scenario went untested. Finish the output the same way the
            // success path below does, THEN report the error and exit nonzero -- the error
            // message itself is unchanged, only well-formedness of whatever came before it.
            if (writer) writer->end();
            if (color) {
                out->flush();
                if (writing_to_stdout) {
                    write_raw_color_reset_to_stdout();
                } else {
                    *out << "\033[0m";
                    out->flush();
                }
            }
            std::cerr << "error: " << e.what() << "\n";
            return 1;
        } catch (const ProtocolResultTypeMismatch& e) {
            // Same well-formed-output-on-fatal-error treatment as the ParseError catch immediately
            // above, for the same reason -- see that catch's own comment. This one should never
            // actually fire (see ProtocolResultTypeMismatch's own comment, protocol_decoder.hpp);
            // it exists so that IF a future decoder migration ever gets a protocol_id<->T
            // association wrong, the failure is this clean, immediate, reportable error instead of
            // undefined behavior with no useful diagnostic.
            if (writer) writer->end();
            if (color) {
                out->flush();
                if (writing_to_stdout) {
                    write_raw_color_reset_to_stdout();
                } else {
                    *out << "\033[0m";
                    out->flush();
                }
            }
            std::cerr << "error: " << e.what() << "\n";
            return 1;
        }

        writer->end();

        // Authoritative color reset -- belt-and-braces alongside run_sigint_cleanup's own
        // immediate raw-fd write (see its comment above). That handler-thread write is a
        // best-effort backstop for the case this process gets killed before reaching here; it
        // can't be the ONLY reset, because on Windows the handler runs on a separate,
        // genuinely-concurrent thread (see SigintGuard's own comment), while LiveCapture::next()
        // (live_capture.cpp) only checks stop_requested at the TOP of its retry loop -- once
        // pcap_next_ex() has already returned a packet, next() hands it back even if
        // stop_requested was just set. So this main thread can legitimately decode and print one
        // or more MORE colored packets after the handler's own reset write already ran, via
        // ordinary buffered std::cout output that can reach the console AFTER that raw write,
        // undoing it -- that race is what left the terminal colored even with the
        // SetConsoleCtrlHandler fix in place. Doing the reset here instead, on this same thread,
        // strictly after every packet this run will ever print -- regardless of whether the loop
        // above ended via EOF, --duration, --max-packets, or Ctrl+C -- has no such race: nothing
        // this run's colored output ever writes can land after it.
        //
        // Written via write_raw_color_reset_to_stdout() (a small, separate, unbuffered write),
        // not `*out << "\033[0m"`, when writing to stdout specifically -- see that function's own
        // comment: an offline decode has no natural per-packet pacing the way live capture does,
        // so it can flush its entire output in one very large write, and a large single write to a
        // Windows console is documented to sometimes come back short/truncated. Flushing `out`
        // first, then writing the reset as its own small separate call, keeps it decoupled from
        // that risk regardless of how much output came before it. `-o FILE` writes through `*out`
        // as before -- an ordinary file has no such quirk, and the raw write is stdout-specific.
        if (color) {
            out->flush();
            if (writing_to_stdout) {
                write_raw_color_reset_to_stdout();
            } else {
                *out << "\033[0m";
                out->flush();
            }
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << decoded_count
                 << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        // `decode` has no Report/truncation_reasons of its own to fold a drop reason into (see
        // append_live_capture_drop_reason's own comment) -- it's a raw per-packet dump, not a
        // verdict a silent drop could make falsely look clean -- but the OS/driver-level drop
        // count itself is still real data loss worth surfacing plainly. Printed unconditionally,
        // ignoring --quiet: this is the same "affects correctness, not just diagnostic noise"
        // posture run_baseline_learn's own INCOMPLETE warning already takes, not routine progress
        // chatter.
        if (!interface_name.empty() && source.live_ptr() != nullptr) {
            std::optional<std::string> drop_reason =
                format_live_capture_drop_reason(source.live_ptr()->stats());
            if (drop_reason) diag << "warning: " << *drop_reason << "\n";
        }
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int run_info(const std::string& input, std::ostream& out, const std::vector<std::string>& stat_values,
             size_t max_conversations, size_t max_endpoints, size_t max_follow_bytes) {
    try {
        // -z conv,ip / -z endpoints,ip / -z conv,eth / -z endpoints,eth / -z conv,tcp / -z
        // follow,tcp,stream,<N> / -z follow,udp,stream,<N> (tshark's own `-z` as design precedent)
        // -- repeatable, explicit opt-in; info_cmd's own validate_stat_value check (above) already
        // rejects anything else, so stat_values here only ever holds the five fixed spellings or a
        // well-shaped follow,<tcp|udp>,stream,<N>, each at most whatever multiplicity the user
        // repeated it. The numeric suffix's own std::stoull is re-parsed here (not reused from
        // validate_stat_value, which only checked its SHAPE) -- same division of labor
        // parse_decode_as_rules' own port-number parsing has relative to its own CLI11-level shape
        // checks elsewhere in this file.
        RequestedStatsTables tables;
        std::vector<FollowStreamRequest> follow_requests;
        for (const auto& value : stat_values) {
            if (value == "conv,ip") { tables.ip_conversations = true; continue; }
            if (value == "endpoints,ip") { tables.ip_endpoints = true; continue; }
            if (value == "conv,eth") { tables.eth_conversations = true; continue; }
            if (value == "endpoints,eth") { tables.eth_endpoints = true; continue; }
            if (value == "conv,tcp") { tables.tcp_conversations = true; continue; }
            for (bool is_tcp : {true, false}) {
                const std::string prefix = is_tcp ? "follow,tcp,stream," : "follow,udp,stream,";
                if (value.rfind(prefix, 0) != 0) continue;
                // validate_stat_value (above) already confirmed the suffix is all-digits and
                // non-empty; std::stoull can still throw out_of_range for a suffix with more
                // digits than fit in an unsigned long long (an implausible but user-typeable
                // stream index) -- caught here rather than left to propagate and terminate the
                // process, the same "a malformed value is a clean error, never a crash" posture
                // parse_decode_as_rules' own std::stoi handling (above) already established.
                try {
                    FollowStreamRequest req;
                    req.is_tcp = is_tcp;
                    req.stream_index = std::stoull(value.substr(prefix.size()));
                    follow_requests.push_back(req);
                } catch (const std::exception&) {
                    std::cerr << "error: -z '" << value << "' has a stream index too large to "
                                  "represent\n";
                    return 1;
                }
                break;
            }
        }
        PcapReader reader(input);
        // capture_transport_payload is opt-in specifically because at least one follow,tcp/
        // follow,udp table was requested -- see DecodeOptions::capture_transport_payload's own
        // comment; every other `info` invocation (including one that only asked for conv,ip/
        // conv,tcp/endpoints,*) leaves this false and pays nothing for it.
        DecodeOptions decode_opts;
        decode_opts.capture_transport_payload = !follow_requests.empty();
        Decoder decoder(decode_opts);
        // ROADMAP item 109 -- Jurgen's own explicit request: "If the -z option is used, no output
        // is expected except of the -z option output." stat_output_only mirrors exactly what
        // gated `info`'s own pre-item-109 default behavior (stat_values empty means classic `info`
        // -- file metadata, packet count, protocol histogram, no -z tables at all) -- true the
        // moment the caller passed at least one `-z` value, whether `info` was typed explicitly or
        // (see inject_default_subcommand, above main()) selected automatically because `-z`
        // appeared with no subcommand at all.
        const bool stat_output_only = !stat_values.empty();
        StatsWriter stats_writer(tables, max_conversations, max_endpoints, stat_output_only);
        FollowStreamWriter follow_writer(follow_requests, max_follow_bytes);

        PcapPacket pkt;
        size_t index = 0;
        while (reader.next(pkt)) {
            ++index;
            DecodedPacket decoded = decoder.decode(pkt, reader.info().linktype, index);
            stats_writer.write_packet(decoded);
            if (!follow_requests.empty()) follow_writer.write_packet(decoded);
        }

        if (!stat_output_only) {
            const auto& info = reader.info();
            out << "file:           " << input << "\n";
            out << "pcap version:   " << info.version_major << "." << info.version_minor << "\n";
            out << "link type:      " << link_type_name(info.linktype) << "\n";
            out << "snaplen:        " << info.snaplen << " bytes\n";
            out << "timestamps:     " << (info.nanosecond_ts ? "nanosecond" : "microsecond")
                << " resolution\n";
        }
        stats_writer.print_summary(out);
        if (!follow_requests.empty()) follow_writer.print_summary(out);
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

// Exit codes specific to `policy validate` (see man/conduitscope.1's EXIT STATUS and
// docs/MANUAL.md): 0 = compliant (every observed flow was explicitly allowed by a conduit), 1 =
// fatal error (bad arguments, an unreadable/malformed policy or capture file, or a --strict parse
// failure -- same meaning as run_decode's exit 1), 3 = the capture is readable and the policy is
// valid, but PolicyReport::compliant() is false (at least one violation and/or unclassified flow
// was found). 3, not 2, specifically so a script can tell "ran fine, found problems" (3) apart from
// "couldn't even run" (1) without also colliding with 2, which every other exit-status-checking
// caller of this tool has so far only ever seen mean "no fatal error, but nothing to do" (the
// now-retired `policy validate` stub was the only user of 2; nothing currently returns it, but the
// value is left unclaimed rather than reused, in case a future documented-stub command needs it
// again).
constexpr int kExitPolicyNonCompliant = 3;

// patch257 security review finding 3 fix ("protocol state exhaustion remains a central threat"):
// a SHARED exit code for every subcommand whose own report carries an `observation_truncated`
// field other than `baseline check` (which keeps its own pre-existing kExitBaselineIncomplete,
// defined further below near run_baseline_check -- changing an already-shipped exit code's value
// would break any caller already scripting against it). Returned whenever that report's own
// engine hit at least one of its internal growth ceilings and therefore only PARTLY observed the
// capture -- same "never silently produce a clean result from a truncated observation" reasoning
// as kExitBaselineIncomplete's own comment, generalized across commands instead of duplicated per
// command. Used by `detect`, `inventory`, and `policy validate` (each report's own
// `observation_truncated` field is checked right before that subcommand's own ordinary exit
// codes, in each of their own run_* functions below -- see item 97, docs/DEVELOPMENT.md). A
// caller scripting against this exit code should treat 6 as "re-run with a higher
// --max-<subcommand>-* limit and try again," the same posture kExitBaselineIncomplete's own
// comment already establishes for `baseline check`.
constexpr int kExitObservationIncomplete = 6;

// patch257 security review finding 2 fix ("continuous capture: disk exhaustion and rotation-
// boundary behavior"): `capture` only, returned when the run stopped because the write side
// failed mid-capture -- RotatingPcapWriter::write_packet threw ParseError, e.g. the disk filled
// up, a permission changed, or the target directory disappeared out from under an unattended run
// -- rather than because the requested stop condition (Ctrl+C, --duration, --max-packets) was
// reached. Deliberately its own value, never 1: exit 1 already means "this run never produced any
// evidence at all" (bad arguments, the interface couldn't be opened, the initial directory didn't
// exist) elsewhere in this same subcommand, and a caller/monitoring script needs to tell that
// apart from "this run captured real evidence for a while and then lost coverage partway
// through" -- the same reasoning kExitBaselineIncomplete/kExitObservationIncomplete's own comments
// already establish for their respective subcommands. See run_capture's own inner try/catch below
// for exactly what gets reported alongside this exit code (how many packets/files were captured
// before the failure, and that every already-rotated file up to that point is still intact).
constexpr int kExitCaptureIncomplete = 7;

int run_policy_validate(const std::string& input, const std::string& interface_name,
                         const std::string& filter, int duration_seconds, int snaplen, bool promiscuous,
                         const std::string& policy_path, const std::string& output, const std::string& format,
                         bool strict, bool strict_it_protocols, bool summarize_unclassified, bool quiet,
                         const ResourceLimitCliVars& limit_vars, const PolicyEngineLimits& engine_limits,
                         bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                         bool service_names_enabled, const std::string& services_path, std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        Policy policy = parse_policy_file(policy_path);

        // Same Resolver, built the same "fail fast before opening the packet source" way, that
        // run_decode above already builds for `decode`'s writers -- see resolver.hpp's file header:
        // this OUI/hostname/service-name annotation now reaches `policy validate`'s report too, not
        // just `decode`'s per-packet output.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled,
                           services_path, resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        // A hostname zone (policy.hpp's ZoneKind::Hostname) can only ever be matched against a
        // pinned, operator-supplied hosts file -- never live DNS (see resolver.hpp's own file
        // header for why, and policy.hpp's own header comment for the reproducibility this buys a
        // compliance verdict). Fail fast, before opening the packet source, rather than silently
        // matching nothing against every hostname zone for the whole run.
        if (policy.has_hostname_zone() && !(resolve_hostnames && !hosts_path.empty())) {
            std::cerr << "error: " << policy_path
                      << " declares one or more hostname zones, but --resolve/--hosts were not both "
                         "given -- hostname-zone matching requires a pinned hosts file (see "
                         "docs/USER_GUIDE.md's POLICY FILE FORMAT section); it is never resolved via "
                         "live DNS\n";
            return 1;
        }

        DecodeOptions options;
        options.strict = strict;
        options.limits = build_resource_limits(limit_vars);
        // No --max-packets equivalent for policy validate (matching its existing offline-file
        // CLI surface, which never had one either): a live run here relies on --duration and/or
        // Ctrl+C to stop, same as `decode -i` does when --max-packets is left at its default of 0.
        PacketSource source =
            open_packet_source(input, interface_name, snaplen, promiscuous, filter, duration_seconds, 0);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);
        PolicyEngine engine(policy, engine_limits);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (!g_stop_requested.load(std::memory_order_acquire) && source.next(pkt)) {
            // See run_decode's own comment on source.index() -- same "preserve the file position,
            // don't renumber from 1" fix applies here.
            index = source.index();
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        // The report's "capture:" line identifies what was checked -- for a live run that's the
        // interface (input is empty in that case, having been mutually exclusive with -i), not a
        // file path.
        std::string capture_label = interface_name.empty() ? input : "live:" + interface_name;
        PolicyReport report = engine.finish(resolver);
        // See append_live_capture_drop_reason's own comment (above open_packet_source) -- a no-op
        // for an offline `-r` read.
        if (append_live_capture_drop_reason(source, report.truncation_reasons, report.observation_incomplete_reasons)) {
            report.observation_truncated = true;
        }
        if (format == "json") {
            write_policy_report_json(*out, report, policy, capture_label, policy_path, resolver);
        } else if (format == "cef") {
            write_policy_report_cef(*out, report);
        } else if (format == "leef") {
            write_policy_report_leef(*out, report);
        } else if (format == "syslog") {
            write_policy_report_syslog(*out, report);
        } else {
            write_policy_report_text(*out, report, policy, capture_label, policy_path, resolver, summarize_unclassified);
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        // report.compliant() is, and stays, completely independent of notable_protocols (see
        // PolicyReport::notable_protocols' own comment) -- --strict-it-protocols is the explicit,
        // opt-in way a non-empty notable_protocols list ALSO fails this exit code, applied here at
        // the CLI layer rather than inside compliant() itself, so a caller of PolicyReport directly
        // (or the JSON report's own "compliant" field) always sees the same protocol/port/conduit-
        // allow-list-only verdict this engine has always computed.
        // patch257 finding 3 fix: a truncated observation must never exit 0/kExitPolicyNonCompliant
        // as if it were an ordinary complete verdict -- takes priority over both, same reasoning as
        // kExitBaselineIncomplete's own comment (this file): a "COMPLIANT" result from a truncated
        // observation is not trustworthy.
        if (report.observation_truncated) return kExitObservationIncomplete;
        bool ok = report.compliant() && (!strict_it_protocols || report.notable_protocols.empty());
        return ok ? 0 : kExitPolicyNonCompliant;
    } catch (const PolicyError& e) {
        // e.what() is already "<policy_path>:<line>: <message>" (see policy.cpp's fail()) --
        // no need to prefix the path again here.
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// Passive OT asset inventory -- see asset_inventory.hpp's own file header and docs/MANUAL.md's
// ROADMAP item 17. Unlike run_decode/run_policy_validate above, there is no "compliance"/pass-fail
// concept here (nothing is being checked against anything), so this always returns 0 on success --
// see EXIT STATUS.
int run_inventory(const std::string& input, const std::string& interface_name, const std::string& filter,
                   int duration_seconds, int snaplen, bool promiscuous, const std::string& output,
                   const std::string& format, bool strict, bool quiet, uint8_t zone_prefix_len,
                   const std::string& diagram_path, const std::string& diagram_format,
                   const std::string& policy_out_path, const std::string& acl_out_path,
                   const std::string& acl_format, const std::string& edges_csv_path,
                   const std::string& conduits_csv_path, const ResourceLimitCliVars& limit_vars,
                   const AssetInventoryEngineLimits& engine_limits, bool oui_enabled, bool resolve_hostnames,
                   const std::string& hosts_path, bool service_names_enabled, const std::string& services_path,
                   std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        // Same Resolver, built the same fail-fast way run_decode/run_policy_validate already do.
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled, services_path,
                           resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        DecodeOptions options;
        options.strict = strict;
        options.limits = build_resource_limits(limit_vars);
        // Same "no --max-packets" posture as run_policy_validate -- see its own comment.
        PacketSource source =
            open_packet_source(input, interface_name, snaplen, promiscuous, filter, duration_seconds, 0);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);
        AssetInventoryEngine engine(zone_prefix_len, engine_limits);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (!g_stop_requested.load(std::memory_order_acquire) && source.next(pkt)) {
            // See run_decode's own comment on source.index() -- same "preserve the file position,
            // don't renumber from 1" fix applies here.
            index = source.index();
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        std::string capture_label = interface_name.empty() ? input : "live:" + interface_name;
        AssetInventoryReport report = engine.finish();
        // See append_live_capture_drop_reason's own comment (above open_packet_source) -- a no-op
        // for an offline `-r` read.
        if (append_live_capture_drop_reason(source, report.truncation_reasons, report.observation_incomplete_reasons)) {
            report.observation_truncated = true;
        }
        if (format == "json") {
            write_inventory_report_json(*out, report, capture_label, resolver);
        } else if (format == "csv") {
            // Phase 8 of Grok gap #2 -- see write_inventory_report_csv's own doc comment
            // (asset_inventory.hpp) for why this is deliberately asset-only, not the full
            // asset/communications/zones/conduits report text/json render.
            write_inventory_report_csv(*out, report, resolver);
        } else if (format == "stix") {
            // Phase 9 of Grok gap #2 -- see write_inventory_stix_json's own doc comment
            // (asset_inventory.hpp): a minimal, valid STIX 2.1 bundle, also deliberately
            // asset-only.
            write_inventory_stix_json(*out, report, capture_label, resolver);
        } else {
            write_inventory_report_text(*out, report, capture_label, resolver);
        }

        if (!diagram_path.empty()) {
            std::ofstream diagram_out(diagram_path, std::ios::binary);
            if (!diagram_out) {
                std::cerr << "error: cannot open diagram output file '" << diagram_path << "'\n";
                return 1;
            }
            if (diagram_format == "dot") write_inventory_diagram_dot(diagram_out, report);
            else write_inventory_diagram_mermaid(diagram_out, report);
        }
        if (!policy_out_path.empty()) {
            std::ofstream policy_out(policy_out_path, std::ios::binary);
            if (!policy_out) {
                std::cerr << "error: cannot open policy output file '" << policy_out_path << "'\n";
                return 1;
            }
            write_inventory_policy_yaml(policy_out, report);
            if (report.zones.empty() && !quiet) {
                diag << "note: no asset was observed, so '" << policy_out_path
                     << "' has no 'zones:'/'conduits:' keys and is not a loadable policy file as-is "
                        "-- see the file's own header comment\n";
            }
        }
        if (!acl_out_path.empty()) {
            std::ofstream acl_out(acl_out_path, std::ios::binary);
            if (!acl_out) {
                std::cerr << "error: cannot open ACL output file '" << acl_out_path << "'\n";
                return 1;
            }
            // Phase 10 of Grok gap #2 -- see write_inventory_acl_cisco's own doc comment
            // (asset_inventory.hpp): a FIRST-DRAFT ACL for human review, never something this
            // project claims is ready to deploy -- the generated file's own header says so too.
            if (acl_format == "fortinet") write_inventory_acl_fortinet(acl_out, report);
            else if (acl_format == "paloalto") write_inventory_acl_paloalto(acl_out, report);
            else write_inventory_acl_cisco(acl_out, report);
            if (report.zones.empty() && !quiet) {
                diag << "note: no asset was observed, so '" << acl_out_path
                     << "' has no address/service/rule objects and is not a loadable ACL file as-is "
                        "-- see the file's own header comment\n";
            }
        }
        // Follow-up to Phase 8 of Grok gap #2, added after initial delivery at Jurgen's request --
        // see write_inventory_edges_csv's own doc comment (asset_inventory.hpp) for why this is a
        // SEPARATE file from --format csv's own asset-only output, not a second --format value.
        if (!edges_csv_path.empty()) {
            std::ofstream edges_csv_out(edges_csv_path, std::ios::binary);
            if (!edges_csv_out) {
                std::cerr << "error: cannot open edges CSV output file '" << edges_csv_path << "'\n";
                return 1;
            }
            write_inventory_edges_csv(edges_csv_out, report, resolver);
        }
        // Follow-up to Phase 8, added alongside --edges-csv above at Jurgen's request -- see
        // write_inventory_conduits_csv's own doc comment (asset_inventory.hpp).
        if (!conduits_csv_path.empty()) {
            std::ofstream conduits_csv_out(conduits_csv_path, std::ios::binary);
            if (!conduits_csv_out) {
                std::cerr << "error: cannot open conduits CSV output file '" << conduits_csv_path << "'\n";
                return 1;
            }
            write_inventory_conduits_csv(conduits_csv_out, report, resolver);
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        // patch257 finding 3 fix: a truncated observation must never exit 0 -- see
        // kExitObservationIncomplete's own comment above for why this is a shared exit code, not a
        // new inventory-specific one.
        if (report.observation_truncated) return kExitObservationIncomplete;
        return 0;
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// `detect` -- Grok gap #4 ("Detection that OT IR teams recognize"). See detect_engine.hpp's own
// file header for the design and docs/design/detection-engine.md for the full record. Mirrors
// run_inventory's own shape (a single-pass observe/finish engine, text/json report) with two
// optional whole-of-run inputs read the same way run_baseline_check already reads them:
// `policy_path` (--policy, reusing parse_policy_file -- only for the RemoteAccessChannel
// T0886-vs-T0822 zone-crossing distinction, see DetectEngine::finish's own comment) and
// `baseline_path` (--baseline-file, reusing load_baseline_store -- for new-vs-known resolution).
// Both stay unconstructed (nullptr) when their flag is empty, the exact same "an absent optional
// flag never touches this code path at all" posture run_baseline_check's own policy_path already
// established.
int run_detect(const std::string& input, const std::string& interface_name, const std::string& filter,
                int duration_seconds, int snaplen, bool promiscuous, const std::string& output,
                const std::string& format, bool strict, bool quiet, const std::string& policy_path,
                const std::string& baseline_path, size_t max_baseline_file_bytes,
                const ResourceLimitCliVars& limit_vars, const DetectEngineLimits& engine_limits,
                bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                bool service_names_enabled, const std::string& services_path, std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        std::optional<Policy> policy;
        if (!policy_path.empty()) {
            policy = parse_policy_file(policy_path);
        }
        std::optional<BaselineStore> baseline;
        if (!baseline_path.empty()) {
            baseline = load_baseline_store(baseline_path, max_baseline_file_bytes);
        }

        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled, services_path,
                           resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        DecodeOptions options;
        options.strict = strict;
        options.limits = build_resource_limits(limit_vars);
        PacketSource source =
            open_packet_source(input, interface_name, snaplen, promiscuous, filter, duration_seconds, 0);
        SigintGuard sigint_guard(source.live_ptr());
        Decoder decoder(options);
        DetectEngine engine(engine_limits);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (!g_stop_requested.load(std::memory_order_acquire) && source.next(pkt)) {
            index = source.index();
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        std::string capture_label = interface_name.empty() ? input : "live:" + interface_name;
        DetectionReport report = engine.finish(policy ? &*policy : nullptr, baseline ? &*baseline : nullptr);
        // See append_live_capture_drop_reason's own comment (above open_packet_source) -- a no-op
        // for an offline `-r` read. This is the literal fix for patch257 section 4's "Detection
        // completeness" finding's own "packet loss... must be distinguishable from a clean
        // capture with no findings": a live `detect` run that silently dropped packets at the OS
        // level must never come back as a trustworthy "no findings".
        if (append_live_capture_drop_reason(source, report.truncation_reasons, report.observation_incomplete_reasons)) {
            report.observation_truncated = true;
        }
        if (format == "json") {
            write_detection_report_json(*out, report, capture_label, resolver);
        } else if (format == "cef") {
            write_detection_report_cef(*out, report);
        } else if (format == "leef") {
            write_detection_report_leef(*out, report);
        } else if (format == "syslog") {
            write_detection_report_syslog(*out, report);
        } else {
            write_detection_report_text(*out, report, capture_label, resolver);
        }

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        // patch257 finding 3 fix: a truncated observation must never exit 0 -- same reasoning as
        // kExitBaselineIncomplete's own comment below (this file), generalized as
        // kExitObservationIncomplete since `detect` has no separate "compliant/anomaly" ternary of
        // its own to take priority over (unlike `baseline check`) -- an incomplete observation is
        // the only condition this exit code needs to report here.
        if (report.observation_truncated) return kExitObservationIncomplete;
        return 0;
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const PolicyError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const BaselineStoreError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// Exit code specific to `baseline check` (see man/conduitscope.1's EXIT STATUS and
// docs/USER_GUIDE.md): 0 = clean (every operation this capture exercised was already covered by
// the baseline), 1 = fatal error (bad arguments, an unreadable/malformed baseline or capture file),
// 4 = the capture and baseline file were both valid, but BaselineCheckReport::compliant() is false
// (at least one finding). Not 3 (kExitPolicyNonCompliant, `policy validate`'s own "ran fine, found
// problems" code) -- a caller scripting against both subcommands' exit codes needs to be able to
// tell which one flagged something without also parsing output, so each gets its own value rather
// than reusing kExitPolicyNonCompliant's meaning across two unrelated commands.
constexpr int kExitBaselineAnomaly = 4;

// Item 64 fix (docs/reviews/2026-09-chatgpt-security-review-patch209.md, finding 1): a fifth,
// still-unclaimed exit code for `baseline check` specifically -- returned whenever
// BaselineCheckReport::observation_truncated is true, i.e. this run's own BaselineEngine hit at
// least one of its four internal growth ceilings and therefore only PARTLY observed the capture.
// Takes priority over both 0 and kExitBaselineAnomaly: a truncated observation can only ever
// produce false negatives (see observation_truncated's own comment, baseline.hpp), so a plain 0
// here would be exactly the "silently produce a clean compliance result from truncated
// observations" outcome the review explicitly calls out as unacceptable, and an ordinary
// kExitBaselineAnomaly wouldn't tell a caller that the findings it DID get are also incomplete.
// A caller scripting against this exit code should treat 5 as "re-run with a higher
// --max-baseline-* limit and try again" -- not as "clean" and not as an ordinary anomaly.
constexpr int kExitBaselineIncomplete = 5;

// `baseline learn` -- reads `baseline_file` if it already exists (merges; see
// load_baseline_store's own comment for why a missing file isn't an error here specifically),
// absorbs every packet's operations from every pcap in `inputs` in order, and always writes the
// result back to `baseline_file`. Never produces a pass/fail verdict -- see baseline.hpp's own file
// header comment for why `learn`/`check` are deliberately separate commands. Offline pcap/pcapng
// files only (no `-i` live-capture equivalent): a baseline is meant to be built from captures
// already reviewed and trusted to be clean (see the design doc's own baseline-poisoning caveat),
// which a live interface can't offer the same "already looked at this" assurance for.
int run_baseline_learn(const std::vector<std::string>& inputs, const std::string& baseline_file, bool strict,
                        bool quiet, const ResourceLimitCliVars& limit_vars, size_t max_baseline_file_bytes,
                        const BaselineEngineLimits& engine_limits, std::ostream& diag) {
    try {
        BaselineStore store = load_baseline_store(baseline_file, max_baseline_file_bytes);

        DecodeOptions options;
        options.strict = strict;
        options.limits = build_resource_limits(limit_vars);

        size_t total_conduits_touched = 0;
        for (const std::string& input : inputs) {
            PcapReader reader(input);
            Decoder decoder(options);
            BaselineEngine engine(engine_limits);

            PcapPacket pkt;
            size_t index = 0, warnings = 0;
            while (reader.next(pkt)) {
                ++index;
                DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
                if (dp.protocol == "parse-error") {
                    ++warnings;
                    if (!quiet) diag << "warning: " << input << ": packet " << index << ": " << dp.summary << "\n";
                }
                engine.observe(dp);
            }
            std::vector<ConduitBaseline> observed = engine.finish();
            total_conduits_touched += observed.size();
            merge_baseline_observations(store, observed, input);

            if (warnings > 0 && !quiet) {
                diag << warnings
                     << " packet(s) in '" << input
                     << "' had parse warnings (shown above); rerun with --strict to stop at the "
                        "first one, or -q to silence this message\n";
            }
            // Item 64 fix: `learn` still absorbs whatever this engine DID manage to observe (same
            // best-effort posture as the parse-warnings handling right above -- a merge from a
            // partial observation is still strictly better than none), but must say so plainly
            // rather than silently baking an incomplete observation into the baseline file. Always
            // printed, even under -q/--quiet -- unlike an ordinary parse warning, this affects the
            // CORRECTNESS of the baseline file being written, not just diagnostic noise.
            // F4 fix (patch282 security review): fold in any flow-state evictions from this
            // file's own decode pass too -- see append_flow_state_eviction_reason's own comment
            // (resource_limits.hpp). `learn` has no Report struct to attach this to the way
            // `check`/`detect`/`policy validate`/`inventory` do (see their own identical
            // comments), so it's collected into its own local vector and printed alongside
            // engine.truncation_reasons() in the SAME warning block below instead. `learn` prints
            // plain text only (no JSON/CEF output of its own), so the categorized
            // ObservationIncompleteReason list has nothing to be surfaced in -- collected into its
            // own throwaway local the same way, never read back, since append_flow_state_eviction_
            // reason now always requires both vectors.
            std::vector<std::string> flow_state_eviction_reasons;
            std::vector<ObservationIncompleteReason> flow_state_eviction_categories;
            bool flow_state_evicted =
                append_flow_state_eviction_reason(flow_state_eviction_reasons, flow_state_eviction_categories);
            if (engine.truncated() || flow_state_evicted) {
                diag << "warning: baseline observation of '" << input
                     << "' is INCOMPLETE -- the merged baseline may be missing some of this "
                        "capture's own conduits/operations/ranges:\n";
                for (const std::string& reason : engine.truncation_reasons()) {
                    diag << "  - " << reason << "\n";
                }
                for (const std::string& reason : flow_state_eviction_reasons) {
                    diag << "  - " << reason << "\n";
                }
            }
        }

        save_baseline_store(baseline_file, store);

        if (!quiet) {
            diag << "learned from " << inputs.size() << " capture(s), touching " << total_conduits_touched
                 << " conduit observation(s); baseline file '" << baseline_file << "' now has "
                 << store.conduits.size() << " conduit(s)\n";
        }
        return 0;
    } catch (const BaselineStoreError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// `baseline check` -- reads `baseline_file` (must already exist -- enforced by CLI11's
// ->check(CLI::ExistingFile) on the option, see main() below) and compares `input`'s own observed
// operations against it, never writing the file back. See kExitBaselineAnomaly's own comment for
// the exit-code contract.
//
// `policy_path` (`--policy`, optional): the zone-awareness follow-up (docs/design/baseline-engine.md's
// own "Follow-up" section) that resolves the design doc's originally-deferred "does a new IP in an
// already-trusted zone count as NewConduit or not" question. Empty (the default) reproduces the
// exact pre-existing behavior, byte for byte -- `check_baseline` itself defaults its own `policy`
// parameter to nullptr, and this function only ever parses/passes a Policy when `policy_path` is
// non-empty, so a caller who never passes `--policy` never touches this code path at all. Reuses
// `policy validate`'s own `parse_policy_file`/`Policy`/`PolicyError` machinery exactly -- no new
// file format, no second policy parser. `baseline learn` is entirely untouched by this: zones are
// resolved fresh at `check` time only, never persisted into the baseline file, so a baseline
// learned before a policy existed (or before it changed) needs no re-`learn`.
int run_baseline_check(const std::string& input, const std::string& baseline_file, const std::string& output,
                        const std::string& format, bool strict, bool symbolic_addresses,
                        const std::string& policy_path, bool quiet, const ResourceLimitCliVars& limit_vars,
                        size_t max_baseline_file_bytes, const BaselineEngineLimits& engine_limits,
                        std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        BaselineStore store = load_baseline_store(baseline_file, max_baseline_file_bytes);

        // Only parsed when given -- see this function's own doc comment above for why an absent
        // --policy must never even construct a Policy, let alone reach check_baseline with one.
        std::optional<Policy> policy;
        if (!policy_path.empty()) {
            policy = parse_policy_file(policy_path);
        }

        DecodeOptions options;
        options.strict = strict;
        options.limits = build_resource_limits(limit_vars);
        PcapReader reader(input);
        Decoder decoder(options);
        BaselineEngine engine(engine_limits);

        PcapPacket pkt;
        size_t index = 0, warnings = 0;
        while (reader.next(pkt)) {
            ++index;
            DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            engine.observe(dp);
        }

        BaselineCheckReport report = check_baseline(store, engine.finish(), input, policy ? &*policy : nullptr);
        // Item 64 fix: attached from the SAME engine that produced `report`'s own `observed` input,
        // never recomputed -- see BaselineCheckReport::observation_truncated's own comment
        // (baseline.hpp) and kExitBaselineIncomplete's own comment below for what this changes.
        report.observation_truncated = engine.truncated();
        report.truncation_reasons = engine.truncation_reasons();
        report.observation_incomplete_reasons = engine.truncation_categories();
        // F4 fix (patch282 security review): fold in any flow-state evictions from this run -- see
        // DetectEngine::finish()'s own identical comment (detect_engine.cpp) and
        // append_flow_state_eviction_reason's own comment (resource_limits.hpp). `baseline check`
        // builds its own report here rather than inside BaselineEngine itself (unlike Detect/
        // Policy/AssetInventory), so this fold-in lives here instead of baseline.cpp.
        if (append_flow_state_eviction_reason(report.truncation_reasons, report.observation_incomplete_reasons))
            report.observation_truncated = true;
        if (format == "json") {
            write_baseline_check_report_json(*out, report, symbolic_addresses);
        } else if (format == "cef") {
            write_baseline_check_report_cef(*out, report);
        } else if (format == "leef") {
            write_baseline_check_report_leef(*out, report);
        } else if (format == "syslog") {
            write_baseline_check_report_syslog(*out, report);
        } else {
            write_baseline_check_report_text(*out, report, symbolic_addresses);
        }

        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
        // Item 64 fix: observation_truncated takes priority over compliant()'s own ternary --
        // see kExitBaselineIncomplete's own comment for why a truncated observation must never
        // exit 0, even when report.compliant() (no findings) would otherwise say CLEAN.
        if (report.observation_truncated) return kExitBaselineIncomplete;
        return report.compliant() ? 0 : kExitBaselineAnomaly;
    } catch (const BaselineStoreError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const PolicyError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// `evidence` -- Jurgen's direct request for an audit-binder-ready "evidence pack" produced from
// one command (see evidence_report.hpp's own file header for the full design record, including the
// deliberate "assemble existing proven report writers, don't reimplement any of them" decision this
// function follows). Offline captures ONLY -- no -i/--interface, unlike every other subcommand that
// reads a packet source: this report hashes the capture file and may run more than one independent
// decode pass over it (inventory always, policy/detect/baseline each needing their own pass over
// the SAME bytes), both of which need a static, already-complete file, not a live, one-shot stream.
//
// Up to four independent passes, one per engine -- deliberately NOT a single pass feeding all four
// engines at once. Every other subcommand in this codebase already does its own single-engine,
// single-pass decode loop; reusing that exact proven shape four times here (rather than inventing
// the first-ever multi-engine combined pass) is the lower-risk choice for a report that stitches
// four already-independently-tested engines together, at the cost of decoding the same file up to
// four times. Inventory's own pass is the one that gathers capture-wide timing (first/last
// timestamp, the largest inter-packet gap, total packet/parse-error counts) -- decoding is
// deterministic over the same bytes, so every other pass would produce identical counts; there is
// no need to re-gather them.
int run_evidence(const std::string& input, const std::string& policy_path,
                  const std::string& baseline_path, const std::string& sl_target,
                  bool cip_monitoring_window, const std::string& sign_key_path,
                  const std::string& output, const std::string& format, bool strict, bool quiet,
                  uint8_t zone_prefix_len, bool oui_enabled, bool resolve_hostnames,
                  const std::string& hosts_path, bool service_names_enabled,
                  const std::string& services_path, std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        // Fail fast, before any decode pass runs, on every file this command needs to read whole --
        // same "validate every input up front" posture run_policy_validate's hostname-zone check
        // already established.
        std::ifstream capture_in(input, std::ios::binary);
        if (!capture_in) {
            std::cerr << "error: cannot open '" << input << "' for reading\n";
            return 1;
        }
        std::vector<uint8_t> capture_bytes((std::istreambuf_iterator<char>(capture_in)),
                                            std::istreambuf_iterator<char>());
        capture_in.close();

        std::string policy_sha256_hex;
        std::optional<Policy> policy;
        if (!policy_path.empty()) {
            std::ifstream policy_in(policy_path, std::ios::binary);
            if (!policy_in) {
                std::cerr << "error: cannot open '" << policy_path << "' for reading\n";
                return 1;
            }
            std::vector<uint8_t> policy_bytes((std::istreambuf_iterator<char>(policy_in)),
                                               std::istreambuf_iterator<char>());
            policy_sha256_hex = sha256_hex(policy_bytes);
            policy = parse_policy_file(policy_path);
        }

        std::vector<uint8_t> sign_key;
        if (!sign_key_path.empty()) {
            std::ifstream key_in(sign_key_path, std::ios::binary);
            if (!key_in) {
                std::cerr << "error: cannot open --sign-key file '" << sign_key_path << "' for reading\n";
                return 1;
            }
            sign_key.assign((std::istreambuf_iterator<char>(key_in)), std::istreambuf_iterator<char>());
        }

        std::optional<BaselineStore> baseline_store;
        if (!baseline_path.empty()) {
            baseline_store = load_baseline_store(baseline_path);
        }

        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled,
                           services_path, resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        DecodeOptions options;
        options.strict = strict;
        // Deliberately the compiled-in default resource limits for every engine below, not exposed
        // as CLI overrides here -- see evidence_report.hpp's own header comment: keeping this
        // command's own CLI surface small, on top of four already-large per-engine surfaces, is a
        // deliberate v1 scoping choice, not an oversight. A capture large enough to need a raised
        // limit here can still be analyzed with the individual subcommands' own --max-* flags.

        // --- Pass 1: asset inventory -- always runs; gathers capture-wide timing too -------------
        size_t total_packets = 0, parse_error_packets = 0;
        double first_ts = 0.0, last_ts = 0.0, max_gap = 0.0, max_gap_at = 0.0;
        AssetInventoryReport inventory_report;
        {
            PcapReader reader(input);
            Decoder decoder(options);
            AssetInventoryEngine engine(zone_prefix_len);
            PcapPacket pkt;
            size_t index = 0;
            bool have_prev = false;
            double prev_ts = 0.0;
            while (reader.next(pkt)) {
                ++index;
                DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
                if (dp.protocol == "parse-error") {
                    ++parse_error_packets;
                    if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
                }
                engine.observe(dp);
                if (index == 1) first_ts = dp.timestamp;
                last_ts = dp.timestamp;
                if (have_prev) {
                    double gap = dp.timestamp - prev_ts;
                    if (gap > max_gap) {
                        max_gap = gap;
                        max_gap_at = dp.timestamp;
                    }
                }
                prev_ts = dp.timestamp;
                have_prev = true;
            }
            total_packets = index;
            inventory_report = engine.finish();
        }

        // --- Pass 2: policy validate -- only when --policy was given ----------------------------
        std::optional<PolicyReport> policy_report;
        if (policy) {
            PcapReader reader(input);
            Decoder decoder(options);
            PolicyEngine engine(*policy);
            PcapPacket pkt;
            size_t index = 0;
            while (reader.next(pkt)) {
                ++index;
                DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
                engine.observe(dp);
            }
            policy_report = engine.finish(resolver);
        }

        // --- Pass 3: detect -- always runs ---------------------------------------------------------
        DetectionReport detection_report;
        {
            PcapReader reader(input);
            Decoder decoder(options);
            DetectEngine engine;
            PcapPacket pkt;
            size_t index = 0;
            while (reader.next(pkt)) {
                ++index;
                DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
                engine.observe(dp);
            }
            detection_report =
                engine.finish(policy ? &*policy : nullptr, baseline_store ? &*baseline_store : nullptr);
        }

        // --- Pass 4: baseline check -- only when --baseline-file was given --------------------------
        std::optional<BaselineCheckReport> baseline_report;
        if (baseline_store) {
            PcapReader reader(input);
            Decoder decoder(options);
            BaselineEngine engine;
            PcapPacket pkt;
            size_t index = 0;
            while (reader.next(pkt)) {
                ++index;
                DecodedPacket dp = decoder.decode(pkt, reader.info().linktype, index);
                engine.observe(dp);
            }
            baseline_report =
                check_baseline(*baseline_store, engine.finish(), input, policy ? &*policy : nullptr);
            baseline_report->observation_truncated = engine.truncated();
            baseline_report->truncation_reasons = engine.truncation_reasons();
            baseline_report->observation_incomplete_reasons = engine.truncation_categories();
        }

        std::string inventory_diagram;
        {
            std::ostringstream diagram_out;
            write_inventory_diagram_mermaid(diagram_out, inventory_report);
            inventory_diagram = diagram_out.str();
        }

        EvidenceReportInputs in;
        in.tool_version = "conduitscope " + version_string();
        double now = static_cast<double>(std::time(nullptr));
        in.generated_at_utc = format_timestamp(now, TimeFormat::AbsoluteDate, TimeOffset{}, now, now);
        in.capture_path = input;
        in.capture_sha256_hex = sha256_hex(capture_bytes);
        in.policy_path = policy_path;
        in.policy_sha256_hex = policy_sha256_hex;
        in.sl_target = sl_target;
        in.cip_monitoring_window = cip_monitoring_window;
        in.capture_first_ts = first_ts;
        in.capture_last_ts = last_ts;
        in.total_packets = total_packets;
        in.parse_error_packets = parse_error_packets;
        in.max_inter_packet_gap_seconds = max_gap;
        in.max_inter_packet_gap_at_ts = max_gap_at;
        in.inventory = &inventory_report;
        in.inventory_diagram_mermaid = inventory_diagram;
        in.policy = policy ? &*policy : nullptr;
        in.policy_report = policy_report ? &*policy_report : nullptr;
        in.detection = &detection_report;
        in.baseline = baseline_report ? &*baseline_report : nullptr;
        in.resolver = &resolver;

        if (format == "json") {
            write_evidence_report_json(*out, in, sign_key);
        } else {
            write_evidence_report_text(*out, in, sign_key);
        }

        if (parse_error_packets > 0 && !quiet) {
            diag << parse_error_packets
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }

        bool any_truncated = inventory_report.observation_truncated ||
                              (policy_report && policy_report->observation_truncated) ||
                              detection_report.observation_truncated ||
                              (baseline_report && baseline_report->observation_truncated);
        if (any_truncated) return kExitObservationIncomplete;
        if (policy_report && !policy_report->compliant()) return kExitPolicyNonCompliant;
        if (baseline_report && !baseline_report->compliant()) return kExitBaselineAnomaly;
        return 0;
    } catch (const PolicyError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const BaselineStoreError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ProtocolResultTypeMismatch& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

int run_interfaces(std::ostream& out) {
    try {
        std::vector<InterfaceInfo> interfaces = list_interfaces();
        if (interfaces.empty()) {
            out << "(no interfaces found -- this can mean there genuinely are none, or that "
                   "listing them needs more privilege than this process has; try running as "
                   "root/Administrator)\n";
            return 0;
        }
        for (const auto& iface : interfaces) {
            out << iface.name;
            if (iface.loopback) out << "  [loopback]";
            if (!iface.description.empty()) out << "  -- " << iface.description;
            out << "\n";
        }
        return 0;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// Filesystem-safe filename component -- replaces every character other than ASCII letters/digits/
// '-'/'_'/'.' with '_'. Used to turn -i/--interface (or a user-supplied --prefix) into something
// safe to use as a filename prefix: on Linux this is usually already safe ("eth0"), but Npcap
// interface names on Windows are GUID-style device paths (e.g. "\Device\NPF_{4E2E1911-...}")
// containing '\', '{', '}', all of which are either a path separator or simply unwise to put in a
// filename unescaped. See rotating_pcap_writer.hpp's own constructor comment on `prefix`.
std::string sanitize_filename_component(const std::string& raw) {
    std::string out;
    out.reserve(raw.size());
    for (char c : raw) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' ||
            c == '_' || c == '.') {
            out.push_back(c);
        } else {
            out.push_back('_');
        }
    }
    return out.empty() ? std::string("capture") : out;
}

// `capture`: continuous, safe sensor mode -- writes rotated, retention-bounded classic-pcap files
// to disk from a live interface only, with NO decode/analysis running inside it (Grok review item
// 5, docs/reviews/2026-09-grok-ics-ot-improvement-areas.md; full design record at
// docs/design/sensor-mode.md's "capture-only rotator" scoping decision). Structurally similar to
// run_decode's own live-capture-plus-write path, minus everything decode-specific (Decoder,
// Resolver, every OutputWriter, direction tracking, --range, --filter applied twice for -r/-i --
// none of that applies to a source that is always live and is never decoded here at all).
int run_capture(const std::string& interface_name, const std::string& filter, int duration_seconds,
                 int snaplen, bool promiscuous, size_t max_packets, const std::string& directory,
                 const std::string& prefix, size_t rotate_bytes, size_t rotate_seconds,
                 size_t max_total_bytes, size_t max_files, bool quiet, std::ostream& diag) {
    try {
        LiveCapture capture(interface_name, snaplen, promiscuous, filter, duration_seconds, max_packets);
        // Same Ctrl+C posture as run_decode/run_policy_validate/run_inventory above -- `false` for
        // `color` since `capture` has no colorized text output of its own to restore (it prints at
        // most a plain end-of-run summary line, never per-packet text).
        SigintGuard sigint_guard(&capture);

        RotationPolicy policy;
        policy.rotate_bytes = rotate_bytes;
        policy.rotate_seconds = rotate_seconds;
        policy.max_total_bytes = max_total_bytes;
        policy.max_files = max_files;

        std::string effective_prefix =
            sanitize_filename_component(prefix.empty() ? interface_name : prefix);
        RotatingPcapWriter writer(
            directory, effective_prefix, capture.info().linktype, static_cast<uint32_t>(snaplen),
            policy, [&](const std::string& warning) {
                if (!quiet) diag << "warning: " << warning << "\n";
            });

        if (!quiet) {
            diag << "capturing on '" << interface_name << "' into '" << directory << "/"
                 << effective_prefix << "_*.pcap' -- Ctrl+C to stop\n";
        }

        PcapPacket pkt;
        size_t captured_count = 0;
        // See append_live_capture_drop_reason's own comment (above open_packet_source) for the
        // general "why" -- `capture` has no Report/truncation_reasons to fold this into (it's the
        // write-side sensor, not a report-producing subcommand), but it's the one place patch257's
        // own "report capture loss... prominently rather than silently continuing as if the
        // evidence stream were complete" wording (finding 2, the sibling of section 4's "Detection
        // completeness") applies MOST directly: this is the actual "continuously running sensor"
        // deployment surface the whole review is written against. Printed unconditionally,
        // ignoring --quiet, from both the normal-completion path and the CAPTURE INCOMPLETE path
        // below -- a drop can occur either way, and this is data-loss evidence, not progress
        // chatter.
        auto print_drop_stats_if_any = [&]() {
            std::optional<std::string> drop_reason = format_live_capture_drop_reason(capture.stats());
            if (drop_reason) std::cerr << "warning: " << *drop_reason << "\n";
        };
        // patch257 security review finding 2 fix: this inner try/catch is deliberately separate
        // from the outer one below. A ParseError here means the write side failed AFTER capture
        // was already under way (RotatingPcapWriter::write_packet -- disk full, a permission
        // change, the target directory disappearing out from under an unattended run) and real
        // evidence up to this point exists on disk; a ParseError/CaptureError from the OUTER catch
        // means this run never got that far at all (bad arguments, the interface couldn't be
        // opened, the initial --directory didn't exist). Those are different failure shapes a
        // caller/monitoring script needs to tell apart -- see kExitCaptureIncomplete's own comment
        // above -- so they get different exit codes and different, purpose-specific messages
        // rather than sharing the same generic "error: <what>" this file uses for a setup failure.
        try {
            while (!g_stop_requested.load(std::memory_order_acquire) && capture.next(pkt)) {
                writer.write_packet(pkt);
                ++captured_count;
                if (max_packets != 0 && captured_count >= max_packets) break;
            }
        } catch (const ParseError& e) {
            std::cerr << "*** CAPTURE INCOMPLETE -- " << e.what() << " -- stopped after "
                       << captured_count << " packet(s) across " << (writer.rotation_count() + 1)
                       << " file(s) in '" << directory << "'. Every already-rotated file up to this "
                       << "point is intact; '" << writer.current_path() << "' (the file being "
                       << "written when this happened) may be truncated for its final record, and "
                       << "no traffic past this point was captured. This is NOT the requested stop "
                       << "condition (Ctrl+C/--duration/--max-packets) -- treat this run's coverage "
                       << "as incomplete and investigate the underlying storage problem before "
                       << "relying on it. ***\n";
            print_drop_stats_if_any();
            return kExitCaptureIncomplete;
        }
        print_drop_stats_if_any();

        if (!quiet) {
            diag << captured_count << " packet(s) captured across " << (writer.rotation_count() + 1)
                 << " file(s); most recent: '" << writer.current_path() << "' (" << writer.current_bytes()
                 << " bytes)\n";
        }
        return 0;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// `merge inventory`: the "multiple-simultaneous-tap-point stitching into one site-wide matrix"
// half of Grok review item 5 -- combines N `inventory --format json` reports (one per tap point,
// each produced by its own independent `capture`-then-`inventory` pass, per Jurgen's own
// "independent per-tap processes + merge subcommand" scoping decision) into one merged
// AssetInventoryReport, then renders it through the exact same writers `inventory` itself uses
// (write_inventory_report_text/_json/_csv) -- see inventory_merge.hpp's own file header for the
// merge semantics and its deliberately-scoped-out fields.
int run_merge_inventory(const std::vector<std::string>& inputs, const std::string& output,
                         const std::string& format, uint8_t zone_prefix_len, bool quiet, bool oui_enabled,
                         bool resolve_hostnames, const std::string& hosts_path, bool service_names_enabled,
                         const std::string& services_path, size_t max_inventory_file_bytes,
                         std::ostream& diag) {
    std::ofstream file_out;
    std::ostream* out = &std::cout;
    if (!output.empty()) {
        file_out.open(output, std::ios::binary);
        if (!file_out) {
            std::cerr << "error: cannot open output file '" << output << "'\n";
            return 1;
        }
        out = &file_out;
    }

    try {
        std::vector<std::string> resolver_notes;
        Resolver resolver(oui_enabled, resolve_hostnames, hosts_path, service_names_enabled, services_path,
                           resolver_notes);
        if (!quiet) {
            for (const auto& note : resolver_notes) diag << "note: " << note << "\n";
        }

        std::vector<AssetInventoryReport> reports;
        reports.reserve(inputs.size());
        for (const auto& path : inputs) {
            reports.push_back(read_inventory_report_file_for_merge(path, max_inventory_file_bytes));
        }

        AssetInventoryReport merged = merge_inventory_reports(reports, zone_prefix_len);

        std::ostringstream label;
        label << "merged: " << inputs.size() << " report(s) (";
        for (size_t i = 0; i < inputs.size(); ++i) {
            if (i) label << ", ";
            label << inputs[i];
        }
        label << ")";

        if (format == "json") {
            write_inventory_report_json(*out, merged, label.str(), resolver);
        } else if (format == "csv") {
            write_inventory_report_csv(*out, merged, resolver);
        } else {
            write_inventory_report_text(*out, merged, label.str(), resolver);
        }
        return 0;
    } catch (const InventoryMergeError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
}

// Lets every top-level subcommand also be selected via a double-dashed flag of the same name
// (--decode, --info, --interfaces, --policy, --inventory, --detect, --baseline, --capture,
// --merge), usable like any other flag rather than only as a same-position substitute for the
// bare subcommand word -- so `conduitscope -r file.pcap --decode` and `conduitscope --decode -r
// file.pcap` both work, not just the latter, and editing a previous command line (e.g. swapping
// `decode` for `info`) never requires hunting for where the subcommand word is or moving anything
// else around: drop `--x` in wherever's convenient. CLI11 subcommands are positional tokens with
// no native "a flag becomes a subcommand, from anywhere on the line" mechanism, so this is a small
// argv-preprocessing pass, run once from main() right before CLI11_PARSE -- NOT a real CLI11
// option.
//
// Scans left to right past any leading global flags (-q/--quiet, --no-color/--color, --version,
// -h/--help, --log-file FILE -- kept in sync with the globals registered in main() just below),
// which may only ever lead the line, exactly as they do today. The first token after that leading
// run is the "candidate" position -- normally where a bare subcommand word belongs. If a bare
// subcommand word (`decode`, `info`, ...) turns up anywhere from there on, the line is already
// using the classic form and nothing is touched. Otherwise, the scan keeps going token by token --
// an ordinary option/value token (`-r`, a filename, ...) is passed over unchanged -- until it
// either runs out or finds one of the nine alias flags above. Once found, that token's own text is
// rewritten in place to its bare-word target, and then rotated up to the candidate position (a
// sequence of adjacent swaps, preserving the relative order of every token that was in between) --
// CLI11 needs the subcommand word leading its own arguments, so simply overwriting the token's
// text without relocating it would otherwise stew that leading argument (or the leading run of
// them) as an ordinary token, alone in the leading prefix (rejected). Every alias spelling is
// textually longer than its target (the "--" prefix on an otherwise-identical word), so
// overwriting the found token's own buffer in place is always safe -- no reallocation, no overrun.
// Uses memcpy (copying the target's own length, including its trailing NUL) rather than strcpy:
// functionally identical here since the copy always shrinks the string, but strcpy trips MSVC's
// C4996 "unsafe function" deprecation warning (it can't see that this particular call is bounded)
// -- memcpy isn't on that deprecated-function list, and passing the exact byte count makes the
// safety argument explicit at the call site instead of just in this comment.
//
// `--policy` is the one alias that collides with a real, differently-scoped option of the same
// spelling (`--policy FILE`, accepted by `policy validate`/`detect`/`baseline check` once already
// inside one of those three subcommands) -- so unlike the other eight, `--policy` is only ever
// resolved as the alias when it sits exactly at the candidate position (matching every prior
// release's behavior); found later in the scan, it's left untouched and scanning continues,
// leaving `policy validate --policy zones.yaml`, `detect --policy zones.yaml`, and `baseline check
// --policy zones.yaml` all working unchanged whether the subcommand itself was written as `policy`
// or `--policy`. This costs `--policy` alone the same order-independence the other eight aliases
// gain; there's no way around that without risking a real, silent misparse, given `--policy` in
// isolation cannot otherwise be told apart from its unrelated same-spelled option.
//
// `--version` is deliberately not in this table: app.set_version_flag("--version", ...) (main(),
// below) already prints the identical text the `version` subcommand's own fallthrough prints --
// confirmed by comparing both call sites -- so `--version` already IS "a double-dashed flag that
// does what the `version` subcommand does," just via CLI11's own built-in mechanism (immediate
// exit, no require_subcommand(1) involved). Nothing to rewrite there.
//
// Return value (ROADMAP item 109, added alongside inject_default_subcommand just below): -1 when
// argv already names a subcommand by the time this returns -- either a bare word that was already
// there, or a --decode/--info/... alias flag this same call just resolved and rotated into place
// -- meaning the caller has nothing more to do. Otherwise, the scan reached the end of argv
// without ever finding one, and the return value is the candidate_start position a subcommand
// word belongs at (argc itself if the entire line was nothing but the leading run of global
// flags, or a bare invocation with no arguments at all) -- the caller passes this straight to
// inject_default_subcommand.
int rewrite_subcommand_alias(int argc, char** argv) {
    static const std::map<std::string, std::string> kAliases = {
        {"--decode", "decode"},     {"--info", "info"},         {"--interfaces", "interfaces"},
        {"--policy", "policy"},     {"--inventory", "inventory"}, {"--detect", "detect"},
        {"--baseline", "baseline"}, {"--capture", "capture"},   {"--merge", "merge"},
    };
    static const std::set<std::string> kBareSubcommands = {
        "decode", "info", "interfaces", "policy",  "inventory",
        "detect",  "baseline", "capture", "merge", "version", "evidence",
    };

    int candidate_start = -1;  // index a resolved alias is rotated up to; -1 while still skipping
                                // the leading run of global flags.
    for (int i = 1; i < argc; ++i) {
        const std::string token = argv[i];
        if (candidate_start == -1) {
            if (token == "-q" || token == "--quiet" || token == "--no-color" ||
                token == "--color" || token == "--version" || token == "-h" ||
                token == "--help") {
                continue;
            }
            if (token == "--log-file") {
                ++i;  // also skip its value token, if one was given (a missing value is a CLI11
                      // usage error either way, reported exactly as it is today)
                continue;
            }
            candidate_start = i;
        }
        if (kBareSubcommands.count(token) != 0) {
            return -1;  // already the classic form from here on -- nothing to rewrite.
        }
        auto it = kAliases.find(token);
        if (it == kAliases.end()) {
            continue;  // an ordinary option/value token -- keep scanning for an alias later on
                       // the line; unlike a bare subcommand word, this doesn't resolve anything
                       // by itself.
        }
        if (token == "--policy" && i != candidate_start) {
            continue;  // ambiguous anywhere but the candidate position -- see the collision note
                       // above; leave it for CLI11 to parse as-is and keep scanning.
        }
        std::memcpy(argv[i], it->second.c_str(), it->second.size() + 1);
        for (int j = i; j > candidate_start; --j) {
            std::swap(argv[j], argv[j - 1]);
        }
        return -1;
    }
    return candidate_start == -1 ? argc : candidate_start;
}

// ROADMAP item 109 -- Jurgen's own direct request: "-z option can be done independent from the
// --info subcommand", and "(unless -z option is used) when no subcommand have been given the
// decode is the default subcommand used." Called from main() only when rewrite_subcommand_alias
// (run immediately before this, same call site) returned non-negative -- i.e. argv has no
// subcommand word or alias flag anywhere on it at all, classic or otherwise.
//
// tshark itself needs no subcommand to just read a capture and print it, or to run a `-z` stats
// table -- conduitscope's own subcommand structure has no equivalent "just read it" default, so
// today both require explicitly typing `decode`/`info` first. This closes that gap: no
// subcommand at all now defaults to `decode` (tshark's own "just read and print" convention),
// UNLESS a `-z`/`--stat` token appears anywhere on the line -- `-z` is otherwise only ever
// meaningful under `info` (it isn't a decode option), so its mere presence is itself now enough
// to select `info` instead, with no subcommand word required -- exactly what makes `-z`
// "independent from the --info subcommand" in the first place, rather than teaching `decode` a
// second, parallel stats-output mode of its own.
//
// Unlike rewrite_subcommand_alias (which only ever overwrites+rotates an EXISTING token into
// place, since every alias spelling it resolves is already present somewhere on the line), there
// is no existing token to relabel here -- the default subcommand word is genuinely new, so this
// builds a brand new argv rather than mutating the original in place: `storage` owns the one new
// string ("decode" or "info"), and `new_argv` is the full replacement pointer array (every other
// entry just aliases the original argv's own storage, which is fine -- CLI11 only reads through
// these pointers once, during the CLI11_PARSE call immediately after, never past it). Both must
// stay alive across that call, so the caller declares them in main()'s own scope, not this
// function's.
void inject_default_subcommand(int argc, char** argv, int candidate_start,
                                std::vector<std::string>& storage, std::vector<char*>& new_argv) {
    bool has_stat_flag = false;
    for (int i = candidate_start; i < argc; ++i) {
        if (std::string(argv[i]) == "-z" || std::string(argv[i]) == "--stat") {
            has_stat_flag = true;
            break;
        }
    }

    storage.emplace_back(has_stat_flag ? "info" : "decode");
    new_argv.reserve(static_cast<size_t>(argc) + 1);
    for (int i = 0; i < candidate_start; ++i) new_argv.push_back(argv[i]);
    new_argv.push_back(storage.back().data());  // C++17: std::string::data() is mutable here, but
                                                 // CLI11 only ever reads through this pointer.
    for (int i = candidate_start; i < argc; ++i) new_argv.push_back(argv[i]);
}

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"conduitscope decodes Modbus/TCP, DNP3, and S7comm/COTP traffic from offline pcap/"
                  "pcapng captures, as a building block for OT/ICS conduit and zone auditing (IEC 62443 / "
                  "NIS2 workflows).",
                  "conduitscope"};
    // "conduitscope " + version_string(), not version_string() alone -- matches the `version`
    // subcommand's own fallthrough exactly (see its "conduitscope " << version_string() print,
    // below), so --version and `version` are truly interchangeable, not just close.
    app.set_version_flag("--version", "conduitscope " + version_string());
    app.require_subcommand(1);
    app.footer(
        "Run 'conduitscope <command> --help' for command-specific options, or see docs/MANUAL.md\n"
        "in the source tree for the full reference including output-format examples and the\n"
        "current Roadmap.\n\n"
        "COMMAND may be omitted: it then defaults to 'decode', or to 'info' if -z/--stat appears\n"
        "anywhere on the line (ROADMAP item 109) -- e.g. 'conduitscope -r FILE' is 'decode -r FILE',\n"
        "and 'conduitscope -r FILE -z conv,tcp' is 'info -r FILE -z conv,tcp'.");
    // Friendlier --help (Jurgen's direct request): word-wrap long option descriptions to the
    // real terminal width and sort options into named sections instead of one flat list -- see
    // WrappingHelpFormatter's own comment, above stdout_is_terminal(), for the full rationale.
    // Set BEFORE any add_subcommand() call below: CLI11's own App constructor copies its
    // parent's formatter_ at subcommand-creation time (see CLI11.hpp's own `formatter_ =
    // parent_->formatter_;`), so every subcommand -- and every nested subcommand created from
    // one of those, like `policy validate`/`baseline learn`/`baseline check`/`merge inventory`
    // -- inherits this same formatter automatically, with nothing to repeat at each add_
    // subcommand() call site below.
    app.formatter(std::make_shared<WrappingHelpFormatter>());

    bool quiet = false;
    bool no_color = false;
    bool force_color = false;
    std::string log_file;
    app.add_flag("-q,--quiet", quiet, "Suppress non-essential diagnostic/warning output");
    auto* no_color_opt =
        app.add_flag("--no-color", no_color, "Disable ANSI color in decode's text-format output");
    auto* force_color_opt = app.add_flag(
        "--color", force_color,
        "Force ANSI color in decode's text-format output, even when not writing to a terminal "
        "(e.g. piping to a pager that supports it). Without either flag, color is used only when "
        "writing directly to an interactive terminal.");
    no_color_opt->excludes(force_color_opt);
    force_color_opt->excludes(no_color_opt);
    app.add_option("--log-file", log_file,
                    "Write diagnostic/warning messages to this file instead of stderr");

    // --- decode ---------------------------------------------------------
    auto* decode_cmd =
        app.add_subcommand("decode", "Decode a pcap/pcapng capture and print each recognized packet");
    std::string decode_input, decode_interface, decode_filter, decode_display_filter, decode_output;
    int decode_duration = 0;
    int decode_snaplen = 65535;
    bool decode_promiscuous = true;
    std::string decode_format = "text";
    std::string decode_protocol = "auto";
    std::vector<int> decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
        decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
        decode_kerberos_ports, decode_ldap_ports, decode_smb_ports, decode_melsec_ports, decode_fins_ports,
        decode_bgp_ports,
        decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports, decode_mdns_ports,
        decode_llmnr_ports, decode_nbns_ports, decode_doh_ports, decode_rip_ports, decode_hsrp_ports,
        decode_remote_access_ports, decode_lateral_movement_ports, decode_enterprise_trust_ports,
        decode_wireless_backhaul_ports, decode_tunnel_vpn_ports, decode_winrm_ports, decode_dcom_ports,
        decode_ge_srtp_ports, decode_bsap_ports, decode_cclink_ie_ports, decode_codesys_ports,
        decode_coap_ports, decode_rmcp_ports, decode_amqp_ports, decode_dicom_ports,
        decode_fox_ports,
        decode_powerlink_sdo_ports,
        decode_dhcpv6_ports;
    std::vector<std::string> decode_as_raw;  // raw -d/--decode-as rule strings, parsed after CLI11
                                               // itself finishes parsing -- see parse_decode_as_rules
    size_t decode_flood_threshold = 0;  // 0 means "not given" -- keeps DecodeOptions::flood_threshold's
                                          // own compile-time default (attack_detect.hpp's
                                          // DEFAULT_FLOOD_THRESHOLD); see run_decode's own use of this.
    size_t decode_max_packets = 0;
    std::string decode_range;  // empty means "not given" -- see packet_range.hpp
    ResourceLimitCliVars decode_limit_vars;
    bool decode_strict = false;
    bool decode_mac_vendor = false, decode_resolve = false, decode_service_names = true;
    bool decode_show_vlan = true;
    bool decode_show_direction = true;
    bool decode_show_mac = false;
    bool decode_verbose = false;
    bool decode_redact = true;
    bool decode_detect_highlight = true;
    std::string decode_time_format = "r", decode_time_offset = "utc";
    std::string decode_hosts_file, decode_services_file;
    std::vector<std::string> decode_fields;
    std::string decode_write;
    bool decode_hex = false;
    bool decode_details = false;

    auto* decode_input_opt =
        decode_cmd->add_option("-r,--read", decode_input,
                                "Input capture file (classic pcap or pcapng, auto-detected)")->group("Input/output")
            ->check(CLI::ExistingFile);
    auto* decode_interface_opt = decode_cmd->add_option(
        "-i,--interface", decode_interface,
        "Capture live from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required")->group("Input/output");
    decode_input_opt->excludes(decode_interface_opt);
    decode_interface_opt->excludes(decode_input_opt);
    decode_cmd->add_option("-f,--filter", decode_filter,
                            "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; with -r, "
                            "applied per-packet after reading the file (same filter syntax either way); "
                            "requires this build to have been compiled with libpcap/Npcap support in "
                            "both cases -- mirrors tshark's own -f")->group("Filtering");
    decode_cmd->add_option("-Y,--display-filter", decode_display_filter,
                            "Display filter (Wireshark display-filter syntax), e.g. "
                            "'modbus.func_code == 16 && ip.src == 10.1.2.3'. Unlike -f/--filter (a BPF "
                            "filter applied to raw bytes before/during decode), this is evaluated "
                            "per-packet AFTER decode, against the same dissected fields this run's own "
                            "-T json output would show -- mirrors tshark's own -Y. A non-matching "
                            "packet is skipped entirely: it is not counted toward --max-packets and "
                            "does not appear in the output stream, but -w/--write's raw pcap "
                            "passthrough is unaffected (governed by -f/--filter only -- see "
                            "docs/USER_GUIDE.md's Display filters subsection). Covers universal "
                            "eth/ip/tcp/udp fields plus a curated set of protocols (Modbus, S7comm, "
                            "S7comm-Plus, DNP3, EtherNet/IP, BACnet, IEC104, GOOSE, SV, HART-IP, OPC "
                            "UA, MMS, UMAS) -- see docs/USER_GUIDE.md for the full field list. A "
                            "malformed expression is a CLI error (nonzero exit) before any packet is "
                            "processed. '@<path>' reads the expression from a file instead (one "
                            "trailing line ending trimmed, if present) -- useful for a long, "
                            "generated, or shell-generation-fragile expression.")->group("Filtering");
    decode_cmd->add_option("-a,--duration", decode_duration,
                            "Stop a live capture (-i) after this many seconds (0 = unlimited; stop "
                            "with Ctrl+C or --max-packets instead) -- mirrors tshark's own -a "
                            "autostop condition, specialized here to duration only")->group("Live capture (-i only)")
        ->capture_default_str();
    decode_cmd->add_option("--snaplen", decode_snaplen,
                            "Maximum bytes captured per packet with -i")->group("Live capture (-i only)")
        ->capture_default_str();
    decode_cmd->add_flag("!--no-promiscuous", decode_promiscuous,
                          "With -i, don't put the interface into promiscuous mode (by default it "
                          "is, since the main use case -- watching a mirrored/SPAN switch port -- "
                          "needs traffic not addressed to this host)")->group("Live capture (-i only)");
    decode_cmd->add_option("-o,--output", decode_output,
                            "Write output here instead of stdout. Caution: a single-dash "
                            "long-option typo glues onto this flag (e.g. a typo of a double-dash "
                            "long option, typed with only one dash, is parsed as -o followed by "
                            "the rest of that typo as this flag's own filename value) -- always "
                            "use the double dash for a long option name")->group("Input/output");
    decode_cmd
        ->add_option("-T,--format", decode_format,
                      "Output format: text, json, csv, fields, or zeek (fields mirrors tshark's own -T "
                      "fields -- print only the -e/--field values requested, tab-separated; see -e. "
                      "zeek writes a real Zeek conn.log -- one row per TCP/UDP connection, not per "
                      "packet, in Zeek's own TSV envelope, with `service` naming whichever protocol "
                      "conduitscope decoded -- see docs/USER_GUIDE.md's Zeek export section for exactly "
                      "which conn.log fields this first pass populates versus leaves unset)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "csv", "fields", "zeek"}))
        ->capture_default_str();
    decode_cmd
        ->add_option("-t,--time-format", decode_time_format,
                      "How to render each packet's timestamp -- mirrors tshark's own -t mnemonics: "
                      "r/relative (elapsed since the first packet, the default), e/epoch (raw "
                      "seconds since the Unix epoch), d/delta (elapsed since the previous packet), "
                      "a/absolute (HH:MM:SS.ffffff), ad/absolute-date (YYYY-MM-DD HH:MM:SS.ffffff) "
                      "-- see --time-offset for absolute/absolute-date's timezone, and docs/"
                      "MANUAL.md's OUTPUT FORMATS section")->group("Output format")
        ->transform(CLI::IsMember({"e", "epoch", "r", "relative", "d", "delta", "a", "absolute", "ad",
                                    "absolute-date"}))
        ->capture_default_str();
    decode_cmd
        ->add_option("--time-offset", decode_time_offset,
                      "Timezone for --time-format=absolute/absolute-date: \"utc\" (the default), "
                      "\"local\" (this machine's own system timezone), or a fixed \"+HH:MM\"/\"-HH:MM\" "
                      "offset -- e.g. to read a capture in the timezone of the site it came from "
                      "regardless of where you're analyzing it; neither tshark nor tcpdump offers this "
                      "beyond UTC-vs-local, so this is conduitscope's own extension -- ignored by every "
                      "other --time-format value")->group("Output format")
        ->capture_default_str();
    decode_cmd
        ->add_option("--protocol", decode_protocol,
                      "Restrict decoding to one protocol instead of auto-detecting all of them")->group("Protocol selection")
        ->transform(CLI::IsMember({"auto", "modbus", "dnp3", "s7comm", "mms", "iec104", "enip", "profinet", "goose", "sv", "ethercat", "stp", "devicenet", "canopen", "j1939", "bacnet", "hartip", "opcua", "mqtt", "s7comm-plus", "ff-hse", "dns", "mdns", "llmnr", "nbns", "doh", "rip", "icmp", "igmp", "vrrp", "hsrp", "igrp", "pim", "eigrp", "ospf", "remote-access", "lateral-movement", "enterprise-trust", "eapol", "wireless-backhaul", "pppoe", "tunnel-vpn", "mpls", "arp", "lldp", "twincat", "kerberos", "ldap", "smb", "melsec", "fins", "bgp", "slow-protocols", "winrm", "dcom", "ge-srtp", "bsap", "cclink-ie", "codesys", "coap", "zigbee", "cdp", "asf", "ipmi", "rmcp", "amqp091", "amqp10", "dicom", "powerlink", "fox", "icmpv6", "dhcpv6", "homeplug-av"}))
        ->capture_default_str();
    decode_cmd->add_option("--modbus-port", decode_modbus_ports,
                            "Additional TCP port to treat as expected for Modbus (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--dnp3-port", decode_dnp3_ports,
                            "Additional TCP port to treat as expected for DNP3 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--s7comm-port", decode_s7comm_ports,
                            "Additional TCP port to treat as expected for COTP/S7comm, MMS, and "
                            "S7comm-Plus (repeatable, shared -- all three ride the identical "
                            "TPKT/COTP transport and TCP port); does not change detection, only "
                            "whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--iec104-port", decode_iec104_ports,
                            "Additional TCP port to treat as expected for IEC 104 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--enip-port", decode_enip_ports,
                            "Additional TCP port to treat as expected for EtherNet/IP explicit "
                            "messaging (repeatable); does not change detection, only whether the "
                            "port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--enip-io-port", decode_enip_io_ports,
                            "Additional UDP port to treat as expected for EtherNet/IP CIP I/O "
                            "implicit messaging (repeatable); does not change detection, only "
                            "whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--bacnet-port", decode_bacnet_ports,
                            "Additional UDP port to treat as expected for BACnet/IP (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--hartip-port", decode_hartip_ports,
                            "Additional TCP or UDP port to treat as expected for HART-IP "
                            "(repeatable); does not change detection, only whether the port is "
                            "flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--kerberos-port", decode_kerberos_ports,
                            "Additional TCP or UDP port to treat as expected for Kerberos "
                            "(repeatable); does not change detection, only whether the port is "
                            "flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--melsec-port", decode_melsec_ports,
                            "Additional TCP or UDP port to treat as expected for MELSEC "
                            "Communication Protocol (MC Protocol/SLMP, repeatable); applies to both "
                            "transports even though their conventional defaults differ (5001/TCP, "
                            "5000/UDP); does not change detection, only whether the port is "
                            "flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--fins-port", decode_fins_ports,
                            "Additional TCP or UDP port to treat as expected for FINS (Omron, "
                            "repeatable); applies to both transports, which share the same "
                            "conventional default (9600) unlike MELSEC's own split ports; does not "
                            "change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--bgp-port", decode_bgp_ports,
                            "Additional TCP port to treat as expected for BGP (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--ldap-port", decode_ldap_ports,
                            "Additional TCP port to treat as expected for LDAP (repeatable); does "
                            "not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--smb-port", decode_smb_ports,
                            "Additional TCP port to treat as expected for SMB (repeatable); does "
                            "not change detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--opcua-port", decode_opcua_ports,
                            "Additional TCP port to treat as expected for OPC UA (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--mqtt-port", decode_mqtt_ports,
                            "Additional TCP port to treat as expected for MQTT (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--ffhse-port", decode_ffhse_ports,
                            "Additional TCP or UDP port to treat as expected for FOUNDATION "
                            "Fieldbus HSE (repeatable, shared across FDA/SM/FMS/LAN Redundancy -- "
                            "the sub-protocol is signaled in-band, not by port); does not change "
                            "detection, only whether the port is flagged as unexpected")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--dns-port", decode_dns_ports,
                            "Additional UDP port to treat as expected for DNS (repeatable); UNLIKE "
                            "every --*-port option above, this DOES widen detection in Auto mode, "
                            "not just the 'expected port' annotation -- DNS has no self-describing "
                            "wire format at all, so it is normally only attempted on port 53 (see "
                            "docs/MANUAL.md)")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--mdns-port", decode_mdns_ports,
                            "Additional UDP port to treat as expected for Multicast DNS "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 5353")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--llmnr-port", decode_llmnr_ports,
                            "Additional UDP port to treat as expected for LLMNR (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 5355")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--nbns-port", decode_nbns_ports,
                            "Additional UDP port to treat as expected for NetBIOS Name Service/"
                            "NBT-NS (repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 137")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--doh-port", decode_doh_ports,
                            "Additional TCP port to check for a DNS-over-HTTPS TLS ClientHello "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 443. Detection only -- "
                            "see docs/MANUAL.md; the DNS message itself is never visible")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--winrm-port", decode_winrm_ports,
                            "Additional TCP port to treat as expected for WS-Management (WinRM) "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 5985 (plaintext; TLS-"
                            "wrapped port 5986 is out of scope, see docs/MANUAL.md)")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--dcom-port", decode_dcom_ports,
                            "Additional TCP port to treat as expected for DCOM activation "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 135. Structural "
                            "activation/OXID-resolution recognition only, see docs/MANUAL.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--ge-srtp-port", decode_ge_srtp_ports,
                            "Additional TCP port to treat as expected for GE SRTP (GE Fanuc/GE "
                            "Intelligent Platforms PLC protocol) (repeatable); widens detection in "
                            "Auto mode, same caveat as --dns-port -- normally only attempted on "
                            "port 18245, see docs/MANUAL.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--rip-port", decode_rip_ports,
                            "Additional UDP port to treat as expected for RIP (repeatable); widens "
                            "detection in Auto mode, same caveat as --dns-port -- normally only "
                            "attempted on port 520")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--hsrp-port", decode_hsrp_ports,
                            "Additional UDP port to treat as expected for HSRP (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 1985. IGMP and VRRP need no port option at all "
                            "-- both are dispatched purely by IP protocol number, see docs/"
                            "MANUAL.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--bsap-port", decode_bsap_ports,
                            "Additional UDP port to treat as expected for BSAP (Bristol Standard "
                            "Asynchronous/Synchronous Protocol, Bristol Babcock/Emerson RTU "
                            "protocol) (repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 1234, see docs/"
                            "MANUAL.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--cclink-ie-port", decode_cclink_ie_ports,
                            "Additional UDP port to treat as expected for CC-Link IE Field Network "
                            "Basic (CCIEFB cyclic data / SLMP node search / set IP address) "
                            "(repeatable); UNLIKE most --x-port options this does not gate "
                            "detection (CC-Link IE is tried on every UDP port in Auto mode, like "
                            "MELSEC) -- it only widens which port(s) count as expected rather than "
                            "flagged as non-standard. Normally 61450 (cyclic) and 61451 (node "
                            "search/set IP address), see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--codesys-port", decode_codesys_ports,
                            "Additional TCP or UDP port to treat as expected for CODESYS V3 (3S-"
                            "Smart/CODESYS GmbH's PLC runtime protocol) (repeatable); UNLIKE most "
                            "--x-port options this does not gate detection (CODESYS is tried on "
                            "every TCP and UDP port in Auto mode, like CC-Link IE) -- it only "
                            "widens which port(s) count as expected rather than flagged as "
                            "non-standard. Normally 11740/1217 (TCP) and 1740-1743 (UDP), see docs/"
                            "PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--coap-port", decode_coap_ports,
                            "Additional UDP port to treat as expected for CoAP (Constrained "
                            "Application Protocol, RFC 7252) (repeatable); UNLIKE most --x-port "
                            "options this DOES gate detection (CoAP is only tried on this port, "
                            "like BSAP/RIP/HSRP/DNS -- its own shortest legal messages are too "
                            "weak a structural signal to try on every UDP port). Normally 5683, "
                            "see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--rmcp-port", decode_rmcp_ports,
                            "Additional UDP port to treat as expected for RMCP/ASF/IPMI (Remote "
                            "Management Control Protocol / Alert Standard Format / Intelligent "
                            "Platform Management Interface -- BMC/OOB server management; one "
                            "shared list, since all three always ride the same UDP port by "
                            "wire-format construction) (repeatable); UNLIKE most --x-port options "
                            "this DOES gate detection (like BSAP/CoAP/RIP/HSRP -- no magic-byte-"
                            "strength structural gate). Normally 623, see docs/"
                            "PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--amqp-port", decode_amqp_ports,
                            "Additional TCP port to treat as expected for AMQP 0-9-1/1.0 "
                            "(Advanced Message Queuing Protocol -- two wire-INCOMPATIBLE "
                            "protocols that share this same default port by convention; one "
                            "shared list, see amqp_common.hpp) (repeatable); in Auto mode this "
                            "DOES gate detection (like WinRM/DCOM/GE SRTP -- no magic-byte-"
                            "strength structural gate on every frame, only on a connection's "
                            "very first message). Normally 5672, see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--dicom-port", decode_dicom_ports,
                            "Additional TCP port to treat as expected for DICOM (Digital Imaging "
                            "and Communications in Medicine, NEMA/ACR PS3.x -- PACS/modality "
                            "network traffic) beyond BOTH of its own two default ports (repeatable); "
                            "in Auto mode this DOES gate detection (like WinRM/DCOM/GE SRTP/AMQP -- "
                            "no magic-byte-strength structural gate). UNLIKE every other --x-port "
                            "option here, DICOM already checks TWO default ports automatically with "
                            "no flag needed -- 104 (IANA-registered, rare in practice) AND 11112 "
                            "(the de facto real-world default for modern PACS/dcm4che/Orthanc/most "
                            "vendor software); neither is \"the\" default the other merely widens. "
                            "See docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--fox-port", decode_fox_ports,
                            "Additional TCP port to treat as expected for Tridium Niagara Fox "
                            "(building-automation-system station protocol -- see the unauthenticated "
                            "'fox hello' system-identity-disclosure finding, CISA ICSA-12-228-01A) "
                            "(repeatable); in Auto mode this DOES gate detection (like WinRM/DCOM/"
                            "GE SRTP/AMQP/DICOM -- no magic-byte-strength structural gate). "
                            "Normally 1911, see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--powerlink-sdo-port", decode_powerlink_sdo_ports,
                            "Additional UDP port to treat as expected for Ethernet POWERLINK's "
                            "SDO-over-UDP secondary gate (EPSG DS301 non-cyclic/out-of-band SDO "
                            "access; the primary cyclic real-time path rides raw Ethernet, EtherType "
                            "0x88AB, and has no port concept at all) (repeatable); UNLIKE most "
                            "--x-port options this DOES gate detection (like BSAP/CoAP/RIP/HSRP -- "
                            "an SDO Sequence Layer header is too weak a structural signal to try on "
                            "every UDP port). Normally 3819, see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--dhcpv6-port", decode_dhcpv6_ports,
                            "Additional UDP port to treat as expected for DHCPv6 (repeatable); "
                            "UNLIKE most --x-port options this DOES gate detection (like BSAP/CoAP/"
                            "RIP/HSRP/DNS -- no magic-byte-strength structural gate). Applies to "
                            "BOTH of DHCPv6's own default ports at once (546 client, 547 server), "
                            "see docs/PROTOCOL_COVERAGE.md")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option(
        "-d,--decode-as", decode_as_raw,
        "Force a specific decoder onto traffic on a given port that wouldn't otherwise be "
        "recognized as it -- mirrors Wireshark/tshark's own -d, restricted here to a subset of "
        "its selector syntax: '<tcp|udp>.port==<port>,<name>' (repeatable). Only ever WIDENS "
        "detection, exactly like every --x-port option above -- a `-d` rule is consulted as a "
        "LAST RESORT on the named port, after every one of this decoder's own stronger "
        "structural/port checks has already failed to match anything, so it never overrides an "
        "already-correct match (e.g. VNC's own RFB banner still wins over a -d rule naming a "
        "different protocol on that same port). Deliberately scoped to PORT-GATED protocols "
        "only: the ~40 opportunistic ICS protocols (Modbus/DNP3/S7comm/etc.) are already tried "
        "on every port by structural signature, so forcing them is meaningless, and the "
        "tunnel-vpn tier's IP-protocol-number-gated names (gre/nvgre/eoip/esp/ah/ip-in-ip/6in4) "
        "aren't expressible by a tcp.port==/udp.port== selector -- neither is supported by -d in "
        "this release. Supported names: rdp, vnc, teamviewer, anydesk, zoom (tcp or udp); ssh, "
        "http, https, telnet, ftp (tcp only); snmp, tftp (udp only); ntp, dhcp, radius (udp "
        "only); ldaps, tacacs-plus (tcp only); capwap-control, capwap-data, lwapp-control, "
        "lwapp-data, gtp-u (udp only); ike, l2tp, vxlan, geneve, wireguard, dtls-tunnel (udp "
        "only); openvpn (tcp or udp); stt (tcp only); and every name that already has its own "
        "dedicated --x-port option above (dns, mdns, llmnr, nbns, doh, rip, hsrp, winrm, dcom, "
        "ge-srtp, bsap, coap, rmcp, amqp, dicom, fox, powerlink-sdo, dhcpv6 -- each restricted to "
        "that name's own real transport, e.g. dns/udp, doh/tcp). Example: "
        "-d tcp.port==8443,ldaps forces port 8443/TCP to be reported as LDAPS even though it "
        "isn't one of LDAPS's own configured ports")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("--flood-threshold", decode_flood_threshold,
                            "Per-destination packet count that trips a SYN/ACK/TCP/ICMP/UDP flood "
                            "note (see docs/PROTOCOL_COVERAGE.md's Attack Detection section) -- a "
                            "WHOLE-CAPTURE count, not a per-second rate. ALSO governs the IPv6-side "
                            "volumetric counters (see ipv6_attack_detect.hpp): the Router "
                            "Advertisement flood counter (a whole-link count, not per-destination) "
                            "and the DHCPv6 exhaustion counter (a distinct-Client-DUID count, not a "
                            "raw packet count) -- one shared, overridable threshold rather than a "
                            "second IPv6-specific concept. Default: " +
                                std::to_string(DEFAULT_FLOOD_THRESHOLD) +
                                " (a deliberately small, documented-as-arbitrary illustrative "
                                "value, not sourced from any vendor's own default)")->group("Resource limits (advanced)");
    decode_cmd->add_option(
        "--remote-access-port", decode_remote_access_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 1 \"IT protocols an OT "
        "auditor flags\" family (RDP/VNC/TeamViewer/AnyDesk/Zoom -- see docs/MANUAL.md's ROADMAP "
        "item 18); widens detection in Auto mode for RDP's COTP-gated check and the three port-only "
        "protocols (TeamViewer/AnyDesk/Zoom), same caveat as --dns-port -- VNC's own RFB banner "
        "check is never port-gated regardless, see it_protocols.hpp")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option(
        "--lateral-movement-port", decode_lateral_movement_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 2 \"IT protocols an OT "
        "auditor flags\" family (SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP -- SMB was promoted to "
        "its own dedicated decoder, see --smb-port -- see docs/MANUAL.md's ROADMAP item 18); "
        "widens detection in Auto mode for SNMP/Telnet/FTP/TFTP's own port-gated checks and "
        "HTTPS's port-only fallback, same caveat as --dns-port -- SSH's version-exchange banner "
        "and HTTP's request-line/status-line are never port-gated regardless, see it_protocols.hpp")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option(
        "--enterprise-trust-port", decode_enterprise_trust_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 3 \"IT protocols an OT "
        "auditor flags\" family (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+ -- see docs/MANUAL.md's ROADMAP "
        "item 18); widens detection in Auto mode for NTP/LDAP/RADIUS/TACACS+'s own port-gated checks "
        "and LDAPS's port-only fallback, same caveat as --dns-port -- DHCP's magic cookie is never "
        "port-gated regardless, see it_protocols.hpp. IEEE 802.1X/EAPOL needs no port option at all "
        "-- it has no port, see docs/MANUAL.md and eapol.hpp")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option(
        "--wireless-backhaul-port", decode_wireless_backhaul_ports,
        "Additional UDP port to treat as expected for the Tier 4 \"IT protocols an OT auditor "
        "flags\" family (CAPWAP control/data, LWAPP control/data, GTP-U -- see docs/MANUAL.md's "
        "ROADMAP item 18); widens detection in Auto mode for all five, since none of this tier's "
        "own structural checks are strong enough to run port-independently, same caveat as "
        "--dns-port -- see it_protocols.hpp. PPPoE needs no port option at all -- it has no port, "
        "see docs/MANUAL.md and pppoe.hpp")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option(
        "--tunnel-vpn-port", decode_tunnel_vpn_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 5 \"IT protocols an OT "
        "auditor flags\" family (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve, "
        "WireGuard, OpenVPN, dtls-tunnel, STT -- see docs/MANUAL.md's ROADMAP item 18); widens "
        "detection in Auto mode for every port-based protocol here EXCEPT dtls-tunnel, whose own "
        "DTLS record structural check is never port-gated regardless, same caveat as --dns-port -- "
        "see tunnel_vpn.hpp. GRE/ESP/AH/IP-in-IP/6in4/L2TP's own IP-protocol-number-keyed forms, and "
        "MPLS, need no port option at all -- see docs/MANUAL.md, tunnel_vpn.hpp, and mpls.hpp")->group("Protocol port overrides (rarely needed)");
    decode_cmd->add_option("-c,--max-packets", decode_max_packets,
                            "Stop after decoding this many packets (0 = unlimited) -- mirrors "
                            "tshark's own -c")->group("Input/output")
        ->capture_default_str();
    auto* decode_range_opt = decode_cmd->add_option(
        "--range", decode_range,
        "Select packets by their real position in the capture file: a comma-separated list of "
        "1-based packet numbers and/or inclusive start-end ranges, e.g. '5,10-20,30-40' -- same "
        "syntax and numbering as Wireshark's editcap (and this tool's own '#<n>' packet index in "
        "decode's text output); -r only. Combines with -f/--filter (both must match) and with "
        "-c/--max-packets (which caps the number of packets taken from the selection, same as it "
        "always has)")->group("Input/output");
    decode_range_opt->excludes(decode_interface_opt);
    decode_interface_opt->excludes(decode_range_opt);
    add_resource_limit_options(decode_cmd, decode_limit_vars);
    decode_cmd->add_flag("--strict", decode_strict,
                          "Abort on the first malformed packet instead of reporting it and continuing")->group("Display options");
    decode_cmd->add_flag("!--no-vlan", decode_show_vlan,
                          "Disable display of the 802.1Q VLAN ID for VLAN-tagged packets, on by "
                          "default -- see docs/MANUAL.md's OUTPUT FORMATS section")->group("Display options");
    decode_cmd->add_flag(
        "!--no-direction", decode_show_direction,
        "Disable display of per-packet TCP flow direction (client/server determination and which "
        "tier decided it -- handshake/content/port-heuristic), on by default -- see docs/MANUAL.md's "
        "OUTPUT FORMATS section and ROADMAP item 19")->group("Display options");
    decode_cmd->add_flag(
        "--ether", decode_show_mac,
        "For a packet with an IP layer, show its Ethernet header (source/destination MAC "
        "address, VLAN tag) below the packet line in text output -- mirrors tcpdump's own -e "
        "(long-form only here: -e is reserved for -T fields' own --field, tshark's convention -- "
        "see -e/--field below). "
        "Off by default to keep output compact; implied by --mac-vendor (there'd be nothing to "
        "attach a vendor name to otherwise). A no-op for a packet with no IP layer at all (ARP/"
        "LLDP/EAPOL/PPPoE/MPLS/etc.), since its MAC address pair is already shown on its own "
        "head line unconditionally. Only affects text output -- JSON/CSV always include "
        "src_mac/dst_mac as base fields, same as src_ip/dst_ip -- see docs/MANUAL.md's OUTPUT "
        "FORMATS section")->group("Display options");
    decode_cmd->add_flag(
        "-v,--verbose", decode_verbose,
        "Show per-packet notes (the longer-form contextual/security observations) and the "
        "trailing (client X -- tier) direction-source suffix; both are suppressed by default "
        "to keep default output readable, since on a busy capture the notes in particular can "
        "swamp the per-packet lines. Off by default. Text output only (--format text, the "
        "default) -- JSON/CSV always include notes/direction fields unconditionally, same as "
        "every other field; --no-direction still suppresses the direction suffix even under "
        "-v, since that flag turns off direction detection display entirely rather than just "
        "its verbosity")->group("Display options");
    decode_cmd->add_flag(
        "--redact,!--no-redact", decode_redact,
        "Mask cleartext authentication secrets found while decoding (HSRP/VRRP authentication "
        "data, OPC UA ActivateSessionRequest passwords, MQTT CONNECT passwords) with "
        "[REDACTED] wherever they would otherwise appear -- summary/notes text and JSON value "
        "fields alike -- so output can be shared safely by default. On by default; pass "
        "--no-redact to see the real cleartext values (useful for local triage/incident "
        "response where the analyst is already trusted with the capture itself). Usernames "
        "are never redacted, only passwords/authentication data -- see docs/MANUAL.md")->group("Display options");
    decode_cmd->add_flag(
        "--detect-highlight,!--no-detect-highlight", decode_detect_highlight,
        "Highlight (bold red in text output; a detect_finding/detect_finding_technique/"
        "detect_finding_description field in json/csv/fields output) any packet that matches one "
        "of the 'detect' subcommand's own always-notable findings (a PLC/controller mode change, a "
        "firmware/logic download, a device restart, an unsolicited/unexpected protocol message, a "
        "known scanner-tool fingerprint, ...) -- live, one packet at a time, including under -i "
        "live capture. On by default; pass --no-detect-highlight to skip running DetectEngine "
        "against every packet entirely (e.g. for maximum decode throughput, or when the highlight "
        "isn't wanted). Deliberately does NOT cover 'new vs. known' findings (a new remote-access "
        "channel, a new CIP originator) or the two whole-capture-only patterns (S7 Setup "
        "Communication probing, the download-then-restart composite) -- those need the complete "
        "capture (or a baseline) to resolve and cannot be decided live, one packet at a time; use "
        "the 'detect' subcommand itself for those. See docs/MANUAL.md's own \"Always-notable "
        "highlighting\" subsection under decode")->group("Display options");
    decode_cmd->add_option(
        "-e,--field", decode_fields,
        "With -T fields, print this field's value (repeatable, printed in the order given, "
        "tab-separated) -- mirrors tshark's own -e. The field name is whatever key appears in "
        "this tool's own --format json output for that packet (e.g. src_ip, dst_port, "
        "modbus_function_code); a field absent for a given packet (wrong protocol, optional "
        "field not present) prints as an empty column rather than an error. Requires -T fields; "
        "see --format")->group("Output format");
    decode_cmd->add_option(
        "-w,--write", decode_write,
        "Write every packet that reaches this run (after -f/--filter, if given) to this path as "
        "a new classic-pcap capture file, raw and unmodified -- mirrors tshark/tcpdump's own -w. "
        "Works identically whether packets come from a live capture (-i) or an offline read "
        "(-r); does not change or replace the normal --format output, which continues to stdout/"
        "-o exactly as without -w")->group("Input/output");
    decode_cmd->add_flag(
        "-x,--hex", decode_hex,
        "Print a hex+ASCII dump of each packet's raw bytes below its normal decode line -- "
        "mirrors tshark's own -x. Text output only (--format text, the default); ignored under "
        "--format json/csv/fields")->group("Display options");
    decode_cmd->add_flag(
        "-V,--details", decode_details,
        "Print the complete protocol breakdown of each packet, layer by layer, instead of the "
        "default one-line summary -- mirrors tshark's own -V (Wireshark's 'Packet Details' "
        "pane). Every field this tool's own --format json output would show for the packet is "
        "shown here too, grouped under the layer it belongs to (Frame, Ethernet II, Internet "
        "Protocol, Transmission Control Protocol/User Datagram Protocol, then the recognized "
        "application protocol's own fields) rather than flattened into one JSON object -- "
        "nothing is held back for -V specifically: notes and any detect/attack finding are "
        "always shown here regardless of -v/--verbose, since completeness is this flag's whole "
        "point. Text output only (--format text, the default); ignored under --format "
        "json/csv/fields/zeek, the same posture -x/--hex already has. Composes with -x: the hex "
        "dump, when also given, still appears below this packet's own layer breakdown")->group("Display options");
    decode_cmd->add_flag("--mac-vendor", decode_mac_vendor,
                          "Enable OUI (MAC vendor) resolution and show it next to each MAC "
                          "address; off by default to keep output compact. Implies --ether -- "
                          "see docs/MANUAL.md's OUTPUT FORMATS section. (Named --mac-vendor, "
                          "not --oui, specifically so a single-dash typo of this flag reports a "
                          "clean \"argument not expected\" error instead of silently gluing onto "
                          "-o/--output the way a single-dash -oui used to -- see -o's own help "
                          "text and docs/DEVELOPMENT.md's ROADMAP for the full story)")->group("Name resolution");
    decode_cmd->add_flag(
        "--resolve", decode_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts); off by "
        "default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section")->group("Name resolution");
    decode_cmd
        ->add_option("--hosts", decode_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    decode_cmd->add_flag("!--nn", decode_service_names,
                          "Disable service name resolution (built-in table plus --services), on "
                          "by default")->group("Name resolution");
    decode_cmd
        ->add_option("--services", decode_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- info -------------------------------------------------------------
    auto* info_cmd = app.add_subcommand(
        "info",
        "Print pcap file metadata and a protocol histogram, without full per-packet output. "
        "Typing 'info' isn't actually required to use this subcommand's own -z/--stat -- see "
        "-z's own help text below, and docs/DEVELOPMENT.md's ROADMAP item 109");
    std::string info_input;
    info_cmd->add_option("-r,--read", info_input, "Input capture file (classic pcap or pcapng, auto-detected)")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    std::vector<std::string> info_stat_values;
    info_cmd
        ->add_option(
            "-z,--stat", info_stat_values,
            "Print an aggregate Conversations/Endpoints/Follow-stream table (mirrors tshark's own "
            "-z; repeatable -- each occurrence adds one table/stream, and none are shown, or even "
            "tracked, unless requested here): 'conv,ip' (IPv4 address-pair conversations), "
            "'endpoints,ip' (per-address IPv4 traffic), 'conv,eth' / 'endpoints,eth' (the same two "
            "views over raw Ethernet/MAC traffic -- also covers non-IP OT L2 traffic with no IP "
            "layer at all, such as PROFINET RT/GOOSE/SV/EtherCAT/POWERLINK/unrecognized "
            "EtherTypes), 'conv,tcp' (TCP address:port-pair conversations, each row also giving its "
            "0-based tcp.stream index -- the <N> a later follow,tcp,stream,<N> should ask for), "
            "'follow,tcp,stream,<N>' / 'follow,udp,stream,<N>' (reconstruct and hex+ASCII-dump the "
            "raw byte stream of TCP/UDP session <N> -- streams are numbered 0,1,2,... in the order "
            "each session's first packet appears in the capture, separately for TCP and UDP, "
            "tshark's own tcp.stream/udp.stream convention; each direction is shown separately, "
            "same ordering tshark's own Follow Stream uses, no HTTP/TLS/HTTP-2/QUIC-aware "
            "reassembly -- raw TCP/UDP bytes only, deliberately, see docs/DEVELOPMENT.md's ROADMAP "
            "item 108). ROADMAP item 109: -z doesn't need 'info' typed at all -- 'conduitscope -r "
            "FILE -z conv,tcp' (no subcommand) works exactly like 'conduitscope info -r FILE -z "
            "conv,tcp', since no subcommand at all now defaults to 'info' whenever -z/--stat "
            "appears anywhere on the line (decode otherwise). Also item 109: once -z is given at "
            "all (however the subcommand was reached), 'info' prints ONLY the table(s)/stream(s) "
            "actually requested here -- no file metadata, no packet count, no protocol histogram, "
            "none of info's other usual output")->group("Output format")
        ->check(validate_stat_value);
    size_t info_max_conversations = 0, info_max_endpoints = 0;
    add_conversation_stats_options(info_cmd, info_max_conversations, info_max_endpoints);
    size_t info_max_follow_bytes = 0;
    info_cmd
        ->add_option(
            "--max-follow-bytes", info_max_follow_bytes,
            "Cap the bytes buffered PER DIRECTION for each 'follow,tcp,stream,<N>'/"
            "'follow,udp,stream,<N>' table (default 16 MiB, the same default as decoder.cpp's own "
            "general TCP reassembly cap -- see resource_limits.hpp's max_reassembly_bytes). 0 = "
            "leave it at its own default; past this, that direction's own stream is truncated (not "
            "the whole capture's read -- every other -z/info counter is unaffected) and a warning "
            "line is printed")->group("Resource limits (advanced)")
        ->capture_default_str();

    // --- interfaces -----------------------------------------------------------
    auto* interfaces_cmd = app.add_subcommand(
        "interfaces", "List network interfaces available for live capture (-i); requires this "
                       "build to have been compiled with libpcap/Npcap support");

    // --- policy validate ----------------------------------------------------
    auto* policy_cmd =
        app.add_subcommand("policy", "Zone/conduit compliance checking against a policy file");
    auto* policy_validate_cmd = policy_cmd->add_subcommand(
        "validate", "Check decoded traffic against a zone/conduit policy file");
    std::string policy_input, policy_interface, policy_filter, policy_file, policy_output;
    int policy_duration = 0;
    int policy_snaplen = 65535;
    bool policy_promiscuous = true;
    std::string policy_format = "text";
    bool policy_strict = false;
    bool policy_strict_it_protocols = false;
    bool policy_summarize_unclassified = false;
    bool policy_mac_vendor = false, policy_resolve = false, policy_service_names = true;
    std::string policy_hosts_file, policy_services_file;
    ResourceLimitCliVars policy_limit_vars;
    size_t policy_max_tcp_flows = 0, policy_max_udp_flows = 0, policy_max_ethernet_flows = 0,
           policy_max_notable_protocols = 0;
    auto* policy_input_opt =
        policy_validate_cmd->add_option("-r,--read", policy_input,
                                         "Input capture file (classic pcap or pcapng, auto-detected)")->group("Input/output")
            ->check(CLI::ExistingFile);
    auto* policy_interface_opt = policy_validate_cmd->add_option(
        "-i,--interface", policy_interface,
        "Check live traffic from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required")->group("Input/output");
    policy_input_opt->excludes(policy_interface_opt);
    policy_interface_opt->excludes(policy_input_opt);
    policy_validate_cmd->add_option("-f,--filter", policy_filter,
                                     "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; "
                                     "with -r, applied per-packet after reading the file (same filter syntax "
                                     "either way); requires this build to have been compiled with libpcap/Npcap "
                                     "support in both cases -- mirrors tshark's own -f, and `decode`'s -f/--filter")->group("Filtering");
    policy_validate_cmd
        ->add_option("--duration", policy_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")->group("Live capture (-i only)")
        ->capture_default_str();
    policy_validate_cmd->add_option("--snaplen", policy_snaplen, "Maximum bytes captured per packet with -i")->group("Live capture (-i only)")
        ->capture_default_str();
    policy_validate_cmd->add_flag(
        "!--no-promiscuous", policy_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)")->group("Live capture (-i only)");
    policy_validate_cmd
        ->add_option("--policy", policy_file,
                      "Zone/conduit policy file (a restricted YAML subset -- see docs/MANUAL.md's "
                      "POLICY FILE FORMAT section)")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_option(
        "-o,--output", policy_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name")->group("Input/output");
    policy_validate_cmd
        ->add_option("-T,--format", policy_format,
                     "Report format: text/json (the full report), or cef/leef/syslog (curated "
                     "one-liners, one per FlowVerdict::Violation only -- see docs/USER_GUIDE.md's "
                     "SECURITY EVENT EXPORT section)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "cef", "leef", "syslog"}))
        ->capture_default_str();
    policy_validate_cmd->add_flag("--strict", policy_strict,
                                   "Abort on the first malformed packet instead of reporting it and continuing")->group("Display options");
    add_resource_limit_options(policy_validate_cmd, policy_limit_vars);
    add_policy_engine_limit_options(policy_validate_cmd, policy_max_tcp_flows, policy_max_udp_flows,
                                     policy_max_ethernet_flows, policy_max_notable_protocols);
    policy_validate_cmd->add_flag(
        "--strict-it-protocols", policy_strict_it_protocols,
        "Also fail compliance (non-zero exit code) when any \"IT protocol an OT auditor flags\" "
        "(RDP/VNC/SMB/SSH/HTTP(S)/SNMP/GRE/... -- see docs/MANUAL.md's ROADMAP item 18, and the "
        "report's own \"notable protocols\" section) was observed, even on an otherwise COMPLIANT "
        "capture -- off by default: the \"notable protocols\" section is always populated regardless "
        "of this flag, so nothing is hidden without it; this flag only controls whether that finding "
        "additionally affects the exit code, for a CI/audit pipeline that wants to gate on it")->group("Display options");
    policy_validate_cmd->add_flag(
        "--summarize-unclassified", policy_summarize_unclassified,
        "Collapse UNCLASSIFIED TRAFFIC (and, if present, ETHERNET UNCLASSIFIED TRAFFIC) entries that "
        "share the same endpoints/port/protocol(s)/zones into one summary line with a flow count and "
        "total packet count, instead of one block per individual flow. Off by default -- the "
        "unsummarized, one-block-per-flow report is unchanged unless this is given. Aimed at a busy "
        "capture with far more distinct TCP flows (a new source port on every reconnect) than "
        "distinct (client, server, port) patterns actually worth reviewing, where that can otherwise "
        "make a text report unnecessarily huge; VIOLATIONS and ALLOWED are never summarized, only "
        "the unclassified groups. Only affects --format text -- the JSON report always lists every "
        "flow individually, since it's already structured data a script can group/deduplicate on its "
        "own with more precision than any one fixed grouping key here could offer")->group("Display options");
    policy_validate_cmd->add_flag("--mac-vendor", policy_mac_vendor,
                                   "Enable OUI (MAC vendor) resolution in the report; off by "
                                   "default to keep output compact -- see docs/MANUAL.md's "
                                   "OUTPUT FORMATS section. (Named --mac-vendor, not --oui, so a "
                                   "single-dash typo errors cleanly instead of silently gluing "
                                   "onto -o/--output -- see decode's --mac-vendor help text)")->group("Name resolution");
    policy_validate_cmd->add_flag(
        "--resolve", policy_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section")->group("Name resolution");
    policy_validate_cmd
        ->add_option("--hosts", policy_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_flag("!--nn", policy_service_names,
                                   "Disable service name resolution (built-in table plus --services) "
                                   "in the report, on by default")->group("Name resolution");
    policy_validate_cmd
        ->add_option("--services", policy_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- inventory ------------------------------------------------------------
    auto* inventory_cmd = app.add_subcommand(
        "inventory", "Passive OT asset inventory: infer a first-draft zone/conduit model (asset "
                      "list, communication matrix, proposed zones/conduits) from a capture -- the "
                      "opposite direction from 'policy validate'. See docs/MANUAL.md's ROADMAP "
                      "item 17.");
    std::string inventory_input, inventory_interface, inventory_filter, inventory_output;
    int inventory_duration = 0;
    int inventory_snaplen = 65535;
    bool inventory_promiscuous = true;
    std::string inventory_format = "text";
    bool inventory_strict = false;
    int inventory_zone_prefix = static_cast<int>(kDefaultInventoryZonePrefixLen);
    std::string inventory_diagram_file;
    std::string inventory_diagram_format = "mermaid";
    std::string inventory_policy_out;
    std::string inventory_acl_out;
    std::string inventory_acl_format = "cisco";
    std::string inventory_edges_csv;
    std::string inventory_conduits_csv;
    bool inventory_mac_vendor = false, inventory_resolve = false, inventory_service_names = true;
    std::string inventory_hosts_file, inventory_services_file;
    ResourceLimitCliVars inventory_limit_vars;
    size_t inventory_max_assets = 0, inventory_max_edges = 0, inventory_max_tcp_sessions = 0,
           inventory_max_notable_protocols = 0;

    auto* inventory_input_opt =
        inventory_cmd->add_option("-r,--read", inventory_input,
                                   "Input capture file (classic pcap or pcapng, auto-detected)")->group("Input/output")
            ->check(CLI::ExistingFile);
    auto* inventory_interface_opt = inventory_cmd->add_option(
        "-i,--interface", inventory_interface,
        "Build the inventory from live traffic on this network interface instead of reading a "
        "file (see 'conduitscope interfaces'); requires this build to have been compiled with "
        "libpcap/Npcap support -- exactly one of -r/-i is required")->group("Input/output");
    inventory_input_opt->excludes(inventory_interface_opt);
    inventory_interface_opt->excludes(inventory_input_opt);
    inventory_cmd->add_option("-f,--filter", inventory_filter,
                               "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; "
                               "with -r, applied per-packet after reading the file (same filter syntax "
                               "either way); requires this build to have been compiled with libpcap/Npcap "
                               "support in both cases -- mirrors tshark's own -f, and `decode`'s -f/--filter")->group("Filtering");
    inventory_cmd
        ->add_option("--duration", inventory_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")->group("Live capture (-i only)")
        ->capture_default_str();
    inventory_cmd->add_option("--snaplen", inventory_snaplen, "Maximum bytes captured per packet with -i")->group("Live capture (-i only)")
        ->capture_default_str();
    inventory_cmd->add_flag(
        "!--no-promiscuous", inventory_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)")->group("Live capture (-i only)");
    inventory_cmd->add_option(
        "-o,--output", inventory_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name")->group("Input/output");
    inventory_cmd
        ->add_option("-T,--format", inventory_format,
                      "Report format: text, json, csv, or stix (csv and stix are both deliberately "
                      "asset-only -- one row/object per device, for CMDB import or a STIX 2.1 "
                      "bundle; use text/json for the full communications/zones/conduits picture)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "csv", "stix"}))
        ->capture_default_str();
    inventory_cmd->add_flag("--strict", inventory_strict,
                             "Abort on the first malformed packet instead of reporting it and continuing")->group("Display options");
    add_resource_limit_options(inventory_cmd, inventory_limit_vars);
    add_inventory_engine_limit_options(inventory_cmd, inventory_max_assets, inventory_max_edges,
                                        inventory_max_tcp_sessions, inventory_max_notable_protocols);
    inventory_cmd
        ->add_option("--zone-prefix", inventory_zone_prefix,
                      "CIDR prefix length ([0, 32]) used to group observed asset IPs into "
                      "inferred zones -- see docs/MANUAL.md's ROADMAP item 17")->group("Zone & conduit output")
        ->capture_default_str()
        ->check(CLI::Range(0, 32));
    inventory_cmd->add_option("--diagram", inventory_diagram_file,
                               "Also write a zone/conduit diagram here (see --diagram-format)")->group("Zone & conduit output");
    inventory_cmd
        ->add_option("--diagram-format", inventory_diagram_format,
                      "Diagram format for --diagram: a Mermaid flowchart or Graphviz DOT")->group("Zone & conduit output")
        ->transform(CLI::IsMember({"mermaid", "dot"}))
        ->capture_default_str();
    inventory_cmd->add_option(
        "--policy-out", inventory_policy_out,
        "Also write the inferred zone/conduit model as a policy YAML file here, directly loadable "
        "by 'policy validate --policy' -- closes the discover-then-enforce loop")->group("Zone & conduit output");
    inventory_cmd->add_option(
        "--acl-out", inventory_acl_out,
        "Also write the inferred zone/conduit model as a firewall ACL DRAFT here (see --acl-format) "
        "-- a starting point for a human to review, never something to deploy as-is")->group("Zone & conduit output");
    inventory_cmd
        ->add_option("--acl-format", inventory_acl_format,
                      "ACL dialect for --acl-out: Cisco IOS/ASA object-group + extended ACL, "
                      "FortiGate 'config firewall' blocks, or Palo Alto PAN-OS 'set' commands")->group("Zone & conduit output")
        ->transform(CLI::IsMember({"cisco", "fortinet", "paloalto"}))
        ->capture_default_str();
    inventory_cmd->add_option(
        "--edges-csv", inventory_edges_csv,
        "Also write the host-to-host communication matrix (report.edges) as a SEPARATE CSV file "
        "here, one row per client/server/protocol/port pair -- --format csv's own CSV is "
        "deliberately asset-only and never includes this")->group("Zone & conduit output");
    inventory_cmd->add_option(
        "--conduits-csv", inventory_conduits_csv,
        "Also write the inferred zone-to-zone conduit summary (report.conduits) as a CSV file "
        "here, one row per (from_zone, to_zone, protocol, port)")->group("Zone & conduit output");
    inventory_cmd->add_flag("--mac-vendor", inventory_mac_vendor,
                             "Enable OUI (MAC vendor) resolution in the report; off by default to "
                             "keep output compact -- see docs/MANUAL.md's OUTPUT FORMATS section. "
                             "(Named --mac-vendor, not --oui, so a single-dash typo errors cleanly "
                             "instead of silently gluing onto -o/--output -- see decode's "
                             "--mac-vendor help text)")->group("Name resolution");
    inventory_cmd->add_flag(
        "--resolve", inventory_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section")->group("Name resolution");
    inventory_cmd
        ->add_option("--hosts", inventory_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    inventory_cmd->add_flag("!--nn", inventory_service_names,
                             "Disable service name resolution (built-in table plus --services) in "
                             "the report, on by default")->group("Name resolution");
    inventory_cmd
        ->add_option("--services", inventory_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- detect ------------------------------------------------------------------
    // Grok gap #4 ("Detection that OT IR teams recognize") -- see detect_engine.hpp's own file
    // header and docs/design/detection-engine.md for the design record.
    auto* detect_cmd = app.add_subcommand(
        "detect", "Detection findings OT incident-response teams recognize: engineering-station "
                   "mode changes, firmware/logic downloads and restarts, protocol misuse, and new "
                   "remote-access channels -- each finding cites a MITRE ATT&CK for ICS technique "
                   "and three independent, labeled dimensions: evidence (how reliably the protocol "
                   "event was observed), novelty (new vs. known), and severity (impact if genuine). "
                   "Never asserts malicious intent. See docs/design/detection-engine.md.");
    std::string detect_input, detect_interface, detect_filter, detect_output;
    int detect_duration = 0;
    int detect_snaplen = 65535;
    bool detect_promiscuous = true;
    std::string detect_format = "text";
    bool detect_strict = false;
    std::string detect_policy_path;
    std::string detect_baseline_file;
    size_t detect_max_baseline_file_bytes = kDefaultMaxBaselineFileBytes;
    bool detect_mac_vendor = false, detect_resolve = false, detect_service_names = true;
    std::string detect_hosts_file, detect_services_file;
    ResourceLimitCliVars detect_limit_vars;
    size_t detect_max_findings = 0, detect_max_tracked_keys_per_map = 0, detect_max_originators_per_server = 0;

    auto* detect_input_opt =
        detect_cmd->add_option("-r,--read", detect_input,
                                "Input capture file (classic pcap or pcapng, auto-detected)")->group("Input/output")
            ->check(CLI::ExistingFile);
    auto* detect_interface_opt = detect_cmd->add_option(
        "-i,--interface", detect_interface,
        "Run detection against live traffic on this network interface instead of reading a file "
        "(see 'conduitscope interfaces'); requires this build to have been compiled with "
        "libpcap/Npcap support -- exactly one of -r/-i is required")->group("Input/output");
    detect_input_opt->excludes(detect_interface_opt);
    detect_interface_opt->excludes(detect_input_opt);
    detect_cmd->add_option("-f,--filter", detect_filter,
                            "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; "
                            "with -r, applied per-packet after reading the file; requires this build to "
                            "have been compiled with libpcap/Npcap support in both cases")->group("Filtering");
    detect_cmd
        ->add_option("--duration", detect_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")->group("Live capture (-i only)")
        ->capture_default_str();
    detect_cmd->add_option("--snaplen", detect_snaplen, "Maximum bytes captured per packet with -i")->group("Live capture (-i only)")
        ->capture_default_str();
    detect_cmd->add_flag(
        "!--no-promiscuous", detect_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is)")->group("Live capture (-i only)");
    detect_cmd->add_option(
        "-o,--output", detect_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name")->group("Input/output");
    detect_cmd
        ->add_option("-T,--format", detect_format,
                     "Report format: text/json (the full report), or cef/leef/syslog (curated "
                     "one-liners, one per finding -- see docs/USER_GUIDE.md's SECURITY EVENT "
                     "EXPORT section)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "cef", "leef", "syslog"}))
        ->capture_default_str();
    detect_cmd->add_flag("--strict", detect_strict,
                          "Abort on the first malformed packet instead of reporting it and continuing")->group("Display options");
    add_resource_limit_options(detect_cmd, detect_limit_vars);
    add_detect_engine_limit_options(detect_cmd, detect_max_findings, detect_max_tracked_keys_per_map,
                                     detect_max_originators_per_server);
    detect_cmd
        ->add_option("--policy", detect_policy_path,
                      "Policy YAML file (see 'policy validate') -- used only to tell a new "
                      "remote-access session that stays within one declared zone (MITRE ATT&CK for "
                      "ICS T0886, Remote Services) from one that crosses a zone boundary (T0822, "
                      "External Remote Services); every other finding is unaffected by this flag")->group("Policy & baseline inputs (optional)")
        ->check(CLI::ExistingFile);
    detect_cmd
        ->add_option("--baseline-file", detect_baseline_file,
                      "Baseline JSON file (see 'baseline learn') -- used to resolve every "
                      "new-vs-known finding's novelty (a new remote-access channel, a new CIP "
                      "originator) against real history instead of this capture's own "
                      "first-occurrence order. A conduit already present in the baseline is not "
                      "flagged at all; one genuinely absent gets novelty 'Confirmed New'. Without "
                      "this flag, a new-vs-known finding gets novelty 'First Occurrence' (first "
                      "occurrence within this capture only) -- either way, the finding's own "
                      "evidence and severity are unaffected by this flag")->group("Policy & baseline inputs (optional)")
        ->check(CLI::ExistingFile);
    detect_cmd
        ->add_option("--max-baseline-file-bytes", detect_max_baseline_file_bytes,
                      "Cap how large --baseline-file may be before it's read into memory (default "
                      "256 MiB)")->group("Policy & baseline inputs (optional)")
        ->capture_default_str();
    detect_cmd->add_flag("--mac-vendor", detect_mac_vendor,
                          "Enable OUI (MAC vendor) resolution in the report; off by default")->group("Name resolution");
    detect_cmd->add_flag(
        "--resolve", detect_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the "
        "report; off by default; NEVER performs live DNS")->group("Name resolution");
    detect_cmd
        ->add_option("--hosts", detect_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    detect_cmd->add_flag("!--nn", detect_service_names,
                          "Disable service name resolution (built-in table plus --services) in "
                          "the report, on by default")->group("Name resolution");
    detect_cmd
        ->add_option("--services", detect_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- baseline learn / baseline check ---------------------------------------
    // ICS communication-baseline analysis at the protocol-operation level (roadmap item 41,
    // docs/DEVELOPMENT.md; full design and rationale at docs/design/baseline-engine.md). Mirrors
    // `policy`'s own group-plus-sub-subcommand shape (`policy_cmd`/`policy_validate_cmd` above),
    // just with two sub-subcommands instead of one -- see baseline.hpp's own file header for why
    // `learn`/`check` are deliberately separate commands rather than one auto-detected mode.
    auto* baseline_cmd = app.add_subcommand(
        "baseline", "ICS communication-baseline analysis at the protocol-operation level "
                     "(S7comm, Modbus, EtherNet/IP, DNP3, BACnet, OPC UA, MELSEC, FINS, IEC 104) -- "
                     "learn what operations/address ranges are normally seen on a conduit, then "
                     "check a capture against that baseline");

    auto* baseline_learn_cmd = baseline_cmd->add_subcommand(
        "learn", "Absorb every capture's own operations into a baseline file, "
                  "creating it if it doesn't exist yet. Never flags anything as anomalous -- "
                  "running this against N captures over N days is how a real baseline is built. "
                  "Only ever learn from captures already trusted to be clean: this absorbs "
                  "whatever a capture contains with no judgment at all, so a malicious operation "
                  "in a 'learned' capture becomes baselined as normal");
    std::string baseline_learn_file;
    std::vector<std::string> baseline_learn_inputs;
    bool baseline_learn_strict = false;
    ResourceLimitCliVars baseline_learn_limit_vars;
    size_t baseline_learn_max_file_bytes = 0;
    size_t baseline_learn_max_tcp_sessions = 0, baseline_learn_max_conduits = 0,
           baseline_learn_max_operations_per_conduit = 0, baseline_learn_max_ranges_per_operation = 0;
    baseline_learn_cmd
        ->add_option("--baseline-file", baseline_learn_file,
                      "Baseline JSON file to read (if it exists) and write back. Required")->group("Input/output")
        ->required();
    baseline_learn_cmd
        ->add_option("--max-baseline-file-bytes", baseline_learn_max_file_bytes,
                      "Cap how large --baseline-file may be before it's read into memory (default "
                      "256 MiB). 0 = leave it at its own default; a baseline file this large "
                      "genuinely being legitimate is essentially always a sign something else is "
                      "wrong (see docs/DEVELOPMENT.md's security review write-up)")->group("Input/output")
        ->capture_default_str();
    add_baseline_engine_limit_options(baseline_learn_cmd, baseline_learn_max_tcp_sessions,
                                        baseline_learn_max_conduits, baseline_learn_max_operations_per_conduit,
                                        baseline_learn_max_ranges_per_operation);
    baseline_learn_cmd
        ->add_option("-r,--read,captures", baseline_learn_inputs,
                      "One or more pcap/pcapng capture files to learn from, in order (classic "
                      "pcap or pcapng, auto-detected) -- repeatable (-r a.pcap -r b.pcap) or "
                      "positional (a.pcap b.pcap), matching every other file-reading subcommand's "
                      "own -r/--read spelling")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    baseline_learn_cmd->add_flag("--strict", baseline_learn_strict,
                                  "Abort on the first malformed packet instead of warning and continuing")->group("Display options");
    add_resource_limit_options(baseline_learn_cmd, baseline_learn_limit_vars);

    auto* baseline_check_cmd = baseline_cmd->add_subcommand(
        "check", "Compare one capture's own operations against an existing baseline "
                  "file (read-only -- never writes it) and report every operation the baseline "
                  "doesn't already cover. Non-zero exit code on any finding -- see EXIT STATUS -- "
                  "for CI/cron use");
    std::string baseline_check_file, baseline_check_input, baseline_check_output, baseline_check_policy_file;
    std::string baseline_check_format = "text";
    bool baseline_check_strict = false;
    bool baseline_check_symbolic_addresses = false;
    ResourceLimitCliVars baseline_check_limit_vars;
    size_t baseline_check_max_file_bytes = 0;
    size_t baseline_check_max_tcp_sessions = 0, baseline_check_max_conduits = 0,
           baseline_check_max_operations_per_conduit = 0, baseline_check_max_ranges_per_operation = 0;
    baseline_check_cmd
        ->add_option("--baseline-file", baseline_check_file, "Baseline JSON file to check against. Required")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    baseline_check_cmd
        ->add_option("--max-baseline-file-bytes", baseline_check_max_file_bytes,
                      "Cap how large --baseline-file may be before it's read into memory (default "
                      "256 MiB). 0 = leave it at its own default; a baseline file this large "
                      "genuinely being legitimate is essentially always a sign something else is "
                      "wrong (see docs/DEVELOPMENT.md's security review write-up)")->group("Input/output")
        ->capture_default_str();
    add_baseline_engine_limit_options(baseline_check_cmd, baseline_check_max_tcp_sessions,
                                        baseline_check_max_conduits, baseline_check_max_operations_per_conduit,
                                        baseline_check_max_ranges_per_operation);
    baseline_check_cmd
        ->add_option("-r,--read,capture", baseline_check_input,
                      "The pcap/pcapng capture file to check (classic pcap or pcapng, "
                      "auto-detected) -- -r/--read or positional, matching every other "
                      "file-reading subcommand's own -r/--read spelling")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    baseline_check_cmd->add_option(
        "-o,--output", baseline_check_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name")->group("Input/output");
    baseline_check_cmd
        ->add_option("-T,--format", baseline_check_format,
                     "Report format: text/json (the full report), or cef/leef/syslog (curated "
                     "one-liners, one per finding -- see docs/USER_GUIDE.md's SECURITY EVENT "
                     "EXPORT section)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "cef", "leef", "syslog"}))
        ->capture_default_str();
    baseline_check_cmd->add_flag("--strict", baseline_check_strict,
                                  "Abort on the first malformed packet instead of warning and continuing")->group("Display options");
    baseline_check_cmd->add_flag(
        "--symbolic-addresses", baseline_check_symbolic_addresses,
        "Also render S7comm ranges in Step7 byte/word/bit notation (e.g. \"MB10-MB19\", \"M10.3\") "
        "alongside the existing raw numeric range_start/range_end fields, for NewTargetRange "
        "findings. Default off -- output is unchanged unless this is passed. No effect on any "
        "other protocol's findings")->group("Display options");
    baseline_check_cmd
        ->add_option("--policy", baseline_check_policy_file,
                      "Zone/conduit policy file (same format and option name as 'policy validate --policy' "
                      "-- see docs/MANUAL.md's POLICY FILE FORMAT section). Optional; omitted by default. "
                      "When given, a conduit with NO exact baseline match whose client IP resolves to a "
                      "declared zone, where at least one OTHER client IP already baselined against the same "
                      "server/protocol/port and ALSO in that zone already has this exact operation baselined "
                      "(range-covered too, when the operation has one), is reported as new-conduit-known-zone "
                      "instead of plain new-conduit -- a known zone never vouches for an operation nobody in "
                      "it has actually done, so this stays new-conduit whenever there is no such precedent, "
                      "even with --policy given. Leaves 'baseline learn' and every 'baseline check' run "
                      "without this flag completely unchanged -- zones are resolved fresh from the policy "
                      "file at check time only, never persisted into the baseline file itself, so swapping "
                      "in an updated policy later needs no re-learn")->group("Policy & baseline inputs (optional)")
        ->check(CLI::ExistingFile);
    add_resource_limit_options(baseline_check_cmd, baseline_check_limit_vars);

    // --- capture --------------------------------------------------------------
    // Continuous, safe sensor mode (Grok review item 5, docs/reviews/2026-09-grok-ics-ot-
    // improvement-areas.md; full design record at docs/design/sensor-mode.md). Deliberately its
    // own subcommand, separate from `decode -i -w` (which already writes a live capture to a
    // single ever-growing file, but never rotates it and always fully decodes+prints every packet
    // too, wasted overhead for an unattended run nobody is watching): `capture` skips decode
    // entirely and writes ONLY rotated, retention-bounded classic-pcap files -- see
    // rotating_pcap_writer.hpp's own file header. Live-interface-only (-i/--interface is
    // ->required() below, no -r/--read at all) -- rotating an already-finite offline file has no
    // "does not fill the disk over weeks" problem to solve in the first place; validate rotation
    // policy logic offline instead via tools/rotating_pcap_writer_selftest.cpp. NEVER transmits
    // any packet onto the wire or the process network -- this subcommand, like `decode`'s own -w,
    // only ever writes to a local file; see docs/design/sensor-mode.md for how that assurance was
    // confirmed (no send/inject capability exists anywhere in this codebase).
    auto* capture_cmd = app.add_subcommand(
        "capture", "Continuous, disk-bounded live packet capture to rotated classic-pcap files -- "
                    "no decoding, no analysis, never transmits. Meant to run unattended for weeks "
                    "on a SPAN/TAP collector; analyze the rotated files afterward with 'decode'/"
                    "'inventory'/'detect'/'baseline' as a separate pass, same as any offline "
                    "capture. One tap point (interface) per process -- for a multi-tap site, run "
                    "one independent 'capture' process per tap point, each with its own --directory, "
                    "then combine their own separate analysis passes' reports afterward");
    std::string capture_interface;
    std::string capture_filter;
    int capture_duration = 0;
    int capture_snaplen = 65535;
    bool capture_promiscuous = true;
    size_t capture_max_packets = 0;
    std::string capture_directory = ".";
    std::string capture_prefix;
    size_t capture_rotate_bytes = 0;
    size_t capture_rotate_seconds = 0;
    size_t capture_max_total_bytes = 0;
    size_t capture_max_files = 0;

    capture_cmd
        ->add_option("-i,--interface", capture_interface,
                      "Capture live from this network interface (see 'conduitscope interfaces'); "
                      "requires this build to have been compiled with libpcap/Npcap support. "
                      "Required -- unlike 'decode'/'policy validate'/'inventory', 'capture' has no "
                      "-r/--read offline-file mode at all (see this subcommand's own --help header)")->group("Input/output")
        ->required();
    capture_cmd->add_option("-f,--filter", capture_filter,
                             "BPF filter (tcpdump syntax), applied by libpcap at capture time -- "
                             "same syntax and meaning as 'decode'/'policy validate'/'inventory''s "
                             "own -f")->group("Filtering");
    capture_cmd->add_option("-a,--duration", capture_duration,
                             "Stop after this many seconds (0 = unlimited; stop with Ctrl+C or "
                             "--max-packets instead)")->group("Live capture (-i only)")
        ->capture_default_str();
    capture_cmd->add_option("--snaplen", capture_snaplen, "Maximum bytes captured per packet")->group("Live capture (-i only)")
        ->capture_default_str();
    capture_cmd->add_flag("!--no-promiscuous", capture_promiscuous,
                           "Don't put the interface into promiscuous mode (by default it is, since "
                           "the main use case -- watching a mirrored/SPAN switch port -- needs "
                           "traffic not addressed to this host)")->group("Live capture (-i only)");
    capture_cmd->add_option("-c,--max-packets", capture_max_packets,
                             "Stop after capturing this many packets total, across every rotated "
                             "file (0 = unlimited, the default -- the normal setting for a "
                             "long-running sensor; a nonzero value is mainly useful for a bounded "
                             "test/smoke run)")->group("Input/output")
        ->capture_default_str();
    capture_cmd
        ->add_option("-d,--directory", capture_directory,
                      "Directory to write rotated capture files into. Must already exist -- this "
                      "subcommand never creates it")->group("Capture rotation")
        ->capture_default_str()
        ->check(CLI::ExistingDirectory);
    capture_cmd->add_option(
        "--prefix", capture_prefix,
        "Filename prefix for every rotated file (default: -i/--interface's own name, sanitized -- "
        "see this subcommand's own --help header). Useful to give a shorter/friendlier name than "
        "a raw platform interface identifier, especially on Windows/Npcap where interface names "
        "can be long GUID-style strings")->group("Capture rotation");
    capture_cmd
        ->add_option("--rotate-bytes", capture_rotate_bytes,
                      "Rotate to a new file once the current one reaches roughly this many bytes "
                      "(0 = no size-based rotation, the default). See rotating_pcap_writer.hpp's "
                      "own RotationPolicy::rotate_bytes for the exact boundary behavior")->group("Capture rotation")
        ->capture_default_str();
    capture_cmd
        ->add_option("--rotate-seconds", capture_rotate_seconds,
                      "Rotate to a new file once a captured packet's own timestamp is at least this "
                      "many seconds past the current file's first packet (0 = no time-based "
                      "rotation, the default). Checked against each packet's own capture timestamp, "
                      "not wall-clock -- see rotating_pcap_writer.hpp's own RotationPolicy::"
                      "rotate_seconds for why")->group("Capture rotation")
        ->capture_default_str();
    capture_cmd
        ->add_option("--max-total-bytes", capture_max_total_bytes,
                      "Delete the oldest already-rotated file(s) so the combined size of every "
                      "rotated file this run still has on disk (never counting the file currently "
                      "being written, which is never deleted) stays at or under this many bytes "
                      "(0 = no size-based retention cap, the default). Requires --rotate-bytes "
                      "and/or --rotate-seconds to be set too -- with no rotation there is only ever "
                      "one file, which is always the active file, and the active file is never "
                      "deleted, so this could never actually bound disk use on its own")->group("Capture rotation")
        ->capture_default_str();
    capture_cmd
        ->add_option("--max-files", capture_max_files,
                      "Delete the oldest already-rotated file(s) so this run has at most this many "
                      "files on disk IN TOTAL, counting the file currently being written (0 = no "
                      "count-based retention cap, the default). Same --rotate-bytes/--rotate-seconds "
                      "requirement as --max-total-bytes above")->group("Capture rotation")
        ->capture_default_str();

    // --- merge ------------------------------------------------------------
    // The "stitch multiple tap points into one site-wide matrix" half of Grok review item 5 --
    // see inventory_merge.hpp's own file header for the full design and scope. A group subcommand
    // with one sub-subcommand so far ('inventory'), mirroring `baseline`'s own group-plus-sub-
    // subcommand shape -- merging a site's `policy validate`/`detect`/`baseline` reports is each a
    // reasonable, structurally different follow-up, not attempted in this pass (see
    // inventory_merge.hpp's own file header for exactly why each is a different problem).
    auto* merge_cmd = app.add_subcommand(
        "merge", "Combine reports from multiple independent tap points into one site-wide view. "
                  "Currently only 'inventory' exists -- merging policy/detect/baseline reports "
                  "across tap points is a reasonable follow-up, not built yet");
    auto* merge_inventory_cmd = merge_cmd->add_subcommand(
        "inventory", "Combine N 'inventory --format json' reports (one per tap point) into one "
                      "site-wide asset/communications/zone/conduit matrix -- see this codebase's "
                      "own inventory_merge.hpp for exactly how assets/edges are unioned and why "
                      "zones/conduits are always freshly re-derived from the merged result rather "
                      "than merged themselves");
    std::vector<std::string> merge_inventory_inputs;
    std::string merge_inventory_output, merge_inventory_format = "text";
    int merge_inventory_zone_prefix = kDefaultInventoryZonePrefixLen;
    bool merge_inventory_mac_vendor = false, merge_inventory_resolve = false, merge_inventory_service_names = true;
    std::string merge_inventory_hosts_file, merge_inventory_services_file;
    size_t merge_inventory_max_file_bytes = kDefaultMaxInventoryFileBytes;
    merge_inventory_cmd
        ->add_option("reports", merge_inventory_inputs,
                      "One or more 'inventory --format json' report files, one per tap point "
                      "(merging just one is also legal -- e.g. to re-derive zones at a different "
                      "--zone-prefix)")->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    merge_inventory_cmd
        ->add_option("--max-inventory-file-bytes", merge_inventory_max_file_bytes,
                      "Cap how large any one input report file may be before it's read into memory "
                      "(default 256 MiB) -- same shape as --max-baseline-file-bytes; see "
                      "inventory_merge.hpp's kDefaultMaxInventoryFileBytes comment")->group("Input/output")
        ->capture_default_str();
    merge_inventory_cmd->add_option(
        "-o,--output", merge_inventory_output,
        "Write the merged report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name")->group("Input/output");
    merge_inventory_cmd
        ->add_option("-T,--format", merge_inventory_format,
                      "Merged report format: text, json, or csv (csv is deliberately asset-only, "
                      "same as 'inventory --format csv' -- see write_inventory_report_csv's own "
                      "doc comment)")->group("Output format")
        ->transform(CLI::IsMember({"text", "json", "csv"}))
        ->capture_default_str();
    merge_inventory_cmd
        ->add_option("--zone-prefix", merge_inventory_zone_prefix,
                      "CIDR prefix length ([0, 32]) used to group the MERGED asset list into "
                      "zones -- independent of whatever --zone-prefix, if any, each individual "
                      "input report was itself generated with; zones/conduits are always freshly "
                      "re-derived from the merged assets/edges, never merged from the inputs' own "
                      "zones/conduits arrays (which are ignored entirely -- see inventory_merge.hpp)")->group("Zone & conduit output")
        ->capture_default_str()
        ->check(CLI::Range(0, 32));
    merge_inventory_cmd->add_flag("--mac-vendor", merge_inventory_mac_vendor,
                                   "Enable OUI (MAC vendor) resolution in the merged report; off by "
                                   "default, same as 'inventory' itself")->group("Name resolution");
    merge_inventory_cmd->add_flag(
        "--resolve", merge_inventory_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the merged "
        "report; off by default; NEVER performs live DNS")->group("Name resolution");
    merge_inventory_cmd
        ->add_option("--hosts", merge_inventory_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    merge_inventory_cmd->add_flag("!--nn", merge_inventory_service_names,
                                   "Disable service name resolution (built-in table plus --services) "
                                   "in the merged report, on by default")->group("Name resolution");
    merge_inventory_cmd
        ->add_option("--services", merge_inventory_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- evidence -------------------------------------------------------------
    // Jurgen's direct request: an audit-binder-ready "evidence pack" produced from one command --
    // see evidence_report.hpp's own file header for the full design record. Offline captures only
    // (no -i/--interface -- see run_evidence's own comment for why), and deliberately no --filter:
    // an audit evidence pack should reflect the whole capture, not a filtered subset of it.
    auto* evidence_cmd = app.add_subcommand(
        "evidence",
        "Produce an audit-binder-ready evidence pack from one command: the observed zone/conduit "
        "topology (reuses 'inventory'), policy compliance mapped to IEC 62443 FR5 (Restricted Data "
        "Flow)/NIS2 segmentation evidence (reuses 'policy validate', if --policy is given), "
        "detection findings with their own FR mapping (reuses 'detect'), an optional baseline "
        "check (reuses 'baseline check', if --baseline-file is given), an optional NERC CIP-007 "
        "R4/CIP-015-style monitoring-coverage note, and a reproducible integrity record (tool "
        "version, capture/policy file SHA-256 hashes, an optional HMAC-SHA256 signature). Every "
        "framework mapping is this tool's own interpretive cross-reference, never an official "
        "conformance/compliance determination -- see this report's own SCOPE & HONESTY NOTE "
        "section, and docs/USER_GUIDE.md's 'evidence' section for the full design rationale.");
    std::string evidence_input, evidence_policy_file, evidence_baseline_file, evidence_sl_target,
        evidence_sign_key, evidence_output, evidence_format = "text";
    bool evidence_cip_monitoring_window = false, evidence_strict = false;
    int evidence_zone_prefix = static_cast<int>(kDefaultInventoryZonePrefixLen);
    bool evidence_mac_vendor = false, evidence_resolve = false, evidence_service_names = true;
    std::string evidence_hosts_file, evidence_services_file;
    evidence_cmd->add_option("-r,--read", evidence_input, "Input capture file (classic pcap or pcapng, auto-detected)")
        ->group("Input/output")
        ->required()
        ->check(CLI::ExistingFile);
    evidence_cmd
        ->add_option("--policy", evidence_policy_file,
                      "Zone/conduit policy file -- when given, adds the Policy Compliance / FR5 / "
                      "NIS2 section (Section 2) with a real compliance verdict; when omitted, that "
                      "section says plainly that no policy was supplied, rather than being silently "
                      "left out")->group("Input/output")
        ->check(CLI::ExistingFile);
    evidence_cmd
        ->add_option("--baseline-file", evidence_baseline_file,
                      "Baseline file (from 'baseline learn') -- when given, adds the Baseline "
                      "Anomalies section (Section 4) and also feeds 'detect's own new-vs-known "
                      "novelty determination")->group("Input/output")
        ->check(CLI::ExistingFile);
    evidence_cmd->add_option(
        "--sl-target", evidence_sl_target,
        "An operator-declared IEC 62443-3-2 Security Level target (e.g. 'SL2'), echoed verbatim "
        "into the report for audit cross-referencing -- NEVER computed by this tool from traffic; "
        "SL-T is an organizational risk-assessment output, something a passive-monitoring tool has "
        "no basis to infer. Omit to have the report say plainly that none was supplied")->group("Input/output");
    evidence_cmd->add_flag(
        "--cip-monitoring-window", evidence_cip_monitoring_window,
        "Also include a NERC CIP-007 R4 / CIP-015-style 'monitoring coverage' section: this "
        "capture's own time window, packet count, and largest inter-packet gap -- explicitly "
        "caveated as coverage of this capture file only, never proof of continuous monitoring "
        "infrastructure uptime. Off by default (CIP applies only to the North American bulk "
        "electric system; most captures have no reason to carry this section)")->group("Input/output");
    evidence_cmd
        ->add_option("--sign-key", evidence_sign_key,
                      "HMAC-SHA256-sign the report with this key file's raw bytes -- the report's "
                      "own Integrity section then includes a hex signature and a one-line recipe "
                      "to independently verify it. Omit to leave the report unsigned (its "
                      "Integrity section says so explicitly); there is no PKI/certificate "
                      "mechanism here, only a shared-key HMAC stamp")->group("Input/output")
        ->check(CLI::ExistingFile);
    evidence_cmd->add_option("-o,--output", evidence_output,
                              "Write the report here instead of stdout. Caution: a single-dash "
                              "long-option typo glues onto this flag -- always use the double dash "
                              "for a long option name")->group("Input/output");
    evidence_cmd
        ->add_option("-T,--format", evidence_format, "Report format: text or json")->group("Output format")
        ->transform(CLI::IsMember({"text", "json"}))
        ->capture_default_str();
    evidence_cmd->add_flag("--strict", evidence_strict,
                            "Abort on the first malformed packet instead of reporting it and "
                            "continuing")->group("Display options");
    evidence_cmd
        ->add_option("--zone-prefix", evidence_zone_prefix,
                      "CIDR prefix length ([0, 32]) used to group observed asset IPs into inferred "
                      "zones for Section 1's topology -- see docs/MANUAL.md's ROADMAP item 17")->group("Display options")
        ->capture_default_str()
        ->check(CLI::Range(0, 32));
    evidence_cmd->add_flag("--mac-vendor", evidence_mac_vendor,
                            "Enable OUI (MAC vendor) resolution in the embedded sub-reports")->group("Name resolution");
    evidence_cmd->add_flag(
        "--resolve", evidence_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts); NEVER "
        "performs live DNS -- file-only")->group("Name resolution");
    evidence_cmd
        ->add_option("--hosts", evidence_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")->group("Name resolution")
        ->check(CLI::ExistingFile);
    evidence_cmd->add_flag("!--nn", evidence_service_names,
                            "Disable service name resolution (built-in table plus --services), on "
                            "by default")->group("Name resolution");
    evidence_cmd
        ->add_option("--services", evidence_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")->group("Name resolution")
        ->check(CLI::ExistingFile);

    // --- version ------------------------------------------------------------
    app.add_subcommand("version", "Print version and build information");

    // A bare invocation -- no arguments at all -- prints the top-level --help and exits cleanly,
    // rather than falling into ROADMAP item 109's own default-subcommand behavior just below
    // (which would inject `decode` and then immediately fail with decode's own "needs exactly
    // one of -r/--read or -i/--interface" error). That error is the right one for e.g.
    // `conduitscope -r FILE` -- there IS something on the line for `decode` to act on, just
    // missing a required option -- but it's a confusing first impression for anyone who ran the
    // bare executable with nothing else typed (including, on Windows, simply double-clicking
    // conduitscope.exe from Explorer) expecting to see what the tool does, not an error about a
    // subcommand they never typed at all. `argc == 1` (program name only, no other tokens) is
    // deliberately the exact and only case this short-circuits -- `conduitscope -q` or any other
    // explicit flag with no subcommand still falls through to item 109's default exactly as
    // before, since the operator did type something and decode's own error remains the correct,
    // specific diagnosis there.
    if (argc == 1) {
        std::cout << app.help();
        return 0;
    }

    // --decode/--info/--interfaces/--policy/--inventory/--detect/--baseline/--capture/--merge:
    // every subcommand above is also selectable via a double-dashed flag of its own name -- see
    // rewrite_subcommand_alias's own comment for why this is a pre-parse argv rewrite rather than
    // a CLI11 option.
    //
    // ROADMAP item 109: when that leaves argv with no subcommand at all (rewrite_subcommand_alias
    // returns non-negative rather than -1), inject_default_subcommand picks `decode` or `info`
    // (see its own comment) and builds a replacement argv with that word inserted -- owned by
    // default_subcommand_storage/default_subcommand_argv, which must outlive the CLI11_PARSE call
    // just below, hence declared here rather than inside either function. parse_argc/parse_argv
    // point at the replacement only when one was actually built; otherwise they're just the
    // original argc/argv, unchanged, exactly as before item 109 existed.
    int subcommand_candidate_start = rewrite_subcommand_alias(argc, argv);
    std::vector<std::string> default_subcommand_storage;
    std::vector<char*> default_subcommand_argv;
    int parse_argc = argc;
    char** parse_argv = argv;
    if (subcommand_candidate_start >= 0) {
        inject_default_subcommand(argc, argv, subcommand_candidate_start, default_subcommand_storage,
                                   default_subcommand_argv);
        parse_argc = static_cast<int>(default_subcommand_argv.size());
        parse_argv = default_subcommand_argv.data();
    }

    CLI11_PARSE(app, parse_argc, parse_argv);

    // -r/-i are mutually exclusive (enforced above via ->excludes()) but neither is individually
    // ->required(), since exactly which one is required depends on the other -- CLI11 has no
    // built-in "exactly one of these two plain options" validator, so it's checked by hand here,
    // once parsing has otherwise succeeded, with a message that names both flags.
    if (decode_cmd->parsed() && decode_input.empty() == decode_interface.empty()) {
        std::cerr << "error: 'decode' needs exactly one of -r/--read (an offline capture file) or "
                     "-i/--interface (a live capture interface)\n";
        return 1;
    }
    if (policy_validate_cmd->parsed() && policy_input.empty() == policy_interface.empty()) {
        std::cerr << "error: 'policy validate' needs exactly one of -r/--read (an offline capture "
                     "file) or -i/--interface (a live capture interface)\n";
        return 1;
    }
    if (inventory_cmd->parsed() && inventory_input.empty() == inventory_interface.empty()) {
        std::cerr << "error: 'inventory' needs exactly one of -r/--read (an offline capture file) "
                     "or -i/--interface (a live capture interface)\n";
        return 1;
    }
    // Same rule RotatingPcapWriter's own constructor (rotating_pcap_writer.hpp) enforces -- checked
    // again here, before this process ever opens the capture interface, so a bad flag combination
    // is reported immediately rather than after already needing (and possibly failing to get)
    // capture privilege.
    if (capture_cmd->parsed() && (capture_max_total_bytes != 0 || capture_max_files != 0) &&
        capture_rotate_bytes == 0 && capture_rotate_seconds == 0) {
        std::cerr << "error: 'capture' --max-total-bytes/--max-files requires --rotate-bytes "
                     "and/or --rotate-seconds to be set too (see 'capture --help')\n";
        return 1;
    }

    std::ofstream log_stream;
    std::ostream* diag = &std::cerr;
    if (!log_file.empty()) {
        log_stream.open(log_file, std::ios::app);
        if (!log_stream) {
            std::cerr << "error: cannot open log file '" << log_file << "'\n";
            return 1;
        }
        diag = &log_stream;
    }

    if (decode_cmd->parsed()) {
        // --oui implies --ether: without it there'd be no eth line to attach a vendor name to.
        // --ether alone (no --oui) shows the MAC pair with no vendor annotation.
        decode_show_mac = decode_show_mac || decode_mac_vendor;

        // -d/--decode-as: resolve every raw rule now, before run_decode -- Group A rules widen
        // the same CLI-local --x-port vectors run_decode is about to convert into
        // DecodeOptions::extra_X_ports below (so this MUST run before that conversion happens,
        // i.e. before run_decode is called at all, not inside it); Group B/C rules become the
        // DecodeAsRule list passed straight through into DecodeOptions::decode_as. See
        // parse_decode_as_rules's own comment above for the full design.
        std::vector<DecodeAsGroupATarget> decode_as_group_a = {
            {"dns", false, &decode_dns_ports},
            {"mdns", false, &decode_mdns_ports},
            {"llmnr", false, &decode_llmnr_ports},
            {"nbns", false, &decode_nbns_ports},
            {"doh", true, &decode_doh_ports},
            {"rip", false, &decode_rip_ports},
            {"hsrp", false, &decode_hsrp_ports},
            {"winrm", true, &decode_winrm_ports},
            {"dcom", true, &decode_dcom_ports},
            {"ge-srtp", true, &decode_ge_srtp_ports},
            {"bsap", false, &decode_bsap_ports},
            {"coap", false, &decode_coap_ports},
            {"rmcp", false, &decode_rmcp_ports},
            {"amqp", true, &decode_amqp_ports},
            {"dicom", true, &decode_dicom_ports},
            {"fox", true, &decode_fox_ports},
            {"powerlink-sdo", false, &decode_powerlink_sdo_ports},
            {"dhcpv6", false, &decode_dhcpv6_ports},
        };
        std::vector<DecodeAsRule> decode_as_rules;
        if (!parse_decode_as_rules(decode_as_raw, decode_as_group_a, &decode_as_rules)) {
            return 1;
        }

        // Compiled once, before any packet is read, the same fail-fast-before-the-loop posture as
        // parse_decode_as_rules above -- see display_filter.hpp's own compile_display_filter comment.
        std::optional<CompiledDisplayFilter> decode_display_filter_compiled;
        if (!decode_display_filter.empty()) {
            // '@<path>' reads the actual expression from a file instead of the command line. Not
            // just a convenience: on Windows, CreateProcess's own ~32767-character total
            // command-line length limit makes a multi-kilobyte -Y expression impossible to pass as
            // a literal argv entry at all -- this is exactly how CTest's own decode_display_filter_
            // error_expression_too_long regression test, which deliberately exercises a 65537-byte
            // expression to exercise kMaxExpressionLength, invokes this flag (see CMakeLists.txt).
            // A single leading '@' is unambiguous: every real display-filter field reference is a
            // bare identifier/keyword (e.g. 'modbus.func_code'), never a '@'-prefixed token, so this
            // can never collide with a real filter expression.
            if (decode_display_filter.front() == '@') {
                const std::string display_filter_path = decode_display_filter.substr(1);
                std::ifstream display_filter_file(display_filter_path, std::ios::binary);
                if (!display_filter_file) {
                    std::cerr << "error: cannot open display filter file '" << display_filter_path
                               << "' for reading\n";
                    return 1;
                }
                std::ostringstream display_filter_buf;
                display_filter_buf << display_filter_file.rdbuf();
                decode_display_filter = display_filter_buf.str();
                // Trim exactly one trailing line ending -- near-universal in a file written by an
                // editor or a shell redirection -- so the expression's own length/content checks
                // (and any error message that echoes it back) see exactly what the author meant,
                // not one incidental extra byte they almost certainly never intended as part of the
                // filter itself.
                if (!decode_display_filter.empty() && decode_display_filter.back() == '\n') {
                    decode_display_filter.pop_back();
                    if (!decode_display_filter.empty() && decode_display_filter.back() == '\r') {
                        decode_display_filter.pop_back();
                    }
                }
            }
            std::string display_filter_error;
            decode_display_filter_compiled = compile_display_filter(decode_display_filter, &display_filter_error);
            if (!decode_display_filter_compiled) {
                std::cerr << display_filter_error;
                return 1;
            }
        }

        return run_decode(decode_input, decode_interface, decode_filter, decode_duration, decode_snaplen,
                           decode_promiscuous, decode_output, decode_format, decode_protocol,
                           decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
                           decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
                           decode_kerberos_ports, decode_ldap_ports, decode_smb_ports,
                           decode_melsec_ports, decode_fins_ports,
                           decode_bgp_ports,
                           decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports,
                           decode_mdns_ports, decode_llmnr_ports, decode_nbns_ports, decode_doh_ports,
                           decode_rip_ports, decode_hsrp_ports, decode_remote_access_ports,
                           decode_lateral_movement_ports, decode_enterprise_trust_ports,
                           decode_wireless_backhaul_ports, decode_tunnel_vpn_ports,
                           decode_winrm_ports, decode_dcom_ports, decode_ge_srtp_ports,
                           decode_bsap_ports, decode_cclink_ie_ports, decode_codesys_ports,
                           decode_coap_ports,
                           decode_rmcp_ports,
                           decode_amqp_ports,
                           decode_dicom_ports,
                           decode_fox_ports,
                           decode_powerlink_sdo_ports,
                           decode_dhcpv6_ports,
                           decode_as_rules,
                           decode_flood_threshold,
                           decode_max_packets, decode_range, decode_limit_vars, decode_strict,
                           quiet,
                           no_color, force_color, decode_mac_vendor, decode_resolve, decode_hosts_file,
                           decode_service_names, decode_services_file, decode_show_vlan,
                           decode_time_format, decode_time_offset, *diag, decode_show_direction,
                           decode_show_mac, decode_fields, decode_write, decode_hex,
                           decode_verbose, decode_details, decode_redact, decode_detect_highlight,
                           decode_display_filter_compiled);
    }
    if (info_cmd->parsed()) {
        return run_info(info_input, std::cout, info_stat_values, info_max_conversations, info_max_endpoints,
                         info_max_follow_bytes);
    }
    if (interfaces_cmd->parsed()) {
        return run_interfaces(std::cout);
    }
    if (policy_validate_cmd->parsed()) {
        return run_policy_validate(policy_input, policy_interface, policy_filter, policy_duration, policy_snaplen,
                                    policy_promiscuous, policy_file, policy_output, policy_format, policy_strict,
                                    policy_strict_it_protocols, policy_summarize_unclassified, quiet,
                                    policy_limit_vars,
                                    resolve_policy_engine_limits(policy_max_tcp_flows, policy_max_udp_flows,
                                                                  policy_max_ethernet_flows,
                                                                  policy_max_notable_protocols),
                                    policy_mac_vendor, policy_resolve, policy_hosts_file,
                                    policy_service_names, policy_services_file, *diag);
    }
    if (policy_cmd->parsed()) {
        std::cerr << "error: 'policy' needs a subcommand (currently only 'validate' exists)\n";
        return 1;
    }
    if (inventory_cmd->parsed()) {
        return run_inventory(inventory_input, inventory_interface, inventory_filter, inventory_duration,
                              inventory_snaplen, inventory_promiscuous, inventory_output, inventory_format,
                              inventory_strict, quiet, static_cast<uint8_t>(inventory_zone_prefix),
                              inventory_diagram_file, inventory_diagram_format, inventory_policy_out,
                              inventory_acl_out, inventory_acl_format,
                              inventory_edges_csv, inventory_conduits_csv,
                              inventory_limit_vars,
                              resolve_inventory_engine_limits(inventory_max_assets, inventory_max_edges,
                                                               inventory_max_tcp_sessions,
                                                               inventory_max_notable_protocols),
                              inventory_mac_vendor, inventory_resolve, inventory_hosts_file, inventory_service_names,
                              inventory_services_file, *diag);
    }
    if (detect_cmd->parsed()) {
        return run_detect(detect_input, detect_interface, detect_filter, detect_duration, detect_snaplen,
                           detect_promiscuous, detect_output, detect_format, detect_strict, quiet,
                           detect_policy_path, detect_baseline_file, detect_max_baseline_file_bytes,
                           detect_limit_vars,
                           resolve_detect_engine_limits(detect_max_findings, detect_max_tracked_keys_per_map,
                                                         detect_max_originators_per_server),
                           detect_mac_vendor, detect_resolve, detect_hosts_file, detect_service_names,
                           detect_services_file, *diag);
    }
    if (baseline_learn_cmd->parsed()) {
        return run_baseline_learn(baseline_learn_inputs, baseline_learn_file, baseline_learn_strict, quiet,
                                   baseline_learn_limit_vars,
                                   baseline_learn_max_file_bytes != 0 ? baseline_learn_max_file_bytes
                                                                      : kDefaultMaxBaselineFileBytes,
                                   resolve_baseline_engine_limits(baseline_learn_max_tcp_sessions,
                                                                    baseline_learn_max_conduits,
                                                                    baseline_learn_max_operations_per_conduit,
                                                                    baseline_learn_max_ranges_per_operation),
                                   *diag);
    }
    if (baseline_check_cmd->parsed()) {
        return run_baseline_check(baseline_check_input, baseline_check_file, baseline_check_output,
                                   baseline_check_format, baseline_check_strict, baseline_check_symbolic_addresses,
                                   baseline_check_policy_file, quiet, baseline_check_limit_vars,
                                   baseline_check_max_file_bytes != 0 ? baseline_check_max_file_bytes
                                                                      : kDefaultMaxBaselineFileBytes,
                                   resolve_baseline_engine_limits(baseline_check_max_tcp_sessions,
                                                                    baseline_check_max_conduits,
                                                                    baseline_check_max_operations_per_conduit,
                                                                    baseline_check_max_ranges_per_operation),
                                   *diag);
    }
    if (baseline_cmd->parsed()) {
        std::cerr << "error: 'baseline' needs a subcommand ('learn' or 'check')\n";
        return 1;
    }
    if (capture_cmd->parsed()) {
        return run_capture(capture_interface, capture_filter, capture_duration, capture_snaplen,
                            capture_promiscuous, capture_max_packets, capture_directory, capture_prefix,
                            capture_rotate_bytes, capture_rotate_seconds, capture_max_total_bytes,
                            capture_max_files, quiet, *diag);
    }
    if (merge_inventory_cmd->parsed()) {
        return run_merge_inventory(merge_inventory_inputs, merge_inventory_output, merge_inventory_format,
                                    static_cast<uint8_t>(merge_inventory_zone_prefix), quiet,
                                    merge_inventory_mac_vendor, merge_inventory_resolve, merge_inventory_hosts_file,
                                    merge_inventory_service_names, merge_inventory_services_file,
                                    merge_inventory_max_file_bytes, *diag);
    }
    if (merge_cmd->parsed()) {
        std::cerr << "error: 'merge' needs a subcommand (currently only 'inventory' exists)\n";
        return 1;
    }
    if (evidence_cmd->parsed()) {
        return run_evidence(evidence_input, evidence_policy_file, evidence_baseline_file, evidence_sl_target,
                             evidence_cip_monitoring_window, evidence_sign_key, evidence_output, evidence_format,
                             evidence_strict, quiet, static_cast<uint8_t>(evidence_zone_prefix), evidence_mac_vendor,
                             evidence_resolve, evidence_hosts_file, evidence_service_names, evidence_services_file,
                             *diag);
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
