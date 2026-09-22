// SPDX-License-Identifier: Apache-2.0
// cli_main.cpp - command-line interface, built on the vendored CLI11 header.
//
// See docs/MANUAL.md for the full option reference; --help at any level
// (top-level, `decode --help`, `policy validate --help`, ...) is generated
// from the same option definitions below, so the two should never drift
// far apart -- but the manual also explains the *why* behind choices like
// the protocol-detection heuristics, which --help intentionally keeps brief.
#include <CLI11.hpp>

#include <atomic>
#include <csignal>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <thread>
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
#include <unistd.h>
#endif

#include "conduitscope/asset_inventory.hpp"
#include "conduitscope/bpf_filter.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/flow_direction.hpp"
#include "conduitscope/live_capture.hpp"
#include "conduitscope/output.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/policy.hpp"
#include "conduitscope/policy_engine.hpp"
#include "conduitscope/resolver.hpp"
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
    // reason Wireshark's own capture-filter (-f) numbering renumbers too.
    bool next(PcapPacket& out) {
        if (reader_) {
            while (reader_->next(out)) {
                ++file_position_;
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

std::string link_type_name(uint32_t linktype) {
    switch (linktype) {
        case LINKTYPE_ETHERNET: return "Ethernet";
        case LINKTYPE_RAW: return "Raw IP (no link-layer header)";
        case LINKTYPE_CAN_SOCKETCAN: return "Linux SocketCAN (DeviceNet)";
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
};

void add_resource_limit_options(CLI::App* cmd, ResourceLimitCliVars& vars) {
    cmd->add_option(
           "--max-reassembly-bytes", vars.max_reassembly_bytes,
           "Override every cross-segment payload-buffering byte cap at once: the general TCP "
           "reassembly path (default 16 MiB), DNP3 fragment reassembly (default 64 KiB), COTP "
           "TSDU reassembly (default 1 MiB), and OPC UA's/FF-HSE's own declared-length "
           "plausibility ceiling (default 16 MiB each). 0 = leave every site at its own default "
           "(see docs/DEVELOPMENT.md item 7 for the full constant-by-constant mapping)")
        ->capture_default_str();
    cmd->add_option(
           "--max-reassembly-segments", vars.max_reassembly_segments,
           "Override every cross-segment frame/segment-count cap at once: the general TCP "
           "reassembly path (default 20,000 segments), DNP3 fragment reassembly (default 500 "
           "frames), and COTP TSDU reassembly (default 2,000 frames). 0 = leave every site at "
           "its own default")
        ->capture_default_str();
    cmd->add_option(
           "--max-recursion-depth", vars.max_recursion_depth,
           "Override every recursive-decode depth cap at once: MMS Data-value nesting (default "
           "32), EtherNet/IP CIP Multiple_Service_Packet/Unconnected_Send nesting (default 4), "
           "MPLS label-stack depth (default 16), S7comm-Plus struct/item nesting (default 16), "
           "and GOOSE Data ASN.1 nesting (default 6). 0 = leave every site at its own default")
        ->capture_default_str();
    cmd->add_option(
           "--max-decoded-objects", vars.max_decoded_objects,
           "Override every per-message decoded-object/value/list-entry cap at once (~43 "
           "individually-named constants across DNP3/IEC104/GOOSE/EtherNet-IP/S7comm-Plus/MQTT/"
           "decoder.cpp's own summary lists, plus the 9 duplicated 50-entry list caps shared by "
           "EIGRP/OSPF/PIM/IGMP/ICMP/IGRP/RIP/VRRP/HSRP). 0 = leave every site at its own "
           "default; too many constants to enumerate here -- see docs/DEVELOPMENT.md item 7 for "
           "the full mapping")
        ->capture_default_str();
    cmd->add_option(
           "--max-coalesced-messages", vars.max_coalesced_messages,
           "Override every 'N application-layer messages found coalesced in one TCP/UDP "
           "payload' cap at once: FF-HSE, HART-IP, MQTT, EtherNet/IP, and OPC UA (all default "
           "50). 0 = leave every site at its own default")
        ->capture_default_str();
}

ResourceLimits build_resource_limits(const ResourceLimitCliVars& vars) {
    ResourceLimits limits;
    if (vars.max_reassembly_bytes != 0) limits.max_reassembly_bytes = vars.max_reassembly_bytes;
    if (vars.max_reassembly_segments != 0) limits.max_reassembly_segments = vars.max_reassembly_segments;
    if (vars.max_recursion_depth != 0) limits.max_recursion_depth = vars.max_recursion_depth;
    if (vars.max_decoded_objects != 0) limits.max_decoded_objects = vars.max_decoded_objects;
    if (vars.max_coalesced_messages != 0) limits.max_coalesced_messages = vars.max_coalesced_messages;
    return limits;
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
                size_t max_packets,
                const ResourceLimitCliVars& limit_vars,
                bool stats, bool strict, bool quiet,
                bool no_color, bool force_color,
                bool oui_enabled, bool resolve_hostnames, const std::string& hosts_path,
                bool service_names_enabled, const std::string& services_path, bool show_vlan,
                const std::string& time_format, const std::string& time_offset,
                std::ostream& diag, bool show_direction, bool show_mac) {
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

    DecodeOptions options;
    options.strict = strict;
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
                               : (protocol == "twincat") ? ProtocolFilter::TwinCatOnly
                               : (protocol == "kerberos") ? ProtocolFilter::KerberosOnly
                               : (protocol == "ldap")   ? ProtocolFilter::LdapOnly
                               : (protocol == "smb")    ? ProtocolFilter::SmbOnly
                               : (protocol == "melsec") ? ProtocolFilter::MelsecOnly
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
        // `color` here (not a literal false) is what makes handle_sigint restore the terminal's
        // default colors on Ctrl+C -- see SigintGuard's own comment.
        SigintGuard sigint_guard(source.live_ptr(), color);
        Decoder decoder(options);

        std::unique_ptr<OutputWriter> writer;
        StatsWriter stats_writer;
        if (!stats) {
            if (format == "json") {
                writer = std::make_unique<JsonWriter>(*out, resolver, show_vlan, *parsed_time_format,
                                                        *parsed_time_offset, show_direction);
            } else if (format == "csv") {
                writer = std::make_unique<CsvWriter>(*out, resolver, show_vlan, *parsed_time_format,
                                                       *parsed_time_offset, show_direction);
            } else {
                writer = std::make_unique<TextWriter>(*out, color, resolver, show_vlan, *parsed_time_format,
                                                        *parsed_time_offset, show_direction, show_mac);
            }
            writer->begin();
        }

        // Separate layer on top of Decoder's already-public output (see flow_direction.hpp's own
        // file header) -- fills in each TCP packet's has_direction/direction_client_is_src/
        // direction_source fields (decoder.hpp) in place, right after decode() and before the
        // packet reaches any writer, mirroring how PolicyEngine/AssetInventoryEngine each track
        // direction for `policy validate`/`inventory`. One instance per `decode` invocation, fed in
        // strict capture order, the same discipline `decoder` itself follows.
        FlowDirectionTracker direction_tracker;

        PcapPacket pkt;
        size_t decoded_count = 0, warnings = 0;
        while (!g_stop_requested.load(std::memory_order_acquire) && source.next(pkt)) {
            // source.index() -- not a locally incremented counter -- so a `--filter`ed offline
            // read reports each surviving packet under its real position in the file (matching
            // Wireshark's own display-filter numbering), rather than renumbering from 1 within
            // just the matches; see PacketSource::next()'s own comment.
            size_t index = source.index();
            DecodedPacket dp = decoder.decode(pkt, source.linktype(), index);
            direction_tracker.observe(dp);
            if (dp.protocol == "parse-error") {
                ++warnings;
                if (!quiet) diag << "warning: packet " << index << ": " << dp.summary << "\n";
            }
            if (stats) stats_writer.write_packet(dp);
            else writer->write_packet(dp);
            ++decoded_count;
            if (max_packets != 0 && decoded_count >= max_packets) break;
        }

        if (stats) stats_writer.print_summary(*out);
        else writer->end();

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
    } catch (const ResolverError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const ParseError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    } catch (const CaptureError& e) {
        std::cerr << "error: " << e.what() << "\n";
        return 1;
    }
    return 0;
}

int run_info(const std::string& input, std::ostream& out) {
    try {
        PcapReader reader(input);
        Decoder decoder(DecodeOptions{});
        StatsWriter stats_writer;

        PcapPacket pkt;
        size_t index = 0;
        while (reader.next(pkt)) {
            ++index;
            stats_writer.write_packet(decoder.decode(pkt, reader.info().linktype, index));
        }

        const auto& info = reader.info();
        out << "file:           " << input << "\n";
        out << "pcap version:   " << info.version_major << "." << info.version_minor << "\n";
        out << "link type:      " << link_type_name(info.linktype) << "\n";
        out << "snaplen:        " << info.snaplen << " bytes\n";
        out << "timestamps:     " << (info.nanosecond_ts ? "nanosecond" : "microsecond") << " resolution\n";
        stats_writer.print_summary(out);
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

int run_policy_validate(const std::string& input, const std::string& interface_name,
                         const std::string& filter, int duration_seconds, int snaplen, bool promiscuous,
                         const std::string& policy_path, const std::string& output, const std::string& format,
                         bool strict, bool strict_it_protocols, bool summarize_unclassified, bool quiet,
                         const ResourceLimitCliVars& limit_vars,
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
        PolicyEngine engine(policy);

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
        PolicyReport report = engine.finish();
        if (format == "json") {
            write_policy_report_json(*out, report, policy, capture_label, policy_path, resolver);
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
                   const std::string& policy_out_path, const ResourceLimitCliVars& limit_vars,
                   bool oui_enabled, bool resolve_hostnames,
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
        AssetInventoryEngine engine(zone_prefix_len);

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
        if (format == "json") {
            write_inventory_report_json(*out, report, capture_label, resolver);
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

        if (!interface_name.empty() && !quiet) {
            diag << "capture on '" << interface_name << "' stopped (" << index << " packet(s) captured)\n";
        }
        if (warnings > 0 && !quiet) {
            diag << warnings
                 << " packet(s) had parse warnings (shown above); rerun with --strict to stop at "
                    "the first one, or -q to silence this message\n";
        }
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

}  // namespace

int main(int argc, char** argv) {
    CLI::App app{"conduitscope decodes Modbus/TCP, DNP3, and S7comm/COTP traffic from offline pcap/"
                  "pcapng captures, as a building block for OT/ICS conduit and zone auditing (IEC 62443 / "
                  "NIS2 workflows).",
                  "conduitscope"};
    app.set_version_flag("--version", version_string());
    app.require_subcommand(1);
    app.footer(
        "Run 'conduitscope <command> --help' for command-specific options, or see docs/MANUAL.md\n"
        "in the source tree for the full reference including output-format examples and the\n"
        "current Roadmap.");

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
    std::string decode_input, decode_interface, decode_filter, decode_output;
    int decode_duration = 0;
    int decode_snaplen = 65535;
    bool decode_promiscuous = true;
    std::string decode_format = "text";
    std::string decode_protocol = "auto";
    std::vector<int> decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
        decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
        decode_kerberos_ports, decode_ldap_ports, decode_smb_ports, decode_melsec_ports,
        decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports, decode_mdns_ports,
        decode_llmnr_ports, decode_nbns_ports, decode_doh_ports, decode_rip_ports, decode_hsrp_ports,
        decode_remote_access_ports, decode_lateral_movement_ports, decode_enterprise_trust_ports,
        decode_wireless_backhaul_ports, decode_tunnel_vpn_ports;
    size_t decode_max_packets = 0;
    ResourceLimitCliVars decode_limit_vars;
    bool decode_stats = false, decode_strict = false;
    bool decode_mac_vendor = false, decode_resolve = false, decode_service_names = true;
    bool decode_show_vlan = true;
    bool decode_show_direction = true;
    bool decode_show_mac = false;
    std::string decode_time_format = "r", decode_time_offset = "utc";
    std::string decode_hosts_file, decode_services_file;

    auto* decode_input_opt =
        decode_cmd->add_option("-r,--read", decode_input,
                                "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* decode_interface_opt = decode_cmd->add_option(
        "-i,--interface", decode_interface,
        "Capture live from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required");
    decode_input_opt->excludes(decode_interface_opt);
    decode_interface_opt->excludes(decode_input_opt);
    decode_cmd->add_option("--filter", decode_filter,
                            "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; with -r, "
                            "applied per-packet after reading the file (same filter syntax either way); "
                            "requires this build to have been compiled with libpcap/Npcap support in "
                            "both cases");
    decode_cmd->add_option("--duration", decode_duration,
                            "Stop a live capture (-i) after this many seconds (0 = unlimited; stop "
                            "with Ctrl+C or --max-packets instead)")
        ->capture_default_str();
    decode_cmd->add_option("--snaplen", decode_snaplen,
                            "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    decode_cmd->add_flag("!--no-promiscuous", decode_promiscuous,
                          "With -i, don't put the interface into promiscuous mode (by default it "
                          "is, since the main use case -- watching a mirrored/SPAN switch port -- "
                          "needs traffic not addressed to this host)");
    decode_cmd->add_option("-o,--output", decode_output,
                            "Write output here instead of stdout. Caution: a single-dash "
                            "long-option typo glues onto this flag (e.g. a typo of a double-dash "
                            "long option, typed with only one dash, is parsed as -o followed by "
                            "the rest of that typo as this flag's own filename value) -- always "
                            "use the double dash for a long option name");
    decode_cmd->add_option("-f,--format", decode_format, "Output format: text, json, or csv")
        ->transform(CLI::IsMember({"text", "json", "csv"}))
        ->capture_default_str();
    decode_cmd
        ->add_option("-t,--time-format", decode_time_format,
                      "How to render each packet's timestamp -- mirrors tshark's own -t mnemonics: "
                      "r/relative (elapsed since the first packet, the default), e/epoch (raw "
                      "seconds since the Unix epoch), d/delta (elapsed since the previous packet), "
                      "a/absolute (HH:MM:SS.ffffff), ad/absolute-date (YYYY-MM-DD HH:MM:SS.ffffff) "
                      "-- see --time-offset for absolute/absolute-date's timezone, and docs/"
                      "MANUAL.md's OUTPUT FORMATS section")
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
                      "other --time-format value")
        ->capture_default_str();
    decode_cmd
        ->add_option("--protocol", decode_protocol,
                      "Restrict decoding to one protocol instead of auto-detecting all of them")
        ->transform(CLI::IsMember({"auto", "modbus", "dnp3", "s7comm", "mms", "iec104", "enip", "profinet", "goose", "sv", "ethercat", "stp", "devicenet", "bacnet", "hartip", "opcua", "mqtt", "s7comm-plus", "ff-hse", "dns", "mdns", "llmnr", "nbns", "doh", "rip", "icmp", "igmp", "vrrp", "hsrp", "igrp", "pim", "eigrp", "ospf", "remote-access", "lateral-movement", "enterprise-trust", "eapol", "wireless-backhaul", "pppoe", "tunnel-vpn", "mpls", "twincat", "kerberos", "ldap", "smb", "melsec"}))
        ->capture_default_str();
    decode_cmd->add_option("--modbus-port", decode_modbus_ports,
                            "Additional TCP port to treat as expected for Modbus (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--dnp3-port", decode_dnp3_ports,
                            "Additional TCP port to treat as expected for DNP3 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--s7comm-port", decode_s7comm_ports,
                            "Additional TCP port to treat as expected for COTP/S7comm, MMS, and "
                            "S7comm-Plus (repeatable, shared -- all three ride the identical "
                            "TPKT/COTP transport and TCP port); does not change detection, only "
                            "whether the port is flagged as unexpected");
    decode_cmd->add_option("--iec104-port", decode_iec104_ports,
                            "Additional TCP port to treat as expected for IEC 104 (repeatable); "
                            "does not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--enip-port", decode_enip_ports,
                            "Additional TCP port to treat as expected for EtherNet/IP explicit "
                            "messaging (repeatable); does not change detection, only whether the "
                            "port is flagged as unexpected");
    decode_cmd->add_option("--enip-io-port", decode_enip_io_ports,
                            "Additional UDP port to treat as expected for EtherNet/IP CIP I/O "
                            "implicit messaging (repeatable); does not change detection, only "
                            "whether the port is flagged as unexpected");
    decode_cmd->add_option("--bacnet-port", decode_bacnet_ports,
                            "Additional UDP port to treat as expected for BACnet/IP (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--hartip-port", decode_hartip_ports,
                            "Additional TCP or UDP port to treat as expected for HART-IP "
                            "(repeatable); does not change detection, only whether the port is "
                            "flagged as unexpected");
    decode_cmd->add_option("--kerberos-port", decode_kerberos_ports,
                            "Additional TCP or UDP port to treat as expected for Kerberos "
                            "(repeatable); does not change detection, only whether the port is "
                            "flagged as unexpected");
    decode_cmd->add_option("--melsec-port", decode_melsec_ports,
                            "Additional TCP or UDP port to treat as expected for MELSEC "
                            "Communication Protocol (MC Protocol/SLMP, repeatable); applies to both "
                            "transports even though their conventional defaults differ (5001/TCP, "
                            "5000/UDP); does not change detection, only whether the port is "
                            "flagged as unexpected");
    decode_cmd->add_option("--ldap-port", decode_ldap_ports,
                            "Additional TCP port to treat as expected for LDAP (repeatable); does "
                            "not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--smb-port", decode_smb_ports,
                            "Additional TCP port to treat as expected for SMB (repeatable); does "
                            "not change detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--opcua-port", decode_opcua_ports,
                            "Additional TCP port to treat as expected for OPC UA (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--mqtt-port", decode_mqtt_ports,
                            "Additional TCP port to treat as expected for MQTT (repeatable); "
                            "does not change detection, only whether the port is flagged as "
                            "unexpected");
    decode_cmd->add_option("--ffhse-port", decode_ffhse_ports,
                            "Additional TCP or UDP port to treat as expected for FOUNDATION "
                            "Fieldbus HSE (repeatable, shared across FDA/SM/FMS/LAN Redundancy -- "
                            "the sub-protocol is signaled in-band, not by port); does not change "
                            "detection, only whether the port is flagged as unexpected");
    decode_cmd->add_option("--dns-port", decode_dns_ports,
                            "Additional UDP port to treat as expected for DNS (repeatable); UNLIKE "
                            "every --*-port option above, this DOES widen detection in Auto mode, "
                            "not just the 'expected port' annotation -- DNS has no self-describing "
                            "wire format at all, so it is normally only attempted on port 53 (see "
                            "docs/MANUAL.md)");
    decode_cmd->add_option("--mdns-port", decode_mdns_ports,
                            "Additional UDP port to treat as expected for Multicast DNS "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 5353");
    decode_cmd->add_option("--llmnr-port", decode_llmnr_ports,
                            "Additional UDP port to treat as expected for LLMNR (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 5355");
    decode_cmd->add_option("--nbns-port", decode_nbns_ports,
                            "Additional UDP port to treat as expected for NetBIOS Name Service/"
                            "NBT-NS (repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 137");
    decode_cmd->add_option("--doh-port", decode_doh_ports,
                            "Additional TCP port to check for a DNS-over-HTTPS TLS ClientHello "
                            "(repeatable); widens detection in Auto mode, same caveat as "
                            "--dns-port -- normally only attempted on port 443. Detection only -- "
                            "see docs/MANUAL.md; the DNS message itself is never visible");
    decode_cmd->add_option("--rip-port", decode_rip_ports,
                            "Additional UDP port to treat as expected for RIP (repeatable); widens "
                            "detection in Auto mode, same caveat as --dns-port -- normally only "
                            "attempted on port 520");
    decode_cmd->add_option("--hsrp-port", decode_hsrp_ports,
                            "Additional UDP port to treat as expected for HSRP (repeatable); "
                            "widens detection in Auto mode, same caveat as --dns-port -- normally "
                            "only attempted on port 1985. IGMP and VRRP need no port option at all "
                            "-- both are dispatched purely by IP protocol number, see docs/"
                            "MANUAL.md");
    decode_cmd->add_option(
        "--remote-access-port", decode_remote_access_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 1 \"IT protocols an OT "
        "auditor flags\" family (RDP/VNC/TeamViewer/AnyDesk/Zoom -- see docs/MANUAL.md's ROADMAP "
        "item 18); widens detection in Auto mode for RDP's COTP-gated check and the three port-only "
        "protocols (TeamViewer/AnyDesk/Zoom), same caveat as --dns-port -- VNC's own RFB banner "
        "check is never port-gated regardless, see it_protocols.hpp");
    decode_cmd->add_option(
        "--lateral-movement-port", decode_lateral_movement_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 2 \"IT protocols an OT "
        "auditor flags\" family (SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP -- SMB was promoted to "
        "its own dedicated decoder, see --smb-port -- see docs/MANUAL.md's ROADMAP item 18); "
        "widens detection in Auto mode for SNMP/Telnet/FTP/TFTP's own port-gated checks and "
        "HTTPS's port-only fallback, same caveat as --dns-port -- SSH's version-exchange banner "
        "and HTTP's request-line/status-line are never port-gated regardless, see it_protocols.hpp");
    decode_cmd->add_option(
        "--enterprise-trust-port", decode_enterprise_trust_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 3 \"IT protocols an OT "
        "auditor flags\" family (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+ -- see docs/MANUAL.md's ROADMAP "
        "item 18); widens detection in Auto mode for NTP/LDAP/RADIUS/TACACS+'s own port-gated checks "
        "and LDAPS's port-only fallback, same caveat as --dns-port -- DHCP's magic cookie is never "
        "port-gated regardless, see it_protocols.hpp. IEEE 802.1X/EAPOL needs no port option at all "
        "-- it has no port, see docs/MANUAL.md and eapol.hpp");
    decode_cmd->add_option(
        "--wireless-backhaul-port", decode_wireless_backhaul_ports,
        "Additional UDP port to treat as expected for the Tier 4 \"IT protocols an OT auditor "
        "flags\" family (CAPWAP control/data, LWAPP control/data, GTP-U -- see docs/MANUAL.md's "
        "ROADMAP item 18); widens detection in Auto mode for all five, since none of this tier's "
        "own structural checks are strong enough to run port-independently, same caveat as "
        "--dns-port -- see it_protocols.hpp. PPPoE needs no port option at all -- it has no port, "
        "see docs/MANUAL.md and pppoe.hpp");
    decode_cmd->add_option(
        "--tunnel-vpn-port", decode_tunnel_vpn_ports,
        "Additional TCP or UDP port to treat as expected for the Tier 5 \"IT protocols an OT "
        "auditor flags\" family (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve, "
        "WireGuard, OpenVPN, dtls-tunnel, STT -- see docs/MANUAL.md's ROADMAP item 18); widens "
        "detection in Auto mode for every port-based protocol here EXCEPT dtls-tunnel, whose own "
        "DTLS record structural check is never port-gated regardless, same caveat as --dns-port -- "
        "see tunnel_vpn.hpp. GRE/ESP/AH/IP-in-IP/6in4/L2TP's own IP-protocol-number-keyed forms, and "
        "MPLS, need no port option at all -- see docs/MANUAL.md, tunnel_vpn.hpp, and mpls.hpp");
    decode_cmd->add_option("--max-packets", decode_max_packets,
                            "Stop after decoding this many packets (0 = unlimited)")
        ->capture_default_str();
    add_resource_limit_options(decode_cmd, decode_limit_vars);
    decode_cmd->add_flag("--stats", decode_stats,
                          "Print an aggregate summary (protocol/function-code histogram) instead of "
                          "one line per packet; ignores --format");
    decode_cmd->add_flag("--strict", decode_strict,
                          "Abort on the first malformed packet instead of reporting it and continuing");
    decode_cmd->add_flag("!--no-vlan", decode_show_vlan,
                          "Disable display of the 802.1Q VLAN ID for VLAN-tagged packets, on by "
                          "default -- see docs/MANUAL.md's OUTPUT FORMATS section");
    decode_cmd->add_flag(
        "!--no-direction", decode_show_direction,
        "Disable display of per-packet TCP flow direction (client/server determination and which "
        "tier decided it -- handshake/content/port-heuristic), on by default -- see docs/MANUAL.md's "
        "OUTPUT FORMATS section and ROADMAP item 19. Does not affect `decode --stats`'s own "
        "direction-tier breakdown, which has no display toggles of its own");
    decode_cmd->add_flag(
        "-e,--ether", decode_show_mac,
        "For a packet with an IP layer, show its Ethernet header (source/destination MAC "
        "address, VLAN tag) below the packet line in text output -- mirrors tcpdump's own -e. "
        "Off by default to keep output compact; implied by --mac-vendor (there'd be nothing to "
        "attach a vendor name to otherwise). A no-op for a packet with no IP layer at all (ARP/"
        "LLDP/EAPOL/PPPoE/MPLS/etc.), since its MAC address pair is already shown on its own "
        "head line unconditionally. Only affects text output -- JSON/CSV always include "
        "src_mac/dst_mac as base fields, same as src_ip/dst_ip -- see docs/MANUAL.md's OUTPUT "
        "FORMATS section");
    decode_cmd->add_flag("--mac-vendor", decode_mac_vendor,
                          "Enable OUI (MAC vendor) resolution and show it next to each MAC "
                          "address; off by default to keep output compact. Implies -e/--ether -- "
                          "see docs/MANUAL.md's OUTPUT FORMATS section. (Named --mac-vendor, "
                          "not --oui, specifically so a single-dash typo of this flag reports a "
                          "clean \"argument not expected\" error instead of silently gluing onto "
                          "-o/--output the way a single-dash -oui used to -- see -o's own help "
                          "text and docs/DEVELOPMENT.md's ROADMAP for the full story)");
    decode_cmd->add_flag(
        "--resolve", decode_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts); off by "
        "default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    decode_cmd
        ->add_option("--hosts", decode_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    decode_cmd->add_flag("!--nn", decode_service_names,
                          "Disable service name resolution (built-in table plus --services), on "
                          "by default");
    decode_cmd
        ->add_option("--services", decode_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
        ->check(CLI::ExistingFile);

    // --- info -------------------------------------------------------------
    auto* info_cmd = app.add_subcommand(
        "info", "Print pcap file metadata and a protocol histogram, without full per-packet output");
    std::string info_input;
    info_cmd->add_option("-r,--read", info_input, "Input capture file (classic pcap or pcapng, auto-detected)")
        ->required()
        ->check(CLI::ExistingFile);

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
    auto* policy_input_opt =
        policy_validate_cmd->add_option("-r,--read", policy_input,
                                         "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* policy_interface_opt = policy_validate_cmd->add_option(
        "-i,--interface", policy_interface,
        "Check live traffic from this network interface instead of reading a file (see "
        "'conduitscope interfaces'); requires this build to have been compiled with libpcap/Npcap "
        "support -- exactly one of -r/-i is required");
    policy_input_opt->excludes(policy_interface_opt);
    policy_interface_opt->excludes(policy_input_opt);
    policy_validate_cmd->add_option("--filter", policy_filter,
                                     "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; "
                                     "with -r, applied per-packet after reading the file (same filter syntax "
                                     "either way); requires this build to have been compiled with libpcap/Npcap "
                                     "support in both cases");
    policy_validate_cmd
        ->add_option("--duration", policy_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")
        ->capture_default_str();
    policy_validate_cmd->add_option("--snaplen", policy_snaplen, "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    policy_validate_cmd->add_flag(
        "!--no-promiscuous", policy_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)");
    policy_validate_cmd
        ->add_option("--policy", policy_file,
                      "Zone/conduit policy file (a restricted YAML subset -- see docs/MANUAL.md's "
                      "POLICY FILE FORMAT section)")
        ->required()
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_option(
        "-o,--output", policy_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name");
    policy_validate_cmd->add_option("-f,--format", policy_format, "Report format: text or json")
        ->transform(CLI::IsMember({"text", "json"}))
        ->capture_default_str();
    policy_validate_cmd->add_flag("--strict", policy_strict,
                                   "Abort on the first malformed packet instead of reporting it and continuing");
    add_resource_limit_options(policy_validate_cmd, policy_limit_vars);
    policy_validate_cmd->add_flag(
        "--strict-it-protocols", policy_strict_it_protocols,
        "Also fail compliance (non-zero exit code) when any \"IT protocol an OT auditor flags\" "
        "(RDP/VNC/SMB/SSH/HTTP(S)/SNMP/GRE/... -- see docs/MANUAL.md's ROADMAP item 18, and the "
        "report's own \"notable protocols\" section) was observed, even on an otherwise COMPLIANT "
        "capture -- off by default: the \"notable protocols\" section is always populated regardless "
        "of this flag, so nothing is hidden without it; this flag only controls whether that finding "
        "additionally affects the exit code, for a CI/audit pipeline that wants to gate on it");
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
        "own with more precision than any one fixed grouping key here could offer");
    policy_validate_cmd->add_flag("--mac-vendor", policy_mac_vendor,
                                   "Enable OUI (MAC vendor) resolution in the report; off by "
                                   "default to keep output compact -- see docs/MANUAL.md's "
                                   "OUTPUT FORMATS section. (Named --mac-vendor, not --oui, so a "
                                   "single-dash typo errors cleanly instead of silently gluing "
                                   "onto -o/--output -- see decode's --mac-vendor help text)");
    policy_validate_cmd->add_flag(
        "--resolve", policy_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    policy_validate_cmd
        ->add_option("--hosts", policy_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    policy_validate_cmd->add_flag("!--nn", policy_service_names,
                                   "Disable service name resolution (built-in table plus --services) "
                                   "in the report, on by default");
    policy_validate_cmd
        ->add_option("--services", policy_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
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
    bool inventory_mac_vendor = false, inventory_resolve = false, inventory_service_names = true;
    std::string inventory_hosts_file, inventory_services_file;
    ResourceLimitCliVars inventory_limit_vars;

    auto* inventory_input_opt =
        inventory_cmd->add_option("-r,--read", inventory_input,
                                   "Input capture file (classic pcap or pcapng, auto-detected)")
            ->check(CLI::ExistingFile);
    auto* inventory_interface_opt = inventory_cmd->add_option(
        "-i,--interface", inventory_interface,
        "Build the inventory from live traffic on this network interface instead of reading a "
        "file (see 'conduitscope interfaces'); requires this build to have been compiled with "
        "libpcap/Npcap support -- exactly one of -r/-i is required");
    inventory_input_opt->excludes(inventory_interface_opt);
    inventory_interface_opt->excludes(inventory_input_opt);
    inventory_cmd->add_option("--filter", inventory_filter,
                               "BPF filter (tcpdump syntax) -- with -i, applied by libpcap at capture time; "
                               "with -r, applied per-packet after reading the file (same filter syntax "
                               "either way); requires this build to have been compiled with libpcap/Npcap "
                               "support in both cases");
    inventory_cmd
        ->add_option("--duration", inventory_duration,
                      "Stop a live capture (-i) after this many seconds (0 = unlimited; stop with "
                      "Ctrl+C instead)")
        ->capture_default_str();
    inventory_cmd->add_option("--snaplen", inventory_snaplen, "Maximum bytes captured per packet with -i")
        ->capture_default_str();
    inventory_cmd->add_flag(
        "!--no-promiscuous", inventory_promiscuous,
        "With -i, don't put the interface into promiscuous mode (by default it is, since the main "
        "use case -- watching a mirrored/SPAN switch port -- needs traffic not addressed to this host)");
    inventory_cmd->add_option(
        "-o,--output", inventory_output,
        "Write the report here instead of stdout. Caution: a single-dash long-option typo "
        "glues onto this flag -- always use the double dash for a long option name");
    inventory_cmd->add_option("-f,--format", inventory_format, "Report format: text or json")
        ->transform(CLI::IsMember({"text", "json"}))
        ->capture_default_str();
    inventory_cmd->add_flag("--strict", inventory_strict,
                             "Abort on the first malformed packet instead of reporting it and continuing");
    add_resource_limit_options(inventory_cmd, inventory_limit_vars);
    inventory_cmd
        ->add_option("--zone-prefix", inventory_zone_prefix,
                      "CIDR prefix length ([0, 32]) used to group observed asset IPs into "
                      "inferred zones -- see docs/MANUAL.md's ROADMAP item 17")
        ->capture_default_str()
        ->check(CLI::Range(0, 32));
    inventory_cmd->add_option("--diagram", inventory_diagram_file,
                               "Also write a zone/conduit diagram here (see --diagram-format)");
    inventory_cmd
        ->add_option("--diagram-format", inventory_diagram_format,
                      "Diagram format for --diagram: a Mermaid flowchart or Graphviz DOT")
        ->transform(CLI::IsMember({"mermaid", "dot"}))
        ->capture_default_str();
    inventory_cmd->add_option(
        "--policy-out", inventory_policy_out,
        "Also write the inferred zone/conduit model as a policy YAML file here, directly loadable "
        "by 'policy validate --policy' -- closes the discover-then-enforce loop");
    inventory_cmd->add_flag("--mac-vendor", inventory_mac_vendor,
                             "Enable OUI (MAC vendor) resolution in the report; off by default to "
                             "keep output compact -- see docs/MANUAL.md's OUTPUT FORMATS section. "
                             "(Named --mac-vendor, not --oui, so a single-dash typo errors cleanly "
                             "instead of silently gluing onto -o/--output -- see decode's "
                             "--mac-vendor help text)");
    inventory_cmd->add_flag(
        "--resolve", inventory_resolve,
        "Enable hostname resolution from an explicitly-supplied hosts file (--hosts) in the report; "
        "off by default; NEVER performs live DNS -- file-only, see docs/MANUAL.md's OUTPUT FORMATS "
        "section");
    inventory_cmd
        ->add_option("--hosts", inventory_hosts_file,
                      "Unix /etc/hosts-style file to resolve IP addresses from, for --resolve")
        ->check(CLI::ExistingFile);
    inventory_cmd->add_flag("!--nn", inventory_service_names,
                             "Disable service name resolution (built-in table plus --services) in "
                             "the report, on by default");
    inventory_cmd
        ->add_option("--services", inventory_services_file,
                      "Unix /etc/services-style file to supplement/override the built-in "
                      "port->service-name table")
        ->check(CLI::ExistingFile);

    // --- version ------------------------------------------------------------
    app.add_subcommand("version", "Print version and build information");

    CLI11_PARSE(app, argc, argv);

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
        // --oui implies -e/--ether: without it there'd be no eth line to attach a vendor name to.
        // -e alone (no --oui) shows the MAC pair with no vendor annotation.
        decode_show_mac = decode_show_mac || decode_mac_vendor;
        return run_decode(decode_input, decode_interface, decode_filter, decode_duration, decode_snaplen,
                           decode_promiscuous, decode_output, decode_format, decode_protocol,
                           decode_modbus_ports, decode_dnp3_ports, decode_s7comm_ports, decode_iec104_ports,
                           decode_enip_ports, decode_enip_io_ports, decode_bacnet_ports, decode_hartip_ports,
                           decode_kerberos_ports, decode_ldap_ports, decode_smb_ports,
                           decode_melsec_ports,
                           decode_opcua_ports, decode_mqtt_ports, decode_ffhse_ports, decode_dns_ports,
                           decode_mdns_ports, decode_llmnr_ports, decode_nbns_ports, decode_doh_ports,
                           decode_rip_ports, decode_hsrp_ports, decode_remote_access_ports,
                           decode_lateral_movement_ports, decode_enterprise_trust_ports,
                           decode_wireless_backhaul_ports, decode_tunnel_vpn_ports,
                           decode_max_packets, decode_limit_vars, decode_stats, decode_strict,
                           quiet, no_color, force_color, decode_mac_vendor, decode_resolve, decode_hosts_file,
                           decode_service_names, decode_services_file, decode_show_vlan,
                           decode_time_format, decode_time_offset, *diag, decode_show_direction,
                           decode_show_mac);
    }
    if (info_cmd->parsed()) {
        return run_info(info_input, std::cout);
    }
    if (interfaces_cmd->parsed()) {
        return run_interfaces(std::cout);
    }
    if (policy_validate_cmd->parsed()) {
        return run_policy_validate(policy_input, policy_interface, policy_filter, policy_duration, policy_snaplen,
                                    policy_promiscuous, policy_file, policy_output, policy_format, policy_strict,
                                    policy_strict_it_protocols, policy_summarize_unclassified, quiet,
                                    policy_limit_vars,
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
                              inventory_limit_vars,
                              inventory_mac_vendor, inventory_resolve, inventory_hosts_file, inventory_service_names,
                              inventory_services_file, *diag);
    }
    std::cout << "conduitscope " << version_string() << "\n";
    return 0;
}
