// SPDX-License-Identifier: Apache-2.0
// live_capture.hpp - optional live packet capture via libpcap (Linux) / Npcap (Windows).
//
// This is the one place in conduitscope that is allowed to depend on something outside this
// repo and the standard library. It's kept strictly optional and build-time-detected (see
// CMakeLists.txt's CONDUITSCOPE_HAVE_PCAP detection): when libpcap/the Npcap SDK isn't found at
// configure time, this whole translation unit still compiles (so the rest of the tool, and every
// existing offline-pcap-file code path, stays completely dependency-free), but every function
// below throws CaptureError with a clear "not built with live-capture support" message instead of
// doing anything. Callers (cli_main.cpp) don't need to `#ifdef` around that -- they can always
// offer `-I/--interface` and `conduitscope interfaces`, and simply surface whatever CaptureError
// says if this build doesn't have it.
//
// Runtime note for Windows builds that DO have this compiled in: Npcap's driver/service must
// still be installed on the machine actually running conduitscope (the Npcap SDK used at build
// time only supplies headers and import libraries) -- see docs/MANUAL.md's LIVE CAPTURE section.
#pragma once

#include <cstdint>
#include <memory>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

// True when this binary was built with libpcap (Linux) or the Npcap SDK (Windows) found and
// linked in. Purely informational (`conduitscope version` reports it) -- callers don't need to
// check it before calling list_interfaces()/LiveCapture: both throw a clear CaptureError instead
// when it's false, which every caller here already has to handle anyway (a live interface can
// fail to open for plenty of other reasons too).
bool live_capture_available();

// True when the underlying pcap RUNTIME -- as opposed to the SDK/import library this binary was
// merely built against -- can actually be loaded on this machine right now. Only Windows draws a
// real distinction here: wpcap.dll is delay-loaded (see CMakeLists.txt's /DELAYLOAD:wpcap.dll
// comment) specifically so a machine with this binary but WITHOUT the separate Npcap runtime
// installer having been run can still use every offline (non---filter) code path with zero extra
// dependency -- but that means the first genuine call into a wpcap.dll export, on such a machine,
// would otherwise hit a raw, unfriendly Windows delay-load structured exception instead of an
// ordinary C++ exception. On every other platform (or once CONDUITSCOPE_HAVE_PCAP itself is
// unset, where neither caller below is even compiled) this is unconditionally true -- Linux/macOS
// link libpcap normally, with no build-time/run-time split to check.
//
// Exposed here (rather than staying a live_capture.cpp implementation detail, which is where this
// check originated) because it has TWO call sites needing the identical guard before THEIR own
// first pcap_*() call: LiveCapture's own constructor/list_interfaces here, and BpfFilter's own
// compile_or_throw in bpf_filter.cpp -- BPF filter compilation (--filter on an offline -r read)
// is, perhaps non-obviously, just as dependent on wpcap.dll as opening a live interface is, since
// pcap_compile() is itself one of wpcap.dll's exports. Each call site throws its own
// CaptureError with wording specific to what IT was trying to do, rather than sharing one
// generic message that would be misleading for the other.
bool pcap_runtime_available();

class CaptureError : public std::runtime_error {
public:
    explicit CaptureError(const std::string& message) : std::runtime_error(message) {}
};

// Live-capture drop statistics, from the underlying pcap_stats() call -- OS/driver-level packet
// loss that happened BEFORE a packet ever reached this process. This is a distinct failure mode
// from every other "observation incomplete" signal this codebase already tracks (an engine's own
// internal growth ceiling, a flow-state eviction, a malformed/truncated capture FILE): those all
// involve a packet this process actually received, just not fully retained or analyzed. A
// pcap_stats() drop means the packet never arrived here at all -- no decoder, engine, or report
// writer above LiveCapture::stats() itself can ever detect that it existed, which is exactly why
// this needs its own explicit, separate signal rather than being inferred from anything else (see
// docs/reviews/2026-09-chatgpt-security-review-patch257.md section 4, "Detection completeness":
// "Packet loss... must be distinguishable from a clean capture with no findings").
struct LiveCaptureStats {
    // pcap_stat::ps_recv -- packets libpcap itself received from the OS, whether or not this
    // process ever read them out via pcap_next_ex() (e.g. capture stopped early with packets still
    // queued -- not itself evidence of loss on its own).
    uint64_t packets_received = 0;
    // pcap_stat::ps_drop -- packets libpcap received but dropped because its own internal
    // buffer/ring filled up before this process read them out. The single most common real-world
    // "packet loss" cause this field exists to surface: a burst of traffic (or a process that
    // fell behind, e.g. blocked on slow -o/-w disk I/O) outpacing this capture's own read rate.
    uint64_t packets_dropped_by_libpcap = 0;
    // pcap_stat::ps_ifdrop -- packets dropped by the network interface/driver itself, below
    // libpcap entirely. NOT implemented on every platform/driver -- reads 0 both when nothing was
    // dropped there AND when this platform simply doesn't report the counter at all, two cases
    // this field cannot tell apart (a known, accepted libpcap limitation, not a bug in this
    // wrapper). packets_dropped_by_libpcap above has no such ambiguity: ps_drop is universally
    // supported.
    uint64_t packets_dropped_by_interface = 0;
};

// Formats a human-readable "observation incomplete" reason string from a LiveCaptureStats
// snapshot, or returns std::nullopt when it shows zero drops (packets_dropped_by_libpcap == 0 &&
// packets_dropped_by_interface == 0) -- the exact same "nothing to report" condition every call
// site below treats as a no-op. Pure/stateless, and deliberately independent of
// CONDUITSCOPE_HAVE_PCAP/pcap.h entirely (plain string formatting over three already-extracted
// integers) -- this is what lets cli_main.cpp's own several call sites (decode/policy validate/
// inventory/detect/capture, one per `-i`-capable subcommand) share identical wording without
// hand-writing it five times, AND what makes this specific logic unit-testable at all
// (tools/live_capture_stats_selftest.cpp): a REAL OS-level pcap_stats() drop can't be
// deterministically constructed through the CLI/CTest the way every other "observation
// incomplete" condition this codebase tracks can (an engine's own --max-* ceiling, say) -- it
// depends on genuine kernel/driver buffer timing under real traffic load, not anything a fixed
// capture file replayed through PcapReader can reproduce. Splitting the decision+wording out from
// the actual pcap_stats() call (LiveCapture::stats()) is what makes the former independently
// testable even though the latter still isn't.
std::optional<std::string> format_live_capture_drop_reason(const LiveCaptureStats& stats);

struct InterfaceInfo {
    std::string name;         // pass this to LiveCapture's constructor / -I
    std::string description;  // platform-supplied, often empty on Linux; may be empty
    bool loopback = false;
};

// Enumerates capturable network interfaces, for `conduitscope interfaces`. Throws CaptureError if
// this build has no live-capture support, or if the underlying enumeration call itself fails.
// Unlike actually opening one for capture, this generally does not require elevated privilege.
std::vector<InterfaceInfo> list_interfaces();

// Captures live traffic from one interface. Exposes the same info()/next() shape PcapReader does
// (see pcap_reader.hpp) so cli_main.cpp's decode/policy-validate packet loops can treat an offline
// file and a live interface as interchangeable packet sources.
class LiveCapture {
public:
    // interface_name: as returned by list_interfaces(), e.g. "eth0" (Linux) or the GUID-style name
    //   Npcap uses on Windows.
    // snaplen: maximum bytes captured per packet.
    // promiscuous: capture traffic not addressed to this host, where the platform/interface
    //   supports it. Defaults to on at the CLI layer (see cli_main.cpp) because the primary use
    //   case -- watching a mirrored/SPAN switch port for zone/conduit traffic that isn't addressed
    //   to the capturing host at all -- needs it.
    // filter: an optional BPF filter expression (same syntax as tcpdump's `-f`); empty = no filter.
    // duration_seconds: stop automatically after this many seconds; 0 = unlimited (rely on
    //   max_packets, stop(), or a caller-installed SIGINT handler instead).
    // max_packets: stop automatically after this many packets; 0 = unlimited.
    // Throws CaptureError if the interface can't be opened, activated, or the filter is invalid.
    LiveCapture(const std::string& interface_name, int snaplen, bool promiscuous,
                const std::string& filter, int duration_seconds, size_t max_packets);
    ~LiveCapture();

    LiveCapture(const LiveCapture&) = delete;
    LiveCapture& operator=(const LiveCapture&) = delete;

    const PcapFileInfo& info() const { return info_; }

    // Blocks until the next packet arrives, or returns false once capture has stopped (the
    // duration elapsed, max_packets was reached, stop() was called, or the capture handle
    // errored). Mirrors PcapReader::next()'s "false means no more packets" contract.
    bool next(PcapPacket& out);

    // Requests an early stop. This call itself only stores to a std::atomic<bool> -- the same
    // idiom std::atomic_flag/sig_atomic_t are conventionally used for -- so it's fine to invoke
    // from a POSIX signal handler despite the C++ standard not formally guaranteeing std::atomic
    // is async-signal-safe. What it does NOT do on its own is guarantee `this` is still alive
    // when a handler calls it: on Windows, Ctrl+C handlers run on a separate OS thread that can
    // execute concurrently with this object being destroyed, not just interrupt the calling
    // thread the way a POSIX signal does. cli_main.cpp's SigintGuard is what closes that race (it
    // waits for any in-flight handler invocation before letting the LiveCapture it guards be
    // destroyed) -- a caller invoking stop() from its own signal/Ctrl+C handler without an
    // equivalent guard would need to provide the same guarantee itself.
    void stop();

    // A snapshot of this capture's own OS/driver-level drop counters (pcap_stats()), safe to call
    // at any point after construction -- including after stop()/the final next() returning false,
    // right up until this object is destroyed (pcap_close() hasn't happened yet). Never throws: if
    // the underlying pcap_stats() call itself fails (platform/driver-dependent -- the handle may
    // simply not support it), this returns an all-zero LiveCaptureStats rather than propagating a
    // CaptureError, since a caller unable to learn whether packets were dropped should not be a
    // harder failure than just not knowing -- the capture itself already succeeded.
    LiveCaptureStats stats() const;

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    PcapFileInfo info_;
};

}  // namespace conduitscope
