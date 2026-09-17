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

class CaptureError : public std::runtime_error {
public:
    explicit CaptureError(const std::string& message) : std::runtime_error(message) {}
};

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

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    PcapFileInfo info_;
};

}  // namespace conduitscope
