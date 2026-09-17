// SPDX-License-Identifier: Apache-2.0
// live_capture.cpp - see live_capture.hpp for the design rationale (optional, build-time-detected
// libpcap/Npcap dependency; this whole file compiles either way, behavior gated on
// CONDUITSCOPE_HAVE_PCAP, which CMakeLists.txt defines only when it actually found a usable
// libpcap/Npcap SDK).

#include "conduitscope/live_capture.hpp"

#include <atomic>
#include <chrono>
#include <thread>

#ifdef CONDUITSCOPE_HAVE_PCAP
#include <pcap/pcap.h>
#endif

namespace conduitscope {

bool live_capture_available() {
#ifdef CONDUITSCOPE_HAVE_PCAP
    return true;
#else
    return false;
#endif
}

#ifndef CONDUITSCOPE_HAVE_PCAP

// --- No libpcap/Npcap SDK found at configure time: every entry point throws a clear, actionable
// error instead of failing to link or (worse) silently doing nothing. ---------------------------

namespace {
[[noreturn]] void throw_unavailable() {
    throw CaptureError(
        "live capture is not available: this build of conduitscope was compiled without "
        "libpcap (Linux) / Npcap SDK (Windows) support. Install libpcap-dev (Linux) or the Npcap "
        "SDK (Windows), then reconfigure and rebuild so CMake can find it -- or use 'decode' / "
        "'policy validate' with -i on an offline pcap file instead. See docs/MANUAL.md's LIVE "
        "CAPTURE section.");
}
}  // namespace

std::vector<InterfaceInfo> list_interfaces() { throw_unavailable(); }

struct LiveCapture::Impl {};

LiveCapture::LiveCapture(const std::string&, int, bool, const std::string&, int, size_t) {
    throw_unavailable();
}

LiveCapture::~LiveCapture() = default;

bool LiveCapture::next(PcapPacket&) { throw_unavailable(); }

void LiveCapture::stop() {}

#else  // CONDUITSCOPE_HAVE_PCAP

// --- Real libpcap/Npcap-backed implementation. ---------------------------------------------

std::vector<InterfaceInfo> list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_if_t* all = nullptr;
    if (pcap_findalldevs(&all, errbuf) == -1) {
        throw CaptureError(std::string("cannot enumerate network interfaces: ") + errbuf);
    }
    std::vector<InterfaceInfo> result;
    for (pcap_if_t* d = all; d != nullptr; d = d->next) {
        InterfaceInfo iface;
        iface.name = d->name != nullptr ? d->name : "";
        iface.description = d->description != nullptr ? d->description : "";
        iface.loopback = (d->flags & PCAP_IF_LOOPBACK) != 0;
        result.push_back(std::move(iface));
    }
    pcap_freealldevs(all);
    return result;
}

namespace {
// A read timeout short enough that stop() (e.g. from a SIGINT handler) takes effect promptly,
// without busy-looping: next() blocks for at most this long per pcap_next_ex() call before
// re-checking the stop conditions below.
constexpr int kReadTimeoutMs = 200;
}  // namespace

struct LiveCapture::Impl {
    pcap_t* handle = nullptr;
    std::atomic<bool> stop_requested{false};
    std::chrono::steady_clock::time_point deadline{};
    bool has_deadline = false;
    size_t max_packets = 0;
    size_t packets_seen = 0;

    ~Impl() {
        if (handle != nullptr) pcap_close(handle);
    }
};

LiveCapture::LiveCapture(const std::string& interface_name, int snaplen, bool promiscuous,
                          const std::string& filter, int duration_seconds, size_t max_packets)
    : impl_(std::make_unique<Impl>()) {
    char errbuf[PCAP_ERRBUF_SIZE] = {0};
    pcap_t* handle = pcap_create(interface_name.c_str(), errbuf);
    if (handle == nullptr) {
        throw CaptureError("cannot open interface '" + interface_name + "': " + errbuf);
    }
    pcap_set_snaplen(handle, snaplen);
    pcap_set_promisc(handle, promiscuous ? 1 : 0);
    pcap_set_timeout(handle, kReadTimeoutMs);
    // Without immediate mode, libpcap on Linux buffers captured packets until its internal ring
    // fills OR the read timeout above elapses -- but with zero or very sparse traffic (routine for
    // this project's target networks, and always true of the "no traffic during this timeout
    // window" case next() relies on to notice stop()/--duration promptly), that timeout is only
    // "best effort" against the underlying mmap'd ring and pcap_next_ex() can block far longer
    // than kReadTimeoutMs in practice. Immediate mode delivers each packet (and, just as
    // importantly here, each timeout) as soon as it's available instead of batching, which is
    // exactly what an interactive/duration-bounded/Ctrl+C-stoppable capture needs; conduitscope
    // has no bulk-throughput use case where the batching would otherwise help. Return value
    // deliberately ignored: on a libpcap too old to have it (pre-1.5), the fallback is just the
    // batchier behavior this comment describes, not a hard failure.
    pcap_set_immediate_mode(handle, 1);

    int activate_rc = pcap_activate(handle);
    if (activate_rc < 0) {
        // A negative return is a hard failure (e.g. PCAP_ERROR_PERM_DENIED, PCAP_ERROR_NO_SUCH_DEVICE):
        // the handle is still open but unusable, and pcap_geterr() has the OS-level detail
        // pcap_statustostr()'s generic message doesn't.
        std::string detail = pcap_geterr(handle);
        std::string msg = "cannot activate capture on '" + interface_name +
                           "': " + pcap_statustostr(activate_rc);
        if (!detail.empty()) msg += " (" + detail + ")";
        pcap_close(handle);
        throw CaptureError(msg);
    }
    // A positive return means it activated anyway with a non-fatal warning (e.g. promiscuous mode
    // isn't supported on this interface) -- proceed; nothing here currently surfaces the warning
    // text itself, since PcapReader (the offline counterpart) has no equivalent "soft warning at
    // open time" concept to match either.

    // pcap_set_timeout()'s read timeout above is only "best effort": observed in this project's
    // own test environment, pcap_next_ex() can block indefinitely past it when an interface sees
    // no traffic at all during that window, rather than reliably returning 0. Since a read timeout
    // that doesn't fire on genuinely idle traffic is exactly the case --duration/stop() most need
    // to work for, next() doesn't rely on it: the handle is put in non-blocking mode instead, and
    // next() polls it with its own short sleep between attempts (see below). This is slightly
    // less CPU-efficient than a well-behaved blocking timeout would be, but it's a small, bounded
    // cost for a tool whose whole point is interactive/bounded capture, not sustained
    // high-throughput sniffing.
    if (pcap_setnonblock(handle, 1, errbuf) < 0) {
        std::string msg = "cannot set non-blocking mode on '" + interface_name + "': " + errbuf;
        pcap_close(handle);
        throw CaptureError(msg);
    }

    if (!filter.empty()) {
        bpf_program compiled{};
        if (pcap_compile(handle, &compiled, filter.c_str(), 1 /* optimize */, PCAP_NETMASK_UNKNOWN) < 0) {
            std::string msg = "invalid capture filter '" + filter + "': " + pcap_geterr(handle);
            pcap_close(handle);
            throw CaptureError(msg);
        }
        if (pcap_setfilter(handle, &compiled) < 0) {
            std::string msg = std::string("cannot apply capture filter: ") + pcap_geterr(handle);
            pcap_freecode(&compiled);
            pcap_close(handle);
            throw CaptureError(msg);
        }
        pcap_freecode(&compiled);
    }

    impl_->handle = handle;
    impl_->max_packets = max_packets;
    if (duration_seconds > 0) {
        impl_->has_deadline = true;
        impl_->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(duration_seconds);
    }

    info_ = PcapFileInfo{};
    info_.linktype = static_cast<uint32_t>(pcap_datalink(handle));
    info_.snaplen = static_cast<uint32_t>(snaplen);
    // pcap_next_ex()'s struct timeval is always microsecond-resolution here (this project doesn't
    // request PCAP_TSTAMP_PRECISION_NANO), unlike an offline file, whose own header says which
    // resolution it was written with -- see PcapFileInfo::nanosecond_ts's doc comment.
    info_.nanosecond_ts = false;
}

LiveCapture::~LiveCapture() = default;

void LiveCapture::stop() {
    if (impl_) impl_->stop_requested.store(true);
}

bool LiveCapture::next(PcapPacket& out) {
    if (!impl_ || impl_->handle == nullptr) return false;
    for (;;) {
        if (impl_->stop_requested.load()) return false;
        if (impl_->max_packets != 0 && impl_->packets_seen >= impl_->max_packets) return false;
        if (impl_->has_deadline && std::chrono::steady_clock::now() >= impl_->deadline) return false;

        struct pcap_pkthdr* hdr = nullptr;
        const unsigned char* data = nullptr;
        int rc = pcap_next_ex(impl_->handle, &hdr, &data);
        if (rc == 1) {
            out.ts_sec = static_cast<uint32_t>(hdr->ts.tv_sec);
            out.ts_frac = static_cast<uint32_t>(hdr->ts.tv_usec);
            out.captured_len = hdr->caplen;
            out.original_len = hdr->len;
            out.data.assign(data, data + hdr->caplen);
            out.nanosecond_ts_hint = false;
            ++impl_->packets_seen;
            return true;
        }
        if (rc == 0) {
            // Non-blocking mode: no packet was available right now. Sleep briefly (rather than
            // busy-looping) and re-check the stop conditions above -- see the comment by
            // pcap_setnonblock() in the constructor for why this polls instead of trusting
            // libpcap's own read timeout to wake it up.
            std::this_thread::sleep_for(std::chrono::milliseconds(kReadTimeoutMs));
            continue;
        }
        // rc == -1 (capture error) or -2 (EOF -- savefile-only, shouldn't happen on a live
        // handle, but treated the same as "no more packets" rather than asserting on it).
        return false;
    }
}

#endif  // CONDUITSCOPE_HAVE_PCAP

}  // namespace conduitscope
