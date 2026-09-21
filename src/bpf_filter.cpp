// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/bpf_filter.hpp"

#include "conduitscope/live_capture.hpp"  // CaptureError

#ifdef CONDUITSCOPE_HAVE_PCAP
#include <pcap.h>
#endif

namespace conduitscope {

#ifdef CONDUITSCOPE_HAVE_PCAP

struct BpfFilter::Impl {
    bpf_program program{};
    uint32_t compiled_for_linktype = 0;
    bool has_program = false;
};

namespace {

// Widened-snaplen fallback for a PcapReader::info().snaplen of 0 ("no limit declared" -- e.g. a
// pcapng interface with no if_snaplen option, or a classic pcap file whose global header snaplen
// field was itself written as 0). The BPF compiler uses the snaplen it's given to bounds-check
// filter terms that dereference into the packet (e.g. "tcp port 502" needs to read past the
// Ethernet/IP/TCP headers) -- passing 0 through literally would make the compiler assume nothing
// past byte 0 is ever safely readable, silently turning almost every content-referencing filter
// term into "never matches" instead of the "match against whatever bytes are actually there"
// behavior a user asking for --filter obviously wants. 262144 is the same generous ceiling
// tcpdump/libpcap's own tools fall back to in the equivalent situation -- comfortably larger than
// any real Ethernet-family capture's snaplen would legitimately be.
constexpr uint32_t kFallbackSnaplen = 262144;

bpf_program compile_or_throw(const std::string& filter, uint32_t linktype, uint32_t snaplen) {
    // pcap_open_dead() gives a "fake" pcap_t bound to a linktype/snaplen with no real capture
    // behind it, purely so pcap_compile() has something to compile against -- the maintained
    // replacement for the deprecated pcap_compile_nopcap() (which did the same thing internally,
    // just without a handle a caller could otherwise reuse or inspect errors from as clearly).
    pcap_t* dead = pcap_open_dead(static_cast<int>(linktype), static_cast<int>(snaplen));
    if (dead == nullptr) {
        throw CaptureError("cannot prepare a BPF compiler for link type " + std::to_string(linktype));
    }
    bpf_program compiled{};
    // PCAP_NETMASK_UNKNOWN: same tradeoff live_capture.cpp's own pcap_compile() call already
    // makes -- this process has no live interface to query a real netmask from (there's no
    // concept of "the netmask a pcap file was captured on"), and the only filter terms that
    // actually need one (broadcast-address-relative net/host matches) are rare enough that the
    // live-capture path already accepts the same limitation.
    if (pcap_compile(dead, &compiled, filter.c_str(), 1 /* optimize */, PCAP_NETMASK_UNKNOWN) < 0) {
        std::string detail = pcap_geterr(dead);
        pcap_close(dead);
        throw CaptureError("invalid capture filter '" + filter + "': " + detail);
    }
    pcap_close(dead);
    return compiled;
}

}  // namespace

BpfFilter::BpfFilter(const std::string& filter, uint32_t linktype, uint32_t snaplen)
    : impl_(std::make_unique<Impl>()),
      filter_(filter),
      snaplen_(snaplen != 0 ? snaplen : kFallbackSnaplen) {
    impl_->program = compile_or_throw(filter_, linktype, snaplen_);
    impl_->compiled_for_linktype = linktype;
    impl_->has_program = true;
}

BpfFilter::~BpfFilter() {
    if (impl_ && impl_->has_program) pcap_freecode(&impl_->program);
}

bool BpfFilter::matches(const PcapPacket& packet, uint32_t linktype) {
    if (linktype != impl_->compiled_for_linktype) {
        // A multi-interface pcapng file switched linktype (see this class's own header comment)
        // -- recompile once for the new linktype and keep reusing that compiled program for
        // however many subsequent packets share it, rather than recompiling every call.
        bpf_program recompiled;
        try {
            recompiled = compile_or_throw(filter_, linktype, snaplen_);
        } catch (const CaptureError&) {
            throw CaptureError("capture filter '" + filter_ +
                                "' is not valid for this capture's link type");
        }
        if (impl_->has_program) pcap_freecode(&impl_->program);
        impl_->program = recompiled;
        impl_->compiled_for_linktype = linktype;
        impl_->has_program = true;
    }
    return bpf_filter(impl_->program.bf_insns, reinterpret_cast<const u_char*>(packet.data.data()),
                       static_cast<u_int>(packet.original_len),
                       static_cast<u_int>(packet.captured_len)) != 0;
}

#else  // !CONDUITSCOPE_HAVE_PCAP

struct BpfFilter::Impl {};

BpfFilter::BpfFilter(const std::string&, uint32_t, uint32_t) : snaplen_(0) {
    throw CaptureError(
        "BPF filtering (--filter) on an offline capture (-r) requires this build to have been "
        "compiled with libpcap/Npcap support -- see 'conduitscope version'");
}

BpfFilter::~BpfFilter() = default;

bool BpfFilter::matches(const PcapPacket&, uint32_t) { return true; }

#endif

}  // namespace conduitscope
