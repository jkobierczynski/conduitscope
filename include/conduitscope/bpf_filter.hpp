// SPDX-License-Identifier: Apache-2.0
// bpf_filter.hpp - BPF filtering of an offline pcap/pcapng file's already-read packets.
//
// live_capture.hpp's own --filter support applies a BPF program at CAPTURE time, via libpcap's
// pcap_setfilter() against an open pcap_t handle -- non-matching packets are dropped by the
// kernel/libpcap before this process ever sees them. An offline file has no equivalent "at
// capture time" step to hook: PcapReader (pcap_reader.hpp) is a from-scratch, libpcap-free
// parser, deliberately kept that way so every offline decode path stays dependency-free even in
// a build with no libpcap/Npcap at all (see PcapReader's own file header). So this applies the
// identical tcpdump-syntax filter expression to each packet AFTER PcapReader has already parsed
// it off disk, via libpcap's pcap_compile_nopcap()/bpf_filter() -- the same BPF compiler and
// matcher live_capture.cpp uses, just not bound to an open capture handle ("nopcap" in the
// function's own name means "no open pcap_t", not "no libpcap" -- this still needs libpcap/Npcap
// linked in, same as live capture does).
//
// Same optional-dependency posture as live_capture.hpp: this header/its .cpp compile either way
// (CONDUITSCOPE_HAVE_PCAP or not, see CMakeLists.txt's own detection), but BpfFilter's
// constructor throws CaptureError with a clear "not built with libpcap/Npcap support" message
// when it isn't available -- exactly like LiveCapture's own constructor already does for -i, so
// cli_main.cpp doesn't need any #ifdef of its own around this either.
#pragma once

#include <cstdint>
#include <memory>
#include <string>

#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

// Compiles one BPF filter expression once and matches PcapPacket instances against it repeatedly
// -- reused across an entire decode run instead of recompiling per packet. Not thread-safe;
// construct one per PcapReader/decode run, same lifetime convention as PcapReader/LiveCapture
// themselves.
class BpfFilter {
public:
    // filter: tcpdump-syntax BPF expression, e.g. "tcp port 502" or "host 192.168.1.10 and not
    //   arp". Never empty -- callers should simply not construct a BpfFilter at all when no
    //   filter was given, same "empty = no filter, don't even try" convention LiveCapture's own
    //   constructor uses.
    // linktype: the LINKTYPE_* this filter is initially compiled against (a PcapReader's
    //   info().linktype right after construction). See matches() below for why this isn't fixed
    //   for the filter's whole lifetime.
    // snaplen: the maximum captured length the filter program may need to reason about
    //   (PcapReader's info().snaplen); 0 (no limit declared -- e.g. a pcapng interface with no
    //   if_snaplen option) is widened to a generous default internally rather than passed through
    //   as literally unlimited -- see bpf_filter.cpp's own comment for why.
    // Throws CaptureError (the same type live_capture.hpp defines and cli_main.cpp already
    // catches around packet-source setup) if this build has no libpcap/Npcap support, or if the
    // filter expression itself fails to compile against this linktype.
    BpfFilter(const std::string& filter, uint32_t linktype, uint32_t snaplen);
    ~BpfFilter();

    BpfFilter(const BpfFilter&) = delete;
    BpfFilter& operator=(const BpfFilter&) = delete;

    // True if `packet` matches the compiled filter. `linktype` is the packet's OWN link type
    // (PcapReader::info().linktype at the moment this particular packet was read) -- for the
    // common single-interface capture this never differs from the linktype the filter was
    // constructed against, but a multi-interface pcapng file (see pcap_reader.hpp's own file
    // header) can genuinely change linktype packet-to-packet. When it does, the filter is
    // transparently recompiled for the new linktype before matching, and reused again as long as
    // linktype keeps matching that recompilation -- so the common case pays the recompile cost
    // at most once, not per packet. Throws CaptureError if recompiling for a new linktype fails
    // (the filter expression is valid for the original linktype but not this one -- e.g. an
    // Ethernet-only filter term against a raw-IP interface).
    bool matches(const PcapPacket& packet, uint32_t linktype);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
    std::string filter_;
    uint32_t snaplen_;
};

}  // namespace conduitscope
