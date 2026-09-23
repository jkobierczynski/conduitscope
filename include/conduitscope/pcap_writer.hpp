// SPDX-License-Identifier: Apache-2.0
// pcap_writer.hpp - writer for classic pcap capture files, the `decode -w/--write` counterpart to
// pcap_reader.hpp's PcapReader. Deliberately writes ONLY the classic, single-global-header pcap
// format (not pcapng) -- it is universally reopenable (tcpdump, Wireshark, tshark, this tool's own
// PcapReader all read it) and, unlike pcapng, needs no block-length bookkeeping or per-interface
// state to write correctly. This mirrors tcpdump's/tshark's/dumpcap's own long-standing default
// output format for `-w`.
//
// `decode -w <path>` writes the RAW bytes of every packet that reaches its main loop (i.e. after
// -i/-r selects a source and -f/--filter is applied, but before any protocol decoding) to a new
// capture file -- the same "write whatever passed the filter, unmodified" contract tshark's/
// dumpcap's own -w has. It works identically whether the packets came from a live interface (-i)
// or an offline, filtered read (-r + -f): PacketSource (decoder.hpp) already presents both as the
// same PcapPacket stream (see cli_main.cpp's run_decode), so this writer only ever needs that one
// packet shape plus the stream's own link type (PacketSource::linktype()) once, up front.
#pragma once

#include <cstdint>
#include <fstream>
#include <string>

#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

// Not thread-safe; one writer per output file, matching PcapReader's own "one reader per file"
// contract. Always writes microsecond-resolution timestamps (classic pcap's traditional default,
// magic 0xa1b2c3d4) regardless of the source capture's own resolution -- a source packet whose
// PcapPacket::nanosecond_ts_hint is true has its ts_frac divided down to microseconds by
// write_packet, so nanosecond-resolution *input* is always safe to pass here even though the
// *output* file is always microsecond-resolution. (Losing sub-microsecond precision on write is
// the same trade tcpdump's own classic-format `-w` has always made; a user who needs to preserve
// nanosecond timestamps through a filter/rewrite pass should keep working with pcapng tooling for
// that step -- out of scope for this first cut, see this file's own header comment.)
class PcapWriter {
public:
    // Throws ParseError (byteio.hpp) if `path` cannot be opened for writing. `linktype` is
    // whatever PacketSource::linktype() reports for the run's own source -- see this file's header
    // comment; `snaplen` defaults to 262144 (libpcap's own common default) when the caller has no
    // more specific value (an offline read has no meaningful snaplen of its own to propagate, only
    // a live capture's --snaplen does).
    PcapWriter(const std::string& path, uint32_t linktype, uint32_t snaplen = 262144);

    // Appends one packet record: ts_sec/ts_usec (converted from `pkt`'s own resolution, see this
    // class's own comment)/incl_len/orig_len, then `pkt.data` verbatim. Throws ParseError if the
    // stream is no longer writable (e.g. disk full) -- callers decide whether that is fatal.
    void write_packet(const PcapPacket& pkt);

private:
    std::ofstream out_;
    std::string path_;
};

}  // namespace conduitscope
