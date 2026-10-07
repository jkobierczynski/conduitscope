// SPDX-License-Identifier: Apache-2.0
// pcap_reader.hpp - reader for offline capture files: both classic pcap and pcapng.
//
// This reads offline capture files (what tcpdump/Wireshark/`tshark -w` write) rather than
// capturing live traffic; live capture is a separate, optional feature -- see
// live_capture.hpp. Reading offline files needs no libpcap/Npcap at all, which matters a
// lot for "clones and builds cleanly on both platforms with zero required dependencies".
//
// Both classic pcap (the single-global-header format tcpdump has always written) and
// pcapng (the newer block-based format Wireshark/dumpcap default to today) are supported,
// auto-detected from the first four bytes of the file. Which one a given file is stays an
// internal implementation detail -- PcapReader's public interface (this header) does not
// change based on it. See pcap_reader.cpp for the pcapng block-parsing internals and for
// exactly which pcapng block types are understood.
#pragma once

#include <cstdint>
#include <fstream>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"

namespace conduitscope {

// Well-known pcap link-layer type values (from the tcpdump LINKTYPE_ registry) that
// this tool understands. Anything else is reported per-packet as "unsupported link
// type" rather than treated as a fatal error, so a mixed-capability capture can still
// be partially decoded.
//
// LINKTYPE_CAN_SOCKETCAN (227) is Linux SocketCAN's own pcap capture framing -- what
// `candump -l`, `tcpdump -i can0`, or Wireshark itself write when capturing a CAN
// (Controller Area Network) bus. It is a wholly separate, unrelated link layer from
// Ethernet (no MAC addresses, no EtherType, no relationship to LINKTYPE_ETHERNET's own
// framing at all) -- see can_socketcan.hpp's own file header comment for the exact
// 8-byte-header-plus-payload record shape, and devicenet.hpp for the one protocol this
// codebase currently decodes on top of it (DeviceNet).
//
// LINKTYPE_IEEE802_15_4_WITHFCS (195) and LINKTYPE_IEEE802_15_4_TAP (283) are the two raw IEEE
// 802.15.4 radio-capture framings this codebase supports (Zigbee's own MAC layer) -- see
// ieee802154.hpp's own file header comment for the exact record shapes and why these two, and only
// these two, of the five IEEE 802.15.4 LINKTYPE values tcpdump.org registers are in scope (LINUX=191,
// NONASK_PHY=215, and NOFCS=230 are deliberately not added here -- an unrecognized link type already
// falls through to this reader's own callers' "unsupported link type" per-packet handling, so nothing
// else is needed for them). zigbee.hpp is the one protocol this codebase currently decodes on top of
// either of these two.
enum LinkType : uint32_t {
    LINKTYPE_ETHERNET = 1,
    LINKTYPE_RAW = 101,
    LINKTYPE_IEEE802_15_4_WITHFCS = 195,
    LINKTYPE_CAN_SOCKETCAN = 227,
    LINKTYPE_IEEE802_15_4_TAP = 283,
};

struct PcapFileInfo {
    uint16_t version_major = 0;
    uint16_t version_minor = 0;
    int32_t thiszone = 0;
    uint32_t snaplen = 0;
    uint32_t linktype = 0;
    bool byte_swapped = false;   // capture file endianness differs from this host
    bool nanosecond_ts = false;  // 0xa1b23c4d / 0x4d3cb2a1 magic variant
};

// pcapng Decryption Secrets Block (Block Type 0x0000000A, draft-ietf-opsawg-pcapng section 4.7):
// one embedded "here are secrets a later analysis tool can use" blob, written by the SAME capture
// tool that wrote the packets (e.g. a browser or TLS library configured to log its own keys, with
// Wireshark/dumpcap/tshark embedding them into the capture file as it's written) rather than
// derived from the packets themselves. This reader stores every one it sees verbatim --
// `secrets_type` + `secrets_data` only, any trailing options discarded -- rather than
// interpreting it: interpretation is protocol-specific (the one secrets_type this codebase acts
// on, kPcapngSecretsTypeTls, is SSLKEYLOGFILE-format text -- see tls_keylog.hpp's own
// TlsKeyLog::ingest) and belongs to the caller, not this generic capture-format reader.
struct PendingDecryptionSecret {
    uint32_t secrets_type = 0;
    std::vector<uint8_t> data;
};

// Secrets Type "TLS Key Log" (the literal ASCII bytes "TLSK", read big-endian as one uint32 --
// Wireshark's own wsutil/secrets-types.h names this SECRETS_TYPE_TLS) -- a Decryption Secrets
// Block of this type's own `data` is SSLKEYLOGFILE/RFC 9850-format text, the exact same shape a
// --tls-keylog FILE on disk already is. The only secrets_type this codebase currently consumes;
// any other value (e.g. Wireshark's own SECRETS_TYPE_WIREGUARD, SECRETS_TYPE_ZIGBEE_NWK_KEY,
// SECRETS_TYPE_OPCUA) is still stored and returned by take_pending_decryption_secrets() like any
// other, for a caller to recognize or ignore -- this reader itself doesn't gate on secrets_type at
// the parse level, only this constant's own consumer (cli_main.cpp) does.
constexpr uint32_t kPcapngSecretsTypeTls = 0x544c534bu;

struct PcapPacket {
    uint32_t ts_sec = 0;
    uint32_t ts_frac = 0;  // microseconds, or nanoseconds if info().nanosecond_ts
    uint32_t captured_len = 0;
    uint32_t original_len = 0;
    std::vector<uint8_t> data;

    double timestamp_seconds() const {
        double frac = ts_frac / (nanosecond_ts_hint ? 1e9 : 1e6);
        return static_cast<double>(ts_sec) + frac;
    }

    bool nanosecond_ts_hint = false;  // set by PcapReader::next()
};

// Reads one offline capture file -- classic pcap or pcapng, auto-detected. Not
// thread-safe; one reader per file.
//
// info() reflects classic pcap's single, file-wide header for a classic pcap file. pcapng
// has no such single header: link type, snaplen, and timestamp resolution are declared per
// *interface* (an Interface Description Block), and a capture can legitimately contain more
// than one interface (e.g. dumpcap capturing two NICs into one file) with different values
// for each. So for a pcapng file, info() reflects whichever interface most recently owned a
// packet returned by next() -- initially the first interface declared in the file, updated
// on every next() call after that. Every call site in this codebase already re-reads
// info().linktype fresh on each iteration of its packet loop (rather than caching it once
// before the loop) for exactly this reason, so per-packet/per-interface accuracy falls out
// automatically without those call sites needing to know or care which format is in play.
class PcapReader {
public:
    explicit PcapReader(const std::string& path);

    const PcapFileInfo& info() const { return info_; }

    // Reads the next packet into `out`. Returns false at a clean end of file.
    // Throws ParseError if the file is truncated mid-record (a corrupt/partial
    // capture), so callers can decide whether that is fatal.
    bool next(PcapPacket& out);

    const std::string& path() const { return path_; }

    // Drains and returns every Decryption Secrets Block (see PendingDecryptionSecret above) seen
    // by next() calls SINCE THE LAST call to this method (or since construction, for the first
    // call) -- callers that care about embedded secrets (cli_main.cpp's --tls-keylog handling)
    // call this once per next() call, right after it, and merge whatever comes back into their own
    // TlsKeyLog; a caller that never calls this simply never sees these blocks at all (they're
    // otherwise invisible -- next() itself only ever returns real packets, exactly as before this
    // feature existed). Returns an empty vector on the (overwhelmingly common) case of no DSBs
    // since the last drain, which costs nothing beyond one empty-vector move.
    std::vector<PendingDecryptionSecret> take_pending_decryption_secrets();

private:
    // Per-interface state accumulated from pcapng Interface Description Blocks. Interface
    // IDs referenced by Enhanced Packet Blocks are indices into this, scoped to the current
    // section (see PCAPNG SECTIONS note in pcap_reader.cpp).
    struct PcapNgInterface {
        uint32_t linktype = 1;         // LINKTYPE_ETHERNET, pcapng's own default absent an IDB
        uint32_t snaplen = 0;          // 0 means "no limit declared"
        double units_per_second = 1e6;  // from the if_tsresol option; default is microseconds
    };

    // pcapng-only: reads the Section Header Block at the reader's current stream position,
    // bootstrapping (or re-bootstrapping, for a later section) byte order from the
    // byte-order-magic field, and resets per-section interface state. Called once from the
    // constructor for the file's first section and again from next() whenever a later
    // Section Header Block is encountered (pcapng permits concatenating multiple captures,
    // potentially with different byte order, into one file).
    void read_section_header_block();
    // pcapng-only: reads one generic block's Block Total Length, body, and trailing (repeated)
    // Block Total Length, given that its 4-byte Block Type has already been read by the caller
    // (this method never looks at the type itself, so it's shared verbatim by next_pcapng()'s
    // own block loop and prefetch_first_interface_linktype() below). Throws ParseError on any
    // of the same truncation/corruption conditions next_pcapng() has always enforced inline.
    void read_pcapng_block_body(std::vector<uint8_t>& body);
    // pcapng-only: parses one Interface Description Block's body (already read by the caller)
    // into a new PcapNgInterface, appending it to pcapng_interfaces_ -- and, if this is the
    // FIRST interface declared in the current section, also updates info_.linktype/snaplen
    // immediately (see this method's own comment, pcap_reader.cpp, for why that immediacy
    // matters). Shared by next_pcapng()'s own kIdbBlockType case and
    // prefetch_first_interface_linktype() below.
    void handle_idb_block(const std::vector<uint8_t>& body);
    // pcapng-only: called once from the constructor, right after read_section_header_block()
    // establishes byte order for the file's first section -- walks forward through any
    // Interface Description Block(s) that precede the first packet block (the normal shape of
    // every real pcapng file: dumpcap/Wireshark/tshark always declare every interface up front),
    // parsing each via handle_idb_block so info() reflects the first interface's real link type
    // immediately, THEN SEEKS THE STREAM BACK to right before the first block that wasn't an
    // IDB -- so next_pcapng()'s own loop, invoked later by the first real next() call, resumes
    // from that exact position and parses that block (and everything after it) exactly as it
    // always has, with no awareness this prefetch ever ran. See pcap_reader.cpp's own comment on
    // this method, and on PcapReader::info()'s class-level doc comment above, for the bug this
    // fixes: info() reading PcapFileInfo's raw linktype=0 (LINKTYPE_NULL) default for any caller
    // that queries it before ever calling next() -- e.g. cli_main.cpp's `decode -w`, which
    // constructs PcapWriter from source.linktype() once, before its packet loop starts.
    void prefetch_first_interface_linktype();
    // pcapng-only: the block loop driving next() for a pcapng file -- walks blocks from the
    // current stream position, updating interface_/info_ state as it goes, until it has a
    // packet to return (true) or reaches a clean end of file (false).
    bool next_pcapng(PcapPacket& out);

    std::string path_;
    std::ifstream stream_;
    PcapFileInfo info_;

    bool is_pcapng_ = false;
    bool pcapng_little_endian_ = true;
    std::vector<PcapNgInterface> pcapng_interfaces_;
    // Accumulates across next_pcapng() calls until take_pending_decryption_secrets() drains it --
    // see that method's own comment above for why this isn't drained automatically by next().
    std::vector<PendingDecryptionSecret> pending_decryption_secrets_;
};

}  // namespace conduitscope
