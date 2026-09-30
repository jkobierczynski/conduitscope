// SPDX-License-Identifier: Apache-2.0
// output.hpp - renders a stream of DecodedPacket values as text, JSON, or
// CSV, plus a StatsWriter that accumulates a summary instead of per-packet
// lines (used by `decode --stats` and the `info` command).
#pragma once

#include <map>
#include <ostream>
#include <set>
#include <sstream>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/time_format.hpp"

namespace conduitscope {

class OutputWriter {
public:
    virtual ~OutputWriter() = default;
    virtual void begin() {}
    virtual void write_packet(const DecodedPacket& packet) = 0;
    virtual void end() {}
};

// `resolver` is held as a reference, not owned -- it outlives every writer here, since
// cli_main.cpp's run_decode constructs exactly one Resolver per `decode` invocation, on the stack,
// before constructing whichever OutputWriter the requested --format needs, and destroys it only
// after that writer is done. Every accessor on Resolver already returns std::nullopt when its own
// lookup is n't enabled (no --oui/--nn given) or has nothing to resolve against (--resolve with no
// --hosts), so a writer never needs to ask "is this lookup even enabled" itself -- it just calls
// resolver_.oui_vendor()/hostname()/service_name() unconditionally and renders whatever comes
// back, or nothing at all on a miss. See resolver.hpp's own file header for the full "annotation,
// never replacement" contract every writer below follows.
// `show_vlan` (default true, every constructor below) governs whether a VLAN-tagged packet's
// 802.1Q VLAN ID (DecodedPacket::has_vlan_tag/vlan_id -- already unconditionally populated by the
// decoding layer for every Ethernet-linktype packet, see link_layer.cpp's parse_ethernet) is shown
// at all. Unlike the OUI/hostname/service-name annotations above, this isn't a resolver lookup
// that can simply return nothing on a miss -- the VLAN ID is a base decoded fact -- so `decode`'s
// `--no-vlan` flag (cli_main.cpp) wires straight into this constructor parameter instead of going
// through Resolver, the same "pure display toggle" precedent TextWriter's own `color` parameter
// already set.
// `show_direction` (default true, every constructor below) is the same kind of pure display
// toggle as `show_vlan` just above, for DecodedPacket::has_direction/direction_client_is_src/
// direction_source (FlowDirectionTracker, see flow_direction.hpp -- populated by `decode`'s own
// run_decode loop before a packet ever reaches a writer, same as VLAN unwrapping happens before
// this class ever sees the packet) -- `decode`'s `--no-direction` flag (cli_main.cpp) wires
// straight into this constructor parameter. TextWriter folds it into the packet's head line
// itself (see write_packet's own comment) rather than a separate line, colored by
// DirectionSource::PortHeuristic vs. the other two tiers -- see DirectionSource's own comment
// (decoder.hpp) for why only that tier can actually be wrong. JsonWriter omits both fields
// entirely when false (never just null), the same "omit outright, not just a value" convention
// `show_vlan` already set for has_vlan_tag/vlan_id above; CsvWriter's direction_source/
// direction_client_ip columns always exist (CSV can't omit a column conditionally) but render
// empty, the same "column always exists" precedent `show_vlan`'s own comment already documents
// for its own vlan_id column just below.
// `time_format`/`time_offset` (default TimeFormat::Epoch/TimeOffset{}, every constructor below)
// govern how each packet's timestamp is rendered -- see time_format.hpp's file header comment for
// what each value does. Epoch reproduces today's original raw-seconds-since-epoch rendering
// byte-for-byte, so a writer constructed without passing these two (or with them left at their
// defaults) behaves exactly as before `decode`'s own `-t`/--time-format/--time-offset flags
// (cli_main.cpp) existed at all.
class TextWriter : public OutputWriter {
public:
    explicit TextWriter(std::ostream& out, bool color, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                         bool show_direction = true, bool show_mac = true, bool verbose = true)
        : out_(out), color_(color), resolver_(resolver), show_vlan_(show_vlan),
          time_(time_format, time_offset), show_direction_(show_direction), show_mac_(show_mac),
          verbose_(verbose) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    bool color_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
    // `show_mac` (default true, matching every other toggle above so a caller that doesn't pass it
    // keeps this class's original always-on behavior) governs whether the "eth <src> -> <dst>" line
    // (DecodedPacket::src_mac/dst_mac, plus any OUI vendor annotation Resolver supplies and the VLAN
    // ID show_vlan_ already governs) is shown at all -- decode's -e/--ether flag (cli_main.cpp,
    // defaulting to false there, mirroring tcpdump's own -e) wires straight into this constructor
    // parameter, the same "pure display toggle" precedent show_vlan/show_direction already set. Only
    // TextWriter gets this: JsonWriter/CsvWriter always include src_mac/dst_mac as base fields (like
    // src_ip/dst_ip), by design -- see this file's own header comment -- so machine-readable output
    // never loses data just to make a human-facing dump more compact. VLAN display is independent of
    // this: a VLAN-tagged packet still shows "vlan <id>" (on its own line) when show_mac_ is false,
    // since 802.1Q membership isn't specifically a MAC-address fact and show_vlan_ already has its
    // own default-on toggle -- see write_packet's own comment for exactly how the two combine.
    bool show_mac_;
    // `verbose` (default true here, matching every other toggle above so a caller that doesn't
    // pass it keeps this class's original always-on behavior) governs whether per-packet notes
    // ("note: ..." lines) and the "(client X -- handshake/content/port-heuristic)" direction-tier
    // suffix are shown at all -- decode's own -v/--verbose flag (cli_main.cpp, defaulting to
    // false there) wires straight into this constructor parameter. Text output only, the same
    // "pure display toggle" scope show_mac_ already has: JsonWriter/CsvWriter/FieldsWriter are
    // unaffected (notes are a proper structured field there, not visual clutter on a shared line --
    // see this file's own header comment) and show_direction_'s own JSON/CSV "direction_source"
    // field/column keeps working exactly as before regardless of this flag. When true, the
    // direction suffix still additionally requires show_direction_ -- verbose_ is an extra gate on
    // top of it, not a replacement, so --no-direction still suppresses it even under -v, and -v
    // alone does nothing for it if --no-direction was also given -- see write_packet's own comment.
    bool verbose_;
};

class JsonWriter : public OutputWriter {
public:
    explicit JsonWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                         bool show_direction = true)
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset),
          show_direction_(show_direction) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;
    void end() override;

private:
    std::ostream& out_;
    bool wrote_any_ = false;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
};

class CsvWriter : public OutputWriter {
public:
    explicit CsvWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                        TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                        bool show_direction = true)
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset),
          show_direction_(show_direction) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
};

// `decode -T fields -e <field>` (repeatable), mirroring tshark's own `-T fields`/`-e` -- see
// output.cpp's own FieldsWriter::write_packet comment for exactly how this is implemented (it
// reuses JsonWriter's own already-correct, already-comprehensive per-protocol field rendering
// rather than re-deriving field names/values a second time -- the only way this stays in sync with
// every one of this codebase's ~90 protocols' own JSON fields without hand-maintaining a second,
// parallel field list). One tab-separated line per packet, fields in the order `-e` was given;
// a field name JsonWriter never emits for that packet (wrong protocol, disabled by a flag, etc.)
// renders as an empty column -- the same "empty, not an error" convention tshark's own `-T fields`
// has for a field absent from a given packet.
class FieldsWriter : public OutputWriter {
public:
    explicit FieldsWriter(std::ostream& out, const Resolver& resolver, std::vector<std::string> fields,
                           bool show_vlan = true, TimeFormat time_format = TimeFormat::Epoch,
                           TimeOffset time_offset = TimeOffset{}, bool show_direction = true)
        : out_(out), resolver_(resolver), fields_(std::move(fields)), show_vlan_(show_vlan),
          time_format_(time_format), time_offset_(time_offset), show_direction_(show_direction) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    const Resolver& resolver_;
    std::vector<std::string> fields_;
    bool show_vlan_;
    TimeFormat time_format_;
    TimeOffset time_offset_;
    bool show_direction_;
};

// `decode -V,--details` -- the text-mode equivalent of tshark's own -V ("packet details"; the
// Wireshark GUI calls the same view the "Packet Details" pane), as opposed to TextWriter's
// default one-line-per-packet summary. Same "reuse JsonWriter, don't re-derive ~65 protocols'
// worth of field logic a second time" trick FieldsWriter uses just above (see that class's own
// comment and output.cpp's write_packet for exactly how): a one-shot JsonWriter renders the
// packet into a flat JSON object, parsed back via parse_flat_json_object (output.cpp, private to
// that file), then every field is printed grouped under the layer it belongs to (Frame, Ethernet
// II, Internet Protocol, Transmission Control Protocol/User Datagram Protocol, then the
// recognized application protocol's own fields, by full field name, unprefix-stripped) instead of
// flattened into one object. Unlike -v/--verbose (TextWriter's own show_mac_-adjacent toggle),
// there is no way to make -V less verbose -- completeness is the entire point, so notes and any
// detect/attack finding are always shown, and every layer is always shown regardless of
// -e/--ether/--mac-vendor (which exist only to keep TextWriter's own default line compact).
//
// Known, pre-existing limitation inherited from parse_flat_json_object (see its own comment,
// output.cpp): SMB and the DCE/RPC-over-SMB families (netlogon/samr/lsarpc/srvsvc/wkssvc/drsuapi
// calls, and DCOM) emit genuinely nested "X_messages"/"X_calls" JSON arrays-of-objects with
// unprefixed inner keys -- the flat-line parser already can't reconstruct that nesting for
// `-T fields` today, and this writer inherits the identical gap (last inner object's keys win,
// per-message granularity lost) rather than fixing it, which would need a real JSON tree parser,
// out of scope here. The base layers and `summary` line still render correctly for these packets
// either way.
class DetailWriter : public OutputWriter {
public:
    explicit DetailWriter(std::ostream& out, bool color, const Resolver& resolver, bool show_vlan = true,
                           TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                           bool show_direction = true)
        : out_(out), color_(color), resolver_(resolver), show_vlan_(show_vlan),
          time_(time_format, time_offset), show_direction_(show_direction) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    bool color_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
};

// `decode --format zeek` -- Grok review item 8's "optional Zeek/Malcolm exporter or Zeek-style
// TSV" bullet (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md), scoped (per an
// AskUserQuestion decision with Jurgen) to a foundation-first phase: Zeek's own real conn.log
// schema and TSV envelope -- not a made-up "Zeek-style" approximation, and not yet the
// full per-protocol ICSNPP-compatible logs (modbus_detailed.log, bacnet_property.log, etc.) a
// later phase may add. conn.log is the right foundation because it's the join key every other
// Zeek/Malcolm log (including ICSNPP's own) hangs off of via `uid` -- see this class's own .cpp
// comment for exactly which of Zeek's 21 documented Conn::Info fields this first pass populates
// honestly versus leaves at Zeek's own "-" unset marker, and why, verified against
// docs.zeek.org's own conn.log/Conn::Info reference and zed.brimdata.io's own worked TSV example
// (both cited in output.cpp).
//
// Unlike every writer above, this one is NOT a per-packet streamer: Zeek's conn.log is one row
// per CONNECTION (aggregated over its whole lifetime), not one row per packet, so write_packet()
// only accumulates into an internal flow table -- nothing is written to `out` until end(), which
// emits the full TSV (header block, one row per flow in first-seen order, footer) in one shot.
// This mirrors StatsWriter's own "accumulate via write_packet(), finalize separately" shape just
// below, but end() (not a separately-named print_summary()) is where ZeekWriter's own
// finalization happens, since -- unlike StatsWriter, which `info` and `decode --stats` both reuse
// with two different header styles -- this writer has exactly one caller (`decode --format
// zeek`) and exactly one output shape, so OutputWriter's own end() hook is already the right,
// un-duplicated place for it.
class ZeekWriter : public OutputWriter {
public:
    explicit ZeekWriter(std::ostream& out) : out_(out) {}
    void write_packet(const DecodedPacket& packet) override;
    void end() override;

private:
    // One entry per bidirectional flow (proto + unordered {ip:port, ip:port} pair) -- see
    // output.cpp's own write_packet for exactly how the key is built and how "which side is
    // orig" is decided (first packet seen for that key, matching Zeek's own actual conn_id
    // semantics, not this codebase's own separate FlowDirectionTracker heuristic tiers -- a
    // deliberate choice, see output.cpp).
    struct ZeekFlow {
        size_t uid_ordinal = 0;  // assignment order == first-seen order == this flow's row order
        double first_ts = 0.0, last_ts = 0.0;
        std::string orig_h, resp_h;
        uint16_t orig_p = 0, resp_p = 0;
        std::string proto;  // "tcp" or "udp" -- see output.cpp's own scope note on why this first
                              // pass covers only those two of Zeek's four transport_proto values
        std::set<std::string> services;  // distinct DecodedPacket::protocol names seen on this
                                           // flow, excluding the generic transport-only "tcp"/"udp"
                                           // fallback labels -- see output.cpp
        size_t orig_pkts = 0, resp_pkts = 0;
        uint64_t orig_ip_bytes = 0, resp_ip_bytes = 0;
    };
    std::ostream& out_;
    std::map<std::string, ZeekFlow> flows_;      // keyed by the canonical undirected flow key
    std::vector<std::string> flow_order_;         // keys in first-seen order, for end()'s own
                                                    // chronological row output (matches Zeek's own
                                                    // conn.log ordering)
};

// Conversations/Endpoints tables (tshark's own `-z conv,ip`/`-z endpoints,ip` as design
// precedent) -- ip_conversations_/ip_endpoints_/eth_conversations_/eth_endpoints_ below are the
// only StatsWriter maps keyed by attacker-controlled, effectively unbounded-cardinality identity
// (every other map here is keyed by a small fixed vocabulary of protocol/function/opnum names),
// so unlike those, these four are capped -- same posture as kDefaultMaxInventoryAssets/
// kDefaultMaxInventoryEdges (asset_inventory.hpp) for the identical class of risk. Applied
// independently per map (an IP-conversation flood and an Ethernet-conversation flood each get
// their own budget, not a shared one), via --max-conversations/--max-endpoints (cli_main.cpp).
inline constexpr size_t kDefaultMaxConversationEntries = 200000;
inline constexpr size_t kDefaultMaxEndpointEntries = 200000;

// Which of the four Conversations/Endpoints tables `info`'s own `-z conv,ip`/`-z endpoints,ip`/
// `-z conv,eth`/`-z endpoints,eth` (cli_main.cpp) asked for -- tshark's own `-z` is explicit,
// repeatable opt-in, not an always-on aggregate dump, so a table nobody asked for is never even
// accumulated (not just never printed): each flag below individually gates the matching pair of
// update_conversation/update_endpoint calls in StatsWriter::write_packet. All-false (the default)
// is a perfectly ordinary StatsWriter that tracks none of the four -- used by every StatsWriter
// that only wants the protocol histogram/direction-source breakdown/per-protocol sections below.
struct RequestedStatsTables {
    bool ip_conversations = false;
    bool ip_endpoints = false;
    bool eth_conversations = false;
    bool eth_endpoints = false;
    // ROADMAP item 108 ("Follow stream as a first-class object") -- `-z conv,tcp`. Unlike
    // ip_conversations/eth_conversations above (address-only, so one UDP and one TCP session
    // between the same two hosts collapse into a single row), this is keyed by address:PORT pair
    // -- a genuinely different, TCP-specific view tshark's own `-z conv,tcp` mirrors, and the one
    // that actually correlates with a tcp.stream index a later `-z follow,tcp,stream,<N>` can ask
    // for (see StatsWriter::AddrConversationStats::stream_index below).
    bool tcp_conversations = false;
};

// Accumulates counts instead of printing per packet; call begin()/write_packet()
// as usual, then print_summary(out) once at the end (that's separate from
// OutputWriter::end() so callers building a StatsWriter for different reasons -- currently just
// `info` -- can share this class while formatting their own headers differently).
class StatsWriter : public OutputWriter {
public:
    // tables: which of the four Conversations/Endpoints tables to track -- see
    // RequestedStatsTables' own comment above. max_conversations/max_endpoints: 0 means "use the
    // default" (kDefaultMaxConversationEntries/kDefaultMaxEndpointEntries above) -- 0 is never
    // itself a usable cap (an all-zero cap would silently produce permanently-empty tables), so it
    // doubles as "not explicitly set," the same "0 means use the built-in default" sentinel several
    // existing --max-* options already use (see cli_main.cpp's build_resource_limits). Every
    // existing call site that builds a StatsWriter with no arguments keeps compiling unchanged and
    // gets a writer that tracks none of the four tables, with the default caps ready for whenever
    // one is requested.
    // stat_output_only: ROADMAP item 109 -- Jurgen's own explicit request, "If the -z option is
    // used, no output is expected except of the -z option output." False (the default) is `info`'s
    // original behavior, unchanged: print_summary always prints the packet-count/protocols
    // histogram and every populated protocol-specific section, with the four Conversations/
    // Endpoints/`conv,tcp` tables (still individually gated by `tables` above) interleaved among
    // them. True -- set by `info` only when at least one `-z` value was actually given, whether
    // `info` was typed explicitly or (item 109) selected automatically because `-z` appeared with
    // no subcommand at all -- makes print_summary skip everything EXCEPT those four tables: no
    // packet count, no histogram, no per-protocol sections. write_packet's own accumulation is
    // completely unaffected either way -- this only changes what print_summary chooses to render
    // from what's already been counted.
    explicit StatsWriter(RequestedStatsTables tables = RequestedStatsTables{},
                          size_t max_conversations = 0, size_t max_endpoints = 0,
                          bool stat_output_only = false);
    void write_packet(const DecodedPacket& packet) override;
    void print_summary(std::ostream& out) const;

    size_t total_packets() const { return total_packets_; }

private:
    // Shared shape for both the IPv4 and the raw-Ethernet conversation/endpoint tables -- the
    // fields mean the same thing at either layer, only the address strings' own format differs
    // (dotted-quad vs colon-hex MAC). "A"/"B" are assigned once, from whichever address sent the
    // conversation's very first packet (address_a = that packet's src, address_b = its dst) --
    // matches tshark's own A/B assignment convention, and ZeekWriter's own identical orig_h/resp_h
    // "first packet seen becomes orig" precedent just above in this same file -- NOT an alphabetic
    // tiebreak (that's used only for the internal, never-displayed map key, so A<->B and B<->A
    // packets collapse into one entry regardless of which side happened to be "src" on any given
    // packet).
    struct AddrConversationStats {
        std::string address_a, address_b;
        uint64_t frames_a_to_b = 0, bytes_a_to_b = 0;
        uint64_t frames_b_to_a = 0, bytes_b_to_a = 0;
        double first_ts = 0.0, last_ts = 0.0;
        // ROADMAP item 108 -- only ever set (to >= 0) for tcp_conversations_'s own rows; always -1
        // (and never rendered, see print_conversations) for ip_conversations_/eth_conversations_,
        // which have no stream-index concept. This session's 0-based tcp.stream index (see
        // FollowStreamWriter's own comment for the numbering rule) -- printed alongside the row so
        // a reader can go straight from "-z conv,tcp" to the matching "-z follow,tcp,stream,<N>".
        int64_t stream_index = -1;
    };
    // tx/rx are this address's own role: tx = frames where this address was the source, rx =
    // frames where it was the destination -- the address-centric analog of AddrConversationStats'
    // pair-centric a_to_b/b_to_a above.
    struct AddrEndpointStats {
        uint64_t tx_frames = 0, tx_bytes = 0;
        uint64_t rx_frames = 0, rx_bytes = 0;
    };
    // Shared update logic for all four maps below (IP and Ethernet each have one conversation map
    // and one endpoint map) -- src/dst are already-formatted address strings (dotted-quad or
    // colon-hex MAC, whichever table this call is for), bytes is DecodedPacket::original_len (the
    // on-the-wire frame length, matching tshark's own frame.len-based tallying -- correct even
    // under a truncating snaplen), ts is DecodedPacket::timestamp. Once table.size() == max_entries
    // and this pair/address is not already tracked, the packet is dropped from THIS table only
    // (every other StatsWriter counter for the same packet is unaffected) and *truncated is set --
    // print_summary reports that with a trailing warning line, see output.cpp.
    // stream_index: -1 (the default) for ip_conversations_/eth_conversations_, which never set it;
    // tcp_conversations_'s own call site passes its session's real 0-based tcp.stream index --
    // stored on the entry ONLY the first time it's created (a conversation's stream index never
    // changes once assigned, same as address_a/address_b above), see AddrConversationStats' own
    // comment.
    static void update_conversation(std::map<std::string, AddrConversationStats>& table,
                                     std::vector<std::string>& order, bool& truncated,
                                     size_t max_entries, const std::string& src,
                                     const std::string& dst, uint64_t bytes, double ts,
                                     int64_t stream_index = -1);
    static void update_endpoint(std::map<std::string, AddrEndpointStats>& table,
                                 std::vector<std::string>& order, bool& truncated,
                                 size_t max_entries, const std::string& addr, bool is_tx,
                                 uint64_t bytes);
    // Rendering helpers for print_summary (output.cpp) -- label is e.g. "ipv4 conversations"/
    // "ethernet endpoints", used verbatim as the printed section header. Rows are sorted by total
    // bytes descending (a stable_sort over `order`, so equal-byte entries keep their first-seen
    // order as a deterministic tiebreak) -- more useful for scanning a report than raw first-seen
    // order, and matches what Wireshark's own Conversations/Endpoints GUI defaults to sorting by.
    // Each is a no-op (prints nothing, not even a header) when `table` is empty, matching every
    // other conditional block in print_summary.
    static void print_conversations(std::ostream& out, const char* label,
                                     const std::map<std::string, AddrConversationStats>& table,
                                     const std::vector<std::string>& order, bool truncated,
                                     size_t max_entries);
    static void print_endpoints(std::ostream& out, const char* label,
                                 const std::map<std::string, AddrEndpointStats>& table,
                                 const std::vector<std::string>& order, bool truncated,
                                 size_t max_entries);

    RequestedStatsTables tables_;  // which of the four tables write_packet actually accumulates
    size_t max_conversations_;  // resolved (never 0) in the constructor -- see output.cpp
    size_t max_endpoints_;
    bool stat_output_only_;  // ROADMAP item 109 -- see the constructor's own comment above

    // Populated from DecodedPacket::src_ip/dst_ip whenever has_ip -- see write_packet. Every IP
    // fragment (buffering, abandoned, or the one that completes reassembly) already has has_ip and
    // src_ip/dst_ip populated before Decoder::reassemble_ip_fragment even runs, so a fragment
    // counts as ordinary traffic between those two hosts with no special-casing needed here.
    std::map<std::string, AddrConversationStats> ip_conversations_;
    std::vector<std::string> ip_conversation_order_;
    bool ip_conversations_truncated_ = false;
    std::map<std::string, AddrEndpointStats> ip_endpoints_;
    std::vector<std::string> ip_endpoint_order_;
    bool ip_endpoints_truncated_ = false;

    // Populated from DecodedPacket::src_mac/dst_mac whenever has_ethernet -- for EVERY Ethernet-
    // linktype frame, IP-carrying or not, so an IPv4 packet is counted in both its IP conversation
    // above AND its underlying Ethernet conversation here, independently -- exactly like tshark's
    // own conv,ip and conv,eth are two independent layers, not parent/child. This is what actually
    // gives visibility into PROFINET RT/GOOSE/SV/EtherCAT/POWERLINK/unrecognized-EtherType traffic,
    // which has no IP layer at all (the same raw-L2 blind spot ROADMAP item 103's own
    // ethertypes:/to_macs: policy-side work closed for `policy validate`).
    std::map<std::string, AddrConversationStats> eth_conversations_;
    std::vector<std::string> eth_conversation_order_;
    bool eth_conversations_truncated_ = false;
    std::map<std::string, AddrEndpointStats> eth_endpoints_;
    std::vector<std::string> eth_endpoint_order_;
    bool eth_endpoints_truncated_ = false;

    // ROADMAP item 108 -- `-z conv,tcp`. Keyed by an undirected "ip#port<->ip#port" session string
    // (this class's own tcp_conversation_session_key, output.cpp -- '#' not ':' between address and
    // port for the same IPv6-ambiguity reason decoder.cpp's tcp_session_key already documents;
    // independently reimplemented here rather than shared with decoder.cpp's own anonymous-
    // namespace helper of the same name, since StatsWriter only ever sees already-decoded
    // DecodedPacket fields, never decoder-internal state). tcp_stream_index_/next_tcp_stream_
    // assign each session the same 0-based, first-seen-order index FollowStreamWriter's own,
    // entirely separate indexer would assign for the identical packets -- see that class's own
    // comment for why two independent indexers over the same packet stream are guaranteed to agree
    // rather than needing to be the same object.
    std::map<std::string, AddrConversationStats> tcp_conversations_;
    std::vector<std::string> tcp_conversation_order_;
    bool tcp_conversations_truncated_ = false;
    std::map<std::string, uint64_t> tcp_stream_index_;
    uint64_t next_tcp_stream_ = 0;

    size_t total_packets_ = 0;
    std::map<std::string, size_t> protocol_counts_;
    // Keyed by direction_source_name ("handshake"/"content"/"port-heuristic") -- counted whenever
    // has_direction is true, i.e. TCP flows only (FlowDirectionTracker's own scope, see
    // flow_direction.hpp), across every protocol at once rather than gated on p.protocol like the
    // per-protocol maps below, since direction determination is cross-cutting, not
    // protocol-specific -- see DirectionSource's own comment (decoder.hpp). Empty (and so never
    // printed, see print_summary) for `info`, which never runs FlowDirectionTracker at all.
    std::map<std::string, size_t> direction_source_counts_;
    std::map<std::string, size_t> modbus_function_counts_;
    size_t modbus_exceptions_ = 0;
    // Count of responses authoritatively paired (by MBAP transaction ID + TCP session, not the
    // payload-shape heuristic) to a specific earlier request -- see Decoder::pair_modbus_transaction.
    size_t modbus_paired_responses_ = 0;
    // registration-model decoder refactor (see decoder.hpp's DecodedPacket::result): TwinCAT's own
    // Command ID breakdown, read from DecodedPacket::result rather than a twincat_* flat field --
    // see write_packet's own p.protocol == "twincat" block (output.cpp) and twincat.hpp's file
    // header comment for why this protocol has no flat fields at all.
    std::map<std::string, size_t> twincat_command_counts_;
    size_t twincat_paired_responses_ = 0;  // authoritatively paired by Invoke ID, not a heuristic
                                             // -- TwinCAT's analog of modbus_paired_responses_ above
    // MELSEC's own command-name breakdown (melsec.hpp), read from DecodedPacket::result the same
    // way twincat_command_counts_ is above. Keyed by MelsecFrame::command_name -- "response" for an
    // unmatched response whose own command couldn't be determined (see melsec.hpp's "RESPONSE
    // DECODING NEEDS SESSION CONTEXT" paragraph), never double-counted against the matched name a
    // later-arriving response might otherwise also claim.
    std::map<std::string, size_t> melsec_command_counts_;
    // Session-scoped matches (see melsec.hpp/melsec.cpp) -- NOT authoritative pairing like
    // twincat_paired_responses_ above (there's no unique per-request ID on the wire to make it
    // authoritative), just "a response was matched to its most recently sent, not-yet-answered
    // request on the same session."
    size_t melsec_matched_responses_ = 0;
    // FINS's own command-name breakdown (fins.hpp), read from DecodedPacket::result the same way
    // melsec_command_counts_ is above. Keyed by FinsFrame::command_name -- unlike MELSEC, a FINS
    // response self-describes its own command code (see fins.hpp's "A GENUINE ARCHITECTURAL
    // DIFFERENCE FROM MELSEC" paragraph), so this never falls back to a generic "response" bucket
    // the way melsec_command_counts_ sometimes must.
    std::map<std::string, size_t> fins_command_counts_;
    // Session-scoped matches (see fins.hpp/fins.cpp) -- NOT authoritative pairing, the same
    // "matched to the most recently sent, not-yet-answered request on this session" posture
    // melsec_matched_responses_ has above, kept narrower in scope (see FinsFlowState's own comment
    // -- only Memory Area Read/Multiple Memory Area Read responses actually need it).
    size_t fins_matched_responses_ = 0;
    // Curated Note 5 (kerberos.hpp's file header comment) -- named KRB-ERROR error-code counts,
    // keyed by error_name ("KDC_ERR_PREAUTH_REQUIRED", or "error N" for an unnamed code), read
    // from DecodedPacket::result the same way twincat_command_counts_ is above.
    std::map<std::string, size_t> kerberos_error_counts_;
    // Curated Note 6 (ldap.hpp's file header comment) -- named LDAP resultCode counts, keyed by
    // result_code_name ("invalidCredentials", or "resultCode N" for an unnamed code), read from
    // DecodedPacket::result the same way kerberos_error_counts_ is above.
    std::map<std::string, size_t> ldap_result_code_counts_;
    // Curated Note 6 (smb.hpp's file header comment) -- named SMB Status counts from SESSION_SETUP
    // responses only (not every SMB2 command's own Status -- this stays focused on authentication
    // outcomes, the direct SMB-side analog of kerberos_error_counts_/ldap_result_code_counts_
    // above), keyed by status_name ("STATUS_LOGON_FAILURE", or "0xNNNNNNNN" for an unnamed code),
    // read from DecodedPacket::result the same way ldap_result_code_counts_ is above.
    std::map<std::string, size_t> smb_status_counts_;
    // Netlogon opnum counts (netlogon.hpp), the Netlogon-side analog of smb_status_counts_ above
    // -- keyed by netlogon_opnum_name() (e.g. "NetrServerAuthenticate3", or "opnum N" for an
    // uncurated one), incremented once per decoded NetlogonCall REQUEST (not per response, so a
    // request/response pair counts once, the same "count the request side" convention
    // kerberos_error_counts_'s own sibling counters don't need but this one does to avoid
    // double-counting a call twice).
    std::map<std::string, size_t> netlogon_opnum_counts_;
    // Same convention as netlogon_opnum_counts_ above, one map per Phase-1 interface (samr.hpp/
    // lsarpc.hpp).
    std::map<std::string, size_t> samr_opnum_counts_;
    std::map<std::string, size_t> lsarpc_opnum_counts_;
    // Same convention, phase 2's own two interfaces (srvsvc.hpp/wkssvc.hpp).
    std::map<std::string, size_t> srvsvc_opnum_counts_;
    std::map<std::string, size_t> wkssvc_opnum_counts_;
    // Same convention, phase 3's own single interface (drsuapi.hpp) -- see that file's own header
    // comment for why this map is essentially always empty in a realistic capture.
    std::map<std::string, size_t> drsuapi_opnum_counts_;
    std::map<std::string, size_t> s7comm_function_counts_;
    std::map<std::string, size_t> dnp3_function_counts_;
    std::map<std::string, size_t> iec104_asdu_type_counts_;
    std::map<std::string, size_t> enip_command_counts_;
    std::map<std::string, size_t> enip_cip_service_counts_;
    size_t enip_io_datagram_count_ = 0;  // CIP I/O (implicit messaging) UDP datagrams -- see enip_has_io
    std::map<std::string, size_t> profinet_frame_id_counts_;
    size_t profinet_dcp_count_ = 0;
    size_t profinet_cyclic_count_ = 0;
    size_t goose_pdu_count_ = 0;
    size_t goose_gse_management_count_ = 0;
    size_t goose_simulated_count_ = 0;
    size_t sv_frame_count_ = 0;
    size_t sv_asdu_total_ = 0;  // summed across every decoded SV frame, since one frame can carry
                                 // more than one ASDU -- see sv_asdu_count
    std::map<std::string, size_t> ethercat_frame_type_counts_;
    size_t ethercat_datagram_total_ = 0;  // summed across every decoded EtherCAT frame, since one
                                            // frame can carry more than one datagram -- see
                                            // ethercat_datagram_count
    std::map<std::string, size_t> stp_bpdu_type_counts_;      // "Configuration"/"Rapid/Multiple
                                                                 // Spanning Tree"/"Topology Change
                                                                 // Notification"
    std::map<std::string, size_t> stp_protocol_version_counts_;  // "STP (802.1D)"/"RSTP (802.1w)"/
                                                                    // "MSTP (802.1s)"/"SPB (802.1aq)"
    size_t stp_mstp_count_ = 0;      // full MST extension decoded -- see stp_is_mstp
    size_t stp_msti_total_ = 0;      // summed across every decoded MST BPDU, since one can carry
                                       // more than one MSTI Configuration Message
    size_t stp_tc_count_ = 0;        // Configuration/RST/MST BPDUs with the TC flag set
    std::map<std::string, size_t> cdp_device_id_counts_;  // keyed by CdpFrame::device_id, only when
                                                             // has_device_id
    std::map<std::string, size_t> cdp_platform_counts_;   // keyed by CdpFrame::platform, only when
                                                             // has_platform
    std::map<std::string, size_t> cdp_capability_counts_; // one increment per named capability bit
                                                             // seen (see cdp_render_capabilities),
                                                             // across every decoded CDP frame -- a
                                                             // device with several bits set
                                                             // increments several entries
    std::map<uint16_t, size_t> cdp_native_vlan_counts_;   // keyed by CdpFrame::native_vlan, only
                                                             // when has_native_vlan -- a histogram,
                                                             // per this task's own suggested stats
                                                             // shape
    std::map<std::string, size_t> devicenet_group_counts_;   // "Group 1"/"Group 2"/"Group 3"/
                                                                // "Group 4"/"Unclassified (0x07F0-0x07FF)"
    std::map<std::string, size_t> devicenet_message_type_counts_;
    size_t devicenet_fragmented_count_ = 0;  // Group 3 messages with the Fragmentation flag set
    size_t devicenet_fd_count_ = 0;          // CAN FD frames -- see devicenet.hpp's scope note
    // CANopen's own breakdown (canopen.hpp) -- function-code/message-type counts, the task's own
    // requested shape, keyed by CanopenFrame::message_type_name ("NMT"/"SYNC"/"TIME STAMP"/"EMCY"/
    // "PDO1 (tx)"/.../"Default-SDO (rx)"/"NMT Error Control"/"LSS (Master)"/"LSS (Slave)"/"Unknown").
    std::map<std::string, size_t> canopen_message_type_counts_;
    // SAE J1939's own breakdown (j1939.hpp) -- PGN counts, the task's own requested shape, keyed by
    // "<PGN> (<name>)" or a bare "<PGN>" when uncurated. j1939_dm1_active_dtc_count_ is this
    // decoder's own headline finding (a summed count of every individual DTC across every decoded
    // DM1 message) -- printed on its own, clearly-labeled line in --stats output, matching this
    // codebase's own "never buried" posture already established for ipmi_cipher_suite_zero_count_.
    std::map<std::string, size_t> j1939_pgn_counts_;
    size_t j1939_dm1_active_dtc_count_ = 0;
    std::map<std::string, size_t> bacnet_bvlc_function_counts_;
    std::map<std::string, size_t> bacnet_service_counts_;  // keyed by APDU service-choice name,
                                                              // only when bacnet_has_apdu
    std::map<std::string, size_t> hartip_message_type_counts_;
    std::map<std::string, size_t> hartip_command_counts_;  // keyed by "N (Name)" or "N", only when
                                                              // hartip_has_pass_through
    std::map<std::string, size_t> opcua_message_type_counts_;  // "Hello"/"OpenSecureChannel"/"Message"/...
    std::map<std::string, size_t> opcua_service_counts_;  // keyed by service name, only when
                                                             // opcua_service_recognized
    std::map<std::string, size_t> mms_pdu_counts_;      // "confirmed-RequestPDU"/"initiate-RequestPDU"/...
    std::map<std::string, size_t> mms_service_counts_;  // keyed by service name, only when
                                                          // MmsFrame::service_recognized (mms.hpp)
    std::map<std::string, size_t> mqtt_packet_type_counts_;  // "CONNECT"/"PUBLISH"/...
    size_t mqtt_sparkplug_count_ = 0;  // PUBLISH packets whose topic matched the spBv1.0 namespace
    std::map<std::string, size_t> mqtt_sparkplug_message_type_counts_;  // "NBIRTH"/.../"STATE",
                                                                          // only when mqtt_is_sparkplug
    std::map<std::string, size_t> s7plus_pdu_type_counts_;  // "Connect"/"Data"/"DataFW1_5"/"Keep Alive"
    std::map<std::string, size_t> s7plus_function_counts_;  // keyed by function name, only when
                                                               // s7plus_has_function
    size_t s7plus_body_decoded_count_ = 0;  // Tier-1 functions this decoder fully decoded (see
                                              // s7commplus.hpp); the gap vs. s7plus_has_function's
                                              // own total count is everything left Tier-2
    std::map<std::string, size_t> ffhse_protocol_counts_;  // "FDA Session Management"/"SM"/"FMS"/
                                                              // "LAN Redundancy"
    std::map<std::string, size_t> ffhse_message_counts_;   // keyed by ffhse_message_name, only
                                                              // when ffhse_recognized
    size_t ffhse_body_decoded_count_ = 0;  // Tier-1 messages this decoder fully decoded -- the gap
                                             // vs. ffhse_message_counts_'s own total is everything
                                             // left Tier-2 or unrecognized
    // Keyed by "<protocol> <opcode name>" (e.g. "dns Query", "mdns Query", "llmnr Query") --
    // one shared map for all three DNS-message-shaped protocols, since they share DecodedPacket's
    // own dns_* field family too -- see dns.hpp.
    std::map<std::string, size_t> dns_family_opcode_counts_;
    std::map<std::string, size_t> nbns_opcode_counts_;
    std::map<std::string, size_t> doh_provider_counts_;  // keyed by doh_matched_provider
    std::map<std::string, size_t> winrm_action_counts_;  // keyed by wsa_action_name, requests only
    std::map<std::string, size_t> dcom_call_counts_;  // keyed by "<interface> <opnum_name>",
                                                         // requests only -- Phase 5's own analog of
                                                         // drsuapi_opnum_counts_ above, but keyed by
                                                         // interface+opnum together since DCOM (unlike
                                                         // every earlier interface in this batch) can
                                                         // have more than one interface bound per
                                                         // session -- see dcom.hpp's own STATE section
    // GE SRTP's own service-request-name breakdown (ge_srtp.hpp), read from DecodedPacket::result
    // the same way melsec_command_counts_ above is. Keyed by GeSrtpFrame::service_request_name --
    // requests only (a response's own name is only known once matched, see below).
    std::map<std::string, size_t> ge_srtp_service_counts_;
    // Session-scoped matches (see ge_srtp.hpp/ge_srtp.cpp) -- UNLIKE melsec_matched_responses_/
    // fins_matched_responses_ above, this IS authoritative pairing (GE SRTP's own Sequence Number
    // is a genuine wire-carried transaction ID) -- the same tier modbus_paired_responses_/
    // twincat_paired_responses_ above already established.
    size_t ge_srtp_paired_responses_ = 0;
    // BSAP's own breakdown (bsap.hpp) -- how many messages used each of the two framings this
    // decoder recognizes, and how many link-layer NAKs were observed (see bsap.hpp's own
    // SECURITY CONTEXT section for why this decoder does not attempt a full per-operation
    // breakdown the way ge_srtp_service_counts_ above does: BSAP's own RDB function codes have no
    // confirmed numeric meaning in any source this project found).
    size_t bsap_serial_tunnel_count_ = 0;
    size_t bsap_ip_native_count_ = 0;
    size_t bsap_nak_count_ = 0;
    // CC-Link IE's own breakdown (cclink_ie.hpp) -- one counter per message kind this decoder
    // recognizes, plus how many cyclic responses reported a non-success end code.
    size_t cclink_ie_cyclic_request_count_ = 0;
    size_t cclink_ie_cyclic_response_count_ = 0;
    size_t cclink_ie_cyclic_error_count_ = 0;
    size_t cclink_ie_node_search_count_ = 0;
    size_t cclink_ie_set_ip_address_count_ = 0;
    std::map<std::string, size_t> rip_command_counts_;   // keyed by rip_command_name
    std::map<std::string, size_t> icmp_type_counts_;     // keyed by icmp_type_name
    // Roadmap item 45 (icmpv6.hpp/dhcpv6.hpp) -- the same "one map, keyed by rendered name" shape
    // icmp_type_counts_/rip_command_counts_ already use. The curated RA-collision/RA-flood/NS-NA-
    // spoofing/DHCPv6-exhaustion/rogue-server findings themselves (ipv6_attack_detect.hpp) are NOT
    // separately counted here -- they live only as per-packet notes, the same posture ICMP
    // Redirect's own note already has (no dedicated ICMP-Redirect counter either).
    std::map<std::string, size_t> icmpv6_type_counts_;     // keyed by icmpv6_type_name
    std::map<std::string, size_t> dhcpv6_msg_type_counts_; // keyed by dhcpv6_msg_type_name
    std::map<std::string, size_t> igmp_type_counts_;     // keyed by igmp_type_name
    std::map<std::string, size_t> vrrp_version_counts_;  // "VRRPv2"/"VRRPv3"
    std::map<std::string, size_t> hsrp_version_counts_;  // "HSRPv1"/"HSRPv2"
    std::map<std::string, size_t> igrp_opcode_counts_;   // keyed by igrp_opcode_name
    std::map<std::string, size_t> pim_type_counts_;      // keyed by pim_type_name
    std::map<std::string, size_t> eigrp_opcode_counts_;  // keyed by eigrp_opcode_name
    std::map<std::string, size_t> ospf_type_counts_;     // keyed by ospf_type_name
    // CODESYS's own breakdown (codesys.hpp) -- one counter per named channel command (GET_INFO/
    // OPEN_CHANNEL/.../BLK/ACK/KEEPALIVE), plus how many Login/AUTH exchanges carried a decoded
    // username. Deliberately no per-component/per-command breakdown beyond this -- see codesys.hpp's
    // own SCOPING paragraph for why every component/command besides CmpDevice's own Login/AUTH is
    // structural-only.
    std::map<std::string, size_t> codesys_channel_command_counts_;  // keyed by channel command name
                                                                      // (or "0xNN" when unnamed)
    size_t codesys_auth_username_count_ = 0;
    // CoAP (coap.hpp) -- message Type (CON/NON/ACK/RST) and Code ("GET"/"2.05 Content"/etc, or a
    // raw "c.dd" for an unnamed Code) counts, the same "one map, keyed by rendered name" shape
    // rip_command_counts_/icmp_type_counts_ already use.
    std::map<std::string, size_t> coap_type_counts_;
    std::map<std::string, size_t> coap_code_counts_;
    // Zigbee (ieee802154.hpp/zigbee.hpp) -- counts by NWK frame type, APS frame type, and ZDP
    // cluster name (only for a frame that reached that layer -- see ZigbeeFrame::nwk_present/
    // aps_present/zdp_present), plus how many frames had NWK-layer or APS-layer security enabled
    // (and were therefore reported opaque/encrypted at that layer, see zigbee.hpp's own scope
    // notes) -- the same "one map per counted dimension, plus a couple of plain counters" shape
    // devicenet_group_counts_/devicenet_fragmented_count_ already established just above.
    std::map<std::string, size_t> zigbee_nwk_frame_type_counts_;
    std::map<std::string, size_t> zigbee_aps_frame_type_counts_;
    std::map<std::string, size_t> zigbee_zdp_cluster_counts_;
    size_t zigbee_nwk_encrypted_count_ = 0;
    size_t zigbee_aps_encrypted_count_ = 0;
    // RMCP/ASF/IPMI (rmcp.hpp) -- RMCP Class-of-Message counts (synthesized from which of the
    // three decoders/protocol ids claimed a packet, plus rmcp's own header.is_ack/class_name for
    // the generic ACK/OEM cases -- see rmcp.hpp's own DETECTION/DISPATCH for why this is a
    // complete partition), ASF Message Type counts, and IPMI NetFn/Command counts (keyed by
    // "<NetFn name> / <Command name>", falling back to raw hex for either half when unnamed, the
    // same "curated name or raw hex" fallback rip_command_counts_/icmp_type_counts_ already use).
    // ipmi_cipher_suite_zero_count_ is this decoder's own headline security finding (see rmcp.hpp's
    // own SECURITY note) and is printed on its own, clearly-labeled line in --stats output, never
    // folded into a generic map, so it can never be missed by a reader scanning for it.
    std::map<std::string, size_t> rmcp_class_counts_;
    std::map<std::string, size_t> asf_message_type_counts_;
    std::map<std::string, size_t> ipmi_netfn_command_counts_;
    size_t ipmi_cipher_suite_zero_count_ = 0;
    // AMQP 0-9-1/1.0 (amqp091.hpp/amqp10.hpp) -- method/performative counts (keyed by "Class.Method"
    // for 0-9-1, by performative name for 1.0, the same "one map, keyed by rendered name" shape
    // rip_command_counts_/coap_type_counts_ already use), plus this feature's own curated security
    // findings, each printed on its own clearly-labeled headline line in --stats output, never
    // folded into a generic map, the same "never buried" posture ipmi_cipher_suite_zero_count_
    // already establishes -- see amqp091.hpp's/amqp10.hpp's own SECURITY sections:
    //   - cleartext credential exchange (PLAIN/AMQPLAIN for 0-9-1, PLAIN for 1.0's SASL layer) --
    //     this feature's own headline finding, the AMQP analog of Cipher Suite 0/Zerologon/DCSync.
    //   - a 0-9-1 Connection/Channel.Close (or 1.0 detach/end/close) carrying an error --
    //     reply-code >= 400 for 0-9-1, any non-empty error-condition for 1.0.
    //   - 0-9-1 Basic.Publish with immediate=true (old-broker/probing signal, see amqp091.cpp).
    //   - 1.0 SASL negotiation failure (sasl-outcome code != 0).
    // DICOM (dicom.hpp) -- see write_packet's own "dicom" block and print_summary's own DICOM
    // section (output.cpp) for what each counter means; dicom_no_identity_count_ is this decoder's
    // own headline finding, the direct analog of ipmi_cipher_suite_zero_count_/
    // amqp091_cleartext_credentials_count_ above.
    std::map<std::string, size_t> dicom_pdu_type_counts_;
    std::map<std::string, size_t> dicom_command_field_counts_;
    std::map<std::string, size_t> dicom_pc_result_counts_;
    std::map<std::string, size_t> dicom_rj_reason_counts_;
    std::map<std::string, size_t> dicom_abort_source_counts_;
    size_t dicom_no_identity_count_ = 0;
    size_t dicom_cleartext_identity_count_ = 0;
    size_t dicom_compressed_ts_count_ = 0;
    size_t dicom_plain_ts_count_ = 0;
    // Tridium Niagara Fox (fox.hpp) -- see write_packet's own "fox" block and print_summary's own
    // Fox section (output.cpp) for what each counter means. fox_hello_exchange_count_ is this
    // decoder's own headline finding (the direct analog of dicom_no_identity_count_/
    // ipmi_cipher_suite_zero_count_ above -- every hello exchange this decoder sees IS, by
    // construction, unauthenticated system-identity disclosure, see fox.hpp's own SECURITY
    // section); fox_host_address_mismatch_count_ is the secondary, hostAddress-vs-peer-IP
    // internal-topology-leakage finding.
    std::map<std::string, size_t> fox_frame_type_counts_;
    size_t fox_hello_exchange_count_ = 0;
    size_t fox_host_address_mismatch_count_ = 0;
    // Ethernet POWERLINK (powerlink.hpp) -- see write_packet's own "powerlink" block and
    // print_summary's own POWERLINK section (output.cpp) for what each counter means.
    // powerlink_message_type_counts_ is the task's own requested breakdown shape (keyed by
    // PowerlinkFrame::message_type_name -- "SoC"/"PReq"/"PRes"/"SoA"/"ASnd"/"AMNI"/"AInv"/
    // "unrecognized"). The four curated findings (see powerlink.hpp's file header comment's
    // CURATED FINDINGS section) are: (1) powerlink_anomalous_nmt_command_count_, a disruptive
    // NMTCommand targeting a NodeID separately observed Operational earlier in the same capture --
    // powerlink_operational_node_ids_ is the supporting single-forward-pass state, not itself
    // printed; (2) powerlink_mn_identities_, distinct (source MAC, source NodeID) identities
    // observed sourcing an MN-only message type (SoC/PReq/SoA) -- printed only when its own size()
    // exceeds 1 (rogue-MN signature); (3) powerlink_sdo_write_by_index_count_, SDO WriteByIndex
    // operations observed; (4) powerlink_cn_sourced_nmtcommand_count_, a Controlled Node (NodeID
    // 1-239) sourcing an ASnd/NMTCommand -- only the Managing Node should ever do so.
    std::map<std::string, size_t> powerlink_message_type_counts_;
    std::set<uint8_t> powerlink_operational_node_ids_;
    size_t powerlink_anomalous_nmt_command_count_ = 0;
    std::set<std::string> powerlink_mn_identities_;
    size_t powerlink_sdo_write_by_index_count_ = 0;
    size_t powerlink_cn_sourced_nmtcommand_count_ = 0;
    std::map<std::string, size_t> amqp091_method_counts_;
    std::map<std::string, size_t> amqp10_performative_counts_;
    size_t amqp091_cleartext_credentials_count_ = 0;
    size_t amqp091_error_close_count_ = 0;
    size_t amqp091_publish_immediate_count_ = 0;
    size_t amqp10_cleartext_credentials_count_ = 0;
    size_t amqp10_error_count_ = 0;
    size_t amqp10_sasl_failure_count_ = 0;
    bool has_ts_ = false;
    double first_ts_ = 0.0, last_ts_ = 0.0;
};

// ROADMAP item 108 ("Follow stream as a first-class object") -- one `-z follow,tcp,stream,<N>` /
// `-z follow,udp,stream,<N>` request (cli_main.cpp parses each raw `-z` value into this). is_tcp
// distinguishes the two independent index spaces -- tshark's own tcp.stream/udp.stream
// convention: a TCP stream 0 and a UDP stream 0 are unrelated sessions, each numbered in its own
// separate 0,1,2,... sequence.
struct FollowStreamRequest {
    bool is_tcp = true;
    uint64_t stream_index = 0;
};

// Overrides decoder.cpp's general TCP reassembly cap (see resource_limits.hpp's
// max_reassembly_bytes) as this class's own default per-direction byte budget -- same order of
// magnitude reasoning (a single session's own reconstructed stream is bounded the same way a
// single in-progress PDU reassembly already is), overridable via `info`'s own
// --max-follow-bytes (cli_main.cpp).
inline constexpr uint64_t kDefaultMaxFollowStreamBytes = 16u * 1024u * 1024u;  // 16 MiB

// Reconstructs and prints the raw, per-direction byte stream for one or more specific TCP/UDP
// sessions -- tshark's own "Follow Stream" (`-z follow,tcp,...`/`-z follow,udp,...`) as design
// precedent, Jurgen's own framing: "tshark's follow-stream model (one directional byte stream,
// pairing, export) is what you want when a capture starts mid-session or when policy direction is
// 'who initiated'". Deliberately scoped to raw TCP/UDP bytes only -- no HTTP/TLS/HTTP-2/QUIC-aware
// reassembly (tshark's own follow,http/follow,tls/follow,http2/follow,quic variants), matching
// Jurgen's own explicit "No http, https, https/2, quic for now" scoping. See
// docs/DEVELOPMENT.md's ROADMAP item 108 for the full design writeup.
//
// MEMORY: unlike StatsWriter's conv,ip/conv,tcp tables (which must track EVERY session to build a
// complete table), this class only ever BUFFERS BYTES for the specific stream_index(es) actually
// requested -- a capture with a million TCP sessions but one `-z follow,tcp,stream,0` request
// costs the same as a capture with exactly one session. Every session still needs its INDEX
// assigned in first-seen order (tcp_stream_index_/udp_stream_index_ below), which is O(1) map
// bookkeeping per packet, not a byte buffer -- only a session matching a requested (is_tcp, index)
// pair goes on to accumulate actual payload bytes (tcp_sessions_/udp_sessions_ below). Each
// requested stream's own accumulated bytes are still capped (max_bytes_per_direction_, default
// kDefaultMaxFollowStreamBytes above) per direction, for the same "a single crafted session can't
// exhaust memory" reason every other unbounded-cardinality StatsWriter table is capped.
//
// TCP ORDERING: segments are placed by their own TCP sequence number (DecodedPacket::tcp_seq),
// relative to whichever segment this class saw FIRST in that direction (not necessarily the true
// SYN/ISN -- this is deliberate, see DecodedPacket::tcp_seq's own comment: it's what lets a
// capture that starts mid-session still follow correctly, matching tshark's own relative sequence
// numbers). An overlapping retransmission is resolved first-received-wins, the SAME policy
// decoder.cpp's own reassemble_tcp_payload uses for PDU reassembly (see that function's own
// comment) -- only genuinely new bytes past what's already recorded are appended, and a conflict
// (the overlapping bytes actually DISAGREE, not just repeat) is flagged once in the printed
// summary rather than silently favored either way. An out-of-order arrival (this segment's start
// offset is past the current contiguous end) is buffered and spliced in once the gap closes --
// see TcpDirection::pending below for the one deliberately-unhandled corner case (a segment that
// itself only partially overlaps an EXISTING pending, not-yet-contiguous segment).
//
// UDP ORDERING: none -- UDP has no sequence number, so each direction's bytes are simply
// concatenated in CAPTURE order (the order write_packet saw them), tshark's own udp.stream follow
// behavior for the same reason.
class FollowStreamWriter {
public:
    explicit FollowStreamWriter(std::vector<FollowStreamRequest> requests,
                                 uint64_t max_bytes_per_direction = 0);
    void write_packet(const DecodedPacket& p);
    void print_summary(std::ostream& out) const;

private:
    // TCP's own per-direction accumulator -- sequence-ordered, overlap-aware. See this class' own
    // file header comment ("TCP ORDERING") for the algorithm `insert_segment` (output.cpp)
    // implements over `bytes`/`pending` below.
    struct TcpDirection {
        bool have_isn = false;
        // This direction's own FIRST-CAPTURED segment's raw tcp_seq -- relative-offset-0 anchor,
        // NOT necessarily the true ISN (deliberate -- see this class's own file header comment,
        // "TCP ORDERING": it's what lets a capture that starts mid-session, missing the real SYN
        // entirely, still follow correctly). SCOPE BOUNDARY this does NOT cover: the anchor is
        // fixed forever the first time this direction is touched and never rebased, so it only
        // gives correct seq-sorted reconstruction when the first-CAPTURED segment in a direction
        // is also genuinely first in SEQUENCE order. A capture where packet reordering (NIC/driver
        // reordering, multi-path capture) put a LATER-sequenced segment ahead of an EARLIER one
        // specifically for THIS direction's very first appearance would misplace everything after
        // it (the earlier segment's own offset, computed against the wrong anchor, wraps via
        // unsigned 32-bit subtraction into an enormous "far in the future" value instead of "before
        // the start"). Reordering AFTER the anchor is already established is handled correctly
        // (see `pending` below) -- this boundary is narrow: only the anchor-establishing segment
        // itself needs to already be first in true sequence order, exactly the same limitation
        // Wireshark's own relative-sequence-number tracking has for the identical reason.
        uint32_t isn = 0;
        std::string bytes;        // contiguous bytes, from relative offset 0 up to bytes.size()
        // Segments that arrived before their predecessor (a gap not yet filled), keyed by their
        // own relative start offset -- drained into `bytes` once that offset becomes reachable
        // (i.e. equals bytes.size()). NOT itself checked for overlap against OTHER pending entries
        // (only ever checked against the committed `bytes` prefix) -- a segment that partially
        // overlaps an already-pending, not-yet-contiguous entry is simply stored at its own offset
        // as a second, separate pending entry; this requires BOTH out-of-order arrival AND an
        // overlapping retransmission of that same not-yet-delivered range to actually matter, and
        // is documented here rather than chased further.
        std::map<uint64_t, std::string> pending;
        uint64_t pending_bytes = 0;  // running total of pending values' own sizes -- avoids an
                                       // O(pending.size()) rescan on every insert's cap check
        uint64_t frames = 0;
        bool truncated = false;
        bool had_conflicting_overlap = false;
    };
    struct TcpSession {
        std::string addr_a; uint16_t port_a = 0;  // whichever endpoint sent this session's very
        std::string addr_b; uint16_t port_b = 0;   // first packet -- matches AddrConversationStats'
                                                     // own A/B convention (StatsWriter, above)
        TcpDirection a_to_b, b_to_a;
    };
    // UDP's own per-direction accumulator -- capture-order concatenation only, no sequencing (see
    // this class's own file header comment, "UDP ORDERING").
    struct UdpDirection {
        std::string bytes;
        uint64_t frames = 0;
        bool truncated = false;
    };
    struct UdpSession {
        std::string addr_a; uint16_t port_a = 0;
        std::string addr_b; uint16_t port_b = 0;
        UdpDirection a_to_b, b_to_a;
    };

    static void insert_tcp_segment(TcpDirection& dir, uint64_t offset, std::string bytes,
                                    uint64_t max_bytes);
    static void append_udp_datagram(UdpDirection& dir, const std::string& bytes, uint64_t max_bytes);
    void print_tcp_stream(std::ostream& out, uint64_t index) const;
    void print_udp_stream(std::ostream& out, uint64_t index) const;

    std::vector<FollowStreamRequest> requests_;  // de-duplicated, first-occurrence order preserved
                                                   // -- see output.cpp's constructor
    uint64_t max_bytes_per_direction_;
    std::set<uint64_t> requested_tcp_indices_, requested_udp_indices_;

    // Index assignment -- EVERY has_tcp/has_udp packet updates the matching one of these (first-
    // seen session -> next sequential index), regardless of whether that particular index was
    // ever requested; only a session matching a requested (is_tcp, index) pair goes on to get a
    // TcpSession/UdpSession entry below. Keyed by an undirected "ip#port<->ip#port" session string
    // -- see output.cpp's tcp_conversation_session_key (shared with StatsWriter's own
    // tcp_conversations_ table for the identical string shape, though each class keeps its own
    // independent map instance -- see this class' own file header comment on why that's fine).
    std::map<std::string, uint64_t> tcp_stream_index_;
    uint64_t next_tcp_stream_ = 0;
    std::map<std::string, uint64_t> udp_stream_index_;
    uint64_t next_udp_stream_ = 0;

    std::map<uint64_t, TcpSession> tcp_sessions_;  // only requested indices ever get an entry
    std::map<uint64_t, UdpSession> udp_sessions_;
};

std::string json_escape(const std::string& s);
std::string csv_escape(const std::string& s);

// Sanitizes packet-derived text for TEXT-MODE output only (TextWriter/FieldsWriter) -- never
// JSON/CSV, which have their own complete serialization rules already. See output.cpp's own
// definition for the full rationale (finding 4,
// docs/reviews/2026-09-chatgpt-security-review-patch160.md).
std::string terminal_escape(const std::string& s);

// `decode -x/--hex` -- a tcpdump/tshark-style hex+ASCII dump of one packet's raw captured bytes:
// 16 bytes per line, a 4-hex-digit byte offset, each byte as two hex digits (an extra gap after
// the 8th byte, the same "two visually separated halves" layout every classic hex dump uses), then
// the same 16 bytes rendered as ASCII (printable 0x20-0x7e verbatim, anything else as '.'). Text
// output only -- see cli_main.cpp's own run_decode for where this is called from and why it's
// gated on --format text.
void write_hex_ascii_dump(std::ostream& out, ByteSpan data);

}  // namespace conduitscope
