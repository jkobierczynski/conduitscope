// SPDX-License-Identifier: MIT
// decoder.hpp - orchestrates link/IPv4/TCP parsing and protocol dispatch
// (Modbus/DNP3) for a single captured packet, producing one DecodedPacket
// that every output writer (text/json/csv) renders from.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/pcap_reader.hpp"

namespace conduitscope {

enum class ProtocolFilter {
    Auto,         // opportunistically detect Modbus/DNP3/S7comm regardless of port
    ModbusOnly,   // only attempt Modbus decoding
    Dnp3Only,     // only attempt DNP3 decoding
    S7commOnly,   // only attempt TPKT/COTP/S7comm decoding
};

struct DecodeOptions {
    ProtocolFilter protocol_filter = ProtocolFilter::Auto;
    // Additional ports to treat as "expected" for each protocol, beyond the
    // IANA-registered defaults (502 for Modbus, 20000 for DNP3). This does
    // NOT gate detection in Auto mode (detection is payload-shape based) --
    // it only changes whether the decoded output calls a port "standard" or
    // flags it as unexpected, which is itself a useful signal when auditing
    // a conduit against a zone policy.
    std::vector<uint16_t> extra_modbus_ports;
    std::vector<uint16_t> extra_dnp3_ports;
    std::vector<uint16_t> extra_s7comm_ports;
    // If true, a parse failure at the Ethernet/IPv4/TCP layer is rethrown to
    // the caller instead of being recorded as a per-packet "parse-error"
    // result. Off by default so one malformed packet doesn't abort decoding
    // an entire capture.
    bool strict = false;
};

struct DecodedPacket {
    size_t index = 0;           // 1-based position in the capture file
    double timestamp = 0.0;     // seconds since the Unix epoch, from the pcap record header
    uint32_t captured_len = 0;
    uint32_t original_len = 0;

    bool has_ethernet = false;
    std::string src_mac, dst_mac;
    bool has_vlan_tag = false;
    uint16_t vlan_id = 0;

    bool has_ip = false;
    std::string src_ip, dst_ip;
    uint8_t ip_protocol = 0;
    uint8_t ttl = 0;

    bool has_tcp = false;
    uint16_t src_port = 0, dst_port = 0;
    std::string tcp_flags;

    // "modbus", "dnp3", "s7comm", "cotp" (recognized TPKT/COTP framing but not
    // S7comm inside it -- e.g. a connection setup frame), "tcp" (recognized
    // transport, no app-layer match), "non-tcp", "non-ip", "unsupported-link",
    // or "parse-error".
    std::string protocol;
    std::string summary;
    std::vector<std::string> notes;

    // Only set when protocol == "modbus"; useful for downstream JSON consumers.
    bool modbus_is_exception = false;
    std::string modbus_function_name;

    // Only set when protocol == "s7comm" and a function code was decoded.
    bool s7comm_has_function = false;
    std::string s7comm_function_name;

    // Only populated for Read Var / Write Var packets whose item addressing was decoded
    // (see S7Item::tag in s7comm.hpp) -- Step7-style tags like "DB10.DBW100", "I0.0", "MB50".
    // Request packets: the addresses being read/written. Response packets: empty (a response's
    // parameter block doesn't repeat the addresses; see s7comm_value_summaries below for what it
    // returned instead). Capped at 50 entries so a heavily batched request can't blow up JSON output.
    std::vector<std::string> s7comm_item_tags;
    // Only populated for Read Var / Write Var response packets: one short rendering per returned
    // value or return code (e.g. "0004" for a 2-byte value, "Success", "Object does not exist").
    // Same 50-entry cap as s7comm_item_tags.
    std::vector<std::string> s7comm_value_summaries;

    // Only set when protocol == "dnp3" and this fragment's application layer was decoded (see
    // Dnp3ApplicationFragment::application_decoded in dnp3.hpp -- false for a fragment that spans
    // multiple data-link frames, which only gets its transport header decoded).
    bool dnp3_has_function = false;
    std::string dnp3_function_name;
    // One entry per object header decoded in this fragment (e.g. "g1v2 (Binary Input)"), capped
    // at 50 entries for the same reason as s7comm_item_tags.
    std::vector<std::string> dnp3_object_headers;
    // One entry per decoded point value across every object header in this fragment (e.g.
    // "g1v2 idx=0: 1 [ONLINE]"), for the group/variation combinations in the point-format table
    // (see dnp3.hpp) -- empty for an object header outside that table, or when no object headers
    // had any points (e.g. a Class 0 poll). Capped at 50 entries, same reason as s7comm_items.
    std::vector<std::string> dnp3_point_values;
};

// Cross-packet DNP3 fragment-reassembly state for one directional TCP flow (src ip:port -> dst
// ip:port) -- see Decoder::dnp3_reassembly_ and Decoder::process_dnp3_frame. A DNP3 fragment can
// span more than one data-link frame (transport FIR=1 on the first, FIN=1 on the last), and each
// of those frames can arrive in its own separate TCP segment/packet -- reassembling that requires
// remembering, per flow, the application-layer bytes buffered so far and the next sequence number
// expected, across however many Decoder::decode() calls it takes for the rest to show up. Not
// meant for use outside Decoder; exposed here only because it's a plain-data member type.
struct Dnp3FragmentReassembly {
    bool in_progress = false;
    std::vector<uint8_t> buffered_app_bytes;  // concatenated post-transport-byte bytes so far
    uint8_t last_seq = 0;                     // transport SEQ of the most recently buffered frame
    size_t frame_count = 0;                   // data-link frames contributed so far
};

class Decoder {
public:
    explicit Decoder(DecodeOptions options) : options_(std::move(options)) {}

    // May throw ParseError only when options.strict is true and an
    // Ethernet/IPv4/TCP-layer parse fails; otherwise failures are captured
    // in the returned DecodedPacket's protocol/summary/notes fields.
    //
    // NOTE ON STATEFULNESS: this method is `const` in the sense that every DecodedPacket it
    // returns is still produced deterministically from (a) the packet passed in and (b) whatever
    // DNP3 fragment-reassembly state (dnp3_reassembly_) earlier calls on THIS Decoder instance
    // left behind -- it is not const/pure in the stronger sense of depending only on its
    // arguments. That only means anything if packets are decoded through one Decoder instance, in
    // strict capture-file order, one at a time -- which is exactly what cli_main.cpp does (a
    // single Decoder per file-decode pass, one sequential while-loop, no concurrency). Decoding
    // the same packet twice on a fresh Decoder, or out of order, will not reproduce reassembly
    // that depended on packets decoded earlier in the file.
    DecodedPacket decode(const PcapPacket& packet, uint32_t link_type, size_t index) const;

private:
    DecodeOptions options_;

    // See Dnp3FragmentReassembly above. Keyed by "src_ip:src_port->dst_ip:dst_port" (one entry
    // per directional TCP flow that has ever carried an in-progress DNP3 fragment). `mutable`
    // because it is cross-packet state accumulated across decode() calls, not a function of the
    // current packet alone -- see the NOTE ON STATEFULNESS above for why that is safe here.
    mutable std::unordered_map<std::string, Dnp3FragmentReassembly> dnp3_reassembly_;

    // Decodes one DNP3 data-link frame's transport header and, once its fragment is complete,
    // application layer -- buffering across packets via dnp3_reassembly_[flow_key] when the
    // fragment spans more than one data-link frame (transport FIR=1,FIN=0 on an earlier frame).
    // `link`/`tcp_payload` are the same as try_parse_dnp3_transport_and_application's, which this
    // supersedes as decoder.cpp's call site precisely because that function has no flow to buffer
    // against. Same nullopt contract: only when link.user_data_bytes == 0. See dnp3.hpp for the
    // reassemble_dnp3_user_data/decode_dnp3_application_layer primitives this is built from.
    std::optional<Dnp3ApplicationFragment> process_dnp3_frame(const Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                                const std::string& flow_key) const;
};

}  // namespace conduitscope
