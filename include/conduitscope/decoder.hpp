// SPDX-License-Identifier: MIT
// decoder.hpp - orchestrates link/IPv4/TCP parsing and protocol dispatch
// (Modbus/DNP3) for a single captured packet, producing one DecodedPacket
// that every output writer (text/json/csv) renders from.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

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
};

class Decoder {
public:
    explicit Decoder(DecodeOptions options) : options_(std::move(options)) {}

    // May throw ParseError only when options.strict is true and an
    // Ethernet/IPv4/TCP-layer parse fails; otherwise failures are captured
    // in the returned DecodedPacket's protocol/summary/notes fields.
    DecodedPacket decode(const PcapPacket& packet, uint32_t link_type, size_t index) const;

private:
    DecodeOptions options_;
};

}  // namespace conduitscope
