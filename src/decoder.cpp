// SPDX-License-Identifier: MIT
#include "conduitscope/decoder.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/tcp.hpp"

namespace conduitscope {

namespace {

bool port_in(uint16_t port, uint16_t default_port, const std::vector<uint16_t>& extra) {
    if (port == default_port) return true;
    return std::find(extra.begin(), extra.end(), port) != extra.end();
}

}  // namespace

DecodedPacket Decoder::decode(const PcapPacket& packet, uint32_t link_type, size_t index) const {
    DecodedPacket out;
    out.index = index;
    out.timestamp = static_cast<double>(packet.ts_sec) +
                     static_cast<double>(packet.ts_frac) / (packet.nanosecond_ts_hint ? 1e9 : 1e6);
    out.captured_len = packet.captured_len;
    out.original_len = packet.original_len;

    ByteSpan frame(packet.data.data(), packet.data.size());

    try {
        ByteSpan network_layer_payload;

        if (link_type == LINKTYPE_ETHERNET) {
            EthernetFrame eth = parse_ethernet(frame);
            out.has_ethernet = true;
            out.src_mac = format_mac(eth.src_mac);
            out.dst_mac = format_mac(eth.dst_mac);
            out.has_vlan_tag = eth.has_vlan_tag;
            out.vlan_id = eth.vlan_id;

            if (eth.ethertype != ETHERTYPE_IPV4) {
                out.protocol = "non-ip";
                std::ostringstream s;
                s << "Ethernet frame with ethertype 0x" << std::hex << eth.ethertype << " (not IPv4)";
                out.summary = s.str();
                return out;
            }
            network_layer_payload = eth.payload;
        } else if (link_type == LINKTYPE_RAW) {
            network_layer_payload = frame;
        } else {
            out.protocol = "unsupported-link";
            out.summary = "capture link type " + std::to_string(link_type) +
                           " is not supported in this groundwork release (only Ethernet and raw IP are)";
            return out;
        }

        Ipv4Header ip = parse_ipv4(network_layer_payload);
        out.has_ip = true;
        out.src_ip = format_ipv4(ip.src_addr);
        out.dst_ip = format_ipv4(ip.dst_addr);
        out.ip_protocol = ip.protocol;
        out.ttl = ip.ttl;
        if (ip.trailing_bytes_trimmed > 0) {
            out.notes.push_back(std::to_string(ip.trailing_bytes_trimmed) +
                                 " trailing byte(s) after the IP header's declared total length were "
                                 "trimmed (almost always Ethernet minimum-frame-size padding, not real "
                                 "payload)");
        }

        if (ip.protocol != IPPROTO_TCP_VALUE) {
            out.protocol = "non-tcp";
            out.summary = "IPv4 protocol number " + std::to_string(ip.protocol) + " (not TCP)";
            return out;
        }

        TcpSegment tcp = parse_tcp(ip.payload);
        out.has_tcp = true;
        out.src_port = tcp.src_port;
        out.dst_port = tcp.dst_port;
        out.tcp_flags = format_tcp_flags(tcp.flags);

        if (tcp.payload.empty()) {
            out.protocol = "tcp";
            out.summary = "TCP segment " + std::to_string(tcp.src_port) + " -> " +
                           std::to_string(tcp.dst_port) + " with no payload (handshake/ACK/teardown)";
            return out;
        }

        bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::ModbusOnly;
        bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::Dnp3Only;
        bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::S7commOnly;

        if (want_modbus) {
            if (auto mb = try_parse_modbus_tcp(tcp.payload)) {
                out.protocol = "modbus";
                out.modbus_is_exception = mb->is_exception;
                out.modbus_function_name = mb->function_name;
                out.summary = mb->function_name + ": " + mb->summary;
                for (const auto& n : mb->notes) out.notes.push_back(n);
                bool expected_port = port_in(tcp.src_port, MODBUS_TCP_PORT, options_.extra_modbus_ports) ||
                                      port_in(tcp.dst_port, MODBUS_TCP_PORT, options_.extra_modbus_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard Modbus port (502)");
                }
                return out;
            }
        }

        if (want_dnp3) {
            if (auto d = try_parse_dnp3_link_layer(tcp.payload)) {
                out.protocol = "dnp3";
                out.summary = d->summary;
                if (auto app = try_parse_dnp3_transport_and_application(*d, tcp.payload)) {
                    out.summary += "; " + app->summary;
                    for (const auto& n : app->notes) out.notes.push_back(n);
                    out.dnp3_has_function = app->has_function;
                    out.dnp3_function_name = app->function_name;
                    constexpr size_t kMaxObjHeaders = 50;
                    for (size_t i = 0; i < app->objects.size() && i < kMaxObjHeaders; ++i) {
                        const auto& oh = app->objects[i];
                        out.dnp3_object_headers.push_back("g" + std::to_string(oh.group) + "v" +
                                                           std::to_string(oh.variation) + " (" +
                                                           oh.group_name + ")");
                    }
                    constexpr size_t kMaxPointValues = 50;
                    for (const auto& oh : app->objects) {
                        if (out.dnp3_point_values.size() >= kMaxPointValues) break;
                        std::string tag = "g" + std::to_string(oh.group) + "v" + std::to_string(oh.variation);
                        for (const auto& pv : oh.values) {
                            if (out.dnp3_point_values.size() >= kMaxPointValues) break;
                            std::string entry = tag + " idx=" + std::to_string(pv.index) + ": " + pv.value;
                            if (!pv.flags.empty()) {
                                entry += " [";
                                for (size_t f = 0; f < pv.flags.size(); ++f) {
                                    if (f != 0) entry += ",";
                                    entry += pv.flags[f];
                                }
                                entry += "]";
                            }
                            out.dnp3_point_values.push_back(entry);
                        }
                    }
                }
                bool expected_port = port_in(tcp.src_port, DNP3_TCP_PORT, options_.extra_dnp3_ports) ||
                                      port_in(tcp.dst_port, DNP3_TCP_PORT, options_.extra_dnp3_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard DNP3 port (20000)");
                }
                return out;
            }
        }

        if (want_s7comm) {
            if (auto cotp = try_parse_tpkt_cotp(tcp.payload)) {
                bool expected_port = port_in(tcp.src_port, COTP_TCP_PORT, options_.extra_s7comm_ports) ||
                                      port_in(tcp.dst_port, COTP_TCP_PORT, options_.extra_s7comm_ports);
                auto annotate_port = [&]() {
                    if (!expected_port) {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard COTP/S7comm port (102)");
                    }
                };

                if (cotp->kind == CotpPduKind::Data && !cotp->user_data.empty()) {
                    if (auto s7 = try_parse_s7comm(cotp->user_data)) {
                        out.protocol = "s7comm";
                        out.summary = s7->summary;
                        for (const auto& n : s7->notes) out.notes.push_back(n);
                        out.s7comm_has_function = s7->has_function;
                        out.s7comm_function_name = s7->function_name;
                        constexpr size_t kMaxTags = 50;
                        for (size_t i = 0; i < s7->items.size() && i < kMaxTags; ++i) {
                            const auto& it = s7->items[i];
                            std::string display_tag = !it.tag.empty() ? it.tag : it.area_name;
                            // A consumer parsing this array as trusted addresses must not mistake an
                            // unverified reconstruction for the well-established S7ANY decode.
                            if (it.is_experimental) display_tag += " [EXPERIMENTAL]";
                            out.s7comm_item_tags.push_back(display_tag);
                        }
                        for (size_t i = 0; i < s7->data_items.size() && i < kMaxTags; ++i) {
                            const auto& di = s7->data_items[i];
                            // return_code_name is only set for items that carry a return code on
                            // the wire (Read Var / Write Var responses); a Write Var request's
                            // value item has none, so this falls straight through to the value.
                            if (!di.return_code_name.empty() && di.return_code != 0xFF) {
                                out.s7comm_value_summaries.push_back(di.return_code_name);
                            } else if (di.has_value_fields && di.transport_size == 0x03 && di.data.size() == 1) {
                                out.s7comm_value_summaries.push_back(di.data.at(0) != 0 ? "1" : "0");
                            } else if (di.has_value_fields && !di.data.empty()) {
                                out.s7comm_value_summaries.push_back(to_hex(di.data, ""));
                            } else if (!di.return_code_name.empty()) {
                                out.s7comm_value_summaries.push_back("ok");
                            } else {
                                out.s7comm_value_summaries.push_back("");
                            }
                        }
                        for (const auto& n : cotp->notes) out.notes.push_back(n);
                        annotate_port();
                        return out;
                    }
                }

                out.protocol = "cotp";
                out.summary = cotp->summary;
                for (const auto& n : cotp->notes) out.notes.push_back(n);
                annotate_port();
                return out;
            }
        }

        out.protocol = "tcp";
        std::ostringstream s;
        s << "TCP payload of " << tcp.payload.size() << " byte(s) on port " << tcp.src_port << "->"
          << tcp.dst_port << " did not match Modbus, DNP3, or COTP/S7comm";
        out.summary = s.str();
        return out;

    } catch (const ParseError& e) {
        if (options_.strict) {
            throw;
        }
        out.protocol = "parse-error";
        out.summary = std::string("could not parse packet: ") + e.what();
        return out;
    }
}

}  // namespace conduitscope
