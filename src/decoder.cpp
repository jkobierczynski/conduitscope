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

std::optional<Dnp3ApplicationFragment> Decoder::process_dnp3_frame(const Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                                     const std::string& flow_key) const {
    if (link.user_data_bytes == 0) {
        return std::nullopt;
    }

    Dnp3ApplicationFragment frag;
    std::vector<uint8_t> logical = reassemble_dnp3_user_data(link, tcp_payload, frag.notes);

    if (logical.empty()) {
        frag.notes.push_back("no transport-layer byte could be recovered for this fragment");
        frag.summary = "transport/application layer not decoded (no data recovered)";
        return frag;
    }

    // --- Transport header: 1 byte, bit7=FIR, bit6=FIN, bits5-0=SEQ. Same as
    // try_parse_dnp3_transport_and_application; the difference starts below, in what happens for
    // a fragment that isn't complete in this one data-link frame. ---
    uint8_t transport_byte = logical[0];
    frag.has_transport = true;
    frag.transport_fir = (transport_byte & 0x80) != 0;
    frag.transport_fin = (transport_byte & 0x40) != 0;
    frag.transport_seq = transport_byte & 0x3F;

    std::ostringstream summary;
    summary << "transport: FIR=" << (frag.transport_fir ? 1 : 0) << " FIN=" << (frag.transport_fin ? 1 : 0)
            << " SEQ=" << static_cast<unsigned>(frag.transport_seq);

    ByteSpan app_bytes_this_frame =
        logical.size() > 1 ? ByteSpan(logical.data() + 1, logical.size() - 1) : ByteSpan();
    Dnp3FragmentReassembly& state = dnp3_reassembly_[flow_key];

    if (frag.transport_fir && frag.transport_fin) {
        // Complete, single-data-link-frame fragment -- the large majority of real traffic. Any
        // reassembly left in progress for this flow is now stale (its FIN=1 will never come from
        // the frame that was supposed to send it -- a fragment that arrived complete on its own
        // took its place instead), so it's abandoned with a note rather than silently forgotten.
        if (state.in_progress) {
            frag.notes.push_back(
                "a complete single-frame DNP3 fragment (FIR=1, FIN=1) arrived on this TCP flow "
                "while a previous multi-frame fragment reassembly was still in progress (" +
                std::to_string(state.buffered_app_bytes.size()) + " byte(s) buffered across " +
                std::to_string(state.frame_count) +
                " frame(s)) -- the earlier, incomplete fragment is abandoned");
            state = Dnp3FragmentReassembly{};
        }
        decode_dnp3_application_layer(app_bytes_this_frame, frag);
        if (!frag.summary.empty()) {
            summary << " | " << frag.summary;
        }
        frag.summary = summary.str();
        return frag;
    }

    if (frag.transport_fir) {
        // Begins a fragment that continues in a later data-link frame -- possibly in a later TCP
        // segment/packet entirely. Buffer it per-flow and wait for a continuation; nothing to
        // decode yet.
        if (state.in_progress) {
            frag.notes.push_back(
                "a new DNP3 fragment (FIR=1, FIN=0, SEQ=" + std::to_string(frag.transport_seq) +
                ") began on this TCP flow while a previous fragment reassembly was still in "
                "progress (" + std::to_string(state.buffered_app_bytes.size()) +
                " byte(s) buffered across " + std::to_string(state.frame_count) +
                " frame(s)) -- the earlier, incomplete fragment is abandoned");
        }
        state = Dnp3FragmentReassembly{};
        state.in_progress = true;
        state.buffered_app_bytes.assign(app_bytes_this_frame.data(),
                                         app_bytes_this_frame.data() + app_bytes_this_frame.size());
        state.last_seq = frag.transport_seq;
        state.frame_count = 1;
        frag.notes.push_back(
            "beginning a DNP3 fragment that spans multiple data-link frames (FIR=1, FIN=0, SEQ=" +
            std::to_string(frag.transport_seq) + ") -- " +
            std::to_string(state.buffered_app_bytes.size()) +
            " application-layer byte(s) buffered so far for this TCP flow; the application layer "
            "will be decoded once a continuation frame with FIN=1 is seen on the same flow "
            "(reassembly assumes packets are processed in capture order, which conduitscope's "
            "single sequential decode pass guarantees)");
        frag.summary = summary.str();  // transport-only, same rendering as before this fragment began
        return frag;
    }

    // frag.transport_fir is false: a continuation frame.
    if (!state.in_progress) {
        frag.notes.push_back(
            "continuation DNP3 data-link frame (FIR=0, SEQ=" + std::to_string(frag.transport_seq) +
            ") with no fragment reassembly in progress on this TCP flow -- the frame that began it "
            "was never seen (capture may start mid-fragment) or the reassembly was already "
            "completed/abandoned; application layer not decoded");
        frag.summary = summary.str();
        return frag;
    }

    uint8_t expected_seq = (state.last_seq + 1) & 0x3F;
    if (frag.transport_seq != expected_seq) {
        frag.notes.push_back(
            "continuation DNP3 data-link frame's sequence number (" + std::to_string(frag.transport_seq) +
            ") does not follow the previous frame's (expected " + std::to_string(expected_seq) +
            ") -- discarding " + std::to_string(state.buffered_app_bytes.size()) +
            " already-buffered byte(s) and abandoning this fragment reassembly; application layer "
            "not decoded");
        state = Dnp3FragmentReassembly{};
        frag.summary = summary.str();
        return frag;
    }

    // Safety caps against a pathological/malformed capture stalling a fragment open forever and
    // growing dnp3_reassembly_ without bound -- a real fragment is nowhere near either limit.
    constexpr size_t kMaxBufferedBytes = 65536;
    constexpr size_t kMaxFramesPerFragment = 500;

    state.buffered_app_bytes.insert(state.buffered_app_bytes.end(), app_bytes_this_frame.data(),
                                     app_bytes_this_frame.data() + app_bytes_this_frame.size());
    state.last_seq = frag.transport_seq;
    ++state.frame_count;

    if (state.buffered_app_bytes.size() > kMaxBufferedBytes || state.frame_count > kMaxFramesPerFragment) {
        frag.notes.push_back(
            "DNP3 fragment reassembly on this TCP flow exceeded its safety cap (" +
            std::to_string(state.buffered_app_bytes.size()) + " byte(s) across " +
            std::to_string(state.frame_count) +
            " frame(s)) -- abandoning it; application layer not decoded");
        state = Dnp3FragmentReassembly{};
        frag.summary = summary.str();
        return frag;
    }

    if (!frag.transport_fin) {
        frag.notes.push_back(
            "continuing a DNP3 fragment reassembly on this TCP flow (SEQ=" +
            std::to_string(frag.transport_seq) + "): " + std::to_string(state.buffered_app_bytes.size()) +
            " application-layer byte(s) buffered across " + std::to_string(state.frame_count) +
            " frame(s) so far, still waiting for FIN=1");
        frag.summary = summary.str();
        return frag;
    }

    // FIN=1: the fragment is complete. Decode the concatenated application-layer bytes, then
    // clear the flow's reassembly state -- it's spent either way, whether decoding succeeds or
    // turns up something malformed.
    size_t total_bytes = state.buffered_app_bytes.size();
    size_t total_frames = state.frame_count;
    frag.notes.push_back("completed a " + std::to_string(total_frames) +
                          "-data-link-frame DNP3 fragment reassembled across separate TCP segments (" +
                          std::to_string(total_bytes) + " application-layer byte(s) total)");
    ByteSpan reassembled(state.buffered_app_bytes.data(), state.buffered_app_bytes.size());
    decode_dnp3_application_layer(reassembled, frag);
    state = Dnp3FragmentReassembly{};

    summary << " (fragment reassembled across " << total_frames << " data-link frame(s), " << total_bytes
            << " application-layer byte(s) total)";
    if (!frag.summary.empty()) {
        summary << " | " << frag.summary;
    }
    frag.summary = summary.str();
    return frag;
}

bool Decoder::reassemble_tcp_payload(const TcpSegment& tcp, const std::string& flow_key, DecodedPacket& out,
                                      std::vector<uint8_t>& storage, ByteSpan& effective_payload) const {
    TcpFlowBuffer& fb = tcp_reassembly_[flow_key];

    ByteSpan candidate = tcp.payload;
    bool combined = false;

    if (fb.active) {
        // int32_t of the mod-2^32 difference is the standard wraparound-safe way to compare TCP
        // sequence numbers: negative means `tcp.seq` is "behind" what's expected (overlap/
        // retransmission), positive means it's "ahead" (a gap -- something wasn't captured).
        int32_t delta = static_cast<int32_t>(tcp.seq - fb.next_seq);
        if (delta == 0) {
            storage = fb.bytes;
            storage.insert(storage.end(), tcp.payload.data(), tcp.payload.data() + tcp.payload.size());
            candidate = ByteSpan(storage.data(), storage.size());
            combined = true;
        } else if (delta < 0) {
            size_t overlap = static_cast<size_t>(-delta);
            if (overlap >= tcp.payload.size()) {
                // Entirely already-seen bytes (a full retransmission) -- nothing new to add, and
                // nothing wrong with what's already buffered either. Ignore it and keep waiting.
                out.protocol = "tcp";
                out.summary = "retransmitted/duplicate TCP segment " + std::to_string(tcp.src_port) + "->" +
                               std::to_string(tcp.dst_port) + " (fully overlaps bytes already buffered for "
                               "an in-progress " + std::to_string(fb.bytes.size()) +
                               "-byte PDU/frame reassembly on this flow) -- ignored, still waiting for more";
                return false;
            }
            storage = fb.bytes;
            ByteSpan new_part = tcp.payload.from(overlap);
            storage.insert(storage.end(), new_part.data(), new_part.data() + new_part.size());
            candidate = ByteSpan(storage.data(), storage.size());
            combined = true;
            out.notes.push_back("TCP segment on this flow overlaps " + std::to_string(overlap) +
                                 " already-buffered byte(s) (likely a retransmission) -- trimmed and only "
                                 "the new byte(s) appended");
        } else {
            out.notes.push_back(
                "TCP sequence gap on this flow (expected seq " + std::to_string(fb.next_seq) + ", got " +
                std::to_string(tcp.seq) + ", " + std::to_string(delta) +
                " byte(s) apparently missing) -- abandoning an in-progress " +
                std::to_string(fb.bytes.size()) +
                "-byte PDU/frame reassembly on this flow (a TCP segment was very likely not captured)");
            fb = TcpFlowBuffer{};
            candidate = tcp.payload;
            combined = false;
        }
    }

    bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::ModbusOnly;
    bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::Dnp3Only;
    bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::S7commOnly;

    std::optional<size_t> declared;
    std::string which;
    if (want_modbus) {
        if (auto d = modbus_tcp_declared_length(candidate)) {
            declared = d;
            which = "Modbus/TCP";
        }
    }
    if (!declared && want_dnp3) {
        if (auto d = dnp3_link_frame_declared_length(candidate)) {
            declared = d;
            which = "DNP3 data-link";
        }
    }
    if (!declared && want_s7comm) {
        if (auto d = tpkt_declared_length(candidate)) {
            declared = d;
            which = "TPKT/COTP";
        }
    }

    if (declared && *declared > candidate.size()) {
        fb.active = true;
        fb.bytes.assign(candidate.data(), candidate.data() + candidate.size());
        fb.next_seq = tcp.seq + static_cast<uint32_t>(tcp.payload.size());
        fb.segment_count = combined ? fb.segment_count + 1 : 1;
        out.protocol = "tcp";
        std::ostringstream s;
        s << "buffering a " << which << " PDU/frame split across TCP segments " << tcp.src_port << "->"
          << tcp.dst_port << ": " << candidate.size() << " of " << *declared
          << " declared byte(s) seen so far across " << fb.segment_count
          << " segment(s) on this flow, waiting for more";
        out.summary = s.str();
        return false;
    }

    size_t completed_segment_count = fb.segment_count + (combined ? 1 : 0);
    fb = TcpFlowBuffer{};
    effective_payload = candidate;
    if (combined && declared) {
        out.notes.push_back("reassembled a " + which + " PDU/frame from " + std::to_string(candidate.size()) +
                             " byte(s) spanning " + std::to_string(completed_segment_count) +
                             " TCP segments on this flow");
    }
    return true;
}

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

        // Directional TCP flow identity, reused below both for cross-TCP-segment PDU/frame
        // reassembly (tcp_reassembly_) and DNP3 cross-packet application-fragment reassembly
        // (dnp3_reassembly_) -- see reassemble_tcp_payload/process_dnp3_frame.
        std::string flow_key =
            out.src_ip + ":" + std::to_string(tcp.src_port) + "->" + out.dst_ip + ":" + std::to_string(tcp.dst_port);

        // Bytes to actually run protocol detection against: tcp.payload as-is, unless this flow
        // has bytes buffered from an earlier packet (a PDU/frame split across TCP segments) that
        // this segment continues, completes, or invalidates (gap/retransmission) -- see
        // reassemble_tcp_payload's own comment in decoder.hpp for the full contract. `tcp_storage`
        // backs `effective_payload` when combining was needed and must outlive its use below.
        std::vector<uint8_t> tcp_storage;
        ByteSpan effective_payload;
        if (!reassemble_tcp_payload(tcp, flow_key, out, tcp_storage, effective_payload)) {
            // Either still incomplete (buffered, waiting for more) or an ignored duplicate
            // retransmission -- reassemble_tcp_payload has already filled in `out` either way.
            return out;
        }

        bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::ModbusOnly;
        bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::Dnp3Only;
        bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::S7commOnly;

        if (want_modbus) {
            if (auto mb = try_parse_modbus_tcp(effective_payload)) {
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
            if (auto d = try_parse_dnp3_link_layer(effective_payload)) {
                out.protocol = "dnp3";
                out.summary = d->summary;

                // Object headers/point values are capped cumulatively across every data link
                // frame found in this TCP payload, not per frame -- same caps as before, just
                // now shared across however many frames turned up.
                constexpr size_t kMaxObjHeaders = 50;
                constexpr size_t kMaxPointValues = 50;
                auto merge_application_layer = [&](const Dnp3ApplicationFragment& app, bool is_first_frame) {
                    if (is_first_frame) {
                        out.summary += "; " + app.summary;
                        out.dnp3_has_function = app.has_function;
                        out.dnp3_function_name = app.function_name;
                    }
                    for (const auto& n : app.notes) out.notes.push_back(n);
                    for (size_t i = 0; i < app.objects.size() && out.dnp3_object_headers.size() < kMaxObjHeaders;
                         ++i) {
                        const auto& oh = app.objects[i];
                        out.dnp3_object_headers.push_back("g" + std::to_string(oh.group) + "v" +
                                                           std::to_string(oh.variation) + " (" +
                                                           oh.group_name + ")");
                    }
                    for (const auto& oh : app.objects) {
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
                };

                if (auto app = process_dnp3_frame(*d, effective_payload, flow_key)) {
                    merge_application_layer(*app, /*is_first_frame=*/true);
                }

                // DNP3 frames are small (<=255 bytes on the wire) and it's normal for a sender
                // or the OS to coalesce several into one TCP segment before flushing. Keep
                // looking for more, immediately after the first frame's own wire bytes, rather
                // than silently stopping at the first one -- previously anything past it in the
                // same payload was dropped with no warning at all.
                constexpr size_t kMaxDnp3FramesPerPayload = 50;
                size_t offset = dnp3_frame_wire_length(*d);
                size_t frame_count = 1;
                while (offset < effective_payload.size() && frame_count < kMaxDnp3FramesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_dnp3_link_layer(rest);
                    if (!next) break;  // remaining bytes aren't another DNP3 frame -- stop, don't guess
                    ++frame_count;
                    std::string note = "additional DNP3 data link frame " + std::to_string(frame_count) +
                                        " found in the same TCP payload at byte offset " +
                                        std::to_string(offset) + " (coalesced by the sender/OS): " +
                                        next->summary;
                    if (frame_count == 2) {
                        note +=
                            " -- only the first frame's function code is reflected in the summary line "
                            "above and the dnp3_function field; every frame's own function/objects/values "
                            "are still fully decoded and included here and in dnp3_objects/dnp3_values";
                    }
                    out.notes.push_back(note);
                    if (auto next_app = process_dnp3_frame(*next, rest, flow_key)) {
                        merge_application_layer(*next_app, /*is_first_frame=*/false);
                    }
                    offset += dnp3_frame_wire_length(*next);
                }
                if (frame_count >= kMaxDnp3FramesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxDnp3FramesPerPayload) +
                                         " DNP3 data link frame(s) in this one TCP payload, more may remain "
                                         "(safety cap)");
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
            if (auto cotp = try_parse_tpkt_cotp(effective_payload)) {
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
        s << "TCP payload of " << effective_payload.size() << " byte(s) on port " << tcp.src_port << "->"
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
