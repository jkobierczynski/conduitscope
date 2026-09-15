// SPDX-License-Identifier: MIT
#include "conduitscope/decoder.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/byteio.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/iec104.hpp"
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

// Canonicalizes both directions of one TCP 4-tuple into a single, direction-independent session
// key, so Decoder::modbus_pending_ can track outstanding requests per SESSION (request and
// response travel in opposite directions) rather than per directional flow -- unlike flow_key
// (used by dnp3_reassembly_/tcp_reassembly_/cotp_reassembly_, which genuinely are per-direction).
// "<->" is used as the join delimiter specifically so this can never collide with a directional
// flow_key string (which always uses "->"), even though the two happen to key different maps.
std::string modbus_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b,
                                uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
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

    bool want_iec104 = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::Iec104Only;
    bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::ModbusOnly;
    bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::Dnp3Only;
    bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::S7commOnly;

    // IEC104 is checked first, ahead of Modbus, even though Modbus has been in this dispatch
    // chain the longest -- see try_parse_iec104_apci's header comment for the collision this
    // avoids: an I-format APDU with N(S)=N(R)=0 (common very early in a session) can otherwise
    // read as a plausible Modbus/TCP MBAP header (protocol-id==0, mbap_length==0) by coincidence.
    // IEC104's own structural checks (start byte + fixed control-field bit patterns) are a much
    // stronger signal than Modbus/TCP's single protocol-id==0 tell, so trying it first resolves
    // the collision in IEC104's favor without needing to make Modbus's own check any stricter --
    // the same fix already applied once before for a real-capture-found DNP3-vs-Modbus collision
    // (see modbus.cpp's function-code-0 check).
    std::optional<size_t> declared;
    std::string which;
    if (want_iec104) {
        if (auto d = iec104_apdu_declared_length(candidate)) {
            declared = d;
            which = "IEC 104 APDU";
        }
    }
    if (!declared && want_modbus) {
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

void Decoder::pair_modbus_transaction(const ModbusFrame& mb, const std::string& flow_key,
                                       const std::string& session_key, size_t packet_index,
                                       DecodedPacket& out) const {
    auto& pending_for_session = modbus_pending_[session_key];
    auto it = pending_for_session.find(mb.transaction_id);

    if (it != pending_for_session.end()) {
        ModbusPendingRequest& pending = it->second;
        if (pending.flow_key != flow_key) {
            // Opposite direction: authoritatively the response to that specific request.
            out.modbus_is_paired_response = true;
            out.modbus_paired_request_index = pending.packet_index;
            std::ostringstream s;
            s << "authoritative pairing: response to transaction id " << mb.transaction_id << " (unit "
              << static_cast<unsigned>(mb.unit_id) << ") -- matches the request seen in packet #"
              << pending.packet_index << " (" << pending.function_name << ": " << pending.request_summary
              << "), paired by TCP session + transaction ID, not the payload-shape heuristic above";
            if (pending.unit_id != mb.unit_id) {
                s << " [unit id mismatch: request was unit " << static_cast<unsigned>(pending.unit_id) << "]";
            }
            out.notes.push_back(s.str());
            pending_for_session.erase(it);
            return;
        }
        // Same direction: transaction ID reused before its previous request was ever paired.
        out.notes.push_back("transaction id " + std::to_string(mb.transaction_id) +
                             " reused on this TCP flow before its previous outstanding request (packet #" +
                             std::to_string(pending.packet_index) +
                             ") was matched with a response -- possibly a retry, an orphaned request, or "
                             "out-of-order capture; treating this as a new outstanding request");
        pending = ModbusPendingRequest{packet_index, flow_key, mb.function_name, mb.summary, mb.unit_id};
        return;
    }

    // No outstanding request found for this transaction ID on this session. If the payload-shape
    // heuristic already called this packet a response, it's an orphan -- nothing to pair it
    // against, most likely because its request was sent before this capture began (or used a
    // different transaction ID/session). Otherwise, record it as newly outstanding so a later
    // opposite-direction packet with the same transaction ID can pair against it.
    bool looks_like_response = mb.is_exception || mb.summary.rfind("response:", 0) == 0;
    if (looks_like_response) {
        out.notes.push_back("no outstanding request found on this TCP session for transaction id " +
                             std::to_string(mb.transaction_id) +
                             " -- the payload-shape heuristic above classified this packet as a response, "
                             "but its request was never seen on this session (capture may have started "
                             "after it was sent, or it used a different transaction ID/session)");
        return;
    }

    // Capacity guard against a pathological/malformed capture leaking memory -- a real session
    // realistically never has anywhere near this many transactions outstanding at once, so hitting
    // this just means new requests stop being recorded until earlier ones are paired off.
    constexpr size_t kMaxTrackedTransactionsPerSession = 2000;
    if (pending_for_session.size() >= kMaxTrackedTransactionsPerSession) {
        return;
    }
    pending_for_session[mb.transaction_id] =
        ModbusPendingRequest{packet_index, flow_key, mb.function_name, mb.summary, mb.unit_id};
}

bool Decoder::reassemble_cotp_data_frame(const CotpFrame& cotp, const std::string& flow_key, DecodedPacket& out,
                                          std::vector<uint8_t>& storage, ByteSpan& s7_candidate) const {
    CotpFragmentReassembly& state = cotp_reassembly_[flow_key];

    if (!cotp.eot) {
        // Begins or continues a TSDU fragmented across multiple complete TPKT/COTP frames -- buffer
        // this frame's user data and wait for the final (EOT=1) frame. COTP has no FIR-equivalent
        // bit, so "nothing in progress yet on this flow" is what distinguishes a fresh start from a
        // continuation, not any field on this frame itself.
        bool starting = !state.in_progress;
        state.in_progress = true;
        state.buffered_user_data.insert(state.buffered_user_data.end(), cotp.user_data.data(),
                                         cotp.user_data.data() + cotp.user_data.size());
        ++state.frame_count;

        // Safety caps against a pathological/malformed capture stalling a fragment open forever --
        // sized generously above real S7 block-transfer scenarios (large DB/program-block
        // uploads/downloads), which is what genuine multi-frame chaining is for.
        constexpr size_t kMaxBufferedBytes = 1 << 20;  // 1 MiB
        constexpr size_t kMaxFramesPerFragment = 2000;
        if (state.buffered_user_data.size() > kMaxBufferedBytes || state.frame_count > kMaxFramesPerFragment) {
            out.protocol = "cotp";
            out.summary = "COTP/S7comm fragment reassembly on this TCP flow exceeded its safety cap (" +
                           std::to_string(state.buffered_user_data.size()) + " byte(s) across " +
                           std::to_string(state.frame_count) + " frame(s)) -- abandoning it";
            state = CotpFragmentReassembly{};
            return false;
        }

        out.protocol = "cotp";
        std::ostringstream s;
        s << (starting ? "beginning" : "continuing")
          << " a COTP/S7comm message fragmented across multiple complete TPKT/COTP frames on this TCP "
             "flow (EOT=0): "
          << state.buffered_user_data.size() << " user-data byte(s) buffered across " << state.frame_count
          << " frame(s) so far, waiting for the final (EOT=1) frame";
        out.summary = s.str();
        return false;
    }

    // cotp.eot: this frame completes a TSDU -- either the common case (nothing was in progress, so
    // this frame's own user data IS the whole message, exactly as before this feature existed) or
    // the final fragment of a reassembly that began on an earlier frame on this flow.
    if (!state.in_progress) {
        s7_candidate = cotp.user_data;
        return true;
    }

    storage = state.buffered_user_data;
    storage.insert(storage.end(), cotp.user_data.data(), cotp.user_data.data() + cotp.user_data.size());
    s7_candidate = ByteSpan(storage.data(), storage.size());
    size_t total_frames = state.frame_count + 1;
    out.notes.push_back("reassembled a COTP/S7comm message from " + std::to_string(s7_candidate.size()) +
                         " user-data byte(s) chained across " + std::to_string(total_frames) +
                         " complete TPKT/COTP frames on this TCP flow (EOT=0 on all but the last)");
    state = CotpFragmentReassembly{};
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

        bool want_iec104 = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::Iec104Only;
        bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::ModbusOnly;
        bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::Dnp3Only;
        bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::S7commOnly;

        // Tried first, ahead of Modbus -- see the matching comment in reassemble_tcp_payload
        // above for the collision this dispatch ordering avoids.
        if (want_iec104) {
            if (auto apci = try_parse_iec104_apci(effective_payload)) {
                out.protocol = "iec104";
                out.summary = apci->summary;

                constexpr size_t kMaxObjectValues = 50;
                auto merge_asdu = [&](const Iec104Asdu& asdu, bool is_first_apdu) {
                    if (is_first_apdu) {
                        out.summary += "; " + asdu.summary;
                        out.iec104_has_asdu = true;
                        out.iec104_asdu_type_name = asdu.type_name;
                        out.iec104_cot_name = asdu.cot_name;
                        out.iec104_common_address = asdu.common_address;
                    }
                    for (const auto& n : asdu.notes) out.notes.push_back(n);
                    for (const auto& obj : asdu.objects) {
                        if (out.iec104_object_values.size() >= kMaxObjectValues) break;
                        std::string entry = "ioa=" + std::to_string(obj.ioa) + ": " + obj.value;
                        if (!obj.flags.empty()) {
                            entry += " [";
                            for (size_t f = 0; f < obj.flags.size(); ++f) {
                                if (f != 0) entry += ",";
                                entry += obj.flags[f];
                            }
                            entry += "]";
                        }
                        out.iec104_object_values.push_back(entry);
                    }
                };

                if (apci->frame_type == Iec104FrameType::I) {
                    ByteSpan asdu_bytes = effective_payload.subspan(6, apci->asdu_length);
                    Iec104Asdu asdu = decode_iec104_asdu(asdu_bytes);
                    merge_asdu(asdu, /*is_first_apdu=*/true);
                }

                // Like DNP3, an APDU is small and it's normal for a sender or the OS to coalesce
                // several into one TCP segment before flushing (S-format acks and U-format
                // STARTDT/TESTFR handshakes are especially likely to arrive alongside an I-format
                // APDU). Keep looking for more, immediately after the first APDU's own wire
                // bytes, rather than silently stopping at the first one.
                constexpr size_t kMaxApdusPerPayload = 50;
                size_t offset = apci->wire_length;
                size_t apdu_count = 1;
                while (offset < effective_payload.size() && apdu_count < kMaxApdusPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_iec104_apci(rest);
                    if (!next) break;  // remaining bytes aren't another APDU -- stop, don't guess
                    ++apdu_count;
                    std::string note = "additional IEC 104 APDU " + std::to_string(apdu_count) +
                                        " found in the same TCP payload at byte offset " +
                                        std::to_string(offset) + " (coalesced by the sender/OS): " +
                                        next->summary;
                    if (next->frame_type == Iec104FrameType::I) {
                        ByteSpan next_asdu_bytes = rest.subspan(6, next->asdu_length);
                        Iec104Asdu next_asdu = decode_iec104_asdu(next_asdu_bytes);
                        note += " | " + next_asdu.summary;
                        if (apdu_count == 2) {
                            note += " -- only the first I-format APDU's ASDU is reflected in the "
                                    "summary line above and the iec104_asdu_type_name/iec104_cot_name "
                                    "fields; every APDU's own ASDU is still fully decoded and included "
                                    "here and in iec104_object_values";
                        }
                        out.notes.push_back(note);
                        merge_asdu(next_asdu, /*is_first_apdu=*/false);
                    } else {
                        out.notes.push_back(note);
                    }
                    offset += next->wire_length;
                }
                if (apdu_count >= kMaxApdusPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxApdusPerPayload) +
                                         " IEC 104 APDU(s) in this one TCP payload, more may remain "
                                         "(safety cap)");
                }

                bool expected_port = port_in(tcp.src_port, IEC104_TCP_PORT, options_.extra_iec104_ports) ||
                                      port_in(tcp.dst_port, IEC104_TCP_PORT, options_.extra_iec104_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard IEC 104 port (2404)");
                }
                return out;
            }
        }

        if (want_modbus) {
            if (auto mb = try_parse_modbus_tcp(effective_payload)) {
                out.protocol = "modbus";
                out.modbus_is_exception = mb->is_exception;
                out.modbus_function_name = mb->function_name;
                out.summary = mb->function_name + ": " + mb->summary;
                for (const auto& n : mb->notes) out.notes.push_back(n);

                std::string session = modbus_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
                pair_modbus_transaction(*mb, flow_key, session, index, out);

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

                if (cotp->kind != CotpPduKind::Data) {
                    // A non-Data COTP frame (connection setup/teardown) on this flow means any
                    // COTP/S7comm fragment reassembly still in progress here is stale -- the
                    // continuation it was waiting for will never come from this frame, and a new
                    // session/teardown starting means whatever was buffered no longer applies.
                    auto it = cotp_reassembly_.find(flow_key);
                    if (it != cotp_reassembly_.end() && it->second.in_progress) {
                        out.notes.push_back(
                            "a " + cotp->pdu_type_name + " frame arrived on this TCP flow while a "
                            "COTP/S7comm fragment reassembly was still in progress (" +
                            std::to_string(it->second.buffered_user_data.size()) + " byte(s) buffered across " +
                            std::to_string(it->second.frame_count) +
                            " frame(s)) -- the earlier, incomplete fragment is abandoned");
                        cotp_reassembly_.erase(it);
                    }
                }

                if (cotp->kind == CotpPduKind::Data) {
                    std::vector<uint8_t> cotp_storage;
                    ByteSpan s7_candidate;
                    if (!reassemble_cotp_data_frame(*cotp, flow_key, out, cotp_storage, s7_candidate)) {
                        // Still buffering (EOT=0, waiting for the final fragment) or the flow's
                        // safety cap was hit -- reassemble_cotp_data_frame has already filled in
                        // `out`'s protocol/summary.
                        for (const auto& n : cotp->notes) out.notes.push_back(n);
                        annotate_port();
                        return out;
                    }

                    // try_parse_s7comm already returns std::nullopt (never throws) for an empty
                    // payload, so no separate emptiness check is needed here -- s7_candidate can
                    // legitimately be empty (e.g. every buffered fragment plus the final one all
                    // carried zero bytes of user data, seen in real captures -- see
                    // tests/real_captures/s7comm/ATTRIBUTION.md).
                    if (auto s7 = try_parse_s7comm(s7_candidate)) {
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
          << tcp.dst_port << " did not match IEC 104, Modbus, DNP3, or COTP/S7comm";
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
