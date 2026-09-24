// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/decoder.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/cdp.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/devicenet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/eigrp.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/ethercat.hpp"
#include "conduitscope/ffhse.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/hsrp.hpp"
#include "conduitscope/icmp.hpp"
#include "conduitscope/ieee802154.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/igmp.hpp"
#include "conduitscope/igrp.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/ipv6.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/mqtt.hpp"
#include "conduitscope/ospf.hpp"
#include "conduitscope/pim.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/protocol_registry.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tcp.hpp"
#include "conduitscope/udp.hpp"
#include "conduitscope/vrrp.hpp"
#include "conduitscope/zigbee.hpp"

namespace conduitscope {

const char* direction_source_name(DirectionSource source) {
    switch (source) {
        case DirectionSource::Handshake: return "handshake";
        case DirectionSource::Content: return "content";
        case DirectionSource::PortHeuristic: return "port-heuristic";
    }
    return "port-heuristic";
}

namespace {

bool port_in(uint16_t port, uint16_t default_port, const std::vector<uint16_t>& extra) {
    if (port == default_port) return true;
    return std::find(extra.begin(), extra.end(), port) != extra.end();
}

// A UDP port worth calling out by name in a "udp" packet's summary, for a port this groundwork
// release still doesn't decode the payload of -- an informational note only, in the same spirit
// as the "not a configured/standard <protocol> port" notes the TCP-based protocols already get.
// This is NOT how CIP I/O (UDP port 2222) is recognized any more: try_parse_cip_io is tried first
// (see decode()'s UDP branch below), so port 2222 traffic reaches this function at all only when
// that structural check didn't match (e.g. non-CIP-I/O traffic incidentally sharing the port, or a
// malformed/truncated datagram) -- this table currently has nothing left in it as a result, kept
// (rather than deleted outright) as the natural place a future UDP-riding protocol's port name
// would go once named-but-not-yet-decoded, the same role it played for 2222 before this feature.
std::string well_known_udp_port_name(uint16_t /*port*/) {
    return "";
}

// One endpoint's own "ip#port" text, shared by tcp_session_key and every inline flow_key/
// session_key construction below. IPv6 addition: the separator between the IP text and the port
// is '#', not ':' -- a canonical IPv6 address is itself full of colons (see format_ipv6, ipv6.hpp),
// so "ip:port" is ambiguous the moment ip can be IPv6 (e.g. is "2001:db8::1:8080" address
// "2001:db8::1" port 8080, or address "2001:db8::1:8" port 80?). These strings are internal map
// keys only -- never rendered in any output format (see output.cpp, which never reads flow_key/
// session_key) -- so changing the separator has no visible effect on any existing output; it only
// removes a latent flow_key/session_key collision between two unrelated flows that this codebase's
// IPv4-only history never had to consider. '#' can't appear in a dotted-quad, a canonical IPv6
// address, or a decimal port number, so "ip#port" round-trips unambiguously for either address
// family (not that anything here actually parses it back apart -- uniqueness is all this needs).
std::string format_flow_endpoint(const std::string& ip, uint16_t port) {
    return ip + "#" + std::to_string(port);
}

// Canonicalizes both directions of one TCP 4-tuple into a single, direction-independent session
// key, so Decoder::modbus_pending_ and (via ctx.session_key) session-keyed registration-model
// state like ModbusFlowState/MqttFlowState can track state per SESSION (a request and its
// response, or a CONNECT and a later SUBSCRIBE, can travel in opposite directions) rather than
// per directional flow -- unlike flow_key (used by tcp_reassembly_ and, via
// FlowStateKeying::DirectionalFlow, CotpReassemblyState/Dnp3ReassemblyState -- see cotp.hpp/
// dnp3.hpp -- which genuinely are per-direction). "<->" is used as the join delimiter
// specifically so this can never collide with a directional flow_key string (which always uses
// "->"), even though the two happen to key different maps.
std::string tcp_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b,
                             uint16_t port_b) {
    std::string ea = format_flow_endpoint(ip_a, port_a);
    std::string eb = format_flow_endpoint(ip_b, port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

// Renders one OspfLsa's header ONLY (no body) as a single line -- used for DB Description and LS
// Ack, which never carry LSA bodies (see ospf.hpp).
std::string ospf_lsa_header_summary(const OspfLsa& lsa) {
    std::ostringstream s;
    s << lsa.type_name << " len " << lsa.length << ": " << lsa.link_state_id << " " << lsa.advertising_router
      << " Seq=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << lsa.sequence_number
      << std::dec << " Age=" << lsa.age_sec << "s";
    if (lsa.do_not_age) s << " (DoNotAge)";
    return s.str();
}

// Renders one OspfLsa's header plus, when present, a short rendering of its decoded body -- used
// for LS Update, the only packet type that ever carries LSA bodies.
std::string ospf_lsa_full_summary(const OspfLsa& lsa) {
    std::string s = ospf_lsa_header_summary(lsa);
    if (lsa.router_body) {
        s += " links=" + std::to_string(lsa.router_body->links.size());
        if (lsa.router_body->flag_border) s += " ABR";
        if (lsa.router_body->flag_external) s += " ASBR";
        if (lsa.router_body->flag_virtual) s += " V";
    } else if (lsa.network_body) {
        s += " mask=" + lsa.network_body->network_mask +
             " routers=" + std::to_string(lsa.network_body->attached_routers.size());
    } else if (lsa.summary_body) {
        s += " mask=" + lsa.summary_body->network_mask + " metric=" + std::to_string(lsa.summary_body->metric);
    } else if (lsa.as_external_body) {
        s += " mask=" + lsa.as_external_body->network_mask +
             " metric=" + std::to_string(lsa.as_external_body->metric) +
             (lsa.as_external_body->e_bit ? " (Type 2)" : " (Type 1)");
    }
    return s;
}

// Renders one OspfLsRequestEntry as a single line for DecodedPacket::ospf_ls_requests.
std::string ospf_ls_request_summary(const OspfLsRequestEntry& e) {
    return e.ls_type_name + ": " + e.link_state_id + " " + e.advertising_router;
}

// Flattens a parsed OspfMessage (see ospf.hpp) into DecodedPacket's ospf_* fields. Which of the
// per-type field groups end up populated depends entirely on msg.type_name -- this just copies
// every group across unconditionally, since the unused ones are simply left at their default
// (empty/false/0) values.
void fill_ospf_fields(DecodedPacket& out, const OspfMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.ospf_type_name = msg.type_name;
    out.ospf_router_id = msg.router_id;
    out.ospf_area_id = msg.area_id;
    out.ospf_auth_type_name = msg.auth_type_name;

    out.ospf_hello_designated_router = msg.hello_designated_router;
    out.ospf_hello_backup_designated_router = msg.hello_backup_designated_router;
    out.ospf_hello_neighbors_truncated = msg.hello_neighbors_truncated;
    out.ospf_hello_neighbors = msg.hello_neighbors;

    out.ospf_dbd_lsa_headers_truncated = msg.dbd_lsa_headers_truncated;
    for (const auto& lsa : msg.dbd_lsa_headers) out.ospf_dbd_lsa_headers.push_back(ospf_lsa_header_summary(lsa));

    out.ospf_ls_requests_truncated = msg.ls_requests_truncated;
    for (const auto& e : msg.ls_requests) out.ospf_ls_requests.push_back(ospf_ls_request_summary(e));

    out.ospf_ls_update_lsas_truncated = msg.ls_update_lsas_truncated;
    for (const auto& lsa : msg.ls_update_lsas) out.ospf_ls_update_lsas.push_back(ospf_lsa_full_summary(lsa));

    out.ospf_ls_ack_headers_truncated = msg.ls_ack_headers_truncated;
    for (const auto& lsa : msg.ls_ack_headers) out.ospf_ls_ack_headers.push_back(ospf_lsa_header_summary(lsa));
}

}  // namespace

namespace {

// ---------------------------------------------------------------------------------------------
// GateKind::EtherType cascade -- registration-model-driven dispatch. Decoder::decode's own
// EtherType block below now loops over ethertype_registry() (protocol_registry.cpp) instead of a
// hand-maintained if-chain -- see that vector's own doc comment (protocol_registry.hpp) for why
// this is now safe. Most of this cascade's protocols predate the newer no-dual-write
// "out.result = *result" pattern (TwinCAT/BGP/Slow Protocols use that one directly), so each
// matched decode() result still needs its own protocol-specific dual-write into DecodedPacket's
// flat fields -- extracted here into free functions, local to this translation unit, purely so
// the dispatch loop has something uniform to call. Every function takes the matched ethertype;
// only populate_mpls actually uses it (to tell its two registry entries, which share one id(),
// apart -- see mpls.hpp) but the uniform signature keeps the lookup table below a plain
// id()-keyed map rather than a special case in the loop itself. STP has no ethertype() at all
// (it's LLC-framed, see stp.hpp) so it can never match this loop and has no populate_stp here --
// it stays its own explicit block at decoder.cpp's own EtherType call site, unchanged.

bool ethertype_cascade_filter_allows(ProtocolFilter filter, std::string_view id) {
    if (filter == ProtocolFilter::Auto) return true;
    if (id == "profinet") return filter == ProtocolFilter::ProfinetOnly;
    if (id == "goose") return filter == ProtocolFilter::GooseOnly;
    if (id == "sv") return filter == ProtocolFilter::SvOnly;
    if (id == "ethercat") return filter == ProtocolFilter::EthercatOnly;
    if (id == "eapol") return filter == ProtocolFilter::EapolOnly;
    if (id == "pppoe") return filter == ProtocolFilter::PppoeOnly;
    if (id == "mpls") return filter == ProtocolFilter::MplsOnly;
    if (id == "arp") return filter == ProtocolFilter::ArpOnly;
    if (id == "lldp") return filter == ProtocolFilter::LldpOnly;
    if (id == "slow-protocols") return filter == ProtocolFilter::SlowProtocolsOnly;
    if (id == "powerlink") return filter == ProtocolFilter::PowerlinkOnly;
    return false;
}

void populate_profinet(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const ProfinetFrame& pn = result.as<ProfinetFrame>();
    out.protocol = "profinet";
    out.summary = pn.summary;
    for (const auto& n : pn.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_goose(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const GooseFrame& gs = result.as<GooseFrame>();
    out.protocol = "goose";
    out.summary = gs.summary;
    for (const auto& n : gs.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_sv(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const SvFrame& sv = result.as<SvFrame>();
    out.protocol = "sv";
    out.summary = sv.summary;
    for (const auto& n : sv.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_ethercat(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const EthercatFrame& ec = result.as<EthercatFrame>();
    out.protocol = "ethercat";
    out.summary = ec.summary;
    for (const auto& n : ec.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_powerlink(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const PowerlinkFrame& pl = result.as<PowerlinkFrame>();
    out.protocol = "powerlink";
    out.summary = pl.summary;
    for (const auto& n : pl.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_eapol(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const EapolFrame& ea = result.as<EapolFrame>();
    out.protocol = "eapol";
    out.summary = ea.summary;
    for (const auto& n : ea.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_pppoe(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const PppoeFrame& pp = result.as<PppoeFrame>();
    out.protocol = "pppoe";
    out.summary = pp.summary;
    for (const auto& n : pp.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_mpls(DecodedPacket& out, const ProtocolResult& result, uint16_t matched_ethertype) {
    // The one populate function that needs matched_ethertype -- mpls_unicast_decoder() and
    // mpls_multicast_decoder() share one id() ("mpls"), so is_multicast can't be read off the
    // decoded MplsFrame itself; it's derived here from which of the two EtherTypes actually
    // matched, exactly as decoder.cpp's old if-chain used to compute it inline, and stashed onto a
    // copy of the frame (MplsFrame::is_multicast, see mpls.hpp) so a zero-flat-field DecodedPacket
    // ::result still carries it forward to output.cpp -- the one field in this whole migration that
    // genuinely can't come from try_parse_mpls alone.
    MplsFrame mp = result.as<MplsFrame>();
    mp.is_multicast = (matched_ethertype == ETHERTYPE_MPLS_MULTICAST);
    out.protocol = "mpls";
    out.summary = mp.summary;
    for (const auto& n : mp.notes) out.notes.push_back(n);
    out.result = ProtocolResult::make<MplsFrame>("mpls", std::move(mp));
}

void populate_arp(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const ArpMessage& arp = result.as<ArpMessage>();
    out.protocol = "arp";
    out.summary = arp.summary;
    for (const auto& n : arp.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_lldp(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const LldpMessage& lldp = result.as<LldpMessage>();
    out.protocol = "lldp";
    out.summary = lldp.summary;
    for (const auto& n : lldp.notes) out.notes.push_back(n);
    out.result = result;
}

void populate_slow_protocols(DecodedPacket& out, const ProtocolResult& result, uint16_t /*matched_ethertype*/) {
    const SlowProtocolsMessage& sp = result.as<SlowProtocolsMessage>();
    out.protocol = "slow-protocols";
    out.summary = sp.summary;
    for (const auto& n : sp.notes) out.notes.push_back(n);
    out.result = result;
}

using EthertypeCascadePopulate = void (*)(DecodedPacket&, const ProtocolResult&, uint16_t);

const EthertypeCascadePopulate* ethertype_cascade_populate_for(std::string_view id) {
    static const std::unordered_map<std::string_view, EthertypeCascadePopulate> kPopulate = {
        {"profinet", &populate_profinet},
        {"goose", &populate_goose},
        {"sv", &populate_sv},
        {"ethercat", &populate_ethercat},
        {"powerlink", &populate_powerlink},
        {"eapol", &populate_eapol},
        {"pppoe", &populate_pppoe},
        {"mpls", &populate_mpls},
        {"arp", &populate_arp},
        {"lldp", &populate_lldp},
        {"slow-protocols", &populate_slow_protocols},
    };
    auto it = kPopulate.find(id);
    return it != kPopulate.end() ? &it->second : nullptr;
}

}  // namespace

bool Decoder::reassemble_tcp_payload(const TcpSegment& tcp, const std::string& flow_key, DecodedPacket& out,
                                      std::vector<uint8_t>& storage, ByteSpan& effective_payload) const {
    // Security fix (finding 1, docs/reviews/2026-09-chatgpt-security-review-patch160.md): this
    // used to be `TcpFlowBuffer& fb = tcp_reassembly_[flow_key];`, which unconditionally created a
    // map entry for EVERY TCP flow this function was ever called on -- including the overwhelming
    // majority that never need cross-segment reassembly at all. A capture with millions of
    // distinct src-ip:port->dst-ip:port tuples, none of which ever split a PDU across segments,
    // still grew tcp_reassembly_ by one entry per flow forever; nothing anywhere erased a
    // never-needed entry once created. extract() takes ownership of any existing entry for this
    // flow (one hash lookup, no vector copy) and removes it from the map; everything below
    // operates on a purely local `fb` from here on. Only the two places that decide this flow's
    // buffer must survive past this packet -- still incomplete, or an unchanged duplicate segment
    // on an already-in-progress reassembly -- explicitly put it back with
    // `tcp_reassembly_[flow_key] = std::move(fb)`. The ordinary "fully decoded this packet" exit
    // at the bottom does NOT reinsert -- that omission IS the fix: no entry is ever created for a
    // flow that didn't need one, and an entry that just finished is removed rather than left
    // behind empty. `had_existing_entry` records whether this flow already had map state, so the
    // global `--max-active-flows` cap below (defense in depth: even a flow that legitimately
    // matches some protocol's declared-length gate on every packet, so this fix alone doesn't
    // starve it, still can't grow the map past a configured ceiling) only ever fires on the one
    // path that can actually grow tcp_reassembly_'s size -- reinserting an existing key, whether
    // unchanged or updated, never changes how many entries the map holds.
    auto node = tcp_reassembly_.extract(flow_key);
    bool had_existing_entry = !node.empty();
    TcpFlowBuffer fb = had_existing_entry ? std::move(node.mapped()) : TcpFlowBuffer{};

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
            // Widen to int64_t before negating -- delta == INT32_MIN (-2147483648) has no positive
            // int32_t representation, so negating it directly is undefined behavior (found by
            // fuzz_packet_decode; see fuzz/corpus/packet_decode/regress_decoder_int32min_negate.bin).
            // int64_t has ample room for -delta regardless of delta's sign, so this cast is always
            // exact and never overflows.
            size_t overlap = static_cast<size_t>(-static_cast<int64_t>(delta));
            if (overlap >= tcp.payload.size()) {
                // Entirely already-seen bytes (a full retransmission) -- nothing new to add, and
                // nothing wrong with what's already buffered either. Ignore it and keep waiting.
                out.protocol = "tcp";
                out.summary = "retransmitted/duplicate TCP segment " + std::to_string(tcp.src_port) + "->" +
                               std::to_string(tcp.dst_port) + " (fully overlaps bytes already buffered for "
                               "an in-progress " + std::to_string(fb.bytes.size()) +
                               "-byte PDU/frame reassembly on this flow) -- ignored, still waiting for more";
                // Restore the extracted state unchanged (see this function's own header comment) --
                // this branch only ever runs when had_existing_entry is true (it's nested inside
                // `if (fb.active)`, which a freshly default-constructed TcpFlowBuffer never is), so
                // this never grows tcp_reassembly_'s size and never needs the --max-active-flows
                // check below.
                tcp_reassembly_[flow_key] = std::move(fb);
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

    // Safety cap against a pathological/malformed capture -- or a protocol's own declared-length
    // field claiming far more data than any real deployment would ever send -- growing this
    // flow's buffer without bound while segments keep trickling in. Unlike DNP3 fragment
    // reassembly (Dnp3Decoder::process_frame's own kMaxBufferedBytes=65536, dnp3.cpp) and COTP TSDU reassembly
    // (CotpDecoder::decode's own kMaxBufferedBytes=1<<20, cotp.cpp), this general path -- shared by
    // every one of Modbus/TCP, IEC 104, EtherNet/IP, TPKT/S7comm/S7comm-Plus/MMS, HART-IP, OPC
    // UA, MQTT, and FF-HSE -- had no cap of its own: it buffered up to whatever each protocol's
    // own `*_declared_length()` returned. Most of those are already naturally or explicitly
    // bounded (Modbus/TCP's MBAP length against modbus.cpp's kMaxPlausibleMbapLength=300;
    // EtherNet/IP's and TPKT's against their own 16-bit length fields, ~64KB), but OPC UA's and
    // FF-HSE's declared-length fields are raw, uncapped 32-bit values -- confirmed against the
    // real CLI: a single 66-byte OPC UA segment can make this flow "buffer" towards a declared
    // ~4 GiB, exactly the "thousands of flows each announcing 4 GB of data coming" resource-
    // exhaustion scenario docs/reviews/2026-09-chatgpt-security-review.md's own §3 describes. See
    // docs/DEVELOPMENT.md's "Correction to item 7" for the full writeup. Fixed two ways: this cap
    // here (defense in depth for every protocol on this path, not just the two with no bound of
    // their own), and a matching plausibility ceiling added directly to
    // opcua_declared_length()/ffhse_declared_length() (opcua.cpp/ffhse.cpp) so those two stop
    // claiming an implausible length in the first place. Checked here, right after combining,
    // rather than only where buffering is (re-)committed below, so it applies uniformly to both
    // the delta==0 and delta<0 growth paths above before anything else -- including this
    // function's own declared-length dispatch chain immediately below -- sees the over-grown
    // candidate. Mirrors DNP3/COTP's own byte-count + segment-count shape, and reuses the same
    // "16 MiB is implausible for anything real" ceiling pcap_reader.cpp's own
    // kMaxPlausiblePacketBytes/kMaxPlausibleBlockBytes already established for this codebase,
    // rather than inventing a third magic number. The segment-count cap is sized so a legitimate
    // ~16 MiB reassembly over realistic (~1460-byte MSS) segments -- roughly 11,500 of them --
    // comfortably completes before it fires; it exists to catch a pathological *many-tiny-
    // segments* capture well before the byte cap alone would.
    if (combined) {
        // CLI-configurable via --max-reassembly-bytes/--max-reassembly-segments (all three
        // subcommands) -- see resource_limits.hpp. 0/unset (the default) keeps these two literal
        // values, byte-identical to this feature's absence.
        const size_t kMaxBufferedBytes = resource_limits().max_reassembly_bytes.value_or(16u * 1024u * 1024u);  // 16 MiB
        const size_t kMaxSegmentsPerReassembly = resource_limits().max_reassembly_segments.value_or(20000);
        size_t next_segment_count = fb.segment_count + 1;
        if (candidate.size() > kMaxBufferedBytes || next_segment_count > kMaxSegmentsPerReassembly) {
            out.notes.push_back(
                "TCP segment reassembly on this flow exceeded its safety cap (" +
                std::to_string(candidate.size()) + " byte(s) across " + std::to_string(next_segment_count) +
                " segment(s)) -- abandoning it; this segment's own payload is tried fresh instead");
            fb = TcpFlowBuffer{};
            candidate = tcp.payload;
            combined = false;
        }
    }

    bool want_iec104 = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::Iec104Only;
    bool want_enip = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::EnipOnly;
    bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::ModbusOnly;
    bool want_twincat = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::TwinCatOnly;
    bool want_melsec = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::MelsecOnly;
    bool want_kerberos = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::KerberosOnly;
    bool want_ldap = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::LdapOnly;
    bool want_smb = options_.protocol_filter == ProtocolFilter::Auto ||
                     options_.protocol_filter == ProtocolFilter::SmbOnly;
    bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::Dnp3Only;
    bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::S7commOnly;
    bool want_mms = options_.protocol_filter == ProtocolFilter::Auto ||
                     options_.protocol_filter == ProtocolFilter::MmsOnly;
    bool want_hartip = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::HartIpOnly;
    bool want_opcua = options_.protocol_filter == ProtocolFilter::Auto ||
                       options_.protocol_filter == ProtocolFilter::OpcUaOnly;
    bool want_mqtt = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::MqttOnly;
    bool want_s7commplus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::S7commPlusOnly;
    bool want_ffhse = options_.protocol_filter == ProtocolFilter::Auto ||
                       options_.protocol_filter == ProtocolFilter::FfHseOnly;
    bool want_fins = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::FinsOnly;
    bool want_bgp = options_.protocol_filter == ProtocolFilter::Auto ||
                     options_.protocol_filter == ProtocolFilter::BgpOnly;
    bool want_winrm = options_.protocol_filter == ProtocolFilter::Auto ||
                       options_.protocol_filter == ProtocolFilter::WinRmOnly;
    bool want_dcom = options_.protocol_filter == ProtocolFilter::Auto ||
                      options_.protocol_filter == ProtocolFilter::DcomOnly;
    bool want_ge_srtp = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::GeSrtpOnly;
    bool want_codesys = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::CodesysOnly;
    bool want_amqp091 = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::Amqp091Only;
    bool want_amqp10 = options_.protocol_filter == ProtocolFilter::Auto ||
                        options_.protocol_filter == ProtocolFilter::Amqp10Only;
    bool want_dicom = options_.protocol_filter == ProtocolFilter::Auto ||
                       options_.protocol_filter == ProtocolFilter::DicomOnly;

    // OPC UA is checked first of all: its own structural detection gate (the leading 3 bytes must
    // be one of exactly 7 fixed ASCII MessageType strings -- "HEL"/"ACK"/"ERR"/"RHE"/"OPN"/"CLO"/
    // "MSG" -- see opcua.hpp's own "structural detection gate" paragraph) is a magic-string check
    // against a small allowlist, which this codebase's own research found cannot collide with any
    // other protocol's own leading-bytes gate below (none of those 7 strings' constituent bytes
    // can satisfy Modbus's protocol-id==0 check, IEC104's 0x68 start byte, TPKT's version==3 byte,
    // DNP3's 0x0564 sync bytes, or EtherNet/IP's own small enumerated command-code set) -- so,
    // unlike HART-IP below, trying it first costs nothing and is the safest place for it.
    //
    // EtherNet/IP is checked next: its own dedicated TCP port (44818, no overlap with the other
    // four protocols) plus three independent structural checks (a 9-value command enum, a
    // 7-value status enum, and a reserved-must-be-0 options field -- see try_parse_enip's header
    // comment in enip.hpp) make it, if anything, a stronger signal than IEC104's own -- so it
    // costs nothing to try next and is the safest place for it.
    //
    // IEC104 is checked next, ahead of Modbus, even though Modbus has been in this dispatch
    // chain the longest -- see try_parse_iec104_apci's header comment for the collision this
    // avoids: an I-format APDU with N(S)=N(R)=0 (common very early in a session) can otherwise
    // read as a plausible Modbus/TCP MBAP header (protocol-id==0, mbap_length==0) by coincidence.
    // IEC104's own structural checks (start byte + fixed control-field bit patterns) are a much
    // stronger signal than Modbus/TCP's single protocol-id==0 tell, so trying it first resolves
    // the collision in IEC104's favor without needing to make Modbus's own check any stricter --
    // the same fix already applied once before for a real-capture-found DNP3-vs-Modbus collision
    // (see modbus.cpp's function-code-0 check).
    //
    std::optional<size_t> declared;
    std::string which;
    if (want_opcua) {
        // Migration batch 2: opcua_declared_length is now reached through
        // OpcUaDecoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see opcua.hpp.
        if (auto d = opcua_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "OPC UA message";
        }
    }
    if (!declared && want_enip) {
        // Migration batch 2: enip_declared_length is now reached through
        // EnipTcpDecoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see enip.hpp.
        if (auto d = enip_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "EtherNet/IP encapsulation message";
        }
    }
    if (!declared && want_iec104) {
        // Migration batch 2: iec104_apdu_declared_length is now reached through
        // Iec104Decoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see iec104.hpp.
        if (auto d = iec104_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "IEC 104 APDU";
        }
    }
    // MELSEC (MC Protocol/SLMP), tried BEFORE Modbus -- a real, reproducible collision (found via
    // Jurgen's own report during this feature's own FINS follow-up work, confirmed with a synthetic
    // decode before this fix): Modbus/TCP's own structural gate is just protocol_id==0 (payload
    // bytes 2-3) plus a plausible-length check plus a nonzero function code -- see modbus.cpp's own
    // comment on how weak that tell is. A genuine MELSEC 3E request's own bytes 2-3 are Network
    // No.(1) + PC No.(1) -- BOTH legitimately 0 for network_no (very common: "local network") and
    // pc_no (a real, valid MC-protocol station number, not just the 0xFF "own station" convention
    // this decoder's own sample fixture happens to default to) -- and bytes 4-5 (Request Destination
    // Module I/O No., little-endian) can easily read as a small, plausible Modbus mbap_length when
    // reinterpreted big-endian (e.g. io_no=0x0000, a real I/O number for a module at slot 0, not just
    // the 0x3FF "own station" sentinel): Modbus's own decode does NOT hard-reject on a length
    // mismatch (see try_parse_modbus_tcp's own "possible truncation..." note, which fires but doesn't
    // block acceptance) and its own function-code check accepts any nonzero low-7-bit value, which a
    // MELSEC declared-length's own low byte satisfies in the overwhelming majority of real requests.
    // Net effect: without this ordering, a real MELSEC request with network_no=pc_no=0 and a small
    // io_no would be silently swallowed by Modbus (shown as "Unknown (0xNN)") before MELSEC's own
    // gate ever ran -- even on MELSEC's own TCP port 5001, not even port 502 -- the exact same
    // collision CLASS already resolved once for IEC104-vs-Modbus above (an I-format APDU with
    // N(S)=N(R)=0 reading as a plausible MBAP header) and again for MELSEC-vs-HART-IP below on the
    // UDP side. MELSEC's own two-part gate here (exact 16-bit subheader magic + exact declared-
    // length cross-check) is at least as strong as IEC104's own, so the same "stronger gate wins"
    // resolution applies: try MELSEC before Modbus. See melsec.hpp's file header comment for the
    // wire format, and the matching decode-dispatch call site below and
    // protocol_registry.cpp's tcp_port_independent_registry() for the rest of this collision survey.
    if (!declared && want_melsec) {
        if (auto d = melsec_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "MELSEC (MC Protocol/SLMP)";
        }
    }
    // FINS/TCP (Omron), tried right after MELSEC -- its own structural gate is an exact 4-byte ASCII
    // magic ("FINS", offset 0), as strong a gate as any protocol in this codebase (comparable to OPC
    // UA's own 3-byte ASCII MessageType magic tried first of all above), so it cannot collide with
    // Modbus/TCP's own weak protocol_id==0 tell or with any other decoder's own gate below -- see
    // fins.hpp's file header comment for the wire format and the collision survey, and the matching
    // decode-dispatch call site below and protocol_registry.cpp's tcp_port_independent_registry() for
    // the rest of this collision survey. Positioned right after MELSEC purely for locality (both are
    // recent additions with adjacent file-header commentary), not because of any collision risk with
    // MELSEC's own gate.
    if (!declared && want_fins) {
        if (auto d = fins_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "FINS/TCP (Omron)";
        }
    }
    // DICOM (dicom.hpp), TCP ports 104/11112 -- tried BEFORE Modbus here, deliberately, for a
    // real, near-universal structural collision this task's own fixture testing surfaced: a
    // DICOM PDU's 6-byte common header is PDU-type(1) reserved(1,==0x00) PDU-length(4,BE), and
    // every real DICOM PDU's own length fits in 16 bits (any single PDU well under 65536 bytes),
    // so bytes[2:4] (the TOP 16 bits of that 4-byte length field) are ALWAYS 0x0000 -- which is
    // EXACTLY the byte range Modbus/TCP's own MBAP header reads as `protocol_id` (its primary,
    // and only mandatory, gate). Unlike AMQP 0-9-1's own narrow, single-fixed-8-byte-frame
    // collision with Modbus (documented, not reordered, in amqp091.hpp's own KNOWN COLLISION
    // note), this collision is NOT narrow -- it would claim virtually every DICOM PDU in Auto mode
    // if Modbus (opportunistic, port-independent) ran first, since DICOM's own gate is port-gated
    // and Modbus's own decode() never checks the port at all. So, UNLIKE every other GateKind::
    // TcpPort protocol in this codebase (WinRM/DCOM/GE SRTP/AMQP all sit well after Modbus in this
    // cascade, since none of them collide with it this pervasively), DICOM's own port-gated check
    // is positioned HERE, immediately before Modbus's, so a packet on a configured DICOM port gets
    // a chance to be recognized as DICOM before Modbus's own port-independent gate ever sees it --
    // this changes nothing for any existing Modbus capture (DICOM's own check only ever fires on
    // ports 104/11112/--dicom-port, none of which any pre-existing Modbus fixture uses). An
    // explicit `--protocol dicom` still tries it port-independently, same as every other
    // GateKind::TcpPort protocol; `--protocol modbus` is of course unaffected (want_dicom is false
    // under that filter, so this block is skipped entirely and Modbus's own check runs exactly as
    // it always has).
    bool require_dicom_port = options_.protocol_filter == ProtocolFilter::Auto;
    bool candidate_port_is_dicom = port_in(tcp.src_port, DICOM_PORT, options_.extra_dicom_ports) ||
                                    port_in(tcp.dst_port, DICOM_PORT, options_.extra_dicom_ports) ||
                                    port_in(tcp.src_port, DICOM_PORT_ALT, options_.extra_dicom_ports) ||
                                    port_in(tcp.dst_port, DICOM_PORT_ALT, options_.extra_dicom_ports);
    if (!declared && want_dicom && (!require_dicom_port || candidate_port_is_dicom)) {
        if (auto d = dicom_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "DICOM PDU";
        }
    }
    if (!declared && want_modbus) {
        // Registration-model pilot (Stage 2): modbus_tcp_declared_length is now reached through
        // ModbusDecoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see modbus.hpp.
        if (auto d = modbus_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "Modbus/TCP";
        }
    }
    // TwinCAT/ADS (AMS/TCP), tried right after Modbus -- see twincat.hpp's file header comment
    // and protocol_registry.hpp for the full collision survey/ordering rationale.
    if (!declared && want_twincat) {
        if (auto d = twincat_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "AMS/TCP (TwinCAT/ADS)";
        }
    }
    // BGP-4 (RFC 4271, TCP port 179), tried right after TwinCAT -- see bgp.hpp's file header
    // comment for the full wire format. No ordering rationale is actually needed here: BGP's own
    // structural gate (a 128-bit Marker that MUST be all-0xFF, RFC 4271 section 4.1) is the
    // strongest in this whole codebase -- stronger even than OPC UA's own 3-byte ASCII magic tried
    // first of all above -- so it cannot collide with anything else in this cascade regardless of
    // where it's tried.
    if (!declared && want_bgp) {
        if (auto d = bgp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "BGP-4 message";
        }
    }
    // Kerberos/TCP, tried right after BGP (itself right after TwinCAT, right after Modbus, right after MELSEC --
    // see MELSEC's own call site above for why it moved ahead of Modbus) -- see kerberos.hpp's file
    // header comment for the full collision survey/ordering rationale. kerberos_tcp_declared_length's
    // own gate (4-byte length prefix, then a peek at one of 7 recognized ASN.1 APPLICATION tag bytes)
    // is nearly as selective as the full decode gate, not merely "4+ bytes present".
    if (!declared && want_kerberos) {
        if (auto d = kerberos_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "Kerberos message (RFC 4120)";
        }
    }
    // LDAP/TCP, tried right after Kerberos -- see ldap.hpp's file header comment for the full
    // collision survey/ordering rationale. ldap_tcp_declared_length's own gate reuses
    // it_protocols.hpp's match_ldap_ber (outer SEQUENCE/length, INTEGER messageID, APPLICATION-class
    // protocolOp with a recognized op number) -- nearly as selective as the full decode gate, not
    // merely "7+ bytes present".
    if (!declared && want_ldap) {
        if (auto d = ldap_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "LDAP message (RFC 4511)";
        }
    }
    // SMB/TCP, tried right after LDAP -- see smb.hpp's file header comment for the full collision
    // survey/ordering rationale. smb_tcp_declared_length's own gate (4-byte Zero+StreamProtocolLength
    // prefix, then match_smb_magic on the 4 bytes that follow) is as selective as the full decode
    // gate itself -- there's no weaker "structural probe" version of the magic check to fall back to.
    if (!declared && want_smb) {
        if (auto d = smb_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "SMB message (MS-SMB2)";
        }
    }
    // WinRM (WS-Management over plaintext HTTP), TCP port 5985 -- deliberately PORT-GATED here in
    // Auto mode, unlike every structural-signature protocol above: WinRM's own framing signal is an
    // ordinary HTTP/1.1 request-line/status-line (it_protocols.hpp's match_http), which this
    // codebase's own Tier 2 "IT protocols an OT auditor flags" family already checks
    // opportunistically on every TCP port for generic "http" -- trying it here too,
    // port-independently, would just race that existing check for no benefit (see winrm.hpp's own
    // "COLLISION SURVEY" section). Gating by port in Auto mode lets this decoder win that race
    // specifically on WinRM's own port, while leaving every other port's HTTP traffic to Tier 2
    // exactly as before; an explicit `--protocol winrm` still tries it port-independently, the same
    // "gate only in Auto mode" exception DoH's own require_doh_port already establishes.
    // winrm_tcp_declared_length's own return value can (unlike every declared-length probe above)
    // legitimately exceed what's needed to recognize the message -- it can ask for one more byte at
    // a time while the HTTP header block itself is still arriving -- see that function's own doc
    // comment for why.
    bool require_winrm_port = options_.protocol_filter == ProtocolFilter::Auto;
    bool candidate_port_is_winrm = port_in(tcp.src_port, WINRM_PORT, options_.extra_winrm_ports) ||
                                    port_in(tcp.dst_port, WINRM_PORT, options_.extra_winrm_ports);
    if (!declared && want_winrm && (!require_winrm_port || candidate_port_is_winrm)) {
        if (auto d = winrm_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "WinRM/HTTP message";
        }
    }
    // DCOM activation, TCP port 135 -- deliberately PORT-GATED here in Auto mode, the same posture
    // WinRM just above already establishes for this gate kind: DCOM's own structural gate
    // (rpc_vers==5 plus a plausible frag_length, dcerpc_tcp_declared_length -- dcerpc.hpp) is
    // considerably weaker than SMB's own magic-byte check, so trying it opportunistically on every
    // TCP payload port-independently would risk false-positiving on ordinary binary traffic whose
    // first byte happens to be 5; gating by port in Auto mode avoids that, at no cost to real DCOM
    // traffic on its own well-known port (see dcom.hpp's own COLLISION SURVEY section -- port 135
    // has no existing recognizer to race against anyway, unlike WinRM's genuine HTTP collision, but
    // the "weak gate, so port-gate in Auto mode" reasoning still applies on its own). An explicit
    // `--protocol dcom` still tries it port-independently, the same exception every other
    // GateKind::TcpPort protocol here already has.
    bool require_dcom_port = options_.protocol_filter == ProtocolFilter::Auto;
    bool candidate_port_is_dcom = port_in(tcp.src_port, DCOM_PORT, options_.extra_dcom_ports) ||
                                   port_in(tcp.dst_port, DCOM_PORT, options_.extra_dcom_ports);
    if (!declared && want_dcom && (!require_dcom_port || candidate_port_is_dcom)) {
        if (auto d = dcom_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "DCOM/DCE-RPC message";
        }
    }
    // GE SRTP, TCP port 18245 -- deliberately PORT-GATED here in Auto mode, the same posture
    // WinRM/DCOM just above already establish for this gate kind: GE SRTP's own structural gate (a
    // small enumerated Packet Type plus Message Type, no magic-constant field at all -- see
    // ge_srtp.hpp's own "STRUCTURAL DETECTION GATE" section) is weaker than SMB's own magic-byte
    // check, so gating by port in Auto mode avoids opportunistically false-positiving on ordinary
    // binary traffic elsewhere. An explicit `--protocol ge-srtp` still tries it port-independently,
    // the same exception every other GateKind::TcpPort protocol here already has.
    // ge_srtp_declared_length only ever declares a fixed 56 for the SHORT-family/INIT-family
    // shapes -- EXTENDED/EXTENDED_ACK messages return std::nullopt here (no reliable trailing-
    // length field on the wire, see ge_srtp.hpp's own "DECLARED LENGTH" section), so this decoder
    // simply doesn't participate in cross-segment reassembly for that one shape.
    bool require_ge_srtp_port = options_.protocol_filter == ProtocolFilter::Auto;
    bool candidate_port_is_ge_srtp = port_in(tcp.src_port, GE_SRTP_PORT, options_.extra_ge_srtp_ports) ||
                                      port_in(tcp.dst_port, GE_SRTP_PORT, options_.extra_ge_srtp_ports);
    if (!declared && want_ge_srtp && (!require_ge_srtp_port || candidate_port_is_ge_srtp)) {
        if (auto d = ge_srtp_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "GE SRTP message";
        }
    }
    // AMQP (0-9-1 and 1.0), TCP port 5672 -- deliberately PORT-GATED here in Auto mode, the same
    // posture WinRM/DCOM/GE SRTP just above already establish for this gate kind: neither AMQP
    // version's own structural gate is a strong self-describing magic constant checked on every
    // TCP payload (the 8-byte "AMQP" preamble IS such a magic constant, but it only ever appears
    // once, on the very first bytes of a connection -- every subsequent frame in the same session
    // has no such marker, see amqp_common.hpp's own header comment), so gating by port in Auto
    // mode avoids false-positiving on ordinary binary traffic elsewhere. An explicit
    // `--protocol amqp091`/`--protocol amqp10` still tries the matching decoder port-
    // independently, the same exception every other GateKind::TcpPort protocol here already has.
    // Both decoders share one port-gate list (options_.extra_amqp_ports) since both versions ride
    // the same default port by convention -- see extra_amqp_ports's own doc comment in
    // decoder.hpp. amqp091_tcp_declared_length/amqp10_tcp_declared_length each independently
    // require the full 8-byte preamble to recognize a NEW connection's very first message (no
    // partial-preamble buffering, since a 4-7 byte prefix of "AMQP\x00..." cannot yet be told
    // apart from a 4-7 byte prefix of an entirely unrelated protocol) -- see amqp091.hpp/amqp10.hpp.
    bool require_amqp_port = options_.protocol_filter == ProtocolFilter::Auto;
    bool candidate_port_is_amqp = port_in(tcp.src_port, AMQP_PORT, options_.extra_amqp_ports) ||
                                   port_in(tcp.dst_port, AMQP_PORT, options_.extra_amqp_ports);
    if (!declared && want_amqp091 && (!require_amqp_port || candidate_port_is_amqp)) {
        if (auto d = amqp091_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "AMQP 0-9-1 frame";
        }
    }
    if (!declared && want_amqp10 && (!require_amqp_port || candidate_port_is_amqp)) {
        if (auto d = amqp10_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "AMQP 1.0 frame";
        }
    }
    if (!declared && want_dnp3) {
        // Migration batch 2: dnp3_link_frame_declared_length is now reached through
        // Dnp3Decoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see dnp3.hpp.
        if (auto d = dnp3_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "DNP3 data-link";
        }
    }
    if (!declared && (want_s7comm || want_mms || want_s7commplus)) {
        // Registration-model migration batch 2: tpkt_declared_length is now reached through
        // CotpDecoder::tcp_declared_length rather than called directly -- same function, same
        // semantics, see cotp.hpp.
        if (auto d = cotp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "TPKT/COTP";
        }
    }
    // HART-IP is tried LAST in this chain, deliberately -- unlike every protocol above, its own
    // structural detection gate is genuinely weak (two adjacent bytes each landing on one of a
    // handful of small values -- see hartip.hpp's "structural detection gate" paragraph). A real
    // collision WAS found while scoping this feature -- a HART-IP Session Initiate message's own
    // header (MessageID 0, Status almost always 0 -- the only value ever observed in this
    // decoder's own research) reads as a plausible Modbus/TCP MBAP header (protocol-id==0), the
    // same shape of collision this codebase already resolved once for IEC104 (see
    // try_parse_iec104_apci's header comment) by reordering. That fix isn't safe to repeat here,
    // though: unlike IEC104's own multi-field structural check, HART-IP's two-byte gate is weak
    // enough that trying it ahead of Modbus/DNP3/S7comm measurably regresses this project's own
    // existing Modbus/S7comm test corpus (confirmed empirically while scoping this feature -- ~2%
    // of ordinary Modbus/TCP traffic with a non-zero unit ID also happens to satisfy HART-IP's own
    // gate). So this decoder accepts, rather than resolves, the Session-Initiate-over-TCP
    // collision: it is tried last, and a genuine HART-IP Session Initiate message whose Status is
    // 0 will be misclassified as Modbus/TCP (or COTP/S7comm, or left as generic "tcp") when it
    // rides over TCP -- see tests/sample_hartip.pcap's own "known collision" packet and
    // hartip.hpp's LIMITATIONS-relevant note for the honest, documented scope of this gap. HART-IP
    // over UDP is entirely unaffected (UDP has no equivalent declared-length pre-check at all).
    if (!declared && want_hartip) {
        // Migration batch 2: hartip_declared_length is now reached through
        // HartIpTcpDecoder::tcp_declared_length -- same function, same semantics, see hartip.hpp.
        if (auto d = hartip_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "HART-IP message";
        }
    }
    // MQTT is tried LAST of all -- its own structural detection gate is honestly weaker still than
    // HART-IP's (a single leading byte, not two -- see mqtt.hpp's own "structural detection gate"
    // paragraph for the full comparison), so it gets the lowest priority in this opportunistic
    // dispatch chain, the same "weaker signal, lower priority" principle already established for
    // HART-IP itself. No specific byte-for-byte collision with another protocol above was found
    // during this feature's own research, but this ordering means any that do exist resolve in
    // every other protocol's favor, not MQTT's.
    //
    // One real, empirically-confirmed collision Tier 2 of the "IT protocols an OT auditor flags"
    // family DID find, though (see it_protocols.hpp's own file header comment): an FTP reply-code
    // line ("220 Welcome...") or command-verb line ("USER anonymous...") begins with ASCII bytes
    // that can coincidentally satisfy MQTT's own single-byte "control packet type + flags, then a
    // plausible variable-length-encoded remaining length" gate purely by chance (an ASCII digit or
    // uppercase letter's top nibble often lands on a valid MQTT control-packet-type value, and the
    // following byte, itself printable ASCII, is always < 0x80 and so parses as a complete one-byte
    // varint). Unlike HART-IP/MQTT/FF-HSE's own mutual "weaker signal, lower priority" ordering
    // above, this is resolved by PORT, the same way RDP's own collision with S7comm/MMS's COTP
    // framing is (see decode()'s own TCP dispatch, right before the S7comm/MMS COTP check): real
    // MQTT brokers do not run on FTP's own well-known control-channel port (21), so a candidate on
    // that port (or a configured --lateral-movement-port) that structurally matches an FTP reply-
    // code/command-verb line is deliberately excluded from MQTT's own declared-length probe below,
    // letting it fall straight through to Tier 2's own FTP recognition once reassembly completes
    // (immediately, since no declared-length framing claims it) rather than being buffered
    // indefinitely waiting for MQTT bytes that will never arrive.
    bool want_lateral_movement_reassembly = options_.protocol_filter == ProtocolFilter::Auto ||
                                             options_.protocol_filter == ProtocolFilter::LateralMovementOnly;
    bool candidate_is_ftp_control =
        want_lateral_movement_reassembly &&
        (port_in(tcp.src_port, FTP_CONTROL_PORT, options_.extra_lateral_movement_ports) ||
         port_in(tcp.dst_port, FTP_CONTROL_PORT, options_.extra_lateral_movement_ports)) &&
        looks_like_ftp_control_line(candidate);
    // The SAME shape of collision, found while implementing Tier 3: LDAP's own SEQUENCE tag byte
    // (0x30) is bit-for-bit identical to a valid MQTT PUBLISH control-packet-type/flags byte -- see
    // it_protocols.hpp's own looks_like_ldap_ber comment for the full reasoning. In practice this is
    // now moot for any genuine LDAP message reaching this point: LDAP has its own full
    // TcpPortIndependent decoder (ldap.hpp), tried well above MQTT in this same cascade (right after
    // Kerberos), so a real LDAP candidate is already claimed by `declared`/`which` above and never
    // falls through to here at all. This carve-out is kept anyway, unchanged, as a safety net for
    // ProtocolFilter combinations where LDAP's own probe didn't run (e.g. --protocol mqtt alone) --
    // same defense-in-depth posture as everywhere else in this cascade.
    bool want_enterprise_trust_reassembly = options_.protocol_filter == ProtocolFilter::Auto ||
                                             options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly ||
                                             options_.protocol_filter == ProtocolFilter::LdapOnly;
    bool candidate_is_ldap =
        want_enterprise_trust_reassembly &&
        (port_in(tcp.src_port, LDAP_PORT, options_.extra_ldap_ports) ||
         port_in(tcp.dst_port, LDAP_PORT, options_.extra_ldap_ports) ||
         port_in(tcp.src_port, LDAP_GC_PORT, options_.extra_ldap_ports) ||
         port_in(tcp.dst_port, LDAP_GC_PORT, options_.extra_ldap_ports)) &&
        looks_like_ldap_ber(candidate);
    if (!declared && want_mqtt && !candidate_is_ftp_control && !candidate_is_ldap) {
        // Migration batch 2: mqtt_declared_length is now reached through
        // MqttDecoder::tcp_declared_length -- same function, same semantics, see mqtt.hpp.
        if (auto d = mqtt_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "MQTT packet";
        }
    }
    // CODESYS V3 (Block Driver-framed TCP), tried right after MQTT and before FF-HSE -- its own
    // structural detection gate (a 4-byte exact magic, E8 17 01 00, plus a cross-checked Length
    // field bounded to [8, 520]) is a strong, TwinCAT-AMS/TCP-strength two-independently-
    // constrained-field check, so it is tried well ahead of FF-HSE's own genuinely weak single-byte
    // gate -- see codesys.hpp's file header comment for the wire format and full collision
    // reasoning (no specific byte-for-byte collision with any protocol above was found during this
    // decoder's own scoping).
    if (!declared && want_codesys) {
        if (auto d = codesys_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "CODESYS V3 (Block Driver/TCP)";
        }
    }
    // FF-HSE is tried LAST of all, even after MQTT -- its own structural detection gate is a
    // SINGLE byte at offset 2 (ProtocolAndType) landing on one of 12 valid values out of 256, plus
    // a Message Length >= 12 plausibility check that all but the smallest 12 possible 32-bit values
    // already satisfy -- honestly a WEAKER anchor than even HART-IP's own two-adjacent-byte gate
    // (see ffhse.hpp's own file header comment), so it gets the lowest priority in this
    // opportunistic, port-independent dispatch chain. No specific byte-for-byte collision with
    // another protocol above was found during this feature's own scoping, but given how weak this
    // gate is on its own, this ordering means any such collision resolves in every other protocol's
    // favor, not FF-HSE's -- the same "weaker signal, lower priority" principle already established
    // for HART-IP and MQTT above.
    if (!declared && want_ffhse) {
        // Registration-model migration: ffhse_declared_length is now reached through
        // FfhseTcpDecoder::tcp_declared_length -- same function, same semantics, see ffhse.hpp.
        if (auto d = ffhse_tcp_decoder().tcp_declared_length(candidate)) {
            declared = d;
            which = "FF-HSE PDU";
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
        // This is the only path that can actually grow tcp_reassembly_'s size (see this
        // function's own header comment): had_existing_entry is false exactly when flow_key had
        // no map entry before this call, so persisting it below adds a brand-new entry. Global
        // cap, defense in depth on top of the "don't retain empty entries" fix above -- a flow
        // that matches some protocol's own declared-length gate on every packet it sends can still
        // legitimately reach this branch every time, so the fix alone doesn't bound the map on its
        // own; this does. Unset (the default) skips the check entirely, same "byte-identical to
        // this feature's absence" posture every other resource_limits() field already has. No
        // per-entry recency tracking -- evicting tcp_reassembly_.begin() removes AN existing
        // in-progress reassembly, not necessarily the oldest one, from whichever bucket the hash
        // table iterates first. That's an accepted tradeoff: the security property this cap gives
        // is "the map never grows past max_active_flows", which an arbitrary eviction guarantees
        // exactly as well as LRU would; only the quality-of-service question of WHICH flow
        // occasionally has to restart its own reassembly from scratch is affected, and that's
        // already a normal, harmless occurrence elsewhere in this same function (every sequence-gap
        // abandon above does the same thing to its own flow).
        if (!had_existing_entry) {
            if (auto cap = resource_limits().max_active_flows) {
                if (tcp_reassembly_.size() >= *cap) {
                    tcp_reassembly_.erase(tcp_reassembly_.begin());
                    out.notes.push_back("active TCP flow-reassembly limit (" + std::to_string(*cap) +
                                         ") reached -- evicted an existing in-progress reassembly on "
                                         "another flow to make room for this one (--max-active-flows)");
                }
            }
        }
        tcp_reassembly_[flow_key] = std::move(fb);
        return false;
    }

    size_t completed_segment_count = fb.segment_count + (combined ? 1 : 0);
    // Deliberately NOT reinserted into tcp_reassembly_ -- this flow's buffer is fully consumed (or,
    // for the had_existing_entry==false case, was never created in the first place). See this
    // function's own header comment: this omission is the "don't retain empty entries" half of the
    // finding 1 fix.
    effective_payload = candidate;
    if (combined && declared) {
        out.notes.push_back("reassembled a " + which + " PDU/frame from " + std::to_string(candidate.size()) +
                             " byte(s) spanning " + std::to_string(completed_segment_count) +
                             " TCP segments on this flow");
    }
    return true;
}

// Decoder::pair_modbus_transaction used to live here. It moved to ModbusDecoder::decode
// (modbus.cpp) as part of the registration-model decoder refactor's pilot (Stage 2) -- see
// modbus.hpp's ModbusPendingRequest/ModbusFlowState and protocol_decoder.hpp's DecodeContext.
//
// Decoder::reassemble_cotp_data_frame used to live here too. It moved to CotpDecoder::decode
// (cotp.cpp) as part of migration batch 2 -- see cotp.hpp's CotpReassemblyState/CotpDecodeResult
// and protocol_decoder.hpp's DecodeContext::flow_state<T>(FlowStateKeying::DirectionalFlow).
//
// Decoder::process_dnp3_frame used to live here too. It moved to Dnp3Decoder::process_frame
// (dnp3.cpp), also as part of migration batch 2 -- see dnp3.hpp's Dnp3ReassemblyState/Dnp3Result
// and the same DecodeContext::flow_state<T>(FlowStateKeying::DirectionalFlow) extension.

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

            // IPv6 addition (docs/DEVELOPMENT.md ROADMAP item 24): ETHERTYPE_IPV6 joins
            // ETHERTYPE_IPV4 here rather than getting its own branch -- both just hand
            // eth.payload down to the shared version-sniffing parse_ipv4-or-parse_ipv6 dispatch
            // right below this whole if/else (see its own comment), the same dispatch a raw-IP
            // link type already has to do since it has no ethertype field to check at all. Every
            // OTHER ethertype below is unchanged.
            if (eth.ethertype != ETHERTYPE_IPV4 && eth.ethertype != ETHERTYPE_IPV6) {
                // Registration-model dispatch (see protocol_registry.hpp's own file header):
                // ethertype_registry() now DRIVES this cascade's dispatch order, rather than being
                // audit-trail data kept in sync by hand -- looping over it in order and trying
                // decode() on the first entry whose ethertype() matches this frame's (and whose
                // --protocol filter allows it) is exactly equivalent to the former hand-maintained
                // if-chain (PROFINET RT, GOOSE, SV, EtherCAT, EAPOL, PPPoE, MPLS, ARP, LLDP, Slow
                // Protocols, in that order -- see this vector's own doc comment for why that order
                // is safe: every EtherType here is IANA/IEEE-exclusive to its own protocol, so no
                // two entries can ever both match one frame). Each matched result's protocol-
                // specific dual-write still runs afterward via the populate_* functions defined
                // above this method (most of this cascade predates the newer no-dual-write
                // "out.result = *result" pattern that Slow Protocols already uses). STP has no
                // ethertype() at all (it's LLC-framed, see stp.hpp) so it can never match this loop
                // and stays its own explicit block below, unchanged, exactly where it always sat.
                for (const ProtocolDecoder* decoder : ethertype_registry()) {
                    std::optional<uint16_t> et = decoder->ethertype();
                    if (!et || *et != eth.ethertype) continue;
                    if (!ethertype_cascade_filter_allows(options_.protocol_filter, decoder->id())) continue;

                    DecodeContext ctx;
                    ctx.protocol_id = std::string(decoder->id());
                    auto result = decoder->decode(eth.payload, ctx);
                    if (!result) continue;

                    if (const EthertypeCascadePopulate* populate =
                            ethertype_cascade_populate_for(decoder->id())) {
                        (*populate)(out, *result, *et);
                    }
                    return out;
                }

                // STP (classic IEEE 802.3 LLC framing -- NOT any EtherType at all, see
                // link_layer.hpp's file header comment). Every branch above is EtherType-keyed
                // (ethertype >= 0x0800); a length-framed frame (eth.is_llc_length) can never match
                // any of them, since 802.3 Length values are always < 0x0600. This is entirely
                // additive: nothing above this point ever looked at a sub-0x0600 "ethertype" value.
                if (eth.is_llc_length && eth.has_llc) {
                    bool want_stp = options_.protocol_filter == ProtocolFilter::Auto ||
                                     options_.protocol_filter == ProtocolFilter::StpOnly;

                    // GARP (GVRP/GMRP) shares STP's own LLC DSAP/SSAP pair (0x42/0x42) --
                    // disambiguated only by destination MAC, matching the reference source
                    // (packet-bpdu.c's dissect_bpdu) exactly -- see stp.hpp's "GARP collision"
                    // paragraph. Checked before try_parse_stp is even called.
                    bool is_garp_dst = eth.dst_mac[0] == 0x01 && eth.dst_mac[1] == 0x80 &&
                                        eth.dst_mac[2] == 0xC2 && eth.dst_mac[3] == 0x00 &&
                                        eth.dst_mac[4] == 0x00 &&
                                        (eth.dst_mac[5] == 0x0D || (eth.dst_mac[5] & 0xF0) == 0x20);

                    if (want_stp && eth.llc_dsap == LLC_SAP_BPDU && eth.llc_ssap == LLC_SAP_BPDU &&
                        eth.llc_control == LLC_CONTROL_UI && !is_garp_dst) {
                        // Registration-model migration (batch 3): try_parse_stp is now reached
                        // through StpDecoder::decode rather than called directly -- same function,
                        // same semantics, see stp.hpp. The gating above (DSAP/SSAP/Control/GARP)
                        // stays right here at the call site, unchanged -- see StpDecoder's own
                        // comment in stp.hpp for why. The dual-write below is unchanged.
                        DecodeContext ctx;
                        ctx.protocol_id = "stp";
                        if (auto result = stp_decoder().decode(eth.llc_payload, ctx)) {
                            const StpFrame& stp = result->as<StpFrame>();
                            out.protocol = "stp";
                            out.summary = stp.summary;
                            for (const auto& n : stp.notes) out.notes.push_back(n);
                            if (eth.llc_trailing_bytes_trimmed > 0) {
                                out.notes.push_back(
                                    std::to_string(eth.llc_trailing_bytes_trimmed) +
                                    " trailing byte(s) after the 802.3 Length field's declared LLC "
                                    "client-data length were trimmed (almost always Ethernet "
                                    "minimum-frame-size padding, not real payload)");
                            }
                            out.result = *result;
                            return out;
                        }
                    }

                    // CDP (Cisco Discovery Protocol) -- see cdp.hpp's file header comment. Unlike
                    // STP just above (LLC-SAP-keyed: DSAP==SSAP==LLC_SAP_BPDU), CDP is SNAP-
                    // Protocol-ID-keyed: it rides the exact same LLC/SNAP envelope (DSAP==SSAP==
                    // LLC_SAP_SNAP under Cisco's OUI) that (R)PVST+ uses -- so it cannot collide
                    // with the STP branch above (different DSAP/SSAP entirely), but it very much
                    // COULD, and until this fix DID, collide with the generic "Cisco PVST+" naming
                    // right below.
                    //
                    // COLLISION FIX (docs/DEVELOPMENT.md roadmap item 48): before this fix, the
                    // "else if (eth.has_snap && eth.snap_oui == SNAP_OUI_CISCO)" branch below
                    // unconditionally reported EVERY Cisco-OUI SNAP frame as "Cisco PVST+ (SNAP-
                    // encapsulated, not decoded)", regardless of its actual SNAP Protocol ID -- so a
                    // real CDP frame (SNAP Protocol ID 0x2000) was silently mislabeled as PVST+.
                    // This was verified as a real, reproducible mislabeling (not a hypothetical)
                    // before this fix landed: a synthetic CDP-shaped SNAP frame, decoded through the
                    // pre-fix code, printed exactly "Cisco PVST+ (SNAP-encapsulated, not decoded)" --
                    // see tools/make_sample_pcap.py's own pinning-fixture packets in
                    // build_cdp_sample() and the cdp_pre_fix_pinning_* CTest entries below, which
                    // keep that pre-fix behavior pinned against regression by asserting it against
                    // deliberately-PVST+-PID (0x010B) traffic. Cisco's own SNAP Protocol ID registry
                    // (Wireshark's packet-cisco-oui.c, `cisco_pid_vals[]` -- see cdp.hpp's own
                    // "SNAP PROTOCOL ID" header comment) makes PVSTP+ (0x010B) and CDP (0x2000)
                    // genuinely, cleanly distinct values, so this dispatch now checks the SNAP
                    // Protocol ID itself: exactly SNAP_PID_CDP (0x2000) tries CDP decoding, below;
                    // every OTHER Cisco-OUI SNAP Protocol ID falls through to the naming chain right
                    // below, which itself now only claims the specific "Cisco PVST+" name for the
                    // frame whose PID is actually SNAP_PID_PVSTPP (0x010B), and names every other
                    // Cisco-OUI SNAP Protocol ID (VTP 0x2003, DTP 0x2004, PAgP 0x0104, UDLD 0x0111,
                    // CGMP 0x2001, or anything else this codebase doesn't decode) with a generic,
                    // honestly-scoped "Cisco SNAP frame (OUI=00:00:0C, ProtocolID=0xNNNN, not
                    // decoded)" label instead of the now-precise "PVST+" one.
                    bool want_cdp = options_.protocol_filter == ProtocolFilter::Auto ||
                                     options_.protocol_filter == ProtocolFilter::CdpOnly;
                    if (want_cdp && eth.has_snap && eth.snap_oui == SNAP_OUI_CISCO &&
                        eth.snap_protocol_id == SNAP_PID_CDP) {
                        DecodeContext ctx;
                        ctx.protocol_id = "cdp";
                        if (auto result = cdp_decoder().decode(eth.llc_payload, ctx)) {
                            const CdpFrame& cdp = result->as<CdpFrame>();
                            out.protocol = "cdp";
                            out.summary = cdp.summary;
                            for (const auto& n : cdp.notes) out.notes.push_back(n);
                            out.result = *result;
                            return out;
                        }
                        // try_parse_cdp only ever returns nullopt when fewer than 4 bytes are
                        // present -- too short to even read the fixed Version/TTL/Checksum header
                        // (see cdp.hpp) -- named explicitly as CDP-but-truncated rather than falling
                        // through to the generic Cisco-SNAP naming below, since the SNAP Protocol ID
                        // match already confirms this WAS meant to be CDP.
                        out.protocol = "non-ip";
                        out.summary = "Cisco Discovery Protocol (SNAP-encapsulated), too short to "
                                      "decode (need at least 4 bytes for the Version/TTL/Checksum "
                                      "header)";
                        return out;
                    }

                    // Not STP, not CDP (or the GARP-destination-MAC / non-STP-DSAP fallback above)
                    // -- named structurally where cheaply possible, never guessed at further.
                    out.protocol = "non-ip";
                    std::ostringstream s;
                    if (is_garp_dst && eth.llc_dsap == LLC_SAP_BPDU && eth.llc_ssap == LLC_SAP_BPDU) {
                        s << "GARP (GVRP/GMRP) -- shares STP's Bridge Group Address DSAP/SSAP "
                             "(0x42/0x42), disambiguated by destination MAC, not decoded";
                    } else if (eth.has_snap && eth.snap_oui == SNAP_OUI_CISCO &&
                               eth.snap_protocol_id == SNAP_PID_PVSTPP) {
                        s << "Cisco PVST+ (SNAP-encapsulated, not decoded)";
                    } else if (eth.has_snap && eth.snap_oui == SNAP_OUI_CISCO) {
                        // Any other Cisco-OUI SNAP Protocol ID (VTP/DTP/PAgP/UDLD/CGMP/etc, or CDP's
                        // own 0x2000 when --protocol restricts detection to something other than cdp
                        // -- see want_cdp above) -- see this branch's own COLLISION FIX comment above
                        // for why this is no longer lumped into the "Cisco PVST+" name.
                        s << "Cisco SNAP frame (OUI=00:00:0C, ProtocolID=0x" << std::hex
                          << std::uppercase << std::setw(4) << std::setfill('0')
                          << eth.snap_protocol_id << std::dec << std::setfill(' ') << ", not decoded)";
                    } else if (eth.has_snap) {
                        s << "IEEE 802.3 LLC/SNAP frame, DSAP=0x" << std::hex << std::uppercase
                          << static_cast<unsigned>(eth.llc_dsap) << " SSAP=0x"
                          << static_cast<unsigned>(eth.llc_ssap) << " OUI=" << std::setw(2)
                          << std::setfill('0') << static_cast<unsigned>(eth.snap_oui[0]) << ":"
                          << std::setw(2) << static_cast<unsigned>(eth.snap_oui[1]) << ":"
                          << std::setw(2) << static_cast<unsigned>(eth.snap_oui[2])
                          << " ProtocolID=0x" << std::setw(4) << eth.snap_protocol_id << std::dec
                          << std::setfill(' ');
                    } else {
                        s << "IEEE 802.3 LLC frame, DSAP=0x" << std::hex << std::uppercase
                          << static_cast<unsigned>(eth.llc_dsap) << " SSAP=0x"
                          << static_cast<unsigned>(eth.llc_ssap) << " Control=0x"
                          << static_cast<unsigned>(eth.llc_control) << std::dec
                          << " (length=" << eth.length_field << ")";
                    }
                    out.summary = s.str();
                    return out;
                }

                out.protocol = "non-ip";
                std::ostringstream s;
                if (eth.is_llc_length) {
                    s << "IEEE 802.3 frame, length=" << eth.length_field
                      << " (too short for an LLC header)";
                } else {
                    s << "Ethernet frame with ethertype 0x" << std::hex << eth.ethertype << std::dec;
                    std::string name = ethertype_name(eth.ethertype);
                    if (!name.empty()) s << " (" << name << ")";
                    s << " (not IPv4)";
                }
                out.summary = s.str();
                return out;
            }
            network_layer_payload = eth.payload;
        } else if (link_type == LINKTYPE_RAW) {
            network_layer_payload = frame;
        } else if (link_type == LINKTYPE_CAN_SOCKETCAN) {
            // DeviceNet (CAN-bus CIP) / CANopen (CiA 301) / SAE J1939 -- see can_socketcan.hpp/
            // devicenet.hpp/canopen.hpp/j1939.hpp. A wholly separate link layer from Ethernet:
            // has_ethernet and has_ip both stay false for every packet reached this way (no MAC
            // addresses, no IP layer at all). This returns directly, the same pattern the
            // EtherType-keyed non-IPv4 branches above use, rather than falling through to the
            // IPv4/TCP/UDP parsing below, which has nothing to do here.
            CanSocketcanFrame can = parse_socketcan_frame(frame);
            // NOTE: can.notes (e.g. a truncated-payload note) is NOT copied into out.notes here --
            // each of try_parse_devicenet/try_parse_canopen/try_parse_j1939's own *Frame::notes
            // already forwards every CanSocketcanFrame note verbatim, and the fallback branch below
            // adds them itself, so copying here too would duplicate every such note.

            bool want_devicenet = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::DevicenetOnly;
            // CANopen deliberately does NOT join Auto mode -- see canopen.hpp's own file header
            // comment (the "THE DEVICENET-VS-CANOPEN DISPATCH COLLISION" section) for the full,
            // from-source analysis of why: both protocols classify literally the entire 11-bit
            // standard CAN ID space into named categories of their own, with no bit shape either
            // one's own reference dissector checks that the other would ever violate, so there is
            // no reliable structural way to try both opportunistically without silently
            // reclassifying a large fraction of every existing DeviceNet capture's own frames.
            // An explicit --protocol canopen is required.
            bool want_canopen = options_.protocol_filter == ProtocolFilter::CanopenOnly;
            // J1939, by contrast, DOES join Auto mode alongside DeviceNet -- see j1939.hpp's own
            // file header comment: its Extended (29-bit) CAN ID requirement is a genuine, hardware-
            // enforced disjoint gate from DeviceNet/CANopen's own standard-ID space (both of which
            // categorically reject any EFF-flagged frame outright, mirrored from each protocol's own
            // reference dissector), so there is no collision here to avoid the way there is with
            // CANopen above.
            bool want_j1939 = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::J1939Only;

            if (can.eff) {
                // Extended (29-bit) ID -- DeviceNet and CANopen both categorically reject this shape
                // (see devicenet.hpp/canopen.hpp); only J1939 (SAE J1939) legitimately uses it, so
                // this is the one sub-branch where DeviceNet/CANopen are never even attempted.
                if (want_j1939) {
                    DecodeContext ctx;
                    ctx.packet_index = index;
                    ctx.protocol_id = "j1939";
                    if (auto result = j1939_decoder().decode(frame, ctx)) {
                        const J1939Frame& jf = result->as<J1939Frame>();
                        out.protocol = "j1939";
                        out.summary = jf.summary;
                        for (const auto& n : jf.notes) out.notes.push_back(n);
                        out.result = *result;
                        return out;
                    }
                }
                for (const auto& n : can.notes) out.notes.push_back(n);
                out.protocol = "non-ip";
                std::ostringstream s;
                s << "CAN frame, id=0x" << std::hex << std::uppercase << can.id << std::dec
                  << " [EFF -- extended 29-bit id]";
                if (can.err) s << " [ERR -- error frame]";
                s << (can.err ? " (not a valid J1939 frame shape)"
                               : " (not decoded -- J1939 decoding disabled by --protocol)");
                out.summary = s.str();
                return out;
            }

            if (want_devicenet) {
                // Registration-model migration: try_parse_devicenet is now reached through
                // DeviceNetDecoder::decode -- the first GateKind::LinkType decoder (see
                // protocol_decoder.hpp's own comment on that gate kind). DeviceNet is a
                // zero-flat-field migrated protocol (like TwinCAT/HART-IP/etc.): out.result
                // carries the whole DeviceNetFrame, and output.cpp's write_devicenet_json_fields
                // reads straight from it. decode() re-parses the same SocketCAN header `can`
                // above already did (harmless -- parse_socketcan_frame is a handful of cheap
                // fixed-offset reads with no allocation on the non-truncated path) rather than
                // taking a CanSocketcanFrame directly, so it fits ProtocolDecoder::decode's shared
                // ByteSpan signature the same way every other migrated protocol's decode() does;
                // `can` itself stays needed here regardless, for the not-DeviceNet fallback
                // classification below. See devicenet.hpp's own DeviceNetDecoder comment for the
                // one deliberate deviation this call makes from every sibling decode(): it can
                // throw ParseError, exactly as this line always could before migration.
                DecodeContext ctx;
                ctx.packet_index = index;
                ctx.protocol_id = "devicenet";
                if (auto result = devicenet_decoder().decode(frame, ctx)) {
                    const DeviceNetFrame& dn = result->as<DeviceNetFrame>();
                    out.protocol = "devicenet";
                    out.summary = dn.summary;
                    for (const auto& n : dn.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }

            if (want_canopen) {
                // Same "zero-flat-field migrated protocol" shape as DeviceNet just above, see
                // canopen.hpp's own CanopenDecoder comment for the ParseError deviation.
                DecodeContext ctx;
                ctx.packet_index = index;
                ctx.protocol_id = "canopen";
                if (auto result = canopen_decoder().decode(frame, ctx)) {
                    const CanopenFrame& cf = result->as<CanopenFrame>();
                    out.protocol = "canopen";
                    out.summary = cf.summary;
                    for (const auto& n : cf.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }

            // Not DeviceNet (RTR/ERR flag set -- see can_socketcan.hpp/devicenet.hpp), and either
            // CANopen wasn't explicitly requested or (structurally impossible, since try_parse_canopen
            // shares DeviceNet's own eff/rtr/err rejection exactly) didn't recognize it either --
            // named structurally, never decoded further.
            for (const auto& n : can.notes) out.notes.push_back(n);
            out.protocol = "non-ip";
            std::ostringstream s;
            s << "CAN frame, id=0x" << std::hex << std::uppercase << can.id << std::dec;
            if (can.rtr) s << " [RTR -- remote transmission request]";
            if (can.err) s << " [ERR -- error frame]";
            if (!can.rtr && !can.err) {
                if (want_canopen) {
                    s << " (not a valid CANopen frame shape)";
                } else {
                    s << " (not decoded -- DeviceNet decoding disabled by --protocol)";
                }
            } else {
                if (want_canopen) {
                    s << " (not a valid DeviceNet/CANopen frame shape)";
                } else {
                    s << " (not a valid DeviceNet frame shape)";
                }
            }
            out.summary = s.str();
            return out;
        } else if (link_type == LINKTYPE_IEEE802_15_4_WITHFCS || link_type == LINKTYPE_IEEE802_15_4_TAP) {
            // Zigbee (IEEE 802.15.4 MAC + NWK + APS + ZDP) -- see ieee802154.hpp/zigbee.hpp. A
            // wholly separate link layer from Ethernet: has_ethernet and has_ip both stay false for
            // every packet reached this way, the same posture the LINKTYPE_CAN_SOCKETCAN/DeviceNet
            // branch above already established for this codebase's other non-Ethernet link type.
            // This returns directly, never falling through to the IPv4/TCP/UDP parsing below.
            //
            // TWO LINK TYPES, ONE SHARED ZIGBEE PARSE: this branch is the one place that has to
            // know which of the two in-scope capture formats produced `frame` -- see
            // ieee802154.hpp's own file header comment for why that knowledge doesn't belong inside
            // a single ProtocolDecoder::decode() call, and zigbee.hpp's own ZigbeeDecoder class
            // comment for the full design rationale. Once parsed into one shared Ieee802154Frame,
            // both link types converge on the exact same try_parse_zigbee(...) call below.
            Ieee802154Frame mac = (link_type == LINKTYPE_IEEE802_15_4_WITHFCS)
                                       ? parse_ieee802154_withfcs(frame)
                                       : parse_ieee802154_tap(frame);

            bool want_zigbee = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::ZigbeeOnly;

            if (want_zigbee) {
                // try_parse_zigbee is called directly here (not through ZigbeeDecoder::decode(),
                // which can only assume one capture format) -- see zigbee.hpp's own class comment.
                // Zigbee is a zero-flat-field migrated protocol (like DeviceNet/TwinCAT): out.result
                // carries the whole ZigbeeFrame (which itself embeds the full Ieee802154Frame MAC
                // decode -- see zigbee.hpp), and output.cpp's write_zigbee_json_fields reads
                // straight from it.
                if (auto zf = try_parse_zigbee(mac)) {
                    out.protocol = "zigbee";
                    out.summary = zf->summary;
                    for (const auto& n : zf->notes) out.notes.push_back(n);
                    out.result = ProtocolResult::make<ZigbeeFrame>("zigbee", std::move(*zf));
                    return out;
                }
            }

            // Not a Zigbee-carrying frame (a Beacon/Ack/MAC-Command MAC frame type, or Zigbee
            // decoding disabled by --protocol) -- named structurally by its MAC Frame Type, never
            // decoded further, the same "recognized link/frame shape, not this protocol" fallback
            // posture the CAN/DeviceNet branch above already established.
            for (const auto& n : mac.notes) out.notes.push_back(n);
            out.protocol = "non-ip";
            std::ostringstream s;
            s << "IEEE 802.15.4 " << ieee802154_frame_type_name(mac.frame_type) << " frame";
            if (mac.has_seqno) s << ", seq=" << static_cast<unsigned>(mac.seqno);
            if (mac.frame_type == 1 /* Data */ && !want_zigbee) {
                s << " (not decoded -- Zigbee decoding disabled by --protocol)";
            } else if (mac.frame_type == 1 /* Data */) {
                s << " (not a valid Zigbee NWK frame shape)";
            } else {
                s << " (not decoded -- not a Zigbee NWK-carrying MAC frame type)";
            }
            out.summary = s.str();
            return out;
        } else {
            out.protocol = "unsupported-link";
            out.summary = "capture link type " + std::to_string(link_type) +
                           " is not supported in this groundwork release (only Ethernet, raw IP, "
                           "SocketCAN, and IEEE 802.15.4 WITHFCS/TAP are)";
            return out;
        }

        // Version-sniff (IPv6 addition, docs/DEVELOPMENT.md ROADMAP item 24): a raw-IP link type
        // has no ethertype field to tell IPv4 and IPv6 apart with, and an Ethernet frame carrying
        // ETHERTYPE_IPV6 lands here too (see this function's own EtherType branch above, which
        // now lets ETHERTYPE_IPV6 through alongside ETHERTYPE_IPV4 rather than giving it a
        // separate call site) -- both converge on checking the actual IP version nibble, the one
        // signal that's always present regardless of how the packet arrived. Anything that's
        // neither 4 nor 6 falls through to parse_ipv4 exactly as it always did before this
        // addition, which throws ParseError for a version field that isn't 4 -- unchanged
        // behavior for a non-IP/corrupt/truncated raw-IP-link payload.
        if (!network_layer_payload.empty() && (network_layer_payload.at(0) >> 4) == 6) {
            Ipv6Header ip6 = parse_ipv6(network_layer_payload);
            out.has_ip = true;
            out.src_ip = format_ipv6(ip6.src_addr);
            out.dst_ip = format_ipv6(ip6.dst_addr);
            out.ip_protocol = ip6.next_header;
            out.ttl = ip6.hop_limit;
            if (ip6.trailing_bytes_trimmed > 0) {
                out.notes.push_back(std::to_string(ip6.trailing_bytes_trimmed) +
                                     " trailing byte(s) after the IPv6 header's declared payload "
                                     "length (and every extension header this parse walked past) "
                                     "were trimmed (almost always Ethernet minimum-frame-size "
                                     "padding, not real payload)");
            }
            return decode_ip_payload(std::move(out), ip6.next_header, ip6.payload, ip6.hop_limit, index,
                                      /*ip_version=*/6, /*ipv4_src_addr_for_igrp=*/0);
        }

        Ipv4Header ip = parse_ipv4(network_layer_payload);
        out.has_ip = true;
        out.src_ip = format_ipv4(ip.src_addr);
        out.dst_ip = format_ipv4(ip.dst_addr);
        out.ip_protocol = ip.protocol;
        out.ttl = ip.ttl;
        // Attack detection (see attack_detect.hpp): IP Source Routing, Ping of Death, and
        // Teardrop are all IP-fragmentation/IP-option-level checks that don't need to wait for
        // TCP/UDP/ICMP dispatch below -- run once here, right after the IPv4 header itself is
        // parsed. IPv6 has no equivalent call site (see attack_detect.hpp's own file header).
        attack_state_.observe_ipv4(ip, out.notes);
        if (ip.trailing_bytes_trimmed > 0) {
            out.notes.push_back(std::to_string(ip.trailing_bytes_trimmed) +
                                 " trailing byte(s) after the IP header's declared total length were "
                                 "trimmed (almost always Ethernet minimum-frame-size padding, not real "
                                 "payload)");
        }
        return decode_ip_payload(std::move(out), ip.protocol, ip.payload, ip.ttl, index, /*ip_version=*/4,
                                  /*ipv4_src_addr_for_igrp=*/ip.src_addr);

    } catch (const ParseError& e) {
        if (options_.strict) {
            throw;
        }
        out.protocol = "parse-error";
        out.summary = std::string("could not parse packet: ") + e.what();
        return out;
    }
}

// Version-agnostic continuation of Decoder::decode() above, extracted verbatim (mechanical rename
// only -- ip.protocol/ip.payload/ip.ttl become the protocol/payload/ttl_or_hop_limit parameters
// below, no logic changed) so both the IPv4 and IPv6 branches above can share every protocol-
// number/TCP/UDP dispatch decision that never actually depended on which IP version got it here --
// the ~44 IP-protocol-number/TCP-port/UDP-port-keyed decoders in this cascade (Modbus, DNP3,
// S7comm, MQTT, EIGRP, ICMP's own protocol-number gate, ...) have no IPv4-specific logic of their
// own; nothing ever handed them an IPv6 flow before this addition, not because each one was
// individually scoped out (docs/DEVELOPMENT.md ROADMAP item 24's own wording). `out` is taken and
// returned BY VALUE, the same "cheap enough to copy, DecodedPacket already is" posture
// ProtocolResult's own file header comment documents -- every one of this cascade's own many
// `return out;` exit points below is completely unchanged from before this extraction.
//
// ip_version (4 or 6) is used in exactly one place below (the "not TCP" fallback's own summary
// text) -- everything else in this ~2000-line cascade genuinely never needed to know which IP
// version it came from, which is the whole point of extracting it this way rather than
// duplicating the cascade per version.
DecodedPacket Decoder::decode_ip_payload(DecodedPacket out, uint8_t protocol, ByteSpan payload,
                                          uint8_t ttl_or_hop_limit, size_t index, int ip_version,
                                          uint32_t ipv4_src_addr_for_igrp) const {
    (void)ttl_or_hop_limit;  // out.ttl is already populated by both callers before this is reached;
                              // kept as a parameter for symmetry with protocol/payload and because a
                              // future caller of this cascade may need it even though none in this
                              // cascade's own body currently reads it back out (out.ttl already holds
                              // it).
    try {
        if (protocol == IPPROTO_UDP_VALUE) {
            // Unlike TCP, a UDP datagram is already a complete, self-delimited unit, so none of
            // the TCP-segment reassembly machinery below applies here at all.
            UdpDatagram udp = parse_udp(payload);
            out.has_udp = true;
            out.src_port = udp.src_port;
            out.dst_port = udp.dst_port;
            // Attack detection (see attack_detect.hpp): Fraggle + UDP flood counter. Runs
            // regardless of which application-layer protocol (if any) this datagram is
            // subsequently recognized as -- out.notes is additive, never reset below.
            attack_state_.observe_udp(udp, out.dst_ip, out.notes);

            // Tried first, port-independently, same rationale as EtherNet/IP explicit messaging's
            // own TCP dispatch below: try_parse_cip_io's structural check (an exact CPF item
            // type + exact length) is strong enough to run unconditionally in Auto mode -- see its
            // header comment in enip.hpp.
            bool want_enip_io = options_.protocol_filter == ProtocolFilter::Auto ||
                                 options_.protocol_filter == ProtocolFilter::EnipOnly;
            if (want_enip_io) {
                // Migration batch 2: try_parse_cip_io is now reached through
                // EnipUdpDecoder::decode -- CIP I/O needs no coalescing/merging of its own, so
                // decode() is a direct pass-through and the returned ProtocolResult's payload IS
                // the CipIoFrame itself. See enip.hpp/enip.cpp. This shares its "enip" id() with
                // EnipTcpDecoder above (the TCP explicit-messaging side) -- first intentionally-
                // shared id() in this codebase's registration-model decoders, see EnipTcpDecoder's
                // own comment for why that's safe.
                DecodeContext enip_io_ctx;
                enip_io_ctx.packet_index = index;
                enip_io_ctx.protocol_id = "enip";
                enip_io_ctx.flow_states = &registry_flow_state_;
                if (auto io_result = enip_udp_decoder().decode(udp.payload, enip_io_ctx)) {
                    const CipIoFrame& io = io_result->as<CipIoFrame>();
                    out.protocol = "enip";
                    out.summary = io.summary;
                    for (const auto& n : io.notes) out.notes.push_back(n);
                    out.result = *io_result;

                    bool expected_port = port_in(udp.src_port, ENIP_IO_UDP_PORT, options_.extra_enip_io_ports) ||
                                          port_in(udp.dst_port, ENIP_IO_UDP_PORT, options_.extra_enip_io_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard EtherNet/IP CIP I/O port "
                                             "(2222)");
                    }
                    return out;
                }
            }

            // Also tried first, port-independently -- try_parse_bacnet's structural check (BVLC
            // Type==0x81 + Function in the 13-value 0x00-0x0C range) is a 2-byte anchor, the same
            // "opportunistic, payload-shape" posture as CIP I/O's own check just above -- see
            // bacnet.hpp's "structural detection gate" paragraph.
            bool want_bacnet = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::BacnetOnly;
            if (want_bacnet) {
                // Migration batch 2: try_parse_bacnet is now reached through BacnetDecoder::decode
                // -- BACnet/IP is purely stateless, so ctx is passed only because
                // ProtocolDecoder::decode's signature requires one. Unlike EtherNet/IP's CIP I/O
                // and HART-IP's own UDP path, no new result-wrapper type was needed -- BacnetFrame
                // already carries everything this call site dual-writes, so decode() returns it
                // unwrapped. See bacnet.hpp/bacnet.cpp.
                DecodeContext bacnet_ctx;
                bacnet_ctx.packet_index = index;
                bacnet_ctx.protocol_id = "bacnet";
                bacnet_ctx.flow_states = &registry_flow_state_;
                if (auto bacnet = bacnet_decoder().decode(udp.payload, bacnet_ctx)) {
                    const BacnetFrame& bf = bacnet->as<BacnetFrame>();
                    out.protocol = "bacnet";
                    out.summary = bf.summary;
                    for (const auto& n : bf.notes) out.notes.push_back(n);
                    out.result = *bacnet;

                    bool expected_port = port_in(udp.src_port, BACNET_UDP_PORT, options_.extra_bacnet_ports) ||
                                          port_in(udp.dst_port, BACNET_UDP_PORT, options_.extra_bacnet_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard BACnet/IP port (47808)");
                    }
                    return out;
                }
            }

            // CC-Link IE Field Network Basic (CCIEFB cyclic data + SLMP node search/set-IP-address)
            // over UDP -- a brand-new protocol, NOT part of migration batch 2, deliberately tried
            // BEFORE MELSEC's own UDP block just below: CCIEFB/node-search/set-IP ride the exact
            // same SLMP 3E/4E outer framing MELSEC's own decoder already parses, and MELSEC's own
            // decoder treats any command code it doesn't recognize as a structurally-valid
            // "unrecognized command" MELSEC frame rather than rejecting it outright -- so if MELSEC
            // ran first, a real CCIEFB/node-search/set-IP REQUEST would be silently swallowed and
            // mislabeled "melsec" (confirmed via this protocol's own required manual verification,
            // not theoretically). This decoder's own request-side gate is strictly MORE specific
            // than MELSEC's (exact command-code match 0x0E70/0x0E30/0x0E31, on top of the same
            // subheader+declared-length cross-check MELSEC itself uses), and MELSEC's own command
            // table never uses those three values, so this ordering is safe by construction: every
            // genuine MELSEC command still reaches MELSEC's decoder untouched. See cclink_ie.hpp's
            // own "DISPATCH ORDER" section for the full writeup, and its "RESPONSES CARRY NO
            // COMMAND FIELD" section for why a *response* additionally needs this decoder's own
            // session-scoped CclinkIeFlowState (mirroring MelsecFlowState) rather than just the
            // request-side command-code gate: an orphan CC-Link IE response (no tracked request on
            // this session) is deliberately NOT claimed here and falls through to MELSEC's own
            // decoder instead, exactly like MELSEC already does for its own orphan responses.
            bool want_cclink_ie = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::CclinkIeOnly;
            if (want_cclink_ie) {
                std::string udp_session =
                    tcp_session_key(out.src_ip, udp.src_port, out.dst_ip, udp.dst_port);
                DecodeContext ctx;
                ctx.flow_key = format_flow_endpoint(out.src_ip, udp.src_port) + "->" +
                               format_flow_endpoint(out.dst_ip, udp.dst_port);
                ctx.session_key = udp_session;
                ctx.packet_index = index;
                ctx.protocol_id = "cclink-ie";
                ctx.flow_states = &registry_flow_state_;
                if (auto result = cclink_ie_decoder().decode(udp.payload, ctx)) {
                    const CclinkIeFrame& cf = result->as<CclinkIeFrame>();
                    out.protocol = "cclink-ie";
                    out.summary = cf.summary;
                    for (const auto& n : cf.notes) out.notes.push_back(n);
                    out.result = *result;

                    bool expected_port =
                        port_in(udp.src_port, CCLINK_IE_CYCLIC_PORT, options_.extra_cclink_ie_ports) ||
                        port_in(udp.dst_port, CCLINK_IE_CYCLIC_PORT, options_.extra_cclink_ie_ports) ||
                        port_in(udp.src_port, CCLINK_IE_NODE_SEARCH_PORT, options_.extra_cclink_ie_ports) ||
                        port_in(udp.dst_port, CCLINK_IE_NODE_SEARCH_PORT, options_.extra_cclink_ie_ports);
                    if (!expected_port) {
                        out.notes.push_back(
                            "seen on UDP port " + std::to_string(udp.src_port) + "->" +
                            std::to_string(udp.dst_port) +
                            ", which is not a configured/standard CC-Link IE port (61450 cyclic, "
                            "61451 node search/set IP address)");
                    }
                    return out;
                }
            }

            // CODESYS V3 over UDP (ports 1740-1743, all four sharing identical Datagram/Router-
            // layer framing -- no Block Driver header at all on this transport), tried right after
            // CC-Link IE -- its own three-independently-constrained-field Datagram-layer header
            // (exact Magic 0xC5, ServiceId one of five values, AddressLengths exactly 0x43/0x34) is
            // a comparably strong opportunistic gate, and no byte-for-byte collision with CC-Link
            // IE, MELSEC, FINS, BACnet, or any protocol tried below was found during this decoder's
            // own scoping -- see codesys.hpp's file header comment for the wire format and full
            // collision reasoning.
            bool want_codesys_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                     options_.protocol_filter == ProtocolFilter::CodesysOnly;
            if (want_codesys_udp) {
                DecodeContext ctx;
                ctx.packet_index = index;
                ctx.protocol_id = "codesys";
                ctx.flow_states = &registry_flow_state_;
                if (auto result = codesys_udp_decoder().decode(udp.payload, ctx)) {
                    const CodesysFrame& cf = result->as<CodesysFrame>();
                    out.protocol = "codesys";
                    out.summary = cf.summary;
                    for (const auto& n : cf.notes) out.notes.push_back(n);
                    out.result = *result;

                    bool expected_port =
                        port_in(udp.src_port, CODESYS_UDP_PORT_0, options_.extra_codesys_ports) ||
                        port_in(udp.dst_port, CODESYS_UDP_PORT_0, options_.extra_codesys_ports) ||
                        port_in(udp.src_port, CODESYS_UDP_PORT_1, options_.extra_codesys_ports) ||
                        port_in(udp.dst_port, CODESYS_UDP_PORT_1, options_.extra_codesys_ports) ||
                        port_in(udp.src_port, CODESYS_UDP_PORT_2, options_.extra_codesys_ports) ||
                        port_in(udp.dst_port, CODESYS_UDP_PORT_2, options_.extra_codesys_ports) ||
                        port_in(udp.src_port, CODESYS_UDP_PORT_3, options_.extra_codesys_ports) ||
                        port_in(udp.dst_port, CODESYS_UDP_PORT_3, options_.extra_codesys_ports);
                    if (!expected_port) {
                        out.notes.push_back(
                            "seen on UDP port " + std::to_string(udp.src_port) + "->" +
                            std::to_string(udp.dst_port) +
                            ", which is not a configured/standard CODESYS UDP port "
                            "(1740-1743)");
                    }
                    return out;
                }
            }

            // MELSEC (MC Protocol/SLMP) over UDP, tried right after BACnet and CIP I/O -- see
            // melsec.hpp's file header comment for the wire format. Same session-scoped
            // request/command tracking (MelsecFlowState) as the TCP side, not authoritative
            // pairing (no unique transaction ID on the wire) -- see melsec.hpp/melsec.cpp for why
            // a response needs it anyway (MELSEC responses carry no command field of their own at
            // all). Deliberately placed BEFORE HART-IP's own weaker structural gate further down:
            // HART-IP's UDP check only requires payload byte[1] (MessageType) in {0,1,2,3,15},
            // byte[2] (MessageID) in {0,1,2,3}, and bytes[6:8] read big-endian (MsgLength) >= 8 --
            // a real MELSEC 3E/4E request or response routinely satisfies all three incidentally
            // (e.g. subheader 0x5000's low byte 0x00 is a valid MessageType, a Network No. of 0 is
            // a valid MessageID, and any Batch/Random Read-Write's declared length is very
            // commonly >= 8), so if HART-IP's weaker check ran first it would silently steal
            // genuine MELSEC traffic. MELSEC's own two-part gate (exact 16-bit subheader magic +
            // exact declared-length cross-check) is far stronger and has no realistic reverse
            // collision risk against real HART-IP traffic (whose Version byte is small, not one of
            // 0x50/0xD0/0x54/0xD4), so trying MELSEC first is the correct "stronger gate wins"
            // resolution -- the same principle IEC104-before-Modbus and QUIC-before-HART-IP (just
            // above) already establish in this cascade. Confirmed empirically during this
            // protocol's own manual smoke test, which is what caught the collision in the first
            // place.
            bool want_melsec = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::MelsecOnly;
            if (want_melsec) {
                std::string udp_session =
                    tcp_session_key(out.src_ip, udp.src_port, out.dst_ip, udp.dst_port);
                DecodeContext ctx;
                ctx.flow_key = format_flow_endpoint(out.src_ip, udp.src_port) + "->" +
                               format_flow_endpoint(out.dst_ip, udp.dst_port);
                ctx.session_key = udp_session;
                ctx.packet_index = index;
                ctx.protocol_id = "melsec";
                ctx.flow_states = &registry_flow_state_;
                if (auto result = melsec_udp_decoder().decode(udp.payload, ctx)) {
                    const MelsecFrame& mf = result->as<MelsecFrame>();
                    out.protocol = "melsec";
                    out.summary = mf.summary;
                    for (const auto& n : mf.notes) out.notes.push_back(n);
                    out.result = *result;

                    bool expected_port = port_in(udp.src_port, MELSEC_UDP_PORT, options_.extra_melsec_ports) ||
                                          port_in(udp.dst_port, MELSEC_UDP_PORT, options_.extra_melsec_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard MELSEC port (5000)");
                    }
                    return out;
                }
            }

            // FINS (Omron) over UDP, tried right after MELSEC and, like MELSEC, deliberately placed
            // BEFORE HART-IP's own weaker structural gate further down -- see fins.hpp's file header
            // comment for the full collision survey. FINS's own UDP gate has no magic bytes to lean
            // on (unlike FINS/TCP's exact "FINS" magic), so it's built as a multi-field structural
            // check instead (minimum length, ICF reserved bits exactly zero, RSV exactly 0x00, DA2/
            // SA2 both <= 31, and the command code must exactly match one of the 17 curated verified
            // commands -- an unrecognized command is rejected outright, not accepted structurally).
            // HART-IP's own gate (MessageType/MessageID at payload bytes 1/2 both small enumerated
            // values) has a partial overlap with FINS's own byte layout: FINS's byte[1] is always
            // RSV=0x00 (satisfies HART-IP's MessageType==0 condition), and byte[2] is GCT, which real
            // devices do NOT reliably keep at the conventional 0x07 (a live probe observed 0x02,
            // which DOES satisfy HART-IP's own MessageID-in-{0,1,2,3} condition) -- so, exactly like
            // MELSEC's own defensive positioning above, FINS is tried first as the stronger, more
            // selective gate (its 17-command allowlist plus four independent structural checks vs.
            // HART-IP's own two enumerated-byte check), resolving the risk without needing to weaken
            // either gate.
            bool want_fins = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::FinsOnly;
            if (want_fins) {
                std::string udp_session =
                    tcp_session_key(out.src_ip, udp.src_port, out.dst_ip, udp.dst_port);
                DecodeContext ctx;
                ctx.flow_key = format_flow_endpoint(out.src_ip, udp.src_port) + "->" +
                               format_flow_endpoint(out.dst_ip, udp.dst_port);
                ctx.session_key = udp_session;
                ctx.packet_index = index;
                ctx.protocol_id = "fins";
                ctx.flow_states = &registry_flow_state_;
                if (auto result = fins_udp_decoder().decode(udp.payload, ctx)) {
                    const FinsFrame& ff = result->as<FinsFrame>();
                    out.protocol = "fins";
                    out.summary = ff.summary;
                    for (const auto& n : ff.notes) out.notes.push_back(n);
                    out.result = *result;

                    bool expected_port = port_in(udp.src_port, FINS_UDP_PORT, options_.extra_fins_ports) ||
                                          port_in(udp.dst_port, FINS_UDP_PORT, options_.extra_fins_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard FINS port (9600)");
                    }
                    return out;
                }
            }

            // QUIC -- Tier 2, joining HTTPS (see quic.hpp's own file header comment for why, and
            // try_recognize_quic's own doc comment for why it gets its own dedicated call site
            // rather than folding into try_recognize_it_lateral_movement below, the same "own call
            // site" shape HTTPS's own early TLS ClientHello check has on the TCP side of this
            // dispatch): long-header QUIC packets are checked port-independently even in Auto mode
            // (a genuinely strong, self-describing structural signal, the Header Form/Fixed Bit/
            // exact version match), while try_recognize_quic's own short-header fallback stays
            // port-gated internally -- see that function's own doc comment. Tried here, BEFORE
            // HART-IP's own weak gate just below, rather than down among the rest of Tier 2's UDP
            // checks (SNMP/TFTP) where it originally lived: HART-IP's gate is MessageType/MessageID
            // at payload bytes 1/2 both landing on small enumerated values (0/0/1/2/3/15), and QUIC
            // v1's own Version field -- present at that SAME byte range on every long-header packet
            // (Initial/0-RTT/Handshake/Retry all carry version 0x00000001; Version Negotiation
            // carries 0x00000000) -- SYSTEMATICALLY supplies exactly 0x00/0x00 there, i.e. always a
            // valid MessageType (0, "Request") and MessageID (0, "Session Initiate"). That is the
            // exact same shape of guaranteed, spec-mandated collision as the IKE NAT-T/VXLAN one
            // HART-IP's own port exclusion just below already documents (not a low-probability
            // coincidence), except here it isn't confined to one or two fixed ports -- QUIC has no
            // single standard port -- so a port exclusion can't fix it the same way; running QUIC's
            // much stronger, self-describing check first (and returning immediately on a match)
            // does instead, the same "stronger signal wins the collision" resolution FTP-vs-MQTT and
            // LDAP-vs-MQTT use elsewhere in this file, just expressed as ordering rather than a
            // looks_like_* carveout since there's no shared candidate-buffer here to gate.
            bool want_lateral_movement_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                              options_.protocol_filter == ProtocolFilter::LateralMovementOnly;
            if (want_lateral_movement_udp) {
                if (auto m = try_recognize_quic(udp.payload, udp.src_port, udp.dst_port,
                                                 options_.extra_lateral_movement_ports)) {
                    out.protocol = "quic";
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // BSAP (Bristol Standard Asynchronous/Synchronous Protocol) -- a brand-new protocol,
            // NOT part of migration batch 4, port-gated in Auto mode (see bsap.hpp's own file
            // header comment for why: its own structural checks -- a 2-byte magic for the
            // serial-tunneled shape, nothing stronger than a plausible header shape for the
            // BSAP-IP-native one -- are too weak to try against arbitrary UDP traffic on every
            // port). Tried HERE, BEFORE HART-IP's and FF-HSE's own fully opportunistic (tried on
            // every UDP port) checks just below, for a REAL, EMPIRICALLY-FOUND reason, not a
            // theoretical one -- this decoder was originally placed after NBT-NS instead (the same
            // position RIP/HSRP/DNS/mDNS/LLMNR/NBT-NS's own port-gated checks already occupy), and
            // manual CLI verification of this decoder's own test fixture caught it losing BOTH
            // collisions: a BSAP serial-tunneled response (trailing bytes 01 00 2a 00 00 00 00)
            // misclassified as an FF-HSE "FDA Open Session Rsp", and a different one misclassified
            // as a truncated HART-IP "Request Session Close" -- both purely because HART-IP/FF-HSE
            // are tried opportunistically on every port and ran first, before this decoder's own
            // later, port-gated check ever got a chance, even though the payload was genuinely on
            // BSAP's own port 1234 both times. The same "stronger/more-specific signal should win
            // the collision" resolution QUIC's own early placement just above already uses -- once
            // BSAP's own port (1234) actually matches, that exact-port-plus-structural-shape
            // combination is a more specific signal than HART-IP's/FF-HSE's own fully
            // port-independent opportunistic gates, so it is given priority by running first,
            // rather than by carving out port exclusions on the HART-IP/FF-HSE side (which would
            // only suppress the SYMPTOM on port 1234 specifically, not the underlying weaker-signal-
            // runs-first ordering problem this decoder's own dispatch already solved once, for
            // RIP/HSRP-vs-FF-HSE -- see that pair's own comment below).
            bool want_bsap = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::BsapOnly;
            bool require_bsap_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_bsap) {
                bool port_match = port_in(udp.src_port, BSAP_PORT, options_.extra_bsap_ports) ||
                                   port_in(udp.dst_port, BSAP_PORT, options_.extra_bsap_ports);
                if (!require_bsap_port || port_match) {
                    DecodeContext ctx;
                    ctx.protocol_id = "bsap";
                    if (auto result = bsap_decoder().decode(udp.payload, ctx)) {
                        const BsapFrame& frame = result->as<BsapFrame>();
                        out.protocol = "bsap";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard BSAP port (1234)");
                        }
                        return out;
                    }
                }
            }

            // CoAP (Constrained Application Protocol, RFC 7252) -- a brand-new protocol,
            // port-gated in Auto mode for the same class of reason BSAP just above is: its own
            // shortest legal messages (a bare 4-byte header, no options, no payload) are too weak
            // a structural signal to try against arbitrary UDP traffic on every port -- see
            // coap.hpp's own DETECTION/DISPATCH paragraph. No known collision with any other
            // decoder's own port has been found (5683 is not shared with anything else in this
            // codebase), so unlike BSAP this block does not need to run early to win an ordering
            // fight -- placed here purely for locality with BSAP's own port-gated check just
            // above.
            bool want_coap = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::CoapOnly;
            bool require_coap_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_coap) {
                bool port_match = port_in(udp.src_port, COAP_UDP_PORT, options_.extra_coap_ports) ||
                                   port_in(udp.dst_port, COAP_UDP_PORT, options_.extra_coap_ports);
                if (!require_coap_port || port_match) {
                    DecodeContext ctx;
                    ctx.protocol_id = "coap";
                    if (auto result = coap_udp_decoder().decode(udp.payload, ctx)) {
                        const CoapFrame& frame = result->as<CoapFrame>();
                        out.protocol = "coap";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) +
                                                 "->" + std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard CoAP port (5683)");
                        }
                        return out;
                    }
                }
            }

            // RMCP (Remote Management Control Protocol) / ASF (Alert Standard Format) / IPMI
            // (Intelligent Platform Management Interface) -- a brand-new protocol family, all
            // three sharing UDP port 623 by wire-format construction (RMCP IS the shared 4-byte
            // framing both ASF and IPMI ride inside -- see rmcp.hpp's own file header comment for
            // the full sourcing/scoping writeup). Port-gated in Auto mode for the same class of
            // reason CoAP/BSAP/RIP/HSRP just above already are: RMCP's own header, while stronger
            // than CoAP's own shortest-message gate (see rmcp.hpp's own DETECTION/DISPATCH
            // paragraph for the honest strength comparison), still has no magic-string/checksum-
            // spanning-the-whole-header property to lean on for a fully opportunistic,
            // port-independent try. Placed here, right after CoAP, purely for locality (both are
            // recent UDP-port-gated additions); no collision with anything else in this codebase
            // was found (623 is not shared with any other decoder's own port). Three
            // ProtocolDecoder instances share this one port-gated block, tried most-specific-
            // first: AsfUdpDecoder and IpmiUdpDecoder each parse the RMCP header themselves and
            // only produce a result when the Class byte matches their own protocol (they are
            // mutually exclusive by construction, so their relative order can never create a
            // collision between the two); RmcpUdpDecoder is the generic fallback (an RMCP ACK, any
            // Class, or a Normal message with Class==OEM), tried last so its two siblings get
            // first refusal.
            bool want_asf = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::AsfOnly;
            bool want_ipmi = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IpmiOnly;
            bool want_rmcp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::RmcpOnly;
            bool require_rmcp_port = options_.protocol_filter == ProtocolFilter::Auto;
            bool rmcp_port_match = port_in(udp.src_port, RMCP_UDP_PORT, options_.extra_rmcp_ports) ||
                                    port_in(udp.dst_port, RMCP_UDP_PORT, options_.extra_rmcp_ports);
            if ((want_asf || want_ipmi || want_rmcp) && (!require_rmcp_port || rmcp_port_match)) {
                if (want_asf) {
                    DecodeContext ctx;
                    ctx.protocol_id = "asf";
                    if (auto result = asf_udp_decoder().decode(udp.payload, ctx)) {
                        const AsfFrame& frame = result->as<AsfFrame>();
                        out.protocol = "asf";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!rmcp_port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) +
                                                 "->" + std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard RMCP/ASF/IPMI "
                                                 "port (623)");
                        }
                        return out;
                    }
                }
                if (want_ipmi) {
                    DecodeContext ctx;
                    ctx.protocol_id = "ipmi";
                    ctx.flow_states = &registry_flow_state_;
                    ctx.session_key = tcp_session_key(out.src_ip, udp.src_port, out.dst_ip,
                                                       udp.dst_port);
                    if (auto result = ipmi_udp_decoder().decode(udp.payload, ctx)) {
                        const IpmiFrame& frame = result->as<IpmiFrame>();
                        out.protocol = "ipmi";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!rmcp_port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) +
                                                 "->" + std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard RMCP/ASF/IPMI "
                                                 "port (623)");
                        }
                        return out;
                    }
                }
                if (want_rmcp) {
                    DecodeContext ctx;
                    ctx.protocol_id = "rmcp";
                    if (auto result = rmcp_udp_decoder().decode(udp.payload, ctx)) {
                        const RmcpFrame& frame = result->as<RmcpFrame>();
                        out.protocol = "rmcp";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!rmcp_port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) +
                                                 "->" + std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard RMCP/ASF/IPMI "
                                                 "port (623)");
                        }
                        return out;
                    }
                }
            }

            // POWERLINK's SDO-over-UDP secondary gate (UDP port 3819, EPSG DS301) -- see
            // powerlink.hpp's own "UDP:3819 SDO variant" architecture note for why this reuses
            // try_parse_powerlink UNCHANGED (via powerlink_sdo_udp_decoder()) rather than a
            // separate/stripped-down parser. Port-gated in Auto mode for the same class of reason
            // CoAP/BSAP/RIP/HSRP/RMCP above already are: an SDO Sequence Layer header is just a few
            // small integer fields, too weak a structural signal to try against arbitrary UDP
            // traffic on every port. Placed here, right after RMCP/ASF/IPMI, purely for locality
            // (both are UDP-port-gated additions); no collision with anything else in this codebase
            // was found (3819 is not shared with any other decoder's own port, confirmed by grep
            // before this decoder was added).
            bool want_powerlink_sdo = options_.protocol_filter == ProtocolFilter::Auto ||
                                       options_.protocol_filter == ProtocolFilter::PowerlinkOnly;
            bool require_powerlink_sdo_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_powerlink_sdo) {
                bool port_match = port_in(udp.src_port, POWERLINK_SDO_UDP_PORT,
                                           options_.extra_powerlink_sdo_ports) ||
                                   port_in(udp.dst_port, POWERLINK_SDO_UDP_PORT,
                                           options_.extra_powerlink_sdo_ports);
                if (!require_powerlink_sdo_port || port_match) {
                    DecodeContext ctx;
                    ctx.protocol_id = "powerlink";
                    if (auto result = powerlink_sdo_udp_decoder().decode(udp.payload, ctx)) {
                        const PowerlinkFrame& frame = result->as<PowerlinkFrame>();
                        out.protocol = "powerlink";
                        out.summary = frame.summary;
                        for (const auto& n : frame.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) +
                                                 "->" + std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard POWERLINK "
                                                 "SDO-over-UDP port (3819)");
                        }
                        return out;
                    }
                }
            }

            // Tried last among these UDP checks, port-independently -- see the matching comment in
            // reassemble_tcp_payload above for why HART-IP's own weaker structural detection gate
            // is deliberately given the lowest priority in this decoder's opportunistic dispatch.
            // UNLIKE the accepted, documented HART-IP/Modbus TCP collision noted below, ports 4500
            // and 4789 are excluded from this opportunistic attempt entirely, not merely
            // deprioritized: HART-IP's own gate (MessageType/MessageID at payload bytes 1/2 both
            // being small enumerated values) is trivially, SYSTEMATICALLY satisfied by two Tier 5
            // protocols' own spec-mandated wire formats rather than by coincidence -- RFC 3948's
            // IKE NAT-T non-ESP marker (port 4500) is an all-zero 4-byte prefix by definition, and
            // RFC 7348's VXLAN header (port 4789) has an all-zero Reserved field at that exact
            // byte range by definition -- so without this exclusion, genuine NAT-T IKE/VXLAN
            // traffic would ALWAYS misclassify as "hartip" rather than only occasionally, unlike
            // the low-probability, coincidental collisions this codebase otherwise tolerates. See
            // tunnel_vpn.hpp's own IKE/VXLAN paragraphs for the Tier 5 side of this. Only excluded
            // in Auto mode -- an explicit `--protocol hartip` still attempts every port, same as
            // every other explicit protocol filter in this codebase always overriding Auto's own
            // opportunistic-detection caveats.
            bool want_hartip =
                options_.protocol_filter == ProtocolFilter::HartIpOnly ||
                (options_.protocol_filter == ProtocolFilter::Auto &&
                 !hartip_udp_excluded_port(udp.dst_port) && !hartip_udp_excluded_port(udp.src_port));
            if (want_hartip) {
                // Migration batch 2: try_parse_hartip is now reached through
                // HartIpUdpDecoder::decode -- HART-IP over UDP is purely stateless (a single
                // datagram, no coalescing), so decode() is a direct pass-through and the returned
                // ProtocolResult's payload IS one HartIpResult wrapping the one HartIpFrame. See
                // hartip.hpp/hartip.cpp. Shares its "hartip" id() with HartIpTcpDecoder below --
                // the same two-instance-shared-id() pattern EnipTcpDecoder/EnipUdpDecoder
                // established first, see either pair's own comments for why that's safe. The
                // IKE-NAT-T/VXLAN port exclusion above (want_hartip's own computation) is now
                // hartip_udp_excluded_port -- same two ports, same rationale, moved into
                // hartip.hpp alongside the parser it protects.
                DecodeContext ctx;
                ctx.packet_index = index;
                ctx.protocol_id = "hartip";
                ctx.flow_states = &registry_flow_state_;
                if (auto hartip_result = hartip_udp_decoder().decode(udp.payload, ctx)) {
                    const HartIpResult& hr = hartip_result->as<HartIpResult>();
                    out.protocol = "hartip";
                    out.summary = hr.summary;
                    for (const auto& n : hr.notes) out.notes.push_back(n);
                    out.result = *hartip_result;

                    bool expected_port = port_in(udp.src_port, HARTIP_PORT, options_.extra_hartip_ports) ||
                                          port_in(udp.dst_port, HARTIP_PORT, options_.extra_hartip_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard HART-IP port (5094)");
                    }
                    return out;
                }
            }

            // Kerberos over UDP/88, tried right after HART-IP -- the
            // first Windows AD-suite protocol (see kerberos.hpp's file header comment). Purely
            // stateless as far as
            // per-datagram parsing goes (a single UDP datagram carries exactly one Kerberos
            // message, no coalescing), so decode() is a direct pass-through into
            // try_parse_kerberos plus the session-scoped AS-REQ/TGS-REQ correlation layer -- see
            // kerberos.cpp.
            bool want_kerberos = options_.protocol_filter == ProtocolFilter::Auto ||
                                  options_.protocol_filter == ProtocolFilter::KerberosOnly;
            if (want_kerberos) {
                std::string udp_session =
                    tcp_session_key(out.src_ip, udp.src_port, out.dst_ip, udp.dst_port);
                DecodeContext ctx;
                ctx.flow_key = format_flow_endpoint(out.src_ip, udp.src_port) + "->" +
                               format_flow_endpoint(out.dst_ip, udp.dst_port);
                ctx.session_key = udp_session;
                ctx.packet_index = index;
                ctx.protocol_id = "kerberos";
                ctx.flow_states = &registry_flow_state_;
                if (auto result = kerberos_udp_decoder().decode(udp.payload, ctx)) {
                    const KerberosMessage& km = result->as<KerberosMessage>();
                    out.protocol = "kerberos";
                    out.summary = km.summary;
                    for (const auto& n : km.notes) out.notes.push_back(n);
                    out.result = *result;

                    bool expected_port = port_in(udp.src_port, KERBEROS_PORT, options_.extra_kerberos_ports) ||
                                          port_in(udp.dst_port, KERBEROS_PORT, options_.extra_kerberos_ports);
                    if (!expected_port) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard Kerberos port (88)");
                    }
                    return out;
                }
            }

            // RIP and HSRP, UNLIKE every opportunistic check above (CIP I/O/BACnet/HART-IP/FF-HSE),
            // are port-GATED in Auto mode -- see extra_rip_ports/extra_hsrp_ports in decoder.hpp:
            // try_parse_rip's and try_parse_hsrp's own structural checks are too weak (a handful of
            // small integers for RIP; a version/opcode/state match or a self-consistent TLV chain
            // for HSRP) to try against arbitrary UDP traffic on every port. They still have to run
            // BEFORE FF-HSE's own fully opportunistic, any-port check just below, though: FF-HSE's
            // structural gate is weak enough in the other direction (see its own "tried last, even
            // after HART-IP" comment there) that it was found to accept a synthetic HSRPv1 message
            // on port 1985 as truncated FF-HSE traffic -- a real collision between "port-gated but
            // otherwise unchecked" and "opportunistic but weak," resolved by giving the port-gated
            // check priority once its own gate (an exact, configured port) already matched.
            bool want_rip = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::RipOnly;
            bool require_rip_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_rip) {
                bool port_match = port_in(udp.src_port, RIP_PORT, options_.extra_rip_ports) ||
                                   port_in(udp.dst_port, RIP_PORT, options_.extra_rip_ports);
                if (!require_rip_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_rip is now reached through
                    // RipDecoder::decode rather than called directly -- same function, same
                    // semantics, see rip.hpp. Zero-flat-field migration (cheap batch): out.result
                    // now carries the whole RipMessage, and output.cpp's write_rip_json_fields
                    // reads straight from it.
                    DecodeContext ctx;
                    ctx.protocol_id = "rip";
                    if (auto result = rip_decoder().decode(udp.payload, ctx)) {
                        const RipMessage& msg = result->as<RipMessage>();
                        out.protocol = "rip";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard RIP port (520)");
                        }
                        return out;
                    }
                }
            }

            bool want_hsrp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::HsrpOnly;
            bool require_hsrp_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_hsrp) {
                bool port_match = port_in(udp.src_port, HSRP_PORT, options_.extra_hsrp_ports) ||
                                   port_in(udp.dst_port, HSRP_PORT, options_.extra_hsrp_ports);
                if (!require_hsrp_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_hsrp is now reached
                    // through HsrpDecoder::decode rather than called directly -- same function,
                    // same semantics, see hsrp.hpp. Zero-flat-field migration (mid-size batch):
                    // out.result now carries the whole HsrpMessage (including auth_data, already
                    // redacted by HsrpDecoder::decode when active), and output.cpp's
                    // write_hsrp_json_fields reads straight from it -- no output.cpp reader ever
                    // rendered auth_data, so there is nothing further to preserve there (same
                    // finding as the cheap batch's vrrp_auth_password).
                    DecodeContext ctx;
                    ctx.protocol_id = "hsrp";
                    ctx.redact_secrets = options_.redact_secrets;
                    if (auto result = hsrp_decoder().decode(udp.payload, ctx)) {
                        const HsrpMessage& msg = result->as<HsrpMessage>();
                        out.protocol = "hsrp";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard HSRP port (1985)");
                        }
                        return out;
                    }
                }
            }

            // Tried last among these UDP checks, port-independently, even after HART-IP -- see the
            // matching comment in reassemble_tcp_payload for why FF-HSE's own structural detection
            // gate is deliberately given the lowest priority in this decoder's opportunistic
            // dispatch.
            //
            // Registration-model migration: try_parse_ffhse + the same-datagram multi-PDU
            // coalescing loop that used to live directly in this call site are now reached through
            // FfhseUdpDecoder::decode -- FF-HSE is a zero-flat-field migrated protocol (like
            // TwinCAT/HART-IP/etc.): out.result carries the whole FfhseResult, and
            // output.cpp's write_ffhse_json_fields reads straight from it. See ffhse.hpp/ffhse.cpp.
            bool want_ffhse = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::FfHseOnly;
            if (want_ffhse) {
                DecodeContext ctx;
                ctx.packet_index = index;
                ctx.protocol_id = "ffhse";
                ctx.flow_states = &registry_flow_state_;
                if (auto ffhse_result = ffhse_udp_decoder().decode(udp.payload, ctx)) {
                    const FfhseResult& fr = ffhse_result->as<FfhseResult>();
                    out.protocol = "ffhse";
                    out.summary = fr.summary;
                    for (const auto& n : fr.notes) out.notes.push_back(n);
                    out.result = *ffhse_result;

                    auto is_ffhse_port = [&](uint16_t port) {
                        return port_in(port, FFHSE_PORT_ANNUNC, options_.extra_ffhse_ports) ||
                               port_in(port, FFHSE_PORT_FMS, options_.extra_ffhse_ports) ||
                               port_in(port, FFHSE_PORT_SM, options_.extra_ffhse_ports) ||
                               port_in(port, FFHSE_PORT_LAN, options_.extra_ffhse_ports);
                    };
                    if (!is_ffhse_port(udp.src_port) && !is_ffhse_port(udp.dst_port)) {
                        out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                             std::to_string(udp.dst_port) +
                                             ", which is not a configured/standard FF-HSE port "
                                             "(1089/1090/1091/3622)");
                    }
                    return out;
                }
            }

            // DNS / mDNS / LLMNR / NBT-NS -- UNLIKE every UDP check above, these are port-GATED in
            // Auto mode, not tried opportunistically port-independent: none of the four has any
            // self-describing wire-format signal at all, so trying them against arbitrary UDP
            // traffic on every port would false-positive constantly -- see dns.hpp's/nbns.hpp's
            // own "Detection" paragraphs. An explicit --protocol dns/mdns/llmnr/nbns skips the
            // port gate (the user is asserting the protocol identity directly).
            bool want_dns = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::DnsOnly;
            bool require_dns_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_dns) {
                bool port_match = port_in(udp.src_port, DNS_PORT, options_.extra_dns_ports) ||
                                   port_in(udp.dst_port, DNS_PORT, options_.extra_dns_ports);
                if (!require_dns_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_dns_message is now reached
                    // through DnsDecoder::decode rather than called directly -- same function,
                    // same semantics, see dns.hpp. Zero-flat-field migration (mid-size batch):
                    // out.result now carries the whole DnsMessage, and output.cpp's
                    // write_dns_json_fields (shared by dns/mdns/llmnr) reads straight from it.
                    DecodeContext ctx;
                    ctx.protocol_id = "dns";
                    if (auto result = dns_decoder().decode(udp.payload, ctx)) {
                        const DnsMessage& msg = result->as<DnsMessage>();
                        out.protocol = "dns";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard DNS port (53)");
                        }
                        return out;
                    }
                }
            }

            bool want_mdns = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::MdnsOnly;
            bool require_mdns_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_mdns) {
                bool port_match = port_in(udp.src_port, MDNS_PORT, options_.extra_mdns_ports) ||
                                   port_in(udp.dst_port, MDNS_PORT, options_.extra_mdns_ports);
                if (!require_mdns_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_dns_message is now reached
                    // through MdnsDecoder::decode rather than called directly -- same function,
                    // same semantics, see dns.hpp. Zero-flat-field migration (mid-size batch):
                    // out.result now carries the whole DnsMessage, and output.cpp's
                    // write_dns_json_fields (shared by dns/mdns/llmnr) reads straight from it.
                    DecodeContext ctx;
                    ctx.protocol_id = "mdns";
                    if (auto result = mdns_decoder().decode(udp.payload, ctx)) {
                        const DnsMessage& msg = result->as<DnsMessage>();
                        out.protocol = "mdns";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard mDNS port (5353)");
                        }
                        return out;
                    }
                }
            }

            bool want_llmnr = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::LlmnrOnly;
            bool require_llmnr_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_llmnr) {
                bool port_match = port_in(udp.src_port, LLMNR_PORT, options_.extra_llmnr_ports) ||
                                   port_in(udp.dst_port, LLMNR_PORT, options_.extra_llmnr_ports);
                if (!require_llmnr_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_dns_message is now reached
                    // through LlmnrDecoder::decode rather than called directly -- same function,
                    // same semantics, see dns.hpp. Zero-flat-field migration (mid-size batch):
                    // out.result now carries the whole DnsMessage, and output.cpp's
                    // write_dns_json_fields (shared by dns/mdns/llmnr) reads straight from it.
                    DecodeContext ctx;
                    ctx.protocol_id = "llmnr";
                    if (auto result = llmnr_decoder().decode(udp.payload, ctx)) {
                        const DnsMessage& msg = result->as<DnsMessage>();
                        out.protocol = "llmnr";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard LLMNR port (5355)");
                        }
                        return out;
                    }
                }
            }

            bool want_nbns = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::NbnsOnly;
            bool require_nbns_port = options_.protocol_filter == ProtocolFilter::Auto;
            if (want_nbns) {
                bool port_match = port_in(udp.src_port, NBNS_PORT, options_.extra_nbns_ports) ||
                                   port_in(udp.dst_port, NBNS_PORT, options_.extra_nbns_ports);
                if (!require_nbns_port || port_match) {
                    // Registration-model migration (batch 4): try_parse_nbns is now reached
                    // through NbnsDecoder::decode rather than called directly -- same function,
                    // same semantics, see nbns.hpp. Zero-flat-field migration (mid-size batch):
                    // out.result now carries the whole NbnsMessage, and output.cpp's
                    // write_nbns_json_fields reads straight from it.
                    DecodeContext ctx;
                    ctx.protocol_id = "nbns";
                    if (auto result = nbns_decoder().decode(udp.payload, ctx)) {
                        const NbnsMessage& msg = result->as<NbnsMessage>();
                        out.protocol = "nbns";
                        out.summary = msg.summary;
                        for (const auto& n : msg.notes) out.notes.push_back(n);
                        out.result = *result;
                        if (!port_match) {
                            out.notes.push_back("seen on UDP port " + std::to_string(udp.src_port) + "->" +
                                                 std::to_string(udp.dst_port) +
                                                 ", which is not a configured/standard NBT-NS port (137)");
                        }
                        return out;
                    }
                }
            }

            // Tier 1 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp and the
            // matching comment on the TCP side of this dispatch (reassemble_tcp_payload's own tail)
            // for why this is tried last. Only TeamViewer, AnyDesk, and Zoom are reachable here in
            // practice (RDP and VNC are both TCP-only by spec, so is_tcp=false short-circuits their
            // own checks inside try_recognize_it_remote_access immediately) -- kept as one shared
            // call anyway rather than a UDP-specific variant, since the port-only logic for those
            // three protocols is identical regardless of transport.
            bool want_remote_access_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                           options_.protocol_filter == ProtocolFilter::RemoteAccessOnly;
            if (want_remote_access_udp) {
                if (auto m = try_recognize_it_remote_access(udp.payload, udp.src_port, udp.dst_port,
                                                              /*is_tcp=*/false,
                                                              options_.extra_remote_access_ports)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // Tier 2 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp and the
            // matching comment on the TCP side of this dispatch for why this is tried last. Only
            // SNMP and TFTP are reachable here (SMB/SSH/HTTP/HTTPS/Telnet/FTP are all TCP-only by
            // spec, so is_tcp=false short-circuits their own checks inside
            // try_recognize_it_lateral_movement immediately). QUIC -- also Tier 2, joining HTTPS --
            // is handled separately, well above (before HART-IP's own dispatch): see the comment
            // there for why it needed to move, and `want_lateral_movement_udp` (declared there,
            // still in scope here) is reused as-is for SNMP/TFTP below.
            if (want_lateral_movement_udp) {
                if (auto m = try_recognize_it_lateral_movement(udp.payload, udp.src_port, udp.dst_port,
                                                                 /*is_tcp=*/false,
                                                                 options_.extra_lateral_movement_ports)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // Tier 3 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp and the
            // matching comment on the TCP side of this dispatch for why this is tried last. Only
            // NTP, DHCP, and RADIUS are reachable here (LDAP/LDAPS/TACACS+ are all TCP-only by spec,
            // so is_tcp=false short-circuits their own checks inside
            // try_recognize_it_enterprise_trust immediately). EAPOL, the seventh Tier 3 protocol, is
            // dispatched separately, in the EtherType-keyed region above -- see eapol.hpp.
            bool want_enterprise_trust_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                              options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly;
            if (want_enterprise_trust_udp) {
                if (auto m = try_recognize_it_enterprise_trust(udp.payload, udp.src_port, udp.dst_port,
                                                                  /*is_tcp=*/false,
                                                                  options_.extra_enterprise_trust_ports)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // Tier 4 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp. All
            // five of this tier's port-based protocols (CAPWAP control/data, LWAPP control/data,
            // GTP-U) are UDP-only by spec, so unlike Tiers 1-3 there is no matching TCP-side call
            // site anywhere in this file -- see try_recognize_it_wireless_backhaul's own comment for
            // why it takes no `is_tcp` parameter at all. PPPoE, the sixth Tier 4 protocol, is
            // dispatched separately, in the EtherType-keyed region above -- see pppoe.hpp.
            bool want_wireless_backhaul_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                               options_.protocol_filter == ProtocolFilter::WirelessBackhaulOnly;
            if (want_wireless_backhaul_udp) {
                if (auto m = try_recognize_it_wireless_backhaul(udp.payload, udp.src_port, udp.dst_port,
                                                                  options_.extra_wireless_backhaul_ports)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // Tier 5 "IT protocols an OT auditor flags" recognition, UDP-port-keyed half -- see
            // tunnel_vpn.hpp. IKE, L2TP-over-UDP, VXLAN, Geneve, WireGuard, OpenVPN, and the generic
            // dtls-tunnel structural check (port-independent, tried last within this function -- see
            // its own header comment) are all UDP-only by spec, so there is no matching TCP-side
            // call site for any of them; OpenVPN's own TCP framing and STT are dispatched
            // separately, in the TCP tail region below (try_recognize_tunnel_vpn_tcp). GRE/ESP/AH/
            // IP-in-IP/6in4/L2TP's own IP-protocol-number-keyed forms, and MPLS, are dispatched
            // separately still, in the regions noted at their own call sites.
            bool want_tunnel_vpn_udp = options_.protocol_filter == ProtocolFilter::Auto ||
                                        options_.protocol_filter == ProtocolFilter::TunnelVpnOnly;
            if (want_tunnel_vpn_udp) {
                if (auto m = try_recognize_tunnel_vpn_udp(udp.payload, udp.src_port, udp.dst_port,
                                                             options_.extra_tunnel_vpn_ports)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }

            // Groundwork plumbing beyond this point: the UDP header/payload split is recognized
            // and reported (src/dst port, byte count), but no other application-layer protocol
            // riding on UDP is decoded -- see udp.hpp's file header comment and docs/MANUAL.md's
            // ROADMAP.
            out.protocol = "udp";
            std::ostringstream s;
            if (udp.payload.empty()) {
                s << "UDP datagram with no payload";
            } else {
                s << "UDP payload of " << udp.payload.size() << " byte(s)";
            }
            s << " on port " << udp.src_port << "->" << udp.dst_port;
            std::string port_name = well_known_udp_port_name(udp.dst_port);
            if (port_name.empty()) port_name = well_known_udp_port_name(udp.src_port);
            if (!port_name.empty()) {
                s << " (" << port_name << ", not decoded in this groundwork release)";
            }
            out.summary = s.str();
            return out;
        }

        // ICMP, IGMP, VRRP, IGRP, PIM, EIGRP, and OSPF each ride directly on IP (no UDP/TCP
        // header), dispatched purely by their own IANA-exclusive IP protocol number rather than
        // any port -- see icmp.hpp's/igmp.hpp's/vrrp.hpp's/igrp.hpp's/pim.hpp's/eigrp.hpp's/
        // ospf.hpp's own file header comments. All seven are tried unconditionally (in Auto mode,
        // or their own --protocol filter) since that protocol number alone is already a strong,
        // exclusive signal. Unlike the other six, ICMP's own try_parse_icmp accepts virtually any
        // 4+ byte payload on protocol number 1 (see icmp.hpp) -- so, uniquely among this group, an
        // ICMP-protocol-number payload essentially never falls through to "non-tcp" below.
        // Migration batch 5: all seven are now on the ProtocolDecoder interface (EIGRP was already
        // the GateKind::IpProtocol pilot; this batch migrated the other six) -- each call site below
        // now reaches its try_parse_x through x_decoder().decode() instead of calling it directly,
        // at the exact same textual position it always occupied; nothing about detection order or
        // behavior changed. See protocol_registry.cpp's ip_protocol_registry().
        if (protocol == ICMP_IP_PROTOCOL) {
            bool want_icmp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IcmpOnly;
            if (want_icmp) {
                // Migration batch 5: try_parse_icmp is now reached through IcmpDecoder::decode
                // rather than called directly -- same function, same semantics, see icmp.hpp.
                // Zero-flat-field migration (mid-size batch): out.result now carries the whole
                // IcmpMessage, and output.cpp's write_icmp_json_fields reads straight from it.
                DecodeContext ctx;
                ctx.protocol_id = "icmp";
                if (auto result = icmp_decoder().decode(payload, ctx)) {
                    const IcmpMessage& msg = result->as<IcmpMessage>();
                    out.protocol = "icmp";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    // Attack detection (see attack_detect.hpp): Smurf, ICMP Redirect, and the
                    // ICMP (Echo Request) flood counter.
                    attack_state_.observe_icmp(msg, out.dst_ip, out.notes);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == IGMP_IP_PROTOCOL) {
            bool want_igmp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IgmpOnly;
            if (want_igmp) {
                // Migration batch 5: try_parse_igmp is now reached through IgmpDecoder::decode
                // rather than called directly -- same function, same semantics, see igmp.hpp.
                // Zero-flat-field migration (cheap batch): out.result now carries the whole
                // IgmpMessage, and output.cpp's write_igmp_json_fields reads straight from it.
                DecodeContext ctx;
                ctx.protocol_id = "igmp";
                if (auto result = igmp_decoder().decode(payload, ctx)) {
                    const IgmpMessage& msg = result->as<IgmpMessage>();
                    out.protocol = "igmp";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == VRRP_IP_PROTOCOL) {
            bool want_vrrp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::VrrpOnly;
            if (want_vrrp) {
                // Migration batch 5: try_parse_vrrp is now reached through VrrpDecoder::decode
                // rather than called directly -- same function, same semantics, see vrrp.hpp.
                // Zero-flat-field migration (cheap batch): out.result now carries the whole
                // VrrpMessage (including auth_simple_password, already redacted by
                // VrrpDecoder::decode when active) -- no output.cpp reader ever rendered it, so
                // there is nothing further to preserve there.
                DecodeContext ctx;
                ctx.protocol_id = "vrrp";
                ctx.redact_secrets = options_.redact_secrets;
                if (auto result = vrrp_decoder().decode(payload, ctx)) {
                    const VrrpMessage& msg = result->as<VrrpMessage>();
                    out.protocol = "vrrp";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == IGRP_IP_PROTOCOL) {
            bool want_igrp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IgrpOnly;
            if (want_igrp) {
                // Migration batch 5: try_parse_igrp is now reached through IgrpDecoder::decode
                // rather than called directly -- same function, same semantics, see igrp.hpp.
                // IGRP is the one protocol in this batch that needs more than the payload bytes
                // (its classful Network field needs the packet's own IP source address to
                // reconstruct the missing high octet -- see igrp.hpp's file header), so ctx.
                // ip_src_addr (protocol_decoder.hpp) is populated here, unlike every other call
                // site in this batch. Zero-flat-field migration (cheap batch): out.result now
                // carries the whole IgrpMessage, and output.cpp's write_igrp_json_fields reads
                // straight from it.
                //
                // IPv6 addition: ipv4_src_addr_for_igrp (this function's own parameter, below) is
                // 0 whenever this call reached here via the IPv6 branch -- IGRP is a classful IPv4-
                // only routing protocol with no IPv6 equivalent (superseded by EIGRP/OSPFv3/etc.,
                // which already have their own decoders), so it has no real IPv6 traffic to ever
                // reconstruct an address for; 0 here is the same "a real, if unlikely, address that
                // nothing meaningful ever reads" default DecodeContext::ip_src_addr's own comment
                // already documents for every other decoder in this cascade.
                DecodeContext ctx;
                ctx.protocol_id = "igrp";
                ctx.ip_src_addr = ipv4_src_addr_for_igrp;
                if (auto result = igrp_decoder().decode(payload, ctx)) {
                    const IgrpMessage& msg = result->as<IgrpMessage>();
                    out.protocol = "igrp";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == PIM_IP_PROTOCOL) {
            bool want_pim = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::PimOnly;
            if (want_pim) {
                // Migration batch 5: try_parse_pim is now reached through PimDecoder::decode
                // rather than called directly -- same function, same semantics, see pim.hpp.
                // Zero-flat-field migration (mid-size batch): out.result now carries the whole
                // PimMessage, and output.cpp's write_pim_json_fields reads straight from it.
                DecodeContext ctx;
                ctx.protocol_id = "pim";
                if (auto result = pim_decoder().decode(payload, ctx)) {
                    const PimMessage& msg = result->as<PimMessage>();
                    out.protocol = "pim";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == EIGRP_IP_PROTOCOL) {
            bool want_eigrp = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::EigrpOnly;
            if (want_eigrp) {
                // Registration-model pilot (Stage 1): try_parse_eigrp is now reached through
                // EigrpDecoder::decode rather than called directly -- same function, same
                // semantics, see eigrp.hpp.
                //
                // Update (ROADMAP item 3's own "migrate output.cpp's rendering for the three
                // pilot protocols" follow-up): EIGRP no longer dual-writes into DecodedPacket's
                // own eigrp_* flat fields at all -- fill_eigrp_fields is gone, and out.result now
                // carries the whole EigrpMessage, the same zero-flat-field shape TwinCAT/BGP/
                // Kerberos/etc. already established. output.cpp's write_eigrp_json_fields reads
                // straight from it (see output.cpp's own comment on that function for why this
                // was safe: eigrp_* had exactly two readers in the entire codebase, decoder.cpp's
                // own dual-write and output.cpp's own rendering -- no third-party consumer like
                // policy_engine.cpp/asset_inventory.cpp ever read an eigrp_* field).
                DecodeContext ctx;
                ctx.protocol_id = "eigrp";
                if (auto result = eigrp_decoder().decode(payload, ctx)) {
                    const EigrpMessage& msg = result->as<EigrpMessage>();
                    out.protocol = "eigrp";
                    out.summary = msg.summary;
                    for (const auto& n : msg.notes) out.notes.push_back(n);
                    out.result = *result;
                    return out;
                }
            }
        }

        if (protocol == OSPF_IP_PROTOCOL) {
            bool want_ospf = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::OspfOnly;
            if (want_ospf) {
                // Migration batch 5: try_parse_ospf is now reached through OspfDecoder::decode
                // rather than called directly -- same function, same semantics, see ospf.hpp.
                // fill_ospf_fields is unchanged. This completes migration batch 5: every protocol
                // in decoder.cpp's IP-protocol-number-gated cascade (ICMP, IGMP, VRRP, IGRP, PIM,
                // EIGRP, OSPF) is now on the ProtocolDecoder interface -- the fifth of six GateKinds
                // to reach that state (see protocol_registry.cpp's ip_protocol_registry()).
                DecodeContext ctx;
                ctx.protocol_id = "ospf";
                if (auto result = ospf_decoder().decode(payload, ctx)) {
                    out.protocol = "ospf";
                    fill_ospf_fields(out, result->as<OspfMessage>());
                    return out;
                }
            }
        }

        // Tier 5 "IT protocols an OT auditor flags" recognition, IP-protocol-number-keyed half --
        // see tunnel_vpn.hpp. GRE (47, with NVGRE/EoIP as its own Protocol-Type sub-cases), ESP (50),
        // AH (51), IP-in-IP (4), 6in4 (41), and L2TPv3's own direct-IP form (115) all ride directly
        // on IP with no port at all, same dispatch shape as IGMP/VRRP/IGRP/PIM/EIGRP/OSPF just
        // above; the port/UDP/TCP-based half of this tier (IKE/L2TP-over-UDP/VXLAN/Geneve/
        // WireGuard/OpenVPN/dtls-tunnel/STT) is dispatched separately, in the UDP and TCP tail
        // regions below. MPLS, the fifteenth Tier 5 protocol, is dispatched separately still, in the
        // EtherType-keyed region above -- see mpls.hpp.
        if (protocol == GRE_IP_PROTOCOL || protocol == ESP_IP_PROTOCOL ||
            protocol == AH_IP_PROTOCOL || protocol == IPIP_IP_PROTOCOL ||
            protocol == IPV6_6IN4_IP_PROTOCOL || protocol == L2TPV3_IP_PROTOCOL) {
            bool want_tunnel_vpn = options_.protocol_filter == ProtocolFilter::Auto ||
                                    options_.protocol_filter == ProtocolFilter::TunnelVpnOnly;
            if (want_tunnel_vpn) {
                if (auto m = try_recognize_tunnel_vpn_ip_proto(payload, protocol)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }
        }

        if (protocol != IPPROTO_TCP_VALUE) {
            out.protocol = "non-tcp";
            std::ostringstream s;
            // ip_version's one and only use in this whole ~2000-line cascade (see this function's
            // own header comment) -- wording kept byte-identical to before this function existed
            // for ip_version==4 (many existing CTest PASS_REGULAR_EXPRESSION entries pin this exact
            // "IPv4 protocol number N" text), with an IPv6-specific wording added alongside it
            // rather than generalized into one IP-version-agnostic phrase.
            if (ip_version == 6) {
                s << "IPv6 next-header protocol number " << static_cast<unsigned>(protocol);
            } else {
                s << "IPv4 protocol number " << static_cast<unsigned>(protocol);
            }
            std::string name = ip_protocol_name(protocol);
            if (!name.empty()) s << " (" << name << ")";
            s << " (not TCP)";
            out.summary = s.str();
            return out;
        }

        TcpSegment tcp = parse_tcp(payload);
        out.has_tcp = true;
        out.src_port = tcp.src_port;
        out.dst_port = tcp.dst_port;
        out.tcp_flags = format_tcp_flags(tcp.flags);
        // Attack detection (see attack_detect.hpp): LAND, WinNuke, and the SYN/ACK/TCP flood
        // counters. Deliberately BEFORE the empty-payload early return directly below -- LAND,
        // SYN flood, and ACK flood are all classically bare (no-payload) segments, so running
        // this after that return would miss most of what these signatures actually look like.
        attack_state_.observe_tcp(tcp, out.src_ip, out.dst_ip, out.notes);

        if (tcp.payload.empty()) {
            out.protocol = "tcp";
            out.summary = "TCP segment " + std::to_string(tcp.src_port) + " -> " +
                           std::to_string(tcp.dst_port) + " with no payload (handshake/ACK/teardown)";
            return out;
        }

        // DNS-over-HTTPS detection -- deliberately checked against tcp.payload directly, a SINGLE
        // TCP segment, never effective_payload's cross-segment reassembly below: this is
        // detection-only (see tls_sni.hpp's file header comment for why the DNS message itself
        // can never be decoded here), and a ClientHello split across segments simply isn't
        // detected rather than needing its own reassembly machinery for a feature this narrow.
        // Port-gated in Auto mode, same rationale and same exception for an explicit --protocol
        // doh as DNS/mDNS/LLMNR/NBT-NS above -- see tls_sni.hpp's own "Detection" paragraph.
        //
        // Registration-model migration: try_detect_doh is now reached through DohDecoder::decode
        // rather than called directly -- same function, same semantics, see tls_sni.hpp. DoH is a
        // zero-flat-field migrated protocol from the start (like TwinCAT/FF-HSE/DeviceNet):
        // out.result carries the whole DohDetection, and output.cpp's write_doh_json_fields reads
        // straight from it. GateKind::TcpPort's first and so far only user -- see
        // protocol_decoder.hpp's own comment on that gate kind.
        bool want_doh = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::DohOnly;
        bool require_doh_port = options_.protocol_filter == ProtocolFilter::Auto;
        if (want_doh) {
            bool port_match = port_in(tcp.src_port, DOH_PORT, options_.extra_doh_ports) ||
                               port_in(tcp.dst_port, DOH_PORT, options_.extra_doh_ports);
            if (!require_doh_port || port_match) {
                DecodeContext ctx;
                ctx.protocol_id = "doh";
                if (auto result = doh_decoder().decode(tcp.payload, ctx)) {
                    const DohDetection& d = result->as<DohDetection>();
                    out.protocol = "doh";
                    out.summary = d.summary;
                    out.result = *result;
                    if (!port_match) {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard HTTPS/DoH port (443)");
                    }
                    return out;
                }
            }
        }

        // Generic HTTPS detection -- Tier 2 of the "IT protocols an OT auditor flags" family (see
        // it_protocols.hpp's own file header comment for the full writeup). Deliberately layered
        // right here, directly after the DoH check above and reusing that SAME single-TCP-segment
        // try_parse_tls_client_hello call this codebase already has (tls_sni.hpp) rather than
        // duplicating TLS record/handshake parsing: a DoH match always wins (a known public DoH
        // resolver hostname is strictly more specific than "generic HTTPS"), and a ClientHello that
        // parses but ISN'T a known DoH provider's hostname falls through to here instead, tagged
        // "https". Checked port-independently even in Auto mode -- TLS record/handshake framing
        // (ContentType=Handshake, HandshakeType=ClientHello) is a genuinely strong, self-describing
        // signal, the same treatment SSH's version-exchange banner and SMB's direct-hosting magic
        // get below (see it_protocols.hpp) -- a vendor web UI terminating TLS on a nonstandard port
        // is exactly the case worth still catching. This does NOT confirm the traffic is
        // specifically HTTP-over-TLS rather than some other TLS-wrapped protocol sharing the same
        // port (MQTT-over-TLS, OPC UA over TLS, etc. all begin with the identical ClientHello
        // framing) -- ALPN offering "http/1.1"/"h2" is a genuine confirmation when present; absent
        // that, a standard HTTPS port (443/8443, or a configured extra port) is treated as good
        // enough corroboration to still call it "https", but says so honestly in a note rather than
        // implying a confidence neither signal actually backs up.
        // LDAPS (LDAP-over-TLS, port 636/3269) is layered into this SAME ClientHello call site --
        // see it_protocols.hpp's own LDAPS paragraph. When ALPN doesn't already confirm HTTP and the
        // port is specifically 636/3269 (an Active Directory Global Catalog-over-TLS port is never
        // legitimately also an HTTPS port), the more specific "ldaps" tag wins over generic "https".
        bool want_lateral_movement_early = options_.protocol_filter == ProtocolFilter::Auto ||
                                            options_.protocol_filter == ProtocolFilter::LateralMovementOnly;
        bool want_enterprise_trust_early = options_.protocol_filter == ProtocolFilter::Auto ||
                                            options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly;
        if (want_lateral_movement_early || want_enterprise_trust_early) {
            if (auto hello = try_parse_tls_client_hello(tcp.payload)) {
                bool alpn_confirms_http =
                    std::find(hello->alpn_protocols.begin(), hello->alpn_protocols.end(), "http/1.1") !=
                        hello->alpn_protocols.end() ||
                    std::find(hello->alpn_protocols.begin(), hello->alpn_protocols.end(), "h2") !=
                        hello->alpn_protocols.end();
                bool https_port_match = port_in(tcp.src_port, HTTPS_PORT_443, options_.extra_lateral_movement_ports) ||
                                         port_in(tcp.dst_port, HTTPS_PORT_443, options_.extra_lateral_movement_ports) ||
                                         port_in(tcp.src_port, HTTPS_PORT_8443, options_.extra_lateral_movement_ports) ||
                                         port_in(tcp.dst_port, HTTPS_PORT_8443, options_.extra_lateral_movement_ports);
                bool ldaps_port_match = port_in(tcp.src_port, LDAPS_PORT, options_.extra_enterprise_trust_ports) ||
                                         port_in(tcp.dst_port, LDAPS_PORT, options_.extra_enterprise_trust_ports) ||
                                         port_in(tcp.src_port, LDAPS_GC_PORT, options_.extra_enterprise_trust_ports) ||
                                         port_in(tcp.dst_port, LDAPS_GC_PORT, options_.extra_enterprise_trust_ports);

                if (want_enterprise_trust_early && !alpn_confirms_http && ldaps_port_match &&
                    !(want_lateral_movement_early && https_port_match)) {
                    out.protocol = "ldaps";
                    std::ostringstream s;
                    s << "LDAPS/TLS ClientHello (Active Directory Global Catalog-over-TLS port, if 3269)";
                    if (!hello->sni.empty()) s << " (SNI: " << hello->sni << ")";
                    out.summary = s.str();
                    out.notes.push_back("TLS ClientHello on a standard/configured LDAPS port (636/3269), "
                                         "and ALPN did not confirm HTTP -- most likely LDAP-over-TLS, but "
                                         "any other TLS-wrapped protocol sharing this port would look "
                                         "identical at this layer");
                    return out;
                }

                if (!want_lateral_movement_early) {
                    // Only EnterpriseTrustOnly was requested and this ClientHello wasn't tagged
                    // "ldaps" above -- fall through without claiming generic "https", which belongs
                    // to Tier 2's own filter value.
                } else {
                    out.protocol = "https";
                    std::ostringstream s;
                    s << "HTTPS/TLS ClientHello";
                    if (!hello->sni.empty()) s << " (SNI: " << hello->sni << ")";
                    out.summary = s.str();
                    if (alpn_confirms_http) {
                        out.notes.push_back("ALPN offered \"http/1.1\" or \"h2\", confirming this is "
                                             "specifically HTTP-over-TLS rather than some other TLS-"
                                             "wrapped protocol");
                    } else if (https_port_match) {
                        out.notes.push_back("TLS ClientHello on a standard/configured HTTPS port, but "
                                             "ALPN did not confirm HTTP specifically -- most likely HTTPS, "
                                             "but any other TLS-wrapped protocol sharing this port would "
                                             "look identical at this layer");
                    } else {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard HTTPS port (443/8443), "
                                             "and ALPN did not confirm HTTP specifically -- a genuine TLS "
                                             "ClientHello was observed, but this could be any TLS-wrapped "
                                             "protocol using this port, not necessarily HTTPS");
                    }
                    return out;
                }
            }
        }

        // Directional TCP flow identity, reused below both for cross-TCP-segment PDU/frame
        // reassembly (tcp_reassembly_) and, via DecodeContext::flow_key, registration-model
        // decoders' own directional-flow-keyed state (Dnp3ReassemblyState/CotpReassemblyState --
        // see reassemble_tcp_payload and dnp3.hpp/cotp.hpp).
        std::string flow_key = format_flow_endpoint(out.src_ip, tcp.src_port) + "->" +
                                format_flow_endpoint(out.dst_ip, tcp.dst_port);

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
        bool want_enip = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::EnipOnly;
        bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::ModbusOnly;
        bool want_twincat = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::TwinCatOnly;
        bool want_melsec = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::MelsecOnly;
        bool want_kerberos = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::KerberosOnly;
        bool want_ldap = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::LdapOnly;
        bool want_smb = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::SmbOnly;
        bool want_dnp3 = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::Dnp3Only;
        bool want_s7comm = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::S7commOnly;
        bool want_mms = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::MmsOnly;
        bool want_hartip = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::HartIpOnly;
        bool want_opcua = options_.protocol_filter == ProtocolFilter::Auto ||
                           options_.protocol_filter == ProtocolFilter::OpcUaOnly;
        bool want_mqtt = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::MqttOnly;
        bool want_s7commplus = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::S7commPlusOnly;
        bool want_ffhse = options_.protocol_filter == ProtocolFilter::Auto ||
                           options_.protocol_filter == ProtocolFilter::FfHseOnly;
        bool want_fins = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::FinsOnly;
        bool want_bgp = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::BgpOnly;
        bool want_winrm = options_.protocol_filter == ProtocolFilter::Auto ||
                           options_.protocol_filter == ProtocolFilter::WinRmOnly;
        bool want_dcom = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::DcomOnly;
        bool want_ge_srtp = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::GeSrtpOnly;
        bool want_codesys = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::CodesysOnly;
        bool want_amqp091 = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::Amqp091Only;
        bool want_amqp10 = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::Amqp10Only;
        bool want_dicom = options_.protocol_filter == ProtocolFilter::Auto ||
                           options_.protocol_filter == ProtocolFilter::DicomOnly;

        // Tried first of all -- see the matching, fuller comment in reassemble_tcp_payload above
        // for why OPC UA's own magic-string detection gate is strong enough, and non-colliding
        // enough with every other protocol below, that trying it first costs nothing.
        if (want_opcua) {
            // Migration batch 2: the same-payload multi-chunk coalescing loop and the per-field
            // dual-write that used to live directly in this call site are now reached through
            // OpcUaDecoder::decode -- OPC UA is purely stateless, so ctx is passed only because
            // ProtocolDecoder::decode's signature requires one. See opcua.hpp/opcua.cpp.
            DecodeContext opcua_ctx;
            opcua_ctx.packet_index = index;
            opcua_ctx.protocol_id = "opcua";
            opcua_ctx.flow_states = &registry_flow_state_;
            opcua_ctx.redact_secrets = options_.redact_secrets;
            if (auto opcua_result = opcua_decoder().decode(effective_payload, opcua_ctx)) {
                const OpcUaResult& oua = opcua_result->as<OpcUaResult>();
                out.protocol = "opcua";
                out.summary = oua.summary;
                for (const auto& n : oua.notes) out.notes.push_back(n);
                out.result = *opcua_result;

                bool expected_port = port_in(tcp.src_port, OPCUA_PORT, options_.extra_opcua_ports) ||
                                      port_in(tcp.dst_port, OPCUA_PORT, options_.extra_opcua_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard OPC UA port (4840)");
                }
                return out;
            }
        }

        // Tried next -- see the matching comment in reassemble_tcp_payload above for why
        // EtherNet/IP's own structural checks are strong enough that dispatch order doesn't
        // matter for it the way it does for IEC104-vs-Modbus, but trying it early costs nothing.
        if (want_enip) {
            // Migration batch 2: the same-payload multi-message coalescing loop and the merge-CIP-
            // fields logic that used to live directly in this call site are now reached through
            // EnipTcpDecoder::decode -- EtherNet/IP explicit messaging is purely stateless, so ctx
            // is passed only because ProtocolDecoder::decode's signature requires one. See
            // enip.hpp/enip.cpp. This is the TCP side only -- CIP I/O (UDP) is a separate decoder
            // instance sharing this same "enip" id(), reached from the UDP dispatch below.
            DecodeContext enip_ctx;
            enip_ctx.packet_index = index;
            enip_ctx.protocol_id = "enip";
            enip_ctx.flow_states = &registry_flow_state_;
            if (auto enip_result = enip_tcp_decoder().decode(effective_payload, enip_ctx)) {
                const EnipResult& er = enip_result->as<EnipResult>();
                out.protocol = "enip";
                out.summary = er.summary;
                for (const auto& n : er.notes) out.notes.push_back(n);
                out.result = *enip_result;

                bool expected_port = port_in(tcp.src_port, ENIP_TCP_PORT, options_.extra_enip_ports) ||
                                      port_in(tcp.dst_port, ENIP_TCP_PORT, options_.extra_enip_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard EtherNet/IP port (44818)");
                }
                return out;
            }
        }

        if (want_iec104) {
            // Migration batch 2: the same-payload multi-APDU coalescing loop and ASDU-merging
            // logic that used to live directly in this call site are now reached through
            // Iec104Decoder::decode -- IEC 104 is purely stateless (no per-flow reassembly, unlike
            // DNP3/COTP), so there is no DecodeContext flow-state involved at all; ctx is passed
            // only because ProtocolDecoder::decode's signature requires one. See iec104.hpp/.cpp.
            DecodeContext iec104_ctx;
            iec104_ctx.packet_index = index;
            iec104_ctx.protocol_id = "iec104";
            iec104_ctx.flow_states = &registry_flow_state_;
            if (auto iec104_result = iec104_decoder().decode(effective_payload, iec104_ctx)) {
                const Iec104Result& ir = iec104_result->as<Iec104Result>();
                out.protocol = "iec104";
                out.summary = ir.summary;
                for (const auto& n : ir.notes) out.notes.push_back(n);
                out.result = *iec104_result;

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

        if (want_melsec) {
            // MELSEC Communication Protocol (MC Protocol/SLMP), tried BEFORE Modbus -- see the
            // matching, fuller comment in reassemble_tcp_payload above (this exact call site's
            // sibling) for the real, reproducible MELSEC-vs-Modbus collision this position resolves
            // (a genuine MELSEC request with Network No.==PC No.==0 and a small Request Destination
            // Module I/O No. reads as a plausible Modbus/TCP MBAP header -- Modbus's own decode does
            // not hard-reject the resulting length mismatch). MELSEC's own two-part gate (exact
            // subheader magic + exact declared-length cross-check) is stronger than Modbus's single
            // protocol-id==0 tell, so trying it first costs nothing and resolves the collision in
            // MELSEC's favor, the same "stronger gate wins" principle IEC104-before-Modbus above
            // already establishes. Same out.result-only shape TwinCAT established below -- no
            // melsec_* DecodedPacket fields exist, JsonWriter renders from out.result (output.cpp's
            // write_melsec_json_fields), TextWriter/CsvWriter from out.summary/out.notes generically.
            // This decoder DOES use session-scoped state (MelsecFlowState) -- not for authoritative
            // pairing (there's no unique transaction ID on the wire, see melsec.hpp), but because a
            // MELSEC response carries no command field of its own at all, so decoding its body
            // command-specifically requires knowing the matching request.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "melsec";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = melsec_tcp_decoder().decode(effective_payload, ctx)) {
                const MelsecFrame& mf = result->as<MelsecFrame>();
                out.protocol = "melsec";
                out.summary = mf.summary;
                for (const auto& n : mf.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port = port_in(tcp.src_port, MELSEC_TCP_PORT, options_.extra_melsec_ports) ||
                                      port_in(tcp.dst_port, MELSEC_TCP_PORT, options_.extra_melsec_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard MELSEC port (5001)");
                }
                return out;
            }
        }

        if (want_fins) {
            // FINS/TCP (Omron), tried right after MELSEC -- see the matching, fuller comment in
            // reassemble_tcp_payload above (this exact call site's sibling) for why FINS's own exact
            // 4-byte ASCII magic ("FINS", offset 0) makes it safe to try this early, well ahead of
            // any weak-gated protocol below. Same out.result-only shape MELSEC/TwinCAT established --
            // no fins_* DecodedPacket fields exist, JsonWriter renders from out.result (output.cpp's
            // write_fins_json_fields), TextWriter/CsvWriter from out.summary/out.notes generically.
            // FinsTcpDecoder::decode unwraps the outer FINS/TCP envelope itself (handshake commands
            // 0x00/0x01, Frame Send 0x02 -- the only one carrying an inner FINS command/response
            // frame, decoded via the shared try_parse_fins_frame -- and 0x03/0x06 shown by name
            // only); it also owns the session-scoped FinsFlowState lookup (mirrors MELSEC's own
            // MelsecFlowState) needed only for Memory Area Read/Multiple Memory Area Read responses'
            // own values -- see fins.hpp's "A GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph
            // for why every other command's response decodes context-free instead.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "fins";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = fins_tcp_decoder().decode(effective_payload, ctx)) {
                const FinsFrame& ff = result->as<FinsFrame>();
                out.protocol = "fins";
                out.summary = ff.summary;
                for (const auto& n : ff.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port = port_in(tcp.src_port, FINS_TCP_PORT, options_.extra_fins_ports) ||
                                      port_in(tcp.dst_port, FINS_TCP_PORT, options_.extra_fins_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard FINS port (9600)");
                }
                return out;
            }
        }

        // DICOM, tried BEFORE Modbus here -- see the matching, fuller comment at this same
        // ordering's declared-length-cascade counterpart above (reassemble_tcp_payload) for why:
        // a DICOM PDU's length field's own top 16 bits are always 0x0000 for any real PDU, which
        // is exactly the byte range Modbus/TCP's own MBAP header reads as `protocol_id` -- a real,
        // near-universal collision, not a narrow edge case, so DICOM's own port-gated check runs
        // here rather than after Modbus (unlike AMQP/WinRM/DCOM/GE SRTP, none of which collide
        // this pervasively). Only ever fires on a configured DICOM port in Auto mode, so this
        // changes nothing for any existing Modbus fixture.
        bool require_dicom_port = options_.protocol_filter == ProtocolFilter::Auto;
        bool candidate_port_is_dicom = port_in(tcp.src_port, DICOM_PORT, options_.extra_dicom_ports) ||
                                        port_in(tcp.dst_port, DICOM_PORT, options_.extra_dicom_ports) ||
                                        port_in(tcp.src_port, DICOM_PORT_ALT, options_.extra_dicom_ports) ||
                                        port_in(tcp.dst_port, DICOM_PORT_ALT, options_.extra_dicom_ports);
        if (want_dicom && (!require_dicom_port || candidate_port_is_dicom)) {
            DecodeContext ctx;
            ctx.session_key = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            ctx.flow_key = flow_key;
            ctx.packet_index = index;
            ctx.protocol_id = "dicom";
            ctx.flow_states = &registry_flow_state_;
            ctx.redact_secrets = options_.redact_secrets;
            if (auto result = dicom_tcp_decoder().decode(effective_payload, ctx)) {
                const DicomResult& dr = result->as<DicomResult>();
                out.protocol = "dicom";
                out.summary = dr.summary;
                for (const auto& n : dr.notes) out.notes.push_back(n);
                out.result = *result;

                if (!candidate_port_is_dicom) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard DICOM port (104/11112)");
                }
                return out;
            }
        }

        if (want_modbus) {
            // Registration-model pilot (Stage 2): try_parse_modbus_tcp + the transaction-pairing
            // logic that used to be Decoder::pair_modbus_transaction are now both reached through
            // ModbusDecoder::decode -- same functions, same semantics, see modbus.hpp/modbus.cpp.
            //
            // Update (ROADMAP item 3's own "migrate output.cpp's rendering for the three pilot
            // protocols" follow-up): Modbus no longer dual-writes into DecodedPacket's own
            // modbus_* flat fields -- out.result now carries the whole ModbusFrame, the same
            // zero-flat-field shape TwinCAT/BGP/EIGRP/etc. already established. output.cpp's
            // write_modbus_json_fields reads straight from it; policy_engine.cpp/asset_inventory.cpp
            // (modbus_function_name's only other two readers) now read via
            // dp.result->as<ModbusFrame>().function_name instead.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "modbus";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = modbus_decoder().decode(effective_payload, ctx)) {
                const ModbusFrame& mb = result->as<ModbusFrame>();
                out.protocol = "modbus";
                out.summary = mb.function_name + ": " + mb.summary;
                for (const auto& n : mb.notes) out.notes.push_back(n);
                out.result = *result;

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

        if (want_twincat) {
            // TwinCAT/ADS (AMS/TCP) -- the first protocol built entirely on the ProtocolDecoder
            // interface (protocol_decoder.hpp); see twincat.hpp's file header comment for the wire
            // format and the collision survey behind this decoder's position here, right after
            // Modbus. Unlike every protocol above, there is no twincat_* dual-write into
            // DecodedPacket's own fields: out.result carries the full TwinCatFrame for JsonWriter's
            // own registry-based rendering (output.cpp), and out.protocol/summary/notes below are
            // all TextWriter/CsvWriter need, since both already render generically from those three
            // fields for every protocol (see output.cpp's own file header comment).
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "twincat";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = twincat_decoder().decode(effective_payload, ctx)) {
                const TwinCatFrame& tc = result->as<TwinCatFrame>();
                out.protocol = "twincat";
                out.summary = tc.summary;
                for (const auto& n : tc.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port =
                    port_in(tcp.src_port, TWINCAT_AMS_TCP_PORT, options_.extra_twincat_ports) ||
                    port_in(tcp.dst_port, TWINCAT_AMS_TCP_PORT, options_.extra_twincat_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard TwinCAT/AMS port (48898)");
                }
                return out;
            }
        }

        if (want_bgp) {
            // BGP-4 (RFC 4271, TCP port 179) -- the last piece of the three-stage plan that also
            // added ARP and LLDP. Unlike those two, BGP is TCP-port-independent and needs declared-
            // length reassembly (handled above, in reassemble_tcp_payload) plus its own coalescing
            // loop (inside BgpDecoder::decode itself, see bgp.hpp's file header comment) and
            // session-scoped state (BgpFlowState, tracking whether 4-octet AS numbers were
            // negotiated) -- same "no dual-write into DecodedPacket's own fields" posture TwinCAT
            // established just above: out.result carries the full BgpResult for JsonWriter's own
            // registry-based rendering (output.cpp's write_bgp_json_fields), and
            // out.protocol/summary/notes below are all TextWriter/CsvWriter need.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "bgp";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = bgp_decoder().decode(effective_payload, ctx)) {
                const BgpResult& br = result->as<BgpResult>();
                out.protocol = "bgp";
                out.summary = br.summary;
                for (const auto& n : br.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port = port_in(tcp.src_port, BGP_PORT, options_.extra_bgp_ports) ||
                                      port_in(tcp.dst_port, BGP_PORT, options_.extra_bgp_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard BGP port (179)");
                }
                return out;
            }
        }

        if (want_kerberos) {
            // Kerberos over TCP/88 -- the first Windows AD-suite protocol (see kerberos.hpp's
            // file header comment). Same out.result-only shape TwinCAT established just above --
            // no kerberos_* DecodedPacket fields exist, JsonWriter renders from out.result
            // (output.cpp's write_kerberos_json_fields), TextWriter/CsvWriter from
            // out.summary/out.notes generically. KerberosTcpDecoder::decode strips the 4-byte
            // length prefix itself (see kerberos.cpp) -- effective_payload here still carries it,
            // matching what kerberos_tcp_declared_length measured against.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "kerberos";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = kerberos_tcp_decoder().decode(effective_payload, ctx)) {
                const KerberosMessage& km = result->as<KerberosMessage>();
                out.protocol = "kerberos";
                out.summary = km.summary;
                for (const auto& n : km.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port = port_in(tcp.src_port, KERBEROS_PORT, options_.extra_kerberos_ports) ||
                                      port_in(tcp.dst_port, KERBEROS_PORT, options_.extra_kerberos_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard Kerberos port (88)");
                }
                return out;
            }
        }

        if (want_ldap) {
            // LDAP over TCP/389 (and TCP/3268, Global Catalog) -- the second Windows AD-suite
            // protocol (see ldap.hpp's file header comment). Same out.result-only shape Kerberos/
            // TwinCAT established just above -- no ldap_* DecodedPacket fields exist, JsonWriter
            // renders from out.result (output.cpp's write_ldap_json_fields), TextWriter/CsvWriter
            // from out.summary/out.notes generically. LDAP-over-TCP has no length-prefix framing of
            // its own to strip (unlike Kerberos's 4-byte prefix) -- effective_payload here IS the
            // LDAPMessage bytes LdapTcpDecoder::decode expects directly.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "ldap";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = ldap_tcp_decoder().decode(effective_payload, ctx)) {
                const LdapMessage& lm = result->as<LdapMessage>();
                out.protocol = "ldap";
                out.summary = lm.summary;
                for (const auto& n : lm.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port = port_in(tcp.src_port, LDAP_PORT, options_.extra_ldap_ports) ||
                                      port_in(tcp.dst_port, LDAP_PORT, options_.extra_ldap_ports) ||
                                      port_in(tcp.src_port, LDAP_GC_PORT, options_.extra_ldap_ports) ||
                                      port_in(tcp.dst_port, LDAP_GC_PORT, options_.extra_ldap_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard LDAP port (389/3268)");
                }
                return out;
            }
        }

        if (want_smb) {
            // SMB over TCP/445 (direct hosting) and TCP/139 (NetBIOS Session Service) -- the third
            // Windows AD-suite protocol (see smb.hpp's file header comment). Same out.result-only
            // shape Kerberos/LDAP established just above -- no smb_* DecodedPacket fields exist,
            // JsonWriter renders from out.result (output.cpp's write_smb_json_fields), TextWriter/
            // CsvWriter from out.summary/out.notes generically. SmbTcpDecoder::decode strips the
            // 4-byte Zero+StreamProtocolLength prefix itself (see smb.cpp) -- effective_payload here
            // still carries it, matching what smb_tcp_declared_length measured against.
            std::string session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.flow_key = flow_key;
            ctx.session_key = session;
            ctx.packet_index = index;
            ctx.protocol_id = "smb";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = smb_tcp_decoder().decode(effective_payload, ctx)) {
                const SmbFrame& sf = result->as<SmbFrame>();
                out.protocol = "smb";
                out.summary = sf.summary;
                for (const auto& n : sf.notes) out.notes.push_back(n);
                out.result = *result;

                bool expected_port =
                    port_in(tcp.src_port, SMB_PORT_445, options_.extra_smb_ports) ||
                    port_in(tcp.dst_port, SMB_PORT_445, options_.extra_smb_ports) ||
                    port_in(tcp.src_port, SMB_NETBIOS_SESSION_PORT_139, options_.extra_smb_ports) ||
                    port_in(tcp.dst_port, SMB_NETBIOS_SESSION_PORT_139, options_.extra_smb_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard SMB port (445/139)");
                }
                return out;
            }
        }

        // Re-derived here (reassemble_tcp_payload above is a separate member function -- its own
        // locals don't carry over). require_winrm_port mirrors DoH's own require_doh_port: gated by
        // port only in Auto mode (so this decoder wins the race against Tier 2's own generic "http"
        // recognition specifically on WinRM's own port, without silently swallowing ordinary HTTP
        // traffic on every other port -- see winrm.hpp's own "COLLISION SURVEY" section); an
        // explicit `--protocol winrm` still tries it port-independently.
        bool require_winrm_port = options_.protocol_filter == ProtocolFilter::Auto;
        bool candidate_port_is_winrm = port_in(tcp.src_port, WINRM_PORT, options_.extra_winrm_ports) ||
                                        port_in(tcp.dst_port, WINRM_PORT, options_.extra_winrm_ports);
        if (want_winrm && (!require_winrm_port || candidate_port_is_winrm)) {
            // WS-Management (WinRM), TCP port 5985 -- Phase 4 of the Windows RPC/remote-management
            // batch, and the first protocol in that batch with no DCE/RPC or SMB involvement at all
            // (see winrm.hpp's file header comment). Same out.result-only shape Kerberos/LDAP/SMB
            // established just above -- no winrm_* DecodedPacket fields exist, JsonWriter renders
            // from out.result (output.cpp's write_winrm_json_fields), TextWriter/CsvWriter from
            // out.summary/out.notes generically. WinRmTcpDecoder is stateless -- ctx is passed only
            // because ProtocolDecoder::decode's signature requires one -- but DOES need
            // redact_secrets wired through, unlike Kerberos/LDAP/SMB above, since it genuinely
            // decodes a plaintext, potentially credential-bearing field (the CommandLine's own
            // command_line, redacted by default -- see winrm.hpp).
            DecodeContext ctx;
            ctx.packet_index = index;
            ctx.protocol_id = "winrm";
            ctx.flow_states = &registry_flow_state_;
            ctx.redact_secrets = options_.redact_secrets;
            if (auto result = winrm_tcp_decoder().decode(effective_payload, ctx)) {
                const WinRmMessage& wm = result->as<WinRmMessage>();
                out.protocol = "winrm";
                out.summary = wm.summary;
                for (const auto& n : wm.notes) out.notes.push_back(n);
                out.result = *result;

                if (!candidate_port_is_winrm) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard WinRM port (5985)");
                }
                return out;
            }
        }

        // Re-derived here (reassemble_tcp_payload above is a separate member function -- its own
        // locals don't carry over). require_dcom_port mirrors require_winrm_port immediately above:
        // gated by port only in Auto mode (DCOM's own structural gate is weaker than SMB's own magic
        // check -- see dcom.hpp's own COLLISION SURVEY section); an explicit `--protocol dcom` still
        // tries it port-independently.
        bool require_dcom_port = options_.protocol_filter == ProtocolFilter::Auto;
        bool candidate_port_is_dcom = port_in(tcp.src_port, DCOM_PORT, options_.extra_dcom_ports) ||
                                       port_in(tcp.dst_port, DCOM_PORT, options_.extra_dcom_ports);
        if (want_dcom && (!require_dcom_port || candidate_port_is_dcom)) {
            // DCOM activation, TCP port 135 -- Phase 5 (the last) of the Windows RPC/remote-
            // management batch (see dcom.hpp's own file header comment for the full REDUCED SCOPE/
            // TRANSPORT rationale). Same out.result-only shape WinRM/MELSEC/FINS established -- no
            // dcom_* DecodedPacket fields exist, JsonWriter renders from out.result (output.cpp's
            // write_dcom_json_fields), TextWriter/CsvWriter from out.summary/out.notes generically.
            // Unlike WinRmTcpDecoder (stateless), DcomTcpDecoder needs session-scoped state
            // (DcomFlowState -- a DCOM session can legitimately bind more than one known interface
            // at once, see dcom.hpp's own STATE section), the same session_key wiring MELSEC's/
            // FINS's own dispatch sites above already establish for their own flow state.
            std::string dcom_session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.session_key = dcom_session;
            ctx.packet_index = index;
            ctx.protocol_id = "dcom";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = dcom_tcp_decoder().decode(effective_payload, ctx)) {
                const DcomMessage& dcm = result->as<DcomMessage>();
                out.protocol = "dcom";
                out.summary = dcm.summary;
                for (const auto& n : dcm.notes) out.notes.push_back(n);
                out.result = *result;

                if (!candidate_port_is_dcom) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard DCOM port (135)");
                }
                return out;
            }
        }

        // Re-derived here (reassemble_tcp_payload above is a separate member function -- its own
        // locals don't carry over). require_ge_srtp_port mirrors require_dcom_port immediately
        // above: gated by port only in Auto mode (GE SRTP's own structural gate has no magic-
        // constant field at all -- see ge_srtp.hpp's own "STRUCTURAL DETECTION GATE" section); an
        // explicit `--protocol ge-srtp` still tries it port-independently.
        bool require_ge_srtp_port = options_.protocol_filter == ProtocolFilter::Auto;
        bool candidate_port_is_ge_srtp = port_in(tcp.src_port, GE_SRTP_PORT, options_.extra_ge_srtp_ports) ||
                                          port_in(tcp.dst_port, GE_SRTP_PORT, options_.extra_ge_srtp_ports);
        if (want_ge_srtp && (!require_ge_srtp_port || candidate_port_is_ge_srtp)) {
            // GE SRTP (Service Request Transport Protocol), TCP port 18245 -- a brand-new protocol
            // (see ge_srtp.hpp's own file header comment), not part of the Windows RPC/remote-
            // management batch WinRM/DCOM above belong to, despite landing right after them in this
            // same GateKind::TcpPort cascade. Same out.result-only shape WinRM/DCOM/MELSEC/FINS
            // established -- no ge_srtp_* DecodedPacket fields exist, JsonWriter renders from
            // out.result (output.cpp's write_ge_srtp_json_fields), TextWriter/CsvWriter from
            // out.summary/out.notes generically. UNLIKE WinRM (stateless) and MELSEC/FINS (no real
            // transaction ID, single-outstanding-slot heuristic), GeSrtpTcpDecoder's own session
            // state (GeSrtpFlowState) pairs request/response AUTHORITATIVELY by GE SRTP's own
            // Sequence Number field -- the same real-transaction-ID tier Modbus's/TwinCAT's own
            // pairing already established, see ge_srtp.hpp's own file header comment.
            std::string ge_srtp_session =
                tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.session_key = ge_srtp_session;
            ctx.packet_index = index;
            ctx.protocol_id = "ge-srtp";
            ctx.flow_states = &registry_flow_state_;
            if (auto result = ge_srtp_tcp_decoder().decode(effective_payload, ctx)) {
                const GeSrtpFrame& gf = result->as<GeSrtpFrame>();
                out.protocol = "ge-srtp";
                out.summary = gf.summary;
                for (const auto& n : gf.notes) out.notes.push_back(n);
                out.result = *result;

                if (!candidate_port_is_ge_srtp) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard GE SRTP port (18245)");
                }
                return out;
            }
        }

        // Re-derived here (reassemble_tcp_payload above is a separate member function -- its own
        // locals don't carry over). require_amqp_port mirrors require_ge_srtp_port immediately
        // above: gated by port only in Auto mode; an explicit `--protocol amqp091`/
        // `--protocol amqp10` still tries the matching decoder port-independently. Both AMQP
        // decoders share this one port-gate check (and options_.extra_amqp_ports), see that
        // field's own doc comment in decoder.hpp.
        bool require_amqp_port = options_.protocol_filter == ProtocolFilter::Auto;
        bool candidate_port_is_amqp = port_in(tcp.src_port, AMQP_PORT, options_.extra_amqp_ports) ||
                                       port_in(tcp.dst_port, AMQP_PORT, options_.extra_amqp_ports);
        if ((want_amqp091 || want_amqp10) && (!require_amqp_port || candidate_port_is_amqp)) {
            // AMQP 0-9-1 and AMQP 1.0 -- two genuinely wire-INCOMPATIBLE protocols that happen to
            // share TCP port 5672 by convention (see amqp_common.hpp's own file header comment for
            // the full detection-posture rationale). Both decoders are tried against the SAME
            // session, sharing ONE per-session AmqpFlowState bucket keyed by the fixed string
            // "amqp" (deliberately NOT each decoder's own id(), the one exception to this
            // codebase's usual ctx.protocol_id-equals-id() convention -- see amqp_common.hpp's own
            // STATEFULNESS section) so that sticky per-session version detection (established once,
            // from the connection's own 8-byte preamble, the only fully reliable way to tell the
            // two apart) survives across both decoders' own calls. A session whose preamble this
            // codebase never captured declines to classify as AMQP at all in Auto mode -- see
            // amqp_common.hpp's DETECTION POSTURE section for why that scope boundary is
            // deliberate and honestly documented, not a bug. Same out.result-only shape WinRM/
            // DCOM/GE SRTP established -- out.result carries an Amqp091Result or Amqp10Result,
            // JsonWriter renders from it (output.cpp's write_amqp091_json_fields/
            // write_amqp10_json_fields), TextWriter/CsvWriter from out.summary/out.notes
            // generically.
            std::string amqp_session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.session_key = amqp_session;
            ctx.packet_index = index;
            ctx.protocol_id = "amqp";  // shared bucket -- see the comment above.
            ctx.flow_states = &registry_flow_state_;
            if (want_amqp091) {
                if (auto result = amqp091_tcp_decoder().decode(effective_payload, ctx)) {
                    const Amqp091Result& ar = result->as<Amqp091Result>();
                    out.protocol = "amqp091";
                    out.summary = ar.summary;
                    for (const auto& n : ar.notes) out.notes.push_back(n);
                    out.result = *result;

                    if (!candidate_port_is_amqp) {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard AMQP port (5672)");
                    }
                    return out;
                }
            }
            if (want_amqp10) {
                if (auto result = amqp10_tcp_decoder().decode(effective_payload, ctx)) {
                    const Amqp10Result& ar = result->as<Amqp10Result>();
                    out.protocol = "amqp10";
                    out.summary = ar.summary;
                    for (const auto& n : ar.notes) out.notes.push_back(n);
                    out.result = *result;

                    if (!candidate_port_is_amqp) {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard AMQP port (5672)");
                    }
                    return out;
                }
            }
        }

        if (want_dnp3) {
            // Migration batch 2: the same-payload multi-data-link-frame coalescing loop and the
            // cross-packet application-fragment reassembly (reading/writing
            // Decoder::dnp3_reassembly_ and calling Decoder::process_dnp3_frame) that used to
            // live directly in this call site are now both reached through Dnp3Decoder::decode --
            // same algorithm, same Dnp3ReassemblyState shape, just via
            // DecodeContext::flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow)
            // instead of a Decoder member dedicated to DNP3 alone. See dnp3.hpp/dnp3.cpp.
            DecodeContext dnp3_ctx;
            dnp3_ctx.flow_key = flow_key;
            dnp3_ctx.packet_index = index;
            dnp3_ctx.protocol_id = "dnp3";
            dnp3_ctx.flow_states = &registry_flow_state_;
            if (auto dnp3_result = dnp3_decoder().decode(effective_payload, dnp3_ctx)) {
                const Dnp3Result& dr = dnp3_result->as<Dnp3Result>();
                out.protocol = "dnp3";
                out.summary = dr.summary;
                for (const auto& n : dr.notes) out.notes.push_back(n);
                out.result = *dnp3_result;

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

        // RDP's initial X.224 Connection Request/Confirm, checked BEFORE the opportunistic, port-
        // independent COTP/S7comm dispatch just below -- see it_protocols.hpp's own file header
        // comment for why: RDP's handshake rides the IDENTICAL TPKT+COTP framing S7comm/MMS use on
        // port 102, so without this carve-out the S7comm/MMS dispatch below (which tries every TCP
        // payload against try_parse_tpkt_cotp regardless of port) would claim a genuine RDP CR/CC on
        // port 3389 as generic "cotp" traffic first, and try_recognize_it_remote_access's own
        // matching check (run much later, only as a last resort -- see this function's TCP tail)
        // would never get a chance to run at all. Deliberately narrow: ONLY a Connection Request/
        // Confirm on port 3389 (or a configured extra port) is intercepted here -- a Data frame on
        // that same port (not RDP's own handshake shape at all) still falls through to the generic
        // COTP dispatch below exactly as it always has, the same "genuinely ambiguous, both
        // readings left available" posture this codebase's HART-IP/Modbus MBAP-header collision
        // already has (see hartip.hpp).
        bool want_remote_access_early = options_.protocol_filter == ProtocolFilter::Auto ||
                                         options_.protocol_filter == ProtocolFilter::RemoteAccessOnly;
        if (want_remote_access_early &&
            (port_in(tcp.src_port, RDP_PORT, options_.extra_remote_access_ports) ||
             port_in(tcp.dst_port, RDP_PORT, options_.extra_remote_access_ports))) {
            if (auto cotp = try_parse_tpkt_cotp(effective_payload)) {
                if (cotp->kind == CotpPduKind::ConnectionRequest || cotp->kind == CotpPduKind::ConnectionConfirm) {
                    out.protocol = "rdp";
                    out.summary = "RDP X.224 " + cotp->pdu_type_name;
                    return out;
                }
            }
        }

        if (want_s7comm || want_mms || want_s7commplus) {
            // Registration-model migration batch 2: TPKT/COTP framing plus the non-Data-abandons-
            // reassembly and Data-frame EOT-chaining logic that used to live directly in this call
            // site (reading/writing Decoder::cotp_reassembly_ and calling
            // Decoder::reassemble_cotp_data_frame) are now both reached through CotpDecoder::decode
            // -- same algorithm, same CotpReassemblyState shape, just via
            // DecodeContext::flow_state<CotpReassemblyState>(FlowStateKeying::DirectionalFlow)
            // instead of a Decoder member dedicated to COTP alone. See cotp.hpp/cotp.cpp.
            //
            // S7comm/S7comm-Plus/MMS themselves are ALSO migrated (S7CommDecoder/S7CommPlusDecoder/
            // MmsDecoder, gate_kind() == CotpPayload -- protocol_decoder.hpp), but this call site
            // still tries each of the three explicitly, in the same fixed order, rather than
            // iterating cotp_payload_registry() generically: their dual-write blocks below differ
            // too much (different DecodedPacket fields entirely) to generalize into one loop
            // without real loss of clarity. cotp_payload_registry() exists purely as this gate
            // group's own audit trail, the same "data, not control flow" role every other registry
            // vector has during this project's staged migration -- see protocol_registry.hpp.
            std::string cotp_session = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext cotp_ctx;
            cotp_ctx.flow_key = flow_key;
            cotp_ctx.session_key = cotp_session;
            cotp_ctx.packet_index = index;
            cotp_ctx.protocol_id = "cotp";
            cotp_ctx.flow_states = &registry_flow_state_;
            if (auto cotp_result = cotp_decoder().decode(effective_payload, cotp_ctx)) {
                const CotpDecodeResult& cr = cotp_result->as<CotpDecodeResult>();
                bool expected_port = port_in(tcp.src_port, COTP_TCP_PORT, options_.extra_s7comm_ports) ||
                                      port_in(tcp.dst_port, COTP_TCP_PORT, options_.extra_s7comm_ports);
                auto annotate_port = [&]() {
                    if (!expected_port) {
                        out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                             std::to_string(tcp.dst_port) +
                                             ", which is not a configured/standard COTP/S7comm port (102)");
                    }
                };

                if (cr.still_buffering) {
                    // Still buffering (EOT=0, waiting for the final fragment) or the flow's safety
                    // cap was hit -- CotpDecoder::decode has already filled in cr.buffering_summary.
                    out.protocol = "cotp";
                    out.summary = cr.buffering_summary;
                    for (const auto& n : cr.notes) out.notes.push_back(n);
                    annotate_port();
                    return out;
                }

                if (cr.frame.kind == CotpPduKind::Data) {
                    DecodeContext rider_ctx;
                    rider_ctx.flow_key = flow_key;
                    rider_ctx.session_key = cotp_session;
                    rider_ctx.packet_index = index;
                    rider_ctx.flow_states = &registry_flow_state_;

                    // s7comm_decoder().decode already returns std::nullopt (never throws) for an
                    // empty payload, so no separate emptiness check is needed here -- cr.s7_candidate()
                    // can legitimately be empty (e.g. every buffered fragment plus the final one all
                    // carried zero bytes of user data, seen in real captures -- see
                    // tests/real_captures/s7comm/ATTRIBUTION.md).
                    if (want_s7comm) {
                        rider_ctx.protocol_id = "s7comm";
                        if (auto result = s7comm_decoder().decode(cr.s7_candidate(), rider_ctx)) {
                            const S7CommFrame& s7 = result->as<S7CommFrame>();
                            out.protocol = "s7comm";
                            out.summary = s7.summary;
                            for (const auto& n : s7.notes) out.notes.push_back(n);
                            S7CommResult sr;
                            sr.summary = s7.summary;
                            sr.notes = s7.notes;
                            sr.has_function = s7.has_function;
                            sr.function_name = s7.function_name;
                            const size_t kMaxTags = resource_limits().max_decoded_objects.value_or(50);
                            // `items` carries forward unmodified -- S7Item has no ByteSpan of its own,
                            // so the display-tag-plus-"[EXPERIMENTAL]" transform (previously done right
                            // here) is deferred to output.cpp's write_s7comm_json_fields instead. See
                            // S7CommResult's own comment in s7comm.hpp for why this differs from
                            // value_summaries below.
                            for (size_t i = 0; i < s7.items.size() && i < kMaxTags; ++i) {
                                sr.items.push_back(s7.items[i]);
                            }
                            // value_summaries, unlike items, must be computed EAGERLY here -- di.data is
                            // a ByteSpan that can point into cr's own s7_candidate_storage, which does not
                            // outlive this call. See S7CommResult's own comment in s7comm.hpp.
                            for (size_t i = 0; i < s7.data_items.size() && i < kMaxTags; ++i) {
                                const auto& di = s7.data_items[i];
                                // return_code_name is only set for items that carry a return code on
                                // the wire (Read Var / Write Var responses); a Write Var request's
                                // value item has none, so this falls straight through to the value.
                                if (!di.return_code_name.empty() && di.return_code != 0xFF) {
                                    sr.value_summaries.push_back(di.return_code_name);
                                } else if (di.has_value_fields && di.transport_size == 0x03 && di.data.size() == 1) {
                                    sr.value_summaries.push_back(di.data.at(0) != 0 ? "1" : "0");
                                } else if (di.has_value_fields && !di.data.empty()) {
                                    sr.value_summaries.push_back(to_hex(di.data, ""));
                                } else if (!di.return_code_name.empty()) {
                                    sr.value_summaries.push_back("ok");
                                } else {
                                    sr.value_summaries.push_back("");
                                }
                            }
                            sr.plc_stop_message = s7.plc_stop_message;
                            sr.has_pi_service = s7.has_pi_service;
                            sr.pi_service_name = s7.pi_service_name;
                            sr.pi_service_description = s7.pi_service_description;
                            sr.pi_control_argument = s7.pi_control_argument;
                            for (size_t i = 0; i < s7.pi_control_blocks.size() && i < kMaxTags; ++i) {
                                sr.pi_control_blocks.push_back(s7.pi_control_blocks[i]);
                            }
                            sr.has_pi_control_status = s7.has_pi_control_status;
                            sr.pi_control_has_more_data = s7.pi_control_has_more_data;
                            sr.pi_control_has_error = s7.pi_control_has_error;
                            out.result = ProtocolResult::make<S7CommResult>("s7comm", std::move(sr));
                            for (const auto& n : cr.notes) out.notes.push_back(n);
                            annotate_port();
                            return out;
                        }
                    }

                    // S7comm-Plus shares this exact TCP port 102 / TPKT+COTP transport with
                    // classic S7comm and MMS, but is disambiguated by its own protocol id byte
                    // (0x72 vs S7comm's 0x32) -- no collision risk with the S7comm check just
                    // above, since a single leading byte can't match both. Tried here, before
                    // MMS, purely for file-organization reasons (S7comm and S7comm-Plus are
                    // conceptually "the same vendor's two generations", not because of any
                    // detection-strength ordering need -- see s7commplus.hpp).
                    if (want_s7commplus) {
                        rider_ctx.protocol_id = "s7comm-plus";
                        if (auto result = s7comm_plus_decoder().decode(cr.s7_candidate(), rider_ctx)) {
                            const S7CommPlusFrame& s7p = result->as<S7CommPlusFrame>();
                            out.protocol = "s7comm-plus";
                            out.summary = s7p.summary;
                            for (const auto& n : s7p.notes) out.notes.push_back(n);
                            out.s7plus_pdu_type_name = s7p.pdu_type_name;
                            out.s7plus_is_keepalive = s7p.is_keepalive;
                            out.s7plus_keepalive_seq = s7p.keepalive_seq;
                            out.s7plus_has_opcode = s7p.has_data_part && !s7p.is_notification &&
                                                     !s7p.opcode_name.empty();
                            out.s7plus_opcode_name = s7p.opcode_name;
                            out.s7plus_has_function = s7p.has_function;
                            out.s7plus_function_code = s7p.function_code;
                            out.s7plus_function_name = s7p.function_name;
                            out.s7plus_has_sequence_number = s7p.has_sequence_number;
                            out.s7plus_sequence_number = s7p.sequence_number;
                            out.s7plus_has_session_id = s7p.has_session_id;
                            out.s7plus_session_id = s7p.session_id;
                            out.s7plus_body_decoded = s7p.body_decoded;
                            out.s7plus_has_return_value = s7p.has_return_value;
                            out.s7plus_return_code = s7p.return_code;
                            out.s7plus_return_code_name = s7p.return_code_name;
                            const size_t kMaxTags = resource_limits().max_decoded_objects.value_or(50);
                            for (size_t i = 0; i < s7p.item_addresses.size() && i < kMaxTags; ++i) {
                                out.s7plus_item_tags.push_back(s7p.item_addresses[i].tag);
                            }
                            for (size_t i = 0; i < s7p.id_values.size() && i < kMaxTags; ++i) {
                                out.s7plus_value_summaries.push_back(s7p.id_values[i].rendered);
                            }
                            for (size_t i = 0; i < s7p.item_errors.size() && i < kMaxTags; ++i) {
                                out.s7plus_item_errors.push_back(s7p.item_errors[i].rendered);
                            }
                            out.s7plus_has_integrity = s7p.has_integrity;
                            out.s7plus_integrity_digest_present = s7p.integrity_digest_present;
                            out.s7plus_integrity_digest_length = s7p.integrity_digest_length;
                            out.s7plus_has_trailer = s7p.has_trailer;
                            for (const auto& n : cr.notes) out.notes.push_back(n);
                            annotate_port();
                            return out;
                        }
                    }

                    // MMS shares this exact TCP port 102 / TPKT+COTP transport with S7comm -- see
                    // mms.hpp's own file-header comment on dispatch ordering. S7comm's single-byte
                    // protocol-id gate is tried first (above) since it is materially stronger and
                    // cheaper; this is only reached once that has already failed.
                    if (want_mms) {
                        rider_ctx.protocol_id = "mms";
                        if (auto result = mms_decoder().decode(cr.s7_candidate(), rider_ctx)) {
                            const MmsFrame& mms = result->as<MmsFrame>();
                            out.protocol = "mms";
                            out.summary = mms.summary;
                            for (const auto& n : mms.notes) out.notes.push_back(n);
                            // MmsFrame has no ByteSpan of its own (every field above is an owned
                            // scalar/string/vector -- see mms.hpp), so it's safe to carry forward
                            // unmodified, unlike S7comm's own S7CommResult wrapper. The old dual
                            // write's own 50-entry cap on mms_values is now applied where it's
                            // rendered instead (output.cpp's write_mms_json_fields), the same
                            // "defer the transform" shape S7CommResult::items uses.
                            out.result = *result;
                            for (const auto& n : cr.notes) out.notes.push_back(n);
                            annotate_port();
                            return out;
                        }
                    }
                }

                out.protocol = "cotp";
                out.summary = cr.frame.summary;
                for (const auto& n : cr.notes) out.notes.push_back(n);
                annotate_port();
                return out;
            }
        }

        // Tried LAST -- see the matching, fuller comment in reassemble_tcp_payload above for why
        // HART-IP's own weaker structural detection gate is deliberately given the lowest priority
        // in this opportunistic, port-independent dispatch chain, and for the accepted, documented
        // collision (HART-IP Session Initiate over TCP misclassifying as Modbus/TCP) this ordering
        // does NOT resolve.
        if (want_hartip) {
            // Migration batch 2: the same-payload multi-message coalescing loop and the merge-
            // fields logic that used to live directly in this call site are now reached through
            // HartIpTcpDecoder::decode -- HART-IP over TCP is purely stateless, so ctx is passed
            // only because ProtocolDecoder::decode's signature requires one. See
            // hartip.hpp/hartip.cpp. This is the TCP side only -- HART-IP's own UDP path is a
            // separate decoder instance sharing this same "hartip" id(), reached from the UDP
            // dispatch above.
            DecodeContext ctx;
            ctx.packet_index = index;
            ctx.protocol_id = "hartip";
            ctx.flow_states = &registry_flow_state_;
            if (auto hartip_result = hartip_tcp_decoder().decode(effective_payload, ctx)) {
                const HartIpResult& hr = hartip_result->as<HartIpResult>();
                out.protocol = "hartip";
                out.summary = hr.summary;
                for (const auto& n : hr.notes) out.notes.push_back(n);
                out.result = *hartip_result;

                bool expected_port = port_in(tcp.src_port, HARTIP_PORT, options_.extra_hartip_ports) ||
                                      port_in(tcp.dst_port, HARTIP_PORT, options_.extra_hartip_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard HART-IP port (5094)");
                }
                return out;
            }
        }

        // Tried LAST of all -- see the matching, fuller comment in reassemble_tcp_payload above for
        // why MQTT's own structural detection gate is deliberately given the lowest priority in
        // this opportunistic, port-independent dispatch chain, even below HART-IP's. The SAME
        // FTP-vs-MQTT collision reassemble_tcp_payload's own declared-length probe already
        // excludes (see that comment for the full reasoning) applies here too, to MQTT's own full
        // message parse, not just its length probe -- an FTP reply-code/command-verb line on port
        // 21 that happened to satisfy MQTT's length gate would otherwise still be mis-parsed here
        // as a (bogus, near-empty) PUBLISH message once past the buffering stage.
        bool want_lateral_movement_mqtt_carveout = options_.protocol_filter == ProtocolFilter::Auto ||
                                                    options_.protocol_filter == ProtocolFilter::LateralMovementOnly;
        bool effective_payload_is_ftp_control =
            want_lateral_movement_mqtt_carveout &&
            (port_in(tcp.src_port, FTP_CONTROL_PORT, options_.extra_lateral_movement_ports) ||
             port_in(tcp.dst_port, FTP_CONTROL_PORT, options_.extra_lateral_movement_ports)) &&
            looks_like_ftp_control_line(effective_payload);
        // The SAME LDAP-vs-MQTT collision reassemble_tcp_payload's own declared-length probe above
        // already excludes (see that comment, and it_protocols.hpp's own looks_like_ldap_ber
        // comment, for the full reasoning) applies here too, to MQTT's own full message parse.
        bool want_enterprise_trust_mqtt_carveout = options_.protocol_filter == ProtocolFilter::Auto ||
                                                    options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly;
        bool effective_payload_is_ldap =
            want_enterprise_trust_mqtt_carveout &&
            (port_in(tcp.src_port, LDAP_PORT, options_.extra_enterprise_trust_ports) ||
             port_in(tcp.dst_port, LDAP_PORT, options_.extra_enterprise_trust_ports) ||
             port_in(tcp.src_port, LDAP_GC_PORT, options_.extra_enterprise_trust_ports) ||
             port_in(tcp.dst_port, LDAP_GC_PORT, options_.extra_enterprise_trust_ports)) &&
            looks_like_ldap_ber(effective_payload);
        if (want_mqtt && !effective_payload_is_ftp_control && !effective_payload_is_ldap) {
            // Migration batch 2: the session-version-hint lookup/learning and the same-payload
            // multi-message coalescing loop that used to live directly in this call site are now
            // reached through MqttDecoder::decode -- Decoder::mqtt_session_version_'s own bespoke
            // map is retired in favor of MqttFlowState, reached via the same
            // DecodeContext::flow_state<T>() (session-keyed, the unchanged default) every other
            // session-scoped stateful decoder in this codebase already uses. See mqtt.hpp/mqtt.cpp.
            std::string mqtt_session_key = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            DecodeContext ctx;
            ctx.session_key = mqtt_session_key;
            ctx.packet_index = index;
            ctx.protocol_id = "mqtt";
            ctx.flow_states = &registry_flow_state_;
            ctx.redact_secrets = options_.redact_secrets;
            if (auto mqtt_result = mqtt_decoder().decode(effective_payload, ctx)) {
                const MqttResult& mr = mqtt_result->as<MqttResult>();
                out.protocol = "mqtt";
                out.summary = mr.summary;
                for (const auto& n : mr.notes) out.notes.push_back(n);
                out.result = *mqtt_result;

                bool expected_port = port_in(tcp.src_port, MQTT_PORT, options_.extra_mqtt_ports) ||
                                      port_in(tcp.dst_port, MQTT_PORT, options_.extra_mqtt_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard MQTT port (1883)");
                }
                return out;
            }
        }

        // CODESYS V3 (Block Driver/TCP), tried right after MQTT and before FF-HSE -- see the
        // matching, fuller comment in reassemble_tcp_payload above for the collision reasoning.
        // Both TCP ports (11740 CmpChannelServer, 1217 CmpRouter gateway protocol) carry the
        // identical wire format, so this one decoder recognizes either. See codesys.hpp/codesys.cpp.
        if (want_codesys) {
            DecodeContext ctx;
            ctx.packet_index = index;
            ctx.protocol_id = "codesys";
            ctx.flow_states = &registry_flow_state_;
            if (auto codesys_result = codesys_tcp_decoder().decode(effective_payload, ctx)) {
                const CodesysFrame& cf = codesys_result->as<CodesysFrame>();
                out.protocol = "codesys";
                out.summary = cf.summary;
                for (const auto& n : cf.notes) out.notes.push_back(n);
                out.result = *codesys_result;

                bool expected_port =
                    port_in(tcp.src_port, CODESYS_TCP_PORT, options_.extra_codesys_ports) ||
                    port_in(tcp.dst_port, CODESYS_TCP_PORT, options_.extra_codesys_ports) ||
                    port_in(tcp.src_port, CODESYS_GATEWAY_TCP_PORT, options_.extra_codesys_ports) ||
                    port_in(tcp.dst_port, CODESYS_GATEWAY_TCP_PORT, options_.extra_codesys_ports);
                if (!expected_port) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard CODESYS port "
                                         "(11740, 1217)");
                }
                return out;
            }
        }

        // Tried LAST of all, even after MQTT -- see the matching, fuller comment in
        // reassemble_tcp_payload above for why FF-HSE's own structural detection gate is
        // deliberately given the lowest priority in this opportunistic, port-independent dispatch
        // chain.
        //
        // Registration-model migration: try_parse_ffhse + the same-payload multi-PDU coalescing
        // loop that used to live directly in this call site are now reached through
        // FfhseTcpDecoder::decode -- FF-HSE is a zero-flat-field migrated protocol (like
        // TwinCAT/HART-IP/etc.): out.result carries the whole FfhseResult, and output.cpp's
        // write_ffhse_json_fields reads straight from it. See ffhse.hpp/ffhse.cpp.
        if (want_ffhse) {
            DecodeContext ctx;
            ctx.packet_index = index;
            ctx.protocol_id = "ffhse";
            ctx.flow_states = &registry_flow_state_;
            if (auto ffhse_result = ffhse_tcp_decoder().decode(effective_payload, ctx)) {
                const FfhseResult& fr = ffhse_result->as<FfhseResult>();
                out.protocol = "ffhse";
                out.summary = fr.summary;
                for (const auto& n : fr.notes) out.notes.push_back(n);
                out.result = *ffhse_result;

                auto is_ffhse_port = [&](uint16_t port) {
                    return port_in(port, FFHSE_PORT_ANNUNC, options_.extra_ffhse_ports) ||
                           port_in(port, FFHSE_PORT_FMS, options_.extra_ffhse_ports) ||
                           port_in(port, FFHSE_PORT_SM, options_.extra_ffhse_ports) ||
                           port_in(port, FFHSE_PORT_LAN, options_.extra_ffhse_ports);
                };
                if (!is_ffhse_port(tcp.src_port) && !is_ffhse_port(tcp.dst_port)) {
                    out.notes.push_back("seen on TCP port " + std::to_string(tcp.src_port) + "->" +
                                         std::to_string(tcp.dst_port) +
                                         ", which is not a configured/standard FF-HSE port "
                                         "(1089/1090/1091/3622)");
                }
                return out;
            }
        }

        // Tier 1 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp. Tried
        // LAST among every TCP check above, deliberately: this is name-only recognition with the
        // weakest structural confidence in this codebase for three of its five protocols (port
        // number alone -- see it_protocols.hpp's own file header comment), so a real S7comm/MMS/
        // OPC UA/EtherNet/IP/etc. session gets every chance to be identified by its own, far
        // stronger signal first. It never collides with any of those anyway (none of RDP/VNC/
        // TeamViewer/AnyDesk/Zoom's own ports overlap a port this decoder already dispatches on),
        // so this ordering is a belt-and-suspenders precaution, not a fix for an actual conflict.
        bool want_remote_access = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::RemoteAccessOnly;
        if (want_remote_access) {
            if (auto m = try_recognize_it_remote_access(effective_payload, tcp.src_port, tcp.dst_port,
                                                          /*is_tcp=*/true, options_.extra_remote_access_ports)) {
                out.protocol = m->protocol;
                out.summary = m->summary;
                for (const auto& n : m->notes) out.notes.push_back(n);
                return out;
            }
        }

        // Tier 2 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp. Tried LAST,
        // same "weakest signals last" reasoning Tier 1 just above documents -- a real OT-protocol
        // session or a Tier 1 remote-access match always gets first chance. HTTPS's own strong
        // ClientHello check already ran much earlier (right after the DoH check, before TCP
        // reassembly -- see that call site's own comment); what reaches this point for "https" is
        // only ever its port-only fallback, handled inside try_recognize_it_lateral_movement below
        // exactly like every other Tier 2 protocol's own weak fallback.
        bool want_lateral_movement = options_.protocol_filter == ProtocolFilter::Auto ||
                                      options_.protocol_filter == ProtocolFilter::LateralMovementOnly;
        if (want_lateral_movement) {
            if (auto m = try_recognize_it_lateral_movement(effective_payload, tcp.src_port, tcp.dst_port,
                                                             /*is_tcp=*/true, options_.extra_lateral_movement_ports)) {
                out.protocol = m->protocol;
                out.summary = m->summary;
                for (const auto& n : m->notes) out.notes.push_back(n);
                return out;
            }
        }

        // Tier 3 "IT protocols an OT auditor flags" recognition -- see it_protocols.hpp. Tried LAST,
        // same "weakest signals last" reasoning Tiers 1-2 just above document. LDAPS's own strong
        // ClientHello check already ran much earlier (layered into the same early call site as
        // HTTPS's own -- see that call site's own comment); what reaches this point for "ldaps" is
        // only ever its port-only fallback, handled inside try_recognize_it_enterprise_trust below
        // exactly like every other Tier 3 protocol's own weak fallback.
        bool want_enterprise_trust = options_.protocol_filter == ProtocolFilter::Auto ||
                                      options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly;
        if (want_enterprise_trust) {
            if (auto m = try_recognize_it_enterprise_trust(effective_payload, tcp.src_port, tcp.dst_port,
                                                              /*is_tcp=*/true, options_.extra_enterprise_trust_ports)) {
                out.protocol = m->protocol;
                out.summary = m->summary;
                for (const auto& n : m->notes) out.notes.push_back(n);
                return out;
            }
        }

        // Tier 5 "IT protocols an OT auditor flags" recognition, TCP-port-keyed half -- see
        // tunnel_vpn.hpp. Tried LAST, same "weakest signals last" reasoning Tiers 1-3 just above
        // document. Only OpenVPN's own TCP framing and STT are reachable here (every other Tier 5
        // protocol is UDP-only or IP-protocol-number-keyed, dispatched elsewhere -- see those call
        // sites' own comments).
        bool want_tunnel_vpn = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::TunnelVpnOnly;
        if (want_tunnel_vpn) {
            if (auto m = try_recognize_tunnel_vpn_tcp(effective_payload, tcp.src_port, tcp.dst_port,
                                                         options_.extra_tunnel_vpn_ports)) {
                out.protocol = m->protocol;
                out.summary = m->summary;
                for (const auto& n : m->notes) out.notes.push_back(n);
                return out;
            }
        }

        // Generic "no protocol claimed this payload" fallback -- deliberately as terse as the
        // "udp" fallback just above (see udp_header's own summary a few hundred lines up): every
        // protocol this decoder knows was already tried by the time execution reaches here (Tiers
        // 1-5, in the order this function's own comments document), so spelling that whole list
        // out on every single unmatched TCP payload just added noise without adding information --
        // a user asked for this to be shortened after seeing it on ordinary, unremarkable traffic.
        out.protocol = "tcp";
        std::ostringstream s;
        s << "TCP payload of " << effective_payload.size() << " byte(s) on port " << tcp.src_port << "->"
          << tcp.dst_port;
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
