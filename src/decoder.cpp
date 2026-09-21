// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/decoder.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
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
#include "conduitscope/opcua.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/igmp.hpp"
#include "conduitscope/igrp.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/mqtt.hpp"
#include "conduitscope/ospf.hpp"
#include "conduitscope/pim.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tcp.hpp"
#include "conduitscope/udp.hpp"
#include "conduitscope/vrrp.hpp"

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

// Canonicalizes both directions of one TCP 4-tuple into a single, direction-independent session
// key, so Decoder::modbus_pending_/mqtt_session_version_ can track state per SESSION (a request and
// its response, or a CONNECT and a later SUBSCRIBE, can travel in opposite directions) rather than
// per directional flow -- unlike flow_key (used by dnp3_reassembly_/tcp_reassembly_/
// cotp_reassembly_, which genuinely are per-direction). "<->" is used as the join delimiter
// specifically so this can never collide with a directional flow_key string (which always uses
// "->"), even though the two happen to key different maps.
std::string tcp_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b,
                             uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

// Flattens a parsed DnsMessage (shared by "dns"/"mdns"/"llmnr" -- see dns.hpp) into
// DecodedPacket's dns_* fields, in wire order (questions, then answer/authority/additional).
void fill_dns_fields(DecodedPacket& out, const DnsMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.dns_transaction_id = msg.transaction_id;
    out.dns_is_response = msg.is_response;
    out.dns_opcode_name = msg.opcode_name;
    out.dns_header_flags = msg.header_flags;
    out.dns_rcode_name = msg.rcode_name;
    out.dns_qdcount = msg.qdcount;
    out.dns_ancount = msg.ancount;
    out.dns_nscount = msg.nscount;
    out.dns_arcount = msg.arcount;
    out.dns_records_truncated = msg.records_truncated;
    for (const auto& q : msg.questions) out.dns_records.push_back(q.summary);
    for (const auto& rr : msg.answers) out.dns_records.push_back(rr.summary);
    for (const auto& rr : msg.authorities) out.dns_records.push_back(rr.summary);
    for (const auto& rr : msg.additionals) out.dns_records.push_back(rr.summary);
}

// Flattens a parsed NbnsMessage (see nbns.hpp) into DecodedPacket's nbns_* fields.
void fill_nbns_fields(DecodedPacket& out, const NbnsMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.nbns_transaction_id = msg.transaction_id;
    out.nbns_is_response = msg.is_response;
    out.nbns_opcode_name = msg.opcode_name;
    out.nbns_flags = msg.flags;
    out.nbns_rcode_name = msg.rcode_name;
    out.nbns_qdcount = msg.qdcount;
    out.nbns_ancount = msg.ancount;
    out.nbns_nscount = msg.nscount;
    out.nbns_arcount = msg.arcount;
    out.nbns_records_truncated = msg.records_truncated;
    for (const auto& q : msg.questions) out.nbns_records.push_back(q.summary);
    for (const auto& rr : msg.answers) out.nbns_records.push_back(rr.summary);
    for (const auto& rr : msg.authorities) out.nbns_records.push_back(rr.summary);
    for (const auto& rr : msg.additionals) out.nbns_records.push_back(rr.summary);
}

// Renders one RipRoute as a single line for DecodedPacket::rip_routes -- see rip.hpp for what
// each of the three RTE shapes (ordinary route, full-table-request marker, authentication entry)
// means.
std::string rip_route_summary(const RipRoute& r) {
    if (r.is_auth_entry) {
        std::ostringstream s;
        s << "authentication: " << r.auth_type_name;
        if (r.auth_type == 3) {
            s << " (key id " << static_cast<unsigned>(r.md5_key_id) << ")";
        }
        return s.str();
    }
    if (r.is_full_table_request) {
        return "full table request";
    }
    std::ostringstream s;
    s << r.address << "/" << r.subnet_mask << " via " << r.next_hop << " metric " << r.metric;
    if (r.route_tag != 0) {
        s << " tag " << r.route_tag;
    }
    return s.str();
}

// Flattens a parsed RipMessage (see rip.hpp) into DecodedPacket's rip_* fields.
void fill_rip_fields(DecodedPacket& out, const RipMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.rip_version = msg.version;
    out.rip_command_name = msg.command_name;
    out.rip_routes_truncated = msg.routes_truncated;
    for (const auto& r : msg.routes) out.rip_routes.push_back(rip_route_summary(r));
}

// Renders one IcmpRouterAddress as a single line for DecodedPacket::icmp_router_addresses.
std::string icmp_router_address_summary(const IcmpRouterAddress& ra) {
    std::ostringstream s;
    s << ra.address << " (" << ra.preference << ")";
    return s.str();
}

// Flattens a parsed IcmpMessage (see icmp.hpp) into DecodedPacket's icmp_* fields.
void fill_icmp_fields(DecodedPacket& out, const IcmpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.icmp_type = msg.type;
    out.icmp_code = msg.code;
    out.icmp_type_name = msg.type_name;
    out.icmp_code_name = msg.code_name;
    out.icmp_checksum_valid = msg.checksum_valid;
    out.icmp_echo_identifier = msg.echo_identifier;
    out.icmp_echo_sequence = msg.echo_sequence;
    out.icmp_next_hop_mtu = msg.next_hop_mtu;
    out.icmp_redirect_gateway = msg.redirect_gateway;
    out.icmp_parameter_pointer = msg.parameter_pointer;
    out.icmp_address_mask = msg.address_mask;
    out.icmp_originate_timestamp_ms = msg.originate_timestamp_ms;
    out.icmp_receive_timestamp_ms = msg.receive_timestamp_ms;
    out.icmp_transmit_timestamp_ms = msg.transmit_timestamp_ms;
    out.icmp_router_addresses_truncated = msg.router_addresses_truncated;
    for (const auto& ra : msg.router_addresses) out.icmp_router_addresses.push_back(icmp_router_address_summary(ra));
    if (msg.embedded_datagram) {
        const auto& ed = *msg.embedded_datagram;
        std::ostringstream s;
        s << ed.src_addr << "->" << ed.dst_addr;
        if (!ed.protocol_name.empty()) {
            s << " (" << ed.protocol_name;
            if (ed.has_ports) s << " " << ed.src_port << "->" << ed.dst_port;
            s << ")";
        } else {
            s << " (IP protocol " << static_cast<unsigned>(ed.protocol) << ")";
        }
        out.icmp_embedded_datagram = s.str();
    }
}

// Renders one IgmpGroupRecord as a single line for DecodedPacket::igmp_group_records.
std::string igmp_group_record_summary(const IgmpGroupRecord& rec) {
    std::ostringstream s;
    s << rec.record_type_name << ": " << rec.multicast_address << " (" << rec.source_addresses.size()
      << " source(s))";
    return s.str();
}

// Flattens a parsed IgmpMessage (see igmp.hpp) into DecodedPacket's igmp_* fields.
void fill_igmp_fields(DecodedPacket& out, const IgmpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.igmp_version = msg.version;
    out.igmp_type_name = msg.type_name;
    out.igmp_group_address = msg.group_address;
    out.igmp_group_records_truncated = msg.group_records_truncated;
    for (const auto& rec : msg.group_records) out.igmp_group_records.push_back(igmp_group_record_summary(rec));
}

// Flattens a parsed VrrpMessage (see vrrp.hpp) into DecodedPacket's vrrp_* fields.
void fill_vrrp_fields(DecodedPacket& out, const VrrpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.vrrp_version = msg.version;
    out.vrrp_virtual_router_id = msg.virtual_router_id;
    out.vrrp_priority = msg.priority;
    out.vrrp_ip_addresses = msg.ip_addresses;
    out.vrrp_ip_addresses_truncated = msg.ip_addresses_truncated;
}

// Flattens a parsed HsrpMessage (see hsrp.hpp) into DecodedPacket's hsrp_* fields.
void fill_hsrp_fields(DecodedPacket& out, const HsrpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.hsrp_version = msg.version;
    if (msg.version == 1) {
        out.hsrp_opcode_name = msg.opcode_name;
        out.hsrp_state_name = msg.state_name;
        out.hsrp_virtual_ip = msg.virtual_ip;
    } else {
        for (const auto& tlv : msg.tlvs) out.hsrp_tlv_types.push_back(tlv.type_name);
        out.hsrp_tlvs_truncated = msg.tlvs_truncated;
    }
}

// Renders one IgrpRoute as a single line for DecodedPacket::igrp_routes -- see igrp.hpp for why
// route_kind changes how address was reconstructed.
std::string igrp_route_summary(const IgrpRoute& r) {
    std::ostringstream s;
    s << r.route_kind << " " << r.address;
    if (r.unreachable) {
        s << " unreachable";
    } else {
        s << " delay=" << r.delay_microseconds << "us bw=" << r.bandwidth_kbps
          << "kbps hops=" << static_cast<unsigned>(r.hop_count);
    }
    return s.str();
}

// Flattens a parsed IgrpMessage (see igrp.hpp) into DecodedPacket's igrp_* fields.
void fill_igrp_fields(DecodedPacket& out, const IgrpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.igrp_version = msg.version;
    out.igrp_opcode_name = msg.opcode_name;
    out.igrp_autonomous_system = msg.autonomous_system;
    out.igrp_routes_truncated = msg.routes_truncated;
    for (const auto& r : msg.routes) out.igrp_routes.push_back(igrp_route_summary(r));
}

// Renders one PimHelloOption as a single line for DecodedPacket::pim_hello_options.
std::string pim_hello_option_summary(const PimHelloOption& opt) {
    if (!opt.addresses.empty()) {
        std::ostringstream s;
        s << opt.option_type_name << " (";
        for (size_t i = 0; i < opt.addresses.size(); ++i) {
            if (i != 0) s << ", ";
            s << opt.addresses[i];
        }
        s << ")";
        return s.str();
    }
    if (opt.value.empty()) return opt.option_type_name;
    return opt.option_type_name + ": " + opt.value;
}

// Renders one PimJoinPruneGroup as a single line for DecodedPacket::pim_jp_groups.
std::string pim_jp_group_summary(const PimJoinPruneGroup& g) {
    std::ostringstream s;
    s << g.group << ": " << g.joins.size() << " join(s), " << g.prunes.size() << " prune(s)";
    return s.str();
}

// Renders one PimBsrGroupRps as a single line for DecodedPacket::pim_bsr_groups.
std::string pim_bsr_group_summary(const PimBsrGroupRps& g) {
    std::ostringstream s;
    s << g.group << ": " << g.candidate_rps.size() << " candidate-RP(s)";
    return s.str();
}

// Flattens a parsed PimMessage (see pim.hpp) into DecodedPacket's pim_* fields. Which fields end
// up populated depends entirely on msg.type_name (pim.hpp's PimMessage doc comment says which
// group belongs to which message type) -- this just copies every group across unconditionally,
// since the unused ones are simply left at their default (empty/false/0) values.
void fill_pim_fields(DecodedPacket& out, const PimMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.pim_type_name = msg.type_name;

    out.pim_hello_options_truncated = msg.hello_options_truncated;
    for (const auto& opt : msg.hello_options) out.pim_hello_options.push_back(pim_hello_option_summary(opt));

    out.pim_register_border_bit = msg.register_border_bit;
    out.pim_register_null_register_bit = msg.register_null_register_bit;
    out.pim_register_inner_src_ip = msg.register_inner_src_ip;
    out.pim_register_inner_group_ip = msg.register_inner_group_ip;

    out.pim_register_stop_group = msg.register_stop_group;
    out.pim_register_stop_source = msg.register_stop_source;

    out.pim_jp_upstream_neighbor = msg.jp_upstream_neighbor;
    out.pim_jp_holdtime_sec = msg.jp_holdtime_sec;
    out.pim_jp_groups_truncated = msg.jp_groups_truncated;
    for (const auto& g : msg.jp_groups) out.pim_jp_groups.push_back(pim_jp_group_summary(g));

    out.pim_bsr_fragment_tag = msg.bsr_fragment_tag;
    out.pim_bsr_hash_mask_len = msg.bsr_hash_mask_len;
    out.pim_bsr_priority = msg.bsr_priority;
    out.pim_bsr_address = msg.bsr_address;
    out.pim_bsr_groups_truncated = msg.bsr_groups_truncated;
    for (const auto& g : msg.bsr_groups) out.pim_bsr_groups.push_back(pim_bsr_group_summary(g));

    out.pim_assert_group = msg.assert_group;
    out.pim_assert_source = msg.assert_source;
    out.pim_assert_rpt_bit = msg.assert_rpt_bit;
    out.pim_assert_metric_preference = msg.assert_metric_preference;
    out.pim_assert_metric = msg.assert_metric;

    out.pim_crp_prefix_count = msg.crp_prefix_count;
    out.pim_crp_priority = msg.crp_priority;
    out.pim_crp_holdtime_sec = msg.crp_holdtime_sec;
    out.pim_crp_rp_address = msg.crp_rp_address;
    out.pim_crp_groups_truncated = msg.crp_groups_truncated;
    out.pim_crp_groups = msg.crp_groups;
}

// Renders one EigrpGeneralTlv as a single line for DecodedPacket::eigrp_general_tlvs.
std::string eigrp_general_tlv_summary(const EigrpGeneralTlv& tlv) {
    if (tlv.value.empty()) return tlv.type_name;
    return tlv.type_name + ": " + tlv.value;
}

// Flattens a parsed EigrpMessage (see eigrp.hpp) into DecodedPacket's eigrp_* fields.
void fill_eigrp_fields(DecodedPacket& out, const EigrpMessage& msg) {
    out.summary = msg.summary;
    for (const auto& n : msg.notes) out.notes.push_back(n);
    out.eigrp_opcode_name = msg.opcode_name;
    out.eigrp_autonomous_system = msg.autonomous_system;
    if (msg.flag_init) out.eigrp_flags.push_back("Init");
    if (msg.flag_conditional_receive) out.eigrp_flags.push_back("Conditional Receive");
    if (msg.flag_restart) out.eigrp_flags.push_back("Restart");
    if (msg.flag_end_of_table) out.eigrp_flags.push_back("End Of Table");
    out.eigrp_general_tlvs_truncated = msg.general_tlvs_truncated;
    for (const auto& tlv : msg.general_tlvs) out.eigrp_general_tlvs.push_back(eigrp_general_tlv_summary(tlv));
    out.eigrp_routes_truncated = msg.routes_truncated;
    for (const auto& r : msg.routes) out.eigrp_routes.push_back(r.summary);
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

std::optional<Dnp3ApplicationFragment> Decoder::process_dnp3_frame(Dnp3LinkFrame& link, ByteSpan tcp_payload,
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
    // reassembly (process_dnp3_frame's own kMaxBufferedBytes=65536) and COTP TSDU reassembly
    // (reassemble_cotp_data_frame's own kMaxBufferedBytes=1<<20), this general path -- shared by
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
        constexpr size_t kMaxBufferedBytes = 16u * 1024u * 1024u;  // 16 MiB
        constexpr size_t kMaxSegmentsPerReassembly = 20000;
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
        if (auto d = opcua_declared_length(candidate)) {
            declared = d;
            which = "OPC UA message";
        }
    }
    if (!declared && want_enip) {
        if (auto d = enip_declared_length(candidate)) {
            declared = d;
            which = "EtherNet/IP encapsulation message";
        }
    }
    if (!declared && want_iec104) {
        if (auto d = iec104_apdu_declared_length(candidate)) {
            declared = d;
            which = "IEC 104 APDU";
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
    if (!declared && want_dnp3) {
        if (auto d = dnp3_link_frame_declared_length(candidate)) {
            declared = d;
            which = "DNP3 data-link";
        }
    }
    if (!declared && (want_s7comm || want_mms || want_s7commplus)) {
        if (auto d = tpkt_declared_length(candidate)) {
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
        if (auto d = hartip_declared_length(candidate)) {
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
    // it_protocols.hpp's own looks_like_ldap_ber comment for the full reasoning. Resolved the same
    // way, by port.
    bool want_enterprise_trust_reassembly = options_.protocol_filter == ProtocolFilter::Auto ||
                                             options_.protocol_filter == ProtocolFilter::EnterpriseTrustOnly;
    bool candidate_is_ldap =
        want_enterprise_trust_reassembly &&
        (port_in(tcp.src_port, LDAP_PORT, options_.extra_enterprise_trust_ports) ||
         port_in(tcp.dst_port, LDAP_PORT, options_.extra_enterprise_trust_ports) ||
         port_in(tcp.src_port, LDAP_GC_PORT, options_.extra_enterprise_trust_ports) ||
         port_in(tcp.dst_port, LDAP_GC_PORT, options_.extra_enterprise_trust_ports)) &&
        looks_like_ldap_ber(candidate);
    if (!declared && want_mqtt && !candidate_is_ftp_control && !candidate_is_ldap) {
        if (auto d = mqtt_declared_length(candidate)) {
            declared = d;
            which = "MQTT packet";
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
        if (auto d = ffhse_declared_length(candidate)) {
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

// Decoder::pair_modbus_transaction used to live here. It moved to ModbusDecoder::decode
// (modbus.cpp) as part of the registration-model decoder refactor's pilot (Stage 2) -- see
// modbus.hpp's ModbusPendingRequest/ModbusFlowState and protocol_decoder.hpp's DecodeContext.

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
                // PROFINET RT (EtherType 0x8892) is tried first, port-independently -- there is
                // no port at all here, but same rationale as CIP I/O's own UDP dispatch (see
                // above): try_parse_profinet's FrameID check is this decoder's only structural
                // gate, and this EtherType has zero collision risk with any other protocol this
                // tool decodes (see profinet.hpp's file header comment).
                bool want_profinet = options_.protocol_filter == ProtocolFilter::Auto ||
                                      options_.protocol_filter == ProtocolFilter::ProfinetOnly;
                if (want_profinet && eth.ethertype == ETHERTYPE_PROFINET) {
                    if (auto pn = try_parse_profinet(eth.payload)) {
                        out.protocol = "profinet";
                        out.summary = pn->summary;
                        out.profinet_frame_id = pn->frame_id;
                        out.profinet_frame_id_name = pn->frame_id_name;
                        for (const auto& n : pn->notes) out.notes.push_back(n);

                        if (pn->has_dcp) {
                            out.profinet_has_dcp = true;
                            out.profinet_dcp_service_name = pn->dcp_service_name;
                            out.profinet_dcp_service_type_name = pn->dcp_service_type_name;
                            constexpr size_t kMaxDcpBlockValues = 50;
                            for (const auto& block : pn->dcp_blocks) {
                                if (out.profinet_dcp_blocks.size() >= kMaxDcpBlockValues) break;
                                std::string label = !block.name.empty() ? block.name
                                                                          : ("option=" + std::to_string(block.option) +
                                                                             " suboption=" + std::to_string(block.suboption));
                                out.profinet_dcp_blocks.push_back(label + "=" + block.value);
                            }
                        }
                        if (pn->has_cyclic_data) {
                            out.profinet_has_cyclic_data = true;
                            out.profinet_cyclic_io_data_hex = pn->cyclic_io_data_hex;
                            out.profinet_cyclic_io_data_length = pn->cyclic_io_data_length;
                            out.profinet_cyclic_cycle_counter = pn->cyclic_cycle_counter;
                            out.profinet_cyclic_data_status_summary = pn->cyclic_data_status_summary;
                            out.profinet_cyclic_transfer_status = pn->cyclic_transfer_status;
                        }
                        return out;
                    }
                }

                // IEC 61850-8-1 GOOSE (EtherType 0x88B8), same rationale/pattern as PROFINET RT
                // above: port-independent, try_parse_goose's own outer-APDU-tag check is this
                // decoder's structural gate (see goose.hpp's file header comment).
                bool want_goose = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::GooseOnly;
                if (want_goose && eth.ethertype == ETHERTYPE_IEC61850_GOOSE) {
                    // Registration-model pilot (Stage 3): try_parse_goose is now reached through
                    // GooseDecoder::decode rather than called directly -- same function, same
                    // semantics, see goose.hpp. The dual-write below is unchanged.
                    DecodeContext ctx;
                    ctx.protocol_id = "goose";
                    if (auto result = goose_decoder().decode(eth.payload, ctx)) {
                        const GooseFrame& gs = result->as<GooseFrame>();
                        out.protocol = "goose";
                        out.summary = gs.summary;
                        out.goose_appid = gs.appid;
                        out.goose_is_gse_management = gs.is_gse_management;
                        out.goose_has_pdu = gs.has_pdu;
                        for (const auto& n : gs.notes) out.notes.push_back(n);

                        if (gs.has_pdu) {
                            out.goose_simulated = gs.header_simulated || (gs.simulation && *gs.simulation);
                            out.goose_gocb_ref = gs.gocb_ref;
                            out.goose_dat_set = gs.dat_set;
                            if (gs.go_id) out.goose_go_id = *gs.go_id;
                            out.goose_st_num = gs.st_num;
                            out.goose_sq_num = gs.sq_num;
                            out.goose_conf_rev = gs.conf_rev;
                            out.goose_num_dat_set_entries = gs.num_dat_set_entries;
                            constexpr size_t kMaxGooseDataValueEntries = 50;
                            for (const auto& v : gs.all_data) {
                                if (out.goose_all_data.size() >= kMaxGooseDataValueEntries) break;
                                std::string label = !v.type_name.empty() ? v.type_name : "raw";
                                out.goose_all_data.push_back(v.path + ": " + label + "=" + v.value);
                            }
                        }
                        return out;
                    }
                }

                // IEC 61850-9-2 Sampled Values (EtherType 0x88BA), same rationale/pattern as
                // GOOSE above -- the two share their entire link-layer header format (see
                // sv.hpp's file header comment) -- try_parse_sv's own outer-APDU-tag check is
                // this decoder's structural gate.
                bool want_sv = options_.protocol_filter == ProtocolFilter::Auto ||
                                options_.protocol_filter == ProtocolFilter::SvOnly;
                if (want_sv && eth.ethertype == ETHERTYPE_IEC61850_SV) {
                    if (auto sv = try_parse_sv(eth.payload)) {
                        out.protocol = "sv";
                        out.summary = sv->summary;
                        out.sv_appid = sv->appid;
                        out.sv_simulated = sv->header_simulated;
                        out.sv_no_asdu = sv->no_asdu;
                        out.sv_asdu_count = sv->asdus.size();
                        for (const auto& n : sv->notes) out.notes.push_back(n);

                        if (!sv->asdus.empty()) {
                            const SvAsdu& first = sv->asdus[0];
                            out.sv_id = first.sv_id;
                            if (first.dat_set) out.sv_dat_set = *first.dat_set;
                            out.sv_smp_cnt = first.smp_cnt;
                            out.sv_conf_rev = first.conf_rev;
                            if (first.smp_synch) out.sv_smp_synch = *first.smp_synch;
                            if (first.smp_rate) out.sv_smp_rate = *first.smp_rate;
                            if (first.smp_mod) out.sv_smp_mod = *first.smp_mod;
                            out.sv_seq_data_hex = first.seq_data_hex;
                            out.sv_seq_data_length = first.seq_data_length;
                            if (first.gmid_hex) out.sv_gmid_hex = *first.gmid_hex;
                        }
                        constexpr size_t kMaxSvAsduSummaries = 50;
                        for (const auto& asdu : sv->asdus) {
                            if (out.sv_asdus.size() >= kMaxSvAsduSummaries) break;
                            std::ostringstream a;
                            a << "svID=\"" << asdu.sv_id << "\"";
                            if (asdu.dat_set) a << " datSet=\"" << *asdu.dat_set << "\"";
                            a << " smpCnt=" << asdu.smp_cnt << " confRev=" << asdu.conf_rev;
                            if (asdu.smp_synch) a << " smpSynch=" << *asdu.smp_synch;
                            if (asdu.smp_rate) a << " smpRate=" << *asdu.smp_rate;
                            if (asdu.smp_mod) a << " smpMod=" << *asdu.smp_mod;
                            a << " seqData=" << asdu.seq_data_length << " byte(s)";
                            out.sv_asdus.push_back(a.str());
                        }
                        return out;
                    }
                }

                // EtherCAT (EtherType 0x88A4), same rationale/pattern as PROFINET RT/GOOSE/SV
                // above -- try_parse_ethercat's own frame-header Type check is this decoder's
                // structural gate (see ethercat.hpp's file header comment's "structural detection
                // gate" paragraph for why that gate is weaker than GOOSE/SV/PROFINET's own, and
                // why the dedicated EtherType still makes this a safe default in Auto mode).
                bool want_ethercat = options_.protocol_filter == ProtocolFilter::Auto ||
                                      options_.protocol_filter == ProtocolFilter::EthercatOnly;
                if (want_ethercat && eth.ethertype == ETHERTYPE_ETHERCAT) {
                    if (auto ec = try_parse_ethercat(eth.payload)) {
                        out.protocol = "ethercat";
                        out.summary = ec->summary;
                        out.ethercat_frame_type = ec->frame_type;
                        out.ethercat_frame_type_name = ec->frame_type_name;
                        out.ethercat_declared_length = ec->declared_length;
                        out.ethercat_has_datagrams = ec->has_datagrams;
                        out.ethercat_datagram_count = ec->datagrams.size();
                        for (const auto& n : ec->notes) out.notes.push_back(n);

                        if (!ec->datagrams.empty()) {
                            const EthercatDatagram& first = ec->datagrams[0];
                            out.ethercat_first_cmd = first.cmd;
                            out.ethercat_first_cmd_name = first.cmd_name;
                            out.ethercat_first_idx = first.idx;
                            out.ethercat_first_logical_addressing = first.logical_addressing;
                            out.ethercat_first_adp = first.adp;
                            out.ethercat_first_ado = first.ado;
                            out.ethercat_first_logical_address = first.logical_address;
                            out.ethercat_first_data_hex = first.data_hex;
                            out.ethercat_first_data_length = first.data_length;
                            out.ethercat_first_wkc = first.wkc;
                            out.ethercat_first_irq = first.irq;
                            out.ethercat_first_circulating = first.circulating;
                        }
                        constexpr size_t kMaxEthercatDatagramSummaries = 50;
                        for (const auto& dgram : ec->datagrams) {
                            if (out.ethercat_datagrams.size() >= kMaxEthercatDatagramSummaries) break;
                            std::ostringstream a;
                            a << dgram.cmd_name << " idx=" << static_cast<unsigned>(dgram.idx) << " ";
                            if (dgram.logical_addressing) {
                                a << "logAddr=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                                  << dgram.logical_address << std::dec;
                            } else {
                                a << "adp=0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                                  << dgram.adp << " ado=0x" << std::setw(4) << std::setfill('0') << dgram.ado
                                  << std::dec;
                            }
                            a << " len=" << dgram.data_len << " wkc=" << dgram.wkc;
                            // irq/circulating are shown only when notable (irq != 0, circulating
                            // set) to keep the common case's summary line uncluttered -- the same
                            // "only when it deviates" posture ethercat.hpp's frame-level notes take
                            // for the Reserved bit.
                            if (dgram.irq != 0) {
                                a << " irq=0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                                  << dgram.irq << std::dec;
                            }
                            if (dgram.circulating) a << " circulating";
                            out.ethercat_datagrams.push_back(a.str());
                        }
                        return out;
                    }
                }

                // IEEE 802.1X/EAPOL (EtherType 0x888E) -- ROADMAP item 18's Tier 3, same
                // EtherType-keyed rationale/pattern as PROFINET RT/GOOSE/SV/EtherCAT above, except
                // EAPOL has its own dedicated ProtocolFilter::EapolOnly rather than sharing Tier 3's
                // port-based EnterpriseTrustOnly filter -- see decoder.hpp's own comment on both and
                // eapol.hpp's file header comment for the full reasoning.
                bool want_eapol = options_.protocol_filter == ProtocolFilter::Auto ||
                                    options_.protocol_filter == ProtocolFilter::EapolOnly;
                if (want_eapol && eth.ethertype == ETHERTYPE_EAPOL) {
                    if (auto ea = try_parse_eapol(eth.payload)) {
                        out.protocol = "eapol";
                        out.summary = ea->summary;
                        out.eapol_version = ea->version;
                        out.eapol_version_name = ea->version_name;
                        out.eapol_type = ea->type;
                        out.eapol_type_name = ea->type_name;
                        out.eapol_length = ea->length;
                        out.eapol_has_eap = ea->has_eap;
                        out.eapol_eap_code = ea->eap_code;
                        out.eapol_eap_code_name = ea->eap_code_name;
                        out.eapol_eap_identifier = ea->eap_identifier;
                        out.eapol_eap_declared_length = ea->eap_declared_length;
                        out.eapol_has_eap_type = ea->has_eap_type;
                        out.eapol_eap_type = ea->eap_type;
                        out.eapol_eap_type_name = ea->eap_type_name;
                        out.eapol_has_key_descriptor = ea->has_eapol_key_descriptor;
                        out.eapol_key_descriptor_type = ea->eapol_key_descriptor_type;
                        out.eapol_key_descriptor_type_name = ea->eapol_key_descriptor_type_name;
                        for (const auto& n : ea->notes) out.notes.push_back(n);
                        return out;
                    }
                }

                // PPPoE (EtherType 0x8863 Discovery / 0x8864 Session) -- ROADMAP item 18's Tier 4,
                // same EtherType-keyed rationale/pattern as PROFINET RT/GOOSE/SV/EtherCAT/EAPOL
                // above, except PPPoE has its own dedicated ProtocolFilter::PppoeOnly rather than
                // sharing Tier 4's port-based WirelessBackhaulOnly filter -- see decoder.hpp's own
                // comment on both and pppoe.hpp's file header comment for the full reasoning. Two
                // EtherTypes share one dispatch: try_parse_pppoe itself decides which Code values
                // are valid based on which stage its own `is_session_ethertype` argument names.
                bool want_pppoe = options_.protocol_filter == ProtocolFilter::Auto ||
                                    options_.protocol_filter == ProtocolFilter::PppoeOnly;
                if (want_pppoe && (eth.ethertype == ETHERTYPE_PPPOE_DISCOVERY ||
                                    eth.ethertype == ETHERTYPE_PPPOE_SESSION)) {
                    bool is_session_ethertype = (eth.ethertype == ETHERTYPE_PPPOE_SESSION);
                    if (auto pp = try_parse_pppoe(eth.payload, is_session_ethertype)) {
                        out.protocol = "pppoe";
                        out.summary = pp->summary;
                        out.pppoe_version = pp->version;
                        out.pppoe_type = pp->type;
                        out.pppoe_code = pp->code;
                        out.pppoe_code_name = pp->code_name;
                        out.pppoe_session_id = pp->session_id;
                        out.pppoe_length = pp->length;
                        out.pppoe_is_session = pp->is_session;
                        out.pppoe_has_ppp_protocol = pp->has_ppp_protocol;
                        out.pppoe_ppp_protocol = pp->ppp_protocol;
                        out.pppoe_ppp_protocol_name = pp->ppp_protocol_name;
                        for (const auto& n : pp->notes) out.notes.push_back(n);
                        return out;
                    }
                }

                // MPLS (EtherType 0x8847 unicast / 0x8848 multicast) -- ROADMAP item 18's Tier 5,
                // same EtherType-keyed rationale/pattern as EAPOL/PPPoE above, except MPLS has its
                // own dedicated ProtocolFilter::MplsOnly rather than sharing Tier 5's port/IP-
                // protocol-number-based TunnelVpnOnly filter -- see decoder.hpp's own comment on
                // both and mpls.hpp's file header comment for the full reasoning. There is no
                // structural gate to fail here (see mpls.hpp's own try_parse_mpls comment) -- the
                // EtherType alone carries all the confidence, so this always succeeds once at least
                // 4 bytes are available.
                bool want_mpls = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::MplsOnly;
                if (want_mpls && (eth.ethertype == ETHERTYPE_MPLS_UNICAST ||
                                    eth.ethertype == ETHERTYPE_MPLS_MULTICAST)) {
                    if (auto mp = try_parse_mpls(eth.payload)) {
                        out.protocol = "mpls";
                        out.summary = mp->summary;
                        out.mpls_is_multicast = (eth.ethertype == ETHERTYPE_MPLS_MULTICAST);
                        out.mpls_stack_truncated = mp->stack_truncated;
                        out.mpls_stack_too_deep = mp->stack_too_deep;
                        out.mpls_label_count = mp->labels.size();
                        if (!mp->labels.empty()) {
                            const MplsLabelEntry& top = mp->labels.front();
                            out.mpls_top_label = top.label;
                            out.mpls_top_exp = top.exp;
                            out.mpls_top_ttl = top.ttl;
                        }
                        constexpr size_t kMaxMplsLabelSummaries = 50;
                        for (const auto& entry : mp->labels) {
                            if (out.mpls_labels.size() >= kMaxMplsLabelSummaries) break;
                            std::ostringstream ls;
                            ls << "label=" << entry.label;
                            if (!entry.label_name.empty()) ls << " (" << entry.label_name << ")";
                            ls << " exp=" << static_cast<unsigned>(entry.exp)
                               << " ttl=" << static_cast<unsigned>(entry.ttl)
                               << " s=" << (entry.bottom_of_stack ? "true" : "false");
                            out.mpls_labels.push_back(ls.str());
                        }
                        for (const auto& n : mp->notes) out.notes.push_back(n);
                        return out;
                    }
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
                        if (auto stp = try_parse_stp(eth.llc_payload)) {
                            out.protocol = "stp";
                            out.summary = stp->summary;
                            for (const auto& n : stp->notes) out.notes.push_back(n);
                            if (eth.llc_trailing_bytes_trimmed > 0) {
                                out.notes.push_back(
                                    std::to_string(eth.llc_trailing_bytes_trimmed) +
                                    " trailing byte(s) after the 802.3 Length field's declared LLC "
                                    "client-data length were trimmed (almost always Ethernet "
                                    "minimum-frame-size padding, not real payload)");
                            }

                            out.stp_protocol_version_name = stp->protocol_version_name;
                            out.stp_protocol_version = stp->protocol_version;
                            out.stp_bpdu_type_name = stp->bpdu_type_name;
                            out.stp_bpdu_type = stp->bpdu_type;
                            out.stp_is_tcn = stp->is_tcn;
                            out.stp_is_spb = stp->is_spb;

                            if (stp->has_common_body) {
                                out.stp_has_common_body = true;
                                out.stp_flags = stp->flags;
                                out.stp_flag_tca = stp->flag_tca;
                                out.stp_flag_agreement = stp->flag_agreement;
                                out.stp_flag_forwarding = stp->flag_forwarding;
                                out.stp_flag_learning = stp->flag_learning;
                                out.stp_flag_port_role = stp->flag_port_role;
                                out.stp_flag_port_role_name = stp_port_role_name(stp->flag_port_role);
                                out.stp_flag_proposal = stp->flag_proposal;
                                out.stp_flag_tc = stp->flag_tc;

                                out.stp_root_priority = stp->root_id.priority;
                                out.stp_root_sys_id_ext = stp->root_id.ext;
                                out.stp_root_mac = format_mac(stp->root_id.mac);
                                out.stp_root_path_cost = stp->root_path_cost;
                                out.stp_bridge_priority = stp->bridge_id.priority;
                                out.stp_bridge_sys_id_ext = stp->bridge_id.ext;
                                out.stp_bridge_mac = format_mac(stp->bridge_id.mac);
                                out.stp_port_id_raw = stp->port_id_raw;
                                out.stp_port_priority = stp->port_id_priority;
                                out.stp_port_number = stp->port_id_number;
                                out.stp_message_age = stp->message_age;
                                out.stp_max_age = stp->max_age;
                                out.stp_hello_time = stp->hello_time;
                                out.stp_forward_delay = stp->forward_delay;

                                out.stp_has_version1 = stp->has_version1;
                                out.stp_version_1_length = stp->version_1_length;

                                if (stp->is_mstp) {
                                    out.stp_is_mstp = true;
                                    out.stp_version_3_length = stp->version_3_length;
                                    out.stp_mst_config_name = stp->mst_config_name;
                                    out.stp_mst_config_revision_level = stp->mst_config_revision_level;
                                    out.stp_mst_config_digest_hex = stp->mst_config_digest_hex;
                                    out.stp_cist_internal_root_path_cost = stp->cist_internal_root_path_cost;
                                    out.stp_cist_bridge_priority = stp->cist_bridge_id.priority;
                                    out.stp_cist_bridge_sys_id_ext = stp->cist_bridge_id.ext;
                                    out.stp_cist_bridge_mac = format_mac(stp->cist_bridge_id.mac);
                                    out.stp_cist_remaining_hops = stp->cist_remaining_hops;

                                    constexpr size_t kMaxStpMstiSummaries = 50;
                                    for (const auto& m : stp->msti_messages) {
                                        if (out.stp_msti_messages.size() >= kMaxStpMstiSummaries) break;
                                        out.stp_msti_messages.push_back(stp_render_msti_summary(m));
                                    }
                                }
                                out.stp_is_alt_msti_format = stp->is_alt_msti_format;
                            }
                            return out;
                        }
                    }

                    // Not STP (or the GARP-destination-MAC / non-STP-DSAP fallback above) -- named
                    // structurally where cheaply possible, never guessed at further.
                    out.protocol = "non-ip";
                    std::ostringstream s;
                    if (is_garp_dst && eth.llc_dsap == LLC_SAP_BPDU && eth.llc_ssap == LLC_SAP_BPDU) {
                        s << "GARP (GVRP/GMRP) -- shares STP's Bridge Group Address DSAP/SSAP "
                             "(0x42/0x42), disambiguated by destination MAC, not decoded";
                    } else if (eth.has_snap && eth.snap_oui == SNAP_OUI_CISCO) {
                        s << "Cisco PVST+ (SNAP-encapsulated, not decoded)";
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
            // DeviceNet (CAN-bus CIP) -- see can_socketcan.hpp/devicenet.hpp. A wholly separate
            // link layer from Ethernet: has_ethernet and has_ip both stay false for every packet
            // reached this way (no MAC addresses, no IP layer at all -- see devicenet.hpp's own
            // comment on DecodedPacket's devicenet_* fields). This returns directly, the same
            // pattern the EtherType-keyed non-IPv4 branches above use, rather than falling through
            // to the IPv4/TCP/UDP parsing below, which has nothing to do here.
            CanSocketcanFrame can = parse_socketcan_frame(frame);
            // NOTE: can.notes (e.g. a truncated-payload note) is NOT copied into out.notes here --
            // try_parse_devicenet's own DeviceNetFrame::notes already forwards every CanSocketcanFrame
            // note verbatim (see devicenet.cpp), and the fallback branch below (not-DeviceNet) adds
            // them itself, so copying here too would duplicate every such note.

            bool want_devicenet = options_.protocol_filter == ProtocolFilter::Auto ||
                                   options_.protocol_filter == ProtocolFilter::DevicenetOnly;
            if (want_devicenet) {
                if (auto dn = try_parse_devicenet(can)) {
                    out.protocol = "devicenet";
                    out.summary = dn->summary;
                    for (const auto& n : dn->notes) out.notes.push_back(n);

                    out.devicenet_can_id = dn->can_id;
                    out.devicenet_group = dn->group;
                    out.devicenet_group_name = dn->group_name;
                    out.devicenet_message_type_name = dn->message_type_name;
                    out.devicenet_has_source_mac_id = dn->has_source_mac_id;
                    out.devicenet_source_mac_id = dn->source_mac_id;
                    out.devicenet_has_group3_header = dn->has_group3_header;
                    out.devicenet_is_fragmented = dn->is_fragmented;
                    out.devicenet_is_xid = dn->is_xid;
                    out.devicenet_dest_mac_id = dn->dest_mac_id;
                    out.devicenet_has_cip_service = dn->has_cip_service;
                    out.devicenet_cip_is_response = dn->cip_is_response;
                    out.devicenet_cip_service = dn->cip_service;
                    out.devicenet_cip_service_name = dn->cip_service_name;
                    out.devicenet_has_dup_mac_id_check = dn->has_dup_mac_id_check;
                    out.devicenet_dup_mac_id_is_response = dn->dup_mac_id_is_response;
                    out.devicenet_dup_mac_id_physical_port_number = dn->dup_mac_id_physical_port_number;
                    out.devicenet_dup_mac_id_vendor_id = dn->dup_mac_id_vendor_id;
                    out.devicenet_dup_mac_id_serial_number = dn->dup_mac_id_serial_number;
                    out.devicenet_fd = dn->fd;
                    out.devicenet_payload_truncated = can.truncated;
                    out.devicenet_payload_hex = to_hex(dn->payload, "");
                    out.devicenet_payload_length = dn->payload.size();
                    return out;
                }
            }

            // Not DeviceNet (EFF/RTR/ERR flag set -- see can_socketcan.hpp/devicenet.hpp) --
            // named structurally, never decoded further.
            for (const auto& n : can.notes) out.notes.push_back(n);
            out.protocol = "non-ip";
            std::ostringstream s;
            s << "CAN frame, id=0x" << std::hex << std::uppercase << can.id << std::dec;
            if (can.eff) s << " [EFF -- extended 29-bit id]";
            if (can.rtr) s << " [RTR -- remote transmission request]";
            if (can.err) s << " [ERR -- error frame]";
            if (!can.eff && !can.rtr && !can.err) {
                s << " (not decoded -- DeviceNet decoding disabled by --protocol)";
            } else {
                s << " (not a valid DeviceNet frame shape)";
            }
            out.summary = s.str();
            return out;
        } else {
            out.protocol = "unsupported-link";
            out.summary = "capture link type " + std::to_string(link_type) +
                           " is not supported in this groundwork release (only Ethernet, raw IP, "
                           "and SocketCAN are)";
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

        if (ip.protocol == IPPROTO_UDP_VALUE) {
            // Unlike TCP, a UDP datagram is already a complete, self-delimited unit, so none of
            // the TCP-segment reassembly machinery below applies here at all.
            UdpDatagram udp = parse_udp(ip.payload);
            out.has_udp = true;
            out.src_port = udp.src_port;
            out.dst_port = udp.dst_port;

            // Tried first, port-independently, same rationale as EtherNet/IP explicit messaging's
            // own TCP dispatch below: try_parse_cip_io's structural check (an exact CPF item
            // type + exact length) is strong enough to run unconditionally in Auto mode -- see its
            // header comment in enip.hpp.
            bool want_enip_io = options_.protocol_filter == ProtocolFilter::Auto ||
                                 options_.protocol_filter == ProtocolFilter::EnipOnly;
            if (want_enip_io) {
                if (auto io = try_parse_cip_io(udp.payload)) {
                    out.protocol = "enip";
                    out.summary = io->summary;
                    out.enip_has_io = true;
                    out.enip_io_connection_id = io->connection_id;
                    out.enip_io_sequence_number = io->sequence_number;
                    out.enip_io_has_data = io->has_io_data;
                    out.enip_io_data_hex = io->io_data_hex;
                    out.enip_io_data_length = io->io_data_length;
                    for (const auto& n : io->notes) out.notes.push_back(n);

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
                if (auto bacnet = try_parse_bacnet(udp.payload)) {
                    out.protocol = "bacnet";
                    out.summary = bacnet->summary;
                    out.bacnet_bvlc_function = bacnet->bvlc_function_name;
                    out.bacnet_has_npdu = bacnet->has_npdu;
                    for (const auto& n : bacnet->notes) out.notes.push_back(n);
                    if (bacnet->has_npdu) {
                        const BacnetNpdu& npdu = bacnet->npdu;
                        out.bacnet_npdu_version = npdu.version;
                        out.bacnet_npdu_is_network_layer_message = npdu.is_network_layer_message;
                        out.bacnet_npdu_expecting_reply = npdu.expecting_reply;
                        out.bacnet_npdu_priority = npdu.priority;
                        out.bacnet_npdu_has_dest = npdu.has_dest;
                        out.bacnet_npdu_dnet = npdu.dnet;
                        out.bacnet_npdu_has_src = npdu.has_src;
                        out.bacnet_npdu_snet = npdu.snet;
                        out.bacnet_npdu_hop_count = npdu.hop_count;
                        if (npdu.is_network_layer_message) {
                            out.bacnet_npdu_message_type = npdu.message_type_name;
                        } else if (npdu.has_apdu) {
                            const BacnetApdu& apdu = npdu.apdu;
                            out.bacnet_has_apdu = true;
                            out.bacnet_apdu_type = apdu.pdu_type_name;
                            out.bacnet_service_name = apdu.service_choice_name;
                            out.bacnet_invoke_id = apdu.invoke_id;
                            out.bacnet_segmented = apdu.segmented;
                            out.bacnet_values = apdu.values;
                        }
                    }

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
                (options_.protocol_filter == ProtocolFilter::Auto && udp.dst_port != IKE_NATT_PORT &&
                 udp.src_port != IKE_NATT_PORT && udp.dst_port != VXLAN_PORT &&
                 udp.src_port != VXLAN_PORT);
            if (want_hartip) {
                if (auto frame = try_parse_hartip(udp.payload)) {
                    out.protocol = "hartip";
                    out.summary = frame->summary;
                    for (const auto& n : frame->notes) out.notes.push_back(n);
                    out.hartip_version = frame->version;
                    out.hartip_message_type = frame->message_type_name;
                    out.hartip_message_id = frame->message_id_name;
                    out.hartip_status = frame->status;
                    out.hartip_transaction_id = frame->transaction_id;
                    out.hartip_msg_length = frame->msg_length;
                    out.hartip_has_session_init = frame->has_session_init;
                    if (frame->has_session_init) {
                        out.hartip_host_type_name = frame->session_init.host_type_name;
                        out.hartip_inactivity_close_timer = frame->session_init.inactivity_close_timer;
                    }
                    out.hartip_has_error = frame->has_error;
                    if (frame->has_error) {
                        out.hartip_error_code = frame->error_code;
                        out.hartip_error_code_name = frame->error_code_name;
                    }
                    out.hartip_has_pass_through = frame->has_pass_through;
                    if (frame->has_pass_through) {
                        const HartIpPassThrough& pt = frame->pass_through;
                        out.hartip_frame_type = pt.frame_type_name;
                        out.hartip_is_response = pt.is_response;
                        out.hartip_is_long_address = pt.is_long_address;
                        if (pt.is_long_address) {
                            out.hartip_address_hex = pt.long_address_hex;
                        } else {
                            std::ostringstream a;
                            a << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                              << static_cast<unsigned>(pt.short_address);
                            out.hartip_address_hex = a.str();
                        }
                        out.hartip_command = pt.command;
                        out.hartip_command_name = pt.command_name;
                        if (pt.is_response) {
                            out.hartip_response_code = pt.response_code;
                            out.hartip_response_is_comm_error = pt.response_is_comm_error;
                            out.hartip_response_code_name = pt.response_code_name;
                            out.hartip_comm_error_flags = pt.comm_error_flags;
                            out.hartip_device_status = pt.device_status;
                            out.hartip_device_status_flags = pt.device_status_flags;
                        }
                        out.hartip_values = pt.values;
                        out.hartip_checksum = pt.checksum;
                        out.hartip_checksum_valid = pt.checksum_valid;
                    }

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
                    if (auto msg = try_parse_rip(udp.payload)) {
                        out.protocol = "rip";
                        fill_rip_fields(out, *msg);
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
                    if (auto msg = try_parse_hsrp(udp.payload)) {
                        out.protocol = "hsrp";
                        fill_hsrp_fields(out, *msg);
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
            // dispatch. UNLIKE every protocol above, a single UDP datagram can carry more than one
            // concatenated FF-HSE PDU back-to-back -- see ffhse.hpp's own "UDP framing" paragraph --
            // so this is its own coalescing while-loop, not a single try_parse_ffhse call.
            bool want_ffhse = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::FfHseOnly;
            if (want_ffhse) {
                if (auto frame = try_parse_ffhse(udp.payload)) {
                    out.protocol = "ffhse";
                    out.summary = frame->summary;

                    auto merge_ffhse = [&](const FfhseFrame& f, bool is_first_message) {
                        for (const auto& n : f.notes) out.notes.push_back(n);
                        if (!is_first_message) return;
                        out.ffhse_version = f.header.version;
                        out.ffhse_options = f.header.options;
                        out.ffhse_protocol_name = f.header.protocol_name;
                        out.ffhse_type_name = f.header.type_name;
                        out.ffhse_confirmed = f.header.confirmed;
                        out.ffhse_service_id = f.header.service_id;
                        out.ffhse_fda_address = f.header.fda_address;
                        out.ffhse_link_id = f.header.link_id;
                        out.ffhse_message_length = f.header.message_length;
                        out.ffhse_has_message_number = f.trailer.has_message_number;
                        out.ffhse_message_number = f.trailer.message_number;
                        out.ffhse_has_invoke_id = f.trailer.has_invoke_id;
                        out.ffhse_invoke_id = f.trailer.invoke_id;
                        out.ffhse_has_time_stamp = f.trailer.has_time_stamp;
                        out.ffhse_time_stamp = f.trailer.time_stamp;
                        out.ffhse_has_extended_control_field = f.trailer.has_extended_control_field;
                        out.ffhse_extended_control_field = f.trailer.extended_control_field;
                        out.ffhse_message_name = f.message_name;
                        out.ffhse_recognized = f.recognized;
                        out.ffhse_body_decoded = f.body_decoded;
                        out.ffhse_values = f.values;
                        out.ffhse_body_shown_as_hex = f.body_shown_as_hex;
                        out.ffhse_body_hex = f.body_hex;
                        out.ffhse_body_length = f.body_length;
                    };
                    merge_ffhse(*frame, /*is_first_message=*/true);

                    constexpr size_t kMaxFfhseMessagesPerDatagram = 50;
                    size_t offset = frame->wire_length;
                    size_t message_count = 1;
                    while (offset < udp.payload.size() && message_count < kMaxFfhseMessagesPerDatagram) {
                        ByteSpan rest = udp.payload.from(offset);
                        auto next = try_parse_ffhse(rest);
                        if (!next) break;  // remaining bytes aren't another FF-HSE PDU -- stop, don't guess
                        ++message_count;
                        std::string note = "additional FF-HSE PDU " + std::to_string(message_count) +
                                            " found in the same UDP datagram at byte offset " + std::to_string(offset) +
                                            ": " + next->summary;
                        out.notes.push_back(note);
                        merge_ffhse(*next, /*is_first_message=*/false);
                        offset += next->wire_length;
                    }
                    if (message_count >= kMaxFfhseMessagesPerDatagram) {
                        out.notes.push_back("stopped after " + std::to_string(kMaxFfhseMessagesPerDatagram) +
                                             " FF-HSE PDU(s) in this one UDP datagram, more may remain (safety cap)");
                    }

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
                    if (auto msg = try_parse_dns_message(udp.payload, DnsFlavor::Dns)) {
                        out.protocol = "dns";
                        fill_dns_fields(out, *msg);
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
                    if (auto msg = try_parse_dns_message(udp.payload, DnsFlavor::Mdns)) {
                        out.protocol = "mdns";
                        fill_dns_fields(out, *msg);
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
                    if (auto msg = try_parse_dns_message(udp.payload, DnsFlavor::Llmnr)) {
                        out.protocol = "llmnr";
                        fill_dns_fields(out, *msg);
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
                    if (auto msg = try_parse_nbns(udp.payload)) {
                        out.protocol = "nbns";
                        fill_nbns_fields(out, *msg);
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
        if (ip.protocol == ICMP_IP_PROTOCOL) {
            bool want_icmp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IcmpOnly;
            if (want_icmp) {
                if (auto msg = try_parse_icmp(ip.payload)) {
                    out.protocol = "icmp";
                    fill_icmp_fields(out, *msg);
                    return out;
                }
            }
        }

        if (ip.protocol == IGMP_IP_PROTOCOL) {
            bool want_igmp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IgmpOnly;
            if (want_igmp) {
                if (auto msg = try_parse_igmp(ip.payload)) {
                    out.protocol = "igmp";
                    fill_igmp_fields(out, *msg);
                    return out;
                }
            }
        }

        if (ip.protocol == VRRP_IP_PROTOCOL) {
            bool want_vrrp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::VrrpOnly;
            if (want_vrrp) {
                if (auto msg = try_parse_vrrp(ip.payload)) {
                    out.protocol = "vrrp";
                    fill_vrrp_fields(out, *msg);
                    return out;
                }
            }
        }

        if (ip.protocol == IGRP_IP_PROTOCOL) {
            bool want_igrp = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::IgrpOnly;
            if (want_igrp) {
                if (auto msg = try_parse_igrp(ip.payload, ip.src_addr)) {
                    out.protocol = "igrp";
                    fill_igrp_fields(out, *msg);
                    return out;
                }
            }
        }

        if (ip.protocol == PIM_IP_PROTOCOL) {
            bool want_pim = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::PimOnly;
            if (want_pim) {
                if (auto msg = try_parse_pim(ip.payload)) {
                    out.protocol = "pim";
                    fill_pim_fields(out, *msg);
                    return out;
                }
            }
        }

        if (ip.protocol == EIGRP_IP_PROTOCOL) {
            bool want_eigrp = options_.protocol_filter == ProtocolFilter::Auto ||
                               options_.protocol_filter == ProtocolFilter::EigrpOnly;
            if (want_eigrp) {
                // Registration-model pilot (Stage 1): try_parse_eigrp is now reached through
                // EigrpDecoder::decode rather than called directly -- same function, same
                // semantics, see eigrp.hpp. fill_eigrp_fields is unchanged.
                DecodeContext ctx;
                ctx.protocol_id = "eigrp";
                if (auto result = eigrp_decoder().decode(ip.payload, ctx)) {
                    out.protocol = "eigrp";
                    fill_eigrp_fields(out, result->as<EigrpMessage>());
                    return out;
                }
            }
        }

        if (ip.protocol == OSPF_IP_PROTOCOL) {
            bool want_ospf = options_.protocol_filter == ProtocolFilter::Auto ||
                              options_.protocol_filter == ProtocolFilter::OspfOnly;
            if (want_ospf) {
                if (auto msg = try_parse_ospf(ip.payload)) {
                    out.protocol = "ospf";
                    fill_ospf_fields(out, *msg);
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
        if (ip.protocol == GRE_IP_PROTOCOL || ip.protocol == ESP_IP_PROTOCOL ||
            ip.protocol == AH_IP_PROTOCOL || ip.protocol == IPIP_IP_PROTOCOL ||
            ip.protocol == IPV6_6IN4_IP_PROTOCOL || ip.protocol == L2TPV3_IP_PROTOCOL) {
            bool want_tunnel_vpn = options_.protocol_filter == ProtocolFilter::Auto ||
                                    options_.protocol_filter == ProtocolFilter::TunnelVpnOnly;
            if (want_tunnel_vpn) {
                if (auto m = try_recognize_tunnel_vpn_ip_proto(ip.payload, ip.protocol)) {
                    out.protocol = m->protocol;
                    out.summary = m->summary;
                    for (const auto& n : m->notes) out.notes.push_back(n);
                    return out;
                }
            }
        }

        if (ip.protocol != IPPROTO_TCP_VALUE) {
            out.protocol = "non-tcp";
            std::ostringstream s;
            s << "IPv4 protocol number " << static_cast<unsigned>(ip.protocol);
            std::string name = ip_protocol_name(ip.protocol);
            if (!name.empty()) s << " (" << name << ")";
            s << " (not TCP)";
            out.summary = s.str();
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

        // DNS-over-HTTPS detection -- deliberately checked against tcp.payload directly, a SINGLE
        // TCP segment, never effective_payload's cross-segment reassembly below: this is
        // detection-only (see tls_sni.hpp's file header comment for why the DNS message itself
        // can never be decoded here), and a ClientHello split across segments simply isn't
        // detected rather than needing its own reassembly machinery for a feature this narrow.
        // Port-gated in Auto mode, same rationale and same exception for an explicit --protocol
        // doh as DNS/mDNS/LLMNR/NBT-NS above -- see tls_sni.hpp's own "Detection" paragraph.
        bool want_doh = options_.protocol_filter == ProtocolFilter::Auto ||
                         options_.protocol_filter == ProtocolFilter::DohOnly;
        bool require_doh_port = options_.protocol_filter == ProtocolFilter::Auto;
        if (want_doh) {
            bool port_match = port_in(tcp.src_port, DOH_PORT, options_.extra_doh_ports) ||
                               port_in(tcp.dst_port, DOH_PORT, options_.extra_doh_ports);
            if (!require_doh_port || port_match) {
                if (auto doh = try_detect_doh(tcp.payload)) {
                    out.protocol = "doh";
                    out.summary = doh->summary;
                    out.doh_sni = doh->sni;
                    out.doh_matched_provider = doh->matched_provider;
                    out.doh_alpn_protocols = doh->alpn_protocols;
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
        bool want_enip = options_.protocol_filter == ProtocolFilter::Auto ||
                          options_.protocol_filter == ProtocolFilter::EnipOnly;
        bool want_modbus = options_.protocol_filter == ProtocolFilter::Auto ||
                            options_.protocol_filter == ProtocolFilter::ModbusOnly;
        bool want_twincat = options_.protocol_filter == ProtocolFilter::Auto ||
                             options_.protocol_filter == ProtocolFilter::TwinCatOnly;
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

        // Tried first of all -- see the matching, fuller comment in reassemble_tcp_payload above
        // for why OPC UA's own magic-string detection gate is strong enough, and non-colliding
        // enough with every other protocol below, that trying it first costs nothing.
        if (want_opcua) {
            if (auto msg = try_parse_opcua_message(effective_payload)) {
                out.protocol = "opcua";
                out.summary = msg->summary;

                auto merge_opcua = [&](const OpcUaMessage& m, bool is_first_message) {
                    for (const auto& n : m.notes) out.notes.push_back(n);
                    if (!is_first_message) return;
                    out.opcua_message_type = m.message_type;
                    out.opcua_chunk_type = m.chunk_type;
                    out.opcua_message_size = m.message_size;
                    out.opcua_has_secure_channel = m.has_secure_channel;
                    if (m.has_secure_channel) {
                        out.opcua_secure_channel_id = m.secure_channel_id;
                        out.opcua_is_asymmetric = m.is_asymmetric;
                        if (m.is_asymmetric) {
                            out.opcua_security_policy_uri = m.security_policy_uri;
                            out.opcua_has_sender_certificate = m.has_sender_certificate;
                            out.opcua_sender_certificate_length = m.sender_certificate_length;
                            out.opcua_has_receiver_certificate_thumbprint =
                                m.has_receiver_certificate_thumbprint;
                        } else {
                            out.opcua_token_id = m.token_id;
                        }
                        out.opcua_sequence_number = m.sequence_number;
                        out.opcua_request_id = m.request_id;
                    }
                    out.opcua_service_recognized = m.service_recognized;
                    out.opcua_service_name = m.service_name;
                    out.opcua_service_namespace = m.service_namespace;
                    out.opcua_service_type_id = m.service_type_id;
                    out.opcua_service_body_decoded = m.service_body_decoded;
                    out.opcua_has_header = m.has_header;
                    if (m.has_header) {
                        out.opcua_request_handle = m.header.request_handle;
                        out.opcua_is_response = m.header.is_response;
                        out.opcua_status_code = m.header.status_code;
                        out.opcua_status_code_name = m.header.status_code_name;
                        out.opcua_status_is_good = m.header.status_is_good;
                    }
                    out.opcua_values = m.values;
                    out.opcua_body_shown_as_hex = m.body_shown_as_hex;
                    if (m.body_shown_as_hex) {
                        out.opcua_body_hex = m.body_hex;
                        out.opcua_body_length = m.body_length;
                    }
                };
                merge_opcua(*msg, /*is_first_message=*/true);

                // Like EtherNet/IP/HART-IP's own small messages, it's normal for a sender or the
                // OS to coalesce several OPC UA chunks into one TCP segment before flushing.
                constexpr size_t kMaxOpcUaMessagesPerPayload = 50;
                size_t offset = msg->wire_length;
                size_t message_count = 1;
                while (offset < effective_payload.size() && message_count < kMaxOpcUaMessagesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_opcua_message(rest);
                    if (!next) break;  // remaining bytes aren't another OPC UA message -- stop, don't guess
                    ++message_count;
                    std::string note = "additional OPC UA message " + std::to_string(message_count) +
                                        " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                        " (coalesced by the sender/OS): " + next->summary;
                    out.notes.push_back(note);
                    merge_opcua(*next, /*is_first_message=*/false);
                    offset += next->wire_length;
                }
                if (message_count >= kMaxOpcUaMessagesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxOpcUaMessagesPerPayload) +
                                         " OPC UA message(s) in this one TCP payload, more may remain "
                                         "(safety cap)");
                }

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
            if (auto frame = try_parse_enip(effective_payload)) {
                out.protocol = "enip";
                out.summary = frame->summary;
                out.enip_command_name = frame->header.command_name;
                for (const auto& n : frame->notes) out.notes.push_back(n);

                constexpr size_t kMaxCipValues = 50;
                auto merge_cip = [&](const EnipFrame& f, bool is_first_message) {
                    if (!f.has_cip) return;
                    if (is_first_message) {
                        out.enip_has_cip = true;
                        out.enip_cip_is_response = f.cip.is_response;
                        out.enip_cip_service_name = f.cip.service_name;
                        out.enip_cip_path = f.cip.path.summary;
                        out.enip_cip_status_name = f.cip.status_name;
                    }
                    for (const auto& n : f.cip.notes) out.notes.push_back(n);
                    for (const auto& v : f.cip.values) {
                        if (out.enip_cip_values.size() >= kMaxCipValues) break;
                        out.enip_cip_values.push_back(v);
                    }
                };
                merge_cip(*frame, /*is_first_message=*/true);

                // Like IEC104/DNP3, one encapsulation message is small and it's normal for a
                // sender or the OS to coalesce several into one TCP segment before flushing.
                constexpr size_t kMaxEnipMessagesPerPayload = 50;
                size_t offset = frame->wire_length;
                size_t message_count = 1;
                while (offset < effective_payload.size() && message_count < kMaxEnipMessagesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_enip(rest);
                    if (!next) break;  // remaining bytes aren't another EtherNet/IP message -- stop, don't guess
                    ++message_count;
                    std::string note = "additional EtherNet/IP message " + std::to_string(message_count) +
                                        " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                        " (coalesced by the sender/OS): " + next->summary;
                    out.notes.push_back(note);
                    merge_cip(*next, /*is_first_message=*/false);
                    offset += next->wire_length;
                }
                if (message_count >= kMaxEnipMessagesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxEnipMessagesPerPayload) +
                                         " EtherNet/IP message(s) in this one TCP payload, more may remain "
                                         "(safety cap)");
                }

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
            if (auto apci = try_parse_iec104_apci(effective_payload)) {
                out.protocol = "iec104";
                out.summary = apci->summary;

                constexpr size_t kMaxObjectValues = 50;
                auto merge_asdu = [&](const Iec104Asdu& asdu, bool is_first_apdu) {
                    if (is_first_apdu) {
                        out.summary += "; " + asdu.summary;
                        out.iec104_has_asdu = true;
                        out.iec104_asdu_type_name = asdu.type_name;
                        out.iec104_asdu_type_short_name = asdu.type_short_name;
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
            // Registration-model pilot (Stage 2): try_parse_modbus_tcp + the transaction-pairing
            // logic that used to be Decoder::pair_modbus_transaction are now both reached through
            // ModbusDecoder::decode -- same functions, same semantics, see modbus.hpp/modbus.cpp.
            // The dual-write below (mb.* -> out.modbus_*) is unchanged.
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
                out.modbus_is_exception = mb.is_exception;
                out.modbus_function_name = mb.function_name;
                out.summary = mb.function_name + ": " + mb.summary;
                for (const auto& n : mb.notes) out.notes.push_back(n);
                out.modbus_is_paired_response = mb.paired_response;
                out.modbus_paired_request_index = mb.paired_request_index;

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

        if (want_dnp3) {
            if (auto d = try_parse_dnp3_link_layer(effective_payload, out.notes)) {
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
                // Read AFTER process_dnp3_frame: that call (when it runs -- it doesn't for a
                // link-layer-only control frame with no user data, see its own doc comment) is
                // what finalizes block_count/block_crc_failures/crc_validated on top of the header
                // result try_parse_dnp3_link_layer already set -- see Dnp3LinkFrame's own comment
                // in dnp3.hpp for why. Either way, by this point d's crc fields are final.
                out.dnp3_link_crc_valid = d->crc_validated;
                out.dnp3_header_crc_valid = d->header_crc_valid;
                out.dnp3_block_count = d->block_count;
                out.dnp3_block_crc_failures = d->block_crc_failures;
                out.dnp3_source_address = d->source;
                out.dnp3_destination_address = d->destination;

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
                    auto next = try_parse_dnp3_link_layer(rest, out.notes);
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
                    if (want_s7comm) {
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
                            out.s7comm_plc_stop_message = s7->plc_stop_message;
                            out.s7comm_has_pi_service = s7->has_pi_service;
                            out.s7comm_pi_service_name = s7->pi_service_name;
                            out.s7comm_pi_service_description = s7->pi_service_description;
                            out.s7comm_pi_control_argument = s7->pi_control_argument;
                            for (size_t i = 0; i < s7->pi_control_blocks.size() && i < kMaxTags; ++i) {
                                out.s7comm_pi_control_blocks.push_back(s7->pi_control_blocks[i]);
                            }
                            out.s7comm_has_pi_control_status = s7->has_pi_control_status;
                            out.s7comm_pi_control_has_more_data = s7->pi_control_has_more_data;
                            out.s7comm_pi_control_has_error = s7->pi_control_has_error;
                            for (const auto& n : cotp->notes) out.notes.push_back(n);
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
                        if (auto s7p = try_parse_s7comm_plus(s7_candidate)) {
                            out.protocol = "s7comm-plus";
                            out.summary = s7p->summary;
                            for (const auto& n : s7p->notes) out.notes.push_back(n);
                            out.s7plus_pdu_type_name = s7p->pdu_type_name;
                            out.s7plus_is_keepalive = s7p->is_keepalive;
                            out.s7plus_keepalive_seq = s7p->keepalive_seq;
                            out.s7plus_has_opcode = s7p->has_data_part && !s7p->is_notification &&
                                                     !s7p->opcode_name.empty();
                            out.s7plus_opcode_name = s7p->opcode_name;
                            out.s7plus_has_function = s7p->has_function;
                            out.s7plus_function_code = s7p->function_code;
                            out.s7plus_function_name = s7p->function_name;
                            out.s7plus_has_sequence_number = s7p->has_sequence_number;
                            out.s7plus_sequence_number = s7p->sequence_number;
                            out.s7plus_has_session_id = s7p->has_session_id;
                            out.s7plus_session_id = s7p->session_id;
                            out.s7plus_body_decoded = s7p->body_decoded;
                            out.s7plus_has_return_value = s7p->has_return_value;
                            out.s7plus_return_code = s7p->return_code;
                            out.s7plus_return_code_name = s7p->return_code_name;
                            constexpr size_t kMaxTags = 50;
                            for (size_t i = 0; i < s7p->item_addresses.size() && i < kMaxTags; ++i) {
                                out.s7plus_item_tags.push_back(s7p->item_addresses[i].tag);
                            }
                            for (size_t i = 0; i < s7p->id_values.size() && i < kMaxTags; ++i) {
                                out.s7plus_value_summaries.push_back(s7p->id_values[i].rendered);
                            }
                            for (size_t i = 0; i < s7p->item_errors.size() && i < kMaxTags; ++i) {
                                out.s7plus_item_errors.push_back(s7p->item_errors[i].rendered);
                            }
                            out.s7plus_has_integrity = s7p->has_integrity;
                            out.s7plus_integrity_digest_present = s7p->integrity_digest_present;
                            out.s7plus_integrity_digest_length = s7p->integrity_digest_length;
                            out.s7plus_has_trailer = s7p->has_trailer;
                            for (const auto& n : cotp->notes) out.notes.push_back(n);
                            annotate_port();
                            return out;
                        }
                    }

                    // MMS shares this exact TCP port 102 / TPKT+COTP transport with S7comm -- see
                    // mms.hpp's own file-header comment on dispatch ordering. S7comm's single-byte
                    // protocol-id gate is tried first (above) since it is materially stronger and
                    // cheaper; this is only reached once that has already failed.
                    if (want_mms) {
                        if (auto mms = try_parse_mms(s7_candidate)) {
                            out.protocol = "mms";
                            out.summary = mms->summary;
                            for (const auto& n : mms->notes) out.notes.push_back(n);
                            out.mms_is_bare = mms->is_bare;
                            out.mms_session_spdu_type = mms->session_spdu_type;
                            out.mms_session_pdu_name = mms->session_pdu_name;
                            out.mms_has_presentation = mms->has_presentation;
                            out.mms_presentation_context_list = mms->presentation_context_list;
                            out.mms_presentation_context_id = mms->presentation_context_id;
                            out.mms_presentation_context_is_acse = mms->presentation_context_is_acse;
                            out.mms_has_acse = mms->has_acse;
                            out.mms_acse_pdu_name = mms->acse_pdu_name;
                            out.mms_acse_application_context_name = mms->acse_application_context_name;
                            out.mms_acse_has_result = mms->acse_has_result;
                            out.mms_acse_result_name = mms->acse_result_name;
                            out.mms_acse_values = mms->acse_values;
                            out.mms_has_pdu = mms->has_pdu;
                            out.mms_pdu_name = mms->pdu_name;
                            out.mms_has_invoke_id = mms->has_invoke_id;
                            out.mms_invoke_id = mms->invoke_id;
                            out.mms_service_recognized = mms->service_recognized;
                            out.mms_service_name = mms->service_name;
                            out.mms_service_body_decoded = mms->service_body_decoded;
                            out.mms_is_response = mms->is_response;
                            out.mms_has_error = mms->has_error;
                            out.mms_error_name = mms->error_name;
                            constexpr size_t kMaxMmsValues = 50;
                            for (size_t i = 0; i < mms->values.size() && i < kMaxMmsValues; ++i) {
                                out.mms_values.push_back(mms->values[i]);
                            }
                            out.mms_body_shown_as_hex = mms->body_shown_as_hex;
                            out.mms_body_hex = mms->body_hex;
                            out.mms_body_length = mms->body_length;
                            for (const auto& n : cotp->notes) out.notes.push_back(n);
                            annotate_port();
                            return out;
                        }
                    }
                }

                out.protocol = "cotp";
                out.summary = cotp->summary;
                for (const auto& n : cotp->notes) out.notes.push_back(n);
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
            if (auto frame = try_parse_hartip(effective_payload)) {
                out.protocol = "hartip";
                out.summary = frame->summary;

                auto merge_hartip = [&](const HartIpFrame& f, bool is_first_message) {
                    for (const auto& n : f.notes) out.notes.push_back(n);
                    if (!is_first_message) return;
                    out.hartip_version = f.version;
                    out.hartip_message_type = f.message_type_name;
                    out.hartip_message_id = f.message_id_name;
                    out.hartip_status = f.status;
                    out.hartip_transaction_id = f.transaction_id;
                    out.hartip_msg_length = f.msg_length;
                    out.hartip_has_session_init = f.has_session_init;
                    if (f.has_session_init) {
                        out.hartip_host_type_name = f.session_init.host_type_name;
                        out.hartip_inactivity_close_timer = f.session_init.inactivity_close_timer;
                    }
                    out.hartip_has_error = f.has_error;
                    if (f.has_error) {
                        out.hartip_error_code = f.error_code;
                        out.hartip_error_code_name = f.error_code_name;
                    }
                    out.hartip_has_pass_through = f.has_pass_through;
                    if (f.has_pass_through) {
                        const HartIpPassThrough& pt = f.pass_through;
                        out.hartip_frame_type = pt.frame_type_name;
                        out.hartip_is_response = pt.is_response;
                        out.hartip_is_long_address = pt.is_long_address;
                        if (pt.is_long_address) {
                            out.hartip_address_hex = pt.long_address_hex;
                        } else {
                            std::ostringstream a;
                            a << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
                              << static_cast<unsigned>(pt.short_address);
                            out.hartip_address_hex = a.str();
                        }
                        out.hartip_command = pt.command;
                        out.hartip_command_name = pt.command_name;
                        if (pt.is_response) {
                            out.hartip_response_code = pt.response_code;
                            out.hartip_response_is_comm_error = pt.response_is_comm_error;
                            out.hartip_response_code_name = pt.response_code_name;
                            out.hartip_comm_error_flags = pt.comm_error_flags;
                            out.hartip_device_status = pt.device_status;
                            out.hartip_device_status_flags = pt.device_status_flags;
                        }
                        out.hartip_values = pt.values;
                        out.hartip_checksum = pt.checksum;
                        out.hartip_checksum_valid = pt.checksum_valid;
                    }
                };
                merge_hartip(*frame, /*is_first_message=*/true);

                // Like EtherNet/IP's own encapsulation messages, one HART-IP message is small and
                // it's normal for a sender or the OS to coalesce several into one TCP segment.
                constexpr size_t kMaxHartIpMessagesPerPayload = 50;
                size_t offset = frame->wire_length;
                size_t message_count = 1;
                while (offset < effective_payload.size() && message_count < kMaxHartIpMessagesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_hartip(rest);
                    if (!next) break;  // remaining bytes aren't another HART-IP message -- stop, don't guess
                    ++message_count;
                    std::string note = "additional HART-IP message " + std::to_string(message_count) +
                                        " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                        " (coalesced by the sender/OS): " + next->summary;
                    out.notes.push_back(note);
                    merge_hartip(*next, /*is_first_message=*/false);
                    offset += next->wire_length;
                }
                if (message_count >= kMaxHartIpMessagesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxHartIpMessagesPerPayload) +
                                         " HART-IP message(s) in this one TCP payload, more may remain "
                                         "(safety cap)");
                }

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
            std::string mqtt_session_key = tcp_session_key(out.src_ip, tcp.src_port, out.dst_ip, tcp.dst_port);
            auto session_it = mqtt_session_version_.find(mqtt_session_key);
            uint8_t session_hint = session_it != mqtt_session_version_.end() ? session_it->second : 0;

            if (auto first = try_parse_mqtt_message(effective_payload, session_hint)) {
                out.protocol = "mqtt";
                out.summary = first->summary;

                auto merge_mqtt = [&](const MqttMessage& m, bool is_first_message) {
                    for (const auto& n : m.notes) out.notes.push_back(n);
                    if (!is_first_message) return;
                    out.mqtt_packet_type_name = m.packet_type_name;
                    out.mqtt_remaining_length = m.remaining_length;
                    out.mqtt_dup = m.dup;
                    out.mqtt_retain = m.retain;
                    out.mqtt_qos = m.qos;
                    out.mqtt_has_packet_id = m.has_packet_id;
                    out.mqtt_packet_id = m.packet_id;
                    out.mqtt_topic = m.topic;
                    out.mqtt_has_payload = m.has_payload;
                    out.mqtt_payload_length = m.payload_length;
                    out.mqtt_payload_hex = m.payload_hex;
                    out.mqtt_protocol_version_name = m.protocol_version_name;
                    out.mqtt_values = m.values;
                    out.mqtt_is_sparkplug = m.is_sparkplug;
                    if (m.is_sparkplug) {
                        out.mqtt_sparkplug_group_id = m.sparkplug_group_id;
                        out.mqtt_sparkplug_message_type = m.sparkplug_message_type;
                        out.mqtt_sparkplug_edge_node_id = m.sparkplug_edge_node_id;
                        out.mqtt_sparkplug_device_id = m.sparkplug_device_id;
                        out.mqtt_sparkplug_is_state = m.sparkplug_is_state;
                        if (m.sparkplug_is_state) {
                            out.mqtt_sparkplug_state_host_id = m.sparkplug_state_host_id;
                            out.mqtt_sparkplug_state_text = m.sparkplug_state_text;
                        } else {
                            out.mqtt_sparkplug_payload_decoded = m.sparkplug_payload.parse_ok;
                            out.mqtt_sparkplug_has_timestamp = m.sparkplug_payload.has_timestamp;
                            out.mqtt_sparkplug_timestamp = m.sparkplug_payload.timestamp;
                            out.mqtt_sparkplug_has_seq = m.sparkplug_payload.has_seq;
                            out.mqtt_sparkplug_seq = m.sparkplug_payload.seq;
                            out.mqtt_sparkplug_has_uuid = m.sparkplug_payload.has_uuid;
                            out.mqtt_sparkplug_uuid = m.sparkplug_payload.uuid;
                            out.mqtt_sparkplug_has_body = m.sparkplug_payload.has_body;
                            out.mqtt_sparkplug_body_length = m.sparkplug_payload.body_length;
                            out.mqtt_sparkplug_metric_count = m.sparkplug_payload.metric_count;
                            out.mqtt_sparkplug_metrics = m.sparkplug_payload.metrics;
                        }
                    }
                };
                merge_mqtt(*first, /*is_first_message=*/true);

                // A CONNECT anywhere in this payload updates this session's tracked version for
                // every later packet on it (including any further coalesced packets in this very
                // same TCP payload, handled via `running_hint` below) -- see mqtt.hpp's "Version
                // disambiguation" section and mqtt_session_version_'s own declaration in
                // decoder.hpp.
                uint8_t running_hint = session_hint;
                auto maybe_learn_version = [&](const MqttMessage& m) {
                    if (m.packet_type != 1) return;
                    if (m.connect_discovered_version == 5) {
                        running_hint = 5;
                        mqtt_session_version_[mqtt_session_key] = running_hint;
                    } else if (m.connect_discovered_version == 4 || m.connect_discovered_version == 3) {
                        // Level 3 is the pre-OASIS "MQTT 3.1" CONNECT (ProtocolName "MQIsdp") --
                        // seen in real traffic (e.g. older Paho clients). Its SUBSCRIBE/SUBACK/
                        // UNSUBSCRIBE/PUBLISH wire shapes are identical to 3.1.1's (no unconditional
                        // Properties section), so it's tracked under the same "4" hint value rather
                        // than left to fall back on the weaker per-packet heuristic.
                        running_hint = 4;
                        mqtt_session_version_[mqtt_session_key] = running_hint;
                    }
                };
                maybe_learn_version(*first);

                // Small control packets (PINGREQ/PUBACK/SUBACK/...) are common and it's normal for
                // a sender or the OS to coalesce several into one TCP segment before flushing, the
                // same pattern as every other small-message protocol in this codebase.
                constexpr size_t kMaxMqttMessagesPerPayload = 50;
                size_t offset = first->wire_length;
                size_t message_count = 1;
                while (offset < effective_payload.size() && message_count < kMaxMqttMessagesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_mqtt_message(rest, running_hint);
                    if (!next) break;  // remaining bytes aren't another MQTT packet -- stop, don't guess
                    ++message_count;
                    std::string note = "additional MQTT packet " + std::to_string(message_count) +
                                        " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                        " (coalesced by the sender/OS): " + next->summary;
                    out.notes.push_back(note);
                    merge_mqtt(*next, /*is_first_message=*/false);
                    maybe_learn_version(*next);
                    offset += next->wire_length;
                }
                if (message_count >= kMaxMqttMessagesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxMqttMessagesPerPayload) +
                                         " MQTT packet(s) in this one TCP payload, more may remain (safety cap)");
                }

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

        // Tried LAST of all, even after MQTT -- see the matching, fuller comment in
        // reassemble_tcp_payload above for why FF-HSE's own structural detection gate is
        // deliberately given the lowest priority in this opportunistic, port-independent dispatch
        // chain.
        if (want_ffhse) {
            if (auto frame = try_parse_ffhse(effective_payload)) {
                out.protocol = "ffhse";
                out.summary = frame->summary;

                auto merge_ffhse = [&](const FfhseFrame& f, bool is_first_message) {
                    for (const auto& n : f.notes) out.notes.push_back(n);
                    if (!is_first_message) return;
                    out.ffhse_version = f.header.version;
                    out.ffhse_options = f.header.options;
                    out.ffhse_protocol_name = f.header.protocol_name;
                    out.ffhse_type_name = f.header.type_name;
                    out.ffhse_confirmed = f.header.confirmed;
                    out.ffhse_service_id = f.header.service_id;
                    out.ffhse_fda_address = f.header.fda_address;
                    out.ffhse_link_id = f.header.link_id;
                    out.ffhse_message_length = f.header.message_length;
                    out.ffhse_has_message_number = f.trailer.has_message_number;
                    out.ffhse_message_number = f.trailer.message_number;
                    out.ffhse_has_invoke_id = f.trailer.has_invoke_id;
                    out.ffhse_invoke_id = f.trailer.invoke_id;
                    out.ffhse_has_time_stamp = f.trailer.has_time_stamp;
                    out.ffhse_time_stamp = f.trailer.time_stamp;
                    out.ffhse_has_extended_control_field = f.trailer.has_extended_control_field;
                    out.ffhse_extended_control_field = f.trailer.extended_control_field;
                    out.ffhse_message_name = f.message_name;
                    out.ffhse_recognized = f.recognized;
                    out.ffhse_body_decoded = f.body_decoded;
                    out.ffhse_values = f.values;
                    out.ffhse_body_shown_as_hex = f.body_shown_as_hex;
                    out.ffhse_body_hex = f.body_hex;
                    out.ffhse_body_length = f.body_length;
                };
                merge_ffhse(*frame, /*is_first_message=*/true);

                // Like HART-IP/EtherNet/IP's own small messages, it's normal for a sender or the OS
                // to coalesce several FF-HSE PDUs into one TCP segment before flushing.
                constexpr size_t kMaxFfhseMessagesPerPayload = 50;
                size_t offset = frame->wire_length;
                size_t message_count = 1;
                while (offset < effective_payload.size() && message_count < kMaxFfhseMessagesPerPayload) {
                    ByteSpan rest = effective_payload.from(offset);
                    auto next = try_parse_ffhse(rest);
                    if (!next) break;  // remaining bytes aren't another FF-HSE PDU -- stop, don't guess
                    ++message_count;
                    std::string note = "additional FF-HSE PDU " + std::to_string(message_count) +
                                        " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                        " (coalesced by the sender/OS): " + next->summary;
                    out.notes.push_back(note);
                    merge_ffhse(*next, /*is_first_message=*/false);
                    offset += next->wire_length;
                }
                if (message_count >= kMaxFfhseMessagesPerPayload) {
                    out.notes.push_back("stopped after " + std::to_string(kMaxFfhseMessagesPerPayload) +
                                         " FF-HSE PDU(s) in this one TCP payload, more may remain (safety cap)");
                }

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
