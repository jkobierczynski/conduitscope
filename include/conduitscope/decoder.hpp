// SPDX-License-Identifier: Apache-2.0
// decoder.hpp - orchestrates link/IPv4/TCP parsing and protocol dispatch
// (Modbus/DNP3) for a single captured packet, producing one DecodedPacket
// that every output writer (text/json/csv) renders from.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/byteio.hpp"
#include "conduitscope/can_socketcan.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/devicenet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/dns.hpp"
#include "conduitscope/eapol.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/eigrp.hpp"
#include "conduitscope/ethercat.hpp"
#include "conduitscope/ffhse.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/hsrp.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/igmp.hpp"
#include "conduitscope/igrp.hpp"
#include "conduitscope/it_protocols.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/mpls.hpp"
#include "conduitscope/mqtt.hpp"
#include "conduitscope/nbns.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/ospf.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/pim.hpp"
#include "conduitscope/pppoe.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7commplus.hpp"
#include "conduitscope/stp.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tcp.hpp"
#include "conduitscope/tls_sni.hpp"
#include "conduitscope/tunnel_vpn.hpp"
#include "conduitscope/vrrp.hpp"

namespace conduitscope {

enum class ProtocolFilter {
    Auto,         // opportunistically detect IEC104/Modbus/DNP3/S7comm/EtherNet-IP/PROFINET/GOOSE/SV/EtherCAT/STP/BACnet-IP/HART-IP/OPC-UA regardless of port
    ModbusOnly,   // only attempt Modbus decoding
    Dnp3Only,     // only attempt DNP3 decoding
    S7commOnly,   // only attempt TPKT/COTP/S7comm decoding
    Iec104Only,   // only attempt IEC 60870-5-104 decoding
    EnipOnly,     // only attempt EtherNet/IP (CIP explicit messaging) decoding
    ProfinetOnly, // only attempt PROFINET RT (DCP + cyclic IO data) decoding
    GooseOnly,    // only attempt IEC 61850-8-1 GOOSE decoding
    SvOnly,       // only attempt IEC 61850-9-2 Sampled Values decoding
    EthercatOnly, // only attempt EtherCAT decoding
    StpOnly,      // only attempt STP/RSTP/MSTP (classic IEEE 802.3 LLC BPDU) decoding
    DevicenetOnly, // only attempt DeviceNet (CAN-bus CIP) decoding -- meaningful only on a
                    // LINKTYPE_CAN_SOCKETCAN capture, see can_socketcan.hpp/devicenet.hpp
    BacnetOnly,   // only attempt BACnet/IP (BVLC/NPDU/APDU) decoding
    HartIpOnly,   // only attempt HART-IP (session control / tunneled Pass-Through) decoding
    OpcUaOnly,    // only attempt OPC UA (UA-TCP / Secure Conversation) decoding
    MmsOnly,      // only attempt TPKT/COTP/IEC 61850 MMS decoding
    MqttOnly,     // only attempt MQTT (v3.1.1/v5.0) / Sparkplug B decoding
    S7commPlusOnly,  // only attempt TPKT/COTP/S7comm-Plus decoding
    FfHseOnly,    // only attempt FOUNDATION Fieldbus HSE (FDA/SM/FMS/LAN Redundancy) decoding
    DnsOnly,      // only attempt classic DNS (UDP port 53) decoding
    MdnsOnly,     // only attempt Multicast DNS decoding
    LlmnrOnly,    // only attempt LLMNR decoding
    NbnsOnly,     // only attempt NetBIOS Name Service (NBT-NS) decoding
    DohOnly,      // only attempt DNS-over-HTTPS detection (TLS ClientHello SNI only -- see tls_sni.hpp)
    RipOnly,      // only attempt RIP v1/v2 decoding
    IgmpOnly,     // only attempt IGMP v1/v2/v3 decoding
    VrrpOnly,     // only attempt VRRP v2/v3 decoding
    HsrpOnly,     // only attempt HSRP v1/v2 decoding
    IgrpOnly,     // only attempt Cisco IGRP decoding
    PimOnly,      // only attempt PIMv2 decoding
    EigrpOnly,    // only attempt Cisco EIGRP decoding
    OspfOnly,     // only attempt OSPFv2 decoding
    RemoteAccessOnly,  // only attempt the Tier 1 "IT protocols an OT auditor flags" recognition
                        // (RDP/VNC/TeamViewer/AnyDesk/Zoom) -- see it_protocols.hpp. One filter
                        // value covers all five, the same "one feature toggle, several sub-
                        // protocols sharing it" convention FfHseOnly already established.
    LateralMovementOnly,  // only attempt the Tier 2 "IT protocols an OT auditor flags" recognition
                           // (SMB/SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP) -- see it_protocols.hpp.
                           // One filter value covers all eight, the same grouping RemoteAccessOnly
                           // above already established for Tier 1.
    EnterpriseTrustOnly,   // only attempt the Tier 3 "IT protocols an OT auditor flags" recognition
                           // (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+) -- see it_protocols.hpp. One
                           // filter value covers all six port-based protocols, the same grouping
                           // RemoteAccessOnly/LateralMovementOnly above already established for
                           // Tiers 1-2. EAPOL (also Tier 3, but EtherType-keyed, no port at all --
                           // see eapol.hpp) is NOT covered by this filter value; it has its own
                           // EapolOnly below, the same split GOOSE/SV/EtherCAT/PROFINET's own
                           // EtherType-keyed filters already have from every port-based one.
    EapolOnly,             // only attempt IEEE 802.1X/EAPOL decoding -- see eapol.hpp
    WirelessBackhaulOnly,  // only attempt the Tier 4 "IT protocols an OT auditor flags" recognition
                           // (CAPWAP control/data, LWAPP control/data, GTP-U) -- see it_protocols.hpp.
                           // One filter value covers all five port-based protocols, the same grouping
                           // RemoteAccessOnly/LateralMovementOnly/EnterpriseTrustOnly above already
                           // established for Tiers 1-3. PPPoE (also Tier 4, but EtherType-keyed, no
                           // port at all -- see pppoe.hpp) is NOT covered by this filter value; it
                           // has its own PppoeOnly below, the same split EapolOnly above already has
                           // from EnterpriseTrustOnly.
    PppoeOnly,             // only attempt PPPoE decoding -- see pppoe.hpp
    TunnelVpnOnly,         // only attempt the Tier 5 "IT protocols an OT auditor flags" recognition
                           // (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve,
                           // WireGuard, OpenVPN, dtls-tunnel, STT -- see tunnel_vpn.hpp). One filter
                           // value covers all fourteen IP-protocol-number/port-based protocols, the
                           // same grouping RemoteAccessOnly/LateralMovementOnly/EnterpriseTrustOnly/
                           // WirelessBackhaulOnly above already established for Tiers 1-4. MPLS (also
                           // Tier 5, but EtherType-keyed, no port or IP layer at all -- see mpls.hpp)
                           // is NOT covered by this filter value; it has its own MplsOnly below, the
                           // same split EapolOnly/PppoeOnly above already have from their own port-
                           // based tiers.
    MplsOnly,              // only attempt MPLS label-stack decoding -- see mpls.hpp
};

struct DecodeOptions {
    ProtocolFilter protocol_filter = ProtocolFilter::Auto;
    // Additional ports to treat as "expected" for each protocol, beyond the
    // IANA-registered defaults (502 for Modbus, 20000 for DNP3, 2404 for
    // IEC 104, 44818 for EtherNet/IP explicit messaging, 2222 for EtherNet/IP
    // CIP I/O implicit messaging). This does NOT gate detection in Auto
    // mode (detection is payload-shape based) -- it only changes whether the
    // decoded output calls a port "standard" or flags it as unexpected,
    // which is itself a useful signal when auditing a conduit against a
    // zone policy.
    std::vector<uint16_t> extra_modbus_ports;
    std::vector<uint16_t> extra_dnp3_ports;
    std::vector<uint16_t> extra_s7comm_ports;  // also governs S7comm-Plus and MMS "expected port"
                                                 // annotations -- all three share TCP port 102
    std::vector<uint16_t> extra_iec104_ports;
    std::vector<uint16_t> extra_enip_ports;
    std::vector<uint16_t> extra_enip_io_ports;  // UDP, unlike extra_enip_ports (TCP) -- see ENIP_IO_UDP_PORT
    std::vector<uint16_t> extra_bacnet_ports;   // UDP -- see BACNET_UDP_PORT (47808/0xBAC0)
    std::vector<uint16_t> extra_hartip_ports;   // TCP AND UDP -- see HARTIP_PORT (5094, same for both)
    std::vector<uint16_t> extra_opcua_ports;    // TCP only -- see OPCUA_PORT (4840)
    std::vector<uint16_t> extra_mqtt_ports;     // TCP only -- see MQTT_PORT (1883)
    std::vector<uint16_t> extra_ffhse_ports;    // TCP AND UDP -- see FFHSE_PORT_ANNUNC/_FMS/_SM/_LAN
                                                  // (1089/1090/1091/3622); a single list covers all
                                                  // four, since the sub-protocol is signaled in-band,
                                                  // not by port -- see ffhse.hpp
    // UNLIKE every extra_*_ports list above, these five DO gate detection in Auto mode, not just
    // the "expected port" annotation -- see dns.hpp's/nbns.hpp's/tls_sni.hpp's own "Detection"
    // paragraphs for why: DNS/mDNS/LLMNR/NBT-NS have no self-describing wire-format signal at all,
    // and DoH detection is inherently port+SNI based, so port-independent opportunistic detection
    // (this codebase's usual posture) would false-positive constantly. Only meaningful in Auto
    // mode -- an explicit --protocol dns/mdns/llmnr/nbns/doh already skips the port gate entirely.
    std::vector<uint16_t> extra_dns_ports;      // UDP -- see DNS_PORT (53)
    std::vector<uint16_t> extra_mdns_ports;     // UDP -- see MDNS_PORT (5353)
    std::vector<uint16_t> extra_llmnr_ports;    // UDP -- see LLMNR_PORT (5355)
    std::vector<uint16_t> extra_nbns_ports;     // UDP -- see NBNS_PORT (137)
    std::vector<uint16_t> extra_doh_ports;      // TCP -- see DOH_PORT (443)
    std::vector<uint16_t> extra_rip_ports;      // UDP -- see RIP_PORT (520); joins the same
                                                  // detection-gating group as DNS/mDNS/LLMNR/
                                                  // NBT-NS above, for the same reason: RIP's wire
                                                  // format signal (a handful of small integers) is
                                                  // too weak to try opportunistically on every UDP
                                                  // port -- see rip.hpp's own try_parse_rip comment.
    std::vector<uint16_t> extra_hsrp_ports;     // UDP -- see HSRP_PORT (1985); same detection-
                                                  // gating group and reasoning as extra_rip_ports
                                                  // above -- see hsrp.hpp's own try_parse_hsrp
                                                  // comment. IGMP, VRRP, IGRP, PIM, EIGRP, and
                                                  // OSPF need no port list at all: all six are
                                                  // dispatched purely by their own IANA-exclusive
                                                  // IP protocol number (2, 112, 9, 103, 88, and 89
                                                  // respectively), which is a strong signal with
                                                  // no port concept.
    // One shared list across all five Tier 1 "IT protocols an OT auditor flags" protocols (RDP/
    // VNC/TeamViewer/AnyDesk/Zoom -- see it_protocols.hpp), the same "one feature toggle" grouping
    // extra_ffhse_ports already established. Gates detection for RDP's COTP-based check and for
    // the three port-only protocols (TeamViewer/AnyDesk/Zoom, which have no payload signal at all)
    // -- joins the same detection-gating group as DNS/RIP/HSRP above for that reason. VNC is the
    // one exception: its RFB protocol-version banner (see it_protocols.hpp) is checked port-
    // independently even in Auto mode, since it's a genuinely strong, self-describing signal, the
    // same "structural signature overrides the port gate" treatment BACnet/IP's or HART-IP's own
    // opportunistic checks get -- this list still extends what counts as VNC's "expected" port for
    // the purposes of the "seen on a non-standard port" note, just never gates the detection itself.
    std::vector<uint16_t> extra_remote_access_ports;
    // One shared list across all eight Tier 2 "IT protocols an OT auditor flags" protocols (SMB/
    // SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP -- see it_protocols.hpp), the same one-list grouping
    // extra_remote_access_ports above already established for Tier 1. Gates detection for the four
    // protocols with no strong port-independent signature (SNMP, Telnet, FTP, TFTP -- joins the
    // same detection-gating group as extra_dns_ports/extra_rip_ports/etc. above) and extends the
    // "expected port" set for HTTPS's own port-only fallback. SMB/SSH/HTTP are the exceptions: SMB's
    // direct-hosting magic, SSH's version-exchange banner, and HTTP's request-line/status-line are
    // all checked port-independently even in Auto mode (each is a genuinely strong, self-describing
    // signal, the same "structural signature overrides the port gate" treatment VNC's RFB banner
    // gets above) -- this list still extends what counts as each one's own "expected" port for the
    // purposes of the "seen on a non-standard port" note, just never gates those three's detection.
    std::vector<uint16_t> extra_lateral_movement_ports;
    // One shared list across all six port-based Tier 3 "IT protocols an OT auditor flags"
    // protocols (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+ -- see it_protocols.hpp), the same grouping
    // extra_remote_access_ports/extra_lateral_movement_ports above already established for
    // Tiers 1-2. EAPOL has no port at all (EtherType-keyed, see eapol.hpp) so it is not covered by
    // this list. NTP/RADIUS/TACACS+/LDAP are all port-gated even for their own structural checks
    // (join the same detection-gating group as extra_dns_ports/extra_rip_ports/etc. above) --
    // DHCP's magic cookie and LDAP over TLS's own ClientHello (layered into the existing HTTPS/DoH
    // early-detection call site, see decoder.cpp) are the two exceptions checked port-independently
    // even in Auto mode, the same "structural signature overrides the port gate" treatment VNC/SMB/
    // SSH/HTTP already have in Tiers 1-2.
    std::vector<uint16_t> extra_enterprise_trust_ports;
    // One shared list across all five port-based Tier 4 "IT protocols an OT auditor flags"
    // protocols (CAPWAP control/data, LWAPP control/data, GTP-U -- see it_protocols.hpp), the same
    // grouping extra_remote_access_ports/extra_lateral_movement_ports/extra_enterprise_trust_ports
    // above already established for Tiers 1-3. PPPoE has no port at all (EtherType-keyed, see
    // pppoe.hpp) so it is not covered by this list. All five ARE port-gated even for their own
    // structural checks (join the same detection-gating group as extra_dns_ports/extra_rip_ports/
    // etc. above) -- unlike DHCP's magic cookie or LDAP-over-TLS's ClientHello in Tier 3, none of
    // CAPWAP/LWAPP/GTP-U's own signals are strong enough to check opportunistically on every UDP
    // port (see it_protocols.hpp's own Tier 4 comment for the full per-protocol reasoning).
    std::vector<uint16_t> extra_wireless_backhaul_ports;
    // One shared list across all fourteen IP-protocol-number/port-based Tier 5 "IT protocols an OT
    // auditor flags" protocols (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve,
    // WireGuard, OpenVPN, dtls-tunnel, STT -- see tunnel_vpn.hpp), the same grouping
    // extra_remote_access_ports/.../extra_wireless_backhaul_ports above already established for
    // Tiers 1-4. MPLS has no port at all (EtherType-keyed, see mpls.hpp) so it is not covered by
    // this list. GRE/ESP/AH/IP-in-IP/6in4/L2TP's own IP-protocol-number-keyed forms need no port
    // list either -- like IGMP/VRRP/etc. above, they are dispatched purely by IP protocol number.
    // Every port-based protocol here IS port-gated even for its own structural check (joins the
    // same detection-gating group as extra_dns_ports/extra_rip_ports/etc. above) with one
    // exception: dtls-tunnel's own DTLS record header is checked port-independently even in Auto
    // mode, the same "structural signature overrides the port gate" treatment VNC/SMB/SSH/HTTP/DHCP
    // already have -- see tunnel_vpn.hpp's own header comment for why.
    std::vector<uint16_t> extra_tunnel_vpn_ports;
    // If true, a parse failure at the Ethernet/IPv4/TCP layer is rethrown to
    // the caller instead of being recorded as a per-packet "parse-error"
    // result. Off by default so one malformed packet doesn't abort decoding
    // an entire capture.
    bool strict = false;
};

// How a TCP flow's client (initiator) vs. server side was determined -- shared by `decode`'s own
// per-packet direction tracking (FlowDirectionTracker, see flow_direction.hpp), PolicyEngine's
// FlowReport (policy_engine.hpp), and AssetInventoryEngine's InventoryEdge (asset_inventory.hpp).
// Each of those three keeps its own independent direction-determination logic (deliberately not
// shared -- see docs/MANUAL.md's ROADMAP item 19, "Why two copies, not one shared implementation",
// which the same reasoning now also covers for a third, decode-side copy), but all three report
// which of these tiers produced their answer using this one shared enum/name pair. "Approximately"
// (as used informally in docs/MANUAL.md's LIMITATIONS) means exactly one specific thing throughout
// this codebase: PortHeuristic below, not backed by an observed TCP handshake -- nothing vaguer.
// See docs/MANUAL.md's ROADMAP item 19 for the full three-tier design record and the industry
// precedent (Zeek/Suricata/Wireshark) researched before settling on these three values.
enum class DirectionSource {
    Handshake,      // a SYN and a matching SYN-ACK were both observed for this TCP flow (on any
                    // packet, not just the first) -- the only tier this project calls unambiguous:
                    // TCP's own three-way handshake is authoritative by construction, the initiator
                    // is whoever sent the SYN.
    Content,        // no handshake was observed (or the protocol has none at all, e.g. UDP), but the
                    // protocol's own application-layer semantics settle it without guessing -- e.g.
                    // BACnet's Confirmed-Request/Unconfirmed-Request source is definitionally the
                    // client, since BACnet client and server both conventionally listen on the same
                    // UDP port and the port heuristic below can't even be attempted.
    PortHeuristic,  // neither of the above: falls back to a known-service-port-then-lower-port-number
                    // guess that CAN be wrong -- the only tier that is ever actually a guess, not a
                    // determination.
};

// Renders a DirectionSource as the exact lowercase, hyphenated string used in every text/JSON/CSV
// report this codebase produces for it: "handshake" / "content" / "port-heuristic".
const char* direction_source_name(DirectionSource source);

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
    bool has_udp = false;  // exactly one of has_tcp/has_udp is ever true for a given IPv4 packet
    // Shared between TCP and UDP -- populated whichever of has_tcp/has_udp is set. tcp_flags is
    // TCP-only (UDP has no equivalent) and stays empty for a UDP packet.
    uint16_t src_port = 0, dst_port = 0;
    std::string tcp_flags;

    // "iec104", "modbus", "dnp3", "s7comm", "enip", "profinet", "goose", "sv", "ethercat", "stp",
    // "devicenet" (LINKTYPE_CAN_SOCKETCAN captures only -- see can_socketcan.hpp/devicenet.hpp),
    // "bacnet", "hartip", "opcua", "mms", "mqtt", "s7comm-plus", "cotp"
    // (recognized TPKT/COTP framing but not S7comm inside it -- e.g. a connection setup frame),
    // "tcp" (recognized transport, no app-layer match), "udp" (recognized transport, no app-layer
    // protocol decoded -- see udp.hpp; UDP/2222 CIP I/O traffic that try_parse_cip_io actually
    // recognizes is promoted to "enip" instead -- see enip_has_io below), "non-tcp" (a non-TCP,
    // non-UDP IPv4 payload, e.g. ICMP), "non-ip" (a non-IPv4 Ethernet frame, e.g. ARP, or a
    // PROFINET RT frame whose FrameID try_parse_profinet doesn't recognize, or a GOOSE frame
    // whose outer APDU tag try_parse_goose doesn't recognize, or an SV frame whose outer APDU tag
    // try_parse_sv doesn't recognize, or an EtherCAT frame whose header Type field
    // try_parse_ethercat doesn't recognize, or a classic-802.3-LLC-framed frame (EthernetFrame::
    // is_llc_length -- see link_layer.hpp) whose LLC DSAP/SSAP isn't STP's 0x42/0x42 (reported as
    // "IEEE 802.3 LLC frame, DSAP=0xNN SSAP=0xNN" -- a Cisco (R)PVST+ SNAP/OUI match, or a GARP
    // destination-MAC match, gets its own more specific name in that same summary instead, see
    // stp.hpp -- neither is decoded further) -- see link_layer.hpp's ethertype_name; EtherType
    // 0x8892 traffic that try_parse_profinet DOES recognize is promoted to "profinet" instead --
    // see profinet_has_dcp/profinet_has_cyclic_data below; EtherType 0x88B8 traffic that
    // try_parse_goose DOES recognize is promoted to "goose" instead -- see goose_has_pdu/
    // goose_is_gse_management below; EtherType 0x88BA traffic that try_parse_sv DOES recognize is
    // promoted to "sv" instead -- see sv_asdu_count below; EtherType 0x88A4 traffic that
    // try_parse_ethercat DOES recognize is promoted to "ethercat" instead -- see
    // ethercat_frame_type below; a UDP payload that try_parse_bacnet recognizes as a BACnet/IP
    // BVLC message is promoted to "bacnet" instead -- see bacnet_bvlc_function below; a TCP or UDP
    // payload that try_parse_hartip recognizes as a HART-IP message is promoted to "hartip"
    // instead -- see hartip_message_type below; a classic-802.3-LLC-framed frame with LLC DSAP==
    // SSAP==0x42, Control==0x03, and a destination MAC outside the GARP range that try_parse_stp
    // recognizes is promoted to "stp" instead -- see stp_bpdu_type_name below; on a
    // LINKTYPE_CAN_SOCKETCAN capture, a CAN frame that try_parse_devicenet recognizes (i.e. not an
    // EFF/RTR/ERR-flagged frame, see can_socketcan.hpp/devicenet.hpp) is "devicenet" -- see
    // devicenet_can_id below; an EFF/RTR/ERR-flagged frame on that same link type is "non-ip"
    // (named structurally by which flag(s) are set, never decoded further -- not a valid DeviceNet
    // frame shape at all)),
    // "unsupported-link", or "parse-error". Also "dns"/"mdns"/"llmnr" (a UDP payload on the
    // matching port -- 53/5353/5355 -- that try_parse_dns_message recognizes, see dns_* fields
    // below), "nbns" (NetBIOS Name Service/NBT-NS, UDP port 137, see nbns_* fields below), and
    // "doh" (a TCP/443 flow whose TLS ClientHello SNI matches a known DNS-over-HTTPS resolver --
    // detection only, see doh_* fields below and tls_sni.hpp). Also "rip" (a UDP payload on port
    // 520, or any port with --protocol rip, that try_parse_rip recognizes -- see rip_* fields
    // below and rip.hpp), "igmp" (an IP payload with IP protocol number 2, dispatched regardless
    // of port since IGMP has none, that try_parse_igmp recognizes -- see igmp_* fields below and
    // igmp.hpp; a non-IGMP-shaped IP-protocol-2 payload still falls through to "non-tcp"), "vrrp"
    // (an IP payload with IP protocol number 112 that try_parse_vrrp recognizes -- see vrrp_*
    // fields below and vrrp.hpp; same "non-tcp" fallback if it doesn't structurally match), and
    // "hsrp" (a UDP payload on port 1985, or any port with --protocol hsrp, that try_parse_hsrp
    // recognizes -- see hsrp_* fields below and hsrp.hpp). Also "igrp" (an IP payload with IP
    // protocol number 9 that try_parse_igrp recognizes -- see igrp_* fields below and igrp.hpp),
    // "pim" (IP protocol number 103, try_parse_pim, see pim_* fields and pim.hpp), "eigrp" (IP
    // protocol number 88, try_parse_eigrp, see eigrp_* fields and eigrp.hpp), and "ospf" (IP
    // protocol number 89, try_parse_ospf, see ospf_* fields and ospf.hpp) -- all four dispatched
    // regardless of port, the same IP-protocol-number posture as igmp/vrrp above; a non-matching
    // payload on any of these four IP protocol numbers still falls through to "non-tcp".
    std::string protocol;
    std::string summary;
    std::vector<std::string> notes;

    // Only set when protocol == "modbus"; useful for downstream JSON consumers.
    bool modbus_is_exception = false;
    std::string modbus_function_name;
    // Only set when protocol == "modbus" and Decoder::pair_modbus_transaction authoritatively
    // (by MBAP transaction ID + TCP session, not the payload-shape heuristic modbus.cpp always
    // applies) determined this packet is the response to a specific earlier request on the same
    // TCP session. modbus_paired_request_index is that request's DecodedPacket::index.
    bool modbus_is_paired_response = false;
    size_t modbus_paired_request_index = 0;

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

    // Only set for function_code == 0x29 (PLC Stop), Job (request) side -- see
    // S7CommFrame::plc_stop_message in s7comm.hpp for the exact wire layout and what is/isn't
    // decoded. Security context: this is the wire-level mechanism behind the well-known
    // unauthenticated ICS attack that halts an S7-300/400 class CPU with no authentication at all.
    std::string s7comm_plc_stop_message;

    // Only set for function_code == 0x28 (PLC Control / "PI-Service"), Job (request) side, whose
    // PI service name was decoded -- see S7CommFrame's pi_* fields in s7comm.hpp for the full
    // wire layout and the deliberate _N_* Sinumerik/CNC scope boundary (name+description lookup
    // only, no parameter decode).
    bool s7comm_has_pi_service = false;
    std::string s7comm_pi_service_name;
    std::string s7comm_pi_service_description;  // empty when pi_service_name isn't in the known table
    // _INSE/_INS2/_DELE only -- one "<type><number> (<destination>)" string per block descriptor,
    // e.g. "DB100 (Passive)", "FC5 (Active)". Capped at 50 entries, same reason as s7comm_item_tags.
    std::vector<std::string> s7comm_pi_control_blocks;
    // P_PROGRAM/_MODU/_GARB only, when a non-empty argument was present on the wire.
    std::string s7comm_pi_control_argument;

    // Only set for function_code == 0x28, Ack_Data (response) side, whose 1-byte status field was
    // present -- see S7CommFrame::has_pi_control_status in s7comm.hpp.
    bool s7comm_has_pi_control_status = false;
    bool s7comm_pi_control_has_more_data = false;  // status bit 0x01
    bool s7comm_pi_control_has_error = false;      // status bit 0x02

    // Only set when protocol == "s7comm-plus" -- see s7commplus.hpp/try_parse_s7comm_plus. A
    // DIFFERENT, independent application protocol from classic S7comm above despite the shared
    // "s7comm" name and TCP port 102/TPKT/COTP transport -- kept as its own "protocol" value
    // (not an s7comm variant flag) for the same reason MMS is its own protocol value despite
    // sharing that transport too.
    std::string s7plus_pdu_type_name;  // "Connect", "Data", "DataFW1_5", "Keep Alive" -- always
                                         // set when protocol == "s7comm-plus"
    bool s7plus_is_keepalive = false;
    uint8_t s7plus_keepalive_seq = 0;   // only meaningful when s7plus_is_keepalive
    bool s7plus_has_opcode = false;
    std::string s7plus_opcode_name;     // "Request"/"Response"/"Notification"/"Response2"
    bool s7plus_has_function = false;
    uint16_t s7plus_function_code = 0;
    std::string s7plus_function_name;   // e.g. "GetMultiVariables", or "Unknown (0xNNNN)"
    bool s7plus_has_sequence_number = false;
    uint16_t s7plus_sequence_number = 0;
    bool s7plus_has_session_id = false;  // Request telegrams only
    uint32_t s7plus_session_id = 0;
    // True only for the Tier-1 functions this decoder fully decodes (GetMultiVariables,
    // SetMultiVariables, SetVariable, DeleteObject) -- see s7commplus.hpp's file header for the
    // full Tier-1/Tier-2 split and why. False means the function code was still named (see
    // s7plus_function_name) but its body is shown only via `notes`, same "named but not decoded"
    // convention as MMS's other 67 services or OPC UA's Tier 2 services.
    bool s7plus_body_decoded = false;
    bool s7plus_has_return_value = false;
    int16_t s7plus_return_code = 0;
    std::string s7plus_return_code_name;
    // Item addresses (GetMultiVariables/SetMultiVariables requests, SetVariable/DeleteObject) --
    // S7comm-Plus's own native symbolic (CRC+LID) or object-id addressing, see
    // S7CommPlusItemAddress::tag in s7commplus.hpp. Capped at 50 entries, same reason as
    // s7comm_item_tags above.
    std::vector<std::string> s7plus_item_tags;
    // Decoded {id, value} pairs -- response values (GetMultiVariables), or values being written
    // (SetMultiVariables/SetVariable requests). Same 50-entry cap.
    std::vector<std::string> s7plus_value_summaries;
    // Per-item status from a GetMultiVariables/SetMultiVariables response's own errorvalue-list.
    // Same 50-entry cap.
    std::vector<std::string> s7plus_item_errors;
    bool s7plus_has_integrity = false;
    bool s7plus_integrity_digest_present = false;  // false when the digest bytes weren't there
                                                      // to consume (a truncated capture) or,
                                                      // pre-DataFW1_5-fix, a digest_len != 32
    uint8_t s7plus_integrity_digest_length = 0;      // expected 32; digest bytes never verified
    bool s7plus_has_trailer = false;

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

    // Data-link CRC validation -- see Dnp3LinkFrame::crc_validated/header_crc_valid/block_count/
    // block_crc_failures in dnp3.hpp for the full semantics. Unlike dnp3_has_function above (which
    // needs a fully decoded application layer), these mirror the FIRST DNP3 data link frame found
    // in this TCP payload and are always set whenever protocol == "dnp3" -- a link-layer-only
    // control frame with no user data at all still has a header CRC to check. A frame coalesced
    // after the first one (see the coalescing loop in decoder.cpp) gets its own CRC-mismatch note
    // in `notes` if it has one, same as its function/objects/values, but isn't reflected in these
    // headline fields, same "first frame only" convention as dnp3_has_function/dnp3_function_name.
    bool dnp3_link_crc_valid = false;    // header CRC AND every block CRC (if any) validated
    bool dnp3_header_crc_valid = false;  // header CRC alone -- false means destination/source/
                                          // control/length on this frame cannot be trusted at all
    size_t dnp3_block_count = 0;         // <=16-byte user-data blocks this frame had (0 for a
                                          // link-layer-only control frame with no user data)
    size_t dnp3_block_crc_failures = 0;  // how many of those blocks' CRCs failed (mismatch or
                                          // couldn't be read at all, e.g. truncated capture)

    // DNP3 data-link source/destination address (Dnp3LinkFrame::source/destination in dnp3.hpp --
    // each a 16-bit DNP3 station address, NOT an IP address: the actual outstation/master
    // identity a serial-to-IP DNP3 gateway multiplexes behind one shared IP, which IP-only
    // zone/conduit matching (see PolicyEngine/POLICY FILE FORMAT's "Addressing scope" section)
    // cannot distinguish on its own). Always set whenever protocol == "dnp3" -- unlike
    // dnp3_has_function above, a link-layer-only control frame with no user data at all still has
    // a data-link header carrying both addresses -- but, same "first frame only" convention as
    // dnp3_link_crc_valid/dnp3_header_crc_valid above, mirrors only the FIRST DNP3 data link frame
    // found in this TCP payload; a coalesced later frame's own source/destination, if different,
    // is not reflected here. Their reliability tracks dnp3_header_crc_valid: a bad header CRC
    // means these two values (like control/length on the same frame) cannot be trusted either.
    uint16_t dnp3_source_address = 0;
    uint16_t dnp3_destination_address = 0;

    // Only set when protocol == "iec104". Reflects the first APDU found in this TCP payload (an
    // I-format APDU with a decoded ASDU) -- see the coalescing loop in decoder.cpp for how
    // additional APDUs coalesced into the same payload are still fully decoded and folded in here,
    // same pattern as DNP3's multi-frame-per-payload handling.
    bool iec104_has_asdu = false;
    std::string iec104_asdu_type_name;
    // Just the mnemonic half of iec104_asdu_type_name (e.g. "M_SP_NA_1" rather than "M_SP_NA_1
    // (Single-point information)") -- see iec104_type_short_name's comment in iec104.hpp. This is
    // the field a policy file's 'functions:' entries for an iec104-restricted conduit are
    // validated/matched against (see policy.cpp/PolicyEngine), since the parenthetical description
    // in iec104_asdu_type_name bundles two independent pieces of information into one string.
    std::string iec104_asdu_type_short_name;
    std::string iec104_cot_name;
    uint16_t iec104_common_address = 0;
    // One entry per decoded information object across every ASDU found in this TCP payload (e.g.
    // "ioa=1001: ON [SB]"), capped at 50 entries for the same reason as dnp3_point_values.
    std::vector<std::string> iec104_object_values;

    // Only set when protocol == "enip". Reflects the first EtherNet/IP encapsulation message
    // found in this TCP payload (see the coalescing loop in decoder.cpp for how additional
    // messages coalesced into the same payload are still fully decoded, same pattern as IEC 104/
    // DNP3's multi-frame-per-payload handling -- their detail is folded into enip_cip_values/notes
    // but not reflected in these headline fields).
    std::string enip_command_name;  // always set when protocol == "enip" (NOP/ListIdentity/SendRRData/...)
    bool enip_has_cip = false;      // true once a CIP explicit message (request or response) was located
    bool enip_cip_is_response = false;
    std::string enip_cip_service_name;
    std::string enip_cip_path;         // request path summary (request only, e.g. "MyTag" or "Class=0x01 (Identity) Instance=1")
    std::string enip_cip_status_name;  // general status name (response only)
    // One entry per decoded request/response data item (element values, Multiple_Service_Packet
    // members, Unconnected_Send's embedded message, ...) -- capped at 50 entries for the same
    // reason as dnp3_point_values/iec104_object_values.
    std::vector<std::string> enip_cip_values;

    // Only set when protocol == "enip" AND this packet is a CIP I/O (implicit messaging) UDP
    // datagram, not an explicit-messaging TCP encapsulation message -- see try_parse_cip_io in
    // enip.hpp. enip_command_name is left empty in that case (there is no encapsulation command on
    // the wire for implicit messaging at all -- see enip.hpp's file header comment).
    bool enip_has_io = false;
    uint32_t enip_io_connection_id = 0;
    uint32_t enip_io_sequence_number = 0;
    bool enip_io_has_data = false;   // true once a Connected Data Item (0x00B1) was located
    std::string enip_io_data_hex;    // raw hex, deliberately not value-decoded -- see enip.hpp
    size_t enip_io_data_length = 0;

    // Only set when protocol == "profinet" -- see try_parse_profinet in profinet.hpp. PROFINET RT
    // rides directly on raw Ethernet (EtherType 0x8892, has_ip stays false), so unlike every other
    // protocol above there is no src_ip/dst_ip/src_port/dst_port for it -- src_mac/dst_mac (above)
    // are the only addressing this packet carries.
    uint16_t profinet_frame_id = 0;
    std::string profinet_frame_id_name;  // always set when protocol == "profinet"

    // DCP (Discovery and Configuration Protocol) -- set only when profinet_frame_id is one of the
    // four DCP FrameIDs (see profinet.hpp).
    bool profinet_has_dcp = false;
    std::string profinet_dcp_service_name;       // Hello / Get / Set / Identify
    std::string profinet_dcp_service_type_name;  // Request / Response-Success / ...
    // One entry per decoded DCP block (e.g. "NameOfStation=\"plc-01\""), capped at 50 entries for
    // the same reason as enip_cip_values.
    std::vector<std::string> profinet_dcp_blocks;

    // Cyclic RT IO data -- set only when profinet_frame_id falls in the cyclic RT FrameID ranges
    // (see profinet.hpp).
    bool profinet_has_cyclic_data = false;
    std::string profinet_cyclic_io_data_hex;  // raw hex, deliberately not value-decoded
    size_t profinet_cyclic_io_data_length = 0;
    uint16_t profinet_cyclic_cycle_counter = 0;
    std::string profinet_cyclic_data_status_summary;
    uint8_t profinet_cyclic_transfer_status = 0;

    // Only set when protocol == "goose" -- see try_parse_goose in goose.hpp. Like PROFINET RT
    // above, GOOSE rides directly on raw Ethernet (EtherType 0x88B8, has_ip stays false), so there
    // is no src_ip/dst_ip/src_port/dst_port for it -- src_mac/dst_mac (above) are the only
    // addressing this packet carries. GOOSE traffic is commonly multicast to a well-known MAC
    // range (01-0C-CD-01-xx-xx) and/or 802.1Q priority-tagged -- see has_vlan_tag/vlan_id above.
    bool goose_is_gse_management = false;  // outer APDU tag 0xA0 -- named only, fields below unset
    bool goose_has_pdu = false;            // outer APDU tag 0x61 -- IECGoosePdu decoded, fields below set
    uint16_t goose_appid = 0;              // always set when protocol == "goose"
    bool goose_simulated = false;          // header S-bit set, or the PDU's own simulation field true
    std::string goose_gocb_ref;
    std::string goose_dat_set;
    std::string goose_go_id;               // empty when the optional goID field wasn't present
    uint64_t goose_st_num = 0;
    uint64_t goose_sq_num = 0;
    uint64_t goose_conf_rev = 0;
    uint64_t goose_num_dat_set_entries = 0;
    // One entry per decoded allData value (e.g. "0: boolean=false", "6.1: bit-string=13-bit
    // 0b0000000000000"), capped at 50 entries for the same reason as profinet_dcp_blocks/
    // enip_cip_values -- see goose.hpp's GooseDataValue for the dotted-path scheme.
    std::vector<std::string> goose_all_data;

    // Only set when protocol == "sv" -- see try_parse_sv in sv.hpp. Like GOOSE and PROFINET RT
    // above, SV rides directly on raw Ethernet (EtherType 0x88BA, has_ip stays false) --
    // src_mac/dst_mac (above) are the only addressing this packet carries.
    uint16_t sv_appid = 0;
    bool sv_simulated = false;  // header S-bit (Reserved1 0x8000) -- SV has no PDU-level
                                  // simulation field to cross-check it against, unlike GOOSE
    uint64_t sv_no_asdu = 0;     // SavPdu's declared noASDU count
    uint64_t sv_asdu_count = 0;  // how many ASDUs were actually decoded -- a mismatch against
                                   // sv_no_asdu is noted

    // The first decoded ASDU's own fields, promoted here for convenience -- the great majority of
    // real SV traffic carries exactly one ASDU per frame (see sv.hpp's LIMITATIONS-relevant
    // Validation paragraph). See sv_asdus below for every ASDU when sv_asdu_count > 1. All
    // empty/0 when sv_asdu_count == 0.
    std::string sv_id;
    std::string sv_dat_set;      // empty when the optional datSet field wasn't present
    uint64_t sv_smp_cnt = 0;
    uint64_t sv_conf_rev = 0;
    std::string sv_smp_synch;    // "none"/"local"/"global"/"unknown(N)", empty when absent
    uint64_t sv_smp_rate = 0;    // 0 when the optional smpRate field wasn't present
    std::string sv_smp_mod;      // "samplesPerNormalPeriod"/etc, empty when absent
    std::string sv_seq_data_hex; // raw hex, deliberately not value-decoded -- see sv.hpp
    size_t sv_seq_data_length = 0;
    std::string sv_gmid_hex;     // 8-byte EUI-64 grandmaster identity, raw hex; empty when absent

    // One summary string per decoded ASDU (e.g. "svID=\"MU01\" smpCnt=1234 confRev=1"), capped at
    // 50 entries for the same reason as profinet_dcp_blocks/goose_all_data.
    std::vector<std::string> sv_asdus;

    // Only set when protocol == "ethercat" -- see try_parse_ethercat in ethercat.hpp. Like
    // PROFINET RT/GOOSE/SV above, EtherCAT rides directly on raw Ethernet (EtherType 0x88A4,
    // has_ip stays false) -- src_mac/dst_mac (above) are the only addressing this packet carries.
    uint8_t ethercat_frame_type = 0;    // always set when protocol == "ethercat"
    std::string ethercat_frame_type_name;  // "EtherCAT command"/"ADS"/"RAW-IO"/"NV"/"Mailbox"
    uint16_t ethercat_declared_length = 0;  // the frame header's own Length field (11 bits)

    // Set only when ethercat_frame_type == 1 ("EtherCAT command") -- Types 2-5 are named only,
    // not decoded further, see ethercat.hpp.
    bool ethercat_has_datagrams = false;
    uint64_t ethercat_datagram_count = 0;  // how many datagrams were actually decoded

    // The first decoded datagram's own fields, promoted here for convenience -- see sv_id/etc.
    // above for the same pattern. All 0/empty when ethercat_datagram_count == 0.
    uint8_t ethercat_first_cmd = 0;
    std::string ethercat_first_cmd_name;
    uint8_t ethercat_first_idx = 0;
    bool ethercat_first_logical_addressing = false;
    uint16_t ethercat_first_adp = 0;            // meaningful only when !ethercat_first_logical_addressing
    uint16_t ethercat_first_ado = 0;            // meaningful only when !ethercat_first_logical_addressing
    uint32_t ethercat_first_logical_address = 0;  // meaningful only when ethercat_first_logical_addressing
    std::string ethercat_first_data_hex;  // raw hex, deliberately not value-decoded -- see ethercat.hpp
    size_t ethercat_first_data_length = 0;
    uint16_t ethercat_first_wkc = 0;  // Working Counter -- see ethercat.hpp's WKC paragraph
    uint16_t ethercat_first_irq = 0;  // raw interrupt-request bitmask, not decoded further
    bool ethercat_first_circulating = false;  // Len word's Circulating bit (0x4000)

    // One summary string per decoded datagram (e.g. "APRD idx=2 adp=0x0000 ado=0x0130 len=2
    // wkc=1"), capped at 50 entries for the same reason as sv_asdus/goose_all_data.
    std::vector<std::string> ethercat_datagrams;

    // Only set when protocol == "eapol" -- see try_parse_eapol in eapol.hpp. Like PROFINET/EtherCAT/
    // GOOSE/SV above, EAPOL rides raw Ethernet (EtherType 0x888E), not IP -- has_ethernet stays true,
    // has_ip stays false.
    uint8_t eapol_version = 0;
    std::string eapol_version_name;
    uint8_t eapol_type = 0;
    std::string eapol_type_name;
    uint16_t eapol_length = 0;  // EAPOL's own declared body length
    // Set only when eapol_type == 0 (EAP-Packet) and the body carried RFC 3748's Code/Identifier/
    // Length header.
    bool eapol_has_eap = false;
    uint8_t eapol_eap_code = 0;
    std::string eapol_eap_code_name;
    uint8_t eapol_eap_identifier = 0;
    uint16_t eapol_eap_declared_length = 0;
    // Set only when eapol_has_eap && eapol_eap_code is Request(1)/Response(2) and a further Type
    // byte was present.
    bool eapol_has_eap_type = false;
    uint8_t eapol_eap_type = 0;
    std::string eapol_eap_type_name;
    // Set only when eapol_type == 3 (EAPOL-Key) and the body carried at least a Descriptor Type byte.
    bool eapol_has_key_descriptor = false;
    uint8_t eapol_key_descriptor_type = 0;
    std::string eapol_key_descriptor_type_name;

    // Only set when protocol == "pppoe" -- see try_parse_pppoe in pppoe.hpp. Like EAPOL above,
    // PPPoE rides raw Ethernet (EtherType 0x8863 Discovery / 0x8864 Session), not IP -- has_ethernet
    // stays true, has_ip stays false. The five port-based Tier 4 protocols (CAPWAP/LWAPP/GTP-U) have
    // no fields of their own here -- like every port-based Tier 1-3 protocol, they only ever set
    // protocol/summary/notes, see decoder.cpp's own Tier 4 UDP dispatch.
    uint8_t pppoe_version = 0;  // always 1
    uint8_t pppoe_type = 0;     // always 1
    uint8_t pppoe_code = 0;
    std::string pppoe_code_name;  // "PADI"/"PADO"/"PADR"/"PADS"/"PADT"/"Session Data"
    uint16_t pppoe_session_id = 0;
    uint16_t pppoe_length = 0;    // PPPoE's own declared payload length
    bool pppoe_is_session = false;  // true for EtherType 0x8864 (Session stage)
    // Set only when pppoe_is_session && the payload carried at least PPP's own 2-byte Protocol field.
    bool pppoe_has_ppp_protocol = false;
    uint16_t pppoe_ppp_protocol = 0;
    std::string pppoe_ppp_protocol_name;

    // Only set when protocol == "mpls" -- see try_parse_mpls in mpls.hpp. Like EAPOL/PPPoE above,
    // MPLS rides raw Ethernet (EtherType 0x8847 unicast / 0x8848 multicast), not IP -- has_ethernet
    // stays true, has_ip stays false. The fourteen IP-protocol-number/port-based Tier 5 protocols
    // (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN, Geneve, WireGuard, OpenVPN,
    // dtls-tunnel, STT) have no fields of their own here -- like every port-based Tier 1-4 protocol,
    // they only ever set protocol/summary/notes, see decoder.cpp's own Tier 5 dispatch.
    bool mpls_is_multicast = false;  // true for EtherType 0x8848
    // One summary string per label entry (e.g. "label=100352 exp=0 ttl=254 s=false"), in stack
    // order (top label first), capped at kMaxMplsLabelDepth entries -- see mpls.hpp.
    std::vector<std::string> mpls_labels;
    size_t mpls_label_count = 0;
    uint32_t mpls_top_label = 0;
    uint8_t mpls_top_exp = 0;
    uint8_t mpls_top_ttl = 0;
    bool mpls_stack_truncated = false;
    bool mpls_stack_too_deep = false;

    // Only set when protocol == "stp" -- see try_parse_stp in stp.hpp. Unlike every EtherType-keyed
    // raw-Ethernet protocol above, STP rides classic IEEE 802.3 LLC framing (has_ethernet stays
    // true, has_ip stays false, src_mac/dst_mac are the only addressing) -- see link_layer.hpp's
    // file header comment for the length-vs-EtherType plumbing this required.
    std::string stp_protocol_version_name;  // "STP (802.1D)"/"RSTP (802.1w)"/"MSTP (802.1s)"/
                                              // "SPB (802.1aq)" -- always set when protocol == "stp"
    uint8_t stp_protocol_version = 0;        // 0/2/3/4, the raw Protocol Version Identifier byte
    std::string stp_bpdu_type_name;          // "Configuration"/"Rapid/Multiple Spanning Tree"/
                                               // "Topology Change Notification"
    uint8_t stp_bpdu_type = 0;               // 0x00/0x02/0x80

    bool stp_is_tcn = false;  // BPDU Type 0x80 -- nothing else below is ever set
    bool stp_is_spb = false;  // Protocol Version 4 -- named only, nothing else below is ever set

    // Set when !stp_is_tcn && !stp_is_spb (a Configuration or RST/MST BPDU whose common 35-byte
    // body -- Flags through Forward Delay -- fit); false only for a truncated frame.
    bool stp_has_common_body = false;
    uint8_t stp_flags = 0;
    bool stp_flag_tca = false, stp_flag_agreement = false, stp_flag_forwarding = false,
         stp_flag_learning = false;
    uint8_t stp_flag_port_role = 0;         // 0-3, see stp.hpp's role_vals table
    std::string stp_flag_port_role_name;    // "Unknown"/"Alternate/Backup"/"Root"/"Designated" --
                                              // meaningful only for RSTP/MSTP (version >= 2), still
                                              // populated for version 0 (see stp.hpp)
    bool stp_flag_proposal = false, stp_flag_tc = false;

    uint16_t stp_root_priority = 0, stp_root_sys_id_ext = 0;
    std::string stp_root_mac;
    uint32_t stp_root_path_cost = 0;
    uint16_t stp_bridge_priority = 0, stp_bridge_sys_id_ext = 0;
    std::string stp_bridge_mac;
    uint16_t stp_port_id_raw = 0;
    uint16_t stp_port_priority = 0, stp_port_number = 0;  // see stp.hpp's "Port Identifier"
                                                             // paragraph for the priority multiplier
    double stp_message_age = 0.0, stp_max_age = 0.0, stp_hello_time = 0.0, stp_forward_delay = 0.0;  // seconds

    // Set when stp_bpdu_type == 0x02 (RST/MST-shaped) and at least the Version 1 Length byte fit.
    bool stp_has_version1 = false;
    uint8_t stp_version_1_length = 0;

    // Set only when the full three-part MSTP detection gate held (see stp.hpp) -- otherwise a
    // Protocol Version 3 frame is still reported with stp_protocol_version_name == "MSTP (802.1s)"
    // but stp_is_mstp stays false (decoded as a plain RST BPDU instead, matching the reference
    // dissector's own fallback -- see stp.hpp's file header comment).
    bool stp_is_mstp = false;
    uint16_t stp_version_3_length = 0;
    std::string stp_mst_config_name;
    uint16_t stp_mst_config_revision_level = 0;
    std::string stp_mst_config_digest_hex;   // 16 bytes, raw hex, never verified
    uint32_t stp_cist_internal_root_path_cost = 0;
    uint16_t stp_cist_bridge_priority = 0, stp_cist_bridge_sys_id_ext = 0;
    std::string stp_cist_bridge_mac;
    uint8_t stp_cist_remaining_hops = 0;

    bool stp_is_alt_msti_format = false;  // legacy/alternative MSTI layout detected, not decoded

    // One summary string per decoded MSTI Configuration Message, capped at 50 entries for the same
    // reason as ethercat_datagrams/goose_all_data.
    std::vector<std::string> stp_msti_messages;

    // Only set when protocol == "devicenet" -- see try_parse_devicenet in devicenet.hpp. Unlike
    // every other protocol this tool decodes, DeviceNet rides a wholly different link layer (CAN,
    // via SocketCAN pcap framing, LINKTYPE_CAN_SOCKETCAN -- see can_socketcan.hpp) rather than
    // Ethernet at all: has_ethernet AND has_ip both stay false for these packets (no MAC addresses,
    // no IP layer -- src_mac/dst_mac/src_ip/dst_ip are all meaningless here), the same "no
    // conventional addressing at all" shape STP's own has_ip==false (but has_ethernet==true, since
    // STP at least still rides Ethernet framing) doesn't quite share -- DeviceNet is the first
    // protocol in this codebase with NEITHER.
    uint16_t devicenet_can_id = 0;         // the masked 11-bit standard CAN identifier (0-0x7FF)
    int devicenet_group = 0;               // 1-4, or 0 for the unclassified 0x07F0-0x07FF range
    std::string devicenet_group_name;      // "Group 1"/"Group 2"/"Group 3"/"Group 4"/
                                             // "Unclassified (0x07F0-0x07FF)"
    std::string devicenet_message_type_name;  // per-group named message type, see devicenet.hpp

    bool devicenet_has_source_mac_id = false;  // Groups 1-3 only
    uint8_t devicenet_source_mac_id = 0;

    bool devicenet_has_group3_header = false;  // Group 3 only -- see devicenet.hpp
    bool devicenet_is_fragmented = false;
    bool devicenet_is_xid = false;
    uint8_t devicenet_dest_mac_id = 0;  // only meaningful when devicenet_has_group3_header

    bool devicenet_has_cip_service = false;  // Group 3, non-fragmented only
    bool devicenet_cip_is_response = false;
    uint8_t devicenet_cip_service = 0;       // the 7-bit service code, reply bit already stripped
    std::string devicenet_cip_service_name;

    bool devicenet_has_dup_mac_id_check = false;  // Group 2, message ID 0x07 only -- see devicenet.hpp
    bool devicenet_dup_mac_id_is_response = false;
    uint8_t devicenet_dup_mac_id_physical_port_number = 0;
    uint16_t devicenet_dup_mac_id_vendor_id = 0;
    uint32_t devicenet_dup_mac_id_serial_number = 0;

    bool devicenet_fd = false;  // CAN FD frame -- payload not semantically decoded, see devicenet.hpp
    bool devicenet_payload_truncated = false;  // the underlying SocketCAN record's own payload was
                                                 // shorter than its declared Payload Length -- see
                                                 // can_socketcan.hpp
    std::string devicenet_payload_hex;
    size_t devicenet_payload_length = 0;

    // Only set when protocol == "bacnet" -- see try_parse_bacnet in bacnet.hpp. Unlike EtherCAT/
    // PROFINET/GOOSE/SV above, BACnet/IP rides on UDP (conventionally port 47808/0xBAC0, has_ip
    // and has_udp both stay true) -- the same "opportunistic, payload-shape" detection posture as
    // EtherNet/IP CIP I/O (see enip_has_io above).
    std::string bacnet_bvlc_function;  // "BVLC-Result"/.../"Original-Unicast-NPDU"/... -- always
                                         // set when protocol == "bacnet"
    bool bacnet_has_npdu = false;  // true only for the BVLC functions that carry an NPDU
                                     // (Forwarded-NPDU/Distribute-Broadcast-To-Network/Original-
                                     // Unicast-NPDU/Original-Broadcast-NPDU) -- see bacnet.hpp

    uint8_t bacnet_npdu_version = 0;
    bool bacnet_npdu_is_network_layer_message = false;  // Control NET bit -- when true, this NPDU
                                                           // has no APDU at all, see bacnet.hpp
    bool bacnet_npdu_expecting_reply = false;
    uint8_t bacnet_npdu_priority = 0;  // 0-3
    bool bacnet_npdu_has_dest = false;
    uint16_t bacnet_npdu_dnet = 0;
    bool bacnet_npdu_has_src = false;
    uint16_t bacnet_npdu_snet = 0;
    uint8_t bacnet_npdu_hop_count = 0;       // meaningful only when bacnet_npdu_has_dest
    std::string bacnet_npdu_message_type;    // set only when bacnet_npdu_is_network_layer_message
                                                // -- named only, not decoded further, see bacnet.hpp

    // Set only when there IS an APDU (bacnet_has_npdu && !bacnet_npdu_is_network_layer_message).
    bool bacnet_has_apdu = false;
    std::string bacnet_apdu_type;      // "Confirmed-Request"/"Unconfirmed-Request"/"Simple-ACK"/
                                          // "Complex-ACK"/"Segment-ACK"/"Error"/"Reject"/"Abort"
    std::string bacnet_service_name;   // confirmed/unconfirmed service-choice name, when this PDU
                                          // type carries one -- empty for Segment-ACK/Reject/Abort
    int32_t bacnet_invoke_id = -1;     // -1 only for Segment-ACK's own separate invoke-id-like
                                          // field naming (still populated -- see bacnet.hpp), kept
                                          // signed so "-1" unambiguously means "not present"
    bool bacnet_segmented = false;     // Confirmed-Request/Complex-ACK's SEG bit -- see bacnet.hpp's
                                          // segmentation paragraph for why segmented APDUs' service
                                          // data is never value-decoded

    // Decoded field-by-field summary of the "first pass" services' request/ACK data (Who-Is/
    // I-Am/Who-Has/I-Have/ReadProperty/WriteProperty/generic-Error) -- see bacnet.hpp. Mirrors
    // enip_cip_values' scheme. Empty when this PDU's service is outside the first-pass set, or
    // when segmented.
    std::vector<std::string> bacnet_values;

    // Only set when protocol == "hartip" -- see try_parse_hartip in hartip.hpp. Unlike every
    // other protocol above, HART-IP is detected identically on BOTH has_tcp and has_udp payloads
    // (conventionally port 5094 for both) -- see hartip.hpp's "structural detection gate"
    // paragraph for why this decoder's own detection anchor here is honestly weaker than most of
    // this codebase's other opportunistic detectors.
    uint8_t hartip_version = 0;
    std::string hartip_message_type;  // "Request"/"Response"/"Publish"/"Error"/"NAK" -- always set
                                        // when protocol == "hartip"
    std::string hartip_message_id;    // "Session Initiate"/"Session Close"/"Keep Alive"/
                                        // "Pass Through" -- always set when protocol == "hartip"
    uint8_t hartip_status = 0;        // raw byte -- see hartip.hpp, no authoritative bit table found
    uint16_t hartip_transaction_id = 0;  // "Sequence Number" in Wireshark's own UI text
    uint16_t hartip_msg_length = 0;      // this message's own declared total length, header included

    // Set only for a Session Initiate (MessageID 0) message with a structurally valid 5-byte body.
    bool hartip_has_session_init = false;
    std::string hartip_host_type_name;  // "Secondary Host"/"Primary Host"
    uint32_t hartip_inactivity_close_timer = 0;  // seconds

    // Set only for an Error (MessageType 3) or NAK (MessageType 15) message with a structurally
    // valid 1-byte body -- checked BEFORE MessageID, see hartip.hpp.
    bool hartip_has_error = false;
    uint8_t hartip_error_code = 0;
    std::string hartip_error_code_name;

    // Set only for a Pass Through (MessageID 3) message -- the tunneled classic wired-HART
    // token-passing Data-Link PDU that carries the actual HART command/response traffic. Covers
    // Request/Response/Publish alike -- see hartip.hpp.
    bool hartip_has_pass_through = false;
    std::string hartip_frame_type;  // "STX"/"ACK"/"BACK"/"unknown(N)"
    bool hartip_is_response = false;
    bool hartip_is_long_address = false;
    std::string hartip_address_hex;  // the short (masked 0x3F, rendered as 2 hex digits) or the
                                       // 5-byte long address, whichever hartip_is_long_address says
    uint8_t hartip_command = 0;
    std::string hartip_command_name;  // best-effort name; empty for commands 31/203 -- see hartip.hpp

    // Present only when hartip_is_response.
    uint8_t hartip_response_code = 0;
    bool hartip_response_is_comm_error = false;
    std::string hartip_response_code_name;  // empty when hartip_response_is_comm_error
    std::vector<std::string> hartip_comm_error_flags;  // set only when hartip_response_is_comm_error
    uint8_t hartip_device_status = 0;
    std::vector<std::string> hartip_device_status_flags;

    // Decoded field-by-field summary of this command's request/response data -- see hartip.hpp's
    // "Command dispatch" section for exactly which command numbers this decoder value-decodes.
    // Mirrors bacnet_values'/enip_cip_values' scheme. Empty when this command is outside the
    // first-pass dispatch table (commands 77/178, and any unrecognized command number).
    std::vector<std::string> hartip_values;

    // The trailing classic wired-HART longitudinal (XOR) checksum byte, and whether this decoder's
    // own computed checksum (Delimiter..Data inclusive, see hartip.hpp) matched it -- only
    // meaningful when hartip_has_pass_through; hartip_checksum_valid is false both for a genuine
    // mismatch AND for a checksum byte that was truncated away entirely (see
    // HartIpPassThrough::checksum_valid's own doc comment -- an unverifiable checksum is never
    // treated as valid, mirroring dnp3_header_crc_valid's own convention).
    uint8_t hartip_checksum = 0;
    bool hartip_checksum_valid = false;

    // Only set when protocol == "opcua" -- see try_parse_opcua_message in opcua.hpp. OPC UA rides
    // TCP only (no UDP mapping in the spec); its own structural detection gate (a 3-byte ASCII
    // MessageType magic string against a 7-member allowlist) is one of the STRONGEST gates in
    // this codebase -- see opcua.hpp's own confidence comparison.
    std::string opcua_message_type;  // "Hello"/"Acknowledge"/"Error"/"ReverseHello"/
                                       // "OpenSecureChannel"/"CloseSecureChannel"/"Message"
    char opcua_chunk_type = 'F';      // 'F'/'C'/'A' -- see opcua.hpp's "Chunking" section
    uint32_t opcua_message_size = 0;  // this chunk's own declared total length, header included

    // Set only for OpenSecureChannel/CloseSecureChannel/Message (the SecureConversation messages
    // -- Hello/Acknowledge/Error/ReverseHello have no SecureChannelId of their own).
    bool opcua_has_secure_channel = false;
    uint32_t opcua_secure_channel_id = 0;
    bool opcua_is_asymmetric = false;  // true only for OpenSecureChannel
    std::string opcua_security_policy_uri;  // asymmetric (OpenSecureChannel) only
    bool opcua_has_sender_certificate = false;
    size_t opcua_sender_certificate_length = 0;
    bool opcua_has_receiver_certificate_thumbprint = false;
    uint32_t opcua_token_id = 0;  // symmetric (CloseSecureChannel/Message) only
    uint32_t opcua_sequence_number = 0;
    uint32_t opcua_request_id = 0;

    // Set only for Message (MSG) whose leading bytes this decoder could parse as a NodeId -- see
    // opcua.hpp's "Opportunistic MSG/OPN/CLO body decode" section for why this can fail even on a
    // structurally valid OPC UA message (an encrypted/signed body).
    bool opcua_service_recognized = false;  // TypeId matched a name in this decoder's own table
    std::string opcua_service_name;         // e.g. "OpenSecureChannelRequest" -- empty when !opcua_service_recognized
    uint16_t opcua_service_namespace = 0;
    uint32_t opcua_service_type_id = 0;  // the raw numeric identifier
    bool opcua_service_body_decoded = false;  // true for this decoder's "Tier 1" services (full
                                                // field decode); false for "Tier 2" (named, header
                                                // decoded, body shown as raw hex) and for any
                                                // unrecognized TypeId -- see opcua.hpp

    bool opcua_has_header = false;  // RequestHeader/ResponseHeader was itself decoded
    uint32_t opcua_request_handle = 0;
    bool opcua_is_response = false;
    uint32_t opcua_status_code = 0;       // ResponseHeader's own ServiceResult
    std::string opcua_status_code_name;   // "Good"/"Uncertain"/"Bad (0xNNNNNNNN)" -- see opcua.hpp
    bool opcua_status_is_good = false;

    // Decoded field-by-field summary of this Tier-1 service's own request/response fields --
    // mirrors bacnet_values'/hartip_values' scheme. Empty when opcua_service_body_decoded is
    // false.
    std::vector<std::string> opcua_values;

    bool opcua_body_shown_as_hex = false;
    std::string opcua_body_hex;
    size_t opcua_body_length = 0;

    // Only set when protocol == "mms" -- see try_parse_mms in mms.hpp. MMS rides the exact same
    // TCP port 102 / TPKT+COTP transport as S7comm (see s7comm.hpp/cotp.hpp) -- S7comm's own
    // single-byte protocol-id gate is always tried first, so this decoder is only ever reached
    // once that has already failed (see decoder.cpp's own dispatch-order comment). Fields below
    // mirror MmsFrame field-for-field; see mms.hpp for the full four-layer (Session/Presentation/
    // ACSE/MMS) byte layout and decode scope of each.
    bool mms_is_bare = false;
    uint8_t mms_session_spdu_type = 0;
    std::string mms_session_pdu_name;

    bool mms_has_presentation = false;
    std::vector<std::string> mms_presentation_context_list;
    uint32_t mms_presentation_context_id = 0;
    bool mms_presentation_context_is_acse = false;

    bool mms_has_acse = false;
    std::string mms_acse_pdu_name;
    std::string mms_acse_application_context_name;
    bool mms_acse_has_result = false;
    std::string mms_acse_result_name;
    std::vector<std::string> mms_acse_values;

    bool mms_has_pdu = false;
    std::string mms_pdu_name;

    bool mms_has_invoke_id = false;
    uint32_t mms_invoke_id = 0;

    bool mms_service_recognized = false;
    std::string mms_service_name;
    bool mms_service_body_decoded = false;

    bool mms_is_response = false;

    bool mms_has_error = false;
    std::string mms_error_name;

    // Tier 1 service-specific decoded fields (and Initiate's own capability negotiation, and
    // InformationReport's own variable+value list, and ServiceError/RejectPDU detail) --
    // mirrors opcua_values'/hartip_values' scheme.
    std::vector<std::string> mms_values;

    bool mms_body_shown_as_hex = false;
    std::string mms_body_hex;
    size_t mms_body_length = 0;

    // Only set when protocol == "mqtt" -- see try_parse_mqtt_message in mqtt.hpp. MQTT rides plain
    // TCP, conventionally port 1883 (this decoder's own structural detection gate is honestly weak
    // -- see mqtt.hpp's file header comment -- so it is tried LAST in decoder.cpp's opportunistic
    // TCP dispatch chain, after HART-IP). Fields below mirror MqttMessage field-for-field.
    std::string mqtt_packet_type_name;  // "CONNECT"/"PUBLISH"/... -- always set when protocol == "mqtt"
    uint32_t mqtt_remaining_length = 0;
    bool mqtt_dup = false, mqtt_retain = false;  // PUBLISH only
    uint8_t mqtt_qos = 0;                         // PUBLISH only
    bool mqtt_has_packet_id = false;
    uint16_t mqtt_packet_id = 0;
    std::string mqtt_topic;  // PUBLISH only
    bool mqtt_has_payload = false;
    size_t mqtt_payload_length = 0;
    std::string mqtt_payload_hex;  // PUBLISH only -- raw application payload, not value-decoded,
                                     // EXCEPT left empty when Sparkplug B decode below succeeded
    std::string mqtt_protocol_version_name;  // "3.1.1"/"5.0"/"" (unknown) -- see mqtt.hpp's own
                                               // "Version disambiguation" section
    // Every other packet-type-specific field, including every decoded MQTT5 Property -- mirrors
    // opcua_values'/bacnet_values'/hartip_values' scheme.
    std::vector<std::string> mqtt_values;

    // Sparkplug B -- PUBLISH only, set only when the topic matched the spBv1.0 namespace.
    bool mqtt_is_sparkplug = false;
    std::string mqtt_sparkplug_group_id, mqtt_sparkplug_message_type, mqtt_sparkplug_edge_node_id,
        mqtt_sparkplug_device_id;
    bool mqtt_sparkplug_is_state = false;
    std::string mqtt_sparkplug_state_host_id;  // set only when mqtt_sparkplug_is_state
    std::string mqtt_sparkplug_state_text;      // set only when mqtt_sparkplug_is_state -- raw JSON
                                                  // text, unparsed (see mqtt.hpp)
    bool mqtt_sparkplug_payload_decoded = false;  // protobuf Payload decode succeeded structurally
                                                    // (only meaningful when !mqtt_sparkplug_is_state)
    bool mqtt_sparkplug_has_timestamp = false;
    uint64_t mqtt_sparkplug_timestamp = 0;
    bool mqtt_sparkplug_has_seq = false;
    uint64_t mqtt_sparkplug_seq = 0;
    bool mqtt_sparkplug_has_uuid = false;
    std::string mqtt_sparkplug_uuid;
    bool mqtt_sparkplug_has_body = false;
    size_t mqtt_sparkplug_body_length = 0;
    size_t mqtt_sparkplug_metric_count = 0;  // every metric found, even past the rendering cap below
    std::vector<std::string> mqtt_sparkplug_metrics;  // one rendered summary per metric, capped

    // Only set when protocol == "ffhse" -- see try_parse_ffhse in ffhse.hpp. FOUNDATION Fieldbus
    // HSE rides EITHER TCP or UDP, conventionally ports 1089/1090/1091/3622 depending on
    // sub-protocol (FDA/SM/FMS/LAN Redundancy), all recorded as "expected port" annotations only
    // (the sub-protocol is signaled in-band via the header, not by port) -- see ffhse.hpp's file
    // header comment for this decoder's own honest comparison of its structural detection gate
    // against this codebase's other opportunistic detectors (it is weaker than even HART-IP's).
    uint8_t ffhse_version = 0;
    uint8_t ffhse_options = 0;  // raw Options byte
    std::string ffhse_protocol_name;  // "FDA Session Management"/"SM"/"FMS"/"LAN Redundancy" --
                                        // always set when protocol == "ffhse"
    std::string ffhse_type_name;      // "Request"/"Response"/"Error"
    bool ffhse_confirmed = false;     // Service byte's own bit 7
    uint8_t ffhse_service_id = 0;     // Service byte & 0x7f
    uint32_t ffhse_fda_address = 0;
    uint16_t ffhse_link_id = 0;       // fda_address >> 16 -- see ffhse.hpp's "LinkId branch"
    uint32_t ffhse_message_length = 0;

    // Optional trailer fields -- present only when their own Options bit is set.
    bool ffhse_has_message_number = false;
    uint32_t ffhse_message_number = 0;
    bool ffhse_has_invoke_id = false;
    uint32_t ffhse_invoke_id = 0;
    bool ffhse_has_time_stamp = false;
    uint64_t ffhse_time_stamp = 0;
    bool ffhse_has_extended_control_field = false;
    uint32_t ffhse_extended_control_field = 0;

    // Best-effort message name, e.g. "FDA Open Session Req", "SM Identify Rsp", "FMS Initiate
    // Err" -- always set when protocol == "ffhse".
    std::string ffhse_message_name;
    bool ffhse_recognized = false;   // this decoder recognized the (protocol,type,confirmed,
                                       // service id) combination at all (Tier 1 OR Tier 2)
    bool ffhse_body_decoded = false;  // true only for a Tier-1 message whose body matched this
                                        // decoder's expected shape -- see ffhse.hpp's Tier-1/Tier-2
                                        // split
    // One "field=value" entry per decoded field, wire order -- mirrors hartip_values'/
    // bacnet_values' scheme. Populated only when ffhse_body_decoded.
    std::vector<std::string> ffhse_values;

    bool ffhse_body_shown_as_hex = false;
    std::string ffhse_body_hex;
    size_t ffhse_body_length = 0;

    // Only set when protocol == "dns", "mdns", or "llmnr" -- see try_parse_dns_message in
    // dns.hpp. All three share this one field family (rather than each getting its own, the way
    // most other protocols do) because all three are the exact same wire format -- see dns.hpp's
    // file header comment for exactly what differs between them, which is reflected here only in
    // dns_header_flags' letters (only meaningful together with `protocol` -- the same bit
    // position means something different depending on flavor).
    uint16_t dns_transaction_id = 0;
    bool dns_is_response = false;
    std::string dns_opcode_name;
    std::string dns_header_flags;  // e.g. "AA,RD" (dns/mdns) or "C,T" (llmnr); empty if none set
    std::string dns_rcode_name;
    uint16_t dns_qdcount = 0, dns_ancount = 0, dns_nscount = 0, dns_arcount = 0;  // as declared
    // One "section: name TYPE CLASS ..." entry per question/answer/authority/additional record
    // actually parsed, in wire order -- mirrors bacnet_values'/ffhse_values' scheme but section-
    // tagged (e.g. "question: example.com. A IN" / "answer: example.com. A IN ttl=300s ->
    // address=93.184.216.34") rather than split into parallel per-section arrays, since that's
    // the order they appear in the message. See dns.hpp's DnsResourceRecordEntry/DnsQuestionEntry
    // for the structured form this is rendered from.
    std::vector<std::string> dns_records;
    bool dns_records_truncated = false;  // declared counts implied more than the payload had room for

    // Only set when protocol == "nbns" (NetBIOS Name Service/NBT-NS) -- see try_parse_nbns in
    // nbns.hpp.
    uint16_t nbns_transaction_id = 0;
    bool nbns_is_response = false;
    std::string nbns_opcode_name;
    std::string nbns_flags;  // e.g. "AA,RD,B" -- wire order AA,TC,RD,RA,B
    std::string nbns_rcode_name;
    uint16_t nbns_qdcount = 0, nbns_ancount = 0, nbns_nscount = 0, nbns_arcount = 0;
    std::vector<std::string> nbns_records;  // same section-tagged scheme as dns_records above
    bool nbns_records_truncated = false;

    // Only set when protocol == "doh" -- detection only, see try_detect_doh in tls_sni.hpp. There
    // is deliberately no "doh_query"/"doh_answer" field of any kind: the DNS message itself is
    // TLS-encrypted and never visible to this decoder.
    std::string doh_sni;
    std::string doh_matched_provider;
    std::vector<std::string> doh_alpn_protocols;

    // Only set when protocol == "rip" -- see try_parse_rip in rip.hpp.
    uint8_t rip_version = 0;
    std::string rip_command_name;
    // One "route/entry" rendering per RipRoute, wire order -- e.g. "192.168.1.0/255.255.255.0 via
    // 10.0.0.1 metric 2" for an ordinary route, "full table request" for the AFI-0 marker entry,
    // or "authentication: Simple Password" / "authentication: Keyed MD5 (key id N)" for an auth
    // entry. Capped at 50 entries, same convention as s7comm_item_tags above.
    std::vector<std::string> rip_routes;
    bool rip_routes_truncated = false;  // more than 50 route table entries were present

    // Only set when protocol == "igmp" -- see try_parse_igmp in igmp.hpp.
    int igmp_version = 0;
    std::string igmp_type_name;
    std::string igmp_group_address;  // Query/v1/v2 Report/Leave only; empty for a v3 Report
    // One "type: multicast_address (N source(s))" entry per Group Record, wire order --
    // v3 Report only. Capped at 50 entries.
    std::vector<std::string> igmp_group_records;
    bool igmp_group_records_truncated = false;  // more than 50 group records were declared

    // Only set when protocol == "vrrp" -- see try_parse_vrrp in vrrp.hpp.
    uint8_t vrrp_version = 0;
    uint8_t vrrp_virtual_router_id = 0;
    uint8_t vrrp_priority = 0;
    std::vector<std::string> vrrp_ip_addresses;  // capped at 50 entries
    bool vrrp_ip_addresses_truncated = false;    // more than 50 addresses were declared

    // Only set when protocol == "hsrp" -- see try_parse_hsrp in hsrp.hpp.
    uint8_t hsrp_version = 0;
    std::string hsrp_opcode_name;   // v1 only; empty for v2 (see hsrp_tlv_types instead)
    std::string hsrp_state_name;    // v1 only
    std::string hsrp_virtual_ip;    // v1 only
    std::vector<std::string> hsrp_tlv_types;  // v2 only: one "Group State"/"Interface State"/...
                                                // entry per TLV, wire order. Capped at 50 entries.
    bool hsrp_tlvs_truncated = false;          // more than 50 TLVs were present

    // Only set when protocol == "igrp" -- see try_parse_igrp in igrp.hpp.
    uint8_t igrp_version = 0;
    std::string igrp_opcode_name;  // "Response" or "Request"
    uint16_t igrp_autonomous_system = 0;
    // One "<Interior|System|Exterior> <address> delay=Xus bw=Ykbps hops=Z" entry per route (or
    // "... unreachable" when the route's Delay field is all-ones), Interior first then System then
    // Exterior, matching wire order. Capped at 50 entries total.
    std::vector<std::string> igrp_routes;
    bool igrp_routes_truncated = false;

    // Only set when protocol == "pim" -- see try_parse_pim in pim.hpp. Which of the fields below
    // are populated depends on pim_type_name; see pim.hpp's own PimMessage for exactly which
    // message type populates which group.
    std::string pim_type_name;
    std::vector<std::string> pim_hello_options;  // Hello only: one "TypeName: value" (or
                                                   // "TypeName (addr1, addr2, ...)" for an Address
                                                   // List option) entry per option. Capped at 50.
    bool pim_hello_options_truncated = false;
    bool pim_register_border_bit = false;         // Register only
    bool pim_register_null_register_bit = false;  // Register only
    std::string pim_register_inner_src_ip;        // Register only
    std::string pim_register_inner_group_ip;      // Register only
    std::string pim_register_stop_group;          // Register-Stop only
    std::string pim_register_stop_source;         // Register-Stop only
    std::string pim_jp_upstream_neighbor;         // Join/Prune, Graft, Graft-Ack only
    uint16_t pim_jp_holdtime_sec = 0;             // Join/Prune, Graft, Graft-Ack only
    // One "<group>: N join(s), M prune(s)" entry per group, wire order. Capped at 50.
    std::vector<std::string> pim_jp_groups;
    bool pim_jp_groups_truncated = false;
    uint16_t pim_bsr_fragment_tag = 0;   // Bootstrap only
    uint8_t pim_bsr_hash_mask_len = 0;   // Bootstrap only
    uint8_t pim_bsr_priority = 0;        // Bootstrap only
    std::string pim_bsr_address;         // Bootstrap only
    std::vector<std::string> pim_bsr_groups;  // Bootstrap only: one "<group>: N candidate-RP(s)"
                                                // entry per group. Capped at 50.
    bool pim_bsr_groups_truncated = false;
    std::string pim_assert_group;                 // Assert only
    std::string pim_assert_source;                // Assert only
    bool pim_assert_rpt_bit = false;              // Assert only
    uint32_t pim_assert_metric_preference = 0;    // Assert only
    uint32_t pim_assert_metric = 0;               // Assert only
    uint8_t pim_crp_prefix_count = 0;             // Candidate-RP-Advertisement only
    uint8_t pim_crp_priority = 0;                 // Candidate-RP-Advertisement only
    uint16_t pim_crp_holdtime_sec = 0;            // Candidate-RP-Advertisement only
    std::string pim_crp_rp_address;               // Candidate-RP-Advertisement only
    std::vector<std::string> pim_crp_groups;      // Candidate-RP-Advertisement only. Capped at 50.
    bool pim_crp_groups_truncated = false;

    // Only set when protocol == "eigrp" -- see try_parse_eigrp in eigrp.hpp.
    std::string eigrp_opcode_name;
    uint16_t eigrp_autonomous_system = 0;
    std::vector<std::string> eigrp_flags;  // zero or more of "Init"/"Conditional Receive"/
                                             // "Restart"/"End Of Table", whichever bits are set
    // One "TypeName: value" (or bare "TypeName" when not decoded further) entry per general TLV
    // (Parameters/Authentication/Sequence/Software Version/Next Multicast Sequence/anything
    // else), wire order. Capped at 50.
    std::vector<std::string> eigrp_general_tlvs;
    bool eigrp_general_tlvs_truncated = false;
    // One EigrpRoute::summary entry per Classic or Wide-Metric IPv4 route TLV, wire order. Capped
    // at 50.
    std::vector<std::string> eigrp_routes;
    bool eigrp_routes_truncated = false;

    // Only set when protocol == "ospf" -- see try_parse_ospf in ospf.hpp. Which of the fields
    // below are populated depends on ospf_type_name; see ospf.hpp's own OspfMessage for exactly
    // which packet type populates which group.
    std::string ospf_type_name;
    std::string ospf_router_id;
    std::string ospf_area_id;
    std::string ospf_auth_type_name;
    std::string ospf_hello_designated_router;         // Hello only
    std::string ospf_hello_backup_designated_router;  // Hello only
    std::vector<std::string> ospf_hello_neighbors;    // Hello only. Capped at 50.
    bool ospf_hello_neighbors_truncated = false;
    // One rendered "Type len N: LinkStateID AdvRouter Seq=... Age=...s" entry per LSA header, wire
    // order. Capped at 50.
    std::vector<std::string> ospf_dbd_lsa_headers;    // DB Description only
    bool ospf_dbd_lsa_headers_truncated = false;
    std::vector<std::string> ospf_ls_requests;        // LS Request only. Capped at 50.
    bool ospf_ls_requests_truncated = false;
    // Same one-line rendering as ospf_dbd_lsa_headers, but with a decoded body's own key fields
    // appended when this LSA's type has one (see ospf.hpp) -- e.g. a Router-LSA's link count, a
    // Network-LSA's mask, a Summary/ASBR-Summary/AS-External's metric.
    std::vector<std::string> ospf_ls_update_lsas;     // LS Update only. Capped at 50.
    bool ospf_ls_update_lsas_truncated = false;
    std::vector<std::string> ospf_ls_ack_headers;     // LS Ack only. Capped at 50.
    bool ospf_ls_ack_headers_truncated = false;

    // Appended last, after every other field above, so this addition never shifts the position of
    // any existing one -- the same append-only discipline this struct's own writers already follow
    // for src_mac_vendor/vlan_id/time (see output.cpp's own comments). Set only by
    // FlowDirectionTracker::observe (flow_direction.hpp), called from cli_main.cpp's run_decode
    // loop right after Decoder::decode() returns -- Decoder/decode() itself has no knowledge of
    // this, the same "separate layer on top of already-public output" boundary PolicyEngine
    // (policy_engine.hpp) and AssetInventoryEngine (asset_inventory.hpp) each already keep for
    // themselves (FlowDirectionTracker is `decode`'s own third, independent copy of the same
    // per-TCP-flow direction logic -- see docs/MANUAL.md's ROADMAP item 19). has_direction is true
    // only for a has_tcp packet (FlowDirectionTracker's scope matches PolicyEngine::observe's own:
    // TCP flows only, so direction_source here is always Handshake or PortHeuristic, never Content
    // -- content-based direction, i.e. BACnet, is UDP-only and stays out of `decode`'s own per-
    // packet direction tracking, unlike `inventory`'s InventoryEdge). direction_client_is_src is
    // which side of THIS packet (src, not dst) FlowDirectionTracker's per-flow tracking currently
    // believes is the client (initiator); direction_source is which tier decided it -- see
    // DirectionSource's own comment above for the full three-tier definition.
    bool has_direction = false;
    bool direction_client_is_src = false;  // meaningful only when has_direction
    DirectionSource direction_source = DirectionSource::PortHeuristic;  // meaningful only when has_direction
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

// Generic per-directional-TCP-flow byte buffer for a Modbus MBAP message, a DNP3 data-link
// frame, or a TPKT/COTP frame whose OWN declared length exceeds what has arrived in the TCP
// segments seen so far for that flow -- see Decoder::tcp_reassembly_ and
// Decoder::reassemble_tcp_payload. This is a different (and lower) layer than
// Dnp3FragmentReassembly above: that one reassembles a DNP3 *application* fragment across several
// already-complete data-link frames; this one reassembles a single PDU/frame's own bytes when one
// TCP segment doesn't contain all of them. The two compose without conflict -- a data-link frame
// can be completed here, across TCP segments, and then Decoder's existing frame-coalescing loop
// and Dnp3FragmentReassembly both still operate on it exactly as before, since by the time they
// run they're just looking at a complete (however it got assembled) buffer.
struct TcpFlowBuffer {
    bool active = false;
    std::vector<uint8_t> bytes;  // bytes buffered so far for the in-progress PDU/frame
    uint32_t next_seq = 0;       // TCP sequence number expected to begin the next segment
    size_t segment_count = 0;    // TCP segments contributed to `bytes` so far
};

// One outstanding Modbus request, tracked per TCP session (both directions -- see
// Decoder::modbus_pending_) and keyed further by its MBAP transaction ID, so a later packet on the
// SAME session carrying the SAME transaction ID from the OPPOSITE direction can be authoritatively
// paired to it -- see Decoder::pair_modbus_transaction. `flow_key` is the *directional* flow the
// request itself was seen on (src->dst), kept so a same-direction repeat of the same transaction ID
// (reused before any response arrived) can be told apart from a genuine opposite-direction reply.
struct ModbusPendingRequest {
    size_t packet_index = 0;
    std::string flow_key;
    std::string function_name;
    std::string request_summary;  // the request packet's ModbusFrame::summary, for the response's note
    uint8_t unit_id = 0;
};

// Cross-packet COTP/S7comm reassembly state for one directional TCP flow -- see
// Decoder::cotp_reassembly_ and Decoder::reassemble_cotp_data_frame. A single S7comm message can
// be chained across more than one COTP Data (DT) frame when it doesn't fit the negotiated PDU
// length: every DT frame but the last has EOT=0, and the last has EOT=1 (ISO 8073's own TSDU
// fragmentation signal -- unlike DNP3, COTP has no separate FIR-equivalent bit, so "in_progress"
// alone distinguishes a fresh start from a continuation). This is a different layer from
// TcpFlowBuffer above: that one reassembles one TPKT/COTP frame's own bytes across TCP segments;
// this one chains several already-complete TPKT/COTP frames' user data together into one logical
// S7comm message.
struct CotpFragmentReassembly {
    bool in_progress = false;
    std::vector<uint8_t> buffered_user_data;  // concatenated COTP Data frame user_data so far
    size_t frame_count = 0;                    // complete TPKT/COTP DT frames contributed so far
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

    // See TcpFlowBuffer above. Keyed the same way as dnp3_reassembly_ (same flow_key string, same
    // map-per-flow shape; a separate map because the two track different layers and there's no
    // reason to conflate them). `mutable` for the same reason as dnp3_reassembly_.
    mutable std::unordered_map<std::string, TcpFlowBuffer> tcp_reassembly_;

    // See ModbusPendingRequest above. Outer key is a *session* key (both directions of one TCP
    // 4-tuple canonicalized into one string -- see the session_key helper in decoder.cpp; NOT the
    // same shape as the directional flow_key used by dnp3_reassembly_/tcp_reassembly_ above),
    // inner key is the MBAP transaction ID. `mutable` for the same reason as dnp3_reassembly_.
    mutable std::unordered_map<std::string, std::unordered_map<uint16_t, ModbusPendingRequest>> modbus_pending_;

    // See CotpFragmentReassembly above. Keyed by directional flow_key, same shape as
    // dnp3_reassembly_/tcp_reassembly_. `mutable` for the same reason as dnp3_reassembly_.
    mutable std::unordered_map<std::string, CotpFragmentReassembly> cotp_reassembly_;

    // MQTT protocol version (0=unknown, 4=v3.1.1, 5=v5.0) learned from a CONNECT packet seen
    // earlier on this TCP SESSION (both directions -- keyed the same way as modbus_pending_'s outer
    // key, via the session_key helper in decoder.cpp, since a later SUBSCRIBE/SUBACK/UNSUBSCRIBE
    // needing this hint can arrive in either direction relative to the CONNECT itself). Used only to
    // disambiguate the handful of MQTT packet types whose own wire shape is genuinely ambiguous
    // between v3.1.1 and v5 without it -- see mqtt.hpp's "Version disambiguation" section; every
    // other MQTT packet type is self-describing and never consults this map. `mutable` for the same
    // reason as dnp3_reassembly_ above.
    mutable std::unordered_map<std::string, uint8_t> mqtt_session_version_;

    // Decodes one DNP3 data-link frame's transport header and, once its fragment is complete,
    // application layer -- buffering across packets via dnp3_reassembly_[flow_key] when the
    // fragment spans more than one data-link frame (transport FIR=1,FIN=0 on an earlier frame).
    // `link`/`tcp_payload` are the same as try_parse_dnp3_transport_and_application's, which this
    // supersedes as decoder.cpp's call site precisely because that function has no flow to buffer
    // against. Same nullopt contract: only when link.user_data_bytes == 0. See dnp3.hpp for the
    // reassemble_dnp3_user_data/decode_dnp3_application_layer primitives this is built from.
    // `link` is non-const: this is where link.block_count/block_crc_failures/crc_validated get
    // their final values (see reassemble_dnp3_user_data/Dnp3LinkFrame's own comments in dnp3.hpp).
    std::optional<Dnp3ApplicationFragment> process_dnp3_frame(Dnp3LinkFrame& link, ByteSpan tcp_payload,
                                                                const std::string& flow_key) const;

    // Determines the bytes protocol detection (Modbus/DNP3-link-layer/TPKT) should run against
    // for this packet: either `tcp.payload` unchanged, or a buffer combining it with bytes carried
    // over from earlier packets on the same flow (see TcpFlowBuffer/tcp_reassembly_).
    //
    // Handles TCP segment gaps and overlaps using sequence numbers alone: a segment whose seq
    // doesn't extend the buffered bytes contiguously is either a retransmission (seq is behind
    // where expected -- the overlapping prefix is trimmed and only new bytes, if any, are
    // appended) or evidence of a gap (seq is ahead of where expected, meaning an earlier segment
    // was very likely not captured) -- a gap abandons whatever was buffered, since it can never be
    // completed correctly, and starts fresh from this packet's own payload. This resyncs rather
    // than buffering out-of-order segments for later reordering, matching how this tool already
    // processes packets: one single, strict capture-file-order pass (see decode()'s NOTE ON
    // STATEFULNESS above) with no out-of-order buffering anywhere else either.
    //
    // If, after combining, the result is still short of what a recognized protocol's own length
    // field declares (see modbus_tcp_declared_length/dnp3_link_frame_declared_length/
    // tpkt_declared_length), this buffers the combined bytes back into tcp_reassembly_[flow_key],
    // fills in `out`'s protocol/summary/notes to say so, and returns false -- decode() must return
    // immediately in that case without attempting protocol detection on a known-incomplete buffer.
    // Also returns false (with `out` filled in) for a fully-duplicate retransmission that adds no
    // new bytes -- there's nothing new to decode and the existing buffered state is left as-is.
    //
    // On true, `effective_payload` is set to the bytes to actually run detection against.
    // `storage` backs it when combining was needed (an empty vector otherwise) and must outlive
    // `effective_payload`'s use -- the caller keeps it alive as a same-scope local in decode().
    bool reassemble_tcp_payload(const TcpSegment& tcp, const std::string& flow_key, DecodedPacket& out,
                                 std::vector<uint8_t>& storage, ByteSpan& effective_payload) const;

    // Attempts authoritative (MBAP transaction-ID + TCP-session, non-heuristic) Modbus
    // request/response pairing for `mb`, seen in the current packet (`packet_index`) on directional
    // flow `flow_key`, part of TCP session `session_key` (see the session_key helper in
    // decoder.cpp, which canonicalizes both directions of one TCP 4-tuple into one string). This
    // runs unconditionally alongside -- never instead of -- modbus.cpp's own payload-shape
    // heuristic (still applied first, into mb.summary/mb.notes, exactly as before this feature):
    //   - If `mb`'s transaction ID matches an outstanding request recorded earlier on this session
    //     from the OPPOSITE flow direction, this packet IS that request's response, authoritatively
    //     -- appends a note naming the matched request's packet index and sets
    //     out.modbus_is_paired_response/out.modbus_paired_request_index accordingly, regardless of
    //     what the shape heuristic guessed (this is exactly what resolves Write Single Coil/
    //     Register's inherent shape ambiguity -- request and response share the identical 4-byte
    //     shape per spec, per modbus.cpp -- since transaction ID + direction doesn't need the shape
    //     to differ).
    //   - If the transaction ID matches an outstanding request from the SAME direction instead, it
    //     was reused before ever being paired (a retry, an orphaned request, or out-of-order
    //     capture) -- notes this and starts tracking `mb` as the new outstanding request for that ID.
    //   - Otherwise, if the shape heuristic already called `mb` a response, there is no outstanding
    //     request to pair it to on this session -- notes it as an orphan (most likely its request
    //     was sent before this capture began) rather than silently accepting the heuristic's guess
    //     as the last word. Otherwise, records `mb` as newly outstanding so a later opposite-
    //     direction packet with the same transaction ID can pair against it.
    // Bounded per session by a capacity cap against a pathological/malformed capture leaking memory
    // (see decoder.cpp); past the cap, new requests simply stop being recorded until earlier ones
    // are paired off -- a capacity guard, not something worth a note on every packet past it.
    void pair_modbus_transaction(const ModbusFrame& mb, const std::string& flow_key,
                                  const std::string& session_key, size_t packet_index, DecodedPacket& out) const;

    // Determines the bytes S7comm detection should run against for a COTP Data (DT) frame `cotp`
    // already parsed from this packet: either `cotp.user_data` unchanged (the common, fast path --
    // this frame's own EOT=1 with nothing in progress, behaving exactly as before this feature
    // existed) or the concatenation of this and every earlier buffered fragment's user data on this
    // flow (EOT=1 completing a reassembly that an earlier EOT=0 frame began) -- see
    // CotpFragmentReassembly/cotp_reassembly_ above for why EOT alone, not a FIR-equivalent bit, is
    // what COTP gives us to detect a fresh start vs. a continuation.
    //
    // On true, `s7_candidate` is set to those bytes; `storage` backs it when concatenation was
    // needed (an empty vector otherwise) and must outlive `s7_candidate`'s use -- the caller keeps
    // it alive as a same-scope local in decode(), same contract as reassemble_tcp_payload.
    //
    // On false, `cotp.eot` is false: this frame's own bytes were buffered (or the flow's safety cap
    // was hit and the in-progress reassembly abandoned) -- `out`'s protocol/summary have already
    // been filled in (a "buffering..." or cap-abandonment report) and decode() must return `out`
    // immediately without attempting S7comm/COTP-only output for it.
    bool reassemble_cotp_data_frame(const CotpFrame& cotp, const std::string& flow_key, DecodedPacket& out,
                                     std::vector<uint8_t>& storage, ByteSpan& s7_candidate) const;
};

}  // namespace conduitscope
