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

#include "conduitscope/arp.hpp"
#include "conduitscope/bacnet.hpp"
#include "conduitscope/bgp.hpp"
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
#include "conduitscope/fins.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/hsrp.hpp"
#include "conduitscope/icmp.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/igmp.hpp"
#include "conduitscope/igrp.hpp"
#include "conduitscope/it_protocols.hpp"
#include "conduitscope/kerberos.hpp"
#include "conduitscope/ldap.hpp"
#include "conduitscope/lldp.hpp"
#include "conduitscope/melsec.hpp"
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
#include "conduitscope/protocol_decoder.hpp"
#include "conduitscope/quic.hpp"
#include "conduitscope/resource_limits.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7commplus.hpp"
#include "conduitscope/slow_protocols.hpp"
#include "conduitscope/smb.hpp"
#include "conduitscope/stp.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tcp.hpp"
#include "conduitscope/tls_sni.hpp"
#include "conduitscope/tunnel_vpn.hpp"
#include "conduitscope/twincat.hpp"
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
    IcmpOnly,     // only attempt ICMP decoding -- see icmp.hpp
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
                           // (NTP/DHCP/LDAPS/RADIUS/TACACS+) -- see it_protocols.hpp. One filter
                           // value covers all five port-based protocols, the same grouping
                           // RemoteAccessOnly/LateralMovementOnly above already established for
                           // Tiers 1-2. EAPOL (also Tier 3, but EtherType-keyed, no port at all --
                           // see eapol.hpp) is NOT covered by this filter value; it has its own
                           // EapolOnly below, the same split GOOSE/SV/EtherCAT/PROFINET's own
                           // EtherType-keyed filters already have from every port-based one. Plain
                           // LDAP is ALSO no longer covered by this filter value -- it has its own
                           // dedicated LdapOnly below, see that value's own comment.
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
    ArpOnly,               // only attempt ARP decoding -- see arp.hpp. A brand-new protocol (not a
                           // migration -- ARP had no decode logic of any kind before this, only the
                           // generic ethertype-name fallback), EtherType-gated (0x0806) with no port
                           // at all, the same posture EAPOL/PPPoE/MPLS already established for their
                           // own dedicated filter values.
    LldpOnly,              // only attempt LLDP decoding -- see lldp.hpp. A brand-new protocol (not a
                           // migration -- LLDP had no decode logic of any kind before this, only the
                           // generic ethertype-name fallback), EtherType-gated (0x88CC) with no port
                           // at all, the same posture ARP/EAPOL/PPPoE/MPLS already established for
                           // their own dedicated filter values.
    TwinCatOnly,           // only attempt Beckhoff TwinCAT/ADS (AMS/TCP) decoding -- see
                           // twincat.hpp. The first protocol built entirely on the
                           // registration-model ProtocolDecoder interface (protocol_decoder.hpp)
                           // -- see docs/DEVELOPMENT.md's "registration-model decoder refactor"
                           // entry.
    KerberosOnly,          // only attempt Kerberos (RFC 4120, UDP/88 and TCP/88) decoding -- see
                           // kerberos.hpp. The first protocol in the Windows Active Directory
                           // suite (Kerberos, then LDAP, then SMB/NTLM, then Netlogon/DCE-RPC --
                           // delivered one at a time).
    LdapOnly,              // only attempt LDAP (RFC 4511, TCP/389 and TCP/3268) decoding -- see
                           // ldap.hpp. The second protocol in the Windows Active Directory suite,
                           // no UDP sibling (CLDAP is deliberately out of scope). Plain LDAP was
                           // previously part of EnterpriseTrustOnly's own name-only Tier 3
                           // recognition (it_protocols.hpp); it moved here once it was upgraded to
                           // a full ProtocolDecoder, the same split EapolOnly already has from
                           // EnterpriseTrustOnly.
    SmbOnly,               // only attempt SMB2/SMB3 (MS-SMB2, TCP/445 and TCP/139) decoding, with
                           // embedded NTLM (MS-NLMP) authentication decoding -- see smb.hpp. The
                           // third protocol in the Windows Active Directory suite, no UDP sibling.
                           // SMB was previously part of LateralMovementOnly's own name-only Tier 2
                           // recognition (it_protocols.hpp); it moved here once it was upgraded to
                           // a full ProtocolDecoder, the same split LdapOnly already has from
                           // EnterpriseTrustOnly.
    MelsecOnly,            // only attempt MELSEC Communication Protocol (MC Protocol / SLMP,
                           // Mitsubishi Electric; TCP port 5001 / UDP port 5000, both
                           // port-independent) decoding -- see melsec.hpp. A brand-new protocol
                           // (not a migration), built entirely on the ProtocolDecoder interface
                           // from the start like TwinCAT, and the first protocol on that interface
                           // with a genuine dual TCP+UDP transport built from scratch (TwinCAT is
                           // TCP-only; Kerberos's own TCP+UDP split shares the same "two instances,
                           // one id()" pattern reused here).
    FinsOnly,              // only attempt Omron FINS (Factory Interface Network Service) decoding --
                           // see fins.hpp. TCP port 9600 and UDP port 9600 (same conventional port
                           // number for both transports, unlike MELSEC's split 5001/5000) -- a
                           // brand-new protocol built entirely on the ProtocolDecoder interface from
                           // the start, the same "two instances, one id()" dual TCP+UDP transport
                           // pattern MELSEC just established. Unlike MELSEC, a FINS response frame
                           // self-describes its own command code, so no MELSEC-style mandatory
                           // session-pending-request state machine is needed to decode response
                           // fields (FinsFlowState here is lighter-weight, matching only for a
                           // "matched to packet #N" note).
    BgpOnly,               // only attempt BGP-4 (RFC 4271, TCP port 179) decoding -- see bgp.hpp. A
                           // brand-new protocol built entirely on the ProtocolDecoder interface from
                           // the start, like TwinCAT/MELSEC/FINS -- but the first of those to need
                           // declared-length TCP reassembly (its own Length field, same role
                           // Modbus's/MELSEC's/FINS's own Length fields already play) AND a
                           // coalescing loop over the reassembled payload (same pattern OPC UA's own
                           // decode() already established) AND genuine session-scoped state
                           // (BgpFlowState -- whether 4-octet AS numbers were negotiated).
    SlowProtocolsOnly,     // only attempt IEEE 802.3 Slow Protocols (LACP/Marker/OAM, EtherType
                           // 0x8809) decoding -- see slow_protocols.hpp. A brand-new protocol, same
                           // EtherType-gated/stateless shape as ARP/LLDP, but subtype-multiplexed
                           // (one EtherType, three distinct message shapes told apart by a Subtype
                           // byte) -- so, like TwinCAT/BGP and unlike ARP/LLDP, it carries its
                           // result via DecodedPacket::result rather than a dedicated dual-written
                           // field block, given how deeply nested its OAM sub-message is.
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
    std::vector<uint16_t> extra_twincat_ports;  // no --extra-twincat-ports CLI flag yet (unlike
                                                  // every other protocol's own extra_*_ports here)
                                                  // -- deliberately deferred; see docs/DEVELOPMENT.md's
                                                  // TwinCAT/ADS entry. Always empty for now, so
                                                  // TWINCAT_AMS_TCP_PORT (48898) is the only port
                                                  // ever treated as "expected."
    std::vector<uint16_t> extra_dnp3_ports;
    std::vector<uint16_t> extra_s7comm_ports;  // also governs S7comm-Plus and MMS "expected port"
                                                 // annotations -- all three share TCP port 102
    std::vector<uint16_t> extra_iec104_ports;
    std::vector<uint16_t> extra_enip_ports;
    std::vector<uint16_t> extra_enip_io_ports;  // UDP, unlike extra_enip_ports (TCP) -- see ENIP_IO_UDP_PORT
    std::vector<uint16_t> extra_bacnet_ports;   // UDP -- see BACNET_UDP_PORT (47808/0xBAC0)
    std::vector<uint16_t> extra_hartip_ports;   // TCP AND UDP -- see HARTIP_PORT (5094, same for both)
    std::vector<uint16_t> extra_kerberos_ports;  // TCP AND UDP -- see KERBEROS_PORT (88, same for both)
    std::vector<uint16_t> extra_ldap_ports;      // TCP only -- see LDAP_PORT/LDAP_GC_PORT (389/3268,
                                                   // it_protocols.hpp)
    std::vector<uint16_t> extra_smb_ports;       // TCP only -- see SMB_PORT_445/
                                                   // SMB_NETBIOS_SESSION_PORT_139 (445/139,
                                                   // it_protocols.hpp)
    std::vector<uint16_t> extra_melsec_ports;    // TCP AND UDP -- see MELSEC_TCP_PORT/
                                                   // MELSEC_UDP_PORT (5001/5000, melsec.hpp) -- a
                                                   // single list covers both transports, the same
                                                   // "one list, two ports, different defaults"
                                                   // shape extra_enip_io_ports/extra_bacnet_ports
                                                   // don't need (single port) but extra_hartip_ports/
                                                   // extra_kerberos_ports also don't need (single
                                                   // SHARED port number for both transports) --
                                                   // MELSEC is the first protocol here whose TCP and
                                                   // UDP conventional ports genuinely differ.
    std::vector<uint16_t> extra_fins_ports;      // TCP AND UDP -- see FINS_TCP_PORT/FINS_UDP_PORT
                                                   // (9600/9600, fins.hpp) -- a single list covers
                                                   // both transports, the same SHARED-port-number
                                                   // shape extra_hartip_ports/extra_kerberos_ports
                                                   // already have (unlike MELSEC's own split ports).
    std::vector<uint16_t> extra_bgp_ports;      // TCP only -- see BGP_PORT (179, bgp.hpp). Unlike
                                                  // extra_twincat_ports (deliberately deferred, no
                                                  // CLI flag), BGP follows the ordinary Modbus-style
                                                  // pattern: a well-known, always-negotiated port,
                                                  // so a --bgp-port flag makes sense from the start.
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
    // One shared list across all seven Tier 2 "IT protocols an OT auditor flags" protocols (SSH/
    // HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP -- see it_protocols.hpp), the same one-list grouping
    // extra_remote_access_ports above already established for Tier 1. Gates detection for the four
    // protocols with no strong port-independent signature (SNMP, Telnet, FTP, TFTP -- joins the
    // same detection-gating group as extra_dns_ports/extra_rip_ports/etc. above) and extends the
    // "expected port" set for HTTPS's own port-only fallback. SSH/HTTP are the exceptions: SSH's
    // version-exchange banner and HTTP's request-line/status-line are both checked port-
    // independently even in Auto mode (each is a genuinely strong, self-describing signal, the same
    // "structural signature overrides the port gate" treatment VNC's RFB banner gets above) -- this
    // list still extends what counts as each one's own "expected" port for the purposes of the
    // "seen on a non-standard port" note, just never gates those two's detection. SMB was an eighth
    // Tier 2 protocol covered by this list; it now has its own dedicated extra_smb_ports above,
    // since it is a full ProtocolDecoder (see smb.hpp) rather than a Tier 2 name-only recognition --
    // the same split extra_ldap_ports already has from extra_enterprise_trust_ports.
    std::vector<uint16_t> extra_lateral_movement_ports;
    // One shared list across all five port-based Tier 3 "IT protocols an OT auditor flags"
    // protocols (NTP/DHCP/LDAPS/RADIUS/TACACS+ -- see it_protocols.hpp), the same grouping
    // extra_remote_access_ports/extra_lateral_movement_ports above already established for
    // Tiers 1-2. EAPOL has no port at all (EtherType-keyed, see eapol.hpp) so it is not covered by
    // this list; plain LDAP is ALSO no longer covered by this list -- it has its own dedicated
    // extra_ldap_ports above, since it is now a full ProtocolDecoder (see ldap.hpp) rather than a
    // Tier 3 name-only recognition. NTP/RADIUS/TACACS+ are all port-gated even for their own
    // structural checks (join the same detection-gating group as extra_dns_ports/extra_rip_ports/
    // etc. above) -- DHCP's magic cookie and LDAP over TLS's own ClientHello (layered into the
    // existing HTTPS/DoH early-detection call site, see decoder.cpp) are the two exceptions checked
    // port-independently even in Auto mode, the same "structural signature overrides the port gate"
    // treatment VNC/SMB/SSH/HTTP already have in Tiers 1-2.
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
    // Whether a decoded cleartext secret (HSRP's/VRRP's own plaintext authentication field, OPC
    // UA's UserNameIdentityToken password, MQTT's CONNECT password) is replaced with a fixed
    // "[REDACTED]" placeholder in every output format, or shown as the literal value that was on
    // the wire -- see decode's own --redact/--no-redact flag (cli_main.cpp) and
    // docs/MANUAL.md's OUTPUT FORMATS section. On by default ("reverting the earlier stance of
    // simply never decoding these values at all" -- see hsrp.hpp's/vrrp.hpp's own file header
    // comments -- to "decode them, but mask them by default so a shared capture or report stays
    // safe without losing the finding itself: THAT a cleartext credential exists here, which
    // protocol/field it's in, and how many bytes it is, are still real, useful OT-security
    // findings on their own, independent of the literal value"). Threaded into DecodeContext
    // (protocol_decoder.hpp)'s own redact_secrets field by decoder.cpp's HSRP/VRRP/OPC UA/MQTT
    // call sites specifically -- the only protocols in this codebase that ever place a literal
    // cleartext credential value into their own output at all; every other protocol's DecodeContext
    // just carries this field's default (true) unused, the same "only the few call sites that need
    // it ever populate it" precedent DecodeContext::ip_src_addr already set for IGRP.
    bool redact_secrets = true;
    // Process-wide overrides for the resource-exhaustion/DoS-protection constants scattered
    // across decoder.cpp and the individual protocol files -- see resource_limits.hpp for the
    // full rationale. Default-constructed (every field std::nullopt) means every site keeps its
    // own compile-time default, byte-identical to this feature's absence. Decoder's constructor
    // below installs this into the process-wide resource_limits() accessor.
    ResourceLimits limits;
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
    // non-UDP, non-ICMP/IGMP/VRRP/IGRP/PIM/EIGRP/OSPF IPv4 payload -- see the icmp/igmp/vrrp/igrp/
    // pim/eigrp/ospf paragraph below for what's promoted out of this fallback), "non-ip" (a non-IPv4 Ethernet frame, e.g. ARP, or a
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
    // try_parse_goose DOES recognize is promoted to "goose" instead -- see GooseFrame (goose.hpp),
    // reached via DecodedPacket::result; EtherType 0x88BA traffic that try_parse_sv DOES recognize is
    // promoted to "sv" instead -- see sv_asdu_count below; EtherType 0x88A4 traffic that
    // try_parse_ethercat DOES recognize is promoted to "ethercat" instead -- see
    // ethercat_frame_type below; a UDP payload that try_parse_bacnet recognizes as a BACnet/IP
    // BVLC message is promoted to "bacnet" instead -- see the BacnetFrame carried by
    // DecodedPacket::result (bacnet.hpp) below; a TCP or UDP
    // payload that try_parse_hartip recognizes as a HART-IP message is promoted to "hartip"
    // instead -- see the HartIpResult carried by DecodedPacket::result (hartip.hpp) below; a
    // classic-802.3-LLC-framed frame with LLC DSAP==
    // SSAP==0x42, Control==0x03, and a destination MAC outside the GARP range that try_parse_stp
    // recognizes is promoted to "stp" instead -- see stp_bpdu_type_name below; on a
    // LINKTYPE_CAN_SOCKETCAN capture, a CAN frame that try_parse_devicenet recognizes (i.e. not an
    // EFF/RTR/ERR-flagged frame, see can_socketcan.hpp/devicenet.hpp) is "devicenet" -- a zero-
    // flat-field migrated protocol, see DecodedPacket::result and devicenet.hpp; an EFF/RTR/ERR-
    // flagged frame on that same link type is "non-ip"
    // (named structurally by which flag(s) are set, never decoded further -- not a valid DeviceNet
    // frame shape at all)),
    // "unsupported-link", or "parse-error". Also "dns"/"mdns"/"llmnr" (a UDP payload on the
    // matching port -- 53/5353/5355 -- that try_parse_dns_message recognizes, see dns_* fields
    // below), "nbns" (NetBIOS Name Service/NBT-NS, UDP port 137, see nbns_* fields below), and
    // "doh" (a TCP/443 flow whose TLS ClientHello SNI matches a known DNS-over-HTTPS resolver --
    // detection only, a zero-flat-field migrated protocol, see DecodedPacket::result and
    // tls_sni.hpp). Also "rip" (a UDP payload on port
    // 520, or any port with --protocol rip, that try_parse_rip recognizes -- see rip_* fields
    // below and rip.hpp), "icmp" (an IP payload with IP protocol number 1, dispatched regardless
    // of port since ICMP has none, that try_parse_icmp recognizes -- see icmp_* fields below and
    // icmp.hpp; unlike igmp/vrrp/igrp/pim/eigrp/ospf below, try_parse_icmp accepts virtually any
    // 4+ byte payload -- ICMP's Type byte alone gives no useful structural filter -- so it is the
    // IP-protocol-number match itself, not a shape match, doing the real work here), "igmp" (an IP
    // payload with IP protocol number 2, dispatched regardless
    // of port since IGMP has none, that try_parse_igmp recognizes -- see igmp_* fields below and
    // igmp.hpp; a non-IGMP-shaped IP-protocol-2 payload still falls through to "non-tcp"), "vrrp"
    // (an IP payload with IP protocol number 112 that try_parse_vrrp recognizes -- see vrrp_*
    // fields below and vrrp.hpp; same "non-tcp" fallback if it doesn't structurally match), and
    // "hsrp" (a UDP payload on port 1985, or any port with --protocol hsrp, that try_parse_hsrp
    // recognizes -- see hsrp_* fields below and hsrp.hpp). Also "igrp" (an IP payload with IP
    // protocol number 9 that try_parse_igrp recognizes -- see igrp_* fields below and igrp.hpp),
    // "pim" (IP protocol number 103, try_parse_pim, see pim_* fields and pim.hpp), "eigrp" (IP
    // protocol number 88, EigrpDecoder -- a zero-flat-field migrated protocol, see
    // DecodedPacket::result and eigrp.hpp), and "ospf" (IP
    // protocol number 89, try_parse_ospf, see ospf_* fields and ospf.hpp) -- all four dispatched
    // regardless of port, the same IP-protocol-number posture as igmp/vrrp above; a non-matching
    // payload on any of these four IP protocol numbers still falls through to "non-tcp".
    std::string protocol;
    std::string summary;
    std::vector<std::string> notes;

    // registration-model decoder refactor (see protocol_decoder.hpp): set only by a protocol built
    // on the new ProtocolDecoder interface that chooses to carry its own structured result forward
    // for a renderer to read (TwinCAT, BGP, Slow Protocols, Kerberos, LDAP, SMB, MELSEC, FINS,
    // EIGRP, and Modbus so far -- see each protocol's own decoder.cpp call site), rather than
    // flattening its fields onto this struct the way every protocol below still does. Every
    // protocol-prefixed field below this point is untouched by the refactor; this is strictly
    // additive.
    std::optional<ProtocolResult> result;

    // Modbus is a zero-flat-field migrated protocol (see ProtocolDecoder/ProtocolResult in
    // protocol_decoder.hpp): its fields (function name, exception flag, transaction pairing) live
    // in the ModbusFrame carried by DecodedPacket::result, not here -- see output.cpp's
    // write_modbus_json_fields.

    // S7comm (classic, function_code-based -- not S7comm-Plus below) is a zero-flat-field migrated
    // protocol: its fields (function name, item tags/value summaries, PLC Stop message, PI-Service
    // fields) live in the S7CommResult carried by DecodedPacket::result, not here -- see
    // output.cpp's write_s7comm_json_fields. Unlike most other zero-flat-field protocols,
    // S7CommResult is NOT simply the decoder's own raw result type carried forward unmodified: see
    // S7CommResult's own comment in s7comm.hpp for why (a ByteSpan-into-a-call-site-local-buffer
    // lifetime hazard specific to S7comm's Read Var/Write Var response values).

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
    // S7CommPlusItemAddress::tag in s7commplus.hpp. Capped at 50 entries so a heavily batched
    // request can't blow up JSON output (same cap classic S7comm's own item tags used, back when
    // they were a flat field here too -- see S7CommResult::items in s7comm.hpp now).
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

    // DNP3 is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the Dnp3Result
    // carried by DecodedPacket::result, not here -- see output.cpp's write_dnp3_json_fields.
    // Dnp3Result::dnp3_has_function/dnp3_function_name are set only when this fragment's
    // application layer was decoded (see Dnp3ApplicationFragment::application_decoded in
    // dnp3.hpp -- false for a fragment that spans multiple data-link frames, which only gets its
    // transport header decoded); source_address/destination_address/link_crc_valid/
    // header_crc_valid/block_count/block_crc_failures mirror only the FIRST DNP3 data-link frame
    // found in this TCP payload, same "first frame only" convention -- a frame coalesced after the
    // first one gets its own CRC-mismatch note in `notes` if it has one, same as its
    // function/objects/values, but isn't reflected in these headline fields.

    // IEC 104 is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the Iec104Result
    // carried by DecodedPacket::result, not here -- see output.cpp's write_iec104_json_fields.
    // Reflects the first APDU found in this TCP payload (an I-format APDU with a decoded ASDU) --
    // see the coalescing loop in iec104.hpp/.cpp for how additional APDUs coalesced into the same
    // payload are still fully decoded and folded in. Iec104Result::iec104_asdu_type_short_name is
    // the field a policy file's 'functions:' entries for an iec104-restricted conduit are
    // validated/matched against (see policy.cpp/PolicyEngine), since the parenthetical description
    // in iec104_asdu_type_name bundles two independent pieces of information into one string.

    // EtherNet/IP is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp. It's the one protocol in this
    // codebase whose id() ("enip") is shared by two decoders with genuinely DIFFERENT
    // ProtocolResult payload types: EnipTcpDecoder's EnipResult (wrapping the first coalesced
    // EnipFrame, for TCP explicit messaging) vs EnipUdpDecoder's CipIoFrame directly (for UDP CIP
    // I/O/implicit messaging) -- see write_enip_json_fields/write_enip_io_json_fields's own
    // comments in output.cpp for how every reader of DecodedPacket::result discriminates between
    // the two (via has_tcp/has_udp, since CIP I/O only ever runs on UDP and explicit messaging
    // only ever runs on TCP). enip_command_name/enip_cip_* live in EnipResult::first;
    // enip_io_* live directly in CipIoFrame.

    // PROFINET RT is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the ProfinetFrame
    // carried by DecodedPacket::result, not here -- see output.cpp's write_profinet_json_fields and
    // profinet.hpp's own ProfinetFrame. PROFINET RT rides directly on raw Ethernet (EtherType
    // 0x8892, has_ip stays false), so unlike every other protocol above there is no
    // src_ip/dst_ip/src_port/dst_port for it -- src_mac/dst_mac (above) are the only addressing
    // this packet carries.

    // GOOSE is a zero-flat-field migrated protocol (see ProtocolDecoder/ProtocolResult in
    // protocol_decoder.hpp): its fields live in the GooseFrame carried by DecodedPacket::result,
    // not here -- see output.cpp's write_goose_json_fields. Like PROFINET RT above, GOOSE rides
    // directly on raw Ethernet (EtherType 0x88B8, has_ip stays false), so there is no
    // src_ip/dst_ip/src_port/dst_port for it -- src_mac/dst_mac (above) are the only addressing
    // this packet carries. GOOSE traffic is commonly multicast to a well-known MAC range
    // (01-0C-CD-01-xx-xx) and/or 802.1Q priority-tagged -- see has_vlan_tag/vlan_id above.

    // SV (IEC 61850-9-2 Sampled Values) is a zero-flat-field migrated protocol (mid-size batch) --
    // see ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the SvFrame
    // carried by DecodedPacket::result, not here -- see output.cpp's write_sv_json_fields and
    // sv.hpp's own SvFrame/SvAsdu. Like GOOSE and PROFINET RT above, SV rides directly on raw
    // Ethernet (EtherType 0x88BA, has_ip stays false) -- src_mac/dst_mac (above) are the only
    // addressing this packet carries.

    // EtherCAT is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the EthercatFrame
    // carried by DecodedPacket::result, not here -- see output.cpp's write_ethercat_json_fields and
    // ethercat.hpp's own EthercatFrame/EthercatDatagram. Like PROFINET RT/GOOSE/SV above, EtherCAT
    // rides directly on raw Ethernet (EtherType 0x88A4, has_ip stays false) -- src_mac/dst_mac
    // (above) are the only addressing this packet carries.

    // EAPOL is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the EapolFrame
    // carried by DecodedPacket::result, not here (and were never rendered by any writer even before
    // this migration -- output.cpp has never had an eapol_* JSON block, the same finding the cheap
    // batch made for ARP/MPLS/PPPoE). Like PROFINET/EtherCAT/GOOSE/SV above, EAPOL rides raw
    // Ethernet (EtherType 0x888E), not IP -- has_ethernet stays true, has_ip stays false.

    // protocol == "pppoe" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and pppoe.hpp's PppoeFrame. Like EAPOL above, PPPoE rides raw Ethernet
    // (EtherType 0x8863 Discovery / 0x8864 Session), not IP -- has_ethernet stays true, has_ip
    // stays false. The five port-based Tier 4 protocols (CAPWAP/LWAPP/GTP-U) have no fields of
    // their own here -- like every port-based Tier 1-3 protocol, they only ever set
    // protocol/summary/notes, see decoder.cpp's own Tier 4 UDP dispatch.

    // protocol == "mpls" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and mpls.hpp's MplsFrame (including MplsFrame::is_multicast, set by
    // decoder.cpp's own populate_mpls from the matched EtherType, since try_parse_mpls itself has
    // no way to know which of the two EtherTypes matched -- see that struct's own comment). Like
    // EAPOL/PPPoE above, MPLS rides raw Ethernet (EtherType 0x8847 unicast / 0x8848 multicast),
    // not IP -- has_ethernet stays true, has_ip stays false. The fourteen IP-protocol-number/
    // port-based Tier 5 protocols (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP, IKE, VXLAN,
    // Geneve, WireGuard, OpenVPN, dtls-tunnel, STT) have no fields of their own here -- like every
    // port-based Tier 1-4 protocol, they only ever set protocol/summary/notes, see decoder.cpp's
    // own Tier 5 dispatch.

    // ARP (EtherType 0x0806, arp.hpp) is a zero-flat-field migrated protocol (mid-size batch) --
    // see ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the ArpMessage
    // carried by DecodedPacket::result, not here (and were never rendered by any writer even before
    // this migration -- output.cpp has never had an arp_* JSON block, the same finding the cheap
    // batch made for MPLS/PPPoE).

    // LLDP (EtherType 0x88CC, lldp.hpp) is a zero-flat-field migrated protocol (mid-size batch) --
    // see ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the
    // LldpMessage carried by DecodedPacket::result, not here (and were never rendered by any writer
    // even before this migration -- output.cpp has never had an lldp_* JSON block, the same finding
    // as ARP/EAPOL just above).

    // STP is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the StpFrame
    // carried by DecodedPacket::result, not here -- see output.cpp's write_stp_json_fields and
    // stp.hpp's own StpFrame/StpBridgeId/StpMstiMessage. Unlike every EtherType-keyed raw-Ethernet
    // protocol above, STP rides classic IEEE 802.3 LLC framing (has_ethernet stays true, has_ip
    // stays false, src_mac/dst_mac are the only addressing) -- see link_layer.hpp's file header
    // comment for the length-vs-EtherType plumbing this required. StpFrame::port_id_raw is the one
    // field this migration dropped from ever being rendered -- confirmed, like the cheap batch's
    // own vrrp_auth_password finding, that no writer ever read the old flat stp_port_id_raw either.

    // DeviceNet is a zero-flat-field migrated protocol (see ProtocolDecoder/ProtocolResult in
    // protocol_decoder.hpp): its fields live in the DeviceNetFrame carried by
    // DecodedPacket::result, not here -- see output.cpp's write_devicenet_json_fields and
    // devicenet.hpp's own DeviceNetDecoder (the first GateKind::LinkType protocol). Unlike every
    // other protocol this tool decodes, DeviceNet rides a wholly different link layer (CAN, via
    // SocketCAN pcap framing, LINKTYPE_CAN_SOCKETCAN -- see can_socketcan.hpp) rather than
    // Ethernet at all: has_ethernet AND has_ip both stay false for these packets (no MAC addresses,
    // no IP layer -- src_mac/dst_mac/src_ip/dst_ip are all meaningless here), the same "no
    // conventional addressing at all" shape STP's own has_ip==false (but has_ethernet==true, since
    // STP at least still rides Ethernet framing) doesn't quite share -- DeviceNet is the first
    // protocol in this codebase with NEITHER.

    // BACnet/IP is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields (BVLC function, NPDU,
    // APDU, decoded service values) live in the BacnetFrame carried by DecodedPacket::result, not
    // here -- see output.cpp's write_bacnet_json_fields and bacnet.hpp's own BacnetFrame/
    // BacnetNpdu/BacnetApdu. Unlike EtherCAT/PROFINET/GOOSE/SV above, BACnet/IP rides on UDP
    // (conventionally port 47808/0xBAC0, has_ip and has_udp both stay true) -- the same
    // "opportunistic, payload-shape" detection posture as EtherNet/IP CIP I/O (see enip_has_io
    // above).

    // HART-IP is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the HartIpResult
    // carried by DecodedPacket::result, not here -- see output.cpp's write_hartip_json_fields and
    // hartip.hpp's own HartIpResult/HartIpFrame/HartIpPassThrough. HartIpResult::first is the
    // first coalesced message's own HartIpFrame -- see HartIpResult's own comment in hartip.hpp
    // for why only the first message's fields ever fed the rest of DecodedPacket, even before
    // this migration. Unlike every other protocol above, HART-IP is detected identically on BOTH
    // has_tcp and has_udp payloads (conventionally port 5094 for both) -- see hartip.hpp's
    // "structural detection gate" paragraph for why this decoder's own detection anchor here is
    // honestly weaker than most of this codebase's other opportunistic detectors.

    // OPC UA is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the OpcUaResult
    // carried by DecodedPacket::result, not here -- see output.cpp's write_opcua_json_fields and
    // opcua.hpp's own OpcUaResult/OpcUaMessage. OpcUaResult::first is the first coalesced chunk's
    // own OpcUaMessage -- see OpcUaResult's own comment in opcua.hpp for why only the first
    // chunk's fields ever fed the rest of DecodedPacket, even before this migration. OPC UA rides
    // TCP only (no UDP mapping in the spec); its own structural detection gate (a 3-byte ASCII
    // MessageType magic string against a 7-member allowlist) is one of the STRONGEST gates in
    // this codebase -- see opcua.hpp's own confidence comparison.

    // MMS is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields (the full four-layer
    // Session/Presentation/ACSE/MMS decode) live in the MmsFrame carried by
    // DecodedPacket::result, not here -- see output.cpp's write_mms_json_fields and mms.hpp's own
    // MmsFrame. MMS rides the exact same TCP port 102 / TPKT+COTP transport as S7comm (see
    // s7comm.hpp/cotp.hpp) -- S7comm's own single-byte protocol-id gate is always tried first, so
    // this decoder is only ever reached once that has already failed (see decoder.cpp's own
    // dispatch-order comment).

    // MQTT is a zero-flat-field migrated protocol (extra-reader batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields (including the Sparkplug
    // B decode) live in the MqttResult carried by DecodedPacket::result, not here -- see
    // output.cpp's write_mqtt_json_fields and mqtt.hpp's own MqttResult/MqttMessage.
    // MqttResult::first is the first coalesced packet's own MqttMessage -- see MqttResult's own
    // comment in mqtt.hpp for why only the first packet's fields ever fed the rest of
    // DecodedPacket, even before this migration. MQTT rides plain TCP, conventionally port 1883
    // (this decoder's own structural detection gate is honestly weak -- see mqtt.hpp's file header
    // comment -- so it is tried LAST in decoder.cpp's opportunistic TCP dispatch chain, after
    // HART-IP).

    // FF-HSE is a zero-flat-field migrated protocol (see ProtocolDecoder/ProtocolResult in
    // protocol_decoder.hpp): its fields live in the FfhseFrame carried by
    // DecodedPacket::result (DecodedPacket::result->as<FfhseResult>().first), not here -- see
    // output.cpp's write_ffhse_json_fields. FOUNDATION Fieldbus HSE rides EITHER TCP or UDP,
    // conventionally ports 1089/1090/1091/3622 depending on sub-protocol (FDA/SM/FMS/LAN
    // Redundancy), all recorded as "expected port" annotations only (the sub-protocol is signaled
    // in-band via the header, not by port) -- see ffhse.hpp's file header comment for this
    // decoder's own honest comparison of its structural detection gate against this codebase's
    // other opportunistic detectors (it is weaker than even HART-IP's).

    // protocol == "dns"/"mdns"/"llmnr" is a zero-flat-field migrated protocol family (mid-size
    // batch) -- see ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: their fields live in
    // the shared DnsMessage carried by DecodedPacket::result, not here -- see output.cpp's
    // write_dns_json_fields (shared by all three, the same way fill_dns_fields used to be, and for
    // the same reason: all three are the exact same wire format, see dns.hpp's file header comment
    // for exactly what differs between them, reflected only in DnsMessage::header_flags' letters).

    // protocol == "nbns" (NetBIOS Name Service/NBT-NS) is a zero-flat-field migrated protocol
    // (mid-size batch) -- see ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields
    // live in the NbnsMessage carried by DecodedPacket::result, not here -- see output.cpp's
    // write_nbns_json_fields. NbnsMessage's own shape mirrors DnsMessage's exactly (see nbns.hpp).

    // protocol == "doh" is a zero-flat-field migrated protocol -- see DecodedPacket::result and
    // tls_sni.hpp's DohDecoder/DohDetection, and output.cpp's write_doh_json_fields for rendering.

    // protocol == "rip" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and rip.hpp's RipMessage, and output.cpp's write_rip_json_fields
    // (including rip_route_summary, the former decoder.cpp helper of the same name) for rendering.

    // protocol == "icmp" is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the IcmpMessage
    // carried by DecodedPacket::result, not here -- see output.cpp's write_icmp_json_fields
    // (including icmp_router_address_summary, the former decoder.cpp helper of the same name).

    // protocol == "igmp" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and igmp.hpp's IgmpMessage, and output.cpp's write_igmp_json_fields
    // (including igmp_group_record_summary, the former decoder.cpp helper of the same name).

    // protocol == "vrrp" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and vrrp.hpp's VrrpMessage (auth_simple_password, auth_type == 1 only,
    // already redacted by VrrpDecoder::decode when --redact is active -- see
    // DecodeOptions::redact_secrets's own comment), and output.cpp's write_vrrp_json_fields for
    // rendering (deliberately no "vrrp_auth_password" JSON field -- no writer ever rendered the
    // old flat field either).

    // protocol == "hsrp" is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the HsrpMessage
    // carried by DecodedPacket::result (auth_data, v1 only, already redacted by HsrpDecoder::decode
    // when --redact is active -- see DecodeOptions::redact_secrets's own comment), not here -- see
    // output.cpp's write_hsrp_json_fields (deliberately no "hsrp_auth_data" JSON field -- no writer
    // ever rendered the old flat field either, the same finding the cheap batch made for VRRP's own
    // auth_simple_password).

    // protocol == "igrp" is a zero-flat-field migrated protocol (cheap batch) -- see
    // DecodedPacket::result and igrp.hpp's IgrpMessage, and output.cpp's write_igrp_json_fields
    // (including igrp_route_summary, the former decoder.cpp helper of the same name).

    // protocol == "pim" is a zero-flat-field migrated protocol (mid-size batch) -- see
    // ProtocolDecoder/ProtocolResult in protocol_decoder.hpp: its fields live in the PimMessage
    // carried by DecodedPacket::result, not here -- see output.cpp's write_pim_json_fields
    // (including pim_hello_option_summary/pim_jp_group_summary/pim_bsr_group_summary, the former
    // decoder.cpp helpers of the same names). Which of PimMessage's own field groups are populated
    // depends on its type_name; see pim.hpp's own PimMessage for exactly which message type
    // populates which group.

    // EIGRP is a zero-flat-field migrated protocol (see ProtocolDecoder/ProtocolResult in
    // protocol_decoder.hpp): its fields live in the EigrpMessage carried by DecodedPacket::result,
    // not here -- see output.cpp's write_eigrp_json_fields.

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

// Cross-packet DNP3 application-fragment reassembly state used to live here as
// Dnp3FragmentReassembly/Decoder::dnp3_reassembly_/Decoder::process_dnp3_frame (a bespoke struct
// and member dedicated to DNP3 alone). It's now Dnp3ReassemblyState/Dnp3Decoder in dnp3.hpp
// (migration batch 2 -- see protocol_decoder.hpp/protocol_registry.hpp), reached generically
// through Decoder::registry_flow_state_ below.

// Generic per-directional-TCP-flow byte buffer for a Modbus MBAP message, a DNP3 data-link
// frame, or a TPKT/COTP frame whose OWN declared length exceeds what has arrived in the TCP
// segments seen so far for that flow -- see Decoder::tcp_reassembly_ and
// Decoder::reassemble_tcp_payload. This is a different (and lower) layer than DNP3's own
// application-fragment reassembly (Dnp3ReassemblyState, dnp3.hpp): that one reassembles a DNP3
// *application* fragment across several already-complete data-link frames; this one reassembles a
// single PDU/frame's own bytes when one TCP segment doesn't contain all of them. The two compose
// without conflict -- a data-link frame can be completed here, across TCP segments, and then
// Decoder's existing frame-coalescing loop and Dnp3ReassemblyState both still operate on it
// exactly as before, since by the time they run they're just looking at a complete (however it
// got assembled) buffer.
struct TcpFlowBuffer {
    bool active = false;
    std::vector<uint8_t> bytes;  // bytes buffered so far for the in-progress PDU/frame
    uint32_t next_seq = 0;       // TCP sequence number expected to begin the next segment
    size_t segment_count = 0;    // TCP segments contributed to `bytes` so far
};

// Cross-packet Modbus transaction-pairing state used to live here as ModbusPendingRequest/
// Decoder::modbus_pending_ (a bespoke member dedicated to Modbus alone). It's now
// ModbusPendingRequest/ModbusFlowState in modbus.hpp, reached generically through
// Decoder::registry_flow_state_ below -- see protocol_decoder.hpp/protocol_registry.hpp for why
// (registration-model decoder refactor, Stage 2 of the pilot).

// Cross-packet COTP/S7comm reassembly state used to live here as CotpFragmentReassembly/
// Decoder::cotp_reassembly_/Decoder::reassemble_cotp_data_frame (a bespoke member dedicated to
// COTP alone). It's now CotpReassemblyState/CotpDecoder in cotp.hpp (migration batch 2 -- see
// protocol_decoder.hpp/protocol_registry.hpp), reached generically through
// Decoder::registry_flow_state_ below via
// DecodeContext::flow_state<CotpReassemblyState>(FlowStateKeying::DirectionalFlow), the same
// generalization Stage 2 of the pilot already did for Decoder::modbus_pending_ above.

// Cross-packet DNP3 application-fragment reassembly state used to live here as
// Dnp3FragmentReassembly/Decoder::dnp3_reassembly_/Decoder::process_dnp3_frame (a bespoke member
// dedicated to DNP3 alone). It's now Dnp3ReassemblyState/Dnp3Decoder in dnp3.hpp (migration batch
// 2 -- see protocol_decoder.hpp/protocol_registry.hpp), reached generically through
// Decoder::registry_flow_state_ below via
// DecodeContext::flow_state<Dnp3ReassemblyState>(FlowStateKeying::DirectionalFlow) -- the same
// generalization COTP above just went through, and Stage 2 of the pilot did for
// Decoder::modbus_pending_ before that.

class Decoder {
public:
    // Installs options.limits into the process-wide resource_limits() accessor before storing
    // options_, so every in-scope constant site (many with no DecodeContext/options access at
    // all -- see resource_limits.hpp) sees the configured overrides from the very first
    // decode() call. Safe under this codebase's actual usage pattern: every real entry point
    // (the three CLI subcommands, every fuzz harness) constructs exactly one Decoder per
    // process -- see resource_limits.hpp's own comment on set_resource_limits.
    explicit Decoder(DecodeOptions options) : options_(std::move(options)) {
        set_resource_limits(options_.limits);
    }

    // May throw ParseError only when options.strict is true and an
    // Ethernet/IPv4/TCP-layer parse fails; otherwise failures are captured
    // in the returned DecodedPacket's protocol/summary/notes fields.
    //
    // NOTE ON STATEFULNESS: this method is `const` in the sense that every DecodedPacket it
    // returns is still produced deterministically from (a) the packet passed in and (b) whatever
    // cross-packet reassembly state (registry_flow_state_, tcp_reassembly_, ...) earlier calls on
    // THIS Decoder instance left behind -- it is not const/pure in the stronger sense of depending
    // only on its arguments. That only means anything if packets are decoded through one Decoder
    // instance, in strict capture-file order, one at a time -- which is exactly what cli_main.cpp
    // does (a single Decoder per file-decode pass, one sequential while-loop, no concurrency).
    // Decoding the same packet twice on a fresh Decoder, or out of order, will not reproduce
    // reassembly that depended on packets decoded earlier in the file.
    DecodedPacket decode(const PcapPacket& packet, uint32_t link_type, size_t index) const;

private:
    DecodeOptions options_;

    // See TcpFlowBuffer above. Keyed by "src_ip:src_port->dst_ip:dst_port" (one entry per
    // directional TCP flow that has ever needed cross-segment PDU/frame reassembly). `mutable`
    // because it is cross-packet state accumulated across decode() calls, not a function of the
    // current packet alone -- see the NOTE ON STATEFULNESS above for why that is safe here.
    mutable std::unordered_map<std::string, TcpFlowBuffer> tcp_reassembly_;

    // registration-model decoder refactor (see protocol_decoder.hpp/protocol_registry.hpp): one
    // generic per-migrated-protocol flow-state map, replacing what used to require a bespoke
    // Decoder member per stateful protocol (this generalizes the old Decoder::modbus_pending_,
    // which is now ModbusFlowState, reached via DecodeContext::flow_state<T>() -- see modbus.hpp;
    // migration batch 2 generalized Decoder::cotp_reassembly_/Decoder::dnp3_reassembly_ into it
    // the same way, via DecodeContext::flow_state<T>(FlowStateKeying::DirectionalFlow) -- see
    // cotp.hpp/dnp3.hpp). Outer key is FlowStateMap's own protocol_id; `mutable` for the same
    // reason as tcp_reassembly_ above -- cross-packet state accumulated across decode() calls.
    mutable FlowStateMap registry_flow_state_;

    // MQTT's own per-session learned protocol version used to live here as a bespoke
    // mqtt_session_version_ map -- migration batch 2 (Stage 11) moved it into MqttFlowState,
    // reached via registry_flow_state_ above (DecodeContext::flow_state<T>(), session-keyed, the
    // same generalization Stage 2 already did for modbus_pending_) -- see mqtt.hpp.

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
};

}  // namespace conduitscope
