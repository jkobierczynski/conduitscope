// SPDX-License-Identifier: Apache-2.0
// protocol_registry.hpp - the ordered, hand-maintained list of which protocols have been migrated
// onto the ProtocolDecoder interface (protocol_decoder.hpp), one std::vector per decoder.cpp
// dispatch cascade (EtherType / IP-protocol-number / TCP-port-independent / UDP-port).
//
// THIS IS DATA, NOT CONTROL FLOW, AND IT IS NOT WHAT DRIVES DISPATCH ORDER DURING THE PILOT. Each
// migrated protocol's actual decoder.cpp call site still sits at its own exact former textual
// position (see protocol_decoder.hpp's "COEXISTENCE RULE"); these vectors exist purely as the
// audit trail a fully-registry-driven dispatch would eventually read from, kept accurate and
// ordered from day one so that transition -- if it ever happens for a whole cascade -- is a
// mechanical "iterate this vector instead of the hand-written if-chain" change, not a rediscovery
// of what order 44 protocols need to run in. Read docs/DEVELOPMENT.md's PROTOCOL DETECTION section
// before reordering anything here; every entry's ordering rationale is commented at its own
// decoder.cpp call site (the actual source of truth while dispatch stays call-site-driven) and,
// for a genuinely new addition like TwinCAT, restated here too.
#pragma once

#include <vector>

#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// Migrated EtherType-gated protocols, in the order their decoder.cpp call sites run. Populated:
// GOOSE (Stage 3 of the pilot). Not migrated (still legacy if-chains, in this relative order):
// PROFINET RT, SV, EtherCAT, STP, EAPOL, PPPoE, MPLS.
const std::vector<const ProtocolDecoder*>& ethertype_registry();

// Migrated IP-protocol-number-gated protocols. Populated: EIGRP (Stage 1). Not migrated: ICMP,
// IGMP, VRRP, IGRP, PIM, OSPF.
const std::vector<const ProtocolDecoder*>& ip_protocol_registry();

// Migrated TCP-port-independent protocols, in the order their decoder.cpp call sites run.
// Populated: Modbus (Stage 2 of the pilot), TwinCAT, Kerberos (TCP side only -- see
// udp_port_independent_registry() below for its UDP sibling, sharing this same id() -- the first
// Windows AD-suite protocol, see kerberos.hpp), LDAP (the second Windows AD-suite protocol, no UDP
// sibling -- see ldap.hpp), SMB (the third Windows AD-suite protocol, no UDP sibling -- see
// smb.hpp; its own NTLM sub-decode, ntlm.hpp, has no ProtocolDecoder or registry entry of its own,
// see that file's header comment), OPC UA, EtherNet/IP (TCP side only -- see
// udp_port_independent_registry() below for its UDP CIP I/O sibling, sharing this same id()),
// IEC104, DNP3, COTP, HART-IP (TCP side only -- see udp_port_independent_registry() below for its
// UDP sibling, sharing this same id()), MQTT (migration batch 2 -- see decoder.cpp's call site
// comment for exactly why each sits where it does relative to Modbus and to the still-legacy
// protocols around it). Not migrated: FF-HSE -- the only protocol left in this whole cascade,
// tried last of all (see decoder.cpp's own dispatch-order comment), out of scope for this batch.
const std::vector<const ProtocolDecoder*>& tcp_port_independent_registry();

// Reserved for a future migrated UDP-port-gated protocol (DNS/mDNS/LLMNR/NBT-NS/HSRP/RIP today).
// No protocol in this gate group is migrated by the pilot or by TwinCAT (TwinCAT is
// TcpPortIndependent) -- kept here, empty, for the same reason the other three are populated
// early: so a later addition to this group has an obvious, already-named place to register into,
// rather than inventing the fourth vector at that point.
const std::vector<const ProtocolDecoder*>& udp_port_registry();

// Migration batch 2 addition: migrated UDP-port-INDEPENDENT protocols (GateKind::UdpPortIndependent
// -- see protocol_decoder.hpp), the UDP-side mirror of tcp_port_independent_registry() above.
// Populated: EtherNet/IP's own CIP I/O UDP path (EnipUdpDecoder, enip.hpp -- shares its "enip"
// id() with enip_tcp_decoder() in tcp_port_independent_registry() above; see that entry's own
// comment for why), BACnet/IP (BacnetDecoder, bacnet.hpp -- its own id(), no sharing), HART-IP's
// own UDP path (HartIpUdpDecoder, hartip.hpp -- shares its "hartip" id() with hartip_tcp_decoder()
// in tcp_port_independent_registry() above, the same pattern EnipUdpDecoder/EnipTcpDecoder
// established first). Lists all three in decoder.cpp's real UDP dispatch order (CIP I/O, then
// BACnet/IP, then HART-IP), matching tcp_port_independent_registry()'s own "keep migrated entries
// in real relative order" convention. Also populated: Kerberos's own UDP path
// (KerberosUdpDecoder, kerberos.hpp -- shares its "kerberos" id() with kerberos_tcp_decoder() in
// tcp_port_independent_registry() above, the same shared-id() pattern), registered after HART-IP.
const std::vector<const ProtocolDecoder*>& udp_port_independent_registry();

// Migration batch 2 addition: S7comm/S7comm-Plus/MMS (GateKind::CotpPayload -- see
// protocol_decoder.hpp). THIS VECTOR IS AUDIT-TRAIL DATA ONLY, even more so than the other four
// above -- decoder.cpp's single COTP/S7comm-family call site does NOT iterate it (each of the
// three riders' dual-write logic differs too much to generalize into one loop without real loss of
// clarity), it still calls each rider's decode() explicitly, in the exact fixed try-order this
// vector documents ("file-organization, not detection-strength" -- see decoder.cpp's own comment).
// Kept here anyway so this gate group has the same audit trail every other one does. Not migrated:
// none -- this batch migrates all three.
const std::vector<const ProtocolDecoder*>& cotp_payload_registry();

}  // namespace conduitscope
