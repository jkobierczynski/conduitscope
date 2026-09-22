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

// Migrated EtherType-gated protocols, in the order their decoder.cpp call sites run. Fully
// populated as of migration batch 3 -- the only one of the four cascades to reach that state so
// far: PROFINET RT, GOOSE (Stage 3 of the pilot), SV (GOOSE's own direct sibling, see sv.hpp's
// file header comment), EtherCAT, EAPOL, PPPoE (two EtherTypes, one id(), see pppoe.hpp), MPLS
// (likewise two EtherTypes, one id(), see mpls.hpp), STP (no EtherType of its own at all -- LLC-
// framed, see stp.hpp's own comment on its ProtocolDecoder wrapper). Every protocol here migrated
// in migration batch 3 except GOOSE itself (the pilot). ARP was added to this vector afterward,
// NOT as part of migration batch 3 or any other migration -- it is a brand-new protocol built
// directly on ProtocolDecoder from inception (see arp.hpp), the same "new addition, not a
// migration" posture TwinCAT/MELSEC/FINS established for their own cascades. LLDP was added right
// after ARP, same posture (see lldp.hpp).
const std::vector<const ProtocolDecoder*>& ethertype_registry();

// Migrated IP-protocol-number-gated protocols, in the order their decoder.cpp call sites run. Fully
// populated as of migration batch 5 -- the fifth of the six GateKinds to reach that state (see
// ethertype_registry() above for the fourth, EtherType, and udp_port_independent_registry()/
// cotp_payload_registry() below for the other two batch-2-completed ones): ICMP, IGMP, VRRP, IGRP,
// PIM, EIGRP (Stage 1 of the pilot), OSPF. IGRP is the one protocol in this list whose decode()
// needs more than the payload bytes -- see DecodeContext::ip_src_addr's own comment
// (protocol_decoder.hpp) and igrp.hpp's file header for why.
const std::vector<const ProtocolDecoder*>& ip_protocol_registry();

// Migrated TCP-port-independent protocols, in the order their decoder.cpp call sites run.
// Populated: MELSEC (TCP side only -- see udp_port_independent_registry() below for its UDP sibling,
// sharing this same id() -- a brand-new protocol built entirely on this interface from inception,
// like TwinCAT, see melsec.hpp; tried BEFORE Modbus, moved there after a real MELSEC-vs-Modbus
// collision was found -- see decoder.cpp's MELSEC call site comment), FINS (TCP side only -- see
// udp_port_independent_registry() below for its UDP sibling, sharing this same id() -- another
// brand-new protocol built entirely on this interface from inception, tried right after MELSEC and
// also BEFORE Modbus thanks to its own exact 4-byte magic, see fins.hpp), Modbus (Stage 2 of the
// pilot), TwinCAT, Kerberos
// (TCP side only -- see udp_port_independent_registry() below for its UDP sibling, sharing this
// same id() -- the first Windows AD-suite protocol, see kerberos.hpp), LDAP (the second Windows
// AD-suite protocol, no UDP sibling -- see ldap.hpp), SMB (the third Windows AD-suite protocol, no
// UDP sibling -- see smb.hpp; its own NTLM sub-decode, ntlm.hpp, has no ProtocolDecoder or registry
// entry of its own, see that file's header comment), OPC UA, EtherNet/IP (TCP side only -- see
// udp_port_independent_registry() below for its UDP CIP I/O sibling, sharing this same id()),
// IEC104, DNP3, COTP, HART-IP (TCP side only -- see udp_port_independent_registry() below for its
// UDP sibling, sharing this same id()), MQTT (migration batch 2 -- see decoder.cpp's call site
// comment for exactly why each sits where it does relative to Modbus and to the still-legacy
// protocols around it). BGP was added to this vector afterward, NOT as part of any migration
// batch -- like ARP/LLDP in ethertype_registry() above, it's a brand-new protocol built directly
// on ProtocolDecoder from inception (see bgp.hpp), appended after Modbus/TwinCAT (see
// decoder.cpp's own BGP call site comment for why its Marker-based structural gate needs no
// ordering rationale at all). Not migrated: FF-HSE -- the only protocol left in this whole
// cascade, tried last of all (see decoder.cpp's own dispatch-order comment), out of scope for
// this batch.
const std::vector<const ProtocolDecoder*>& tcp_port_independent_registry();

// Migrated UDP-port-gated protocols, in the order their decoder.cpp call sites run. This GateKind
// went unpopulated by the pilot and by every batch through batch 3 (TwinCAT is
// TcpPortIndependent; batches 1-3 never touched a port-only-gated protocol at all) -- migration
// batch 4 is this vector's first real user, and ProtocolDecoder::udp_port()'s first real use too
// (added in that same batch). Fully populated in true call-site order: RIP, HSRP, DNS, mDNS,
// LLMNR, NBT-NS. DNS/mDNS/LLMNR share one parser, try_parse_dns_message -- see DnsDecoder's own
// comment in dns.hpp for why that's three classes, not one.
const std::vector<const ProtocolDecoder*>& udp_port_registry();

// Migration batch 2 addition: migrated UDP-port-INDEPENDENT protocols (GateKind::UdpPortIndependent
// -- see protocol_decoder.hpp), the UDP-side mirror of tcp_port_independent_registry() above.
// Populated: EtherNet/IP's own CIP I/O UDP path (EnipUdpDecoder, enip.hpp -- shares its "enip"
// id() with enip_tcp_decoder() in tcp_port_independent_registry() above; see that entry's own
// comment for why), BACnet/IP (BacnetDecoder, bacnet.hpp -- its own id(), no sharing), MELSEC's own
// UDP path (MelsecUdpDecoder, melsec.hpp -- shares its "melsec" id() with melsec_tcp_decoder() in
// tcp_port_independent_registry() above), FINS's own UDP path (FinsUdpDecoder, fins.hpp -- shares
// its "fins" id() with fins_tcp_decoder() in tcp_port_independent_registry() above), HART-IP's own
// UDP path (HartIpUdpDecoder, hartip.hpp -- shares its "hartip" id() with hartip_tcp_decoder() in
// tcp_port_independent_registry() above, the same pattern EnipUdpDecoder/EnipTcpDecoder established
// first), and Kerberos's own UDP path (KerberosUdpDecoder, kerberos.hpp -- shares its "kerberos"
// id() with kerberos_tcp_decoder() in tcp_port_independent_registry() above, the same shared-id()
// pattern). Lists all six in decoder.cpp's real UDP dispatch order (CIP I/O, then BACnet/IP, then
// MELSEC, then FINS, then HART-IP, then Kerberos), matching tcp_port_independent_registry()'s own
// "keep migrated entries in real relative order" convention. MELSEC and FINS are both deliberately
// tried BEFORE HART-IP despite being added later -- HART-IP's own weak UDP structural gate
// (MessageType/MessageID at payload bytes 1/2 both small enumerated values, MsgLength >= 8) is
// incidentally satisfied by real MELSEC 3E/4E traffic often enough to matter, and has a partial
// byte-layout overlap with FINS's own RSV/GCT bytes too (see fins.hpp's own collision survey), so
// both protocols' own much stronger gates must run first -- see melsec.hpp/melsec.cpp and
// fins.hpp/fins.cpp plus the matching decoder.cpp call-site comments for the full collision
// analysis, discovered via each protocol's own required manual smoke test.
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
