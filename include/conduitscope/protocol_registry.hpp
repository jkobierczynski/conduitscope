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
// Populated: Modbus (Stage 2), TwinCAT (see decoder.cpp's call site comment for exactly why it
// sits where it does relative to Modbus and to the still-legacy protocols around it). Not
// migrated: OPC UA, EtherNet/IP, IEC104, DNP3, S7comm/MMS/S7comm-Plus (TPKT/COTP), HART-IP, MQTT,
// FF-HSE.
const std::vector<const ProtocolDecoder*>& tcp_port_independent_registry();

// Reserved for a future migrated UDP-port-gated protocol (DNS/mDNS/LLMNR/NBT-NS/HSRP/RIP today).
// No protocol in this gate group is migrated by the pilot or by TwinCAT (TwinCAT is
// TcpPortIndependent) -- kept here, empty, for the same reason the other three are populated
// early: so a later addition to this group has an obvious, already-named place to register into,
// rather than inventing the fourth vector at that point.
const std::vector<const ProtocolDecoder*>& udp_port_registry();

}  // namespace conduitscope
