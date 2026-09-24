// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/protocol_registry.hpp"

#include "conduitscope/arp.hpp"
#include "conduitscope/bacnet.hpp"
#include "conduitscope/bgp.hpp"
#include "conduitscope/bsap.hpp"
#include "conduitscope/cclink_ie.hpp"
#include "conduitscope/codesys.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/dcom.hpp"
#include "conduitscope/devicenet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/dns.hpp"
#include "conduitscope/eapol.hpp"
#include "conduitscope/eigrp.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/ethercat.hpp"
#include "conduitscope/ffhse.hpp"
#include "conduitscope/fins.hpp"
#include "conduitscope/ge_srtp.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/hsrp.hpp"
#include "conduitscope/icmp.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/igmp.hpp"
#include "conduitscope/igrp.hpp"
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
#include "conduitscope/pim.hpp"
#include "conduitscope/pppoe.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/s7commplus.hpp"
#include "conduitscope/slow_protocols.hpp"
#include "conduitscope/smb.hpp"
#include "conduitscope/stp.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tls_sni.hpp"
#include "conduitscope/twincat.hpp"
#include "conduitscope/vrrp.hpp"
#include "conduitscope/winrm.hpp"

namespace conduitscope {

const std::vector<const ProtocolDecoder*>& ethertype_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &profinet_decoder(),  // Migration batch 3 -- sits exactly where the old
                            // `if (want_profinet)` block always did: tried FIRST of this whole
                            // cascade, ahead of GOOSE/SV (both migrated below). No ordering
                            // rationale beyond position preservation needed -- EtherType 0x8892
                            // is exclusive to PROFINET RT, no collision possible with any other
                            // EtherType-keyed protocol, migrated or not (see profinet.hpp's file
                            // header comment).
        &goose_decoder(),  // Stage 3 of the pilot -- no ordering rationale needed beyond what its
                            // own decoder.cpp call site's comment already documents: EtherType
                            // 0x88B8 is exclusive to GOOSE, no collision possible with any other
                            // EtherType-keyed protocol (PROFINET/SV/EtherCAT/STP/EAPOL/PPPoE/MPLS),
                            // migrated or not.
        &sv_decoder(),     // Migration batch 3 -- sits exactly where the old `if (want_sv)` block
                            // always did: immediately after GOOSE (migrated above, in the pilot),
                            // before PROFINET/EtherCAT/EAPOL/STP/MPLS/PPPoE (still legacy). No
                            // ordering rationale beyond position preservation needed -- EtherType
                            // 0x88BA is exclusive to SV, no collision possible with any other
                            // EtherType-keyed protocol, migrated or not (same reasoning as GOOSE's
                            // own entry above; SV is its direct sibling, see sv.hpp's file header
                            // comment).
        &ethercat_decoder(),  // Migration batch 3 -- sits exactly where the old
                            // `if (want_ethercat)` block always did: after PROFINET RT/GOOSE/SV
                            // (all migrated above, in this same batch), before EAPOL/STP/MPLS/
                            // PPPoE (still legacy). No ordering rationale beyond position
                            // preservation needed -- EtherType 0x88A4 is exclusive to EtherCAT, no
                            // collision possible with any other EtherType-keyed protocol,
                            // migrated or not (see ethercat.hpp's file header comment's
                            // "structural detection gate" paragraph).
        &eapol_decoder(),  // Migration batch 3 -- sits exactly where the old `if (want_eapol)`
                            // block always did: after PROFINET RT/GOOSE/SV/EtherCAT (all migrated
                            // above, in this same batch), before PPPoE/MPLS/STP (still legacy). No
                            // ordering rationale beyond position preservation needed -- EtherType
                            // 0x888E is exclusive to EAPOL, no collision possible with any other
                            // EtherType-keyed protocol, migrated or not (see eapol.hpp's own
                            // "structural detection gate" paragraph).
        &pppoe_discovery_decoder(),  // Migration batch 3 -- sits exactly where the old
                            // `if (want_pppoe)` block always did: after PROFINET RT/GOOSE/SV/
                            // EtherCAT/EAPOL (all migrated above, in this same batch), before MPLS
                            // (migrated below, in this same batch too)/STP (still legacy). No
                            // ordering rationale beyond position preservation needed -- EtherTypes
                            // 0x8863/0x8864 are exclusive to PPPoE, no collision possible with any
                            // other EtherType-keyed protocol, migrated or not. Shares its "pppoe"
                            // id() with pppoe_session_decoder() immediately below -- see
                            // PppoeDiscoveryDecoder's own comment in pppoe.hpp for why that's safe.
        &pppoe_session_decoder(),    // The Session-stage half of the same `if (want_pppoe)` block
                            // -- see pppoe_discovery_decoder() immediately above.
        &mpls_unicast_decoder(),  // Migration batch 3 -- sits exactly where the old
                            // `if (want_mpls)` block always did: after PROFINET RT/GOOSE/SV/
                            // EtherCAT/EAPOL/PPPoE (all migrated above, in this same batch), before
                            // STP (still legacy, the last protocol left in this whole cascade). No
                            // ordering rationale beyond position preservation needed -- EtherTypes
                            // 0x8847/0x8848 are exclusive to MPLS, no collision possible with any
                            // other EtherType-keyed protocol, migrated or not. Shares its "mpls"
                            // id() with mpls_multicast_decoder() immediately below -- see
                            // MplsUnicastDecoder's own comment in mpls.hpp for why that's safe.
        &mpls_multicast_decoder(),  // The multicast half of the same `if (want_mpls)` block -- see
                            // mpls_unicast_decoder() immediately above.
        &arp_decoder(),    // Added after MPLS, NOT part of migration batch 3 (or any migration) --
                            // ARP is a brand-new protocol added to this cascade afterward, built
                            // directly on ProtocolDecoder from inception (see arp.hpp's file header
                            // comment). EtherType 0x0806 is exclusive to ARP, no collision risk with
                            // anything else in this vector; position here is purely "appended after
                            // the batch, not reasoned about relative to the others" -- see this
                            // vector's own doc comment in protocol_registry.hpp.
        &lldp_decoder(),   // Added after ARP, same posture -- a brand-new protocol, not part of any
                            // migration, built directly on ProtocolDecoder from inception (see
                            // lldp.hpp's file header comment). EtherType 0x88CC is exclusive to LLDP,
                            // no collision risk with anything else in this vector; position here is
                            // purely "appended after ARP, not reasoned about relative to the others".
        &slow_protocols_decoder(),  // Added after the three-stage ARP/LLDP/BGP plan, at Jurgen's
                            // request -- same posture as ARP/LLDP above, a brand-new protocol built
                            // directly on ProtocolDecoder from inception (see slow_protocols.hpp's
                            // file header comment). EtherType 0x8809 is exclusive to it, no
                            // collision risk with anything else in this vector.
        &stp_decoder(),    // Migration batch 3 -- sits exactly where the old `if (want_stp)` block
                            // always did: tried LAST of this whole cascade, after every EtherType-
                            // keyed protocol above (ARP/LLDP/Slow Protocols were all added to this
                            // vector, and to decoder.cpp's own call site, after migration batch 3
                            // completed -- see their own entries above -- so STP has stayed last
                            // through every one of those additions too). Unlike every entry above,
                            // STP has no EtherType of its own at all (see stp_decoder()'s own
                            // comment in stp.hpp) -- its ordering here is purely "last, because it's
                            // LLC-framed, not EtherType-framed, and every EtherType-framed candidate
                            // above must have already failed to match before an LLC-framed one is
                            // even structurally possible" (see decoder.cpp's own call site comment).
                            // Since ethertype() returns nullopt for STP, this cascade's own
                            // registry-driven dispatch loop (decoder.cpp) can never match it via
                            // that loop regardless of where it sits in this vector -- it's listed
                            // here, in its real position, purely for this vector's own audit-trail
                            // completeness (every migrated/added protocol in this GateKind, not just
                            // the ones the loop itself can reach); STP's own gating (LLC DSAP/SSAP/
                            // Control, the GARP destination-MAC carve-out) stays its own explicit
                            // block at decoder.cpp's call site, after the loop, exactly as before.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& ip_protocol_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &icmp_decoder(),   // Migration batch 5 -- sits exactly where the old `if (want_icmp)` block
                            // always did: tried first of this whole cascade. No ordering rationale
                            // beyond position preservation needed -- IP protocol number 1 is
                            // IANA-exclusive to ICMP, no collision possible with any other
                            // IP-protocol-number-keyed protocol, migrated or not.
        &igmp_decoder(),   // Migration batch 5 -- sits exactly where the old `if (want_igmp)` block
                            // always did: after ICMP (migrated above, in this same batch), before
                            // VRRP/IGRP/PIM/EIGRP/OSPF. IP protocol number 2 is IANA-exclusive to
                            // IGMP -- no collision rationale needed, same reasoning as ICMP above.
        &vrrp_decoder(),   // Migration batch 5 -- sits exactly where the old `if (want_vrrp)` block
                            // always did: after ICMP/IGMP (migrated above), before IGRP/PIM/EIGRP/
                            // OSPF. IP protocol number 112 is IANA-exclusive to VRRP.
        &igrp_decoder(),   // Migration batch 5 -- sits exactly where the old `if (want_igrp)` block
                            // always did: after ICMP/IGMP/VRRP (migrated above), before PIM/EIGRP/
                            // OSPF. IP protocol number 9 is IANA-exclusive to IGRP. The one protocol
                            // in this batch whose decode() needs more than the payload bytes -- see
                            // DecodeContext::ip_src_addr's own comment (protocol_decoder.hpp) and
                            // igrp.hpp's file header for why.
        &pim_decoder(),    // Migration batch 5 -- sits exactly where the old `if (want_pim)` block
                            // always did: after ICMP/IGMP/VRRP/IGRP (migrated above), before EIGRP/
                            // OSPF. IP protocol number 103 is IANA-exclusive to PIM.
        &eigrp_decoder(),  // Stage 1 of the pilot -- IP protocol number 88 is IANA-exclusive to
                            // EIGRP, no ordering rationale needed for the same reason GOOSE above
                            // needs none.
        &ospf_decoder(),   // Migration batch 5 -- sits exactly where the old `if (want_ospf)` block
                            // always did: tried last of this whole cascade, after every
                            // IP-protocol-number-keyed protocol above (all seven now migrated, in
                            // this and the pilot's own batches). This completes migration batch 5 --
                            // the IP-protocol-number gate cascade is now fully populated, the fifth
                            // GateKind (after EtherType/TcpPortIndependent/UdpPortIndependent/
                            // CotpPayload) to reach that state. IP protocol number 89 is
                            // IANA-exclusive to OSPF.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& tcp_port_independent_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &opcua_decoder(),    // Migration batch 2 -- sits exactly where the old `if (want_opcua)`
                              // block always did: tried first of all in this cascade, ahead of
                              // EtherNet/IP (still legacy) and everything after it. See
                              // decoder.cpp's own call site comment (and the matching comment in
                              // Decoder::reassemble_tcp_payload) for why OPC UA's own magic-string
                              // detection gate is strong and non-colliding enough that trying it
                              // first costs nothing.
        &enip_tcp_decoder(), // Migration batch 2 -- sits exactly where the old `if (want_enip)`
                              // block always did: after OPC UA (migrated above, in this same
                              // batch), before IEC104. See decoder.cpp's own call site comment
                              // (and the matching comment in Decoder::reassemble_tcp_payload) for
                              // why EtherNet/IP's own three-independent-structural-checks gate is
                              // strong enough that trying it next costs nothing. First protocol in
                              // this codebase to share its id() ("enip") with a second decoder
                              // instance -- see enip_udp_decoder() in udp_port_independent_registry
                              // below, and EnipTcpDecoder's own comment in enip.hpp for why that's
                              // safe (every output writer already dispatches on the plain
                              // DecodedPacket::protocol string, never on registry id() lookup).
        &iec104_decoder(),   // Migration batch 2 -- sits exactly where the old `if (want_iec104)`
                              // block always did: after OPC UA/EtherNet-IP (both migrated above,
                              // in this same batch), before Modbus. See docs/DEVELOPMENT.md's
                              // PROTOCOL DETECTION section for why that position resolves the real
                              // IEC104-vs-Modbus collision found during development (an I-format
                              // APDU with N(S)=N(R)=0 can otherwise coincidentally read as a
                              // plausible Modbus/TCP MBAP header) -- IEC104 must keep running
                              // before Modbus regardless of which of the two has migrated, which
                              // is exactly what decoder.cpp's own linear call-site order
                              // (unaffected by migration, see protocol_decoder.hpp's COEXISTENCE
                              // RULE) already guarantees; this vector's own ordering just mirrors
                              // that for its audit-trail role, see this file's own header comment.
        &melsec_tcp_decoder(),  // Moved to directly BEFORE Modbus (was originally added directly
                              // after TwinCAT) -- a real, reproducible MELSEC-vs-Modbus collision
                              // was found (a genuine MELSEC request with Network No.==PC No.==0 and
                              // a small Request Destination Module I/O No. reads as a plausible
                              // Modbus/TCP MBAP header; Modbus's own decode does not hard-reject the
                              // resulting length mismatch) -- see decoder.cpp's MELSEC call site
                              // comment for the full writeup. MELSEC's own two-part gate (exact
                              // subheader magic + exact declared-length cross-check) is stronger
                              // than Modbus's single protocol-id==0 tell, the same "stronger gate
                              // wins" principle IEC104's own entry above already establishes. First
                              // TCP-side use of the "two instances, one id()" pattern for a protocol
                              // BUILT ENTIRELY on the ProtocolDecoder interface from inception
                              // (TwinCAT is also on this interface but TCP-only; Kerberos/HART-IP/
                              // EtherNet-IP's own TCP+UDP splits predate the interface and were
                              // migrated onto it) -- see melsec_udp_decoder() in
                              // udp_port_independent_registry() below, and MelsecTcpDecoder's own
                              // comment in melsec.hpp for why sharing "melsec" is safe.
        &fins_tcp_decoder(),  // Added directly after MELSEC, before Modbus -- FINS/TCP's own exact
                              // 4-byte ASCII magic ("FINS", offset 0) is as strong a gate as any
                              // protocol in this registry (comparable to OPC UA's own magic-string
                              // gate at the very top), so it cannot collide with Modbus/TCP's own
                              // weak protocol-id==0 tell -- see fins.hpp's file header comment and
                              // decoder.cpp's own FINS call site comment for the full collision
                              // survey. Positioned right after MELSEC purely for locality (both are
                              // recent additions with adjacent file-header commentary), not because
                              // of any collision risk with MELSEC's own gate. Second TCP-side use of
                              // the "two instances, one id()" pattern for a protocol BUILT ENTIRELY
                              // on the ProtocolDecoder interface from inception (MELSEC was the
                              // first) -- see fins_udp_decoder() in udp_port_independent_registry()
                              // below, and FinsTcpDecoder's own comment in fins.hpp for why sharing
                              // "fins" is safe.
        &modbus_decoder(),   // Stage 2 of the pilot -- decoder.cpp's call site sits exactly where
                              // Modbus's old `if (want_modbus)` block always did: after OPC UA/
                              // EtherNet-IP/IEC104/MELSEC/FINS (all now migrated above -- MELSEC and
                              // FINS moved to right before Modbus, see their own entries above),
                              // before TwinCAT/DNP3/COTP (see IEC104's own entry above for the
                              // collision this relative order resolves).
        &twincat_decoder(),  // Added directly after Modbus, before DNP3/S7comm family/HART-IP/
                              // MQTT/FF-HSE -- see decoder.cpp's TwinCAT call site comment for the
                              // full collision survey this position is based on (AMS/TCP's own
                              // multi-field State-Flags/Command-ID/Data-Length gate is stronger
                              // than Modbus's single protocol-id==0 tell, so trying it right after
                              // Modbus costs nothing and cannot be weakened by anything below it).
        &kerberos_tcp_decoder(),  // Added directly after TwinCAT (itself directly after Modbus,
                              // itself directly after MELSEC) -- the first Windows AD-suite
                              // protocol (see kerberos.hpp's file header comment). Its own gate
                              // (a 4-byte length prefix plus one of 7 recognized ASN.1
                              // APPLICATION tag bytes, then a pvno==5/msg-type cross-check on full
                              // decode) doesn't collide with anything above it -- see kerberos.hpp's
                              // COLLISION SURVEY paragraph for the full writeup.
        &ldap_tcp_decoder(),  // Added directly after Kerberos -- the second Windows AD-suite
                              // protocol (see ldap.hpp's file header comment), no UDP sibling. Its
                              // own gate (the outer SEQUENCE/messageID/protocolOp structural check,
                              // reused from it_protocols.hpp's match_ldap_ber, PLUS a per-op
                              // constructed-bit cross-check on full decode) doesn't collide with
                              // Kerberos immediately above it despite 5 numerically-overlapping
                              // APPLICATION tags -- see ldap.hpp's own COLLISION SURVEY paragraph
                              // for the full writeup (Kerberos's gate reads the whole payload's own
                              // leading byte, LDAP's own protocolOp tags never appear there).
        &smb_tcp_decoder(),  // Added directly after LDAP -- the third Windows AD-suite protocol
                              // (see smb.hpp's file header comment), no UDP sibling. Its own gate
                              // (it_protocols.hpp's match_smb_magic, a 4-byte 0xFF/0xFE/0xFD+"SMB"
                              // signature reused as-is from the legacy Tier 2 lateral-movement
                              // check it replaces) is already proven collision-free in this exact
                              // cascade -- no new collision survey needed, see smb.hpp's own
                              // STRUCTURAL DETECTION GATE paragraph.
        &dnp3_decoder(),     // Migration batch 2 -- sits exactly where the old `if (want_dnp3)`
                              // block always did: after Modbus/TwinCAT (both above), before the
                              // COTP/S7comm family below (also still true after COTP's own
                              // migration in this same batch). No ordering rationale beyond
                              // position preservation -- DNP3's data-link magic bytes (0x05 0x64)
                              // don't collide with anything else in this cascade.
        &cotp_decoder(),     // Migration batch 2 -- sits exactly where the old, single
                              // `if (want_s7comm || want_mms || want_s7commplus)` block always did:
                              // after DNP3 (migrated above, in this same batch), before HART-IP
                              // (also migrated in this same batch, immediately below) and MQTT/
                              // FF-HSE (still legacy). See decoder.cpp's own call site comment for
                              // the RDP CR/CC carve-out this position sits right after.
        &hartip_tcp_decoder(),  // Migration batch 2 -- sits exactly where the old `if (want_hartip)`
                              // TCP block always did: after COTP (migrated above, in this same
                              // batch), before MQTT (migrated below, in this same batch too), ahead
                              // of only still-legacy FF-HSE. See decoder.cpp's own call site
                              // comment for the accepted, documented
                              // HART-IP-Session-Initiate-vs-Modbus/TCP collision this position
                              // deliberately does NOT resolve (reordering HART-IP earlier was tried
                              // while scoping this feature and measurably regressed the Modbus/
                              // S7comm test corpus). First TCP-side use of the same "two instances,
                              // one id()" pattern EnipTcpDecoder/EnipUdpDecoder established first --
                              // see hartip_udp_decoder() in udp_port_independent_registry() below,
                              // and HartIpTcpDecoder's own comment in hartip.hpp for why that's
                              // safe.
        &mqtt_decoder(),      // Migration batch 2 -- sits exactly where the old `if (want_mqtt)`
                              // block always did: tried LAST of this whole cascade (after HART-IP,
                              // migrated above in this same batch), ahead of only still-legacy
                              // FF-HSE. See mqtt.hpp's own "structural detection gate" paragraph
                              // for why MQTT's honestly weak single-leading-byte gate earns it the
                              // lowest priority of every migrated protocol in this vector. Its own
                              // per-session learned version hint (MqttFlowState) replaces the
                              // bespoke Decoder::mqtt_session_version_ map, the same generalization
                              // Modbus's own ModbusFlowState already did for modbus_pending_.
        &bgp_decoder(),      // Added after MQTT, NOT part of any migration batch -- a brand-new
                              // protocol added to this cascade afterward, built directly on
                              // ProtocolDecoder from inception (see bgp.hpp's file header comment),
                              // the same "new addition, not a migration" posture ARP/LLDP
                              // established for ethertype_registry() above. decoder.cpp's own call
                              // site sits right after TwinCAT (before Kerberos), not at the end of
                              // this cascade -- this vector's own append-at-the-end position is
                              // purely its audit-trail convention (see this vector's own doc
                              // comment in protocol_registry.hpp), not a claim about dispatch
                              // order. BGP's own structural gate (a 128-bit Marker that MUST be
                              // all-0xFF) is the strongest in this whole codebase, so it cannot
                              // collide with anything else in this cascade regardless of position.
        &codesys_tcp_decoder(),  // A brand-new protocol, NOT part of any migration batch, added
                              // right after BGP/FF-HSE landed -- decoder.cpp's own call site sits
                              // right after MQTT, before FF-HSE (see that entry's own comment
                              // below for why FF-HSE stays last regardless). CODESYS's own Block
                              // Driver-layer gate (a 4-byte exact magic plus a cross-checked Length
                              // field) is strong, TwinCAT-AMS/TCP-strength -- see codesys.hpp's own
                              // file header comment for the full wire format and collision
                              // reasoning.
        &ffhse_tcp_decoder(),  // Migrated after BGP -- decoder.cpp's own call site tries it LAST
                              // of this whole cascade, after MQTT and CODESYS (see that entry's own
                              // comment above), because FF-HSE's own structural detection gate (declared-
                              // length framing plus a small enumerated PDU-type byte) is the
                              // weakest, most collision-prone gate of any protocol in this
                              // cascade -- see decoder.cpp's own FF-HSE TCP call site comment for
                              // the full "tried last of all" rationale. This fully populates this
                              // GateKind: no protocol remains unmigrated in this cascade. First
                              // TCP-side use of the "two instances, one id()" pattern for a
                              // protocol whose UDP sibling ALSO runs its own coalescing loop (see
                              // ffhse_udp_decoder() in udp_port_independent_registry() below, and
                              // FfhseTcpDecoder's/FfhseUdpDecoder's own comments in ffhse.hpp).
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& tcp_port_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &doh_decoder(),  // decoder.cpp's own DoH call site calls it directly (see
                          // protocol_registry.hpp's own doc comment on this vector for why that
                          // call site doesn't iterate it the way EtherType's does). tcp_port()
                          // returns DOH_PORT (443, tls_sni.hpp).
        &winrm_tcp_decoder(),  // decoder.cpp's own WinRM call site likewise calls it directly.
                                 // tcp_port() returns WINRM_PORT (5985, winrm.hpp).
        &dcom_tcp_decoder(),  // decoder.cpp's own DCOM call site likewise calls it directly.
                                // tcp_port() returns DCOM_PORT (135, dcom.hpp).
        &ge_srtp_tcp_decoder(),  // GE SRTP (GE Fanuc/GE Intelligent Platforms PLC protocol),
                                   // joining this gate right after DCOM -- decoder.cpp's own GE
                                   // SRTP call site likewise calls it directly. tcp_port() returns
                                   // GE_SRTP_PORT (18245, ge_srtp.hpp). Port-gated in Auto mode for
                                   // the same "no magic-byte-strength structural gate" reason
                                   // WinRM/DCOM already are -- see ge_srtp.hpp's own file header
                                   // comment's "STRUCTURAL DETECTION GATE" section. Not migrated:
                                   // none -- GE SRTP is this gate's fourth and (so far) last
                                   // protocol and it is migrated.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& udp_port_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &rip_decoder(),    // Migration batch 4 -- this GateKind's first real user (see this
                            // vector's own doc comment in protocol_registry.hpp). Sits exactly
                            // where the old `if (want_rip)` block always did: first of this
                            // cascade, ahead of HSRP/DNS/mDNS/LLMNR/NBT-NS. No ordering rationale
                            // beyond position preservation needed -- unlike the opportunistic
                            // TcpPortIndependent/UdpPortIndependent cascades, every decoder here is
                            // genuinely port-gated (in Auto mode) by its own distinct,
                            // non-overlapping well-known port, so there is no collision to resolve
                            // between any two entries in this vector.
        &hsrp_decoder(),   // Migration batch 4 -- sits exactly where the old `if (want_hsrp)` block
                            // always did: after RIP, before DNS.
        &dns_decoder(),    // Migration batch 4 -- sits exactly where the old `if (want_dns)` block
                            // always did: after HSRP, before mDNS.
        &mdns_decoder(),   // Migration batch 4 -- sits exactly where the old `if (want_mdns)` block
                            // always did: after DNS, before LLMNR. Shares DnsDecoder's own
                            // try_parse_dns_message (a different DnsFlavor, a different id() and
                            // udp_port()) -- see MdnsDecoder's own comment in dns.hpp.
        &llmnr_decoder(),  // Migration batch 4 -- sits exactly where the old `if (want_llmnr)`
                            // block always did: after mDNS, before NBT-NS. Same sharing as mDNS
                            // above -- see LlmnrDecoder's own comment in dns.hpp.
        &nbns_decoder(),   // Migration batch 4 -- sits exactly where the old `if (want_nbns)` block
                            // always did: last of this cascade, after LLMNR.
        &bsap_decoder(),   // BSAP (Bristol Standard Asynchronous/Synchronous Protocol) -- a
                            // brand-new protocol, NOT part of migration batch 4, built entirely on
                            // the ProtocolDecoder interface from inception like TwinCAT/MELSEC/
                            // FINS/GE SRTP. Joins this gate right after NBT-NS, port-gated for the
                            // same "no magic-byte-strength structural gate of its own" reason RIP/
                            // HSRP already are -- see bsap.hpp's own file header comment.
                            // decoder.cpp's own BSAP call site likewise sits right after its NBT-NS
                            // block.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& udp_port_independent_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &enip_udp_decoder(),  // Migration batch 2 -- sits exactly where the old CIP I/O
                                // `if (want_enip_io)` block always did: tried first of the UDP
                                // port-independent cascade (ahead of BACnet, still legacy), same
                                // rationale as its TCP sibling above -- try_parse_cip_io's own
                                // structural check (an exact CPF item type + exact length) is
                                // strong enough to run unconditionally in Auto mode. Shares its
                                // "enip" id() with enip_tcp_decoder() in
                                // tcp_port_independent_registry above -- see that entry's own
                                // comment.
        &bacnet_decoder(),    // Migration batch 2 -- sits exactly where the old `if (want_bacnet)`
                                // UDP block always did: after CIP I/O (migrated above, in this same
                                // batch), before HART-IP (migrated below, in this same batch too).
                                // try_parse_bacnet's own structural check (BVLC Type==0x81 +
                                // Function in a 13-value range) is strong enough to run
                                // unconditionally in Auto mode, the same posture as its neighbors.
                                // Its own id() ("bacnet"), not shared with anything -- the second,
                                // simpler UdpPortIndependent use in this batch, unlike its two
                                // shared-id() neighbors.
        &cclink_ie_decoder(),  // A brand-new protocol, NOT part of migration batch 2, deliberately
                                // placed BEFORE MELSEC (added right below): CCIEFB cyclic data and
                                // SLMP node search/set-IP-address ride the exact same SLMP 3E/4E
                                // outer framing MELSEC's own UDP decoder already parses, and
                                // MELSEC's own decoder treats any command it doesn't recognize as
                                // a structurally-valid "unrecognized command" frame rather than
                                // rejecting it -- so a real CCIEFB/node-search/set-IP request would
                                // otherwise be silently swallowed and mislabeled "melsec". This
                                // decoder's own request-side gate (exact command-code match, on
                                // top of MELSEC's own subheader+length cross-check) is strictly
                                // more specific, and MELSEC's own command table never uses
                                // 0x0E70/0x0E30/0x0E31, so this ordering is safe by construction --
                                // see cclink_ie.hpp's own "DISPATCH ORDER" section and
                                // decoder.cpp's own CC-Link IE call site comment.
        &codesys_udp_decoder(),  // A brand-new protocol, NOT part of migration batch 2, joining
                                // this gate right after CC-Link IE. Its own Datagram-layer header
                                // (exact Magic 0xC5, ServiceId one of five values, AddressLengths
                                // exactly 0x43/0x34 -- three independently-constrained fields) is
                                // strong enough to run unconditionally in Auto mode, and no
                                // byte-for-byte collision with CC-Link IE, MELSEC, FINS, BACnet, or
                                // any protocol below was found during this decoder's own scoping --
                                // see codesys.hpp's own file header comment. Shares its "codesys"
                                // id() with codesys_tcp_decoder() in tcp_port_independent_registry
                                // above.
        &melsec_udp_decoder(),  // Added after BACnet/IP and CIP I/O, deliberately BEFORE HART-IP --
                                // see decoder.cpp's MELSEC UDP call site comment for why: HART-IP's
                                // own weak 3-condition UDP gate (MessageType/MessageID at payload
                                // bytes 1/2 both small enumerated values, MsgLength >= 8) is
                                // incidentally satisfied by real MELSEC 3E/4E traffic often enough
                                // to matter, so MELSEC's own much stronger two-part gate (exact
                                // subheader magic + exact declared-length cross-check) must run
                                // first -- discovered via this protocol's own required manual smoke
                                // test. Shares its "melsec" id() with melsec_tcp_decoder() in
                                // tcp_port_independent_registry above -- see that entry's own
                                // comment.
        &fins_udp_decoder(),  // Added directly after MELSEC, deliberately BEFORE HART-IP -- see
                                // decoder.cpp's FINS UDP call site comment for why: FINS's own byte[1]
                                // is always RSV=0x00 (satisfies HART-IP's own MessageType==0
                                // condition) and byte[2] is GCT, which real devices do not reliably
                                // keep at the conventional 0x07 (a live probe observed 0x02, which
                                // DOES satisfy HART-IP's own MessageID-in-{0,1,2,3} condition) -- so,
                                // like MELSEC just above, FINS's own stronger multi-field gate (no
                                // magic bytes, but a 17-command allowlist plus four independent
                                // structural checks) is tried first as a defensive measure, the same
                                // "stronger gate wins" principle MELSEC's own entry above already
                                // establishes. Shares its "fins" id() with fins_tcp_decoder() in
                                // tcp_port_independent_registry above -- see that entry's own comment.
        &hartip_udp_decoder(),  // Migration batch 2 -- originally sat exactly where the old
                                // `if (want_hartip)` UDP block always did: after CIP I/O and BACnet/
                                // IP. Now also tried after MELSEC and FINS (both added later, see
                                // their own entries for why they had to move ahead of HART-IP here). Excludes
                                // ports 4500 (IKE NAT-T) and 4789 (VXLAN) from even being attempted
                                // -- see hartip_udp_excluded_port in hartip.hpp for why that's a hard
                                // exclusion rather than a mere deprioritization. Shares its "hartip"
                                // id() with hartip_tcp_decoder() in tcp_port_independent_registry
                                // above -- see that entry's own comment.
        &kerberos_udp_decoder(),  // Added after HART-IP -- Kerberos's own UDP
                                // path, see kerberos.hpp's file header comment. Shares its
                                // "kerberos" id() with kerberos_tcp_decoder() in
                                // tcp_port_independent_registry above.
        &ffhse_udp_decoder(),   // Added after Kerberos -- FF-HSE's own UDP path, shares its
                                // "ffhse" id() with ffhse_tcp_decoder() in
                                // tcp_port_independent_registry above. Tried LAST of this whole
                                // cascade (even after HART-IP/Kerberos) -- decoder.cpp's own UDP
                                // call site comment gives the same "weakest, most collision-prone
                                // gate in this cascade" rationale its TCP sibling's entry above
                                // documents. UNLIKE every other UDP-side entry in this vector,
                                // FfhseUdpDecoder::decode() runs its own multi-PDU coalescing loop
                                // (FF-HSE's own UDP framing can carry several concatenated PDUs
                                // per datagram) -- see ffhse.hpp's class comment.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& cotp_payload_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &s7comm_decoder(),       // Tried first -- classic S7comm's own protocol-id byte (0x32) is
                                   // this whole family's strongest, cheapest single-byte gate.
        &s7comm_plus_decoder(),  // Tried next, purely for file-organization reasons (S7comm and
                                   // S7comm-Plus are conceptually "the same vendor's two
                                   // generations") -- disambiguated from S7comm by its own,
                                   // different protocol-id byte (0x72), so there is no detection-
                                   // strength reason it couldn't run first instead.
        &mms_decoder(),          // Tried last -- S7comm's single-byte protocol-id gate is tried
                                   // first since it is materially stronger and cheaper; this is
                                   // only reached once that (and S7comm-Plus's) has already failed.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& link_type_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &devicenet_decoder(),  // This gate's only protocol -- decoder.cpp's own
                                 // LINKTYPE_CAN_SOCKETCAN branch calls it directly (see
                                 // protocol_registry.hpp's own doc comment on this vector for why
                                 // that branch doesn't iterate this vector the way EtherType's
                                 // does). link_type() returns LINKTYPE_CAN_SOCKETCAN (227, see
                                 // pcap_reader.hpp) -- see devicenet.hpp's own class comment for
                                 // the deliberate, documented exception to the "decode() never
                                 // throws" contract this decoder takes (it re-parses the raw
                                 // ByteSpan into a CanSocketcanFrame internally, which can throw
                                 // ParseError on a malformed capture record, exactly mirroring
                                 // what decoder.cpp's own call site did directly before this
                                 // migration).
    };
    return order;
}

}  // namespace conduitscope
