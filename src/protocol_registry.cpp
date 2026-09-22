// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/protocol_registry.hpp"

#include "conduitscope/bacnet.hpp"
#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/dns.hpp"
#include "conduitscope/eapol.hpp"
#include "conduitscope/eigrp.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/ethercat.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/hsrp.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/kerberos.hpp"
#include "conduitscope/ldap.hpp"
#include "conduitscope/melsec.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/mpls.hpp"
#include "conduitscope/mqtt.hpp"
#include "conduitscope/nbns.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/pppoe.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/rip.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/s7commplus.hpp"
#include "conduitscope/smb.hpp"
#include "conduitscope/stp.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/twincat.hpp"

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
        &stp_decoder(),    // Migration batch 3 -- sits exactly where the old `if (want_stp)` block
                            // always did: tried LAST of this whole cascade, after every EtherType-
                            // keyed protocol above (all seven now migrated, in this and the pilot's
                            // own batches). This completes migration batch 3 -- the EtherType/LLC
                            // gate cascade is now fully populated, the fourth GateKind (after
                            // IpProtocol/TcpPortIndependent/UdpPortIndependent) to reach that
                            // state. Unlike every entry above, STP has no EtherType of its own at
                            // all (see stp_decoder()'s own comment in stp.hpp) -- its ordering here
                            // is purely "last, because it's LLC-framed, not EtherType-framed, and
                            // every EtherType-framed candidate above must have already failed to
                            // match before an LLC-framed one is even structurally possible" (see
                            // decoder.cpp's own call site comment).
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& ip_protocol_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &eigrp_decoder(),  // Stage 1 of the pilot -- IP protocol number 88 is IANA-exclusive to
                            // EIGRP, no ordering rationale needed for the same reason GOOSE above
                            // needs none.
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
        &modbus_decoder(),   // Stage 2 of the pilot -- decoder.cpp's call site sits exactly where
                              // Modbus's old `if (want_modbus)` block always did: after OPC UA/
                              // EtherNet-IP/IEC104 (all three migrated above, in this same batch),
                              // before TwinCAT/DNP3/COTP (see IEC104's own entry above for the
                              // collision this relative order resolves).
        &twincat_decoder(),  // Added directly after Modbus, before DNP3/S7comm family/HART-IP/
                              // MQTT/FF-HSE -- see decoder.cpp's TwinCAT call site comment for the
                              // full collision survey this position is based on (AMS/TCP's own
                              // multi-field State-Flags/Command-ID/Data-Length gate is stronger
                              // than Modbus's single protocol-id==0 tell, so trying it right after
                              // Modbus costs nothing and cannot be weakened by anything below it).
        &melsec_tcp_decoder(),  // Added directly after TwinCAT -- see decoder.cpp's MELSEC call
                              // site comment for the full collision-survey rationale (comparably
                              // strong multi-field structural gate: subheader magic + a
                              // declared-length cross-check). First TCP-side use of the "two
                              // instances, one id()" pattern for a protocol BUILT ENTIRELY on the
                              // ProtocolDecoder interface from inception (TwinCAT is also on this
                              // interface but TCP-only; Kerberos/HART-IP/EtherNet-IP's own TCP+UDP
                              // splits predate the interface and were migrated onto it) -- see
                              // melsec_udp_decoder() in udp_port_independent_registry() below, and
                              // MelsecTcpDecoder's own comment in melsec.hpp for why sharing "melsec"
                              // is safe.
        &kerberos_tcp_decoder(),  // Added directly after MELSEC (itself directly after TwinCAT) --
                              // the first Windows AD-suite
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
        &hartip_udp_decoder(),  // Migration batch 2 -- originally sat exactly where the old
                                // `if (want_hartip)` UDP block always did: after CIP I/O and BACnet/
                                // IP. Now also tried after MELSEC (added later, see that entry's own
                                // comment for why it had to move ahead of HART-IP here). Excludes
                                // ports 4500 (IKE NAT-T) and 4789 (VXLAN) from even being attempted
                                // -- see hartip_udp_excluded_port in hartip.hpp for why that's a hard
                                // exclusion rather than a mere deprioritization. Shares its "hartip"
                                // id() with hartip_tcp_decoder() in tcp_port_independent_registry
                                // above -- see that entry's own comment.
        &kerberos_udp_decoder(),  // Added after HART-IP -- Kerberos's own UDP
                                // path, see kerberos.hpp's file header comment. Shares its
                                // "kerberos" id() with kerberos_tcp_decoder() in
                                // tcp_port_independent_registry above.
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

}  // namespace conduitscope
