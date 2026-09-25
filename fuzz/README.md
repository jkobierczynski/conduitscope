# Fuzzing

libFuzzer harnesses for the parsers with the most hand-rolled length/state-machine
logic in this codebase. The original five (pcap_reader, TCP reassembly, DNP3,
COTP/S7comm, MQTT) -- see docs/DEVELOPMENT.md's "External code review and
engineering priorities" section for why these were picked first -- were joined by
a second wave of four (BACnet/IP, IEC 104, EtherNet/IP+CIP, S7comm-Plus): the next
highest hand-rolled-parsing-complexity OT/ICS protocols in this codebase, added
once every protocol gained its own standalone `try_parse_*` entry point taking a
`ByteSpan`, making a dedicated harness for any of them a small, mechanical
addition. BACnet in particular already had a confirmed payoff before it got its
own harness: `fuzz_packet_decode` found a real signed-left-shift undefined-behavior
bug in `bacnet.cpp`, fixed before this dedicated, faster-reaching harness existed.
Each harness is a thin `LLVMFuzzerTestOneInput` wrapper around a small piece of
real production code from `conduitscope_core` -- no parsing logic is duplicated
here. A third wave of eight joined those nine: five GateKind::TcpPort decoders
parsed directly off a raw TCP payload on a specific port (DCOM, DICOM, Fox,
GE SRTP, WinRM), the two AMQP wire formats that share one TCP port and one
connection-preamble parser (AMQP 0-9-1, AMQP 1.0 -- each of their two harnesses
also drives the shared preamble parser directly, so no separate ninth harness
was needed for it; see fuzz_amqp091.cpp's own file header for the full
reasoning), and the DNS-over-HTTPS TLS-SNI detector. Same shape, same house
style: a thin wrapper around the real, standalone entry point(s) each protocol's
own decode() already calls.

A systematic hardening pass then closed out the remaining gap: every protocol
decoder in the codebase without a dedicated harness got one, following the
exact same pattern. This landed in six more waves: the eight `GateKind::
IpProtocol` decoders dispatched directly off the IP payload by protocol number
(ICMP, ICMPv6, IGMP, IGRP, OSPF, PIM, VRRP, EIGRP); eleven more UDP/EtherType-
gated decoders (BSAP, CC-Link IE, CoAP, DHCPv6, DNS/mDNS/LLMNR, HSRP, NBNS,
POWERLINK, QUIC, RIP, RMCP); thirteen `GateKind::TcpPortIndependent` decoders
including Modbus itself plus six dual TCP+UDP protocol modules and MMS (BGP,
LDAP, Modbus, OPC UA, SMB, TwinCAT, CODESYS, FF-HSE, FINS, HART-IP, Kerberos,
MELSEC, MMS); the thirteen remaining `GateKind::EtherType` decoders, including
two (CDP, STP) that ride 802.2 LLC/SNAP framing instead of a plain EtherType
(ARP, CDP, EAPOL, EtherCAT, GOOSE, HomePlug AV, LLDP, MPLS, PPPoE, PROFINET,
Slow Protocols, STP, Sampled Values); the six `GateKind::LinkType` decoders for
non-Ethernet captures -- SocketCAN and IEEE 802.15.4 (CAN/SocketCAN framing,
CANopen, DeviceNet, IEEE 802.15.4, J1939, Zigbee); and the Windows Active
Directory / DCE-RPC suite (the shared DCE/RPC envelope, NTLM, and the five
named-pipe RPC interfaces built on top of it: Netlogon, SAMR, LSARPC, SRVSVC,
WKSSVC, DRSUAPI). No functional bugs were found by this pass -- every decoder
already handled adversarial input correctly -- but the codebase's fuzz coverage
is now exhaustive: every protocol module with a real parsing entry point has
its own dedicated harness.

## Building

Requires Clang (libFuzzer is a Clang/compiler-rt feature; GCC cannot build these
targets -- `CONDUITSCOPE_ENABLE_FUZZING` fails the CMake configure step under any
other compiler). On Debian/Ubuntu, the fuzzer and sanitizer runtimes are a separate
package from the compiler itself:

```sh
sudo apt-get install clang libclang-rt-<version>-dev   # e.g. libclang-rt-18-dev
```

```sh
cmake -S . -B build-fuzz \
  -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_COMPILER=clang++ \
  -DCONDUITSCOPE_ENABLE_FUZZING=ON
cmake --build build-fuzz -j"$(nproc)"
```

This builds seventy-six executables directly in `build-fuzz/` (not a `fuzz/` subdirectory
of it -- despite the name, these targets have no `RUNTIME_OUTPUT_DIRECTORY`
override in `CMakeLists.txt`, so they land wherever every other target in this
build tree does):

| Binary                       | Fuzzes                                                              | Seed corpus                  |
|-------------------------------|----------------------------------------------------------------------|-------------------------------|
| `fuzz_pcap_reader`            | `PcapReader` -- classic pcap AND pcapng file-format parsing          | `fuzz/corpus/pcap_reader/`    |
| `fuzz_packet_decode`          | `Decoder::decode()`, the full dispatch pipeline, over a *sequence* of packets fed to one `Decoder` instance -- this is what exercises `Decoder::reassemble_tcp_payload` (TCP segment reassembly) and every other cross-packet, per-flow state (DNP3 fragment reassembly, COTP/S7comm chaining, MQTT session-version tracking, Modbus transaction pairing) | `fuzz/corpus/packet_decode/`  |
| `fuzz_dnp3`                    | `try_parse_dnp3_link_layer` + `try_parse_dnp3_transport_and_application` (single-TCP-payload DNP3 link/transport/application parsing) | `fuzz/corpus/dnp3/`           |
| `fuzz_cotp_s7comm`             | `try_parse_tpkt_cotp` + `try_parse_s7comm` (TPKT/COTP framing, then S7comm on its user data) | `fuzz/corpus/cotp_s7comm/`    |
| `fuzz_mqtt`                     | `try_parse_mqtt_message` (MQTT v3.1/v3.1.1/v5, including Sparkplug B) | `fuzz/corpus/mqtt/`           |
| `fuzz_bacnet`                  | `try_parse_bacnet` (BVLC Annex J framing + the self-describing application-layer TLV tag encoding, ASHRAE 135 clause 20.2.1) | `fuzz/corpus/bacnet/`         |
| `fuzz_iec104`                  | `try_parse_iec104_apci` + `decode_iec104_asdu` (the fixed 6-byte APCI, then an I-format frame's type-keyed ASDU object table) | `fuzz/corpus/iec104/`         |
| `fuzz_enip`                    | `try_parse_enip` + `try_parse_cip_io` (EtherNet/IP encapsulation + CIP explicit messaging with EPATH/service-code recursion, and CIP I/O implicit messaging, both in one harness since they're independent entry points over two different transports) | `fuzz/corpus/enip/`           |
| `fuzz_s7comm_plus`             | `try_parse_tpkt_cotp` + `try_parse_s7comm_plus` (TPKT/COTP framing, then S7comm-Plus's object-oriented, unofficial/community-reverse-engineered application layer on its user data) | `fuzz/corpus/s7comm_plus/`    |
| `fuzz_dcom`                    | `try_parse_dcom` (raw DCE/RPC-over-TCP/135 framing via dcerpc.hpp's `parse_dcerpc_chain`, then DCOM's own bind/bind_ack/request-response interface-and-opnum recognition on top) | `fuzz/corpus/dcom/`           |
| `fuzz_dicom`                   | `try_parse_dicom_pdu` (DICOM upper-layer PDU framing: ASSOCIATE-RQ/AC/RJ, P-DATA-TF, A-RELEASE/A-ABORT) + `decode_dicom_command_set` + `decode_dicom_data_set` (the tag-table decoders a reassembled Command Set/Data Set is handed to, called directly on the same input for independent coverage) | `fuzz/corpus/dicom/`          |
| `fuzz_fox`                     | `try_parse_fox_pdu` (Niagara/Tridium Fox: terminator-delimited framing plus its self-describing per-tuple type-tag walk, including nested message recursion) | `fuzz/corpus/fox/`            |
| `fuzz_ge_srtp`                 | `try_parse_ge_srtp` (GE/Emerson PLC Service Request Transport Protocol: INIT/SHORT/EXTENDED framing and curated service-request-code decoding) | `fuzz/corpus/ge_srtp/`        |
| `fuzz_winrm`                   | `try_parse_winrm_http` (hand-rolled HTTP/1.1 request-and-response parsing feeding a SOAP/WS-Man envelope walk, called with both redact=true and redact=false) | `fuzz/corpus/winrm/`          |
| `fuzz_amqp091`                 | `try_parse_amqp_preamble` (amqp_common.hpp's shared 8-byte connection preamble) + `try_parse_amqp091_frame` (AMQP 0-9-1's METHOD/HEADER/BODY/HEARTBEAT frame layer) | `fuzz/corpus/amqp091/`        |
| `fuzz_amqp10`                  | `try_parse_amqp_preamble` (the same shared preamble parser fuzz_amqp091 also drives -- see its own file header for why no separate fuzz_amqp_common target exists) + `try_parse_amqp10_frame` (AMQP 1.0's DOFF/TYPE frame layer and performative-keyed body walk) | `fuzz/corpus/amqp10/`         |
| `fuzz_tls_sni`                 | `try_detect_doh` (the DNS-over-HTTPS detector decoder.cpp itself calls) + `try_parse_tls_handshake_client_hello` (its inner handshake-body parser, independently reachable from quic.cpp with a different, record-header-free input shape) | `fuzz/corpus/tls_sni/`        |
| `fuzz_icmp`                     | `try_parse_icmp` (ICMPv4, including a nested re-parse of the embedded/quoted original IP datagram carried by Destination Unreachable/Redirect/Time Exceeded/Parameter Problem messages) | `fuzz/corpus/icmp/`           |
| `fuzz_icmpv6`                   | `try_parse_icmpv6` (ICMPv6 base + Neighbor Discovery Protocol/NDP, including the NDP option TLV walk), against two fixed pseudo-header IPv6 addresses for the RFC 4443 checksum | `fuzz/corpus/icmpv6/`         |
| `fuzz_igmp`                     | `try_parse_igmp` (IGMP v1/v2/v3, including the v3 Membership Report's per-group Group Record list and the shared Max Resp Code/QQIC exponential encoding) | `fuzz/corpus/igmp/`           |
| `fuzz_igrp`                     | `try_parse_igrp` (Cisco IGRP's classful route-vector table), against two fixed source-IP values since IGRP's own classful Network field decoding needs the carrying packet's source address | `fuzz/corpus/igrp/`           |
| `fuzz_ospf`                     | `try_parse_ospf` (OSPFv2 Hello/DB Description/LS Request/LS Update/LS Ack, including LS Update's nested list of type-keyed LSA bodies) | `fuzz/corpus/ospf/`           |
| `fuzz_pim`                      | `try_parse_pim` (PIM-SM/PIM-DM v2, including the shared Encoded-Address decoding and Join/Prune's doubly-nested group/source-list walk) | `fuzz/corpus/pim/`            |
| `fuzz_vrrp`                     | `try_parse_vrrp` (VRRP v2/v3, including the version-dependent fixed-header reinterpretation and v2's conditional trailing Authentication Data field) | `fuzz/corpus/vrrp/`           |
| `fuzz_eigrp`                    | `try_parse_eigrp` (Cisco EIGRP's general + Classic/Wide-Metric route TLV chain, including a route TLV's prefix-length-compressed multi-destination expansion) | `fuzz/corpus/eigrp/`          |
| `fuzz_bsap`                     | `try_parse_bsap` (BSAP serial-tunneled and BSAP-IP-native framing, UDP port 1234) | `fuzz/corpus/bsap/`           |
| `fuzz_cclink_ie`                | `try_parse_cclink_ie_cyclic_request` + `try_parse_cclink_ie_cyclic_response` + `try_parse_cclink_ie_slmp_request` + `try_parse_cclink_ie_slmp_response` (both expected-kind hints) -- CC-Link IE Field Network Basic cyclic data (UDP 61450) and SLMP node search/set-IP-address (UDP 61451) | `fuzz/corpus/cclink_ie/`      |
| `fuzz_coap`                     | `try_parse_coap` (CoAP RFC 7252 header, option-chain walk, RFC 7641/7959 Observe/Block options; UDP port 5683) | `fuzz/corpus/coap/`           |
| `fuzz_dhcpv6`                   | `try_parse_dhcpv6` (DHCPv6 RFC 8415 client/server and RELAY-FORW/RELAY-REPL headers, recursive IA_NA/IA_TA/IA_PD option nesting; UDP ports 546/547) | `fuzz/corpus/dhcpv6/`         |
| `fuzz_dns`                      | `try_parse_dns_message` (shared DNS/mDNS/LLMNR message grammar, looped over all three `DnsFlavor` values; UDP ports 53/5353/5355) | `fuzz/corpus/dns/`            |
| `fuzz_hsrp`                     | `try_parse_hsrp` (HSRPv1 fixed header and HSRPv2 TLV chain; UDP port 1985) | `fuzz/corpus/hsrp/`           |
| `fuzz_nbns`                     | `try_parse_nbns` (NBT-NS NAME_SERVICE message, its own first-level-encoded NAME grammar; UDP port 137) | `fuzz/corpus/nbns/`           |
| `fuzz_powerlink`                | `try_parse_powerlink` (Ethernet POWERLINK MessageType/Sequence/Command-Layer parsing, shared unchanged by both the EtherType 0x88AB and UDP port 3819 SDO gates) | `fuzz/corpus/powerlink/`      |
| `fuzz_quic`                     | `try_recognize_quic` (QUIC long-header structural recognition plus RFC 9001 publicly-derivable Initial-packet AEAD decryption, looped over several (src_port, dst_port, extra_ports) combinations since QUIC has no single fixed port) | `fuzz/corpus/quic/`           |
| `fuzz_rip`                      | `try_parse_rip` (RIP RFC 1058 header and route-table-entry walk; UDP port 520) | `fuzz/corpus/rip/`            |
| `fuzz_rmcp`                     | `try_parse_rmcp_header` + `try_parse_asf` + `try_parse_ipmi` (RMCP's 4-byte envelope, then ASF Presence Pong and IPMI 1.5/2.0 session+message+RAKP parsing on its class payload; UDP port 623) | `fuzz/corpus/rmcp/`           |
| `fuzz_bgp`                     | `try_parse_bgp_message` (BGP-4 OPEN/UPDATE/NOTIFICATION/KEEPALIVE/ROUTE-REFRESH, looped over the three reachable `as_width_authoritative`/`as_width_is_four_octet` combinations) | `fuzz/corpus/bgp/`            |
| `fuzz_ldap`                    | `try_parse_ldap` (LDAP/RFC 4511's hand-rolled IMPLICIT-TAGS BER/DER reader) | `fuzz/corpus/ldap/`           |
| `fuzz_modbus`                  | `try_parse_modbus_tcp` (MBAP header + PDU, all four read families/single-write/multiple-write/exception decoding) | `fuzz/corpus/modbus/`         |
| `fuzz_opcua`                   | `try_parse_opcua_message` (UA-TCP + SecureConversation chunk framing, self-describing Variant/DataValue decoding, looped over `redact` true/false) | `fuzz/corpus/opcua/`          |
| `fuzz_smb`                     | `try_parse_smb` (SMB2/SMB3 compounded-chain framing plus embedded NTLM Type 1/2/3 decoding) | `fuzz/corpus/smb/`            |
| `fuzz_twincat`                 | `try_parse_twincat` (Beckhoff AMS/TCP framing + ADS command-keyed data layout) | `fuzz/corpus/twincat/`        |
| `fuzz_codesys`                 | `try_parse_codesys_tcp` + `try_parse_codesys_udp` (CODESYS V3's Block-Driver-framed TCP entry point and its un-framed UDP entry point, two genuinely distinct functions sharing one Datagram/Router/Channel/Services inner parser) | `fuzz/corpus/codesys/`        |
| `fuzz_ffhse`                   | `try_parse_ffhse` (FOUNDATION Fieldbus HSE PDU framing; TCP and UDP decoders converge on this identical call) | `fuzz/corpus/ffhse/`          |
| `fuzz_fins`                    | `try_parse_fins_frame` called directly (UDP entry point) and again after a real `fins_tcp_declared_length`-gated FINS/TCP envelope command-0x02 (Frame Send) unwrap (TCP entry point) | `fuzz/corpus/fins/`           |
| `fuzz_hartip`                  | `try_parse_hartip` (HART-IP's 8-byte header + Pass-Through Command body; TCP and UDP decoders converge on this identical call for one message) | `fuzz/corpus/hartip/`         |
| `fuzz_kerberos`                | `try_parse_kerberos` called on the raw payload (UDP entry point) and again on `payload.from(4)` (TCP entry point, mirroring `KerberosTcpDecoder::decode`'s own RFC 4120 SS7.2.2 length-prefix strip) | `fuzz/corpus/kerberos/`       |
| `fuzz_melsec`                  | `try_parse_melsec` (MELSEC 3E frame structural gate; TCP and UDP decoders converge on this identical call) | `fuzz/corpus/melsec/`         |
| `fuzz_mms`                     | `try_parse_tpkt_cotp` + `try_parse_mms` (TPKT/COTP framing, then MMS's ASN.1 BER-encoded, self-describing Data CHOICE application layer on its user data) | `fuzz/corpus/mms/`            |
| `fuzz_arp`                     | `try_parse_arp` (RFC 826 base layout + RFC 903/1931/2390/2225 RARP/DRARP/InARP/ATMARP opcode extensions + RFC 5227 ARP Probe/Announcement) | `fuzz/corpus/arp/`            |
| `fuzz_cdp`                     | `try_parse_cdp` (Cisco Discovery Protocol: fixed Version/TTL/Checksum header + TLV stream, on the post-LLC/SNAP-header payload) | `fuzz/corpus/cdp/`            |
| `fuzz_eapol`                   | `try_parse_eapol` (IEEE 802.1X/EAPOL header + a shallow, bounded look inside an encapsulated EAP packet and EAPOL-Key Descriptor Type) | `fuzz/corpus/eapol/`          |
| `fuzz_ethercat`                | `try_parse_ethercat` (2-byte frame header +, for Type 1 frames, the chained EtherCAT datagram walk and trailing Working Counter) | `fuzz/corpus/ethercat/`       |
| `fuzz_goose`                   | `try_parse_goose` (IEC 61850-8-1 GOOSE: 8-byte APDU header + ASN.1 BER-encoded PDU, including the recursive allData "Data" value walk) | `fuzz/corpus/goose/`          |
| `fuzz_homeplug_av`             | `try_parse_homeplug_av` (HomePlug AV/AV2 MME header, MMTYPE Kind/Category, MMV header-size edge cases, curated payload decoding) | `fuzz/corpus/homeplug_av/`    |
| `fuzz_lldp`                    | `try_parse_lldp` (IEEE 802.1AB TLV stream with its packed type/length word, and the Chassis ID/Port ID subtype tables) | `fuzz/corpus/lldp/`           |
| `fuzz_mpls`                    | `try_parse_mpls` (RFC 3032 label-stack walk, Bottom-of-Stack-bit-terminated and depth-capped) | `fuzz/corpus/mpls/`           |
| `fuzz_pppoe`                   | `try_parse_pppoe` (RFC 2516 PPPoE Discovery/Session header + PPP Protocol-field peek, looped over both `is_session_ethertype` values) | `fuzz/corpus/pppoe/`          |
| `fuzz_profinet`                | `try_parse_profinet` (FrameID classification, DCP request/response decoding, cyclic RT I/O framing) | `fuzz/corpus/profinet/`       |
| `fuzz_slow_protocols`          | `try_parse_slow_protocols` (IEEE 802.3 Slow Protocols: LACP/Marker/OAM, Subtype-multiplexed inside a single entry point) | `fuzz/corpus/slow_protocols/` |
| `fuzz_stp`                     | `try_parse_stp` (STP/RSTP/MSTP BPDU decoding, including MSTP's Version-3-Length-driven, capped MSTI walk, on the post-LLC-header payload) | `fuzz/corpus/stp/`            |
| `fuzz_sv`                      | `try_parse_sv` (IEC 61850-9-2 Sampled Values: 8-byte APDU header + ASN.1 BER-encoded SavPdu/ASDU-list walk) | `fuzz/corpus/sv/`             |
| `fuzz_can_socketcan`           | `parse_socketcan_frame` (the shared 8-byte fixed CAN frame header every CAN-bus protocol here rides on, pcap LINKTYPE_CAN_SOCKETCAN == 227) | `fuzz/corpus/can_socketcan/`  |
| `fuzz_canopen`                 | `parse_socketcan_frame` + `try_parse_canopen(const CanSocketcanFrame&)` (CiA 301 NMT/EMCY/PDO/SYNC/TIME/heartbeat classification + SDO expedited/segmented transfer decoding) | `fuzz/corpus/canopen/`        |
| `fuzz_devicenet`               | `parse_socketcan_frame` + `try_parse_devicenet(const CanSocketcanFrame&)` (DeviceNet CAN-bus CIP message-group classification) | `fuzz/corpus/devicenet/`      |
| `fuzz_ieee802154`              | `parse_ieee802154_withfcs` + `parse_ieee802154_tap` (raw IEEE 802.15.4 MAC header parsing, pcap LINKTYPE_IEEE802_15_4_WITHFCS == 195 and LINKTYPE_IEEE802_15_4_TAP == 283) | `fuzz/corpus/ieee802154/`     |
| `fuzz_j1939`                   | `parse_socketcan_frame` + `try_parse_j1939(const CanSocketcanFrame&)` (SAE J1939 message classification off an extended-ID CAN frame, including RTR frames) | `fuzz/corpus/j1939/`          |
| `fuzz_zigbee`                  | `parse_ieee802154_withfcs`/`parse_ieee802154_tap` + `try_parse_zigbee(const Ieee802154Frame&)` (Zigbee MAC+NWK+APS+ZDP, both capture-format entry points against the same input) | `fuzz/corpus/zigbee/`         |
| `fuzz_dcerpc`                  | `try_parse_dcerpc` + `parse_dcerpc_chain` + `dcerpc_tcp_declared_length` (the shared, interface-agnostic DCE/RPC common header, bind/bind_ack/alter_context/fault, and back-to-back multi-PDU chain walk every RPC interface below rides on) | `fuzz/corpus/dcerpc/`         |
| `fuzz_ntlm`                    | `try_parse_ntlm` (MS-NLMP NEGOTIATE/CHALLENGE/AUTHENTICATE decoding via the shared Len/MaxLen/Offset field-descriptor grammar, starting at the "NTLMSSP\0" signature) | `fuzz/corpus/ntlm/`           |
| `fuzz_netlogon`                | `try_parse_netlogon_request`/`_response` on the DCE/RPC stub, looped over every named opnum (including the Zerologon-relevant NetrServerReqChallenge/NetrServerAuthenticate family) and both `sealed` values | `fuzz/corpus/netlogon/`       |
| `fuzz_samr`                    | `try_parse_samr_request`/`_response` on the DCE/RPC stub, looped over every named SAMR opnum (RID<->name resolution, enumeration, the Connect family, credential-material opnums left unparsed) and both `sealed` values | `fuzz/corpus/samr/`           |
| `fuzz_lsarpc`                  | `try_parse_lsarpc_request`/`_response` on the DCE/RPC stub, looped over every named LSARPC opnum (SID<->name resolution, trust-domain/account enumeration) and both `sealed` values | `fuzz/corpus/lsarpc/`         |
| `fuzz_srvsvc`                  | `try_parse_srvsvc_request`/`_response` on the DCE/RPC stub, looped over every named SRVSVC opnum (NetrShareEnum/NetrShareGetInfo full decode, enumeration opnums header-only) and both `sealed` values | `fuzz/corpus/srvsvc/`         |
| `fuzz_wkssvc`                  | `try_parse_wkssvc_request`/`_response` on the DCE/RPC stub, looped over every named WKSSVC opnum (NetrWkstaGetInfo/NetrWkstaUserEnum full decode, join/unjoin left structural-only) and both `sealed` values | `fuzz/corpus/wkssvc/`         |
| `fuzz_drsuapi`                 | `try_parse_drsuapi_request`/`_response` on the DCE/RPC stub, looped over DRSBind/DRSUnbind/DRSGetNCChanges/DRSCrackNames (DRSGetNCChanges/DCSync deliberately structural-only) and both `sealed` values | `fuzz/corpus/drsuapi/`        |

## Running

Each binary is a standalone libFuzzer executable -- point it at its own corpus
directory and let it run:

```sh
./build-fuzz/fuzz_dnp3 fuzz/corpus/dnp3/ -max_total_time=300
```

Useful flags: `-max_total_time=N` (seconds), `-jobs=N -workers=N` (parallel fuzzing,
merges crashes/coverage back into the corpus directory), `-max_len=N` (cap input
size -- these protocols are all small-frame, so 4096 or less is plenty and fuzzes
faster). A crash writes a `crash-<hash>` file in the current directory; reproduce it
directly with `./fuzz_dnp3 crash-<hash>`, and add it to the target's `fuzz/corpus/`
directory once fixed so it's replayed on every future run.

`CTest` (only when `CONDUITSCOPE_ENABLE_FUZZING=ON`) registers a short bounded run
of each target over its own seed corpus as a regression check -- `ctest -R ^fuzz_`
-- so a corpus file that used to crash and was fixed stays fixed. This is
deliberately not part of the default CTest suite or `ci.yml` yet (`CMAKE_BUILD_TYPE`
must also be a sanitizer-friendly build, and the fuzzer/sanitizer runtime package
above isn't installed on the CI image) -- folding ASan/UBSan into the CI matrix and
wiring these targets into a scheduled CI fuzzing job is the next step per
docs/DEVELOPMENT.md's adopted priority order, not yet done here.

## Corpus

`fuzz/corpus/*/` seed files are the TCP payload bytes (or, for `pcap_reader`/
`packet_decode`, whole/framed packet bytes) extracted from this repo's own existing
`tests/sample_*.pcap` fixtures -- real, known-good traffic for each protocol, so the
fuzzer starts mutating from valid structure instead of an empty corpus. They are
deliberately small; growing the corpus (via `-jobs`/merge, or by adding
interesting/crashing inputs found later) is expected over time and those additions
should be committed.

`fuzz_packet_decode`'s corpus files use a custom framing (see `fuzz_packet_decode.cpp`'s
own header comment): a sequence of `[uint16_t little-endian length][that many raw
captured-Ethernet-frame bytes]` records, so one fuzzer input drives several
`Decoder::decode()` calls against the *same* `Decoder` instance and can therefore
reach state that only exists after more than one packet.
