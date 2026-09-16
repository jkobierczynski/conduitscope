// SPDX-License-Identifier: MIT
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
#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/ethercat.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/mqtt.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/profinet.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/tcp.hpp"

namespace conduitscope {

enum class ProtocolFilter {
    Auto,         // opportunistically detect IEC104/Modbus/DNP3/S7comm/EtherNet-IP/PROFINET/GOOSE/SV/EtherCAT/BACnet-IP/HART-IP/OPC-UA regardless of port
    ModbusOnly,   // only attempt Modbus decoding
    Dnp3Only,     // only attempt DNP3 decoding
    S7commOnly,   // only attempt TPKT/COTP/S7comm decoding
    Iec104Only,   // only attempt IEC 60870-5-104 decoding
    EnipOnly,     // only attempt EtherNet/IP (CIP explicit messaging) decoding
    ProfinetOnly, // only attempt PROFINET RT (DCP + cyclic IO data) decoding
    GooseOnly,    // only attempt IEC 61850-8-1 GOOSE decoding
    SvOnly,       // only attempt IEC 61850-9-2 Sampled Values decoding
    EthercatOnly, // only attempt EtherCAT decoding
    BacnetOnly,   // only attempt BACnet/IP (BVLC/NPDU/APDU) decoding
    HartIpOnly,   // only attempt HART-IP (session control / tunneled Pass-Through) decoding
    OpcUaOnly,    // only attempt OPC UA (UA-TCP / Secure Conversation) decoding
    MmsOnly,      // only attempt TPKT/COTP/IEC 61850 MMS decoding
    MqttOnly,     // only attempt MQTT (v3.1.1/v5.0) / Sparkplug B decoding
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
    std::vector<uint16_t> extra_s7comm_ports;
    std::vector<uint16_t> extra_iec104_ports;
    std::vector<uint16_t> extra_enip_ports;
    std::vector<uint16_t> extra_enip_io_ports;  // UDP, unlike extra_enip_ports (TCP) -- see ENIP_IO_UDP_PORT
    std::vector<uint16_t> extra_bacnet_ports;   // UDP -- see BACNET_UDP_PORT (47808/0xBAC0)
    std::vector<uint16_t> extra_hartip_ports;   // TCP AND UDP -- see HARTIP_PORT (5094, same for both)
    std::vector<uint16_t> extra_opcua_ports;    // TCP only -- see OPCUA_PORT (4840)
    std::vector<uint16_t> extra_mqtt_ports;     // TCP only -- see MQTT_PORT (1883)
    // If true, a parse failure at the Ethernet/IPv4/TCP layer is rethrown to
    // the caller instead of being recorded as a per-packet "parse-error"
    // result. Off by default so one malformed packet doesn't abort decoding
    // an entire capture.
    bool strict = false;
};

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

    // "iec104", "modbus", "dnp3", "s7comm", "enip", "profinet", "goose", "sv", "ethercat", "bacnet",
    // "hartip", "opcua", "mms", "mqtt", "cotp"
    // (recognized TPKT/COTP framing but not S7comm inside it -- e.g. a connection setup frame),
    // "tcp" (recognized transport, no app-layer match), "udp" (recognized transport, no app-layer
    // protocol decoded -- see udp.hpp; UDP/2222 CIP I/O traffic that try_parse_cip_io actually
    // recognizes is promoted to "enip" instead -- see enip_has_io below), "non-tcp" (a non-TCP,
    // non-UDP IPv4 payload, e.g. ICMP), "non-ip" (a non-IPv4 Ethernet frame, e.g. ARP, or a
    // PROFINET RT frame whose FrameID try_parse_profinet doesn't recognize, or a GOOSE frame
    // whose outer APDU tag try_parse_goose doesn't recognize, or an SV frame whose outer APDU tag
    // try_parse_sv doesn't recognize, or an EtherCAT frame whose header Type field
    // try_parse_ethercat doesn't recognize -- see link_layer.hpp's ethertype_name; EtherType
    // 0x8892 traffic that try_parse_profinet DOES recognize is promoted to "profinet" instead --
    // see profinet_has_dcp/profinet_has_cyclic_data below; EtherType 0x88B8 traffic that
    // try_parse_goose DOES recognize is promoted to "goose" instead -- see goose_has_pdu/
    // goose_is_gse_management below; EtherType 0x88BA traffic that try_parse_sv DOES recognize is
    // promoted to "sv" instead -- see sv_asdu_count below; EtherType 0x88A4 traffic that
    // try_parse_ethercat DOES recognize is promoted to "ethercat" instead -- see
    // ethercat_frame_type below; a UDP payload that try_parse_bacnet recognizes as a BACnet/IP
    // BVLC message is promoted to "bacnet" instead -- see bacnet_bvlc_function below; a TCP or UDP
    // payload that try_parse_hartip recognizes as a HART-IP message is promoted to "hartip"
    // instead -- see hartip_message_type below),
    // "unsupported-link", or "parse-error".
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

    // Only set when protocol == "iec104". Reflects the first APDU found in this TCP payload (an
    // I-format APDU with a decoded ASDU) -- see the coalescing loop in decoder.cpp for how
    // additional APDUs coalesced into the same payload are still fully decoded and folded in here,
    // same pattern as DNP3's multi-frame-per-payload handling.
    bool iec104_has_asdu = false;
    std::string iec104_asdu_type_name;
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
    std::optional<Dnp3ApplicationFragment> process_dnp3_frame(const Dnp3LinkFrame& link, ByteSpan tcp_payload,
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
