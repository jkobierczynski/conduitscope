// SPDX-License-Identifier: Apache-2.0
// output.hpp - renders a stream of DecodedPacket values as text, JSON, or
// CSV, plus a StatsWriter that accumulates a summary instead of per-packet
// lines (used by `decode --stats` and the `info` command).
#pragma once

#include <map>
#include <ostream>
#include <string>

#include "conduitscope/decoder.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/time_format.hpp"

namespace conduitscope {

class OutputWriter {
public:
    virtual ~OutputWriter() = default;
    virtual void begin() {}
    virtual void write_packet(const DecodedPacket& packet) = 0;
    virtual void end() {}
};

// `resolver` is held as a reference, not owned -- it outlives every writer here, since
// cli_main.cpp's run_decode constructs exactly one Resolver per `decode` invocation, on the stack,
// before constructing whichever OutputWriter the requested --format needs, and destroys it only
// after that writer is done. Every accessor on Resolver already returns std::nullopt when its own
// lookup is disabled (--no-oui/--nn) or has nothing to resolve against (--resolve with no
// --hosts), so a writer never needs to ask "is this lookup even enabled" itself -- it just calls
// resolver_.oui_vendor()/hostname()/service_name() unconditionally and renders whatever comes
// back, or nothing at all on a miss. See resolver.hpp's own file header for the full "annotation,
// never replacement" contract every writer below follows.
// `show_vlan` (default true, every constructor below) governs whether a VLAN-tagged packet's
// 802.1Q VLAN ID (DecodedPacket::has_vlan_tag/vlan_id -- already unconditionally populated by the
// decoding layer for every Ethernet-linktype packet, see link_layer.cpp's parse_ethernet) is shown
// at all. Unlike the OUI/hostname/service-name annotations above, this isn't a resolver lookup
// that can simply return nothing on a miss -- the VLAN ID is a base decoded fact -- so `decode`'s
// `--no-vlan` flag (cli_main.cpp) wires straight into this constructor parameter instead of going
// through Resolver, the same "pure display toggle" precedent TextWriter's own `color` parameter
// already set.
// `time_format`/`time_offset` (default TimeFormat::Epoch/TimeOffset{}, every constructor below)
// govern how each packet's timestamp is rendered -- see time_format.hpp's file header comment for
// what each value does. Epoch reproduces today's original raw-seconds-since-epoch rendering
// byte-for-byte, so a writer constructed without passing these two (or with them left at their
// defaults) behaves exactly as before `decode`'s own `-t`/--time-format/--time-offset flags
// (cli_main.cpp) existed at all.
class TextWriter : public OutputWriter {
public:
    explicit TextWriter(std::ostream& out, bool color, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{})
        : out_(out), color_(color), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    bool color_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
};

class JsonWriter : public OutputWriter {
public:
    explicit JsonWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{})
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;
    void end() override;

private:
    std::ostream& out_;
    bool wrote_any_ = false;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
};

class CsvWriter : public OutputWriter {
public:
    explicit CsvWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                        TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{})
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
};

// Accumulates counts instead of printing per packet; call begin()/write_packet()
// as usual, then print_summary(out) once at the end (that's separate from
// OutputWriter::end() so `info` and `decode --stats` can share this class
// while formatting their headers differently).
class StatsWriter : public OutputWriter {
public:
    void write_packet(const DecodedPacket& packet) override;
    void print_summary(std::ostream& out) const;

    size_t total_packets() const { return total_packets_; }

private:
    size_t total_packets_ = 0;
    std::map<std::string, size_t> protocol_counts_;
    std::map<std::string, size_t> modbus_function_counts_;
    size_t modbus_exceptions_ = 0;
    // Count of responses authoritatively paired (by MBAP transaction ID + TCP session, not the
    // payload-shape heuristic) to a specific earlier request -- see Decoder::pair_modbus_transaction.
    size_t modbus_paired_responses_ = 0;
    std::map<std::string, size_t> s7comm_function_counts_;
    std::map<std::string, size_t> dnp3_function_counts_;
    std::map<std::string, size_t> iec104_asdu_type_counts_;
    std::map<std::string, size_t> enip_command_counts_;
    std::map<std::string, size_t> enip_cip_service_counts_;
    size_t enip_io_datagram_count_ = 0;  // CIP I/O (implicit messaging) UDP datagrams -- see enip_has_io
    std::map<std::string, size_t> profinet_frame_id_counts_;
    size_t profinet_dcp_count_ = 0;
    size_t profinet_cyclic_count_ = 0;
    size_t goose_pdu_count_ = 0;
    size_t goose_gse_management_count_ = 0;
    size_t goose_simulated_count_ = 0;
    size_t sv_frame_count_ = 0;
    size_t sv_asdu_total_ = 0;  // summed across every decoded SV frame, since one frame can carry
                                 // more than one ASDU -- see sv_asdu_count
    std::map<std::string, size_t> ethercat_frame_type_counts_;
    size_t ethercat_datagram_total_ = 0;  // summed across every decoded EtherCAT frame, since one
                                            // frame can carry more than one datagram -- see
                                            // ethercat_datagram_count
    std::map<std::string, size_t> stp_bpdu_type_counts_;      // "Configuration"/"Rapid/Multiple
                                                                 // Spanning Tree"/"Topology Change
                                                                 // Notification"
    std::map<std::string, size_t> stp_protocol_version_counts_;  // "STP (802.1D)"/"RSTP (802.1w)"/
                                                                    // "MSTP (802.1s)"/"SPB (802.1aq)"
    size_t stp_mstp_count_ = 0;      // full MST extension decoded -- see stp_is_mstp
    size_t stp_msti_total_ = 0;      // summed across every decoded MST BPDU, since one can carry
                                       // more than one MSTI Configuration Message
    size_t stp_tc_count_ = 0;        // Configuration/RST/MST BPDUs with the TC flag set
    std::map<std::string, size_t> devicenet_group_counts_;   // "Group 1"/"Group 2"/"Group 3"/
                                                                // "Group 4"/"Unclassified (0x07F0-0x07FF)"
    std::map<std::string, size_t> devicenet_message_type_counts_;
    size_t devicenet_fragmented_count_ = 0;  // Group 3 messages with the Fragmentation flag set
    size_t devicenet_fd_count_ = 0;          // CAN FD frames -- see devicenet.hpp's scope note
    std::map<std::string, size_t> bacnet_bvlc_function_counts_;
    std::map<std::string, size_t> bacnet_service_counts_;  // keyed by APDU service-choice name,
                                                              // only when bacnet_has_apdu
    std::map<std::string, size_t> hartip_message_type_counts_;
    std::map<std::string, size_t> hartip_command_counts_;  // keyed by "N (Name)" or "N", only when
                                                              // hartip_has_pass_through
    std::map<std::string, size_t> opcua_message_type_counts_;  // "Hello"/"OpenSecureChannel"/"Message"/...
    std::map<std::string, size_t> opcua_service_counts_;  // keyed by service name, only when
                                                             // opcua_service_recognized
    std::map<std::string, size_t> mms_pdu_counts_;      // "confirmed-RequestPDU"/"initiate-RequestPDU"/...
    std::map<std::string, size_t> mms_service_counts_;  // keyed by service name, only when
                                                          // mms_service_recognized
    std::map<std::string, size_t> mqtt_packet_type_counts_;  // "CONNECT"/"PUBLISH"/...
    size_t mqtt_sparkplug_count_ = 0;  // PUBLISH packets whose topic matched the spBv1.0 namespace
    std::map<std::string, size_t> mqtt_sparkplug_message_type_counts_;  // "NBIRTH"/.../"STATE",
                                                                          // only when mqtt_is_sparkplug
    std::map<std::string, size_t> s7plus_pdu_type_counts_;  // "Connect"/"Data"/"DataFW1_5"/"Keep Alive"
    std::map<std::string, size_t> s7plus_function_counts_;  // keyed by function name, only when
                                                               // s7plus_has_function
    size_t s7plus_body_decoded_count_ = 0;  // Tier-1 functions this decoder fully decoded (see
                                              // s7commplus.hpp); the gap vs. s7plus_has_function's
                                              // own total count is everything left Tier-2
    std::map<std::string, size_t> ffhse_protocol_counts_;  // "FDA Session Management"/"SM"/"FMS"/
                                                              // "LAN Redundancy"
    std::map<std::string, size_t> ffhse_message_counts_;   // keyed by ffhse_message_name, only
                                                              // when ffhse_recognized
    size_t ffhse_body_decoded_count_ = 0;  // Tier-1 messages this decoder fully decoded -- the gap
                                             // vs. ffhse_message_counts_'s own total is everything
                                             // left Tier-2 or unrecognized
    // Keyed by "<protocol> <opcode name>" (e.g. "dns Query", "mdns Query", "llmnr Query") --
    // one shared map for all three DNS-message-shaped protocols, since they share DecodedPacket's
    // own dns_* field family too -- see dns.hpp.
    std::map<std::string, size_t> dns_family_opcode_counts_;
    std::map<std::string, size_t> nbns_opcode_counts_;
    std::map<std::string, size_t> doh_provider_counts_;  // keyed by doh_matched_provider
    std::map<std::string, size_t> rip_command_counts_;   // keyed by rip_command_name
    std::map<std::string, size_t> igmp_type_counts_;     // keyed by igmp_type_name
    std::map<std::string, size_t> vrrp_version_counts_;  // "VRRPv2"/"VRRPv3"
    std::map<std::string, size_t> hsrp_version_counts_;  // "HSRPv1"/"HSRPv2"
    std::map<std::string, size_t> igrp_opcode_counts_;   // keyed by igrp_opcode_name
    std::map<std::string, size_t> pim_type_counts_;      // keyed by pim_type_name
    std::map<std::string, size_t> eigrp_opcode_counts_;  // keyed by eigrp_opcode_name
    std::map<std::string, size_t> ospf_type_counts_;     // keyed by ospf_type_name
    bool has_ts_ = false;
    double first_ts_ = 0.0, last_ts_ = 0.0;
};

std::string json_escape(const std::string& s);
std::string csv_escape(const std::string& s);

}  // namespace conduitscope
