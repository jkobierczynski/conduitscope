// SPDX-License-Identifier: Apache-2.0
// output.hpp - renders a stream of DecodedPacket values as text, JSON, or
// CSV, plus a StatsWriter that accumulates a summary instead of per-packet
// lines (used by `decode --stats` and the `info` command).
#pragma once

#include <map>
#include <ostream>
#include <sstream>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
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
// lookup is n't enabled (no --oui/--nn given) or has nothing to resolve against (--resolve with no
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
// `show_direction` (default true, every constructor below) is the same kind of pure display
// toggle as `show_vlan` just above, for DecodedPacket::has_direction/direction_client_is_src/
// direction_source (FlowDirectionTracker, see flow_direction.hpp -- populated by `decode`'s own
// run_decode loop before a packet ever reaches a writer, same as VLAN unwrapping happens before
// this class ever sees the packet) -- `decode`'s `--no-direction` flag (cli_main.cpp) wires
// straight into this constructor parameter. TextWriter folds it into the packet's head line
// itself (see write_packet's own comment) rather than a separate line, colored by
// DirectionSource::PortHeuristic vs. the other two tiers -- see DirectionSource's own comment
// (decoder.hpp) for why only that tier can actually be wrong. JsonWriter omits both fields
// entirely when false (never just null), the same "omit outright, not just a value" convention
// `show_vlan` already set for has_vlan_tag/vlan_id above; CsvWriter's direction_source/
// direction_client_ip columns always exist (CSV can't omit a column conditionally) but render
// empty, the same "column always exists" precedent `show_vlan`'s own comment already documents
// for its own vlan_id column just below.
// `time_format`/`time_offset` (default TimeFormat::Epoch/TimeOffset{}, every constructor below)
// govern how each packet's timestamp is rendered -- see time_format.hpp's file header comment for
// what each value does. Epoch reproduces today's original raw-seconds-since-epoch rendering
// byte-for-byte, so a writer constructed without passing these two (or with them left at their
// defaults) behaves exactly as before `decode`'s own `-t`/--time-format/--time-offset flags
// (cli_main.cpp) existed at all.
class TextWriter : public OutputWriter {
public:
    explicit TextWriter(std::ostream& out, bool color, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                         bool show_direction = true, bool show_mac = true, bool verbose = true)
        : out_(out), color_(color), resolver_(resolver), show_vlan_(show_vlan),
          time_(time_format, time_offset), show_direction_(show_direction), show_mac_(show_mac),
          verbose_(verbose) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    bool color_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
    // `show_mac` (default true, matching every other toggle above so a caller that doesn't pass it
    // keeps this class's original always-on behavior) governs whether the "eth <src> -> <dst>" line
    // (DecodedPacket::src_mac/dst_mac, plus any OUI vendor annotation Resolver supplies and the VLAN
    // ID show_vlan_ already governs) is shown at all -- decode's -e/--ether flag (cli_main.cpp,
    // defaulting to false there, mirroring tcpdump's own -e) wires straight into this constructor
    // parameter, the same "pure display toggle" precedent show_vlan/show_direction already set. Only
    // TextWriter gets this: JsonWriter/CsvWriter always include src_mac/dst_mac as base fields (like
    // src_ip/dst_ip), by design -- see this file's own header comment -- so machine-readable output
    // never loses data just to make a human-facing dump more compact. VLAN display is independent of
    // this: a VLAN-tagged packet still shows "vlan <id>" (on its own line) when show_mac_ is false,
    // since 802.1Q membership isn't specifically a MAC-address fact and show_vlan_ already has its
    // own default-on toggle -- see write_packet's own comment for exactly how the two combine.
    bool show_mac_;
    // `verbose` (default true here, matching every other toggle above so a caller that doesn't
    // pass it keeps this class's original always-on behavior) governs whether per-packet notes
    // ("note: ..." lines) and the "(client X -- handshake/content/port-heuristic)" direction-tier
    // suffix are shown at all -- decode's own -v/--verbose flag (cli_main.cpp, defaulting to
    // false there) wires straight into this constructor parameter. Text output only, the same
    // "pure display toggle" scope show_mac_ already has: JsonWriter/CsvWriter/FieldsWriter are
    // unaffected (notes are a proper structured field there, not visual clutter on a shared line --
    // see this file's own header comment) and show_direction_'s own JSON/CSV "direction_source"
    // field/column keeps working exactly as before regardless of this flag. When true, the
    // direction suffix still additionally requires show_direction_ -- verbose_ is an extra gate on
    // top of it, not a replacement, so --no-direction still suppresses it even under -v, and -v
    // alone does nothing for it if --no-direction was also given -- see write_packet's own comment.
    bool verbose_;
};

class JsonWriter : public OutputWriter {
public:
    explicit JsonWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                         TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                         bool show_direction = true)
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset),
          show_direction_(show_direction) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;
    void end() override;

private:
    std::ostream& out_;
    bool wrote_any_ = false;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
};

class CsvWriter : public OutputWriter {
public:
    explicit CsvWriter(std::ostream& out, const Resolver& resolver, bool show_vlan = true,
                        TimeFormat time_format = TimeFormat::Epoch, TimeOffset time_offset = TimeOffset{},
                        bool show_direction = true)
        : out_(out), resolver_(resolver), show_vlan_(show_vlan), time_(time_format, time_offset),
          show_direction_(show_direction) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    const Resolver& resolver_;
    bool show_vlan_;
    TimeFormatter time_;
    bool show_direction_;
};

// `decode -T fields -e <field>` (repeatable), mirroring tshark's own `-T fields`/`-e` -- see
// output.cpp's own FieldsWriter::write_packet comment for exactly how this is implemented (it
// reuses JsonWriter's own already-correct, already-comprehensive per-protocol field rendering
// rather than re-deriving field names/values a second time -- the only way this stays in sync with
// every one of this codebase's ~90 protocols' own JSON fields without hand-maintaining a second,
// parallel field list). One tab-separated line per packet, fields in the order `-e` was given;
// a field name JsonWriter never emits for that packet (wrong protocol, disabled by a flag, etc.)
// renders as an empty column -- the same "empty, not an error" convention tshark's own `-T fields`
// has for a field absent from a given packet.
class FieldsWriter : public OutputWriter {
public:
    explicit FieldsWriter(std::ostream& out, const Resolver& resolver, std::vector<std::string> fields,
                           bool show_vlan = true, TimeFormat time_format = TimeFormat::Epoch,
                           TimeOffset time_offset = TimeOffset{}, bool show_direction = true)
        : out_(out), resolver_(resolver), fields_(std::move(fields)), show_vlan_(show_vlan),
          time_format_(time_format), time_offset_(time_offset), show_direction_(show_direction) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    const Resolver& resolver_;
    std::vector<std::string> fields_;
    bool show_vlan_;
    TimeFormat time_format_;
    TimeOffset time_offset_;
    bool show_direction_;
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
    // Keyed by direction_source_name ("handshake"/"content"/"port-heuristic") -- counted whenever
    // has_direction is true, i.e. TCP flows only (FlowDirectionTracker's own scope, see
    // flow_direction.hpp), across every protocol at once rather than gated on p.protocol like the
    // per-protocol maps below, since direction determination is cross-cutting, not
    // protocol-specific -- see DirectionSource's own comment (decoder.hpp). Empty (and so never
    // printed, see print_summary) for `info`, which never runs FlowDirectionTracker at all.
    std::map<std::string, size_t> direction_source_counts_;
    std::map<std::string, size_t> modbus_function_counts_;
    size_t modbus_exceptions_ = 0;
    // Count of responses authoritatively paired (by MBAP transaction ID + TCP session, not the
    // payload-shape heuristic) to a specific earlier request -- see Decoder::pair_modbus_transaction.
    size_t modbus_paired_responses_ = 0;
    // registration-model decoder refactor (see decoder.hpp's DecodedPacket::result): TwinCAT's own
    // Command ID breakdown, read from DecodedPacket::result rather than a twincat_* flat field --
    // see write_packet's own p.protocol == "twincat" block (output.cpp) and twincat.hpp's file
    // header comment for why this protocol has no flat fields at all.
    std::map<std::string, size_t> twincat_command_counts_;
    size_t twincat_paired_responses_ = 0;  // authoritatively paired by Invoke ID, not a heuristic
                                             // -- TwinCAT's analog of modbus_paired_responses_ above
    // MELSEC's own command-name breakdown (melsec.hpp), read from DecodedPacket::result the same
    // way twincat_command_counts_ is above. Keyed by MelsecFrame::command_name -- "response" for an
    // unmatched response whose own command couldn't be determined (see melsec.hpp's "RESPONSE
    // DECODING NEEDS SESSION CONTEXT" paragraph), never double-counted against the matched name a
    // later-arriving response might otherwise also claim.
    std::map<std::string, size_t> melsec_command_counts_;
    // Session-scoped matches (see melsec.hpp/melsec.cpp) -- NOT authoritative pairing like
    // twincat_paired_responses_ above (there's no unique per-request ID on the wire to make it
    // authoritative), just "a response was matched to its most recently sent, not-yet-answered
    // request on the same session."
    size_t melsec_matched_responses_ = 0;
    // FINS's own command-name breakdown (fins.hpp), read from DecodedPacket::result the same way
    // melsec_command_counts_ is above. Keyed by FinsFrame::command_name -- unlike MELSEC, a FINS
    // response self-describes its own command code (see fins.hpp's "A GENUINE ARCHITECTURAL
    // DIFFERENCE FROM MELSEC" paragraph), so this never falls back to a generic "response" bucket
    // the way melsec_command_counts_ sometimes must.
    std::map<std::string, size_t> fins_command_counts_;
    // Session-scoped matches (see fins.hpp/fins.cpp) -- NOT authoritative pairing, the same
    // "matched to the most recently sent, not-yet-answered request on this session" posture
    // melsec_matched_responses_ has above, kept narrower in scope (see FinsFlowState's own comment
    // -- only Memory Area Read/Multiple Memory Area Read responses actually need it).
    size_t fins_matched_responses_ = 0;
    // Curated Note 5 (kerberos.hpp's file header comment) -- named KRB-ERROR error-code counts,
    // keyed by error_name ("KDC_ERR_PREAUTH_REQUIRED", or "error N" for an unnamed code), read
    // from DecodedPacket::result the same way twincat_command_counts_ is above.
    std::map<std::string, size_t> kerberos_error_counts_;
    // Curated Note 6 (ldap.hpp's file header comment) -- named LDAP resultCode counts, keyed by
    // result_code_name ("invalidCredentials", or "resultCode N" for an unnamed code), read from
    // DecodedPacket::result the same way kerberos_error_counts_ is above.
    std::map<std::string, size_t> ldap_result_code_counts_;
    // Curated Note 6 (smb.hpp's file header comment) -- named SMB Status counts from SESSION_SETUP
    // responses only (not every SMB2 command's own Status -- this stays focused on authentication
    // outcomes, the direct SMB-side analog of kerberos_error_counts_/ldap_result_code_counts_
    // above), keyed by status_name ("STATUS_LOGON_FAILURE", or "0xNNNNNNNN" for an unnamed code),
    // read from DecodedPacket::result the same way ldap_result_code_counts_ is above.
    std::map<std::string, size_t> smb_status_counts_;
    // Netlogon opnum counts (netlogon.hpp), the Netlogon-side analog of smb_status_counts_ above
    // -- keyed by netlogon_opnum_name() (e.g. "NetrServerAuthenticate3", or "opnum N" for an
    // uncurated one), incremented once per decoded NetlogonCall REQUEST (not per response, so a
    // request/response pair counts once, the same "count the request side" convention
    // kerberos_error_counts_'s own sibling counters don't need but this one does to avoid
    // double-counting a call twice).
    std::map<std::string, size_t> netlogon_opnum_counts_;
    // Same convention as netlogon_opnum_counts_ above, one map per Phase-1 interface (samr.hpp/
    // lsarpc.hpp).
    std::map<std::string, size_t> samr_opnum_counts_;
    std::map<std::string, size_t> lsarpc_opnum_counts_;
    // Same convention, phase 2's own two interfaces (srvsvc.hpp/wkssvc.hpp).
    std::map<std::string, size_t> srvsvc_opnum_counts_;
    std::map<std::string, size_t> wkssvc_opnum_counts_;
    // Same convention, phase 3's own single interface (drsuapi.hpp) -- see that file's own header
    // comment for why this map is essentially always empty in a realistic capture.
    std::map<std::string, size_t> drsuapi_opnum_counts_;
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
                                                          // MmsFrame::service_recognized (mms.hpp)
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
    std::map<std::string, size_t> icmp_type_counts_;     // keyed by icmp_type_name
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

// `decode -x/--hex` -- a tcpdump/tshark-style hex+ASCII dump of one packet's raw captured bytes:
// 16 bytes per line, a 4-hex-digit byte offset, each byte as two hex digits (an extra gap after
// the 8th byte, the same "two visually separated halves" layout every classic hex dump uses), then
// the same 16 bytes rendered as ASCII (printable 0x20-0x7e verbatim, anything else as '.'). Text
// output only -- see cli_main.cpp's own run_decode for where this is called from and why it's
// gated on --format text.
void write_hex_ascii_dump(std::ostream& out, ByteSpan data);

}  // namespace conduitscope
