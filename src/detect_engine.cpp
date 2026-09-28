// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/detect_engine.hpp"

#include <cstdio>
#include <ostream>
#include <sstream>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/ipv4.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/notable_it_protocols.hpp"
#include "conduitscope/resolver.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/time_format.hpp"

namespace conduitscope {

const char* detection_category_name(DetectionCategory category) {
    switch (category) {
        case DetectionCategory::EngineeringStationActivity: return "Engineering-Station Activity";
        case DetectionCategory::FirmwareLogicChange: return "Firmware/Logic Change";
        case DetectionCategory::RemoteAccessChannel: return "Remote-Access Channel";
        case DetectionCategory::ProtocolMisuse: return "Protocol Misuse";
    }
    return "Unknown";
}

const char* detection_confidence_name(DetectionConfidence confidence) {
    switch (confidence) {
        case DetectionConfidence::High: return "High";
        case DetectionConfidence::Medium: return "Medium";
        case DetectionConfidence::Low: return "Low";
    }
    return "Unknown";
}

namespace {

// Each writer in this codebase keeps its own local json_escape/format_epoch_seconds rather than
// sharing one across translation units -- see asset_inventory.cpp's own identical pair and its own
// comment on why (this file's header comment references the same convention).
std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string format_epoch_seconds(double ts) {
    return format_timestamp(ts, TimeFormat::AbsoluteDate, TimeOffset{}, ts, ts);
}

// `finding_kind` (e.g. "s7-plc-stop", "s7-plc-control") is a plain source-tag discriminator, NOT
// derived from category/technique: two different finding sources can share the same category and
// technique (S7 PLC Stop and PLC Control both map to EngineeringStationActivity/T0858) while still
// being two genuinely different things to report -- without this tag, the second one observed on
// the same conduit would silently collapse into the first one's own existing finding (packet_count/
// last_seen updated, its own distinct description lost entirely). Caught during this feature's own
// manual verification pass against sample_s7comm_pi_control.pcap, which legitimately contains both
// PLC Stop and PLC Control traffic on the same conduit -- only PLC Stop's own finding was surviving
// before this tag was added.
std::string always_notable_key(const char* finding_kind, const std::string& client_ip,
                                const std::string& server_ip, const std::string& protocol,
                                uint16_t server_port) {
    std::ostringstream k;
    k << finding_kind << '|' << client_ip << '|' << server_ip << '|' << protocol << '|' << server_port;
    return k.str();
}

std::string new_conduit_key(const std::string& client_ip, const std::string& server_ip,
                             const std::string& protocol, uint16_t server_port, const char* source_tag) {
    std::ostringstream k;
    k << client_ip << '|' << server_ip << '|' << protocol << '|' << server_port << '|' << source_tag;
    return k.str();
}

}  // namespace

void DetectEngine::observe(const DecodedPacket& dp) {
    ++total_packets_;
    if (!dp.has_ip) return;

    auto record_always_notable = [&](const char* finding_kind, DetectionCategory category,
                                      const MitreAttackTechnique& technique, const std::string& client_ip,
                                      const std::string& server_ip, const std::string& protocol,
                                      uint16_t server_port, const std::string& description) {
        std::string key = always_notable_key(finding_kind, client_ip, server_ip, protocol, server_port);
        auto it = always_notable_.find(key);
        if (it == always_notable_.end()) {
            DetectionFinding f;
            f.category = category;
            f.technique = technique;
            f.confidence = DetectionConfidence::High;
            f.client_ip = client_ip;
            f.server_ip = server_ip;
            f.protocol = protocol;
            f.server_port = server_port;
            f.description = description;
            f.first_seen = f.last_seen = dp.timestamp;
            f.packet_count = 1;
            always_notable_.emplace(key, std::move(f));
            always_notable_order_.push_back(key);
        } else {
            DetectionFinding& f = it->second;
            if (dp.timestamp < f.first_seen || f.packet_count == 0) f.first_seen = dp.timestamp;
            if (dp.timestamp > f.last_seen) f.last_seen = dp.timestamp;
            ++f.packet_count;
        }
    };

    auto record_new_conduit_candidate = [&](DetectionCategory category, const MitreAttackTechnique& technique,
                                             bool is_remote_access, const std::string& client_ip,
                                             const std::string& server_ip, const std::string& protocol,
                                             uint16_t server_port, const char* source_tag) {
        std::string key = new_conduit_key(client_ip, server_ip, protocol, server_port, source_tag);
        auto it = new_conduit_candidates_.find(key);
        if (it == new_conduit_candidates_.end()) {
            NewConduitCandidate c;
            c.category = category;
            c.technique = technique;
            c.is_remote_access = is_remote_access;
            c.client_ip = client_ip;
            c.server_ip = server_ip;
            c.protocol = protocol;
            c.server_port = server_port;
            c.first_seen = c.last_seen = dp.timestamp;
            c.packet_count = 1;
            c.source_tag = source_tag;
            new_conduit_candidates_.emplace(key, std::move(c));
            new_conduit_order_.push_back(key);
        } else {
            NewConduitCandidate& c = it->second;
            if (dp.timestamp > c.last_seen) c.last_seen = dp.timestamp;
            ++c.packet_count;
        }
    };

    // --- S7comm: PLC Control/PLC Stop (mode change), block download (firmware/logic change) -------
    // NOT gated on has_function alone: unlike has_pi_service/plc_stop_message (Job-side only, per
    // baseline.cpp's own extract_s7comm_operations comment), S7CommResult::has_function/
    // function_name are populated on BOTH the Job (request, rosctr 0x01) AND Ack_Data (response,
    // rosctr 0x03) sides -- confirmed directly against src/s7comm.cpp's own decode (the function-code
    // byte is read whenever frame.rosctr == 0x01 || frame.rosctr == 0x03), and caught during this
    // feature's own manual verification pass (sample_s7comm_pi_control.pcap's PLC Control ACK
    // initially produced a finding with client/server reversed and the PLC's own ephemeral-port-side
    // as the "target"). S7CommResult carries no rosctr field of its own to check directly (a
    // zero-flat-field migrated type that dropped it), so the request side is instead identified the
    // same way this codebase's own "known port" direction heuristic already does elsewhere: a Job
    // request is addressed TO the PLC's S7comm port (dst_port == 102); the Ack_Data response comes
    // FROM it (src_port == 102, dst_port an ephemeral client port). A non-standard-port S7comm session
    // (unusual but not rejected by this decoder) would be silently skipped by this check -- an honest,
    // documented limitation, not a crash risk.
    if (dp.protocol == "s7comm" && dp.result && dp.dst_port == 102) {
        const S7CommResult& sr = dp.result->as<S7CommResult>();
        if (sr.has_function) {
            if (sr.function_name == "PLC Stop") {
                record_always_notable("s7-plc-stop", DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm PLC Stop command -- CPU commanded to STOP from the process "
                                       "network");
            } else if (sr.function_name == "PLC Control") {
                record_always_notable("s7-plc-control", DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm PLC Control (PI-Service) command -- an engineering-station-"
                                       "class program invocation issued to the CPU");
            } else if (sr.function_name == "Request Download" || sr.function_name == "Download Block" ||
                       sr.function_name == "Download Ended") {
                record_always_notable("s7-download", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0843_program_download(), dp.src_ip, dp.dst_ip, "s7comm",
                                       dp.dst_port,
                                       "S7comm block download (" + sr.function_name +
                                           ") -- a program/logic block is being written TO the CPU from an "
                                           "engineering station");
            }
        }
    }

    // --- DNP3: Cold/Warm Restart (firmware/logic change), unsolicited misuse (protocol misuse) -----
    // Cold/Warm Restart/Enable/Disable Unsolicited Responses are all MASTER -> OUTSTATION request
    // function codes (dp.src_ip issues them, dp.dst_ip is the outstation acting on them); Unsolicited
    // Response (0x82) is the one function here sent OUTSTATION -> MASTER unprompted, so its own
    // client/server roles are the reverse of every other DNP3 function this engine reads -- see this
    // file's own header comment and dnp3_unsolicited_enabled_'s own doc comment (detect_engine.hpp)
    // for the consistent "<master>|<outstation>" key ordering used on both sides of that tracking.
    if (dp.protocol == "dnp3" && dp.result) {
        const Dnp3Result& dr = dp.result->as<Dnp3Result>();
        if (dr.dnp3_has_function) {
            if (dr.dnp3_function_name == "Cold Restart" || dr.dnp3_function_name == "Warm Restart") {
                record_always_notable("dnp3-restart", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "dnp3",
                                       dp.dst_port,
                                       "DNP3 " + dr.dnp3_function_name +
                                           " request -- an outstation is being commanded to restart");
            } else if (dr.dnp3_function_name == "Enable Unsolicited Responses") {
                dnp3_unsolicited_enabled_[dp.src_ip + "|" + dp.dst_ip] = true;
            } else if (dr.dnp3_function_name == "Disable Unsolicited Responses") {
                dnp3_unsolicited_enabled_[dp.src_ip + "|" + dp.dst_ip] = false;
            } else if (dr.dnp3_function_name == "Unsolicited Response") {
                // Reverse roles: dp.src_ip is the outstation reporting unprompted, dp.dst_ip is the
                // master. Only master IPs actually seen ENABLING unsolicited responses on this exact
                // conduit are trusted; a master this engine has never seen enable it (including one
                // this capture simply starts after -- an honest limitation, not a false-positive fix)
                // makes the report say so plainly rather than silently assume it was enabled offscreen.
                std::string ukey = dp.dst_ip + "|" + dp.src_ip;
                auto it = dnp3_unsolicited_enabled_.find(ukey);
                if (it == dnp3_unsolicited_enabled_.end() || !it->second) {
                    record_always_notable(
                        "dnp3-unsolicited-misuse", DetectionCategory::ProtocolMisuse,
                        mitre_t0855_unauthorized_command_message(), dp.dst_ip, dp.src_ip, "dnp3", dp.src_port,
                        "DNP3 Unsolicited Response from an outstation this capture never saw a master "
                        "enable unsolicited responses on (Enable Unsolicited Responses, function 0x14) -- "
                        "either enabled before this capture began, or genuinely unexpected");
                }
            }
        }
    }

    // --- IEC 104: a genuinely anomalous COT (protocol misuse), Reset Process (device restart) ------
    // Deliberately does NOT flag ordinary General/Station Interrogation (C_IC_NA_1) on its own --
    // periodic interrogation is routine SCADA master polling, and unconditionally flagging it would
    // be pure noise, not a real finding; see docs/design/detection-engine.md's own scoping note. The
    // COT values 44-47 ("unknown type identification"/"unknown cause of transmission"/"unknown
    // common address of ASDU"/"unknown information object address" -- iec104_cot_name's own table,
    // iec104.cpp) are the outstation itself flagging the exchange as malformed/unexpected, a
    // genuinely anomalous signal regardless of ASDU type -- matched on the rendered name's own
    // "unknown " prefix rather than a raw COT code (Iec104Result exposes no numeric COT field, only
    // the rendered name -- see Iec104AsduInfo's own comment, iec104.hpp).
    if (dp.protocol == "iec104" && dp.result) {
        const Iec104Result& ir = dp.result->as<Iec104Result>();
        if (ir.iec104_has_asdu) {
            if (ir.iec104_cot_name.rfind("unknown ", 0) == 0) {
                record_always_notable("iec104-unexpected-cot", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "iec104", dp.dst_port,
                                       "IEC 104 ASDU with cause-of-transmission \"" + ir.iec104_cot_name +
                                           "\" (type " + ir.iec104_asdu_type_short_name +
                                           ") -- the receiving end's own reported COT is one of IEC "
                                           "60870-5-101/104's four error codes");
            }
            // C_RP_NA_1's own type ID is shared by the command itself (COT 6, "activation") and its
            // own confirmation/termination ASDUs sent back the OTHER direction (COT 7/10) -- IEC 104
            // reuses one type ID across a command and its acknowledgments, unlike DNP3's separate
            // request/response function codes. Gated on COT "activation" specifically so this finding
            // is always the actual command, correctly directed master -> outstation, never double-
            // counted (once per direction) off the same exchange's own ack/termination ASDUs.
            if (ir.iec104_asdu_type_short_name == "C_RP_NA_1" && ir.iec104_cot_name == "activation") {
                record_always_notable("iec104-reset-process", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "iec104",
                                       dp.dst_port,
                                       "IEC 104 Reset Process command (C_RP_NA_1) -- a controlling station "
                                       "commanded a process reset");
            }
        }
    }

    // --- BACnet: reinitializeDevice (restart), deviceCommunicationControl (misuse) ------------------
    // Confirmed-Request side only (pdu_type_name == "Confirmed-Request") -- the ACK carries no
    // repeatable "what was requested" signal of its own worth a second finding, the exact same
    // "request side only" posture this engine already takes for S7/DNP3/IEC104 above. Service names
    // are lower-camelCase (kBacnetConfirmedServiceChoice, bacnet_tables.inc, transcribed from
    // Wireshark's own BACnetConfirmedServiceChoice value_string table) -- "reinitializeDevice"/
    // "deviceCommunicationControl", NOT PascalCase; confirmed directly against that table during
    // this feature's own manual verification pass after an initial PascalCase guess matched nothing.
    if (dp.protocol == "bacnet" && dp.result) {
        const BacnetFrame& bf = dp.result->as<BacnetFrame>();
        if (bf.has_npdu && bf.npdu.has_apdu && bf.npdu.apdu.pdu_type_name == "Confirmed-Request") {
            const std::string& svc = bf.npdu.apdu.service_choice_name;
            if (svc == "reinitializeDevice") {
                record_always_notable("bacnet-reinitialize", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0816_device_restart_shutdown(), dp.src_ip, dp.dst_ip, "bacnet",
                                       dp.dst_port,
                                       "BACnet ReinitializeDevice request -- a device is being commanded to "
                                       "restart or change its reinitialization state");
            } else if (svc == "deviceCommunicationControl") {
                record_always_notable("bacnet-devicecommcontrol", DetectionCategory::ProtocolMisuse,
                                       mitre_t0855_unauthorized_command_message(), dp.src_ip, dp.dst_ip,
                                       "bacnet", dp.dst_port,
                                       "BACnet DeviceCommunicationControl request -- a device's own "
                                       "communication can be silenced or re-enabled by this service");
            }
        }
    }

    // --- EtherNet/IP: CIP Forward_Open/Large_Forward_Open from a new originator (protocol misuse) --
    // Request side only (CipMessage::is_response == false) -- the response carries no originator
    // identity of its own to track. The FIRST originator ever seen opening a connection to a given
    // server is deliberately NOT flagged (nothing to be "new" relative to within this capture); a
    // SECOND, DIFFERENT originator to the SAME server is what finish() may turn into a finding --
    // see this file's own header comment and cip_originators_by_server_'s own doc comment
    // (detect_engine.hpp).
    if (dp.protocol == "enip" && dp.has_tcp && dp.result) {
        const EnipFrame& ef = dp.result->as<EnipResult>().first;
        if (ef.has_cip && !ef.cip.is_response &&
            (ef.cip.service_name == "Forward_Open" || ef.cip.service_name == "Large_Forward_Open")) {
            auto& originators = cip_originators_by_server_[dp.dst_ip];
            bool already_seen = false;
            for (const auto& o : originators) {
                if (o == dp.src_ip) {
                    already_seen = true;
                    break;
                }
            }
            if (!already_seen) {
                if (!originators.empty()) {
                    record_new_conduit_candidate(DetectionCategory::ProtocolMisuse,
                                                  mitre_t0855_unauthorized_command_message(),
                                                  /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "enip",
                                                  dp.dst_port, "cip-new-originator");
                }
                originators.push_back(dp.src_ip);
            }
        }
    }

    // --- UMAS (umas.hpp): START_PLC/STOP_PLC (mode change), download sequence (firmware/logic
    // --- change), and a new engineering-station originator issuing TAKE_PLC_RESERVATION or a
    // --- read-only discovery command (protocol misuse / engineering-station activity) -----------
    // Grok gap #4 Phase 6 -- UMAS is Modbus/TCP at the wire level (dp.protocol is "modbus", never
    // "umas"; see umas.hpp's own header comment), so this is gated on dp.protocol == "modbus" plus
    // mb.umas being set (function code 0x5A), exactly the same shape baseline.cpp's own
    // extract_modbus_operations UMAS branch uses. Request side only for all four (mb.umas->
    // is_response == false) -- a UMAS response carries no function code at all to match against
    // (see umas.hpp), so there is nothing repeatable to extract a finding from on that side, the
    // same "request side only" posture S7/DNP3/IEC104/BACnet above all take.
    if (dp.protocol == "modbus" && dp.result) {
        const ModbusFrame& mb = dp.result->as<ModbusFrame>();
        if (mb.umas && !mb.umas->is_response) {
            uint8_t fc = mb.umas->function_code;
            if (fc == UMAS_START_PLC || fc == UMAS_STOP_PLC) {
                record_always_notable(fc == UMAS_START_PLC ? "umas-start-plc" : "umas-stop-plc",
                                       DetectionCategory::EngineeringStationActivity,
                                       mitre_t0858_change_operating_mode(), dp.src_ip, dp.dst_ip, "modbus",
                                       dp.dst_port,
                                       "UMAS " + mb.umas->function_name +
                                           " command -- an engineering station changed the PLC's own "
                                           "run/stop mode");
            } else if (fc == UMAS_INITIALIZE_DOWNLOAD || fc == UMAS_DOWNLOAD_BLOCK ||
                       fc == UMAS_END_STRATEGY_DOWNLOAD) {
                record_always_notable("umas-download", DetectionCategory::FirmwareLogicChange,
                                       mitre_t0843_program_download(), dp.src_ip, dp.dst_ip, "modbus",
                                       dp.dst_port,
                                       "UMAS " + mb.umas->function_name +
                                           " -- a program/logic block is being transferred to/from the "
                                           "PLC from an engineering station");
            } else if (fc == UMAS_TAKE_PLC_RESERVATION || fc == UMAS_READ_ID ||
                       fc == UMAS_READ_PROJECT_INFO || fc == UMAS_READ_PLC_INFO) {
                // Same "second-plus originator to a given server is new, first is not" mechanism as
                // the CIP Forward_Open branch above (cip_originators_by_server_), generalized
                // across all four of these UMAS commands via one shared per-server originator set
                // (umas_engineering_originators_by_server_) rather than one map per command -- see
                // that member's own comment (detect_engine.hpp) for why a client already credited
                // via one command isn't re-flagged for later issuing a different one.
                auto& originators = umas_engineering_originators_by_server_[dp.dst_ip];
                bool already_seen = false;
                for (const auto& o : originators) {
                    if (o == dp.src_ip) {
                        already_seen = true;
                        break;
                    }
                }
                if (!already_seen) {
                    if (!originators.empty()) {
                        bool is_reservation = (fc == UMAS_TAKE_PLC_RESERVATION);
                        record_new_conduit_candidate(
                            is_reservation ? DetectionCategory::ProtocolMisuse
                                           : DetectionCategory::EngineeringStationActivity,
                            is_reservation ? mitre_t0855_unauthorized_command_message()
                                           : mitre_t0888_remote_system_information_discovery(),
                            /*is_remote_access=*/false, dp.src_ip, dp.dst_ip, "modbus", dp.dst_port,
                            is_reservation ? "umas-new-originator-reservation" : "umas-new-originator-discovery");
                    }
                    originators.push_back(dp.src_ip);
                }
            }
        }
    }

    // --- Notable IT protocols: a Tier-1 remote-access protocol reaching a conduit (RemoteAccessChannel)
    // Every one of this feature's five Tier-1 protocols (rdp/vnc/teamviewer/anydesk/zoom,
    // notable_it_protocols.hpp) is IP-based, so dp.has_ip already guards this whole function; the
    // usual port-heuristic "lower port is the server" guess (mirroring
    // AssetInventoryEngine::observe's own InventoryNotableProtocol posture, since building real
    // per-protocol direction detection for these five is out of this feature's scope) decides
    // client/server here -- see write_detection_report_text/_json for how that's caveated.
    if (auto tier = notable_it_protocol_tier(dp.protocol); tier && *tier == "remote-access") {
        // "Lower port number is the server" -- default assumes dst_ip/dst_port is the server (true
        // whenever dst_port <= src_port); swapped only when src_port is actually the LOWER of the
        // two, meaning src_ip is the real server. Caught and fixed during this feature's own manual
        // verification pass: an earlier version of this condition had the comparison backwards
        // (swapping exactly when the default was already correct), which silently reported every
        // RDP/VNC/... finding with client and server reversed.
        std::string client_ip = dp.src_ip, server_ip = dp.dst_ip;
        uint16_t server_port = dp.dst_port;
        if (dp.has_tcp && dp.src_port < dp.dst_port) {
            client_ip = dp.dst_ip;
            server_ip = dp.src_ip;
            server_port = dp.src_port;
        }
        record_new_conduit_candidate(DetectionCategory::RemoteAccessChannel, mitre_t0886_remote_services(),
                                      /*is_remote_access=*/true, client_ip, server_ip, dp.protocol,
                                      server_port, "remote-access");
    }
}

DetectionReport DetectEngine::finish(const Policy* policy, const BaselineStore* baseline) const {
    DetectionReport report;
    report.total_packets = total_packets_;

    auto in_baseline = [&](const std::string& client_ip, const std::string& server_ip,
                            const std::string& protocol, uint16_t server_port) {
        if (!baseline) return false;
        for (const auto& cb : baseline->conduits) {
            if (cb.client_ip == client_ip && cb.server_ip == server_ip && cb.protocol == protocol &&
                cb.server_port == server_port) {
                return true;
            }
        }
        return false;
    };

    for (const auto& key : always_notable_order_) {
        report.findings.push_back(always_notable_.at(key));
    }

    for (const auto& key : new_conduit_order_) {
        const NewConduitCandidate& c = new_conduit_candidates_.at(key);
        if (in_baseline(c.client_ip, c.server_ip, c.protocol, c.server_port)) continue;  // not new

        DetectionFinding f;
        f.category = c.category;
        f.confidence = baseline ? DetectionConfidence::Medium : DetectionConfidence::Low;
        f.client_ip = c.client_ip;
        f.server_ip = c.server_ip;
        f.protocol = c.protocol;
        f.server_port = c.server_port;
        f.first_seen = c.first_seen;
        f.last_seen = c.last_seen;
        f.packet_count = c.packet_count;

        if (c.is_remote_access) {
            // T0886 (Remote Services, no zone crossing) by default -- see this function's own doc
            // comment (detect_engine.hpp) for exactly when this upgrades to T0822 (External Remote
            // Services).
            f.technique = mitre_t0886_remote_services();
            bool crosses_zone = false;
            if (policy) {
                auto client_u32 = parse_ipv4_string(c.client_ip);
                auto server_u32 = parse_ipv4_string(c.server_ip);
                if (client_u32 && server_u32) {
                    const Zone* cz = policy->zone_for(*client_u32);
                    const Zone* sz = policy->zone_for(*server_u32);
                    if (cz && sz && cz->name != sz->name) crosses_zone = true;
                }
            }
            if (crosses_zone) f.technique = mitre_t0822_external_remote_services();
            std::ostringstream d;
            d << "New " << c.protocol << " (remote-access) session " << c.client_ip << " -> " << c.server_ip
              << ":" << c.server_port
              << (crosses_zone ? " -- crosses a declared zone boundary" : "");
            if (!baseline) {
                d << " -- first occurrence within this capture; no --baseline-file was supplied, so this "
                     "may already be a normal, previously-established channel -- rerun with "
                     "--baseline-file for a stronger signal";
            } else {
                d << " -- confirmed absent from the supplied baseline";
            }
            f.description = d.str();
        } else {
            f.technique = c.technique;
            std::ostringstream d;
            // source_tag picks the description template -- see NewConduitCandidate::source_tag's
            // own comment (detect_engine.hpp) for why this can't just be inferred from category/
            // technique alone (umas-new-originator-reservation shares ProtocolMisuse/T0855 with
            // cip-new-originator, but is a different UMAS command, not CIP).
            if (c.source_tag == "umas-new-originator-reservation") {
                d << "UMAS TAKE_PLC_RESERVATION from a new engineering-station originator " << c.client_ip
                  << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen issuing an engineering-station "
                     "command to this PLC in this capture";
            } else if (c.source_tag == "umas-new-originator-discovery") {
                d << "UMAS read-only discovery command (READ_ID/READ_PROJECT_INFO/READ_PLC_INFO) from a "
                     "new engineering-station originator "
                  << c.client_ip << " to " << c.server_ip
                  << " -- a different client than the one(s) already seen issuing an engineering-station "
                     "command to this PLC in this capture";
            } else {
                // "cip-new-originator" -- the only other non-remote-access source this engine has.
                d << "CIP Forward_Open from a new originator " << c.client_ip << " to " << c.server_ip
                  << " -- a different engineering/control client than the one(s) already seen opening a "
                     "connection to this target in this capture";
            }
            if (!baseline) {
                d << " (first occurrence within this capture; no --baseline-file was supplied)";
            } else {
                d << " (confirmed absent from the supplied baseline)";
            }
            f.description = d.str();
        }
        report.findings.push_back(std::move(f));
    }

    for (const auto& f : report.findings) {
        ++report.summary.total;
        switch (f.confidence) {
            case DetectionConfidence::High: ++report.summary.high; break;
            case DetectionConfidence::Medium: ++report.summary.medium; break;
            case DetectionConfidence::Low: ++report.summary.low; break;
        }
        switch (f.category) {
            case DetectionCategory::EngineeringStationActivity: ++report.summary.engineering_station_activity; break;
            case DetectionCategory::FirmwareLogicChange: ++report.summary.firmware_logic_change; break;
            case DetectionCategory::RemoteAccessChannel: ++report.summary.remote_access_channel; break;
            case DetectionCategory::ProtocolMisuse: ++report.summary.protocol_misuse; break;
        }
    }
    return report;
}

void write_detection_report_text(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    (void)resolver;  // reserved for a future service-name annotation pass, matching every other
                      // report writer's Resolver parameter -- not yet used, see LIMITATIONS
    out << "=== conduitscope detect report ===\n";
    out << "capture: " << capture_path << "\n";
    out << "total packets: " << report.total_packets << "\n";
    out << "findings: " << report.summary.total << " (High " << report.summary.high << ", Medium "
        << report.summary.medium << ", Low " << report.summary.low << ")\n";
    out << "  Engineering-Station Activity: " << report.summary.engineering_station_activity << "\n";
    out << "  Firmware/Logic Change: " << report.summary.firmware_logic_change << "\n";
    out << "  Remote-Access Channel: " << report.summary.remote_access_channel << "\n";
    out << "  Protocol Misuse: " << report.summary.protocol_misuse << "\n";

    if (report.findings.empty()) {
        out << "\nno findings\n";
        return;
    }

    out << "\n--- findings (first-seen order) ---\n";
    for (const auto& f : report.findings) {
        out << "\n[" << detection_category_name(f.category) << "] " << f.technique.id << " ("
            << f.technique.name << ") -- confidence: " << detection_confidence_name(f.confidence) << "\n";
        out << "  " << f.client_ip << " -> " << f.server_ip;
        if (f.server_port != 0) out << ":" << f.server_port;
        out << " (" << f.protocol << ")\n";
        out << "  " << f.description << "\n";
        out << "  first seen: " << format_epoch_seconds(f.first_seen)
            << "  last seen: " << format_epoch_seconds(f.last_seen) << "  packets: " << f.packet_count
            << "\n";
    }
}

void write_detection_report_json(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver) {
    (void)resolver;
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(capture_path) << "\",\n";
    out << "  \"total_packets\": " << report.total_packets << ",\n";
    out << "  \"summary\": {\n";
    out << "    \"total\": " << report.summary.total << ",\n";
    out << "    \"high\": " << report.summary.high << ",\n";
    out << "    \"medium\": " << report.summary.medium << ",\n";
    out << "    \"low\": " << report.summary.low << ",\n";
    out << "    \"engineering_station_activity\": " << report.summary.engineering_station_activity << ",\n";
    out << "    \"firmware_logic_change\": " << report.summary.firmware_logic_change << ",\n";
    out << "    \"remote_access_channel\": " << report.summary.remote_access_channel << ",\n";
    out << "    \"protocol_misuse\": " << report.summary.protocol_misuse << "\n";
    out << "  },\n";

    out << "  \"techniques_referenced\": [\n";
    auto techniques = all_mitre_attack_ics_techniques();
    for (size_t i = 0; i < techniques.size(); ++i) {
        out << "    {\"id\": \"" << json_escape(techniques[i].id) << "\", \"name\": \""
            << json_escape(techniques[i].name) << "\"}" << (i + 1 < techniques.size() ? "," : "") << "\n";
    }
    out << "  ],\n";

    out << "  \"findings\": [";
    bool first = true;
    for (const auto& f : report.findings) {
        out << (first ? "\n" : ",\n");
        first = false;
        out << "    {\n";
        out << "      \"category\": \"" << json_escape(detection_category_name(f.category)) << "\",\n";
        out << "      \"technique_id\": \"" << json_escape(f.technique.id) << "\",\n";
        out << "      \"technique_name\": \"" << json_escape(f.technique.name) << "\",\n";
        out << "      \"confidence\": \"" << json_escape(detection_confidence_name(f.confidence)) << "\",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"description\": \"" << json_escape(f.description) << "\",\n";
        out << "      \"first_seen\": " << f.first_seen << ",\n";
        out << "      \"first_seen_text\": \"" << json_escape(format_epoch_seconds(f.first_seen)) << "\",\n";
        out << "      \"last_seen\": " << f.last_seen << ",\n";
        out << "      \"last_seen_text\": \"" << json_escape(format_epoch_seconds(f.last_seen)) << "\",\n";
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }";
    }
    out << (first ? "" : "\n") << "  ]\n";
    out << "}\n";
}

}  // namespace conduitscope
