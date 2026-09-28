// SPDX-License-Identifier: Apache-2.0
// detect_engine.hpp - the `detect` subcommand's engine: "Detection that OT IR teams recognize"
// (Grok gap #4, docs/reviews/2026-09-grok-ics-ot-improvement-areas.md item 4). See
// docs/design/detection-engine.md for the full design record and Jurgen's own scoping decisions.
//
// One dedicated subcommand holds every item-4 finding in a single unified report (Jurgen's own
// choice, over the alternative of splitting baseline-independent-structural findings into
// attack_detect.hpp's existing curated-notes model and new-vs-known findings into `baseline
// check`'s report). Two structurally different kinds of finding live here, exactly mirroring
// attack_detect.hpp's own "two kinds of evidence" split (see that file's header comment) but for a
// different reason:
//
// ALWAYS-NOTABLE findings -- a PLC/controller mode change, a firmware/logic download, a device
// restart, an unsolicited/unexpected protocol message -- need no "new vs. known" judgment at all:
// the traffic SHAPE itself is what's notable, every single time it's seen, the same "always worth a
// human's attention regardless of baseline" concept baseline.cpp's own Operation::always_flag
// already established for S7 PLC Control/PLC Stop (see that field's own comment, baseline.hpp).
// These get DetectionConfidence::High unconditionally and are produced entirely from fields this
// codebase already decodes -- see detect_engine.cpp's per-protocol wiring for exactly which.
//
// NEW-VS-KNOWN findings -- a remote-access protocol reaching a conduit, a CIP originator opening a
// connection -- are only notable when they're NEW, and "new" needs a concrete, honestly-labeled
// mechanism (Grok's own text: "keep the honesty: label confidence"):
//   - With an optional --baseline-file supplied (reusing baseline.hpp's own load_baseline_store/
//     BaselineStore read-only, mirroring `baseline check`'s own flag name): a conduit genuinely
//     absent from the loaded store's ConduitBaseline list is real evidence of "new" ->
//     DetectionConfidence::Medium.
//   - Genuinely PRESENT in the loaded baseline: not new at all -- no finding is produced.
//   - No --baseline-file given (the common single-pcap assessment case): evaluated as
//     first-occurrence-within-this-capture -- weaker evidence (the capture might simply start after
//     the channel was already long-established), so DetectionConfidence::Low, and the finding's own
//     description says so and suggests --baseline-file.
// See DetectEngine::finish's own comment for exactly how this two-stage (per-packet candidate
// tracking, then whole-capture baseline resolution) pipeline works.
//
// Confidence is deliberately new-findings-only for now: retrofitting a structured confidence field
// onto attack_detect.hpp/ipv6_attack_detect.hpp/baseline's own existing findings is a separate,
// larger effort across already-shipped, already-tested code, and wasn't part of what Jurgen asked
// to start here -- see docs/design/detection-engine.md's own "explicitly out of scope" note.
//
// Six Snort-style patterns added as a direct follow-up (docs/design/detection-engine.md's own
// "Snort-style pattern extensions" section has the full research/scoping record for each):
//   - CIP Identity Object write (any Set_Attribute_Single/Set_Attributes_All WRITE addressed at CIP
//     class 0x01) -- always-notable, ProtocolMisuse/T0855. Deliberately scoped to "any write to the
//     Identity object" rather than a specific run/idle-mode attribute/value, since no citable
//     primary source for a ControlLogix mode-change wire format could be found -- see
//     detect_engine.cpp's own call-site comment.
//   - DNP3 Operate (0x04) with no matching prior Select (0x03) on the same master/outstation pair --
//     always-notable, ProtocolMisuse/T0855. Deliberately NOT "Direct Operate observed" (Direct
//     Operate is a legitimate, routinely-used DNP3 mechanism, not a bypass) -- see
//     dnp3_select_seen_'s own comment.
//   - A Modbus Write Multiple Coils/Registers request whose address range was never covered by any
//     prior read (same function family, same conduit) in this capture -- always-notable but
//     DetectionConfidence::Low unconditionally (not the usual unconditional High every other
//     always-notable finding gets): many legitimate deployments write setpoints without ever
//     reading them back first, so this is honestly a much weaker signal -- see
//     modbus_read_ranges_by_conduit_table_'s own comment and record_always_notable's own
//     confidence parameter (detect_engine.cpp).
//   - A BACnet Who-Is volumetric flood/enumeration sweep from one source, past a threshold --
//     always-notable, ProtocolMisuse/T0888 -- see bacnet_who_is_count_by_source_'s own comment.
//   - S7comm Setup Communication (0xF0) probing: a (client, server) pair with Setup Communication
//     seen repeatedly and NO other S7comm function ever seen between them in this whole capture --
//     resolved in finish() (not observe(), since "no other function ever seen" can only be known
//     once the whole capture has been read), EngineeringStationActivity/T0888 -- see
//     s7_setup_comm_state_'s own comment.
//   - A composite: a Program Download finding (T0843) and a restart/mode-change finding (T0858/
//     T0816) both seen against the same server within a short window -- the classic "install then
//     activate" sabotage sequence, not necessarily two unrelated findings. Resolved in finish() as a
//     post-pass over this engine's OWN already-produced findings (needs no new observe()-time
//     tracking) -- FirmwareLogicChange/T0831, see finish()'s own implementation comment
//     (detect_engine.cpp).
#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "conduitscope/baseline.hpp"  // BaselineStore -- optional finish() input
#include "conduitscope/decoder.hpp"
#include "conduitscope/mitre_attack_ics.hpp"
#include "conduitscope/policy.hpp"  // Policy -- optional finish() input, for T0886-vs-T0822

namespace conduitscope {

class Resolver;  // forward-declared -- see asset_inventory.hpp's own identical forward declaration

// One of the four finding shapes Grok's item 4 names -- see this file's own header comment for the
// techniques each maps to. Independent of DetectionConfidence: a category says WHAT KIND of thing
// this is, confidence says HOW SURE this tool is it's genuinely notable.
enum class DetectionCategory {
    EngineeringStationActivity,  // a PLC/controller mode change (S7 PLC Control/Stop, ...)
    FirmwareLogicChange,         // a firmware/logic/program download, or a device restart
    RemoteAccessChannel,         // a new remote-access session (RDP/VNC/TeamViewer/...) into a zone
    ProtocolMisuse,              // an unsolicited/unexpected protocol message, a new CIP originator
};

const char* detection_category_name(DetectionCategory category);  // "Engineering-Station Activity",
                                                                     // "Firmware/Logic Change",
                                                                     // "Remote-Access Channel",
                                                                     // "Protocol Misuse"

// See this file's own header comment for exactly what each level means and how it's decided.
enum class DetectionConfidence { High, Medium, Low };

const char* detection_confidence_name(DetectionConfidence confidence);  // "High"/"Medium"/"Low"

// One finding. `technique` is always populated (every finding this engine produces cites exactly
// one MITRE ATT&CK for ICS technique, from mitre_attack_ics.hpp's own curated ten) -- never a
// generic "something happened" note with no citation, matching Grok's own "not a generic 'IT
// protocol seen' bucket" ask.
struct DetectionFinding {
    DetectionCategory category = DetectionCategory::ProtocolMisuse;
    MitreAttackTechnique technique;
    DetectionConfidence confidence = DetectionConfidence::Low;
    std::string client_ip, server_ip;  // client_ip is the initiator/originator side
    std::string protocol;              // "s7comm"/"dnp3"/"iec104"/"bacnet"/"enip"/"rdp"/"vnc"/...
    uint16_t server_port = 0;          // 0 when not meaningful (e.g. a MAC-only remote-access match
                                        // never happens in practice for this feature's tier-1
                                        // protocols, which are all IP-based -- kept for symmetry with
                                        // every other protocol here)
    std::string description;           // human-readable, incident-ticket-ready -- see
                                        // detect_engine.cpp for exactly what each finding source
                                        // writes here, including the Low-confidence
                                        // first-occurrence caveat text
    double first_seen = 0.0;
    double last_seen = 0.0;
    size_t packet_count = 0;
};

struct DetectionSummary {
    size_t total = 0;
    size_t high = 0, medium = 0, low = 0;
    size_t engineering_station_activity = 0, firmware_logic_change = 0, remote_access_channel = 0,
           protocol_misuse = 0;
};

struct DetectionReport {
    std::vector<DetectionFinding> findings;  // first-seen order
    DetectionSummary summary;
    size_t total_packets = 0;
};

class DetectEngine {
public:
    // Folds one already-decoded packet into this engine's state. Call once per packet, in capture
    // order (same discipline as Decoder::decode/PolicyEngine::observe/AssetInventoryEngine::observe).
    //
    // Produces an ALWAYS-NOTABLE finding immediately (usually High confidence -- the Modbus
    // write-without-prior-read pattern below is the one deliberate exception, see its own comment)
    // the first time a given (category, technique, client_ip, server_ip, protocol, server_port)
    // combination is observed; a later packet matching the same combination only updates that
    // finding's own last_seen/packet_count, never creates a second finding for the same combination
    // -- see detect_engine.cpp's own per-protocol wiring for exactly which decoded fields produce
    // these (S7 PLC Control/PLC Stop/block-download, DNP3 Cold/Warm Restart/Enable-Unsolicited-then-
    // Unsolicited-Response-with-none-seen/Operate-with-no-prior-Select, an ASDU with an "unknown ..."
    // IEC 104 COT/a C_RP_NA_1 Reset Process command, BACnet ReinitializeDevice/
    // DeviceCommunicationControl/a Who-Is flood past threshold, a CIP Identity Object write, a
    // Modbus write outside every range ever read on the same conduit/table).
    //
    // Tracks a NEW-VS-KNOWN candidate (see this file's own header comment) the first time a given
    // (client_ip, server_ip, protocol, server_port) conduit is observed carrying a Tier-1
    // remote-access protocol (notable_it_protocols.hpp) or a CIP Forward_Open/Large_Forward_Open
    // from a client not seen opening one before -- these do NOT become findings here; finish()
    // resolves them against an optional baseline.
    void observe(const DecodedPacket& packet);

    // Produces the final report. `policy`: optional (nullptr when `detect --policy` wasn't given) --
    // used only to resolve a RemoteAccessChannel finding's technique between T0886 (Remote Services,
    // no zone crossing) and T0822 (External Remote Services, crosses a zone boundary): when both
    // endpoints resolve to a declared zone and the zones differ, T0822; otherwise (no policy, an
    // endpoint outside every declared zone, or both endpoints in the same zone) the narrower T0886
    // claim, since "crossed a boundary" isn't inferable without a policy that says where the
    // boundaries are.
    //
    // `baseline`: optional (nullptr when `detect --baseline-file` wasn't given) -- used to resolve
    // every tracked new-vs-known candidate: a candidate whose (client_ip, server_ip, protocol,
    // server_port) key matches a ConduitBaseline entry in `baseline->conduits` is NOT new (dropped
    // entirely, no finding produced); a candidate genuinely absent gets DetectionConfidence::Medium.
    // With `baseline` null, every tracked candidate becomes a DetectionConfidence::Low finding
    // instead (first-occurrence-within-this-capture -- see this file's own header comment).
    //
    // Also resolves the two finding sources that genuinely need whole-capture knowledge and so
    // can't be decided in observe() alone: S7comm Setup Communication probing
    // (s7_setup_comm_state_ -- "no other function ever seen" can't be confirmed mid-capture), and
    // the download-then-restart composite (a post-pass over this SAME call's own already-produced
    // findings, so it always sees the complete set -- see detect_engine.cpp's own implementation
    // comment for both).
    //
    // Safe to call more than once; does not reset state.
    DetectionReport finish(const Policy* policy = nullptr, const BaselineStore* baseline = nullptr) const;

private:
    // Keyed by "<category>|<technique-id>|<client_ip>|<server_ip>|<protocol>|<server_port>" -- see
    // detect_engine.cpp's own always_notable_key(). Insertion order preserved via
    // always_notable_order_ so the final report is deterministic independent of an
    // unordered_map's own iteration order.
    std::unordered_map<std::string, DetectionFinding> always_notable_;
    std::vector<std::string> always_notable_order_;

    // One tracked new-vs-known candidate -- see this file's own header comment. `category`/
    // `technique_no_zone_crossing` covers the RemoteAccessChannel case's own T0886 default (finish()
    // may upgrade it to T0822); every other new-vs-known source (CIP originator) has a single fixed
    // technique with no such upgrade.
    struct NewConduitCandidate {
        DetectionCategory category = DetectionCategory::ProtocolMisuse;
        MitreAttackTechnique technique;
        bool is_remote_access = false;  // true only for the RemoteAccessChannel source -- the one
                                          // case finish() may retarget T0886 -> T0822
        std::string client_ip, server_ip, protocol;
        uint16_t server_port = 0;
        double first_seen = 0.0;
        double last_seen = 0.0;
        size_t packet_count = 0;
        // The exact `source_tag` record_new_conduit_candidate (detect_engine.cpp) was called
        // with -- carried onto the candidate itself (not just folded into the map key) so
        // finish() can pick the right description template for a non-remote-access candidate:
        // "cip-new-originator", "umas-new-originator-reservation", or
        // "umas-new-originator-discovery" each read differently even though they share the same
        // category/technique shape in some cases. Remote-access candidates render from
        // is_remote_access instead (their own source_tag is always "remote-access", never checked).
        std::string source_tag;
    };
    // Keyed by "<client_ip>|<server_ip>|<protocol>|<server_port>|<source-tag>" -- see
    // detect_engine.cpp's own new_conduit_key(). Two different sources (remote-access, CIP
    // originator) never share a key even for the same 4-tuple, since they're different findings
    // about the same conduit.
    std::unordered_map<std::string, NewConduitCandidate> new_conduit_candidates_;
    std::vector<std::string> new_conduit_order_;

    // CIP-originator tracking: every client_ip this engine has ever seen open a Forward_Open/
    // Large_Forward_Open to a given server_ip, so a SECOND originator to the SAME server is the one
    // that's actually new -- the first originator ever seen for a server is not itself flagged (it
    // has nothing to be "new" relative to within this capture; see detect_engine.cpp's own comment
    // at the call site for why this asymmetry is deliberate, not an oversight).
    std::unordered_map<std::string, std::vector<std::string>> cip_originators_by_server_;

    // The UMAS (umas.hpp) analog of cip_originators_by_server_ above -- same "second-plus
    // originator to a given server is new, first is not" mechanism, generalized across all four
    // UMAS engineering-station commands this engine tracks (TAKE_PLC_RESERVATION,
    // READ_ID/READ_PROJECT_INFO/READ_PLC_INFO) rather than one map per command: a client already
    // credited as a known originator via one of these commands isn't re-flagged for later issuing
    // a DIFFERENT one of the four against the same server -- see detect_engine.cpp's own call site
    // comment for why that's the right posture, not an oversight.
    std::unordered_map<std::string, std::vector<std::string>> umas_engineering_originators_by_server_;

    // DNP3 unsolicited-response tracking: every (client_ip, server_ip) pair that has seen an Enable
    // Unsolicited Responses (0x14) request, so a later Unsolicited Response (0x82) from a server
    // that was never enabled is the misuse-shaped case -- see detect_engine.cpp's own call site.
    // Keyed "<master_ip>|<outstation_ip>".
    std::unordered_map<std::string, bool> dnp3_unsolicited_enabled_;

    // DNP3 Select-before-Operate tracking: every (master_ip, outstation_ip) pair that has seen a
    // Select (0x03) request, so a later Operate (0x04) with no Select ever recorded for that same
    // pair is the misuse-shaped case. Deliberately does NOT flag Direct Operate (0x05) at all --
    // Direct Operate is a real, spec-legal, routinely-used DNP3 mechanism that intentionally skips
    // Select, not a bypass of one; flagging every Direct Operate would be pure noise, not a real
    // finding (this was this engine's own original, imprecise framing of this pattern -- corrected
    // before implementation once DNP3's actual semantics were checked, see docs/design/
    // detection-engine.md). Also deliberately coarse: a "Select ever seen for this pair" boolean,
    // not per-object-index Select/Operate pairing (DNP3's own spec pairs a Select with a SPECIFIC
    // point/index, immediately followed by the matching Operate) -- the same "per-pair, not
    // per-object" granularity dnp3_unsolicited_enabled_ above already uses for this same reason:
    // this engine has no cross-request object-index correlation state today, and a coarser signal
    // that's honestly scoped beats a falsely-precise one this codebase can't actually back. Never
    // reset to false (unlike dnp3_unsolicited_enabled_, which DOES toggle off on Disable Unsolicited
    // Responses -- there is no DNP3 "un-select" concept to mirror that with). Keyed
    // "<master_ip>|<outstation_ip>", same ordering convention as dnp3_unsolicited_enabled_.
    std::unordered_map<std::string, bool> dnp3_select_seen_;

    // Modbus write-without-prior-read tracking: every address range ([start, start+quantity)) a
    // Read Coils or Read Holding Registers request has observed, per conduit AND per address-space
    // table -- so a Write Multiple Coils/Registers request whose range isn't covered by any prior
    // read from the SAME table on the SAME conduit is the notable case. Deliberately two separate
    // per-conduit maps in spirit (one keyed table per Modbus's own two writable data tables, Coils
    // and Holding Registers -- Discrete Inputs and Input Registers are read-only tables nothing ever
    // writes to, so they're never tracked here at all), folded into one map keyed
    // "<client_ip>|<server_ip>|<server_port>|<table>" (table is "coils" or "holding_registers")
    // rather than two separate members, mirroring extract_modbus_operations' own (baseline.cpp)
    // "one address space per function" framing so a Coils read never silences a Holding-Registers
    // write or vice versa. Write Single Coil/Write Single Register are NOT covered by this pattern
    // at all -- modbus.hpp's own ModbusFrame::start_address/quantity comment documents why those two
    // functions have no is_request-confirmed direction signal to key on in the first place. Ranges
    // are merge-on-insert coalesced (see detect_engine.cpp's own modbus_merge_range_into, a small
    // local copy of baseline.cpp's own merge_range_into -- this file's own per-translation-unit-copy
    // convention, matching json_escape/format_epoch_seconds above) so a write spanning what were
    // originally two separate, now-adjacent/overlapping reads is still correctly recognized as fully
    // covered.
    std::unordered_map<std::string, std::vector<std::pair<uint32_t, uint32_t>>>
        modbus_read_ranges_by_conduit_table_;

    // BACnet Who-Is volumetric flood/device-enumeration-sweep tracking: a running count of Who-Is
    // (unconfirmed service choice 8, "who-Is") requests seen from a given source IP across this
    // whole capture, regardless of destination (Who-Is is routinely sent as a BACnet/IP broadcast,
    // so grouping by source alone -- not source+destination -- is the right granularity: the same
    // sweep would otherwise be split across however many distinct broadcast/unicast destinations it
    // happened to use). Once a source's count reaches kBacnetWhoIsFloodThreshold
    // (detect_engine.cpp), every Who-Is from that source (including ones already counted before the
    // threshold was reached) becomes part of one always-notable finding -- see detect_engine.cpp's
    // own call site for exactly how the threshold check is done. Keyed by bare source IP.
    std::unordered_map<std::string, size_t> bacnet_who_is_count_by_source_;

    // S7comm Setup Communication (function code 0xF0) probing state, per (client_ip, server_ip)
    // pair -- see this struct's own two fields for exactly what's tracked. Deliberately resolved in
    // finish(), not observe(): "no other S7comm function was EVER seen between this pair" can only
    // be known once the whole capture has been read (a later packet could always introduce a real
    // function), unlike every other always-notable source in this engine, which only ever needs the
    // CURRENT packet plus already-settled prior state to decide. Keyed "<client_ip>|<server_ip>".
    struct S7SetupCommProbeState {
        size_t setup_comm_count = 0;
        bool other_function_seen = false;  // true once ANY S7comm function other than Setup
                                             // Communication has been seen from this client to this
                                             // server -- PLC Stop/Control, Read/Write Var, block
                                             // download, anything at all; a pair that goes on to do
                                             // real engineering-station work is not probing.
        double first_seen = 0.0;
        double last_seen = 0.0;
    };
    std::unordered_map<std::string, S7SetupCommProbeState> s7_setup_comm_state_;

    size_t total_packets_ = 0;
};

// Renders `report` as a human-readable text report to `out`: a summary line, then every finding
// grouped by category, each showing its technique citation, confidence, endpoints, and description.
// `capture_path` is shown in the report header purely for context. `resolver` supplies the same
// OUI/hostname/service-name annotations every other report writer in this codebase already provides.
void write_detection_report_text(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

// Renders `report` as JSON to `out`, for scripting/automation. Includes a "techniques_referenced"
// array (all_mitre_attack_ics_techniques()'s own full ten, not just the ones this report actually
// cites) so a consumer always has the full citation text available without a second lookup.
void write_detection_report_json(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

}  // namespace conduitscope
