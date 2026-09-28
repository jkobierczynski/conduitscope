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
#pragma once

#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
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
    // Produces an ALWAYS-NOTABLE finding immediately (High confidence) the first time a given
    // (category, technique, client_ip, server_ip, protocol, server_port) combination is observed;
    // a later packet matching the same combination only updates that finding's own last_seen/
    // packet_count, never creates a second finding for the same combination -- see
    // detect_engine.cpp's own per-protocol wiring for exactly which decoded fields produce these
    // (S7 PLC Control/PLC Stop/block-download, DNP3 Cold/Warm Restart/Enable-Unsolicited-then-
    // Unsolicited-Response-with-none-seen/an ASDU with an "unknown ..." IEC 104 COT/a C_RP_NA_1
    // Reset Process command, BACnet ReinitializeDevice/DeviceCommunicationControl).
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
