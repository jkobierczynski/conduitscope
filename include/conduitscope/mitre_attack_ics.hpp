// SPDX-License-Identifier: Apache-2.0
// mitre_attack_ics.hpp - a small, curated MITRE ATT&CK for ICS technique lookup table, built for
// Grok gap #4 (docs/reviews/2026-09-grok-ics-ot-improvement-areas.md item 4: "mapping findings to
// MITRE ATT&CK for ICS ... at the technique level, not a generic 'IT protocol seen' bucket").
// Jurgen chose MITRE ATT&CK for ICS only, no Dragos-style activity-group attribution (Dragos's own
// taxonomy is proprietary threat intel this project has no legitimate data to correlate against) --
// see docs/design/detection-engine.md for the full scoping discussion.
//
// Every technique ID/name below was independently verified against attack.mitre.org directly
// (fetched, not assumed from training data) during this feature's research pass, on 2026-09-28 --
// plus one later addition, T0872 (Indicator Removal on Host), added the same way for the Batch 1
// "Snort-style pattern extensions" follow-up (docs/research/2026-09-detect-pattern-candidates-
// batch2.md's Batch 1 item 3, Modbus Clear Counters and Diagnostic Registers) and verified against
// attack.mitre.org/techniques/T0872/ directly, not assumed. This is deliberately a SMALL, curated
// table covering exactly the finding shapes the `detect` subcommand (detect_engine.hpp) actually
// produces -- not an attempt to mirror the whole ATT&CK for ICS matrix (which has ~80 techniques
// across 12 tactics; most have no counterpart in anything this codebase can passively observe).
// Mirrors notable_it_protocols.hpp's own "just a lookup table, nothing more" posture: no decode work
// happens here, only classification of already-decoded findings.
//
// A technique ID/name pair is a factual citation (MITRE's own naming), not a diagnosis -- a
// DetectionFinding citing T0858 says "this traffic has the SHAPE ATT&CK for ICS calls Change
// Operating Mode," not "this is malicious." See DetectionFinding::confidence (detect_engine.hpp)
// for the separate, honest signal about how sure this tool is the finding itself is notable.
#pragma once

#include <string>
#include <vector>

namespace conduitscope {

// One MITRE ATT&CK for ICS technique citation. `id` is the bare technique ID ("T0858"), `name` is
// MITRE's own technique name ("Change Operating Mode") -- rendered together as "T0858 (Change
// Operating Mode)" by every report writer that cites one, matching how this codebase already cites
// other external identifiers (e.g. a CVE ID next to its own short description).
struct MitreAttackTechnique {
    std::string id;
    std::string name;
};

// The eleven techniques this feature's findings cite, each verified individually against
// attack.mitre.org/techniques/<id>/ during this feature's research pass (2026-09-28, T0872 added
// the same way in a later follow-up -- see this file's own header comment) -- not pulled from a
// bulk export, and not inferred from a technique's ID number alone (ATT&CK for ICS IDs are not
// sequentially meaningful). Declared as free functions (not a single vector) so each call site
// in detect_engine.cpp names exactly the technique it means, self-documenting at the call site
// rather than requiring a lookup-by-string.
MitreAttackTechnique mitre_t0858_change_operating_mode();      // PLC/controller stop, start, mode change
MitreAttackTechnique mitre_t0816_device_restart_shutdown();    // Device restart (cold/warm)
MitreAttackTechnique mitre_t0843_program_download();           // Firmware/logic/program download
MitreAttackTechnique mitre_t0821_modify_controller_tasking();  // Task/logic structure change
MitreAttackTechnique mitre_t0855_unauthorized_command_message();  // Unsolicited/unexpected command
MitreAttackTechnique mitre_t0886_remote_services();             // New remote-access session, no zone crossing
MitreAttackTechnique mitre_t0822_external_remote_services();    // New remote-access session, zone crossing
MitreAttackTechnique mitre_t0888_remote_system_information_discovery();  // Read-only enumeration
MitreAttackTechnique mitre_t0861_point_and_tag_identification();         // Point/tag enumeration
MitreAttackTechnique mitre_t0831_manipulation_of_control();     // Direct control manipulation, other
MitreAttackTechnique mitre_t0872_indicator_removal_on_host();   // Clearing device counters/diagnostic logs

// Returns every technique this file declares, id order -- used by write_detection_report_json's
// (detect_engine.hpp) own "techniques referenced" summary section and by tests that want to assert
// every citation this codebase can produce is one of these ten, never a stray/invented ID.
std::vector<MitreAttackTechnique> all_mitre_attack_ics_techniques();

}  // namespace conduitscope
