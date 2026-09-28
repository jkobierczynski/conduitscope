// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/mitre_attack_ics.hpp"

namespace conduitscope {

// Each one-liner mirrors the citation this file's own header comment documents: verified directly
// against https://attack.mitre.org/techniques/<id>/ during this feature's research pass. Kept as
// individual functions rather than a static table + string-keyed lookup (contrast
// notable_it_protocols.cpp's own tier_by_protocol()) since callers in detect_engine.cpp always know
// exactly which technique they mean at the call site -- there is no "look up by observed value" use
// case here the way there is for a protocol name.

MitreAttackTechnique mitre_t0858_change_operating_mode() {
    return {"T0858", "Change Operating Mode"};
}
MitreAttackTechnique mitre_t0816_device_restart_shutdown() {
    return {"T0816", "Device Restart/Shutdown"};
}
MitreAttackTechnique mitre_t0843_program_download() {
    return {"T0843", "Program Download"};
}
MitreAttackTechnique mitre_t0821_modify_controller_tasking() {
    return {"T0821", "Modify Controller Tasking"};
}
MitreAttackTechnique mitre_t0855_unauthorized_command_message() {
    return {"T0855", "Unauthorized Command Message"};
}
MitreAttackTechnique mitre_t0886_remote_services() {
    return {"T0886", "Remote Services"};
}
MitreAttackTechnique mitre_t0822_external_remote_services() {
    return {"T0822", "External Remote Services"};
}
MitreAttackTechnique mitre_t0888_remote_system_information_discovery() {
    return {"T0888", "Remote System Information Discovery"};
}
MitreAttackTechnique mitre_t0861_point_and_tag_identification() {
    return {"T0861", "Point & Tag Identification"};
}
MitreAttackTechnique mitre_t0831_manipulation_of_control() {
    return {"T0831", "Manipulation of Control"};
}
MitreAttackTechnique mitre_t0872_indicator_removal_on_host() {
    return {"T0872", "Indicator Removal on Host"};
}

std::vector<MitreAttackTechnique> all_mitre_attack_ics_techniques() {
    // Deliberately id-sorted (not declaration order) so this list -- and anything rendered from it
    // -- stays stable if the header's own declaration order ever changes for readability.
    return {
        mitre_t0816_device_restart_shutdown(),
        mitre_t0821_modify_controller_tasking(),
        mitre_t0822_external_remote_services(),
        mitre_t0831_manipulation_of_control(),
        mitre_t0843_program_download(),
        mitre_t0855_unauthorized_command_message(),
        mitre_t0858_change_operating_mode(),
        mitre_t0861_point_and_tag_identification(),
        mitre_t0872_indicator_removal_on_host(),
        mitre_t0886_remote_services(),
        mitre_t0888_remote_system_information_discovery(),
    };
}

}  // namespace conduitscope
