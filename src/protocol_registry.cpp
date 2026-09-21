// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/protocol_registry.hpp"

#include "conduitscope/eigrp.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/twincat.hpp"

namespace conduitscope {

const std::vector<const ProtocolDecoder*>& ethertype_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &goose_decoder(),  // Stage 3 of the pilot -- no ordering rationale needed beyond what its
                            // own decoder.cpp call site's comment already documents: EtherType
                            // 0x88B8 is exclusive to GOOSE, no collision possible with any other
                            // EtherType-keyed protocol (PROFINET/SV/EtherCAT/STP/EAPOL/PPPoE/MPLS),
                            // migrated or not.
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
        &modbus_decoder(),   // Stage 2 of the pilot -- decoder.cpp's call site sits exactly where
                              // Modbus's old `if (want_modbus)` block always did: after OPC UA/
                              // EtherNet/IP/IEC104 (all three still legacy), before DNP3 (also
                              // still legacy) -- see docs/DEVELOPMENT.md's PROTOCOL DETECTION
                              // section for why that position resolves the real IEC104-vs-Modbus
                              // collision found during development.
        &twincat_decoder(),  // Added directly after Modbus, before DNP3/S7comm family/HART-IP/
                              // MQTT/FF-HSE -- see decoder.cpp's TwinCAT call site comment for the
                              // full collision survey this position is based on (AMS/TCP's own
                              // multi-field State-Flags/Command-ID/Data-Length gate is stronger
                              // than Modbus's single protocol-id==0 tell, so trying it right after
                              // Modbus costs nothing and cannot be weakened by anything below it).
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& udp_port_registry() {
    static const std::vector<const ProtocolDecoder*> order = {};
    return order;
}

}  // namespace conduitscope
