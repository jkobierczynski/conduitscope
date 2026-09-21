// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/protocol_registry.hpp"

#include "conduitscope/cotp.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/eigrp.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/s7commplus.hpp"
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
        &dnp3_decoder(),     // Migration batch 2 -- sits exactly where the old `if (want_dnp3)`
                              // block always did: after Modbus/TwinCAT (both above), before the
                              // COTP/S7comm family below (also still true after COTP's own
                              // migration in this same batch). No ordering rationale beyond
                              // position preservation -- DNP3's data-link magic bytes (0x05 0x64)
                              // don't collide with anything else in this cascade.
        &cotp_decoder(),     // Migration batch 2 -- sits exactly where the old, single
                              // `if (want_s7comm || want_mms || want_s7commplus)` block always did:
                              // after DNP3 (migrated above, in this same batch), before HART-IP/
                              // MQTT/FF-HSE (still legacy). See decoder.cpp's own call site
                              // comment for the RDP CR/CC carve-out this position sits right after.
    };
    return order;
}

const std::vector<const ProtocolDecoder*>& udp_port_registry() {
    static const std::vector<const ProtocolDecoder*> order = {};
    return order;
}

const std::vector<const ProtocolDecoder*>& udp_port_independent_registry() {
    static const std::vector<const ProtocolDecoder*> order = {};
    return order;
}

const std::vector<const ProtocolDecoder*>& cotp_payload_registry() {
    static const std::vector<const ProtocolDecoder*> order = {
        &s7comm_decoder(),       // Tried first -- classic S7comm's own protocol-id byte (0x32) is
                                   // this whole family's strongest, cheapest single-byte gate.
        &s7comm_plus_decoder(),  // Tried next, purely for file-organization reasons (S7comm and
                                   // S7comm-Plus are conceptually "the same vendor's two
                                   // generations") -- disambiguated from S7comm by its own,
                                   // different protocol-id byte (0x72), so there is no detection-
                                   // strength reason it couldn't run first instead.
        &mms_decoder(),          // Tried last -- S7comm's single-byte protocol-id gate is tried
                                   // first since it is materially stronger and cheaper; this is
                                   // only reached once that (and S7comm-Plus's) has already failed.
    };
    return order;
}

}  // namespace conduitscope
