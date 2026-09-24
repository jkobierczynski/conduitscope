// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/j1939.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// j1939_fmt_address's own curated handful -- see j1939.hpp's own "29-bit CAN identifier structure"
// paragraph for why this is a small subset of Wireshark's own ~90-entry NMEA-2000-flavored table,
// not a full port.
std::string j1939_source_address_name(uint8_t addr) {
    switch (addr) {
        case 0: return "Engine #1";
        case 3: return "Transmission #1";
        case 11: return "Brakes - System Controller";
        case 23: return "Instrument Cluster #1";
        case 33: return "Body Controller";
        case 49: return "Cab Controller - Primary";
        case 249: return "Off Board Diagnostic-Service Tool #1";
        case 250: return "Off Board Diagnostic-Service Tool #2";
        case 254: return "Null Address";
        case 255: return "GLOBAL";
        default: return "";
    }
}

// Curated PGN name table -- see j1939.hpp's own "Curated PGN table" paragraph for the full citation
// and rationale. Every one of these fourteen values (plus the four given full field decode
// elsewhere in this file) is named; anything else returns empty (shown as a bare PGN number).
std::string j1939_pgn_name(uint32_t pgn) {
    switch (pgn) {
        case 59392: return "Acknowledgment";
        case 59904: return "Request";
        case 60928: return "Address Claimed";
        case 61443: return "EEC2";
        case 61444: return "EEC1";
        case 61445: return "ETC1";
        case 65226: return "DM1";
        case 65227: return "DM2";
        case 65253: return "Engine Hours, Revolutions";
        case 65262: return "ET1";
        case 65263: return "EFL/P1";
        case 65265: return "CCVS";
        case 65266: return "LFE";
        case 65276: return "DD";
        default: return "";
    }
}

// Shared 2-bit SAE J1939 status convention -- see j1939.hpp's own "CCVS"/"DM1" paragraphs.
std::string j1939_two_bit_status_name(uint8_t v) {
    switch (v & 0x03) {
        case 0: return "Off";
        case 1: return "On";
        case 2: return "Reserved";
        default: return "Not Available";
    }
}

void decode_eec1(J1939Frame& f) {
    if (f.payload.size() < 5) {
        f.notes.push_back("EEC1 message shorter than the 5 bytes needed for Driver's Demand/Actual "
                           "Percent Torque + Engine Speed -- not decoded");
        return;
    }
    f.has_eec1 = true;
    f.eec1_driver_demand_percent_torque = static_cast<int>(f.payload.at(1)) - 125;
    f.eec1_actual_percent_torque = static_cast<int>(f.payload.at(2)) - 125;
    uint16_t raw_speed = static_cast<uint16_t>(f.payload.at(3) | (f.payload.at(4) << 8));
    f.eec1_engine_speed_rpm = raw_speed * 0.125;
}

void decode_et1(J1939Frame& f) {
    if (f.payload.size() < 2) {
        f.notes.push_back("ET1 message shorter than the 2 bytes needed for Coolant/Fuel Temperature "
                           "-- not decoded");
        return;
    }
    f.has_et1 = true;
    f.et1_coolant_temp_c = static_cast<int>(f.payload.at(0)) - 40;
    f.et1_fuel_temp_c = static_cast<int>(f.payload.at(1)) - 40;
    if (f.payload.size() >= 4) {
        f.et1_has_oil_temp = true;
        uint16_t raw_oil = static_cast<uint16_t>(f.payload.at(2) | (f.payload.at(3) << 8));
        f.et1_oil_temp_c = raw_oil * 0.03125 - 273.0;
    }
}

void decode_ccvs(J1939Frame& f) {
    f.has_ccvs = true;
    if (f.payload.size() >= 2) {
        f.ccvs_has_speed = true;
        uint16_t raw_speed = static_cast<uint16_t>(f.payload.at(0) | (f.payload.at(1) << 8));
        f.ccvs_vehicle_speed_kmh = raw_speed / 256.0;
    }
    if (f.payload.size() >= 3) {
        f.ccvs_has_cruise_active = true;
        f.ccvs_cruise_active_raw = static_cast<uint8_t>((f.payload.at(2) >> 6) & 0x03);
        f.ccvs_cruise_active_name = j1939_two_bit_status_name(f.ccvs_cruise_active_raw);
    }
    if (!f.ccvs_has_speed) {
        f.notes.push_back("CCVS message with no payload at all -- Wheel-Based Vehicle Speed not "
                           "decoded");
    }
}

void decode_request(J1939Frame& f) {
    f.has_request = true;
    if (f.payload.size() >= 3) {
        f.request_has_target_pgn = true;
        f.request_target_pgn = static_cast<uint32_t>(f.payload.at(0)) |
                                (static_cast<uint32_t>(f.payload.at(1)) << 8) |
                                (static_cast<uint32_t>(f.payload.at(2)) << 16);
    } else {
        f.notes.push_back("Request message shorter than the 3 bytes needed for the target PGN -- "
                           "not decoded");
    }
}

void decode_dm1(J1939Frame& f) {
    f.has_dm1 = true;
    if (f.payload.size() < 1) {
        f.notes.push_back("DM1 message with no payload at all -- lamp status not decoded");
        return;
    }
    f.dm1_has_lamp_status = true;
    uint8_t b0 = f.payload.at(0);
    f.dm1_mil_raw = static_cast<uint8_t>((b0 >> 6) & 0x03);
    f.dm1_rsl_raw = static_cast<uint8_t>((b0 >> 4) & 0x03);
    f.dm1_awl_raw = static_cast<uint8_t>((b0 >> 2) & 0x03);
    f.dm1_pl_raw = static_cast<uint8_t>(b0 & 0x03);
    f.dm1_mil_name = j1939_two_bit_status_name(f.dm1_mil_raw);
    f.dm1_rsl_name = j1939_two_bit_status_name(f.dm1_rsl_raw);
    f.dm1_awl_name = j1939_two_bit_status_name(f.dm1_awl_raw);
    f.dm1_pl_name = j1939_two_bit_status_name(f.dm1_pl_raw);

    if (f.payload.size() >= 2) f.dm1_flash_byte_present = true;

    if (f.payload.size() > 2) {
        size_t remaining = f.payload.size() - 2;
        size_t dtc_count = remaining / 4;  // whatever complete 4-byte blocks are present -- see
                                             // j1939.hpp's own "DM1" paragraph
        for (size_t i = 0; i < dtc_count; ++i) {
            size_t off = 2 + i * 4;
            uint8_t d0 = f.payload.at(off), d1 = f.payload.at(off + 1);
            uint8_t d2 = f.payload.at(off + 2), d3 = f.payload.at(off + 3);
            J1939Dtc dtc;
            dtc.spn = static_cast<uint32_t>(d0) | (static_cast<uint32_t>(d1) << 8) |
                      (static_cast<uint32_t>((d2 >> 5) & 0x07) << 16);
            dtc.fmi = static_cast<uint8_t>(d2 & 0x1F);
            dtc.conversion_method = (d3 & 0x80) != 0;
            dtc.occurrence_count = static_cast<uint8_t>(d3 & 0x7F);
            f.dm1_dtcs.push_back(dtc);
        }
        if (remaining % 4 != 0) {
            f.notes.push_back("DM1 message's own DTC area isn't a whole number of 4-byte blocks -- "
                               "the trailing partial block was not decoded");
        }
    }
}

}  // namespace

std::optional<J1939Frame> try_parse_j1939(const CanSocketcanFrame& can) {
    // Mirrors dissect_j1939's own literal first check exactly -- see j1939.hpp's file header
    // comment's "ONE FURTHER DIFFERENCE" paragraph for why RTR is deliberately NOT rejected here,
    // unlike try_parse_devicenet/try_parse_canopen.
    if (!can.eff || can.err) return std::nullopt;

    J1939Frame f;
    f.can_id = can.id & CAN_EFF_MASK;
    f.priority = static_cast<uint8_t>((f.can_id >> 26) & 0x07);
    f.extended_data_page = (f.can_id & 0x02000000) != 0;
    f.data_page = (f.can_id & 0x01000000) != 0;
    f.pdu_format = static_cast<uint8_t>((f.can_id >> 16) & 0xFF);
    f.pdu_specific = static_cast<uint8_t>((f.can_id >> 8) & 0xFF);
    f.source_address = static_cast<uint8_t>(f.can_id & 0xFF);
    f.source_address_name = j1939_source_address_name(f.source_address);
    f.is_rtr = can.rtr;
    f.fd = can.fd;
    f.payload = can.payload;
    f.payload_truncated = can.truncated;
    for (const auto& n : can.notes) f.notes.push_back(n);

    // PGN reconstruction -- see j1939.hpp's own "PDU1 vs. PDU2 and PGN reconstruction" paragraph,
    // reproduced exactly from dissect_j1939's own `pgn = (can_info.id & 0x3FFFF00) >> 8;` plus its
    // PF-vs-240 branch.
    uint32_t pgn18 = (f.can_id & 0x03FFFF00) >> 8;
    f.is_pdu1 = f.pdu_format < 240;
    if (f.is_pdu1) {
        f.pgn = pgn18 & 0x0003FF00;
        f.destination_address = f.pdu_specific;
        f.destination_is_broadcast = (f.destination_address == 255);
    } else {
        f.pgn = pgn18;
    }
    f.pgn_name = j1939_pgn_name(f.pgn);

    if (f.fd) {
        f.notes.push_back(
            "CAN FD frame (fd_flags 0x04 set) -- UNLIKE DeviceNet/CANopen on this same link type, "
            "this decoder still attempts its normal payload-derived decoding for a J1939 FD frame "
            "(J1939-22 legitimately rides CAN FD); see j1939.hpp's own file header comment");
    }

    std::ostringstream s;
    s << "J1939 PGN " << f.pgn;
    if (!f.pgn_name.empty()) s << " (" << f.pgn_name << ")";
    s << " Priority=" << static_cast<unsigned>(f.priority)
      << " SA=" << static_cast<unsigned>(f.source_address);
    if (!f.source_address_name.empty()) s << " (" << f.source_address_name << ")";
    if (f.is_pdu1) {
        s << " DA=" << static_cast<unsigned>(f.destination_address);
        if (f.destination_is_broadcast) s << " (GLOBAL)";
    } else {
        s << " (broadcast)";
    }

    if (f.is_rtr) {
        s << " [RTR -- no payload]";
        f.summary = s.str();
        return f;
    }

    // UNLIKE DeviceNet/CANopen (both of which predate CAN FD entirely and never legitimately carry
    // a larger-than-classic payload -- see devicenet.hpp/canopen.hpp's own CAN FD scope notes), a
    // CAN FD frame is NOT skipped here: J1939-22 (the CAN-FD-riding successor to classic J1939)
    // legitimately uses larger payloads, and this decoder's own curated per-PGN decoders (below)
    // read however many bytes `f.payload` actually contains regardless of how it got that size --
    // see j1939.hpp's own "DM1" paragraph for why a CAN FD DM1 frame carrying more than one DTC
    // without needing J1939's own multi-packet Transport Protocol is exactly the scenario this
    // enables (`tools/make_sample_pcap.py`'s own `build_canopen_j1939_sample` exercises this).
    if (f.pgn == 61444) {
        decode_eec1(f);
        if (f.has_eec1) {
            s << " EngineSpeed=" << f.eec1_engine_speed_rpm << "rpm ActualTorque="
              << f.eec1_actual_percent_torque << "%";
        }
    } else if (f.pgn == 65262) {
        decode_et1(f);
        if (f.has_et1) {
            s << " Coolant=" << f.et1_coolant_temp_c << "C Fuel=" << f.et1_fuel_temp_c << "C";
        }
    } else if (f.pgn == 65265) {
        decode_ccvs(f);
        if (f.ccvs_has_speed) s << " VehicleSpeed=" << f.ccvs_vehicle_speed_kmh << "km/h";
        if (f.ccvs_has_cruise_active) s << " CruiseActive=" << f.ccvs_cruise_active_name;
    } else if (f.pgn == 59904) {
        decode_request(f);
        if (f.request_has_target_pgn) s << " TargetPGN=" << f.request_target_pgn;
    } else if (f.pgn == 65226) {
        decode_dm1(f);
        if (f.dm1_has_lamp_status) {
            s << " MIL=" << f.dm1_mil_name;
            if (!f.dm1_dtcs.empty()) {
                s << " DTCs=" << f.dm1_dtcs.size();
                for (const auto& dtc : f.dm1_dtcs) {
                    s << " [SPN=" << dtc.spn << " FMI=" << static_cast<unsigned>(dtc.fmi)
                      << " OC=" << static_cast<unsigned>(dtc.occurrence_count) << "]";
                }
            }
        }
    } else {
        s << " data=" << f.payload.size() << " byte(s) (structural only)";
    }

    f.summary = s.str();
    return f;
}

std::optional<ProtocolResult> J1939Decoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    // See j1939.hpp's own J1939Decoder comment for why this can throw ParseError.
    CanSocketcanFrame can = parse_socketcan_frame(payload);
    if (auto frame = try_parse_j1939(can)) {
        return ProtocolResult::make<J1939Frame>("j1939", std::move(*frame));
    }
    return std::nullopt;
}

const ProtocolDecoder& j1939_decoder() {
    static const J1939Decoder instance;
    return instance;
}

}  // namespace conduitscope
