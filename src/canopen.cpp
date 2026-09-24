// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/canopen.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

constexpr uint8_t kFcNmt = 0x0;
constexpr uint8_t kFcSyncOrEmcy = 0x1;
constexpr uint8_t kFcTimeStamp = 0x2;
constexpr uint8_t kFcPdo1Tx = 0x3, kFcPdo1Rx = 0x4, kFcPdo2Tx = 0x5, kFcPdo2Rx = 0x6;
constexpr uint8_t kFcPdo3Tx = 0x7, kFcPdo3Rx = 0x8, kFcPdo4Tx = 0x9, kFcPdo4Rx = 0xA;
constexpr uint8_t kFcSdoRx = 0xB;  // client request
constexpr uint8_t kFcSdoTx = 0xC;  // server response
constexpr uint8_t kFcNmtErrControl = 0xE;
constexpr uint8_t kFcLss = 0xF;

constexpr uint16_t kLssSlaveCanId = 0x7E4;
constexpr uint16_t kLssMasterCanId = 0x7E5;

constexpr uint32_t kTsDaysBetween1970And1984 = 5113;

std::string hex16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string hex32(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return s.str();
}

// Broadcast function codes (node_id == 0) -- CAN_open_bcast_msg_type_vals.
std::string broadcast_message_type_name(uint8_t fc) {
    switch (fc) {
        case kFcNmt: return "NMT";
        case kFcSyncOrEmcy: return "SYNC";
        case kFcTimeStamp: return "TIME STAMP";
        default: return "";
    }
}

// Point-to-point function codes (node_id != 0) -- CAN_open_p2p_msg_type_vals.
std::string p2p_message_type_name(uint8_t fc) {
    switch (fc) {
        case kFcSyncOrEmcy: return "EMCY";
        case kFcPdo1Tx: return "PDO1 (tx)";
        case kFcPdo1Rx: return "PDO1 (rx)";
        case kFcPdo2Tx: return "PDO2 (tx)";
        case kFcPdo2Rx: return "PDO2 (rx)";
        case kFcPdo3Tx: return "PDO3 (tx)";
        case kFcPdo3Rx: return "PDO3 (rx)";
        case kFcPdo4Tx: return "PDO4 (tx)";
        case kFcPdo4Rx: return "PDO4 (rx)";
        case kFcSdoTx: return "Default-SDO (tx)";
        case kFcSdoRx: return "Default-SDO (rx)";
        case kFcNmtErrControl: return "NMT Error Control";
        default: return "";
    }
}

bool is_pdo_function_code(uint8_t fc) {
    return fc >= kFcPdo1Tx && fc <= kFcPdo4Rx;
}

// nmt_ctrl_cs -- every value the reference table defines.
std::string nmt_command_name(uint8_t cs) {
    switch (cs) {
        case 0x01: return "Start remote node";
        case 0x02: return "Stop remote node";
        case 0x80: return "Enter pre-operational state";
        case 0x81: return "Reset node";
        case 0x82: return "Reset communication";
        default: return "";
    }
}

// nmt_guard_state -- every value the reference table defines.
std::string heartbeat_state_name(uint8_t state) {
    switch (state) {
        case 0x00: return "Boot-up";
        case 0x04: return "Stopped";
        case 0x05: return "Operational";
        case 0x7F: return "Pre-operational";
        default: return "";
    }
}

// em_err_code -- a RANGE table (range_string in the reference source); every major range from
// packet-canopen.c's own `em_err_code` is ported here, in the same order.
std::string emergency_error_code_name(uint16_t code) {
    struct Range { uint16_t lo, hi; const char* name; };
    static const Range kRanges[] = {
        {0x0000, 0x00FF, "Error reset or no error"},
        {0x1000, 0x10FF, "Generic error"},
        {0x2000, 0x20FF, "Current"},
        {0x2100, 0x21FF, "Current, CANopen device input side"},
        {0x2200, 0x22FF, "Current inside the CANopen device"},
        {0x2300, 0x23FF, "Current, CANopen device output side"},
        {0x3000, 0x30FF, "Voltage"},
        {0x3100, 0x31FF, "Mains voltage"},
        {0x3200, 0x32FF, "Voltage inside the CANopen device"},
        {0x3300, 0x33FF, "Output voltage"},
        {0x4000, 0x40FF, "Temperature"},
        {0x4100, 0x41FF, "Ambient temperature"},
        {0x4200, 0x42FF, "CANopen device temperature"},
        {0x5000, 0x50FF, "CANopen device hardware"},
        {0x6000, 0x60FF, "CANopen device software"},
        {0x6100, 0x61FF, "Internal software"},
        {0x6200, 0x62FF, "User software"},
        {0x6300, 0x63FF, "Data set"},
        {0x7000, 0x70FF, "Additional modules"},
        {0x8000, 0x80FF, "Monitoring"},
        {0x8100, 0x810F, "Communication"},
        {0x8110, 0x8110, "Communication - CAN overrun (objects lost)"},
        {0x8111, 0x811F, "Communication"},
        {0x8120, 0x8120, "Communication - CAN in error passive mode"},
        {0x8121, 0x812F, "Communication"},
        {0x8130, 0x8130, "Communication - Life guard error or heartbeat error"},
        {0x8131, 0x813F, "Communication"},
        {0x8140, 0x8140, "Communication - recovered from bus off"},
        {0x8141, 0x814F, "Communication"},
        {0x8150, 0x8150, "Communication - CAN-ID collision"},
        {0x8151, 0x81FF, "Communication"},
        {0x8200, 0x820F, "Protocol error"},
        {0x8210, 0x8210, "Protocol error - PDO not processed due to length error"},
        {0x8211, 0x821F, "Protocol error"},
        {0x8220, 0x8220, "Protocol error - PDO length exceeded"},
        {0x8221, 0x822F, "Protocol error"},
        {0x8230, 0x8230, "Protocol error - DAM MPDO not processed, destination object not available"},
        {0x8231, 0x823F, "Protocol error"},
        {0x8240, 0x8240, "Protocol error - Unexpected SYNC data length"},
        {0x8241, 0x824F, "Protocol error"},
        {0x8250, 0x8250, "Protocol error - RPDO timeout"},
        {0x8251, 0x82FF, "Protocol error"},
        {0x9000, 0x90FF, "External error"},
        {0xF000, 0xF0FF, "Additional functions"},
        {0xFF00, 0xFFFF, "CANopen device specific"},
    };
    // Later (more specific, narrower) entries appear after their own containing broader range in the
    // reference table and must win -- iterate in reverse so the most specific match found last in the
    // wire-order table above is preferred, mirroring range_string's own "first match in declaration
    // order wins" semantics (narrower entries are declared right after their broader parent above).
    std::string result;
    for (const auto& r : kRanges) {
        if (code >= r.lo && code <= r.hi) result = r.name;
    }
    return result;
}

// em_err_reg_* -- 8 named bits, every one the reference source defines.
std::vector<std::string> emergency_error_register_bits(uint8_t reg) {
    std::vector<std::string> out;
    if (reg & 0x01) out.push_back("Generic error");
    if (reg & 0x02) out.push_back("Current");
    if (reg & 0x04) out.push_back("Voltage");
    if (reg & 0x08) out.push_back("Temperature");
    if (reg & 0x10) out.push_back("Communication error (overrun, error state)");
    if (reg & 0x20) out.push_back("Device profile specific");
    if (reg & 0x40) out.push_back("Reserved (must be false)");
    if (reg & 0x80) out.push_back("Manufacturer specific");
    return out;
}

// obj_dict -- the Object Dictionary area range table, ranged against the SDO main-index. A curated
// subset of the reference source's own full range table (every entry that names a real CiA 301
// communication-profile object or a whole profile-area band), matching this codebase's "curated
// depth, not exhaustive" posture for anything below the level of a single named field -- the
// reference source's own table is itself already just area/object NAMES, not full semantic decode of
// what's inside them, so this port is complete relative to what the reference source actually
// provides, not abbreviated from it.
std::string object_dictionary_area_name(uint16_t idx) {
    struct Range { uint16_t lo, hi; const char* name; };
    static const Range kRanges[] = {
        {0x0000, 0x0000, "not used"},
        {0x0001, 0x001F, "Static data types"},
        {0x0020, 0x003F, "Complex data types"},
        {0x0040, 0x005F, "Manufacturer-specific complex data types"},
        {0x0060, 0x025F, "Device profile specific data types"},
        {0x1000, 0x1000, "Device type"},
        {0x1001, 0x1001, "Error register"},
        {0x1003, 0x1003, "Pre-defined error field"},
        {0x1005, 0x1005, "COB-ID SYNC message"},
        {0x1008, 0x1008, "Manufacturer device name"},
        {0x1010, 0x1010, "Store parameters"},
        {0x1011, 0x1011, "Restore default parameters"},
        {0x1012, 0x1012, "COB-ID time stamp object"},
        {0x1014, 0x1014, "COB-ID EMCY"},
        {0x1016, 0x1016, "Consumer heartbeat time"},
        {0x1017, 0x1017, "Producer heartbeat time"},
        {0x1018, 0x1018, "Identity object"},
        {0x1200, 0x127F, "SDO server parameter"},
        {0x1280, 0x12FF, "SDO client parameter"},
        {0x1400, 0x15FF, "RPDO communication parameter"},
        {0x1600, 0x17FF, "RPDO mapping parameter"},
        {0x1800, 0x19FF, "TPDO communication parameter"},
        {0x1A00, 0x1BFF, "TPDO mapping parameter"},
        {0x2000, 0x5FFF, "Manufacturer-specific profile area"},
        {0x6000, 0x67FF, "Standardized profile area 1st logical device"},
        {0x6800, 0x6FFF, "Standardized profile area 2nd logical device"},
        {0x7000, 0x77FF, "Standardized profile area 3rd logical device"},
        {0x7800, 0x7FFF, "Standardized profile area 4th logical device"},
        {0xA000, 0xAFFF, "Standardized network variable area"},
        {0xB000, 0xBFFF, "Standardized system variable area"},
    };
    std::string result;
    for (const auto& r : kRanges) {
        if (idx >= r.lo && idx <= r.hi) result = r.name;
    }
    return result;
}

// sdo_ccs -- client (request) command specifier.
std::string sdo_ccs_name(uint8_t cs) {
    switch (cs) {
        case 0: return "Download segment request";
        case 1: return "Initiate download request";
        case 2: return "Initiate upload request";
        case 3: return "Upload segment request";
        case 4: return "Abort transfer";
        case 5: return "Block upload";
        case 6: return "Block download";
        default: return "";
    }
}

// sdo_scs -- server (response) command specifier. Note ccs==5/scs==6 are both "Block upload" and
// ccs==6/scs==5 are both "Block download" -- the direction swap is intentional, see canopen.hpp.
std::string sdo_scs_name(uint8_t cs) {
    switch (cs) {
        case 0: return "Upload segment response";
        case 1: return "Download segment response";
        case 2: return "Initiate upload response";
        case 3: return "Initiate download response";
        case 4: return "Abort transfer";
        case 5: return "Block download";
        case 6: return "Block upload";
        default: return "";
    }
}

// sdo_client_subcommand_meaning
std::string sdo_client_subcommand_name(uint8_t sub) {
    switch (sub) {
        case 0: return "Initiate upload/download request";
        case 1: return "End block upload/download request";
        case 2: return "Block upload response";
        case 3: return "Start upload";
        default: return "";
    }
}

// sdo_server_subcommand_meaning
std::string sdo_server_subcommand_name(uint8_t sub) {
    switch (sub) {
        case 0: return "Initiate upload/download response";
        case 1: return "End block upload/download response";
        case 2: return "Block download response";
        default: return "";
    }
}

}  // namespace

// sdo_abort_code -- every value the reference source defines. Exposed (see canopen.hpp's own
// comment on this declaration) so powerlink.cpp can share it rather than duplicating the table --
// POWERLINK's own SDO Abort Code space is numerically identical to CANopen's, confirmed
// value-by-value against packet-epl.c's own sdo_cmd_abort_code[] during that decoder's research.
std::string canopen_sdo_abort_code_name(uint32_t code) {
    switch (code) {
        case 0x05030000: return "Toggle bit not alternated";
        case 0x05040000: return "SDO protocol timed out";
        case 0x05040001: return "Client/server command specifier not valid or unknown";
        case 0x05040002: return "Invalid block size";
        case 0x05040003: return "Invalid sequence number";
        case 0x05040004: return "CRC error";
        case 0x05040005: return "Out of memory";
        case 0x06010000: return "Unsupported access to an object";
        case 0x06010001: return "Attempt to read a write only object";
        case 0x06010002: return "Attempt to write a read only object";
        case 0x06020000: return "Object does not exist in the object dictionary";
        case 0x06040041: return "Object cannot be mapped to the PDO";
        case 0x06040042: return "The number and length of the objects to be mapped would exceed PDO length";
        case 0x06040043: return "General parameter incompatibility reason";
        case 0x06040047: return "General internal incompatibility in the device";
        case 0x06060000: return "Access failed due to an hardware error";
        case 0x06070010: return "Data type does not match, length of service parameter does not match";
        case 0x06070012: return "Data type does not match, length of service parameter too high";
        case 0x06070013: return "Data type does not match, length of service parameter too low";
        case 0x06090011: return "Sub-index does not exist";
        case 0x06090030: return "Invalid value for parameter";
        case 0x06090031: return "Value of parameter written too high";
        case 0x06090032: return "Value of parameter written too low";
        case 0x06090036: return "Maximum value is less than minimum value";
        case 0x060A0023: return "Resource not available: SDO connection";
        case 0x08000000: return "General error";
        case 0x08000020: return "Data cannot be transferred or stored to the application";
        case 0x08000021: return "Data cannot be transferred or stored to the application because of local control";
        case 0x08000022: return "Data cannot be transferred or stored to the application because of the present device state";
        case 0x08000023: return "Object dictionary dynamic generation fails or no object dictionary is present";
        case 0x08000024: return "No data available";
        default: return "";
    }
}

namespace {

// Decodes the SDO command byte (byte 0 of the payload) and everything that follows it, for either
// direction -- `is_request` selects sdo_ccs/sdo_client_subcommand vs. sdo_scs/sdo_server_subcommand,
// matching dissect_sdo's own `function_code == FC_DEFAULT_SDO_RX` branch. See canopen.hpp's own "SDO"
// paragraph for the full field-by-field citation.
void decode_sdo(CanopenFrame& f, bool is_request) {
    if (f.payload.size() < 1) {
        f.notes.push_back("SDO message with no payload at all -- the command byte could not be read");
        return;
    }
    uint8_t byte0 = f.payload.at(0);
    uint8_t cs = static_cast<uint8_t>((byte0 & 0xE0) >> 5);
    f.sdo_is_request = is_request;
    f.sdo_cs = cs;
    f.sdo_cs_name = is_request ? sdo_ccs_name(cs) : sdo_scs_name(cs);
    f.sdo_recognized = !f.sdo_cs_name.empty();

    size_t offset = 1;
    bool has_mux = false;  // index/sub-index follow
    size_t data_len = 0;   // expedited/other trailing data length, computed per-case below

    // dissect_sdo's own per-direction switch, re-tabulated: cs==0 ("Download segment request" for
    // ccs / "Upload segment response" for scs) is the ONE cs value whose shape is uniform across
    // both directions (mux=0, full toggle+n+c, data=7-n -- this is the "segment carries a real data
    // payload" case, DOWNLOAD data being WRITTEN in the request, UPLOAD data being READ BACK in the
    // response). Every other cs value (1/2/3) means something structurally DIFFERENT depending on
    // direction -- ccs1 ("Initiate download request") is the full expedited-init shape (mux=1,
    // e/s/n present, carries the value being WRITTEN), but scs1 ("Download segment response") is a
    // bare toggle-only ack (mux=0, no data); ccs2 ("Initiate upload request") is a bare mux-only ack
    // (mux=1, no e/s/n, no data -- just naming the index being asked for), but scs2 ("Initiate
    // upload response") is the full expedited-init shape carrying the value being READ; ccs3
    // ("Upload segment request") is a bare toggle-only ack, but scs3 ("Initiate download response")
    // is a bare mux-only ack. See canopen.hpp's own "SDO" paragraph for the full request/response
    // pairing this reflects (Initiate-download/Initiate-upload/Download-segment/Upload-segment, each
    // a two-message exchange whose "data-carrying" half is on a DIFFERENT cs value than its own
    // "just an ack" half).
    bool is_segment_shape = (is_request && (cs == 0 || cs == 3)) || (!is_request && (cs == 0 || cs == 1));
    bool is_init_shape = (is_request && (cs == 1 || cs == 2)) || (!is_request && (cs == 2 || cs == 3));
    bool is_full_shape = (cs == 0) || (is_request && cs == 1) || (!is_request && cs == 2);

    if (cs == 4) {
        // Abort transfer -- both directions, identical shape.
        f.sdo_is_abort = true;
        has_mux = true;
        data_len = 0;  // the abort code itself is read separately below, not through sdo_data
    } else if (is_segment_shape) {
        f.sdo_is_segment = true;
        f.sdo_segment_toggle = (byte0 & 0x10) != 0;
        has_mux = false;
        if (is_full_shape) {
            uint8_t n = static_cast<uint8_t>((byte0 & 0x0E) >> 1);
            f.sdo_segment_no_more = (byte0 & 0x01) != 0;
            data_len = (n <= 7) ? static_cast<size_t>(7 - n) : 0;
        } else {
            data_len = 0;
        }
    } else if (is_init_shape) {
        f.sdo_is_expedited_init = true;
        has_mux = true;
        if (is_full_shape) {
            f.sdo_expedited = (byte0 & 0x02) != 0;
            f.sdo_size_indicated = (byte0 & 0x01) != 0;
            uint8_t n = static_cast<uint8_t>((byte0 & 0x0C) >> 2);
            data_len = f.sdo_expedited ? static_cast<size_t>(4 - n) : 4;  // non-expedited initiate
                                        // still reserves 4 placeholder bytes on the wire per CiA 301
        } else {
            data_len = 0;
        }
    } else if (cs == 5 || cs == 6) {
        // Block transfer -- named/structural only per this file's own documented scope (see
        // canopen.hpp's "SDO" paragraph): the subcommand is decoded and named, and the OD index/
        // sub-index are decoded when the subcommand indicates they're present (subcommand==0, both
        // directions -- mirrors dissect_sdo's own `if (sdo_subcommand == 0) sdo_mux = 1;` in every
        // one of its four BLOCK_UP/BLOCK_DOWN cases), but the reference dissector's own further
        // per-subcommand micro-fields (CRC-support flag, block size, ack sequence number, protocol
        // switch threshold -- each only 1 byte, in a subcommand-dependent combination) are NOT
        // individually decoded here; whatever payload remains after the subcommand byte (and index/
        // sub-index, when present) is shown as raw hex via sdo_data instead, which still lets a
        // reader see every byte, just without Wireshark's own field-by-field micro-layout.
        f.sdo_is_block = true;
        // cs==5 is SDO_CCS_BLOCK_UP (client "Block upload" request) / SDO_SCS_BLOCK_DOWN (server
        // "Block download" response) -- the subcommand field is 2 bits (mask 0x03) in the client
        // case, 2 bits (mask 0x03) in the server case too (both read via tvb_get_bits8(tvb, 6, 2)).
        // cs==6 is SDO_CCS_BLOCK_DOWN (client) / SDO_SCS_BLOCK_UP (server) -- 1 bit (mask 0x01) in
        // both cases (tvb_get_bits8(tvb, 7, 1)). See dissect_sdo's own per-case bit-offset reads.
        uint8_t subcommand = (cs == 5) ? static_cast<uint8_t>(byte0 & 0x03)
                                        : static_cast<uint8_t>(byte0 & 0x01);
        f.sdo_block_subcommand = subcommand;
        f.sdo_block_subcommand_name = is_request ? sdo_client_subcommand_name(subcommand)
                                                   : sdo_server_subcommand_name(subcommand);
        has_mux = (subcommand == 0);
        data_len = f.payload.size() > offset + (has_mux ? 3 : 0)
                       ? f.payload.size() - offset - (has_mux ? 3 : 0)
                       : 0;
    } else {
        // sdo_cs_name is already empty (unrecognized cs) -- nothing further to decode, matching
        // dissect_sdo's own `default: return;`.
        return;
    }

    if (has_mux) {
        if (f.payload.size() >= offset + 3) {
            f.sdo_has_index = true;
            f.sdo_index = static_cast<uint16_t>(f.payload.at(offset) | (f.payload.at(offset + 1) << 8));
            f.sdo_index_area_name = object_dictionary_area_name(f.sdo_index);
            f.sdo_sub_index = f.payload.at(offset + 2);
            offset += 3;
        } else {
            f.notes.push_back(
                "SDO message with a Client/Server Command Specifier that indicates an OD index/"
                "sub-index follows, but fewer than 3 more payload bytes are present -- index/"
                "sub-index not decoded");
        }
    }

    if (f.sdo_is_abort) {
        if (f.payload.size() >= offset + 4) {
            f.sdo_has_abort_code = true;
            f.sdo_abort_code = static_cast<uint32_t>(f.payload.at(offset)) |
                                (static_cast<uint32_t>(f.payload.at(offset + 1)) << 8) |
                                (static_cast<uint32_t>(f.payload.at(offset + 2)) << 16) |
                                (static_cast<uint32_t>(f.payload.at(offset + 3)) << 24);
            f.sdo_abort_code_name = canopen_sdo_abort_code_name(f.sdo_abort_code);
        } else {
            f.notes.push_back("SDO Abort Transfer message but fewer than 4 bytes remain for the "
                               "Abort Code -- not decoded");
        }
        return;
    }

    if (data_len > 0 && f.payload.size() >= offset) {
        size_t available = f.payload.size() - offset;
        size_t actual = data_len < available ? data_len : available;
        if (actual > 0) {
            f.sdo_has_data = true;
            f.sdo_data = ByteSpan(f.payload.data() + offset, actual);
            if (actual < data_len) {
                f.payload_truncated = true;
                f.notes.push_back("SDO data field shorter than its own e/s/n-declared length -- "
                                   "shown truncated to what was actually captured");
            }
        }
    }
}

}  // namespace

std::optional<CanopenFrame> try_parse_canopen(const CanSocketcanFrame& can) {
    // Mirrors dissect_canopen's own unconditional, first-thing rejection -- identical to
    // try_parse_devicenet's own check (see canopen.hpp's header comment's dispatch-collision
    // section for why the two protocols' rejection conditions being identical is exactly the
    // problem the decoder.cpp call site resolves via explicit opt-in, not a structural difference
    // here).
    if (can.eff || can.rtr || can.err) return std::nullopt;

    CanopenFrame f;
    f.cob_id = static_cast<uint16_t>(can.id & CAN_SFF_MASK);
    f.function_code = static_cast<uint8_t>((f.cob_id >> 7) & 0x0F);
    f.node_id = static_cast<uint8_t>(f.cob_id & 0x7F);
    f.is_broadcast = (f.node_id == 0);
    f.fd = can.fd;
    f.payload = can.payload;
    f.payload_truncated = can.truncated;
    for (const auto& n : can.notes) f.notes.push_back(n);

    if (f.fd) {
        f.notes.push_back(
            "CAN FD frame (fd_flags 0x04 set) -- this decoder still classifies the message type from "
            "the COB-ID, but does not attempt any payload-derived decoding for an FD frame (see "
            "canopen.hpp)");
    }

    // LSS special case -- checked first, since it's keyed by the exact cob_id, not by function_code
    // alone (function_code 0xF alone would otherwise fall to "Unknown" for every OTHER 0x780-0x7FF id
    // -- see canopen.hpp's own Function Code table).
    if (f.cob_id == kLssMasterCanId || f.cob_id == kLssSlaveCanId) {
        f.has_lss = true;
        f.lss_is_master = (f.cob_id == kLssMasterCanId);
        f.message_type_name = f.lss_is_master ? "LSS (Master)" : "LSS (Slave)";
    } else if (f.is_broadcast) {
        f.message_type_name = broadcast_message_type_name(f.function_code);
    } else {
        f.message_type_name = p2p_message_type_name(f.function_code);
    }
    if (f.message_type_name.empty()) f.message_type_name = "Unknown";

    std::ostringstream s;
    s << "CANopen " << f.message_type_name << " (COB-ID=" << hex16(f.cob_id)
      << " FC=" << hex16(f.function_code) << " Node=" << static_cast<unsigned>(f.node_id) << ")";

    if (!f.fd) {
        if (f.has_lss) {
            s << " [LSS -- structural recognition only, not decoded]";
        } else if (f.function_code == kFcNmt) {
            f.has_nmt = true;
            if (f.payload.size() >= 1) {
                f.nmt_command_raw = f.payload.at(0);
                f.nmt_command_name = nmt_command_name(f.nmt_command_raw);
                if (f.payload.size() >= 2) {
                    f.has_nmt_target = true;
                    f.nmt_target_node = f.payload.at(1);
                }
                s << ": " << (f.nmt_command_name.empty()
                                  ? ("Unknown command " + hex16(f.nmt_command_raw))
                                  : f.nmt_command_name);
                if (f.has_nmt_target) {
                    s << (f.nmt_target_node == 0 ? " [All]"
                                                  : (" [Node " + std::to_string(f.nmt_target_node) + "]"));
                }
            } else {
                f.notes.push_back("NMT message with no payload at all -- command byte not decoded");
            }
        } else if (f.function_code == kFcNmtErrControl) {
            f.has_heartbeat = true;
            if (f.payload.size() >= 1) {
                uint8_t b = f.payload.at(0);
                f.heartbeat_toggle = (b & 0x80) != 0;
                f.heartbeat_state_raw = static_cast<uint8_t>(b & 0x7F);
                f.heartbeat_state_name = heartbeat_state_name(f.heartbeat_state_raw);
                s << ": " << (f.heartbeat_state_name.empty()
                                  ? ("Unknown state " + hex16(f.heartbeat_state_raw))
                                  : f.heartbeat_state_name);
            }
        } else if (f.function_code == kFcSyncOrEmcy && f.is_broadcast) {
            f.has_sync = true;
            if (f.payload.size() >= 1) {
                f.sync_has_counter = true;
                f.sync_counter = f.payload.at(0);
                s << " [counter=" << static_cast<unsigned>(f.sync_counter) << "]";
            }
        } else if (f.function_code == kFcTimeStamp) {
            f.has_time_stamp = true;
            if (f.payload.size() >= 6) {
                f.time_stamp_ms = static_cast<uint32_t>(f.payload.at(0)) |
                                   (static_cast<uint32_t>(f.payload.at(1)) << 8) |
                                   (static_cast<uint32_t>(f.payload.at(2)) << 16) |
                                   (static_cast<uint32_t>(f.payload.at(3)) << 24);
                f.time_stamp_days = static_cast<uint16_t>(f.payload.at(4) | (f.payload.at(5) << 8));
                s << " [days=" << f.time_stamp_days << " (since 1984-01-01, epoch day "
                  << kTsDaysBetween1970And1984 << ") ms=" << f.time_stamp_ms << "]";
            } else {
                f.notes.push_back("TIME STAMP message shorter than the 6 bytes a CiA 301 "
                                   "TIME_OF_DAY value needs -- not decoded");
            }
        } else if (f.function_code == kFcSyncOrEmcy && !f.is_broadcast) {
            f.has_emcy = true;
            if (f.payload.size() >= 3) {
                f.emcy_error_code = static_cast<uint16_t>(f.payload.at(0) | (f.payload.at(1) << 8));
                f.emcy_error_code_name = emergency_error_code_name(f.emcy_error_code);
                f.emcy_error_register = f.payload.at(2);
                f.emcy_error_register_bits = emergency_error_register_bits(f.emcy_error_register);
                if (f.payload.size() > 3) {
                    f.emcy_has_manufacturer_field = true;
                    size_t n = f.payload.size() - 3;
                    if (n > 5) n = 5;  // CiA 301's own field is fixed at 5 bytes; never over-read
                    f.emcy_manufacturer_field = ByteSpan(f.payload.data() + 3, n);
                }
                s << " [ErrCode=" << hex16(f.emcy_error_code)
                  << (f.emcy_error_code_name.empty() ? "" : (" (" + f.emcy_error_code_name + ")"))
                  << " ErrReg=" << hex16(f.emcy_error_register) << "]";
            } else {
                f.notes.push_back("EMCY message shorter than the 3 bytes an Error Code + Error "
                                   "Register needs -- not decoded");
            }
        } else if (is_pdo_function_code(f.function_code)) {
            f.has_pdo = true;
            s << " data=" << f.payload.size() << " byte(s) (structural only -- no Object Dictionary "
                                                   "mapping, see canopen.hpp)";
        } else if (f.function_code == kFcSdoRx || f.function_code == kFcSdoTx) {
            f.has_sdo = true;
            decode_sdo(f, /*is_request=*/f.function_code == kFcSdoRx);
            s << ": " << (f.sdo_cs_name.empty() ? ("Unknown command specifier " + hex16(f.sdo_cs))
                                                  : f.sdo_cs_name);
            if (f.sdo_has_index) {
                s << " idx=" << hex16(f.sdo_index) << " sub=" << static_cast<unsigned>(f.sdo_sub_index);
            }
            if (f.sdo_has_abort_code) {
                s << " AbortCode=" << hex32(f.sdo_abort_code)
                  << (f.sdo_abort_code_name.empty() ? "" : (" (" + f.sdo_abort_code_name + ")"));
            }
            if (f.sdo_is_block && !f.sdo_block_subcommand_name.empty()) {
                s << " [" << f.sdo_block_subcommand_name << "]";
            }
        }
    }

    f.summary = s.str();
    return f;
}

std::optional<ProtocolResult> CanopenDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    // See canopen.hpp's own CanopenDecoder comment for why this can throw ParseError.
    CanSocketcanFrame can = parse_socketcan_frame(payload);
    if (auto frame = try_parse_canopen(can)) {
        return ProtocolResult::make<CanopenFrame>("canopen", std::move(*frame));
    }
    return std::nullopt;
}

const ProtocolDecoder& canopen_decoder() {
    static const CanopenDecoder instance;
    return instance;
}

}  // namespace conduitscope
