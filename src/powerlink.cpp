// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/powerlink.hpp"

#include "conduitscope/canopen.hpp"
#include "conduitscope/resource_limits.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

constexpr uint8_t kMtypSoc = 0x01;
constexpr uint8_t kMtypPreq = 0x03;
constexpr uint8_t kMtypPres = 0x04;
constexpr uint8_t kMtypSoa = 0x05;
constexpr uint8_t kMtypAsnd = 0x06;
constexpr uint8_t kMtypAmni = 0x07;
constexpr uint8_t kMtypAinv = 0x0D;

constexpr uint8_t kNodeIdDynamic = 0;
constexpr uint8_t kNodeIdMn = 240;
constexpr uint8_t kNodeIdDiagnostic = 253;
constexpr uint8_t kNodeIdLegacyRouter = 254;
constexpr uint8_t kNodeIdBroadcast = 255;

constexpr uint8_t kAsndIdentResponse = 1;
constexpr uint8_t kAsndStatusResponse = 2;
constexpr uint8_t kAsndNmtRequest = 3;
constexpr uint8_t kAsndNmtCommand = 4;
constexpr uint8_t kAsndSdo = 5;
constexpr uint8_t kAsndSyncResponse = 6;

constexpr uint8_t kSoaSvidNoService = 0;
constexpr uint8_t kSoaSvidIdentRequest = 1;

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

std::string hex8(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return s.str();
}

std::string node_id_note(uint8_t node) {
    if (node == kNodeIdDynamic) return " (dynamically assigned)";
    if (node == kNodeIdMn) return " (Managing Node)";
    if (node == kNodeIdDiagnostic) return " (Diagnostic Device)";
    if (node == kNodeIdLegacyRouter) return " (to legacy Ethernet Router)";
    if (node == kNodeIdBroadcast) return " (broadcast)";
    return "";
}

// mtyp_vals -- every value the reference dissector defines; see powerlink.hpp's file header
// comment's "MessageType values" section, including the confirmed absence of any bit-7 masking.
std::string message_type_name(uint8_t mtyp, bool& recognized) {
    recognized = true;
    switch (mtyp) {
        case kMtypSoc: return "SoC";
        case kMtypPreq: return "PReq";
        case kMtypPres: return "PRes";
        case kMtypSoa: return "SoA";
        case kMtypAsnd: return "ASnd";
        case kMtypAmni: return "AMNI";
        case kMtypAinv: return "AInv";
        default:
            recognized = false;
            return "unrecognized";
    }
}

// epl_nmt_cs_vals / epl_nmt_ms_vals -- see powerlink.hpp's file header comment's "NMT state values"
// section. `is_mn` selects which of the two role-specific name prefixes (CS_/MS_) to use for the
// six values that differ between roles; the four generic/reset values share one name either way.
std::string nmt_state_name(uint8_t state, bool is_mn) {
    switch (state) {
        case 0x00: return "NMT_GS_OFF";
        case 0x19: return "NMT_GS_INITIALIZING";
        case 0x29: return "NMT_GS_RESET_APPLICATION";
        case 0x39: return "NMT_GS_RESET_COMMUNICATION";
        case 0x1C: return is_mn ? "NMT_MS_NOT_ACTIVE" : "NMT_CS_NOT_ACTIVE";
        case 0x1D: return is_mn ? "NMT_MS_PRE_OPERATIONAL_1" : "NMT_CS_PRE_OPERATIONAL_1";
        case 0x5D: return is_mn ? "NMT_MS_PRE_OPERATIONAL_2" : "NMT_CS_PRE_OPERATIONAL_2";
        case 0x6D: return is_mn ? "NMT_MS_READY_TO_OPERATE" : "NMT_CS_READY_TO_OPERATE";
        case 0xFD: return is_mn ? "NMT_MS_OPERATIONAL" : "NMT_CS_OPERATIONAL";
        case 0x4D: return is_mn ? "" : "NMT_CS_STOPPED";  // NMT_MS_STOPPED has no wire value in the
                                                             // reference source -- an MN is never
                                                             // reported "Stopped"
        case 0x1E: return is_mn ? "NMT_MS_BASIC_ETHERNET" : "NMT_CS_BASIC_ETHERNET";
        default: return "";
    }
}

// soa_svid_vals/asnd_svid_vals -- two DIFFERENT numeric spaces, see powerlink.hpp's file header
// comment's own callout of this. NOT shared with each other or with ASnd's own service-id table
// below.
std::string soa_requested_service_id_name(uint8_t svid) {
    switch (svid) {
        case 0: return "NoService";
        case 1: return "IdentRequest";
        case 2: return "StatusRequest";
        case 3: return "NMTRequestInvite";
        case 6: return "SyncRequest";
        case 255: return "UnspecifiedInvite";
        default:
            if (svid >= 0xA0 && svid <= 0xFE) return "Manufacturer Specific";
            return "";
    }
}

std::string asnd_service_id_name(uint8_t svid) {
    switch (svid) {
        case kAsndIdentResponse: return "IdentResponse";
        case kAsndStatusResponse: return "StatusResponse";
        case kAsndNmtRequest: return "NMTRequest";
        case kAsndNmtCommand: return "NMTCommand";
        case kAsndSdo: return "SDO";
        case kAsndSyncResponse: return "SyncResponse";
        default:
            if (svid >= 0xA0 && svid <= 0xFE) return "Manufacturer Specific";
            return "";
    }
}

// asnd_cid_vals -- every NMTCommandID the reference source defines (29 values). See powerlink.hpp's
// file header comment's "NMT Command ID table" section.
std::string nmt_command_id_name(uint8_t cid) {
    switch (cid) {
        case 0x21: return "NMTStartNode";
        case 0x22: return "NMTStopNode";
        case 0x23: return "NMTEnterPreOperational2";
        case 0x24: return "NMTEnableReadyToOperate";
        case 0x28: return "NMTResetNode";
        case 0x29: return "NMTResetCommunication";
        case 0x2A: return "NMTResetConfiguration";
        case 0x2B: return "NMTSwReset";
        case 0x2D: return "NMTDNA";
        case 0x41: return "NMTStartNodeEx";
        case 0x42: return "NMTStopNodeEx";
        case 0x43: return "NMTEnterPreOperational2Ex";
        case 0x44: return "NMTEnableReadyToOperateEx";
        case 0x48: return "NMTResetNodeEx";
        case 0x49: return "NMTCommunicationEx";
        case 0x4A: return "NMTResetConfigurationEx";
        case 0x4B: return "NMTSwResetEx";
        case 0x62: return "NMTNetHostNameSet";
        case 0x63: return "NMTFlushArpEntry";
        case 0x80: return "NMTPublishConfiguredNodes";
        case 0x90: return "NMTPublishActiveNodes";
        case 0x91: return "NMTPublishPreOperational1";
        case 0x92: return "NMTPublishPreOperational2";
        case 0x93: return "NMTPublishReadyToOperate";
        case 0x94: return "NMTPublishOperational";
        case 0x95: return "NMTPublishStopped";
        case 0xA0: return "NMTPublishEmergencyNew";
        case 0xB0: return "NMTPublishTime";
        case 0xFF: return "NMTInvalidService";
        default: return "";
    }
}

// EPL_ASND_SDO_COMMAND_* -- every value the reference source defines. See powerlink.hpp's file
// header comment's "SDO Command Layer" section for why this table is POWERLINK-specific, not
// shared with canopen.hpp's own (differently-shaped) SDO command-specifier space.
std::string sdo_command_id_name(uint8_t cmd) {
    switch (cmd) {
        case 0x01: return "WriteByIndex";
        case 0x02: return "ReadByIndex";
        case 0x03: return "WriteAllByIndex";
        case 0x04: return "ReadAllByIndex";
        case 0x05: return "WriteByName";
        case 0x06: return "ReadByName";
        case 0x20: return "FileWrite";
        case 0x21: return "FileRead";
        case 0x31: return "WriteMultipleParameterByIndex";
        case 0x32: return "ReadMultipleParameterByIndex";
        case 0x70: return "MaximumSegmentSize";
        case 0x71: return "LinkNameToIndex";
        default: return "";
    }
}

std::string sdo_con_name(uint8_t con) {
    switch (con) {
        case 0: return "No connection";
        case 1: return "Initialization";
        case 2: return "Connection valid";
        case 3: return "Error Response / Connection valid with acknowledge request";
        default: return "";
    }
}

std::string sdo_segmentation_name(uint8_t seg) {
    switch (seg) {
        case 0: return "Expedited";
        case 1: return "Initiate";
        case 2: return "Segment";
        case 3: return "Transfer Complete";
        default: return "";
    }
}

// Reads `len` bytes at `c`'s current position as an IPv4 dotted-quad -- IdentResponse's own
// IPAddress/SubnetMask/DefaultGateway are the ONE place in this whole frame shape that is
// big-endian on the wire (tvb_get_ntohl in the reference source), unlike every other multi-byte
// field here -- see powerlink.hpp's file header comment's IdentResponse section.
std::string read_ipv4_be(Cursor& c) {
    uint32_t a = c.u8(), b = c.u8(), cc = c.u8(), d = c.u8();
    std::ostringstream s;
    s << a << "." << b << "." << cc << "." << d;
    return s.str();
}

std::string ascii_trim_nul(ByteSpan span) {
    std::string s(reinterpret_cast<const char*>(span.data()), span.size());
    size_t nul = s.find('\0');
    if (nul != std::string::npos) s.resize(nul);
    return s;
}

// Shared SDO Sequence Layer + Command Layer decoder -- the ONE place this logic lives, used by
// ASnd/SDO, AInv/SDO, and the standalone UDP:3819 path alike (all three reach here through
// try_parse_powerlink's own shared dispatch, see powerlink.hpp's file header comment's
// "UDP:3819 SDO variant" architecture note). See powerlink.hpp's file header comment's "SDO
// Sequence Layer"/"SDO Command Layer" sections for the full field-by-field citation.
PowerlinkSdo decode_sdo(Cursor& c, std::vector<std::string>& notes) {
    PowerlinkSdo sdo;
    if (c.remaining() < 4) {
        notes.push_back("SDO message with fewer than 4 bytes remaining -- Sequence Layer not decoded");
        return sdo;
    }
    uint8_t b0 = c.u8();
    uint8_t b1 = c.u8();
    c.skip(2);  // reserved/unused -- see file header comment
    sdo.seq_receive_sequence_number = static_cast<uint8_t>(b0 >> 2);
    sdo.seq_receive_con = static_cast<uint8_t>(b0 & 0x03);
    sdo.seq_receive_con_name = sdo_con_name(sdo.seq_receive_con);
    sdo.seq_send_sequence_number = static_cast<uint8_t>(b1 >> 2);
    sdo.seq_send_con = static_cast<uint8_t>(b1 & 0x03);
    sdo.seq_send_con_name = sdo_con_name(sdo.seq_send_con);

    std::ostringstream s;
    s << "Seq:" << static_cast<unsigned>(sdo.seq_receive_sequence_number) << "/"
      << static_cast<unsigned>(sdo.seq_send_sequence_number);

    // Command Layer -- 1 reserved byte, then the 8-byte header proper (see file header comment for
    // why this reserved byte precedes TransactionID rather than TransactionID starting immediately).
    if (c.remaining() < 8) {
        if (c.remaining() > 0) {
            notes.push_back("SDO message: Command Layer header needs 8 byte(s) but only " +
                             std::to_string(c.remaining()) + " remain -- not decoded (Empty CommandLayer)");
        }
        sdo.summary = s.str();
        return sdo;
    }
    c.skip(1);  // reserved -- see file header comment
    sdo.has_command = true;
    sdo.transaction_id = c.u8();
    uint8_t flags = c.u8();
    sdo.is_response = (flags & 0x80) != 0;
    sdo.is_abort = (flags & 0x40) != 0;
    sdo.segmentation = static_cast<uint8_t>((flags & 0x30) >> 4);
    sdo.segmentation_name = sdo_segmentation_name(sdo.segmentation);
    sdo.command_id_raw = c.u8();
    sdo.command_id_name = sdo_command_id_name(sdo.command_id_raw);
    sdo.segment_size = c.u16le();
    c.skip(2);  // 2 more reserved bytes -- see file header comment

    s << " Cmd:" << (sdo.command_id_name.empty() ? hex2(sdo.command_id_raw) : sdo.command_id_name)
      << " TID=" << static_cast<unsigned>(sdo.transaction_id) << " "
      << (sdo.is_response ? "Response" : "Request");

    bool is_write_or_read = (sdo.command_id_raw == 0x01 || sdo.command_id_raw == 0x02);

    if (sdo.segmentation == 1 && is_write_or_read) {  // Initiate
        if (c.remaining() >= 4) {
            sdo.has_data_size = true;
            sdo.data_size = c.u32le();
        } else {
            notes.push_back("SDO Initiate transfer but fewer than 4 bytes remain for DataSize -- not decoded");
        }
    }

    if (sdo.is_abort) {
        if (c.remaining() >= 4) {
            sdo.has_abort_code = true;
            sdo.abort_code = c.u32le();
            sdo.abort_code_name = canopen_sdo_abort_code_name(sdo.abort_code);
            s << " Abort:" << hex8(sdo.abort_code)
              << (sdo.abort_code_name.empty() ? "" : (" (" + sdo.abort_code_name + ")"));
        } else {
            notes.push_back("SDO Abort but fewer than 4 bytes remain for the Abort Code -- not decoded");
        }
        sdo.summary = s.str();
        return sdo;
    }

    if (is_write_or_read && (sdo.segmentation == 0 || sdo.segmentation == 1)) {
        // Expedited or Initiate -- Index/SubIndex present (Segment/Transfer Complete continuation
        // frames carry no Index/SubIndex at all, see file header comment).
        if (c.remaining() >= 3) {
            sdo.has_index = true;
            sdo.index = c.u16le();
            sdo.sub_index = c.u8();
            // WriteByIndex pads SubIndex to 2 bytes (1 reserved byte follows); ReadByIndex does
            // NOT -- a genuine, source-confirmed asymmetry, see file header comment.
            if (sdo.command_id_raw == 0x01 && c.remaining() >= 1) c.skip(1);
            s << " idx=" << hex4(sdo.index) << " sub=" << static_cast<unsigned>(sdo.sub_index);
        } else {
            notes.push_back("SDO WriteByIndex/ReadByIndex but fewer than 3 bytes remain for Index/SubIndex -- not decoded");
        }
    }

    if (c.remaining() > 0) {
        sdo.has_data = true;
        sdo.data = c.rest();
        c.skip(c.remaining());
        s << " data=" << sdo.data.size() << "B";
    }

    sdo.summary = s.str();
    return sdo;
}

// StaticErrorBitfield's own first byte -- named field-by-field only as "an error-register-shaped
// bitmask" by the reference source (see powerlink.hpp's file header comment's StatusResponse
// section); this decoder reuses CANopen's own, semantically-equivalent Error Register bit names
// (CiA 301's Error Register IS this byte, per POWERLINK's shared CANopen heritage) rather than
// inventing new ones. Bit 6 has no name in the reference source either.
std::vector<std::string> error_register_bits(uint8_t reg) {
    std::vector<std::string> out;
    if (reg & 0x01) out.push_back("Generic error");
    if (reg & 0x02) out.push_back("Current");
    if (reg & 0x04) out.push_back("Voltage");
    if (reg & 0x08) out.push_back("Temperature");
    if (reg & 0x10) out.push_back("Communication error");
    if (reg & 0x20) out.push_back("Device profile specific");
    if (reg & 0x80) out.push_back("Manufacturer specific");
    return out;
}

PowerlinkIdentResponse decode_ident_response(Cursor& c, bool is_mn, std::vector<std::string>& notes) {
    PowerlinkIdentResponse r;
    if (c.remaining() < 158) {
        notes.push_back("IdentResponse needs 158 byte(s) but only " + std::to_string(c.remaining()) +
                         " remain -- decoding what is present, rest left at default");
    }
    if (c.remaining() < 1) return r;
    uint8_t enec = c.u8();
    r.en = (enec & 0x10) != 0;
    r.ec = (enec & 0x08) != 0;
    if (c.remaining() < 1) return r;
    uint8_t flsm = c.u8();
    r.fls = (flsm & 0x80) != 0;
    r.sls = (flsm & 0x40) != 0;
    r.pr = static_cast<uint8_t>((flsm & 0x38) >> 3);
    r.rs = static_cast<uint8_t>(flsm & 0x07);
    if (c.remaining() < 2) return r;
    r.nmt_status_raw = c.u8();
    r.nmt_status_name = nmt_state_name(r.nmt_status_raw, is_mn);
    c.skip(1);
    if (c.remaining() < 2) return r;
    r.epl_version_raw = c.u8();
    c.skip(1);
    if (c.remaining() < 4) return r;
    r.feature_flags = c.u32le();
    if (c.remaining() < 2) return r;
    r.mtu = c.u16le();
    if (c.remaining() < 2) return r;
    r.poll_in_size = c.u16le();
    if (c.remaining() < 2) return r;
    r.poll_out_size = c.u16le();
    if (c.remaining() < 6) return r;
    r.response_time_us = c.u32le();
    c.skip(2);
    if (c.remaining() < 4) return r;
    r.device_type = c.u16le();
    r.device_type_additional_info = c.u16le();
    if (c.remaining() < 4) return r;
    r.vendor_id = c.u32le();
    if (c.remaining() < 4) return r;
    r.product_code = c.u32le();
    if (c.remaining() < 4) return r;
    r.revision_number = c.u32le();
    if (c.remaining() < 4) return r;
    r.serial_number = c.u32le();
    if (c.remaining() < 8) return r;
    r.vendor_specific_extension1_hex = to_hex(c.bytes(8), "");
    if (c.remaining() < 4) return r;
    r.verify_configuration_date = c.u32le();
    if (c.remaining() < 4) return r;
    r.verify_configuration_time = c.u32le();
    if (c.remaining() < 4) return r;
    r.application_sw_date = c.u32le();
    if (c.remaining() < 4) return r;
    r.application_sw_time = c.u32le();
    if (c.remaining() < 4) return r;
    r.ip_address = read_ipv4_be(c);
    if (c.remaining() < 4) return r;
    r.subnet_mask = read_ipv4_be(c);
    if (c.remaining() < 4) return r;
    r.default_gateway = read_ipv4_be(c);
    if (c.remaining() < 32) return r;
    r.host_name = ascii_trim_nul(c.bytes(32));
    if (c.remaining() < 48) return r;
    r.vendor_specific_extension2_hex = to_hex(c.bytes(48), "");
    return r;
}

PowerlinkStatusResponse decode_status_response(Cursor& c, bool is_mn, std::vector<std::string>& notes) {
    PowerlinkStatusResponse r;
    if (c.remaining() < 1) return r;
    uint8_t enec = c.u8();
    r.en = (enec & 0x10) != 0;
    r.ec = (enec & 0x08) != 0;
    if (c.remaining() < 1) return r;
    uint8_t flsm = c.u8();
    r.fls = (flsm & 0x80) != 0;
    r.sls = (flsm & 0x40) != 0;
    r.pr = static_cast<uint8_t>((flsm & 0x38) >> 3);
    r.rs = static_cast<uint8_t>(flsm & 0x07);
    if (c.remaining() < 4) return r;
    r.nmt_status_raw = c.u8();
    r.nmt_status_name = nmt_state_name(r.nmt_status_raw, is_mn);
    c.skip(3);
    if (c.remaining() < 8) return r;
    r.error_register_raw = c.u8();
    r.error_register_bits = error_register_bits(r.error_register_raw);
    c.skip(1);
    r.device_specific_error_hex = to_hex(c.bytes(6), "");

    size_t max_entries = resource_limits().max_decoded_objects.value_or(50);
    while (c.remaining() >= 20) {
        if (r.error_entries.size() >= max_entries) {
            r.error_entries_truncated = true;
            notes.push_back("StatusResponse ErrorCodeList: stopped after " + std::to_string(max_entries) +
                             " entrie(s) (safety cap)");
            break;
        }
        PowerlinkStatusResponseEntry e;
        e.entry_type_raw = c.u16le();
        e.error_code = c.u16le();
        e.time_stamp_hex = to_hex(c.bytes(8), "");
        e.add_info_hex = to_hex(c.bytes(8), "");
        r.error_entries.push_back(e);
    }
    return r;
}

PowerlinkNmtRequest decode_nmt_request(Cursor& c) {
    PowerlinkNmtRequest r;
    if (c.remaining() < 1) return r;
    r.requested_command_id_raw = c.u8();
    r.requested_command_id_name = nmt_command_id_name(r.requested_command_id_raw);
    if (c.remaining() < 1) return r;
    r.requested_command_target = c.u8();
    r.requested_command_data = c.rest();
    c.skip(c.remaining());
    return r;
}

// NMTDNA's own fixed 27-byte structure -- see powerlink.hpp's file header comment's NMTCommand
// section for why this is shown as raw hex rather than individually broken out.
constexpr size_t kNmtDnaLength = 27;

PowerlinkNmtCommand decode_nmt_command(Cursor& c) {
    PowerlinkNmtCommand r;
    if (c.remaining() < 1) return r;
    r.command_id_raw = c.u8();
    r.command_id_name = nmt_command_id_name(r.command_id_raw);
    if (r.command_id_name == "NMTDNA") {
        // The reference source backs up 1 byte here -- the byte ordinarily reserved for other NMT
        // commands carries DNA's own leading flags byte instead (see powerlink.hpp's file header
        // comment). This decoder mirrors that: DNA's own region starts right after the CommandID
        // byte, not after the usual 1-byte-reserved skip every other command uses.
        ByteSpan region = c.remaining() >= kNmtDnaLength ? c.bytes(kNmtDnaLength) : c.rest();
        if (c.remaining() > 0 && region.size() < kNmtDnaLength) c.skip(c.remaining());
        r.command_data = region;
        return r;
    }
    if (c.remaining() < 1) return r;
    c.skip(1);  // reserved -- see file header comment
    if (r.command_id_name == "NMTNetHostNameSet") {
        if (c.remaining() >= 32) {
            r.has_host_name = true;
            r.host_name = ascii_trim_nul(c.bytes(32));
        }
    } else if (r.command_id_name == "NMTFlushArpEntry") {
        if (c.remaining() >= 1) {
            r.has_flush_arp_target = true;
            r.flush_arp_target = c.u8();
        }
    } else if (r.command_id_name == "NMTPublishTime") {
        if (c.remaining() >= 6) {
            r.has_publish_time_raw = true;
            r.publish_time_hex = to_hex(c.bytes(6), "");
        }
    } else if (r.command_id_name == "NMTResetNode") {
        if (c.remaining() >= 2) {
            r.has_reset_node_reason = true;
            r.reset_node_reason = c.u16le();
        }
    }
    if (!r.has_host_name && !r.has_flush_arp_target && !r.has_publish_time_raw &&
        !r.has_reset_node_reason && c.remaining() > 0) {
        r.command_data = c.rest();
        c.skip(c.remaining());
    }
    return r;
}

// Shared ASnd-service-body decoder -- one decode path, used by both ASnd (0x06) and AInv's (0x0D)
// own embedded ASnd-shaped body, at the identical relative offset (see powerlink.hpp's file header
// comment's AInv section for why the two share this rather than duplicating it).
void decode_asnd_service_body(PowerlinkFrame& f, Cursor& c, bool is_mn, std::vector<std::string>& notes) {
    if (c.remaining() < 1) {
        notes.push_back("ASnd/AInv service body with no ServiceID byte present");
        return;
    }
    f.asnd_service_id_raw = c.u8();
    f.asnd_service_id_name = asnd_service_id_name(f.asnd_service_id_raw);

    switch (f.asnd_service_id_raw) {
        case kAsndIdentResponse:
            f.has_ident_response = true;
            f.ident_response = decode_ident_response(c, is_mn, notes);
            break;
        case kAsndStatusResponse:
            f.has_status_response = true;
            f.status_response = decode_status_response(c, is_mn, notes);
            break;
        case kAsndNmtRequest:
            f.has_nmt_request = true;
            f.nmt_request = decode_nmt_request(c);
            break;
        case kAsndNmtCommand:
            f.has_nmt_command = true;
            f.nmt_command = decode_nmt_command(c);
            break;
        case kAsndSdo:
            f.has_sdo = true;
            f.sdo = decode_sdo(c, notes);
            break;
        case kAsndSyncResponse:
            // Named only -- ring/cable-redundancy timing data, no OT-security-relevant content of
            // its own; see powerlink.hpp's file header comment's scope note.
            break;
        default:
            break;
    }
}

}  // namespace

bool nmt_command_is_disruptive(const std::string& name) {
    return name == "NMTStopNode" || name == "NMTResetNode" || name == "NMTResetCommunication" ||
           name == "NMTResetConfiguration" || name == "NMTSwReset" || name == "NMTStopNodeEx" ||
           name == "NMTResetNodeEx" || name == "NMTResetConfigurationEx" || name == "NMTSwResetEx";
}

bool nmt_state_is_operational(const std::string& name) {
    return name == "NMT_CS_OPERATIONAL" || name == "NMT_MS_OPERATIONAL";
}

std::optional<PowerlinkFrame> try_parse_powerlink(ByteSpan payload) {
    if (payload.size() < 3) return std::nullopt;
    try {
        Cursor c(payload);
        PowerlinkFrame f;
        f.message_type_raw = c.u8();
        f.message_type_name = message_type_name(f.message_type_raw, f.message_type_recognized);
        f.dst_node_id = c.u8();
        f.src_node_id = c.u8();
        f.dst_node_id_note = node_id_note(f.dst_node_id);
        f.src_node_id_note = node_id_note(f.src_node_id);
        bool src_is_mn = (f.src_node_id == kNodeIdMn);

        std::ostringstream s;
        s << "POWERLINK " << f.message_type_name;

        switch (f.message_type_raw) {
            case kMtypSoc: {
                f.has_soc = true;
                if (c.remaining() >= 19) {
                    c.skip(1);  // reserved -- see file header comment
                    uint8_t flags = c.u8();
                    f.soc_mc = (flags & 0x80) != 0;
                    f.soc_ps = (flags & 0x40) != 0;
                    f.soc_an_global = (flags & 0x08) != 0;
                    c.skip(1);  // reserved
                    f.soc_net_time_hex = to_hex(c.bytes(8), "");
                    f.soc_relative_time_hex = to_hex(c.bytes(8), "");
                    s << " [MC=" << (f.soc_mc ? 1 : 0) << " PS=" << (f.soc_ps ? 1 : 0) << "]";
                } else {
                    f.notes.push_back("SoC needs 19 byte(s) after the common header but only " +
                                       std::to_string(c.remaining()) + " remain");
                }
                break;
            }
            case kMtypPreq: {
                f.has_preq = true;
                if (c.remaining() >= 7) {
                    c.skip(1);
                    uint8_t flags = c.u8();
                    f.preq_ms = (flags & 0x20) != 0;
                    f.preq_ea = (flags & 0x04) != 0;
                    f.preq_rd = (flags & 0x01) != 0;
                    uint8_t flags2 = c.u8();
                    f.preq_fls = (flags2 & 0x80) != 0;
                    f.preq_sls = (flags2 & 0x40) != 0;
                    f.preq_pdo_version_raw = c.u8();
                    c.skip(1);
                    f.preq_size = c.u16le();
                    size_t avail = c.remaining();
                    size_t take = std::min<size_t>(f.preq_size, avail);
                    f.preq_payload = c.bytes(take);
                    f.preq_payload_truncated = take < f.preq_size;
                    s << " dst=" << static_cast<unsigned>(f.dst_node_id) << " [" << f.preq_size << "B]";
                } else {
                    f.notes.push_back("PReq needs 7 byte(s) after the common header but only " +
                                       std::to_string(c.remaining()) + " remain");
                }
                break;
            }
            case kMtypPres: {
                f.has_pres = true;
                if (c.remaining() >= 7) {
                    f.pres_nmt_status_raw = c.u8();
                    f.pres_nmt_status_name = nmt_state_name(f.pres_nmt_status_raw, src_is_mn);
                    uint8_t flags = c.u8();
                    f.pres_ms = (flags & 0x20) != 0;
                    f.pres_en = (flags & 0x10) != 0;
                    f.pres_rd = (flags & 0x01) != 0;
                    uint8_t flags2 = c.u8();
                    f.pres_fls = (flags2 & 0x80) != 0;
                    f.pres_sls = (flags2 & 0x40) != 0;
                    f.pres_pr = static_cast<uint8_t>((flags2 & 0x38) >> 3);
                    f.pres_rs = static_cast<uint8_t>(flags2 & 0x07);
                    f.pres_pdo_version_raw = c.u8();
                    c.skip(1);
                    f.pres_size = c.u16le();
                    size_t avail = c.remaining();
                    size_t take = std::min<size_t>(f.pres_size, avail);
                    f.pres_payload = c.bytes(take);
                    f.pres_payload_truncated = take < f.pres_size;
                    s << " src=" << static_cast<unsigned>(f.src_node_id) << " "
                      << (f.pres_nmt_status_name.empty() ? hex2(f.pres_nmt_status_raw) : f.pres_nmt_status_name)
                      << " [" << f.pres_size << "B]";
                } else {
                    f.notes.push_back("PRes needs 7 byte(s) after the common header but only " +
                                       std::to_string(c.remaining()) + " remain");
                }
                break;
            }
            case kMtypSoa: {
                f.has_soa = true;
                if (c.remaining() >= 8) {
                    f.soa_nmt_status_raw = c.u8();
                    f.soa_nmt_status_name = nmt_state_name(f.soa_nmt_status_raw, src_is_mn);
                    c.skip(1);  // reserved
                    uint8_t flags = c.u8();
                    // RequestedServiceID is peeked 2 bytes ahead of `flags` in the reference source
                    // to decide whether AN(Local) applies -- read it non-destructively here too.
                    uint8_t svid_peek = payload.size() > c.position() + 1 ? payload.at(c.position() + 1) : 0;
                    f.soa_an_global = (flags & 0x08) != 0;
                    if (svid_peek == kSoaSvidIdentRequest) f.soa_an_local = (flags & 0x10) != 0;
                    f.soa_ea = (flags & 0x04) != 0;
                    f.soa_er = (flags & 0x02) != 0;
                    c.skip(1);  // reserved
                    f.soa_requested_service_id_raw = c.u8();
                    f.soa_requested_service_id_name = soa_requested_service_id_name(f.soa_requested_service_id_raw);
                    f.soa_requested_service_target = c.u8();
                    f.soa_epl_version_raw = c.u8();
                    f.soa_redundancy_flags_raw = c.u8();
                    f.soa_mn_redundancy = (f.soa_redundancy_flags_raw & 0x01) != 0;
                    f.soa_cable_redundancy = (f.soa_redundancy_flags_raw & 0x02) != 0;
                    f.soa_ring_redundancy = (f.soa_redundancy_flags_raw & 0x04) != 0;
                    f.soa_ring_closed = (f.soa_redundancy_flags_raw & 0x08) == 0;
                    if (f.soa_requested_service_id_raw == kSoaSvidNoService) {
                        // nothing further named -- no service invited
                    } else if (!f.soa_requested_service_id_name.empty() &&
                               f.soa_requested_service_id_name != "Manufacturer Specific") {
                        // SyncRequest's own extended fields are not decoded further -- see file
                        // header comment.
                    }
                    s << " (" << (f.soa_requested_service_id_name.empty()
                                      ? hex2(f.soa_requested_service_id_raw)
                                      : f.soa_requested_service_id_name)
                      << ")->" << static_cast<unsigned>(f.soa_requested_service_target);
                } else {
                    f.notes.push_back("SoA needs 8 byte(s) after the common header but only " +
                                       std::to_string(c.remaining()) + " remain");
                }
                break;
            }
            case kMtypAsnd: {
                f.has_asnd = true;
                decode_asnd_service_body(f, c, src_is_mn, f.notes);
                s << " (" << (f.asnd_service_id_name.empty() ? hex2(f.asnd_service_id_raw) : f.asnd_service_id_name)
                  << ") dst=" << static_cast<unsigned>(f.dst_node_id)
                  << " src=" << static_cast<unsigned>(f.src_node_id);
                break;
            }
            case kMtypAinv: {
                f.has_ainv = true;
                if (c.remaining() >= 4) {
                    f.ainv_nmt_status_raw = c.u8();
                    f.ainv_nmt_status_name = nmt_state_name(f.ainv_nmt_status_raw, src_is_mn);
                    c.skip(1);  // reserved
                    uint8_t flags = c.u8();
                    f.ainv_ea = (flags & 0x04) != 0;
                    f.ainv_er = (flags & 0x02) != 0;
                    decode_asnd_service_body(f, c, src_is_mn, f.notes);
                    s << " (" << (f.asnd_service_id_name.empty() ? hex2(f.asnd_service_id_raw) : f.asnd_service_id_name)
                      << ") dst=" << static_cast<unsigned>(f.dst_node_id)
                      << " src=" << static_cast<unsigned>(f.src_node_id);
                } else {
                    f.notes.push_back("AInv needs at least 4 byte(s) after the common header but only " +
                                       std::to_string(c.remaining()) + " remain");
                }
                break;
            }
            case kMtypAmni:
                f.has_amni = true;
                s << " (every field reserved per the reference dissector)";
                break;
            default:
                s << " message type " << hex2(f.message_type_raw) << " (unrecognized)";
                break;
        }

        f.summary = s.str();
        return f;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check (min()-clamped payload reads,
        // remaining()-gated field reads) -- caught defensively anyway, the same belt-and-suspenders
        // posture this codebase's other raw-Ethernet decoders (ethercat.cpp/profinet.cpp) take.
        return std::nullopt;
    }
}

std::optional<ProtocolResult> PowerlinkDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto f = try_parse_powerlink(payload)) {
        return ProtocolResult::make<PowerlinkFrame>("powerlink", std::move(*f));
    }
    return std::nullopt;
}

const ProtocolDecoder& powerlink_decoder() {
    static const PowerlinkDecoder instance;
    return instance;
}

std::optional<ProtocolResult> PowerlinkSdoUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    // Reuses try_parse_powerlink UNCHANGED -- see powerlink.hpp's file header comment's "UDP:3819
    // SDO variant" architecture note for why this is not a separate/stripped-down parser.
    if (auto f = try_parse_powerlink(payload)) {
        return ProtocolResult::make<PowerlinkFrame>("powerlink", std::move(*f));
    }
    return std::nullopt;
}

const ProtocolDecoder& powerlink_sdo_udp_decoder() {
    static const PowerlinkSdoUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
