// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/rmcp.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

std::string hex(ByteSpan span) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < span.size(); ++i) oss << std::setw(2) << static_cast<int>(span.at(i));
    return oss.str();
}

std::string hex32(uint32_t v) {
    std::ostringstream oss;
    oss << "0x" << std::hex << std::setfill('0') << std::setw(8) << v;
    return oss.str();
}

// ------------------------------------------------------------------------------------------- //
// ASF message type table -- packet-asf.c's own asf_type_vals, source-confirmed. The three
// "RAKP Message 1/2/3" entries are ASF's own vestigial/deprecated ones -- see rmcp.hpp's own
// header comment for why this decoder never further decodes them (real RAKP rides under RMCP
// Class=IPMI, not ASF -- see the IPMI-side RAKP support below).
struct AsfTypeEntry { uint8_t raw; const char* name; };
constexpr AsfTypeEntry kAsfTypes[] = {
    {0x10, "Reset"}, {0x11, "Power-up"}, {0x12, "Unconditional Power-down"},
    {0x13, "Power Cycle"},
    {0x40, "Presence Pong"}, {0x41, "Capabilities Response"},
    {0x42, "System State Response"}, {0x43, "Open Session Response"},
    {0x44, "Close Session Response"},
    {0x80, "Presence Ping"}, {0x81, "Capabilities Request"},
    {0x82, "System State Request"}, {0x83, "Open Session Request"},
    {0x84, "Close Session Request"},
    {0xC0, "RAKP Message 1"}, {0xC1, "RAKP Message 2"}, {0xC2, "RAKP Message 3"},
};

// IPMI 1.5 AuthType + the IPMI 2.0/RMCP+ marker value (0x06) -- packet-ipmi-session.c's own
// ipmi_authtype_vals.
struct U8NameEntry { uint8_t raw; const char* name; };
constexpr U8NameEntry kAuthTypes[] = {
    {0x00, "NONE"}, {0x01, "MD2"}, {0x02, "MD5"}, {0x04, "PASSWORD"},
    {0x05, "OEM"}, {0x06, "RMCP+"},
};

// IPMI 2.0 session Payload Type (6-bit masked value) -- packet-ipmi-session.c's own
// ipmi_payload_vals.
constexpr U8NameEntry kPayloadTypes[] = {
    {0x00, "IPMI Message"}, {0x01, "SOL (Serial over LAN)"}, {0x02, "OEM Explicit"},
    {0x10, "RMCP+ Open Session Request"}, {0x11, "RMCP+ Open Session Response"},
    {0x12, "RAKP Message 1"}, {0x13, "RAKP Message 2"}, {0x14, "RAKP Message 3"},
    {0x15, "RAKP Message 4"},
    {0x20, "OEM0 (OEM Payload)"}, {0x21, "OEM1 (OEM Payload)"}, {0x22, "OEM2 (OEM Payload)"},
    {0x23, "OEM3 (OEM Payload)"}, {0x24, "OEM4 (OEM Payload)"}, {0x25, "OEM5 (OEM Payload)"},
    {0x26, "OEM6 (OEM Payload)"}, {0x27, "OEM7 (OEM Payload)"},
};

// NetFn (request/even values only) -- packet-ipmi.c's own ipmi_netfn_setdesc() calls plus the
// 0x30-0x3E OEM range loop.
constexpr U8NameEntry kNetFnBase[] = {
    {0x00, "Chassis"}, {0x02, "Bridge"}, {0x04, "Sensor/Event"}, {0x06, "Application"},
    {0x08, "Firmware Update"}, {0x0A, "Storage"}, {0x0C, "Transport"},
    {0x2C, "Group"}, {0x2E, "OEM/Group"},
};

// Curated NetFn/Command name table -- App/Chassis/Storage/Transport only, "curated depth, not
// exhaustive" (see rmcp.hpp SCOPE). Source: packet-ipmi-app.c's cmd_app[], packet-ipmi-chassis.c's
// cmd_chassis[], packet-ipmi-storage.c's cmd_storage[], packet-ipmi-transport.c's cmd_transport[].
struct CommandEntry { uint8_t netfn_base; uint8_t cmd; const char* name; };
constexpr CommandEntry kCommands[] = {
    // Application (0x06).
    {0x06, 0x01, "Get Device ID"}, {0x06, 0x02, "Cold Reset"}, {0x06, 0x03, "Warm Reset"},
    {0x06, 0x04, "Get Self Test Results"},
    {0x06, 0x38, "Get Channel Authentication Capabilities"},
    {0x06, 0x39, "Get Session Challenge"}, {0x06, 0x3A, "Activate Session"},
    {0x06, 0x3B, "Set Session Privilege Level"}, {0x06, 0x3C, "Close Session"},
    {0x06, 0x3D, "Get Session Info"}, {0x06, 0x54, "Get Channel Cipher Suites"},
    // Chassis (0x00).
    {0x00, 0x01, "Get Chassis Status"}, {0x00, 0x02, "Chassis Control"},
    {0x00, 0x03, "Chassis Reset"}, {0x00, 0x04, "Chassis Identify"},
    {0x00, 0x06, "Set Power Restore Policy"}, {0x00, 0x08, "Set System Boot Options"},
    {0x00, 0x09, "Get System Boot Options"}, {0x00, 0x0F, "Get POH Counter"},
    // Storage (0x0A) -- SEL-focused, per rmcp.hpp's own SCOPE.
    {0x0A, 0x10, "Get FRU Inventory Area Info"}, {0x0A, 0x20, "Get SDR Repository Info"},
    {0x0A, 0x23, "Get SDR"}, {0x0A, 0x40, "Get SEL Info"},
    {0x0A, 0x41, "Get SEL Allocation Info"}, {0x0A, 0x42, "Reserve SEL"},
    {0x0A, 0x43, "Get SEL Entry"}, {0x0A, 0x44, "Add SEL Entry"},
    {0x0A, 0x46, "Delete SEL Entry"}, {0x0A, 0x47, "Clear SEL"}, {0x0A, 0x48, "Get SEL Time"},
    // Transport (0x0C) -- SOL-activation-focused, per rmcp.hpp's own SCOPE.
    {0x0C, 0x01, "Set LAN Configuration Parameters"},
    {0x0C, 0x02, "Get LAN Configuration Parameters"},
    {0x0C, 0x04, "Get IP/UDP/RMCP Statistics"}, {0x0C, 0x20, "SOL Activating"},
    {0x0C, 0x21, "Set SOL Configuration Parameters"},
    {0x0C, 0x22, "Get SOL Configuration Parameters"},
};

// Standard IPMI Completion Code table -- packet-ipmi.c's own ipmi_get_completion_code()
// std_completion_codes, source-confirmed, verbatim.
constexpr U8NameEntry kCompletionCodes[] = {
    {0x00, "Command Completed Normally"}, {0xC0, "Node Busy"}, {0xC1, "Invalid Command"},
    {0xC2, "Command invalid for given LUN"},
    {0xC3, "Timeout while processing command, response unavailable"},
    {0xC4, "Out of space"}, {0xC5, "Reservation Canceled or Invalid Reservation ID"},
    {0xC6, "Request data truncated"}, {0xC7, "Request data length invalid"},
    {0xC8, "Request data field length limit exceeded"}, {0xC9, "Parameter out of range"},
    {0xCA, "Cannot return number of requested data bytes"},
    {0xCB, "Requested Sensor, data, or record not present"},
    {0xCC, "Invalid data field in Request"},
    {0xCD, "Command illegal for specified sensor or record type"},
    {0xCE, "Command response could not be provided"},
    {0xCF, "Cannot execute duplicated request"},
    {0xD0, "Command response could not be provided: SDR Repository in update mode"},
    {0xD1, "Command response could not be provided: device in firmware update mode"},
    {0xD2, "Command response could not be provided: BMC initialization or initialization agent "
           "in progress"},
    {0xD3, "Destination unavailable"},
    {0xD4, "Cannot execute command: insufficient privilege level or other security-based "
           "restriction"},
    {0xD5, "Cannot execute command: command, or request parameter(s), not supported in present "
           "state"},
    {0xD6, "Cannot execute command: parameter is illegal because subfunction is disabled or "
           "unavailable"},
    {0xFF, "Unspecified error"},
};

// Requested/Granted Privilege Level -- packet-ipmi-app.c's own value_string, source-confirmed
// (rq38/rs38's own vals table).
constexpr U8NameEntry kPrivilegeLevels[] = {
    {0x00, "None / No change"}, {0x01, "Callback"}, {0x02, "User"},
    {0x03, "Operator"}, {0x04, "Administrator"}, {0x05, "OEM Proprietary"},
};

// IPMI 2.0/RMCP+ algorithm tables -- see rmcp.hpp's own ALGORITHM VALUES section for the exact
// sourcing/confirmation tier of each entry (0x01 in each of the first two tables is
// cross-confirmed from packet-asf.c; everything else is spec-sourced only, honestly noted there).
constexpr U8NameEntry kAuthAlgorithms[] = {
    {0x00, "RAKP-none"}, {0x01, "RAKP-HMAC-SHA1"}, {0x02, "RAKP-HMAC-MD5"},
    {0x03, "RAKP-HMAC-SHA256"},
};
constexpr U8NameEntry kIntegrityAlgorithms[] = {
    {0x00, "None"}, {0x01, "HMAC-SHA1-96"}, {0x02, "HMAC-MD5-128"}, {0x03, "MD5-128"},
    {0x04, "HMAC-SHA256-128"},
};
constexpr U8NameEntry kConfidentialityAlgorithms[] = {
    {0x00, "None"}, {0x01, "AES-CBC-128"}, {0x02, "xRC4-128"}, {0x03, "xRC4-40"},
};

// RMCP+ Status Code -- 0x00-0x07 cross-confirmed from packet-asf.c's own (mislabeled)
// asf_rssp_status_code_vals table; 0x08-0x12 spec-sourced only, see rmcp.hpp's own SOURCING note.
constexpr U8NameEntry kRmcpPlusStatusCodes[] = {
    {0x00, "No errors"}, {0x01, "Insufficient resources to create a session"},
    {0x02, "Invalid session ID"}, {0x03, "Invalid payload type"},
    {0x04, "Invalid authentication algorithm"}, {0x05, "Invalid integrity algorithm"},
    {0x06, "No matching authentication payload"}, {0x07, "No matching integrity payload"},
    {0x08, "Inactive session ID"}, {0x09, "Invalid role"},
    {0x0A, "Unauthorized role or privilege level requested"},
    {0x0B, "Insufficient resources to create a session at the requested role"},
    {0x0C, "Invalid name length"}, {0x0D, "Unauthorized name"}, {0x0E, "Unauthorized GUID"},
    {0x0F, "Invalid integrity check value"}, {0x10, "Invalid confidentiality algorithm"},
    {0x11, "No cipher suite match with proposed security algorithms"},
    {0x12, "Illegal or unrecognized parameter"},
};

// Chassis Control (NetFn Chassis 0x00, Command 0x02) low nibble -- packet-ipmi-chassis.c's own
// vals_02_cctrl, source-confirmed, verbatim.
constexpr U8NameEntry kChassisControl[] = {
    {0x00, "Power down"}, {0x01, "Power up"}, {0x02, "Power cycle"}, {0x03, "Hard reset"},
    {0x04, "Pulse Diagnostic Interrupt"},
    {0x05, "Initiate a soft-shutdown of OS via ACPI by emulating a fatal overtemperature"},
};

template <typename T, size_t N>
const char* lookup(const T (&table)[N], uint8_t raw) {
    for (const auto& e : table) {
        if (e.raw == raw) return e.name;
    }
    return nullptr;
}

}  // namespace

const char* rmcp_class_name(uint8_t class_masked) {
    switch (class_masked & 0x1F) {
        case 0x06: return "ASF";
        case 0x07: return "IPMI";
        case 0x08: return "OEM";
        default: return nullptr;
    }
}

std::optional<RmcpHeader> try_parse_rmcp_header(ByteSpan udp_payload) {
    if (udp_payload.size() < 4) return std::nullopt;
    RmcpHeader h;
    h.version_raw = udp_payload.at(0);
    h.reserved_raw = udp_payload.at(1);
    h.sequence_raw = udp_payload.at(2);
    if (h.version_raw != 0x06 || h.reserved_raw != 0xFF) return std::nullopt;
    uint8_t b3 = udp_payload.at(3);
    h.is_ack = (b3 & 0x80) != 0;
    h.class_raw = b3 & 0x1F;
    h.class_name = rmcp_class_name(h.class_raw);
    if (!h.class_name) return std::nullopt;
    return h;
}

std::optional<ProtocolResult> RmcpUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto header = try_parse_rmcp_header(payload);
    if (!header) return std::nullopt;
    // ASF/IPMI classes are claimed by their own, more specific decoders -- see rmcp.hpp's
    // DETECTION/DISPATCH section. Only an ACK (any class) or a Normal OEM-class message reach
    // this generic fallback.
    if (!header->is_ack && header->class_raw != 0x08) return std::nullopt;

    RmcpFrame frame;
    frame.header = *header;
    std::ostringstream summary;
    if (header->is_ack) {
        summary << "RMCP ACK, Class: " << (header->class_name ? header->class_name : "?");
    } else {
        frame.body = payload.from(4).to_vector();
        summary << "RMCP OEM message (" << frame.body.size() << " byte(s), not decoded -- see "
                << "rmcp.hpp's own OUT OF SCOPE note)";
    }
    frame.summary = summary.str();
    return ProtocolResult::make<RmcpFrame>("rmcp", std::move(frame));
}

const ProtocolDecoder& rmcp_udp_decoder() {
    static const RmcpUdpDecoder instance;
    return instance;
}

// ------------------------------------------------------------------------------------------- //
// ASF

const char* asf_message_type_name(uint8_t type_raw) { return lookup(kAsfTypes, type_raw); }

std::optional<AsfFrame> try_parse_asf(ByteSpan class_payload) {
    if (class_payload.size() < 8) return std::nullopt;
    try {
        Cursor cur(class_payload);
        AsfFrame f;
        f.iana = cur.u32be();
        f.message_type_raw = cur.u8();
        f.message_type_name = asf_message_type_name(f.message_type_raw);
        f.message_tag = cur.u8();
        cur.skip(1);  // reserved.
        f.data_length = cur.u8();

        size_t avail = cur.remaining();
        size_t body_len = f.data_length;
        bool truncated = false;
        if (body_len > avail) {
            truncated = true;
            body_len = avail;
        }
        ByteSpan body = cur.bytes(body_len);
        f.raw_body = body.to_vector();
        if (truncated) {
            f.notes.push_back("declared Data Length (" + std::to_string(f.data_length) +
                               " byte(s)) exceeds available bytes -- body truncated to what's "
                               "present");
        }

        if (f.message_type_raw == 0x40 /* Presence Pong */) {
            if (body.size() >= 16) {
                AsfPresencePong pong;
                Cursor pc(body);
                pong.oem_iana = pc.u32be();
                pong.oem_defined_hex = hex(pc.bytes(4));
                pong.supported_entities_raw = pc.u8();
                pong.asf_version = pong.supported_entities_raw & 0x0F;
                pong.supported_interactions_raw = pc.u8();
                pong.security_extensions_supported =
                    (pong.supported_interactions_raw & 0x80) != 0;
                f.presence_pong = pong;
            } else {
                f.notes.push_back(
                    "Presence Pong body shorter than the expected 16 bytes (DSP0136 Section "
                    "3.2.4.3) -- not further decoded, see raw body bytes");
            }
        }

        std::ostringstream summary;
        summary << "ASF ";
        if (f.message_type_name) {
            summary << f.message_type_name;
        } else {
            summary << "type 0x" << std::hex << static_cast<int>(f.message_type_raw) << std::dec;
        }
        summary << " tag=" << static_cast<int>(f.message_tag);
        if (f.presence_pong) {
            summary << " OEM-IANA=" << f.presence_pong->oem_iana
                    << " ASF-ver=" << static_cast<int>(f.presence_pong->asf_version)
                    << " sec-ext="
                    << (f.presence_pong->security_extensions_supported ? "yes" : "no");
        } else if (!f.raw_body.empty()) {
            summary << " (" << f.raw_body.size() << " byte(s) of body, not decoded -- see "
                    << "rmcp.hpp)";
        }
        f.summary = summary.str();
        return f;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> AsfUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto header = try_parse_rmcp_header(payload);
    if (!header || header->is_ack || header->class_raw != 0x06) return std::nullopt;
    auto asf = try_parse_asf(payload.from(4));
    if (!asf) return std::nullopt;
    return ProtocolResult::make<AsfFrame>("asf", std::move(*asf));
}

const ProtocolDecoder& asf_udp_decoder() {
    static const AsfUdpDecoder instance;
    return instance;
}

// ------------------------------------------------------------------------------------------- //
// IPMI

const char* ipmi_auth_type_name(uint8_t auth_type_raw) { return lookup(kAuthTypes, auth_type_raw); }

const char* ipmi_payload_type_name(uint8_t payload_type_masked) {
    return lookup(kPayloadTypes, payload_type_masked & 0x3F);
}

const char* ipmi_netfn_base_name(uint8_t netfn_base) {
    if (const char* n = lookup(kNetFnBase, netfn_base)) return n;
    if (netfn_base >= 0x30 && netfn_base < 0x40) return "OEM";
    return nullptr;
}

const char* ipmi_command_name(uint8_t netfn_base, uint8_t command_raw) {
    for (const auto& e : kCommands) {
        if (e.netfn_base == netfn_base && e.cmd == command_raw) return e.name;
    }
    return nullptr;
}

const char* ipmi_completion_code_name(uint8_t completion_code) {
    return lookup(kCompletionCodes, completion_code);
}

const char* ipmi_privilege_level_name(uint8_t privilege_raw) {
    return lookup(kPrivilegeLevels, privilege_raw & 0x0F);
}

const char* ipmi_auth_algorithm_name(uint8_t alg_raw) { return lookup(kAuthAlgorithms, alg_raw); }

const char* ipmi_integrity_algorithm_name(uint8_t alg_raw) {
    return lookup(kIntegrityAlgorithms, alg_raw);
}

const char* ipmi_confidentiality_algorithm_name(uint8_t alg_raw) {
    return lookup(kConfidentialityAlgorithms, alg_raw);
}

const char* ipmi_rmcpplus_status_code_name(uint8_t status_raw) {
    return lookup(kRmcpPlusStatusCodes, status_raw);
}

const char* ipmi_chassis_control_name(uint8_t control_raw) {
    return lookup(kChassisControl, control_raw & 0x0F);
}

namespace {

// The classic IPMI request/response message -- see rmcp.hpp's own WIRE FORMAT section for the
// exact byte layout and sourcing. `msg_span` is the IPMI session wrapper's own Message region.
std::optional<IpmiMessage> try_parse_ipmi_message(ByteSpan msg_span) {
    if (msg_span.size() < 7) return std::nullopt;
    IpmiMessage m;
    m.rs_addr = msg_span.at(0);
    uint8_t b1 = msg_span.at(1);
    m.netfn_raw = b1 >> 2;
    m.rs_lun = b1 & 0x3;
    m.netfn_name = ipmi_netfn_base_name(m.netfn_raw & ~static_cast<uint8_t>(1));
    m.is_response = (m.netfn_raw & 1) != 0;
    m.checksum1_raw = msg_span.at(2);
    m.checksum1_valid =
        static_cast<uint8_t>(m.rs_addr + b1 + m.checksum1_raw) == 0;
    m.rq_addr = msg_span.at(3);
    uint8_t b4 = msg_span.at(4);
    m.rq_seq = b4 >> 2;
    m.rq_lun = b4 & 0x3;
    m.command_raw = msg_span.at(5);
    if (const char* nm = ipmi_command_name(m.netfn_raw & ~static_cast<uint8_t>(1), m.command_raw)) {
        m.command_name = nm;
    }

    ByteSpan rest = msg_span.from(6);  // Data (or Completion Code + Data) + trailing Checksum 2.
    if (rest.empty()) return std::nullopt;
    size_t data_and_cc_len = rest.size() - 1;
    ByteSpan data_and_cc = rest.subspan(0, data_and_cc_len);
    m.checksum2_raw = rest.at(rest.size() - 1);
    uint32_t sum2 = static_cast<uint32_t>(m.rq_addr) + b4 + m.command_raw;
    for (size_t i = 0; i < data_and_cc.size(); ++i) sum2 += data_and_cc.at(i);
    sum2 += m.checksum2_raw;
    m.checksum2_valid = ((sum2 & 0xFF) == 0);

    if (m.is_response) {
        if (!data_and_cc.empty()) {
            m.completion_code = data_and_cc.at(0);
            if (const char* cc = ipmi_completion_code_name(*m.completion_code)) {
                m.completion_code_name = cc;
            }
            m.data = data_and_cc.from(1).to_vector();
        }
    } else {
        m.data = data_and_cc.to_vector();
    }
    return m;
}

std::optional<IpmiOpenSessionRequest> try_parse_open_session_request(ByteSpan span) {
    if (span.size() < 8) return std::nullopt;
    Cursor cur(span);
    IpmiOpenSessionRequest r;
    r.message_tag = cur.u8();
    r.requested_max_privilege_raw = cur.u8() & 0x0F;
    if (const char* n = ipmi_privilege_level_name(r.requested_max_privilege_raw)) {
        r.requested_max_privilege_name = n;
    }
    cur.skip(2);
    r.remote_console_session_id = cur.u32le();

    if (cur.remaining() >= 8) {
        cur.skip(4);  // Payload Type(1) + Reserved(2) + Payload Length(1) -- always 0x00/../8.
        r.auth_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_auth_algorithm_name(r.auth_algorithm_raw)) {
            r.auth_algorithm_name = n;
        }
        r.is_cipher_suite_zero = (r.auth_algorithm_raw == 0x00);
    }
    if (cur.remaining() >= 8) {
        cur.skip(4);
        r.integrity_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_integrity_algorithm_name(r.integrity_algorithm_raw)) {
            r.integrity_algorithm_name = n;
        }
    }
    if (cur.remaining() >= 8) {
        cur.skip(4);
        r.confidentiality_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_confidentiality_algorithm_name(r.confidentiality_algorithm_raw)) {
            r.confidentiality_algorithm_name = n;
        }
    }
    return r;
}

std::optional<IpmiOpenSessionResponse> try_parse_open_session_response(ByteSpan span) {
    if (span.size() < 12) return std::nullopt;
    Cursor cur(span);
    IpmiOpenSessionResponse r;
    r.message_tag = cur.u8();
    r.status_code_raw = cur.u8();
    if (const char* n = ipmi_rmcpplus_status_code_name(r.status_code_raw)) {
        r.status_code_name = n;
    }
    r.max_privilege_raw = cur.u8() & 0x0F;
    if (const char* n = ipmi_privilege_level_name(r.max_privilege_raw)) {
        r.max_privilege_name = n;
    }
    cur.skip(1);
    r.remote_console_session_id = cur.u32le();
    r.managed_system_session_id = cur.u32le();

    if (r.status_code_raw == 0 && cur.remaining() >= 24) {
        r.algorithms_present = true;
        cur.skip(4);
        r.auth_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_auth_algorithm_name(r.auth_algorithm_raw)) {
            r.auth_algorithm_name = n;
        }
        cur.skip(4);
        r.integrity_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_integrity_algorithm_name(r.integrity_algorithm_raw)) {
            r.integrity_algorithm_name = n;
        }
        cur.skip(4);
        r.confidentiality_algorithm_raw = cur.u8();
        cur.skip(3);
        if (const char* n = ipmi_confidentiality_algorithm_name(r.confidentiality_algorithm_raw)) {
            r.confidentiality_algorithm_name = n;
        }
        r.is_cipher_suite_zero = (r.auth_algorithm_raw == 0x00);
    }
    return r;
}

std::optional<IpmiRakpMessage1> try_parse_rakp1(ByteSpan span) {
    if (span.size() < 28) return std::nullopt;
    Cursor cur(span);
    IpmiRakpMessage1 m;
    m.message_tag = cur.u8();
    cur.skip(3);
    m.managed_system_session_id = cur.u32le();
    m.remote_console_random_number_hex = hex(cur.bytes(16));
    uint8_t priv_byte = cur.u8();
    m.requested_max_privilege_raw = priv_byte & 0x0F;
    m.name_only_lookup = (priv_byte & 0x10) != 0;
    if (const char* n = ipmi_privilege_level_name(m.requested_max_privilege_raw)) {
        m.requested_max_privilege_name = n;
    }
    cur.skip(2);
    m.user_name_length = cur.u8();
    size_t namelen = std::min<size_t>(m.user_name_length, cur.remaining());
    if (namelen > 0) {
        ByteSpan nm = cur.bytes(namelen);
        m.user_name.assign(reinterpret_cast<const char*>(nm.data()), nm.size());
    }
    return m;
}

std::optional<IpmiRakpMessage2> try_parse_rakp2(ByteSpan span) {
    if (span.size() < 40) return std::nullopt;
    Cursor cur(span);
    IpmiRakpMessage2 m;
    m.message_tag = cur.u8();
    m.status_code_raw = cur.u8();
    if (const char* n = ipmi_rmcpplus_status_code_name(m.status_code_raw)) m.status_code_name = n;
    cur.skip(2);
    m.remote_console_session_id = cur.u32le();
    m.managed_system_random_number_hex = hex(cur.bytes(16));
    m.managed_system_guid_hex = hex(cur.bytes(16));
    if (cur.remaining() > 0) m.key_exchange_auth_code_hex = hex(cur.rest());
    return m;
}

std::optional<IpmiRakpMessage3> try_parse_rakp3(ByteSpan span) {
    if (span.size() < 8) return std::nullopt;
    Cursor cur(span);
    IpmiRakpMessage3 m;
    m.message_tag = cur.u8();
    m.status_code_raw = cur.u8();
    if (const char* n = ipmi_rmcpplus_status_code_name(m.status_code_raw)) m.status_code_name = n;
    cur.skip(2);
    m.managed_system_session_id = cur.u32le();
    if (cur.remaining() > 0) m.key_exchange_auth_code_hex = hex(cur.rest());
    return m;
}

std::optional<IpmiRakpMessage4> try_parse_rakp4(ByteSpan span) {
    if (span.size() < 8) return std::nullopt;
    Cursor cur(span);
    IpmiRakpMessage4 m;
    m.message_tag = cur.u8();
    m.status_code_raw = cur.u8();
    if (const char* n = ipmi_rmcpplus_status_code_name(m.status_code_raw)) m.status_code_name = n;
    cur.skip(2);
    m.remote_console_session_id = cur.u32le();
    if (cur.remaining() > 0) m.integrity_check_value_hex = hex(cur.rest());
    return m;
}

// Curated command-specific notes -- Get Channel Authentication Capabilities and Chassis Control
// only, matching rmcp.hpp's own "curated depth" scope note.
void add_curated_command_notes(const IpmiMessage& m, std::vector<std::string>& notes) {
    uint8_t netfn_base = m.netfn_raw & ~static_cast<uint8_t>(1);
    if (netfn_base == 0x06 && m.command_raw == 0x38) {
        if (!m.is_response && m.data.size() >= 2) {
            uint8_t channel = m.data[0] & 0x0F;
            uint8_t priv = m.data[1] & 0x0F;
            const char* priv_name = ipmi_privilege_level_name(priv);
            notes.push_back("Get Channel Authentication Capabilities request: channel=" +
                             std::to_string(channel) + ", requested privilege=" +
                             (priv_name ? priv_name : "unknown"));
        } else if (m.is_response && m.data.size() >= 8) {
            uint8_t auth_support = m.data[1];
            std::vector<std::string> supported;
            if (auth_support & 0x01) supported.push_back("NONE");
            if (auth_support & 0x02) supported.push_back("MD2");
            if (auth_support & 0x04) supported.push_back("MD5");
            if (auth_support & 0x10) supported.push_back("PASSWORD");
            if (auth_support & 0x20) supported.push_back("OEM");
            std::string joined;
            for (size_t i = 0; i < supported.size(); ++i) {
                if (i) joined += ", ";
                joined += supported[i];
            }
            notes.push_back("Get Channel Authentication Capabilities response: supported auth "
                             "types = " + (joined.empty() ? std::string("none") : joined) +
                             (auth_support & 0x80 ? "; IPMI 2.0/RMCP+ extended capabilities "
                                                     "supported" : ""));
        }
    } else if (netfn_base == 0x00 && m.command_raw == 0x02 && !m.is_response &&
               !m.data.empty()) {
        const char* action = ipmi_chassis_control_name(m.data[0]);
        notes.push_back(std::string("Chassis Control: ") + (action ? action : "unknown action") +
                         " -- a remote power-control command (security-relevant: any session "
                         "that can reach this NetFn/Command, including one authenticated under "
                         "Cipher Suite 0, can power off/reset this chassis)");
    }
}

}  // namespace

std::optional<IpmiFrame> try_parse_ipmi(ByteSpan class_payload, IpmiFlowState* flow_state) {
    if (class_payload.size() < 10) return std::nullopt;  // shortest legal shape: v1.5, AuthType==NONE.
    try {
        IpmiFrame frame;
        IpmiSessionHeader& sh = frame.session;
        Cursor cur(class_payload);
        sh.auth_type_raw = cur.u8();
        sh.auth_type_name = ipmi_auth_type_name(sh.auth_type_raw);
        sh.is_v2 = (sh.auth_type_raw == 0x06);

        size_t msg_start;
        if (sh.is_v2) {
            uint8_t pt_byte = cur.u8();
            sh.payload_encrypted = (pt_byte & 0x80) != 0;
            sh.payload_authenticated = (pt_byte & 0x40) != 0;
            sh.payload_type_raw = pt_byte & 0x3F;
            sh.payload_type_name = ipmi_payload_type_name(sh.payload_type_raw);

            if (sh.payload_type_raw == 0x02 /* OEM Explicit */) {
                if (class_payload.size() < 18) return std::nullopt;
                sh.oem_iana = cur.u32be();
                sh.oem_payload_id = cur.u16be();
            } else if (class_payload.size() < 12) {
                return std::nullopt;
            }
            sh.session_id = cur.u32le();
            sh.session_sequence = cur.u32le();
            sh.message_length = cur.u16le();
            msg_start = cur.position();
        } else {
            sh.session_sequence = cur.u32le();
            sh.session_id = cur.u32le();
            if (sh.auth_type_raw != 0x00) {
                if (class_payload.size() < 26) return std::nullopt;
                sh.auth_code_present = true;
                sh.auth_code_length = 16;  // never store the actual bytes -- see rmcp.hpp WIRE
                                            // FORMAT.
                cur.skip(16);
            }
            sh.message_length = cur.u8();
            msg_start = cur.position();
        }

        size_t available = class_payload.size() - msg_start;
        size_t msg_len = sh.message_length;
        bool truncated = false;
        if (msg_len > available) {
            truncated = true;
            msg_len = available;
        }
        ByteSpan msg_span = class_payload.subspan(msg_start, msg_len);
        if (!truncated) sh.trailer_length = available - msg_len;
        if (truncated) {
            frame.notes.push_back("declared Message Length (" +
                                   std::to_string(sh.message_length) +
                                   ") exceeds available bytes -- message region truncated to "
                                   "what's present");
        }

        if (sh.auth_code_present) {
            frame.notes.push_back(
                "Authentication Code present (" + std::to_string(sh.auth_code_length) +
                " byte(s)) -- never rendered, only presence/length noted (see rmcp.hpp WIRE "
                "FORMAT)");
        }

        if (sh.payload_encrypted) {
            frame.notes.push_back("payload is Encrypted (Confidentiality flag set) -- not "
                                   "decrypted, " + std::to_string(msg_span.size()) +
                                   " opaque byte(s)");
        } else if (!sh.is_v2 || sh.payload_type_raw == 0x00 /* IPMI Message */) {
            if (auto m = try_parse_ipmi_message(msg_span)) {
                add_curated_command_notes(*m, frame.notes);
                frame.message = std::move(m);
            } else if (!msg_span.empty()) {
                frame.notes.push_back("message region present but too short/malformed for the "
                                       "classic IPMI request/response shape");
            }
        } else if (sh.payload_type_raw == 0x10) {
            if (auto r = try_parse_open_session_request(msg_span)) {
                frame.open_session_request = r;
            } else {
                frame.notes.push_back("Open Session Request region too short to decode");
            }
        } else if (sh.payload_type_raw == 0x11) {
            if (auto r = try_parse_open_session_response(msg_span)) {
                frame.open_session_response = r;
            } else {
                frame.notes.push_back("Open Session Response region too short to decode");
            }
        } else if (sh.payload_type_raw == 0x12) {
            if (auto r = try_parse_rakp1(msg_span)) {
                frame.rakp1 = r;
            } else {
                frame.notes.push_back("RAKP Message 1 region too short to decode");
            }
        } else if (sh.payload_type_raw == 0x13) {
            if (auto r = try_parse_rakp2(msg_span)) {
                frame.rakp2 = r;
            } else {
                frame.notes.push_back("RAKP Message 2 region too short to decode");
            }
        } else if (sh.payload_type_raw == 0x14) {
            if (auto r = try_parse_rakp3(msg_span)) {
                frame.rakp3 = r;
            } else {
                frame.notes.push_back("RAKP Message 3 region too short to decode");
            }
        } else if (sh.payload_type_raw == 0x15) {
            if (auto r = try_parse_rakp4(msg_span)) {
                frame.rakp4 = r;
            } else {
                frame.notes.push_back("RAKP Message 4 region too short to decode");
            }
        } else {
            frame.notes.push_back(std::string("Payload Type ") +
                                   (sh.payload_type_name ? sh.payload_type_name : "unknown") +
                                   " not further decoded (SOL/OEM payload -- see rmcp.hpp SCOPE)");
        }

        if (!truncated && sh.trailer_length > 0) {
            std::string note = std::to_string(sh.trailer_length) +
                                " trailing byte(s) beyond the declared Message Length";
            if (sh.payload_authenticated) {
                note += " -- likely an Integrity trailer (pad + pad-length + next-header + "
                        "auth-code), not independently verified, see rmcp.hpp SCOPE";
            }
            frame.notes.push_back(note);
        }

        // Cipher Suite 0 -- see rmcp.hpp's own SECURITY note.
        bool this_packet_cipher_suite_zero = false;
        std::string cipher_suite_zero_note;
        if (frame.open_session_request && frame.open_session_request->is_cipher_suite_zero) {
            this_packet_cipher_suite_zero = true;
            cipher_suite_zero_note =
                "SECURITY: this Open Session Request PROPOSES Cipher Suite 0 (Authentication "
                "Algorithm = RAKP-none) -- if the BMC accepts it, RAKP's own key-exchange "
                "authentication check never happens for the rest of this session "
                "(CVE-2013-4786-class authentication bypass; see rmcp.hpp's own SECURITY note)";
        }
        if (frame.open_session_response && frame.open_session_response->is_cipher_suite_zero) {
            this_packet_cipher_suite_zero = true;
            cipher_suite_zero_note =
                "SECURITY: this Open Session Response ACCEPTS Cipher Suite 0 (Authentication "
                "Algorithm = RAKP-none, status = No errors) -- RAKP's own key-exchange "
                "authentication check will never happen for the rest of this session; ANY "
                "password, including a nonexistent one, will complete this handshake "
                "(CVE-2013-4786-class authentication bypass; see rmcp.hpp's own SECURITY note)";
        }
        if (this_packet_cipher_suite_zero) {
            frame.cipher_suite_zero = true;
            frame.notes.push_back(cipher_suite_zero_note);
        }
        if (flow_state) {
            if (this_packet_cipher_suite_zero) {
                flow_state->cipher_suite_zero_seen = true;
            } else if (flow_state->cipher_suite_zero_seen &&
                       (frame.rakp1 || frame.rakp2 || frame.rakp3 || frame.rakp4)) {
                frame.cipher_suite_zero = true;
                frame.notes.push_back(
                    "this session's own earlier Open Session exchange proposed/accepted Cipher "
                    "Suite 0 (RAKP-none) -- see rmcp.hpp's own SECURITY note");
            }
        }

        // Summary.
        std::ostringstream summary;
        summary << (sh.is_v2 ? "IPMI2.0/RMCP+ " : "IPMI1.5 ");
        if (frame.message) {
            const IpmiMessage& m = *frame.message;
            summary << (m.is_response ? "Response" : "Request") << " NetFn="
                    << (m.netfn_name ? m.netfn_name : "0x");
            if (!m.netfn_name) {
                summary << std::hex << static_cast<int>(m.netfn_raw & ~static_cast<uint8_t>(1))
                        << std::dec;
            }
            summary << " Cmd=";
            if (m.command_name) {
                summary << *m.command_name;
            } else {
                summary << "0x" << std::hex << static_cast<int>(m.command_raw) << std::dec;
            }
            if (m.completion_code) {
                summary << " CC=";
                if (m.completion_code_name) {
                    summary << *m.completion_code_name;
                } else {
                    summary << "0x" << std::hex << static_cast<int>(*m.completion_code)
                            << std::dec;
                }
            }
        } else if (frame.open_session_request) {
            const auto& r = *frame.open_session_request;
            summary << "Open Session Request tag=" << static_cast<int>(r.message_tag)
                    << " priv=" << (r.requested_max_privilege_name
                                         ? *r.requested_max_privilege_name
                                         : "unknown")
                    << " auth=" << (r.auth_algorithm_name ? *r.auth_algorithm_name : "unknown");
            if (r.is_cipher_suite_zero) summary << " [CIPHER SUITE 0 PROPOSED]";
        } else if (frame.open_session_response) {
            const auto& r = *frame.open_session_response;
            summary << "Open Session Response tag=" << static_cast<int>(r.message_tag)
                    << " status=" << (r.status_code_name ? *r.status_code_name : "unknown");
            if (r.algorithms_present) {
                summary << " auth=" << (r.auth_algorithm_name ? *r.auth_algorithm_name
                                                                : "unknown");
            }
            if (r.is_cipher_suite_zero) summary << " [CIPHER SUITE 0 ACCEPTED]";
        } else if (frame.rakp1) {
            const auto& r = *frame.rakp1;
            summary << "RAKP Message 1 tag=" << static_cast<int>(r.message_tag) << " user="
                    << (r.user_name.empty() ? "(anonymous)" : r.user_name);
        } else if (frame.rakp2) {
            const auto& r = *frame.rakp2;
            summary << "RAKP Message 2 tag=" << static_cast<int>(r.message_tag)
                    << " status=" << (r.status_code_name ? *r.status_code_name : "unknown");
        } else if (frame.rakp3) {
            const auto& r = *frame.rakp3;
            summary << "RAKP Message 3 tag=" << static_cast<int>(r.message_tag)
                    << " status=" << (r.status_code_name ? *r.status_code_name : "unknown");
        } else if (frame.rakp4) {
            const auto& r = *frame.rakp4;
            summary << "RAKP Message 4 tag=" << static_cast<int>(r.message_tag)
                    << " status=" << (r.status_code_name ? *r.status_code_name : "unknown");
        } else {
            summary << "session Payload Type=";
            if (sh.is_v2) {
                summary << (sh.payload_type_name ? sh.payload_type_name : "unknown");
            } else {
                summary << "IPMI Message";
            }
            summary << " Session ID=" << hex32(sh.session_id);
        }
        frame.summary = summary.str();

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> IpmiUdpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto header = try_parse_rmcp_header(payload);
    if (!header || header->is_ack || header->class_raw != 0x07) return std::nullopt;
    IpmiFlowState& state = ctx.flow_state<IpmiFlowState>();
    auto ipmi = try_parse_ipmi(payload.from(4), &state);
    if (!ipmi) return std::nullopt;
    return ProtocolResult::make<IpmiFrame>("ipmi", std::move(*ipmi));
}

const ProtocolDecoder& ipmi_udp_decoder() {
    static const IpmiUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
