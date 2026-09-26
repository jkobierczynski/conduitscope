// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ffhse.hpp"

#include "conduitscope/resource_limits.hpp"

#include <algorithm>
#include <cstdint>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Small formatting/reading helpers -- see ffhse.hpp for the byte layouts these serve.

std::string hex8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(2) << static_cast<unsigned>(v);
    return s.str();
}
std::string hex16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << static_cast<unsigned>(v);
    return s.str();
}

uint16_t be16(ByteSpan s, size_t off) { return static_cast<uint16_t>((s.at(off) << 8) | s.at(off + 1)); }
uint32_t be32(ByteSpan s, size_t off) {
    return (static_cast<uint32_t>(s.at(off)) << 24) | (static_cast<uint32_t>(s.at(off + 1)) << 16) |
           (static_cast<uint32_t>(s.at(off + 2)) << 8) | static_cast<uint32_t>(s.at(off + 3));
}
uint64_t be64(ByteSpan s, size_t off) {
    uint64_t v = 0;
    for (size_t i = 0; i < 8; ++i) v = (v << 8) | s.at(off + i);
    return v;
}

// Plausibility ceiling for the header's own 32-bit Message Length field -- see
// docs/DEVELOPMENT.md's "Correction to item 7". FF-HSE's wire format puts no ceiling of its own on
// this field, so it does double duty: ffhse_declared_length (below) uses it to keep
// Decoder::reassemble_tcp_payload from buffering a TCP flow towards an implausible declared size,
// and try_parse_ffhse (below) uses the SAME constant as an extra structural-detection check.
// That second use matters more than it might look: FF-HSE's own detection gate is already the
// weakest in this codebase (12 valid ProtocolAndType byte values out of 256 -- see ffhse.hpp's own
// "Structural detection gate" paragraph), and without this ceiling a message_length field with no
// bound at all meant essentially ANY random noise that happened to match that one byte -- e.g. a
// UDP/443 QUIC/TLS datagram landing on FF-HSE's Auto-mode dispatch after every other protocol had
// already declined it -- would misdetect as FF-HSE. Confirmed against exactly that on a real
// capture: a UDP/443 response byte pattern matched the ProtocolAndType gate and decoded a
// Message Length of 4237566479 (essentially random 32-bit noise, not a real length), which this
// decoder then dutifully "explained" as a badly truncated FF-HSE message instead of being rejected
// outright. Since values below this ceiling are a small fraction of the full 32-bit range (roughly
// 0.4%), adding it here removes the great majority of that false-positive class without weakening
// this decoder's ability to recognize a real, truncated FF-HSE message -- a legitimate capture's
// Message Length is never anywhere near 16 MiB in practice.
// CLI-configurable via --max-reassembly-bytes -- see resource_limits.hpp. 0/unset keeps the
// literal 16 MiB default this constant always had. A function rather than a constexpr/const
// namespace-scope value, since it now reads process-wide configuration rather than a fixed
// literal, and both call sites below already call it fresh each time.
uint32_t max_plausible_message_length() {
    return static_cast<uint32_t>(resource_limits().max_reassembly_bytes.value_or(16u * 1024u * 1024u));
}

std::string ascii_field(ByteSpan s) { return std::string(reinterpret_cast<const char*>(s.data()), s.size()); }

// Trims trailing NUL (0x00) bytes -- used only for the Error body's AdditionalDescription field,
// per ffhse.hpp. A description that isn't NUL-terminated at all is returned unchanged, not treated
// as an error.
std::string trim_trailing_nul(ByteSpan s) {
    size_t n = s.size();
    while (n > 0 && s.at(n - 1) == 0x00) --n;
    return std::string(reinterpret_cast<const char*>(s.data()), n);
}

// Safety cap on how many list entries this decoder ever renders into `values` for one message --
// see the SM Find Tag Reply/SM Identify/LAN Get Statistics/LAN Diagnostic decode functions.
// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
// literal 64 default. A function rather than a constexpr/const namespace-scope value, for the
// same reason as max_plausible_message_length() above.
size_t list_cap() { return resource_limits().max_decoded_objects.value_or(64); }

// ------------------------------------------------------------------------------------------
// Shared plumbing every decode_* function below uses -- see ffhse.hpp's own "Message-family/
// struct-organization note" for why message bodies are rendered into FfhseFrame::values rather
// than one struct per shape.

// `frame.message_name` must already be set by the caller (every dispatch_* function below sets it
// before calling any decode_* function) -- used only to word the resulting note.
bool require_min(FfhseFrame& frame, ByteSpan body, size_t need) {
    if (body.size() < need) {
        frame.notes.push_back(frame.message_name + " body is " + std::to_string(body.size()) +
                               " byte(s), expected at least " + std::to_string(need) +
                               " -- not decoded, shown as raw hex");
        return false;
    }
    return true;
}

bool require_empty(FfhseFrame& frame, ByteSpan body) {
    if (!body.empty()) {
        frame.notes.push_back(frame.message_name + " body is " + std::to_string(body.size()) +
                               " byte(s), expected 0 (empty) -- shown as raw hex");
        return false;
    }
    return true;
}

// Marks whatever bytes remain past `consumed` (this message's own fixed/variable decoded shape) as
// raw hex -- the "remainder@N=raw" idiom this file's own design document uses for almost every
// message shape.
void set_remainder(FfhseFrame& frame, ByteSpan body, size_t consumed) {
    if (consumed < body.size()) {
        ByteSpan rest = body.from(consumed);
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(rest, "");
        frame.body_length = rest.size();
        frame.notes.push_back(std::to_string(rest.size()) +
                               " trailing byte(s) beyond this message's own decoded shape -- shown as raw hex");
    }
}

// Tier-2 (or unrecognized) fallback: the WHOLE body is shown as raw hex, nothing decoded.
void show_whole_body_as_hex(FfhseFrame& frame, ByteSpan body) {
    frame.body_length = body.size();
    if (!body.empty()) {
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(body, "");
    }
}

// Every Tier-1 dispatch case below ends by calling this: `ok` says whether the fixed part of the
// body matched this decoder's expected shape (values already pushed by the decode_* function that
// produced it); when it didn't, the whole body is shown as raw hex instead (a decode_* function
// that returns false never partially fills `values`, matching hartip.cpp's own convention).
void finish_tier1(FfhseFrame& frame, ByteSpan body, bool ok) {
    frame.body_decoded = ok;
    if (!ok) show_whole_body_as_hex(frame, body);
}

// ------------------------------------------------------------------------------------------
// Name lookup tables -- see ffhse.hpp's file header comment for which of these are pulled
// verbatim from a real copy of Wireshark's packet-ff.c (fetched and inspected directly while
// building this decoder) vs. this decoder's own conservative fallback.

std::string protocol_name(uint8_t protocol_masked) {
    switch (protocol_masked) {
        case 0x04: return "FDA Session Management";
        case 0x08: return "SM";
        case 0x0c: return "FMS";
        case 0x10: return "LAN Redundancy";
        default: return "unknown(" + hex8(protocol_masked) + ")";
    }
}

std::string type_name(uint8_t type_masked) {
    switch (type_masked) {
        case 0: return "Request";
        case 1: return "Response";
        case 2: return "Error";
        default: return "unknown(" + std::to_string(type_masked) + ")";
    }
}

// The 11-entry ErrorClass table -- pulled verbatim from packet-ff.c's own names_err_class.
std::string error_class_name(uint8_t c) {
    switch (c) {
        case 1: return "VFD State";
        case 2: return "Application Reference";
        case 3: return "Definition";
        case 4: return "Resource";
        case 5: return "Service";
        case 6: return "Access";
        case 7: return "OD";
        case 8: return "Other";
        case 9: return "Reject";
        case 10: return "H1 SM Reason Code";
        case 11: return "FMS Initiate";
        default: return "unknown(" + std::to_string(c) + ")";
    }
}

// The full, exhaustive per-ErrorClass ErrorCode tables -- pulled verbatim from packet-ff.c's own
// val_to_str_err_code() and its 11 backing names_err_code_* value_string arrays. An unmapped
// (class, code) pair renders "unknown(N)", exactly like the reference dissector's own "Unknown"
// fallback -- never guessed at.
std::string error_code_name(uint8_t error_class, uint8_t code) {
    switch (error_class) {
        case 1:  // VFD State
            if (code == 0) return "other";
            break;
        case 2:  // Application Reference
            switch (code) {
                case 0: return "other";
                case 1: return "object undefined";
                case 2: return "object attributes inconsistent";
                case 3: return "name already exists";
            }
            break;
        case 3:  // Definition
            switch (code) {
                case 0: return "other";
                case 1: return "application unreachable";
            }
            break;
        case 4:  // Resource
            switch (code) {
                case 0: return "other";
                case 1: return "memory unavailable";
                case 2: return "max outstanding requests per session exceeded";
                case 3: return "max sessions exceeded";
                case 4: return "object creation failure";
            }
            break;
        case 5:  // Service
            switch (code) {
                case 0: return "other";
                case 1: return "object state conflict";
                case 2: return "pdu size";
                case 3: return "object constraint conflict";
                case 4: return "parameter inconsistent";
                case 5: return "illegal parameter";
                case 6: return "unsupported service";
                case 7: return "unsupported version";
                case 8: return "invalid options";
                case 9: return "unsupported protocol";
                case 10: return "reserved";
                case 11: return "key parameter mismatch";
                case 12: return "assignments already made";
                case 13: return "unsupported device redundancy state";
                case 14: return "response time-out";
                case 15: return "duplicate PD Tag detected";
            }
            break;
        case 6:  // Access
            switch (code) {
                case 0: return "other";
                case 1: return "object invalidated";
                case 2: return "hardware fault";
                case 3: return "object access denied";
                case 4: return "invalid address";
                case 5: return "object attribute inconsistent";
                case 6: return "object access unsupported";
                case 7: return "object non existent";
                case 8: return "type conflict";
                case 9: return "named access unsupported";
                case 10: return "access to element unsupported";
                case 11: return "config access already open";
                case 12: return "reserved";
                case 13: return "unrecognized FDA Address";
            }
            break;
        case 7:  // OD
            switch (code) {
                case 0: return "other";
                case 1: return "name length overflow";
                case 2: return "od overflow";
                case 3: return "od write protected";
                case 4: return "extension length overflow";
                case 5: return "od description length overflow";
                case 6: return "operational problem";
                case 7: return "hse to h1 format conversion not supported";
            }
            break;
        case 8:  // Other
            if (code == 0) return "other";
            break;
        case 9:  // Reject
            if (code == 5) return "pdu size";
            break;
        case 10:  // H1 SM Reason Code
            switch (code) {
                case 0: return "other";
                case 1: return "DLL Error - insufficient resources";
                case 2: return "DLL Error - sending queue full";
                case 3: return "DLL Error - time-out before transmission";
                case 4: return "DLL Error - reason unspecified";
                case 5: return "Device failed to respond to SET_PD_TAG";
                case 6: return "Device failed to respond to WHO_HAS_PD_TAG";
                case 7: return "Device failed to respond to SET_ADDR";
                case 8: return "Device failed to respond to IDENTIFY";
                case 9: return "Device failed to respond to ENABLE_SM_OP";
                case 10: return "Device failed to respond to CLEAR_ADDRESS";
                case 11: return "Multiple Response from WHO_HAS_PD_TAG";
                case 12: return "Non-Matching PD_TAG from WHO_HAS_PD_TAG";
                case 13: return "Non-Matching PD_TAG from IDENTIFY";
                case 14: return "Non-Matching DEV_ID from IDENTIFY";
                case 15: return "Remote Error Invalid State";
                case 16: return "Remote Error PD-Tag doesn't match";
                case 17: return "Remote Error Dev-ID doesn't match";
                case 18: return "Remote Error SMIB object write failed";
                case 19: return "Remote Error Starting SM Operational";
            }
            break;
        case 11:  // FMS Initiate
            switch (code) {
                case 0: return "other";
                case 1: return "max-fms-pdu-size-insufficient";
                case 2: return "feature-not-supported";
                case 3: return "version-od-incompatible";
                case 4: return "user-initiate-denied";
                case 5: return "password-error";
                case 6: return "profile-number-incompatible";
            }
            break;
        default:
            break;
    }
    return "unknown(" + std::to_string(code) + ")";
}

// SM Find Tag Query's QueryType (7 entries) -- pulled verbatim from packet-ff.c's own
// names_query_type.
std::string query_type_name(uint8_t t) {
    switch (t) {
        case 0: return "PD Tag query for primary device";
        case 1: return "VFD tag query";
        case 2: return "Function-Block tag query";
        case 3: return "Element Id query";
        case 4: return "PD Tag/VFD Reference query";
        case 5: return "Device Index query";
        case 6: return "PD Tag query for secondary or member of redundant set";
        default: return "unknown(" + std::to_string(t) + ")";
    }
}

// FDA Open Session's NmaConfigurationUse -- pulled verbatim from packet-ff.c's own
// names_nma_conf_use.
std::string nma_conf_use_name(uint8_t v) {
    switch (v) {
        case 0: return "NMA Configuration Not Permitted";
        case 1: return "NMA Configuration Permitted";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// FMS Initiate's ConnectOption -- pulled verbatim from packet-ff.c's own names_conn_opt.
std::string conn_opt_name(uint8_t v) {
    switch (v) {
        case 1: return "VCR Selector";
        case 2: return "NMA Access";
        case 3: return "FBAP Access";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// The Redundant Device Type Capability sub-field (DevType bits 0-2, 0-7) -- pulled verbatim from
// packet-ff.c's own names_dev_type.
std::string dev_type_capability_name(uint8_t v) {
    switch (v) {
        case 0: return "Type D-1 Device";
        case 1: return "Type D-2 Device";
        case 2: return "Type D-3 Device";
        case 3: return "Type D-3 and Type D-2 Device";
        case 4: return "Not used";
        case 5: return "Type D-2 and Type D-1 Device";
        case 6: return "Type D-3 and Type D-1 Device";
        case 7: return "Type D-3 and D-2 and Type D-1 Device";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// DevType(1B) bitmask -- bit7=Linking Device, bit6=I/O Gateway, bit5=HSE Field Device, bit4=H1
// Device (bit positions confirmed against packet-ff.c's own inline "Bit 8/7/6/5 = ..." comments),
// bits0-2=Redundant Device Type Capability (see dev_type_capability_name above).
std::vector<std::string> dev_type_fields(uint8_t b) {
    std::vector<std::string> out;
    out.push_back(std::string("linking-device=") + ((b & 0x80) ? "true" : "false"));
    out.push_back(std::string("io-gateway=") + ((b & 0x40) ? "true" : "false"));
    out.push_back(std::string("hse-field-device=") + ((b & 0x20) ? "true" : "false"));
    out.push_back(std::string("h1-device=") + ((b & 0x10) ? "true" : "false"));
    uint8_t cap = static_cast<uint8_t>(b & 0x07);
    out.push_back("redundant-device-type-capability=" + std::to_string(cap) + " (" + dev_type_capability_name(cap) +
                   ")");
    return out;
}

// DupDetectionState(1B) bitmask -- bit0=Duplicate Device Index, bit1=Duplicate PD Tag, bits2-7
// reserved. Confirmed against packet-ff.c's own hf_ff_sm_id_rsp_dup_detection_state_* field
// definitions (identical 0x01/0x02 masks reused for SM Identify Rsp, SM Device Annunciation, and
// LAN Diagnostic Message's own DupDetectionState byte -- one shared helper for all three). Only
// SET bits are listed, matching hartip.cpp's own device_status_flags/comm_error_flags convention.
std::vector<std::string> dup_detection_state_flags(uint8_t b) {
    std::vector<std::string> out;
    if (b & 0x01) out.push_back("duplicate-device-index");
    if (b & 0x02) out.push_back("duplicate-pd-tag");
    return out;
}

// SmkState(1B) bitmask -- pulled verbatim from packet-ff.c's own names_smk_state (only bits 0/1
// are named there; other bits are not asserted).
std::vector<std::string> smk_state_flags(uint8_t b) {
    std::vector<std::string> out;
    if (b & 0x01) out.push_back("NO_TAG");
    if (b & 0x02) out.push_back("OPERATIONAL");
    return out;
}

// LrFlags(1B) bitmask -- see ffhse.hpp/LAN Redundancy Get/Put Info.
std::vector<std::string> lr_flags_names(uint8_t b) {
    std::vector<std::string> out;
    if (b & 0x10) out.push_back("load-balance");
    if (b & 0x08) out.push_back("diag");
    if (b & 0x04) out.push_back("multi-recv");
    if (b & 0x02) out.push_back("cross-cable");
    if (b & 0x01) out.push_back("multi-trans");
    return out;
}

std::string transmission_interface_name(uint8_t v) {
    switch (v) {
        case 0: return "Interface A";
        case 1: return "Interface B";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// FDA/SM/FMS/LAN Redundancy service-name tables -- see ffhse.hpp's file header comment: these
// exact strings and service-id constants are pulled verbatim from packet-ff.c's own
// names_fda_confirmed/names_sm_confirmed/names_sm_unconfirmed/names_fms_confirmed/
// names_fms_unconfirmed/names_lan_confirmed/names_lan_unconfirmed value_string arrays. FDA has no
// separate unconfirmed table in the reference source (FDA's own two services are, per ffhse.hpp,
// "always Confirmed") -- this decoder still names an FDA message by service id alone regardless of
// the wire's own Confirmed flag, since Request/Response is already independently determined by the
// header's own Type field.

std::string fda_service_name(uint8_t sid) {
    switch (sid) {
        case 1: return "FDA Open Session";
        case 3: return "FDA Idle";
        default: return std::string();
    }
}

std::string sm_confirmed_name(uint8_t sid) {
    switch (sid) {
        case 3: return "SM Identify";
        case 12: return "SM Clear Address";
        case 14: return "SM Set Assignment Info";
        case 15: return "SM Clear Assignment Info";
        default: return std::string();
    }
}

std::string sm_unconfirmed_name(uint8_t sid) {
    switch (sid) {
        case 1: return "SM Find Tag Query";
        case 2: return "SM Find Tag Reply";
        case 16: return "SM Device Annunciation";
        default: return std::string();
    }
}

std::string fms_confirmed_name(uint8_t sid) {
    switch (sid) {
        case 0: return "FMS Status";
        case 1: return "FMS Identify";
        case 2: return "FMS Read";
        case 3: return "FMS Write";
        case 4: return "FMS Get OD";
        case 7: return "FMS Define Variable List";
        case 8: return "FMS Delete Variable List";
        case 9: return "FMS Initiate Download Sequence";
        case 10: return "FMS Download Segment";
        case 11: return "FMS Terminate Download Sequence";
        case 12: return "FMS Initiate Upload Sequence";
        case 13: return "FMS Upload Segment";
        case 14: return "FMS Terminate Upload Sequence";
        case 15: return "FMS Request Domain Download";
        case 16: return "FMS Request Domain Upload";
        case 17: return "FMS Create Program Invocation";
        case 18: return "FMS Delete Program Invocation";
        case 19: return "FMS Start";
        case 20: return "FMS Stop";
        case 21: return "FMS Resume";
        case 22: return "FMS Reset";
        case 23: return "FMS Kill";
        case 24: return "FMS Alter Event Condition Monitoring";
        case 25: return "FMS Acknowledge Event Notification";
        case 28: return "FMS Initiate Put OD";
        case 29: return "FMS Put OD";
        case 30: return "FMS Terminate Put OD";
        case 31: return "FMS Generic Initiate Download Sequence";
        case 32: return "FMS Generic Download Segment";
        case 33: return "FMS Generic Terminate Download Sequence";
        case 82: return "FMS Read with Subindex";
        case 83: return "FMS Write with Subindex";
        case 96: return "FMS Initiate";
        default: return std::string();
    }
}

bool fms_confirmed_is_tier1(uint8_t sid) {
    switch (sid) {
        case 0: case 1: case 2: case 3: case 82: case 83: case 96: return true;
        default: return false;
    }
}

std::string fms_unconfirmed_name(uint8_t sid) {
    switch (sid) {
        case 0: return "FMS Information Report";
        case 1: return "FMS Unsolicited Status";
        case 2: return "FMS Event Notification";
        case 16: return "FMS Information Report with Subindex";
        case 17: return "FMS Information Report On Change";
        case 18: return "FMS Information Report On Change with Subindex";
        case 112: return "FMS Abort";
        default: return std::string();
    }
}

std::string lan_confirmed_name(uint8_t sid) {
    switch (sid) {
        case 1: return "LAN Redundancy Get Info";
        case 2: return "LAN Redundancy Put Info";
        case 3: return "LAN Redundancy Get Statistics";
        default: return std::string();
    }
}

std::string lan_unconfirmed_name(uint8_t sid) {
    switch (sid) {
        case 1: return "LAN Redundancy Diagnostic Message";
        default: return std::string();
    }
}

// Best-effort base name for an Error message -- tries the same service-name tables the request/
// response dispatchers use, regardless of Tier 1/Tier 2 (an Error can be returned for a Tier-2
// service just as easily as a Tier-1 one). Returns empty when the (protocol, confirmed, service
// id) combination isn't recognized at all.
std::string service_base_name(const FfhseHeader& h) {
    switch (h.protocol) {
        case 0x04: return fda_service_name(h.service_id);
        case 0x08: return h.confirmed ? sm_confirmed_name(h.service_id) : sm_unconfirmed_name(h.service_id);
        case 0x0c: return h.confirmed ? fms_confirmed_name(h.service_id) : fms_unconfirmed_name(h.service_id);
        case 0x10: return h.confirmed ? lan_confirmed_name(h.service_id) : lan_unconfirmed_name(h.service_id);
        default: return std::string();
    }
}

std::string build_summary(const FfhseFrame& frame) {
    std::ostringstream s;
    s << frame.message_name;
    if (!frame.values.empty()) {
        s << " [" << frame.values.front();
        if (frame.values.size() > 1) s << " +" << (frame.values.size() - 1) << " more";
        s << "]";
    }
    return s.str();
}

// ================================================================================================
// Error body (20 bytes fixed + remainder) -- shared by every _err message. See ffhse.hpp.

bool decode_error_body(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 20)) return false;
    uint8_t error_class = body.at(0);
    uint8_t error_code = body.at(1);
    uint16_t additional_code = be16(body, 2);
    std::string description = trim_trailing_nul(body.subspan(4, 16));
    frame.values.push_back("error-class=" + std::to_string(error_class) + " (" + error_class_name(error_class) +
                            ")");
    frame.values.push_back("error-code=" + std::to_string(error_code) + " (" +
                            error_code_name(error_class, error_code) + ")");
    frame.values.push_back("additional-code=" + std::to_string(additional_code));
    frame.values.push_back("additional-description=\"" + description + "\"");
    set_remainder(frame, body, 20);
    return true;
}

// ================================================================================================
// FDA -- see ffhse.hpp.

// FDA Open Session Req/Rsp -- identical 52-byte shape for both.
bool decode_fda_open_session(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 52)) return false;
    uint32_t session_index = be32(body, 0);
    uint32_t max_buffer_size = be32(body, 4);
    uint32_t max_msg_length = be32(body, 8);
    uint8_t reserved = body.at(12);
    uint8_t nma_use = body.at(13);
    uint16_t inactivity_close_time = be16(body, 14);
    uint32_t transmit_delay_time = be32(body, 16);
    std::string pd_tag = ascii_field(body.subspan(20, 32));

    frame.values.push_back("session-index=" + std::to_string(session_index));
    frame.values.push_back("max-buffer-size=" + std::to_string(max_buffer_size));
    frame.values.push_back("max-msg-length=" + std::to_string(max_msg_length));
    frame.values.push_back("reserved=" + hex8(reserved));
    frame.values.push_back("nma-configuration-use=" + std::to_string(nma_use) + " (" + nma_conf_use_name(nma_use) +
                            ")");
    frame.values.push_back("inactivity-close-time=" + std::to_string(inactivity_close_time));
    frame.values.push_back("transmit-delay-time=" + std::to_string(transmit_delay_time));
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    set_remainder(frame, body, 52);
    return true;
}

void dispatch_fda(const FfhseHeader& h, ByteSpan body, FfhseFrame& frame) {
    std::string base = fda_service_name(h.service_id);
    if (base.empty()) {
        frame.message_name = "FDA service " + std::to_string(h.service_id);
        frame.recognized = false;
        show_whole_body_as_hex(frame, body);
        frame.notes.push_back("FDA service id " + std::to_string(h.service_id) +
                               " is not recognized by this decoder -- shown as raw hex");
        return;
    }
    frame.message_name = base + (h.type == 0 ? " Req" : " Rsp");
    frame.recognized = true;
    bool ok = (h.service_id == 1) ? decode_fda_open_session(body, frame) : require_empty(frame, body);
    finish_tier1(frame, body, ok);
}

// ================================================================================================
// SM -- see ffhse.hpp.

// SM Find Tag Query Req -- 72 bytes fixed + remainder.
bool decode_sm_find_tag_query_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 72)) return false;
    uint8_t query_type = body.at(0);
    uint32_t index = be32(body, 4);
    std::string tag = ascii_field(body.subspan(8, 32));
    std::string vfd_tag = ascii_field(body.subspan(40, 32));

    frame.values.push_back("query-type=" + std::to_string(query_type) + " (" + query_type_name(query_type) + ")");
    frame.values.push_back("index=" + std::to_string(index));
    frame.values.push_back("tag=\"" + tag + "\"");
    frame.values.push_back("vfd-tag=\"" + vfd_tag + "\"");
    set_remainder(frame, body, 72);
    return true;
}

// SM Find Tag Reply Req -- 100 bytes fixed + N*2-byte FDA Address Selector list + remainder.
bool decode_sm_find_tag_reply_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 100)) return false;
    uint8_t query_type = body.at(0);
    uint8_t h1_node_address = body.at(1);
    uint16_t fda_addr_link_id = be16(body, 2);
    uint32_t vfd_reference = be32(body, 4);
    uint32_t od_index = be32(body, 8);
    std::string ip_address = to_hex(body.subspan(12, 16), "");
    uint32_t od_version = be32(body, 28);
    std::string device_id = ascii_field(body.subspan(32, 32));
    std::string pd_tag = ascii_field(body.subspan(64, 32));
    uint8_t dup_state = body.at(96);
    uint32_t n = be16(body, 98);

    frame.values.push_back("query-type=" + std::to_string(query_type) + " (" + query_type_name(query_type) + ")");
    frame.values.push_back("h1-node-address=" + hex8(h1_node_address));
    frame.values.push_back("fda-addr-link-id=" + hex16(fda_addr_link_id));
    frame.values.push_back("vfd-reference=" + std::to_string(vfd_reference));
    frame.values.push_back("od-index=" + std::to_string(od_index));
    frame.values.push_back("ip-address=" + ip_address);
    frame.values.push_back("od-version=" + std::to_string(od_version));
    frame.values.push_back("device-id=\"" + device_id + "\"");
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    frame.values.push_back("dup-detection-state=" + hex8(dup_state));
    for (const auto& f : dup_detection_state_flags(dup_state)) frame.values.push_back("dup-detection-state-flag=" + f);
    frame.values.push_back("num-of-fda-addr-selectors=" + std::to_string(n));

    size_t needed = 100 + 2 * static_cast<size_t>(n);
    if (body.size() < needed) {
        frame.notes.push_back("SM Find Tag Reply Req declares " + std::to_string(n) +
                               " FDA Address Selector(s) needing " + std::to_string(needed) +
                               " total byte(s) but only " + std::to_string(body.size()) +
                               " are available -- selector list truncated");
        n = static_cast<uint32_t>((body.size() - 100) / 2);
    }
    for (uint32_t i = 0; i < n && i < list_cap(); ++i) {
        uint16_t sel = be16(body, 100 + 2 * static_cast<size_t>(i));
        frame.values.push_back("fda-address-selector[" + std::to_string(i) + "]=" + hex16(sel));
    }
    if (n > list_cap()) {
        frame.notes.push_back("only showing " + std::to_string(list_cap()) + " of " + std::to_string(n) +
                               " FDA Address Selector entries (safety cap)");
    }
    set_remainder(frame, body, 100 + 2 * static_cast<size_t>(n));
    return true;
}

// SM Identify Rsp / SM Device Annunciation Req -- identical 108-byte fixed shape + the LinkId-
// branched version-number list -- see ffhse.hpp's own "The LinkId branch" section.
bool decode_sm_identify_like(ByteSpan body, uint16_t link_id, FfhseFrame& frame) {
    if (!require_min(frame, body, 108)) return false;
    uint8_t smk_state = body.at(0);
    uint8_t dev_type = body.at(1);
    uint8_t dev_redundancy_state = body.at(2);
    uint8_t dup_state = body.at(3);
    uint16_t device_index = be16(body, 4);
    uint16_t max_device_index = be16(body, 6);
    std::string op_ip = to_hex(body.subspan(8, 16), "");
    std::string device_id = ascii_field(body.subspan(24, 32));
    std::string pd_tag = ascii_field(body.subspan(56, 32));
    uint32_t hse_repeat_time = be32(body, 88);
    uint16_t lr_port = be16(body, 92);
    uint32_t annunciation_version = be32(body, 96);
    uint32_t hse_device_version = be32(body, 100);
    uint32_t n = be32(body, 104);

    frame.values.push_back("smk-state=" + hex8(smk_state));
    for (const auto& f : smk_state_flags(smk_state)) frame.values.push_back("smk-state-flag=" + f);
    frame.values.push_back("dev-type=" + hex8(dev_type));
    for (const auto& f : dev_type_fields(dev_type)) frame.values.push_back("dev-type." + f);
    frame.values.push_back("dev-redundancy-state=" + hex8(dev_redundancy_state));
    frame.values.push_back("dup-detection-state=" + hex8(dup_state));
    for (const auto& f : dup_detection_state_flags(dup_state)) frame.values.push_back("dup-detection-state-flag=" + f);
    frame.values.push_back("device-index=" + std::to_string(device_index));
    frame.values.push_back("max-device-index=" + std::to_string(max_device_index));
    frame.values.push_back("operational-ip-address=" + op_ip);
    frame.values.push_back("device-id=\"" + device_id + "\"");
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    frame.values.push_back("hse-repeat-time=" + std::to_string(hse_repeat_time));
    frame.values.push_back("lr-port=" + std::to_string(lr_port));
    frame.values.push_back("annunciation-version-number=" + std::to_string(annunciation_version));
    frame.values.push_back("hse-device-version-number=" + std::to_string(hse_device_version));
    frame.values.push_back("num-of-entries-in-ver-num-list=" + std::to_string(n));

    size_t needed = 108 + 4 * static_cast<size_t>(n);
    if (body.size() < needed) {
        frame.notes.push_back(frame.message_name + " declares " + std::to_string(n) +
                               " version-number-list entry(ies) needing " + std::to_string(needed) +
                               " total byte(s) but only " + std::to_string(body.size()) +
                               " are available -- list truncated");
        n = static_cast<uint32_t>((body.size() - 108) / 4);
    }
    frame.notes.push_back("LinkId (this PDU's own header FDA Address, upper 16 bits) = " + hex16(link_id) +
                           (link_id != 0
                                ? " -- version-number-list decoded as H1NodeAddress+VersionNumber pairs (2 per entry)"
                                : " -- version-number-list decoded as H1LinkId+Reserved+VersionNumber quads"));
    for (uint32_t i = 0; i < n && i < list_cap(); ++i) {
        size_t off = 108 + 4 * static_cast<size_t>(i);
        if (link_id != 0) {
            uint8_t node_a = body.at(off), ver_a = body.at(off + 1);
            uint8_t node_b = body.at(off + 2), ver_b = body.at(off + 3);
            frame.values.push_back("version-number-list[" + std::to_string(i) +
                                    "].a=h1-node-address=" + hex8(node_a) + " version=" + std::to_string(ver_a));
            frame.values.push_back("version-number-list[" + std::to_string(i) +
                                    "].b=h1-node-address=" + hex8(node_b) + " version=" + std::to_string(ver_b));
        } else {
            uint16_t h1_link_id = be16(body, off);
            uint8_t ver = body.at(off + 3);
            frame.values.push_back("version-number-list[" + std::to_string(i) + "]=h1-link-id=" + hex16(h1_link_id) +
                                    " version=" + std::to_string(ver));
        }
    }
    if (n > list_cap()) {
        frame.notes.push_back("only showing " + std::to_string(list_cap()) + " of " + std::to_string(n) +
                               " version-number-list entries (safety cap)");
    }
    set_remainder(frame, body, 108 + 4 * static_cast<size_t>(n));
    return true;
}

// SM Clear Address Req -- 68 bytes fixed + remainder.
bool decode_sm_clear_address_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 68)) return false;
    std::string device_id = ascii_field(body.subspan(0, 32));
    std::string pd_tag = ascii_field(body.subspan(32, 32));
    uint8_t iface = body.at(64);
    frame.values.push_back("device-id=\"" + device_id + "\"");
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    frame.values.push_back("interface-to-clear=" + hex8(iface));
    set_remainder(frame, body, 68);
    return true;
}

// SM Set Assignment Info Req -- 96 bytes fixed + remainder.
bool decode_sm_set_assignment_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 96)) return false;
    std::string device_id = ascii_field(body.subspan(0, 32));
    std::string pd_tag = ascii_field(body.subspan(32, 32));
    uint8_t h1_new_address = body.at(64);
    uint8_t dev_redundancy_state = body.at(65);
    uint16_t lr_port = be16(body, 66);
    uint32_t hse_repeat_time = be32(body, 68);
    uint16_t device_index = be16(body, 72);
    uint16_t max_device_index = be16(body, 74);
    std::string op_ip = to_hex(body.subspan(76, 16), "");
    uint8_t clear_dup_detection_state = body.at(95);

    frame.values.push_back("device-id=\"" + device_id + "\"");
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    frame.values.push_back("h1-new-address=" + hex8(h1_new_address));
    frame.values.push_back("dev-redundancy-state=" + hex8(dev_redundancy_state));
    frame.values.push_back("lr-port=" + std::to_string(lr_port));
    frame.values.push_back("hse-repeat-time=" + std::to_string(hse_repeat_time));
    frame.values.push_back("device-index=" + std::to_string(device_index));
    frame.values.push_back("max-device-index=" + std::to_string(max_device_index));
    frame.values.push_back("operational-ip-address=" + op_ip);
    frame.values.push_back("clear-dup-detection-state=" + hex8(clear_dup_detection_state));
    for (const auto& f : dup_detection_state_flags(clear_dup_detection_state))
        frame.values.push_back("clear-dup-detection-state-flag=" + f);
    set_remainder(frame, body, 96);
    return true;
}

// SM Set Assignment Info Rsp -- 8 bytes fixed + remainder.
bool decode_sm_set_assignment_rsp(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 8)) return false;
    uint16_t max_device_index = be16(body, 2);
    uint32_t hse_repeat_time = be32(body, 4);
    frame.values.push_back("max-device-index=" + std::to_string(max_device_index));
    frame.values.push_back("hse-repeat-time=" + std::to_string(hse_repeat_time));
    set_remainder(frame, body, 8);
    return true;
}

// SM Clear Assignment Info Req -- 64 bytes fixed + remainder.
bool decode_sm_clear_assignment_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 64)) return false;
    std::string device_id = ascii_field(body.subspan(0, 32));
    std::string pd_tag = ascii_field(body.subspan(32, 32));
    frame.values.push_back("device-id=\"" + device_id + "\"");
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    set_remainder(frame, body, 64);
    return true;
}

void dispatch_sm(const FfhseHeader& h, ByteSpan body, FfhseFrame& frame) {
    if (!h.confirmed) {
        std::string base = sm_unconfirmed_name(h.service_id);
        if (base.empty()) {
            frame.message_name = "SM unconfirmed service " + std::to_string(h.service_id);
            frame.recognized = false;
            show_whole_body_as_hex(frame, body);
            frame.notes.push_back("SM unconfirmed service id " + std::to_string(h.service_id) +
                                   " is not recognized by this decoder -- shown as raw hex");
            return;
        }
        frame.message_name = base + " Req";
        frame.recognized = true;
        bool ok = false;
        switch (h.service_id) {
            case 1: ok = decode_sm_find_tag_query_req(body, frame); break;
            case 2: ok = decode_sm_find_tag_reply_req(body, frame); break;
            case 16: ok = decode_sm_identify_like(body, h.link_id, frame); break;
            default: break;  // unreachable -- base non-empty already means one of the above
        }
        finish_tier1(frame, body, ok);
        return;
    }

    std::string base = sm_confirmed_name(h.service_id);
    if (base.empty()) {
        frame.message_name = "SM confirmed service " + std::to_string(h.service_id);
        frame.recognized = false;
        show_whole_body_as_hex(frame, body);
        frame.notes.push_back("SM confirmed service id " + std::to_string(h.service_id) +
                               " is not recognized by this decoder -- shown as raw hex");
        return;
    }
    frame.message_name = base + (h.type == 0 ? " Req" : " Rsp");
    frame.recognized = true;
    bool ok = false;
    switch (h.service_id) {
        case 3:  // Identify
            ok = (h.type == 0) ? require_empty(frame, body) : decode_sm_identify_like(body, h.link_id, frame);
            break;
        case 12:  // Clear Address
            ok = (h.type == 0) ? decode_sm_clear_address_req(body, frame) : require_empty(frame, body);
            break;
        case 14:  // Set Assignment Info
            ok = (h.type == 0) ? decode_sm_set_assignment_req(body, frame) : decode_sm_set_assignment_rsp(body, frame);
            break;
        case 15:  // Clear Assignment Info
            ok = (h.type == 0) ? decode_sm_clear_assignment_req(body, frame) : require_empty(frame, body);
            break;
        default: break;  // unreachable
    }
    finish_tier1(frame, body, ok);
}

// ================================================================================================
// FMS -- see ffhse.hpp.

// FMS Initiate Req -- 40 bytes fixed + remainder.
bool decode_fms_initiate_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 40)) return false;
    uint8_t connect_option = body.at(0);
    uint8_t access_protection = body.at(1);
    uint16_t passwd_and_access_grps = be16(body, 2);
    uint16_t ver_od_calling = be16(body, 4);
    uint16_t prof_num_calling = be16(body, 6);
    std::string pd_tag = ascii_field(body.subspan(8, 32));

    frame.values.push_back("connect-option=" + std::to_string(connect_option) + " (" +
                            conn_opt_name(connect_option) + ")");
    frame.values.push_back("access-protection-supported-calling=" + hex8(access_protection));
    frame.values.push_back("passwd-and-access-grps-calling=" + hex16(passwd_and_access_grps));
    frame.values.push_back("ver-od-calling=" + std::to_string(ver_od_calling));
    frame.values.push_back("prof-num-calling=" + std::to_string(prof_num_calling));
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    set_remainder(frame, body, 40);
    return true;
}

// FMS Initiate Rsp -- 4 bytes fixed + remainder.
bool decode_fms_initiate_rsp(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 4)) return false;
    uint16_t ver_od_called = be16(body, 0);
    uint16_t prof_num_called = be16(body, 2);
    frame.values.push_back("ver-od-called=" + std::to_string(ver_od_called));
    frame.values.push_back("prof-num-called=" + std::to_string(prof_num_called));
    set_remainder(frame, body, 4);
    return true;
}

// FMS Abort Req -- 20 bytes fixed + remainder.
bool decode_fms_abort_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 20)) return false;
    std::string detail = to_hex(body.subspan(0, 16), "");
    uint8_t abort_id = body.at(16);
    uint8_t reason_code = body.at(17);
    frame.values.push_back("abort-detail=" + detail);
    frame.values.push_back("abort-id=" + hex8(abort_id));
    frame.values.push_back("reason-code=" + hex8(reason_code));
    set_remainder(frame, body, 20);
    return true;
}

// FMS Status Rsp / FMS Unsolicited Status Req -- identical 8-byte shape.
bool decode_fms_status_shape(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 8)) return false;
    uint8_t logical_status = body.at(0);
    uint8_t physical_status = body.at(1);
    uint32_t local_detail = be32(body, 4);
    frame.values.push_back("logical-status=" + hex8(logical_status));
    frame.values.push_back("physical-status=" + hex8(physical_status));
    frame.values.push_back("local-detail=" + std::to_string(local_detail));
    set_remainder(frame, body, 8);
    return true;
}

// FMS Identify Rsp -- 96 bytes fixed + remainder.
bool decode_fms_identify_rsp(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 96)) return false;
    std::string vendor_name = ascii_field(body.subspan(0, 32));
    std::string model_name = ascii_field(body.subspan(32, 32));
    std::string revision = ascii_field(body.subspan(64, 32));
    frame.values.push_back("vendor-name=\"" + vendor_name + "\"");
    frame.values.push_back("model-name=\"" + model_name + "\"");
    frame.values.push_back("revision=\"" + revision + "\"");
    set_remainder(frame, body, 96);
    return true;
}

// FMS Read Req -- 4 bytes fixed + remainder.
bool decode_fms_read_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 4)) return false;
    uint32_t index = be32(body, 0);
    frame.values.push_back("index=" + std::to_string(index));
    set_remainder(frame, body, 4);
    return true;
}

// FMS Read with Subindex Req -- 8 bytes fixed + remainder.
bool decode_fms_read_with_subindex_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 8)) return false;
    uint32_t index = be32(body, 0);
    uint32_t subindex = be32(body, 4);
    frame.values.push_back("index=" + std::to_string(index));
    frame.values.push_back("subindex=" + std::to_string(subindex));
    set_remainder(frame, body, 8);
    return true;
}

// FMS Read/Read with Subindex Rsp -- the ENTIRE body is deliberately left raw -- see ffhse.hpp's
// own Tier-1/Tier-2 split paragraph (no self-describing wire type without external Object
// Dictionary context). Always returns false so the caller's own finish_tier1 renders it as raw hex
// uniformly -- this function only contributes the explanatory note.
bool decode_fms_value_response_raw(FfhseFrame& frame) {
    frame.notes.push_back(
        frame.message_name +
        "'s returned value has no self-describing wire type without external Object Dictionary context -- "
        "deliberately shown as raw hex, not value-decoded (same scope limit this project's EtherNet/IP CIP "
        "I/O and S7comm-Plus decoders already take for analogous opaque values)");
    return false;
}

// FMS Write Req -- Index(4) + Data(raw, rest). Data's own rawness is inherent (no self-describing
// wire type), NOT a shape mismatch -- Index is still genuinely decoded, so this returns true.
bool decode_fms_write_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 4)) return false;
    uint32_t index = be32(body, 0);
    frame.values.push_back("index=" + std::to_string(index));
    ByteSpan data = body.from(4);
    frame.body_length = data.size();
    if (!data.empty()) {
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(data, "");
        frame.notes.push_back(
            "Write Data has no self-describing wire type without external Object Dictionary context -- shown "
            "as raw hex, not value-decoded");
    }
    return true;
}

// FMS Write with Subindex Req -- Index(4) + Subindex(4) + Data(raw, rest).
bool decode_fms_write_with_subindex_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 8)) return false;
    uint32_t index = be32(body, 0);
    uint32_t subindex = be32(body, 4);
    frame.values.push_back("index=" + std::to_string(index));
    frame.values.push_back("subindex=" + std::to_string(subindex));
    ByteSpan data = body.from(8);
    frame.body_length = data.size();
    if (!data.empty()) {
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(data, "");
        frame.notes.push_back(
            "Write Data has no self-describing wire type without external Object Dictionary context -- shown "
            "as raw hex, not value-decoded");
    }
    return true;
}

// FMS Information Report (Req, Unconfirmed) / Information Report On Change (Req, Unconfirmed) --
// identical shape: Index(4) + Data(raw, rest).
bool decode_fms_index_data(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 4)) return false;
    uint32_t index = be32(body, 0);
    frame.values.push_back("index=" + std::to_string(index));
    ByteSpan data = body.from(4);
    frame.body_length = data.size();
    if (!data.empty()) {
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(data, "");
    }
    return true;
}

// FMS Information Report with Subindex / On Change with Subindex (both Req, Unconfirmed) --
// identical shape: Index(4) + Subindex(4) + Data(raw, rest).
bool decode_fms_index_subindex_data(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 8)) return false;
    uint32_t index = be32(body, 0);
    uint32_t subindex = be32(body, 4);
    frame.values.push_back("index=" + std::to_string(index));
    frame.values.push_back("subindex=" + std::to_string(subindex));
    ByteSpan data = body.from(8);
    frame.body_length = data.size();
    if (!data.empty()) {
        frame.body_shown_as_hex = true;
        frame.body_hex = to_hex(data, "");
    }
    return true;
}

void dispatch_fms(const FfhseHeader& h, ByteSpan body, FfhseFrame& frame) {
    if (!h.confirmed) {
        std::string base = fms_unconfirmed_name(h.service_id);
        if (base.empty()) {
            frame.message_name = "FMS unconfirmed service " + std::to_string(h.service_id);
            frame.recognized = false;
            show_whole_body_as_hex(frame, body);
            frame.notes.push_back("FMS unconfirmed service id " + std::to_string(h.service_id) +
                                   " is not recognized by this decoder -- shown as raw hex");
            return;
        }
        frame.message_name = base + " Req";
        frame.recognized = true;
        if (h.service_id == 2) {  // Event Notification -- Tier 2
            show_whole_body_as_hex(frame, body);
            frame.notes.push_back("this decoder does not further decode message " + base + " -- shown as raw hex");
            return;
        }
        bool ok = false;
        switch (h.service_id) {
            case 0: ok = decode_fms_index_data(body, frame); break;               // Information Report
            case 1: ok = decode_fms_status_shape(body, frame); break;             // Unsolicited Status
            case 16: ok = decode_fms_index_subindex_data(body, frame); break;     // ...with Subindex
            case 17: ok = decode_fms_index_data(body, frame); break;              // ...On Change
            case 18: ok = decode_fms_index_subindex_data(body, frame); break;     // ...On Change w/Subindex
            case 112: ok = decode_fms_abort_req(body, frame); break;              // Abort
            default: break;  // unreachable
        }
        finish_tier1(frame, body, ok);
        return;
    }

    std::string base = fms_confirmed_name(h.service_id);
    if (base.empty()) {
        frame.message_name = "FMS confirmed service " + std::to_string(h.service_id);
        frame.recognized = false;
        show_whole_body_as_hex(frame, body);
        frame.notes.push_back("FMS confirmed service id " + std::to_string(h.service_id) +
                               " is not recognized by this decoder -- shown as raw hex");
        return;
    }
    frame.message_name = base + (h.type == 0 ? " Req" : " Rsp");
    frame.recognized = true;

    if (!fms_confirmed_is_tier1(h.service_id)) {
        show_whole_body_as_hex(frame, body);
        std::string note = "this decoder does not further decode message " + base + " -- shown as raw hex";
        if (h.service_id == 4) {
            note += " (even the reference Wireshark dissector leaves FMS Get OD entries undecoded -- no Object "
                    "Dictionary context is available to interpret them)";
        }
        frame.notes.push_back(note);
        return;
    }

    bool ok = false;
    switch (h.service_id) {
        case 0:  // Status
            ok = (h.type == 0) ? require_empty(frame, body) : decode_fms_status_shape(body, frame);
            break;
        case 1:  // Identify
            ok = (h.type == 0) ? require_empty(frame, body) : decode_fms_identify_rsp(body, frame);
            break;
        case 2:  // Read
            ok = (h.type == 0) ? decode_fms_read_req(body, frame) : decode_fms_value_response_raw(frame);
            break;
        case 3:  // Write
            ok = (h.type == 0) ? decode_fms_write_req(body, frame) : require_empty(frame, body);
            break;
        case 82:  // Read with Subindex
            ok = (h.type == 0) ? decode_fms_read_with_subindex_req(body, frame) : decode_fms_value_response_raw(frame);
            break;
        case 83:  // Write with Subindex
            ok = (h.type == 0) ? decode_fms_write_with_subindex_req(body, frame) : require_empty(frame, body);
            break;
        case 96:  // Initiate
            ok = (h.type == 0) ? decode_fms_initiate_req(body, frame) : decode_fms_initiate_rsp(body, frame);
            break;
        default: break;  // unreachable
    }
    finish_tier1(frame, body, ok);
}

// ================================================================================================
// LAN Redundancy -- see ffhse.hpp.

// LAN Get Info Rsp / LAN Put Info Req/Rsp -- identical 80-byte fixed shape + remainder.
bool decode_lan_info(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 80)) return false;
    uint32_t lr_attrs_version = be32(body, 0);
    uint8_t max_msg_num_diff = body.at(4);
    uint8_t lr_flags = body.at(5);
    uint32_t diag_msg_interval = be32(body, 8);
    uint32_t aging_time = be32(body, 12);
    std::string a_send = to_hex(body.subspan(16, 16), "");
    std::string a_recv = to_hex(body.subspan(32, 16), "");
    std::string b_send = to_hex(body.subspan(48, 16), "");
    std::string b_recv = to_hex(body.subspan(64, 16), "");

    frame.values.push_back("lr-attrs-version=" + std::to_string(lr_attrs_version));
    if (max_msg_num_diff <= 1) {
        frame.values.push_back("max-msg-num-diff=" + std::to_string(max_msg_num_diff) + " (Do not detect a fault)");
    } else {
        frame.values.push_back("max-msg-num-diff=" + std::to_string(max_msg_num_diff));
    }
    frame.values.push_back("lr-flags=" + hex8(lr_flags));
    for (const auto& f : lr_flags_names(lr_flags)) frame.values.push_back("lr-flags-flag=" + f);
    frame.values.push_back("diagnostic-msg-interval=" + std::to_string(diag_msg_interval));
    frame.values.push_back("aging-time=" + std::to_string(aging_time));
    frame.values.push_back("diag-msg-if-a-send-addr=" + a_send);
    frame.values.push_back("diag-msg-if-a-recv-addr=" + a_recv);
    frame.values.push_back("diag-msg-if-b-send-addr=" + b_send);
    frame.values.push_back("diag-msg-if-b-recv-addr=" + b_recv);
    set_remainder(frame, body, 80);
    return true;
}

// LAN Get Statistics Rsp -- 28 bytes fixed + N*4-byte XCableStat list + remainder.
bool decode_lan_get_statistics_rsp(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 28)) return false;
    uint32_t recv_a = be32(body, 0);
    uint32_t miss_a = be32(body, 4);
    uint32_t fault_a = be32(body, 8);
    uint32_t recv_b = be32(body, 12);
    uint32_t miss_b = be32(body, 16);
    uint32_t fault_b = be32(body, 20);
    uint32_t n = be32(body, 24);

    frame.values.push_back("num-diag-svr-ind-recv-a=" + std::to_string(recv_a));
    frame.values.push_back("num-diag-svr-ind-miss-a=" + std::to_string(miss_a));
    frame.values.push_back("num-rem-dev-diag-recv-fault-a=" + std::to_string(fault_a));
    frame.values.push_back("num-diag-svr-ind-recv-b=" + std::to_string(recv_b));
    frame.values.push_back("num-diag-svr-ind-miss-b=" + std::to_string(miss_b));
    frame.values.push_back("num-rem-dev-diag-recv-fault-b=" + std::to_string(fault_b));
    frame.values.push_back("num-x-cable-stat=" + std::to_string(n));

    size_t needed = 28 + 4 * static_cast<size_t>(n);
    if (body.size() < needed) {
        frame.notes.push_back("LAN Redundancy Get Statistics Rsp declares " + std::to_string(n) +
                               " XCableStat entry(ies) needing " + std::to_string(needed) +
                               " total byte(s) but only " + std::to_string(body.size()) +
                               " are available -- list truncated");
        n = static_cast<uint32_t>((body.size() - 28) / 4);
    }
    for (uint32_t i = 0; i < n && i < list_cap(); ++i) {
        uint32_t v = be32(body, 28 + 4 * static_cast<size_t>(i));
        frame.values.push_back("x-cable-stat[" + std::to_string(i) + "]=" + std::to_string(v));
    }
    if (n > list_cap()) {
        frame.notes.push_back("only showing " + std::to_string(list_cap()) + " of " + std::to_string(n) +
                               " XCableStat entries (safety cap)");
    }
    set_remainder(frame, body, 28 + 4 * static_cast<size_t>(n));
    return true;
}

// LAN Diagnostic Message Req (Unconfirmed) -- 44 bytes fixed + 4 parallel N*4-byte interface-
// status lists (A-to-A, B-to-A, A-to-B, B-to-B, in that order) + remainder.
bool decode_lan_diagnostic_req(ByteSpan body, FfhseFrame& frame) {
    if (!require_min(frame, body, 44)) return false;
    uint16_t device_index = be16(body, 0);
    uint8_t num_if = body.at(2);
    uint8_t trans_if = body.at(3);
    uint32_t diag_msg_interval = be32(body, 4);
    std::string pd_tag = ascii_field(body.subspan(8, 32));
    uint8_t dup_state = body.at(41);
    uint32_t n = be16(body, 42);

    if (device_index == 0) {
        frame.values.push_back("device-index=0 (Index not assigned)");
    } else {
        frame.values.push_back("device-index=" + std::to_string(device_index));
    }
    frame.values.push_back("num-of-network-interfaces=" + std::to_string(num_if));
    frame.values.push_back("transmission-interface=" + std::to_string(trans_if) + " (" +
                            transmission_interface_name(trans_if) + ")");
    frame.values.push_back("diagnostic-msg-interval=" + std::to_string(diag_msg_interval));
    frame.values.push_back("pd-tag=\"" + pd_tag + "\"");
    frame.values.push_back("dup-detection-state=" + hex8(dup_state));
    for (const auto& f : dup_detection_state_flags(dup_state)) frame.values.push_back("dup-detection-state-flag=" + f);
    frame.values.push_back("num-of-interface-statuses=" + std::to_string(n));

    size_t needed = 44 + 16 * static_cast<size_t>(n);
    if (body.size() < needed) {
        frame.notes.push_back("LAN Redundancy Diagnostic Message Req declares " + std::to_string(n) +
                               " interface-status entry(ies) needing " + std::to_string(needed) +
                               " total byte(s) but only " + std::to_string(body.size()) +
                               " are available -- interface-status lists truncated");
        n = static_cast<uint32_t>((body.size() - 44) / 16);
    }
    for (uint32_t i = 0; i < n && i < list_cap(); ++i) {
        uint32_t a_to_a = be32(body, 44 + 4 * static_cast<size_t>(i));
        uint32_t b_to_a = be32(body, 44 + 4 * static_cast<size_t>(n) + 4 * static_cast<size_t>(i));
        uint32_t a_to_b = be32(body, 44 + 8 * static_cast<size_t>(n) + 4 * static_cast<size_t>(i));
        uint32_t b_to_b = be32(body, 44 + 12 * static_cast<size_t>(n) + 4 * static_cast<size_t>(i));
        frame.values.push_back("if-a-to-a-status[" + std::to_string(i) + "]=" + std::to_string(a_to_a));
        frame.values.push_back("if-b-to-a-status[" + std::to_string(i) + "]=" + std::to_string(b_to_a));
        frame.values.push_back("if-a-to-b-status[" + std::to_string(i) + "]=" + std::to_string(a_to_b));
        frame.values.push_back("if-b-to-b-status[" + std::to_string(i) + "]=" + std::to_string(b_to_b));
    }
    if (n > list_cap()) {
        frame.notes.push_back("only showing " + std::to_string(list_cap()) + " of " + std::to_string(n) +
                               " interface-status entries per list (safety cap)");
    }
    set_remainder(frame, body, 44 + 16 * static_cast<size_t>(n));
    return true;
}

void dispatch_lan(const FfhseHeader& h, ByteSpan body, FfhseFrame& frame) {
    if (!h.confirmed) {
        if (h.service_id == 1) {
            frame.message_name = "LAN Redundancy Diagnostic Message Req";
            frame.recognized = true;
            finish_tier1(frame, body, decode_lan_diagnostic_req(body, frame));
        } else {
            frame.message_name = "LAN Redundancy unconfirmed service " + std::to_string(h.service_id);
            frame.recognized = false;
            show_whole_body_as_hex(frame, body);
            frame.notes.push_back("LAN Redundancy unconfirmed service id " + std::to_string(h.service_id) +
                                   " is not recognized by this decoder -- shown as raw hex");
        }
        return;
    }

    std::string base = lan_confirmed_name(h.service_id);
    if (base.empty()) {
        frame.message_name = "LAN Redundancy confirmed service " + std::to_string(h.service_id);
        frame.recognized = false;
        show_whole_body_as_hex(frame, body);
        frame.notes.push_back("LAN Redundancy confirmed service id " + std::to_string(h.service_id) +
                               " is not recognized by this decoder -- shown as raw hex");
        return;
    }
    frame.message_name = base + (h.type == 0 ? " Req" : " Rsp");
    frame.recognized = true;
    bool ok = false;
    switch (h.service_id) {
        case 1:  // Get Info
            ok = (h.type == 0) ? require_empty(frame, body) : decode_lan_info(body, frame);
            break;
        case 2:  // Put Info -- identical shape both directions
            ok = decode_lan_info(body, frame);
            break;
        case 3:  // Get Statistics
            ok = (h.type == 0) ? require_empty(frame, body) : decode_lan_get_statistics_rsp(body, frame);
            break;
        default: break;  // unreachable
    }
    finish_tier1(frame, body, ok);
}

}  // namespace

// ================================================================================================
// Public entry points.

std::optional<size_t> ffhse_declared_length(ByteSpan payload) {
    if (payload.size() < 12) return std::nullopt;
    uint8_t protocol_and_type = payload.at(2);
    uint8_t protocol = static_cast<uint8_t>(protocol_and_type & 0xfc);
    uint8_t type = static_cast<uint8_t>(protocol_and_type & 0x03);
    if (protocol != 0x04 && protocol != 0x08 && protocol != 0x0c && protocol != 0x10) return std::nullopt;
    if (type > 2) return std::nullopt;
    uint32_t message_length = be32(payload, 8);
    if (message_length < 12) return std::nullopt;
    // See max_plausible_message_length()'s own comment above (top of this anonymous namespace) for why
    // this ceiling exists and why try_parse_ffhse below now applies it too.
    if (message_length > max_plausible_message_length()) return std::nullopt;
    return static_cast<size_t>(message_length);
}

std::optional<FfhseFrame> try_parse_ffhse(ByteSpan payload) {
    if (payload.size() < 12) return std::nullopt;
    try {
        uint8_t protocol_and_type = payload.at(2);
        uint8_t protocol = static_cast<uint8_t>(protocol_and_type & 0xfc);
        uint8_t type = static_cast<uint8_t>(protocol_and_type & 0x03);
        if (protocol != 0x04 && protocol != 0x08 && protocol != 0x0c && protocol != 0x10) return std::nullopt;
        if (type > 2) return std::nullopt;
        uint32_t message_length = be32(payload, 8);
        if (message_length < 12) return std::nullopt;
        // Structural-detection plausibility ceiling -- see max_plausible_message_length()'s own comment
        // above. Without this, an implausible Message Length (essentially random noise on a
        // non-FF-HSE payload that happened to match the weak ProtocolAndType byte gate) would still
        // be "detected" as FF-HSE and produce a nonsensical, confusing truncation report instead of
        // correctly falling through to another protocol / the generic udp/non-tcp fallback.
        if (message_length > max_plausible_message_length()) return std::nullopt;

        FfhseFrame frame;
        FfhseHeader& h = frame.header;
        h.version = payload.at(0);
        h.options = payload.at(1);
        h.opt_message_number = (h.options & 0x80) != 0;
        h.opt_invoke_id = (h.options & 0x40) != 0;
        h.opt_time_stamp = (h.options & 0x20) != 0;
        h.opt_extended_control_field = (h.options & 0x08) != 0;
        h.pad_length = static_cast<uint8_t>(h.options & 0x07);
        h.protocol_and_type = protocol_and_type;
        h.protocol = protocol;
        h.protocol_name = protocol_name(protocol);
        h.type = type;
        h.type_name = type_name(type);
        h.service = payload.at(3);
        h.confirmed = (h.service & 0x80) != 0;
        h.service_id = static_cast<uint8_t>(h.service & 0x7f);
        h.fda_address = be32(payload, 4);
        h.link_id = static_cast<uint16_t>(h.fda_address >> 16);
        h.message_length = message_length;

        size_t available = payload.size();
        size_t pdu_end = std::min(static_cast<size_t>(message_length), available);
        if (static_cast<size_t>(message_length) > available) {
            frame.notes.push_back("FF-HSE message declares Message Length " + std::to_string(message_length) +
                                   " but only " + std::to_string(available) + " byte(s) are available -- truncated");
        }
        frame.wire_length = pdu_end;

        // Length accounting -- see ffhse.hpp's own "Length accounting" paragraph. Worked in a
        // signed accumulator so a Message Length too small to even cover its own header plus the
        // trailer fields its Options byte declares is caught and clamped, never underflowed.
        int64_t remaining = static_cast<int64_t>(message_length);
        size_t trailer_len = 0;
        if (h.opt_message_number) { remaining -= 4; trailer_len += 4; }
        if (h.opt_invoke_id) { remaining -= 4; trailer_len += 4; }
        if (h.opt_time_stamp) { remaining -= 8; trailer_len += 8; }
        if (h.opt_extended_control_field) { remaining -= 4; trailer_len += 4; }
        remaining -= 12;

        size_t body_length;
        if (remaining < 0) {
            frame.notes.push_back(
                "FF-HSE Message Length (" + std::to_string(message_length) +
                ") is too small to cover its own 12-byte header plus the trailer field(s) its Options byte "
                "declares (" +
                std::to_string(trailer_len) + " byte(s)) -- body length treated as 0");
            body_length = 0;
        } else {
            body_length = static_cast<size_t>(remaining);
        }

        // Clamp against what's actually available in this payload, not just what the header
        // claims -- a truncated capture must never be read past what's really there.
        size_t body_and_trailer_avail = pdu_end > 12 ? pdu_end - 12 : 0;
        if (body_length + trailer_len > body_and_trailer_avail) {
            size_t deficit = (body_length + trailer_len) - body_and_trailer_avail;
            frame.notes.push_back("FF-HSE body+trailer (" + std::to_string(body_length + trailer_len) +
                                   " byte(s), from Message Length/Options) exceeds the " +
                                   std::to_string(body_and_trailer_avail) +
                                   " byte(s) actually available in this PDU -- truncated by " +
                                   std::to_string(deficit) + " byte(s)");
            if (trailer_len > body_and_trailer_avail) {
                trailer_len = body_and_trailer_avail;
                body_length = 0;
            } else {
                body_length = body_and_trailer_avail - trailer_len;
            }
        }

        ByteSpan body = payload.subspan(12, body_length);
        size_t trailer_offset = 12 + body_length;
        ByteSpan trailer_bytes = payload.subspan(trailer_offset, trailer_len);

        FfhseTrailer& tr = frame.trailer;
        size_t toff = 0;
        if (h.opt_message_number && toff + 4 <= trailer_bytes.size()) {
            tr.has_message_number = true;
            tr.message_number = be32(trailer_bytes, toff);
            toff += 4;
        }
        if (h.opt_invoke_id && toff + 4 <= trailer_bytes.size()) {
            tr.has_invoke_id = true;
            tr.invoke_id = be32(trailer_bytes, toff);
            toff += 4;
        }
        if (h.opt_time_stamp && toff + 8 <= trailer_bytes.size()) {
            tr.has_time_stamp = true;
            tr.time_stamp = be64(trailer_bytes, toff);
            toff += 8;
        }
        if (h.opt_extended_control_field && toff + 4 <= trailer_bytes.size()) {
            tr.has_extended_control_field = true;
            tr.extended_control_field = be32(trailer_bytes, toff);
            toff += 4;
        }

        if (h.type == 2) {  // Error -- generic across every sub-protocol/service.
            std::string base = service_base_name(h);
            frame.message_name =
                base.empty() ? (h.protocol_name + " service " + std::to_string(h.service_id) + " Err") : (base + " Err");
            frame.recognized = true;
            finish_tier1(frame, body, decode_error_body(body, frame));
        } else {
            switch (h.protocol) {
                case 0x04: dispatch_fda(h, body, frame); break;
                case 0x08: dispatch_sm(h, body, frame); break;
                case 0x0c: dispatch_fms(h, body, frame); break;
                case 0x10: dispatch_lan(h, body, frame); break;
                default: break;  // unreachable -- protocol already validated above
            }
        }

        frame.summary = build_summary(frame);
        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check (require_min/require_empty/the
        // length-accounting clamp above), so this should be unreachable -- caught defensively
        // anyway, the same belt-and-suspenders posture this codebase's other decoders all take.
        return std::nullopt;
    }
}

std::optional<ProtocolResult> FfhseTcpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_ffhse(payload);
    if (!frame) return std::nullopt;

    FfhseResult result;
    result.summary = frame->summary;
    for (const auto& n : frame->notes) result.notes.push_back(n);
    result.first = *frame;

    // Like HART-IP's/EtherNet/IP's own small messages, it's normal for a sender or the OS to
    // coalesce several FF-HSE PDUs into one TCP segment before flushing -- exact transplant of
    // the legacy `if (want_ffhse)` TCP call site's own coalescing loop.
    const size_t kMaxFfhseMessagesPerPayload = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = frame->wire_length;
    size_t message_count = 1;
    while (offset < payload.size() && message_count < kMaxFfhseMessagesPerPayload) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_ffhse(rest);
        if (!next) break;  // remaining bytes aren't another FF-HSE PDU -- stop, don't guess
        ++message_count;
        std::string note = "additional FF-HSE PDU " + std::to_string(message_count) +
                            " found in the same TCP payload at byte offset " + std::to_string(offset) +
                            " (coalesced by the sender/OS): " + next->summary;
        result.notes.push_back(note);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
    }
    if (message_count >= kMaxFfhseMessagesPerPayload) {
        result.notes.push_back("stopped after " + std::to_string(kMaxFfhseMessagesPerPayload) +
                                " FF-HSE PDU(s) in this one TCP payload, more may remain (safety cap)");
    }

    return ProtocolResult::make<FfhseResult>("ffhse", std::move(result));
}

std::optional<ProtocolResult> FfhseUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_ffhse(payload);
    if (!frame) return std::nullopt;
    // Matches the reference dissector's own dissect_ff_udp() exactly: "/* Make sure the length
    // field is valid */ if ((length > tvb_reported_length_remaining(tvb, offset)) || ...) break;"
    // -- a UDP datagram is delivered whole; unlike TCP (see ffhse_declared_length/
    // tcp_declared_length, which legitimately drives this codebase's own stream-reassembly "wait
    // for more" buffering before decode() is even called), there is no reassembly at this layer,
    // so a PDU whose own declared Message Length exceeds the bytes actually present in THIS
    // datagram can never really be "still arriving" the way a TCP PDU legitimately can -- it's
    // structurally implausible on its face, not a truncated-but-real message. try_parse_ffhse
    // itself still accepts it (with a "declares more than available" note, for the TCP call site
    // above, where that note DOES describe a real, if unusual, state), so this decoder-specific
    // check is what actually declines it here, exactly as the reference dissector's own `break`
    // does.
    //
    // Real bug found via a user-submitted capture: a real-time UDP flow's essentially-random
    // bytes (an incrementing per-packet counter byte landing squarely on ffhse's own Service
    // field, hence the false "FMS unconfirmed service 83/84/85/..." sequence, one higher every
    // packet) matched this decoder's weak header gate, with a Message Length (20748) two orders
    // of magnitude past every one of dozens of actual datagram sizes (47-291 bytes) -- previously
    // "explained" as truncated instead of rejected. Same false-positive class
    // kMaxPlausibleMessageLength was added for (see its own comment above), just caught via
    // message-length-vs-actual-payload-size rather than an absolute ceiling: 20748 is comfortably
    // under the 16 MiB ceiling, so that check alone didn't catch this one.
    if (frame->header.message_length > payload.size()) return std::nullopt;

    FfhseResult result;
    result.summary = frame->summary;
    for (const auto& n : frame->notes) result.notes.push_back(n);
    result.first = *frame;

    // UNLIKE HART-IP's own UDP decode (a single datagram, no coalescing), FF-HSE's own UDP
    // framing can carry more than one concatenated PDU per datagram -- exact transplant of the
    // legacy `if (want_ffhse)` UDP call site's own coalescing loop, see ffhse.hpp's "UDP framing"
    // paragraph.
    const size_t kMaxFfhseMessagesPerDatagram = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = frame->wire_length;
    size_t message_count = 1;
    while (offset < payload.size() && message_count < kMaxFfhseMessagesPerDatagram) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_ffhse(rest);
        if (!next) break;  // remaining bytes aren't another FF-HSE PDU -- stop, don't guess
        if (next->header.message_length > rest.size()) break;  // same reasoning, mid-datagram
        ++message_count;
        std::string note = "additional FF-HSE PDU " + std::to_string(message_count) +
                            " found in the same UDP datagram at byte offset " + std::to_string(offset) +
                            ": " + next->summary;
        result.notes.push_back(note);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
    }
    if (message_count >= kMaxFfhseMessagesPerDatagram) {
        result.notes.push_back("stopped after " + std::to_string(kMaxFfhseMessagesPerDatagram) +
                                " FF-HSE PDU(s) in this one UDP datagram, more may remain (safety cap)");
    }

    return ProtocolResult::make<FfhseResult>("ffhse", std::move(result));
}

const ProtocolDecoder& ffhse_tcp_decoder() {
    static const FfhseTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& ffhse_udp_decoder() {
    static const FfhseUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
