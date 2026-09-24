// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ge_srtp.hpp"

#include <iomanip>
#include <sstream>
#include <unordered_map>

namespace conduitscope {

namespace {

constexpr size_t kHeaderSize = 56;

constexpr uint8_t kMsgTypeShort = 0xc0;
constexpr uint8_t kMsgTypeShortAck = 0xd4;
constexpr uint8_t kMsgTypeShortErr = 0xd1;
constexpr uint8_t kMsgTypeExtended = 0x80;
constexpr uint8_t kMsgTypeExtendedAck = 0x94;

// A real GE SRTP response body is never larger than this codebase would ever plausibly need to
// hex-render; defense in depth, mirroring every other protocol's own kMaxPlausible* guard, though
// GE SRTP's own fixed-56-byte-plus-trailing shape makes this far less load-bearing than MELSEC's/
// TwinCAT's own declared-length guards.
constexpr size_t kMaxPlausibleExtendedTrailingBytes = 1u << 16;

// Renders a byte span as compact (no-separator) lowercase hex -- this file's own local shorthand
// for the shared conduitscope::to_hex(ByteSpan, separator) (byteio.hpp), called with an empty
// separator throughout ge_srtp.cpp.
std::string hex_compact(ByteSpan span) { return conduitscope::to_hex(span, ""); }

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

std::string hex_u16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
      << static_cast<unsigned>(v);
    return s.str();
}

struct ServiceRequestInfo {
    const char* name;
};

// See ge_srtp.hpp's file header comment ("SERVICE REQUEST CODES") for the full sourcing.
const std::unordered_map<uint8_t, ServiceRequestInfo>& service_request_table() {
    static const std::unordered_map<uint8_t, ServiceRequestInfo> table = {
        {0x00, {"PLC short status request"}},
        {0x03, {"return control program names"}},
        {0x04, {"read system memory"}},
        {0x05, {"read task memory"}},
        {0x06, {"read program memory"}},
        {0x07, {"write system memory"}},
        {0x08, {"write task memory"}},
        {0x09, {"write program block memory"}},
        {0x20, {"programmer logon"}},
        {0x21, {"change PLC CPU privilege level"}},
        {0x22, {"set control ID (CPU ID)"}},
        {0x23, {"set PLC (run vs. stop)"}},
        {0x24, {"set PLC time/date"}},
        {0x25, {"get PLC time/date"}},
        {0x38, {"get fault table"}},
        {0x39, {"clear fault table"}},
        {0x3f, {"program store (upload from PLC)"}},
        {0x40, {"program load (download to PLC)"}},
        {0x43, {"get controller type and id information"}},
        {0x44, {"toggle force system memory"}},
    };
    return table;
}

struct SelectorInfo {
    const char* memory_area;  // e.g. "%R"
    const char* unit;         // "bit", "byte", or "word"
};

// See ge_srtp.hpp's file header comment ("SEGMENT SELECTORS") for the full sourcing.
const std::unordered_map<uint8_t, SelectorInfo>& selector_table() {
    static const std::unordered_map<uint8_t, SelectorInfo> table = {
        {0x46, {"%I", "bit"}},   {0x10, {"%I", "byte"}},
        {0x48, {"%Q", "bit"}},   {0x12, {"%Q", "byte"}},
        {0x4c, {"%M", "bit"}},   {0x16, {"%M", "byte"}},
        {0x4a, {"%T", "bit"}},   {0x14, {"%T", "byte"}},
        {0x4e, {"%SA", "bit"}},  {0x18, {"%SA", "byte"}},
        {0x50, {"%SB", "bit"}},  {0x1a, {"%SB", "byte"}},
        {0x52, {"%SC", "bit"}},  {0x1c, {"%SC", "byte"}},
        {0x54, {"%S", "bit"}},   {0x1e, {"%S", "byte"}},
        {0x56, {"%G", "bit"}},   {0x38, {"%G", "byte"}},
        {0x0a, {"%AI", "word"}},
        {0x0c, {"%AQ", "word"}},
        {0x08, {"%R", "word"}},
    };
    return table;
}

std::string status_code_name(uint8_t major) {
    // From the DFRWS paper's own text (see ge_srtp.hpp's file header comment); every other value
    // is shown honestly as unverified, the same posture MELSEC's own end_code_name takes for any
    // error code past its own two independently-confirmed values.
    if (major == 0x00) return "No error";
    if (major == 0x01) return "illegal service request";
    if (major == 0x02) return "insufficient privilege level";
    if (major == 0x04) return "protocol sequence error";
    if (major == 0x07) return "full PLC service request queue";
    return "Error " + hex_u8(major) +
           " (not independently verified against a GE-published error-code appendix)";
}

std::string control_program_state_name(uint8_t v) {
    if (v == 0x00) return "logged in to a program task";
    if (v == 0xff) return "not logged in to a program task";
    return "unrecognized (" + hex_u8(v) + ")";
}

GeSrtpTarget parse_target(uint8_t selector, uint16_t index, uint16_t count) {
    GeSrtpTarget t;
    t.segment_selector = selector;
    t.target_index = index;
    t.target_count = count;
    auto it = selector_table().find(selector);
    if (it == selector_table().end()) {
        t.selector_recognized = false;
        t.target_text = hex_u8(selector) + ":" + std::to_string(index);
    } else {
        t.selector_recognized = true;
        t.target_text = std::string(it->second.memory_area) + std::to_string(index + 1);
    }
    return t;
}

// Security-context notes for the service-request codes the DFRWS 2017 paper's own field finding
// (no authentication by default on real GE Fanuc Series 90-30 deployments -- see ge_srtp.hpp's
// file header comment's "SECURITY CONTEXT" section) is most directly relevant to. Called once per
// decoded request; a no-op for any code not in this list.
void append_security_note(GeSrtpFrame& frame, uint8_t service_request_code) {
    switch (service_request_code) {
        case 0x04:
        case 0x05:
        case 0x06:
            frame.notes.push_back(
                "arbitrary PLC memory read, commonly with no protocol-level authentication at all "
                "(DFRWS 2017 field finding on real GE Fanuc Series 90-30 deployments -- see "
                "ge_srtp.hpp)");
            break;
        case 0x07:
        case 0x08:
        case 0x09:
            frame.notes.push_back(
                "arbitrary PLC memory write, commonly with no protocol-level authentication at all "
                "(DFRWS 2017 field finding on real GE Fanuc Series 90-30 deployments -- see "
                "ge_srtp.hpp)");
            break;
        case 0x23:
            frame.notes.push_back(
                "PLC run/stop control: commonly no protocol-level authentication at all -- "
                "privilege levels exist on the wire but the DFRWS 2017 paper's own field "
                "experience found them rarely activated in practice (see ge_srtp.hpp)");
            break;
        case 0x3f:
            frame.notes.push_back(
                "program store (upload FROM the PLC): unauthenticated reconnaissance risk -- "
                "reveals the PLC's own control-logic program, commonly with no credential required "
                "(DFRWS 2017 field finding, see ge_srtp.hpp)");
            break;
        case 0x40:
            frame.notes.push_back(
                "program load (download TO the PLC): arbitrary control-logic replacement, commonly "
                "with no protocol-level authentication at all (DFRWS 2017 field finding, see "
                "ge_srtp.hpp)");
            break;
        case 0x43:
            frame.notes.push_back(
                "get controller type and id information: unauthenticated reconnaissance -- reveals "
                "PLC hardware/firmware family to any network-reachable client");
            break;
        case 0x20:
            frame.notes.push_back(
                "programmer logon: this decoder does not decode the request's own payload (no "
                "source used establishes its byte layout well enough to safely redact a password "
                "that may be in it, see ge_srtp.hpp) -- the DFRWS 2017 paper's own field experience "
                "found GE SRTP's optional privilege-level protection rarely activated in practice");
            break;
        default:
            break;
    }
}

// Decodes a SHORT/EXTENDED request's own service-request-specific fields (target, inline payload)
// into `frame`, and builds its summary/notes. Shared by the request-side of try_parse_ge_srtp
// (SHORT) and decode_extended_body below (EXTENDED) -- the two shapes carry the exact same
// service-request/selector/index/count fields, just at different byte offsets (see ge_srtp.hpp's
// file header comment).
void decode_request_common(GeSrtpFrame& frame, uint8_t service_request_code, uint8_t selector,
                            uint16_t index, uint16_t count) {
    frame.has_service_request = true;
    frame.service_request_code = service_request_code;
    auto name = ge_srtp_service_request_name(service_request_code);
    frame.service_request_recognized = name.has_value();
    frame.service_request_name = name ? *name : ("Unknown service request code " + hex_u8(service_request_code));

    std::ostringstream summary;
    summary << frame.message_type_name << ": " << frame.service_request_name;

    bool has_memory_target = service_request_code >= 0x04 && service_request_code <= 0x09;
    if (has_memory_target) {
        frame.has_target = true;
        frame.target = parse_target(selector, index, count);
        summary << " " << frame.target.target_text << " (" << frame.target.target_count << " "
                << (frame.target.selector_recognized ? selector_table().at(selector).unit : "unit")
                << "(s))";
    }
    append_security_note(frame, service_request_code);
    frame.summary = summary.str();
}

// Decodes a SHORT_ACK/SHORT_ERR/EXTENDED_ACK response's own status/return-data fields (bytes 42-55
// of the 56-byte header -- identical shape for all three) into `frame`.
void decode_response_common(GeSrtpFrame& frame, Cursor& c) {
    frame.has_status = true;
    frame.status_code = c.u8();
    frame.status_code_minor = c.u8();
    frame.status_code_name = status_code_name(frame.status_code);
    frame.return_data_hex = hex_compact(c.bytes(6));
    frame.control_program_number = c.u8();
    frame.has_control_program_number = true;
    frame.control_program_state = control_program_state_name(frame.control_program_number);
    frame.current_privilege_level = c.u8();
    frame.last_sweep_time_us = c.u16le();
    frame.plc_status_word = c.u16le();

    std::ostringstream summary;
    summary << frame.message_type_name << ": " << frame.status_code_name;
    if (frame.is_error) {
        summary << " (status minor " << hex_u8(frame.status_code_minor) << ")";
    }
    frame.summary = summary.str();
    if (frame.is_error) {
        frame.notes.push_back("request rejected (SHORT_ERR / Nack Mailbox message)");
    }
}

std::string packet_type_name(uint16_t packet_type, bool is_init) {
    if (is_init) return "INIT";
    switch (packet_type) {
        case 0: return "INIT";
        case 1: return "INIT_ACK";
        case 2: return "REQ";
        case 3: return "REQ_ACK";
        case 8: return "UNKNOWN";
        default: return "Unrecognized packet type " + hex_u16(packet_type);
    }
}

bool is_all_zero(ByteSpan span) {
    for (size_t i = 0; i < span.size(); ++i) {
        if (span.at(i) != 0) return false;
    }
    return true;
}

}  // namespace

std::optional<std::string> ge_srtp_service_request_name(uint8_t code) {
    auto it = service_request_table().find(code);
    if (it == service_request_table().end()) return std::nullopt;
    return it->second.name;
}

std::optional<size_t> ge_srtp_declared_length(ByteSpan payload) {
    if (payload.size() < 2) return std::nullopt;
    try {
        Cursor c(payload);
        uint16_t packet_type = c.u16le();
        if (packet_type != 0 && packet_type != 1 && packet_type != 2 && packet_type != 3 &&
            packet_type != 8) {
            return std::nullopt;
        }
        // Not yet enough bytes to reach Message Type (byte 31) and apply the stronger check below
        // -- claim this candidate for GE SRTP's own reassembly anyway on Packet Type alone. This
        // matters even for a short first TCP segment of a real GE SRTP message (as little as these
        // 2 bytes): decoder.cpp's own reassembly cascade recomputes this function fresh on every
        // new segment against the whole accumulated candidate (buffered bytes + the new segment),
        // so returning std::nullopt here just because not enough bytes have arrived YET would leave
        // `declared` unset on this call and let a weaker, still-opportunistic later gate in that
        // same cascade (COTP/TPKT's own version==3/reserved==0 check -- GE SRTP's own Packet Type
        // values 2/3, REQ/REQ_ACK, happen to supply TPKT's version byte by coincidence) hijack the
        // flow and corrupt its own reassembly state -- a real, reproducible collision found while
        // building this decoder's own fixture (a SHORT response split across TCP segments right at
        // this boundary). The stronger Message-Type-based check immediately below still runs, and
        // can still return std::nullopt, once 56 bytes have actually accumulated.
        if (payload.size() < kHeaderSize) return kHeaderSize;

        c.skip(29);  // bytes 2-30 (sequence/text-length/reserved/time/msg-seq)
        uint8_t message_type = c.u8();
        if (packet_type == 2 || packet_type == 3) {
            // REQ/REQ_ACK must carry one of the 5 known message types (see file header comment) --
            // this is the strongest part of the gate.
            if (message_type != kMsgTypeShort && message_type != kMsgTypeShortAck &&
                message_type != kMsgTypeShortErr && message_type != kMsgTypeExtended &&
                message_type != kMsgTypeExtendedAck) {
                return std::nullopt;
            }
        }
        // EXTENDED REQUEST ONLY: no reliable trailing-length field anywhere in the fixed header --
        // see this file's own "DECLARED LENGTH" header-comment section for why this deliberately
        // returns nullopt rather than guessing, so a multi-segment EXTENDED request is never
        // reassembled. EXTENDED_ACK is deliberately NOT included here -- no source suggests it
        // carries trailing bulk data the way an EXTENDED request legitimately can (see "BODY,
        // EXTENDED_ACK" above), so it gets the ordinary fixed 56 like every SHORT-family shape.
        if (message_type == kMsgTypeExtended) return std::nullopt;
        return kHeaderSize;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<GeSrtpFrame> try_parse_ge_srtp(ByteSpan payload) {
    if (payload.size() < kHeaderSize) return std::nullopt;
    try {
        GeSrtpFrame frame;

        if (is_all_zero(payload.subspan(0, kHeaderSize)) && payload.size() == kHeaderSize) {
            frame.is_init = true;
            frame.packet_type = 0;
            frame.packet_type_name = "INIT";
            frame.summary = "GE SRTP INIT (connection handshake, 56 all-zero bytes)";
            return frame;
        }

        Cursor c(payload);
        uint16_t packet_type = c.u16le();
        if (packet_type != 0 && packet_type != 1 && packet_type != 2 && packet_type != 3 &&
            packet_type != 8) {
            return std::nullopt;
        }
        frame.packet_type = packet_type;

        frame.sequence_number = c.u16le();
        frame.text_length = c.u16le();
        c.skip(20);  // bytes 6-25, reserved/unknown -- see file header comment
        frame.time_seconds = c.u8();
        frame.time_minutes = c.u8();
        frame.time_hours = c.u8();
        c.u8();  // byte 29, reserved
        frame.msg_seq = c.u8();
        uint8_t message_type = c.u8();
        frame.message_type_raw = message_type;

        if (packet_type == 2 || packet_type == 3) {
            if (message_type != kMsgTypeShort && message_type != kMsgTypeShortAck &&
                message_type != kMsgTypeShortErr && message_type != kMsgTypeExtended &&
                message_type != kMsgTypeExtendedAck) {
                return std::nullopt;
            }
        }

        frame.mailbox_source = c.u32le();
        frame.mailbox_dest = c.u32le();
        frame.packet_num = c.u8();
        frame.total_packet_num = c.u8();

        switch (message_type) {
            case kMsgTypeShort:
                frame.message_type_name = "SHORT request";
                frame.is_response = false;
                break;
            case kMsgTypeShortAck:
                frame.message_type_name = "SHORT_ACK response";
                frame.is_response = true;
                break;
            case kMsgTypeShortErr:
                frame.message_type_name = "SHORT_ERR response (Nack)";
                frame.is_response = true;
                frame.is_error = true;
                break;
            case kMsgTypeExtended:
                frame.message_type_name = "EXTENDED request";
                frame.is_response = false;
                frame.is_extended = true;
                break;
            case kMsgTypeExtendedAck:
                frame.message_type_name = "EXTENDED_ACK response";
                frame.is_response = true;
                frame.is_extended = true;
                break;
            default:
                frame.message_type_name = "Unrecognized message type " + hex_u8(message_type);
                break;
        }
        frame.packet_type_name = packet_type_name(packet_type, false);

        if (message_type == kMsgTypeShort) {
            uint8_t service_request_code = c.u8();
            uint8_t selector = c.u8();
            uint16_t index = c.u16le();
            uint16_t count = c.u16le();
            decode_request_common(frame, service_request_code, selector, index, count);
            frame.inline_payload_hex = hex_compact(c.bytes(6));
            c.skip(2);  // bytes 54-55, trailing, not independently verified -- see file header
        } else if (message_type == kMsgTypeShortAck || message_type == kMsgTypeShortErr) {
            decode_response_common(frame, c);
        } else if (message_type == kMsgTypeExtended) {
            c.skip(6);  // bytes 42-47, unknown -- see file header comment
            c.skip(2);  // bytes 48-49, Packet#/Total Packet# repeated
            uint8_t service_request_code = c.u8();
            uint8_t selector = c.u8();
            uint16_t index = c.u16le();
            uint16_t count = c.u16le();
            decode_request_common(frame, service_request_code, selector, index, count);
            ByteSpan trailing = c.rest();
            if (!trailing.empty() && trailing.size() <= kMaxPlausibleExtendedTrailingBytes) {
                frame.has_extended_trailing_payload = true;
                frame.extended_trailing_payload_byte_count = trailing.size();
                frame.extended_trailing_payload_hex = hex_compact(trailing);
            }
        } else if (message_type == kMsgTypeExtendedAck) {
            // Per this file's own header comment ("BODY, EXTENDED_ACK"): genuinely unverified by
            // any of this decoder's three sources -- reported as an honest undecoded blob rather
            // than guessed at.
            ByteSpan rest = c.rest();
            frame.has_undecoded_body = true;
            frame.undecoded_body_byte_count = rest.size();
            frame.undecoded_body_hex = hex_compact(rest);
            std::ostringstream summary;
            summary << frame.message_type_name << " (" << rest.size()
                    << " byte(s) from byte 42 onward, layout not independently verified -- see "
                       "ge_srtp.hpp)";
            frame.summary = summary.str();
        } else {
            ByteSpan rest = c.rest();
            if (!rest.empty()) {
                frame.has_undecoded_body = true;
                frame.undecoded_body_byte_count = rest.size();
                frame.undecoded_body_hex = hex_compact(rest);
            }
            std::ostringstream summary;
            summary << frame.packet_type_name << " / " << frame.message_type_name
                    << " (not otherwise decoded)";
            frame.summary = summary.str();
        }

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

namespace {

std::optional<ProtocolResult> decode_with_session_state(ByteSpan payload, DecodeContext& ctx) {
    auto parsed = try_parse_ge_srtp(payload);
    if (!parsed) return std::nullopt;
    GeSrtpFrame frame = std::move(*parsed);

    if (frame.has_service_request && !frame.is_response) {
        GeSrtpFlowState& state = ctx.flow_state<GeSrtpFlowState>();
        auto existing = state.pending.find(frame.sequence_number);
        if (existing != state.pending.end()) {
            frame.notes.push_back(
                "a previous request with this same sequence number (" +
                std::to_string(frame.sequence_number) + ", packet #" +
                std::to_string(existing->second.packet_index) +
                ") on this session was never matched with a response before this new request was "
                "sent -- possibly a missed reply, an out-of-order capture, or sequence-number reuse");
        }
        state.pending[frame.sequence_number] =
            GeSrtpPendingRequest{frame.service_request_code, frame.service_request_name,
                                  frame.has_target, frame.target, ctx.packet_index};
    } else if (frame.is_response) {
        GeSrtpFlowState& state = ctx.flow_state<GeSrtpFlowState>();
        auto it = state.pending.find(frame.sequence_number);
        if (it != state.pending.end()) {
            frame.matched_to_request = true;
            frame.matched_request_packet_index = it->second.packet_index;
            frame.has_service_request = true;
            frame.service_request_code = it->second.service_request_code;
            frame.service_request_name = it->second.service_request_name;
            frame.service_request_recognized =
                ge_srtp_service_request_name(it->second.service_request_code).has_value();
            frame.has_target = it->second.has_target;
            frame.target = it->second.target;
            frame.notes.push_back(
                "matched to the " + it->second.service_request_name + " request seen in packet #" +
                std::to_string(it->second.packet_index) +
                " on this session (authoritatively paired by GE SRTP's own Sequence Number, "
                "bytes 2-3)");
            state.pending.erase(it);
        } else {
            frame.notes.push_back(
                "no outstanding request with this sequence number found on this session -- this "
                "response's own service request is unknown (GE SRTP responses carry no service "
                "request code of their own on the wire)");
        }
    }

    return ProtocolResult::make<GeSrtpFrame>("ge-srtp", std::move(frame));
}

}  // namespace

std::optional<ProtocolResult> GeSrtpTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    return decode_with_session_state(payload, ctx);
}

const ProtocolDecoder& ge_srtp_tcp_decoder() {
    static const GeSrtpTcpDecoder instance;
    return instance;
}

}  // namespace conduitscope
