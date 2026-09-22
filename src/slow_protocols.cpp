// SPDX-License-Identifier: Apache-2.0
//
// Every offset/bitmask/TLV-type constant below was confirmed against Wireshark's own
// epan/dissectors/packet-slowprotocols.c (fetched from the boundary/wireshark mirror on GitHub,
// since wireshark/wireshark's own GitHub/GitLab trees were unreachable from this environment) --
// specifically its LACPDU_*, OAMPDU_*, and marker_vals[] named constants. See slow_protocols.hpp's
// own header comment for the full citation and for the two fields (OAM's Information TLV State
// byte's internal bit split, and the Marker(-Response) Information TLV's exact total-length
// convention) this file could not independently verify and therefore does not over-claim.
#include "conduitscope/slow_protocols.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// LACP (subtype 1) -- see slow_protocols.hpp's header comment for the full offset table this was
// built from. Every TLV's Length field is the TLV's OWN TOTAL SIZE including its 2-byte Type+Length
// header (confirmed by the fetched offsets: Actor Information spans offset 2..21 inclusive -- 20
// bytes -- for a declared Length of 20), not a value-only length the way e.g. BGP's path attribute
// lengths work -- a genuine per-protocol convention difference, not an inconsistency in this
// codebase's own handling.
constexpr size_t kLacpMinLength = 60;  // subtype(1)+version(1)+actor(20)+partner(20)+collector(16)+terminator(2)

std::string lacp_state_render(const LacpStateFlags& s) {
    std::ostringstream o;
    o << "Activity=" << (s.activity ? "Active" : "Passive")
      << " Timeout=" << (s.timeout ? "Short" : "Long")
      << " Aggregation=" << (s.aggregation ? "Aggregatable" : "Individual")
      << " Synchronization=" << (s.synchronization ? "InSync" : "OutOfSync")
      << " Collecting=" << (s.collecting ? "Enabled" : "Disabled")
      << " Distributing=" << (s.distributing ? "Enabled" : "Disabled")
      << " Defaulted=" << (s.defaulted ? "Yes" : "No")
      << " Expired=" << (s.expired ? "Yes" : "No");
    return o.str();
}

LacpStateFlags parse_lacp_state(uint8_t raw) {
    LacpStateFlags s;
    s.raw = raw;
    s.activity = (raw & 0x01) != 0;
    s.timeout = (raw & 0x02) != 0;
    s.aggregation = (raw & 0x04) != 0;
    s.synchronization = (raw & 0x08) != 0;
    s.collecting = (raw & 0x10) != 0;
    s.distributing = (raw & 0x20) != 0;
    s.defaulted = (raw & 0x40) != 0;
    s.expired = (raw & 0x80) != 0;
    s.rendered = lacp_state_render(s);
    return s;
}

std::string format_mac6(ByteSpan span) {
    std::array<uint8_t, 6> mac{};
    for (size_t i = 0; i < 6; ++i) mac[i] = span.at(i);
    return format_mac(mac);
}

std::optional<LacpMessage> parse_lacp(ByteSpan eth_payload) {
    if (eth_payload.size() < kLacpMinLength) {
        return std::nullopt;
    }

    Cursor c(eth_payload);
    c.u8();  // Subtype, already known to be 0x01 by the caller
    uint8_t version = c.u8();

    uint8_t actor_type = c.u8();
    uint8_t actor_len = c.u8();
    uint16_t actor_sys_prio = c.u16be();
    ByteSpan actor_sys = c.bytes(6);
    uint16_t actor_key = c.u16be();
    uint16_t actor_port_prio = c.u16be();
    uint16_t actor_port = c.u16be();
    uint8_t actor_state_raw = c.u8();
    c.skip(3);  // Reserved

    uint8_t partner_type = c.u8();
    uint8_t partner_len = c.u8();
    uint16_t partner_sys_prio = c.u16be();
    ByteSpan partner_sys = c.bytes(6);
    uint16_t partner_key = c.u16be();
    uint16_t partner_port_prio = c.u16be();
    uint16_t partner_port = c.u16be();
    uint8_t partner_state_raw = c.u8();
    c.skip(3);  // Reserved

    uint8_t collector_type = c.u8();
    uint8_t collector_len = c.u8();
    uint16_t collector_max_delay = c.u16be();
    c.skip(12);  // Reserved

    uint8_t terminator_type = c.u8();
    uint8_t terminator_len = c.u8();

    // Structural gate: every TLV's type AND length must match the fixed values a real LACPDU
    // always uses -- see this file's own header comment. Any mismatch means this isn't really a
    // LACPDU (or is a version/variant this decoder doesn't understand), so decline rather than
    // guess at a different layout.
    if (actor_type != 1 || actor_len != 20 || partner_type != 2 || partner_len != 20 ||
        collector_type != 3 || collector_len != 16 || terminator_type != 0 || terminator_len != 0) {
        return std::nullopt;
    }

    LacpMessage msg;
    msg.version = version;
    msg.actor_system_priority = actor_sys_prio;
    msg.actor_system = format_mac6(actor_sys);
    msg.actor_key = actor_key;
    msg.actor_port_priority = actor_port_prio;
    msg.actor_port = actor_port;
    msg.actor_state = parse_lacp_state(actor_state_raw);
    msg.partner_system_priority = partner_sys_prio;
    msg.partner_system = format_mac6(partner_sys);
    msg.partner_key = partner_key;
    msg.partner_port_priority = partner_port_prio;
    msg.partner_port = partner_port;
    msg.partner_state = parse_lacp_state(partner_state_raw);
    msg.collector_max_delay = collector_max_delay;

    if (!msg.actor_state.synchronization || !msg.partner_state.synchronization) {
        msg.notes.push_back(
            "LACP Out of Sync reported (actor and/or partner) -- normal only transiently during "
            "(re)negotiation; a link that stays Out of Sync is not joining its aggregate, usually "
            "because of a mismatched Key/Port-Priority or an admin-down member port on one side");
    }
    if (msg.actor_state.defaulted || msg.partner_state.defaulted) {
        msg.notes.push_back(
            "LACP Defaulted flag set -- this side has not received a valid LACPDU from its partner "
            "recently and is operating on default (not learned) partner information");
    }

    std::ostringstream s;
    s << "LACP actor=" << msg.actor_system << " (key=" << actor_key << " port=" << actor_port
      << " pri=" << actor_sys_prio << ") partner=" << msg.partner_system << " (key=" << partner_key
      << " port=" << partner_port << " pri=" << partner_sys_prio << ") ["
      << msg.actor_state.rendered << "]";
    msg.summary = s.str();

    return msg;
}

// Marker Protocol (subtype 2). See slow_protocols.hpp's own header comment for why this decoder
// reads the TLV's declared Length (its own total size, including its 2-byte Type+Length header --
// the same convention LACP's own TLVs use) to find the Terminator that follows, rather than
// assuming an exact total size for a field layout it could not independently verify.
constexpr size_t kMarkerFixedFieldBytes = 12;  // Requester_Port(2)+Requester_System(6)+Requester_Transaction_ID(4)
constexpr size_t kMarkerMinTlvLength = 2 + kMarkerFixedFieldBytes;  // header + the three fields above

std::optional<MarkerMessage> parse_marker(ByteSpan eth_payload) {
    if (eth_payload.size() < 2 + kMarkerMinTlvLength) {  // subtype+version, then at least the TLV header+fields
        return std::nullopt;
    }

    Cursor c(eth_payload);
    c.u8();  // Subtype, already known to be 0x02
    c.u8();  // Version Number -- not curated further (LACPDU's own Version is the only one this
             // decoder surfaces; Marker's is present on the wire but not diagnostically useful)

    uint8_t tlv_type = c.u8();
    uint8_t tlv_len = c.u8();
    if ((tlv_type != 0x01 && tlv_type != 0x02) || tlv_len < kMarkerMinTlvLength) {
        return std::nullopt;
    }
    if (eth_payload.size() < 2 + static_cast<size_t>(tlv_len) + 2) {  // + Terminator TLV (2 bytes)
        return std::nullopt;
    }

    uint16_t requester_port = c.u16be();
    ByteSpan requester_sys = c.bytes(6);
    uint32_t requester_trans_id = c.u32be();

    // Skip any trailing Pad/Reserved bytes this TLV's own declared Length says are present, using
    // the Length field itself rather than a hardcoded total -- see this file's header comment.
    size_t consumed_since_tlv_header = 2 + kMarkerFixedFieldBytes;
    if (tlv_len > consumed_since_tlv_header) {
        c.skip(tlv_len - consumed_since_tlv_header);
    }

    uint8_t term_type = c.u8();
    uint8_t term_len = c.u8();
    if (term_type != 0x00 || term_len != 0x00) {
        return std::nullopt;
    }

    MarkerMessage msg;
    msg.is_response = (tlv_type == 0x02);
    msg.requester_port = requester_port;
    msg.requester_system = format_mac6(requester_sys);
    msg.requester_transaction_id = requester_trans_id;

    std::ostringstream s;
    s << "Marker " << (msg.is_response ? "Response Information" : "Information") << " requester="
      << msg.requester_system << " port=" << requester_port << " transaction_id=" << requester_trans_id;
    msg.summary = s.str();

    return msg;
}

// 802.3 OAM / Ethernet-in-the-First-Mile (subtype 3). See slow_protocols.hpp's own header comment
// for the full field table and for the two fields (Information TLV's State byte, OAMPDU_Configuration's
// exact reserved-bit layout) this decoder deliberately shows as raw values rather than bit-decoding.
uint64_t read_uint_be(Cursor& c, size_t n) {
    uint64_t v = 0;
    for (size_t i = 0; i < n; ++i) v = (v << 8) | c.u8();
    return v;
}

std::string oam_code_name(uint8_t code) {
    switch (code) {
        case 0x00: return "Information";
        case 0x01: return "Event Notification";
        case 0x02: return "Variable Request";
        case 0x03: return "Variable Response";
        case 0x04: return "Loopback Control";
        case 0xFE: return "Organization Specific";
        default: return "";
    }
}

std::string oam_event_type_name(uint8_t type) {
    switch (type) {
        case 0x01: return "Errored Symbol Period Event";
        case 0x02: return "Errored Frame Event";
        case 0x03: return "Errored Frame Period Event";
        case 0x04: return "Errored Frame Seconds Summary Event";
        case 0xFE: return "Organization Specific Event";
        default: return "";
    }
}

// Parses one Local/Remote Information TLV's 14-byte value (Version/Revision/State/Config/
// OAMPDU_Config/OUI/Vendor, per this file's own header comment), given a Cursor positioned right
// after the TLV's own Type+Length header. Returns nullopt if fewer than 14 bytes remain.
std::optional<OamInformationTlv> parse_oam_information_value(Cursor& c, const std::string& which) {
    if (c.remaining() < 14) return std::nullopt;
    OamInformationTlv tlv;
    tlv.which = which;
    tlv.oam_version = c.u8();
    tlv.revision = c.u16be();
    tlv.state_raw = c.u8();
    tlv.config_raw = c.u8();
    tlv.config_mode_active = (tlv.config_raw & 0x01) != 0;
    tlv.config_unidirectional = (tlv.config_raw & 0x02) != 0;
    tlv.config_remote_loopback = (tlv.config_raw & 0x04) != 0;
    tlv.config_link_events = (tlv.config_raw & 0x08) != 0;
    tlv.config_variable_retrieval = (tlv.config_raw & 0x10) != 0;
    tlv.oampdu_config_raw = c.u16be();
    ByteSpan oui = c.bytes(3);
    tlv.oui_hex = to_hex(oui, ":");
    ByteSpan vendor = c.bytes(4);
    tlv.vendor_specific_hex = to_hex(vendor, "");

    std::ostringstream s;
    s << which << " Info: version=" << static_cast<unsigned>(tlv.oam_version)
      << " mode=" << (tlv.config_mode_active ? "Active" : "Passive") << " oui=" << tlv.oui_hex;
    tlv.rendered = s.str();
    return tlv;
}

std::optional<OamEvent> parse_oam_event(Cursor& c) {
    if (c.remaining() < 2) return std::nullopt;
    uint8_t type = c.u8();
    uint8_t length = c.u8();
    if (type == 0x00) {
        // End of TLVs marker for the event list -- caller stops the walk on seeing this, this
        // function is never invoked for it in practice, kept here only as a defensive no-op.
        return std::nullopt;
    }
    // `length` is this event TLV's OWN TOTAL SIZE including its 2-byte Type+Length header, matching
    // the convention already confirmed for LACP's and OAM's Information TLVs.
    if (length < 4 || c.remaining() < static_cast<size_t>(length) - 2) {
        return std::nullopt;  // truncated -- caller stops the walk
    }
    size_t tlv_end_remaining_budget = length - 2;  // bytes left in THIS TLV after Type+Length
    OamEvent ev;
    ev.type = type;
    ev.type_name = oam_event_type_name(type);
    ev.timestamp = c.u16be();
    tlv_end_remaining_budget -= 2;

    size_t window_sz = 0, threshold_sz = 0, errors_sz = 0, err_total_sz = 0, event_total_sz = 0;
    switch (type) {
        case 0x01: window_sz = 8; threshold_sz = 8; errors_sz = 8; err_total_sz = 8; event_total_sz = 4; break;
        case 0x02: window_sz = 2; threshold_sz = 4; errors_sz = 4; err_total_sz = 8; event_total_sz = 4; break;
        case 0x03: window_sz = 4; threshold_sz = 4; errors_sz = 4; err_total_sz = 8; event_total_sz = 4; break;
        case 0x04: window_sz = 2; threshold_sz = 2; errors_sz = 2; err_total_sz = 4; event_total_sz = 4; break;
        default: break;  // Organization Specific (0xFE) or an unrecognized type -- raw hex only, below
    }

    size_t fixed_total = window_sz + threshold_sz + errors_sz + err_total_sz + event_total_sz;
    if (fixed_total > 0 && fixed_total <= tlv_end_remaining_budget) {
        ev.fields_decoded = true;
        ev.window = read_uint_be(c, window_sz);
        ev.threshold = read_uint_be(c, threshold_sz);
        ev.errors = read_uint_be(c, errors_sz);
        ev.error_running_total = read_uint_be(c, err_total_sz);
        ev.event_running_total = static_cast<uint32_t>(read_uint_be(c, event_total_sz));
        size_t leftover = tlv_end_remaining_budget - fixed_total;
        if (leftover > 0) c.skip(leftover);  // trailing pad, if any -- tolerated, not decoded

        std::ostringstream s;
        s << ev.type_name << " window=" << ev.window << " threshold=" << ev.threshold
          << " errors=" << ev.errors << " error_running_total=" << ev.error_running_total
          << " event_running_total=" << ev.event_running_total;
        ev.rendered = s.str();
    } else {
        ev.fields_decoded = false;
        ByteSpan rest = c.bytes(tlv_end_remaining_budget);
        ev.raw_hex = to_hex(rest);
        std::ostringstream s;
        s << (ev.type_name.empty() ? ("event type 0x" + std::to_string(type)) : ev.type_name)
          << " (raw " << tlv_end_remaining_budget << " byte(s)): " << ev.raw_hex;
        ev.rendered = s.str();
    }
    return ev;
}

std::optional<OamMessage> parse_oam(ByteSpan eth_payload) {
    if (eth_payload.size() < 4) {  // Subtype(1)+Flags(2)+Code(1)
        return std::nullopt;
    }
    Cursor c(eth_payload);
    c.u8();  // Subtype, already known to be 0x03
    uint16_t flags = c.u16be();
    uint8_t code = c.u8();

    std::string code_name = oam_code_name(code);
    if (code_name.empty()) {
        // Not one of the six recognized Code values -- this codebase's primary structural gate for
        // OAM (necessarily weaker than LACP's combined TLV-type+length gate, since OAM's own
        // framing has less redundancy to check -- see this file's header comment).
        return std::nullopt;
    }

    OamMessage msg;
    msg.flags_raw = flags;
    msg.flag_link_fault = (flags & 0x0001) != 0;
    msg.flag_dying_gasp = (flags & 0x0002) != 0;
    msg.flag_critical_event = (flags & 0x0004) != 0;
    msg.flag_local_evaluating = (flags & 0x0008) != 0;
    msg.flag_local_stable = (flags & 0x0010) != 0;
    msg.flag_remote_evaluating = (flags & 0x0020) != 0;
    msg.flag_remote_stable = (flags & 0x0040) != 0;
    msg.code = code;
    msg.code_name = code_name;

    if (msg.flag_dying_gasp) {
        msg.notes.push_back(
            "OAM Dying Gasp flag set -- the sending device is reporting an imminent, uncontrolled "
            "loss of power (e.g. a UPS-backed access device transmitting its last gasp before going "
            "dark), a real-time link/power-health signal worth flagging on its own");
    }
    if (msg.flag_link_fault) {
        msg.notes.push_back("OAM Link Fault flag set -- the sending device's receive path has detected a fault");
    }
    if (msg.flag_critical_event) {
        msg.notes.push_back("OAM Critical Event flag set -- an unspecified vendor-defined critical condition is active");
    }

    std::ostringstream s;
    s << "OAM " << code_name;

    if (code == 0x00) {  // Information
        msg.is_information = true;
        size_t tlv_count = 0;
        while (c.remaining() >= 2 && tlv_count < 16) {
            uint8_t tlv_type = c.u8();
            uint8_t tlv_len = c.u8();
            if (tlv_type == 0x00) break;  // End of TLVs marker
            if (tlv_len < 2 || c.remaining() < static_cast<size_t>(tlv_len) - 2) {
                // Truncated/malformed trailing TLV -- stop the walk gracefully rather than reject
                // the whole message (matching LLDP's own graceful-truncation posture).
                msg.notes.push_back("OAM Information TLV stream truncated or malformed -- stopped walking further TLVs");
                break;
            }
            size_t value_len = static_cast<size_t>(tlv_len) - 2;
            if (tlv_type == 0x01 || tlv_type == 0x02) {
                std::string which = (tlv_type == 0x01) ? "Local" : "Remote";
                if (value_len == 14) {
                    if (auto info = parse_oam_information_value(c, which)) {
                        if (tlv_type == 0x01) msg.local_info = info; else msg.remote_info = info;
                    } else {
                        c.skip(value_len);
                    }
                } else {
                    c.skip(value_len);  // unexpected size for this TLV type -- skip, don't guess
                }
            } else if (tlv_type == 0xFE) {
                msg.has_organization_specific_info_tlv = true;
                c.skip(value_len);
            } else {
                c.skip(value_len);  // unrecognized TLV type -- skip without further interpretation
            }
            ++tlv_count;
        }
        s << " local=" << (msg.local_info ? msg.local_info->rendered : std::string("(none)"))
          << " remote=" << (msg.remote_info ? msg.remote_info->rendered : std::string("(none)"));
    } else if (code == 0x01) {  // Event Notification
        msg.is_event_notification = true;
        if (c.remaining() < 2) return std::nullopt;
        msg.event_sequence = c.u16be();
        size_t event_count = 0;
        while (c.remaining() >= 2 && event_count < 32) {
            size_t before = c.position();
            uint8_t peek_type = eth_payload.at(before);
            if (peek_type == 0x00) break;  // End of TLVs marker
            auto ev = parse_oam_event(c);
            if (!ev) {
                msg.events_truncated = true;
                break;
            }
            msg.events.push_back(*ev);
            ++event_count;
        }
        s << " seq=" << msg.event_sequence << " events=" << msg.events.size();
    } else if (code == 0x02) {
        msg.is_variable_request = true;
    } else if (code == 0x03) {
        msg.is_variable_response = true;
    } else if (code == 0x04) {  // Loopback Control
        msg.is_loopback_control = true;
        if (c.remaining() >= 1) {
            uint8_t cmd = c.u8();
            if (cmd == 0x01) {
                msg.loopback_enable = true;
                s << ": Enable";
            } else if (cmd == 0x02) {
                msg.loopback_enable = false;
                s << ": Disable";
            } else {
                s << ": unrecognized command 0x" << std::hex << static_cast<unsigned>(cmd) << std::dec;
            }
        }
    } else if (code == 0xFE) {
        msg.is_organization_specific = true;
    }

    msg.summary = s.str();
    return msg;
}

}  // namespace

std::optional<SlowProtocolsMessage> try_parse_slow_protocols(ByteSpan eth_payload) {
    if (eth_payload.empty()) return std::nullopt;
    uint8_t subtype = eth_payload.at(0);

    SlowProtocolsMessage msg;
    msg.subtype = subtype;

    if (subtype == 0x01) {
        auto lacp = parse_lacp(eth_payload);
        if (!lacp) return std::nullopt;
        msg.subtype_name = "LACP";
        msg.is_lacp = true;
        msg.summary = lacp->summary;
        msg.notes = lacp->notes;
        msg.lacp = std::move(lacp);
    } else if (subtype == 0x02) {
        auto marker = parse_marker(eth_payload);
        if (!marker) return std::nullopt;
        msg.subtype_name = "Marker Protocol";
        msg.is_marker = true;
        msg.summary = marker->summary;
        msg.notes = marker->notes;
        msg.marker = std::move(marker);
    } else if (subtype == 0x03) {
        auto oam = parse_oam(eth_payload);
        if (!oam) return std::nullopt;
        msg.subtype_name = "802.3 OAM (EFM)";
        msg.is_oam = true;
        msg.summary = oam->summary;
        msg.notes = oam->notes;
        msg.oam = std::move(oam);
    } else {
        // Subtype not recognized/supported by this decoder (e.g. ESMC/G.8264=0x0A, MEF E-LMI=0x0B)
        // -- see slow_protocols.hpp's own "deliberately out of scope" paragraph. Decline, falling
        // back to the existing generic ethertype-name-only report.
        return std::nullopt;
    }

    return msg;
}

std::optional<ProtocolResult> SlowProtocolsDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_slow_protocols(payload)) {
        return ProtocolResult::make<SlowProtocolsMessage>("slow-protocols", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& slow_protocols_decoder() {
    static const SlowProtocolsDecoder instance;
    return instance;
}

}  // namespace conduitscope
