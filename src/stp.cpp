// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/stp.hpp"

#include <iomanip>
#include <sstream>

#include "conduitscope/link_layer.hpp"

namespace conduitscope {

namespace {

// Safety cap against a malformed/adversarial capture's Version 3 Length claiming an absurd number
// of MSTI Configuration Messages -- 64 is not an arbitrary round number, it's the reference
// source's own documented ceiling ("an integral number, from 0 to 64 inclusive, of MSTI
// Configuration Messages", see packet-bpdu.c's comment on VERSION_3_STATIC_LENGTH, quoted in
// stp.hpp's file header comment).
constexpr size_t kMaxStpMstiMessages = 64;

constexpr uint8_t kFlagTca = 0x80;
constexpr uint8_t kFlagAgreement = 0x40;
constexpr uint8_t kFlagForwarding = 0x20;
constexpr uint8_t kFlagLearning = 0x10;
constexpr uint8_t kFlagPortRoleMask = 0x0C;
constexpr uint8_t kFlagProposal = 0x02;
constexpr uint8_t kFlagTc = 0x01;

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

std::string version_name(uint8_t version) {
    switch (version) {
        case 0: return "STP (802.1D)";
        case 2: return "RSTP (802.1w)";
        case 3: return "MSTP (802.1s)";
        case 4: return "SPB (802.1aq)";
        default: return "unknown(" + std::to_string(static_cast<unsigned>(version)) + ")";
    }
}

std::string bpdu_type_name(uint8_t type) {
    switch (type) {
        case 0x00: return "Configuration";
        case 0x02: return "Rapid/Multiple Spanning Tree";
        case 0x80: return "Topology Change Notification";
        default: return "unknown(" + hex2(type) + ")";
    }
}

// Reads one Bridge/Root Identifier-shaped 8-byte field (2-byte priority+extension, 6-byte MAC) --
// see stp.hpp's file header comment. Used identically for Root/Bridge/CIST Bridge Identifier AND
// MSTI Regional Root (all four share this exact packing, confirmed against the reference source --
// see stp.hpp's "MSTI Regional Root's priority/MSTID split" paragraph).
StpBridgeId read_bridge_id(Cursor& c) {
    StpBridgeId id;
    id.raw = c.u16be();
    id.priority = id.raw & 0xF000;
    id.ext = id.raw & 0x0FFF;
    for (auto& b : id.mac) b = c.u8();
    return id;
}

std::string render_bridge_id(const StpBridgeId& id) {
    std::ostringstream s;
    s << id.priority << "/" << id.ext << "/" << format_mac(id.mac);
    return s.str();
}

// Decodes the common 8-bit Flags layout -- identical for the BPDU-level Flags byte and every MSTI
// Configuration Message's own Flags byte (see stp.hpp's file header comment).
struct DecodedFlags {
    bool tca = false, agreement = false, forwarding = false, learning = false;
    uint8_t port_role = 0;
    bool proposal = false, tc = false;
};

DecodedFlags decode_flags(uint8_t flags) {
    DecodedFlags f;
    f.tca = (flags & kFlagTca) != 0;
    f.agreement = (flags & kFlagAgreement) != 0;
    f.forwarding = (flags & kFlagForwarding) != 0;
    f.learning = (flags & kFlagLearning) != 0;
    f.port_role = static_cast<uint8_t>((flags & kFlagPortRoleMask) >> 2);
    f.proposal = (flags & kFlagProposal) != 0;
    f.tc = (flags & kFlagTc) != 0;
    return f;
}

// Trims trailing NUL padding from the 32-byte MST Config Name field. Not full ASCII validation
// (matching this codebase's usual "render bytes as text, no charset checking" posture elsewhere,
// e.g. GOOSE's visible-string/mMSString fields).
std::string trim_nul_padded(ByteSpan s) {
    std::string text;
    text.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        uint8_t b = s.at(i);
        if (b == 0) break;
        text += static_cast<char>(b);
    }
    return text;
}

// One 16-byte MSTI Configuration Message -- see stp.hpp's file header comment.
StpMstiMessage decode_msti_message(Cursor& c) {
    StpMstiMessage m;
    m.flags = c.u8();
    DecodedFlags df = decode_flags(m.flags);
    m.flag_tca = df.tca;
    m.flag_agreement = df.agreement;
    m.flag_forwarding = df.forwarding;
    m.flag_learning = df.learning;
    m.flag_port_role = df.port_role;
    m.flag_proposal = df.proposal;
    m.flag_tc = df.tc;

    m.regional_root = read_bridge_id(c);
    m.internal_root_path_cost = c.u32be();

    // See stp.hpp's "MSTI Bridge/Port Identifier Priority bytes" paragraph -- only the top nibble
    // of each byte is ever decoded by the reference source; the bottom nibble is left undecoded.
    m.bridge_identifier_priority_nibble = static_cast<uint8_t>(c.u8() >> 4);
    m.port_identifier_priority_nibble = static_cast<uint8_t>(c.u8() >> 4);

    m.remaining_hops = c.u8();
    return m;
}

}  // namespace

std::string stp_port_role_name(uint8_t role) {
    switch (role) {
        case 0: return "Unknown";
        case 1: return "Alternate/Backup";
        case 2: return "Root";
        case 3: return "Designated";
        default: return "unknown";  // unreachable -- role is always a 2-bit value
    }
}

std::string stp_render_msti_summary(const StpMstiMessage& m) {
    std::ostringstream s;
    s << "MSTID=" << m.regional_root.ext << " RegionalRoot=" << m.regional_root.priority << "/"
      << format_mac(m.regional_root.mac) << " Cost=" << m.internal_root_path_cost
      << " BridgePrio=" << static_cast<unsigned>(m.bridge_identifier_priority_nibble)
      << " PortPrio=" << static_cast<unsigned>(m.port_identifier_priority_nibble)
      << " RemainingHops=" << static_cast<unsigned>(m.remaining_hops) << " Role="
      << stp_port_role_name(m.flag_port_role);
    if (m.flag_tc) s << " [TC]";
    if (m.flag_proposal) s << " [Proposal]";
    if (m.flag_agreement) s << " [Agreement]";
    if (m.flag_learning) s << " [Learning]";
    if (m.flag_forwarding) s << " [Forwarding]";
    return s.str();
}

std::optional<StpFrame> try_parse_stp(ByteSpan llc_payload) {
    if (llc_payload.size() < 4) return std::nullopt;
    try {
        Cursor c(llc_payload);
        uint16_t proto_id = c.u16be();
        uint8_t version = c.u8();
        uint8_t type = c.u8();

        if (proto_id != 0x0000) return std::nullopt;
        if (type != 0x00 && type != 0x02 && type != 0x80) return std::nullopt;
        if (type != 0x80 && version != 0 && version != 2 && version != 3 && version != 4) {
            // See stp.hpp's "Structural detection gate" paragraph -- deliberately narrower than the
            // reference source, which accepts (and merely warns on) any version byte at all.
            return std::nullopt;
        }

        StpFrame f;
        f.protocol_identifier = proto_id;
        f.protocol_version = version;
        f.protocol_version_name = version_name(version);
        f.bpdu_type = type;
        f.bpdu_type_name = bpdu_type_name(type);

        if (type == 0x80) {
            f.is_tcn = true;
            f.summary = "STP Topology Change Notification (" + f.protocol_version_name + ")";
            if (llc_payload.size() > 4) {
                f.notes.push_back(std::to_string(llc_payload.size() - 4) +
                                   " byte(s) follow a TCN BPDU's own 4-byte body -- a TCN BPDU "
                                   "carries no further fields (see stp.hpp), ignored");
            }
            return f;
        }

        if (version == 4) {
            f.is_spb = true;
            f.summary = "SPB (802.1aq), not decoded -- out of scope (see stp.hpp)";
            return f;
        }

        // --- Common Configuration/RST BPDU body (35 bytes: Flags through Forward Delay) ---
        if (llc_payload.size() < 35) {
            f.notes.push_back("only " + std::to_string(llc_payload.size()) +
                               " byte(s) present, need 35 for the common Configuration/RST BPDU "
                               "body -- not decoded further");
            f.summary = f.bpdu_type_name + " BPDU (truncated before the common body)";
            return f;
        }
        f.has_common_body = true;
        f.flags = c.u8();
        {
            DecodedFlags df = decode_flags(f.flags);
            f.flag_tca = df.tca;
            f.flag_agreement = df.agreement;
            f.flag_forwarding = df.forwarding;
            f.flag_learning = df.learning;
            f.flag_port_role = df.port_role;
            f.flag_proposal = df.proposal;
            f.flag_tc = df.tc;
        }
        f.root_id = read_bridge_id(c);
        f.root_path_cost = c.u32be();
        f.bridge_id = read_bridge_id(c);
        f.port_id_raw = c.u16be();
        f.port_id_priority = static_cast<uint16_t>((f.port_id_raw >> 12) * 16);
        f.port_id_number = f.port_id_raw & 0x0FFF;
        f.message_age = c.u16be() / 256.0;
        f.max_age = c.u16be() / 256.0;
        f.hello_time = c.u16be() / 256.0;
        f.forward_delay = c.u16be() / 256.0;
        // c.position() == 35 here.

        if (type == 0x00) {
            std::ostringstream s;
            s << (f.protocol_version == 0 ? "STP Configuration" : (f.bpdu_type_name + " BPDU (version " +
                  std::to_string(static_cast<unsigned>(version)) + ")"))
              << ": Root=" << render_bridge_id(f.root_id) << " Cost=" << f.root_path_cost
              << " Bridge=" << render_bridge_id(f.bridge_id) << " Port=0x" << std::hex
              << std::uppercase << std::setw(4) << std::setfill('0') << f.port_id_raw << std::dec;
            if (f.flag_tc) s << " [TC]";
            if (f.flag_tca) s << " [TCA]";
            f.summary = s.str();
            if (f.protocol_version != 0) {
                f.notes.push_back("BPDU Type 0x00 (Configuration) with Protocol Version " +
                                   std::to_string(static_cast<unsigned>(version)) +
                                   " -- an unusual combination (classic Configuration BPDUs are "
                                   "conventionally version 0), decoded structurally anyway");
            }
            if (c.remaining() > 0) {
                f.notes.push_back(std::to_string(c.remaining()) +
                                   " byte(s) remain after the 35-byte Configuration BPDU body -- "
                                   "a plain Configuration BPDU carries nothing further, ignored");
            }
            return f;
        }

        // --- Type 0x02: RST BPDU (version_1_length onward), possibly extending into a full MST
        // BPDU -- see stp.hpp's file header comment. Decoded regardless of what `version` actually
        // says (matching the reference source's own tolerant behavior exactly).
        if (c.remaining() < 1) {
            f.notes.push_back("Version 1 Length byte (offset 35) missing -- frame truncated right "
                               "after the common body; decoded as RST-shaped with no trailer");
            std::ostringstream s;
            s << "RST/MST BPDU (" << f.protocol_version_name << "): Root=" << render_bridge_id(f.root_id)
              << " Cost=" << f.root_path_cost << " Bridge=" << render_bridge_id(f.bridge_id)
              << " (truncated -- no Version 1 Length)";
            f.summary = s.str();
            return f;
        }
        f.has_version1 = true;
        f.version_1_length = c.u8();  // offset 35; c.position() == 36 now

        auto render_rst_summary = [&]() {
            std::ostringstream s;
            s << (version == 3 ? "MSTP" : (version == 2 ? "RSTP" : f.protocol_version_name))
              << " BPDU: Root=" << render_bridge_id(f.root_id) << " Cost=" << f.root_path_cost
              << " Bridge=" << render_bridge_id(f.bridge_id) << " Port=0x" << std::hex
              << std::uppercase << std::setw(4) << std::setfill('0') << f.port_id_raw << std::dec
              << " Role=" << stp_port_role_name(f.flag_port_role);
            if (f.flag_tc) s << " [TC]";
            if (f.flag_tca) s << " [TCA]";
            if (f.flag_proposal) s << " [Proposal]";
            if (f.flag_agreement) s << " [Agreement]";
            if (f.flag_learning) s << " [Learning]";
            if (f.flag_forwarding) s << " [Forwarding]";
            return s.str();
        };

        // The three-part MSTP detection gate -- see stp.hpp's file header comment. Uses the WHOLE
        // BPDU body's size (not just what's been consumed so far), matching the reference source's
        // own `tvb_reported_length(tvb) >= 102` check exactly.
        bool attempt_mst = (version >= 3) && (f.version_1_length == 0) && (llc_payload.size() >= 102);
        if (!attempt_mst) {
            f.summary = render_rst_summary();
            if (version >= 3 && f.version_1_length != 0) {
                f.notes.push_back("Protocol Version " + std::to_string(static_cast<unsigned>(version)) +
                                   " but Version 1 Length is " +
                                   std::to_string(static_cast<unsigned>(f.version_1_length)) +
                                   " (not 0) -- MST extension not attempted, decoded as a plain RST "
                                   "BPDU (matches the reference source's own behavior exactly)");
            } else if (version >= 3 && llc_payload.size() < 102) {
                f.notes.push_back("Protocol Version " + std::to_string(static_cast<unsigned>(version)) +
                                   " but only " + std::to_string(llc_payload.size()) +
                                   " byte(s) present (need >= 102) -- MST extension not attempted, "
                                   "decoded as a plain RST BPDU");
            }
            return f;
        }

        // --- Full MST extension ---
        f.is_mstp = true;
        f.version_3_length = c.u16be();          // offset 36-37; pos == 38
        f.mst_config_format_selector = c.u8();   // offset 38; pos == 39
        f.mst_config_name = trim_nul_padded(c.bytes(32));  // offset 39..70; pos == 71
        f.mst_config_revision_level = c.u16be(); // offset 71-72; pos == 73
        f.mst_config_digest_hex = to_hex(c.bytes(16), "");  // offset 73..88; pos == 89

        // Version 3 Length == 0 is the legacy/alternative MSTI format's own trigger condition (see
        // stp.hpp's file header comment) -- and CIST Bridge Identifier/Root Path Cost genuinely
        // live at DIFFERENT byte offsets in that format (ALT_BPDU_CIST_BRIDGE_IDENTIFIER == 89, vs.
        // this (IEEE) format's 93) than the fixed IEEE offsets this decoder reads below. Reading the
        // IEEE offsets anyway for a Version-3-Length-0 frame would produce misleading, meaningless
        // values (whatever bytes happen to sit there), not a decode of anything real -- so this
        // decoder deliberately does NOT read cist_internal_root_path_cost/cist_bridge_id/
        // cist_remaining_hops or attempt any MSTI Configuration Message in that case at all,
        // regardless of whether the alt-format's own byte-count trigger matches exactly or not
        // (an exact match is named as such; anything else is simply "not decoded", the same honest
        // "out of scope" treatment either way).
        size_t total_msti_length = 0;
        if (f.version_3_length != 0) {
            f.cist_internal_root_path_cost = c.u32be();  // offset 89-92; pos == 93
            f.cist_bridge_id = read_bridge_id(c);         // offset 93..100; pos == 101
            f.cist_remaining_hops = c.u8();               // offset 101; pos == 102

            // total_msti_length arithmetic -- see stp.hpp's file header comment for the reference
            // source's own (non-obvious) rules this reproduces exactly.
            if (f.version_3_length >= 64) {
                total_msti_length = static_cast<size_t>(f.version_3_length) - 64;
            } else {
                total_msti_length = static_cast<size_t>(f.version_3_length) * 16;
                f.notes.push_back("Version 3 Length (" + std::to_string(f.version_3_length) +
                                   ") is nonzero but less than the 64-byte static MST extension "
                                   "header -- treated as a COUNT OF MESSAGES rather than bytes, per "
                                   "the reference source's own Cisco-C3550-firmware work-around "
                                   "(see stp.hpp)");
            }
        } else {
            size_t alt_expected_len = static_cast<size_t>(f.mst_config_format_selector) + 38 + 1;
            if (llc_payload.size() == alt_expected_len) {
                f.is_alt_msti_format = true;
                f.notes.push_back("Version 3 Length is 0 and the frame's total length matches the "
                                   "legacy/alternative MSTI Configuration Message format's own "
                                   "sizing rule -- that format is not decoded by this release, see "
                                   "stp.hpp's file header comment");
            } else {
                f.notes.push_back("Version 3 Length is 0 and the frame's total length doesn't match "
                                   "the legacy/alternative MSTI format's own sizing rule either -- "
                                   "CIST Bridge Identifier and MSTI Configuration Message(s), if "
                                   "any, are not decoded (their offsets are format-dependent)");
            }

            std::ostringstream s;
            s << "MSTP BPDU: CIST Root=" << render_bridge_id(f.root_id) << " Cost=" << f.root_path_cost
              << " Bridge=" << render_bridge_id(f.bridge_id) << " MST Config Name=\""
              << f.mst_config_name << "\" (CIST Bridge Identifier/MSTI not decoded -- Version 3 "
              << "Length is 0, see notes)";
            f.summary = s.str();
            return f;
        }

        size_t available_after_cist = c.remaining();
        if (total_msti_length > available_after_cist) {
            f.notes.push_back("Version 3 Length implies " + std::to_string(total_msti_length) +
                               " byte(s) of MSTI Configuration Message(s) but only " +
                               std::to_string(available_after_cist) +
                               " byte(s) remain -- decoding as many whole messages as fit");
            total_msti_length = available_after_cist;
        }
        size_t whole_messages = total_msti_length / 16;
        size_t leftover = total_msti_length % 16;
        if (leftover != 0) {
            f.notes.push_back("Version 3 Length implies a partial trailing MSTI Configuration "
                               "Message (" + std::to_string(leftover) +
                               " byte(s) leftover) -- not decoded");
        }
        if (whole_messages > kMaxStpMstiMessages) {
            f.notes.push_back("stopped after " + std::to_string(kMaxStpMstiMessages) +
                               " MSTI Configuration Message(s) (safety cap, " +
                               std::to_string(whole_messages) + " implied by Version 3 Length)");
            whole_messages = kMaxStpMstiMessages;
        }
        for (size_t i = 0; i < whole_messages; ++i) {
            f.msti_messages.push_back(decode_msti_message(c));
        }

        std::ostringstream s;
        s << "MSTP BPDU: CIST Root=" << render_bridge_id(f.root_id) << " Cost=" << f.root_path_cost
          << " CIST RegionalRoot=" << render_bridge_id(f.cist_bridge_id) << " Bridge="
          << render_bridge_id(f.bridge_id) << " MSTIs=" << f.msti_messages.size();
        if (f.flag_tc) s << " [TC]";
        if (f.flag_tca) s << " [TCA]";
        f.summary = s.str();

        if (c.remaining() > 0) {
            f.notes.push_back(std::to_string(c.remaining()) +
                               " byte(s) remain after the last decoded MSTI Configuration Message "
                               "-- ignored");
        }
        return f;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // goose.cpp/profinet.cpp take.
        return std::nullopt;
    }
}

}  // namespace conduitscope
