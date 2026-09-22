// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/it_protocols.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <iomanip>
#include <sstream>
#include <utility>

namespace conduitscope {

namespace {

bool port_in(uint16_t port, uint16_t default_port, const std::vector<uint16_t>& extra) {
    if (port == default_port) return true;
    return std::find(extra.begin(), extra.end(), port) != extra.end();
}

bool port_in_range(uint16_t port, uint16_t range_start, uint16_t range_end,
                    const std::vector<uint16_t>& extra) {
    if (port >= range_start && port <= range_end) return true;
    return std::find(extra.begin(), extra.end(), port) != extra.end();
}

bool is_vnc_port(uint16_t port, const std::vector<uint16_t>& extra) {
    return port_in_range(port, VNC_PORT_BASE, static_cast<uint16_t>(VNC_PORT_BASE + VNC_PORT_MAX_DISPLAY),
                          extra);
}

bool is_zoom_port(uint16_t port, const std::vector<uint16_t>& extra) {
    return port_in_range(port, ZOOM_PORT_RANGE_START, ZOOM_PORT_RANGE_END, extra) ||
           port_in_range(port, ZOOM_STUN_PORT_START, ZOOM_STUN_PORT_END, extra);
}

// RFC 6143 section 7.1.1: "ProtocolVersion" -- the very first bytes an RFB (VNC) server ever sends,
// always exactly 12 bytes, always this exact ASCII shape: "RFB " + 3 digits + "." + 3 digits + "\n".
// Every real-world RFB version this decoder's own research found (003.003, 003.007, 003.008 --
// classic VNC/RealVNC/TightVNC's usual choice -- 003.889 -- Apple Remote Desktop's own variant --
// 004.000/004.001 -- TigerVNC -- 005.000 -- RealVNC 5.x) fits this same fixed-width digit shape, so
// this check is exact, not a loose byte-range guess the way the port-only protocols below have to
// be.
std::optional<std::string> match_rfb_banner(ByteSpan payload) {
    if (payload.size() < 12) return std::nullopt;
    auto byte_at = [&](size_t i) { return payload.at(i); };
    if (byte_at(0) != 'R' || byte_at(1) != 'F' || byte_at(2) != 'B' || byte_at(3) != ' ') return std::nullopt;
    for (size_t i : {4, 5, 6, 8, 9, 10}) {
        if (byte_at(i) < '0' || byte_at(i) > '9') return std::nullopt;
    }
    if (byte_at(7) != '.' || byte_at(11) != '\n') return std::nullopt;
    std::string version;
    for (size_t i = 4; i < 11; ++i) version += static_cast<char>(byte_at(i));
    return version;
}

}  // namespace

std::optional<ItRemoteAccessMatch> try_recognize_it_remote_access(ByteSpan payload, uint16_t src_port,
                                                                    uint16_t dst_port, bool is_tcp,
                                                                    const std::vector<uint16_t>& extra_ports) {
    // VNC's RFB banner -- checked FIRST and port-independently, since it's this whole file's one
    // genuinely strong, cleartext structural signature (see file header comment): a real VNC server
    // running on a nonstandard port is still confidently identified, not missed.
    if (is_tcp) {
        if (auto version = match_rfb_banner(payload)) {
            ItRemoteAccessMatch m;
            m.protocol = "vnc";
            m.summary = "VNC (RFB) server protocol-version banner \"RFB " + *version + "\"";
            if (!is_vnc_port(src_port, extra_ports) && !is_vnc_port(dst_port, extra_ports)) {
                m.notes.push_back("seen on TCP port " + std::to_string(src_port) + "->" +
                                   std::to_string(dst_port) +
                                   ", which is not a configured/standard VNC port (5900-5906)");
            }
            return m;
        }
    }

    // Everything below this point is a port-only match -- no payload content is consulted at all.
    // RDP's own structural check (its X.224 Connection Request/Confirm) is NOT here -- see this
    // file's header comment and decoder.cpp's own call site for why it has to run earlier, directly
    // in decoder.cpp, before the S7comm/MMS dispatch that shares its TPKT/COTP framing. By the time
    // this function is reached, port 3389 traffic that WAS a genuine RDP handshake has already been
    // claimed there; what's left is real subsequent (already-established, encrypted) RDP traffic.
    // This is deliberately the weakest identification tier in this entire codebase (see file header
    // comment): every match produced here says so explicitly in its own summary/notes, rather than
    // presenting the same confidence VNC's banner or RDP's COTP framing above can back up.
    if (port_in(src_port, RDP_PORT, extra_ports) || port_in(dst_port, RDP_PORT, extra_ports)) {
        ItRemoteAccessMatch m;
        m.protocol = "rdp";
        m.summary = "RDP (TCP port " + std::to_string(RDP_PORT) +
                     ") -- port match only, not confirmed by an X.224 Connection Request/Confirm in "
                     "this packet (an already-established, encrypted RDP session looks like this)";
        return m;
    }
    if (is_vnc_port(src_port, extra_ports) || is_vnc_port(dst_port, extra_ports)) {
        ItRemoteAccessMatch m;
        m.protocol = "vnc";
        m.summary = "VNC (TCP port 5900-5906 range) -- port match only, not confirmed by an RFB "
                     "protocol-version banner in this packet (an already-established VNC session "
                     "looks like this)";
        return m;
    }
    if (port_in(src_port, TEAMVIEWER_PORT, extra_ports) || port_in(dst_port, TEAMVIEWER_PORT, extra_ports)) {
        ItRemoteAccessMatch m;
        m.protocol = "teamviewer";
        std::ostringstream s;
        s << "TeamViewer (" << (is_tcp ? "TCP" : "UDP") << " port " << TEAMVIEWER_PORT
          << ") -- port match only; TeamViewer's own wire protocol is encrypted from its first byte, "
             "so no stronger structural signature exists to check";
        m.summary = s.str();
        return m;
    }
    if (port_in(src_port, ANYDESK_PORT, extra_ports) || port_in(dst_port, ANYDESK_PORT, extra_ports)) {
        ItRemoteAccessMatch m;
        m.protocol = "anydesk";
        std::ostringstream s;
        s << "AnyDesk (" << (is_tcp ? "TCP" : "UDP") << " port " << ANYDESK_PORT
          << ", AnyDesk's own documented default) -- port match only; AnyDesk's own wire protocol is "
             "encrypted from its first byte, so no stronger structural signature exists to check";
        m.summary = s.str();
        return m;
    }
    if (is_zoom_port(src_port, extra_ports) || is_zoom_port(dst_port, extra_ports)) {
        ItRemoteAccessMatch m;
        m.protocol = "zoom";
        bool is_stun_port = port_in_range(src_port, ZOOM_STUN_PORT_START, ZOOM_STUN_PORT_END, extra_ports) ||
                             port_in_range(dst_port, ZOOM_STUN_PORT_START, ZOOM_STUN_PORT_END, extra_ports);
        std::ostringstream s;
        s << "Zoom (" << (is_tcp ? "TCP" : "UDP") << " port ";
        if (is_stun_port) {
            s << ZOOM_STUN_PORT_START << "-" << ZOOM_STUN_PORT_END
              << " STUN range) -- port match only; this range is a shared STUN convention, not "
                 "exclusive to Zoom (other WebRTC-based video/conferencing tools commonly use it "
                 "too), and Zoom's own wire protocol is encrypted from its first byte regardless, so "
                 "no stronger structural signature exists to check";
        } else {
            s << ZOOM_PORT_RANGE_START << "-" << ZOOM_PORT_RANGE_END
              << " client range, per Zoom's own documented port usage) -- port match only; Zoom's "
                 "own wire protocol is encrypted from its first byte, so no stronger structural "
                 "signature exists to check";
        }
        m.summary = s.str();
        return m;
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------
// Tier 2 -- see it_protocols.hpp's own header comment for the full per-protocol confidence writeup.

namespace {

// Matches the 4-byte SMB magic (0xFF/0xFE/0xFD + "SMB") at `offset` within `payload`. Returns a
// human-readable label naming which SMB generation/framing it is, or std::nullopt if it doesn't
// match at all.
std::optional<std::string> match_smb_magic(ByteSpan payload, size_t offset) {
    if (payload.size() < offset + 4) return std::nullopt;
    uint8_t b0 = payload.at(offset);
    if (b0 != 0xFF && b0 != 0xFE && b0 != 0xFD) return std::nullopt;
    if (payload.at(offset + 1) != 'S' || payload.at(offset + 2) != 'M' || payload.at(offset + 3) != 'B') {
        return std::nullopt;
    }
    if (b0 == 0xFF) return std::string("SMB1 (CIFS) header, 0xFF\"SMB\" magic");
    if (b0 == 0xFE) return std::string("SMB2/SMB3 header, 0xFE\"SMB\" magic");
    return std::string("SMB2/SMB3 Transform (encrypted) header, 0xFD\"SMB\" magic");
}

// RFC 4253 section 4.2's own version-exchange banner: "SSH-" + protoversion + "-" + a software
// version/comment field, CR- or LF-terminated, max 255 bytes including the terminator. Returns the
// full banner line (without its terminator) on a match.
std::optional<std::string> match_ssh_banner(ByteSpan payload) {
    static const char kPrefix[] = "SSH-";
    if (payload.size() < 6) return std::nullopt;
    for (size_t i = 0; i < 4; ++i) {
        if (payload.at(i) != static_cast<uint8_t>(kPrefix[i])) return std::nullopt;
    }
    size_t limit = std::min<size_t>(payload.size(), 255);
    size_t line_end = 0;
    bool found_end = false;
    for (size_t i = 4; i < limit; ++i) {
        uint8_t c = payload.at(i);
        if (c == '\r' || c == '\n') {
            line_end = i;
            found_end = true;
            break;
        }
    }
    if (!found_end) return std::nullopt;  // truncated within this segment -- not confirmed
    // Require a "-" delimiting protoversion from softwareversion, with at least one digit before it
    // (e.g. "2.0-" or "1.99-") -- this is what actually distinguishes a real banner from four
    // arbitrary "SSH-" bytes at the start of unrelated traffic.
    size_t dash = 0;
    bool found_dash = false;
    for (size_t i = 4; i < line_end; ++i) {
        if (payload.at(i) == '-') {
            dash = i;
            found_dash = true;
            break;
        }
    }
    if (!found_dash || dash == 4) return std::nullopt;
    bool saw_digit = false;
    for (size_t i = 4; i < dash; ++i) {
        uint8_t c = payload.at(i);
        if (c >= '0' && c <= '9') {
            saw_digit = true;
        } else if (c != '.') {
            return std::nullopt;  // protoversion must be digits and dots only
        }
    }
    if (!saw_digit) return std::nullopt;
    std::string line;
    for (size_t i = 0; i < line_end; ++i) line += static_cast<char>(payload.at(i));
    return line;
}

// RFC 9112's request-line/status-line shape. Returns a short description on a match; checks only
// the first (at most) 256 bytes, since a real request-line/status-line is always short.
std::optional<std::string> match_http(ByteSpan payload) {
    static const std::vector<std::string> kVerbs = {"GET",  "POST", "PUT",     "DELETE", "HEAD",
                                                       "OPTIONS", "PATCH", "CONNECT", "TRACE"};
    size_t limit = std::min<size_t>(payload.size(), 256);
    std::string prefix;
    for (size_t i = 0; i < limit; ++i) prefix += static_cast<char>(payload.at(i));

    for (const auto& verb : kVerbs) {
        std::string needle = verb + " ";
        if (prefix.size() < needle.size() || prefix.compare(0, needle.size(), needle) != 0) continue;
        if (prefix.find(" HTTP/1.") != std::string::npos || prefix.find(" HTTP/2") != std::string::npos ||
            prefix.find(" HTTP/0.9") != std::string::npos) {
            return "HTTP request (" + verb + " ...)";
        }
    }
    static const std::vector<std::string> kStatusPrefixes = {"HTTP/1.0 ", "HTTP/1.1 ", "HTTP/2 ",
                                                                "HTTP/0.9 "};
    for (const auto& sp : kStatusPrefixes) {
        if (prefix.size() < sp.size() + 3 || prefix.compare(0, sp.size(), sp) != 0) continue;
        bool digits = true;
        for (size_t i = 0; i < 3; ++i) {
            char c = prefix[sp.size() + i];
            if (c < '0' || c > '9') { digits = false; break; }
        }
        if (digits) {
            std::string code = prefix.substr(sp.size(), 3);
            return "HTTP response (status " + code + ")";
        }
    }
    return std::nullopt;
}

// IAC (0xFF) + WILL/WONT/DO/DONT (0xFB-0xFE) + one option byte, RFC 854 -- returns true on at
// least one well-formed triplet anywhere in the payload (real sessions send several back-to-back
// at connection start, but this doesn't insist on that).
bool has_telnet_negotiation(ByteSpan payload) {
    if (payload.size() < 3) return false;
    for (size_t i = 0; i + 2 < payload.size(); ++i) {
        if (payload.at(i) != 0xFF) continue;
        uint8_t cmd = payload.at(i + 1);
        if (cmd == 0xFB || cmd == 0xFC || cmd == 0xFD || cmd == 0xFE) return true;
    }
    return false;
}

// A 3-digit FTP reply code (RFC 959 4.2) followed by ' ' (final line) or '-' (start of a multiline
// reply), or a known command verb followed by ' ', CR, LF, or end-of-buffer.
std::optional<std::string> match_ftp(ByteSpan payload) {
    if (payload.size() >= 4) {
        bool digits = true;
        for (size_t i = 0; i < 3; ++i) {
            uint8_t c = payload.at(i);
            if (c < '0' || c > '9') { digits = false; break; }
        }
        if (digits) {
            uint8_t c3 = payload.at(3);
            if (c3 == ' ' || c3 == '-') {
                std::string code;
                for (size_t i = 0; i < 3; ++i) code += static_cast<char>(payload.at(i));
                return "FTP reply code " + code;
            }
        }
    }
    static const std::vector<std::string> kVerbs = {
        "USER", "PASS", "ACCT", "CWD",  "CDUP", "SMNT", "QUIT", "REIN", "PORT", "PASV",
        "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU", "APPE", "ALLO", "REST", "RNFR",
        "RNTO", "ABOR", "DELE", "RMD",  "MKD",  "PWD",  "LIST", "NLST", "SITE", "SYST",
        "STAT", "HELP", "NOOP", "FEAT", "EPSV", "EPRT"};
    for (const auto& verb : kVerbs) {
        if (payload.size() < verb.size()) continue;
        bool match = true;
        for (size_t i = 0; i < verb.size(); ++i) {
            if (payload.at(i) != static_cast<uint8_t>(verb[i])) { match = false; break; }
        }
        if (!match) continue;
        if (payload.size() == verb.size()) return "FTP command \"" + verb + "\"";
        uint8_t next = payload.at(verb.size());
        if (next == ' ' || next == '\r' || next == '\n') return "FTP command \"" + verb + "\"";
    }
    return std::nullopt;
}

// Minimal BER length decoder (definite form only, short or up to 4 long-form length bytes --
// ample for anything SNMP's own SEQUENCE/INTEGER/OCTET STRING triple ever needs). Returns
// {length, bytes-this-length-field-itself-consumed}, or std::nullopt if malformed/out-of-range.
std::optional<std::pair<size_t, size_t>> ber_length(ByteSpan payload, size_t offset) {
    if (offset >= payload.size()) return std::nullopt;
    uint8_t b0 = payload.at(offset);
    if ((b0 & 0x80) == 0) return std::make_pair(static_cast<size_t>(b0), static_cast<size_t>(1));
    size_t num_len_bytes = b0 & 0x7F;
    if (num_len_bytes == 0 || num_len_bytes > 4) return std::nullopt;  // indefinite form, or absurd
    if (offset + 1 + num_len_bytes > payload.size()) return std::nullopt;
    size_t len = 0;
    for (size_t i = 0; i < num_len_bytes; ++i) len = (len << 8) | payload.at(offset + 1 + i);
    return std::make_pair(len, static_cast<size_t>(1 + num_len_bytes));
}

struct SnmpMatch {
    int version = 0;  // 0 = v1, 1 = v2c
    std::string community;
};

// SEQUENCE { INTEGER version, OCTET STRING community, ... } -- the fixed prefix every SNMPv1/v2c
// PDU shares (RFC 1157/RFC 1901). Deliberately requires the community string to be printable ASCII
// -- a real one always is, and requiring it is what keeps this from false-positiving on arbitrary
// binary UDP traffic that happens to start with a plausible-looking SEQUENCE/INTEGER shape.
std::optional<SnmpMatch> match_snmpv1v2c(ByteSpan payload) {
    if (payload.size() < 2 || payload.at(0) != 0x30) return std::nullopt;  // SEQUENCE
    auto seq_len = ber_length(payload, 1);
    if (!seq_len) return std::nullopt;
    size_t pos = 1 + seq_len->second;

    if (pos >= payload.size() || payload.at(pos) != 0x02) return std::nullopt;  // INTEGER
    auto int_len = ber_length(payload, pos + 1);
    if (!int_len || int_len->first < 1 || int_len->first > 4) return std::nullopt;
    pos = pos + 1 + int_len->second;
    if (pos + int_len->first > payload.size()) return std::nullopt;
    int version = 0;
    for (size_t i = 0; i < int_len->first; ++i) version = (version << 8) | payload.at(pos + i);
    pos += int_len->first;
    if (version != 0 && version != 1) return std::nullopt;  // only v1/v2c -- v3 has no cleartext
                                                               // community string, see file header

    if (pos >= payload.size() || payload.at(pos) != 0x04) return std::nullopt;  // OCTET STRING
    auto str_len = ber_length(payload, pos + 1);
    if (!str_len) return std::nullopt;
    pos = pos + 1 + str_len->second;
    if (pos + str_len->first > payload.size()) return std::nullopt;
    if (str_len->first == 0 || str_len->first > 128) return std::nullopt;  // a real community string
                                                                              // is always short
    std::string community;
    for (size_t i = 0; i < str_len->first; ++i) {
        uint8_t c = payload.at(pos + i);
        if (c < 0x20 || c > 0x7e) return std::nullopt;  // must be printable ASCII, see comment above
        community += static_cast<char>(c);
    }
    SnmpMatch m;
    m.version = version;
    m.community = community;
    return m;
}

// TFTP RRQ/WRQ (opcode 1/2, RFC 1350 section 5): opcode + NUL-terminated filename + NUL-terminated
// mode ("netascii"/"octet"/"mail", case-insensitive). Deliberately does not attempt to parse the
// optional RFC 2347 option/value pairs some RRQ/WRQ packets append -- naming the request is enough.
std::optional<std::string> match_tftp_request(ByteSpan payload) {
    if (payload.size() < 4) return std::nullopt;
    uint16_t opcode = (static_cast<uint16_t>(payload.at(0)) << 8) | payload.at(1);
    if (opcode != 1 && opcode != 2) return std::nullopt;

    size_t pos = 2;
    std::string filename;
    while (pos < payload.size() && payload.at(pos) != 0) {
        uint8_t c = payload.at(pos);
        if (c < 0x20 || c > 0x7e) return std::nullopt;
        filename += static_cast<char>(c);
        ++pos;
        if (filename.size() > 255) return std::nullopt;
    }
    if (pos >= payload.size() || filename.empty()) return std::nullopt;
    ++pos;  // skip filename's NUL terminator

    std::string mode;
    while (pos < payload.size() && payload.at(pos) != 0) {
        uint8_t c = payload.at(pos);
        if (c < 0x20 || c > 0x7e) return std::nullopt;
        mode += static_cast<char>(c);
        ++pos;
        if (mode.size() > 16) return std::nullopt;
    }
    if (mode.empty()) return std::nullopt;
    std::string mode_lower = mode;
    std::transform(mode_lower.begin(), mode_lower.end(), mode_lower.begin(),
                    [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (mode_lower != "netascii" && mode_lower != "octet" && mode_lower != "mail") return std::nullopt;

    std::string op_name = (opcode == 1) ? "RRQ (read request)" : "WRQ (write request)";
    return op_name + " for \"" + filename + "\", mode " + mode;
}

}  // namespace

bool looks_like_ftp_control_line(ByteSpan payload) { return match_ftp(payload).has_value(); }

// ---------------------------------------------------------------------------------------------
// Tier 3 -- see it_protocols.hpp's own header comment for the full per-protocol confidence writeup.

namespace {

// RFC 5905 section 7.3's first byte: LI(2 bits)/VN(3 bits)/Mode(3 bits), plus the minimum 48-byte
// NTPv3/v4 fixed header. Returns a short Mode name on a match.
std::optional<std::string> match_ntp(ByteSpan payload) {
    if (payload.size() < 48) return std::nullopt;
    uint8_t b0 = payload.at(0);
    uint8_t vn = (b0 >> 3) & 0x07;
    uint8_t mode = b0 & 0x07;
    if (vn < 1 || vn > 4) return std::nullopt;
    std::string mode_name;
    switch (mode) {
        case 1: mode_name = "symmetric active"; break;
        case 2: mode_name = "symmetric passive"; break;
        case 3: mode_name = "client"; break;
        case 4: mode_name = "server"; break;
        case 5: mode_name = "broadcast"; break;
        case 6: mode_name = "NTP control message"; break;
        default: return std::nullopt;  // 0 and 7 are reserved -- not a plausible real packet
    }
    return "NTPv" + std::to_string(static_cast<unsigned>(vn)) + " " + mode_name;
}

// RFC 2132 section 9.6 (DHCP Message Type, option 53) name lookup.
std::string dhcp_message_type_name(uint8_t t) {
    switch (t) {
        case 1: return "DISCOVER";
        case 2: return "OFFER";
        case 3: return "REQUEST";
        case 4: return "DECLINE";
        case 5: return "ACK";
        case 6: return "NAK";
        case 7: return "RELEASE";
        case 8: return "INFORM";
        case 9: return "FORCERENEW";     // RFC 3203
        case 10: return "LEASEQUERY";    // RFC 4388
        case 11: return "LEASEUNASSIGNED";
        case 12: return "LEASEUNKNOWN";
        case 13: return "LEASEACTIVE";
        default: return "";
    }
}

struct DhcpMatch {
    uint8_t op = 0;               // 1 = BOOTREQUEST, 2 = BOOTREPLY
    bool has_message_type = false;
    uint8_t message_type = 0;
    std::string message_type_name;
};

// RFC 2131's fixed 236-byte BOOTP-derived header followed by RFC 1497/2131 section 3's own 4-byte
// magic cookie (0x63825363) -- see it_protocols.hpp's own header comment for why this is checked
// port-independently. Also scans the TLV options that follow for option 53 (DHCP Message Type,
// RFC 2132 section 9.6), stopping at End (0xFF) or if the options run out.
std::optional<DhcpMatch> match_dhcp(ByteSpan payload) {
    static constexpr size_t kFixedHeaderLen = 236;
    static constexpr std::array<uint8_t, 4> kMagicCookie = {0x63, 0x82, 0x53, 0x63};
    if (payload.size() < kFixedHeaderLen + 4) return std::nullopt;
    for (size_t i = 0; i < 4; ++i) {
        if (payload.at(kFixedHeaderLen + i) != kMagicCookie[i]) return std::nullopt;
    }
    uint8_t op = payload.at(0);
    if (op != 1 && op != 2) return std::nullopt;

    DhcpMatch m;
    m.op = op;

    size_t pos = kFixedHeaderLen + 4;
    while (pos < payload.size()) {
        uint8_t code = payload.at(pos);
        if (code == 0xFF) break;   // End
        if (code == 0x00) { ++pos; continue; }  // Pad
        if (pos + 1 >= payload.size()) break;
        uint8_t opt_len = payload.at(pos + 1);
        if (pos + 2 + opt_len > payload.size()) break;  // truncated option -- stop scanning
        if (code == 53 && opt_len == 1) {
            m.has_message_type = true;
            m.message_type = payload.at(pos + 2);
            m.message_type_name = dhcp_message_type_name(m.message_type);
        }
        pos += 2 + opt_len;
    }
    return m;
}

// RFC 4511 section 4.1's LDAPMessage envelope: SEQUENCE { INTEGER messageID, protocolOp [APPLICATION
// n], ... }. Returns the protocolOp's name and its raw application-tag number on a match.
std::string ldap_protocol_op_name(uint8_t op_num) {
    switch (op_num) {
        case 0: return "bindRequest";
        case 1: return "bindResponse";
        case 2: return "unbindRequest";
        case 3: return "searchRequest";
        case 4: return "searchResEntry";
        case 5: return "searchResDone";
        case 6: return "modifyRequest";
        case 7: return "modifyResponse";
        case 8: return "addRequest";
        case 9: return "addResponse";
        case 10: return "delRequest";
        case 11: return "delResponse";
        case 12: return "modDNRequest";
        case 13: return "modDNResponse";
        case 14: return "compareRequest";
        case 15: return "compareResponse";
        case 16: return "abandonRequest";
        case 19: return "searchResRef";
        case 23: return "extendedReq";
        case 24: return "extendedResp";
        case 25: return "intermediateResponse";
        default: return "";
    }
}

struct LdapMatch {
    std::string op_name;
    uint8_t op_num = 0;
};

std::optional<LdapMatch> match_ldap_ber(ByteSpan payload) {
    if (payload.size() < 7 || payload.at(0) != 0x30) return std::nullopt;  // SEQUENCE
    auto seq_len = ber_length(payload, 1);
    if (!seq_len) return std::nullopt;
    size_t pos = 1 + seq_len->second;

    if (pos >= payload.size() || payload.at(pos) != 0x02) return std::nullopt;  // INTEGER messageID
    auto int_len = ber_length(payload, pos + 1);
    if (!int_len || int_len->first < 1 || int_len->first > 4) return std::nullopt;
    pos = pos + 1 + int_len->second;
    if (pos + int_len->first > payload.size()) return std::nullopt;
    pos += int_len->first;

    if (pos >= payload.size()) return std::nullopt;
    uint8_t op_tag = payload.at(pos);
    if ((op_tag & 0xC0) != 0x40) return std::nullopt;  // must be [APPLICATION n]
    uint8_t op_num = op_tag & 0x1F;
    std::string name = ldap_protocol_op_name(op_num);
    if (name.empty()) return std::nullopt;

    LdapMatch m;
    m.op_name = name;
    m.op_num = op_num;
    return m;
}

// RFC 2865 section 3's own enumerated Code values (plus RFC 5176's Dynamic Authorization extension).
std::string radius_code_name(uint8_t code) {
    switch (code) {
        case 1: return "Access-Request";
        case 2: return "Access-Accept";
        case 3: return "Access-Reject";
        case 4: return "Accounting-Request";
        case 5: return "Accounting-Response";
        case 11: return "Access-Challenge";
        case 12: return "Status-Server";
        case 13: return "Status-Client";
        case 40: return "Disconnect-Request";
        case 41: return "Disconnect-ACK";
        case 42: return "Disconnect-NAK";
        case 43: return "CoA-Request";
        case 44: return "CoA-ACK";
        case 45: return "CoA-NAK";
        default: return "";
    }
}

struct RadiusMatch {
    std::string code_name;
    uint8_t identifier = 0;
    uint16_t declared_length = 0;
};

// RFC 2865 section 3's fixed 20-byte header: Code(1) + Identifier(1) + Length(2, big-endian,
// "20 <= Length <= 4096") + a 16-byte Authenticator this file never inspects.
std::optional<RadiusMatch> match_radius(ByteSpan payload) {
    if (payload.size() < 20) return std::nullopt;
    uint8_t code = payload.at(0);
    std::string name = radius_code_name(code);
    if (name.empty()) return std::nullopt;
    uint16_t length = static_cast<uint16_t>((payload.at(2) << 8) | payload.at(3));
    if (length < 20 || length > 4096) return std::nullopt;

    RadiusMatch m;
    m.code_name = name;
    m.identifier = payload.at(1);
    m.declared_length = length;
    return m;
}

std::string tacacs_type_name(uint8_t t) {
    switch (t) {
        case 1: return "Authentication";
        case 2: return "Authorization";
        case 3: return "Accounting";
        default: return "";
    }
}

struct TacacsMatch {
    uint8_t major_version = 0;
    uint8_t minor_version = 0;
    std::string type_name;
    bool unencrypted = false;
};

// RFC 8907's 12-byte fixed header: version(1) + type(1) + seq_no(1) + flags(1) + session_id(4) +
// length(4, big-endian body length, not re-validated against payload size here -- TACACS+ TCP
// streams routinely span multiple segments, unlike this file's other, single-datagram UDP checks).
std::optional<TacacsMatch> match_tacacs_plus(ByteSpan payload) {
    if (payload.size() < 12) return std::nullopt;
    uint8_t version = payload.at(0);
    uint8_t major = (version >> 4) & 0x0F;
    uint8_t minor = version & 0x0F;
    if (major != 0x0C) return std::nullopt;
    if (minor != 0x00 && minor != 0x01) return std::nullopt;

    uint8_t type = payload.at(1);
    std::string type_name = tacacs_type_name(type);
    if (type_name.empty()) return std::nullopt;

    TacacsMatch m;
    m.major_version = major;
    m.minor_version = minor;
    m.type_name = type_name;
    m.unencrypted = (payload.at(3) & 0x01) != 0;  // TAC_PLUS_UNENCRYPTED_FLAG
    return m;
}

}  // namespace

bool looks_like_ldap_ber(ByteSpan payload) { return match_ldap_ber(payload).has_value(); }

std::optional<ItEnterpriseTrustMatch> try_recognize_it_enterprise_trust(ByteSpan payload, uint16_t src_port,
                                                                          uint16_t dst_port, bool is_tcp,
                                                                          const std::vector<uint16_t>& extra_ports) {
    if (!is_tcp) {
        // 1. NTP -- gated to port 123 (see file header comment for why, unlike DHCP's magic cookie
        // below).
        if (port_in(src_port, NTP_PORT, extra_ports) || port_in(dst_port, NTP_PORT, extra_ports)) {
            ItEnterpriseTrustMatch m;
            m.protocol = "ntp";
            if (auto n = match_ntp(payload)) {
                m.summary = *n + " (UDP port " + std::to_string(NTP_PORT) + ")";
            } else {
                m.summary = "NTP (UDP port " + std::to_string(NTP_PORT) +
                             ") -- port match only, not a plausible NTP LI/VN/Mode header in this "
                             "packet (could be malformed, or NTP extension/MAC fields this file "
                             "doesn't parse further)";
            }
            return m;
        }
        // 2. DHCP -- magic cookie checked port-independently, same treatment VNC/SMB/SSH/HTTP get in
        // Tiers 1-2 (see file header comment).
        if (auto d = match_dhcp(payload)) {
            ItEnterpriseTrustMatch m;
            m.protocol = "dhcp";
            std::string op_name = (d->op == 1) ? "BOOTREQUEST" : "BOOTREPLY";
            std::ostringstream s;
            s << "DHCP " << op_name;
            if (d->has_message_type) {
                if (!d->message_type_name.empty()) {
                    s << " (" << d->message_type_name << ")";
                } else {
                    s << " (message type " << static_cast<unsigned>(d->message_type) << ", unrecognized)";
                }
            }
            m.summary = s.str();
            if (!port_in(src_port, DHCP_SERVER_PORT, extra_ports) && !port_in(dst_port, DHCP_SERVER_PORT, extra_ports) &&
                !port_in(src_port, DHCP_CLIENT_PORT, extra_ports) && !port_in(dst_port, DHCP_CLIENT_PORT, extra_ports)) {
                m.notes.push_back("seen on UDP port " + std::to_string(src_port) + "->" +
                                   std::to_string(dst_port) +
                                   ", which is not the standard DHCP port pair (67/68) -- a rogue or "
                                   "misconfigured DHCP server answering on an unexpected port is "
                                   "exactly what this port-independent check is meant to catch");
            }
            return m;
        }
        // 3. RADIUS -- gated to port 1812/1813 (current) or 1645/1646 (legacy); Code alone is not
        // self-describing enough to check opportunistically (see file header comment).
        if (port_in(src_port, RADIUS_AUTH_PORT, extra_ports) || port_in(dst_port, RADIUS_AUTH_PORT, extra_ports) ||
            port_in(src_port, RADIUS_ACCT_PORT, extra_ports) || port_in(dst_port, RADIUS_ACCT_PORT, extra_ports) ||
            port_in(src_port, RADIUS_AUTH_PORT_LEGACY, extra_ports) || port_in(dst_port, RADIUS_AUTH_PORT_LEGACY, extra_ports) ||
            port_in(src_port, RADIUS_ACCT_PORT_LEGACY, extra_ports) || port_in(dst_port, RADIUS_ACCT_PORT_LEGACY, extra_ports)) {
            ItEnterpriseTrustMatch m;
            m.protocol = "radius";
            if (auto r = match_radius(payload)) {
                m.summary = "RADIUS " + r->code_name + " (id=" + std::to_string(static_cast<unsigned>(r->identifier)) +
                             ", declared length " + std::to_string(r->declared_length) + ")";
            } else {
                m.summary = "RADIUS (UDP port 1812/1813/1645/1646) -- port match only, not a "
                             "plausible Code/Identifier/Length header in this packet";
            }
            return m;
        }
    } else {
        // 1. TACACS+ -- gated to port 49, same "not self-describing enough on its own" reasoning as
        // RADIUS/NTP above. Plain LDAP (formerly "1." here) moved to its own dedicated ldap.hpp full
        // ProtocolDecoder -- see this file's own header comment; match_ldap_ber/looks_like_ldap_ber
        // below are still used by it and by decoder.cpp's own MQTT-collision carve-out.
        if (port_in(src_port, TACACS_PLUS_PORT, extra_ports) || port_in(dst_port, TACACS_PLUS_PORT, extra_ports)) {
            ItEnterpriseTrustMatch m;
            m.protocol = "tacacs-plus";
            if (auto t = match_tacacs_plus(payload)) {
                std::ostringstream s;
                s << "TACACS+ " << t->type_name << " (v" << static_cast<unsigned>(t->major_version) << "."
                  << static_cast<unsigned>(t->minor_version) << ")";
                m.summary = s.str();
                if (t->unencrypted) {
                    m.notes.push_back("TAC_PLUS_UNENCRYPTED_FLAG set -- this session's body is sent "
                                       "in cleartext (RFC 8907 calls TACACS+'s own body \"encryption\" "
                                       "obfuscation at best even when this flag is clear)");
                }
            } else {
                m.summary = "TACACS+ (TCP port 49) -- port match only, not a plausible version/type "
                             "header in this packet (could be a continuation of a multi-segment "
                             "session)";
            }
            return m;
        }
        // 2. LDAPS port-only fallback -- the actual ClientHello structural check runs earlier in
        // decoder.cpp, reusing tls_sni.hpp (see it_protocols.hpp's own file header comment for why);
        // this only covers an already-established, fully-encrypted session on a configured LDAPS
        // port with no visible ClientHello in this particular packet.
        if (port_in(src_port, LDAPS_PORT, extra_ports) || port_in(dst_port, LDAPS_PORT, extra_ports) ||
            port_in(src_port, LDAPS_GC_PORT, extra_ports) || port_in(dst_port, LDAPS_GC_PORT, extra_ports)) {
            ItEnterpriseTrustMatch m;
            m.protocol = "ldaps";
            m.summary = "LDAPS/TLS (TCP port 636/3269) -- port match only, no TLS ClientHello in "
                         "this packet (an already-established, encrypted session looks like this)";
            return m;
        }
    }

    return std::nullopt;
}

std::optional<ItLateralMovementMatch> try_recognize_it_lateral_movement(ByteSpan payload, uint16_t src_port,
                                                                          uint16_t dst_port, bool is_tcp,
                                                                          const std::vector<uint16_t>& extra_ports) {
    if (is_tcp) {
        // 1. SMB direct-hosting magic -- port-independent, a genuinely strong signal (see file
        // header comment), same treatment VNC's RFB banner gets above.
        if (auto d = match_smb_magic(payload, 0)) {
            ItLateralMovementMatch m;
            m.protocol = "smb";
            m.summary = "SMB, direct TCP hosting (" + *d + ")";
            if (!port_in(src_port, SMB_PORT_445, extra_ports) && !port_in(dst_port, SMB_PORT_445, extra_ports)) {
                m.notes.push_back("seen on TCP port " + std::to_string(src_port) + "->" +
                                   std::to_string(dst_port) +
                                   ", which is not the configured/standard direct-hosting SMB port (445)");
            }
            return m;
        }
        // 2. SMB over a NetBIOS Session Service wrapper -- gated to port 139 (the wrapper's own
        // leading type byte alone is too common a value to check opportunistically, unlike the
        // direct-hosting magic above).
        if ((port_in(src_port, SMB_NETBIOS_SESSION_PORT_139, extra_ports) ||
             port_in(dst_port, SMB_NETBIOS_SESSION_PORT_139, extra_ports)) &&
            payload.size() >= 8 && payload.at(0) == 0x00) {
            if (auto d = match_smb_magic(payload, 4)) {
                ItLateralMovementMatch m;
                m.protocol = "smb";
                m.summary = "SMB over NetBIOS Session Service (RFC 1002 session message wrapper, " + *d + ")";
                return m;
            }
        }
        // 3. SSH version-exchange banner -- port-independent, same reasoning as SMB/VNC above: SSH
        // deliberately running on a nonstandard port is still worth flagging.
        if (auto banner = match_ssh_banner(payload)) {
            ItLateralMovementMatch m;
            m.protocol = "ssh";
            m.summary = "SSH version-exchange banner \"" + *banner + "\"";
            if (!port_in(src_port, SSH_PORT, extra_ports) && !port_in(dst_port, SSH_PORT, extra_ports)) {
                m.notes.push_back("seen on TCP port " + std::to_string(src_port) + "->" +
                                   std::to_string(dst_port) +
                                   ", which is not a configured/standard SSH port (22)");
            }
            return m;
        }
        // 4. HTTP request-line/status-line -- port-independent by design, since a vendor web UI's
        // whole point is running on whatever port the vendor picked.
        if (auto h = match_http(payload)) {
            ItLateralMovementMatch m;
            m.protocol = "http";
            m.summary = *h;
            if (!port_in(src_port, HTTP_PORT_80, extra_ports) && !port_in(dst_port, HTTP_PORT_80, extra_ports) &&
                !port_in(src_port, HTTP_PORT_8080, extra_ports) && !port_in(dst_port, HTTP_PORT_8080, extra_ports) &&
                !port_in(src_port, HTTP_PORT_8000, extra_ports) && !port_in(dst_port, HTTP_PORT_8000, extra_ports)) {
                m.notes.push_back("seen on TCP port " + std::to_string(src_port) + "->" +
                                   std::to_string(dst_port) +
                                   ", not one of this decoder's curated \"commonly configured\" HTTP "
                                   "ports (80/8080/8000) -- exactly the vendor-web-UI-on-an-arbitrary-"
                                   "port case this check is meant to catch");
            }
            return m;
        }
        // 5. Telnet IAC negotiation -- gated to port 23 (IAC's 0xFF is too common a byte value in
        // arbitrary binary traffic to check opportunistically, unlike SMB/SSH/HTTP's own much more
        // self-describing signatures above).
        if (port_in(src_port, TELNET_PORT, extra_ports) || port_in(dst_port, TELNET_PORT, extra_ports)) {
            ItLateralMovementMatch m;
            m.protocol = "telnet";
            if (has_telnet_negotiation(payload)) {
                m.summary = "Telnet (TCP port " + std::to_string(TELNET_PORT) +
                             ") -- IAC option-negotiation sequence observed";
            } else {
                m.summary = "Telnet (TCP port " + std::to_string(TELNET_PORT) +
                             ") -- port match only, no IAC negotiation sequence in this packet "
                             "(already-established session data looks like this)";
            }
            return m;
        }
        // 6. FTP control channel -- gated to port 21 (the data channel is out of scope, see file
        // header comment).
        if (port_in(src_port, FTP_CONTROL_PORT, extra_ports) || port_in(dst_port, FTP_CONTROL_PORT, extra_ports)) {
            ItLateralMovementMatch m;
            m.protocol = "ftp";
            if (auto f = match_ftp(payload)) {
                m.summary = "FTP control channel (TCP port " + std::to_string(FTP_CONTROL_PORT) + ") -- " + *f;
            } else {
                m.summary = "FTP control channel (TCP port " + std::to_string(FTP_CONTROL_PORT) +
                             ") -- port match only, no reply code or command verb recognized in this packet";
            }
            return m;
        }
        // 7. HTTPS port-only fallback -- the actual ClientHello structural check runs earlier in
        // decoder.cpp, reusing tls_sni.hpp (see it_protocols.hpp's own file header comment for why);
        // this only covers an already-established, fully-encrypted session on a configured HTTPS
        // port with no visible ClientHello in this particular packet.
        if (port_in(src_port, HTTPS_PORT_443, extra_ports) || port_in(dst_port, HTTPS_PORT_443, extra_ports) ||
            port_in(src_port, HTTPS_PORT_8443, extra_ports) || port_in(dst_port, HTTPS_PORT_8443, extra_ports)) {
            ItLateralMovementMatch m;
            m.protocol = "https";
            m.summary = "HTTPS/TLS (TCP port 443/8443) -- port match only, no TLS ClientHello in "
                         "this packet (an already-established, encrypted session looks like this)";
            return m;
        }
    } else {
        // 1. SNMPv1/v2c -- gated to port 161/162 (see file header comment for why, unlike SMB/SSH/
        // HTTP above).
        if (port_in(src_port, SNMP_AGENT_PORT, extra_ports) || port_in(dst_port, SNMP_AGENT_PORT, extra_ports) ||
            port_in(src_port, SNMP_TRAP_PORT, extra_ports) || port_in(dst_port, SNMP_TRAP_PORT, extra_ports)) {
            ItLateralMovementMatch m;
            m.protocol = "snmp";
            bool is_trap_port = port_in(src_port, SNMP_TRAP_PORT, extra_ports) ||
                                 port_in(dst_port, SNMP_TRAP_PORT, extra_ports);
            if (auto s = match_snmpv1v2c(payload)) {
                std::string ver = (s->version == 0) ? "v1" : "v2c";
                m.summary = "SNMP" + ver + " (UDP port " + (is_trap_port ? "162, trap" : "161, agent") +
                             ") -- community string \"" + s->community + "\"";
                m.notes.push_back("cleartext community string \"" + s->community +
                                   "\" was observed on the wire in this packet -- treat it as "
                                   "compromised, it maps every SNMP-speaking device on this segment "
                                   "that shares it");
            } else {
                m.summary = "SNMP (UDP port 161/162) -- port match only, not decodable as an SNMPv1/"
                             "v2c BER structure in this packet (could be SNMPv3, which authenticates/"
                             "encrypts and has no cleartext community string, or a malformed/"
                             "truncated PDU)";
            }
            return m;
        }
        // 2. TFTP -- gated to port 69, same reasoning as Telnet/FTP above.
        if (port_in(src_port, TFTP_PORT, extra_ports) || port_in(dst_port, TFTP_PORT, extra_ports)) {
            ItLateralMovementMatch m;
            m.protocol = "tftp";
            if (auto t = match_tftp_request(payload)) {
                m.summary = "TFTP (UDP port " + std::to_string(TFTP_PORT) + ") -- " + *t;
            } else {
                m.summary = "TFTP (UDP port " + std::to_string(TFTP_PORT) +
                             ") -- port match only, not a recognizable RRQ/WRQ in this packet (a "
                             "DATA/ACK/ERROR packet mid-transfer looks like this -- only the initial "
                             "RRQ/WRQ has a strong structural signature, see file header comment)";
            }
            return m;
        }
    }

    return std::nullopt;
}

// ---------------------------------------------------------------------------------------------
// Tier 4 -- see it_protocols.hpp's own header comment for the full per-protocol confidence writeup.

namespace {

// RFC 5415 section 4.5 / IANA "CAPWAP Message Types" registry -- the common, well-established
// subset; anything else is still reported by its raw numeric value (a vendor extension, or a type
// added by an RFC past this file's own research).
std::string capwap_message_type_name(uint32_t t) {
    switch (t) {
        case 1: return "Discovery Request";
        case 2: return "Discovery Response";
        case 3: return "Join Request";
        case 4: return "Join Response";
        case 5: return "Configuration Status Request";
        case 6: return "Configuration Status Response";
        case 7: return "Configuration Update Request";
        case 8: return "Configuration Update Response";
        case 9: return "WTP Event Request";
        case 10: return "WTP Event Response";
        case 11: return "Change State Event Request";
        case 12: return "Change State Event Response";
        case 13: return "Echo Request";
        case 14: return "Echo Response";
        case 15: return "Image Data Request";
        case 16: return "Image Data Response";
        case 17: return "Reset Request";
        case 18: return "Reset Response";
        case 19: return "Primary Discovery Request";
        case 20: return "Primary Discovery Response";
        case 21: return "Data Transfer Request";
        case 22: return "Data Transfer Response";
        case 23: return "Clear Configuration Request";
        case 24: return "Clear Configuration Response";
        case 25: return "Station Configuration Request";
        case 26: return "Station Configuration Response";
        default: return "";
    }
}

struct CapwapMatch {
    bool is_dtls = false;
    bool has_message_type = false;
    uint32_t message_type = 0;
    std::string message_type_name;
};

// RFC 5415 section 4.3's Preamble (Version(4 bits)/Type(4 bits)) plus, for a plaintext header
// (Type 0), the Transport Header's own HLEN field -- see it_protocols.hpp's own file header comment
// for why this file doesn't attempt a bit-perfect decode of every transport-header field. Returns
// std::nullopt only when the Preamble itself doesn't match (wrong Version, or a Type other than
// 0/1) -- a plaintext header that's merely too short to resolve HLEN/a Message Type still returns a
// CapwapMatch with has_message_type left false, so the caller can still report "Preamble matched,
// nothing further resolvable" rather than treating it as no match at all. `want_control` selects
// whether a plaintext header's Control Header (Message Type) is even looked for -- CAPWAP data has
// no Control Header, only CAPWAP control does.
std::optional<CapwapMatch> match_capwap(ByteSpan payload, bool want_control) {
    if (payload.empty()) return std::nullopt;
    uint8_t preamble = payload.at(0);
    uint8_t version = (preamble >> 4) & 0x0F;
    uint8_t type = preamble & 0x0F;
    if (version != 0) return std::nullopt;  // only version RFC 5415 ever defines
    if (type > 1) return std::nullopt;      // 0 = plaintext header, 1 = DTLS header

    CapwapMatch m;
    if (type == 1) {
        m.is_dtls = true;
        return m;
    }

    // Plaintext header -- need at least the 8-byte minimum Transport Header (HLEN's own minimum
    // value, 2 words, when neither the optional Radio MAC Address nor Wireless Info field is
    // present) before HLEN can even be trusted.
    if (payload.size() < 1 + 8) return m;
    uint8_t hlen = (payload.at(1) >> 3) & 0x1F;  // top 5 bits of the byte right after the Preamble
    if (hlen < 2) return m;  // implausible -- shorter than the mandatory fields alone allow
    size_t header_end = 1 + static_cast<size_t>(hlen) * 4;
    if (!want_control || header_end + 4 > payload.size()) return m;  // Control Header's Message
                                                                        // Type (4 bytes) doesn't fit
    uint32_t message_type = (static_cast<uint32_t>(payload.at(header_end)) << 24) |
                             (static_cast<uint32_t>(payload.at(header_end + 1)) << 16) |
                             (static_cast<uint32_t>(payload.at(header_end + 2)) << 8) |
                             static_cast<uint32_t>(payload.at(header_end + 3));
    m.has_message_type = true;
    m.message_type = message_type;
    m.message_type_name = capwap_message_type_name(message_type);
    return m;
}

// 3GPP TS 29.281's own enumerated Message Type registry -- the common subset; anything else is
// still reported by its raw numeric value.
std::string gtp_message_type_name(uint8_t t) {
    switch (t) {
        case 1: return "Echo Request";
        case 2: return "Echo Response";
        case 26: return "Error Indication";
        case 31: return "Supported Extension Headers Notification";
        case 254: return "End Marker";
        case 255: return "G-PDU";  // the actual tunneled user-plane packet
        default: return "";
    }
}

struct GtpMatch {
    std::string message_type_name;
    uint8_t message_type = 0;
    uint16_t declared_length = 0;
    uint32_t teid = 0;
};

// 3GPP TS 29.281 section 5's mandatory 8-byte header: Flags(1, top nibble Version=1|PT=1 => 0x3) +
// Message Type(1) + Length(2, big-endian, payload length AFTER this header) + TEID(4). Length is
// deliberately not re-validated against the captured payload -- see it_protocols.hpp's own file
// header comment for why.
std::optional<GtpMatch> match_gtp_u(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    uint8_t flags = payload.at(0);
    if ((flags >> 4) != 0x3) return std::nullopt;  // Version(3 bits)=1, PT(1 bit)=1
    uint8_t message_type = payload.at(1);
    std::string name = gtp_message_type_name(message_type);
    if (name.empty()) return std::nullopt;

    GtpMatch m;
    m.message_type = message_type;
    m.message_type_name = name;
    m.declared_length = static_cast<uint16_t>((payload.at(2) << 8) | payload.at(3));
    m.teid = (static_cast<uint32_t>(payload.at(4)) << 24) | (static_cast<uint32_t>(payload.at(5)) << 16) |
             (static_cast<uint32_t>(payload.at(6)) << 8) | static_cast<uint32_t>(payload.at(7));
    return m;
}

}  // namespace

std::optional<ItWirelessBackhaulMatch> try_recognize_it_wireless_backhaul(ByteSpan payload, uint16_t src_port,
                                                                            uint16_t dst_port,
                                                                            const std::vector<uint16_t>& extra_ports) {
    // 1. CAPWAP control -- gated to port 5246 (see file header comment: a modest but genuine
    // structural signature).
    if (port_in(src_port, CAPWAP_CONTROL_PORT, extra_ports) || port_in(dst_port, CAPWAP_CONTROL_PORT, extra_ports)) {
        ItWirelessBackhaulMatch m;
        m.protocol = "capwap-control";
        if (auto c = match_capwap(payload, /*want_control=*/true)) {
            if (c->is_dtls) {
                m.summary = "CAPWAP control, DTLS-protected (UDP port " + std::to_string(CAPWAP_CONTROL_PORT) +
                             ") -- body is an opaque DTLS record, not decoded further";
            } else if (c->has_message_type) {
                if (!c->message_type_name.empty()) {
                    m.summary = "CAPWAP control " + c->message_type_name + " (UDP port " +
                                 std::to_string(CAPWAP_CONTROL_PORT) + ")";
                } else {
                    m.summary = "CAPWAP control, message type " + std::to_string(c->message_type) +
                                 " (unrecognized) (UDP port " + std::to_string(CAPWAP_CONTROL_PORT) + ")";
                }
            } else {
                m.summary = "CAPWAP control (UDP port " + std::to_string(CAPWAP_CONTROL_PORT) +
                             ") -- plaintext Preamble present, Control Header/Message Type not "
                             "resolvable in this packet (could be truncated, or an implausible HLEN)";
            }
        } else {
            m.summary = "CAPWAP control (UDP port " + std::to_string(CAPWAP_CONTROL_PORT) +
                         ") -- port match only, not a plausible Preamble in this packet";
        }
        return m;
    }
    // 2. CAPWAP data -- gated to port 5247, same modest structural check (Preamble + HLEN sanity)
    // as CAPWAP control above, minus any Control Header/Message Type -- see file header comment for
    // why this file goes no further than naming the tunnel itself.
    if (port_in(src_port, CAPWAP_DATA_PORT, extra_ports) || port_in(dst_port, CAPWAP_DATA_PORT, extra_ports)) {
        ItWirelessBackhaulMatch m;
        m.protocol = "capwap-data";
        if (auto c = match_capwap(payload, /*want_control=*/false)) {
            if (c->is_dtls) {
                m.summary = "CAPWAP data, DTLS-protected (UDP port " + std::to_string(CAPWAP_DATA_PORT) +
                             ") -- the tunneled client frame is opaque, encrypted";
            } else {
                m.summary = "CAPWAP data (UDP port " + std::to_string(CAPWAP_DATA_PORT) +
                             ") -- the actual bridged wireless client frame is tunneled here, not "
                             "decoded (see it_protocols.hpp's own file header comment)";
            }
        } else {
            m.summary = "CAPWAP data (UDP port " + std::to_string(CAPWAP_DATA_PORT) +
                         ") -- port match only, not a plausible Preamble in this packet";
        }
        return m;
    }
    // 3. LWAPP control -- port only; LWAPP has no publicly documented wire format this file could
    // check a structural signature against (see file header comment).
    if (port_in(src_port, LWAPP_CONTROL_PORT, extra_ports) || port_in(dst_port, LWAPP_CONTROL_PORT, extra_ports)) {
        ItWirelessBackhaulMatch m;
        m.protocol = "lwapp-control";
        m.summary = "LWAPP control (UDP port " + std::to_string(LWAPP_CONTROL_PORT) +
                     ") -- port match only; LWAPP (CAPWAP's Cisco-proprietary predecessor) has no "
                     "authoritative public wire-format specification this decoder could check a "
                     "structural signature against";
        return m;
    }
    // 4. LWAPP data -- ditto.
    if (port_in(src_port, LWAPP_DATA_PORT, extra_ports) || port_in(dst_port, LWAPP_DATA_PORT, extra_ports)) {
        ItWirelessBackhaulMatch m;
        m.protocol = "lwapp-data";
        m.summary = "LWAPP data (UDP port " + std::to_string(LWAPP_DATA_PORT) +
                     ") -- port match only; same reasoning as LWAPP control above";
        return m;
    }
    // 5. GTP-U -- gated to port 2152, a genuine structural signature (see file header comment).
    if (port_in(src_port, GTP_U_PORT, extra_ports) || port_in(dst_port, GTP_U_PORT, extra_ports)) {
        ItWirelessBackhaulMatch m;
        m.protocol = "gtp-u";
        if (auto g = match_gtp_u(payload)) {
            std::ostringstream s;
            s << "GTP-U " << g->message_type_name << " (TEID=0x" << std::hex << std::uppercase
              << std::setw(8) << std::setfill('0') << g->teid << std::dec << ", UDP port " << GTP_U_PORT << ")";
            m.summary = s.str();
            if (g->message_type == 255) {
                m.notes.push_back("G-PDU -- an actual tunneled user-plane packet; this decoder does "
                                   "not unwrap the inner IP packet (see it_protocols.hpp's own file "
                                   "header comment)");
            }
        } else {
            m.summary = "GTP-U (UDP port " + std::to_string(GTP_U_PORT) +
                         ") -- port match only, not a plausible Version/PT/Message-Type header in "
                         "this packet";
        }
        return m;
    }

    return std::nullopt;
}

}  // namespace conduitscope
