// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/it_protocols.hpp"

#include <algorithm>
#include <sstream>

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

}  // namespace conduitscope
