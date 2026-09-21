// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/output.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

namespace conduitscope {

std::string json_escape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        switch (c) {
            case '"': out << "\\\""; break;
            case '\\': out << "\\\\"; break;
            case '\n': out << "\\n"; break;
            case '\r': out << "\\r"; break;
            case '\t': out << "\\t"; break;
            default:
                if (c < 0x20) {
                    out << "\\u" << std::hex << std::setw(4) << std::setfill('0') << static_cast<int>(c)
                        << std::dec;
                } else {
                    out << static_cast<char>(c);
                }
        }
    }
    return out.str();
}

std::string csv_escape(const std::string& s) {
    bool needs_quotes = s.find_first_of(",\"\n\r") != std::string::npos;
    if (!needs_quotes) return s;
    std::string out = "\"";
    for (char c : s) {
        if (c == '"') out += "\"\"";
        else out += c;
    }
    out += "\"";
    return out;
}

namespace {
// Renders one side (src or dst) of a packet's addressing for the text-format headline, with
// Resolver-provided hostname/service-name annotations appended in parentheses right after the
// raw value they explain -- never replacing it (see resolver.hpp's file header for why: this is a
// security/OT tool, ground-truth addresses stay visible always). A lookup MISS adds nothing --
// no "(unknown)" placeholder -- matching this codebase's existing convention of omitting a field
// entirely on a negative result rather than noting every miss.
std::string endpoint(const DecodedPacket& p, bool src, const Resolver& resolver) {
    if (!p.has_ip) {
        // No IP layer at all (ARP/LLDP/EAPOL/PPPoE/MPLS, PROFINET RT/GOOSE/SV/EtherCAT/STP, or the
        // generic non-ip/non-tcp fallback) -- every one of these still carries a real src_mac/
        // dst_mac (decoder.cpp's Decoder::decode populates it for every Ethernet-linktype packet
        // regardless of protocol), so fall back to that instead of a bare "-" placeholder with
        // literally no addressing information on the line at all. With --oui enabled, the vendor
        // name is appended the same way it always is elsewhere -- Resolver::oui_vendor() is
        // already self-gated on --oui (returns std::nullopt when disabled), so this is safe to
        // call unconditionally, the same convention the JSON/CSV writers already follow. This
        // fallback fires regardless of -e/--ether: unlike the "eth <src> -> <dst>" line below
        // (which write_packet now skips for exactly this case -- see its own comment), there is no
        // separate opt-in needed to see a non-IP packet's own addresses on its headline.
        if (!p.has_ethernet) return "-";
        std::string mac = src ? p.src_mac : p.dst_mac;
        if (auto v = resolver.oui_vendor(mac)) mac += " (" + *v + ")";
        return mac;
    }
    std::string ip = src ? p.src_ip : p.dst_ip;
    std::string rendered = ip;
    if (auto host = resolver.hostname(ip)) rendered += " (" + *host + ")";
    if (!p.has_tcp && !p.has_udp) return rendered;
    uint16_t port = src ? p.src_port : p.dst_port;
    std::string port_str = std::to_string(port);
    if (auto svc = resolver.service_name(port, p.has_tcp ? "tcp" : "udp")) port_str += " (" + *svc + ")";
    return rendered + ":" + port_str;
}

// ANSI SGR (Select Graphic Rendition) escape sequences. Only ever emitted when TextWriter::color_
// is true -- see cli_main.cpp's stdout_is_terminal()/--color/--no-color for how that's decided.
constexpr const char* kReset = "\033[0m";
constexpr const char* kDim = "\033[2m";
constexpr const char* kBoldRed = "\033[1;31m";
constexpr const char* kCyan = "\033[36m";
constexpr const char* kMagenta = "\033[35m";
constexpr const char* kBlue = "\033[34m";
constexpr const char* kGreen = "\033[32m";
constexpr const char* kYellow = "\033[33m";
constexpr const char* kBrightCyan = "\033[96m";
constexpr const char* kBrightGreen = "\033[92m";
constexpr const char* kBrightMagenta = "\033[95m";
constexpr const char* kBrightYellow = "\033[93m";
constexpr const char* kBrightBlue = "\033[94m";
constexpr const char* kBrightWhite = "\033[97m";
constexpr const char* kBrightRed = "\033[91m";
constexpr const char* kBoldBlue = "\033[1;34m";
constexpr const char* kBoldCyan = "\033[1;36m";
constexpr const char* kBoldMagenta = "\033[1;35m";
constexpr const char* kBoldGreen = "\033[1;32m";
constexpr const char* kWhite = "\033[37m";
constexpr const char* kGray = "\033[90m";
constexpr const char* kBoldYellow = "\033[1;33m";
// Every plain/bright/bold combination of the 16 standard ANSI colors above is already spoken for
// by an existing protocol tag by the time RIP/IGMP/VRRP/HSRP were added -- underline is a fresh
// modifier dimension rather than another documented-reuse case like ffhse/opcua or mms/s7comm-plus
// above (those needed to justify sharing a hue; there simply isn't a hue left to share from that
// wouldn't require its own equally-long justification).
constexpr const char* kUnderlineCyan = "\033[4;36m";
constexpr const char* kUnderlineGreen = "\033[4;32m";
constexpr const char* kUnderlineMagenta = "\033[4;35m";
constexpr const char* kUnderlineYellow = "\033[4;33m";
// IGRP/PIM/EIGRP/OSPF round: rounding out the underline dimension with the remaining three
// standard hues (blue/red/white) still covers only 7 of underline's 8 possible hues -- one short
// for four new protocols, so OSPF reuses underline-cyan's own blue-ish neighbor via a bold+
// underline combination instead of inventing a genuinely new escape-code family for a single tag.
constexpr const char* kUnderlineBlue = "\033[4;34m";
constexpr const char* kUnderlineRed = "\033[4;31m";
constexpr const char* kUnderlineWhite = "\033[4;37m";
constexpr const char* kBoldUnderlineCyan = "\033[1;4;36m";
// Tier 1 "IT protocols an OT auditor flags" round (RDP/VNC/TeamViewer/AnyDesk/Zoom -- see
// it_protocols.hpp): every plain/bright/bold hue AND every underline hue is already spoken for by
// this point, so this rounds out the bold+underline combination OSPF's own tag started (only cyan
// used there) with its remaining four standard hues, rather than inventing a third escape-code
// dimension for five tags. These five protocols very much CAN coexist with anything else in this
// table in a real mixed IT/OT capture (unlike e.g. DeviceNet's link-layer isolation), so this is a
// genuine "no fresh hue left" reuse, not a "these never collide" one -- the "[protocol]" tag text
// is what actually disambiguates them from OSPF/each other in practice, the same reliance DNS/
// mDNS/LLMNR's own shared kWhite already has.
constexpr const char* kBoldUnderlineGreen = "\033[1;4;32m";
constexpr const char* kBoldUnderlineMagenta = "\033[1;4;35m";
constexpr const char* kBoldUnderlineYellow = "\033[1;4;33m";
constexpr const char* kBoldUnderlineBlue = "\033[1;4;34m";
constexpr const char* kBoldUnderlineRed = "\033[1;4;31m";
// Tier 2 "IT protocols an OT auditor flags" round (SMB/SSH/HTTP/HTTPS/SNMPv1v2c/Telnet/FTP/TFTP --
// see it_protocols.hpp): plain/bright/bold/underline/bold+underline are now ALL fully spoken for,
// so this introduces italic as a fresh fourth modifier dimension -- six italic hues plus two more
// combining italic with bold covers all eight of this round's new tags without a fifth dimension.
// Same "no fresh hue left, genuine reuse" justification Tier 1's own bold+underline round documents
// above, not a "these never collide" case: several of these eight (SSH especially, sometimes HTTP/
// HTTPS on a jump host) can very plausibly coexist with anything else in this table in a real mixed
// IT/OT capture, so the "[protocol]" tag text is again what actually disambiguates in practice.
constexpr const char* kItalicRed = "\033[3;31m";
constexpr const char* kItalicGreen = "\033[3;32m";
constexpr const char* kItalicYellow = "\033[3;33m";
constexpr const char* kItalicBlue = "\033[3;34m";
constexpr const char* kItalicMagenta = "\033[3;35m";
constexpr const char* kItalicCyan = "\033[3;36m";
// QUIC (added well after the rest of this tier -- see quic.hpp) is Tier 2's one outlier: every
// other protocol here is named/recognized from a port or a cleartext structural signature alone,
// while QUIC's own detection genuinely DECRYPTS an Initial packet (RFC 9001's publicly-derivable
// keys) to surface its ClientHello SNI. Plain (not bold) italic white -- the one hue/weight
// combination the rest of this six-hue italic family (red/green/yellow/blue/magenta/cyan, see
// just above) never used -- the same "spend an unused weight+hue combination on this tier's own
// outlier" reasoning mpls.hpp's own strikethrough-white choice documents for Tier 5.
constexpr const char* kItalicWhite = "\033[3;37m";
constexpr const char* kBoldItalicRed = "\033[1;3;31m";
constexpr const char* kBoldItalicGreen = "\033[1;3;32m";
// Tier 3 "IT protocols an OT auditor flags" round (NTP/DHCP/LDAP/LDAPS/RADIUS/TACACS+/EAPOL -- see
// it_protocols.hpp/eapol.hpp): rounds out the bold+italic combination Tier 2's own FTP/TFTP tags
// started (only red/green used there) with its remaining four standard hues.
constexpr const char* kBoldItalicYellow = "\033[1;3;33m";
constexpr const char* kBoldItalicBlue = "\033[1;3;34m";
constexpr const char* kBoldItalicMagenta = "\033[1;3;35m";
constexpr const char* kBoldItalicCyan = "\033[1;3;36m";
// That still leaves three of Tier 3's seven new tags (RADIUS/TACACS+/EAPOL) with no combination left
// in plain/bright/bold/underline/bold+underline/italic/bold+italic -- every one of those seven
// dimensions is now fully spoken for. `kDim` itself has existed in this file from the start, but
// only ever bare (for notes/eth-line prefixes and the generic tcp/udp/non-ip/non-tcp fallback below),
// never paired with a hue -- pairing it with a color here is a genuinely fresh dimension, not a
// reuse of dim's own existing bare meaning (nothing below uses bare kDim for a *recognized* protocol
// tag, only for "nothing OT-specific to say" and structural/prefix text).
constexpr const char* kDimRed = "\033[2;31m";
constexpr const char* kDimGreen = "\033[2;32m";
constexpr const char* kDimYellow = "\033[2;33m";

// Tier 4 "IT protocols an OT auditor flags" round (CAPWAP control/data, LWAPP control/data, GTP-U,
// PPPoE -- see it_protocols.hpp/pppoe.hpp): six new tags, so rather than spending three of Tier 3's
// own unused kDim{Blue,Magenta,Cyan} slots and still needing three more from somewhere else, this
// introduces underline+italic as a wholly fresh dimension of its own -- the same "one tier, one new
// combination" pattern Tier 1's own bold+underline established -- and fills all six standard hues in
// one shot, the same way bold+italic took two tiers (Tier 2's FTP/TFTP, then Tier 3's NTP/DHCP/LDAP/
// LDAPS) to fill.
constexpr const char* kUnderlineItalicRed = "\033[4;3;31m";
constexpr const char* kUnderlineItalicGreen = "\033[4;3;32m";
constexpr const char* kUnderlineItalicYellow = "\033[4;3;33m";
constexpr const char* kUnderlineItalicBlue = "\033[4;3;34m";
constexpr const char* kUnderlineItalicMagenta = "\033[4;3;35m";
constexpr const char* kUnderlineItalicCyan = "\033[4;3;36m";

// Tier 5 "IT protocols an OT auditor flags" round (GRE/NVGRE/EoIP, ESP, AH, IP-in-IP, 6in4, L2TP,
// IKE, VXLAN, Geneve, WireGuard, OpenVPN, dtls-tunnel, STT, MPLS -- see tunnel_vpn.hpp/mpls.hpp):
// sixteen new tags, the largest single round yet, so rather than hunt for one more leftover slot
// per tag this pulls from three sources at once: the three Tier 3 "dim" hues (kDimRed/Green/Yellow)
// left Blue/Magenta/Cyan unclaimed (dim was only ever paired with three of the six standard hues,
// see that round's own comment above), which covers three of sixteen; a wholly fresh "bold+dim"
// combination covers six more (every standard hue); and a wholly fresh "strikethrough" combination
// -- a deliberate thematic fit for a tier about traffic that bypasses ordinary perimeter inspection
// -- covers the remaining seven (all six standard hues plus white, since seven tags were left once
// the first two sources were spent).
constexpr const char* kDimBlue = "\033[2;34m";
constexpr const char* kDimMagenta = "\033[2;35m";
constexpr const char* kDimCyan = "\033[2;36m";
constexpr const char* kBoldDimRed = "\033[1;2;31m";
constexpr const char* kBoldDimGreen = "\033[1;2;32m";
constexpr const char* kBoldDimYellow = "\033[1;2;33m";
constexpr const char* kBoldDimBlue = "\033[1;2;34m";
constexpr const char* kBoldDimMagenta = "\033[1;2;35m";
constexpr const char* kBoldDimCyan = "\033[1;2;36m";
constexpr const char* kStrikeRed = "\033[9;31m";
constexpr const char* kStrikeGreen = "\033[9;32m";
constexpr const char* kStrikeYellow = "\033[9;33m";
constexpr const char* kStrikeBlue = "\033[9;34m";
constexpr const char* kStrikeMagenta = "\033[9;35m";
constexpr const char* kStrikeCyan = "\033[9;36m";
constexpr const char* kStrikeWhite = "\033[9;37m";
// ICMP: every plain/bright/bold/underline/italic/dim/strike hue combination above is already
// spoken for, and ICMP -- unlike IGMP/VRRP/HSRP/IGRP/PIM/EIGRP/OSPF, which it otherwise shares a
// dispatch shape with (see decoder.cpp's own "rides directly on IP" comment) -- is common enough
// in ordinary traffic (routing diagnostics, path MTU discovery, plain pings) that reusing one of
// those rarer protocols' own colors risked real visual confusion in a mixed capture, unlike e.g.
// ffhse/opcua's reuse (both genuinely rare together in practice). Dim+underline is a fresh
// combination, following the same "invent one new escape-code family member" pattern IGMP/OSPF/
// MPLS above each used when their own current dimension ran out.
constexpr const char* kDimUnderlineCyan = "\033[2;4;36m";

// Color for a packet's "[protocol]" tag -- picked so a mixed-protocol capture scans quickly by
// eye, not for any deeper meaning. parse-error is the one exception: it gets the same "something
// is wrong here" red as a Modbus exception response, rather than a plain identification color,
// since it's a problem rather than a protocol match.
const char* protocol_tag_color(const std::string& protocol) {
    if (protocol == "modbus") return kCyan;
    if (protocol == "dnp3") return kMagenta;
    if (protocol == "s7comm") return kBlue;
    if (protocol == "cotp") return kBlue;  // recognized TPKT/COTP framing, no S7comm inside yet
    if (protocol == "iec104") return kGreen;
    if (protocol == "enip") return kYellow;
    if (protocol == "profinet") return kBrightCyan;
    if (protocol == "goose") return kBrightGreen;
    if (protocol == "sv") return kBrightMagenta;
    if (protocol == "ethercat") return kBrightYellow;
    if (protocol == "stp") return kMagenta;  // deliberately shares DNP3's plain magenta -- the two
                                                // never share a transport/link (STP is classic
                                                // 802.3 LLC, not IP-based at all), so there is no
                                                // realistic capture where this collision would
                                                // actually confuse a reader scanning by eye, the
                                                // same reasoning FF-HSE's bright red reuse documents
                                                // above
    if (protocol == "bacnet") return kBrightBlue;
    if (protocol == "hartip") return kBrightWhite;
    if (protocol == "opcua") return kBrightRed;
    if (protocol == "mms") return kBoldBlue;  // deliberately close to s7comm's plain blue -- they
                                                // share the same TPKT/COTP transport/port, bold
                                                // distinguishes MMS at a glance
    if (protocol == "s7comm-plus") return kBoldMagenta;  // deliberately NOT a third shade of blue
                                                            // alongside s7comm's plain blue/mms's
                                                            // bold blue (despite sharing their
                                                            // exact TPKT/COTP transport/port) --
                                                            // S7comm-Plus is a wholly different,
                                                            // independent application protocol
                                                            // from classic S7comm (see
                                                            // s7commplus.hpp), and bold magenta
                                                            // stays visually distinct from DNP3's
                                                            // own plain magenta too
    if (protocol == "mqtt") return kBoldCyan;  // bold, vs. Modbus's plain cyan -- deliberately
                                                 // distinct from every other tag color, no shared
                                                 // transport/port with any other decoded protocol
    if (protocol == "ffhse") return kBrightRed;  // deliberately shares opcua's bright red rather
                                                    // than adding a 20th distinct hue -- the two
                                                    // never share a transport/port, so there is no
                                                    // realistic capture where this collision would
                                                    // actually confuse a reader scanning by eye
    if (protocol == "devicenet") return kBoldGreen;  // a genuinely new hue (not a documented reuse
                                                        // like mms/s7comm-plus/mqtt/ffhse above) --
                                                        // DeviceNet is the only protocol in this
                                                        // codebase that isn't Ethernet-based at all
                                                        // (see decoder.hpp's own comment on
                                                        // devicenet_can_id/can_socketcan.hpp), so a
                                                        // mixed-protocol capture containing it is
                                                        // structurally impossible in the first place
                                                        // -- no collision risk to reason about either way
    if (protocol == "dns" || protocol == "mdns" || protocol == "llmnr") return kWhite;  // one shared
                                                        // color for all three -- they're the exact
                                                        // same wire format (see dns.hpp), not just a
                                                        // deliberate hue reuse the way ffhse/opcua or
                                                        // mms/s7comm are; the "[protocol]" tag text
                                                        // itself is what actually disambiguates them
    if (protocol == "nbns") return kGray;               // a fresh hue -- NBT-NS traffic routinely
                                                        // coexists with DNS-family and everything
                                                        // else in a real mixed IT/OT capture, unlike
                                                        // e.g. DeviceNet's own link-layer isolation
    if (protocol == "doh") return kBoldYellow;          // also fresh -- DoH detection fires on
                                                        // ordinary TCP/443 traffic, which can appear
                                                        // alongside literally any other protocol here
    if (protocol == "rip") return kUnderlineCyan;       // first use of the underline modifier --
                                                        // see its own comment above; plain cyan is
                                                        // already Modbus's, but the two never share
                                                        // a transport (RIP is UDP/520 only)
    if (protocol == "icmp") return kDimUnderlineCyan;
    if (protocol == "igmp") return kUnderlineGreen;
    if (protocol == "vrrp") return kUnderlineMagenta;
    if (protocol == "hsrp") return kUnderlineYellow;
    if (protocol == "igrp") return kUnderlineRed;      // legacy/deprecated protocol -- red doubles
                                                          // as a mild "this shouldn't be running"
                                                          // visual cue, matching igrp.hpp's own
                                                          // Security context note
    if (protocol == "pim") return kUnderlineBlue;
    if (protocol == "eigrp") return kUnderlineWhite;
    if (protocol == "ospf") return kBoldUnderlineCyan;  // bold+underline cyan -- OSPF and RIP both
                                                           // never share a transport (RIP is UDP/520
                                                           // only, OSPF rides IP protocol 89
                                                           // directly), so reusing cyan's hue here
                                                           // with an extra bold weight to
                                                           // disambiguate from RIP's plain-underline
                                                           // cyan costs nothing in practice
    if (protocol == "rdp") return kBoldUnderlineRed;       // red doubles as a mild "this shouldn't
                                                              // be running here" cue, same reasoning
                                                              // igrp's own color choice documents
    if (protocol == "vnc") return kBoldUnderlineGreen;
    if (protocol == "teamviewer") return kBoldUnderlineMagenta;
    if (protocol == "anydesk") return kBoldUnderlineYellow;
    if (protocol == "zoom") return kBoldUnderlineBlue;
    if (protocol == "smb") return kItalicRed;          // red doubles as a mild "this shouldn't be
                                                           // running here" cue, same reasoning igrp's
                                                           // and rdp's own color choices document --
                                                           // NCSC's own rule of thumb names SMB as a
                                                           // wormable-malware path
    if (protocol == "ssh") return kItalicGreen;
    if (protocol == "http") return kItalicYellow;
    if (protocol == "https") return kItalicBlue;
    if (protocol == "quic") return kItalicWhite;  // see kItalicWhite's own comment above
    if (protocol == "snmp") return kItalicMagenta;
    if (protocol == "telnet") return kItalicCyan;
    if (protocol == "ftp") return kBoldItalicRed;       // also a mild "cleartext credentials" cue,
                                                           // same reasoning as smb's own plain-italic
                                                           // red just above
    if (protocol == "tftp") return kBoldItalicGreen;
    if (protocol == "ntp") return kBoldItalicYellow;
    if (protocol == "dhcp") return kBoldItalicBlue;
    if (protocol == "ldap") return kBoldItalicMagenta;
    if (protocol == "ldaps") return kBoldItalicCyan;
    if (protocol == "radius") return kDimRed;
    if (protocol == "tacacs-plus") return kDimGreen;
    if (protocol == "eapol") return kDimYellow;
    if (protocol == "capwap-control") return kUnderlineItalicCyan;
    if (protocol == "capwap-data") return kUnderlineItalicBlue;
    if (protocol == "lwapp-control") return kUnderlineItalicMagenta;
    if (protocol == "lwapp-data") return kUnderlineItalicYellow;
    if (protocol == "gtp-u") return kUnderlineItalicGreen;
    if (protocol == "pppoe") return kUnderlineItalicRed;
    if (protocol == "gre") return kDimBlue;
    if (protocol == "nvgre") return kDimMagenta;
    if (protocol == "eoip") return kDimCyan;
    if (protocol == "esp") return kBoldDimRed;
    if (protocol == "ah") return kBoldDimGreen;
    if (protocol == "ip-in-ip") return kBoldDimYellow;
    if (protocol == "6in4") return kBoldDimBlue;
    if (protocol == "l2tp") return kBoldDimMagenta;
    if (protocol == "ike") return kBoldDimCyan;
    if (protocol == "vxlan") return kStrikeRed;
    if (protocol == "geneve") return kStrikeGreen;
    if (protocol == "wireguard") return kStrikeYellow;  // mild "shadow-IT" cue, same reasoning
                                                           // igrp's/rdp's/smb's own color choices
                                                           // document -- an unexpected WireGuard
                                                           // tunnel is exactly the shadow-IT/vendor-
                                                           // remote-access case ROADMAP item 18 calls
                                                           // out
    if (protocol == "openvpn") return kStrikeBlue;        // same "shadow-IT" cue as wireguard above
    if (protocol == "dtls-tunnel") return kStrikeMagenta;
    if (protocol == "stt") return kStrikeCyan;
    if (protocol == "mpls") return kStrikeWhite;           // the seventh strikethrough hue -- MPLS is
                                                              // this tier's one outlier (no port, no
                                                              // IP layer, EtherType-keyed), so white
                                                              // doubles as a visual "different shape"
                                                              // cue too
    if (protocol == "parse-error") return kBoldRed;
    return kDim;  // tcp / udp / non-tcp / non-ip / unsupported-link: recognized, nothing OT-specific
}
}  // namespace

void TextWriter::write_packet(const DecodedPacket& p) {
    // A parse failure, or a Modbus exception response, is the one piece of a packet line worth
    // drawing the eye to over everything else in a long decode -- both mean "look at this one".
    bool severe = p.protocol == "parse-error" || (p.protocol == "modbus" && p.modbus_is_exception);

    std::ostringstream head;
    head << "#" << p.index << "  " << time_.format(p.timestamp) << "  "
         << endpoint(p, true, resolver_) << " -> " << endpoint(p, false, resolver_) << "  ";
    if (color_) head << protocol_tag_color(p.protocol);
    head << "[" << p.protocol << "]";
    if (color_) head << kReset;
    head << "  ";
    if (color_ && severe) head << kBoldRed;
    head << p.summary;
    if (color_ && severe) head << kReset;
    // How this TCP flow's client (initiator) side was determined -- see DirectionSource's own
    // comment (decoder.hpp) and docs/MANUAL.md's ROADMAP item 19. Folded into the head line itself
    // (appended after the summary, purely additive -- notes/eth/etc. below are unaffected) rather
    // than its own separate line, so it reads alongside the endpoints/protocol/summary it
    // describes instead of requiring a second line to connect back to them. Colored yellow for
    // DirectionSource::PortHeuristic specifically -- the only tier that can actually be wrong, per
    // ROADMAP item 19's own precedent survey -- and dim (like every other secondary annotation on
    // this line) for the two authoritative tiers, handshake and content; the tier name itself is
    // always printed regardless of color/--no-color, so nothing here is color-only information.
    // --no-direction (show_direction_, cli_main.cpp) suppresses this outright; has_direction is
    // only ever true for a has_tcp packet (FlowDirectionTracker's scope, see flow_direction.hpp),
    // so this never appears for a UDP/non-IP/parse-error packet regardless of the flag.
    if (show_direction_ && p.has_direction) {
        bool uncertain = p.direction_source == DirectionSource::PortHeuristic;
        head << "  ";
        if (color_) head << (uncertain ? kYellow : kDim);
        head << "(client " << (p.direction_client_is_src ? p.src_ip : p.dst_ip) << " -- "
             << direction_source_name(p.direction_source) << ")";
        if (color_) head << kReset;
    }
    out_ << head.str() << "\n";

    for (const auto& note : p.notes) {
        out_ << "        ";
        if (color_) out_ << kDim;
        out_ << "note: " << note;
        if (color_) out_ << kReset;
        out_ << "\n";
    }

    // Every Ethernet-linktype packet carries src_mac/dst_mac regardless of protocol (see
    // decoder.cpp's Decoder::decode) -- shown here, with OUI vendor annotations, for every
    // protocol alike, not just the raw-Ethernet ones (GOOSE/SV/EtherCAT/PROFINET/STP) that already
    // fold their own MAC fields into stp_root_mac/etc. Gated behind show_mac_ (decode's -e/--ether,
    // off by default, implied by --oui -- see output.hpp's own comment): mirrors tcpdump's own -e,
    // a pure display toggle for the human-facing text dump, not a resolver lookup -- JSON/CSV keep
    // showing src_mac/dst_mac unconditionally regardless of this flag, see output.hpp. VLAN ID
    // (show_vlan_, --no-vlan, on by default) is independent of show_mac_ -- 802.1Q membership isn't
    // specifically a MAC-address fact -- so a VLAN-tagged packet still gets a line here even with
    // show_mac_ false, just without the "eth <mac> -> <mac>" prefix ahead of it. Printed AFTER any
    // notes (rather than between the summary line and them) so a packet's own notes -- often
    // matched in tests immediately against the summary line right above them -- stay exactly
    // adjacent to it; this line is purely additive at the end of this packet's block.
    if (p.has_ethernet) {
        bool show_vlan_here = show_vlan_ && p.has_vlan_tag;
        // For a packet with no IP layer, the headline above already rendered src_mac/dst_mac (plus
        // any --oui vendor name) in place of the usual "-" placeholder -- see endpoint()'s own
        // comment -- so repeating that same pair on an "eth <mac> -> <mac>" line here would just be
        // noise, regardless of -e/--ether or --oui: show_mac_here is forced off in that case. A
        // VLAN tag (PROFINET RT/GOOSE/SV/EtherCAT commonly carry one) still gets its own bare
        // "vlan <id>" line exactly as it always has, same as the untagged/-e-off case already
        // produces below. For an IP-bearing packet nothing here changes: the headline shows IP
        // addresses, not MAC, so -e/--ether's own line is still the only place to see it.
        bool show_mac_here = show_mac_ && p.has_ip;
        if (show_mac_here || show_vlan_here) {
            out_ << "        ";
            if (color_) out_ << kDim;
            if (show_mac_here) {
                out_ << "eth " << p.src_mac;
                if (auto v = resolver_.oui_vendor(p.src_mac)) out_ << " (" << *v << ")";
                out_ << " -> " << p.dst_mac;
                if (auto v = resolver_.oui_vendor(p.dst_mac)) out_ << " (" << *v << ")";
                if (show_vlan_here) out_ << "  vlan " << p.vlan_id;
            } else {
                out_ << "vlan " << p.vlan_id;
            }
            if (color_) out_ << kReset;
            out_ << "\n";
        }
    }
}

void JsonWriter::begin() { out_ << "[\n"; }

void JsonWriter::write_packet(const DecodedPacket& p) {
    if (wrote_any_) out_ << ",\n";
    wrote_any_ = true;
    out_ << "  {\n";
    out_ << "    \"index\": " << p.index << ",\n";
    out_ << "    \"timestamp\": " << std::fixed << std::setprecision(6) << p.timestamp << ",\n";
    out_ << "    \"captured_len\": " << p.captured_len << ",\n";
    out_ << "    \"original_len\": " << p.original_len << ",\n";
    // Resolver-derived fields (OUI vendor / hostname / service name) and the base src_mac/dst_mac
    // gap-fix (see resolver.hpp's file header and this feature's own notes) are all grouped in one
    // block here, right after original_len and before src_ip -- NOT scattered next to each field
    // they annotate (src_mac next to src_ip, a service name next to its port, etc.), which would
    // read more naturally but would insert content between fields several existing tests already
    // match as strictly adjacent (src_port/dst_port/tcp_flags/protocol, and protocol/summary) --
    // see CMakeLists.txt's hartip_modbus_collision_never_reports_hartip_protocol and
    // udp_ports_populate_json_and_csv tests. Every field below is present (as a string) or `null`
    // exactly like src_ip/dst_ip's own existing convention when the base value isn't applicable
    // (!has_ethernet); every *_vendor/*_hostname/*_service annotation field is OMITTED ENTIRELY on
    // a lookup miss or when that lookup is disabled, never emitted as null -- see resolver.hpp's
    // file header for why an annotation is held to a stricter "omit, don't clutter" standard than
    // a base decoded value.
    out_ << "    \"src_mac\": " << (p.has_ethernet ? ("\"" + json_escape(p.src_mac) + "\"") : "null") << ",\n";
    out_ << "    \"dst_mac\": " << (p.has_ethernet ? ("\"" + json_escape(p.dst_mac) + "\"") : "null") << ",\n";
    if (p.has_ethernet) {
        if (auto v = resolver_.oui_vendor(p.src_mac)) {
            out_ << "    \"src_mac_vendor\": \"" << json_escape(*v) << "\",\n";
        }
        if (auto v = resolver_.oui_vendor(p.dst_mac)) {
            out_ << "    \"dst_mac_vendor\": \"" << json_escape(*v) << "\",\n";
        }
        // VLAN ID, shown by default (--no-vlan omits both fields entirely, not just a value --
        // this isn't a resolver annotation with its own "omit on a miss" convention, it's a base
        // decoded fact the flag is meant to suppress outright). Mirrors policy_engine.cpp's own
        // write_policy_report_json convention for EthernetFlowReport: has_vlan_tag always present
        // alongside vlan_id, vlan_id null when untagged.
        if (show_vlan_) {
            out_ << "    \"has_vlan_tag\": " << (p.has_vlan_tag ? "true" : "false") << ",\n";
            out_ << "    \"vlan_id\": " << (p.has_vlan_tag ? std::to_string(p.vlan_id) : "null") << ",\n";
        }
    }
    if (p.has_ip) {
        if (auto h = resolver_.hostname(p.src_ip)) {
            out_ << "    \"src_hostname\": \"" << json_escape(*h) << "\",\n";
        }
        if (auto h = resolver_.hostname(p.dst_ip)) {
            out_ << "    \"dst_hostname\": \"" << json_escape(*h) << "\",\n";
        }
    }
    if (p.has_tcp || p.has_udp) {
        std::string proto = p.has_tcp ? "tcp" : "udp";
        if (auto s = resolver_.service_name(p.src_port, proto)) {
            out_ << "    \"src_port_service\": \"" << json_escape(*s) << "\",\n";
        }
        if (auto s = resolver_.service_name(p.dst_port, proto)) {
            out_ << "    \"dst_port_service\": \"" << json_escape(*s) << "\",\n";
        }
    }
    out_ << "    \"src_ip\": " << (p.has_ip ? ("\"" + json_escape(p.src_ip) + "\"") : "null") << ",\n";
    out_ << "    \"dst_ip\": " << (p.has_ip ? ("\"" + json_escape(p.dst_ip) + "\"") : "null") << ",\n";
    bool has_port = p.has_tcp || p.has_udp;
    out_ << "    \"src_port\": " << (has_port ? std::to_string(p.src_port) : "null") << ",\n";
    out_ << "    \"dst_port\": " << (has_port ? std::to_string(p.dst_port) : "null") << ",\n";
    out_ << "    \"tcp_flags\": " << (p.has_tcp ? ("\"" + json_escape(p.tcp_flags) + "\"") : "null") << ",\n";
    out_ << "    \"protocol\": \"" << json_escape(p.protocol) << "\",\n";
    out_ << "    \"summary\": \"" << json_escape(p.summary) << "\",\n";
    if (p.protocol == "modbus" && p.modbus_is_paired_response) {
        out_ << "    \"modbus_paired_request_index\": " << p.modbus_paired_request_index << ",\n";
    }
    if (p.protocol == "s7comm" && p.s7comm_has_function) {
        out_ << "    \"s7comm_function\": \"" << json_escape(p.s7comm_function_name) << "\",\n";
    }
    if (!p.s7comm_item_tags.empty()) {
        out_ << "    \"s7comm_items\": [";
        for (size_t i = 0; i < p.s7comm_item_tags.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.s7comm_item_tags[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (!p.s7comm_value_summaries.empty()) {
        out_ << "    \"s7comm_values\": [";
        for (size_t i = 0; i < p.s7comm_value_summaries.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.s7comm_value_summaries[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (!p.s7comm_plc_stop_message.empty()) {
        out_ << "    \"s7comm_plc_stop_message\": \"" << json_escape(p.s7comm_plc_stop_message) << "\",\n";
    }
    if (p.s7comm_has_pi_service) {
        out_ << "    \"s7comm_pi_service_name\": \"" << json_escape(p.s7comm_pi_service_name) << "\",\n";
        if (!p.s7comm_pi_service_description.empty()) {
            out_ << "    \"s7comm_pi_service_description\": \"" << json_escape(p.s7comm_pi_service_description)
                 << "\",\n";
        }
    }
    if (!p.s7comm_pi_control_argument.empty()) {
        out_ << "    \"s7comm_pi_control_argument\": \"" << json_escape(p.s7comm_pi_control_argument) << "\",\n";
    }
    if (!p.s7comm_pi_control_blocks.empty()) {
        out_ << "    \"s7comm_pi_control_blocks\": [";
        for (size_t i = 0; i < p.s7comm_pi_control_blocks.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.s7comm_pi_control_blocks[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.s7comm_has_pi_control_status) {
        out_ << "    \"s7comm_pi_control_has_more_data\": "
             << (p.s7comm_pi_control_has_more_data ? "true" : "false") << ",\n";
        out_ << "    \"s7comm_pi_control_has_error\": " << (p.s7comm_pi_control_has_error ? "true" : "false")
             << ",\n";
    }
    if (p.protocol == "dnp3") {
        out_ << "    \"dnp3_source_address\": " << p.dnp3_source_address << ",\n";
        out_ << "    \"dnp3_destination_address\": " << p.dnp3_destination_address << ",\n";
        out_ << "    \"dnp3_link_crc_valid\": " << (p.dnp3_link_crc_valid ? "true" : "false") << ",\n";
        out_ << "    \"dnp3_header_crc_valid\": " << (p.dnp3_header_crc_valid ? "true" : "false") << ",\n";
        out_ << "    \"dnp3_block_count\": " << p.dnp3_block_count << ",\n";
        out_ << "    \"dnp3_block_crc_failures\": " << p.dnp3_block_crc_failures << ",\n";
    }
    if (p.protocol == "dnp3" && p.dnp3_has_function) {
        out_ << "    \"dnp3_function\": \"" << json_escape(p.dnp3_function_name) << "\",\n";
    }
    if (!p.dnp3_object_headers.empty()) {
        out_ << "    \"dnp3_objects\": [";
        for (size_t i = 0; i < p.dnp3_object_headers.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.dnp3_object_headers[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (!p.dnp3_point_values.empty()) {
        out_ << "    \"dnp3_values\": [";
        for (size_t i = 0; i < p.dnp3_point_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.dnp3_point_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.protocol == "iec104" && p.iec104_has_asdu) {
        out_ << "    \"iec104_asdu_type\": \"" << json_escape(p.iec104_asdu_type_name) << "\",\n";
        out_ << "    \"iec104_asdu_type_short\": \"" << json_escape(p.iec104_asdu_type_short_name) << "\",\n";
        out_ << "    \"iec104_cot\": \"" << json_escape(p.iec104_cot_name) << "\",\n";
        out_ << "    \"iec104_common_address\": " << p.iec104_common_address << ",\n";
    }
    if (!p.iec104_object_values.empty()) {
        out_ << "    \"iec104_objects\": [";
        for (size_t i = 0; i < p.iec104_object_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.iec104_object_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.protocol == "enip" && !p.enip_command_name.empty()) {
        // Empty for a CIP I/O (implicit messaging) UDP datagram -- there is no encapsulation
        // command on the wire for that (see enip_has_io below and enip.hpp's file header comment).
        out_ << "    \"enip_command\": \"" << json_escape(p.enip_command_name) << "\",\n";
    }
    if (p.enip_has_cip) {
        out_ << "    \"enip_cip_is_response\": " << (p.enip_cip_is_response ? "true" : "false") << ",\n";
        out_ << "    \"enip_cip_service\": \"" << json_escape(p.enip_cip_service_name) << "\",\n";
        if (!p.enip_cip_path.empty()) {
            out_ << "    \"enip_cip_path\": \"" << json_escape(p.enip_cip_path) << "\",\n";
        }
        if (!p.enip_cip_status_name.empty()) {
            out_ << "    \"enip_cip_status\": \"" << json_escape(p.enip_cip_status_name) << "\",\n";
        }
    }
    if (!p.enip_cip_values.empty()) {
        out_ << "    \"enip_cip_values\": [";
        for (size_t i = 0; i < p.enip_cip_values.size(); ++i) {
            if (i != 0) out_ << ", ";
            out_ << "\"" << json_escape(p.enip_cip_values[i]) << "\"";
        }
        out_ << "],\n";
    }
    if (p.enip_has_io) {
        std::ostringstream connid;
        connid << "0x" << std::hex << std::uppercase << p.enip_io_connection_id;
        out_ << "    \"enip_io_connection_id\": \"" << connid.str() << "\",\n";
        out_ << "    \"enip_io_sequence_number\": " << p.enip_io_sequence_number << ",\n";
        if (p.enip_io_has_data) {
            out_ << "    \"enip_io_data_length\": " << p.enip_io_data_length << ",\n";
            out_ << "    \"enip_io_data_hex\": \"" << json_escape(p.enip_io_data_hex) << "\",\n";
        }
    }
    if (p.protocol == "profinet") {
        std::ostringstream fid;
        fid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.profinet_frame_id;
        out_ << "    \"profinet_frame_id\": \"" << fid.str() << "\",\n";
        out_ << "    \"profinet_frame_id_name\": \"" << json_escape(p.profinet_frame_id_name) << "\",\n";
    }
    if (p.profinet_has_dcp) {
        out_ << "    \"profinet_dcp_service\": \"" << json_escape(p.profinet_dcp_service_name) << "\",\n";
        out_ << "    \"profinet_dcp_service_type\": \"" << json_escape(p.profinet_dcp_service_type_name) << "\",\n";
        if (!p.profinet_dcp_blocks.empty()) {
            out_ << "    \"profinet_dcp_blocks\": [";
            for (size_t i = 0; i < p.profinet_dcp_blocks.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.profinet_dcp_blocks[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.profinet_has_cyclic_data) {
        out_ << "    \"profinet_cyclic_io_data_length\": " << p.profinet_cyclic_io_data_length << ",\n";
        out_ << "    \"profinet_cyclic_io_data_hex\": \"" << json_escape(p.profinet_cyclic_io_data_hex) << "\",\n";
        out_ << "    \"profinet_cyclic_cycle_counter\": " << p.profinet_cyclic_cycle_counter << ",\n";
        out_ << "    \"profinet_cyclic_data_status\": \"" << json_escape(p.profinet_cyclic_data_status_summary)
             << "\",\n";
        out_ << "    \"profinet_cyclic_transfer_status\": " << static_cast<unsigned>(p.profinet_cyclic_transfer_status)
             << ",\n";
    }
    if (p.protocol == "goose") {
        std::ostringstream appid;
        appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.goose_appid;
        out_ << "    \"goose_appid\": \"" << appid.str() << "\",\n";
        out_ << "    \"goose_is_gse_management\": " << (p.goose_is_gse_management ? "true" : "false") << ",\n";
    }
    if (p.goose_has_pdu) {
        out_ << "    \"goose_simulated\": " << (p.goose_simulated ? "true" : "false") << ",\n";
        out_ << "    \"goose_gocb_ref\": \"" << json_escape(p.goose_gocb_ref) << "\",\n";
        out_ << "    \"goose_dat_set\": \"" << json_escape(p.goose_dat_set) << "\",\n";
        if (!p.goose_go_id.empty()) out_ << "    \"goose_go_id\": \"" << json_escape(p.goose_go_id) << "\",\n";
        out_ << "    \"goose_st_num\": " << p.goose_st_num << ",\n";
        out_ << "    \"goose_sq_num\": " << p.goose_sq_num << ",\n";
        out_ << "    \"goose_conf_rev\": " << p.goose_conf_rev << ",\n";
        out_ << "    \"goose_num_dat_set_entries\": " << p.goose_num_dat_set_entries << ",\n";
        if (!p.goose_all_data.empty()) {
            out_ << "    \"goose_all_data\": [";
            for (size_t i = 0; i < p.goose_all_data.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.goose_all_data[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.protocol == "sv") {
        std::ostringstream appid;
        appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.sv_appid;
        out_ << "    \"sv_appid\": \"" << appid.str() << "\",\n";
        out_ << "    \"sv_simulated\": " << (p.sv_simulated ? "true" : "false") << ",\n";
        out_ << "    \"sv_no_asdu\": " << p.sv_no_asdu << ",\n";
        out_ << "    \"sv_asdu_count\": " << p.sv_asdu_count << ",\n";
        if (p.sv_asdu_count > 0) {
            out_ << "    \"sv_id\": \"" << json_escape(p.sv_id) << "\",\n";
            if (!p.sv_dat_set.empty()) out_ << "    \"sv_dat_set\": \"" << json_escape(p.sv_dat_set) << "\",\n";
            out_ << "    \"sv_smp_cnt\": " << p.sv_smp_cnt << ",\n";
            out_ << "    \"sv_conf_rev\": " << p.sv_conf_rev << ",\n";
            if (!p.sv_smp_synch.empty()) out_ << "    \"sv_smp_synch\": \"" << json_escape(p.sv_smp_synch) << "\",\n";
            if (p.sv_smp_rate != 0) out_ << "    \"sv_smp_rate\": " << p.sv_smp_rate << ",\n";
            if (!p.sv_smp_mod.empty()) out_ << "    \"sv_smp_mod\": \"" << json_escape(p.sv_smp_mod) << "\",\n";
            out_ << "    \"sv_seq_data_length\": " << p.sv_seq_data_length << ",\n";
            out_ << "    \"sv_seq_data_hex\": \"" << json_escape(p.sv_seq_data_hex) << "\",\n";
            if (!p.sv_gmid_hex.empty()) out_ << "    \"sv_gmid_hex\": \"" << json_escape(p.sv_gmid_hex) << "\",\n";
        }
        if (!p.sv_asdus.empty()) {
            out_ << "    \"sv_asdus\": [";
            for (size_t i = 0; i < p.sv_asdus.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.sv_asdus[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.protocol == "ethercat") {
        out_ << "    \"ethercat_frame_type\": " << static_cast<unsigned>(p.ethercat_frame_type) << ",\n";
        out_ << "    \"ethercat_frame_type_name\": \"" << json_escape(p.ethercat_frame_type_name) << "\",\n";
        out_ << "    \"ethercat_declared_length\": " << p.ethercat_declared_length << ",\n";
        out_ << "    \"ethercat_has_datagrams\": " << (p.ethercat_has_datagrams ? "true" : "false") << ",\n";
        if (p.ethercat_has_datagrams) {
            out_ << "    \"ethercat_datagram_count\": " << p.ethercat_datagram_count << ",\n";
            if (p.ethercat_datagram_count > 0) {
                out_ << "    \"ethercat_first_cmd\": " << static_cast<unsigned>(p.ethercat_first_cmd) << ",\n";
                out_ << "    \"ethercat_first_cmd_name\": \"" << json_escape(p.ethercat_first_cmd_name) << "\",\n";
                out_ << "    \"ethercat_first_idx\": " << static_cast<unsigned>(p.ethercat_first_idx) << ",\n";
                if (p.ethercat_first_logical_addressing) {
                    out_ << "    \"ethercat_first_logical_address\": " << p.ethercat_first_logical_address << ",\n";
                } else {
                    out_ << "    \"ethercat_first_adp\": " << p.ethercat_first_adp << ",\n";
                    out_ << "    \"ethercat_first_ado\": " << p.ethercat_first_ado << ",\n";
                }
                out_ << "    \"ethercat_first_data_length\": " << p.ethercat_first_data_length << ",\n";
                out_ << "    \"ethercat_first_data_hex\": \"" << json_escape(p.ethercat_first_data_hex) << "\",\n";
                out_ << "    \"ethercat_first_wkc\": " << p.ethercat_first_wkc << ",\n";
                out_ << "    \"ethercat_first_irq\": " << p.ethercat_first_irq << ",\n";
                out_ << "    \"ethercat_first_circulating\": " << (p.ethercat_first_circulating ? "true" : "false") << ",\n";
            }
            if (!p.ethercat_datagrams.empty()) {
                out_ << "    \"ethercat_datagrams\": [";
                for (size_t i = 0; i < p.ethercat_datagrams.size(); ++i) {
                    if (i != 0) out_ << ", ";
                    out_ << "\"" << json_escape(p.ethercat_datagrams[i]) << "\"";
                }
                out_ << "],\n";
            }
        }
    }
    if (p.protocol == "stp") {
        out_ << "    \"stp_protocol_version\": " << static_cast<unsigned>(p.stp_protocol_version) << ",\n";
        out_ << "    \"stp_protocol_version_name\": \"" << json_escape(p.stp_protocol_version_name) << "\",\n";
        out_ << "    \"stp_bpdu_type\": " << static_cast<unsigned>(p.stp_bpdu_type) << ",\n";
        out_ << "    \"stp_bpdu_type_name\": \"" << json_escape(p.stp_bpdu_type_name) << "\",\n";
        out_ << "    \"stp_is_tcn\": " << (p.stp_is_tcn ? "true" : "false") << ",\n";
        out_ << "    \"stp_is_spb\": " << (p.stp_is_spb ? "true" : "false") << ",\n";
        if (p.stp_has_common_body) {
            out_ << "    \"stp_flags\": " << static_cast<unsigned>(p.stp_flags) << ",\n";
            out_ << "    \"stp_flag_tca\": " << (p.stp_flag_tca ? "true" : "false") << ",\n";
            out_ << "    \"stp_flag_agreement\": " << (p.stp_flag_agreement ? "true" : "false") << ",\n";
            out_ << "    \"stp_flag_forwarding\": " << (p.stp_flag_forwarding ? "true" : "false") << ",\n";
            out_ << "    \"stp_flag_learning\": " << (p.stp_flag_learning ? "true" : "false") << ",\n";
            out_ << "    \"stp_flag_port_role\": \"" << json_escape(p.stp_flag_port_role_name) << "\",\n";
            out_ << "    \"stp_flag_proposal\": " << (p.stp_flag_proposal ? "true" : "false") << ",\n";
            out_ << "    \"stp_flag_tc\": " << (p.stp_flag_tc ? "true" : "false") << ",\n";
            out_ << "    \"stp_root_priority\": " << p.stp_root_priority << ",\n";
            out_ << "    \"stp_root_sys_id_ext\": " << p.stp_root_sys_id_ext << ",\n";
            out_ << "    \"stp_root_mac\": \"" << json_escape(p.stp_root_mac) << "\",\n";
            out_ << "    \"stp_root_path_cost\": " << p.stp_root_path_cost << ",\n";
            out_ << "    \"stp_bridge_priority\": " << p.stp_bridge_priority << ",\n";
            out_ << "    \"stp_bridge_sys_id_ext\": " << p.stp_bridge_sys_id_ext << ",\n";
            out_ << "    \"stp_bridge_mac\": \"" << json_escape(p.stp_bridge_mac) << "\",\n";
            out_ << "    \"stp_port_priority\": " << p.stp_port_priority << ",\n";
            out_ << "    \"stp_port_number\": " << p.stp_port_number << ",\n";
            out_ << "    \"stp_message_age\": " << std::fixed << std::setprecision(3) << p.stp_message_age << ",\n";
            out_ << "    \"stp_max_age\": " << std::fixed << std::setprecision(3) << p.stp_max_age << ",\n";
            out_ << "    \"stp_hello_time\": " << std::fixed << std::setprecision(3) << p.stp_hello_time << ",\n";
            out_ << "    \"stp_forward_delay\": " << std::fixed << std::setprecision(3) << p.stp_forward_delay << ",\n";
            out_ << "    \"stp_has_version1\": " << (p.stp_has_version1 ? "true" : "false") << ",\n";
            if (p.stp_has_version1) {
                out_ << "    \"stp_version_1_length\": " << static_cast<unsigned>(p.stp_version_1_length) << ",\n";
            }
            out_ << "    \"stp_is_mstp\": " << (p.stp_is_mstp ? "true" : "false") << ",\n";
            if (p.stp_is_mstp) {
                out_ << "    \"stp_version_3_length\": " << p.stp_version_3_length << ",\n";
                out_ << "    \"stp_mst_config_name\": \"" << json_escape(p.stp_mst_config_name) << "\",\n";
                out_ << "    \"stp_mst_config_revision_level\": " << p.stp_mst_config_revision_level << ",\n";
                out_ << "    \"stp_mst_config_digest\": \"" << json_escape(p.stp_mst_config_digest_hex) << "\",\n";
                out_ << "    \"stp_cist_internal_root_path_cost\": " << p.stp_cist_internal_root_path_cost << ",\n";
                out_ << "    \"stp_cist_bridge_priority\": " << p.stp_cist_bridge_priority << ",\n";
                out_ << "    \"stp_cist_bridge_sys_id_ext\": " << p.stp_cist_bridge_sys_id_ext << ",\n";
                out_ << "    \"stp_cist_bridge_mac\": \"" << json_escape(p.stp_cist_bridge_mac) << "\",\n";
                out_ << "    \"stp_cist_remaining_hops\": " << static_cast<unsigned>(p.stp_cist_remaining_hops) << ",\n";
                if (!p.stp_msti_messages.empty()) {
                    out_ << "    \"stp_msti_messages\": [";
                    for (size_t i = 0; i < p.stp_msti_messages.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.stp_msti_messages[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
            out_ << "    \"stp_is_alt_msti_format\": " << (p.stp_is_alt_msti_format ? "true" : "false") << ",\n";
        }
    }
    if (p.protocol == "devicenet") {
        std::ostringstream canid;
        canid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.devicenet_can_id;
        out_ << "    \"devicenet_can_id\": \"" << canid.str() << "\",\n";
        out_ << "    \"devicenet_group\": " << p.devicenet_group << ",\n";
        out_ << "    \"devicenet_group_name\": \"" << json_escape(p.devicenet_group_name) << "\",\n";
        out_ << "    \"devicenet_message_type\": \"" << json_escape(p.devicenet_message_type_name) << "\",\n";
        if (p.devicenet_has_source_mac_id) {
            out_ << "    \"devicenet_source_mac_id\": " << static_cast<unsigned>(p.devicenet_source_mac_id) << ",\n";
        }
        if (p.devicenet_has_group3_header) {
            out_ << "    \"devicenet_dest_mac_id\": " << static_cast<unsigned>(p.devicenet_dest_mac_id) << ",\n";
            out_ << "    \"devicenet_is_fragmented\": " << (p.devicenet_is_fragmented ? "true" : "false") << ",\n";
            out_ << "    \"devicenet_is_xid\": " << (p.devicenet_is_xid ? "true" : "false") << ",\n";
        }
        if (p.devicenet_has_cip_service) {
            out_ << "    \"devicenet_cip_is_response\": " << (p.devicenet_cip_is_response ? "true" : "false") << ",\n";
            out_ << "    \"devicenet_cip_service\": \"" << json_escape(p.devicenet_cip_service_name) << "\",\n";
        }
        if (p.devicenet_has_dup_mac_id_check) {
            out_ << "    \"devicenet_dup_mac_id_is_response\": "
                 << (p.devicenet_dup_mac_id_is_response ? "true" : "false") << ",\n";
            out_ << "    \"devicenet_dup_mac_id_physical_port_number\": "
                 << static_cast<unsigned>(p.devicenet_dup_mac_id_physical_port_number) << ",\n";
            out_ << "    \"devicenet_dup_mac_id_vendor_id\": " << p.devicenet_dup_mac_id_vendor_id << ",\n";
            out_ << "    \"devicenet_dup_mac_id_serial_number\": " << p.devicenet_dup_mac_id_serial_number << ",\n";
        }
        out_ << "    \"devicenet_fd\": " << (p.devicenet_fd ? "true" : "false") << ",\n";
        out_ << "    \"devicenet_payload_truncated\": " << (p.devicenet_payload_truncated ? "true" : "false") << ",\n";
        out_ << "    \"devicenet_payload_length\": " << p.devicenet_payload_length << ",\n";
        out_ << "    \"devicenet_payload_hex\": \"" << json_escape(p.devicenet_payload_hex) << "\",\n";
    }
    if (p.protocol == "bacnet") {
        out_ << "    \"bacnet_bvlc_function\": \"" << json_escape(p.bacnet_bvlc_function) << "\",\n";
        out_ << "    \"bacnet_has_npdu\": " << (p.bacnet_has_npdu ? "true" : "false") << ",\n";
        if (p.bacnet_has_npdu) {
            out_ << "    \"bacnet_npdu_version\": " << static_cast<unsigned>(p.bacnet_npdu_version) << ",\n";
            out_ << "    \"bacnet_npdu_is_network_layer_message\": "
                 << (p.bacnet_npdu_is_network_layer_message ? "true" : "false") << ",\n";
            out_ << "    \"bacnet_npdu_expecting_reply\": " << (p.bacnet_npdu_expecting_reply ? "true" : "false")
                 << ",\n";
            out_ << "    \"bacnet_npdu_priority\": " << static_cast<unsigned>(p.bacnet_npdu_priority) << ",\n";
            out_ << "    \"bacnet_npdu_has_dest\": " << (p.bacnet_npdu_has_dest ? "true" : "false") << ",\n";
            if (p.bacnet_npdu_has_dest) out_ << "    \"bacnet_npdu_dnet\": " << p.bacnet_npdu_dnet << ",\n";
            out_ << "    \"bacnet_npdu_has_src\": " << (p.bacnet_npdu_has_src ? "true" : "false") << ",\n";
            if (p.bacnet_npdu_has_src) out_ << "    \"bacnet_npdu_snet\": " << p.bacnet_npdu_snet << ",\n";
            if (p.bacnet_npdu_has_dest)
                out_ << "    \"bacnet_npdu_hop_count\": " << static_cast<unsigned>(p.bacnet_npdu_hop_count)
                     << ",\n";
            if (p.bacnet_npdu_is_network_layer_message) {
                out_ << "    \"bacnet_npdu_message_type\": \"" << json_escape(p.bacnet_npdu_message_type)
                     << "\",\n";
            }
            out_ << "    \"bacnet_has_apdu\": " << (p.bacnet_has_apdu ? "true" : "false") << ",\n";
            if (p.bacnet_has_apdu) {
                out_ << "    \"bacnet_apdu_type\": \"" << json_escape(p.bacnet_apdu_type) << "\",\n";
                if (!p.bacnet_service_name.empty())
                    out_ << "    \"bacnet_service_name\": \"" << json_escape(p.bacnet_service_name) << "\",\n";
                out_ << "    \"bacnet_invoke_id\": " << p.bacnet_invoke_id << ",\n";
                out_ << "    \"bacnet_segmented\": " << (p.bacnet_segmented ? "true" : "false") << ",\n";
                if (!p.bacnet_values.empty()) {
                    out_ << "    \"bacnet_values\": [";
                    for (size_t i = 0; i < p.bacnet_values.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.bacnet_values[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
    }
    if (p.protocol == "hartip") {
        out_ << "    \"hartip_version\": " << static_cast<unsigned>(p.hartip_version) << ",\n";
        out_ << "    \"hartip_message_type\": \"" << json_escape(p.hartip_message_type) << "\",\n";
        out_ << "    \"hartip_message_id\": \"" << json_escape(p.hartip_message_id) << "\",\n";
        out_ << "    \"hartip_status\": " << static_cast<unsigned>(p.hartip_status) << ",\n";
        out_ << "    \"hartip_transaction_id\": " << p.hartip_transaction_id << ",\n";
        out_ << "    \"hartip_msg_length\": " << p.hartip_msg_length << ",\n";
        if (p.hartip_has_session_init) {
            out_ << "    \"hartip_host_type\": \"" << json_escape(p.hartip_host_type_name) << "\",\n";
            out_ << "    \"hartip_inactivity_close_timer\": " << p.hartip_inactivity_close_timer << ",\n";
        }
        if (p.hartip_has_error) {
            out_ << "    \"hartip_error_code\": " << static_cast<unsigned>(p.hartip_error_code) << ",\n";
            out_ << "    \"hartip_error_code_name\": \"" << json_escape(p.hartip_error_code_name) << "\",\n";
        }
        out_ << "    \"hartip_has_pass_through\": " << (p.hartip_has_pass_through ? "true" : "false") << ",\n";
        if (p.hartip_has_pass_through) {
            out_ << "    \"hartip_frame_type\": \"" << json_escape(p.hartip_frame_type) << "\",\n";
            out_ << "    \"hartip_is_response\": " << (p.hartip_is_response ? "true" : "false") << ",\n";
            out_ << "    \"hartip_is_long_address\": " << (p.hartip_is_long_address ? "true" : "false") << ",\n";
            out_ << "    \"hartip_address\": \"" << json_escape(p.hartip_address_hex) << "\",\n";
            out_ << "    \"hartip_command\": " << static_cast<unsigned>(p.hartip_command) << ",\n";
            if (!p.hartip_command_name.empty())
                out_ << "    \"hartip_command_name\": \"" << json_escape(p.hartip_command_name) << "\",\n";
            if (p.hartip_is_response) {
                out_ << "    \"hartip_response_code\": " << static_cast<unsigned>(p.hartip_response_code) << ",\n";
                out_ << "    \"hartip_response_is_comm_error\": "
                     << (p.hartip_response_is_comm_error ? "true" : "false") << ",\n";
                if (!p.hartip_response_code_name.empty())
                    out_ << "    \"hartip_response_code_name\": \"" << json_escape(p.hartip_response_code_name)
                         << "\",\n";
                if (!p.hartip_comm_error_flags.empty()) {
                    out_ << "    \"hartip_comm_error_flags\": [";
                    for (size_t i = 0; i < p.hartip_comm_error_flags.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.hartip_comm_error_flags[i]) << "\"";
                    }
                    out_ << "],\n";
                }
                out_ << "    \"hartip_device_status\": " << static_cast<unsigned>(p.hartip_device_status) << ",\n";
                if (!p.hartip_device_status_flags.empty()) {
                    out_ << "    \"hartip_device_status_flags\": [";
                    for (size_t i = 0; i < p.hartip_device_status_flags.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.hartip_device_status_flags[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
            if (!p.hartip_values.empty()) {
                out_ << "    \"hartip_values\": [";
                for (size_t i = 0; i < p.hartip_values.size(); ++i) {
                    if (i != 0) out_ << ", ";
                    out_ << "\"" << json_escape(p.hartip_values[i]) << "\"";
                }
                out_ << "],\n";
            }
            // The classic wired-HART longitudinal (XOR) checksum -- unconditionally emitted
            // (unlike hartip_command_name/hartip_values, which are gated on non-empty) since a
            // zero/false pair is itself meaningful here: it's exactly what a truncated body
            // (checksum byte never read at all) also produces, and that truncation already gets
            // its own note -- mirrors dnp3_header_crc_valid's own "always present" convention.
            out_ << "    \"hartip_checksum\": " << static_cast<unsigned>(p.hartip_checksum) << ",\n";
            out_ << "    \"hartip_checksum_valid\": " << (p.hartip_checksum_valid ? "true" : "false") << ",\n";
        }
    }
    if (p.protocol == "opcua") {
        out_ << "    \"opcua_message_type\": \"" << json_escape(p.opcua_message_type) << "\",\n";
        out_ << "    \"opcua_chunk_type\": \"" << std::string(1, p.opcua_chunk_type) << "\",\n";
        out_ << "    \"opcua_message_size\": " << p.opcua_message_size << ",\n";
        out_ << "    \"opcua_has_secure_channel\": " << (p.opcua_has_secure_channel ? "true" : "false")
             << ",\n";
        if (p.opcua_has_secure_channel) {
            out_ << "    \"opcua_secure_channel_id\": " << p.opcua_secure_channel_id << ",\n";
            out_ << "    \"opcua_is_asymmetric\": " << (p.opcua_is_asymmetric ? "true" : "false") << ",\n";
            if (p.opcua_is_asymmetric) {
                out_ << "    \"opcua_security_policy_uri\": \"" << json_escape(p.opcua_security_policy_uri)
                     << "\",\n";
                out_ << "    \"opcua_has_sender_certificate\": "
                     << (p.opcua_has_sender_certificate ? "true" : "false") << ",\n";
                if (p.opcua_has_sender_certificate)
                    out_ << "    \"opcua_sender_certificate_length\": " << p.opcua_sender_certificate_length
                         << ",\n";
                out_ << "    \"opcua_has_receiver_certificate_thumbprint\": "
                     << (p.opcua_has_receiver_certificate_thumbprint ? "true" : "false") << ",\n";
            } else {
                out_ << "    \"opcua_token_id\": " << p.opcua_token_id << ",\n";
            }
            out_ << "    \"opcua_sequence_number\": " << p.opcua_sequence_number << ",\n";
            out_ << "    \"opcua_request_id\": " << p.opcua_request_id << ",\n";
        }
        out_ << "    \"opcua_service_recognized\": " << (p.opcua_service_recognized ? "true" : "false")
             << ",\n";
        if (p.opcua_service_recognized) {
            out_ << "    \"opcua_service_name\": \"" << json_escape(p.opcua_service_name) << "\",\n";
        }
        if (p.opcua_service_namespace != 0 || p.opcua_service_type_id != 0 || p.opcua_service_recognized) {
            out_ << "    \"opcua_service_namespace\": " << p.opcua_service_namespace << ",\n";
            out_ << "    \"opcua_service_type_id\": " << p.opcua_service_type_id << ",\n";
        }
        out_ << "    \"opcua_has_header\": " << (p.opcua_has_header ? "true" : "false") << ",\n";
        if (p.opcua_has_header) {
            out_ << "    \"opcua_request_handle\": " << p.opcua_request_handle << ",\n";
            out_ << "    \"opcua_is_response\": " << (p.opcua_is_response ? "true" : "false") << ",\n";
            if (p.opcua_is_response) {
                out_ << "    \"opcua_status_code\": " << p.opcua_status_code << ",\n";
                out_ << "    \"opcua_status_code_name\": \"" << json_escape(p.opcua_status_code_name)
                     << "\",\n";
                out_ << "    \"opcua_status_is_good\": " << (p.opcua_status_is_good ? "true" : "false")
                     << ",\n";
            }
        }
        if (!p.opcua_values.empty()) {
            out_ << "    \"opcua_values\": [";
            for (size_t i = 0; i < p.opcua_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.opcua_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"opcua_body_shown_as_hex\": " << (p.opcua_body_shown_as_hex ? "true" : "false")
             << ",\n";
        if (p.opcua_body_shown_as_hex) {
            out_ << "    \"opcua_body_length\": " << p.opcua_body_length << ",\n";
            out_ << "    \"opcua_body_hex\": \"" << json_escape(p.opcua_body_hex) << "\",\n";
        }
    }
    if (p.protocol == "mms") {
        out_ << "    \"mms_is_bare\": " << (p.mms_is_bare ? "true" : "false") << ",\n";
        if (!p.mms_is_bare) {
            out_ << "    \"mms_session_pdu\": \"" << json_escape(p.mms_session_pdu_name) << "\",\n";
            out_ << "    \"mms_has_presentation\": " << (p.mms_has_presentation ? "true" : "false") << ",\n";
            if (p.mms_has_presentation) {
                if (!p.mms_presentation_context_list.empty()) {
                    out_ << "    \"mms_presentation_contexts\": [";
                    for (size_t i = 0; i < p.mms_presentation_context_list.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mms_presentation_context_list[i]) << "\"";
                    }
                    out_ << "],\n";
                }
                out_ << "    \"mms_presentation_context_id\": " << p.mms_presentation_context_id << ",\n";
                out_ << "    \"mms_presentation_context_is_acse\": "
                     << (p.mms_presentation_context_is_acse ? "true" : "false") << ",\n";
            }
            out_ << "    \"mms_has_acse\": " << (p.mms_has_acse ? "true" : "false") << ",\n";
            if (p.mms_has_acse) {
                out_ << "    \"mms_acse_pdu\": \"" << json_escape(p.mms_acse_pdu_name) << "\",\n";
                if (!p.mms_acse_application_context_name.empty()) {
                    out_ << "    \"mms_acse_application_context_name\": \""
                         << json_escape(p.mms_acse_application_context_name) << "\",\n";
                }
                if (p.mms_acse_has_result) {
                    out_ << "    \"mms_acse_result\": \"" << json_escape(p.mms_acse_result_name) << "\",\n";
                }
                if (!p.mms_acse_values.empty()) {
                    out_ << "    \"mms_acse_values\": [";
                    for (size_t i = 0; i < p.mms_acse_values.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mms_acse_values[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
        out_ << "    \"mms_has_pdu\": " << (p.mms_has_pdu ? "true" : "false") << ",\n";
        if (p.mms_has_pdu) {
            out_ << "    \"mms_pdu\": \"" << json_escape(p.mms_pdu_name) << "\",\n";
            out_ << "    \"mms_is_response\": " << (p.mms_is_response ? "true" : "false") << ",\n";
            if (p.mms_has_invoke_id) {
                out_ << "    \"mms_invoke_id\": " << p.mms_invoke_id << ",\n";
            }
            out_ << "    \"mms_service_recognized\": " << (p.mms_service_recognized ? "true" : "false")
                 << ",\n";
            if (p.mms_service_recognized) {
                out_ << "    \"mms_service\": \"" << json_escape(p.mms_service_name) << "\",\n";
            }
            if (p.mms_has_error) {
                out_ << "    \"mms_error\": \"" << json_escape(p.mms_error_name) << "\",\n";
            }
        }
        if (!p.mms_values.empty()) {
            out_ << "    \"mms_values\": [";
            for (size_t i = 0; i < p.mms_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.mms_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"mms_body_shown_as_hex\": " << (p.mms_body_shown_as_hex ? "true" : "false") << ",\n";
        if (p.mms_body_shown_as_hex) {
            out_ << "    \"mms_body_length\": " << p.mms_body_length << ",\n";
            out_ << "    \"mms_body_hex\": \"" << json_escape(p.mms_body_hex) << "\",\n";
        }
    }
    if (p.protocol == "mqtt") {
        out_ << "    \"mqtt_packet_type\": \"" << json_escape(p.mqtt_packet_type_name) << "\",\n";
        out_ << "    \"mqtt_remaining_length\": " << p.mqtt_remaining_length << ",\n";
        if (!p.mqtt_protocol_version_name.empty()) {
            out_ << "    \"mqtt_protocol_version\": \"" << json_escape(p.mqtt_protocol_version_name) << "\",\n";
        }
        if (p.mqtt_packet_type_name == "PUBLISH") {
            out_ << "    \"mqtt_dup\": " << (p.mqtt_dup ? "true" : "false") << ",\n";
            out_ << "    \"mqtt_qos\": " << static_cast<unsigned>(p.mqtt_qos) << ",\n";
            out_ << "    \"mqtt_retain\": " << (p.mqtt_retain ? "true" : "false") << ",\n";
            out_ << "    \"mqtt_topic\": \"" << json_escape(p.mqtt_topic) << "\",\n";
        }
        if (p.mqtt_has_packet_id) {
            out_ << "    \"mqtt_packet_id\": " << p.mqtt_packet_id << ",\n";
        }
        if (p.mqtt_has_payload) {
            out_ << "    \"mqtt_payload_length\": " << p.mqtt_payload_length << ",\n";
            // Omitted only when a successful Sparkplug B decode cleared it (see mqtt.hpp) -- a
            // genuinely empty payload still renders an empty hex string, same as p.mqtt_payload_length == 0.
            bool hex_cleared_by_sparkplug = p.mqtt_payload_length > 0 && p.mqtt_payload_hex.empty();
            if (!hex_cleared_by_sparkplug) {
                out_ << "    \"mqtt_payload_hex\": \"" << json_escape(p.mqtt_payload_hex) << "\",\n";
            }
        }
        if (!p.mqtt_values.empty()) {
            out_ << "    \"mqtt_values\": [";
            for (size_t i = 0; i < p.mqtt_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.mqtt_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"mqtt_is_sparkplug\": " << (p.mqtt_is_sparkplug ? "true" : "false") << ",\n";
        if (p.mqtt_is_sparkplug) {
            out_ << "    \"mqtt_sparkplug_message_type\": \"" << json_escape(p.mqtt_sparkplug_message_type)
                 << "\",\n";
            out_ << "    \"mqtt_sparkplug_is_state\": " << (p.mqtt_sparkplug_is_state ? "true" : "false")
                 << ",\n";
            if (p.mqtt_sparkplug_is_state) {
                out_ << "    \"mqtt_sparkplug_state_host_id\": \"" << json_escape(p.mqtt_sparkplug_state_host_id)
                     << "\",\n";
                out_ << "    \"mqtt_sparkplug_state_text\": \"" << json_escape(p.mqtt_sparkplug_state_text)
                     << "\",\n";
            } else {
                out_ << "    \"mqtt_sparkplug_group_id\": \"" << json_escape(p.mqtt_sparkplug_group_id) << "\",\n";
                out_ << "    \"mqtt_sparkplug_edge_node_id\": \"" << json_escape(p.mqtt_sparkplug_edge_node_id)
                     << "\",\n";
                if (!p.mqtt_sparkplug_device_id.empty()) {
                    out_ << "    \"mqtt_sparkplug_device_id\": \"" << json_escape(p.mqtt_sparkplug_device_id)
                         << "\",\n";
                }
                out_ << "    \"mqtt_sparkplug_payload_decoded\": "
                     << (p.mqtt_sparkplug_payload_decoded ? "true" : "false") << ",\n";
                if (p.mqtt_sparkplug_has_timestamp) {
                    out_ << "    \"mqtt_sparkplug_timestamp\": " << p.mqtt_sparkplug_timestamp << ",\n";
                }
                if (p.mqtt_sparkplug_has_seq) {
                    out_ << "    \"mqtt_sparkplug_seq\": " << p.mqtt_sparkplug_seq << ",\n";
                }
                if (p.mqtt_sparkplug_has_uuid) {
                    out_ << "    \"mqtt_sparkplug_uuid\": \"" << json_escape(p.mqtt_sparkplug_uuid) << "\",\n";
                }
                if (p.mqtt_sparkplug_has_body) {
                    out_ << "    \"mqtt_sparkplug_body_length\": " << p.mqtt_sparkplug_body_length << ",\n";
                }
                out_ << "    \"mqtt_sparkplug_metric_count\": " << p.mqtt_sparkplug_metric_count << ",\n";
                if (!p.mqtt_sparkplug_metrics.empty()) {
                    out_ << "    \"mqtt_sparkplug_metrics\": [";
                    for (size_t i = 0; i < p.mqtt_sparkplug_metrics.size(); ++i) {
                        if (i != 0) out_ << ", ";
                        out_ << "\"" << json_escape(p.mqtt_sparkplug_metrics[i]) << "\"";
                    }
                    out_ << "],\n";
                }
            }
        }
    }
    if (p.protocol == "s7comm-plus") {
        out_ << "    \"s7plus_pdu_type\": \"" << json_escape(p.s7plus_pdu_type_name) << "\",\n";
        if (p.s7plus_is_keepalive) {
            out_ << "    \"s7plus_keepalive_seq\": " << static_cast<unsigned>(p.s7plus_keepalive_seq) << ",\n";
        }
        if (p.s7plus_has_opcode) {
            out_ << "    \"s7plus_opcode\": \"" << json_escape(p.s7plus_opcode_name) << "\",\n";
        }
        if (p.s7plus_has_function) {
            out_ << "    \"s7plus_function\": \"" << json_escape(p.s7plus_function_name) << "\",\n";
            out_ << "    \"s7plus_body_decoded\": " << (p.s7plus_body_decoded ? "true" : "false") << ",\n";
        }
        if (p.s7plus_has_sequence_number) {
            out_ << "    \"s7plus_sequence_number\": " << p.s7plus_sequence_number << ",\n";
        }
        if (p.s7plus_has_session_id) {
            out_ << "    \"s7plus_session_id\": " << p.s7plus_session_id << ",\n";
        }
        if (p.s7plus_has_return_value) {
            out_ << "    \"s7plus_return_code\": " << p.s7plus_return_code << ",\n";
            out_ << "    \"s7plus_return_code_name\": \"" << json_escape(p.s7plus_return_code_name) << "\",\n";
        }
        if (!p.s7plus_item_tags.empty()) {
            out_ << "    \"s7plus_items\": [";
            for (size_t i = 0; i < p.s7plus_item_tags.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_item_tags[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (!p.s7plus_value_summaries.empty()) {
            out_ << "    \"s7plus_values\": [";
            for (size_t i = 0; i < p.s7plus_value_summaries.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_value_summaries[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (!p.s7plus_item_errors.empty()) {
            out_ << "    \"s7plus_item_errors\": [";
            for (size_t i = 0; i < p.s7plus_item_errors.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.s7plus_item_errors[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (p.s7plus_has_integrity) {
            out_ << "    \"s7plus_integrity_digest_present\": "
                 << (p.s7plus_integrity_digest_present ? "true" : "false") << ",\n";
        }
        out_ << "    \"s7plus_has_trailer\": " << (p.s7plus_has_trailer ? "true" : "false") << ",\n";
    }
    if (p.protocol == "ffhse") {
        out_ << "    \"ffhse_version\": " << static_cast<unsigned>(p.ffhse_version) << ",\n";
        out_ << "    \"ffhse_options\": " << static_cast<unsigned>(p.ffhse_options) << ",\n";
        out_ << "    \"ffhse_protocol\": \"" << json_escape(p.ffhse_protocol_name) << "\",\n";
        out_ << "    \"ffhse_type\": \"" << json_escape(p.ffhse_type_name) << "\",\n";
        out_ << "    \"ffhse_confirmed\": " << (p.ffhse_confirmed ? "true" : "false") << ",\n";
        out_ << "    \"ffhse_service_id\": " << static_cast<unsigned>(p.ffhse_service_id) << ",\n";
        std::ostringstream fda_addr;
        fda_addr << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << p.ffhse_fda_address;
        out_ << "    \"ffhse_fda_address\": \"" << fda_addr.str() << "\",\n";
        out_ << "    \"ffhse_link_id\": " << p.ffhse_link_id << ",\n";
        out_ << "    \"ffhse_message_length\": " << p.ffhse_message_length << ",\n";
        if (p.ffhse_has_message_number) out_ << "    \"ffhse_message_number\": " << p.ffhse_message_number << ",\n";
        if (p.ffhse_has_invoke_id) out_ << "    \"ffhse_invoke_id\": " << p.ffhse_invoke_id << ",\n";
        if (p.ffhse_has_time_stamp) out_ << "    \"ffhse_time_stamp\": " << p.ffhse_time_stamp << ",\n";
        if (p.ffhse_has_extended_control_field)
            out_ << "    \"ffhse_extended_control_field\": " << p.ffhse_extended_control_field << ",\n";
        out_ << "    \"ffhse_message_name\": \"" << json_escape(p.ffhse_message_name) << "\",\n";
        out_ << "    \"ffhse_recognized\": " << (p.ffhse_recognized ? "true" : "false") << ",\n";
        out_ << "    \"ffhse_body_decoded\": " << (p.ffhse_body_decoded ? "true" : "false") << ",\n";
        if (!p.ffhse_values.empty()) {
            out_ << "    \"ffhse_values\": [";
            for (size_t i = 0; i < p.ffhse_values.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ffhse_values[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"ffhse_body_shown_as_hex\": " << (p.ffhse_body_shown_as_hex ? "true" : "false") << ",\n";
        if (p.ffhse_body_shown_as_hex) {
            out_ << "    \"ffhse_body_length\": " << p.ffhse_body_length << ",\n";
            out_ << "    \"ffhse_body_hex\": \"" << json_escape(p.ffhse_body_hex) << "\",\n";
        }
    }
    if (p.protocol == "dns" || p.protocol == "mdns" || p.protocol == "llmnr") {
        std::ostringstream txn_id;
        txn_id << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.dns_transaction_id;
        out_ << "    \"dns_transaction_id\": \"" << txn_id.str() << "\",\n";
        out_ << "    \"dns_is_response\": " << (p.dns_is_response ? "true" : "false") << ",\n";
        out_ << "    \"dns_opcode\": \"" << json_escape(p.dns_opcode_name) << "\",\n";
        out_ << "    \"dns_header_flags\": \"" << json_escape(p.dns_header_flags) << "\",\n";
        out_ << "    \"dns_rcode\": \"" << json_escape(p.dns_rcode_name) << "\",\n";
        out_ << "    \"dns_qdcount\": " << p.dns_qdcount << ",\n";
        out_ << "    \"dns_ancount\": " << p.dns_ancount << ",\n";
        out_ << "    \"dns_nscount\": " << p.dns_nscount << ",\n";
        out_ << "    \"dns_arcount\": " << p.dns_arcount << ",\n";
        if (!p.dns_records.empty()) {
            out_ << "    \"dns_records\": [";
            for (size_t i = 0; i < p.dns_records.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.dns_records[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"dns_records_truncated\": " << (p.dns_records_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "nbns") {
        std::ostringstream txn_id;
        txn_id << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << p.nbns_transaction_id;
        out_ << "    \"nbns_transaction_id\": \"" << txn_id.str() << "\",\n";
        out_ << "    \"nbns_is_response\": " << (p.nbns_is_response ? "true" : "false") << ",\n";
        out_ << "    \"nbns_opcode\": \"" << json_escape(p.nbns_opcode_name) << "\",\n";
        out_ << "    \"nbns_flags\": \"" << json_escape(p.nbns_flags) << "\",\n";
        out_ << "    \"nbns_rcode\": \"" << json_escape(p.nbns_rcode_name) << "\",\n";
        out_ << "    \"nbns_qdcount\": " << p.nbns_qdcount << ",\n";
        out_ << "    \"nbns_ancount\": " << p.nbns_ancount << ",\n";
        out_ << "    \"nbns_nscount\": " << p.nbns_nscount << ",\n";
        out_ << "    \"nbns_arcount\": " << p.nbns_arcount << ",\n";
        if (!p.nbns_records.empty()) {
            out_ << "    \"nbns_records\": [";
            for (size_t i = 0; i < p.nbns_records.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.nbns_records[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"nbns_records_truncated\": " << (p.nbns_records_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "doh") {
        out_ << "    \"doh_sni\": \"" << json_escape(p.doh_sni) << "\",\n";
        out_ << "    \"doh_matched_provider\": \"" << json_escape(p.doh_matched_provider) << "\",\n";
        if (!p.doh_alpn_protocols.empty()) {
            out_ << "    \"doh_alpn_protocols\": [";
            for (size_t i = 0; i < p.doh_alpn_protocols.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.doh_alpn_protocols[i]) << "\"";
            }
            out_ << "],\n";
        }
    }
    if (p.protocol == "rip") {
        out_ << "    \"rip_version\": " << static_cast<unsigned>(p.rip_version) << ",\n";
        out_ << "    \"rip_command\": \"" << json_escape(p.rip_command_name) << "\",\n";
        if (!p.rip_routes.empty()) {
            out_ << "    \"rip_routes\": [";
            for (size_t i = 0; i < p.rip_routes.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.rip_routes[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"rip_routes_truncated\": " << (p.rip_routes_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "icmp") {
        out_ << "    \"icmp_type\": " << static_cast<unsigned>(p.icmp_type) << ",\n";
        out_ << "    \"icmp_code\": " << static_cast<unsigned>(p.icmp_code) << ",\n";
        out_ << "    \"icmp_type_name\": \"" << json_escape(p.icmp_type_name) << "\",\n";
        if (!p.icmp_code_name.empty()) {
            out_ << "    \"icmp_code_name\": \"" << json_escape(p.icmp_code_name) << "\",\n";
        }
        out_ << "    \"icmp_checksum_valid\": " << (p.icmp_checksum_valid ? "true" : "false") << ",\n";
        if (p.icmp_type == 0 || p.icmp_type == 8) {  // Echo Reply/Request
            out_ << "    \"icmp_echo_identifier\": " << p.icmp_echo_identifier << ",\n";
            out_ << "    \"icmp_echo_sequence\": " << p.icmp_echo_sequence << ",\n";
        }
        if (p.icmp_type == 13 || p.icmp_type == 14) {  // Timestamp Request/Reply
            out_ << "    \"icmp_echo_identifier\": " << p.icmp_echo_identifier << ",\n";
            out_ << "    \"icmp_echo_sequence\": " << p.icmp_echo_sequence << ",\n";
            out_ << "    \"icmp_originate_timestamp_ms\": " << p.icmp_originate_timestamp_ms << ",\n";
            out_ << "    \"icmp_receive_timestamp_ms\": " << p.icmp_receive_timestamp_ms << ",\n";
            out_ << "    \"icmp_transmit_timestamp_ms\": " << p.icmp_transmit_timestamp_ms << ",\n";
        }
        if (p.icmp_next_hop_mtu != 0) {
            out_ << "    \"icmp_next_hop_mtu\": " << p.icmp_next_hop_mtu << ",\n";
        }
        if (!p.icmp_redirect_gateway.empty()) {
            out_ << "    \"icmp_redirect_gateway\": \"" << json_escape(p.icmp_redirect_gateway) << "\",\n";
        }
        if (p.icmp_type == 12) {  // Parameter Problem
            out_ << "    \"icmp_parameter_pointer\": " << static_cast<unsigned>(p.icmp_parameter_pointer) << ",\n";
        }
        if (!p.icmp_address_mask.empty()) {
            out_ << "    \"icmp_address_mask\": \"" << json_escape(p.icmp_address_mask) << "\",\n";
        }
        if (!p.icmp_embedded_datagram.empty()) {
            out_ << "    \"icmp_embedded_datagram\": \"" << json_escape(p.icmp_embedded_datagram) << "\",\n";
        }
        if (!p.icmp_router_addresses.empty()) {
            out_ << "    \"icmp_router_addresses\": [";
            for (size_t i = 0; i < p.icmp_router_addresses.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.icmp_router_addresses[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"icmp_router_addresses_truncated\": " << (p.icmp_router_addresses_truncated ? "true" : "false") << ",\n";
        }
    }
    if (p.protocol == "igmp") {
        out_ << "    \"igmp_version\": " << p.igmp_version << ",\n";
        out_ << "    \"igmp_type\": \"" << json_escape(p.igmp_type_name) << "\",\n";
        if (!p.igmp_group_address.empty()) {
            out_ << "    \"igmp_group_address\": \"" << json_escape(p.igmp_group_address) << "\",\n";
        }
        if (!p.igmp_group_records.empty()) {
            out_ << "    \"igmp_group_records\": [";
            for (size_t i = 0; i < p.igmp_group_records.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.igmp_group_records[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"igmp_group_records_truncated\": " << (p.igmp_group_records_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "vrrp") {
        out_ << "    \"vrrp_version\": " << static_cast<unsigned>(p.vrrp_version) << ",\n";
        out_ << "    \"vrrp_virtual_router_id\": " << static_cast<unsigned>(p.vrrp_virtual_router_id) << ",\n";
        out_ << "    \"vrrp_priority\": " << static_cast<unsigned>(p.vrrp_priority) << ",\n";
        if (!p.vrrp_ip_addresses.empty()) {
            out_ << "    \"vrrp_ip_addresses\": [";
            for (size_t i = 0; i < p.vrrp_ip_addresses.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.vrrp_ip_addresses[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"vrrp_ip_addresses_truncated\": " << (p.vrrp_ip_addresses_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "hsrp") {
        out_ << "    \"hsrp_version\": " << static_cast<unsigned>(p.hsrp_version) << ",\n";
        if (p.hsrp_version == 1) {
            out_ << "    \"hsrp_opcode\": \"" << json_escape(p.hsrp_opcode_name) << "\",\n";
            out_ << "    \"hsrp_state\": \"" << json_escape(p.hsrp_state_name) << "\",\n";
            out_ << "    \"hsrp_virtual_ip\": \"" << json_escape(p.hsrp_virtual_ip) << "\",\n";
        } else {
            if (!p.hsrp_tlv_types.empty()) {
                out_ << "    \"hsrp_tlv_types\": [";
                for (size_t i = 0; i < p.hsrp_tlv_types.size(); ++i) {
                    if (i != 0) out_ << ", ";
                    out_ << "\"" << json_escape(p.hsrp_tlv_types[i]) << "\"";
                }
                out_ << "],\n";
            }
            out_ << "    \"hsrp_tlvs_truncated\": " << (p.hsrp_tlvs_truncated ? "true" : "false") << ",\n";
        }
    }
    if (p.protocol == "igrp") {
        out_ << "    \"igrp_version\": " << static_cast<unsigned>(p.igrp_version) << ",\n";
        out_ << "    \"igrp_opcode\": \"" << json_escape(p.igrp_opcode_name) << "\",\n";
        out_ << "    \"igrp_autonomous_system\": " << p.igrp_autonomous_system << ",\n";
        if (!p.igrp_routes.empty()) {
            out_ << "    \"igrp_routes\": [";
            for (size_t i = 0; i < p.igrp_routes.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.igrp_routes[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"igrp_routes_truncated\": " << (p.igrp_routes_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "pim") {
        out_ << "    \"pim_type\": \"" << json_escape(p.pim_type_name) << "\",\n";
        if (!p.pim_hello_options.empty()) {
            out_ << "    \"pim_hello_options\": [";
            for (size_t i = 0; i < p.pim_hello_options.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.pim_hello_options[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"pim_hello_options_truncated\": " << (p.pim_hello_options_truncated ? "true" : "false") << ",\n";
        }
        if (!p.pim_register_inner_src_ip.empty() || !p.pim_register_inner_group_ip.empty()) {
            out_ << "    \"pim_register_border_bit\": " << (p.pim_register_border_bit ? "true" : "false") << ",\n";
            out_ << "    \"pim_register_null_register_bit\": " << (p.pim_register_null_register_bit ? "true" : "false") << ",\n";
            out_ << "    \"pim_register_inner_src_ip\": \"" << json_escape(p.pim_register_inner_src_ip) << "\",\n";
            out_ << "    \"pim_register_inner_group_ip\": \"" << json_escape(p.pim_register_inner_group_ip) << "\",\n";
        }
        if (!p.pim_register_stop_group.empty()) {
            out_ << "    \"pim_register_stop_group\": \"" << json_escape(p.pim_register_stop_group) << "\",\n";
            out_ << "    \"pim_register_stop_source\": \"" << json_escape(p.pim_register_stop_source) << "\",\n";
        }
        if (!p.pim_jp_groups.empty() || !p.pim_jp_upstream_neighbor.empty()) {
            out_ << "    \"pim_jp_upstream_neighbor\": \"" << json_escape(p.pim_jp_upstream_neighbor) << "\",\n";
            out_ << "    \"pim_jp_holdtime_sec\": " << p.pim_jp_holdtime_sec << ",\n";
            out_ << "    \"pim_jp_groups\": [";
            for (size_t i = 0; i < p.pim_jp_groups.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.pim_jp_groups[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"pim_jp_groups_truncated\": " << (p.pim_jp_groups_truncated ? "true" : "false") << ",\n";
        }
        if (!p.pim_bsr_address.empty()) {
            out_ << "    \"pim_bsr_fragment_tag\": " << p.pim_bsr_fragment_tag << ",\n";
            out_ << "    \"pim_bsr_hash_mask_len\": " << static_cast<unsigned>(p.pim_bsr_hash_mask_len) << ",\n";
            out_ << "    \"pim_bsr_priority\": " << static_cast<unsigned>(p.pim_bsr_priority) << ",\n";
            out_ << "    \"pim_bsr_address\": \"" << json_escape(p.pim_bsr_address) << "\",\n";
            out_ << "    \"pim_bsr_groups\": [";
            for (size_t i = 0; i < p.pim_bsr_groups.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.pim_bsr_groups[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"pim_bsr_groups_truncated\": " << (p.pim_bsr_groups_truncated ? "true" : "false") << ",\n";
        }
        if (!p.pim_assert_group.empty()) {
            out_ << "    \"pim_assert_group\": \"" << json_escape(p.pim_assert_group) << "\",\n";
            out_ << "    \"pim_assert_source\": \"" << json_escape(p.pim_assert_source) << "\",\n";
            out_ << "    \"pim_assert_rpt_bit\": " << (p.pim_assert_rpt_bit ? "true" : "false") << ",\n";
            out_ << "    \"pim_assert_metric_preference\": " << p.pim_assert_metric_preference << ",\n";
            out_ << "    \"pim_assert_metric\": " << p.pim_assert_metric << ",\n";
        }
        if (!p.pim_crp_rp_address.empty()) {
            out_ << "    \"pim_crp_prefix_count\": " << static_cast<unsigned>(p.pim_crp_prefix_count) << ",\n";
            out_ << "    \"pim_crp_priority\": " << static_cast<unsigned>(p.pim_crp_priority) << ",\n";
            out_ << "    \"pim_crp_holdtime_sec\": " << p.pim_crp_holdtime_sec << ",\n";
            out_ << "    \"pim_crp_rp_address\": \"" << json_escape(p.pim_crp_rp_address) << "\",\n";
            out_ << "    \"pim_crp_groups\": [";
            for (size_t i = 0; i < p.pim_crp_groups.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.pim_crp_groups[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"pim_crp_groups_truncated\": " << (p.pim_crp_groups_truncated ? "true" : "false") << ",\n";
        }
    }
    if (p.protocol == "eigrp") {
        out_ << "    \"eigrp_opcode\": \"" << json_escape(p.eigrp_opcode_name) << "\",\n";
        out_ << "    \"eigrp_autonomous_system\": " << p.eigrp_autonomous_system << ",\n";
        if (!p.eigrp_flags.empty()) {
            out_ << "    \"eigrp_flags\": [";
            for (size_t i = 0; i < p.eigrp_flags.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.eigrp_flags[i]) << "\"";
            }
            out_ << "],\n";
        }
        if (!p.eigrp_general_tlvs.empty()) {
            out_ << "    \"eigrp_general_tlvs\": [";
            for (size_t i = 0; i < p.eigrp_general_tlvs.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.eigrp_general_tlvs[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"eigrp_general_tlvs_truncated\": " << (p.eigrp_general_tlvs_truncated ? "true" : "false") << ",\n";
        if (!p.eigrp_routes.empty()) {
            out_ << "    \"eigrp_routes\": [";
            for (size_t i = 0; i < p.eigrp_routes.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.eigrp_routes[i]) << "\"";
            }
            out_ << "],\n";
        }
        out_ << "    \"eigrp_routes_truncated\": " << (p.eigrp_routes_truncated ? "true" : "false") << ",\n";
    }
    if (p.protocol == "ospf") {
        out_ << "    \"ospf_type\": \"" << json_escape(p.ospf_type_name) << "\",\n";
        out_ << "    \"ospf_router_id\": \"" << json_escape(p.ospf_router_id) << "\",\n";
        out_ << "    \"ospf_area_id\": \"" << json_escape(p.ospf_area_id) << "\",\n";
        out_ << "    \"ospf_auth_type\": \"" << json_escape(p.ospf_auth_type_name) << "\",\n";
        if (!p.ospf_hello_designated_router.empty() || !p.ospf_hello_neighbors.empty()) {
            out_ << "    \"ospf_hello_designated_router\": \"" << json_escape(p.ospf_hello_designated_router) << "\",\n";
            out_ << "    \"ospf_hello_backup_designated_router\": \"" << json_escape(p.ospf_hello_backup_designated_router) << "\",\n";
            out_ << "    \"ospf_hello_neighbors\": [";
            for (size_t i = 0; i < p.ospf_hello_neighbors.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ospf_hello_neighbors[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"ospf_hello_neighbors_truncated\": " << (p.ospf_hello_neighbors_truncated ? "true" : "false") << ",\n";
        }
        if (!p.ospf_dbd_lsa_headers.empty()) {
            out_ << "    \"ospf_dbd_lsa_headers\": [";
            for (size_t i = 0; i < p.ospf_dbd_lsa_headers.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ospf_dbd_lsa_headers[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"ospf_dbd_lsa_headers_truncated\": " << (p.ospf_dbd_lsa_headers_truncated ? "true" : "false") << ",\n";
        }
        if (!p.ospf_ls_requests.empty()) {
            out_ << "    \"ospf_ls_requests\": [";
            for (size_t i = 0; i < p.ospf_ls_requests.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ospf_ls_requests[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"ospf_ls_requests_truncated\": " << (p.ospf_ls_requests_truncated ? "true" : "false") << ",\n";
        }
        if (!p.ospf_ls_update_lsas.empty()) {
            out_ << "    \"ospf_ls_update_lsas\": [";
            for (size_t i = 0; i < p.ospf_ls_update_lsas.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ospf_ls_update_lsas[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"ospf_ls_update_lsas_truncated\": " << (p.ospf_ls_update_lsas_truncated ? "true" : "false") << ",\n";
        }
        if (!p.ospf_ls_ack_headers.empty()) {
            out_ << "    \"ospf_ls_ack_headers\": [";
            for (size_t i = 0; i < p.ospf_ls_ack_headers.size(); ++i) {
                if (i != 0) out_ << ", ";
                out_ << "\"" << json_escape(p.ospf_ls_ack_headers[i]) << "\"";
            }
            out_ << "],\n";
            out_ << "    \"ospf_ls_ack_headers_truncated\": " << (p.ospf_ls_ack_headers_truncated ? "true" : "false") << ",\n";
        }
    }
    out_ << "    \"notes\": [";
    for (size_t i = 0; i < p.notes.size(); ++i) {
        if (i != 0) out_ << ", ";
        out_ << "\"" << json_escape(p.notes[i]) << "\"";
    }
    out_ << "],\n";
    // Appended last, after every other field -- not next to "timestamp" (the raw epoch double
    // above, kept exactly as-is for machine parseability) -- specifically so this addition never
    // shifts the position of any existing field, the same "append-only" discipline src_mac_vendor/
    // dst_mac_vendor/etc. already follow here (see this class's own file header comment) for the
    // same reason: several tests match fields by exact adjacency. --time-format/--time-offset
    // (cli_main.cpp) control how this is rendered; see time_format.hpp.
    out_ << "    \"time\": \"" << json_escape(time_.format(p.timestamp)) << "\"";
    // How this TCP flow's client (initiator) side was determined -- "handshake"/"port-heuristic",
    // never "content" here (FlowDirectionTracker only tracks TCP flows, see flow_direction.hpp's
    // own file header) -- see DirectionSource's own comment (decoder.hpp) and docs/MANUAL.md's
    // ROADMAP item 19. Appended last, after "time" (now the new last field before these), for the
    // same append-only reason as every field above. Both null for a non-TCP packet, the same
    // "null, not omitted, when the base field doesn't apply" convention src_ip/src_port already
    // follow in this same object -- unlike a resolver *_vendor/*_hostname/*_service annotation,
    // which is omitted entirely on a miss (see this class's own comment above); these two aren't
    // annotations, they're base decoded values that simply don't exist for a non-TCP packet.
    // --no-direction (show_direction_) omits both fields entirely, not just a value -- the same
    // "omit outright" convention show_vlan_ already sets for has_vlan_tag/vlan_id above -- which is
    // why "time"'s own trailing comma moved here instead of staying on "time" unconditionally: with
    // show_direction_ false, "time" is the object's last field and must not have a dangling comma.
    if (show_direction_) {
        out_ << ",\n    \"direction_source\": "
             << (p.has_direction ? ("\"" + std::string(direction_source_name(p.direction_source)) + "\"") : "null")
             << ",\n    \"direction_client_ip\": "
             << (p.has_direction ? ("\"" + json_escape(p.direction_client_is_src ? p.src_ip : p.dst_ip) + "\"") : "null")
             << "\n";
    } else {
        out_ << "\n";
    }
    out_ << "  }";
}

void JsonWriter::end() { out_ << (wrote_any_ ? "\n]\n" : "]\n"); }

void CsvWriter::begin() {
    // vlan_id is a trailing column (rather than inserted next to src_mac/dst_mac, where it's
    // conceptually closest) specifically so it never shifts the position of any existing column --
    // several tests match adjacent fields by exact position (e.g.
    // resolver_base_src_dst_mac_always_present_regardless_of_no_oui's
    // "00:0c:29:11:22:33,00:0c:29:aa:bb:cc,,," expecting src_mac_vendor/dst_mac_vendor to
    // immediately follow dst_mac). Empty both when the packet carries no VLAN tag and when
    // --no-vlan suppresses display -- CSV has no null, and this column's header always exists
    // regardless of the flag, so the row shape never changes based on it.
    // "time" is appended last, after vlan_id -- not next to "timestamp" (the raw epoch value,
    // kept exactly as-is for machine parseability) -- so this new column never shifts the
    // position of any existing one; see this file's src_mac_vendor/dst_mac_vendor comment just
    // above for the same "append-only" discipline and why it matters here. --time-format/
    // --time-offset (cli_main.cpp) control how it's rendered; see time_format.hpp.
    //
    // direction_source/direction_client_ip are appended after `time`, now the new last two
    // columns, for the same append-only reason -- see DirectionSource's own comment (decoder.hpp)
    // and docs/MANUAL.md's ROADMAP item 19. Both are empty for a non-TCP packet (has_direction
    // false -- FlowDirectionTracker's scope matches PolicyEngine::observe's own: TCP flows only,
    // see flow_direction.hpp) and, same as vlan_id above, also empty outright when --no-direction
    // suppresses display (show_direction_) regardless of has_direction -- this column's header
    // always exists either way, so the row shape never changes based on the flag.
    out_ << "index,timestamp,src_mac,dst_mac,src_mac_vendor,dst_mac_vendor,src_ip,src_hostname,"
            "src_port,src_port_service,dst_ip,dst_hostname,dst_port,dst_port_service,protocol,"
            "summary,notes,vlan_id,time,direction_source,direction_client_ip\n";
}

void CsvWriter::write_packet(const DecodedPacket& p) {
    std::ostringstream notes;
    for (size_t i = 0; i < p.notes.size(); ++i) {
        if (i != 0) notes << " | ";
        notes << p.notes[i];
    }
    bool has_port = p.has_tcp || p.has_udp;
    std::string proto = p.has_tcp ? "tcp" : "udp";

    // Same "annotation, empty string on a miss/disabled, never a placeholder" convention as the
    // text/JSON writers -- see resolver.hpp's file header. src_mac/dst_mac themselves (the base
    // gap-fix, not a resolver annotation) are empty only when !has_ethernet, matching how src_ip/
    // dst_ip/src_port/dst_port already render empty when their own has_ip/has_tcp/has_udp is false.
    std::string src_mac_vendor, dst_mac_vendor, src_hostname, dst_hostname, src_port_service,
        dst_port_service;
    if (p.has_ethernet) {
        if (auto v = resolver_.oui_vendor(p.src_mac)) src_mac_vendor = *v;
        if (auto v = resolver_.oui_vendor(p.dst_mac)) dst_mac_vendor = *v;
    }
    if (p.has_ip) {
        if (auto h = resolver_.hostname(p.src_ip)) src_hostname = *h;
        if (auto h = resolver_.hostname(p.dst_ip)) dst_hostname = *h;
    }
    if (has_port) {
        if (auto s = resolver_.service_name(p.src_port, proto)) src_port_service = *s;
        if (auto s = resolver_.service_name(p.dst_port, proto)) dst_port_service = *s;
    }

    out_ << p.index << ',' << std::fixed << std::setprecision(6) << p.timestamp << ','
         << (p.has_ethernet ? csv_escape(p.src_mac) : "") << ','
         << (p.has_ethernet ? csv_escape(p.dst_mac) : "") << ',' << csv_escape(src_mac_vendor) << ','
         << csv_escape(dst_mac_vendor) << ',' << (p.has_ip ? csv_escape(p.src_ip) : "") << ','
         << csv_escape(src_hostname) << ',' << (has_port ? std::to_string(p.src_port) : "") << ','
         << csv_escape(src_port_service) << ',' << (p.has_ip ? csv_escape(p.dst_ip) : "") << ','
         << csv_escape(dst_hostname) << ',' << (has_port ? std::to_string(p.dst_port) : "") << ','
         << csv_escape(dst_port_service) << ',' << csv_escape(p.protocol) << ','
         << csv_escape(p.summary) << ',' << csv_escape(notes.str()) << ','
         << ((show_vlan_ && p.has_vlan_tag) ? std::to_string(p.vlan_id) : "") << ','
         << csv_escape(time_.format(p.timestamp)) << ','
         << ((show_direction_ && p.has_direction) ? direction_source_name(p.direction_source) : "") << ','
         << ((show_direction_ && p.has_direction) ? csv_escape(p.direction_client_is_src ? p.src_ip : p.dst_ip)
                                                    : "")
         << "\n";
}

void StatsWriter::write_packet(const DecodedPacket& p) {
    total_packets_++;
    protocol_counts_[p.protocol]++;
    // Cross-protocol, not gated on p.protocol like the maps below -- see this member's own
    // comment (output.hpp). Not gated on `decode`'s --no-direction either: --stats has no display
    // toggles of its own (--no-vlan/--oui don't affect it), it's an aggregate view independent
    // of them, consistent with that precedent.
    if (p.has_direction) {
        direction_source_counts_[direction_source_name(p.direction_source)]++;
    }
    if (p.protocol == "modbus") {
        modbus_function_counts_[p.modbus_function_name]++;
        if (p.modbus_is_exception) modbus_exceptions_++;
        if (p.modbus_is_paired_response) modbus_paired_responses_++;
    }
    if (p.protocol == "s7comm" && p.s7comm_has_function) {
        s7comm_function_counts_[p.s7comm_function_name]++;
    }
    if (p.protocol == "dnp3" && p.dnp3_has_function) {
        dnp3_function_counts_[p.dnp3_function_name]++;
    }
    if (p.protocol == "iec104" && p.iec104_has_asdu) {
        iec104_asdu_type_counts_[p.iec104_asdu_type_name]++;
    }
    if (p.protocol == "enip") {
        if (!p.enip_command_name.empty()) enip_command_counts_[p.enip_command_name]++;
        if (p.enip_has_cip) enip_cip_service_counts_[p.enip_cip_service_name]++;
        if (p.enip_has_io) enip_io_datagram_count_++;
    }
    if (p.protocol == "profinet") {
        profinet_frame_id_counts_[p.profinet_frame_id_name]++;
        if (p.profinet_has_dcp) profinet_dcp_count_++;
        if (p.profinet_has_cyclic_data) profinet_cyclic_count_++;
    }
    if (p.protocol == "goose") {
        if (p.goose_has_pdu) goose_pdu_count_++;
        if (p.goose_is_gse_management) goose_gse_management_count_++;
        if (p.goose_simulated) goose_simulated_count_++;
    }
    if (p.protocol == "sv") {
        sv_frame_count_++;
        sv_asdu_total_ += p.sv_asdu_count;
    }
    if (p.protocol == "ethercat") {
        ethercat_frame_type_counts_[p.ethercat_frame_type_name]++;
        ethercat_datagram_total_ += p.ethercat_datagram_count;
    }
    if (p.protocol == "stp") {
        stp_bpdu_type_counts_[p.stp_bpdu_type_name]++;
        stp_protocol_version_counts_[p.stp_protocol_version_name]++;
        if (p.stp_is_mstp) {
            stp_mstp_count_++;
            stp_msti_total_ += p.stp_msti_messages.size();
        }
        if (p.stp_has_common_body && p.stp_flag_tc) stp_tc_count_++;
    }
    if (p.protocol == "devicenet") {
        devicenet_group_counts_[p.devicenet_group_name]++;
        devicenet_message_type_counts_[p.devicenet_message_type_name]++;
        if (p.devicenet_is_fragmented) devicenet_fragmented_count_++;
        if (p.devicenet_fd) devicenet_fd_count_++;
    }
    if (p.protocol == "bacnet") {
        bacnet_bvlc_function_counts_[p.bacnet_bvlc_function]++;
        if (p.bacnet_has_apdu && !p.bacnet_service_name.empty()) {
            bacnet_service_counts_[p.bacnet_service_name]++;
        }
    }
    if (p.protocol == "hartip") {
        hartip_message_type_counts_[p.hartip_message_type]++;
        if (p.hartip_has_pass_through) {
            std::string key = std::to_string(static_cast<unsigned>(p.hartip_command));
            if (!p.hartip_command_name.empty()) key += " (" + p.hartip_command_name + ")";
            hartip_command_counts_[key]++;
        }
    }
    if (p.protocol == "opcua") {
        opcua_message_type_counts_[p.opcua_message_type]++;
        if (p.opcua_service_recognized) {
            opcua_service_counts_[p.opcua_service_name]++;
        }
    }
    if (p.protocol == "mms") {
        if (p.mms_has_pdu) mms_pdu_counts_[p.mms_pdu_name]++;
        if (p.mms_service_recognized) mms_service_counts_[p.mms_service_name]++;
    }
    if (p.protocol == "mqtt") {
        mqtt_packet_type_counts_[p.mqtt_packet_type_name]++;
        if (p.mqtt_is_sparkplug) {
            mqtt_sparkplug_count_++;
            mqtt_sparkplug_message_type_counts_[p.mqtt_sparkplug_message_type]++;
        }
    }
    if (p.protocol == "s7comm-plus") {
        s7plus_pdu_type_counts_[p.s7plus_pdu_type_name]++;
        if (p.s7plus_has_function) {
            s7plus_function_counts_[p.s7plus_function_name]++;
            if (p.s7plus_body_decoded) s7plus_body_decoded_count_++;
        }
    }
    if (p.protocol == "ffhse") {
        ffhse_protocol_counts_[p.ffhse_protocol_name]++;
        if (p.ffhse_recognized) {
            ffhse_message_counts_[p.ffhse_message_name]++;
            if (p.ffhse_body_decoded) ffhse_body_decoded_count_++;
        }
    }
    if (p.protocol == "dns" || p.protocol == "mdns" || p.protocol == "llmnr") {
        dns_family_opcode_counts_[p.protocol + " " + p.dns_opcode_name]++;
    }
    if (p.protocol == "nbns") {
        nbns_opcode_counts_[p.nbns_opcode_name]++;
    }
    if (p.protocol == "doh") {
        doh_provider_counts_[p.doh_matched_provider]++;
    }
    if (p.protocol == "rip") {
        rip_command_counts_[p.rip_command_name]++;
    }
    if (p.protocol == "icmp") {
        icmp_type_counts_[p.icmp_type_name]++;
    }
    if (p.protocol == "igmp") {
        igmp_type_counts_[p.igmp_type_name]++;
    }
    if (p.protocol == "vrrp") {
        vrrp_version_counts_["VRRPv" + std::to_string(p.vrrp_version)]++;
    }
    if (p.protocol == "hsrp") {
        hsrp_version_counts_["HSRPv" + std::to_string(p.hsrp_version)]++;
    }
    if (p.protocol == "igrp") {
        igrp_opcode_counts_[p.igrp_opcode_name]++;
    }
    if (p.protocol == "pim") {
        pim_type_counts_[p.pim_type_name]++;
    }
    if (p.protocol == "eigrp") {
        eigrp_opcode_counts_[p.eigrp_opcode_name]++;
    }
    if (p.protocol == "ospf") {
        ospf_type_counts_[p.ospf_type_name]++;
    }
    if (!has_ts_) {
        first_ts_ = last_ts_ = p.timestamp;
        has_ts_ = true;
    } else {
        first_ts_ = std::min(first_ts_, p.timestamp);
        last_ts_ = std::max(last_ts_, p.timestamp);
    }
}

void StatsWriter::print_summary(std::ostream& out) const {
    out << "packets:        " << total_packets_ << "\n";
    if (has_ts_) {
        out << "time span:      " << std::fixed << std::setprecision(3) << (last_ts_ - first_ts_)
            << " s\n";
    }
    out << "protocols:\n";
    for (const auto& [name, count] : protocol_counts_) {
        out << "  " << std::left << std::setw(16) << name << count << "\n";
    }
    // Cross-protocol breakdown, printed right after the protocols histogram it complements rather
    // than down among the protocol-specific sections below -- see direction_source_counts_'s own
    // comment (output.hpp). Never populated (so never printed) for `info`, which never runs
    // FlowDirectionTracker.
    if (!direction_source_counts_.empty()) {
        out << "direction sources (tcp flows only):\n";
        for (const auto& [name, count] : direction_source_counts_) {
            out << "  " << std::left << std::setw(16) << name << count << "\n";
        }
    }
    if (!modbus_function_counts_.empty()) {
        out << "modbus function codes:\n";
        for (const auto& [name, count] : modbus_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "modbus exception responses: " << modbus_exceptions_ << "\n";
        out << "modbus responses authoritatively paired (transaction ID, not heuristic): "
            << modbus_paired_responses_ << "\n";
    }
    if (!s7comm_function_counts_.empty()) {
        out << "s7comm function codes:\n";
        for (const auto& [name, count] : s7comm_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!dnp3_function_counts_.empty()) {
        out << "dnp3 function codes:\n";
        for (const auto& [name, count] : dnp3_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!iec104_asdu_type_counts_.empty()) {
        out << "iec104 asdu types:\n";
        for (const auto& [name, count] : iec104_asdu_type_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!enip_command_counts_.empty()) {
        out << "enip encapsulation commands:\n";
        for (const auto& [name, count] : enip_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!enip_cip_service_counts_.empty()) {
        out << "enip cip services:\n";
        for (const auto& [name, count] : enip_cip_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (enip_io_datagram_count_ > 0) {
        out << "enip cip i/o (implicit messaging) datagrams: " << enip_io_datagram_count_ << "\n";
    }
    if (!profinet_frame_id_counts_.empty()) {
        out << "profinet frame id types:\n";
        for (const auto& [name, count] : profinet_frame_id_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
        out << "profinet dcp messages: " << profinet_dcp_count_ << "\n";
        out << "profinet cyclic rt io datagrams: " << profinet_cyclic_count_ << "\n";
    }
    if (goose_pdu_count_ > 0 || goose_gse_management_count_ > 0) {
        out << "goose pdus: " << goose_pdu_count_ << "\n";
        out << "goose gse management pdus (not decoded further): " << goose_gse_management_count_ << "\n";
        out << "goose simulated (S-bit or simulation field set): " << goose_simulated_count_ << "\n";
    }
    if (sv_frame_count_ > 0) {
        out << "sv frames: " << sv_frame_count_ << "\n";
        out << "sv asdus (summed across every frame): " << sv_asdu_total_ << "\n";
    }
    if (!ethercat_frame_type_counts_.empty()) {
        out << "ethercat frame types:\n";
        for (const auto& [name, count] : ethercat_frame_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "ethercat datagrams (summed across every frame): " << ethercat_datagram_total_ << "\n";
    }
    if (!stp_bpdu_type_counts_.empty()) {
        out << "stp bpdu types:\n";
        for (const auto& [name, count] : stp_bpdu_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "stp protocol versions:\n";
        for (const auto& [name, count] : stp_protocol_version_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "stp mst bpdus (full mst extension decoded): " << stp_mstp_count_ << "\n";
        out << "stp msti configuration messages (summed across every mst bpdu): " << stp_msti_total_ << "\n";
        out << "stp topology change flag set: " << stp_tc_count_ << "\n";
    }
    if (!devicenet_group_counts_.empty()) {
        out << "devicenet message groups:\n";
        for (const auto& [name, count] : devicenet_group_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "devicenet message types:\n";
        for (const auto& [name, count] : devicenet_message_type_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
        out << "devicenet fragmented group 3 messages: " << devicenet_fragmented_count_ << "\n";
        out << "devicenet can fd frames: " << devicenet_fd_count_ << "\n";
    }
    if (!bacnet_bvlc_function_counts_.empty()) {
        out << "bacnet bvlc functions:\n";
        for (const auto& [name, count] : bacnet_bvlc_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!bacnet_service_counts_.empty()) {
        out << "bacnet apdu services:\n";
        for (const auto& [name, count] : bacnet_service_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!hartip_message_type_counts_.empty()) {
        out << "hartip message types:\n";
        for (const auto& [name, count] : hartip_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!hartip_command_counts_.empty()) {
        out << "hartip pass-through commands:\n";
        for (const auto& [name, count] : hartip_command_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!opcua_message_type_counts_.empty()) {
        out << "opcua message types:\n";
        for (const auto& [name, count] : opcua_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!opcua_service_counts_.empty()) {
        out << "opcua services:\n";
        for (const auto& [name, count] : opcua_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!mms_pdu_counts_.empty()) {
        out << "mms pdu types:\n";
        for (const auto& [name, count] : mms_pdu_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!mms_service_counts_.empty()) {
        out << "mms services:\n";
        for (const auto& [name, count] : mms_service_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
    }
    if (!mqtt_packet_type_counts_.empty()) {
        out << "mqtt packet types:\n";
        for (const auto& [name, count] : mqtt_packet_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "mqtt sparkplug b publishes: " << mqtt_sparkplug_count_ << "\n";
    }
    if (!mqtt_sparkplug_message_type_counts_.empty()) {
        out << "mqtt sparkplug b message types:\n";
        for (const auto& [name, count] : mqtt_sparkplug_message_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!s7plus_pdu_type_counts_.empty()) {
        out << "s7comm-plus pdu types:\n";
        for (const auto& [name, count] : s7plus_pdu_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!s7plus_function_counts_.empty()) {
        out << "s7comm-plus functions:\n";
        for (const auto& [name, count] : s7plus_function_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "s7comm-plus function bodies fully decoded (Tier 1): " << s7plus_body_decoded_count_ << "\n";
    }
    if (!ffhse_protocol_counts_.empty()) {
        out << "ffhse sub-protocols:\n";
        for (const auto& [name, count] : ffhse_protocol_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!ffhse_message_counts_.empty()) {
        out << "ffhse messages:\n";
        for (const auto& [name, count] : ffhse_message_counts_) {
            out << "  " << std::left << std::setw(60) << name << count << "\n";
        }
        out << "ffhse message bodies fully decoded (Tier 1): " << ffhse_body_decoded_count_ << "\n";
    }
    if (!dns_family_opcode_counts_.empty()) {
        out << "dns/mdns/llmnr opcodes:\n";
        for (const auto& [name, count] : dns_family_opcode_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!nbns_opcode_counts_.empty()) {
        out << "nbns opcodes:\n";
        for (const auto& [name, count] : nbns_opcode_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!doh_provider_counts_.empty()) {
        out << "doh matched providers:\n";
        for (const auto& [name, count] : doh_provider_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!rip_command_counts_.empty()) {
        out << "rip commands:\n";
        for (const auto& [name, count] : rip_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!icmp_type_counts_.empty()) {
        out << "icmp types:\n";
        for (const auto& [name, count] : icmp_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!igmp_type_counts_.empty()) {
        out << "igmp types:\n";
        for (const auto& [name, count] : igmp_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!vrrp_version_counts_.empty()) {
        out << "vrrp versions:\n";
        for (const auto& [name, count] : vrrp_version_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!hsrp_version_counts_.empty()) {
        out << "hsrp versions:\n";
        for (const auto& [name, count] : hsrp_version_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!igrp_opcode_counts_.empty()) {
        out << "igrp opcodes:\n";
        for (const auto& [name, count] : igrp_opcode_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!pim_type_counts_.empty()) {
        out << "pim types:\n";
        for (const auto& [name, count] : pim_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!eigrp_opcode_counts_.empty()) {
        out << "eigrp opcodes:\n";
        for (const auto& [name, count] : eigrp_opcode_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!ospf_type_counts_.empty()) {
        out << "ospf types:\n";
        for (const auto& [name, count] : ospf_type_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
}

}  // namespace conduitscope
