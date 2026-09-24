// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/output.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "conduitscope/s7comm.hpp"

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

// Security fix (finding 4, docs/reviews/2026-09-chatgpt-security-review-patch160.md: "Terminal
// escape/control-sequence injection in text output"). Sanitizes packet-derived text before it
// reaches a real terminal -- TextWriter's own summary/note lines, and FieldsWriter's tab-
// separated field values (see both call sites' own comments for why each needs this). Never
// applied to JsonWriter/CsvWriter output -- those already have their own complete, different
// serialization rules (json_escape/csv_escape above), and running this on top would be both
// redundant and wrong (it would mangle JSON's own `\uXXXX` escapes as ordinary printable text).
//
// Summary/note text is built directly from wire bytes for several protocols today (DNS names,
// MQTT ClientId/Topic/Username/UserProperty/Sparkplug strings, and more -- see mqtt.cpp/dns.cpp),
// and used to reach the terminal completely unescaped. A malicious capture's summary/note text
// could contain ESC (0x1B) and drive a real ANSI/VT100 escape sequence on the analyst's own
// terminal -- this tool's own --color already legitimately emits real ANSI SGR sequences (see
// kReset/kBoldRed/etc. below), so escape sequences reaching the terminal aren't a boundary this
// tool avoids crossing itself, only one attacker-controlled bytes must stay on the wrong side
// of -- or embed a raw newline to forge what looks like a second, fabricated packet line in the
// one-line-per-packet view.
//
// Every C0 control byte (0x00-0x1F) and DEL (0x7F) is rendered as \xNN; everything else passes
// through unchanged. Deliberately a pure byte-range filter, not a UTF-8 decoder: valid UTF-8
// multi-byte sequences use only bytes >= 0x80, which this never touches, so "preserves printable
// UTF-8" falls out of the byte range alone rather than needing actual UTF-8-aware decoding -- the
// same reasoning to_hex/write_hex_ascii_dump below already lean on for not needing charset
// awareness. Already-invalid UTF-8 (also possible from arbitrary wire bytes) passes through
// unchanged too -- decoding validity isn't this function's job, only keeping control bytes out of
// the terminal is.
std::string terminal_escape(const std::string& s) {
    std::ostringstream out;
    for (unsigned char c : s) {
        if (c <= 0x1F || c == 0x7F) {
            out << "\\x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(c) << std::dec;
        } else {
            out << static_cast<char>(c);
        }
    }
    return out.str();
}

void write_hex_ascii_dump(std::ostream& out, ByteSpan data) {
    const size_t n = data.size();
    for (size_t offset = 0; offset < n; offset += 16) {
        out << std::hex << std::setfill('0') << std::setw(4) << offset << "  " << std::dec;
        std::string ascii;
        for (size_t col = 0; col < 16; ++col) {
            if (offset + col < n) {
                uint8_t b = data.at(offset + col);
                out << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(b) << std::dec << " ";
                ascii += (b >= 0x20 && b < 0x7f) ? static_cast<char>(b) : '.';
            } else {
                out << "   ";
            }
            if (col == 7) out << " ";
        }
        out << " " << ascii << "\n";
    }
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
// wouldn't require its own equally-long justification). One exception found later: kBoldMagenta
// (declared alongside kBoldBlue/kBoldCyan/kBoldGreen/kBoldRed/kBoldYellow above) was never actually
// claimed by any tag -- ARP's own entry below is the first to use it, completing the plain-bold
// family rather than opening a new dimension for a single new tag.
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
// LLDP: by the time this decoder was added, every plain/bright/bold/underline/italic/bold+underline/
// bold+italic/underline+italic/dim/bold+dim/strike hue combination above is already spoken for, and
// ARP's own addition just before this one already spent the last unclaimed plain-bold slot (see
// arp's own comment below) -- so this reuses the same dim+underline dimension ICMP introduced above,
// picking the next fresh hue in that family rather than inventing yet another modifier combination
// for a single new tag.
constexpr const char* kDimUnderlineGreen = "\033[2;4;32m";
// BGP: same dim+underline family ICMP/LLDP already established above -- four of its six hues
// (red/yellow/blue/magenta) remain unclaimed by the time BGP was added, so this just picks the
// next one (yellow) rather than opening yet another modifier dimension for a single new tag.
constexpr const char* kDimUnderlineYellow = "\033[2;4;33m";
// Slow Protocols (LACP/Marker/OAM): same dim+underline family -- blue/magenta remain unclaimed by
// the time this was added, so this picks blue.
constexpr const char* kDimUnderlineBlue = "\033[2;4;34m";

// TWO DELIBERATE EXCEPTIONS TO THIS FILE'S "16 standard ANSI colors only" CONVENTION, both from
// migration batch 2: Jurgen asked for TwinCAT's and S7comm/S7comm-Plus's tags to match their real
// vendors' actual brand colors (Beckhoff red, Siemens' official "Viridian Green"/Petrol teal),
// which the 16-color palette above cannot reproduce. Every OTHER tag's color in this function is
// picked purely for at-a-glance mixed-capture disambiguation, never for brand-matching -- these
// three 24-bit truecolor SGR escapes (\033[38;2;r;g;bm) are used ONLY for the tags below that
// specifically need an external hex value, not as a new general-purpose color dimension for future
// protocols. A terminal without truecolor support may render these as the nearest color it has (or
// ignore the escape) rather than the intended hue -- everywhere else in this file that's a non-
// issue since the 16 standard colors are universally supported.
constexpr const char* kBeckhoffRed = "\033[38;2;226;0;26m";   // #E2001A -- a reasonable, clearly-
                                     // labeled approximation of Beckhoff's own brand/logo red; no
                                     // single authoritative digital hex value was found for it,
                                     // unlike Siemens' own color below
constexpr const char* kSiemensTeal = "\033[38;2;0;153;153m";  // #009999 -- Siemens' own official
                                     // brand color since 1991 ("Viridian Green"/Petrol, Pantone
                                     // 7716 C, RAL 5018) -- confirmed via brandpalettes.com/
                                     // siemens-colors and schemecolor.com/siemens-logo-colors.php
constexpr const char* kSiemensTealBold = "\033[1;38;2;0;153;153m";  // s7comm-plus's own shade --
                                     // mirrors the s7comm-plain/mms-bold weight convention this
                                     // function already used to keep same-family tags visually
                                     // distinguishable (see mms's own comment below)

// Color for a packet's "[protocol]" tag -- picked so a mixed-protocol capture scans quickly by
// eye, not for any deeper meaning. parse-error is the one exception: it gets the same "something
// is wrong here" red as a Modbus exception response, rather than a plain identification color,
// since it's a problem rather than a protocol match.
const char* protocol_tag_color(const std::string& protocol) {
    if (protocol == "modbus") return kCyan;
    if (protocol == "dnp3") return kMagenta;
    if (protocol == "s7comm") return kSiemensTeal;  // Siemens' own brand teal, per Jurgen's
                                                       // request -- see kSiemensTeal's own comment
                                                       // above. NOT extended to "cotp" below (the
                                                       // family's generic recognized-but-not-S7comm
                                                       // fallback tag), which was not part of that
                                                       // request and stays plain blue.
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
    if (protocol == "twincat") return kBeckhoffRed;  // Beckhoff's own brand red, per Jurgen's
                                                        // request -- see kBeckhoffRed's own comment
                                                        // above. Pre-existing gap fix: TwinCAT was
                                                        // built on the registration-model
                                                        // ProtocolDecoder/renderer path from the
                                                        // start (see decoder.cpp's TwinCAT call
                                                        // site) but never had a tag-color entry
                                                        // here at all -- it silently fell through
                                                        // to the generic kDim default below.
    if (protocol == "mms") return kBoldBlue;  // kept at plain bold blue rather than following
                                                // s7comm into the new Siemens-teal family below
                                                // (not requested) -- MMS is a distinct IEC 61850
                                                // application protocol, not one of Siemens' own S7
                                                // product line, despite sharing their exact
                                                // TPKT/COTP transport/port
    if (protocol == "s7comm-plus") return kSiemensTealBold;  // Siemens' own brand teal, bold --
                                                                // per Jurgen's request, the same
                                                                // "same vendor's two generations"
                                                                // relationship this function
                                                                // already expressed between plain
                                                                // s7comm and bold mms, just now
                                                                // with s7comm/s7comm-plus sharing
                                                                // the teal family instead
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
    if (protocol == "arp") return kBoldMagenta;             // the one previously-unclaimed plain-bold
                                                              // hue -- see this function's own "Every
                                                              // plain/bright/bold combination... is
                                                              // already spoken for" comment above for
                                                              // why this, not a new dimension, is the
                                                              // right pick for a single new tag
    if (protocol == "lldp") return kDimUnderlineGreen;       // next fresh hue in the dim+underline
                                                              // family ICMP introduced -- every other
                                                              // combination, including plain-bold
                                                              // (arp just above spent the last one),
                                                              // is now fully claimed -- see
                                                              // kDimUnderlineGreen's own comment above
    if (protocol == "bgp") return kDimUnderlineYellow;        // next fresh hue in the dim+underline
                                                                 // family (see kDimUnderlineYellow's
                                                                 // own comment above)
    if (protocol == "slow-protocols") return kDimUnderlineBlue;  // see kDimUnderlineBlue's own comment above
    if (protocol == "parse-error") return kBoldRed;
    return kDim;  // tcp / udp / non-tcp / non-ip / unsupported-link: recognized, nothing OT-specific
}
}  // namespace

void TextWriter::write_packet(const DecodedPacket& p) {
    // A parse failure, or a Modbus exception response, is the one piece of a packet line worth
    // drawing the eye to over everything else in a long decode -- both mean "look at this one".
    bool severe = p.protocol == "parse-error" ||
                  (p.protocol == "modbus" && p.result && p.result->as<ModbusFrame>().is_exception);

    std::ostringstream head;
    head << "#" << p.index << "  " << time_.format(p.timestamp) << "  "
         << endpoint(p, true, resolver_) << " -> " << endpoint(p, false, resolver_) << "  ";
    if (color_) head << protocol_tag_color(p.protocol);
    head << "[" << p.protocol << "]";
    if (color_) head << kReset;
    head << "  ";
    if (color_ && severe) head << kBoldRed;
    // terminal_escape (finding 4) -- p.summary is built directly from wire bytes for several
    // protocols (DNS names, MQTT strings, ...) and, unlike JsonWriter/CsvWriter, this writer puts
    // it straight on the terminal with nothing else in between.
    head << terminal_escape(p.summary);
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
    // so this never appears for a UDP/non-IP/parse-error packet regardless of the flag. verbose_
    // (decode's own -v/--verbose, defaulting to false) is an ADDITIONAL gate on top of
    // show_direction_, not a replacement for it -- both must be true, so this suffix is hidden by
    // default (it was reported noisy appearing on every single line) and needs -v to reappear,
    // while --no-direction still suppresses it outright even under -v -- see verbose_'s own
    // comment (output.hpp).
    if (verbose_ && show_direction_ && p.has_direction) {
        bool uncertain = p.direction_source == DirectionSource::PortHeuristic;
        head << "  ";
        if (color_) head << (uncertain ? kYellow : kDim);
        head << "(client " << (p.direction_client_is_src ? p.src_ip : p.dst_ip) << " -- "
             << direction_source_name(p.direction_source) << ")";
        if (color_) head << kReset;
    }
    out_ << head.str() << "\n";

    // Suppressed by default (-v/--verbose, defaulting to false, see verbose_'s own comment,
    // output.hpp) -- a capture with several curated security-finding notes per packet otherwise
    // swamps the one-line-per-packet view these notes are meant to sit underneath. JSON/CSV/
    // FieldsWriter are unaffected -- notes are a proper structured field/column there, not visual
    // clutter on a shared terminal line.
    if (verbose_) {
        for (const auto& note : p.notes) {
            out_ << "        ";
            if (color_) out_ << kDim;
            out_ << "note: " << terminal_escape(note);  // finding 4 -- same rationale as p.summary above
            if (color_) out_ << kReset;
            out_ << "\n";
        }
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

namespace {

// registration-model decoder refactor (see protocol_decoder.hpp/decoder.hpp's DecodedPacket::result):
// the JSON-rendering analog of every `if (p.protocol == "x") { ... }` block above this point in
// JsonWriter::write_packet, for a protocol whose own fields were never flattened onto DecodedPacket
// in the first place (today, only TwinCAT -- see twincat.hpp's file header comment for why).
// Deliberately a plain free function, not a virtual ProtocolRenderer hierarchy: with exactly one
// protocol using this path so far, a full interface would be premature abstraction for no present
// benefit; TextWriter/CsvWriter need no equivalent at all, since both already render generically
// from DecodedPacket::protocol/summary/notes (already correctly populated for TwinCAT -- see
// decoder.cpp's TwinCAT call site) for every protocol, migrated or not.
void write_twincat_json_fields(std::ostream& out, const TwinCatFrame& tc) {
    out << "    \"twincat_command\": \"" << json_escape(tc.command_name) << "\",\n";
    out << "    \"twincat_is_response\": " << (tc.is_response ? "true" : "false") << ",\n";
    out << "    \"twincat_invoke_id\": " << tc.invoke_id << ",\n";
    out << "    \"twincat_target_ams_net_id\": \"" << json_escape(tc.target_ams_net_id) << "\",\n";
    out << "    \"twincat_target_ams_port\": " << tc.target_ams_port << ",\n";
    out << "    \"twincat_source_ams_net_id\": \"" << json_escape(tc.source_ams_net_id) << "\",\n";
    out << "    \"twincat_source_ams_port\": " << tc.source_ams_port << ",\n";
    if (tc.error_code != 0) {
        out << "    \"twincat_error_code\": " << tc.error_code << ",\n";
    }
    if (tc.has_index_addressing) {
        out << "    \"twincat_index_group\": " << tc.index_group << ",\n";
        out << "    \"twincat_index_offset\": " << tc.index_offset << ",\n";
    }
    if (tc.has_ads_result) {
        out << "    \"twincat_ads_result\": " << tc.ads_result << ",\n";
    }
    if (tc.paired_response) {
        out << "    \"twincat_paired_request_index\": " << tc.paired_request_index << ",\n";
    }
}

// The GOOSE analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Reproduces the exact two-tier truncation cap this always had:
// goose.cpp itself caps GooseFrame::all_data at max_goose_data_values() (default 200), and this
// function applies a SEPARATE, smaller cap (resource_limits().max_decoded_objects.value_or(50))
// when rendering goose_all_data for JSON -- the same pattern PROFINET RT's DCP blocks use
// (kMaxDcpBlocks vs kMaxDcpBlockValues). Also note goose_is_gse_management/goose_appid are always
// emitted for a "goose" packet, while the has_pdu-gated fields below were historically populated
// (and rendered) whenever GooseFrame::has_pdu was true regardless of DecodedPacket::protocol --
// moot in practice since has_pdu is only ever true on a GOOSE packet, but reproduced here exactly
// via the same `if (gs.has_pdu)` gate, not a `protocol == "goose"` gate.
void write_goose_json_fields(std::ostream& out, const GooseFrame& gs) {
    std::ostringstream appid;
    appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << gs.appid;
    out << "    \"goose_appid\": \"" << appid.str() << "\",\n";
    out << "    \"goose_is_gse_management\": " << (gs.is_gse_management ? "true" : "false") << ",\n";
    if (gs.has_pdu) {
        bool simulated = gs.header_simulated || (gs.simulation && *gs.simulation);
        out << "    \"goose_simulated\": " << (simulated ? "true" : "false") << ",\n";
        out << "    \"goose_gocb_ref\": \"" << json_escape(gs.gocb_ref) << "\",\n";
        out << "    \"goose_dat_set\": \"" << json_escape(gs.dat_set) << "\",\n";
        if (gs.go_id && !gs.go_id->empty()) {
            out << "    \"goose_go_id\": \"" << json_escape(*gs.go_id) << "\",\n";
        }
        out << "    \"goose_st_num\": " << gs.st_num << ",\n";
        out << "    \"goose_sq_num\": " << gs.sq_num << ",\n";
        out << "    \"goose_conf_rev\": " << gs.conf_rev << ",\n";
        out << "    \"goose_num_dat_set_entries\": " << gs.num_dat_set_entries << ",\n";
        const size_t kMaxGooseDataValueEntries = resource_limits().max_decoded_objects.value_or(50);
        std::vector<std::string> rendered;
        for (const auto& v : gs.all_data) {
            if (rendered.size() >= kMaxGooseDataValueEntries) break;
            std::string label = !v.type_name.empty() ? v.type_name : "raw";
            rendered.push_back(v.path + ": " + label + "=" + v.value);
        }
        if (!rendered.empty()) {
            out << "    \"goose_all_data\": [";
            for (size_t i = 0; i < rendered.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(rendered[i]) << "\"";
            }
            out << "],\n";
        }
    }
}

// The FF-HSE analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Reads straight from the FIRST coalesced PDU's own
// FfhseFrame (FfhseResult::first) -- exactly what the legacy call sites' own merge_ffhse lambda
// used to copy into DecodedPacket's flat fields only for `is_first_message`; every OTHER
// coalesced PDU (if any) contributes only its own notes (already folded into
// DecodedPacket::notes at the call site), never a second set of JSON fields, matching BGP's own
// "one full struct, extra ones as notes" posture for its own coalescing.
void write_ffhse_json_fields(std::ostream& out, const FfhseFrame& f) {
    out << "    \"ffhse_version\": " << static_cast<unsigned>(f.header.version) << ",\n";
    out << "    \"ffhse_options\": " << static_cast<unsigned>(f.header.options) << ",\n";
    out << "    \"ffhse_protocol\": \"" << json_escape(f.header.protocol_name) << "\",\n";
    out << "    \"ffhse_type\": \"" << json_escape(f.header.type_name) << "\",\n";
    out << "    \"ffhse_confirmed\": " << (f.header.confirmed ? "true" : "false") << ",\n";
    out << "    \"ffhse_service_id\": " << static_cast<unsigned>(f.header.service_id) << ",\n";
    std::ostringstream fda_addr;
    fda_addr << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << f.header.fda_address;
    out << "    \"ffhse_fda_address\": \"" << fda_addr.str() << "\",\n";
    out << "    \"ffhse_link_id\": " << f.header.link_id << ",\n";
    out << "    \"ffhse_message_length\": " << f.header.message_length << ",\n";
    if (f.trailer.has_message_number) out << "    \"ffhse_message_number\": " << f.trailer.message_number << ",\n";
    if (f.trailer.has_invoke_id) out << "    \"ffhse_invoke_id\": " << f.trailer.invoke_id << ",\n";
    if (f.trailer.has_time_stamp) out << "    \"ffhse_time_stamp\": " << f.trailer.time_stamp << ",\n";
    if (f.trailer.has_extended_control_field) {
        out << "    \"ffhse_extended_control_field\": " << f.trailer.extended_control_field << ",\n";
    }
    out << "    \"ffhse_message_name\": \"" << json_escape(f.message_name) << "\",\n";
    out << "    \"ffhse_recognized\": " << (f.recognized ? "true" : "false") << ",\n";
    out << "    \"ffhse_body_decoded\": " << (f.body_decoded ? "true" : "false") << ",\n";
    if (!f.values.empty()) {
        out << "    \"ffhse_values\": [";
        for (size_t i = 0; i < f.values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(f.values[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"ffhse_body_shown_as_hex\": " << (f.body_shown_as_hex ? "true" : "false") << ",\n";
    if (f.body_shown_as_hex) {
        out << "    \"ffhse_body_length\": " << f.body_length << ",\n";
        out << "    \"ffhse_body_hex\": \"" << json_escape(f.body_hex) << "\",\n";
    }
}

// The DeviceNet analog of write_twincat_json_fields above -- same rationale (a plain free
// function, not a ProtocolRenderer interface). Reads straight from the DeviceNetFrame carried by
// DecodedPacket::result -- see devicenet.hpp's own DeviceNetDecoder comment for why DeviceNet, the
// first GateKind::LinkType protocol, needed no separate "Result" wrapper struct (unlike FF-HSE/
// HART-IP/BGP, it has no coalescing concept at all: one CAN frame is always one message).
void write_devicenet_json_fields(std::ostream& out, const DeviceNetFrame& dn) {
    std::ostringstream canid;
    canid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << dn.can_id;
    out << "    \"devicenet_can_id\": \"" << canid.str() << "\",\n";
    out << "    \"devicenet_group\": " << dn.group << ",\n";
    out << "    \"devicenet_group_name\": \"" << json_escape(dn.group_name) << "\",\n";
    out << "    \"devicenet_message_type\": \"" << json_escape(dn.message_type_name) << "\",\n";
    if (dn.has_source_mac_id) {
        out << "    \"devicenet_source_mac_id\": " << static_cast<unsigned>(dn.source_mac_id) << ",\n";
    }
    if (dn.has_group3_header) {
        out << "    \"devicenet_dest_mac_id\": " << static_cast<unsigned>(dn.dest_mac_id) << ",\n";
        out << "    \"devicenet_is_fragmented\": " << (dn.is_fragmented ? "true" : "false") << ",\n";
        out << "    \"devicenet_is_xid\": " << (dn.is_xid ? "true" : "false") << ",\n";
    }
    if (dn.has_cip_service) {
        out << "    \"devicenet_cip_is_response\": " << (dn.cip_is_response ? "true" : "false") << ",\n";
        out << "    \"devicenet_cip_service\": \"" << json_escape(dn.cip_service_name) << "\",\n";
    }
    if (dn.has_dup_mac_id_check) {
        out << "    \"devicenet_dup_mac_id_is_response\": "
            << (dn.dup_mac_id_is_response ? "true" : "false") << ",\n";
        out << "    \"devicenet_dup_mac_id_physical_port_number\": "
            << static_cast<unsigned>(dn.dup_mac_id_physical_port_number) << ",\n";
        out << "    \"devicenet_dup_mac_id_vendor_id\": " << dn.dup_mac_id_vendor_id << ",\n";
        out << "    \"devicenet_dup_mac_id_serial_number\": " << dn.dup_mac_id_serial_number << ",\n";
    }
    out << "    \"devicenet_fd\": " << (dn.fd ? "true" : "false") << ",\n";
    out << "    \"devicenet_payload_truncated\": " << (dn.payload_truncated ? "true" : "false") << ",\n";
    out << "    \"devicenet_payload_length\": " << dn.payload.size() << ",\n";
    out << "    \"devicenet_payload_hex\": \"" << json_escape(to_hex(dn.payload, "")) << "\",\n";
}

// The DoH analog of write_twincat_json_fields above -- same rationale (a plain free function, not
// a ProtocolRenderer interface). Reads straight from the DohDetection carried by
// DecodedPacket::result. Reproduces the prior dual-write's exact field set and shape (doh_sni/
// doh_matched_provider always present, doh_alpn_protocols only when non-empty) -- see tls_sni.hpp's
// own DohDetection comment; there is deliberately no "doh_query"/"doh_answer" field of any kind,
// since the DNS message itself is TLS-encrypted and never visible to this decoder.
void write_doh_json_fields(std::ostream& out, const DohDetection& d) {
    out << "    \"doh_sni\": \"" << json_escape(d.sni) << "\",\n";
    out << "    \"doh_matched_provider\": \"" << json_escape(d.matched_provider) << "\",\n";
    if (!d.alpn_protocols.empty()) {
        out << "    \"doh_alpn_protocols\": [";
        for (size_t i = 0; i < d.alpn_protocols.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(d.alpn_protocols[i]) << "\"";
        }
        out << "],\n";
    }
}

// The WinRM analog of write_doh_json_fields above -- reads straight from the WinRmMessage carried
// by DecodedPacket::result. See winrm.hpp's own file header comment for what each field means;
// winrm_command_line is already redacted (or not) by the time it reaches here -- DecodeContext::
// redact_secrets was applied inside WinRmTcpDecoder::decode itself, the same "decode raw, redact
// before returning" order MQTT's own CONNECT password and HSRP's/VRRP's own plaintext auth field
// already establish.
void write_winrm_json_fields(std::ostream& out, const WinRmMessage& w) {
    out << "    \"winrm_is_response\": " << (w.is_response ? "true" : "false") << ",\n";
    if (!w.is_response) {
        out << "    \"winrm_http_method\": \"" << json_escape(w.http_method) << "\",\n";
        out << "    \"winrm_http_target\": \"" << json_escape(w.http_target) << "\",\n";
    } else {
        out << "    \"winrm_http_status\": " << w.http_status << ",\n";
        out << "    \"winrm_http_status_text\": \"" << json_escape(w.http_status_text) << "\",\n";
    }
    if (w.has_content_type) {
        out << "    \"winrm_content_type\": \"" << json_escape(w.content_type) << "\",\n";
    }
    out << "    \"winrm_chunked\": " << (w.chunked ? "true" : "false") << ",\n";
    if (w.has_content_length) {
        out << "    \"winrm_content_length\": " << w.declared_content_length << ",\n";
    }
    if (w.has_auth_header) {
        out << "    \"winrm_auth_scheme\": \"" << json_escape(w.auth_scheme) << "\",\n";
    }
    if (w.has_envelope) {
        out << "    \"winrm_action\": \"" << json_escape(w.wsa_action) << "\",\n";
        out << "    \"winrm_action_name\": \"" << json_escape(w.wsa_action_name) << "\",\n";
        if (!w.resource_uri.empty()) {
            out << "    \"winrm_resource_uri\": \"" << json_escape(w.resource_uri) << "\",\n";
        }
        if (w.is_cim_query) out << "    \"winrm_is_cim_query\": true,\n";
        if (w.is_psrp) out << "    \"winrm_is_psrp\": true,\n";
        if (w.has_shell_id) out << "    \"winrm_shell_id\": \"" << json_escape(w.shell_id) << "\",\n";
        if (w.has_command_id) out << "    \"winrm_command_id\": \"" << json_escape(w.command_id) << "\",\n";
        if (w.has_command_line) {
            out << "    \"winrm_command_line\": \"" << json_escape(w.command_line) << "\",\n";
        }
        if (w.has_wql_filter) out << "    \"winrm_wql_filter\": \"" << json_escape(w.wql_filter) << "\",\n";
        if (w.has_fault) {
            out << "    \"winrm_fault_reason\": \"" << json_escape(w.fault_reason) << "\",\n";
        }
    }
}

// Renders one DcomCall (dcom.hpp) as a JSON object's inner fields -- same conventions as
// write_drsuapi_call_json_fields above.
void write_dcom_call_json_fields(std::ostream& out, const DcomCall& c) {
    out << "        \"interface\": \"" << json_escape(c.interface_name) << "\",\n";
    out << "        \"opnum\": \"" << json_escape(c.opnum_name) << "\",\n";
    out << "        \"call_id\": " << c.call_id << ",\n";
    out << "        \"context_id\": " << c.context_id << ",\n";
    out << "        \"is_response\": " << (c.is_response ? "true" : "false") << ",\n";
    if (c.sealed) {
        out << "        \"sealed\": true,\n";
    }
    out << "        \"summary\": \"" << json_escape(c.summary) << "\"\n";
}

// The DCOM analog of write_winrm_json_fields above -- reads straight from the DcomMessage carried
// by DecodedPacket::result. dcom_calls mirrors write_drsuapi_call_json_fields's own array shape
// (drsuapi_calls, nested inside write_one_smb_message_json_fields below) -- but sits directly under
// the packet's own top-level JSON object instead of inside another message's own array, since DCOM
// is itself a top-level protocol (raw TCP/135, not SMB-wrapped -- see dcom.hpp's own TRANSPORT
// section), the same "top-level result, not a dual-written nested field" shape WinRM established.
void write_dcom_json_fields(std::ostream& out, const DcomMessage& m) {
    if (!m.calls.empty()) {
        out << "    \"dcom_calls\": [\n";
        for (size_t i = 0; i < m.calls.size(); ++i) {
            out << "      {\n";
            write_dcom_call_json_fields(out, m.calls[i]);
            out << "      }" << (i + 1 < m.calls.size() ? "," : "") << "\n";
        }
        out << "    ],\n";
    }
}

// The GE SRTP analog of write_melsec_json_fields above -- reads straight from the GeSrtpFrame
// carried by DecodedPacket::result. See ge_srtp.hpp's own file header comment for what each field
// means.
void write_ge_srtp_json_fields(std::ostream& out, const GeSrtpFrame& gf) {
    out << "    \"ge_srtp_packet_type\": \"" << json_escape(gf.packet_type_name) << "\",\n";
    out << "    \"ge_srtp_message_type\": \"" << json_escape(gf.message_type_name) << "\",\n";
    out << "    \"ge_srtp_is_response\": " << (gf.is_response ? "true" : "false") << ",\n";
    out << "    \"ge_srtp_sequence_number\": " << gf.sequence_number << ",\n";
    if (gf.has_service_request) {
        out << "    \"ge_srtp_service_request\": \"" << json_escape(gf.service_request_name) << "\",\n";
    }
    if (gf.has_target) {
        out << "    \"ge_srtp_target\": \"" << json_escape(gf.target.target_text) << "\",\n";
        out << "    \"ge_srtp_target_count\": " << gf.target.target_count << ",\n";
    }
    if (!gf.inline_payload_hex.empty()) {
        out << "    \"ge_srtp_inline_payload\": \"" << json_escape(gf.inline_payload_hex) << "\",\n";
    }
    if (gf.has_extended_trailing_payload) {
        out << "    \"ge_srtp_extended_trailing_payload_bytes\": "
            << gf.extended_trailing_payload_byte_count << ",\n";
    }
    if (gf.has_status) {
        out << "    \"ge_srtp_status\": \"" << json_escape(gf.status_code_name) << "\",\n";
        out << "    \"ge_srtp_return_data\": \"" << json_escape(gf.return_data_hex) << "\",\n";
    }
    if (gf.has_control_program_number) {
        out << "    \"ge_srtp_control_program_state\": \""
            << json_escape(gf.control_program_state) << "\",\n";
    }
    if (gf.has_undecoded_body) {
        out << "    \"ge_srtp_undecoded_body_bytes\": " << gf.undecoded_body_byte_count << ",\n";
    }
    out << "    \"ge_srtp_matched_to_request\": " << (gf.matched_to_request ? "true" : "false") << ",\n";
}

void write_bsap_json_fields(std::ostream& out, const BsapFrame& bf) {
    out << "    \"bsap_is_serial_tunnel\": " << (bf.is_serial_tunnel ? "true" : "false") << ",\n";
    if (bf.is_serial_tunnel) {
        out << "    \"bsap_is_global\": " << (bf.is_global ? "true" : "false") << ",\n";
        out << "    \"bsap_local_address\": " << static_cast<unsigned>(bf.local_address) << ",\n";
        out << "    \"bsap_ser\": " << static_cast<unsigned>(bf.ser) << ",\n";
        out << "    \"bsap_seq\": " << bf.seq << ",\n";
        if (bf.dfun_name) {
            out << "    \"bsap_dfun\": \"" << json_escape(*bf.dfun_name) << "\",\n";
        }
        if (bf.sfun_name) {
            out << "    \"bsap_sfun\": \"" << json_escape(*bf.sfun_name) << "\",\n";
        }
        if (bf.has_global_addressing) {
            out << "    \"bsap_dadd\": " << bf.dadd << ",\n";
            out << "    \"bsap_sadd\": " << bf.sadd << ",\n";
        }
    } else {
        out << "    \"bsap_leading_value\": " << bf.leading_value << ",\n";
        out << "    \"bsap_message_func\": " << bf.message_func << ",\n";
    }
    if (bf.has_trailing_data) {
        out << "    \"bsap_trailing_data_bytes\": " << bf.trailing_data_byte_count << ",\n";
    }
}

void write_cclink_ie_json_fields(std::ostream& out, const CclinkIeFrame& cf) {
    const char* kind_name = "cyclic-request";
    switch (cf.kind) {
        case CclinkIeMessageKind::CyclicRequest: kind_name = "cyclic-request"; break;
        case CclinkIeMessageKind::CyclicResponse: kind_name = "cyclic-response"; break;
        case CclinkIeMessageKind::NodeSearchRequest: kind_name = "node-search-request"; break;
        case CclinkIeMessageKind::NodeSearchResponse: kind_name = "node-search-response"; break;
        case CclinkIeMessageKind::SetIpAddressRequest: kind_name = "set-ip-address-request"; break;
        case CclinkIeMessageKind::SetIpAddressResponse: kind_name = "set-ip-address-response"; break;
    }
    out << "    \"cclink_ie_kind\": \"" << kind_name << "\",\n";
    if (cf.kind == CclinkIeMessageKind::CyclicRequest) {
        out << "    \"cclink_ie_master_id\": \"" << json_escape(cf.master_id) << "\",\n";
        out << "    \"cclink_ie_group_no\": " << static_cast<unsigned>(cf.group_no) << ",\n";
        out << "    \"cclink_ie_frame_sequence_no\": " << cf.frame_sequence_no << ",\n";
        out << "    \"cclink_ie_occupied_stations\": " << cf.occupied_stations << ",\n";
        out << "    \"cclink_ie_cyclic_io_bytes\": " << cf.cyclic_io_byte_count << ",\n";
    } else if (cf.kind == CclinkIeMessageKind::CyclicResponse) {
        out << "    \"cclink_ie_slave_id\": \"" << json_escape(cf.slave_id) << "\",\n";
        out << "    \"cclink_ie_frame_sequence_no\": " << cf.frame_sequence_no << ",\n";
        out << "    \"cclink_ie_end_code\": " << cf.end_code << ",\n";
        if (cf.end_code_name) {
            out << "    \"cclink_ie_end_code_name\": \"" << json_escape(*cf.end_code_name) << "\",\n";
        }
        if (cf.end_code == 0) {
            out << "    \"cclink_ie_occupied_stations\": " << cf.occupied_stations << ",\n";
            out << "    \"cclink_ie_cyclic_io_bytes\": " << cf.cyclic_io_byte_count << ",\n";
        }
    } else if (cf.kind == CclinkIeMessageKind::NodeSearchRequest ||
               cf.kind == CclinkIeMessageKind::SetIpAddressRequest) {
        out << "    \"cclink_ie_master_mac\": \"" << json_escape(cf.master_mac) << "\",\n";
        out << "    \"cclink_ie_master_ip\": \"" << json_escape(cf.master_ip) << "\",\n";
        if (cf.kind == CclinkIeMessageKind::SetIpAddressRequest) {
            out << "    \"cclink_ie_slave_mac\": \"" << json_escape(cf.slave_mac) << "\",\n";
            out << "    \"cclink_ie_slave_ip\": \"" << json_escape(cf.slave_ip) << "\",\n";
            out << "    \"cclink_ie_slave_netmask\": \"" << json_escape(cf.slave_netmask) << "\",\n";
        }
    } else {  // node-search-response / set-ip-address-response
        out << "    \"cclink_ie_end_code\": " << cf.end_code << ",\n";
        if (cf.end_code_name) {
            out << "    \"cclink_ie_end_code_name\": \"" << json_escape(*cf.end_code_name) << "\",\n";
        }
        if (cf.end_code == 0) {
            out << "    \"cclink_ie_master_mac\": \"" << json_escape(cf.master_mac) << "\",\n";
            if (cf.kind == CclinkIeMessageKind::NodeSearchResponse) {
                out << "    \"cclink_ie_slave_mac\": \"" << json_escape(cf.slave_mac) << "\",\n";
                out << "    \"cclink_ie_slave_ip\": \"" << json_escape(cf.slave_ip) << "\",\n";
                out << "    \"cclink_ie_vendor_code\": " << cf.vendor_code << ",\n";
                out << "    \"cclink_ie_model_code\": " << cf.model_code << ",\n";
            }
        }
    }
}

// Renders one RipRoute as a single line -- see rip.hpp for what each of the three RTE shapes
// (ordinary route, full-table-request marker, authentication entry) means. Reproduces
// decoder.cpp's own former rip_route_summary exactly (that copy was retired along with the
// dual-write it only existed to feed -- see rip.hpp's own file header for why this rendering
// belongs to output.cpp now, not decoder.cpp).
std::string rip_route_summary(const RipRoute& r) {
    if (r.is_auth_entry) {
        std::ostringstream s;
        s << "authentication: " << r.auth_type_name;
        if (r.auth_type == 3) {
            s << " (key id " << static_cast<unsigned>(r.md5_key_id) << ")";
        }
        return s.str();
    }
    if (r.is_full_table_request) {
        return "full table request";
    }
    std::ostringstream s;
    s << r.address << "/" << r.subnet_mask << " via " << r.next_hop << " metric " << r.metric;
    if (r.route_tag != 0) {
        s << " tag " << r.route_tag;
    }
    return s.str();
}

// The RIP analog of write_twincat_json_fields above -- same rationale (a plain free function, not
// a ProtocolRenderer interface). Reads straight from the RipMessage carried by
// DecodedPacket::result. Reproduces the prior dual-write's exact field set and shape.
void write_rip_json_fields(std::ostream& out, const RipMessage& msg) {
    out << "    \"rip_version\": " << static_cast<unsigned>(msg.version) << ",\n";
    out << "    \"rip_command\": \"" << json_escape(msg.command_name) << "\",\n";
    if (!msg.routes.empty()) {
        out << "    \"rip_routes\": [";
        for (size_t i = 0; i < msg.routes.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(rip_route_summary(msg.routes[i])) << "\"";
        }
        out << "],\n";
    }
    out << "    \"rip_routes_truncated\": " << (msg.routes_truncated ? "true" : "false") << ",\n";
}

// Renders one IgmpGroupRecord as a single line -- reproduces decoder.cpp's own former
// igmp_group_record_summary exactly, retired along with the dual-write it only existed to feed.
std::string igmp_group_record_summary(const IgmpGroupRecord& rec) {
    std::ostringstream s;
    s << rec.record_type_name << ": " << rec.multicast_address << " (" << rec.source_addresses.size()
      << " source(s))";
    return s.str();
}

// The IGMP analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Reads straight from the IgmpMessage carried by
// DecodedPacket::result. Reproduces the prior dual-write's exact field set and shape.
void write_igmp_json_fields(std::ostream& out, const IgmpMessage& msg) {
    out << "    \"igmp_version\": " << msg.version << ",\n";
    out << "    \"igmp_type\": \"" << json_escape(msg.type_name) << "\",\n";
    if (!msg.group_address.empty()) {
        out << "    \"igmp_group_address\": \"" << json_escape(msg.group_address) << "\",\n";
    }
    if (!msg.group_records.empty()) {
        out << "    \"igmp_group_records\": [";
        for (size_t i = 0; i < msg.group_records.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(igmp_group_record_summary(msg.group_records[i])) << "\"";
        }
        out << "],\n";
    }
    out << "    \"igmp_group_records_truncated\": " << (msg.group_records_truncated ? "true" : "false") << ",\n";
}

// The VRRP analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Reads straight from the VrrpMessage carried by
// DecodedPacket::result. Reproduces the prior dual-write's exact field set and shape -- there is
// deliberately no "vrrp_auth_password" field: no output.cpp reader ever rendered the old
// vrrp_auth_password flat field either (auth_simple_password, already redacted by
// VrrpDecoder::decode when active, is still present on the VrrpMessage itself for any future
// reader, just not written to JSON today).
void write_vrrp_json_fields(std::ostream& out, const VrrpMessage& msg) {
    out << "    \"vrrp_version\": " << static_cast<unsigned>(msg.version) << ",\n";
    out << "    \"vrrp_virtual_router_id\": " << static_cast<unsigned>(msg.virtual_router_id) << ",\n";
    out << "    \"vrrp_priority\": " << static_cast<unsigned>(msg.priority) << ",\n";
    if (!msg.ip_addresses.empty()) {
        out << "    \"vrrp_ip_addresses\": [";
        for (size_t i = 0; i < msg.ip_addresses.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(msg.ip_addresses[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"vrrp_ip_addresses_truncated\": " << (msg.ip_addresses_truncated ? "true" : "false") << ",\n";
}

// Renders one IgrpRoute as a single line -- see igrp.hpp for why route_kind changes how address
// was reconstructed. Reproduces decoder.cpp's own former igrp_route_summary exactly, retired
// along with the dual-write it only existed to feed.
std::string igrp_route_summary(const IgrpRoute& r) {
    std::ostringstream s;
    s << r.route_kind << " " << r.address;
    if (r.unreachable) {
        s << " unreachable";
    } else {
        s << " delay=" << r.delay_microseconds << "us bw=" << r.bandwidth_kbps
          << "kbps hops=" << static_cast<unsigned>(r.hop_count);
    }
    return s.str();
}

// The IGRP analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Reads straight from the IgrpMessage carried by
// DecodedPacket::result. Reproduces the prior dual-write's exact field set and shape.
void write_igrp_json_fields(std::ostream& out, const IgrpMessage& msg) {
    out << "    \"igrp_version\": " << static_cast<unsigned>(msg.version) << ",\n";
    out << "    \"igrp_opcode\": \"" << json_escape(msg.opcode_name) << "\",\n";
    out << "    \"igrp_autonomous_system\": " << msg.autonomous_system << ",\n";
    if (!msg.routes.empty()) {
        out << "    \"igrp_routes\": [";
        for (size_t i = 0; i < msg.routes.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(igrp_route_summary(msg.routes[i])) << "\"";
        }
        out << "],\n";
    }
    out << "    \"igrp_routes_truncated\": " << (msg.routes_truncated ? "true" : "false") << ",\n";
}

// Zero-flat-field migration (mid-size batch): the PROFINET analog of write_goose_json_fields
// above. Reproduces the exact same two-tier DCP block truncation decoder.cpp's old populate_profinet
// applied (kMaxDcpBlockValues == resource_limits().max_decoded_objects.value_or(50)).
void write_profinet_json_fields(std::ostream& out, const ProfinetFrame& pn) {
    std::ostringstream fid;
    fid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << pn.frame_id;
    out << "    \"profinet_frame_id\": \"" << fid.str() << "\",\n";
    out << "    \"profinet_frame_id_name\": \"" << json_escape(pn.frame_id_name) << "\",\n";
    if (pn.has_dcp) {
        out << "    \"profinet_dcp_service\": \"" << json_escape(pn.dcp_service_name) << "\",\n";
        out << "    \"profinet_dcp_service_type\": \"" << json_escape(pn.dcp_service_type_name) << "\",\n";
        const size_t kMaxDcpBlockValues = resource_limits().max_decoded_objects.value_or(50);
        std::vector<std::string> blocks;
        for (const auto& block : pn.dcp_blocks) {
            if (blocks.size() >= kMaxDcpBlockValues) break;
            std::string label = !block.name.empty() ? block.name
                                                      : ("option=" + std::to_string(block.option) +
                                                         " suboption=" + std::to_string(block.suboption));
            blocks.push_back(label + "=" + block.value);
        }
        if (!blocks.empty()) {
            out << "    \"profinet_dcp_blocks\": [";
            for (size_t i = 0; i < blocks.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(blocks[i]) << "\"";
            }
            out << "],\n";
        }
    }
    if (pn.has_cyclic_data) {
        out << "    \"profinet_cyclic_io_data_length\": " << pn.cyclic_io_data_length << ",\n";
        out << "    \"profinet_cyclic_io_data_hex\": \"" << json_escape(pn.cyclic_io_data_hex) << "\",\n";
        out << "    \"profinet_cyclic_cycle_counter\": " << pn.cyclic_cycle_counter << ",\n";
        out << "    \"profinet_cyclic_data_status\": \"" << json_escape(pn.cyclic_data_status_summary) << "\",\n";
        out << "    \"profinet_cyclic_transfer_status\": " << static_cast<unsigned>(pn.cyclic_transfer_status)
            << ",\n";
    }
}

// Zero-flat-field migration (mid-size batch): the SV (IEC 61850-9-2 Sampled Values) analog of
// write_goose_json_fields above. Reproduces the exact same asdus summary truncation decoder.cpp's
// old populate_sv applied (kMaxSvAsduSummaries == resource_limits().max_decoded_objects.value_or(50)).
void write_sv_json_fields(std::ostream& out, const SvFrame& sv) {
    std::ostringstream appid;
    appid << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << sv.appid;
    out << "    \"sv_appid\": \"" << appid.str() << "\",\n";
    out << "    \"sv_simulated\": " << (sv.header_simulated ? "true" : "false") << ",\n";
    out << "    \"sv_no_asdu\": " << sv.no_asdu << ",\n";
    out << "    \"sv_asdu_count\": " << sv.asdus.size() << ",\n";
    if (!sv.asdus.empty()) {
        // Gates below reproduce the exact old dual-write's OWN gates exactly: decoder.hpp's now-gone
        // flat sv_dat_set/sv_smp_synch/sv_smp_mod/sv_gmid_hex fields were plain (non-optional)
        // std::string members, populated only `if (first.x)`, then output.cpp's old reader gated on
        // the FLATTENED string being non-empty -- not on the optional itself being engaged. An
        // optional holding an empty string (were that ever to occur) must therefore still print
        // nothing here, exactly as it printed nothing before this migration.
        const SvAsdu& first = sv.asdus[0];
        out << "    \"sv_id\": \"" << json_escape(first.sv_id) << "\",\n";
        if (first.dat_set && !first.dat_set->empty()) {
            out << "    \"sv_dat_set\": \"" << json_escape(*first.dat_set) << "\",\n";
        }
        out << "    \"sv_smp_cnt\": " << first.smp_cnt << ",\n";
        out << "    \"sv_conf_rev\": " << first.conf_rev << ",\n";
        if (first.smp_synch && !first.smp_synch->empty()) {
            out << "    \"sv_smp_synch\": \"" << json_escape(*first.smp_synch) << "\",\n";
        }
        if (first.smp_rate && *first.smp_rate != 0) out << "    \"sv_smp_rate\": " << *first.smp_rate << ",\n";
        if (first.smp_mod && !first.smp_mod->empty()) {
            out << "    \"sv_smp_mod\": \"" << json_escape(*first.smp_mod) << "\",\n";
        }
        out << "    \"sv_seq_data_length\": " << first.seq_data_length << ",\n";
        out << "    \"sv_seq_data_hex\": \"" << json_escape(first.seq_data_hex) << "\",\n";
        if (first.gmid_hex && !first.gmid_hex->empty()) {
            out << "    \"sv_gmid_hex\": \"" << json_escape(*first.gmid_hex) << "\",\n";
        }
    }
    const size_t kMaxSvAsduSummaries = resource_limits().max_decoded_objects.value_or(50);
    std::vector<std::string> asdus;
    for (const auto& asdu : sv.asdus) {
        if (asdus.size() >= kMaxSvAsduSummaries) break;
        std::ostringstream a;
        a << "svID=\"" << asdu.sv_id << "\"";
        if (asdu.dat_set) a << " datSet=\"" << *asdu.dat_set << "\"";
        a << " smpCnt=" << asdu.smp_cnt << " confRev=" << asdu.conf_rev;
        if (asdu.smp_synch) a << " smpSynch=" << *asdu.smp_synch;
        if (asdu.smp_rate) a << " smpRate=" << *asdu.smp_rate;
        if (asdu.smp_mod) a << " smpMod=" << *asdu.smp_mod;
        a << " seqData=" << asdu.seq_data_length << " byte(s)";
        asdus.push_back(a.str());
    }
    if (!asdus.empty()) {
        out << "    \"sv_asdus\": [";
        for (size_t i = 0; i < asdus.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(asdus[i]) << "\"";
        }
        out << "],\n";
    }
}

// Zero-flat-field migration (mid-size batch): the EtherCAT analog of write_goose_json_fields above.
// Reproduces the exact same datagram summary truncation decoder.cpp's old populate_ethercat applied
// (kMaxEthercatDatagramSummaries == resource_limits().max_decoded_objects.value_or(50)).
void write_ethercat_json_fields(std::ostream& out, const EthercatFrame& ec) {
    out << "    \"ethercat_frame_type\": " << static_cast<unsigned>(ec.frame_type) << ",\n";
    out << "    \"ethercat_frame_type_name\": \"" << json_escape(ec.frame_type_name) << "\",\n";
    out << "    \"ethercat_declared_length\": " << ec.declared_length << ",\n";
    out << "    \"ethercat_has_datagrams\": " << (ec.has_datagrams ? "true" : "false") << ",\n";
    if (ec.has_datagrams) {
        out << "    \"ethercat_datagram_count\": " << ec.datagrams.size() << ",\n";
        if (!ec.datagrams.empty()) {
            const EthercatDatagram& first = ec.datagrams[0];
            out << "    \"ethercat_first_cmd\": " << static_cast<unsigned>(first.cmd) << ",\n";
            out << "    \"ethercat_first_cmd_name\": \"" << json_escape(first.cmd_name) << "\",\n";
            out << "    \"ethercat_first_idx\": " << static_cast<unsigned>(first.idx) << ",\n";
            if (first.logical_addressing) {
                out << "    \"ethercat_first_logical_address\": " << first.logical_address << ",\n";
            } else {
                out << "    \"ethercat_first_adp\": " << first.adp << ",\n";
                out << "    \"ethercat_first_ado\": " << first.ado << ",\n";
            }
            out << "    \"ethercat_first_data_length\": " << first.data_length << ",\n";
            out << "    \"ethercat_first_data_hex\": \"" << json_escape(first.data_hex) << "\",\n";
            out << "    \"ethercat_first_wkc\": " << first.wkc << ",\n";
            out << "    \"ethercat_first_irq\": " << first.irq << ",\n";
            out << "    \"ethercat_first_circulating\": " << (first.circulating ? "true" : "false") << ",\n";
        }
        const size_t kMaxEthercatDatagramSummaries = resource_limits().max_decoded_objects.value_or(50);
        std::vector<std::string> datagrams;
        for (const auto& dgram : ec.datagrams) {
            if (datagrams.size() >= kMaxEthercatDatagramSummaries) break;
            std::ostringstream a;
            a << dgram.cmd_name << " idx=" << static_cast<unsigned>(dgram.idx) << " ";
            if (dgram.logical_addressing) {
                a << "logAddr=0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0')
                  << dgram.logical_address << std::dec;
            } else {
                a << "adp=0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                  << dgram.adp << " ado=0x" << std::setw(4) << std::setfill('0') << dgram.ado
                  << std::dec;
            }
            a << " len=" << dgram.data_len << " wkc=" << dgram.wkc;
            if (dgram.irq != 0) {
                a << " irq=0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0')
                  << dgram.irq << std::dec;
            }
            if (dgram.circulating) a << " circulating";
            datagrams.push_back(a.str());
        }
        if (!datagrams.empty()) {
            out << "    \"ethercat_datagrams\": [";
            for (size_t i = 0; i < datagrams.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(datagrams[i]) << "\"";
            }
            out << "],\n";
        }
    }
}

// Zero-flat-field migration (mid-size batch): the STP analog of write_goose_json_fields above.
// stp_port_role_name/stp_render_msti_summary are stp.hpp's own free functions (already public,
// unlike icmp_router_address_summary/pim_*_summary below which were decoder.cpp-local and had to
// move here), so this function calls them directly rather than re-deriving anything. Reproduces the
// exact same MSTI summary truncation decoder.cpp's old inline STP call site applied
// (kMaxStpMstiSummaries == resource_limits().max_decoded_objects.value_or(50)).
void write_stp_json_fields(std::ostream& out, const StpFrame& stp) {
    out << "    \"stp_protocol_version\": " << static_cast<unsigned>(stp.protocol_version) << ",\n";
    out << "    \"stp_protocol_version_name\": \"" << json_escape(stp.protocol_version_name) << "\",\n";
    out << "    \"stp_bpdu_type\": " << static_cast<unsigned>(stp.bpdu_type) << ",\n";
    out << "    \"stp_bpdu_type_name\": \"" << json_escape(stp.bpdu_type_name) << "\",\n";
    out << "    \"stp_is_tcn\": " << (stp.is_tcn ? "true" : "false") << ",\n";
    out << "    \"stp_is_spb\": " << (stp.is_spb ? "true" : "false") << ",\n";
    if (stp.has_common_body) {
        out << "    \"stp_flags\": " << static_cast<unsigned>(stp.flags) << ",\n";
        out << "    \"stp_flag_tca\": " << (stp.flag_tca ? "true" : "false") << ",\n";
        out << "    \"stp_flag_agreement\": " << (stp.flag_agreement ? "true" : "false") << ",\n";
        out << "    \"stp_flag_forwarding\": " << (stp.flag_forwarding ? "true" : "false") << ",\n";
        out << "    \"stp_flag_learning\": " << (stp.flag_learning ? "true" : "false") << ",\n";
        out << "    \"stp_flag_port_role\": \"" << json_escape(stp_port_role_name(stp.flag_port_role)) << "\",\n";
        out << "    \"stp_flag_proposal\": " << (stp.flag_proposal ? "true" : "false") << ",\n";
        out << "    \"stp_flag_tc\": " << (stp.flag_tc ? "true" : "false") << ",\n";
        out << "    \"stp_root_priority\": " << stp.root_id.priority << ",\n";
        out << "    \"stp_root_sys_id_ext\": " << stp.root_id.ext << ",\n";
        out << "    \"stp_root_mac\": \"" << json_escape(format_mac(stp.root_id.mac)) << "\",\n";
        out << "    \"stp_root_path_cost\": " << stp.root_path_cost << ",\n";
        out << "    \"stp_bridge_priority\": " << stp.bridge_id.priority << ",\n";
        out << "    \"stp_bridge_sys_id_ext\": " << stp.bridge_id.ext << ",\n";
        out << "    \"stp_bridge_mac\": \"" << json_escape(format_mac(stp.bridge_id.mac)) << "\",\n";
        out << "    \"stp_port_priority\": " << stp.port_id_priority << ",\n";
        out << "    \"stp_port_number\": " << stp.port_id_number << ",\n";
        out << "    \"stp_message_age\": " << std::fixed << std::setprecision(3) << stp.message_age << ",\n";
        out << "    \"stp_max_age\": " << std::fixed << std::setprecision(3) << stp.max_age << ",\n";
        out << "    \"stp_hello_time\": " << std::fixed << std::setprecision(3) << stp.hello_time << ",\n";
        out << "    \"stp_forward_delay\": " << std::fixed << std::setprecision(3) << stp.forward_delay << ",\n";
        out << "    \"stp_has_version1\": " << (stp.has_version1 ? "true" : "false") << ",\n";
        if (stp.has_version1) {
            out << "    \"stp_version_1_length\": " << static_cast<unsigned>(stp.version_1_length) << ",\n";
        }
        out << "    \"stp_is_mstp\": " << (stp.is_mstp ? "true" : "false") << ",\n";
        if (stp.is_mstp) {
            out << "    \"stp_version_3_length\": " << stp.version_3_length << ",\n";
            out << "    \"stp_mst_config_name\": \"" << json_escape(stp.mst_config_name) << "\",\n";
            out << "    \"stp_mst_config_revision_level\": " << stp.mst_config_revision_level << ",\n";
            out << "    \"stp_mst_config_digest\": \"" << json_escape(stp.mst_config_digest_hex) << "\",\n";
            out << "    \"stp_cist_internal_root_path_cost\": " << stp.cist_internal_root_path_cost << ",\n";
            out << "    \"stp_cist_bridge_priority\": " << stp.cist_bridge_id.priority << ",\n";
            out << "    \"stp_cist_bridge_sys_id_ext\": " << stp.cist_bridge_id.ext << ",\n";
            out << "    \"stp_cist_bridge_mac\": \"" << json_escape(format_mac(stp.cist_bridge_id.mac)) << "\",\n";
            out << "    \"stp_cist_remaining_hops\": " << static_cast<unsigned>(stp.cist_remaining_hops) << ",\n";
            const size_t kMaxStpMstiSummaries = resource_limits().max_decoded_objects.value_or(50);
            std::vector<std::string> mstis;
            for (const auto& m : stp.msti_messages) {
                if (mstis.size() >= kMaxStpMstiSummaries) break;
                mstis.push_back(stp_render_msti_summary(m));
            }
            if (!mstis.empty()) {
                out << "    \"stp_msti_messages\": [";
                for (size_t i = 0; i < mstis.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(mstis[i]) << "\"";
                }
                out << "],\n";
            }
        }
        out << "    \"stp_is_alt_msti_format\": " << (stp.is_alt_msti_format ? "true" : "false") << ",\n";
    }
}

// Zero-flat-field migration (mid-size batch): the ICMP analog of write_goose_json_fields above.
// icmp_router_address_summary was decoder.cpp-local (unlike stp_port_role_name above); moved here
// since it's purely a rendering helper, same as rip_route_summary/igmp_group_record_summary/
// igrp_route_summary already are in this file.
std::string icmp_router_address_summary(const IcmpRouterAddress& ra) {
    std::ostringstream s;
    s << ra.address << " (" << ra.preference << ")";
    return s.str();
}

void write_icmp_json_fields(std::ostream& out, const IcmpMessage& msg) {
    out << "    \"icmp_type\": " << static_cast<unsigned>(msg.type) << ",\n";
    out << "    \"icmp_code\": " << static_cast<unsigned>(msg.code) << ",\n";
    out << "    \"icmp_type_name\": \"" << json_escape(msg.type_name) << "\",\n";
    if (!msg.code_name.empty()) {
        out << "    \"icmp_code_name\": \"" << json_escape(msg.code_name) << "\",\n";
    }
    out << "    \"icmp_checksum_valid\": " << (msg.checksum_valid ? "true" : "false") << ",\n";
    if (msg.type == 0 || msg.type == 8) {  // Echo Reply/Request
        out << "    \"icmp_echo_identifier\": " << msg.echo_identifier << ",\n";
        out << "    \"icmp_echo_sequence\": " << msg.echo_sequence << ",\n";
    }
    if (msg.type == 13 || msg.type == 14) {  // Timestamp Request/Reply
        out << "    \"icmp_echo_identifier\": " << msg.echo_identifier << ",\n";
        out << "    \"icmp_echo_sequence\": " << msg.echo_sequence << ",\n";
        out << "    \"icmp_originate_timestamp_ms\": " << msg.originate_timestamp_ms << ",\n";
        out << "    \"icmp_receive_timestamp_ms\": " << msg.receive_timestamp_ms << ",\n";
        out << "    \"icmp_transmit_timestamp_ms\": " << msg.transmit_timestamp_ms << ",\n";
    }
    if (msg.next_hop_mtu != 0) {
        out << "    \"icmp_next_hop_mtu\": " << msg.next_hop_mtu << ",\n";
    }
    if (!msg.redirect_gateway.empty()) {
        out << "    \"icmp_redirect_gateway\": \"" << json_escape(msg.redirect_gateway) << "\",\n";
    }
    if (msg.type == 12) {  // Parameter Problem
        out << "    \"icmp_parameter_pointer\": " << static_cast<unsigned>(msg.parameter_pointer) << ",\n";
    }
    if (!msg.address_mask.empty()) {
        out << "    \"icmp_address_mask\": \"" << json_escape(msg.address_mask) << "\",\n";
    }
    if (msg.embedded_datagram) {
        const auto& ed = *msg.embedded_datagram;
        std::ostringstream s;
        s << ed.src_addr << "->" << ed.dst_addr;
        if (!ed.protocol_name.empty()) {
            s << " (" << ed.protocol_name;
            if (ed.has_ports) s << " " << ed.src_port << "->" << ed.dst_port;
            s << ")";
        } else {
            s << " (IP protocol " << static_cast<unsigned>(ed.protocol) << ")";
        }
        out << "    \"icmp_embedded_datagram\": \"" << json_escape(s.str()) << "\",\n";
    }
    if (!msg.router_addresses.empty()) {
        out << "    \"icmp_router_addresses\": [";
        for (size_t i = 0; i < msg.router_addresses.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(icmp_router_address_summary(msg.router_addresses[i])) << "\"";
        }
        out << "],\n";
        out << "    \"icmp_router_addresses_truncated\": " << (msg.router_addresses_truncated ? "true" : "false")
            << ",\n";
    }
}

// Zero-flat-field migration (mid-size batch): the HSRP analog of write_goose_json_fields above.
void write_hsrp_json_fields(std::ostream& out, const HsrpMessage& msg) {
    out << "    \"hsrp_version\": " << static_cast<unsigned>(msg.version) << ",\n";
    if (msg.version == 1) {
        out << "    \"hsrp_opcode\": \"" << json_escape(msg.opcode_name) << "\",\n";
        out << "    \"hsrp_state\": \"" << json_escape(msg.state_name) << "\",\n";
        out << "    \"hsrp_virtual_ip\": \"" << json_escape(msg.virtual_ip) << "\",\n";
    } else {
        if (!msg.tlvs.empty()) {
            out << "    \"hsrp_tlv_types\": [";
            for (size_t i = 0; i < msg.tlvs.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(msg.tlvs[i].type_name) << "\"";
            }
            out << "],\n";
        }
        out << "    \"hsrp_tlvs_truncated\": " << (msg.tlvs_truncated ? "true" : "false") << ",\n";
    }
}

// Zero-flat-field migration (mid-size batch): the PIM analog of write_goose_json_fields above.
// pim_hello_option_summary/pim_jp_group_summary/pim_bsr_group_summary were decoder.cpp-local
// rendering helpers (like icmp_router_address_summary above); moved here for the same reason.
std::string pim_hello_option_summary(const PimHelloOption& opt) {
    if (!opt.addresses.empty()) {
        std::ostringstream s;
        s << opt.option_type_name << " (";
        for (size_t i = 0; i < opt.addresses.size(); ++i) {
            if (i != 0) s << ", ";
            s << opt.addresses[i];
        }
        s << ")";
        return s.str();
    }
    if (opt.value.empty()) return opt.option_type_name;
    return opt.option_type_name + ": " + opt.value;
}

std::string pim_jp_group_summary(const PimJoinPruneGroup& g) {
    std::ostringstream s;
    s << g.group << ": " << g.joins.size() << " join(s), " << g.prunes.size() << " prune(s)";
    return s.str();
}

std::string pim_bsr_group_summary(const PimBsrGroupRps& g) {
    std::ostringstream s;
    s << g.group << ": " << g.candidate_rps.size() << " candidate-RP(s)";
    return s.str();
}

void write_pim_json_fields(std::ostream& out, const PimMessage& msg) {
    out << "    \"pim_type\": \"" << json_escape(msg.type_name) << "\",\n";
    if (!msg.hello_options.empty()) {
        out << "    \"pim_hello_options\": [";
        for (size_t i = 0; i < msg.hello_options.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(pim_hello_option_summary(msg.hello_options[i])) << "\"";
        }
        out << "],\n";
        out << "    \"pim_hello_options_truncated\": " << (msg.hello_options_truncated ? "true" : "false") << ",\n";
    }
    if (!msg.register_inner_src_ip.empty() || !msg.register_inner_group_ip.empty()) {
        out << "    \"pim_register_border_bit\": " << (msg.register_border_bit ? "true" : "false") << ",\n";
        out << "    \"pim_register_null_register_bit\": " << (msg.register_null_register_bit ? "true" : "false")
            << ",\n";
        out << "    \"pim_register_inner_src_ip\": \"" << json_escape(msg.register_inner_src_ip) << "\",\n";
        out << "    \"pim_register_inner_group_ip\": \"" << json_escape(msg.register_inner_group_ip) << "\",\n";
    }
    if (!msg.register_stop_group.empty()) {
        out << "    \"pim_register_stop_group\": \"" << json_escape(msg.register_stop_group) << "\",\n";
        out << "    \"pim_register_stop_source\": \"" << json_escape(msg.register_stop_source) << "\",\n";
    }
    if (!msg.jp_groups.empty() || !msg.jp_upstream_neighbor.empty()) {
        out << "    \"pim_jp_upstream_neighbor\": \"" << json_escape(msg.jp_upstream_neighbor) << "\",\n";
        out << "    \"pim_jp_holdtime_sec\": " << msg.jp_holdtime_sec << ",\n";
        out << "    \"pim_jp_groups\": [";
        for (size_t i = 0; i < msg.jp_groups.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(pim_jp_group_summary(msg.jp_groups[i])) << "\"";
        }
        out << "],\n";
        out << "    \"pim_jp_groups_truncated\": " << (msg.jp_groups_truncated ? "true" : "false") << ",\n";
    }
    if (!msg.bsr_address.empty()) {
        out << "    \"pim_bsr_fragment_tag\": " << msg.bsr_fragment_tag << ",\n";
        out << "    \"pim_bsr_hash_mask_len\": " << static_cast<unsigned>(msg.bsr_hash_mask_len) << ",\n";
        out << "    \"pim_bsr_priority\": " << static_cast<unsigned>(msg.bsr_priority) << ",\n";
        out << "    \"pim_bsr_address\": \"" << json_escape(msg.bsr_address) << "\",\n";
        out << "    \"pim_bsr_groups\": [";
        for (size_t i = 0; i < msg.bsr_groups.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(pim_bsr_group_summary(msg.bsr_groups[i])) << "\"";
        }
        out << "],\n";
        out << "    \"pim_bsr_groups_truncated\": " << (msg.bsr_groups_truncated ? "true" : "false") << ",\n";
    }
    if (!msg.assert_group.empty()) {
        out << "    \"pim_assert_group\": \"" << json_escape(msg.assert_group) << "\",\n";
        out << "    \"pim_assert_source\": \"" << json_escape(msg.assert_source) << "\",\n";
        out << "    \"pim_assert_rpt_bit\": " << (msg.assert_rpt_bit ? "true" : "false") << ",\n";
        out << "    \"pim_assert_metric_preference\": " << msg.assert_metric_preference << ",\n";
        out << "    \"pim_assert_metric\": " << msg.assert_metric << ",\n";
    }
    if (!msg.crp_rp_address.empty()) {
        out << "    \"pim_crp_prefix_count\": " << static_cast<unsigned>(msg.crp_prefix_count) << ",\n";
        out << "    \"pim_crp_priority\": " << static_cast<unsigned>(msg.crp_priority) << ",\n";
        out << "    \"pim_crp_holdtime_sec\": " << msg.crp_holdtime_sec << ",\n";
        out << "    \"pim_crp_rp_address\": \"" << json_escape(msg.crp_rp_address) << "\",\n";
        out << "    \"pim_crp_groups\": [";
        for (size_t i = 0; i < msg.crp_groups.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(msg.crp_groups[i]) << "\"";
        }
        out << "],\n";
        out << "    \"pim_crp_groups_truncated\": " << (msg.crp_groups_truncated ? "true" : "false") << ",\n";
    }
}

// Zero-flat-field migration (mid-size batch): the DNS family analog of write_goose_json_fields
// above -- shared by dns/mdns/llmnr, same as fill_dns_fields used to be shared in decoder.cpp.
void write_dns_json_fields(std::ostream& out, const DnsMessage& msg) {
    std::ostringstream txn_id;
    txn_id << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << msg.transaction_id;
    out << "    \"dns_transaction_id\": \"" << txn_id.str() << "\",\n";
    out << "    \"dns_is_response\": " << (msg.is_response ? "true" : "false") << ",\n";
    out << "    \"dns_opcode\": \"" << json_escape(msg.opcode_name) << "\",\n";
    out << "    \"dns_header_flags\": \"" << json_escape(msg.header_flags) << "\",\n";
    out << "    \"dns_rcode\": \"" << json_escape(msg.rcode_name) << "\",\n";
    out << "    \"dns_qdcount\": " << msg.qdcount << ",\n";
    out << "    \"dns_ancount\": " << msg.ancount << ",\n";
    out << "    \"dns_nscount\": " << msg.nscount << ",\n";
    out << "    \"dns_arcount\": " << msg.arcount << ",\n";
    std::vector<std::string> records;
    for (const auto& q : msg.questions) records.push_back(q.summary);
    for (const auto& rr : msg.answers) records.push_back(rr.summary);
    for (const auto& rr : msg.authorities) records.push_back(rr.summary);
    for (const auto& rr : msg.additionals) records.push_back(rr.summary);
    if (!records.empty()) {
        out << "    \"dns_records\": [";
        for (size_t i = 0; i < records.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(records[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"dns_records_truncated\": " << (msg.records_truncated ? "true" : "false") << ",\n";
}

// Zero-flat-field migration (mid-size batch): the NBT-NS analog of write_dns_json_fields above --
// NbnsMessage's own shape mirrors DnsMessage's exactly (see nbns.hpp), but is not the same type, so
// this stays a separate function rather than a template (matching this file's existing convention:
// no other write_x_json_fields function here is templated either).
void write_nbns_json_fields(std::ostream& out, const NbnsMessage& msg) {
    std::ostringstream txn_id;
    txn_id << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << msg.transaction_id;
    out << "    \"nbns_transaction_id\": \"" << txn_id.str() << "\",\n";
    out << "    \"nbns_is_response\": " << (msg.is_response ? "true" : "false") << ",\n";
    out << "    \"nbns_opcode\": \"" << json_escape(msg.opcode_name) << "\",\n";
    out << "    \"nbns_flags\": \"" << json_escape(msg.flags) << "\",\n";
    out << "    \"nbns_rcode\": \"" << json_escape(msg.rcode_name) << "\",\n";
    out << "    \"nbns_qdcount\": " << msg.qdcount << ",\n";
    out << "    \"nbns_ancount\": " << msg.ancount << ",\n";
    out << "    \"nbns_nscount\": " << msg.nscount << ",\n";
    out << "    \"nbns_arcount\": " << msg.arcount << ",\n";
    std::vector<std::string> records;
    for (const auto& q : msg.questions) records.push_back(q.summary);
    for (const auto& rr : msg.answers) records.push_back(rr.summary);
    for (const auto& rr : msg.authorities) records.push_back(rr.summary);
    for (const auto& rr : msg.additionals) records.push_back(rr.summary);
    if (!records.empty()) {
        out << "    \"nbns_records\": [";
        for (size_t i = 0; i < records.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(records[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"nbns_records_truncated\": " << (msg.records_truncated ? "true" : "false") << ",\n";
}

// The Modbus analog of write_twincat_json_fields above -- same rationale (a plain free function,
// not a ProtocolRenderer interface). Modbus's function name and exception flag are already folded
// into DecodedPacket::protocol/summary (see decoder.cpp's Modbus call site) and need no JSON field
// of their own; paired_request_index is the one field genuinely only meaningful in JSON.
void write_modbus_json_fields(std::ostream& out, const ModbusFrame& mb) {
    if (mb.paired_response) {
        out << "    \"modbus_paired_request_index\": " << mb.paired_request_index << ",\n";
    }
}

// The EIGRP analog of write_twincat_json_fields above -- same rationale (a plain free function, not
// a ProtocolRenderer interface). Renders one EigrpGeneralTlv as a single line (previously
// decoder.cpp's own eigrp_general_tlv_summary helper, inlined here now that this is its only
// caller) and reads EigrpRoute::summary directly (precomputed at parse time in eigrp.cpp).
void write_eigrp_json_fields(std::ostream& out, const EigrpMessage& msg) {
    out << "    \"eigrp_opcode\": \"" << json_escape(msg.opcode_name) << "\",\n";
    out << "    \"eigrp_autonomous_system\": " << msg.autonomous_system << ",\n";
    std::vector<std::string> flags;
    if (msg.flag_init) flags.push_back("Init");
    if (msg.flag_conditional_receive) flags.push_back("Conditional Receive");
    if (msg.flag_restart) flags.push_back("Restart");
    if (msg.flag_end_of_table) flags.push_back("End Of Table");
    if (!flags.empty()) {
        out << "    \"eigrp_flags\": [";
        for (size_t i = 0; i < flags.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(flags[i]) << "\"";
        }
        out << "],\n";
    }
    if (!msg.general_tlvs.empty()) {
        out << "    \"eigrp_general_tlvs\": [";
        for (size_t i = 0; i < msg.general_tlvs.size(); ++i) {
            if (i != 0) out << ", ";
            const EigrpGeneralTlv& tlv = msg.general_tlvs[i];
            std::string line = tlv.value.empty() ? tlv.type_name : tlv.type_name + ": " + tlv.value;
            out << "\"" << json_escape(line) << "\"";
        }
        out << "],\n";
    }
    out << "    \"eigrp_general_tlvs_truncated\": " << (msg.general_tlvs_truncated ? "true" : "false") << ",\n";
    if (!msg.routes.empty()) {
        out << "    \"eigrp_routes\": [";
        for (size_t i = 0; i < msg.routes.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(msg.routes[i].summary) << "\"";
        }
        out << "],\n";
    }
    out << "    \"eigrp_routes_truncated\": " << (msg.routes_truncated ? "true" : "false") << ",\n";
}

// The BGP analog of write_twincat_json_fields above -- same rationale (a plain free function, not a
// ProtocolRenderer interface). BgpResult (bgp.hpp) wraps one fully-decoded message (`first`) plus,
// when BgpDecoder::decode's own coalescing loop found more, a `coalesced_message_count` > 1 (every
// message past the first is summarized only as a note, not a full second set of fields here -- same
// "one full struct, extra ones as notes" posture OPC UA's own coalescing already established).
void write_bgp_json_fields(std::ostream& out, const BgpResult& r) {
    const BgpMessage& m = r.first;
    out << "    \"bgp_type\": \"" << json_escape(m.type_name) << "\",\n";
    out << "    \"bgp_length\": " << m.length << ",\n";
    if (r.coalesced_message_count > 1) {
        out << "    \"bgp_coalesced_message_count\": " << r.coalesced_message_count << ",\n";
    }

    if (m.is_open) {
        const BgpOpenMessage& o = m.open;
        out << "    \"bgp_open_version\": " << static_cast<int>(o.version) << ",\n";
        out << "    \"bgp_open_my_as\": " << o.my_as << ",\n";
        out << "    \"bgp_open_hold_time\": " << o.hold_time << ",\n";
        out << "    \"bgp_open_identifier\": \"" << json_escape(o.bgp_identifier) << "\",\n";
        out << "    \"bgp_open_four_octet_as_capable\": "
            << (o.has_four_octet_as_capability ? "true" : "false") << ",\n";
        if (!o.capabilities.empty()) {
            out << "    \"bgp_open_capabilities\": [";
            for (size_t i = 0; i < o.capabilities.size(); ++i) {
                if (i != 0) out << ", ";
                const BgpCapability& c = o.capabilities[i];
                std::string name = c.code_name.empty() ? ("code " + std::to_string(c.code)) : c.code_name;
                std::ostringstream one;
                one << name;
                if (c.is_multiprotocol) {
                    one << " (AFI=" << c.mp_afi << " SAFI=" << static_cast<int>(c.mp_safi) << ")";
                } else if (c.is_four_octet_as) {
                    one << " (" << c.four_octet_as << ")";
                }
                out << "\"" << json_escape(one.str()) << "\"";
            }
            out << "],\n";
        }
    } else if (m.is_update) {
        const BgpUpdateMessage& u = m.update;
        auto write_prefix_array = [&out](const char* key, const std::vector<BgpPrefix>& prefixes) {
            out << "    \"" << key << "\": [";
            for (size_t i = 0; i < prefixes.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << prefixes[i].address << "/" << static_cast<int>(prefixes[i].prefix_length_bits)
                    << "\"";
            }
            out << "],\n";
        };
        write_prefix_array("bgp_update_withdrawn_routes", u.withdrawn_routes);
        out << "    \"bgp_update_withdrawn_routes_truncated\": "
            << (u.withdrawn_routes_truncated ? "true" : "false") << ",\n";
        write_prefix_array("bgp_update_nlri", u.nlri);
        out << "    \"bgp_update_nlri_truncated\": " << (u.nlri_truncated ? "true" : "false") << ",\n";
        if (!u.path_attributes.empty()) {
            out << "    \"bgp_update_path_attributes\": [";
            for (size_t i = 0; i < u.path_attributes.size(); ++i) {
                if (i != 0) out << ", ";
                const BgpPathAttribute& a = u.path_attributes[i];
                std::string name = a.type_name.empty() ? ("type " + std::to_string(a.type_code)) : a.type_name;
                std::string value = a.rendered.empty() ? a.raw_hex : a.rendered;
                out << "\"" << json_escape(name + ": " + value) << "\"";
            }
            out << "],\n";
        }
        if (u.has_origin) out << "    \"bgp_update_origin\": \"" << json_escape(u.origin_name) << "\",\n";
        if (u.has_as_path) {
            std::ostringstream ap;
            for (size_t i = 0; i < u.as_path.size(); ++i) {
                if (i != 0) ap << " ";
                for (size_t j = 0; j < u.as_path[i].as_numbers.size(); ++j) {
                    if (j != 0) ap << " ";
                    ap << u.as_path[i].as_numbers[j];
                }
            }
            out << "    \"bgp_update_as_path\": \"" << json_escape(ap.str()) << "\",\n";
            out << "    \"bgp_update_as_path_authoritative\": "
                << (u.as_path_width_authoritative ? "true" : "false") << ",\n";
        }
        if (u.has_next_hop) out << "    \"bgp_update_next_hop\": \"" << json_escape(u.next_hop) << "\",\n";
        if (u.has_communities) {
            out << "    \"bgp_update_communities\": [";
            for (size_t i = 0; i < u.community_names.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(u.community_names[i]) << "\"";
            }
            out << "],\n";
        }
    } else if (m.is_notification) {
        const BgpNotificationMessage& n = m.notification;
        out << "    \"bgp_notification_error_code\": " << static_cast<int>(n.error_code) << ",\n";
        if (!n.error_code_name.empty()) {
            out << "    \"bgp_notification_error_code_name\": \"" << json_escape(n.error_code_name) << "\",\n";
        }
        out << "    \"bgp_notification_error_subcode\": " << static_cast<int>(n.error_subcode) << ",\n";
        if (!n.error_subcode_name.empty()) {
            out << "    \"bgp_notification_error_subcode_name\": \"" << json_escape(n.error_subcode_name)
                << "\",\n";
        }
        if (n.has_shutdown_communication) {
            out << "    \"bgp_notification_shutdown_communication\": \""
                << json_escape(n.shutdown_communication) << "\",\n";
        }
    } else if (m.is_route_refresh) {
        out << "    \"bgp_route_refresh_afi\": " << m.route_refresh.afi << ",\n";
        out << "    \"bgp_route_refresh_safi\": " << static_cast<int>(m.route_refresh.safi) << ",\n";
    }
}

// The Slow Protocols analog of write_twincat_json_fields/write_bgp_json_fields above -- same
// rationale (SlowProtocolsMessage's OAM sub-message nests two optional OamInformationTlv structs
// and a variable-length event list, deep enough to follow BGP's own "no dual-write" posture rather
// than ARP's/LLDP's flat one -- see slow_protocols.hpp's file header comment).
void write_slow_protocols_json_fields(std::ostream& out, const SlowProtocolsMessage& sp) {
    out << "    \"slow_protocols_subtype\": " << static_cast<int>(sp.subtype) << ",\n";
    out << "    \"slow_protocols_subtype_name\": \"" << json_escape(sp.subtype_name) << "\",\n";

    if (sp.is_lacp) {
        const LacpMessage& l = *sp.lacp;
        out << "    \"lacp_version\": " << static_cast<int>(l.version) << ",\n";
        out << "    \"lacp_actor_system\": \"" << json_escape(l.actor_system) << "\",\n";
        out << "    \"lacp_actor_system_priority\": " << l.actor_system_priority << ",\n";
        out << "    \"lacp_actor_key\": " << l.actor_key << ",\n";
        out << "    \"lacp_actor_port\": " << l.actor_port << ",\n";
        out << "    \"lacp_actor_port_priority\": " << l.actor_port_priority << ",\n";
        out << "    \"lacp_actor_state\": \"" << json_escape(l.actor_state.rendered) << "\",\n";
        out << "    \"lacp_partner_system\": \"" << json_escape(l.partner_system) << "\",\n";
        out << "    \"lacp_partner_system_priority\": " << l.partner_system_priority << ",\n";
        out << "    \"lacp_partner_key\": " << l.partner_key << ",\n";
        out << "    \"lacp_partner_port\": " << l.partner_port << ",\n";
        out << "    \"lacp_partner_port_priority\": " << l.partner_port_priority << ",\n";
        out << "    \"lacp_partner_state\": \"" << json_escape(l.partner_state.rendered) << "\",\n";
        out << "    \"lacp_collector_max_delay\": " << l.collector_max_delay << ",\n";
    } else if (sp.is_marker) {
        const MarkerMessage& mk = *sp.marker;
        out << "    \"marker_is_response\": " << (mk.is_response ? "true" : "false") << ",\n";
        out << "    \"marker_requester_port\": " << mk.requester_port << ",\n";
        out << "    \"marker_requester_system\": \"" << json_escape(mk.requester_system) << "\",\n";
        out << "    \"marker_requester_transaction_id\": " << mk.requester_transaction_id << ",\n";
    } else if (sp.is_oam) {
        const OamMessage& o = *sp.oam;
        out << "    \"oam_flags\": " << o.flags_raw << ",\n";
        out << "    \"oam_flag_link_fault\": " << (o.flag_link_fault ? "true" : "false") << ",\n";
        out << "    \"oam_flag_dying_gasp\": " << (o.flag_dying_gasp ? "true" : "false") << ",\n";
        out << "    \"oam_flag_critical_event\": " << (o.flag_critical_event ? "true" : "false") << ",\n";
        out << "    \"oam_flag_local_evaluating\": " << (o.flag_local_evaluating ? "true" : "false") << ",\n";
        out << "    \"oam_flag_local_stable\": " << (o.flag_local_stable ? "true" : "false") << ",\n";
        out << "    \"oam_flag_remote_evaluating\": " << (o.flag_remote_evaluating ? "true" : "false") << ",\n";
        out << "    \"oam_flag_remote_stable\": " << (o.flag_remote_stable ? "true" : "false") << ",\n";
        out << "    \"oam_code\": " << static_cast<int>(o.code) << ",\n";
        out << "    \"oam_code_name\": \"" << json_escape(o.code_name) << "\",\n";

        auto write_info_tlv = [&out](const char* prefix, const OamInformationTlv& t) {
            out << "    \"" << prefix << "_version\": " << static_cast<int>(t.oam_version) << ",\n";
            out << "    \"" << prefix << "_revision\": " << t.revision << ",\n";
            out << "    \"" << prefix << "_config_mode_active\": " << (t.config_mode_active ? "true" : "false") << ",\n";
            out << "    \"" << prefix << "_config_unidirectional\": " << (t.config_unidirectional ? "true" : "false") << ",\n";
            out << "    \"" << prefix << "_config_remote_loopback\": " << (t.config_remote_loopback ? "true" : "false") << ",\n";
            out << "    \"" << prefix << "_config_link_events\": " << (t.config_link_events ? "true" : "false") << ",\n";
            out << "    \"" << prefix << "_config_variable_retrieval\": " << (t.config_variable_retrieval ? "true" : "false") << ",\n";
            out << "    \"" << prefix << "_max_oampdu_size\": " << t.oampdu_config_raw << ",\n";
            out << "    \"" << prefix << "_oui\": \"" << json_escape(t.oui_hex) << "\",\n";
        };
        if (o.local_info) write_info_tlv("oam_local_info", *o.local_info);
        if (o.remote_info) write_info_tlv("oam_remote_info", *o.remote_info);

        if (o.is_event_notification) {
            out << "    \"oam_event_sequence\": " << o.event_sequence << ",\n";
            if (!o.events.empty()) {
                out << "    \"oam_events\": [";
                for (size_t i = 0; i < o.events.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(o.events[i].rendered) << "\"";
                }
                out << "],\n";
            }
        }
        if (o.is_loopback_control && o.loopback_enable) {
            out << "    \"oam_loopback_enable\": " << (*o.loopback_enable ? "true" : "false") << ",\n";
        }
    }
}

// The Kerberos analog of write_twincat_json_fields above -- same rationale (a plain free
// function, not a ProtocolRenderer interface, still premature with only two users of this
// result-object path). Every field is either always-set (message_type/msg_type_value/
// is_response/pvno) or conditioned on the same has_*/non-empty check KerberosMessage's own
// fields document -- see kerberos.hpp's struct comment for which fields apply to which message
// type; a field left at its default (empty string/vector, false) for a given message type is
// omitted here exactly like TwinCAT's own has_index_addressing/has_ads_result convention above,
// never emitted as an empty/zero placeholder.
void write_kerberos_json_fields(std::ostream& out, const KerberosMessage& km) {
    out << "    \"kerberos_message_type\": \"" << json_escape(km.message_type) << "\",\n";
    out << "    \"kerberos_msg_type_value\": " << static_cast<int>(km.msg_type_value) << ",\n";
    out << "    \"kerberos_is_response\": " << (km.is_response ? "true" : "false") << ",\n";
    out << "    \"kerberos_pvno\": " << static_cast<int>(km.pvno) << ",\n";
    if (!km.padata_types.empty()) {
        out << "    \"kerberos_padata_types\": [";
        for (size_t i = 0; i < km.padata_types.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(km.padata_types[i]) << "\"";
        }
        out << "],\n";
        out << "    \"kerberos_has_pa_enc_timestamp\": " << (km.has_pa_enc_timestamp ? "true" : "false") << ",\n";
    }
    if (!km.kdc_options.empty()) {
        out << "    \"kerberos_kdc_options\": [";
        for (size_t i = 0; i < km.kdc_options.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(km.kdc_options[i]) << "\"";
        }
        out << "],\n";
    }
    if (!km.cname.empty()) out << "    \"kerberos_cname\": \"" << json_escape(km.cname) << "\",\n";
    if (!km.realm.empty()) out << "    \"kerberos_realm\": \"" << json_escape(km.realm) << "\",\n";
    if (!km.sname.empty()) out << "    \"kerberos_sname\": \"" << json_escape(km.sname) << "\",\n";
    if (!km.till.empty()) out << "    \"kerberos_till\": \"" << json_escape(km.till) << "\",\n";
    if (km.message_type == "AS-REQ" || km.message_type == "TGS-REQ") {
        out << "    \"kerberos_nonce\": " << km.nonce << ",\n";
    }
    if (!km.etypes.empty()) {
        out << "    \"kerberos_etypes\": [";
        for (size_t i = 0; i < km.etypes.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(km.etypes[i]) << "\"";
        }
        out << "],\n";
    }
    if (km.has_additional_tickets) out << "    \"kerberos_has_additional_tickets\": true,\n";
    if (!km.crealm.empty()) out << "    \"kerberos_crealm\": \"" << json_escape(km.crealm) << "\",\n";
    if (km.has_ticket) {
        out << "    \"kerberos_ticket_tkt_vno\": " << static_cast<int>(km.ticket_tkt_vno) << ",\n";
        out << "    \"kerberos_ticket_realm\": \"" << json_escape(km.ticket_realm) << "\",\n";
        out << "    \"kerberos_ticket_sname\": \"" << json_escape(km.ticket_sname) << "\",\n";
        out << "    \"kerberos_ticket_enc_part_etype\": \"" << json_escape(km.ticket_enc_part_etype) << "\",\n";
    }
    if (km.has_enc_part) {
        out << "    \"kerberos_enc_part_etype\": \"" << json_escape(km.enc_part_etype) << "\",\n";
    }
    if (km.message_type == "KRB-ERROR") {
        out << "    \"kerberos_error_code\": " << km.error_code << ",\n";
        out << "    \"kerberos_error_name\": \"" << json_escape(km.error_name) << "\",\n";
        if (!km.error_text.empty()) {
            out << "    \"kerberos_error_text\": \"" << json_escape(km.error_text) << "\",\n";
        }
    }
    if (!km.ap_options.empty()) {
        out << "    \"kerberos_ap_options\": [";
        for (size_t i = 0; i < km.ap_options.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(km.ap_options[i]) << "\"";
        }
        out << "],\n";
    }
    if (km.correlated_request_seen) {
        out << "    \"kerberos_correlated_request_index\": " << km.correlated_request_index << ",\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the EtherNet/IP explicit-messaging (TCP) analog
// of write_goose_json_fields above. EtherNet/IP is the one protocol in this codebase whose id()
// ("enip") is shared by two decoders with genuinely DIFFERENT ProtocolResult payload types --
// EnipTcpDecoder's EnipResult (wrapping EnipFrame) here, vs EnipUdpDecoder's CipIoFrame directly
// in write_enip_io_json_fields below -- unlike MPLS's own shared-id() case (mpls.hpp), where both
// decoders produce the same MplsFrame type. So, unlike every other write_x_json_fields function in
// this file, JsonWriter's own call site (below) has to discriminate WHICH of the two to cast
// `p.result` to before calling either of these -- it does so via p.has_tcp/p.has_udp, since CIP I/O
// only ever runs on UDP and explicit messaging only ever runs on TCP (see EnipTcpDecoder/
// EnipUdpDecoder's own gate_kind()s in enip.hpp). Reproduces the exact same three-tier gating the
// old JsonWriter block had: enip_command prints only when non-empty (empty for -- impossible here,
// since this overload is only ever called for the TCP/EnipFrame side, but the emptiness check
// itself is preserved verbatim since a NOP command still decodes with an empty name -- see
// enip.hpp's file header comment), the cip_* fields print only when ef.has_cip, and cip_values
// prints independently whenever non-empty.
void write_enip_json_fields(std::ostream& out, const EnipFrame& ef) {
    if (!ef.header.command_name.empty()) {
        out << "    \"enip_command\": \"" << json_escape(ef.header.command_name) << "\",\n";
    }
    if (ef.has_cip) {
        out << "    \"enip_cip_is_response\": " << (ef.cip.is_response ? "true" : "false") << ",\n";
        out << "    \"enip_cip_service\": \"" << json_escape(ef.cip.service_name) << "\",\n";
        if (!ef.cip.path.summary.empty()) {
            out << "    \"enip_cip_path\": \"" << json_escape(ef.cip.path.summary) << "\",\n";
        }
        if (!ef.cip.status_name.empty()) {
            out << "    \"enip_cip_status\": \"" << json_escape(ef.cip.status_name) << "\",\n";
        }
    }
    if (!ef.cip.values.empty()) {
        out << "    \"enip_cip_values\": [";
        for (size_t i = 0; i < ef.cip.values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(ef.cip.values[i]) << "\"";
        }
        out << "],\n";
    }
}

// The CIP I/O (implicit messaging, UDP) counterpart to write_enip_json_fields above -- see that
// function's own comment for why EtherNet/IP needs two write functions instead of the usual one.
void write_enip_io_json_fields(std::ostream& out, const CipIoFrame& io) {
    std::ostringstream connid;
    connid << "0x" << std::hex << std::uppercase << io.connection_id;
    out << "    \"enip_io_connection_id\": \"" << connid.str() << "\",\n";
    out << "    \"enip_io_sequence_number\": " << io.sequence_number << ",\n";
    if (io.has_io_data) {
        out << "    \"enip_io_data_length\": " << io.io_data_length << ",\n";
        out << "    \"enip_io_data_hex\": \"" << json_escape(io.io_data_hex) << "\",\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the BACnet/IP analog of write_devicenet_json_fields
// above. Reproduces the exact same nested gating the old JsonWriter block had: bvlc_function/
// has_npdu print unconditionally for any "bacnet" packet, everything else is nested under
// bf.has_npdu (dest/src-dependent dnet/snet/hop_count, network-layer-message-only message_type,
// APDU-only fields), unchanged from before this migration.
void write_bacnet_json_fields(std::ostream& out, const BacnetFrame& bf) {
    out << "    \"bacnet_bvlc_function\": \"" << json_escape(bf.bvlc_function_name) << "\",\n";
    out << "    \"bacnet_has_npdu\": " << (bf.has_npdu ? "true" : "false") << ",\n";
    if (bf.has_npdu) {
        const BacnetNpdu& npdu = bf.npdu;
        out << "    \"bacnet_npdu_version\": " << static_cast<unsigned>(npdu.version) << ",\n";
        out << "    \"bacnet_npdu_is_network_layer_message\": "
            << (npdu.is_network_layer_message ? "true" : "false") << ",\n";
        out << "    \"bacnet_npdu_expecting_reply\": " << (npdu.expecting_reply ? "true" : "false") << ",\n";
        out << "    \"bacnet_npdu_priority\": " << static_cast<unsigned>(npdu.priority) << ",\n";
        out << "    \"bacnet_npdu_has_dest\": " << (npdu.has_dest ? "true" : "false") << ",\n";
        if (npdu.has_dest) out << "    \"bacnet_npdu_dnet\": " << npdu.dnet << ",\n";
        out << "    \"bacnet_npdu_has_src\": " << (npdu.has_src ? "true" : "false") << ",\n";
        if (npdu.has_src) out << "    \"bacnet_npdu_snet\": " << npdu.snet << ",\n";
        if (npdu.has_dest)
            out << "    \"bacnet_npdu_hop_count\": " << static_cast<unsigned>(npdu.hop_count) << ",\n";
        if (npdu.is_network_layer_message) {
            out << "    \"bacnet_npdu_message_type\": \"" << json_escape(npdu.message_type_name) << "\",\n";
        }
        out << "    \"bacnet_has_apdu\": " << (npdu.has_apdu ? "true" : "false") << ",\n";
        if (npdu.has_apdu) {
            const BacnetApdu& apdu = npdu.apdu;
            out << "    \"bacnet_apdu_type\": \"" << json_escape(apdu.pdu_type_name) << "\",\n";
            if (!apdu.service_choice_name.empty())
                out << "    \"bacnet_service_name\": \"" << json_escape(apdu.service_choice_name) << "\",\n";
            out << "    \"bacnet_invoke_id\": " << apdu.invoke_id << ",\n";
            out << "    \"bacnet_segmented\": " << (apdu.segmented ? "true" : "false") << ",\n";
            if (!apdu.values.empty()) {
                out << "    \"bacnet_values\": [";
                for (size_t i = 0; i < apdu.values.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(apdu.values[i]) << "\"";
                }
                out << "],\n";
            }
        }
    }
}

// Zero-flat-field migration (extra-reader batch): the MMS analog of write_bacnet_json_fields
// above. Reproduces the exact same nested gating the old JsonWriter block had: mms_is_bare prints
// unconditionally, the session/presentation/ACSE fields are nested under !mf.is_bare (and,
// further, presentation-specific/ACSE-specific fields nested under their own has_presentation/
// has_acse), mms_has_pdu prints unconditionally, the PDU-specific fields nested under mf.has_pdu,
// and mms_values/mms_body_* print unconditionally at the end -- unchanged from before this
// migration. The one addition: mf.values' old 50-entry cap (previously applied at decoder.cpp's
// own call site) is applied HERE instead, the same "defer the cap" shape S7CommResult::items'
// rendering in write_s7comm_json_fields uses -- see decoder.cpp's own comment on this call site.
void write_mms_json_fields(std::ostream& out, const MmsFrame& mf) {
    out << "    \"mms_is_bare\": " << (mf.is_bare ? "true" : "false") << ",\n";
    if (!mf.is_bare) {
        out << "    \"mms_session_pdu\": \"" << json_escape(mf.session_pdu_name) << "\",\n";
        out << "    \"mms_has_presentation\": " << (mf.has_presentation ? "true" : "false") << ",\n";
        if (mf.has_presentation) {
            if (!mf.presentation_context_list.empty()) {
                out << "    \"mms_presentation_contexts\": [";
                for (size_t i = 0; i < mf.presentation_context_list.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(mf.presentation_context_list[i]) << "\"";
                }
                out << "],\n";
            }
            out << "    \"mms_presentation_context_id\": " << mf.presentation_context_id << ",\n";
            out << "    \"mms_presentation_context_is_acse\": "
                << (mf.presentation_context_is_acse ? "true" : "false") << ",\n";
        }
        out << "    \"mms_has_acse\": " << (mf.has_acse ? "true" : "false") << ",\n";
        if (mf.has_acse) {
            out << "    \"mms_acse_pdu\": \"" << json_escape(mf.acse_pdu_name) << "\",\n";
            if (!mf.acse_application_context_name.empty()) {
                out << "    \"mms_acse_application_context_name\": \""
                    << json_escape(mf.acse_application_context_name) << "\",\n";
            }
            if (mf.acse_has_result) {
                out << "    \"mms_acse_result\": \"" << json_escape(mf.acse_result_name) << "\",\n";
            }
            if (!mf.acse_values.empty()) {
                out << "    \"mms_acse_values\": [";
                for (size_t i = 0; i < mf.acse_values.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(mf.acse_values[i]) << "\"";
                }
                out << "],\n";
            }
        }
    }
    out << "    \"mms_has_pdu\": " << (mf.has_pdu ? "true" : "false") << ",\n";
    if (mf.has_pdu) {
        out << "    \"mms_pdu\": \"" << json_escape(mf.pdu_name) << "\",\n";
        out << "    \"mms_is_response\": " << (mf.is_response ? "true" : "false") << ",\n";
        if (mf.has_invoke_id) {
            out << "    \"mms_invoke_id\": " << mf.invoke_id << ",\n";
        }
        out << "    \"mms_service_recognized\": " << (mf.service_recognized ? "true" : "false") << ",\n";
        if (mf.service_recognized) {
            out << "    \"mms_service\": \"" << json_escape(mf.service_name) << "\",\n";
        }
        if (mf.has_error) {
            out << "    \"mms_error\": \"" << json_escape(mf.error_name) << "\",\n";
        }
    }
    if (!mf.values.empty()) {
        const size_t kMaxMmsValues = resource_limits().max_decoded_objects.value_or(50);
        out << "    \"mms_values\": [";
        for (size_t i = 0; i < mf.values.size() && i < kMaxMmsValues; ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(mf.values[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"mms_body_shown_as_hex\": " << (mf.body_shown_as_hex ? "true" : "false") << ",\n";
    if (mf.body_shown_as_hex) {
        out << "    \"mms_body_length\": " << mf.body_length << ",\n";
        out << "    \"mms_body_hex\": \"" << json_escape(mf.body_hex) << "\",\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the OPC UA analog of write_bacnet_json_fields
// above -- takes OpcUaResult::first (the first coalesced chunk's OpcUaMessage), mirroring how
// decoder.cpp's own call site only ever fed the rest of DecodedPacket from oua.first even before
// this migration (see OpcUaResult's own comment in opcua.hpp). Reproduces the exact same nested
// gating the old JsonWriter block had: header/chunk/size fields print unconditionally,
// secure-channel fields nested under m.has_secure_channel (and further split
// asymmetric-vs-symmetric), service_namespace/service_type_id print whenever recognized OR either
// is non-zero (an intentional three-way OR, not just !service_recognized), header fields nested
// under m.has_header (and status fields further nested under m.header.is_response), and
// values/body_hex print unconditionally at the end -- unchanged from before this migration.
void write_opcua_json_fields(std::ostream& out, const OpcUaMessage& m) {
    out << "    \"opcua_message_type\": \"" << json_escape(m.message_type) << "\",\n";
    out << "    \"opcua_chunk_type\": \"" << std::string(1, m.chunk_type) << "\",\n";
    out << "    \"opcua_message_size\": " << m.message_size << ",\n";
    out << "    \"opcua_has_secure_channel\": " << (m.has_secure_channel ? "true" : "false") << ",\n";
    if (m.has_secure_channel) {
        out << "    \"opcua_secure_channel_id\": " << m.secure_channel_id << ",\n";
        out << "    \"opcua_is_asymmetric\": " << (m.is_asymmetric ? "true" : "false") << ",\n";
        if (m.is_asymmetric) {
            out << "    \"opcua_security_policy_uri\": \"" << json_escape(m.security_policy_uri) << "\",\n";
            out << "    \"opcua_has_sender_certificate\": " << (m.has_sender_certificate ? "true" : "false")
                << ",\n";
            if (m.has_sender_certificate)
                out << "    \"opcua_sender_certificate_length\": " << m.sender_certificate_length << ",\n";
            out << "    \"opcua_has_receiver_certificate_thumbprint\": "
                << (m.has_receiver_certificate_thumbprint ? "true" : "false") << ",\n";
        } else {
            out << "    \"opcua_token_id\": " << m.token_id << ",\n";
        }
        out << "    \"opcua_sequence_number\": " << m.sequence_number << ",\n";
        out << "    \"opcua_request_id\": " << m.request_id << ",\n";
    }
    out << "    \"opcua_service_recognized\": " << (m.service_recognized ? "true" : "false") << ",\n";
    if (m.service_recognized) {
        out << "    \"opcua_service_name\": \"" << json_escape(m.service_name) << "\",\n";
    }
    if (m.service_namespace != 0 || m.service_type_id != 0 || m.service_recognized) {
        out << "    \"opcua_service_namespace\": " << m.service_namespace << ",\n";
        out << "    \"opcua_service_type_id\": " << m.service_type_id << ",\n";
    }
    out << "    \"opcua_has_header\": " << (m.has_header ? "true" : "false") << ",\n";
    if (m.has_header) {
        out << "    \"opcua_request_handle\": " << m.header.request_handle << ",\n";
        out << "    \"opcua_is_response\": " << (m.header.is_response ? "true" : "false") << ",\n";
        if (m.header.is_response) {
            out << "    \"opcua_status_code\": " << m.header.status_code << ",\n";
            out << "    \"opcua_status_code_name\": \"" << json_escape(m.header.status_code_name) << "\",\n";
            out << "    \"opcua_status_is_good\": " << (m.header.status_is_good ? "true" : "false") << ",\n";
        }
    }
    if (!m.values.empty()) {
        out << "    \"opcua_values\": [";
        for (size_t i = 0; i < m.values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(m.values[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"opcua_body_shown_as_hex\": " << (m.body_shown_as_hex ? "true" : "false") << ",\n";
    if (m.body_shown_as_hex) {
        out << "    \"opcua_body_length\": " << m.body_length << ",\n";
        out << "    \"opcua_body_hex\": \"" << json_escape(m.body_hex) << "\",\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the MQTT analog of write_opcua_json_fields
// above -- takes MqttResult::first (the first coalesced packet's MqttMessage), mirroring how
// decoder.cpp's own call site only ever fed the rest of DecodedPacket from mr.first even before
// this migration (see MqttResult's own comment in mqtt.hpp). Reproduces the exact same nested
// gating the old JsonWriter block had, including its one non-obvious detail: sparkplug_group_id/
// sparkplug_edge_node_id/sparkplug_device_id/payload_decoded/timestamp/seq/uuid/body_length/
// metric_count/metrics print ONLY in the else-branch of sparkplug_is_state (never alongside
// state_host_id/state_text) -- unchanged from before this migration.
void write_mqtt_json_fields(std::ostream& out, const MqttMessage& m) {
    out << "    \"mqtt_packet_type\": \"" << json_escape(m.packet_type_name) << "\",\n";
    out << "    \"mqtt_remaining_length\": " << m.remaining_length << ",\n";
    if (!m.protocol_version_name.empty()) {
        out << "    \"mqtt_protocol_version\": \"" << json_escape(m.protocol_version_name) << "\",\n";
    }
    if (m.packet_type_name == "PUBLISH") {
        out << "    \"mqtt_dup\": " << (m.dup ? "true" : "false") << ",\n";
        out << "    \"mqtt_qos\": " << static_cast<unsigned>(m.qos) << ",\n";
        out << "    \"mqtt_retain\": " << (m.retain ? "true" : "false") << ",\n";
        out << "    \"mqtt_topic\": \"" << json_escape(m.topic) << "\",\n";
    }
    if (m.has_packet_id) {
        out << "    \"mqtt_packet_id\": " << m.packet_id << ",\n";
    }
    if (m.has_payload) {
        out << "    \"mqtt_payload_length\": " << m.payload_length << ",\n";
        // Omitted only when a successful Sparkplug B decode cleared it (see mqtt.hpp) -- a
        // genuinely empty payload still renders an empty hex string, same as m.payload_length == 0.
        bool hex_cleared_by_sparkplug = m.payload_length > 0 && m.payload_hex.empty();
        if (!hex_cleared_by_sparkplug) {
            out << "    \"mqtt_payload_hex\": \"" << json_escape(m.payload_hex) << "\",\n";
        }
    }
    if (!m.values.empty()) {
        out << "    \"mqtt_values\": [";
        for (size_t i = 0; i < m.values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(m.values[i]) << "\"";
        }
        out << "],\n";
    }
    out << "    \"mqtt_is_sparkplug\": " << (m.is_sparkplug ? "true" : "false") << ",\n";
    if (m.is_sparkplug) {
        out << "    \"mqtt_sparkplug_message_type\": \"" << json_escape(m.sparkplug_message_type) << "\",\n";
        out << "    \"mqtt_sparkplug_is_state\": " << (m.sparkplug_is_state ? "true" : "false") << ",\n";
        if (m.sparkplug_is_state) {
            out << "    \"mqtt_sparkplug_state_host_id\": \"" << json_escape(m.sparkplug_state_host_id)
                << "\",\n";
            out << "    \"mqtt_sparkplug_state_text\": \"" << json_escape(m.sparkplug_state_text) << "\",\n";
        } else {
            out << "    \"mqtt_sparkplug_group_id\": \"" << json_escape(m.sparkplug_group_id) << "\",\n";
            out << "    \"mqtt_sparkplug_edge_node_id\": \"" << json_escape(m.sparkplug_edge_node_id)
                << "\",\n";
            if (!m.sparkplug_device_id.empty()) {
                out << "    \"mqtt_sparkplug_device_id\": \"" << json_escape(m.sparkplug_device_id) << "\",\n";
            }
            out << "    \"mqtt_sparkplug_payload_decoded\": "
                << (m.sparkplug_payload.parse_ok ? "true" : "false") << ",\n";
            if (m.sparkplug_payload.has_timestamp) {
                out << "    \"mqtt_sparkplug_timestamp\": " << m.sparkplug_payload.timestamp << ",\n";
            }
            if (m.sparkplug_payload.has_seq) {
                out << "    \"mqtt_sparkplug_seq\": " << m.sparkplug_payload.seq << ",\n";
            }
            if (m.sparkplug_payload.has_uuid) {
                out << "    \"mqtt_sparkplug_uuid\": \"" << json_escape(m.sparkplug_payload.uuid) << "\",\n";
            }
            if (m.sparkplug_payload.has_body) {
                out << "    \"mqtt_sparkplug_body_length\": " << m.sparkplug_payload.body_length << ",\n";
            }
            out << "    \"mqtt_sparkplug_metric_count\": " << m.sparkplug_payload.metric_count << ",\n";
            if (!m.sparkplug_payload.metrics.empty()) {
                out << "    \"mqtt_sparkplug_metrics\": [";
                for (size_t i = 0; i < m.sparkplug_payload.metrics.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(m.sparkplug_payload.metrics[i]) << "\"";
                }
                out << "],\n";
            }
        }
    }
}

// Zero-flat-field migration (extra-reader batch): the HART-IP analog of write_bacnet_json_fields
// above -- takes HartIpResult::first (the first coalesced message's HartIpFrame), mirroring how
// decoder.cpp's own two call sites (TCP and UDP -- see HartIpResult's own comment in hartip.hpp
// for why both share this one result type, unlike EtherNet/IP's TCP/UDP split) only ever fed the
// rest of DecodedPacket from hr.first even before this migration. Reproduces the exact same
// nested gating the old JsonWriter block had, including its one non-obvious detail: the
// hartip_address rendering (short address formatted as 2 uppercase hex digits, long address
// passed through as-is) used to be computed once at each decoder.cpp call site and stored in the
// old flat hartip_address_hex field -- HartIpPassThrough itself carries no such field, only the
// raw short_address byte plus long_address_hex, so that formatting is now done HERE instead, the
// same "defer the transform to where it's rendered" shape this batch's other protocols use.
void write_hartip_json_fields(std::ostream& out, const HartIpFrame& frame) {
    out << "    \"hartip_version\": " << static_cast<unsigned>(frame.version) << ",\n";
    out << "    \"hartip_message_type\": \"" << json_escape(frame.message_type_name) << "\",\n";
    out << "    \"hartip_message_id\": \"" << json_escape(frame.message_id_name) << "\",\n";
    out << "    \"hartip_status\": " << static_cast<unsigned>(frame.status) << ",\n";
    out << "    \"hartip_transaction_id\": " << frame.transaction_id << ",\n";
    out << "    \"hartip_msg_length\": " << frame.msg_length << ",\n";
    if (frame.has_session_init) {
        out << "    \"hartip_host_type\": \"" << json_escape(frame.session_init.host_type_name) << "\",\n";
        out << "    \"hartip_inactivity_close_timer\": " << frame.session_init.inactivity_close_timer
            << ",\n";
    }
    if (frame.has_error) {
        out << "    \"hartip_error_code\": " << static_cast<unsigned>(frame.error_code) << ",\n";
        out << "    \"hartip_error_code_name\": \"" << json_escape(frame.error_code_name) << "\",\n";
    }
    out << "    \"hartip_has_pass_through\": " << (frame.has_pass_through ? "true" : "false") << ",\n";
    if (frame.has_pass_through) {
        const HartIpPassThrough& pt = frame.pass_through;
        out << "    \"hartip_frame_type\": \"" << json_escape(pt.frame_type_name) << "\",\n";
        out << "    \"hartip_is_response\": " << (pt.is_response ? "true" : "false") << ",\n";
        out << "    \"hartip_is_long_address\": " << (pt.is_long_address ? "true" : "false") << ",\n";
        std::string address_hex;
        if (pt.is_long_address) {
            address_hex = pt.long_address_hex;
        } else {
            std::ostringstream a;
            a << std::hex << std::uppercase << std::setfill('0') << std::setw(2)
              << static_cast<unsigned>(pt.short_address);
            address_hex = a.str();
        }
        out << "    \"hartip_address\": \"" << json_escape(address_hex) << "\",\n";
        out << "    \"hartip_command\": " << static_cast<unsigned>(pt.command) << ",\n";
        if (!pt.command_name.empty())
            out << "    \"hartip_command_name\": \"" << json_escape(pt.command_name) << "\",\n";
        if (pt.is_response) {
            out << "    \"hartip_response_code\": " << static_cast<unsigned>(pt.response_code) << ",\n";
            out << "    \"hartip_response_is_comm_error\": " << (pt.response_is_comm_error ? "true" : "false")
                << ",\n";
            if (!pt.response_code_name.empty())
                out << "    \"hartip_response_code_name\": \"" << json_escape(pt.response_code_name) << "\",\n";
            if (!pt.comm_error_flags.empty()) {
                out << "    \"hartip_comm_error_flags\": [";
                for (size_t i = 0; i < pt.comm_error_flags.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(pt.comm_error_flags[i]) << "\"";
                }
                out << "],\n";
            }
            out << "    \"hartip_device_status\": " << static_cast<unsigned>(pt.device_status) << ",\n";
            if (!pt.device_status_flags.empty()) {
                out << "    \"hartip_device_status_flags\": [";
                for (size_t i = 0; i < pt.device_status_flags.size(); ++i) {
                    if (i != 0) out << ", ";
                    out << "\"" << json_escape(pt.device_status_flags[i]) << "\"";
                }
                out << "],\n";
            }
        }
        if (!pt.values.empty()) {
            out << "    \"hartip_values\": [";
            for (size_t i = 0; i < pt.values.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(pt.values[i]) << "\"";
            }
            out << "],\n";
        }
        // The classic wired-HART longitudinal (XOR) checksum -- unconditionally emitted (unlike
        // hartip_command_name/hartip_values, which are gated on non-empty) since a zero/false pair
        // is itself meaningful here: it's exactly what a truncated body (checksum byte never read
        // at all) also produces, and that truncation already gets its own note -- mirrors
        // dnp3_header_crc_valid's own "always present" convention.
        out << "    \"hartip_checksum\": " << static_cast<unsigned>(pt.checksum) << ",\n";
        out << "    \"hartip_checksum_valid\": " << (pt.checksum_valid ? "true" : "false") << ",\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the DNP3 analog of write_goose_json_fields
// above. Reproduces the exact same four-tier gating the old JsonWriter block had: the link-layer
// fields (source/destination/crc/block counts) print unconditionally for any "dnp3" packet,
// dnp3_function prints only when dr.dnp3_has_function, and dnp3_object_headers/dnp3_point_values
// each print independently whenever non-empty -- unchanged from before this migration.
void write_dnp3_json_fields(std::ostream& out, const Dnp3Result& dr) {
    out << "    \"dnp3_source_address\": " << dr.source_address << ",\n";
    out << "    \"dnp3_destination_address\": " << dr.destination_address << ",\n";
    out << "    \"dnp3_link_crc_valid\": " << (dr.link_crc_valid ? "true" : "false") << ",\n";
    out << "    \"dnp3_header_crc_valid\": " << (dr.header_crc_valid ? "true" : "false") << ",\n";
    out << "    \"dnp3_block_count\": " << dr.block_count << ",\n";
    out << "    \"dnp3_block_crc_failures\": " << dr.block_crc_failures << ",\n";
    if (dr.dnp3_has_function) {
        out << "    \"dnp3_function\": \"" << json_escape(dr.dnp3_function_name) << "\",\n";
    }
    if (!dr.dnp3_object_headers.empty()) {
        out << "    \"dnp3_objects\": [";
        for (size_t i = 0; i < dr.dnp3_object_headers.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(dr.dnp3_object_headers[i]) << "\"";
        }
        out << "],\n";
    }
    if (!dr.dnp3_point_values.empty()) {
        out << "    \"dnp3_values\": [";
        for (size_t i = 0; i < dr.dnp3_point_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(dr.dnp3_point_values[i]) << "\"";
        }
        out << "],\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the IEC 104 analog of write_goose_json_fields
// above. Reproduces the exact same two-tier gating the old JsonWriter block had: the headline
// fields print only when iec104_has_asdu, but iec104_object_values prints whenever it's non-empty
// -- a separate, independent gate (not `if (ir.iec104_has_asdu)`), unchanged from before this
// migration.
void write_iec104_json_fields(std::ostream& out, const Iec104Result& ir) {
    if (ir.iec104_has_asdu) {
        out << "    \"iec104_asdu_type\": \"" << json_escape(ir.iec104_asdu_type_name) << "\",\n";
        out << "    \"iec104_asdu_type_short\": \"" << json_escape(ir.iec104_asdu_type_short_name) << "\",\n";
        out << "    \"iec104_cot\": \"" << json_escape(ir.iec104_cot_name) << "\",\n";
        out << "    \"iec104_common_address\": " << ir.iec104_common_address << ",\n";
    }
    if (!ir.iec104_object_values.empty()) {
        out << "    \"iec104_objects\": [";
        for (size_t i = 0; i < ir.iec104_object_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(ir.iec104_object_values[i]) << "\"";
        }
        out << "],\n";
    }
}

// Zero-flat-field migration (extra-reader batch): the S7comm analog of write_dnp3_json_fields
// above, with one addition -- the s7comm_items display-tag-plus-"[EXPERIMENTAL]" transform, which
// used to run at decoder.cpp's own call site, now happens HERE instead (deferred from sr.items,
// which S7CommResult carries forward unmodified -- see that struct's own comment in s7comm.hpp for
// why sr.value_summaries, unlike sr.items, could NOT also be deferred this way). Every other field
// below reproduces the exact same independent per-field gating the old JsonWriter block had: none
// of these are nested under one shared "has s7comm data" check, each stands alone, unchanged from
// before this migration.
void write_s7comm_json_fields(std::ostream& out, const S7CommResult& sr) {
    if (sr.has_function) {
        out << "    \"s7comm_function\": \"" << json_escape(sr.function_name) << "\",\n";
    }
    if (!sr.items.empty()) {
        const size_t kMaxTags = resource_limits().max_decoded_objects.value_or(50);
        out << "    \"s7comm_items\": [";
        bool first = true;
        for (size_t i = 0; i < sr.items.size() && i < kMaxTags; ++i) {
            const auto& it = sr.items[i];
            std::string display_tag = !it.tag.empty() ? it.tag : it.area_name;
            // A consumer parsing this array as trusted addresses must not mistake an
            // unverified reconstruction for the well-established S7ANY decode.
            if (it.is_experimental) display_tag += " [EXPERIMENTAL]";
            if (!first) out << ", ";
            first = false;
            out << "\"" << json_escape(display_tag) << "\"";
        }
        out << "],\n";
    }
    if (!sr.value_summaries.empty()) {
        out << "    \"s7comm_values\": [";
        for (size_t i = 0; i < sr.value_summaries.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(sr.value_summaries[i]) << "\"";
        }
        out << "],\n";
    }
    if (!sr.plc_stop_message.empty()) {
        out << "    \"s7comm_plc_stop_message\": \"" << json_escape(sr.plc_stop_message) << "\",\n";
    }
    if (sr.has_pi_service) {
        out << "    \"s7comm_pi_service_name\": \"" << json_escape(sr.pi_service_name) << "\",\n";
        if (!sr.pi_service_description.empty()) {
            out << "    \"s7comm_pi_service_description\": \"" << json_escape(sr.pi_service_description)
                << "\",\n";
        }
    }
    if (!sr.pi_control_argument.empty()) {
        out << "    \"s7comm_pi_control_argument\": \"" << json_escape(sr.pi_control_argument) << "\",\n";
    }
    if (!sr.pi_control_blocks.empty()) {
        out << "    \"s7comm_pi_control_blocks\": [";
        for (size_t i = 0; i < sr.pi_control_blocks.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(sr.pi_control_blocks[i]) << "\"";
        }
        out << "],\n";
    }
    if (sr.has_pi_control_status) {
        out << "    \"s7comm_pi_control_has_more_data\": "
            << (sr.pi_control_has_more_data ? "true" : "false") << ",\n";
        out << "    \"s7comm_pi_control_has_error\": " << (sr.pi_control_has_error ? "true" : "false")
            << ",\n";
    }
}

// The MELSEC analog of write_twincat_json_fields/write_kerberos_json_fields above -- same
// rationale (plain free function, not a ProtocolRenderer interface). Devices/values render as
// parallel JSON arrays (melsec_devices lines up index-for-index with melsec_word_values/
// melsec_bit_values/melsec_dword_values, whichever is populated) -- see melsec.hpp's MelsecFrame
// comment for which vector(s) a given command/subcommand combination fills.
void write_melsec_json_fields(std::ostream& out, const MelsecFrame& mf) {
    out << "    \"melsec_frame_type\": \"" << (mf.is_4e_frame ? "4E" : "3E") << "\",\n";
    if (mf.is_4e_frame) {
        out << "    \"melsec_serial_number\": " << mf.serial_number << ",\n";
    }
    out << "    \"melsec_is_response\": " << (mf.is_response ? "true" : "false") << ",\n";
    out << "    \"melsec_network_no\": " << static_cast<int>(mf.network_no) << ",\n";
    out << "    \"melsec_pc_no\": " << static_cast<int>(mf.pc_no) << ",\n";
    out << "    \"melsec_command_name\": \"" << json_escape(mf.command_name) << "\",\n";
    if (mf.has_command) {
        out << "    \"melsec_command\": " << mf.command << ",\n";
        out << "    \"melsec_subcommand\": " << mf.subcommand << ",\n";
    }
    if (mf.has_end_code) {
        out << "    \"melsec_end_code\": " << mf.end_code << ",\n";
        out << "    \"melsec_end_code_name\": \"" << json_escape(mf.end_code_name) << "\",\n";
    }
    if (!mf.devices.empty()) {
        out << "    \"melsec_devices\": [";
        for (size_t i = 0; i < mf.devices.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(mf.devices[i].device_text) << "\"";
        }
        out << "],\n";
    }
    if (mf.has_point_count) {
        out << "    \"melsec_point_count\": " << mf.point_count << ",\n";
    }
    if (!mf.word_values.empty()) {
        out << "    \"melsec_word_values\": [";
        for (size_t i = 0; i < mf.word_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << mf.word_values[i];
        }
        out << "],\n";
    }
    if (!mf.dword_values.empty()) {
        out << "    \"melsec_dword_values\": [";
        for (size_t i = 0; i < mf.dword_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << mf.dword_values[i];
        }
        out << "],\n";
    }
    if (!mf.bit_values.empty()) {
        out << "    \"melsec_bit_values\": [";
        for (size_t i = 0; i < mf.bit_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << static_cast<int>(mf.bit_values[i]);
        }
        out << "],\n";
    }
    if (mf.has_undecoded_response_bytes) {
        out << "    \"melsec_undecoded_response_bytes\": " << mf.undecoded_response_byte_count << ",\n";
    }
    if (mf.has_remote_mode) {
        out << "    \"melsec_remote_mode\": \"" << json_escape(mf.remote_mode_name) << "\",\n";
    }
    if (mf.has_clear_mode) {
        out << "    \"melsec_clear_mode\": \"" << json_escape(mf.clear_mode_name) << "\",\n";
    }
    if (mf.has_remote_password) {
        // Per Jurgen's own decision: the password value is never rendered, only its length -- see
        // melsec.hpp's file header comment.
        out << "    \"melsec_remote_password_length\": " << mf.remote_password_length << ",\n";
    }
    if (mf.has_cpu_type) {
        out << "    \"melsec_cpu_type\": \"" << json_escape(mf.cpu_type_name) << "\",\n";
        out << "    \"melsec_cpu_code\": " << mf.cpu_code << ",\n";
    }
    if (mf.has_echo_data) {
        out << "    \"melsec_echo_data\": \"" << json_escape(mf.echo_data) << "\",\n";
    }
}

// The FINS analog of write_melsec_json_fields above -- same rationale (plain free function, not a
// ProtocolRenderer interface). UNLIKE MELSEC, a FINS response self-describes its own command code
// (see fins.hpp's "A GENUINE ARCHITECTURAL DIFFERENCE FROM MELSEC" paragraph), so fins_command_name
// is always meaningful, never a generic "response" fallback. Devices/values render as parallel JSON
// arrays (fins_devices lines up index-for-index with fins_word_values/fins_bit_values, whichever is
// populated) -- see fins.hpp's FinsFrame comment for which vector(s) a given command fills.
void write_fins_json_fields(std::ostream& out, const FinsFrame& ff) {
    if (ff.is_tcp_envelope_only) {
        // FINS/TCP handshake (command 0x00/0x01), Frame Send Error Notification (0x03), or
        // Connection Confirmation (0x06) -- see fins.hpp's own "FINS/TCP ENVELOPE-ONLY MESSAGES"
        // paragraph. None of the inner 10-byte-header fields below are meaningful here.
        out << "    \"fins_tcp_command\": " << ff.tcp_command << ",\n";
        out << "    \"fins_tcp_command_name\": \"" << json_escape(ff.tcp_command_name) << "\",\n";
        out << "    \"fins_tcp_error_code\": " << ff.tcp_error_code << ",\n";
        out << "    \"fins_tcp_error_code_name\": \"" << json_escape(ff.tcp_error_code_name) << "\",\n";
        if (ff.has_handshake_client_node) {
            out << "    \"fins_handshake_client_node\": " << ff.handshake_client_node << ",\n";
        }
        if (ff.has_handshake_server_node) {
            out << "    \"fins_handshake_server_node\": " << ff.handshake_server_node << ",\n";
        }
        return;
    }
    out << "    \"fins_is_response\": " << (ff.is_response ? "true" : "false") << ",\n";
    out << "    \"fins_dna\": " << static_cast<int>(ff.dna) << ",\n";
    out << "    \"fins_da1\": " << static_cast<int>(ff.da1) << ",\n";
    out << "    \"fins_da2\": " << static_cast<int>(ff.da2) << ",\n";
    out << "    \"fins_sna\": " << static_cast<int>(ff.sna) << ",\n";
    out << "    \"fins_sa1\": " << static_cast<int>(ff.sa1) << ",\n";
    out << "    \"fins_sa2\": " << static_cast<int>(ff.sa2) << ",\n";
    out << "    \"fins_sid\": " << static_cast<int>(ff.sid) << ",\n";
    out << "    \"fins_command\": " << ff.command << ",\n";
    out << "    \"fins_command_name\": \"" << json_escape(ff.command_name) << "\",\n";
    if (ff.matched_to_request) {
        out << "    \"fins_matched_to_request\": true,\n";
    }
    if (ff.has_end_code) {
        out << "    \"fins_end_code\": " << ff.end_code << ",\n";
        out << "    \"fins_end_code_name\": \"" << json_escape(ff.end_code_name) << "\",\n";
    }
    if (!ff.devices.empty()) {
        out << "    \"fins_devices\": [";
        for (size_t i = 0; i < ff.devices.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(ff.devices[i].device_text) << "\"";
        }
        out << "],\n";
        // Multiple Memory Area Read (0104) response only -- per-item value_text, since items can
        // differ in type (word vs. bit) -- see FinsMemoryItem's own comment in fins.hpp.
        bool any_value_text = false;
        for (const auto& d : ff.devices) {
            if (!d.value_text.empty()) { any_value_text = true; break; }
        }
        if (any_value_text) {
            out << "    \"fins_device_values\": [";
            for (size_t i = 0; i < ff.devices.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(ff.devices[i].value_text) << "\"";
            }
            out << "],\n";
        }
    }
    if (ff.has_point_count) {
        out << "    \"fins_point_count\": " << ff.point_count << ",\n";
    }
    if (!ff.word_values.empty()) {
        out << "    \"fins_word_values\": [";
        for (size_t i = 0; i < ff.word_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << ff.word_values[i];
        }
        out << "],\n";
    }
    if (!ff.bit_values.empty()) {
        out << "    \"fins_bit_values\": [";
        for (size_t i = 0; i < ff.bit_values.size(); ++i) {
            if (i != 0) out << ", ";
            out << static_cast<int>(ff.bit_values[i]);
        }
        out << "],\n";
    }
    if (ff.has_undecoded_response_bytes) {
        out << "    \"fins_undecoded_response_bytes\": " << ff.undecoded_response_byte_count << ",\n";
    }
    if (ff.has_program_number) {
        out << "    \"fins_program_number\": " << ff.program_number << ",\n";
    }
    if (ff.has_mode_code) {
        out << "    \"fins_mode_code\": " << static_cast<int>(ff.mode_code) << ",\n";
    }
    if (ff.has_controller_info) {
        out << "    \"fins_controller_model\": \"" << json_escape(ff.controller_model) << "\",\n";
        out << "    \"fins_controller_version\": \"" << json_escape(ff.controller_version) << "\",\n";
    }
    if (ff.has_status_info) {
        out << "    \"fins_status\": " << static_cast<int>(ff.status) << ",\n";
        out << "    \"fins_status_name\": \"" << json_escape(ff.status_name) << "\",\n";
        out << "    \"fins_ctrl_mode\": " << static_cast<int>(ff.ctrl_mode) << ",\n";
        out << "    \"fins_ctrl_mode_name\": \"" << json_escape(ff.ctrl_mode_name) << "\",\n";
        out << "    \"fins_fatal_error_flags\": " << ff.fatal_error_flags << ",\n";
        out << "    \"fins_non_fatal_error_flags\": " << ff.non_fatal_error_flags << ",\n";
        out << "    \"fins_message_flags\": " << ff.message_flags << ",\n";
        out << "    \"fins_error_message\": \"" << json_escape(ff.error_message) << "\",\n";
    }
    if (ff.has_fals_number) {
        out << "    \"fins_fals_number\": " << ff.fals_number << ",\n";
    }
    if (ff.has_cycle_parameter) {
        out << "    \"fins_cycle_parameter\": " << static_cast<int>(ff.cycle_parameter) << ",\n";
    }
    if (ff.has_cycle_stats) {
        out << "    \"fins_cycle_avg_us\": " << ff.cycle_avg_us << ",\n";
        out << "    \"fins_cycle_max_us\": " << ff.cycle_max_us << ",\n";
        out << "    \"fins_cycle_min_us\": " << ff.cycle_min_us << ",\n";
    }
    if (ff.has_clock) {
        std::ostringstream clock;
        clock << "20" << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_year) << "-"
              << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_month) << "-"
              << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_date) << " "
              << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_hour) << ":"
              << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_minute) << ":"
              << std::setw(2) << std::setfill('0') << static_cast<int>(ff.clock_second);
        out << "    \"fins_clock\": \"" << clock.str() << "\",\n";
    }
    if (ff.has_echo_data) {
        out << "    \"fins_echo_data\": \"" << json_escape(ff.echo_data) << "\",\n";
    }
    if (ff.has_access_right_holder) {
        out << "    \"fins_access_right_unit_address\": " << static_cast<int>(ff.access_right_unit_address) << ",\n";
        out << "    \"fins_access_right_node_number\": " << static_cast<int>(ff.access_right_node_number) << ",\n";
        out << "    \"fins_access_right_network_address\": " << static_cast<int>(ff.access_right_network_address) << ",\n";
    }
    if (!ff.force_entries.empty()) {
        out << "    \"fins_force_entries\": [";
        for (size_t i = 0; i < ff.force_entries.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(ff.force_entries[i].specification_name) << " "
                << json_escape(ff.force_entries[i].device_text) << "\"";
        }
        out << "],\n";
    }
}

// The LDAP analog of write_kerberos_json_fields above -- same rationale, same "always-set fields
// unconditional, everything else conditioned on the same has_*/non-empty check LdapMessage's own
// fields document" posture -- see ldap.hpp's struct comment for which fields apply to which message
// type.
void write_ldap_json_fields(std::ostream& out, const LdapMessage& lm) {
    out << "    \"ldap_message_id\": " << lm.message_id << ",\n";
    out << "    \"ldap_message_type\": \"" << json_escape(lm.message_type) << "\",\n";
    out << "    \"ldap_op_num\": " << static_cast<int>(lm.op_num) << ",\n";
    out << "    \"ldap_is_response\": " << (lm.is_response ? "true" : "false") << ",\n";
    if (lm.message_type == "BindRequest") {
        out << "    \"ldap_bind_version\": " << static_cast<int>(lm.bind_version) << ",\n";
        out << "    \"ldap_bind_dn\": \"" << json_escape(lm.bind_dn) << "\",\n";
        out << "    \"ldap_bind_is_sasl\": " << (lm.bind_is_sasl ? "true" : "false") << ",\n";
        if (!lm.bind_auth_mechanism.empty()) {
            out << "    \"ldap_bind_auth_mechanism\": \"" << json_escape(lm.bind_auth_mechanism) << "\",\n";
        }
        out << "    \"ldap_bind_credential_present\": " << (lm.bind_credential_present ? "true" : "false") << ",\n";
        if (lm.bind_credential_present) {
            out << "    \"ldap_bind_credential_length\": " << lm.bind_credential_length << ",\n";
        }
    }
    if (lm.has_result) {
        out << "    \"ldap_result_code\": " << lm.result_code << ",\n";
        out << "    \"ldap_result_code_name\": \"" << json_escape(lm.result_code_name) << "\",\n";
        if (!lm.matched_dn.empty()) out << "    \"ldap_matched_dn\": \"" << json_escape(lm.matched_dn) << "\",\n";
        if (!lm.diagnostic_message.empty()) {
            out << "    \"ldap_diagnostic_message\": \"" << json_escape(lm.diagnostic_message) << "\",\n";
        }
    }
    if (!lm.referral_uris.empty()) {
        out << "    \"ldap_referral_uris\": [";
        for (size_t i = 0; i < lm.referral_uris.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(lm.referral_uris[i]) << "\"";
        }
        out << "],\n";
    }
    if (lm.message_type == "SearchRequest") {
        out << "    \"ldap_search_base_object\": \"" << json_escape(lm.search_base_object) << "\",\n";
        out << "    \"ldap_search_scope\": \"" << json_escape(lm.search_scope) << "\",\n";
        out << "    \"ldap_search_deref_aliases\": \"" << json_escape(lm.search_deref_aliases) << "\",\n";
        out << "    \"ldap_search_size_limit\": " << lm.search_size_limit << ",\n";
        out << "    \"ldap_search_time_limit\": " << lm.search_time_limit << ",\n";
        out << "    \"ldap_search_types_only\": " << (lm.search_types_only ? "true" : "false") << ",\n";
        out << "    \"ldap_search_filter\": \"" << json_escape(lm.search_filter) << "\",\n";
        if (!lm.search_attributes.empty()) {
            out << "    \"ldap_search_attributes\": [";
            for (size_t i = 0; i < lm.search_attributes.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(lm.search_attributes[i]) << "\"";
            }
            out << "],\n";
        }
    }
    if (lm.message_type == "SearchResultEntry") {
        out << "    \"ldap_search_result_object_name\": \"" << json_escape(lm.search_result_object_name) << "\",\n";
        if (!lm.search_result_attributes.empty()) {
            out << "    \"ldap_search_result_attributes\": [";
            for (size_t i = 0; i < lm.search_result_attributes.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(lm.search_result_attributes[i]) << "\"";
            }
            out << "],\n";
        }
    }
    if (lm.message_type == "SearchResultDone" && lm.correlated_request_seen) {
        out << "    \"ldap_search_entry_count\": " << lm.search_entry_count << ",\n";
    }
    if (lm.message_type == "CompareRequest") {
        out << "    \"ldap_compare_entry\": \"" << json_escape(lm.compare_entry) << "\",\n";
        out << "    \"ldap_compare_attribute\": \"" << json_escape(lm.compare_attribute) << "\",\n";
        out << "    \"ldap_compare_value\": \"" << json_escape(lm.compare_value) << "\",\n";
    }
    if (lm.message_type == "AbandonRequest") {
        out << "    \"ldap_abandon_message_id\": " << lm.abandon_message_id << ",\n";
    }
    if (lm.message_type == "ExtendedRequest" || lm.message_type == "ExtendedResponse") {
        if (!lm.extended_request_name.empty()) {
            out << "    \"ldap_extended_request_name\": \"" << json_escape(lm.extended_request_name) << "\",\n";
        }
        if (!lm.extended_request_name_known.empty()) {
            out << "    \"ldap_extended_request_name_known\": \"" << json_escape(lm.extended_request_name_known)
                << "\",\n";
        }
        if (!lm.extended_response_name.empty()) {
            out << "    \"ldap_extended_response_name\": \"" << json_escape(lm.extended_response_name) << "\",\n";
        }
        out << "    \"ldap_extended_value_present\": " << (lm.extended_value_present ? "true" : "false") << ",\n";
        if (lm.extended_value_present) {
            out << "    \"ldap_extended_value_length\": " << lm.extended_value_length << ",\n";
        }
    }
    if (!lm.control_oids.empty()) {
        out << "    \"ldap_control_oids\": [";
        for (size_t i = 0; i < lm.control_oids.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(lm.control_oids[i]) << "\"";
        }
        out << "],\n";
    }
    if (lm.correlated_request_seen) {
        out << "    \"ldap_correlated_request_index\": " << lm.correlated_request_index << ",\n";
    }
}

// Renders one DceRpcMessage (dcerpc.hpp) as a JSON object's inner fields -- called from within
// write_one_smb_message_json_fields's own "dcerpc_messages" array below. auth_value/stub bytes
// are never rendered (dcerpc.hpp itself never decodes them into anything but offset/length) --
// see dcerpc.hpp's own file header comment.
void write_dcerpc_message_json_fields(std::ostream& out, const DceRpcMessage& dm) {
    out << "            \"ptype\": \"" << json_escape(dm.ptype_name) << "\",\n";
    out << "            \"call_id\": " << dm.call_id << ",\n";
    if (!dm.pfc_flags.empty()) {
        out << "            \"pfc_flags\": [";
        for (size_t i = 0; i < dm.pfc_flags.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(dm.pfc_flags[i]) << "\"";
        }
        out << "],\n";
    }
    if (dm.has_bind) {
        out << "            \"bind_contexts\": [";
        for (size_t i = 0; i < dm.bind_contexts.size(); ++i) {
            const DceRpcContextElement& c = dm.bind_contexts[i];
            if (i != 0) out << ", ";
            out << "{\"context_id\": " << c.context_id << ", \"abstract_syntax_uuid\": \""
                << json_escape(c.abstract_syntax_uuid) << "\", \"is_netlogon\": "
                << (is_netlogon_interface_uuid(c.abstract_syntax_uuid) ? "true" : "false") << "}";
        }
        out << "],\n";
    }
    if (dm.has_bind_ack) {
        out << "            \"bind_ack_results\": [";
        for (size_t i = 0; i < dm.bind_ack_results.size(); ++i) {
            const DceRpcContextResult& r = dm.bind_ack_results[i];
            if (i != 0) out << ", ";
            out << "\"" << json_escape(r.result_name) << "\"";
        }
        out << "],\n";
    }
    if (dm.has_request) {
        out << "            \"opnum\": " << dm.opnum << ",\n";
    }
    if (dm.has_fault) {
        out << "            \"fault_status\": " << dm.fault_status << ",\n";
    }
    if (dm.has_sec_trailer) {
        out << "            \"auth_level\": \"" << json_escape(dm.auth_level_name) << "\",\n";
        out << "            \"sealed\": " << (dm.sealed ? "true" : "false") << ",\n";
    }
    out << "            \"summary\": \"" << json_escape(dm.summary) << "\"\n";
}

// Renders one NetlogonCall (netlogon.hpp) as a JSON object's inner fields -- called from within
// write_one_smb_message_json_fields's own "netlogon_calls" array below. ClearNewPassword and
// Authenticator are deliberately never rendered beyond presence/length -- see netlogon.hpp's own
// file header comment and NetlogonCall's own doc comment; this function has no field to leak them
// through even if it wanted to, since NetlogonCall itself never carries their bytes.
void write_netlogon_call_json_fields(std::ostream& out, const NetlogonCall& nc) {
    out << "            \"opnum\": \"" << json_escape(nc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << nc.call_id << ",\n";
    out << "            \"is_response\": " << (nc.is_response ? "true" : "false") << ",\n";
    if (nc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (nc.has_request_fields) {
        if (!nc.primary_name.empty()) {
            out << "            \"primary_name\": \"" << json_escape(nc.primary_name) << "\",\n";
        }
        if (!nc.account_name.empty()) {
            out << "            \"account_name\": \"" << json_escape(nc.account_name) << "\",\n";
        }
        if (!nc.computer_name.empty()) {
            out << "            \"computer_name\": \"" << json_escape(nc.computer_name) << "\",\n";
        }
        if (nc.has_secure_channel_type) {
            out << "            \"secure_channel_type\": \""
                << json_escape(nc.secure_channel_type_name) << "\",\n";
        }
        if (nc.has_client_credential) {
            out << "            \"client_credential_all_zero\": "
                << (nc.client_credential_is_all_zero ? "true" : "false") << ",\n";
        }
        if (nc.has_negotiate_flags) {
            out << "            \"negotiate_flags\": " << nc.negotiate_flags << ",\n";
        }
        if (nc.has_authenticator) {
            out << "            \"authenticator_present\": true,\n";
        }
        if (nc.has_clear_new_password) {
            out << "            \"clear_new_password_length\": " << nc.clear_new_password_length
                << ",\n";
        }
    }
    if (nc.has_response_fields) {
        if (nc.has_account_rid) {
            out << "            \"account_rid\": " << nc.account_rid << ",\n";
        }
        if (nc.has_status) {
            out << "            \"status_name\": \"" << json_escape(nc.status_name) << "\",\n";
        }
    }
    out << "            \"summary\": \"" << json_escape(nc.summary) << "\"\n";
}

// Renders one SamrCall (samr.hpp) as a JSON object's inner fields -- called from within
// write_one_smb_message_json_fields's own "samr_calls" array below. Fields not meaningful for this
// call's own opnum/direction are omitted, the same convention write_netlogon_call_json_fields above
// already establishes.
void write_samr_call_json_fields(std::ostream& out, const SamrCall& sc) {
    out << "            \"opnum\": \"" << json_escape(sc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << sc.call_id << ",\n";
    out << "            \"is_response\": " << (sc.is_response ? "true" : "false") << ",\n";
    if (sc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (sc.has_server_name && !sc.server_name.empty()) {
        out << "            \"server_name\": \"" << json_escape(sc.server_name) << "\",\n";
    }
    if (sc.has_handle) {
        out << "            \"handle\": \"" << json_escape(sc.handle_hex) << "\",\n";
    }
    if (sc.has_open_target) {
        out << "            \"desired_access\": " << sc.desired_access << ",\n";
        if (!sc.open_domain_sid.empty()) {
            out << "            \"domain_sid\": \"" << json_escape(sc.open_domain_sid) << "\",\n";
        }
        if (sc.has_open_rid) {
            out << "            \"rid\": " << sc.open_rid << ",\n";
        }
    }
    if (sc.has_enumeration_context) {
        out << "            \"enumeration_context\": " << sc.enumeration_context << ",\n";
    }
    if (!sc.lookup_names.empty()) {
        out << "            \"names\": [";
        for (size_t i = 0; i < sc.lookup_names.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(sc.lookup_names[i]) << "\"";
        }
        out << "],\n";
    }
    if (!sc.lookup_rids.empty()) {
        out << "            \"rids\": [";
        for (size_t i = 0; i < sc.lookup_rids.size(); ++i) {
            if (i != 0) out << ", ";
            out << sc.lookup_rids[i];
        }
        out << "],\n";
    }
    if (!sc.membership_query_sids.empty()) {
        out << "            \"query_sids\": [";
        for (size_t i = 0; i < sc.membership_query_sids.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(sc.membership_query_sids[i]) << "\"";
        }
        out << "],\n";
    }
    if (sc.has_response_fields) {
        if (sc.has_result_handle) {
            out << "            \"result_handle\": \"" << json_escape(sc.result_handle_hex) << "\",\n";
        }
        if (!sc.resolved_rids.empty()) {
            out << "            \"resolved_rids\": [";
            for (size_t i = 0; i < sc.resolved_rids.size(); ++i) {
                if (i != 0) out << ", ";
                out << sc.resolved_rids[i];
            }
            out << "],\n";
        }
        if (!sc.resolved_names.empty()) {
            out << "            \"resolved_names\": [";
            for (size_t i = 0; i < sc.resolved_names.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(sc.resolved_names[i]) << "\"";
            }
            out << "],\n";
        }
        if (!sc.enumerated_rids.empty()) {
            out << "            \"enumerated_rids\": [";
            for (size_t i = 0; i < sc.enumerated_rids.size(); ++i) {
                if (i != 0) out << ", ";
                out << sc.enumerated_rids[i];
            }
            out << "],\n";
            out << "            \"enumerated_names\": [";
            for (size_t i = 0; i < sc.enumerated_names.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(sc.enumerated_names[i]) << "\"";
            }
            out << "],\n";
        }
        if (!sc.membership_rids.empty()) {
            out << "            \"membership_rids\": [";
            for (size_t i = 0; i < sc.membership_rids.size(); ++i) {
                if (i != 0) out << ", ";
                out << sc.membership_rids[i];
            }
            out << "],\n";
        }
        if (sc.has_status) {
            out << "            \"status_name\": \"" << json_escape(sc.status_name) << "\",\n";
        }
    }
    out << "            \"summary\": \"" << json_escape(sc.summary) << "\"\n";
}

// Renders one LsarCall (lsarpc.hpp) as a JSON object's inner fields -- same conventions as
// write_samr_call_json_fields above.
void write_lsarpc_call_json_fields(std::ostream& out, const LsarCall& lc) {
    out << "            \"opnum\": \"" << json_escape(lc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << lc.call_id << ",\n";
    out << "            \"is_response\": " << (lc.is_response ? "true" : "false") << ",\n";
    if (lc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (lc.has_handle) {
        out << "            \"handle\": \"" << json_escape(lc.handle_hex) << "\",\n";
    }
    if (lc.has_enumeration_context) {
        out << "            \"enumeration_context\": " << lc.enumeration_context << ",\n";
    }
    if (!lc.lookup_names.empty()) {
        out << "            \"names\": [";
        for (size_t i = 0; i < lc.lookup_names.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(lc.lookup_names[i]) << "\"";
        }
        out << "],\n";
    }
    if (!lc.lookup_sids.empty()) {
        out << "            \"sids\": [";
        for (size_t i = 0; i < lc.lookup_sids.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(lc.lookup_sids[i]) << "\"";
        }
        out << "],\n";
    }
    if (lc.has_response_fields) {
        if (lc.has_result_handle) {
            out << "            \"result_handle\": \"" << json_escape(lc.result_handle_hex) << "\",\n";
        }
        if (!lc.referenced_domains.empty()) {
            out << "            \"referenced_domains\": [\n";
            for (size_t i = 0; i < lc.referenced_domains.size(); ++i) {
                const LsarDomainEntry& d = lc.referenced_domains[i];
                out << "              {\"name\": \"" << json_escape(d.name) << "\", \"sid\": \""
                    << json_escape(d.sid) << "\"}"
                    << (i + 1 < lc.referenced_domains.size() ? "," : "") << "\n";
            }
            out << "            ],\n";
        }
        if (!lc.translated_rids.empty()) {
            out << "            \"translated_rids\": [";
            for (size_t i = 0; i < lc.translated_rids.size(); ++i) {
                if (i != 0) out << ", ";
                out << lc.translated_rids[i];
            }
            out << "],\n";
        }
        if (!lc.translated_names.empty()) {
            out << "            \"translated_names\": [";
            for (size_t i = 0; i < lc.translated_names.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(lc.translated_names[i]) << "\"";
            }
            out << "],\n";
        }
        if (!lc.enumerated_sids.empty()) {
            out << "            \"enumerated_sids\": [";
            for (size_t i = 0; i < lc.enumerated_sids.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(lc.enumerated_sids[i]) << "\"";
            }
            out << "],\n";
        }
        if (!lc.enumerated_trusted_domains.empty()) {
            out << "            \"enumerated_trusted_domains\": [\n";
            for (size_t i = 0; i < lc.enumerated_trusted_domains.size(); ++i) {
                const LsarDomainEntry& d = lc.enumerated_trusted_domains[i];
                out << "              {\"name\": \"" << json_escape(d.name) << "\", \"sid\": \""
                    << json_escape(d.sid) << "\"}"
                    << (i + 1 < lc.enumerated_trusted_domains.size() ? "," : "") << "\n";
            }
            out << "            ],\n";
        }
        if (lc.has_status) {
            out << "            \"status_name\": \"" << json_escape(lc.status_name) << "\",\n";
        }
    }
    out << "            \"summary\": \"" << json_escape(lc.summary) << "\"\n";
}

// Renders one SrvsvcCall (srvsvc.hpp) as a JSON object's inner fields -- same conventions as
// write_samr_call_json_fields above.
void write_srvsvc_call_json_fields(std::ostream& out, const SrvsvcCall& sc) {
    out << "            \"opnum\": \"" << json_escape(sc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << sc.call_id << ",\n";
    out << "            \"is_response\": " << (sc.is_response ? "true" : "false") << ",\n";
    if (sc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (sc.has_server_name && !sc.server_name.empty()) {
        out << "            \"server_name\": \"" << json_escape(sc.server_name) << "\",\n";
    }
    if (sc.has_level) {
        out << "            \"level\": " << sc.level << ",\n";
    }
    if (!sc.net_name.empty()) {
        out << "            \"net_name\": \"" << json_escape(sc.net_name) << "\",\n";
    }
    if (!sc.shares.empty()) {
        out << "            \"shares\": [\n";
        for (size_t i = 0; i < sc.shares.size(); ++i) {
            const SrvsvcShareEntry& s = sc.shares[i];
            out << "              {\"net_name\": \"" << json_escape(s.net_name) << "\", \"type\": \""
                << json_escape(s.type_name) << "\", \"remark\": \"" << json_escape(s.remark) << "\"}"
                << (i + 1 < sc.shares.size() ? "," : "") << "\n";
        }
        out << "            ],\n";
    }
    if (sc.has_total_entries) {
        out << "            \"total_entries\": " << sc.total_entries << ",\n";
    }
    if (sc.has_response_fields && sc.has_status) {
        out << "            \"status_name\": \"" << json_escape(sc.status_name) << "\",\n";
    }
    out << "            \"summary\": \"" << json_escape(sc.summary) << "\"\n";
}

// Renders one WkssvcCall (wkssvc.hpp) as a JSON object's inner fields -- same conventions as
// write_samr_call_json_fields above.
void write_wkssvc_call_json_fields(std::ostream& out, const WkssvcCall& wc) {
    out << "            \"opnum\": \"" << json_escape(wc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << wc.call_id << ",\n";
    out << "            \"is_response\": " << (wc.is_response ? "true" : "false") << ",\n";
    if (wc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (wc.has_server_name && !wc.server_name.empty()) {
        out << "            \"server_name\": \"" << json_escape(wc.server_name) << "\",\n";
    }
    if (wc.has_level) {
        out << "            \"level\": " << wc.level << ",\n";
    }
    if (wc.has_wksta_info) {
        out << "            \"platform_id\": " << wc.platform_id << ",\n";
        out << "            \"computername\": \"" << json_escape(wc.computername) << "\",\n";
        out << "            \"langroup\": \"" << json_escape(wc.langroup) << "\",\n";
        out << "            \"os_version\": \"" << wc.ver_major << "." << wc.ver_minor << "\",\n";
    }
    if (!wc.logged_on_users.empty()) {
        out << "            \"logged_on_users\": [\n";
        for (size_t i = 0; i < wc.logged_on_users.size(); ++i) {
            const WkssvcUserEntry& u = wc.logged_on_users[i];
            out << "              {\"username\": \"" << json_escape(u.username)
                << "\", \"logon_domain\": \"" << json_escape(u.logon_domain)
                << "\", \"oth_domains\": \"" << json_escape(u.oth_domains)
                << "\", \"logon_server\": \"" << json_escape(u.logon_server) << "\"}"
                << (i + 1 < wc.logged_on_users.size() ? "," : "") << "\n";
        }
        out << "            ],\n";
    }
    if (wc.has_total_entries) {
        out << "            \"total_entries\": " << wc.total_entries << ",\n";
    }
    if (wc.has_response_fields && wc.has_status) {
        out << "            \"status_name\": \"" << json_escape(wc.status_name) << "\",\n";
    }
    out << "            \"summary\": \"" << json_escape(wc.summary) << "\"\n";
}

// Renders one DrsuapiCall (drsuapi.hpp) as a JSON object's inner fields -- same conventions as
// write_samr_call_json_fields above.
void write_drsuapi_call_json_fields(std::ostream& out, const DrsuapiCall& dc) {
    out << "            \"opnum\": \"" << json_escape(dc.opnum_name) << "\",\n";
    out << "            \"call_id\": " << dc.call_id << ",\n";
    out << "            \"is_response\": " << (dc.is_response ? "true" : "false") << ",\n";
    if (dc.sealed) {
        out << "            \"sealed\": true,\n";
    }
    if (dc.has_client_dsa_guid) {
        out << "            \"client_dsa_guid\": \"" << json_escape(dc.client_dsa_guid) << "\",\n";
    }
    if (dc.has_handle) {
        out << "            \"handle\": \"" << json_escape(dc.handle_hex) << "\",\n";
    }
    if (dc.has_response_fields && dc.has_status) {
        out << "            \"status_name\": \"" << json_escape(dc.status_name) << "\",\n";
    }
    out << "            \"summary\": \"" << json_escape(dc.summary) << "\"\n";
}

// Renders one SmbMessage (smb.hpp) as a JSON object's inner fields, indented for use inside
// write_smb_json_fields's own "smb_messages" array below -- one call per sub-message in a
// (possibly compounded, see smb.hpp's own COMPOUNDING paragraph) SmbFrame. Every field not
// meaningful for this particular message's own command is simply omitted, the same "always-set
// vs. has_*/non-empty-gated" convention write_kerberos_json_fields/write_ldap_json_fields above
// already establish.
void write_one_smb_message_json_fields(std::ostream& out, const SmbMessage& m) {
    out << "        \"command\": \"" << json_escape(m.command_name) << "\",\n";
    out << "        \"command_value\": " << m.command_value << ",\n";
    out << "        \"is_response\": " << (m.is_response ? "true" : "false") << ",\n";
    out << "        \"message_id\": " << m.message_id << ",\n";
    out << "        \"session_id\": " << m.session_id << ",\n";
    if (m.is_async) {
        out << "        \"async_id\": " << m.async_id << ",\n";
    } else {
        out << "        \"tree_id\": " << m.tree_id << ",\n";
    }
    if (m.is_response) {
        out << "        \"status\": " << m.status << ",\n";
        out << "        \"status_name\": \"" << json_escape(m.status_name) << "\",\n";
    }
    if (!m.header_flags.empty()) {
        out << "        \"header_flags\": [";
        for (size_t i = 0; i < m.header_flags.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(m.header_flags[i]) << "\"";
        }
        out << "],\n";
    }
    if (m.next_command != 0) {
        out << "        \"compounded_next\": true,\n";
    }

    if (!m.negotiate_dialects.empty()) {
        out << "        \"negotiate_dialects\": [";
        for (size_t i = 0; i < m.negotiate_dialects.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(m.negotiate_dialects[i]) << "\"";
        }
        out << "],\n";
    }
    if (m.has_negotiate_response) {
        out << "        \"negotiated_dialect\": \"" << json_escape(m.negotiated_dialect) << "\",\n";
        out << "        \"server_guid\": \"" << json_escape(m.server_guid_hex) << "\",\n";
        if (!m.negotiate_response_security_mode.empty()) {
            out << "        \"security_mode\": [";
            for (size_t i = 0; i < m.negotiate_response_security_mode.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(m.negotiate_response_security_mode[i]) << "\"";
            }
            out << "],\n";
        }
        if (!m.negotiate_capabilities.empty()) {
            out << "        \"capabilities\": [";
            for (size_t i = 0; i < m.negotiate_capabilities.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(m.negotiate_capabilities[i]) << "\"";
            }
            out << "],\n";
        }
    }
    if (m.has_session_setup_request) {
        out << "        \"previous_session_id\": " << m.previous_session_id << ",\n";
    }
    if (m.has_session_setup_response && !m.session_flags.empty()) {
        out << "        \"session_flags\": [";
        for (size_t i = 0; i < m.session_flags.size(); ++i) {
            if (i != 0) out << ", ";
            out << "\"" << json_escape(m.session_flags[i]) << "\"";
        }
        out << "],\n";
    }
    if (m.has_ntlm) {
        out << "        \"ntlm_message_type\": \"" << json_escape(m.ntlm.message_type) << "\",\n";
        if (!m.ntlm.target_name.empty()) {
            out << "        \"ntlm_target_name\": \"" << json_escape(m.ntlm.target_name) << "\",\n";
        }
        if (!m.ntlm.user_name.empty()) {
            out << "        \"ntlm_user_name\": \"" << json_escape(m.ntlm.user_name) << "\",\n";
        }
        if (!m.ntlm.auth_domain_name.empty()) {
            out << "        \"ntlm_domain_name\": \"" << json_escape(m.ntlm.auth_domain_name) << "\",\n";
        }
    }
    if (m.has_tree_connect_request) {
        out << "        \"tree_connect_path\": \"" << json_escape(m.tree_connect_path) << "\",\n";
    }
    if (m.has_tree_connect_response) {
        out << "        \"share_type\": \"" << json_escape(m.share_type) << "\",\n";
        if (!m.share_flags.empty()) {
            out << "        \"share_flags\": [";
            for (size_t i = 0; i < m.share_flags.size(); ++i) {
                if (i != 0) out << ", ";
                out << "\"" << json_escape(m.share_flags[i]) << "\"";
            }
            out << "],\n";
        }
    }
    if (m.has_create_request && !m.create_name.empty()) {
        out << "        \"create_name\": \"" << json_escape(m.create_name) << "\",\n";
    }
    if (m.has_file_id) {
        std::ostringstream fid;
        fid << std::hex << std::setfill('0') << std::setw(16) << m.file_id.persistent << ":"
            << std::setw(16) << m.file_id.volatile_id;
        out << "        \"file_id\": \"" << fid.str() << "\",\n";
    }
    if (!m.dcerpc_messages.empty()) {
        out << "        \"dcerpc_messages\": [\n";
        for (size_t i = 0; i < m.dcerpc_messages.size(); ++i) {
            out << "          {\n";
            write_dcerpc_message_json_fields(out, m.dcerpc_messages[i]);
            out << "          }" << (i + 1 < m.dcerpc_messages.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.netlogon_calls.empty()) {
        out << "        \"netlogon_calls\": [\n";
        for (size_t i = 0; i < m.netlogon_calls.size(); ++i) {
            out << "          {\n";
            write_netlogon_call_json_fields(out, m.netlogon_calls[i]);
            out << "          }" << (i + 1 < m.netlogon_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.samr_calls.empty()) {
        out << "        \"samr_calls\": [\n";
        for (size_t i = 0; i < m.samr_calls.size(); ++i) {
            out << "          {\n";
            write_samr_call_json_fields(out, m.samr_calls[i]);
            out << "          }" << (i + 1 < m.samr_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.lsarpc_calls.empty()) {
        out << "        \"lsarpc_calls\": [\n";
        for (size_t i = 0; i < m.lsarpc_calls.size(); ++i) {
            out << "          {\n";
            write_lsarpc_call_json_fields(out, m.lsarpc_calls[i]);
            out << "          }" << (i + 1 < m.lsarpc_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.srvsvc_calls.empty()) {
        out << "        \"srvsvc_calls\": [\n";
        for (size_t i = 0; i < m.srvsvc_calls.size(); ++i) {
            out << "          {\n";
            write_srvsvc_call_json_fields(out, m.srvsvc_calls[i]);
            out << "          }" << (i + 1 < m.srvsvc_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.wkssvc_calls.empty()) {
        out << "        \"wkssvc_calls\": [\n";
        for (size_t i = 0; i < m.wkssvc_calls.size(); ++i) {
            out << "          {\n";
            write_wkssvc_call_json_fields(out, m.wkssvc_calls[i]);
            out << "          }" << (i + 1 < m.wkssvc_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (!m.drsuapi_calls.empty()) {
        out << "        \"drsuapi_calls\": [\n";
        for (size_t i = 0; i < m.drsuapi_calls.size(); ++i) {
            out << "          {\n";
            write_drsuapi_call_json_fields(out, m.drsuapi_calls[i]);
            out << "          }" << (i + 1 < m.drsuapi_calls.size() ? "," : "") << "\n";
        }
        out << "        ],\n";
    }
    if (m.ntlm_handshake_closed) {
        out << "        \"ntlm_handshake_summary\": \"" << json_escape(m.ntlm_handshake_summary) << "\",\n";
    }
    if (m.correlated_request_seen) {
        out << "        \"correlated_request_index\": " << m.correlated_request_index << ",\n";
    }
    out << "        \"summary\": \"" << json_escape(m.summary) << "\"\n";
}

// The SMB analog of write_kerberos_json_fields/write_ldap_json_fields above -- SmbFrame (smb.hpp)
// differs from KerberosMessage/LdapMessage in carrying a whole vector of sub-messages rather than
// one message, since one SMB2 TCP payload can be a compounded chain (see smb.hpp's own COMPOUNDING
// paragraph); "smb_messages" is always present (possibly empty, for SMB1/SMB2_TRANSFORM traffic,
// which this decoder recognizes but doesn't field-decode -- see smb.hpp's own DELIBERATELY NOT
// IMPLEMENTED list) rather than gated on a has_* flag, so a JSON consumer never has to special-case
// its absence.
void write_smb_json_fields(std::ostream& out, const SmbFrame& sf) {
    out << "    \"smb_envelope_kind\": \"" << json_escape(sf.envelope_kind) << "\",\n";
    out << "    \"smb_compounded\": " << (sf.messages.size() > 1 ? "true" : "false") << ",\n";
    out << "    \"smb_messages\": [";
    if (sf.messages.empty()) {
        out << "],\n";
    } else {
        out << "\n";
        for (size_t i = 0; i < sf.messages.size(); ++i) {
            out << "      {\n";
            write_one_smb_message_json_fields(out, sf.messages[i]);
            out << "      }" << (i + 1 < sf.messages.size() ? "," : "") << "\n";
        }
        out << "    ],\n";
    }
}

}  // namespace

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
    if (p.protocol == "modbus" && p.result) {
        write_modbus_json_fields(out_, p.result->as<ModbusFrame>());
    }
    if (p.protocol == "s7comm" && p.result) {
        write_s7comm_json_fields(out_, p.result->as<S7CommResult>());
    }
    if (p.protocol == "dnp3" && p.result) {
        write_dnp3_json_fields(out_, p.result->as<Dnp3Result>());
    }
    if (p.protocol == "iec104" && p.result) {
        write_iec104_json_fields(out_, p.result->as<Iec104Result>());
    }
    if (p.protocol == "enip" && p.result) {
        // See write_enip_json_fields's own comment for why "enip" needs this has_tcp/has_udp
        // discriminator, unlike every other zero-flat-field protocol in this file.
        if (p.has_tcp) {
            write_enip_json_fields(out_, p.result->as<EnipResult>().first);
        } else if (p.has_udp) {
            write_enip_io_json_fields(out_, p.result->as<CipIoFrame>());
        }
    }
    if (p.protocol == "profinet" && p.result) {
        write_profinet_json_fields(out_, p.result->as<ProfinetFrame>());
    }
    if (p.protocol == "goose" && p.result) {
        write_goose_json_fields(out_, p.result->as<GooseFrame>());
    }
    if (p.protocol == "sv" && p.result) {
        write_sv_json_fields(out_, p.result->as<SvFrame>());
    }
    if (p.protocol == "ethercat" && p.result) {
        write_ethercat_json_fields(out_, p.result->as<EthercatFrame>());
    }
    if (p.protocol == "stp" && p.result) {
        write_stp_json_fields(out_, p.result->as<StpFrame>());
    }
    if (p.protocol == "devicenet" && p.result) {
        write_devicenet_json_fields(out_, p.result->as<DeviceNetFrame>());
    }
    if (p.protocol == "bacnet" && p.result) {
        write_bacnet_json_fields(out_, p.result->as<BacnetFrame>());
    }
    if (p.protocol == "hartip" && p.result) {
        write_hartip_json_fields(out_, p.result->as<HartIpResult>().first);
    }
    if (p.protocol == "opcua" && p.result) {
        write_opcua_json_fields(out_, p.result->as<OpcUaResult>().first);
    }
    if (p.protocol == "mms" && p.result) {
        write_mms_json_fields(out_, p.result->as<MmsFrame>());
    }
    if (p.protocol == "mqtt" && p.result) {
        write_mqtt_json_fields(out_, p.result->as<MqttResult>().first);
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
    if (p.protocol == "ffhse" && p.result) {
        write_ffhse_json_fields(out_, p.result->as<FfhseResult>().first);
    }
    if ((p.protocol == "dns" || p.protocol == "mdns" || p.protocol == "llmnr") && p.result) {
        write_dns_json_fields(out_, p.result->as<DnsMessage>());
    }
    if (p.protocol == "nbns" && p.result) {
        write_nbns_json_fields(out_, p.result->as<NbnsMessage>());
    }
    if (p.protocol == "doh" && p.result) {
        write_doh_json_fields(out_, p.result->as<DohDetection>());
    }
    if (p.protocol == "rip" && p.result) {
        write_rip_json_fields(out_, p.result->as<RipMessage>());
    }
    if (p.protocol == "icmp" && p.result) {
        write_icmp_json_fields(out_, p.result->as<IcmpMessage>());
    }
    if (p.protocol == "igmp" && p.result) {
        write_igmp_json_fields(out_, p.result->as<IgmpMessage>());
    }
    if (p.protocol == "vrrp" && p.result) {
        write_vrrp_json_fields(out_, p.result->as<VrrpMessage>());
    }
    if (p.protocol == "hsrp" && p.result) {
        write_hsrp_json_fields(out_, p.result->as<HsrpMessage>());
    }
    if (p.protocol == "igrp" && p.result) {
        write_igrp_json_fields(out_, p.result->as<IgrpMessage>());
    }
    if (p.protocol == "pim" && p.result) {
        write_pim_json_fields(out_, p.result->as<PimMessage>());
    }
    if (p.protocol == "eigrp" && p.result) {
        write_eigrp_json_fields(out_, p.result->as<EigrpMessage>());
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
    if (p.protocol == "twincat" && p.result) {
        write_twincat_json_fields(out_, p.result->as<TwinCatFrame>());
    }
    if (p.protocol == "bgp" && p.result) {
        write_bgp_json_fields(out_, p.result->as<BgpResult>());
    }
    if (p.protocol == "slow-protocols" && p.result) {
        write_slow_protocols_json_fields(out_, p.result->as<SlowProtocolsMessage>());
    }
    if (p.protocol == "melsec" && p.result) {
        write_melsec_json_fields(out_, p.result->as<MelsecFrame>());
    }
    if (p.protocol == "fins" && p.result) {
        write_fins_json_fields(out_, p.result->as<FinsFrame>());
    }
    if (p.protocol == "kerberos" && p.result) {
        write_kerberos_json_fields(out_, p.result->as<KerberosMessage>());
    }
    if (p.protocol == "ldap" && p.result) {
        write_ldap_json_fields(out_, p.result->as<LdapMessage>());
    }
    if (p.protocol == "smb" && p.result) {
        write_smb_json_fields(out_, p.result->as<SmbFrame>());
    }
    if (p.protocol == "winrm" && p.result) {
        write_winrm_json_fields(out_, p.result->as<WinRmMessage>());
    }
    if (p.protocol == "dcom" && p.result) {
        write_dcom_json_fields(out_, p.result->as<DcomMessage>());
    }
    if (p.protocol == "ge-srtp" && p.result) {
        write_ge_srtp_json_fields(out_, p.result->as<GeSrtpFrame>());
    }
    if (p.protocol == "bsap" && p.result) {
        write_bsap_json_fields(out_, p.result->as<BsapFrame>());
    }
    if (p.protocol == "cclink-ie" && p.result) {
        write_cclink_ie_json_fields(out_, p.result->as<CclinkIeFrame>());
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

namespace {

// Reverses json_escape's own escaping (this file, above) for one string LITERAL's inner text (the
// substring between its surrounding quotes, already stripped by the caller) -- the counterpart
// FieldsWriter needs since it re-parses JsonWriter's own already-escaped output rather than the
// original DecodedPacket fields. Unrecognized escape sequences (none should ever appear, since
// json_escape only ever produces the five handled below plus \\uXXXX for control characters --
// \u is deliberately left un-decoded here, since no field this codebase emits needs it rendered
// back to a raw control character for -T fields' own tab-separated output) are left as-is rather
// than guessed at.
std::string json_unescape_inner(const std::string& inner) {
    std::string out;
    out.reserve(inner.size());
    for (size_t i = 0; i < inner.size(); ++i) {
        if (inner[i] == '\\' && i + 1 < inner.size()) {
            char n = inner[i + 1];
            switch (n) {
                case '"': out += '"'; ++i; continue;
                case '\\': out += '\\'; ++i; continue;
                case '/': out += '/'; ++i; continue;
                case 'n': out += '\n'; ++i; continue;
                case 't': out += '\t'; ++i; continue;
                case 'r': out += '\r'; ++i; continue;
                default: break;  // \uXXXX or anything else -- fall through, keep the backslash literally
            }
        }
        out += inner[i];
    }
    return out;
}

// Renders a JSON array-of-strings LITERAL (e.g. `["a", "b"]`, `bgp_update_communities`'s own
// shape) as a comma-joined plain-text list -- every list-valued field this codebase's JsonWriter
// emits is an array of pre-rendered strings, never a nested object or an array of bare numbers
// (confirmed by inspection of every write_packet/write_*_json_fields function in this file), so
// this only needs to handle quoted-string elements.
std::string render_json_array(const std::string& arr) {
    std::string inner = arr.size() >= 2 ? arr.substr(1, arr.size() - 2) : std::string();
    std::vector<std::string> items;
    size_t i = 0;
    while (i < inner.size()) {
        while (i < inner.size() && (inner[i] == ' ' || inner[i] == ',')) ++i;
        if (i >= inner.size()) break;
        if (inner[i] == '"') {
            size_t j = i + 1;
            std::string item;
            while (j < inner.size() && inner[j] != '"') {
                if (inner[j] == '\\' && j + 1 < inner.size()) {
                    item += inner[j];
                    item += inner[j + 1];
                    j += 2;
                } else {
                    item += inner[j];
                    ++j;
                }
            }
            items.push_back(json_unescape_inner(item));
            i = j + 1;
        } else {
            size_t start = i;
            while (i < inner.size() && inner[i] != ',') ++i;
            items.push_back(inner.substr(start, i - start));
        }
    }
    std::ostringstream joined;
    for (size_t k = 0; k < items.size(); ++k) {
        if (k != 0) joined << ",";
        joined << items[k];
    }
    return joined.str();
}

// Converts one field's raw JSON-literal text (everything after `"key": ` on its own line, trailing
// comma already stripped by the caller) into the plain-text form -T fields prints: `null` becomes
// an empty column (a JSON `null` and an entirely absent field render identically -- see
// FieldsWriter's own class comment), a quoted string is unescaped and unquoted, an array is
// rendered by render_json_array above, and anything else (a bare number, `true`/`false`) is passed
// through verbatim, since it's already exactly the text a tab-separated column should show.
std::string render_field_value(const std::string& raw) {
    if (raw.empty() || raw == "null") return "";
    if (raw.size() >= 2 && raw.front() == '"' && raw.back() == '"') {
        return json_unescape_inner(raw.substr(1, raw.size() - 2));
    }
    if (raw.size() >= 2 && raw.front() == '[' && raw.back() == ']') {
        return render_json_array(raw);
    }
    return raw;
}

// Parses the flat `{ "key": value, ... }` object JsonWriter::write_packet produces for exactly one
// packet (see JsonWriter's own file header -- every field lives on its own line, never nested, a
// deliberate simplicity choice this parser depends on) into a key -> plain-text-value map. Any line
// that isn't `whitespace "key": ...` (the opening `  {`, a closing `  }`, or a continuation this
// codebase's JsonWriter never actually produces) is simply skipped, not an error.
std::map<std::string, std::string> parse_flat_json_object(const std::string& text) {
    std::map<std::string, std::string> out;
    std::istringstream iss(text);
    std::string line;
    while (std::getline(iss, line)) {
        size_t p = line.find_first_not_of(" \t");
        if (p == std::string::npos || line[p] != '"') continue;
        size_t key_start = p + 1;
        size_t key_end = line.find('"', key_start);
        if (key_end == std::string::npos) continue;
        std::string key = line.substr(key_start, key_end - key_start);
        size_t colon = line.find(':', key_end);
        if (colon == std::string::npos) continue;
        size_t val_start = colon + 1;
        while (val_start < line.size() && line[val_start] == ' ') ++val_start;
        size_t last = line.find_last_not_of(" \t\r");
        if (last == std::string::npos || last < val_start) {
            out[key] = "";
            continue;
        }
        size_t val_end = (line[last] == ',') ? last : last + 1;
        if (val_end < val_start) val_end = val_start;
        out[key] = render_field_value(line.substr(val_start, val_end - val_start));
    }
    return out;
}

}  // namespace

void FieldsWriter::write_packet(const DecodedPacket& packet) {
    // A fresh JsonWriter per packet, not a reused member -- JsonWriter::write_packet prefixes
    // every call after its first with ",\n" (see its own definition above), state this class has
    // no use for and would otherwise have to explicitly reset; constructing one per packet is
    // cheap and sidesteps that state entirely.
    std::ostringstream capture;
    JsonWriter one_shot(capture, resolver_, show_vlan_, time_format_, time_offset_, show_direction_);
    one_shot.write_packet(packet);
    std::map<std::string, std::string> values = parse_flat_json_object(capture.str());

    // terminal_escape (finding 4, docs/reviews/2026-09-chatgpt-security-review-patch160.md): this
    // is text-mode output too (a real terminal, same as TextWriter), and json_unescape_inner above
    // deliberately restores literal \n/\t/\r bytes from JSON's own \n/\t/\r escapes (see its own
    // comment) -- without this, a packet-derived field containing one of those could inject a raw
    // tab into a supposedly tab-separated row (corrupting the column structure a downstream script
    // might trust) or a raw newline to forge what looks like an extra row. \uXXXX escapes (ESC
    // included) are already left untouched as literal text by json_unescape_inner, so this is
    // narrower defense in depth on top of that, not the primary fix for the ANSI-escape case --
    // TextWriter's own two call sites above are.
    for (size_t i = 0; i < fields_.size(); ++i) {
        if (i != 0) out_ << "\t";
        auto it = values.find(fields_[i]);
        out_ << (it != values.end() ? terminal_escape(it->second) : "");
    }
    out_ << "\n";
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
    if (p.protocol == "modbus" && p.result) {
        const ModbusFrame& mb = p.result->as<ModbusFrame>();
        modbus_function_counts_[mb.function_name]++;
        if (mb.is_exception) modbus_exceptions_++;
        if (mb.paired_response) modbus_paired_responses_++;
    }
    if (p.protocol == "twincat" && p.result) {
        const TwinCatFrame& tc = p.result->as<TwinCatFrame>();
        twincat_command_counts_[tc.command_name]++;
        if (tc.paired_response) twincat_paired_responses_++;
    }
    if (p.protocol == "melsec" && p.result) {
        const MelsecFrame& mf = p.result->as<MelsecFrame>();
        melsec_command_counts_[mf.command_name]++;
        if (mf.is_response && mf.has_command) melsec_matched_responses_++;
    }
    if (p.protocol == "fins" && p.result) {
        const FinsFrame& ff = p.result->as<FinsFrame>();
        if (!ff.is_tcp_envelope_only) {
            fins_command_counts_[ff.command_name]++;
        } else {
            fins_command_counts_[ff.tcp_command_name]++;
        }
        if (ff.matched_to_request) fins_matched_responses_++;
    }
    // Curated Note 5 (kerberos.hpp's file header comment) -- passive burst/enumeration
    // visibility: named KRB-ERROR error-code counts, aggregated across the whole capture, with
    // no per-session correlation needed at all. A burst of KDC_ERR_PREAUTH_FAILED/
    // KDC_ERR_C_PRINCIPAL_UNKNOWN is a password-spray/account-enumeration signal visible here
    // even when the flagship per-packet notes (which do need correlation) don't fire.
    if (p.protocol == "kerberos" && p.result) {
        const KerberosMessage& km = p.result->as<KerberosMessage>();
        if (km.message_type == "KRB-ERROR") {
            kerberos_error_counts_[km.error_name]++;
        }
    }
    // Curated Note 6 (ldap.hpp's file header comment) -- the LDAP-native analog of Kerberos's own
    // KRB-ERROR count aggregation just above: named resultCode counts across every LDAPResult-
    // shaped message in the capture, so a burst of invalidCredentials (a password spray across many
    // distinct bind DNs) is visible with no per-request correlation needed at all.
    if (p.protocol == "ldap" && p.result) {
        const LdapMessage& lm = p.result->as<LdapMessage>();
        if (lm.has_result) {
            ldap_result_code_counts_[lm.result_code_name]++;
        }
    }
    // Curated Note 6 (smb.hpp's file header comment) -- the SMB-native analog of Kerberos's/LDAP's
    // own aggregate count notes just above: named Status counts from SESSION_SETUP responses only
    // (authentication outcomes specifically, not every SMB2 command's own Status), so a burst of
    // STATUS_LOGON_FAILURE across many SESSION_SETUP attempts on one session -- the SMB-side
    // password-spray signature -- is visible with no per-request correlation needed at all.
    if (p.protocol == "smb" && p.result) {
        const SmbFrame& sf = p.result->as<SmbFrame>();
        for (const SmbMessage& m : sf.messages) {
            if (m.command_value == 0x01 /* SESSION_SETUP */ && m.is_response) {
                smb_status_counts_[m.status_name]++;
            }
            for (const NetlogonCall& nc : m.netlogon_calls) {
                if (!nc.is_response) netlogon_opnum_counts_[nc.opnum_name]++;
            }
            for (const SamrCall& sc : m.samr_calls) {
                if (!sc.is_response) samr_opnum_counts_[sc.opnum_name]++;
            }
            for (const LsarCall& lc : m.lsarpc_calls) {
                if (!lc.is_response) lsarpc_opnum_counts_[lc.opnum_name]++;
            }
            for (const SrvsvcCall& svc : m.srvsvc_calls) {
                if (!svc.is_response) srvsvc_opnum_counts_[svc.opnum_name]++;
            }
            for (const WkssvcCall& wc : m.wkssvc_calls) {
                if (!wc.is_response) wkssvc_opnum_counts_[wc.opnum_name]++;
            }
            for (const DrsuapiCall& dc : m.drsuapi_calls) {
                if (!dc.is_response) drsuapi_opnum_counts_[dc.opnum_name]++;
            }
        }
    }
    if (p.protocol == "s7comm" && p.result) {
        const S7CommResult& sr = p.result->as<S7CommResult>();
        if (sr.has_function) s7comm_function_counts_[sr.function_name]++;
    }
    if (p.protocol == "dnp3" && p.result) {
        const Dnp3Result& dr = p.result->as<Dnp3Result>();
        if (dr.dnp3_has_function) dnp3_function_counts_[dr.dnp3_function_name]++;
    }
    if (p.protocol == "iec104" && p.result) {
        const Iec104Result& ir = p.result->as<Iec104Result>();
        if (ir.iec104_has_asdu) iec104_asdu_type_counts_[ir.iec104_asdu_type_name]++;
    }
    if (p.protocol == "enip" && p.result) {
        if (p.has_tcp) {
            const EnipFrame& ef = p.result->as<EnipResult>().first;
            if (!ef.header.command_name.empty()) enip_command_counts_[ef.header.command_name]++;
            if (ef.has_cip) enip_cip_service_counts_[ef.cip.service_name]++;
        } else if (p.has_udp) {
            enip_io_datagram_count_++;
        }
    }
    if (p.protocol == "profinet" && p.result) {
        const ProfinetFrame& pn = p.result->as<ProfinetFrame>();
        profinet_frame_id_counts_[pn.frame_id_name]++;
        if (pn.has_dcp) profinet_dcp_count_++;
        if (pn.has_cyclic_data) profinet_cyclic_count_++;
    }
    if (p.protocol == "goose" && p.result) {
        const GooseFrame& gs = p.result->as<GooseFrame>();
        if (gs.has_pdu) goose_pdu_count_++;
        if (gs.is_gse_management) goose_gse_management_count_++;
        if (gs.has_pdu && (gs.header_simulated || (gs.simulation && *gs.simulation))) goose_simulated_count_++;
    }
    if (p.protocol == "sv" && p.result) {
        const SvFrame& sv = p.result->as<SvFrame>();
        sv_frame_count_++;
        sv_asdu_total_ += sv.asdus.size();
    }
    if (p.protocol == "ethercat" && p.result) {
        const EthercatFrame& ec = p.result->as<EthercatFrame>();
        ethercat_frame_type_counts_[ec.frame_type_name]++;
        ethercat_datagram_total_ += ec.datagrams.size();
    }
    if (p.protocol == "stp" && p.result) {
        const StpFrame& stp = p.result->as<StpFrame>();
        stp_bpdu_type_counts_[stp.bpdu_type_name]++;
        stp_protocol_version_counts_[stp.protocol_version_name]++;
        if (stp.is_mstp) {
            stp_mstp_count_++;
            stp_msti_total_ += stp.msti_messages.size();
        }
        if (stp.has_common_body && stp.flag_tc) stp_tc_count_++;
    }
    if (p.protocol == "devicenet" && p.result) {
        const DeviceNetFrame& dn = p.result->as<DeviceNetFrame>();
        devicenet_group_counts_[dn.group_name]++;
        devicenet_message_type_counts_[dn.message_type_name]++;
        if (dn.is_fragmented) devicenet_fragmented_count_++;
        if (dn.fd) devicenet_fd_count_++;
    }
    if (p.protocol == "bacnet" && p.result) {
        const BacnetFrame& bf = p.result->as<BacnetFrame>();
        bacnet_bvlc_function_counts_[bf.bvlc_function_name]++;
        if (bf.has_npdu && bf.npdu.has_apdu && !bf.npdu.apdu.service_choice_name.empty()) {
            bacnet_service_counts_[bf.npdu.apdu.service_choice_name]++;
        }
    }
    if (p.protocol == "hartip" && p.result) {
        const HartIpFrame& frame = p.result->as<HartIpResult>().first;
        hartip_message_type_counts_[frame.message_type_name]++;
        if (frame.has_pass_through) {
            std::string key = std::to_string(static_cast<unsigned>(frame.pass_through.command));
            if (!frame.pass_through.command_name.empty()) key += " (" + frame.pass_through.command_name + ")";
            hartip_command_counts_[key]++;
        }
    }
    if (p.protocol == "opcua" && p.result) {
        const OpcUaMessage& m = p.result->as<OpcUaResult>().first;
        opcua_message_type_counts_[m.message_type]++;
        if (m.service_recognized) {
            opcua_service_counts_[m.service_name]++;
        }
    }
    if (p.protocol == "mms" && p.result) {
        const MmsFrame& mf = p.result->as<MmsFrame>();
        if (mf.has_pdu) mms_pdu_counts_[mf.pdu_name]++;
        if (mf.service_recognized) mms_service_counts_[mf.service_name]++;
    }
    if (p.protocol == "mqtt" && p.result) {
        const MqttMessage& m = p.result->as<MqttResult>().first;
        mqtt_packet_type_counts_[m.packet_type_name]++;
        if (m.is_sparkplug) {
            mqtt_sparkplug_count_++;
            mqtt_sparkplug_message_type_counts_[m.sparkplug_message_type]++;
        }
    }
    if (p.protocol == "s7comm-plus") {
        s7plus_pdu_type_counts_[p.s7plus_pdu_type_name]++;
        if (p.s7plus_has_function) {
            s7plus_function_counts_[p.s7plus_function_name]++;
            if (p.s7plus_body_decoded) s7plus_body_decoded_count_++;
        }
    }
    if (p.protocol == "ffhse" && p.result) {
        const FfhseFrame& f = p.result->as<FfhseResult>().first;
        ffhse_protocol_counts_[f.header.protocol_name]++;
        if (f.recognized) {
            ffhse_message_counts_[f.message_name]++;
            if (f.body_decoded) ffhse_body_decoded_count_++;
        }
    }
    if ((p.protocol == "dns" || p.protocol == "mdns" || p.protocol == "llmnr") && p.result) {
        dns_family_opcode_counts_[p.protocol + " " + p.result->as<DnsMessage>().opcode_name]++;
    }
    if (p.protocol == "nbns" && p.result) {
        nbns_opcode_counts_[p.result->as<NbnsMessage>().opcode_name]++;
    }
    if (p.protocol == "doh" && p.result) {
        doh_provider_counts_[p.result->as<DohDetection>().matched_provider]++;
    }
    if (p.protocol == "winrm" && p.result) {
        const WinRmMessage& wm = p.result->as<WinRmMessage>();
        if (!wm.is_response && !wm.wsa_action_name.empty()) {
            winrm_action_counts_[wm.wsa_action_name]++;
        }
    }
    if (p.protocol == "dcom" && p.result) {
        for (const DcomCall& dc : p.result->as<DcomMessage>().calls) {
            if (!dc.is_response) dcom_call_counts_[dc.interface_name + " " + dc.opnum_name]++;
        }
    }
    if (p.protocol == "ge-srtp" && p.result) {
        const GeSrtpFrame& gf = p.result->as<GeSrtpFrame>();
        if (!gf.is_response && gf.has_service_request) {
            ge_srtp_service_counts_[gf.service_request_name]++;
        }
        if (gf.is_response && gf.matched_to_request) ge_srtp_paired_responses_++;
    }
    if (p.protocol == "bsap" && p.result) {
        const BsapFrame& bf = p.result->as<BsapFrame>();
        if (bf.is_serial_tunnel) {
            bsap_serial_tunnel_count_++;
            if (bf.dfun_raw == 0x95 || bf.sfun_raw == 0x95) bsap_nak_count_++;
        } else {
            bsap_ip_native_count_++;
        }
    }
    if (p.protocol == "cclink-ie" && p.result) {
        const CclinkIeFrame& cf = p.result->as<CclinkIeFrame>();
        switch (cf.kind) {
            case CclinkIeMessageKind::CyclicRequest:
                cclink_ie_cyclic_request_count_++;
                break;
            case CclinkIeMessageKind::CyclicResponse:
                cclink_ie_cyclic_response_count_++;
                if (cf.end_code != 0) cclink_ie_cyclic_error_count_++;
                break;
            case CclinkIeMessageKind::NodeSearchRequest:
            case CclinkIeMessageKind::NodeSearchResponse:
                cclink_ie_node_search_count_++;
                break;
            case CclinkIeMessageKind::SetIpAddressRequest:
            case CclinkIeMessageKind::SetIpAddressResponse:
                cclink_ie_set_ip_address_count_++;
                break;
        }
    }
    if (p.protocol == "rip" && p.result) {
        rip_command_counts_[p.result->as<RipMessage>().command_name]++;
    }
    if (p.protocol == "icmp" && p.result) {
        icmp_type_counts_[p.result->as<IcmpMessage>().type_name]++;
    }
    if (p.protocol == "igmp" && p.result) {
        igmp_type_counts_[p.result->as<IgmpMessage>().type_name]++;
    }
    if (p.protocol == "vrrp" && p.result) {
        vrrp_version_counts_["VRRPv" + std::to_string(p.result->as<VrrpMessage>().version)]++;
    }
    if (p.protocol == "hsrp" && p.result) {
        hsrp_version_counts_["HSRPv" + std::to_string(p.result->as<HsrpMessage>().version)]++;
    }
    if (p.protocol == "igrp" && p.result) {
        igrp_opcode_counts_[p.result->as<IgrpMessage>().opcode_name]++;
    }
    if (p.protocol == "pim" && p.result) {
        pim_type_counts_[p.result->as<PimMessage>().type_name]++;
    }
    if (p.protocol == "eigrp" && p.result) {
        eigrp_opcode_counts_[p.result->as<EigrpMessage>().opcode_name]++;
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
    if (!twincat_command_counts_.empty()) {
        out << "twincat/ads command ids:\n";
        for (const auto& [name, count] : twincat_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "twincat responses authoritatively paired (invoke id, not heuristic): "
            << twincat_paired_responses_ << "\n";
    }
    if (!melsec_command_counts_.empty()) {
        out << "melsec/mc protocol command names:\n";
        for (const auto& [name, count] : melsec_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "melsec responses matched to their own session's outstanding request (not "
               "authoritative -- no unique transaction ID on the wire): "
            << melsec_matched_responses_ << "\n";
    }
    if (!fins_command_counts_.empty()) {
        out << "fins (omron) command names:\n";
        for (const auto& [name, count] : fins_command_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "fins responses matched to their own session's outstanding request (not "
               "authoritative -- no unique transaction ID on the wire): "
            << fins_matched_responses_ << "\n";
    }
    if (!kerberos_error_counts_.empty()) {
        out << "kerberos krb-error codes:\n";
        for (const auto& [name, count] : kerberos_error_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!ldap_result_code_counts_.empty()) {
        out << "ldap resultcode counts:\n";
        for (const auto& [name, count] : ldap_result_code_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!smb_status_counts_.empty()) {
        out << "smb session_setup status counts:\n";
        for (const auto& [name, count] : smb_status_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!netlogon_opnum_counts_.empty()) {
        out << "netlogon opnum counts:\n";
        for (const auto& [name, count] : netlogon_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!samr_opnum_counts_.empty()) {
        out << "samr opnum counts:\n";
        for (const auto& [name, count] : samr_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!lsarpc_opnum_counts_.empty()) {
        out << "lsarpc opnum counts:\n";
        for (const auto& [name, count] : lsarpc_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!srvsvc_opnum_counts_.empty()) {
        out << "srvsvc opnum counts:\n";
        for (const auto& [name, count] : srvsvc_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!wkssvc_opnum_counts_.empty()) {
        out << "wkssvc opnum counts:\n";
        for (const auto& [name, count] : wkssvc_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!drsuapi_opnum_counts_.empty()) {
        out << "drsuapi opnum counts:\n";
        for (const auto& [name, count] : drsuapi_opnum_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
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
    if (!winrm_action_counts_.empty()) {
        out << "winrm action counts:\n";
        for (const auto& [name, count] : winrm_action_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!dcom_call_counts_.empty()) {
        out << "dcom activation counts:\n";
        for (const auto& [name, count] : dcom_call_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
    }
    if (!ge_srtp_service_counts_.empty()) {
        out << "ge srtp service request names:\n";
        for (const auto& [name, count] : ge_srtp_service_counts_) {
            out << "  " << std::left << std::setw(40) << name << count << "\n";
        }
        out << "ge srtp responses authoritatively paired (sequence number, not heuristic): "
            << ge_srtp_paired_responses_ << "\n";
    }
    if (bsap_serial_tunnel_count_ > 0 || bsap_ip_native_count_ > 0) {
        out << "bsap serial-tunneled messages: " << bsap_serial_tunnel_count_ << "\n";
        out << "bsap-ip-native messages: " << bsap_ip_native_count_ << "\n";
        out << "bsap link-layer NAKs observed: " << bsap_nak_count_ << "\n";
    }
    if (cclink_ie_cyclic_request_count_ > 0 || cclink_ie_cyclic_response_count_ > 0 ||
        cclink_ie_node_search_count_ > 0 || cclink_ie_set_ip_address_count_ > 0) {
        out << "cclink-ie cyclic requests: " << cclink_ie_cyclic_request_count_ << "\n";
        out << "cclink-ie cyclic responses: " << cclink_ie_cyclic_response_count_ << "\n";
        out << "cclink-ie cyclic responses with non-success end code: "
            << cclink_ie_cyclic_error_count_ << "\n";
        out << "cclink-ie node search messages: " << cclink_ie_node_search_count_ << "\n";
        out << "cclink-ie set IP address messages: " << cclink_ie_set_ip_address_count_ << "\n";
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
