// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/dhcpv6.hpp"

#include "conduitscope/ipv6.hpp"
#include "conduitscope/resource_limits.hpp"

#include <sstream>

namespace conduitscope {

namespace {

enum Dhcpv6MessageType : uint8_t {
    DHCPV6_SOLICIT = 1,
    DHCPV6_ADVERTISE = 2,
    DHCPV6_REQUEST = 3,
    DHCPV6_CONFIRM = 4,
    DHCPV6_RENEW = 5,
    DHCPV6_REBIND = 6,
    DHCPV6_REPLY = 7,
    DHCPV6_RELEASE = 8,
    DHCPV6_DECLINE = 9,
    DHCPV6_RECONFIGURE = 10,
    DHCPV6_INFORMATION_REQUEST = 11,
    DHCPV6_RELAY_FORW = 12,
    DHCPV6_RELAY_REPL = 13,
};

enum Dhcpv6OptionCode : uint16_t {
    DHCPV6_OPT_CLIENTID = 1,
    DHCPV6_OPT_SERVERID = 2,
    DHCPV6_OPT_IA_NA = 3,
    DHCPV6_OPT_IA_TA = 4,
    DHCPV6_OPT_IAADDR = 5,
    DHCPV6_OPT_ORO = 6,
    DHCPV6_OPT_ELAPSED_TIME = 8,
    DHCPV6_OPT_RELAY_MSG = 9,
    DHCPV6_OPT_STATUS_CODE = 13,
    DHCPV6_OPT_RAPID_COMMIT = 14,
    DHCPV6_OPT_IA_PD = 25,
    DHCPV6_OPT_IAPREFIX = 26,
};

// CLI-configurable via --max-decoded-objects -- same convention as icmpv6.cpp's own max_options.
size_t max_options() { return resource_limits().max_decoded_objects.value_or(50); }

std::string msg_type_name(uint8_t t) {
    switch (t) {
        case DHCPV6_SOLICIT: return "SOLICIT";
        case DHCPV6_ADVERTISE: return "ADVERTISE";
        case DHCPV6_REQUEST: return "REQUEST";
        case DHCPV6_CONFIRM: return "CONFIRM";
        case DHCPV6_RENEW: return "RENEW";
        case DHCPV6_REBIND: return "REBIND";
        case DHCPV6_REPLY: return "REPLY";
        case DHCPV6_RELEASE: return "RELEASE";
        case DHCPV6_DECLINE: return "DECLINE";
        case DHCPV6_RECONFIGURE: return "RECONFIGURE";
        case DHCPV6_INFORMATION_REQUEST: return "INFORMATION-REQUEST";
        case DHCPV6_RELAY_FORW: return "RELAY-FORW";
        case DHCPV6_RELAY_REPL: return "RELAY-REPL";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(t)) + ")";
    }
}

std::string option_code_name(uint16_t code) {
    switch (code) {
        case DHCPV6_OPT_CLIENTID: return "Client Identifier";
        case DHCPV6_OPT_SERVERID: return "Server Identifier";
        case DHCPV6_OPT_IA_NA: return "IA_NA";
        case DHCPV6_OPT_IA_TA: return "IA_TA";
        case DHCPV6_OPT_IAADDR: return "IA Address";
        case DHCPV6_OPT_ORO: return "Option Request";
        case DHCPV6_OPT_ELAPSED_TIME: return "Elapsed Time";
        case DHCPV6_OPT_RELAY_MSG: return "Relay Message";
        case DHCPV6_OPT_STATUS_CODE: return "Status Code";
        case DHCPV6_OPT_RAPID_COMMIT: return "Rapid Commit";
        case DHCPV6_OPT_IA_PD: return "IA_PD";
        case DHCPV6_OPT_IAPREFIX: return "IA Prefix";
        default: return "DHCPv6 option code " + std::to_string(static_cast<unsigned>(code));
    }
}

std::string status_name(uint16_t code) {
    switch (code) {
        case 0: return "Success";
        case 1: return "UnspecFail";
        case 2: return "NoAddrsAvail";
        case 3: return "NoBinding";
        case 4: return "NotOnLink";
        case 5: return "UseMulticast";
        case 6: return "NoPrefixAvail";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(code)) + ")";
    }
}

std::string duid_type_name(uint16_t t) {
    switch (t) {
        case 1: return "DUID-LLT";
        case 2: return "DUID-EN";
        case 3: return "DUID-LL";
        case 4: return "DUID-UUID";
        default: return "Unknown (" + std::to_string(static_cast<unsigned>(t)) + ")";
    }
}

std::string to_hex_string(const std::vector<uint8_t>& bytes) {
    static const char* kDigits = "0123456789abcdef";
    std::string out;
    out.reserve(bytes.size() * 2);
    for (uint8_t b : bytes) {
        out.push_back(kDigits[b >> 4]);
        out.push_back(kDigits[b & 0x0F]);
    }
    return out;
}

// RFC 4122 canonical 8-4-4-4-12 hex grouping -- no existing UUID formatter elsewhere in this
// codebase to reuse (checked before adding this), so a small local one lives here rather than
// pulling in a dependency for a 16-byte display-only nicety.
std::string format_uuid(ByteSpan bytes /* exactly 16 */) {
    std::vector<uint8_t> v = bytes.to_vector();
    std::string hex = to_hex_string(v);
    std::ostringstream out;
    out << hex.substr(0, 8) << "-" << hex.substr(8, 4) << "-" << hex.substr(12, 4) << "-"
        << hex.substr(16, 4) << "-" << hex.substr(20, 12);
    return out.str();
}

// RFC 8415 11 -- see dhcpv6.hpp's own DUID FORMATS section for the byte layout of each type.
Dhcpv6Duid parse_duid(ByteSpan span) {
    Dhcpv6Duid d;
    d.raw = span.to_vector();
    if (span.size() < 2) {
        d.type_name = "malformed (too short for a DUID-Type field)";
        d.display = d.type_name;
        return d;
    }
    Cursor c(span);
    d.duid_type = c.u16be();
    d.type_name = duid_type_name(d.duid_type);

    std::ostringstream disp;
    switch (d.duid_type) {
        case 1: {  // DUID-LLT
            if (c.remaining() >= 6) {
                d.hardware_type = c.u16be();
                d.time_raw = c.u32be();
                ByteSpan lla = c.rest();
                d.link_layer_address = lla.to_vector();
                disp << "DUID-LLT (hw-type=" << d.hardware_type << ", time=" << d.time_raw
                     << "s since 2000-01-01, lladdr=" << to_hex_string(d.link_layer_address) << ")";
            } else {
                disp << "DUID-LLT (truncated)";
            }
            break;
        }
        case 2: {  // DUID-EN
            if (c.remaining() >= 4) {
                d.enterprise_number = c.u32be();
                ByteSpan ident = c.rest();
                d.identifier = ident.to_vector();
                disp << "DUID-EN (enterprise=" << d.enterprise_number << ", identifier="
                     << d.identifier.size() << " byte(s))";
            } else {
                disp << "DUID-EN (truncated)";
            }
            break;
        }
        case 3: {  // DUID-LL
            if (c.remaining() >= 2) {
                d.hardware_type = c.u16be();
                ByteSpan lla = c.rest();
                d.link_layer_address = lla.to_vector();
                disp << "DUID-LL (hw-type=" << d.hardware_type << ", lladdr="
                     << to_hex_string(d.link_layer_address) << ")";
            } else {
                disp << "DUID-LL (truncated)";
            }
            break;
        }
        case 4: {  // DUID-UUID (RFC 6355) -- fixed 18 bytes total (2 + 16)
            if (c.remaining() >= 16) {
                d.uuid_string = format_uuid(c.bytes(16));
                disp << "DUID-UUID (" << d.uuid_string << ")";
            } else {
                disp << "DUID-UUID (truncated)";
            }
            break;
        }
        default:
            disp << d.type_name << " (" << (span.size() >= 2 ? span.size() - 2 : 0)
                 << " byte(s) of type-specific data)";
            break;
    }
    d.display = disp.str();
    return d;
}

void decode_dhcpv6_options(ByteSpan span, std::vector<Dhcpv6Option>& out,
                            std::vector<std::string>& notes, bool& truncated);

// IA_NA (3) / IA_TA (4) / IA_PD (25) share the same "fixed fields, then nested options" shape,
// just a different fixed-field prefix (IA_TA has no T1/T2). `fixed_field_bytes` is 12 for IA_NA/
// IA_PD, 4 for IA_TA.
struct IaCommon {
    uint32_t iaid = 0;
    uint32_t t1_sec = 0;  // 0 for IA_TA (no T1/T2 field on the wire at all)
    uint32_t t2_sec = 0;
    std::vector<Dhcpv6Option> options;
};

IaCommon parse_ia_common(ByteSpan data, bool has_t1_t2, std::vector<std::string>& notes,
                          bool& truncated) {
    IaCommon ia;
    Cursor c(data);
    size_t fixed = has_t1_t2 ? 12 : 4;
    if (data.size() < fixed) return ia;
    ia.iaid = c.u32be();
    if (has_t1_t2) {
        ia.t1_sec = c.u32be();
        ia.t2_sec = c.u32be();
    }
    decode_dhcpv6_options(c.rest(), ia.options, notes, truncated);
    return ia;
}

void decode_dhcpv6_options(ByteSpan span, std::vector<Dhcpv6Option>& out,
                            std::vector<std::string>& notes, bool& truncated) {
    Cursor c(span);
    while (c.remaining() >= 4) {
        uint16_t code = c.u16be();
        uint16_t len = c.u16be();
        if (len > c.remaining()) {
            notes.push_back("a DHCPv6 option (code " + std::to_string(code) +
                             ") declared a length that runs past the end of its container -- "
                             "stopped decoding options here");
            return;
        }
        if (out.size() >= max_options()) {
            truncated = true;
            notes.push_back("output capped at " + std::to_string(max_options()) +
                             " DHCPv6 option(s); more were present");
            return;
        }

        ByteSpan data = c.bytes(len);
        Dhcpv6Option opt;
        opt.code = code;
        opt.code_name = option_code_name(code);
        opt.data_length = len;

        switch (code) {
            case DHCPV6_OPT_CLIENTID:
            case DHCPV6_OPT_SERVERID:
                opt.duid = parse_duid(data);
                break;
            case DHCPV6_OPT_IA_NA: {
                IaCommon ia = parse_ia_common(data, /*has_t1_t2=*/true, notes, truncated);
                Dhcpv6IaNa v;
                v.iaid = ia.iaid;
                v.t1_sec = ia.t1_sec;
                v.t2_sec = ia.t2_sec;
                v.options = std::move(ia.options);
                opt.ia_na = std::move(v);
                break;
            }
            case DHCPV6_OPT_IA_TA: {
                IaCommon ia = parse_ia_common(data, /*has_t1_t2=*/false, notes, truncated);
                Dhcpv6IaTa v;
                v.iaid = ia.iaid;
                v.options = std::move(ia.options);
                opt.ia_ta = std::move(v);
                break;
            }
            case DHCPV6_OPT_IA_PD: {
                IaCommon ia = parse_ia_common(data, /*has_t1_t2=*/true, notes, truncated);
                Dhcpv6IaPd v;
                v.iaid = ia.iaid;
                v.t1_sec = ia.t1_sec;
                v.t2_sec = ia.t2_sec;
                v.options = std::move(ia.options);
                opt.ia_pd = std::move(v);
                break;
            }
            case DHCPV6_OPT_IAADDR: {
                if (data.size() >= 24) {
                    Cursor ic(data);
                    Dhcpv6IaAddress a;
                    ByteSpan addr_bytes = ic.bytes(16);
                    Ipv6Address addr{};
                    for (size_t i = 0; i < 16; ++i) addr[i] = addr_bytes.at(i);
                    a.address = format_ipv6(addr);
                    a.preferred_lifetime_sec = ic.u32be();
                    a.valid_lifetime_sec = ic.u32be();
                    decode_dhcpv6_options(ic.rest(), a.options, notes, truncated);
                    opt.ia_address = std::move(a);
                }
                break;
            }
            case DHCPV6_OPT_IAPREFIX: {
                // See dhcpv6.hpp's own [SECONDARY-SOURCE/UNCERTAIN] note on this 16-byte field.
                if (data.size() >= 25) {
                    Cursor ic(data);
                    Dhcpv6IaPrefix p;
                    p.preferred_lifetime_sec = ic.u32be();
                    p.valid_lifetime_sec = ic.u32be();
                    p.prefix_length = ic.u8();
                    ByteSpan prefix_rest = ic.rest();
                    Ipv6Address prefix_bytes{};
                    for (size_t i = 0; i < prefix_rest.size() && i < 16; ++i) {
                        prefix_bytes[i] = prefix_rest.at(i);
                    }
                    p.prefix = format_ipv6(prefix_bytes);
                    if (prefix_rest.size() > 16) {
                        Cursor pc(prefix_rest);
                        pc.skip(16);
                        decode_dhcpv6_options(pc.rest(), p.options, notes, truncated);
                    }
                    opt.ia_prefix = std::move(p);
                }
                break;
            }
            case DHCPV6_OPT_ORO: {
                Cursor oc(data);
                while (oc.remaining() >= 2) opt.oro_codes.push_back(oc.u16be());
                break;
            }
            case DHCPV6_OPT_ELAPSED_TIME: {
                if (data.size() == 2) {
                    Cursor ec(data);
                    opt.elapsed_time_centiseconds = ec.u16be();
                } else {
                    notes.push_back("Elapsed Time option has a non-standard length (" +
                                     std::to_string(data.size()) + " byte(s), RFC 8415 expects 2)");
                }
                break;
            }
            case DHCPV6_OPT_STATUS_CODE: {
                if (data.size() >= 2) {
                    Cursor sc(data);
                    Dhcpv6StatusCode s;
                    s.status_code = sc.u16be();
                    s.status_name = status_name(s.status_code);
                    ByteSpan msg = sc.rest();
                    s.status_message.assign(reinterpret_cast<const char*>(msg.data()), msg.size());
                    opt.status_code = std::move(s);
                }
                break;
            }
            case DHCPV6_OPT_RAPID_COMMIT: {
                opt.is_rapid_commit = true;
                if (data.size() != 0) {
                    notes.push_back("Rapid Commit option carries " + std::to_string(data.size()) +
                                     " byte(s) of data; RFC 8415 defines it as a zero-length flag");
                }
                break;
            }
            case DHCPV6_OPT_RELAY_MSG:
                // Structural only -- see dhcpv6.hpp's own OUT OF SCOPE section: the inner message
                // is not decoded through.
                opt.is_relay_message = true;
                break;
            default:
                break;  // name-only -- see dhcpv6.hpp's own file header
        }
        out.push_back(std::move(opt));
    }
}

}  // namespace

std::optional<Dhcpv6Message> try_parse_dhcpv6(ByteSpan udp_payload) {
    if (udp_payload.size() < 4) {
        return std::nullopt;
    }
    Cursor c(udp_payload);
    uint8_t type = c.u8();
    if (type == 0 || type > 13) {
        return std::nullopt;  // never assigned by RFC 8415 -- decoder.cpp's own port gate (546/547)
                               // is what actually keeps this from mis-firing on unrelated UDP
                               // traffic, same posture dns.hpp's own file header documents
    }

    Dhcpv6Message msg;
    msg.msg_type = type;
    msg.msg_type_name = msg_type_name(type);
    msg.is_relay = (type == DHCPV6_RELAY_FORW || type == DHCPV6_RELAY_REPL);

    std::ostringstream out;
    out << "DHCPv6 " << msg.msg_type_name;

    if (msg.is_relay) {
        if (udp_payload.size() < 34) {  // msg-type(1)+hop-count(1)+link-addr(16)+peer-addr(16)
            return std::nullopt;
        }
        msg.hop_count = c.u8();
        ByteSpan link_bytes = c.bytes(16);
        ByteSpan peer_bytes = c.bytes(16);
        Ipv6Address link_addr{}, peer_addr{};
        for (size_t i = 0; i < 16; ++i) {
            link_addr[i] = link_bytes.at(i);
            peer_addr[i] = peer_bytes.at(i);
        }
        msg.link_address = format_ipv6(link_addr);
        msg.peer_address = format_ipv6(peer_addr);
        decode_dhcpv6_options(c.rest(), msg.options, msg.notes, msg.options_truncated);
        out << ", hop-count=" << static_cast<unsigned>(msg.hop_count)
            << ", link-address=" << msg.link_address << ", peer-address=" << msg.peer_address;

        bool has_relay_msg = false;
        for (const auto& opt : msg.options) {
            if (opt.is_relay_message) has_relay_msg = true;
        }
        if (has_relay_msg) {
            out << " (Relay Message option present, inner message not decoded)";
        } else {
            msg.notes.push_back(
                "no Relay Message option (code 9) was present in this RELAY-FORW/RELAY-REPL "
                "message -- unusual but not itself a parse failure");
        }
    } else {
        // RFC 8415 8: transaction-id is a 3-byte field.
        uint32_t hi = c.u8();
        uint32_t mid = c.u8();
        uint32_t lo = c.u8();
        msg.transaction_id = (hi << 16) | (mid << 8) | lo;
        decode_dhcpv6_options(c.rest(), msg.options, msg.notes, msg.options_truncated);
        out << ", xid=0x" << std::hex << msg.transaction_id << std::dec;

        for (const auto& opt : msg.options) {
            if (opt.code == DHCPV6_OPT_CLIENTID && opt.duid) {
                msg.client_duid_key.assign(reinterpret_cast<const char*>(opt.duid->raw.data()),
                                            opt.duid->raw.size());
                out << ", client=" << opt.duid->display;
            }
            if (opt.code == DHCPV6_OPT_SERVERID && opt.duid) {
                msg.server_duid_key.assign(reinterpret_cast<const char*>(opt.duid->raw.data()),
                                            opt.duid->raw.size());
                out << ", server=" << opt.duid->display;
            }
            if (opt.status_code && opt.status_code->status_code != 0) {
                out << ", status=" << opt.status_code->status_name;
            }
            if (opt.is_rapid_commit) {
                out << ", Rapid Commit";
            }
        }
    }

    out << ", " << msg.options.size() << " option(s)";
    msg.summary = out.str();
    return msg;
}

std::optional<ProtocolResult> Dhcpv6Decoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto msg = try_parse_dhcpv6(payload)) {
        return ProtocolResult::make<Dhcpv6Message>("dhcpv6", std::move(*msg));
    }
    return std::nullopt;
}

const ProtocolDecoder& dhcpv6_decoder() {
    static const Dhcpv6Decoder instance;
    return instance;
}

}  // namespace conduitscope
