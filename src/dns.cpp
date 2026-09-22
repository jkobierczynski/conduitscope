// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/dns.hpp"

#include "conduitscope/resource_limits.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Name tables -- see dns.hpp's file header comment for sourcing (RFC 1035 section 3.2.2/3.2.3
// plus the later RFCs that registered AAAA/SRV/DNSSEC/SVCB-family types).

std::string opcode_name(uint8_t v) {
    switch (v) {
        case 0: return "Query";
        case 1: return "IQuery";       // RFC 1035, obsoleted by RFC 3425 but still a named value
        case 2: return "Status";
        case 4: return "Notify";       // RFC 1996
        case 5: return "Update";       // RFC 2136
        case 6: return "DSO";          // RFC 8490 (DNS Stateful Operations)
        default: return "reserved(" + std::to_string(v) + ")";
    }
}

// Opcodes this decoder treats as plausible enough to pass the detection gate -- see dns.hpp's
// file header comment's "Detection" paragraph. 3 has never been assigned; DSO(6) is TCP-only in
// practice (it manages a persistent connection) so this decoder, UDP-only, is unlikely to ever
// legitimately see it, but it's still a defined value, not obviously bogus -- included rather
// than rejected.
bool opcode_plausible(uint8_t v) { return v <= 2 || v == 4 || v == 5 || v == 6; }

std::string rcode_name(uint8_t v) {
    switch (v) {
        case 0: return "NoError";
        case 1: return "FormErr";
        case 2: return "ServFail";
        case 3: return "NXDomain";
        case 4: return "NotImp";
        case 5: return "Refused";
        case 6: return "YXDomain";   // RFC 2136
        case 7: return "YXRRSet";    // RFC 2136
        case 8: return "NXRRSet";    // RFC 2136
        case 9: return "NotAuth";    // RFC 2136 / RFC 8945
        case 10: return "NotZone";   // RFC 2136
        case 11: return "DSOTYPENI"; // RFC 8490
        default: return "reserved(" + std::to_string(v) + ")";
    }
}

std::string class_name(uint16_t v) {
    switch (v) {
        case 1: return "IN";
        case 2: return "CS";
        case 3: return "CH";
        case 4: return "HS";
        case 254: return "NONE";
        case 255: return "ANY";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// RR type table -- RFC 1035 3.2.2/3.2.3 plus the later RFCs each type was actually defined in
// (noted inline). Includes several types this decoder never value-decodes (see dns.hpp's "first
// pass" scope): naming every type seen is still useful even when its RDATA is shown as hex only.
std::string type_name(uint16_t v) {
    switch (v) {
        case 1: return "A";
        case 2: return "NS";
        case 3: return "MD";
        case 4: return "MF";
        case 5: return "CNAME";
        case 6: return "SOA";
        case 7: return "MB";
        case 8: return "MG";
        case 9: return "MR";
        case 10: return "NULL";
        case 11: return "WKS";
        case 12: return "PTR";
        case 13: return "HINFO";
        case 14: return "MINFO";
        case 15: return "MX";
        case 16: return "TXT";
        case 17: return "RP";
        case 18: return "AFSDB";
        case 24: return "SIG";         // RFC 2535
        case 25: return "KEY";         // RFC 2535
        case 28: return "AAAA";        // RFC 3596
        case 29: return "LOC";         // RFC 1876
        case 33: return "SRV";         // RFC 2782
        case 35: return "NAPTR";       // RFC 3403
        case 36: return "KX";          // RFC 2230
        case 37: return "CERT";        // RFC 4398
        case 39: return "DNAME";       // RFC 6672
        case 41: return "OPT";         // RFC 6891 (EDNS0 pseudo-RR)
        case 43: return "DS";          // RFC 4034
        case 44: return "SSHFP";       // RFC 4255
        case 45: return "IPSECKEY";    // RFC 4025
        case 46: return "RRSIG";       // RFC 4034
        case 47: return "NSEC";        // RFC 4034
        case 48: return "DNSKEY";      // RFC 4034
        case 50: return "NSEC3";       // RFC 5155
        case 51: return "NSEC3PARAM";  // RFC 5155
        case 52: return "TLSA";        // RFC 6698
        case 64: return "SVCB";        // RFC 9460
        case 65: return "HTTPS";       // RFC 9460
        case 99: return "SPF";         // RFC 4408 (obsoleted, but still seen on the wire)
        case 252: return "AXFR";
        case 253: return "MAILB";
        case 254: return "MAILA";
        case 255: return "ANY";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

std::string hex_or_empty(ByteSpan span) { return span.empty() ? std::string() : to_hex(span, ""); }

// ------------------------------------------------------------------------------------------
// Name decompression (RFC 1035 4.1.4). `message` is the WHOLE payload (compression pointers are
// offsets from its start, not from the name's own start), `offset` is where this name begins.
// Returns the decoded dot-joined name (root name as ".") and how many bytes were consumed from
// `offset` in the ORIGINAL, non-followed stream -- once a pointer is taken, only that pointer's
// own 2 bytes count toward the caller's advance, per RFC 1035 4.1.4's own worked example.
struct DnsNameResult {
    std::string name;
    size_t bytes_consumed = 0;
};

// CLI-configurable via --max-recursion-depth -- see resource_limits.hpp (folded in as the
// closest fit among the five categories for a pointer-following loop guard, the same role a
// recursion-depth cap plays elsewhere; see docs/DEVELOPMENT.md's item 7 "Update: implemented"
// entry). 0/unset keeps the literal 128 default -- loop/decompression-bomb guard, not itself an
// RFC value.
size_t max_name_pointer_hops() { return resource_limits().max_recursion_depth.value_or(128); }

std::optional<DnsNameResult> read_dns_name(ByteSpan message, size_t offset) {
    std::string name;
    size_t pos = offset;
    size_t consumed = 0;
    bool jumped = false;
    size_t hops = 0;
    while (true) {
        if (pos >= message.size()) return std::nullopt;
        uint8_t len = message.at(pos);
        if ((len & 0xC0) == 0xC0) {
            if (pos + 1 >= message.size()) return std::nullopt;
            uint16_t ptr = static_cast<uint16_t>(((len & 0x3F) << 8) | message.at(pos + 1));
            if (!jumped) {
                consumed = (pos - offset) + 2;
                jumped = true;
            }
            if (++hops > max_name_pointer_hops()) return std::nullopt;
            if (ptr >= message.size()) return std::nullopt;
            pos = ptr;
            continue;
        }
        if ((len & 0xC0) != 0) return std::nullopt;  // 01/10 top bits are reserved, not a label length
        if (len == 0) {
            pos += 1;
            if (!jumped) consumed = pos - offset;
            break;
        }
        if (pos + 1 + len > message.size()) return std::nullopt;
        if (!name.empty()) name += '.';
        for (size_t i = 0; i < len; ++i) name += static_cast<char>(message.at(pos + 1 + i));
        pos += 1 + len;
        if (!jumped) consumed = pos - offset;
    }
    if (name.empty()) name = ".";
    return DnsNameResult{name, consumed};
}

// ------------------------------------------------------------------------------------------
// RDATA "first pass" decode -- see dns.hpp's file header comment for the exact type list and
// sourcing. `message`/`rdata_offset` are needed (not just the RDATA bytes themselves) because
// NS/CNAME/PTR/MX/SOA/SRV names inside RDATA can themselves be compression pointers referencing
// elsewhere in the whole message.
bool decode_rdata(ByteSpan message, size_t rdata_offset, uint16_t rdlength, uint16_t rtype,
                   std::vector<std::string>& values) {
    ByteSpan rdata = message.subspan(rdata_offset, rdlength);
    switch (rtype) {
        case 1: {  // A
            if (rdlength != 4) return false;
            std::ostringstream s;
            s << static_cast<unsigned>(rdata.at(0)) << "." << static_cast<unsigned>(rdata.at(1)) << "."
              << static_cast<unsigned>(rdata.at(2)) << "." << static_cast<unsigned>(rdata.at(3));
            values.push_back("address=" + s.str());
            return true;
        }
        case 28: {  // AAAA
            if (rdlength != 16) return false;
            std::ostringstream s;
            s << std::hex;
            for (int i = 0; i < 16; i += 2) {
                if (i != 0) s << ":";
                s << ((static_cast<unsigned>(rdata.at(i)) << 8) | rdata.at(i + 1));
            }
            values.push_back("address=" + s.str());
            return true;
        }
        case 2:   // NS
        case 5:   // CNAME
        case 12: {  // PTR
            auto n = read_dns_name(message, rdata_offset);
            if (!n) return false;
            values.push_back((rtype == 2 ? "nsdname=" : rtype == 5 ? "cname=" : "ptrdname=") + n->name);
            return true;
        }
        case 15: {  // MX
            if (rdlength < 3) return false;
            uint16_t preference = static_cast<uint16_t>((rdata.at(0) << 8) | rdata.at(1));
            auto n = read_dns_name(message, rdata_offset + 2);
            if (!n) return false;
            values.push_back("preference=" + std::to_string(preference));
            values.push_back("exchange=" + n->name);
            return true;
        }
        case 6: {  // SOA
            auto mname = read_dns_name(message, rdata_offset);
            if (!mname) return false;
            auto rname = read_dns_name(message, rdata_offset + mname->bytes_consumed);
            if (!rname) return false;
            size_t tail = rdata_offset + mname->bytes_consumed + rname->bytes_consumed;
            if (tail + 20 > message.size()) return false;
            uint32_t serial = static_cast<uint32_t>((message.at(tail) << 24) | (message.at(tail + 1) << 16) |
                                                      (message.at(tail + 2) << 8) | message.at(tail + 3));
            uint32_t refresh = static_cast<uint32_t>((message.at(tail + 4) << 24) | (message.at(tail + 5) << 16) |
                                                       (message.at(tail + 6) << 8) | message.at(tail + 7));
            uint32_t retry = static_cast<uint32_t>((message.at(tail + 8) << 24) | (message.at(tail + 9) << 16) |
                                                     (message.at(tail + 10) << 8) | message.at(tail + 11));
            uint32_t expire = static_cast<uint32_t>((message.at(tail + 12) << 24) | (message.at(tail + 13) << 16) |
                                                      (message.at(tail + 14) << 8) | message.at(tail + 15));
            uint32_t minimum = static_cast<uint32_t>((message.at(tail + 16) << 24) | (message.at(tail + 17) << 16) |
                                                       (message.at(tail + 18) << 8) | message.at(tail + 19));
            values.push_back("mname=" + mname->name);
            values.push_back("rname=" + rname->name);
            values.push_back("serial=" + std::to_string(serial));
            values.push_back("refresh=" + std::to_string(refresh) + "s");
            values.push_back("retry=" + std::to_string(retry) + "s");
            values.push_back("expire=" + std::to_string(expire) + "s");
            values.push_back("minimum=" + std::to_string(minimum) + "s");
            return true;
        }
        case 16: {  // TXT -- one or more length-prefixed character-strings
            size_t pos = 0;
            std::vector<std::string> strings;
            while (pos < rdata.size()) {
                uint8_t slen = rdata.at(pos);
                if (pos + 1 + slen > rdata.size()) return false;
                strings.emplace_back(reinterpret_cast<const char*>(rdata.data() + pos + 1), slen);
                pos += 1 + slen;
            }
            for (size_t i = 0; i < strings.size(); ++i) {
                values.push_back("txt[" + std::to_string(i) + "]=" + strings[i]);
            }
            if (strings.empty()) values.push_back("txt=(empty)");
            return true;
        }
        case 33: {  // SRV
            if (rdlength < 7) return false;
            uint16_t priority = static_cast<uint16_t>((rdata.at(0) << 8) | rdata.at(1));
            uint16_t weight = static_cast<uint16_t>((rdata.at(2) << 8) | rdata.at(3));
            uint16_t port = static_cast<uint16_t>((rdata.at(4) << 8) | rdata.at(5));
            auto target = read_dns_name(message, rdata_offset + 6);
            if (!target) return false;
            values.push_back("priority=" + std::to_string(priority));
            values.push_back("weight=" + std::to_string(weight));
            values.push_back("port=" + std::to_string(port));
            values.push_back("target=" + target->name);
            return true;
        }
        default:
            return false;
    }
}

}  // namespace

std::optional<DnsMessage> try_parse_dns_message(ByteSpan payload, DnsFlavor flavor) {
    if (payload.size() < 12) return std::nullopt;
    try {

    DnsMessage msg;
    msg.flavor = flavor;
    msg.transaction_id = static_cast<uint16_t>((payload.at(0) << 8) | payload.at(1));

    uint16_t word2 = static_cast<uint16_t>((payload.at(2) << 8) | payload.at(3));
    msg.is_response = (word2 & 0x8000) != 0;
    msg.opcode = static_cast<uint8_t>((word2 >> 11) & 0x0F);
    if (!opcode_plausible(msg.opcode)) return std::nullopt;
    msg.opcode_name = opcode_name(msg.opcode);
    msg.rcode = static_cast<uint8_t>(word2 & 0x0F);
    msg.rcode_name = rcode_name(msg.rcode);

    std::vector<std::string> flags;
    if (flavor == DnsFlavor::Llmnr) {
        bool c = (word2 & 0x0400) != 0;
        bool tc = (word2 & 0x0200) != 0;
        bool t = (word2 & 0x0100) != 0;
        uint8_t z = static_cast<uint8_t>((word2 >> 4) & 0x0F);
        if (c) flags.push_back("C");
        if (tc) flags.push_back("TC");
        if (t) flags.push_back("T");
        msg.reserved_bits_nonzero = z != 0;
        // RFC 4795 2.1.1: "the sender MUST set [these bits] to zero" -- treated as part of the
        // detection gate for LLMNR specifically (see dns.hpp's file header "Detection" paragraph),
        // unlike DNS/mDNS's own reserved Z bits, which are merely noted (many real DNS resolvers
        // are laxer about this than the RFC asks).
        if (msg.reserved_bits_nonzero) return std::nullopt;
    } else {
        bool aa = (word2 & 0x0400) != 0;
        bool tc = (word2 & 0x0200) != 0;
        bool rd = (word2 & 0x0100) != 0;
        bool ra = (word2 & 0x0080) != 0;
        uint8_t z = static_cast<uint8_t>((word2 >> 4) & 0x07);
        if (aa) flags.push_back("AA");
        if (tc) flags.push_back("TC");
        if (rd) flags.push_back("RD");
        if (ra) flags.push_back("RA");
        msg.reserved_bits_nonzero = z != 0;
    }
    for (size_t i = 0; i < flags.size(); ++i) {
        if (i != 0) msg.header_flags += ",";
        msg.header_flags += flags[i];
    }

    msg.qdcount = static_cast<uint16_t>((payload.at(4) << 8) | payload.at(5));
    msg.ancount = static_cast<uint16_t>((payload.at(6) << 8) | payload.at(7));
    msg.nscount = static_cast<uint16_t>((payload.at(8) << 8) | payload.at(9));
    msg.arcount = static_cast<uint16_t>((payload.at(10) << 8) | payload.at(11));

    // Structural sanity gate (see dns.hpp's file header "Detection" paragraph): the smallest
    // possible question is a 1-byte root name + QTYPE(2) + QCLASS(2) = 5 bytes; the smallest
    // possible RR is a 1-byte root name + TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2) + 0-byte RDATA
    // = 11 bytes. If the declared counts can't possibly fit even that minimum in the bytes
    // actually present, this isn't a DNS-family message (or is hopelessly truncated) -- reject
    // rather than attempt a parse that will fail messily partway through anyway.
    size_t min_needed = 12 + static_cast<size_t>(msg.qdcount) * 5 +
                         (static_cast<size_t>(msg.ancount) + msg.nscount + msg.arcount) * 11;
    if (min_needed > payload.size()) return std::nullopt;

    size_t pos = 12;
    auto parse_question = [&](DnsQuestionEntry& q) -> bool {
        auto n = read_dns_name(payload, pos);
        if (!n) return false;
        pos += n->bytes_consumed;
        if (pos + 4 > payload.size()) return false;
        q.name = n->name;
        q.qtype = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
        q.qtype_name = type_name(q.qtype);
        uint16_t raw_class = static_cast<uint16_t>((payload.at(pos + 2) << 8) | payload.at(pos + 3));
        pos += 4;
        if (flavor == DnsFlavor::Mdns && (raw_class & 0x8000)) {
            q.unicast_response_requested = true;
            raw_class &= 0x7FFF;
        }
        q.qclass = raw_class;
        q.qclass_name = class_name(raw_class);
        std::ostringstream s;
        s << "question: " << q.name << " " << q.qtype_name << " " << q.qclass_name;
        if (q.unicast_response_requested) s << " (QU)";
        q.summary = s.str();
        return true;
    };

    for (uint16_t i = 0; i < msg.qdcount; ++i) {
        DnsQuestionEntry q;
        if (!parse_question(q)) {
            msg.records_truncated = true;
            msg.notes.push_back("stopped parsing the question section after " + std::to_string(i) +
                                 " of " + std::to_string(msg.qdcount) +
                                 " declared question(s) -- truncated or malformed");
            break;
        }
        msg.questions.push_back(std::move(q));
    }

    auto parse_rr = [&](const char* section, DnsResourceRecordEntry& rr) -> bool {
        auto n = read_dns_name(payload, pos);
        if (!n) return false;
        pos += n->bytes_consumed;
        if (pos + 10 > payload.size()) return false;
        rr.name = n->name;
        rr.rtype = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
        rr.rtype_name = type_name(rr.rtype);
        rr.is_opt_pseudo_record = rr.rtype == 41;
        uint16_t raw_class = static_cast<uint16_t>((payload.at(pos + 2) << 8) | payload.at(pos + 3));
        uint32_t raw_ttl = static_cast<uint32_t>((payload.at(pos + 4) << 24) | (payload.at(pos + 5) << 16) |
                                                  (payload.at(pos + 6) << 8) | payload.at(pos + 7));
        pos += 8;
        rr.rdlength = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
        pos += 2;
        if (pos + rr.rdlength > payload.size()) return false;

        std::ostringstream s;
        s << section << ": " << rr.name << " " << rr.rtype_name << " ";
        if (rr.is_opt_pseudo_record) {
            rr.rclass = raw_class;  // requestor's UDP payload size, not a class code
            rr.ttl = raw_ttl;
            rr.opt_extended_rcode = static_cast<uint8_t>((raw_ttl >> 24) & 0xFF);
            rr.opt_version = static_cast<uint8_t>((raw_ttl >> 16) & 0xFF);
            rr.opt_dnssec_ok = (raw_ttl & 0x00008000) != 0;
            s << "udp-payload-size=" << rr.rclass << " extended-rcode=" << static_cast<unsigned>(rr.opt_extended_rcode)
              << " version=" << static_cast<unsigned>(rr.opt_version) << (rr.opt_dnssec_ok ? " DO" : "");
        } else {
            if (flavor == DnsFlavor::Mdns && (raw_class & 0x8000)) {
                rr.cache_flush = true;
                raw_class &= 0x7FFF;
            }
            rr.rclass = raw_class;
            rr.rclass_name = class_name(raw_class);
            rr.ttl = raw_ttl;
            s << rr.rclass_name << " ttl=" << rr.ttl << "s" << (rr.cache_flush ? " (cache-flush)" : "");
        }

        rr.rdata_hex = hex_or_empty(payload.subspan(pos, rr.rdlength));
        if (!rr.is_opt_pseudo_record) {
            rr.rdata_decoded = decode_rdata(payload, pos, rr.rdlength, rr.rtype, rr.values);
            if (rr.rdata_decoded) {
                s << " ->";
                for (const auto& v : rr.values) s << " " << v;
            }
        }
        pos += rr.rdlength;
        rr.summary = s.str();
        return true;
    };

    auto parse_section = [&](const char* section, uint16_t count, std::vector<DnsResourceRecordEntry>& out_vec) {
        for (uint16_t i = 0; i < count; ++i) {
            DnsResourceRecordEntry rr;
            if (!parse_rr(section, rr)) {
                msg.records_truncated = true;
                msg.notes.push_back(std::string("stopped parsing the ") + section + " section after " +
                                     std::to_string(i) + " of " + std::to_string(count) +
                                     " declared record(s) -- truncated or malformed");
                return;
            }
            out_vec.push_back(std::move(rr));
        }
    };
    if (!msg.records_truncated) parse_section("answer", msg.ancount, msg.answers);
    if (!msg.records_truncated) parse_section("authority", msg.nscount, msg.authorities);
    if (!msg.records_truncated) parse_section("additional", msg.arcount, msg.additionals);

    std::ostringstream s;
    const char* flavor_name = flavor == DnsFlavor::Dns ? "DNS" : flavor == DnsFlavor::Mdns ? "mDNS" : "LLMNR";
    s << flavor_name << " " << (msg.is_response ? "response" : "query") << " id=0x" << std::hex << std::uppercase
      << std::setfill('0') << std::setw(4) << msg.transaction_id << std::dec << std::nouppercase << " "
      << msg.opcode_name;
    if (msg.is_response) s << " " << msg.rcode_name;
    if (!msg.header_flags.empty()) s << " [" << msg.header_flags << "]";
    s << ", " << msg.questions.size() << " question(s), " << msg.answers.size() << " answer(s), "
      << msg.authorities.size() << " authority(-ies), " << msg.additionals.size() << " additional(s)";
    if (!msg.questions.empty()) s << " -- " << msg.questions.front().name;
    else if (!msg.answers.empty()) s << " -- " << msg.answers.front().name;
    msg.summary = s.str();

    return msg;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

}  // namespace conduitscope
