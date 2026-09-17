// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/nbns.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

std::string opcode_name(uint8_t v) {
    switch (v) {
        case 0: return "Query";
        case 5: return "Registration";
        case 6: return "Release";
        case 7: return "WACK";
        case 8: return "Refresh";
        default: return "reserved(" + std::to_string(v) + ")";
    }
}

std::string rcode_name(uint8_t v) {
    switch (v) {
        case 0: return "Success";
        case 1: return "FMT_ERR";
        case 2: return "SRV_ERR";
        case 3: return "NAM_ERR";
        case 4: return "IMP_ERR";
        case 5: return "RFS_ERR";
        case 6: return "ACT_ERR";
        case 7: return "CFT_ERR";
        default: return "reserved(" + std::to_string(v) + ")";
    }
}

std::string node_type_name(uint8_t v) {
    switch (v) {
        case 0: return "B-node";
        case 1: return "P-node";
        case 2: return "M-node";
        default: return "reserved(" + std::to_string(v) + ")";
    }
}

std::string rr_type_name(uint16_t v) {
    switch (v) {
        case 0x0020: return "NB";
        case 0x0021: return "NBSTAT";
        case 0x0001: return "A";     // RFC 1002 permits ordinary A records in an NBNS reply too
        case 0x0002: return "NS";
        default: return "unknown(0x" + [&] { std::ostringstream s; s << std::hex << v; return s.str(); }() + ")";
    }
}

// Microsoft's own NetBIOS-suffix convention (NOT part of RFC 1002 -- see nbns.hpp's file header
// comment) -- the single most commonly seen suffixes, cross-checked against Wireshark's own
// packet-nbns.c netbios_names[] table. Anything else is rendered "unknown(0xNN)".
std::string suffix_name(uint8_t v) {
    switch (v) {
        case 0x00: return "Workstation Service";
        case 0x03: return "Messenger Service";
        case 0x06: return "RAS Server Service";
        case 0x1B: return "Domain Master Browser (PDC)";
        case 0x1C: return "Domain Controllers";
        case 0x1D: return "Master Browser";
        case 0x1E: return "Browser Election Service";
        case 0x1F: return "NetDDE Service";
        case 0x20: return "File Server Service";
        case 0x21: return "RAS Client Service";
        case 0x2B: return "Lotus Notes Server Service";
        case 0x30: return "Modem Sharing Server Service";
        case 0x31: return "Modem Sharing Client Service";
        case 0x43: return "SMS Clients Remote Control";
        case 0x44: return "SMS Administrators Remote Control Tool";
        case 0x45: return "SMS Clients Remote Chat";
        case 0x46: return "SMS Clients Remote Transfer";
        case 0x4C: return "DEC Pathworks TCP/IP Service";
        case 0x6A: return "Microsoft Exchange Interchange (IMC)";
        case 0x87: return "Microsoft Exchange MTA";
        case 0xBE: return "Network Monitor Agent";
        case 0xBF: return "Network Monitor Application";
        default: {
            std::ostringstream s;
            s << "unknown(0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0')
              << static_cast<unsigned>(v) << ")";
            return s.str();
        }
    }
}

std::string mac_string(ByteSpan b) {
    std::ostringstream s;
    s << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < b.size(); ++i) {
        if (i != 0) s << ":";
        s << std::setw(2) << static_cast<unsigned>(b.at(i));
    }
    return s.str();
}

// Decodes one first-level-encoded NetBIOS NAME field (RFC 1002 4.1) starting at `offset`: a
// 1-byte length (must be exactly 0x20 -- see nbns.hpp's "Detection" paragraph), 32 encoded
// bytes (each an 'A'-'P' pair encoding one raw byte's high/low nibble), optionally followed by
// further length-prefixed scope-ID labels up to a zero-length terminator (almost always absent
// -- see nbns.hpp's "Explicitly out of scope" paragraph for why a compression pointer here is
// not followed). Returns the 16 raw decoded bytes plus how many bytes were consumed from
// `offset`.
struct NbnsNameResult {
    uint8_t raw[16] = {};
    size_t bytes_consumed = 0;
};

std::optional<NbnsNameResult> read_nbns_name(ByteSpan payload, size_t offset) {
    if (offset >= payload.size()) return std::nullopt;
    uint8_t len = payload.at(offset);
    if (len != 0x20) return std::nullopt;
    if (offset + 1 + 32 > payload.size()) return std::nullopt;
    NbnsNameResult result;
    for (int i = 0; i < 16; ++i) {
        uint8_t hi = payload.at(offset + 1 + static_cast<size_t>(i) * 2);
        uint8_t lo = payload.at(offset + 1 + static_cast<size_t>(i) * 2 + 1);
        if (hi < 'A' || hi > 'P' || lo < 'A' || lo > 'P') return std::nullopt;
        result.raw[i] = static_cast<uint8_t>(((hi - 'A') << 4) | (lo - 'A'));
    }
    size_t pos = offset + 1 + 32;
    // Scope ID labels -- ordinary length-prefixed ASCII, terminated by a zero-length label. A
    // compression pointer (top two bits set) here is deliberately not followed -- see nbns.hpp's
    // file header comment.
    while (true) {
        if (pos >= payload.size()) return std::nullopt;
        uint8_t l = payload.at(pos);
        if ((l & 0xC0) != 0) return std::nullopt;  // pointer or reserved -- not decoded, reject
        if (l == 0) {
            pos += 1;
            break;
        }
        if (pos + 1 + l > payload.size()) return std::nullopt;
        pos += 1 + l;
    }
    result.bytes_consumed = pos - offset;
    return result;
}

std::string trimmed_name(const uint8_t raw[16]) {
    std::string s(reinterpret_cast<const char*>(raw), 15);
    while (!s.empty() && s.back() == ' ') s.pop_back();
    return s;
}

}  // namespace

std::optional<NbnsMessage> try_parse_nbns(ByteSpan payload) {
    if (payload.size() < 12) return std::nullopt;
    try {
        NbnsMessage msg;
        msg.transaction_id = static_cast<uint16_t>((payload.at(0) << 8) | payload.at(1));
        uint16_t word2 = static_cast<uint16_t>((payload.at(2) << 8) | payload.at(3));
        msg.is_response = (word2 & 0x8000) != 0;
        msg.opcode = static_cast<uint8_t>((word2 >> 11) & 0x0F);
        msg.opcode_name = opcode_name(msg.opcode);
        bool aa = (word2 & 0x0400) != 0;
        bool tc = (word2 & 0x0200) != 0;
        bool rd = (word2 & 0x0100) != 0;
        bool ra = (word2 & 0x0080) != 0;
        bool b = (word2 & 0x0010) != 0;
        msg.rcode = static_cast<uint8_t>(word2 & 0x0F);
        msg.rcode_name = rcode_name(msg.rcode);
        std::vector<std::string> flags;
        if (aa) flags.push_back("AA");
        if (tc) flags.push_back("TC");
        if (rd) flags.push_back("RD");
        if (ra) flags.push_back("RA");
        if (b) flags.push_back("B");
        for (size_t i = 0; i < flags.size(); ++i) {
            if (i != 0) msg.flags += ",";
            msg.flags += flags[i];
        }

        msg.qdcount = static_cast<uint16_t>((payload.at(4) << 8) | payload.at(5));
        msg.ancount = static_cast<uint16_t>((payload.at(6) << 8) | payload.at(7));
        msg.nscount = static_cast<uint16_t>((payload.at(8) << 8) | payload.at(9));
        msg.arcount = static_cast<uint16_t>((payload.at(10) << 8) | payload.at(11));

        // Structural sanity gate (see nbns.hpp's "Detection" paragraph): the smallest possible
        // question is a 33-byte NAME (0x20 length + 32 encoded bytes + 1-byte zero-length scope
        // terminator) + QTYPE(2) + QCLASS(2) = 37 bytes; the smallest possible RR adds TYPE(2) +
        // CLASS(2) + TTL(4) + RDLENGTH(2) + 0-byte RDATA to the same 33-byte NAME = 43 bytes.
        size_t min_needed = 12 + static_cast<size_t>(msg.qdcount) * 37 +
                             (static_cast<size_t>(msg.ancount) + msg.nscount + msg.arcount) * 43;
        if (min_needed > payload.size()) return std::nullopt;

        // The first NAME field (whichever section it's in) is this decoder's own detection gate
        // -- see nbns.hpp's file header comment. A message with QDCOUNT==ANCOUNT==NSCOUNT==
        // ARCOUNT==0 has no NAME field at all to gate on; this decoder treats that (a
        // syntactically valid but practically useless NBT-NS message) as a rejection too, since
        // nothing distinguishes it from 12 bytes of arbitrary UDP payload.
        if (msg.qdcount == 0 && msg.ancount == 0 && msg.nscount == 0 && msg.arcount == 0) return std::nullopt;
        if (!read_nbns_name(payload, 12)) return std::nullopt;

        size_t pos = 12;
        auto parse_question = [&](NbnsQuestionEntry& q) -> bool {
            auto n = read_nbns_name(payload, pos);
            if (!n) return false;
            pos += n->bytes_consumed;
            if (pos + 4 > payload.size()) return false;
            q.name = trimmed_name(n->raw);
            q.suffix = n->raw[15];
            q.suffix_name = suffix_name(q.suffix);
            q.qtype = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
            q.qtype_name = rr_type_name(q.qtype);
            q.qclass = static_cast<uint16_t>((payload.at(pos + 2) << 8) | payload.at(pos + 3));
            pos += 4;
            std::ostringstream s;
            s << "question: " << q.name << "<" << std::hex << std::uppercase << std::setw(2)
              << std::setfill('0') << static_cast<unsigned>(q.suffix) << std::dec << std::nouppercase
              << "> (" << q.suffix_name << ") " << q.qtype_name;
            q.summary = s.str();
            return true;
        };
        for (uint16_t i = 0; i < msg.qdcount; ++i) {
            NbnsQuestionEntry q;
            if (!parse_question(q)) {
                msg.records_truncated = true;
                msg.notes.push_back("stopped parsing the question section after " + std::to_string(i) + " of " +
                                     std::to_string(msg.qdcount) + " declared question(s) -- truncated or malformed");
                break;
            }
            msg.questions.push_back(std::move(q));
        }

        auto parse_rr = [&](const char* section, NbnsResourceRecordEntry& rr) -> bool {
            auto n = read_nbns_name(payload, pos);
            if (!n) return false;
            pos += n->bytes_consumed;
            if (pos + 10 > payload.size()) return false;
            rr.name = trimmed_name(n->raw);
            rr.suffix = n->raw[15];
            rr.suffix_name = suffix_name(rr.suffix);
            rr.rtype = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
            rr.rtype_name = rr_type_name(rr.rtype);
            rr.rclass = static_cast<uint16_t>((payload.at(pos + 2) << 8) | payload.at(pos + 3));
            rr.ttl = static_cast<uint32_t>((payload.at(pos + 4) << 24) | (payload.at(pos + 5) << 16) |
                                            (payload.at(pos + 6) << 8) | payload.at(pos + 7));
            pos += 8;
            uint16_t rdlength = static_cast<uint16_t>((payload.at(pos) << 8) | payload.at(pos + 1));
            pos += 2;
            if (pos + rdlength > payload.size()) return false;
            ByteSpan rdata = payload.subspan(pos, rdlength);

            std::ostringstream s;
            s << section << ": " << rr.name << "<" << std::hex << std::uppercase << std::setw(2)
              << std::setfill('0') << static_cast<unsigned>(rr.suffix) << std::dec << std::nouppercase
              << "> (" << rr.suffix_name << ") " << rr.rtype_name << " ttl=" << rr.ttl << "s";

            if (rr.rtype == 0x0020 && rdlength % 6 == 0 && rdlength > 0) {  // NB
                for (size_t off = 0; off + 6 <= rdlength; off += 6) {
                    uint16_t nb_flags = static_cast<uint16_t>((rdata.at(off) << 8) | rdata.at(off + 1));
                    NbnsAddressEntry a;
                    a.is_group_name = (nb_flags & 0x8000) != 0;
                    a.owner_node_type = static_cast<uint8_t>((nb_flags >> 13) & 0x03);
                    a.owner_node_type_name = node_type_name(a.owner_node_type);
                    std::ostringstream addr;
                    addr << static_cast<unsigned>(rdata.at(off + 2)) << "." << static_cast<unsigned>(rdata.at(off + 3))
                         << "." << static_cast<unsigned>(rdata.at(off + 4)) << "." << static_cast<unsigned>(rdata.at(off + 5));
                    a.address = addr.str();
                    s << " -> " << a.address << " (" << (a.is_group_name ? "group" : "unique") << ", "
                      << a.owner_node_type_name << ")";
                    rr.addresses.push_back(std::move(a));
                }
            } else if (rr.rtype == 0x0021 && rdlength >= 1) {  // NBSTAT
                uint8_t num_names = rdata.at(0);
                size_t off = 1;
                bool ok = true;
                for (uint8_t i = 0; i < num_names && ok; ++i) {
                    if (off + 18 > rdlength) {
                        ok = false;
                        break;
                    }
                    NbnsNodeName nm;
                    nm.name = trimmed_name(reinterpret_cast<const uint8_t*>(rdata.data() + off));
                    nm.suffix = rdata.at(off + 15);
                    nm.suffix_name = suffix_name(nm.suffix);
                    uint16_t name_flags = static_cast<uint16_t>((rdata.at(off + 16) << 8) | rdata.at(off + 17));
                    nm.is_group_name = (name_flags & 0x8000) != 0;
                    nm.owner_node_type = static_cast<uint8_t>((name_flags >> 13) & 0x03);
                    nm.owner_node_type_name = node_type_name(nm.owner_node_type);
                    nm.deregister = (name_flags & 0x1000) != 0;
                    nm.conflict = (name_flags & 0x0800) != 0;
                    nm.active = (name_flags & 0x0400) != 0;
                    nm.permanent = (name_flags & 0x0200) != 0;
                    rr.node_names.push_back(nm);
                    off += 18;
                    s << " | " << nm.name << "<" << std::hex << std::uppercase << std::setw(2)
                      << std::setfill('0') << static_cast<unsigned>(nm.suffix) << std::dec << std::nouppercase
                      << "> (" << nm.suffix_name << ")" << (nm.is_group_name ? " group" : " unique")
                      << (nm.active ? " ACT" : "") << (nm.permanent ? " PRM" : "") << (nm.conflict ? " CNF" : "")
                      << (nm.deregister ? " DRG" : "");
                }
                // STATISTICS: UNIT_ID (6-byte MAC) + implementation-defined traffic counters --
                // see nbns.hpp's file header comment's NBSTAT paragraph for the full 46-byte
                // layout this decoder deliberately doesn't break out past UNIT_ID.
                if (ok && off + 6 <= rdlength) {
                    rr.has_unit_id = true;
                    rr.unit_id_mac = mac_string(rdata.subspan(off, 6));
                    s << " unit_id=" << rr.unit_id_mac;
                    off += 6;
                    if (off < rdlength) rr.statistics_tail_hex = to_hex(rdata.subspan(off, rdlength - off), "");
                }
            } else {
                rr.rdata_hex = to_hex(rdata, "");
            }

            pos += rdlength;
            rr.summary = s.str();
            return true;
        };
        auto parse_section = [&](const char* section, uint16_t count, std::vector<NbnsResourceRecordEntry>& out_vec) {
            for (uint16_t i = 0; i < count; ++i) {
                NbnsResourceRecordEntry rr;
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
        s << "NBT-NS " << (msg.is_response ? "response" : "query") << " id=0x" << std::hex << std::uppercase
          << std::setfill('0') << std::setw(4) << msg.transaction_id << std::dec << std::nouppercase << " "
          << msg.opcode_name;
        if (msg.is_response) s << " " << msg.rcode_name;
        if (!msg.flags.empty()) s << " [" << msg.flags << "]";
        if (!msg.questions.empty()) s << " -- " << msg.questions.front().name;
        else if (!msg.answers.empty()) s << " -- " << msg.answers.front().name;
        msg.summary = s.str();

        return msg;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

}  // namespace conduitscope
