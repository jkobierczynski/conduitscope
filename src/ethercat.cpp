// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/ethercat.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

std::string hex8(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(8) << std::setfill('0') << v;
    return s.str();
}

// Safety cap against a malformed/adversarial frame claiming an implausible chain of datagrams --
// see ethercat.hpp's file header comment's "declared Length" paragraph. The real capture fixture's
// deepest observed chain is 11 datagrams (see ATTRIBUTION.md); this cap is set well above that,
// the same margin SV's kMaxSvAsdus gives its own real-world-observed count.
constexpr size_t kMaxEthercatDatagrams = 200;

// Frame header Type field -- see ethercat.hpp's file header comment's frame header table
// (cross-checked against packet-ethercat-frame.c's EthercatFrameTypes value_string).
std::optional<std::string> frame_type_name(uint8_t type) {
    switch (type) {
        case 1: return "EtherCAT command";
        case 2: return "ADS";
        case 3: return "RAW-IO";
        case 4: return "NV";
        case 5: return "Mailbox";
        default: return std::nullopt;  // not one of the five the spec defines
    }
}

// Cmd name table -- see ethercat.hpp's file header comment's Cmd name paragraph (cross-checked
// against packet-ethercat-datagram.c's EcCmdShort).
std::string cmd_name(uint8_t cmd) {
    switch (cmd) {
        case 0: return "NOP";
        case 1: return "APRD";
        case 2: return "APWR";
        case 3: return "APRW";
        case 4: return "FPRD";
        case 5: return "FPWR";
        case 6: return "FPRW";
        case 7: return "BRD";
        case 8: return "BWR";
        case 9: return "BRW";
        case 10: return "LRD";
        case 11: return "LWR";
        case 12: return "LRW";
        case 13: return "ARMW";
        case 14: return "FRMW";
        case 255: return "EXT";
        default: return "unknown(" + std::to_string(static_cast<unsigned>(cmd)) + ")";
    }
}

std::string render_datagram_address(const EthercatDatagram& d) {
    if (d.logical_addressing) return "logAddr=" + hex8(d.logical_address);
    return "adp=" + hex4(d.adp) + " ado=" + hex4(d.ado);
}

std::string render_datagram(const EthercatDatagram& d) {
    std::ostringstream s;
    s << d.cmd_name << " idx=" << static_cast<unsigned>(d.idx) << " " << render_datagram_address(d)
      << " len=" << d.data_len << " wkc=" << d.wkc;
    return s.str();
}

// Decodes one EtherCAT datagram (EcParserHDR + Data + WKC -- see ethercat.hpp's file header
// comment's datagram field table) starting at `c`'s current position, bounded by `c`'s own
// remaining bytes (the caller, decode_datagram_chain, is responsible for bounding `c` to the
// declared-Length region or the tolerant available-bytes fallback). Returns std::nullopt when
// even the fixed 10-byte header doesn't fit -- the caller treats that as "chain truncated, stop".
std::optional<EthercatDatagram> decode_one_datagram(Cursor& c, std::vector<std::string>& notes) {
    if (c.remaining() < 10) {
        notes.push_back("EtherCAT datagram header needs 10 byte(s) but only " + std::to_string(c.remaining()) +
                         " remain -- chain truncated, stopping");
        return std::nullopt;
    }
    EthercatDatagram d;
    d.cmd = c.u8();
    d.cmd_name = cmd_name(d.cmd);
    d.idx = c.u8();

    d.logical_addressing = (d.cmd == 10 || d.cmd == 11 || d.cmd == 12);
    if (d.logical_addressing) {
        d.logical_address = c.u32le();
    } else {
        d.adp = c.u16le();
        d.ado = c.u16le();
    }

    uint16_t len_word = c.u16le();
    d.data_len = len_word & 0x07FF;
    d.circulating = (len_word & 0x4000) != 0;
    d.more_follows = (len_word & 0x8000) != 0;
    d.irq = c.u16le();

    if (c.remaining() < static_cast<size_t>(d.data_len) + 2) {
        notes.push_back(d.cmd_name + " idx=" + std::to_string(static_cast<unsigned>(d.idx)) + " declares " +
                         std::to_string(d.data_len) + " data byte(s) + 2-byte WKC but only " +
                         std::to_string(c.remaining()) + " byte(s) remain -- chain truncated, stopping");
        return std::nullopt;
    }
    ByteSpan data = c.bytes(d.data_len);
    d.data_hex = to_hex(data, "");
    d.data_length = data.size();
    d.wkc = c.u16le();
    return d;
}

// Walks the chain of datagrams within `region` (either the declared-Length-bounded area or the
// tolerant available-bytes fallback -- see try_parse_ethercat) while each datagram's More bit is
// set, capped at kMaxEthercatDatagrams. See ethercat.hpp's file header comment's "declared Length"
// paragraph for why bounding by `region` (rather than walking every byte physically present in
// the Ethernet frame, as Wireshark's own dissector does) avoids misreading Ethernet minimum-frame
// padding as a spurious trailing NOP-shaped datagram.
std::vector<EthercatDatagram> decode_datagram_chain(ByteSpan region, std::vector<std::string>& notes) {
    std::vector<EthercatDatagram> datagrams;
    Cursor c(region);
    while (true) {
        if (datagrams.size() >= kMaxEthercatDatagrams) {
            notes.push_back("EtherCAT datagram chain: stopped after " + std::to_string(kMaxEthercatDatagrams) +
                             " datagram(s) (safety cap)");
            break;
        }
        auto d = decode_one_datagram(c, notes);
        if (!d) break;
        bool more = d->more_follows;
        datagrams.push_back(std::move(*d));
        if (!more) break;
        if (c.remaining() == 0) {
            notes.push_back("EtherCAT datagram chain: More bit set on the last datagram decoded, but no bytes "
                             "remain in this frame's declared Length -- chain truncated");
            break;
        }
    }
    if (c.remaining() > 0) {
        notes.push_back(std::to_string(c.remaining()) +
                         " byte(s) remain inside this frame's declared Length after its last datagram (More bit "
                         "clear) -- unexpected, not decoded further");
    }
    return datagrams;
}

}  // namespace

std::optional<EthercatFrame> try_parse_ethercat(ByteSpan eth_payload) {
    if (eth_payload.size() < 2) {
        return std::nullopt;
    }
    try {
        Cursor c(eth_payload);
        uint16_t header_word = c.u16le();
        uint16_t declared_length = header_word & 0x07FF;
        bool reserved_bit_set = (header_word & 0x0800) != 0;
        uint8_t type = static_cast<uint8_t>((header_word >> 12) & 0x0F);

        auto type_name = frame_type_name(type);
        if (!type_name) {
            return std::nullopt;  // not one of the five the spec defines -- see the header
                                    // comment's "structural detection gate" paragraph
        }

        EthercatFrame frame;
        frame.declared_length = declared_length;
        frame.reserved_bit_set = reserved_bit_set;
        frame.frame_type = type;
        frame.frame_type_name = *type_name;
        if (reserved_bit_set) {
            frame.notes.push_back("frame header Reserved bit is set -- the spec says this must be zero");
        }

        if (type != 1) {
            frame.summary = "ECAT type=" + *type_name + " (not decoded further)";
            return frame;
        }

        frame.has_datagrams = true;
        ByteSpan after_header = c.rest();
        ByteSpan region;
        if (declared_length > 0 && declared_length <= after_header.size()) {
            region = after_header.subspan(0, declared_length);
        } else {
            region = after_header;
            frame.notes.push_back("frame header Length (" + std::to_string(declared_length) +
                                   ") is implausible (must be >= 1 and <= the " +
                                   std::to_string(after_header.size()) +
                                   " byte(s) actually present) -- using all available bytes instead");
        }

        frame.datagrams = decode_datagram_chain(region, frame.notes);

        std::ostringstream s;
        s << "ECAT ";
        if (frame.datagrams.empty()) {
            s << "0 datagram(s) decoded";
        } else {
            s << render_datagram(frame.datagrams[0]);
            if (frame.datagrams.size() > 1) {
                s << " (+" << (frame.datagrams.size() - 1) << " more datagram(s))";
            }
        }
        frame.summary = s.str();
        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // goose.cpp/sv.cpp/profinet.cpp all take.
        return std::nullopt;
    }
}

}  // namespace conduitscope
