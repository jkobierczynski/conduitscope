// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/pcap_writer.hpp"

#include "conduitscope/byteio.hpp"

namespace conduitscope {

namespace {

void put_u32le(std::ofstream& out, uint32_t v) {
    char b[4] = {static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff),
                 static_cast<char>((v >> 16) & 0xff), static_cast<char>((v >> 24) & 0xff)};
    out.write(b, 4);
}

void put_u16le(std::ofstream& out, uint16_t v) {
    char b[2] = {static_cast<char>(v & 0xff), static_cast<char>((v >> 8) & 0xff)};
    out.write(b, 2);
}

}  // namespace

PcapWriter::PcapWriter(const std::string& path, uint32_t linktype, uint32_t snaplen) : path_(path) {
    out_.open(path, std::ios::binary | std::ios::trunc);
    if (!out_) {
        throw ParseError("cannot open '" + path + "' for writing");
    }
    // Classic pcap global header (24 bytes), little-endian, microsecond resolution -- see this
    // class's own file header comment. version 2.4 / thiszone 0 / sigfigs 0 match every modern
    // writer (tcpdump/dumpcap/Wireshark all leave thiszone/sigfigs at 0 too -- see
    // pcap_reader.cpp's own read of these same fields, which never uses them beyond display).
    put_u32le(out_, 0xa1b2c3d4u);  // magic: little-endian, microsecond resolution
    put_u16le(out_, 2);            // version_major
    put_u16le(out_, 4);            // version_minor
    put_u32le(out_, 0);            // thiszone
    put_u32le(out_, 0);            // sigfigs
    put_u32le(out_, snaplen);
    put_u32le(out_, linktype);
    if (!out_) {
        throw ParseError("failed writing pcap global header to '" + path + "'");
    }
}

void PcapWriter::write_packet(const PcapPacket& pkt) {
    uint32_t ts_usec = pkt.nanosecond_ts_hint ? (pkt.ts_frac / 1000u) : pkt.ts_frac;
    put_u32le(out_, pkt.ts_sec);
    put_u32le(out_, ts_usec);
    put_u32le(out_, pkt.captured_len);
    put_u32le(out_, pkt.original_len);
    out_.write(reinterpret_cast<const char*>(pkt.data.data()), static_cast<std::streamsize>(pkt.data.size()));
    if (!out_) {
        throw ParseError("failed writing packet record to '" + path_ + "'");
    }
}

}  // namespace conduitscope
