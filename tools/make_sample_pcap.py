#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generates the synthetic pcap fixtures under tests/.

Pure standard library (struct, base64) -- deliberately has no dependency on
scapy/pymodbus/etc. so the test fixtures can be regenerated (or new ones
added) without installing anything. This is a build-time/dev-time helper,
not something the CMake build invokes automatically -- the generated files
are committed under tests/ like any other fixture.

Run it from the repository root:
    python3 tools/make_sample_pcap.py
"""
import struct
import pathlib
import base64
import socket

ROOT = pathlib.Path(__file__).resolve().parent.parent
TESTS_DIR = ROOT / "tests"

PCAP_MAGIC_LE_MICROSECOND = 0xA1B2C3D4
LINKTYPE_ETHERNET = 1
LINKTYPE_RAW = 101
LINKTYPE_CAN_SOCKETCAN = 227

# --- pcapng block builders -------------------------------------------------------------
# Minimal, little-endian-only (conduitscope's pcapng reader handles both byte orders, but
# there is no need to exercise that here -- the LE/BE bootstrap logic itself lives entirely
# in pcap_reader.cpp and isn't sensitive to which order a given *test* file happens to use).
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D
PCAPNG_SHB_TYPE = 0x0A0D0D0A
PCAPNG_IDB_TYPE = 0x00000001
PCAPNG_SPB_TYPE = 0x00000003
PCAPNG_EPB_TYPE = 0x00000006


def pcapng_block(block_type: int, body: bytes) -> bytes:
    """Wraps `body` in a pcapng block: Block Type, Block Total Length, the (4-byte-padded)
    body, then Block Total Length again."""
    pad = (-len(body)) % 4
    padded = body + b"\x00" * pad
    total_length = 12 + len(padded)
    return struct.pack("<II", block_type, total_length) + padded + struct.pack("<I", total_length)


def pcapng_option(code: int, value: bytes) -> bytes:
    pad = (-len(value)) % 4
    return struct.pack("<HH", code, len(value)) + value + b"\x00" * pad


def pcapng_shb() -> bytes:
    # Byte-Order Magic, major version 1, minor version 0, section length -1 (unknown/don't care).
    body = struct.pack("<IHHq", PCAPNG_BYTE_ORDER_MAGIC, 1, 0, -1)
    return pcapng_block(PCAPNG_SHB_TYPE, body)


def pcapng_idb(linktype=LINKTYPE_ETHERNET, snaplen=262144, tsresol=None) -> bytes:
    """`tsresol`, if given, is the raw if_tsresol option byte: 6 (the default, so normally
    omitted) means microsecond resolution, 9 means nanosecond."""
    body = struct.pack("<HHI", linktype, 0, snaplen)
    if tsresol is not None:
        body += pcapng_option(9, bytes([tsresol]))
    body += pcapng_option(0, b"")  # opt_endofopt
    return pcapng_block(PCAPNG_IDB_TYPE, body)


def pcapng_epb(interface_id: int, ts_ticks: int, payload: bytes, orig_len=None) -> bytes:
    """`ts_ticks` is the full 64-bit timestamp in units of the owning interface's declared
    resolution (e.g. microseconds since the epoch at the default resolution) -- not seconds
    and not split into a sec/frac pair the way classic pcap and Enhanced Packet Block's own
    ts_high/ts_low split might suggest; the split here is purely how the 64-bit value is laid
    out on the wire, not a sec/frac semantic split."""
    if orig_len is None:
        orig_len = len(payload)
    ts_high = (ts_ticks >> 32) & 0xFFFFFFFF
    ts_low = ts_ticks & 0xFFFFFFFF
    body = struct.pack("<IIIII", interface_id, ts_high, ts_low, len(payload), orig_len) + payload
    return pcapng_block(PCAPNG_EPB_TYPE, body)


def pcapng_spb(payload: bytes, orig_len=None) -> bytes:
    """Simple Packet Block: always implicitly interface 0, no timestamp."""
    if orig_len is None:
        orig_len = len(payload)
    body = struct.pack("<I", orig_len) + payload
    return pcapng_block(PCAPNG_SPB_TYPE, body)


def pcap_global_header(linktype=LINKTYPE_ETHERNET, snaplen=262144):
    return struct.pack(
        "<IHHiIII",
        PCAP_MAGIC_LE_MICROSECOND,
        2, 4,          # version major, minor
        0,              # thiszone
        0,              # sigfigs
        snaplen,
        linktype,
    )


def pcap_record(payload: bytes, ts_sec: int, ts_usec: int):
    return struct.pack("<IIII", ts_sec, ts_usec, len(payload), len(payload)) + payload


def mac(s: str) -> bytes:
    return bytes(int(b, 16) for b in s.split(":"))


def eth_header(dst: bytes, src: bytes, ethertype: int) -> bytes:
    return struct.pack("!6s6sH", dst, src, ethertype)


def ipv4_header(src: str, dst: str, protocol: int, payload_len: int, ident: int) -> bytes:
    def ip_bytes(addr):
        return bytes(int(o) for o in addr.split("."))

    total_length = 20 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x45,            # version 4, IHL 5 words
        0,                # ToS
        total_length,
        ident,
        0x4000,           # flags=DF, fragment offset 0
        64,               # TTL
        protocol,
        0,                # checksum -- not validated by conduitscope; left as 0
        ip_bytes(src),
        ip_bytes(dst),
    )


ETHERTYPE_IPV6 = 0x86DD


def ipv6_header(src: str, dst: str, next_header: int, payload_len: int) -> bytes:
    """Fixed 40-byte IPv6 base header -- no extension headers (see ipv6_header_with_extensions
    below for that). Mirrors ipv4_header's own shape/signature as closely as IPv6's different wire
    format allows."""
    version_tc_flowlabel = 0x6 << 28  # version=6, traffic class=0, flow label=0
    return struct.pack(
        "!IHBB16s16s",
        version_tc_flowlabel,
        payload_len,
        next_header,
        64,  # hop limit
        socket.inet_pton(socket.AF_INET6, src),
        socket.inet_pton(socket.AF_INET6, dst),
    )


def ipv6_extension_header(next_header: int, option_data: bytes) -> bytes:
    """One generic RFC 8200 Hop-by-Hop/Routing/Destination-Options-shaped extension header:
    Next Header(1) + Hdr Ext Len(1, in 8-byte units not counting the first 8 bytes) + option_data,
    padded with zero bytes to the next 8-byte boundary (a real Hop-by-Hop/Destination-Options
    header would pad with a real PadN option instead -- conduitscope's own parse_ipv6 doesn't
    interpret option contents at all, only walks past the header by its declared length, so plain
    zero padding round-trips through it identically and keeps this fixture builder simple)."""
    body = option_data
    # Header content after the 2 fixed bytes must be a multiple of 8 bytes (Hdr Ext Len is itself
    # in 8-byte units); pad with zero bytes until (2 + len(body)) % 8 == 0.
    while (2 + len(body)) % 8 != 0:
        body += b"\x00"
    hdr_ext_len = (2 + len(body)) // 8 - 1
    return struct.pack("!BB", next_header, hdr_ext_len) + body


def tcp_header(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload_len: int) -> bytes:
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        0x50,             # data offset = 5 words, no options
        flags,
        8192,             # window
        0,                # checksum -- not validated
        0,                # urgent pointer
    )


TCP_SYN, TCP_ACK, TCP_PSH = 0x02, 0x10, 0x08

HMI_MAC = mac("00:0c:29:11:22:33")
PLC_MAC = mac("00:0c:29:aa:bb:cc")
HMI_IP, PLC_IP = "192.168.1.50", "192.168.1.10"


def build_modbus_sample():
    packets = []

    # Request: Read Holding Registers, address 0, quantity 10.
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_req = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req
    packets.append(eth_req)

    # Response: 10 holding registers, values 0..9.
    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    mb_resp = struct.pack("!HHHBBB", 1, 0, 2 + 1 + len(reg_data), 1, 3, len(reg_data)) + reg_data
    tcp_resp = tcp_header(502, 51000, 2000, 1000 + len(mb_req), TCP_PSH | TCP_ACK, len(mb_resp)) + mb_resp
    ip_resp = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp_resp), 0x1001) + tcp_resp
    eth_resp = eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_resp
    packets.append(eth_resp)

    # Exception response: illegal data address, to exercise that decode path too.
    mb_exc = struct.pack("!HHHBBB", 2, 0, 3, 1, 0x83, 0x02)
    tcp_exc = tcp_header(502, 51000, 3000, 1000, TCP_PSH | TCP_ACK, len(mb_exc)) + mb_exc
    ip_exc = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp_exc), 0x1002) + tcp_exc
    eth_exc = eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_exc
    packets.append(eth_exc)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_000 + i, i * 1000)
    (TESTS_DIR / "sample_modbus.pcap").write_bytes(data)


def build_modbus_false_positive_sample():
    """Regression fixture for a real false-positive: non-Modbus traffic (here, a DNP3-shaped
    payload chosen so its own bytes are irrelevant to the point) whose first four bytes happen
    to look like a valid Modbus MBAP transaction_id + protocol_id==0, and whose function-code
    byte happens to be 0x00. Function code 0 is reserved and never assigned in the Modbus spec,
    so this must NOT be classified as Modbus (found via a real capture: DNP3 traffic on port
    20000 was landing on this coincidence and getting mislabeled)."""
    # transaction_id=0x0564 (arbitrary, chosen to look DNP3-ish), protocol_id=0x0000,
    # mbap_length/unit_id/function_code chosen so function_code == 0x00.
    bogus = struct.pack("!HHHBB", 0x0564, 0x0000, 2, 0x01, 0x00) + bytes([0xAA, 0xBB, 0xCC])
    tcp_seg = tcp_header(57125, 20000, 9000, 9100, TCP_PSH | TCP_ACK, len(bogus)) + bogus
    ip_seg = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_seg), 0x5000) + tcp_seg
    eth_seg = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_seg

    data = pcap_global_header()
    data += pcap_record(eth_seg, 1_700_000_500, 0)
    (TESTS_DIR / "sample_modbus_false_positive.pcap").write_bytes(data)


def build_modbus_pairing_sample():
    """Exercises Decoder::pair_modbus_transaction -- authoritative (MBAP transaction-ID + TCP-
    session, non-heuristic) Modbus request/response pairing, layered on top of (never replacing)
    modbus.cpp's own payload-shape heuristic. sample_modbus.pcap already incidentally exercises the
    common "read family" pairing case and one orphan response (see its packets 1-3); this fixture
    is specifically for the cases that need their own scenario:

    A) Write Single Register: request and response share the IDENTICAL 4-byte wire shape per spec
       (modbus.cpp's own heuristic note literally says so) -- payload shape alone cannot tell them
       apart. Transaction ID + which direction it was first seen on can, and must here, since this
       is the strongest real-world motivation for this feature existing at all.
    B) A transaction ID reused (by a misbehaving/retrying client) before its first request was ever
       paired with a response -- the reassembly must not silently overwrite this without a trace, and
       the eventual response must pair to the SECOND (most recent) outstanding request, not the first."""
    packets = []

    def add(src_port, dst_port, seq, ack, payload, ident, from_plc):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # A) Write Single Register: address=10, value=0x1234, transaction id 500. Request and response
    #    are byte-for-byte identical apart from the MBAP transaction ID being echoed (that's the
    #    whole point -- see modbus.cpp's decode_write_single).
    ws_pdu = struct.pack("!BHH", 0x06, 10, 0x1234)
    ws_req = struct.pack("!HHHB", 500, 0, 1 + len(ws_pdu), 1) + ws_pdu
    add(51700, 502, 100, 200, ws_req, 0x7000, from_plc=False)
    ws_resp = struct.pack("!HHHB", 500, 0, 1 + len(ws_pdu), 1) + ws_pdu  # identical shape, echoed tx id
    add(502, 51700, 200, 100 + len(ws_req), ws_resp, 0x7001, from_plc=True)

    # B) Transaction id 600 reused on the same flow before its first request is ever answered
    #    (e.g. a client that times out and retries without waiting), then a real response arrives
    #    for that reused id -- must pair to the SECOND (most recently outstanding) request.
    first_req = struct.pack("!HHHBB HH", 600, 0, 6, 1, 3, 0, 5)  # read 5 holding registers @ 0
    add(51701, 502, 300, 400, first_req, 0x7002, from_plc=False)
    second_req = struct.pack("!HHHBB HH", 600, 0, 6, 1, 3, 100, 5)  # read 5 holding registers @ 100 (retry)
    add(51701, 502, 300 + len(first_req), 400, second_req, 0x7003, from_plc=False)
    reg_vals = b"".join(struct.pack("!H", v) for v in (9001, 9002, 9003, 9004, 9005))
    resp = struct.pack("!HHHBB", 600, 0, 2 + 1 + len(reg_vals), 1, 3) + bytes([len(reg_vals)]) + reg_vals
    add(502, 51701, 400, 300 + len(first_req) + len(second_req), resp, 0x7004, from_plc=True)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_700 + i, i * 1000)
    (TESTS_DIR / "sample_modbus_pairing.pcap").write_bytes(data)


# DNP3 data-link CRC-16 table (reflected, polynomial 0x3D65 / reflected form 0xA6BC, seed 0, final
# complement) -- the EXACT same table as kDnp3CrcTable in src/dnp3.cpp, copied verbatim rather than
# re-derived, so this generator and conduitscope's own validator are guaranteed to agree bit-for-
# bit. conduitscope now actually validates both the header CRC and every block CRC (previously it
# only located and skipped them), so every frame this file builds gets a genuinely correct CRC by
# default -- see dnp3_crc16/dnp3_block_crc_encode/dnp3_link_frame below. The two deliberately
# CORRUPTED frames in build_dnp3_sample (packets 13 and 14) start from a correctly-CRC'd frame and
# then flip specific CRC bytes, so the corruption is unambiguous and doesn't depend on this table
# being subtly wrong in some other way.
DNP3_CRC_TABLE = [
    0x0000, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
    0xFF89, 0xC9D7, 0x9335, 0xA56B, 0x26F1, 0x10AF, 0x4A4D, 0x7C13,
    0xB26B, 0x8435, 0xDED7, 0xE889, 0x6B13, 0x5D4D, 0x07AF, 0x31F1,
    0x4DE2, 0x7BBC, 0x215E, 0x1700, 0x949A, 0xA2C4, 0xF826, 0xCE78,
    0x29AF, 0x1FF1, 0x4513, 0x734D, 0xF0D7, 0xC689, 0x9C6B, 0xAA35,
    0xD626, 0xE078, 0xBA9A, 0x8CC4, 0x0F5E, 0x3900, 0x63E2, 0x55BC,
    0x9BC4, 0xAD9A, 0xF778, 0xC126, 0x42BC, 0x74E2, 0x2E00, 0x185E,
    0x644D, 0x5213, 0x08F1, 0x3EAF, 0xBD35, 0x8B6B, 0xD189, 0xE7D7,
    0x535E, 0x6500, 0x3FE2, 0x09BC, 0x8A26, 0xBC78, 0xE69A, 0xD0C4,
    0xACD7, 0x9A89, 0xC06B, 0xF635, 0x75AF, 0x43F1, 0x1913, 0x2F4D,
    0xE135, 0xD76B, 0x8D89, 0xBBD7, 0x384D, 0x0E13, 0x54F1, 0x62AF,
    0x1EBC, 0x28E2, 0x7200, 0x445E, 0xC7C4, 0xF19A, 0xAB78, 0x9D26,
    0x7AF1, 0x4CAF, 0x164D, 0x2013, 0xA389, 0x95D7, 0xCF35, 0xF96B,
    0x8578, 0xB326, 0xE9C4, 0xDF9A, 0x5C00, 0x6A5E, 0x30BC, 0x06E2,
    0xC89A, 0xFEC4, 0xA426, 0x9278, 0x11E2, 0x27BC, 0x7D5E, 0x4B00,
    0x3713, 0x014D, 0x5BAF, 0x6DF1, 0xEE6B, 0xD835, 0x82D7, 0xB489,
    0xA6BC, 0x90E2, 0xCA00, 0xFC5E, 0x7FC4, 0x499A, 0x1378, 0x2526,
    0x5935, 0x6F6B, 0x3589, 0x03D7, 0x804D, 0xB613, 0xECF1, 0xDAAF,
    0x14D7, 0x2289, 0x786B, 0x4E35, 0xCDAF, 0xFBF1, 0xA113, 0x974D,
    0xEB5E, 0xDD00, 0x87E2, 0xB1BC, 0x3226, 0x0478, 0x5E9A, 0x68C4,
    0x8F13, 0xB94D, 0xE3AF, 0xD5F1, 0x566B, 0x6035, 0x3AD7, 0x0C89,
    0x709A, 0x46C4, 0x1C26, 0x2A78, 0xA9E2, 0x9FBC, 0xC55E, 0xF300,
    0x3D78, 0x0B26, 0x51C4, 0x679A, 0xE400, 0xD25E, 0x88BC, 0xBEE2,
    0xC2F1, 0xF4AF, 0xAE4D, 0x9813, 0x1B89, 0x2DD7, 0x7735, 0x416B,
    0xF5E2, 0xC3BC, 0x995E, 0xAF00, 0x2C9A, 0x1AC4, 0x4026, 0x7678,
    0x0A6B, 0x3C35, 0x66D7, 0x5089, 0xD313, 0xE54D, 0xBFAF, 0x89F1,
    0x4789, 0x71D7, 0x2B35, 0x1D6B, 0x9EF1, 0xA8AF, 0xF24D, 0xC413,
    0xB800, 0x8E5E, 0xD4BC, 0xE2E2, 0x6178, 0x5726, 0x0DC4, 0x3B9A,
    0xDC4D, 0xEA13, 0xB0F1, 0x86AF, 0x0535, 0x336B, 0x6989, 0x5FD7,
    0x23C4, 0x159A, 0x4F78, 0x7926, 0xFABC, 0xCCE2, 0x9600, 0xA05E,
    0x6E26, 0x5878, 0x029A, 0x34C4, 0xB75E, 0x8100, 0xDBE2, 0xEDBC,
    0x91AF, 0xA7F1, 0xFD13, 0xCB4D, 0x48D7, 0x7E89, 0x246B, 0x1235,
]


def dnp3_crc16(data: bytes) -> int:
    """Same algorithm as conduitscope's own dnp3_crc16 (src/dnp3.cpp): table-driven, reflected,
    seed 0, final bitwise complement."""
    crc = 0
    for b in data:
        crc = DNP3_CRC_TABLE[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return (~crc) & 0xFFFF


assert dnp3_crc16(b"123456789") == 0xEA82, "DNP3 CRC-16 reference test vector failed"


def dnp3_block_crc_encode(payload: bytes) -> bytes:
    """Splits `payload` (the logical transport+application bytes) into <=16-byte blocks, each
    followed by its own genuine, correctly-computed 2-byte CRC (little-endian on the wire) --
    the real DNP3 data-link user-data wire format, now that conduitscope actually validates it."""
    out = b""
    for i in range(0, len(payload), 16):
        chunk = payload[i:i + 16]
        out += chunk + struct.pack("<H", dnp3_crc16(chunk))
    return out


def dnp3_link_frame(source: int, destination: int, user_data: bytes, control: int = 0xC4) -> bytes:
    """A full DNP3 data-link frame: 10-byte header (start+length+control+dest+src+header-CRC, a
    genuine, correctly-computed CRC over the first 8 header bytes) followed by `user_data`'s
    block-CRC-encoded wire bytes."""
    length_field = 5 + len(user_data)
    assert length_field <= 255, "single data-link frame can't carry this much user data"
    header_no_crc = bytes([0x05, 0x64, length_field, control]) + struct.pack("<HH", destination, source)
    header = header_no_crc + struct.pack("<H", dnp3_crc16(header_no_crc))
    return header + dnp3_block_crc_encode(user_data)


def build_dnp3_sample():
    packets = []

    # 1) A bare data-link frame with no user data at all (e.g. a link-layer control frame) --
    #    user_data_bytes decodes to 0 and there is nothing above the data link layer to decode.
    #    Kept as the very first packet so a regression here reproduces the original, simplest case.
    bare_frame = dnp3_link_frame(source=1, destination=1024, user_data=b"")
    tcp1 = tcp_header(51500, 20000, 5000, 6000, TCP_PSH | TCP_ACK, len(bare_frame)) + bare_frame
    ip1 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp1), 0x2000) + tcp1
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip1)

    # 2) A real single-fragment Read request: Class 0 poll (group=60 var=1 qualifier=0x06 "all",
    #    which by definition carries zero object data) -- the most common real DNP3 request shape.
    #    Transport byte: FIR=1 FIN=1 SEQ=0 -> 0xC0. Application control: FIR=1 FIN=1 CON=0 UNS=0
    #    SEQ=0 -> 0xC0. Function code 0x01 (Read).
    read_class0 = bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06])
    read_frame = dnp3_link_frame(source=1, destination=1024, user_data=read_class0)
    tcp2 = tcp_header(51500, 20000, 5001, 6000, TCP_PSH | TCP_ACK, len(read_frame)) + read_frame
    ip2 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp2), 0x2001) + tcp2
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip2)

    # 3) The matching response: function 0x81 (Response), IIN1=0x80 (DEVICE_RESTART) / IIN2=0x00,
    #    then two object headers -- g1v2 (Binary Input w/ flags, byte-oriented) start-stop 0-2 (3
    #    points, 3 bytes of data) and g30v1 (Analog Input 32-bit w/ flag, 5 bytes/point) start-stop
    #    0-0 (1 point, 5 bytes of data). Logical payload is 23 bytes -- over the 16-byte block
    #    size, so this is also the fixture that exercises multi-block CRC reassembly.
    resp_payload = (
        bytes([0xC0, 0xC0, 0x81, 0x80, 0x00]) +           # transport, app control, fc, IIN1, IIN2
        bytes([1, 2, 0x00, 0, 2]) + bytes([0x81, 0x01, 0x00]) +   # g1v2 start-stop 0-2, 3 data bytes
        bytes([30, 1, 0x00, 0, 0]) + bytes([0x01, 0x00, 0x00, 0x00, 0x00])  # g30v1 start-stop 0-0, 5 data bytes
    )
    assert len(resp_payload) == 23
    resp_frame = dnp3_link_frame(source=1024, destination=1, user_data=resp_payload)
    tcp3 = tcp_header(20000, 51500, 6000, 5001 + len(read_frame), TCP_PSH | TCP_ACK, len(resp_frame)) + resp_frame
    ip3 = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp3), 0x2002) + tcp3
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip3)

    # 4) A fragment that spans multiple data-link frames (transport FIR=1, FIN=0 -- "more to
    #    come"): only the transport header should be decoded, application layer left alone.
    #    The bytes after the transport byte are arbitrary/unparseable on purpose -- they must
    #    never be touched.
    multi_frame_payload = bytes([0x80, 0xDE, 0xAD, 0xBE, 0xEF])  # FIR=1 FIN=0 SEQ=0, then junk
    multi_frame = dnp3_link_frame(source=1, destination=1024, user_data=multi_frame_payload)
    tcp4 = tcp_header(51500, 20000, 5002, 6000 + len(resp_frame), TCP_PSH | TCP_ACK,
                       len(multi_frame)) + multi_frame
    ip4 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp4), 0x2003) + tcp4
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip4)

    # 5) An object header this release deliberately does not decode further: qualifier 0x46 ==
    #    prefix code 4 (object-size-prefixed), which is out of scope -- exercises the bailout
    #    path rather than guessing at a length.
    unsupported_prefix_payload = bytes([0xC0, 0xC0, 0x01, 1, 2, 0x46])
    unsupported_frame = dnp3_link_frame(source=1, destination=1024, user_data=unsupported_prefix_payload)
    tcp5 = tcp_header(51500, 20000, 5003, 6000, TCP_PSH | TCP_ACK, len(unsupported_frame)) + unsupported_frame
    ip5 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp5), 0x2004) + tcp5
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip5)

    # 6) Direct Operate request commanding a single CROB (Control Relay Output Block, group 12
    #    var 1) point: qualifier 0x17 (prefix code 1 = 1-byte index, range code 7 = 1-byte count),
    #    count=1, index=7, then the 11-byte CROB itself: control byte 0x43 (trip/close=Close(1),
    #    queue/clear=0, control code=Latch On(3)), count=1, on_time=1000ms, off_time=0ms, status=0
    #    (ignored on a request). This is also >16 logical bytes, so it doubles as another
    #    multi-block CRC reassembly regression case. High security relevance: CROB is literally
    #    how DNP3 issues output commands.
    crob_payload = (
        bytes([0xC0, 0xC0, 0x05]) +               # transport, app control, fc=Direct Operate
        bytes([12, 1, 0x17]) +                     # group=12 var=1 qualifier=0x17
        bytes([0x01]) +                             # count=1
        bytes([0x07]) +                             # 1-byte index=7
        bytes([0x43, 0x01]) + (1000).to_bytes(4, "little") + (0).to_bytes(4, "little") + bytes([0x00])
    )
    assert len(crob_payload) == 19
    crob_frame = dnp3_link_frame(source=1, destination=1024, user_data=crob_payload)
    tcp6 = tcp_header(51500, 20000, 5004, 6000, TCP_PSH | TCP_ACK, len(crob_frame)) + crob_frame
    ip6 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp6), 0x2005) + tcp6
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip6)

    # 7) Two complete data-link frames coalesced into ONE TCP payload (one pcap packet) -- a
    #    real Read Class 0 request immediately followed by a real Direct Operate/CROB request,
    #    reusing the exact same payload bytes as packets 2 and 6 above so this is a pure framing
    #    regression test, not a new decode path. try_parse_dnp3_link_layer alone only ever looks
    #    at the first 10+ bytes of a TCP payload; this exercises the loop in decoder.cpp that
    #    keeps looking for more frames after the first one's own wire bytes are consumed, so the
    #    second frame isn't silently dropped.
    coalesced = dnp3_link_frame(source=1, destination=1024, user_data=read_class0) + \
        dnp3_link_frame(source=1, destination=1024, user_data=crob_payload)
    tcp7 = tcp_header(51500, 20000, 5005, 6000, TCP_PSH | TCP_ACK, len(coalesced)) + coalesced
    ip7 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp7), 0x2006) + tcp7
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip7)

    # 8) & 9) A genuine cross-packet fragment: the SAME Direct Operate/CROB application-layer
    #    bytes as packet 6's crob_payload (minus its own transport byte), split across TWO
    #    data-link frames delivered in two SEPARATE TCP segments/pcap packets -- exercising
    #    Decoder's per-flow reassembly (dnp3_reassembly_/process_dnp3_frame), not the single-TCP-
    #    payload coalescing packet 7 exercises. This is a contrived split for test purposes (a
    #    real 19-byte CROB command would never need to span frames); what's being tested is the
    #    reassembly mechanism itself, which is agnostic to which function code or how the bytes
    #    happen to be divided -- only to FIR/FIN/SEQ continuity. On a fresh flow (new source port)
    #    so it can't interact with packet 4's already-abandoned, never-completed reassembly above.
    #    First frame: transport FIR=1 FIN=0 SEQ=5 (0x85), then app_control+fc+group/var/qualifier+
    #    count+index (7 bytes) -- everything up to but not including the CROB fields themselves.
    crob_app_bytes = crob_payload[1:]  # drop crob_payload's own transport byte (see packet 6 above)
    crob_first_part, crob_second_part = crob_app_bytes[:7], crob_app_bytes[7:]
    assert len(crob_first_part) == 7 and len(crob_second_part) == 11
    frame8_payload = bytes([0x85]) + crob_first_part
    frame8 = dnp3_link_frame(source=1, destination=1024, user_data=frame8_payload)
    tcp8 = tcp_header(51501, 20000, 7000, 8000, TCP_PSH | TCP_ACK, len(frame8)) + frame8
    ip8 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp8), 0x2007) + tcp8
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip8)

    # Second frame, in its own pcap packet: transport FIR=0 FIN=1 SEQ=6 (0x46), then the
    # remaining 11 bytes (the CROB fields) -- completes the fragment on receipt.
    frame9_payload = bytes([0x46]) + crob_second_part
    frame9 = dnp3_link_frame(source=1, destination=1024, user_data=frame9_payload)
    tcp9 = tcp_header(51501, 20000, 7000 + len(frame8), 8000, TCP_PSH | TCP_ACK, len(frame9)) + frame9
    ip9 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp9), 0x2008) + tcp9
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip9)

    # 10) An orphan continuation: a FIR=0 data-link frame on a flow with no reassembly in
    #     progress at all (no FIR=1 start was ever seen on this flow) -- must be left with only
    #     its transport header decoded, and must say so, not silently guess or crash.
    orphan_payload = bytes([0x41]) + bytes([0xDE, 0xAD])  # FIR=0 FIN=1 SEQ=1, then unparsed junk
    orphan_frame = dnp3_link_frame(source=1, destination=1024, user_data=orphan_payload)
    tcp10 = tcp_header(51502, 20000, 9000, 9100, TCP_PSH | TCP_ACK, len(orphan_frame)) + orphan_frame
    ip10 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp10), 0x2009) + tcp10
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip10)

    # 11) & 12) A sequence-number mismatch: frame 11 begins a fragment (FIR=1 FIN=0 SEQ=10), but
    #     frame 12's SEQ jumps to 35 instead of continuing at 11 (SEQ is only 6 bits wide, 0-63) --
    #     the in-progress reassembly must be discarded (not silently concatenated out of order),
    #     with a note explaining why, and frame 12 itself must not be misread as an orphan
    #     continuation either.
    mismatch_first_payload = bytes([0x8A]) + bytes([0xC0, 0x01, 60, 1, 0x06])  # FIR=1 FIN=0 SEQ=10
    mismatch_first = dnp3_link_frame(source=1, destination=1024, user_data=mismatch_first_payload)
    tcp11 = tcp_header(51503, 20000, 10000, 11000, TCP_PSH | TCP_ACK, len(mismatch_first)) + mismatch_first
    ip11 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp11), 0x200A) + tcp11
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip11)

    mismatch_second_payload = bytes([0x63]) + bytes([0xAA, 0xBB])  # FIR=0 FIN=1 SEQ=35, then junk
    mismatch_second = dnp3_link_frame(source=1, destination=1024, user_data=mismatch_second_payload)
    tcp12 = tcp_header(51503, 20000, 10000 + len(mismatch_first), 11000, TCP_PSH | TCP_ACK,
                        len(mismatch_second)) + mismatch_second
    ip12 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp12), 0x200B) + tcp12
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip12)

    # 13) Same Read Class 0 request as packet 2 (read_class0), but with the header CRC
    #     deliberately corrupted (flip every bit of both header CRC bytes) -- exercises
    #     header_crc_valid=false / dnp3_link_crc_valid=false while confirming decoding still
    #     proceeds normally otherwise (destination/source/control are still shown, the
    #     application layer -- unaffected by a corrupted HEADER CRC -- still decodes the same
    #     Read/g60v1 as packet 2). This is the "more severe" CRC failure: a bad header CRC means
    #     destination/source/control/length can't be trusted, unlike a bad block CRC (packet 14
    #     below), which only affects that one block's data.
    good_header_frame = dnp3_link_frame(source=1, destination=1024, user_data=read_class0)
    bad_header_crc_frame = bytearray(good_header_frame)
    bad_header_crc_frame[8] ^= 0xFF
    bad_header_crc_frame[9] ^= 0xFF
    bad_header_crc_frame = bytes(bad_header_crc_frame)
    tcp13 = tcp_header(51500, 20000, 5006, 6000, TCP_PSH | TCP_ACK, len(bad_header_crc_frame)) + bad_header_crc_frame
    ip13 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp13), 0x200C) + tcp13
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip13)

    # 14) Same 23-byte multi-block Response as packet 3 (resp_payload), but with ONLY block 2's
    #     CRC deliberately corrupted (block 1's CRC, and the header CRC, are both left genuinely
    #     correct) -- exercises per-block granularity: block_count=2, block_crc_failures=1,
    #     header_crc_valid stays true, dnp3_link_crc_valid is false overall. Object headers still
    #     decode from the (structurally intact -- corrupting a CRC never touches the data bytes
    #     it covers) bytes regardless, same degrade-gracefully philosophy as everywhere else in
    #     this decoder.
    good_multiblock_frame = dnp3_link_frame(source=1024, destination=1, user_data=resp_payload)
    bad_block_crc_frame = bytearray(good_multiblock_frame)
    # header(10) + block 1 data(16) + block 1 CRC(2) + block 2 data(7) = offset of block 2's own
    # 2-byte CRC (resp_payload is 23 bytes: a 16-byte block 1 and a 7-byte block 2).
    block2_crc_offset = 10 + 16 + 2 + 7
    bad_block_crc_frame[block2_crc_offset] ^= 0xFF
    bad_block_crc_frame[block2_crc_offset + 1] ^= 0xFF
    bad_block_crc_frame = bytes(bad_block_crc_frame)
    tcp14 = tcp_header(20000, 51500, 6001, 6100, TCP_PSH | TCP_ACK, len(bad_block_crc_frame)) + bad_block_crc_frame
    ip14 = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp14), 0x200D) + tcp14
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip14)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_100 + i, i * 1000)
    (TESTS_DIR / "sample_dnp3.pcap").write_bytes(data)


IEC104_PORT = 2404

# U-format function-byte constants (bytes 1 of the 4-byte control field; bytes 2-4 are always
# zero) -- see iec104.hpp/try_parse_iec104_apci.
IEC104_STARTDT_ACT, IEC104_STARTDT_CON = 0x07, 0x0B
IEC104_STOPDT_ACT, IEC104_STOPDT_CON = 0x13, 0x23
IEC104_TESTFR_ACT, IEC104_TESTFR_CON = 0x43, 0x83


def iec104_i_control(ns: int, nr: int) -> bytes:
    """4-byte I-format control field: N(S) in the first two bytes (low bit of byte 1 fixed 0),
    N(R) in the last two (same shape)."""
    return bytes([(ns & 0x7F) << 1, (ns >> 7) & 0xFF, (nr & 0x7F) << 1, (nr >> 7) & 0xFF])


def iec104_s_control(nr: int) -> bytes:
    return bytes([0x01, 0x00, (nr & 0x7F) << 1, (nr >> 7) & 0xFF])


def iec104_u_control(function_byte: int) -> bytes:
    return bytes([function_byte, 0x00, 0x00, 0x00])


def iec104_apdu(control: bytes, asdu: bytes = b"") -> bytes:
    """Wraps a 4-byte control field (+ optional ASDU, I-format only) in the 2-byte start+length
    APCI prefix (0x68, then the byte count of everything after it)."""
    assert len(control) == 4
    body = control + asdu
    assert len(body) <= 253
    return bytes([0x68, len(body)]) + body


def iec104_cot_byte(cot_code: int, test: bool = False, negative: bool = False) -> int:
    return (0x80 if test else 0) | (0x40 if negative else 0) | (cot_code & 0x3F)


def cp56time2a(year: int, month: int, day: int, hour: int, minute: int, ms: int,
               iv: bool = False, su: bool = False, dow: int = 0) -> bytes:
    return struct.pack(
        "<HBBBBB",
        ms,
        (minute & 0x3F) | (0x80 if iv else 0),
        (hour & 0x1F) | (0x80 if su else 0),
        (day & 0x1F) | ((dow & 0x07) << 5),
        month & 0x0F,
        (year - 2000) & 0x7F,
    )


def cp24time2a(minute: int, ms: int, iv: bool = False) -> bytes:
    return struct.pack(
        "<HB",
        ms,
        (minute & 0x3F) | (0x80 if iv else 0),
    )


def iec104_asdu(type_id: int, vsq: int, cot_code: int, casdu: int, object_bytes: bytes,
                 test: bool = False, negative: bool = False, originator: int = 0) -> bytes:
    return (bytes([type_id, vsq, iec104_cot_byte(cot_code, test, negative), originator]) +
            struct.pack("<H", casdu) + object_bytes)


def ioa(value: int) -> bytes:
    """3-byte little-endian Information Object Address."""
    return struct.pack("<I", value)[:3]


def build_iec104_sample():
    """Exercises U/I/S-format APCI framing, discontinuous and sequential (SQ=1) information
    objects, a time-tagged measured value, a double command activation with a negative
    confirmation, and the S-format supervisory ack -- the APDU shapes real traffic (see
    tests/real_captures/iec104/ATTRIBUTION.md) is dominated by, built by hand so the exact
    expected bytes/values are known rather than inferred from a real capture."""
    packets = []
    client_seq = [3000]
    server_seq = [4000]

    def add(from_client: bool, payload: bytes):
        if from_client:
            src_port, dst_port = 51800, IEC104_PORT
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = IEC104_PORT, 51800
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x3000 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # 1) & 2) STARTDT act/con -- the handshake that begins every real IEC 104 session.
    add(True, iec104_apdu(iec104_u_control(IEC104_STARTDT_ACT)))
    add(False, iec104_apdu(iec104_u_control(IEC104_STARTDT_CON)))

    # 3) General interrogation activation (C_IC_NA_1, QOI=20 "station interrogation general"),
    #    N(S)=0 N(R)=0 -- deliberately the very first I-frame on the session, since N(S)=N(R)=0
    #    is exactly the shape that collides with a Modbus/TCP MBAP header read (see
    #    build_iec104_modbus_precedence_sample below for a minimal fixture pinning that down).
    gi_req = iec104_asdu(100, 0x01, 6, 1, ioa(0) + bytes([20]))
    add(True, iec104_apdu(iec104_i_control(0, 0), gi_req))

    # 4) Activation confirmation, N(S)=0 N(R)=1.
    gi_conf = iec104_asdu(100, 0x01, 7, 1, ioa(0) + bytes([20]))
    add(False, iec104_apdu(iec104_i_control(0, 1), gi_conf))

    # 5) GI data: M_SP_NA_1 (type 1), SQ=1 (sequential IOAs), 3 points starting at IOA 100 --
    #    ON, OFF+IV, ON+BL -- N(S)=1 N(R)=1.
    sp_objects = ioa(100) + bytes([0x01, 0x80, 0x11])
    sp_report = iec104_asdu(1, 0x83, 20, 1, sp_objects)  # vsq: SQ=1 (0x80) | count=3
    add(False, iec104_apdu(iec104_i_control(1, 1), sp_report))

    # 6) A time-tagged measured value (M_ME_TD_1, type 34): IOA 200, normalized value 16384
    #    (fraction 0.5), quality good, CP56Time2a 2024-03-15 10:30:00.500 -- N(S)=2 N(R)=1.
    me_value = struct.pack("<h", 16384) + bytes([0x00]) + cp56time2a(2024, 3, 15, 10, 30, 500)
    me_report = iec104_asdu(34, 0x01, 3, 1, ioa(200) + me_value)  # COT=3 spontaneous
    add(False, iec104_apdu(iec104_i_control(2, 1), me_report))

    # 7) Double command activation (C_DC_NA_1, type 46): IOA 300, DCS=ON(2), QU=short pulse(1),
    #    Execute (S/E=0) -> byte = 2 | (1<<2) = 0x06 -- N(S)=1 N(R)=3.
    dc_req = iec104_asdu(46, 0x01, 6, 1, ioa(300) + bytes([0x06]))
    add(True, iec104_apdu(iec104_i_control(1, 3), dc_req))

    # 8) Negative activation confirmation (COT test/P-N bit set): the RTU refuses the command --
    #    N(S)=3 N(R)=2. Echoes the same DCO byte, as real devices do.
    dc_conf = iec104_asdu(46, 0x01, 7, 1, ioa(300) + bytes([0x06]), negative=True)
    add(False, iec104_apdu(iec104_i_control(3, 2), dc_conf))

    # 9) S-format supervisory ack from the client, N(R)=4 -- no ASDU, nothing to decode above
    #    the APCI itself.
    add(True, iec104_apdu(iec104_s_control(4)))

    # 10) & 11) TESTFR act/con -- the periodic keepalive real sessions send throughout their
    #     lifetime, not just at the start.
    add(True, iec104_apdu(iec104_u_control(IEC104_TESTFR_ACT)))
    add(False, iec104_apdu(iec104_u_control(IEC104_TESTFR_CON)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_001_000 + i, i * 1000)
    (TESTS_DIR / "sample_iec104.pcap").write_bytes(data)


def build_iec104_extended_types_sample():
    """Exercises every one of the 21 ASDU type IDs added to the information-element decode table
    alongside the original set covered by build_iec104_sample: step position (VTI), bitstring-of-
    32-bit (BSI) monitoring and command, the CP24Time2a-tagged measured-value/integrated-totals
    variants, the normalized-value-without-quality-descriptor variant, the time-tagged regulating-
    step and scaled-setpoint commands, delay acquisition, test command with time tag, and
    parameter-of-measured-value/parameter-activation -- one spontaneous report (COT=3) per
    monitoring type and one activation (COT=6) per command/parameter type, each with a single
    hand-picked object whose expected decoded string is computed in the comment right above it
    (the same one CMakeLists.txt's iec104_*_decoded tests assert against). Starts with the same
    STARTDT act/con handshake build_iec104_sample uses."""
    packets = []
    client_seq = [5000]
    server_seq = [6000]
    client_ns = [0]  # client's own N(S), incremented after each I-frame it sends
    client_nr = [0]  # client's N(R): count of I-frames received so far from the server
    server_ns = [0]  # server's own N(S)
    server_nr = [0]  # server's N(R): count of I-frames received so far from the client

    def add_tcp(from_client: bool, payload: bytes):
        if from_client:
            src_port, dst_port = 51900, IEC104_PORT
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = IEC104_PORT, 51900
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x7000 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    def add_u(from_client: bool, function_byte: int):
        add_tcp(from_client, iec104_apdu(iec104_u_control(function_byte)))

    def add_i(from_client: bool, asdu: bytes):
        if from_client:
            control = iec104_i_control(client_ns[0], client_nr[0])
            client_ns[0] += 1
            server_nr[0] = client_ns[0]
        else:
            control = iec104_i_control(server_ns[0], server_nr[0])
            server_ns[0] += 1
            client_nr[0] = server_ns[0]
        add_tcp(from_client, iec104_apdu(control, asdu))

    # 1) & 2) STARTDT act/con -- same handshake build_iec104_sample opens with.
    add_u(True, IEC104_STARTDT_ACT)
    add_u(False, IEC104_STARTDT_CON)

    # M_ST_NA_1 (type 5): IOA 500, position=-10, transient, quality good. VTI = 7-bit two's
    # complement -10 (0x76) with the transient bit (0x80) set -> 0xF6; QDS=0x00.
    add_i(False, iec104_asdu(5, 0x01, 3, 1, ioa(500) + bytes([0xF6, 0x00])))

    # M_ST_TA_1 (type 6): IOA 501, position=50 (not transient), quality good, CP24Time2a
    # minute=15 ms=12345 ("15:12.345").
    add_i(False, iec104_asdu(6, 0x01, 3, 1, ioa(501) + bytes([0x32, 0x00]) + cp24time2a(15, 12345)))

    # M_ST_TB_1 (type 32): IOA 502, position=-1 (0x7F, not transient), QDS=0x01 (OV flag), CP56Time2a
    # 2024-06-01 08:45:06.789.
    add_i(False, iec104_asdu(32, 0x01, 3, 1,
                              ioa(502) + bytes([0x7F, 0x01]) + cp56time2a(2024, 6, 1, 8, 45, 6789)))

    # M_BO_NA_1 (type 7): IOA 600, bitstring=0xDEADBEEF, quality good.
    add_i(False, iec104_asdu(7, 0x01, 3, 1, ioa(600) + struct.pack("<I", 0xDEADBEEF) + bytes([0x00])))

    # M_BO_TA_1 (type 8): IOA 601, bitstring=0x0000FFFF, QDS=0x80 (IV flag), CP24Time2a
    # minute=59 ms=59999 ("59:59.999").
    add_i(False, iec104_asdu(8, 0x01, 3, 1,
                              ioa(601) + struct.pack("<I", 0x0000FFFF) + bytes([0x80]) + cp24time2a(59, 59999)))

    # M_BO_TB_1 (type 33): IOA 602, bitstring=0x12345678, quality good, CP56Time2a
    # 2025-12-31 23:59:59.000 with the summer-time (SU) flag set.
    add_i(False, iec104_asdu(33, 0x01, 3, 1,
                              ioa(602) + struct.pack("<I", 0x12345678) + bytes([0x00]) +
                              cp56time2a(2025, 12, 31, 23, 59, 59000, su=True)))

    # M_ME_TA_1 (type 10): IOA 700, normalized value 8192 (fraction 0.25), quality good,
    # CP24Time2a minute=30 ms=0 ("30:00.000").
    add_i(False, iec104_asdu(10, 0x01, 3, 1,
                              ioa(700) + struct.pack("<h", 8192) + bytes([0x00]) + cp24time2a(30, 0)))

    # M_ME_TB_1 (type 12): IOA 701, scaled value -1234, QDS=0x01 (OV flag), CP24Time2a
    # minute=1 ms=1000 with the IV time-invalid flag set ("01:01.000 [IV]").
    add_i(False, iec104_asdu(12, 0x01, 3, 1,
                              ioa(701) + struct.pack("<h", -1234) + bytes([0x01]) + cp24time2a(1, 1000, iv=True)))

    # M_ME_TC_1 (type 14): IOA 702, short-float value 100.5, quality good, CP24Time2a
    # minute=45 ms=45123 ("45:45.123").
    add_i(False, iec104_asdu(14, 0x01, 3, 1,
                              ioa(702) + struct.pack("<f", 100.5) + bytes([0x00]) + cp24time2a(45, 45123)))

    # M_IT_TA_1 (type 16): IOA 703, counter value 123456, seq=5 with the CY (carry) flag set
    # (sq byte = 5 | 0x20 = 0x25), CP24Time2a minute=10 ms=500 ("10:00.500").
    add_i(False, iec104_asdu(16, 0x01, 3, 1,
                              ioa(703) + struct.pack("<i", 123456) + bytes([0x25]) + cp24time2a(10, 500)))

    # M_ME_ND_1 (type 21): IOA 704, normalized value -16384 (fraction -0.5) -- no QDS byte
    # follows at all, unlike every other M_ME_* case.
    add_i(False, iec104_asdu(21, 0x01, 3, 1, ioa(704) + struct.pack("<h", -16384)))

    # C_BO_NA_1 (type 51): IOA 800, bitstring command=0xFFFFFFFF, activation.
    add_i(True, iec104_asdu(51, 0x01, 6, 1, ioa(800) + struct.pack("<I", 0xFFFFFFFF)))

    # C_RC_TA_1 (type 60): IOA 801, RCO byte 0x0A = state 2 ("step up/higher") | qualifier=2
    # ("long pulse duration") << 2 | Execute (bit7=0), CP56Time2a 2023-01-01 00:00:00.000.
    add_i(True, iec104_asdu(60, 0x01, 6, 1,
                             ioa(801) + bytes([0x0A]) + cp56time2a(2023, 1, 1, 0, 0, 0)))

    # C_SE_TB_1 (type 62): IOA 802, scaled setpoint 5000, QOS byte 0xB2 = ql=50 | Select
    # (bit7=1), CP56Time2a 2022-07-04 12:00:00.000.
    add_i(True, iec104_asdu(62, 0x01, 6, 1,
                             ioa(802) + struct.pack("<h", 5000) + bytes([0xB2]) +
                             cp56time2a(2022, 7, 4, 12, 0, 0)))

    # C_BO_TA_1 (type 64): IOA 803, bitstring command=0xCAFEBABE, CP56Time2a
    # 2021-11-11 11:11:11.000.
    add_i(True, iec104_asdu(64, 0x01, 6, 1,
                             ioa(803) + struct.pack("<I", 0xCAFEBABE) + cp56time2a(2021, 11, 11, 11, 11, 11000)))

    # C_CD_NA_1 (type 106): IOA 804, delay acquisition command = 5000 ms.
    add_i(True, iec104_asdu(106, 0x01, 6, 1, ioa(804) + struct.pack("<H", 5000)))

    # C_TS_TA_1 (type 107): IOA 805, test sequence=0x55AA, CP56Time2a 2020-02-29 03:03:03.003.
    add_i(True, iec104_asdu(107, 0x01, 6, 1,
                             ioa(805) + struct.pack("<H", 0x55AA) + cp56time2a(2020, 2, 29, 3, 3, 3003)))

    # P_ME_NA_1 (type 110): IOA 900, normalized parameter value 16384 (fraction 0.5), QPM byte
    # 0x41 = KPA=1 ("threshold value") | LPC (bit6, local parameter change).
    add_i(True, iec104_asdu(110, 0x01, 6, 1,
                             ioa(900) + struct.pack("<h", 16384) + bytes([0x41])))

    # P_ME_NB_1 (type 111): IOA 901, scaled parameter value -100, QPM byte 0x83 = KPA=3
    # ("low limit for transmission") | POP (bit7, parameter operation).
    add_i(True, iec104_asdu(111, 0x01, 6, 1,
                             ioa(901) + struct.pack("<h", -100) + bytes([0x83])))

    # P_ME_NC_1 (type 112): IOA 902, short-float parameter value 2.5, QPM byte 0xC4 = KPA=4
    # ("high limit for transmission") | LPC | POP (both bit6 and bit7 set).
    add_i(True, iec104_asdu(112, 0x01, 6, 1,
                             ioa(902) + struct.pack("<f", 2.5) + bytes([0xC4])))

    # P_AC_NA_1 (type 113): IOA 903, QPA=2 ("act/deact of the parameter of the addressed
    # object").
    add_i(True, iec104_asdu(113, 0x01, 6, 1, ioa(903) + bytes([0x02])))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_000 + i, i * 1000)
    (TESTS_DIR / "sample_iec104_extended_types.pcap").write_bytes(data)


def build_iec104_modbus_precedence_sample():
    """Regression fixture for the IEC104-vs-Modbus detection collision found while scoping this
    feature (see the comment on try_parse_iec104_apci in iec104.hpp and the dispatch-order
    comment in decoder.cpp's reassemble_tcp_payload/decode): an I-format APDU with N(S)=N(R)=0
    (the very first data frame of any session) makes its APCI bytes read as a Modbus/TCP MBAP
    header with protocol-id==0 and mbap_length==0, and the ASDU's type-ID/VSQ bytes can land
    exactly where Modbus expects unit-id/function-code (here, VSQ=0x01 reads as Modbus function
    code 1, "Read Coils" -- a plausible, non-zero function code, so Modbus's own reserved-
    function-code-0 guard does not save it). This must be classified as iec104, not modbus --
    IEC104 detection is tried first in Decoder's Auto-mode dispatch specifically because its own
    structural checks (start byte + fixed control-field bit patterns) are a much stronger signal
    than Modbus/TCP's single protocol-id==0 tell."""
    gi_req = iec104_asdu(100, 0x01, 6, 1, ioa(0) + bytes([20]))
    payload = iec104_apdu(iec104_i_control(0, 0), gi_req)
    tcp = tcp_header(51801, IEC104_PORT, 12000, 13000, TCP_PSH | TCP_ACK, len(payload)) + payload
    ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), 0x4000) + tcp
    eth = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip

    data = pcap_global_header()
    data += pcap_record(eth, 1_700_001_500, 0)
    (TESTS_DIR / "sample_iec104_modbus_precedence.pcap").write_bytes(data)


def udp_header(src_port: int, dst_port: int, payload: bytes) -> bytes:
    """The fixed 8-byte UDP header (src port, dst port, length = header+payload, checksum -- left
    as 0, same as every other checksum field in this file: conduitscope doesn't validate any of
    them) followed by `payload`."""
    return struct.pack("!HHHH", src_port, dst_port, 8 + len(payload), 0) + payload


def build_link_and_transport_layer_sample():
    """Exercises the link/IP-layer "plumbing" this tool recognizes but does not further decode:
    non-IPv4 Ethernet frames (protocol "non-ip") and non-TCP IPv4 payloads (protocol "non-tcp"/
    "udp"), each named when the ethertype/IP-protocol-number is one this tool knows, and left as a
    bare number when it isn't -- see link_layer.hpp's ethertype_name and ipv4.hpp's
    ip_protocol_name. Every frame here is a standalone
    packet (no TCP-style flow/session needed at this layer), so this is one flat list rather than
    a multi-packet session like build_modbus_sample."""
    packets = []

    def add_eth(ethertype: int, payload: bytes):
        eth = eth_header(PLC_MAC, HMI_MAC, ethertype) + payload
        packets.append(eth)

    def add_ip(ip_protocol: int, payload: bytes):
        ip = ipv4_header(HMI_IP, PLC_IP, ip_protocol, len(payload), 0x6000 + len(packets)) + payload
        packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # Non-IPv4 Ethernet frames -- named ethertypes (ARP, PROFINET RT, IEC 61850 GOOSE) and one
    # deliberately unrecognized ethertype (0x9999, not a real IANA/IEEE assignment) to pin down
    # that an unknown ethertype still shows the bare hex number and nothing else, never a guess.
    add_eth(0x0806, bytes(28))                    # ARP (28-byte body, arbitrary content -- not parsed)
    # PROFINET RT (0x8892) IS decoded by this tool now (see build_profinet_sample below) --
    # FrameID 0x1234 falls in a genuinely reserved FrameID range (0x1000-0x7FFF, see
    # profinet.hpp's file header comment), so try_parse_profinet correctly declines it and this
    # still exercises the "recognized ethertype, content not decoded" fallback path, same as
    # before this feature existed.
    add_eth(0x8892, bytes([0x12, 0x34]) + bytes([0xAA] * 18))
    add_eth(0x88B8, bytes([0xBB] * 20))            # IEC 61850-8-1 GOOSE -- content arbitrary, not parsed
    add_eth(0x9999, bytes([0xCC] * 10))            # unrecognized ethertype -- must stay unnamed

    # A non-TCP, non-UDP IPv4 payload that this tool names but still does not further decode --
    # ICMPv6 (IP protocol 58), arbitrary content, named via ip_protocol_name. IP protocol 1
    # (plain ICMP) used to be the example here, but try_parse_icmp now genuinely decodes it (see
    # icmp.hpp/icmp.cpp and tests/sample_icmp.pcap for that dedicated coverage) -- ICMPv6 keeps
    # this packet actually exercising the "recognized-but-not-decoded" fallback path it's meant
    # to test, rather than silently starting to test something else.
    icmpv6 = bytes([0x80, 0x00, 0x00, 0x00]) + bytes([0x01, 0x02, 0x03, 0x04])
    add_ip(58, icmpv6)

    # UDP on EtherNet/IP's own CIP I/O port (2222) -- but only 4 bytes of arbitrary content, far
    # too short to be a genuine Sequenced Address Item (see enip.hpp), so try_parse_cip_io
    # correctly declines this and it falls through to the generic "udp" tag rather than being
    # misdetected -- see tests/sample_enip_cip_io.pcap for actual CIP I/O decoding coverage.
    add_ip(17, udp_header(2222, 55000, bytes([0xDE, 0xAD, 0xBE, 0xEF])))

    # UDP on an arbitrary, unnamed port, and with an empty payload -- exercises both the "no
    # payload" summary wording and the "port not named" case in the same packet.
    add_ip(17, udp_header(51999, 51998, b""))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_900 + i, i * 1000)
    (TESTS_DIR / "sample_link_transport_layers.pcap").write_bytes(data)


def profinet_frame(frame_id: int, payload: bytes, dst: bytes = None, src: bytes = None, vlan_tci=None) -> bytes:
    """One raw-Ethernet PROFINET RT frame: EtherType 0x8892, then a 2-byte big-endian FrameID,
    then `payload` -- see profinet.hpp's file header comment for the wire format. `vlan_tci`, when
    given, inserts an 802.1Q tag (EtherType 0x8100) before the real EtherType, the same
    vlan_tci-optional shape goose_frame/sv_frame/ecat_frame below already use."""
    dst = dst if dst is not None else PLC_MAC
    src = src if src is not None else HMI_MAC
    body = struct.pack("!H", frame_id) + payload
    if vlan_tci is not None:
        return struct.pack("!6s6sHH", dst, src, 0x8100, vlan_tci) + struct.pack("!H", 0x8892) + body
    return eth_header(dst, src, 0x8892) + body


def dcp_block(option: int, suboption: int, data: bytes) -> bytes:
    """One DCP block: Option(1) + Suboption(1) + DCPBlockLength(2, big-endian) + `data`, plus a
    pad byte if `data`'s length is odd (word-alignment -- see profinet.cpp's decode_dcp_blocks)."""
    block = struct.pack("!BBH", option, suboption, len(data)) + data
    if len(data) % 2 != 0:
        block += b"\x00"
    return block


def dcp_pdu(service_id: int, service_type: int, xid: int, blocks: bytes, response_delay: int = 0) -> bytes:
    """A DCP PDU (the bytes immediately after the FrameID): ServiceID(1) + ServiceType(1) +
    Xid(4) + ResponseDelay-or-Reserved(2) + DCPDataLength(2), all big-endian, then `blocks`."""
    return struct.pack("!BBIHH", service_id, service_type, xid, response_delay, len(blocks)) + blocks


def dcp_block_with_prefix(option: int, suboption: int, content: bytes) -> bytes:
    """An Option 0x01/0x02 DCP block carrying the 2-byte BlockInfo/BlockQualifier prefix real
    devices send before the block's actual content in specific (ServiceID, direction)
    combinations -- see profinet.hpp's file header comment's "IMPORTANT wire-format wrinkle"
    paragraph and dcp_block_prefix_len's comment in profinet.cpp. The prefix's own value isn't
    surfaced by this decoder, so an arbitrary placeholder (0x0000) is used here, same as most real
    devices' Get/Identify responses (see tests/real_captures/profinet/ATTRIBUTION.md)."""
    return dcp_block(option, suboption, struct.pack("!H", 0x0000) + content)


def build_profinet_sample():
    """PROFINET RT (EtherType 0x8892): DCP (Discovery and Configuration Protocol) request/response
    exchanges and cyclic real-time IO data frames. See profinet.hpp's file header comment for the
    exact wire format each packet below exercises (independently cross-checked against Wireshark's
    packet-pn-rt.c/packet-pn-dcp.c dissector sources, not reverse-engineered from a single
    example), and tests/real_captures/profinet/ATTRIBUTION.md for why there's no real-capture
    coverage alongside this synthetic fixture."""
    packets = []

    def add(frame_id, payload, dst=None, src=None):
        packets.append(profinet_frame(frame_id, payload, dst, src))

    # 1) DCP Identify Request (multicast) -- an "All Selector" block (Option 0xFF, Suboption
    #    0xFF, zero-length), the real shape a PROFINET engineering tool broadcasts to discover
    #    every device on the segment. Option 0xFF/Suboption 0xFF isn't in this decoder's known
    #    block table, so its (empty) value is shown as raw hex -- exercises the "block not
    #    decoded" note path.
    xid = 0x00112233
    add(0xFEFE, dcp_pdu(5, 0, xid, dcp_block(0xFF, 0xFF, b"")))

    # 2) DCP Identify Response (unicast) replying to the request above -- same Xid, ServiceType=1
    #    (Response-Success), and every one of this decoder's five value-decoded block types in one
    #    PDU: MACAddress, IPParameter, NameOfStation (deliberately an ODD-length string, "plc-1",
    #    forcing the pad byte before the next block -- if that padding were wrong, DeviceID/
    #    DeviceRole below would misparse), DeviceID, DeviceRole. An Identify Response is one of the
    #    (ServiceID, direction) combinations that carries a 2-byte BlockInfo prefix before each
    #    Option 0x01/0x02 block's actual content (see dcp_block_with_prefix), confirmed against a
    #    real device's own Identify Response bytes -- see tests/real_captures/profinet/
    #    ATTRIBUTION.md.
    resp_blocks = (
        dcp_block_with_prefix(0x01, 0x01, PLC_MAC) +
        dcp_block_with_prefix(0x01, 0x02, bytes([192, 168, 1, 10]) + bytes([255, 255, 255, 0]) + bytes([192, 168, 1, 1])) +
        dcp_block_with_prefix(0x02, 0x02, b"plc-1") +
        dcp_block_with_prefix(0x02, 0x03, struct.pack("!HH", 0x002A, 0x0101)) +
        dcp_block_with_prefix(0x02, 0x04, bytes([0x01, 0x00]))
    )
    add(0xFEFF, dcp_pdu(5, 1, xid, resp_blocks), dst=HMI_MAC, src=PLC_MAC)

    # 3) DCP Set request carrying an IPParameter block -- the other (ServiceID, direction)
    #    combination that carries a 2-byte prefix (BlockQualifier this time, same 2-byte shape --
    #    see dcp_block_with_prefix), confirmed against a real device's own Set Request bytes.
    set_blocks = dcp_block_with_prefix(
        0x01, 0x02, bytes([192, 168, 1, 20]) + bytes([255, 255, 255, 0]) + bytes([192, 168, 1, 1]))
    add(0xFEFD, dcp_pdu(4, 0, 0x00445566, set_blocks))

    # 4) DCP Hello (device announcement on power-up/link-up) carrying just a NameOfStation block --
    #    Hello is the third (ServiceID, direction) combination that carries the 2-byte BlockInfo
    #    prefix (see dcp_block_prefix_len's comment in profinet.cpp).
    add(0xFEFC, dcp_pdu(6, 0, 0x00998877, dcp_block_with_prefix(0x02, 0x02, b"device-1")))

    # 5) Cyclic RT IO data, unicast (FrameID 0x8001): 8 bytes of IO data, a healthy DataStatus
    #    (Primary, Valid, Run, Ok -- bits 0x01|0x04|0x10|0x20 = 0x35), TransferStatus=0 (OK).
    add(0x8001, bytes(range(1, 9)) + struct.pack("!HBB", 0x1234, 0x35, 0x00))

    # 6) Cyclic RT IO data, multicast (FrameID 0xBC00, the first multicast FrameID): a
    #    backup/invalid/stopped/problem DataStatus with the Ignore bit set (0x80) and a nonzero
    #    TransferStatus -- exercises the "bad status"/"ignore this frame" wording.
    add(0xBC00, bytes([0xAA, 0xBB, 0xCC, 0xDD]) + struct.pack("!HBB", 0x5678, 0x80, 0x01))

    # 7) Cyclic RT IO data with NO IO data at all (frame is exactly the 4-byte trailer) --
    #    exercises the "no IO data present" note.
    add(0x8002, struct.pack("!HBB", 0x0001, 0x35, 0x00))

    # 8) Alarm High (FrameID 0xFC01) -- a recognized FrameID this groundwork release names but
    #    does not further decode (Alarm frames carry their own block structure, out of scope --
    #    see profinet.hpp's file header comment).
    add(0xFC01, bytes([0x00] * 12))

    # 9) A DCP PDU too short for even the fixed 10-byte header -- must not crash, and must note
    #    the truncation rather than guess at fields that aren't there.
    add(0xFEFD, bytes([0x03, 0x00, 0x01]))

    # 10) A cyclic-range FrameID with fewer than 4 bytes of payload -- too short for even the
    #     trailer; must not crash, and must note the truncation.
    add(0x8003, bytes([0x01, 0x02]))

    # 11) A reserved/unrecognized FrameID (0x1000, start of the 0x1000-0x7FFF reserved range) --
    #     must NOT be misdetected as anything; falls through to the generic "non-ip" ethertype-
    #     name-only report, same as tests/sample_link_transport_layers.pcap's own 0x8892 packet.
    add(0x1000, bytes([0xEE] * 10))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_700 + i, i * 1000)
    (TESTS_DIR / "sample_profinet.pcap").write_bytes(data)


def ber_length(n: int) -> bytes:
    """BER length octets for a content length of `n` bytes -- short form (one byte, 0-127) or
    long form (a byte with the top bit set and the low 7 bits giving how many big-endian length
    bytes follow) -- see goose.cpp's read_ber_length."""
    if n < 128:
        return bytes([n])
    length_bytes = []
    v = n
    while v > 0:
        length_bytes.insert(0, v & 0xFF)
        v >>= 8
    return bytes([0x80 | len(length_bytes)]) + bytes(length_bytes)


def ber_tlv(tag: int, content: bytes) -> bytes:
    """One BER TLV: tag(1) + BER length + content."""
    return bytes([tag]) + ber_length(len(content)) + content


def ber_int(value: int) -> bytes:
    """Minimal-length big-endian two's-complement BER INTEGER content bytes for `value` -- see
    goose.cpp's decode_ber_integer."""
    n_bytes = 1
    while True:
        try:
            return value.to_bytes(n_bytes, "big", signed=True)
        except OverflowError:
            n_bytes += 1


def utctime_bytes(seconds: int, fraction24: int, quality: int) -> bytes:
    """The 8-byte UtcTime encoding: Seconds(4) + Fraction-of-second(3) + TimeQuality(1), all
    big-endian -- see goose.hpp's file header comment's UtcTime paragraph."""
    return struct.pack("!I", seconds) + fraction24.to_bytes(3, "big") + bytes([quality])


# --- GOOSE allData "Data" choice value builders -- see goose.hpp's file header comment's allData
# paragraph for the tag table each of these matches. ------------------------------------------
def data_bool(v: bool) -> bytes: return ber_tlv(0x83, b"\x01" if v else b"\x00")
def data_bitstring(unused: int, bits: bytes) -> bytes: return ber_tlv(0x84, bytes([unused]) + bits)
def data_int(v: int) -> bytes: return ber_tlv(0x85, ber_int(v))
def data_unsigned(v: int) -> bytes: return ber_tlv(0x86, ber_int(v))
def data_float_single(f: float) -> bytes: return ber_tlv(0x87, bytes([8]) + struct.pack("!f", f))
def data_float_double(f: float) -> bytes: return ber_tlv(0x87, bytes([11]) + struct.pack("!d", f))
def data_real_raw(raw: bytes) -> bytes: return ber_tlv(0x88, raw)
def data_octet_string(b: bytes) -> bytes: return ber_tlv(0x89, b)
def data_visible_string(s: str) -> bytes: return ber_tlv(0x8A, s.encode("ascii"))
def data_binary_time_raw(raw: bytes) -> bytes: return ber_tlv(0x8C, raw)
def data_bcd(v: int) -> bytes: return ber_tlv(0x8D, ber_int(v))
def data_boolean_array(unused: int, bits: bytes) -> bytes: return ber_tlv(0x8E, bytes([unused]) + bits)
def data_obj_id_raw(raw: bytes) -> bytes: return ber_tlv(0x8F, raw)
def data_mms_string(s: str) -> bytes: return ber_tlv(0x90, s.encode("ascii"))
def data_utc_time(seconds: int, fraction24: int, quality: int) -> bytes:
    return ber_tlv(0x91, utctime_bytes(seconds, fraction24, quality))
def data_structure(children: bytes) -> bytes: return ber_tlv(0xA2, children)
def data_array(children: bytes) -> bytes: return ber_tlv(0xA1, children)
def data_unrecognized(tag: int, raw: bytes) -> bytes: return ber_tlv(tag, raw)


def goose_pdu(gocb_ref: str, time_allowed_to_live: int, dat_set: str, go_id, t_bytes: bytes,
              st_num: int, sq_num: int, simulation, conf_rev: int, nds_com,
              num_dat_set_entries: int, all_data: bytes) -> bytes:
    """Builds the 0x61-tagged IECGoosePdu -- fields in IECGoosePdu_sequence order (see goose.hpp's
    file header comment). `go_id`/`simulation`/`nds_com` are optional per spec -- pass None to
    omit that field entirely (exercises try_parse_goose's optional-field-absence path).
    `num_dat_set_entries` is passed explicitly, independent of `all_data`'s actual content, so a
    caller can deliberately mismatch them (see decode_goose_pdu's cross-check note)."""
    parts = [
        ber_tlv(0x80, gocb_ref.encode("ascii")),
        ber_tlv(0x81, ber_int(time_allowed_to_live)),
        ber_tlv(0x82, dat_set.encode("ascii")),
    ]
    if go_id is not None:
        parts.append(ber_tlv(0x83, go_id.encode("ascii")))
    parts.append(ber_tlv(0x84, t_bytes))
    parts.append(ber_tlv(0x85, ber_int(st_num)))
    parts.append(ber_tlv(0x86, ber_int(sq_num)))
    if simulation is not None:
        parts.append(ber_tlv(0x87, b"\x01" if simulation else b"\x00"))
    parts.append(ber_tlv(0x88, ber_int(conf_rev)))
    if nds_com is not None:
        parts.append(ber_tlv(0x89, b"\x01" if nds_com else b"\x00"))
    parts.append(ber_tlv(0x8A, ber_int(num_dat_set_entries)))
    parts.append(ber_tlv(0xAB, all_data))
    return ber_tlv(0x61, b"".join(parts))


def goose_frame(appid: int, apdu: bytes, dst: bytes = None, src: bytes = None, vlan_tci=None,
                 reserved1: int = 0, declared_length=None) -> bytes:
    """One raw-Ethernet GOOSE frame: EtherType 0x88B8 (optionally after one 802.1Q VLAN tag when
    `vlan_tci` is given, e.g. real GOOSE traffic's common priority-tagging -- see goose.hpp's file
    header comment), then the 8-byte APPID/Length/Reserved1/Reserved2 header, then `apdu`.
    `declared_length` overrides the header's own Length field when given (for exercising the
    "Length field is implausible" path); it defaults to the real total (8 + len(apdu))."""
    dst = dst if dst is not None else PLC_MAC
    src = src if src is not None else HMI_MAC
    length = declared_length if declared_length is not None else (8 + len(apdu))
    header = struct.pack("!HHHH", appid, length, reserved1, 0) + apdu
    if vlan_tci is not None:
        return struct.pack("!6s6sHH", dst, src, 0x8100, vlan_tci) + struct.pack("!H", 0x88B8) + header
    return eth_header(dst, src, 0x88B8) + header


def build_goose_sample():
    """IEC 61850-8-1 GOOSE (EtherType 0x88B8): the ASN.1 BER-encoded GOOSE PDU (gocbRef/datSet/
    goID/timestamp/stNum/sqNum/simulation/confRev/ndsCom/allData) and the allData dataset's own
    recursive "Data" values. See goose.hpp's file header comment for the exact wire format each
    packet below exercises (independently cross-checked against Wireshark's packet-goose.c, not
    reverse-engineered from a single example), and tests/real_captures/goose/ATTRIBUTION.md for
    which of these paths a real capture also validates vs. which are synthetic-only."""
    packets = []
    ts_field = utctime_bytes(0x386EBBF3, 0x421728, 0x0A)  # a real device's own 't' bytes (see
                                                            # tests/real_captures/goose/ATTRIBUTION.md)

    # 1) A baseline full-field GOOSE PDU -- every field present (including the three optional
    #    ones), boolean + bit-string allData, matching the shape every real capture checked while
    #    building this decoder actually used (see ATTRIBUTION.md).
    all_data_1 = data_bool(False) + data_bitstring(3, bytes([0x00, 0x00])) + data_bool(True) + data_bitstring(3, bytes([0x20, 0x00]))
    pdu1 = goose_pdu("IED1/LLN0$GO$gcb01", 2000, "IED1/LLN0$GOOSE1", "gcb01", ts_field,
                      1, 1, False, 1, False, 4, all_data_1)
    packets.append(goose_frame(0x0001, pdu1))

    # 2) Every optional field (goID, simulation, ndsCom) OMITTED entirely -- exercises
    #    try_parse_goose's optional-field-absence path (spec-legal; no real capture checked ever
    #    did this -- see ATTRIBUTION.md).
    pdu2 = goose_pdu("IED1/LLN0$GO$gcb02", 2000, "IED1/LLN0$GOOSE2", None, ts_field,
                      1, 1, None, 1, None, 1, data_bool(True))
    packets.append(goose_frame(0x0002, pdu2))

    # 3) Header S-bit set ("Simulated") but the PDU's own simulation field is explicitly false --
    #    the inconsistency Wireshark's own ei_goose_invalid_sim flags (see goose.hpp's file header
    #    comment and try_parse_goose's mismatch note).
    pdu3 = goose_pdu("IED1/LLN0$GO$gcb03", 2000, "IED1/LLN0$GOOSE3", None, ts_field,
                      1, 1, False, 1, None, 1, data_bool(False))
    packets.append(goose_frame(0x0003, pdu3, reserved1=0x8000))

    # 4) Header S-bit set AND the PDU's own simulation field true -- consistent, no mismatch note;
    #    goose_simulated ends up true either way.
    pdu4 = goose_pdu("IED1/LLN0$GO$gcb04", 2000, "IED1/LLN0$GOOSE4", None, ts_field,
                      1, 1, True, 1, None, 1, data_bool(False))
    packets.append(goose_frame(0x0004, pdu4, reserved1=0x8000))

    # 5) Every allData "Data" choice type this decoder value-decodes that no real capture checked
    #    ever exercised (see ATTRIBUTION.md): integer (negative, to exercise sign-extension),
    #    unsigned, bcd, floating-point single AND double precision, octet-string, visible-string,
    #    mMSString, and a nested utc-time value.
    all_data_5 = (
        data_int(-5) + data_unsigned(70000) + data_bcd(42) +
        data_float_single(3.5) + data_float_double(-2.25) +
        data_octet_string(bytes([0xDE, 0xAD, 0xBE, 0xEF])) +
        data_visible_string("hello") + data_mms_string("world") +
        data_utc_time(0x386EBBF3, 0x800000, 0x27)
    )
    pdu5 = goose_pdu("IED2/LLN0$GO$gcb05", 5000, "IED2/LLN0$GOOSE5", "gcb05", ts_field,
                      3, 1, None, 2, None, 9, all_data_5)
    packets.append(goose_frame(0x1005, pdu5))

    # 6) Nested structure/array -- a structure of [boolean, integer] followed by an array of two
    #    floating-point values -- exercises decode_data_sequence's recursion and the dotted
    #    "N.M" path scheme (GooseDataValue::path).
    inner_structure = data_bool(True) + data_int(7)
    inner_array = data_float_single(1.5) + data_float_single(2.5)
    all_data_6 = data_structure(inner_structure) + data_array(inner_array)
    pdu6 = goose_pdu("IED2/LLN0$GO$gcb06", 5000, "IED2/LLN0$GOOSE6", None, ts_field,
                      1, 1, None, 1, None, 2, all_data_6)
    packets.append(goose_frame(0x1006, pdu6))

    # 7) Types this decoder recognizes by name but deliberately never value-decodes (real ASN.1
    #    REAL, binary-time, objId -- see goose.hpp's file header comment), plus one entirely
    #    unrecognized tag (0x95) -- all four show as raw hex, and the unrecognized one also
    #    triggers a "tag not recognized" note (type_name left empty).
    all_data_7 = (
        data_real_raw(bytes([0x01, 0x02, 0x03])) +
        data_binary_time_raw(bytes([0x00, 0x00, 0x00, 0x01])) +
        data_obj_id_raw(bytes([0x28, 0x01, 0x02])) +
        data_unrecognized(0x95, bytes([0xFF, 0xEE]))
    )
    pdu7 = goose_pdu("IED2/LLN0$GO$gcb07", 5000, "IED2/LLN0$GOOSE7", None, ts_field,
                      1, 1, None, 1, None, 4, all_data_7)
    packets.append(goose_frame(0x1007, pdu7))

    # 8) numDatSetEntries declares 5 but allData actually carries only 2 top-level values --
    #    exercises decode_goose_pdu's mismatch-count note.
    pdu8 = goose_pdu("IED2/LLN0$GO$gcb08", 5000, "IED2/LLN0$GOOSE8", None, ts_field,
                      1, 1, None, 1, None, 5, data_bool(True) + data_bool(False))
    packets.append(goose_frame(0x1008, pdu8))

    # 9) A GSE Management PDU (outer APDU tag 0xA0, GetReferenceRequest/Response -- an
    #    engineering-tool query/response exchange) -- named only, not decoded further; out of this
    #    release's scope (see goose.hpp's file header comment).
    gse_mgmt_apdu = ber_tlv(0xA0, bytes([0x80, 0x02, 0x00, 0x01]))  # arbitrary placeholder content
    packets.append(goose_frame(0x2000, gse_mgmt_apdu))

    # 10) 802.1Q VLAN-priority-tagged GOOSE, and a multicast destination MAC in the well-known
    #     GOOSE range (01-0C-CD-01-xx-xx) -- real GOOSE traffic's common framing (see goose.hpp's
    #     file header comment and tests/real_captures/goose/ATTRIBUTION.md's VLAN-tagged real
    #     frame), confirming parse_ethernet's single-VLAN-tag unwrap composes correctly with GOOSE
    #     detection (mirroring PROFINET RT's own untagged-only synthetic coverage -- this is
    #     GOOSE's dedicated VLAN test).
    pdu10 = goose_pdu("IED3/LLN0$GO$gcb10", 2000, "IED3/LLN0$GOOSE10", None, ts_field,
                       1, 1, None, 1, None, 1, data_bool(True))
    packets.append(goose_frame(0x3001, pdu10, dst=bytes.fromhex("010ccd010001"),
                                src=bytes.fromhex("000c291a2b3c"), vlan_tci=0x8000))

    # 11) Header too short for even the fixed 8-byte APPID/Length/Reserved1/Reserved2 -- must not
    #     crash, falls through to the generic "non-ip" ethertype-name-only report.
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x88B8) + bytes([0x00, 0x01, 0x00, 0x02]))

    # 12) A full 8-byte header but the byte immediately after it is neither 0x61 nor 0xA0 -- must
    #     NOT be misdetected as GOOSE; falls through to the generic "non-ip" report, same as
    #     tests/sample_link_transport_layers.pcap's own 0x88B8 packet (arbitrary 0xBB bytes).
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x88B8) + struct.pack("!HHHH", 0x0009, 10, 0, 0) +
                    bytes([0x99, 0x01, 0x02, 0x03]))

    # 13) Length field declares fewer than 8 bytes (bogus per packet-goose.c's own
    #     ei_goose_bogus_length check) -- falls back to "use all available bytes instead", still
    #     decodes correctly, with a note.
    pdu13 = goose_pdu("IED4/LLN0$GO$gcb13", 2000, "IED4/LLN0$GOOSE13", None, ts_field,
                       1, 1, None, 1, None, 1, data_bool(True))
    packets.append(goose_frame(0x1013, pdu13, declared_length=3))

    # 14) The outer APDU TLV's own declared length exceeds what's actually present (a
    #     snaplen-truncated capture, most plausibly) -- decodes nothing from the PDU fields
    #     (there's nothing complete to decode) but is still confidently recognized as "goose"
    #     rather than falling back to "non-ip", with a truncation note. Built by hand rather than
    #     via goose_pdu/goose_frame, since this needs a genuinely inconsistent outer length.
    truncated_apdu = bytes([0x61]) + ber_length(200) + ber_tlv(0x80, b"IED5/LLN0$GO$gcb14")
    packets.append(goose_frame(0x1014, truncated_apdu))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_800 + i, i * 1000)
    (TESTS_DIR / "sample_goose.pcap").write_bytes(data)


def build_goose_deep_nesting_sample():
    """A single GOOSE frame whose allData is a structure nested three levels deep around one
    boolean leaf (structure > structure > structure > boolean) -- deep enough that
    --max-recursion-depth 1 visibly truncates it (see resource_limits.hpp/goose.cpp's
    max_goose_data_depth(), default 6) while every OTHER GOOSE fixture's allData (see
    build_goose_sample() above, at most one level deep) is too shallow to demonstrate that flag's
    effect at any CLI-representable value (0 means "unset/default", so a 1-level-deep structure
    can't be truncated at cap=1 either). Kept as its own tiny, dedicated fixture -- not folded
    into build_goose_sample() -- so existing GOOSE tests' packet indices/expectations are
    untouched. See CMakeLists.txt's max_recursion_depth_goose_truncates test, added alongside
    docs/DEVELOPMENT.md's item 7 "Update: implemented" entry."""
    ts_field = utctime_bytes(0x386EBBF3, 0x421728, 0x0A)
    innermost = data_bool(True)
    level2 = data_structure(innermost)  # depth 2
    level1 = data_structure(level2)     # depth 1
    all_data = data_structure(level1)   # depth 0 (top-level allData entry)
    pdu = goose_pdu("IEDX/LLN0$GO$gcbDeep", 2000, "IEDX/LLN0$GOOSEDeep", None, ts_field,
                     1, 1, None, 1, None, 1, all_data)
    frame = goose_frame(0x2001, pdu)
    data = pcap_global_header() + pcap_record(frame, 0, 0)
    (TESTS_DIR / "sample_goose_deep_nesting.pcap").write_bytes(data)


def sv_asdu(sv_id: str, smp_cnt: int, conf_rev: int, seq_data: bytes, dat_set=None, refr_tm=None,
            smp_synch=None, smp_rate=None, smp_mod=None, gmid=None) -> bytes:
    """Builds one 0x30-tagged (UNIVERSAL SEQUENCE) ASDU element -- ASDU_sequence field order (see
    sv.hpp's file header comment's ASDU field table). `dat_set`/`refr_tm`/`smp_synch`/`smp_rate`/
    `smp_mod`/`gmid` are all OPTIONAL per spec -- pass None (the default) to omit that field
    entirely (exercises try_parse_sv's optional-field-absence path). `refr_tm` and `gmid`, when
    given, are already-encoded byte strings (8 bytes each -- see utctime_bytes for refr_tm)."""
    parts = [ber_tlv(0x80, sv_id.encode("ascii"))]
    if dat_set is not None:
        parts.append(ber_tlv(0x81, dat_set.encode("ascii")))
    parts.append(ber_tlv(0x82, ber_int(smp_cnt)))
    parts.append(ber_tlv(0x83, ber_int(conf_rev)))
    if refr_tm is not None:
        parts.append(ber_tlv(0x84, refr_tm))
    if smp_synch is not None:
        parts.append(ber_tlv(0x85, ber_int(smp_synch)))
    if smp_rate is not None:
        parts.append(ber_tlv(0x86, ber_int(smp_rate)))
    parts.append(ber_tlv(0x87, seq_data))
    if smp_mod is not None:
        parts.append(ber_tlv(0x88, ber_int(smp_mod)))
    if gmid is not None:
        parts.append(ber_tlv(0x89, gmid))
    return ber_tlv(0x30, b"".join(parts))


def sv_sav_pdu(asdus, no_asdu=None) -> bytes:
    """Builds the 0x60-tagged SampledValues/SavPdu: noASDU + seqASDU, `asdus` being a list of
    already-encoded sv_asdu() elements (see sv.hpp's file header comment). `no_asdu` overrides the
    declared noASDU count when given, independent of len(asdus) -- for deliberately exercising
    decode_sav_pdu's mismatch-count note; defaults to len(asdus)."""
    n = no_asdu if no_asdu is not None else len(asdus)
    parts = [ber_tlv(0x80, ber_int(n)), ber_tlv(0xA2, b"".join(asdus))]
    return ber_tlv(0x60, b"".join(parts))


def sv_frame(appid: int, apdu: bytes, dst: bytes = None, src: bytes = None, vlan_tci=None,
             reserved1: int = 0, declared_length=None) -> bytes:
    """One raw-Ethernet SV frame: EtherType 0x88BA, with the identical 8-byte APPID/Length/
    Reserved1/Reserved2 header goose_frame uses (SV and GOOSE share this header shape -- see
    sv.hpp's file header comment). Same optional-VLAN-tag/declared_length-override behavior as
    goose_frame."""
    dst = dst if dst is not None else PLC_MAC
    src = src if src is not None else HMI_MAC
    length = declared_length if declared_length is not None else (8 + len(apdu))
    header = struct.pack("!HHHH", appid, length, reserved1, 0) + apdu
    if vlan_tci is not None:
        return struct.pack("!6s6sHH", dst, src, 0x8100, vlan_tci) + struct.pack("!H", 0x88BA) + header
    return eth_header(dst, src, 0x88BA) + header


def build_sv_sample():
    """IEC 61850-9-2 Sampled Values (EtherType 0x88BA): the ASN.1 BER-encoded SavPdu (noASDU +
    one or more ASDU elements) and each ASDU's own svID/datSet/smpCnt/confRev/refrTm/smpSynch/
    smpRate/seqData/smpMod/gmidData fields. See sv.hpp's file header comment for the exact wire
    format each packet below exercises (cross-checked against Wireshark's packet-sv.c) -- no real
    SV capture was found despite a genuine search (see sv.hpp's Validation paragraph), so every
    path here is synthetic-only, unlike GOOSE's real-capture-corroborated fixture."""
    packets = []
    refr_tm = utctime_bytes(0x386EBBF3, 0x421728, 0x0A)  # arbitrary but plausible UtcTime bytes,
                                                            # same encoding goose.hpp's UtcTime
                                                            # paragraph documents

    # 1) A baseline full-field ASDU -- every optional field present (datSet, refrTm, smpSynch=
    #    global, smpRate, smpMod=samplesPerNormalPeriod, gmidData), a plausible 9-2LE-shaped
    #    64-byte seqData (8 channels x (4-byte value + 4-byte quality), though this decoder never
    #    interprets it that way -- see sv.hpp's seqData paragraph).
    seq_data_1 = bytes(64)
    gmid_1 = bytes.fromhex("0019FBFFFE001122")  # vendor OUI 00:19:FB + 0xFFFE + card ID, the
                                                  # EUI-64 shape dissect_sv_GmidData checks for
    asdu1 = sv_asdu("IED1/MSVCB01", 1234, 1, seq_data_1, dat_set="IED1/LLN0$MEAS1", refr_tm=refr_tm,
                     smp_synch=2, smp_rate=4000, smp_mod=0, gmid=gmid_1)
    packets.append(sv_frame(0x4000, sv_sav_pdu([asdu1])))

    # 2) Every optional field (datSet, refrTm, smpSynch, smpRate, smpMod, gmidData) OMITTED
    #    entirely -- exercises try_parse_sv's optional-field-absence path (spec-legal).
    asdu2 = sv_asdu("IED1/MSVCB02", 5678, 1, bytes(8))
    packets.append(sv_frame(0x4001, sv_sav_pdu([asdu2])))

    # 3) Two ASDUs in one seqASDU (noASDU=2) -- a merging unit publishing two logical streams in
    #    one frame; smpSynch=local on the first, smpSynch=none on the second, exercising both
    #    enumerated values plus multi-ASDU decoding/summarization (sv_asdus).
    asdu3a = sv_asdu("IED2/MSVCB01", 100, 3, bytes(8), smp_synch=1)
    asdu3b = sv_asdu("IED2/MSVCB02", 200, 3, bytes(8), smp_synch=0)
    packets.append(sv_frame(0x4002, sv_sav_pdu([asdu3a, asdu3b])))

    # 4) Header S-bit set ("Simulated") -- unlike GOOSE, SV's ASDU has no PDU-level simulation
    #    field to cross-check against (see sv.hpp's file header comment), so this is simply
    #    sv_simulated=true with no consistency note to make.
    asdu4 = sv_asdu("IED1/MSVCB04", 1, 1, bytes(8))
    packets.append(sv_frame(0x4003, sv_sav_pdu([asdu4]), reserved1=0x8000))

    # 5) smpSynch and smpMod both carrying a value outside the recognized enumeration (5) --
    #    rendered as "unknown(5)" rather than guessed at or dropped.
    asdu5 = sv_asdu("IED1/MSVCB05", 1, 1, bytes(8), smp_synch=5, smp_mod=5)
    packets.append(sv_frame(0x4004, sv_sav_pdu([asdu5])))

    # 6) smpMod=samplesPerSecond(1) and smpMod=secondsPerSample(2) -- the two enumerated values
    #    packet 1/5 above don't already cover -- one ASDU each, to keep every enumerated value
    #    individually attributable in the decoded output.
    asdu6a = sv_asdu("IED1/MSVCB06", 1, 1, bytes(8), smp_mod=1)
    packets.append(sv_frame(0x4005, sv_sav_pdu([asdu6a])))
    asdu6b = sv_asdu("IED1/MSVCB07", 1, 1, bytes(8), smp_mod=2)
    packets.append(sv_frame(0x4006, sv_sav_pdu([asdu6b])))

    # 7) noASDU declares 3 but seqASDU actually carries only 2 -- exercises decode_sav_pdu's
    #    mismatch-count note (mirroring GOOSE's numDatSetEntries mismatch test).
    asdu7a = sv_asdu("IED3/MSVCB01", 1, 1, bytes(8))
    asdu7b = sv_asdu("IED3/MSVCB02", 1, 1, bytes(8))
    packets.append(sv_frame(0x4007, sv_sav_pdu([asdu7a, asdu7b], no_asdu=3)))

    # 8) 802.1Q VLAN-priority-tagged SV, multicast to the well-known SV MAC range (01-0C-CD-04-
    #    xx-xx, distinct from GOOSE's 01-0C-CD-01-xx-xx -- see sv.hpp's file header comment and
    #    IEC 61850-8-1's own default multicast address table) -- confirms parse_ethernet's single-
    #    VLAN-tag unwrap composes correctly with SV detection, mirroring GOOSE's own VLAN test.
    asdu8 = sv_asdu("IED4/MSVCB01", 1, 1, bytes(8))
    packets.append(sv_frame(0x5000, sv_sav_pdu([asdu8]), dst=bytes.fromhex("010ccd040001"),
                             src=bytes.fromhex("000c291a2b3c"), vlan_tci=0x8000))

    # 9) Header too short for even the fixed 8-byte APPID/Length/Reserved1/Reserved2 -- must not
    #    crash, falls through to the generic "non-ip" ethertype-name-only report.
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x88BA) + bytes([0x00, 0x01, 0x00, 0x02]))

    # 10) A full 8-byte header but the byte immediately after it is not 0x60 -- must NOT be
    #     misdetected as SV; falls through to the generic "non-ip" report.
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x88BA) + struct.pack("!HHHH", 0x0009, 10, 0, 0) +
                    bytes([0x99, 0x01, 0x02, 0x03]))

    # 11) Length field declares fewer than 8 bytes (bogus, mirroring GOOSE's own test) -- falls
    #     back to "use all available bytes instead", still decodes correctly, with a note.
    asdu11 = sv_asdu("IED5/MSVCB01", 1, 1, bytes(8))
    packets.append(sv_frame(0x4008, sv_sav_pdu([asdu11]), declared_length=3))

    # 12) The outer APDU TLV's own declared length exceeds what's actually present (a plausibly
    #     snaplen-truncated capture) -- decodes nothing from SavPdu's fields (nothing complete to
    #     decode) but is still confidently recognized as "sv" rather than falling back to
    #     "non-ip", with a truncation note. Built by hand, mirroring GOOSE's own test #14.
    truncated_apdu = bytes([0x60]) + ber_length(200) + ber_tlv(0x80, ber_int(1))
    packets.append(sv_frame(0x4009, truncated_apdu))

    # 13) A seqASDU element whose tag is not the expected UNIVERSAL SEQUENCE tag (0x30) -- skipped
    #     with a note rather than mis-parsed as an ASDU.
    bogus_sav_pdu = ber_tlv(0x80, ber_int(1)) + ber_tlv(0xA2, ber_tlv(0x31, bytes([0x80, 0x01, 0x41])))
    packets.append(sv_frame(0x400A, ber_tlv(0x60, bogus_sav_pdu)))

    # 14) An unrecognized ASDU field tag (0x8F, not part of ASDU_sequence -- see sv.hpp's file
    #     header comment) -- skipped with a note, raw hex shown, rest of the ASDU still decoded.
    asdu14_content = ber_tlv(0x80, b"IED6/MSVCB01") + ber_tlv(0x82, ber_int(1)) + ber_tlv(0x83, ber_int(1)) + \
                      ber_tlv(0x8F, bytes([0xAA, 0xBB])) + ber_tlv(0x87, bytes(8))
    packets.append(sv_frame(0x400B, ber_tlv(0x60, ber_tlv(0x80, ber_int(1)) +
                                              ber_tlv(0xA2, ber_tlv(0x30, asdu14_content)))))

    # 15) An unrecognized SavPdu-level field tag (context tag 1 -- reserved/unused per
    #     SavPdu_sequence, see sv.hpp's file header comment) -- skipped with a note.
    asdu15 = sv_asdu("IED7/MSVCB01", 1, 1, bytes(8))
    bogus_sav_pdu_2 = ber_tlv(0x81, bytes([0x00])) + ber_tlv(0x80, ber_int(1)) + ber_tlv(0xA2, asdu15)
    packets.append(sv_frame(0x400C, ber_tlv(0x60, bogus_sav_pdu_2)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_003_000 + i, i * 1000)
    (TESTS_DIR / "sample_sv.pcap").write_bytes(data)


def ecat_datagram(cmd: int, idx: int, data: bytes = b"", *, adp: int = 0, ado: int = 0,
                   logical_address: int = None, irq: int = 0, circulating: bool = False,
                   more: bool = False, wkc: int = 0) -> bytes:
    """Builds one 10-byte EcParserHDR header + Data + 2-byte WKC EtherCAT datagram -- see
    ethercat.hpp's file header comment's datagram field table. `cmd` selects the addressing mode:
    for LRD/LWR/LRW (10/11/12) pass `logical_address` (a single 32-bit address); for every other
    Cmd pass `adp`/`ado` (the default, both 0) instead -- whichever doesn't apply to `cmd` is simply
    ignored, matching decode_one_datagram's own `logical_addressing = (cmd in {10,11,12})` switch.
    `more` sets the Len word's More bit (0x8000), chaining this datagram to whatever bytes
    immediately follow it in the same frame -- see decode_datagram_chain. `circulating` sets the Len
    word's Circulating bit (0x4000, "frame has circulated once on a ring segment")."""
    if logical_address is not None:
        address = struct.pack("<I", logical_address)
    else:
        address = struct.pack("<HH", adp, ado)
    len_word = len(data) & 0x07FF
    if circulating:
        len_word |= 0x4000
    if more:
        len_word |= 0x8000
    header = struct.pack("<BB", cmd, idx) + address + struct.pack("<HH", len_word, irq)
    return header + data + struct.pack("<H", wkc)


def ecat_frame(datagrams: bytes, *, frame_type: int = 1, reserved: bool = False,
               declared_length=None, dst: bytes = None, src: bytes = None, vlan_tci=None) -> bytes:
    """One raw-Ethernet EtherCAT frame: EtherType 0x88A4, the 2-byte frame header (Length(11 bits) +
    Reserved(1 bit) + Type(4 bits), all little-endian -- see ethercat.hpp's file header comment),
    followed by `datagrams` (the concatenation of one or more already-encoded ecat_datagram() calls,
    already chained via their own More bits -- meaningful only when frame_type == 1; for any other
    Type, `datagrams` is simply raw, undecoded bytes). `declared_length` overrides the header's own
    Length field independent of len(datagrams), for deliberately exercising the "implausible Length"
    fallback path documented in ethercat.hpp; defaults to len(datagrams) (the honest, correct value
    this decoder's real capture fixture shows in all 986 of 986 real frames -- see Validation)."""
    dst = dst if dst is not None else PLC_MAC
    src = src if src is not None else HMI_MAC
    length = declared_length if declared_length is not None else len(datagrams)
    header_word = (length & 0x07FF) | (0x0800 if reserved else 0) | ((frame_type & 0x0F) << 12)
    payload = struct.pack("<H", header_word) + datagrams
    if vlan_tci is not None:
        return struct.pack("!6s6sHH", dst, src, 0x8100, vlan_tci) + struct.pack("!H", 0x88A4) + payload
    return eth_header(dst, src, 0x88A4) + payload


def build_ethercat_sample():
    """EtherCAT (EtherType 0x88A4): the 2-byte frame header (Length+Reserved+Type) and, for Type 1
    ("EtherCAT command") frames, the chained EtherCAT datagram(s) that follow -- see ethercat.hpp's
    file header comment for the exact wire format each packet below exercises (cross-checked against
    Wireshark's own packet-ethercat-frame.c/packet-ethercat-datagram.c). Packet 1 below reproduces
    tests/real_captures/ethercat/ICS-Ethercat-001.pcap's own frame 0 byte-for-byte (BRD/AL-Status,
    idx=2, adp=0x0000, ado=0x0130, wkc=0), and packet 2 reproduces that same capture's boot-time
    auto-increment topology-discovery chain (Adp 0x0000, 0xFFFF, 0xFFFE, 0xFFFD, 0xFFFC in one
    frame) -- see ethercat.hpp's "Auto increment addressing" paragraph. Every other packet below is
    synthetic-only, covering paths the real capture doesn't happen to exercise (see ethercat.hpp's
    Validation paragraph and tests/real_captures/ethercat/ATTRIBUTION.md)."""
    packets = []

    # 1) Baseline: a single BRD (Broadcast Read) datagram, byte-for-byte identical to the real
    #    capture's own frame 0 (a master polling every slave's AL Status register, ado=0x0130, at
    #    boot) -- see ethercat.hpp's Validation paragraph.
    packets.append(ecat_frame(ecat_datagram(7, 2, bytes(2), adp=0x0000, ado=0x0130, wkc=0)))

    # 2) Five chained APRD (Auto Increment Physical Read) datagrams in one frame, reproducing the
    #    real capture's own boot-time topology-discovery sequence: Adp 0x0000, 0xFFFF, 0xFFFE,
    #    0xFFFD, 0xFFFC -- "whichever slave is first on the segment", then second, third, ... -- see
    #    ethercat.hpp's "Auto increment addressing" paragraph. Exercises the More-bit chain, the
    #    frame summary's "(+N more datagram(s))" suffix, and ethercat_datagram_count == 5.
    topo_chain = b"".join([
        ecat_datagram(1, 10, bytes(2), adp=0x0000, ado=0x0130, wkc=1, more=True),
        ecat_datagram(1, 11, bytes(2), adp=0xFFFF, ado=0x0130, wkc=1, more=True),
        ecat_datagram(1, 12, bytes(2), adp=0xFFFE, ado=0x0130, wkc=1, more=True),
        ecat_datagram(1, 13, bytes(2), adp=0xFFFD, ado=0x0130, wkc=1, more=True),
        ecat_datagram(1, 14, bytes(2), adp=0xFFFC, ado=0x0130, wkc=1, more=False),
    ])
    packets.append(ecat_frame(topo_chain))

    # 3) Logical addressing (LRD/LWR/LRW, cmd 10/11/12) -- each uses a single 32-bit logical address
    #    instead of Adp+Ado, exercising EthercatDatagram::logical_addressing/logical_address.
    packets.append(ecat_frame(ecat_datagram(10, 20, bytes(4), logical_address=0x00010000, wkc=1)))
    packets.append(ecat_frame(ecat_datagram(11, 21, bytes(4), logical_address=0x00020000, wkc=1)))
    packets.append(ecat_frame(ecat_datagram(12, 22, bytes(4), logical_address=0x00030000, wkc=3)))

    # 4) Every Cmd value the real capture does NOT exercise (see ATTRIBUTION.md) -- APRW/FPRW/BRW
    #    (the ReadWrite variants of AP/FP/BRD-BWR), ARMW/FRMW (Read Multiple Write), EXT, and NOP --
    #    one datagram each, all using the ordinary Adp+Ado default addressing case.
    packets.append(ecat_frame(ecat_datagram(3, 30, bytes(2), adp=0x0001, ado=0x0800, wkc=1)))   # APRW
    packets.append(ecat_frame(ecat_datagram(6, 31, bytes(2), adp=0x0002, ado=0x0800, wkc=1)))   # FPRW
    packets.append(ecat_frame(ecat_datagram(9, 32, bytes(2), adp=0x0000, ado=0x0800, wkc=1)))   # BRW
    packets.append(ecat_frame(ecat_datagram(13, 33, bytes(2), adp=0x0003, ado=0x0910, wkc=1)))  # ARMW
    packets.append(ecat_frame(ecat_datagram(14, 34, bytes(2), adp=0x0004, ado=0x0910, wkc=1)))  # FRMW
    packets.append(ecat_frame(ecat_datagram(255, 35, bytes(2), adp=0x0000, ado=0x0000, wkc=0)))  # EXT
    packets.append(ecat_frame(ecat_datagram(0, 36, b"", adp=0x0000, ado=0x0000, wkc=0)))         # NOP

    # 5) An unrecognized/reserved Cmd byte (200) -- rendered "unknown(200)" rather than guessed at,
    #    but still decoded structurally (Adp/Ado addressing, the default case).
    packets.append(ecat_frame(ecat_datagram(200, 40, bytes(2), adp=0x0005, ado=0x0100, wkc=0)))

    # 6) The Len word's Circulating bit (0x4000, "frame has circulated once") set -- never observed
    #    in the real capture (see ethercat.hpp's Len(2) field paragraph), synthetic-only.
    packets.append(ecat_frame(ecat_datagram(4, 41, bytes(2), adp=0x0006, ado=0x0130, wkc=1, circulating=True)))

    # 7) The frame header's own Reserved bit (0x0800, must be zero per spec) set -- surfaced as a
    #    note, not a rejection (the EtherType alone remains the primary confidence signal -- see
    #    ethercat.hpp's "structural detection gate" paragraph).
    packets.append(ecat_frame(ecat_datagram(4, 42, bytes(2), adp=0x0007, ado=0x0130, wkc=1), reserved=True))

    # 8) WKC=0 on a command that should reach at least one slave -- the field's single unambiguous
    #    "something didn't respond" signal, surfaced raw with no verdict (see ethercat.hpp's WKC
    #    paragraph). BWR (Broadcast Write) is a plausible real-world command to see this on.
    packets.append(ecat_frame(ecat_datagram(8, 43, bytes(2), adp=0x0000, ado=0x0130, wkc=0)))

    # 9) Frame Types 2-5 (ADS/RAW-IO/NV/Mailbox) -- named only, not decoded further, the same
    #    "named only" pattern goose.hpp's GSE Management PDU and profinet.hpp's non-cyclic FrameID
    #    ranges already use. Payload bytes are arbitrary raw content, never interpreted.
    for t in (2, 3, 4, 5):
        packets.append(ecat_frame(bytes([0xAA, 0xBB, 0xCC, 0xDD]), frame_type=t,
                                   declared_length=4))

    # 10) A genuinely unrecognized/reserved Type value (0, not one of the spec's five 1-5) -- must
    #     NOT be misdetected as EtherCAT at all; falls back to the generic "non-ip" ethertype-name-
    #     only report, the same "structural detection gate" this decoder applies to every raw-
    #     Ethernet protocol (see ethercat.hpp's file header comment).
    packets.append(ecat_frame(bytes([0x01, 0x02]), frame_type=0, declared_length=2))

    # 11) 802.1Q VLAN-priority-tagged EtherCAT -- confirms parse_ethernet's single-VLAN-tag unwrap
    #     composes correctly with EtherCAT detection, mirroring GOOSE/SV's own VLAN tests.
    packets.append(ecat_frame(ecat_datagram(7, 44, bytes(2), adp=0x0000, ado=0x0130, wkc=1),
                               dst=bytes.fromhex("010ccd040001"), src=bytes.fromhex("000c291a2b3c"),
                               vlan_tci=0x8000))

    # 12) Header too short for even the fixed 2-byte frame header -- must not crash, falls through
    #     to the generic "non-ip" ethertype-name-only report.
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x88A4) + bytes([0x01]))

    # 13) A bogus/implausible declared Length (0 -- must be >= 1 per try_parse_ethercat) -- falls
    #     back to "using all available bytes instead", still decodes the one datagram actually
    #     present correctly, with a note (mirroring GOOSE/SV's own bogus-Length tests).
    packets.append(ecat_frame(ecat_datagram(7, 45, bytes(2), adp=0x0000, ado=0x0130, wkc=1),
                               declared_length=0))

    # 14) More bit set on the last (only) datagram decoded, but no bytes remain in this frame's
    #     declared Length afterward -- the chain is truncated; noted, not silently accepted.
    packets.append(ecat_frame(ecat_datagram(1, 46, bytes(2), adp=0x0000, ado=0x0130, wkc=1, more=True)))

    # 15) A declared Length that claims more bytes than a partial datagram header actually needs --
    #     specifically, only 5 bytes are present where a full 10-byte EcParserHDR is required --
    #     exercises decode_one_datagram's own "chain truncated, stopping" header-level bounds check
    #     (distinct from #14's Data+WKC-level truncation).
    packets.append(ecat_frame(bytes([0x01, 0x47, 0x00, 0x00, 0x30])))

    # 16) The safety cap (kMaxEthercatDatagrams == 200): a chain of 210 NOP datagrams, every one
    #     with More set, inside a frame whose declared Length is deliberately implausible (0, so the
    #     "use all available bytes" fallback -- see #13 -- is what actually bounds the scan; the
    #     11-bit Length field alone couldn't express this many bytes). Exercises the "stopped after
    #     N datagram(s) (safety cap)" note.
    capped_chain = b"".join(ecat_datagram(0, i & 0xFF, b"", wkc=0, more=True) for i in range(210))
    packets.append(ecat_frame(capped_chain, declared_length=0))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_004_000 + i, i * 1000)
    (TESTS_DIR / "sample_ethercat.pcap").write_bytes(data)


# --- STP / RSTP / MSTP (classic IEEE 802.3 LLC framing, not any EtherType) ---------------------

STP_BRIDGE_GROUP_MAC = mac("01:80:c2:00:00:00")  # the well-known "Bridge Group Address" multicast


def llc_length_frame(dsap: int, ssap: int, control: int, body: bytes, *, dst: bytes = None,
                      src: bytes = None, vlan_tci=None, declared_length=None) -> bytes:
    """One classic IEEE 802.3 length-framed LLC frame: MAC header, an 802.3 LENGTH field (not an
    EtherType -- always < 0x0600), a 3-byte LLC header (DSAP/SSAP/Control), then `body`. See
    link_layer.hpp's file header comment for why this is a new kind of frame for this codebase.
    `declared_length` overrides the Length field's own value (defaults to 3 + len(body), the honest
    LLC-header-plus-body length) -- for exercising the "implausible/truncated 802.3 Length field"
    fallback paths in parse_ethernet."""
    dst = dst if dst is not None else STP_BRIDGE_GROUP_MAC
    src = src if src is not None else HMI_MAC
    llc = bytes([dsap, ssap, control]) + body
    length = declared_length if declared_length is not None else len(llc)
    if vlan_tci is not None:
        return struct.pack("!6s6sHH", dst, src, 0x8100, vlan_tci) + struct.pack("!H", length) + llc
    return struct.pack("!6s6sH", dst, src, length) + llc


def snap_pvst_frame(body: bytes = b"", *, dst: bytes = None, src: bytes = None) -> bytes:
    """A SNAP-encapsulated classic-802.3 frame using Cisco's IEEE-assigned OUI (00:00:0C) --
    structurally what a Cisco PVST+/Rapid-PVST+ BPDU looks like at the LLC/SNAP level (see stp.hpp's
    "Out of scope" section: LLC DSAP=SSAP=0xAA, not 0x42). `body` is arbitrary bytes standing in for
    PVST+'s own Protocol-ID-keyed body -- this decoder never looks past the SNAP header itself, so
    its content doesn't matter for the "recognized but not decoded" assertion this fixture exists
    for. 0x010B is Cisco's real SNAP Protocol ID for PVST+ BPDUs (CISCO_PID_PVSTPP in the reference
    source), included for realism though this decoder never reads it."""
    dst = dst if dst is not None else mac("01:00:0c:cc:cc:cd")
    src = src if src is not None else HMI_MAC
    snap = bytes([0x00, 0x00, 0x0C]) + struct.pack("!H", 0x010B) + body
    return llc_length_frame(0xAA, 0xAA, 0x03, snap, dst=dst, src=src)


# --- CDP (Cisco Discovery Protocol) -- same LLC/SNAP envelope as PVST+ above, disambiguated purely
# by SNAP Protocol ID -- see cdp.hpp's file header comment. -------------------------------------

CDP_MULTICAST_MAC = mac("01:00:0c:cc:cc:cc")  # the well-known CDP/VTP/DTP/PAgP/UDLD multicast MAC
CDP_SNAP_PID = 0x2000
PVSTPP_SNAP_PID = 0x010B  # Cisco (R)PVST+'s own SNAP Protocol ID -- see snap_pvst_frame above


def snap_cdp_frame(body: bytes, *, snap_pid: int = CDP_SNAP_PID, dst: bytes = None,
                    src: bytes = None) -> bytes:
    """A SNAP-encapsulated classic-802.3 frame under Cisco's OUI (00:00:0C), carrying `body` after a
    SNAP Protocol ID of `snap_pid` (CDP's own 0x2000 by default -- see cdp.hpp's "SNAP PROTOCOL ID"
    header comment). Overriding `snap_pid` (e.g. to PVSTPP_SNAP_PID) builds the pinning-collision
    fixtures below: a frame that is byte-for-byte identical in every way EXCEPT its SNAP Protocol ID,
    used to prove decoder.cpp's dispatch keys on that field precisely rather than on SNAP_OUI_CISCO
    alone (the bug this release's own roadmap item fixed)."""
    dst = dst if dst is not None else CDP_MULTICAST_MAC
    src = src if src is not None else PLC_MAC
    snap = bytes([0x00, 0x00, 0x0C]) + struct.pack("!H", snap_pid) + body
    return llc_length_frame(0xAA, 0xAA, 0x03, snap, dst=dst, src=src)


def cdp_tlv(type_: int, value: bytes) -> bytes:
    """One CDP TLV: Type(2, BE) + Length(2, BE, INCLUDING this 4-byte header itself) + value -- see
    cdp.hpp's own "TLV FORMAT" header comment."""
    return struct.pack("!HH", type_, 4 + len(value)) + value


def cdp_header(version: int, ttl: int, checksum: int = 0) -> bytes:
    """The fixed 4-byte CDP header -- Version(1) + TTL(1) + Checksum(2, BE, never validated by this
    decoder -- see cdp.hpp's own "CHECKSUM" header comment, so an arbitrary/zero value here is fine)."""
    return struct.pack("!BBH", version, ttl, checksum)


def cdp_address_entry(protocol_type: int, protocol_bytes: bytes, address: bytes) -> bytes:
    """One entry of a CDP Addresses/Management-Address TLV's own repeated structure: Protocol
    Type(1) + Protocol Length(1) + Protocol(variable) + Address Length(2, BE) + Address(variable) --
    see cdp.hpp's own "ADDRESS TLV STRUCTURE" header comment."""
    return (struct.pack("!BB", protocol_type, len(protocol_bytes)) + protocol_bytes +
            struct.pack("!H", len(address)) + address)


def cdp_addresses_value(entries: list) -> bytes:
    """The Addresses/Management-Address TLV's own value: Number of Addresses(4, BE) + that many
    cdp_address_entry()s."""
    return struct.pack("!I", len(entries)) + b"".join(entries)


CAN_EFF_FLAG = 0x80000000
CAN_RTR_FLAG = 0x40000000
CAN_ERR_FLAG = 0x20000000
CANFD_FDF_FLAG = 0x04


def can_socketcan_frame(can_id: int, payload: bytes = b"", *, eff: bool = False, rtr: bool = False,
                         err: bool = False, fd: bool = False, fd_flags: int = 0,
                         payload_length_override=None) -> bytes:
    """One SocketCAN pcap capture record (LINKTYPE_CAN_SOCKETCAN == 227): the fixed 8-byte header
    (4-byte BIG-ENDIAN CAN ID + flags, 1-byte Payload Length, 1-byte FD Flags, 2 reserved bytes)
    immediately followed by `payload` -- see can_socketcan.hpp's file header comment for the exact
    wire format, cross-checked directly against libpcap's own pcap/can_socketcan.h and tcpdump.org's
    own LINKTYPE_CAN_SOCKETCAN registry page ("The CAN ID and flags field is in big-endian byte
    order"). `payload_length_override` lets a test deliberately claim a Payload Length that doesn't
    match len(payload) -- for exercising parse_socketcan_frame's own truncation-tolerance path."""
    can_id_flags = can_id & (0x1FFFFFFF if eff else 0x7FF)
    if eff:
        can_id_flags |= CAN_EFF_FLAG
    if rtr:
        can_id_flags |= CAN_RTR_FLAG
    if err:
        can_id_flags |= CAN_ERR_FLAG
    flags_byte = (fd_flags | CANFD_FDF_FLAG) if fd else fd_flags
    payload_length = payload_length_override if payload_length_override is not None else len(payload)
    header = struct.pack("!IBBBB", can_id_flags, payload_length, flags_byte, 0, 0)
    return header + payload


def stp_priority_ext16(priority: int, ext: int) -> int:
    """Packs a Bridge/Root/CIST-Bridge-Identifier-shaped 16-bit value: top 4 bits (masked, i.e.
    `priority` is already given as its own multiple-of-4096 value, e.g. 32768) + bottom 12 bits
    `ext` -- see stp.hpp's file header comment."""
    return (priority & 0xF000) | (ext & 0x0FFF)


def stp_port_id16(priority: int, number: int) -> int:
    """Packs a Port-Identifier-shaped 16-bit value: top 4 bits = `priority` / 16 (`priority` is a
    multiple of 16, e.g. 128), bottom 12 bits = `number` -- see stp.hpp's "Port Identifier"
    paragraph for why this multiplier differs from stp_priority_ext16's own."""
    return (((priority // 16) & 0xF) << 12) | (number & 0x0FFF)


def stp_time256(seconds: float) -> int:
    """Message Age/Max Age/Hello Time/Forward Delay are all in units of 1/256 second."""
    return round(seconds * 256)


def stp_common_body(version: int, bpdu_type: int, flags: int, root_priority: int, root_ext: int,
                     root_mac: bytes, root_cost: int, bridge_priority: int, bridge_ext: int,
                     bridge_mac: bytes, port_priority: int, port_number: int, msg_age: float,
                     max_age: float, hello: float, fwd_delay: float) -> bytes:
    """The 35-byte Configuration/RST BPDU common body -- Protocol Identifier through Forward Delay
    inclusive -- see stp.hpp's file header comment."""
    body = struct.pack("!HBBB", 0x0000, version, bpdu_type, flags)
    body += struct.pack("!H", stp_priority_ext16(root_priority, root_ext)) + root_mac
    body += struct.pack("!I", root_cost)
    body += struct.pack("!H", stp_priority_ext16(bridge_priority, bridge_ext)) + bridge_mac
    body += struct.pack("!H", stp_port_id16(port_priority, port_number))
    body += struct.pack("!HHHH", stp_time256(msg_age), stp_time256(max_age), stp_time256(hello),
                         stp_time256(fwd_delay))
    assert len(body) == 35
    return body


def stp_msti_message(flags: int, mstid: int, regional_root_priority: int, regional_root_mac: bytes,
                      internal_root_path_cost: int, bridge_priority_nibble: int,
                      port_priority_nibble: int, remaining_hops: int, *,
                      bridge_low_nibble: int = 0, port_low_nibble: int = 0) -> bytes:
    """One 16-byte MSTI Configuration Message -- see stp.hpp's file header comment. `bridge_low_
    nibble`/`port_low_nibble` let a test deliberately set the low (undecoded) nibble of the MSTI
    Bridge/Port Identifier Priority bytes to a nonzero value, confirming this decoder truly never
    decodes it (see stp.hpp's own double-checked-against-the-source paragraph on this field)."""
    m = struct.pack("!B", flags)
    m += struct.pack("!H", stp_priority_ext16(regional_root_priority, mstid)) + regional_root_mac
    m += struct.pack("!I", internal_root_path_cost)
    m += bytes([((bridge_priority_nibble & 0xF) << 4) | (bridge_low_nibble & 0xF)])
    m += bytes([((port_priority_nibble & 0xF) << 4) | (port_low_nibble & 0xF)])
    m += bytes([remaining_hops])
    assert len(m) == 16
    return m


def stp_mst_extension(mst_config_name: str, mst_config_revision: int, mst_config_digest: bytes,
                       cist_root_cost: int, cist_bridge_priority: int, cist_bridge_ext: int,
                       cist_bridge_mac: bytes, cist_remaining_hops: int, msti_messages: bytes = b"",
                       *, config_format_selector: int = 0, version_3_length_override=None) -> bytes:
    """Version 3 Length onward -- the MST extension appended after the RST common body + a Version 1
    Length byte of 0 (required for a full MST BPDU to be recognized at all, see stp.hpp)."""
    name_bytes = mst_config_name.encode("ascii")[:32].ljust(32, b"\x00")
    static_part = (struct.pack("!B", config_format_selector) + name_bytes +
                   struct.pack("!H", mst_config_revision) +
                   mst_config_digest.ljust(16, b"\x00")[:16] +
                   struct.pack("!I", cist_root_cost) +
                   struct.pack("!H", stp_priority_ext16(cist_bridge_priority, cist_bridge_ext)) +
                   cist_bridge_mac + struct.pack("!B", cist_remaining_hops))
    assert len(static_part) == 64
    v3len = version_3_length_override if version_3_length_override is not None else (64 + len(msti_messages))
    return struct.pack("!H", v3len) + static_part + msti_messages


def build_stp_sample():
    """STP/RSTP/MSTP (classic IEEE 802.3 LLC framing, LLC DSAP=SSAP=0x42, Control=0x03) -- see
    stp.hpp's file header comment for the exact wire format each packet below exercises (cross-
    checked against Wireshark's own packet-bpdu.c). Packets 1 and 2 reproduce two independent real
    captures' own frames byte-for-byte (see tests/real_captures/stp/ATTRIBUTION.md): a classic
    Configuration BPDU (Plant1.pcap frame 617) and an RSTP RST BPDU (Sample_File_MMS_and_GOOSE.pcap
    frame 30). Every other packet below is synthetic-only, covering paths those real captures don't
    happen to exercise (no real MSTP, no real TCN, no real malformed/truncated frame, no real
    PVST+/GARP/VLAN-tagged frame in either capture)."""
    packets = []

    bridge_a = mac("00:1a:2b:3c:4d:5e")
    bridge_b = mac("00:1a:2b:3c:4d:5f")
    bridge_c = mac("00:1a:2b:3c:4d:60")

    # 1) Byte-for-byte reproduction of a real classic Configuration BPDU (802.1D, version 0) --
    #    Plant1.pcap frame 617 (see ATTRIBUTION.md): Root=32768/80/64:a0:e7:9a:05:80 Cost=4
    #    Bridge=32768/80/64:ae:0c:34:a3:80 Port=0x8083, no flags, 8 bytes of Ethernet minimum-
    #    frame-size padding after the 35-byte body (exercises llc_trailing_bytes_trimmed).
    packets.append(bytes.fromhex(
        "0180c200000064ae0c34ab9700264242030000000000805064a0e79a058000000004"
        "805064ae0c34a38080830200140002000f000000000000000000"))

    # 2) Byte-for-byte reproduction of a real RSTP RST BPDU (802.1w, version 2) --
    #    Sample_File_MMS_and_GOOSE.pcap frame 30 (see ATTRIBUTION.md): Root=28672/4095/
    #    00:40:15:18:1d:7c Cost=1100 Bridge=32768/0/00:0a:dc:06:19:5c Port=0x8010
    #    Role=Designated, Learning+Forwarding set, Version 1 Length=0.
    packets.append(bytes.fromhex(
        "0180c2000000000adc06196b0027424203000002023c7fff004015181d7c00000"
        "44c8000000adc06195c80100140140002000f00004563a240020320"))

    # 3) TCN BPDU (Topology Change Notification, BPDU Type 0x80) -- 4-byte body only, no flags, no
    #    bridge/root IDs. Synthetic (neither real capture contains one).
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 0, 0x80)))

    # 4) TCN BPDU with an unusual Protocol Version Identifier byte (2) -- a TCN BPDU's own version
    #    byte is never gated on (see stp.hpp), still decoded as a plain TCN.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 2, 0x80)))

    # 5) Classic Configuration BPDU with TC (Topology Change) and TCA (Topology Change
    #    Acknowledgment) flags both set -- the only two flag bits ever meaningful under version 0.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        0, 0x00, 0x81, 32768, 0, bridge_a, 19, 32768, 0, bridge_a, 128, 3,
        0.0, 20.0, 2.0, 15.0)))

    # 6) Configuration BPDU (Type 0x00) with an unusual Protocol Version Identifier (2) -- an
    #    unusual but still-decoded combination (see stp.hpp), exercises the "unusual combination"
    #    note.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x00, 0x00, 32768, 0, bridge_a, 0, 32768, 0, bridge_a, 128, 1,
        0.0, 20.0, 2.0, 15.0)))

    # 7) RST BPDU (Type 0x02) with Protocol Version Identifier 0 -- also an unusual combination
    #    (RST BPDUs are conventionally version 2+), but the reference source decodes ANY Type-0x02
    #    BPDU through the same 36-byte shape regardless of version, and this decoder matches that
    #    exactly (see stp.hpp) -- no note, decoded normally, labeled "STP (802.1D) BPDU".
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        0, 0x02, 0x00, 32768, 0, bridge_b, 0, 32768, 0, bridge_b, 128, 5,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)))

    # 8) RSTP RST BPDU, Port Role = Root (2), Proposal set, Agreement NOT set (the real capture's
    #    own two frames are both Role=Designated with neither Proposal nor Agreement -- this
    #    exercises a Port Role/flag combination that capture doesn't).
    flags8 = 0x02 | (2 << 2)  # Proposal | Port Role=Root
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x02, flags8, 4096, 10, bridge_a, 200000, 32768, 0, bridge_b, 128, 7,
        1.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)))

    # 9) RSTP RST BPDU, Port Role = Alternate/Backup (1), Agreement set, Proposal NOT set, TC set.
    flags9 = 0x40 | (1 << 2) | 0x01  # Agreement | Port Role=Alternate/Backup | TC
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x02, flags9, 32768, 0, bridge_b, 4, 32768, 0, bridge_c, 128, 9,
        3.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)))

    # 10) RSTP RST BPDU, Port Role = Unknown (0), no other flags set at all (flags byte 0x00).
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x02, 0x00, 32768, 0, bridge_c, 0, 32768, 0, bridge_c, 128, 1,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)))

    # 11) 802.1Q VLAN-priority-tagged RSTP RST BPDU -- confirms parse_ethernet's single-VLAN-tag
    #     unwrap composes correctly with classic-802.3-LLC recognition, mirroring GOOSE/SV/
    #     EtherCAT's own VLAN tests.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x02, (3 << 2) | 0x30, 32768, 7, bridge_a, 100, 32768, 7, bridge_a, 128, 2,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0), vlan_tci=0x2000))

    # 12) MSTP MST BPDU with 2 MSTI Configuration Messages -- ordinary case, Version 3 Length ==
    #     64 + 2*16 == 96. The first MSTI message deliberately sets nonzero low nibbles on the
    #     Bridge/Port Identifier Priority bytes (bridge_low_nibble/port_low_nibble) to confirm this
    #     decoder truly ignores them (see stp.hpp).
    msti1 = stp_msti_message(0x3C, 10, 32768, bridge_a, 20000, 8, 8, 20,
                              bridge_low_nibble=0xF, port_low_nibble=0xA)
    msti2 = stp_msti_message(0x00, 20, 4096, bridge_b, 0, 0, 0, 20)
    mst_ext_12 = stp_mst_extension("region-1", 3, bytes.fromhex("00112233445566778899aabbccddeeff"[:32]),
                                    50, 32768, 100, bridge_a, 19, msti1 + msti2)
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 100, bridge_a, 50, 32768, 100, bridge_a, 128, 3,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0) + mst_ext_12))

    # 13) MSTP MST BPDU with 0 MSTI Configuration Messages (Version 3 Length == 64 exactly, the
    #     VERSION_3_STATIC_LENGTH boundary with nothing past it).
    mst_ext_13 = stp_mst_extension("region-empty", 1, b"\x11" * 16, 0, 32768, 0, bridge_c, 20, b"")
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_c, 0, 32768, 0, bridge_c, 128, 4,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0) + mst_ext_13))

    # 14) MSTP MST BPDU exercising the reference source's own Cisco-C3550-firmware work-around:
    #     Version 3 Length is nonzero but less than 64 (the static header size) -- treated as a
    #     COUNT OF MESSAGES rather than bytes (2 here, so 2*16 == 32 MSTI bytes) -- see stp.hpp.
    msti14a = stp_msti_message(0x00, 1, 32768, bridge_a, 10, 8, 8, 19)
    msti14b = stp_msti_message(0x00, 2, 32768, bridge_b, 10, 8, 8, 19)
    mst_ext_14 = stp_mst_extension("cisco-units", 0, b"\x22" * 16, 5, 32768, 0, bridge_a, 20,
                                    msti14a + msti14b, version_3_length_override=2)
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_a, 5, 32768, 0, bridge_a, 128, 6,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0) + mst_ext_14))

    # 15) MSTP MST BPDU whose Version 3 Length declares more MSTI bytes than are actually present
    #     (32 declared, only 16 -- one message -- physically present) -- exercises the "decoding as
    #     many whole messages as fit" truncation-tolerant fallback.
    msti15 = stp_msti_message(0x00, 30, 32768, bridge_b, 1, 8, 8, 5)
    mst_ext_15 = stp_mst_extension("truncated", 0, b"\x33" * 16, 1, 32768, 0, bridge_b, 5, msti15,
                                    version_3_length_override=64 + 32)
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_b, 1, 32768, 0, bridge_b, 128, 8,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0) + mst_ext_15))

    # 16) MSTP MST BPDU with a partial trailing MSTI Configuration Message (Version 3 Length
    #     implies 64 + 20 bytes -- one whole 16-byte message plus 4 leftover bytes) -- exercises
    #     the "partial trailing MSTI Configuration Message ... not decoded" note.
    msti16 = stp_msti_message(0x00, 40, 32768, bridge_c, 1, 8, 8, 5)
    mst_ext_16 = stp_mst_extension("partial-msti", 0, b"\x44" * 16, 1, 32768, 0, bridge_c, 5,
                                    msti16 + b"\xaa\xbb\xcc\xdd",
                                    version_3_length_override=64 + 20)
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_c, 1, 32768, 0, bridge_c, 128, 9,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0) + mst_ext_16))

    # 17) Protocol Version 3 (MSTP-eligible) but the frame is too short (< 102 bytes total) for the
    #     MST detection gate to hold -- falls back to a plain RST-shaped BPDU (36 bytes), noted.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_a, 0, 32768, 0, bridge_a, 128, 10,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)))

    # 18) Protocol Version 3 with enough total bytes present, but Version 1 Length is NOT 0 -- the
    #     MST detection gate's second condition fails, also falls back to a plain RST-shaped BPDU,
    #     with the rest of the (>=102-byte) frame simply ignored.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        3, 0x02, 0x00, 32768, 0, bridge_b, 0, 32768, 0, bridge_b, 128, 11,
        0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 5) + b"\x00" * 70))

    # 19) The legacy/alternative MSTI Configuration Message format's own detection trigger:
    #     Version 3 Length == 0, and the frame's total length equals `MST Config Format Selector
    #     byte's value + MST_BPDU_SIZE(38) + 1` -- named (is_alt_msti_format) but not decoded, see
    #     stp.hpp. This trigger is only ever CHECKED once the outer MST-detection gate's own
    #     `>= 102 total bytes` condition already holds (see stp.hpp's "MSTP detection" paragraph --
    #     the alt-format check happens strictly inside that gate, not before it), so
    #     config_format_selector must be chosen large enough that config_format_selector + 39 is
    #     itself >= 102 -- 63 is the smallest value that satisfies both that and the alt-format's
    #     own equality check simultaneously (63 + 39 == 102 exactly).
    cfs19 = 63
    body19 = stp_common_body(3, 0x02, 0x00, 32768, 0, bridge_c, 0, 32768, 0, bridge_c, 128, 12,
                              0.0, 20.0, 2.0, 15.0) + struct.pack("!B", 0)
    # Version 3 Length (0) + the rest of the fixed 38-byte-through-that-point header, using
    # config_format_selector=26 as ALT_MSTI's own "length" stand-in, then exactly enough filler
    # bytes so tvb_reported_length(tvb) == config_format_selector + MST_BPDU_SIZE + 1 == 65.
    body19 += struct.pack("!H", 0)  # Version 3 Length == 0
    body19 += struct.pack("!B", cfs19)  # MST Config Format Selector doubles as ALT's length field
    alt_expected_len19 = cfs19 + 38 + 1  # == tvb_reported_length(tvb) the reference source checks
    body19 += b"\x00" * (alt_expected_len19 - len(body19))  # pad so the WHOLE llc_payload matches
    packets.append(llc_length_frame(0x42, 0x42, 0x03, body19))

    # 20) SPB (802.1aq), Protocol Version Identifier 4 -- named-only, never body-decoded (see
    #     stp.hpp). BPDU Type 0x02 reused, same as RST/MST.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 4, 0x02) +
                                     b"\x00" * 40))

    # 21) Malformed: Protocol Identifier != 0x0000 -- not recognized as STP at all, falls back to
    #     the generic "IEEE 802.3 LLC frame, DSAP=... SSAP=... Control=..." report.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x1234, 0, 0x00) +
                                     b"\x00" * 31))

    # 22) Malformed: BPDU Type not one of {0x00, 0x02, 0x80} -- not recognized as STP at all.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 0, 0x01) +
                                     b"\x00" * 31))

    # 23) Malformed: Configuration BPDU truncated before the 35-byte common body fits (only 20
    #     bytes of body present) -- structurally recognized (Protocol ID/Version/Type all valid)
    #     but too short to decode further, noted.
    packets.append(llc_length_frame(0x42, 0x42, 0x03,
                                     struct.pack("!HBB", 0x0000, 0, 0x00) + b"\x00" * 16))

    # 24) Malformed: RST BPDU truncated right after the 35-byte common body -- Version 1 Length
    #     byte (offset 35) itself missing, noted.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, stp_common_body(
        2, 0x02, 0x00, 32768, 0, bridge_a, 0, 32768, 0, bridge_a, 128, 13,
        0.0, 20.0, 2.0, 15.0)))

    # 25) Cisco PVST+ (SNAP-encapsulated, Cisco OUI 00:00:0C) -- recognized structurally, named,
    #     but never decoded (see stp.hpp's "Out of scope" section).
    packets.append(snap_pvst_frame(b"\x00\x00" + stp_common_body(
        0, 0x00, 0x00, 32768, 5, bridge_a, 0, 32768, 5, bridge_a, 128, 1, 0.0, 20.0, 2.0, 15.0) +
        struct.pack("!BH", 0, 0) + struct.pack("!HH", 0, 5)))  # Version1Length + PVST+ TLV, arbitrary

    # 26) GARP (GVRP/GMRP) -- shares STP's own LLC DSAP/SSAP pair (0x42/0x42), disambiguated only
    #     by destination MAC (01:80:C2:00:00:21, inside the GARP range) -- recognized structurally,
    #     named "GARP (GVRP/GMRP)", never decoded, and NOT misdetected as STP -- see stp.hpp's
    #     "GARP collision" paragraph and decoder.cpp's own dst-MAC check.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 0, 0x00) +
                                     b"\x00" * 31, dst=mac("01:80:c2:00:00:21")))

    # 27) Unrecognized LLC DSAP/SSAP on an otherwise well-formed classic-802.3 frame (0xE0/0xE0,
    #     the well-known IPX SAP) -- not STP, not SNAP, not GARP -- named generically by its raw
    #     DSAP/SSAP values, never guessed at further.
    packets.append(llc_length_frame(0xE0, 0xE0, 0x03, b"\x00" * 10))

    # 28) A length-framed 802.3 frame too short for even a 3-byte LLC header (only 2 bytes present
    #     after the Length field) -- must not crash, falls back to the "too short for an LLC
    #     header" report.
    packets.append(struct.pack("!6s6sH", PLC_MAC, HMI_MAC, 5) + b"\x01\x02")

    # 29) An implausible 802.3 Length field (1 -- too small to even cover the 3-byte LLC header
    #     already consumed) on an otherwise well-formed, fully-present STP frame -- exercises
    #     parse_ethernet's "Length field too small" fallback (uses all captured bytes instead), and
    #     confirms try_parse_stp still decodes correctly despite it.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 0, 0x80),
                                     declared_length=1))

    # 30) An 802.3 Length field that declares MORE client-data bytes than were actually captured
    #     (200, versus only 7 bytes -- LLC header + a 4-byte TCN body -- physically present) --
    #     exercises parse_ethernet's snaplen-truncation fallback (uses whatever's actually present)
    #     and confirms a TCN BPDU still decodes correctly from what's left.
    packets.append(llc_length_frame(0x42, 0x42, 0x03, struct.pack("!HBB", 0x0000, 0, 0x80),
                                     declared_length=200))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_710_000_000 + i, i * 1000)
    (TESTS_DIR / "sample_stp.pcap").write_bytes(data)


def build_devicenet_sample():
    """DeviceNet over SocketCAN pcap framing (LINKTYPE_CAN_SOCKETCAN == 227) -- see
    can_socketcan.hpp/devicenet.hpp's own file header comments for the exact wire formats each
    packet below exercises (cross-checked against libpcap's own pcap/can_socketcan.h and
    Wireshark's own epan/dissectors/packet-devicenet.c). Entirely synthetic -- no real public
    DeviceNet/CAN capture was found during this task's own research (see devicenet.hpp/this
    project's task notes); every packet below is hand-built directly from the reference sources.
    Packet numbers in comments match this function's own numbered comments 1-30."""
    packets = []

    # 1) Group 1, Slave's I/O Multicast Poll Response (message bits 0x0300), Source MAC ID 5.
    packets.append(can_socketcan_frame(0x0300 | 5, bytes([0x11, 0x22, 0x33, 0x44])))

    # 2) Group 1, Slave's I/O Change of State or Cyclic Message (0x0340), Source MAC ID 12.
    packets.append(can_socketcan_frame(0x0340 | 12, bytes([0xAA, 0xBB])))

    # 3) Group 1, Slave's I/O Bit-Strobe Response Message (0x0380), Source MAC ID 0, empty payload
    #    (a bit-strobe response can legitimately carry 0 or 1 bytes).
    packets.append(can_socketcan_frame(0x0380 | 0, b""))

    # 4) Group 1, Slave's I/O Poll Response or COS/Cyclic Ack Message (0x03C0), Source MAC ID 63
    #    (the largest possible 6-bit MAC ID).
    packets.append(can_socketcan_frame(0x03C0 | 63, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])))

    # 5) Group 1, an unnamed message-ID sub-value (0x0040 -- not one of the four named values) --
    #    falls back to "Other Group 1 Message", the reference dissector's own fallback string.
    packets.append(can_socketcan_frame(0x0040 | 7, bytes([0x00])))

    # 6) Group 2, Master's I/O Bit-Strobe Command Message (message bits 0x00), Source MAC ID 20
    #    ((20 << 3) == 0xA0).
    packets.append(can_socketcan_frame(0x0400 | (20 << 3) | 0x00, bytes([0xFF] * 8)))

    # 7) Group 2, Slave's Explicit/Unconnected Response Messages (0x03), Source MAC ID 3.
    packets.append(can_socketcan_frame(0x0400 | (3 << 3) | 0x03, bytes([0x00, 0x10])))

    # 8) Group 2, Master's Explicit Request Messages (0x04), Source MAC ID 10.
    packets.append(can_socketcan_frame(0x0400 | (10 << 3) | 0x04, bytes([0x0E, 0x01, 0x02])))

    # 9) Group 2, Group 2 Only Unconnected Explicit Request Messages (0x06), Source MAC ID 45.
    packets.append(can_socketcan_frame(0x0400 | (45 << 3) | 0x06, bytes([0x4B])))

    # 10) Group 2, Duplicate MAC ID Check Messages (0x07), Source MAC ID 7 -- with the full decoded
    #     payload structure: RR bit clear (Request), Physical Port Number 2, Vendor ID 0x00AB
    #     (little-endian), Serial Number 0x12345678 (little-endian) -- see devicenet.hpp's Group 2
    #     paragraph.
    dup10 = bytes([0x02]) + struct.pack("<H", 0x00AB) + struct.pack("<I", 0x12345678)
    packets.append(can_socketcan_frame(0x0400 | (7 << 3) | 0x07, dup10))

    # 11) Group 2, Duplicate MAC ID Check Messages, RESPONSE this time (RR bit set, byte0 bit 0x80),
    #     Physical Port Number 1, Vendor ID 0x1234, Serial Number 0xCAFEBABE.
    dup11 = bytes([0x80 | 0x01]) + struct.pack("<H", 0x1234) + struct.pack("<I", 0xCAFEBABE)
    packets.append(can_socketcan_frame(0x0400 | (7 << 3) | 0x07, dup11))

    # 12) Group 3, a generic Group 3 Message (message bits 0x000), Source MAC ID 9, non-fragmented,
    #     destination MAC ID 15, CIP service 0x0E (Get_Attribute_Single -- a GENERIC CIP service
    #     code, reused directly from enip.hpp's cip_service_name, not DeviceNet-specific), Request.
    packets.append(can_socketcan_frame(0x0600 | 9, bytes([15, 0x0E, 0x01, 0x02])))

    # 13) Group 3, Unconnected Explicit Request Message (0x180), Source MAC ID 12, destination MAC
    #     ID 20, CIP service 0x4B (Open Explicit Message Connection Request -- DeviceNet-SPECIFIC,
    #     not in EtherNet/IP's own generic CIP table), Request.
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 12, bytes([20, 0x4B, 0x00, 0x00, 0x01, 0x00, 0x00])))

    # 14) Group 3, Unconnected Explicit Response Message (0x140), Source MAC ID 20 (the target
    #     replying), destination MAC ID 12 (back to the originator), CIP service 0x4C (Close
    #     Connection Request -- also DeviceNet-specific) with the reply bit (0x80) set -> Response.
    packets.append(can_socketcan_frame(0x0600 | 0x140 | 20, bytes([12, 0x80 | 0x4C])))

    # 15) Group 3, Unconnected Explicit Request Message (0x180), CIP service 0x4D (Device Heartbeat
    #     Message -- DeviceNet-specific), Source MAC ID 1, destination MAC ID 1 (a device
    #     heartbeating to itself's own group, a legitimate real-world shape).
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 1, bytes([1, 0x4D])))

    # 16) Group 3, Unconnected Explicit Request Message (0x180), CIP service 0x4E (Device Shutdown
    #     Message -- DeviceNet-specific; note this differs entirely from EtherNet/IP's own 0x4E,
    #     which is Forward_Close/Read_Modify_Write_Tag -- see devicenet.hpp/cip_service_name).
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 2, bytes([2, 0x4E])))

    # 17) Group 3, Invalid Group 3 Message (message bits 0x1C0) -- named as such (matches the
    #     reference dissector's own fallback for this specific message-ID value), still structurally
    #     decoded (destination MAC ID + service byte), not rejected outright.
    packets.append(can_socketcan_frame(0x0600 | 0x1C0 | 5, bytes([5, 0x01])))

    # 18) Group 3, non-fragmented, XID flag set (byte0 bit 0x40) alongside destination MAC ID 30.
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 8, bytes([0x40 | 30, 0x0E])))

    # 19) Group 3, FRAGMENTED message (byte0 bit 0x80 set) -- not reassembled, matching Wireshark's
    #     own unimplemented TODO (see devicenet.hpp). Destination MAC ID 40 is still decoded; nothing
    #     past byte 0 is.
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 3, bytes([0x80 | 40, 0x4B, 0xFF, 0xFF])))

    # 20) Group 3, non-fragmented, but the payload has ONLY the destination-MAC-ID byte (no service
    #     byte at all) -- exercises the "service byte isn't present" tolerant path.
    packets.append(can_socketcan_frame(0x0600 | 0x180 | 4, bytes([11])))

    # 21) Group 3 message with NO payload at all -- exercises the "no payload, nothing Group-3-
    #     specific decodable" tolerant path (CAN ID classification alone still succeeds).
    packets.append(can_socketcan_frame(0x0600 | 6, b""))

    # 22) Group 4, Communication Faulted Response Message (0x2C).
    packets.append(can_socketcan_frame(0x07C0 | 0x2C, bytes([0x00])))

    # 23) Group 4, Communication Faulted Request Message (0x2D).
    packets.append(can_socketcan_frame(0x07C0 | 0x2D, bytes([0x01, 0x02])))

    # 24) Group 4, Offline Ownership Response Message (0x2E).
    packets.append(can_socketcan_frame(0x07C0 | 0x2E, bytes([0x03])))

    # 25) Group 4, Offline Ownership Request Message (0x2F).
    packets.append(can_socketcan_frame(0x07C0 | 0x2F, bytes([5, 0x01])))

    # 26) Group 4, a message-ID value not one of the four named ones -- "Reserved Group 4 Message",
    #     the reference dissector's own fallback.
    packets.append(can_socketcan_frame(0x07C0 | 0x10, b""))

    # 27) Unclassified CAN ID range (0x07F0-0x07FF) -- the reference dissector itself has no
    #     handling at all for this range; shown structurally only, no message group invented.
    packets.append(can_socketcan_frame(0x07F5, bytes([0xDE, 0xAD])))

    # 28) Extended Frame Format (EFF, 29-bit id) -- NOT a valid DeviceNet frame shape, rejected
    #     exactly the way Wireshark's own packet-devicenet.c rejects it (its very first check).
    packets.append(can_socketcan_frame(0x1ABCDEF, bytes([0x01]), eff=True))

    # 29) Remote Transmission Request (RTR) -- also rejected, same reasoning.
    packets.append(can_socketcan_frame(0x0305, b"", rtr=True))

    # 30) Error frame (ERR) -- also rejected, same reasoning.
    packets.append(can_socketcan_frame(0x0000, b"", err=True))

    # 31) CAN FD frame (fd_flags bit 0x04 set) on an otherwise ordinary Group 1 CAN ID -- the
    #     CAN-ID-derived message-group classification is still shown, but DeviceNet.hpp's own
    #     documented CAN-FD-out-of-scope note means the payload is NOT semantically decoded (no
    #     "I/O data=N byte(s)" annotation the equivalent non-FD Group 1 packet gets).
    packets.append(can_socketcan_frame(0x0300 | 9, bytes([0x01] * 16), fd=True))

    # 32) Truncated: fewer than the fixed 8-byte SocketCAN header itself is present (only 5 bytes
    #     total) -- must not crash; reported as a "parse-error" packet, the same tolerant handling
    #     an undersized Ethernet frame already gets from parse_ethernet.
    packets.append(b"\x00\x00\x03\x05\x02")

    # 33) Truncated payload: the 8-byte header is fully present and declares a Payload Length of 8,
    #     but only 3 payload bytes actually follow in the captured record -- exercises
    #     parse_socketcan_frame's own truncation-tolerant clamping (not a thrown ParseError).
    packets.append(can_socketcan_frame(0x0300 | 22, bytes([0x01, 0x02, 0x03]),
                                        payload_length_override=8))

    data = pcap_global_header(linktype=LINKTYPE_CAN_SOCKETCAN)
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_720_000_000 + i, i * 1000)
    (TESTS_DIR / "sample_devicenet.pcap").write_bytes(data)


def build_canopen_j1939_sample():
    """CANopen (CiA 301) and SAE J1939 over SocketCAN pcap framing (LINKTYPE_CAN_SOCKETCAN == 227)
    -- see canopen.hpp/j1939.hpp's own file header comments for the exact wire formats each packet
    below exercises (cross-checked against Wireshark's own epan/dissectors/packet-canopen.c and
    packet-j1939.c for the ID/PGN structure; SAE J1939-71/-73 domain knowledge, cited in j1939.hpp,
    for the EEC1/ET1/CCVS/DM1 payload field layouts no Wireshark source implements). One combined
    fixture, matching this task's own "one combined CAN-family fixture file" option -- CANopen's own
    standard (non-EFF) IDs and J1939's own extended (EFF) IDs coexist here without any isolation
    problem, since decoder.cpp's own LINKTYPE_CAN_SOCKETCAN branch already dispatches purely on the
    EFF flag; --protocol canopen/j1939 each cleanly ignore the other's own frames in this same file.
    Entirely synthetic -- no real public CANopen/J1939 capture was found during this task's own
    research (same honest gap devicenet.hpp's own Validation section already documents for
    DeviceNet). Packet numbers in comments match this function's own numbered comments 1-36."""
    packets = []

    # ================================ CANopen (CiA 301) section ================================

    # 1) NMT "Start remote node" targeting node 5 -- COB-ID 0x000 (Function Code 0, broadcast).
    #    DELIBERATE DOUBLE DUTY: this exact CAN ID/payload is ALSO a perfectly valid DeviceNet Group 1
    #    frame (id 0x000 <= 0x03FF, SrcMAC=id&0x3F=0, MsgID=id&0x3C0=0 -> "Other Group 1 Message",
    #    the reference dissector's own generic fallback) -- see canopen.hpp's own file header comment's
    #    dispatch-collision analysis and this fixture's own CTest entries (decoded 3 ways: as
    #    DeviceNet under --protocol devicenet AND under the Auto default, as CANopen only under an
    #    explicit --protocol canopen) for the negative-control proof that this codebase's own
    #    DeviceNet-wins-Auto-mode policy actually behaves as documented.
    packets.append(can_socketcan_frame(0x000, bytes([0x01, 0x05])))

    # 2) NMT "Enter pre-operational state" targeting "All" (target node 0x00).
    packets.append(can_socketcan_frame(0x000, bytes([0x80, 0x00])))

    # 3) Heartbeat (NMT Error Control, FC=0xE), node 1 -> COB-ID 0x701, state Operational (0x05).
    #    COB-ID 0x701 is ALSO squarely inside DeviceNet's own Group 3 range (0x600-0x7BF) --
    #    canopen.hpp's own header comment uses this exact COB-ID as its own worked example.
    packets.append(can_socketcan_frame(0x701, bytes([0x05])))

    # 4) Heartbeat, node 4 -> COB-ID 0x704, state Boot-up (0x00).
    packets.append(can_socketcan_frame(0x704, bytes([0x00])))

    # 5) Heartbeat, node 5 -> COB-ID 0x705, state Pre-operational (0x7F) with the legacy Node
    #    Guarding toggle bit (0x80) ALSO set -- proves the toggle bit is read independently of state.
    packets.append(can_socketcan_frame(0x705, bytes([0x80 | 0x7F])))

    # 6) SYNC (FC=1, node 0) -- no optional Counter byte.
    packets.append(can_socketcan_frame(0x080, b""))

    # 7) SYNC with the optional Counter byte present (42).
    packets.append(can_socketcan_frame(0x080, bytes([42])))

    # 8) TIME STAMP (FC=2, node 0) -- 4-byte LE milliseconds (1234) + 2-byte LE days (100).
    packets.append(can_socketcan_frame(0x100, struct.pack("<IH", 1234, 100)))

    # 9) EMCY (FC=1, node 5 -- non-broadcast) -- Error Code 0x2310 ("Current, CANopen device output
    #    side", LE), Error Register 0x05 (Generic 0x01 | Voltage 0x04), 5 manufacturer-specific bytes.
    packets.append(can_socketcan_frame(0x085,
        struct.pack("<H", 0x2310) + bytes([0x05]) + bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00])))

    # 10) PDO1 (tx), node 10 -> COB-ID 0x18A -- structural only, raw hex payload.
    packets.append(can_socketcan_frame(0x18A, bytes(range(0x11, 0x19))))

    # 11) PDO1 (rx), node 10 -> COB-ID 0x20A.
    packets.append(can_socketcan_frame(0x20A, bytes([0xAA, 0xBB, 0xCC, 0xDD])))

    # 12) SDO Initiate download request (ccs=1, the "full" e/s/n-carrying half), node 7 -> COB-ID
    #     0x587 (FC=0xB, Default-SDO rx). e=1,s=1,n=0 -> byte0=0x23. Index 0x1017 ("Producer
    #     heartbeat time"), sub-index 0, 4-byte expedited data (1000, LE).
    packets.append(can_socketcan_frame(0x587,
        bytes([0x23]) + struct.pack("<H", 0x1017) + bytes([0x00]) + struct.pack("<I", 1000)))

    # 13) SDO Initiate download response (scs=3, the "ack-only" half), node 7 -> COB-ID 0x607
    #     (FC=0xC, Default-SDO tx). Same index/sub-index, no data.
    packets.append(can_socketcan_frame(0x607, bytes([0x60]) + struct.pack("<H", 0x1017) + bytes([0x00])))

    # 14) SDO Initiate upload request (ccs=2, "ack-only" half), node 8 -> COB-ID 0x588. Index 0x1008
    #     ("Manufacturer device name"), sub-index 0.
    packets.append(can_socketcan_frame(0x588, bytes([0x40]) + struct.pack("<H", 0x1008) + bytes([0x00])))

    # 15) SDO Initiate upload response (scs=2, "full" half carrying the value being read), node 8 ->
    #     COB-ID 0x608. e=1,s=1,n=2 (2 unused trailing bytes -> 2 real data bytes) -> byte0=0x4B.
    packets.append(can_socketcan_frame(0x608,
        bytes([0x4B]) + struct.pack("<H", 0x1008) + bytes([0x00]) + bytes([0x41, 0x42])))

    # 16) SDO Download segment request (ccs=0, the "full" segment half carrying data), node 9 ->
    #     COB-ID 0x589. toggle=0, n=1 (1 unused trailing byte -> 6 real data bytes), c=1 ("no more
    #     segments") -> byte0=0x03.
    packets.append(can_socketcan_frame(0x589,
        bytes([0x03, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])))

    # 17) SDO Upload segment request (ccs=3, "toggle-only ack" half), node 9 -> COB-ID 0x589 (same
    #     session, later message). toggle=1 -> byte0=0x70, no data.
    packets.append(can_socketcan_frame(0x589, bytes([0x70])))

    # 18) SDO Abort Transfer (ccs=4), node 11 -> COB-ID 0x58B. Index 0x2000, sub-index 1, Abort Code
    #     0x06020000 ("Object does not exist in the object dictionary", LE).
    packets.append(can_socketcan_frame(0x58B,
        bytes([0x80]) + struct.pack("<H", 0x2000) + bytes([0x01]) + struct.pack("<I", 0x06020000)))

    # 19) SDO Block upload request (ccs=5, subcommand 0 -- "Initiate upload/download request", the
    #     mux-carrying subcommand), node 12 -> COB-ID 0x58C. CRC support bit set (0x04) -> byte0=0xA4.
    #     Index 0x6000 ("Standardized profile area 1st logical device"), sub-index 1.
    packets.append(can_socketcan_frame(0x58C, bytes([0xA4]) + struct.pack("<H", 0x6000) + bytes([0x01])))

    # 20) SDO Block upload response (scs=6, subcommand 0), node 12 -> COB-ID 0x60C. byte0=0xC0.
    packets.append(can_socketcan_frame(0x60C, bytes([0xC0]) + struct.pack("<H", 0x6000) + bytes([0x01])))

    # 21) LSS (Master), COB-ID 0x7E5 -- structural recognition only, not further decoded.
    packets.append(can_socketcan_frame(0x7E5, bytes([0x04, 0, 0, 0, 0, 0, 0, 0])))

    # 22) Unrecognized Function Code 0xD (node 15) -> COB-ID 0x68F -- "Unknown", the reference
    #     dissector's own gap, not one invented here.
    packets.append(can_socketcan_frame(0x68F, b""))

    # 23) Truncated payload: SYNC-shaped COB-ID declaring Payload Length 4 but only 1 byte actually
    #     captured -- exercises parse_socketcan_frame's own truncation-tolerant clamping.
    packets.append(can_socketcan_frame(0x080, bytes([0x2A]), payload_length_override=4))

    # 24) Truncated: fewer than the fixed 8-byte SocketCAN header itself is present -- parse-error.
    packets.append(b"\x00\x00\x00\x85\x02")

    # 25) Negative control: an ERR-flagged frame -- rejected by DeviceNet, CANopen, AND J1939 alike
    #     (the one rejection condition all three protocols' own reference dissectors share).
    packets.append(can_socketcan_frame(0x080, b"", err=True))

    # 26) Negative control: an RTR-flagged, non-EFF frame -- rejected by DeviceNet and CANopen (both
    #     reject RTR outright), proving CANopen's own rejection matches DeviceNet's exactly here even
    #     though J1939 (see packet 33 below) uniquely tolerates RTR.
    packets.append(can_socketcan_frame(0x080, b"", rtr=True))

    # ================================== SAE J1939 section =======================================

    def j1939_id(priority, pf, ps, sa, edp=0, dp=0):
        return ((priority & 0x07) << 26) | ((edp & 1) << 25) | ((dp & 1) << 24) | \
               ((pf & 0xFF) << 16) | ((ps & 0xFF) << 8) | (sa & 0xFF)

    # 27) EEC1 (PGN 61444/0xF004, PDU2/broadcast -- PF=0xF0 >= 240), priority 3, SA=0 (Engine #1).
    #     Driver's Demand Torque=+50% (byte=175), Actual Torque=+40% (byte=165), Engine Speed
    #     1500.000 rpm (raw 12000, LE).
    packets.append(can_socketcan_frame(
        j1939_id(3, 0xF0, 0x04, 0x00),
        bytes([0x00, 175, 165]) + struct.pack("<H", 12000) + bytes([0xFF, 0xFF, 0xFF]),
        eff=True))

    # 28) ET1 (PGN 65262/0xFEEE, PDU2 -- PF=0xFE), priority 6, SA=0. Coolant=85C (byte=125),
    #     Fuel=30C (byte=70), Oil Temp=90C (raw 11616, LE).
    packets.append(can_socketcan_frame(
        j1939_id(6, 0xFE, 0xEE, 0x00),
        bytes([125, 70]) + struct.pack("<H", 11616) + bytes([0xFF, 0xFF, 0xFF, 0xFF]),
        eff=True))

    # 29) CCVS (PGN 65265/0xFEF1, PDU2 -- PF=0xFE), priority 6, SA=0. Wheel-Based Vehicle Speed
    #     100.5 km/h (raw 25728, LE), Cruise Control Active = On (2-bit value 1, bits 7-6 of byte 2).
    packets.append(can_socketcan_frame(
        j1939_id(6, 0xFE, 0xF1, 0x00),
        struct.pack("<H", 25728) + bytes([0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
        eff=True))

    # 30) Request (PGN 59904/0xEA00, PDU1/point-to-point -- PF=0xEA < 240), priority 6, destination
    #     0x00 (Engine #1), source 249 (Off Board Diagnostic-Service Tool #1) -- proves
    #     destination-address extraction (this task's own explicit ask). Requests PGN 65262 (ET1),
    #     3-byte LE.
    packets.append(can_socketcan_frame(
        j1939_id(6, 0xEA, 0x00, 249),
        struct.pack("<I", 65262)[:3],
        eff=True))

    # 31) DM1 (PGN 65226/0xFECA, PDU2 -- PF=0xFE), priority 6, SA=0, CARRIED IN A CAN FD FRAME (10-
    #     byte payload -- exceeds classic CAN's 8-byte max, exactly the scenario j1939.hpp's own file
    #     header comment names) with TWO packed DTCs, proving the SPN/FMI/OC/CM bit-unpacking:
    #       lamp byte: MIL=On (2-bit 1, bits 7-6), AWL=On (2-bit 1, bits 3-2) -> 0x44; flash byte 0x00.
    #       DTC1: SPN=1569 (0x621) -> low=0x21 mid=0x06 high3=0, FMI=4, CM=0, OC=3 -> [0x21,0x06,0x04,0x03]
    #       DTC2: SPN=0x12345 -> low=0x45 mid=0x23 high3=1, FMI=13(0x0D), CM=1, OC=127(0x7F, "not
    #         available") -> [0x45,0x23,0x2D,0xFF]
    packets.append(can_socketcan_frame(
        j1939_id(6, 0xFE, 0xCA, 0x00),
        bytes([0x44, 0x00, 0x21, 0x06, 0x04, 0x03, 0x45, 0x23, 0x2D, 0xFF]),
        eff=True, fd=True))

    # 32) DM1, all lamps Off, zero DTCs (SA=3) -- the "nothing currently faulting" case, proving the
    #     zero-DTC path doesn't fabricate a phantom finding.
    packets.append(can_socketcan_frame(j1939_id(6, 0xFE, 0xCA, 0x03), bytes([0x00, 0x00]), eff=True))

    # 33) RTR, EFF-flagged frame -- J1939 UNIQUELY tolerates this (see j1939.hpp's own file header
    #     comment's "ONE FURTHER DIFFERENCE" paragraph); no payload, classified by ID alone.
    packets.append(can_socketcan_frame(j1939_id(3, 0xF0, 0x04, 0x00), b"", eff=True, rtr=True))

    # 34) Negative control: EFF AND ERR both set -- rejected even though EFF is present, proving ERR
    #     always wins regardless of EFF (mirrors dissect_j1939's own `(can_info.id & CAN_ERR_FLAG)`
    #     check, checked before/independent of the EFF requirement).
    packets.append(can_socketcan_frame(j1939_id(3, 0xF0, 0x04, 0x00), b"", eff=True, err=True))

    # 35) An uncurated PGN (PF=0xFF, PS=0xFF -> PGN 65535, not in this decoder's own curated table) --
    #     shown structurally only, by bare PGN number, never treated as an error.
    packets.append(can_socketcan_frame(j1939_id(6, 0xFF, 0xFF, 0x01),
                                        bytes([0x01, 0x02, 0x03, 0x04]), eff=True))

    # 36) Truncated payload: EEC1-shaped id declaring Payload Length 8 but only 3 bytes actually
    #     captured -- exercises the truncation-tolerant clamp path for an EFF-flagged frame too, and
    #     proves EEC1's own decode gracefully declines (fewer than 5 bytes) rather than misreading.
    packets.append(can_socketcan_frame(j1939_id(3, 0xF0, 0x04, 0x00), bytes([0x00, 0xAF, 0xA5]),
                                        eff=True, payload_length_override=8))

    data = pcap_global_header(linktype=LINKTYPE_CAN_SOCKETCAN)
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_730_000_000 + i, i * 1000)
    (TESTS_DIR / "sample_canopen_j1939.pcap").write_bytes(data)


BACNET_PORT = 47808


def ip4(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def bacnet_app_tag(tag_no: int, value: bytes) -> bytes:
    """One application-tagged primitive (class bit 0) -- tag byte + optional extended-length
    escape + value bytes. Only the short (LVT<=4, no extended length) and the one-byte-escape
    (5<=LVT<=253) forms are needed for this fixture's own values -- see bacnet.hpp's tag-encoding
    paragraph for the full clause-20.2.1 rules this mirrors."""
    lvt = len(value)
    if lvt <= 4:
        return bytes([(tag_no << 4) | lvt]) + value
    if lvt < 254:
        return bytes([(tag_no << 4) | 5, lvt]) + value
    raise ValueError("fixture helper doesn't need LVT>=254 encoding")


def bacnet_app_bool(value: bool) -> bytes:
    """Application-tagged Boolean -- the LVT field itself IS the value (0/1), no separate value
    byte at all -- see bacnet.hpp's Property value decode paragraph."""
    return bytes([(1 << 4) | (1 if value else 0)])


def bacnet_context_tag(tag_no: int, value: bytes) -> bytes:
    """One context-tagged primitive (class bit set, 0x08) -- same LVT/value shape as an
    application tag, just with the class bit set and the tag number meaning "field position"
    rather than "type"."""
    lvt = len(value)
    if lvt <= 4:
        return bytes([(tag_no << 4) | 0x08 | lvt]) + value
    if lvt < 254:
        return bytes([(tag_no << 4) | 0x08 | 5, lvt]) + value
    raise ValueError("fixture helper doesn't need LVT>=254 encoding")


def bacnet_open(tag_no: int) -> bytes:
    return bytes([(tag_no << 4) | 0x08 | 6])


def bacnet_close(tag_no: int) -> bytes:
    return bytes([(tag_no << 4) | 0x08 | 7])


def bacnet_object_id(obj_type: int, instance: int) -> bytes:
    raw = ((obj_type & 0x3FF) << 22) | (instance & 0x3FFFFF)
    return struct.pack("!I", raw)


def bacnet_unsigned(value: int) -> bytes:
    """Minimal big-endian byte count (1-4 bytes) for an Unsigned/Enumerated value -- mirrors how
    a real BACnet stack encodes these (never more bytes than needed)."""
    n = 1
    while value >= (1 << (8 * n)) and n < 4:
        n += 1
    return value.to_bytes(n, "big")


def bacnet_char_string(text: str, charset: int = 0) -> bytes:
    return bytes([charset]) + text.encode("ascii")


def bacnet_bit_string(bits: str) -> bytes:
    """`bits` a string of '1'/'0' characters, MSB first -- packed into whole bytes with an
    unused-bit-count prefix, mirroring fBitStringTagVSBase's own encoding."""
    n = len(bits)
    pad = (8 - (n % 8)) % 8
    padded = bits + ("0" * pad)
    out = bytes([pad])
    for i in range(0, len(padded), 8):
        byte = 0
        for b in padded[i:i + 8]:
            byte = (byte << 1) | (1 if b == "1" else 0)
        out += bytes([byte])
    return out


def bacnet_property_value(app_tag_no: int, value: bytes, context_tag: int = 3) -> bytes:
    return bacnet_open(context_tag) + bacnet_app_tag(app_tag_no, value) + bacnet_close(context_tag)


def bacnet_property_value_bool(value: bool, context_tag: int = 3) -> bytes:
    return bacnet_open(context_tag) + bacnet_app_bool(value) + bacnet_close(context_tag)


def bacnet_object_property_reference(obj_type: int, instance: int, prop_id: int, array_index=None) -> bytes:
    out = bacnet_context_tag(0, bacnet_object_id(obj_type, instance)) + \
        bacnet_context_tag(1, bacnet_unsigned(prop_id))
    if array_index is not None:
        out += bacnet_context_tag(2, bacnet_unsigned(array_index))
    return out


def bvlc_message(function: int, body: bytes) -> bytes:
    total = 4 + len(body)
    return struct.pack("!BBH", 0x81, function, total) + body


def npdu_header(control: int = 0x00, dnet=None, dadr: bytes = b"", snet=None, sadr: bytes = b"",
                hop_count=None, version: int = 1) -> bytes:
    out = bytes([version, control])
    if control & 0x20:  # DEST present
        out += struct.pack("!H", dnet if dnet is not None else 0) + bytes([len(dadr)]) + dadr
    if control & 0x08:  # SRC present
        out += struct.pack("!H", snet if snet is not None else 0) + bytes([len(sadr)]) + sadr
    if control & 0x20:
        out += bytes([hop_count if hop_count is not None else 255])
    return out


def npdu_network_message(msg_type: int, control: int = 0x80, vendor_id=None, body: bytes = b"", **kw) -> bytes:
    out = npdu_header(control=control, **kw)
    out += bytes([msg_type])
    if msg_type >= 0x80:
        out += struct.pack("!H", vendor_id if vendor_id is not None else 0)
    return out + body


def apdu_confirmed_request(service_choice: int, data: bytes = b"", invoke_id: int = 1, segmented: bool = False,
                            more: bool = False, seg_accepted: bool = True, seq: int = 0, window: int = 16,
                            max_segs_apdu_byte: int = 0x30) -> bytes:
    byte0 = (0 << 4) | (0x08 if segmented else 0) | (0x04 if more else 0) | (0x02 if seg_accepted else 0)
    out = bytes([byte0, max_segs_apdu_byte, invoke_id])
    if segmented:
        out += bytes([seq, window])
    return out + bytes([service_choice]) + data


def apdu_unconfirmed_request(service_choice: int, data: bytes = b"") -> bytes:
    return bytes([(1 << 4), service_choice]) + data


def apdu_simple_ack(service_choice: int, invoke_id: int = 1) -> bytes:
    return bytes([(2 << 4), invoke_id, service_choice])


def apdu_complex_ack(service_choice: int, data: bytes = b"", invoke_id: int = 1, segmented: bool = False,
                      more: bool = False, seq: int = 0, window: int = 16) -> bytes:
    byte0 = (3 << 4) | (0x08 if segmented else 0) | (0x04 if more else 0)
    out = bytes([byte0, invoke_id])
    if segmented:
        out += bytes([seq, window])
    return out + bytes([service_choice]) + data


def apdu_segment_ack(invoke_id: int, seq: int, window: int, nak: bool = False, server: bool = False) -> bytes:
    byte0 = (4 << 4) | (0x02 if nak else 0) | (0x01 if server else 0)
    return bytes([byte0, invoke_id, seq, window])


def apdu_error(error_choice: int, error_class: int, error_code: int, invoke_id: int = 1) -> bytes:
    return (bytes([(5 << 4), invoke_id, error_choice]) +
            bacnet_app_tag(9, bacnet_unsigned(error_class)) +
            bacnet_app_tag(9, bacnet_unsigned(error_code)))


def apdu_error_service_specific(error_choice: int, invoke_id: int = 1) -> bytes:
    """A service-specific error body (deliberately NOT the generic errorClass/errorCode shape) --
    here, WritePropertyMultipleError's own first-failed-write-attempt structure (a context[0]-
    wrapped object-id + context[1] priority + generic error, per fWritePropertyMultipleError) --
    exercises this decoder's "may use a service-specific error structure" note, since it does not
    special-case any of the 7 services that define one -- see bacnet.hpp's PDU-type-5 paragraph."""
    body = bacnet_open(0) + bacnet_context_tag(0, bacnet_object_id(0, 3)) + bacnet_close(0)
    return bytes([(5 << 4), invoke_id, error_choice]) + body


def apdu_reject(reason: int, invoke_id: int = 1) -> bytes:
    return bytes([(6 << 4), invoke_id, reason])


def apdu_abort(reason: int, invoke_id: int = 1, server: bool = False) -> bytes:
    byte0 = (7 << 4) | (0x01 if server else 0)
    return bytes([byte0, invoke_id, reason])


def bacnet_frame(dst=None, src=None, sport=BACNET_PORT, dport=BACNET_PORT, bvlc: bytes = b"",
                  src_ip=None, dst_ip=None) -> bytes:
    dst = dst if dst is not None else b"\xff\xff\xff\xff\xff\xff"
    src = src if src is not None else PLC_MAC
    src_ip = src_ip if src_ip is not None else PLC_IP
    dst_ip = dst_ip if dst_ip is not None else "192.168.1.255"
    udp = udp_header(sport, dport, bvlc)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x7000)
    return eth_header(dst, src, 0x0800) + ip + udp


def build_bacnet_sample():
    """BACnet/IP (Annex J) over UDP port 47808: BVLC framing, NPDU network layer, APDU application
    layer/services -- see bacnet.hpp's file header comment for the exact wire format each packet
    below exercises (cross-checked against Wireshark's own packet-bvlc.c/packet-bacnet.c/
    packet-bacapp.c). No real capture happens to be attributed for this fixture set yet at the time
    each packet was written -- see tests/real_captures/bacnet/ATTRIBUTION.md (if present) or
    bacnet.hpp's own Validation paragraph for the current state of that search."""
    packets = []

    def add(bvlc: bytes, **kw):
        packets.append(bacnet_frame(bvlc=bvlc, **kw))

    # 1) Who-Is, unrestricted (no device-instance range) -- the single most common BACnet/IP
    #    discovery broadcast, Original-Broadcast-NPDU carrying an Unconfirmed-Request.
    add(bvlc_message(0x0B, npdu_header() + apdu_unconfirmed_request(8)))

    # 2) Who-Is with a device-instance range (context[0]/[1] both present).
    add(bvlc_message(0x0B, npdu_header() +
                      apdu_unconfirmed_request(8, bacnet_context_tag(0, bacnet_unsigned(100)) +
                                                bacnet_context_tag(1, bacnet_unsigned(200)))))

    # 3) I-Am -- device object-identifier, Max-APDU-Length-Accepted, Segmentation-Supported,
    #    Vendor-ID -- the richest device-discovery/fingerprinting message on the wire.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_unconfirmed_request(0, bacnet_app_tag(12, bacnet_object_id(8, 1234)) +
                                                bacnet_app_tag(2, bacnet_unsigned(1476)) +
                                                bacnet_app_tag(9, bacnet_unsigned(3)) +
                                                bacnet_app_tag(2, bacnet_unsigned(260)))))

    # 4) Who-Has, by ObjectIdentifier, with a device-instance range.
    add(bvlc_message(0x0B, npdu_header() +
                      apdu_unconfirmed_request(7, bacnet_context_tag(0, bacnet_unsigned(1)) +
                                                bacnet_context_tag(1, bacnet_unsigned(4194302)) +
                                                bacnet_context_tag(2, bacnet_object_id(0, 3)))))

    # 5) Who-Has, by ObjectName instead (the CHOICE's other branch), no range.
    add(bvlc_message(0x0B, npdu_header() +
                      apdu_unconfirmed_request(7, bacnet_context_tag(3, bacnet_char_string("ZN-T-1")))))

    # 6) I-Have -- device id + object id + object name.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_unconfirmed_request(1, bacnet_app_tag(12, bacnet_object_id(8, 1234)) +
                                                bacnet_app_tag(12, bacnet_object_id(0, 3)) +
                                                bacnet_app_tag(7, bacnet_char_string("ZN-T-1")))))

    # 7) ReadProperty request -- present-value (85) of analog-input,3.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_confirmed_request(12, bacnet_object_property_reference(0, 3, 85), invoke_id=10)))

    # 8) ReadProperty ACK -- Real value (the most common analog present-value type).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 85) +
                                       bacnet_property_value(4, struct.pack("!f", 72.5)), invoke_id=10)))

    # 9) ReadProperty ACK -- Unsigned value (e.g. a multi-state-input's present-value).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(13, 1, 85) +
                                       bacnet_property_value(2, bacnet_unsigned(3)), invoke_id=11)))

    # 10) ReadProperty ACK -- Enumerated value (e.g. a binary-input's present-value, 0/1).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(3, 1, 85) +
                                       bacnet_property_value(9, bacnet_unsigned(1)), invoke_id=12)))

    # 11) ReadProperty ACK -- Boolean value (e.g. out-of-service).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 81) +
                                       bacnet_property_value_bool(False), invoke_id=13)))

    # 12) ReadProperty ACK -- CharacterString value (object-name).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 77) +
                                       bacnet_property_value(7, bacnet_char_string("ZN-T-1")),
                                       invoke_id=14)))

    # 13) ReadProperty ACK -- BitString value (e.g. status-flags: in-alarm=F,fault=F,overridden=F,
    #     out-of-service=T).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 111) +
                                       bacnet_property_value(8, bacnet_bit_string("0001")),
                                       invoke_id=15)))

    # 14) ReadProperty ACK with a propertyArrayIndex present (context[2]).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 85, array_index=0) +
                                       bacnet_property_value(4, struct.pack("!f", 1.0)), invoke_id=16)))

    # 15) ReadProperty ACK whose PropertyValue is CONSTRUCTED (here: two Real values back-to-back
    #     inside the open/close bracket, standing in for an array/list) -- not a single primitive,
    #     so this decoder's "first pass" does not value-decode it, only notes as much and skips
    #     past it structurally -- see bacnet.hpp's "Property value decode" paragraph.
    constructed_value = (bacnet_open(3) + bacnet_app_tag(4, struct.pack("!f", 1.0)) +
                          bacnet_app_tag(4, struct.pack("!f", 2.0)) + bacnet_close(3))
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 85) + constructed_value,
                                       invoke_id=17)))

    # 16) WriteProperty request, no Priority.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_confirmed_request(15, bacnet_object_property_reference(4, 5, 85) +
                                              bacnet_property_value(9, bacnet_unsigned(1)), invoke_id=20)))

    # 17) WriteProperty request WITH Priority (context[4]).
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_confirmed_request(15, bacnet_object_property_reference(4, 5, 85) +
                                              bacnet_property_value(9, bacnet_unsigned(0)) +
                                              bacnet_context_tag(4, bacnet_unsigned(8)), invoke_id=21)))

    # 18) Simple-ACK -- e.g. acknowledging the WriteProperty above.
    add(bvlc_message(0x0A, npdu_header() + apdu_simple_ack(15, invoke_id=20)))

    # 19) Error-PDU, generic shape -- errorClass=property(2), errorCode=unknown-property(32).
    add(bvlc_message(0x0A, npdu_header() + apdu_error(12, 2, 32, invoke_id=22)))

    # 20) Error-PDU whose error-choice (WritePropertyMultiple, 16) defines its OWN service-
    #     specific error structure rather than the generic errorClass/errorCode shape -- this
    #     decoder doesn't special-case those 7 services, so it's named but shown as raw hex, with
    #     an explanatory note -- see bacnet.hpp's PDU-type-5 paragraph.
    add(bvlc_message(0x0A, npdu_header() + apdu_error_service_specific(16, invoke_id=23)))

    # 21) Reject-PDU.
    add(bvlc_message(0x0A, npdu_header() + apdu_reject(9, invoke_id=24)))  # unrecognized-service

    # 22) Abort-PDU, server=False (client aborted).
    add(bvlc_message(0x0A, npdu_header() + apdu_abort(0, invoke_id=25, server=False)))

    # 23) Abort-PDU, server=True (server aborted).
    add(bvlc_message(0x0A, npdu_header() + apdu_abort(9, invoke_id=26, server=True)))  # out-of-resources

    # 24) Segment-ACK, ordinary (not negative, not server).
    add(bvlc_message(0x0A, npdu_header() + apdu_segment_ack(invoke_id=27, seq=2, window=8)))

    # 25) Segment-ACK, negative (NAK) and server bits both set.
    add(bvlc_message(0x0A, npdu_header() + apdu_segment_ack(invoke_id=28, seq=0, window=8, nak=True, server=True)))

    # 26) A segmented Confirmed-Request (SEG bit set) -- this decoder decodes the sequence-
    #     number/proposed-window-size header fields but deliberately does NOT value-decode the
    #     segment's own service data (no cross-packet reassembly) -- shown as raw hex with an
    #     explanatory note. service_choice 14 = readPropertyMultiple, a service this decoder
    #     doesn't value-decode even when unsegmented, doubling as an "outside the first-pass set"
    #     example too.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_confirmed_request(14, bytes([0xAA, 0xBB, 0xCC, 0xDD]), invoke_id=30,
                                              segmented=True, seq=1, window=8)))

    # 27) A segmented Complex-ACK.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_complex_ack(14, bytes([0xEE, 0xFF]), invoke_id=31, segmented=True, seq=2,
                                       window=8)))

    # 28) A confirmed service outside this decoder's "first pass" set (SubscribeCOV, 5) -- named
    #     via the service-choice table, but its data is shown as raw hex, not value-decoded.
    add(bvlc_message(0x0A, npdu_header() +
                      apdu_confirmed_request(5, bytes([0x0C, 0x02, 0x00, 0x03]), invoke_id=32)))

    # 29) An unconfirmed service outside the "first pass" set (UnconfirmedCOVNotification, 2).
    add(bvlc_message(0x0B, npdu_header() + apdu_unconfirmed_request(2, bytes([0x09, 0x01, 0x64]))))

    # 30) NPDU with DEST present (DNET/DLEN/DADR + trailing HopCount) -- an ordinary 6-byte
    #     Ethernet MAC destination address on a remote network.
    add(bvlc_message(0x0A, npdu_header(control=0x20, dnet=5, dadr=bytes.fromhex("aabbccddeeff"),
                                        hop_count=255) +
                      apdu_unconfirmed_request(8)))

    # 31) NPDU with DEST present and DLEN=0 -- broadcast on the destination network.
    add(bvlc_message(0x0A, npdu_header(control=0x20, dnet=5, dadr=b"", hop_count=255) +
                      apdu_unconfirmed_request(8)))

    # 32) NPDU with SRC present (this NPDU was forwarded from another network by a router).
    add(bvlc_message(0x0A, npdu_header(control=0x08, snet=7, sadr=bytes.fromhex("112233445566")) +
                      apdu_unconfirmed_request(0, bacnet_app_tag(12, bacnet_object_id(8, 999)) +
                                                bacnet_app_tag(2, bacnet_unsigned(480)) +
                                                bacnet_app_tag(9, bacnet_unsigned(3)) +
                                                bacnet_app_tag(2, bacnet_unsigned(0)))))

    # 33) NPDU with BOTH DEST and SRC present (a router forwarding across two networks).
    add(bvlc_message(0x0A, npdu_header(control=0x28, dnet=5, dadr=bytes.fromhex("aabbccddeeff"),
                                        snet=7, sadr=bytes.fromhex("112233445566"), hop_count=200) +
                      apdu_unconfirmed_request(8)))

    # 34) A Network Layer Message (Control NET bit set) -- Who-Is-Router-To-Network (0x00), no
    #     APDU at all. Named only, not value-decoded -- see bacnet.hpp's NPDU section.
    add(bvlc_message(0x0A, npdu_network_message(0x00)))

    # 35) A vendor-proprietary Network Layer Message (message type 0x80+, carries a 2-byte Vendor
    #     ID immediately after the message type).
    add(bvlc_message(0x0A, npdu_network_message(0x80, vendor_id=999, body=bytes([0x01, 0x02]))))

    # 36) BVLC-Result (0x00) -- a BBMD's ack/nak of a preceding BDT/FDT-management request; no
    #     NPDU at all (the whole message is BVLC).
    add(bvlc_message(0x00, struct.pack("!H", 0x0000)))

    # 37) Write-Broadcast-Distribution-Table -- two 10-byte BDT entries (IP+Port+Mask).
    bdt_entries = (ip4("192.168.1.1") + struct.pack("!H", 47808) + ip4("255.255.255.0") +
                   ip4("192.168.2.1") + struct.pack("!H", 47808) + ip4("255.255.255.0"))
    add(bvlc_message(0x01, bdt_entries))

    # 38) Read-Broadcast-Distribution-Table -- an empty request, nothing beyond the BVLC header.
    add(bvlc_message(0x02, b""))

    # 39) Read-Broadcast-Distribution-Table-Ack -- same 10-byte-entry shape as function 0x01.
    add(bvlc_message(0x03, bdt_entries))

    # 40) Register-Foreign-Device -- 2-byte Time-To-Live.
    add(bvlc_message(0x05, struct.pack("!H", 300)))

    # 41) Read-Foreign-Device-Table -- an empty request.
    add(bvlc_message(0x06, b""))

    # 42) Read-Foreign-Device-Table-Ack -- one 10-byte entry (IP+Port+TTL+Timeout).
    fdt_entry = ip4("192.168.1.50") + struct.pack("!H", 47808) + struct.pack("!HH", 300, 180)
    add(bvlc_message(0x07, fdt_entry))

    # 43) Delete-Foreign-Device-Table-Entry -- 6-byte IP+Port.
    add(bvlc_message(0x08, ip4("192.168.1.50") + struct.pack("!H", 47808)))

    # 44) Forwarded-NPDU -- a BBMD relaying a Who-Is broadcast on behalf of a foreign device,
    #     carrying the ORIGINATING device's own 6-byte B/IP address ahead of the NPDU (distinct
    #     from this packet's own UDP/IP source, which is the relaying BBMD).
    add(bvlc_message(0x04, ip4("192.168.5.20") + struct.pack("!H", 47808) +
                      npdu_header() + apdu_unconfirmed_request(8)))

    # 45) Distribute-Broadcast-To-Network -- a foreign device asking its BBMD to broadcast an
    #     NPDU on its behalf.
    add(bvlc_message(0x09, npdu_header() + apdu_unconfirmed_request(8)))

    # 46) Secure-BVLL -- an opaque, encrypted/signed payload this decoder cannot decrypt --
    #     named only, with a note, see bacnet.hpp's BVLC section.
    add(bvlc_message(0x0C, bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])))

    # 47) BVLC header's own declared Length mismatched against the bytes actually present --
    #     surfaced as a note, not a rejection (mirrors GOOSE/SV/EtherCAT's own tolerant-declared-
    #     length handling).
    mismatched = bytearray(bvlc_message(0x0A, npdu_header() + apdu_unconfirmed_request(8)))
    struct.pack_into("!H", mismatched, 2, len(mismatched) + 10)
    add(bytes(mismatched))

    # 48) BVLC message truncated before even the fixed 4-byte header completes -- must not crash,
    #     falls back to the generic "udp" groundwork report (structural detection gate declines).
    add(bytes([0x81, 0x0A]))

    # 49) BVLC Type byte is not 0x81 (here 0x82, BACnet/SC's own type byte) -- must NOT be
    #     misdetected as BACnet/IP (Annex J) -- see bacnet.hpp's "structural detection gate"
    #     paragraph.
    wrong_type = bytearray(bvlc_message(0x0A, npdu_header() + apdu_unconfirmed_request(8)))
    wrong_type[0] = 0x82
    add(bytes(wrong_type))

    # 50) BVLC Function byte is not one of the 13 the spec defines (0x00-0x0C) -- here 0x0D --
    #     must NOT be misdetected.
    bogus_function = bytearray(bvlc_message(0x0A, npdu_header() + apdu_unconfirmed_request(8)))
    bogus_function[1] = 0x0D
    add(bytes(bogus_function))

    # 51) NPDU truncated right after Version/Control (no APDU bytes at all present).
    add(bvlc_message(0x0A, bytes([0x01, 0x00])))

    # 52) An APDU PDU type this decoder doesn't recognize (top nibble 15, not one of the 8 the
    #     spec defines 0-7) -- the BVLC/NPDU layers still decode fine; only the APDU itself is
    #     left unrecognized, with a note.
    add(bvlc_message(0x0A, npdu_header() + bytes([0xF0])))

    # 53) Not BACnet/IP at all -- ordinary UDP traffic on an unrelated port with a payload that
    #     happens to start with 0x81 -- must not be misdetected regardless of port (the structural
    #     gate is Type+Function, not port -- see bacnet.hpp).
    add_unrelated = bacnet_frame(sport=51000, dport=51001,
                                  bvlc=bytes([0x99, 0x99, 0x99, 0x99]))
    packets.append(add_unrelated)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_005_000 + i, i * 1000)
    (TESTS_DIR / "sample_bacnet.pcap").write_bytes(data)


ENIP_PORT = 44818


def enip_header(command: int, data_len: int, session_handle: int = 0, status: int = 0,
                 sender_context: bytes = b"\x00" * 8, options: int = 0) -> bytes:
    """The fixed 24-byte EtherNet/IP encapsulation header -- see enip.hpp's file header comment.
    Everything here is little-endian."""
    assert len(sender_context) == 8
    return (struct.pack("<HHII", command, data_len, session_handle, status) + sender_context +
            struct.pack("<I", options))


def enip_message(command: int, data: bytes = b"", session_handle: int = 0, status: int = 0,
                  sender_context: bytes = b"\x00" * 8, options: int = 0) -> bytes:
    return enip_header(command, len(data), session_handle, status, sender_context, options) + data


def enip_cpf_unconnected(cip_bytes: bytes, timeout: int = 10) -> bytes:
    """SendRRData's encapsulated data: Interface Handle(4, always 0) + Timeout(2) + Item Count(2)=2,
    then a Null Address Item (type 0x0000, empty) and an Unconnected Data Item (type 0x00B2)
    carrying `cip_bytes` -- the common shape real unconnected explicit-messaging clients use."""
    return (struct.pack("<IH", 0, timeout) + struct.pack("<H", 2) +
            struct.pack("<HH", 0x0000, 0) +
            struct.pack("<HH", 0x00B2, len(cip_bytes)) + cip_bytes)


def cip_symbolic_path(tag: str) -> bytes:
    """The ANSI Extended Symbol segment (0x91) Logix5000 uses for named-tag addressing: segment
    byte + 1-byte ASCII length + the ASCII tag name + a pad byte if that length is odd (EPATH
    segments are always word-aligned)."""
    name = tag.encode("ascii")
    body = bytes([0x91, len(name)]) + name
    if len(name) % 2 != 0:
        body += b"\x00"
    assert len(body) % 2 == 0
    return body


def cip_read_tag_request(tag: str, element_count: int = 1) -> bytes:
    path = cip_symbolic_path(tag)
    return bytes([0x4C, len(path) // 2]) + path + struct.pack("<H", element_count)


def cip_read_tag_response(type_code: int, value_bytes: bytes, status: int = 0x00) -> bytes:
    # service|0x80, reserved=0, general_status, additional_status_size=0, then type_code + value(s).
    return bytes([0x4C | 0x80, 0x00, status, 0x00]) + struct.pack("<H", type_code) + value_bytes


def cip_write_tag_request(tag: str, type_code: int, value_bytes: bytes, element_count: int = 1) -> bytes:
    path = cip_symbolic_path(tag)
    return (bytes([0x4D, len(path) // 2]) + path + struct.pack("<HH", type_code, element_count) +
             value_bytes)


def cip_write_tag_response(status: int = 0x00) -> bytes:
    return bytes([0x4D | 0x80, 0x00, status, 0x00])


def build_enip_sample():
    """A hand-built EtherNet/IP session exercising RegisterSession/UnRegisterSession (real captures
    obtained for this feature happened not to include one -- see tests/real_captures/enip/
    ATTRIBUTION.md), a ListIdentity request/response (device-fingerprinting fields: vendor/device
    type/product code/revision/serial/product name), and a symbolic (ANSI Extended Symbol segment
    0x91) Read_Tag/Write_Tag round trip against a named tag -- also not present in the real
    captures, which only ever used class/instance addressing -- so the full type+value decode path
    is exercised with hand-verifiable expected values, same rationale as build_iec104_sample above."""
    packets = []
    client_seq = [8000]
    server_seq = [9000]

    def add(from_client: bool, payload: bytes):
        if from_client:
            src_port, dst_port = 52000, ENIP_PORT
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = ENIP_PORT, 52000
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x5000 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    session_handle = 0x11223344
    ctx = b"CS-ENIP1"

    # 1) & 2) RegisterSession request/response -- the handshake that begins every real EtherNet/IP
    #    explicit-messaging session (protocol version 1, options flags 0).
    add(True, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=0, sender_context=ctx))
    add(False, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=session_handle,
                             sender_context=ctx))

    # 3) & 4) ListIdentity request/response -- device fingerprinting fields. List commands don't
    #    require a registered session, so session_handle stays 0 here (as real clients do).
    add(True, enip_message(0x0063, data=b"", session_handle=0, sender_context=ctx))
    name = b"Conduit-ENIP-Sample"
    identity_item = (
        struct.pack("<H", 1) +                                           # protocol version
        struct.pack("!H", 2) +                                           # sin_family AF_INET (big-endian)
        struct.pack("!H", ENIP_PORT) +                                   # sin_port (big-endian)
        bytes(int(o) for o in PLC_IP.split(".")) +                       # sin_addr (network/big-endian octets)
        b"\x00" * 8 +                                                    # sin_zero
        struct.pack("<HHH", 1, 0x0C, 54) +                               # vendor=1 (Rockwell Automation),
                                                                          # device_type=0x0C (Comms Adapter),
                                                                          # product_code=54
        bytes([2, 1]) +                                                  # revision 2.1
        struct.pack("<H", 0x0030) +                                      # status
        struct.pack("<I", 0x001337AB) +                                  # serial number
        bytes([len(name)]) + name
    )
    li_item = struct.pack("<H", 1) + struct.pack("<HH", 0x000C, len(identity_item)) + identity_item
    add(False, enip_message(0x0063, data=li_item, session_handle=0, sender_context=ctx))

    # 5) & 6) SendRRData: symbolic Read_Tag request/response for tag "Pump1_Speed" -- a DINT (type
    #    0xC4) value of 42.
    add(True, enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("Pump1_Speed", 1)),
                            session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(0x006F,
                             data=enip_cpf_unconnected(cip_read_tag_response(0xC4, struct.pack("<i", 42))),
                             session_handle=session_handle, sender_context=ctx))

    # 7) & 8) SendRRData: symbolic Write_Tag request/response, writing 100 to the same tag.
    add(True, enip_message(
        0x006F, data=enip_cpf_unconnected(cip_write_tag_request("Pump1_Speed", 0xC4, struct.pack("<i", 100), 1)),
        session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(0x006F, data=enip_cpf_unconnected(cip_write_tag_response(0x00)),
                             session_handle=session_handle, sender_context=ctx))

    # 9) UnRegisterSession -- no response by spec; the client just closes its connection afterward.
    add(True, enip_message(0x0066, data=b"", session_handle=session_handle, sender_context=ctx))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_000 + i, i * 1000)
    (TESTS_DIR / "sample_enip.pcap").write_bytes(data)


def build_enip_string_and_structured_sample():
    """A hand-built EtherNet/IP session (RegisterSession handshake, then a series of symbolic
    Read_Tag/Write_Tag request+response pairs over that one registered session) exercising the two
    CIP value categories build_enip_sample above doesn't touch: STRING (0xD0)/SHORT_STRING (0xDA)
    elementary types, and Rockwell Logix5000's Structured Data Type (UDT/array-of-UDT tag)
    encoding (type code >= 0x02A0, a 2-byte Structure Handle followed by raw member bytes) -- see
    decode_cip_string_elements/decode_cip_structured_element in enip.cpp for the decoder side."""
    packets = []
    client_seq = [8000]
    server_seq = [9000]

    def add(from_client: bool, payload: bytes):
        if from_client:
            src_port, dst_port = 52000, ENIP_PORT
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = ENIP_PORT, 52000
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x5200 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    session_handle = 0x55667788
    ctx = b"CS-ENIP2"

    # 1) & 2) RegisterSession request/response -- same handshake shape as build_enip_sample above.
    add(True, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=0, sender_context=ctx))
    add(False, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=session_handle,
                             sender_context=ctx))

    # 3) & 4) Read_Tag request/response for tag "FaultMessage": a STRING (0xD0) value. Expected
    #    decoded values: type=STRING, "PumpFault" (len=9, ASCII, no null terminator/padding).
    fault_text = b"PumpFault"
    add(True, enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("FaultMessage", 1)),
                            session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(
        0x006F,
        data=enip_cpf_unconnected(cip_read_tag_response(0xD0, struct.pack("<H", len(fault_text)) + fault_text)),
        session_handle=session_handle, sender_context=ctx))

    # 5) & 6) Write_Tag request/response for tag "StatusCode": a SHORT_STRING (0xDA) value.
    #    Expected decoded value: type=SHORT_STRING element_count=1, "OK" (len=2, ASCII).
    status_text = b"OK"
    add(True, enip_message(
        0x006F,
        data=enip_cpf_unconnected(cip_write_tag_request(
            "StatusCode", 0xDA, bytes([len(status_text)]) + status_text, 1)),
        session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(0x006F, data=enip_cpf_unconnected(cip_write_tag_response(0x00)),
                             session_handle=session_handle, sender_context=ctx))

    # 7) & 8) Read_Tag request/response for tag "EmptyMessage": a STRING (0xD0) value whose length
    #    prefix is 0 -- the empty-string edge case. Expected decoded values: type=STRING, "" (an
    #    empty string entry in enip_cip_values).
    add(True, enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("EmptyMessage", 1)),
                            session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(
        0x006F, data=enip_cpf_unconnected(cip_read_tag_response(0xD0, struct.pack("<H", 0))),
        session_handle=session_handle, sender_context=ctx))

    # 9) & 10) Read_Tag request/response for tag "MotorParams": a UDT-typed tag -- Structured Data
    #    Type (type code 0x02A0, in the >= 0x02A0 reserved range) + a hand-chosen Structure Handle
    #    (0x1234) + 6 bytes of arbitrary "member data" (meaningless here -- shown as hex, since
    #    this decoder has no Template definition to split it into members). Expected decoded
    #    values: type=Structured Data Type (0x02A0), structure_handle=0x1234; the member bytes
    #    show up as a hex note, not as a values[] entry.
    structure_handle = 0x1234
    member_bytes = b"\x01\x00\x2A\x00\x00\x00"
    add(True, enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("MotorParams", 1)),
                            session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(
        0x006F,
        data=enip_cpf_unconnected(cip_read_tag_response(
            0x02A0, struct.pack("<H", structure_handle) + member_bytes)),
        session_handle=session_handle, sender_context=ctx))

    # 11) & 12) Write_Tag request/response writing the same UDT shape back to "MotorParams".
    #     Expected decoded values: type=Structured Data Type (0x02A0) element_count=1,
    #     structure_handle=0x1234 (same member bytes note as above).
    add(True, enip_message(
        0x006F,
        data=enip_cpf_unconnected(cip_write_tag_request(
            "MotorParams", 0x02A0, struct.pack("<H", structure_handle) + member_bytes, 1)),
        session_handle=session_handle, sender_context=ctx))
    add(False, enip_message(0x006F, data=enip_cpf_unconnected(cip_write_tag_response(0x00)),
                             session_handle=session_handle, sender_context=ctx))

    # 13) UnRegisterSession -- no response by spec.
    add(True, enip_message(0x0066, data=b"", session_handle=session_handle, sender_context=ctx))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_100 + i, i * 1000)
    (TESTS_DIR / "sample_enip_string_and_structured.pcap").write_bytes(data)


def build_enip_nop_precedence_sample():
    """Regression fixture for the NOP-exclusion fix (see enip_command_name's comment in enip.cpp
    and tests/real_captures/enip/ATTRIBUTION.md): a 24-byte all-zero buffer -- exactly what a NOP
    encapsulation message (command 0x0000, length 0, session handle 0, status 0, sender context all
    zero, options 0) looks like on the wire -- sent on EtherNet/IP's own port must NOT be classified
    as enip, since NOP is deliberately not a recognized command. It should fall through to the
    generic "did not match any known protocol" TCP summary instead."""
    payload = bytes(24)
    tcp = tcp_header(52001, ENIP_PORT, 100, 200, TCP_PSH | TCP_ACK, len(payload)) + payload
    ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), 0x5100) + tcp
    eth = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip

    data = pcap_global_header()
    data += pcap_record(eth, 1_700_002_500, 0)
    (TESTS_DIR / "sample_enip_nop_precedence.pcap").write_bytes(data)


ENIP_IO_PORT = 2222


def cip_sequenced_address_item(connection_id: int, sequence_number: int) -> bytes:
    """CPF item 0x8002 (Sequenced Address Item): type+length header, then a 4-byte connection ID
    and 4-byte sequence number, both little-endian -- the fixed 8-byte shape try_parse_cip_io
    (enip.cpp) uses as its structural detection anchor (exact type AND exact length -- see that
    function's header comment in enip.hpp)."""
    return struct.pack("<HH", 0x8002, 8) + struct.pack("<II", connection_id, sequence_number)


def cip_connected_data_item(data: bytes) -> bytes:
    """CPF item 0x00B1 (Connected Data Item) carrying `data` -- for CIP I/O this is the raw
    I/O/assembly data (or, for a Class 1/2/3 connection, a leading 16-bit CIP sequence count
    followed by that data -- conduitscope does not distinguish the two on the wire alone; see
    enip.hpp's file header comment's CIP implicit messaging section for why)."""
    return struct.pack("<HH", 0x00B1, len(data)) + data


def cip_io_datagram(connection_id: int, sequence_number: int, io_data: bytes = None,
                     extra_items: bytes = b"", extra_item_count: int = 0) -> bytes:
    """One complete CIP I/O (implicit messaging) UDP payload: Item Count(2) + a Sequenced Address
    Item, optionally followed by a Connected Data Item carrying `io_data` and/or already-encoded
    raw `extra_items` bytes (for exercising CPF item types this decoder names but doesn't further
    decode). There is no 24-byte encapsulation header here at all, unlike explicit messaging --
    see enip.hpp's file header comment's CIP implicit messaging section."""
    items = cip_sequenced_address_item(connection_id, sequence_number)
    item_count = 1
    if io_data is not None:
        items += cip_connected_data_item(io_data)
        item_count += 1
    items += extra_items
    item_count += extra_item_count
    return struct.pack("<H", item_count) + items


def build_enip_cip_io_sample():
    """CIP I/O (implicit messaging) UDP/2222 datagrams -- the real-time, cyclic I/O data exchange a
    prior Forward_Open (explicit messaging, see build_enip_sample) establishes between an
    originator and a target. See enip.hpp's file header comment's CIP implicit messaging section
    and try_parse_cip_io's own comment (enip.hpp) for the exact wire format this exercises.

    No real-world CIP I/O capture was found for this feature (see tests/real_captures/enip/
    ATTRIBUTION.md) -- these datagrams are built from ODVA's documented Common Packet Format item
    shapes (Sequenced Address Item 0x8002, Connected Data Item 0x00B1), independently cross-checked
    against Wireshark's own packet-enip.c dissector source rather than reverse-engineered from a
    single example."""
    packets = []

    def add(payload: bytes, ts_offset: int):
        udp = udp_header(ENIP_IO_PORT, ENIP_IO_PORT, payload)
        ip = ipv4_header(PLC_IP, HMI_IP, 17, len(udp), 0x7000 + ts_offset) + udp
        packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip)

    # 1) First cyclic I/O update on a connection: connection ID 0xABCD1234, sequence 1, 4 bytes of
    #    I/O data -- shown only as raw hex (see enip.hpp).
    add(cip_io_datagram(0xABCD1234, 1, io_data=bytes([0xDE, 0xAD, 0xBE, 0xEF])), 0)

    # 2) Same connection's next update: sequence rolls to 2, the data changes -- confirms each
    #    datagram is decoded independently (no cross-packet state needed for this).
    add(cip_io_datagram(0xABCD1234, 2, io_data=bytes([0x01, 0x02, 0x03, 0x04])), 1)

    # 3) A datagram with a Sequenced Address Item but no Connected Data Item at all -- a legitimate
    #    shape (e.g. a heartbeat with no data segment); exercises the "(no Connected Data Item
    #    present)" summary wording.
    add(cip_io_datagram(0xABCD1234, 3), 2)

    # 4) A different connection whose item list also carries a Sockaddr Info item (0x8002's
    #    neighbor, 0x8001 -- present but not decoded) ahead of its Connected Data Item -- exercises
    #    the generic "CPF item ... not decoded" note path alongside a real data item in the same
    #    datagram.
    sockaddr_info_item = struct.pack("<HH", 0x8001, 4) + bytes([0x00, 0x01, 0x02, 0x03])
    add(cip_io_datagram(0x11112222, 10, io_data=bytes([0xFF]),
                         extra_items=sockaddr_info_item, extra_item_count=1), 3)

    # 5) A UDP/2222 payload that does NOT start with a Sequenced Address Item (item type 0x0000, a
    #    Null Address Item, instead) -- must NOT be misdetected as CIP I/O; falls through to the
    #    generic "udp" tag. Regression fixture for try_parse_cip_io's structural gate (exact item
    #    type AND exact length -- see its header comment in enip.hpp).
    not_cip_io = struct.pack("<H", 1) + struct.pack("<HH", 0x0000, 8) + bytes(8)
    add(not_cip_io, 4)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_002_600 + i, i * 1000)
    (TESTS_DIR / "sample_enip_cip_io.pcap").write_bytes(data)


def build_policy_functions_enip_sample():
    """Minimal fixture for the policy 'functions:' allow-list feature (policy.hpp/policy_engine.cpp)
    covering EtherNet/IP specifically: unlike every other protocol's existing sample fixtures,
    sample_enip.pcap's one Read_Tag/Write_Tag round trip happens on a SINGLE TCP flow, so there is
    no existing capture with a flow that exercises just one CIP service on its own -- needed to
    demonstrate a functions-restricted conduit passing a compliant flow while flagging a DIFFERENT
    flow on the same protocol/port/zone-pair as a violation (see PolicyEngine's strict-all function
    matching in finish()). Two separate flows, one CIP service (request+response) on each:
      - client port 53000: Read_Tag only.
      - client port 53001: Write_Tag only.
    No RegisterSession/ListIdentity handshake -- see build_enip_sample for that; this fixture is
    deliberately as small as it can be while still giving PolicyEngine two independent flows to
    tell apart."""
    packets = []
    ident = [0x5200]

    def add(from_client: bool, client_port: int, seq: int, ack: int, payload: bytes):
        if from_client:
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            src_port, dst_port = client_port, ENIP_PORT
        else:
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            src_port, dst_port = ENIP_PORT, client_port
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        ident[0] += 1
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    session_handle = 0x99887766
    ctx = b"CS-PLFN1"

    # Flow A (client port 53000): Read_Tag request/response only.
    req_a = enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("Speed", 1)),
                          session_handle=session_handle, sender_context=ctx)
    add(True, 53000, 1000, 2000, req_a)
    resp_a = enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_response(0xC4, struct.pack("<i", 7))),
                           session_handle=session_handle, sender_context=ctx)
    add(False, 53000, 2000, 1000 + len(req_a), resp_a)

    # Flow B (client port 53001): Write_Tag request/response only.
    req_b = enip_message(
        0x006F, data=enip_cpf_unconnected(cip_write_tag_request("Speed", 0xC4, struct.pack("<i", 55), 1)),
        session_handle=session_handle, sender_context=ctx)
    add(True, 53001, 3000, 4000, req_b)
    resp_b = enip_message(0x006F, data=enip_cpf_unconnected(cip_write_tag_response(0x00)),
                           session_handle=session_handle, sender_context=ctx)
    add(False, 53001, 4000, 3000 + len(req_b), resp_b)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_020_000 + i, i * 1000)
    (TESTS_DIR / "sample_policy_functions_enip.pcap").write_bytes(data)


def tpkt_frame(cotp_header: bytes, user_data: bytes = b"") -> bytes:
    """Wraps a COTP header in its length-indicator byte and the 4-byte TPKT
    header, then appends `user_data` (e.g. an S7comm payload) AFTER the
    length-indicator-counted portion. This matters: for a Data (DT) PDU, the
    length indicator counts only the fixed 2-byte DT header (PDU type +
    TPDU-NR/EOT) -- the user data that follows is NOT included in it, even
    though it obviously is included in the overall TPKT length. Folding user
    data into `cotp_header` here would produce a frame conduitscope (correctly)
    reads as having zero bytes of user data, since it trusts the length
    indicator over guessing. For a Connection Request/Confirm, there IS no
    separate user data -- the whole thing (including TLV parameters) belongs
    in `cotp_header`, and `user_data` should be left empty."""
    li = len(cotp_header)
    tpkt_length = 4 + 1 + li + len(user_data)
    return struct.pack("!BBH", 0x03, 0x00, tpkt_length) + bytes([li]) + cotp_header + user_data


def cotp_connection_pdu(pdu_type: int, dst_ref: int, src_ref: int, calling_tsap: bytes,
                         called_tsap: bytes) -> bytes:
    body = bytes([pdu_type]) + struct.pack("!HHB", dst_ref, src_ref, 0x00)
    body += bytes([0xC0, 1, 0x0A])  # TPDU size = 2^10
    body += bytes([0xC1, len(calling_tsap)]) + calling_tsap
    body += bytes([0xC2, len(called_tsap)]) + called_tsap
    return body


# Fixed 2-byte COTP header for a Data (DT) PDU: PDU type 0xF0, TPDU-NR=0 with the EOT bit set.
COTP_DT_HEADER = bytes([0xF0, 0x80])


def s7_header(rosctr: int, pdu_ref: int, param_len: int, data_len: int) -> bytes:
    return struct.pack("!BB", 0x32, rosctr) + struct.pack("!H", 0) + struct.pack("!HHH", pdu_ref, param_len, data_len)


def build_s7comm_sample():
    ENG_IP = HMI_IP  # reuse the same fake addresses/MACs as the Modbus sample
    ENG_PORT = 49200

    packets = []

    # 1) COTP Connection Request: engineering station -> PLC, TSAP 01:00 calling / 03:02 called
    #    (a typical S7-300 rack 0 / slot 2 addressing).
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cr = tpkt_frame(cr)
    tcp_cr = tcp_header(ENG_PORT, 102, 200, 300, TCP_PSH | TCP_ACK, len(cotp_cr)) + cotp_cr
    ip_cr = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_cr), 0x3000) + tcp_cr
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_cr)

    # 2) COTP Connection Confirm: PLC -> engineering station
    cc = cotp_connection_pdu(0xD0, 0x0001, 0x5001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cc = tpkt_frame(cc)
    tcp_cc = tcp_header(102, ENG_PORT, 300, 200 + len(cotp_cr), TCP_PSH | TCP_ACK, len(cotp_cc)) + cotp_cc
    ip_cc = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_cc), 0x3001) + tcp_cc
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_cc)

    # 3) S7comm Setup Communication -- Job request
    setup_param = struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240)
    setup_req = s7_header(0x01, 1, len(setup_param), 0) + setup_param
    cotp_setup_req = tpkt_frame(COTP_DT_HEADER, setup_req)
    tcp3 = tcp_header(ENG_PORT, 102, 400, 500, TCP_PSH | TCP_ACK, len(cotp_setup_req)) + cotp_setup_req
    ip3 = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp3), 0x3002) + tcp3
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip3)

    # 4) S7comm Setup Communication -- Ack_Data response
    setup_resp_param = struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240)
    setup_resp = s7_header(0x03, 1, len(setup_resp_param), 0) + struct.pack("!BB", 0, 0) + setup_resp_param
    cotp_setup_resp = tpkt_frame(COTP_DT_HEADER, setup_resp)
    tcp4 = tcp_header(102, ENG_PORT, 500, 400 + len(cotp_setup_req), TCP_PSH | TCP_ACK,
                       len(cotp_setup_resp)) + cotp_setup_resp
    ip4 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp4), 0x3003) + tcp4
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip4)

    # An S7ANY item address spec: var-spec header (0x12, length=10) + syntax id
    # (0x10) + transport size + count + DB number + area + 3-byte address
    # (byte_address << 3 | bit_offset). This is the real wire format, not a
    # placeholder -- it's what tests/sample_s7comm.pcap now exercises the new
    # item-level decoder against.
    def s7any_item(transport_size: int, count: int, db_number: int, area: int, byte_address: int,
                    bit_offset: int = 0) -> bytes:
        addr = (byte_address << 3) | bit_offset
        return (bytes([0x12, 0x0A, 0x10, transport_size]) +
                struct.pack("!HHB", count, db_number, area) +
                bytes([(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]))

    AREA_DB, AREA_MERKER = 0x84, 0x83
    TS_WORD, TS_BIT = 0x04, 0x01

    # 5) S7comm Read Var -- Job request: read 5 words from DB10 starting at byte 100.
    read_item = s7any_item(TS_WORD, 5, 10, AREA_DB, 100)
    read_param = bytes([0x04, 0x01]) + read_item
    read_req = s7_header(0x01, 2, len(read_param), 0) + read_param
    cotp_read_req = tpkt_frame(COTP_DT_HEADER, read_req)
    tcp5 = tcp_header(ENG_PORT, 102, 600, 700, TCP_PSH | TCP_ACK, len(cotp_read_req)) + cotp_read_req
    ip5 = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp5), 0x3004) + tcp5
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip5)

    # 6) S7comm Read Var -- Ack_Data response: the 5 words just requested (values 1..5),
    #    as one data item -- return_code=Success, transport_size=BYTE/WORD/DWORD (0x04),
    #    length=80 bits (5 words * 16 bits), then the 10 bytes of data itself.
    read_values = b"".join(struct.pack("!H", v) for v in range(1, 6))
    read_resp_param = bytes([0x04, 0x01])
    read_resp_data = bytes([0xFF, 0x04, 0x00, 0x50]) + read_values
    read_resp = (s7_header(0x03, 2, len(read_resp_param), len(read_resp_data)) + struct.pack("!BB", 0, 0) +
                 read_resp_param + read_resp_data)
    cotp_read_resp = tpkt_frame(COTP_DT_HEADER, read_resp)
    tcp6 = tcp_header(102, ENG_PORT, 700, 600 + len(cotp_read_req), TCP_PSH | TCP_ACK,
                       len(cotp_read_resp)) + cotp_read_resp
    ip6 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp6), 0x3005) + tcp6
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip6)

    # 7) S7comm Write Var -- Job request: write a single bit (true) to M0.0.
    write_item = s7any_item(TS_BIT, 1, 0, AREA_MERKER, 0, bit_offset=0)
    write_param = bytes([0x05, 0x01]) + write_item
    write_data = bytes([0x00, 0x03, 0x00, 0x01, 0x01])  # reserved(0)+transport(BIT)+length=1 bit+data(true)
    write_req = s7_header(0x01, 3, len(write_param), len(write_data)) + write_param + write_data
    cotp_write_req = tpkt_frame(COTP_DT_HEADER, write_req)
    tcp7 = tcp_header(ENG_PORT, 102, 800, 900, TCP_PSH | TCP_ACK, len(cotp_write_req)) + cotp_write_req
    ip7 = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp7), 0x3006) + tcp7
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip7)

    # 8) S7comm Write Var -- Ack_Data response: single Success return code, no value payload.
    write_resp_param = bytes([0x05, 0x01])
    write_resp_data = bytes([0xFF])
    write_resp = (s7_header(0x03, 3, len(write_resp_param), len(write_resp_data)) + struct.pack("!BB", 0, 0) +
                  write_resp_param + write_resp_data)
    cotp_write_resp = tpkt_frame(COTP_DT_HEADER, write_resp)
    tcp8 = tcp_header(102, ENG_PORT, 900, 800 + len(cotp_write_req), TCP_PSH | TCP_ACK,
                       len(cotp_write_resp)) + cotp_write_resp
    ip8 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp8), 0x3007) + tcp8
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip8)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_200 + i, i * 1000)
    (TESTS_DIR / "sample_s7comm.pcap").write_bytes(data)


def build_s7comm_items_sample():
    """A single Read Var request covering every area/transport-size code path the
    item decoder branches on: bit vs. byte-oriented addressing, DB vs. DI vs. plain
    areas, the Counter/Timer areas (whose address field is a raw item number, not a
    byte<<3|bit encoding -- a genuinely different code path from every other area),
    and an unsupported (non-S7ANY) syntax id to exercise the "recognized but not
    decoded" fallback."""
    ENG_IP, ENG_PORT = HMI_IP, 49200

    def s7any_item(transport_size, count, db_number, area, byte_address, bit_offset=0):
        addr = (byte_address << 3) | bit_offset
        return (bytes([0x12, 0x0A, 0x10, transport_size]) +
                struct.pack("!HHB", count, db_number, area) +
                bytes([(addr >> 16) & 0xFF, (addr >> 8) & 0xFF, addr & 0xFF]))

    def s7any_item_raw_addr(transport_size, count, db_number, area, raw_addr):
        # Counters/timers: the 3-byte address field IS the item number, unshifted.
        return (bytes([0x12, 0x0A, 0x10, transport_size]) +
                struct.pack("!HHB", count, db_number, area) +
                bytes([(raw_addr >> 16) & 0xFF, (raw_addr >> 8) & 0xFF, raw_addr & 0xFF]))

    def unsupported_syntax_item():
        # syntax id 0xB0 (S7-1200/1500 symbolic addressing) -- recognized as an item,
        # but its address encoding is out of scope for this groundwork release.
        body = bytes([0xB0, 0xAA, 0xBB, 0xCC])
        return bytes([0x12, len(body)]) + body

    AREA_I, AREA_Q, AREA_M, AREA_DB, AREA_DI, AREA_C, AREA_T = 0x81, 0x82, 0x83, 0x84, 0x85, 0x1C, 0x1D
    TS_BIT, TS_BYTE, TS_WORD, TS_DWORD = 0x01, 0x02, 0x04, 0x06

    items = (
        s7any_item(TS_BIT, 1, 0, AREA_I, 0, bit_offset=1) +      # I0.1
        s7any_item(TS_BYTE, 1, 0, AREA_Q, 2) +                    # QB2
        s7any_item(TS_WORD, 1, 0, AREA_M, 10) +                   # MW10
        s7any_item(TS_DWORD, 1, 5, AREA_DB, 20) +                 # DB5.DBD20
        s7any_item(TS_WORD, 1, 3, AREA_DI, 8) +                   # DI3.DBW8
        s7any_item_raw_addr(TS_WORD, 1, 0, AREA_T, 5) +           # T5
        s7any_item_raw_addr(TS_WORD, 1, 0, AREA_C, 3) +           # C3
        unsupported_syntax_item()                                 # unsupported syntax id
    )
    read_param = bytes([0x04, len([1, 2, 3, 4, 5, 6, 7, 8])]) + items
    read_req = s7_header(0x01, 10, len(read_param), 0) + read_param
    cotp_req = tpkt_frame(COTP_DT_HEADER, read_req)
    tcp_seg = tcp_header(ENG_PORT, 102, 1000, 1100, TCP_PSH | TCP_ACK, len(cotp_req)) + cotp_req
    ip_seg = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_seg), 0x3100) + tcp_seg
    eth_seg = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_seg

    data = pcap_global_header()
    data += pcap_record(eth_seg, 1_700_000_400, 0)
    (TESTS_DIR / "sample_s7comm_items.pcap").write_bytes(data)


def build_s7comm_1200sym_sample():
    """The experimental 0xB2 (S7-1200/1500 "symbolic" addressing) decode, exercised with
    the *exact* item bytes pulled from a real 4SICS capture (packet #94 of one of the
    larger GeekLounge pcaps) during this feature's development -- not a synthetic
    approximation. Five items in one Read Var request, all addressing the Merker (M)
    area with sequential LID values that decode to M2.0 through M2.4: a strong
    internal-consistency signal for the reconstructed byte layout (real PLC programs
    commonly batch-read a run of related status bits like this), even though the
    layout remains unverified against authoritative documentation -- see s7comm.cpp."""
    ENG_IP, ENG_PORT = HMI_IP, 49156

    real_items_hex = [
        "b2ff00000052ea2db0d940000010",  # -> M2.0
        "b2ff0000005278041f0f40000011",  # -> M2.1
        "b2ff000000526b1223fc40000012",  # -> M2.2
        "b2ff00000052f93b8c2a40000013",  # -> M2.3
        "b2ff000000524d3e5a1a40000014",  # -> M2.4
    ]
    # Two synthetic (not from a real capture) items appended to exercise the experimental
    # decode's fallback paths: an area1 value it doesn't recognize, and a CRC followed by
    # more than 4 bytes (more than one LID entry -- an unverified shape it deliberately
    # bails out of rather than guessing at).
    synthetic_edge_cases_hex = [
        "b2ff0000ffffea2db0d940000010",              # unrecognized area1 (0xffff)
        "b2ff00000052ea2db0d94000001012345678",       # 8 bytes after CRC instead of 4
    ]
    all_items_hex = real_items_hex + synthetic_edge_cases_hex
    items = b"".join(bytes([0x12, len(bytes.fromhex(h))]) + bytes.fromhex(h) for h in all_items_hex)
    read_param = bytes([0x04, len(all_items_hex)]) + items
    read_req = s7_header(0x01, 50, len(read_param), 0) + read_param
    cotp_req = tpkt_frame(COTP_DT_HEADER, read_req)
    tcp_seg = tcp_header(ENG_PORT, 102, 2000, 2100, TCP_PSH | TCP_ACK, len(cotp_req)) + cotp_req
    ip_seg = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_seg), 0x3400) + tcp_seg
    eth_seg = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_seg

    data = pcap_global_header()
    data += pcap_record(eth_seg, 1_445_465_444, 995098)  # same timestamp as the real packet
    (TESTS_DIR / "sample_s7comm_1200sym.pcap").write_bytes(data)


def build_s7comm_chaining_sample():
    """Exercises Decoder::reassemble_cotp_data_frame -- chaining a single S7comm message's bytes
    across multiple COMPLETE TPKT/COTP Data (DT) frames via the EOT bit (ISO 8073's own TSDU-
    fragmentation signal). This is a different layer from sample_tcp_reassembly.pcap's scenario C,
    which splits ONE TPKT frame's own bytes across TCP segments; here, every individual TPKT frame
    is itself complete and independently well-formed -- it's the logical S7comm message inside them
    that only decodes correctly once several such frames are chained together.

    Real S7comm captures checked for this project (see tests/real_captures/s7comm/ATTRIBUTION.md)
    do exercise this EOT-chaining path, but only in a content-free shape: a zero-byte EOT=0 "priming"
    DT frame immediately followed by a normal EOT=1 frame carrying the entire real message --
    concatenating zero bytes with the real ones is indistinguishable from not chaining at all.
    Scenario A below is what real traffic doesn't (yet) give this project a real-world example of:
    a message whose *actual content* -- specifically, a Read Var response's returned register
    values -- is itself split mid-data-block across two chained frames, so it only decodes correctly
    if both are genuinely concatenated, not just if the reassembly machinery politely does nothing."""
    ENG_IP, ENG_PORT = HMI_IP, 49300
    COTP_DT_HEADER_FRAGMENT = bytes([0xF0, 0x00])  # PDU type 0xF0, TPDU-NR=0, EOT bit CLEAR (not last)

    packets = []

    # A) Read Var Ack_Data response for 5 words (real, distinctive values so the CTest regex can't
    #    be accidentally satisfied by some other fixture's text -- see the CMake regex lesson in
    #    CMakeLists.txt's tcp_reassembly_* tests), split mid-data-block across two chained DT frames.
    read_values = b"".join(struct.pack("!H", v) for v in (5100, 5101, 5102, 5103, 5104))
    resp_param = bytes([0x04, 0x01])
    resp_data = bytes([0xFF, 0x04, 0x00, 0x50]) + read_values  # return_code=Success, WORD, 80 bits, 10 bytes
    resp = s7_header(0x03, 88, len(resp_param), len(resp_data)) + struct.pack("!BB", 0, 0) + resp_param + resp_data
    # resp_data's own 4-byte prefix (return_code/transport_size/length) ends at offset 18, so the
    # register values themselves span offsets 18-27 (5 x 2 bytes). split=21 lands mid-byte inside
    # the second register's (5101) own 2-byte encoding -- proof this reconstructs real register
    # values correctly, not just whole records or byte-aligned chunks.
    split = 21
    assert 18 < split < len(resp) - 2, "split must land inside the register value bytes themselves"
    frame_a1 = tpkt_frame(COTP_DT_HEADER_FRAGMENT, resp[:split])
    frame_a2 = tpkt_frame(COTP_DT_HEADER, resp[split:])  # EOT=1 -- COTP_DT_HEADER's TPDU-NR/EOT byte is 0x80
    tcp_a1 = tcp_header(102, ENG_PORT, 9000, 9100, TCP_PSH | TCP_ACK, len(frame_a1)) + frame_a1
    ip_a1 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_a1), 0x6000) + tcp_a1
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_a1)
    tcp_a2 = tcp_header(102, ENG_PORT, 9000 + len(frame_a1), 9100, TCP_PSH | TCP_ACK, len(frame_a2)) + frame_a2
    ip_a2 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_a2), 0x6001) + tcp_a2
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_a2)

    # B) A COTP Disconnect Request arriving mid-reassembly must abandon it with a note, not silently
    #    drop it or try to splice the Disconnect frame's own (irrelevant) bytes in.
    partial = tpkt_frame(COTP_DT_HEADER_FRAGMENT, resp[:split])  # begins a reassembly, never completed
    tcp_b1 = tcp_header(102, ENG_PORT + 1, 9200, 9300, TCP_PSH | TCP_ACK, len(partial)) + partial
    ip_b1 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_b1), 0x6002) + tcp_b1
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_b1)
    dr = bytes([0x80, 0x00, 0x01, 0x00, 0x02, 0x00])  # DR: dst-ref, src-ref, reason -- minimal, no TSAP params
    frame_dr = tpkt_frame(dr)
    tcp_b2 = tcp_header(102, ENG_PORT + 1, 9200 + len(partial), 9300, TCP_PSH | TCP_ACK, len(frame_dr)) + frame_dr
    ip_b2 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_b2), 0x6003) + tcp_b2
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_b2)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_600 + i, i * 1000)
    (TESTS_DIR / "sample_s7comm_chaining.pcap").write_bytes(data)


def build_s7comm_pi_control_sample():
    """Function codes 0x28 (PLC Control / "PI-Service") and 0x29 (PLC Stop) parameter decoding --
    see s7comm.hpp's file header for the security context and the deliberate _N_* Sinumerik/CNC
    scope boundary. Each scenario below is its own standalone one-packet TCP "flow" (distinct
    source port), same pattern as build_s7comm_items_sample() -- this decoder is stateless
    per-packet for these function codes, no COTP/TCP reassembly is being exercised here."""
    ENG_IP = HMI_IP

    def block_descriptor(block_type: str, block_number, dest: str) -> bytes:
        # block_number is normally an int (formatted as 5 decimal digits, zero-padded, matching
        # real S7comm traffic), but a raw 5-character str is accepted too, to build the
        # non-numeric-block-number malformed-input scenario below.
        number_field = f"{block_number:05d}" if isinstance(block_number, int) else block_number
        assert len(block_type) == 2 and len(number_field) == 5 and len(dest) == 1
        return block_type.encode("ascii") + number_field.encode("ascii") + dest.encode("ascii")

    def blocks_param(blocks) -> bytes:
        return bytes([len(blocks), 0x00]) + b"".join(block_descriptor(*b) for b in blocks)

    def pi_control_param(pi_param: bytes, name: bytes) -> bytes:
        return bytes([0x28]) + bytes(7) + struct.pack("!H", len(pi_param)) + pi_param + bytes([len(name)]) + name

    packets = []

    def add_request(param: bytes, port: int, ident: int, pdu_ref: int):
        req = s7_header(0x01, pdu_ref, len(param), 0) + param
        cotp = tpkt_frame(COTP_DT_HEADER, req)
        tcp = tcp_header(port, 102, 1000 + pdu_ref, 1100 + pdu_ref, TCP_PSH | TCP_ACK, len(cotp)) + cotp
        ip = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp), ident) + tcp
        packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    def add_response(param: bytes, port: int, ident: int, pdu_ref: int):
        resp = s7_header(0x03, pdu_ref, len(param), 0) + struct.pack("!BB", 0, 0) + param
        cotp = tpkt_frame(COTP_DT_HEADER, resp)
        tcp = tcp_header(102, port, 1100 + pdu_ref, 1000 + pdu_ref, TCP_PSH | TCP_ACK, len(cotp)) + cotp
        ip = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp), ident) + tcp
        packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip)

    # 1) PLC Stop -- Job request. Real traffic carries literally "PLC_STOP", used here too (this
    #    decoder doesn't validate against it -- see s7comm.cpp/plc_stop_message).
    add_request(bytes([0x29]) + bytes(5) + bytes([8]) + b"PLC_STOP", 49210, 0x3810, 101)

    # 2) PLC Control _INSE -- activates/inserts 2 blocks of different types: DB100 (Passive
    #    filesystem destination) and FC5 (Active).
    add_request(pi_control_param(blocks_param([("DB", 100, "P"), ("FC", 5, "A")]), b"_INSE"),
                49211, 0x3811, 102)

    # 3) PLC Control _DELE -- removes 1 block, destination code 'B' (Active as well as passive).
    add_request(pi_control_param(blocks_param([("DB", 50, "B")]), b"_DELE"), 49212, 0x3812, 103)

    # 4) PLC Control P_PROGRAM -- bare invocation, no argument (paramlen == 0).
    add_request(pi_control_param(b"", b"P_PROGRAM"), 49213, 0x3813, 104)

    # 5) PLC Control P_PROGRAM -- with a non-empty argument. "OB1" here is an arbitrary test
    #    string, not a claim about what this specific argument value means on real hardware --
    #    see s7comm.hpp/pi_control_argument for why this decoder doesn't interpret it.
    add_request(pi_control_param(b"OB1", b"P_PROGRAM"), 49214, 0x3814, 105)

    # 6) PLC Control with a Sinumerik/CNC-specific PI service name (_N_F_XFER) that has a non-empty
    #    parameter block -- confirms the name+description lookup fires (it's in kPiServiceNames)
    #    while the parameter block itself is deliberately left undecoded (scope boundary).
    add_request(pi_control_param(bytes([0xAA, 0xBB, 0xCC, 0xDD]), b"_N_F_XFER"), 49215, 0x3815, 106)

    # 7) PLC Control _INSE -- a block descriptor whose 5-character number field isn't all digits,
    #    exercising the "non-numeric block number" fallback rather than a crash/garbage int.
    add_request(pi_control_param(blocks_param([("DB", "ABCDE", "P")]), b"_INSE"), 49216, 0x3816, 107)

    # 8) PLC Control _INSE -- declares 2 blocks but only ships one complete 8-byte descriptor,
    #    exercising parse_pi_control_blocks' truncation note (and confirming no crash).
    truncated_blocks_param = bytes([2, 0x00]) + block_descriptor("DB", 10, "P")
    add_request(pi_control_param(truncated_blocks_param, b"_INSE"), 49217, 0x3817, 108)

    # 9) PLC Control Ack_Data response -- both status flag bits set (more data + error).
    add_response(bytes([0x28, 0x03]), 49218, 0x3818, 109)

    # 10) PLC Control Ack_Data response -- neither status flag bit set.
    add_response(bytes([0x28, 0x00]), 49219, 0x3819, 110)

    # 11) PLC Stop -- truncated request: only the function code byte, none of the reserved/
    #     length/message bytes. Must degrade gracefully (a note, no crash), never throw.
    add_request(bytes([0x29]), 49220, 0x3820, 111)

    # 12) PLC Control -- truncated request: only 2 of the 7 reserved bytes present, nowhere near
    #     enough for the reserved-bytes-plus-paramlen-field shape. Must degrade gracefully.
    add_request(bytes([0x28, 0x00, 0x00]), 49221, 0x3821, 112)

    # 13) PLC Control -- declares a 50-byte PI parameter block but only 3 bytes are actually
    #     present (and the PI service name length byte is missing entirely). Exercises both the
    #     "parameter block truncated" note and the "missing name length byte" note together,
    #     without crashing.
    add_request(bytes([0x28]) + bytes(7) + struct.pack("!H", 50) + bytes([0x01, 0x02, 0x03]),
                49222, 0x3822, 113)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_700 + i, i * 1000)
    (TESTS_DIR / "sample_s7comm_pi_control.pcap").write_bytes(data)


# ==================================================================================================
# IEC 61850 MMS (ISO 9506) fixture helpers -- Session(ISO 8327-1)/Presentation(ISO 8823)/
# ACSE(ISO 8650-1)/MMS(ISO 9506-2) TLV builders, matching src/mms.cpp's own decode logic field for
# field (see that file's own header comments for the wire-format citations these mirror). Reuses
# the generic BER helpers above (ber_length/ber_tlv/ber_int) and the MMS "Data" value builders
# already defined for GOOSE/SV (data_bool/data_int/... -- MMS's own Data CHOICE, ISO 9506-2, is the
# exact same encoding IEC 61850-8-1 reuses for GOOSE/SV's own allData).
# --------------------------------------------------------------------------------------------------

def oid_bytes(dotted: str) -> bytes:
    """OBJECT IDENTIFIER content octets (X.690 8.19) for a dotted-decimal string."""
    parts = [int(p) for p in dotted.split(".")]
    out = bytes([parts[0] * 40 + parts[1]])
    for value in parts[2:]:
        if value == 0:
            out += bytes([0])
            continue
        chunks = []
        v = value
        while v > 0:
            chunks.insert(0, v & 0x7F)
            v >>= 7
        for i in range(len(chunks) - 1):
            chunks[i] |= 0x80
        out += bytes(chunks)
    return out


def ber_tag_bytes(class_bits: int, constructed: bool, tag_number: int) -> bytes:
    """One BER tag's own octet(s) -- single-byte form for tag_number<=30, the high-tag-number
    multi-byte form (X.690 8.1.2.4) otherwise. `class_bits` is one of 0x00/0x40/0x80/0xC0
    (universal/application/context/private)."""
    first = class_bits | (0x20 if constructed else 0x00)
    if tag_number <= 30:
        return bytes([first | tag_number])
    out = [tag_number & 0x7F]
    v = tag_number >> 7
    while v > 0:
        out.insert(0, (v & 0x7F) | 0x80)
        v >>= 7
    return bytes([first | 0x1F]) + bytes(out)


def ber_tlv_tag(class_bits: int, constructed: bool, tag_number: int, content: bytes = b"") -> bytes:
    return ber_tag_bytes(class_bits, constructed, tag_number) + ber_length(len(content)) + content


def ctx_c(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x80, True, tag, content)
def ctx_p(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x80, False, tag, content)
def app_c(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x40, True, tag, content)
def app_p(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x40, False, tag, content)
def uni_c(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x00, True, tag, content)
def uni_p(tag: int, content: bytes = b"") -> bytes: return ber_tlv_tag(0x00, False, tag, content)

# confirmedServiceRequest/Response CHOICE alternative -- same shape as ctx_c/ctx_p, named
# separately for readability at MMS-layer call sites.
def svc(tag: int, constructed: bool, content: bytes = b"") -> bytes:
    return ctx_c(tag, content) if constructed else ctx_p(tag, content)

# Top-level MMSpdu CHOICE alternative -- see mms.cpp's own looks_like_bare_mms_pdu comment for
# which of the 14 alternatives are constructed (SEQUENCE) vs. primitive (Unsigned32/NULL).
def mms_pdu(tag: int, constructed: bool, content: bytes = b"") -> bytes:
    return ctx_c(tag, content) if constructed else ctx_p(tag, content)


# ---- ObjectName (mms.cpp's decode_object_name/decode_object_name_flexible) -----------------------
def object_name_vmd(name: str) -> bytes:
    return ctx_p(0, name.encode("ascii"))


def object_name_domain(domain: str, item: str) -> bytes:
    # decode_object_name reads the two children's raw content directly regardless of their own
    # tag -- UNIVERSAL VisibleString (tag 26) used here purely for wire-realism.
    return ctx_c(1, uni_p(26, domain.encode("ascii")) + uni_p(26, item.encode("ascii")))


def object_name_aa(name: str) -> bytes:
    return ctx_p(2, name.encode("ascii"))


# ---- VariableSpecification / VariableAccessSpecification (mms.cpp) --------------------------------
def var_spec_name(object_name_alt: bytes) -> bytes:
    return ctx_c(0, object_name_alt)  # name[0], EXPLICIT wrap around the ObjectName alternative


def list_of_variable(var_specs) -> bytes:
    entries = b"".join(uni_c(16, vs) for vs in var_specs)  # each: SEQUENCE{variableSpecification, ...}
    return ctx_c(0, entries)  # listOfVariable[0]


def variable_list_name(object_name_alt: bytes) -> bytes:
    return ctx_c(1, object_name_alt)  # variableListName[1], EXPLICIT wrap around ObjectName


# ---- AccessResult (mms.cpp's decode_access_result) -------------------------------------------------
def access_result_success(data_bytes: bytes) -> bytes:
    return data_bytes  # a Data value TLV directly, untagged (e.g. data_bool(...)/data_int(...))


def access_result_failure(error_code: int) -> bytes:
    return ctx_p(0, ber_int(error_code))  # failure[0] DataAccessError


def write_result_success() -> bytes:
    return ctx_p(1, b"")


def write_result_failure(error_code: int) -> bytes:
    return ctx_p(0, ber_int(error_code))


# ---- Bit-string content (unused-bit-count byte + MSB-first bits) for parameterCBB/servicesSupported
def bitstring_content(bit_indexes, num_bits: int) -> bytes:
    num_bytes = (num_bits + 7) // 8
    unused = num_bytes * 8 - num_bits
    buf = bytearray(num_bytes)
    for b in bit_indexes:
        buf[b // 8] |= (0x80 >> (b % 8))
    return bytes([unused]) + bytes(buf)


# ---- Tier1 confirmedServiceRequest/Response body builders (mms.cpp's own dispatch table) ----------
def status_request(toggle: bool) -> bytes:
    return svc(0, False, b"\x01" if toggle else b"\x00")


def status_response(vmd_logical: int, vmd_physical: int) -> bytes:
    content = ctx_p(0, ber_int(vmd_logical)) + ctx_p(1, ber_int(vmd_physical))
    return svc(0, True, content)


def getnamelist_request(scope_kind: str, scope_domain: str = None, continue_after: str = None) -> bytes:
    if scope_kind == "vmd":
        inner = ctx_p(0, b"")
    elif scope_kind == "domain":
        inner = ctx_p(1, scope_domain.encode("ascii"))
    else:
        inner = ctx_p(2, b"")
    content = ctx_c(1, inner)  # objectScope[1], EXPLICIT wrap around the ObjectScope CHOICE
    if continue_after is not None:
        content += ctx_p(2, continue_after.encode("ascii"))
    return svc(1, True, content)


def getnamelist_response(identifiers, more_follows: bool = False) -> bytes:
    idlist = b"".join(uni_p(26, s.encode("ascii")) for s in identifiers)
    content = ctx_c(0, idlist) + ctx_p(1, b"\x01" if more_follows else b"\x00")
    return svc(1, True, content)


def identify_response(vendor: str, model: str, revision: str, abstract_syntaxes=None) -> bytes:
    content = ctx_p(0, vendor.encode("ascii")) + ctx_p(1, model.encode("ascii")) + ctx_p(2, revision.encode("ascii"))
    if abstract_syntaxes:
        oids = b"".join(uni_p(6, oid_bytes(o)) for o in abstract_syntaxes)
        content += ctx_c(3, oids)
    return svc(2, True, content)


def read_request(spec_with_result: bool, var_access_spec: bytes) -> bytes:
    content = b""
    if spec_with_result:
        content += ctx_p(0, b"\x01")
    content += ctx_c(1, var_access_spec)  # variableAccessSpecification[1], EXPLICIT wrap
    return svc(4, True, content)


def read_response(results, var_access_spec: bytes = None) -> bytes:
    content = ctx_c(0, var_access_spec) if var_access_spec is not None else b""
    content += ctx_c(1, b"".join(results))  # listOfAccessResult[1], IMPLICIT SEQUENCE OF, no extra wrap
    return svc(4, True, content)


def write_request(var_access_spec: bytes, values) -> bytes:
    content = var_access_spec + uni_c(16, b"".join(values))  # listOfData: SEQUENCE OF Data
    return svc(5, True, content)


def write_response(results) -> bytes:
    return svc(5, True, b"".join(results))


def getvariableaccessattributes_request(object_name_alt: bytes) -> bytes:
    return svc(6, True, ctx_c(0, object_name_alt))  # name[0], EXPLICIT wrap


def getvariableaccessattributes_response(deletable: bool, type_specification_placeholder: bytes = b"\x00") -> bytes:
    content = ctx_p(0, b"\x01" if deletable else b"\x00") + ctx_c(2, type_specification_placeholder)
    return svc(6, True, content)


def definenamedvariablelist_request(object_name_alt: bytes, members) -> bytes:
    member_entries = b"".join(uni_c(16, m) for m in members)  # each: SEQUENCE{variableSpecification, ...}
    content = object_name_alt + uni_c(16, member_entries)
    return svc(11, True, content)


def definenamedvariablelist_response() -> bytes:
    return svc(11, False, b"")  # DefineNamedVariableList-Response ::= NULL


def getnamedvariablelistattributes_request(object_name_alt: bytes) -> bytes:
    # GetNamedVariableListAttributes-Request ::= ObjectName, IMPLICIT-behaving-as-EXPLICIT over the
    # CHOICE (see mms.cpp's decode_object_name_flexible header comment) -- content is the single
    # natural-tagged ObjectName alternative.
    return svc(12, True, object_name_alt)


def getnamedvariablelistattributes_response(deletable: bool, members) -> bytes:
    member_entries = b"".join(uni_c(16, m) for m in members)
    content = ctx_p(0, b"\x01" if deletable else b"\x00") + ctx_c(1, member_entries)
    return svc(12, True, content)


def deletenamedvariablelist_request(scope: int = None, names=None, domain_name: str = None) -> bytes:
    content = b""
    if scope is not None:
        content += ctx_p(0, ber_int(scope))
    if names:
        content += ctx_c(1, b"".join(names))  # each: a natural-tagged ObjectName alternative directly
    if domain_name is not None:
        content += ctx_p(2, domain_name.encode("ascii"))
    return svc(13, True, content)


def deletenamedvariablelist_response(matched: int, deleted: int) -> bytes:
    content = ctx_p(0, ber_int(matched)) + ctx_p(1, ber_int(deleted))
    return svc(13, True, content)


def getcapabilitylist_request(continue_after: str = None) -> bytes:
    content = ctx_p(0, continue_after.encode("ascii")) if continue_after is not None else b""
    return svc(71, True, content)


def getcapabilitylist_response(caps, more_follows: bool = False) -> bytes:
    caplist = b"".join(uni_p(26, c.encode("ascii")) for c in caps)
    content = ctx_c(0, caplist) + ctx_p(1, b"\x01" if more_follows else b"\x00")
    return svc(71, True, content)


def getdomainattributes_request(domain_name: str) -> bytes:
    return svc(37, False, domain_name.encode("ascii"))


def getdomainattributes_response(caps, state: int, deletable: bool, sharable: bool,
                                  program_invocations=None, upload_in_progress: int = None) -> bytes:
    content = ctx_c(0, b"".join(uni_p(26, c.encode("ascii")) for c in caps))
    content += ctx_p(1, ber_int(state))
    content += ctx_p(2, b"\x01" if deletable else b"\x00")
    content += ctx_p(3, b"\x01" if sharable else b"\x00")
    if program_invocations is not None:
        content += ctx_c(4, b"".join(uni_p(26, p.encode("ascii")) for p in program_invocations))
    if upload_in_progress is not None:
        content += ctx_p(5, ber_int(upload_in_progress))
    return svc(37, True, content)


# ---- File-transfer services (mms.cpp's own "File-transfer services" section) -- FileName ::=
# SEQUENCE OF GraphicString, rendered here as UNIVERSAL GraphicString (tag 25) elements per part,
# joined "/" by the decoder; FileAttributes ::= SEQUENCE { sizeOfFile [0] IMPLICIT Unsigned32,
# lastModified [1] IMPLICIT GeneralizedTime OPTIONAL } -- GeneralizedTime is raw ASCII text bytes,
# not a BER-wrapped structure, since it is IMPLICIT over a primitive.
def file_name(*parts: str) -> bytes:
    return b"".join(uni_p(25, p.encode("ascii")) for p in parts)


def file_attributes(size_of_file: int, last_modified: str = None) -> bytes:
    content = ctx_p(0, ber_int(size_of_file))
    if last_modified is not None:
        content += ctx_p(1, last_modified.encode("ascii"))
    return content


def obtainfile_request(source_file, destination_file, include_source_file_server: bool = False) -> bytes:
    content = b""
    if include_source_file_server:
        content += ctx_c(0, b"")  # ApplicationReference, empty -- every field OPTIONAL, not decoded
    content += ctx_c(1, file_name(*source_file))
    content += ctx_c(2, file_name(*destination_file))
    return svc(46, True, content)


def fileopen_request(file_name_parts, initial_position: int) -> bytes:
    content = ctx_c(0, file_name(*file_name_parts)) + ctx_p(1, ber_int(initial_position))
    return svc(72, True, content)


def fileopen_response(frsm_id: int, size_of_file: int, last_modified: str = None) -> bytes:
    content = ctx_p(0, ber_int(frsm_id)) + ctx_c(1, file_attributes(size_of_file, last_modified))
    return svc(72, True, content)


def fileread_request(frsm_id: int) -> bytes:
    return svc(73, False, ber_int(frsm_id))  # FileRead-Request ::= Integer32, bare primitive


def fileread_response(data: bytes, more_follows: bool = True) -> bytes:
    content = ctx_p(0, data)
    if not more_follows:  # DEFAULT TRUE -- only encode when overriding the default to false
        content += ctx_p(1, b"\x00")
    return svc(73, True, content)


def fileclose_request(frsm_id: int) -> bytes:
    return svc(74, False, ber_int(frsm_id))  # FileClose-Request ::= Integer32, bare primitive


def filerename_request(current_file, new_file) -> bytes:
    content = ctx_c(0, file_name(*current_file)) + ctx_c(1, file_name(*new_file))
    return svc(75, True, content)


def filedelete_request(file_name_parts) -> bytes:
    return svc(76, True, file_name(*file_name_parts))  # FileDelete-Request ::= FileName, bare (constructed)


def filedirectory_request(file_spec=None, continue_after=None) -> bytes:
    content = b""
    if file_spec is not None:
        content += ctx_c(0, file_name(*file_spec))
    if continue_after is not None:
        content += ctx_c(1, file_name(*continue_after))
    return svc(77, True, content)


def directory_entry(file_name_parts, size_of_file: int, last_modified: str = None) -> bytes:
    content = ctx_c(0, file_name(*file_name_parts)) + ctx_c(1, file_attributes(size_of_file, last_modified))
    return uni_c(16, content)  # DirectoryEntry ::= SEQUENCE


def filedirectory_response(entries, more_follows: bool = False) -> bytes:
    content = ctx_c(0, uni_c(16, b"".join(entries)))  # listOfDirectoryEntry[0], EXPLICIT wrap around
                                                         # SEQUENCE OF DirectoryEntry
    if more_follows:  # DEFAULT FALSE -- only encode when overriding the default to true
        content += ctx_p(1, b"\x01")
    return svc(77, True, content)


# ---- confirmed-RequestPDU/ResponsePDU wrapper (mms.cpp's decode_confirmed_request/response) -------
def confirmed_request_pdu(invoke_id: int, service_body: bytes = None) -> bytes:
    content = uni_p(2, ber_int(invoke_id))
    if service_body is not None:
        content += service_body
    return mms_pdu(0, True, content)


def confirmed_response_pdu(invoke_id: int, service_body: bytes = None) -> bytes:
    content = uni_p(2, ber_int(invoke_id))
    if service_body is not None:
        content += service_body
    return mms_pdu(1, True, content)


# ---- ServiceError fields, shared by confirmed-ErrorPDU/cancel-ErrorPDU/conclude-ErrorPDU/
# initiate-ErrorPDU (mms.cpp's decode_service_error is called on a different enclosing TLV per PDU
# type -- see each builder below for exactly how these fields get wrapped).
def service_error_fields(category_tag: int, code: int, additional_code: int = None,
                          additional_description: str = None) -> bytes:
    content = ctx_c(0, ctx_p(category_tag, ber_int(code)))  # errorClass[0], EXPLICIT wrap
    if additional_code is not None:
        content += ctx_p(1, ber_int(additional_code))
    if additional_description is not None:
        content += ctx_p(2, additional_description.encode("ascii"))
    return content


def confirmed_error_pdu(invoke_id: int, category_tag: int, code: int, modifier_position: int = None,
                         additional_code: int = None, additional_description: str = None) -> bytes:
    content = ctx_p(0, ber_int(invoke_id))
    if modifier_position is not None:
        content += ctx_p(1, ber_int(modifier_position))
    content += ctx_c(2, service_error_fields(category_tag, code, additional_code, additional_description))
    return mms_pdu(2, True, content)


def unconfirmed_pdu(service_alt: bytes) -> bytes:
    return mms_pdu(3, True, service_alt)


def information_report(var_access_spec: bytes, results) -> bytes:
    content = var_access_spec + uni_c(16, b"".join(results))
    return ctx_c(0, content)  # informationReport[0] -- the unconfirmed-PDU's own choice alternative


def reject_pdu(invoke_id: int, reason_tag: int, reason_code: int) -> bytes:
    content = ctx_p(0, ber_int(invoke_id)) + ctx_p(reason_tag, ber_int(reason_code))
    return mms_pdu(4, True, content)


def cancel_request_pdu(invoke_id: int) -> bytes:
    return mms_pdu(5, False, ber_int(invoke_id))


def cancel_response_pdu(invoke_id: int) -> bytes:
    return mms_pdu(6, False, ber_int(invoke_id))


def cancel_error_pdu(invoke_id: int, category_tag: int, code: int) -> bytes:
    content = ctx_p(0, ber_int(invoke_id)) + ctx_c(1, service_error_fields(category_tag, code))
    return mms_pdu(7, True, content)


def initiate_pdu(is_response: bool, local_detail: int, max_calling: int, max_called: int, nesting: int,
                  version: int, parameter_cbb_bits, services_supported_bits) -> bytes:
    content = ctx_p(0, ber_int(local_detail))
    content += ctx_p(1, ber_int(max_calling))
    content += ctx_p(2, ber_int(max_called))
    content += ctx_p(3, ber_int(nesting))
    detail = ctx_p(0, ber_int(version))
    detail += ctx_p(1, bitstring_content(parameter_cbb_bits, 11))   # ParameterSupportOptions, 11 bits
    detail += ctx_p(2, bitstring_content(services_supported_bits, 85))  # ServiceSupportOptions, 85 bits
    content += ctx_c(4, detail)
    return mms_pdu(9 if is_response else 8, True, content)


def initiate_error_pdu(category_tag: int, code: int) -> bytes:
    return mms_pdu(10, True, service_error_fields(category_tag, code))


def conclude_request_pdu() -> bytes:
    return mms_pdu(11, False, b"")


def conclude_response_pdu() -> bytes:
    return mms_pdu(12, False, b"")


def conclude_error_pdu(category_tag: int, code: int) -> bytes:
    return mms_pdu(13, True, service_error_fields(category_tag, code))


def malformed_confirmed_request_no_service(invoke_id: int) -> bytes:
    return mms_pdu(0, True, uni_p(2, ber_int(invoke_id)))  # invokeID present, service field missing


def malformed_confirmed_response_no_service(invoke_id: int) -> bytes:
    return mms_pdu(1, True, uni_p(2, ber_int(invoke_id)))


# ---- Presentation layer (ISO 8823) -----------------------------------------------------------------
def presentation_context_item(ctx_id: int, transfer_syntax_oid: str) -> bytes:
    content = uni_p(2, ber_int(ctx_id)) + uni_p(6, oid_bytes(transfer_syntax_oid))
    return uni_c(16, content)  # SEQUENCE{presentation-context-identifier, transfer-syntax-name}


def presentation_context_list(items) -> bytes:
    return ctx_c(4, b"".join(items))  # presentation-context-definition-list[4]


def pdv_entry(context_id: int, single_asn1_bytes: bytes) -> bytes:
    content = uni_p(2, ber_int(context_id)) + ctx_c(0, single_asn1_bytes)  # single-ASN1-type[0], EXPLICIT
    return uni_c(16, content)  # PDV-list SEQUENCE element


def user_data_fully_encoded(pdv: bytes) -> bytes:
    return app_c(1, pdv)  # user-data CHOICE, fully-encoded-data[APPLICATION 1] alternative


def presentation_association(context_list, context_id: int, single_asn1_bytes: bytes) -> bytes:
    """CP-type/CPA-type (association-time): a UNIVERSAL SET wrapping normal-mode-parameters, which
    itself carries the context-definition-list and the fully-encoded user-data (see mms.cpp's
    decode_presentation)."""
    ctxlist = presentation_context_list([presentation_context_item(cid, oid) for cid, oid in context_list])
    userdata = user_data_fully_encoded(pdv_entry(context_id, single_asn1_bytes))
    npm = ctx_c(2, ctxlist + userdata)  # normal-mode-parameters[2]
    return uni_c(17, npm)  # SET, universal tag 17


def presentation_bare_fully_encoded(context_id: int, single_asn1_bytes: bytes) -> bytes:
    """The ongoing-message shape with no CP-type/CPA-type wrapper -- just the bare fully-encoded-
    data CHOICE alternative directly."""
    return user_data_fully_encoded(pdv_entry(context_id, single_asn1_bytes))


# ---- ACSE layer (ISO 8650-1) -------------------------------------------------------------------
ACSE_APPLICATION_CONTEXT_OID = "2.2.1.0.1"


def acse_user_information(inner_pdu_bytes: bytes) -> bytes:
    external = uni_c(16, ctx_c(0, inner_pdu_bytes))  # EXTERNAL ~= SEQUENCE{single-ASN1-type[0] inner}
    return ctx_c(30, external)  # user-information[30] IMPLICIT Association-data (SEQUENCE OF EXTERNAL)


def acse_aarq(user_info_pdu: bytes, app_context_oid: str = ACSE_APPLICATION_CONTEXT_OID) -> bytes:
    content = ctx_c(1, uni_p(6, oid_bytes(app_context_oid))) + acse_user_information(user_info_pdu)
    return ctx_c(0, content)


def acse_aare(result: int, user_info_pdu: bytes, app_context_oid: str = ACSE_APPLICATION_CONTEXT_OID) -> bytes:
    content = (ctx_c(1, uni_p(6, oid_bytes(app_context_oid))) +
               ctx_c(2, uni_p(2, ber_int(result))) +
               acse_user_information(user_info_pdu))
    return ctx_c(1, content)


def acse_rlrq(reason: int = None) -> bytes:
    return ctx_c(2, ctx_p(0, ber_int(reason)) if reason is not None else b"")


def acse_rlre(reason: int = None) -> bytes:
    return ctx_c(3, ctx_p(0, ber_int(reason)) if reason is not None else b"")


def acse_abrt(source: int, diagnostic: int = None) -> bytes:
    content = ctx_p(0, ber_int(source))
    if diagnostic is not None:
        content += ctx_p(1, ber_int(diagnostic))
    return ctx_c(4, content)


# ---- Session layer (ISO 8327-1) ------------------------------------------------------------------
def session_param(code: int, content: bytes) -> bytes:
    assert len(content) <= 254, "Session parameter content exceeds the one-byte-length form"
    return bytes([code, len(content)]) + content


def session_spdu(si: int, params: bytes = b"") -> bytes:
    assert len(params) <= 254, "Session SPDU parameters exceed the one-byte-length form (extended " \
                                "form -- LI==0xFF -- is not supported by conduitscope's own decoder)"
    return bytes([si, len(params)]) + params


def session_connect(user_data_bytes: bytes) -> bytes:
    # A small genuinely-nested Connect_Accept_Item(5)/Linking_Information(33) pair, purely to
    # exercise walk_session_parameters' own recursion -- see mms.cpp's own header comment on which
    # PGI codes recurse vs. which (193/194, used below) carry the next layer's raw bytes directly.
    nested = session_param(33, b"\x00\x01")
    params = session_param(5, nested) + session_param(193, user_data_bytes)
    return session_spdu(13, params)  # CONNECT (CN)


def session_accept(user_data_bytes: bytes) -> bytes:
    params = session_param(193, user_data_bytes)
    return session_spdu(14, params)  # ACCEPT (AC)


def session_ongoing_prefix(count: int = 2) -> bytes:
    # The "ubiquitous SI=1" shape real traffic uses for every ongoing Data-Transfer message: one or
    # more ubiquitous SI=1/LI=0 markers (Data Transfer / Give Tokens share SPDU type 1) followed
    # directly by Presentation-layer bytes with no Session parameter at all -- see mms.cpp's own
    # ATTRIBUTION.md-cited header comment. `count`=2 by default specifically to also exercise the
    # real structural-gate bug this decoder's own real-capture validation found and fixed (the
    # Presentation layer's own fully-encoded-data tag, 0x61=97, being mistaken for a third bogus
    # SPDU by a looser bound).
    return session_spdu(1, b"") * count


# --- S7comm-Plus (0x72) helpers -----------------------------------------------------------
# See include/conduitscope/s7commplus.hpp / src/s7commplus.cpp for the exact wire format these
# mirror. All multi-byte integers used directly in a header/envelope are big-endian; the
# "varuint"/"varint" fields are this protocol's own Variable-Length Quantity encoding (big-endian/
# MSB-first 7-bit groups, continuation bit 0x80; the signed forms use bit 0x40 of the FIRST byte
# as a sign flag with only 6 payload bits in that first byte).
S7P_OPCODE_REQUEST = 0x31
S7P_OPCODE_RESPONSE = 0x32
S7P_OPCODE_NOTIFICATION = 0x33
S7P_OPCODE_RESPONSE2 = 0x02

S7P_PDUTYPE_CONNECT = 0x01
S7P_PDUTYPE_DATA = 0x02
S7P_PDUTYPE_DATAFW1_5 = 0x03
S7P_PDUTYPE_KEEPALIVE = 0xff

S7P_FC_EXPLORE = 0x04bb
S7P_FC_CREATEOBJECT = 0x04ca
S7P_FC_DELETEOBJECT = 0x04d4
S7P_FC_SETVARIABLE = 0x04f2
S7P_FC_GETLINK = 0x0524
S7P_FC_SETMULTIVAR = 0x0542
S7P_FC_GETMULTIVAR = 0x054c
S7P_FC_BEGINSEQUENCE = 0x0556
S7P_FC_ENDSEQUENCE = 0x0560
S7P_FC_INVOKE = 0x056b
S7P_FC_GETVARSUBSTR = 0x0586


def vlq_u(value: int, max_groups: int = 5) -> bytes:
    """Unsigned varuint32/varuint64 encoder: plain big-endian/MSB-first 7-bit groups, matching
    read_varuint32/read_varuint64 in s7commplus.cpp exactly (no sign-flag reservation)."""
    assert value >= 0
    if value == 0:
        return bytes([0])
    k = max(1, -(-value.bit_length() // 7))
    assert k <= max_groups, f"{value} needs {k} groups, only {max_groups} allowed"
    shift = (k - 1) * 7
    out = bytearray()
    for i in range(k):
        g = (value >> shift) & 0x7f
        out.append(g | (0x80 if i != k - 1 else 0))
        shift -= 7
    return bytes(out)


def vlq_s(value: int, max_groups: int = 5) -> bytes:
    """Signed varint32/varint64 encoder: first byte carries 6 payload bits plus a 0x40 sign flag,
    every following byte carries 7 payload bits -- matches read_varint32/read_varint64 exactly."""
    if value == 0:
        return bytes([0])
    neg = value < 0
    extra = 0
    while True:
        total_bits = 6 + extra * 7
        lo, hi = -(1 << (total_bits - 1)), (1 << (total_bits - 1)) - 1
        if lo <= value <= hi:
            break
        extra += 1
        assert extra < max_groups, f"{value} does not fit in {max_groups} varint groups"
    total_bits = 6 + extra * 7
    uval = value & ((1 << total_bits) - 1)
    groups, shift = [], extra * 7
    groups.append((uval >> shift) & 0x3f)
    shift -= 7
    while shift >= 0:
        groups.append((uval >> shift) & 0x7f)
        shift -= 7
    out = bytearray()
    for i, g in enumerate(groups):
        b = g | (0x40 if (i == 0 and neg) else 0)
        b |= 0x80 if i != len(groups) - 1 else 0
        out.append(b)
    return bytes(out)


def s7p_returnvalue(code: int) -> bytes:
    """A ReturnValue: a varuint64 whose low 16 bits are the signed error code -- encoded here as
    just that low-16-bit value (upper OMS-line/error-source/debug-info bits left zero, matching
    the common real-world case of a "plain" success/failure code with no extra flags set)."""
    return vlq_u(code & 0xffff, max_groups=9)


# --- Value encoding (S7CommPlusValue, see decode_value/decode_value_element) --------------------
def s7p_scalar(datatype: int, payload: bytes) -> bytes:
    return bytes([0x00, datatype]) + payload


def s7p_array(datatype: int, elements, address_array: bool = False) -> bytes:
    flags = 0x20 if address_array else 0x10
    return bytes([flags, datatype]) + vlq_u(len(elements)) + b"".join(elements)


def s7p_sparsearray(datatype: int, keyed_elements) -> bytes:
    out = bytearray([0x40, datatype])
    for key, elem in keyed_elements:
        out += vlq_u(key)
        out += elem
    out += vlq_u(0)  # terminating null key
    return bytes(out)


def s7p_struct_members(pairs) -> bytes:
    """`pairs`: list of (id, value_bytes). Used both for a Struct value's own members (looping,
    needs the trailing null terminator) -- see decode_id_value_list(looping=true)."""
    out = b"".join(vlq_u(id_) + v for id_, v in pairs)
    out += vlq_u(0)
    return out


def s7p_value_struct(pairs) -> bytes:
    # flags=0 (scalar) + datatype 0x17 (Struct) + 4-byte marker (not further interpreted) +
    # the nested, null-terminated id-value-list of members.
    return bytes([0x00, 0x17]) + struct.pack("!I", 0) + s7p_struct_members(pairs)


def s7p_idvalue(id_: int, value_bytes: bytes) -> bytes:
    """One {id, value} pair as consumed by decode_id_value_list(looping=false) -- exactly one
    pair, no trailing null terminator (SetMultiVariables/SetVariable request items)."""
    return vlq_u(id_) + value_bytes


# Fixed-width scalar element encoders (datatype byte, payload) pairs for the common cases used
# below -- element payload only, matching decode_value_element's per-datatype byte layout exactly.
def el_bool(v: bool) -> bytes: return bytes([1 if v else 0])
def el_usint(v: int) -> bytes: return bytes([v & 0xff])
def el_uint(v: int) -> bytes: return struct.pack("!H", v & 0xffff)
def el_udint(v: int) -> bytes: return vlq_u(v)
def el_ulint(v: int) -> bytes: return vlq_u(v, max_groups=9)
def el_sint(v: int) -> bytes: return struct.pack("!b", v)
def el_int(v: int) -> bytes: return struct.pack("!h", v)
def el_dint(v: int) -> bytes: return vlq_s(v)
def el_lint(v: int) -> bytes: return vlq_s(v, max_groups=9)
def el_byte(v: int) -> bytes: return bytes([v & 0xff])
def el_word(v: int) -> bytes: return struct.pack("!H", v & 0xffff)
def el_dword(v: int) -> bytes: return struct.pack("!I", v & 0xffffffff)
def el_lword(v: int) -> bytes: return struct.pack("!Q", v & 0xffffffffffffffff)
def el_real(v: float) -> bytes: return struct.pack("!f", v)
def el_lreal(v: float) -> bytes: return struct.pack("!d", v)
def el_timestamp(ns: int) -> bytes: return struct.pack("!Q", ns)
def el_timespan(ns: int) -> bytes: return vlq_u(ns, max_groups=9)
def el_rid(v: int) -> bytes: return struct.pack("!I", v)
def el_aid(v: int) -> bytes: return vlq_u(v)
def el_variant(type_id: int) -> bytes: return vlq_u(type_id)


def el_blob(data: bytes) -> bytes:
    return bytes([0]) + vlq_u(len(data)) + data


def el_wstring(s: str) -> bytes:
    b = s.encode("utf-8")
    return vlq_u(len(b)) + b


# --- Item address encoding (decode_item_address) ------------------------------------------------
def s7p_item_symbolic(crc: int, area2: int, lid_depth: int = 1, base_area: int = 0,
                       extra_lids=None, area1: int = 0x0000) -> bytes:
    extra_lids = extra_lids or []
    field2 = (area1 << 16) | area2
    out = vlq_u(crc) + vlq_u(field2) + vlq_u(lid_depth) + vlq_u(base_area)
    for v in extra_lids:
        out += vlq_u(v)
    return out


def s7p_item_object_id(rid: int, base_id: int, lid_depth: int = 1, extra_ids=None) -> bytes:
    extra_ids = extra_ids or []
    out = vlq_u(0) + vlq_u(rid) + vlq_u(lid_depth) + vlq_u(base_id)
    for v in extra_ids:
        out += vlq_u(v)
    return out


# --- Function bodies (see the matching decode_request_*/decode_response_* in s7commplus.cpp) ----
def s7p_getmultivar_request(item_addrs) -> bytes:
    out = struct.pack("!I", 0)  # link_id = 0 (the "normal", non-subscribed-link path)
    out += vlq_u(len(item_addrs)) + vlq_u(len(item_addrs))  # item_count + "fields in complete set"
    for a in item_addrs:
        out += a
    return out


def s7p_getmultivar_request_subscribed(link_id: int, ids) -> bytes:
    out = struct.pack("!I", link_id)
    out += vlq_u(len(ids))  # item_count (present on the wire, unused by this branch's own loop)
    out += vlq_u(len(ids))  # addr_count
    for i in ids:
        out += vlq_u(i)
    return out


def s7p_getmultivar_response(return_code: int, item_values, item_errors=()) -> bytes:
    out = s7p_returnvalue(return_code)
    for item_num, value_bytes in item_values:
        out += vlq_u(item_num) + value_bytes
    out += vlq_u(0)
    for item_num, err_code in item_errors:
        out += vlq_u(item_num) + s7p_returnvalue(err_code)
    out += vlq_u(0)
    return out


def s7p_setmultivar_request_marker0(item_addrs, idvalue_pairs) -> bytes:
    out = struct.pack("!I", 0)
    out += vlq_u(len(item_addrs)) + vlq_u(len(item_addrs))
    for a in item_addrs:
        out += a
    for iv in idvalue_pairs:
        out += iv
    return out


def s7p_setmultivar_request_marker(marker: int, ids, idvalue_pairs) -> bytes:
    out = struct.pack("!I", marker)
    out += vlq_u(len(ids)) + vlq_u(len(ids))  # item_count + addr_count
    for i in ids:
        out += vlq_u(i)
    for iv in idvalue_pairs:
        out += iv
    return out


def s7p_setmultivar_response(return_code: int, item_errors=()) -> bytes:
    out = s7p_returnvalue(return_code)
    for item_num, err_code in item_errors:
        out += vlq_u(item_num) + s7p_returnvalue(err_code)
    out += vlq_u(0)
    return out


def s7p_setvariable_request(object_id: int, idvalue_pairs) -> bytes:
    out = struct.pack("!I", object_id) + vlq_u(len(idvalue_pairs))
    for iv in idvalue_pairs:
        out += iv
    return out


def s7p_setvariable_response(return_code: int) -> bytes:
    return s7p_returnvalue(return_code)


def s7p_deleteobject_request(object_id: int) -> bytes:
    return struct.pack("!I", object_id)


def s7p_deleteobject_response(return_code: int, object_id: int) -> bytes:
    return s7p_returnvalue(return_code) + struct.pack("!I", object_id)


# --- Envelope / header / trailer / integrity ------------------------------------------------
def s7p_integrity(integrity_id: int = 1, digest_len: int = 32) -> bytes:
    out = vlq_u(integrity_id) + bytes([digest_len])
    if digest_len == 32:
        out += bytes((i * 7 + 3) % 256 for i in range(32))  # arbitrary deterministic filler
    return out


def s7p_integrity_fw1_5(integrity_id: int = 1) -> bytes:
    """DataFW1_5's own Integrity shape, at the FRONT of the Data part rather than the end: the
    same varuint32 id + 32-byte digest as s7p_integrity() above, but with NO length-prefix byte
    in between -- confirmed against a real S7-1212C capture, see decode_integrity_fw1_5 in
    src/s7commplus.cpp."""
    return vlq_u(integrity_id) + bytes((i * 5 + 11) % 256 for i in range(32))  # arbitrary filler


def s7p_envelope(opcode: int, function_code: int, seq: int, body: bytes, session_id: int = 0,
                  integrity: bool = True) -> bytes:
    out = bytearray([opcode])
    out += struct.pack("!H", 0)  # reserved1
    out += struct.pack("!H", function_code)
    out += struct.pack("!H", 0)  # reserved2
    out += struct.pack("!H", seq)
    if opcode == S7P_OPCODE_REQUEST:
        out += struct.pack("!I", session_id) + bytes([0])
    else:
        out += bytes([0])
    out += body
    if integrity:
        out += s7p_integrity()
    return bytes(out)


def s7p_frame(pdu_type: int, data_part: bytes) -> bytes:
    data_length = len(data_part)
    hdr = bytes([0x72, pdu_type]) + struct.pack("!H", data_length)
    trl = bytes([0x72, pdu_type]) + struct.pack("!H", data_length)
    return hdr + data_part + trl


def s7p_frame_no_trailer(pdu_type: int, partial_data: bytes, declared_full_length: int) -> bytes:
    """A telegram whose trailer hasn't arrived yet (the ABSENCE of a trailer, not COTP's own EOT
    bit, is S7comm-Plus's own fragmentation signal -- see s7commplus.hpp; this decoder does not
    reassemble across it, only reports it)."""
    hdr = bytes([0x72, pdu_type]) + struct.pack("!H", declared_full_length)
    return hdr + partial_data


def s7p_keepalive(seq: int) -> bytes:
    return bytes([0x72, S7P_PDUTYPE_KEEPALIVE, seq & 0xff, 0x00])


def build_s7commplus_sample():
    """S7comm-Plus (0x72) -- see s7commplus.hpp's own file header for the wire format this
    exercises. Main flow (port 102, one long-lived TCP session, mirroring a real TIA Portal HMI
    connection): COTP Connection Request/Confirm, then every Tier-1 function this decoder fully
    decodes in both directions -- GetMultiVariables (both the normal "link_id=0" item-address path,
    covering a symbolic Merker/DB/nested-LID/unrecognized-IQMCT-area/unrecognized-area address
    shapes plus an object-ID-style item, and the "subscribed link" item-number path) with a
    response covering nearly every datatype (including a genuinely nested Struct-of-Struct, an
    Array, an Addressarray, and a Sparsearray) plus a per-item error entry; SetMultiVariables in
    both its marker==0 (native symbolic item-address) and marker!=0 (object-ID) request shapes,
    responses with per-item errors; SetVariable and DeleteObject request/response pairs; and a
    DataFW1_5-framed GetMultiVariables request (Tier 1, same body decode as PDU type Data, just
    with its own Integrity value at the front of the Data part instead of the end -- confirmed
    against a real S7-1212C capture, see decode_integrity_fw1_5 in src/s7commplus.cpp). Then the
    Tier-2 (named, not body-decoded) shapes: Connect, Notification, and one representative
    "other" function code (Explore) neither direction decodes. Then a Keep Alive
    PDU (its own distinct 4-byte-header-only framing). Then two deliberate edge cases: a value with
    an array-of-Struct (the one shape this decoder deliberately refuses to decode, throwing
    ParseError rather than risk silent misalignment -- see s7commplus.hpp/decode_value's own
    comment, and the genuine bug this project's own code review caught before ever building it),
    and a value using the one datatype code (S7String, 0x19) this decoder's value switch does not
    implement, both exercising the per-Data-part try/catch's graceful "decoding stopped" note
    rather than losing the whole packet. Separate flows (own port pairs): a telegram missing its
    trailer (S7comm-Plus's own above-COTP fragmentation signal, NOT reassembled by this decoder --
    reported as such); a completely truncated (<4 byte) telegram (the outer catch(ParseError)
    "could not parse packet" path); and a session on a non-102 TCP port (the "not a configured/
    standard COTP/S7comm port" note)."""
    ENG_IP, PLC_PORT = HMI_IP, 102
    packets = []
    ident = [0x8000]

    # ---------------------------------------------------------------------------------------------
    # Main flow, port 50300.
    # ---------------------------------------------------------------------------------------------
    ENG_PORT = 50300
    client_seq, server_seq = [30000], [40000]

    def add(from_client: bool, tpkt_bytes: bytes, sport=ENG_PORT, dport=PLC_PORT):
        ident[0] += 1
        if from_client:
            src_ip, dst_ip, src_mac, dst_mac = ENG_IP, PLC_IP, HMI_MAC, PLC_MAC
            src_port, dst_port = sport, dport
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(tpkt_bytes)
        else:
            src_ip, dst_ip, src_mac, dst_mac = PLC_IP, ENG_IP, PLC_MAC, HMI_MAC
            src_port, dst_port = dport, sport
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(tpkt_bytes)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(tpkt_bytes)) + tpkt_bytes
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    def dt(s7p_bytes: bytes) -> bytes:
        return tpkt_frame(COTP_DT_HEADER, s7p_bytes)

    # 1) & 2) COTP Connection Request/Confirm.
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0003, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(True, tpkt_frame(cr))
    cc = cotp_connection_pdu(0xD0, 0x0003, 0x7001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(False, tpkt_frame(cc))

    # 3) & 4) GetMultiVariables request/response -- the "normal" (link_id=0) item-address path,
    #    covering five distinct address shapes in one request: symbolic Merker (M), symbolic DB
    #    with a nested LID (struct/array member chain), an unrecognized IQMCT area code, a wholly
    #    unrecognized area1/area2 pair, and an object-ID-style item.
    items_a = [
        s7p_item_symbolic(0xea2db0d9, 0x52, lid_depth=1),                       # SYM-CRC=..., LID=M
        s7p_item_symbolic(0xa9bc66e6, 5, lid_depth=2,                           # SYM-CRC=..., LID=DB5.10
                           extra_lids=[10], area1=0x8a0e, base_area=0),
        s7p_item_symbolic(0x11111111, 0x99, lid_depth=1),                       # unrecognized IQMCT area
        s7p_item_symbolic(0x22222222, 0x5678, lid_depth=1, area1=0x1234),       # unrecognized area1/area2
        s7p_item_object_id(rid=100, base_id=500, lid_depth=2, extra_ids=[7]),   # by IDs: RID=100, ID=500, ID=7
    ]
    req_a = s7p_getmultivar_request(items_a)
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_GETMULTIVAR, 1,
                                                            req_a, session_id=0x1001, integrity=False))))

    values_a = [
        (1, s7p_scalar(0x07, el_int(-1234))),                                    # Int
        (2, s7p_array(0x08, [el_dint(1), el_dint(2), el_dint(-3)])),             # Array of DInt
        (3, s7p_array(0x03, [el_uint(10), el_uint(20)], address_array=True)),    # Addressarray of UInt
        (4, s7p_sparsearray(0x0a, [(5, el_byte(0xAA)), (9, el_byte(0xBB))])),    # Sparsearray of Byte
        (5, s7p_value_struct([(315, s7p_scalar(0x04, el_udint(320))),
                               (316, s7p_value_struct([(1826, s7p_scalar(0x05, el_ulint(123456789))),
                                                        (1827, s7p_scalar(0x04, el_udint(42)))])),
                               (317, s7p_scalar(0x15, el_wstring("V1.0;6ES7 511-1AK00-0AB0")))])),
        (6, s7p_scalar(0x0f, el_lreal(3.14159265))),                             # LReal
        (7, s7p_scalar(0x10, el_timestamp(1_726_000_000_123_456_789))),          # Timestamp
        (8, s7p_scalar(0x11, el_timespan(1_500_000_000))),                       # Timespan
        (9, s7p_scalar(0x14, el_blob(bytes(range(40))))),                        # Blob (truncated display)
    ]
    resp_a = s7p_getmultivar_response(0, values_a, item_errors=[(10, -12)])  # one item: Object not found
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_GETMULTIVAR, 1,
                                                             resp_a))))

    # 5) & 6) GetMultiVariables request/response -- the "subscribed link" item-number path
    #    (link_id != 0), a genuinely different request shape from items_a above.
    req_b = s7p_getmultivar_request_subscribed(link_id=42, ids=[1, 2, 3])
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_GETMULTIVAR, 2,
                                                            req_b, session_id=0x1001, integrity=False))))
    resp_b = s7p_getmultivar_response(0, [(1, s7p_scalar(0x01, el_bool(True))),
                                           (2, s7p_scalar(0x01, el_bool(False))),
                                           (3, s7p_scalar(0x02, el_usint(7)))])
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_GETMULTIVAR, 2,
                                                             resp_b))))

    # 7) & 8) SetMultiVariables -- marker==0 (native symbolic item-address) request shape.
    set_items_a = [s7p_item_symbolic(0xdeadbeef, 0x52, lid_depth=1),
                   s7p_item_symbolic(0xcafef00d, 5, lid_depth=2, extra_lids=[20], area1=0x8a0e)]
    set_values_a = [s7p_idvalue(1, s7p_scalar(0x0e, el_real(98.6))),
                    s7p_idvalue(2, s7p_scalar(0x0c, el_dword(0xdeadbeef)))]
    req_c = s7p_setmultivar_request_marker0(set_items_a, set_values_a)
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_SETMULTIVAR, 3,
                                                            req_c, session_id=0x1001, integrity=False))))
    resp_c = s7p_setmultivar_response(0)
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_SETMULTIVAR, 3,
                                                             resp_c))))

    # 9) & 10) SetMultiVariables -- marker!=0 (object-ID) request shape, with a per-item error in
    #     the response (a genuine write failure, not just an "OK" -- Invalid CRC this time).
    req_d = s7p_setmultivar_request_marker(
        0x00000388, [306, 305],
        [s7p_idvalue(1, s7p_scalar(0x04, el_udint(320))), s7p_idvalue(2, s7p_scalar(0x03, el_uint(3)))])
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_SETMULTIVAR, 4,
                                                            req_d, session_id=0x1001, integrity=False))))
    resp_d = s7p_setmultivar_response(0, item_errors=[(2, -17)])  # item 2: Invalid CRC
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_SETMULTIVAR, 4,
                                                             resp_d))))

    # 11) & 12) SetVariable request/response.
    req_e = s7p_setvariable_request(0x00000390, [s7p_idvalue(1, s7p_scalar(0x01, el_bool(True)))])
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_SETVARIABLE, 5,
                                                            req_e, session_id=0x1001, integrity=False))))
    resp_e = s7p_setvariable_response(0)
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_SETVARIABLE, 5,
                                                             resp_e))))

    # 13) & 14) DeleteObject request/response (the real captures only ever showed the request side
    #     -- this is the only place the response shape is validated at all, even synthetically).
    req_f = s7p_deleteobject_request(0x0000039a)
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_DELETEOBJECT, 6,
                                                            req_f, session_id=0x1001, integrity=False))))
    resp_f = s7p_deleteobject_response(0, 0x0000039a)
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_DELETEOBJECT, 6,
                                                             resp_f))))

    # 15) & 16) Connect PDU (Tier-2: recognized, not decoded) -- a second logical "session"
    #     handshake exchanged mid-flow, as real TIA Portal HMI sessions do when reconnecting.
    add(True, dt(s7p_frame(S7P_PDUTYPE_CONNECT, bytes(range(20)))))
    add(False, dt(s7p_frame(S7P_PDUTYPE_CONNECT, bytes(range(20, 40)))))

    # 17) Notification (Tier-2: opcode recognized, body not decoded) -- no function code, no
    #     session id; a materially different envelope shape from Request/Response.
    notif_body = bytes([S7P_OPCODE_NOTIFICATION]) + bytes(range(30))
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, notif_body)))

    # 18) DataFW1_5 (Tier 1, same as PDU type Data -- its own Integrity value just sits at the
    #     FRONT of the Data part instead of the end, confirmed against a real S7-1212C capture,
    #     see decode_integrity_fw1_5 in src/s7commplus.cpp). Once that's consumed, the rest is an
    #     ordinary GetMultiVariables request, decoded the same way PDU type Data's own is.
    fw15_data = s7p_integrity_fw1_5() + s7p_envelope(
        S7P_OPCODE_REQUEST, S7P_FC_GETMULTIVAR, 7,
        s7p_getmultivar_request([s7p_item_symbolic(0x1, 0x52)]),
        session_id=0x1001, integrity=False)
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATAFW1_5, fw15_data)))

    # 19) & 20) Explore (Tier-2: an "other" function code neither direction decodes).
    req_g = struct.pack("!I", 0x00000001) + bytes(range(10))  # arbitrary body, never parsed
    add(True, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_EXPLORE, 8,
                                                            req_g, session_id=0x1001, integrity=False))))
    resp_g = s7p_returnvalue(0) + bytes(range(10))
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_EXPLORE, 8,
                                                             resp_g))))

    # 21) Keep Alive -- its own distinct 4-byte header-only framing (no Data part, no trailer).
    add(True, dt(s7p_keepalive(9)))

    # 22) & 23) Edge cases exercising the Data part's own try/catch: an array-of-Struct value (the
    #     one shape this decoder deliberately refuses rather than risk silent misalignment -- see
    #     s7commplus.hpp/decode_value's own comment, and the bug this project's own code review
    #     caught before ever building it) and a value using S7String (0x19), the one datatype code
    #     the reference plugin's own generic value switch doesn't implement either.
    # datatype=Struct, is_array=true: decode_value reads the flags/datatype/array-size header, then
    # decode_value_element consumes the Struct element's own 4-byte marker (present below, all
    # zero, matching s7p_value_struct's own marker) before decode_value sees is_struct=true and
    # throws -- the nested member list a real Struct element would have next is never reached.
    array_of_struct_value = s7p_array(0x17, [struct.pack("!I", 0)])
    req_h_values = [(1, array_of_struct_value)]
    req_h = s7p_getmultivar_response(0, req_h_values)  # reusing the response shape (item-value-list)
    # via a GetMultiVariables Response envelope -- content only, doesn't need to be a real response
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_GETMULTIVAR, 10,
                                                             req_h))))

    s7string_value = s7p_scalar(0x19, b"\x05HELLO")  # datatype 0x19 -- unrecognized by decode_value_element
    req_i = s7p_getmultivar_response(0, [(1, s7string_value)])
    add(False, dt(s7p_frame(S7P_PDUTYPE_DATA, s7p_envelope(S7P_OPCODE_RESPONSE, S7P_FC_GETMULTIVAR, 11,
                                                             req_i))))

    # ---------------------------------------------------------------------------------------------
    # Separate flow: a telegram missing its trailer -- S7comm-Plus's own above-COTP fragmentation
    # signal (not COTP's own EOT bit), NOT reassembled by this decoder -- reported as such rather
    # than guessed at. Own port pair so it can't interact with the main flow's reassembly state.
    # ---------------------------------------------------------------------------------------------
    frag_port = 50301
    full_body = s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_GETMULTIVAR, 12,
                              s7p_getmultivar_request([s7p_item_symbolic(0x1, 0x52)]),
                              session_id=0x1001, integrity=False)
    partial = full_body[: len(full_body) // 2]
    frag = s7p_frame_no_trailer(S7P_PDUTYPE_DATA, partial, declared_full_length=len(full_body))
    tcp_frag = tcp_header(frag_port, PLC_PORT, 100, 200, TCP_PSH | TCP_ACK, len(dt(frag))) + dt(frag)
    ip_frag = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_frag), 0x8100) + tcp_frag
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_frag)

    # ---------------------------------------------------------------------------------------------
    # Separate flow: a completely truncated (<4 byte) telegram -- too short even for the fixed
    # header, so try_parse_s7comm_plus throws ParseError, surfaced via the decoder's outer
    # catch(ParseError) as protocol="parse-error" rather than a partial S7comm-Plus decode.
    # ---------------------------------------------------------------------------------------------
    trunc_port = 50302
    trunc = bytes([0x72, S7P_PDUTYPE_DATA])  # only 2 of the required 4 header bytes
    tcp_trunc = tcp_header(trunc_port, PLC_PORT, 100, 200, TCP_PSH | TCP_ACK, len(dt(trunc))) + dt(trunc)
    ip_trunc = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_trunc), 0x8200) + tcp_trunc
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_trunc)

    # ---------------------------------------------------------------------------------------------
    # Separate flow: a Keep Alive on a TCP session where NEITHER port is 102 (or any
    # --s7comm-port addition) -- exercises the "not a configured/standard COTP/S7comm port" note.
    # ---------------------------------------------------------------------------------------------
    other_port_a, other_port_b = 50303, 50304
    ka = tpkt_frame(COTP_DT_HEADER, s7p_keepalive(1))
    tcp_ka = tcp_header(other_port_a, other_port_b, 100, 200, TCP_PSH | TCP_ACK, len(ka)) + ka
    ip_ka = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_ka), 0x8300) + tcp_ka
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_ka)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_030_000 + i, i * 1000)
    (TESTS_DIR / "sample_s7commplus.pcap").write_bytes(data)


def build_mms_sample():
    """IEC 61850 MMS (ISO 9506) over the same TPKT/COTP transport S7comm shares -- see mms.hpp's own
    file header for the full Session/Presentation/ACSE/MMS layer stack this exercises. Covers: a
    full association (Session CONNECT/ACCEPT wrapping Presentation CP-type/CPA-type wrapping ACSE
    AARQ/AARE wrapping MMS initiate-RequestPDU/ResponsePDU), the "ubiquitous SI=1" ongoing-message
    shape (two concatenated SI=1/LI=0 markers -- see session_ongoing_prefix's own comment for why
    2, not 1), every Tier1 confirmed service this decoder fully decodes -- including the seven
    file-transfer services (obtainFile/fileOpen/fileRead/fileClose/fileRename/fileDelete/
    fileDirectory) IEC 61850's own COMTRADE/disturbance-file-retrieval workflow rides on -- an
    InformationReport, the Tier1/Tier2 split (a confirmed service this decoder recognizes by name but doesn't further
    decode), ServiceError/RejectPDU/Cancel-*/Conclude-* PDUs, and a genuinely malformed/truncated
    confirmedServiceRequest (invokeID present, service field missing -- mirrors the real one found
    in tests/real_captures/mms/iec61850_read.pcap, see its own ATTRIBUTION.md). Separate flows (own
    port pairs, so they can't interact) cover: a bare MMS PDU (no Session/Presentation/ACSE at all),
    a bare-Presentation ongoing message (Session omitted entirely -- the newer of this decoder's two
    "skip a layer" shapes, see mms.cpp's looks_like_bare_presentation), a single TPKT/session/
    presentation/MMS frame split mid-frame across two raw TCP segments (Decoder::
    reassemble_tcp_payload), a single MMS message chained across two COMPLETE TPKT/COTP DT frames
    via the EOT bit (Decoder::reassemble_cotp_data_frame), and two complete MMS frames coalesced by
    the sender/OS into one TCP segment (this decoder's own COTP/TPKT framing decodes only the first
    of these, with an honest note about the rest -- see cotp.cpp -- so this documents that known
    limitation for MMS specifically rather than a successful decode of both)."""
    ENG_IP, PLC_PORT = HMI_IP, 102
    packets = []
    ident = [0x7000]

    # ---------------------------------------------------------------------------------------------
    # Main flow: full association, then a long run of ongoing Data-Transfer messages.
    # ---------------------------------------------------------------------------------------------
    ENG_PORT = 49300
    client_seq = [10000]
    server_seq = [20000]

    def add(from_client: bool, tpkt_bytes: bytes):
        ident[0] += 1
        if from_client:
            src_ip, dst_ip, src_mac, dst_mac = ENG_IP, PLC_IP, HMI_MAC, PLC_MAC
            src_port, dst_port = ENG_PORT, PLC_PORT
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(tpkt_bytes)
        else:
            src_ip, dst_ip, src_mac, dst_mac = PLC_IP, ENG_IP, PLC_MAC, HMI_MAC
            src_port, dst_port = PLC_PORT, ENG_PORT
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(tpkt_bytes)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(tpkt_bytes)) + tpkt_bytes
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    def dt(bytes_) -> bytes:
        return tpkt_frame(COTP_DT_HEADER, bytes_)

    def ongoing(mms_pdu_bytes: bytes) -> bytes:
        return session_ongoing_prefix(2) + presentation_bare_fully_encoded(3, mms_pdu_bytes)

    # 1) & 2) COTP Connection Request/Confirm -- engineering workstation <-> IED.
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0002, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(True, tpkt_frame(cr))
    cc = cotp_connection_pdu(0xD0, 0x0002, 0x6001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(False, tpkt_frame(cc))

    # 3) Session CONNECT / Presentation CP-type / ACSE AARQ / MMS initiate-RequestPDU -- the
    #    association-establishment exchange every real IEC 61850 MMS session begins with.
    initiate_req = initiate_pdu(False, local_detail=1400, max_calling=5, max_called=5, nesting=6,
                                 version=1, parameter_cbb_bits=[0, 1, 2, 3, 6, 7],
                                 services_supported_bits=[0, 1, 2, 4, 5, 6, 11, 12, 13, 37, 71, 79])
    aarq = acse_aarq(initiate_req)
    cp = presentation_association([(1, ACSE_APPLICATION_CONTEXT_OID), (3, "1.0.9506.2.3")], 1, aarq)
    add(True, dt(session_connect(cp)))

    # 4) Session ACCEPT / Presentation CPA-type / ACSE AARE (accepted) / MMS initiate-ResponsePDU.
    initiate_resp = initiate_pdu(True, local_detail=1400, max_calling=5, max_called=5, nesting=6,
                                  version=1, parameter_cbb_bits=[0, 1, 2, 3, 6, 7],
                                  services_supported_bits=[0, 1, 2, 4, 5, 6, 11, 12, 13, 37, 71, 79])
    aare = acse_aare(0, initiate_resp)
    cpa = presentation_association([(1, ACSE_APPLICATION_CONTEXT_OID), (3, "1.0.9506.2.3")], 1, aare)
    add(False, dt(session_accept(cpa)))

    # 5) & 6) Read -- one variable, specificationWithResult=true.
    read_var = list_of_variable([var_spec_name(object_name_domain("IED1Device", "GGIO1$ST$Ind1$stVal"))])
    add(True, dt(ongoing(confirmed_request_pdu(1, read_request(True, read_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(1, read_response([access_result_success(data_bool(True))])))))

    # 7) & 8) Write -- one variable, one boolean value.
    write_var = list_of_variable([var_spec_name(object_name_domain("IED1Device", "GGIO1$SP$Ind1$setVal"))])
    add(True, dt(ongoing(confirmed_request_pdu(2, write_request(write_var, [data_bool(False)])))))
    add(False, dt(ongoing(confirmed_response_pdu(2, write_response([write_result_success()])))))

    # 9) & 10) GetNameList -- scoped to a domain.
    add(True, dt(ongoing(confirmed_request_pdu(3, getnamelist_request("domain", "IED1Device")))))
    add(False, dt(ongoing(confirmed_response_pdu(
        3, getnamelist_response(["LLN0", "GGIO1", "MMXU1"], more_follows=False)))))

    # 11) & 12) Identify.
    add(True, dt(ongoing(confirmed_request_pdu(4, svc(2, False, b"")))))  # identify-Request ::= NULL
    add(False, dt(ongoing(confirmed_response_pdu(
        4, identify_response("ConduitScope Labs", "Virtual IED", "1.0", ["1.0.9506.2.3"])))))

    # 13) & 14) GetVariableAccessAttributes.
    gvaa_name = object_name_domain("IED1Device", "GGIO1$ST$Ind1$stVal")
    add(True, dt(ongoing(confirmed_request_pdu(5, getvariableaccessattributes_request(gvaa_name)))))
    add(False, dt(ongoing(confirmed_response_pdu(5, getvariableaccessattributes_response(False)))))

    # 15) & 16) DefineNamedVariableList.
    dnvl_members = [var_spec_name(object_name_domain("IED1Device", "GGIO1$ST$Ind1$stVal")),
                     var_spec_name(object_name_domain("IED1Device", "GGIO1$ST$Ind2$stVal"))]
    add(True, dt(ongoing(confirmed_request_pdu(
        6, definenamedvariablelist_request(object_name_vmd("MyDataSet1"), dnvl_members)))))
    add(False, dt(ongoing(confirmed_response_pdu(6, definenamedvariablelist_response()))))

    # 17) & 18) GetNamedVariableListAttributes.
    add(True, dt(ongoing(confirmed_request_pdu(
        7, getnamedvariablelistattributes_request(object_name_vmd("MyDataSet1"))))))
    add(False, dt(ongoing(confirmed_response_pdu(
        7, getnamedvariablelistattributes_response(True, dnvl_members)))))

    # 19) & 20) DeleteNamedVariableList.
    add(True, dt(ongoing(confirmed_request_pdu(
        8, deletenamedvariablelist_request(names=[object_name_vmd("MyDataSet1")])))))
    add(False, dt(ongoing(confirmed_response_pdu(8, deletenamedvariablelist_response(1, 1)))))

    # 21) & 22) GetCapabilityList.
    add(True, dt(ongoing(confirmed_request_pdu(9, getcapabilitylist_request()))))
    add(False, dt(ongoing(confirmed_response_pdu(
        9, getcapabilitylist_response(["STR1", "VNAM", "VALT"], more_follows=False)))))

    # 23) & 24) GetDomainAttributes.
    add(True, dt(ongoing(confirmed_request_pdu(10, getdomainattributes_request("IED1Device")))))
    add(False, dt(ongoing(confirmed_response_pdu(
        10, getdomainattributes_response(["STR1"], state=2, deletable=False, sharable=True)))))

    # 25) & 26) ObtainFile -- IEC 61850's own COMTRADE/disturbance-file-retrieval workflow rides on
    #     this service (see ROADMAP in docs/MANUAL.md); sourceFileServer omitted (OPTIONAL).
    add(True, dt(ongoing(confirmed_request_pdu(
        11, obtainfile_request(["COMTRADE", "fault17.dat"], ["fault17.dat"])))))
    add(False, dt(ongoing(confirmed_response_pdu(11, svc(46, False, b"")))))  # ObtainFile-Response ::= NULL

    # 27) & 28) FileOpen -- fileAttributes' own lastModified (GeneralizedTime) exercised here.
    add(True, dt(ongoing(confirmed_request_pdu(
        12, fileopen_request(["COMTRADE", "fault17.dat"], initial_position=0)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        12, fileopen_response(frsm_id=7, size_of_file=20480, last_modified="20250115120000Z")))))

    # 29) & 30) FileRead -- moreFollows explicitly encoded false (overriding its own DEFAULT TRUE).
    add(True, dt(ongoing(confirmed_request_pdu(13, fileread_request(frsm_id=7)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        13, fileread_response(bytes.fromhex("cafebabe0102"), more_follows=False)))))

    # 31) & 32) FileClose -- releases the frsmID FileOpen returned above.
    add(True, dt(ongoing(confirmed_request_pdu(14, fileclose_request(frsm_id=7)))))
    add(False, dt(ongoing(confirmed_response_pdu(14, svc(74, False, b"")))))  # FileClose-Response ::= NULL

    # 33) & 34) FileRename.
    add(True, dt(ongoing(confirmed_request_pdu(
        15, filerename_request(["COMTRADE", "fault17.dat"], ["COMTRADE", "fault17_archived.dat"])))))
    add(False, dt(ongoing(confirmed_response_pdu(15, svc(75, False, b"")))))  # FileRename-Response ::= NULL

    # 35) & 36) FileDelete -- FileName is a bare (constructed) alternative at the CHOICE level.
    add(True, dt(ongoing(confirmed_request_pdu(
        16, filedelete_request(["COMTRADE", "fault17_archived.dat"])))))
    add(False, dt(ongoing(confirmed_response_pdu(16, svc(76, False, b"")))))  # FileDelete-Response ::= NULL

    # 37) & 38) FileDirectory -- listOfDirectoryEntry is the one EXPLICIT-tagged field in this whole
    #     section (see mms.cpp's own header comment); moreFollows explicitly encoded true here
    #     (overriding its own DEFAULT FALSE), and one entry omits lastModified (OPTIONAL).
    add(True, dt(ongoing(confirmed_request_pdu(17, filedirectory_request(file_spec=["COMTRADE"])))))
    add(False, dt(ongoing(confirmed_response_pdu(17, filedirectory_response(
        [directory_entry(["COMTRADE", "fault17.cfg"], size_of_file=512, last_modified="20250115120000Z"),
         directory_entry(["COMTRADE", "fault18.dat"], size_of_file=20480)],
        more_follows=True)))))

    # 39) InformationReport -- an unconfirmed, unsolicited report from the IED (this decoder's own
    #     MMS analog of its GOOSE decoder, see mms.hpp).
    report_var = variable_list_name(object_name_vmd("MyDataSet1"))
    add(False, dt(ongoing(unconfirmed_pdu(information_report(
        report_var, [access_result_success(data_bool(True)),
                     access_result_success(data_utc_time(1_700_000_000, 0, 0x0A))])))))

    # 40) & 41) Tier2 demo -- takeControl(19) is a real, named confirmedServiceRequest/Response
    #     alternative (see kConfirmedServiceNames) that this decoder's own Tier1 dispatch does NOT
    #     further decode (mirrors the real tests/real_captures/mms/mms-takeControl.pcap finding):
    #     service_recognized=true, service_name=takeControl, but the body is shown as hex, not
    #     structurally decoded.
    add(True, dt(ongoing(confirmed_request_pdu(18, svc(19, True, ctx_p(0, b"IED1Device"))))))
    add(False, dt(ongoing(confirmed_response_pdu(18, svc(19, True, b"")))))

    # 42) ServiceError -- a Read request answered with confirmed-ErrorPDU instead of a normal
    #     response (errorClass=resource(3)).
    add(True, dt(ongoing(confirmed_request_pdu(19, read_request(False, read_var)))))
    add(False, dt(ongoing(confirmed_error_pdu(
        19, category_tag=3, code=1, additional_description="variable not found"))))

    # 43) RejectPDU -- server rejects invokeID 20 outright (confirmed-requestPDU category).
    add(False, dt(ongoing(reject_pdu(20, reason_tag=1, reason_code=1))))

    # 44) & 45) Cancel-Request/Response -- client cancels the earlier GetVariableAccessAttributes
    #     (invokeID 5).
    add(True, dt(ongoing(cancel_request_pdu(5))))
    add(False, dt(ongoing(cancel_response_pdu(5))))

    # 46) & 47) Cancel-Error -- a cancel for an invokeID the server has nothing outstanding for.
    add(True, dt(ongoing(cancel_request_pdu(99))))
    add(False, dt(ongoing(cancel_error_pdu(99, category_tag=10, code=1))))

    # 48) & 49) Malformed/truncated confirmedServiceRequest/Response -- invokeID present, service
    #     field missing entirely. Mirrors the real, genuinely truncated frame 18 of
    #     tests/real_captures/mms/iec61850_read.pcap (see its own ATTRIBUTION.md) -- this decoder
    #     degrades to an honest note rather than guessing or crashing.
    add(True, dt(ongoing(malformed_confirmed_request_no_service(77))))
    add(False, dt(ongoing(malformed_confirmed_response_no_service(78))))

    # 50) & 51) Conclude-Request/Response -- normal, graceful association release at the MMS level.
    add(True, dt(ongoing(conclude_request_pdu())))
    add(False, dt(ongoing(conclude_response_pdu())))

    # 52) & 53) Conclude-Error -- a second conclude attempt the server refuses.
    add(True, dt(ongoing(conclude_request_pdu())))
    add(False, dt(ongoing(conclude_error_pdu(category_tag=9, code=2))))

    # ---------------------------------------------------------------------------------------------
    # Separate flow: a bare MMS PDU -- no Session/Presentation/ACSE at all, the COTP Data frame's
    # user data starting directly with the MMS PDU's own tag byte (see mms.hpp's own "Bare MMS"
    # section; confirmed against tests/real_captures/mms/mms-cancelRequest.pcap and
    # mms-takeControl.pcap, both entirely bare).
    # ---------------------------------------------------------------------------------------------
    BARE_PORT = 49301
    bare_client_seq, bare_server_seq = [30000], [40000]

    def add_bare(from_client: bool, tpkt_bytes: bytes):
        ident[0] += 1
        if from_client:
            src_ip, dst_ip, src_mac, dst_mac = ENG_IP, PLC_IP, HMI_MAC, PLC_MAC
            src_port, dst_port = BARE_PORT, PLC_PORT
            seq, ack = bare_client_seq[0], bare_server_seq[0]
            bare_client_seq[0] += len(tpkt_bytes)
        else:
            src_ip, dst_ip, src_mac, dst_mac = PLC_IP, ENG_IP, PLC_MAC, HMI_MAC
            src_port, dst_port = PLC_PORT, BARE_PORT
            seq, ack = bare_server_seq[0], bare_client_seq[0]
            bare_server_seq[0] += len(tpkt_bytes)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(tpkt_bytes)) + tpkt_bytes
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    bare_cr = cotp_connection_pdu(0xE0, 0x0000, 0x0003, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add_bare(True, tpkt_frame(bare_cr))
    bare_cc = cotp_connection_pdu(0xD0, 0x0003, 0x6002, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add_bare(False, tpkt_frame(bare_cc))
    add_bare(True, dt(confirmed_request_pdu(1, svc(2, False, b""))))  # bare identify-Request
    add_bare(False, dt(confirmed_response_pdu(1, identify_response("ConduitScope Labs", "Virtual IED", "1.0"))))
    add_bare(True, dt(cancel_request_pdu(1)))
    add_bare(False, dt(conclude_request_pdu()))  # unrelated bare PDU right after, just to vary shapes

    # ---------------------------------------------------------------------------------------------
    # Separate flow: bare-Presentation ongoing message -- Session omitted entirely (see mms.hpp's
    # "Bare MMS" section's own related-shape paragraph and mms.cpp's looks_like_bare_presentation;
    # confirmed against tests/real_captures/mms/ATTRIBUTION.md's own real-capture finding).
    # ---------------------------------------------------------------------------------------------
    NOSESS_PORT = 49302
    nosess_client_seq, nosess_server_seq = [50000], [60000]

    def add_nosess(from_client: bool, tpkt_bytes: bytes):
        ident[0] += 1
        if from_client:
            src_ip, dst_ip, src_mac, dst_mac = ENG_IP, PLC_IP, HMI_MAC, PLC_MAC
            src_port, dst_port = NOSESS_PORT, PLC_PORT
            seq, ack = nosess_client_seq[0], nosess_server_seq[0]
            nosess_client_seq[0] += len(tpkt_bytes)
        else:
            src_ip, dst_ip, src_mac, dst_mac = PLC_IP, ENG_IP, PLC_MAC, HMI_MAC
            src_port, dst_port = PLC_PORT, NOSESS_PORT
            seq, ack = nosess_server_seq[0], nosess_client_seq[0]
            nosess_server_seq[0] += len(tpkt_bytes)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(tpkt_bytes)) + tpkt_bytes
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    nosess_cr = cotp_connection_pdu(0xE0, 0x0000, 0x0004, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add_nosess(True, tpkt_frame(nosess_cr))
    nosess_cc = cotp_connection_pdu(0xD0, 0x0004, 0x6003, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add_nosess(False, tpkt_frame(nosess_cc))
    status_body = confirmed_request_pdu(1, status_request(True))
    add_nosess(True, dt(presentation_bare_fully_encoded(3, status_body)))
    status_resp_body = confirmed_response_pdu(1, status_response(0, 0))
    add_nosess(False, dt(presentation_bare_fully_encoded(3, status_resp_body)))

    # ---------------------------------------------------------------------------------------------
    # Separate flow: one complete TPKT/session/presentation/MMS frame split mid-frame across two
    # raw TCP segments -- Decoder::reassemble_tcp_payload, the same general per-flow mechanism
    # sample_tcp_reassembly.pcap's own scenario C exercises for S7comm.
    # ---------------------------------------------------------------------------------------------
    SPLIT_PORT = 49303
    split_frame = dt(ongoing(confirmed_response_pdu(
        20, getcapabilitylist_response(["STR1", "STR2", "VNAM", "VALT", "VADR"], more_follows=False))))
    split_at = len(split_frame) // 2
    ident[0] += 1
    tcp_s1 = tcp_header(PLC_PORT, SPLIT_PORT, 70000, 500, TCP_PSH | TCP_ACK,
                         len(split_frame[:split_at])) + split_frame[:split_at]
    ip_s1 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_s1), ident[0]) + tcp_s1
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_s1)
    ident[0] += 1
    tcp_s2 = tcp_header(PLC_PORT, SPLIT_PORT, 70000 + split_at, 500, TCP_PSH | TCP_ACK,
                         len(split_frame[split_at:])) + split_frame[split_at:]
    ip_s2 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_s2), ident[0]) + tcp_s2
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_s2)

    # ---------------------------------------------------------------------------------------------
    # Separate flow: one MMS message chained across two COMPLETE TPKT/COTP DT frames via the EOT
    # bit -- Decoder::reassemble_cotp_data_frame -- mirroring sample_s7comm_chaining.pcap's own
    # scenario A, but for MMS: the split lands mid-way through a GetNameList response's own
    # listOfIdentifier so it only decodes correctly if both frames are genuinely concatenated.
    # ---------------------------------------------------------------------------------------------
    CHAIN_PORT = 49304
    COTP_DT_HEADER_FRAGMENT = bytes([0xF0, 0x00])  # EOT bit clear -- not the last fragment
    chain_payload = ongoing(confirmed_response_pdu(
        21, getnamelist_response(["Domain1LLN0", "Domain1GGIO1", "Domain1MMXU1", "Domain1XCBR1"],
                                  more_follows=False)))
    chain_split = len(chain_payload) // 2
    frame_c1 = tpkt_frame(COTP_DT_HEADER_FRAGMENT, chain_payload[:chain_split])
    frame_c2 = tpkt_frame(COTP_DT_HEADER, chain_payload[chain_split:])
    ident[0] += 1
    tcp_c1 = tcp_header(PLC_PORT, CHAIN_PORT, 80000, 600, TCP_PSH | TCP_ACK, len(frame_c1)) + frame_c1
    ip_c1 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_c1), ident[0]) + tcp_c1
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_c1)
    ident[0] += 1
    tcp_c2 = tcp_header(PLC_PORT, CHAIN_PORT, 80000 + len(frame_c1), 600, TCP_PSH | TCP_ACK,
                         len(frame_c2)) + frame_c2
    ip_c2 = ipv4_header(PLC_IP, ENG_IP, 6, len(tcp_c2), ident[0]) + tcp_c2
    packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_c2)

    # ---------------------------------------------------------------------------------------------
    # Separate flow: two complete MMS frames (Conclude-Request twice) coalesced by the sender/OS
    # into ONE TCP segment. cotp.cpp's own COTP/TPKT framing is genuinely single-PDU-per-call (see
    # its own "possible pipelined TPKT frames; only the first is decoded in this groundwork
    # release" note) -- unlike EtherNet/IP's or HART-IP's own dedicated multi-message-per-segment
    # loops, so this deliberately exercises (and documents, via the note it produces) that known,
    # already-honestly-labeled limitation for MMS specifically, rather than a successful decode of
    # both frames.
    # ---------------------------------------------------------------------------------------------
    COALESCE_PORT = 49305
    coalesced = dt(conclude_request_pdu()) + dt(conclude_request_pdu())
    ident[0] += 1
    tcp_co = tcp_header(COALESCE_PORT, PLC_PORT, 90000, 700, TCP_PSH | TCP_ACK, len(coalesced)) + coalesced
    ip_co = ipv4_header(ENG_IP, PLC_IP, 6, len(tcp_co), ident[0]) + tcp_co
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_co)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_010_000 + i, i * 1000)
    (TESTS_DIR / "sample_mms.pcap").write_bytes(data)


def build_iccp_sample():
    """ICCP/TASE.2 (IEC 60870-6-802) recognition -- see mms.hpp's own "ICCP/TASE.2 recognition"
    section and mms.cpp's own header comment right above apply_iccp_recognition for the full
    design and sourcing. TASE.2 rides the exact same COTP/Session/Presentation/ACSE/MMS stack and
    the same 14 MMSpdu alternatives build_mms_sample() above already exercises in full -- this
    fixture reuses the identical association-establishment shape (Session CONNECT/ACCEPT, ACSE
    AARQ/AARE over the same generic MMS application context, MMS initiate-Request/ResponsePDU) and
    then carries ordinary Read/Write/GetNameList/InformationReport traffic whose ObjectNames are
    TASE.2's own reserved VCC-scope/domain-scope system-variable names (cross-checked against two
    independent sources -- see mms.cpp's own comment) rather than IEC 61850's own LN/DO/DA
    convention. Covers: a domain-scope reserved name (Bilateral_Table_ID) read; a VCC-scope
    reserved name (TASE2_Version) read, whose own Data value is a two-element structure -- proving
    vmd-specific ObjectName rendering and this decoder's own recursive Data-structure decode
    combine correctly with the recognition note; a VCC-scope BIT STRING (Supported_Features) read;
    a device-control write to a reserved "_SBO"-suffixed variable and a second to a "_TAG"-suffixed
    one, each producing this decoder's own higher-value device-control note; an explicit NEGATIVE
    control proving that merely READING a similarly "_SBO"-suffixed variable (as opposed to
    WRITING it) does NOT produce the device-control note -- only an actual write is a control
    action; a GetNameList response enumerating several of these reserved names as bare
    vmd-scope identifiers; an InformationReport (a DSTransferSet's own periodic/exception report)
    carrying the Transfer_Set_Name/Transfer_Set_Time_Stamp/DSConditions_Detected trio; and a final
    SECOND negative control -- an ordinary IEC 61850-shaped Read (domain/item names carrying none
    of TASE.2's own reserved vocabulary) in the SAME session, proving this decoder does not flag
    plain IEC 61850 MMS traffic as ICCP merely because it rode the same association."""
    ENG_IP, PLC_PORT = HMI_IP, 102
    packets = []
    ident = [0x7100]

    ENG_PORT = 51000
    client_seq = [10000]
    server_seq = [20000]

    def add(from_client: bool, tpkt_bytes: bytes):
        ident[0] += 1
        if from_client:
            src_ip, dst_ip, src_mac, dst_mac = ENG_IP, PLC_IP, HMI_MAC, PLC_MAC
            src_port, dst_port = ENG_PORT, PLC_PORT
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(tpkt_bytes)
        else:
            src_ip, dst_ip, src_mac, dst_mac = PLC_IP, ENG_IP, PLC_MAC, HMI_MAC
            src_port, dst_port = PLC_PORT, ENG_PORT
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(tpkt_bytes)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(tpkt_bytes)) + tpkt_bytes
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident[0]) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    def dt(bytes_) -> bytes:
        return tpkt_frame(COTP_DT_HEADER, bytes_)

    def ongoing(mms_pdu_bytes: bytes) -> bytes:
        return session_ongoing_prefix(2) + presentation_bare_fully_encoded(3, mms_pdu_bytes)

    # 1) & 2) COTP Connection Request/Confirm.
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0010, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(True, tpkt_frame(cr))
    cc = cotp_connection_pdu(0xD0, 0x0010, 0x6010, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    add(False, tpkt_frame(cc))

    # 3) & 4) Session CONNECT/ACCEPT, ACSE AARQ/AARE, MMS initiate-Request/ResponsePDU -- the
    #    SAME generic MMS association shape build_mms_sample() uses (see this function's own
    #    header comment: TASE.2 does not appear to negotiate a distinct application context).
    initiate_req = initiate_pdu(False, local_detail=1400, max_calling=5, max_called=5, nesting=4,
                                 version=1, parameter_cbb_bits=[0, 1, 2, 3],
                                 services_supported_bits=[0, 1, 2, 4, 5, 6])
    aarq = acse_aarq(initiate_req)
    cp = presentation_association([(1, ACSE_APPLICATION_CONTEXT_OID), (3, "1.0.9506.2.3")], 1, aarq)
    add(True, dt(session_connect(cp)))

    initiate_resp = initiate_pdu(True, local_detail=1400, max_calling=5, max_called=5, nesting=4,
                                  version=1, parameter_cbb_bits=[0, 1, 2, 3],
                                  services_supported_bits=[0, 1, 2, 4, 5, 6])
    aare = acse_aare(0, initiate_resp)
    cpa = presentation_association([(1, ACSE_APPLICATION_CONTEXT_OID), (3, "1.0.9506.2.3")], 1, aare)
    add(False, dt(session_accept(cpa)))

    # 5) & 6) Read -- Bilateral_Table_ID, a domain-scope reserved TASE.2 system variable.
    blt_var = list_of_variable([var_spec_name(object_name_domain("ICCP_BLOCK1", "Bilateral_Table_ID"))])
    add(True, dt(ongoing(confirmed_request_pdu(1, read_request(True, blt_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        1, read_response([access_result_success(data_visible_string("SUBSTATION_A-CTRL_CTR_1"))])))))

    # 7) & 8) Read -- TASE2_Version, a VCC-scope (vmd-specific) reserved variable whose own Data
    #    value is a two-element structure (major, minor) -- exercises this decoder's own recursive
    #    Data-structure decode together with the recognition note in the same frame.
    ver_var = list_of_variable([var_spec_name(object_name_vmd("TASE2_Version"))])
    add(True, dt(ongoing(confirmed_request_pdu(2, read_request(True, ver_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        2, read_response([access_result_success(
            data_structure(data_unsigned(2000) + data_unsigned(8)))])))))

    # 9) & 10) Read -- Supported_Features, a VCC-scope BIT STRING (one bit per TASE.2 conformance
    #    block; bits 0/1/4 set here, i.e. blocks 1/2/5).
    feat_var = list_of_variable([var_spec_name(object_name_vmd("Supported_Features"))])
    add(True, dt(ongoing(confirmed_request_pdu(3, read_request(True, feat_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        3, read_response([access_result_success(data_bitstring(4, bytes([0xC8])))])))))  # bits 0,1,4 of 12

    # 11) & 12) Write -- device control: Select-Before-Operate handle for a breaker, the reserved
    #     "_SBO" suffix (see mms.cpp's own has_reserved_control_suffix). This is an actual WRITE,
    #     so it earns the higher-value device-control note, not just the general recognition one.
    sbo_var = list_of_variable([var_spec_name(object_name_domain("ICCP_BLOCK1", "Breaker52_SBO"))])
    add(True, dt(ongoing(confirmed_request_pdu(4, write_request(sbo_var, [data_bool(True)])))))
    add(False, dt(ongoing(confirmed_response_pdu(4, write_response([write_result_success()])))))

    # 13) & 14) Write -- device control: the reserved "_TAG" suffix (operator hold/blocking tag).
    tag_var = list_of_variable([var_spec_name(object_name_domain("ICCP_BLOCK1", "Breaker52_TAG"))])
    add(True, dt(ongoing(confirmed_request_pdu(5, write_request(tag_var, [data_int(1)])))))
    add(False, dt(ongoing(confirmed_response_pdu(5, write_response([write_result_success()])))))

    # 15) & 16) NEGATIVE CONTROL -- reading (not writing) a different "_SBO"-suffixed variable must
    #     NOT produce the device-control note: only an actual write is a control action.
    sbo_read_var = list_of_variable([var_spec_name(object_name_domain("ICCP_BLOCK1", "Breaker99_SBO"))])
    add(True, dt(ongoing(confirmed_request_pdu(6, read_request(True, sbo_read_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        6, read_response([access_result_success(data_int(0))])))))

    # 17) & 18) GetNameList -- VCC scope, enumerating several reserved names as bare identifiers
    #     alongside one unrelated one, proving detection also fires from a GetNameList response.
    add(True, dt(ongoing(confirmed_request_pdu(7, getnamelist_request("vmd")))))
    add(False, dt(ongoing(confirmed_response_pdu(
        7, getnamelist_response(
            ["Bilateral_Table_ID", "Supported_Features", "TASE2_Version", "SomeOtherName"],
            more_follows=False)))))

    # 19) InformationReport -- a DSTransferSet's own periodic/exception report, carrying the
    #     Transfer_Set_Name/Transfer_Set_Time_Stamp/DSConditions_Detected trio FreeTase2's own
    #     (commented-out reference) source builds a variable list from -- see mms.cpp's own
    #     recognition-section sourcing comment.
    report_var = list_of_variable([
        var_spec_name(object_name_domain("ICCP_BLOCK1", "Transfer_Set_Name")),
        var_spec_name(object_name_domain("ICCP_BLOCK1", "Transfer_Set_Time_Stamp")),
        var_spec_name(object_name_domain("ICCP_BLOCK1", "DSConditions_Detected")),
    ])
    add(False, dt(ongoing(unconfirmed_pdu(information_report(
        report_var,
        [access_result_success(data_visible_string("DSTransferSet1")),
         access_result_success(data_utc_time(1_700_000_000, 0, 0x0A)),
         access_result_success(data_bitstring(5, bytes([0x08])))])))))

    # 20) & 21) SECOND NEGATIVE CONTROL -- an ordinary IEC 61850-shaped Read, in the SAME session,
    #     whose domain/item names carry none of TASE.2's own reserved vocabulary: must NOT be
    #     flagged as ICCP merely because it rode the same association as the frames above.
    plain_var = list_of_variable([var_spec_name(object_name_domain("IED1Device", "GGIO1$ST$Ind1$stVal"))])
    add(True, dt(ongoing(confirmed_request_pdu(8, read_request(True, plain_var)))))
    add(False, dt(ongoing(confirmed_response_pdu(
        8, read_response([access_result_success(data_bool(True))])))))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_100_000 + i, i * 1000)
    (TESTS_DIR / "sample_iccp.pcap").write_bytes(data)


def build_policy_engine_sample():
    """Exercises PolicyEngine's client/server (initiator) determination and its cross-protocol
    "cotp counts as s7comm" folding (see policy_engine.cpp) -- none of which the other sample
    fixtures cover, since they don't carry real SYN/SYN-ACK handshakes at all (every other builder
    goes straight to PSH|ACK data, which is fine for protocol decoding but says nothing about
    PolicyEngine's flow-direction logic)."""
    packets = []

    def full_packet(src_ip, dst_ip, tcp_bytes, ident, from_plc):
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp_bytes), ident) + tcp_bytes
        eth_src, eth_dst = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        return eth_header(eth_dst, eth_src, 0x0800) + ip

    # Scenario A: a normal 3-way handshake (SYN, SYN-ACK, ACK) followed by a real Modbus
    # request/response, client port 51900 -> server port 502. The handshake's SYN and the
    # known-service-port fallback agree here -- this is the ordinary case PolicyEngine's client/
    # server logic should get right without needing to fall back to anything unusual.
    syn = tcp_header(51900, 502, 100, 0, TCP_SYN, 0)
    packets.append(full_packet(HMI_IP, PLC_IP, syn, 0x7000, from_plc=False))
    synack = tcp_header(502, 51900, 200, 101, TCP_SYN | TCP_ACK, 0)
    packets.append(full_packet(PLC_IP, HMI_IP, synack, 0x7001, from_plc=True))
    ack = tcp_header(51900, 502, 101, 201, TCP_ACK, 0)
    packets.append(full_packet(HMI_IP, PLC_IP, ack, 0x7002, from_plc=False))
    mb_req = struct.pack("!HHHBB HH", 10, 0, 6, 1, 3, 0, 1)
    tcp_req = tcp_header(51900, 502, 101, 201, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    packets.append(full_packet(HMI_IP, PLC_IP, tcp_req, 0x7003, from_plc=False))
    mb_resp = struct.pack("!HHHBBB", 10, 0, 5, 1, 3, 2) + bytes([0x00, 0x2A])
    tcp_resp = tcp_header(502, 51900, 201, 101 + len(mb_req), TCP_PSH | TCP_ACK, len(mb_resp)) + mb_resp
    packets.append(full_packet(PLC_IP, HMI_IP, tcp_resp, 0x7004, from_plc=True))

    # Scenario B: a bare handshake on a port pair that isn't any recognized OT protocol port and
    # carries no payload at all -- PolicyEngine must still record the flow (for
    # PolicyReport::skipped_non_tcp/total_packets accounting and so the flow shows up as
    # Unclassified with "no ... traffic was recognized", not silently dropped), but with zero
    # protocols observed.
    syn_b = tcp_header(51901, 9999, 300, 0, TCP_SYN, 0)
    packets.append(full_packet(HMI_IP, PLC_IP, syn_b, 0x7010, from_plc=False))
    synack_b = tcp_header(9999, 51901, 400, 301, TCP_SYN | TCP_ACK, 0)
    packets.append(full_packet(PLC_IP, HMI_IP, synack_b, 0x7011, from_plc=True))

    # Scenario C: tests that a later SYN can still correct an earlier, wrong port-based guess.
    # Client port 80 <-> "server" port 55000 -- deliberately the opposite of the usual
    # low-port-is-the-server convention PolicyEngine falls back to when neither port is a
    # recognized OT protocol port. The capture (unusually, but validly for this test) shows a data
    # packet from port 55000 BEFORE the SYN from port 80 arrives: PolicyEngine's first-packet
    # fallback for this flow guesses port 55000 (the numerically lower port) is the server --
    # exactly backwards. The SYN that arrives next, from port 80, must override that guess: real
    # SYN/SYN-ACK evidence always wins over the port-number fallback once it's seen, on any packet
    # in the flow, not just the first one (see PolicyEngine::observe's doc comment).
    early_data = tcp_header(55000, 80, 500, 0, TCP_PSH | TCP_ACK, 1) + b"\x00"
    packets.append(full_packet(PLC_IP, HMI_IP, early_data, 0x7020, from_plc=True))
    late_syn = tcp_header(80, 55000, 600, 0, TCP_SYN, 0)
    packets.append(full_packet(HMI_IP, PLC_IP, late_syn, 0x7021, from_plc=False))

    # Scenario D: a COTP Connection Request/Confirm with no S7comm payload ever following (unlike
    # sample_s7comm.pcap, which always continues into a full S7comm session) -- both packets decode
    # as protocol "cotp", never "s7comm". A policy conduit that only lists "s7comm" in its
    # 'protocols' must still match this flow, proving PolicyEngine::observe folds "cotp" into the
    # same protocol bucket as "s7comm" rather than treating a connection-setup-only session as
    # unrecognized traffic.
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0002, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cr = tpkt_frame(cr)
    tcp_cr = tcp_header(49300, 102, 700, 800, TCP_PSH | TCP_ACK, len(cotp_cr)) + cotp_cr
    packets.append(full_packet(HMI_IP, PLC_IP, tcp_cr, 0x7030, from_plc=False))
    cc = cotp_connection_pdu(0xD0, 0x0002, 0x5002, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cc = tpkt_frame(cc)
    tcp_cc = tcp_header(102, 49300, 800, 700 + len(cotp_cr), TCP_PSH | TCP_ACK, len(cotp_cc)) + cotp_cc
    packets.append(full_packet(PLC_IP, HMI_IP, tcp_cc, 0x7031, from_plc=True))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_700 + i, i * 1000)
    (TESTS_DIR / "sample_policy_engine.pcap").write_bytes(data)


def build_summarize_unclassified_sample():
    """Exercises `policy validate --summarize-unclassified` (policy_engine.cpp's
    summarize_unclassified_flows/write_unclassified_flow_group_summarized_text) -- a feature added
    after a real capture (a busy conference-network pcap) produced a 37MB/567K-line text report,
    almost entirely because one reconnecting host pair alone contributed 16,378 separate
    near-identical UNCLASSIFIED TRAFFIC entries (a new TCP flow, and so a new report entry, on every
    reconnect). None of the other sample fixtures repeat the exact same (client, server, port)
    pattern across multiple distinct TCP flows -- every one of them was built to exercise a single
    flow's own decoding, not this multi-flow-of-the-same-pattern shape -- so this is a dedicated,
    minimal fixture: bare SYN/SYN-ACK-only handshakes (no payload, so no protocol is ever recognized
    -- the "protocol-recognition-gap" unclassified reason), on three distinct (client, server, port)
    patterns, with the first two repeated across multiple flows (different source ports each time,
    since PolicyEngine keys a flow by the full 4-tuple) and the third going to an address outside
    every declared zone (the OTHER unclassified reason, "no declared zone contains ...") so both of
    FlowReport's two possible unclassified-reason shapes are covered:

      Pattern A: HMI_IP -> PLC_IP:9999, 3 separate flows (source ports 51940-51942), both zone-
                 classified, no payload -> "no recognized OT protocol traffic ..." reason.
      Pattern B: HMI_IP -> PLC_IP:8888, 2 separate flows (source ports 51950-51951), same reason as
                 A but a different server port, proving the summarizer keys by (client, server,
                 port), not just (client, server) -- these must NOT collapse into pattern A's group.
      Pattern C: HMI_IP -> 10.0.0.5:7777 (10.0.0.5 outside every zone tests/policies/
                 summarize_unclassified.yaml declares), 2 separate flows (source ports 51960-51961)
                 -> "no declared zone contains 10.0.0.5" reason instead.

    7 total unclassified flows (3+2+2), 14 total packets (2 per flow, SYN+SYN-ACK) -- summarizing
    should collapse these into exactly 3 groups, with each group's own flow-count/packet-total
    computed correctly (see CMakeLists.txt's summarize_unclassified_* tests)."""
    packets = []

    def full_packet(src_ip, dst_ip, tcp_bytes, ident, from_plc):
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp_bytes), ident) + tcp_bytes
        eth_src, eth_dst = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        return eth_header(eth_dst, eth_src, 0x0800) + ip

    def bare_handshake(client_ip, client_port, server_ip, server_port, ident_base, server_is_plc):
        syn = tcp_header(client_port, server_port, 100, 0, TCP_SYN, 0)
        packets.append(full_packet(client_ip, server_ip, syn, ident_base, from_plc=False))
        synack = tcp_header(server_port, client_port, 200, 101, TCP_SYN | TCP_ACK, 0)
        packets.append(full_packet(server_ip, client_ip, synack, ident_base + 1, from_plc=server_is_plc))

    ident = 0x7100
    # Pattern A: three separate flows, same (client, server, port).
    for client_port in (51940, 51941, 51942):
        bare_handshake(HMI_IP, client_port, PLC_IP, 9999, ident, server_is_plc=True)
        ident += 2
    # Pattern B: two separate flows, same (client, server) as A but a different port.
    for client_port in (51950, 51951):
        bare_handshake(HMI_IP, client_port, PLC_IP, 8888, ident, server_is_plc=True)
        ident += 2
    # Pattern C: two separate flows to an address outside every declared zone.
    for client_port in (51960, 51961):
        bare_handshake(HMI_IP, client_port, "10.0.0.5", 7777, ident, server_is_plc=False)
        ident += 2

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_800 + i, i * 1000)
    (TESTS_DIR / "sample_summarize_unclassified.pcap").write_bytes(data)


def build_inventory_sample():
    """Feeds the `inventory` subcommand (asset_inventory.cpp/hpp) a capture that spans TWO distinct
    /24 subnets -- every other sample fixture in this file uses only 192.168.1.0/24, which would
    only ever exercise AssetInventoryEngine::finish's single-zone case. This is the one fixture that
    proves inferred conduits can cross zone boundaries, not just connect a zone to itself.

    Zone "plant" (192.168.1.0/24) hosts every server: the Modbus PLC, the DNP3 outstation, the
    EtherNet/IP adapter, the S7-1500 PLC, and a BACnet AHU controller plus a BACnet operator
    workstation (both in-zone, unlike the other four). Zone "engineering" (10.0.5.0/24) hosts a
    single engineering workstation (10.0.5.21) that plays DNP3 master AND S7comm engineering client
    -- one real asset legitimately speaking two protocols -- plus a second host (10.0.5.22) acting
    as the EtherNet/IP explicit-messaging client, so the inferred asset list shows more than one
    engineering-side IP too. The Modbus HMI stays in-zone with its PLC (192.168.1.50 -> .10), giving
    the inferred conduit set a mix of intra-zone and cross-zone conduits:
        zone_192_168_1_0_24  -> zone_192_168_1_0_24   (modbus/502)   [intra-zone]
        zone_192_168_1_0_24  -> zone_192_168_1_0_24   (bacnet/47808) [intra-zone]
        zone_10_0_5_0_24     -> zone_192_168_1_0_24   (dnp3/20000)   [cross-zone]
        zone_10_0_5_0_24     -> zone_192_168_1_0_24   (s7comm/102)   [cross-zone]
        zone_10_0_5_0_24     -> zone_192_168_1_0_24   (enip/44818)   [cross-zone]
    """
    packets = []

    def add(payload: bytes):
        packets.append(payload)

    DNP3_OUTSTATION_IP, DNP3_OUTSTATION_MAC = "192.168.1.11", mac("00:0c:29:aa:bb:11")
    ENIP_SERVER_IP, ENIP_SERVER_MAC = "192.168.1.12", mac("00:0c:29:aa:bb:12")
    BACNET_CLIENT_IP, BACNET_CLIENT_MAC = "192.168.1.14", mac("00:0c:29:aa:bb:14")
    BACNET_SERVER_IP, BACNET_SERVER_MAC = "192.168.1.15", mac("00:0c:29:aa:bb:15")
    S7_PLC_IP, S7_PLC_MAC = "192.168.1.16", mac("00:0c:29:aa:bb:16")
    ENG_IP, ENG_MAC = "10.0.5.21", mac("00:0c:29:de:ad:01")
    ENIP_CLIENT_IP, ENIP_CLIENT_MAC = "10.0.5.22", mac("00:0c:29:de:ad:02")

    # --- Modbus: HMI (192.168.1.50) -> PLC (192.168.1.10), intra-zone -----------------------------
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req)
    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    mb_resp = struct.pack("!HHHBBB", 1, 0, 2 + 1 + len(reg_data), 1, 3, len(reg_data)) + reg_data
    tcp_resp = tcp_header(502, 51000, 2000, 1000 + len(mb_req), TCP_PSH | TCP_ACK, len(mb_resp)) + mb_resp
    ip_resp = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp_resp), 0x1001) + tcp_resp
    add(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_resp)

    # --- DNP3: engineering workstation (10.0.5.21, master) -> outstation (192.168.1.11), cross-zone
    read_class0 = bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06])
    read_frame = dnp3_link_frame(source=1, destination=1024, user_data=read_class0)
    tcp_dnp3_req = tcp_header(51500, 20000, 5000, 6000, TCP_PSH | TCP_ACK, len(read_frame)) + read_frame
    ip_dnp3_req = ipv4_header(ENG_IP, DNP3_OUTSTATION_IP, 6, len(tcp_dnp3_req), 0x2000) + tcp_dnp3_req
    add(eth_header(DNP3_OUTSTATION_MAC, ENG_MAC, 0x0800) + ip_dnp3_req)
    resp_payload = bytes([0xC0, 0xC0, 0x81, 0x80, 0x00]) + bytes([1, 2, 0x00, 0, 2]) + bytes([0x81, 0x01, 0x00])
    resp_frame = dnp3_link_frame(source=1024, destination=1, user_data=resp_payload)
    tcp_dnp3_resp = tcp_header(20000, 51500, 6000, 5000 + len(read_frame), TCP_PSH | TCP_ACK,
                                len(resp_frame)) + resp_frame
    ip_dnp3_resp = ipv4_header(DNP3_OUTSTATION_IP, ENG_IP, 6, len(tcp_dnp3_resp), 0x2001) + tcp_dnp3_resp
    add(eth_header(ENG_MAC, DNP3_OUTSTATION_MAC, 0x0800) + ip_dnp3_resp)

    # --- S7comm: same engineering workstation (10.0.5.21) -> S7-1500 PLC (192.168.1.16), cross-zone
    cr = cotp_connection_pdu(0xE0, 0x0000, 0x0001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cr = tpkt_frame(cr)
    tcp_cr = tcp_header(49200, 102, 200, 300, TCP_PSH | TCP_ACK, len(cotp_cr)) + cotp_cr
    ip_cr = ipv4_header(ENG_IP, S7_PLC_IP, 6, len(tcp_cr), 0x3000) + tcp_cr
    add(eth_header(S7_PLC_MAC, ENG_MAC, 0x0800) + ip_cr)
    cc = cotp_connection_pdu(0xD0, 0x0001, 0x5001, bytes([0x01, 0x00]), bytes([0x03, 0x02]))
    cotp_cc = tpkt_frame(cc)
    tcp_cc = tcp_header(102, 49200, 300, 200 + len(cotp_cr), TCP_PSH | TCP_ACK, len(cotp_cc)) + cotp_cc
    ip_cc = ipv4_header(S7_PLC_IP, ENG_IP, 6, len(tcp_cc), 0x3001) + tcp_cc
    add(eth_header(ENG_MAC, S7_PLC_MAC, 0x0800) + ip_cc)
    setup_param = struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240)
    setup_req = s7_header(0x01, 1, len(setup_param), 0) + setup_param
    cotp_setup_req = tpkt_frame(COTP_DT_HEADER, setup_req)
    tcp_s7_req = tcp_header(49200, 102, 400, 500, TCP_PSH | TCP_ACK, len(cotp_setup_req)) + cotp_setup_req
    ip_s7_req = ipv4_header(ENG_IP, S7_PLC_IP, 6, len(tcp_s7_req), 0x3002) + tcp_s7_req
    add(eth_header(S7_PLC_MAC, ENG_MAC, 0x0800) + ip_s7_req)
    setup_resp_param = struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240)
    setup_resp = s7_header(0x03, 1, len(setup_resp_param), 0) + struct.pack("!BB", 0, 0) + setup_resp_param
    cotp_setup_resp = tpkt_frame(COTP_DT_HEADER, setup_resp)
    tcp_s7_resp = tcp_header(102, 49200, 500, 400 + len(cotp_setup_req), TCP_PSH | TCP_ACK,
                              len(cotp_setup_resp)) + cotp_setup_resp
    ip_s7_resp = ipv4_header(S7_PLC_IP, ENG_IP, 6, len(tcp_s7_resp), 0x3003) + tcp_s7_resp
    add(eth_header(ENG_MAC, S7_PLC_MAC, 0x0800) + ip_s7_resp)

    # --- EtherNet/IP: a SEPARATE engineering host (10.0.5.22) -> adapter (192.168.1.12), cross-zone
    ctx = b"CS-INV01"
    session_handle = 0x99887766

    def add_enip(from_client: bool, payload: bytes, seq_state=[7000, 8000]):
        if from_client:
            src_port, dst_port = 52100, ENIP_PORT
            src_ip, dst_ip, src_mac, dst_mac = ENIP_CLIENT_IP, ENIP_SERVER_IP, ENIP_CLIENT_MAC, ENIP_SERVER_MAC
            seq, ack = seq_state[0], seq_state[1]
            seq_state[0] += len(payload)
        else:
            src_port, dst_port = ENIP_PORT, 52100
            src_ip, dst_ip, src_mac, dst_mac = ENIP_SERVER_IP, ENIP_CLIENT_IP, ENIP_SERVER_MAC, ENIP_CLIENT_MAC
            seq, ack = seq_state[1], seq_state[0]
            seq_state[1] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x4000 + len(packets)) + tcp
        add(eth_header(dst_mac, src_mac, 0x0800) + ip)

    add_enip(True, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=0, sender_context=ctx))
    add_enip(False, enip_message(0x0065, data=struct.pack("<HH", 1, 0), session_handle=session_handle,
                                  sender_context=ctx))
    add_enip(True, enip_message(0x006F, data=enip_cpf_unconnected(cip_read_tag_request("Line3_Speed", 1)),
                                 session_handle=session_handle, sender_context=ctx))
    add_enip(False, enip_message(0x006F,
                                  data=enip_cpf_unconnected(cip_read_tag_response(0xC4, struct.pack("<i", 7))),
                                  session_handle=session_handle, sender_context=ctx))

    # --- BACnet: operator workstation (192.168.1.14) -> AHU controller (192.168.1.15), intra-zone,
    #     UNICAST (not the broadcast Who-Is/I-Am traffic build_bacnet_sample uses) so both endpoints
    #     register as real assets/an edge rather than being filtered as broadcast destinations --
    #     see looks_like_broadcast_or_multicast's own comment in asset_inventory.cpp.
    req_apdu = apdu_confirmed_request(12, bacnet_object_property_reference(0, 3, 85), invoke_id=20)
    req_bvlc = bvlc_message(0x0A, npdu_header() + req_apdu)
    add(bacnet_frame(dst=BACNET_SERVER_MAC, src=BACNET_CLIENT_MAC, bvlc=req_bvlc,
                      src_ip=BACNET_CLIENT_IP, dst_ip=BACNET_SERVER_IP))
    ack_apdu = apdu_complex_ack(12, bacnet_object_property_reference(0, 3, 85) +
                                 bacnet_property_value(4, struct.pack("!f", 68.0)), invoke_id=20)
    ack_bvlc = bvlc_message(0x0A, npdu_header() + ack_apdu)
    add(bacnet_frame(dst=BACNET_CLIENT_MAC, src=BACNET_SERVER_MAC, bvlc=ack_bvlc,
                      src_ip=BACNET_SERVER_IP, dst_ip=BACNET_CLIENT_IP))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_020_000 + i, i * 1000)
    (TESTS_DIR / "sample_inventory.pcap").write_bytes(data)


def build_tcp_reassembly_sample():
    """Exercises Decoder::reassemble_tcp_payload -- general, per-TCP-flow reassembly of a single
    PDU/frame's own bytes split across TCP segments -- directly. This is a different layer from
    sample_dnp3.pcap's packets 8-12, which exercise DNP3's separate *application*-fragment
    reassembly across several already-COMPLETE data-link frames; here, a single Modbus ADU, DNP3
    data-link frame, or TPKT frame is itself cut apart mid-frame and delivered as two or more TCP
    segments (separate pcap packets, real sequence numbers). Each scenario below uses its own port
    pair so flows can't interact with each other or with any other sample file's fixtures."""
    packets = []

    def add_segment(src_port, dst_port, seq, ack, payload, ident, from_plc):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # A) A real Modbus/TCP response ADU (Read Holding Registers, 10 registers) split across two
    #    TCP segments mid-PDU.
    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    adu_a = struct.pack("!HHHBBB", 0xAAAA, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    assert len(adu_a) == 29
    split_a = 15
    add_segment(502, 51600, 20000, 100, adu_a[:split_a], 0x5000, from_plc=True)
    add_segment(502, 51600, 20000 + split_a, 100, adu_a[split_a:], 0x5001, from_plc=True)

    # B) A complete single-data-link-frame DNP3 fragment (Read Class 0) split mid-*header* -- the
    #    link layer's own bytes, not the application-fragment-across-frames case.
    read_class0 = bytes([0xC0, 0xC0, 0x01, 60, 1, 0x06])
    frame_b = dnp3_link_frame(source=1, destination=1024, user_data=read_class0)
    assert len(frame_b) == 18  # 10-byte header + 6 bytes of user data + 2-byte block CRC
    split_b = 6  # inside the 10-byte data-link header itself
    add_segment(51601, 20000, 21000, 200, frame_b[:split_b], 0x5002, from_plc=False)
    add_segment(51601, 20000, 21000 + split_b, 200, frame_b[split_b:], 0x5003, from_plc=False)

    # C) A TPKT/S7comm Setup Communication request split across two TCP segments.
    setup_param = struct.pack("!BBHHH", 0xF0, 0x00, 1, 1, 240)
    setup_req = s7_header(0x01, 77, len(setup_param), 0) + setup_param
    frame_c = tpkt_frame(COTP_DT_HEADER, setup_req)
    split_c = 10
    add_segment(51602, 102, 22000, 300, frame_c[:split_c], 0x5004, from_plc=False)
    add_segment(51602, 102, 22000 + split_c, 300, frame_c[split_c:], 0x5005, from_plc=False)

    # D) Sequence gap: a Modbus PDU begins, but the next segment on this flow arrives at a
    #    sequence number far past where the in-progress PDU expected -- as if an intervening
    #    segment was simply never captured. The in-progress reassembly must be abandoned (not
    #    spliced together wrong), and a later, ordinary, self-contained request on the SAME flow
    #    afterward must still decode normally, proving the abandoned state doesn't wedge the flow.
    gap_first = struct.pack("!HHHBBB", 0xBBBB, 0, 1 + 1 + 40, 1, 0x03, 40)  # declares 40 more bytes
    add_segment(502, 51603, 30000, 400, gap_first, 0x5006, from_plc=True)
    bogus_gap_segment = bytes(10)
    add_segment(502, 51603, 30000 + len(gap_first) + 500, 400, bogus_gap_segment, 0x5007, from_plc=True)
    fresh_req = struct.pack("!HHHBB HH", 2, 0, 6, 1, 3, 0, 10)  # ordinary, complete, 12-byte request ADU
    add_segment(502, 51603, 30000 + len(gap_first) + 1000, 400, fresh_req, 0x5008, from_plc=True)

    # E) A fully-duplicate retransmission (identical bytes, identical sequence number) arriving
    #    mid-reassembly must be ignored -- ignored, not appended a second time and not mistaken
    #    for a gap -- and the real completing segment afterward must still complete it correctly.
    adu_e = struct.pack("!HHHBBB", 0xCCCC, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    part1_e, part2_e, part3_e = adu_e[:10], adu_e[10:20], adu_e[20:]
    add_segment(502, 51604, 40000, 500, part1_e, 0x5009, from_plc=True)
    add_segment(502, 51604, 40000 + len(part1_e), 500, part2_e, 0x500A, from_plc=True)
    add_segment(502, 51604, 40000 + len(part1_e), 500, part2_e, 0x500B, from_plc=True)  # exact duplicate
    add_segment(502, 51604, 40000 + len(part1_e) + len(part2_e), 500, part3_e, 0x500C, from_plc=True)

    # F) A partial-overlap retransmission -- a segment that repeats a few already-buffered bytes
    #    and then extends past them with new ones (a common real TCP retransmit shape when the
    #    sender's own retransmit buffer starts slightly behind the last acknowledged byte) -- must
    #    be trimmed to just its new bytes and appended, not misaligned or duplicated.
    adu_f = struct.pack("!HHHBBB", 0xDDDD, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    part1_f = adu_f[:10]
    part2_f = adu_f[7:20]  # starts 3 bytes into part1_f's already-sent territory, extends to byte 20
    part3_f = adu_f[20:]
    add_segment(502, 51605, 50000, 600, part1_f, 0x500D, from_plc=True)
    add_segment(502, 51605, 50000 + 7, 600, part2_f, 0x500E, from_plc=True)
    add_segment(502, 51605, 50000 + len(part1_f) + (len(part2_f) - 3), 600, part3_f, 0x500F, from_plc=True)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_500 + i, i * 1000)
    (TESTS_DIR / "sample_tcp_reassembly.pcap").write_bytes(data)


def build_resource_exhaustion_active_flows_sample():
    """Exercises --max-active-flows (docs/reviews/2026-09-chatgpt-security-review-patch160.md's
    finding 1, resource_limits.hpp's max_active_flows): two DISTINCT TCP flows (different HMI
    source ports against the same PLC:502), each sending only the first half of a split Modbus
    ADU -- so each, on its own, leaves Decoder::tcp_reassembly_ with one entry "waiting for
    more". With the cap set low enough, the second flow's own still-incomplete segment forces
    eviction of the first flow's entry to make room."""
    packets = []

    def add_segment(src_port, dst_port, seq, ack, payload, ident, from_plc):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    split = 15

    # Flow 1 (PLC:502 -> HMI:51700): first half only of a 29-byte Modbus response ADU -- left
    # "waiting for more" in tcp_reassembly_, never completed in this fixture.
    adu_1 = struct.pack("!HHHBBB", 0x1111, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    add_segment(502, 51700, 60000, 1, adu_1[:split], 0x8000, from_plc=True)

    # Flow 2 (PLC:502 -> HMI:51701): a DIFFERENT flow (different HMI port), same shape -- its own
    # first segment is the one that should trigger eviction of flow 1's entry under
    # --max-active-flows 1.
    adu_2 = struct.pack("!HHHBBB", 0x2222, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    add_segment(502, 51701, 70000, 1, adu_2[:split], 0x8001, from_plc=True)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_600 + i, i * 1000)
    (TESTS_DIR / "sample_resource_exhaustion_active_flows.pcap").write_bytes(data)


def build_resource_exhaustion_flow_state_sample():
    """Exercises --max-flow-state-entries (docs/reviews/2026-09-chatgpt-security-review-
    patch160.md's finding 1, resource_limits.hpp's max_flow_state_entries): two DISTINCT Modbus
    TCP SESSIONS (different HMI source ports against the same PLC:502), each opening with a
    request that creates a ModbusFlowState entry in Decoder::registry_flow_state_. Session 2's
    own request forces eviction of session 1's entry when the cap is set to 1; session 1's later
    response (matching transaction id, same session) then finds no pending request at all --
    modbus.cpp's own "no outstanding request found on this TCP session" note -- which is the
    observable proof the eviction actually happened, not just that the cap was configured."""
    packets = []

    def add_segment(src_port, dst_port, seq, ack, payload, ident, from_plc):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # Session 1 (HMI:53000 <-> PLC:502): request, transaction id 100, read 5 holding registers.
    req_1 = struct.pack("!HHHBB HH", 100, 0, 6, 1, 0x03, 0, 5)
    add_segment(53000, 502, 10000, 1, req_1, 0x9000, from_plc=False)

    # Session 2 (HMI:53001 <-> PLC:502): a DIFFERENT session, own request -- forces eviction of
    # session 1's ModbusFlowState under --max-flow-state-entries 1.
    req_2 = struct.pack("!HHHBB HH", 200, 0, 6, 1, 0x03, 0, 5)
    add_segment(53001, 502, 20000, 1, req_2, 0x9001, from_plc=False)

    # Session 1's response to transaction id 100 -- with session 1's flow state evicted, this
    # finds no matching pending request even though the real request is right above.
    reg_data = b"".join(struct.pack("!H", v) for v in range(5))
    resp_1 = struct.pack("!HHHBBB", 100, 0, 1 + 2 + len(reg_data), 1, 0x03, len(reg_data)) + reg_data
    add_segment(502, 53000, 1, 10000 + len(req_1), resp_1, 0x9002, from_plc=True)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_000_700 + i, i * 1000)
    (TESTS_DIR / "sample_resource_exhaustion_flow_state.pcap").write_bytes(data)


def ipv6_packet(src: str, dst: str, upper_protocol: int, upper_payload: bytes, extensions: list = None) -> bytes:
    """Builds a full IPv6 packet (base header + optional extension-header chain + upper-layer
    payload). `extensions` is a list of (header_type_const, option_data_bytes) tuples, walked in
    the order given; `upper_protocol` is the real upper-layer protocol carried after the last
    extension header (or directly after the base header when `extensions` is empty/omitted)."""
    extensions = extensions or []
    ext_bytes = b""
    next_header_for_base = upper_protocol
    if extensions:
        next_header_for_base = extensions[0][0]
        for i, (_hdr_type, option_data) in enumerate(extensions):
            following = extensions[i + 1][0] if i + 1 < len(extensions) else upper_protocol
            ext_bytes += ipv6_extension_header(following, option_data)
    payload_len = len(ext_bytes) + len(upper_payload)
    return ipv6_header(src, dst, next_header_for_base, payload_len) + ext_bytes + upper_payload


IPV6_HOP_BY_HOP, IPV6_ROUTING, IPV6_DESTINATION_OPTIONS, IPV6_ESP = 0, 43, 60, 50


def build_ipv6_sample():
    """Exercises IPv6 support end to end (docs/DEVELOPMENT.md ROADMAP item 24) -- decoder.cpp's
    shared version-sniffing dispatch (Decoder::decode_ip_payload), parse_ipv6's own base-header and
    extension-header-chain parsing, and format_ipv6's RFC 5952 canonical rendering, all exercised
    through real Modbus/TCP traffic (the same protocol build_modbus_sample already uses over IPv4)
    so this is an end-to-end proof, not just a header-parsing unit test.

    Addresses are deliberately chosen for formatting variety: HMI6/PLC6 each have a zero run
    RFC 5952 must compress; LINK_LOCAL_A is almost entirely zero-run (::1-shaped compression at a
    different position); NO_COMPRESSION_ADDR has no zero run at all, proving format_ipv6 doesn't
    over-compress when there's nothing to compress."""
    packets = []

    HMI6, PLC6 = "2001:db8::50", "2001:db8::10"
    LINK_LOCAL_A, LINK_LOCAL_B = "fe80::1", "fe80::2"
    NO_COMPRESSION_ADDR = "2001:db8:1:2:3:4:5:6"

    # 1-2) Modbus request/response over IPv6+TCP, no extension headers -- the direct IPv6 mirror of
    # build_modbus_sample's own first exchange, proving the whole upper-layer cascade (TCP dispatch,
    # port-based Modbus recognition, request/response pairing) works completely unchanged when
    # decode_ip_payload was reached via the IPv6 branch instead of the IPv4 one.
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip6_req = ipv6_packet(HMI6, PLC6, 6, tcp_req)
    packets.append(eth_header(PLC_MAC, HMI_MAC, ETHERTYPE_IPV6) + ip6_req)

    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    mb_resp = struct.pack("!HHHBBB", 1, 0, 2 + 1 + len(reg_data), 1, 3, len(reg_data)) + reg_data
    tcp_resp = tcp_header(502, 51000, 2000, 1000 + len(mb_req), TCP_PSH | TCP_ACK, len(mb_resp)) + mb_resp
    ip6_resp = ipv6_packet(PLC6, HMI6, 6, tcp_resp)
    packets.append(eth_header(HMI_MAC, PLC_MAC, ETHERTYPE_IPV6) + ip6_resp)

    # 3) A UDP datagram over IPv6 between two link-local addresses (no recognized upper-layer
    # protocol on this port -- the point is proving has_udp/src_port/dst_port populate correctly
    # off an IPv6 outer header, the same way sample_modbus.pcap's own packets prove it for IPv4;
    # which specific UDP protocol carries it is not what this packet is testing).
    udp_payload = b"\xAA\xBB\xCC\xDD"
    udp_seg = udp_header(34567, 44444, udp_payload) + udp_payload
    ip6_udp = ipv6_packet(LINK_LOCAL_A, LINK_LOCAL_B, 17, udp_seg)
    packets.append(eth_header(PLC_MAC, HMI_MAC, ETHERTYPE_IPV6) + ip6_udp)

    # 4) The same Modbus request as packet 1, but preceded by a Hop-by-Hop Options header AND a
    # Destination Options header -- proves parse_ipv6's extension-header walk correctly reaches the
    # real upper-layer protocol (and the real payload) past two chained generic extension headers,
    # not just the "no extension headers at all" case packets 1-2 already cover. Addresses with no
    # zero run at all (NO_COMPRESSION_ADDR), to also prove format_ipv6 renders a fully-populated
    # address with plain colons and no "::" when there's nothing to compress.
    mb_req2 = struct.pack("!HHHBB HH", 2, 0, 6, 1, 3, 0, 4)
    tcp_req2 = tcp_header(51001, 502, 3000, 4000, TCP_PSH | TCP_ACK, len(mb_req2)) + mb_req2
    ip6_ext = ipv6_packet(
        NO_COMPRESSION_ADDR, PLC6, 6, tcp_req2,
        extensions=[(IPV6_HOP_BY_HOP, b"\x01\x02\x00\x00"), (IPV6_DESTINATION_OPTIONS, b"\x01\x02\x00\x00")],
    )
    packets.append(eth_header(PLC_MAC, HMI_MAC, ETHERTYPE_IPV6) + ip6_ext)

    # 5) next_header == ESP directly off the base header (no extension headers at all) -- proves
    # parse_ipv6 deliberately does NOT walk past ESP (its payload is encrypted, the same opaque-
    # regardless-of-IP-version limit ESP already has over IPv4): this must surface as a recognized-
    # but-undecoded ESP packet via decoder.cpp's existing GRE/ESP/AH/IPIP/6in4/L2TPv3 tunnel_vpn
    # recognition (tunnel_vpn.hpp), completely unchanged code, now reachable over IPv6 too.
    fake_esp_payload = struct.pack("!II", 0x12345678, 1) + b"\x00" * 8  # SPI + sequence + opaque ICV-ish bytes
    ip6_esp = ipv6_packet(HMI6, PLC6, IPV6_ESP, fake_esp_payload)
    packets.append(eth_header(PLC_MAC, HMI_MAC, ETHERTYPE_IPV6) + ip6_esp)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_030_000 + i, i * 1000)
    (TESTS_DIR / "sample_ipv6.pcap").write_bytes(data)


def build_ipv6_raw_link_sample():
    """A raw-IP link type (no Ethernet framing, no ethertype field at all) carrying an IPv6
    packet -- proves decoder.cpp's version-sniff (peeking the IP version nibble directly, since a
    raw-IP link has nothing else to tell IPv4 and IPv6 apart with) works with no ethertype hint to
    lean on, the scenario docs/DEVELOPMENT.md ROADMAP item 24 specifically calls out ("over a
    raw-IP link type there is no ethertype field to name it by at all"). pcapng (not classic pcap)
    because that's what build_pcapng_multi_interface_sample already established as this codebase's
    own way to declare a non-Ethernet link type for a fixture."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    raw_ip6_pkt = ipv6_packet("2001:db8::50", "2001:db8::10", 6, tcp_req)  # no Ethernet header at all

    data = (
        pcapng_shb()
        + pcapng_idb(linktype=LINKTYPE_RAW, snaplen=65535)
        + pcapng_epb(0, 1_700_030_500 * 1_000_000, raw_ip6_pkt)
    )
    (TESTS_DIR / "sample_ipv6_raw_link.pcapng").write_bytes(data)


def build_padded_ack_sample():
    # A bare ACK: 0 bytes of real TCP payload. Real Ethernet links pad frames
    # shorter than 60 bytes with trailing zeros, so the *captured* frame is
    # longer than the IP header's own total_length field says the datagram
    # is. This is exactly the shape that exposed a real conduitscope bug
    # (found via a real 4SICS capture, not synthetically): the IPv4 parser
    # used to hand every captured byte after the IP header to TCP as
    # "payload" instead of clamping to total_length, so this padding got
    # misreported as several bytes of phantom TCP payload on totally
    # ordinary ACKs.
    tcp_seg = tcp_header(49156, 102, 100, 200, TCP_ACK, 0)  # 20-byte header, 0 payload
    ip_seg = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_seg), 0x4000) + tcp_seg  # total_length = 40
    eth_frame = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_seg  # 54 bytes so far
    padded = eth_frame + bytes(max(0, 60 - len(eth_frame)))  # zero-pad to the 60-byte Ethernet minimum

    data = pcap_global_header()
    data += pcap_record(padded, 1_700_000_300, 0)
    (TESTS_DIR / "sample_padded_ack.pcap").write_bytes(data)


def build_pcapng_malformed():
    # First 4 bytes are the byte-order-independent pcapng Section Header Block magic
    # (0A 0D 0D 0A), which conduitscope's reader correctly recognizes as pcapng; the next 8
    # bytes (Block Total Length + what should be the Byte-Order Magic field) are left zeroed,
    # which is not a valid byte-order magic in either endianness. This exercises the "this is
    # pcapng, but it's corrupt" error path specifically -- distinct from "not a capture file
    # at all" -- since a zeroed Byte-Order Magic is the first thing that can go wrong while
    # parsing a real pcapng file.
    (TESTS_DIR / "pcapng_bad_byte_order.pcapng").write_bytes(bytes([0x0A, 0x0D, 0x0D, 0x0A]) + b"\x00" * 28)


def build_pcapng_basic_sample():
    """Same three Modbus/TCP packets as build_modbus_sample(), wrapped in pcapng blocks
    (one Section Header Block, one Interface Description Block, three Enhanced Packet
    Blocks) instead of a classic pcap global header + records. Exercises the ordinary,
    by-far-most-common pcapng shape (what dumpcap/Wireshark/tshark write by default today)."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_req = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req

    reg_data = b"".join(struct.pack("!H", v) for v in range(10))
    mb_resp = struct.pack("!HHHBBB", 1, 0, 2 + 1 + len(reg_data), 1, 3, len(reg_data)) + reg_data
    tcp_resp = tcp_header(502, 51000, 2000, 1000 + len(mb_req), TCP_PSH | TCP_ACK, len(mb_resp)) + mb_resp
    ip_resp = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp_resp), 0x1001) + tcp_resp
    eth_resp = eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_resp

    mb_exc = struct.pack("!HHHBBB", 2, 0, 3, 1, 0x83, 0x02)
    tcp_exc = tcp_header(502, 51000, 3000, 1000, TCP_PSH | TCP_ACK, len(mb_exc)) + mb_exc
    ip_exc = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp_exc), 0x1002) + tcp_exc
    eth_exc = eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip_exc

    packets = [eth_req, eth_resp, eth_exc]
    data = pcapng_shb() + pcapng_idb()
    for i, pkt in enumerate(packets):
        ts_ticks = (1_700_000_000 + i) * 1_000_000  # microsecond ticks, matching the IDB's default resolution
        data += pcapng_epb(0, ts_ticks, pkt)
    (TESTS_DIR / "sample_modbus.pcapng").write_bytes(data)


def build_pcapng_nanosecond_sample():
    """A single interface declared with if_tsresol=9 (nanosecond resolution) and one packet,
    to exercise pcapng's per-interface timestamp resolution (something classic pcap's single
    global header can't express at all -- it picks one resolution for the whole file via its
    magic number)."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_req = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req

    ts_ticks = 1_700_000_000 * 1_000_000_000 + 123_456_789  # whole seconds + a distinctive nanosecond remainder
    data = pcapng_shb() + pcapng_idb(tsresol=9) + pcapng_epb(0, ts_ticks, eth_req)
    (TESTS_DIR / "sample_pcapng_nanosecond.pcapng").write_bytes(data)


def build_pcapng_implausible_tsresol_sample():
    """Exercises parse_if_tsresol_option's/fill_pcapng_timestamp's own bounds check
    (docs/reviews/2026-09-chatgpt-security-review-patch160.md's finding 2, pcap_reader.cpp):
    if_tsresol's low 7 bits are a full exponent (0-127) regardless of base, so a malicious value
    can ask for a units-per-second figure that doesn't fit in a uint64_t -- converting a double
    that large to uint64_t is undefined behavior, not just an inaccurate timestamp. Three
    interfaces here, each a distinct raw if_tsresol byte, and one ordinary packet per interface
    so a decode of this file completes normally either way (the fix falls back to the same
    microsecond default this function already uses for a malformed/truncated option, it doesn't
    reject the packet):
      - interface 0: tsresol=0xFF -- binary (high bit set), exponent 127 -- far past the
        exponent-63 boundary (2^64 already overflows uint64_t) -- must fall back to the default.
      - interface 1: tsresol=100 -- decimal (high bit clear), exponent 100 -- far past the
        exponent-19 boundary (10^20 already overflows uint64_t) -- must fall back to the default.
      - interface 2: tsresol=0xBF -- binary, exponent 63 -- exactly the boundary, still safely
        representable (2^63 fits) -- must NOT fall back; proves the boundary itself isn't
        miscategorized as malformed by an off-by-one."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_req = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req

    data = pcapng_shb()
    data += pcapng_idb(tsresol=0xFF)  # interface 0: implausible binary exponent (127)
    data += pcapng_idb(tsresol=100)  # interface 1: implausible decimal exponent (100)
    data += pcapng_idb(tsresol=0xBF)  # interface 2: exactly the safe binary boundary (63)
    for iface_id in range(3):
        data += pcapng_epb(iface_id, 1_700_000_000_000_000 + iface_id, eth_req)
    (TESTS_DIR / "sample_pcapng_implausible_tsresol.pcapng").write_bytes(data)


def build_pcapng_multi_interface_sample():
    """Two Interface Description Blocks (interface 0: Ethernet; interface 1: raw IP, no
    link-layer header) each with one packet referencing it, to prove per-packet/
    per-interface link type is honored -- a pcapng-only capability (classic pcap has exactly
    one link type for the whole file) that a capture merging two differently-configured NICs
    into one file (e.g. dumpcap capturing on both an Ethernet uplink and a raw tunnel
    interface at once) would actually need."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_pkt = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req  # interface 0: needs an Ethernet header stripped first

    mb_req2 = struct.pack("!HHHBB HH", 2, 0, 6, 1, 3, 0, 4)
    tcp_req2 = tcp_header(51100, 502, 5000, 6000, TCP_PSH | TCP_ACK, len(mb_req2)) + mb_req2
    raw_ip_pkt = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req2), 0x2000) + tcp_req2  # interface 1: IP header comes first, no Ethernet framing

    data = (
        pcapng_shb()
        + pcapng_idb(linktype=LINKTYPE_ETHERNET)
        + pcapng_idb(linktype=LINKTYPE_RAW, snaplen=65535)
        + pcapng_epb(0, 1_700_000_500 * 1_000_000, eth_pkt)
        + pcapng_epb(1, 1_700_000_501 * 1_000_000, raw_ip_pkt)
    )
    (TESTS_DIR / "sample_pcapng_multi_interface.pcapng").write_bytes(data)


def build_pcapng_simple_packet_block_sample():
    """A Simple Packet Block -- the minimal, timestamp-less, always-interface-0 packet
    record a handful of lightweight/embedded pcapng writers use instead of the Enhanced
    Packet Block every mainstream tool (dumpcap, Wireshark, tshark) actually writes."""
    mb_req = struct.pack("!HHHBB HH", 1, 0, 6, 1, 3, 0, 10)
    tcp_req = tcp_header(51000, 502, 1000, 2000, TCP_PSH | TCP_ACK, len(mb_req)) + mb_req
    ip_req = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_req), 0x1000) + tcp_req
    eth_req = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_req

    data = pcapng_shb() + pcapng_idb() + pcapng_spb(eth_req)
    (TESTS_DIR / "sample_pcapng_simple_packet_block.pcapng").write_bytes(data)


HARTIP_PORT = 5094


def hartip_message(message_type: int, message_id: int, body: bytes = b"", status: int = 0, txn: int = 1,
                    version: int = 1, msg_length_override: int = None) -> bytes:
    """The fixed 8-byte HART-IP header plus `body` -- see hartip.hpp's file header comment.
    `msg_length_override`, when given, writes a deliberately wrong MsgLength (for malformed-input
    fixtures) instead of the correct 8+len(body)."""
    total = msg_length_override if msg_length_override is not None else 8 + len(body)
    return struct.pack("!BBBBHH", version, message_type, message_id, status, txn, total) + body


def ascii6_to_char(v: int) -> str:
    return chr(v + 64) if v < 32 else chr(v)


def char_to_ascii6(ch: str) -> int:
    code = ord(ch)
    assert 32 <= code <= 95, f"HART packed-ASCII only covers ASCII 32-95, got {ch!r}"
    return code - 64 if code >= 64 else code


def pack_ascii(text: str) -> bytes:
    """Inverse of dissect_packAscii/decode_packed_ascii (hartip.cpp) -- 4 characters -> 3 bytes.
    `text`'s length must be a multiple of 4."""
    assert len(text) % 4 == 0
    out = bytearray()
    for i in range(0, len(text), 4):
        c0, c1, c2, c3 = (char_to_ascii6(ch) for ch in text[i : i + 4])
        b0 = (c0 << 2) | (c1 >> 4)
        b1 = ((c1 & 0x0F) << 4) | (c2 >> 2)
        b2 = ((c2 & 0x03) << 6) | c3
        out += bytes([b0 & 0xFF, b1 & 0xFF, b2 & 0xFF])
    return bytes(out)


def pass_through_body(frame_type: int, command: int, data: bytes = b"", is_long_address: bool = False,
                       address=0x01, expansion: bytes = b"", is_response=None, response_code: int = 0,
                       device_status: int = 0, preamble_count: int = 2, checksum="auto",
                       byte_count_override: int = None) -> bytes:
    """One tunneled classic-HART token-passing Data-Link PDU -- see hartip.hpp's Pass-Through
    section. `is_response` defaults to the same is_rsp derivation hartip.cpp uses (frame_type 6=ACK
    or 1=BACK); pass it explicitly only for a deliberately-inconsistent fixture. `address`, for a
    long address, must be exactly 5 bytes; for a short address, an int (masked to 0x3F on decode,
    so the raw byte doesn't need to be pre-masked here). `checksum` defaults to "auto", which
    computes the real longitudinal (XOR) checksum over Delimiter..Data inclusive -- exactly
    hartip.cpp's own decode_pass_through algorithm (see its "checksum_span_start" comment) -- so
    every packet built here decodes with hartip_checksum_valid=true unless a test wants otherwise.
    Pass an explicit int to force a specific (possibly deliberately wrong) byte, or None to omit
    the trailing Checksum byte entirely for a deliberately-truncated frame. A dedicated fixture,
    tests/sample_hartip_checksum.pcap, covers the valid/mismatch cases explicitly instead of any
    packet in this function's caller (build_hartip_sample) -- see CMakeLists.txt's own comment on
    hartip_checksum_valid_json for why: perturbing a checksum in this large, widely-shared fixture
    would ripple into many other tests' unrelated "notes": [] assertions."""
    if is_response is None:
        is_response = frame_type in (1, 6)
    delimiter = (frame_type & 0x07) | ((len(expansion) & 0x03) << 5) | (0x80 if is_long_address else 0x00)
    if is_long_address:
        assert len(address) == 5
        addr_bytes = address
    else:
        addr_bytes = bytes([address & 0xFF])
    header = bytes([delimiter]) + addr_bytes + expansion + bytes([command])
    payload = (bytes([response_code, device_status]) + data) if is_response else data
    byte_count = byte_count_override if byte_count_override is not None else len(payload)
    body = header + bytes([byte_count & 0xFF]) + payload
    if checksum == "auto":
        computed = 0
        for b in body:
            computed ^= b
        checksum = computed
    if checksum is not None:
        body += bytes([checksum & 0xFF])
    return bytes([0xFF] * preamble_count) + body


def hartip_udp_frame(payload: bytes, sport=HARTIP_PORT, dport=HARTIP_PORT, src_ip=None, dst_ip=None,
                      src_mac=None, dst_mac=None) -> bytes:
    src_mac = src_mac if src_mac is not None else HMI_MAC
    dst_mac = dst_mac if dst_mac is not None else PLC_MAC
    src_ip = src_ip if src_ip is not None else HMI_IP
    dst_ip = dst_ip if dst_ip is not None else PLC_IP
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x7100)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


OPCUA_PORT = 4840

# --- OPC UA Binary (UA-TCP / Secure Conversation) primitive encoders -----------------------
# Mirrors opcua.hpp's own "Primitive encoding" section byte-for-byte -- these are the inverse of
# the readers in opcua.cpp (read_string/read_bytestring/read_node_id/etc.), not independently
# reinvented, so a mistake here would show up as this decoder failing to parse its own fixture.

# 1601-01-01 -> 1970-01-01, in seconds -- see opcua.cpp's format_opcua_datetime.
OPCUA_FILETIME_EPOCH_OFFSET = 11644473600
# A fixed, deliberately unremarkable RequestHeader/ResponseHeader timestamp for every message
# below (except the two "sentinel" cases noted at their own call sites) -- reuses this file's own
# existing 1_700_006_000 unix-time convention (see build_hartip_sample) so every fixture in this
# repository anchors to the same rough point in time.
OPCUA_FIXED_TICKS = (1_700_006_000 + OPCUA_FILETIME_EPOCH_OFFSET) * 10_000_000


def opcua_string(s):
    """UA String: Int32 LE length prefix (-1 = null, distinct from 0 = present-but-empty), then
    that many UTF-8 bytes. `s=None` encodes the null form."""
    if s is None:
        return struct.pack("<i", -1)
    b = s.encode("utf-8")
    return struct.pack("<i", len(b)) + b


def opcua_bytestring(b):
    """UA ByteString -- same Int32-length-prefix shape as opcua_string, raw bytes instead of UTF-8."""
    if b is None:
        return struct.pack("<i", -1)
    return struct.pack("<i", len(b)) + b


def opcua_array_count(n):
    return struct.pack("<i", n)


def node_id_two_byte(identifier):
    """NodeId encoding 0x00 -- Identifier(1 byte); namespace implicitly 0."""
    assert 0 <= identifier <= 0xFF
    return bytes([0x00, identifier])


def node_id_four_byte(identifier, ns=0):
    """NodeId encoding 0x01 -- Namespace(1 byte) + Identifier(UInt16 LE). Used below for every
    service TypeId (all namespace 0, all well under 65536 -- see src/opcua.cpp's kServices table)."""
    assert 0 <= ns <= 0xFF and 0 <= identifier <= 0xFFFF
    return bytes([0x01, ns]) + struct.pack("<H", identifier)


def node_id_numeric(ns, identifier):
    """NodeId encoding 0x02 -- Namespace(UInt16 LE) + Identifier(UInt32 LE)."""
    return bytes([0x02]) + struct.pack("<H", ns) + struct.pack("<I", identifier)


def node_id_string(ns, s):
    """NodeId encoding 0x03 -- Namespace(UInt16 LE) + Identifier(String)."""
    return bytes([0x03]) + struct.pack("<H", ns) + opcua_string(s)


def null_node_id():
    """The conventional Null NodeId (Two-Byte encoding, identifier 0) -- used below everywhere a
    real session's AuthenticationToken would go (this decoder consumes, but never validates or
    correlates, that field -- see opcua.hpp's "Deliberately NOT implemented" section)."""
    return node_id_two_byte(0)


def opcua_localized_text(locale=None, text=None):
    """LocalizedText -- a 1-byte presence mask (0x01=Locale present, 0x02=Text present) then
    whichever of Locale(String)/Text(String) that mask flags."""
    mask = (0x01 if locale is not None else 0) | (0x02 if text is not None else 0)
    out = bytes([mask])
    if locale is not None:
        out += opcua_string(locale)
    if text is not None:
        out += opcua_string(text)
    return out


def opcua_extension_object(type_id_bytes, encoding=0x00, body=b""):
    """ExtensionObject -- TypeId(NodeId) + Encoding(1 byte) + [Int32 length + body, only when
    Encoding != 0x00]."""
    out = type_id_bytes + bytes([encoding])
    if encoding in (0x01, 0x02):
        out += struct.pack("<i", len(body)) + body
    return out


def opcua_extension_object_null():
    """The conventional "no AdditionalHeader" ExtensionObject every RequestHeader/ResponseHeader
    ends with below -- Null TypeId, Encoding 0x00 (no body)."""
    return opcua_extension_object(null_node_id(), 0x00)


def opcua_diagnostic_info_null():
    """The conventional "nothing set" DiagnosticInfo -- a single mask byte of 0 (no optional field
    present, so nothing recursive follows) -- see opcua.cpp's skip_diagnostic_info."""
    return bytes([0x00])


def opcua_signature_data(algorithm=None, signature=None):
    """SignatureData -- Algorithm(String) + Signature(ByteString); empty/null for every fixture
    below (this decoder only structurally skips it, never surfaces it -- see opcua.cpp)."""
    return opcua_string(algorithm) + opcua_bytestring(signature)


def opcua_application_description(app_uri, product_uri="", app_name_text=None, app_name_locale=None,
                                    app_type=0, gateway_uri=None, discovery_profile_uri=None,
                                    discovery_urls=()):
    body = opcua_string(app_uri)
    body += opcua_string(product_uri)
    body += opcua_localized_text(app_name_locale, app_name_text)
    body += struct.pack("<I", app_type)
    body += opcua_string(gateway_uri)
    body += opcua_string(discovery_profile_uri)
    body += opcua_array_count(len(discovery_urls))
    for u in discovery_urls:
        body += opcua_string(u)
    return body


def opcua_endpoint_description(endpoint_url, server_app_desc_bytes, server_cert=None, security_mode=1,
                                security_policy_uri="http://opcfoundation.org/UA/SecurityPolicy#None",
                                user_token_policies=(),
                                transport_profile_uri="http://opcfoundation.org/UA-Profile/Transport/uatcp-uasc-uabinary",
                                security_level=0):
    body = opcua_string(endpoint_url)
    body += server_app_desc_bytes
    body += opcua_bytestring(server_cert)
    body += struct.pack("<I", security_mode)
    body += opcua_string(security_policy_uri)
    body += opcua_array_count(len(user_token_policies))
    for policy_id, token_type, issued_token_type, issuer_endpoint_url, sec_policy in user_token_policies:
        body += opcua_string(policy_id)
        body += struct.pack("<I", token_type)
        body += opcua_string(issued_token_type)
        body += opcua_string(issuer_endpoint_url)
        body += opcua_string(sec_policy)
    body += opcua_string(transport_profile_uri)
    body += bytes([security_level])
    return body


def opcua_request_header(request_handle, auth_token_bytes=None, ts_ticks=None, return_diagnostics=0,
                          audit_entry_id=None, timeout_hint=0):
    """RequestHeader -- shared by every service (Tier 1 and Tier 2 alike). See
    opcua.cpp's read_request_header."""
    if auth_token_bytes is None:
        auth_token_bytes = null_node_id()
    if ts_ticks is None:
        ts_ticks = OPCUA_FIXED_TICKS
    body = auth_token_bytes
    body += struct.pack("<Q", ts_ticks & 0xFFFFFFFFFFFFFFFF)
    body += struct.pack("<I", request_handle)
    body += struct.pack("<I", return_diagnostics)
    body += opcua_string(audit_entry_id)
    body += struct.pack("<I", timeout_hint)
    body += opcua_extension_object_null()
    return body


def opcua_response_header(request_handle, service_result=0, ts_ticks=None, string_table=()):
    """ResponseHeader -- shared by every service. See opcua.cpp's read_response_header."""
    if ts_ticks is None:
        ts_ticks = OPCUA_FIXED_TICKS
    body = struct.pack("<Q", ts_ticks & 0xFFFFFFFFFFFFFFFF)
    body += struct.pack("<I", request_handle)
    body += struct.pack("<I", service_result)
    body += opcua_diagnostic_info_null()
    body += opcua_array_count(len(string_table))
    for s in string_table:
        body += opcua_string(s)
    body += opcua_extension_object_null()
    return body


# Identity token TypeIds (namespace 0, _Encoding_DefaultBinary) -- must match opcua.cpp's own
# kAnonymousIdentityToken/kUserNameIdentityToken/kX509IdentityToken/kIssuedIdentityToken constants.
OPCUA_ANONYMOUS_IDENTITY_TOKEN = 321
OPCUA_USERNAME_IDENTITY_TOKEN = 324
OPCUA_X509_IDENTITY_TOKEN = 327
OPCUA_ISSUED_IDENTITY_TOKEN = 940


def opcua_anonymous_identity_token_body(policy_id="anonymous"):
    return opcua_string(policy_id)


def opcua_username_identity_token_body(policy_id, username, password, encryption_algorithm=None):
    return (opcua_string(policy_id) + opcua_string(username) + opcua_bytestring(password) +
            opcua_string(encryption_algorithm))


def opcua_identity_token(type_id_numeric, body_bytes):
    return opcua_extension_object(node_id_four_byte(type_id_numeric), 0x01, body_bytes)


def opcua_service_message(service_id, header_bytes, params_bytes=b""):
    """A complete service-layer body: TypeId(NodeId, Four-Byte encoding, namespace 0) followed by
    that service's own RequestHeader/ResponseHeader and parameters -- see opcua.hpp's "Service
    identification" section. `service_id` is the service's own "_Encoding_DefaultBinary" NodeId, as
    cross-checked against the OPC Foundation's own NodeIds.csv in src/opcua.cpp's kServices table."""
    return node_id_four_byte(service_id) + header_bytes + params_bytes


def opcua_ua_tcp_header(message_type, chunk_type, total_size):
    assert len(message_type) == 3
    return message_type.encode("ascii") + chunk_type.encode("ascii") + struct.pack("<I", total_size)


def opcua_simple_message(message_type, body, chunk_type="F", total_size_override=None):
    """A UA Connection Protocol message (Hello/Acknowledge/Error/ReverseHello) -- 8-byte header
    directly followed by `body`, no SecureConversation framing."""
    total = total_size_override if total_size_override is not None else 8 + len(body)
    return opcua_ua_tcp_header(message_type, chunk_type, total) + body


def opcua_asymmetric_security_header(policy_uri, sender_cert=None, receiver_cert_thumbprint=None):
    return opcua_string(policy_uri) + opcua_bytestring(sender_cert) + opcua_bytestring(receiver_cert_thumbprint)


def opcua_sequence_header(sequence_number, request_id):
    return struct.pack("<II", sequence_number, request_id)


# --- Variant/DataValue encoders -- mirror src/opcua.cpp's format_scalar_value/format_variant/
# format_data_value byte-for-byte (the inverse of those readers, not independently reinvented --
# see this file's own "Primitive encoding" comment above for why that matters). Only the handful
# of BuiltInTypes the Read/Write/Call fixtures below actually use are implemented; this is a test
# fixture generator, not a general-purpose encoder.

def opcua_qualified_name(ns, name=None):
    """QualifiedName -- NamespaceIndex(UInt16 LE) + Name(String). See opcua.cpp's
    read_qualified_name_display."""
    return struct.pack("<H", ns) + opcua_string(name)


def opcua_read_value_id(node_id_bytes, attribute, index_range=None, data_encoding_ns=0,
                         data_encoding_name=None):
    """ReadValueId -- NodeId + AttributeId(UInt32 LE) + IndexRange(String) + DataEncoding
    (QualifiedName). Shared by ReadRequest's NodesToRead and (minus DataEncoding) WriteRequest's
    NodesToWrite -- see opcua.cpp's decode_read_request_params."""
    return (node_id_bytes + struct.pack("<I", attribute) + opcua_string(index_range) +
            opcua_qualified_name(data_encoding_ns, data_encoding_name))


def opcua_variant_int32(v):
    """Variant(scalar Int32) -- EncodingMask=6 (Int32, no array/dims bits) + Int32 LE."""
    return bytes([6]) + struct.pack("<i", v)


def opcua_variant_float(v):
    """Variant(scalar Float) -- EncodingMask=10 (Float) + IEEE-754 single LE."""
    return bytes([10]) + struct.pack("<f", v)


def opcua_variant_null():
    """Variant(Null) -- EncodingMask=0, no value follows."""
    return bytes([0x00])


def opcua_variant_string_array(strings):
    """Variant(array of String) -- EncodingMask=12|0x80 (String, array bit set) + Int32 ArrayLength
    + that many String elements, no ArrayDimensions."""
    body = bytes([12 | 0x80]) + struct.pack("<i", len(strings))
    for s in strings:
        body += opcua_string(s)
    return body


def opcua_variant_uint32_array(values, dims=None):
    """Variant(array of UInt32) -- EncodingMask=7|0x80 (UInt32, array bit), +0x40 when
    ArrayDimensions follows -- + Int32 ArrayLength + that many UInt32 LE elements + (if dims)
    Int32 count + that many Int32 LE dimension sizes."""
    mask = 7 | 0x80
    if dims:
        mask |= 0x40
    body = bytes([mask]) + struct.pack("<i", len(values))
    for v in values:
        body += struct.pack("<I", v)
    if dims:
        body += struct.pack("<i", len(dims))
        for d in dims:
            body += struct.pack("<i", d)
    return body


def opcua_data_value(variant_bytes=None, status=None, source_ts_ticks=None, source_picoseconds=None,
                      server_ts_ticks=None, server_picoseconds=None):
    """DataValue(variable) -- 1-byte EncodingMask + whichever fields it flags, in WIRE order:
    Value, StatusCode, SourceTimestamp, SourcePicoseconds, ServerTimestamp, ServerPicoseconds --
    NOT bit order (SourcePicoseconds's bit, 0x10, is numerically after ServerTimestamp's, 0x08, but
    precedes it on the wire). Mirrors opcua.cpp's format_data_value exactly -- see that function's
    own header comment for the cross-checked sourcing behind this field order."""
    mask = 0
    body = b""
    if variant_bytes is not None:
        mask |= 0x01
        body += variant_bytes
    if status is not None:
        mask |= 0x02
        body += struct.pack("<I", status)
    if source_ts_ticks is not None:
        mask |= 0x04
        body += struct.pack("<Q", source_ts_ticks & 0xFFFFFFFFFFFFFFFF)
    if source_picoseconds is not None:
        mask |= 0x10
        body += struct.pack("<H", source_picoseconds)
    if server_ts_ticks is not None:
        mask |= 0x08
        body += struct.pack("<Q", server_ts_ticks & 0xFFFFFFFFFFFFFFFF)
    if server_picoseconds is not None:
        mask |= 0x20
        body += struct.pack("<H", server_picoseconds)
    return bytes([mask]) + body


def opcua_opn_message(secure_channel_id, policy_uri, sequence_number, request_id, service_body,
                       chunk_type="F"):
    """An OpenSecureChannel (OPN) message: 8-byte header + SecureChannelId + Asymmetric Algorithm
    Security Header + SequenceHeader + service body."""
    inner = (struct.pack("<I", secure_channel_id) + opcua_asymmetric_security_header(policy_uri) +
             opcua_sequence_header(sequence_number, request_id) + service_body)
    return opcua_ua_tcp_header("OPN", chunk_type, 8 + len(inner)) + inner


def opcua_symmetric_message(message_type, secure_channel_id, token_id, sequence_number, request_id,
                             service_body, chunk_type="F"):
    """A CloseSecureChannel (CLO) or Message (MSG) chunk: 8-byte header + SecureChannelId +
    Symmetric Algorithm Security Header (TokenId only) + SequenceHeader + service body."""
    inner = (struct.pack("<I", secure_channel_id) + struct.pack("<I", token_id) +
             opcua_sequence_header(sequence_number, request_id) + service_body)
    return opcua_ua_tcp_header(message_type, chunk_type, 8 + len(inner)) + inner


def build_opcua_sample():
    """OPC UA Binary (UA-TCP / OPC UA Secure Conversation, TCP-only, conventionally port 4840) --
    the UA Connection Protocol handshake (Hello/Acknowledge), a full OpenSecureChannel/
    CloseSecureChannel round trip (SecurityPolicyUri "...#None", so the body stays plaintext-
    decodable -- see opcua.hpp's "Opportunistic MSG/OPN/CLO body decode" section), GetEndpoints/
    FindServers discovery, a CreateSession/ActivateSession/CloseSession lifecycle -- including,
    deliberately, an Anonymous ActivateSession AND a UserName/Password one with an empty
    EncryptionAlgorithm (the cleartext-credential-exposure "SECURITY FINDING" case opcua.hpp's own
    "Identity token decode" section documents) -- Tier-1 Read/Write/Call request/response pairs
    exercising the full Variant/DataValue value decode (a DataValue with all six optional fields
    set, a Float scalar, a Null Variant, and Variant arrays with and without ArrayDimensions), an
    entirely unrecognized service TypeId, an Error message, a
    ReverseHello (on its own, separately-directioned connection, per spec), a non-'F' (intermediate)
    chunk, a structurally-invalid NodeId shape (regression case for the inner try/catch that must
    still preserve the already-decoded channel/security/sequence fields), a genuinely truncated/
    incomplete capture (TCP-reassembly "buffering, waiting for more" path), port-independence (a
    valid exchange on a non-standard TCP port), and two OPC UA messages coalesced into one TCP
    segment. No real capture happens to be attributed for this fixture set yet at the time each
    packet was written -- see tests/real_captures/opcua/ATTRIBUTION.md (if present) or opcua.hpp's/
    opcua.cpp's own Validation paragraph for the current state of that search."""
    packets = []
    client_seq = [10000]
    server_seq = [20000]

    def add(from_client: bool, payload: bytes, sport=53000, dport=OPCUA_PORT, src_ip=None, dst_ip=None,
            src_mac=None, dst_mac=None):
        if from_client:
            src_port, dst_port = sport, dport
            s_ip, d_ip = src_ip or HMI_IP, dst_ip or PLC_IP
            s_mac, d_mac = src_mac or HMI_MAC, dst_mac or PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = dport, sport
            s_ip, d_ip = dst_ip or PLC_IP, src_ip or HMI_IP
            s_mac, d_mac = dst_mac or PLC_MAC, src_mac or HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(s_ip, d_ip, 6, len(tcp), 0x7300 + len(packets)) + tcp
        packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

    endpoint_url = "opc.tcp://192.168.1.10:4840/UA/PLC"
    none_policy = "http://opcfoundation.org/UA/SecurityPolicy#None"
    basic256_policy = "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"

    # 1) & 2) Hello (client->server, always the first message on a new connection) / Acknowledge.
    hel_body = (struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + opcua_string(endpoint_url))
    add(True, opcua_simple_message("HEL", hel_body))
    ack_body = struct.pack("<IIIII", 0, 65536, 65536, 0, 0)
    add(False, opcua_simple_message("ACK", ack_body))

    # 3) & 4) OpenSecureChannel request/response -- SecurityPolicyUri "...#None" and
    #    MessageSecurityMode "None", itself the audit finding this decoder's own file header
    #    comment's "Security posture is visible even when the body is not" section describes.
    #    SecureChannelId is 0 on the request (not yet assigned); the response assigns 500001.
    opn_req_params = (struct.pack("<III", 0, 0, 1) + opcua_bytestring(b"") + struct.pack("<I", 3_600_000))
    opn_req_body = opcua_service_message(446, opcua_request_header(1), opn_req_params)  # OpenSecureChannelRequest
    add(True, opcua_opn_message(0, none_policy, 1, 1, opn_req_body))

    channel_id = 500001
    token_id = 1
    opn_resp_params = (struct.pack("<III", 0, channel_id, token_id) +
                        struct.pack("<Q", OPCUA_FIXED_TICKS + 10_000_000) +  # +1s
                        struct.pack("<I", 3_600_000) + opcua_bytestring(bytes(range(4))))
    opn_resp_body = opcua_service_message(449, opcua_response_header(1, 0), opn_resp_params)  # OpenSecureChannelResponse
    add(False, opcua_opn_message(channel_id, none_policy, 1, 1, opn_resp_body))

    # 5) & 6) GetEndpoints request/response -- device/endpoint fingerprinting, this codebase's own
    #    OPC UA analog of BACnet I-Am / EtherNet/IP ListIdentity / HART-IP Read-Unique-Identifier.
    ge_req_params = opcua_string(endpoint_url) + opcua_array_count(0) + opcua_array_count(0)
    ge_req_body = opcua_service_message(428, opcua_request_header(2), ge_req_params)  # GetEndpointsRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 2, 2, ge_req_body))

    server_app_desc = opcua_application_description(
        "urn:conduitscope:sample-plc", "urn:conduitscope:conduitscope:sample-plc:product",
        app_name_text="ConduitScope Sample PLC", app_name_locale="en", app_type=0)
    endpoint_none = opcua_endpoint_description(endpoint_url, server_app_desc, security_mode=1,
                                                security_policy_uri=none_policy)
    endpoint_secure = opcua_endpoint_description(
        endpoint_url, server_app_desc, security_mode=3, security_policy_uri=basic256_policy,
        user_token_policies=[("username_basic256", 1, None, None, basic256_policy)])
    ge_resp_params = opcua_array_count(2) + endpoint_none + endpoint_secure
    ge_resp_body = opcua_service_message(431, opcua_response_header(2, 0), ge_resp_params)  # GetEndpointsResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 2, 2, ge_resp_body))

    # 7) & 8) FindServers request/response -- the second Tier-1 discovery service.
    fs_req_params = opcua_string(endpoint_url) + opcua_array_count(0) + opcua_array_count(0)
    fs_req_body = opcua_service_message(422, opcua_request_header(3), fs_req_params)  # FindServersRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 3, 3, fs_req_body))

    fs_resp_params = opcua_array_count(1) + server_app_desc
    fs_resp_body = opcua_service_message(425, opcua_response_header(3, 0), fs_resp_params)  # FindServersResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 3, 3, fs_resp_body))

    # 9) & 10) CreateSession request/response.
    client_app_desc = opcua_application_description(
        "urn:conduitscope:sample-hmi", app_name_text="ConduitScope Sample HMI", app_name_locale="en",
        app_type=1)
    cs_req_params = (client_app_desc + opcua_string(None) + opcua_string(endpoint_url) +
                      opcua_string("ConduitScope Sample Session") + opcua_bytestring(bytes(range(4))) +
                      opcua_bytestring(None) + struct.pack("<d", 1_200_000.0) + struct.pack("<I", 0))
    cs_req_body = opcua_service_message(461, opcua_request_header(4), cs_req_params)  # CreateSessionRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 4, 4, cs_req_body))

    session_id = node_id_numeric(1, 1001)
    session_auth_token = node_id_string(1, "sample-session-auth-token")
    cs_resp_params = (session_id + session_auth_token + struct.pack("<d", 1_200_000.0) +
                       opcua_bytestring(bytes(range(4, 8))) + opcua_bytestring(None) +
                       opcua_array_count(0) + opcua_array_count(0) + opcua_signature_data() +
                       struct.pack("<I", 0))
    cs_resp_body = opcua_service_message(464, opcua_response_header(4, 0), cs_resp_params)  # CreateSessionResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 4, 4, cs_resp_body))

    # 11) & 12) ActivateSession request/response -- Anonymous identity, the unremarkable case.
    as_anon_params = (opcua_signature_data() + opcua_array_count(0) + opcua_array_count(1) +
                       opcua_string("en") +
                       opcua_identity_token(OPCUA_ANONYMOUS_IDENTITY_TOKEN,
                                            opcua_anonymous_identity_token_body("anonymous")) +
                       opcua_signature_data())
    as_anon_req_body = opcua_service_message(467, opcua_request_header(5, auth_token_bytes=session_auth_token),
                                              as_anon_params)  # ActivateSessionRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 5, 5, as_anon_req_body))

    as_resp_params = opcua_bytestring(bytes(range(8, 12))) + opcua_array_count(1) + struct.pack("<I", 0) + \
        opcua_array_count(0)
    as_anon_resp_body = opcua_service_message(470, opcua_response_header(5, 0), as_resp_params)  # ActivateSessionResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 5, 5, as_anon_resp_body))

    # 13) & 14) ActivateSession request/response -- UserName/Password identity with an EMPTY
    #     EncryptionAlgorithm: per OPC 10000-4 7.41, this means the password was placed on the wire
    #     UNENCRYPTED -- a real, documented OPC UA security finding this decoder deliberately
    #     surfaces (see opcua.hpp's "Identity token decode" section and its own "SECURITY FINDING"
    #     note). Pairs with this same exchange's own OpenSecureChannel above having negotiated
    #     SecurityPolicy "...#None" in the first place -- the worst-case, and not hypothetical,
    #     combination.
    as_userpass_params = (
        opcua_signature_data() + opcua_array_count(0) + opcua_array_count(1) + opcua_string("en") +
        opcua_identity_token(
            OPCUA_USERNAME_IDENTITY_TOKEN,
            opcua_username_identity_token_body("username_basic256", "operator1", b"Sup3rSecret!1",
                                                encryption_algorithm=None)) +
        opcua_signature_data())
    as_userpass_req_body = opcua_service_message(
        467, opcua_request_header(6, auth_token_bytes=session_auth_token), as_userpass_params)
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 6, 6, as_userpass_req_body))

    as_userpass_resp_body = opcua_service_message(470, opcua_response_header(6, 0), as_resp_params)
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 6, 6, as_userpass_resp_body))

    # 15) & 16) Read request/response -- Tier 1 (promoted once Variant/DataValue value decoding
    #     existed to give NodesToRead/Results somewhere to go -- see opcua.cpp's own comment ahead
    #     of decode_read_request_params). One ReadValueId (ns=2;i=1001, attribute=Value,
    #     TimestampsToReturn=Both); the response's one DataValue deliberately sets ALL SIX optional
    #     fields (Value/Status/SourceTimestamp/SourcePicoseconds/ServerTimestamp/ServerPicoseconds)
    #     as a regression fixture for format_data_value's non-bit-numeric wire field order (Source-
    #     Picoseconds, mask bit 0x10, precedes ServerTimestamp, mask bit 0x08, on the wire).
    read_req_params = (struct.pack("<d", 5000.0) + struct.pack("<I", 2) + opcua_array_count(1) +
                        opcua_read_value_id(node_id_numeric(2, 1001), 13))  # attribute 13 = Value
    read_req_body = opcua_service_message(631, opcua_request_header(7, auth_token_bytes=session_auth_token),
                                           read_req_params)  # ReadRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 7, 7, read_req_body))

    read_resp_params = (opcua_array_count(1) +
                         opcua_data_value(opcua_variant_int32(42), status=0,
                                          source_ts_ticks=OPCUA_FIXED_TICKS, source_picoseconds=500,
                                          server_ts_ticks=OPCUA_FIXED_TICKS + 10_000_000,
                                          server_picoseconds=250) +
                         opcua_array_count(0))  # DiagnosticInfos
    read_resp_body = opcua_service_message(634, opcua_response_header(7, 0), read_resp_params)  # ReadResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 7, 7, read_resp_body))

    # 17) & 18) Write request/response -- one WriteValue (ns=2;i=1002, attribute=Value) carrying a
    #     DataValue with only its Value field set (a scalar Float, 3.5) -- the common "just write
    #     the value" case, unlike the Read response's every-field-set case above.
    write_req_params = (opcua_array_count(1) + node_id_numeric(2, 1002) + struct.pack("<I", 13) +
                         opcua_string(None) + opcua_data_value(opcua_variant_float(3.5)))
    write_req_body = opcua_service_message(673, opcua_request_header(8, auth_token_bytes=session_auth_token),
                                            write_req_params)  # WriteRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 8, 8, write_req_body))

    write_resp_params = opcua_array_count(1) + struct.pack("<I", 0) + opcua_array_count(0)  # 1x Good
    write_resp_body = opcua_service_message(676, opcua_response_header(8, 0), write_resp_params)  # WriteResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 8, 8, write_resp_body))

    # 19) & 20) Call request/response -- one CallMethodRequest (object ns=2;i=2000, method
    #     ns=2;i=2001) whose single input argument is itself a Variant array (String[3]); the
    #     response's single output argument is a Variant array (UInt32[2]) WITH ArrayDimensions
    #     set -- exercises format_variant's array-of-scalar path and its own ArrayDimensions tail
    #     in both directions, on top of format_data_value's coverage above.
    call_req_params = (opcua_array_count(1) + node_id_numeric(2, 2000) + node_id_numeric(2, 2001) +
                        opcua_array_count(1) + opcua_variant_string_array(["a", "bee", "c"]))
    call_req_body = opcua_service_message(712, opcua_request_header(9, auth_token_bytes=session_auth_token),
                                           call_req_params)  # CallRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 9, 9, call_req_body))

    call_resp_params = (opcua_array_count(1) + struct.pack("<I", 0) + opcua_array_count(0) +
                         opcua_array_count(0) + opcua_array_count(1) +
                         opcua_variant_uint32_array([10, 20], dims=[2]))
    call_resp_body = opcua_service_message(715, opcua_response_header(9, 0), call_resp_params)  # CallResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 9, 9, call_resp_body))

    # 21) & 22) Write request/response -- a Null Variant (EncodingMask 0x00, no value at all): the
    #     degenerate case format_variant's own `type_id == 0` branch exists for, distinct from a
    #     present-but-empty array or a present scalar.
    null_write_params = (opcua_array_count(1) + node_id_numeric(2, 1003) + struct.pack("<I", 13) +
                          opcua_string(None) + opcua_data_value(opcua_variant_null()))
    null_write_req_body = opcua_service_message(
        673, opcua_request_header(10, auth_token_bytes=session_auth_token), null_write_params)  # WriteRequest
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 10, 10, null_write_req_body))

    null_write_resp_params = opcua_array_count(1) + struct.pack("<I", 0) + opcua_array_count(0)
    null_write_resp_body = opcua_service_message(676, opcua_response_header(10, 0),
                                                  null_write_resp_params)  # WriteResponse
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 10, 10, null_write_resp_body))

    # 23) A service TypeId this decoder's dispatch table does not recognize AT ALL (Numeric
    #     encoding, namespace 0, identifier 999999 -- not one of the ~53 known values in
    #     src/opcua.cpp's kServices table) -- this decoder does not guess whether it's even shaped
    #     like a Request or Response, so the ENTIRE remainder is shown as raw hex.
    unknown_service_body = node_id_numeric(0, 999999) + bytes([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01])
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 11, 11, unknown_service_body))

    # 24) & 25) CloseSession request/response.
    cls_req_body = opcua_service_message(473, opcua_request_header(11, auth_token_bytes=session_auth_token),
                                          bytes([0x01]))  # CloseSessionRequest, DeleteSubscriptions=true
    add(True, opcua_symmetric_message("MSG", channel_id, token_id, 12, 12, cls_req_body))
    clsr_resp_body = opcua_service_message(476, opcua_response_header(11, 0))  # CloseSessionResponse, no params
    add(False, opcua_symmetric_message("MSG", channel_id, token_id, 12, 12, clsr_resp_body))

    # 26) CloseSecureChannel request -- no response by spec (mirrors EtherNet/IP's own
    #     UnRegisterSession -- see build_enip_sample -- the client just closes the TCP connection
    #     afterward).
    clo_body = opcua_service_message(452, opcua_request_header(12, auth_token_bytes=session_auth_token))
    add(True, opcua_symmetric_message("CLO", channel_id, token_id, 13, 13, clo_body))

    # 27) A standalone Error message (either direction; sent here as if the server were rejecting a
    #     new request on an already-closed channel) -- StatusCode + Reason, both decoded.
    err_body = struct.pack("<I", 0x80220000) + opcua_string("SecureChannel has been closed")  # BadSecureChannelIdInvalid
    add(False, opcua_simple_message("ERR", err_body))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_007_000 + i, i * 1000)

    # 28) ReverseHello -- used only for the "reverse connect" pattern, where the SERVER initiates
    #     the TCP connection to the Client (the opposite direction from every packet above) -- a
    #     dedicated, separately-directioned connection, per spec.
    rhe_body = opcua_string("urn:conduitscope:sample-plc") + opcua_string(endpoint_url)
    rhe_tcp = tcp_header(OPCUA_PORT, 53100, 30000, 0, TCP_PSH | TCP_ACK,
                          len(opcua_simple_message("RHE", rhe_body))) + opcua_simple_message("RHE", rhe_body)
    rhe_ip = ipv4_header(PLC_IP, HMI_IP, 6, len(rhe_tcp), 0x7400) + rhe_tcp
    data += pcap_record(eth_header(HMI_MAC, PLC_MAC, 0x0800) + rhe_ip, 1_700_007_100, 0)

    # 29) A non-'F' (intermediate) chunk -- fully decoded at the UA-TCP/SecureConversation HEADER
    #     level (MessageType/ChunkType/SecureChannelId/security header/sequence header), but its own
    #     body is always shown as raw hex regardless of what it might contain -- this decoder does
    #     not reassemble a message split across multiple chunks (see opcua.hpp's "Chunking" section).
    #     Uses a fresh channel/token pair (this flow's own OpenSecureChannel is not itself shown --
    #     only the chunking behavior is under test here).
    chunk_c_body = struct.pack("<I", 424242) + struct.pack("<I", 7) + opcua_sequence_header(1, 1) + \
        bytes([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08])
    chunk_c_msg = opcua_ua_tcp_header("MSG", "C", 8 + len(chunk_c_body)) + chunk_c_body
    data += pcap_record(
        eth_header(PLC_MAC, HMI_MAC, 0x0800) +
        ipv4_header(HMI_IP, PLC_IP, 6,
                    20 + len(tcp_header(53200, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(chunk_c_msg))) +
                    len(chunk_c_msg), 0x7500) +
        tcp_header(53200, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(chunk_c_msg)) + chunk_c_msg,
        1_700_007_200, 0)

    # 30) A structurally-invalid NodeId encoding byte (0x3F -- low 6 bits outside the valid 0x00-
    #     0x05 range) as a MSG service TypeId -- regression case for the inner try/catch in
    #     try_parse_opcua_message that must fall back to raw hex for JUST the service body while
    #     preserving the already-decoded SecureChannelId/security header/sequence header fields
    #     (see opcua.hpp's "Opportunistic MSG/OPN/CLO body decode" section).
    bad_nodeid_body = struct.pack("<I", 555555) + struct.pack("<I", 9) + opcua_sequence_header(2, 2) + \
        bytes([0x3F, 0xAA, 0xBB, 0xCC])
    bad_nodeid_msg = opcua_ua_tcp_header("MSG", "F", 8 + len(bad_nodeid_body)) + bad_nodeid_body
    data += pcap_record(
        eth_header(PLC_MAC, HMI_MAC, 0x0800) +
        ipv4_header(HMI_IP, PLC_IP, 6,
                    20 + len(tcp_header(53201, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(bad_nodeid_msg))) +
                    len(bad_nodeid_msg), 0x7501) +
        tcp_header(53201, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(bad_nodeid_msg)) + bad_nodeid_msg,
        1_700_007_201, 0)

    # 31) A genuinely truncated/incomplete capture: a Hello message declaring a MessageSize larger
    #     than the bytes actually sent, with no follow-up TCP segment -- this decoder's usual
    #     declared-length TCP reassembly (opcua_declared_length, mirroring hartip_declared_length/
    #     enip_declared_length) buffers it, reports protocol "tcp", and never resolves it (the same
    #     honest "buffering, waiting for more" posture this codebase already uses for every other
    #     declared-length protocol -- see reassemble_tcp_payload in decoder.cpp).
    truncated_hel = struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + opcua_string(endpoint_url)
    # Declares 100 bytes more than are actually sent.
    truncated_msg = opcua_ua_tcp_header("HEL", "F", 8 + len(truncated_hel) + 100) + truncated_hel
    data += pcap_record(
        eth_header(PLC_MAC, HMI_MAC, 0x0800) +
        ipv4_header(HMI_IP, PLC_IP, 6,
                    20 + len(tcp_header(53202, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(truncated_msg))) +
                    len(truncated_msg), 0x7502) +
        tcp_header(53202, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(truncated_msg)) + truncated_msg,
        1_700_007_202, 0)

    # 32) Port-independence: a structurally valid Hello/Acknowledge exchange on a TCP port other
    #     than 4840 -- still decoded, annotated as an unexpected port (mirrors BACnet's/HART-IP's/
    #     EtherNet/IP's own posture).
    alt_hel = opcua_simple_message("HEL", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) + opcua_string(endpoint_url))
    data += pcap_record(
        eth_header(PLC_MAC, HMI_MAC, 0x0800) +
        ipv4_header(HMI_IP, PLC_IP, 6,
                    20 + len(tcp_header(53210, 51005, 1, 1, TCP_PSH | TCP_ACK, len(alt_hel))) + len(alt_hel),
                    0x7503) +
        tcp_header(53210, 51005, 1, 1, TCP_PSH | TCP_ACK, len(alt_hel)) + alt_hel,
        1_700_007_203, 0)

    # 33) Two OPC UA messages coalesced into ONE TCP segment (sender/OS coalescing, mirrors HART-
    #     IP's/EtherNet/IP's own coalescing tests) -- a Hello immediately followed by an
    #     Acknowledge, both sent together as a single TCP payload, exercising the wire_length-
    #     driven "additional OPC UA message" loop in decoder.cpp.
    coalesced_hel = opcua_simple_message("HEL", struct.pack("<IIIII", 0, 65536, 65536, 0, 0) +
                                          opcua_string(endpoint_url))
    coalesced_ack = opcua_simple_message("ACK", struct.pack("<IIIII", 0, 65536, 65536, 0, 0))
    coalesced_payload = coalesced_hel + coalesced_ack
    data += pcap_record(
        eth_header(PLC_MAC, HMI_MAC, 0x0800) +
        ipv4_header(HMI_IP, PLC_IP, 6,
                    20 + len(tcp_header(53220, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(coalesced_payload))) +
                    len(coalesced_payload), 0x7504) +
        tcp_header(53220, OPCUA_PORT, 1, 1, TCP_PSH | TCP_ACK, len(coalesced_payload)) + coalesced_payload,
        1_700_007_204, 0)

    (TESTS_DIR / "sample_opcua.pcap").write_bytes(data)


def build_hartip_sample():
    """HART-IP (TCP or UDP, conventionally port 5094 for both) -- the fixed 8-byte header, its
    four session-control body shapes, and the tunneled classic-HART Pass-Through PDU -- see
    hartip.hpp's file header comment for the exact wire format each packet below exercises
    (cross-checked against Wireshark's own packet-hartip.c, plus the externally-sourced Response
    Code/Device Status/command-name material hartip.hpp documents). No real capture happens to be
    attributed for this fixture set yet at the time each packet was written -- see
    tests/real_captures/hartip/ATTRIBUTION.md (if present) or hartip.hpp's own Validation
    paragraph for the current state of that search."""
    packets = []

    def add(payload: bytes, **kw):
        packets.append(hartip_udp_frame(payload, **kw))

    # 1) & 2) Session Initiate request/response -- HostType + InactivityCloseTimer(seconds). Same
    #    body shape for both directions, per hartip.hpp.
    add(hartip_message(0, 0, struct.pack("!BI", 1, 180), txn=1))  # request, Primary Host
    add(hartip_message(1, 0, struct.pack("!BI", 0, 180), txn=1))  # response, Secondary Host

    # 3) & 4) Keep Alive request/response -- both expected EMPTY.
    add(hartip_message(0, 2, b"", txn=2))
    add(hartip_message(1, 2, b"", txn=2))

    # 5) Session Close request.
    add(hartip_message(0, 1, b"", txn=3))

    # 6) Error -- ErrorCode 0 (Session closed), one of the 3 values packet-hartip.c's own table
    #    defines.
    add(hartip_message(3, 1, bytes([0]), txn=4))

    # 7) NAK -- ErrorCode 2 (Service unavailable). MessageType 15 renders "NAK", distinct from
    #    MessageType 3's "Error" even though Wireshark's own UI collapses both to "Error" -- see
    #    hartip.hpp.
    add(hartip_message(15, 1, bytes([2]), txn=5))

    # 8) Error with an ErrorCode value outside the 3 packet-hartip.c defines -- "unknown(N)".
    add(hartip_message(3, 1, bytes([9]), txn=6))

    # 9) Error/NAK with a body length other than 1 -- shown as raw hex, not guessed at.
    add(hartip_message(3, 1, bytes([0, 1]), txn=7))

    # 10) Session Initiate with a body length other than 5 -- shown as raw hex.
    add(hartip_message(0, 0, bytes([1, 2, 3]), txn=8))

    # 11) Session Close with an unexpectedly non-empty body -- shown as raw hex with a note (the
    #     empty case is the expected, unremarkable one, so it gets no note at all -- see #5 above).
    add(hartip_message(0, 1, bytes([0xAA]), txn=9))

    # 12) & 13) Command 0 (Read Unique Identifier) request (empty data) / response, the 12-byte
    #     BASIC form -- Expansion Code, Expanded Device Type, Min. Request Preambles, Universal/
    #     Device/Software revisions, packed Hardware-Rev+Signaling byte, Flags, 3-byte Device ID.
    add(hartip_message(0, 3, pass_through_body(2, 0, b""), txn=10))
    cmd0_basic = struct.pack("!BHBBBBBB", 0xFE, 0x1234, 5, 7, 1, 3, (12 << 3) | 2, 0x80) + bytes([0x00, 0x11, 0x22])
    assert len(cmd0_basic) == 12
    add(hartip_message(1, 3, pass_through_body(6, 0, cmd0_basic, response_code=0), txn=10))

    # 14) Command 11 (Read Unique Identifier Associated with Tag) response, the 22-byte EXTENDED
    #     form -- adds Min. Response Preambles, Max. Device Variables, Configuration Change
    #     Counter, Extended Device Status, Manufacturer ID, Private-Label Distributor code, Device
    #     Profile.
    cmd11_ext = cmd0_basic + struct.pack("!BBHBHHB", 5, 24, 7, 0x00, 0x004B, 0x004B, 1)
    assert len(cmd11_ext) == 22
    add(hartip_message(1, 3, pass_through_body(6, 11, cmd11_ext, response_code=0), txn=11))

    # 15) Command 21 (Read Unique Identifier Associated with Long Tag) response, also 22-byte
    #     extended form, with the LONG address form this time (5 raw bytes).
    add(hartip_message(1, 3, pass_through_body(6, 21, cmd11_ext, is_long_address=True,
                                                 address=bytes([0x82, 0x00, 0x4B, 0x00, 0x01]),
                                                 response_code=0), txn=12))

    # 16) & 17) Command 1 (Read Primary Variable) request (empty)/response -- PV Units + PV(float).
    add(hartip_message(0, 3, pass_through_body(2, 1, b""), txn=13))
    cmd1_data = struct.pack("!Bf", 1, 72.5)  # units=1 (kPa, per common HART unit-code tables)
    add(hartip_message(1, 3, pass_through_body(6, 1, cmd1_data, response_code=0), txn=13))

    # 18) Command 2 (Read Loop Current and Percent of Range) response.
    cmd2_data = struct.pack("!ff", 12.5, 65.625)
    add(hartip_message(1, 3, pass_through_body(6, 2, cmd2_data, response_code=0), txn=14))

    # 19) Command 3 (Read Dynamic Variables and Loop Current) response -- loop current, then 4x
    #     [units + value] for PV/SV/TV/QV.
    cmd3_data = struct.pack("!f", 12.5) + b"".join(
        struct.pack("!Bf", u, v) for u, v in [(1, 72.5), (32, 15.0), (33, 25.0), (250, 0.0)]
    )
    assert len(cmd3_data) == 24
    add(hartip_message(1, 3, pass_through_body(6, 3, cmd3_data, response_code=0), txn=15))

    # 20) Command 6 (Write Polling Address) response -- identical shape to command 7.
    add(hartip_message(1, 3, pass_through_body(6, 6, bytes([3, 0]), response_code=0), txn=16))

    # 21) Command 7 (Read Loop Configuration) response.
    add(hartip_message(1, 3, pass_through_body(6, 7, bytes([0, 1]), response_code=0), txn=17))

    # 22) Command 8 (Read Dynamic Variable Classifications) response -- 4 raw class bytes.
    add(hartip_message(1, 3, pass_through_body(6, 8, bytes([1, 2, 2, 3]), response_code=0), txn=18))

    # 23) Command 9 (Read Device Variables with Status) response with 2 device-variable slots --
    #     Extended Device Status, then N x [code+classification+units+value+status], then a
    #     trailing 4-byte HART-format timestamp (here: raw=32*90000 -> 90.000s -> 00:01:30.000).
    cmd9_data = (bytes([0x00]) +
                 struct.pack("!BBBfB", 1, 1, 1, 72.5, 0x00) +
                 struct.pack("!BBBfB", 2, 1, 32, 15.0, 0x00) +
                 struct.pack("!I", 32 * 90000))
    add(hartip_message(1, 3, pass_through_body(6, 9, cmd9_data, response_code=0), txn=19))

    # 24) Command 12 (Read Message) response -- 24-byte packed-ASCII (32 chars).
    add(hartip_message(1, 3, pass_through_body(6, 12, pack_ascii("PUMP 1 HIGH VIBRATION ALARM     "[:32]),
                                                 response_code=0), txn=20))

    # 25) Command 17 (Write Message) request -- same 24-byte packed-ASCII shape.
    add(hartip_message(0, 3, pass_through_body(2, 17, pack_ascii(("CALIBRATED " + "2026").ljust(32)[:32])),
                        txn=21))

    # 26) Command 13 (Read Tag, Descriptor, Date) response -- Tag(6B packed, 8 chars) +
    #     Descriptor(12B packed, 16 chars) + Day/Month/Year(1 byte each).
    cmd13_data = pack_ascii("PT-101  ") + pack_ascii("PUMP DISCH PRESS") + bytes([15, 3, 126])  # 2026-03-15
    assert len(cmd13_data) == 21
    add(hartip_message(1, 3, pass_through_body(6, 13, cmd13_data, response_code=0), txn=22))

    # 27) Command 18 (Write Tag, Descriptor, Date) request -- same shape.
    add(hartip_message(0, 3, pass_through_body(2, 18, cmd13_data), txn=23))

    # 28) Command 14 (Read Primary Variable Transducer Information) response -- 3-byte S/N +
    #     Limit Units + Upper/Lower Limit(float) + Minimum Span(float).
    cmd14_data = bytes([0x01, 0x02, 0x03]) + struct.pack("!Bfff", 1, 500.0, -500.0, 1.0)
    assert len(cmd14_data) == 16
    add(hartip_message(1, 3, pass_through_body(6, 14, cmd14_data, response_code=0), txn=24))

    # 29) Command 15 (Read Device Information) response.
    cmd15_data = (bytes([0, 0, 1]) + struct.pack("!fff", 500.0, 0.0, 0.5) + bytes([0, 0, 0]))
    assert len(cmd15_data) == 18
    add(hartip_message(1, 3, pass_through_body(6, 15, cmd15_data, response_code=0), txn=25))

    # 30) Command 16 (Read Final Assembly Number) response -- 3-byte raw number.
    add(hartip_message(1, 3, pass_through_body(6, 16, bytes([0x00, 0x30, 0x39]), response_code=0), txn=26))

    # 31) Command 19 (Write Final Assembly Number) request -- same 3-byte shape.
    add(hartip_message(0, 3, pass_through_body(2, 19, bytes([0x00, 0x30, 0x39])), txn=27))

    # 32) Command 20 (Read Long Tag) response -- 32-byte PLAIN (unpacked) ASCII, unlike Tag's own
    #     packed-ASCII encoding.
    long_tag = "PUMP-101-DISCHARGE-PRESSURE".ljust(32)
    add(hartip_message(1, 3, pass_through_body(6, 20, long_tag.encode("ascii"), response_code=0), txn=28))

    # 33) Command 22 (Write Long Tag) request -- same shape.
    add(hartip_message(0, 3, pass_through_body(2, 22, long_tag.encode("ascii")), txn=29))

    # 34) Command 31 (extended-command-number wrapper) response, extended command 64386 (0xFB82) --
    #     a pairing directly confirmed in Wireshark's own source -- further decoded as command 203
    #     (Read Discrete Variables): Index of First DV(u16) + Number of DVs(1) + Extended Device
    #     Status(1) + timestamp(4) + N x [State(u16)+Status(1)].
    cmd203_data = (struct.pack("!HBB", 0, 2, 0x00) + struct.pack("!I", 32 * 5000) +
                   struct.pack("!HB", 1, 0x00) + struct.pack("!HB", 0, 0x00))
    add(hartip_message(1, 3, pass_through_body(6, 31, struct.pack("!H", 64386) + cmd203_data, response_code=0),
                        txn=30))

    # 35) Command 31 response with an extended command number OTHER than 64386 -- the extended-
    #     command-number field is still decoded, but the remaining data is left as raw hex (this
    #     decoder only knows the 64386->203 pairing).
    add(hartip_message(1, 3, pass_through_body(6, 31, struct.pack("!H", 1000) + bytes([0xDE, 0xAD, 0xBE]),
                                                 response_code=0), txn=31))

    # 36) Command 203 (Read Discrete Variables) as a STANDALONE command (not wrapped by 31) --
    #     structurally decoded, deliberately not given a top-level name -- see hartip.hpp.
    add(hartip_message(1, 3, pass_through_body(6, 203, cmd203_data, response_code=0), txn=32))

    # 37) Command 33 (Read Device Variables) response with 2 slots -- [code+units+value] each.
    cmd33_data = struct.pack("!Bbf", 1, 1, 72.5) + struct.pack("!Bbf", 2, 32, 15.0)
    add(hartip_message(1, 3, pass_through_body(6, 33, cmd33_data, response_code=0), txn=33))

    # 38) Command 38 (Reset Configuration Changed Flag) REQUEST -- no data at all (unlike every
    #     other command pair this decoder handles, the request and response shapes legitimately
    #     differ here).
    add(hartip_message(0, 3, pass_through_body(2, 38, b""), txn=34))

    # 39) Command 38 RESPONSE -- 2-byte Configuration Change Counter.
    add(hartip_message(1, 3, pass_through_body(6, 38, struct.pack("!H", 42), response_code=0), txn=34))

    # 40) Command 48 (Read Additional Device Status) response, the 6-byte MINIMAL form.
    add(hartip_message(1, 3, pass_through_body(6, 48, bytes([0, 0, 0, 0, 0, 0]), response_code=0), txn=35))

    # 41) Command 48 response, the 14-byte EXTENDED form.
    cmd48_ext = bytes([0, 0, 0, 0, 0, 0]) + bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
    assert len(cmd48_ext) == 14
    add(hartip_message(1, 3, pass_through_body(6, 48, cmd48_ext, response_code=0), txn=36))

    # 42) Command 77 (Send Command to Sub-Device) response -- I/O Card/Channel embedded-command
    #     relay wrapping an embedded command 1 (Read Primary Variable) response, SHORT embedded
    #     Address -- exercises the full recursive decode via decode_nested_command (hartip.cpp):
    #     the embedded command's own PV value is decoded, not just shown as raw bytes.
    cmd77_emb_byte_count = 2 + len(cmd1_data)  # embedded Response Code + Device Status + Data
    cmd77_resp_short = bytes([3, 1, 0x00, 0x07, 1, cmd77_emb_byte_count, 0, 0]) + cmd1_data
    add(hartip_message(1, 3, pass_through_body(6, 77, cmd77_resp_short, response_code=0), txn=60))

    # 43) Command 77 response, same embedded command 1, but a LONG (5-byte, Unique ID) embedded
    #     Address instead (Embedded Command Delimiter bit 7 set) -- exercises the embedded
    #     Address's own 1-vs-5-byte branch independently of the outer Pass-Through frame's own
    #     Address (which is short in every fixture in this file).
    cmd77_resp_long = (bytes([3, 1, 0x80, 0x1E, 0xAA, 0xBB, 0xCC, 0xDD, 1, cmd77_emb_byte_count, 0, 0]) +
                        cmd1_data)
    add(hartip_message(1, 3, pass_through_body(6, 77, cmd77_resp_long, response_code=0), txn=61))

    # 44) Command 77 REQUEST -- the request shape genuinely differs from the response shape above
    #     (TX Preamble Count present, Response Code/Device Status absent, per hartip.hpp) --
    #     relays an embedded command 1 REQUEST, whose own data is empty (Read Primary Variable
    #     takes no request parameters), so nothing decodes past the embedded command number itself.
    cmd77_req = bytes([3, 1, 2, 0x00, 0x07, 1, 0])
    add(hartip_message(0, 3, pass_through_body(2, 77, cmd77_req), txn=62))

    # 45) Command 77 response, truncated before its Embedded Command Number byte (only IO
    #     Card/Channel/Embedded Command Delimiter/Address present) -- exercises the "partial fill,
    #     note where it stopped" truncation posture decode_cmd_77's own header comment documents,
    #     distinct from a structurally-unparseable command falling back to raw hex.
    add(hartip_message(1, 3, pass_through_body(6, 77, bytes([1, 0, 0, 5]), response_code=0), txn=37))

    # 46) Command 178 response -- a BATCH/aggregate wrapper with 2 entries: entry 0 is a recognized
    #     embedded command 1 (Read Primary Variable, decoded recursively, same reuse command 77
    #     above uses); entry 1 is command 99, entirely outside this decoder's dispatch table, shown
    #     as raw hex with its own note (command 178 itself has no top-level name asserted -- see
    #     hartip.hpp).
    cmd178_entry0 = struct.pack("!H", 1) + bytes([1 + len(cmd1_data), 0]) + cmd1_data
    cmd178_entry1 = struct.pack("!H", 99) + bytes([1 + 2, 0]) + bytes([0xAA, 0xBB])
    cmd178_data = bytes([2]) + cmd178_entry0 + cmd178_entry1
    add(hartip_message(1, 3, pass_through_body(6, 178, cmd178_data, response_code=0), txn=63))

    # 47) Command 178 response with entry 0's own Command Byte Count malformed (0, smaller than
    #     the 1 Response Code byte it must include) -- the command as a whole is still
    #     "recognized" (Number of Commands is shown) but entry 0's own Response Code/Data is not
    #     decoded, and any remaining declared entries are skipped -- same "partial fill" posture
    #     as #45 above.
    add(hartip_message(1, 3, pass_through_body(6, 178, bytes([2, 0, 1, 0, 2]), response_code=0), txn=38))

    # 48) A command number entirely outside this decoder's dispatch table (99) -- no name at all,
    #     raw hex, a different note wording than #46/#47 above.
    add(hartip_message(1, 3, pass_through_body(6, 99, bytes([0xAA, 0xBB]), response_code=0), txn=39))

    # 49) A recognized command (1, Read Primary Variable) whose response data length does NOT
    #     match what this decoder expects (4 bytes instead of 5) -- named, but not value-decoded,
    #     shown as raw hex with a "does not match the byte layout" note (distinct wording from #44).
    add(hartip_message(1, 3, pass_through_body(6, 1, bytes([1, 2, 3, 4]), response_code=0), txn=40))

    # 50) A response with the communication-error bit (bit 7) set in its Response Code --
    #     0xC8 = 0x80 (comm-error) | 0x40 (vertical-parity-error) | 0x08 (longitudinal-parity-error).
    add(hartip_message(1, 3, pass_through_body(6, 2, cmd2_data, response_code=0xC8), txn=41))

    # 51) A response whose Response Code is a "single-definition" code OTHER than Success (32,
    #     Busy) -- exercises the response_code_name lookup table beyond the all-zero default.
    add(hartip_message(1, 3, pass_through_body(6, 2, cmd2_data, response_code=32), txn=42))

    # 52) A response whose Response Code (100) is command-specific and NOT in the single-definition
    #     table -- "command-specific response code 100 (meaning depends on which command produced
    #     it -- not decoded)".
    add(hartip_message(1, 3, pass_through_body(6, 2, cmd2_data, response_code=100), txn=43))

    # 53) A response with every Device Status bit set (0xFF) -- exercises all 8 named flags at once.
    add(hartip_message(1, 3, pass_through_body(6, 1, cmd1_data, response_code=0, device_status=0xFF), txn=44))

    # 54) BACK (Burst Frame, frame_type=1) -- also an is_response frame per hartip.hpp's own
    #     is_rsp derivation, carrying an unsolicited command 2 reading.
    add(hartip_message(1, 3, pass_through_body(1, 2, cmd2_data, response_code=0), txn=45))

    # 55) Byte Count smaller than the Response Code/Device Status bytes it must include (a
    #     malformed response claiming byte_count=1 while still being a response, which needs at
    #     least 2) -- Data length is treated as 0 rather than underflowing.
    add(hartip_message(1, 3, pass_through_body(6, 2, b"", response_code=0, byte_count_override=1), txn=46))

    # 56) Pass-Through body truncated before its trailing Checksum byte (byte_count correct, but
    #     the checksum byte itself is simply missing from the wire).
    truncated_pt = pass_through_body(6, 2, cmd2_data, response_code=0, checksum=None)
    add(hartip_message(1, 3, truncated_pt, txn=47))

    # 57) Pass-Through body truncated before its Command byte entirely (just preambles + delimiter
    #     + address).
    add(hartip_message(0, 3, bytes([0xFF, 0xFF, 0x02, 0x01]), txn=48))

    # 58) Trailing byte(s) remain after the Checksum -- unexpected, not decoded.
    add(hartip_message(1, 3, pass_through_body(6, 2, cmd2_data, response_code=0) + bytes([0x00, 0x00]), txn=49))

    # 59) Port-independence: a structurally valid HART-IP message on a UDP port other than 5094 --
    #     still decoded, annotated as an unexpected port (mirrors BACnet's/CIP I/O's own posture).
    add(hartip_message(0, 2, b"", txn=50), sport=51005, dport=51006)

    # 60) MsgLength implausibly small (< 8, the header's own fixed size) -- this decoder's own
    #     third, self-added plausibility check beyond Wireshark's own two-byte gate -- falls
    #     through to a generic "udp" groundwork report rather than being misdetected as HART-IP.
    add(hartip_message(0, 0, struct.pack("!BI", 1, 180), txn=51, msg_length_override=5))

    # 61) MessageType/MessageID values outside the gate's 5/4-value sets -- also falls through to
    #     a generic "udp" report.
    add(hartip_message(99, 0, b"", txn=52))

    # --- HART-IP over TCP: the same port (5094) serves both transports -- see hartip.hpp. Also
    # exercises two HART-IP messages coalesced into one TCP segment (mirrors EtherNet/IP's own
    # coalescing test), via the wire_length-driven loop in decoder.cpp.
    client_seq = [3000]
    server_seq = [4000]

    def add_tcp(from_client: bool, payload: bytes, sport=52010, dport=HARTIP_PORT):
        if from_client:
            src_port, dst_port = sport, dport
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = dport, sport
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x7200 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # 62), 63) & 64) KNOWN, ACCEPTED, DOCUMENTED COLLISION -- see the dispatch-order comment on
    #     HART-IP's own TCP declared-length check in decoder.cpp's reassemble_tcp_payload, and
    #     hartip.hpp's LIMITATIONS-relevant note. A HART-IP Session Initiate message's own header
    #     (MessageID 0, Status 0 -- the only value ever observed in this decoder's own research)
    #     reads as a plausible Modbus/TCP MBAP header (protocol-id==0, from bytes 2-3; a small,
    #     plausible mbap_length, from bytes 4-5 -- HART-IP's own TransactionID field). Unlike the
    #     IEC104-vs-Modbus collision this codebase already resolved by reordering (see
    #     try_parse_iec104_apci's header comment), THIS one is not resolved -- reordering HART-IP
    #     ahead of Modbus was tried while scoping this feature and measurably regressed this
    #     project's own existing Modbus/S7comm test corpus (HART-IP's own two-byte gate is weak
    #     enough that ~2% of ordinary Modbus/TCP traffic with a non-zero unit ID also satisfies it),
    #     so it was reverted. The result: every packet on this TCP flow, from the very first
    #     Session Initiate request onward, is misclassified as a Modbus/TCP PDU "buffering,
    #     waiting for more" bytes that will never arrive (the two coalesced Keep Alive messages
    #     that follow just add more buffered bytes to the same phantom wait, never resolving it) --
    #     this flow uses its own dedicated TCP ports specifically so this documented, permanent
    #     misclassification doesn't contaminate the genuinely-working TCP Pass-Through round trip
    #     in #65/#66 below (a different flow, unaffected -- Pass-Through's own MessageID 3 does not
    #     produce a protocol-id==0 collision).
    add_tcp(True, hartip_message(0, 0, struct.pack("!BI", 1, 60), txn=100))
    add_tcp(False, hartip_message(1, 0, struct.pack("!BI", 0, 60), txn=100))
    add_tcp(True, hartip_message(0, 2, b"", txn=101) + hartip_message(0, 2, b"", txn=102))

    # 65) & 66) A Pass-Through command 1 request/response pair over TCP, on a DIFFERENT flow using
    #     a non-standard TCP port (to also exercise the "not a configured/standard HART-IP port"
    #     note on the TCP path) -- demonstrates genuine, working HART-IP-over-TCP decoding.
    #     Pass-Through's own MessageID (3) never produces the protocol-id==0 collision above, so
    #     this flow is entirely unaffected by it.
    add_tcp(True, hartip_message(0, 3, pass_through_body(2, 1, b""), txn=103), sport=52099, dport=15094)
    add_tcp(False, hartip_message(1, 3, pass_through_body(6, 1, cmd1_data, response_code=0), txn=103),
            sport=52099, dport=15094)

    # 67) Two Keep Alive messages coalesced into ONE TCP segment (sender/OS coalescing), on YET
    #     ANOTHER fresh flow (Keep Alive's own MessageID, 2, does not collide with Modbus's
    #     protocol-id==0 check the way Session Initiate's MessageID 0 does -- see #58-60 above) --
    #     exercises the wire_length-driven "additional HART-IP message" loop in decoder.cpp with a
    #     genuinely successful decode.
    add_tcp(True, hartip_message(0, 2, b"", txn=200) + hartip_message(0, 2, b"", txn=201),
            sport=52150, dport=HARTIP_PORT)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_006_000 + i, i * 1000)
    (TESTS_DIR / "sample_hartip.pcap").write_bytes(data)


def mqtt_vbi(n: int) -> bytes:
    out = b""
    while True:
        b = n % 128
        n //= 128
        if n > 0:
            b |= 0x80
        out += bytes([b])
        if n == 0:
            break
    return out


def mqtt_str(s: str) -> bytes:
    b = s.encode("utf-8")
    return struct.pack(">H", len(b)) + b


def mqtt_bin(b: bytes) -> bytes:
    return struct.pack(">H", len(b)) + b


def mqtt_packet(packet_type: int, flags: int, body: bytes = b"") -> bytes:
    return bytes([(packet_type << 4) | flags]) + mqtt_vbi(len(body)) + body


def mqtt_property_byte(prop_id: int, value: int) -> bytes: return mqtt_vbi(prop_id) + bytes([value])
def mqtt_property_u16(prop_id: int, value: int) -> bytes: return mqtt_vbi(prop_id) + struct.pack(">H", value)
def mqtt_property_u32(prop_id: int, value: int) -> bytes: return mqtt_vbi(prop_id) + struct.pack(">I", value)
def mqtt_property_vbi(prop_id: int, value: int) -> bytes: return mqtt_vbi(prop_id) + mqtt_vbi(value)
def mqtt_property_str(prop_id: int, value: str) -> bytes: return mqtt_vbi(prop_id) + mqtt_str(value)
def mqtt_property_bin(prop_id: int, value: bytes) -> bytes: return mqtt_vbi(prop_id) + mqtt_bin(value)


def mqtt_property_strpair(prop_id: int, key: str, value: str) -> bytes:
    return mqtt_vbi(prop_id) + mqtt_str(key) + mqtt_str(value)


def mqtt_properties(*entries: bytes) -> bytes:
    body = b"".join(entries)
    return mqtt_vbi(len(body)) + body


# Sparkplug B -- minimal protobuf wire-format encoder (varint + length-delimited + fixed32/64),
# matching src/mqtt.cpp's own hand-rolled decoder field-for-field (org.eclipse.tahu.protobuf.Payload,
# fetched raw from github.com/eclipse-tahu/tahu/blob/master/sparkplug_b/sparkplug_b.proto).

def pb_varint(n: int) -> bytes:
    if n < 0:
        n &= 0xFFFFFFFFFFFFFFFF
    out = b""
    while True:
        b = n & 0x7F
        n >>= 7
        if n:
            out += bytes([b | 0x80])
        else:
            out += bytes([b])
            break
    return out


def pb_tag(field: int, wire_type: int) -> bytes: return pb_varint((field << 3) | wire_type)
def pb_bytes_field(field: int, data: bytes) -> bytes: return pb_tag(field, 2) + pb_varint(len(data)) + data
def pb_varint_field(field: int, value: int) -> bytes: return pb_tag(field, 0) + pb_varint(value)


def pb_fixed32_field(field: int, raw: bytes) -> bytes:
    assert len(raw) == 4
    return pb_tag(field, 5) + raw


def pb_fixed64_field(field: int, raw: bytes) -> bytes:
    assert len(raw) == 8
    return pb_tag(field, 1) + raw


SPARKPLUG_DATATYPES = {
    "Int8": 1, "Int16": 2, "Int32": 3, "Int64": 4, "UInt8": 5, "UInt16": 6, "UInt32": 7, "UInt64": 8,
    "Float": 9, "Double": 10, "Boolean": 11, "String": 12, "DateTime": 13, "Text": 14, "UUID": 15,
    "Bytes": 17,
}


def sparkplug_metric(name, datatype, value=None, alias=None, timestamp=None, is_null=False,
                      is_historical=False) -> bytes:
    dt = SPARKPLUG_DATATYPES[datatype]
    out = pb_bytes_field(1, name.encode("utf-8"))
    if alias is not None:
        out += pb_varint_field(2, alias)
    if timestamp is not None:
        out += pb_varint_field(3, timestamp)
    out += pb_varint_field(4, dt)
    if is_historical:
        out += pb_varint_field(5, 1)
    if is_null:
        out += pb_varint_field(7, 1)
        return out
    if datatype in ("Int8", "Int16", "Int32", "UInt8", "UInt16", "UInt32"):
        # Signed types are stored as their raw two's-complement bit pattern reinterpreted as
        # unsigned in the uint32 int_value field -- see mqtt.hpp's own documented rationale (a
        # negative value here deliberately produces the inefficient 5-byte varint real Sparkplug
        # traffic is known for, exercising that exact decode path).
        raw = (value & 0xFFFFFFFF) if value < 0 else value
        out += pb_varint_field(10, raw)
    elif datatype in ("Int64", "UInt64"):
        raw = (value & 0xFFFFFFFFFFFFFFFF) if value < 0 else value
        out += pb_varint_field(11, raw)
    elif datatype == "Float":
        out += pb_fixed32_field(12, struct.pack("<f", value))
    elif datatype == "Double":
        out += pb_fixed64_field(13, struct.pack("<d", value))
    elif datatype == "Boolean":
        out += pb_varint_field(14, 1 if value else 0)
    elif datatype in ("String", "Text", "UUID"):
        out += pb_bytes_field(15, value.encode("utf-8"))
    elif datatype == "DateTime":
        out += pb_varint_field(11, value)  # long_value, milliseconds since the Unix epoch
    elif datatype == "Bytes":
        out += pb_bytes_field(16, value)
    else:
        raise ValueError("unhandled datatype in sample fixture builder: " + datatype)
    return out


def sparkplug_payload(metrics, timestamp=None, seq=None, uuid=None, body=None) -> bytes:
    out = b""
    if timestamp is not None:
        out += pb_varint_field(1, timestamp)
    for m in metrics:
        out += pb_bytes_field(2, m)
    if seq is not None:
        out += pb_varint_field(3, seq)
    if uuid is not None:
        out += pb_bytes_field(4, uuid.encode("utf-8"))
    if body is not None:
        out += pb_bytes_field(5, body)
    return out


def build_mqtt_sample():
    """MQTT v3.1.1 and v5.0, plus Sparkplug B on top of PUBLISH -- see mqtt.hpp's file header
    comment for the full byte layout and decode scope each packet below exercises: a full v3.1.1
    CONNECT/CONNACK/PUBLISH(qos0/1/2)/SUBSCRIBE/UNSUBSCRIBE/PINGREQ/DISCONNECT lifecycle including a
    cleartext Username/Password CONNECT (a genuine, directly actionable OT-security finding this
    decoder deliberately surfaces -- see mqtt.hpp's own reasoning); a full v5.0 lifecycle exercising
    Properties on CONNECT/CONNACK/PUBLISH/PUBACK/SUBSCRIBE/SUBACK/UNSUBSCRIBE/UNSUBACK/AUTH/
    DISCONNECT; a Sparkplug B flow (NBIRTH/DBIRTH/NDATA/DDATA/DDEATH plus the separate STATE
    namespace) covering every scalar DataType this decoder decodes, a negative-Int32 metric (the
    documented sign-handling gotcha), a null-valued metric, a Bytes-typed (Tier 2) metric, and a
    genuinely malformed Sparkplug payload; two flows exercising the SUBSCRIBE/UNSUBSCRIBE version-
    disambiguation HEURISTIC (no CONNECT ever seen on either flow in this capture) in both its
    v3.1.1-shape and v5-shape forms; a PUBLISH split mid-message across two TCP segments (
    Decoder::reassemble_tcp_payload, driven by mqtt_declared_length); three small packets (PINGREQ +
    PUBACK + PINGREQ) coalesced by the sender/OS into one TCP segment; an invalid QoS=3 PUBLISH; a
    CONNECT-shaped byte whose Protocol Name is neither "MQTT" nor "MQIsdp" (a structural-gate
    REJECTION regression case -- this packet must NOT be recognized as MQTT at all); an unrecognized
    MQTT5 Property Identifier (decode_properties' own contained-failure fallback); and a genuinely
    truncated/incomplete final packet (the TCP-reassembly "buffering, waiting for more" path,
    mirroring sample_opcua.pcap's own equivalent case). No real capture happens to be attributed for
    this fixture set yet at the time each packet was written -- see tests/real_captures/mqtt/
    ATTRIBUTION.md (if present) for the current state of that search."""
    packets = []

    def make_flow(sport, dport=1883, src_ip=HMI_IP, dst_ip=PLC_IP, src_mac=HMI_MAC, dst_mac=PLC_MAC,
                  ident_start=0x9000):
        state = {"cseq": 10000, "sseq": 20000, "ident": ident_start}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, dport
                s_ip, d_ip = src_ip, dst_ip
                s_mac, d_mac = src_mac, dst_mac
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = dport, sport
                s_ip, d_ip = dst_ip, src_ip
                s_mac, d_mac = dst_mac, src_mac
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), state["ident"] & 0xFFFF) + tcp
            state["ident"] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    # ---------------------------------------------------------------------------------------------
    # Flow A: full v3.1.1 lifecycle, port 61000.
    # ---------------------------------------------------------------------------------------------
    a = make_flow(61000)
    connect_body = (mqtt_str("MQTT") + bytes([4]) + bytes([0xC6]) + struct.pack(">H", 60) +
                    mqtt_str("plc1-hmi") + mqtt_str("devices/plc1/lwt") + mqtt_bin(b"offline") +
                    mqtt_str("admin") + mqtt_bin(b"Passw0rd!"))
    a(True, mqtt_packet(1, 0, connect_body))  # CONNECT: will(qos1,retain0)+username+password
    a(False, mqtt_packet(2, 0, bytes([0x00, 0x00])))  # CONNACK: session present=0, accepted

    a(True, mqtt_packet(3, 0x01, mqtt_str("devices/plc1/status") + b"online"))  # PUBLISH qos0 retain

    a(True, mqtt_packet(3, 0x02, mqtt_str("devices/plc1/temp") + struct.pack(">H", 1) + b"72.3"))  # qos1
    a(False, mqtt_packet(4, 0, struct.pack(">H", 1)))  # PUBACK id=1

    a(True, mqtt_packet(3, 0x04,
                         mqtt_str("devices/plc1/alarm") + struct.pack(">H", 2) + b"HIGH_PRESSURE"))  # qos2
    a(False, mqtt_packet(5, 0, struct.pack(">H", 2)))  # PUBREC id=2
    a(True, mqtt_packet(6, 0x02, struct.pack(">H", 2)))  # PUBREL id=2
    a(False, mqtt_packet(7, 0, struct.pack(">H", 2)))  # PUBCOMP id=2

    sub_body = (struct.pack(">H", 3) + mqtt_str("devices/+/status") + bytes([0]) +
                mqtt_str("devices/plc1/#") + bytes([1]))
    a(True, mqtt_packet(8, 0x02, sub_body))  # SUBSCRIBE id=3, 2 filters
    a(False, mqtt_packet(9, 0, struct.pack(">H", 3) + bytes([0, 1])))  # SUBACK id=3

    unsub_body = struct.pack(">H", 4) + mqtt_str("devices/+/status")
    a(True, mqtt_packet(10, 0x02, unsub_body))  # UNSUBSCRIBE id=4
    a(False, mqtt_packet(11, 0, struct.pack(">H", 4)))  # UNSUBACK id=4 (v3.1.1: packet id only)

    a(True, mqtt_packet(12, 0))  # PINGREQ
    a(False, mqtt_packet(13, 0))  # PINGRESP
    a(True, mqtt_packet(14, 0))  # DISCONNECT (v3.1.1: Remaining Length always 0)

    # ---------------------------------------------------------------------------------------------
    # Flow B: full v5.0 lifecycle exercising Properties throughout, port 62000.
    # ---------------------------------------------------------------------------------------------
    b = make_flow(62000)
    connect_props = mqtt_properties(
        mqtt_property_u32(17, 3600),  # SessionExpiryInterval
        mqtt_property_u16(33, 20),    # ReceiveMaximum
        mqtt_property_strpair(38, "app", "conduitscope-test"),  # UserProperty
    )
    will_props = mqtt_properties(mqtt_property_u32(24, 5))  # WillDelayInterval
    connect_v5_body = (mqtt_str("MQTT") + bytes([5]) + bytes([0xC6]) + struct.pack(">H", 30) +
                        connect_props + mqtt_str("plc2-controller") + will_props +
                        mqtt_str("devices/plc2/lwt") + mqtt_bin(b"offline") +
                        mqtt_str("svc-account") + mqtt_bin(b"hunter2v5"))
    b(True, mqtt_packet(1, 0, connect_v5_body))
    connack_props = mqtt_properties(mqtt_property_u16(19, 60), mqtt_property_u16(34, 10))
    b(False, mqtt_packet(2, 0, bytes([0x00, 0x00]) + connack_props))

    pub_props = mqtt_properties(mqtt_property_byte(1, 1), mqtt_property_str(3, "text/plain"))
    b(True, mqtt_packet(3, 0x02, mqtt_str("devices/plc2/temp") + struct.pack(">H", 1) + pub_props + b"68.9"))
    b(False, mqtt_packet(4, 0, struct.pack(">H", 1) + bytes([0x00])))  # PUBACK v5: reason, no properties

    sub_v5_props = mqtt_properties(mqtt_property_vbi(11, 7))  # SubscriptionIdentifier
    sub_v5_body = struct.pack(">H", 2) + sub_v5_props + mqtt_str("devices/plc2/#") + bytes([0x05])  # QoS1+NoLocal
    b(True, mqtt_packet(8, 0x02, sub_v5_body))
    b(False, mqtt_packet(9, 0, struct.pack(">H", 2) + mqtt_vbi(0) + bytes([0x01])))

    unsub_v5_body = struct.pack(">H", 3) + mqtt_vbi(0) + mqtt_str("devices/plc2/#")
    b(True, mqtt_packet(10, 0x02, unsub_v5_body))
    b(False, mqtt_packet(11, 0, struct.pack(">H", 3) + mqtt_vbi(0) + bytes([0x00])))

    auth_props = mqtt_properties(mqtt_property_str(21, "SCRAM-SHA-256"),
                                  mqtt_property_bin(22, bytes(range(8))))
    b(True, mqtt_packet(15, 0, bytes([0x18]) + auth_props))  # AUTH: Continue authentication
    auth_resp_props = mqtt_properties(mqtt_property_str(21, "SCRAM-SHA-256"))
    b(False, mqtt_packet(15, 0, bytes([0x00]) + auth_resp_props))  # AUTH: Success

    disc_props = mqtt_properties(mqtt_property_str(31, "administrative disconnect"))
    b(True, mqtt_packet(14, 0, bytes([0x04]) + disc_props))  # DISCONNECT: with Will Message

    # ---------------------------------------------------------------------------------------------
    # Flow C: Sparkplug B, port 63000 -- a v3.1.1 CONNECT/CONNACK first so this flow's own version
    # is session-tracked (not heuristic) for the PUBLISH packets that follow.
    # ---------------------------------------------------------------------------------------------
    c = make_flow(63000, src_ip=PLC_IP, dst_ip=HMI_IP, src_mac=PLC_MAC, dst_mac=HMI_MAC)
    c_connect = mqtt_str("MQTT") + bytes([4]) + bytes([0x02]) + struct.pack(">H", 30) + mqtt_str("edge-node-1")
    c(True, mqtt_packet(1, 0, c_connect))
    c(False, mqtt_packet(2, 0, bytes([0x00, 0x00])))

    ts0 = 1_700_000_000_000
    nbirth_metrics = [
        sparkplug_metric("bdSeq", "UInt64", 0),
        sparkplug_metric("Temperature", "Float", 21.5, timestamp=ts0),
        sparkplug_metric("Running", "Boolean", True, timestamp=ts0),
        sparkplug_metric("Count", "Int32", -5, timestamp=ts0),  # negative -- sign-handling gotcha
        sparkplug_metric("SerialNumber", "String", "SN-00123", timestamp=ts0),
        sparkplug_metric("StartTime", "DateTime", ts0, timestamp=ts0),
    ]
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/NBIRTH/EdgeNode1") +
                         sparkplug_payload(nbirth_metrics, timestamp=ts0, seq=0)))

    dbirth_metrics = [
        sparkplug_metric("Pressure", "Double", 101.325, timestamp=ts0 + 1000),
        sparkplug_metric("Status", "Text", "OK", timestamp=ts0 + 1000),
    ]
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/DBIRTH/EdgeNode1/Device1") +
                         sparkplug_payload(dbirth_metrics, timestamp=ts0 + 1000, seq=1)))

    ndata_metrics = [sparkplug_metric("Temperature", "Float", 22.1, timestamp=ts0 + 2000)]
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/NDATA/EdgeNode1") +
                         sparkplug_payload(ndata_metrics, timestamp=ts0 + 2000, seq=2)))

    ddata_metrics = [
        sparkplug_metric("Pressure", "Double", 101.9, timestamp=ts0 + 3000),
        sparkplug_metric("Fault", "Boolean", None, is_null=True, timestamp=ts0 + 3000),
        sparkplug_metric("Firmware", "Bytes", bytes([0xDE, 0xAD, 0xBE, 0xEF]), timestamp=ts0 + 3000),
    ]
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/DDATA/EdgeNode1/Device1") +
                         sparkplug_payload(ddata_metrics, timestamp=ts0 + 3000, seq=3)))

    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/DDEATH/EdgeNode1/Device1") +
                         sparkplug_payload([], timestamp=ts0 + 4000, seq=4, body=b"\x00")))

    state_json = b'{"online":true,"timestamp":1700000000000}'
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/STATE/scada-host-1") + state_json))

    # A genuinely malformed Sparkplug payload -- a topic that matches the namespace but a payload
    # that is NOT valid protobuf (a length-delimited field claiming far more bytes than are present)
    # -- exercises decode_sparkplug_payload's own try/catch fallback (parse_ok=false, note added).
    malformed_sp = pb_tag(2, 2) + pb_varint(200) + bytes([0x01, 0x02, 0x03])  # claims 200 bytes, has 3
    c(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/NDATA/EdgeNode1") + malformed_sp))

    # A v5 PUBLISH carrying an unrecognized MQTT5 Property Identifier (100 is not in mqtt.hpp's own
    # 27-entry table) -- exercises decode_properties' own "can't safely continue past an unknown
    # property" contained-failure fallback. Uses a fresh v5-tracked sub-flow so the Properties
    # section is unambiguously expected.
    c5 = make_flow(63005, src_ip=PLC_IP, dst_ip=HMI_IP, src_mac=PLC_MAC, dst_mac=HMI_MAC)
    c5(True, mqtt_packet(1, 0, mqtt_str("MQTT") + bytes([5]) + bytes([0x02]) + struct.pack(">H", 30) +
                          mqtt_properties() + mqtt_str("edge-node-2")))
    c5(False, mqtt_packet(2, 0, bytes([0x00, 0x00]) + mqtt_properties()))
    bogus_props = mqtt_properties(mqtt_property_byte(1, 1))
    # Splice in one unknown property id (100) with a bogus 1-byte value, by rebuilding the length
    # prefix around a hand-assembled properties body rather than using mqtt_properties() (which only
    # knows named property ids from mqtt.hpp's own table).
    bogus_body = mqtt_vbi(1) + bytes([0x01]) + mqtt_vbi(100) + bytes([0xFF])
    bogus_props = mqtt_vbi(len(bogus_body)) + bogus_body
    c5(True, mqtt_packet(3, 0, mqtt_str("spBv1.0/PlantA/NDATA/EdgeNode2") + bogus_props +
                          sparkplug_payload([sparkplug_metric("X", "Int32", 1)], seq=0)))

    # ---------------------------------------------------------------------------------------------
    # Flows D1/D2: SUBSCRIBE/UNSUBSCRIBE version-disambiguation HEURISTIC -- no CONNECT is ever sent
    # on either flow in this capture, so Decoder's own per-session version tracking has nothing to
    # go on and mqtt.cpp's own heuristic (see mqtt.hpp's "Version disambiguation" section) is what
    # actually determines the shape.
    # ---------------------------------------------------------------------------------------------
    # Packet identifiers below are deliberately >= 4096 (so the packet-id high byte is > 3), not
    # small round numbers -- see the ATTRIBUTION-style note in decoder.cpp/hartip.cpp: HART-IP's own
    # declared_length gate (tried earlier in the TCP dispatch chain than MQTT) treats byte offset 1
    # as a HART-IP "message type" (valid values include 15/NAK) and byte offset 2 as a "message id"
    # that must be <= 3 -- for a SUBSCRIBE/UNSUBSCRIBE/SUBACK/UNSUBACK packet, byte offset 2 is the
    # packet identifier's high byte, so a small packet id (e.g. 100) can coincidentally satisfy
    # HART-IP's gate and get misclassified/buffered as a truncated HART-IP message before MQTT ever
    # gets a turn. A packet id >= 4096 makes that high byte > 3 and steps around the collision.
    d1 = make_flow(64001)  # v3.1.1-shape (no Properties section)
    d1(True, mqtt_packet(8, 0x02, struct.pack(">H", 4100) + mqtt_str("test/topic") + bytes([0])))
    d1(False, mqtt_packet(9, 0, struct.pack(">H", 4100) + bytes([0x00])))
    d1(True, mqtt_packet(10, 0x02, struct.pack(">H", 4101) + mqtt_str("test/topic")))
    d1(False, mqtt_packet(11, 0, struct.pack(">H", 4101)))

    d2 = make_flow(64002)  # v5-shape (unconditional Properties section, even if empty)
    d2(True, mqtt_packet(8, 0x02, struct.pack(">H", 4200) + mqtt_properties() + mqtt_str("test/topic") +
                          bytes([0x01])))
    d2(False, mqtt_packet(9, 0, struct.pack(">H", 4200) + mqtt_properties() + bytes([0x01])))
    d2(True, mqtt_packet(10, 0x02, struct.pack(">H", 4201) + mqtt_properties() + mqtt_str("test/topic")))
    d2(False, mqtt_packet(11, 0, struct.pack(">H", 4201) + mqtt_properties() + bytes([0x00])))

    # ---------------------------------------------------------------------------------------------
    # Flow E: one PUBLISH split mid-message across two TCP segments -- Decoder::reassemble_tcp_payload,
    # driven by mqtt_declared_length. Port 65000.
    # ---------------------------------------------------------------------------------------------
    split_payload = mqtt_str("devices/plc1/split-test") + struct.pack(">H", 9) + (b"X" * 200)
    split_frame = mqtt_packet(3, 0x02, split_payload)
    split_at = len(split_frame) // 2
    tcp_e1 = tcp_header(65000, 1883, 30000, 400, TCP_PSH | TCP_ACK, len(split_frame[:split_at])) + \
        split_frame[:split_at]
    ip_e1 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_e1), 0x9100) + tcp_e1
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_e1)
    tcp_e2 = tcp_header(65000, 1883, 30000 + split_at, 400, TCP_PSH | TCP_ACK,
                         len(split_frame[split_at:])) + split_frame[split_at:]
    ip_e2 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_e2), 0x9101) + tcp_e2
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_e2)

    # ---------------------------------------------------------------------------------------------
    # Flow F: PINGREQ + PUBACK + PINGREQ coalesced by the sender/OS into ONE TCP segment -- the
    # wire_length-driven "additional MQTT packet" loop in decoder.cpp. Port 55010.
    # ---------------------------------------------------------------------------------------------
    coalesced = mqtt_packet(12, 0) + mqtt_packet(4, 0, struct.pack(">H", 5)) + mqtt_packet(12, 0)
    tcp_f = tcp_header(55010, 1883, 40000, 500, TCP_PSH | TCP_ACK, len(coalesced)) + coalesced
    ip_f = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_f), 0x9200) + tcp_f
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_f)

    # ---------------------------------------------------------------------------------------------
    # Flow G: negative/edge cases, port 55020.
    # ---------------------------------------------------------------------------------------------
    g = make_flow(55020)
    # An invalid QoS=3 PUBLISH (MQTT-3.3.1-4 reserves QoS to 0-2) -- fixed header flags 0x06 =
    # DUP=0, QoS=(0x06>>1)&0x3=3, RETAIN=0.
    g(True, mqtt_packet(3, 0x06, mqtt_str("devices/plc1/badqos") + b"x"))

    # A CONNECT-shaped byte whose Protocol Name is neither "MQTT" nor "MQIsdp" -- this MUST be
    # rejected outright by the structural detection gate (see mqtt.hpp), not decoded as MQTT at all.
    bogus_connect = mqtt_str("BOGUS") + bytes([4]) + bytes([0x02]) + struct.pack(">H", 30) + mqtt_str("x")
    g(True, mqtt_packet(1, 0, bogus_connect))

    # A genuinely truncated/incomplete final packet on its own flow -- declares more Remaining
    # Length than actually follows, with nothing more ever arriving on this flow in this capture --
    # the TCP-reassembly "buffering, waiting for more" path, mirroring sample_opcua.pcap's own
    # equivalent regression case.
    full_trunc_frame = mqtt_packet(3, 0, mqtt_str("devices/plc1/truncated") + (b"Y" * 100))
    truncated_bytes = full_trunc_frame[:20]
    tcp_t = tcp_header(55030, 1883, 50000, 600, TCP_PSH | TCP_ACK, len(truncated_bytes)) + truncated_bytes
    ip_t = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_t), 0x9300) + tcp_t
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_t)

    # ---------------------------------------------------------------------------------------------
    # Flow H: PINGREQ/PINGRESP on a TCP session where NEITHER port is 1883 (or any --mqtt-port
    # addition) -- exercises the "not a configured/standard MQTT port (1883)" note. Every other
    # flow above uses port 1883 on one side, so without this flow that note path goes untested.
    # ---------------------------------------------------------------------------------------------
    h = make_flow(52000, dport=52001)
    h(True, mqtt_packet(12, 0))
    h(False, mqtt_packet(13, 0))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_020_000 + i, i * 1000)
    (TESTS_DIR / "sample_mqtt.pcap").write_bytes(data)


def build_terminal_escape_injection_sample():
    """Exercises terminal_escape() (docs/reviews/2026-09-chatgpt-security-review-patch160.md's
    finding 4, output.cpp): two MQTT PUBLISH packets whose Topic string -- taken verbatim from
    wire bytes into MqttMessage::topic and straight into the decoded summary, see mqtt.cpp's
    build_summary -- carries bytes that would be dangerous if written straight to a real
    terminal. Packet 1's topic embeds an actual ESC (0x1B) byte driving a fake ANSI SGR sequence
    (the same escape family --color legitimately uses); packet 2's topic embeds a raw newline,
    which could otherwise forge what looks like a second, fabricated packet line in the
    one-line-per-packet text view. Both must render as literal \\xNN text in TextWriter/
    FieldsWriter output, never as raw control bytes."""
    packets = []

    def make_flow(sport, dport=1883, src_ip=HMI_IP, dst_ip=PLC_IP, src_mac=HMI_MAC, dst_mac=PLC_MAC):
        state = {"seq": 40000, "ack": 500}

        def add(payload: bytes):
            tcp = tcp_header(sport, dport, state["seq"], state["ack"], TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), state["seq"] & 0xFFFF) + tcp
            state["seq"] += len(payload)
            packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

        return add

    a = make_flow(58000)
    escape_topic = "evil\x1b[31mFAKE-ALERT\x1b[0m"
    a(mqtt_packet(3, 0x00, mqtt_str(escape_topic) + b"payload"))  # PUBLISH qos0

    b = make_flow(58001)
    newline_topic = "evil\nfake-injected-line"
    b(mqtt_packet(3, 0x00, mqtt_str(newline_topic) + b"payload"))  # PUBLISH qos0

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_030_000 + i, i * 1000)
    (TESTS_DIR / "sample_terminal_escape_injection.pcap").write_bytes(data)


FFHSE_PORT_ANNUNC = 1089
FFHSE_PORT_FMS = 1090
FFHSE_PORT_SM = 1091
FFHSE_PORT_LAN = 3622

FFHSE_FDA = 0x04
FFHSE_SM = 0x08
FFHSE_FMS = 0x0c
FFHSE_LAN = 0x10
FFHSE_REQ = 0
FFHSE_RSP = 1
FFHSE_ERR = 2


def ffhse_udp_frame(payload: bytes, sport: int, dport: int, src_ip: str, dst_ip: str,
                     src_mac: bytes, dst_mac: bytes) -> bytes:
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x7400)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def ffhse_pdu(protocol: int, type_: int, service_id: int, confirmed: bool, body: bytes = b"",
              fda_address: int = 0, pad_length: int = 0, message_number=None, invoke_id=None,
              time_stamp=None, ext_ctrl=None, version: int = 1, msg_length_override: int = None) -> bytes:
    """The 12-byte FF-HSE common header (+ optional trailer, order fixed: Message Number, Invoke
    Id, Time Stamp, Extended Control Field -- each only on the wire when its own kwarg here is not
    None, which also sets its own Options bit) plus `body` -- see ffhse.hpp's file header comment.
    `msg_length_override`, when given, writes a deliberately wrong Message Length (for
    malformed-input fixtures) instead of the correct 12+len(body)+len(trailer)."""
    options = pad_length & 0x07
    trailer = b""
    if message_number is not None:
        options |= 0x80
        trailer += struct.pack("!I", message_number)
    if invoke_id is not None:
        options |= 0x40
        trailer += struct.pack("!I", invoke_id)
    if time_stamp is not None:
        options |= 0x20
        trailer += struct.pack("!Q", time_stamp)
    if ext_ctrl is not None:
        options |= 0x08
        trailer += struct.pack("!I", ext_ctrl)
    protocol_and_type = (protocol & 0xfc) | (type_ & 0x03)
    service = (0x80 if confirmed else 0x00) | (service_id & 0x7f)
    total_length = msg_length_override if msg_length_override is not None else 12 + len(body) + len(trailer)
    header = struct.pack("!BBBBII", version, options, protocol_and_type, service, fda_address, total_length)
    return header + body + trailer


def ffhse_str(s: str, n: int) -> bytes:
    return s.encode("ascii")[:n].ljust(n, b"\x00")


def ffhse_error_body(error_class: int, error_code: int, additional_code: int, description: str,
                      remainder: bytes = b"") -> bytes:
    return struct.pack("!BBH", error_class, error_code, additional_code) + ffhse_str(description, 16) + remainder


def fda_open_session_body(session_index: int, max_buffer_size: int, max_msg_length: int, nma_use: int,
                           inactivity_close_time: int, transmit_delay_time: int, pd_tag: str,
                           reserved: int = 0) -> bytes:
    return (struct.pack("!IIIBBHI", session_index, max_buffer_size, max_msg_length, reserved, nma_use,
                         inactivity_close_time, transmit_delay_time) + ffhse_str(pd_tag, 32))


def sm_find_tag_query_body(query_type: int, index: int, tag: str, vfd_tag: str) -> bytes:
    return struct.pack("!B3xI", query_type, index) + ffhse_str(tag, 32) + ffhse_str(vfd_tag, 32)


def sm_find_tag_reply_body(query_type: int, h1_node_address: int, fda_addr_link_id: int, vfd_reference: int,
                            od_index: int, ip_address_bytes: bytes, od_version: int, device_id: str, pd_tag: str,
                            dup_state: int, selectors) -> bytes:
    assert len(ip_address_bytes) == 16
    out = struct.pack("!BBHII", query_type, h1_node_address, fda_addr_link_id, vfd_reference, od_index)
    out += ip_address_bytes
    out += struct.pack("!I", od_version)
    out += ffhse_str(device_id, 32) + ffhse_str(pd_tag, 32)
    out += struct.pack("!BBH", dup_state, 0, len(selectors))
    out += b"".join(struct.pack("!H", s) for s in selectors)
    return out


def sm_identify_body(smk_state: int, dev_type: int, dev_redundancy_state: int, dup_state: int, device_index: int,
                      max_device_index: int, op_ip_bytes: bytes, device_id: str, pd_tag: str, hse_repeat_time: int,
                      lr_port: int, annunciation_version: int, hse_device_version: int,
                      entries_link_nonzero=None, entries_link_zero=None) -> bytes:
    """Builds the 108-byte fixed shape + the LinkId-branched trailing version-number list -- see
    ffhse.hpp's own "The LinkId branch" section. Pass exactly one of entries_link_nonzero (a list
    of (h1-node-a, ver-a, h1-node-b, ver-b) 4-tuples -- for a header whose own FDA Address upper 16
    bits, i.e. LinkId, will be NONZERO) or entries_link_zero (a list of (h1-link-id, version)
    2-tuples -- for a header whose LinkId will be ZERO)."""
    assert len(op_ip_bytes) == 16
    if entries_link_nonzero is not None:
        n = len(entries_link_nonzero)
    elif entries_link_zero is not None:
        n = len(entries_link_zero)
    else:
        n = 0
    out = struct.pack("!BBBBHH", smk_state, dev_type, dev_redundancy_state, dup_state, device_index,
                       max_device_index)
    out += op_ip_bytes
    out += ffhse_str(device_id, 32) + ffhse_str(pd_tag, 32)
    out += struct.pack("!IH2xII", hse_repeat_time, lr_port, annunciation_version, hse_device_version)
    out += struct.pack("!I", n)
    if entries_link_nonzero is not None:
        for (na, va, nb, vb) in entries_link_nonzero:
            out += struct.pack("!BBBB", na, va, nb, vb)
    elif entries_link_zero is not None:
        for (h1link, ver) in entries_link_zero:
            out += struct.pack("!HBB", h1link, 0, ver)
    return out


def sm_clear_address_body(device_id: str, pd_tag: str, iface: int) -> bytes:
    return ffhse_str(device_id, 32) + ffhse_str(pd_tag, 32) + bytes([iface]) + b"\x00" * 3


def sm_set_assignment_body(device_id: str, pd_tag: str, h1_new_address: int, dev_redundancy_state: int,
                            lr_port: int, hse_repeat_time: int, device_index: int, max_device_index: int,
                            op_ip_bytes: bytes, clear_dup_detection_state: int) -> bytes:
    assert len(op_ip_bytes) == 16
    out = ffhse_str(device_id, 32) + ffhse_str(pd_tag, 32)
    out += struct.pack("!BBHIHH", h1_new_address, dev_redundancy_state, lr_port, hse_repeat_time,
                        device_index, max_device_index)
    out += op_ip_bytes
    out += b"\x00" * 3
    out += bytes([clear_dup_detection_state])
    return out


def sm_set_assignment_rsp_body(max_device_index: int, hse_repeat_time: int) -> bytes:
    return b"\x00\x00" + struct.pack("!HI", max_device_index, hse_repeat_time)


def sm_clear_assignment_body(device_id: str, pd_tag: str) -> bytes:
    return ffhse_str(device_id, 32) + ffhse_str(pd_tag, 32)


def fms_initiate_req_body(connect_option: int, access_protection: int, passwd_and_access_grps: int,
                           ver_od_calling: int, prof_num_calling: int, pd_tag: str) -> bytes:
    return struct.pack("!BBHHH", connect_option, access_protection, passwd_and_access_grps, ver_od_calling,
                        prof_num_calling) + ffhse_str(pd_tag, 32)


def fms_initiate_rsp_body(ver_od_called: int, prof_num_called: int) -> bytes:
    return struct.pack("!HH", ver_od_called, prof_num_called)


def fms_abort_body(detail_bytes: bytes, abort_id: int, reason_code: int) -> bytes:
    assert len(detail_bytes) == 16
    return detail_bytes + bytes([abort_id, reason_code]) + b"\x00\x00"


def fms_status_body(logical_status: int, physical_status: int, local_detail: int) -> bytes:
    return struct.pack("!BB2xI", logical_status, physical_status, local_detail)


def fms_identify_body(vendor_name: str, model_name: str, revision: str) -> bytes:
    return ffhse_str(vendor_name, 32) + ffhse_str(model_name, 32) + ffhse_str(revision, 32)


def fms_read_body(index: int) -> bytes:
    return struct.pack("!I", index)


def fms_read_subindex_body(index: int, subindex: int) -> bytes:
    return struct.pack("!II", index, subindex)


def fms_index_data_body(index: int, data: bytes) -> bytes:
    return struct.pack("!I", index) + data


def fms_index_subindex_data_body(index: int, subindex: int, data: bytes) -> bytes:
    return struct.pack("!II", index, subindex) + data


def lan_info_body(lr_attrs_version: int, max_msg_num_diff: int, lr_flags: int, diag_msg_interval: int,
                   aging_time: int, a_send: bytes, a_recv: bytes, b_send: bytes, b_recv: bytes) -> bytes:
    for b in (a_send, a_recv, b_send, b_recv):
        assert len(b) == 16
    return (struct.pack("!IBB2xII", lr_attrs_version, max_msg_num_diff, lr_flags, diag_msg_interval, aging_time)
            + a_send + a_recv + b_send + b_recv)


def lan_statistics_body(recv_a: int, miss_a: int, fault_a: int, recv_b: int, miss_b: int, fault_b: int,
                         stats) -> bytes:
    return (struct.pack("!IIIIIII", recv_a, miss_a, fault_a, recv_b, miss_b, fault_b, len(stats))
            + b"".join(struct.pack("!I", v) for v in stats))


def lan_diagnostic_body(device_index: int, num_if: int, trans_if: int, diag_msg_interval: int, pd_tag: str,
                         dup_state: int, a_to_a, b_to_a, a_to_b, b_to_b) -> bytes:
    n = len(a_to_a)
    assert len(b_to_a) == n and len(a_to_b) == n and len(b_to_b) == n
    out = struct.pack("!HBBI", device_index, num_if, trans_if, diag_msg_interval)
    out += ffhse_str(pd_tag, 32)
    out += b"\x00"  # 1-byte reserved gap before dup_state (body offset 41 -- see decode_lan_diagnostic_req)
    out += bytes([dup_state])
    out += struct.pack("!H", n)
    for lst in (a_to_a, b_to_a, a_to_b, b_to_b):
        out += b"".join(struct.pack("!I", v) for v in lst)
    return out


def build_ffhse_sample():
    """FOUNDATION Fieldbus HSE (FDA/SM/FMS/LAN Redundancy, all 4 signaled in-band via the 12-byte
    common header's own ProtocolAndType/Service bytes -- ports 1089/1090/1091/3622 are recorded as
    "expected port" annotations only, never a detection gate) -- see ffhse.hpp's file header
    comment for the exact wire format each packet below exercises (cross-checked against
    Wireshark's own packet-ff.c/packet-ff.h). No real capture happens to be attributed for this
    fixture set yet -- see ffhse.hpp's own sourcing paragraph for the current state of that
    search.

    Every packet here uses Version=1 (FfhseHeader::version is never itself validated), chosen
    specifically because it structurally cannot collide with any earlier-tried protocol's own TCP
    declared-length gate in decoder.cpp's dispatch chain (OPC UA's magic-string check, EtherNet/
    IP's 9-value command enum, IEC104's start byte, Modbus/TCP's protocol-id==0 check, DNP3's sync
    bytes, TPKT's version==3 byte, HART-IP's own message-type/message-id two-byte gate all fail to
    match a leading Version=1 byte or FF-HSE's own always->=4 ProtocolAndType byte at HART-IP's
    message-id offset) -- see decoder.cpp's own FF-HSE dispatch-order comment.

    Scenario coverage: all 4 sub-protocols x Req/Rsp/Err where applicable; every Options trailer
    combination (none, one field, all four fields); FDA Open Session + Idle; SM Identify AND SM
    Device Annunciation on BOTH LinkId branches (the single trickiest piece of this decoder); SM
    Find Tag Query/Reply; the SM Clear/Set/Clear-Assignment Address family; the FMS Initiate
    handshake; Status; Identify; Read/Write (+with-subindex, both directions); the Information
    Report family; Abort; Tier-2 FMS Event Notification and Get OD; LAN Redundancy Get/Put Info,
    Get Statistics, and Diagnostic (with its 4 parallel interface-status lists); unrecognized
    service ids on every sub-protocol/confirmed-flag combination; a concatenated multi-PDU-per-
    UDP-datagram case; an unexpected-port case; a malformed/truncated case; an implausible-Message-
    Length false-positive regression (see kMaxPlausibleMessageLength in ffhse.cpp); and, over TCP,
    a genuine request/response round trip, a TCP-segment-split PDU, and two PDUs coalesced into one
    TCP segment."""
    packets = []

    def add(payload: bytes, dport: int, sport: int = 52200, from_client: bool = True):
        if from_client:
            packets.append(ffhse_udp_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(ffhse_udp_frame(payload, dport, sport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    op_ip = bytes([192, 168, 1, 10]) + b"\x00" * 12
    dev_ip = bytes([192, 168, 1, 20]) + b"\x00" * 12

    # 1)-3) FDA Open Session Req/Rsp/Err -- the Rsp also carries a Message-Number + Invoke-Id
    #    trailer (Options 0xC0), exercising two of the four optional trailer fields at once.
    open_session = fda_open_session_body(1, 8192, 8192, nma_use=1, inactivity_close_time=180,
                                          transmit_delay_time=10, pd_tag="PLC-01")
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 1, True, open_session), dport=FFHSE_PORT_ANNUNC)
    add(ffhse_pdu(FFHSE_FDA, FFHSE_RSP, 1, True, open_session, message_number=1, invoke_id=1),
        dport=FFHSE_PORT_ANNUNC, from_client=False)
    add(ffhse_pdu(FFHSE_FDA, FFHSE_ERR, 1, True, ffhse_error_body(5, 6, 0, "unsupported service")),
        dport=FFHSE_PORT_ANNUNC, from_client=False)

    # 4)-5) FDA Idle Req/Rsp -- both expected EMPTY.
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 3, True), dport=FFHSE_PORT_ANNUNC)
    add(ffhse_pdu(FFHSE_FDA, FFHSE_RSP, 3, True), dport=FFHSE_PORT_ANNUNC, from_client=False)

    # 6) FDA unrecognized service id -- shown as raw hex, not guessed at.
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 2, True, bytes([0xAA, 0xBB])), dport=FFHSE_PORT_ANNUNC)

    # 7) SM Find Tag Query Req (unconfirmed).
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 1, False,
                  sm_find_tag_query_body(0, 0, "PT-101", "")), dport=FFHSE_PORT_SM)

    # 8) SM Find Tag Reply Req (unconfirmed) with 2 FDA Address Selector entries.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 2, False,
                  sm_find_tag_reply_body(0, 0x05, 0x1234, 100, 200, dev_ip, 1, "DEV-0001", "PT-101", 0x01,
                                          [0x1111, 0x2222])),
        dport=FFHSE_PORT_SM)

    # 9) SM Identify Req (confirmed) -- empty body.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 3, True), dport=FFHSE_PORT_SM)

    # 10) SM Identify Rsp (confirmed) -- LinkId != 0 branch (2-byte H1NodeAddress+VersionNumber
    #     pairs). LinkId comes from the HEADER's own FDA Address upper 16 bits, not the body.
    identify_nonzero = sm_identify_body(0x03, 0x02, 0x00, 0x00, 1, 8, op_ip, "DEV-0001", "PT-101",
                                         1000, FFHSE_PORT_LAN, 1, 1,
                                         entries_link_nonzero=[(0x01, 1, 0x02, 1), (0x03, 2, 0x04, 1)])
    add(ffhse_pdu(FFHSE_SM, FFHSE_RSP, 3, True, identify_nonzero, fda_address=0x00050000),
        dport=FFHSE_PORT_SM, from_client=False)

    # 11) SM Identify Rsp (confirmed) -- LinkId == 0 branch (4-byte H1LinkId+Reserved+Version
    #     quads) -- the OTHER half of the LinkId branch, same message shape.
    identify_zero = sm_identify_body(0x03, 0x02, 0x00, 0x00, 2, 8, op_ip, "DEV-0002", "PT-102",
                                      1000, FFHSE_PORT_LAN, 1, 1,
                                      entries_link_zero=[(0x0005, 1), (0x0006, 2)])
    add(ffhse_pdu(FFHSE_SM, FFHSE_RSP, 3, True, identify_zero, fda_address=0x00000000),
        dport=FFHSE_PORT_SM, from_client=False)

    # 12) & 13) SM Device Annunciation Req (unconfirmed) -- the SAME 108-byte-plus-list shape as
    #     SM Identify Rsp, on BOTH LinkId branches again (a device announcing itself unsolicited).
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 16, False, identify_nonzero, fda_address=0x00050000),
        dport=FFHSE_PORT_ANNUNC)
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 16, False, identify_zero, fda_address=0x00000000),
        dport=FFHSE_PORT_ANNUNC)

    # 14) & 15) SM Clear Address Req/Rsp (confirmed) -- Rsp is expected EMPTY.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 12, True, sm_clear_address_body("DEV-0001", "PT-101", 0x01)),
        dport=FFHSE_PORT_SM)
    add(ffhse_pdu(FFHSE_SM, FFHSE_RSP, 12, True), dport=FFHSE_PORT_SM, from_client=False)

    # 16) & 17) SM Set Assignment Info Req/Rsp (confirmed) -- two DIFFERENT body shapes, unlike
    #     most other confirmed services here.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 14, True,
                  sm_set_assignment_body("DEV-0001", "PT-101", 0x05, 0x00, FFHSE_PORT_LAN, 1000, 1, 8, op_ip,
                                          0x00)),
        dport=FFHSE_PORT_SM)
    add(ffhse_pdu(FFHSE_SM, FFHSE_RSP, 14, True, sm_set_assignment_rsp_body(8, 1000)),
        dport=FFHSE_PORT_SM, from_client=False)

    # 18) SM Set Assignment Info Err.
    add(ffhse_pdu(FFHSE_SM, FFHSE_ERR, 14, True, ffhse_error_body(5, 12, 0, "assignments already made")),
        dport=FFHSE_PORT_SM, from_client=False)

    # 19) & 20) SM Clear Assignment Info Req/Rsp (confirmed) -- Rsp is expected EMPTY.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 15, True, sm_clear_assignment_body("DEV-0001", "PT-101")),
        dport=FFHSE_PORT_SM)
    add(ffhse_pdu(FFHSE_SM, FFHSE_RSP, 15, True), dport=FFHSE_PORT_SM, from_client=False)

    # 21) SM unconfirmed unrecognized service id -- shown as raw hex.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 7, False, bytes([0x01, 0x02])), dport=FFHSE_PORT_SM)

    # 22)-24) FMS Initiate Req/Rsp/Err -- the confirmed service that establishes an FMS
    #     association. The Rsp also carries a full 8-byte Time Stamp trailer (Options 0x20).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 96, True,
                  fms_initiate_req_body(1, 0x00, 0x0000, 1, 1, "PT-101")), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 96, True, fms_initiate_rsp_body(1, 1), time_stamp=0x0102030405060708),
        dport=FFHSE_PORT_FMS, from_client=False)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_ERR, 96, True, ffhse_error_body(11, 2, 0, "feature-not-supported")),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 25) & 26) FMS Status Req (empty)/Rsp.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 0, True), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 0, True, fms_status_body(0x00, 0x00, 0)),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 27) & 28) FMS Identify Req (empty)/Rsp.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 1, True), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 1, True, fms_identify_body("Yokogawa", "HSE-Transmitter", "1.0")),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 29) & 30) FMS Read Req/Rsp -- the Rsp's own returned value is deliberately left raw (no
    #     self-describing wire type without external Object Dictionary context -- see ffhse.hpp).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 2, True, fms_read_body(315)), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 2, True, struct.pack("!f", 72.5)),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 31) & 32) FMS Read with Subindex Req/Rsp -- same "value left raw" treatment.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 82, True, fms_read_subindex_body(316, 2)), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 82, True, struct.pack("!I", 42)),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 33) & 34) FMS Write Req (Index decoded, Data left raw inline)/Rsp (expected EMPTY).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 3, True, fms_index_data_body(315, struct.pack("!f", 80.0))),
        dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 3, True), dport=FFHSE_PORT_FMS, from_client=False)

    # 35) & 36) FMS Write with Subindex Req/Rsp (expected EMPTY).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 83, True,
                  fms_index_subindex_data_body(316, 2, struct.pack("!I", 99))), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 83, True), dport=FFHSE_PORT_FMS, from_client=False)

    # 37)-40) FMS unconfirmed Information Report family -- plain, with Subindex, On Change, and On
    #     Change with Subindex (2 shapes total, reused across 4 service ids).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 0, False, fms_index_data_body(315, struct.pack("!f", 72.5))),
        dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 16, False,
                  fms_index_subindex_data_body(316, 2, struct.pack("!I", 7))), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 17, False, fms_index_data_body(315, struct.pack("!f", 73.0))),
        dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 18, False,
                  fms_index_subindex_data_body(316, 2, struct.pack("!I", 8))), dport=FFHSE_PORT_FMS)

    # 41) FMS Unsolicited Status Req (unconfirmed) -- same 8-byte shape as the confirmed Status Rsp.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 1, False, fms_status_body(0x01, 0x00, 5)), dport=FFHSE_PORT_FMS)

    # 42) FMS Abort (unconfirmed).
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 112, False, fms_abort_body(bytes(range(16)), 1, 2)),
        dport=FFHSE_PORT_FMS)

    # 43) FMS Event Notification Req (unconfirmed) -- Tier 2, shown as raw hex.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 2, False, bytes([0x01, 0x02, 0x03, 0x04])), dport=FFHSE_PORT_FMS)

    # 44) & 45) FMS Get OD Req/Rsp (confirmed) -- Tier 2, even the reference dissector leaves OD
    #     entries undecoded.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 4, True, bytes([0x00, 0x00, 0x01, 0x3B])), dport=FFHSE_PORT_FMS)
    add(ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 4, True, bytes([0xDE, 0xAD, 0xBE, 0xEF])),
        dport=FFHSE_PORT_FMS, from_client=False)

    # 46) FMS Initiate Download Sequence Req (confirmed) -- another Tier 2 confirmed service.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 9, True, bytes([0x00, 0x01])), dport=FFHSE_PORT_FMS)

    # 47) FMS confirmed unrecognized service id -- shown as raw hex.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 50, True, bytes([0x00])), dport=FFHSE_PORT_FMS)

    # 48) FMS unconfirmed unrecognized service id -- shown as raw hex.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 99, False, bytes([0x00])), dport=FFHSE_PORT_FMS)

    # 49) & 50) LAN Redundancy Get Info Req (empty)/Rsp.
    a_send, a_recv = bytes([10, 0, 0, 1]) + b"\x00" * 12, bytes([10, 0, 0, 2]) + b"\x00" * 12
    b_send, b_recv = bytes([10, 0, 1, 1]) + b"\x00" * 12, bytes([10, 0, 1, 2]) + b"\x00" * 12
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 1, True), dport=FFHSE_PORT_LAN)
    add(ffhse_pdu(FFHSE_LAN, FFHSE_RSP, 1, True,
                  lan_info_body(1, 1, 0x03, 5000, 30000, a_send, a_recv, b_send, b_recv)),
        dport=FFHSE_PORT_LAN, from_client=False)

    # 51) & 52) LAN Redundancy Put Info Req/Rsp -- identical shape both directions.
    put_info = lan_info_body(1, 0, 0x01, 5000, 30000, a_send, a_recv, b_send, b_recv)
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 2, True, put_info), dport=FFHSE_PORT_LAN)
    add(ffhse_pdu(FFHSE_LAN, FFHSE_RSP, 2, True, put_info), dport=FFHSE_PORT_LAN, from_client=False)

    # 53) & 54) LAN Redundancy Get Statistics Req (empty)/Rsp with 2 XCableStat entries.
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 3, True), dport=FFHSE_PORT_LAN)
    add(ffhse_pdu(FFHSE_LAN, FFHSE_RSP, 3, True,
                  lan_statistics_body(100, 1, 0, 100, 0, 0, [5, 7])), dport=FFHSE_PORT_LAN, from_client=False)

    # 55) LAN Redundancy Get Statistics Err.
    add(ffhse_pdu(FFHSE_LAN, FFHSE_ERR, 3, True, ffhse_error_body(8, 0, 0, "other")),
        dport=FFHSE_PORT_LAN, from_client=False)

    # 56) LAN Redundancy Diagnostic Message Req (unconfirmed) -- 1 interface-status entry across
    #     all 4 parallel lists (A-to-A/B-to-A/A-to-B/B-to-B).
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 1, False,
                  lan_diagnostic_body(1, 2, 0, 5000, "PT-101", 0x00, [1], [0], [1], [0])),
        dport=FFHSE_PORT_LAN)

    # 57) LAN Redundancy unconfirmed unrecognized service id -- shown as raw hex.
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 5, False, bytes([0x00])), dport=FFHSE_PORT_LAN)

    # 58) LAN Redundancy confirmed unrecognized service id -- shown as raw hex.
    add(ffhse_pdu(FFHSE_LAN, FFHSE_REQ, 9, True, bytes([0x00])), dport=FFHSE_PORT_LAN)

    # 59) A message with ALL FOUR trailer fields present at once (Options 0xE8) -- FMS Status Req.
    add(ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 0, True, message_number=7, invoke_id=8,
                  time_stamp=0x1122334455667788, ext_ctrl=0x0A0B0C0D), dport=FFHSE_PORT_FMS)

    # 60) A message with the decorative Pad Length sub-field set (Options low 3 bits = 0x07) --
    #     surfaced but not acted on in any length arithmetic (see ffhse.hpp's Options paragraph).
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 3, True, pad_length=0x07), dport=FFHSE_PORT_ANNUNC)

    # 61) Two FF-HSE PDUs concatenated into ONE UDP datagram (FDA Idle Req + FDA Idle Rsp) --
    #     exercises the wire_length-driven coalescing while-loop in decoder.cpp's UDP dispatch.
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 3, True) + ffhse_pdu(FFHSE_FDA, FFHSE_RSP, 3, True),
        dport=FFHSE_PORT_ANNUNC)

    # 62) Malformed/truncated: Message Length claims a full 52-byte FDA Open Session Req body, but
    #     only 20 bytes of it are actually present in the captured payload -- exercises BOTH the
    #     "Message Length exceeds bytes available" note (from the true UDP datagram being short)
    #     and require_min's own "not enough bytes for this shape" fallback to raw hex.
    truncated_body = open_session[:20]
    add(ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 1, True, truncated_body,
                  msg_length_override=12 + len(open_session)), dport=FFHSE_PORT_ANNUNC)

    # 63) Unexpected port: an otherwise perfectly valid SM Identify Req on a port that is none of
    #     the 4 configured FF-HSE ports -- still decodes, but with the "not a configured/standard
    #     FF-HSE port" note.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 3, True), dport=40000)

    # 64) False-positive regression: ProtocolAndType matches a valid combo (this decoder's own
    #     weakest structural gate -- see ffhse.hpp's "Structural detection gate" paragraph), but
    #     Message Length is far beyond any real FF-HSE message -- must be rejected outright, not
    #     "detected" as a badly truncated FF-HSE message. Mirrors a real false positive found on a
    #     genuine capture: a UDP/443 QUIC/TLS response's essentially-random bytes happened to match
    #     this gate and decoded a Message Length of 4237566479, which this decoder then "explained"
    #     as truncated instead of rejecting -- see kMaxPlausibleMessageLength's own comment in
    #     ffhse.cpp. Same port pairing (server:443 -> client) as that real capture.
    add(ffhse_pdu(FFHSE_SM, FFHSE_REQ, 3, True, bytes(range(40, 60)),
                  msg_length_override=4237566479), dport=443, sport=58201, from_client=False)

    # --- FF-HSE over TCP: the same 4 ports serve both transports -- see ffhse.hpp. ---
    client_seq = [5000]
    server_seq = [6000]

    def add_tcp(from_client: bool, payload: bytes, sport: int = 52300, dport: int = FFHSE_PORT_FMS):
        if from_client:
            src_port, dst_port = sport, dport
            src_ip, dst_ip = HMI_IP, PLC_IP
            src_mac, dst_mac = HMI_MAC, PLC_MAC
            seq, ack = client_seq[0], server_seq[0]
            client_seq[0] += len(payload)
        else:
            src_port, dst_port = dport, sport
            src_ip, dst_ip = PLC_IP, HMI_IP
            src_mac, dst_mac = PLC_MAC, HMI_MAC
            seq, ack = server_seq[0], client_seq[0]
            server_seq[0] += len(payload)
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), 0x7500 + len(packets)) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # 65) & 66) A genuine FMS Initiate request/response round trip over TCP.
    add_tcp(True, ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 96, True,
                             fms_initiate_req_body(1, 0x00, 0x0000, 1, 1, "PT-101")))
    add_tcp(False, ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 96, True, fms_initiate_rsp_body(1, 1)))

    # 67) & 68) One FDA Open Session Req PDU split across TWO TCP segments -- the FIRST segment
    #     carries only the 12-byte header plus a few body bytes; the SECOND carries the rest.
    #     Exercises ffhse_declared_length-driven cross-segment reassembly (mirrors
    #     hartip_declared_length's own TCP reassembly test).
    split_pdu = ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 1, True, open_session)
    split_point = 20
    add_tcp(True, split_pdu[:split_point], sport=52310)
    add_tcp(True, split_pdu[split_point:], sport=52310)

    # 69) Two SM Clear Assignment Info Rsp messages coalesced into ONE TCP segment (sender/OS
    #     coalescing) -- exercises the wire_length-driven "additional FF-HSE message" loop for TCP.
    add_tcp(True, ffhse_pdu(FFHSE_SM, FFHSE_RSP, 15, True) + ffhse_pdu(FFHSE_SM, FFHSE_RSP, 15, True),
            sport=52320, dport=FFHSE_PORT_SM)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_007_000 + i, i * 1000)
    (TESTS_DIR / "sample_ffhse.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# Beckhoff TwinCAT / ADS over AMS/TCP (TCP port 48898) -- see twincat.hpp's file header comment
# for the exact wire format each packet below exercises. TwinCAT is the first protocol in this
# codebase built entirely on the ProtocolDecoder interface (protocol_decoder.hpp); this fixture
# doubles as that interface's own proof, alongside the registration-model refactor's differential
# checks against its EIGRP/Modbus/GOOSE pilot migrations (see docs/DEVELOPMENT.md).

AMS_ADS_COMMAND_FLAG = 0x0004
AMS_RESPONSE_FLAG = 0x0001

TWINCAT_PLC_NET_ID = bytes([5, 62, 196, 212, 1, 1])
TWINCAT_HMI_NET_ID = bytes([5, 62, 196, 211, 1, 1])
TWINCAT_PLC_AMS_PORT = 851    # TwinCAT 3 "TC3 PLC1" runtime port
TWINCAT_HMI_AMS_PORT = 32000  # a typical ADS client's own ephemeral AMS port


def ams_frame(*, command_id: int, is_response: bool, invoke_id: int, body: bytes = b"",
              target_net_id: bytes = TWINCAT_PLC_NET_ID, target_port: int = TWINCAT_PLC_AMS_PORT,
              source_net_id: bytes = TWINCAT_HMI_NET_ID, source_port: int = TWINCAT_HMI_AMS_PORT,
              error_code: int = 0, ads_command_flag: bool = True) -> bytes:
    """One complete AMS/TCP-framed ADS message: the 6-byte AMS/TCP header (2 reserved bytes + a
    4-byte LE Data Length, always honestly derived from `body`'s own length here) followed by the
    32-byte AMS header and `body` -- see twincat.hpp's file header comment for the exact field
    layout/order this mirrors byte-for-byte."""
    state_flags = (AMS_ADS_COMMAND_FLAG if ads_command_flag else 0) | (AMS_RESPONSE_FLAG if is_response else 0)
    ams_header = (target_net_id + struct.pack("<H", target_port) +
                  source_net_id + struct.pack("<H", source_port) +
                  struct.pack("<HHIII", command_id, state_flags, len(body), error_code, invoke_id))
    ams_message = ams_header + body
    return struct.pack("<HI", 0, len(ams_message)) + ams_message


def build_twincat_sample():
    """Covers all 9 ADS Command IDs (request+response shapes), authoritative Invoke-ID pairing
    (opposite-direction match, same-direction reuse, and an orphan response), a DeviceNotification
    push (deliberately excluded from pairing), a payload truncated relative to its own command's
    expected shape, three structural-gate rejections (unrecognized Command ID, missing ADS command
    State Flags bit, and a Data-Length cross-check mismatch -- see twincat.hpp's detection-gate
    paragraph), a non-standard AMS/TCP port, and a frame split across two TCP segments (exercising
    TwinCatDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the same split/rejoin
    shape build_tcp_reassembly_sample already covers for Modbus/DNP3/TPKT)."""
    packets = []

    def add(src_port, dst_port, seq, ack, payload, ident, from_plc):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    seq_c, seq_s = 1000, 5000
    ident = 0x1000

    def client(payload):
        nonlocal seq_c, ident
        add(53000, 48898, seq_c, seq_s, payload, ident, from_plc=False)
        seq_c += len(payload)
        ident += 1

    def server(payload):
        nonlocal seq_s, ident
        add(48898, 53000, seq_s, seq_c, payload, ident, from_plc=True)
        seq_s += len(payload)
        ident += 1

    # 1) & 2) ReadDeviceInfo request (no payload) / response (result=0, version 3.1 build 4024,
    #    device name "Plan1") -- Invoke ID 1, authoritative opposite-direction pairing.
    client(ams_frame(command_id=1, is_response=False, invoke_id=1))
    dev_name = b"Plan1" + b"\x00" * (16 - len(b"Plan1"))
    server(ams_frame(command_id=1, is_response=True, invoke_id=1,
                      body=struct.pack("<IBBH", 0, 3, 1, 4024) + dev_name))

    # 3) & 4) Read request (IndexGroup 0x4020, IndexOffset 0x101, 4 bytes) / response (result=0,
    #    4 bytes of data) -- Invoke ID 2.
    client(ams_frame(command_id=2, is_response=False, invoke_id=2, body=struct.pack("<III", 0x4020, 0x101, 4)))
    server(ams_frame(command_id=2, is_response=True, invoke_id=2,
                      body=struct.pack("<II", 0, 4) + struct.pack("<I", 0xDEADBEEF)))

    # 5) & 6) Write request (same address, 4 bytes) / response (result=0) -- Invoke ID 3.
    client(ams_frame(command_id=3, is_response=False, invoke_id=3,
                      body=struct.pack("<III", 0x4020, 0x101, 4) + struct.pack("<I", 100)))
    server(ams_frame(command_id=3, is_response=True, invoke_id=3, body=struct.pack("<I", 0)))

    # 7) & 8) ReadWrite request (SumRead-style: read 8 bytes back while writing 4) / response
    #    (result=0, 8 bytes of data) -- Invoke ID 4.
    client(ams_frame(command_id=9, is_response=False, invoke_id=4,
                      body=struct.pack("<IIII", 0xF080, 0, 8, 4) + struct.pack("<I", 1)))
    server(ams_frame(command_id=9, is_response=True, invoke_id=4,
                      body=struct.pack("<II", 0, 8) + struct.pack("<Q", 0x1122334455667788)))

    # 9) & 10) ReadState request (no payload) / response (result=0, ADS state 5 == Run, device
    #    state 0) -- Invoke ID 5.
    client(ams_frame(command_id=4, is_response=False, invoke_id=5))
    server(ams_frame(command_id=4, is_response=True, invoke_id=5, body=struct.pack("<IHH", 0, 5, 0)))

    # 11) & 12) WriteControl request (requesting ADS state 5 == Run, device state 0, no associated
    #     data) / response (result=0) -- Invoke ID 6.
    client(ams_frame(command_id=5, is_response=False, invoke_id=6, body=struct.pack("<HHI", 5, 0, 0)))
    server(ams_frame(command_id=5, is_response=True, invoke_id=6, body=struct.pack("<I", 0)))

    # 13) & 14) AddDeviceNotification request (IndexGroup 0x4020, IndexOffset 0x101, 4 bytes,
    #     cyclic mode 3, max delay 0, cycle time 200000 (100ns units == 20ms)) / response (result=0,
    #     handle 0xABCD1234) -- Invoke ID 7.
    client(ams_frame(command_id=6, is_response=False, invoke_id=7,
                      body=struct.pack("<IIIIII", 0x4020, 0x101, 4, 3, 0, 200000)))
    server(ams_frame(command_id=6, is_response=True, invoke_id=7, body=struct.pack("<II", 0, 0xABCD1234)))

    # 15) & 16) DeleteDeviceNotification request (handle 0xABCD1234, from #14) / response
    #     (result=0) -- Invoke ID 8.
    client(ams_frame(command_id=7, is_response=False, invoke_id=8, body=struct.pack("<I", 0xABCD1234)))
    server(ams_frame(command_id=7, is_response=True, invoke_id=8, body=struct.pack("<I", 0)))

    # 17) DeviceNotification -- unsolicited push (server -> client), no Invoke ID pairing at all
    #     (Command ID 8 is deliberately excluded from pairing -- see TwinCatDecoder::decode). One
    #     stamp, two samples.
    sample1 = struct.pack("<II", 0xABCD1234, 4) + struct.pack("<I", 42)
    sample2 = struct.pack("<II", 0xABCD1234, 4) + struct.pack("<I", 43)
    stamp = struct.pack("<Q", 132_000_000_000_000_000) + struct.pack("<I", 2) + sample1 + sample2
    server(ams_frame(command_id=8, is_response=False, invoke_id=0, body=struct.pack("<II", len(stamp), 1) + stamp))

    # 18) & 19) Invoke ID reused on the SAME direction before its first request (Invoke ID 9) was
    #     ever paired with a response, then a response arrives for it -- exercises the "reused"
    #     note, mirroring build_modbus_pairing_sample's own scenario B.
    client(ams_frame(command_id=2, is_response=False, invoke_id=9, body=struct.pack("<III", 0x4020, 0x200, 2)))
    client(ams_frame(command_id=2, is_response=False, invoke_id=9, body=struct.pack("<III", 0x4020, 0x300, 2)))
    server(ams_frame(command_id=2, is_response=True, invoke_id=9,
                      body=struct.pack("<II", 0, 2) + struct.pack("<H", 7)))

    # 20) Orphan response: Invoke ID 999, no matching request ever seen on this session.
    server(ams_frame(command_id=2, is_response=True, invoke_id=999, body=struct.pack("<II", 0, 0)))

    # 21) Truncated payload relative to its own command's expected shape: a ReadState response
    #     whose AMS Data Length (4) is honestly declared and consistent with the AMS/TCP header (so
    #     the frame itself is accepted), but is too short for ReadState's own response shape
    #     (result + ADS state + device state == 8 bytes) -- exercises decode_payload's own internal
    #     ParseError catch, distinct from try_parse_twincat's outer structural gate.
    server(ams_frame(command_id=4, is_response=True, invoke_id=10, body=struct.pack("<I", 0)))

    # 22) Unrecognized Command ID (99), otherwise-valid AMS/TCP framing (correct length cross-check,
    #     ADS command State Flags bit set) -- must still be rejected outright by
    #     twincat_command_name's own allowlist, not misdetected as TwinCAT.
    client(ams_frame(command_id=99, is_response=False, invoke_id=11, body=bytes([1, 2, 3, 4])))

    # 23) ADS command State Flags bit (0x0004) NOT set -- an AMS router-internal message shape this
    #     decoder deliberately doesn't recognize (see twincat.hpp's State Flags paragraph) -- must
    #     not be misdetected as ADS traffic even though Command ID/length are otherwise plausible.
    client(ams_frame(command_id=1, is_response=False, invoke_id=12, ads_command_flag=False))

    # 24) AMS/TCP Data Length vs. the AMS header's own Data Length cross-check mismatch -- the AMS
    #     header honestly declares a 4-byte body, but the AMS/TCP prefix's own Data Length is
    #     inflated by 4 beyond what that implies -- a direct contradiction, this decoder's strongest
    #     structural signal, and must be rejected outright.
    mismatched = bytearray(ams_frame(command_id=2, is_response=False, invoke_id=13, body=bytes(4)))
    struct.pack_into("<I", mismatched, 2, struct.unpack_from("<I", mismatched, 2)[0] + 4)
    add(53000, 48898, seq_c, seq_s, bytes(mismatched), ident, from_plc=False)
    seq_c += len(mismatched)
    ident += 1

    # 25) Non-standard AMS/TCP port (TCP port 3000, not 48898) -- still structurally valid AMS/TCP
    #     (the gate is entirely port-independent -- see twincat.hpp), so it's still decoded, but
    #     gets the "not a configured/standard TwinCAT/AMS port" note, mirroring every other
    #     TCP-port-independent protocol's own such-note test.
    add(53500, 3000, seq_c, seq_s, ams_frame(command_id=1, is_response=False, invoke_id=14), ident, from_plc=False)
    seq_c += len(ams_frame(command_id=1, is_response=False, invoke_id=14))
    ident += 1

    # 26), 27) & 28) TCP-segment-split reassembly: a Read request (Invoke ID 15, whole in one
    #     segment) followed by its response, whose own AMS/TCP frame is split across two TCP
    #     segments -- exercises TwinCatDecoder::tcp_declared_length via Decoder::
    #     reassemble_tcp_payload (the same split/rejoin shape build_tcp_reassembly_sample already
    #     covers for Modbus/DNP3/TPKT), together with Invoke-ID pairing still resolving correctly
    #     once the response is fully reassembled. The split point (40) is deliberately chosen to
    #     fall AFTER the complete 38-byte AMS/TCP+AMS header (not mid-header) -- twincat_declared_
    #     length can only recognize a frame that needs buffering once that whole header has
    #     arrived (see its own comment in twincat.cpp for the documented, narrower gap this leaves).
    client(ams_frame(command_id=2, is_response=False, invoke_id=15, body=struct.pack("<III", 0x4020, 0x400, 8)))
    split_frame = ams_frame(command_id=2, is_response=True, invoke_id=15,
                             body=struct.pack("<II", 0, 8) + struct.pack("<Q", 0xAABBCCDDEEFF0011))
    split_at = 40
    add(48898, 53000, seq_s, seq_c, split_frame[:split_at], ident, from_plc=True)
    seq_s += split_at
    ident += 1
    add(48898, 53000, seq_s, seq_c, split_frame[split_at:], ident, from_plc=True)
    seq_s += len(split_frame) - split_at
    ident += 1

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_008_000 + i, i * 1000)
    (TESTS_DIR / "sample_twincat.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# MELSEC Communication Protocol (MC Protocol / SLMP), TCP port 5001 / UDP port 5000 -- see
# melsec.hpp's file header comment for the full wire format, structural detection gate, and the
# session-scoped request/response matching each packet group below is designed to exercise.

MELSEC_TCP_PORT = 5001
MELSEC_UDP_PORT = 5000

MELSEC_DEVICE_CODE = {
    "D": 0xA8, "M": 0x90, "X": 0x9C, "Y": 0x9D, "W": 0xB4, "B": 0xA0,
}


def melsec_device(letter: str, number: int, extended: bool = False) -> bytes:
    """One device spec -- see melsec.hpp's file header comment (device number is plain
    little-endian binary, NOT BCD; device code is 1 byte standard / 2 bytes little-endian
    extended)."""
    code = MELSEC_DEVICE_CODE[letter]
    num_bytes = struct.pack("<I", number)[: 4 if extended else 3]
    return num_bytes + (struct.pack("<H", code) if extended else struct.pack("<B", code))


def melsec_request(command: int, subcommand: int, body: bytes = b"", monitor_timer: int = 0,
                    network_no: int = 0, pc_no: int = 0xFF, io_no: int = 0x03FF, station_no: int = 0,
                    is_4e: bool = False, serial: int = 1, length_override: int = None) -> bytes:
    """One 3E- or 4E-framed binary MC Protocol/SLMP REQUEST -- see melsec.hpp's file header comment.
    `length_override`, when given, writes a deliberately wrong Request Data Length (for the
    declared-length-mismatch negative control) instead of the correct 6 + len(body)."""
    tail = struct.pack("<HHH", monitor_timer, command, subcommand) + body
    declared = length_override if length_override is not None else len(tail)
    header = struct.pack(">H", 0x5400 if is_4e else 0x5000)
    if is_4e:
        header += struct.pack("<H", serial)
    header += struct.pack("<BBHB", network_no, pc_no, io_no, station_no)
    header += struct.pack("<H", declared)
    return header + tail


def melsec_response(end_code: int = 0, body: bytes = b"", is_4e: bool = False, serial: int = 1,
                     network_no: int = 0, pc_no: int = 0xFF, io_no: int = 0x03FF, station_no: int = 0,
                     length_override: int = None) -> bytes:
    """One 3E- or 4E-framed binary MC Protocol/SLMP RESPONSE."""
    tail = struct.pack("<H", end_code) + body
    declared = length_override if length_override is not None else len(tail)
    header = struct.pack(">H", 0xD400 if is_4e else 0xD000)
    if is_4e:
        header += struct.pack("<H", serial)
    header += struct.pack("<BBHB", network_no, pc_no, io_no, station_no)
    header += struct.pack("<H", declared)
    return header + tail


def melsec_udp_frame(payload: bytes, sport: int = MELSEC_UDP_PORT, dport: int = MELSEC_UDP_PORT,
                      from_plc: bool = False) -> bytes:
    src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
    src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x7400)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def build_melsec_sample():
    """Covers every command this decoder verified against pymcprotocol (see melsec.hpp's file
    header comment): Batch Read word+bit units, Batch Write word units, Random Read (word+dword
    mixed, matched response splitting correctly via session state), Remote RUN/STOP/PAUSE/LATCH
    CLEAR/RESET, Read CPU Type, Remote Password UNLOCK (proving the password value never appears in
    output, only its length), Echo Test, a 4E-frame variant (Serial No. field), an unknown
    command/subcommand (structural fallback, numeric-only), a non-zero End Code response (both the
    named 0xC059 "Unsupported command" path and a raw-hex fallback), a declared-length mismatch
    negative control (subheader magic matches but the length accounting doesn't), a payload whose
    leading bytes don't match any of the 4 subheader values at all (pure gate rejection), a frame
    split across two TCP segments (exercising MelsecTcpDecoder::tcp_declared_length via
    Decoder::reassemble_tcp_payload), a real MELSEC-vs-Modbus TCP collision regression (Network
    No.==PC No.==0, a small I/O No. -- see melsec.hpp's own "POST-DELIVERY FIX" paragraph), and both
    transports (TCP port 5001, UDP port 5000)."""
    packets = []

    # --- TCP: one continuous session (port 53400 -> 5001), commands exercised strictly one
    # request/response pair at a time so the single-pending-slot session state (MelsecFlowState)
    # always has an unambiguous match -- see melsec.hpp's "RESPONSE DECODING NEEDS SESSION CONTEXT"
    # paragraph for why that's the realistic case this fixture is built around.
    seq_c, seq_s = 1000, 5000
    ident = 0x2000

    def add(src_port, dst_port, seq, ack, payload, from_plc):
        nonlocal ident
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)
        ident += 1

    def client(payload):
        nonlocal seq_c
        add(53400, MELSEC_TCP_PORT, seq_c, seq_s, payload, from_plc=False)
        seq_c += len(payload)

    def server(payload):
        nonlocal seq_s
        add(MELSEC_TCP_PORT, 53400, seq_s, seq_c, payload, from_plc=True)
        seq_s += len(payload)

    # 1) & 2) Batch Read, word units (subcommand 0x0000): D1000, 3 points.
    client(melsec_request(0x0401, 0x0000, melsec_device("D", 1000) + struct.pack("<H", 3)))
    server(melsec_response(body=struct.pack("<3h", 100, -1, 32767)))

    # 3) & 4) Batch Read, bit units (subcommand 0x0001): M100, 5 points -- exercises the
    #    even-index-bit4/odd-index-bit0 packing quirk (values 1,0,1,1,0 -> 0x10, 0x11, 0x00).
    client(melsec_request(0x0401, 0x0001, melsec_device("M", 100) + struct.pack("<H", 5)))
    server(melsec_response(body=bytes([0x10, 0x11, 0x00])))

    # 5) & 6) Batch Write, word units: D2000, 2 points, values [1234, -1] -- response has no data
    #    beyond the end code.
    client(melsec_request(0x1401, 0x0000,
                           melsec_device("D", 2000) + struct.pack("<H", 2) + struct.pack("<2h", 1234, -1)))
    server(melsec_response())

    # 7) & 8) Random Read (word+dword mixed, subcommand 0x0000): 2 word devices (D100, D200) + 1
    #    dword device (D300) -- the response carries no counts of its own on the wire, so this
    #    proves MelsecPendingRequest's own random_read_word_count/dword_count carry-forward works.
    client(melsec_request(0x0403, 0x0000,
                           bytes([2, 1]) + melsec_device("D", 100) + melsec_device("D", 200) +
                           melsec_device("D", 300)))
    server(melsec_response(body=struct.pack("<2h", 111, 222) + struct.pack("<i", 333333)))

    # 9) & 10) Remote RUN, force execution + clear all.
    client(melsec_request(0x1001, 0x0000, struct.pack("<HBB", 0x0003, 2, 0)))
    server(melsec_response())

    # 11) & 12) Remote STOP.
    client(melsec_request(0x1002, 0x0000, struct.pack("<H", 1)))
    server(melsec_response())

    # 13) & 14) Remote PAUSE, normal mode.
    client(melsec_request(0x1003, 0x0000, struct.pack("<H", 0x0001)))
    server(melsec_response())

    # 15) & 16) Remote LATCH CLEAR.
    client(melsec_request(0x1005, 0x0000, struct.pack("<H", 1)))
    server(melsec_response())

    # 17) & 18) Remote RESET.
    client(melsec_request(0x1006, 0x0000, struct.pack("<H", 1)))
    server(melsec_response())

    # 19) & 20) Read CPU Type -- request has no data; response is a 16-byte space-padded ASCII name
    #     ("Q06UDVCPU" here) plus a 2-byte CPU code.
    client(melsec_request(0x0101, 0x0000))
    cpu_name = b"Q06UDVCPU".ljust(16, b" ")
    server(melsec_response(body=cpu_name + struct.pack("<H", 0x0500)))

    # 21) & 22) Remote Password UNLOCK -- per Jurgen's own decision, the password value itself must
    #     never appear in this decoder's output, only its length (8 here). The CMakeLists.txt test
    #     for this packet asserts "remote_password_length" is present AND the literal string
    #     "S3cr3t!!" is absent from every output format.
    client(melsec_request(0x1630, 0x0000, struct.pack("<H", 8) + b"S3cr3t!!"))
    server(melsec_response())

    # 23) & 24) Echo/Loopback Test -- response echoes the same shape back.
    client(melsec_request(0x0619, 0x0000, struct.pack("<H", 5) + b"HELLO"))
    server(melsec_response(body=struct.pack("<H", 5) + b"HELLO"))

    # 25) & 26) Unknown command/subcommand (structural fallback, numeric-only -- never guessed at)
    #     paired with an End Code 0xC059 ("Unsupported command", the one error code pymcprotocol's
    #     own source names explicitly) response -- proves both the unknown-command fallback AND the
    #     named End Code path in one exchange, since a real PLC would plausibly answer an
    #     unrecognized command this way.
    client(melsec_request(0x9999, 0x0000, bytes([0xAA, 0xBB])))
    server(melsec_response(end_code=0xC059))

    # 27) & 28) A recognized command (Batch Read, word units) answered with an arbitrary non-zero
    #     End Code (0x4031) that ISN'T 0xC059 -- proves the raw-hex fallback naming path
    #     ("Error 0x4031 (not independently verified...)").
    client(melsec_request(0x0401, 0x0000, melsec_device("D", 500) + struct.pack("<H", 1)))
    server(melsec_response(end_code=0x4031))

    # 29) & 30) 4E frame variant (Serial No. 0x002A) -- Batch Read, word units, D1500, 1 point.
    client(melsec_request(0x0401, 0x0000, melsec_device("D", 1500) + struct.pack("<H", 1),
                           is_4e=True, serial=0x002A))
    server(melsec_response(body=struct.pack("<h", 42), is_4e=True, serial=0x002A))

    # 31) Pure gate rejection (TCP) -- leading bytes don't match any of the 4 recognized subheader
    #     values at all (0x1234 instead of 0x5000/0xD000/0x5400/0xD400). Rejected at peek_header,
    #     before any length-based reassembly slicing even begins -- must NOT be recognized as melsec.
    client(struct.pack(">H", 0x1234) + b"\x00" * 10)

    # 32) & 33) A Batch Read response (D1600, 1 point, value 7) split across TWO TCP segments --
    #     exercises MelsecTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the
    #     same split/rejoin shape build_tcp_reassembly_sample already covers for Modbus/DNP3/TPKT
    #     and build_twincat_sample covers for AMS/TCP.
    client(melsec_request(0x0401, 0x0000, melsec_device("D", 1600) + struct.pack("<H", 1)))
    split_frame = melsec_response(body=struct.pack("<h", 7))
    split_at = 9
    add(MELSEC_TCP_PORT, 53400, seq_s, seq_c, split_frame[:split_at], from_plc=True)
    seq_s += split_at
    add(MELSEC_TCP_PORT, 53400, seq_s, seq_c, split_frame[split_at:], from_plc=True)
    seq_s += len(split_frame) - split_at

    # 34) A real, reproducible MELSEC-vs-Modbus TCP collision (found via Jurgen's own report,
    #     see melsec.hpp's "POST-DELIVERY FIX" paragraph): Network No.==PC No.==0 (both real, valid
    #     values -- not just the 0xFF "own station" convention every other request/response in this
    #     fixture defaults to) and Request Destination Module I/O No.==0x0000 (a real I/O number for
    #     a module at slot 0 -- not the 0x3FF "own station" sentinel every other request/response
    #     here also defaults to). Before this fix, Modbus's own weak protocol_id==0 gate swallowed
    #     this request first (shown as "Unknown (0xNN)") even on MELSEC's own TCP port 5001 -- must
    #     decode as melsec, never as modbus, standalone (no response needed for this negative-control
    #     style proof).
    client(melsec_request(0x0401, 0x0000, melsec_device("D", 1800) + struct.pack("<H", 1),
                           network_no=0, pc_no=0, io_no=0x0000))

    # --- UDP: a separate 4-tuple (port 53500 -> 5000), same session-scoped matching mechanism.
    # 34) & 35) Batch Read, word units: D1700, 1 point.
    packets.append(melsec_udp_frame(melsec_request(0x0401, 0x0000, melsec_device("D", 1700) +
                                                     struct.pack("<H", 1)), sport=53500))
    packets.append(melsec_udp_frame(melsec_response(body=struct.pack("<h", 999)),
                                     sport=MELSEC_UDP_PORT, dport=53500, from_plc=True))

    # 36) & 37) Same UDP flow, non-standard port pair (53501 -> 15000) -- exercises the "not a
    #     configured/standard MELSEC port" note on the UDP path (mirrors packet #23/#24 in
    #     build_hartip_sample's own TCP-side non-standard-port coverage).
    packets.append(melsec_udp_frame(melsec_request(0x1002, 0x0000, struct.pack("<H", 1)),
                                     sport=53501, dport=15000))
    packets.append(melsec_udp_frame(melsec_response(), sport=15000, dport=53501, from_plc=True))

    # 38) Declared-length mismatch negative control (UDP -- see build_melsec_sample's own docstring
    #     for why this must be a single self-contained datagram, not a TCP segment: over TCP, the
    #     reassembly cascade trusts the declared length and slices the buffer down to it, so a
    #     TRUNCATED slice re-checked in isolation would appear internally self-consistent again; a
    #     UDP datagram has no such slicing step, so this checks the real thing -- subheader magic
    #     (0x5000) matches, but the Request Data Length field is deliberately wrong (declares 6 when
    #     the real tail is 6 + 3-byte device number + 1-byte device code + 2-byte point count = 12
    #     bytes), so payload.size() can never equal bytes_before_length_field + 2 + declared_length).
    #     Must NOT be recognized as melsec at all (falls through to generic "udp" recognition) -- the
    #     same collision-resistance proof this session's own QUIC investigation demonstrated the
    #     value of.
    packets.append(melsec_udp_frame(
        melsec_request(0x0401, 0x0000, melsec_device("D", 999) + struct.pack("<H", 1),
                        length_override=6),
        sport=53502))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_009_000 + i, i * 1000)
    (TESTS_DIR / "sample_melsec.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# FINS (Factory Interface Network Service, Omron) -- TCP and UDP, both port 9600 (see fins.hpp's
# file header comment for the full wire format, structural detection gate, and curated security
# notes). Built the same way build_melsec_sample() above is: a synthetic fixture, since no real
# Omron/FINS capture was found in the same corpus checked for MELSEC (see fins.hpp's own
# "real-capture corpus check" paragraph in its plan).

FINS_TCP_PORT = 9600
FINS_UDP_PORT = 9600

FINS_AREA = {
    "D_WORD": 0x82, "D_BIT": 0x02, "CIO_BIT": 0x30, "CIO_WORD": 0xB0, "H_BIT": 0x32,
}


def fins_bcd(v: int) -> int:
    return ((v // 10) << 4) | (v % 10)


def fins_frame(command: int, body: bytes = b"", is_response: bool = False, gct: int = 0x02,
               dna: int = 0, da1: int = 1, da2: int = 0, sna: int = 0, sa1: int = 1, sa2: int = 0,
               sid: int = 1, icf_override: int = None, rsv_override: int = None) -> bytes:
    """One transport-independent FINS command/response frame (10-byte header + MRC/SRC + body) --
    see fins.hpp's own wire-format paragraph. `gct` defaults to 0x02 (a real probe's own observed
    value, NOT the conventional-but-unreliable 0x07 -- see fins.hpp's own corrections-from-real-
    evidence paragraph) deliberately, so this fixture's own FINS/UDP traffic naturally exercises
    the HART-IP collision risk fins.hpp's UDP gate ordering defends against (GCT=0x02 DOES satisfy
    HART-IP's own weak MessageID-in-{0,1,2,3} condition) on every packet, not just one dedicated
    negative control. `icf_override`/`rsv_override` are for the two structural-gate-rejection
    negative controls (reserved bits set / RSV != 0)."""
    icf = icf_override if icf_override is not None else (0xC0 if is_response else 0x80)
    rsv = rsv_override if rsv_override is not None else 0x00
    mrc = (command >> 8) & 0xFF
    src = command & 0xFF
    header = bytes([icf, rsv, gct, dna, da1, da2, sna, sa1, sa2, sid, mrc, src])
    return header + body


def fins_tcp_envelope(command: int, data: bytes = b"", error_code: int = 0) -> bytes:
    """FINS/TCP's own outer envelope -- Magic("FINS",4) + Length(4,BE) + Command(4,BE) +
    ErrorCode(4,BE) + data, Length counting everything after itself (8 + Length total bytes) --
    see fins.hpp's own FINS/TCP framing paragraph."""
    length = 8 + len(data)
    return b"FINS" + struct.pack(">I", length) + struct.pack(">II", command, error_code) + data


def fins_udp_frame(payload: bytes, sport: int = FINS_UDP_PORT, dport: int = FINS_UDP_PORT,
                    from_plc: bool = False) -> bytes:
    src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
    src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x8400)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def build_fins_sample():
    """Covers every one of the 17 commands this decoder verified (see fins.hpp's file header
    comment), both directions where applicable: Memory Area Read (word AND bit units), Memory Area
    Write, Memory Area Fill, Multiple Memory Area Read (mixed word+bit items, matched response
    splitting correctly via session state -- the same FinsFlowState proof build_melsec_sample's own
    Random Read packet gives MelsecFlowState), Run (with mode code), Stop, Controller Data Read (the
    92-byte model/version variant), Controller Status Read, Cycle Time Read (both the
    "initialize" -- no stats -- and "read" -- with stats -- response shapes), Clock Read, Clock
    Write, LOOP-BACK Test, Access Right Acquire (both the plain-success and already-held-elsewhere
    response shapes), Access Right Forced Acquire, Access Right Release, Error Clear, Forced
    Set/Reset (two entries, one CIO bit set, one H bit reset), Forced Set/Reset Cancel. Also covers
    the FINS/TCP handshake (commands 0x00/0x01), Frame Send Error Notification (0x03), Connection
    Confirmation (0x06), a FINS/TCP declared-length reassembly split (exercising
    FinsTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the same split/rejoin
    shape build_melsec_sample's own packet already covers), a TCP Frame Send carrying an
    unrecognized command code (structural fallback, numeric-only -- TCP's own outer "FINS" magic is
    gate enough on its own, unlike UDP), a UDP negative control with that SAME unrecognized command
    code (must be rejected outright, falling through to generic "udp" -- the deliberate departure
    from MELSEC's own numeric-fallback posture, see fins.hpp), two UDP structural-gate-rejection
    negative controls (ICF reserved bits set; RSV != 0x00), a non-standard-port UDP pair, and both
    transports (TCP port 9600, UDP port 9600 -- the same conventional port number for both, unlike
    MELSEC's own split 5001/5000)."""
    packets = []

    # --- TCP: one continuous session (port 53600 -> 9600), commands exercised strictly one
    # request/response pair at a time so the single-pending-slot session state (FinsFlowState)
    # always has an unambiguous match -- see fins.hpp's own "A GENUINE ARCHITECTURAL DIFFERENCE
    # FROM MELSEC" paragraph for why only 2 of these 17 commands' own responses actually need it.
    seq_c, seq_s = 2000, 8000
    ident = 0x3000

    def add(src_port, dst_port, seq, ack, payload, from_plc):
        nonlocal ident
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_plc else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_plc else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)
        ident += 1

    def client(payload):
        nonlocal seq_c
        add(53600, FINS_TCP_PORT, seq_c, seq_s, payload, from_plc=False)
        seq_c += len(payload)

    def server(payload):
        nonlocal seq_s
        add(FINS_TCP_PORT, 53600, seq_s, seq_c, payload, from_plc=True)
        seq_s += len(payload)

    # 1) & 2) FINS/TCP handshake -- Node Address Data Send, client->server then server->client.
    client(fins_tcp_envelope(0x00, struct.pack(">I", 1)))
    server(fins_tcp_envelope(0x01, struct.pack(">II", 1, 1)))

    # 3) & 4) Memory Area Read, word units: D1000, 3 items.
    client(fins_tcp_envelope(0x02, fins_frame(
        0x0101, bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 1000, 0) + struct.pack(">H", 3))))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0101, struct.pack(">H", 0) + struct.pack(">3h", 100, -1, 32767), is_response=True)))

    # 5) & 6) Memory Area Read, bit units: CIO10.05, 4 items.
    client(fins_tcp_envelope(0x02, fins_frame(
        0x0101, bytes([FINS_AREA["CIO_BIT"]]) + struct.pack(">HB", 10, 5) + struct.pack(">H", 4))))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0101, struct.pack(">H", 0) + bytes([1, 0, 1, 1]), is_response=True)))

    # 7) & 8) Memory Area Write, word units: D2000, 2 items, values [111, -1].
    client(fins_tcp_envelope(0x02, fins_frame(
        0x0102, bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 2000, 0) + struct.pack(">H", 2) +
        struct.pack(">2h", 111, -1))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0102, struct.pack(">H", 0), is_response=True)))

    # 9) & 10) Memory Area Fill: D3000, 5 items, fill value 1234.
    client(fins_tcp_envelope(0x02, fins_frame(
        0x0103, bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 3000, 0) + struct.pack(">H", 5) +
        struct.pack(">h", 1234))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0103, struct.pack(">H", 0), is_response=True)))

    # 11) & 12) Multiple Memory Area Read: D4000 (word) + CIO20.03 (bit), 2 items -- proves
    #     FinsFlowState carries the request's own device list forward so the response's own raw
    #     values split correctly per-item (word vs. bit), the same proof build_melsec_sample's own
    #     Random Read packet gives MelsecPendingRequest.
    client(fins_tcp_envelope(0x02, fins_frame(
        0x0104,
        bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 4000, 0) +
        bytes([FINS_AREA["CIO_BIT"]]) + struct.pack(">HB", 20, 3))))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0104, struct.pack(">H", 0) + struct.pack(">h", 4242) + bytes([1]), is_response=True)))

    # 13) & 14) Run: program 0, mode 2 (force execution).
    client(fins_tcp_envelope(0x02, fins_frame(0x0401, struct.pack(">HB", 0, 2))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0401, struct.pack(">H", 0), is_response=True)))

    # 15) & 16) Stop.
    client(fins_tcp_envelope(0x02, fins_frame(0x0402)))
    server(fins_tcp_envelope(0x02, fins_frame(0x0402, struct.pack(">H", 0), is_response=True)))

    # 17) & 18) Controller Data Read -- request has no data; response is the 92-byte variant
    #     (20-byte model + 20-byte version + 52 bytes not decoded further).
    client(fins_tcp_envelope(0x02, fins_frame(0x0501)))
    model = b"CJ2M-CPU31".ljust(20, b" ")
    version = b"V2.06".ljust(20, b" ")
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0501, struct.pack(">H", 0) + model + version + bytes(52), is_response=True)))

    # 19) & 20) Controller Status Read -- request has no data; response: status=Run, mode=RUN mode,
    #     FALS number 0x1234, error message "NO ERROR".
    client(fins_tcp_envelope(0x02, fins_frame(0x0601)))
    error_msg = b"NO ERROR".ljust(16, b" ")
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0601, struct.pack(">H", 0) + bytes([0x01, 0x04]) + struct.pack(">HHH", 0, 0, 0) +
        struct.pack(">H", 0x1234) + error_msg, is_response=True)))

    # 21) & 22) Cycle Time Read, "initialize" (parameter 0) -- response carries no stats (data
    #     shorter than 12 bytes beyond the end code).
    client(fins_tcp_envelope(0x02, fins_frame(0x0620, bytes([0]))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0620, struct.pack(">H", 0), is_response=True)))

    # 23) & 24) Cycle Time Read, "read" (parameter 1) -- response carries avg/max/min stats.
    client(fins_tcp_envelope(0x02, fins_frame(0x0620, bytes([1]))))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0620, struct.pack(">H", 0) + struct.pack(">III", 1500, 2500, 800), is_response=True)))

    # 25) & 26) Clock Read -- request has no data; response: 2026-09-22 13:45:30, day=2 (Tuesday).
    client(fins_tcp_envelope(0x02, fins_frame(0x0701)))
    clock_body = bytes([fins_bcd(26), fins_bcd(9), fins_bcd(22), fins_bcd(13), fins_bcd(45),
                         fins_bcd(30), 2])
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0701, struct.pack(">H", 0) + clock_body, is_response=True)))

    # 27) & 28) Clock Write -- same date/time (7-byte variant, second+day included).
    client(fins_tcp_envelope(0x02, fins_frame(0x0702, clock_body)))
    server(fins_tcp_envelope(0x02, fins_frame(0x0702, struct.pack(">H", 0), is_response=True)))

    # 29) & 30) LOOP-BACK Test -- response echoes the same data back.
    client(fins_tcp_envelope(0x02, fins_frame(0x0801, b"PING")))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0801, struct.pack(">H", 0) + b"PING", is_response=True)))

    # 31) & 32) Access Right Acquire -- plain success (no data beyond the end code).
    client(fins_tcp_envelope(0x02, fins_frame(0x0C01, struct.pack(">H", 1))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0C01, struct.pack(">H", 0), is_response=True)))

    # 33) & 34) Access Right Acquire, retried -- already held elsewhere: network 1, node 5, unit 0.
    client(fins_tcp_envelope(0x02, fins_frame(0x0C01, struct.pack(">H", 2))))
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0C01, struct.pack(">H", 0) + bytes([0x00, 0x05, 0x01]), is_response=True)))

    # 35) & 36) Access Right Forced Acquire -- curated note: no credential check, seizes the right
    #     from whoever currently holds it.
    client(fins_tcp_envelope(0x02, fins_frame(0x0C02, struct.pack(">H", 2))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0C02, struct.pack(">H", 0), is_response=True)))

    # 37) & 38) Access Right Release.
    client(fins_tcp_envelope(0x02, fins_frame(0x0C03, struct.pack(">H", 2))))
    server(fins_tcp_envelope(0x02, fins_frame(0x0C03, struct.pack(">H", 0), is_response=True)))

    # 39) & 40) Error Clear -- FALS number 0x1234.
    client(fins_tcp_envelope(0x02, fins_frame(0x2101, struct.pack(">H", 0x1234))))
    server(fins_tcp_envelope(0x02, fins_frame(0x2101, struct.pack(">H", 0), is_response=True)))

    # 41) & 42) Forced Set/Reset -- 2 entries: force-set CIO10.05 ON, force-reset H20.03 OFF --
    #     curated note: overrides live I/O directly, bypassing normal program logic.
    entry1 = struct.pack(">H", 0x0001) + bytes([FINS_AREA["CIO_BIT"]]) + struct.pack(">I", 10 * 16 + 5)[1:]
    entry2 = struct.pack(">H", 0x0000) + bytes([FINS_AREA["H_BIT"]]) + struct.pack(">I", 20 * 16 + 3)[1:]
    client(fins_tcp_envelope(0x02, fins_frame(0x2301, struct.pack(">H", 2) + entry1 + entry2)))
    server(fins_tcp_envelope(0x02, fins_frame(0x2301, struct.pack(">H", 0), is_response=True)))

    # 43) & 44) Forced Set/Reset Cancel.
    client(fins_tcp_envelope(0x02, fins_frame(0x2302)))
    server(fins_tcp_envelope(0x02, fins_frame(0x2302, struct.pack(">H", 0), is_response=True)))

    # 45) & 46) TCP Frame Send Error Notification (command 0x03), then Connection Confirmation
    #     (command 0x06) -- both envelope-only, no inner FINS command/response frame.
    client(fins_tcp_envelope(0x03, error_code=0x03))
    server(fins_tcp_envelope(0x06))

    # 47) TCP Frame Send carrying an unrecognized command code (0x9999) -- unlike UDP's own hard
    #     rejection, FINS/TCP's outer "FINS" magic is gate enough on its own, so this decodes
    #     structurally (numeric-only fallback), the same posture MELSEC's own TCP side uses.
    client(fins_tcp_envelope(0x02, fins_frame(0x9999, b"\x01\x02\x03")))

    # 48) TCP declared-length reassembly split: a Memory Area Read request for D5000 split across
    #     two TCP segments mid-envelope -- exercises FinsTcpDecoder::tcp_declared_length via
    #     Decoder::reassemble_tcp_payload, the same split/rejoin shape build_melsec_sample's own
    #     packet already covers.
    split_payload = fins_tcp_envelope(0x02, fins_frame(
        0x0101, bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 5000, 0) + struct.pack(">H", 1)))
    half = len(split_payload) // 2
    client(split_payload[:half])
    client(split_payload[half:])
    server(fins_tcp_envelope(0x02, fins_frame(
        0x0101, struct.pack(">H", 0) + struct.pack(">h", 777), is_response=True)))

    # --- UDP: single-datagram request/response pairs (no reassembly on this side).

    # 49) & 50) Memory Area Read, word units, over UDP -- also the packet that most directly proves
    #     the HART-IP defensive ordering matters: GCT=0x02 (fins_frame's own default) DOES satisfy
    #     HART-IP's own weak MessageID-in-{0,1,2,3} UDP gate condition, and RSV=0x00 always
    #     satisfies its MessageType==0 condition too -- this MUST decode as "fins", never "hartip".
    packets.append(fins_udp_frame(fins_frame(
        0x0101, bytes([FINS_AREA["D_WORD"]]) + struct.pack(">HB", 6000, 0) + struct.pack(">H", 2))))
    packets.append(fins_udp_frame(fins_frame(
        0x0101, struct.pack(">H", 0) + struct.pack(">2h", 55, 66), is_response=True), from_plc=True))

    # 51) & 52) Same UDP flow, non-standard port pair (53601 -> 15001) -- exercises the "not a
    #     configured/standard FINS port" note on the UDP path.
    packets.append(fins_udp_frame(fins_frame(0x0402), sport=53601, dport=15001))
    packets.append(fins_udp_frame(fins_frame(
        0x0402, struct.pack(">H", 0), is_response=True), sport=15001, dport=53601, from_plc=True))

    # 53) UDP negative control: the SAME unrecognized command code (0x9999) packet #47 already
    #     proved decodes structurally over TCP -- over UDP it must be REJECTED outright (falls
    #     through to generic "udp"), the deliberate departure from MELSEC's own numeric-fallback
    #     posture forced by FINS/UDP having no other structural anchor to lean on (see fins.hpp).
    packets.append(fins_udp_frame(fins_frame(0x9999, b"\x01\x02\x03"), sport=53602))

    # 54) UDP negative control: ICF reserved bits (0x3E mask) set -- structural gate rejection, must
    #     NOT be recognized as fins at all.
    packets.append(fins_udp_frame(fins_frame(0x0402, icf_override=0x82), sport=53603))

    # 55) UDP negative control: RSV != 0x00 -- structural gate rejection, must NOT be recognized as
    #     fins at all.
    packets.append(fins_udp_frame(fins_frame(0x0402, rsv_override=0x01), sport=53604))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_010_000 + i, i * 1000)
    (TESTS_DIR / "sample_fins.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# Kerberos (RFC 4120), TCP and UDP port 88 -- the first Windows AD-suite protocol (see
# kerberos.hpp's file header comment for the full wire format, structural detection gate, and the
# curated attack/monitoring notes each packet group below is designed to exercise). Built with the
# same generic ctx_c/app_c/uni_p/uni_c/ber_int/ber_tlv ASN.1 BER/DER helpers the MMS section above
# already established (ber_tag_bytes and friends, ~line 3431) -- Kerberos needs nothing those
# don't already provide (every tag it ever uses fits the low-tag-number, definite-length-only BER
# subset those helpers cover).

KERBEROS_PORT = 88


def kb_seq(content: bytes = b"") -> bytes:
    return uni_c(16, content)  # SEQUENCE, universal tag 16


def kb_int(value: int) -> bytes:
    return uni_p(2, ber_int(value))  # INTEGER, universal tag 2


def kb_str(s: str) -> bytes:
    return uni_p(0x1B, s.encode("ascii"))  # GeneralString, universal tag 27


def kb_time(yyyymmddhhmmss: str) -> bytes:
    return uni_p(0x18, (yyyymmddhhmmss + "Z").encode("ascii"))  # GeneralizedTime, universal tag 24


def kb_bitstring(flag_bits: list) -> bytes:
    """BIT STRING content for KDCOptions/APOptions: an unused-bits count byte (always 0 here,
    since every flag this fixture sets falls on a byte boundary already) followed by 4 bytes with
    the given 0-indexed bit numbers set, matching kdc_option_flag_name/ap_option_flag_name's own
    numbering in kerberos.cpp."""
    bits = 0
    for b in flag_bits:
        bits |= 1 << (31 - b)
    return uni_p(0x03, b"\x00" + struct.pack("!I", bits))


def kb_principal_name(name_type: int, components: list) -> bytes:
    return kb_seq(ctx_c(0, kb_int(name_type)) + ctx_c(1, kb_seq(b"".join(kb_str(c) for c in components))))


def kb_encrypted_data(etype: int, cipher: bytes = b"\xAA\xBB\xCC\xDD") -> bytes:
    return kb_seq(ctx_c(0, kb_int(etype)) + ctx_c(2, uni_p(0x04, cipher)))


def kb_ticket(realm: str, sname: list, etype: int) -> bytes:
    """`Ticket ::= [APPLICATION 1] SEQUENCE {...}` -- note this carries its OWN APPLICATION tag
    even when embedded inside a context-tagged `ticket [5] Ticket` field elsewhere (the double-peel
    kerberos.cpp's decode_ticket documents)."""
    inner = kb_seq(ctx_c(0, kb_int(5)) + ctx_c(1, kb_str(realm)) + ctx_c(2, kb_principal_name(2, sname)) +
                    ctx_c(3, kb_encrypted_data(etype)))
    return app_c(1, inner)


def kb_as_req(*, cname: list, sname: list, etypes: list, realm: str = "EXAMPLE.COM",
              padata_present: bool = True, kdc_option_bits: list = (), additional_ticket=None,
              nonce: int = 12345) -> bytes:
    pvno = ctx_c(1, kb_int(5))
    msg_type = ctx_c(2, kb_int(10))
    parts = pvno + msg_type
    if padata_present:
        # PA-ENC-TIMESTAMP (2) -- padata-value content is opaque ciphertext, not decoded, so its
        # exact bytes don't matter here.
        padata_entry = kb_seq(ctx_c(1, kb_int(2)) + ctx_c(2, uni_p(0x04, b"\x30\x03\x01\x01\xff")))
        parts += ctx_c(3, kb_seq(padata_entry))
    body = (ctx_c(0, kb_bitstring(list(kdc_option_bits))) + ctx_c(1, kb_principal_name(1, cname)) +
            ctx_c(2, kb_str(realm)) + ctx_c(3, kb_principal_name(2, sname)) +
            ctx_c(5, kb_time("20370101000000")) + ctx_c(7, kb_int(nonce)) +
            ctx_c(8, kb_seq(b"".join(kb_int(e) for e in etypes))))
    if additional_ticket is not None:
        body += ctx_c(11, kb_seq(additional_ticket))
    inner = kb_seq(parts + ctx_c(4, kb_seq(body)))
    return app_c(10, inner)


def kb_tgs_req(*, sname: list, etypes: list, realm: str = "EXAMPLE.COM", nonce: int = 54321) -> bytes:
    pvno = ctx_c(1, kb_int(5))
    msg_type = ctx_c(2, kb_int(12))
    # PA-TGS-REQ (1) -- padata-value would normally be an AP-REQ authenticating to the TGS; its
    # exact bytes are opaque/not decoded here either, same as PA-ENC-TIMESTAMP above.
    padata_entry = kb_seq(ctx_c(1, kb_int(1)) + ctx_c(2, uni_p(0x04, b"\x30\x05\xa0\x03\x02\x01\x05")))
    padata = ctx_c(3, kb_seq(padata_entry))
    body = (ctx_c(0, kb_bitstring([])) + ctx_c(2, kb_str(realm)) + ctx_c(3, kb_principal_name(2, sname)) +
            ctx_c(5, kb_time("20370101000000")) + ctx_c(7, kb_int(nonce)) +
            ctx_c(8, kb_seq(b"".join(kb_int(e) for e in etypes))))
    inner = kb_seq(pvno + msg_type + padata + ctx_c(4, kb_seq(body)))
    return app_c(12, inner)


def kb_kdc_rep(*, is_tgs: bool, crealm: str, cname: list, ticket_sname: list, ticket_etype: int,
               enc_part_etype: int) -> bytes:
    msg_tag, msg_type_val = (13, 13) if is_tgs else (11, 11)
    pvno = ctx_c(0, kb_int(5))
    msg_type = ctx_c(1, kb_int(msg_type_val))
    crealm_f = ctx_c(3, kb_str(crealm))
    cname_f = ctx_c(4, kb_principal_name(1, cname))
    ticket_f = ctx_c(5, kb_ticket(crealm, ticket_sname, ticket_etype))
    enc_part_f = ctx_c(6, kb_encrypted_data(enc_part_etype))
    inner = kb_seq(pvno + msg_type + crealm_f + cname_f + ticket_f + enc_part_f)
    return app_c(msg_tag, inner)


def kb_krb_error(*, error_code: int, realm: str = "EXAMPLE.COM", sname: list = ("krbtgt", "EXAMPLE.COM"),
                  e_text: str = None) -> bytes:
    pvno = ctx_c(0, kb_int(5))
    msg_type = ctx_c(1, kb_int(30))
    stime = ctx_c(4, kb_time("20260922000000"))
    susec = ctx_c(5, kb_int(0))
    error_code_f = ctx_c(6, kb_int(error_code))
    realm_f = ctx_c(9, kb_str(realm))
    sname_f = ctx_c(10, kb_principal_name(2, list(sname)))
    parts = pvno + msg_type + stime + susec + error_code_f + realm_f + sname_f
    if e_text is not None:
        parts += ctx_c(11, kb_str(e_text))
    return app_c(30, kb_seq(parts))


def kb_ap_req(*, realm: str = "EXAMPLE.COM", sname: list = ("cifs", "fileserver.example.com"),
              ticket_etype: int = 18, ap_option_bits: list = ()) -> bytes:
    pvno = ctx_c(0, kb_int(5))
    msg_type = ctx_c(1, kb_int(14))
    ap_options = ctx_c(2, kb_bitstring(list(ap_option_bits)))
    ticket_f = ctx_c(3, kb_ticket(realm, list(sname), ticket_etype))
    authenticator = ctx_c(4, kb_encrypted_data(18, cipher=b"\x11\x22\x33"))
    inner = kb_seq(pvno + msg_type + ap_options + ticket_f + authenticator)
    return app_c(14, inner)


def kb_ap_rep() -> bytes:
    pvno = ctx_c(0, kb_int(5))
    msg_type = ctx_c(1, kb_int(15))
    enc_part = ctx_c(2, kb_encrypted_data(18, cipher=b"\x44\x55\x66"))
    return app_c(15, kb_seq(pvno + msg_type + enc_part))


def build_kerberos_sample():
    """Covers all 6 fully/structurally-decoded Kerberos message types, both flagship curated
    detections with an explicit negative case each (proving the curated-not-noisy bar is actually
    met, not just the positive cases -- see kerberos.hpp's file header comment), the always-on
    downgrade note, the delegation-shape structural note, a KRB-ERROR on a non-standard UDP port,
    and a TCP-framed message both whole and split across two segments (exercising
    KerberosTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the same
    split/rejoin shape build_twincat_sample already covers for AMS/TCP)."""
    packets = []
    ident = [0xD000]

    def add_udp(src_port, dst_port, payload, from_client):
        udp = udp_header(src_port, dst_port, payload)
        src_ip, dst_ip = (HMI_IP, PLC_IP) if from_client else (PLC_IP, HMI_IP)
        src_mac, dst_mac = (HMI_MAC, PLC_MAC) if from_client else (PLC_MAC, HMI_MAC)
        ip = ipv4_header(src_ip, dst_ip, 17, len(udp), ident[0]) + udp
        ident[0] += 1
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # 1) & 2) AS-REQ with no PA-ENC-TIMESTAMP (the roast-style request shape -- standing note),
    #    answered by a successful AS-REP whose enc-part uses RC4 -- correlates to #1 by cname and
    #    triggers the AS-REP-Roasting FLAGSHIP note (packet #2 only, not #1).
    add_udp(51000, KERBEROS_PORT,
            kb_as_req(cname=["alice"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[18, 17, 23],
                      padata_present=False),
            from_client=True)
    add_udp(KERBEROS_PORT, 51000,
            kb_kdc_rep(is_tgs=False, crealm="EXAMPLE.COM", cname=["alice"],
                       ticket_sname=["krbtgt", "EXAMPLE.COM"], ticket_etype=18, enc_part_etype=23),
            from_client=False)

    # 3) & 4) TGS-REQ for a specific SPN, answered by a TGS-REP whose Ticket's OWN enc-part uses
    #    RC4 -- correlates to #3 by sname and triggers the Kerberoasting FLAGSHIP note. Note this
    #    keys off the Ticket's enc-part etype (encrypted to the target SERVICE account's key), not
    #    the response's own outer enc-part etype (encrypted to the requesting CLIENT's session
    #    key, here deliberately left AES to prove the two are checked independently).
    add_udp(51000, KERBEROS_PORT,
            kb_tgs_req(sname=["cifs", "fileserver.example.com"], etypes=[18, 17, 23]),
            from_client=True)
    add_udp(KERBEROS_PORT, 51000,
            kb_kdc_rep(is_tgs=True, crealm="EXAMPLE.COM", cname=["alice"],
                       ticket_sname=["cifs", "fileserver.example.com"], ticket_etype=23,
                       enc_part_etype=18),
            from_client=False)

    # 5) Kerberoasting exclusion: a TGS-REP for a krbtgt sname (an ordinary TGT re-request, e.g. a
    #    renewal) with an RC4 ticket enc-part must NOT be flagged -- see kerberos.cpp's own
    #    "krbtgt tickets are excluded" comment. No preceding TGS-REQ needed; this only exercises
    #    the sname-prefix exclusion on the response side.
    add_udp(KERBEROS_PORT, 51000,
            kb_kdc_rep(is_tgs=True, crealm="EXAMPLE.COM", cname=["alice"],
                       ticket_sname=["krbtgt", "EXAMPLE.COM"], ticket_etype=23, enc_part_etype=18),
            from_client=False)

    # 6) Kerberoasting negative control: a TGS-REP for a real (non-krbtgt) SPN whose ticket enc-
    #    part is AES -- a "healthy", fully-patched-domain answer that must NOT be flagged either.
    add_udp(KERBEROS_PORT, 51000,
            kb_kdc_rep(is_tgs=True, crealm="EXAMPLE.COM", cname=["alice"],
                       ticket_sname=["ldap", "dc1.example.com"], ticket_etype=18, enc_part_etype=18),
            from_client=False)

    # 7)-10) AS-REP-Roasting negative case: ordinary Windows-style behavior is an AS-REQ with no
    #    preauth, a KDC_ERR_PREAUTH_REQUIRED KRB-ERROR, then a RETRY that DOES include
    #    PA-ENC-TIMESTAMP, finally answered by a successful AS-REP -- this must NOT trigger the
    #    flagship note, proving the correlation tracks the MOST RECENT request for a given cname
    #    (see kerberos.cpp's KerberosFlowState::pending_as_req, keyed by cname, overwritten on the
    #    retry) rather than latching onto the first, no-preauth attempt.
    add_udp(52000, KERBEROS_PORT,
            kb_as_req(cname=["bob"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[18, 17],
                      padata_present=False, nonce=1001),
            from_client=True)
    add_udp(KERBEROS_PORT, 52000, kb_krb_error(error_code=25, sname=["krbtgt", "EXAMPLE.COM"]),
            from_client=False)
    add_udp(52000, KERBEROS_PORT,
            kb_as_req(cname=["bob"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[18, 17],
                      padata_present=True, nonce=1002),
            from_client=True)
    add_udp(KERBEROS_PORT, 52000,
            kb_kdc_rep(is_tgs=False, crealm="EXAMPLE.COM", cname=["bob"],
                       ticket_sname=["krbtgt", "EXAMPLE.COM"], ticket_etype=18, enc_part_etype=18),
            from_client=False)

    # 11) A second, distinct KRB-ERROR code (KDC_ERR_C_PRINCIPAL_UNKNOWN) -- gives --stats'
    #    kerberos_error_counts_ more than one bucket to aggregate, and exercises the named-table
    #    lookup for a code other than PREAUTH_REQUIRED.
    add_udp(KERBEROS_PORT, 51000, kb_krb_error(error_code=6, sname=["nosuchuser", "EXAMPLE.COM"]),
            from_client=False)

    # 12) AP-REQ / 13) AP-REP -- structural-only coverage (ap-options flags, the embedded Ticket's
    #    visible realm/sname/enc-part etype; the Authenticator/AP-REP enc-part ciphertext itself is
    #    opaque without keys, deliberately not decoded -- see kerberos.hpp's DELIBERATELY NOT
    #    IMPLEMENTED list).
    add_udp(51500, KERBEROS_PORT,
            kb_ap_req(sname=["cifs", "fileserver.example.com"], ticket_etype=18,
                      ap_option_bits=[2]),  # mutual-required
            from_client=True)
    add_udp(KERBEROS_PORT, 51500, kb_ap_rep(), from_client=False)

    # 14) Downgrade note: an AS-REQ offering only DES/RC4 (no AES type at all) -- always-on, lower
    #    severity, standalone exposure visibility independent of the roasting flagship note.
    add_udp(53000, KERBEROS_PORT,
            kb_as_req(cname=["legacy-svc"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[3, 23],
                      nonce=2001),
            from_client=True)

    # 15) Delegation-shape structural note: forwardable(1)+proxiable(3) KDCOptions flags plus
    #    additional-tickets present (the S4U2Proxy/constrained-delegation shape) -- surfaced, never
    #    asserted as abuse. Also placed on a non-standard UDP port (4088, not 88) to exercise the
    #    "not a configured/standard Kerberos port" note alongside it.
    dummy_additional_ticket = kb_ticket("EXAMPLE.COM", ["svc1", "EXAMPLE.COM"], 18)
    delegation_req = kb_as_req(cname=["svc1"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[18, 23],
                                kdc_option_bits=[1, 3], additional_ticket=dummy_additional_ticket,
                                nonce=2002)
    udp = udp_header(53001, 4088, delegation_req)
    ip = ipv4_header(HMI_IP, PLC_IP, 17, len(udp), ident[0]) + udp
    ident[0] += 1
    packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_009_000 + i, i * 1000)
    (TESTS_DIR / "sample_kerberos.pcap").write_bytes(data)

    # --- TCP: one whole-frame AS-REQ, and the same message split across two TCP segments --------
    tcp_packets = []
    tcp_as_req = kb_as_req(cname=["carol"], sname=["krbtgt", "EXAMPLE.COM"], etypes=[18, 17, 23],
                            padata_present=False, nonce=3001)
    framed = struct.pack("!I", len(tcp_as_req)) + tcp_as_req

    def add_tcp(src_port, dst_port, seq, ack, payload, ident_val, from_client):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (HMI_IP, PLC_IP) if from_client else (PLC_IP, HMI_IP)
        src_mac, dst_mac = (HMI_MAC, PLC_MAC) if from_client else (PLC_MAC, HMI_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident_val) + tcp
        tcp_packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    # Whole frame, one TCP segment.
    add_tcp(51600, KERBEROS_PORT, 1000, 2000, framed, 0xE000, from_client=True)

    # The same message again, on a different source port, split across two TCP segments.
    split_at = 60
    add_tcp(51601, KERBEROS_PORT, 3000, 4000, framed[:split_at], 0xE001, from_client=True)
    add_tcp(51601, KERBEROS_PORT, 3000 + split_at, 4000, framed[split_at:], 0xE002, from_client=True)

    data = pcap_global_header()
    for i, pkt in enumerate(tcp_packets):
        data += pcap_record(pkt, 1_700_009_100 + i, i * 1000)
    (TESTS_DIR / "sample_kerberos_tcp.pcap").write_bytes(data)


def build_ldap_sample():
    """LDAP (RFC 4511), the second Windows AD-suite protocol -- see ldap.hpp's own file header
    comment for the wire format (IMPLICIT tagging, NOT Kerberos's own EXPLICIT convention) and the
    six curated attack/monitoring notes this fixture exercises with an explicit negative case each:
    an anonymous BindRequest (note 1); a cleartext-credential simple bind with no prior StartTLS
    (note 2 positive), the same shape preceded by a StartTLS ExtendedRequest on the same session
    (note 2 negative -- must NOT fire), a SASL GSSAPI bind (note 2 negative -- non-PLAIN mechanism
    is never flagged), and a SASL PLAIN bind with no StartTLS (note 2 positive via SASL); a
    SearchRequest filter referencing servicePrincipalName (note 3) and one referencing adminCount on
    the Global Catalog port 3268 (note 3, other technique); a userAccountControl bitwise-extensible-
    match filter against DONT_REQ_PREAUTH (note 4 positive) and the same shape against an unrelated
    bit (note 4/5 negative control); the same bitwise mechanism against TRUSTED_FOR_DELEGATION (note
    5 positive) and a second, independent path to note 5 via a bare msDS-AllowedToDelegateTo
    presence filter; one deliberately "ordinary" filter nesting AND/OR/NOT/equality/present/approx/
    greaterOrEqual/lessOrEqual/substrings all in one query -- exercising decode_filter's full
    rendering surface while proving notes 3-5 stay silent on a filter that doesn't touch any of
    their trigger attributes/bits (the "curated, not noisy" bar Kerberos's own fixture already
    proved); the "many SearchResultEntry, one SearchResultDone" correlation shape (with one binary-
    looking attribute value, rendered "(N bytes, binary)" rather than guessed); a CompareRequest/
    CompareResponse pair (compareTrue and compareFalse); an AbandonRequest; a BindRequest/
    BindResponse pair followed by an UnbindRequest; a SearchResultReference (referral URIs) followed
    by a SearchResultDone with resultCode=referral; every structural-only op (AddRequest/AddResponse,
    ModifyRequest/ModifyResponse, DelRequest/DelResponse, ModifyDNRequest/ModifyDNResponse,
    IntermediateResponse); a burst of failed binds (invalidCredentials) across distinct bind DNs
    followed by one successful bind -- note 6's --stats resultCode-aggregation, the password-spray
    signature; a BindRequest on a non-standard TCP port (5000, not 389/3268) -- LDAP is
    GateKind::TcpPortIndependent, so this must still be recognized as ldap, with a "not a
    configured/standard LDAP port" note that --ldap-port 5000 suppresses; and one SearchRequest split
    across two TCP segments (LdapTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload
    -- unlike Kerberos's own split test, LDAP has no 4-byte length prefix to account for, the
    message's own outer BER SEQUENCE length IS the framing). One Controls[0] (a Paged Results OID) is
    also attached to one SearchRequest, exercising control_oids."""
    packets = []
    ident = [0xB000]

    def make_flow(sport, dport=389, src_ip=HMI_IP, dst_ip=PLC_IP, src_mac=HMI_MAC, dst_mac=PLC_MAC):
        state = {"cseq": 10000, "sseq": 20000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, dport
                s_ip, d_ip = src_ip, dst_ip
                s_mac, d_mac = src_mac, dst_mac
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = dport, sport
                s_ip, d_ip = dst_ip, src_ip
                s_mac, d_mac = dst_mac, src_mac
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    # --- BER/LDAP wire-format helpers -- IMPLICIT tagging throughout, see ldap.hpp/ldap.cpp's own
    # header comments for the exact per-field tag/shape table each of these matches. -------------
    def L_id(n): return uni_p(2, ber_int(n))          # messageID INTEGER
    def L_dn(s): return uni_p(4, s.encode("utf-8"))    # LDAPDN / LDAPString -- OCTET STRING
    def L_enum(n): return uni_p(10, ber_int(n))        # ENUMERATED
    def L_bool(b): return uni_p(1, b"\x01" if b else b"\x00")
    def L_int(n): return uni_p(2, ber_int(n))

    def L_msg(message_id, op_bytes, controls_bytes=b""):
        return uni_c(16, L_id(message_id) + op_bytes + controls_bytes)  # LDAPMessage's own SEQUENCE

    def L_result(result_code, matched_dn="", diagnostic_message="", referrals=None):
        parts = L_enum(result_code) + L_dn(matched_dn) + L_dn(diagnostic_message)
        if referrals:
            parts += ctx_c(3, b"".join(L_dn(r) for r in referrals))  # referral [3]
        return parts

    def L_bind_req(version, dn, password=None, sasl_mechanism=None, sasl_credentials=None):
        parts = L_int(version) + L_dn(dn)
        if sasl_mechanism is not None:
            sasl_content = L_dn(sasl_mechanism)
            if sasl_credentials is not None:
                sasl_content += uni_p(4, sasl_credentials)
            parts += ctx_c(3, sasl_content)  # sasl [3] SaslCredentials
        else:
            # simple [0] OCTET STRING -- context-PRIMITIVE, the password bytes directly, no wrapper
            # tag (see ldap.hpp/ldap.cpp's own comment on exactly this field).
            parts += ctx_p(0, (password or "").encode("utf-8"))
        return app_c(0, parts)

    def L_bind_resp(result_code, matched_dn="", diagnostic_message=""):
        return app_c(1, L_result(result_code, matched_dn, diagnostic_message))

    def L_unbind_req():
        return app_p(2, b"")  # NULL body

    # --- SearchRequest's own recursive Filter CHOICE (RFC 4511 section 4.5.1). ------------------
    def F_and(*filters): return ctx_c(0, b"".join(filters))
    def F_or(*filters): return ctx_c(1, b"".join(filters))
    def F_not(f): return ctx_c(2, f)

    def F_eq(attr, val): return ctx_c(3, L_dn(attr) + uni_p(4, val.encode() if isinstance(val, str) else val))

    def F_substrings(attr, initial="", any_parts=(), final_part=""):
        subs = b""
        if initial: subs += ctx_p(0, initial.encode())
        for a in any_parts: subs += ctx_p(1, a.encode())
        if final_part: subs += ctx_p(2, final_part.encode())
        return ctx_c(4, L_dn(attr) + uni_c(16, subs))

    def F_ge(attr, val): return ctx_c(5, L_dn(attr) + uni_p(4, val.encode()))
    def F_le(attr, val): return ctx_c(6, L_dn(attr) + uni_p(4, val.encode()))
    def F_present(attr): return ctx_p(7, attr.encode())  # context-PRIMITIVE, raw attribute name bytes
    def F_approx(attr, val): return ctx_c(8, L_dn(attr) + uni_p(4, val.encode()))

    def F_extensible(matching_rule=None, type_=None, match_value="", dn_attrs=False):
        parts = b""
        if matching_rule: parts += ctx_p(1, matching_rule.encode())
        if type_: parts += ctx_p(2, type_.encode())
        parts += ctx_p(3, match_value.encode() if isinstance(match_value, str) else match_value)
        if dn_attrs: parts += ctx_p(4, b"\x01")
        return ctx_c(9, parts)

    def L_search_req(base, scope, deref, size_limit, time_limit, types_only, filter_bytes, attributes):
        parts = (L_dn(base) + L_enum(scope) + L_enum(deref) + L_int(size_limit) + L_int(time_limit) +
                 L_bool(types_only) + filter_bytes + uni_c(16, b"".join(L_dn(a) for a in attributes)))
        return app_c(3, parts)

    def L_search_result_entry(object_name, attrs):
        attr_parts = b""
        for attr_type, values in attrs.items():
            vals_bytes = b""
            for v in values:
                vb = v if isinstance(v, bytes) else v.encode("utf-8")
                vals_bytes += uni_p(4, vb)
            attr_parts += uni_c(16, L_dn(attr_type) + uni_c(17, vals_bytes))  # PartialAttribute
        return app_c(4, L_dn(object_name) + uni_c(16, attr_parts))

    def L_search_result_done(result_code, matched_dn="", diagnostic_message="", referrals=None):
        return app_c(5, L_result(result_code, matched_dn, diagnostic_message, referrals))

    def L_modify_req(entry): return app_c(6, L_dn(entry) + uni_c(16, b""))
    def L_modify_resp(result_code=0): return app_c(7, L_result(result_code))
    def L_add_req(entry): return app_c(8, L_dn(entry) + uni_c(16, b""))
    def L_add_resp(result_code=0): return app_c(9, L_result(result_code))
    def L_del_req(entry): return app_p(10, entry.encode("utf-8"))  # [APPLICATION 10] LDAPDN, primitive
    def L_del_resp(result_code=0): return app_c(11, L_result(result_code))

    def L_moddn_req(entry, new_rdn, delete_old_rdn=True):
        return app_c(12, L_dn(entry) + L_dn(new_rdn) + L_bool(delete_old_rdn))

    def L_moddn_resp(result_code=0): return app_c(13, L_result(result_code))

    def L_compare_req(entry, attr, value):
        return app_c(14, L_dn(entry) + uni_c(16, L_dn(attr) + L_dn(value)))

    def L_compare_resp(result_code): return app_c(15, L_result(result_code))

    def L_abandon_req(target_message_id):
        return app_p(16, ber_int(target_message_id))  # [APPLICATION 16] MessageID, primitive INTEGER

    def L_search_result_reference(uris):
        return app_c(19, b"".join(L_dn(u) for u in uris))

    def L_extended_req(name_oid, value=None):
        parts = ctx_p(0, name_oid.encode())
        if value is not None:
            parts += ctx_p(1, value)
        return app_c(23, parts)

    def L_extended_resp(result_code, matched_dn="", diagnostic_message="", response_name=None,
                         response_value=None):
        parts = L_result(result_code, matched_dn, diagnostic_message)
        if response_name is not None:
            parts += ctx_p(10, response_name.encode())
        if response_value is not None:
            parts += ctx_p(11, response_value)
        return app_c(24, parts)

    def L_intermediate_resp(): return app_c(25, b"")

    STARTTLS_OID = "1.3.6.1.4.1.1466.20037"
    AD_BITWISE_AND_OID = "1.2.840.113556.1.4.803"
    UAC_DONT_REQ_PREAUTH = 0x400000
    UAC_TRUSTED_FOR_DELEGATION = 0x80000
    UAC_ACCOUNTDISABLE = 0x2  # unrelated bit -- the note 4/5 negative control

    # ---------------------------------------------------------------------------------------------
    # Flow A (port 50101->389): SPN-sweep SearchRequest (note 3), a Paged Results control attached
    # (control_oids coverage), 2 SearchResultEntry (one carrying a binary-looking attribute value --
    # "(N bytes, binary)" rendering) then SearchResultDone -- the "many responses, one request"
    # correlation with its own entry-count note.
    # ---------------------------------------------------------------------------------------------
    fa = make_flow(50101)
    spn_filter = F_and(F_eq("objectClass", "user"), F_present("servicePrincipalName"))
    paged_results_control = ctx_c(0, uni_c(16, L_dn("1.2.840.113556.1.4.319")))
    fa(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, spn_filter,
                                    ["cn", "servicePrincipalName", "objectGUID"]),
                   controls_bytes=paged_results_control))
    # NOTE: a SearchResultEntry/SearchResultDone shares the SAME messageID as its own SearchRequest
    # (RFC 4511 section 4.1.1.1) -- unlike a fresh packet-sequence counter, this is what
    # LdapFlowState::pending_searches actually correlates on.
    fa(False, L_msg(1, L_search_result_entry(
        "cn=svc-sql,ou=Service Accounts,dc=example,dc=com",
        {"cn": ["svc-sql"], "servicePrincipalName": ["MSSQLSvc/db1.example.com:1433"]})))
    fa(False, L_msg(1, L_search_result_entry(
        "cn=svc-web,ou=Service Accounts,dc=example,dc=com",
        {"cn": ["svc-web"], "servicePrincipalName": ["HTTP/web1.example.com"],
         "objectGUID": [bytes(range(16))]})))
    fa(False, L_msg(1, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow B (port 50102->389): anonymous bind -- note 1, correlated BindRequest/BindResponse.
    # ---------------------------------------------------------------------------------------------
    fb = make_flow(50102)
    fb(True, L_msg(1, L_bind_req(3, "")))
    fb(False, L_msg(1, L_bind_resp(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow C (port 50103->389): cleartext simple bind, no StartTLS on this session -- note 2
    # positive.
    # ---------------------------------------------------------------------------------------------
    fc = make_flow(50103)
    fc(True, L_msg(1, L_bind_req(3, "cn=admin,dc=example,dc=com", password="Sup3rSecret!")))
    fc(False, L_msg(1, L_bind_resp(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow D (port 50104->389): StartTLS ExtendedRequest/Response, THEN a cleartext simple bind on
    # the SAME session -- note 2 NEGATIVE control (must NOT fire, proving starttls_seen suppresses
    # it). Also exercises ExtendedRequest/ExtendedResponse's own StartTLS-name recognition.
    # ---------------------------------------------------------------------------------------------
    fd = make_flow(50104)
    fd(True, L_msg(1, L_extended_req(STARTTLS_OID)))
    fd(False, L_msg(1, L_extended_resp(0, response_name=STARTTLS_OID)))
    fd(True, L_msg(2, L_bind_req(3, "cn=admin,dc=example,dc=com", password="Sup3rSecret!")))
    fd(False, L_msg(2, L_bind_resp(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow E (port 50105->389): SASL GSSAPI bind, no StartTLS -- note 2 NEGATIVE control (a
    # negotiated, non-cleartext SASL mechanism other than PLAIN is never flagged).
    # ---------------------------------------------------------------------------------------------
    fe = make_flow(50105)
    fe(True, L_msg(1, L_bind_req(3, "", sasl_mechanism="GSSAPI", sasl_credentials=bytes(range(20)))))
    fe(False, L_msg(1, L_bind_resp(14)))  # saslBindInProgress

    # ---------------------------------------------------------------------------------------------
    # Flow F (port 50106->389): SASL PLAIN bind, no StartTLS -- note 2 positive via the SASL path
    # (PLAIN carries an authzid\0authcid\0password triple in the same credentials field).
    # ---------------------------------------------------------------------------------------------
    ff = make_flow(50106)
    ff(True, L_msg(1, L_bind_req(3, "", sasl_mechanism="PLAIN",
                                  sasl_credentials=b"\x00admin\x00Sup3rSecret!")))
    ff(False, L_msg(1, L_bind_resp(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow G (port 50107->3268, Global Catalog): adminCount SearchRequest -- note 3's other
    # technique (privileged-account enumeration sweep).
    # ---------------------------------------------------------------------------------------------
    fg = make_flow(50107, dport=3268)
    fg(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, F_eq("adminCount", "1"),
                                    ["cn", "adminCount"])))
    fg(False, L_msg(1, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow H (port 50108->389): AS-REP-Roasting target-discovery filter (note 4 positive, the AD
    # bitwise-AND matching rule against userAccountControl's DONT_REQ_PREAUTH bit), then a second
    # SearchRequest on the SAME session using the same bitwise mechanism against an UNRELATED bit --
    # note 4/5 NEGATIVE control.
    # ---------------------------------------------------------------------------------------------
    fh = make_flow(50108)
    roast_filter = F_extensible(matching_rule=AD_BITWISE_AND_OID, type_="userAccountControl",
                                 match_value=str(UAC_DONT_REQ_PREAUTH))
    fh(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, roast_filter,
                                    ["cn", "userAccountControl"])))
    fh(False, L_msg(1, L_search_result_done(0)))
    unrelated_bit_filter = F_extensible(matching_rule=AD_BITWISE_AND_OID, type_="userAccountControl",
                                         match_value=str(UAC_ACCOUNTDISABLE))
    fh(True, L_msg(2, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, unrelated_bit_filter,
                                    ["cn", "userAccountControl"])))
    fh(False, L_msg(2, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow I (port 50109->389): delegation discovery via the bitwise TRUSTED_FOR_DELEGATION bit --
    # note 5 positive, path 1.
    # ---------------------------------------------------------------------------------------------
    fi = make_flow(50109)
    delegation_bit_filter = F_extensible(matching_rule=AD_BITWISE_AND_OID, type_="userAccountControl",
                                          match_value=str(UAC_TRUSTED_FOR_DELEGATION))
    fi(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, delegation_bit_filter,
                                    ["cn", "userAccountControl"])))
    fi(False, L_msg(1, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow I2 (port 50110->389): delegation discovery via a bare msDS-AllowedToDelegateTo presence
    # filter -- note 5 positive, path 2 (independent of the bitwise mechanism above).
    # ---------------------------------------------------------------------------------------------
    fi2 = make_flow(50110)
    fi2(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False,
                                     F_present("msDS-AllowedToDelegateTo"), ["cn"])))
    fi2(False, L_msg(1, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow J (port 50111->389): a deliberately ORDINARY filter -- AND/OR/NOT/equality/present/
    # approxMatch/greaterOrEqual/lessOrEqual/substrings all in one query, touching none of notes
    # 3-5's trigger attributes/bits -- proving the curated notes stay silent on ordinary traffic
    # while exercising decode_filter's full rendering surface.
    # ---------------------------------------------------------------------------------------------
    fj = make_flow(50111)
    ordinary_filter = F_and(
        F_eq("objectClass", "user"),
        F_or(F_eq("cn", "alice"), F_eq("cn", "bob")),
        F_not(F_eq("cn", "disabled")),
        F_present("mail"),
        F_approx("sn", "Smith"),
        F_ge("givenName", "A"),
        F_le("uid", "zzz"),
        F_substrings("description", initial="foo", any_parts=["bar"], final_part="baz"),
    )
    fj(True, L_msg(1, L_search_req("ou=Users,dc=example,dc=com", 1, 0, 100, 30, True, ordinary_filter,
                                    ["cn", "mail"])))
    fj(False, L_msg(1, L_search_result_entry("cn=alice,ou=Users,dc=example,dc=com",
                                              {"cn": ["alice"], "mail": ["alice@example.com"]})))
    fj(False, L_msg(1, L_search_result_done(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow K (port 50112->389): CompareRequest/CompareResponse -- compareTrue then compareFalse.
    # ---------------------------------------------------------------------------------------------
    fk = make_flow(50112)
    fk(True, L_msg(1, L_compare_req("cn=alice,dc=example,dc=com", "mail", "alice@example.com")))
    fk(False, L_msg(1, L_compare_resp(6)))  # compareTrue
    fk(True, L_msg(2, L_compare_req("cn=alice,dc=example,dc=com", "mail", "nobody@example.com")))
    fk(False, L_msg(2, L_compare_resp(5)))  # compareFalse

    # ---------------------------------------------------------------------------------------------
    # Flow L (port 50113->389): SearchRequest followed by an AbandonRequest targeting it (abandon
    # itself has no response, per RFC 4511 section 4.11).
    # ---------------------------------------------------------------------------------------------
    fl = make_flow(50113)
    fl(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, F_eq("objectClass", "user"),
                                    [])))
    fl(True, L_msg(2, L_abandon_req(1)))

    # ---------------------------------------------------------------------------------------------
    # Flow M (port 50114->389): ordinary bind/unbind lifecycle -- UnbindRequest coverage.
    # ---------------------------------------------------------------------------------------------
    fm = make_flow(50114)
    fm(True, L_msg(1, L_bind_req(3, "cn=svc-reader,dc=example,dc=com", password="ReaderPass1")))
    fm(False, L_msg(1, L_bind_resp(0)))
    fm(True, L_msg(2, L_unbind_req()))

    # ---------------------------------------------------------------------------------------------
    # Flow N (port 50115->389): SearchResultReference (2 referral URIs) followed by a
    # SearchResultDone with resultCode=referral.
    # ---------------------------------------------------------------------------------------------
    fn = make_flow(50115)
    fn(True, L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False, F_eq("objectClass", "user"),
                                    [])))
    fn(False, L_msg(1, L_search_result_reference(
        ["ldap://dc2.example.com/dc=example,dc=com", "ldap://dc3.example.com/dc=example,dc=com"])))
    fn(False, L_msg(1, L_search_result_done(10)))  # referral

    # ---------------------------------------------------------------------------------------------
    # Flow O (port 50116->389): every structural-only op (AddRequest/AddResponse,
    # ModifyRequest/ModifyResponse, DelRequest/DelResponse, ModifyDNRequest/ModifyDNResponse,
    # IntermediateResponse) -- recognized/named, not field-decoded, see ldap.hpp's own
    # STRUCTURAL-ONLY list.
    # ---------------------------------------------------------------------------------------------
    fo = make_flow(50116)
    fo(True, L_msg(1, L_add_req("cn=newuser,ou=Users,dc=example,dc=com")))
    fo(False, L_msg(1, L_add_resp(0)))
    fo(True, L_msg(2, L_modify_req("cn=newuser,ou=Users,dc=example,dc=com")))
    fo(False, L_msg(2, L_modify_resp(0)))
    fo(True, L_msg(3, L_del_req("cn=olduser,ou=Users,dc=example,dc=com")))
    fo(False, L_msg(3, L_del_resp(0)))
    fo(True, L_msg(4, L_moddn_req("cn=newuser,ou=Users,dc=example,dc=com", "cn=renameduser")))
    fo(False, L_msg(4, L_moddn_resp(0)))
    fo(False, L_msg(5, L_intermediate_resp()))

    # ---------------------------------------------------------------------------------------------
    # Flow P (port 50117->389): note 6 -- a burst of failed binds (invalidCredentials) across
    # distinct bind DNs (the password-spray signature), then one successful bind, all aggregated by
    # --stats' ldap_result_code_counts_ with no per-request correlation needed.
    # ---------------------------------------------------------------------------------------------
    fp = make_flow(50117)
    spray_targets = [
        ("cn=admin,dc=example,dc=com", "wrongpass1"),
        ("cn=svc-backup,dc=example,dc=com", "wrongpass2"),
        ("cn=jdoe,dc=example,dc=com", "wrongpass3"),
        ("cn=svc-backup,dc=example,dc=com", "wrongpass2b"),
    ]
    mid = 1
    for dn, pw in spray_targets:
        fp(True, L_msg(mid, L_bind_req(3, dn, password=pw)))
        fp(False, L_msg(mid, L_bind_resp(49)))  # invalidCredentials
        mid += 1
    fp(True, L_msg(mid, L_bind_req(3, "cn=administrator,dc=example,dc=com", password="CorrectHorse1")))
    fp(False, L_msg(mid, L_bind_resp(0)))

    # ---------------------------------------------------------------------------------------------
    # Flow Q (port 50118->5000, a non-standard/non-configured TCP port): anonymous BindRequest --
    # LDAP is GateKind::TcpPortIndependent, so this must still be recognized as ldap, with a
    # "seen on TCP port ..., which is not a configured/standard LDAP port (389/3268)" note that
    # --ldap-port 5000 suppresses.
    # ---------------------------------------------------------------------------------------------
    fq = make_flow(50118, dport=5000)
    fq(True, L_msg(1, L_bind_req(3, "")))
    fq(False, L_msg(1, L_bind_resp(0)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_030_000 + i, i * 1000)
    (TESTS_DIR / "sample_ldap.pcap").write_bytes(data)

    # ---------------------------------------------------------------------------------------------
    # TCP segment-split reassembly, in its own file -- a SearchRequest split across two TCP
    # segments, exercising LdapTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload.
    # Unlike Kerberos's own split test, LDAP has no 4-byte length prefix to strip first -- the
    # message's own outer BER SEQUENCE length IS the framing (ldap_tcp_declared_length).
    # ---------------------------------------------------------------------------------------------
    split_msg = L_msg(1, L_search_req("dc=example,dc=com", 2, 0, 0, 0, False,
                                       F_present("servicePrincipalName"),
                                       ["cn", "servicePrincipalName", "sAMAccountName", "memberOf"]))
    split_at = 40
    split_packets = []
    tcp1 = tcp_header(51410, 389, 5000, 6000, TCP_PSH | TCP_ACK, len(split_msg[:split_at])) + \
        split_msg[:split_at]
    ip1 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp1), 0xB100) + tcp1
    split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip1)
    tcp2 = tcp_header(51410, 389, 5000 + split_at, 6000, TCP_PSH | TCP_ACK,
                       len(split_msg[split_at:])) + split_msg[split_at:]
    ip2 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp2), 0xB101) + tcp2
    split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip2)

    data = pcap_global_header()
    for i, pkt in enumerate(split_packets):
        data += pcap_record(pkt, 1_700_030_100 + i, i * 1000)
    (TESTS_DIR / "sample_ldap_tcp_split.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# SMB2/NTLM (MS-SMB2/MS-NLMP), the third Windows AD-suite protocol -- see smb.hpp's/ntlm.hpp's
# own file header comments for the wire format (fixed-width little-endian fields throughout, NOT
# BER like Kerberos/LDAP). Every helper below matches the exact byte offsets smb.cpp/ntlm.cpp
# themselves read -- verified directly against those two files, not re-derived independently, the
# same "match the decoder's own documented offsets" discipline this file's other builders use.

def smb2_header(command, is_response, status=0, message_id=0, session_id=0, tree_id=0,
                 next_command=0, extra_flags=0):
    flags = extra_flags | (0x00000001 if is_response else 0)
    h = b"\xFESMB"
    h += struct.pack("<H", 64)            # StructureSize
    h += struct.pack("<H", 1)             # CreditCharge
    h += struct.pack("<I", status)        # Status
    h += struct.pack("<H", command)       # Command
    h += struct.pack("<H", 1)             # CreditReqResp
    h += struct.pack("<I", flags)         # Flags
    h += struct.pack("<I", next_command)  # NextCommand
    h += struct.pack("<Q", message_id)    # MessageId
    h += struct.pack("<I", 0)             # Reserved
    h += struct.pack("<I", tree_id)       # TreeId
    h += struct.pack("<Q", session_id)    # SessionId
    h += b"\x00" * 16                     # Signature -- never verified, see smb.hpp's own list
    assert len(h) == 64
    return h


def smb2_message(command, is_response, body=b"", **kw):
    return smb2_header(command, is_response, **kw) + body


def smb_with_prefix(smb2_area: bytes) -> bytes:
    """The 4-byte Zero+StreamProtocolLength Direct-TCP/NBSS prefix, [MS-SMB2] section 2.1 --
    identical on port 445 and port 139, see smb.hpp's own FRAMING paragraph."""
    n = len(smb2_area)
    return bytes([0x00, (n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF]) + smb2_area


def smb2_negotiate_req_body(dialects, security_mode=0x01):
    b = struct.pack("<H", 36)              # StructureSize
    b += struct.pack("<H", len(dialects))  # DialectCount
    b += struct.pack("<H", security_mode)  # SecurityMode
    b += struct.pack("<H", 0)              # Reserved
    b += struct.pack("<I", 0)              # Capabilities (client-side, not rendered)
    b += b"\x00" * 16                       # ClientGuid
    b += b"\x00" * 8                        # ClientStartTime/NegotiateContextOffset+Count+Rsvd2
    for d in dialects:
        b += struct.pack("<H", d)
    return b


def smb2_negotiate_resp_body(security_mode, dialect_revision=0x0311):
    b = struct.pack("<H", 65)              # StructureSize
    b += struct.pack("<H", security_mode)  # SecurityMode
    b += struct.pack("<H", dialect_revision)  # DialectRevision
    b += struct.pack("<H", 0)              # NegotiateContextCount/Reserved
    b += b"\xAA" * 16                       # ServerGuid
    b += struct.pack("<I", 0x00000007)     # Capabilities (DFS|LEASING|LARGE_MTU)
    b += b"\x00" * 12                       # MaxTransactSize/MaxReadSize/MaxWriteSize
    b += b"\x00" * 16                       # SystemTime/ServerStartTime
    b += struct.pack("<H", 0)              # SecurityBufferOffset -- unused by this decoder
    b += struct.pack("<H", 0)              # SecurityBufferLength
    b += b"\x00" * 4                        # padding to the documented 64-byte fixed size
    assert len(b) == 64
    return b


def smb2_session_setup_req_body(ntlm_blob: bytes, security_mode=0x01):
    header_len = 24
    buf_offset = 64 + header_len  # header(64) + this fixed body(24) -- offsets are relative to
                                   # the start of the SMB2 header, per [MS-SMB2], see smb.cpp's
                                   # own bounded() comment.
    b = struct.pack("<H", 25)              # StructureSize
    b += struct.pack("<B", 0)              # Flags (binding, not rendered)
    b += struct.pack("<B", security_mode)  # SecurityMode
    b += struct.pack("<I", 0)              # Capabilities
    b += struct.pack("<I", 0)              # Channel (reserved)
    b += struct.pack("<H", buf_offset)     # SecurityBufferOffset
    b += struct.pack("<H", len(ntlm_blob))  # SecurityBufferLength
    b += struct.pack("<Q", 0)              # PreviousSessionId
    assert len(b) == header_len
    return b + ntlm_blob


def smb2_session_setup_resp_body(ntlm_blob: bytes, session_flags=0):
    header_len = 8
    buf_offset = 64 + header_len
    b = struct.pack("<H", 9)               # StructureSize
    b += struct.pack("<H", session_flags)  # SessionFlags
    b += struct.pack("<H", buf_offset)     # SecurityBufferOffset
    b += struct.pack("<H", len(ntlm_blob))  # SecurityBufferLength
    assert len(b) == header_len
    return b + ntlm_blob


def smb2_tree_connect_req_body(path: str):
    header_len = 8
    path_bytes = path.encode("utf-16-le")
    path_offset = 64 + header_len
    b = struct.pack("<H", 9)               # StructureSize
    b += struct.pack("<H", 0)              # Flags/Reserved
    b += struct.pack("<H", path_offset)    # PathOffset
    b += struct.pack("<H", len(path_bytes))  # PathLength
    assert len(b) == header_len
    return b + path_bytes


def smb2_tree_connect_resp_body(share_type, share_flags=0, capabilities=0):
    b = struct.pack("<H", 16)              # StructureSize
    b += struct.pack("<B", share_type)     # ShareType
    b += struct.pack("<B", 0)              # Reserved
    b += struct.pack("<I", share_flags)    # ShareFlags
    b += struct.pack("<I", capabilities)   # Capabilities
    b += struct.pack("<I", 0)              # MaximalAccess -- not rendered, no OT-security value
    assert len(b) == 16
    return b


SMB_SHARE_TYPE_DISK, SMB_SHARE_TYPE_PIPE = 0x01, 0x02

NTLM_SIGNATURE = b"NTLMSSP\x00"
NTLM_FLAG_UNICODE = 0x00000001
NTLM_FLAG_REQUEST_TARGET = 0x00000004
NTLM_FLAG_NTLM = 0x00000200
NTLM_FLAG_ALWAYS_SIGN = 0x00008000
NTLM_FLAG_OEM_DOMAIN_SUPPLIED = 0x00001000
NTLM_FLAG_OEM_WORKSTATION_SUPPLIED = 0x00002000
NTLM_FLAG_TARGET_TYPE_DOMAIN = 0x00010000
NTLM_FLAG_EXTENDED_SESSIONSECURITY = 0x00080000
NTLM_FLAG_TARGET_INFO = 0x00800000
NTLM_FLAG_128 = 0x20000000
NTLM_FLAG_56 = 0x80000000


def ntlm_field(length, offset):
    return struct.pack("<HHI", length, length, offset)  # Len, MaxLen (==Len), Offset


def ntlm_negotiate_message(domain: str, workstation: str) -> bytes:
    flags = (NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM | NTLM_FLAG_ALWAYS_SIGN |
             NTLM_FLAG_OEM_DOMAIN_SUPPLIED | NTLM_FLAG_OEM_WORKSTATION_SUPPLIED |
             NTLM_FLAG_EXTENDED_SESSIONSECURITY | NTLM_FLAG_128 | NTLM_FLAG_56)
    domain_b = domain.encode("ascii")
    workstation_b = workstation.encode("ascii")
    header_len = 32  # sig(8)+type(4)+flags(4)+domain_field(8)+workstation_field(8)
    domain_off = header_len
    workstation_off = domain_off + len(domain_b)
    h = NTLM_SIGNATURE + struct.pack("<I", 1) + struct.pack("<I", flags)
    h += ntlm_field(len(domain_b), domain_off)
    h += ntlm_field(len(workstation_b), workstation_off)
    assert len(h) == header_len
    return h + domain_b + workstation_b


def ntlm_av_pair(av_id, value: bytes) -> bytes:
    return struct.pack("<HH", av_id, len(value)) + value


def ntlm_challenge_message(target_name: str, domain_name: str, computer_name: str) -> bytes:
    flags = (NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM |
             NTLM_FLAG_TARGET_TYPE_DOMAIN | NTLM_FLAG_EXTENDED_SESSIONSECURITY |
             NTLM_FLAG_TARGET_INFO | NTLM_FLAG_128 | NTLM_FLAG_56)
    header_len = 48  # sig+type+targetname_field+flags+challenge(8)+reserved(8)+targetinfo_field
    target_name_b = target_name.encode("utf-16-le")
    target_info = (ntlm_av_pair(2, domain_name.encode("utf-16-le")) +   # MsvAvNbDomainName
                   ntlm_av_pair(1, computer_name.encode("utf-16-le")) +  # MsvAvNbComputerName
                   ntlm_av_pair(7, b"\x00" * 8) +                        # MsvAvTimestamp, opaque
                   ntlm_av_pair(0, b""))                                 # MsvAvEOL terminator
    target_name_off = header_len
    target_info_off = target_name_off + len(target_name_b)
    h = NTLM_SIGNATURE + struct.pack("<I", 2)
    h += ntlm_field(len(target_name_b), target_name_off)
    h += struct.pack("<I", flags)
    h += b"\x11\x22\x33\x44\x55\x66\x77\x88"  # ServerChallenge -- a nonce, safe to render
    h += b"\x00" * 8                           # Reserved
    h += ntlm_field(len(target_info), target_info_off)
    assert len(h) == header_len
    return h + target_name_b + target_info


def ntlm_authenticate_message(domain: str, user: str, workstation: str, lm_len=24, nt_len=86) -> bytes:
    flags = (NTLM_FLAG_UNICODE | NTLM_FLAG_REQUEST_TARGET | NTLM_FLAG_NTLM |
             NTLM_FLAG_TARGET_TYPE_DOMAIN | NTLM_FLAG_EXTENDED_SESSIONSECURITY |
             NTLM_FLAG_128 | NTLM_FLAG_56)
    header_len = 64  # sig(8)+type(4)+6 field-descriptors(48)+flags(4)
    # Credential/keying material -- opaque filler bytes. This decoder deliberately never renders
    # LmChallengeResponse/NtChallengeResponse/EncryptedRandomSessionKey beyond presence+byte
    # length (see ntlm.hpp's own file header comment) -- the actual byte content here is
    # therefore irrelevant to what's being tested, only the lengths are.
    lm_bytes = b"\xAA" * lm_len
    nt_bytes = b"\xBB" * nt_len
    domain_b = domain.encode("utf-16-le")
    user_b = user.encode("utf-16-le")
    workstation_b = workstation.encode("utf-16-le")
    session_key_bytes = b""

    off = header_len
    lm_off = off; off += len(lm_bytes)
    nt_off = off; off += len(nt_bytes)
    domain_off = off; off += len(domain_b)
    user_off = off; off += len(user_b)
    workstation_off = off; off += len(workstation_b)
    session_key_off = off; off += len(session_key_bytes)

    h = NTLM_SIGNATURE + struct.pack("<I", 3)
    h += ntlm_field(len(lm_bytes), lm_off)
    h += ntlm_field(len(nt_bytes), nt_off)
    h += ntlm_field(len(domain_b), domain_off)
    h += ntlm_field(len(user_b), user_off)
    h += ntlm_field(len(workstation_b), workstation_off)
    h += ntlm_field(len(session_key_bytes), session_key_off)
    h += struct.pack("<I", flags)
    assert len(h) == header_len
    return h + lm_bytes + nt_bytes + domain_b + user_b + workstation_b + session_key_bytes


SMB_STATUS_SUCCESS = 0x00000000
SMB_STATUS_MORE_PROCESSING_REQUIRED = 0xC0000016
SMB_STATUS_LOGON_FAILURE = 0xC000006D

SMB_SESSION_FLAG_IS_GUEST = 0x0001
SMB_SESSION_FLAG_IS_NULL = 0x0002


def build_smb_sample():
    """SMB2/NTLM (MS-SMB2/MS-NLMP), the third Windows AD-suite protocol -- see smb.hpp's/
    ntlm.hpp's own file header comments for the wire format and the six curated attack/
    monitoring notes this fixture exercises with an explicit negative case each: a full
    NEGOTIATE/SESSION_SETUP(NTLM negotiate/challenge/authenticate)/TREE_CONNECT/LOGOFF exchange
    on flow A, where the NEGOTIATE Response's SecurityMode is SIGNING_ENABLED-but-not-REQUIRED
    (note 2 positive), the SESSION_SETUP legs carry NTLM (note 3, on every NTLM-bearing message),
    the terminal SESSION_SETUP Response closes the multi-leg handshake with a "succeeded"
    correlation note, and TREE_CONNECT to "\\\\SERVER\\IPC$" is flagged preliminarily on the
    request and confirmed via ShareType==pipe on the response (note 5, both forms) -- followed
    on the SAME session by an ordinary "\\\\SERVER\\data" TREE_CONNECT as note 5's own negative
    control (must NOT fire); flow B is bare SMB1 magic on port 139 (note 1); flow C is a full
    NTLM handshake ending in a SESSION_SETUP Response with SessionFlags.IS_GUEST set (note 4);
    flow D is a NEGOTIATE Response with SecurityMode SIGNING_ENABLED|SIGNING_REQUIRED -- note 2's
    own negative control (must NOT fire); flow E is an NTLM handshake ending in
    STATUS_LOGON_FAILURE -- note 6's --stats Status-count aggregation and the handshake's own
    "failed" correlation note; flow F is a compounded request (a NEGOTIATE Request chained via
    NextCommand to a SESSION_SETUP Request carrying an NTLM NEGOTIATE_MESSAGE, both in one TCP
    segment), exercising parse_smb2_chain's own compounding walk; flow G is a NEGOTIATE exchange
    on a non-standard TCP port (4455, not 445/139) -- SmbTcpDecoder is GateKind::TcpPortIndependent,
    so this must still decode as smb, with a "not a configured/standard SMB port" note that
    --smb-port 4455 suppresses. A NEGOTIATE Request split across two TCP segments (exercising
    smb_tcp_declared_length via Decoder::reassemble_tcp_payload) is written to its own file,
    sample_smb_tcp_split.pcap, mirroring how sample_ldap_tcp_split.pcap is kept separate. Every
    byte offset and note-trigger condition here was independently smoke-tested against a hand-
    built synthetic exchange, decoded and inspected in both --format text and --format json,
    BEFORE this fixture (and the CMakeLists.txt tests reading it) were written -- the same
    verification discipline Kerberos's/LDAP's own fixtures were held to."""
    packets = []
    ident = [0xC000]

    def make_flow(sport, dport=445, src_ip=HMI_IP, dst_ip=PLC_IP, src_mac=HMI_MAC, dst_mac=PLC_MAC):
        state = {"cseq": 30000, "sseq": 40000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, dport
                s_ip, d_ip = src_ip, dst_ip
                s_mac, d_mac = src_mac, dst_mac
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = dport, sport
                s_ip, d_ip = dst_ip, src_ip
                s_mac, d_mac = dst_mac, src_mac
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    mid = [100]

    def next_mid():
        mid[0] += 1
        return mid[0]

    # ---------------------------------------------------------------------------------------------
    # Flow A (port 52501->445): full happy-path exchange.
    # ---------------------------------------------------------------------------------------------
    fa = make_flow(52501)
    sess_id_a = 0xAABBCCDD11223344

    m_negreq = next_mid()
    fa(True, smb_with_prefix(smb2_message(
        0x00, False, smb2_negotiate_req_body([0x0202, 0x0210, 0x0300, 0x0302, 0x0311, 0x02FF]),
        message_id=m_negreq)))
    fa(False, smb_with_prefix(smb2_message(
        0x00, True, smb2_negotiate_resp_body(0x01),  # SIGNING_ENABLED only -- note 2 positive
        message_id=m_negreq, status=SMB_STATUS_SUCCESS)))

    ntlm_neg = ntlm_negotiate_message("CORP", "WIN10-PC")
    m_ss1 = next_mid()
    fa(True, smb_with_prefix(smb2_message(0x01, False, smb2_session_setup_req_body(ntlm_neg),
                                           message_id=m_ss1)))

    ntlm_chal = ntlm_challenge_message("CORP", "CORP", "DC1")
    fa(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(ntlm_chal), message_id=m_ss1,
        status=SMB_STATUS_MORE_PROCESSING_REQUIRED, session_id=sess_id_a)))

    ntlm_auth = ntlm_authenticate_message("CORP", "jdoe", "WIN10-PC")
    m_ss2 = next_mid()
    fa(True, smb_with_prefix(smb2_message(0x01, False, smb2_session_setup_req_body(ntlm_auth),
                                           message_id=m_ss2, session_id=sess_id_a)))
    fa(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(b"", session_flags=0), message_id=m_ss2,
        status=SMB_STATUS_SUCCESS, session_id=sess_id_a)))

    m_tc1 = next_mid()
    fa(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\IPC$"),
                                           message_id=m_tc1, session_id=sess_id_a)))
    fa(False, smb_with_prefix(smb2_message(
        0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_PIPE), message_id=m_tc1,
        status=SMB_STATUS_SUCCESS, session_id=sess_id_a, tree_id=1)))

    m_tc2 = next_mid()
    fa(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\data"),
                                           message_id=m_tc2, session_id=sess_id_a)))
    fa(False, smb_with_prefix(smb2_message(
        0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_DISK), message_id=m_tc2,
        status=SMB_STATUS_SUCCESS, session_id=sess_id_a, tree_id=2)))

    m_lo = next_mid()
    fa(True, smb_with_prefix(smb2_message(0x02, False, b"", message_id=m_lo, session_id=sess_id_a)))
    fa(False, smb_with_prefix(smb2_message(0x02, True, b"", message_id=m_lo, status=SMB_STATUS_SUCCESS,
                                            session_id=sess_id_a)))

    # ---------------------------------------------------------------------------------------------
    # Flow B (port 52502->139, NetBIOS Session Service port): SMB1 magic -- note 1.
    # ---------------------------------------------------------------------------------------------
    fb = make_flow(52502, dport=139)
    smb1_body = b"\xFFSMB" + b"\x72" + b"\x00" * 32  # SMB1 header stub (0x72 = Negotiate command)
    fb(True, smb_with_prefix(smb1_body))

    # ---------------------------------------------------------------------------------------------
    # Flow C (port 52503->445): NTLM handshake resulting in a GUEST session -- note 4.
    # ---------------------------------------------------------------------------------------------
    fc = make_flow(52503)
    sess_id_c = 0x1111222233334444
    m_c1 = next_mid()
    fc(True, smb_with_prefix(smb2_message(0x01, False,
                                           smb2_session_setup_req_body(ntlm_negotiate_message("", "")),
                                           message_id=m_c1)))
    fc(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(ntlm_challenge_message("", "", "")),
        message_id=m_c1, status=SMB_STATUS_MORE_PROCESSING_REQUIRED, session_id=sess_id_c)))
    m_c2 = next_mid()
    fc(True, smb_with_prefix(smb2_message(
        0x01, False, smb2_session_setup_req_body(ntlm_authenticate_message("", "guest", "")),
        message_id=m_c2, session_id=sess_id_c)))
    fc(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(b"", session_flags=SMB_SESSION_FLAG_IS_GUEST),
        message_id=m_c2, status=SMB_STATUS_SUCCESS, session_id=sess_id_c)))

    # ---------------------------------------------------------------------------------------------
    # Flow D (port 52504->445): NEGOTIATE Response with SIGNING_ENABLED|SIGNING_REQUIRED -- note 2
    # NEGATIVE control (must NOT fire).
    # ---------------------------------------------------------------------------------------------
    fd = make_flow(52504)
    m_d = next_mid()
    fd(True, smb_with_prefix(smb2_message(0x00, False, smb2_negotiate_req_body([0x0311]), message_id=m_d)))
    fd(False, smb_with_prefix(smb2_message(0x00, True, smb2_negotiate_resp_body(0x03), message_id=m_d,
                                            status=SMB_STATUS_SUCCESS)))

    # ---------------------------------------------------------------------------------------------
    # Flow E (port 52505->445): NTLM handshake FAILING with STATUS_LOGON_FAILURE -- note 6's
    # --stats aggregation and the handshake's own "failed" correlation note.
    # ---------------------------------------------------------------------------------------------
    fe = make_flow(52505)
    sess_id_e = 0x5555666677778888
    m_e1 = next_mid()
    fe(True, smb_with_prefix(smb2_message(
        0x01, False, smb2_session_setup_req_body(ntlm_negotiate_message("CORP", "ATK")), message_id=m_e1)))
    fe(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(ntlm_challenge_message("CORP", "CORP", "DC1")),
        message_id=m_e1, status=SMB_STATUS_MORE_PROCESSING_REQUIRED, session_id=sess_id_e)))
    m_e2 = next_mid()
    fe(True, smb_with_prefix(smb2_message(
        0x01, False, smb2_session_setup_req_body(ntlm_authenticate_message("CORP", "attacker", "ATK")),
        message_id=m_e2, session_id=sess_id_e)))
    fe(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(b""), message_id=m_e2,
        status=SMB_STATUS_LOGON_FAILURE, session_id=sess_id_e)))

    # ---------------------------------------------------------------------------------------------
    # Flow F (port 52506->445): a compounded request -- NEGOTIATE Request chained via NextCommand
    # to a SESSION_SETUP Request (NTLM NEGOTIATE_MESSAGE), both in one TCP segment.
    # ---------------------------------------------------------------------------------------------
    ff = make_flow(52506)
    sub1_body = smb2_negotiate_req_body([0x0311])
    sub1_len = 64 + len(sub1_body)
    pad = (-sub1_len) % 8  # pad to an 8-byte boundary, matching real compounding practice
    sub1 = smb2_message(0x00, False, sub1_body + b"\x00" * pad, message_id=next_mid(),
                         next_command=sub1_len + pad)
    sub2 = smb2_message(0x01, False, smb2_session_setup_req_body(ntlm_negotiate_message("CORP", "PAD")),
                         message_id=next_mid())
    ff(True, smb_with_prefix(sub1 + sub2))

    # ---------------------------------------------------------------------------------------------
    # Flow G (port 52507->4455, a non-standard/non-configured SMB port): NEGOTIATE Request/
    # Response -- SmbTcpDecoder is GateKind::TcpPortIndependent, so this must still decode as smb,
    # with a "not a configured/standard SMB port (445/139)" note that --smb-port 4455 suppresses.
    # ---------------------------------------------------------------------------------------------
    fg = make_flow(52507, dport=4455)
    m_g = next_mid()
    fg(True, smb_with_prefix(smb2_message(0x00, False, smb2_negotiate_req_body([0x0311]), message_id=m_g)))
    fg(False, smb_with_prefix(smb2_message(0x00, True, smb2_negotiate_resp_body(0x01), message_id=m_g,
                                            status=SMB_STATUS_SUCCESS)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_040_000 + i, i * 1000)
    (TESTS_DIR / "sample_smb.pcap").write_bytes(data)

    # ---------------------------------------------------------------------------------------------
    # TCP segment-split reassembly, in its own file -- a NEGOTIATE Request split across two TCP
    # segments, exercising smb_tcp_declared_length via Decoder::reassemble_tcp_payload. Unlike
    # LDAP's own split test, SMB2 DOES have its own 4-byte length prefix (like Kerberos), so the
    # split point below is deliberately chosen to fall inside that prefix's own declared-length
    # cascade, not just inside the SMB2 body.
    # ---------------------------------------------------------------------------------------------
    split_full = smb_with_prefix(smb2_message(0x00, False, smb2_negotiate_req_body(
        [0x0202, 0x0210, 0x0300, 0x0302, 0x0311]), message_id=9999))
    split_at = len(split_full) // 2
    split_packets = []
    tcp1 = tcp_header(51420, 445, 7000, 8000, TCP_PSH | TCP_ACK, len(split_full[:split_at])) + \
        split_full[:split_at]
    ip1 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp1), 0xB200) + tcp1
    split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip1)
    tcp2 = tcp_header(51420, 445, 7000 + split_at, 8000, TCP_PSH | TCP_ACK,
                       len(split_full[split_at:])) + split_full[split_at:]
    ip2 = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp2), 0xB201) + tcp2
    split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip2)

    data = pcap_global_header()
    for i, pkt in enumerate(split_packets):
        data += pcap_record(pkt, 1_700_040_100 + i, i * 1000)
    (TESTS_DIR / "sample_smb_tcp_split.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# Netlogon/DCE-RPC (MS-NRPC/MS-RPCE), the fourth and final Windows AD-suite protocol -- see
# netlogon.hpp's/dcerpc.hpp's own file header comments for the wire format. Every byte offset
# below matches those two files' own parsers exactly (smb2_create/write/read/ioctl/close_*_body
# match smb.cpp's own CREATE/WRITE/READ/IOCTL/CLOSE handling added alongside this phase; the
# dcerpc_*/ndr_* helpers match dcerpc.cpp/netlogon.cpp field-for-field), deliberately using plain
# struct.pack rather than a third-party NDR/RPC library -- impacket was a one-time empirical
# verification aid during planning only, never a dependency of this fixture generator.

NETLOGON_INTERFACE_UUID = "12345678-1234-abcd-ef00-01234567cffb"
SAMR_INTERFACE_UUID = "12345778-1234-abcd-ef00-0123456789ac"      # samr.hpp's own kSamrInterfaceUuid
LSARPC_INTERFACE_UUID = "12345778-1234-abcd-ef00-0123456789ab"    # lsarpc.hpp's own kLsarpcInterfaceUuid
SRVSVC_INTERFACE_UUID = "4b324fc8-1670-01d3-1278-5a47bf6ee188"    # srvsvc.hpp's own kSrvsvcInterfaceUuid
                                                                     # -- version 3.0, not 1.0
WKSSVC_INTERFACE_UUID = "6bffd098-a112-3610-9833-46c3f87e345a"    # wkssvc.hpp's own kWkssvcInterfaceUuid
DRSUAPI_INTERFACE_UUID = "e3514235-4b06-11d1-ab04-00c04fc2dcd2"   # drsuapi.hpp's own kDrsuapiInterfaceUuid
                                                                     # -- version 4.0, not 1.0
NDR32_TRANSFER_SYNTAX_UUID = "8a885d04-1ceb-11c9-9fe8-08002b104860"
FSCTL_PIPE_TRANSCEIVE = 0x0011C017
RPC_C_AUTHN_LEVEL_PKT_PRIVACY = 6


def smb2_create_req_body(name: str) -> bytes:
    header_len = 56
    name_bytes = name.encode("utf-16-le")
    name_offset = 64 + header_len
    b = struct.pack("<H", 57)                  # StructureSize
    b += struct.pack("<B", 0)                  # SecurityFlags
    b += struct.pack("<B", 0)                  # RequestedOplockLevel
    b += struct.pack("<I", 2)                  # ImpersonationLevel
    b += struct.pack("<Q", 0)                  # SmbCreateFlags
    b += struct.pack("<Q", 0)                  # Reserved
    b += struct.pack("<I", 0x001F01FF)         # DesiredAccess
    b += struct.pack("<I", 0)                  # FileAttributes
    b += struct.pack("<I", 0x00000007)         # ShareAccess
    b += struct.pack("<I", 1)                  # CreateDisposition (FILE_OPEN)
    b += struct.pack("<I", 0)                  # CreateOptions
    b += struct.pack("<H", name_offset)        # NameOffset
    b += struct.pack("<H", len(name_bytes))    # NameLength
    b += struct.pack("<I", 0)                  # CreateContextsOffset
    b += struct.pack("<I", 0)                  # CreateContextsLength
    assert len(b) == header_len
    return b + name_bytes


def smb2_create_resp_body(file_id: bytes, create_action=1) -> bytes:
    assert len(file_id) == 16
    b = struct.pack("<H", 89)      # StructureSize
    b += struct.pack("<B", 0)      # OplockLevel
    b += struct.pack("<B", 0)      # Flags
    b += struct.pack("<I", create_action)  # CreateAction
    b += b"\x00" * (8 * 6)          # CreationTime/LastAccessTime/LastWriteTime/ChangeTime/
                                     # AllocationSize/EndofFile
    b += struct.pack("<I", 0)      # FileAttributes
    b += struct.pack("<I", 0)      # Reserved2
    b += file_id                    # FileId (offset 64, 16 bytes)
    b += struct.pack("<I", 0)      # CreateContextsOffset
    b += struct.pack("<I", 0)      # CreateContextsLength
    assert len(b) == 88
    return b


def smb2_write_req_body(file_id: bytes, data: bytes, offset=0) -> bytes:
    header_len = 48
    data_offset = 64 + header_len
    b = struct.pack("<H", 49)              # StructureSize
    b += struct.pack("<H", data_offset)    # DataOffset
    b += struct.pack("<I", len(data))      # Length
    b += struct.pack("<Q", offset)         # Offset
    b += file_id                            # FileId
    b += struct.pack("<I", 0)              # Channel
    b += struct.pack("<I", 0)              # RemainingBytes
    b += struct.pack("<H", 0)              # WriteChannelInfoOffset
    b += struct.pack("<H", 0)              # WriteChannelInfoLength
    b += struct.pack("<I", 0)              # Flags
    assert len(b) == header_len
    return b + data


def smb2_write_resp_body(count: int) -> bytes:
    b = struct.pack("<H", 17)  # StructureSize
    b += struct.pack("<H", 0)  # Reserved
    b += struct.pack("<I", count)  # Count
    b += struct.pack("<I", 0)  # Remaining
    b += struct.pack("<H", 0)  # WriteChannelInfoOffset
    b += struct.pack("<H", 0)  # WriteChannelInfoLength
    assert len(b) == 16
    return b


def smb2_read_req_body(file_id: bytes, length=4096, offset=0) -> bytes:
    b = struct.pack("<H", 49)      # StructureSize
    b += struct.pack("<B", 0)      # Padding
    b += struct.pack("<B", 0)      # Flags
    b += struct.pack("<I", length)  # Length
    b += struct.pack("<Q", offset)  # Offset
    b += file_id                    # FileId
    b += struct.pack("<I", 1)      # MinimumCount
    b += struct.pack("<I", 0)      # Channel
    b += struct.pack("<I", 0)      # RemainingBytes
    b += struct.pack("<H", 0)      # ReadChannelInfoOffset
    b += struct.pack("<H", 0)      # ReadChannelInfoLength
    b += b"\x00"                    # Buffer (1-byte padding, StructureSize documents 49)
    assert len(b) == 49
    return b


def smb2_read_resp_body(data: bytes) -> bytes:
    header_len = 16
    data_offset = 64 + header_len
    b = struct.pack("<H", 17)              # StructureSize
    b += struct.pack("<B", data_offset)    # DataOffset (1 byte -- fits, 80 < 256)
    b += struct.pack("<B", 0)              # Reserved
    b += struct.pack("<I", len(data))      # DataLength
    b += struct.pack("<I", 0)              # DataRemaining
    b += struct.pack("<I", 0)              # Reserved2
    assert len(b) == header_len
    return b + data


def smb2_ioctl_req_body(file_id: bytes, ctl_code: int, input_data: bytes) -> bytes:
    header_len = 56
    input_offset = (64 + header_len) if input_data else 0
    b = struct.pack("<H", 57)                  # StructureSize
    b += struct.pack("<H", 0)                  # Reserved
    b += struct.pack("<I", ctl_code)           # CtlCode
    b += file_id                                # FileId
    b += struct.pack("<I", input_offset)       # InputOffset
    b += struct.pack("<I", len(input_data))    # InputCount
    b += struct.pack("<I", 0)                  # MaxInputResponse
    b += struct.pack("<I", 0)                  # OutputOffset
    b += struct.pack("<I", 0)                  # OutputCount
    b += struct.pack("<I", 4096)               # MaxOutputResponse
    b += struct.pack("<I", 0)                  # Flags
    b += struct.pack("<I", 0)                  # Reserved2
    assert len(b) == header_len
    return b + input_data


def smb2_ioctl_resp_body(file_id: bytes, ctl_code: int, output_data: bytes) -> bytes:
    header_len = 48
    output_offset = (64 + header_len) if output_data else 0
    b = struct.pack("<H", 49)                   # StructureSize
    b += struct.pack("<H", 0)                   # Reserved
    b += struct.pack("<I", ctl_code)            # CtlCode
    b += file_id                                 # FileId
    b += struct.pack("<I", 0)                   # InputOffset
    b += struct.pack("<I", 0)                   # InputCount
    b += struct.pack("<I", output_offset)       # OutputOffset
    b += struct.pack("<I", len(output_data))    # OutputCount
    b += struct.pack("<I", 0)                   # Flags
    b += struct.pack("<I", 0)                   # Reserved2
    assert len(b) == header_len
    return b + output_data


def smb2_close_req_body(file_id: bytes) -> bytes:
    b = struct.pack("<H", 24)  # StructureSize
    b += struct.pack("<H", 0)  # Flags
    b += struct.pack("<I", 0)  # Reserved
    b += file_id
    assert len(b) == 24
    return b


def smb2_close_resp_body() -> bytes:
    b = struct.pack("<H", 60)  # StructureSize
    b += struct.pack("<H", 0)  # Flags
    b += struct.pack("<I", 0)  # Reserved
    b += b"\x00" * (8 * 6)      # CreationTime/LastAccessTime/LastWriteTime/ChangeTime/
                                 # AllocationSize/EndofFile
    b += struct.pack("<I", 0)  # FileAttributes
    return b


def uuid_to_wire(u: str) -> bytes:
    """The inverse of dcerpc.cpp's own guid_to_string: Data1 4 bytes LE, Data2 2 bytes LE, Data3 2
    bytes LE, Data4 8 bytes byte-order-preserved."""
    p1, p2, p3, p4, p5 = u.split("-")
    data4 = bytes.fromhex(p4 + p5)
    assert len(data4) == 8
    return struct.pack("<IHH", int(p1, 16), int(p2, 16), int(p3, 16)) + data4


class NdrBuf:
    """Builds one DCE/RPC stub's own bytes, matching netlogon.cpp's own read_ndr_string/
    read_ndr_unique_string/align4 exactly: only ref_string/unique_string self-align (a conformant
    array's own MaxCount is a 4-byte field) -- u16/u32/raw never auto-pad, since netlogon.cpp
    itself never pads before a plain scalar read, only before a string."""

    def __init__(self):
        self.buf = bytearray()

    def _pad4(self):
        pad = (-len(self.buf)) % 4
        self.buf += b"\x00" * pad

    def u16(self, v):
        self.buf += struct.pack("<H", v)

    def u32(self, v):
        self.buf += struct.pack("<I", v)

    def raw(self, b: bytes):
        self.buf += bytes(b)

    def ref_string(self, s: str):
        self._pad4()
        chars = (s + "\x00").encode("utf-16-le")
        actual_count = len(chars) // 2
        self.buf += struct.pack("<III", actual_count, 0, actual_count)
        self.buf += chars
        self._pad4()

    def unique_string(self, s):
        self._pad4()
        if s is None:
            self.buf += struct.pack("<I", 0)  # NULL referent -- no string data follows
        else:
            self.buf += struct.pack("<I", 0x00020000)  # any nonzero referent id
            self.ref_string(s)

    def get(self) -> bytes:
        return bytes(self.buf)

    # -------------------------------------------------------------------------------------------
    # SAMR/LSARPC-specific NDR primitives, added for the SAMR/LSARPC phase -- each is the exact
    # inverse of one shared reader in dcerpc.cpp (read_ndr_sid/read_ndr_sid_pointer_array/
    # read_ndr_unicode_string_array/read_ndr_ulong_conformant_varying_array/
    # read_ndr_count_and_ptr_ulong_array), byte-for-byte, per those functions' own doc comments and
    # samr.cpp's/lsarpc.cpp's own per-opnum field-order comments. `_ref()` mints a small counter of
    # distinct nonzero referent IDs -- their exact values are never meaningful to the decoder (only
    # zero vs nonzero is), but distinct values make a hex dump easier to eyeball while debugging.
    _next_referent = [0x00100000]

    def _ref(self):
        NdrBuf._next_referent[0] += 1
        return NdrBuf._next_referent[0]

    def sid(self, sid_str: str):
        """RPC_SID, embedded by value (no referent of its own) -- read_ndr_sid's own inverse:
        hoisted MaximumCount(u32) + Revision(u8) + SubAuthorityCount(u8) +
        IdentifierAuthority(6 bytes, big-endian) + SubAuthority (N x u32 LE)."""
        parts = sid_str.split("-")
        assert parts[0] == "S", f"not a SID string: {sid_str!r}"
        revision = int(parts[1])
        authority = int(parts[2])
        subs = [int(p) for p in parts[3:]]
        self.u32(len(subs))
        self.buf += struct.pack("<B", revision)
        self.buf += struct.pack("<B", len(subs))
        self.buf += authority.to_bytes(6, "big")
        for s in subs:
            self.u32(s)

    def sid_pointer_array(self, sids):
        """The deferred body of a conformant array of pointer-to-RPC_SID -- read_ndr_sid_pointer_
        array's own inverse: MaximumCount(u32) + N referents(u32 each) + each nonzero referent's own
        SID, in order. Used both as a top-level embedded array (SamrGetAliasMembership's/LsarLookup-
        Sids' own SidArray, via sid_array_ptr below) and for LsarEnumerateAccounts' response."""
        self._pad4()
        n = len(sids)
        self.u32(n)
        refs = [self._ref() for _ in sids]
        for r in refs:
            self.u32(r)
        for sid_str in sids:
            self.sid(sid_str)

    def sid_array_ptr(self, sids):
        """SidArray{Count(u32), Sids:pointer-to-conformant-array-of-pointer-to-RPC_SID} -- the shape
        SamrGetAliasMembership's own request and LsarLookupSids' own request share (see samr.cpp's
        parse_get_alias_membership_request / lsarpc.cpp's parse_lookup_sids_request)."""
        self._pad4()
        self.u32(len(sids))
        if not sids:
            self.u32(0)
            return
        self.u32(self._ref())
        self.sid_pointer_array(sids)

    def unicode_string_array(self, names):
        """A top-level embedded conformant-varying array of RPC_UNICODE_STRING -- read_ndr_unicode_
        string_array's own inverse: MaxCount(u32)/Offset(u32)/ActualCount(u32), then each element's
        own fixed part (Length u16, MaximumLength u16, Referent u32) batched, THEN each nonzero
        referent's own deferred NDR string (ref_string's own shape), batched, in order. Used both as
        a bare top-level parameter (SamrLookupNamesInDomain's/LsarLookupNames' own request `Names`)
        and as one pointer's own deferred content (SamrLookupIdsInDomain's response `Names`, via
        names_ptr_array below)."""
        self._pad4()
        n = len(names)
        self.u32(n)
        self.u32(0)
        self.u32(n)
        refs = []
        for name in names:
            blen = len(name) * 2
            self.u16(blen)
            self.u16(blen + 2)
            r = self._ref()
            refs.append(r)
            self.u32(r)
        for name in names:
            self.ref_string(name)

    def names_ptr_array(self, names):
        """Names:SAMPR_RETURNED_USTRING_ARRAY{Count(u32), Element:pointer-to-array-of-RPC_UNICODE_
        STRING} -- SamrLookupIdsInDomain's own response shape (see samr.cpp's
        parse_lookup_ids_response): Count(u32) + Referent(u32) + [if nonzero: the pointed-to array's
        own unicode_string_array body]."""
        self._pad4()
        self.u32(len(names))
        if not names:
            self.u32(0)
            return
        self.u32(self._ref())
        self.unicode_string_array(names)

    def ulong_array(self, values):
        """A top-level embedded conformant-varying array of plain ULONG -- read_ndr_ulong_
        conformant_varying_array's own inverse: MaxCount(u32)/Offset(u32)/ActualCount(u32) + N x
        u32. Used for SamrLookupIdsInDomain's own request `RelativeIds`."""
        self._pad4()
        n = len(values)
        self.u32(n)
        self.u32(0)
        self.u32(n)
        for v in values:
            self.u32(v)

    def count_and_ptr_ulong_array(self, values):
        """A SAMPR_ULONG_ARRAY-shaped field -- read_ndr_count_and_ptr_ulong_array's own inverse:
        Count(u32) + Referent(u32) + [if nonzero: MaximumCount(u32) + N x u32]. Used for
        SamrLookupNamesInDomain's response RelativeIds/Use and SamrGetAliasMembership's response
        Membership."""
        self._pad4()
        n = len(values)
        self.u32(n)
        if n == 0:
            self.u32(0)
            return
        self.u32(self._ref())
        self.u32(n)
        for v in values:
            self.u32(v)

    def trust_info_array(self, entries):
        """The deferred body of a conformant array of LSAPR_TRUST_INFORMATION{Name, Sid} -- each
        entry's own fixed part (Name.Length u16, Name.MaximumLength u16, Name.Referent u32,
        Sid.Referent u32 -- 12 bytes) batched first, THEN each entry's own deferred Name string and
        Sid, in order (array-of-pointer-containing-elements rule -- see samr.cpp's own header
        comment). `entries` is a list of (name, sid_str) pairs. Reused both for
        LsarEnumerateTrustedDomains' own inline EnumerationBuffer.Information array and (with an
        outer Entries/Domains-pointer/MaxEntries wrapper -- see referenced_domain_list below) for
        LsarLookupNames'/LsarLookupSids' own ReferencedDomains field, since both share this element
        shape (lsarpc.cpp's own read_referenced_domain_list doc comment)."""
        self._pad4()
        n = len(entries)
        self.u32(n)
        refs = []
        for name, _sid in entries:
            blen = len(name) * 2
            self.u16(blen)
            self.u16(blen + 2)
            name_ref = self._ref()
            sid_ref = self._ref()
            refs.append((name_ref, sid_ref))
            self.u32(name_ref)
            self.u32(sid_ref)
        for (name, sid_str), (name_ref, sid_ref) in zip(entries, refs):
            if name_ref:
                self.ref_string(name)
            if sid_ref:
                self.sid(sid_str)

    def referenced_domain_list_field(self, entries):
        """LSAPR_REFERENCED_DOMAIN_LIST, reached via one top-level pointer field (ReferencedDomains)
        -- read_referenced_domain_list's own inverse: outer Referent(u32) + [if nonzero:
        Entries(u32) + Domains-Referent(u32) + MaxEntries(u32) + [if Domains-Referent nonzero: the
        Domains array's own trust_info_array body]]. `entries` is a list of (name, sid_str) pairs;
        an empty list writes a NULL outer referent (matching read_referenced_domain_list's own
        early-return-on-null-outer-referent behavior, so nothing else is written for that case)."""
        self._pad4()
        if not entries:
            self.u32(0)
            return
        self.u32(self._ref())
        self.u32(len(entries))
        self.u32(self._ref())
        self.u32(len(entries))
        # Domains' own conformant array header is exactly one MaximumCount field (no Offset/
        # ActualCount -- read_referenced_domain_list reads `maximum_count` directly), the same body
        # shape trust_info_array already writes; reuse it (its own leading _pad4() is a no-op here,
        # position is already a multiple of 4).
        self.trust_info_array(entries)

    def translated_sids_field(self, rids):
        """LSA_TRANSLATED_SID array (LsarLookupNames' own response `TranslatedSids`) -- read_
        translated_sids' own inverse: Entries(u32) + Referent(u32) + [if nonzero: MaximumCount(u32)
        + N x (Use(u32)=SidTypeUser, RelativeId(u32), DomainIndex(i32)=0) -- no deferred data, every
        field fixed-size]."""
        self._pad4()
        self.u32(len(rids))
        if not rids:
            self.u32(0)
            return
        self.u32(self._ref())
        self.u32(len(rids))
        for rid in rids:
            self.u32(1)  # Use = SidTypeUser -- discarded by the decoder, any nonzero value will do
            self.u32(rid)
            self.u32(0)  # DomainIndex -- discarded

    def translated_names_field(self, names):
        """LSA_TRANSLATED_NAME array (LsarLookupSids' own response `TranslatedNames`) -- read_
        translated_names' own inverse: Entries(u32) + Referent(u32) + [if nonzero: MaximumCount(u32)
        + N x (Use(u32), Name.Length(u16), Name.MaximumLength(u16), Name.Referent(u32),
        DomainIndex(i32)=0) fixed, THEN each nonzero-referent Name's own deferred string, batched]."""
        self._pad4()
        self.u32(len(names))
        if not names:
            self.u32(0)
            return
        self.u32(self._ref())
        self.u32(len(names))
        refs = []
        for name in names:
            self.u32(1)  # Use = SidTypeUser
            blen = len(name) * 2
            self.u16(blen)
            self.u16(blen + 2)
            r = self._ref()
            refs.append(r)
            self.u32(r)
            self.u32(0)  # DomainIndex
        for name, r in zip(names, refs):
            if r:
                self.ref_string(name)


def samr_enumerate_response_stub(enumeration_context: int, entries, count_returned: int,
                                  status: int = 0) -> bytes:
    """SamrEnumerateUsersInDomain(13)/SamrEnumerateAliasesInDomain(15) response -- see samr.cpp's
    own parse_enumerate_response doc comment for the exact (eager top-level / nested-batched) field
    order this mirrors. `entries` is a list of (rid:int, name:str) pairs, or None/[] for a NULL
    Buffer pointer."""
    b = NdrBuf()
    b.u32(enumeration_context)
    if not entries:
        b.u32(0)  # Buffer referent NULL
    else:
        b.u32(b._ref())  # Buffer referent
        b.u32(len(entries))  # EntriesRead (nested field, discarded by the decoder)
        b.u32(b._ref())  # inner (RID+Name array) referent
        b.u32(len(entries))  # MaximumCount
        refs = []
        for rid, name in entries:
            b.u32(rid)
            blen = len(name) * 2
            b.u16(blen)
            b.u16(blen + 2)
            r = b._ref()
            refs.append(r)
            b.u32(r)
        for (rid, name), r in zip(entries, refs):
            if r:
                b.ref_string(name)
    b.u32(count_returned)
    b.u32(status)
    return b.get()


def lsar_enumerate_accounts_response_stub(enumeration_context: int, sids, status: int = 0) -> bytes:
    """LsarEnumerateAccounts(11) response -- see lsarpc.cpp's own parse_enumerate_accounts_response:
    EnumerationContext(u32) + EntriesRead(u32, discard) + Information-Referent(u32) + [if nonzero:
    the Information array's own sid_pointer_array body] + ErrorCode(u32)."""
    b = NdrBuf()
    b.u32(enumeration_context)
    b.u32(len(sids))
    if not sids:
        b.u32(0)
    else:
        b.u32(b._ref())
        b.sid_pointer_array(sids)
    b.u32(status)
    return b.get()


def lsar_enumerate_trusted_domains_response_stub(enumeration_context: int, entries,
                                                  status: int = 0) -> bytes:
    """LsarEnumerateTrustedDomains(13) response -- see lsarpc.cpp's own
    parse_enumerate_trusted_domains_response: EnumerationContext(u32) + EntriesRead(u32, discard) +
    Information-Referent(u32) + [if nonzero: the Information array's own trust_info_array body] +
    ErrorCode(u32). `entries` is a list of (name, sid_str) pairs."""
    b = NdrBuf()
    b.u32(enumeration_context)
    b.u32(len(entries))
    if not entries:
        b.u32(0)
    else:
        b.u32(b._ref())
        b.trust_info_array(entries)
    b.u32(status)
    return b.get()


def srvsvc_share_enum_response_stub(shares, total_entries: int, status: int = 0) -> bytes:
    """NetrShareEnum(15) response -- see srvsvc.cpp's own parse_share_enum_response doc comment for
    the exact field order this mirrors (InfoStruct{Level, ShareInfo:SHARE_ENUM_UNION{tag, Level1:
    pointer to SHARE_INFO_1_CONTAINER{EntriesRead, Buffer:pointer to SHARE_INFO_1_ARRAY}}},
    TotalEntries, ResumeHandle, ErrorCode). `shares` is a list of (netname, type, remark) triples,
    level 1 only, or []/None for a NULL Buffer (in which case SHARE_INFO_1_ARRAY's own per-element
    "batched" shape -- fixed parts for every element, THEN every element's deferred string data, in
    order -- was empirically confirmed during planning by marshalling a real two-share response
    through impacket and hex-dumping the actual bytes; see srvsvc.hpp's own header comment)."""
    b = NdrBuf()
    b.u32(1)  # Level
    b.u32(1)  # ShareInfo.tag -- duplicate of Level, empirically confirmed present on the wire
    if not shares:
        b.u32(0)  # Level1 container referent NULL
    else:
        b.u32(b._ref())  # container referent
        b.u32(len(shares))  # EntriesRead (discarded by the decoder -- TotalEntries below is used)
        b.u32(b._ref())  # array referent
        b.u32(len(shares))  # MaximumCount
        refs = []
        for netname, share_type, remark in shares:
            nr = b._ref()
            b.u32(nr)
            b.u32(share_type)
            rr = b._ref()
            b.u32(rr)
            refs.append((nr, rr))
        for (netname, _share_type, remark), (nr, rr) in zip(shares, refs):
            if nr:
                b.ref_string(netname)
            if rr:
                b.ref_string(remark)
    b.u32(total_entries)
    b.u32(0)  # ResumeHandle -- NULL pointer
    b.u32(status)
    return b.get()


def srvsvc_share_get_info_response_stub(entry, status: int = 0) -> bytes:
    """NetrShareGetInfo(16) response -- see srvsvc.cpp's own parse_share_get_info_response doc
    comment: SHARE_INFO union{tag, ShareInfo1:pointer to a single (batched-shape, see
    read_share_info_1's own doc comment) SHARE_INFO_1}, ErrorCode. `entry` is a single (netname,
    type, remark) triple, or None for a NULL pointer."""
    b = NdrBuf()
    b.u32(1)  # tag
    if entry is None:
        b.u32(0)  # ShareInfo1 referent NULL
    else:
        b.u32(b._ref())  # ShareInfo1 referent
        netname, share_type, remark = entry
        nr = b._ref()
        b.u32(nr)
        b.u32(share_type)
        rr = b._ref()
        b.u32(rr)
        if nr:
            b.ref_string(netname)
        if rr:
            b.ref_string(remark)
    b.u32(status)
    return b.get()


def wksta_get_info_response_stub(platform_id: int, computername: str, langroup: str, ver_major: int,
                                  ver_minor: int, status: int = 0) -> bytes:
    """NetrWkstaGetInfo(0) response, level 100 only -- see wkssvc.cpp's own parse_get_info_response
    doc comment: WKSTA_INFO union{tag, WkstaInfo100:pointer to a nested WKSTA_INFO_100 struct (own
    "batched" shape -- platform_id/computername-referent/langroup-referent/ver_major/ver_minor fixed
    first, then computername's and langroup's own deferred strings, in that order -- empirically
    confirmed during planning)}, ErrorCode."""
    b = NdrBuf()
    b.u32(100)  # tag
    b.u32(b._ref())  # WkstaInfo100 referent
    b.u32(platform_id)
    cr = b._ref()
    b.u32(cr)
    lr = b._ref()
    b.u32(lr)
    b.u32(ver_major)
    b.u32(ver_minor)
    b.ref_string(computername)
    b.ref_string(langroup)
    b.u32(status)
    return b.get()


def wksta_user_enum_response_stub(users, total_entries: int, status: int = 0) -> bytes:
    """NetrWkstaUserEnum(2) response, level 1 only -- see wkssvc.cpp's own parse_user_enum_response
    doc comment: UserInfo{Level, WkstaUserInfo:WKSTA_USER_ENUM_UNION{tag, Level1:pointer to
    WKSTA_USER_INFO_1_CONTAINER{EntriesRead, Buffer:pointer to WKSTA_USER_INFO_1_ARRAY}}},
    TotalEntries, ResumeHandle (a PLAIN ULONG VALUE here, not a pointer -- empirically confirmed
    during planning, unlike SRVSVC's own NetrShareEnum response), ErrorCode. `users` is a list of
    (username, logon_domain, oth_domains, logon_server) 4-tuples, or []/None for a NULL Buffer."""
    b = NdrBuf()
    b.u32(1)  # Level
    b.u32(1)  # WkstaUserInfo.tag -- duplicate of Level
    if not users:
        b.u32(0)  # Level1 container referent NULL
    else:
        b.u32(b._ref())  # container referent
        b.u32(len(users))  # EntriesRead (discarded)
        b.u32(b._ref())  # array referent
        b.u32(len(users))  # MaximumCount
        refs = []
        for _u in users:
            r1, r2, r3, r4 = b._ref(), b._ref(), b._ref(), b._ref()
            b.u32(r1)
            b.u32(r2)
            b.u32(r3)
            b.u32(r4)
            refs.append((r1, r2, r3, r4))
        for (username, logon_domain, oth_domains, logon_server), (r1, r2, r3, r4) in zip(users, refs):
            if r1:
                b.ref_string(username)
            if r2:
                b.ref_string(logon_domain)
            if r3:
                b.ref_string(oth_domains)
            if r4:
                b.ref_string(logon_server)
    b.u32(total_entries)
    b.u32(0)  # ResumeHandle -- plain value, not a pointer
    b.u32(status)
    return b.get()


def netlogon_req_challenge_request_stub(primary_name, computer_name, client_challenge: bytes) -> bytes:
    assert len(client_challenge) == 8
    b = NdrBuf()
    b.unique_string(primary_name)
    b.ref_string(computer_name)
    b.raw(client_challenge)
    return b.get()


def netlogon_req_challenge_response_stub(server_challenge: bytes, status=0) -> bytes:
    assert len(server_challenge) == 8
    b = NdrBuf()
    b.raw(server_challenge)
    b.u32(status)
    return b.get()


def netlogon_authenticate_request_stub(opnum, primary_name, account_name, secure_channel_type,
                                        computer_name, client_credential: bytes, negotiate_flags=0):
    assert len(client_credential) == 8
    b = NdrBuf()
    b.unique_string(primary_name)
    b.ref_string(account_name)
    b.u16(secure_channel_type)
    b.ref_string(computer_name)
    b.raw(client_credential)
    if opnum != 5:
        b.u32(negotiate_flags)
    return b.get()


def netlogon_authenticate_response_stub(opnum, server_credential: bytes, negotiate_flags=0,
                                         account_rid=0, status=0):
    assert len(server_credential) == 8
    b = NdrBuf()
    b.raw(server_credential)
    if opnum != 5:
        b.u32(negotiate_flags)
    if opnum == 26:
        b.u32(account_rid)
    b.u32(status)
    return b.get()


def netlogon_password_set2_request_stub(primary_name, account_name, secure_channel_type,
                                         computer_name, include_authenticator=True,
                                         include_new_password=True, new_password_length=0):
    b = NdrBuf()
    b.unique_string(primary_name)
    b.ref_string(account_name)
    b.u16(secure_channel_type)
    b.ref_string(computer_name)
    if include_authenticator:
        b.raw(b"\x00" * 8)  # NETLOGON_AUTHENTICATOR.Credential
        b.u32(0)             # NETLOGON_AUTHENTICATOR.Timestamp
    if include_new_password:
        b.raw(b"\x00" * 512)  # NL_TRUST_PASSWORD's own opaque buffer
        b.u32(new_password_length)
    return b.get()


def dcerpc_context_element(context_id, abstract_uuid, abstract_ver_major=1, abstract_ver_minor=0,
                            transfer_uuid=NDR32_TRANSFER_SYNTAX_UUID, transfer_ver_major=2,
                            transfer_ver_minor=0):
    e = struct.pack("<H", context_id)
    e += struct.pack("<B", 1)  # n_transfer_syn
    e += struct.pack("<B", 0)  # reserved
    e += uuid_to_wire(abstract_uuid)
    e += struct.pack("<HH", abstract_ver_major, abstract_ver_minor)
    e += uuid_to_wire(transfer_uuid)
    e += struct.pack("<HH", transfer_ver_major, transfer_ver_minor)
    return e


def dcerpc_context_result(result_value, transfer_uuid=NDR32_TRANSFER_SYNTAX_UUID,
                           transfer_ver_major=2, transfer_ver_minor=0, reason=0):
    r = struct.pack("<HH", result_value, reason)
    r += uuid_to_wire(transfer_uuid)
    r += struct.pack("<HH", transfer_ver_major, transfer_ver_minor)
    assert len(r) == 24
    return r


def dcerpc_bind_body(context_elements, max_xmit=4280, max_recv=4280, assoc_group=0):
    b = struct.pack("<HH", max_xmit, max_recv)
    b += struct.pack("<I", assoc_group)
    b += struct.pack("<B", len(context_elements))  # n_context_elem
    b += b"\x00" * 3                                # reserved/reserved2
    for e in context_elements:
        b += e
    return b


def dcerpc_bind_ack_body(results, sec_addr: bytes = b"", max_xmit=4280, max_recv=4280,
                          assoc_group=0x00012345):
    b = struct.pack("<HH", max_xmit, max_recv)
    b += struct.pack("<I", assoc_group)
    b += struct.pack("<H", len(sec_addr))
    b += sec_addr
    pad = (-(16 + len(b))) % 4  # pad2, 4-byte-aligned relative to the PDU's own start
    b += b"\x00" * pad
    b += struct.pack("<B", len(results))  # n_results
    b += b"\x00" * 3                       # reserved
    for r in results:
        b += r
    return b


def dcerpc_request_body(context_id, opnum, stub: bytes) -> bytes:
    b = struct.pack("<I", len(stub))  # alloc_hint
    b += struct.pack("<H", context_id)
    b += struct.pack("<H", opnum)
    return b + stub


def dcerpc_response_body(context_id, stub: bytes) -> bytes:
    b = struct.pack("<I", len(stub))  # alloc_hint
    b += struct.pack("<H", context_id)
    b += struct.pack("<B", 0)  # cancel_count
    b += struct.pack("<B", 0)  # reserved
    return b + stub


def dcerpc_fault_body(context_id, fault_status) -> bytes:
    b = struct.pack("<I", 0)  # alloc_hint
    b += struct.pack("<H", context_id)
    b += struct.pack("<B", 0)  # cancel_count
    b += struct.pack("<B", 0)  # reserved
    b += struct.pack("<I", fault_status)
    b += struct.pack("<I", 0)  # reserved2
    return b


def dcerpc_pdu(ptype, call_id, body: bytes, pfc_flags=0x03, auth=None) -> bytes:
    """`auth`, if given, is (auth_type, auth_level, auth_value_bytes) -- the sec_trailer's own
    8-byte fixed header (auth_type/auth_level/auth_pad_length=0/reserved=0/auth_context_id=0) is
    built here; `auth_length` in the common header is auth_value's own length, per MS-RPCE (NOT
    including the 8-byte trailer header itself) -- see dcerpc.cpp's own trailer_start computation."""
    if auth:
        auth_type, auth_level, auth_value = auth
        trailer = struct.pack("<BBBB", auth_type, auth_level, 0, 0) + struct.pack("<I", 0) + auth_value
        auth_length = len(auth_value)
    else:
        trailer = b""
        auth_length = 0
    frag_length = 16 + len(body) + len(trailer)
    h = struct.pack("<BBBB", 5, 0, ptype, pfc_flags)  # rpc_vers, rpc_vers_minor, ptype, pfc_flags
    h += b"\x10\x00\x00\x00"  # packed_drep -- little-endian integers, ASCII chars
    h += struct.pack("<HH", frag_length, auth_length)
    h += struct.pack("<I", call_id)
    pdu = h + body + trailer
    assert len(pdu) == frag_length
    return pdu


def build_srvsvc_wkssvc_sample():
    """SRVSVC + WKSSVC (MS-SRVS/MS-WKST), phase 2 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI batch --
    see srvsvc.hpp's/wkssvc.hpp's own file header comments for the wire format, opnum coverage, and
    the empirically-derived NDR facts (SHARE_ENUM_UNION's own duplicate tag, SHARE_INFO_1's/
    WKSTA_INFO_100's/WKSTA_USER_INFO_1_ARRAY's own batched-pointer shapes) every full-decode opnum
    below relies on. Same transport-layer conventions as build_samr_lsarpc_sample (TREE_CONNECT to
    "\\\\SERVER\\IPC$", then CREATE of "\\PIPE\\srvsvc"/"\\PIPE\\wkssvc", WRITE+READ named-pipe
    transport throughout). Unlike SAMR+LSARPC, these two interfaces have no cross-interface note --
    bundled purely for scope-per-phase consistency (see srvsvc.hpp's own header comment). Flows, each
    its own TCP session:
      A: SRVSVC only -- bind (interface version 3.0, not 1.0) + NetrShareEnum(15) (two shares: an
         ordinary disk share and IPC$ as an STYPE_IPC|STYPE_SPECIAL admin share, exercising
         srvsvc_share_type_name's own "(special)" suffix), NetrShareGetInfo(16) (single share),
         NetrConnectionEnum(8)/NetrFileEnum(9)/NetrSessionEnum(12) (header-only request decode, NO
         response field decode -- see srvsvc.hpp's own OPNUM COVERAGE note), NetrShareAdd(14)/
         NetrShareDel(18) (structural-only, each firing its own curated note).
      B: WKSSVC only -- bind + NetrWkstaGetInfo(0) (level 100), NetrWkstaUserEnum(2) (level 1, two
         logged-on users), NetrWkstaTransportEnum(5) (header-only, same posture as flow A's own three
         SRVSVC header-only opnums), NetrJoinDomain2(22)/NetrUnjoinDomain2(23) (structural-only,
         non-empty non-zero stub bytes to prove the encrypted password material is never rendered,
         each firing its own curated note).
      C: a SEALED (auth_level=PKT_PRIVACY) NetrShareGetInfo request/response pair on an already-bound
         SRVSVC context -- the "sealed, N bytes, not decoded" fallback, no field decode, no note.
      D: a bind whose only offered context names Netlogon's OWN interface UUID (not SRVSVC's) on a
         "srvsvc"-named pipe -- the request that follows must stay structural (no srvsvc_calls at
         all), the same defensive negative control build_samr_lsarpc_sample's own flow F establishes.
    Every byte offset and note-trigger condition here was independently smoke-tested against a
    hand-built synthetic exchange, decoded and inspected in both --format text and --format json,
    BEFORE this fixture (and the CMakeLists.txt tests reading it) were written -- the same
    verification discipline every prior phase's own fixture was held to."""
    packets = []
    ident = [0xF000]
    port = [55001]
    file_id_counter = [1]
    call_id_counter = [1]

    def next_file_id() -> bytes:
        file_id_counter[0] += 1
        return struct.pack("<QQ", file_id_counter[0], 0xCAFE0000 + file_id_counter[0])

    def next_call_id() -> int:
        call_id_counter[0] += 1
        return call_id_counter[0]

    def make_flow():
        sport = port[0]
        port[0] += 1
        state = {"cseq": 80000, "sseq": 90000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, 445
                s_ip, d_ip = HMI_IP, PLC_IP
                s_mac, d_mac = HMI_MAC, PLC_MAC
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = 445, sport
                s_ip, d_ip = PLC_IP, HMI_IP
                s_mac, d_mac = PLC_MAC, HMI_MAC
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    mid = [500]

    def next_mid():
        mid[0] += 1
        return mid[0]

    def open_pipe(fx, session_id, tree_id, pipe_name):
        m_tc = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\IPC$"),
                                               message_id=m_tc, session_id=session_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_PIPE), message_id=m_tc,
            status=SMB_STATUS_SUCCESS, session_id=session_id, tree_id=tree_id)))

        file_id = next_file_id()
        m_cr = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x05, False, smb2_create_req_body("\\PIPE\\" + pipe_name),
                                               message_id=m_cr, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x05, True, smb2_create_resp_body(file_id), message_id=m_cr, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        return file_id

    def close_pipe(fx, session_id, tree_id, file_id):
        m_cl = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x06, False, smb2_close_req_body(file_id),
                                               message_id=m_cl, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x06, True, smb2_close_resp_body(), message_id=m_cl, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))

    pending_read_mid = [None]

    def write_read(fx, session_id, tree_id, file_id, pdu_bytes: bytes):
        m_w = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x09, False, smb2_write_req_body(file_id, pdu_bytes),
                                               message_id=m_w, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x09, True, smb2_write_resp_body(len(pdu_bytes)), message_id=m_w, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        m_r = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x08, False, smb2_read_req_body(file_id),
                                               message_id=m_r, session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = m_r

    def read_response(fx, session_id, tree_id, pdu_bytes: bytes):
        m_r = pending_read_mid[0]
        assert m_r is not None, "read_response called without a preceding write_read"
        fx(False, smb_with_prefix(smb2_message(
            0x08, True, smb2_read_resp_body(pdu_bytes), message_id=m_r, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = None

    def bind_and_ack(fx, session_id, tree_id, file_id, call_id, abstract_uuid, result=0,
                      abstract_ver_major=1, abstract_ver_minor=0):
        bind_pdu = dcerpc_pdu(11, call_id, dcerpc_bind_body(
            [dcerpc_context_element(0, abstract_uuid, abstract_ver_major=abstract_ver_major,
                                     abstract_ver_minor=abstract_ver_minor)]))
        bind_ack_pdu = dcerpc_pdu(12, call_id, dcerpc_bind_ack_body([dcerpc_context_result(result)]))
        write_read(fx, session_id, tree_id, file_id, bind_pdu)
        read_response(fx, session_id, tree_id, bind_ack_pdu)

    def call(fx, session_id, tree_id, file_id, opnum, req_stub, resp_stub, auth=None):
        cid = next_call_id()
        write_read(fx, session_id, tree_id, file_id,
                   dcerpc_pdu(0, cid, dcerpc_request_body(0, opnum, req_stub), auth=auth))
        read_response(fx, session_id, tree_id,
                      dcerpc_pdu(2, cid, dcerpc_response_body(0, resp_stub), auth=auth))

    # ---------------------------------------------------------------------------------------------
    # Flow A: SRVSVC only -- full-decode opnum coverage (NetrShareEnum/NetrShareGetInfo), the three
    # header-only enumeration opnums, and the two opnum-name-only curated-note opnums.
    # ---------------------------------------------------------------------------------------------
    fa = make_flow()
    sess_a, tree_a = 0xC000000000000001, 1
    fid_a = open_pipe(fa, sess_a, tree_a, "srvsvc")
    bind_and_ack(fa, sess_a, tree_a, fid_a, next_call_id(), SRVSVC_INTERFACE_UUID,
                 abstract_ver_major=3, abstract_ver_minor=0)

    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.u32(1); b.u32(1)
    resp = srvsvc_share_enum_response_stub(
        [("DATA", 0, "Data share"), ("IPC$", 3 | 0x80000000, "Remote IPC")], total_entries=2, status=0)
    call(fa, sess_a, tree_a, fid_a, 15, b.get(), resp)

    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.ref_string("DATA"); b.u32(1)
    resp = srvsvc_share_get_info_response_stub(("DATA", 0, "Data share"), status=0)
    call(fa, sess_a, tree_a, fid_a, 16, b.get(), resp)

    # NetrConnectionEnum(8) -- ServerName + Qualifier(1 extra unique string) + Level.
    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.unique_string(None); b.u32(0); b.u32(0)
    call(fa, sess_a, tree_a, fid_a, 8, b.get(), b"\x00" * 16)

    # NetrFileEnum(9) -- ServerName + BasePath + UserName (2 extra unique strings) + Level.
    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.unique_string(None); b.unique_string(None); b.u32(3); b.u32(3)
    call(fa, sess_a, tree_a, fid_a, 9, b.get(), b"\x00" * 16)

    # NetrSessionEnum(12) -- ServerName + ClientName + UserName (2 extra unique strings) + Level.
    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.unique_string(None); b.unique_string(None); b.u32(10); b.u32(10)
    call(fa, sess_a, tree_a, fid_a, 12, b.get(), b"\x00" * 16)

    # NetrShareAdd(14)/NetrShareDel(18) -- structural-only by design (see srvsvc.hpp's own OPNUM
    # COVERAGE note); stub bytes are deliberately non-empty to prove they're never field-decoded.
    call(fa, sess_a, tree_a, fid_a, 14, b"\xAB" * 40, b"\x00" * 8)
    call(fa, sess_a, tree_a, fid_a, 18, b"\xCD" * 24, b"\x00" * 4)

    close_pipe(fa, sess_a, tree_a, fid_a)

    # ---------------------------------------------------------------------------------------------
    # Flow B: WKSSVC only -- full-decode opnum coverage, header-only NetrWkstaTransportEnum, and the
    # two opnum-name-only curated-note opnums (join/unjoin, encrypted password material never
    # rendered).
    # ---------------------------------------------------------------------------------------------
    fb = make_flow()
    sess_b, tree_b = 0xC000000000000002, 1
    fid_b = open_pipe(fb, sess_b, tree_b, "wkssvc")
    bind_and_ack(fb, sess_b, tree_b, fid_b, next_call_id(), WKSSVC_INTERFACE_UUID)

    b = NdrBuf(); b.unique_string(None); b.u32(100)
    resp = wksta_get_info_response_stub(500, "WORKSTATION1", "CORP", 10, 0, status=0)
    call(fb, sess_b, tree_b, fid_b, 0, b.get(), resp)

    b = NdrBuf(); b.unique_string(None); b.u32(1); b.u32(1)
    resp = wksta_user_enum_response_stub(
        [("alice", "CORP", "", "\\\\DC1"), ("bob", "CORP", "", "\\\\DC1")], total_entries=2, status=0)
    call(fb, sess_b, tree_b, fid_b, 2, b.get(), resp)

    # NetrWkstaTransportEnum(5) -- header-only, same posture as flow A's own three SRVSVC
    # header-only opnums (see wkssvc.hpp's own OPNUM COVERAGE note).
    b = NdrBuf(); b.unique_string(None); b.u32(0); b.u32(0)
    call(fb, sess_b, tree_b, fid_b, 5, b.get(), b"\x00" * 16)

    # NetrJoinDomain2(22)/NetrUnjoinDomain2(23) -- structural-only by design; stub bytes are
    # deliberately non-empty and non-zero to prove the encrypted password material is never rendered.
    call(fb, sess_b, tree_b, fid_b, 22, b"\xEF" * 48, b"\x00" * 4)
    call(fb, sess_b, tree_b, fid_b, 23, b"\x12" * 32, b"\x00" * 4)

    close_pipe(fb, sess_b, tree_b, fid_b)

    # ---------------------------------------------------------------------------------------------
    # Flow C: a SEALED NetrShareGetInfo request/response pair on an already-bound SRVSVC context --
    # the "sealed, N bytes, not decoded" fallback.
    # ---------------------------------------------------------------------------------------------
    fc = make_flow()
    sess_c, tree_c = 0xC000000000000003, 1
    fid_c = open_pipe(fc, sess_c, tree_c, "srvsvc")
    bind_and_ack(fc, sess_c, tree_c, fid_c, next_call_id(), SRVSVC_INTERFACE_UUID,
                 abstract_ver_major=3, abstract_ver_minor=0)
    call(fc, sess_c, tree_c, fid_c, 16, b"\x45" * 20, b"\x46" * 16,
         auth=(16, 6, b"\x01\x02\x03\x04\x05\x06\x07\x08"))  # auth_type 16 (SSPI), auth_level 6 (PKT_PRIVACY)
    close_pipe(fc, sess_c, tree_c, fid_c)

    # ---------------------------------------------------------------------------------------------
    # Flow D: a bind whose only offered context names Netlogon's OWN interface UUID (not SRVSVC's) on
    # a "srvsvc"-named pipe -- the request that follows must stay structural (no srvsvc_calls at
    # all).
    # ---------------------------------------------------------------------------------------------
    fd = make_flow()
    sess_d, tree_d = 0xC000000000000004, 1
    fid_d = open_pipe(fd, sess_d, tree_d, "srvsvc")
    bind_and_ack(fd, sess_d, tree_d, fid_d, next_call_id(), NETLOGON_INTERFACE_UUID)
    b = NdrBuf(); b.unique_string("\\\\SRV1"); b.u32(1); b.u32(1)
    call(fd, sess_d, tree_d, fid_d, 15, b.get(), b"\x00" * 16)
    close_pipe(fd, sess_d, tree_d, fid_d)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_070_000 + i, i * 1000)
    (TESTS_DIR / "sample_srvsvc_wkssvc.pcap").write_bytes(data)


def drsuapi_bind_response_stub(ext_bytes, handle: bytes, status: int = 0) -> bytes:
    """DRSBind(0) response -- ppextServer (a DRS_EXTENSIONS blob the decoder deliberately skips
    past, never renders -- see drsuapi.cpp's own skip_drs_extensions doc comment: referent(u32) +
    [if nonzero: hoisted MaximumCount(u32) + cb(u32) + cb raw bytes + pad to 4]), phDrs (the bound
    context handle, 20 raw bytes), ErrorCode. `ext_bytes` is None for a NULL ppextServer, or the raw
    extension payload for a non-NULL one -- deliberately not required to be 4-byte-aligned, so a
    caller can exercise the decoder's own trailing-pad skip with e.g. a 3-byte payload, the same
    case empirically hex-dumped during planning (see drsuapi.hpp's own header comment)."""
    b = NdrBuf()
    if ext_bytes is None:
        b.u32(0)
    else:
        b.u32(b._ref())
        b.u32(len(ext_bytes))  # MaximumCount -- hoisted array bound, discarded by the decoder
        b.u32(len(ext_bytes))  # cb -- authoritative, self-describing
        b.raw(ext_bytes)
        b._pad4()
    assert len(handle) == 20
    b.raw(handle)
    b.u32(status)
    return b.get()


def build_drsuapi_sample():
    """DRSUAPI (MS-DRSR), phase 3 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI batch, alone rather than
    bundled -- see drsuapi.hpp's own header comment for the full design rationale, the OPNUM
    COVERAGE table this fixture exercises, and -- most importantly -- the EMPIRICALLY-DISCOVERED
    SCOPE CAVEAT this fixture's own gate name ("drsuapi", matching this batch's established
    per-interface pipe-name convention) is deliberately synthetic for: real DRSUAPI traffic
    predominantly rides a dynamically-negotiated raw TCP connection, not a named pipe, so this
    fixture -- like the decoder it exercises -- only demonstrates the narrow "also exposed over a
    named pipe" case, not real-world DCSync traffic as it actually appears on the wire. Same
    transport-layer conventions as build_srvsvc_wkssvc_sample (TREE_CONNECT to "\\\\SERVER\\IPC$",
    then CREATE of "\\PIPE\\drsuapi", WRITE+READ named-pipe transport throughout). Flows, each its
    own TCP session:
      A: bind (interface version 4.0, not 1.0) + DRSBind(0) with a non-NULL puuidClientDsa (full
         field decode) + a second DRSBind(0) with a NULL puuidClientDsa (negative control -- no
         client_dsa_guid field at all) -- the first call's own response carries a non-NULL, 3-byte
         (deliberately non-4-byte-aligned) DRS_EXTENSIONS payload, proving skip_drs_extensions'
         own padding logic doesn't misalign the phDrs/status fields that follow it; DRSUnbind(1)
         request/response (handle decode both directions); two separate DRSGetNCChanges(3) request/
         response pairs (structural-only, zero field decode of the deliberately non-zero/distinctive
         stub bytes each side sends -- proving the DCSync curated note fires on EVERY occurrence, not
         just the first, i.e. not sticky); one DRSCrackNames(12) request/response pair (structural-
         only, no curated note at all).
      B: a SEALED (auth_level=PKT_PRIVACY) DRSGetNCChanges request/response pair on an already-bound
         DRSUAPI context -- the "sealed, N bytes, not decoded" fallback, ZERO field decode, but the
         DCSync curated note STILL fires on the request side: the opnum itself lives in the DCE/RPC
         request header, not the encrypted stub, so it remains visible under RPC-layer sealing even
         though this codebase renders none of the sealed content -- the same posture Kerberos's/
         LDAP's/SMB's own curated notes already take on header-level facts that survive an otherwise
         opaque body.
      C: a bind whose only offered context names Netlogon's OWN interface UUID (not DRSUAPI's) on a
         "drsuapi"-named pipe -- the request that follows must stay structural (no drsuapi_calls at
         all), the same defensive negative control every other interface in this batch's own
         fixture already establishes.
    Every byte offset and note-trigger condition here was independently smoke-tested against a
    hand-built synthetic exchange, decoded and inspected in both --format text and --format json,
    BEFORE this fixture (and the CMakeLists.txt tests reading it) were written -- the same
    verification discipline every prior phase's own fixture was held to."""
    packets = []
    ident = [0xF100]
    port = [55101]
    file_id_counter = [1]
    call_id_counter = [1]

    def next_file_id() -> bytes:
        file_id_counter[0] += 1
        return struct.pack("<QQ", file_id_counter[0], 0xDADA0000 + file_id_counter[0])

    def next_call_id() -> int:
        call_id_counter[0] += 1
        return call_id_counter[0]

    def make_flow():
        sport = port[0]
        port[0] += 1
        state = {"cseq": 81000, "sseq": 91000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, 445
                s_ip, d_ip = HMI_IP, PLC_IP
                s_mac, d_mac = HMI_MAC, PLC_MAC
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = 445, sport
                s_ip, d_ip = PLC_IP, HMI_IP
                s_mac, d_mac = PLC_MAC, HMI_MAC
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    mid = [600]

    def next_mid():
        mid[0] += 1
        return mid[0]

    def open_pipe(fx, session_id, tree_id, pipe_name):
        m_tc = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\IPC$"),
                                               message_id=m_tc, session_id=session_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_PIPE), message_id=m_tc,
            status=SMB_STATUS_SUCCESS, session_id=session_id, tree_id=tree_id)))

        file_id = next_file_id()
        m_cr = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x05, False, smb2_create_req_body("\\PIPE\\" + pipe_name),
                                               message_id=m_cr, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x05, True, smb2_create_resp_body(file_id), message_id=m_cr, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        return file_id

    def close_pipe(fx, session_id, tree_id, file_id):
        m_cl = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x06, False, smb2_close_req_body(file_id),
                                               message_id=m_cl, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x06, True, smb2_close_resp_body(), message_id=m_cl, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))

    pending_read_mid = [None]

    def write_read(fx, session_id, tree_id, file_id, pdu_bytes: bytes):
        m_w = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x09, False, smb2_write_req_body(file_id, pdu_bytes),
                                               message_id=m_w, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x09, True, smb2_write_resp_body(len(pdu_bytes)), message_id=m_w, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        m_r = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x08, False, smb2_read_req_body(file_id),
                                               message_id=m_r, session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = m_r

    def read_response(fx, session_id, tree_id, pdu_bytes: bytes):
        m_r = pending_read_mid[0]
        assert m_r is not None, "read_response called without a preceding write_read"
        fx(False, smb_with_prefix(smb2_message(
            0x08, True, smb2_read_resp_body(pdu_bytes), message_id=m_r, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = None

    def bind_and_ack(fx, session_id, tree_id, file_id, call_id, abstract_uuid, result=0,
                      abstract_ver_major=1, abstract_ver_minor=0):
        bind_pdu = dcerpc_pdu(11, call_id, dcerpc_bind_body(
            [dcerpc_context_element(0, abstract_uuid, abstract_ver_major=abstract_ver_major,
                                     abstract_ver_minor=abstract_ver_minor)]))
        bind_ack_pdu = dcerpc_pdu(12, call_id, dcerpc_bind_ack_body([dcerpc_context_result(result)]))
        write_read(fx, session_id, tree_id, file_id, bind_pdu)
        read_response(fx, session_id, tree_id, bind_ack_pdu)

    def call(fx, session_id, tree_id, file_id, opnum, req_stub, resp_stub, auth=None):
        cid = next_call_id()
        write_read(fx, session_id, tree_id, file_id,
                   dcerpc_pdu(0, cid, dcerpc_request_body(0, opnum, req_stub), auth=auth))
        read_response(fx, session_id, tree_id,
                      dcerpc_pdu(2, cid, dcerpc_response_body(0, resp_stub), auth=auth))

    # ---------------------------------------------------------------------------------------------
    # Flow A: DRSBind (GUID present + NULL negative control), DRSUnbind, DRSGetNCChanges (x2, proving
    # the curated note is not sticky), DRSCrackNames (no note).
    # ---------------------------------------------------------------------------------------------
    fa = make_flow()
    sess_a, tree_a = 0xD000000000000001, 1
    fid_a = open_pipe(fa, sess_a, tree_a, "drsuapi")
    bind_and_ack(fa, sess_a, tree_a, fid_a, next_call_id(), DRSUAPI_INTERFACE_UUID,
                 abstract_ver_major=4, abstract_ver_minor=0)

    # DRSBind(0) -- non-NULL puuidClientDsa, and a response whose own DRS_EXTENSIONS payload is a
    # deliberately non-4-byte-aligned 3 bytes (0x99 x3), proving skip_drs_extensions' own trailing
    # pad computation doesn't misalign phDrs/ErrorCode.
    client_guid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
    b = NdrBuf(); b.u32(b._ref()); b.raw(uuid_to_wire(client_guid)); b.u32(0)  # pextClient NULL
    resp = drsuapi_bind_response_stub(b"\x99\x99\x99", b"\x01" * 20, status=0)
    call(fa, sess_a, tree_a, fid_a, 0, b.get(), resp)

    # DRSBind(0) again -- NULL puuidClientDsa this time (negative control: no client_dsa_guid field
    # at all in the decoded request).
    b = NdrBuf(); b.u32(0); b.u32(0)
    resp = drsuapi_bind_response_stub(None, b"\x02" * 20, status=0)
    call(fa, sess_a, tree_a, fid_a, 0, b.get(), resp)

    # DRSUnbind(1) -- handle decode both directions.
    b = NdrBuf(); b.raw(b"\x01" * 20)
    resp = NdrBuf(); resp.raw(b"\x00" * 20); resp.u32(0)
    call(fa, sess_a, tree_a, fid_a, 1, b.get(), resp.get())

    # DRSGetNCChanges(3) -- structural-only, ZERO field decode of the deliberately distinctive stub
    # bytes either side sends, fired TWICE to prove the curated note is not sticky.
    call(fa, sess_a, tree_a, fid_a, 3, b"\xFE" * 32, b"\xFD" * 64)
    call(fa, sess_a, tree_a, fid_a, 3, b"\xFE" * 32, b"\xFD" * 64)

    # DRSCrackNames(12) -- structural-only, no curated note at all.
    call(fa, sess_a, tree_a, fid_a, 12, b"\xAA" * 16, b"\xBB" * 16)

    close_pipe(fa, sess_a, tree_a, fid_a)

    # ---------------------------------------------------------------------------------------------
    # Flow B: a SEALED DRSGetNCChanges request/response pair on an already-bound DRSUAPI context --
    # the "sealed, N bytes, not decoded" fallback, and (unlike flow A's own two DRSGetNCChanges
    # calls) NO curated note, since this codebase never claims to have decoded a call it hasn't.
    # ---------------------------------------------------------------------------------------------
    fb = make_flow()
    sess_b, tree_b = 0xD000000000000002, 1
    fid_b = open_pipe(fb, sess_b, tree_b, "drsuapi")
    bind_and_ack(fb, sess_b, tree_b, fid_b, next_call_id(), DRSUAPI_INTERFACE_UUID,
                 abstract_ver_major=4, abstract_ver_minor=0)
    call(fb, sess_b, tree_b, fid_b, 3, b"\x55" * 24, b"\x56" * 16,
         auth=(16, 6, b"\x01\x02\x03\x04\x05\x06\x07\x08"))  # auth_type 16 (SSPI), auth_level 6 (PKT_PRIVACY)
    close_pipe(fb, sess_b, tree_b, fid_b)

    # ---------------------------------------------------------------------------------------------
    # Flow C: a bind whose only offered context names Netlogon's OWN interface UUID (not DRSUAPI's)
    # on a "drsuapi"-named pipe -- the request that follows must stay structural (no drsuapi_calls at
    # all).
    # ---------------------------------------------------------------------------------------------
    fc = make_flow()
    sess_c, tree_c = 0xD000000000000003, 1
    fid_c = open_pipe(fc, sess_c, tree_c, "drsuapi")
    bind_and_ack(fc, sess_c, tree_c, fid_c, next_call_id(), NETLOGON_INTERFACE_UUID)
    b = NdrBuf(); b.u32(0); b.u32(0)
    call(fc, sess_c, tree_c, fid_c, 0, b.get(), b"\x00" * 8)
    close_pipe(fc, sess_c, tree_c, fid_c)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_080_000 + i, i * 1000)
    (TESTS_DIR / "sample_drsuapi.pcap").write_bytes(data)


def build_netlogon_sample():
    """Netlogon/DCE-RPC (MS-NRPC/MS-RPCE), the fourth and final Windows AD-suite protocol -- see
    netlogon.hpp's/dcerpc.hpp's own file header comments for the wire format and smb.hpp's own
    STATE/CORRELATION section for exactly how a WRITE/READ/IOCTL message's own FileId gets tracked
    as the "netlogon" named pipe. Every flow below opens with a TREE_CONNECT to "\\\\SERVER\\IPC$"
    (ShareType pipe) then a CREATE of "\\PIPE\\netlogon", so smb.cpp's own pipe_shares/netlogon_pipes
    tracking is exercised on every flow, not assumed. Flows, each its own TCP session:
      A: ReqChallenge (non-zero challenge) + NetrServerAuthenticate3 (non-zero credential,
         status=SUCCESS) over WRITE+READ -- note 1 positive ("established"), note 2's own negative
         control (must NOT fire).
      B: ReqChallenge with an all-zero ClientChallenge -- note 2 positive (the Zerologon pattern).
      C: NetrServerAuthenticate2 (opnum 15, non-zero credential) -- note 3 positive (legacy method).
      D: NetrServerAuthenticate3 with SecureChannelType=WorkstationSecureChannel and AccountName
         "WORKSTATION1" (no trailing "$") -- note 4 positive; the same call with AccountName
         "WORKSTATION1$" is note 4's own negative control, on a second FileId in the same session.
      E: NetrServerPasswordSet2 -- note 5 (fires every time, not sticky).
      F: a sealed (auth_level=PKT_PRIVACY) NetrServerPasswordSet2 call on an already-bound
         Netlogon context -- exercises the "sealed, N bytes, not decoded" fallback (no field decode
         at all, no note 5).
      G: a bind whose only offered context names a NON-Netlogon interface UUID on a
         "netlogon"-named pipe -- the request that follows must stay structural-only (no
         netlogon_calls), the defensive "bind confirmed something else" edge case.
      H: the same ReqChallenge+Authenticate3 exchange as flow A, but against a "lsarpc"-named pipe
         instead of "netlogon" -- the negative control proving only "netlogon" is ever tracked.
      I: the same ReqChallenge+Authenticate3 exchange as flow A, but carried over
         IOCTL(FSCTL_PIPE_TRANSCEIVE) request/response pairs instead of separate WRITE/READ --
         the other real-world named-pipe transport shape.
    Every byte offset and note-trigger condition here was independently smoke-tested against a
    hand-built synthetic exchange, decoded and inspected in both --format text and --format json,
    BEFORE this fixture (and the CMakeLists.txt tests reading it) were written -- the same
    verification discipline every prior phase's own fixture was held to."""
    packets = []
    ident = [0xD000]
    port = [53001]
    file_id_counter = [1]
    call_id_counter = [1]

    def next_file_id() -> bytes:
        file_id_counter[0] += 1
        return struct.pack("<QQ", file_id_counter[0], 0xF00D0000 + file_id_counter[0])

    def next_call_id() -> int:
        call_id_counter[0] += 1
        return call_id_counter[0]

    def make_flow():
        sport = port[0]
        port[0] += 1
        state = {"cseq": 20000, "sseq": 30000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, 445
                s_ip, d_ip = HMI_IP, PLC_IP
                s_mac, d_mac = HMI_MAC, PLC_MAC
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = 445, sport
                s_ip, d_ip = PLC_IP, HMI_IP
                s_mac, d_mac = PLC_MAC, HMI_MAC
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    mid = [200]

    def next_mid():
        mid[0] += 1
        return mid[0]

    def open_pipe(fx, session_id, tree_id, pipe_name="netlogon"):
        """TREE_CONNECT to an IPC$-style pipe share, then CREATE of \\PIPE\\<pipe_name>. Returns the
        16-byte FileId the CREATE Response reports."""
        m_tc = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\IPC$"),
                                               message_id=m_tc, session_id=session_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_PIPE), message_id=m_tc,
            status=SMB_STATUS_SUCCESS, session_id=session_id, tree_id=tree_id)))

        file_id = next_file_id()
        m_cr = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x05, False, smb2_create_req_body("\\PIPE\\" + pipe_name),
                                               message_id=m_cr, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x05, True, smb2_create_resp_body(file_id), message_id=m_cr, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        return file_id

    def close_pipe(fx, session_id, tree_id, file_id):
        m_cl = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x06, False, smb2_close_req_body(file_id),
                                               message_id=m_cl, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x06, True, smb2_close_resp_body(), message_id=m_cl, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))

    pending_read_mid = [None]  # shared between write_read/read_response, see read_response's own
                                 # doc comment -- SMB2 request/response correlation is by MessageId,
                                 # so the READ Response below MUST reuse the matching READ Request's
                                 # own MessageId, not mint a fresh one.

    def write_read(fx, session_id, tree_id, file_id, pdu_bytes: bytes):
        """The WRITE(request)+READ(response) named-pipe transport shape. The READ Request's own
        MessageId is stashed in pending_read_mid for read_response (below) to reuse."""
        m_w = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x09, False, smb2_write_req_body(file_id, pdu_bytes),
                                               message_id=m_w, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x09, True, smb2_write_resp_body(len(pdu_bytes)), message_id=m_w, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        m_r = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x08, False, smb2_read_req_body(file_id),
                                               message_id=m_r, session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = m_r

    def read_response(fx, session_id, tree_id, pdu_bytes: bytes):
        """Sends the READ Response matching the most recent write_read's own READ Request -- MUST
        reuse that request's MessageId (SMB2's own request/response correlation key), not a fresh
        one, or smb.cpp's own pending_requests map (keyed by MessageId) never finds the match and
        this response is never decoded as DCE/RPC at all."""
        m_r = pending_read_mid[0]
        assert m_r is not None, "read_response called without a preceding write_read"
        fx(False, smb_with_prefix(smb2_message(
            0x08, True, smb2_read_resp_body(pdu_bytes), message_id=m_r, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = None

    def ioctl_pipe_transceive(fx, session_id, tree_id, file_id, request_pdu: bytes, response_pdu: bytes):
        """The IOCTL(FSCTL_PIPE_TRANSCEIVE) write-then-read-in-one-call transport shape."""
        m_i = next_mid()
        fx(True, smb_with_prefix(smb2_message(
            0x0B, False, smb2_ioctl_req_body(file_id, FSCTL_PIPE_TRANSCEIVE, request_pdu),
            message_id=m_i, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x0B, True, smb2_ioctl_resp_body(file_id, FSCTL_PIPE_TRANSCEIVE, response_pdu),
            message_id=m_i, status=SMB_STATUS_SUCCESS, session_id=session_id, tree_id=tree_id)))

    def bind_and_ack(fx, session_id, tree_id, file_id, call_id, abstract_uuid=NETLOGON_INTERFACE_UUID,
                      result=0):
        bind_pdu = dcerpc_pdu(11, call_id, dcerpc_bind_body(
            [dcerpc_context_element(0, abstract_uuid)]))
        bind_ack_pdu = dcerpc_pdu(12, call_id, dcerpc_bind_ack_body([dcerpc_context_result(result)]))
        write_read(fx, session_id, tree_id, file_id, bind_pdu)
        read_response(fx, session_id, tree_id, bind_ack_pdu)

    # ---------------------------------------------------------------------------------------------
    # Flow A: normal ReqChallenge -> NetrServerAuthenticate3 handshake -- note 1 positive, note 2
    # negative control.
    # ---------------------------------------------------------------------------------------------
    fa = make_flow()
    sess_a, tree_a = 0xA000000000000001, 1
    fid_a = open_pipe(fa, sess_a, tree_a)
    bind_and_ack(fa, sess_a, tree_a, fid_a, next_call_id())

    call_id = next_call_id()
    req_stub = netlogon_req_challenge_request_stub("DC1", "WIN10-PC", b"\x11\x22\x33\x44\x55\x66\x77\x88")
    write_read(fa, sess_a, tree_a, fid_a, dcerpc_pdu(0, call_id, dcerpc_request_body(0, 4, req_stub)))
    resp_stub = netlogon_req_challenge_response_stub(b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00", status=0)
    read_response(fa, sess_a, tree_a, dcerpc_pdu(2, call_id, dcerpc_response_body(0, resp_stub)))

    call_id = next_call_id()
    auth_req_stub = netlogon_authenticate_request_stub(
        26, "DC1", "WIN10-PC$", 2, "WIN10-PC", b"\x12\x34\x56\x78\x9A\xBC\xDE\xF0",
        negotiate_flags=0x612FFFFF)
    write_read(fa, sess_a, tree_a, fid_a,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 26, auth_req_stub)))
    auth_resp_stub = netlogon_authenticate_response_stub(
        26, b"\x0F\x1E\x2D\x3C\x4B\x5A\x69\x78", negotiate_flags=0x612FFFFF, account_rid=1105, status=0)
    read_response(fa, sess_a, tree_a, dcerpc_pdu(2, call_id, dcerpc_response_body(0, auth_resp_stub)))
    close_pipe(fa, sess_a, tree_a, fid_a)

    # ---------------------------------------------------------------------------------------------
    # Flow B: all-zero ClientChallenge -- note 2 positive (Zerologon pattern).
    # ---------------------------------------------------------------------------------------------
    fb = make_flow()
    sess_b, tree_b = 0xB000000000000001, 1
    fid_b = open_pipe(fb, sess_b, tree_b)
    bind_and_ack(fb, sess_b, tree_b, fid_b, next_call_id())
    call_id = next_call_id()
    zero_req_stub = netlogon_req_challenge_request_stub("DC1", "ATTACKER-PC", b"\x00" * 8)
    write_read(fb, sess_b, tree_b, fid_b, dcerpc_pdu(0, call_id, dcerpc_request_body(0, 4, zero_req_stub)))
    zero_resp_stub = netlogon_req_challenge_response_stub(b"\x01" * 8, status=0)
    read_response(fb, sess_b, tree_b, dcerpc_pdu(2, call_id, dcerpc_response_body(0, zero_resp_stub)))
    close_pipe(fb, sess_b, tree_b, fid_b)

    # ---------------------------------------------------------------------------------------------
    # Flow C: NetrServerAuthenticate2 (opnum 15) -- note 3 positive (legacy/downgraded method).
    # ---------------------------------------------------------------------------------------------
    fc = make_flow()
    sess_c, tree_c = 0xC000000000000001, 1
    fid_c = open_pipe(fc, sess_c, tree_c)
    bind_and_ack(fc, sess_c, tree_c, fid_c, next_call_id())
    call_id = next_call_id()
    auth2_req_stub = netlogon_authenticate_request_stub(
        15, "DC1", "LEGACY-PC$", 2, "LEGACY-PC", b"\xAA\xBB\xCC\xDD\xEE\xFF\x11\x22",
        negotiate_flags=0x000001FF)
    write_read(fc, sess_c, tree_c, fid_c,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 15, auth2_req_stub)))
    auth2_resp_stub = netlogon_authenticate_response_stub(
        15, b"\x33\x44\x55\x66\x77\x88\x99\xAA", negotiate_flags=0x000001FF, status=0)
    read_response(fc, sess_c, tree_c, dcerpc_pdu(2, call_id, dcerpc_response_body(0, auth2_resp_stub)))
    close_pipe(fc, sess_c, tree_c, fid_c)

    # ---------------------------------------------------------------------------------------------
    # Flow D: WorkstationSecureChannel with an AccountName not ending in "$" -- note 4 positive --
    # followed, on a second FileId in the SAME session, by one that DOES end in "$" -- note 4's own
    # negative control.
    # ---------------------------------------------------------------------------------------------
    fd = make_flow()
    sess_d, tree_d = 0xD000000000000001, 1
    fid_d1 = open_pipe(fd, sess_d, tree_d)
    bind_and_ack(fd, sess_d, tree_d, fid_d1, next_call_id())
    call_id = next_call_id()
    mismatch_stub = netlogon_authenticate_request_stub(
        26, "DC1", "WORKSTATION1", 2, "WORKSTATION1", b"\x01\x02\x03\x04\x05\x06\x07\x08",
        negotiate_flags=0x612FFFFF)
    write_read(fd, sess_d, tree_d, fid_d1,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 26, mismatch_stub)))
    mismatch_resp = netlogon_authenticate_response_stub(
        26, b"\x08\x07\x06\x05\x04\x03\x02\x01", negotiate_flags=0x612FFFFF, account_rid=1106, status=0)
    read_response(fd, sess_d, tree_d, dcerpc_pdu(2, call_id, dcerpc_response_body(0, mismatch_resp)))
    close_pipe(fd, sess_d, tree_d, fid_d1)

    fid_d2 = open_pipe(fd, sess_d, tree_d)
    bind_and_ack(fd, sess_d, tree_d, fid_d2, next_call_id())
    call_id = next_call_id()
    ok_stub = netlogon_authenticate_request_stub(
        26, "DC1", "WORKSTATION1$", 2, "WORKSTATION1", b"\x11\x12\x13\x14\x15\x16\x17\x18",
        negotiate_flags=0x612FFFFF)
    write_read(fd, sess_d, tree_d, fid_d2,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 26, ok_stub)))
    ok_resp = netlogon_authenticate_response_stub(
        26, b"\x18\x17\x16\x15\x14\x13\x12\x11", negotiate_flags=0x612FFFFF, account_rid=1107, status=0)
    read_response(fd, sess_d, tree_d, dcerpc_pdu(2, call_id, dcerpc_response_body(0, ok_resp)))
    close_pipe(fd, sess_d, tree_d, fid_d2)

    # ---------------------------------------------------------------------------------------------
    # Flow E: NetrServerPasswordSet2 -- note 5 (not sticky, fires on every occurrence).
    # ---------------------------------------------------------------------------------------------
    fe = make_flow()
    sess_e, tree_e = 0xE000000000000001, 1
    fid_e = open_pipe(fe, sess_e, tree_e)
    bind_and_ack(fe, sess_e, tree_e, fid_e, next_call_id())
    call_id = next_call_id()
    pwset_stub = netlogon_password_set2_request_stub(
        "DC1", "WIN10-PC$", 2, "WIN10-PC", new_password_length=516)
    write_read(fe, sess_e, tree_e, fid_e,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 30, pwset_stub)))
    pwset_resp_stub = b"\x00" * 12 + struct.pack("<I", 0)  # ReturnAuthenticator + status=SUCCESS
    read_response(fe, sess_e, tree_e, dcerpc_pdu(2, call_id, dcerpc_response_body(0, pwset_resp_stub)))
    close_pipe(fe, sess_e, tree_e, fid_e)

    # ---------------------------------------------------------------------------------------------
    # Flow F: a sealed NetrServerPasswordSet2 call on an already-bound Netlogon context -- exercises
    # the "sealed, N bytes, not decoded" fallback. The bind/bind_ack themselves are never sealed
    # (nothing to seal with yet -- see netlogon.hpp's own SEALING paragraph), only the request/
    # response that follows.
    # ---------------------------------------------------------------------------------------------
    ff = make_flow()
    sess_f, tree_f = 0xF000000000000001, 1
    fid_f = open_pipe(ff, sess_f, tree_f)
    bind_and_ack(ff, sess_f, tree_f, fid_f, next_call_id())
    call_id = next_call_id()
    sealed_ciphertext = b"\xDE\xAD\xBE\xEF" * 8  # opaque -- this codebase holds no key to decrypt it
    sealed_req = dcerpc_pdu(0, call_id, dcerpc_request_body(0, 30, sealed_ciphertext),
                             auth=(0x0A, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, b"\x00" * 16))
    write_read(ff, sess_f, tree_f, fid_f, sealed_req)
    sealed_resp = dcerpc_pdu(2, call_id, dcerpc_response_body(0, sealed_ciphertext),
                              auth=(0x0A, RPC_C_AUTHN_LEVEL_PKT_PRIVACY, b"\x00" * 16))
    read_response(ff, sess_f, tree_f, sealed_resp)
    close_pipe(ff, sess_f, tree_f, fid_f)

    # ---------------------------------------------------------------------------------------------
    # Flow G: a bind whose only offered context names a NON-Netlogon interface UUID, on a
    # "netlogon"-named pipe -- the request that follows must stay structural-only (dcerpc_messages
    # populated, netlogon_calls empty), the defensive "bind confirmed something else" edge case.
    # ---------------------------------------------------------------------------------------------
    fg = make_flow()
    sess_g, tree_g = 0x7000000000000001, 1
    fid_g = open_pipe(fg, sess_g, tree_g)
    other_interface_uuid = "367abb81-9844-35f1-ad32-98f038001003"  # SCM/svcctl, an arbitrary non-
                                                                     # Netlogon well-known interface
    bind_and_ack(fg, sess_g, tree_g, fid_g, next_call_id(), abstract_uuid=other_interface_uuid)
    call_id = next_call_id()
    other_req_stub = b"\x00" * 32  # opaque -- never interpreted as Netlogon, no context is bound
    write_read(fg, sess_g, tree_g, fid_g,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 4, other_req_stub)))
    other_resp_stub = b"\x00" * 12
    read_response(fg, sess_g, tree_g, dcerpc_pdu(2, call_id, dcerpc_response_body(0, other_resp_stub)))
    close_pipe(fg, sess_g, tree_g, fid_g)

    # ---------------------------------------------------------------------------------------------
    # Flow H: the same ReqChallenge+Authenticate3 exchange as flow A, but against a "lsarpc"-named
    # pipe -- the negative control proving only a "netlogon"-named pipe is ever tracked (no
    # dcerpc_messages/netlogon_calls at all, on either message).
    # ---------------------------------------------------------------------------------------------
    fh = make_flow()
    sess_h, tree_h = 0x8000000000000001, 1
    fid_h = open_pipe(fh, sess_h, tree_h, pipe_name="lsarpc")
    bind_and_ack(fh, sess_h, tree_h, fid_h, next_call_id())
    call_id = next_call_id()
    lsarpc_req_stub = netlogon_req_challenge_request_stub("DC1", "WIN10-PC",
                                                           b"\x11\x22\x33\x44\x55\x66\x77\x88")
    write_read(fh, sess_h, tree_h, fid_h,
               dcerpc_pdu(0, call_id, dcerpc_request_body(0, 4, lsarpc_req_stub)))
    lsarpc_resp_stub = netlogon_req_challenge_response_stub(b"\x99\xAA\xBB\xCC\xDD\xEE\xFF\x00", status=0)
    read_response(fh, sess_h, tree_h, dcerpc_pdu(2, call_id, dcerpc_response_body(0, lsarpc_resp_stub)))
    close_pipe(fh, sess_h, tree_h, fid_h)

    # ---------------------------------------------------------------------------------------------
    # Flow I: the same ReqChallenge+Authenticate3 exchange as flow A, but carried entirely over
    # IOCTL(FSCTL_PIPE_TRANSCEIVE) request/response pairs -- the other real-world named-pipe
    # transport shape (write-then-read in one call, rather than a separate WRITE and READ).
    # ---------------------------------------------------------------------------------------------
    fi = make_flow()
    sess_i, tree_i = 0x9000000000000001, 1
    fid_i = open_pipe(fi, sess_i, tree_i)
    bind_call_id_i = next_call_id()
    bind_pdu_i = dcerpc_pdu(11, bind_call_id_i, dcerpc_bind_body(
        [dcerpc_context_element(0, NETLOGON_INTERFACE_UUID)]))
    bind_ack_pdu_i = dcerpc_pdu(12, bind_call_id_i, dcerpc_bind_ack_body([dcerpc_context_result(0)]))
    ioctl_pipe_transceive(fi, sess_i, tree_i, fid_i, bind_pdu_i, bind_ack_pdu_i)

    call_id = next_call_id()
    req_stub_i = netlogon_req_challenge_request_stub("DC1", "WIN10-PC", b"\x21\x22\x23\x24\x25\x26\x27\x28")
    resp_stub_i = netlogon_req_challenge_response_stub(b"\x91\x92\x93\x94\x95\x96\x97\x98", status=0)
    ioctl_pipe_transceive(fi, sess_i, tree_i, fid_i,
                           dcerpc_pdu(0, call_id, dcerpc_request_body(0, 4, req_stub_i)),
                           dcerpc_pdu(2, call_id, dcerpc_response_body(0, resp_stub_i)))

    call_id = next_call_id()
    auth_req_i = netlogon_authenticate_request_stub(
        26, "DC1", "WIN10-PC$", 2, "WIN10-PC", b"\x31\x32\x33\x34\x35\x36\x37\x38",
        negotiate_flags=0x612FFFFF)
    auth_resp_i = netlogon_authenticate_response_stub(
        26, b"\x41\x42\x43\x44\x45\x46\x47\x48", negotiate_flags=0x612FFFFF, account_rid=1108, status=0)
    ioctl_pipe_transceive(fi, sess_i, tree_i, fid_i,
                           dcerpc_pdu(0, call_id, dcerpc_request_body(0, 26, auth_req_i)),
                           dcerpc_pdu(2, call_id, dcerpc_response_body(0, auth_resp_i)))
    close_pipe(fi, sess_i, tree_i, fid_i)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_050_000 + i, i * 1000)
    (TESTS_DIR / "sample_netlogon.pcap").write_bytes(data)


def build_samr_lsarpc_sample():
    """SAMR + LSARPC (MS-SAMR/MS-LSAD/MS-LSAT), phase 1 of the SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI
    batch -- see samr.hpp's/lsarpc.hpp's own file header comments for the wire format, opnum
    coverage, and the empirically-derived NDR deferred-pointer-ordering rule every full-decode
    opnum below relies on. Every flow opens with a TREE_CONNECT to "\\\\SERVER\\IPC$" then a CREATE
    of "\\PIPE\\samr" or "\\PIPE\\lsarpc" (or both), exactly mirroring build_netlogon_sample's own
    transport-layer conventions (WRITE+READ named-pipe transport throughout). Flows, each its own
    TCP session:
      A: SAMR only -- bind + SamrConnect2(57), SamrOpenDomain(7) against a real domain SID,
         SamrLookupNamesInDomain(17) (one not-found name -- the SAMR enumeration note's own
         trigger), SamrLookupIdsInDomain(18) (one not-found RID), SamrEnumerateUsersInDomain(13)
         (STATUS_MORE_ENTRIES, exercising samr_status_name's curated table), SamrEnumerateAliases-
         InDomain(15), SamrGetAliasMembership(16), SamrOpenUser(34); then SamrChangePasswordUser(38)
         and SamrSetInformationUser(37) as the structural-only, zero-field-decode, secret-shaped
         negative controls (no password bytes anywhere in the decoded output).
      B: LSARPC only -- bind + LsarOpenPolicy2(44) (request stays structural-only by design; the
         response is decoded), LsarLookupNames(14) (the LSARPC enumeration note's own trigger; one
         not-found name via TranslatedSids' own RID=0), LsarLookupSids(15) (STATUS_SOME_NOT_MAPPED,
         exercising lsarpc_status_name's curated table), LsarEnumerateAccounts(11), LsarEnumerate-
         TrustedDomains(13), LsarClose(0) (structural-only, opnum-name-only).
      C: SAMR + LSARPC pipes open on the SAME session -- a SamrLookupNamesInDomain(17) recon call
         fires both the SAMR enumeration note AND (since the lsarpc pipe is already open on this
         same SmbFlowState) the cross-interface note; a subsequent LsarLookupNames(14) recon call on
         the second pipe fires LSARPC's own enumeration note but NOT a second cross-interface note
         (the sticky flag already fired once).
      D: a full NTLM handshake ending in a GUEST session (SessionFlags.IS_GUEST), followed by a SAMR
         pipe + SamrEnumerateUsersInDomain(13) recon call -- the SAMR enumeration note must carry the
         escalated "established as anonymous/guest" wording this session state adds.
      E: bind SAMR normally, then a SEALED (auth_level=PKT_PRIVACY) SamrOpenUser(34) request/response
         pair on the already-bound context -- the "sealed, N bytes, not decoded" fallback, no field
         decode, no enumeration note.
      F: a bind whose only offered context names a NON-SAMR interface UUID (Netlogon's own) on a
         "samr"-named pipe -- the request that follows must stay structural (no samr_calls at all),
         the same defensive negative control build_netlogon_sample's own flow G establishes for
         Netlogon.
    Every byte offset and note-trigger condition here was independently smoke-tested against a
    hand-built synthetic exchange, decoded and inspected in both --format text and --format json,
    BEFORE this fixture (and the CMakeLists.txt tests reading it) were written -- the same
    verification discipline every prior phase's own fixture was held to."""
    packets = []
    ident = [0xE000]
    port = [54001]
    file_id_counter = [1]
    call_id_counter = [1]

    def next_file_id() -> bytes:
        file_id_counter[0] += 1
        return struct.pack("<QQ", file_id_counter[0], 0xBEEF0000 + file_id_counter[0])

    def next_call_id() -> int:
        call_id_counter[0] += 1
        return call_id_counter[0]

    def make_flow():
        sport = port[0]
        port[0] += 1
        state = {"cseq": 60000, "sseq": 70000}

        def add(from_client: bool, payload: bytes):
            if from_client:
                s_port, d_port = sport, 445
                s_ip, d_ip = HMI_IP, PLC_IP
                s_mac, d_mac = HMI_MAC, PLC_MAC
                seq, ack = state["cseq"], state["sseq"]
                state["cseq"] += len(payload)
            else:
                s_port, d_port = 445, sport
                s_ip, d_ip = PLC_IP, HMI_IP
                s_mac, d_mac = PLC_MAC, HMI_MAC
                seq, ack = state["sseq"], state["cseq"]
                state["sseq"] += len(payload)
            tcp = tcp_header(s_port, d_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
            ip = ipv4_header(s_ip, d_ip, 6, len(tcp), ident[0] & 0xFFFF) + tcp
            ident[0] += 1
            packets.append(eth_header(d_mac, s_mac, 0x0800) + ip)

        return add

    mid = [400]

    def next_mid():
        mid[0] += 1
        return mid[0]

    def open_pipe(fx, session_id, tree_id, pipe_name):
        m_tc = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x03, False, smb2_tree_connect_req_body("\\\\SERVER\\IPC$"),
                                               message_id=m_tc, session_id=session_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x03, True, smb2_tree_connect_resp_body(SMB_SHARE_TYPE_PIPE), message_id=m_tc,
            status=SMB_STATUS_SUCCESS, session_id=session_id, tree_id=tree_id)))

        file_id = next_file_id()
        m_cr = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x05, False, smb2_create_req_body("\\PIPE\\" + pipe_name),
                                               message_id=m_cr, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x05, True, smb2_create_resp_body(file_id), message_id=m_cr, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        return file_id

    def close_pipe(fx, session_id, tree_id, file_id):
        m_cl = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x06, False, smb2_close_req_body(file_id),
                                               message_id=m_cl, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x06, True, smb2_close_resp_body(), message_id=m_cl, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))

    pending_read_mid = [None]

    def write_read(fx, session_id, tree_id, file_id, pdu_bytes: bytes):
        m_w = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x09, False, smb2_write_req_body(file_id, pdu_bytes),
                                               message_id=m_w, session_id=session_id, tree_id=tree_id)))
        fx(False, smb_with_prefix(smb2_message(
            0x09, True, smb2_write_resp_body(len(pdu_bytes)), message_id=m_w, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        m_r = next_mid()
        fx(True, smb_with_prefix(smb2_message(0x08, False, smb2_read_req_body(file_id),
                                               message_id=m_r, session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = m_r

    def read_response(fx, session_id, tree_id, pdu_bytes: bytes):
        m_r = pending_read_mid[0]
        assert m_r is not None, "read_response called without a preceding write_read"
        fx(False, smb_with_prefix(smb2_message(
            0x08, True, smb2_read_resp_body(pdu_bytes), message_id=m_r, status=SMB_STATUS_SUCCESS,
            session_id=session_id, tree_id=tree_id)))
        pending_read_mid[0] = None

    def bind_and_ack(fx, session_id, tree_id, file_id, call_id, abstract_uuid, result=0):
        bind_pdu = dcerpc_pdu(11, call_id, dcerpc_bind_body(
            [dcerpc_context_element(0, abstract_uuid)]))
        bind_ack_pdu = dcerpc_pdu(12, call_id, dcerpc_bind_ack_body([dcerpc_context_result(result)]))
        write_read(fx, session_id, tree_id, file_id, bind_pdu)
        read_response(fx, session_id, tree_id, bind_ack_pdu)

    def call(fx, session_id, tree_id, file_id, opnum, req_stub, resp_stub, auth=None):
        cid = next_call_id()
        write_read(fx, session_id, tree_id, file_id,
                   dcerpc_pdu(0, cid, dcerpc_request_body(0, opnum, req_stub), auth=auth))
        read_response(fx, session_id, tree_id,
                      dcerpc_pdu(2, cid, dcerpc_response_body(0, resp_stub), auth=auth))

    DOMAIN_SID = "S-1-5-21-1111111111-2222222222-3333333333"
    ADMIN_SID = DOMAIN_SID + "-500"
    JDOE_SID = DOMAIN_SID + "-1105"

    def handle20(pattern: int) -> bytes:
        return bytes([pattern] * 20)

    # ---------------------------------------------------------------------------------------------
    # Flow A: SAMR only -- full-decode opnum coverage + the two secret-shaped structural-only
    # negative controls (SamrChangePasswordUser/SamrSetInformationUser).
    # ---------------------------------------------------------------------------------------------
    fa = make_flow()
    sess_a, tree_a = 0xB000000000000001, 1
    fid_a = open_pipe(fa, sess_a, tree_a, "samr")
    bind_and_ack(fa, sess_a, tree_a, fid_a, next_call_id(), SAMR_INTERFACE_UUID)

    server_handle = handle20(0x11)
    b = NdrBuf(); b.unique_string("\\\\DC1")
    call(fa, sess_a, tree_a, fid_a, 57, b.get(), server_handle + struct.pack("<I", 0))

    domain_handle = handle20(0x22)
    b = NdrBuf(); b.raw(server_handle); b.u32(0x02000000); b.sid(DOMAIN_SID)
    call(fa, sess_a, tree_a, fid_a, 7, b.get(), domain_handle + struct.pack("<I", 0))

    b = NdrBuf(); b.raw(domain_handle); b.u32(3); b.unicode_string_array(["Administrator", "jdoe", "nosuchuser"])
    rb = NdrBuf(); rb.count_and_ptr_ulong_array([500, 1105, 0]); rb.count_and_ptr_ulong_array([1, 1, 0]); rb.u32(0)
    call(fa, sess_a, tree_a, fid_a, 17, b.get(), rb.get())

    b = NdrBuf(); b.raw(domain_handle); b.u32(3); b.ulong_array([500, 1105, 9999])
    rb = NdrBuf(); rb.names_ptr_array(["Administrator", "jdoe", ""]); rb.count_and_ptr_ulong_array([1, 1, 0]); rb.u32(0)
    call(fa, sess_a, tree_a, fid_a, 18, b.get(), rb.get())

    b = NdrBuf(); b.raw(domain_handle); b.u32(0)
    resp = samr_enumerate_response_stub(0, [(500, "Administrator"), (1105, "jdoe")], 2, status=0x00000103)
    call(fa, sess_a, tree_a, fid_a, 13, b.get(), resp)

    b = NdrBuf(); b.raw(domain_handle); b.u32(0)
    resp = samr_enumerate_response_stub(0, [(544, "Administrators"), (545, "Users")], 2, status=0)
    call(fa, sess_a, tree_a, fid_a, 15, b.get(), resp)

    b = NdrBuf(); b.raw(domain_handle); b.sid_array_ptr([JDOE_SID])
    rb = NdrBuf(); rb.count_and_ptr_ulong_array([544, 545]); rb.u32(0)
    call(fa, sess_a, tree_a, fid_a, 16, b.get(), rb.get())

    user_handle = handle20(0x33)
    b = NdrBuf(); b.raw(domain_handle); b.u32(0x02000000); b.u32(1105)
    call(fa, sess_a, tree_a, fid_a, 34, b.get(), user_handle + struct.pack("<I", 0))

    # SamrChangePasswordUser/SamrSetInformationUser -- structural-only by design (see samr.hpp's own
    # OPNUM COVERAGE note); stub bytes are deliberately non-empty and non-zero to prove they're never
    # rendered anywhere in the decoded output.
    call(fa, sess_a, tree_a, fid_a, 38, b"\xAB" * 64, b"\x00" * 4)
    call(fa, sess_a, tree_a, fid_a, 37, b"\xCD" * 64, b"\x00" * 4)

    close_pipe(fa, sess_a, tree_a, fid_a)

    # ---------------------------------------------------------------------------------------------
    # Flow B: LSARPC only -- full-decode opnum coverage + LsarOpenPolicy2's own request-side
    # structural-only posture and LsarClose's opnum-name-only fallback.
    # ---------------------------------------------------------------------------------------------
    fb = make_flow()
    sess_b, tree_b = 0xB000000000000002, 1
    fid_b = open_pipe(fb, sess_b, tree_b, "lsarpc")
    bind_and_ack(fb, sess_b, tree_b, fid_b, next_call_id(), LSARPC_INTERFACE_UUID)

    policy_handle = handle20(0x44)
    call(fb, sess_b, tree_b, fid_b, 44, b"\x00" * 8, policy_handle + struct.pack("<I", 0))

    b = NdrBuf(); b.raw(policy_handle); b.u32(2); b.unicode_string_array(["Administrator", "nosuchuser"])
    rb = NdrBuf()
    rb.referenced_domain_list_field([("CORP", DOMAIN_SID)])
    rb.translated_sids_field([500, 0])
    rb.u32(2); rb.u32(0)
    call(fb, sess_b, tree_b, fid_b, 14, b.get(), rb.get())

    b = NdrBuf(); b.raw(policy_handle); b.sid_array_ptr([ADMIN_SID, JDOE_SID])
    rb = NdrBuf()
    rb.referenced_domain_list_field([("CORP", DOMAIN_SID)])
    rb.translated_names_field(["Administrator", "jdoe"])
    rb.u32(2); rb.u32(0x00000107)
    call(fb, sess_b, tree_b, fid_b, 15, b.get(), rb.get())

    b = NdrBuf(); b.raw(policy_handle); b.u32(0)
    resp = lsar_enumerate_accounts_response_stub(0, [ADMIN_SID, JDOE_SID], status=0)
    call(fb, sess_b, tree_b, fid_b, 11, b.get(), resp)

    b = NdrBuf(); b.raw(policy_handle); b.u32(0)
    resp = lsar_enumerate_trusted_domains_response_stub(
        0, [("CHILD.CORP.LOCAL", "S-1-5-21-444444444-555555555-666666666")], status=0)
    call(fb, sess_b, tree_b, fid_b, 13, b.get(), resp)

    # LsarClose -- structural-only, opnum-name-only fallback (outside this file's own curated table).
    call(fb, sess_b, tree_b, fid_b, 0, policy_handle, b"\x00" * 4)

    close_pipe(fb, sess_b, tree_b, fid_b)

    # ---------------------------------------------------------------------------------------------
    # Flow C: SAMR + LSARPC pipes on the SAME session -- the cross-interface note (only possible
    # because Phase 0 put both maps on one SmbFlowState).
    # ---------------------------------------------------------------------------------------------
    fc = make_flow()
    sess_c, tree_c = 0xB000000000000003, 1
    fid_c_samr = open_pipe(fc, sess_c, tree_c, "samr")
    fid_c_lsarpc = open_pipe(fc, sess_c, tree_c, "lsarpc")

    bind_and_ack(fc, sess_c, tree_c, fid_c_samr, next_call_id(), SAMR_INTERFACE_UUID)
    dh = handle20(0x55)
    b = NdrBuf(); b.raw(dh); b.u32(1); b.unicode_string_array(["Administrator"])
    rb = NdrBuf(); rb.count_and_ptr_ulong_array([500]); rb.count_and_ptr_ulong_array([1]); rb.u32(0)
    call(fc, sess_c, tree_c, fid_c_samr, 17, b.get(), rb.get())

    bind_and_ack(fc, sess_c, tree_c, fid_c_lsarpc, next_call_id(), LSARPC_INTERFACE_UUID)
    ph = handle20(0x66)
    b = NdrBuf(); b.raw(ph); b.u32(1); b.unicode_string_array(["Administrator"])
    rb = NdrBuf()
    rb.referenced_domain_list_field([("CORP", DOMAIN_SID)])
    rb.translated_sids_field([500])
    rb.u32(1); rb.u32(0)
    call(fc, sess_c, tree_c, fid_c_lsarpc, 14, b.get(), rb.get())

    close_pipe(fc, sess_c, tree_c, fid_c_samr)
    close_pipe(fc, sess_c, tree_c, fid_c_lsarpc)

    # ---------------------------------------------------------------------------------------------
    # Flow D: an NTLM handshake ending in a GUEST session, then a SAMR recon call -- the
    # null/guest-session escalation wording on the SAMR enumeration note.
    # ---------------------------------------------------------------------------------------------
    fd = make_flow()
    sess_d, tree_d = 0xB000000000000004, 1
    m_d1 = next_mid()
    fd(True, smb_with_prefix(smb2_message(0x01, False,
                                           smb2_session_setup_req_body(ntlm_negotiate_message("", "")),
                                           message_id=m_d1)))
    fd(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(ntlm_challenge_message("", "", "")),
        message_id=m_d1, status=SMB_STATUS_MORE_PROCESSING_REQUIRED, session_id=sess_d)))
    m_d2 = next_mid()
    fd(True, smb_with_prefix(smb2_message(
        0x01, False, smb2_session_setup_req_body(ntlm_authenticate_message("", "guest", "")),
        message_id=m_d2, session_id=sess_d)))
    fd(False, smb_with_prefix(smb2_message(
        0x01, True, smb2_session_setup_resp_body(b"", session_flags=SMB_SESSION_FLAG_IS_GUEST),
        message_id=m_d2, status=SMB_STATUS_SUCCESS, session_id=sess_d)))

    fid_d = open_pipe(fd, sess_d, tree_d, "samr")
    bind_and_ack(fd, sess_d, tree_d, fid_d, next_call_id(), SAMR_INTERFACE_UUID)
    dh = handle20(0x77)
    b = NdrBuf(); b.raw(dh); b.u32(0)
    resp = samr_enumerate_response_stub(0, [(500, "Administrator")], 1, status=0)
    call(fd, sess_d, tree_d, fid_d, 13, b.get(), resp)
    close_pipe(fd, sess_d, tree_d, fid_d)

    # ---------------------------------------------------------------------------------------------
    # Flow E: a SEALED SamrOpenUser request/response pair on an already-bound SAMR context -- the
    # "sealed, N bytes, not decoded" fallback (no field decode at all, no enumeration note).
    # ---------------------------------------------------------------------------------------------
    fe = make_flow()
    sess_e, tree_e = 0xB000000000000005, 1
    fid_e = open_pipe(fe, sess_e, tree_e, "samr")
    bind_and_ack(fe, sess_e, tree_e, fid_e, next_call_id(), SAMR_INTERFACE_UUID)
    call(fe, sess_e, tree_e, fid_e, 34, b"\xEF" * 28, b"\xFE" * 24,
         auth=(16, 6, b"\x01\x02\x03\x04\x05\x06\x07\x08"))  # auth_type 16 (SSPI), auth_level 6 (PKT_PRIVACY)
    close_pipe(fe, sess_e, tree_e, fid_e)

    # ---------------------------------------------------------------------------------------------
    # Flow F: a bind whose only offered context names Netlogon's OWN interface UUID (not SAMR's) on
    # a "samr"-named pipe -- the request that follows must stay structural (no samr_calls at all).
    # ---------------------------------------------------------------------------------------------
    ff = make_flow()
    sess_f, tree_f = 0xB000000000000006, 1
    fid_f = open_pipe(ff, sess_f, tree_f, "samr")
    bind_and_ack(ff, sess_f, tree_f, fid_f, next_call_id(), NETLOGON_INTERFACE_UUID)
    b = NdrBuf(); b.raw(handle20(0x88)); b.u32(0x02000000); b.sid(DOMAIN_SID)
    call(ff, sess_f, tree_f, fid_f, 7, b.get(), handle20(0x99) + struct.pack("<I", 0))
    close_pipe(ff, sess_f, tree_f, fid_f)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_060_000 + i, i * 1000)
    (TESTS_DIR / "sample_samr_lsarpc.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# DNS / mDNS / LLMNR / NBT-NS / DoH-detection (ROADMAP: "Add DNS, DoH, NBT-NS name resolution
# decode") -- see dns.hpp/nbns.hpp/tls_sni.hpp's own file header comments for the wire formats
# these fixtures exercise.

DNS_PORT = 53
MDNS_PORT = 5353
LLMNR_PORT = 5355
NBNS_PORT = 137
DOH_PORT = 443
WINRM_PORT = 5985
DCOM_PORT = 135


def dns_name(name: str) -> bytes:
    """Ordinary length-prefixed DNS labels, no compression -- RFC 1035 4.1.2. `name` may be ""
    or "." for the root name."""
    if name in ("", "."):
        return b"\x00"
    out = b""
    for label in name.rstrip(".").split("."):
        out += bytes([len(label)]) + label.encode("ascii")
    return out + b"\x00"


def dns_message(qr: int, opcode: int, flags_bits: int, rcode: int, questions: list, answers: list,
                 authorities: list = (), additionals: list = (), txn_id: int = 0x1234) -> bytes:
    """Builds one raw DNS/mDNS/LLMNR-shaped message. `flags_bits` is the caller-computed AA/TC/RD/
    RA (or C/TC/T for LLMNR) bit pattern already shifted into word2's bit5-8 position (i.e. the
    caller passes e.g. 0x0400 for AA/C, 0x0200 for TC, 0x0100 for RD/T, 0x0080 for RA) -- kept
    generic here since the three flavors disagree on what those bits mean, not just their values.
    Each of questions/answers/authorities/additionals is already-encoded bytes for that section."""
    word2 = (qr << 15) | ((opcode & 0x0F) << 11) | (flags_bits & 0x07F0) | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", txn_id, word2, len(questions), len(answers), len(authorities),
                          len(additionals))
    return header + b"".join(questions) + b"".join(answers) + b"".join(authorities) + b"".join(additionals)


def dns_question(name: str, qtype: int, qclass: int = 1) -> bytes:
    return dns_name(name) + struct.pack("!HH", qtype, qclass)


def dns_rr(name: str, rtype: int, rclass: int, ttl: int, rdata: bytes) -> bytes:
    return dns_name(name) + struct.pack("!HHIH", rtype, rclass, ttl, len(rdata)) + rdata


def dns_rdata_a(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def dns_rdata_aaaa(addr_hextets: list) -> bytes:
    return b"".join(struct.pack("!H", h) for h in addr_hextets)


def dns_rdata_soa(mname: str, rname: str, serial: int, refresh: int, retry: int, expire: int,
                   minimum: int) -> bytes:
    return dns_name(mname) + dns_name(rname) + struct.pack("!IIIII", serial, refresh, retry, expire, minimum)


def dns_rdata_txt(*strings: str) -> bytes:
    return b"".join(bytes([len(s)]) + s.encode("ascii") for s in strings)


def dns_rdata_srv(priority: int, weight: int, port: int, target: str) -> bytes:
    return struct.pack("!HHH", priority, weight, port) + dns_name(target)


def dns_rdata_mx(preference: int, exchange: str) -> bytes:
    return struct.pack("!H", preference) + dns_name(exchange)


def dns_udp_frame(payload: bytes, sport: int, dport: int, src_ip: str, dst_ip: str, src_mac: bytes,
                   dst_mac: bytes) -> bytes:
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), 0x7100)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def build_dns_sample():
    """Classic DNS (UDP port 53) -- header/flags, question, and the "first pass" RDATA types
    (A/AAAA/NS/CNAME/PTR/MX/SOA/TXT/SRV), an EDNS0 OPT pseudo-record, a name-compression pointer,
    and the structural detection gate correctly rejecting non-DNS-shaped UDP/53 traffic -- see
    dns.hpp's file header comment for the exact wire format and RFC sourcing."""
    packets = []

    def add(payload: bytes, dport: int = DNS_PORT, sport: int = 53500, from_client: bool = True):
        if from_client:
            packets.append(dns_udp_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(dns_udp_frame(payload, dport, sport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) Ordinary A query.
    add(dns_message(0, 0, 0x0100, 0, [dns_question("plc01.plant.example.", 1)], []))

    # 2) A response, AA set, one A answer.
    add(dns_message(1, 0, 0x0400, 0, [dns_question("plc01.plant.example.", 1)],
                     [dns_rr("plc01.plant.example.", 1, 1, 300, dns_rdata_a("192.168.1.10"))]),
        from_client=False)

    # 3) AAAA response.
    add(dns_message(1, 0, 0x0400, 0, [dns_question("plc01.plant.example.", 28)],
                     [dns_rr("plc01.plant.example.", 28, 1, 300,
                             dns_rdata_aaaa([0x2001, 0x0db8, 0, 0, 0, 0, 0, 0x0a]))]),
        from_client=False)

    # 4) A CNAME record whose RDATA is a compression pointer (RFC 1035 4.1.4) back to byte 12 --
    #    the question section's own name, "hmi.plant.example." -- rather than a literal label
    #    sequence, exercising pointer-following specifically (the result is a self-referential
    #    CNAME, which is a perfectly decodable, if unusual, wire shape -- not the same as a
    #    pointer LOOP, since what it points at is an ordinary label sequence, not another
    #    pointer). A second, unrelated A answer for a different name follows in the same message
    #    purely to also exercise "more than one answer."
    cname_answer = dns_name("hmi.plant.example.") + struct.pack("!HHIH", 5, 1, 300, 2) + b"\xc0\x0c"
    a_answer = dns_rr("plc01.plant.example.", 1, 1, 300, dns_rdata_a("192.168.1.10"))
    add(dns_message(1, 0, 0x0400, 0, [dns_question("hmi.plant.example.", 1)],
                     [cname_answer, a_answer]), from_client=False)

    # 5) NS + MX + TXT + SOA + SRV, one of each, in the additional section (purely to exercise
    #    every "first pass" RDATA type in one capture -- a real message wouldn't mix them like
    #    this).
    add(dns_message(1, 0, 0x0400, 0, [dns_question("plant.example.", 2)],
                     [dns_rr("plant.example.", 2, 1, 3600, dns_name("ns1.plant.example."))],
                     additionals=[
                         dns_rr("plant.example.", 15, 1, 3600, dns_rdata_mx(10, "mail.plant.example.")),
                         dns_rr("plant.example.", 16, 1, 3600, dns_rdata_txt("v=spf1 -all", "site=plant-1")),
                         dns_rr("plant.example.", 6, 1, 3600,
                                dns_rdata_soa("ns1.plant.example.", "hostmaster.plant.example.",
                                              2024010101, 7200, 3600, 1209600, 3600)),
                         dns_rr("_ldap._tcp.dc._msdcs.plant.example.", 33, 1, 600,
                                dns_rdata_srv(0, 100, 389, "dc01.plant.example.")),
                     ]),
        from_client=False)

    # 6) NXDOMAIN response, no answers.
    add(dns_message(1, 0, 0x0180, 3, [dns_question("doesnotexist.plant.example.", 1)], []),
        from_client=False)

    # 7) A query with an EDNS0 OPT pseudo-record in the additional section (RFC 6891) -- class
    #    field repurposed as UDP payload size, TTL repurposed as extended-rcode/version/flags (DO
    #    bit set here).
    opt_ttl = (0 << 24) | (0 << 16) | 0x8000
    add(dns_message(0, 0, 0x0100, 0, [dns_question("plc01.plant.example.", 1)], [],
                     additionals=[dns_name(".") + struct.pack("!HHIH", 41, 4096, opt_ttl, 0)]))

    # 8) Malformed: declared ANCOUNT=5 but only one answer actually present -- exercises
    #    records_truncated.
    header = struct.pack("!HHHHHH", 0x9999, 0x8180, 1, 5, 0, 0)
    q = dns_question("plc01.plant.example.", 1)
    one_answer = dns_rr("plc01.plant.example.", 1, 1, 300, dns_rdata_a("192.168.1.10"))
    add(header + q + one_answer, from_client=False)

    # 9) Not DNS-shaped at all -- ordinary UDP/53 traffic with a payload that is NOT 12 bytes of
    #    plausible header + label sequence -- must not be misdetected (the structural gate rejects
    #    it, so this falls back to generic "udp").
    add(b"\x99\x99\x99\x99\x99\x99")

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_008_000 + i, i * 1000)
    (TESTS_DIR / "sample_dns.pcap").write_bytes(data)


def build_mdns_sample():
    """Multicast DNS (UDP port 5353) -- the QU (unicast-response-requested) bit on a question and
    the cache-flush bit on a response record, both top-bit reinterpretations of the DNS wire
    format's own CLASS field -- see dns.hpp's file header comment (RFC 6762 6.2/10.2)."""
    packets = []
    mdns_group_ip = "224.0.0.251"

    def add(payload: bytes, from_client: bool = True):
        if from_client:
            packets.append(dns_udp_frame(payload, MDNS_PORT, MDNS_PORT, HMI_IP, mdns_group_ip, HMI_MAC,
                                          bytes.fromhex("01005e0000fb")))
        else:
            packets.append(dns_udp_frame(payload, MDNS_PORT, MDNS_PORT, PLC_IP, mdns_group_ip, PLC_MAC,
                                          bytes.fromhex("01005e0000fb")))

    # 1) A query for a ".local" name, QU bit set on the question.
    q_qu = dns_question("plc01.local.", 1)
    q_qu = q_qu[:-2] + struct.pack("!H", 1 | 0x8000)  # set the QU top bit on QCLASS
    add(dns_message(0, 0, 0, 0, [q_qu], []))

    # 2) The matching response, cache-flush bit set on the A record, AA set (mDNS responses are
    #    conventionally authoritative). dns_rr() has no cache-flush parameter, so this record is
    #    built directly rather than through it -- its CLASS field's top bit is the cache-flush bit
    #    (RFC 6762 10.2), not an ordinary class value.
    a_rr = dns_name("plc01.local.") + struct.pack("!HHIH", 1, 1 | 0x8000, 120, 4) + dns_rdata_a("192.168.1.10")
    add(dns_message(1, 0, 0x0400, 0, [], [a_rr]), from_client=False)

    # 3) Typical mDNS/DNS-SD service-discovery shape: PTR -> SRV + TXT for a service instance.
    ptr_rr = dns_rr("_http._tcp.local.", 12, 1 | 0x8000, 120, dns_name("PLC01._http._tcp.local."))
    srv_rr = dns_rr("PLC01._http._tcp.local.", 33, 1 | 0x8000, 120, dns_rdata_srv(0, 0, 80, "plc01.local."))
    txt_rr = dns_rr("PLC01._http._tcp.local.", 16, 1 | 0x8000, 120, dns_rdata_txt("path=/status"))
    add(dns_message(1, 0, 0x0400, 0, [], [ptr_rr, srv_rr, txt_rr]), from_client=False)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_008_500 + i, i * 1000)
    (TESTS_DIR / "sample_mdns.pcap").write_bytes(data)


def build_llmnr_sample():
    """LLMNR (UDP port 5355) -- the C (Conflict) and T (Tentative) bits, which replace DNS's own
    AA/RD bit positions, and the reserved-Z-bits detection-gate rejection -- see dns.hpp's file
    header comment (RFC 4795 2.1.1)."""
    packets = []
    llmnr_group_ip = "224.0.0.252"

    def add(payload: bytes, from_client: bool = True):
        if from_client:
            packets.append(dns_udp_frame(payload, LLMNR_PORT, LLMNR_PORT, HMI_IP, llmnr_group_ip, HMI_MAC,
                                          bytes.fromhex("01005e0000fc")))
        else:
            packets.append(dns_udp_frame(payload, LLMNR_PORT, LLMNR_PORT, PLC_IP, llmnr_group_ip, PLC_MAC,
                                          bytes.fromhex("01005e0000fc")))

    # 1) An ordinary query, no flags set.
    add(dns_message(0, 0, 0, 0, [dns_question("hmi-eng01.", 1)], []))

    # 2) A unicast response, name is unique (C clear), not tentative.
    add(dns_message(1, 0, 0, 0, [dns_question("hmi-eng01.", 1)],
                     [dns_rr("hmi-eng01.", 1, 1, 0, dns_rdata_a("192.168.1.50"))]), from_client=False)

    # 3) A response with C (conflict) set -- more than one node claims this name.
    add(dns_message(1, 0, 0x0400, 0, [dns_question("dupe-host.", 1)],
                     [dns_rr("dupe-host.", 1, 1, 0, dns_rdata_a("192.168.1.77"))]), from_client=False)

    # 4) Malformed: reserved Z bits nonzero -- RFC 4795 says implementations MUST zero these; this
    #    decoder treats a nonzero value as a detection-gate rejection (see dns.hpp), so this packet
    #    must NOT decode as "llmnr" at all.
    bad = struct.pack("!HHHHHH", 0xABCD, 0x00F0, 1, 0, 0, 0) + dns_question("bad.", 1)
    add(bad)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_009_000 + i, i * 1000)
    (TESTS_DIR / "sample_llmnr.pcap").write_bytes(data)


def nbns_encode_name(name: str, suffix: int) -> bytes:
    """First-level-encodes a NetBIOS name (RFC 1002 4.1): pads/truncates to 15 characters, appends
    the 1-byte suffix, then maps each raw byte's two nibbles to 'A'+nibble."""
    raw = (name.upper()[:15]).ljust(15) + chr(suffix)
    out = bytearray()
    for ch in raw.encode("latin-1"):
        out.append(ord('A') + (ch >> 4))
        out.append(ord('A') + (ch & 0x0F))
    return bytes([0x20]) + bytes(out) + b"\x00"  # + zero-length scope-ID terminator


def nbns_message(r: int, opcode: int, nm_flags_bits: int, rcode: int, questions: list, answers: list,
                  txn_id: int = 0x5678) -> bytes:
    word2 = (r << 15) | ((opcode & 0x0F) << 11) | (nm_flags_bits & 0x07F0) | (rcode & 0x0F)
    header = struct.pack("!HHHHHH", txn_id, word2, len(questions), len(answers), 0, 0)
    return header + b"".join(questions) + b"".join(answers)


def nbns_question(name: str, suffix: int, qtype: int) -> bytes:
    return nbns_encode_name(name, suffix) + struct.pack("!HH", qtype, 1)


def nbns_nb_rr(name: str, suffix: int, ttl: int, addresses: list) -> bytes:
    """`addresses` is a list of (is_group, node_type, ip_str) tuples."""
    rdata = b""
    for is_group, node_type, ip in addresses:
        flags = (0x8000 if is_group else 0) | ((node_type & 0x03) << 13)
        rdata += struct.pack("!H", flags) + dns_rdata_a(ip)
    return nbns_encode_name(name, suffix) + struct.pack("!HHIH", 0x0020, 1, ttl, len(rdata)) + rdata


def nbns_nbstat_rr(name: str, suffix: int, names: list, mac: bytes) -> bytes:
    """`names` is a list of (name, suffix, is_group, node_type, active, permanent) tuples."""
    rdata = bytes([len(names)])
    for nm_name, nm_suffix, is_group, node_type, active, permanent in names:
        raw = (nm_name.upper()[:15]).ljust(15) + chr(nm_suffix)
        flags = (0x8000 if is_group else 0) | ((node_type & 0x03) << 13)
        if active: flags |= 0x0400
        if permanent: flags |= 0x0200
        rdata += raw.encode("latin-1") + struct.pack("!H", flags)
    rdata += mac + b"\x00" * 40  # UNIT_ID + a zeroed-out STATISTICS tail (not individually decoded)
    return nbns_encode_name(name, suffix) + struct.pack("!HHIH", 0x0021, 1, 0, len(rdata)) + rdata


def build_nbns_sample():
    """NetBIOS Name Service / NBT-NS (UDP port 137) -- the first-level name encoding, an NB
    positive-response address list, and an NBSTAT node-status table with a MAC address -- see
    nbns.hpp's file header comment (RFC 1002 4.1/4.2)."""
    packets = []
    nbns_broadcast_ip = "192.168.1.255"

    def add(payload: bytes, from_client: bool = True):
        if from_client:
            packets.append(dns_udp_frame(payload, NBNS_PORT, NBNS_PORT, HMI_IP, nbns_broadcast_ip, HMI_MAC,
                                          b"\xff\xff\xff\xff\xff\xff"))
        else:
            packets.append(dns_udp_frame(payload, NBNS_PORT, NBNS_PORT, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) NB name query, broadcast, RD set.
    add(nbns_message(0, 0, 0x0100, 0, [nbns_question("PLC01", 0x00, 0x0020)], []))

    # 2) NB positive name query response, AA set, one unique B-node address.
    add(nbns_message(1, 0, 0x0400, 0, [], [nbns_nb_rr("PLC01", 0x00, 300000, [(False, 0, "192.168.1.10")])]),
        from_client=False)

    # 3) NBSTAT query.
    add(nbns_message(0, 0, 0x0100, 0, [nbns_question("*", 0x00, 0x0021)], []))

    # 4) NBSTAT response -- workstation + file-server + domain-controller-group names, plus the
    #    responding node's MAC address.
    names = [
        ("PLC01", 0x00, False, 0, True, True),
        ("PLC01", 0x20, False, 0, True, True),
        ("PLANT", 0x1C, True, 0, True, False),
    ]
    add(nbns_message(1, 0, 0x0400, 0, [], [nbns_nbstat_rr("*", 0x00, names, PLC_MAC)]), from_client=False)

    # 5) Not NBT-NS-shaped -- ordinary UDP/137 traffic whose "name" length byte isn't 0x20 -- must
    #    not be misdetected.
    add(struct.pack("!HHHHHH", 0x1111, 0, 1, 0, 0, 0) + b"\x10" + b"X" * 16)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_009_500 + i, i * 1000)
    (TESTS_DIR / "sample_nbns.pcap").write_bytes(data)


def tls_extension(ext_type: int, data: bytes) -> bytes:
    return struct.pack("!HH", ext_type, len(data)) + data


def tls_sni_extension(hostname: str) -> bytes:
    name = hostname.encode("ascii")
    server_name = struct.pack("!BH", 0, len(name)) + name
    server_name_list = struct.pack("!H", len(server_name)) + server_name
    return tls_extension(0x0000, server_name_list)


def tls_alpn_extension(*protocols: str) -> bytes:
    entries = b"".join(bytes([len(p)]) + p.encode("ascii") for p in protocols)
    return tls_extension(0x0010, struct.pack("!H", len(entries)) + entries)


def tls_client_hello(hostname: str = None, alpn: list = None) -> bytes:
    """A minimal, syntactically-valid TLS 1.2-shaped ClientHello -- just enough structure for
    try_parse_tls_client_hello to walk through (legacy_version + random + empty session id + one
    cipher suite + null compression + optionally SNI/ALPN extensions) -- see tls_sni.hpp."""
    body = struct.pack("!H", 0x0303)  # legacy_version: "TLS 1.2" (used as a compatibility value
                                        # even by real TLS 1.3 ClientHellos)
    body += b"\x00" * 32               # random
    body += b"\x00"                    # session_id length 0
    body += struct.pack("!H", 2) + b"\x13\x01"  # one cipher suite (TLS_AES_128_GCM_SHA256)
    body += b"\x01\x00"                # compression methods: length 1, "null"
    extensions = b""
    if hostname is not None:
        extensions += tls_sni_extension(hostname)
    if alpn:
        extensions += tls_alpn_extension(*alpn)
    if extensions or hostname is not None or alpn is not None:
        body += struct.pack("!H", len(extensions)) + extensions
    handshake = struct.pack("!B", 0x01) + struct.pack("!I", len(body))[1:] + body  # ClientHello, 24-bit length
    record = struct.pack("!BHH", 0x16, 0x0301, len(handshake)) + handshake
    return record


def build_doh_sample():
    """DNS-over-HTTPS detection (TCP port 443) -- a TLS ClientHello whose SNI matches a known
    public DoH resolver (detected as "doh"), one whose SNI does NOT (ordinary ambient HTTPS
    traffic, correctly left alone), and a non-TLS TCP/443 payload (also correctly left alone) --
    see tls_sni.hpp's file header comment."""
    packets = []

    def add(payload: bytes, sport: int = 54000, dport: int = DOH_PORT, seq: int = 1000):
        tcp = tcp_header(sport, dport, seq, 0, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), 0x7200)
        packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)

    # 1) ClientHello to a known Cloudflare DoH hostname, with ALPN offering h2 -- detected as "doh".
    add(tls_client_hello("cloudflare-dns.com", alpn=["h2", "http/1.1"]))

    # 2) ClientHello to an unrelated hostname -- ordinary HTTPS, must NOT be flagged as "doh".
    add(tls_client_hello("www.example.com"), sport=54001)

    # 3) ClientHello to a NextDNS per-account subdomain -- exercises the "*.suffix" provider-table
    #    matching (see tls_sni.hpp), not just an exact hostname.
    add(tls_client_hello("abc123.dns.nextdns.io"), sport=54002)

    # 4) Not a TLS ClientHello at all -- ordinary TCP/443 payload -- must not be misdetected.
    add(b"\x99\x99\x99\x99\x99\x99\x99\x99", sport=54003)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_010_000 + i, i * 1000)
    (TESTS_DIR / "sample_doh.pcap").write_bytes(data)


def build_vlan_zones_sample():
    """Exercises PolicyEngine's VLAN-membership zone/conduit model (ROADMAP item 15 -- see
    policy.hpp's file header comment and PolicyEngine::observe's doc comment) for the four
    protocols with no IP layer at all: PROFINET RT, GOOSE, Sampled Values, and EtherCAT. Each of
    these carries at most one 802.1Q tag, so "L2 flows" here are keyed by (protocol, MAC pair)
    only, never by VLAN -- see ethernet_flow_key in policy_engine.cpp. This one fixture is reused
    by several tests/policies/*.yaml files that each declare a different VLAN zone layout, so it
    deliberately covers every outcome a VLAN-zone policy can produce against the SAME capture:
    membership in a declared zone, membership in the wrong VLAN entirely, and no VLAN tag at all."""
    packets = []

    # A second, distinct MAC pair for the "traffic on the wrong VLAN" scenario -- a different pair
    # is required so this flow's key (protocol + MAC pair) doesn't collide with the VLAN-100 GOOSE
    # flow below; PolicyEngine has no other way to tell them apart, since a single raw-Ethernet
    # frame carries only one VLAN tag; see policy_engine.hpp's EthernetFlowState comment.
    ENG_MAC = mac("00:0c:29:aa:11:22")
    RTU_MAC = mac("00:0c:29:bb:33:44")

    # A third, distinct MAC pair for the "no 802.1Q tag at all" scenario -- again required so this
    # flow doesn't collide with either of the above.
    OFFICE_A_MAC = mac("00:0c:29:cc:55:66")
    OFFICE_B_MAC = mac("00:0c:29:dd:77:88")

    ts_field = utctime_bytes(0x386EBBF3, 0x421728, 0x0A)  # same plausible UtcTime bytes
                                                            # build_goose_sample/build_sv_sample use

    # 1) PROFINET RT, cyclic IO data (FrameID 0x8001), tagged VLAN 100 -- HMI_MAC/PLC_MAC, the
    #    "OT segment" pair every other protocol below on VLAN 100 also uses.
    packets.append(profinet_frame(0x8001, bytes(range(1, 9)) + struct.pack("!HBB", 0x1234, 0x35, 0x00),
                                   vlan_tci=100))

    # 2) GOOSE, tagged VLAN 100 -- same HMI_MAC/PLC_MAC pair as (1); a distinct flow key from (1)
    #    purely because the protocol differs (see ethernet_flow_key), not because of the VLAN.
    pdu_goose_100 = goose_pdu("IED1/LLN0$GO$gcb01", 2000, "IED1/LLN0$GOOSE1", None, ts_field,
                               1, 1, None, 1, None, 1, data_bool(True))
    packets.append(goose_frame(0x0001, pdu_goose_100, vlan_tci=100))

    # 3) Sampled Values, tagged VLAN 100 -- same HMI_MAC/PLC_MAC pair.
    asdu_sv_100 = sv_asdu("IED1/MSVCB01", 1234, 1, bytes(8))
    packets.append(sv_frame(0x4000, sv_sav_pdu([asdu_sv_100]), vlan_tci=100))

    # 4) EtherCAT, tagged VLAN 100 -- same HMI_MAC/PLC_MAC pair; a single LRD (Logical Read)
    #    datagram, the same shape build_ethercat_sample's logical-addressing packets use.
    packets.append(ecat_frame(ecat_datagram(10, 30, bytes(4), logical_address=0x00010000, wkc=1),
                               vlan_tci=100))

    # 5) GOOSE again, but tagged VLAN 200 and using the ENG_MAC/RTU_MAC pair -- a policy that only
    #    declares a VLAN-100 zone must classify this flow as Unclassified ("no declared VLAN zone
    #    contains VLAN 200"); a policy that ALSO declares a VLAN-200 zone without a conduit
    #    permitting goose there must classify it as a Violation instead ("no conduit permits goose
    #    traffic on VLAN zone ...") -- see docs/MANUAL.md's worked VLAN-zone example.
    pdu_goose_200 = goose_pdu("IED2/LLN0$GO$gcb02", 2000, "IED2/LLN0$GOOSE2", None, ts_field,
                               1, 1, None, 1, None, 1, data_bool(False))
    packets.append(goose_frame(0x0002, pdu_goose_200, dst=RTU_MAC, src=ENG_MAC, vlan_tci=200))

    # 6) EtherCAT with NO 802.1Q tag at all, using the OFFICE_A_MAC/OFFICE_B_MAC pair -- must
    #    always classify as Unclassified ("frame carries no 802.1Q VLAN tag at all"), regardless of
    #    which VLAN zones the policy declares, since there is no VLAN membership to check at all.
    packets.append(ecat_frame(ecat_datagram(10, 31, bytes(4), logical_address=0x00020000, wkc=1),
                               dst=OFFICE_B_MAC, src=OFFICE_A_MAC))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_020_000 + i, i * 1000)
    (TESTS_DIR / "sample_vlan_zones.pcap").write_bytes(data)


# --- RIP / IGMP / VRRP / HSRP -----------------------------------------------------------

RIP_PORT = 520
HSRP_PORT = 1985
ICMP_IP_PROTOCOL = 1
IGMP_IP_PROTOCOL = 2
VRRP_IP_PROTOCOL = 112
IGRP_IP_PROTOCOL = 9
EIGRP_IP_PROTOCOL = 88
OSPF_IP_PROTOCOL = 89
PIM_IP_PROTOCOL = 103


def ip_bytes4(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def udp_ip_eth_frame(payload: bytes, sport: int, dport: int, src_ip: str, dst_ip: str,
                      src_mac: bytes, dst_mac: bytes, ident: int = 0x9000) -> bytes:
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), ident)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def ip_eth_frame(payload: bytes, protocol: int, src_ip: str, dst_ip: str, src_mac: bytes,
                  dst_mac: bytes, ident: int = 0x9000) -> bytes:
    """For IGMP/VRRP/ICMP: no UDP/TCP header at all -- `payload` rides directly on IP."""
    ip = ipv4_header(src_ip, dst_ip, protocol, len(payload), ident)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + payload


def rfc1071_checksum(data: bytes) -> int:
    """The classic 16-bit one's-complement Internet checksum (RFC 1071) -- the same algorithm
    IPv4/TCP/UDP/ICMP all use. Sums 16-bit big-endian words (an odd trailing byte is padded with a
    trailing zero byte), folds carries back in, and returns the one's complement -- i.e. the value
    that, written into the checksum field and summed back in, makes the whole message fold to
    0xFFFF. Mirrors icmp.cpp's own verify_checksum exactly, just computing the field instead of
    checking it."""
    if len(data) % 2:
        data = data + b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def icmp_message(icmp_type: int, code: int, body: bytes, checksum_override: int = None) -> bytes:
    """Type(1) + Code(1) + Checksum(2) + `body` -- see icmp.hpp's file header for the wire format.
    Checksum defaults to the real, correctly computed RFC 1071 value (over the whole message,
    checksum field included as the value being solved for) so a freshly generated packet decodes
    with icmp_checksum_valid=true -- same "compute the real value by default" convention this file
    uses for HART-IP's own longitudinal checksum (see pass_through_body's own `checksum`
    parameter). Pass an explicit int to deliberately produce a mismatch instead."""
    if checksum_override is not None:
        return struct.pack("!BBH", icmp_type, code, checksum_override) + body
    checksum = rfc1071_checksum(struct.pack("!BBH", icmp_type, code, 0) + body)
    return struct.pack("!BBH", icmp_type, code, checksum) + body


def icmp_embedded_datagram(src_ip: str, dst_ip: str, protocol: int, src_port: int = None,
                            dst_port: int = None, extra: bytes = b"") -> bytes:
    """The "original datagram" an ICMP error message (Destination Unreachable/Redirect/Time
    Exceeded/Parameter Problem) quotes -- a full 20-byte, no-options IPv4 header (parse_ipv4 trusts
    it exactly like a real one -- header checksum not validated, see ipv4.cpp) followed by just
    enough transport payload to recover the ports (4 bytes: src port + dst port, the same layout
    for TCP and UDP) plus `extra`, mirroring RFC 792's "first 8 bytes of the original payload"
    guarantee -- see icmp.hpp's file header. `src_port=None` omits the transport payload entirely,
    for a quote with no port info to recover."""
    if src_port is not None:
        transport = struct.pack("!HH", src_port, dst_port) + extra
    else:
        transport = extra
    ip = ipv4_header(src_ip, dst_ip, protocol, len(transport), 0xA000)
    return ip + transport


def rip_rte(afi: int, route_tag: int, address: str, mask: str, next_hop: str, metric: int) -> bytes:
    return (struct.pack("!HH", afi, route_tag) + ip_bytes4(address) + ip_bytes4(mask) +
            ip_bytes4(next_hop) + struct.pack("!I", metric))


def rip_auth_simple_password(password: bytes) -> bytes:
    padded = password + b"\x00" * (16 - len(password))
    return struct.pack("!HH", 0xFFFF, 2) + padded


def rip_auth_md5(rip2_packet_length: int, key_id: int, auth_data_length: int, sequence_number: int) -> bytes:
    return (struct.pack("!HHHBBI", 0xFFFF, 3, rip2_packet_length, key_id, auth_data_length,
                         sequence_number) + bytes(8))


def rip_message(command: int, version: int, rtes: list) -> bytes:
    return struct.pack("!BBH", command, version, 0) + b"".join(rtes)


def build_rip_sample():
    """RIP v1 (RFC 1058) and v2 (RFC 2453) -- the full-table-request marker, ordinary routes,
    both authentication types (Simple Password's cleartext password, and Keyed MD5's header
    fields with its trailing digest deliberately NOT located/verified -- see rip.hpp's own file
    header comment), a v1 message with a nonconformant nonzero Route Tag/Subnet Mask/Next Hop,
    trailing bytes that don't form a complete 20-byte RTE, and one deliberately non-RIP-shaped
    payload on RIP's own port 520 to exercise the structural detection gate correctly rejecting
    it (falls back to generic 'udp')."""
    packets = []

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(udp_ip_eth_frame(payload, RIP_PORT, RIP_PORT, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, RIP_PORT, RIP_PORT, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) RIPv2 Request: full routing table requested (single AFI=0 RTE, metric 16).
    add(rip_message(1, 2, [rip_rte(0, 0, "0.0.0.0", "0.0.0.0", "0.0.0.0", 16)]))

    # 2) RIPv2 Response: two ordinary routes.
    add(rip_message(2, 2, [
        rip_rte(2, 0, "10.0.0.0", "255.255.255.0", "0.0.0.0", 1),
        rip_rte(2, 5, "10.0.1.0", "255.255.255.0", "0.0.0.0", 2),
    ]), from_a=False)

    # 3) RIPv2 Response with RIPv2 Simple Password authentication (sent in cleartext on the wire,
    #    by design -- see rip.hpp's Security context note) plus one ordinary route.
    add(rip_message(2, 2, [
        rip_auth_simple_password(b"sample01"),
        rip_rte(2, 0, "10.0.2.0", "255.255.255.0", "0.0.0.0", 3),
    ]), from_a=False)

    # 4) RIPv2 Response with Keyed MD5 authentication (RFC 2082): this decoder reads the auth
    #    header's own fields but does not locate or verify the trailing digest, which is why the
    #    16 bytes standing in for that digest here show up as an explicit "trailing byte(s) ...
    #    do not form a full 20-byte RTE" note rather than being silently consumed.
    add(rip_message(2, 2, [
        rip_auth_md5(24, 1, 16, 42),
        rip_rte(2, 0, "10.0.3.0", "255.255.255.0", "0.0.0.0", 4),
    ]) + bytes(16), from_a=False)

    # 5) RIPv1 Response: one conformant route (Route Tag/Subnet Mask/Next Hop all zero, as v1 requires).
    add(rip_message(2, 1, [rip_rte(2, 0, "10.0.4.0", "0.0.0.0", "0.0.0.0", 5)]))

    # 6) RIPv1 Response with a NONCONFORMANT route -- nonzero Route Tag/Subnet Mask/Next Hop
    #    despite declaring version 1 -- triggers the "possible mislabeled RIPv2 traffic" note.
    add(rip_message(2, 1, [rip_rte(2, 7, "10.0.5.0", "255.255.255.0", "10.0.5.1", 6)]))

    # 7) Trailing garbage after one complete route: 5 stray bytes, not a full 20-byte RTE.
    add(rip_message(2, 2, [rip_rte(2, 0, "10.0.6.0", "255.255.255.0", "0.0.0.0", 7)]) + bytes(5))

    # 8) Deliberately NOT RIP: command byte 99 isn't one of RFC 1058's five values, even on RIP's
    #    own port 520 -- the structural gate must reject this (falls back to generic "udp").
    add(struct.pack("!BBH", 99, 2, 0) + rip_rte(2, 0, "10.0.7.0", "255.255.255.0", "0.0.0.0", 1))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_030_000 + i, i * 1000)
    (TESTS_DIR / "sample_rip.pcap").write_bytes(data)


def igmp_header(msg_type: int, code: int, group: str) -> bytes:
    return struct.pack("!BBH", msg_type, code, 0) + ip_bytes4(group)  # checksum left as 0


def igmp_v3_query(group: str, max_resp_code: int, s_flag: bool, qrv: int, qqic: int,
                   sources: list) -> bytes:
    s_qrv = (0x08 if s_flag else 0) | (qrv & 0x07)
    header = struct.pack("!BBH", 0x11, max_resp_code, 0) + ip_bytes4(group)
    header += struct.pack("!BBH", s_qrv, qqic, len(sources))
    for src in sources:
        header += ip_bytes4(src)
    return header  # checksum left as 0


def igmp_v3_group_record(record_type: int, aux_data_len: int, group: str, sources: list) -> bytes:
    rec = struct.pack("!BBH", record_type, aux_data_len, len(sources)) + ip_bytes4(group)
    for src in sources:
        rec += ip_bytes4(src)
    rec += bytes(aux_data_len * 4)
    return rec


def igmp_v3_report(records: list) -> bytes:
    # Type(1) + Reserved(1) + Checksum(2, left as 0) + Reserved(2) + Number of Group Records(2).
    return struct.pack("!BBHHH", 0x22, 0, 0, 0, len(records)) + b"".join(records)


def build_igmp_sample():
    """IGMP v1/v2 (RFC 1112/2236) and v3 (RFC 3376) -- rides directly on IP protocol 2, no UDP/TCP
    header at all, dispatched purely by that protocol number (see igmp.hpp). Covers a v1 Query/
    Report pair, a v2 Query/Report/Leave trio, a v3 Query with a source list and the exponential
    Max Resp Code/QQIC encoding, and a v3 Report with several group record types."""
    packets = []
    ALL_ROUTERS = "224.0.0.1"
    GROUP_A, GROUP_B = "239.1.1.1", "239.2.2.2"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, IGMP_IP_PROTOCOL, HMI_IP, ALL_ROUTERS, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, IGMP_IP_PROTOCOL, PLC_IP, GROUP_A, PLC_MAC, HMI_MAC))

    # 1) IGMPv1 General Query (Code always 0 in v1).
    add(igmp_header(0x11, 0, "0.0.0.0"))
    # 2) IGMPv1 Membership Report for GROUP_A.
    add(igmp_header(0x12, 0, GROUP_A), from_a=False)

    # 3) IGMPv2 Group-Specific Query (nonzero Max Resp Code, a plain integer -- NOT the v3
    #    exponential encoding, since this message is exactly 8 bytes).
    add(igmp_header(0x11, 100, GROUP_A))
    # 4) IGMPv2 Membership Report.
    add(igmp_header(0x16, 0, GROUP_B), from_a=False)
    # 5) IGMPv2 Leave Group.
    add(igmp_header(0x17, 0, GROUP_B), from_a=False)

    # 6) IGMPv3 General Query with a source list and an exponential-encoded Max Resp Code
    #    (0x8C = exponent 0, mantissa 0xC -> (0xC|0x10)<<3 = 0x1C<<3 = 224 -> 22.4s in tenths).
    add(igmp_v3_query("0.0.0.0", 0x8C, s_flag=True, qrv=2, qqic=125,
                       sources=["10.0.0.1", "10.0.0.2"]))

    # 7) IGMPv3 Membership Report with three group records exercising different record types.
    add(igmp_v3_report([
        igmp_v3_group_record(1, 0, GROUP_A, ["10.0.0.1", "10.0.0.2"]),  # MODE_IS_INCLUDE
        igmp_v3_group_record(2, 0, GROUP_B, []),                        # MODE_IS_EXCLUDE, no sources
        igmp_v3_group_record(5, 0, "239.3.3.3", ["10.0.0.3"]),          # ALLOW_NEW_SOURCES
    ]), from_a=False)

    # 8) Deliberately NOT IGMP: an unrecognized Type byte on IP protocol 2 -- structural gate must
    #    reject it, falling back to generic "non-tcp".
    add(struct.pack("!BBH", 0xEE, 0, 0) + ip_bytes4("0.0.0.0"))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_031_000 + i, i * 1000)
    (TESTS_DIR / "sample_igmp.pcap").write_bytes(data)


def build_icmp_sample():
    """ICMP (RFC 792, plus RFC 1191/1256 extensions) -- rides directly on IP protocol 1, the same
    "no port, dispatched purely by IP protocol number" shape as IGMP/VRRP/PIM/EIGRP/OSPF (see
    icmp.hpp's file header). Covers every Tier 1 message type this decoder fully decodes (Echo,
    Destination Unreachable including the RFC 1191 Next-Hop MTU case and the no-embedded-quote
    case, Redirect, Time Exceeded, Parameter Problem, Timestamp, Address Mask, Router
    Advertisement), a Tier 2 type left named-only (Router Solicitation), an unassigned/reserved
    type ("Unknown (N)"), a checksum mismatch, and the fewer-than-4-byte-payload edge that must
    fall through to the generic "non-tcp" fallback rather than being (mis)claimed as ICMP -- see
    try_parse_icmp's own documented nullopt condition in icmp.hpp."""
    packets = []

    def add(payload: bytes, from_hmi: bool = True):
        if from_hmi:
            packets.append(ip_eth_frame(payload, ICMP_IP_PROTOCOL, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, ICMP_IP_PROTOCOL, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) & 2) Echo Request/Reply -- a plain ping, 32 bytes of data (the common default payload
    #    size on both Windows' and Linux's ping tools).
    ping_data = bytes((0x61 + i) & 0xFF for i in range(32))  # arbitrary, fixed content
    add(icmp_message(8, 0, struct.pack("!HH", 0x1234, 1) + ping_data))
    add(icmp_message(0, 0, struct.pack("!HH", 0x1234, 1) + ping_data), from_hmi=False)

    # 3) Destination Unreachable, code 3 (Port Unreachable) -- the classic "nothing is listening"
    #    response, embedding the original UDP datagram.
    embedded_udp = icmp_embedded_datagram(HMI_IP, PLC_IP, 17, src_port=51000, dst_port=502)
    add(icmp_message(3, 3, struct.pack("!I", 0) + embedded_udp), from_hmi=False)

    # 4) Destination Unreachable, code 4 (Fragmentation Needed, RFC 1191) -- Next-Hop MTU field
    #    populated (1400, a typical VPN/tunnel-constrained MTU), embedding the original Modbus/TCP
    #    (port 502) segment.
    embedded_tcp = icmp_embedded_datagram(HMI_IP, PLC_IP, 6, src_port=51001, dst_port=502)
    add(icmp_message(3, 4, struct.pack("!HH", 0, 1400) + embedded_tcp), from_hmi=False)

    # 5) Destination Unreachable, code 1 (Host Unreachable) -- deliberately too little follows the
    #    fixed header (2 bytes) to attempt an embedded-datagram parse at all (decode_embedded_datagram
    #    requires >=20 bytes), exercising the "absent embedded_datagram" path distinctly from #3/#4.
    add(icmp_message(3, 1, struct.pack("!I", 0) + bytes([0x01, 0x02])), from_hmi=False)

    # 6) Redirect, code 1 (Redirect Datagram for the Host) -- gateway address + embedded TCP quote.
    embedded_tcp2 = icmp_embedded_datagram(HMI_IP, "192.168.1.99", 6, src_port=51002, dst_port=502)
    add(icmp_message(5, 1, ip_bytes4("192.168.1.1") + embedded_tcp2), from_hmi=False)

    # 7) Time Exceeded, code 0 (TTL Exceeded in Transit) -- a traceroute-style hop response,
    #    embedding the original UDP probe (a high, ephemeral destination port -- traceroute's own
    #    classic tell).
    embedded_udp2 = icmp_embedded_datagram(HMI_IP, "8.8.8.8", 17, src_port=51003, dst_port=33434)
    add(icmp_message(11, 0, struct.pack("!I", 0) + embedded_udp2))

    # 8) Parameter Problem, code 0 (Pointer Indicates the Error) -- pointer byte set to 0 (the IP
    #    Version/IHL byte itself), embedding the offending datagram.
    embedded_bad = icmp_embedded_datagram(HMI_IP, PLC_IP, 6, src_port=51004, dst_port=502)
    add(icmp_message(12, 0, bytes([0]) + bytes(3) + embedded_bad), from_hmi=False)

    # 9) & 10) Timestamp Request/Reply -- id/seq + originate/receive/transmit (milliseconds since
    #    UTC midnight per RFC 792 -- NOT a real epoch time, see icmp.hpp).
    add(icmp_message(13, 0, struct.pack("!HH", 0x5678, 1) + struct.pack("!III", 3_600_000, 0, 0)))
    add(icmp_message(14, 0, struct.pack("!HH", 0x5678, 1) +
                      struct.pack("!III", 3_600_000, 3_600_050, 3_600_075)), from_hmi=False)

    # 11) & 12) Address Mask Request/Reply.
    add(icmp_message(17, 0, struct.pack("!HH", 0x9ABC, 1) + ip_bytes4("0.0.0.0")))
    add(icmp_message(18, 0, struct.pack("!HH", 0x9ABC, 1) + ip_bytes4("255.255.255.0")), from_hmi=False)

    # 13) Router Advertisement (RFC 1256) -- two router addresses at the standard 2-word entry
    #     size, distinct preferences (the second deliberately negative, RFC 1256's own
    #     "least preferred" marker).
    ra_body = struct.pack("!BBH", 2, 2, 1800)
    ra_body += ip_bytes4("192.168.1.1") + struct.pack("!i", 0)
    ra_body += ip_bytes4("192.168.1.2") + struct.pack("!i", -1)
    add(icmp_message(9, 0, ra_body), from_hmi=False)

    # 14) Router Solicitation (RFC 1256) -- Tier 2, named only, no further field decode (the fixed
    #     4-byte Reserved field is all that follows Type/Code/Checksum).
    add(icmp_message(10, 0, bytes(4)))

    # 15) An unassigned/reserved ICMP type (40 -- Photuris, formally registered but essentially
    #     never seen in real OT traffic) -- must render as "Unknown (40)", never a guess.
    add(icmp_message(40, 0, bytes(4)))

    # 16) Checksum mismatch -- an explicitly wrong checksum byte on an otherwise well-formed Echo
    #     Request, so icmp_checksum_valid comes back false with a note, same "one dedicated
    #     mismatch case" convention as tests/sample_hartip_checksum.pcap's own pair.
    add(icmp_message(8, 0, struct.pack("!HH", 0xDEAD, 1) + bytes(4), checksum_override=0x0000))

    # 17) Deliberately too short to be ICMP at all -- fewer than the fixed 4-byte Type+Code+
    #     Checksum header -- try_parse_icmp's own documented nullopt condition (see icmp.hpp), so
    #     this must fall through to the generic "non-tcp" fallback, not be (mis)claimed as ICMP.
    add(bytes([0x08, 0x00]))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_040_000 + i, i * 1000)
    (TESTS_DIR / "sample_icmp.pcap").write_bytes(data)


def vrrp_message_v2(vrid: int, priority: int, addrs: list, auth_type: int = 0,
                     adver_int: int = 1, auth_data: bytes = b"") -> bytes:
    body = struct.pack("!BBBB", (2 << 4) | 1, vrid, priority, len(addrs))
    body += struct.pack("!BBH", auth_type, adver_int, 0)  # checksum left as 0
    for a in addrs:
        body += ip_bytes4(a)
    padded_auth = (auth_data + b"\x00" * 8)[:8]
    body += padded_auth
    return body


def vrrp_message_v3(vrid: int, priority: int, addrs: list, interval_centisec: int = 100) -> bytes:
    body = struct.pack("!BBBB", (3 << 4) | 1, vrid, priority, len(addrs))
    body += struct.pack("!HH", interval_centisec & 0x0FFF, 0)  # checksum left as 0
    for a in addrs:
        body += ip_bytes4(a)
    return body


def build_vrrp_sample():
    """VRRP v2 (RFC 3768) and v3 (RFC 5798) -- rides directly on IP protocol 112, no UDP/TCP
    header at all (see vrrp.hpp). Covers ordinary v2/v3 Advertisements, v2 Simple Text Password
    authentication (sent in cleartext -- see vrrp.hpp's Security context note), a Priority-0
    'master is stepping down' Advertisement, and a deliberately non-VRRP-shaped payload on IP
    protocol 112 to exercise the structural detection gate."""
    packets = []
    VRRP_GROUP = "224.0.0.18"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, VRRP_IP_PROTOCOL, HMI_IP, VRRP_GROUP, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, VRRP_IP_PROTOCOL, PLC_IP, VRRP_GROUP, PLC_MAC, HMI_MAC))

    # 1) VRRPv2 Advertisement, priority 100 (ordinary backup), no authentication, one virtual IP.
    add(vrrp_message_v2(1, 100, ["192.168.1.1"]))

    # 2) VRRPv2 Advertisement with Simple Text Password authentication.
    add(vrrp_message_v2(1, 200, ["192.168.1.1"], auth_type=1, auth_data=b"cisco12"), from_a=False)

    # 3) VRRPv2 Advertisement, priority 255 (address owner), two virtual IPs.
    add(vrrp_message_v2(2, 255, ["192.168.2.1", "192.168.2.2"]))

    # 4) VRRPv2 Advertisement, priority 0 -- the current master stepping down.
    add(vrrp_message_v2(1, 0, ["192.168.1.1"]), from_a=False)

    # 5) VRRPv3 Advertisement, centisecond interval.
    add(vrrp_message_v3(3, 100, ["192.168.3.1"], interval_centisec=100))

    # 6) Deliberately NOT VRRP: Type nibble is 2 (undefined; only 1 is ever used) -- structural
    #    gate must reject it, falling back to generic "non-tcp".
    add(struct.pack("!BBBB", (2 << 4) | 2, 1, 100, 0) + struct.pack("!BBH", 0, 1, 0))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_032_000 + i, i * 1000)
    (TESTS_DIR / "sample_vrrp.pcap").write_bytes(data)


def hsrp_v1_message(opcode: int, state: int, hellotime: int, holdtime: int, priority: int,
                     group: int, auth_data: bytes, virtual_ip: str) -> bytes:
    padded_auth = (auth_data + b"\x00" * 8)[:8]
    return (struct.pack("!BBBBBBBB", 0, opcode, state, hellotime, holdtime, priority, group, 0) +
            padded_auth + ip_bytes4(virtual_ip))


def hsrp_tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!BB", tlv_type, len(value)) + value


def hsrp_v2_group_state(version: int, opcode: int, state: int, ip_version: int, group_number: int,
                         identifier: bytes, priority: int, hello_time_ms: int, hold_time_ms: int,
                         virtual_ip: str) -> bytes:
    value = struct.pack("!BBBBH", version, opcode, state, ip_version, group_number)
    value += identifier  # 6 bytes
    value += struct.pack("!III", priority, hello_time_ms, hold_time_ms)
    value += ip_bytes4(virtual_ip)
    value += bytes(40 - len(value))  # pad to the TLV's declared 40-byte length -- see hsrp.hpp's
                                       # own file header comment on this gap for IPv4
    return hsrp_tlv(1, value)


def build_hsrp_sample():
    """HSRP v1 (RFC 2281, a fixed 20-byte message) and v2 (Cisco-proprietary TLV framing) -- see
    hsrp.hpp for the exact wire layout and how this decoder tells the two apart. Covers v1's
    Hello/Coup/Resign opcodes and its cleartext authentication field (see hsrp.hpp's Security
    context note), a v2 Group State TLV, and a deliberately non-HSRP-shaped payload on HSRP's own
    port 1985."""
    packets = []
    HSRP_GROUP = "224.0.0.102"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(udp_ip_eth_frame(payload, HSRP_PORT, HSRP_PORT, HMI_IP, HSRP_GROUP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, HSRP_PORT, HSRP_PORT, PLC_IP, HSRP_GROUP, PLC_MAC, HMI_MAC))

    # 1) HSRPv1 Hello, Active state, conventional "cisco" cleartext authentication.
    add(hsrp_v1_message(0, 16, 3, 10, 100, 1, b"cisco", "192.168.1.1"))

    # 2) HSRPv1 Coup -- a router asserting itself as the new Active router.
    add(hsrp_v1_message(1, 4, 3, 10, 110, 1, b"cisco", "192.168.1.1"), from_a=False)

    # 3) HSRPv1 Resign -- the Active router giving up the role.
    add(hsrp_v1_message(2, 8, 3, 10, 100, 1, b"cisco", "192.168.1.1"))

    # 4) HSRPv2: a single Group State TLV, Active state.
    add(hsrp_v2_group_state(2, 0, 16, 4, 1, bytes.fromhex("000c29aabbcc"), 100, 3000, 10000,
                             "192.168.2.1"))

    # 5) Deliberately NOT HSRP: a payload that is neither a valid 20-byte v1 message nor a
    #    self-consistent TLV chain -- structural gate must reject it, falling back to generic
    #    "udp".
    add(bytes([0x05, 0x00, 0x01, 0x02, 0x03]))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_033_000 + i, i * 1000)
    (TESTS_DIR / "sample_hsrp.pcap").write_bytes(data)


def igrp_route_vector(network3: bytes, delay: int, bandwidth: int, mtu: int, reliability: int,
                       load: int, hop_count: int) -> bytes:
    return (network3 + delay.to_bytes(3, "big") + bandwidth.to_bytes(3, "big") +
            struct.pack("!HBBB", mtu, reliability, load, hop_count))


def igrp_message(opcode: int, edition: int, autonomous_system: int, interior: list, system: list,
                  exterior: list, version: int = 1) -> bytes:
    header = struct.pack("!BBHHHHH", (version << 4) | opcode, edition, autonomous_system,
                          len(interior), len(system), len(exterior), 0)
    return header + b"".join(interior + system + exterior)


def build_igrp_sample():
    """Cisco IGRP (RFC-less, Cisco-proprietary) -- rides directly on IP protocol 9, no UDP/TCP
    header at all (see igrp.hpp). Covers an Update ("Response") sent from HMI_IP (192.168.1.50)
    with one Interior route (full address reconstructed by borrowing HMI_IP's own octet0=192), an
    unreachable Interior route (Delay all-ones), one System route (a bare class-A network number),
    and one Exterior route; a Request; a truncated route table (header declares 50 Interior routes
    but only one complete 14-byte vector is actually present -- must still decode that one route,
    per igrp.hpp's own graceful-degradation posture); and a payload shorter than the 12-byte header
    to exercise outright rejection."""
    packets = []
    IGRP_ALL = "255.255.255.255"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, IGRP_IP_PROTOCOL, HMI_IP, IGRP_ALL, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, IGRP_IP_PROTOCOL, PLC_IP, IGRP_ALL, PLC_MAC, HMI_MAC))

    # 1) Update ("Response") from HMI_IP: Interior route 192.168.5.0 (network3=168.5.0, borrowing
    #    HMI_IP's own octet0=192), an unreachable Interior route, a System route (10.0.0.0), and an
    #    Exterior route (172.16.0.0).
    interior = [
        igrp_route_vector(bytes([168, 5, 0]), 100, 1000, 1500, 255, 1, 2),
        igrp_route_vector(bytes([168, 6, 0]), 0xFFFFFF, 0, 1500, 255, 0, 255),  # unreachable
    ]
    system = [igrp_route_vector(bytes([10, 0, 0]), 200, 1000, 1500, 200, 0, 4)]
    exterior = [igrp_route_vector(bytes([172, 16, 0]), 300, 500, 1500, 180, 0, 6)]
    add(igrp_message(1, 5, 100, interior, system, exterior))

    # 2) Request (opcode 2) -- an empty route table request.
    add(igrp_message(2, 0, 100, [], [], []), from_a=False)

    # 3) Truncated route table: header declares 50 Interior routes but only one complete 14-byte
    #    vector is actually present.
    add(struct.pack("!BBHHHHH", (1 << 4) | 1, 0, 100, 50, 0, 0, 0) +
        igrp_route_vector(bytes([168, 7, 0]), 100, 1000, 1500, 255, 1, 2))

    # 4) Deliberately NOT IGRP: shorter than the 12-byte header -- structural gate must reject it,
    #    falling back to generic "non-tcp".
    add(bytes([0x11, 0x00, 0x00]))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_034_000 + i, i * 1000)
    (TESTS_DIR / "sample_igrp.pcap").write_bytes(data)


def pim_header(msg_type: int, version: int = 2) -> bytes:
    return struct.pack("!BBH", (version << 4) | msg_type, 0, 0)


def pim_encoded_unicast(addr: str) -> bytes:
    return struct.pack("!BB", 1, 0) + ip_bytes4(addr)


def pim_encoded_group(addr: str, mask_len: int = 32) -> bytes:
    return struct.pack("!BBBB", 1, 0, 0, mask_len) + ip_bytes4(addr)


def pim_encoded_source(addr: str, mask_len: int = 32, flags: int = 0) -> bytes:
    return struct.pack("!BBBB", 1, 0, flags, mask_len) + ip_bytes4(addr)


def pim_hello_option(option_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", option_type, len(value)) + value


def pim_hello_message(options: list) -> bytes:
    return pim_header(0) + b"".join(options)


def pim_register_message(border: bool, null_register: bool, inner_src: str, inner_group: str) -> bytes:
    flags = (0x80000000 if border else 0) | (0x40000000 if null_register else 0)
    encap = bytearray(20)
    encap[0] = 0x45  # version 4, IHL 5 -- a minimal, otherwise-unused IPv4-shaped header
    encap[12:16] = ip_bytes4(inner_src)
    encap[16:20] = ip_bytes4(inner_group)
    return pim_header(1) + struct.pack("!I", flags) + bytes(encap)


def pim_register_stop_message(group: str, source_addr: str) -> bytes:
    return pim_header(2) + pim_encoded_group(group) + pim_encoded_unicast(source_addr)


def pim_join_prune_message(msg_type: int, upstream: str, holdtime: int, groups: list) -> bytes:
    body = pim_encoded_unicast(upstream) + struct.pack("!BBH", 0, len(groups), holdtime)
    for group_addr, joins, prunes in groups:
        body += pim_encoded_group(group_addr)
        body += struct.pack("!HH", len(joins), len(prunes))
        for src in joins:
            body += pim_encoded_source(src)
        for src in prunes:
            body += pim_encoded_source(src)
    return pim_header(msg_type) + body


def pim_bootstrap_message(fragment_tag: int, hash_mask_len: int, priority: int, bsr_addr: str,
                           groups: list) -> bytes:
    body = struct.pack("!HBB", fragment_tag, hash_mask_len, priority) + pim_encoded_unicast(bsr_addr)
    for group_addr, rps in groups:
        body += pim_encoded_group(group_addr)
        body += struct.pack("!BBH", len(rps), len(rps), 0)  # RP-Count == Frag-RP-Count here
        for rp_addr, holdtime, rp_priority in rps:
            body += pim_encoded_unicast(rp_addr) + struct.pack("!HBB", holdtime, rp_priority, 0)
    return pim_header(4) + body


def pim_assert_message(group_addr: str, source_addr: str, rpt_bit: bool, metric_pref: int,
                        metric: int) -> bytes:
    rpt_and_pref = (0x80000000 if rpt_bit else 0) | (metric_pref & 0x7FFFFFFF)
    body = pim_encoded_group(group_addr) + pim_encoded_unicast(source_addr) + struct.pack(
        "!II", rpt_and_pref, metric)
    return pim_header(5) + body


def pim_cand_rp_adv_message(priority: int, holdtime: int, rp_addr: str, groups: list) -> bytes:
    body = struct.pack("!BBH", len(groups), priority, holdtime) + pim_encoded_unicast(rp_addr)
    for g in groups:
        body += pim_encoded_group(g)
    return pim_header(8) + body


def build_pim_sample():
    """PIMv2 (RFC 7761/3973) -- rides directly on IP protocol 103, no UDP/TCP header at all (see
    pim.hpp). Covers Hello (HoldTime/DR Priority/Generation ID/Address List options), Register
    (encapsulating a real IPv4-shaped inner packet), Register-Stop, Join/Prune (one group with a
    join and a prune source), Bootstrap (one candidate-RP), Assert, Candidate-RP-Advertisement, and
    a deliberately non-PIM-shaped payload (Type nibble above the highest defined value) to exercise
    the structural detection gate."""
    packets = []
    ALL_PIM_ROUTERS = "224.0.0.13"
    GROUP_A = "239.1.1.1"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, PIM_IP_PROTOCOL, HMI_IP, ALL_PIM_ROUTERS, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, PIM_IP_PROTOCOL, PLC_IP, ALL_PIM_ROUTERS, PLC_MAC, HMI_MAC))

    # 1) Hello: HoldTime, DR Priority, Generation ID, and an Address List option.
    add(pim_hello_message([
        pim_hello_option(1, struct.pack("!H", 105)),
        pim_hello_option(19, struct.pack("!I", 1)),
        pim_hello_option(20, struct.pack("!I", 0x12345678)),
        pim_hello_option(24, pim_encoded_unicast(HMI_IP)),
    ]))

    # 2) Register: encapsulates a real (source, group) = (10.0.0.5, 239.1.1.1) inner packet.
    add(pim_register_message(border=False, null_register=False, inner_src="10.0.0.5", inner_group=GROUP_A),
        from_a=False)

    # 3) Register-Stop for the same (group, source).
    add(pim_register_stop_message(GROUP_A, "10.0.0.5"))

    # 4) Join/Prune: one upstream neighbor, one group with one join source and one prune source.
    add(pim_join_prune_message(3, PLC_IP, 210, [(GROUP_A, ["10.0.0.5"], ["10.0.0.9"])]), from_a=False)

    # 5) Bootstrap: one candidate-RP for one group.
    add(pim_bootstrap_message(1, 30, 192, HMI_IP, [(GROUP_A, [(PLC_IP, 150, 1)])]))

    # 6) Assert.
    add(pim_assert_message(GROUP_A, "10.0.0.5", rpt_bit=False, metric_pref=0, metric=100), from_a=False)

    # 7) Candidate-RP-Advertisement.
    add(pim_cand_rp_adv_message(192, 150, HMI_IP, [GROUP_A]))

    # 8) Deliberately NOT PIM: Type nibble 15, above the highest type this decoder recognizes (13)
    #    -- structural gate must reject it, falling back to generic "non-tcp".
    add(struct.pack("!BBH", (2 << 4) | 15, 0, 0))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_035_000 + i, i * 1000)
    (TESTS_DIR / "sample_pim.pcap").write_bytes(data)


def eigrp_header(opcode: int, flags: int, sequence: int, acknowledge: int, vrid: int,
                  autonomous_system: int, version: int = 2) -> bytes:
    return struct.pack("!BBHIIIHH", version, opcode, 0, flags, sequence, acknowledge, vrid,
                        autonomous_system)


def eigrp_tlv(tlv_type: int, value: bytes) -> bytes:
    return struct.pack("!HH", tlv_type, len(value) + 4) + value


def eigrp_parameters_value(k1: int, k2: int, k3: int, k4: int, k5: int, k6: int, holdtime: int) -> bytes:
    return bytes([k1, k2, k3, k4, k5, k6]) + struct.pack("!H", holdtime)


def eigrp_authentication_value(auth_type: int, digest: bytes, key_id: int = 1, key_seq: int = 1) -> bytes:
    return struct.pack("!HHII", auth_type, len(digest), key_id, key_seq) + bytes(8) + digest


def eigrp_sequence_value(addrs: list) -> bytes:
    body = b""
    for a in addrs:
        body += bytes([4]) + ip_bytes4(a)
    return body


def eigrp_software_version_value(ios_major: int, ios_minor: int, tlv_major: int, tlv_minor: int) -> bytes:
    return bytes([ios_major, ios_minor, tlv_major, tlv_minor])


def eigrp_classic_metric_bytes(delay: int, bandwidth: int, mtu: int, hop_count: int, reliability: int,
                                load: int, internal_tag: int = 0, flags: int = 0) -> bytes:
    return (struct.pack("!II", delay, bandwidth) + mtu.to_bytes(3, "big") +
            struct.pack("!BBBB", hop_count, reliability, load, internal_tag) + bytes([flags]))


def eigrp_wide_metric_bytes(priority: int, reliability: int, load: int, mtu: int, hop_count: int,
                             delay_48: int, bandwidth_48: int, offset: int = 0) -> bytes:
    return (bytes([offset, priority, reliability, load]) + mtu.to_bytes(3, "big") + bytes([hop_count]) +
            delay_48.to_bytes(6, "big") + bandwidth_48.to_bytes(6, "big") + struct.pack("!HH", 0, 0))


def eigrp_external_data_bytes(orig_router: str, as_num: int, route_tag: int, ext_metric: int,
                               ext_protocol: int, is_external: bool = True,
                               is_candidate_default: bool = False) -> bytes:
    flags = (0x01 if is_external else 0) | (0x02 if is_candidate_default else 0)
    return (ip_bytes4(orig_router) + struct.pack("!III", as_num, route_tag, ext_metric) +
            struct.pack("!H", 0) + bytes([ext_protocol, flags]))


def eigrp_destination(addr: str, prefix_len: int) -> bytes:
    addr_bytes = ip_bytes4(addr)
    n = (prefix_len + 7) // 8
    return bytes([prefix_len]) + addr_bytes[:n]


def eigrp_classic_route_tlv(external: bool, next_hop: str, metric: bytes, destinations: list,
                             ext_data: bytes = b"") -> bytes:
    tlv_type = 0x0103 if external else 0x0102
    value = ip_bytes4(next_hop)
    if external:
        value += ext_data
    value += metric
    for addr, plen in destinations:
        value += eigrp_destination(addr, plen)
    return eigrp_tlv(tlv_type, value)


def eigrp_wide_route_tlv(external: bool, topology_id: int, router_id: str, wide_metric: bytes,
                          next_hop: str, destinations: list, ext_data: bytes = b"") -> bytes:
    tlv_type = 0x0603 if external else 0x0602
    value = struct.pack("!HH", topology_id, 1) + ip_bytes4(router_id)  # AFI=1 (IPv4)
    value += wide_metric
    value += ip_bytes4(next_hop)
    if external:
        value += ext_data
    for addr, plen in destinations:
        value += eigrp_destination(addr, plen)
    return eigrp_tlv(tlv_type, value)


def build_eigrp_sample():
    """Cisco EIGRP, now RFC 7868 -- rides directly on IP protocol 88, no UDP/TCP header at all (see
    eigrp.hpp). Covers a Hello with Parameters TLV; a Hello with a nonzero Acknowledge field
    (rendered as "Hello (Ack)"); an Update with Authentication, Sequence, Software Version general
    TLVs plus a Classic-format Internal route and a Classic-format External route (with two
    destination prefixes sharing one next-hop/metric, exercising EIGRP's own compound-TLV design);
    a second Update using the current Wide-Metric format for an Internal and an External route; and
    a payload shorter than the 20-byte header to exercise outright rejection."""
    packets = []
    EIGRP_ALL = "224.0.0.10"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, EIGRP_IP_PROTOCOL, HMI_IP, EIGRP_ALL, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, EIGRP_IP_PROTOCOL, PLC_IP, EIGRP_ALL, PLC_MAC, HMI_MAC))

    # 1) Hello (opcode 5), Acknowledge=0, with a Parameters TLV (K1=1,K3=1, others 0; HoldTime=15s).
    add(eigrp_header(5, 0, 0, 0, 0, 100) + eigrp_tlv(0x0001, eigrp_parameters_value(1, 0, 1, 0, 0, 0, 15)))

    # 2) Hello with a nonzero Acknowledge field -- displays as "Hello (Ack)".
    add(eigrp_header(5, 0, 0, 77, 0, 100), from_a=False)

    # 3) Update (opcode 1): Authentication (MD5, digest not verified), Sequence (one peer address),
    #    Software Version, a Classic Internal route (one destination), and a Classic External route
    #    (TWO destination prefixes sharing one next-hop/metric -- EIGRP's own compound-TLV design).
    classic_internal = eigrp_classic_route_tlv(
        False, "10.0.0.1",
        eigrp_classic_metric_bytes(100, 10000, 1500, 1, 255, 1),
        [("10.0.1.0", 24)])
    classic_external = eigrp_classic_route_tlv(
        True, "10.0.0.1",
        eigrp_classic_metric_bytes(200, 10000, 1500, 2, 255, 1),
        [("192.168.10.0", 24), ("192.168.11.0", 24)],
        ext_data=eigrp_external_data_bytes("10.0.0.9", 65000, 0, 20, 6))  # ext_protocol 6 = OSPF
    add(eigrp_header(1, 0, 1001, 0, 0, 100) +
        eigrp_tlv(0x0002, eigrp_authentication_value(2, bytes(16))) +
        eigrp_tlv(0x0003, eigrp_sequence_value([HMI_IP])) +
        eigrp_tlv(0x0004, eigrp_software_version_value(15, 2, 3, 0)) +
        classic_internal + classic_external)

    # 4) Update using the current Wide-Metric format: one Internal and one External route.
    wide_internal = eigrp_wide_route_tlv(
        False, 0, HMI_IP,
        eigrp_wide_metric_bytes(128, 255, 1, 1500, 1, 1000000, 100000),
        "10.0.0.1", [("10.0.2.0", 24)])
    wide_external = eigrp_wide_route_tlv(
        True, 0, HMI_IP,
        eigrp_wide_metric_bytes(128, 255, 1, 1500, 2, 2000000, 100000),
        "10.0.0.1", [("172.20.0.0", 16)],
        ext_data=eigrp_external_data_bytes("10.0.0.9", 65000, 0, 20, 9))  # ext_protocol 9 = BGP
    add(eigrp_header(1, 0, 1002, 0, 0, 100) + wide_internal + wide_external, from_a=False)

    # 5) Deliberately NOT EIGRP: shorter than the 20-byte header -- structural gate must reject it,
    #    falling back to generic "non-tcp".
    add(bytes([0x02, 0x05, 0x00, 0x00]))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_036_000 + i, i * 1000)
    (TESTS_DIR / "sample_eigrp.pcap").write_bytes(data)


def ospf_header(msg_type: int, router_id: str, area_id: str, packet_length: int, auth_type: int = 0,
                 auth_data: bytes = None, instance_id: int = 0) -> bytes:
    if auth_data is None:
        auth_data = bytes(8)
    else:
        auth_data = (auth_data + bytes(8))[:8]
    return (struct.pack("!BBH", 2, msg_type, packet_length) + ip_bytes4(router_id) + ip_bytes4(area_id) +
            struct.pack("!HBB", 0, instance_id, auth_type) + auth_data)


def ospf_crypto_auth_bytes(key_id: int, auth_data_len: int, seq: int) -> bytes:
    return struct.pack("!HBBI", 0, key_id, auth_data_len, seq)


def ospf_message(msg_type: int, router_id: str, area_id: str, body: bytes, auth_type: int = 0,
                  auth_data: bytes = None, instance_id: int = 0) -> bytes:
    total_len = 24 + len(body)
    header = ospf_header(msg_type, router_id, area_id, total_len, auth_type, auth_data, instance_id)
    return header + body


def ospf_hello_body(network_mask: str, hello_interval: int, options: int, priority: int,
                     dead_interval: int, dr: str, bdr: str, neighbors: list) -> bytes:
    body = (ip_bytes4(network_mask) + struct.pack("!HBBI", hello_interval, options, priority, dead_interval) +
            ip_bytes4(dr) + ip_bytes4(bdr))
    for n in neighbors:
        body += ip_bytes4(n)
    return body


def ospf_dbd_body(mtu: int, options: int, master: bool, more: bool, init: bool, seq: int,
                   lsa_headers: list) -> bytes:
    flags = (0x01 if master else 0) | (0x02 if more else 0) | (0x04 if init else 0)
    body = struct.pack("!HBBI", mtu, options, flags, seq)
    for h in lsa_headers:
        body += h
    return body


def ospf_lsa_header(age: int, options: int, lsa_type: int, link_state_id: str, adv_router: str,
                     seq: int, checksum: int, length: int, do_not_age: bool = False) -> bytes:
    age_raw = (age & 0x7FFF) | (0x8000 if do_not_age else 0)
    return (struct.pack("!HBB", age_raw, options, lsa_type) + ip_bytes4(link_state_id) +
            ip_bytes4(adv_router) + struct.pack("!IHH", seq, checksum, length))


def ospf_ls_request_entry(ls_type: int, link_state_id: str, adv_router: str) -> bytes:
    return struct.pack("!I", ls_type) + ip_bytes4(link_state_id) + ip_bytes4(adv_router)


def ospf_router_link(link_id: str, link_data: str, link_type: int, metric: int, tos_count: int = 0) -> bytes:
    return ip_bytes4(link_id) + ip_bytes4(link_data) + struct.pack("!BBH", link_type, tos_count, metric)


def ospf_router_lsa_body(border: bool, external: bool, virtual_: bool, links: list) -> bytes:
    flags = (0x01 if border else 0) | (0x02 if external else 0) | (0x04 if virtual_ else 0)
    body = struct.pack("!BBH", flags, 0, len(links))
    for l in links:
        body += l
    return body


def ospf_network_lsa_body(network_mask: str, attached_routers: list) -> bytes:
    body = ip_bytes4(network_mask)
    for r in attached_routers:
        body += ip_bytes4(r)
    return body


def ospf_summary_lsa_body(network_mask: str, metric: int, tos: int = 0) -> bytes:
    return ip_bytes4(network_mask) + bytes([tos]) + metric.to_bytes(3, "big")


def ospf_as_external_lsa_body(network_mask: str, e_bit: bool, metric: int, forwarding_address: str,
                               route_tag: int) -> bytes:
    type_and_tos = 0x80 if e_bit else 0x00
    return (ip_bytes4(network_mask) + bytes([type_and_tos]) + metric.to_bytes(3, "big") +
            ip_bytes4(forwarding_address) + struct.pack("!I", route_tag))


def ospf_lsa_full(age: int, options: int, lsa_type: int, link_state_id: str, adv_router: str, seq: int,
                   body: bytes, do_not_age: bool = False) -> bytes:
    length = 20 + len(body)
    header = ospf_lsa_header(age, options, lsa_type, link_state_id, adv_router, seq, 0, length, do_not_age)
    return header + body


def ospf_ls_update_body(lsas: list) -> bytes:
    body = struct.pack("!I", len(lsas))
    for l in lsas:
        body += l
    return body


def build_ospf_sample():
    """OSPFv2 (RFC 2328) -- rides directly on IP protocol 89, no UDP/TCP header at all (see
    ospf.hpp). Covers Hello (with one neighbor already heard from), DB Description (with two LSA
    headers), LS Request, LS Update (Router/Network/Summary/AS-External LSAs, one with the
    DoNotAge bit set), LS Ack, Simple Password and Cryptographic/MD5 authentication, and a
    deliberately non-OSPF-shaped payload (Version byte 3, i.e. OSPFv3) to exercise the structural
    detection gate."""
    packets = []
    ALL_OSPF_ROUTERS = "224.0.0.5"
    ROUTER_A, ROUTER_B = "10.0.0.1", "10.0.0.2"
    AREA0 = "0.0.0.0"

    def add(payload: bytes, from_a: bool = True):
        if from_a:
            packets.append(ip_eth_frame(payload, OSPF_IP_PROTOCOL, HMI_IP, ALL_OSPF_ROUTERS, HMI_MAC, PLC_MAC))
        else:
            packets.append(ip_eth_frame(payload, OSPF_IP_PROTOCOL, PLC_IP, ALL_OSPF_ROUTERS, PLC_MAC, HMI_MAC))

    # 1) Hello: E-bit set, one neighbor already heard from.
    hello_body = ospf_hello_body("255.255.255.0", 10, 0x02, 1, 40, ROUTER_A, "0.0.0.0", [ROUTER_B])
    add(ospf_message(1, ROUTER_A, AREA0, hello_body))

    # 2) DB Description with Simple Password authentication (cleartext) and two LSA headers
    #    (Router, Network -- headers only, no bodies).
    lsa_hdrs = [
        ospf_lsa_header(100, 0x02, 1, ROUTER_A, ROUTER_A, 0x80000001, 0, 20 + 24),
        ospf_lsa_header(200, 0x02, 2, "10.0.0.0", ROUTER_B, 0x80000001, 0, 20 + 8),
    ]
    dbd_body = ospf_dbd_body(1500, 0x02, master=True, more=False, init=False, seq=12345,
                              lsa_headers=lsa_hdrs)
    add(ospf_message(2, ROUTER_B, AREA0, dbd_body, auth_type=1, auth_data=b"cisco123"), from_a=False)

    # 3) LS Request: requesting the same two LSAs described above.
    lsr_body = (ospf_ls_request_entry(1, ROUTER_A, ROUTER_A) +
                ospf_ls_request_entry(2, "10.0.0.0", ROUTER_B))
    add(ospf_message(3, ROUTER_A, AREA0, lsr_body))

    # 4) LS Update with Cryptographic/MD5 authentication (header fields only; digest not verified):
    #    a Router-LSA (one Point-to-Point link, ABR flag set), a Network-LSA, a Summary-LSA, and an
    #    AS-External-LSA -- one of them (the Network-LSA) with the DoNotAge bit set.
    router_body = ospf_router_lsa_body(
        border=True, external=False, virtual_=False,
        links=[ospf_router_link(ROUTER_B, "10.0.0.1", 1, 10)])
    network_body = ospf_network_lsa_body("255.255.255.0", [ROUTER_A, ROUTER_B])
    summary_body = ospf_summary_lsa_body("255.255.255.0", 20)
    as_external_body = ospf_as_external_lsa_body("255.255.255.0", e_bit=True, metric=30,
                                                  forwarding_address="0.0.0.0", route_tag=100)
    lsu_body = ospf_ls_update_body([
        ospf_lsa_full(50, 0x02, 1, ROUTER_A, ROUTER_A, 0x80000002, router_body),
        ospf_lsa_full(60, 0x02, 2, "10.0.0.0", ROUTER_B, 0x80000001, network_body, do_not_age=True),
        ospf_lsa_full(70, 0x02, 3, "10.0.3.0", ROUTER_A, 0x80000001, summary_body),
        ospf_lsa_full(80, 0x02, 5, "10.0.4.0", ROUTER_A, 0x80000001, as_external_body),
    ])
    add(ospf_message(4, ROUTER_A, AREA0, lsu_body, auth_type=2,
                      auth_data=ospf_crypto_auth_bytes(1, 16, 999)), from_a=False)

    # 5) LS Ack: acknowledging the two LSA headers from the DB Description above.
    add(ospf_message(5, ROUTER_B, AREA0, b"".join(lsa_hdrs)))

    # 6) Deliberately NOT OSPF: Version byte 3 (OSPFv3, IPv6-only -- out of scope, see ospf.hpp)
    #    -- structural gate must reject it, falling back to generic "non-tcp".
    add(struct.pack("!BBH", 3, 1, 24) + ip_bytes4(ROUTER_A) + ip_bytes4(AREA0) + struct.pack("!HBB", 0, 0, 0) +
        bytes(8))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_037_000 + i, i * 1000)
    (TESTS_DIR / "sample_ospf.pcap").write_bytes(data)


def build_arp_sample():
    """ARP (RFC 826, EtherType 0x0806) -- rides directly on raw Ethernet, no IP layer, the same
    "no port, no IP layer" shape PROFINET RT/GOOSE/SV/EtherCAT/EAPOL/PPPoE/MPLS already have (see
    arp.hpp's file header comment). Frames are built directly with eth_header() + a hand-packed
    ARP body -- HTYPE(2,BE) + PTYPE(2,BE) + HLEN(1) + PLEN(1) + OPER(2,BE), then SHA(HLEN) +
    SPA(PLEN) + THA(HLEN) + TPA(PLEN) back to back, per arp.hpp's own wire-format comment -- ARP
    needs no extra outer-frame-header helper the way PROFINET/GOOSE do.

    Covers: an ARP Request, an ARP Reply, a gratuitous ARP (Reply with SPA==TPA), an ARP Probe
    (RFC 5227), an ARP Announcement (RFC 5227, wire-identical to a gratuitous Request), and a
    non-Ethernet/non-IPv4 HTYPE/PTYPE case (HTYPE=6 "IEEE 802 Networks", raw-hex SHA/SPA/THA/TPA
    fallback -- see try_parse_arp's own is_ethernet_ipv4 gate)."""
    packets = []
    BROADCAST_MAC = mac("ff:ff:ff:ff:ff:ff")
    ZERO_MAC = mac("00:00:00:00:00:00")
    NEW_HOST_MAC = mac("00:0c:29:de:ad:99")
    NEW_HOST_IP = "192.168.1.99"

    def arp_body(htype: int, ptype: int, hlen: int, plen: int, oper: int,
                 sha: bytes, spa: bytes, tha: bytes, tpa: bytes) -> bytes:
        assert len(sha) == hlen and len(tha) == hlen
        assert len(spa) == plen and len(tpa) == plen
        return struct.pack("!HHBBH", htype, ptype, hlen, plen, oper) + sha + spa + tha + tpa

    def ip4(addr: str) -> bytes:
        return bytes(int(o) for o in addr.split("."))

    def add(dst_mac: bytes, src_mac: bytes, body: bytes):
        packets.append(eth_header(dst_mac, src_mac, 0x0806) + body)

    # 1) ARP Request: HMI asking who has PLC_IP -- broadcast, THA unknown (all-zero).
    add(BROADCAST_MAC, HMI_MAC,
        arp_body(1, 0x0800, 6, 4, 1, HMI_MAC, ip4(HMI_IP), ZERO_MAC, ip4(PLC_IP)))

    # 2) ARP Reply: PLC answering, unicast back to HMI.
    add(HMI_MAC, PLC_MAC,
        arp_body(1, 0x0800, 6, 4, 2, PLC_MAC, ip4(PLC_IP), HMI_MAC, ip4(HMI_IP)))

    # 3) Gratuitous ARP: a Reply with SPA==TPA (both PLC_IP), broadcast -- the standard
    #    "IP moved to this MAC" announcement, per arp.hpp's own Gratuitous ARP paragraph.
    add(BROADCAST_MAC, PLC_MAC,
        arp_body(1, 0x0800, 6, 4, 2, PLC_MAC, ip4(PLC_IP), BROADCAST_MAC, ip4(PLC_IP)))

    # 4) ARP Probe (RFC 5227 section 1.1): Request, SPA==0.0.0.0, TPA==the address NEW_HOST_MAC
    #    is about to claim -- checking whether anyone else already holds it.
    add(BROADCAST_MAC, NEW_HOST_MAC,
        arp_body(1, 0x0800, 6, 4, 1, NEW_HOST_MAC, ip4("0.0.0.0"), ZERO_MAC, ip4(NEW_HOST_IP)))

    # 5) ARP Announcement (RFC 5227 section 2.4): Request, SPA==TPA==the newly-claimed address --
    #    wire-identical to a gratuitous Request, so both notes fire on this one frame (see
    #    arp.hpp's own Announcement paragraph).
    add(BROADCAST_MAC, NEW_HOST_MAC,
        arp_body(1, 0x0800, 6, 4, 1, NEW_HOST_MAC, ip4(NEW_HOST_IP), ZERO_MAC, ip4(NEW_HOST_IP)))

    # 6) Non-Ethernet/non-IPv4 HTYPE: HTYPE=6 ("IEEE 802 Networks", named only for HTYPE==1, so
    #    shown as a bare number here), PTYPE=0x0800 (still named "IPv4") -- is_ethernet_ipv4 stays
    #    false because HTYPE != 1, so SHA/SPA/THA/TPA render as raw hex, not a MAC/dotted-quad.
    add(BROADCAST_MAC, PLC_MAC,
        arp_body(6, 0x0800, 6, 4, 2, PLC_MAC, ip4(PLC_IP), HMI_MAC, ip4(HMI_IP)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_060_000 + i, i * 1000)
    (TESTS_DIR / "sample_arp.pcap").write_bytes(data)


def build_lldp_sample():
    """LLDP (IEEE 802.1AB, EtherType 0x88CC) -- rides directly on raw Ethernet, no IP layer, the
    same "no port, no IP layer" shape ARP/EAPOL/PPPoE/MPLS already have (see lldp.hpp's file header
    comment). Frames are built directly with eth_header() + a hand-packed sequence of TLVs -- each
    TLV a single 2-byte big-endian header packed as `(type << 9) | length` (NOT a byte-split
    type/length the way most other TLV formats in this script work -- both fields share one 16-bit
    word, per lldp.hpp's own wire-format comment), followed by `length` bytes of value.

    Covers: a well-formed PDU with just the 3 mandatory TLVs (Chassis ID as MAC, Port ID as
    interface name, TTL) plus a System Name and a System Capabilities TLV; a PDU adding Port
    Description/System Description/Management Address (IPv4); a PDU using a non-MAC/non-network-
    address Chassis ID subtype ("Locally assigned") to exercise the raw-string rendering path --
    subtype 7 happens to mean the same thing in both of LLDP's two independent Chassis-ID/Port-ID
    subtype tables (see lldp.hpp's own "non-parallel" paragraph for the subtypes that don't, e.g.
    4 = "MAC address" for Chassis ID but "Network address" for Port ID); an Organizationally
    Specific TLV using the recognized IEEE 802.3 OUI; a TTL=0 PDU (exercises the "shutting down"
    note); a malformed/truncated case (a TLV after the mandatory 3 that declares more bytes than
    are actually present -- exercises the graceful truncation fallback, not a whole-PDU decline);
    and a wrong-TLV-order negative control (Port ID before Chassis ID -- confirms this frame falls
    through to the generic ethertype-name fallback, NOT "[lldp]", the equivalent of ARP's own
    unknown-opcode-declines coverage)."""
    packets = []
    SWITCH_MGMT_IP = "192.168.1.1"
    # 01:80:c2:00:00:0e -- the standard "Nearest Bridge" LLDP multicast destination (IEEE 802.1AB
    # Table 7-1). Ethernet-II-framed (ethertype 0x88CC >= 0x0600), so this never collides with
    # stp.hpp's own LLC-framed GARP-range destination-MAC check (that check only ever runs for
    # eth.is_llc_length frames, which an EtherType >= 0x0600 frame like this one never is).
    LLDP_MULTICAST_MAC = mac("01:80:c2:00:00:0e")

    def tlv(type_: int, value: bytes) -> bytes:
        header = (type_ << 9) | len(value)
        assert 0 <= len(value) <= 0x1FF
        return struct.pack("!H", header) + value

    def add(dst_mac: bytes, src_mac: bytes, body: bytes):
        packets.append(eth_header(dst_mac, src_mac, 0x88CC) + body)

    # 1) Well-formed PDU: mandatory Chassis ID (MAC)/Port ID (interface name)/TTL, plus a System
    #    Name TLV and a System Capabilities TLV (capable=[MAC Bridge, Router], enabled=[MAC Bridge]).
    chassis1 = tlv(1, bytes([4]) + PLC_MAC)          # subtype 4 = MAC address
    port1 = tlv(2, bytes([5]) + b"eth0")              # subtype 5 = Interface name
    ttl1 = tlv(3, struct.pack("!H", 120))
    sysname1 = tlv(5, b"plc-01")
    syscap1 = tlv(7, struct.pack("!HH", 0x0014, 0x0004))  # capable=MAC Bridge|Router, enabled=MAC Bridge
    add(LLDP_MULTICAST_MAC, PLC_MAC, chassis1 + port1 + ttl1 + sysname1 + syscap1)

    # 2) Adds Port Description, System Description, and a Management Address (IPv4) TLV -- Address
    #    Subtype 1 (IPv4), Interface Numbering Subtype 2 (ifIndex), no OID.
    chassis2 = tlv(1, bytes([4]) + HMI_MAC)
    port2 = tlv(2, bytes([5]) + b"eth1")
    ttl2 = tlv(3, struct.pack("!H", 60))
    portdesc2 = tlv(4, b"Uplink to switch")
    sysdesc2 = tlv(6, b"Acme HMI Firmware 3.2")
    mgmt_addr_value = (
        bytes([5])                       # Management Address String Length: subtype(1)+addr(4)
        + bytes([1])                     # Address Subtype 1 = IPv4
        + ip4(SWITCH_MGMT_IP)             # Management Address
        + bytes([2])                     # Interface Numbering Subtype 2 = ifIndex
        + struct.pack("!I", 5)            # Interface Number
        + bytes([0])                     # OID String Length = 0 (no OID)
    )
    mgmtaddr2 = tlv(8, mgmt_addr_value)
    add(LLDP_MULTICAST_MAC, HMI_MAC, chassis2 + port2 + ttl2 + portdesc2 + sysdesc2 + mgmtaddr2)

    # 3) Chassis ID subtype 7 ("Locally assigned") -- raw-string rendering path, not MAC/network
    #    address.
    chassis3 = tlv(1, bytes([7]) + b"rack3-lldp-id")
    port3 = tlv(2, bytes([5]) + b"Gi0/1")
    ttl3 = tlv(3, struct.pack("!H", 90))
    add(LLDP_MULTICAST_MAC, PLC_MAC, chassis3 + port3 + ttl3)

    # 4) Organizationally Specific TLV, recognized IEEE 802.3 OUI (00:12:0F), arbitrary subtype/data.
    chassis4 = tlv(1, bytes([4]) + PLC_MAC)
    port4 = tlv(2, bytes([5]) + b"eth0")
    ttl4 = tlv(3, struct.pack("!H", 120))
    orgspecific4 = tlv(127, bytes([0x00, 0x12, 0x0F, 0x01]) + bytes([0xAA, 0xBB, 0xCC]))
    add(LLDP_MULTICAST_MAC, PLC_MAC, chassis4 + port4 + ttl4 + orgspecific4)

    # 5) TTL=0 -- LLDP's own "shutting down" signal.
    chassis5 = tlv(1, bytes([4]) + HMI_MAC)
    port5 = tlv(2, bytes([5]) + b"eth0")
    ttl5 = tlv(3, struct.pack("!H", 0))
    add(LLDP_MULTICAST_MAC, HMI_MAC, chassis5 + port5 + ttl5)

    # 6) Malformed/truncated: the 3 mandatory TLVs decode fine, then a trailing TLV declares a
    #    10-byte value but only 3 bytes actually follow -- graceful truncation, not a whole-PDU
    #    decline (mirrors what try_parse_lldp's own standalone unit harness already covered).
    chassis6 = tlv(1, bytes([4]) + PLC_MAC)
    port6 = tlv(2, bytes([5]) + b"eth0")
    ttl6 = tlv(3, struct.pack("!H", 120))
    broken_header = struct.pack("!H", (5 << 9) | 10)  # declares 10 bytes of System Name...
    broken_data = b"abc"                              # ...but only 3 are actually present
    add(LLDP_MULTICAST_MAC, PLC_MAC, chassis6 + port6 + ttl6 + broken_header + broken_data)

    # 7) Wrong TLV order (Port ID before Chassis ID) -- the structural detection gate declines the
    #    whole frame, which must fall through to the generic ethertype-name "[non-ip]" fallback,
    #    NOT "[lldp]" -- see lldp.hpp's own "structural detection gate" paragraph.
    chassis7 = tlv(1, bytes([4]) + PLC_MAC)
    port7 = tlv(2, bytes([5]) + b"eth0")
    ttl7 = tlv(3, struct.pack("!H", 120))
    add(LLDP_MULTICAST_MAC, PLC_MAC, port7 + chassis7 + ttl7)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_070_000 + i, i * 1000)
    (TESTS_DIR / "sample_lldp.pcap").write_bytes(data)


def build_cdp_sample():
    """Cisco Discovery Protocol (CDP) -- SNAP-encapsulated classic IEEE 802.3 LLC framing under
    Cisco's own OUI (00:00:0C), SNAP Protocol ID 0x2000 -- see cdp.hpp's file header comment for the
    exact wire format each packet below exercises (cross-checked against Wireshark's own
    packet-cdp.c and packet-cisco-oui.c).

    Covers: a full-field CDPv2 announcement (Device ID, Addresses with a real IPv4, Port ID,
    Capabilities with several bits set, Software Version, Platform, Native VLAN, Duplex, VTP
    Management Domain, System Name, Management Address, Power Consumption/Requested/Available); a
    minimal CDPv1 frame (fewer TLVs, proving version handling); a frame with an unknown/vendor
    (HP-proprietary-range) TLV type, proving the structural-only fallback; a malformed/truncated
    frame too short even for the 4-byte CDP header (proving tolerant-degrade behavior;
    try_parse_cdp declines the frame entirely, and decoder.cpp names it as CDP-but-truncated rather
    than falling back to the generic Cisco-SNAP label, since the SNAP Protocol ID already confirms
    this WAS meant to be CDP); a frame with a TLV that declares more bytes than remain (in-body
    truncation, tolerant TLV-walk degradation, not a whole-frame decline); the pinning-collision
    fixtures (a CDP-shaped SNAP frame -- SNAP Protocol ID 0x2000 -- and a non-CDP-PID Cisco SNAP
    frame using PVST+'s own SNAP Protocol ID 0x010B, proving the two are no longer conflated); and a
    negative control (a non-Cisco SNAP OUI, proving no false-positive)."""
    packets = []

    SWITCH_MGMT_IP = "192.168.1.1"
    PLC_IP = "192.168.1.50"

    # 1) Full-field CDPv2 announcement.
    caps1 = (1 << 3) | (1 << 4)  # Switch | Host
    addr1 = cdp_addresses_value([cdp_address_entry(1, bytes([0xCC]), ip4(PLC_IP))])
    body1 = (
        cdp_tlv(0x0001, b"switch-core-01.plant.local") +
        cdp_tlv(0x0002, addr1) +
        cdp_tlv(0x0003, b"GigabitEthernet0/1") +
        cdp_tlv(0x0004, struct.pack("!I", caps1)) +
        cdp_tlv(0x0005, b"Cisco IOS Software, C2960 Software, Version 15.2(2)E") +
        cdp_tlv(0x0006, b"cisco WS-C2960-24TT-L") +
        cdp_tlv(0x0009, b"PLANT-VTP-DOMAIN") +
        cdp_tlv(0x000A, struct.pack("!H", 100)) +
        cdp_tlv(0x000B, bytes([1])) +  # Full duplex
        cdp_tlv(0x0010, struct.pack("!H", 7000)) +  # Power Consumption, mW
        cdp_tlv(0x0014, b"switch-core-01") +
        cdp_tlv(0x0016, cdp_addresses_value([cdp_address_entry(1, bytes([0xCC]), ip4(SWITCH_MGMT_IP))])) +
        cdp_tlv(0x0019, struct.pack("!I", 15400)) +  # Power Requested, mW
        cdp_tlv(0x001A, struct.pack("!I", 30800))    # Power Available, mW
    )
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body1))

    # 2) Minimal CDPv1 frame -- only Device ID/Port ID/Capabilities/Software Version/Platform
    #    (CDPv1's own real-world TLV set; System Name/VTP Domain/Native VLAN/Duplex/power TLVs are
    #    CDPv2-era additions this packet deliberately omits), proving version handling.
    caps2 = 1  # Router
    body2 = (
        cdp_tlv(0x0001, b"router-edge-01") +
        cdp_tlv(0x0003, b"Ethernet0/0") +
        cdp_tlv(0x0004, struct.pack("!I", caps2)) +
        cdp_tlv(0x0005, b"Cisco IOS Software, 2600 Software, Version 12.4(15)T") +
        cdp_tlv(0x0006, b"cisco 2621XM")
    )
    packets.append(snap_cdp_frame(cdp_header(1, 180) + body2, src=HMI_MAC))

    # 3) Unknown/vendor TLV type (an HP-proprietary-range type, 0x1005) alongside a couple of
    #    curated TLVs -- proves the structural-only (name + raw hex) fallback, and that it doesn't
    #    disturb decoding of the curated TLVs around it.
    body3 = (
        cdp_tlv(0x0001, b"hp-ap-guest-03") +
        cdp_tlv(0x0003, b"wifi0") +
        cdp_tlv(0x1005, bytes([0xDE, 0xAD, 0xBE, 0xEF])) +
        cdp_tlv(0x0006, b"HP MSM430 Access Point")
    )
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body3, src=mac("00:1a:1e:aa:bb:cc")))

    # 4) Malformed/truncated: only 3 bytes present after the SNAP header -- too short even for the
    #    fixed 4-byte Version/TTL/Checksum header. try_parse_cdp declines entirely (returns
    #    std::nullopt); decoder.cpp reports this as CDP-but-truncated rather than falling back to
    #    the generic Cisco-SNAP label, since the SNAP Protocol ID (0x2000) already confirms this WAS
    #    meant to be CDP -- the same "throw/decline only when even the fixed minimum can't be read"
    #    tolerance can_socketcan.hpp's/ieee802154.hpp's own parsers already use.
    packets.append(snap_cdp_frame(b"\x02\xb4\x00"))

    # 5) A TLV that declares more bytes than remain in the frame -- in-body truncation: the 4-byte
    #    header and Device ID TLV decode fine, then a Platform TLV claims a 40-byte value but only 6
    #    bytes actually follow -- tolerant TLV-walk degradation (cdp_tlvs_truncated set, a note
    #    added), not a whole-frame decline, mirroring try_parse_lldp's own identical posture.
    broken_tlv = struct.pack("!HH", 0x0006, 44) + b"abcdef"  # declares 40 value bytes, only 6 present
    body5 = cdp_tlv(0x0001, b"truncated-switch") + broken_tlv
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body5))

    # 6) Pinning-collision fixture A: a CDP-shaped SNAP frame (SNAP Protocol ID 0x2000, the default)
    #    -- decodes as "cdp", NOT "Cisco PVST+ (SNAP-encapsulated, not decoded)". See
    #    docs/DEVELOPMENT.md's roadmap item 48 for the pre-fix mislabeling this pins against
    #    regressing back to.
    body6 = cdp_tlv(0x0001, b"pinning-fixture-cdp") + cdp_tlv(0x0003, b"Gi0/2")
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body6))

    # 7) Pinning-collision fixture B: byte-for-byte the same shape as fixture A above, EXCEPT its
    #    SNAP Protocol ID is PVSTPP_SNAP_PID (0x010B, PVST+'s own genuine PID) instead of CDP's
    #    0x2000 -- must still decode as "Cisco PVST+ (SNAP-encapsulated, not decoded)", confirming
    #    the fix didn't overcorrect into calling every Cisco-OUI SNAP frame "cdp" either.
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body6, snap_pid=PVSTPP_SNAP_PID))

    # 8) A THIRD Cisco-OUI SNAP Protocol ID that is neither CDP's (0x2000) nor PVST+'s (0x010B) --
    #    VTP's own real SNAP Protocol ID (0x2003, CISCO_PID_VTP) -- must be named generically
    #    ("Cisco SNAP frame (OUI=00:00:0C, ProtocolID=0x2003, not decoded)"), neither "cdp" nor the
    #    now-precise "Cisco PVST+" label -- proving the fix's own else-if chain is exact, not just a
    #    two-way CDP/PVST+ split.
    packets.append(snap_cdp_frame(cdp_header(2, 180) + body6, snap_pid=0x2003))

    # 9) Negative control: a non-Cisco SNAP OUI (00:00:5E, the well-known IANA OUI) under the exact
    #    same SNAP Protocol ID value as CDP's own (0x2000) -- proves detection keys on SNAP_OUI_CISCO
    #    too, not on the Protocol ID value alone; must NOT decode as "cdp".
    snap_other_oui = bytes([0x00, 0x00, 0x5E]) + struct.pack("!H", 0x2000) + cdp_header(2, 180) + body6
    packets.append(llc_length_frame(0xAA, 0xAA, 0x03, snap_other_oui))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_080_000 + i, i * 1000)
    (TESTS_DIR / "sample_cdp.pcap").write_bytes(data)


# --- BGP-4 (RFC 4271) wire-format helpers -----------------------------------------------
# See bgp.hpp's own file header comment for the exact wire format each of these mirrors.

def bgp_header(total_length: int, msg_type: int) -> bytes:
    return b"\xFF" * 16 + struct.pack("!HB", total_length, msg_type)


def bgp_capability(code: int, value: bytes) -> bytes:
    return struct.pack("!BB", code, len(value)) + value


def bgp_open(version: int, my_as: int, hold_time: int, identifier: str, capabilities) -> bytes:
    cap_bytes = b"".join(capabilities)
    opt_param = (struct.pack("!BB", 2, len(cap_bytes)) + cap_bytes) if cap_bytes else b""
    body = (
        struct.pack("!B", version)
        + struct.pack("!H", my_as)
        + struct.pack("!H", hold_time)
        + ip4(identifier)
        + struct.pack("!B", len(opt_param))
        + opt_param
    )
    return bgp_header(19 + len(body), 1) + body


def bgp_path_attr(flags: int, type_code: int, value: bytes) -> bytes:
    assert len(value) <= 255  # non-extended-length form only -- fine for this fixture
    return struct.pack("!BBB", flags, type_code, len(value)) + value


def bgp_prefix(prefix_len_bits: int, addr: str) -> bytes:
    nbytes = (prefix_len_bits + 7) // 8
    return struct.pack("!B", prefix_len_bits) + ip4(addr)[:nbytes]


def bgp_update(withdrawn: bytes, path_attrs: bytes, nlri: bytes) -> bytes:
    body = struct.pack("!H", len(withdrawn)) + withdrawn + struct.pack("!H", len(path_attrs)) + path_attrs + nlri
    return bgp_header(19 + len(body), 2) + body


def bgp_notification(error_code: int, error_subcode: int, data: bytes) -> bytes:
    body = struct.pack("!BB", error_code, error_subcode) + data
    return bgp_header(19 + len(body), 3) + body


def bgp_keepalive() -> bytes:
    return bgp_header(19, 4)


def bgp_route_refresh(afi: int, safi: int) -> bytes:
    body = struct.pack("!HBB", afi, 0, safi)
    return bgp_header(19 + len(body), 5) + body


def bgp_as_path_value(segments, four_byte: bool) -> bytes:
    """`segments` is a list of (segment_type, [as_numbers]) tuples -- see bgp.hpp's own AS_PATH
    paragraph. `four_byte` picks the 2-vs-4-byte-per-AS-number encoding."""
    fmt = "!I" if four_byte else "!H"
    out = b""
    for stype, as_list in segments:
        out += struct.pack("!BB", stype, len(as_list))
        for as_num in as_list:
            out += struct.pack(fmt, as_num)
    return out


def bgp_community_value(values) -> bytes:
    return b"".join(struct.pack("!I", v) for v in values)


def bgp_mp_reach_value(afi: int, safi: int, next_hop: str, nlri_bytes: bytes) -> bytes:
    nh = ip4(next_hop)
    return struct.pack("!HB", afi, safi) + struct.pack("!B", len(nh)) + nh + b"\x00" + nlri_bytes


def build_bgp_sample():
    """BGP-4 (RFC 4271, TCP port 179) -- the last piece of the three-stage plan that also added
    ARP and LLDP. Unlike those two, BGP needs full Ethernet+IPv4+TCP framing with real
    sequence-number tracking (see peer_a()/peer_b() below, directly modeled on
    build_twincat_sample's own client()/server() closures), since it rides on TCP and needs
    declared-length reassembly plus a coalescing loop -- see bgp.hpp's file header comment.

    All packets below share one TCP session between two BGP routers (peer A = PLC_IP/PLC_MAC,
    peer B = HMI_IP/HMI_MAC, reusing this script's existing host constants the same way
    build_twincat_sample already does for two ordinary hosts) on TCP port 179, except where noted.

    Covers, in order: (1)-(2) an OPEN exchange -- peer A's OPEN advertises both Multiprotocol
    Extensions and the 4-octet AS Number capability (RFC 6793), peer B's OPEN advertises only
    Multiprotocol Extensions (no 4-octet AS support) -- since BgpFlowState is session-scoped, not
    per-direction, processing B's (non-capable) OPEN second means the session's own AS-number
    width becomes authoritatively 2-byte from that point on, the same "session downgrades when
    either side lacks 4-octet AS support" real-world behavior RFC 6793 itself describes; (3) an
    UPDATE carrying ORIGIN/AS_PATH/NEXT_HOP/COMMUNITY/MP_REACH_NLRI in one message -- its AS_PATH
    is the "later AS_PATH attribute" that must decode using the authoritative 2-byte width
    established by (2); (4) an UPDATE that withdraws routes (WithdrawnRoutes only, no path
    attributes or NLRI); (5) three KEEPALIVEs coalesced into a single TCP segment/payload,
    exercising BgpDecoder::decode's own coalescing loop; (6) a NOTIFICATION with an RFC 8203
    shutdown communication string (Cease/Administrative Shutdown); (7)-(8) one UPDATE split across
    two TCP segments, the split point deliberately chosen AFTER the complete 19-byte header (not
    mid-header, mirroring build_twincat_sample's own precedent -- bgp_declared_length can only
    recognize a message once its own full header has arrived). Then two more TCP sessions, each
    with its own fresh BgpFlowState: (9) a ROUTE-REFRESH on a non-standard BGP port (1179, not
    179) -- exercises the "not a configured/standard BGP port" note and --bgp-port; (10) a
    negative control -- a TCP/179 payload whose leading 16 bytes are NOT all 0xFF, so BGP's own
    Marker gate declines it outright and it falls back to the generic "tcp" protocol tag."""
    packets = []

    def add(src_port, dst_port, seq, ack, payload, ident, from_a):
        tcp = tcp_header(src_port, dst_port, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (PLC_IP, HMI_IP) if from_a else (HMI_IP, PLC_IP)
        src_mac, dst_mac = (PLC_MAC, HMI_MAC) if from_a else (HMI_MAC, PLC_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    seq_a, seq_b = 1000, 5000
    ident = 0x3000

    def peer_a(payload):
        nonlocal seq_a, ident
        add(52000, 179, seq_a, seq_b, payload, ident, from_a=True)
        seq_a += len(payload)
        ident += 1

    def peer_b(payload):
        nonlocal seq_b, ident
        add(179, 52000, seq_b, seq_a, payload, ident, from_a=False)
        seq_b += len(payload)
        ident += 1

    # 1) Peer A's OPEN -- AS 65001 advertised via the 4-octet AS capability (my_as itself carries
    #    the RFC 6793 AS_TRANS placeholder, 23456, as real 4-octet-AS-capable implementations do),
    #    plus Multiprotocol Extensions (AFI=1/IPv4, SAFI=1/Unicast).
    open_a = bgp_open(
        version=4, my_as=23456, hold_time=180, identifier="10.0.0.1",
        capabilities=[
            bgp_capability(1, struct.pack("!HBB", 1, 0, 1)),
            bgp_capability(65, struct.pack("!I", 65001)),
        ],
    )
    peer_a(open_a)

    # 2) Peer B's OPEN -- AS 65002, Multiprotocol Extensions only, NO 4-octet AS capability.
    #    Processed after (1) on this same session, so BgpFlowState's own AS-number width becomes
    #    authoritatively 2-byte from here on (see this function's own docstring).
    open_b = bgp_open(
        version=4, my_as=65002, hold_time=180, identifier="10.0.0.2",
        capabilities=[bgp_capability(1, struct.pack("!HBB", 1, 0, 1))],
    )
    peer_b(open_b)

    # 3) UPDATE (peer A -> peer B): ORIGIN=IGP, AS_PATH=AS_SEQUENCE{65001,65002,65003} (2-byte
    #    AS numbers -- must decode authoritatively at 2-byte width, per (2) above), NEXT_HOP,
    #    COMMUNITY (NO_EXPORT + one uncurated raw-hex value), MP_REACH_NLRI (AFI=1/SAFI=1, two
    #    IPv4 NLRI prefixes).
    as_path_val = bgp_as_path_value([(2, [65001, 65002, 65003])], four_byte=False)
    community_val = bgp_community_value([0xFFFFFF01, 0x001E0064])
    mp_reach_val = bgp_mp_reach_value(
        1, 1, "10.0.0.1", bgp_prefix(24, "203.0.113.0") + bgp_prefix(16, "198.51.0.0"))
    path_attrs = (
        bgp_path_attr(0x40, 1, bytes([0]))            # ORIGIN = IGP
        + bgp_path_attr(0x40, 2, as_path_val)          # AS_PATH
        + bgp_path_attr(0x40, 3, ip4("10.0.0.1"))      # NEXT_HOP
        + bgp_path_attr(0xC0, 8, community_val)        # COMMUNITY
        + bgp_path_attr(0x80, 14, mp_reach_val)        # MP_REACH_NLRI
    )
    peer_a(bgp_update(withdrawn=b"", path_attrs=path_attrs, nlri=b""))

    # 4) UPDATE (peer B -> peer A): a pure withdrawal -- WithdrawnRoutes only, no path attributes,
    #    no NLRI.
    withdrawn_bytes = bgp_prefix(24, "203.0.113.0") + bgp_prefix(24, "203.0.114.0")
    peer_b(bgp_update(withdrawn=withdrawn_bytes, path_attrs=b"", nlri=b""))

    # 5) Three KEEPALIVEs coalesced into a single TCP segment (peer A -> peer B) -- exercises
    #    BgpDecoder::decode's own coalescing loop (bgp.hpp/bgp.cpp).
    peer_a(bgp_keepalive() * 3)

    # 6) NOTIFICATION (peer B -> peer A): Cease(6)/Administrative Shutdown(2), with an RFC 8203
    #    shutdown communication string.
    shutdown_text = b"Scheduled maintenance window"
    peer_b(bgp_notification(6, 2, struct.pack("!B", len(shutdown_text)) + shutdown_text))

    # 7) & 8) One UPDATE (peer A -> peer B) split across two TCP segments -- exercises
    #    BgpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the same split/rejoin
    #    shape build_twincat_sample already covers. The split point (25) is deliberately chosen to
    #    fall AFTER the complete 19-byte header (not mid-header) -- bgp_declared_length can only
    #    recognize a message that needs buffering once that whole header has arrived (see
    #    bgp_declared_length's own comment in bgp.cpp).
    split_attrs = bgp_path_attr(0x40, 1, bytes([0])) + bgp_path_attr(0x40, 3, ip4("10.0.0.1"))
    split_msg = bgp_update(withdrawn=b"", path_attrs=split_attrs, nlri=bgp_prefix(24, "192.0.2.0"))
    split_at = 25
    assert split_at > 19
    peer_a(split_msg[:split_at])
    peer_a(split_msg[split_at:])

    # 9) A second, independent TCP session (its own fresh BgpFlowState) on a non-standard BGP port
    #    (1179, not 179) -- a single ROUTE-REFRESH (AFI=1/SAFI=1). BGP's own detection gate is
    #    entirely port-independent (see bgp.hpp), so this still decodes, but gets the "not a
    #    configured/standard BGP port" note.
    add(55000, 1179, 2000, 0, bgp_route_refresh(1, 1), 0x3100, from_a=True)

    # 10) A third, independent TCP session on the standard BGP port (179) whose payload is NOT
    #     BGP-shaped at all (leading 16 bytes aren't all 0xFF) -- negative control: BGP's own
    #     Marker gate must decline this outright, falling back to the generic "tcp" protocol tag,
    #     not a crash or a false positive.
    not_bgp = b"NOT-BGP-PAYLOAD-DATA-1234567890"
    add(56000, 179, 3000, 0, not_bgp, 0x3200, from_a=True)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_080_000 + i, i * 1000)
    (TESTS_DIR / "sample_bgp.pcap").write_bytes(data)


def build_slow_protocols_sample():
    """IEEE 802.3 "Slow Protocols" (EtherType 0x8809) -- rides directly on raw Ethernet, no IP
    layer, the same "no port, no IP layer" shape ARP/LLDP already have (see slow_protocols.hpp's
    file header comment), but subtype-multiplexed: a single Subtype byte right after the EtherType
    tells apart three genuinely distinct link-layer control protocols -- LACP (subtype 0x01),
    Marker Protocol (subtype 0x02), and 802.3 OAM/EFM (subtype 0x03). Frames are built directly
    with eth_header() + a hand-packed body, per slow_protocols.hpp's own wire-format comment; no
    extra outer-frame-header helper is needed, the same posture ARP/LLDP already take.

    Covers: (1) a well-formed LACPDU with both Actor and Partner fully in sync (Activity/Timeout/
    Aggregation/Sync/Collecting/Distributing all set, no Out-of-Sync note); (2) the same LACPDU
    shape but with the Actor's Synchronization bit cleared, exercising the "LACP Out of Sync
    reported" note; (3) a negative control -- an otherwise well-formed LACPDU whose Actor
    Information TLV declares Length=19 instead of the fixed 20, breaking parse_lacp's own
    structural gate, so this frame must fall through to the generic ethertype-name "[non-ip]"
    fallback, NOT "[slow-protocols]" (the equivalent of ARP's/LLDP's own unknown-opcode/wrong-
    order negative-control coverage); (4) a Marker Information (request) TLV; (5) a Marker
    Response Information TLV echoing the same requester fields back, as a real Marker Responder
    does; (6) an OAM Information OAMPDU with the Dying Gasp flag set, carrying both a Local
    Information TLV (Mode Active, all four capability bits set) and a Remote Information TLV
    (Mode Passive, no capability bits set), each with its own OUI; (7) an OAM Event Notification
    OAMPDU carrying one Errored Frame Event TLV (type 0x02); (8) an OAM Loopback Control OAMPDU
    requesting Enable; (9) a second negative control -- an unsupported Subtype (0x0A, ESMC/
    G.8264), which try_parse_slow_protocols declines outright, also falling back to "[non-ip]"."""
    packets = []
    SLOW_PROTOCOLS_MULTICAST_MAC = mac("01:80:c2:00:00:02")  # IEEE "Slow Protocols Multicast" address
    ACTOR_SYS_MAC = mac("00:0c:29:aa:bb:cc")
    PARTNER_SYS_MAC = mac("00:0c:29:11:22:33")

    def add(dst_mac: bytes, src_mac: bytes, body: bytes):
        packets.append(eth_header(dst_mac, src_mac, 0x8809) + body)

    def lacp_pdu(actor_state: int, partner_state: int, actor_len: int = 20) -> bytes:
        actor_tlv = (
            struct.pack("!BBH", 0x01, actor_len, 32768) + ACTOR_SYS_MAC
            + struct.pack("!HHHB", 1, 32768, 1, actor_state) + b"\x00" * 3
        )
        partner_tlv = (
            struct.pack("!BBH", 0x02, 20, 32768) + PARTNER_SYS_MAC
            + struct.pack("!HHHB", 1, 32768, 1, partner_state) + b"\x00" * 3
        )
        collector_tlv = struct.pack("!BBH", 0x03, 16, 0) + b"\x00" * 12
        terminator_tlv = struct.pack("!BB", 0x00, 0x00)
        return struct.pack("!BB", 0x01, 0x01) + actor_tlv + partner_tlv + collector_tlv + terminator_tlv

    # 1) Well-formed LACPDU, Actor and Partner both fully in sync (state=0x3F: Activity|Timeout|
    #    Aggregation|Synchronization|Collecting|Distributing set, Defaulted/Expired clear).
    add(SLOW_PROTOCOLS_MULTICAST_MAC, HMI_MAC, lacp_pdu(0x3F, 0x3F))

    # 2) Same shape, but Actor's Synchronization bit (0x08) cleared -- exercises the "LACP Out of
    #    Sync reported" note.
    add(SLOW_PROTOCOLS_MULTICAST_MAC, HMI_MAC, lacp_pdu(0x37, 0x3F))

    # 3) Negative control: Actor Information TLV's own declared Length is 19, not the fixed 20 --
    #    breaks parse_lacp's structural gate (type+length match required for all four TLVs), so
    #    this must decline and fall back to the generic "[non-ip]" ethertype-name-only report.
    add(SLOW_PROTOCOLS_MULTICAST_MAC, HMI_MAC, lacp_pdu(0x3F, 0x3F, actor_len=19))

    def marker_pdu(tlv_type: int) -> bytes:
        marker_tlv = (
            struct.pack("!BB", tlv_type, 14)  # 2-byte header + 12-byte value, no pad
            + struct.pack("!H", 5) + ACTOR_SYS_MAC + struct.pack("!I", 0xDEADBEEF)
        )
        terminator_tlv = struct.pack("!BB", 0x00, 0x00)
        return struct.pack("!BB", 0x02, 0x01) + marker_tlv + terminator_tlv

    # 4) Marker Information (request): TLV type 0x01.
    add(SLOW_PROTOCOLS_MULTICAST_MAC, PLC_MAC, marker_pdu(0x01))

    # 5) Marker Response Information: TLV type 0x02, same requester fields echoed back, as a real
    #    Marker Responder does. A plausible response direction (HMI -> PLC).
    add(PLC_MAC, HMI_MAC, marker_pdu(0x02))

    # 6) OAM Information OAMPDU with the Dying Gasp flag (0x0002) set -- Local Information TLV
    #    (Mode Active, all four capability bits set) and Remote Information TLV (Mode Passive, no
    #    capability bits set), each its own 14-byte value + distinct OUI.
    def oam_info_tlv(tlv_type: int, config: int, oui_hex: str) -> bytes:
        value = (
            struct.pack("!BHBB", 1, 0, 0x00, config)  # oam_version=1, revision=0, state=0, config
            + struct.pack("!H", 1518)                  # oampdu_config ("Max OAMPDU Size") = 1518
            + bytes.fromhex(oui_hex)                    # OUI (3 bytes)
            + b"\x00\x00\x00\x00"                       # vendor specific (4 bytes)
        )
        assert len(value) == 14
        return struct.pack("!BB", tlv_type, 2 + len(value)) + value

    oam_info_body = (
        struct.pack("!B", 0x03)               # subtype=3
        + struct.pack("!H", 0x0002)            # flags: Dying Gasp
        + struct.pack("!B", 0x00)              # code=0x00 Information
        + oam_info_tlv(0x01, 0x1F, "000c29")   # Local Info: Mode Active + all 4 capability bits
        + oam_info_tlv(0x02, 0x00, "000c30")   # Remote Info: Passive, no capability bits
        + struct.pack("!BB", 0x00, 0x00)       # terminator
    )
    add(SLOW_PROTOCOLS_MULTICAST_MAC, PLC_MAC, oam_info_body)

    # 7) OAM Event Notification OAMPDU with one Errored Frame Event (type 0x02): timestamp=100,
    #    window=1000, threshold=10, errors=15, error_running_total=0, event_running_total=3.
    errored_frame_event = (
        struct.pack("!BB", 0x02, 26)   # Event TLV: type=2, length=26 (2 hdr + 24 value)
        + struct.pack("!H", 100)        # timestamp
        + struct.pack("!H", 1000)       # window
        + struct.pack("!I", 10)         # threshold
        + struct.pack("!I", 15)         # errors
        + struct.pack("!Q", 0)          # error_running_total
        + struct.pack("!I", 3)          # event_running_total
    )
    oam_event_body = (
        struct.pack("!B", 0x03)         # subtype=3
        + struct.pack("!H", 0x0000)      # flags: none set
        + struct.pack("!B", 0x01)        # code=0x01 Event Notification
        + struct.pack("!H", 42)          # sequence number
        + errored_frame_event
        + struct.pack("!B", 0x00)        # end marker
    )
    add(SLOW_PROTOCOLS_MULTICAST_MAC, PLC_MAC, oam_event_body)

    # 8) OAM Loopback Control OAMPDU requesting Enable (command byte 0x01).
    oam_loopback_body = (
        struct.pack("!B", 0x03) + struct.pack("!H", 0x0000) + struct.pack("!B", 0x04)
        + struct.pack("!B", 0x01)
    )
    add(SLOW_PROTOCOLS_MULTICAST_MAC, PLC_MAC, oam_loopback_body)

    # 9) Negative control: unsupported subtype 0x0A (ESMC/G.8264) -- try_parse_slow_protocols
    #    declines outright (see slow_protocols.hpp's own "deliberately out of scope" paragraph),
    #    falling back to the generic "[non-ip]" ethertype-name-only report, same as (3) above.
    esmc_body = struct.pack("!B", 0x0A) + b"\x01\x00\x00\x00\x00\x00"
    add(SLOW_PROTOCOLS_MULTICAST_MAC, PLC_MAC, esmc_body)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_090_000 + i, i * 1000)
    (TESTS_DIR / "sample_slow_protocols.pcap").write_bytes(data)


def build_winrm_sample():
    """WS-Management (WinRM) over plaintext HTTP, TCP port 5985 -- see winrm.hpp's own extensive
    file header comment for the wire format this exercises (verified against pywinrm's own source
    and Microsoft's MS-WSMV specification, including the empirically-corrected finding that
    CommandLine's Command/Arguments text is plain XML, NOT base64+UTF-16LE as this codebase's own
    original implementation plan assumed).

    Covers, on one realistic single-TCP-stream shell session (Create -> Command -> Send -> Receive
    -> Signal -> Delete, ShellId/CommandId correlated exactly as a real WinRS session would produce
    them -- CommandId's own two different wire shapes, element text in the Command response vs. an
    XML attribute in every later Send/Receive/Signal request, both exercised): (1)/(2) Create
    request/response -- the response triggers the "remote shell opened" flagship note (the request
    alone must NOT, since only a successful response actually proves a shell exists); (3)/(4)
    Command request/response -- the request triggers "command executed" (redacted by default, per
    DecodeContext::redact_secrets); (5)/(6) Send request/response (CommandId as an XML attribute,
    the stdin stream content itself deliberately never decoded); (7)/(8) Receive request/response
    (stdout/stderr streams plus a CommandState/Done, all deliberately never decoded either -- see
    winrm.hpp's own DELIBERATELY NOT IMPLEMENTED list); (9)/(10) Signal request/response; (11)/(12)
    Delete request/response, closing the shell.

    Plus, each on its own distinct TCP flow: (13) a CIM/WQL Enumerate request whose ResourceURI
    names a CIM class path -- triggers the CIM/WMI-query flagship note, carrying the literal WQL
    text; (14) a PSRP (PowerShell Remoting) Create request -- triggers the PSRP scope-boundary
    note; (15) a Command request authenticated with HTTP Basic instead of Negotiate -- triggers
    BOTH the "command executed" and the "HTTP Basic auth over plaintext WinRM" notes together;
    (16) a chunked-encoding negative case (Transfer-Encoding: chunked, no Content-Length, and
    deliberately no body bytes at all in this packet) -- proves the documented "not reassembled"
    limitation behaves as designed (header-only declared length, a dedicated note, no envelope
    fields populated); (17) a SOAP Fault response (HTTP 500) -- triggers the SOAP Fault note with
    its Reason/Text; (18) a 401 Unauthorized response carrying WWW-Authenticate: Negotiate and a
    non-SOAP (text/html) body -- response-side auth-scheme coverage with no envelope at all, since
    is_soap_xml is false; (19) the same Create request shape as (1)'s, but on a non-standard TCP
    port (8585) -- in Auto mode WinRmTcpDecoder's own port gate correctly declines it (proven by
    the ABSENCE of "[winrm]" -- what actually claims it in that mode is a genuine, pre-existing,
    entirely unrelated collision: MQTT's own port-independent structural check reads this request's
    leading "PO" bytes as a plausible PUBREC fixed header + remaining-length, the same way any
    POST-starting TCP payload on a port none of this codebase's other port-gated decoders claim
    first can; not a WinRM regression, and not this phase's collision to fix -- see winrm.hpp's own
    "COLLISION SURVEY" section, which only scopes the *generic-HTTP* collision). --winrm-port 8585
    widens Auto-mode detection so WinRmTcpDecoder claims it ahead of MQTT instead; --protocol winrm
    claims it port-independently too, and additionally adds the "not a configured/standard WinRM
    port" note (since the port still isn't 5985 nor in that particular invocation's widened set);
    (20) a Command request split
    across two TCP segments mid-header-block -- exercises WinRmTcpDecoder::tcp_declared_length's
    own "ask for one more byte" reassembly technique via Decoder::reassemble_tcp_payload, the same
    split/rejoin shape build_kerberos_sample already covers for Kerberos/TCP -- must decode
    identically to a whole-message case."""
    packets = []
    ident = [0xF000]

    def next_ident() -> int:
        v = ident[0]
        ident[0] += 1
        return v

    def soap_envelope(action: str, resource_uri: str = "", selector_set_xml: str = "",
                       body_xml: str = "") -> bytes:
        header_extra = ""
        if resource_uri:
            header_extra += f"<w:ResourceURI>{resource_uri}</w:ResourceURI>"
        header_extra += selector_set_xml
        xml = (
            '<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope" '
            'xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
            'xmlns:w="http://schemas.dmtf.org/wbem/wsman/1/wsman.xsd" '
            'xmlns:rsp="http://schemas.microsoft.com/wbem/wsman/1/windows/shell">'
            "<s:Header>"
            "<a:To>http://192.168.1.10:5985/wsman</a:To>"
            "<a:ReplyTo><a:Address mustUnderstand=\"true\">"
            "http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>"
            f'<a:Action mustUnderstand="true">{action}</a:Action>'
            '<w:MaxEnvelopeSize mustUnderstand="true">512000</w:MaxEnvelopeSize>'
            "<a:MessageID>uuid:11111111-2222-3333-4444-555555555555</a:MessageID>"
            "<w:OperationTimeout>PT60S</w:OperationTimeout>"
            f"{header_extra}"
            "</s:Header>"
            f"<s:Body>{body_xml}</s:Body>"
            "</s:Envelope>"
        )
        return xml.encode("utf-8")

    def selector_shell_id(shell_id: str) -> str:
        return f'<w:SelectorSet><w:Selector Name="ShellId">{shell_id}</w:Selector></w:SelectorSet>'

    def http_message(start_line: str, headers: list, body: bytes, include_content_length: bool = True) -> bytes:
        lines = [start_line]
        for k, v in headers:
            lines.append(f"{k}: {v}")
        if include_content_length:
            lines.append(f"Content-Length: {len(body)}")
        head = ("\r\n".join(lines) + "\r\n\r\n").encode("ascii")
        return head + body

    NEGOTIATE_TOKEN = base64.b64encode(b"NEGOTIATE-SPNEGO-TOKEN-PLACEHOLDER-" + b"\x00" * 24).decode()
    BASIC_CREDS = base64.b64encode(b"Administrator:Sup3rSecretPassw0rd!").decode()

    def winrm_request(target: str, action: str, resource_uri: str = "", selector_set_xml: str = "",
                       body_xml: str = "", auth: str = None, extra_headers: list = None) -> bytes:
        body = soap_envelope(action, resource_uri, selector_set_xml, body_xml)
        headers = [
            ("Content-Type", "application/soap+xml;charset=UTF-8"),
            ("User-Agent", "Microsoft WinRM Client"),
            ("Host", "192.168.1.10:5985"),
            ("Connection", "Keep-Alive"),
        ]
        if auth:
            headers.append(("Authorization", auth))
        if extra_headers:
            headers.extend(extra_headers)
        return http_message(f"POST {target} HTTP/1.1", headers, body)

    def winrm_response(status: int, reason: str, action: str = "", resource_uri: str = "",
                        selector_set_xml: str = "", body_xml: str = "", extra_headers: list = None,
                        is_soap: bool = True) -> bytes:
        body = soap_envelope(action, resource_uri, selector_set_xml, body_xml) if is_soap else body_xml.encode("utf-8")
        headers = [("Server", "Microsoft-HTTPAPI/2.0")]
        headers.append(("Content-Type", "application/soap+xml;charset=UTF-8" if is_soap else "text/html"))
        if extra_headers:
            headers.extend(extra_headers)
        return http_message(f"HTTP/1.1 {status} {reason}", headers, body)

    def session(client_port: int, server_port: int = WINRM_PORT):
        state = {"cseq": 5000, "sseq": 9000}

        def request(payload: bytes):
            tcp = tcp_header(client_port, server_port, state["cseq"], state["sseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)
            state["cseq"] += len(payload)

        def response(payload: bytes):
            tcp = tcp_header(server_port, client_port, state["sseq"], state["cseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip + tcp)
            state["sseq"] += len(payload)

        return request, response

    SHELL_CMD_RESOURCE_URI = "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/cmd"
    SHELL_ID = "AAAAAAAA-1111-2222-3333-444444444444"
    COMMAND_ID = "7777AAAA-BBBB-CCCC-DDDD-888888888888"

    # --- Main shell session: one real TCP stream, Create -> Command -> Send -> Receive -> Signal ->
    #     Delete, exactly as a real WinRS/evil-winrm session produces it. ------------------------
    main_req, main_resp = session(49500)

    # 1) Create request.
    main_req(winrm_request(
        "/wsman", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        resource_uri=SHELL_CMD_RESOURCE_URI,
        body_xml="<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
                 "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 2) Create response -- triggers "remote shell opened" (ShellId ...).
    main_resp(winrm_response(
        200, "OK", action="http://schemas.xmlsoap.org/ws/2004/09/transfer/CreateResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI,
        body_xml=(
            "<rsp:ResourceCreated><a:Address>http://192.168.1.10:5985/wsman</a:Address>"
            "<a:ReferenceParameters>"
            f"<w:ResourceURI>{SHELL_CMD_RESOURCE_URI}</w:ResourceURI>"
            f"{selector_shell_id(SHELL_ID)}"
            "</a:ReferenceParameters></rsp:ResourceCreated>")))

    # 3) Command request -- triggers "command executed" (redacted by default).
    main_req(winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id(SHELL_ID),
        body_xml="<rsp:CommandLine><rsp:Command>cmd.exe</rsp:Command>"
                 "<rsp:Arguments>/c</rsp:Arguments><rsp:Arguments>whoami /all</rsp:Arguments>"
                 "</rsp:CommandLine>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 4) Command response -- CommandId as element text (the RESPONSE-side wire shape).
    main_resp(winrm_response(
        200, "OK", action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI,
        body_xml=f"<rsp:CommandResponse><rsp:CommandId>{COMMAND_ID}</rsp:CommandId></rsp:CommandResponse>"))

    # 5) Send request -- CommandId as an XML ATTRIBUTE (the REQUEST-side wire shape), stdin stream
    #    content never decoded.
    main_req(winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Send",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id(SHELL_ID),
        body_xml=f'<rsp:Send><rsp:Stream Name="stdin" CommandId="{COMMAND_ID}">aGVsbG8NCg==</rsp:Stream></rsp:Send>',
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 6) Send response -- minimal ack.
    main_resp(winrm_response(
        200, "OK", action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SendResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI, body_xml="<rsp:SendResponse/>"))

    # 7) Receive request.
    main_req(winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Receive",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id(SHELL_ID),
        body_xml=f'<rsp:Receive><rsp:DesiredStream CommandId="{COMMAND_ID}">stdout stderr</rsp:DesiredStream>'
                 "</rsp:Receive>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 8) Receive response -- stdout/stderr streams (never decoded) plus a CommandState/Done with an
    #    ExitCode; also proves "Command" never false-matches inside "CommandState" (see
    #    find_start_tag's own exact-tag-boundary comment in winrm.cpp).
    main_resp(winrm_response(
        200, "OK", action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/ReceiveResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI,
        body_xml=(
            "<rsp:ReceiveResponse>"
            f'<rsp:Stream Name="stdout" CommandId="{COMMAND_ID}">d2hvYW1pDQo=</rsp:Stream>'
            f'<rsp:Stream Name="stderr" CommandId="{COMMAND_ID}" End="true"></rsp:Stream>'
            f'<rsp:CommandState CommandId="{COMMAND_ID}" '
            'State="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/CommandState/Done">'
            "<rsp:ExitCode>0</rsp:ExitCode></rsp:CommandState>"
            "</rsp:ReceiveResponse>")))

    # 9) Signal request (terminate) -- CommandId as an attribute directly on the Signal element.
    main_req(winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Signal",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id(SHELL_ID),
        body_xml=f'<rsp:Signal CommandId="{COMMAND_ID}">'
                 "<rsp:Code>http://schemas.microsoft.com/wbem/wsman/1/windows/shell/signal/terminate</rsp:Code>"
                 "</rsp:Signal>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 10) Signal response.
    main_resp(winrm_response(
        200, "OK", action="http://schemas.microsoft.com/wbem/wsman/1/windows/shell/SignalResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI, body_xml="<rsp:SignalResponse/>"))

    # 11) Delete request -- closes the shell.
    main_req(winrm_request(
        "/wsman", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Delete",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id(SHELL_ID),
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 12) Delete response.
    main_resp(winrm_response(
        200, "OK", action="http://schemas.xmlsoap.org/ws/2004/09/transfer/DeleteResponse",
        resource_uri=SHELL_CMD_RESOURCE_URI))

    # 13) CIM/WQL Enumerate request -- ResourceURI names a CIM class path (is_cim_query) and a WQL
    #     Filter carries the literal query text -- triggers the CIM/WMI-query flagship note.
    cim_req, _cim_resp = session(49510)
    cim_req(winrm_request(
        "/wsman", "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate",
        resource_uri="http://schemas.dmtf.org/wbem/wscim/1/cim-schema/2/Win32_Process",
        body_xml=(
            '<n:Enumerate xmlns:n="http://schemas.xmlsoap.org/ws/2004/09/enumeration">'
            '<w:Filter Dialect="http://schemas.microsoft.com/wbem/wsman/1/WQL">'
            "select * from Win32_Process where Name='cmd.exe'</w:Filter></n:Enumerate>"),
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 14) PSRP (PowerShell Remoting) Create request -- ResourceURI names a PowerShell endpoint
    #     (is_psrp) -- triggers the PSRP scope-boundary note; the nested PSRP fragment protocol
    #     itself is deliberately never decoded (see winrm.hpp's own DELIBERATELY NOT IMPLEMENTED
    #     list), so a short placeholder stands in for a real CreationXml blob.
    psrp_req, _psrp_resp = session(49520)
    psrp_req(winrm_request(
        "/wsman", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        resource_uri="http://schemas.microsoft.com/powershell/Microsoft.PowerShell",
        body_xml="<rsp:CreationXml>AAEAAAD/////AQAAAAAAAAAEAQAAAA==</rsp:CreationXml>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    # 15) Command request authenticated with HTTP Basic instead of Negotiate -- triggers BOTH
    #     "command executed" (redacted) AND "HTTP Basic auth over plaintext WinRM" together.
    basic_req, _basic_resp = session(49530)
    basic_req(winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id("BASIC-AUTH-SHELL-0001"),
        body_xml="<rsp:CommandLine><rsp:Command>powershell.exe</rsp:Command>"
                 "<rsp:Arguments>-Command</rsp:Arguments><rsp:Arguments>Get-Process</rsp:Arguments>"
                 "</rsp:CommandLine>",
        auth="Basic " + BASIC_CREDS))

    # 16) Chunked-encoding negative case -- Transfer-Encoding: chunked, no Content-Length, and
    #     deliberately no body bytes at all in this packet (see this function's own docstring):
    #     winrm_tcp_declared_length must return the header-block length alone, and try_parse_winrm_http
    #     must never attempt to scan a body for this message.
    chunked_req, _chunked_resp = session(49540)
    chunked_body_headers = [
        ("Content-Type", "application/soap+xml;charset=UTF-8"),
        ("User-Agent", "Microsoft WinRM Client"),
        ("Host", "192.168.1.10:5985"),
        ("Transfer-Encoding", "chunked"),
    ]
    chunked_req(http_message("POST /wsman HTTP/1.1", chunked_body_headers, b"", include_content_length=False))

    # 17) SOAP Fault response (HTTP 500) -- triggers the SOAP Fault note with its Reason/Text.
    _fault_req, fault_resp = session(49550)
    fault_resp(winrm_response(
        500, "Internal Server Error",
        action="http://schemas.xmlsoap.org/ws/2004/08/addressing/fault",
        body_xml=(
            "<s:Fault><s:Code><s:Value>s:Sender</s:Value>"
            "<s:Subcode><s:Value>w:AccessDenied</s:Value></s:Subcode></s:Code>"
            '<s:Reason><s:Text xml:lang="en-US">Access is denied.</s:Text></s:Reason></s:Fault>')))

    # 18) 401 Unauthorized response, WWW-Authenticate: Negotiate, non-SOAP (text/html) body --
    #     response-side auth-scheme coverage with no envelope at all (is_soap_xml is false, so the
    #     body is never scanned).
    _unauth_req, unauth_resp = session(49560)
    unauth_resp(winrm_response(
        401, "Unauthorized", is_soap=False, body_xml="<html><body>Unauthorized</body></html>",
        extra_headers=[("WWW-Authenticate", "Negotiate")]))

    # 19) The same Create request shape as (1)'s, but on a non-standard TCP port (8585) -- Auto mode
    #     must NOT recognize this as WinRM. What DOES claim it in Auto mode is a pre-existing,
    #     unrelated collision -- MQTT's own port-independent structural check reads "PO" (0x50 0x4F)
    #     as a plausible PUBREC fixed-header byte + single-byte remaining-length; this is not a
    #     WinRM regression and not the collision winrm.hpp's own header comment scopes (that one is
    #     specifically against it_protocols.cpp's generic Tier-2 "http" fallback, which this packet
    #     never even reaches). --winrm-port 8585 widens Auto-mode detection so WinRmTcpDecoder claims
    #     it ahead of MQTT instead; --protocol winrm claims it port-independently too, and adds the
    #     "not a configured/standard WinRM port" note (since the port still isn't 5985 nor in the
    #     widened set for that particular CLI invocation).
    nonstd_req, _nonstd_resp = session(49570, server_port=8585)
    nonstd_req(winrm_request(
        "/wsman", "http://schemas.xmlsoap.org/ws/2004/09/transfer/Create",
        resource_uri=SHELL_CMD_RESOURCE_URI,
        body_xml="<rsp:Shell><rsp:InputStreams>stdin</rsp:InputStreams>"
                 "<rsp:OutputStreams>stdout stderr</rsp:OutputStreams></rsp:Shell>",
        auth="Negotiate " + NEGOTIATE_TOKEN))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_100_000 + i, i * 1000)
    (TESTS_DIR / "sample_winrm.pcap").write_bytes(data)

    # 20) Command request split across two TCP segments mid-header-block -- a SEPARATE fixture file
    #     (mirrors build_kerberos_sample's own TCP-framing fixture split into its own file), since
    #     it exercises Decoder::reassemble_tcp_payload rather than a single self-contained packet.
    split_packets = []
    split_body_xml = ("<rsp:CommandLine><rsp:Command>ipconfig</rsp:Command>"
                       "<rsp:Arguments>/all</rsp:Arguments></rsp:CommandLine>")
    split_full = winrm_request(
        "/wsman", "http://schemas.microsoft.com/wbem/wsman/1/windows/shell/Command",
        resource_uri=SHELL_CMD_RESOURCE_URI, selector_set_xml=selector_shell_id("SPLIT-TEST-SHELL-0002"),
        body_xml=split_body_xml, auth="Negotiate " + NEGOTIATE_TOKEN)

    def add_split_tcp(seq: int, ack: int, payload: bytes, ident_val: int):
        tcp = tcp_header(49580, WINRM_PORT, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), ident_val)
        split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)

    split_at = 60  # well inside the header block -- Authorization: Negotiate <token> alone exceeds it.
    add_split_tcp(8000, 9000, split_full[:split_at], next_ident())
    add_split_tcp(8000 + split_at, 9000, split_full[split_at:], next_ident())

    split_data = pcap_global_header()
    for i, pkt in enumerate(split_packets):
        split_data += pcap_record(pkt, 1_700_101_000 + i, i * 1000)
    (TESTS_DIR / "sample_winrm_tcp_split.pcap").write_bytes(split_data)


# The three known DCOM activation interface UUIDs, version 0.0 -- see dcom.hpp's own KNOWN
# INTERFACES section for the empirical corrections/cross-checks behind each value (IObjectExporter
# in particular: this codebase's own original plan recollected a WRONG UUID for it, corrected here
# to the same value dcom.hpp itself uses).
IOBJECTEXPORTER_UUID = "99fcfec4-5260-101b-bbcb-00aa0021347a"
IREMOTESCMACTIVATOR_UUID = "000001a0-0000-0000-c000-000000000046"
IACTIVATION_UUID = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57"


def build_wmi_dcom_activation_sample():
    """DCOM activation/OXID-resolution, raw DCE/RPC over TCP/135 -- Phase 5 (the last) of the
    Windows RPC/remote-management batch (SAMR/LSARPC -> SRVSVC/WKSSVC -> DRSUAPI -> WinRM -> WMI/
    DCOM; see dcom.hpp's own file header comment for the full REDUCED SCOPE/TRANSPORT/STATE
    rationale). Unlike every earlier interface in this batch, DCOM activation is NOT SMB-wrapped --
    every flow below is a raw TCP/135 stream (dcerpc_pdu/dcerpc_bind_body/etc. reused directly,
    exactly as build_drsuapi_sample already reuses them, but wrapped in plain TCP packets via the
    same `session()` closure pattern build_winrm_sample established, rather than SMB WRITE/READ).

    Three flows, each its own TCP session (client port distinguishes them):

      A: IObjectExporter only -- bind (one context element) + bind_ack (accepted) + ServerAlive2
         (opnum 5, request/response pair) + ResolveOxid2 (opnum 4, request/response pair, the
         request triggering BOTH the general activation note and the ResolveOxid/ResolveOxid2
         scope-boundary note) + ComplexPing (opnum 2) whose RESPONSE is a FAULT instead of an
         ordinary response -- proves DcomFlowState's own pending_calls bookkeeping tolerates a
         fault (clears the pending call, produces no spurious DcomCall, doesn't disturb any later
         PDU on the same session).

      B: IRemoteSCMActivator + IActivation bound TOGETHER on one bind PDU (two context elements,
         both accepted in one bind_ack) -- the scenario dcom.hpp's own STATE section says
         resolve_dcerpc_bind_bookkeeping's single-target template cannot express, and the reason
         DcomFlowState tracks its own multi-target bookkeeping instead. Exercises
         RemoteGetClassObject (opnum 3) and RemoteCreateInstance (opnum 4) on IRemoteSCMActivator's
         own context, and RemoteActivation (opnum 0) on IActivation's own context -- three distinct
         request/response pairs, each correctly attributed to its own interface despite sharing one
         TCP session and one bind PDU.

      C: a bind PDU offering TWO context elements where only the SECOND is recognized -- context 0
         names an unrelated, unrecognized interface UUID, context 1 names IObjectExporter -- and
         the bind_ack REJECTS context 0 (user_rejection) while ACCEPTING context 1. This is the
         positional-correlation edge case dcom.hpp's own STATE section calls out explicitly: a
         bind_ack's own result list is positionally parallel to the bind's own context list, not
         keyed by context_id, so this proves position 1's acceptance is attributed to the right
         context_id even though position 0 was both unrecognized AND rejected. Followed by: a
         SimplePing (opnum 1) request/response pair on context 1 (IObjectExporter, decodes
         normally) and a request on context 0 (never bound at all -- neither recognized nor
         accepted) that must fall through to a bare structural PDU summary, produce no DcomCall,
         and fire no note -- this codebase's usual "flag rather than guess" bar applied to a
         context this decoder was never able to attribute to any interface at all.

      D: the same IObjectExporter bind as Flow A's, but on a non-standard TCP port (13135) --
         Auto mode must NOT recognize it (DcomTcpDecoder's own port gate declines, and unlike
         WinRM there's no pre-existing recognizer racing to claim it instead -- see dcom.hpp's own
         COLLISION SURVEY section); --dcom-port widens Auto-mode detection, --protocol dcom claims
         it port-independently and adds the "not a configured/standard DCOM port" note.

    Plus a separate TCP-framing fixture file (sample_wmi_dcom_activation_tcp_split.pcap): a bind
    PDU split across two TCP segments, the split point placed just past the 10-byte prefix
    dcerpc_tcp_declared_length itself peeks (rpc_vers/rpc_vers_minor/PTYPE/pfc_flags/packed_drep/
    frag_length) but well before the PDU's own end -- exercises Decoder::reassemble_tcp_payload's
    buffering path the same way build_winrm_sample's own split fixture does for WinRM/HTTP, and
    build_kerberos_sample's own does for Kerberos/TCP; must decode identically to a whole-message
    case once both segments arrive."""
    packets = []
    ident = [0xF100]

    def next_ident() -> int:
        v = ident[0]
        ident[0] += 1
        return v

    def session(client_port: int, server_port: int = DCOM_PORT):
        state = {"cseq": 6000, "sseq": 10000}

        def request(payload: bytes):
            tcp = tcp_header(client_port, server_port, state["cseq"], state["sseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)
            state["cseq"] += len(payload)

        def response(payload: bytes):
            tcp = tcp_header(server_port, client_port, state["sseq"], state["cseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip + tcp)
            state["sseq"] += len(payload)

        return request, response

    def dcom_bind(context_elements) -> bytes:
        return dcerpc_pdu(11, 1, dcerpc_bind_body(context_elements))  # PTYPE 11 == bind, call_id 1

    def dcom_bind_ack(results) -> bytes:
        return dcerpc_pdu(12, 1, dcerpc_bind_ack_body(results))  # PTYPE 12 == bind_ack, call_id 1

    def dcom_request(call_id: int, context_id: int, opnum: int, stub: bytes = b"") -> bytes:
        return dcerpc_pdu(0, call_id, dcerpc_request_body(context_id, opnum, stub))  # PTYPE 0 == request

    def dcom_response(call_id: int, context_id: int, stub: bytes = b"") -> bytes:
        return dcerpc_pdu(2, call_id, dcerpc_response_body(context_id, stub))  # PTYPE 2 == response

    def dcom_fault(call_id: int, context_id: int, fault_status: int = 0x1C010002) -> bytes:
        return dcerpc_pdu(3, call_id, dcerpc_fault_body(context_id, fault_status))  # PTYPE 3 == fault

    def iface_context(context_id: int, uuid: str) -> bytes:
        # All three known DCOM interfaces are version 0.0 -- see dcom.hpp's own KNOWN INTERFACES
        # section.
        return dcerpc_context_element(context_id, uuid, abstract_ver_major=0, abstract_ver_minor=0)

    # --- Flow A: IObjectExporter only. --------------------------------------------------------
    a_req, a_resp = session(50100)
    a_req(dcom_bind([iface_context(0, IOBJECTEXPORTER_UUID)]))
    a_resp(dcom_bind_ack([dcerpc_context_result(0)]))  # 0 == acceptance
    a_req(dcom_request(101, 0, 5))   # ServerAlive2
    a_resp(dcom_response(101, 0))
    a_req(dcom_request(102, 0, 4))   # ResolveOxid2 -- triggers the scope-boundary note
    a_resp(dcom_response(102, 0))
    a_req(dcom_request(103, 0, 2))   # ComplexPing -- answered with a FAULT, not a response
    a_resp(dcom_fault(103, 0))

    # --- Flow B: IRemoteSCMActivator + IActivation bound together on ONE bind PDU. -----------
    b_req, b_resp = session(50200)
    b_req(dcom_bind([iface_context(0, IREMOTESCMACTIVATOR_UUID), iface_context(1, IACTIVATION_UUID)]))
    b_resp(dcom_bind_ack([dcerpc_context_result(0), dcerpc_context_result(0)]))  # both accepted
    b_req(dcom_request(201, 0, 3))   # RemoteGetClassObject (IRemoteSCMActivator)
    b_resp(dcom_response(201, 0))
    b_req(dcom_request(202, 0, 4))   # RemoteCreateInstance (IRemoteSCMActivator)
    b_resp(dcom_response(202, 0))
    b_req(dcom_request(203, 1, 0))   # RemoteActivation (IActivation)
    b_resp(dcom_response(203, 1))

    # --- Flow C: positional bind_ack correlation with an unrecognized + rejected context 0. ---
    c_req, c_resp = session(50300)
    unrecognized_uuid = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"  # not one of this file's three known interfaces
    c_req(dcom_bind([iface_context(0, unrecognized_uuid), iface_context(1, IOBJECTEXPORTER_UUID)]))
    c_resp(dcom_bind_ack([dcerpc_context_result(1), dcerpc_context_result(0)]))  # 1 == user_rejection
    c_req(dcom_request(301, 1, 1))   # SimplePing on context 1 (IObjectExporter) -- decodes normally
    c_resp(dcom_response(301, 1))
    c_req(dcom_request(302, 0, 99))  # on context 0 -- never bound to any known interface at all;
                                      # must fall through to a bare structural summary, no DcomCall,
                                      # no note (this codebase's "flag rather than guess" bar)

    # --- Flow D: the same IObjectExporter bind as Flow A's, but on a non-standard TCP port
    #     (13135) -- in Auto mode DcomTcpDecoder's own port gate must decline it (see dcom.hpp's own
    #     COLLISION SURVEY section: unlike WinRM, there's no existing recognizer racing to claim it
    #     instead -- it simply goes unrecognized in Auto mode). --dcom-port 13135 widens Auto-mode
    #     detection so DcomTcpDecoder claims it; --protocol dcom claims it port-independently too,
    #     additionally adding the "not a configured/standard DCOM port" note.
    d_req, _d_resp = session(50500, server_port=13135)
    d_req(dcom_bind([iface_context(0, IOBJECTEXPORTER_UUID)]))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_200_000 + i, i * 1000)
    (TESTS_DIR / "sample_wmi_dcom_activation.pcap").write_bytes(data)

    # --- Separate fixture: a bind PDU split across two TCP segments, well past the 10-byte prefix
    #     dcerpc_tcp_declared_length itself peeks but before the PDU's own end. ------------------
    split_packets = []
    split_full = dcom_bind([iface_context(0, IOBJECTEXPORTER_UUID), iface_context(1, IREMOTESCMACTIVATOR_UUID)])

    def add_split_tcp(seq: int, ack: int, payload: bytes, ident_val: int):
        tcp = tcp_header(50400, DCOM_PORT, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), ident_val)
        split_packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)

    split_at = 16  # past the 10-byte prefix declared-length itself reads, before the bind body ends
    add_split_tcp(9000, 11000, split_full[:split_at], next_ident())
    add_split_tcp(9000 + split_at, 11000, split_full[split_at:], next_ident())

    split_data = pcap_global_header()
    for i, pkt in enumerate(split_packets):
        split_data += pcap_record(pkt, 1_700_201_000 + i, i * 1000)
    (TESTS_DIR / "sample_wmi_dcom_activation_tcp_split.pcap").write_bytes(split_data)


# ---------------------------------------------------------------------------------------------
# GE SRTP (Service Request Transport Protocol), TCP port 18245 -- see ge_srtp.hpp's file header
# comment for the full wire format, sourcing, and structural detection gate.

GE_SRTP_PORT = 18245

# The real captured INIT_ACK response bytes from automayt/ICS-pcap's own GE-SRTP/Notes.txt (see
# ge_srtp.hpp's file header comment's "SOURCING" section, source 4) -- 56 bytes, all zero except
# byte 0 (Packet Type low byte, == 1) and byte 8 (0x0f, unexplained by any source, deliberately NOT
# decoded by this project -- see ge_srtp.hpp's "EXPLICITLY OUT OF SCOPE" section).
GE_SRTP_REAL_INIT_ACK = bytes([0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0f] + [0x00] * 47)
assert len(GE_SRTP_REAL_INIT_ACK) == 56


def ge_srtp_header(packet_type: int, seq: int, msg_type: int, mailbox_src: int = 0,
                    mailbox_dst: int = 0x00000E10, packet_num: int = 1, total_packet_num: int = 1) -> bytes:
    """The 42-byte common header shared by every non-INIT GE SRTP message -- see ge_srtp.hpp's file
    header comment's "WIRE FORMAT" section for every field's meaning."""
    h = struct.pack("<H", packet_type)          # 0-1 Packet Type
    h += struct.pack("<H", seq)                  # 2-3 Sequence Number
    h += struct.pack("<H", 0)                     # 4-5 Text Length
    h += b"\x00" * 20                              # 6-25 reserved/unknown
    h += bytes([0, 0, 0, 0])                       # 26-29 time (s/m/h) + reserved
    h += struct.pack("<B", seq & 0xFF)             # 30 Msg Seq # (low byte of Sequence Number)
    h += struct.pack("<B", msg_type)               # 31 Message Type
    h += struct.pack("<I", mailbox_src)            # 32-35 Mailbox Source
    h += struct.pack("<I", mailbox_dst)            # 36-39 Mailbox Destination
    h += bytes([packet_num, total_packet_num])     # 40-41
    assert len(h) == 42
    return h


def ge_srtp_short_request(seq: int, service_code: int, selector: int, index: int, count: int,
                           inline_payload: bytes = b"") -> bytes:
    """SHORT request (Message Type 0xc0), 56 bytes total."""
    h = ge_srtp_header(2, seq, 0xC0)  # Packet Type 2 == REQ
    body = bytes([service_code, selector]) + struct.pack("<HH", index, count)
    body += inline_payload.ljust(6, b"\x00")[:6]
    body += b"\x00\x00"  # bytes 54-55, trailing, not independently verified
    msg = h + body
    assert len(msg) == 56
    return msg


def ge_srtp_short_response(seq: int, status: int = 0, status_minor: int = 0, return_data: bytes = b"",
                            control_program_number: int = 0x00, privilege_level: int = 0,
                            sweep_time_us: int = 0, plc_status_word: int = 0, is_error: bool = False) -> bytes:
    """SHORT_ACK (0xd4) or SHORT_ERR (0xd1) response, 56 bytes total."""
    h = ge_srtp_header(3, seq, 0xD1 if is_error else 0xD4)  # Packet Type 3 == REQ_ACK
    body = bytes([status, status_minor]) + return_data.ljust(6, b"\x00")[:6]
    body += bytes([control_program_number, privilege_level])
    body += struct.pack("<HH", sweep_time_us, plc_status_word)
    msg = h + body
    assert len(msg) == 56
    return msg


def ge_srtp_extended_request(seq: int, service_code: int, selector: int, index: int, count: int,
                              trailing: bytes = b"") -> bytes:
    """EXTENDED request (Message Type 0x80) -- 56-byte fixed header plus whatever trailing bulk
    payload the caller supplies (rides past byte 56, see ge_srtp.hpp's own "BODY, EXTENDED REQUEST"
    section)."""
    h = ge_srtp_header(2, seq, 0x80)
    body = b"\x00" * 6                              # bytes 42-47, unknown
    body += bytes([1, 1])                            # bytes 48-49, Packet#/Total Packet# repeated
    body += bytes([service_code, selector]) + struct.pack("<HH", index, count)  # bytes 50-55
    msg = h + body + trailing
    assert len(msg) == 56 + len(trailing)
    return msg


def ge_srtp_extended_ack(seq: int, undecoded_body: bytes = b"") -> bytes:
    """EXTENDED_ACK (Message Type 0x94) -- this decoder deliberately does not interpret anything
    past byte 42 for this shape (see ge_srtp.hpp's own "BODY, EXTENDED_ACK" section), so this
    fixture helper just pads/truncates whatever bytes the caller supplies to the 14 bytes (42-55)
    that keep the message a plausible, fixed 56 bytes."""
    h = ge_srtp_header(3, seq, 0x94)
    msg = h + undecoded_body.ljust(14, b"\x00")[:14]
    assert len(msg) == 56
    return msg


def build_ge_srtp_sample():
    """Covers: the real captured INIT/INIT_ACK handshake (INIT_ACK bytes taken verbatim from
    automayt/ICS-pcap's own GE-SRTP/Notes.txt, see ge_srtp.hpp's file header comment), a SHORT read
    (%R40, word) and SHORT write (%R39, the DFRWS 2017 paper's own worked "write 57 to %R39"
    example) both triggering their own memory-access security notes, a SHORT bit-mode read (%Q497,
    16 bits -- the DFRWS paper's own other worked example), a controller-type-and-id request
    (unauthenticated-reconnaissance note), a PLC run/stop request answered with a SHORT_ERR
    (insufficient-privilege-level) rejection, a program-store (upload) request (unauthenticated-
    reconnaissance-risk note), an unrecognized service request code (numeric-only fallback, proven
    both on the request AND once matched on its own response), an EXTENDED write with trailing bulk
    payload plus its own EXTENDED_ACK response (proving the deliberately-undecoded-body path), a
    structurally-recognized UNKNOWN (Packet Type 8) message, an orphan response with no matching
    request on this session (negative control), a pure gate-rejection negative control (an invalid
    Packet Type on GE SRTP's own port), a SHORT request/response pair split across two TCP segments
    (exercising GeSrtpTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload), and one
    exchange on a non-standard port (the "not a configured/standard GE SRTP port" note, --protocol
    ge-srtp only -- Auto mode is port-gated and would never attempt this one)."""
    packets = []
    ident = [0xF400]

    def next_ident() -> int:
        v = ident[0]
        ident[0] += 1
        return v

    def session(client_port: int, server_port: int = GE_SRTP_PORT):
        state = {"cseq": 4000, "sseq": 8000}

        def client(payload: bytes):
            tcp = tcp_header(client_port, server_port, state["cseq"], state["sseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip + tcp)
            state["cseq"] += len(payload)

        def server(payload: bytes):
            tcp = tcp_header(server_port, client_port, state["sseq"], state["cseq"], TCP_PSH | TCP_ACK,
                              len(payload)) + payload
            ip = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp), next_ident())
            packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip + tcp)
            state["sseq"] += len(payload)

        def server_split(payload: bytes, split_at: int):
            """Sends `payload` as two separate TCP segments (first `split_at` bytes, then the
            rest) -- exercises Decoder::reassemble_tcp_payload the same way build_melsec_sample's
            own split-response packet group does."""
            first, rest = payload[:split_at], payload[split_at:]
            for chunk in (first, rest):
                tcp = tcp_header(server_port, client_port, state["sseq"], state["cseq"],
                                  TCP_PSH | TCP_ACK, len(chunk)) + chunk
                ip = ipv4_header(PLC_IP, HMI_IP, 6, len(tcp), next_ident())
                packets.append(eth_header(HMI_MAC, PLC_MAC, 0x0800) + ip + tcp)
                state["sseq"] += len(chunk)

        return client, server, server_split

    client, server, server_split = session(53600)

    # 1) & 2) INIT / INIT_ACK connection handshake -- INIT_ACK is the real captured bytes above.
    client(bytes(56))
    server(GE_SRTP_REAL_INIT_ACK)

    # 3) & 4) SHORT read, %R40 (word): service 0x04 (read system memory), selector 0x08 (%R, word),
    #    index 39 (0-based "address - 1"), count 1. Response return_data = 1234 (LE int16).
    client(ge_srtp_short_request(1, 0x04, 0x08, 39, 1))
    server(ge_srtp_short_response(1, return_data=struct.pack("<h", 1234), control_program_number=0x00,
                                   privilege_level=1, sweep_time_us=1500, plc_status_word=0x0004))

    # 5) & 6) SHORT write, %R39 (the DFRWS 2017 paper's own worked example: writing 57dec to %R39,
    #    index 38): service 0x07 (write system memory), selector 0x08, inline payload = 57 (LE
    #    int16). Triggers the "arbitrary PLC memory write" security note.
    client(ge_srtp_short_request(2, 0x07, 0x08, 38, 1, inline_payload=struct.pack("<h", 57)))
    server(ge_srtp_short_response(2))

    # 7) & 8) SHORT read, %Q497-%Q512 (bit mode -- the DFRWS paper's own other worked example):
    #    service 0x04, selector 0x48 (%Q, bit), index 496 (address 497 - 1), count 16 bits.
    client(ge_srtp_short_request(3, 0x04, 0x48, 496, 16))
    server(ge_srtp_short_response(3, return_data=bytes([0xAB, 0xCD])))

    # 9) & 10) Get controller type and id information (service 0x43) -- unauthenticated-
    #     reconnaissance note.
    client(ge_srtp_short_request(4, 0x43, 0x00, 0, 0))
    server(ge_srtp_short_response(4, return_data=b"90-30\x00"))

    # 11) & 12) Set PLC (run vs. stop) (service 0x23) -- triggers the "no protocol-level
    #     authentication" security note -- answered with a SHORT_ERR (0xd1) rejection, status major
    #     0x02 ("insufficient privilege level").
    client(ge_srtp_short_request(5, 0x23, 0x00, 0, 0, inline_payload=bytes([1, 0, 0, 0, 0, 0])))
    server(ge_srtp_short_response(5, status=0x02, is_error=True))

    # 13) & 14) Program store (upload from PLC, service 0x3f) -- unauthenticated-reconnaissance-risk
    #     note (reveals the PLC's own control-logic program).
    client(ge_srtp_short_request(6, 0x3F, 0x00, 0, 0))
    server(ge_srtp_short_response(6))

    # 15) & 16) An unrecognized service request code (0x99, never assigned by any of this decoder's
    #     sources) -- proves the "Unknown service request code 0x99" fallback naming, both on the
    #     request itself AND once matched on its own response (which carries no service request
    #     code of its own on the wire -- see ge_srtp.hpp's "SESSION-SCOPED REQUEST/RESPONSE
    #     PAIRING" section).
    client(ge_srtp_short_request(7, 0x99, 0x08, 0, 1))
    server(ge_srtp_short_response(7))

    # 17) & 18) EXTENDED write (service 0x08, write task memory -- %R1000, 10 words, index 999),
    #     with 20 bytes of trailing bulk payload past the fixed 56-byte header -- proves
    #     has_extended_trailing_payload. Answered with EXTENDED_ACK -- proves the deliberately
    #     undecoded-body path (has_undecoded_body), since no source establishes EXTENDED_ACK's own
    #     body layout (see ge_srtp.hpp's "BODY, EXTENDED_ACK" section).
    extended_trailing = struct.pack("<10h", *range(100, 110))
    client(ge_srtp_extended_request(8, 0x08, 0x08, 999, 10, trailing=extended_trailing))
    server(ge_srtp_extended_ack(8, undecoded_body=bytes([0x00, 0x00])))

    # 19) A structurally-recognized UNKNOWN packet (Packet Type 8 -- named exactly that by the Lua
    #     dissector's own svc_type_str) -- Packet Type 8 does not validate Message Type against the
    #     5 known SHORT/EXTENDED values (see ge_srtp.hpp's own "STRUCTURAL DETECTION GATE" section),
    #     so an arbitrary Message Type byte (0xAB here) is accepted and the body is reported as an
    #     honest, undecoded hex blob rather than guessed at.
    unknown_pkt = ge_srtp_header(8, 42, 0xAB) + bytes(range(14))
    client(unknown_pkt)

    # 20) Orphan response negative control -- a SHORT_ACK carrying a Sequence Number (999) never
    #     seen as a request on this session. Proves the "no outstanding request... found" note and
    #     that has_service_request stays false rather than guessed at.
    server(ge_srtp_short_response(999))

    # 21) Pure gate rejection negative control -- Packet Type 256 (0x0100, not one of {0,1,2,3,8}),
    #     on GE SRTP's own port. Must NOT be recognized as ge-srtp at all. Byte 0 is deliberately
    #     0x00 (not a plausible MQTT control byte -- packet type nibble 0 is reserved/invalid in
    #     MQTT) and byte 1 (0x01) doesn't match TPKT's own version==3 check either, so this falls
    #     all the way through to a plain, unclassified "tcp" result rather than colliding with
    #     another protocol's own opportunistic gate.
    client(struct.pack("<H", 256) + bytes(54))

    # 22) & 23) SHORT read/response (%R1, index 0) split across TWO TCP segments -- exercises
    #     GeSrtpTcpDecoder::tcp_declared_length via Decoder::reassemble_tcp_payload, the same
    #     split/rejoin shape build_melsec_sample/build_twincat_sample already cover for their own
    #     protocols.
    client(ge_srtp_short_request(9, 0x04, 0x08, 0, 1))
    server_split(ge_srtp_short_response(9, return_data=struct.pack("<h", 7)), split_at=20)

    # 24) & 25) The same SHORT read/response exchange again, but on a non-standard port (53601 ->
    #     9999, not GE_SRTP_PORT) -- proves the "seen on TCP port ..., which is not a configured/
    #     standard GE SRTP port (18245)" note. Auto mode is port-gated for GE SRTP (see
    #     ge_srtp.hpp's own "STRUCTURAL DETECTION GATE" section) and would never attempt this
    #     exchange at all, so the dedicated CTest for this packet group runs with
    #     `--protocol ge-srtp` to force it.
    client2, server2, _ = session(53601, server_port=9999)
    client2(ge_srtp_short_request(10, 0x04, 0x08, 0, 1))
    server2(ge_srtp_short_response(10, return_data=struct.pack("<h", 99)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_210_000 + i, i * 1000)
    (TESTS_DIR / "sample_ge_srtp.pcap").write_bytes(data)


# --- BSAP (Bristol Standard Asynchronous/Synchronous Protocol) --------------------------

BSAP_PORT = 1234


def bsap_serial_local(ser: int, dfun: int, seq: int, sfun: int, nsb: int = 0x00,
                       trailing: bytes = b"", local_address: int = 0x05) -> bytes:
    """proto(0x0210, LE) + ADDR(bit 0x80 clear -> Local) + SER + DFUN + SEQ(LE) + SFUN + NSB +
    trailing -- see bsap.hpp's SERIAL-TUNNELED FRAMING / Local header."""
    return (struct.pack("<H", 0x0210) + bytes([local_address & 0x7F, ser, dfun]) +
            struct.pack("<H", seq) + bytes([sfun, nsb]) + trailing)


def bsap_serial_global(ser: int, dadd: int, sadd: int, ctl: int, dfun: int, seq: int, sfun: int,
                        nsb: int = 0x00, trailing: bytes = b"", local_address: int = 0x05) -> bytes:
    """Same as bsap_serial_local but ADDR's 0x80 bit set (-> Global) plus DADD/SADD/CTL -- see
    bsap.hpp's SERIAL-TUNNELED FRAMING / Global header."""
    return (struct.pack("<H", 0x0210) + bytes([0x80 | (local_address & 0x7F), ser]) +
            struct.pack("<H", dadd) + struct.pack("<H", sadd) + bytes([ctl, dfun]) +
            struct.pack("<H", seq) + bytes([sfun, nsb]) + trailing)


def bsap_ip_native(leading_value: int, message_func: int, trailing: bytes = b"") -> bytes:
    """proto/leading_value(LE, != 0x0210) + Message_Func(LE) + trailing -- see bsap.hpp's
    BSAP-IP-NATIVE FRAMING."""
    return struct.pack("<HH", leading_value, message_func) + trailing


def build_bsap_sample():
    """BSAP (Bristol Standard Asynchronous/Synchronous Protocol, Bristol Babcock/Emerson RTU
    protocol) -- UDP port 1234. Jurgen pointed at github.com/EmreEkin/ICS-Pcaps/tree/master/BSAAP;
    no protocol named "BSAAP" (double-A) was found anywhere in this research, so this decoder
    treats it as that repo's own naming variant for BSAP -- see bsap.hpp's own file header for the
    full sourcing writeup, including the honestly-stated gap (no numeric RDB function-code table
    found in any public source, not even the reference open-source Zeek parser this project
    cross-checked the header layout against) that keeps this fixture entirely synthetic; the
    referenced GitHub folder's own pcap could not be browsed by this session's web tools (GitHub's
    robots.txt blocks directory listings)."""
    packets = []

    def add(payload: bytes, from_hmi: bool = True, sport: int = BSAP_PORT,
             dport: int = BSAP_PORT):
        if from_hmi:
            packets.append(udp_ip_eth_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, sport, dport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) Serial-tunneled Local POLL from the master (HMI) to the RTU (PLC) -- no trailing data,
    #    the bare link-layer poll itself.
    add(bsap_serial_local(ser=1, dfun=0x85, seq=100, sfun=0x00))

    # 2) The RTU's own Local ACK/DOWN-ACK reply, carrying an opaque RDB-shaped body this decoder
    #    honestly does not further interpret (see bsap.hpp's sourcing gap).
    add(bsap_serial_local(ser=1, dfun=0x86, seq=100, sfun=0x00,
                           trailing=bytes.fromhex("01002a00000000")), from_hmi=False)

    # 3) Serial-tunneled Global message -- exercises DADD/SADD/CTL decode, a different local
    #    address (0x0A), and a different DFUN/SFUN pairing (a source-function ACK-NODATA).
    add(bsap_serial_global(ser=2, dadd=0x0005, sadd=0x0001, ctl=0x00, dfun=0x85, seq=101,
                            sfun=0x87, local_address=0x0A))

    # 4) A Local message whose DFUN is NAK (0x95) -- exercises the curated
    #    "NAK observed" note and the --stats NAK counter.
    add(bsap_serial_local(ser=3, dfun=0x95, seq=102, sfun=0x00), from_hmi=False)

    # 5) BSAP-IP-native framing: leading_value=0x0008 (not the 0x0210 serial-tunnel magic),
    #    message_func=0x0001, with a trailing body this decoder recognizes structurally but does
    #    not descend into (see bsap.hpp's BSAP-IP-NATIVE FRAMING section on why).
    add(bsap_ip_native(leading_value=0x0008, message_func=0x0001,
                        trailing=bytes.fromhex("0102030405060708")))

    # 6) NEGATIVE CONTROL: a single byte -- too short even to read the 2-byte leading field this
    #    decoder's own gate depends on entirely (try_parse_bsap's own very first check). NOTE: a
    #    4-byte-or-longer payload that doesn't start with the 0x0210 serial-tunnel magic is NOT a
    #    useful negative control here -- the BSAP-IP-native shape's own gate is honestly weak (see
    #    bsap.hpp's own file header: "no strong magic number of its own"), so it would actually
    #    parse successfully as a structurally-recognized (if semantically meaningless)
    #    BSAP-IP-native message rather than being rejected -- confirmed the hard way while building
    #    this fixture, when an earlier 4-byte "negative control" here turned out to parse cleanly.
    add(bytes([0x11]))

    # 7) & 8) The same Local POLL/ACK exchange again, but on a non-standard port (53700 -> 9999,
    #    not BSAP_PORT) -- proves the "seen on UDP port ..., which is not a configured/standard
    #    BSAP port (1234)" note. Auto mode is port-gated for BSAP (see bsap.hpp's own file header),
    #    so the dedicated CTest for this packet group runs with `--protocol bsap` to force it.
    add(bsap_serial_local(ser=4, dfun=0x85, seq=103, sfun=0x00), sport=53700, dport=9999)
    add(bsap_serial_local(ser=4, dfun=0x86, seq=103, sfun=0x00,
                           trailing=bytes.fromhex("00")), from_hmi=False, sport=9999, dport=53700)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_220_000 + i, i * 1000)
    (TESTS_DIR / "sample_bsap.pcap").write_bytes(data)


CCLINK_IE_CYCLIC_PORT = 61450
CCLINK_IE_NODE_SEARCH_PORT = 61451


def cclink_ip_le(ip: str) -> bytes:
    """4-byte little-endian encoding of an IPv4 address for CC-Link IE's own wire fields -- see
    cclink_ie.hpp's WIRE FORMAT section: the wire stores these 'Little endian', meaning the first
    wire byte is the address's last octet."""
    return bytes(reversed(socket.inet_aton(ip)))


def cclink_mac_le(mac_colon: str) -> bytes:
    """6-byte reversed MAC encoding -- see cclink_ie.hpp's own 'SLMP NODE SEARCH' section
    (cl_util_copy_mac_reverse in the reference stack)."""
    raw = bytes(int(x, 16) for x in mac_colon.split(":"))
    return bytes(reversed(raw))


def cclink_cyclic_request(master_ip: str, group_no: int, seq: int, occupied_stations: int,
                           slave_ips: list, parameter_no: int = 1, timeout_value: int = 500,
                           parallel_off_count: int = 3, cyclic_tx_state: int = 0x0001,
                           master_local_unit_info: int = 0x0001, clock_info_ms: int = 0) -> bytes:
    """CCIEFB cyclic request (command 0x0E70) -- see cclink_ie.hpp's 'CCIEFB CYCLIC' section for
    the exact field-by-field layout this reproduces."""
    cyclic_header = struct.pack("<HH", 1, 0x0000) + struct.pack("<H", 36) + bytes(14)
    master_notif = struct.pack("<HH", master_local_unit_info, 0x0000) + struct.pack("<Q", clock_info_ms)
    cyclic_data_header = (cclink_ip_le(master_ip) + bytes([group_no, 0x00]) +
                           struct.pack("<HHHHHH", seq, timeout_value, parallel_off_count,
                                       parameter_no, occupied_stations, cyclic_tx_state) +
                           struct.pack("<H", 0x0000))
    trailing = b""
    for ip in slave_ips:
        trailing += cclink_ip_le(ip)
    for i in range(occupied_stations):
        trailing += struct.pack("<32H", *[(i * 100 + j) & 0xFFFF for j in range(32)])  # RWw
    for i in range(occupied_stations):
        trailing += bytes([0x01 if i == 0 else 0x00] + [0x00] * 7)  # RY
    tail = struct.pack("<H", 0x0000) + struct.pack("<HH", 0x0E70, 0x0000) + \
        cyclic_header + master_notif + cyclic_data_header + trailing
    dl = len(tail)
    header = (struct.pack(">H", 0x5000) + bytes([0x00, 0xFF]) + struct.pack("<H", 0x03FF) +
              bytes([0x00]) + struct.pack("<H", dl))
    return header + tail


def cclink_cyclic_response(slave_ip: str, group_no: int, seq: int, occupied_stations: int,
                            end_code: int = 0x0000, vendor_code: int = 0x00A5,
                            model_code: int = 0x00001234, equipment_ver: int = 1,
                            slave_local_unit_info: int = 1, slave_err_code: int = 0,
                            local_management_info: int = 0) -> bytes:
    """CCIEFB cyclic response -- see cclink_ie.hpp's 'CCIEFB CYCLIC' section. The fixed 59-byte
    header is always present (CCIEFB's own response shape carries no shorter error variant, unlike
    generic SLMP's own rdErrMT-PDU -- see cclink_ie.hpp), even when end_code != 0."""
    cyclic_header = struct.pack("<HH", 1, end_code) + struct.pack("<H", 40) + bytes(14)
    slave_notif = (struct.pack("<HH", vendor_code, 0x0000) + struct.pack("<I", model_code) +
                   struct.pack("<HH", equipment_ver, 0x0000) +
                   struct.pack("<HH", slave_local_unit_info, slave_err_code) +
                   struct.pack("<I", local_management_info))
    cyclic_data_header = cclink_ip_le(slave_ip) + bytes([group_no, 0x00]) + struct.pack("<H", seq)
    trailing = b""
    if end_code == 0:
        for i in range(occupied_stations):
            trailing += struct.pack("<32H", *[(i * 50 + j) & 0xFFFF for j in range(32)])  # RWr
        for i in range(occupied_stations):
            trailing += bytes([0x01 if i == 0 else 0x00] + [0x00] * 7)  # RX
    tail = struct.pack("<H", 0x0000) + cyclic_header + slave_notif + cyclic_data_header + trailing
    dl = len(tail)
    header = (struct.pack(">H", 0xD000) + bytes([0x00, 0xFF]) + struct.pack("<H", 0x03FF) +
              bytes([0x00]) + struct.pack("<H", dl))
    return header + tail


def cclink_slmp_req_header(command: int, body: bytes, serial: int = 1) -> bytes:
    tail = struct.pack("<H", 0x0000) + struct.pack("<HH", command, 0x0000) + body
    length = len(tail)
    header = (struct.pack(">H", 0x5400) + struct.pack("<H", serial) + struct.pack("<H", 0x0000) +
              bytes([0x00, 0xFF]) + struct.pack("<H", 0x03FF) + bytes([0x00]) +
              struct.pack("<H", length))
    return header + tail


def cclink_slmp_resp_header(end_code: int, body: bytes, serial: int = 1) -> bytes:
    tail = struct.pack("<H", end_code) + body
    length = len(tail)
    header = (struct.pack(">H", 0xD400) + struct.pack("<H", serial) + struct.pack("<H", 0x0000) +
              bytes([0x00, 0xFF]) + struct.pack("<H", 0x03FF) + bytes([0x00]) +
              struct.pack("<H", length))
    return header + tail


def cclink_node_search_request(master_mac: str, master_ip: str, serial: int = 1) -> bytes:
    body = cclink_mac_le(master_mac) + bytes([4]) + cclink_ip_le(master_ip)
    return cclink_slmp_req_header(0x0E30, body, serial)


def cclink_node_search_response(master_mac: str, master_ip: str, slave_mac: str, slave_ip: str,
                                 slave_netmask: str, vendor_code: int, model_code: int,
                                 equipment_ver: int, slave_status: int = 0,
                                 serial: int = 1) -> bytes:
    body = (cclink_mac_le(master_mac) + bytes([4]) + cclink_ip_le(master_ip) +
            cclink_mac_le(slave_mac) + bytes([4]) + cclink_ip_le(slave_ip) +
            cclink_ip_le(slave_netmask) + cclink_ip_le("255.255.255.255") + bytes([0]) +
            struct.pack("<H", vendor_code) + struct.pack("<I", model_code) +
            struct.pack("<H", equipment_ver) + bytes([4]) + cclink_ip_le("255.255.255.255") +
            struct.pack("<H", 0xFFFF) + struct.pack("<H", slave_status) +
            struct.pack("<H", CCLINK_IE_NODE_SEARCH_PORT) + bytes([0x01]))
    return cclink_slmp_resp_header(0x0000, body, serial)


def cclink_set_ip_request(master_mac: str, master_ip: str, slave_mac: str, new_ip: str,
                           new_netmask: str, serial: int = 1) -> bytes:
    body = (cclink_mac_le(master_mac) + bytes([4]) + cclink_ip_le(master_ip) +
            cclink_mac_le(slave_mac) + bytes([4]) + cclink_ip_le(new_ip) +
            cclink_ip_le(new_netmask) + cclink_ip_le("255.255.255.255") + bytes([0]) +
            bytes([4]) + cclink_ip_le("255.255.255.255") + struct.pack("<H", 0xFFFF) +
            bytes([0x01]))
    return cclink_slmp_req_header(0x0E31, body, serial)


def cclink_set_ip_response(master_mac: str, serial: int = 1) -> bytes:
    return cclink_slmp_resp_header(0x0000, cclink_mac_le(master_mac), serial)


def cclink_slmp_error_response(end_code: int, serial: int = 1) -> bytes:
    return cclink_slmp_resp_header(end_code, b"", serial)


def build_cclink_ie_sample():
    """CC-Link IE Field Network Basic (CCIEFB) -- UDP port 61450 (cyclic data) / 61451 (SLMP node
    search / set IP address). Jurgen asked "can you add CC-Link IE?" -- see cclink_ie.hpp's own
    file header for the SCOPING DECISION (CCIEFB is the one CC-Link IE family member with public,
    cross-sourced UDP/IP wire documentation; Control/Field/TSN all require dedicated ASIC hardware
    and have none) and its SOURCING (Mitsubishi's own official reference manual + rt-labs'
    open-source c-link stack, github.com/rtlabs-com/c-link).

    Also exercises the critical MELSEC-coexistence design (see cclink_ie.hpp's 'DISPATCH ORDER'
    and 'RESPONSES CARRY NO COMMAND FIELD' sections): a genuine MELSEC command riding the exact
    same 3E framing must still decode as [melsec], and an orphan CC-Link IE response (no
    session-tracked request) must fall through to MELSEC's own generic response handling rather
    than being misattributed."""
    packets = []

    def add(payload: bytes, from_hmi: bool = True, sport: int = CCLINK_IE_CYCLIC_PORT,
             dport: int = CCLINK_IE_CYCLIC_PORT):
        if from_hmi:
            packets.append(udp_ip_eth_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, sport, dport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) & 2) Cyclic request/response pair, one occupied station, success end code -- exercises
    #    the full header field decode plus session-scoped request/response attribution.
    add(cclink_cyclic_request(master_ip=HMI_IP, group_no=1, seq=1, occupied_stations=1,
                               slave_ips=[PLC_IP], parameter_no=7))
    add(cclink_cyclic_response(slave_ip=PLC_IP, group_no=1, seq=1, occupied_stations=1),
        from_hmi=False)

    # 3) & 4) Node search request/response -- passive asset-discovery recon.
    add(cclink_node_search_request(master_mac="00:0c:29:11:22:33", master_ip=HMI_IP, serial=10),
        sport=CCLINK_IE_NODE_SEARCH_PORT, dport=CCLINK_IE_NODE_SEARCH_PORT)
    add(cclink_node_search_response(master_mac="00:0c:29:11:22:33", master_ip=HMI_IP,
                                     slave_mac="00:0c:29:aa:bb:cc", slave_ip=PLC_IP,
                                     slave_netmask="255.255.255.0", vendor_code=0x00A5,
                                     model_code=0x00001234, equipment_ver=1, serial=10),
        from_hmi=False, sport=CCLINK_IE_NODE_SEARCH_PORT, dport=CCLINK_IE_NODE_SEARCH_PORT)

    # 5) & 6) Set IP address request/response -- the genuinely attack-relevant operation (remotely
    #    reassigns a slave's own network identity, no credential documented anywhere).
    add(cclink_set_ip_request(master_mac="00:0c:29:11:22:33", master_ip=HMI_IP,
                               slave_mac="00:0c:29:aa:bb:cc", new_ip="192.168.1.11",
                               new_netmask="255.255.255.0", serial=11),
        sport=CCLINK_IE_NODE_SEARCH_PORT, dport=CCLINK_IE_NODE_SEARCH_PORT)
    add(cclink_set_ip_response(master_mac="00:0c:29:11:22:33", serial=11), from_hmi=False,
        sport=CCLINK_IE_NODE_SEARCH_PORT, dport=CCLINK_IE_NODE_SEARCH_PORT)

    # 7) ORPHAN cyclic response -- no session-tracked request precedes it (a fresh 4-tuple, ports
    #    reversed from every prior cyclic exchange above). Must NOT be claimed as cclink-ie; falls
    #    through to MELSEC's own generic response handling instead -- see cclink_ie.hpp's
    #    'RESPONSES CARRY NO COMMAND FIELD' section. The dedicated CTest for this packet asserts
    #    [melsec] with a "no outstanding request" style note, and explicitly NOT [cclink-ie].
    add(cclink_cyclic_response(slave_ip=PLC_IP, group_no=2, seq=99, occupied_stations=1),
        from_hmi=False, sport=CCLINK_IE_CYCLIC_PORT + 1, dport=CCLINK_IE_CYCLIC_PORT + 1)

    # 8) A genuine MELSEC command (Batch Read D100) riding the exact same 3E framing and port this
    #    decoder is tried on -- proves zero regression: command 0x0401 is not one of this
    #    decoder's own 3 known commands (0x0E70/0x0E30/0x0E31), so it must still decode [melsec].
    add(melsec_request(command=0x0401, subcommand=0x0000,
                        body=melsec_device("D", 100) + struct.pack("<H", 1)),
        sport=CCLINK_IE_CYCLIC_PORT, dport=CCLINK_IE_CYCLIC_PORT)

    # 9) & 10) A second cyclic request/response pair, this one reporting a non-success end code
    #    (CCIEFB: slave error) -- exercises the error-path summary/note and confirms
    #    session-scoped attribution still matches even when the response reports failure.
    add(cclink_cyclic_request(master_ip=HMI_IP, group_no=1, seq=2, occupied_stations=1,
                               slave_ips=[PLC_IP], parameter_no=7))
    add(cclink_cyclic_response(slave_ip=PLC_IP, group_no=1, seq=2, occupied_stations=0,
                                end_code=0xCFF0), from_hmi=False)

    # 11) & 12) The same cyclic request/response exchange again, but on a non-standard port pair
    #    (55000<->55001, not 61450/61451) -- proves the "not a configured/standard CC-Link IE
    #    port" note; CC-Link IE is UdpPortIndependent (unlike BSAP's own UdpPort gating), so Auto
    #    mode still claims it without needing --protocol cclink-ie.
    add(cclink_cyclic_request(master_ip=HMI_IP, group_no=1, seq=3, occupied_stations=1,
                               slave_ips=[PLC_IP], parameter_no=7), sport=55000, dport=55001)
    add(cclink_cyclic_response(slave_ip=PLC_IP, group_no=1, seq=3, occupied_stations=1),
        from_hmi=False, sport=55001, dport=55000)

    # 13) NEGATIVE CONTROL: a 2-byte payload carrying only the 3E-frame request magic (0x5000),
    #     too short for either this decoder's or MELSEC's own header to be read at all -- must
    #     fall through cleanly to generic [udp], not be claimed by either decoder.
    add(struct.pack(">H", 0x5000), sport=CCLINK_IE_CYCLIC_PORT + 2, dport=CCLINK_IE_CYCLIC_PORT + 2)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_230_000 + i, i * 1000)
    (TESTS_DIR / "sample_cclink_ie.pcap").write_bytes(data)


def ipv4_header_ex(src: str, dst: str, protocol: int, payload_len: int, ident: int,
                    flags_and_offset: int = 0x4000, options: bytes = b"") -> bytes:
    """Like ipv4_header, but with caller control over the Flags+Fragment-Offset field (default
    0x4000 = DF set, offset 0, matching ipv4_header's own hardcoded value) and raw IP options
    bytes -- needed for attack_detect.hpp's fragmentation-based (Teardrop/Ping of Death) and IP-
    option-based (Source Routing) fixture packets, none of which ipv4_header's own fixed-shape
    (DF-only, no-options) header can produce. `options` must already be padded by the caller to a
    multiple of 4 bytes (ihl_words must be a whole number of 32-bit words) -- not padded
    automatically here, so a caller building a malformed-on-purpose options block stays in full
    control."""
    def ip_bytes(addr):
        return bytes(int(o) for o in addr.split("."))

    ihl_words = 5 + len(options) // 4
    assert len(options) % 4 == 0, "options must be padded to a multiple of 4 bytes"
    total_length = ihl_words * 4 + payload_len
    return struct.pack(
        "!BBHHHBBH4s4s",
        0x40 | ihl_words,
        0,                # ToS
        total_length,
        ident,
        flags_and_offset,
        64,               # TTL
        protocol,
        0,                # checksum -- not validated by conduitscope; left as 0
        ip_bytes(src),
        ip_bytes(dst),
    ) + options


def tcp_header_ex(src_port: int, dst_port: int, seq: int, ack: int, flags: int, payload_len: int,
                   urgent_pointer: int = 0) -> bytes:
    """Like tcp_header, but with caller control over the Urgent Pointer field (hardcoded to 0 in
    tcp_header) -- needed for attack_detect.hpp's WinNuke fixture packet (tcp.hpp's
    TcpSegment::urgent_pointer, the field WinNuke detection reads)."""
    return struct.pack(
        "!HHIIBBHHH",
        src_port, dst_port,
        seq, ack,
        0x50,             # data offset = 5 words, no options
        flags,
        8192,             # window
        0,                # checksum -- not validated
        urgent_pointer,
    )


def build_attack_detect_sample():
    """attack_detect.hpp -- classic network-layer DoS/reconnaissance attack signatures Jurgen
    asked for by name (LAND, Teardrop, Ping of Death, Smurf, Fraggle, ACK/SYN/ICMP/TCP/UDP Flood,
    ICMP Redirect, IP Source Routing, WinNuke -- see attack_detect.hpp's own file header for the
    full sourcing/scoping writeup, including why "TCP Flood" is a documented catch-all rather than
    a sourced term, and "normal" is not a detector at all).

    Every single-packet/fragment-pair structural signature gets one positive packet and, where the
    false-positive risk is real enough to be worth demonstrating, one negative control proving
    ordinary traffic doesn't trip it. The five flood counters are exercised with --flood-threshold
    5 at the CTest command level (see CMakeLists.txt) rather than baking 100+ packets (the real
    default) into this fixture -- keeps the file small while still exercising the real counting/
    one-shot-note logic, and doubles as coverage for the --flood-threshold override itself.
    Distinct destination addresses are used per flood category so their counters can't interfere
    with each other or with the structural-signature packets above."""
    packets = []

    def add(pkt):
        packets.append(pkt)

    # 1) LAND: TCP SYN with identical source and destination address:port.
    land_ip = "192.168.1.77"
    tcp = tcp_header_ex(4444, 4444, 100, 0, TCP_SYN, 0)
    ip = ipv4_header_ex(land_ip, land_ip, 6, len(tcp), 0xA001) + tcp
    add(eth_header(PLC_MAC, PLC_MAC, 0x0800) + ip)

    # 2) NEGATIVE CONTROL: an ordinary TCP SYN between two distinct hosts/ports -- must NOT be
    #    flagged as LAND.
    tcp = tcp_header_ex(51500, 8080, 100, 0, TCP_SYN, 0)
    ip = ipv4_header_ex(HMI_IP, "192.168.1.200", 6, len(tcp), 0xA002) + tcp
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 3) & 4) Teardrop: two IP fragments of the same datagram (same source/destination/protocol/
    #    identification -- protocol 253, IANA "Use for experimentation and testing", chosen so
    #    decoder.cpp's own dispatch cascade doesn't attempt any further transport-layer parse of
    #    either fragment's raw bytes, keeping this pair's own notes free of unrelated noise) whose
    #    byte ranges overlap: fragment 1 covers bytes [0, 16), fragment 2 (the last fragment, MF
    #    clear) covers bytes [8, 24) -- bytes 8-15 are claimed by both.
    frag_ident = 0xA010
    frag1_payload = bytes(range(16))
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 253, len(frag1_payload), frag_ident,
                         flags_and_offset=0x2000) + frag1_payload  # MF=1, offset=0
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)
    frag2_payload = bytes(range(16, 32))
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 253, len(frag2_payload), frag_ident,
                         flags_and_offset=0x0001) + frag2_payload  # MF=0, offset=1 (byte 8)
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 5) & 6) NEGATIVE CONTROL: a legitimate, NON-overlapping fragment pair of a different
    #    datagram (same protocol/addresses, different identification) -- fragment 1 covers
    #    [0, 16), fragment 2 (last) covers [16, 32) -- back-to-back, no overlap. Must NOT be
    #    flagged as Teardrop.
    ok_ident = 0xA011
    ok_frag1 = bytes(range(16))
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 253, len(ok_frag1), ok_ident, flags_and_offset=0x2000) + ok_frag1
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)
    ok_frag2 = bytes(range(16, 32))
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 253, len(ok_frag2), ok_ident, flags_and_offset=0x0002) + ok_frag2  # offset=2 (byte 16)
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 7) Ping of Death: a single ICMP fragment (MF clear, i.e. the LAST fragment of its datagram)
    #    whose own declared end position (fragment_offset*8 + payload length) exceeds the
    #    65535-byte maximum IP datagram size. fragment_offset=8189 (*8 = 65512 bytes) + a 30-byte
    #    Echo Request body (type/code/checksum/id/seq + 22 bytes of data) = end 65542.
    pod_body = struct.pack("!HH", 0xF001, 1) + bytes(22)
    pod_icmp = icmp_message(8, 0, pod_body)
    ip = ipv4_header_ex(HMI_IP, PLC_IP, ICMP_IP_PROTOCOL, len(pod_icmp), 0xA020,
                         flags_and_offset=8189) + pod_icmp  # MF=0, offset=8189
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 8) Smurf: ICMP Echo Request to a /24 directed-broadcast-looking address (last octet 255).
    add(ip_eth_frame(icmp_message(8, 0, struct.pack("!HH", 0xF002, 1) + bytes(8)),
                      ICMP_IP_PROTOCOL, HMI_IP, "192.168.1.255", HMI_MAC, PLC_MAC))

    # 9) Smurf: ICMP Echo Request to the limited broadcast address (255.255.255.255) -- the
    #    unambiguous case, distinct code path from #8's heuristic.
    add(ip_eth_frame(icmp_message(8, 0, struct.pack("!HH", 0xF003, 1) + bytes(8)),
                      ICMP_IP_PROTOCOL, HMI_IP, "255.255.255.255", HMI_MAC, PLC_MAC))

    # 10) NEGATIVE CONTROL: an ordinary ICMP Echo Request to a plain unicast address -- must NOT
    #     be flagged as Smurf.
    add(ip_eth_frame(icmp_message(8, 0, struct.pack("!HH", 0xF004, 1) + bytes(8)),
                      ICMP_IP_PROTOCOL, HMI_IP, "192.168.1.201", HMI_MAC, PLC_MAC))

    # 11) Fraggle: UDP Echo (port 7) request to a broadcast-looking destination.
    add(udp_ip_eth_frame(b"\x00" * 4, 51600, 7, HMI_IP, "192.168.1.255", HMI_MAC, PLC_MAC, ident=0xA030))

    # 12) NEGATIVE CONTROL: UDP to port 7 (Echo), but an ordinary unicast destination -- must NOT
    #     be flagged as Fraggle.
    add(udp_ip_eth_frame(b"\x00" * 4, 51601, 7, HMI_IP, "192.168.1.202", HMI_MAC, PLC_MAC, ident=0xA031))

    # 13) ICMP Redirect (type 5, code 1 -- Redirect Datagram for the Host).
    embedded = icmp_embedded_datagram(HMI_IP, "192.168.1.203", 6, src_port=51700, dst_port=502)
    add(ip_eth_frame(icmp_message(5, 1, ip_bytes4("192.168.1.1") + embedded),
                      ICMP_IP_PROTOCOL, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 14) IP Source Routing: a Loose Source and Record Route (LSRR, kind 0x83) option carrying one
    #     hop address, padded with one No-Operation (0x01) byte to reach the required 4-byte
    #     option-area multiple (2 option words -> ihl_words=7). Payload: an ordinary UDP datagram,
    #     riding on top to show this is checked independently of the transport protocol.
    lsrr = bytes([0x83, 0x07, 0x04]) + ip_bytes4("10.0.0.1") + bytes([0x01])
    udp = udp_header(51700, 502, b"\x00\x01\x02\x03")
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 17, len(udp), 0xA040, options=lsrr) + udp
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 15) NEGATIVE CONTROL: an ordinary IP packet with no options at all -- must NOT be flagged as
    #     IP Source Routing.
    udp = udp_header(51701, 502, b"\x00\x01\x02\x03")
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 17, len(udp), 0xA041) + udp
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 16) WinNuke: Out-of-Band TCP data (URG set, non-zero urgent pointer, non-empty payload) on
    #     NetBIOS Session Service port 139.
    oob_data = b"\x00\x00"
    tcp = tcp_header_ex(51800, 139, 500, 0, 0x18 | 0x20, len(oob_data), urgent_pointer=1) + oob_data  # PSH,ACK,URG
    ip = ipv4_header_ex(HMI_IP, PLC_IP, 6, len(tcp), 0xA050) + tcp
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 17) NEGATIVE CONTROL: URG set with a non-zero urgent pointer, but on an ordinary port (not
    #     139) -- must NOT be flagged as WinNuke.
    tcp = tcp_header_ex(51801, 8081, 500, 0, 0x18 | 0x20, len(oob_data), urgent_pointer=1) + oob_data
    ip = ipv4_header_ex(HMI_IP, "192.168.1.204", 6, len(tcp), 0xA051) + tcp
    add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 18-23) SYN flood: 6 bare SYN packets (from 6 different spoofed-looking source ports, the
    #    realistic shape) to one destination -- run under --flood-threshold 5 in CTest, so the 5th
    #    one crosses it and fires a note (once, not on the 6th too).
    syn_flood_dst = "192.168.3.10"
    for i in range(6):
        tcp = tcp_header_ex(50000 + i, 502, 100, 0, TCP_SYN, 0)
        ip = ipv4_header_ex(HMI_IP, syn_flood_dst, 6, len(tcp), 0xA100 + i) + tcp
        add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 24-29) ACK flood: 6 bare (no-payload) ACK packets to a distinct destination.
    ack_flood_dst = "192.168.3.11"
    for i in range(6):
        tcp = tcp_header_ex(50100 + i, 502, 200, 300, TCP_ACK, 0)
        ip = ipv4_header_ex(HMI_IP, ack_flood_dst, 6, len(tcp), 0xA110 + i) + tcp
        add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 30-35) TCP flood (the broad catch-all): 6 ordinary PSH,ACK data packets (i.e. NOT bare SYN or
    #    bare ACK -- confirms the catch-all counts every TCP packet, not just the flag-specific
    #    subsets) to a distinct destination.
    tcp_flood_dst = "192.168.3.12"
    for i in range(6):
        body = b"\x01\x02"
        tcp = tcp_header_ex(50200 + i, 502, 400, 500, TCP_PSH | TCP_ACK, len(body)) + body
        ip = ipv4_header_ex(HMI_IP, tcp_flood_dst, 6, len(tcp), 0xA120 + i) + tcp
        add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 36-41) ICMP flood: 6 Echo Request packets to a distinct, non-broadcast destination.
    icmp_flood_dst = "192.168.3.13"
    for i in range(6):
        add(ip_eth_frame(icmp_message(8, 0, struct.pack("!HH", 0xF100 + i, 1) + bytes(8)),
                          ICMP_IP_PROTOCOL, HMI_IP, icmp_flood_dst, HMI_MAC, PLC_MAC))

    # 42-47) UDP flood: 6 datagrams (not port 7/19, so Fraggle doesn't also fire) to a distinct
    #    destination.
    udp_flood_dst = "192.168.3.14"
    for i in range(6):
        add(udp_ip_eth_frame(b"\x00\x00", 50300 + i, 9999, HMI_IP, udp_flood_dst, HMI_MAC, PLC_MAC,
                              ident=0xA140 + i))

    # 48-53) NEGATIVE CONTROL: 6 bare SYN packets to a BROADCAST-looking destination -- must NOT be
    #    flagged as a SYN flood even under --flood-threshold 5 (a flood, by definition, targets one
    #    specific host; broadcast reuse is the same "not a flood" shape sample_bacnet.pcap's own
    #    routine broadcast traffic has -- see attack_detect.hpp's flood_counters_for comment).
    broadcast_flood_dst = "192.168.3.255"
    for i in range(6):
        tcp = tcp_header_ex(50400 + i, 502, 100, 0, TCP_SYN, 0)
        ip = ipv4_header_ex(HMI_IP, broadcast_flood_dst, 6, len(tcp), 0xA150 + i) + tcp
        add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 54-56) NEGATIVE CONTROL: only 3 bare SYN packets (fewer than --flood-threshold 5) to a fresh
    #    destination -- must NOT be flagged as a SYN flood.
    below_threshold_dst = "192.168.3.15"
    for i in range(3):
        tcp = tcp_header_ex(50500 + i, 502, 100, 0, TCP_SYN, 0)
        ip = ipv4_header_ex(HMI_IP, below_threshold_dst, 6, len(tcp), 0xA160 + i) + tcp
        add(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_240_000 + i, i * 1000)
    (TESTS_DIR / "sample_attack_detect.pcap").write_bytes(data)


# --- CODESYS V3 (codesys.hpp) -----------------------------------------------------------------
# See codesys.hpp's own file header comment for the full wire format and sourcing. Jurgen asked
# "can you add CODESYS?" -- scoped with him beforehand via two AskUserQuestion prompts (V3 only,
# not legacy V2; structural-only beyond CmpDevice's own Login/AUTH exchange).

CODESYS_DATAGRAM_MAGIC = 0xC5


def codesys_varint(v: int) -> bytes:
    """The 7-bit-per-byte, LSB-first, continuation-bit(0x80) varint both a CODESYS tag ID and its
    length use -- see codesys.hpp's own PAYLOAD DECODE SCOPE paragraph."""
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            break
    return bytes(out)


def codesys_tag(tag_id: int, value: bytes) -> bytes:
    return codesys_varint(tag_id) + codesys_varint(len(value)) + value


def codesys_addr6(ip: str, port: int) -> bytes:
    """A 6-byte Datagram-layer address: Port(2, big-endian) + IPv4(4, network-order) -- the one
    shape this decoder actually decodes (see codesys.hpp's own DATAGRAM/ROUTER LAYER paragraph)."""
    return struct.pack("!H", port) + bytes(int(o) for o in ip.split("."))


def codesys_addr8(ip: str, port: int) -> bytes:
    """An 8-byte Datagram-layer address: the same 6 bytes plus 2 more this decoder does not
    interpret (shown as raw hex only) -- padded with an arbitrary, non-zero pair so the fixture
    doesn't accidentally look like a truncated 6-byte address."""
    return codesys_addr6(ip, port) + b"\xAB\xCD"


def codesys_l3(service_id: int, sender: bytes, receiver: bytes, hops: int = 0,
               packet_params: int = 0, message_id: int = 0, address_lengths: int = 0x43) -> bytes:
    return struct.pack("<BBBBBB", CODESYS_DATAGRAM_MAGIC, hops, packet_params, service_id,
                        message_id, address_lengths) + sender + receiver


def codesys_channel(command_id: int, flags: int, channel_id: int, blk_num: int, ack_num: int,
                     payload: bytes = b"", checksum: int = 0) -> bytes:
    return struct.pack("<BBHIIII", command_id, flags, channel_id, blk_num, ack_num,
                        len(payload), checksum) + payload


def codesys_services(protocol_id: int, component_id: int, command_id: int, session_id: int,
                      payload: bytes = b"", header_size: int = 20, additional_data: int = 0) -> bytes:
    return struct.pack("<HHHHIII", protocol_id, header_size, component_id, command_id, session_id,
                        len(payload), additional_data) + payload


def codesys_block_driver(body: bytes) -> bytes:
    return struct.pack("<II", 0x000117E8, 8 + len(body)) + body


def build_codesys_sample():
    """CODESYS V3 (3S-Smart/CODESYS GmbH's PLC runtime protocol) -- TCP ports 11740/1217 (Block
    Driver-framed), UDP ports 1740-1743 (no Block Driver framing). See codesys.hpp's own file
    header comment for the full four-layer wire format, sourcing (a public Wireshark dissector
    plus Kaspersky ICS-CERT's own reverse-engineering research), and the two AskUserQuestion
    scoping decisions (V3 only; structural-only beyond CmpDevice's own Login/AUTH exchange).

    TCP session (HMI_IP:53000 <-> PLC_IP:11740), 8 messages:
      1-2) OPEN_CHANNEL request/response -- channel-management, no Services layer at all.
      3) Login/AUTH request (BLK, CmpDevice::Login) carrying tag 0x81 -> {0x10 username="engineer",
         0x11 password (never rendered)}.
      4) Login/AUTH response carrying top-level tag 0x21 (new session ID).
      5) CmpApp (component known) with an unrecognized command ID -- structural-only: component
         named, command shown as a raw number, payload byte count only, no tag-walk attempted.
      6) A BLK frame whose channel payload does NOT structurally validate as a fresh Services
         header (simulates a multi-block transfer's own continuation block) -- must fall back to
         the "not decoded as a fresh Services message" note, not garbage field values.
      7) The same OPEN_CHANNEL request shape again, but on a non-standard TCP port (22222, not
         11740/1217) -- exercises the "not a configured/standard CODESYS port" note.
    Then, on a fresh TCP session on port 11740 again: 8) a NEGATIVE CONTROL -- an ordinary TCP
    payload that does NOT start with the Block Driver magic at all -- must fall through cleanly to
    generic [tcp], not be misclaimed as codesys.

    UDP (no Block Driver framing), 4 datagrams:
      9) Address Service (ServiceId=1) -- Datagram/Router layer only, no Channel layer at all.
      10) Channel Service GET_INFO (command ID 0xC2) on the standard port 1741.
      11) The same GET_INFO shape again, but on a non-standard UDP port (7777, not 1740-1743).
      12) NEGATIVE CONTROL -- a UDP/1740 payload whose first byte is NOT the 0xC5 Datagram magic --
          must fall through cleanly to generic [udp]."""
    packets = []

    def add_tcp(payload: bytes, sport: int, dport: int, seq: int, ack: int, from_hmi: bool,
                ident: int):
        tcp = tcp_header(sport, dport, seq, ack, TCP_PSH | TCP_ACK, len(payload)) + payload
        src_ip, dst_ip = (HMI_IP, PLC_IP) if from_hmi else (PLC_IP, HMI_IP)
        src_mac, dst_mac = (HMI_MAC, PLC_MAC) if from_hmi else (PLC_MAC, HMI_MAC)
        ip = ipv4_header(src_ip, dst_ip, 6, len(tcp), ident) + tcp
        packets.append(eth_header(dst_mac, src_mac, 0x0800) + ip)

    def add_udp(payload: bytes, sport: int, dport: int, from_hmi: bool = True):
        if from_hmi:
            packets.append(udp_ip_eth_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, sport, dport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    seq_c, seq_s = 1000, 9000
    ident = 0x6000

    def client(body: bytes, sport: int = 53000, dport: int = 11740):
        nonlocal seq_c, ident
        frame = codesys_block_driver(body)
        add_tcp(frame, sport, dport, seq_c, seq_s, True, ident)
        seq_c += len(frame)
        ident += 1

    def server(body: bytes, sport: int = 11740, dport: int = 53000):
        nonlocal seq_s, ident
        frame = codesys_block_driver(body)
        add_tcp(frame, sport, dport, seq_s, seq_c, False, ident)
        seq_s += len(frame)
        ident += 1

    # 1) & 2) OPEN_CHANNEL request/response -- no Services layer.
    client(codesys_l3(0x40, codesys_addr6(HMI_IP, 53000), codesys_addr8(PLC_IP, 11740)) +
           codesys_channel(0xC3, 0x81, channel_id=1, blk_num=0, ack_num=0))
    server(codesys_l3(0x40, codesys_addr6(PLC_IP, 11740), codesys_addr8(HMI_IP, 53000)) +
           codesys_channel(0x83, 0x01, channel_id=1, blk_num=0, ack_num=1))

    # 3) Login/AUTH request -- username decoded, password never rendered.
    auth_req_tags = codesys_tag(0x10, b"engineer") + codesys_tag(0x11, b"s3cr3t-pw!")
    auth_req_payload = codesys_tag(0x81, auth_req_tags)
    auth_req_services = codesys_services(0xCD55, component_id=1, command_id=2, session_id=0,
                                          payload=auth_req_payload)
    client(codesys_l3(0x40, codesys_addr6(HMI_IP, 53000), codesys_addr8(PLC_IP, 11740)) +
           codesys_channel(0x01, 0x81, channel_id=1, blk_num=1, ack_num=1,
                            payload=auth_req_services))

    # 4) Login/AUTH response -- new session ID (tag 0x21).
    auth_resp_payload = codesys_tag(0x21, struct.pack("<I", 0x4A3B2C1D))
    auth_resp_services = codesys_services(0xCD55, component_id=1, command_id=2, session_id=0,
                                           payload=auth_resp_payload)
    server(codesys_l3(0x40, codesys_addr6(PLC_IP, 11740), codesys_addr8(HMI_IP, 53000)) +
           codesys_channel(0x01, 0x01, channel_id=1, blk_num=2, ack_num=2,
                            payload=auth_resp_services))

    # 5) CmpApp, unrecognized command ID -- structural-only.
    app_services = codesys_services(0xCD55, component_id=2, command_id=5, session_id=0x4A3B2C1D,
                                     payload=b"\x01\x02\x03\x04")
    client(codesys_l3(0x40, codesys_addr6(HMI_IP, 53000), codesys_addr8(PLC_IP, 11740)) +
           codesys_channel(0x01, 0x81, channel_id=1, blk_num=3, ack_num=2, payload=app_services))

    # 6) BLK frame whose channel payload does not validate as a fresh Services header (simulated
    #    multi-block continuation).
    server(codesys_l3(0x40, codesys_addr6(PLC_IP, 11740), codesys_addr8(HMI_IP, 53000)) +
           codesys_channel(0x01, 0x01, channel_id=1, blk_num=4, ack_num=3,
                            payload=b"\xDE\xAD\xBE\xEF" * 6))

    # 7) OPEN_CHANNEL request again, on a non-standard TCP port (22222).
    client(codesys_l3(0x40, codesys_addr6(HMI_IP, 53001), codesys_addr8(PLC_IP, 22222)) +
           codesys_channel(0xC3, 0x81, channel_id=2, blk_num=0, ack_num=0),
           sport=53001, dport=22222)

    # 8) NEGATIVE CONTROL: an ordinary TCP payload with no Block Driver magic at all.
    add_tcp(b"NOT-CODESYS-TRAFFIC-AT-ALL", 53002, 11740, 2000, 8000, True, ident)
    ident += 1

    # 9) UDP Address Service -- Datagram/Router layer only.
    add_udp(codesys_l3(1, codesys_addr6(HMI_IP, 0), codesys_addr8(PLC_IP, 0)), 1740, 1740)

    # 10) UDP Channel Service GET_INFO, standard port 1741.
    add_udp(codesys_l3(0x40, codesys_addr6(HMI_IP, 1741), codesys_addr8(PLC_IP, 1741)) +
            codesys_channel(0xC2, 0x80, channel_id=7, blk_num=0, ack_num=0), 1741, 1741)

    # 11) The same GET_INFO shape, on a non-standard UDP port (7777).
    add_udp(codesys_l3(0x40, codesys_addr6(HMI_IP, 7777), codesys_addr8(PLC_IP, 7777)) +
            codesys_channel(0xC2, 0x80, channel_id=8, blk_num=0, ack_num=0), 7777, 7777)

    # 12) NEGATIVE CONTROL: UDP/1740 payload not starting with the 0xC5 Datagram magic. Uses an
    #     ASCII payload (matching packet 8's own TCP negative control style) rather than arbitrary
    #     binary bytes, specifically to avoid an accidental structural collision with another
    #     port-independent UDP decoder (e.g. HART-IP's own 8-byte header gate) -- this negative
    #     control's whole point is a clean fall-through to generic [udp], not a coincidental
    #     mis-claim by some *other* protocol's decoder.
    add_udp(b"NOT-CODESYS-UDP-TRAFFIC-AT-ALL!", 1740, 1740)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_250_000 + i, i * 1000)
    (TESTS_DIR / "sample_codesys.pcap").write_bytes(data)


def coap_option(delta: int, value: bytes) -> bytes:
    """One RFC 7252 Section 3.1 Option Delta/Length encoding, correctly extended (nibble 13/14)
    for a delta or length past 12 -- see coap.hpp's own WIRE FORMAT comment for the +13/+269
    scheme this mirrors exactly."""
    def nibble_and_ext(v: int) -> bytes:
        if v <= 12:
            return bytes([v]), b""
        if v <= 12 + 255:
            return bytes([13]), bytes([v - 13])
        return bytes([14]), struct.pack(">H", v - 269)

    length = len(value)
    d_nib, d_ext = nibble_and_ext(delta)
    l_nib, l_ext = nibble_and_ext(length)
    return bytes([(d_nib[0] << 4) | l_nib[0]]) + d_ext + l_ext + value


def coap_message(mtype: int, code: int, msg_id: int, token: bytes,
                  options: list, payload: bytes = b"") -> bytes:
    """Builds one well-formed CoAP message (RFC 7252 Section 3). `options` is a list of
    (option_number, value_bytes) pairs in strictly increasing option_number order -- the delta
    between consecutive entries (and from 0 for the first) is computed here."""
    b0 = (1 << 6) | ((mtype & 0x3) << 4) | (len(token) & 0xF)  # Ver is always 1.
    out = bytes([b0, code]) + struct.pack(">H", msg_id) + token
    prev = 0
    for number, value in options:
        out += coap_option(number - prev, value)
        prev = number
    if payload:
        out += b"\xFF" + payload
    return out


def coap_code(cls: int, detail: int) -> int:
    return (cls << 5) | detail


def build_coap_sample():
    """CoAP (Constrained Application Protocol, RFC 7252) -- UDP port 5683. See coap.hpp's own
    file header for the full sourcing/scoping/wire-format writeup.

    1) CON GET /sensors/temperature (Uri-Path as two options, one per path segment).
    2) ACK 2.05 Content, matching Message ID, Content-Format=application/json, a JSON payload.
    3) CON GET /.well-known/core -- CoRE Resource Discovery (RFC 6690), triggers its own note.
    4) ACK 2.05 Content, Content-Format=application/link-format, a link-format payload.
    5) CON GET /sensors/temperature with Observe=0 (register) and Accept=application/json.
    6) NON 2.05 Content, Observe=5 (a later notification, RFC 7641), Content-Format=application/
       json -- a fresh Message ID (Non-confirmable notifications are not ACKs of packet 5's own
       CON, they are their own independent messages on the wire).
    7) MALFORMED: a Payload Marker (0xFF) as the very last byte, with no payload following at all
       -- a message format error per RFC 7252 Section 3.1, not an empty payload.
    8) MALFORMED: an option whose declared length exceeds the bytes actually remaining in the
       message.
    9) The same GET as packet 1, but on a non-standard UDP port (6683, not 5683).
    10) NEGATIVE CONTROL: a UDP/5683 payload whose Version bits are not 1 -- must fall through
        cleanly to generic [udp]."""
    packets = []

    def send(payload: bytes, sport: int = 5683, dport: int = 5683, from_hmi: bool = True):
        if from_hmi:
            packets.append(udp_ip_eth_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, sport, dport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) CON GET /sensors/temperature.
    send(coap_message(0, coap_code(0, 1), 0x1001, b"\xAB\xCD",
                       [(11, b"sensors"), (11, b"temperature")]),
         sport=52000, dport=5683)

    # 2) ACK 2.05 Content, Content-Format=application/json (50), matching Message ID.
    send(coap_message(2, coap_code(2, 5), 0x1001, b"\xAB\xCD",
                       [(12, bytes([50]))], payload=b'{"c":21.5}'),
         sport=5683, dport=52000, from_hmi=False)

    # 3) CON GET /.well-known/core -- CoRE Resource Discovery.
    send(coap_message(0, coap_code(0, 1), 0x1002, b"\xAA",
                       [(11, b".well-known"), (11, b"core")]),
         sport=52000, dport=5683)

    # 4) ACK 2.05 Content, Content-Format=application/link-format (40).
    send(coap_message(2, coap_code(2, 5), 0x1002, b"\xAA",
                       [(12, bytes([40]))],
                       payload=b'</sensors/temperature>;rt="temperature-c";if="sensor"'),
         sport=5683, dport=52000, from_hmi=False)

    # 5) CON GET /sensors/temperature with Observe=0 (register) and Accept=application/json (17).
    send(coap_message(0, coap_code(0, 1), 0x1003, b"\xBE\xEF",
                       [(6, b"\x00"), (11, b"sensors"), (11, b"temperature"), (17, bytes([50]))]),
         sport=52000, dport=5683)

    # 6) NON 2.05 Content, Observe=5 (a later notification), Content-Format=application/json.
    send(coap_message(1, coap_code(2, 5), 0x1004, b"\xBE\xEF",
                       [(6, b"\x05"), (12, bytes([50]))], payload=b'{"c":21.6}'),
         sport=5683, dport=52000, from_hmi=False)

    # 7) MALFORMED: Payload Marker with nothing following.
    b0 = (1 << 6) | (0 << 4) | 0  # Ver=1, CON, TKL=0.
    send(bytes([b0, coap_code(0, 1)]) + struct.pack(">H", 0x1005) + b"\xFF",
         sport=52000, dport=5683)

    # 8) MALFORMED: an option's declared length (10) exceeds the 2 bytes actually remaining.
    b0 = (1 << 6) | (0 << 4) | 0
    # Option Delta=11 (Uri-Path, small enough for the low nibble), Length=10 -- but only 2 bytes
    # of value actually follow.
    malformed_option = bytes([(11 << 4) | 10])
    send(bytes([b0, coap_code(0, 1)]) + struct.pack(">H", 0x1006) + malformed_option + b"ab",
         sport=52000, dport=5683)

    # 9) Same GET as packet 1, on a non-standard UDP port (6683).
    send(coap_message(0, coap_code(0, 1), 0x1007, b"\x01",
                       [(11, b"sensors"), (11, b"temperature")]),
         sport=52001, dport=6683)

    # 10) NEGATIVE CONTROL: Version bits != 1.
    send(b"\x00\x01\x10\x07", sport=52002, dport=5683)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_260_000 + i, i * 1000)
    (TESTS_DIR / "sample_coap.pcap").write_bytes(data)


# --- RMCP / ASF / IPMI (BMC out-of-band management -- DMTF/Intel, UDP port 623) --------------
#
# See rmcp.hpp's own file header for the full sourcing/scoping/wire-format writeup. All three ride
# RMCP's own shared 4-byte framing (Version=0x06, Reserved=0xFF, Sequence, Type/Class).

RMCP_PORT = 623
RMCP_CLASS_ASF = 0x06
RMCP_CLASS_IPMI = 0x07


def rmcp_header(seq: int, rmcp_class: int, ack: bool = False) -> bytes:
    b3 = (0x80 if ack else 0x00) | (rmcp_class & 0x1F)
    return bytes([0x06, 0xFF, seq & 0xFF, b3])


def asf_message(msg_type: int, tag: int, body: bytes = b"") -> bytes:
    return struct.pack(">IBBBB", 4542, msg_type, tag, 0, len(body)) + body


def asf_presence_pong_body(oem_iana: int = 4542, oem_defined: bytes = b"\x00\x00\x00\x00",
                            asf_version: int = 1, security_extensions: bool = False) -> bytes:
    entities = 0x80 | (asf_version & 0x0F)
    interactions = 0x80 if security_extensions else 0x00
    return struct.pack(">I", oem_iana) + oem_defined + bytes([entities, interactions]) + b"\x00" * 6


def ipmi_msg(rs_addr: int, netfn: int, rs_lun: int, rq_addr: int, rq_seq: int, rq_lun: int,
             cmd: int, data: bytes = b"") -> bytes:
    """The classic IPMI request/response message -- see rmcp.hpp's own WIRE FORMAT section.
    `data` already includes a leading Completion Code byte for a response (netfn odd)."""
    b1 = ((netfn & 0x3F) << 2) | (rs_lun & 0x3)
    cks1 = (-(rs_addr + b1)) & 0xFF
    b4 = ((rq_seq & 0x3F) << 2) | (rq_lun & 0x3)
    rest = bytes([rq_addr, b4, cmd]) + data
    cks2 = (-sum(rest)) & 0xFF
    return bytes([rs_addr, b1, cks1]) + rest + bytes([cks2])


def ipmi15_session(auth_type: int, seq: int, session_id: int, msg: bytes,
                    auth_code: bytes = None) -> bytes:
    out = bytes([auth_type]) + struct.pack("<I", seq) + struct.pack("<I", session_id)
    if auth_type != 0x00:
        code = auth_code if auth_code is not None else b"\x00" * 16
        assert len(code) == 16
        out += code
    out += bytes([len(msg)]) + msg
    return out


def ipmi20_session(payload_type: int, session_id: int, seq: int, msg: bytes,
                    encrypted: bool = False, authenticated: bool = False) -> bytes:
    pt_byte = (0x80 if encrypted else 0) | (0x40 if authenticated else 0) | (payload_type & 0x3F)
    return (bytes([0x06, pt_byte]) + struct.pack("<I", session_id) + struct.pack("<I", seq) +
            struct.pack("<H", len(msg)) + msg)


def open_session_request(tag: int, priv: int, console_session_id: int, auth_alg: int,
                          integrity_alg: int, conf_alg: int) -> bytes:
    body = bytes([tag, priv & 0x0F, 0, 0]) + struct.pack("<I", console_session_id)
    body += bytes([0x00, 0, 0, 0x08, auth_alg, 0, 0, 0])
    body += bytes([0x01, 0, 0, 0x08, integrity_alg, 0, 0, 0])
    body += bytes([0x02, 0, 0, 0x08, conf_alg, 0, 0, 0])
    return body


def open_session_response(tag: int, status: int, max_priv: int, console_session_id: int,
                           managed_session_id: int, auth_alg: int = 0, integrity_alg: int = 0,
                           conf_alg: int = 0) -> bytes:
    body = (bytes([tag, status, max_priv & 0x0F, 0]) + struct.pack("<I", console_session_id) +
            struct.pack("<I", managed_session_id))
    if status == 0:
        body += bytes([0x00, 0, 0, 0x08, auth_alg, 0, 0, 0])
        body += bytes([0x01, 0, 0, 0x08, integrity_alg, 0, 0, 0])
        body += bytes([0x02, 0, 0, 0x08, conf_alg, 0, 0, 0])
    return body


def rakp1(tag: int, managed_session_id: int, console_random: bytes, priv: int, name_only: bool,
          user_name: bytes) -> bytes:
    priv_byte = (priv & 0x0F) | (0x10 if name_only else 0x00)
    return (bytes([tag, 0, 0, 0]) + struct.pack("<I", managed_session_id) + console_random +
            bytes([priv_byte, 0, 0, len(user_name)]) + user_name)


def rakp2(tag: int, status: int, console_session_id: int, managed_random: bytes,
          managed_guid: bytes, auth_code: bytes = b"") -> bytes:
    return (bytes([tag, status, 0, 0]) + struct.pack("<I", console_session_id) + managed_random +
            managed_guid + auth_code)


def rakp3(tag: int, status: int, managed_session_id: int, auth_code: bytes = b"") -> bytes:
    return bytes([tag, status, 0, 0]) + struct.pack("<I", managed_session_id) + auth_code


def rakp4(tag: int, status: int, console_session_id: int, icv: bytes = b"") -> bytes:
    return bytes([tag, status, 0, 0]) + struct.pack("<I", console_session_id) + icv


def build_ipmi_sample():
    """RMCP (rmcp.hpp) / ASF / IPMI 1.5 / IPMI 2.0 RMCP+ (RAKP), all sharing UDP port 623.

    1) ASF Presence Ping (console -> BMC).
    2) ASF Presence Pong (BMC -> console), full field decode (OEM IANA, ASF version, security
       extensions bit).
    3) IPMI 1.5 sessionless Get Channel Authentication Capabilities REQUEST -- the standard first
       step of an IPMI LAN session.
    4) ...its RESPONSE (supported auth types, IPMI 2.0 extended capabilities bit).
    5-10) IPMI 2.0/RMCP+ Open Session Request/Response + full RAKP Message 1-4 handshake, a NORMAL
       cipher suite (Authentication=RAKP-HMAC-SHA1, Integrity=HMAC-SHA1-96,
       Confidentiality=AES-CBC-128 -- Cipher Suite 3), on its own UDP session (source port 52100).
    11-13) A SEPARATE handshake (source port 52200) using Cipher Suite 0 (Authentication=
       RAKP-none) -- Open Session Request (proposes it), Open Session Response (ACCEPTS it, the
       actual exploitable condition), and RAKP Message 1 (proving the sticky per-session note
       fires on a later message that carries no algorithm field of its own).
    14) An authenticated IPMI 1.5 session-based message (AuthType=PASSWORD) with a non-empty
       16-byte Auth Code -- proving it is never rendered, only its presence/length noted.
    15) Chassis Control: Power down -- the security-relevant remote-power-control command, riding
       IPMI 2.0's own classic-message payload type on session A (source port 52100).
    16) Get SEL Info request (Storage NetFn) -- exercising the curated NetFn/Command table.
    17) MALFORMED: a frame too short even for the fixed 4-byte RMCP header.
    18) NEGATIVE CONTROL: a UDP/623 packet that is not RMCP-shaped at all.
    19) The same ASF Presence Ping as packet 1, on a non-standard UDP port (6623, not 623).
    20) RMCP ACK (Class=IPMI) -- exercises the generic RmcpUdpDecoder fallback (--protocol
        rmcp)."""
    packets = []

    def send(payload: bytes, sport: int, dport: int = RMCP_PORT, from_hmi: bool = True):
        if from_hmi:
            packets.append(udp_ip_eth_frame(payload, sport, dport, HMI_IP, PLC_IP, HMI_MAC, PLC_MAC))
        else:
            packets.append(udp_ip_eth_frame(payload, sport, dport, PLC_IP, HMI_IP, PLC_MAC, HMI_MAC))

    # 1) ASF Presence Ping.
    send(rmcp_header(1, RMCP_CLASS_ASF) + asf_message(0x80, 0x00), sport=52000)

    # 2) ASF Presence Pong.
    pong_body = asf_presence_pong_body(oem_iana=4542, asf_version=1, security_extensions=True)
    send(rmcp_header(1, RMCP_CLASS_ASF) + asf_message(0x40, 0x00, pong_body),
         sport=RMCP_PORT, dport=52000, from_hmi=False)

    # 3) IPMI 1.5 sessionless Get Channel Authentication Capabilities REQUEST.
    req38 = ipmi_msg(0x20, 0x06, 0, 0x81, 1, 0, 0x38, bytes([0x0E, 0x04]))  # channel=E(current), priv=Administrator
    send(rmcp_header(2, RMCP_CLASS_IPMI) + ipmi15_session(0x00, 0, 0, req38), sport=52100)

    # 4) ...its RESPONSE.
    rsp38 = ipmi_msg(0x81, 0x07, 0, 0x20, 1, 0, 0x38,
                      bytes([0x00, 0x01, 0x17, 0x00, 0x03, 0x00, 0x00, 0x00, 0x00]))
    send(rmcp_header(2, RMCP_CLASS_IPMI) + ipmi15_session(0x00, 0, 0, rsp38),
         sport=RMCP_PORT, dport=52100, from_hmi=False)

    # 5) Open Session Request -- Cipher Suite 3 (SHA1/SHA1-96/AES-CBC-128).
    osr = open_session_request(0x01, 0x04, 0x11111111, 0x01, 0x01, 0x01)
    send(rmcp_header(3, RMCP_CLASS_IPMI) + ipmi20_session(0x10, 0, 0, osr), sport=52100)

    # 6) Open Session Response -- accepts Cipher Suite 3.
    osp = open_session_response(0x01, 0x00, 0x04, 0x11111111, 0x22222222, 0x01, 0x01, 0x01)
    send(rmcp_header(3, RMCP_CLASS_IPMI) + ipmi20_session(0x11, 0, 0, osp),
         sport=RMCP_PORT, dport=52100, from_hmi=False)

    # 7) RAKP Message 1.
    console_random = bytes(range(16))
    r1 = rakp1(0x01, 0x22222222, console_random, 0x04, False, b"admin")
    send(rmcp_header(4, RMCP_CLASS_IPMI) + ipmi20_session(0x12, 0, 0, r1), sport=52100)

    # 8) RAKP Message 2.
    managed_random = bytes(range(16, 32))
    managed_guid = bytes(range(32, 48))
    r2 = rakp2(0x01, 0x00, 0x11111111, managed_random, managed_guid, auth_code=b"\xAA" * 20)
    send(rmcp_header(4, RMCP_CLASS_IPMI) + ipmi20_session(0x13, 0, 0, r2),
         sport=RMCP_PORT, dport=52100, from_hmi=False)

    # 9) RAKP Message 3.
    r3 = rakp3(0x01, 0x00, 0x22222222, auth_code=b"\xBB" * 20)
    send(rmcp_header(5, RMCP_CLASS_IPMI) + ipmi20_session(0x14, 0, 0, r3), sport=52100)

    # 10) RAKP Message 4.
    r4 = rakp4(0x01, 0x00, 0x11111111, icv=b"\xCC" * 12)
    send(rmcp_header(5, RMCP_CLASS_IPMI) + ipmi20_session(0x15, 0, 0, r4),
         sport=RMCP_PORT, dport=52100, from_hmi=False)

    # 11) SEPARATE handshake, own UDP session (source port 52200) -- Open Session Request
    # PROPOSING Cipher Suite 0 (Authentication=RAKP-none).
    osr0 = open_session_request(0x02, 0x04, 0x33333333, 0x00, 0x00, 0x00)
    send(rmcp_header(1, RMCP_CLASS_IPMI) + ipmi20_session(0x10, 0, 0, osr0), sport=52200)

    # 12) Open Session Response ACCEPTING Cipher Suite 0 -- the actual exploitable condition.
    osp0 = open_session_response(0x02, 0x00, 0x04, 0x33333333, 0x44444444, 0x00, 0x00, 0x00)
    send(rmcp_header(1, RMCP_CLASS_IPMI) + ipmi20_session(0x11, 0, 0, osp0),
         sport=RMCP_PORT, dport=52200, from_hmi=False)

    # 13) RAKP Message 1 on the SAME (Cipher-Suite-0) session -- proves the sticky per-session
    # note fires even though this message carries no algorithm field of its own.
    r1_0 = rakp1(0x02, 0x44444444, bytes(range(48, 64)), 0x04, True, b"")
    send(rmcp_header(2, RMCP_CLASS_IPMI) + ipmi20_session(0x12, 0, 0, r1_0), sport=52200)

    # 14) Authenticated IPMI 1.5 session message (AuthType=PASSWORD), non-empty 16-byte Auth
    # Code -- never rendered, only presence/length noted.
    dev_id_req = ipmi_msg(0x20, 0x06, 0, 0x81, 2, 0, 0x01)  # Get Device ID.
    send(rmcp_header(6, RMCP_CLASS_IPMI) +
         ipmi15_session(0x04, 5, 0xAABBCCDD, dev_id_req, auth_code=b"SuperSecretPass1"),
         sport=52300)

    # 15) Chassis Control: Power down -- security-relevant remote-power-control command, on
    # session A's own established session ID (0x22222222), IPMI 2.0 classic-message payload type.
    cc_req = ipmi_msg(0x20, 0x00, 0, 0x81, 3, 0, 0x02, bytes([0x00]))  # Power down.
    send(rmcp_header(6, RMCP_CLASS_IPMI) + ipmi20_session(0x00, 0x22222222, 2, cc_req),
         sport=52100)

    # 16) Get SEL Info request -- curated Storage NetFn/Command table.
    sel_req = ipmi_msg(0x20, 0x0A, 0, 0x81, 4, 0, 0x40)
    send(rmcp_header(7, RMCP_CLASS_IPMI) + ipmi15_session(0x00, 0, 0, sel_req), sport=52400)

    # 17) MALFORMED: too short even for the fixed 4-byte RMCP header.
    send(b"\x06\xff\x00", sport=52500)

    # 18) NEGATIVE CONTROL: UDP/623, not RMCP-shaped at all (Version/Reserved don't match) --
    # bytes[1]/[2] are deliberately outside HART-IP's own small-enumerated-value gate (see
    # hartip.hpp) so this doesn't accidentally collide with that decoder's own opportunistic,
    # port-independent check.
    send(b"\x01\x99\x99\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C", sport=52600)

    # 19) Same ASF Presence Ping as packet 1, on a non-standard UDP port (6623).
    send(rmcp_header(9, RMCP_CLASS_ASF) + asf_message(0x80, 0x00), sport=52700, dport=6623)

    # 20) RMCP ACK (generic RmcpUdpDecoder fallback -- proves --protocol rmcp works).
    send(rmcp_header(9, RMCP_CLASS_IPMI, ack=True), sport=52000)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_270_000 + i, i * 1000)
    (TESTS_DIR / "sample_ipmi.pcap").write_bytes(data)


# --- Zigbee (IEEE 802.15.4 MAC + Zigbee NWK/APS/ZDP) -----------------------------------------
#
# Zigbee needs raw pcap records containing 802.15.4 MAC frames directly -- no Ethernet framing at
# all, the same "wrap a protocol-agnostic link layer in its own pcap linktype, no Ethernet
# involved" shape can_socketcan_frame()/build_devicenet_sample() already established for DeviceNet
# (see that function's own docstring for the direct precedent this follows). Every helper below is
# built directly from the byte-exact wire-format research ieee802154.hpp/zigbee.hpp's own file
# header comments cite -- see those files rather than duplicating the sourcing citations here.
#
# All MAC frames below use IEEE 802.15.4-2006 (Frame Version 1, the realistic value real Zigbee
# radios use), Short/Short addressing with PAN ID Compression set (so only a single Destination PAN
# ID travels on the wire, no Source PAN ID -- the common real-world shape for a single-PAN mesh).
# All NWK frames use ZigBee PRO (NWK Protocol Version 2), the realistic value for essentially all
# modern Zigbee traffic -- see zigbee.hpp's own "2007+-only" scope note for why this fixture never
# exercises the pre-2007 shapes this decoder deliberately doesn't implement.
LINKTYPE_IEEE802_15_4_WITHFCS = 195
LINKTYPE_IEEE802_15_4_TAP = 283

ZB_PAN = 0x1234
ZB_COORD_SHORT = 0x0000
ZB_COORD_EUI = 0x00124B0001020304
ZB_DEV1_SHORT = 0xA1B2
ZB_DEV1_EUI = 0x00124B0001020305
ZB_DEV2_SHORT = 0xC3D4
ZB_DEV2_EUI = 0x00124B0001020306


def ieee802154_fcf(frame_type: int, *, security: bool = False, frame_pending: bool = False,
                    ack_request: bool = False, pan_id_compression: bool = False,
                    seqno_suppression: bool = False, ie_present: bool = False,
                    dst_addr_mode: int = 0, src_addr_mode: int = 0, frame_version: int = 1) -> int:
    """The 2-byte, little-endian IEEE 802.15.4 Frame Control Field -- see ieee802154.hpp's own
    file header comment (section 3.1) for every mask/bit this packs."""
    fcf = frame_type & 0x07
    if security: fcf |= 0x0008
    if frame_pending: fcf |= 0x0010
    if ack_request: fcf |= 0x0020
    if pan_id_compression: fcf |= 0x0040
    if seqno_suppression: fcf |= 0x0100
    if ie_present: fcf |= 0x0200
    fcf |= (dst_addr_mode & 0x3) << 10
    fcf |= (frame_version & 0x3) << 12
    fcf |= (src_addr_mode & 0x3) << 14
    return fcf


def ieee802154_aux_security_header(security_level: int, key_id_mode: int, frame_counter: int, *,
                                    frame_counter_suppressed: bool = False, key_source: bytes = b"",
                                    key_index=None) -> bytes:
    """The IEEE 802.15.4 MAC-layer Auxiliary Security Header -- see ieee802154.hpp section 3.4.
    A DIFFERENT byte layout from zigbee_security_header() below (the NWK/APS one)."""
    control = (security_level & 0x07) | ((key_id_mode & 0x03) << 3)
    if frame_counter_suppressed:
        control |= 0x20
    out = struct.pack("<B", control)
    if not frame_counter_suppressed:
        out += struct.pack("<I", frame_counter)
    out += key_source
    if key_index is not None:
        out += struct.pack("<B", key_index)
    return out


def ieee802154_mac_frame(frame_type: int, *, seqno=0, dst_pan: bytes = None, dst_addr: bytes = None,
                          src_pan: bytes = None, src_addr: bytes = None, aux_security: bytes = b"",
                          payload: bytes = b"", security: bool = False, frame_pending: bool = False,
                          ack_request: bool = False, pan_id_compression: bool = False,
                          seqno_suppression: bool = False, frame_version: int = 1) -> bytes:
    """Builds one raw 802.15.4 MAC frame (no FCS) -- FCF + conditional fields exactly per
    ieee802154.hpp's own addressing-presence rules. `dst_addr`/`src_addr`/`dst_pan`/`src_pan` are
    already-packed little-endian bytes (2 bytes for a short address/PAN, 8 for an extended
    address) or None; presence on the wire is driven purely by what the CALLER passes here, so the
    caller is responsible for matching them to the FCF flags also passed (pan_id_compression,
    dst/src addr mode implied by dst_addr/src_addr's own length) -- this mirrors real hardware,
    which doesn't validate its own frame shape either."""
    def addr_mode_for(addr):
        if addr is None:
            return 0
        return 2 if len(addr) == 2 else 3

    fcf = ieee802154_fcf(frame_type, security=security, frame_pending=frame_pending,
                          ack_request=ack_request, pan_id_compression=pan_id_compression,
                          seqno_suppression=seqno_suppression, dst_addr_mode=addr_mode_for(dst_addr),
                          src_addr_mode=addr_mode_for(src_addr), frame_version=frame_version)
    out = struct.pack("<H", fcf)
    if not seqno_suppression:
        out += struct.pack("<B", seqno)
    if dst_pan is not None:
        out += dst_pan
    if dst_addr is not None:
        out += dst_addr
    if src_pan is not None:
        out += src_pan
    if src_addr is not None:
        out += src_addr
    out += aux_security
    out += payload
    return out


def ieee802154_withfcs_frame(mac_bytes: bytes, fcs: bytes = b"\xDE\xAD") -> bytes:
    """One LINKTYPE_IEEE802_15_4_WITHFCS (195) pcap record: the raw MAC frame plus a trailing
    2-byte FCS -- this decoder never validates it (see ieee802154.hpp section 1), so any 2 bytes
    do; the value here is deliberately NOT a real CRC, to prove that."""
    return mac_bytes + fcs


def ieee802154_tap_frame(mac_bytes: bytes, *, fcs_type: int = 0, fcs: bytes = b"",
                          extra_tlvs: bytes = b"", version: int = 0) -> bytes:
    """One LINKTYPE_IEEE802_15_4_TAP (283) pcap record: the 4-byte fixed header, an FCS_TYPE TLV
    (0x0000) declaring `fcs_type` (0=None, 1=16-bit CRC, 2=32-bit CRC), then the MAC frame followed
    by however many trailing FCS bytes `fcs_type` implies (the caller passes those explicitly via
    `fcs` -- 0 bytes for fcs_type=0, 2 for fcs_type=1, 4 for fcs_type=2) -- see ieee802154.hpp
    section 2."""
    fcs_type_tlv = struct.pack("<HHB", 0x0000, 1, fcs_type) + b"\x00\x00\x00"  # 1-byte value, padded to 4
    tlvs = fcs_type_tlv + extra_tlvs
    length = 4 + len(tlvs)
    header = struct.pack("<BBH", version, 0, length)
    return header + tlvs + mac_bytes + fcs


def zigbee_nwk_fcf(frame_type: int, version: int, *, discover_route: int = 0, multicast: bool = False,
                    security: bool = False, source_route: bool = False, ext_dst: bool = False,
                    ext_src: bool = False, end_device_initiator: bool = False) -> int:
    """The 2-byte, little-endian Zigbee NWK Frame Control Field -- see zigbee.hpp section 4.1."""
    fcf = frame_type & 0x03
    fcf |= (version & 0x0F) << 2
    fcf |= (discover_route & 0x03) << 6
    if multicast: fcf |= 0x0100
    if security: fcf |= 0x0200
    if source_route: fcf |= 0x0400
    if ext_dst: fcf |= 0x0800
    if ext_src: fcf |= 0x1000
    if end_device_initiator: fcf |= 0x2000
    return fcf


def zigbee_security_header(security_level: int, key_id: int, frame_counter: int, *,
                            extended_nonce: bool = False, ext_source=None, key_seqno=None) -> bytes:
    """The Zigbee NWK/APS Auxiliary Security Header (dissect_zbee_secure -- shared by BOTH layers)
    -- see zigbee.hpp section 4.9/5.9. A DIFFERENT byte layout from
    ieee802154_aux_security_header() above (the MAC-layer one)."""
    control = (security_level & 0x07) | ((key_id & 0x03) << 3)
    if extended_nonce:
        control |= 0x20
    out = struct.pack("<B", control) + struct.pack("<I", frame_counter)
    if extended_nonce:
        out += struct.pack("<Q", ext_source if ext_source is not None else 0)
    if key_id == 1:  # Network Key -- the only key_id value that carries a Key Sequence Number
        out += struct.pack("<B", key_seqno if key_seqno is not None else 0)
    return out


def zigbee_nwk_frame(frame_type: int, version: int, dst: int, src: int, radius: int, seqno: int, *,
                      discover_route: int = 0, multicast: bool = False, security: bool = False,
                      source_route: bool = False, ext_dst_addr=None, ext_src_addr=None,
                      mcast_control=None, relay_list=None, security_header: bytes = b"",
                      payload: bytes = b"") -> bytes:
    """Builds one Zigbee NWK frame -- FCF + conditional fields exactly per zigbee.hpp's own field-
    presence rules (section 4.2-4.10)."""
    ext_dst = ext_dst_addr is not None
    ext_src = ext_src_addr is not None
    fcf = zigbee_nwk_fcf(frame_type, version, discover_route=discover_route, multicast=multicast,
                          security=security, source_route=source_route, ext_dst=ext_dst, ext_src=ext_src)
    out = struct.pack("<H", fcf)
    if frame_type == 3:  # Inter-PAN -- just the FCF, everything else is payload
        return out + payload
    out += struct.pack("<HHBB", dst, src, radius, seqno)
    if ext_dst:
        out += struct.pack("<Q", ext_dst_addr)
    if ext_src:
        out += struct.pack("<Q", ext_src_addr)
    if multicast:
        mode, nmr, mmr = mcast_control if mcast_control else (0, 0, 0)
        out += struct.pack("<B", (mode & 0x3) | ((nmr & 0x7) << 2) | ((mmr & 0x7) << 5))
    if source_route:
        relays = relay_list or []
        out += struct.pack("<BB", len(relays), 0)
        for r in relays:
            out += struct.pack("<H", r)
    out += security_header
    out += payload
    return out


def zigbee_aps_fcf(frame_type: int, delivery_mode: int, *, indirect_or_ack_format: bool = False,
                    security: bool = False, ack_req: bool = False, ext_header: bool = False) -> int:
    """The 1-byte Zigbee APS Frame Control Field -- see zigbee.hpp section 5.1."""
    fcf = frame_type & 0x03
    fcf |= (delivery_mode & 0x03) << 2
    if indirect_or_ack_format: fcf |= 0x10
    if security: fcf |= 0x20
    if ack_req: fcf |= 0x40
    if ext_header: fcf |= 0x80
    return fcf


def zigbee_aps_frame(frame_type: int, delivery_mode: int, *, dst_endpoint=None, group_address=None,
                      cluster_id=None, profile_id=None, src_endpoint=None, counter=None,
                      security: bool = False, ack_req: bool = False, security_header: bytes = b"",
                      command_id=None, payload: bytes = b"") -> bytes:
    """Builds one Zigbee APS frame -- FCF + conditional fields exactly per zigbee.hpp's own
    field-presence rules (section 5.2-5.10), assuming ZigBee PRO (2007+) throughout (this fixture
    never exercises pre-2007 field shapes -- see zigbee.hpp's own scope note)."""
    fcf = zigbee_aps_fcf(frame_type, delivery_mode, security=security, ack_req=ack_req)
    out = struct.pack("<B", fcf)
    if frame_type != 1:  # Command frames skip ALL endpoint/cluster/profile fields unconditionally
        if dst_endpoint is not None:
            out += struct.pack("<B", dst_endpoint)
        if delivery_mode == 3:  # Group
            out += struct.pack("<H", group_address if group_address is not None else 0)
        if cluster_id is not None:
            out += struct.pack("<H", cluster_id)
        if profile_id is not None:
            out += struct.pack("<H", profile_id)
        if src_endpoint is not None:
            out += struct.pack("<B", src_endpoint)
    if counter is not None:
        out += struct.pack("<B", counter)
    out += security_header
    if command_id is not None:
        out += struct.pack("<B", command_id)
    out += payload
    return out


def zigbee_data_mac_frame(mac_seqno: int, dst_short: int, src_short: int, nwk_bytes: bytes, *,
                           pan: int = ZB_PAN, ack_request: bool = True,
                           mac_security_header: bytes = None) -> bytes:
    """Wraps `nwk_bytes` (a full Zigbee NWK frame) in a realistic IEEE 802.15.4-2006 MAC Data
    frame: Short/Short addressing, PAN ID Compression set (single Destination PAN ID on the wire),
    the common real-world shape -- see this section's own module-level comment. When
    `mac_security_header` is given, MAC-layer security is enabled too (FCF Security Enabled bit
    set) -- exercised by exactly one fixture packet, to prove ieee802154.hpp/zigbee.hpp's own
    documented "Zigbee never really does this" scope decision degrades correctly."""
    return ieee802154_mac_frame(
        1, seqno=mac_seqno, dst_pan=struct.pack("<H", pan), dst_addr=struct.pack("<H", dst_short),
        src_addr=struct.pack("<H", src_short), ack_request=ack_request, pan_id_compression=True,
        frame_version=1, security=mac_security_header is not None,
        aux_security=mac_security_header if mac_security_header is not None else b"",
        payload=nwk_bytes)


# --- ZDP payload builders -- see zigbee.hpp section 6.2 for every shape below ------------------

def zdp_hdr(seqno: int, body: bytes) -> bytes:
    return struct.pack("<B", seqno) + body


def zdp_nwk_or_ieee_addr_resp(status: int, *, ieee: int = 0, nwk: int = 0, assoc=None,
                               start_index: int = 0) -> bytes:
    out = struct.pack("<B", status)
    if status == 0:
        out += struct.pack("<Q", ieee) + struct.pack("<H", nwk)
        if assoc is not None:
            out += struct.pack("<BB", len(assoc), start_index)
            for a in assoc:
                out += struct.pack("<H", a)
    return out


def zdp_node_desc_resp(status: int, *, nwk: int = 0, logical_type: int = 1,
                        complex_avail: bool = False, user_avail: bool = False, cap: int = 0x8E,
                        manuf: int = 0x1234, maxbuf: int = 80, maxin: int = 128,
                        servermask: int = 0x0000, maxout: int = 128, desccap: int = 0x00) -> bytes:
    out = struct.pack("<B", status)
    if status == 0:
        flags = logical_type & 0x07
        if complex_avail: flags |= 0x08
        if user_avail: flags |= 0x10
        out += struct.pack("<H", nwk) + struct.pack("<H", flags) + struct.pack("<B", cap)
        out += struct.pack("<H", manuf) + struct.pack("<B", maxbuf) + struct.pack("<H", maxin)
        out += struct.pack("<H", servermask) + struct.pack("<H", maxout) + struct.pack("<B", desccap)
    return out


def zdp_simple_desc_resp(status: int, *, nwk: int = 0, ep: int = 1, profile: int = 0x0104,
                          device: int = 0x0100, devver: int = 1, in_clusters=None,
                          out_clusters=None) -> bytes:
    if status != 0:
        return struct.pack("<B", status)
    in_clusters = in_clusters or []
    out_clusters = out_clusters or []
    body = struct.pack("<B", ep) + struct.pack("<H", profile) + struct.pack("<H", device)
    body += struct.pack("<B", devver) + struct.pack("<B", len(in_clusters))
    for c in in_clusters:
        body += struct.pack("<H", c)
    body += struct.pack("<B", len(out_clusters))
    for c in out_clusters:
        body += struct.pack("<H", c)
    return struct.pack("<B", status) + struct.pack("<H", nwk) + struct.pack("<B", len(body)) + body


def zdp_active_ep_resp(status: int, *, nwk: int = 0, eps=None) -> bytes:
    if status != 0:
        return struct.pack("<B", status)
    eps = eps or []
    return struct.pack("<B", status) + struct.pack("<H", nwk) + struct.pack("<B", len(eps)) + bytes(eps)


def zdp_match_desc_resp(status: int, *, nwk: int = 0, matches=None) -> bytes:
    if status != 0:
        return struct.pack("<B", status)
    matches = matches or []
    return (struct.pack("<B", status) + struct.pack("<H", nwk) + struct.pack("<B", len(matches)) +
            bytes(matches))


def zdp_bind_or_unbind_req(src_ieee: int, src_ep: int, cluster: int, dst_mode: int, *,
                            dst_group=None, dst_ieee=None, dst_ep=None) -> bytes:
    out = (struct.pack("<Q", src_ieee) + struct.pack("<B", src_ep) + struct.pack("<H", cluster) +
           struct.pack("<B", dst_mode))
    if dst_mode == 1:  # Group
        out += struct.pack("<H", dst_group)
    elif dst_mode == 3:  # Unicast
        out += struct.pack("<Q", dst_ieee) + struct.pack("<B", dst_ep)
    return out


def zdp_neighbor_table_entry(ext_pan: int, ext_addr: int, nwk_addr: int, device_type: int,
                              rx_on_idle: int, relationship: int, permit_joining: int, depth: int,
                              lqi: int) -> bytes:
    packed1 = (device_type & 0x03) | ((rx_on_idle & 0x03) << 2) | ((relationship & 0x07) << 4)
    return (struct.pack("<Q", ext_pan) + struct.pack("<Q", ext_addr) + struct.pack("<H", nwk_addr) +
            struct.pack("<B", packed1) + struct.pack("<B", permit_joining & 0x03) +
            struct.pack("<B", depth) + struct.pack("<B", lqi))


def zdp_mgmt_lqi_resp(status: int, *, total: int = 0, start_index: int = 0, entries=None) -> bytes:
    if status != 0:
        return struct.pack("<B", status)
    entries = entries or []
    out = struct.pack("<B", status) + struct.pack("<BBB", total, start_index, len(entries))
    for e in entries:
        out += e
    return out


def zdp_routing_table_entry(dest: int, status_byte: int, next_hop: int) -> bytes:
    return struct.pack("<H", dest) + struct.pack("<B", status_byte) + struct.pack("<H", next_hop)


def zdp_mgmt_rtg_resp(status: int, *, total: int = 0, start_index: int = 0, entries=None) -> bytes:
    if status != 0:
        return struct.pack("<B", status)
    entries = entries or []
    out = struct.pack("<B", status) + struct.pack("<BBB", total, start_index, len(entries))
    for e in entries:
        out += e
    return out


def build_zigbee_sample():
    """Zigbee (IEEE 802.15.4 MAC + NWK + APS + ZDP), LINKTYPE_IEEE802_15_4_WITHFCS (195)-framed --
    see ieee802154.hpp/zigbee.hpp for the full sourcing/scoping/wire-format writeup, and this
    section's own module-level comment for the shared MAC/NWK addressing shape every packet below
    uses. Every APS Data/Command frame below carries an APS Counter of 0 for simplicity (this
    decoder doesn't correlate it against anything).

    Packet numbers in comments match this function's own numbered comments 1-30.
    """
    packets = []
    seq = [0]  # shared mutable MAC sequence-number counter, mirrors a real radio's own counter

    def mac_seq():
        seq[0] = (seq[0] + 1) & 0xFF
        return seq[0]

    def emit(dst_short, src_short, nwk_bytes, **kw):
        packets.append(ieee802154_withfcs_frame(
            zigbee_data_mac_frame(mac_seq(), dst_short, src_short, nwk_bytes, **kw)))

    def nwk_data(dst, src, seqno, aps_bytes, *, radius=30):
        return zigbee_nwk_frame(0, 2, dst, src, radius, seqno, payload=aps_bytes)

    nwk_seq = [0]

    def next_nwk_seq():
        nwk_seq[0] = (nwk_seq[0] + 1) & 0xFF
        return nwk_seq[0]

    def aps_zdp(dst, src, zdp_seqno, cluster, zdp_body, *, aps_counter=0):
        aps = zigbee_aps_frame(0, 0, dst_endpoint=0, cluster_id=cluster, profile_id=0x0000,
                                src_endpoint=0, counter=aps_counter,
                                payload=zdp_hdr(zdp_seqno, zdp_body))
        return nwk_data(dst, src, next_nwk_seq(), aps)

    # 1) NWK_addr request: Coordinator asks DEV1's short address by IEEE address.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 1, 0x0000,
                 struct.pack("<Q", ZB_DEV1_EUI) + struct.pack("<BB", 0, 0)))

    # 2) NWK_addr response: DEV1 replies SUCCESS, no associated-device list.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 1, 0x8000,
                 zdp_nwk_or_ieee_addr_resp(0, ieee=ZB_DEV1_EUI, nwk=ZB_DEV1_SHORT)))

    # 3) IEEE_addr request: Coordinator asks DEV1's IEEE address by short address.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 2, 0x0001,
                 struct.pack("<H", ZB_DEV1_SHORT) + struct.pack("<BB", 0, 0)))

    # 4) IEEE_addr response: SUCCESS, with a 1-entry associated-device list.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 2, 0x8001,
                 zdp_nwk_or_ieee_addr_resp(0, ieee=ZB_DEV1_EUI, nwk=ZB_DEV1_SHORT,
                                            assoc=[ZB_DEV2_SHORT], start_index=0)))

    # 5) Node_Desc request.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 3, 0x0002, struct.pack("<H", ZB_DEV1_SHORT)))

    # 6) Node_Desc response: SUCCESS, Router (logical type 1).
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 3, 0x8002,
                 zdp_node_desc_resp(0, nwk=ZB_DEV1_SHORT, logical_type=1, cap=0x8E)))

    # 7) Simple_Desc request (Endpoint 1).
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 4, 0x0004,
                 struct.pack("<H", ZB_DEV1_SHORT) + struct.pack("<B", 1)))

    # 8) Simple_Desc response: SUCCESS, Home Automation profile, On/Off cluster (0x0006) in, none out.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 4, 0x8004,
                 zdp_simple_desc_resp(0, nwk=ZB_DEV1_SHORT, ep=1, profile=0x0104, device=0x0100,
                                       devver=1, in_clusters=[0x0000, 0x0006], out_clusters=[])))

    # 9) Active_EP request.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 5, 0x0005, struct.pack("<H", ZB_DEV1_SHORT)))

    # 10) Active_EP response: SUCCESS, endpoint 1 only.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 5, 0x8005,
                 zdp_active_ep_resp(0, nwk=ZB_DEV1_SHORT, eps=[1])))

    # 11) Match_Desc request: looking for On/Off cluster (0x0006) servers on the HA profile.
    emit(0xFFFD, ZB_COORD_SHORT,  # 0xFFFD == broadcast to all routers/coordinator (non-sleepy)
         nwk_data(0xFFFD, ZB_COORD_SHORT, next_nwk_seq(),
                  zigbee_aps_frame(0, 2, dst_endpoint=0xFF, cluster_id=0x0006, profile_id=0x0000,
                                    src_endpoint=0, counter=0,
                                    payload=zdp_hdr(6, struct.pack("<H", 0x0000) +
                                                     struct.pack("<H", 0x0104) +
                                                     struct.pack("<B", 1) + struct.pack("<H", 0x0006) +
                                                     struct.pack("<B", 0)))))

    # 12) Match_Desc response: DEV1's endpoint 1 matches.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 6, 0x8006,
                 zdp_match_desc_resp(0, nwk=ZB_DEV1_SHORT, matches=[1])))

    # 13) Bind request: bind DEV1 endpoint 1's On/Off cluster (0x0006) to the Coordinator (unicast).
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 7, 0x0021,
                 zdp_bind_or_unbind_req(ZB_DEV1_EUI, 1, 0x0006, 3, dst_ieee=ZB_COORD_EUI, dst_ep=1)))

    # 14) Bind response: SUCCESS.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 7, 0x8021, bytes([0])))

    # 15) Unbind request: undo the same binding.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 8, 0x0022,
                 zdp_bind_or_unbind_req(ZB_DEV1_EUI, 1, 0x0006, 3, dst_ieee=ZB_COORD_EUI, dst_ep=1)))

    # 16) Unbind response: SUCCESS.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 8, 0x8022, bytes([0])))

    # 17) Mgmt_Lqi request: StartIndex=0.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 9, 0x0031, struct.pack("<B", 0)))

    # 18) Mgmt_Lqi response: SUCCESS, 2 neighbor table entries.
    entries = [
        zdp_neighbor_table_entry(0x1122334455667788, ZB_COORD_EUI, ZB_COORD_SHORT, 0, 1, 1, 2, 1, 200),
        zdp_neighbor_table_entry(0x1122334455667788, ZB_DEV2_EUI, ZB_DEV2_SHORT, 2, 0, 1, 2, 2, 180),
    ]
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 9, 0x8031,
                 zdp_mgmt_lqi_resp(0, total=2, start_index=0, entries=entries)))

    # 19) Mgmt_Rtg request: StartIndex=0.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 10, 0x0032, struct.pack("<B", 0)))

    # 20) Mgmt_Rtg response: SUCCESS, 1 routing table entry.
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV1_SHORT, 10, 0x8032,
                 zdp_mgmt_rtg_resp(0, total=1, start_index=0,
                                    entries=[zdp_routing_table_entry(ZB_DEV2_SHORT, 0x00, ZB_DEV1_SHORT)])))

    # 21) Mgmt_Leave request: remove DEV2, without rejoin.
    emit(ZB_DEV2_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV2_SHORT, ZB_COORD_SHORT, 11, 0x0034,
                 struct.pack("<Q", ZB_DEV2_EUI) + struct.pack("<B", 0x80)))

    # 22) Mgmt_Leave response: SUCCESS.
    emit(ZB_COORD_SHORT, ZB_DEV2_SHORT,
         aps_zdp(ZB_COORD_SHORT, ZB_DEV2_SHORT, 11, 0x8034, bytes([0])))

    # 23) Device_annce: DEV2 (re)joining the network -- broadcast, no response.
    emit(0xFFFD, ZB_DEV2_SHORT,
         nwk_data(0xFFFD, ZB_DEV2_SHORT, next_nwk_seq(),
                  zigbee_aps_frame(0, 2, dst_endpoint=0xFF, cluster_id=0x0013, profile_id=0x0000,
                                    src_endpoint=0, counter=0,
                                    payload=zdp_hdr(12, struct.pack("<H", ZB_DEV2_SHORT) +
                                                     struct.pack("<Q", ZB_DEV2_EUI) +
                                                     struct.pack("<B", 0x8E)))))

    # 24) Mgmt_Permit_Joining request: duration=0xFF (INDEFINITE) -- the curated, security-relevant
    #     "notable operation" case (see zigbee.hpp/zigbee.cpp's own Mgmt_Permit_Joining note, the
    #     same pattern BSAP's/CC-Link IE's own Set IP Address notes established).
    emit(0xFFFD, ZB_COORD_SHORT,
         nwk_data(0xFFFD, ZB_COORD_SHORT, next_nwk_seq(),
                  zigbee_aps_frame(0, 2, dst_endpoint=0xFF, cluster_id=0x0036, profile_id=0x0000,
                                    src_endpoint=0, counter=0,
                                    payload=zdp_hdr(13, struct.pack("<BB", 0xFF, 1)))))

    # 25) Mgmt_Permit_Joining response: SUCCESS.
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT,
         aps_zdp(ZB_DEV1_SHORT, ZB_COORD_SHORT, 13, 0x8036, bytes([0])))

    # 26) NWK-layer security ENABLED: proves the NWK header decodes fully (frame type, addressing,
    #     routing) while APS/ZDP correctly report as "N bytes of NWK-encrypted payload" -- the aux
    #     header's own Extended Nonce bit is set here too, exercising the Extended Source field.
    nwk_sec_hdr = zigbee_security_header(5, 1, 0x00000042, extended_nonce=True,
                                          ext_source=ZB_COORD_EUI, key_seqno=0)
    fake_ciphertext_plus_mic = b"\x11" * 20 + b"\x22" * 4  # 20 bytes "ciphertext" + 4-byte MIC (level 5)
    nwk_secured = zigbee_nwk_frame(0, 2, ZB_DEV1_SHORT, ZB_COORD_SHORT, 30, next_nwk_seq(),
                                    security=True, security_header=nwk_sec_hdr,
                                    payload=fake_ciphertext_plus_mic)
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT, nwk_secured)

    # 27) APS-layer security ENABLED, NWK-layer security NOT enabled: proves NWK decodes fully AND
    #     the APS header (cluster/profile/endpoints) still decodes, while ZDP correctly reports as
    #     "N bytes of APS-encrypted payload".
    aps_sec_hdr = zigbee_security_header(5, 0, 0x00000099)  # Link Key, no Extended Nonce
    aps_fake_ciphertext_plus_mic = b"\x33" * 12 + b"\x44" * 4
    aps_secured = zigbee_aps_frame(0, 0, dst_endpoint=1, cluster_id=0x0006, profile_id=0x0104,
                                    src_endpoint=1, counter=1, security=True,
                                    security_header=aps_sec_hdr, payload=aps_fake_ciphertext_plus_mic)
    emit(ZB_COORD_SHORT, ZB_DEV1_SHORT, nwk_data(ZB_COORD_SHORT, ZB_DEV1_SHORT, next_nwk_seq(), aps_secured))

    # 28) Application-profile (ZCL) frame -- Profile ID 0x0104 (Home Automation), NOT the ZDP
    #     profile (0x0000): proves the NWK+APS headers still decode (cluster/profile/endpoints) but
    #     ZCL is correctly left out of scope (see zigbee.hpp's own ZCL scope note).
    zcl_payload = bytes([0x01, 0x02, 0x01, 0x01])  # a plausible-looking ZCL header, not decoded
    zcl_aps = zigbee_aps_frame(0, 0, dst_endpoint=1, cluster_id=0x0006, profile_id=0x0104,
                                src_endpoint=1, counter=2, payload=zcl_payload)
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT, nwk_data(ZB_DEV1_SHORT, ZB_COORD_SHORT, next_nwk_seq(), zcl_aps))

    # 29) APS Command frame (Transport Key, 0x05) -- proves APS Command frames skip ALL endpoint/
    #     cluster/profile fields (see zigbee.hpp section 5.2-5.8) and the command id decodes by name.
    aps_cmd = zigbee_aps_frame(1, 0, counter=3, command_id=0x05, payload=b"\x00" * 18)
    emit(ZB_DEV1_SHORT, ZB_COORD_SHORT, nwk_data(ZB_DEV1_SHORT, ZB_COORD_SHORT, next_nwk_seq(), aps_cmd))

    # 30) NWK Command frame type (route request, not decoded -- see zigbee.hpp's own NWK-command
    #     out-of-scope note): proves the NWK header decodes but APS is correctly not attempted.
    nwk_cmd = zigbee_nwk_frame(1, 2, 0xFFFC, ZB_DEV1_SHORT, 30, next_nwk_seq(),
                                discover_route=1, payload=b"\x01\x08\x00\x00\xD4\xC3")
    emit(0xFFFC, ZB_DEV1_SHORT, nwk_cmd)

    # 31) A non-Data MAC frame type (Ack) on this same link type -- proves decoder.cpp's own
    #     "recognized IEEE 802.15.4 frame, not Zigbee-NWK-carrying" fallback (see decoder.cpp's own
    #     LINKTYPE_IEEE802_15_4_* branch).
    packets.append(ieee802154_withfcs_frame(
        ieee802154_mac_frame(2, seqno=mac_seq(), frame_version=1)))

    # 32) MALFORMED/TRUNCATED: fewer than the fixed 2-byte Frame Control Field itself is present --
    #     must not crash; reported as a "parse-error" packet, proving the ParseError-vs-tolerant-
    #     degrade boundary (see ieee802154.hpp's own "Truncation handling" paragraph).
    packets.append(b"\x01")

    data = pcap_global_header(linktype=LINKTYPE_IEEE802_15_4_WITHFCS)
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_720_100_000 + i, i * 1000)
    (TESTS_DIR / "sample_zigbee.pcap").write_bytes(data)


def build_zigbee_tap_sample():
    """A small LINKTYPE_IEEE802_15_4_TAP (283)-framed companion to build_zigbee_sample() above,
    proving the second in-scope capture format works too -- reuses the exact same NWK/APS/ZDP
    builders, just wrapped in a TAP pseudo-header instead of a bare trailing FCS. Covers both TAP
    FCS_TYPE variants (a pcap file has one global link type, so this needs its own separate file --
    see ieee802154.hpp's own file header comment; a pcapng file COULD carry both link types across
    two interfaces, as build_pcapng_multi_interface_sample() elsewhere in this module shows, but two
    small classic-pcap files is simpler and equally good coverage here).

    1) NWK_addr request, FCS_TYPE=1 (16-bit CRC present, 2 trailing fake-FCS bytes).
    2) NWK_addr response, FCS_TYPE=0 (no FCS at all -- the TAP spec's own default).
    3) Mgmt_Permit_Joining request (duration=0xFF), FCS_TYPE=2 (32-bit CRC, 4 trailing bytes).
    """
    packets = []

    def tap_emit(dst_short, src_short, nwk_bytes, seqno, *, fcs_type):
        mac = zigbee_data_mac_frame(seqno, dst_short, src_short, nwk_bytes)
        fcs = {0: b"", 1: b"\xDE\xAD", 2: b"\xDE\xAD\xBE\xEF"}[fcs_type]
        packets.append(ieee802154_tap_frame(mac, fcs_type=fcs_type, fcs=fcs))

    aps1 = zigbee_aps_frame(0, 0, dst_endpoint=0, cluster_id=0x0000, profile_id=0x0000,
                             src_endpoint=0, counter=0,
                             payload=zdp_hdr(1, struct.pack("<Q", ZB_DEV1_EUI) + struct.pack("<BB", 0, 0)))
    tap_emit(ZB_DEV1_SHORT, ZB_COORD_SHORT, zigbee_nwk_frame(0, 2, ZB_DEV1_SHORT, ZB_COORD_SHORT, 30, 1,
                                                              payload=aps1), 1, fcs_type=1)

    aps2 = zigbee_aps_frame(0, 0, dst_endpoint=0, cluster_id=0x8000, profile_id=0x0000,
                             src_endpoint=0, counter=0,
                             payload=zdp_hdr(1, zdp_nwk_or_ieee_addr_resp(0, ieee=ZB_DEV1_EUI,
                                                                            nwk=ZB_DEV1_SHORT)))
    tap_emit(ZB_COORD_SHORT, ZB_DEV1_SHORT, zigbee_nwk_frame(0, 2, ZB_COORD_SHORT, ZB_DEV1_SHORT, 30, 1,
                                                              payload=aps2), 2, fcs_type=0)

    aps3 = zigbee_aps_frame(0, 2, dst_endpoint=0xFF, cluster_id=0x0036, profile_id=0x0000,
                             src_endpoint=0, counter=0,
                             payload=zdp_hdr(2, struct.pack("<BB", 0xFF, 1)))
    tap_emit(0xFFFD, ZB_COORD_SHORT, zigbee_nwk_frame(0, 2, 0xFFFD, ZB_COORD_SHORT, 30, 2,
                                                        payload=aps3), 3, fcs_type=2)

    data = pcap_global_header(linktype=LINKTYPE_IEEE802_15_4_TAP)
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_720_200_000 + i, i * 1000)
    (TESTS_DIR / "sample_zigbee_tap.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# `baseline learn`/`baseline check` (baseline.hpp/baseline.cpp) -- deliberately mutated fixtures
# for the anomaly-detection side of the testing plan (docs/design/baseline-engine.md's own
# "Testing plan" section). The "known-good" round trip itself reuses tests/sample_modbus.pcap and
# tests/sample_s7comm.pcap directly (see CMakeLists.txt's baseline_learn_* / baseline_check_*
# entries) -- these two fixtures exist only for the cases those two unmodified captures can't
# exercise: a genuinely new function code, a genuinely new address range, and a genuinely new
# conduit, each in isolation from the others so a CTest regex can assert "exactly these findings,
# not more, not fewer" the way the design doc's testing plan asks for.
# ---------------------------------------------------------------------------------------------

def build_baseline_modbus_mutated_sample():
    """Same conduit tests/sample_modbus.pcap's own baseline already knows (HMI_IP -> PLC_IP,
    Modbus/502), exercising three operations on it:
      1) Read Holding Registers, address 0, quantity 10 -- byte-for-byte the SAME operation/range
         sample_modbus.pcap's own packet 1 already taught the baseline, so `baseline check` must
         call this KnownOperation (0 findings).
      2) Write Multiple Registers, address 5, quantity 2 -- a function code sample_modbus.pcap
         never exercises at all, so `baseline check` must call this NewOperation.
      3) Read Holding Registers again, but address 200, quantity 5 -- the SAME operation_key as
         (1), but a range ([200, 205)) nowhere near the baseline's only known range ([0, 10)), so
         `baseline check` must call this NewTargetRange, not NewOperation (the operation_key
         itself IS already known).
    Exactly one NewOperation + one NewTargetRange finding, and nothing else -- see
    baseline_check_mutated_finds_new_operation_and_new_target_range (CMakeLists.txt)."""
    packets = []

    def add_request(src_port, seq, ack, pdu, ident):
        tcp = tcp_header(src_port, 502, seq, ack, TCP_PSH | TCP_ACK, len(pdu)) + pdu
        ip = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp), ident) + tcp
        packets.append(eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip)

    # 1) Read Holding Registers, address 0, quantity 10 -- KNOWN (matches sample_modbus.pcap
    #    exactly).
    mb1 = struct.pack("!HHHBB HH", 10, 0, 6, 1, 3, 0, 10)
    add_request(51100, 1000, 2000, mb1, 0x9000)

    # 2) Write Multiple Registers, address 5, quantity 2, 2 register values -- NEW function code.
    wm_data = struct.pack("!HH", 0x1111, 0x2222)
    wm_pdu = struct.pack("!HHB", 5, 2, len(wm_data)) + wm_data
    mb2 = struct.pack("!HHHBB", 11, 0, 2 + len(wm_pdu), 1, 0x10) + wm_pdu
    add_request(51100, 1100, 2000, mb2, 0x9001)

    # 3) Read Holding Registers, address 200, quantity 5 -- KNOWN operation_key, NEW range.
    mb3 = struct.pack("!HHHBB HH", 12, 0, 6, 1, 3, 200, 5)
    add_request(51100, 1200, 2000, mb3, 0x9002)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_010_000 + i, i * 1000)
    (TESTS_DIR / "sample_baseline_modbus_mutated.pcap").write_bytes(data)


def build_baseline_two_conduit_sample():
    """Two DISTINCT Modbus conduits in one capture, proving `baseline check`'s per-conduit
    isolation (docs/design/baseline-engine.md's testing plan: "a finding on one conduit never
    appears attributed to another conduit"):
      - HMI_IP -> PLC_IP (the SAME conduit tests/sample_modbus.pcap's own baseline already knows):
        Read Holding Registers, address 0, quantity 10 -- byte-for-byte the known operation/range,
        so this conduit contributes ZERO findings.
      - OTHER_IP (192.168.1.77, never seen by the baseline at all) -> PLC_IP: the SAME Read
        Holding Registers/address 0/quantity 10 operation -- but from a client the baseline has
        never seen talk to PLC_IP at all, so this is a brand-new CONDUIT, and must be reported as
        NewConduit, not silently folded into the known conduit's own clean result just because the
        operation itself looks identical."""
    OTHER_IP = "192.168.1.77"
    OTHER_MAC = mac("00:0c:29:dd:ee:ff")
    packets = []

    def add_request(client_ip, client_mac, src_port, seq, ack, pdu, ident):
        tcp = tcp_header(src_port, 502, seq, ack, TCP_PSH | TCP_ACK, len(pdu)) + pdu
        ip = ipv4_header(client_ip, PLC_IP, 6, len(tcp), ident) + tcp
        packets.append(eth_header(PLC_MAC, client_mac, 0x0800) + ip)

    mb = struct.pack("!HHHBB HH", 20, 0, 6, 1, 3, 0, 10)
    add_request(HMI_IP, HMI_MAC, 51200, 1000, 2000, mb, 0xA000)
    add_request(OTHER_IP, OTHER_MAC, 51300, 1000, 2000, mb, 0xA100)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_011_000 + i, i * 1000)
    (TESTS_DIR / "sample_baseline_two_conduit.pcap").write_bytes(data)


# --- AMQP 0-9-1 / AMQP 1.0 -----------------------------------------------------------------
# Two wire-INCOMPATIBLE protocols sharing TCP port 5672 by convention -- see amqp_common.hpp's own
# file header comment for the full detection-posture rationale this fixture exercises: sticky
# per-session version detection from the connection's own 8-byte preamble, and a deliberate
# decline-to-classify scope boundary for a session whose preamble this codebase never captured.

AMQP_PORT = 5672

AMQP091_PREAMBLE = b"AMQP" + bytes([0x00, 0x00, 0x09, 0x01])
AMQP091_PREAMBLE_HISTORICAL = b"AMQP" + bytes([0x01, 0x01, 0x00, 0x09])
AMQP10_PREAMBLE_AMQP = b"AMQP" + bytes([0x00, 0x01, 0x00, 0x00])
AMQP10_PREAMBLE_SASL = b"AMQP" + bytes([0x03, 0x01, 0x00, 0x00])


def amqp091_shortstr(s: str) -> bytes:
    b = s.encode()
    return bytes([len(b)]) + b


def amqp091_longstr(b) -> bytes:
    if isinstance(b, str):
        b = b.encode()
    return struct.pack(">I", len(b)) + b


def amqp091_table(entries=()) -> bytes:
    """entries: list of (name: str, tag: bytes(1), value_bytes: bytes) -- see amqp091.hpp's own
    field-table type-tag table (industry-practice tags, not the written spec's own)."""
    body = b""
    for name, tag, value in entries:
        nb = name.encode()
        body += bytes([len(nb)]) + nb + tag + value
    return struct.pack(">I", len(body)) + body


def amqp091_frame(frame_type: int, channel: int, payload: bytes) -> bytes:
    return (bytes([frame_type]) + struct.pack(">H", channel) + struct.pack(">I", len(payload)) +
            payload + bytes([0xCE]))


def amqp091_method(class_id: int, method_id: int, args: bytes, channel: int = 0) -> bytes:
    return amqp091_frame(1, channel, struct.pack(">HH", class_id, method_id) + args)


def amqp091_content_header(class_id: int, body_size: int, properties=(), channel: int = 0) -> bytes:
    """properties: list of (flag_bit: int, encoded_value_bytes: bytes), already given in declared
    descending-bit order -- see amqp091.hpp's own Basic class property list."""
    flags = 0
    prop_body = b""
    for bit, value in properties:
        flags |= bit
        prop_body += value
    payload = struct.pack(">HHQH", class_id, 0, body_size, flags) + prop_body
    return amqp091_frame(2, channel, payload)


def amqp091_content_body(data: bytes, channel: int = 0) -> bytes:
    return amqp091_frame(3, channel, data)


AMQP091_HEARTBEAT = amqp091_frame(8, 0, b"")

# AMQP 0-9-1 class ids (see amqp091.hpp's own WIRE FORMAT section).
C091_CONN, C091_CHAN, C091_EXCH, C091_QUEUE, C091_BASIC, C091_TX = 10, 20, 40, 50, 60, 90


def amqp_tcp_session(packets, ident_box, mac_a, ip_a, mac_b, ip_b, port_a, port_b=AMQP_PORT):
    """One bidirectional TCP session's worth of AMQP traffic -- the same session()-closure shape
    build_ge_srtp_sample's own session() already establishes, generalized for both directions to
    split and for either endpoint to initiate. `a` plays the client (ephemeral port_a), `b` plays
    the server/broker (port_b, normally AMQP_PORT)."""
    state = {"aseq": 5000, "bseq": 9000}

    def next_ident():
        v = ident_box[0]
        ident_box[0] += 1
        return v

    def a_to_b(payload: bytes):
        tcp = tcp_header(port_a, port_b, state["aseq"], state["bseq"], TCP_PSH | TCP_ACK,
                          len(payload)) + payload
        ip = ipv4_header(ip_a, ip_b, 6, len(tcp), next_ident())
        packets.append(eth_header(mac_b, mac_a, 0x0800) + ip + tcp)
        state["aseq"] += len(payload)

    def b_to_a(payload: bytes):
        tcp = tcp_header(port_b, port_a, state["bseq"], state["aseq"], TCP_PSH | TCP_ACK,
                          len(payload)) + payload
        ip = ipv4_header(ip_b, ip_a, 6, len(tcp), next_ident())
        packets.append(eth_header(mac_a, mac_b, 0x0800) + ip + tcp)
        state["bseq"] += len(payload)

    def a_to_b_split(payload: bytes, split_at: int):
        first, rest = payload[:split_at], payload[split_at:]
        for chunk in (first, rest):
            tcp = tcp_header(port_a, port_b, state["aseq"], state["bseq"], TCP_PSH | TCP_ACK,
                              len(chunk)) + chunk
            ip = ipv4_header(ip_a, ip_b, 6, len(tcp), next_ident())
            packets.append(eth_header(mac_b, mac_a, 0x0800) + ip + tcp)
            state["aseq"] += len(chunk)

    return a_to_b, b_to_a, a_to_b_split


def build_amqp091_sample():
    """Covers: the 8-byte connection preamble (primary pattern) establishing sticky per-session
    version detection, Connection.Start/Start-Ok (with a PLAIN cleartext-credential exchange --
    this feature's own headline finding, and the redaction proof: the literal password is asserted
    to never appear in any output format) /Tune/Tune-Ok/Open/Open-Ok/Close(reply-code 530, >= 400)/
    Close-Ok, Channel.Open/Open-Ok, Exchange.Declare/Declare-Ok, Queue.Declare/Declare-Ok/Bind,
    Queue.Bind-Ok as an UNDECODED-method proof (a confirmed method ID whose own argument layout
    this decoder deliberately leaves undecoded, see amqp091.hpp's own SCOPE section), Basic.Qos/
    Consume/Consume-Ok/Publish(immediate=true, its own curated finding)/Deliver/Get/Get-Ok, a
    Content-Header frame as its own packet's primary frame (full Basic property-list decode) and a
    Content-Body frame likewise, Basic.Ack+Basic.Reject COALESCED into one TCP payload (proves the
    MQTT-style coalescing loop), Basic.Nack, a HEARTBEAT frame, Tx.Select/Select-Ok, Basic.Cancel as
    a second undecoded-method proof, a connection split across two TCP segments for one frame
    (exercises Amqp091Decoder::tcp_declared_length via Decoder::reassemble_tcp_payload), the
    historical 0-9 preamble variant (still classified as 0-9-1), a mid-stream negative control (no
    preamble ever captured on that session -- must decline to classify at all in Auto mode, see
    amqp_common.hpp's own DETECTION POSTURE section), and one exchange on a non-standard port (the
    "not a configured/standard AMQP port" note, --protocol amqp091 only -- Auto mode is port-gated
    and would never attempt this one)."""
    packets = []
    ident_box = [0xB000]

    client, server, client_split = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 54000)

    # 1) Connection preamble (primary 0-9-1 pattern) -- sent alone, matching every real client.
    client(AMQP091_PREAMBLE)

    # 2) Connection.Start
    server(amqp091_method(C091_CONN, 10,
                           bytes([0, 9]) + amqp091_table() + amqp091_longstr("PLAIN AMQPLAIN") +
                           amqp091_longstr("en_US")))

    # 3) Connection.Start-Ok -- PLAIN mechanism, a real cleartext username+password on the wire.
    #    This is the headline finding (--stats) AND the redaction proof: the literal password
    #    "S3cr3tPLC!99" must never appear in ANY output format (text/json/stats), only the
    #    username and the redacted-placeholder + byte-length.
    plain_response = b"\x00" + b"scada_svc" + b"\x00" + b"S3cr3tPLC!99"
    client(amqp091_method(C091_CONN, 11,
                           amqp091_table() + amqp091_shortstr("PLAIN") +
                           amqp091_longstr(plain_response) + amqp091_shortstr("en_US")))

    # 4) & 5) Tune / Tune-Ok
    server(amqp091_method(C091_CONN, 30, struct.pack(">HIH", 2047, 131072, 60)))
    client(amqp091_method(C091_CONN, 31, struct.pack(">HIH", 2047, 131072, 60)))

    # 6) & 7) Open / Open-Ok
    client(amqp091_method(C091_CONN, 40, amqp091_shortstr("/") + amqp091_shortstr("") + bytes([0x00])))
    server(amqp091_method(C091_CONN, 41, amqp091_shortstr("")))

    # 8) & 9) Channel.Open / Open-Ok
    client(amqp091_method(C091_CHAN, 10, amqp091_shortstr(""), channel=1))
    server(amqp091_method(C091_CHAN, 11, amqp091_longstr(""), channel=1))

    # 10) & 11) Exchange.Declare (durable topic exchange) / Declare-Ok
    client(amqp091_method(C091_EXCH, 10,
                           struct.pack(">H", 0) + amqp091_shortstr("amq.topic") +
                           amqp091_shortstr("topic") + bytes([0x02]) + amqp091_table(), channel=1))
    server(amqp091_method(C091_EXCH, 11, b"", channel=1))

    # 12) & 13) Queue.Declare (durable) / Declare-Ok
    client(amqp091_method(C091_QUEUE, 10,
                           struct.pack(">H", 0) + amqp091_shortstr("telemetry.q") +
                           bytes([0x02]) + amqp091_table(), channel=1))
    server(amqp091_method(C091_QUEUE, 11,
                           amqp091_shortstr("telemetry.q") + struct.pack(">II", 0, 0), channel=1))

    # 14) Queue.Bind
    client(amqp091_method(C091_QUEUE, 20,
                           struct.pack(">H", 0) + amqp091_shortstr("telemetry.q") +
                           amqp091_shortstr("amq.topic") + amqp091_shortstr("plc.#") +
                           bytes([0x00]) + amqp091_table(), channel=1))
    # 15) Queue.Bind-Ok (method id 21) -- a confirmed method ID whose own argument layout this
    #     decoder deliberately leaves undecoded (see amqp091.hpp's own SCOPE section) -- zero-
    #     length body still proves arguments_decoded=false, undecoded_argument_bytes=0.
    server(amqp091_method(C091_QUEUE, 21, b"", channel=1))

    # 16) Basic.Qos
    client(amqp091_method(C091_BASIC, 10, struct.pack(">IH", 0, 10) + bytes([0x00]), channel=1))
    # 17) & 18) Basic.Consume / Consume-Ok
    client(amqp091_method(C091_BASIC, 20,
                           struct.pack(">H", 0) + amqp091_shortstr("telemetry.q") +
                           amqp091_shortstr("ctag-1") + bytes([0x00]) + amqp091_table(), channel=1))
    server(amqp091_method(C091_BASIC, 21, amqp091_shortstr("ctag-1"), channel=1))

    # 19) Basic.Publish, immediate=true -- its own curated finding (old-broker/probing signal).
    client(amqp091_method(C091_BASIC, 40,
                           struct.pack(">H", 0) + amqp091_shortstr("amq.topic") +
                           amqp091_shortstr("plc.telemetry") + bytes([0x02]), channel=1))

    # 20) Content-Header, as its own packet's PRIMARY frame -- full Basic property-list decode
    #     (content-type, delivery-mode=2/persistent, message-id, timestamp).
    body = b'{"tag":"%R40","value":1234}'
    client(amqp091_content_header(C091_BASIC, len(body), properties=[
        (0x8000, amqp091_shortstr("application/json")),
        (0x1000, bytes([2])),
        (0x0080, amqp091_shortstr("msg-001")),
        (0x0040, struct.pack(">Q", 1700000000)),
    ], channel=1))
    # 21) Content-Body, as its own packet's PRIMARY frame.
    client(amqp091_content_body(body, channel=1))

    # 22) Basic.Deliver
    server(amqp091_method(C091_BASIC, 60,
                           amqp091_shortstr("ctag-1") + struct.pack(">Q", 1) + bytes([0x00]) +
                           amqp091_shortstr("amq.topic") + amqp091_shortstr("plc.telemetry"),
                           channel=1))
    # 23) & 24) Basic.Get / Get-Ok
    client(amqp091_method(C091_BASIC, 70,
                           struct.pack(">H", 0) + amqp091_shortstr("telemetry.q") + bytes([0x00]),
                           channel=1))
    server(amqp091_method(C091_BASIC, 71,
                           struct.pack(">Q", 2) + bytes([0x00]) + amqp091_shortstr("amq.topic") +
                           amqp091_shortstr("plc.telemetry") + struct.pack(">I", 0), channel=1))

    # 25) Basic.Ack + Basic.Reject COALESCED into ONE TCP payload -- proves the coalescing loop.
    ack = amqp091_method(C091_BASIC, 80, struct.pack(">Q", 1) + bytes([0x00]), channel=1)
    reject = amqp091_method(C091_BASIC, 90, struct.pack(">Q", 2) + bytes([0x01]), channel=1)
    client(ack + reject)

    # 26) Basic.Nack (RabbitMQ extension)
    client(amqp091_method(C091_BASIC, 120, struct.pack(">Q", 3) + bytes([0x03]), channel=1))

    # 27) HEARTBEAT frame (type 8, empty payload).
    client(AMQP091_HEARTBEAT)

    # 28) & 29) Tx.Select / Select-Ok -- confirmed zero-argument.
    client(amqp091_method(C091_TX, 10, b"", channel=1))
    server(amqp091_method(C091_TX, 11, b"", channel=1))

    # 30) Basic.Cancel (method id 30) -- a SECOND undecoded-method proof (different class-section
    #     boundary than Queue.Bind-Ok above).
    client(amqp091_method(C091_BASIC, 30, amqp091_shortstr("ctag-1") + bytes([0x00]), channel=1))

    # 31) & 32) Connection.Close, reply-code 530 (NOT_ALLOWED, >= 400 -- its own curated finding) /
    #     Close-Ok.
    client(amqp091_method(C091_CONN, 50,
                           struct.pack(">H", 530) +
                           amqp091_shortstr("NOT_ALLOWED - PLAIN login refused") +
                           struct.pack(">HH", 10, 11)))
    server(amqp091_method(C091_CONN, 51, b""))

    # 33) & 34) A second session: preamble, then one Connection.Open method frame split across TWO
    #     TCP segments -- exercises Amqp091Decoder::tcp_declared_length via
    #     Decoder::reassemble_tcp_payload, the same split/rejoin shape build_melsec_sample's/
    #     build_ge_srtp_sample's own split packet groups already cover for their own protocols.
    client2, server2, client2_split = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 54001)
    client2(AMQP091_PREAMBLE)
    split_method = amqp091_method(C091_CONN, 40,
                                   amqp091_shortstr("/") + amqp091_shortstr("") + bytes([0x00]))
    # split_at=8 (not some smaller value): the first 7 bytes of this frame's own header
    # (type=1/channel=0/size=8) coincide byte-for-byte with a plausible Modbus/TCP MBAP prefix
    # (transaction_id=0x0100, protocol_id=0x0000) -- Modbus's OWN declared-length probe runs
    # earlier in decoder.cpp's reassembly cascade than AMQP's, and unlike its full try_parse_
    # modbus_tcp, that probe only rejects the "function-code-0 reserved" case once >= 8 bytes are
    # available (see modbus_tcp_declared_length's own comment) -- an 8-byte first segment lands
    # exactly on this frame's own class-id high byte (0x00), which IS byte 8 here, giving Modbus's
    # probe the same reserved-function-code-0 signal its full parser already uses to decline, so it
    # correctly falls through to AMQP's own declared-length probe instead of misfiring.
    client2_split(split_method, split_at=8)

    # 35) & 36) A third session using the HISTORICAL 0-9 preamble variant (AMQP\x01\x01\x00\x09) --
    #     still classified as 0-9-1 (see amqp_common.hpp's own preamble-pattern table).
    client3, server3, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 54002)
    client3(AMQP091_PREAMBLE_HISTORICAL)
    server3(amqp091_method(C091_CONN, 10,
                            bytes([0, 9]) + amqp091_table() + amqp091_longstr("PLAIN") +
                            amqp091_longstr("en_US")))

    # 37) Negative control: a FOURTH session whose preamble this codebase never captured (the very
    #     first packet on this session is already an ordinary-shaped Connection.Tune-Ok frame) --
    #     must DECLINE to classify as amqp091 at all in Auto mode (see amqp_common.hpp's own
    #     DETECTION POSTURE section) rather than guess from the frame's own byte shape alone.
    client4, server4, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 54003)
    # channel=99 (not the real protocol's own channel 0) specifically so this frame's own byte 2
    # (message-id, in HART-IP's own unrelated, opportunistic TcpPortIndependent gate) is > 3 and
    # that gate declines it too -- otherwise this synthetic frame's byte 0-2 shape would coincide
    # with a channel-0-shaped, message-type=0/message-id=0 HART-IP "Request/Session Initiate"
    # opportunistic match, which would obscure this test's actual point (AMQP's own decline, not
    # some unrelated protocol's own opportunistic gate).
    client4(amqp091_method(C091_CONN, 31, struct.pack(">HIH", 2047, 131072, 60), channel=99))

    # 38) & 39) Non-standard port (54004 -> 9999, not AMQP_PORT) -- proves the "seen on TCP port
    #     ..., which is not a configured/standard AMQP port (5672)" note. Auto mode is port-gated
    #     for AMQP (see decoder.cpp's own AMQP call site) and would never attempt this exchange at
    #     all, so the dedicated CTest for this packet group runs with `--protocol amqp091`.
    client5, server5, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 54004, 9999)
    client5(AMQP091_PREAMBLE)
    server5(amqp091_method(C091_CONN, 10,
                            bytes([0, 9]) + amqp091_table() + amqp091_longstr("PLAIN") +
                            amqp091_longstr("en_US")))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_300_000 + i, i * 1000)
    (TESTS_DIR / "sample_amqp091.pcap").write_bytes(data)


# --- AMQP 1.0 --------------------------------------------------------------------------------
# Wire-incompatible with 0-9-1 above despite sharing a default port -- see amqp10.hpp's own WIRE
# FORMAT section for the generic self-describing primitive type system this fixture exercises.


def amqp10_null() -> bytes:
    return b"\x40"


def amqp10_bool(v: bool) -> bytes:
    return b"\x41" if v else b"\x42"


def amqp10_ubyte(v: int) -> bytes:
    return b"\x50" + bytes([v])


def amqp10_ushort(v: int) -> bytes:
    return b"\x60" + struct.pack(">H", v)


def amqp10_uint(v: int) -> bytes:
    return b"\x70" + struct.pack(">I", v)


def amqp10_ulong(v: int) -> bytes:
    return b"\x80" + struct.pack(">Q", v)


def amqp10_str8(s: str) -> bytes:
    b = s.encode()
    return b"\xa1" + bytes([len(b)]) + b


def amqp10_sym8(s: str) -> bytes:
    b = s.encode()
    return b"\xa3" + bytes([len(b)]) + b


def amqp10_bin8(b: bytes) -> bytes:
    return b"\xa0" + bytes([len(b)]) + b


def amqp10_list0() -> bytes:
    return b"\x45"


def amqp10_list8(elements) -> bytes:
    """elements: list of already fully-encoded (constructor-prefixed) value bytes."""
    body = b"".join(elements)
    inner = bytes([len(elements)]) + body
    return b"\xc0" + bytes([len(inner)]) + inner


def amqp10_map8(pairs) -> bytes:
    """pairs: list of (key_bytes, value_bytes), each already fully-encoded."""
    body = b"".join(k + v for k, v in pairs)
    inner = bytes([len(pairs) * 2]) + body
    return b"\xc1" + bytes([len(inner)]) + inner


def amqp10_array8_sym(strings) -> bytes:
    """A symbol array -- every element shares ONE constructor (0xa3, sym8) read once, per
    elements bytes WITHOUT their own per-element constructor -- see amqp10.hpp's own TYPE SYSTEM
    "array shares one constructor" gotcha."""
    body = b"".join(bytes([len(s.encode())]) + s.encode() for s in strings)
    inner = bytes([len(strings)]) + bytes([0xa3]) + body
    return b"\xe0" + bytes([len(inner)]) + inner


def amqp10_described(code: int, list_bytes: bytes) -> bytes:
    return b"\x00\x53" + bytes([code]) + list_bytes


def amqp10_frame(frame_type: int, channel: int, body: bytes) -> bytes:
    """doff is always 2 (8-byte header, no extended header) for every frame this fixture builds."""
    size = 8 + len(body)
    return struct.pack(">IBBH", size, 2, frame_type, channel) + body


def amqp10_empty_frame(channel: int = 0) -> bytes:
    return struct.pack(">IBBH", 8, 2, 0, channel)


# AMQP 1.0 performative codes (see amqp10.hpp's own amqp10_performative_name/
# amqp10_sasl_performative_name).
P10_OPEN, P10_BEGIN, P10_ATTACH, P10_FLOW, P10_TRANSFER = 0x10, 0x11, 0x12, 0x13, 0x14
P10_DISPOSITION, P10_DETACH, P10_END, P10_CLOSE = 0x15, 0x16, 0x17, 0x18
P10_SASL_MECHANISMS, P10_SASL_INIT, P10_SASL_OUTCOME = 0x40, 0x41, 0x44
SEC_SOURCE, SEC_TARGET, SEC_ERROR = 0x28, 0x29, 0x1d
SEC_REJECTED = 0x25
MSG_HEADER, MSG_PROPERTIES, MSG_APP_PROPERTIES, MSG_DATA = 0x70, 0x73, 0x74, 0x75


def amqp10_error(condition: str, description: str) -> bytes:
    """A described `error` (0x1d) wrapping [condition(symbol), description(string)] -- see
    amqp10.hpp's own extract_error/WIRE FORMAT section."""
    return amqp10_described(SEC_ERROR, amqp10_list8([amqp10_sym8(condition), amqp10_str8(description)]))


def build_amqp10_sample():
    """Covers: the 8-byte connection preamble (AMQP-transport-layer pattern) establishing sticky
    per-session version detection, the SASL layer (its own preamble pattern, sasl-mechanisms/sasl-
    init with a PLAIN cleartext-credential exchange -- this feature's own headline finding and
    redaction proof -- /sasl-outcome success, PLUS a second, separate SASL exchange proving a
    negotiation FAILURE outcome), open/begin/attach (with source/target address extraction)/flow/
    transfer (with a full message-section walk: header/properties/application-properties/data, and
    curated property-field extraction), disposition (a `rejected` delivery-state, proving delivery-
    state/error extraction), detach/end/close (detach and close each carrying a real error
    condition -- their own curated finding; end carrying none, the clean-shutdown case), an EMPTY
    frame (keepalive), a connection split across two TCP segments for one frame (exercises
    Amqp10Decoder::tcp_declared_length via Decoder::reassemble_tcp_payload), a mid-stream negative
    control (no preamble ever captured on that session -- must decline to classify at all in Auto
    mode), and one exchange on a non-standard port (--protocol amqp10 only)."""
    packets = []
    ident_box = [0xC000]

    client, server, client_split = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55000)

    # 1) Connection preamble -- AMQP transport-layer pattern (0x00 0x01 0x00 0x00).
    client(AMQP10_PREAMBLE_AMQP)

    # 2) open (client's own connection-establishment performative).
    open_list = amqp10_list8([amqp10_str8("scada-hmi-01"), amqp10_str8("broker.plant.local"),
                               amqp10_uint(131072)])
    client(amqp10_frame(0, 0, amqp10_described(P10_OPEN, open_list)))
    # 3) open (broker's own response).
    open_resp_list = amqp10_list8([amqp10_str8("broker-01")])
    server(amqp10_frame(0, 0, amqp10_described(P10_OPEN, open_resp_list)))

    # 4) begin -- remote-channel omitted (null placeholder), next-outgoing-id/incoming-window/
    #    outgoing-window present.
    begin_list = amqp10_list8([amqp10_null(), amqp10_uint(0), amqp10_uint(2147483647), amqp10_uint(0)])
    client(amqp10_frame(0, 1, amqp10_described(P10_BEGIN, begin_list)))
    server(amqp10_frame(0, 1, amqp10_described(P10_BEGIN, begin_list)))

    # 5) attach -- a sending link ("plc.telemetry" publisher), source omitted (empty string
    #    address), target = the real destination address. Proves source_address/target_address
    #    extraction (extract_described_list_field).
    source = amqp10_described(SEC_SOURCE, amqp10_list8([amqp10_str8("")]))
    target = amqp10_described(SEC_TARGET, amqp10_list8([amqp10_str8("telemetry.queue")]))
    attach_list = amqp10_list8([amqp10_str8("link-1"), amqp10_uint(0), amqp10_bool(False),
                                 amqp10_null(), amqp10_null(), source, target])
    client(amqp10_frame(0, 1, amqp10_described(P10_ATTACH, attach_list)))
    server(amqp10_frame(0, 1, amqp10_described(P10_ATTACH, attach_list)))

    # 6) flow -- handle at its own fixed position (index 4), everything before it a null
    #    placeholder.
    flow_list = amqp10_list8([amqp10_null(), amqp10_null(), amqp10_null(), amqp10_null(), amqp10_uint(0)])
    server(amqp10_frame(0, 1, amqp10_described(P10_FLOW, flow_list)))

    # 7) transfer, handle=0/delivery-id=1, followed by a FULL message-section walk: header,
    #    properties (message-id/to/subject/correlation-id/content-type all curated-field-
    #    extracted), application-properties (a 2-entry map), and a data section.
    transfer_list = amqp10_list8([amqp10_uint(0), amqp10_uint(1)])
    header_section = amqp10_described(
        MSG_HEADER, amqp10_list8([amqp10_bool(True), amqp10_ubyte(4), amqp10_uint(60000)]))
    properties_section = amqp10_described(MSG_PROPERTIES, amqp10_list8([
        amqp10_str8("msg-001"), amqp10_null(), amqp10_str8("plc.telemetry"),
        amqp10_str8("sensor-reading"), amqp10_null(), amqp10_str8("corr-abc"),
        amqp10_sym8("application/json"),
    ]))
    app_props_section = amqp10_described(MSG_APP_PROPERTIES, amqp10_map8([
        (amqp10_sym8("unit"), amqp10_str8("celsius")),
        (amqp10_sym8("plc-tag"), amqp10_str8("%R40")),
    ]))
    data_payload = b'{"temp": 42.5}'
    data_section = amqp10_described(MSG_DATA, amqp10_bin8(data_payload))
    transfer_body = (amqp10_described(P10_TRANSFER, transfer_list) + header_section +
                      properties_section + app_props_section + data_section)
    client(amqp10_frame(0, 1, transfer_body))

    # 8) disposition -- a `rejected` delivery-state carrying a real error condition, proving
    #    delivery-state/error extraction (extract_error via disposition's own state field).
    rejected_state = amqp10_described(SEC_REJECTED, amqp10_list8([
        amqp10_error("amqp:precondition-failed", "queue full")]))
    disposition_list = amqp10_list8([amqp10_bool(True), amqp10_uint(1), amqp10_null(),
                                      amqp10_bool(True), rejected_state])
    server(amqp10_frame(0, 1, amqp10_described(P10_DISPOSITION, disposition_list)))

    # 9) detach -- WITH a real error condition (its own curated finding).
    detach_list = amqp10_list8([amqp10_uint(0), amqp10_bool(True),
                                 amqp10_error("amqp:resource-deleted", "queue removed by admin")])
    server(amqp10_frame(0, 1, amqp10_described(P10_DETACH, detach_list)))

    # 10) end -- WITHOUT an error (list0, the clean-shutdown case).
    client(amqp10_frame(0, 1, amqp10_described(P10_END, amqp10_list0())))

    # 11) EMPTY frame (keepalive) -- proves is_empty.
    client(amqp10_empty_frame(0))

    # 12) close -- WITH a real error condition (broker forcibly closing the connection -- its own
    #     curated finding).
    close_list = amqp10_list8([amqp10_error("amqp:connection:forced", "too many connections")])
    server(amqp10_frame(0, 0, amqp10_described(P10_CLOSE, close_list)))

    # 13)-19) A SECOND session, entirely on the SASL layer (its own preamble pattern): sasl-
    #     mechanisms, sasl-init (PLAIN, a real cleartext username+password -- the redaction proof:
    #     the literal password "Op3nPLC$99" must never appear in ANY output format), sasl-outcome
    #     (success, code=0).
    client2, server2, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55001)
    client2(AMQP10_PREAMBLE_SASL)
    mechanisms_list = amqp10_list8([amqp10_array8_sym(["PLAIN", "ANONYMOUS"])])
    server2(amqp10_frame(1, 0, amqp10_described(P10_SASL_MECHANISMS, mechanisms_list)))
    sasl_response = b"\x00" + b"hmi_client" + b"\x00" + b"Op3nPLC$99"
    sasl_init_list = amqp10_list8([amqp10_sym8("PLAIN"), amqp10_bin8(sasl_response),
                                    amqp10_str8("broker.plant.local")])
    client2(amqp10_frame(1, 0, amqp10_described(P10_SASL_INIT, sasl_init_list)))
    sasl_outcome_ok = amqp10_list8([amqp10_ubyte(0)])
    server2(amqp10_frame(1, 0, amqp10_described(P10_SASL_OUTCOME, sasl_outcome_ok)))

    # 20)-22) A THIRD session proving a SASL negotiation FAILURE (code=1, "auth") -- its own
    #     curated finding.
    client3, server3, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55002)
    client3(AMQP10_PREAMBLE_SASL)
    sasl_init_bad = amqp10_list8([amqp10_sym8("PLAIN"), amqp10_bin8(b"\x00baduser\x00badpass")])
    client3(amqp10_frame(1, 0, amqp10_described(P10_SASL_INIT, sasl_init_bad)))
    sasl_outcome_fail = amqp10_list8([amqp10_ubyte(1)])
    server3(amqp10_frame(1, 0, amqp10_described(P10_SASL_OUTCOME, sasl_outcome_fail)))

    # 23) & 24) A FOURTH session: preamble, then one `open` frame split across TWO TCP segments --
    #     exercises Amqp10Decoder::tcp_declared_length via Decoder::reassemble_tcp_payload.
    client4, server4, client4_split = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55003)
    client4(AMQP10_PREAMBLE_AMQP)
    split_open = amqp10_frame(0, 0, amqp10_described(P10_OPEN, open_list))
    client4_split(split_open, split_at=6)

    # 25) Negative control: a FIFTH session whose preamble this codebase never captured (the very
    #     first packet already an ordinary-shaped `end` frame) -- must DECLINE to classify as
    #     amqp10 at all in Auto mode (see amqp_common.hpp's own DETECTION POSTURE section).
    client5, server5, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55004)
    client5(amqp10_frame(0, 1, amqp10_described(P10_END, amqp10_list0())))

    # 26) & 27) Non-standard port (55005 -> 9999, not AMQP_PORT) -- proves the "not a configured/
    #     standard AMQP port" note; Auto mode is port-gated so the dedicated CTest for this packet
    #     group runs with `--protocol amqp10`.
    client6, server6, _ = amqp_tcp_session(packets, ident_box, HMI_MAC, HMI_IP, PLC_MAC, PLC_IP, 55005, 9999)
    client6(AMQP10_PREAMBLE_AMQP)
    server6(amqp10_frame(0, 0, amqp10_described(P10_OPEN, open_resp_list)))

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_400_000 + i, i * 1000)
    (TESTS_DIR / "sample_amqp10.pcap").write_bytes(data)


if __name__ == "__main__":
    TESTS_DIR.mkdir(exist_ok=True)
    build_modbus_sample()
    build_modbus_false_positive_sample()
    build_modbus_pairing_sample()
    build_dnp3_sample()
    build_link_and_transport_layer_sample()
    build_iec104_sample()
    build_iec104_extended_types_sample()
    build_iec104_modbus_precedence_sample()
    build_enip_sample()
    build_enip_string_and_structured_sample()
    build_enip_nop_precedence_sample()
    build_enip_cip_io_sample()
    build_policy_functions_enip_sample()
    build_profinet_sample()
    build_goose_sample()
    build_sv_sample()
    build_ethercat_sample()
    build_stp_sample()
    build_devicenet_sample()
    build_canopen_j1939_sample()
    build_bacnet_sample()
    build_hartip_sample()
    build_opcua_sample()
    build_s7comm_sample()
    build_s7comm_items_sample()
    build_s7comm_1200sym_sample()
    build_s7comm_chaining_sample()
    build_s7comm_pi_control_sample()
    build_s7commplus_sample()
    build_mms_sample()
    build_mqtt_sample()
    build_terminal_escape_injection_sample()
    build_ffhse_sample()
    build_twincat_sample()
    build_melsec_sample()
    build_fins_sample()
    build_kerberos_sample()
    build_ldap_sample()
    build_smb_sample()
    build_netlogon_sample()
    build_samr_lsarpc_sample()
    build_srvsvc_wkssvc_sample()
    build_drsuapi_sample()
    build_policy_engine_sample()
    build_summarize_unclassified_sample()
    build_inventory_sample()
    build_tcp_reassembly_sample()
    build_resource_exhaustion_active_flows_sample()
    build_resource_exhaustion_flow_state_sample()
    build_ipv6_sample()
    build_ipv6_raw_link_sample()
    build_padded_ack_sample()
    build_pcapng_malformed()
    build_pcapng_basic_sample()
    build_pcapng_nanosecond_sample()
    build_pcapng_implausible_tsresol_sample()
    build_pcapng_multi_interface_sample()
    build_pcapng_simple_packet_block_sample()
    build_dns_sample()
    build_mdns_sample()
    build_llmnr_sample()
    build_nbns_sample()
    build_doh_sample()
    build_vlan_zones_sample()
    build_rip_sample()
    build_igmp_sample()
    build_icmp_sample()
    build_vrrp_sample()
    build_hsrp_sample()
    build_igrp_sample()
    build_pim_sample()
    build_eigrp_sample()
    build_ospf_sample()
    build_goose_deep_nesting_sample()
    build_arp_sample()
    build_lldp_sample()
    build_cdp_sample()
    build_bgp_sample()
    build_slow_protocols_sample()
    build_winrm_sample()
    build_wmi_dcom_activation_sample()
    build_iccp_sample()
    build_ge_srtp_sample()
    build_bsap_sample()
    build_cclink_ie_sample()
    build_attack_detect_sample()
    build_codesys_sample()
    build_coap_sample()
    build_ipmi_sample()
    build_zigbee_sample()
    build_zigbee_tap_sample()
    build_baseline_modbus_mutated_sample()
    build_baseline_two_conduit_sample()
    build_amqp091_sample()
    build_amqp10_sample()
    print("wrote sample fixtures to", TESTS_DIR)
