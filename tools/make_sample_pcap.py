#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Generates the synthetic pcap fixtures under tests/.

Pure standard library (struct only) -- deliberately has no dependency on
scapy/pymodbus/etc. so the test fixtures can be regenerated (or new ones
added) without installing anything. This is a build-time/dev-time helper,
not something the CMake build invokes automatically -- the generated files
are committed under tests/ like any other fixture.

Run it from the repository root:
    python3 tools/make_sample_pcap.py
"""
import struct
import pathlib

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

    # A non-TCP, non-UDP IPv4 payload -- ICMP echo request (type=8, code=0, checksum=0, arbitrary
    # rest), named via ip_protocol_name.
    icmp = struct.pack("!BBH", 8, 0, 0) + bytes([0x01, 0x02, 0x03, 0x04])
    add_ip(1, icmp)

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
    responses with per-item errors; SetVariable and DeleteObject request/response pairs. Then the
    Tier-2 (named, not body-decoded) shapes: Connect, Notification, DataFW1_5, and one
    representative "other" function code (Explore) neither direction decodes. Then a Keep Alive
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

    # 18) DataFW1_5 (Tier-2: header only -- PDU type/Data Length/trailer decoded, entire Data part
    #     left raw, see s7commplus.hpp on why).
    fw15_data = s7p_envelope(S7P_OPCODE_REQUEST, S7P_FC_GETMULTIVAR, 7,
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
                       device_status: int = 0, preamble_count: int = 2, checksum: int = 0x00,
                       byte_count_override: int = None) -> bytes:
    """One tunneled classic-HART token-passing Data-Link PDU -- see hartip.hpp's Pass-Through
    section. `is_response` defaults to the same is_rsp derivation hartip.cpp uses (frame_type 6=ACK
    or 1=BACK); pass it explicitly only for a deliberately-inconsistent fixture. `address`, for a
    long address, must be exactly 5 bytes; for a short address, an int (masked to 0x3F on decode,
    so the raw byte doesn't need to be pre-masked here)."""
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
    UDP-datagram case; an unexpected-port case; a malformed/truncated case; and, over TCP, a
    genuine request/response round trip, a TCP-segment-split PDU, and two PDUs coalesced into one
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

    # 64) & 65) A genuine FMS Initiate request/response round trip over TCP.
    add_tcp(True, ffhse_pdu(FFHSE_FMS, FFHSE_REQ, 96, True,
                             fms_initiate_req_body(1, 0x00, 0x0000, 1, 1, "PT-101")))
    add_tcp(False, ffhse_pdu(FFHSE_FMS, FFHSE_RSP, 96, True, fms_initiate_rsp_body(1, 1)))

    # 66) & 67) One FDA Open Session Req PDU split across TWO TCP segments -- the FIRST segment
    #     carries only the 12-byte header plus a few body bytes; the SECOND carries the rest.
    #     Exercises ffhse_declared_length-driven cross-segment reassembly (mirrors
    #     hartip_declared_length's own TCP reassembly test).
    split_pdu = ffhse_pdu(FFHSE_FDA, FFHSE_REQ, 1, True, open_session)
    split_point = 20
    add_tcp(True, split_pdu[:split_point], sport=52310)
    add_tcp(True, split_pdu[split_point:], sport=52310)

    # 68) Two SM Clear Assignment Info Rsp messages coalesced into ONE TCP segment (sender/OS
    #     coalescing) -- exercises the wire_length-driven "additional FF-HSE message" loop for TCP.
    add_tcp(True, ffhse_pdu(FFHSE_SM, FFHSE_RSP, 15, True) + ffhse_pdu(FFHSE_SM, FFHSE_RSP, 15, True),
            sport=52320, dport=FFHSE_PORT_SM)

    data = pcap_global_header()
    for i, pkt in enumerate(packets):
        data += pcap_record(pkt, 1_700_007_000 + i, i * 1000)
    (TESTS_DIR / "sample_ffhse.pcap").write_bytes(data)


# ---------------------------------------------------------------------------------------------
# DNS / mDNS / LLMNR / NBT-NS / DoH-detection (ROADMAP: "Add DNS, DoH, NBT-NS name resolution
# decode") -- see dns.hpp/nbns.hpp/tls_sni.hpp's own file header comments for the wire formats
# these fixtures exercise.

DNS_PORT = 53
MDNS_PORT = 5353
LLMNR_PORT = 5355
NBNS_PORT = 137
DOH_PORT = 443


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
IGMP_IP_PROTOCOL = 2
VRRP_IP_PROTOCOL = 112


def ip_bytes4(addr: str) -> bytes:
    return bytes(int(o) for o in addr.split("."))


def udp_ip_eth_frame(payload: bytes, sport: int, dport: int, src_ip: str, dst_ip: str,
                      src_mac: bytes, dst_mac: bytes, ident: int = 0x9000) -> bytes:
    udp = udp_header(sport, dport, payload)
    ip = ipv4_header(src_ip, dst_ip, 17, len(udp), ident)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + udp


def ip_eth_frame(payload: bytes, protocol: int, src_ip: str, dst_ip: str, src_mac: bytes,
                  dst_mac: bytes, ident: int = 0x9000) -> bytes:
    """For IGMP/VRRP: no UDP/TCP header at all -- `payload` rides directly on IP."""
    ip = ipv4_header(src_ip, dst_ip, protocol, len(payload), ident)
    return eth_header(dst_mac, src_mac, 0x0800) + ip + payload


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
    build_ffhse_sample()
    build_policy_engine_sample()
    build_tcp_reassembly_sample()
    build_padded_ack_sample()
    build_pcapng_malformed()
    build_pcapng_basic_sample()
    build_pcapng_nanosecond_sample()
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
    build_vrrp_sample()
    build_hsrp_sample()
    print("wrote sample fixtures to", TESTS_DIR)
