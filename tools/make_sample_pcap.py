#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
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


def build_dnp3_sample():
    # Minimal DNP3 data link frame: no application-layer payload, so
    # user_data_bytes decodes to 0. That's enough to exercise detection and
    # header-field decoding without needing a valid CRC (which conduitscope
    # does not validate in this groundwork release).
    dnp3_frame = bytes([0x05, 0x64, 0x05, 0xC4]) + struct.pack("<HH", 1024, 1) + b"\x00\x00"
    tcp_seg = tcp_header(51500, 20000, 5000, 6000, TCP_PSH | TCP_ACK, len(dnp3_frame)) + dnp3_frame
    ip_seg = ipv4_header(HMI_IP, PLC_IP, 6, len(tcp_seg), 0x2000) + tcp_seg
    eth_seg = eth_header(PLC_MAC, HMI_MAC, 0x0800) + ip_seg

    data = pcap_global_header()
    data += pcap_record(eth_seg, 1_700_000_100, 0)
    (TESTS_DIR / "sample_dnp3.pcap").write_bytes(data)


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


def build_not_a_pcap():
    # First 4 bytes are the byte-order-independent pcapng Section Header
    # Block magic (0A 0D 0D 0A); the rest just needs to pad the file out to
    # conduitscope's 24-byte global-header read so the pcapng-specific error
    # message path is exercised rather than a generic "too short" error.
    (TESTS_DIR / "not_a_pcap.pcapng").write_bytes(bytes([0x0A, 0x0D, 0x0D, 0x0A]) + b"\x00" * 28)


if __name__ == "__main__":
    TESTS_DIR.mkdir(exist_ok=True)
    build_modbus_sample()
    build_dnp3_sample()
    build_s7comm_sample()
    build_s7comm_items_sample()
    build_s7comm_1200sym_sample()
    build_padded_ack_sample()
    build_not_a_pcap()
    print("wrote sample fixtures to", TESTS_DIR)
