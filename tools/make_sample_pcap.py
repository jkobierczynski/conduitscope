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
LINKTYPE_RAW = 101

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


def dnp3_block_crc_encode(payload: bytes) -> bytes:
    """Splits `payload` (the logical transport+application bytes) into <=16-byte blocks, each
    followed by its own 2-byte CRC -- the real DNP3 data-link user-data wire format. The CRC
    bytes are placeholders (conduitscope does not validate them, same as the header CRC), but
    their *placement* -- every 16 bytes, including a short final block -- must be real, since
    that's exactly the reassembly logic being exercised."""
    out = b""
    for i in range(0, len(payload), 16):
        chunk = payload[i:i + 16]
        out += chunk + b"\xAB\xCD"  # placeholder block CRC, not validated by conduitscope
    return out


def dnp3_link_frame(source: int, destination: int, user_data: bytes, control: int = 0xC4) -> bytes:
    """A full DNP3 data-link frame: 10-byte header (start+length+control+dest+src+header-CRC,
    header CRC a placeholder like the block CRCs) followed by `user_data`'s block-CRC-encoded
    wire bytes."""
    length_field = 5 + len(user_data)
    assert length_field <= 255, "single data-link frame can't carry this much user data"
    header = (bytes([0x05, 0x64, length_field, control]) + struct.pack("<HH", destination, source) +
              b"\xEF\xBE")  # placeholder header CRC, not validated by conduitscope
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


def profinet_frame(frame_id: int, payload: bytes, dst: bytes = None, src: bytes = None) -> bytes:
    """One raw-Ethernet PROFINET RT frame: EtherType 0x8892, then a 2-byte big-endian FrameID,
    then `payload` -- see profinet.hpp's file header comment for the wire format."""
    dst = dst if dst is not None else PLC_MAC
    src = src if src is not None else HMI_MAC
    return eth_header(dst, src, 0x8892) + struct.pack("!H", frame_id) + payload


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


if __name__ == "__main__":
    TESTS_DIR.mkdir(exist_ok=True)
    build_modbus_sample()
    build_modbus_false_positive_sample()
    build_modbus_pairing_sample()
    build_dnp3_sample()
    build_link_and_transport_layer_sample()
    build_iec104_sample()
    build_iec104_modbus_precedence_sample()
    build_enip_sample()
    build_enip_nop_precedence_sample()
    build_enip_cip_io_sample()
    build_profinet_sample()
    build_s7comm_sample()
    build_s7comm_items_sample()
    build_s7comm_1200sym_sample()
    build_s7comm_chaining_sample()
    build_policy_engine_sample()
    build_tcp_reassembly_sample()
    build_padded_ack_sample()
    build_pcapng_malformed()
    build_pcapng_basic_sample()
    build_pcapng_nanosecond_sample()
    build_pcapng_multi_interface_sample()
    build_pcapng_simple_packet_block_sample()
    print("wrote sample fixtures to", TESTS_DIR)
