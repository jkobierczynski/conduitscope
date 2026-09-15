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


def build_not_a_pcap():
    # First 4 bytes are the byte-order-independent pcapng Section Header
    # Block magic (0A 0D 0D 0A); the rest just needs to pad the file out to
    # conduitscope's 24-byte global-header read so the pcapng-specific error
    # message path is exercised rather than a generic "too short" error.
    (TESTS_DIR / "not_a_pcap.pcapng").write_bytes(bytes([0x0A, 0x0D, 0x0D, 0x0A]) + b"\x00" * 28)


if __name__ == "__main__":
    TESTS_DIR.mkdir(exist_ok=True)
    build_modbus_sample()
    build_modbus_false_positive_sample()
    build_dnp3_sample()
    build_s7comm_sample()
    build_s7comm_items_sample()
    build_s7comm_1200sym_sample()
    build_tcp_reassembly_sample()
    build_padded_ack_sample()
    build_not_a_pcap()
    print("wrote sample fixtures to", TESTS_DIR)
