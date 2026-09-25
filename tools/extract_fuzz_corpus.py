#!/usr/bin/env python3
"""extract_fuzz_corpus.py - pull real, known-good payload bytes out of this project's own
tests/sample_*.pcap(ng) fixtures to seed a libFuzzer corpus under fuzz/corpus/<name>/, the same
"seed files are the TCP payload bytes ... extracted from this repo's own existing tests/sample_*.pcap
fixtures" approach fuzz/README.md documents for the original nine harnesses.

Supports both classic pcap (magic 0xa1b2c3d4 / 0xd4c3b2a1, either byte order) and pcapng (magic
0x0a0d0d0a) -- this project's own sample fixtures are classic pcap (see tools/make_sample_pcap.py's
pcap_global_header()), but some real-capture fixtures under tests/real_captures/ are pcapng.

Four extraction layers, matching how a fuzz harness actually calls into conduitscope_core (match
the layer to the protocol's own GateKind in protocol_decoder.hpp/its own header -- IpProtocol -> l3,
EtherType -> l2, TcpPort(Independent)/UdpPort(Independent) -> l4):
  l4   (default) -- strips Ethernet (+ 802.1Q tag if present) and IPv4/IPv6, then TCP or UDP,
                    leaving exactly the bytes a TCP/UDP payload-taking try_parse_X(ByteSpan) would
                    see. Optionally filtered by --port and/or --l4-proto.
  l3   -- strips Ethernet (+ 802.1Q tag) and IPv4/IPv6, stopping at the IP payload for a given
          IP protocol number (not just 6/17) -- for GateKind::IpProtocol decoders (ICMP, ICMPv6,
          IGMP, IGRP, OSPF, PIM, VRRP, EIGRP, ...). Filtered by --ip-proto (required).
  l2   -- strips only Ethernet (+ 802.1Q tag if present), leaving the EtherType payload -- for
          protocols decoded directly off an EtherType gate (GOOSE, Sampled Values, LLDP, STP, CDP,
          EAPOL, ARP, HomePlug AV, ...), optionally filtered by --ethertype.
  raw  -- the whole captured frame, unmodified -- for a harness that parses framing itself
          (mirrors fuzz_pcap_reader's own whole-frame corpus), or for non-Ethernet link types
          (GateKind::LinkType -- SocketCAN, IEEE 802.15.4/Zigbee, J1939) where the frame IS the
          payload a try_parse_X(ByteSpan) expects, with no Ethernet header to strip at all.

Output: one file per distinct extracted payload (exact-duplicate payloads are written once),
named seed_0001.bin, seed_0002.bin, ... under --out. Skips empty payloads by default.

Usage:
    python3 tools/extract_fuzz_corpus.py tests/sample_dnp3.pcap fuzz/corpus/dnp3 \
        --layer l4 --l4-proto tcp

    python3 tools/extract_fuzz_corpus.py tests/sample_goose_sv.pcap fuzz/corpus/goose \
        --layer l2 --ethertype 0x88b8
"""
import argparse
import os
import struct
import sys


def parse_classic_pcap(data: bytes):
    magic = data[0:4]
    if magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
        nano = False
    elif magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
        nano = False
    elif magic == b"\xa1\xb2\x3c\x4d":
        endian = ">"
        nano = True
    elif magic == b"\x4d\x3c\xb2\xa1":
        endian = "<"
        nano = True
    else:
        return None
    off = 24  # global header is fixed 24 bytes regardless of nanosecond variant
    frames = []
    while off + 16 <= len(data):
        ts_sec, ts_usec, incl_len, orig_len = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        if off + incl_len > len(data):
            break
        frames.append(data[off:off + incl_len])
        off += incl_len
    return frames


def parse_pcapng(data: bytes):
    frames = []
    off = 0
    link_type = 1  # default Ethernet
    iface_link_types = {}
    iface_index = 0
    endian = "<"
    while off + 12 <= len(data):
        block_type = struct.unpack(endian + "I", data[off:off + 4])[0]
        block_total_len = struct.unpack(endian + "I", data[off + 4:off + 8])[0]
        if block_total_len < 12 or off + block_total_len > len(data):
            break
        body = data[off + 8:off + block_total_len - 4]
        if block_type == 0x0A0D0D0A:  # Section Header Block
            # byte-order magic sits at body[0:4]
            if body[0:4] == b"\x4d\x3c\x2b\x1a":
                endian = ">"
            else:
                endian = "<"
        elif block_type == 0x00000001:  # Interface Description Block
            if len(body) >= 4:
                lt = struct.unpack(endian + "H", body[0:2])[0]
                iface_link_types[iface_index] = lt
                iface_index += 1
        elif block_type == 0x00000006:  # Enhanced Packet Block
            if len(body) >= 20:
                iface_id = struct.unpack(endian + "I", body[0:4])[0]
                cap_len = struct.unpack(endian + "I", body[12:16])[0]
                pkt = body[20:20 + cap_len]
                frames.append((pkt, iface_link_types.get(iface_id, link_type)))
        elif block_type == 0x00000003:  # Simple Packet Block
            if len(body) >= 4:
                cap_len = len(body) - 4
                pkt = body[4:4 + cap_len]
                frames.append((pkt, link_type))
        off += block_total_len
    return [f for f, _lt in frames]


def load_frames(path: str):
    with open(path, "rb") as f:
        data = f.read()
    if len(data) >= 4 and data[0:4] == b"\x0a\x0d\x0d\x0a":
        return parse_pcapng(data)
    frames = parse_classic_pcap(data)
    if frames is None:
        raise ValueError(f"{path}: not a recognized pcap or pcapng file (bad magic)")
    return frames


def strip_ethernet(frame: bytes):
    """Returns (ethertype, payload_after_l2) or None if too short."""
    if len(frame) < 14:
        return None
    ethertype = struct.unpack(">H", frame[12:14])[0]
    off = 14
    # 802.1Q / 802.1ad VLAN tag(s) -- TPID 0x8100 or 0x88a8, each adds 4 bytes and a new
    # ethertype/TPID field right after.
    while ethertype in (0x8100, 0x88A8) and len(frame) >= off + 4:
        ethertype = struct.unpack(">H", frame[off + 2:off + 4])[0]
        off += 4
    return ethertype, frame[off:]


def strip_ip(ethertype: int, payload: bytes):
    """Returns (ip_proto, ip_payload) or None -- the IP header stripped, whatever protocol
    number follows (not just TCP/UDP)."""
    if ethertype == 0x0800:  # IPv4
        if len(payload) < 20:
            return None
        ver_ihl = payload[0]
        ihl = (ver_ihl & 0x0F) * 4
        if ihl < 20 or len(payload) < ihl:
            return None
        return payload[9], payload[ihl:]
    elif ethertype == 0x86DD:  # IPv6 (no extension header walk -- fixtures here don't use them)
        if len(payload) < 40:
            return None
        return payload[6], payload[40:]
    return None


def strip_ip_and_l4(ethertype: int, payload: bytes):
    """Returns (l4_proto, src_port_or_None, dst_port_or_None, l4_payload) or None."""
    stripped = strip_ip(ethertype, payload)
    if stripped is None:
        return None
    proto, l4 = stripped

    if proto == 6:  # TCP
        if len(l4) < 20:
            return None
        src_port, dst_port = struct.unpack(">HH", l4[0:4])
        data_offset = ((l4[12] >> 4) & 0x0F) * 4
        if data_offset < 20 or len(l4) < data_offset:
            return None
        return "tcp", src_port, dst_port, l4[data_offset:]
    elif proto == 17:  # UDP
        if len(l4) < 8:
            return None
        src_port, dst_port = struct.unpack(">HH", l4[0:4])
        return "udp", src_port, dst_port, l4[8:]
    return None


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("pcap", help="source tests/sample_*.pcap(ng) fixture")
    ap.add_argument("out_dir", help="destination fuzz/corpus/<name>/ directory (created if missing)")
    ap.add_argument("--layer", choices=["l4", "l3", "l2", "raw"], default="l4")
    ap.add_argument("--l4-proto", choices=["tcp", "udp"], default=None,
                     help="l4 layer only: keep just this transport")
    ap.add_argument("--port", type=int, action="append", default=None,
                     help="l4 layer only: keep only payloads where this port is src or dst "
                          "(repeatable)")
    ap.add_argument("--ip-proto", type=lambda s: int(s, 0), default=None,
                     help="l3 layer only: keep only this IP protocol number (e.g. 58 for "
                          "ICMPv6, 112 for VRRP)")
    ap.add_argument("--ethertype", type=lambda s: int(s, 0), default=None,
                     help="l2 layer only: keep only frames with this EtherType (e.g. 0x88b8)")
    ap.add_argument("--min-len", type=int, default=1)
    ap.add_argument("--max-seeds", type=int, default=200,
                     help="cap on distinct seed files written (extras are skipped, not truncated)")
    args = ap.parse_args()

    frames = load_frames(args.pcap)
    seen = set()
    kept = []

    for frame in frames:
        if args.layer == "raw":
            payload = frame
        else:
            eth = strip_ethernet(frame)
            if eth is None:
                continue
            ethertype, l2_payload = eth
            if args.layer == "l2":
                if args.ethertype is not None and ethertype != args.ethertype:
                    continue
                payload = l2_payload
            elif args.layer == "l3":
                res3 = strip_ip(ethertype, l2_payload)
                if res3 is None:
                    continue
                ip_proto, ip_payload = res3
                if args.ip_proto is not None and ip_proto != args.ip_proto:
                    continue
                payload = ip_payload
            else:  # l4
                res = strip_ip_and_l4(ethertype, l2_payload)
                if res is None:
                    continue
                proto, sport, dport, l4_payload = res
                if args.l4_proto is not None and proto != args.l4_proto:
                    continue
                if args.port is not None and sport not in args.port and dport not in args.port:
                    continue
                payload = l4_payload

        if len(payload) < args.min_len:
            continue
        if payload in seen:
            continue
        seen.add(payload)
        kept.append(payload)
        if len(kept) >= args.max_seeds:
            break

    os.makedirs(args.out_dir, exist_ok=True)
    for i, payload in enumerate(kept, start=1):
        with open(os.path.join(args.out_dir, f"seed_{i:04d}.bin"), "wb") as f:
            f.write(payload)

    print(f"{args.pcap}: {len(frames)} frame(s) read, {len(kept)} distinct seed(s) written to {args.out_dir}")
    if not kept:
        print("WARNING: zero seeds written -- check --layer/--l4-proto/--port/--ethertype filters", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()
