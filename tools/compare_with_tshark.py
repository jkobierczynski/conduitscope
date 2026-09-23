#!/usr/bin/env python3
"""compare_with_tshark.py -- coarse-grained tshark-vs-conduitscope decode comparison.

Jurgen asked whether conduitscope's own decoding could be checked for errors by
automating a comparison against tshark, the same way he'd already done informally
in another session. This is a v1 methodology, not an exhaustive field-by-field
diff: conduitscope decodes roughly 90 protocols, the large majority of them
proprietary OT/ICS protocols tshark has no dissector for at all (TwinCAT/ADS,
MELSEC, FINS, HART-IP, FOUNDATION Fieldbus HSE, DeviceNet's own CIP framing,
and more), so a byte-for-byte or field-for-field comparison isn't meaningful
across most of this tool's own scope. What tshark's own dissectors DO cover
overlaps conduitscope on maybe a third of its protocol list (Modbus/TCP, DNP3,
S7comm, BACnet, ARP, LLDP, STP, BGP, MQTT, OPC UA, GOOSE/Sampled Values,
EtherCAT, Kerberos, LDAP, SMB, DNS) -- for those, this script compares:

  1. Total packet count per capture (both tools should always agree; a
     mismatch means one tool is silently dropping or duplicating packets).
  2. Per-packet leaf-protocol agreement, via tshark's `frame.protocols` field
     (the full dissector chain, e.g. `eth:ethertype:ip:tcp:mbtcp:modbus`)
     mapped through a small, explicit translation table onto conduitscope's
     own `protocol` field. Only pairs where BOTH tools recognize the packet
     as one of these mutually-known protocols are compared; everything else
     (a proprietary OT protocol tshark has no dissector for, or a tshark
     dissector -- e.g. TLS, HTTP -- conduitscope doesn't try to decode) is
     counted separately and never treated as a mismatch.

A mismatch here means: both tools have a real dissector for this protocol,
and they disagree about which packets belong to it. That is either a real
conduitscope bug (wrong port-based/structural classification) or, for this
project's own deliberately-synthetic malformed/negative-control fixtures, an
intentional divergence (a fixture built to probe conduitscope's OWN fallback
behavior on bytes tshark's dissector doesn't reject the same way). Every
mismatch is printed for a human to look at; this script does not attempt to
auto-classify "real bug" vs "expected fixture divergence" -- see the printed
report's own per-file breakdown and packet numbers for that triage.

Usage:
    tools/compare_with_tshark.py [--conduitscope PATH] [--tshark PATH]
                                  [PCAP_OR_DIR ...]

With no positional arguments, scans tests/*.pcap and tests/real_captures/**/*.pcap
(this project's own fixture corpus). Requires tshark (this sandbox has 4.2.2 at
/usr/bin/tshark) and a built `conduitscope` binary (default: build/conduitscope,
relative to the repo root this script lives under).
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# --- tshark leaf-protocol -> conduitscope `protocol` field translation -----
#
# Keyed by the LAST colon-separated token of tshark's own `frame.protocols`
# field for a packet. Value is the set of conduitscope `protocol` values that
# count as agreement. Built by direct inspection (`tshark -r <fixture> -T
# fields -e frame.protocols`) against this project's own sample_*.pcap
# fixtures for every protocol both tools claim to support -- not guessed.
LEAF_MAP: dict[str, set[str]] = {
    "modbus": {"modbus"},
    "dnp3": {"dnp3"},
    "s7comm": {"s7comm"},
    "s7comm-plus": {"s7comm-plus"},
    "bacapp": {"bacnet"},
    "bvlc": {"bacnet"},  # BVLC-only frames (no APDU) still surface as bacnet here
    "arp": {"arp"},
    "lldp": {"lldp"},
    "stp": {"stp"},
    "bgp": {"bgp"},
    "mqtt": {"mqtt"},
    "opcua": {"opcua"},
    "goose": {"goose"},
    "sv": {"sv"},
    "ecatf": {"ethercat"},
    "ecat": {"ethercat"},
    "kerberos": {"kerberos"},
    "ldap": {"ldap"},
    "smb2": {"smb"},
    "smb": {"smb"},
    "dns": {"dns", "mdns", "llmnr", "nbns", "doh"},
    "mdns": {"mdns", "dns"},
    "nbns": {"nbns"},
    "llmnr": {"llmnr"},
    "cip": {"enip"},
    "enip": {"enip"},
    "pn_dcp": {"profinet"},
    "pn-rt": {"profinet"},
    "igmp": {"igmp"},
    "vrrp": {"vrrp"},
    "eigrp": {"eigrp"},
    "ospf": {"ospf"},
    "rip": {"rip"},
    "pim": {"pim"},
    "icmp": {"icmp"},
    "hsrp": {"hsrp"},
    "eapol": {"eapol"},
    "pppoed": {"pppoe"},
    "pppoes": {"pppoe"},
    "mpls": {"mpls"},
    "lacp": {"slow-protocols"},
    "oam": {"slow-protocols"},
    "quic": {"quic"},
    "tacacs": {"enterprise-trust"},
    "ntlmssp": {"smb", "netlogon"},
    "dcerpc": {"smb", "netlogon"},
}

# tshark leaf tokens that are generic transport/wrapper layers, never a
# meaningful comparison target on their own -- a packet ending here just
# means tshark's own dissector chain stopped one layer short of anything
# conduitscope might also recognize (very common: half of every conversation
# this project's fixtures build is a bare TCP ACK/window-update with no
# upper-layer payload of its own).
GENERIC_LEAVES = {"tcp", "udp", "ip", "data", "eth", "ethertype", "vlan", "ipv6"}


def run(cmd: list[str]) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if result.returncode not in (0, None) and not result.stdout:
        raise RuntimeError(f"command failed: {' '.join(cmd)}\n{result.stderr}")
    return result.stdout


def tshark_leaf_protocols(tshark: str, pcap: Path) -> dict[int, str]:
    out = run([tshark, "-r", str(pcap), "-T", "fields", "-e", "frame.number", "-e", "frame.protocols"])
    result: dict[int, str] = {}
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 2 or not parts[0]:
            continue
        frame_no = int(parts[0])
        chain = parts[1].split(":")
        leaf = chain[-1] if chain else ""
        result[frame_no] = leaf
    return result


def conduitscope_protocols(conduitscope: str, pcap: Path) -> dict[int, str]:
    out = run([conduitscope, "decode", "-r", str(pcap), "--format", "json"])
    try:
        packets = json.loads(out)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"conduitscope produced non-JSON output for {pcap}: {exc}") from exc
    return {p["index"]: p.get("protocol", "") for p in packets}


def compare_file(conduitscope: str, tshark: str, pcap: Path) -> dict:
    ts = tshark_leaf_protocols(tshark, pcap)
    cs = conduitscope_protocols(conduitscope, pcap)

    count_ts = len(ts)
    count_cs = len(cs)

    agree = 0
    disagree: list[tuple[int, str, str]] = []
    tshark_blind = 0  # conduitscope recognized something tshark's leaf token has no mapping for
    conduitscope_blind = 0  # tshark recognized something conduitscope's protocol has no mapping for
    generic_both = 0

    all_frames = sorted(set(ts) | set(cs))
    for frame in all_frames:
        leaf = ts.get(frame, "")
        proto = cs.get(frame, "")
        if leaf in GENERIC_LEAVES:
            generic_both += 1
            continue
        mapped = LEAF_MAP.get(leaf)
        if mapped is None:
            tshark_blind += 1
            continue
        if proto in mapped:
            agree += 1
        elif proto in GENERIC_LEAVES or proto in ("", "unsupported-link", "non-ip", "non-tcp"):
            conduitscope_blind += 1
        else:
            disagree.append((frame, leaf, proto))

    return {
        "pcap": str(pcap.relative_to(REPO_ROOT)),
        "count_tshark": count_ts,
        "count_conduitscope": count_cs,
        "count_mismatch": count_ts != count_cs,
        "agree": agree,
        "disagree": disagree,
        "generic_both": generic_both,
        "tshark_blind": tshark_blind,
        "conduitscope_blind": conduitscope_blind,
    }


def discover_pcaps(paths: list[str]) -> list[Path]:
    if not paths:
        paths = ["tests"]
    found: list[Path] = []
    for p in paths:
        path = Path(p)
        if not path.is_absolute():
            path = REPO_ROOT / p
        if path.is_dir():
            found.extend(sorted(path.rglob("*.pcap")))
        elif path.is_file():
            found.append(path)
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("paths", nargs="*", help="pcap file(s) or directory/directories to scan (default: tests/)")
    parser.add_argument("--conduitscope", default=str(REPO_ROOT / "build" / "conduitscope"))
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--quiet-ok", action="store_true", help="only print files with count mismatches or disagreements")
    args = parser.parse_args()

    pcaps = discover_pcaps(args.paths)
    if not pcaps:
        print("no .pcap files found", file=sys.stderr)
        return 1

    total_agree = total_disagree = total_generic = total_ts_blind = total_cs_blind = 0
    count_mismatches: list[tuple[str, int, int]] = []
    all_disagreements: list[tuple[str, int, str, str]] = []
    errors: list[tuple[str, str]] = []

    for pcap in pcaps:
        try:
            r = compare_file(args.conduitscope, args.tshark, pcap)
        except Exception as exc:  # noqa: BLE001 -- report and keep going
            errors.append((str(pcap.relative_to(REPO_ROOT)), str(exc)))
            continue

        total_agree += r["agree"]
        total_disagree += len(r["disagree"])
        total_generic += r["generic_both"]
        total_ts_blind += r["tshark_blind"]
        total_cs_blind += r["conduitscope_blind"]

        if r["count_mismatch"]:
            count_mismatches.append((r["pcap"], r["count_tshark"], r["count_conduitscope"]))
        for frame, leaf, proto in r["disagree"]:
            all_disagreements.append((r["pcap"], frame, leaf, proto))

        if not args.quiet_ok or r["count_mismatch"] or r["disagree"]:
            flag = " <-- LOOK" if (r["count_mismatch"] or r["disagree"]) else ""
            print(f"{r['pcap']:65s} ts={r['count_tshark']:4d} cs={r['count_conduitscope']:4d} "
                  f"agree={r['agree']:4d} disagree={len(r['disagree']):3d} "
                  f"generic={r['generic_both']:4d} ts-blind={r['tshark_blind']:4d} "
                  f"cs-blind={r['conduitscope_blind']:4d}{flag}")

    print()
    print("=" * 78)
    print(f"Scanned {len(pcaps)} pcap file(s); {len(errors)} error(s) running one of the tools")
    print(f"Leaf-protocol agreement across mutually-known protocols: {total_agree} agree, "
          f"{total_disagree} disagree")
    print(f"Generic/wrapper-only frames (no comparison possible): {total_generic}")
    print(f"tshark recognized a protocol conduitscope has no translation entry for: {total_ts_blind}")
    print(f"tshark recognized a protocol conduitscope reported as unsupported/generic/blank: {total_cs_blind}")

    if count_mismatches:
        print()
        print(f"PACKET COUNT MISMATCHES ({len(count_mismatches)}) -- one tool saw a different "
              f"number of frames than the other:")
        for pcap, ts_count, cs_count in count_mismatches:
            print(f"  {pcap}: tshark={ts_count} conduitscope={cs_count}")

    if all_disagreements:
        print()
        print(f"PROTOCOL DISAGREEMENTS ({len(all_disagreements)}) -- both tools recognize this "
              f"protocol family but classified the same frame differently:")
        for pcap, frame, leaf, proto in all_disagreements:
            print(f"  {pcap} frame #{frame}: tshark says '{leaf}', conduitscope says '{proto}'")

    if errors:
        print()
        print(f"ERRORS ({len(errors)}):")
        for pcap, msg in errors:
            print(f"  {pcap}: {msg}")

    return 1 if (count_mismatches or all_disagreements or errors) else 0


if __name__ == "__main__":
    raise SystemExit(main())
