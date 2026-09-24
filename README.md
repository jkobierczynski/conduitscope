# conduitscope

<p align="center">
  <img src="assets/logo.jpg" alt="conduitscope logo: an amber warning-sign triangle with a shark whose eyes fire laser beams" width="220">
</p>

## What this is for

`conduitscope` is an OT/ICS conduit-auditing tool built around offline pcap/pcapng
captures (live capture is available too, see below, but offline is the primary,
always-available path in). It does three things:

- **`decode` / `info`** -- reliable, honestly-labeled protocol decoding (real
  wire-format fields, not just protocol names) and a stats view, across
  dozens of ICS/OT protocols plus everything needed to notice when
  non-OT/IT/enterprise traffic shows up where it shouldn't.
- **`policy validate`** -- maps decoded traffic against an IEC 62443-style
  zone/conduit segmentation model (for NIS2-flavored compliance work). You
  write a policy file naming your zones (IP/CIDR or VLAN ranges) and the
  conduits allowed between them, and get back a compliant/non-compliant
  report naming every flow that wasn't explicitly permitted.
- **`inventory`** -- runs the opposite direction: point it at a capture with
  no policy file at all, and it infers a first-draft zone/conduit model from
  what it actually sees (Modbus, DNP3, S7comm, EtherNet/IP, and BACnet/IP
  talkers) -- an asset list, a communication matrix, a Mermaid/Graphviz
  diagram, and a `policy`-format YAML file directly loadable by
  `policy validate`, closing the loop from passive discovery to active
  enforcement.

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md)'s POLICY FILE FORMAT section for
the schema and its `inventory` subsection for a worked example.

Offline capture files are the primary, always-available way in: no libpcap on
Linux, no Npcap SDK on Windows, no elevated privileges needed to build or run
-- just a C++17 compiler and CMake. Capture traffic with whatever's already on
your system (`tcpdump -w capture.pcap ...`, Wireshark/`dumpcap`'s default
pcapng output), then decode it here -- both classic pcap and pcapng are read
transparently, auto-detected from the file itself.

Live capture (`-i/--interface`) is also available, as the one deliberate
exception to that zero-dependency design: it's an *optional*, build-time-detected
dependency on libpcap (Linux) / the Npcap SDK (Windows) -- if CMake finds it, `-i`
and `conduitscope interfaces` work; if it doesn't, the build is exactly as
dependency-free as before, and those two just report that clearly at runtime
instead of not existing. See [docs/USER_GUIDE.md](docs/USER_GUIDE.md)'s LIVE CAPTURE
section.

## Why not just use tshark?

Fair question -- tshark wins on raw protocol-decoding breadth (thousands of
dissectors vs. conduitscope's several dozen) and is usually still the
better first reach for general packet analysis. conduitscope isn't trying to
replace it; it does one thing tshark fundamentally doesn't:

- **Turns a capture into a compliance verdict.** `policy validate` takes a
  capture and a written zone/conduit policy file (the kind of artifact an
  IEC 62443-3-2 or NIS2 risk assessment actually asks for) and reports which
  flows were explicitly permitted and which weren't. tshark has no concept
  of zones, conduits, or a pass/fail audit report -- you'd be doing that
  comparison by hand.
- **Labels every heuristic as a heuristic.** Where a general-purpose
  dissector will confidently render a field on shaky evidence, conduitscope
  is built around "decode confidently only where the wire format is
  unambiguous": anything inferred rather than authoritatively known (Modbus
  request/response classification, EtherNet/IP tag-read disambiguation,
  S7comm's experimental symbolic addressing) is explicitly noted as such in
  the output, not silently presented as fact -- important when the output
  might get cited in an audit report.
- **Small enough to actually read.** A few tens of thousands of lines of
  C++17, zero required dependencies for offline analysis (no libpcap needed
  unless you want live capture -- see below). You can read every decoder end
  to end and know exactly what it does and doesn't claim, which matters more
  than usual when pointing a tool at security-sensitive OT captures --
  Wireshark/tshark's dissector surface is enormous and has a long CVE
  history.
- **JSON output shaped for the audit pipeline**, not just for rendering in a
  GUI: authoritative Modbus request/response pairing, EtherNet/IP CIP I/O
  connection tracking, IEC 104 cause-of-transmission, and so on, designed to
  be piped into `jq` or a policy-checking layer.
- **Passive asset discovery, not just enforcement.** `inventory` runs the
  opposite direction from `policy validate`: point it at a capture with no
  policy file at all, and it infers a first-draft zone/conduit model --
  NSA's GRASSMARLIN used to fill this niche but is abandoned, and CISA's
  Malcolm covers similar ground but is a heavy multi-container Zeek/
  OpenSearch/Elastic stack, not a single binary. `inventory` is the
  lightweight, `tshark`-adjacent alternative: pcap in, zone/conduit model
  out, in the same restricted policy-YAML shape `policy validate` already
  understands -- so the model it discovers can be fed straight back in to
  start enforcing it.

In short: tshark for exploring an unfamiliar capture or decoding something
obscure; conduitscope for the specific, repeatable "does this OT network's
traffic match what the segmentation policy says it should" question.

## Supported ICS/OT protocols

Every protocol below has real wire-format fields decoded, not just its name
recognized -- see [docs/PROTOCOL_COVERAGE.md](docs/PROTOCOL_COVERAGE.md) for
exactly what each one surfaces, its structural detection gate, and its
real-capture validation provenance.

| Protocol | Domain | Transport | What's decoded |
|---|---|---|---|
| Modbus/TCP | Supervisory/PLC | TCP 502 | Read/write coil & register requests/responses, authoritative transaction pairing, exception codes |
| DNP3 | Supervisory/RTU | TCP/UDP 20000 | Application-layer objects/variations, fragment reassembly, unsolicited responses |
| IEC 60870-5-104 | Supervisory/SCADA | TCP 2404 | ASDUs, cause of transmission, information objects |
| S7comm / COTP | Siemens PLC | TCP 102 | Read/write var, block up/downloads (TPKT/COTP transport) |
| S7comm-Plus | Siemens PLC (TIA Portal, S7-1200/1500) | TCP 102 | Newer Siemens protocol, shares TPKT/COTP transport with S7comm |
| IEC 61850 MMS | Substation automation | TCP 102 | Manufacturing Message Specification (ISO 9506); ICCP/TASE.2 also recognized |
| EtherNet/IP | Rockwell/ODVA CIP | TCP 44818 (explicit), UDP 2222 (I/O) | CIP explicit messaging + CIP I/O implicit messaging |
| PROFINET RT | Siemens/PI fieldbus | EtherType `0x8892` | DCP device discovery/configuration + cyclic real-time I/O |
| IEC 61850-8-1 GOOSE | Substation automation | EtherType `0x88B8` | Generic Object Oriented Substation Event PDUs |
| IEC 61850-9-2 Sampled Values | Substation automation | EtherType `0x88BA` | Sampled measurement values |
| EtherCAT | Industrial fieldbus | EtherType `0x88A4` | Frame header + datagram fields |
| BACnet/IP | Building automation | UDP 47808 (`0xBAC0`) | ASHRAE 135 Annex J -- BVLC/NPDU/APDU, service value decode |
| HART-IP | Process instrumentation | UDP/TCP 5094 | IEC 62591/HCF_SPEC-151, Pass-Through classic HART commands |
| OPC UA Binary | Manufacturing interop | TCP 4840 | UA-TCP transport / OPC UA Secure Conversation |
| FOUNDATION Fieldbus HSE | Process instrumentation | TCP+UDP 1089-1091, 3622 | FDA/SM/FMS/LAN Redundancy |
| MQTT + Sparkplug B | IIoT | TCP 1883 (conventional) | v3.1/v3.1.1/v5.0, plus Sparkplug B (hand-rolled Protobuf reader) |
| DeviceNet | CAN-bus fieldbus | SocketCAN pcap captures | CIP over CAN, message-group classification |
| TwinCAT/ADS | Beckhoff automation | TCP 48898 (`0xBF02`) | AMS/TCP |
| MELSEC / MC Protocol (SLMP) | Mitsubishi Electric PLC | TCP 5001, UDP 5000 | 13 commands, byte-for-byte verified |
| FINS | Omron PLC | TCP/UDP 9600 | 17 commands |
| GE SRTP | GE Fanuc/GE Intelligent Platforms PLC | TCP 18245 | 90-30/90-70/RX3i/RX7i programming/monitoring/control |
| BSAP | Bristol Babcock/Emerson RTU | UDP 1234 | Link-layer framing/addressing, serial-tunneled and BSAP-IP-native |
| CC-Link IE Field Network Basic (CCIEFB) | Mitsubishi Electric fieldbus | UDP 61450/61451 | Cyclic I/O, SLMP node search, SLMP Set IP Address |
| CODESYS V3 | 3S-Smart/CODESYS PLC runtime | TCP 11740/1217, UDP 1740-1743 | Block Driver/Datagram/Channel/Services, Login/AUTH (password never rendered) |
| CoAP | Constrained-device IIoT | UDP 5683 | RFC 7252 + Observe (RFC 7641) + blockwise transfer (RFC 7959) |
| Zigbee | Wireless mesh (building/industrial sensors) | `LINKTYPE_IEEE802_15_4_WITHFCS`/`TAP` pcap captures | IEEE 802.15.4 MAC + Zigbee NWK + APS + full ZDP |
| RMCP / ASF / IPMI | Server/BMC out-of-band management | UDP 623 | RMCP envelope, ASF Presence Ping/Pong, full IPMI 1.5/2.0 session + RAKP handshake decode, curated NetFn/Command table, Cipher Suite 0 auth-bypass detection |
| CANopen (CiA 301) | CAN-bus fieldbus | SocketCAN pcap captures | NMT, Heartbeat, SYNC/TIME STAMP, EMCY, SDO (expedited/segmented/block), PDO named by COB-ID (`--protocol canopen` only -- see docs) |
| SAE J1939 | Heavy-duty vehicle/engine CAN bus | SocketCAN pcap captures | 29-bit ID/PGN decode, EEC1/ET1/CCVS/Request full decode, DM1 active-DTC SPN/FMI/OC/CM decode |

A cross-cutting **attack-detection** layer runs over every decoded
IPv4/TCP/UDP/ICMP packet regardless of which protocol above matched: LAND,
WinNuke, ICMP Redirect, IP Source Routing (LSRR/SSRR), Smurf, Fraggle, Ping
of Death, and Teardrop as curated structural signatures, plus SYN/ACK/
ICMP/UDP flood and a generic TCP-flood catch-all against a `--flood-threshold`.
See [docs/PROTOCOL_COVERAGE.md](docs/PROTOCOL_COVERAGE.md)'s Attack Detection
section.

## Further supported protocols

conduitscope also recognizes -- and in most cases fully decodes -- protocols
outside the core ICS/OT set above, either because OT networks increasingly
touch Windows Active Directory and enterprise IT, or because an auditor
needs to know when non-OT traffic (remote access, lateral movement,
tunneling) shows up on a segment that shouldn't carry it:

- **Windows Active Directory suite** (fully decoded, most carried inside SMB2
  named-pipe I/O with no independent wire gate of their own): Kerberos
  (RFC 4120), LDAP (RFC 4511), SMB2/NTLM (MS-SMB2/MS-NLMP), Netlogon/DCE-RPC
  (MS-NRPC/MS-RPCE), SAMR (MS-SAMR), LSARPC (MS-LSAD/MS-LSAT), SRVSVC
  (MS-SRVS), WKSSVC (MS-WKST), DRSUAPI (MS-DRSR), WinRM (WS-Management,
  MS-WSMV, TCP 5985), and DCOM activation (MS-DCOM, TCP 135, structural
  recognition only). Each carries curated attack/monitoring notes (e.g.
  AS-REP-Roasting, Kerberoasting, Zerologon's wire signature, DCSync,
  anonymous/guest sessions, SMB signing-not-required).
- **Network infrastructure / routing / link layer**: Spanning Tree Protocol
  (STP/RSTP/MSTP), ARP (RFC 826, with gratuitous-ARP/ARP-Probe/
  ARP-Announcement notes), LLDP (IEEE 802.1AB), CDP (Cisco Discovery
  Protocol), BGP-4 (RFC 4271), IEEE 802.3 Slow Protocols (LACP/Marker/OAM),
  RIP, IGMP, VRRP, HSRP, IGRP, PIM, EIGRP, OSPFv2, and ICMP (RFC 792 plus
  RFC 1191/1256 extensions).
- **Name resolution**: DNS, mDNS, LLMNR, NetBIOS Name Service (NBT-NS), and
  DNS-over-HTTPS (DoH) detection via TLS SNI matching.
- **IT protocol recognition** (named only, by risk tier -- not full field
  decode, except where noted above):
  - *Remote access* -- RDP, VNC, TeamViewer, AnyDesk, Zoom
  - *Lateral movement / credential harvesting* -- SSH, HTTP, HTTPS,
    SNMPv1/v2c, Telnet, FTP, TFTP, QUIC (SMB has since been promoted to a
    full decoder, see the AD suite above)
  - *Enterprise trust boundary* -- NTP, DHCP, LDAPS, RADIUS, TACACS+, IEEE
    802.1X/EAPOL
  - *Wireless/cellular backhaul* -- CAPWAP, LWAPP, GTP-U, PPPoE
  - *Tunnel/VPN encapsulation* -- GRE (+ NVGRE/Mikrotik EoIP), IPsec ESP/AH,
    IP-in-IP, 6in4, L2TP/L2TPv3, IKE, VXLAN, Geneve, WireGuard, OpenVPN, a
    generic DTLS-tunnel structural check, STT, and MPLS

## Status

Groundwork / v0.2.4. Every protocol named above is implemented, decoding real
wire-format fields (not just naming the protocol), and covered by the
automated test suite -- 1769 tests as of this writing, run via `ctest` after
building (see Building below). Where a real capture was available (public
ICS-lab collections, vendor-attributed samples, or a live device on real
hardware), the decoder is validated against it, not just a synthetic
fixture; where it wasn't, that's stated honestly rather than implied. Every
one of those specifics -- what's decoded vs. just named, exactly how a
protocol is structurally detected and why that's collision-resistant against
its neighbors, and each decoder's real-capture validation provenance -- lives
in [docs/PROTOCOL_COVERAGE.md](docs/PROTOCOL_COVERAGE.md), not here.

The full command surface is implemented: `decode`/`info` (protocol decoding
and a stats view), `policy validate` (checks decoded traffic against a
written IEC 62443-style zone/conduit policy, IPv4-zone and VLAN-zone
conduits both), `inventory` (infers a first-draft zone/conduit model from a
capture with no policy file at all, including a Mermaid/Graphviz diagram
and a policy file directly loadable by `policy validate` -- closing the
loop from passive discovery to active enforcement), plus `interfaces` and
`version`, with full `--help` at every level. See
[docs/USER_GUIDE.md](docs/USER_GUIDE.md) for command syntax, the policy
file schema, output formats, exit codes, current limitations, and worked
examples of every command.

Live capture (`-i/--interface`) works on both Linux (libpcap) and Windows
(Npcap) -- an optional, build-time-detected dependency, validated
end-to-end against real traffic on both platforms, including a real
MSVC/Visual Studio build with `interfaces` correctly enumerating real
adapters. `--duration`, `--filter` (BPF, also usable against a saved
capture with `-r`), `--snaplen`, and Ctrl+C all stop a capture cleanly. See
[docs/USER_GUIDE.md](docs/USER_GUIDE.md)'s LIVE CAPTURE section, and Building
below for the one-time setup (`setcap`) that lets live capture run without
root/Administrator on Linux.

For the full development history -- every bug found and fixed along the way,
every protocol-detection collision considered and resolved, and what's
planned next -- see [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)'s ROADMAP.

## Documentation

- **[docs/USER_GUIDE.md](docs/USER_GUIDE.md)** -- start here to run the
  tool: command syntax and options, live capture, the policy file format,
  output formats, limitations, exit status, and worked examples.
- **[docs/PROTOCOL_COVERAGE.md](docs/PROTOCOL_COVERAGE.md)** -- the full
  per-protocol reference: what's recognized on the wire, exactly what each
  decoder surfaces, and how much confidence to place in each detection.
  Read this before citing a `decode` finding in an audit report.
- **[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md)** -- for anyone extending the
  codebase: an architecture snapshot, the external code review that shaped
  current engineering priorities, protocol-detection dispatch order and
  collision handling, and the development roadmap.
- **[man/conduitscope.1](man/conduitscope.1)** -- the man page, built from
  the same material as USER_GUIDE.md.
- **[docs/MANUAL.md](docs/MANUAL.md)** -- a short index page pointing at the
  three docs above (kept in place because compiled-in `--help` text and
  error messages in the binary itself reference it by path).

## Building

Requires a C++17 compiler and CMake >= 3.16. No other dependencies are *required*
-- CLI11 is vendored as a single header under `third_party/`
(see `third_party/CLI11/README.md` for its version, upstream source, license,
and update procedure). If `libpcap-dev`
(Linux) or the Npcap SDK (Windows) happens to be installed and discoverable,
CMake picks it up automatically and live capture (`-i/--interface`) is built in;
if not, the build is unaffected except that `-i` reports it isn't available. Pass
`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` to skip that search entirely and
guarantee a dependency-free build regardless of what's installed. See
docs/USER_GUIDE.md's LIVE CAPTURE section for the runtime-vs-build-time distinction
on Windows (the Npcap *SDK* is build-time only; running a live capture also needs
the separate Npcap *driver/service* installed).

### Linux

```sh
sudo apt install libpcap-dev   # optional, only needed for live capture (-i)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
sudo apt install -y libcap2-bin
sudo setcap cap_net_raw,cap_net_admin=eip build/conduitscope   # optional, see below
ctest --test-dir build --output-on-failure   # optional, runs the fixture-based smoke tests
```

The binary is `build/conduitscope`.

Opening a live capture (`-i`, even against loopback) needs `CAP_NET_RAW`, which
an ordinary user doesn't have -- without the `setcap` step above, `-i` and the
`live_capture_*` CTest tests that exercise it need `sudo`/root. `setcap` grants
that capability to the binary itself, once, as a one-time root/sudo step; every
run after that -- including `ctest` and everyone else who runs this same
binary -- works without root. This is the same fix
[.github/workflows/ci.yml](.github/workflows/ci.yml) already applies before
running its own test suite. (The tests that don't touch a live interface --
argument validation, `--help`, etc. -- always pass without this, root or not.)

### Windows

Either Visual Studio 2022 (MSVC) or MinGW-w64 work, via the same CMake project.
For live capture (`-i`), install the [Npcap SDK](https://npcap.com/#download) and
either set it as the `NPCAP_SDK_DIR` environment variable or pass
`-DNPCAP_SDK_DIR=<path>` to CMake; skip this entirely for a build without live
capture.

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Release
```

or, from an MSYS2/MinGW shell:

```sh
cmake -S . -B build -G "MinGW Makefiles" -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
```

The binary is `build\Release\conduitscope.exe` (MSVC) or `build\conduitscope.exe`
(MinGW). Running a live capture (not just building with support for one) also
needs the [Npcap runtime](https://npcap.com/#download) installed on the machine
that runs it -- the SDK used at build time only supplies headers/import libraries.

## Quick start

```sh
# Generate synthetic Modbus/TCP, DNP3, IEC 104, S7comm/COTP, EtherNet/IP, PROFINET RT,
# GOOSE, Sampled Values, EtherCAT, BACnet/IP, HART-IP, OPC UA, and IEC 61850 MMS captures and
# decode them (no live traffic needed):
python3 tools/make_sample_pcap.py
build/conduitscope decode -r tests/sample_modbus.pcap
build/conduitscope decode -r tests/sample_s7comm.pcap --stats
build/conduitscope decode -r tests/sample_iec104.pcap
build/conduitscope decode -r tests/sample_enip.pcap
build/conduitscope decode -r tests/sample_enip_cip_io.pcap
build/conduitscope decode -r tests/sample_goose.pcap
build/conduitscope decode -r tests/sample_sv.pcap
build/conduitscope decode -r tests/sample_ethercat.pcap
build/conduitscope decode -r tests/sample_bacnet.pcap
build/conduitscope decode -r tests/sample_hartip.pcap
build/conduitscope decode -r tests/sample_opcua.pcap
build/conduitscope decode -r tests/sample_mms.pcap --stats
build/conduitscope decode -r tests/sample_melsec.pcap --stats
build/conduitscope decode -r tests/sample_fins.pcap --stats
build/conduitscope decode -r tests/sample_modbus.pcap --format json
build/conduitscope info -r tests/sample_modbus.pcap

# Check a capture against a zone/conduit policy (see tests/policies/*.yaml for more examples,
# and docs/USER_GUIDE.md's POLICY FILE FORMAT section for the schema):
build/conduitscope policy validate -r tests/sample_modbus.pcap --policy tests/policies/compliant.yaml

# Same, but for a VLAN-membership zone/conduit policy covering PROFINET RT/GOOSE/SV/EtherCAT:
build/conduitscope policy validate -r tests/sample_vlan_zones.pcap --policy tests/policies/vlan_zone_mixed_results.yaml

# Infer a first-draft zone/conduit model from a capture -- no policy file needed -- then feed
# the generated policy straight back into `policy validate`: discover, then enforce.
build/conduitscope inventory -r tests/sample_inventory.pcap --diagram zones.mmd --policy-out inferred.yaml
build/conduitscope policy validate -r tests/sample_inventory.pcap --policy inferred.yaml
```

To decode traffic you've actually captured, e.g. from a Modbus simulator such as
`pymodbus`, or from a public sample set like the
[4SICS ICS pcaps](https://www.netresec.com/?page=PCAP4SICS):

```sh
tcpdump -i <iface> -w capture.pcap port 502 or port 20000 or port 2404 or port 102 or port 44818 or port 2222 or port 47808 or port 5094 or port 4840
build/conduitscope decode -r capture.pcap
```

Or, if this build has live-capture support (see Building above), skip the
intermediate file and check traffic in real time:

```sh
build/conduitscope interfaces                                    # list capturable interfaces
build/conduitscope decode -i eth0 --filter "port 502 or port 2404 or port 102 or port 44818 or port 2222 or port 47808 or port 5094 or port 4840" --duration 60
build/conduitscope policy validate -i eth0 --policy tests/policies/compliant.yaml --duration 60
# or just Ctrl+C to stop either one early -- both still print whatever was captured so far
```

## License

Apache License 2.0 -- see [LICENSE](LICENSE).
