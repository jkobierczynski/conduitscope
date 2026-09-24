# conduitscope

<p align="center">
  <img src="assets/logo.jpg" alt="conduitscope logo: an amber warning-sign triangle with a shark whose eyes fire laser beams" width="220">
</p>

`conduitscope` decodes Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP (Siemens S7 PLC
protocol) and S7comm-Plus (Siemens TIA Portal / S7-1200/1500's newer protocol),
EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP device
discovery/configuration and cyclic real-time I/O data), IEC 61850-8-1 GOOSE,
IEC 61850-9-2 Sampled Values, EtherCAT, BACnet/IP, HART-IP, OPC UA Binary
(UA-TCP/Secure Conversation), IEC 61850 MMS (Manufacturing Message Specification,
ISO 9506), MQTT (v3.1/v3.1.1/v5.0, including Sparkplug B), FOUNDATION
Fieldbus HSE (FDA/SM/FMS/LAN Redundancy), Beckhoff TwinCAT/ADS (over
AMS/TCP), MELSEC Communication Protocol (MC Protocol / SLMP, Mitsubishi
Electric, TCP port 5001 and UDP port 5000, with curated
unauthenticated-CPU-control, cleartext-password-field, and
arbitrary-memory-access attack/monitoring notes -- the cleartext Remote
Password field's own value is never rendered, only its length),
FINS (Factory Interface Network Service, Omron, TCP port 9600 and
UDP port 9600, with curated unauthenticated-CPU-control,
arbitrary-memory-access, credential-free access-right-seizure, and
forced-I/O-override attack/monitoring notes),
Kerberos (RFC 4120, with curated AS-REP-Roasting and
Kerberoasting attack/monitoring notes -- the first of a planned Windows
Active Directory protocol suite), LDAP (RFC 4511, with curated
anonymous-bind, cleartext-credential, AD-reconnaissance,
AS-REP-Roasting-target-discovery, and delegation-discovery
attack/monitoring notes -- the second protocol of that same suite), SMB2/NTLM
(MS-SMB2/MS-NLMP, with curated SMB1-present, signing-not-required,
NTLM-in-use, anonymous-or-guest-session, administrative-share-access, and
repeated-logon-failure attack/monitoring notes -- the third protocol of
that same suite), Netlogon/DCE-RPC (MS-NRPC/MS-RPCE, carried inside SMB2
named-pipe I/O with no independent wire gate or CLI flag of its own, with
curated secure-channel-established, all-zero-challenge-or-credential (the
CVE-2020-1472 "Zerologon" wire signature), legacy-authentication-method,
machine-account-naming-mismatch, and password-reset attack/monitoring
notes -- the fourth protocol of that same suite), SAMR + LSARPC
(MS-SAMR, MS-LSAD/MS-LSAT, likewise carried inside SMB2 named-pipe I/O
with no independent wire gate or CLI flag of their own, with curated
account/group-enumeration, SID/name-translation-or-enumeration,
cross-interface, and null/guest-session-escalation attack/monitoring
notes), SRVSVC + WKSSVC (MS-SRVS, MS-WKST, likewise carried inside SMB2
named-pipe I/O with no independent wire gate or CLI flag of their own,
with level-1-scoped share-enumeration/workstation-identity/logged-on-user
decode and curated share-added/deleted and domain-join/unjoin
attack/monitoring notes), DRSUAPI (MS-DRSR, likewise carried inside SMB2
named-pipe I/O with no independent wire gate or CLI flag of its own, with
a curated DRSGetNCChanges/DCSync-signature attack/monitoring note that
still fires under RPC-layer sealing -- **note:** real-world DRSUAPI
traffic, including DCSync, predominantly rides a dynamically negotiated
raw TCP connection via the RPC endpoint mapper rather than a named pipe,
which this decoder does not follow; see `docs/PROTOCOL_COVERAGE.md`'s
DRSUAPI section for the full scope caveat before relying on this for
DCSync detection), WinRM (WS-Management, MS-WSMV, TCP port 5985
plaintext only -- a self-contained HTTP/1.1 + SOAP 1.2 decoder with no
DCE/RPC involvement at all, decoding a shell session's own
Create/Command/Send/Receive/Signal/Delete exchanges with curated
remote-shell-opened, command-executed (redacted by default,
`--no-redact` opt-in), CIM/WMI-query-over-WinRM, PowerShell-Remoting-
endpoint, HTTP-Basic-auth-over-plaintext, and SOAP-Fault
attack/monitoring notes -- **note:** the command line is plain XML text,
not base64+UTF-16LE, an empirically-corrected finding documented in
`docs/PROTOCOL_COVERAGE.md`'s WinRM section), DCOM activation (MS-DCOM,
raw DCE/RPC directly over TCP port 135, not SMB-wrapped -- structural
activation/OXID-resolution recognition only: `IObjectExporter`/
`IRemoteSCMActivator`/`IActivation` named by interface and opnum, no
request/response body field decoded, with a curated DCOM-activation note
and an explicit `ResolveOxid`/`ResolveOxid2` scope-boundary note stating
the dynamically negotiated data-channel port those calls resolve is not
followed -- **note:** the plan's own recollected `IObjectExporter`
interface UUID was wrong; see `docs/PROTOCOL_COVERAGE.md`'s DCOM section
for the empirically-corrected value and the full scope writeup),
GE SRTP (Service Request Transport Protocol, GE Fanuc/GE Intelligent
Platforms, TCP port 18245 -- programming/monitoring/control for the
90-30/90-70/RX3i/RX7i PLC families, with authoritative session-scoped
request/response pairing by GE SRTP's own wire-carried Sequence Number
and curated unauthenticated-memory-read/write, unauthenticated-
controller-recon, program-store/load, and run/stop-control
attack/monitoring notes sourced from the DFRWS 2017 forensics paper's own
field-deployment findings -- **note:** two real protocol-collision bugs
against the existing TPKT/COTP decoder were found and fixed while
building this decoder; see `docs/PROTOCOL_COVERAGE.md`'s GE SRTP section
for the writeup),
BSAP (Bristol Standard Asynchronous/Synchronous Protocol, Bristol
Babcock/Emerson Remote Automation Solutions, UDP port 1234 -- link-layer
framing/addressing decoded for both the serial-tunneled and BSAP-IP-native
transports, deliberately structural-only by Jurgen's own explicit choice
after a confirmed sourcing gap left no numeric RDB function-code table
available anywhere, including in the reference open-source Zeek parser --
**note:** two real dispatch-ordering collision bugs against the existing
HART-IP/FF-HSE decoders were found and fixed while building this decoder;
see `docs/PROTOCOL_COVERAGE.md`'s BSAP section for the full writeup),
CC-Link IE Field Network Basic (CCIEFB, Mitsubishi Electric, UDP ports
61450/61451 -- cyclic I/O data, SLMP node search, and SLMP Set IP Address
decoded; the only CC-Link IE family member implemented, since the others
(Control/Field/TSN) require dedicated ASIC hardware with no public UDP/IP
wire documentation; rides the same SLMP 3E/4E framing as MELSEC, with a
proactively-designed collision-avoidance scheme (request-side command
gate plus session-scoped response matching) verified against a genuine
MELSEC command and an orphan response in the test fixture -- see
`docs/PROTOCOL_COVERAGE.md`'s CC-Link IE section for the full writeup),
IEEE Spanning Tree Protocol
(STP/RSTP/MSTP), DeviceNet (CAN-bus CIP, via SocketCAN pcap captures), DNS,
mDNS, LLMNR, and NetBIOS Name Service (NBT-NS), ICMP, RIP, IGMP, VRRP, HSRP,
IGRP, PIM, EIGRP, OSPFv2, ARP (RFC 826, with curated gratuitous-ARP/
ARP-Probe/ARP-Announcement notes), LLDP (IEEE 802.1AB, Link Layer
Discovery Protocol, with curated System Capabilities/Management Address
rendering and a TTL=0 "shutting down" note), BGP-4 (RFC 4271, TCP port
179, with declared-length TCP reassembly, a KEEPALIVE-coalescing loop, and
curated OPEN/UPDATE/NOTIFICATION rendering including RFC 8203 shutdown
communication text), and IEEE 802.3 Slow Protocols (LACP/Marker/OAM,
EtherType 0x8809, Subtype-multiplexed into Link Aggregation Control
Protocol with curated Out-of-Sync/Defaulted notes, the Marker Protocol,
and 802.3 OAM/EFM with a curated Dying Gasp note),
plus detects DNS-over-HTTPS
(DoH) via TLS SNI matching, and recognizes (by name only, not full decode)
RDP, VNC, TeamViewer, AnyDesk, and Zoom -- the "interactive remote control"
tier of the IT protocols an OT auditor flags -- plus SSH, HTTP, HTTPS,
SNMPv1/v2c, Telnet, FTP, and TFTP (SMB has since been promoted to a full
decoder, see above), the "lateral-movement and
credential-harvesting" tier of the same family, plus NTP, DHCP,
LDAPS, RADIUS, TACACS+, and IEEE 802.1X/EAPOL, the "does the OT side
blindly trust enterprise IT" tier of the same family, plus CAPWAP
control/data, LWAPP control/data, GTP-U, and PPPoE, the "wireless
access-point control/data planes and cellular backhaul" tier of the same
family, plus GRE (and its NVGRE/Mikrotik EoIP sub-cases), IPsec ESP/AH,
IP-in-IP, 6in4, L2TP/L2TPv3, IKE, VXLAN, Geneve, WireGuard, OpenVPN, a
generic DTLS-tunnel structural check, STT, and MPLS, the "generic
tunnel/VPN encapsulation" tier of the same family,
traffic from offline
pcap/pcapng captures, and checks it
against a zone/conduit segmentation policy. It's an OT/ICS conduit-auditing tool: `decode`/`info` give you reliable
protocol decoding and a stats view, and `policy validate` maps that decoded traffic
against an IEC 62443-style zone/conduit model (for NIS2-flavored compliance work) --
you write a policy file naming your zones (IP/CIDR ranges) and the conduits allowed
between them, and get back a compliant/non-compliant report naming every flow that
wasn't explicitly permitted. A third command, `inventory`, runs the opposite
direction: point it at a capture with no policy file at all, and it infers a
first-draft zone/conduit model from what it actually sees (Modbus, DNP3, S7comm,
EtherNet/IP, and BACnet/IP talkers) -- an asset list, a communication matrix, a
Mermaid/Graphviz diagram, and a `policy`-format YAML file directly loadable by
`policy validate`, closing the loop from passive discovery to active enforcement.
See [docs/USER_GUIDE.md](docs/USER_GUIDE.md)'s POLICY FILE FORMAT section for the schema
and its `inventory` subsection for a worked example.

Offline capture files are still the primary, always-available way in: no libpcap
on Linux, no Npcap SDK on Windows, no elevated privileges needed to build or run --
just a C++17 compiler and CMake. Capture traffic with whatever's already on your
system (`tcpdump -w capture.pcap ...`, Wireshark/`dumpcap`'s default pcapng output),
then decode it here -- both classic pcap and pcapng are read transparently,
auto-detected from the file itself.

Live capture (`-i/--interface`) is also available now, as the one deliberate
exception to that zero-dependency design: it's an *optional*, build-time-detected
dependency on libpcap (Linux) / the Npcap SDK (Windows) -- if CMake finds it, `-i`
and `conduitscope interfaces` work; if it doesn't, the build is exactly as
dependency-free as before, and those two just report that clearly at runtime
instead of not existing. See [docs/USER_GUIDE.md](docs/USER_GUIDE.md)'s LIVE CAPTURE
section.

## Why not just use tshark?

Fair question -- tshark wins on raw protocol-decoding breadth (thousands of
dissectors vs. conduitscope's twelve-plus-CIP-I/O) and is usually still the
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
- **Small enough to actually read.** A few thousand lines of C++17, zero
  required dependencies for offline analysis (no libpcap needed unless you
  want live capture -- see below). You can read every decoder end to end and
  know exactly what it does and doesn't claim, which matters more than usual
  when pointing a tool at security-sensitive OT captures -- Wireshark/
  tshark's dissector surface is enormous and has a long CVE history.
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

## Status

Groundwork / v0.2.4. Every protocol named above is implemented, decoding real
wire-format fields (not just naming the protocol), and covered by the
automated test suite -- 1601 tests as of this writing, run via `ctest` after
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

Apache-2.0 -- see [LICENSE](LICENSE).
