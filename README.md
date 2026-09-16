# conduitscope

`conduitscope` decodes Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP (Siemens S7 PLC
protocol), EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP device
discovery/configuration and cyclic real-time I/O data), IEC 61850-8-1 GOOSE, and
IEC 61850-9-2 Sampled Values traffic from offline pcap/pcapng captures, and checks it
against a zone/conduit segmentation policy. It's an OT/ICS conduit-auditing tool: `decode`/`info` give you reliable
protocol decoding and a stats view, and `policy validate` maps that decoded traffic
against an IEC 62443-style zone/conduit model (for NIS2-flavored compliance work) --
you write a policy file naming your zones (IP/CIDR ranges) and the conduits allowed
between them, and get back a compliant/non-compliant report naming every flow that
wasn't explicitly permitted. See [docs/MANUAL.md](docs/MANUAL.md)'s POLICY FILE FORMAT
section for the schema.

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
instead of not existing. See [docs/MANUAL.md](docs/MANUAL.md)'s LIVE CAPTURE
section.

## Why not just use tshark?

Fair question -- tshark wins on raw protocol-decoding breadth (thousands of
dissectors vs. conduitscope's eight-plus-CIP-I/O) and is usually still the
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

In short: tshark for exploring an unfamiliar capture or decoding something
obscure; conduitscope for the specific, repeatable "does this OT network's
traffic match what the segmentation policy says it should" question.

## Status

Groundwork / v0.1.0. What works right now:

- Classic pcap and pcapng file reading, auto-detected (Ethernet and raw-IP
  link types; IPv4; TCP, with PDU/frame-level reassembly across TCP segments
  for Modbus, DNP3 data-link frames, IEC 104 APDUs, EtherNet/IP encapsulation
  messages, and TPKT/COTP -- see below and docs/MANUAL.md)
- Full Modbus/TCP decoding for the read (1-4), write-single (5-6), and
  write-multiple (15-16) function code families, plus exception responses.
  Every response also gets authoritative (MBAP transaction-ID + TCP-session,
  non-heuristic) pairing to the specific request it answers, layered on top
  of the always-on payload-shape heuristic -- this is what resolves
  write-single's inherent shape ambiguity (request and response are
  byte-for-byte identical per spec). Validated against both synthetic
  fixtures and a real Modbus capture's request/response session; see
  docs/MANUAL.md.
- Full DNP3 decoding through the application layer for a single-data-link-frame
  fragment (the large majority of real traffic): data-link header
  (source/destination addresses, frame length), transport header (FIR/FIN/SEQ,
  with correct per-16-byte-block CRC reassembly of the user data), function
  code, Internal Indications on responses, and every object header
  (group/variation/qualifier/range) -- with **point values decoded**, not just
  skipped, for the object types common in real traffic: Binary/Double-bit
  Binary/Analog/Counter Input and Output states and readings (with quality
  flags), CROB output-command fields (control code, trip/close, on/off time,
  status -- this is literally how DNP3 issues commands), and absolute
  timestamps. A group/variation outside that table still gets its object data
  located and skipped by computed length, just not value-decoded. Multiple
  complete DNP3 data-link frames coalesced into one TCP segment (common,
  since DNP3 frames are small) are all found and decoded, not just the first.
  A fragment that spans more than one data-link frame (FIR=1 on the first,
  FIN=0 until the last) is reassembled across however many separate TCP
  segments/packets it takes, per TCP flow, and its application layer decoded
  once complete -- this path has no real-capture validation yet (every real
  DNP3 capture checked so far used only complete single-frame fragments),
  only the synthetic fixture in tests/sample_dnp3.pcap; see docs/MANUAL.md.
  A single data-link frame's own header/blocks split across TCP segments IS
  now reassembled too, via a separate, lower-level TCP-segment reassembler
  that also covers Modbus and TPKT/COTP (see below and docs/MANUAL.md).
  Validated against a large real 4SICS ICS-lab capture and a
  set of real (not synthetic) DNP3 captures from independent DNP3 stacks --
  real CROB Select/Operate sequences (including a rejected operate), a real
  polling session, and a deliberately corrupted/fuzzed capture that must
  degrade gracefully rather than crash (see
  tests/real_captures/dnp3/ATTRIBUTION.md for provenance).
- S7comm/COTP: full TPKT+COTP framing decode (incl. connection-setup TSAP
  parameters), full S7comm header + function-code decoding, a full
  Setup Communication decode, and full item-level Read Var/Write Var
  addressing -- which memory area (input/output/merker/DB/instance-DB/
  counter/timer), DB number, byte/bit address, and transport size each
  item addresses, rendered in familiar Step 7 notation (`DB10.DBW100`,
  `I0.0`, `MB50`, `T5`), plus the returned/written values. S7-1200/1500
  "symbolic" addressing (`0xB2`) -- confirmed to be common in real traffic --
  also gets a tag, but via an **experimental, unverified** reconstruction
  clearly marked as such everywhere it appears; S7comm-Plus is a documented
  stub. A single S7comm message that doesn't fit one negotiated PDU length
  and gets chained across multiple complete TPKT/COTP frames (via COTP's own
  EOT bit) is reassembled into one logical message before decoding, not just
  the first frame's bytes -- real captures confirm the reassembly itself is
  transparent (several independent devices precede real responses with a
  content-free "priming" fragment), though genuine multi-frame *content*
  splitting is validated only by a synthetic fixture so far; see
  docs/MANUAL.md. Validated against real 4SICS ICS-lab captures -- including two much
  larger ones (1.25M and 2.27M packets) that turned out to be
  overwhelmingly S7comm traffic, which is exactly the case item-level
  addressing was built for. The `0xB2` reconstruction's single validated
  shape (`M2.0`-`M2.4`) was later re-checked against that same 1.25M-packet
  capture in full: over 1 million real `0xB2` items, zero structural
  fallbacks -- strong confidence for a full real session, though it's the
  same session the original finding came from, not an independently
  different one (see tests/real_captures/s7comm/ATTRIBUTION.md). Also
  validated against 14 further real S7comm captures from independent
  sources (up to ~9,000 real items in one) and 3 real Modbus captures --
  see tests/real_captures/{s7comm,modbus}/ATTRIBUTION.md.
- Full IEC 60870-5-104 decoding: APCI framing (I/S/U-format, sequence
  numbers, STARTDT/STOPDT/TESTFR act/con), and, for I-format APDUs, the
  ASDU -- type ID, cause of transmission, common/station address, and every
  information object's address and value, for the type IDs that dominate
  real traffic: single/double-point, measured values (normalized/scaled/
  short-float, each with and without a CP24Time2a/CP56Time2a time tag),
  integrated totals, single/double/regulating-step commands and set-point
  commands, end-of-initialization, general interrogation, clock sync, and
  reset process. Unlike DNP3, one I-format APDU always carries exactly one
  complete ASDU, so no cross-frame application-fragment reassembly is
  needed -- only the same TCP-segment-level PDU reassembly every protocol
  here gets (see below). IEC 104 detection runs *before* Modbus in
  Auto-mode dispatch: an I-format APDU with N(S)=N(R)=0 (the very first
  data frame of any session) would otherwise coincidentally satisfy
  Modbus/TCP's own protocol-id==0 tell, a real collision risk found while
  scoping this feature (see docs/MANUAL.md's PROTOCOL DETECTION section).
  Validated against three independent real IEC 104 stacks' actual wire
  encodings, including the public Industroyer2 capture (real, attributed
  nation-state ICS malware traffic against a live RTU) -- see
  tests/real_captures/iec104/ATTRIBUTION.md.
- EtherNet/IP (TCP port 44818) + CIP explicit messaging: the 24-byte
  encapsulation header (all nine standard commands except NOP -- deliberately
  excluded, see below), a ListIdentity response's device-fingerprinting
  fields (vendor/device type/product code/revision/serial/product name),
  Common Packet Format item parsing for SendRRData/SendUnitData, and a
  "first pass" CIP explicit-message decode covering the generic common
  services (Get/Set_Attribute(_Single/List/All), Reset, Multiple_Service_
  Packet -- fully recursive), Connection Manager's Unconnected_Send (also
  recursive, decoding its embedded message and route path) and Forward_
  Open/Close, and, specifically when the request path addresses a Rockwell
  Logix5000 named tag (an ANSI Extended Symbol segment, `0x91`) rather than
  a class/instance path, full type+value decoding of Read_Tag/Write_Tag(
  _Fragmented) and Read_Modify_Write_Tag. That symbolic-path gating is a
  real-world-motivated scoping decision, not a simplification for its own
  sake: a real capture used to validate this decoder shows the exact same
  service code (0x4C) meaning "Read_Tag" against a named tag and something
  else entirely against a vendor-specific object class -- see
  tests/real_captures/enip/ATTRIBUTION.md. NOP (command `0x0000`) is
  deliberately not recognized as a command at all: its all-zero-bytes shape
  was found, via real-capture regression testing, to false-positive against
  unrelated malformed/padded traffic -- the same reasoning already applied
  once before for Modbus's own function-code-0 exclusion. EtherNet/IP
  detection runs *first* in Auto-mode dispatch (its own dedicated port plus
  three independent structural checks make it a strong signal, and trying it
  first costs nothing). Validated against two real captures -- a real
  Rockwell 1756-ENBT/A ControlLogix bridge module's ListIdentity exchange,
  and a larger real industrial-control-system capture dominated by
  Multiple_Service_Packet/Unconnected_Send/Read_Modify_Write_Tag traffic --
  see tests/real_captures/enip/ATTRIBUTION.md.
- EtherNet/IP CIP I/O (implicit messaging, UDP port 2222): the real-time,
  cyclic I/O data exchange a prior Forward_Open (above) establishes. Unlike
  explicit messaging, there's no 24-byte encapsulation header on this wire at
  all -- a UDP/2222 payload *is* the Common Packet Format item list directly
  (confirmed against Wireshark's own `packet-enip.c` dissector source). The
  Sequenced Address Item (connection ID + rolling sequence number) is fully
  decoded; the Connected Data Item (the actual I/O/assembly data) is located
  and shown as raw hex, deliberately never value-decoded, since it has no
  generic self-describing wire-level type and this decoder doesn't track a
  connection's negotiated transport class (which would be needed to know
  whether a leading 16-bit CIP sequence count is present in it or not) --
  see docs/MANUAL.md. This is the first protocol conduitscope decodes over
  UDP; `--protocol enip` covers both explicit and implicit messaging. No real
  CIP I/O capture was found while building this decoder (searched across
  several public pcap collections, including the ones that supplied the two
  real EtherNet/IP captures above) -- validated by construction against the
  wire format as cross-checked against Wireshark's dissector source and the
  CISA `icsnpp-enip` Zeek parser; see tests/real_captures/enip/ATTRIBUTION.md.
- PROFINET RT (EtherType `0x8892`): unlike every other protocol above, this
  one rides directly on raw Ethernet -- no IPv4/TCP/UDP layer at all. Two
  FrameID-discriminated shapes are fully decoded: DCP (Discovery and
  Configuration Protocol) -- Hello/Get/Set/Identify request/response
  exchanges, including device-fingerprinting fields (NameOfStation, Vendor/
  DeviceID, DeviceRole, MAC/IP configuration) -- and cyclic real-time I/O
  data, whose trailing CycleCounter/DataStatus/TransferStatus fields are
  decoded while the I/O data itself is shown only as raw hex (no GSD/GSDML
  device description to know an assembly's layout from, same reasoning as
  CIP I/O's Connected Data Item above). Building this against a real capture
  caught a genuine bug before it ever shipped: several DCP block types carry
  an undocumented-in-the-obvious-sources extra 2-byte prefix before their
  actual content, but only in specific request/response directions -- see
  tests/real_captures/profinet/ATTRIBUTION.md for the full writeup. Every
  other FrameID range (RTC3, Alarm High/Low, PTCP, fragmentation, ...) is
  named but not further decoded; a genuinely reserved/unrecognized FrameID
  falls back to the same generic "non-ip" ethertype-name-only report as
  before this feature. No real cyclic RT IO data capture was found (same gap
  as CIP I/O above, for the same reason); DCP IS validated against two real
  captures -- see tests/real_captures/profinet/ATTRIBUTION.md.
- IEC 61850-8-1 GOOSE (EtherType `0x88B8`): like PROFINET RT, rides directly
  on raw Ethernet with no IPv4/TCP/UDP layer. The 8-byte header (APPID,
  Length, and a Reserved1 field whose top bit is the "Simulated" S-bit) and
  the ASN.1 BER-encoded APDU underneath it are both fully decoded: every
  IECGoosePdu field (`gocbRef`, `datSet`, `goID`, the UTC timestamp with its
  TimeQuality bits, `stNum`/`sqNum` -- the state-change/retransmission
  counters that are the primary anomaly-detection signal for GOOSE spoofing
  and replay -- `confRev`, `simulation`, `ndsCom`) and every `allData` value
  (booleans, bit-strings, signed/unsigned integers, single/double-precision
  floating point, octet/visible/MMS strings, UTC timestamps, and nested
  array/structure values, recursively). A GSE Management PDU (the other,
  rarer outer APDU shape, used for engineering-tool queries rather than the
  periodic state-change multicast) is recognized and named but not decoded
  further. Building this against real captures caught a genuine tag-table
  error before it shipped: an initial source read suggested every PDU field
  used constructed (0xA0-0xAA) BER encoding, which a hand-written BER walker
  run against real bytes disproved -- only `allData` is actually constructed
  (0xAB); every scalar field is primitive (0x80-0x8A). See
  tests/real_captures/goose/ATTRIBUTION.md for the full writeup. Validated
  against four real captures totaling 494 real GOOSE frames from independent
  substation protection schemes; every one of those frames happens to use
  only `boolean`/`bit-string` `allData` values and carry every optional PDU
  field, so the other `allData` types, optional-field absence, GSE
  Management PDU decoding, and multi-APDU-per-frame handling are validated
  only against the synthetic fixture -- see that same ATTRIBUTION.md for the
  honest gap list. R-GOOSE (routable GOOSE, IEC 61850-90-5, a UDP/IP
  encapsulation with a completely different session layer) and IEC 61850-9-2
  Sampled Values (the sibling EtherType `0x88BA`) are out of scope.
- IEC 61850-9-2 Sampled Values (EtherType `0x88BA`): SV's sibling protocol to
  GOOSE, also riding directly on raw Ethernet with the identical 8-byte
  APPID/Length/Reserved1(S-bit)/Reserved2 header. The full `SavPdu` (`noASDU`
  plus one or more `ASDU` elements in `seqASDU` -- unlike GOOSE, every ASDU in
  the sequence is decoded, since multiple ASDUs per SavPdu is core, spec-defined
  behavior, not a rare edge case) is decoded: `svID`, `datSet`, `smpCnt`
  (the primary stream-integrity/replay-detection signal), `confRev`,
  `refrTm`, `smpSynch`, `smpRate`, `smpMod`, and the Ed.2.1 `gmidData`
  (grandmaster clock identity) field. `seqData` -- the actual sample
  payload -- is deliberately shown only as raw hex and never value-decoded:
  interpreting it (e.g. as the common "9-2LE" 8-channel profile) requires an
  implementation profile layered on top of the base ASN.1, which the standard
  itself doesn't assert; Wireshark gates the same interpretation behind an
  opt-in preference, off by default, and this decoder mirrors that. Despite a
  genuine multi-source search (Wireshark's own test-capture tree and
  SampleCaptures wiki, several public ICS-pcap repositories, IEC 61850 tooling
  projects, and a Wireshark GitLab issue's attached sample), no real,
  publicly-downloadable SV capture was found, so validation here is
  synthetic-fixture-only -- see include/conduitscope/sv.hpp's file header for
  the full honest writeup. R-SV (routable SV, IEC 61850-90-5) is out of scope.
- Non-IPv4 Ethernet frames and non-TCP IPv4 payloads (including UDP) are now
  recognized and named, not just reported as a bare hex/number and dropped:
  ARP, EtherCAT, LLDP, PTP, MPLS, and stacked-VLAN (802.1ad/QinQ) EtherTypes;
  ICMP, IGMP, GRE, ESP, AH, OSPF, and SCTP IP protocol numbers; and the UDP
  header itself (source/destination port, byte count) -- EtherNet/IP's own
  UDP port (2222) is decoded, not just named, when the traffic on it actually
  looks like CIP I/O (see above), PROFINET RT's EtherType is decoded, not
  just named, when the FrameID looks like DCP or cyclic IO data (see above),
  and both IEC 61850-8-1 GOOSE's and IEC 61850-9-2 Sampled Values' EtherTypes
  are decoded, not just named, when the outer APDU tag matches (see above).
  This is otherwise groundwork plumbing, not a new protocol decoder -- none
  of the remaining named-but-not-decoded protocols' own framing is parsed
  any further yet (EtherCAT is the most notable one left), and `policy
  validate` does not yet evaluate any non-TCP traffic against any conduit
  (still counted as `skipped_non_tcp`, same as before) -- but it's a real,
  confirmed visibility gap this closes: re-running conduitscope's own
  real-capture test set after adding this surfaced genuine ARP and UDP (DNS,
  NetBIOS) traffic that was previously invisible. See docs/MANUAL.md's
  PROTOCOL COVERAGE and ROADMAP.
- IPv4 payload is clamped to the header's own `total_length` field, so
  Ethernet's minimum-frame-size padding on short packets (bare ACKs, mostly)
  never gets misreported as phantom TCP payload -- found and fixed against a
  real capture, not just synthetic traffic
- General TCP stream reassembly at the PDU/frame level: a Modbus MBAP
  message, a DNP3 data-link frame, an IEC 104 APDU, an EtherNet/IP
  encapsulation message, or a TPKT/COTP frame
  split across two or more TCP segments is buffered per directional flow and decoded once
  complete, using each protocol's own declared-length field to know how many
  bytes to wait for. Resyncs rather than reorders on capture gaps, and trims
  overlapping retransmissions rather than duplicating bytes. Verified
  byte-for-byte behavior-identical against every real capture in this
  project's test set (none of which happen to split a PDU across segments)
  and against 6 synthetic scenarios covering the happy path plus gaps,
  full-duplicate retransmits, and partial-overlap retransmits; see
  docs/MANUAL.md's LIMITATIONS for exact scope. Modbus request/response
  pairing and multi-frame S7comm chaining are separate mechanisms, described
  above, not part of this one
- Text, JSON, and CSV output; a `--stats` summary mode; an `info` command for
  quick file metadata. Text output is colorized (per-protocol tags, red for
  exceptions/parse-errors) when writing to an interactive terminal, or
  forced on/off with `--color`/`--no-color`
- `policy validate`: a zone/conduit policy engine. A policy file (a
  deliberately restricted, dependency-free YAML subset -- no vendored YAML
  library, same zero-dependency approach as everything else here) declares
  zones (IPv4 CIDR blocks) and conduits (an allowed protocol+port
  relationship, in a given direction, between two zones). Every decoded TCP
  flow in the capture is classified into a zone pair, checked against the
  policy's conduits, and reported as allowed, a violation, or unclassified
  (an endpoint matching no declared zone, or a flow with no recognized
  protocol at all) -- text or JSON output, a distinct exit status for
  "found problems" vs. "couldn't run" vs. "clean", and a report that also
  lists any conduit the capture never exercised. Built entirely on top of
  the decoding layer above (S7comm item tags, decoded DNP3 point values,
  Modbus address+quantity decoding, and authoritative Modbus request/
  response pairing are exactly the concrete facts this checks policy
  against) rather than duplicating any of its parsing. See
  docs/MANUAL.md's POLICY FILE FORMAT section for the full schema and
  LIMITATIONS for exactly what it does and doesn't check (e.g. the
  SYN-based flow-direction heuristic's fallback case).
- Live capture (`decode -i`/`policy validate -i`, plus `conduitscope interfaces`
  to list interfaces): an optional, build-time-detected libpcap (Linux) / Npcap
  (Windows) dependency -- see above and docs/MANUAL.md's LIVE CAPTURE section.
  `--duration`, `--filter` (BPF syntax), `--snaplen`, and Ctrl+C all stop a
  capture cleanly, still producing whatever decode output or policy report was
  captured so far. Validated end-to-end against real loopback traffic on Linux;
  the Windows/Npcap path is implemented against the same documented API but not
  yet run on a real Windows machine -- see docs/MANUAL.md's LIMITATIONS.
- A `decode`/`info`/`interfaces`/`policy validate`/`version` command surface
  with full `--help` at every level

See [docs/MANUAL.md](docs/MANUAL.md) for the complete option reference,
output-format examples, exit codes, and the honest list of current limitations
and what's planned next.

## Building

Requires a C++17 compiler and CMake >= 3.16. No other dependencies are *required*
-- CLI11 is vendored as a single header under `third_party/`. If `libpcap-dev`
(Linux) or the Npcap SDK (Windows) happens to be installed and discoverable,
CMake picks it up automatically and live capture (`-i/--interface`) is built in;
if not, the build is unaffected except that `-i` reports it isn't available. Pass
`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` to skip that search entirely and
guarantee a dependency-free build regardless of what's installed. See
docs/MANUAL.md's LIVE CAPTURE section for the runtime-vs-build-time distinction
on Windows (the Npcap *SDK* is build-time only; running a live capture also needs
the separate Npcap *driver/service* installed).

### Linux

```sh
sudo apt install libpcap-dev   # optional, only needed for live capture (-i)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # optional, runs the fixture-based smoke tests
```

The binary is `build/conduitscope`.

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
# GOOSE, and Sampled Values captures and decode them (no live traffic needed):
python3 tools/make_sample_pcap.py
build/conduitscope decode -r tests/sample_modbus.pcap
build/conduitscope decode -r tests/sample_s7comm.pcap --stats
build/conduitscope decode -r tests/sample_iec104.pcap
build/conduitscope decode -r tests/sample_enip.pcap
build/conduitscope decode -r tests/sample_enip_cip_io.pcap
build/conduitscope decode -r tests/sample_goose.pcap
build/conduitscope decode -r tests/sample_sv.pcap
build/conduitscope decode -r tests/sample_modbus.pcap --format json
build/conduitscope info -r tests/sample_modbus.pcap

# Check a capture against a zone/conduit policy (see tests/policies/*.yaml for more examples,
# and docs/MANUAL.md's POLICY FILE FORMAT section for the schema):
build/conduitscope policy validate -r tests/sample_modbus.pcap --policy tests/policies/compliant.yaml
```

To decode traffic you've actually captured, e.g. from a Modbus simulator such as
`pymodbus`, or from a public sample set like the
[4SICS ICS pcaps](https://www.netresec.com/?page=PCAP4SICS):

```sh
tcpdump -i <iface> -w capture.pcap port 502 or port 20000 or port 2404 or port 102 or port 44818 or port 2222
build/conduitscope decode -r capture.pcap
```

Or, if this build has live-capture support (see Building above), skip the
intermediate file and check traffic in real time:

```sh
build/conduitscope interfaces                                    # list capturable interfaces
build/conduitscope decode -i eth0 --filter "port 502 or port 2404 or port 102 or port 44818 or port 2222" --duration 60
build/conduitscope policy validate -i eth0 --policy tests/policies/compliant.yaml --duration 60
# or just Ctrl+C to stop either one early -- both still print whatever was captured so far
```

## License

MIT -- see [LICENSE](LICENSE).
