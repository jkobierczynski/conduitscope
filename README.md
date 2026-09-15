# conduitscope

`conduitscope` decodes Modbus/TCP, DNP3, and S7comm/COTP (Siemens S7 PLC protocol)
traffic from offline pcap captures, and checks it against a zone/conduit segmentation
policy. It's an OT/ICS conduit-auditing tool: `decode`/`info` give you reliable
protocol decoding and a stats view, and `policy validate` maps that decoded traffic
against an IEC 62443-style zone/conduit model (for NIS2-flavored compliance work) --
you write a policy file naming your zones (IP/CIDR ranges) and the conduits allowed
between them, and get back a compliant/non-compliant report naming every flow that
wasn't explicitly permitted. See [docs/MANUAL.md](docs/MANUAL.md)'s POLICY FILE FORMAT
section for the schema.

Why offline pcap files rather than live capture: it keeps the tool dependency-free.
No libpcap on Linux, no Npcap SDK on Windows, no elevated privileges to build or run
-- just a C++17 compiler and CMake. Capture traffic with whatever's already on your
system (`tcpdump -w capture.pcap ...`, Wireshark's "save as pcap"), then decode it
here. Live capture is a natural later addition; see the Roadmap in
[docs/MANUAL.md](docs/MANUAL.md).

## Status

Groundwork / v0.1.0. What works right now:

- Classic pcap file reading (Ethernet and raw-IP link types; IPv4; TCP, with
  PDU/frame-level reassembly across TCP segments for Modbus, DNP3 data-link
  frames, and TPKT/COTP -- see below and docs/MANUAL.md)
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
- IPv4 payload is clamped to the header's own `total_length` field, so
  Ethernet's minimum-frame-size padding on short packets (bare ACKs, mostly)
  never gets misreported as phantom TCP payload -- found and fixed against a
  real capture, not just synthetic traffic
- General TCP stream reassembly at the PDU/frame level: a Modbus MBAP
  message, a DNP3 data-link frame, or a TPKT/COTP frame split across two or
  more TCP segments is buffered per directional flow and decoded once
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
  quick file metadata
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
- A `decode`/`info`/`policy validate`/`version` command surface with full
  `--help` at every level

See [docs/MANUAL.md](docs/MANUAL.md) for the complete option reference,
output-format examples, exit codes, and the honest list of current limitations
and what's planned next.

## Building

Requires a C++17 compiler and CMake >= 3.16. No other dependencies -- CLI11 is
vendored as a single header under `third_party/`.

### Linux

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
ctest --test-dir build --output-on-failure   # optional, runs the fixture-based smoke tests
```

The binary is `build/conduitscope`.

### Windows

Either Visual Studio 2022 (MSVC) or MinGW-w64 work, via the same CMake project:

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
(MinGW).

## Quick start

```sh
# Generate synthetic Modbus/TCP, DNP3, and S7comm/COTP captures and decode them
# (no live traffic needed):
python3 tools/make_sample_pcap.py
build/conduitscope decode -i tests/sample_modbus.pcap
build/conduitscope decode -i tests/sample_s7comm.pcap --stats
build/conduitscope decode -i tests/sample_modbus.pcap --format json
build/conduitscope info -i tests/sample_modbus.pcap

# Check a capture against a zone/conduit policy (see tests/policies/*.yaml for more examples,
# and docs/MANUAL.md's POLICY FILE FORMAT section for the schema):
build/conduitscope policy validate -i tests/sample_modbus.pcap --policy tests/policies/compliant.yaml
```

To decode traffic you've actually captured, e.g. from a Modbus simulator such as
`pymodbus`, or from a public sample set like the
[4SICS ICS pcaps](https://www.netresec.com/?page=PCAP4SICS):

```sh
tcpdump -i <iface> -w capture.pcap port 502 or port 20000 or port 102
build/conduitscope decode -i capture.pcap
```

## License

MIT -- see [LICENSE](LICENSE).
