# Conduitscope

<p align="center">
  <img src="assets/logo.jpg" alt="conduitscope logo: an amber warning-sign triangle with a shark whose eyes fire laser beams" width="220">
</p>

`Conduitscope` decodes Modbus/TCP, DNP3, IEC 60870-5-104, S7comm/COTP (Siemens S7 PLC
protocol) and S7comm-Plus (Siemens TIA Portal / S7-1200/1500's newer protocol),
EtherNet/IP (CIP explicit and implicit messaging), PROFINET RT (DCP device
discovery/configuration and cyclic real-time I/O data), IEC 61850-8-1 GOOSE,
IEC 61850-9-2 Sampled Values, EtherCAT, BACnet/IP, HART-IP, OPC UA Binary
(UA-TCP/Secure Conversation), IEC 61850 MMS (Manufacturing Message Specification,
ISO 9506), MQTT (v3.1/v3.1.1/v5.0, including Sparkplug B), FOUNDATION
Fieldbus HSE (FDA/SM/FMS/LAN Redundancy), IEEE Spanning Tree Protocol
(STP/RSTP/MSTP), DeviceNet (CAN-bus CIP, via SocketCAN pcap captures), DNS,
mDNS, LLMNR, and NetBIOS Name Service (NBT-NS), RIP, IGMP, VRRP, HSRP, IGRP,
PIM, EIGRP, and OSPFv2,
plus detects DNS-over-HTTPS
(DoH) via TLS SNI matching, and recognizes (by name only, not full decode)
RDP, VNC, TeamViewer, AnyDesk, and Zoom -- the "interactive remote control"
tier of the IT protocols an OT auditor flags -- plus SMB, SSH, HTTP, HTTPS,
SNMPv1/v2c, Telnet, FTP, and TFTP, the "lateral-movement and
credential-harvesting" tier of the same family, plus NTP, DHCP, LDAP,
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

Groundwork / v0.1.7. What works right now:

- Classic pcap and pcapng file reading, auto-detected (Ethernet and raw-IP
  link types; IPv4; TCP, with PDU/frame-level reassembly across TCP segments
  for Modbus, DNP3 data-link frames, IEC 104 APDUs, EtherNet/IP encapsulation
  messages, and TPKT/COTP -- see below and docs/USER_GUIDE.md)
- Full Modbus/TCP decoding for the read (1-4), write-single (5-6), and
  write-multiple (15-16) function code families, plus exception responses.
  Every response also gets authoritative (MBAP transaction-ID + TCP-session,
  non-heuristic) pairing to the specific request it answers, layered on top
  of the always-on payload-shape heuristic -- this is what resolves
  write-single's inherent shape ambiguity (request and response are
  byte-for-byte identical per spec). Validated against both synthetic
  fixtures and a real Modbus capture's request/response session; see
  docs/USER_GUIDE.md.
- Full DNP3 decoding through the application layer for a single-data-link-frame
  fragment (the large majority of real traffic): data-link header
  (source/destination addresses -- 16-bit DNP3 station addresses, exposed as
  `dnp3_source_address`/`dnp3_destination_address`, the actual outstation/
  master identity a serial-to-IP gateway multiplexes behind one shared IP;
  frame length), transport header (FIR/FIN/SEQ,
  with correct per-16-byte-block CRC reassembly of the user data), function
  code, Internal Indications on responses, and every object header
  (group/variation/qualifier/range) -- with **point values decoded**, not just
  skipped, for the object types common in real traffic: Binary/Double-bit
  Binary/Analog/Counter Input and Output states and readings (with quality
  flags), CROB output-command fields (control code, trip/close, on/off time,
  status -- this is literally how DNP3 issues commands), and absolute
  timestamps. The data-link CRC-16 (the 8-byte header's own CRC, and every
  <=16-byte user-data block's own separate CRC) is now genuinely calculated
  and validated against the on-the-wire value, not just located and skipped
  -- a mismatch is flagged (`dnp3_link_crc_valid`/`dnp3_header_crc_valid`/
  `dnp3_block_count`/`dnp3_block_crc_failures` plus a specific `notes` entry)
  without ever stopping decoding, diagnostic only (not yet wired into
  `policy validate`); see docs/USER_GUIDE.md. A group/variation outside that table still gets its object data
  located and skipped by computed length, just not value-decoded. Multiple
  complete DNP3 data-link frames coalesced into one TCP segment (common,
  since DNP3 frames are small) are all found and decoded, not just the first.
  A fragment that spans more than one data-link frame (FIR=1 on the first,
  FIN=0 until the last) is reassembled across however many separate TCP
  segments/packets it takes, per TCP flow, and its application layer decoded
  once complete -- this path has no real-capture validation yet (every real
  DNP3 capture checked so far used only complete single-frame fragments),
  only the synthetic fixture in tests/sample_dnp3.pcap; see docs/USER_GUIDE.md.
  A single data-link frame's own header/blocks split across TCP segments IS
  now reassembled too, via a separate, lower-level TCP-segment reassembler
  that also covers Modbus and TPKT/COTP (see below and docs/USER_GUIDE.md).
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
  clearly marked as such everywhere it appears; PLC Control (`0x28`) and PLC
  Stop (`0x29`) -- the general Program Invocation mechanism used to push or
  remove logic blocks on a live controller, and the wire-level mechanism
  behind the well-known unauthenticated "PLC Stop" DoS technique,
  respectively -- also get their own parameters decoded now (PI service
  name/block descriptors, and the Stop confirmation string); S7comm-Plus (the newer,
  TIA-Portal-native protocol sharing this same transport) is now fully
  decoded too -- see its own bullet below. A single S7comm message that
  doesn't fit one negotiated PDU length
  and gets chained across multiple complete TPKT/COTP frames (via COTP's own
  EOT bit) is reassembled into one logical message before decoding, not just
  the first frame's bytes -- real captures confirm the reassembly itself is
  transparent (several independent devices precede real responses with a
  content-free "priming" fragment), though genuine multi-frame *content*
  splitting is validated only by a synthetic fixture so far; see
  docs/USER_GUIDE.md. Validated against real 4SICS ICS-lab captures -- including two much
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
  information object's address and value, for 51 type IDs covering the
  traffic that dominates real IEC 104 sessions: single/double-point, step
  position, bitstring-of-32-bit, measured values (normalized/scaled/
  short-float, each with and without a CP24Time2a/CP56Time2a time tag, plus
  the normalized-without-quality-descriptor variant), integrated totals,
  single/double/regulating-step commands, bitstring commands, and set-point
  commands, delay acquisition, end-of-initialization, general interrogation,
  clock sync, reset process, test command, and parameter loading/activation.
  Deliberately not decoded: protection-equipment event types, packed
  single-point with status change detection, and file transfer -- see
  docs/PROTOCOL_COVERAGE.md for why. Unlike DNP3, one I-format
  APDU always carries exactly one
  complete ASDU, so no cross-frame application-fragment reassembly is
  needed -- only the same TCP-segment-level PDU reassembly every protocol
  here gets (see below). IEC 104 detection runs *before* Modbus in
  Auto-mode dispatch: an I-format APDU with N(S)=N(R)=0 (the very first
  data frame of any session) would otherwise coincidentally satisfy
  Modbus/TCP's own protocol-id==0 tell, a real collision risk found while
  scoping this feature (see docs/DEVELOPMENT.md's PROTOCOL DETECTION section).
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
  see docs/USER_GUIDE.md. This is the first protocol conduitscope decodes over
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
- EtherCAT (EtherType `0x88A4`): also rides directly on raw Ethernet, no
  IPv4/TCP/UDP layer, like PROFINET RT/GOOSE/SV -- but unlike those three,
  EtherCAT's wire format is plain fixed-binary-layout, little-endian
  throughout, with no ASN.1/BER encoding anywhere. The 2-byte frame header
  (Length, Reserved, and a Type field naming one of five frame kinds) is
  decoded, and for Type 1 ("EtherCAT command") frames, so is the full chain
  of EtherCAT datagrams that follows: `Cmd` (all 15 defined values, plus
  `EXT`), `Idx`, `Adp`/`Ado` addressing (or a 32-bit logical address for
  `LRD`/`LWR`/`LRW`), the `Len` word's Circulating/More bits, `Irq`, and the
  trailing Working Counter (`WKC`) -- EtherCAT's primary stream-integrity
  signal, surfaced raw with no verdict, the same honest posture SV takes with
  `smpCnt`. `Data` is deliberately never value-decoded (the fourth time this
  codebase applies that "no generic self-describing wire-level type"
  reasoning, after PROFINET's cyclic IO data, CIP I/O's Connected Data Item,
  and SV's `seqData`): it's either raw ESC register content or raw
  process-image bytes whose actual layout depends on offline ESI/XML
  engineering configuration this decoder has no access to. Unlike SV, a real
  capture WAS found (986 frames, a master's boot-time slave enumeration and
  register-poll sequence) -- see tests/real_captures/ethercat/ATTRIBUTION.md
  -- and it directly confirmed a deliberate design choice: this decoder
  bounds the datagram-chain scan by the frame header's own declared Length
  field, rather than walking every byte physically present in the frame the
  way Wireshark's own dissector does, specifically to avoid misreading
  Ethernet's minimum-frame-size zero-padding as a spurious trailing
  datagram -- all 986 real frames show declared Length exactly matching the
  actual chained-datagram byte count, zero mismatches. One honest gap this
  protocol has that GOOSE/SV/PROFINET don't: its frame-header Type field is a
  genuinely weaker structural detection signal (5 of 16 possible 4-bit
  values, vs. GOOSE/SV's 1-in-256 outer tag or PROFINET's FrameID range
  table) -- the dedicated, collision-free EtherType remains the primary
  confidence source. The CoE/SoE/EoE/FoE/AoE mailbox protocol family (SDO
  access -- the most common way real EtherCAT configuration/diagnostic
  traffic actually happens), Frame Type 5 ("Mailbox") framing, Frame Types
  2-4 (ADS/RAW-IO/NV), and Distributed Clock register semantics are all out
  of scope -- see include/conduitscope/ethercat.hpp's file header for the
  full honest writeup.
- BACnet/IP (UDP port 47808/0xBAC0, ASHRAE 135 Annex J): unlike EtherCAT/
  GOOSE/SV/PROFINET RT, this one rides over UDP, so detection is a
  payload-shape gate (BVLC Type `0x81` + Function in `0x00`-`0x0C`) applied
  port-independently to every UDP payload, mirroring CIP I/O's own
  opportunistic detection rather than PROFINET/GOOSE/SV's dedicated-EtherType
  approach. Three layers are decoded: BVLC (the UDP framing header, including
  every BBMD/foreign-device-table management function -- Write/Read-BDT,
  Register-Foreign-Device, Read/Delete-FDT-Entry, Forwarded-NPDU,
  Distribute-Broadcast-To-Network -- plus the opaque, undecodable
  Secure-BVLL), NPDU (the network layer: DNET/DLEN/DADR and SNET/SLEN/SADR
  routing fields, HopCount, and Network Layer Messages named but not
  value-decoded), and APDU (the application layer: all 8 PDU types --
  Confirmed/Unconfirmed-Request, Simple-ACK, Complex-ACK, Segment-ACK, Error,
  Reject, Abort -- byte-accurate down to segmentation's SEG/MOR bits). Service
  value-decoding is a deliberate first pass, the same scoping precedent this
  codebase already applies to EtherNet/IP CIP explicit messaging and DNP3's
  object table: Who-Is, I-Am, Who-Has, I-Have, ReadProperty request/ACK,
  WriteProperty request, and generic Error are fully value-decoded (including
  every primitive property-value type -- Real, Unsigned, Signed, Double,
  Boolean, Enumerated, CharacterString, BitString, OctetString, Date, Time,
  ObjectIdentifier); everything else (ReadPropertyMultiple/
  WritePropertyMultiple, SubscribeCOV, segmented service data, and a
  constructed/array PropertyValue -- the fifth "no generic self-describing
  wire-level type" case in this codebase, after PROFINET's cyclic IO data,
  CIP I/O's Connected Data Item, SV's `seqData`, and EtherCAT's `Data`) is
  named via the full service-choice table but shown as raw hex with an
  explanatory note. A real capture was found and validated: 54 frames (a
  ReadProperty polling session against trend-log objects) extracted from a
  larger mixed-OT-protocol capture -- see
  tests/real_captures/bacnet/ATTRIBUTION.md for the full provenance and, more
  usefully, its honest "Gaps" section listing everything that real traffic
  does NOT exercise (device discovery, WriteProperty, every non-scalar
  PropertyValue type, BBMD/FDT functions, and more) -- see
  include/conduitscope/bacnet.hpp's file header for the full writeup.
- HART-IP (UDP/TCP port 5094, IEC 62591 / HCF_SPEC-151): tunnels classic wired-HART
  traffic over IP, either terminating a Session Initiate/Keep-Alive/Session-Close
  session and Pass-Through-wrapped HART commands directly, or carrying them
  end-to-end between a host and a WirelessHART/wired-HART gateway. The 8-byte fixed
  header (Version, MessageType, MessageID, Status, TransactionID, MsgLength) and all
  four MessageID-selected body shapes are decoded, including the full byte-by-byte
  Pass-Through Data-Link PDU (Delimiter/Frame-Type/Address, Command, Byte Count,
  Response Code, Device Status, Data, Checksum) -- including the classic
  wired-HART longitudinal (XOR) Data-Link Checksum itself, which is computed
  and compared against the wire byte, not just surfaced raw (a mismatch is
  flagged as its own note). This is deliberately the most
  honestly-caveated detection gate in this codebase: unlike the dedicated-EtherType
  or multi-field-structural protocols above, HART-IP rides over TCP or UDP with only
  two adjacent header bytes (MessageType in a 5-value set, MessageID in a 4-value
  set) as its structural anchor, and a real, accepted collision follows from that --
  a genuine HART-IP Session Initiate message's own header happens to also look like
  a plausible Modbus/TCP MBAP header, so on TCP it's tried last and, when it loses
  that race, is reported as Modbus/TCP "buffering, waiting for more" instead (UDP is
  unaffected; so is every other HART-IP message type). Rather than silently
  papering over that with an unsafe reordering fix (tried, and it measurably
  regressed this codebase's own Modbus/S7comm test corpus), it's documented,
  demonstrated in the synthetic fixture, and left as an honest, accepted limitation
  -- see include/conduitscope/hartip.hpp's file header for the full writeup. Command
  value-decoding covers the common read/write commands (0/11/21 Read Unique
  Identifier, 1-3, 6-9, 12-20, 22, 31/203, 33, 38, 48, and more) including
  packed-ASCII (6-bit, 3-byte-to-4-char) text field decoding and HART-format
  timestamps, with less-common and device-specific commands (77, 178, and anything
  else outside this first pass) named via the command-number table but shown as raw
  hex. A real capture was found and validated -- 116 frames, a WirelessHART gateway
  exchange over both UDP and TCP, cross-checked field-by-field against Wireshark's
  own HART-IP dissector -- and it independently reproduced the documented Modbus
  collision on genuine field traffic, plus a second, previously-undocumented
  false-positive pattern where the same weak gate also matches unrelated background
  TCP traffic; see tests/real_captures/hartip/ATTRIBUTION.md for both.
- OPC UA Binary (TCP port 4840, UA-TCP transport / OPC UA Secure Conversation, OPC
  10000-6): the 8-byte UA-TCP common header (MessageType/ChunkType/MessageSize) and,
  for OpenSecureChannel/CloseSecureChannel/Message, the SecureChannelId plus
  security header (SecurityPolicyUri and certificate presence/length for
  OpenSecureChannel; TokenId for the rest) and sequence header are always decoded --
  unlike every other protocol in this codebase except EtherNet/IP/CIP, OPC UA's own
  binary encoding is little-endian throughout. At the service layer, a deliberate
  two-tier scope: the full connection/channel/session lifecycle plus both discovery
  services (Hello/Acknowledge/Error/ReverseHello, OpenSecureChannel,
  CloseSecureChannel, GetEndpoints, FindServers, CreateSession, ActivateSession,
  CloseSession, ServiceFault) are fully field-decoded, including -- deliberately --
  ActivateSession's own UserIdentityToken, which surfaces a cleartext
  UserName/Password credential as a real, actionable OT-security finding whenever
  EncryptionAlgorithm is empty (the same "decode what's genuinely useful for an
  audit" reasoning already applied to this codebase's HART-IP Response-Code
  naming). Variant/DataValue -- OPC UA's own self-describing, 25-BuiltInType,
  recursive/array-capable value encoding -- is now fully implemented too, which
  promoted Read, Write, and Call to full field decoding: ReadResponse's own Results,
  WriteRequest's own NodesToWrite, and Call's own Input/Output Arguments are all
  genuinely decoded down to the actual process/tag values, not just named.
  Everything still needing that encoding but NOT actually carrying one in its own
  body (Browse, Subscribe/MonitoredItem management, and more) stays named via its
  own service TypeId with RequestHeader/ResponseHeader decoded but its body shown as
  raw hex -- a deliberate scope line, not a gap in the value-decoding itself. The
  structural detection gate (MessageType against 7 fixed 3-byte ASCII strings) is
  strong enough, and confirmed collision-free with every other protocol's own gate,
  that it's tried first in the dispatch chain -- the opposite ordering rationale
  from HART-IP's own weak-gate "tried last" placement. A real capture was found and
  validated: two OPC UA sessions from a well-known, widely-mirrored Wireshark
  dissector-bug reproduction capture (Bug 3986, 2009), on a non-standard TCP port
  (12001, not 4840) that Wireshark's own *default* configuration doesn't even
  recognize as OPC UA -- this decoder does, without any port hint, cross-checked
  field-by-field against tshark's own OPC UA dissector (via "Decode As") once
  pointed at the right port; see tests/real_captures/opcua/ATTRIBUTION.md for the
  full writeup, including the two genuinely malformed CallRequest packets (one of
  which triggered Wireshark's own 2-minute dissector freeze) that this decoder's own
  bounds-checked Variant/DataValue reads now correctly DETECT as malformed -- see
  include/conduitscope/opcua.hpp's file header for the full writeup.
- IEC 61850 MMS (Manufacturing Message Specification, ISO 9506) over the same
  TPKT/COTP transport S7comm shares (TCP port 102): the full ISO stack an MMS PDU
  actually rides on is decoded, not just the MMS PDU itself -- Session (ISO 8327-1,
  SPDU type and its User Data parameter), Presentation (ISO 8823, the presentation-
  context-definition-list and its "1=ACSE / 3=MMS" convention), and ACSE (ISO 8650-1,
  AARQ/AARE/RLRQ/RLRE/ABRT, association time only) all render as named fields, not
  raw hex. Real IEC 61850 traffic genuinely takes three different shapes at this
  boundary -- a full Session/Presentation/ACSE association, an ongoing message that
  skips straight to a bare MMS PDU with nothing above it, and (a shape this
  decoder's own real-capture validation specifically found) an ongoing message that
  skips only Session, landing straight on Presentation bytes -- and all three are
  recognized by their own structural gate, not guessed at. MMS's own self-describing
  `Data` value type (14 of its 17 CHOICE alternatives, including FloatingPoint,
  UtcTime, and nested array/structure with a hard recursion-depth cap) is fully
  decoded -- unconditionally, for every MMS service that carries one, unlike this
  codebase's own OPC UA decoder, whose analogous Variant/DataValue type is fully
  decoded too but only for the three services (Read/Write/Call) actually promoted
  to full decode; Browse and the subscription services still leave it as raw hex.
  At the service layer, a deliberate two-tier split mirroring OPC UA's own: 18 of
  MMS's 78
  confirmedServiceRequest/Response alternatives (status, getNameList, identify,
  read, write, getVariableAccessAttributes, defineNamedVariableList,
  getNamedVariableListAttributes, deleteNamedVariableList, getDomainAttributes,
  getCapabilityList, plus the seven file-transfer services obtainFile, fileOpen,
  fileRead, fileClose, fileRename, fileDelete, fileDirectory -- IEC 61850's own
  COMTRADE/disturbance-file-retrieval workflow rides on exactly these seven) are
  fully field-decoded, InformationReport (the MMS analog of
  this codebase's own GOOSE decoder) is fully decoded, and every other named
  service -- takeControl among them -- is recognized and named but shown as raw
  hex. initiate-Request/ResponsePDU, ServiceError, RejectPDU, and the Cancel-*/
  Conclude-* PDU families are all decoded too. Three small real captures (a full
  association plus a Read/conclude exchange with two genuinely malformed frames;
  two entirely bare-MMS captures, takeControl/relinquishControl and
  cancelRequest) were found and validated, plus a much larger one (224 frames)
  this project generated itself against a real, independent MMS stack
  (mz-automation/libiec61850) rather than against this decoder's own output. That
  validation caught two genuine structural-gate bugs -- both found and fixed, not
  just discovered and left -- and independently reproduced a real recursion-depth
  assertion failure in tshark 4.2.2's own MMS dissector on ordinary, non-malicious
  traffic (motivating this decoder's own recursion-depth cap); see
  tests/real_captures/mms/ATTRIBUTION.md for the full writeup and
  include/conduitscope/mms.hpp for the wire-format details.
- MQTT (v3.1/v3.1.1/v5.0, conventionally TCP port 1883) and Sparkplug B (the
  Eclipse Tahu IIoT convention layered on top of it): documented honestly as
  having the weakest structural detection gate in this codebase -- MQTT has
  no fixed magic number or length field this decoder can key off unambiguously,
  so it's dispatched dead last, after every other protocol (including
  HART-IP's own already-weak gate) has had a chance to claim the bytes first.
  Real validation against this codebase's own real-capture test set found two
  genuine cross-protocol collisions this ordering alone didn't fully solve --
  a v5 CONNACK payload that coincidentally satisfied Modbus/TCP's
  `protocol_id==0` tell, and small MQTT packet identifiers that coincidentally
  satisfied HART-IP's own weak `message_type`/`message_id` gate -- both found
  and fixed (a missing length-plausibility cap added to Modbus's TCP parser,
  and a test-fixture-side change for the HART-IP case, deliberately without
  weakening HART-IP's own otherwise-sound gate). Once traffic is recognized as
  MQTT, CONNECT/CONNACK/PUBLISH/SUBSCRIBE/SUBACK/UNSUBSCRIBE/UNSUBACK/
  PINGREQ/PINGRESP/DISCONNECT/AUTH are all field-decoded across all three
  protocol versions, with MQTT5's Properties (a TLV scheme absent from 3.1/
  3.1.1) fully parsed, not just skipped. Because SUBSCRIBE/SUBACK/UNSUBSCRIBE's
  own wire shapes are ambiguous between MQTT versions, this decoder tracks
  each TCP session's version from its own CONNECT packet rather than
  guessing per-packet where it can help it. CONNECT's cleartext username/
  password fields are decoded as a deliberate security finding, not omitted --
  this protocol has no transport encryption of its own, and seeing credentials
  in the clear here is the point. Sparkplug B's protobuf-encoded payloads
  (NBIRTH/NDEATH/DBIRTH/DDEATH/DDATA/NDATA, the `spBv1.0/...` topic
  convention) are decoded via a hand-rolled Protocol Buffers reader (no
  external protobuf dependency), including the typed Metric value union and
  nested Template/DataSet metric types. A real capture was found and
  validated -- a genuine Eclipse Paho client's MQTT 3.1 traffic (not just
  3.1.1/5.0) -- and it immediately found a real bug this decoder's own
  synthetic fixture had never exercised: MQTT 3.1's session-version tracking
  was silently never learned at all (only 3.1.1 and 5.0 were), so every
  SUBSCRIBE/SUBACK/PUBLISH after a real MQTT 3.1 CONNECT fell back to weaker
  per-packet heuristics instead of the CONNECT that was right there; found and
  fixed. No real Sparkplug B capture was found despite a genuine search
  (this is the one gap honestly documented, not swept under the rug) -- see
  tests/real_captures/mqtt/ATTRIBUTION.md for the full writeup and
  include/conduitscope/mqtt.hpp for the wire-format details.
- S7comm-Plus (Siemens TIA Portal / S7-1200/1500's newer, object-oriented
  protocol), over the same TPKT/COTP transport and TCP port 102 classic
  S7comm and MMS share, disambiguated by its own protocol id byte (`0x72` vs
  classic S7comm's `0x32`): unlike every other protocol this codebase
  supports, S7comm-Plus has never been officially published by Siemens --
  no standards document, no ASN.1 module -- so every byte-layout fact this
  decoder asserts is sourced from the open-source Wireshark plugin
  `packet-s7comm_plus.c` (Thomas Wiens, the same author as classic S7comm's
  own mainline dissector), itself the product of years of community
  reverse-engineering; that honesty (including a couple of the original
  German source comments' own hedges, "seems to be", "currently unknown")
  is carried through rather than rounded up to false confidence. A two-tier
  split, same posture as MMS/OPC UA above: GetMultiVariables/
  SetMultiVariables (TIA Portal's functional replacement for classic
  S7comm's Read Var/Write Var, and what dominates real traffic),
  SetVariable, and DeleteObject are fully decoded in both directions,
  including the protocol's own native symbolic item addressing (a CRC-like
  hash of the compiled symbol name plus a chain of struct/array-member
  "LID" values -- genuinely native, unlike classic S7comm's own
  EXPERIMENTAL `0xB2` reconstruction, though a LID's/CRC's *symbolic
  meaning* is inherently unresolvable without TIA Portal's own project
  database, same class of limitation as DNP3/OPC UA point indices) and the
  self-describing `Value` encoding (20+ datatypes, INCLUDING recursively
  nested STRUCT values -- confirmed against real Struct-of-Struct traffic,
  not just a synthetic fixture). Connect (session handshake), Notification
  (the cyclic/subscribed-variable feed), CreateObject, Explore, GetLink,
  BeginSequence/EndSequence, Invoke, and GetVarSubStreamed are all
  recognized and named but not body-decoded; DataFW1_5 (firmware >= V1.5)
  gets header-only decode, a deliberately more conservative scope cut after
  this decoder could not independently confirm the reference plugin's own
  byte-accounting for where that variant's body actually starts. Checksums/
  digests (the Integrity part's SHA-256-sized value) are surfaced, never
  verified (DNP3's data-link CRCs and HART-IP's own Data-Link Checksum, by
  contrast, are now genuinely validated -- see below). Two real S7-1511
  captures --
  originally added to this project only to validate the old "detected, not
  decoded" stub -- were re-decoded once full support existed: real HMI
  traffic exercising GetMultiVariables/SetMultiVariables/DeleteObject
  Tier-1 decoding (including a genuinely nested Struct-of-Struct-with-Blob
  value) and Connect/GetVarSubStreamed Tier-2 recognition, plus a
  40-item-in-one-request "all types" capture walking nearly every datatype
  this decoder knows -- zero per-item decode errors in either file. This
  project's own code review (not real-capture validation) caught two
  genuine correctness bugs before this decoder was ever built or tested: an
  array-of-Struct value that this decoder cannot safely delimit per-element
  (now a deliberate, explicit refusal rather than a silent misalignment
  risk) and an unsigned-integer-underflow risk in a truncated-frame length
  calculation. See tests/real_captures/s7comm/ATTRIBUTION.md's own
  S7comm-Plus addendum and include/conduitscope/s7commplus.hpp for the
  wire-format details.
- FOUNDATION Fieldbus HSE (FF-HSE, ports 1089/1090/1091/3622 for
  FDA/FMS/SM/LAN Redundancy respectively, TCP and UDP -- but the
  sub-protocol is signaled in-band by the header itself, so every port is
  an "expected port" annotation only, never a detection gate): FF-HSE's own
  official FieldComm Group specifications are all paywalled, so every byte
  offset this decoder asserts is instead cross-checked against Wireshark's
  own mainline dissector, `packet-ff.c`/`packet-ff.h` (GPL-2.0-or-later,
  vendor-authored by Yukiyo Akisada, a Yokogawa engineer, directly against
  the official FF-588-1.3 spec with inline spec-clause citations) -- a raw
  copy of that dissector source was available for direct inspection, not
  just a secondhand transcription, which is what let the full ErrorClass/
  ErrorCode tables and every FDA/SM/FMS/LAN Redundancy service name be
  pulled byte-for-byte rather than approximated. The same two-tier split
  this codebase already applies to MMS/OPC UA/S7comm-Plus: the 12-byte
  common header, its Options/trailer bitmask fields, and the great majority
  of FDA/SM/LAN Redundancy messages plus FMS's own session-lifecycle/
  status/identify/read/write family are fully decoded, while FMS's Get OD,
  Define/Delete Variable List, the Download/Upload and Program Invocation
  families, and unconfirmed Event Notification are named only, shown as raw
  hex (FMS Get OD is left undecoded even by the reference dissector itself,
  since OD entries depend on Device Description content neither has
  access to). The single trickiest piece is the LinkId branch shared by SM
  Identify Rsp and SM Device Annunciation: a 108-byte fixed body plus a
  trailing version-number list whose *internal* shape (2-byte pairs vs.
  4-byte quads) depends on a LinkId value computed from the 12-byte
  header's own FDA Address field, not anything inside the message body --
  documented explicitly since getting it backwards would silently
  misinterpret every list entry after the first. This decoder's own
  structural detection gate is honestly the **weakest in this codebase**:
  a single byte at header offset 2, landing on one of 12 valid values out
  of 256 -- weaker even than HART-IP's already-weak two-byte gate -- so
  FF-HSE is dispatched dead last in Auto mode, after every other protocol
  here including HART-IP and MQTT, on both TCP and UDP. No distinct cyclic
  Publisher/Subscriber message shape was found anywhere in the reference
  source, so this decoder's best guess that HSE's cyclic/multicast
  function-block traffic reuses the FMS Information Report family (Service
  Ids 0/16/17/18) is flagged everywhere as an unconfirmed inference, never
  asserted as fact. No public real-world FF-HSE capture could be found
  (the usual ICS pcap collections predate it or don't cover it, and a
  small synthetic capture referenced in a Wireshark GitLab bug report
  could not be retrieved either) -- this decoder is therefore validated
  only against its own synthetic fixture. See docs/USER_GUIDE.md's FOUNDATION
  Fieldbus HSE section and include/conduitscope/ffhse.hpp for the full
  wire-format details.
- IEEE Spanning Tree Protocol (STP/RSTP/MSTP): the first protocol this tool
  decodes that's reached neither through IPv4 nor through a DIX Ethernet II
  EtherType -- a BPDU rides classic IEEE 802.3 length-framed Ethernet, with a
  3-byte LLC header (DSAP=SSAP=`0x42`, the Bridge Group Address SAP)
  underneath, which required teaching `link_layer.hpp` the length-vs-EtherType
  boundary and LLC/SNAP framing (additive groundwork -- every existing
  EtherType-keyed protocol is unaffected). Classic Configuration BPDUs, TCN
  (Topology Change Notification) BPDUs, RST BPDUs (RSTP/MSTP's shared 36-byte
  shape), and the full MST BPDU extension (including every MSTI Configuration
  Message and the reference source's own Cisco-C3550-firmware Version-3-
  Length work-around) are all decoded. Cisco PVST+/Rapid-PVST+ (a different,
  SNAP-encapsulated envelope), SPB (802.1aq), the legacy/alternative MSTI
  format, and GARP/GVRP/GMRP (which shares STP's own LLC SAP pair, the one
  case in this codebase where destination MAC genuinely gates detection
  rather than a structural check) are all recognized and named but not
  decoded further. Validated against two real captures (42 classic
  Configuration BPDUs from one bridge's steady-state Hello traffic, and 12
  real RSTP RST BPDUs from six port pairs) -- both confirm periodic
  Hello-interval BPDU transmission from an already-converged bridge, but
  neither exercises a TCN, MSTP, SPB, Proposal/Agreement, or a non-Designated
  Port Role on real bytes; those paths are validated only against the
  synthetic `tests/sample_stp.pcap` fixture, whose first two packets
  reproduce the real captures' own frames byte-for-byte. See
  tests/real_captures/stp/ATTRIBUTION.md and
  include/conduitscope/stp.hpp for the full writeup.
- DeviceNet (CAN-bus CIP): the second wholly new link layer this tool has
  added, and a completely separate one from Ethernet -- a pcap capture of a
  CAN bus (`LINKTYPE_CAN_SOCKETCAN`, what `candump -l`/`tcpdump -i can0`
  write) carries no MAC addresses, no IP layer, no EtherType at all, just
  an 8-byte SocketCAN record per CAN frame, dispatched through its own
  top-level branch in `Decoder::decode` rather than through
  `parse_ethernet`. CAN 11-bit standard identifiers are classified into 4
  message groups (I/O data, master/scanner commands plus Duplicate-MAC-ID-
  Check, unconnected explicit CIP messaging, and offline/fault
  notifications), each with its own MAC-ID bit layout, cross-checked
  directly against Wireshark's own `packet-devicenet.c`. Group 3's own CIP
  explicit-message service codes reuse this codebase's existing
  `cip_service_name` (from `enip.cpp`) for the shared CIP common-services
  set, adding DeviceNet's own four extra codes (Open/Close Explicit Message
  Connection, Device Heartbeat, Device Shutdown). Extended (29-bit) IDs,
  RTR, and error frames aren't valid DeviceNet at all and are rejected
  outright; CAN FD frames are recognized but not semantically decoded
  (DeviceNet predates CAN FD); Group 3 fragmentation is flagged but not
  reassembled, matching Wireshark's own dissector's own unimplemented TODO,
  not a gap unique to this port. No real public DeviceNet/CAN-bus capture
  could be found anywhere (including `ITI/ICS-Security-Tools`, the source
  of several other real captures already used here) -- validated only
  against the synthetic `tests/sample_devicenet.pcap` fixture. ControlNet,
  the other CIP-family protocol requested alongside DeviceNet, is
  deliberately NOT included: it rides a proprietary physical layer (RG-6
  coax, Manchester coding, token-passing) that no pcap-based tool --
  Wireshark included, which has no ControlNet dissector at all -- can ever
  capture; the only real way to observe it is Rockwell's own proprietary
  ControlNet Traffic Analyzer, which produces no pcap-compatible output.
  See docs/USER_GUIDE.md's DeviceNet section and
  include/conduitscope/devicenet.hpp for the full writeup.
- DNS, mDNS, LLMNR, NetBIOS Name Service (NBT-NS), and DNS-over-HTTPS (DoH)
  detection: the first name-resolution protocols decoded here, and the
  first anywhere in this codebase deliberately **port-gated** in
  `--protocol auto` rather than tried opportunistically port-independent --
  none of the four DNS-shaped protocols has a self-describing wire-format
  signal strong enough to check safely against every UDP payload the way
  every other protocol here does, so detection only runs against traffic on
  each protocol's standard port (or one added via `--dns-port`/
  `--mdns-port`/`--llmnr-port`/`--nbns-port`/`--doh-port`), unless the
  protocol is selected explicitly with `--protocol`. DNS (port 53), mDNS
  (port 5353), and LLMNR (port 5355) share one implementation, since RFC
  6762 and RFC 4795 both explicitly reuse RFC 1035's wire format verbatim,
  differing only in a few header-bit meanings and, for mDNS, two
  class-field top-bit reinterpretations (the QU and cache-flush bits);
  "first pass" RDATA decoding covers A/AAAA/NS/CNAME/PTR/MX/SOA/TXT/SRV,
  with EDNS0's OPT pseudo-record correctly recognized. NBT-NS (port 137,
  RFC 1002) gets its own decoder, including first-level NetBIOS name
  encoding, NB (address) and NBSTAT (name table) resource records, and the
  Microsoft/Wireshark suffix-byte convention for what service a name
  represents. DoH is detection-only, by necessity, not choice -- its actual
  DNS content is TLS-encrypted and invisible to any pcap-based tool without
  the session's own decryption keys -- so it works by matching a TLS
  ClientHello's plaintext SNI against a curated table of a dozen known
  public DoH resolvers (Cloudflare, Google, Quad9, OpenDNS, AdGuard,
  NextDNS, and more); a private/enterprise resolver not on that table is
  never flagged, since there's no other signal available. Deliberately out
  of scope for this pass: DNS-over-TCP, DoT/DNS-over-QUIC content, and
  wiring any of these five into `policy validate`'s conduit `protocols`
  classification. Validated against hand-built fixtures cross-checked
  against their governing RFCs, including deliberate negative-control
  packets for every detection gate -- see docs/USER_GUIDE.md's PROTOCOL
  COVERAGE and LIMITATIONS.
- Non-IPv4 Ethernet frames and non-TCP IPv4 payloads (including UDP) are now
  recognized and named, not just reported as a bare hex/number and dropped:
  ARP, LLDP, PTP, MPLS, and stacked-VLAN (802.1ad/QinQ) EtherTypes; ICMP,
  GRE, ESP, AH, and SCTP IP protocol numbers; and the UDP header
  itself (source/destination port, byte count) -- EtherNet/IP's own UDP port
  (2222) is decoded, not just named, when the traffic on it actually looks
  like CIP I/O (see above), PROFINET RT's EtherType is decoded, not just
  named, when the FrameID looks like DCP or cyclic IO data (see above), and
  IEC 61850-8-1 GOOSE's, IEC 61850-9-2 Sampled Values', and EtherCAT's own
  EtherTypes are all decoded, not just named, when their own structural gate
  matches (see above). IGMP (IP protocol 2), VRRP (IP protocol 112), IGRP
  (IP protocol 9), PIM (IP protocol 103), EIGRP (IP protocol 88), and OSPF
  (IP protocol 89) are likewise decoded, not just named, when their own
  structural gate matches -- see the RIP/IGMP/VRRP/HSRP and IGRP/PIM/EIGRP/
  OSPF bullets below. This is otherwise groundwork
  plumbing, not a new protocol decoder -- none of the remaining
  named-but-not-decoded protocols' own framing is parsed any further yet,
  and `policy validate` does not yet evaluate any non-TCP traffic against
  any conduit (still counted as `skipped_non_tcp`, same as before) -- but
  it's a real, confirmed visibility gap this closes: re-running
  conduitscope's own real-capture test set after adding this surfaced
  genuine ARP and UDP (DNS,
  NetBIOS) traffic that was previously invisible. See docs/PROTOCOL_COVERAGE.md and docs/DEVELOPMENT.md's ROADMAP section.
- RIP (v1/v2), IGMP (v1/v2/v3), VRRP (v2/v3), and HSRP (v1/v2) decoding: the
  first batch of a broader routing/redundancy-protocol addition (IGRP, PIM,
  EIGRP, and OSPF now also done -- see the bullet below; BGP planned for a
  later round; IS-IS deliberately deferred further still, since it rides
  the data-link layer directly like STP rather than as an IP payload).
  Added because IGMP underlies GOOSE/SV's own
  routable multicast variants, and because VRRP/HSRP are a straightforward
  gateway-spoofing/MITM primitive worth surfacing regardless of whether a
  segment is "OT" or "IT". RIP (UDP port 520) and HSRP (UDP port 1985) join
  the DNS family above in being **port-gated** in `--protocol auto` (widen
  with `--rip-port`/`--hsrp-port`, or bypass with `--protocol rip`/`hsrp`);
  IGMP and VRRP need no port gate at all, dispatched purely by their own
  IANA-exclusive IP protocol number (2 and 112). RIP's Simple Password and
  VRRPv2's Simple Text Password authentication are decoded as the cleartext
  they are; RIP's Keyed MD5 auth-header fields are decoded but its trailing
  digest is neither located nor verified. A real dispatch-order collision
  was found and fixed while building this: a synthetic HSRPv1 message
  satisfied FF-HSE's own weaker, fully opportunistic gate until RIP/HSRP
  were moved ahead of it in the UDP dispatch chain. Validated against
  hand-built fixtures cross-checked against their governing RFCs and
  Wireshark's own dissector source, plus one real capture for IGMP (12
  genuine IGMPv3 Membership Reports trimmed from the same `Plant1.pcap`
  this project's STP/PROFINET/CIP-I/O fixtures already draw from -- see
  `tests/real_captures/igmp/ATTRIBUTION.md`); a 498-file search across three
  public ICS pcap collections for the same effort found no RIP, VRRP, or
  HSRP traffic anywhere, so those three remain synthetic-only, the same
  accepted gap already documented for FF-HSE/DeviceNet. See
  docs/PROTOCOL_COVERAGE.md, docs/DEVELOPMENT.md's PROTOCOL DETECTION
  section, and docs/USER_GUIDE.md's LIMITATIONS section.
- IGRP, PIM v2 (PIM-SM/PIM-DM), EIGRP (now RFC 7868), and OSPFv2 (RFC 2328)
  decoding: the second batch of the routing/redundancy-protocol addition
  begun above. All four ride directly on IP (protocol numbers 9, 103, 88,
  and 89, all IANA-exclusive) with no UDP/TCP header and therefore no port
  concept at all, the same "no port gate needed" shape IGMP/VRRP already
  have. IGRP's classful route encoding reconstructs an Interior route's full
  address by borrowing the packet's own source IP octet; EIGRP decodes both
  the legacy Classic and current Wide-Metric route TLV formats, including
  the compound-TLV case where one TLV carries several destination prefixes
  sharing a next-hop/metric; PIM decodes all six common message types
  (Hello, Register, Register-Stop, Join/Prune/Graft/Graft-Ack, Bootstrap,
  Assert, Candidate-RP-Advertisement); OSPFv2 decodes Hello, DB Description,
  LS Request, LS Update (with Router/Network/Summary/AS-External LSA
  bodies), and LS Ack. EIGRP's and OSPF's own MD5/Cryptographic
  authentication header fields are decoded but their digests are neither
  located nor verified, the same posture as RIP's Keyed MD5 above. BGP, the
  one protocol from the original request that rides over TCP instead of
  directly on IP, is deliberately not part of this batch and remains
  planned for a later round. Validated against hand-built fixtures
  cross-checked against Wireshark's own dissector source (and RFCs, where
  one exists -- IGRP predates the IETF RFC process for routing protocols);
  the same 1,020-file search across three public ICS pcap collections that
  found no RIP/VRRP/HSRP traffic found none of these four either, so all
  four remain synthetic-only, the same accepted gap already documented
  above. See docs/PROTOCOL_COVERAGE.md, docs/DEVELOPMENT.md's PROTOCOL
  DETECTION section, and docs/USER_GUIDE.md's LIMITATIONS section.
- IPv4 payload is clamped to the header's own `total_length` field, so
  Ethernet's minimum-frame-size padding on short packets (bare ACKs, mostly)
  never gets misreported as phantom TCP payload -- found and fixed against a
  real capture, not just synthetic traffic
- General TCP stream reassembly at the PDU/frame level: a Modbus MBAP
  message, a DNP3 data-link frame, an IEC 104 APDU, an EtherNet/IP
  encapsulation message, a TPKT/COTP frame, a HART-IP message, or an OPC UA
  UA-TCP/Secure Conversation chunk
  split across two or more TCP segments is buffered per directional flow and decoded once
  complete, using each protocol's own declared-length field to know how many
  bytes to wait for. OPC UA's own declared-length check is tried FIRST in this
  chain (its structural gate is strong and collision-free -- see above), while
  HART-IP's own is tried LAST, deliberately, because of the Modbus-collision
  limitation described above. Resyncs rather than reorders on capture gaps, and trims
  overlapping retransmissions rather than duplicating bytes. Verified
  byte-for-byte behavior-identical against every real capture in this
  project's test set -- including, now, OPC UA's own real capture, which
  genuinely exercises this machinery: two responses split across 5 and 6 TCP
  segments respectively, reassembled and decoded correctly -- and against 6
  synthetic scenarios covering the happy path plus gaps,
  full-duplicate retransmits, and partial-overlap retransmits; see
  docs/USER_GUIDE.md's LIMITATIONS for exact scope. Modbus request/response
  pairing and multi-frame S7comm chaining are separate mechanisms, described
  above, not part of this one
- Text, JSON, and CSV output; a `--stats` summary mode; an `info` command for
  quick file metadata. Text output is colorized (per-protocol tags, red for
  exceptions/parse-errors) when writing to an interactive terminal, or
  forced on/off with `--color`/`--no-color`
- `decode` shows a VLAN-tagged packet's 802.1Q VLAN ID by default (`eth ...
  vlan 100` in text, `has_vlan_tag`/`vlan_id` in JSON, a trailing `vlan_id`
  column in CSV) -- `--no-vlan` suppresses it
- HART-IP's own classic wired-HART longitudinal (XOR) Data-Link Checksum is
  now computed and verified against the wire byte, not just surfaced raw --
  a mismatch is flagged as its own note / `hartip_checksum_valid: false`
- Tier 1 of the "IT protocols an OT auditor flags" family (see ROADMAP item
  18): RDP, VNC, TeamViewer, AnyDesk, and Zoom are each recognized by name
  (their own `protocol` value, not folded into a generic `tcp`/`udp`
  bucket) -- name-only, never decoded further, the same "recognized but
  not decoded" posture ARP/LLDP/ICMP already have. VNC's RFB protocol-
  version banner and RDP's initial X.224 Connection Request/Confirm
  (reusing this project's own TPKT/COTP parser) are genuine cleartext
  structural signatures; TeamViewer, AnyDesk, and Zoom have none and are
  recognized by port number alone, the weakest identification gate in this
  codebase. `--protocol remote-access` isolates the family;
  `--remote-access-port` widens its expected-port set. See
  docs/PROTOCOL_COVERAGE.md "Tier 1 remote-access protocol
  recognition" section
- Tier 2 of the same family: SMB, SSH, HTTP, HTTPS, SNMPv1/v2c, Telnet,
  FTP, and TFTP -- the lateral-movement/credential-harvesting protocols
  most hardening guides say shouldn't be on a production OT segment at
  all. SMB's direct-hosting magic, SSH's version-exchange banner, and
  HTTP's own request-line/status-line are genuine, port-independent
  structural signatures; HTTPS reuses this project's own TLS ClientHello
  parser (already built for DoH detection); SNMPv1/v2c genuinely extracts
  and surfaces the cleartext community string itself, since that string is
  the whole audit finding; Telnet/FTP/TFTP each have a narrower,
  port-gated signal. `--protocol lateral-movement` isolates the family;
  `--lateral-movement-port` widens its expected-port set. See
  docs/PROTOCOL_COVERAGE.md "Tier 2 lateral-movement protocol
  recognition" section
- Tier 3 of the same family: NTP, DHCP, LDAP, LDAPS, RADIUS, TACACS+, and
  IEEE 802.1X/EAPOL -- protocols "individually unremarkable in limited
  form but worth an auditor's attention for where they terminate and
  whether the OT side blindly trusts enterprise IT for them." DHCP's own
  magic cookie and LDAPS's TLS ClientHello (the latter layered into the
  same early call site HTTPS's own uses) are genuine, port-independent
  structural signatures; NTP/LDAP/RADIUS/TACACS+ each have a genuine but
  narrower, port-gated signal; TACACS+'s own unencrypted-body flag is
  surfaced as its own note when set. EAPOL rides raw Ethernet (EtherType
  `0x888E`, no port at all, like PROFINET/GOOSE/SV/EtherCAT) and gets its
  own dedicated `--protocol eapol` value -- its presence on an OT switch
  port is reassuring (the device had to authenticate), so its *absence*
  is often the actual finding, the one protocol in this whole family
  where that polarity is reversed. `--protocol enterprise-trust` isolates
  the six port-based protocols; `--enterprise-trust-port` widens their
  shared expected-port set. See docs/PROTOCOL_COVERAGE.md "Tier 3
  enterprise-trust-boundary protocol recognition" section
- Tier 4 of the same family: CAPWAP control/data, LWAPP control/data,
  GTP-U, and PPPoE -- "wireless access-point control/data planes and
  cellular backhaul," where an AP or wireless LAN controller reachable
  from an OT zone is itself a finding, independent of whatever rides
  inside its tunnel. CAPWAP control/data (RFC 5415) share a modest but
  genuine Preamble/HLEN structural check, with CAPWAP control additionally
  naming its own Message Type when resolvable; LWAPP control/data (CAPWAP's
  never-standardized Cisco-proprietary predecessor) are recognized by port
  number alone; GTP-U (3GPP TS 29.281) has a genuine Version/PT structural
  signature and surfaces its own TEID without ever unwrapping the tunneled
  G-PDU's inner IP packet. PPPoE rides raw Ethernet (EtherType `0x8863`
  Discovery / `0x8864` Session, no port at all, like EAPOL) and gets its
  own dedicated `--protocol pppoe` value; a Session-stage frame's
  encapsulated PPP Protocol field is named, and a PAP frame earns a
  cleartext-credential note. `--protocol wireless-backhaul` isolates the
  five port-based protocols; `--wireless-backhaul-port` widens their shared
  expected-port set (and, unlike Tier 3, always gates detection itself,
  since none of this tier's checks are strong enough to run
  port-independently). See docs/PROTOCOL_COVERAGE.md "Tier 4
  wireless-backhaul-and-cellular protocol recognition" section
- Tier 5 of the same family, and the last: GRE (and its NVGRE/Mikrotik
  EoIP sub-cases), IPsec ESP/AH, IP-in-IP, 6in4, L2TP/L2TPv3, IKE, VXLAN,
  Geneve, WireGuard, OpenVPN, a generic DTLS-tunnel structural check, STT,
  and MPLS -- "generic tunnel/VPN encapsulation," the broader problem
  CAPWAP/GTP-U above are specific instances of: an inner VLAN, Modbus
  session, or entire plant subnet is invisible to every decoder (and to
  `policy validate`'s own flow model) until the outer tunnel is stripped
  off, so merely naming the outer protocol is already a finding.
  GRE/ESP/AH/IP-in-IP/6in4/L2TPv3's own direct-IP form ride raw IP with no
  port at all (GRE's own Protocol Type field further splits it into
  plain-GRE/NVGRE/EoIP); IP-in-IP is the one deliberate exception to this
  whole tier's "name it, don't unwrap it" posture, surfacing its inner
  src/dst IPv4 addresses since they sit in plaintext right after the outer
  header. IKE, L2TP-over-UDP, VXLAN, Geneve, WireGuard, and OpenVPN are
  UDP/TCP-port-keyed, each with its own genuine structural signature
  (WireGuard's exact-length match is the strongest in this entire tier);
  port 4500 additionally disambiguates IKE-over-NAT-T from raw
  NAT-Traversed ESP via RFC 3948's own non-ESP marker. A generic
  dtls-tunnel check is tried port-independently, last among every UDP
  check. STT is recognized by port number alone. MPLS rides raw Ethernet
  (EtherType `0x8847`/`0x8848`, no port at all, like EAPOL/PPPoE) and gets
  its own dedicated `--protocol mpls` value, with its full label stack
  genuinely parsed. `--protocol tunnel-vpn` isolates the fourteen
  port/IP-protocol-number-based protocols; `--tunnel-vpn-port` widens
  their shared expected-port set. See docs/PROTOCOL_COVERAGE.md
  "Tier 5 generic tunnel/VPN encapsulation recognition" section
- Name resolution, shared by `decode` and `policy validate` alike: OUI/MAC-
  vendor lookup against a built-in IEEE-registry-derived table (on by
  default, `--no-oui` disables it), hostname resolution from an explicitly-
  supplied `--hosts` file (`--resolve`, file-only -- never live DNS, under
  any circumstance), and port->service-name lookup from a small curated
  built-in table plus an optional `--services` file (`--nn` disables it).
  Every annotation is additive next to the raw MAC/IP/port already decoded,
  never a replacement for it -- see docs/USER_GUIDE.md's OUTPUT FORMATS "Name
  resolution" subsection
- `policy validate`: a zone/conduit policy engine. A policy file (a
  deliberately restricted, dependency-free YAML subset -- no vendored YAML
  library, same zero-dependency approach as everything else here) declares
  zones and conduits. A zone is EITHER a set of IPv4 CIDR blocks OR a set
  of VLAN IDs (`vlans: [...]`, a zone kind added specifically for the four
  protocols with no IP layer at all -- see below), never both. An IPv4-zone
  conduit is an allowed protocol+port relationship, in a given direction,
  from a set of one or more zones to another set of one or more zones
  (many-to-many, not just one zone to one zone), optionally narrowed with
  `functions:` to only certain named functions/services within a conduit's
  one protocol (e.g. Modbus reads but not writes) -- matched against the
  exact function/service name strings each protocol's own decoder emits.
  `protocols`/`protocol` names one of sixteen values -- `modbus`, `dnp3`,
  `s7comm`, `iec104`, `enip`, `bacnet`, `hartip`, `opcua`, `mms`, `mqtt`,
  `ffhse`, `profinet`, `goose`, `sv`, `ethercat`, or the wildcard `any` --
  though `bacnet` can never actually match (this decoder only recognizes
  BACnet/IP over UDP, and IPv4-zone conduits are TCP-only), and
  `functions:` is only supported so far for the first five (see
  docs/USER_GUIDE.md's "Addressing scope" and "Function-level restrictions"
  subsections). Every decoded TCP flow in the capture is classified into a
  zone pair, checked against the policy's conduits (and, for a
  `functions`-restricted conduit, checked flow-wide against every distinct
  function/service observed), and reported as allowed, a violation, or
  unclassified (an endpoint matching no declared zone, or a flow with no
  recognized protocol at all) -- text or JSON output, a distinct exit
  status for "found problems" vs. "couldn't run" vs. "clean", and a report
  that also lists any conduit the capture never exercised. A VLAN-zone
  conduit (`from`/`to` naming only VLAN zones -- and required to name the
  exact same zone set on both sides, since a single raw-Ethernet frame
  carries at most one VLAN tag and so has no separate "source"/
  "destination" zone the way a TCP flow does) instead classifies PROFINET
  RT/GOOSE/Sampled Values/EtherCAT traffic -- aggregated into "L2 flows" by
  protocol + MAC pair -- by whether its own 802.1Q tag falls within a
  declared VLAN zone, reported the same three ways (allowed/violation/
  unclassified) in a parallel "Ethernet flows" section of the same report;
  a policy declaring no VLAN zones behaves exactly as before this existed.
  Built entirely on top of the decoding layer above (S7comm item tags,
  decoded DNP3 point values, Modbus address+quantity decoding, authoritative
  Modbus request/response pairing, and the already-decoded generic 802.1Q
  tag are exactly the concrete facts this checks policy against) rather
  than duplicating any of its parsing. See docs/USER_GUIDE.md's POLICY FILE
  FORMAT section (including its "Function-level restrictions" and
  "Addressing scope" subsections) for the full schema and LIMITATIONS for
  exactly what it does and doesn't check (e.g. the SYN-based
  flow-direction heuristic's fallback case, and the VLAN-zone model's own
  QinQ/directionality/`functions` limits).
- `inventory`: passive OT asset inventory, the opposite direction from
  `policy validate` -- infers a first-draft zone/conduit model from a
  capture instead of checking one against a hand-written policy. Recognizes
  the same five protocols this decoder's own `PolicyEngine` does (Modbus,
  DNP3, S7comm, EtherNet/IP -- both TCP explicit messaging and UDP/2222 CIP
  I/O -- and BACnet/IP); builds an asset list (IP/MAC, OUI vendor guess,
  protocols spoken, client-vs-server role -- BACnet's client/server, which
  both conventionally share UDP port 47808, is disambiguated by
  Confirmed-Request/Unconfirmed-Request vs. ACK/Error/Reject/Abort APDU
  type rather than the usual known-port heuristic) and a communication
  matrix; groups assets into zones by observed subnet (`--zone-prefix`,
  default `/24`); infers a conduit for every distinct zone-pair/protocol/
  port combination actually observed, intra-zone or cross-zone alike;
  renders a Mermaid or Graphviz `.dot` diagram (`--diagram`); and, via
  `--policy-out`, writes the inferred model as a `policy`-format YAML file
  directly loadable by `policy validate --policy` -- closing the loop:
  discover, then enforce (a generated file round-trips cleanly against the
  same capture, with the UDP-based conduits correctly reported as
  "never exercised" since `policy validate` is TCP-only today -- see
  LIMITATIONS). See docs/USER_GUIDE.md's `inventory` subsection for a worked
  example.
- Live capture (`decode -i`/`policy validate -i`/`inventory -i`, plus `conduitscope interfaces`
  to list interfaces): an optional, build-time-detected libpcap (Linux) / Npcap
  (Windows) dependency -- see above and docs/USER_GUIDE.md's LIVE CAPTURE section.
  `--duration`, `--filter` (BPF syntax), `--snaplen`, and Ctrl+C all stop a
  capture cleanly, still producing whatever decode output or policy report was
  captured so far. Validated end-to-end against real loopback traffic on Linux;
  the Windows/Npcap path is implemented against the same documented API but not
  yet run on a real Windows machine -- see docs/USER_GUIDE.md's LIMITATIONS.
- A `decode`/`info`/`interfaces`/`policy validate`/`inventory`/`version`
  command surface with full `--help` at every level

See [docs/USER_GUIDE.md](docs/USER_GUIDE.md) for the complete option reference,
output-format examples, exit codes, and the honest list of current limitations,
[docs/PROTOCOL_COVERAGE.md](docs/PROTOCOL_COVERAGE.md) for what each protocol
decoder actually surfaces and how confidently, and
[docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) for what's planned next.

## Building

Requires a C++17 compiler and CMake >= 3.16. No other dependencies are *required*
-- CLI11 is vendored as a single header under `third_party/`. If `libpcap-dev`
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
