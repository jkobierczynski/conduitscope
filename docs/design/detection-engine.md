# Detection that OT IR teams recognize -- design record

Status: **implemented, all 8 phases (0-7), current release, plus six Snort-style pattern
extensions (own section below).** Written at Jurgen's request to scope Grok review item 4
(`docs/reviews/2026-09-grok-ics-ot-improvement-areas.md`) into something buildable, after items 1-3
(zoning, asset inventory, baseline process behavior) were already fully closed -- see
`docs/DEVELOPMENT.md`'s "External review: Grok's ten improvement areas" section for where this sits
among the ten. The `detect` subcommand (`include/conduitscope/detect_engine.hpp`,
`src/detect_engine.cpp`) and its supporting MITRE ATT&CK-for-ICS lookup table
(`include/conduitscope/mitre_attack_ics.hpp`) and UMAS-over-Modbus/TCP decoder
(`include/conduitscope/umas.hpp`, `src/umas.cpp`) now exist and are covered by CTest, exactly as
scoped below. After gap #4 shipped, Jurgen asked a direct follow-up -- "how do I add more detection
patterns like those of Snort?" -- and, after confirming he wanted to keep extending this same
curated-C++-findings model rather than build a generic runtime rules engine (see "Snort-style
pattern extensions" below for that scoping conversation), asked for six specific new patterns, all
now implemented the same way as gap #4's own original findings: hardcoded, compiled-in C++ over
already-decoded fields, not a new rule language.

## The pitch, restated

Grok's own text for item 4 named five things a plant's incident-response team looks for that a
curated flood/scan signature list does not provide: engineering-station behavior on the process
network (TIA Portal/Studio 5000/Unity), firmware/logic download plus stop/start/cold-restart, a new
remote-access channel (RDP/TeamViewer/vendor VPN) into L2, protocol misuse (unsolicited DNP3, an
unexpected IEC 104 cause-of-transmission, a CIP Forward Open from a new originator), and mapping
every finding to MITRE ATT&CK for ICS at the technique level -- plus a cross-cutting requirement to
"keep the honesty: label confidence." `docs/reviews/2026-09-grok-response.md`'s own fact-check
(item 4) found this "mostly a real gap": `attack_detect.hpp`/`ipv6_attack_detect.hpp` only cover
flood/scan-shaped findings, there was exactly one incidental MITRE ATT&CK citation in the whole
codebase (T1557.003, in a comment, IPv6/DHCPv6-specific, not a structured field), and
engineering-station detection, firmware/download-and-restart as its own category, and "new
remote-access channel" as a distinguished finding were all genuinely unbuilt. No structured
confidence field/enum existed anywhere either -- only prose-level hedging.

Jurgen made three scoping decisions for this feature (via `AskUserQuestion`):

1. **A new dedicated `detect` subcommand** holds every item-4 finding in one unified report, rather
   than splitting baseline-independent-structural findings into `attack_detect.hpp`'s existing
   curated-notes model and new-vs-known findings into `baseline check`'s report.
2. **MITRE ATT&CK for ICS only** -- no Dragos-style activity-group attribution, since Dragos's own
   taxonomy is proprietary threat intel this project has no legitimate data to correlate against.
   Only real, public, citable ATT&CK-for-ICS technique IDs/names.
3. **Unity Pro/UMAS is in scope as new decode work** -- not just recognizing
   "engineering-station-shaped" behavior across protocols already decoded (S7 PLC Control/Stop, CIP
   Forward Open, BACnet ReinitializeDevice), but a genuine new decoder for Schneider's UMAS protocol
   (Modbus/TCP function code 0x5A), comparable in size to gap #2's S7-SZL/BACnet-RPM phases.

Central finding from research: unlike gap #2 (which needed three brand-new decoders), most of gap
#4's asks -- firmware/logic-download-and-restart, protocol misuse, engineering-station control-plane
traffic -- turned out to be a *reporting/detection layer over data this codebase already decodes*,
not new decode work. Confirmed directly against the source before any of this was built:
`src/enip.cpp` already names CIP `Forward_Open`/`Large_Forward_Open`/`Forward_Close` (0x54/0x5B);
`src/dnp3.cpp` already names Enable/Disable Unsolicited Responses (0x14/0x15), Unsolicited Response
(0x82), Cold/Warm Restart (0x0D/0x0E); `src/iec104.cpp` already decodes Interrogation (type 100) and
Reset Process (type 105), and item 3's own baseline-engine work already tracks type/COT/IOA ranges
via `Iec104AsduInfo`/`extract_iec104_operations`; `include/conduitscope/bacnet.hpp` already names
`DeviceCommunicationControl`/`ReinitializeDevice` in its service-choice table; `src/baseline.cpp`
already flags S7 PLC Control/PLC Stop as an `always_flag` `ControlPlaneOperation` -- the exact
"always worth a human's attention regardless of baseline" concept this feature reuses for
confidence; `include/conduitscope/notable_it_protocols.hpp` already tiers 43 IT protocols including
a "remote-access" Tier 1 (rdp/vnc/teamviewer/anydesk/zoom), used by `PolicyEngine`/
`AssetInventoryEngine` but never wired into a "new vs. known" detector. Only UMAS was genuinely new
decode work; everything else is wiring plus one new detection/report engine and one new curated
MITRE lookup table.

## Two kinds of finding

`detect_engine.hpp`'s own header comment states this precisely; restated here as the design's core
idea, mirroring `attack_detect.hpp`'s own "two kinds of evidence" split (see that file's header
comment) but for a different reason:

**ALWAYS-NOTABLE findings** -- a PLC/controller mode change, a firmware/logic download, a device
restart, an unsolicited/unexpected protocol message -- need no "new vs. known" judgment at all: the
traffic SHAPE itself is what's notable, every single time it's seen, the same "always worth a
human's attention regardless of baseline" concept `baseline.cpp`'s own `Operation::always_flag`
already established for S7 PLC Control/PLC Stop. These get `DetectionNovelty::NotApplicable`
unconditionally (no "new vs. known" judgment is ever made for them) and are produced entirely from
fields this codebase already decodes (or, for UMAS, newly decodes -- see below). Their `evidence`/
`severity` are set per finding source -- see "Four-axis model" below.

**NEW-VS-KNOWN findings** -- a remote-access protocol reaching a conduit, a CIP or UMAS
engineering-station originator opening a connection -- are only notable when they're NEW, and "new"
needs a concrete, honestly-labeled mechanism (Grok's own text: "keep the honesty: label
confidence"). See "Four-axis model" below for exactly how that's decided.

`DetectEngine::observe` runs a two-stage pipeline per Jurgen's own approved design: per-packet, it
either emits an always-notable finding immediately (deduplicated by a
`(category, technique, client_ip, server_ip, protocol, server_port)` key -- a later packet matching
the same combination only updates that finding's own `last_seen`/`packet_count`, never creates a
second finding) or records a new-vs-known *candidate* into `new_conduit_candidates_` (deduplicated
by a `(client_ip, server_ip, protocol, server_port, source_tag)` key, so two different sources --
remote-access, CIP, UMAS -- about the same 4-tuple never collide onto one candidate). `finish()`
then resolves every candidate's `novelty` against an optional `--baseline-file` (and a
`RemoteAccessChannel` candidate's `technique` against an optional `--policy`), exactly once, at
whole-capture time -- see "Four-axis model" below.

## Finding categories

```cpp
enum class DetectionCategory {
    EngineeringStationActivity,  // a PLC/controller mode change, or a new eng-station originator
    FirmwareLogicChange,         // a firmware/logic/program download, or a device restart
    RemoteAccessChannel,         // a new remote-access session (RDP/VNC/TeamViewer/...) into a zone
    ProtocolMisuse,              // an unsolicited/unexpected protocol message, a new CIP/UMAS
                                  // reservation originator
};
```

Independent of evidence/novelty/severity: a category says WHAT KIND of thing this is; the other
three say how reliably it was observed, whether it's new, and how much it would matter if genuine
(see "Four-axis model" below).

## MITRE ATT&CK for ICS mapping

`include/conduitscope/mitre_attack_ics.hpp` -- a small, curated lookup table, deliberately not an
attempt to cover the whole ATT&CK-for-ICS matrix (which has roughly 80 techniques across 12
tactics; most have no counterpart in anything this codebase can passively observe). Every technique
ID/name pair below was independently verified against `attack.mitre.org` directly during this
feature's research pass (fetched, not assumed from training data), on 2026-09-28:

| Finding shape | Technique | Name |
|---|---|---|
| PLC/controller stop, start, or mode change (S7 PLC Stop/Control, UMAS START_PLC/STOP_PLC, BACnet ReinitializeDevice-as-mode-change) | T0858 | Change Operating Mode |
| Device restart (DNP3 Cold/Warm Restart, IEC 104 Reset Process, BACnet ReinitializeDevice-as-restart) | T0816 | Device Restart/Shutdown |
| Firmware/logic/program download (S7 block download, UMAS INITIALIZE_DOWNLOAD/DOWNLOAD_BLOCK/END_STRATEGY_DOWNLOAD) | T0843 | Program Download |
| Task/logic structure change distinct from a full download | T0821 | Modify Controller Tasking |
| Unsolicited/unexpected protocol command (DNP3 Unsolicited Response with no prior Enable, an IEC 104 ASDU with an error-shaped COT, BACnet DeviceCommunicationControl, a CIP Forward_Open or UMAS TAKE_PLC_RESERVATION from a new originator) | T0855 | Unauthorized Command Message |
| New remote-access session within the plant (RDP/VNC/TeamViewer, no zone crossing) | T0886 | Remote Services |
| New remote-access session crossing an IT/OT or external zone boundary (uses `--policy`'s own zone data) | T0822 | External Remote Services |
| Read-only engineering/enumeration traffic from a new address (UMAS READ_ID/READ_PROJECT_INFO/READ_PLC_INFO) | T0888 | Remote System Information Discovery |
| Point/tag/address enumeration specifically | T0861 | Point & Tag Identification |
| Direct control manipulation not covered above | T0831 | Manipulation of Control |

Declared as ten free functions (`mitre_t0858_change_operating_mode()`, ...), not a single vector, so
every call site in `detect_engine.cpp` names exactly the technique it means, self-documenting at the
call site rather than requiring a lookup-by-string. `all_mitre_attack_ics_techniques()` returns all
ten, id order -- used by `write_detection_report_json`'s own "techniques referenced" summary section
(always the full ten, not just the ones a given report actually cites, so a consumer always has the
full citation text available without a second lookup) and by CTest assertions that every citation
this codebase can produce is one of these ten, never a stray/invented ID.

A technique ID/name pair is a factual citation (MITRE's own naming), not a diagnosis -- a
`DetectionFinding` citing T0858 says "this traffic has the SHAPE ATT&CK for ICS calls Change
Operating Mode," not "this is malicious." `DetectionFinding::evidence`/`novelty`/`severity` are the
separate, honest signals about how reliably this tool observed the event, whether it's new, and how
much it would matter if genuine -- see "Four-axis model" below; none of them, individually or
combined, is a claim about intent either.

T0821 (Modify Controller Tasking) and T0831 (Manipulation of Control) are included in the table for
completeness against Grok's own finding-shape list, but no current finding source actually cites
either -- nothing this codebase decodes today distinguishes "a task/logic structure change distinct
from a full download" from a plain program download, and no source produces a "direct control
manipulation" finding not already covered by one of the other eight rows. Left in the table (rather
than removed) so a future finding source can cite them without a second MITRE-verification pass;
`write_detection_report_json`'s "techniques referenced" list will show them as available even when
zero findings in a given report cite them.

## Four-axis model: evidence, novelty, severity -- and no claim of intent

Grok's own text says "keep the honesty: label confidence" -- the first shipped version of this
feature answered that with a single conflated field:

```cpp
enum class DetectionConfidence { High, Medium, Low };
```

Jurgen reviewed the shipped feature and identified, precisely, that this quietly mixed three
genuinely different questions into one word, and that "confidence" itself was the wrong frame
because it invited a reader to hear "malicious" where the tool never claimed anything of the kind.
His own critique, verbatim: "Separate evidence confidence from maliciousness and severity. High
confidence should mean that the observed protocol event is reliably established, not that the
activity is malicious. Distinguish confirmed protocol evidence, baseline deviation, operational
severity, and malicious intent." A mid-turn follow-up scoped the fix: "Make the four-axis model the
foundation of the detection and reporting architecture, but keep the protocol decoding and rule
execution mechanisms simple and deterministic." Both instructions together are what this section
documents -- a schema/labeling redesign, not a change to what `observe()`/`finish()` actually decode
or how they decide a finding fires.

`DetectionConfidence` was replaced by three independent fields, plus an explicit non-claim:

```cpp
enum class DetectionEvidence { Confirmed, Heuristic };
enum class DetectionNovelty { NotApplicable, ConfirmedNew, FirstOccurrence };
enum class DetectionSeverity { Critical, Moderate, Informational };
```

- **`evidence`** -- how reliably the underlying protocol event itself was established from the
  decode, and ONLY that. `Confirmed` means a protocol field was read directly and unambiguously off
  the wire (a function code, a service name, a CIP path segment) -- true for every finding source in
  this file except one. `Heuristic` means part of the finding's own claim rests on an inference that
  could be wrong -- today, only `RemoteAccessChannel`: Tier-1 protocol identification
  (`notable_it_protocols.hpp`) is port-only, its own weakest tier, and client/server direction comes
  from the "lower port number is the server" guess, not a decoded field. Every other finding source
  (S7/DNP3/IEC104/BACnet/CIP/UMAS/Modbus) reads a genuine decoded field, so `evidence` stays
  `Confirmed` throughout this codebase apart from that one case.
- **`novelty`** -- exactly the "new vs. known" resolution the old Medium/Low split used to encode,
  now its own field: `NotApplicable` for every always-notable finding (no such judgment is ever
  made); `ConfirmedNew` when a new-vs-known candidate's `(client_ip, server_ip, protocol,
  server_port)` key is checked against a caller-supplied `--baseline-file` (reusing
  `load_baseline_store`/`BaselineStore`, `baseline.hpp`, read-only, mirroring `baseline check`'s own
  flag name) and is genuinely absent from it; `FirstOccurrence` when no `--baseline-file` is
  supplied (the common single-pcap assessment case) -- evaluated as
  first-occurrence-within-this-capture, honestly weaker evidence (the capture might just start after
  the channel was already long-established), so the report text says so explicitly and suggests
  `--baseline-file`, the same spirit as `direction_source`'s own `PortHeuristic` low-confidence
  precedent elsewhere in this codebase. A candidate whose key IS present in the loaded baseline is
  dropped entirely -- not new at all, no finding produced.
- **`severity`** -- the operational impact IF the observed action is genuine and intentional,
  independent of both of the above: a PLC Stop is Critical whether or not the master that sent it
  was authorized, and whether or not it's new, because the operational consequence (the CPU actually
  stops) is the same either way. Set per finding source at the `record_always_notable`/
  `record_new_conduit_candidate` call site (`detect_engine.cpp`) -- most always-notable sources
  default to Critical (a real control/restart/download action), most new-vs-known sources default to
  Moderate (a real but not immediately control-affecting event); a handful of deliberately weaker
  signals -- the Modbus write-without-read pattern, the BACnet Who-Is flood, the S7 Setup
  Communication probing post-pass, UMAS read-only discovery, DNP3 unsolicited misuse, and an
  unexpected IEC 104 COT -- pass Moderate or Informational explicitly, documented at each call site.
- **Nothing asserts malicious intent, and no field claims to.** A MITRE ATT&CK for ICS citation
  names the traffic's SHAPE, not a verdict (`mitre_attack_ics.hpp`'s own header comment already
  establishes this); `evidence` says how sure this tool is that shape was really observed; `severity`
  says how much it would matter if genuine; `novelty` says whether it looks new. None of the three,
  alone or combined, says WHY the event happened or WHO caused it -- this tool has no access to
  change-management records, authorized-personnel lists, or asset criticality context, and does not
  pretend otherwise. That judgment belongs entirely to the human analyst reading the report; both the
  text and JSON writers (`write_detection_report_text`/`_json`) print a one-line reminder of this
  alongside the summary, not just in code comments.

**Explicitly out of scope**: retrofitting `evidence`/`novelty`/`severity` onto
`attack_detect.hpp`/`ipv6_attack_detect.hpp`/baseline's own existing findings. That's a separate,
larger effort across already-shipped, already-tested code and wasn't what Jurgen asked to start with
this feature -- flagged here as a reasonable future follow-up, not silently left undone.

### RemoteAccessChannel's own T0886-vs-T0822 resolution

A `RemoteAccessChannel` candidate additionally needs its *technique* resolved, independent of all
three axes: `finish(policy, ...)` -- `policy` optional, `nullptr` when `detect --policy` wasn't
given -- decides between T0886 (Remote Services, no zone crossing) and T0822 (External Remote
Services, crosses a zone boundary). When both endpoints resolve to a declared zone (via
`Policy::zone_for`, reusing `policy validate`'s own machinery exactly, no second parser) and the
zones differ, T0822; otherwise (no policy given, an endpoint outside every declared zone, or both
endpoints in the same zone) the narrower T0886 claim, since "crossed a boundary" isn't inferable
without a policy that says where the boundaries are. This is a technique upgrade only -- it never
changes the finding's `evidence`/`novelty`/`severity` (still whatever the baseline-file resolution
above and the candidate's own recorded `severity`/`evidence` already decided) and never suppresses
or creates a finding on its own.

## Engineering-station originator tracking

Two structurally identical mechanisms, generalizing the same idea across two different protocols:

**CIP** (`cip_originators_by_server_`, `std::unordered_map<std::string, std::vector<std::string>>`
keyed by server IP): every client_ip ever seen opening a Forward_Open/Large_Forward_Open to a given
server_ip. The first originator ever seen for a server is never flagged (nothing to compare against
within this capture); a second-or-later originator to the SAME server IS flagged as a new-vs-known
candidate (`ProtocolMisuse`, T0855) -- this asymmetry is deliberate, not an oversight: a server's
very first engineering connection in a capture that starts mid-session tells you nothing about
whether it's new, but a SECOND, DIFFERENT client doing the same thing during the capture is real
within-capture evidence of plurality.

**UMAS** (`umas_engineering_originators_by_server_`, same shape): the same mechanism, generalized
across FOUR UMAS commands rather than one -- TAKE_PLC_RESERVATION, READ_ID, READ_PROJECT_INFO, and
READ_PLC_INFO all share ONE map per server, not one map per command, so a client already credited as
a known originator via one of these commands isn't re-flagged for later issuing a *different* one of
the four against the same server. This reflects a real judgment call: TAKE_PLC_RESERVATION is
notable as a control-plane action (a reservation blocks other engineering stations from acting on
the PLC), while READ_ID/READ_PROJECT_INFO/READ_PLC_INFO are read-only enumeration -- so a second
originator's *category/technique* still depends on which specific command triggered the finding
(TAKE_PLC_RESERVATION -> `ProtocolMisuse`/T0855, matching the CIP precedent; any of the three READ_*
commands -> `EngineeringStationActivity`/T0888, Remote System Information Discovery -- settled by
re-reading this feature's own MITRE mapping table's T0888 row, "Read-only engineering/enumeration
traffic from a NEW address," during implementation), but *whether* a given originator is new at all
is decided from the shared, command-agnostic history. `NewConduitCandidate::source_tag`
(`"umas-new-originator-reservation"` vs. `"umas-new-originator-discovery"`, vs. CIP's own
`"cip-new-originator"`) carries which template `finish()`'s description-rendering code should use,
independent of the category/technique that source_tag maps to.

## UMAS-over-Modbus/TCP: research, sourcing, and scope boundary

UMAS (Schneider Electric's Unity Pro/Control Expert engineering-station protocol, Modbus/TCP
function code 0x5A/90) has **no official public specification** -- Kaspersky ICS-CERT states this
plainly, and the only sources are convergent open-source reverse-engineering. Two independent
sources agree on the wire shape:

- Kaspersky ICS-CERT / Securelist, ["The secrets of Schneider Electric's UMAS
  protocol"](https://ics-cert.kaspersky.com/publications/reports/2022/09/29/the-secrets-of-schneider-electrics-umas-protocol/)
  ([Securelist mirror](https://securelist.com/the-secrets-of-schneider-electrics-umas-protocol/107435/)):
  rides Modbus/TCP function code 0x5A (90); payload is a 1-byte session key, then a 1-byte UMAS
  function code, then operation-specific data; response status is `0xFE` (success) / `0xFD`
  (failure) immediately after the session key. Confirms function codes 0x01 (`QueryGetComInfo`),
  0x10 (`QueryTakePLCReservation`), 0x20 (`ReadMemoryBlock`). Documents the session-key weaknesses
  (static 0x01 pre-firmware-2.7, then a 1-byte randomized value, CVE-2020-28212) and the Application
  Password mechanism (nonce + SHA-256, CVE-2021-22779) -- both are pure security history, not
  something this decoder re-implements or validates; stated as a LIMITATIONS line so the decoder
  doesn't imply either.
- [yanissec/umas-wireshark-dissector](https://github.com/yanissec/umas-wireshark-dissector)
  (`umas.lua`), an open-source Wireshark dissector -- the same kind of primary source this project
  already cites for other protocols' field tables. Gives the fuller 27-entry function-code table
  `include/conduitscope/umas.hpp`'s own `UmasFunctionCode` enum is built from, from `INIT_COMM`
  (0x01) through `GET_STATUS_MODULE` (0x73), plus `0xFE`/`0xFD` response status, matching
  Kaspersky's own account.

**Scope decision**: decode function-code-level naming and session-key/request-vs-response
classification only -- the same depth as `bacnet.hpp`'s service-choice table before RPM decode
existed. This decoder does **not** attempt to decode the data field's internal structure (memory
addresses, project name strings, reservation payload contents): Kaspersky's own writeup documents
the session-key/version drift across firmware releases, and without real Unity Pro capture samples
to validate field offsets against, deeper decode would be guesswork this project's own "cite a
primary source, verify against real captured output" discipline can't support. This mirrors
`opcua.hpp`/`bacnet.hpp`'s own precedent of an explicit, stated "first pass" scope boundary rather
than a silent gap. Every UMAS fixture pcap this feature's tests use (`tests/sample_umas.pcap`) is
synthetically constructed (`tools/make_sample_pcap.py`) from the function-code table above --
absent a real Unity Pro capture, the fixtures validate wire-shape parsing correctness, not
real-world traffic fidelity, the same caveat that applies to any reverse-engineered protocol this
project decodes.

### Architectural decision: UMAS lives inside `ModbusFrame`, not as its own top-level protocol

`DecodedPacket::protocol` stays `"modbus"` always for UMAS traffic -- `ModbusFrame` gained a new
`std::optional<UmasFrame> umas` field, populated only when the base function code (exception bit
stripped) equals `UMAS_MODBUS_FUNCTION_CODE` (0x5A). This is because UMAS genuinely IS Modbus/TCP at
the wire level (same MBAP header, same transaction-ID pairing mechanism), just with a
vendor-proprietary meaning for one function code's payload -- unlike, say, S7comm-Plus (a
genuinely distinct application protocol that merely happens to share S7comm's TPKT/COTP transport),
UMAS shares Modbus's own application-layer framing, not just a lower transport layer. Consequences:
`umas_function_name(fc)` is consulted by `modbus.cpp`'s own `function_name()` helper so a UMAS
packet's summary line reads `"UMAS: <umas-specific text>"` rather than `"Unknown (0x5a): ..."`;
`ModbusDecoder::decode`'s own request/response heuristic (`looks_like_response`) additionally checks
`mb.umas && mb.umas->is_response`; and no new "umas" protocol-name branch was needed anywhere a
protocol-name dispatch already exists (`AssetInventoryEngine`'s recognized-protocols list,
`DetectEngine`'s own per-protocol wiring, JSON field emission) -- UMAS traffic already flows through
each one's existing `"modbus"` case, and reads `dp.result->as<ModbusFrame>().umas` when it needs
UMAS-specific fields.

**Request/response heuristic**: the byte immediately after the session key is checked against
`UMAS_RESPONSE_STATUS_SUCCESS` (0xFE) / `UMAS_RESPONSE_STATUS_FAILURE` (0xFD) -- if it matches
either, it's a response; otherwise it's a request and that byte is the function code. Documented in
`decode_umas`'s own comment as a heuristic (mirroring `modbus.cpp`'s own shape-based
request/response heuristic for the base Modbus function codes, always explicitly called out rather
than presented as certain), since no function code in the known 27-entry table comes anywhere near
0xFE/0xFD (the highest is 0x73).

### What UMAS wiring adds across the codebase

Following this project's "a new decoder gets wired everywhere every other decoder is" convention
(not `detect`-only, since Jurgen scoped UMAS as new decode work generally):

- **`AssetInventoryEngine`** (`asset_inventory.cpp`): a UMAS request's `observed_functions` entry is
  `"UMAS/<function-name>"` (e.g. `"UMAS/START_PLC"`) rather than the generic `"UMAS"` every
  UMAS *response* still falls back to, so an inventory report distinguishes which specific
  UMAS operations were seen on a conduit, not just that UMAS traffic occurred at all.
- **`BaselineEngine`** (`baseline.cpp`): UMAS START_PLC/STOP_PLC get the exact same
  `Operation::always_flag = true` treatment S7comm's PLC Control/PLC Stop already had --
  `baseline check` always reports them regardless of prior baseline knowledge, checked BEFORE the
  pre-existing `is_request`/`function_name`-empty early return in `extract_modbus_operations`, since
  `decode_umas` never populates `ModbusFrame::is_request` at all (UMAS's own request/response
  distinction lives on `UmasFrame::is_response` instead).
- **`DetectEngine`** (this feature): START_PLC/STOP_PLC -> T0858 (always-notable, High);
  INITIALIZE_DOWNLOAD/DOWNLOAD_BLOCK/END_STRATEGY_DOWNLOAD -> T0843 (always-notable, High);
  TAKE_PLC_RESERVATION/READ_ID/READ_PROJECT_INFO/READ_PLC_INFO -> the shared new-originator
  mechanism described above (new-vs-known, Medium/Low).

## `DetectionReport` shape

```cpp
struct DetectionFinding {
    DetectionCategory category;
    MitreAttackTechnique technique;    // always populated -- every finding cites exactly one
    DetectionEvidence evidence;        // decode reliability only -- see "Four-axis model" above
    DetectionNovelty novelty;          // new-vs-known only
    DetectionSeverity severity;        // impact-if-genuine only
    std::string client_ip, server_ip;  // client_ip is the initiator/originator side
    std::string protocol;              // "s7comm"/"dnp3"/"iec104"/"bacnet"/"enip"/"modbus"/"rdp"/...
    uint16_t server_port;
    std::string description;           // human-readable, incident-ticket-ready
    double first_seen, last_seen;
    size_t packet_count;
};

struct DetectionSummary {
    size_t total, critical, moderate, informational;      // by severity
    size_t confirmed_evidence, heuristic_evidence;          // by evidence
    size_t engineering_station_activity, firmware_logic_change, remote_access_channel,
           protocol_misuse;
};

struct DetectionReport {
    std::vector<DetectionFinding> findings;  // first-seen order
    DetectionSummary summary;
    size_t total_packets;
};
```

`findings` is always in first-seen order (insertion order into `always_notable_order_`/
`new_conduit_order_`, both plain `std::vector<std::string>` alongside their respective
`unordered_map`s), so the report is deterministic independent of an `unordered_map`'s own iteration
order -- and reads, in text format, as a rough timeline of the capture. `write_detection_report_text`
groups by category for readability; `write_detection_report_json` keeps first-seen order in its
`findings` array and adds the always-full `techniques_referenced` list described above.

## CLI shape

```
conduitscope detect (-r FILE | -i INTERFACE) [--policy FILE] [--baseline-file FILE]
                     [-T text|json] [options]
```

One subcommand, matching every other report-producing subcommand's own `-r`/`-i`/`-f`/`--duration`/
`--snaplen`/`--no-promiscuous`/`-o`/`-T`/`--strict`/the five resource-limit flags/`--mac-vendor`/
`--resolve`/`--hosts`/`--nn`/`--services` shape (`inventory`'s own option set is the closest
existing template, since `detect`, like `inventory`, supports both live capture and file input,
unlike `baseline learn`/`baseline check` which are file-only). `--policy`/`--baseline-file` are
both optional and independent of each other -- either, neither, or both may be given, and their
effects (T0886-vs-T0822 resolution; ConfirmedNew-vs-FirstOccurrence novelty) don't interact. See
`man/conduitscope.1`'s OPTIONS (detect) section and `docs/USER_GUIDE.md`'s DETECT section for the
full flag reference and a worked example.

**Exit status is deliberately always 0 on a successful run, regardless of findings.** Unlike
`policy validate` (exit 3 on non-compliance) or `baseline check` (exit 4 on any finding), `detect`
has no "compliant/non-compliant" concept to report against -- it's a reporting tool surfacing
findings for a human (or a SIEM ingesting its JSON) to triage, not a pass/fail gate a CI pipeline
would want to fail on. A fatal setup error (bad arguments, an unreadable capture, a `--policy` or
`--baseline-file` that fails to parse) still returns 1, the same as every other subcommand. A caller
that wants a non-zero exit specifically when `detect` finds something should check the report's own
`summary.total` (JSON) rather than rely on the process exit code -- documented explicitly in
`man/conduitscope.1`'s EXIT STATUS section so this isn't a silent surprise next to `baseline check`'s
own exit-4 convention.

## Testing and fixtures

`tests/sample_detect.pcap` (`tools/make_sample_pcap.py`'s `build_detect_sample()`) exercises one
scenario per always-notable finding source (S7 block download, DNP3 Cold Restart, DNP3 Unsolicited
Response with no prior Enable, an IEC 104 ASDU with an error-shaped COT, IEC 104 Reset Process,
BACnet ReinitializeDevice, BACnet DeviceCommunicationControl) plus one CIP Forward_Open new-originator
case and one RDP new-remote-access-channel case -- 9 findings total from 12 packets, pinned end to
end (category, technique, evidence, novelty, severity, endpoints, description, in first-seen order)
by
`detect_sample_detect_text_all_findings`/`detect_sample_detect_json_shape` in `CMakeLists.txt`.
`tests/sample_umas.pcap` (`build_umas_sample()`) separately exercises every UMAS function code this
decoder names, plus (added when Phase 6 wired UMAS into `DetectEngine`) a second and third
engineering-station originator, so the shared-map new-originator mechanism is exercised for real
rather than merely unit-shaped. `tests/policies/detect_zone.yaml` (new fixture) declares two zones
so `detect_policy_zone_crossing_upgrades_remote_access_to_t0822` can exercise the T0886-vs-T0822
upgrade against `sample_detect.pcap`'s own RDP scenario. Every CTest assertion in this feature was
written only after manually running the real CLI binary and inspecting its actual output -- this
project's standing rule, restated because it was broken once earlier in this project's history (a
stray-quote CTest regex bug) and is worth re-affirming for every new feature.

Full CTest across all four standing build configurations (default GCC, ASan/UBSan `build-fuzz`,
`-DCONDUITSCOPE_ENABLE_LIVE_CAPTURE=OFF` `build_nolive`, MinGW-w64 `build-mingw`, build-only there)
after every phase, plus a dedicated `fuzz_umas` libFuzzer harness (`fuzz/fuzz_umas.cpp`, seeded from
`fuzz/corpus/umas/`) run for 13.4 million iterations with zero ASan/UBSan findings before this
feature was considered done -- matching this project's "every decoder gets fuzzed" and "a
transitively-reachable sub-decoder still gets its own dedicated harness for full per-iteration
coverage density" conventions (`fuzz/README.md`'s own `fuzz_dnp3`/`fuzz_umas` entries).

## Snort-style pattern extensions

Jurgen's own question, verbatim: "How do I add more detection patterns like those of Snort?" The
honest answer first: Snort/Suricata evaluate a runtime rules file (no recompile to add a rule);
conduitscope has no such mechanism anywhere -- `attack_detect.hpp`/`ipv6_attack_detect.hpp`
(flood/scan signatures) and `detect_engine.hpp` (this file's own OT findings) are both entirely
hardcoded, compiled-in C++, and `policy.yaml`/`baseline.json` are the only user-editable declarative
files this project has, neither a detection-pattern language. Presented with that choice, Jurgen
picked **keep extending the curated C++ findings model** over building a generic rule engine (via
`AskUserQuestion`) -- so every pattern below is implemented exactly the way gap #4's own original
findings are: a new `observe()`/`finish()` branch reading fields this codebase already decodes, not
a new file format or a plugin mechanism.

Jurgen then named six candidate patterns explicitly (starting with one -- CIP `Set_Attribute_Single`
to a controller's run/idle mode attribute -- then expanding mid-conversation to "you can implement
them all"). Two of the six, as first proposed, didn't survive contact with this project's own
"never guess at wire-format/mechanism specifics without a citable primary source" discipline, and
were rescoped with Jurgen's own explicit sign-off (`AskUserQuestion`, both times choosing the
"Recommended" -- honestly narrower -- option):

- **CIP run/idle mode change.** The real-world precedent (Digital Bond's "Basecamp"-era
  ControlLogix remote-mode-change research) uses an undocumented Rockwell mechanism -- no citable
  primary source for the specific CIP class/attribute/value that changes a ControlLogix's run/
  program/remote mode was found (a CISA advisory that might have had it, `ICSA-13-011-03`, 403'd on
  fetch; further searches were inconclusive). Rather than hardcode a guessed attribute number,
  rescoped to **any write to the Identity object (class 0x01)** -- broader than the real mode-change
  mechanism specifically, but every part of it (the class ID, the service codes) is directly
  confirmed against this codebase's own `enip.cpp`/`enip.hpp`, nothing guessed.
- **S7comm password/authentication bypass.** No password/authentication PDU is decoded anywhere in
  this codebase at all (confirmed by grep -- `_N_LOGIN_`/`_N_LOGOUT` in `s7comm.cpp`'s own
  `kPiServiceNames` are Sinumerik NC login services, not a CPU authentication mechanism), so
  "repeated failed auth attempts" would need new, unsourced decode work. Rescoped to **Setup
  Communication (function 0xF0) probing** instead: a real, already-decoded S7comm function, and
  "this pair only ever did the handshake, never anything real" is a genuinely observable,
  honestly-scoped signal without inventing a password mechanism this project can't verify.

A third pattern was corrected without needing to ask -- the original framing, "DNP3 Direct Operate
bypassing Select-before-Operate," mischaracterizes real DNP3 semantics: Direct Operate (0x05) is a
legitimate, intentional, routinely-used mechanism that deliberately skips Select, not a bypass of
one. The defensible signal is the other function code entirely: an **Operate (0x04) with no
matching prior Select (0x03)** on the same master/outstation pair -- flagged in the message that
proposed it, before Jurgen's "implement them all," and never revisited.

The final six, all shipped:

| # | Pattern (as implemented) | Category / technique | Evidence | Severity |
|---|---|---|---|---|
| 1 | CIP `Set_Attribute_Single`/`Set_Attributes_All` write to the Identity object (class 0x01) | ProtocolMisuse / T0855 | Confirmed (always-notable) | Critical |
| 2 | DNP3 Operate (0x04) with no Select (0x03) ever seen for that master/outstation pair | ProtocolMisuse / T0855 | Confirmed (always-notable) | Critical |
| 3 | Modbus Write Multiple Coils/Registers outside every range ever read (same conduit, same table) | ProtocolMisuse / T0831 | Confirmed | **Informational, unconditionally** -- the one deliberate always-notable exception to "the default severity is Critical," see below |
| 4 | BACnet Who-Is flood/device-enumeration sweep, per source IP, past a threshold | ProtocolMisuse / T0888 | Confirmed (always-notable, fires once per source at threshold) | Informational |
| 5 | S7comm Setup Communication (0xF0) probing: repeated, with no other S7comm function ever seen for that pair | EngineeringStationActivity / T0888 | Confirmed (resolved in `finish()`, not `observe()`) | Informational |
| 6 | Composite: a Program Download (T0843) finding and a restart/mode-change (T0858/T0816) finding both against the same server within a short window | FirmwareLogicChange / T0831 | Confirmed (resolved in `finish()`, over this SAME call's own already-produced findings) | Critical |

Every one of the six keeps `evidence: Confirmed` -- each reads a decoded protocol field directly, the
same "no source here needs Heuristic" posture every original gap #4 finding except
`RemoteAccessChannel` already has (see "Four-axis model" above). `novelty` is `NotApplicable` for all
six -- none of them is a new-vs-known finding.

Implementation notes, by pattern:

- **Pattern 3 (Modbus write-without-read) is the one place this feature deliberately breaks its own
  "the default always-notable severity is Critical" rule.** Every other always-notable source in this
  file earns Critical because the traffic SHAPE alone is structurally notable and operationally
  significant regardless of context (a PLC Stop is always worth a human's attention and always stops
  the CPU if genuine). "A write to a range nobody read first" is a genuinely weaker signal on its own
  -- plenty of legitimate deployments write setpoints/commands without ever reading them back,
  especially in a short single-pcap capture that may simply not contain the read traffic that exists
  elsewhere in a plant's normal polling cycle. `record_always_notable` (`detect_engine.cpp`) grew
  optional trailing `DetectionSeverity`/`DetectionEvidence` parameters (defaulting to `Critical`/
  `Confirmed`, every pre-existing call site unaffected) specifically so patterns like this one could
  pass a lower severity explicitly rather than either lying about it or needing a whole second
  mechanism -- `evidence` stays `Confirmed` here: the write and the absence of a prior read genuinely
  were observed exactly as described, it's the SEVERITY of that observation that's deliberately low,
  a distinction the old single confidence field couldn't make. Only the two writable Modbus data
  tables are tracked (Coils, via Write Multiple Coils/Read Coils; Holding Registers, via Write
  Multiple Registers/Read Holding Registers) -- Discrete Inputs and Input Registers are read-only
  tables nothing ever writes to, so they're never tracked at all, and Write Single Coil/Register are
  excluded entirely (`ModbusFrame::start_address`/`quantity`'s own comment, `modbus.hpp`, documents
  why that pair has no request/response-confirmed shape to key on in the first place -- a
  pre-existing, unrelated scope boundary, not something this pattern introduces).
- **Pattern 5 (S7 Setup Communication probing) and pattern 6 (the composite) are the only two of the
  six resolved in `finish()` rather than `observe()`.** Both genuinely need whole-capture knowledge:
  "no other S7comm function was EVER seen for this pair" can't be confirmed until the capture ends (a
  later packet could always introduce a real function), and the composite is by definition a
  relationship between two OTHER findings this same `finish()` call already produced. Both still
  follow this file's own "deterministic report regardless of `unordered_map` iteration order"
  discipline: each collects its own qualifying entries into a `std::vector`, sorts it (by key/
  server_ip), then appends -- the same pattern `always_notable_order_`/`new_conduit_order_` already
  established for `observe()`-time findings.
- **The composite (pattern 6) is a post-pass over already-produced findings, not new tracked
  state.** It scans `report.findings` (everything already pushed by the always-notable loop, the
  resolved new-conduit loop, and pattern 5's own post-pass, all of which run first) for a T0843
  finding and a T0858/T0816 finding sharing a `server_ip`, picks the closest-in-time pair per server
  (so a server with several downloads and restarts produces at most one composite, not a combinatorial
  spam of them), and cites T0831 (Manipulation of Control) rather than reusing either source
  finding's own technique -- a composite is a claim about the SEQUENCE, not a restatement of either
  half. The window (`kCompositeWindowSeconds`, 300s/5 minutes) is a small, documented judgment-call
  default, not vendor-sourced -- the same "modest default I pick and document as a judgment call"
  posture `attack_detect.hpp`'s own `DEFAULT_FLOOD_THRESHOLD` established for this project.
- **Pattern 4 (BACnet Who-Is flood) reuses `attack_detect.hpp`'s own flood-threshold value (100)**
  for consistency across this codebase's two independent flood-shaped detectors, not because 100 is
  researched or vendor-sourced for Who-Is specifically -- see `kBacnetWhoIsFloodThreshold`'s own
  comment (`detect_engine.cpp`). Grouped by source IP alone, not source+destination: Who-Is is
  routinely sent as a BACnet/IP broadcast, so splitting by destination would fragment one real sweep
  across however many broadcast/unicast destinations it happened to use.
- **None of the six add new raw-byte decode work.** Every one reads a field a decoder this codebase
  already had (and already fuzzes) produces -- `CipPath::class_id`, `ModbusFrame::start_address`/
  `quantity`/`function_name`, `S7CommResult::function_name`, `Dnp3Result::dnp3_function_name`,
  `BacnetFrame`'s own `service_choice_name`. So, matching the precedent `baseline.cpp`/
  `asset_inventory.cpp`/`policy.cpp` (which also only ever read already-decoded, already-fuzzed
  structures) already set, none of the six needed a new libFuzzer harness of their own -- unlike gap
  #4's own UMAS decoder, which parses raw bytes and does have one (`fuzz/fuzz_umas.cpp`).

Fixtures: `tests/sample_detect_snort_patterns.pcap`
(`build_detect_snort_patterns_sample()`) covers patterns 1, 2, 3, 5, and 6 in one 16-packet capture,
each finding source on its own conduit, each paired with a negative/contrast conduit proving the
pattern does NOT fire when its own condition isn't met (a DNP3 Select-then-Operate pair; a Modbus
write fully covered by a prior read; an S7 pair that also did a real PLC Stop -- whose OWN T0858
finding still fires, just not the probing finding). Pattern 4 (the BACnet flood) is in its own
fixture, `tests/sample_detect_bacnet_who_is_flood.pcap`
(`build_detect_bacnet_who_is_flood_sample()`), specifically because it genuinely needs
`kBacnetWhoIsFloodThreshold`-worth of packets (100) -- interleaving that many into the other five
scenarios' own exact-packet-count assertions would make them brittle to a threshold constant that
may change later. `detect_snort_patterns_all_findings`/`detect_snort_patterns_json_shape`/
`detect_bacnet_who_is_flood` in `CMakeLists.txt` pin every finding end to end, the same "write the
assertion only after running the real CLI binary and inspecting its actual output" discipline
"Testing and fixtures" above already establishes.

## Explicitly out of scope

- **Evidence/novelty/severity retrofit onto pre-existing engines.** See "Four-axis model" above.
- **Dragos-style activity-group attribution.** Jurgen's own scoping decision #2 -- MITRE ATT&CK for
  ICS technique citations only, never a named threat-actor/campaign label, since this project has no
  legitimate proprietary threat-intel data to correlate against.
- **UMAS data-field decode.** See the UMAS scope-decision paragraph above -- function-code-level
  naming and request/response classification only, no memory-address/project-name/reservation-payload
  parsing.
- **An evidence/novelty/severity field that adapts over multiple `detect` runs.** Every `detect` invocation is a
  fresh, stateless evaluation against whatever `--baseline-file`/`--policy` was given this run; there
  is no persisted `DetectEngine` state the way `BaselineStore` persists across `baseline learn` runs.
  A caller wanting trend-over-time detection today combines `detect --baseline-file` (kept current
  via `baseline learn`) with their own external run-history tooling.
- **A specific CIP run/idle mode-change attribute/value for the Identity-object write pattern.** See
  "Snort-style pattern extensions" above -- deliberately broadened to "any write to class 0x01"
  instead, since no citable primary source for the exact wire format exists.
- **An S7comm password/authentication decoder.** See "Snort-style pattern extensions" above --
  Setup Communication probing was substituted; a genuine fix (decoding whatever real Application
  Password PDU actually looks like on the wire) needs a primary source this project doesn't have
  yet, not a guess.
- **A generic runtime detection-rules file/language (a "Snort mode" for conduitscope).** Jurgen's
  own explicit choice (`AskUserQuestion`, "Snort-style pattern extensions" above) -- every new
  pattern is hardcoded, compiled-in C++ over already-decoded fields, the same model gap #4's own
  original findings use, not a new file format, DSL, or plugin mechanism a user could load without
  recompiling.
