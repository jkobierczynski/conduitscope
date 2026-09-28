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

## Batch 1: six more Snort-style patterns (Modbus/TCP, from Quickdraw-Snort's own `modbus.rules`)

A direct follow-up to "Snort-style pattern extensions" above. Jurgen asked (verbatim) for "a batch
of 3 times 6 further additional patterns from real Snort/Suricata OT rulesets and public ICS
advisories to add to the detection" -- a research/proposal request first, not an implementation
request. The research pass produced `docs/research/2026-09-detect-pattern-candidates-batch2.md`: 18
candidate patterns across three batches of 6, each with its own source citation (Digital Bond's
Quickdraw-Snort `modbus.rules`/`dnp3.rules`, CyberICS's `scada-scan.rules`, public CVE/advisory
text, MITRE ATT&CK for ICS), wire-level condition, and proposed category/technique/evidence/
severity/novelty mapping -- written and delivered as a document, not code, per that message's own
scope. A later follow-up question ("assuming you have done the research, I assume there is no
additional cost to make it 10x6 or 20x6 patterns? what amount of patterns is enough?") was answered
directly: research cost for genuinely relevant, citable OT-protocol rulesets is a largely-exhausted
pool (roughly 18-20 well-sourced candidates was close to the practical ceiling for this project's own
sourcing standard), but implementation cost does NOT get cheaper in bulk -- each pattern still needs
its own decode-field check (or new decode work), engine wiring, fixture, and a CTest case verified
against real CLI output, so 60 patterns is roughly 10x the work of 6, not free. Jurgen then confirmed
"continue with batch 1" -- the six patterns below, all Modbus/TCP, sourced from Quickdraw-Snort's own
`modbus.rules`.

| # | Pattern (as implemented) | Category / technique | Evidence | Severity | Novelty |
|---|---|---|---|---|---|
| 1 | Modbus Diagnostics (0x08) Force Listen Only Mode (sub-function 0x0004) | EngineeringStationActivity / T0858 | Confirmed (always-notable) | Critical | N/A |
| 2 | Modbus Diagnostics Restart Communications Option (sub-function 0x0001) | FirmwareLogicChange / T0816 | Confirmed (always-notable) | Critical | N/A |
| 3 | Modbus Diagnostics Clear Counters and Diagnostic Registers (sub-function 0x000A) | ProtocolMisuse / **T0872** (Indicator Removal on Host -- new citation, see below) | Confirmed (always-notable) | Moderate | N/A |
| 4 | Modbus Read Device Identification (function 0x2B, MEI type 0x0E) from a client | EngineeringStationActivity / T0888 | Confirmed | Informational | **New-vs-known** (baseline-or-first-occurrence) |
| 5 | Modbus Report Server ID (function 0x11) from a client | EngineeringStationActivity / T0888 | Confirmed | Informational | **New-vs-known** (baseline-or-first-occurrence) |
| 6 | Repeated Modbus exception-code response burst: same server, same exception code, 3+ times to the same client within ~60s | ProtocolMisuse / T0855 | Confirmed (always-notable, windowed) | Moderate | N/A |

Implementation notes, by pattern:

- **Patterns 1-3 needed genuinely new decode work** (the only new raw-byte parsing this batch
  added): `ModbusFrame` gained `diagnostics_sub_function` (`std::optional<uint16_t>`, function code
  0x08's own 2-byte sub-function field) and `mei_type` (`std::optional<uint8_t>`, function code
  0x2B's own MEI type byte) -- see their own comments, `modbus.hpp`. `diagnostics_sub_function_name`
  (`modbus.cpp`) names five sub-functions (Return Query Data/Restart Communications Option/Return
  Diagnostic Register/Force Listen Only Mode/Clear Counters and Diagnostic Registers); any other
  sub-function still populates the field but renders "Unknown (0xNNNN)", the same fallback style
  `function_name`'s own table already uses. `mei_type_name` names the two MEI types the spec
  currently assigns (0x0D CANopen General Reference, 0x0E Read Device Identification). Deliberately
  function-code/sub-function/MEI-type-level naming only -- Read Device Identification's own object-
  list payload (conformity level, per-object id/value pairs) is NOT decoded further, the same "first
  pass" scope boundary this project already documents for `opcua.hpp`/`bacnet.hpp`.
- **All five request-side patterns (1, 2, 3, 4, 5) are gated on `dp.dst_port == MODBUS_TCP_PORT`
  (502), not a decoded request/response field.** Diagnostics' request and response share the
  IDENTICAL wire shape for every sub-function this decoder names (sub-function code plus echoed
  data) -- the exact same situation `decode_write_single` already documents for Write Single Coil/
  Register (`ModbusFrame::is_request`'s own comment, `modbus.hpp`) -- so there is no shape-based
  signal to decide direction from. The well-known-port heuristic is the same one S7comm's own detect
  wiring already uses (`dp.dst_port == 102`) for exactly this reason; without it, a Diagnostics
  sub-function whose response happens to echo the request (Restart Communications Option, Clear
  Counters -- confirmed against real traffic, see below) would otherwise be recorded TWICE, once per
  direction, with client/server reversed on the second. Force Listen Only Mode is the one exception
  that needs no such guard in practice -- per spec the target sends NO response to it at all
  (confirmed directly against the real capture below).
- **Three of the six (1, 2, 3) and the exception-burst pattern (6) are independently verified
  against this project's own REAL capture, `tests/real_captures/modbus/modbus_test_data_part1.pcap`**
  -- not just a synthetic fixture. A direct scapy byte-level check of that capture's raw MBAP frames
  found it genuinely contains Force Listen Only Mode (`08 00 04 00 00`), Restart Communications
  Option (`08 00 01 00 00`, request AND its own echoed response), and Clear Counters and Diagnostic
  Registers (`08 00 0a 00 00`) -- confirmed BEFORE writing the corresponding CTest assertions, this
  project's own standing discipline. The same capture also genuinely contains real, repeated
  "Gateway Target Device Failed to Respond"/"Server Device Busy" exception bursts (`detect
  --read tests/real_captures/modbus/modbus_test_data_part1.pcap` fires pattern 6 twice, against two
  different real servers) -- an unplanned but welcome bonus: real evidence for the one pattern a
  synthetic fixture alone couldn't have given the same confidence for. Read Device Identification
  (pattern 4) is confirmed ABSENT from that same real capture (same scapy check), so it's covered
  by the synthetic fixture instead. See `real_modbus_diagnostics_*`/`real_modbus_detect_batch1_
  all_findings` in `CMakeLists.txt`.
- **Pattern 3 needed the one new MITRE ATT&CK for ICS technique this batch added: T0872 (Indicator
  Removal on Host)**, verified directly against `attack.mitre.org/techniques/T0872/` (not assumed),
  added to `mitre_attack_ics.hpp`/`.cpp` following the exact one-liner-function pattern the existing
  ten already use, inserted in the correct id-sorted position in `all_mitre_attack_ics_techniques()`
  (between T0861 and T0886). Category was a genuine judgment call -- "clearing diagnostic counters"
  doesn't cleanly fit any of this engine's four categories (not a mode change, not a firmware/logic
  change, not a remote-access event); `ProtocolMisuse` was picked as the closest fit, the same
  "a protocol command being used in a way that's not routine, even without a cleaner category" shape
  `ProtocolMisuse` already covers for the CIP Identity-object-write and Modbus write-without-read
  patterns above.
- **Patterns 4 and 5 are deliberately new-vs-known candidates, NOT always-notable** -- a genuine
  departure from how Quickdraw's own rules treat them (both are simple always-fire signature
  matches in Snort). The research doc's own proposal for these two was new-vs-known novelty
  specifically: any single Read Device Identification/Report Server ID query is ordinary
  engineering-tool behavior on its own, and only its NOVELTY (a client not seen doing this before,
  or genuinely absent from a supplied `--baseline-file`) is the honestly-supportable signal --
  implemented here exactly that way, via `record_new_conduit_candidate` with a fresh source tag each
  (`modbus-new-originator-read-device-id`/`modbus-new-originator-report-server-id`), resolved in
  `finish()` the same baseline-or-first-occurrence way every other new-vs-known source already is.
  Unlike the CIP `Forward_Open`/UMAS engineering-originator sources above, these are deliberately
  NOT gated on "second-plus originator to this server" -- there is no per-server originator-set
  tracking for either; every occurrence becomes its own candidate. Informational severity, matching
  `umas-new-originator-discovery`'s own posture: read-only enumeration, no control-plane effect if
  genuine.
- **Pattern 6 (the exception-code burst) is the one Batch 1 pattern needing genuinely new
  observe()-time state** -- `modbus_exception_burst_state_` (`detect_engine.hpp`), keyed
  `"<client_ip>|<server_ip>|<exception_code>"`, tracking a running count plus the window's own start
  timestamp. Deliberately WINDOWED, unlike `bacnet_who_is_count_by_source_`'s own whole-capture
  cumulative count above: three exceptions minutes apart across an hour-long capture is not the same
  signal as three within a minute, so the window resets to count=1 whenever a new occurrence's gap
  since the window's own first occurrence exceeds `kModbusExceptionBurstWindowSeconds` (60s) --
  proven by the synthetic fixture's own scenario 10 (exceptions at t=0/30/95 -- the third falls
  outside the window and the pattern correctly does NOT fire). Threshold (3) and window (60s)
  generalize Quickdraw-Snort's own SIDs 1111010 ("Slave Device Busy Exception Code Delay", exception
  0x06) and 1111011 ("Acknowledge Exception Code Delay", exception 0x05), both
  `threshold: count 3-5, seconds 60` -- the low end of that count range is used, the same "small,
  documented judgment-call default" posture as `kS7SetupCommProbeThreshold` above; Quickdraw's own
  rule is cited for the SHAPE of the pattern, not treated as a precise, non-negotiable count/window.
  Moderate severity, unconditionally -- the same "real but weak, legitimate retry/backoff logic can
  trigger this too" posture the Modbus write-without-read pattern above already established for a
  similarly soft signal.

Fixtures: `tests/sample_detect_snort_patterns_batch1.pcap`
(`build_detect_snort_patterns_batch1_sample()`) covers all six patterns plus four negative/contrast
conduits proving each pattern's own condition really is required -- a Diagnostics Return Query Data
request (an ordinary, routinely-used sub-function, not one of the three named ones); an
Encapsulated Interface Transport request with MEI type 0x0D (CANopen General Reference, not Read
Device Identification); a server returning the same exception code only twice (under threshold); and
a server whose third same-code exception falls outside the 60s window (proving pattern 6 is
genuinely windowed, not a whole-capture running count). `detect_snort_patterns_batch1_all_findings`
in `CMakeLists.txt` pins the full six-finding report end to end and asserts (via
`FAIL_REGULAR_EXPRESSION`) that none of the four negative conduits produced a finding of their own.
`real_modbus_diagnostics_force_listen_only_mode_decoded`/`..._restart_communications_option_decoded`/
`..._clear_counters_decoded`/`..._detect_batch1_all_findings` (`CMakeLists.txt`) do the same against
the real capture described above.

## Batch 2: six more Snort-style patterns (DNP3 control-plane operations plus known scanner-tool fingerprints)

A direct follow-up to Batch 1, from the same `docs/research/2026-09-detect-pattern-candidates-
batch2.md` document's own Batch 2 section (items 7-12). Jurgen confirmed "continue with batch 2"
immediately after Batch 1 shipped. Sourced from Quickdraw-Snort's `dnp3.rules`, CyberICS's
`scada-scan.rules`, and nmap's own published NSE source (`modbus-discover.nse`, cross-checked during
the original research pass; the BACnet-related NSE content needed a fresh fetch during this batch's
own implementation, see pattern 12 below).

| # | Pattern (as implemented) | Category / technique | Evidence | Severity | Novelty |
|---|---|---|---|---|---|
| 7 | DNP3 Stop Application (function 0x12) | EngineeringStationActivity / T0858 | Confirmed (always-notable) | Critical | N/A |
| 8 | A DNP3 Write-classified function addressed to a reserved broadcast destination (0xFFFF/0xFFFE/0xFFFD) | ProtocolMisuse / T0855 | Confirmed (always-notable) | Critical | N/A |
| 9 | DNP3 object-group/variation enumeration sweep: a master's Read requests span 5+ distinct object group/variation pairs against one outstation within 60s | EngineeringStationActivity / **T0861** (Point & Tag Identification) | Confirmed (always-notable, windowed) | Moderate | N/A |
| 10 | Modbus request byte-exact matches Metasploit's `scada/modbus_findunitid`/`modbus_detect` probe | ProtocolMisuse / T0888 | Confirmed (byte-exact) | Moderate | N/A |
| 11 | Modbus request byte-exact matches nmap's `modbus-discover.nse` Report Server ID or Read Device Identification probe | ProtocolMisuse / T0888 | Confirmed (byte-exact) | Informational | N/A |
| 12 | BACnet ReadProperty request for the Device object's wildcard/"any" instance (device,4194303) asking for one of nine standard identity properties | ProtocolMisuse / T0888 | Confirmed (field-exact) | Informational | N/A |

Implementation notes, by pattern:

- **Pattern 7 needed zero new decode work** -- function code 0x12 ("Stop Application") was already
  named in `dnp3.cpp`'s own function-code table before this batch (confirmed by grep before writing
  any code, per this project's own "confirm readiness before implementing" discipline). Pure
  `detect_engine.cpp` wiring: a new `else if` branch alongside the existing Cold/Warm Restart branch,
  its own distinct `finding_kind` (`"dnp3-stop-application"`) and technique (T0858, not T0816 --
  halting the application layer is a mode change, not a restart).
- **Pattern 8 is deliberately a SEPARATE check, not folded into the function-name chain.** A broadcast
  Cold Restart or Stop Application must produce BOTH its own function-specific finding AND
  `dnp3-broadcast-command` -- confirmed this is exactly what happens against the real capture below
  (a broadcast Stop Application there produces both findings). Gated on
  `dnp3_write_function_names()` (`dnp3.hpp` -- the same read/write classification
  `Policy::parse_policy_text`'s own `functions: [write]` keyword expansion already uses) rather than
  enumerating function names again in `detect_engine.cpp`; every Write-classified function is
  inherently master-issued (Confirm/Select/Response/Unsolicited Response are all `Other`), so no
  extra direction gating was needed.
- **Pattern 9 is the one pattern in this batch whose implementation deliberately DEPARTS from the
  research doc's own readiness note.** That note suggested "same mechanism as the already-built
  BACnet Who-Is-flood counter" (an unwindowed, whole-capture running count). The pattern's own wire
  condition text -- "an unusually wide spread of distinct object groups/variations... within a short
  window" -- explicitly calls for real time-windowing instead, so this reuses
  `modbus_exception_burst_state_`'s own windowed-reset shape (Batch 1 pattern 6) rather than the
  unwindowed one: a whole-capture running count would treat four unrelated single-object polls spread
  across an hour-long capture the same as four different object types requested within one burst --
  not the same signal. `Dnp3EnumerationSweepState` (`detect_engine.hpp`) tracks a SET of `(group,
  variation)` pairs, not a count -- the pattern is about DIVERSITY of what's being read, so a master
  re-reading the same handful of object types many times within the window must never trip this on
  repetition alone. Threshold (5 distinct pairs) and window (60s, matching
  `kModbusExceptionBurstWindowSeconds` for consistency) are another small, documented judgment call,
  not vendor-sourced -- Quickdraw's own SIDs 1111213/1111214 generalize a differently-shaped condition
  (repeated exception RESPONSES, `threshold: count 3-5, seconds 30-60`) that doesn't transplant
  directly. T0861 (Point & Tag Identification) was picked over the more generic T0888 already used
  elsewhere in this file because it's the more semantically precise MITRE fit for a points-list-shaped
  sweep specifically -- both were already in `mitre_attack_ics.hpp`'s existing table, so no new
  technique citation was needed.
- **Patterns 10 and 11 resolved an open design question the research doc itself flagged**: whether
  byte-exact scanner-tool fingerprinting would need new raw-frame-byte exposure, since every existing
  `detect_engine.cpp` pattern before this batch read a DECODED/named field, never raw payload bytes.
  It did not. Every byte Metasploit's and nmap's own fixed probe framings touch is already available
  as an individually-decoded `ModbusFrame` field (`transaction_id`/`protocol_id`/`mbap_length`/
  `unit_id`/`function_code`) or via `raw_pdu_data` (already exposed "for hex fallback/JSON",
  `modbus.hpp`, covering the PDU bytes after the function code) -- confirmed by decomposing each
  cited byte string field-by-field against `ModbusFrame`'s own layout before writing any code. A new
  `raw_pdu_matches()` helper (`detect_engine.cpp`, an exact-length-and-content byte comparison against
  `raw_pdu_data`) is the only new machinery this needed. Metasploit's probe (pattern 10) is Moderate,
  not Informational like the two nmap probes (pattern 11) -- Metasploit is exploit-adjacent tooling,
  not pure reconnaissance, matching the research doc's own "Informational-to-Moderate" call for that
  one. The two nmap sub-patterns (Report Server ID and Read Device Identification) use two distinct
  `finding_kind` tags (`modbus-scanner-nmap-report-server-id`/`modbus-scanner-nmap-read-device-id`),
  not one shared tag -- a conduit hit by both probes gets two findings, not one silently overwriting
  the other's own description. Both nmap sub-patterns also legitimately co-occur with Batch 1's own
  generic new-vs-known Read-Device-ID/Report-Server-ID findings on the same conduit (a tool-specific,
  higher-confidence fingerprint AND a generic first-occurrence reconnaissance finding are both true at
  once) -- confirmed directly in the synthetic fixture's own report, not assumed.
- **Pattern 12 is the one item the research doc itself flagged as not implementation-ready**: "needs
  the specific nmap BACnet NSE script's own request bytes read directly... before implementing." That
  research pass ran as part of this batch's own implementation (a fresh fetch of CyberICS's
  `scada-scan.rules` BACnet section). It surfaced two corrections to the original research pass: the
  ruleset actually ships **nine** BACnet-nmap SIDs (101563265-101563273), not the eight the original
  pass estimated from the repo's rule count alone (Vendor-Name, SID 101563273, was missed); and every
  one of the nine rules is byte-identical except its final property-identifier byte --
  `|81 0a 00 11 01 04 00 05 01 0c 0c 02 3f ff ff 19 <property>|` -- decoded field by field:
  BVLC-Original-Unicast-NPDU, NPDU version 1, a Confirmed-Request ReadProperty (service 12) whose
  ObjectIdentifier is object type 8 (device) instance `0x3FFFFF` (4194303, BACnet's own
  22-bit-all-ones "any device" wildcard instance -- a real, spec-legal convention for addressing a
  device without already knowing its real instance number, but one a legitimate operator who already
  knows their own devices' instance numbers has no routine reason to use), asking for one of nine
  standard identity properties (Application-Software-Version/Description/Firmware-Revision/Location/
  Model-Name/Object-Identifier/Object-Name/Vendor-Identifier/Vendor-Name). Unlike patterns 10/11, this
  needed NO raw-byte matching at all: every byte this fingerprint needs is already available as
  rendered `BacnetApdu::values` entries (`"object=device,4194303"`/`"property=<name>"`) --
  `decode_object_property_reference` (`bacnet.cpp`) already renders an object identifier as
  `<object_type_name>,<instance>` and a property as its own name, so this pattern is a plain string
  comparison against already-decoded fields, deliberately NOT byte-exact against invoke-ID/max-APDU
  bytes the way patterns 10/11 are (those bytes vary by nmap version/config in ways the object/
  property pair does not).
- **Three of the six (7, 8, 9) are independently verified against this project's own REAL capture,
  `tests/real_captures/dnp3/dnp3_test_data_part1.pcap`** -- an unplanned, welcome bonus matching Batch
  1's own precedent with `modbus_test_data_part1.pcap`. `detect --read` against that capture fires a
  genuine Stop Application finding (twice, against two different outstations), a genuine broadcast
  Disable Unsolicited Responses (destination 0xFFFF), a genuine broadcast Stop Application (both the
  function-specific AND the broadcast finding fire together, confirming pattern 7 and pattern 8 are
  correctly independent), and a genuine 5-distinct-object-group/variation enumeration sweep --
  confirmed via this project's own manual verification pass against the real CLI output before
  writing `real_dnp3_detect_batch2_findings`'s own assertion. Patterns 10/11/12 (the scanner-tool
  fingerprints) have no real-capture evidence -- no real capture in this project happens to have been
  generated by Metasploit or nmap -- so those three rely entirely on the synthetic fixture.

Fixtures: `tests/sample_detect_snort_patterns_batch2.pcap`
(`build_detect_snort_patterns_batch2_sample()`) covers all six patterns plus eight negative/contrast
conduits proving each pattern's own condition really is required: a Stop Application to a
non-broadcast destination (proving 7 and 8 are independent); a broadcast Read (Read-classified, not
Write -- proving 8's function-access gate matters, not just the destination address); an
under-threshold enumeration sweep (4 distinct pairs); a windowed-out enumeration sweep (5 distinct
pairs, but the 5th arrives 95s after the window's own first occurrence); a Metasploit near-miss
(quantity=1, not the probe's own quantity=0); two nmap near-misses (a different unit ID, a different
transaction ID); a BACnet wildcard-instance request for a property outside the nine-property set; and
a BACnet request for one of the nine properties but against a REAL (non-wildcard) device instance.
`detect_snort_patterns_batch2_all_findings` (`CMakeLists.txt`) pins the full eleven-finding report
(seven Batch 2 sources plus four co-occurring Batch 1 generic new-vs-known findings on the nmap
sub-pattern conduits) end to end and asserts, via `FAIL_REGULAR_EXPRESSION`, that none of the six
negative-only conduits produced a finding of their own. `real_dnp3_detect_batch2_findings`
(`CMakeLists.txt`) does the same against the real capture described above.

## Batch 3: six more patterns (public CVE/advisory-grounded field anomalies and cross-protocol weak-security/recon)

A direct follow-up to Batch 2, from the same `docs/research/2026-09-detect-pattern-candidates-
batch2.md` document's own Batch 3 section (items 13-18). Jurgen confirmed "continue with batch 3"
(and, in the same message, "you can do batch 3") immediately after Batch 2 shipped. Sourced from two
real, published NVD CVEs (CVE-2017-16740, CVE-2021-22659 -- both Rockwell Allen-Bradley/MicroLogix
buffer overflows triggered by anomalous Modbus/TCP protocol-field values), Claroty Team82's own
published OPC UA hardening guidance, and Léargas Security's ruleset description. Unlike Batches 1-2,
this batch is NOT built around one single ruleset -- each pattern has its own independent primary
source, matching the research doc's own framing of Batch 3 as "field anomalies and cross-protocol
weak-security/recon patterns" rather than one vendor's SID set.

| # | Pattern (as implemented) | Category / technique | Evidence | Severity | Novelty |
|---|---|---|---|---|---|
| 13 | Modbus MBAP declared length exceeds the true 254-byte spec ceiling, OR disagrees with the packet's own actual remaining byte count | ProtocolMisuse / T0855 | Confirmed (always-notable) | Moderate | N/A |
| 14 | Modbus read/write quantity exceeds its own function's Modbus Application Protocol Specification V1.1b3 maximum | ProtocolMisuse / T0855 (read) or **T0831** (Manipulation of Control, write) | Confirmed (always-notable) | Critical | N/A |
| 15 | OPC UA OpenSecureChannel negotiating SecurityPolicy=None, OR ActivateSession using an anonymous identity token (two independent findings) | ProtocolMisuse / T0886 | Confirmed (always-notable) | Moderate | N/A |
| 16 | CIP Reset (service 0x05) addressed at the Identity object (class 0x01) | FirmwareLogicChange / T0816 | Confirmed (always-notable) | Critical | N/A |
| 17 | CIP List Identity/Services/Interfaces from a second, different originator to the same target | EngineeringStationActivity / T0888 | Confirmed (new-vs-known) | Informational | First Occurrence / Confirmed New |
| 18 | IEC 104 General Interrogation (C_IC_NA_1, COT=activation) addressed to the broadcast Common Address of ASDU (0xFFFF) | ProtocolMisuse / T0855 | Confirmed (always-notable) | Critical | N/A |

Implementation notes, by pattern:

- **Pattern 13 needed zero new decode work**, but its OWN fixture construction surfaced a real
  implementation constraint worth recording: an inflated `mbap_length` can only ever reach this check
  on a function whose request-classification doesn't require an EXACT payload length.
  `decode_read_family` (`modbus.cpp`) classifies a PDU as a request only when it is precisely 4 bytes
  (address+quantity) -- any padding added to push `mbap_length` past 254 lands in that function's own
  "unrecognized payload shape" branch instead, leaving `is_request` unset and this check silently
  unable to fire at all (caught during this batch's own fixture verification pass: an initial Read
  Holding Registers-based scenario produced no finding whatsoever). `decode_write_multiple`'s own
  request branch has no such exact-length requirement (`data.size() >= 5` is enough), so the shipped
  fixture uses Write Multiple Registers instead. The mismatch sub-condition has its own asymmetry:
  this decoder's own TCP reassembly (`modbus_tcp_declared_length`) only calls `try_parse_modbus_tcp`
  once at least `6 + mbap_length` bytes have arrived, so a DECLARED length LARGER than what's actually
  sent leaves the reassembler waiting forever (confirmed the same way -- an initial larger-than-actual
  version of the mismatch scenario produced only a "buffering... waiting for more" decode note, never
  a finding). A declared length SMALLER than actual is instead already-complete from the reassembler's
  point of view, so `try_parse_modbus_tcp` runs immediately against the full actual payload and its own
  existing length-consistency check (unaffected by the declared boundary, since it reads whatever bytes
  are actually there) is what produces the "MBAP length field implies..." note this pattern's mismatch
  branch scans `ModbusFrame::notes` for. Both branches share one `finding_kind`
  (`modbus-mbap-length-anomaly`) -- they're the same underlying wire-condition (a client's declared
  MBAP length disagreeing with reality), not two different patterns.
- **Pattern 14 needed zero new decode work.** `ModbusFrame::quantity` was already decoded and exposed;
  this is a small per-function-code maximum-quantity table (2000 Read Coils/Discrete Inputs, 125 Read
  Holding/Input Registers, 1968 Write Multiple Coils, 123 Write Multiple Registers, from the Modbus
  Application Protocol Specification V1.1b3 itself) plus one comparison. Distinct from the pre-existing
  "write outside every range ever read" pattern (Grok gap #4's own original work): that one is
  baseline-relative (needs a prior read on the same conduit to compare against); this one is
  protocol-conformance-absolute and fires with no baseline needed at all, since a spec-violating
  quantity has no legitimate baseline to be "new" against. Read vs. write picks the MITRE technique
  (T0855 vs. T0831) -- the research doc's own explicit "depending on read-vs-write" call.
- **Pattern 15 resolved the research doc's own explicitly-flagged open question**: whether
  conduitscope's existing OPC UA decoder already exposes the negotiated SecurityPolicy URI and
  UserIdentityToken type on its decoded struct. It does, for both: `OpcUaMessage::security_policy_uri`
  (asymmetric OpenSecureChannel messages) and an `"identity=anonymous"` entry in
  `OpcUaMessage::values` (`ActivateSessionRequest`) were both already exposed before this batch --
  zero new decode work needed, resolving that question the same direction Batch 2 patterns 10/11
  resolved theirs (no new raw-field exposure needed). Implemented as TWO independent, deliberately
  SEPARATE always-notable findings rather than one combined "weak session" finding -- this decoder is
  stateless-per-message (no channel/session correlation, per `opcua.hpp`'s own "Deliberately NOT
  implemented" paragraph), so there is no reliable way to confirm a given ActivateSession's own
  SecureChannel actually used SecurityPolicy=None without adding real cross-message state tracking
  this codebase has for no protocol today; each condition is independently a real, citable OPC UA
  security finding on its own regardless (Claroty's own guidance treats them as two separate checks
  too). A second, related departure from the research doc's own suggestion: T0886 (Remote Services) is
  used unconditionally here, WITHOUT the T0822 (External Remote Services) zone-crossing upgrade the
  pre-existing RemoteAccessChannel new-vs-known source gets. That upgrade lives entirely inside
  `finish()`'s own new-conduit-candidate resolution (`NewConduitCandidate::is_remote_access`), coupled
  to baseline-relative "new vs. known" novelty resolution -- but these two findings are always-notable
  (a weak configuration is worth flagging every time it's seen, not just the first), so reusing that
  path would mean either bolting policy-dependent technique resolution onto the always-notable path
  for the first time in this engine, or duplicating the zone-crossing logic outright. Disproportionate
  complexity for one item among six, when a weak/anonymous OPC UA session is worth flagging regardless
  of whether it happens to cross a declared zone boundary -- a deliberate, documented scope departure,
  the same "who asked, why, what was rejected" convention Batch 2 pattern 9's own windowing departure
  already established.
- **Pattern 16 needed zero new decode work** -- the single most implementation-ready item in this
  whole 18-item candidate list, exactly as the research doc itself called out. CIP service 0x05
  ("Reset") was already named and classified a Write-access service by `src/enip.cpp` before this
  batch. Pure `detect_engine.cpp` wiring: request side only, gated on `ef.cip.path.class_id == 0x01`
  (the Identity object) the same way the pre-existing `cip-identity-write` pattern is gated.
- **Pattern 17 also needed zero new decode work** -- `enip_command_name`'s own case statements for
  `ListServices`/`ListIdentity`/`ListInterfaces` (0x0004/0x0063/0x0064) were already in place. Uses
  the same "second-plus originator to a given server is new, first is not" mechanism as the
  pre-existing CIP Forward_Open pattern, but as its OWN separate per-server originator map
  (`enip_list_discovery_originators_by_server_`, not folded into `cip_originators_by_server_`) -- these
  three encapsulation commands carry no CIP message at all (`EnipFrame::has_cip` stays false for them),
  a structurally different signal from a Forward_Open, so a client credited for one isn't implicitly
  credited for the other. Caught and fixed during this batch's own manual verification pass: an
  initial version of this pattern's `finish()`-side description text fell through to the pre-existing
  `cip-new-originator` fallback branch (which only checked `source_tag` against a fixed, now-stale
  list of names via an `if`/`else if`/... /`else` chain whose final `else` assumed it was the only
  remaining case) and rendered as "CIP Forward_Open from a new originator" -- actively wrong, since no
  Forward_Open was ever involved. Fixed by adding this pattern's own named branch
  (`source_tag == "enip-new-originator-discovery"`) before that fallback; `NewConduitCandidate::
  source_tag`'s own doc comment (`detect_engine.hpp`) now lists every recognized tag so this doesn't
  silently recur for a future pattern. Scope note: this only sees these three commands when carried
  over TCP -- this codebase's own EtherNet/IP UDP path (`enip_udp_decoder()`) covers CIP I/O (implicit
  real-time messaging) only, not encapsulation commands, so a UDP-broadcast discovery scan (the more
  common real-world mechanism for this specific recon shape) is not seen by this finding; see
  `docs/USER_GUIDE.md`'s own LIMITATIONS entry.
- **Pattern 18 needed zero new decode work.** `Iec104AsduInfo::common_address` was already decoded and
  tracked per-ASDU since item 3's own type/COT/IOA-range work. Gated on COT "activation" specifically
  (`ir.iec104_cot_name == "activation"`), the same discipline the pre-existing `iec104-reset-process`
  pattern already established for isolating an actual command from its own confirmation/termination
  ASDUs sharing the same type ID -- confirmed via this batch's own fixture, which includes a negative
  scenario proving a broadcast-addressed interrogation with COT="activation confirmation" does NOT
  fire.
- **Item 15 is independently verified against a REAL capture**,
  `tests/real_captures/opcua/opc-ua-ap-method-wireshark-freeze.pcap` -- an unplanned, welcome bonus
  matching every prior batch's own precedent. `detect --read` against that capture fires both of
  pattern 15's own findings genuinely, on a real OPC UA session between `192.168.41.176` and
  `192.168.41.212:12001`. This project's own pre-existing `tests/sample_opcua.pcap` (built long before
  this batch existed, for `opcua.hpp`'s own decode-coverage purposes) also happens to genuinely
  exercise both sub-patterns, so item 15 needed no new fixture of its own at all -- the only item
  across all three batches so far where BOTH a real capture and a pre-existing synthetic fixture
  already covered a brand-new pattern with zero fixture-construction work.

Fixtures: `tests/sample_detect_snort_patterns_batch3.pcap`
(`build_detect_snort_patterns_batch3_sample()`) covers the five patterns needing a new fixture (13,
14, 16, 17, 18) plus five negative/contrast conduits proving each pattern's own condition really is
required: an MBAP length exactly at the 254-byte spec boundary (inclusive); a quantity exactly at a
function's own spec maximum (inclusive); a CIP Reset addressed at the Assembly object (class 0x04)
instead of Identity; the FIRST originator ever seen querying a CIP List* target (nothing to be "new"
relative to yet); a General Interrogation to a normal, non-broadcast Common Address; and a broadcast-
addressed General Interrogation whose COT is "activation confirmation" rather than "activation". Two
of the five positive scenarios (Modbus MBAP-length-ceiling and quantity-out-of-spec, both Write
Multiple Registers requests with no prior read on their own conduit) also, unavoidably and correctly,
trip this engine's own pre-existing modbus-write-without-read pattern -- expected collateral from
reusing a write function to exercise these checks, not a second bug; documented in the fixture's own
docstring and accounted for in `detect_snort_patterns_batch3_all_findings`'s own assertion.
`detect_snort_patterns_batch3_all_findings` (`CMakeLists.txt`) pins the full ten-finding report end to
end and asserts, via `FAIL_REGULAR_EXPRESSION`, that none of the five negative-only conduits produced
a finding of their own. `opcua_detect_weak_session_findings` and
`real_opcua_detect_weak_session_findings` (`CMakeLists.txt`) cover item 15 against the pre-existing
synthetic fixture and the real capture described above, respectively.

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
