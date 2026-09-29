// SPDX-License-Identifier: Apache-2.0
// detect_engine.hpp - the `detect` subcommand's engine: "Detection that OT IR teams recognize"
// (Grok gap #4, docs/reviews/2026-09-grok-ics-ot-improvement-areas.md item 4). See
// docs/design/detection-engine.md for the full design record and Jurgen's own scoping decisions.
//
// One dedicated subcommand holds every item-4 finding in a single unified report (Jurgen's own
// choice, over the alternative of splitting baseline-independent-structural findings into
// attack_detect.hpp's existing curated-notes model and new-vs-known findings into `baseline
// check`'s report). Two structurally different kinds of finding live here, exactly mirroring
// attack_detect.hpp's own "two kinds of evidence" split (see that file's header comment) but for a
// different reason:
//
// ALWAYS-NOTABLE findings -- a PLC/controller mode change, a firmware/logic download, a device
// restart, an unsolicited/unexpected protocol message -- need no "new vs. known" judgment at all:
// the traffic SHAPE itself is what's notable, every single time it's seen, the same "always worth a
// human's attention regardless of baseline" concept baseline.cpp's own Operation::always_flag
// already established for S7 PLC Control/PLC Stop (see that field's own comment, baseline.hpp).
// These carry DetectionNovelty::NotApplicable (no "new vs. known" judgment is made at all) and are
// produced entirely from fields this codebase already decodes -- see detect_engine.cpp's
// per-protocol wiring for exactly which.
//
// NEW-VS-KNOWN findings -- a remote-access protocol reaching a conduit, a CIP originator opening a
// connection -- are only notable when they're NEW, and "new" needs a concrete, honestly-labeled
// mechanism (Grok's own text: "keep the honesty: label confidence"):
//   - With an optional --baseline-file supplied (reusing baseline.hpp's own load_baseline_store/
//     BaselineStore read-only, mirroring `baseline check`'s own flag name): a conduit genuinely
//     absent from the loaded store's ConduitBaseline list is real evidence of "new" ->
//     DetectionNovelty::ConfirmedNew.
//   - Genuinely PRESENT in the loaded baseline: not new at all -- no finding is produced.
//   - No --baseline-file given (the common single-pcap assessment case): evaluated as
//     first-occurrence-within-this-capture -- weaker evidence (the capture might simply start after
//     the channel was already long-established), so DetectionNovelty::FirstOccurrence, and the
//     finding's own description says so and suggests --baseline-file.
// See DetectEngine::finish's own comment for exactly how this two-stage (per-packet candidate
// tracking, then whole-capture baseline resolution) pipeline works.
//
// THREE INDEPENDENT DIMENSIONS, DELIBERATELY NOT ONE CONFLATED "CONFIDENCE" FIELD. An earlier
// version of this file used a single `DetectionConfidence{High,Medium,Low}` field that quietly
// mixed together three genuinely different questions -- flagged directly by Jurgen ("separate
// evidence confidence from maliciousness and severity... distinguish confirmed protocol evidence,
// baseline deviation, operational severity, and malicious intent") and corrected before it shipped
// further. Every DetectionFinding now carries three independent fields, and asserts nothing at all
// about a fourth:
//   - `evidence` (DetectionEvidence: Confirmed/Heuristic) -- how reliably the underlying protocol
//     event itself was established from the decode. Confirmed means a protocol field was read
//     directly and unambiguously off the wire (a function code, a service name, a CIP path segment)
//     -- true for nearly every finding source in this file. Heuristic means part of the finding's
//     own claim rests on an inference that could be wrong -- today, only the RemoteAccessChannel
//     source (Tier-1 protocol identification is itself notable_it_protocols.hpp's own weakest,
//     port-only tier, and client/server direction is decided by the "lower port number is the
//     server" guess, not a decoded field). This dimension is ONLY about decode/observation
//     reliability -- it says nothing about how bad the observed event would be, or whether it's
//     malicious.
//   - `novelty` (DetectionNovelty: NotApplicable/ConfirmedNew/FirstOccurrence) -- exactly the
//     "new vs. known" resolution described above, now its own field rather than folded into
//     confidence. NotApplicable for every always-notable finding (no such judgment is made at all).
//   - `severity` (DetectionSeverity: Critical/Moderate/Informational) -- the operational impact IF
//     the observed action is genuine and intentional, independent of both of the above: a PLC Stop
//     is Critical whether or not the master that sent it was authorized, because the operational
//     consequence (the CPU actually stops) is the same either way. See detect_engine.cpp's own
//     per-finding-source comment for the Critical/Moderate/Informational call on each one.
//   - Nothing here ever asserts MALICIOUS INTENT, and no field claims to. A citation to MITRE
//     ATT&CK for ICS (mitre_attack_ics.hpp's own header comment already establishes this for
//     `technique`) names the traffic's SHAPE, not a verdict; `evidence` says how sure this tool is
//     that shape was really observed; `severity` says how much it would matter if genuine; `novelty`
//     says whether it looks new. None of the three, alone or combined, says WHY the event happened
//     or WHO caused it -- this tool has no access to change-management records, authorized-
//     personnel lists, or asset criticality context, and does not pretend otherwise. That judgment
//     belongs entirely to the human analyst reading this report.
//
// Confidence/evidence/novelty/severity are deliberately new-findings-only for now: retrofitting a
// structured field onto attack_detect.hpp/ipv6_attack_detect.hpp/baseline's own existing findings is
// a separate, larger effort across already-shipped, already-tested code, and wasn't part of what
// Jurgen asked to start here -- see docs/design/detection-engine.md's own "explicitly out of scope"
// note.
//
// Six Snort-style patterns added as a direct follow-up (docs/design/detection-engine.md's own
// "Snort-style pattern extensions" section has the full research/scoping record for each):
//   - CIP Identity Object write (any Set_Attribute_Single/Set_Attributes_All WRITE addressed at CIP
//     class 0x01) -- always-notable, ProtocolMisuse/T0855, Critical severity. Deliberately scoped to
//     "any write to the Identity object" rather than a specific run/idle-mode attribute/value, since
//     no citable primary source for a ControlLogix mode-change wire format could be found -- see
//     detect_engine.cpp's own call-site comment.
//   - DNP3 Operate (0x04) with no matching prior Select (0x03) on the same master/outstation pair --
//     always-notable, ProtocolMisuse/T0855, Critical severity (Operate always performs a real
//     control action regardless of whether Select-before-Operate's own safety interlock was
//     honored). Deliberately NOT "Direct Operate observed" (Direct Operate is a legitimate,
//     routinely-used DNP3 mechanism, not a bypass) -- see dnp3_select_seen_'s own comment.
//   - A Modbus Write Multiple Coils/Registers request whose address range was never covered by any
//     prior read (same function family, same conduit) in this capture -- always-notable, but
//     Informational severity (not the usual Critical/Moderate every other always-notable finding
//     gets): many legitimate deployments write setpoints without ever reading them back first, so
//     this is honestly a much weaker signal, a prompt to review rather than a strong claim -- see
//     modbus_read_ranges_by_conduit_table_'s own comment and record_always_notable's own severity
//     parameter (detect_engine.cpp). Evidence is still Confirmed here -- the write and the absence
//     of a prior read genuinely were observed exactly as described; it's the SEVERITY of that
//     observation that's deliberately low, a distinction the old single confidence field couldn't
//     make.
//   - A BACnet Who-Is volumetric flood/enumeration sweep from one source, past a threshold --
//     always-notable, ProtocolMisuse/T0888, Informational severity (reconnaissance-shaped, no direct
//     control action) -- see bacnet_who_is_count_by_source_'s own comment.
//   - S7comm Setup Communication (0xF0) probing: a (client, server) pair with Setup Communication
//     seen repeatedly and NO other S7comm function ever seen between them in this whole capture --
//     resolved in finish() (not observe(), since "no other function ever seen" can only be known
//     once the whole capture has been read), EngineeringStationActivity/T0888, Informational
//     severity -- see s7_setup_comm_state_'s own comment.
//   - A composite: a Program Download finding (T0843) and a restart/mode-change finding (T0858/
//     T0816) both seen against the same server within a short window -- the classic "install then
//     activate" sabotage sequence, not necessarily two unrelated findings. Resolved in finish() as a
//     post-pass over this engine's OWN already-produced findings (needs no new observe()-time
//     tracking) -- FirmwareLogicChange/T0831, Critical severity, see finish()'s own implementation
//     comment (detect_engine.cpp).
//
// Six more patterns ("Batch 1"), added as a direct follow-up to the six above -- all Modbus/TCP,
// sourced from Digital Bond's Quickdraw-Snort modbus.rules (docs/research/2026-09-detect-pattern-
// candidates-batch2.md's own Batch 1 section has the full research/scoping record for each,
// including exact SID citations):
//   - Diagnostics (function 0x08) Force Listen Only Mode (sub-function 0x0004) -- always-notable,
//     EngineeringStationActivity/T0858, Critical severity. Per spec the target sends NO response to
//     this command at all (confirmed against this project's own real modbus_test_data_part1.pcap
//     capture, which genuinely contains this exact sub-function).
//   - Diagnostics Restart Communications Option (sub-function 0x0001) -- always-notable,
//     FirmwareLogicChange/T0816, Critical severity (also confirmed against that same real capture).
//   - Diagnostics Clear Counters and Diagnostic Registers (sub-function 0x000A) -- always-notable,
//     ProtocolMisuse/T0872 (Indicator Removal on Host -- the one new MITRE technique this batch
//     needed, mitre_attack_ics.hpp's own header comment has its own separate verification record),
//     Moderate severity (also confirmed against that same real capture). All three Diagnostics
//     sub-functions above share one deliberate scope boundary: Diagnostics' request and response
//     share the identical wire shape (see ModbusFrame::diagnostics_sub_function's own comment,
//     modbus.hpp), so direction is decided the same way S7comm's own detect wiring already decides
//     it (dp.dst_port == the well-known port), not a decoded field -- see detect_engine.cpp's own
//     call-site comment.
//   - Modbus Read Device Identification (function 0x2B, MEI type 0x0E) and Report Server ID
//     (function 0x11) from a client -- deliberately NEW-VS-KNOWN candidates (not always-notable,
//     unlike how Quickdraw's own rules treat them), EngineeringStationActivity/T0888, Informational
//     severity: a single such query is ordinary engineering-tool behavior, and only its novelty is
//     the honestly-supportable signal here -- see the research doc's own explicit proposal for this
//     pattern and detect_engine.cpp's own call-site comment. Unlike the CIP/UMAS new-originator
//     sources above, these are NOT gated on "second-plus originator to this server" -- every
//     occurrence becomes its own baseline-or-first-occurrence candidate.
//   - A repeated Modbus exception-code response burst: the SAME server returning the SAME exception
//     code 3+ times to the SAME client within roughly 60 seconds -- always-notable, ProtocolMisuse/
//     T0855, Moderate severity (a real but weak, retry-shaped signal -- legitimate retry/backoff
//     logic can trigger this too, the same posture as the Modbus write-without-prior-read pattern
//     above). Windowed (unlike bacnet_who_is_count_by_source_'s own whole-capture running count) --
//     see modbus_exception_burst_state_'s own comment for why.
//
// Six more patterns ("Batch 2"), a direct follow-up to Batch 1 -- DNP3 control-plane operations plus
// known Modbus/BACnet scanner-tool fingerprints (docs/research/2026-09-detect-pattern-candidates-
// batch2.md's own Batch 2 section has the full research/scoping record for each, including exact SID
// citations):
//   - DNP3 Stop Application (function 0x12) -- always-notable, EngineeringStationActivity/T0858,
//     Critical severity. Distinct from the pre-existing Cold/Warm Restart finding: this halts the
//     outstation's application layer without a full device restart. Pure wiring -- 0x12 was already
//     named in dnp3.cpp's own function-code table before this batch.
//   - DNP3 broadcast write/operate command: any DNP3 function this codebase already classifies as
//     Write (dnp3_write_function_names(), dnp3.hpp) addressed to one of DNP3's three reserved
//     broadcast destination addresses (0xFFFF/0xFFFE/0xFFFD) -- always-notable, ProtocolMisuse/T0855,
//     Critical severity (a single message with plant-wide blast radius). Deliberately NOT folded into
//     the per-function-name chain above -- a broadcast Cold Restart or Stop Application should still
//     produce BOTH its own function-specific finding and this one, not just one or the other. See
//     detect_engine.cpp's own call-site comment.
//   - DNP3 object-group/variation enumeration sweep: a single master's Read (0x01) requests against
//     one outstation span an unusually wide spread of distinct object group/variation combinations
//     within a short window -- always-notable, EngineeringStationActivity/T0861 (Point & Tag
//     Identification -- picked over the more generic T0888 already used elsewhere in this file
//     because T0861 is the more semantically precise fit for a points-list-shaped sweep specifically,
//     see detect_engine.cpp's own call-site comment), Moderate severity. WINDOWED (unlike
//     bacnet_who_is_count_by_source_'s own whole-capture running count) -- the research doc's own
//     readiness note suggested reusing that unwindowed mechanism, but the pattern's own wire
//     condition text ("within a short window") calls for real time-windowing instead, the same
//     departure already made once for modbus_exception_burst_state_ in Batch 1; see
//     dnp3_enumeration_sweep_state_'s own comment for the full reasoning.
//   - Known Modbus scanner-tool fingerprint, Metasploit's scada/modbus_findunitid / modbus_detect
//     auxiliary modules -- an exact MBAP+PDU byte match (transaction ID, protocol ID, length, unit
//     ID, function code, and PDU data all fixed by the tool itself) on TCP/502 -- always-notable,
//     ProtocolMisuse/T0888, Moderate severity (Metasploit is exploit-adjacent tooling, not pure
//     reconnaissance, so this sits slightly above the nmap fingerprints below -- see the research
//     doc's own "Informational-to-Moderate" call and detect_engine.cpp's own call-site comment for
//     why Moderate was picked). Needed NO new decode work and no raw-frame-byte exposure: every byte
//     this fingerprint touches is already available as an individually-decoded ModbusFrame field
//     (transaction_id/protocol_id/mbap_length/unit_id/function_code) or via raw_pdu_data (already
//     exposed "for hex fallback/JSON", modbus.hpp) for the PDU bytes after the function code --
//     confirmed during this batch's own implementation pass, resolving what the research doc's own
//     readiness note had flagged as possibly needing new raw-byte architecture.
//   - Known Modbus scanner-tool fingerprints, nmap's modbus-discover.nse -- two more exact byte
//     matches (Report Server ID and Read Device Identification, the SAME function codes Batch 1's
//     new-vs-known items 4/5 already watch generically, but nmap's own fixed probe framing is a
//     distinct, higher-confidence, tool-specific signal) -- always-notable, ProtocolMisuse/T0888,
//     Informational severity (pure reconnaissance tooling, not exploit-adjacent).
//   - Known BACnet scanner-tool fingerprint, a ReadProperty (confirmed service 12) request whose
//     ObjectIdentifier is the Device object's wildcard/"any" instance (device,4194303 -- BACnet's own
//     22-bit-all-ones convention for "whichever device answers, regardless of its real instance
//     number") for one of nine specific standard identity properties (Application-Software-Version/
//     Description/Firmware-Revision/Location/Model-Name/Object-Identifier/Object-Name/Vendor-
//     Identifier/Vendor-Name) -- always-notable, ProtocolMisuse/T0888, Informational severity. The
//     research doc's own readiness note flagged this item as needing one more research pass (the
//     CyberICS ruleset's exact rule content, not just its count/target, hadn't been fetched yet);
//     that pass ran as part of this batch's own implementation and also found the CyberICS ruleset
//     actually ships NINE BACnet-nmap SIDs (101563265-101563273), not the eight the original research
//     pass estimated from the repo's rule count alone (Vendor-Name, SID 101563273, was missed) -- see
//     detect_engine.cpp's own call-site comment for the full byte-level derivation. Resolved purely
//     from already-decoded BacnetApdu::values entries ("object=device,4194303"/"property=<name>"),
//     no raw-byte matching needed here either.
//
// Six more patterns ("Batch 3"), a direct follow-up to Batch 2 -- public CVE/advisory-grounded
// protocol-field anomalies and cross-protocol weak-security/recon patterns (docs/research/2026-09-
// detect-pattern-candidates-batch2.md's own Batch 3 section has the full research/scoping record for
// each, including exact CVE/advisory citations):
//   - Modbus MBAP declared-length anomaly (CVE-2017-16740, a real Rockwell Allen-Bradley MicroLogix
//     buffer overflow from a crafted MBAP length field) -- always-notable, ProtocolMisuse/T0855,
//     Moderate severity. Fires on a request whose mbap_length exceeds the Modbus Application Protocol
//     spec's own true 254-byte ceiling (this decoder's own kMaxPlausibleMbapLength, modbus.cpp,
//     already rejects anything above 300 outright, so 255-300 is the only anomalous-but-decoded window
//     this check can ever see) OR whose declared length disagrees with the packet's own actual
//     remaining byte count (already surfaced as a "MBAP length field implies..." note, modbus.cpp).
//     Pure wiring against an already-decoded field, no new decode work.
//   - Modbus read/write quantity out-of-spec (CVE-2021-22659, a real Rockwell MicroLogix 1400 buffer
//     overflow from an out-of-spec quantity value) -- always-notable, ProtocolMisuse/T0855 (read) or
//     ManipulationOfControl/T0831 (write), Critical severity. Fires when a request's already-decoded
//     `quantity` field exceeds ITS OWN function's Modbus Application Protocol Specification V1.1b3
//     maximum (2000 Read Coils/Discrete Inputs, 125 Read Holding/Input Registers, 1968 Write Multiple
//     Coils, 123 Write Multiple Registers) -- a spec violation regardless of what any specific device's
//     firmware does with it, distinct from the pre-existing baseline-relative "write outside every
//     range ever read" pattern (this one needs no baseline at all). Pure wiring.
//   - OPC UA weak-session pattern (Claroty Team82's own published OPC UA hardening guidance) -- TWO
//     deliberately separate always-notable findings, ProtocolMisuse/T0886, Moderate severity: an
//     OpenSecureChannel request negotiating SecurityPolicy=None (no encryption/signing at all), and an
//     ActivateSession request using an anonymous identity token (no real authentication). Kept as two
//     independent checks rather than one combined "weak session" finding because this decoder is
//     stateless-per-message (no channel/session correlation -- see opcua.hpp's own "Deliberately NOT
//     implemented" paragraph) -- there is no reliable way to confirm a given ActivateSession's own
//     SecureChannel actually used SecurityPolicy=None without adding real cross-message state tracking
//     this codebase has for no protocol today; each condition is independently a real, citable OPC UA
//     security finding on its own regardless. T0886 is used unconditionally, WITHOUT the T0822
//     (External Remote Services) zone-crossing upgrade the pre-existing RemoteAccessChannel new-vs-
//     known source gets -- a deliberate, documented scope departure from the research doc's own
//     suggestion to reuse that mechanism: the zone-crossing check lives entirely inside finish()'s own
//     new-conduit-candidate resolution (NewConduitCandidate::is_remote_access), coupled to baseline-
//     relative "new vs. known" novelty resolution; these two findings are always-notable (novelty
//     N/A -- a weak configuration is worth flagging every time it's seen, not just the first), so
//     reusing that path would mean either bolting policy-dependent technique resolution onto the
//     always-notable path for the first time in this engine, or duplicating the zone-crossing logic --
//     disproportionate complexity for one item among six, when a weak/anonymous OPC UA session is
//     worth flagging regardless of whether it happens to cross a declared zone boundary. Needed no new
//     decode work: security_policy_uri (OpcUaMessage, asymmetric OpenSecureChannel messages) and the
//     "identity=anonymous" values entry (ActivateSessionRequest) were both already exposed.
//   - EtherNet/IP CIP Identity Object Reset (service 0x05, "Reset", addressed at CIP class 0x01) --
//     always-notable, FirmwareLogicChange/T0816, Critical severity. A direct CIP-native analog to DNP3
//     Cold Restart/S7 PLC Stop/UMAS STOP_PLC. Needed ZERO new decode work -- src/enip.cpp already
//     named and classified this service before this batch; the single most implementation-ready item
//     in this whole 18-item candidate list.
//   - EtherNet/IP CIP List Identity/Services/Interfaces from a new originator (Léargas Security's own
//     ruleset description names this exact recon shape) -- deliberately a NEW-VS-KNOWN candidate (not
//     always-notable), EngineeringStationActivity/T0888, Informational severity: exactly how legitimate
//     engineering tools (RSLinx, Studio 5000) discover CIP devices on a segment, and exactly how a
//     scanner enumerates one too, so only a SECOND, DIFFERENT originator querying the SAME target
//     within this capture is flagged -- the same cip_originators_by_server_-style "first is not new"
//     asymmetry as the pre-existing CIP Forward_Open source. Needed zero new decode work (enip_command_
//     name already named all three encapsulation commands). Scope note: this only sees these three
//     commands when carried over TCP -- this codebase's own EtherNet/IP UDP path (enip_udp_decoder())
//     covers CIP I/O (implicit real-time messaging) only, not encapsulation commands, so a UDP-
//     broadcast discovery scan (the more common real-world mechanism for this specific recon shape)
//     is not seen by this finding; see docs/USER_GUIDE.md's own LIMITATIONS entry.
//   - IEC 60870-5-104 General Interrogation (C_IC_NA_1, COT "activation") addressed to the broadcast
//     Common Address of ASDU (0xFFFF, the standard's own reserved global/broadcast value) -- always-
//     notable, ProtocolMisuse/T0855, Critical severity (forces every RTU on the segment to report full
//     state at once, the same kind of outsized blast radius as Batch 2's DNP3 broadcast-command
//     finding, but for IEC 104). Deliberately a separate finding from the pre-existing iec104-
//     unexpected-cot/iec104-reset-process sources -- a distinct wire condition, not a variant of
//     either. Pure wiring against iec104_common_address, already decoded and tracked per-ASDU since
//     item 3's own type/COT/IOA-range work.
//
// Four more patterns ("Batch 4"), a direct follow-up to Batch 3 -- Digital Bond Quickdraw-Snort's
// remaining protocol-specific rulesets (s7.rules, enip.rules, bacnet.rules, omron.rules), read fresh
// rather than re-mined from Batches 1-3's own already-exhausted sources (modbus.rules/dnp3.rules/
// CyberICS/nmap/CVE/Claroty) (docs/research/2026-09-detect-pattern-candidates-batch2.md's own Batch 4
// section has the full research/scoping record for each, including exact SID citations):
//   - S7 Read SZL enumeration from a new originator (Quickdraw-Snort s7.rules SIDs 1111301/1111302,
//     "S7 Enumerate Redpoint NSE Request CPU Function Read SZL attempt") -- NEW-VS-KNOWN,
//     EngineeringStationActivity/T0888, same "second-plus originator to this PLC is new, first is not"
//     mechanism as the pre-existing CIP/UMAS/CIP-List* sources (s7_szl_originators_by_server_). The
//     Snort rule itself matches the Read SZL request SHAPE generically (S7 Userdata/CPU-functions/Read-
//     SZL, any SZL-ID), not a tool-specific byte fingerprint the way Batch 2's Metasploit/nmap Modbus
//     matches were -- so this reads as "a new engineering tool enumerated this PLC's identity", the S7
//     analog of the CIP-List*/UMAS-READ_ID/FINS-Controller-Data-Read findings, not a Redpoint-specific
//     signature. Gated the same way the pre-existing S7 PLC Control/Stop/download findings already are
//     (dp.dst_port == 102, a Job-side request addressed TO the PLC). Pure wiring against
//     S7CommResult::has_userdata_szl/userdata_szl_is_response, already decoded before this batch.
//   - EtherNet/IP List Identity via the Redpoint Nmap NSE script specifically (Quickdraw-Snort
//     enip.rules SID 1111517, TCP/44818; SID 1111518's own UDP variant is deliberately NOT implemented
//     here -- see below) -- a genuine byte-exact TOOL fingerprint (unlike the item above): Redpoint's
//     own NSE script hardcodes a fixed 4-byte value in the encapsulation header's own 8-byte Sender
//     Context field. Always-notable, ProtocolMisuse/T0888, Informational severity -- distinct from and
//     in addition to the pre-existing generic enip-new-originator-discovery finding (Batch 3 item 17),
//     the same "generic pattern plus a specific tool fingerprint" relationship Batch 1's Read-Device-
//     Identification/Report-Server-ID findings already have with their own Batch 2 Metasploit/nmap
//     fingerprints. Request side only (!ef.has_identity -- the target echoes the Sender Context
//     verbatim in its own response, so without this the same probe would produce two findings with
//     client/server swapped on the second one). SID 1111518's UDP variant is genuinely NOT
//     implementable today without new decode work: confirmed by reading src/enip.cpp this session that
//     EnipUdpDecoder::decode calls try_parse_cip_io only, never the encapsulation-command parse path,
//     so a UDP ListIdentity packet (the actual real-world discovery mechanism -- broadcast to port
//     44818 rather than opened per-target over TCP) is invisible to this decoder entirely -- the same
//     gap Batch 3 item 17's own LIMITATIONS entry already documents for the generic finding. Flagged
//     honestly as out of scope for this batch rather than silently narrowed or silently claimed.
//   - BACnet foreign-device/broadcast-distribution-table reconnaissance and misuse (Quickdraw-Snort
//     bacnet.rules, 9 SIDs 1111701-1111709 collapsing into three wire-level shapes): (a) a Register-
//     Foreign-Device request (BVLC function 0x05) -- NEW-VS-KNOWN, EngineeringStationActivity/T0888,
//     bacnet_foreign_device_register_originators_by_server_; (b) a Read-Foreign-Device-Table or Read-
//     Broadcast-Distribution-Table request (BVLC functions 0x06/0x02, folded into one finding/one
//     tracking map -- both are a read-only query against the same BBMD's own routing configuration) --
//     NEW-VS-KNOWN, EngineeringStationActivity/T0888, bacnet_bbmd_table_read_originators_by_server_;
//     (c) a BVLC-Result (function 0x00) carrying one of the three matching NAK codes -- 0x0030
//     (Register-Foreign-Device NAK), 0x0020 (Read-Broadcast-Distribution-Table NAK), or 0x0040 (Read-
//     Foreign-Device-Table NAK), verified directly against Wireshark's own packet-bvlc.c
//     bvlc_result_names table this session -- ALWAYS-NOTABLE (not new-vs-known: a NAK is the device's
//     own explicit refusal, real evidence regardless of who sent it), ProtocolMisuse/T0855, Moderate
//     severity. All three BacnetFrame fields (bvlc_function, has_result_code/result_code,
//     has_registration_ttl) were already decoded before this batch -- zero new decode work. Only three
//     of BVLC-Result's own six documented NAK codes are wired (matching the three request-side findings
//     (a)/(b) above); Write-Broadcast-Distribution-Table NAK (0x0010), Delete-Foreign-Device-Table-Entry
//     NAK (0x0050), and Distribute-Broadcast-To-Network NAK (0x0060) are deliberately left for a future
//     batch, since this one has no paired request-side finding for any of those three yet.
//   - OMRON FINS Controller Data Read from a new originator (Quickdraw-Snort omron.rules SIDs 1111401-
//     1111404, TCP/9600 and UDP/9600, command code 0x0501) -- NEW-VS-KNOWN, EngineeringStationActivity/
//     T0888, fins_originators_by_server_, same mechanism as the S7/CIP/UMAS sources above -- the FINS
//     analog of Modbus Read Device Identification/CIP List Identity/S7 Read SZL/UMAS READ_ID. Both TCP
//     and UDP FINS are already decoded by this codebase (unlike EtherNet/IP's own UDP gap above), so no
//     UDP scope limitation applies here; pure wiring against FinsFrame::command/command_name, already
//     decoded and named ("Controller Data Read") before this batch.
//   - Digital Bond's own modicon.rules (Schneider Modicon Function Code 90, i.e. UMAS) needed NO new
//     work: its Download Ladder Logic rule (UMAS function 0x34, DOWNLOAD_BLOCK) is already wired as
//     T0843 by the pre-existing UMAS work. Its Upload Ladder Logic rule (UMAS function 0x58) was
//     deliberately NOT wired -- Digital Bond's own rule message calls 0x58 "Upload Ladder Logic" but
//     the yanissec/umas-wireshark-dissector source this codebase's own UMAS decoder is built from names
//     it CHECK_PLC, a genuine unresolved naming disagreement between two independent reverse-engineering
//     sources -- flagged for one more research pass rather than guessed at.
//
// Five more patterns ("Batch 5"), sourced differently from every batch above: Jurgen asked directly
// whether other ICS ATT&CK techniques existed beyond the ones already cited, so this batch's own
// "source" is the live attack.mitre.org matrix itself (fetched fresh, 2026-09-29), not a Snort/
// Suricata ruleset -- each candidate then had to answer a question the ruleset-sourced batches didn't
// need to: does any already-decoded field actually carry the signal this MITRE technique describes?
// (docs/research/2026-09-detect-pattern-candidates-batch2.md's own Batch 5 section has the full
// research record, including two techniques checked and found NOT currently implementable -- T0800
// Activate Firmware Update Mode, T0892 Change Credential -- documented as honest negatives rather than
// silently skipped, and one flagged as needing one more primary-source check -- T0868 Detect Operating
// Mode, UMAS's MONITOR_PLC is a promising unwired lead but its exact semantics were never confirmed):
//   - Program Upload (S7 Start Upload/Upload/End Upload, function codes 0x1D/0x1E/0x1F; UMAS
//     INITIALIZE_UPLOAD/UPLOAD_BLOCK/END_STRATEGY_UPLOAD, 0x30/0x31/0x32) -- ALWAYS-NOTABLE,
//     FirmwareLogicChange/T0845, the exact mirror of the pre-existing s7-download/umas-download
//     findings (T0843) one function-code trio over in each protocol's own table. Both trios were
//     already fully decoded and named before this batch, sitting right next to their already-wired
//     Download counterparts -- zero new decode work, pure `detect_engine.cpp` wiring.
//   - Port Scan (T0846.001) -- a genuinely new KIND of finding: no protocol decode at all, only the
//     raw TCP layer (DecodedPacket::tcp_flags == "SYN", the same pure-SYN check three other files in
//     this codebase already use for handshake tracking, plus dst_port/has_tcp). One source sweeping an
//     unusually wide spread of distinct destination ports on one destination IP via pure-SYN packets
//     within a short window -- ALWAYS-NOTABLE, ProtocolMisuse/T0846.001, Moderate severity. Windowed
//     SET-of-distinct-values tracking, the same shape Batch 2's DNP3 enumeration sweep established,
//     applied at the TCP-port layer instead of a protocol-semantic one. Deliberately TCP-only this
//     pass -- UDP has no SYN-equivalent unambiguous connection-attempt marker in what this codebase
//     decodes; a UDP sweep heuristic is left for a future pass rather than guessed at now. The first
//     `DetectEngine` finding not gated on any specific ICS protocol at all.
//   - Rogue Master (T0848) -- a second distinct source starts issuing WRITE-classified commands
//     against an outstation that already has an established write-capable master -- NEW-VS-KNOWN,
//     ProtocolMisuse/T0848, Critical severity (a displacing/second write-capable master is a
//     materially more serious signal than mere read-only reconnaissance). Distinct from every existing
//     new-originator finding: those track "any second originator" (mostly read-only enumeration, or
//     one specific control operation); this tracks specifically "a second originator that starts
//     WRITING" as its own signal, reusing modbus_write_function_names()/dnp3_write_function_names()
//     (both already existed, backing Policy::parse_policy_text's own read/write keyword expansion) --
//     zero new decode work, one new write-capable-master-per-outstation tracker per protocol
//     (modbus_write_originators_by_server_/dnp3_write_originators_by_server_). Scoped to Modbus and
//     DNP3 only: Modbus had NO originator-tracking of any kind before this batch (confirmed by grep),
//     and UMAS's own write-shaped functions (START_PLC/STOP_PLC/the Download trio) already produce
//     their own always-notable finding on every occurrence regardless of originator, so a redundant
//     "second writer" layer on top would add noise, not signal, there.
//   - Brute Force I/O (T0806) -- a burst of WRITE-classified requests (the same classification #25
//     reuses) against the same outstation within a short window -- ALWAYS-NOTABLE, ProtocolMisuse/
//     T0806, Moderate severity (deliberately weaker, matching the existing Modbus exception-burst
//     pattern's own posture -- legitimate fast-polling engineering tools doing rapid setpoint
//     adjustment during commissioning can trigger this too). Reuses the exact windowed-count-per-key
//     machinery Batch 1's modbus-exception-burst and Batch 2's dnp3-enumeration-sweep already
//     established, applied to write volume instead of exception responses or object-group diversity.
//   - Also re-mapped, not new: the pre-existing bacnet-who-is-flood finding now cites T0846.002
//     (Broadcast Discovery) instead of T0888 -- MITRE's own T0846.002 description names "BACnet Who-Is
//     requests" as a canonical example BY NAME, not an inference. Zero behavior change, one technique
//     constant swapped at one call site.
#pragma once

#include <cstdint>
#include <iosfwd>
#include <set>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "conduitscope/baseline.hpp"  // BaselineStore -- optional finish() input
#include "conduitscope/decoder.hpp"
#include "conduitscope/mitre_attack_ics.hpp"
#include "conduitscope/policy.hpp"  // Policy -- optional finish() input, for T0886-vs-T0822

namespace conduitscope {

class Resolver;  // forward-declared -- see asset_inventory.hpp's own identical forward declaration

// One of the four finding shapes Grok's item 4 names -- see this file's own header comment for the
// techniques each maps to. Independent of evidence/novelty/severity: a category says WHAT KIND of
// thing this is; the other three say how reliably it was observed, whether it's new, and how much it
// would matter if genuine.
enum class DetectionCategory {
    EngineeringStationActivity,  // a PLC/controller mode change (S7 PLC Control/Stop, ...)
    FirmwareLogicChange,         // a firmware/logic/program download, or a device restart
    RemoteAccessChannel,         // a new remote-access session (RDP/VNC/TeamViewer/...) into a zone
    ProtocolMisuse,              // an unsolicited/unexpected protocol message, a new CIP originator
};

const char* detection_category_name(DetectionCategory category);  // "Engineering-Station Activity",
                                                                     // "Firmware/Logic Change",
                                                                     // "Remote-Access Channel",
                                                                     // "Protocol Misuse"

// How reliably the underlying protocol event itself was established from the decode -- and ONLY
// that. Says nothing about how bad the event would be, whether it's new, or whether it's malicious;
// see this file's own header comment ("THREE INDEPENDENT DIMENSIONS...") for the full rationale.
enum class DetectionEvidence {
    Confirmed,  // a protocol field was read directly and unambiguously off the wire (a function
                // code, a service name, a CIP path segment) -- true for nearly every finding source.
    Heuristic,  // part of the finding's own claim rests on an inference that could be wrong -- today,
                // only the RemoteAccessChannel source (Tier-1 port-only protocol identification, plus
                // the "lower port number is the server" direction guess).
};

const char* detection_evidence_name(DetectionEvidence evidence);  // "Confirmed"/"Heuristic"

// Whether this finding is NEW relative to a baseline -- and ONLY that. Says nothing about how
// reliably the event was observed or how severe it would be; see this file's own header comment.
enum class DetectionNovelty {
    NotApplicable,    // an always-notable finding -- no "new vs. known" judgment is made at all.
    ConfirmedNew,      // --baseline-file was supplied and this conduit is genuinely absent from it.
    FirstOccurrence,   // no --baseline-file was supplied -- first-occurrence-within-this-capture
                        // only, honestly weaker evidence (the capture might simply start after the
                        // channel was already long-established).
};

const char* detection_novelty_name(DetectionNovelty novelty);  // "N/A"/"Confirmed New"/
                                                                  // "First Occurrence"

// The operational impact IF the observed action is genuine and intentional -- and ONLY that.
// Independent of both evidence and novelty: a PLC Stop is Critical whether or not the master that
// sent it was authorized, and whether or not it's new, because the operational consequence (the CPU
// actually stops) is the same either way. Never a claim about malicious intent -- see this file's
// own header comment.
enum class DetectionSeverity { Critical, Moderate, Informational };

const char* detection_severity_name(DetectionSeverity severity);  // "Critical"/"Moderate"/
                                                                     // "Informational"

// One finding. `technique` is always populated (every finding this engine produces cites exactly
// one MITRE ATT&CK for ICS technique, from mitre_attack_ics.hpp's own curated ten) -- never a
// generic "something happened" note with no citation, matching Grok's own "not a generic 'IT
// protocol seen' bucket" ask. `evidence`/`novelty`/`severity` are three deliberately independent
// dimensions -- see this file's own header comment ("THREE INDEPENDENT DIMENSIONS...") -- and never,
// individually or combined, assert malicious intent.
struct DetectionFinding {
    DetectionCategory category = DetectionCategory::ProtocolMisuse;
    MitreAttackTechnique technique;
    DetectionEvidence evidence = DetectionEvidence::Confirmed;
    DetectionNovelty novelty = DetectionNovelty::NotApplicable;
    DetectionSeverity severity = DetectionSeverity::Informational;
    std::string client_ip, server_ip;  // client_ip is the initiator/originator side
    std::string protocol;              // "s7comm"/"dnp3"/"iec104"/"bacnet"/"enip"/"rdp"/"vnc"/...
    uint16_t server_port = 0;          // 0 when not meaningful (e.g. a MAC-only remote-access match
                                        // never happens in practice for this feature's tier-1
                                        // protocols, which are all IP-based -- kept for symmetry with
                                        // every other protocol here)
    std::string description;           // human-readable, incident-ticket-ready -- see
                                        // detect_engine.cpp for exactly what each finding source
                                        // writes here, including the FirstOccurrence
                                        // caveat text
    double first_seen = 0.0;
    double last_seen = 0.0;
    size_t packet_count = 0;
};

struct DetectionSummary {
    size_t total = 0;
    size_t critical = 0, moderate = 0, informational = 0;  // by severity
    size_t confirmed_evidence = 0, heuristic_evidence = 0;  // by evidence
    size_t engineering_station_activity = 0, firmware_logic_change = 0, remote_access_channel = 0,
           protocol_misuse = 0;
};

struct DetectionReport {
    std::vector<DetectionFinding> findings;  // first-seen order
    DetectionSummary summary;
    size_t total_packets = 0;
};

class DetectEngine {
public:
    // Folds one already-decoded packet into this engine's state. Call once per packet, in capture
    // order (same discipline as Decoder::decode/PolicyEngine::observe/AssetInventoryEngine::observe).
    //
    // Produces an ALWAYS-NOTABLE finding immediately (evidence is Confirmed and severity is usually
    // Critical/Moderate -- the Modbus write-without-prior-read and a few reconnaissance-shaped
    // patterns are deliberately Informational instead, see each one's own comment) the first time a
    // given (category, technique, client_ip, server_ip, protocol, server_port)
    // combination is observed; a later packet matching the same combination only updates that
    // finding's own last_seen/packet_count, never creates a second finding for the same combination
    // -- see detect_engine.cpp's own per-protocol wiring for exactly which decoded fields produce
    // these (S7 PLC Control/PLC Stop/block-download, DNP3 Cold/Warm Restart/Enable-Unsolicited-then-
    // Unsolicited-Response-with-none-seen/Operate-with-no-prior-Select, an ASDU with an "unknown ..."
    // IEC 104 COT/a C_RP_NA_1 Reset Process command, BACnet ReinitializeDevice/
    // DeviceCommunicationControl/a Who-Is flood past threshold, a CIP Identity Object write, a
    // Modbus write outside every range ever read on the same conduit/table).
    //
    // Tracks a NEW-VS-KNOWN candidate (see this file's own header comment) the first time a given
    // (client_ip, server_ip, protocol, server_port) conduit is observed carrying a Tier-1
    // remote-access protocol (notable_it_protocols.hpp) or a CIP Forward_Open/Large_Forward_Open
    // from a client not seen opening one before -- these do NOT become findings here; finish()
    // resolves them against an optional baseline.
    void observe(const DecodedPacket& packet);

    // Produces the final report. `policy`: optional (nullptr when `detect --policy` wasn't given) --
    // used only to resolve a RemoteAccessChannel finding's technique between T0886 (Remote Services,
    // no zone crossing) and T0822 (External Remote Services, crosses a zone boundary): when both
    // endpoints resolve to a declared zone and the zones differ, T0822; otherwise (no policy, an
    // endpoint outside every declared zone, or both endpoints in the same zone) the narrower T0886
    // claim, since "crossed a boundary" isn't inferable without a policy that says where the
    // boundaries are.
    //
    // `baseline`: optional (nullptr when `detect --baseline-file` wasn't given) -- used to resolve
    // every tracked new-vs-known candidate: a candidate whose (client_ip, server_ip, protocol,
    // server_port) key matches a ConduitBaseline entry in `baseline->conduits` is NOT new (dropped
    // entirely, no finding produced); a candidate genuinely absent gets DetectionNovelty::ConfirmedNew.
    // With `baseline` null, every tracked candidate becomes a DetectionNovelty::FirstOccurrence
    // finding instead (first-occurrence-within-this-capture -- see this file's own header comment).
    // Either way, `evidence`/`severity` on the resulting finding come from what was recorded on the
    // candidate itself in observe() -- novelty is the only dimension finish() actually decides.
    //
    // Also resolves the two finding sources that genuinely need whole-capture knowledge and so
    // can't be decided in observe() alone: S7comm Setup Communication probing
    // (s7_setup_comm_state_ -- "no other function ever seen" can't be confirmed mid-capture), and
    // the download-then-restart composite (a post-pass over this SAME call's own already-produced
    // findings, so it always sees the complete set -- see detect_engine.cpp's own implementation
    // comment for both).
    //
    // Safe to call more than once; does not reset state.
    DetectionReport finish(const Policy* policy = nullptr, const BaselineStore* baseline = nullptr) const;

private:
    // Keyed by "<category>|<technique-id>|<client_ip>|<server_ip>|<protocol>|<server_port>" -- see
    // detect_engine.cpp's own always_notable_key(). Insertion order preserved via
    // always_notable_order_ so the final report is deterministic independent of an
    // unordered_map's own iteration order.
    std::unordered_map<std::string, DetectionFinding> always_notable_;
    std::vector<std::string> always_notable_order_;

    // One tracked new-vs-known candidate -- see this file's own header comment. `category`/
    // `technique_no_zone_crossing` covers the RemoteAccessChannel case's own T0886 default (finish()
    // may upgrade it to T0822); every other new-vs-known source (CIP originator) has a single fixed
    // technique with no such upgrade.
    struct NewConduitCandidate {
        DetectionCategory category = DetectionCategory::ProtocolMisuse;
        MitreAttackTechnique technique;
        DetectionEvidence evidence = DetectionEvidence::Confirmed;  // set at record time -- see
                                                                      // record_new_conduit_candidate's
                                                                      // own comment (detect_engine.cpp)
        DetectionSeverity severity = DetectionSeverity::Moderate;   // set at record time; novelty is
                                                                      // resolved later, in finish() --
                                                                      // it isn't stored on the
                                                                      // candidate at all
        bool is_remote_access = false;  // true only for the RemoteAccessChannel source -- the one
                                          // case finish() may retarget T0886 -> T0822
        std::string client_ip, server_ip, protocol;
        uint16_t server_port = 0;
        double first_seen = 0.0;
        double last_seen = 0.0;
        size_t packet_count = 0;
        // The exact `source_tag` record_new_conduit_candidate (detect_engine.cpp) was called
        // with -- carried onto the candidate itself (not just folded into the map key) so
        // finish() can pick the right description template for a non-remote-access candidate:
        // "cip-new-originator", "umas-new-originator-reservation",
        // "umas-new-originator-discovery", "modbus-new-originator-read-device-id",
        // "modbus-new-originator-report-server-id", "enip-new-originator-discovery" (Batch 3
        // item 17), "s7-szl-new-originator" (Batch 4 item 19), "fins-new-originator-discovery"
        // (Batch 4 item 22), "bacnet-foreign-device-register-new-originator" (Batch 4 item 21a),
        // "bacnet-bbmd-table-read-new-originator" (Batch 4 item 21b), "modbus-rogue-master", or
        // "dnp3-rogue-master" (Batch 5 item 25) each read differently even though they share the
        // same category/technique shape in some cases. Remote-access candidates render from
        // is_remote_access instead (their own source_tag is always "remote-access", never checked).
        std::string source_tag;
    };
    // Keyed by "<client_ip>|<server_ip>|<protocol>|<server_port>|<source-tag>" -- see
    // detect_engine.cpp's own new_conduit_key(). Two different sources (remote-access, CIP
    // originator) never share a key even for the same 4-tuple, since they're different findings
    // about the same conduit.
    std::unordered_map<std::string, NewConduitCandidate> new_conduit_candidates_;
    std::vector<std::string> new_conduit_order_;

    // CIP-originator tracking: every client_ip this engine has ever seen open a Forward_Open/
    // Large_Forward_Open to a given server_ip, so a SECOND originator to the SAME server is the one
    // that's actually new -- the first originator ever seen for a server is not itself flagged (it
    // has nothing to be "new" relative to within this capture; see detect_engine.cpp's own comment
    // at the call site for why this asymmetry is deliberate, not an oversight).
    std::unordered_map<std::string, std::vector<std::string>> cip_originators_by_server_;

    // The UMAS (umas.hpp) analog of cip_originators_by_server_ above -- same "second-plus
    // originator to a given server is new, first is not" mechanism, generalized across all four
    // UMAS engineering-station commands this engine tracks (TAKE_PLC_RESERVATION,
    // READ_ID/READ_PROJECT_INFO/READ_PLC_INFO) rather than one map per command: a client already
    // credited as a known originator via one of these commands isn't re-flagged for later issuing
    // a DIFFERENT one of the four against the same server -- see detect_engine.cpp's own call site
    // comment for why that's the right posture, not an oversight.
    std::unordered_map<std::string, std::vector<std::string>> umas_engineering_originators_by_server_;

    // DNP3 unsolicited-response tracking: every (client_ip, server_ip) pair that has seen an Enable
    // Unsolicited Responses (0x14) request, so a later Unsolicited Response (0x82) from a server
    // that was never enabled is the misuse-shaped case -- see detect_engine.cpp's own call site.
    // Keyed "<master_ip>|<outstation_ip>".
    std::unordered_map<std::string, bool> dnp3_unsolicited_enabled_;

    // DNP3 Select-before-Operate tracking: every (master_ip, outstation_ip) pair that has seen a
    // Select (0x03) request, so a later Operate (0x04) with no Select ever recorded for that same
    // pair is the misuse-shaped case. Deliberately does NOT flag Direct Operate (0x05) at all --
    // Direct Operate is a real, spec-legal, routinely-used DNP3 mechanism that intentionally skips
    // Select, not a bypass of one; flagging every Direct Operate would be pure noise, not a real
    // finding (this was this engine's own original, imprecise framing of this pattern -- corrected
    // before implementation once DNP3's actual semantics were checked, see docs/design/
    // detection-engine.md). Also deliberately coarse: a "Select ever seen for this pair" boolean,
    // not per-object-index Select/Operate pairing (DNP3's own spec pairs a Select with a SPECIFIC
    // point/index, immediately followed by the matching Operate) -- the same "per-pair, not
    // per-object" granularity dnp3_unsolicited_enabled_ above already uses for this same reason:
    // this engine has no cross-request object-index correlation state today, and a coarser signal
    // that's honestly scoped beats a falsely-precise one this codebase can't actually back. Never
    // reset to false (unlike dnp3_unsolicited_enabled_, which DOES toggle off on Disable Unsolicited
    // Responses -- there is no DNP3 "un-select" concept to mirror that with). Keyed
    // "<master_ip>|<outstation_ip>", same ordering convention as dnp3_unsolicited_enabled_.
    std::unordered_map<std::string, bool> dnp3_select_seen_;

    // Modbus write-without-prior-read tracking: every address range ([start, start+quantity)) a
    // Read Coils or Read Holding Registers request has observed, per conduit AND per address-space
    // table -- so a Write Multiple Coils/Registers request whose range isn't covered by any prior
    // read from the SAME table on the SAME conduit is the notable case. Deliberately two separate
    // per-conduit maps in spirit (one keyed table per Modbus's own two writable data tables, Coils
    // and Holding Registers -- Discrete Inputs and Input Registers are read-only tables nothing ever
    // writes to, so they're never tracked here at all), folded into one map keyed
    // "<client_ip>|<server_ip>|<server_port>|<table>" (table is "coils" or "holding_registers")
    // rather than two separate members, mirroring extract_modbus_operations' own (baseline.cpp)
    // "one address space per function" framing so a Coils read never silences a Holding-Registers
    // write or vice versa. Write Single Coil/Write Single Register are NOT covered by this pattern
    // at all -- modbus.hpp's own ModbusFrame::start_address/quantity comment documents why those two
    // functions have no is_request-confirmed direction signal to key on in the first place. Ranges
    // are merge-on-insert coalesced (see detect_engine.cpp's own modbus_merge_range_into, a small
    // local copy of baseline.cpp's own merge_range_into -- this file's own per-translation-unit-copy
    // convention, matching json_escape/format_epoch_seconds above) so a write spanning what were
    // originally two separate, now-adjacent/overlapping reads is still correctly recognized as fully
    // covered.
    std::unordered_map<std::string, std::vector<std::pair<uint32_t, uint32_t>>>
        modbus_read_ranges_by_conduit_table_;

    // BACnet Who-Is volumetric flood/device-enumeration-sweep tracking: a running count of Who-Is
    // (unconfirmed service choice 8, "who-Is") requests seen from a given source IP across this
    // whole capture, regardless of destination (Who-Is is routinely sent as a BACnet/IP broadcast,
    // so grouping by source alone -- not source+destination -- is the right granularity: the same
    // sweep would otherwise be split across however many distinct broadcast/unicast destinations it
    // happened to use). Once a source's count reaches kBacnetWhoIsFloodThreshold
    // (detect_engine.cpp), every Who-Is from that source (including ones already counted before the
    // threshold was reached) becomes part of one always-notable finding -- see detect_engine.cpp's
    // own call site for exactly how the threshold check is done. Keyed by bare source IP.
    std::unordered_map<std::string, size_t> bacnet_who_is_count_by_source_;

    // S7comm Setup Communication (function code 0xF0) probing state, per (client_ip, server_ip)
    // pair -- see this struct's own two fields for exactly what's tracked. Deliberately resolved in
    // finish(), not observe(): "no other S7comm function was EVER seen between this pair" can only
    // be known once the whole capture has been read (a later packet could always introduce a real
    // function), unlike every other always-notable source in this engine, which only ever needs the
    // CURRENT packet plus already-settled prior state to decide. Keyed "<client_ip>|<server_ip>".
    struct S7SetupCommProbeState {
        size_t setup_comm_count = 0;
        bool other_function_seen = false;  // true once ANY S7comm function other than Setup
                                             // Communication has been seen from this client to this
                                             // server -- PLC Stop/Control, Read/Write Var, block
                                             // download, anything at all; a pair that goes on to do
                                             // real engineering-station work is not probing.
        double first_seen = 0.0;
        double last_seen = 0.0;
    };
    std::unordered_map<std::string, S7SetupCommProbeState> s7_setup_comm_state_;

    // Modbus repeated exception-code response burst state (Batch 1 item 6), per (client_ip,
    // server_ip, exception_code) key ("<client_ip>|<server_ip>|<exception_code>") -- `count` is the
    // number of matching exceptions seen since `window_start`, reset to 1/dp.timestamp whenever a new
    // occurrence's gap since `window_start` exceeds kModbusExceptionBurstWindowSeconds (detect_engine.
    // cpp), so a burst genuinely has to be close together in time to count, unlike
    // bacnet_who_is_count_by_source_ above (a whole-capture running total with no windowing at all --
    // appropriate there because a volumetric flood is notable regardless of pacing, but wrong for
    // this pattern, where three exceptions minutes apart across an hour-long capture is not the same
    // signal as three within a minute).
    struct ModbusExceptionBurstState {
        size_t count = 0;
        double window_start = 0.0;
    };
    std::unordered_map<std::string, ModbusExceptionBurstState> modbus_exception_burst_state_;

    // DNP3 object-group/variation enumeration sweep state (Batch 2 item 9), per (master_ip,
    // outstation_ip) key ("<master_ip>|<outstation_ip>") -- `distinct_group_variations` is the SET of
    // (group, variation) pairs seen across this master's own Read requests to this outstation since
    // `window_start`, reset (cleared, window_start moved to dp.timestamp) whenever a new Read's gap
    // since `window_start` exceeds kDnp3EnumerationSweepWindowSeconds (detect_engine.cpp) -- the same
    // windowed-reset shape modbus_exception_burst_state_ above already established, deliberately
    // chosen over bacnet_who_is_count_by_source_'s own unwindowed whole-capture running count even
    // though the research doc's own readiness note for this pattern suggested reusing that mechanism:
    // the pattern's own wire condition ("an unusually wide spread of distinct object groups/
    // variations... within a short window") explicitly calls for time-windowing, and a whole-capture
    // running count would treat four unrelated single-object polls spread across an hour-long capture
    // the same as four different object types requested within one burst -- not the same signal. A
    // SET, not a count (unlike modbus_exception_burst_state_'s own plain counter): the pattern is
    // about DIVERSITY of what's being read, not how many times something was read, so a master
    // re-reading the same handful of object types many times within the window must never trip this
    // on repetition alone.
    struct Dnp3EnumerationSweepState {
        double window_start = 0.0;
        std::set<std::pair<uint8_t, uint8_t>> distinct_group_variations;  // (group, variation)
    };
    std::unordered_map<std::string, Dnp3EnumerationSweepState> dnp3_enumeration_sweep_state_;

    // EtherNet/IP List Identity/Services/Interfaces originator tracking (Batch 3 item 17) -- the same
    // "second-plus originator to a given server is new, first is not" mechanism as
    // cip_originators_by_server_ above, kept as its own separate map (not folded into
    // cip_originators_by_server_) because these three encapsulation commands are a structurally
    // different signal (no CIP message at all, EnipFrame::has_cip stays false) from a Forward_Open --
    // a client credited here for a List* query isn't implicitly credited as a known CIP originator, and
    // vice versa, since each is a genuinely separate capability/activity being observed.
    std::unordered_map<std::string, std::vector<std::string>> enip_list_discovery_originators_by_server_;

    // S7 Read SZL originator tracking (Batch 4 item 19) -- same "second-plus originator to a given
    // server is new, first is not" mechanism as cip_originators_by_server_/
    // enip_list_discovery_originators_by_server_ above, keyed by the target PLC's own IP.
    std::unordered_map<std::string, std::vector<std::string>> s7_szl_originators_by_server_;

    // FINS Controller Data Read originator tracking (Batch 4 item 22) -- same mechanism, keyed by
    // the target PLC's own IP.
    std::unordered_map<std::string, std::vector<std::string>> fins_originators_by_server_;

    // BACnet Register-Foreign-Device originator tracking (Batch 4 item 21a) -- same mechanism, keyed
    // by the BBMD's own IP. A separate map from bacnet_bbmd_table_read_originators_by_server_ below:
    // registering as a foreign device and reading a BBMD's own table are two structurally different
    // capabilities (one changes the BBMD's own state, the other only reads it), so a client credited
    // for one isn't implicitly credited as a known source of the other.
    std::unordered_map<std::string, std::vector<std::string>> bacnet_foreign_device_register_originators_by_server_;

    // BACnet Read-Foreign-Device-Table / Read-Broadcast-Distribution-Table originator tracking
    // (Batch 4 item 21b) -- same mechanism, keyed by the BBMD's own IP. Both BVLC functions folded
    // into one map (not two): they're both a read-only query against the same BBMD's own routing
    // configuration, the same "distinct capability, one map" reasoning that keeps
    // enip_list_discovery_originators_by_server_ a single map across its own three commands.
    std::unordered_map<std::string, std::vector<std::string>> bacnet_bbmd_table_read_originators_by_server_;

    // Modbus/DNP3 write-capable-master tracking (Batch 5 item 25, "Rogue Master"/T0848) -- every
    // client_ip this engine has seen issue a WRITE-classified request (modbus_write_function_names()/
    // dnp3_write_function_names(), modbus.hpp/dnp3.hpp) to a given server_ip, so a SECOND write-capable
    // master to the SAME outstation is the one that's actually new -- same "first is not itself
    // flagged" asymmetry as cip_originators_by_server_ above, but deliberately its own pair of maps
    // (not folded into any existing originator map): those all track "any second originator"
    // (read-only enumeration in most cases), while this tracks specifically "a second originator that
    // starts WRITING" as its own, more serious signal -- a client already known as a read-only
    // originator elsewhere isn't implicitly credited here, and vice versa. Two separate maps (not one
    // shared across both protocols) since a Modbus writer and a DNP3 writer to the same IP address are
    // not evidence about each other. Scoped to Modbus and DNP3 only -- see this file's own header
    // comment for why UMAS is deliberately excluded (its write-shaped functions already fire their own
    // always-notable finding on every occurrence, so a redundant "second writer" layer would add noise,
    // not signal).
    std::unordered_map<std::string, std::vector<std::string>> modbus_write_originators_by_server_;
    std::unordered_map<std::string, std::vector<std::string>> dnp3_write_originators_by_server_;

    // Port scan state (Batch 5 item 24, T0846.001) -- per "<src_ip>|<dst_ip>" key, a WINDOWED set of
    // distinct destination ports seen reached via a pure-SYN (no-ACK) packet from that source to that
    // destination. Reset (both the window start and the set) whenever a new SYN's gap since
    // window_start exceeds kPortScanWindowSeconds (detect_engine.cpp) -- the same windowed-SET shape
    // dnp3_enumeration_sweep_state_ above already established, just measuring port diversity instead
    // of object-group/variation diversity. A SET, not a count, for the same reason: the signal is
    // DIVERSITY of ports touched, so re-touching the same handful of ports repeatedly within the
    // window must never trip this on repetition alone.
    struct PortScanState {
        double window_start = 0.0;
        std::set<uint16_t> distinct_ports;
    };
    std::unordered_map<std::string, PortScanState> port_scan_state_;

    // Write-burst state (Batch 5 item 26, "Brute Force I/O"/T0806) -- per
    // "<protocol>|<client_ip>|<server_ip>" key, `count` is the number of WRITE-classified requests
    // seen since `window_start`, reset to 1/dp.timestamp whenever a new occurrence's gap since
    // window_start exceeds kWriteBurstWindowSeconds (detect_engine.cpp) -- the exact same shape
    // ModbusExceptionBurstState above already established (Batch 1 item 6), reused here for write
    // volume instead of exception-response volume. Keyed by protocol too (unlike
    // modbus_exception_burst_state_, which only ever sees Modbus) since this same tracker backs both
    // the Modbus and DNP3 write-burst checks.
    struct WriteBurstState {
        size_t count = 0;
        double window_start = 0.0;
    };
    std::unordered_map<std::string, WriteBurstState> write_burst_state_;

    size_t total_packets_ = 0;
};

// Renders `report` as a human-readable text report to `out`: a summary line, then every finding
// grouped by category, each showing its technique citation, evidence, novelty, severity, endpoints,
// and description. Never renders or implies a claim about malicious intent -- see this file's own
// header comment. `capture_path` is shown in the report header purely for context. `resolver` supplies the same
// OUI/hostname/service-name annotations every other report writer in this codebase already provides.
void write_detection_report_text(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

// Renders `report` as JSON to `out`, for scripting/automation. Includes a "techniques_referenced"
// array (all_mitre_attack_ics_techniques()'s own full ten, not just the ones this report actually
// cites) so a consumer always has the full citation text available without a second lookup.
void write_detection_report_json(std::ostream& out, const DetectionReport& report,
                                  const std::string& capture_path, const Resolver& resolver);

}  // namespace conduitscope
