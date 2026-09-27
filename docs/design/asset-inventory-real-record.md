# Asset inventory: a real OT asset record -- design document

Status: **Phases 0-4 (last-seen/identity scaffolding, EtherNet/IP CIP Identity wiring, S7comm-Plus
dispatch, OPC UA identity promotion, S7comm SZL decode + wiring, BACnet ReadPropertyMultiple decode +
Device-object identity correlation) implemented and shipped.** Phases 5-10 (DNP3 Device Attributes
decode, role classification, tag/point/DB touch summarization, CSV/CMDB export, STIX/TAXII-lite
export, firewall-ACL-draft export) are scoped below but not yet started. Written in response to
[Grok's ten-point ICS/OT improvement review](../reviews/2026-09-grok-ics-ot-improvement-areas.md)
(item 2) -- see [docs/reviews/2026-09-grok-response.md](../reviews/2026-09-grok-response.md) for the
fact-check of that review against the repository, and `docs/DEVELOPMENT.md`'s ROADMAP items 75-76,
79 for the changelog-style writeup of what shipped and its exact verification numbers.

## Context

Following the now-shipped Grok gap #1 ("match how plants are zoned" -- see
[policy-engine-zoning.md](policy-engine-zoning.md)), Jurgen asked to tackle Grok's gap #2 next, in his
own stated priority order: **"Turn inventory into a real OT asset record."** Grok's original review
asked for passively-inferred vendor/product/firmware/serial/rack-slot, PLC/RTU/IED/HMI/historian/
engineering-station role classification, which specific tags/points/DBs were touched (not just
function-code categories), last-seen plus client-vs-server-only visibility, CSV/CMDB/STIX-TAXII-lite/
firewall-ACL export, and inventory support for every protocol conduitscope decodes (Grok specifically
flagged S7comm-Plus as still missing from the five-protocol set it originally reviewed).

`docs/reviews/2026-09-grok-response.md`'s fact-check already established that most of the "five
protocols" claim is stale -- MMS/OPC UA/MQTT/BACnet were added in an earlier pass -- and
`InventoryAsset::ever_client`/`ever_server` already satisfies the "seen as client vs. server" ask.
What was actually still open, confirmed by direct research (reading `asset_inventory.hpp`/`.cpp` in
full, `decoder.hpp`, and the identity-bearing decode paths in `enip.hpp`/`s7comm.hpp`/`bacnet.hpp`/
`opcua.hpp`/`dnp3.hpp`):

- **Last-seen** was free: `DecodedPacket::timestamp` already exists on every packet;
  `InventoryAsset`/`InventoryEdge` just didn't track it.
- **EtherNet/IP vendor/product/firmware/serial** was free: CIP Identity (`ListIdentity` response) was
  already fully decoded into named fields on `EnipFrame` (`identity_vendor_id`, `identity_device_type`,
  `identity_product_code`, `identity_revision`, `identity_status`, `identity_serial_number`,
  `identity_product_name`). Pure wiring, no new decode.
- **S7comm-Plus dispatch** was ALSO pure wiring, not new decode work as originally scoped below (see
  Phase 5's own note) -- a full S7comm-Plus decoder already existed (`s7commplus.hpp`/`.cpp`) and was
  simply never added to `AssetInventoryEngine::observe`'s protocol dispatch.
- **OPC UA application/security identity** needs a small, well-scoped promotion, not new decode:
  `GetEndpoints`/`FindServers`/`CreateSession` are already "Tier 1 full decode" and already extract
  `application_uri`, `security_mode`, `security_policy_uri`, `endpoint_url` into local
  `AppDescInfo`/`EndpointDescInfo` structs in `src/opcua.cpp` -- but those get stringified into
  `OpcUaResult`'s generic `values` (`vector<string>`) instead of being kept as named fields. This
  needs the same treatment ENIP already has: promote these onto `OpcUaResult` as first-class fields.
- **BACnet vendor/model/firmware** needs real new work: I-Am carries a Vendor-ID today but only inside
  unstructured `BacnetApdu::values` strings; a Device object's Vendor-Name/Model-Name/
  Firmware-Revision/Application-Software-Version would come back via ReadProperty ACK (whose single
  scalar PropertyValue decode already exists) or, far more realistically for actual deployments,
  ReadPropertyMultiple -- **which isn't decoded at all yet**.
- **S7comm SZL** (System Status List -- Order Number, Module Type Name, System Name/Plant
  Identification) is **not decoded at all** -- net-new decode work, the S7 analog of CIP Identity/I-Am.
- **DNP3 Device Attributes** (IEEE 1815 group 0 -- manufacturer name, product name/model, serial
  number, firmware version) are **not decoded at all** -- also net-new decode work.
- **Tag/point/DB touch tracking**: `InventoryEdge::observed_functions` only tracks function/service
  *names* today, never the specific address touched. Real per-address tracking is unbounded-
  cardinality by nature and needs a deliberate cap/summarization design, not just "add a set."
- **Role classification** has zero existing precedent anywhere in the codebase -- needs a heuristic
  designed from scratch, kept strictly informational like `purdue_level` in the policy engine.
- **Export formats**: GRASSMARLIN-style graphs already exist. CSV/CMDB, STIX-TAXII-lite, and
  firewall-ACL-object-group export have **zero precedent**, and `inventory`'s own `-T,--format` CLI
  option is hardcoded to `{"text","json"}` only -- these are wholly new writers plus new CLI plumbing.

Grok's item #2 is far broader and more heterogeneous than item #1: item #1 was one engine gaining
coherent new capabilities along a single throughline (zoning). Item #2 spans "wire an already-decoded
field through" (cheap), "promote an already-extracted local value to a named struct field"
(cheap-ish), "decode a wire format from scratch" (S7 SZL, DNP3 attributes, BACnet RPM -- real protocol
work, each independently spec-sourced and pinned exactly like every other decoder in this project), a
new heuristic with no ground truth to check it against (role classification), and a new export
subsystem (CSV/STIX/ACL) that has nothing to build on. This plan sequences from cheapest/highest-
confidence to hardest/most-judgment, so each phase after the first ships real, independently useful
value and nothing downstream blocks on the riskiest work finishing first.

## Phase 0 -- `InventoryAsset`/`InventoryEdge` scaffolding: last-seen + vendor/product/firmware fields (shipped)

Added `double first_seen`/`last_seen` to both `InventoryAsset` and `InventoryEdge` (min/max of
`DecodedPacket::timestamp`) and `InventoryAsset` fields `vendor`/`product`/`firmware_revision`/
`serial_number` (empty unless a protocol positively supplied them, first-identity-seen wins, mirroring
`has_mac`/`mac`'s own convention). **Rack/slot is dropped from this plan's scope entirely**: no
protocol conduitscope decodes carries a rack/slot number as a field a device volunteers about itself
(CIP's own path-addressable rack/slot concept only ever appears in an explicit-messaging *request
path* a scanner already has to know out-of-band -- there is nothing to passively infer). Rendered in
text as a `first seen: ... last seen: ...` line and, where present, an `identity: ...` line per asset;
JSON appends `first_seen`/`first_seen_text`/`last_seen`/`last_seen_text` and, when non-empty,
`vendor`/`product`/`firmware_revision`/`serial_number`, all after each object's prior true-last field.

## Phase 1 -- EtherNet/IP identity wiring + S7comm-Plus dispatch (zero/near-zero new decode) (shipped)

EtherNet/IP: when `EnipFrame::has_identity` is true, populate the asset that actually **sent** that
specific response packet (`DecodedPacket::src_ip`, not "the server" of the session generically -- the
exchange itself is the evidence of which side is the real device) from `identity_vendor_id` (rendered
as a raw numeric CIP Vendor ID, e.g. `"Vendor ID 1"` -- no CIP Vendor ID -> name table exists in this
codebase, and building one is out of scope), `identity_product_name`, `identity_revision`,
`identity_serial_number`.

S7comm-Plus: confirmed absent from `AssetInventoryEngine::observe`'s ten-protocol dispatch going in,
but reading `src/asset_inventory.cpp` directly during implementation found this was pure wiring, not
new decode work as originally planned (see this doc's own "Context" section) -- a full S7comm-Plus
decoder already existed (`s7commplus.hpp`/`.cpp`, flat fields on `DecodedPacket`) and just needed one
dispatch branch plus one function-name extraction branch added. Client/server determination needed no
new code: S7comm-Plus rides the same TCP/102/TPKT/COTP transport classic S7comm uses, already covered
by the generic TCP handshake/port-heuristic branch every TCP-based protocol here shares.
`AssetInventoryEngine` is now an eleven-protocol feature.

## Phase 2 -- OPC UA identity promotion (shipped)

Added `has_identity`/`identity_application_uri`/`identity_security_mode_name`/
`identity_security_policy_uri` as named fields on `OpcUaMessage` (not `OpcUaResult` itself, which only
ever has `summary`/`notes`/`first` -- these needed to go on the per-chunk struct `first` wraps, the
same place ENIP's own `identity_*` fields live on `EnipFrame` rather than `EnipResult`; a precise
implementation-location refinement discovered during implementation, not a change to this phase's
intent), alongside (not replacing) the existing stringified `values` entries -- mirroring exactly how
ENIP already exposes both a human summary line and structured `identity_*` fields side by side.
Source: `src/opcua.cpp`'s existing `read_application_description`/`read_endpoint_description` (used
by `decode_get_endpoints_response_params`) already extracted these values locally; this phase only
changed where they end up, threading a new `OpcUaMessage&` parameter through
`decode_get_endpoints_response_params` and `call_tier1_decoder` to do it. Promoted from the FIRST
endpoint only (index 0) -- not "the endpoint the traffic actually used" as originally scoped, since
this decoder has no cross-message state to know which endpoint a later session actually negotiated;
a real server's own ApplicationUri is the same across every endpoint regardless, so this is only an
approximation for SecurityMode/SecurityPolicyUri specifically when a server offers more than one
endpoint -- documented plainly on `OpcUaMessage::has_identity`'s own comment rather than attempting
the originally-scoped "match the session" tracking, which was out of proportion to this phase's size.

Wired into `InventoryAsset::vendor`/`product` using `application_uri` as the vendor/product stand-in
for both (OPC UA has no separate vendor/model -- the decoder's own header comment already treats
ApplicationUri as "the stable identifier this decoder surfaces instead" of ApplicationName/
ProductUri), plus a new `InventoryAsset::security_posture` field (not folded into `notes`, since
`InventoryAsset` has no generic notes list) -- `"SecurityMode=<mode>, Policy=<policy>"`,
`"SECURITY FINDING: "`-prefixed when SecurityMode is `"None"`, mirroring the exact same-named
convention `opcua.cpp`'s own ActivateSession cleartext-credential check already established (the only
other place in this codebase using it). Also surfaced directly on `decode --format json`'s own OPC UA
output (`write_opcua_json_fields`, `src/output.cpp`), independent of `inventory`'s wiring, since OPC
UA (unlike ENIP) is a zero-flat-field-migrated protocol whose `decode` JSON output already renders
every other `OpcUaMessage` field directly. Fixture: `tests/sample_opcua.pcap`'s own
`GetEndpointsResponse` already had exactly the scenario needed (two endpoints, the first with
`SecurityMode=None`) -- no new fixture required. See `docs/DEVELOPMENT.md`'s ROADMAP item 76 for the
full changelog writeup and exact test/verification counts.

## Phase 3 -- S7comm SZL decode + wiring (shipped)

**Correction to this plan's own original assumption, caught before implementing.** The paragraph
below (left in place, struck through in spirit, for the historical record) assumed SZL-ID 0x001C
alone carried the Order Number and Module Type Name. Direct reading of Wireshark's own
`packet-s7comm_szl_ids.c`/`packet-s7comm.c` dissector source -- fetched in full via `curl` after
`WebFetch` truncated the ~4,000+ line file around its own small-model content-processing limit --
found this wrong: SZL-ID 0x001C ("Component Identification") is not one flat record but a family of
eleven differently-shaped sub-records selected by sub-index, and the real Order Number/MLFB actually
lives in a *different* SZL-ID, 0x0011 ("Module identification"). This was flagged to Jurgen as a
correction to the plan before any decode code was written, together with a scoped five-of-eleven
sub-index plan for 0x001C (see below); Jurgen approved with "Yes, that's ok for me, go ahead."

~~New decode work in `s7comm.hpp`/`.cpp`: recognize the SZL read function (Userdata/parameter-block
SZL request, function group 0x04 "CPU functions", subfunction "Read SZL") and decode SZL ID 0x001C
("Component Identification" -- Order Number, Module Type Name, plus, if present, Plant
Identification/System Name) from the response data record~~ -- what actually shipped: both SZL-ID
0x0011 (Order Number/MLFB, module type code, version, PG release -- one fixed 28-byte record) and
SZL-ID 0x001C's five asset-identity-relevant sub-records (PLC name, module name, plant tag/"Plant
Identification", serial number, CPU type name -- the other six documented sub-indices, copyright
string/MMC serial/PROFINET I&M/OEM data/location ID/anything else, are recognized as SZL data but not
decoded further, a deliberate scope boundary approved alongside the correction above), byte layouts
sourced directly from `s7comm_decode_szl_id_0111_idx_0001`/`s7comm_decode_szl_id_xy1c_idx_000x` in
Wireshark's own dissector source -- see `docs/PROTOCOL_COVERAGE.md`'s own "Userdata (0x07) Read SZL"
section for the full field-by-field writeup. New fields live directly on the existing `S7CommFrame`/
`S7CommResult` structs (`has_userdata_szl`, `szl_id`/`_id_name`/`_index`, `szl_return_code`/
`_return_code_name`, `szl_record_count`/`_record_length`, `has_szl_module_identification` +
`szl_order_number`/`_module_type_code`/`_version`/`_pg_release`, and `szl_plc_name`/`_module_name`/
`_plant_identification`/`_serial_number`/`_module_type_name`) rather than a separate `S7SzlInfo`
struct -- additive, nothing renamed or removed, matching the "widen the existing result struct"
convention Phase 1/2 already established for ENIP/OPC UA. Wired into `InventoryAsset`: SZL-ID
0x0011's `szl_order_number` -> `product` (preferred when present), SZL-ID 0x001C's
`szl_module_type_name`/`szl_plc_name`/`szl_module_name` -> `product` as a fallback when 0x0011 wasn't
seen, `szl_serial_number` -> `serial_number`, `szl_plant_identification` -> the new
`InventoryAsset::plant_identification` field -- bound to `dp.src_ip` (the response sender, i.e. the
PLC), mirroring the ENIP/OPC UA identity-binding precedent exactly. `update_identity()`'s signature
grew a trailing `plant_identification` parameter, defaulted to `""` so the ENIP/OPC UA call sites
didn't need updating (same pattern `security_posture` used in Phase 2).

Also surfaced directly on `decode --format json`'s own S7comm output (`s7comm_szl_*` fields in
`write_s7comm_json_fields`, `src/output.cpp`, appended after the existing `pi_control_*` block),
independent of `inventory`'s own wiring -- same "both inventory wiring AND standalone decode fields"
pattern Phase 2 established for OPC UA. `decode`'s own text summary renders a new segment for
`has_userdata_szl`, showing SZL-ID/name/Index/return code and, on success, whichever identity fields
the response actually carried.

**Testing.** A new fixture, `tests/sample_s7comm_szl.pcap` (`build_s7comm_szl_sample` in
`tools/make_sample_pcap.py`), covering: a 0x0011 request/response pair; a 0x001C request/response
carrying all five decoded sub-records in one response (all five sub-record shapes happen to be
exactly 34 bytes, so they share one `record_length`, matching what a real Index-0x0000 "give me every
sub-record" request/response would look like); an SZL-ID this codebase recognizes as SZL data but
decodes no named field for (0x0000); a failed response (return code 0x0A, "Object does not exist");
and a non-SZL Userdata exchange (CPU functions group, but a different subfunction) confirming the
generic fallback note still fires unchanged. All byte layouts cross-checked against the same primary
dissector source before the fixture was written, not guessed. 12 new CTest cases (`decode` text/JSON
for every scenario above, `inventory` text/JSON confirming the `InventoryAsset` wiring, plus
does-not-crash JSON/CSV cases) -- all verified against the real binary's own output, never
hand-written expected text. 9 new fuzz corpus seeds extracted from the new fixture into
`fuzz/corpus/cotp_s7comm/` via `tools/extract_fuzz_corpus.py` (l4/tcp/port 102); a 60-second
corpus-regression CTest run plus a separate ~1.4M-execution/60-second standalone libFuzzer run against
the full corpus, both clean under ASan/UBSan. Full CTest suite: 2060/2060 (default GCC build, up from
the prior 2048); ASan/UBSan (2060/2060 non-fuzz plus 76/76 fuzz corpus-regression targets, all clean)
and no-live-capture (2048/2048) configs, plus a clean-room extract-rebuild-test, all re-verified before
delivery; MinGW-w64 cross-compile confirmed to still compile and link cleanly (same standing
no-Wine-here limitation as every prior phase).

**Not yet done, tracked for a following increment**: BACnet ReadPropertyMultiple decode, DNP3 Device
Attributes, role classification, tag/point/DB touch summarization, and CSV/CMDB, STIX/TAXII-lite, and
firewall-ACL-draft export -- unchanged from Phase 2's own list, minus S7comm SZL, which this phase
completed.

## Phase 4 -- BACnet ReadPropertyMultiple decode + Device-object identity correlation (shipped)

**Correction to this plan's own original assumption, caught before implementing.** The paragraph
below (left in place, struck through in spirit, for the historical record) assumed BACnet has no
standard Serial-Number property on the Device object. Direct primary-source verification -- ASHRAE
135's own `BACnetPropertyIdentifier` enumeration (transcribed in this codebase's own
`kBacnetPropertyIdentifier`, cross-checked against Wireshark's `packet-bacapp.c`) already carries
`serial-number` (372), and OPC UA for BACnet's own published mapping of the base standard's Device
object property table (Table 10 of that companion specification -- a direct, machine-checkable
transcription of ASHRAE 135's own Device object clause, fetched via `WebSearch`/`WebFetch` rather
than assumed) lists `Serial_Number` as a **mandatory** Device object property, not a
vendor-proprietary extension -- found this wrong. This was flagged to Jurgen as a correction to the
plan (documented in full in `bacnet.hpp`'s own "Device object identity correlation" paragraph)
before any decode code was written; Serial-Number is decoded and promoted on the same footing as
Vendor-Name/Model-Name/Firmware-Revision, not dropped.

~~Decode ReadPropertyMultiple request/ACK (ASHRAE 135 clause 15.7). New correlation logic: when a
`ReadProperty`/`ReadPropertyMultiple` ACK's ObjectIdentifier is a Device object (object-type 8) and
PropertyIdentifier is one of Vendor-Name(121)/Model-Name(70)/Firmware-Revision(44)/
Application-Software-Version(12), recognize it and promote the CharacterString value onto named
fields -- check ASHRAE 135's Device object property table directly before assuming a
Serial-Number property exists (it doesn't, as a standard property); if none does, drop
serial-number from BACnet's own field set rather than inventing a vendor-proprietary one. Wire into
`InventoryAsset` alongside the existing I-Am-derived Vendor-ID.~~ -- what actually shipped: both
ReadPropertyMultiple-Request (`listOfReadAccessSpecs`, a sequence of `ReadAccessSpecification` --
per-object `ObjectIdentifier` + a list of `PropertyIdentifier`/optional `PropertyArrayIndex`) and
ReadPropertyMultiple-ACK (`listOfReadAccessResults`, a sequence of `ReadAccessResult` -- per-object
`ObjectIdentifier` + a list of `PropertyIdentifier`/optional `PropertyArrayIndex`/either a decoded
`PropertyValue` primitive or a `propertyAccessError`), byte layout sourced directly from
`packet-bacapp.c`'s own ASN.1 structure comments for `ReadAccessSpecification`/`ReadAccessResult`
(the authoritative source -- not that same file's `fReadAccessResult` C function, whose switch
statement has no explicit case for the `propertyArrayIndex[3]`/`propertyValue[4]` *opening* tag, an
apparent gap/quirk in that specific Wireshark revision this decoder does not reproduce; see
`bacnet.hpp`'s own note). Rendered as indexed `"read-access-spec[i]-object=..."`/
`"read-access-spec[i]-property[j]=..."` (request) and `"read-access-result[i]-object=..."`/
`"read-access-result[i]-property[j]=..."`/`"...-property[j]-value=..."`/`"...-property[j]-error=..."`
(ACK) entries in `BacnetApdu::values`, the one first-pass service whose `values` carry an explicit
index (mirroring HART-IP's own `"device-variable[i]-..."` precedent) since, unlike every other
first-pass service here, ReadPropertyMultiple can legitimately carry more than one object and more
than one property per object in a single message. Device object identity correlation: when a
`ReadProperty` or `ReadPropertyMultiple` ACK's `ObjectIdentifier` is a Device object (object-type 8)
and `PropertyIdentifier` is one of Vendor-Name(121)/Model-Name(70)/Firmware-Revision(44)/
Application-Software-Version(12)/Serial-Number(372), decoded as a Character-String, the value is
promoted onto new `BacnetApdu` fields (`has_device_identity` +
`device_vendor_name`/`device_model_name`/`device_firmware_revision`/
`device_application_software_version`/`device_serial_number`) -- additive, nothing renamed or
removed, same "widen the existing result struct" convention Phase 1-3 already established. Wired
into `InventoryAsset`: `device_vendor_name` -> `vendor`, `device_model_name` -> `product`,
`device_firmware_revision` -> `firmware_revision` (falling back to
`device_application_software_version` only when Firmware-Revision itself wasn't read in that
exchange -- they are genuinely different properties, but `InventoryAsset` has one
`firmware_revision` field, not two, matching S7comm's own product-fallback-chain precedent from
Phase 3), `device_serial_number` -> `serial_number` -- bound to `dp.src_ip` (the ACK's sender, i.e.
the device actually being queried), mirroring the ENIP/OPC UA/S7comm identity-binding precedent
exactly. Also surfaced directly on `decode --format json`'s own BACnet output
(`bacnet_has_device_identity`/`bacnet_device_vendor_name`/`bacnet_device_model_name`/
`bacnet_device_firmware_revision`/`bacnet_device_application_software_version`/
`bacnet_device_serial_number` in `write_bacnet_json_fields`, `src/output.cpp`) and in `decode`'s own
one-line text summary (a trailing `device-identity(vendor=... model=... ...)` segment), independent
of `inventory`'s own wiring -- same "both inventory wiring AND standalone decode fields" pattern
Phase 2/3 established.

**Testing.** 8 new packets appended to `tests/sample_bacnet.pcap` (`build_bacnet_sample` in
`tools/make_sample_pcap.py`, using new `bacnet_read_access_spec`/`bacnet_read_access_result`/
`bacnet_read_access_result_value`/`bacnet_read_access_result_error` helpers): a full five-property
identity request/ACK round-trip (given explicit unicast addressing, unlike most of this fixture's
broadcast-destination packets, so the same exchange also doubles as the inventory-wiring fixture);
a multi-object ACK confirming identity correlation is scoped per-object (a Device object's
Vendor-Name promotes, a sibling analog-input's present-value in the same ACK does not); a
`propertyAccessError` inside a `listOfResults`; a constructed (array-shaped) PropertyValue that is
correctly named-only/not-decoded and correctly never promoted; a two-`ReadAccessSpecification`
request; and malformed/truncated request and ACK cases (each stops with a note, no crash). 14 new
CTest cases (`decode` text/JSON for every scenario above, `inventory` text/JSON confirming the
`InventoryAsset` wiring) plus one updated (`bacnet_stats_counted`'s packet/protocol counts) -- all
verified against the real binary's own output, never hand-written expected text. Fuzz corpus for
`fuzz/corpus/bacnet/` regenerated from the updated fixture via `tools/extract_fuzz_corpus.py`
(l4/udp, no port filter -- BACnet/IP's own `GateKind::UdpPortIndependent`), adding 61 fresh seeds
alongside the corpus's existing libFuzzer-discovered (hash-named) entries; a ~45-second/1.87M-
execution standalone libFuzzer run plus the `fuzz_bacnet_corpus_regression` CTest case, both clean
under ASan/UBSan (zero crashes, zero sanitizer findings). Full CTest suite: 2070/2070 (default GCC
build, up from Phase 3's 2060); ASan/UBSan 2070/2070 (non-fuzz-labeled) plus the BACnet fuzz
corpus-regression target clean; no-live-capture 2058/2058; plus a clean-room extract-rebuild-test,
all re-verified before delivery; MinGW-w64 cross-compile confirmed to still compile and link
cleanly (same standing no-Wine-here limitation as every prior phase).

**Not yet done, tracked for a following increment**: DNP3 Device Attributes decode, role
classification, tag/point/DB touch summarization, and CSV/CMDB, STIX/TAXII-lite, and
firewall-ACL-draft export -- unchanged from Phase 3's own list, minus BACnet ReadPropertyMultiple,
which this phase completed. WritePropertyMultiple remains explicitly out of scope even though
ReadPropertyMultiple is now decoded -- see `bacnet.hpp`'s own "Explicitly out of scope" paragraph
for why sharing ReadPropertyMultiple-Request's object-list framing wasn't reason enough to add a
third repeated-record shape (WritePropertyMultiple's own PropertyValue-per-property, plus optional
Priority) to this first pass.

## Phase 5 -- DNP3 Device Attributes (group 0) decode + wiring

Decode Device Attributes objects (IEEE 1815 group/variation 0): Device Manufacturer's Name, Device
Serial Number, Product Name and Model, Firmware Version -- confirm exact variation numbers against the
spec before implementing, don't guess. Wire into `InventoryAsset`.

(This phase no longer also carries "add S7comm-Plus dispatch," as originally planned here -- that
turned out to be pure wiring and shipped in Phase 1 instead once `src/asset_inventory.cpp` was read
directly; see this doc's own "Context" section.)

## Phase 6 -- Role classification (heuristic, informational only)

New `InventoryAsset::inferred_role` (string, e.g. "PLC/RTU", "HMI", "Engineering Station",
"Historian", "Unknown") from a small, explicit, documented heuristic table: protocol mix plus
port/traffic-volume signals already available in `InventoryAsset`/`InventoryEdge`. Explicitly labeled
low-confidence in both the report output and `docs/USER_GUIDE.md` -- same posture as
`direction_source`'s own `PortHeuristic` tier. Draft the exact heuristic table and put it in front of
Jurgen before implementing -- this one has no spec to cite at all, so it needs the sanity check even
more than Phase 3/4's decode tables.

## Phase 7 -- Tag/point/DB touch summarization

Extend `InventoryEdge` with a capped, summarized per-address touch record (e.g. top 32
most-frequently-touched addresses per edge) rather than an unbounded set. Per protocol: Modbus
register address, S7 DB number + start address, DNP3 point index, IEC104 IOA. New "TOP TOUCHED
ADDRESSES" subsection per edge in text/JSON. CIP/OPC UA/MMS/MQTT "tag" addressing is symbolic-path-
based rather than a small integer -- explicitly deferred/flagged rather than attempted in this phase.

## Phase 8 -- CSV / CMDB export

New `inventory --format csv` (extend `cli_main.cpp`'s `CLI::IsMember({"text","json"})` to include
`"csv"`), one row per `InventoryAsset` -- mirroring `decode`'s own CSV quoting rules exactly, reusing
its existing CSV-field-quoting helper rather than writing a second one. Confirm with Jurgen whether
edges/conduits need their own export before building a second writer speculatively.

## Phase 9 -- STIX/TAXII-lite export

New `write_inventory_stix_json` producing a minimal STIX 2.1 bundle: one `infrastructure` SDO per
asset carrying vendor/product/firmware as `x_`-prefixed custom properties, no TAXII *server* (a
transport protocol out of scope for a decoder/analysis tool) -- "lite" means "a valid STIX bundle
file." Confirm this framing matches what Jurgen actually wants before building it.

## Phase 10 -- Firewall ACL draft export

New `write_inventory_acl_cisco`/`_fortinet`/`_paloalto` deriving object-group/address-group + rule
drafts directly from `InventoryZone`/`InventoryConduit` (already exist) -- needs zero new asset
fields, since Grok's ask here is "propose an ACL matching the zones/conduits I already observed."
Output is explicitly a **draft for a human to review**, never something conduitscope claims is ready
to deploy.

## Testing & fixtures (every phase)

New `tools/make_sample_pcap.py`-generated pcap per new decoded message type (Phase 0-1 needed none --
`tests/sample_enip.pcap` and `tests/sample_s7commplus.pcap` already carried exactly the fixtures
needed). New CTest entries against real captured output from the actual binary, never hand-written
expected output. Full CTest (default GCC, ASan/UBSan, no-live-capture, MinGW-w64) after every phase,
plus a clean-room extract-rebuild-test before delivery. New fuzz coverage for every newly-decoded
message type (SZL, BACnet RPM, DNP3 Device Attributes).

## Docs (same phase as the code)

`asset_inventory.hpp`'s own header comment, `docs/USER_GUIDE.md`'s INVENTORY section and
LIMITATIONS, `docs/DEVELOPMENT.md`'s ROADMAP, and `docs/PROTOCOL_COVERAGE.md` (for newly-decoded
message types) all updated in the same phase as the code, per this project's standing convention.

## Open questions for Jurgen (not blocking Phases 0-3, which already shipped)

1. Rack/slot: confirmed nothing passively discoverable exists for it in any protocol this project
   decodes -- OK to scope out entirely (as this plan now does), or does Jurgen want CIP's
   path-addressable rack/slot surfaced only when a scanner's own explicit-messaging *request* names
   one?
2. Phase 8: asset-centric CSV only, or also an edges/conduits CSV for the CMDB use case?
3. Phase 9: is a STIX 2.1 JSON bundle file sufficient ("TAXII-lite"), or was actual TAXII transport
   part of the ask?

## Critical files

- `include/conduitscope/asset_inventory.hpp` / `src/asset_inventory.cpp` -- every new
  `InventoryAsset`/`InventoryEdge` field, `observe()`/`finish()` wiring per protocol, new report
  writers (text/JSON/CSV/STIX/ACL).
- `include/conduitscope/enip.hpp` -- already has the fields Phase 1 needed; read-only reference.
- `include/conduitscope/opcua.hpp` / `src/opcua.cpp` -- Phase 2's `OpcUaMessage` field promotion
  (shipped); `src/output.cpp`'s `write_opcua_json_fields` also gained the same fields.
- `include/conduitscope/s7comm.hpp` / `src/s7comm.cpp` -- Phase 3's new SZL decode (shipped);
  `src/decoder.cpp`'s `S7CommResult` construction site and `src/output.cpp`'s
  `write_s7comm_json_fields` also gained the same fields.
- `include/conduitscope/bacnet.hpp` / `src/bacnet.cpp` -- Phase 4's new ReadPropertyMultiple decode
  and Device object identity correlation (shipped); `src/asset_inventory.cpp`'s `observe()` and
  `src/output.cpp`'s `write_bacnet_json_fields` also gained the corresponding wiring/fields.
- `include/conduitscope/dnp3.hpp` / `src/dnp3.cpp` -- Phase 5's new Device Attributes decode.
- `src/cli_main.cpp` -- Phase 8's `--format csv` CLI plumbing for `inventory`.
- `tools/make_sample_pcap.py`, `tools/extract_fuzz_corpus.py`, `CMakeLists.txt`, `fuzz/fuzz_*.cpp`.
- `docs/USER_GUIDE.md`, `docs/DEVELOPMENT.md`, `docs/PROTOCOL_COVERAGE.md`.

## Verification bar (every phase, before it's considered done)

Default GCC build + full CTest; ASan/UBSan Clang build; MinGW-w64 cross-compile (compiles/links
cleanly -- this project's sandbox has no Wine, so the cross-compiled binary's own tests have never
been runnable here; an unrelated pre-existing test failing the identical way confirms this is an
environment limitation, not a regression); final clean-room zip rebuild + full `ctest` pass before
delivery via SendUserFile.
