# Asset inventory: a real OT asset record -- design document

Status: **Phases 0-7 (last-seen/identity scaffolding, EtherNet/IP CIP Identity wiring, S7comm-Plus
dispatch, OPC UA identity promotion, S7comm SZL decode + wiring, BACnet ReadPropertyMultiple decode +
Device-object identity correlation, DNP3 Device Attributes decode + identity correlation, role
classification, tag/point/DB touch summarization) implemented and shipped.** Phases 8-10 (CSV/CMDB
export, STIX/TAXII-lite export, firewall-ACL-draft export) are scoped below but not yet started. Written in response to
[Grok's ten-point ICS/OT improvement review](../reviews/2026-09-grok-ics-ot-improvement-areas.md)
(item 2) -- see [docs/reviews/2026-09-grok-response.md](../reviews/2026-09-grok-response.md) for the
fact-check of that review against the repository, and `docs/DEVELOPMENT.md`'s ROADMAP items 75-76,
79, 81-83 for the changelog-style writeup of what shipped and its exact verification numbers.

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

**Not yet done, tracked for a following increment**: role classification, tag/point/DB touch
summarization, and CSV/CMDB, STIX/TAXII-lite, and firewall-ACL-draft export -- unchanged from Phase
3's own list, minus BACnet ReadPropertyMultiple, which Phase 4 completed. WritePropertyMultiple
remains explicitly out of scope even though ReadPropertyMultiple is now decoded -- see
`bacnet.hpp`'s own "Explicitly out of scope" paragraph for why sharing ReadPropertyMultiple-
Request's object-list framing wasn't reason enough to add a third repeated-record shape
(WritePropertyMultiple's own PropertyValue-per-property, plus optional Priority) to this first
pass.

## Phase 5 -- DNP3 Device Attributes (group 0) decode + wiring (shipped)

Decodes IEEE 1815 Device Attributes (group 0) object headers in `dnp3.hpp`/`dnp3.cpp`: variation
numbers confirmed against Wireshark's `packet-dnp.c` `AL_OBJ_DA_*` definitions (fetched directly,
not guessed) -- Device Manufacturer's Name (variation 252), Device Product Name and Model
(variation 250), Device Serial Number (variation 248), Device Manufacturer's Software Version
(variation 242), Device Manufacturer's Hardware Version (variation 243). Group 0's wire format is
fundamentally different from every other group this decoder already handles: a point's byte width
isn't implied by its group/variation at all -- each point instead carries its own inline 1-byte
Data Type Code (VSTR/UINT/INT/FLT/OSTR/BSTR/TIME/UNCD/...) followed by a 1-byte length and that
many bytes of value (cross-checked against `packet-dnp.c`'s own `dnp3_al_process_object`'s
`AL_OBJ_GROUP(al_obj) == 0x0` branch), so it's decoded via a new, separate
`decode_device_attribute_point` function rather than an entry in the existing
`point_format()`/`bits_per_point` table every other group uses. NONE/VSTR/UINT/INT/FLT are fully
decoded (every data type the five promoted attributes, and the large majority of other real-world
attributes, actually use); OSTR/BSTR/TIME/UNCD and the two list types (U8BS8LIST/U8BS8EXLIST) are
recognized but not decoded further -- Wireshark's own dissector has the identical gap for these (it
reads the Data Type Code byte but never advances past it for any of them either), and rather than
guess a length this decoder doesn't actually know, parsing stops with a note, same "never guess"
posture as every other unsupported shape in this codebase. Also explicitly out of scope: variation
0 (the bare null-variation placeholder), 254 (non-specific "all attributes" request), and 255 (List
of Attribute Variations, whose index-prefixed bundle format packs a *different* attribute's
variation number into each list entry's own index prefix rather than naming one attribute in the
object header itself) -- a real single-attribute read/response (e.g. "read g0v252") is by far the
dominant real-world shape and the only one decoded here. One correction worth flagging: a plain
Read (function code 0x01) request never carries object data on the wire for *any* group (only the
object header naming which points to read) -- an asymmetry none of the other groups'
`point_format()`-table path accounts for (their own fixtures simply avoid exercising it). This
decoder applies that rule narrowly to group 0 only, leaving every other group's existing behavior
untouched, since fixing it generally is a separate, unscoped change this phase does not attempt.

Device attribute identity correlation, DNP3's analog of BACnet's own Device-object identity
correlation (Phase 4): when a Device Attributes response's object data resolves to one of the five
recognized variations above as a VSTR (Visible ASCII String) value, its text is promoted onto new
`Dnp3ApplicationFragment` fields (`has_device_identity` + `device_manufacturer_name`/
`device_product_name`/`device_serial_number`/`device_software_version`/`device_hardware_version`)
-- additive, nothing renamed or removed, same "widen the existing result struct" convention every
prior phase established. A non-VSTR value on one of these five variations (legal on the wire,
essentially never seen in practice) still decodes and appears in `dnp3_point_values` like any other
attribute, but is never promoted. Merged across every data-link frame coalesced into one TCP
payload onto `Dnp3Result` (`dnp3_has_device_identity` + the five `dnp3_device_*` fields),
first-seen-wins per field, same convention `dnp3_object_headers`/`dnp3_point_values` already use.
Wired into `InventoryAsset` in `asset_inventory.cpp`: `device_manufacturer_name` -> `vendor`,
`device_product_name` -> `product`, `device_serial_number` -> `serial_number`,
`device_software_version` -> `firmware_revision` -- bound to `dp.src_ip` (the response's sender,
i.e. the outstation actually being queried), mirroring the ENIP/OPC UA/S7comm/BACnet
identity-binding precedent exactly. `device_hardware_version` has no `InventoryAsset` field of its
own and is deliberately not promoted there -- decoded and available in
`dnp3_device_hardware_version`/`dnp3_point_values` regardless -- same "decode it, but don't invent
a narrow new field for a secondary fact" posture as S7comm's own module-type-code/version (Phase
3). Also surfaced directly on `decode --format json`'s own DNP3 output (`dnp3_has_device_identity`
+ the five `dnp3_device_*` fields in `write_dnp3_json_fields`, `src/output.cpp`) and in `decode`'s
own one-line text summary (a trailing `device-identity(manufacturer=... product=... ...)` segment,
mirroring BACnet's own `apdu_summary()` suffix), independent of `inventory`'s own wiring -- same
"both inventory wiring AND standalone decode fields" pattern every prior phase established.

(This phase no longer also carries "add S7comm-Plus dispatch," as originally planned here -- that
turned out to be pure wiring and shipped in Phase 1 instead once `src/asset_inventory.cpp` was read
directly; see this doc's own "Context" section. Re-confirmed while implementing this phase:
`asset_inventory.cpp`'s `observe()` already dispatches on `protocol == "s7comm-plus"` for both
asset tracking and function-name classification -- nothing further needed there.)

**Testing.** 8 new packets appended to `tests/sample_dnp3.pcap` (`build_dnp3_sample` in
`tools/make_sample_pcap.py`, using new `dnp3_device_attribute_header`/`dnp3_device_attribute_vstr`
helpers): a Read request for a single attribute confirming it carries zero object data; the
matching single-attribute Response (the identity correlation's simplest positive case); a Response
bundling all five recognized identity attributes in one fragment (also the inventory-wiring
fixture -- DNP3's own TCP addressing is already genuinely unicast, unlike BACnet's broadcast-heavy
UDP fixture, so no special-casing was needed there); an unsupported data type (OSTR) on an identity
variation, confirming it is noted but never promoted; a non-identity variation decoded generically
as UINT, confirming the generic (non-promoted) path also works for numeric types, not just VSTR; a
non-zero index prefix (the "List of Attribute Variations" bundling format) correctly bailing out;
a truncated VSTR (declared length exceeds what's actually present); and variation 0 (the bare
null-variation placeholder) correctly bailing out distinctly from the index-prefix case. 14 new
CTest cases (`decode` text/JSON for every scenario above, `inventory` text/JSON confirming the
`InventoryAsset` wiring) plus two updated (`baseline_check_dnp3_unmodified_zero_findings`/
`baseline_check_dnp3_empty_baseline_finds_new_conduit`'s distinct-operation/finding counts, which
grew from 6 to 15 now that `extract_dnp3_operations` -- unmodified -- naturally picks up the new
Device Attributes object headers as their own baseline operations, using the same
attribute-specific `group_name` rendering, e.g. "Read/Device Manufacturer's Name/v252", this phase
already needed for `decode`'s own object-header text) -- all verified against the real binary's own
output, never hand-written expected text. Fuzz corpus for `fuzz/corpus/dnp3/` regenerated from the
updated fixture via `tools/extract_fuzz_corpus.py` (l4/tcp), adding 22 fresh seeds alongside the
corpus's existing libFuzzer-discovered (hash-named) entries; a ~45-second/1.2M-execution standalone
libFuzzer run plus the `fuzz_dnp3_corpus_regression` CTest case, both clean under ASan/UBSan (zero
crashes, zero sanitizer findings). Full CTest suite: 2082/2082 (default GCC build, up from Phase
4's 2070); ASan/UBSan 2082/2082 (non-fuzz-labeled) plus the DNP3 fuzz corpus-regression target
clean; no-live-capture 2070/2070; plus a clean-room extract-rebuild-test, all re-verified before
delivery; MinGW-w64 cross-compile confirmed to still compile and link cleanly (same standing
no-Wine-here limitation as every prior phase).

**Not yet done, tracked for a following increment**: role classification, tag/point/DB touch
summarization, and CSV/CMDB, STIX/TAXII-lite, and firewall-ACL-draft export -- unchanged from Phase
4's own list, minus DNP3 Device Attributes, which this phase completed. Every identity-bearing
protocol named in this plan's original Phase 0-5 scope (EtherNet/IP, OPC UA, S7comm, BACnet/IP,
DNP3) is now wired; Modbus, IEC 104, HART-IP, MMS, MQTT, FF-HSE, and S7comm-Plus have no known
passively-discoverable identity fields of their own to wire (none of their wire formats carry an
analog of CIP Identity/SZL/Device-object properties/Device Attributes), so this identity-wiring list
is not expected to grow further as later phases land.

## Phase 6 -- Role classification (heuristic, informational only) (shipped)

New `InventoryAsset::inferred_role` (string, always one of exactly four values -- see that field's
own comment in `asset_inventory.hpp` for the complete rule table this section summarizes) from a
small, explicit, documented heuristic computed in a new pass inside `AssetInventoryEngine::finish`
(after `report.edges` is fully built and deduplicated, since the heuristic needs each asset's count
of DISTINCT peer IPs -- not available per-packet in `observe`, unlike every other `InventoryAsset`
field). Two protocol groupings drive it: `role_field_protocols()` (modbus/dnp3/s7comm/s7comm-plus/
enip/iec104/hartip/bacnet/ffhse -- protocols whose server side is conventionally the physical/
embedded field device being polled or commanded) and `role_data_platform_protocols()` (opcua/mms --
protocols spoken natively by EITHER a field device's own embedded server or a supervisory/
aggregation component, so usable only as a CLIENT-role signal, never a server-role one). MQTT is
deliberately in neither set -- its own broker/publisher-subscriber roles don't map onto "supervisory
client polling field devices" the way every other protocol here does.

Four-rule table, first match wins: (1) **"PLC/RTU"** -- `ever_server && !ever_client` plus at least
one field-device protocol; the single cleanest available signal, since a real field controller
essentially never opens its own outbound OT-protocol session. Deliberately folds in Grok's separate
"IED" ask -- passively, an IED (typically DNP3/IEC 104-heavy) and a PLC/RTU (typically Modbus/
S7comm/EtherNet/IP-heavy) produce the exact same server-only signal, and a PLC can legitimately speak
DNP3 as a substation RTU function just as well as a dedicated IED can, so there's no reliable
protocol-mix tie-break to split them on. (2) **"HMI/Engineering Station"** -- `ever_client &&
!ever_server`, at least one field-device protocol, AND at least two distinct server peers (the
"one console polling many PLCs" shape; the >= 2 threshold keeps a one-off single-peer session, e.g.
a contractor's laptop doing a firmware update, out of this bucket). Deliberately folds in Grok's
separate "Engineering Station" ask alongside "HMI" -- passively the two look identical (both are a
client polling multiple field devices; the difference is which software is installed, which this
tool can't observe on the wire). Confirmed this combined-label design with Jurgen before
implementing (see this phase's own open question below) rather than guessing at a four-way split
with no spec to check it against. (3) **"Historian/Data Collector"** -- `ever_client`, at least two
distinct server peers, via opcua/mms specifically, checked AFTER rule 2 so an asset that's a client
of BOTH a field protocol and OPC UA/MMS lands as HMI/Engineering Station (mixed protocol-client
behavior reads as more characteristic of an engineering workstation than a dedicated historian); a
server-only OPC UA/MMS asset is NOT promoted to PLC/RTU by rule 1 (opcua/mms are excluded from the
field-protocol set specifically because a server-only OPC UA/MMS asset could just as easily be a
real historian/aggregation-side server as a PLC's own embedded one), so it falls through to
"Unknown" unless something else about it matches another rule. (4) **"Unknown"** -- everything else,
including a genuinely dual-role asset (both `ever_client` and `ever_server` on field protocols --
e.g. a protocol gateway or sub-master RTU -- rule 1 and rule 2 are mutually exclusive by their own
`!ever_client`/`!ever_server` conditions, so a dual-role asset can't match either even when it would
otherwise clear the peer-count threshold), a below-threshold single-peer client, an MQTT-only asset,
and anything else this heuristic has no positive signal for. Always rendered as the literal string
"Unknown", never left empty -- unlike `vendor`/`product`/etc. (which stay empty on a miss), a role IS
always computed for every asset that exists; "Unknown" is this heuristic's own honest conclusion,
not an absence of an attempt. Deliberately NOT used as a signal: raw packet-count/traffic-volume
thresholds -- packet count tracks capture duration and per-protocol chattiness, not device role, and
adding a volume cutoff would mean inventing an even less-grounded threshold than the peer-count ones
above; left out of this first pass.

Rendered in `write_inventory_report_text` as a new `role: <value>  (heuristic, low confidence)` line
per asset (same low-confidence framing `direction_source`'s own `port-heuristic` tier already uses),
and in `write_inventory_report_json` as a new, always-present `inferred_role` field, appended after
`plant_identification` (the prior true-last field) -- named `inferred_role`, not `role`, to avoid
colliding with the JSON report's existing `role` field (client/server/client+server, a completely
different, already-established concept `role_text` computes).

One open question surfaced to, and resolved by, Jurgen before implementing (this heuristic has no
spec to check it against at all, so it needed the sanity check even more than Phase 3/4's decode
tables): whether "PLC/RTU"/"IED" and "HMI"/"Engineering Station" should be four separate labels (with
a weak protocol-mix tie-break) or two combined ones, given neither pair is actually distinguishable
from passive traffic alone. Jurgen chose the combined two-label design described above.

**Testing.** New `tests/sample_role_classification.pcap` (`build_role_classification_sample` in
`tools/make_sample_pcap.py`, 22 packets, 11 fresh IPs not reused by any other fixture) purpose-built
to hit every branch of the rule table above at least once in a single capture: an engineering
workstation client of three distinct field devices across three field protocols (HMI/Engineering
Station); a historian client of two distinct OPC UA servers with no field-protocol client activity
at all (Historian/Data Collector); three server-only field-protocol devices, one of which answers
TWO distinct clients while staying PLC/RTU (proving distinct-client count never enters that rule);
two OPC UA-server-only devices staying Unknown (proving opcua/mms are genuinely excluded from
promoting a server straight to PLC/RTU); a dual-role protocol gateway that's both a Modbus server and
a client of two distinct field devices, staying Unknown (proving the mutual-exclusion actually holds
in code); a one-off single-peer Modbus client staying Unknown (below the peer-count threshold); and
an MQTT publisher/broker pair, both staying Unknown (proving MQTT's exclusion holds on both the
client and server side). 11 new CTest cases (`inventory` text confirming each of the nine distinct
role outcomes above by IP, plus two JSON cases confirming `inferred_role` is always present -- both
for a classified asset and for an explicit "Unknown" one -- and that it's a JSON key distinct from
the pre-existing `role` field) -- all verified against the real binary's own output, never
hand-written expected text; one pre-existing CTest regex updated
(`dnp3_device_attribute_inventory_identity_wired_text`, whose match needed one more `[^\n]*\n` to
skip past the new `role:` line this phase inserts between an asset's first-seen/last-seen line and
its `identity:` line). No new decode logic was added this phase -- `AssetInventoryEngine::finish`'s
new role-inference pass operates entirely on already-decoded, already-validated
`InventoryAsset`/`InventoryEdge` structures in memory, parsing no untrusted bytes of its own -- so,
unlike every decode-adding phase before it, there was no new fuzz harness/corpus work to do. Full
CTest suite: 2093/2093 (default GCC build, up from Phase 5's 2082); ASan/UBSan 2169/2169
(non-fuzz-labeled, the higher count reflecting this build's own separately-tracked fuzz-corpus-
regression targets); no-live-capture 2081/2081; plus a clean-room extract-rebuild-test, all
re-verified before delivery; MinGW-w64 cross-compile confirmed to still compile and link cleanly
(same standing no-Wine-here limitation as every prior phase).

**Not yet done, tracked for a following increment**: CSV/CMDB, STIX/TAXII-lite, and
firewall-ACL-draft export -- unchanged from Phase 5's own list, minus role classification (Phase 6)
and tag/point/DB touch summarization (this phase), both now shipped.

## Phase 7 -- Tag/point/DB touch summarization (shipped)

New `InventoryEdge::top_touched_addresses` (a capped, sorted list of `{address, count}` pairs -- see
that field's own comment in `asset_inventory.hpp` for the complete per-protocol design this section
summarizes) plus `touched_addresses_total_distinct`/`touched_addresses_truncated`, replacing the
plan's originally-sketched raw `std::map` with a two-tier cap design worked out during
implementation: an internal per-edge accumulation map (`AssetInventoryEngine::EdgeState::
address_touch_counts`) admits at most `kMaxTrackedAddressesPerEdge` (4096) distinct addresses --
past that ceiling, an already-tracked address keeps incrementing but no new one is admitted, the same
"pure ceiling, no eviction" shape `resource_limits.hpp`'s own `max_active_flows`/
`max_flow_state_entries` already use for an unrelated (decode-time, per-flow) concern. `finish()`
then sorts that map once (count descending, address string ascending as a deterministic tie-break)
and truncates to the top `kMaxShownTouchedAddressesPerEdge` (32, the plan's own suggested example) for
the final report. Both constants are fixed engineering-judgment values, not CLI-configurable --
deliberately NOT wired into `resource_limits.hpp`'s own tunable-cap system, since that system is
scoped to decode-time/per-flow adversarial-input protection inside `Decoder`, a different engine and a
different concern from `AssetInventoryEngine`'s own post-processing accumulation across a whole
capture.

The plan's own research instruction -- confirm during implementation whether CIP/OPC UA/MMS/MQTT's
symbolic-path addressing is "already surfaced anywhere reusable" before deciding per-protocol scope --
turned up a real, materially different answer per protocol, surfaced to and confirmed by Jurgen (see
this phase's own open question below) before implementing: OPC UA's NodeId and MMS's domain/item
object reference are genuinely only ever stringified into free-text `notes`/`values` entries in this
codebase today (neither has a structured field of its own), so promoting either would be real new
decode-surface work and both stay explicitly deferred/out of scope; but CIP's `CipMessage::path.
summary` (already a structured, human-readable tag-name string whenever `CipPath::is_symbolic` is
true) and MQTT's `MqttMessage::topic` (already a structured field, PUBLISH-only) are both zero-new-
decode reuse exactly like every other protocol this phase wires in, so the shipped scope widened from
the plan's original four-protocol list to six:

  - **modbus**: a `"<kind>:<1-based address>[-<1-based end address>]"` key from the read/write-
    multiple families' own already-decoded `function_code`+`start_address`(+`quantity`) --
    `kind` is `coil`/`discrete`/`hreg`/`ireg`; Write Single Coil/Register never contribute
    (`start_address` stays unset for that family -- a pre-existing, documented scope boundary, not
    new here).
  - **s7comm**: `S7Item::tag` verbatim (e.g. `"DB10.DBW100"`, `"I0.0"`, `"T5"`) for every item on a
    Read Var/Write Var request whose `syntax_supported` is true, prefixed `"experimental:"` when
    decoded via the EXPERIMENTAL 0xB2/TIA-1200 path (`is_experimental`) -- never silently presented
    as equally trustworthy as a well-established S7ANY tag.
  - **dnp3**: `"g{group}v{variation}"` (the SAME shorthand `src/dnp3.cpp`'s own summary/
    `dnp3_object_headers` rendering already establishes, reused verbatim) plus `" idx {start}-{stop}"`
    (or `" idx {start}"` for a single-point range) when `Dnp3ObjectRange::has_range` is true --
    deliberately header-range-level, not true per-point (the merged `Dnp3Result` this engine reads
    doesn't retain each fragment's own per-point `Dnp3PointValue::index`; exposing that would be new
    decode-surface work, out of scope here).
  - **iec104**: `"ioa={value}"` from a new, small, additive `Iec104Result::iec104_object_ioas` field
    (a `std::vector<uint32_t>`, populated in lockstep with the already-existing
    `iec104_object_values` inside `Iec104Decoder::decode`'s `merge_asdu` lambda, same cap) -- the same
    "promote an already-extracted value to a named structured field" pattern Phase 1's ENIP
    `identity_*` fields already established.
  - **enip** (explicit messaging only, never CIP I/O implicit messaging): `CipMessage::path.summary`
    verbatim, gated on `CipPath::is_symbolic` -- a class/instance/attribute-addressed CIP message
    (generic object access, e.g. Identity `Get_Attributes_All`) contributes nothing, since that isn't
    a tag/point in the sense this phase's ask means.
  - **mqtt**: `MqttMessage::topic` verbatim, PUBLISH packets only.

BACnet/HART-IP/FF-HSE/S7comm-Plus carry no per-point/per-tag addressing concept this codebase decodes
at all today, and stay out of scope for the same reason.

Rendered as a new "top touched addresses" block per edge in `write_inventory_report_text` (omitted
entirely, not printed empty, for an edge with nothing tracked -- same convention the identity/
security/plant-identification lines already follow), and in `write_inventory_report_json` as three new
fields appended after `last_seen_text` (the prior true-last field) -- `top_touched_addresses` (always
an array, even empty, same unconditional-emission convention `observed_functions` already uses, unlike
`vendor`/`product`'s own omit-when-empty one), `touched_addresses_total_distinct`, and
`touched_addresses_truncated`.

One open question surfaced to, and resolved by, Jurgen before implementing: whether to widen this
phase's scope to include CIP tag paths and MQTT topics (discovered during research to already be
free reuse, unlike the plan's original framing that lumped all four "symbolic" protocols together as
deferred) or ship exactly the plan's original four-protocol list. Jurgen chose to include CIP and MQTT.

**Testing.** New `tests/sample_touch_summarization.pcap`
(`build_touch_summarization_sample` in `tools/make_sample_pcap.py`) puts one concern on its own
isolated, fresh client/server IP pair per edge, so each expected result is independently hand-
verifiable: a modbus edge exercising every key format plus the write-multiple request+response
double-touch; a second modbus edge with 35 distinct single-register reads (every count tied at 1)
proving both the top-32 truncation and the deterministic (count desc, address asc) sort actually fire,
not just documented; an s7comm edge with three S7ANY tags plus one EXPERIMENTAL 0xB2 item, proving the
`"experimental:"` prefix applies to only the right one; a dnp3 edge with a no-range Class-0-poll
request key alongside a real multi-point range and a single-point range in the response, proving all
three has_range/tie-break shapes render correctly; an iec104 edge with a 5-point SQ=1 report, proving
the new `iec104_object_ioas` field feeds this engine correctly; an enip edge with a symbolic Read_Tag/
Write_Tag round trip against the same tag alongside a class/instance `Get_Attributes_All` on the same
edge, proving the latter contributes nothing even though three CIP messages were exchanged; an mqtt
edge with three PUBLISH packets across two topics; and an opcua edge (GetEndpoints), proving this
out-of-scope protocol genuinely emits nothing rather than silently mis-tracking it. 12 new CTest cases
(nine text, three JSON), all verified against the real binary's own output on the first run -- no
hand-written expected text. Two PRE-EXISTING CTest regexes were also found broken during this phase's
verification pass and fixed (`inventory_enip_no_identity_fields_omitted_for_client_json`/
`inventory_opcua_no_identity_fields_omitted_for_client_json`): both anchored on an asset's JSON object
ending immediately after `last_seen_text`, a pattern Phase 6's own unconditional `inferred_role`
addition had already invalidated without either regex being updated at the time -- a latent regression
from Phase 6, not introduced by this phase, caught only because this phase's own verification pass
ran the full suite from a clean build. No new fuzz harness/corpus work was needed: the one piece of
new parsing-adjacent code (`iec104_object_ioas`'s population) is a pure additive promotion of a value
that was already extracted from already-validated bytes inside `merge_asdu` (no new byte-parsing path
of its own), and `AssetInventoryEngine`'s own touch-tracking is, like Phase 6's role inference, pure
post-processing over already-decoded, already-validated structures -- parsing no untrusted bytes of
its own. `docs/PROTOCOL_COVERAGE.md` was deliberately NOT updated for this phase, per the Phase 0/6
precedent that it's scoped to wire-format decode coverage only: nothing here decodes a new wire
format, `iec104_object_ioas` only exposes an already-decoded value as a new structured field. Full
CTest suite: 2105/2105 (default GCC build, up from Phase 6's 2093 -- 12 new touch-summarization tests
plus the 2 pre-existing regex fixes just described, net +12); ASan/UBSan 2181/2181; no-live-capture
2093/2093; plus a clean-room extract-rebuild-test, all re-verified before delivery; MinGW-w64
cross-compile confirmed to still compile and link cleanly (same standing no-Wine-here limitation as
every prior phase).

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
  writers (text/JSON/CSV/STIX/ACL). Also where Phase 6's `inferred_role` heuristic lives (shipped) --
  `InventoryAsset::inferred_role`'s own comment there is the authoritative statement of the full rule
  table; `finish()`'s new role-inference pass and `write_inventory_report_text`/`_json`'s rendering.
  Also where Phase 7's `top_touched_addresses` (shipped) lives -- `InventoryEdge::
  top_touched_addresses`'s own comment there is the authoritative statement of the full per-protocol
  key design and the two-tier cap; `observe()`'s new per-packet address extraction, `EdgeState::
  address_touch_counts`'s capped accumulation, `finish()`'s sort/truncate pass, and
  `write_inventory_report_text`/`_json`'s rendering.
- `include/conduitscope/enip.hpp` -- already has the fields Phase 1 needed; read-only reference.
- `include/conduitscope/opcua.hpp` / `src/opcua.cpp` -- Phase 2's `OpcUaMessage` field promotion
  (shipped); `src/output.cpp`'s `write_opcua_json_fields` also gained the same fields.
- `include/conduitscope/s7comm.hpp` / `src/s7comm.cpp` -- Phase 3's new SZL decode (shipped);
  `src/decoder.cpp`'s `S7CommResult` construction site and `src/output.cpp`'s
  `write_s7comm_json_fields` also gained the same fields.
- `include/conduitscope/bacnet.hpp` / `src/bacnet.cpp` -- Phase 4's new ReadPropertyMultiple decode
  and Device object identity correlation (shipped); `src/asset_inventory.cpp`'s `observe()` and
  `src/output.cpp`'s `write_bacnet_json_fields` also gained the corresponding wiring/fields.
- `include/conduitscope/dnp3.hpp` / `src/dnp3.cpp` -- Phase 5's new Device Attributes decode and
  device attribute identity correlation (shipped); `src/asset_inventory.cpp`'s `observe()` and
  `src/output.cpp`'s `write_dnp3_json_fields` also gained the corresponding wiring/fields.
- `include/conduitscope/iec104.hpp` / `src/iec104.cpp` -- Phase 7's small, additive
  `Iec104Result::iec104_object_ioas` field (shipped), populated alongside the already-existing
  `iec104_object_values` in `Iec104Decoder::decode`'s `merge_asdu` lambda; no new decode.
- `src/cli_main.cpp` -- Phase 8's `--format csv` CLI plumbing for `inventory`.
- `tools/make_sample_pcap.py`, `tools/extract_fuzz_corpus.py`, `CMakeLists.txt`, `fuzz/fuzz_*.cpp`.
- `docs/USER_GUIDE.md`, `docs/DEVELOPMENT.md`, `docs/PROTOCOL_COVERAGE.md`.

## Verification bar (every phase, before it's considered done)

Default GCC build + full CTest; ASan/UBSan Clang build; MinGW-w64 cross-compile (compiles/links
cleanly -- this project's sandbox has no Wine, so the cross-compiled binary's own tests have never
been runnable here; an unrelated pre-existing test failing the identical way confirms this is an
environment limitation, not a regression); final clean-room zip rebuild + full `ctest` pass before
delivery via SendUserFile.
