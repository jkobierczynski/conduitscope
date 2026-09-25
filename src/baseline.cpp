// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/baseline.hpp"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <fstream>
#include <optional>
#include <ostream>
#include <sstream>

#include "conduitscope/bacnet.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/fins.hpp"
#include "conduitscope/melsec.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/s7comm.hpp"

namespace conduitscope {

namespace {

// --------------------------------------------------------------------------------------------
// extract_operations() -- one function per in-scope protocol, see baseline.hpp's own comment.
// --------------------------------------------------------------------------------------------

// Modbus: operation_key is the function name alone (Phase 1 has exactly one address space per
// function, per the design doc), range is [start_address, start_address + quantity) when both are
// set. Deliberately reads ONLY mb.is_request == true frames: a read response carries no address at
// all (nothing to extract), and a write response ECHOES address+quantity back on the wire -- were
// this to also extract from is_request == false, a single write would be double-counted once from
// its request and once from its own paired response echo. See ModbusFrame::is_request's own
// comment (modbus.hpp) for the full per-function-family reasoning, including why Write Single
// Coil/Register never contributes an operation here at all (is_request is never true for that
// family -- see decode_write_single's own comment, modbus.cpp).
std::vector<Operation> extract_modbus_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const ModbusFrame& mb = dp.result->as<ModbusFrame>();
    if (!mb.is_request || mb.function_name.empty()) return ops;

    Operation op;
    op.protocol = "modbus";
    op.operation_key = mb.function_name;
    if (mb.start_address && mb.quantity) {
        op.has_target_range = true;
        op.range_start = *mb.start_address;
        op.range_end = static_cast<uint32_t>(*mb.start_address) + static_cast<uint32_t>(*mb.quantity);
    }
    ops.push_back(std::move(op));
    return ops;
}

// The wire-byte width of one element of S7ANY transport_size `ts`, or std::nullopt for a
// transport size this baseline doesn't know a fixed byte width for (BIT is handled separately by
// the caller, never reaches this function; every other unrecognized/reserved code falls through to
// std::nullopt, same "not decoded further" posture s7comm.cpp's own s7_transport_size_name takes
// for an unrecognized code). Mirrors the wire values s7comm.cpp's own s7_transport_size_name
// documents (BYTE/CHAR=1, WORD/INT/DATE=2, DWORD/DINT/REAL/TOD/TIME=4, DATE_AND_TIME=8) -- kept
// here rather than added to that function, since "how many bytes does this occupy" is a baseline-
// specific question s7comm.cpp's own display-name table has no other reason to answer.
std::optional<uint32_t> s7_transport_size_byte_width(uint8_t ts) {
    switch (ts) {
        case 0x02: return 1;  // BYTE
        case 0x03: return 1;  // CHAR
        case 0x04: return 2;  // WORD
        case 0x05: return 2;  // INT
        case 0x09: return 2;  // DATE
        case 0x06: return 4;  // DWORD
        case 0x07: return 4;  // DINT
        case 0x08: return 4;  // REAL
        case 0x0A: return 4;  // TOD
        case 0x0B: return 4;  // TIME
        case 0x0E: return 8;  // DATE_AND_TIME
        default: return std::nullopt;
    }
}

// True for the two S7ANY area codes (s7comm.hpp: 0x84 Data Block, 0x85 Instance Data Block) whose
// db_number is meaningful -- see S7Item::db_number's own comment ("meaningful when area is DB/DI").
bool s7_area_has_db_number(uint8_t area) { return area == 0x84 || area == 0x85; }

// True for the two S7ANY area codes (0x1C Counters, 0x1D Timers) whose wire address field is the
// counter/timer NUMBER itself, not a byte<<3|bit encoding -- see S7Item::byte_address's own comment
// ("for counter/timer areas, this is the counter/timer number instead").
bool s7_area_is_counter_or_timer(uint8_t area) { return area == 0x1C || area == 0x1D; }

// S7comm: one Operation per S7Item in a Read Var/Write Var Job's item list (a single Job can carry
// several items at different addresses; each is its own operation for baselining purposes, all
// sharing the same conduit -- see baseline.hpp's own header comment). Deliberately reads ONLY the
// Job (request) side: S7CommFrame::items (s7comm.hpp) is populated ONLY for function_code 0x04
// (Read Var) or 0x05 (Write Var) on the Job side -- the Ack_Data (response) side's own `items` is
// always empty (it carries `data_items`, values/return codes, never addresses) -- so `!sr.items.
// empty()` alone is already an authoritative "this is a request" signal, with nothing on the
// response side to double-count against in the first place (unlike Modbus writes, which need the
// explicit is_request check above).
//
// operation_key: "<function_name>/<area_name>[/DB<n>]" -- db_number is only appended for the two
// area codes it's actually meaningful for (s7_area_has_db_number); function_name alone already
// distinguishes Read Var from Write Var, so there's no need to also carry S7comm's own rosctr
// (which S7CommResult doesn't even expose -- see s7comm.hpp's own comment on why S7CommResult
// can't simply be an unmodified S7CommFrame).
//
// Range unit decision (transport_size BIT): a BIT-addressed item's natural address unit is BITS
// (bit_address = byte_address*8 + bit_offset, already computed on the decode side -- see
// S7Item::bit_address's own comment, s7comm.hpp), not bytes -- mixing bit-granularity and byte-
// granularity ranges under the same operation_key's observed_ranges would corrupt the interval math
// (a "bit 3" observation and a "byte 3" observation are not comparable numbers at all; a range
// [0,8) could mean "bits 0-7" or "bytes 0-7" with no way to tell which after the fact). Rather than
// try to widen the existing byte-unit ranges to somehow also hold bit-unit ones (which is exactly
// the corruption this must avoid), a BIT item gets its OWN operation_key -- the same base
// "<function_name>/<area_name>[/DB<n>]" key every other item in this same area/DB would get, with a
// trailing "/bit" appended (a separator no legitimate area_name or "DB<n>" suffix can ever produce,
// so it can never collide) -- and has_target_range/range_start/range_end are populated in
// bit_address units under THAT key. This is exactly Phase 2's own DNP3-precedent for "what counts as
// 'the operation' is inherently per-protocol" (see this file's own Phase 2 header comment): the
// engine (merge_baseline_observations/check_baseline/the JSON schema/the verdict model) never
// interprets operation_key at all, so giving bit- and byte-unit accesses to the same area distinct
// keys costs nothing there -- a conduit that both reads MB bytes and writes M#.# bits to Merkers
// simply shows up as two OperationBaseline rows instead of one, which is the correct, honest
// representation (two genuinely different addressing granularities), not a bug to merge away.
//
// item.count for a BIT item: verified against the real decode path (s7comm.cpp's parse_s7_item),
// not assumed -- the wire's "number of elements" field is read identically for every transport size,
// including BIT, with no special-casing. In practice, every BIT item this codebase's own fixture
// generator (tools/make_sample_pcap.py's s7any_item) and every real capture this project has seen
// produces count == 1 (Step7/TIA Portal/snap7 all address one bit per item; S7ANY has no
// "N consecutive bits in one item" idiom the way byte-oriented areas have "N consecutive words").
// Nothing on the wire actually prohibits count > 1 though, so this treats it the same "one unit per
// element" way the Counter/Timer branch below already does (range_end = bit_address + count) rather
// than assuming 1 and silently dropping anything else -- correct either way, and count == 1 (the
// overwhelmingly common case) degenerates to exactly the single-bit range one would expect.
std::vector<Operation> extract_s7comm_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const S7CommResult& sr = dp.result->as<S7CommResult>();
    if (!sr.has_function || sr.items.empty()) return ops;

    for (const S7Item& item : sr.items) {
        Operation op;
        op.protocol = "s7comm";
        std::ostringstream key;
        key << sr.function_name << "/" << item.area_name;
        if (s7_area_has_db_number(item.area)) {
            key << "/DB" << item.db_number;
        }
        op.operation_key = key.str();
        std::string area_letter = s7_area_letter_for_code(item.area);

        if (s7_area_is_counter_or_timer(item.area)) {
            // byte_address IS the counter/timer number here (see s7_area_is_counter_or_timer's own
            // comment); each element requested is one more counter/timer number, the same
            // "one unit per element" shape byte-granularity areas have, just with a fixed width of
            // 1 rather than a transport-size-dependent one.
            if (item.count > 0) {
                op.has_target_range = true;
                op.range_start = item.byte_address;
                op.range_end = item.byte_address + static_cast<uint32_t>(item.count);
                op.s7_area_letter = area_letter;
                op.s7_range_unit = "counter_or_timer";
            }
        } else if (item.is_experimental) {
            // 0xB2 (S7-1200/1500 symbolic addressing) items carry no transport_size/count at all
            // (see S7Item's own comment) -- nothing to build a byte range from; has_target_range
            // stays false.
        } else if (item.transport_size == 0x01) {
            // BIT -- see this function's own header comment above: its own distinct, "/bit"-suffixed
            // operation_key, range tracked in bit_address units.
            op.operation_key = key.str() + "/bit";
            if (item.count > 0) {
                op.has_target_range = true;
                op.range_start = item.bit_address;
                op.range_end = item.bit_address + static_cast<uint32_t>(item.count);
                op.s7_area_letter = area_letter;
                op.s7_db_number = item.db_number;
                op.s7_range_unit = "bit";
            }
        } else if (auto width = s7_transport_size_byte_width(item.transport_size); width && item.count > 0) {
            op.has_target_range = true;
            op.range_start = item.byte_address;
            op.range_end = item.byte_address + static_cast<uint32_t>(item.count) * (*width);
            op.s7_area_letter = area_letter;
            op.s7_db_number = item.db_number;
            op.s7_range_unit = "byte";
        }
        // Any other case (an unrecognized transport size the byte-width table above doesn't know,
        // or count == 0) leaves has_target_range at its default false -- the operation is still
        // recorded, just without a range to check.

        ops.push_back(std::move(op));
    }
    return ops;
}

// --------------------------------------------------------------------------------------------
// Phase 2 (roadmap item 41, docs/design/baseline-engine.md): the six protocols beyond S7comm/
// Modbus. Per protocol, whether it gets full range-tracking (has_target_range=true, contributing
// to NewTargetRange detection) or key-only tracking (operation_key distinguishes the operation, no
// range) was decided by reading each protocol's own real struct fields -- not assumed from the
// design doc's own earlier speculative notes -- and is documented at each function below. Two
// protocols needed a small additive prerequisite before extraction was even possible, the same
// "structured field, not a string to scrape" precedent ModbusFrame::start_address/quantity already
// set in Phase 1:
//   - DNP3: Dnp3Result (the type actually reachable from DecodedPacket::result) only carried
//     ALREADY-RENDERED display strings for its object headers ("g1v2 (Binary Input)") -- the real
//     group/variation/range_start/range_stop numbers Dnp3ObjectHeader itself computes never reached
//     DecodedPacket at all. Fixed by adding Dnp3Result::dnp3_objects (dnp3.hpp/dnp3.cpp), a small,
//     purely additive structured mirror of that same display list.
//   - EtherNet/IP: CipMessage has NO equivalent gap for its class/instance/attribute addressing
//     (CipPath already carries those as real fields) -- but Read_Tag_Fragmented/Write_Tag_
//     Fragmented's own byte_offset IS exactly this same problem, and was NOT fixed the same way
//     (see extract_enip_operations' own comment for why: it's genuinely out of scope for this pass,
//     not merely deferred).
// --------------------------------------------------------------------------------------------

// EtherNet/IP (CIP): operation_key is the CIP service name, plus class/instance/attribute when the
// request path addresses by class/instance/attribute (CipPath::is_symbolic == false) -- mirrors S7's
// own "fold a bounded, meaningful addressing dimension into the key" precedent for DB number: a real
// conduit talks to a small, stable set of CIP object classes/instances/attributes, not a new one
// per packet, so this doesn't explode operation_key cardinality the way putting a raw per-call
// address would. A Rockwell Logix5000 NAMED-TAG request (is_symbolic == true -- Read_Tag/Write_Tag/
// Read_Tag_Fragmented/Write_Tag_Fragmented/Read_Modify_Write_Tag) carries no class/instance/
// attribute at all (see CipPath's own comment) and the tag NAME itself is deliberately never folded
// into the key either -- that would make every distinct tag name its own operation_key, the same
// over-granular trap this file's own header comment warns against (see extract_modbus_operations'
// "one address space per function" framing) -- so a symbolic request's key is the bare service name.
//
// has_target_range is ALWAYS false here -- this is a genuine, honestly-scoped gap, not an oversight:
// CIP's only linear byte-offset addressing (Read_Tag_Fragmented/Write_Tag_Fragmented's own
// byte_offset, used to read/write a tag element-by-element across several requests) is computed by
// enip.cpp's decode_cip_request_data/decode_write_tag_request and rendered straight into
// CipMessage::values as free text ("element_count=10 byte_offset=1234") -- it never reaches a
// structured field on CipMessage/CipPath the way S7Item::byte_address or ModbusFrame::start_address
// do. Regexing a number back out of that values string would be exactly the "don't scrape a summary
// for numbers" anti-pattern the design doc rejected for Modbus before ModbusFrame::start_address/
// quantity existed (see this file's own header comment) -- so this pass does not attempt it. A
// genuine fix mirrors that same precedent: add a structured byte_offset/element_count field to
// CipMessage, a small, self-contained follow-up to enip.hpp/enip.cpp this baseline engine does not
// make on its own initiative. Get_Attribute_Single/Set_Attribute_Single addressing by class/
// instance/attribute was never a linear range to begin with (per this feature's own design doc), so
// that half of the gap is a correct scoping decision, not a missing field.
std::vector<Operation> extract_enip_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    // EnipResult is EtherNet/IP explicit messaging's own result type (enip.hpp) -- CIP I/O (UDP port
    // 2222, CipIoFrame) shares the "enip" protocol_id but carries no addressable operation at all
    // (raw assembly data only, see enip.hpp's own CipIoFrame comment), so this must be checked BEFORE
    // ever calling dp.result->as<EnipResult>(): calling that accessor on a CipIoFrame-backed result
    // throws ProtocolResultTypeMismatch rather than reinterpreting one struct as the other.
    if (!dp.result || !dp.has_tcp) return ops;
    const EnipResult& er = dp.result->as<EnipResult>();
    const CipMessage& cip = er.first.cip;
    // Request-side only (mirrors S7/Modbus's own convention): a response echoes the same service
    // name back (with the reply bit set) but never carries a request path of its own to key on.
    if (!er.first.has_cip || cip.is_response || !cip.decoded || cip.service_name.empty()) return ops;

    Operation op;
    op.protocol = "enip";
    std::ostringstream key;
    key << cip.service_name;
    if (!cip.path.is_symbolic) {
        if (cip.path.class_id) {
            key << "/Class0x" << std::hex << std::uppercase << *cip.path.class_id << std::dec << std::nouppercase;
        }
        if (cip.path.instance_id) key << "/Instance" << *cip.path.instance_id;
        if (cip.path.attribute_id) key << "/Attr" << *cip.path.attribute_id;
    }
    op.operation_key = key.str();
    // has_target_range stays false -- see this function's own header comment.
    ops.push_back(std::move(op));
    return ops;
}

// DNP3: operation_key is "<function_name>/<group_name>/v<variation>" -- function code, group, and
// variation, per the design doc's own minimum. Deliberately NOT request-side only, unlike every
// other protocol in this file -- a genuine, documented divergence, not an oversight:
//   - DNP3's function_name itself already tells request and response apart (Read/Write/Select/
//     Operate/Direct Operate/... on the request side; Response/Unsolicited Response/Authentication
//     Response on the response side), so it's already baked into operation_key the same way S7/
//     Modbus's own request-only filtering exists to AVOID conflating the two -- there is no
//     operation_key collision risk between a request and its own paired response the way Modbus's
//     write-echo problem has, because they never share a key to begin with.
//   - Unlike Modbus's write echo (where the response redundantly repeats the SAME address the
//     request already gave), a DNP3 Read response's own object headers are NOT an echo of the
//     request's addressing: a real-world Read request very often uses an "all points"/Class-0-poll
//     qualifier with no start-stop range at all (has_range false, nothing to extract), and the
//     RESPONSE is the only place the outstation's own actual reported point range appears. Skipping
//     the response side, the way S7/Modbus do, would leave DNP3 Read range-tracking nearly inert for
//     exactly the traffic pattern (Class 0 polling) that's most common in real deployments.
//   - For control operations (Select/Operate/Direct Operate), the request DOES carry the real
//     target -- but CROB/analog-output objects normally use an INDEX-PREFIXED qualifier, not a
//     start-stop range (has_range false there too), so has_target_range naturally stays false for
//     those regardless of which side is read; nothing here forces a range where the wire format
//     doesn't offer one.
// has_target_range/range_start/range_end come directly from Dnp3ObjectRange (dnp3.hpp/dnp3.cpp's
// own additive structured field -- see this file's own "Phase 2" header comment above for why that
// was needed at all): true only when the object header both used a start-stop range qualifier AND
// was itself fully decoded, range_stop is inclusive on the wire so range_end = range_stop + 1.
std::vector<Operation> extract_dnp3_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const Dnp3Result& dr = dp.result->as<Dnp3Result>();
    if (!dr.dnp3_has_function || dr.dnp3_function_name.empty() || dr.dnp3_objects.empty()) return ops;

    for (const Dnp3ObjectRange& obj : dr.dnp3_objects) {
        Operation op;
        op.protocol = "dnp3";
        std::ostringstream key;
        key << dr.dnp3_function_name << "/" << obj.group_name << "/v" << static_cast<unsigned>(obj.variation);
        op.operation_key = key.str();
        if (obj.has_range && obj.range_stop >= obj.range_start) {
            op.has_target_range = true;
            op.range_start = obj.range_start;
            op.range_end = obj.range_stop + 1;  // inclusive on the wire -> half-open for Operation
        }
        ops.push_back(std::move(op));
    }
    return ops;
}

// BACnet: operation_key is "<service>/<object-type>/<property-name>" for readProperty/writeProperty
// (this decoder's own kBacnetConfirmedServiceChoice spelling -- camelCase, not the PascalCase ASHRAE
// clause-20 service names -- verified against the real decode; these are this decoder's only two
// address-bearing "first pass" services, per bacnet.hpp -- every other
// confirmed/unconfirmed service is named-only, with no object/property to key on, and is skipped
// here rather than recorded under a bare service name: Who-Is/I-Am/Who-Has/I-Have are device-
// discovery broadcasts, not per-object operations against a specific conduit's memory, and don't fit
// this engine's "operation against a target" model at all). Confirmed-Request side only (pdu_type
// 0): the matching Complex-Ack repeats the identical "object="/"property=" pair (see bacnet.cpp's
// decode_read_property_ack), so reading both sides would double-count the same operation_key twice
// per exchange -- the same reasoning S7/Modbus/EtherNet/IP already apply.
//
// has_target_range is ALWAYS false -- confirmed, not merely assumed, against the real decode: a
// BACnet object instance number is an opaque identifier (ASHRAE 135's own 22-bit instance space),
// not a linear "read this many consecutive addresses" operation the way an S7 byte_address+count or
// a DNP3 point-index start-stop is. object-type/property-name are parsed out of BacnetApdu::values'
// own "object="/"property=" entries (decode_object_property_reference, bacnet.cpp) rather than a
// new structured field: unlike DNP3's numeric range math (where a parsing mistake would corrupt
// interval union/containment checks and could produce a wrong anomaly verdict), these two strings
// only ever feed operation_key's TEXT -- a parsing miss here means a cosmetically wrong/missing key
// component, never a wrong range boundary, so the stakes don't justify a new BacnetApdu field the
// way DNP3's genuinely did. The "object="/"property=" prefixes are a fixed, single-code-path
// "key=value" token shape (not a prose summary sentence), unlike the free-text Modbus `summary`
// string this design doc's own precedent warns against scraping.
std::vector<Operation> extract_bacnet_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const BacnetFrame& bf = dp.result->as<BacnetFrame>();
    if (!bf.has_npdu || !bf.npdu.has_apdu) return ops;
    const BacnetApdu& apdu = bf.npdu.apdu;
    if (apdu.pdu_type != 0 || !apdu.has_service_choice) return ops;  // Confirmed-Request only
    // Service names are this decoder's own kBacnetConfirmedServiceChoice spelling (bacnet_tables.inc
    // -- camelCase, e.g. "readProperty"/"writeProperty", NOT the PascalCase ASHRAE clause-20 service
    // names this comment's own earlier draft assumed) -- verified against the real decode rather
    // than guessed, per this file's own review discipline.
    if (apdu.service_choice_name != "readProperty" && apdu.service_choice_name != "writeProperty") return ops;

    std::string object_type, property_name;
    for (const std::string& v : apdu.values) {
        if (v.rfind("object=", 0) == 0) {
            std::string rest = v.substr(7);
            size_t comma = rest.find(',');
            object_type = (comma == std::string::npos) ? rest : rest.substr(0, comma);
        } else if (v.rfind("property=", 0) == 0) {
            property_name = v.substr(9);
        }
    }

    Operation op;
    op.protocol = "bacnet";
    std::ostringstream key;
    key << apdu.service_choice_name;
    if (!object_type.empty()) key << "/" << object_type;
    if (!property_name.empty()) key << "/" << property_name;
    op.operation_key = key.str();
    // has_target_range stays false -- see this function's own header comment.
    ops.push_back(std::move(op));
    return ops;
}

// OPC UA: operation_key is the recognized service name alone (e.g. "ReadRequest", "WriteRequest",
// "CallRequest", "CreateSessionRequest", "BrowseRequest", ...) -- every Tier 1 AND Tier 2 recognized
// service (opcua.hpp) is recorded, not just Read/Write/Call, the same "the operation itself is still
// worth recording even without a range" posture S7 already takes for a BIT-transport-size item.
// Request side only (OpcUaServiceHeader::is_response false): a response carries only a StatusCode,
// never a NodeId to key or range on.
//
// has_target_range is ALWAYS false -- an honest call, not a forced fit (per the design doc's own
// framing): Read/Write/Call's own NodeId list is decoded by opcua.cpp's decode_read_request_params/
// decode_write_request_params/decode_call_request_params straight into OpcUaMessage::values as
// display strings ("nodes-to-read[0]=ns=2;i=1001 attribute=Value") -- there is no structured NodeId
// field on OpcUaMessage this file could read a numeric identifier back out of without parsing a
// rendered string (the same anti-pattern rejected elsewhere in this file). Even a successfully
// parsed NUMERIC NodeId identifier still wouldn't be a genuine [start,end) range the way a register
// block is: a single Read/Write targets one specific NodeId, not a COUNT of consecutive addresses,
// and a request can address several UNRELATED NodeIds in one call (an array, not a contiguous span)
// -- there's no natural "range" to build even with the number in hand, only, at best, a single-point
// interval per NodeId, which this pass does not attempt given the NodeId itself isn't reliably
// numeric in the first place (OPC UA NodeIds are legally String/Guid/ByteString identifiers too, per
// opcua.hpp's own "Primitive encoding" section).
std::vector<Operation> extract_opcua_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const OpcUaResult& our = dp.result->as<OpcUaResult>();
    const OpcUaMessage& msg = our.first;
    if (!msg.service_recognized || msg.service_name.empty()) return ops;
    if (msg.has_header && msg.header.is_response) return ops;

    Operation op;
    op.protocol = "opcua";
    op.operation_key = msg.service_name;
    // has_target_range stays false -- see this function's own header comment.
    ops.push_back(std::move(op));
    return ops;
}

// MELSEC (MC Protocol/SLMP): the device-code hex value, rendered "0x<NN>", stands in for
// operation_key's addressing dimension (mirrors S7's DB number / EtherNet/IP's class/instance) --
// MelsecDeviceSpec::device_text (e.g. "D1000") is deliberately NOT used for this: its own trailing
// device NUMBER varies per call/per device, and for hex-notated device types (X/Y/B/W/...) that
// number's own digits can include a-f, which would make stripping "the numeric suffix" back off
// device_text unreliable -- device_code is the raw, unambiguous wire value this decoder already
// computed, with no string-parsing needed at all.
//
// Full range-tracking for Batch Read (0x0401)/Batch Write (0x1401) -- confirmed against the real
// decode, exactly the design doc's own prediction: a single MelsecDeviceSpec (device_code +
// device_number) plus a real point_count is architecturally identical to S7's own byte_address+count
// shape, no unit-mismatch caveat needed (unlike S7's own BIT-transport-size exclusion): MELSEC's bit-
// type device_number is ALREADY a flat, one-per-bit address space on its own device_code (the "two
// bit values packed per byte" melsec.hpp describes is purely how the wire VALUE bytes are packed for
// a response, not how the ADDRESS is encoded -- unlike S7's own byte_address<<3|bit_offset hybrid),
// so no unit exclusion is needed here for bit-type Batch Read/Write.
//
// Every other command is key-only: Random Read (0x0403)/Random Write (0x1402) address an arbitrary,
// non-contiguous device LIST in one call (no genuine linear range at all -- the design doc only
// names Batch Read/Write as the full-range candidate), so each DISTINCT device_code seen in that
// list becomes its own key-only Operation (folding duplicates, not one per individual device_number
// -- the same "don't explode the key on a per-call address" reasoning this file's own header comment
// already applies to Modbus/S7). Remote RUN/STOP/PAUSE/LATCH-CLEAR/RESET, Read CPU Type, Remote
// Password UNLOCK/LOCK, and Echo/Loopback Test carry no device addressing at all -- recorded under
// the bare command name.
//
// Request side only (!mf.is_response): a MELSEC response frame carries no command field of its own
// on the wire (melsec.hpp's own "RESPONSE DECODING NEEDS SESSION CONTEXT" paragraph) and, even once
// session-matched, never re-carries the request's own device list -- only decoded VALUES -- so there
// is nothing address-bearing to extract from a response in the first place.
namespace {
std::string melsec_device_code_key(uint16_t code) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << code << std::dec << std::nouppercase;
    return s.str();
}
}  // namespace

std::vector<Operation> extract_melsec_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const MelsecFrame& mf = dp.result->as<MelsecFrame>();
    if (mf.is_response || !mf.has_command || !mf.command_recognized || mf.command_name.empty()) return ops;

    bool is_batch = (mf.command == 0x0401 || mf.command == 0x1401);  // Batch Read / Batch Write
    if (is_batch && mf.devices.size() == 1 && mf.has_point_count && mf.point_count > 0) {
        const MelsecDeviceSpec& d = mf.devices[0];
        Operation op;
        op.protocol = "melsec";
        op.operation_key = mf.command_name + "/" + melsec_device_code_key(d.device_code);
        op.has_target_range = true;
        op.range_start = d.device_number;
        op.range_end = d.device_number + static_cast<uint32_t>(mf.point_count);
        ops.push_back(std::move(op));
        return ops;
    }

    if (!mf.devices.empty()) {
        std::vector<uint16_t> seen_codes;
        for (const MelsecDeviceSpec& d : mf.devices) {
            if (std::find(seen_codes.begin(), seen_codes.end(), d.device_code) != seen_codes.end()) continue;
            seen_codes.push_back(d.device_code);
            Operation op;
            op.protocol = "melsec";
            op.operation_key = mf.command_name + "/" + melsec_device_code_key(d.device_code);
            ops.push_back(std::move(op));
        }
        return ops;
    }

    Operation op;
    op.protocol = "melsec";
    op.operation_key = mf.command_name;
    ops.push_back(std::move(op));
    return ops;
}

// FINS (Omron): the same device-code (here, memory area code) shape as MELSEC, rendered "0x<NN>".
// Full range-tracking for Memory Area Read (0x0101)/Memory Area Write (0x0102) -- confirmed against
// the real decode, the design doc's own prediction: a single FinsMemoryItem (area_code + address)
// plus a real point_count is architecturally identical to MELSEC's/S7's own shape -- UNLESS the item
// is bit-addressed (FinsMemoryItem::is_bit): a bit-type Memory Area Read/Write's own `address` field
// only advances once every 16 bits (bit_address rolls 0-15 within one `address` first, per fins.hpp's
// own wire layout), so `address` alone under-counts a bit-granularity range's true span the same unit-
// mismatch problem S7 already excludes its own BIT-transport-size items from range-tracking for --
// this pass applies the identical exclusion here rather than mis-model it, folding bit-type reads/
// writes into the key-only path below instead.
//
// Every other command is key-only: Memory Area Fill (0x0103) has no explicit item-count field on the
// wire at all (fins.hpp's own "COMMANDS DECODED" paragraph -- just one address + a fill pattern, no
// "how many"), so there's no count to build a range from even though addressing is otherwise
// single-item; Multiple Memory Area Read (0x0104) addresses an arbitrary, non-contiguous item LIST
// (same reasoning as MELSEC's own Random Read) -- each distinct area_code seen becomes its own
// key-only Operation, folding duplicates; every other command (Run/Stop, Controller Data/Status
// Read, Cycle Time Read, Clock Read/Write, LOOP-BACK Test, Access Right Acquire/Forced Acquire/
// Release, Error Clear, Forced Set/Reset(-Cancel)) carries no memory-area addressing at all --
// recorded under the bare command name (Forced Set/Reset's own force_entries list, a DIFFERENT
// repeating shape than `devices`, is not extracted here either, for the same "no genuine linear
// range" reasoning -- see fins.hpp's own FinsForceEntry comment).
//
// Request side only (!ff.is_response), and FINS/TCP envelope-only messages (the Node Address Data
// Send handshake / Frame Send Error Notification / Connection Confirmation -- ff.is_tcp_envelope_only)
// are excluded outright: they carry no inner FINS command/response frame at all (fins.hpp's own
// comment), so command/command_name/devices are all meaningless for one.
std::vector<Operation> extract_fins_operations(const DecodedPacket& dp) {
    std::vector<Operation> ops;
    if (!dp.result) return ops;
    const FinsFrame& ff = dp.result->as<FinsFrame>();
    if (ff.is_response || ff.is_tcp_envelope_only || !ff.command_recognized || ff.command_name.empty()) return ops;

    bool is_single_area_rw = (ff.command == 0x0101 || ff.command == 0x0102);  // Memory Area Read/Write
    if (is_single_area_rw && ff.devices.size() == 1 && ff.has_point_count && ff.point_count > 0 &&
        !ff.devices[0].is_bit) {
        const FinsMemoryItem& d = ff.devices[0];
        Operation op;
        op.protocol = "fins";
        std::ostringstream key;
        key << ff.command_name << "/0x" << std::hex << std::uppercase << static_cast<unsigned>(d.area_code)
            << std::dec << std::nouppercase;
        op.operation_key = key.str();
        op.has_target_range = true;
        op.range_start = d.address;
        op.range_end = static_cast<uint32_t>(d.address) + static_cast<uint32_t>(ff.point_count);
        ops.push_back(std::move(op));
        return ops;
    }

    if (!ff.devices.empty()) {
        std::vector<uint8_t> seen_codes;
        for (const FinsMemoryItem& d : ff.devices) {
            if (std::find(seen_codes.begin(), seen_codes.end(), d.area_code) != seen_codes.end()) continue;
            seen_codes.push_back(d.area_code);
            Operation op;
            op.protocol = "fins";
            std::ostringstream key;
            key << ff.command_name << "/0x" << std::hex << std::uppercase << static_cast<unsigned>(d.area_code)
                << std::dec << std::nouppercase;
            op.operation_key = key.str();
            ops.push_back(std::move(op));
        }
        return ops;
    }

    Operation op;
    op.protocol = "fins";
    op.operation_key = ff.command_name;
    ops.push_back(std::move(op));
    return ops;
}

}  // namespace

std::vector<Operation> extract_operations(const DecodedPacket& packet) {
    if (packet.protocol == "modbus") return extract_modbus_operations(packet);
    if (packet.protocol == "s7comm") return extract_s7comm_operations(packet);
    if (packet.protocol == "enip") return extract_enip_operations(packet);
    if (packet.protocol == "dnp3") return extract_dnp3_operations(packet);
    if (packet.protocol == "bacnet") return extract_bacnet_operations(packet);
    if (packet.protocol == "opcua") return extract_opcua_operations(packet);
    if (packet.protocol == "melsec") return extract_melsec_operations(packet);
    if (packet.protocol == "fins") return extract_fins_operations(packet);
    return {};
}

// --------------------------------------------------------------------------------------------
// Interval merge-on-insert -- see OperationBaseline::observed_ranges' own comment (baseline.hpp).
// --------------------------------------------------------------------------------------------

// Merges half-open range `r` into the already-sorted, already-coalesced `ranges`, keeping it
// sorted and coalesced (adjacent or overlapping intervals combined into one). Linear scan, per the
// design doc: a handful of intervals per operation in practice, so no interval tree is needed here.
void merge_range_into(std::vector<std::pair<uint32_t, uint32_t>>& ranges, std::pair<uint32_t, uint32_t> r) {
    if (r.first >= r.second) return;  // empty/invalid range -- nothing to add
    ranges.push_back(r);
    std::sort(ranges.begin(), ranges.end());
    std::vector<std::pair<uint32_t, uint32_t>> merged;
    merged.reserve(ranges.size());
    for (const auto& cur : ranges) {
        // "<=" (not "<") so touching intervals coalesce too, e.g. [0,10) and [10,20) -> [0,20) --
        // see OperationBaseline::observed_ranges' own "coalesce adjacent/overlapping" comment.
        if (!merged.empty() && cur.first <= merged.back().second) {
            merged.back().second = std::max(merged.back().second, cur.second);
        } else {
            merged.push_back(cur);
        }
    }
    ranges = std::move(merged);
}

// True iff [start, end) is fully contained in one single entry of `ranges` -- since `ranges` is
// always already coalesced (merge_range_into's own invariant), a range spanning what were once two
// adjacent/overlapping baseline observations has already been merged into one entry, so checking
// each entry independently (rather than trying to union multiple entries together here) is
// sufficient and correct.
bool range_fully_covered(const std::vector<std::pair<uint32_t, uint32_t>>& ranges, uint32_t start, uint32_t end) {
    for (const auto& r : ranges) {
        if (r.first <= start && end <= r.second) return true;
    }
    return false;
}

// --------------------------------------------------------------------------------------------
// BaselineEngine -- per-capture observation, mirroring PolicyEngine::observe/
// AssetInventoryEngine::observe's own TCP-session client/server determination (see
// BaselineEngine::observe's own doc comment, baseline.hpp, for why this is reimplemented here
// rather than shared).
// --------------------------------------------------------------------------------------------

namespace {

std::string tcp_session_key(const std::string& ip_a, uint16_t port_a, const std::string& ip_b, uint16_t port_b) {
    std::string ea = ip_a + ":" + std::to_string(port_a);
    std::string eb = ip_b + ":" + std::to_string(port_b);
    return (ea < eb) ? (ea + "<->" + eb) : (eb + "<->" + ea);
}

std::string conduit_key(const std::string& protocol, const std::string& client_ip, const std::string& server_ip,
                         uint16_t server_port) {
    return protocol + "|" + client_ip + "->" + server_ip + ":" + std::to_string(server_port);
}

// This feature's own known ports -- Modbus/TCP, COTP (S7comm's own transport), and, as of Phase 2
// (roadmap item 41), the six protocols added there -- the narrowed version of PolicyEngine::
// observe's/AssetInventoryEngine::observe's own is_known_service_port, restricted to the protocols
// this engine ever extracts operations from. FINS_TCP_PORT/FINS_UDP_PORT are numerically identical
// (9600, see fins.hpp) -- listed both for clarity, not because it matters which one C++ compares.
bool is_known_baseline_port(uint16_t port) {
    return port == MODBUS_TCP_PORT || port == COTP_TCP_PORT || port == ENIP_TCP_PORT || port == DNP3_TCP_PORT ||
           port == OPCUA_PORT || port == MELSEC_TCP_PORT || port == MELSEC_UDP_PORT || port == FINS_TCP_PORT ||
           port == FINS_UDP_PORT || port == BACNET_UDP_PORT;
}

bool src_is_client_by_port(uint16_t src_port, uint16_t dst_port) {
    bool src_known = is_known_baseline_port(src_port);
    bool dst_known = is_known_baseline_port(dst_port);
    if (dst_known && !src_known) return true;
    if (src_known && !dst_known) return false;
    return src_port > dst_port;
}

// True for every protocol this engine ever extracts operations from -- S7comm/Modbus (Phase 1) plus
// the six added in Phase 2 (roadmap item 41, docs/design/baseline-engine.md).
bool is_baseline_protocol(const std::string& protocol) {
    return protocol == "modbus" || protocol == "s7comm" || protocol == "enip" || protocol == "dnp3" ||
           protocol == "bacnet" || protocol == "opcua" || protocol == "melsec" || protocol == "fins";
}

}  // namespace

void BaselineEngine::observe(const DecodedPacket& dp) {
    if (!dp.has_ip || (!dp.has_tcp && !dp.has_udp)) return;
    if (!is_baseline_protocol(dp.protocol)) return;

    std::vector<Operation> ops = extract_operations(dp);
    if (ops.empty()) return;

    std::string client_ip, server_ip;
    uint16_t server_port = 0;

    if (dp.has_tcp) {
        // Client/server direction: SYN/SYN-ACK first, known-port fallback otherwise -- see this
        // method's own doc comment (baseline.hpp) for why this mirrors PolicyEngine::observe/
        // AssetInventoryEngine::observe rather than sharing code with either.
        std::string skey = tcp_session_key(dp.src_ip, dp.src_port, dp.dst_ip, dp.dst_port);
        bool is_syn = dp.tcp_flags == "SYN";
        bool is_syn_ack = dp.tcp_flags.rfind("SYN,ACK", 0) == 0;

        auto sit = tcp_sessions_.find(skey);
        if (sit == tcp_sessions_.end()) {
            TcpSessionState st;
            bool src_is_client;
            if (is_syn) {
                src_is_client = true;
                st.initiator_known = true;
            } else if (is_syn_ack) {
                src_is_client = false;
                st.initiator_known = true;
            } else {
                src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
            }
            st.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            st.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            st.server_port = src_is_client ? dp.dst_port : dp.src_port;
            sit = tcp_sessions_.emplace(skey, std::move(st)).first;
        } else if (!sit->second.initiator_known && (is_syn || is_syn_ack)) {
            bool src_is_client = is_syn;
            sit->second.client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
            sit->second.server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
            sit->second.server_port = src_is_client ? dp.dst_port : dp.src_port;
            sit->second.initiator_known = true;
        }
        client_ip = sit->second.client_ip;
        server_ip = sit->second.server_ip;
        server_port = sit->second.server_port;
    } else {
        // UDP (BACnet -- the only one of the eight protocols with no TCP form at all -- plus FINS/
        // MELSEC, which can run over either transport): no session, no handshake, so there is no
        // SYN to key direction off. BACnet's own APDU carries a genuine content-based signal
        // instead (a Confirmed-Request/Unconfirmed-Request PDU type is unambiguously the client
        // side) -- mirrors AssetInventoryEngine::observe's own identical BACnet-UDP handling
        // (asset_inventory.cpp) rather than inventing a second convention for the same decision.
        // Every other UDP packet here falls back to the same known-port heuristic the TCP side
        // above uses when it never saw a SYN/SYN-ACK either.
        //
        // Deliberately does NOT reuse AssetInventoryEngine::observe's own broadcast/multicast
        // filter (looks_like_broadcast_or_multicast, asset_inventory.cpp): a real Confirmed-Request
        // readProperty/writeProperty is unicast in practice (bacnet.hpp's own "Original-Unicast-NPDU
        // is by far the most common" note), so this scoping difference has no real-world effect on
        // the only two BACnet operations this file ever extracts -- and excluding it here keeps this
        // engine's UDP conduit tracking a plain mirror of its own TCP tracking (record whatever
        // client/server pair the wire shows), the same "engine only ever compares what's on the
        // wire, never applies a second judgment call the way inventory's zone-aware asset model
        // does" posture this file's own header comment already takes for conduit identity.
        bool src_is_client;
        const BacnetFrame* bf = (dp.protocol == "bacnet" && dp.result) ? &dp.result->as<BacnetFrame>() : nullptr;
        if (bf && bf->has_npdu && bf->npdu.has_apdu && !bf->npdu.apdu.pdu_type_name.empty()) {
            const std::string& apdu_type = bf->npdu.apdu.pdu_type_name;
            src_is_client = apdu_type == "Confirmed-Request" || apdu_type == "Unconfirmed-Request";
        } else {
            src_is_client = src_is_client_by_port(dp.src_port, dp.dst_port);
        }
        client_ip = src_is_client ? dp.src_ip : dp.dst_ip;
        server_ip = src_is_client ? dp.dst_ip : dp.src_ip;
        server_port = src_is_client ? dp.dst_port : dp.src_port;
    }

    std::string ckey = conduit_key(dp.protocol, client_ip, server_ip, server_port);
    auto cit = conduits_.find(ckey);
    if (cit == conduits_.end()) {
        ConduitState cs;
        cs.client_ip = client_ip;
        cs.server_ip = server_ip;
        cs.protocol = dp.protocol;
        cs.server_port = server_port;
        conduit_order_.push_back(ckey);
        cit = conduits_.emplace(ckey, std::move(cs)).first;
    }
    ConduitState& cs = cit->second;
    ++cs.packet_count;

    for (const Operation& op : ops) {
        auto oit = cs.operations.find(op.operation_key);
        if (oit == cs.operations.end()) {
            cs.operation_order.push_back(op.operation_key);
            oit = cs.operations.emplace(op.operation_key, OperationState{}).first;
        }
        OperationState& os = oit->second;
        ++os.packet_count;
        if (op.has_target_range) {
            os.has_target_range = true;
            merge_range_into(os.observed_ranges, {op.range_start, op.range_end});
        }
        if (!op.s7_range_unit.empty()) {
            os.s7_area_letter = op.s7_area_letter;
            os.s7_db_number = op.s7_db_number;
            os.s7_range_unit = op.s7_range_unit;
        }
    }
}

std::vector<ConduitBaseline> BaselineEngine::finish() const {
    std::vector<ConduitBaseline> result;
    result.reserve(conduit_order_.size());
    for (const auto& ckey : conduit_order_) {
        const ConduitState& cs = conduits_.at(ckey);
        ConduitBaseline cb;
        cb.client_ip = cs.client_ip;
        cb.server_ip = cs.server_ip;
        cb.protocol = cs.protocol;
        cb.server_port = cs.server_port;
        cb.packet_count = cs.packet_count;
        for (const auto& okey : cs.operation_order) {
            const OperationState& os = cs.operations.at(okey);
            OperationBaseline ob;
            ob.operation_key = okey;
            ob.packet_count = os.packet_count;
            ob.has_target_range = os.has_target_range;
            ob.observed_ranges = os.observed_ranges;
            ob.s7_area_letter = os.s7_area_letter;
            ob.s7_db_number = os.s7_db_number;
            ob.s7_range_unit = os.s7_range_unit;
            cb.operations.push_back(std::move(ob));
        }
        result.push_back(std::move(cb));
    }
    return result;
}

// --------------------------------------------------------------------------------------------
// merge_baseline_observations() -- `learn`'s own merge-into-store logic (baseline.hpp).
// --------------------------------------------------------------------------------------------

namespace {

// Finds `key`'s ConduitBaseline inside `store.conduits`, or nullptr -- linear scan (a real
// baseline file has, in practice, a handful to a few dozen conduits, matching every other engine's
// own "linear scan is fine at this scale" posture in this codebase).
ConduitBaseline* find_conduit(BaselineStore& store, const std::string& client_ip, const std::string& server_ip,
                               const std::string& protocol, uint16_t server_port) {
    for (auto& c : store.conduits) {
        if (c.client_ip == client_ip && c.server_ip == server_ip && c.protocol == protocol &&
            c.server_port == server_port) {
            return &c;
        }
    }
    return nullptr;
}

const ConduitBaseline* find_conduit_const(const BaselineStore& store, const std::string& client_ip,
                                           const std::string& server_ip, const std::string& protocol,
                                           uint16_t server_port) {
    for (const auto& c : store.conduits) {
        if (c.client_ip == client_ip && c.server_ip == server_ip && c.protocol == protocol &&
            c.server_port == server_port) {
            return &c;
        }
    }
    return nullptr;
}

OperationBaseline* find_operation(ConduitBaseline& conduit, const std::string& operation_key) {
    for (auto& op : conduit.operations) {
        if (op.operation_key == operation_key) return &op;
    }
    return nullptr;
}

const OperationBaseline* find_operation_const(const ConduitBaseline& conduit, const std::string& operation_key) {
    for (const auto& op : conduit.operations) {
        if (op.operation_key == operation_key) return &op;
    }
    return nullptr;
}

}  // namespace

void merge_baseline_observations(BaselineStore& store, const std::vector<ConduitBaseline>& observed,
                                  const std::string& capture_filename) {
    for (const ConduitBaseline& obs_conduit : observed) {
        ConduitBaseline* conduit =
            find_conduit(store, obs_conduit.client_ip, obs_conduit.server_ip, obs_conduit.protocol,
                         obs_conduit.server_port);
        if (!conduit) {
            ConduitBaseline fresh;
            fresh.client_ip = obs_conduit.client_ip;
            fresh.server_ip = obs_conduit.server_ip;
            fresh.protocol = obs_conduit.protocol;
            fresh.server_port = obs_conduit.server_port;
            fresh.first_seen_capture = capture_filename;
            store.conduits.push_back(std::move(fresh));
            conduit = &store.conduits.back();
        }
        conduit->packet_count += obs_conduit.packet_count;
        conduit->last_seen_capture = capture_filename;

        for (const OperationBaseline& obs_op : obs_conduit.operations) {
            OperationBaseline* op = find_operation(*conduit, obs_op.operation_key);
            if (!op) {
                OperationBaseline fresh_op;
                fresh_op.operation_key = obs_op.operation_key;
                conduit->operations.push_back(std::move(fresh_op));
                op = &conduit->operations.back();
            }
            op->packet_count += obs_op.packet_count;
            if (obs_op.has_target_range) {
                op->has_target_range = true;
                for (const auto& r : obs_op.observed_ranges) {
                    merge_range_into(op->observed_ranges, r);
                }
            }
        }
    }
}

// --------------------------------------------------------------------------------------------
// check_baseline() -- `check`'s own comparison logic (baseline.hpp).
// --------------------------------------------------------------------------------------------

const char* baseline_verdict_name(BaselineVerdict verdict) {
    switch (verdict) {
        case BaselineVerdict::KnownOperation: return "known-operation";
        case BaselineVerdict::NewConduit: return "new-conduit";
        case BaselineVerdict::NewOperation: return "new-operation";
        case BaselineVerdict::NewTargetRange: return "new-target-range";
    }
    return "known-operation";
}

BaselineCheckReport check_baseline(const BaselineStore& baseline, const std::vector<ConduitBaseline>& observed,
                                    const std::string& capture_path) {
    BaselineCheckReport report;
    report.capture_path = capture_path;
    report.conduits_observed = observed.size();

    for (const ConduitBaseline& obs_conduit : observed) {
        const ConduitBaseline* base_conduit = find_conduit_const(
            baseline, obs_conduit.client_ip, obs_conduit.server_ip, obs_conduit.protocol, obs_conduit.server_port);

        for (const OperationBaseline& obs_op : obs_conduit.operations) {
            ++report.operations_observed;
            const OperationBaseline* base_op =
                base_conduit ? find_operation_const(*base_conduit, obs_op.operation_key) : nullptr;

            BaselineVerdict verdict;
            // For NewTargetRange specifically, track only the sub-range(s) of THIS capture's own
            // observed_ranges that the baseline does NOT already cover -- not the outer bounds of
            // every observed sub-range (covered or not). A single operation_key can legitimately
            // have observed several disjoint ranges in one capture (e.g. one already-known range
            // plus one genuinely new one, exactly the scenario
            // sample_baseline_modbus_mutated.pcap's own packet 3 exercises); reporting the union of
            // ALL of them, covered or not, would claim bytes were "observed" that this capture
            // never actually touched (the gap between two disjoint ranges). uncovered_start/end
            // instead only ever widens across ranges that individually failed
            // range_fully_covered, so the report says exactly what wasn't already known -- nothing
            // more.
            bool any_uncovered = false;
            uint32_t uncovered_start = 0, uncovered_end = 0;
            if (!base_conduit) {
                verdict = BaselineVerdict::NewConduit;
            } else if (!base_op) {
                verdict = BaselineVerdict::NewOperation;
            } else if (obs_op.has_target_range) {
                for (const auto& r : obs_op.observed_ranges) {
                    if (!range_fully_covered(base_op->observed_ranges, r.first, r.second)) {
                        if (!any_uncovered) {
                            uncovered_start = r.first;
                            uncovered_end = r.second;
                            any_uncovered = true;
                        } else {
                            uncovered_start = std::min(uncovered_start, r.first);
                            uncovered_end = std::max(uncovered_end, r.second);
                        }
                    }
                }
                verdict = any_uncovered ? BaselineVerdict::NewTargetRange : BaselineVerdict::KnownOperation;
            } else {
                verdict = BaselineVerdict::KnownOperation;
            }

            if (verdict == BaselineVerdict::KnownOperation) {
                ++report.known_operation_count;
                continue;
            }

            BaselineFinding finding;
            finding.verdict = verdict;
            finding.client_ip = obs_conduit.client_ip;
            finding.server_ip = obs_conduit.server_ip;
            finding.protocol = obs_conduit.protocol;
            finding.server_port = obs_conduit.server_port;
            finding.operation_key = obs_op.operation_key;
            finding.packet_count = obs_op.packet_count;
            // Sourced from obs_op (the checked capture's own freshly-extracted operation), never
            // from base_op/the loaded baseline file -- see Operation::s7_area_letter's own comment
            // (baseline.hpp) for why. Harmless no-op for every non-S7comm finding (obs_op.
            // s7_range_unit stays "" there, and only s7comm findings are ever rendered with it).
            finding.s7_area_letter = obs_op.s7_area_letter;
            finding.s7_db_number = obs_op.s7_db_number;
            finding.s7_range_unit = obs_op.s7_range_unit;
            if (verdict == BaselineVerdict::NewTargetRange) {
                finding.observed_start = uncovered_start;
                finding.observed_end = uncovered_end;
                // baseline_ranges gives the reader what the baseline already had, for context, so
                // they can see how far outside it this capture went.
                finding.baseline_ranges = base_op->observed_ranges;
            }
            report.findings.push_back(std::move(finding));
        }
    }
    return report;
}

// --------------------------------------------------------------------------------------------
// JSON (de)serialization -- a small, purpose-built writer/reader for exactly the BaselineStore
// schema above, not a general JSON library: this codebase has none (CLI11 is the only vendored
// third-party code, see CMakeLists.txt), and a full general-purpose JSON parser is not necessary
// for a schema this simple and fixed-shape -- the same "purpose-built, not general" posture
// yaml_mini.hpp/yaml_mini.cpp already take for the policy YAML file, just for JSON instead of YAML
// (this baseline file's own persisted format, per the design doc, rather than reusing the YAML
// subset the policy file uses -- a baseline is generated/diffed data, not hand-authored config, so
// JSON's own "the writer and reader agree on one exact shape" fit is a better match here than
// YAML's more permissive, human-authoring-oriented syntax).
// --------------------------------------------------------------------------------------------

namespace {

std::string json_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '"': out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            case '\t': out += "\\t"; break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    std::snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

}  // namespace

void write_baseline_store_json(std::ostream& out, const BaselineStore& store) {
    out << "{\n";
    out << "  \"schema_version\": " << store.schema_version << ",\n";
    out << "  \"conduits\": [\n";
    for (size_t i = 0; i < store.conduits.size(); ++i) {
        const ConduitBaseline& c = store.conduits[i];
        out << "    {\n";
        out << "      \"client_ip\": \"" << json_escape(c.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(c.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(c.protocol) << "\",\n";
        out << "      \"server_port\": " << c.server_port << ",\n";
        out << "      \"packet_count\": " << c.packet_count << ",\n";
        out << "      \"first_seen_capture\": \"" << json_escape(c.first_seen_capture) << "\",\n";
        out << "      \"last_seen_capture\": \"" << json_escape(c.last_seen_capture) << "\",\n";
        out << "      \"operations\": [\n";
        for (size_t j = 0; j < c.operations.size(); ++j) {
            const OperationBaseline& op = c.operations[j];
            out << "        {\n";
            out << "          \"operation_key\": \"" << json_escape(op.operation_key) << "\",\n";
            out << "          \"packet_count\": " << op.packet_count << ",\n";
            out << "          \"has_target_range\": " << (op.has_target_range ? "true" : "false") << ",\n";
            out << "          \"observed_ranges\": [";
            for (size_t k = 0; k < op.observed_ranges.size(); ++k) {
                if (k) out << ", ";
                out << "[" << op.observed_ranges[k].first << ", " << op.observed_ranges[k].second << "]";
            }
            out << "]\n";
            out << "        }" << (j + 1 < c.operations.size() ? "," : "") << "\n";
        }
        out << "      ]\n";
        out << "    }" << (i + 1 < store.conduits.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

namespace {

// A tiny hand-rolled JSON reader, purpose-built for exactly write_baseline_store_json's own output
// shape above -- not a general JSON parser (no comments, no unicode surrogate-pair escapes beyond
// what's needed to round-trip json_escape's own output, no tolerance for a document that doesn't
// match this exact schema). Throws BaselineStoreError with a byte-offset-free but otherwise
// human-readable message on anything unexpected -- this file is a generated artifact meant to be
// diffed, not hand-edited, so a precise line/column tracker (the way yaml_mini.hpp's own parser has
// for the hand-authored policy file) isn't worth the complexity here.
class JsonCursor {
public:
    explicit JsonCursor(const std::string& text) : text_(text) {}

    void skip_ws() {
        while (pos_ < text_.size() && std::isspace(static_cast<unsigned char>(text_[pos_]))) ++pos_;
    }

    char peek() {
        skip_ws();
        return pos_ < text_.size() ? text_[pos_] : '\0';
    }

    void expect(char c) {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != c) {
            fail(std::string("expected '") + c + "'");
        }
        ++pos_;
    }

    // True and consumes `c` if it's next (after whitespace); false and consumes nothing otherwise.
    bool consume_if(char c) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    std::string parse_string() {
        skip_ws();
        if (pos_ >= text_.size() || text_[pos_] != '"') fail("expected a string");
        ++pos_;
        std::string out;
        while (true) {
            if (pos_ >= text_.size()) fail("unterminated string");
            char c = text_[pos_++];
            if (c == '"') break;
            if (c == '\\') {
                if (pos_ >= text_.size()) fail("unterminated string escape");
                char esc = text_[pos_++];
                switch (esc) {
                    case '"': out += '"'; break;
                    case '\\': out += '\\'; break;
                    case '/': out += '/'; break;
                    case 'n': out += '\n'; break;
                    case 'r': out += '\r'; break;
                    case 't': out += '\t'; break;
                    case 'u': {
                        if (pos_ + 4 > text_.size()) fail("truncated \\u escape");
                        unsigned code = 0;
                        for (int i = 0; i < 4; ++i) {
                            char h = text_[pos_++];
                            code <<= 4;
                            if (h >= '0' && h <= '9') code |= static_cast<unsigned>(h - '0');
                            else if (h >= 'a' && h <= 'f') code |= static_cast<unsigned>(h - 'a' + 10);
                            else if (h >= 'A' && h <= 'F') code |= static_cast<unsigned>(h - 'A' + 10);
                            else fail("invalid \\u escape digit");
                        }
                        // Only the control-character range write_baseline_store_json's own
                        // json_escape ever emits via \u -- a plain byte-for-byte reproduction is
                        // enough here, no UTF-16 surrogate-pair decoding.
                        out += static_cast<char>(code & 0xFF);
                        break;
                    }
                    default: fail("unrecognized string escape");
                }
            } else {
                out += c;
            }
        }
        return out;
    }

    long long parse_integer() {
        skip_ws();
        size_t start = pos_;
        if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
        size_t digits_start = pos_;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
        if (pos_ == digits_start) fail("expected a number");
        return std::stoll(text_.substr(start, pos_ - start));
    }

    bool parse_bool() {
        skip_ws();
        if (text_.compare(pos_, 4, "true") == 0) {
            pos_ += 4;
            return true;
        }
        if (text_.compare(pos_, 5, "false") == 0) {
            pos_ += 5;
            return false;
        }
        fail("expected true or false");
        return false;  // unreachable
    }

    [[noreturn]] void fail(const std::string& what) {
        throw BaselineStoreError("baseline file: malformed JSON (" + what + ", at byte offset " +
                                  std::to_string(pos_) + ")");
    }

private:
    const std::string& text_;
    size_t pos_ = 0;
};

std::vector<std::pair<uint32_t, uint32_t>> parse_ranges(JsonCursor& c) {
    std::vector<std::pair<uint32_t, uint32_t>> ranges;
    c.expect('[');
    if (c.consume_if(']')) return ranges;
    while (true) {
        c.expect('[');
        auto a = c.parse_integer();
        c.expect(',');
        auto b = c.parse_integer();
        c.expect(']');
        ranges.emplace_back(static_cast<uint32_t>(a), static_cast<uint32_t>(b));
        if (c.consume_if(',')) continue;
        c.expect(']');
        break;
    }
    return ranges;
}

OperationBaseline parse_operation(JsonCursor& c) {
    OperationBaseline op;
    bool have_key = false, have_packet_count = false, have_has_range = false, have_ranges = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "operation_key") {
                op.operation_key = c.parse_string();
                have_key = true;
            } else if (key == "packet_count") {
                op.packet_count = static_cast<size_t>(c.parse_integer());
                have_packet_count = true;
            } else if (key == "has_target_range") {
                op.has_target_range = c.parse_bool();
                have_has_range = true;
            } else if (key == "observed_ranges") {
                op.observed_ranges = parse_ranges(c);
                have_ranges = true;
            } else {
                c.fail("unrecognized operation field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_key || !have_packet_count || !have_has_range || !have_ranges) {
        c.fail("operation object missing a required field (operation_key/packet_count/"
               "has_target_range/observed_ranges)");
    }
    return op;
}

ConduitBaseline parse_conduit(JsonCursor& c) {
    ConduitBaseline conduit;
    bool have_client = false, have_server = false, have_protocol = false, have_port = false,
         have_packet_count = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "client_ip") {
                conduit.client_ip = c.parse_string();
                have_client = true;
            } else if (key == "server_ip") {
                conduit.server_ip = c.parse_string();
                have_server = true;
            } else if (key == "protocol") {
                conduit.protocol = c.parse_string();
                have_protocol = true;
            } else if (key == "server_port") {
                conduit.server_port = static_cast<uint16_t>(c.parse_integer());
                have_port = true;
            } else if (key == "packet_count") {
                conduit.packet_count = static_cast<size_t>(c.parse_integer());
                have_packet_count = true;
            } else if (key == "first_seen_capture") {
                conduit.first_seen_capture = c.parse_string();
            } else if (key == "last_seen_capture") {
                conduit.last_seen_capture = c.parse_string();
            } else if (key == "operations") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        conduit.operations.push_back(parse_operation(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else {
                c.fail("unrecognized conduit field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_client || !have_server || !have_protocol || !have_port || !have_packet_count) {
        c.fail("conduit object missing a required field (client_ip/server_ip/protocol/server_port/"
               "packet_count)");
    }
    return conduit;
}

}  // namespace

BaselineStore parse_baseline_store_json(const std::string& text) {
    JsonCursor c(text);
    BaselineStore store;
    bool have_schema_version = false, have_conduits = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "schema_version") {
                store.schema_version = static_cast<int>(c.parse_integer());
                have_schema_version = true;
            } else if (key == "conduits") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        store.conduits.push_back(parse_conduit(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
                have_conduits = true;
            } else {
                c.fail("unrecognized top-level field '" + key + "'");
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_schema_version || !have_conduits) {
        c.fail("missing required top-level field (schema_version/conduits)");
    }
    if (store.schema_version != 1) {
        throw BaselineStoreError("baseline file: unrecognized schema_version " +
                                  std::to_string(store.schema_version) + " (this build only understands 1)");
    }
    return store;
}

// --------------------------------------------------------------------------------------------
// load/save -- file I/O around the (de)serialization above.
// --------------------------------------------------------------------------------------------

BaselineStore load_baseline_store(const std::string& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        // "reads the file if present" -- a missing file is a fresh, empty baseline, not an error
        // (see this function's own comment, baseline.hpp).
        return BaselineStore{};
    }
    std::ostringstream buf;
    buf << in.rdbuf();
    if (!in.good() && !in.eof()) {
        throw BaselineStoreError("baseline file '" + path + "': read error");
    }
    return parse_baseline_store_json(buf.str());
}

void save_baseline_store(const std::string& path, const BaselineStore& store) {
    std::ofstream out(path, std::ios::binary | std::ios::trunc);
    if (!out) {
        throw BaselineStoreError("baseline file '" + path + "': cannot open for writing");
    }
    write_baseline_store_json(out, store);
    if (!out) {
        throw BaselineStoreError("baseline file '" + path + "': write error");
    }
}

// --------------------------------------------------------------------------------------------
// check report rendering -- mirrors write_policy_report_text/_json's own conventions (see this
// file's own header comment, baseline.hpp).
// --------------------------------------------------------------------------------------------

namespace {

std::string ranges_text(const std::vector<std::pair<uint32_t, uint32_t>>& ranges) {
    std::ostringstream out;
    for (size_t i = 0; i < ranges.size(); ++i) {
        if (i) out << ", ";
        out << "[" << ranges[i].first << ", " << ranges[i].second << ")";
    }
    if (ranges.empty()) out << "(none)";
    return out.str();
}

// True only for an S7comm finding whose s7_range_unit was actually populated -- i.e. an area code
// extract_s7comm_operations recognized (s7_area_letter_for_code returned non-empty). An S7comm
// finding CAN reach here with s7_range_unit empty (has_target_range false, e.g. a NewOperation on an
// operation_key with no range concept at all -- PLC Stop, Setup Communication, ...), and this must
// silently render nothing extra for that case, not an empty/garbled notation string.
bool has_s7_symbolic_notation(const BaselineFinding& f) {
    return f.protocol == "s7comm" && !f.s7_range_unit.empty();
}

// Same "(none)"-vs-comma-joined shape as ranges_text above, but rendering each sub-range through
// s7_range_notation (s7comm.hpp) instead of raw numbers -- --symbolic-addresses' own baseline_ranges
// rendering.
std::string ranges_text_symbolic(const BaselineFinding& f) {
    std::ostringstream out;
    for (size_t i = 0; i < f.baseline_ranges.size(); ++i) {
        if (i) out << ", ";
        out << s7_range_notation(f.s7_area_letter, f.s7_db_number, f.s7_range_unit, f.baseline_ranges[i].first,
                                  f.baseline_ranges[i].second);
    }
    if (f.baseline_ranges.empty()) out << "(none)";
    return out.str();
}

}  // namespace

void write_baseline_check_report_text(std::ostream& out, const BaselineCheckReport& report,
                                       bool symbolic_addresses) {
    out << "ICS communication-baseline check\n";
    out << "  capture: " << report.capture_path << "\n\n";

    out << "Result: " << (report.compliant() ? "CLEAN" : "ANOMALIES FOUND");
    if (!report.compliant()) {
        out << " (" << report.findings.size() << " finding(s))";
    }
    out << "\n\n";

    out << report.conduits_observed << " conduit(s) observed, " << report.operations_observed
        << " distinct operation(s) observed, " << report.known_operation_count
        << " matched the baseline, " << report.findings.size() << " did not\n\n";

    out << "FINDINGS (" << report.findings.size() << "):\n";
    if (report.findings.empty()) {
        out << "  (none)\n";
    }
    for (size_t i = 0; i < report.findings.size(); ++i) {
        const BaselineFinding& f = report.findings[i];
        out << "  [" << (i + 1) << "] " << baseline_verdict_name(f.verdict) << "  " << f.client_ip << " -> "
            << f.server_ip << ":" << f.server_port << "  " << f.protocol << "  operation=\"" << f.operation_key
            << "\"  (" << f.packet_count << " packet(s))\n";
        if (f.verdict == BaselineVerdict::NewTargetRange) {
            out << "      observed range: [" << f.observed_start << ", " << f.observed_end << ")\n";
            if (symbolic_addresses && has_s7_symbolic_notation(f)) {
                out << "      observed range (symbolic): "
                    << s7_range_notation(f.s7_area_letter, f.s7_db_number, f.s7_range_unit, f.observed_start,
                                          f.observed_end)
                    << "\n";
            }
            out << "      baseline ranges: " << ranges_text(f.baseline_ranges) << "\n";
            if (symbolic_addresses && has_s7_symbolic_notation(f)) {
                out << "      baseline ranges (symbolic): " << ranges_text_symbolic(f) << "\n";
            }
        }
    }
}

void write_baseline_check_report_json(std::ostream& out, const BaselineCheckReport& report,
                                       bool symbolic_addresses) {
    out << "{\n";
    out << "  \"capture\": \"" << json_escape(report.capture_path) << "\",\n";
    out << "  \"compliant\": " << (report.compliant() ? "true" : "false") << ",\n";
    out << "  \"conduits_observed\": " << report.conduits_observed << ",\n";
    out << "  \"operations_observed\": " << report.operations_observed << ",\n";
    out << "  \"known_operation_count\": " << report.known_operation_count << ",\n";
    out << "  \"findings\": [\n";
    for (size_t i = 0; i < report.findings.size(); ++i) {
        const BaselineFinding& f = report.findings[i];
        out << "    {\n";
        out << "      \"verdict\": \"" << baseline_verdict_name(f.verdict) << "\",\n";
        out << "      \"client_ip\": \"" << json_escape(f.client_ip) << "\",\n";
        out << "      \"server_ip\": \"" << json_escape(f.server_ip) << "\",\n";
        out << "      \"protocol\": \"" << json_escape(f.protocol) << "\",\n";
        out << "      \"server_port\": " << f.server_port << ",\n";
        out << "      \"operation_key\": \"" << json_escape(f.operation_key) << "\",\n";
        if (f.verdict == BaselineVerdict::NewTargetRange) {
            out << "      \"observed_start\": " << f.observed_start << ",\n";
            out << "      \"observed_end\": " << f.observed_end << ",\n";
            if (symbolic_addresses && has_s7_symbolic_notation(f)) {
                out << "      \"observed_range_symbolic\": \""
                    << json_escape(s7_range_notation(f.s7_area_letter, f.s7_db_number, f.s7_range_unit,
                                                       f.observed_start, f.observed_end))
                    << "\",\n";
            }
            out << "      \"baseline_ranges\": [";
            for (size_t k = 0; k < f.baseline_ranges.size(); ++k) {
                if (k) out << ", ";
                out << "[" << f.baseline_ranges[k].first << ", " << f.baseline_ranges[k].second << "]";
            }
            out << "],\n";
            if (symbolic_addresses && has_s7_symbolic_notation(f)) {
                out << "      \"baseline_ranges_symbolic\": [";
                for (size_t k = 0; k < f.baseline_ranges.size(); ++k) {
                    if (k) out << ", ";
                    out << "\""
                        << json_escape(s7_range_notation(f.s7_area_letter, f.s7_db_number, f.s7_range_unit,
                                                           f.baseline_ranges[k].first, f.baseline_ranges[k].second))
                        << "\"";
                }
                out << "],\n";
            }
        }
        out << "      \"packet_count\": " << f.packet_count << "\n";
        out << "    }" << (i + 1 < report.findings.size() ? "," : "") << "\n";
    }
    out << "  ]\n";
    out << "}\n";
}

}  // namespace conduitscope
