// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/s7commplus.hpp"

#include "conduitscope/portable_time.hpp"

#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

#include "conduitscope/resource_limits.hpp"
#include "conduitscope/s7comm.hpp"  // S7COMM_PLUS_PROTOCOL_ID

namespace conduitscope {

std::string s7commplus_pdu_type_name(uint8_t pdu_type) {
    switch (pdu_type) {
        case S7COMMP_PDUTYPE_CONNECT: return "Connect";
        case S7COMMP_PDUTYPE_DATA: return "Data";
        case S7COMMP_PDUTYPE_DATAFW1_5: return "DataFW1_5";
        case S7COMMP_PDUTYPE_KEEPALIVE: return "Keep Alive";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << static_cast<unsigned>(pdu_type) << ")";
            return s.str();
        }
    }
}

std::string s7commplus_opcode_name(uint8_t opcode) {
    switch (opcode) {
        case S7COMMP_OPCODE_REQUEST: return "Request";
        case S7COMMP_OPCODE_RESPONSE: return "Response";
        case S7COMMP_OPCODE_NOTIFICATION: return "Notification";
        case S7COMMP_OPCODE_RESPONSE2: return "Response2";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << static_cast<unsigned>(opcode) << ")";
            return s.str();
        }
    }
}

std::string s7commplus_function_name(uint16_t fc) {
    switch (fc) {
        case S7COMMP_FUNCTIONCODE_EXPLORE: return "Explore";
        case S7COMMP_FUNCTIONCODE_CREATEOBJECT: return "CreateObject";
        case S7COMMP_FUNCTIONCODE_DELETEOBJECT: return "DeleteObject";
        case S7COMMP_FUNCTIONCODE_SETVARIABLE: return "SetVariable";
        case S7COMMP_FUNCTIONCODE_GETLINK: return "GetLink";
        case S7COMMP_FUNCTIONCODE_SETMULTIVAR: return "SetMultiVariables";
        case S7COMMP_FUNCTIONCODE_GETMULTIVAR: return "GetMultiVariables";
        case S7COMMP_FUNCTIONCODE_BEGINSEQUENCE: return "BeginSequence";
        case S7COMMP_FUNCTIONCODE_ENDSEQUENCE: return "EndSequence";
        case S7COMMP_FUNCTIONCODE_INVOKE: return "Invoke";
        case S7COMMP_FUNCTIONCODE_GETVARSUBSTR: return "GetVarSubStreamed";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << fc << ")";
            return s.str();
        }
    }
}

// Small subset of the reference plugin's own `errorcode_names` table (its full table is
// generated from a gated "internals" header this project has no access to -- see
// packet-s7comm_plus.c's `#ifdef USE_INTERNALS`; this is the plugin's own public fallback list).
std::string s7commplus_error_code_name(int16_t code) {
    switch (code) {
        case 0: return "OK";
        case 17: return "Message Session Pre-Legitimated";
        case 19: return "Warning Service Executed With Partial Error";
        case 22: return "Service Session Delegitimated";
        case -12: return "Object not found";
        case -17: return "Invalid CRC";
        case -134: return "Service Multi-ES Not Supported";
        case -255: return "Invalid LID";
        default: return "Unknown (" + std::to_string(code) + ")";
    }
}

std::string s7commplus_datatype_name(uint8_t dt) {
    switch (dt) {
        case 0x00: return "Null";
        case 0x01: return "Bool";
        case 0x02: return "USInt";
        case 0x03: return "UInt";
        case 0x04: return "UDInt";
        case 0x05: return "ULInt";
        case 0x06: return "SInt";
        case 0x07: return "Int";
        case 0x08: return "DInt";
        case 0x09: return "LInt";
        case 0x0a: return "Byte";
        case 0x0b: return "Word";
        case 0x0c: return "DWord";
        case 0x0d: return "LWord";
        case 0x0e: return "Real";
        case 0x0f: return "LReal";
        case 0x10: return "Timestamp";
        case 0x11: return "Timespan";
        case 0x12: return "RID";
        case 0x13: return "AID";
        case 0x14: return "Blob";
        case 0x15: return "WString";
        case 0x16: return "Variant";
        case 0x17: return "Struct";
        case 0x19: return "S7String";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << static_cast<unsigned>(dt) << ")";
            return s.str();
        }
    }
}

// A small, curated subset of the reference plugin's own public `id_number_names` table --
// the IDs most likely to actually show up in ordinary GetMultiVariables/SetVariable traffic
// against a data block or object attribute. Best-effort cosmetic enrichment only: an id NOT
// in this table is still fully decoded (see S7CommPlusIdValue::id), just shown as a bare number.
namespace {
std::string known_id_name(uint32_t id) {
    switch (id) {
        case 233: return "Subscription name";
        case 1048: return "Cyclic variables update set of addresses";
        case 1049: return "Cyclic variables update rate (ms)";
        case 1051: return "Unsubscribe";
        case 1053: return "Cyclic variables number of automatic sent telegrams";
        case 1256: return "Object Qualifier";
        case 1257: return "Parent RID";
        case 1258: return "Composition AID";
        case 1259: return "Key Qualifier";
        case 2421: return "Set CPU clock";
        case 2521: return "Block Number";
        case 2523: return "Block Language";
        case 2524: return "Knowhow Protected";
        case 2532: return "CRC";
        case 3448: return "Knowhow Protection Mode";
        case 4287: return "Title";
        case 4288: return "Comment";
        case 4294: return "Instance DB";
        default: return "";
    }
}

// --------------------------------------------------------------------------------------------
// Variable-Length Quantity readers -- see s7commplus.hpp's own file header for the exact bit
// layout (big-endian/MSB-first 7-bit groups, 0x80 continuation bit; signed forms use bit 0x40 of
// the first byte as a sign flag). Mirrors the reference plugin's own tvb_get_varuint32/varint32/
// varuint64/varint64 algorithm exactly (see packet-s7comm_plus.c).
uint32_t read_varuint32(Cursor& c) {
    uint32_t val = 0;
    for (int i = 0; i < 5; ++i) {
        uint8_t octet = c.u8();
        val = (val << 7) | (octet & 0x7f);
        if ((octet & 0x80) == 0) break;
    }
    return val;
}

int32_t read_varint32(Cursor& c) {
    uint32_t val = 0;
    for (int i = 0; i < 5; ++i) {
        uint8_t octet = c.u8();
        if (i == 0 && (octet & 0x40)) {
            val = 0xffffffc0u;  // sign-extend, excluding the first 6 payload bits
            val |= (octet & 0x3f);
        } else if (i == 0) {
            val = (octet & 0x7f);
        } else {
            val = (val << 7) | (octet & 0x7f);
        }
        if ((octet & 0x80) == 0) break;
    }
    return static_cast<int32_t>(val);
}

uint64_t read_varuint64(Cursor& c) {
    uint64_t val = 0;
    bool cont = false;
    int consumed = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t octet = c.u8();
        ++consumed;
        val = (val << 7) | (octet & 0x7f);
        cont = (octet & 0x80) != 0;
        if (!cont) break;
    }
    if (cont && consumed == 8) {
        uint8_t octet = c.u8();
        val = (val << 8) | octet;
    }
    return val;
}

int64_t read_varint64(Cursor& c) {
    uint64_t val = 0;
    bool cont = false;
    int consumed = 0;
    for (int i = 0; i < 8; ++i) {
        uint8_t octet = c.u8();
        ++consumed;
        if (i == 0 && (octet & 0x40)) {
            val = 0xffffffffffffffc0ull;
            val |= (octet & 0x3f);
        } else if (i == 0) {
            val = (octet & 0x7f);
        } else {
            val = (val << 7) | (octet & 0x7f);
        }
        cont = (octet & 0x80) != 0;
        if (!cont) break;
    }
    if (cont && consumed == 8) {
        uint8_t octet = c.u8();
        val = (val << 8) | octet;
    }
    return static_cast<int64_t>(val);
}

uint64_t read_u64be(Cursor& c) {
    uint64_t hi = c.u32be();
    uint64_t lo = c.u32be();
    return (hi << 32) | lo;
}

float read_f32be(Cursor& c) {
    uint32_t bits = c.u32be();
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

double read_f64be(Cursor& c) {
    uint64_t bits = read_u64be(c);
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(2) << static_cast<unsigned>(v);
    return s.str();
}
std::string hex_u16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(4) << v;
    return s.str();
}
std::string hex_u32(uint32_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(8) << v;
    return s.str();
}
std::string hex_u64(uint64_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::setfill('0') << std::setw(16) << v;
    return s.str();
}
// No "0x" prefix, exactly matching the reference plugin's own "SYM-CRC=%08x" rendering.
std::string hex8_bare(uint32_t v) {
    std::ostringstream s;
    s << std::hex << std::setfill('0') << std::setw(8) << v;
    return s.str();
}

std::string format_float(double v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

// timestamp: nanoseconds since 1970-01-01T00:00:00Z (see s7commp_get_timestring_from_uint64 in
// the reference plugin).
std::string format_s7plus_timestamp(uint64_t ns_since_epoch) {
    uint64_t ns = ns_since_epoch % 1000;
    uint64_t rest = ns_since_epoch / 1000;
    uint64_t us = rest % 1000;
    rest /= 1000;
    uint64_t ms = rest % 1000;
    rest /= 1000;
    std::time_t tt = static_cast<std::time_t>(rest);
    std::tm tm_utc{};
    std::ostringstream s;
    if (portable_gmtime(tt, tm_utc)) {
        s << std::put_time(&tm_utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms
          << '.' << std::setw(3) << us << '.' << std::setw(3) << ns << 'Z';
    } else {
        s << ns_since_epoch << "ns (out of range for calendar display)";
    }
    return s.str();
}

std::string truncate_display(const std::string& s, size_t max_len) {
    if (s.size() <= max_len) return s;
    return s.substr(0, max_len) + "...(" + std::to_string(s.size()) + " bytes total)";
}

// CLI-configurable via --max-recursion-depth/--max-decoded-objects -- see resource_limits.hpp.
// 0/unset keeps each literal default below. Functions rather than constexpr/const namespace-
// scope values, since they now read process-wide configuration.
int max_struct_depth() {  // mirrors mms.cpp's own recursion-depth cap posture
    return static_cast<int>(resource_limits().max_recursion_depth.value_or(16));
}
uint32_t max_array_iterations() {  // defense-in-depth only -- Cursor's own bounds checks already
                                     // stop a genuinely-truncated buffer well before this
    return static_cast<uint32_t>(resource_limits().max_decoded_objects.value_or(10000));
}
size_t max_rendered_elements() { return resource_limits().max_decoded_objects.value_or(20); }
size_t max_rendered_items() {  // matches DecodedPacket's own s7comm_item_tags cap
    return resource_limits().max_decoded_objects.value_or(50);
}
size_t max_blob_display() { return resource_limits().max_decoded_objects.value_or(64); }

// Forward declarations (decode_value and decode_id_value_list are mutually referenced: a Struct
// value signals the caller to recurse into decode_id_value_list for its members).
S7CommPlusValue decode_value(Cursor& c, int depth);
std::vector<S7CommPlusIdValue> decode_id_value_list(Cursor& c, bool looping, int depth);

// Renders exactly one element of `datatype` and advances `c` past it. Throws ParseError (via
// Cursor's own bounds checks, or explicitly for an unrecognized datatype -- see s7commplus.hpp's
// file header on why an unknown datatype must stop decoding rather than guess a length) --
// callers already run inside a try/catch that degrades gracefully.
std::string decode_value_element(Cursor& c, uint8_t datatype, int depth, bool& is_struct) {
    is_struct = false;
    switch (datatype) {
        case 0x00: return "<no value>";                                               // Null
        case 0x01: return hex_u8(c.u8());                                             // Bool
        case 0x02: return std::to_string(c.u8());                                     // USInt
        case 0x03: return std::to_string(c.u16be());                                  // UInt
        case 0x04: return std::to_string(read_varuint32(c));                          // UDInt
        case 0x05: return std::to_string(read_varuint64(c));                          // ULInt
        case 0x06: return std::to_string(static_cast<int8_t>(c.u8()));                // SInt
        case 0x07: return std::to_string(static_cast<int16_t>(c.u16be()));            // Int
        case 0x08: return std::to_string(read_varint32(c));                           // DInt
        case 0x09: return std::to_string(read_varint64(c));                           // LInt
        case 0x0a: return hex_u8(c.u8());                                             // Byte
        case 0x0b: return hex_u16(c.u16be());                                         // Word
        case 0x0c: return hex_u32(c.u32be());                                         // DWord
        case 0x0d: return hex_u64(read_u64be(c));                                     // LWord
        case 0x0e: return format_float(read_f32be(c));                                // Real
        case 0x0f: return format_float(read_f64be(c));                                // LReal
        case 0x10: return format_s7plus_timestamp(read_u64be(c));                     // Timestamp
        case 0x11: return std::to_string(read_varuint64(c)) + " ns";                  // Timespan
        case 0x12: return hex_u32(c.u32be());                                         // RID
        case 0x13: return std::to_string(read_varuint32(c));                          // AID
        case 0x16: return std::to_string(read_varuint32(c));                          // Variant (type-id)
        case 0x17: {                                                                    // Struct
            is_struct = true;
            c.u32be();  // 4-byte marker, meaning not further interpreted (see hpp file header)
            (void)depth;
            return "";  // caller decodes the following nested id-value-list
        }
        case 0x14: {  // Blob: 1 reserved byte + varuint32 length + raw bytes
            c.u8();
            uint32_t len = read_varuint32(c);
            ByteSpan bytes = c.bytes(std::min<size_t>(len, c.remaining()));
            std::string hex = to_hex(bytes, "");
            if (bytes.size() < len) hex += "...(truncated, " + std::to_string(len) + " bytes declared)";
            return truncate_display(hex, max_blob_display() * 2);
        }
        case 0x15: {  // WString: varuint32 length (characters, UTF-8 encoded) + bytes
            uint32_t len = read_varuint32(c);
            ByteSpan bytes = c.bytes(std::min<size_t>(len, c.remaining()));
            std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            return "\"" + truncate_display(text, max_blob_display()) + "\"";
        }
        default:
            throw ParseError("unrecognized S7comm-Plus value datatype 0x" +
                              [&] { std::ostringstream s; s << std::hex << static_cast<unsigned>(datatype); return s.str(); }() +
                              " -- cannot determine its wire length, decoding stops here");
    }
}

S7CommPlusValue decode_value(Cursor& c, int depth) {
    S7CommPlusValue v;
    uint8_t flags = c.u8();
    bool is_array = (flags & 0x10) != 0;
    bool is_address_array = (flags & 0x20) != 0;
    bool is_sparsearray = (flags & 0x40) != 0;
    v.is_array = is_array;
    v.is_address_array = is_address_array;
    v.is_sparsearray = is_sparsearray;

    v.datatype = c.u8();
    v.datatype_name = s7commplus_datatype_name(v.datatype);

    uint32_t array_size = 1;
    if (is_array || is_address_array) {
        array_size = read_varuint32(c);
    } else if (is_sparsearray) {
        array_size = max_array_iterations();  // null-terminated on the wire, see loop below
    }
    v.array_size = (is_sparsearray ? 0 : array_size);  // filled in as elements are actually found

    std::vector<std::string> elements;
    bool saw_struct = false;
    uint32_t bound = std::min(array_size, max_array_iterations());
    for (uint32_t i = 0; i < bound; ++i) {
        if (is_sparsearray) {
            uint32_t key = read_varuint32(c);
            if (key == 0) break;  // terminating null
            v.array_size += 1;
        }
        bool is_struct = false;
        std::string elem = decode_value_element(c, v.datatype, depth, is_struct);
        if (is_struct) {
            // A Struct element's members are a separate nested id-value-list immediately
            // following it on the wire -- unambiguous for a scalar Struct value (exactly one
            // list follows), but this decoder does not know how to delimit N separate member
            // lists for an array/address-array/sparsearray OF Struct (a real but rare shape --
            // see s7commplus.hpp). Rather than misalign every byte after this point, stop here.
            if (is_array || is_address_array || is_sparsearray) {
                throw ParseError("an array of Struct values was encountered -- this decoder does "
                                  "not support delimiting per-element nested member lists for "
                                  "that shape, decoding stops here");
            }
            saw_struct = true;
        }
        if (elements.size() < max_rendered_elements()) elements.push_back(elem);
        v.datatype_recognized = true;
        if (!(is_array || is_address_array || is_sparsearray)) break;  // scalar: exactly one element
    }
    if (!is_sparsearray) v.array_size = array_size;

    std::ostringstream out;
    out << "(" << v.datatype_name << ")";
    if (saw_struct) {
        // Struct members are a nested id-value-list immediately following, not part of `elements`
        // (decode_value_element deliberately returns "" for a Struct scalar) -- see hpp comment.
        auto members = decode_id_value_list(c, /*looping=*/true, depth + 1);
        out << " Struct { ";
        for (size_t i = 0; i < members.size(); ++i) {
            if (i) out << "; ";
            out << members[i].rendered;
        }
        out << " }";
    } else if (is_array || is_address_array) {
        out << " " << (is_address_array ? "Addressarray" : "Array") << "[" << array_size << "] = [";
        for (size_t i = 0; i < elements.size(); ++i) {
            if (i) out << ", ";
            out << elements[i];
        }
        if (elements.size() < array_size) out << ", ...";
        out << "]";
    } else if (is_sparsearray) {
        out << " Sparsearray = [";
        for (size_t i = 0; i < elements.size(); ++i) {
            if (i) out << ", ";
            out << elements[i];
        }
        out << "]";
    } else {
        out << " = " << (elements.empty() ? "" : elements[0]);
    }
    v.rendered = out.str();
    return v;
}

std::vector<S7CommPlusIdValue> decode_id_value_list(Cursor& c, bool looping, int depth) {
    std::vector<S7CommPlusIdValue> result;
    if (depth > max_struct_depth()) {
        throw ParseError("S7comm-Plus id-value-list nesting exceeded the safety depth cap (" +
                          std::to_string(max_struct_depth()) + ") -- decoding stops here");
    }
    do {
        uint32_t id = read_varuint32(c);
        if (id == 0) break;  // terminating null
        S7CommPlusIdValue iv;
        iv.id = id;
        iv.value = decode_value(c, depth);
        std::string name = known_id_name(id);
        std::ostringstream s;
        s << "id=" << id;
        if (!name.empty()) s << " (" << name << ")";
        s << ": " << iv.value.rendered;
        iv.rendered = s.str();
        if (result.size() < max_rendered_items()) result.push_back(iv);
    } while (looping);
    return result;
}

// ReturnValue: a varuint64 whose low 16 bits are a signed error code (see s7commplus.hpp). The
// remaining OMS-line/error-source/debug-info/flag sub-fields are decoded per the reference
// plugin's own bit layout but only surfaced as a raw hex note, not asserted field-by-field.
struct ReturnValueDecode {
    uint64_t raw = 0;
    int16_t error_code = 0;
    std::string error_code_name;
};

ReturnValueDecode decode_return_value(Cursor& c) {
    ReturnValueDecode rv;
    rv.raw = read_varuint64(c);
    rv.error_code = static_cast<int16_t>(rv.raw & 0xffff);
    rv.error_code_name = s7commplus_error_code_name(rv.error_code);
    return rv;
}

// --- Item address (GetMultiVariables/SetMultiVariables/SetVariable/DeleteObject) --------------
S7CommPlusItemAddress decode_item_address(Cursor& c) {
    S7CommPlusItemAddress addr;
    addr.crc_or_rid = read_varuint32(c);
    addr.is_object_id_style = (addr.crc_or_rid == 0);

    uint32_t field2 = read_varuint32(c);
    std::ostringstream tag;
    if (!addr.is_object_id_style) {
        uint16_t area1 = static_cast<uint16_t>(field2 >> 16);
        uint16_t area2 = static_cast<uint16_t>(field2 & 0xffff);
        tag << "SYM-CRC=" << hex8_bare(addr.crc_or_rid) << ", LID=";
        if (area1 == 0x0000) {  // IQMCT
            addr.area_recognized = true;
            switch (area2) {
                case 0x50: addr.area_name = "Inputs (I)"; tag << "I"; break;
                case 0x51: addr.area_name = "Outputs (Q)"; tag << "Q"; break;
                case 0x52: addr.area_name = "Flags (M)"; tag << "M"; break;
                case 0x53: addr.area_name = "Counter (C)"; tag << "C"; break;
                case 0x54: addr.area_name = "Timer (T)"; tag << "T"; break;
                default:
                    addr.area_recognized = false;
                    addr.area_name.clear();
                    tag << "Unknown IQMCT area " << hex_u16(area2);
                    break;
            }
        } else if (area1 == 0x8a0e) {  // DB
            addr.area_recognized = true;
            addr.area_name = "Datablock (DB)";
            addr.db_number = area2;
            tag << "DB" << area2;
        } else {
            addr.area_name.clear();
            tag << "Unknown area " << hex_u16(area1) << "/" << hex_u16(area2);
        }
    } else {
        tag << "by IDs: RID=" << field2;
    }

    addr.lid_nesting_depth = read_varuint32(c);
    uint32_t field4 = read_varuint32(c);
    addr.base_area = field4;
    if (addr.is_object_id_style) tag << ", ID=" << field4;

    for (uint32_t i = 2; i <= addr.lid_nesting_depth && i <= max_array_iterations(); ++i) {
        uint32_t v = read_varuint32(c);
        addr.extra_lids.push_back(v);
        if (addr.is_object_id_style) {
            tag << ", ID=" << v;
        } else {
            tag << "." << v;
        }
    }
    addr.tag = tag.str();
    return addr;
}

// --- GetMultiVariables --------------------------------------------------------------------
void decode_request_getmultivar(Cursor& c, S7CommPlusFrame& frame) {
    uint32_t link_id = c.u32be();
    uint32_t item_count = read_varuint32(c);
    if (link_id == 0) {
        read_varuint32(c);  // "number of fields in complete set" -- not independently surfaced
        for (uint32_t i = 0; i < item_count; ++i) {
            auto addr = decode_item_address(c);
            if (frame.item_addresses.size() < max_rendered_items()) frame.item_addresses.push_back(addr);
        }
    } else {
        uint32_t addr_count = read_varuint32(c);
        for (uint32_t i = 0; i < addr_count; ++i) {
            uint32_t id = read_varuint32(c);
            S7CommPlusItemAddress a;
            a.is_object_id_style = true;
            a.crc_or_rid = 0;
            a.tag = "by subscribed Link-Id=" + std::to_string(link_id) + ", ID=" + std::to_string(id);
            if (frame.item_addresses.size() < max_rendered_items()) frame.item_addresses.push_back(a);
        }
    }
}

void decode_response_getmultivar(Cursor& c, S7CommPlusFrame& frame) {
    auto rv = decode_return_value(c);
    frame.has_return_value = true;
    frame.return_code = rv.error_code;
    frame.return_code_name = rv.error_code_name;

    // itemnumber-value-list (looping, terminated by item number 0)
    do {
        uint32_t item_number = read_varuint32(c);
        if (item_number == 0) break;
        S7CommPlusIdValue iv;
        iv.id = item_number;
        iv.value = decode_value(c, 0);
        std::ostringstream s;
        s << "item=" << item_number << ": " << iv.value.rendered;
        iv.rendered = s.str();
        if (frame.id_values.size() < max_rendered_items()) frame.id_values.push_back(iv);
    } while (true);

    // itemnumber-errorvalue-list (looping, terminated by item number 0)
    do {
        uint32_t item_number = read_varuint32(c);
        if (item_number == 0) break;
        auto item_rv = decode_return_value(c);
        S7CommPlusItemError ie;
        ie.item_number = item_number;
        ie.error_code = item_rv.error_code;
        ie.error_code_name = item_rv.error_code_name;
        std::ostringstream s;
        s << "item=" << item_number << ": " << ie.error_code_name << " (" << ie.error_code << ")";
        ie.rendered = s.str();
        if (frame.item_errors.size() < max_rendered_items()) frame.item_errors.push_back(ie);
    } while (true);
}

// --- SetMultiVariables --------------------------------------------------------------------
void decode_request_setmultivar(Cursor& c, S7CommPlusFrame& frame) {
    uint32_t marker = c.u32be();
    uint32_t item_count = 0;
    if (marker == 0) {
        item_count = read_varuint32(c);
        read_varuint32(c);  // "number of fields in complete set"
        for (uint32_t i = 0; i < item_count; ++i) {
            auto addr = decode_item_address(c);
            if (frame.item_addresses.size() < max_rendered_items()) frame.item_addresses.push_back(addr);
        }
    } else {
        item_count = read_varuint32(c);
        uint32_t addr_count = read_varuint32(c);
        for (uint32_t i = 0; i < addr_count; ++i) {
            uint32_t id = read_varuint32(c);
            S7CommPlusItemAddress a;
            a.is_object_id_style = true;
            a.tag = "in Object Id=" + hex_u32(marker) + ", ID=" + std::to_string(id);
            if (frame.item_addresses.size() < max_rendered_items()) frame.item_addresses.push_back(a);
        }
    }
    for (uint32_t i = 0; i < item_count; ++i) {
        auto one = decode_id_value_list(c, /*looping=*/false, 0);
        for (auto& iv : one) {
            if (frame.id_values.size() < max_rendered_items()) frame.id_values.push_back(iv);
        }
    }
}

void decode_response_setmultivar(Cursor& c, S7CommPlusFrame& frame) {
    auto rv = decode_return_value(c);
    frame.has_return_value = true;
    frame.return_code = rv.error_code;
    frame.return_code_name = rv.error_code_name;
    do {
        uint32_t item_number = read_varuint32(c);
        if (item_number == 0) break;
        auto item_rv = decode_return_value(c);
        S7CommPlusItemError ie;
        ie.item_number = item_number;
        ie.error_code = item_rv.error_code;
        ie.error_code_name = item_rv.error_code_name;
        std::ostringstream s;
        s << "item=" << item_number << ": " << ie.error_code_name << " (" << ie.error_code << ")";
        ie.rendered = s.str();
        if (frame.item_errors.size() < max_rendered_items()) frame.item_errors.push_back(ie);
    } while (true);
}

// --- SetVariable ----------------------------------------------------------------------------
void decode_request_setvariable(Cursor& c, S7CommPlusFrame& frame) {
    uint32_t object_id = c.u32be();
    uint32_t item_count = read_varuint32(c);
    S7CommPlusItemAddress a;
    a.is_object_id_style = true;
    a.tag = "SetVariable in Object Id=" + hex_u32(object_id);
    frame.item_addresses.push_back(a);
    for (uint32_t i = 0; i < item_count; ++i) {
        auto one = decode_id_value_list(c, /*looping=*/false, 0);
        for (auto& iv : one) {
            if (frame.id_values.size() < max_rendered_items()) frame.id_values.push_back(iv);
        }
    }
}

void decode_response_setvariable(Cursor& c, S7CommPlusFrame& frame) {
    auto rv = decode_return_value(c);
    frame.has_return_value = true;
    frame.return_code = rv.error_code;
    frame.return_code_name = rv.error_code_name;
}

// --- DeleteObject ----------------------------------------------------------------------------
void decode_request_deleteobject(Cursor& c, S7CommPlusFrame& frame) {
    uint32_t object_id = c.u32be();
    S7CommPlusItemAddress a;
    a.is_object_id_style = true;
    a.tag = "Delete Object Id=" + hex_u32(object_id);
    frame.item_addresses.push_back(a);
}

void decode_response_deleteobject(Cursor& c, S7CommPlusFrame& frame) {
    auto rv = decode_return_value(c);
    frame.has_return_value = true;
    frame.return_code = rv.error_code;
    frame.return_code_name = rv.error_code_name;
    uint32_t object_id = c.u32be();
    S7CommPlusItemAddress a;
    a.is_object_id_style = true;
    a.tag = "Delete Object Id=" + hex_u32(object_id);
    frame.item_addresses.push_back(a);
}

// --- Integrity (PDU type Data only -- see s7commplus.hpp on DataFW1_5) -----------------------
//
// Simplification: the reference plugin's DeleteObject response decode conditionally omits the
// leading integrity-id varuint when the deleted object id is > 0x70000000 (a narrow, low-value
// nuance for one function's response only). This file always expects the id to be present when
// attempting an integrity decode; on the rare DeleteObject response where it's actually absent,
// the resulting digest_len will not equal 32 and this function simply leaves the digest
// unconsumed/unrendered (has_integrity stays true but integrity_digest_present stays false) --
// a graceful miss, not a crash, and consistent with this field never being verified anyway.
void decode_integrity(Cursor& c, S7CommPlusFrame& frame) {
    frame.has_integrity = true;
    read_varuint32(c);  // integrity id -- not independently surfaced (increments per telegram,
                          // no security value in showing it)
    uint8_t digest_len = c.u8();
    frame.integrity_digest_length = digest_len;
    if (digest_len == 32 && c.remaining() >= 32) {
        c.bytes(32);  // digest bytes themselves are not verified -- see hpp file header
        frame.integrity_digest_present = true;
    }
}

// DataFW1_5's own Integrity shape, at the FRONT of the Data part rather than the end: a
// varuint32 id (same as decode_integrity above) directly followed by a fixed 32-byte digest,
// with NO length-prefix byte in between -- unlike decode_integrity's shape, where that length
// byte is present and is normally 32 anyway. Confirmed against a real capture from a physical
// S7-1212C (firmware version not visible on the wire) driven by a genuine Siemens KTP 400 Basic
// HMI panel: consuming exactly id + 32 bytes here reliably realigns the remainder of the Data
// part onto a valid opcode byte (0x31/0x32/0x33), and the function bodies that then decode are
// internally consistent -- matching request/response sequence numbers, and, for the repeated
// SetVariable telegrams an HMI panel sends to report its own health back to the CPU (object id
// 0x70400002, well-known variable id 1053, "Cyclic variables number of automatic sent
// telegrams"), a value that climbs monotonically in lock-step with the sequence number across
// hundreds of consecutive telegrams. That is real device evidence, not a byte-layout guess, so
// this decode is Tier 1 (not experimental) -- see the DataFW1_5 paragraph in s7commplus.hpp,
// which this finding corrects (the reference plugin's own comments describe a shorter, id-only
// shape with no digest bytes for DataFW1_5; that either describes different firmware or was
// misread previously -- either way, this device's own wire behavior now governs here).
void decode_integrity_fw1_5(Cursor& c, S7CommPlusFrame& frame) {
    frame.has_integrity = true;
    read_varuint32(c);  // integrity id -- see decode_integrity above
    frame.integrity_digest_length = 32;
    if (c.remaining() >= 32) {
        c.bytes(32);  // digest bytes themselves are not verified -- see hpp file header
        frame.integrity_digest_present = true;
    }
}

// --- Above-COTP, trailer-based reassembly (ROADMAP item 147, docs/DEVELOPMENT.md) -------------
//
// Strips THIS ONE physical fragment's own leading Integrity block (DataFW1_5 only -- see
// decode_integrity_fw1_5 above) so that every fragment's contribution to a logical telegram's
// Data part is "pure" content, with no per-fragment integrity blocks interleaved into the
// concatenated buffer. Per the reference plugin's own source comments, firmware >= V1.5 places
// one of these at the FRONT of EVERY physical fragment (first, inner, and last alike), not just
// the single telegram as a whole -- a distinct wrinkle from the plain Data PDU type, where only
// the final fragment ever carries an Integrity part (at the END, handled separately by
// decode_integrity, called from decode_s7comm_plus_body below). A no-op for every other PDU type
// (is_fw1_5 is only ever true for DataFW1_5). Degrades gracefully (leaves whatever's left, possibly
// empty) rather than throwing if a fragment is too short even for the varuint32 id -- the eventual
// opcode-level decode's own try/catch is what surfaces that as a clear note.
ByteSpan strip_fw1_5_fragment_integrity(ByteSpan data_part, bool is_fw1_5, S7CommPlusFrame& frame) {
    if (!is_fw1_5) return data_part;
    Cursor dc(data_part);
    try {
        decode_integrity_fw1_5(dc, frame);
    } catch (const ParseError&) {
        // Too little data even for the leading varuint32 id -- fall through with whatever's left.
    }
    return dc.rest();
}

// Builds S7CommPlusFrame::summary from whatever fields are already populated -- shared by
// try_parse_s7comm_plus's own tail (the common, single-fragment case) and
// finalize_s7comm_plus_fragment's reassembly-completion path (s7commplus.cpp's own
// S7CommPlusDecoder::decode wrapper), so a reassembled telegram's summary is built exactly the
// same way as an unfragmented one's. A summary already set by decode_s7comm_plus_body itself
// (Connect's bare "Connect", or a fragment-placeholder set directly in try_parse_s7comm_plus) is
// left alone, matching this function's own pre-extraction behavior exactly.
std::string build_s7comm_plus_summary(const S7CommPlusFrame& frame) {
    if (!frame.summary.empty()) return frame.summary;
    std::ostringstream s;
    s << frame.pdu_type_name;
    if (frame.has_function) {
        s << ": " << frame.opcode_name << " " << frame.function_name;
    } else if (frame.is_notification) {
        s << ": Notification";
    }
    if (frame.has_sequence_number) s << " (seq=" << frame.sequence_number << ")";
    if (frame.has_return_value && (frame.return_code != 0)) {
        s << " [" << frame.return_code_name << "]";
    }
    if (!frame.item_addresses.empty()) {
        s << " (" << frame.item_addresses.size() << " item(s))";
    }
    if (!frame.id_values.empty()) {
        s << " (" << frame.id_values.size() << " value(s))";
    }
    return s.str();
}

// Decodes a logical Data part's worth of bytes -- either one self-contained, unfragmented
// telegram's own data_part (the overwhelmingly common case, called directly from
// try_parse_s7comm_plus below), or a fully-reassembled multi-fragment buffer (called from
// finalize_s7comm_plus_fragment once a trailer completes an above-COTP reassembly in progress).
// `pure_data` must already have any DataFW1_5 leading Integrity block stripped (by
// strip_fw1_5_fragment_integrity above) -- this function never does that itself, so it behaves
// identically whichever caller reaches it. Exactly today's pre-item-147 logic, just extracted
// and relieved of the DataFW1_5-leading-integrity step it used to do inline (now hoisted to every
// caller, uniformly, whether there's one fragment or many).
void decode_s7comm_plus_body(ByteSpan pure_data, uint8_t pdu_type, S7CommPlusFrame& frame) {
    if (pdu_type == S7COMMP_PDUTYPE_CONNECT) {
        frame.notes.push_back("Connect PDU (session establishment handshake) is recognized but "
                               "not decoded in this release -- see LIMITATIONS in docs/MANUAL.md");
        frame.summary = "Connect";
        return;
    }

    // Any ParseError anywhere below (a truncated capture, or hitting an unrecognized value
    // datatype -- see decode_value_element) is caught here and degrades to a clear note rather
    // than losing the whole packet.
    try {
        Cursor dc(pure_data);
        frame.has_data_part = true;

        frame.opcode = dc.u8();
        frame.opcode_name = s7commplus_opcode_name(frame.opcode);

        if (frame.opcode == S7COMMP_OPCODE_NOTIFICATION) {
            frame.is_notification = true;
            frame.notes.push_back("Notification body (subscribed/cyclic variable updates) is "
                                   "recognized but not decoded in this release -- see "
                                   "LIMITATIONS in docs/MANUAL.md");
        } else {
            dc.u16be();  // reserved1
            frame.function_code = dc.u16be();
            frame.function_name = s7commplus_function_name(frame.function_code);
            frame.has_function = true;
            dc.u16be();  // reserved2
            frame.sequence_number = dc.u16be();
            frame.has_sequence_number = true;

            if (frame.opcode == S7COMMP_OPCODE_REQUEST) {
                frame.session_id = dc.u32be();
                frame.has_session_id = true;
                dc.u8();  // unknown1

                switch (frame.function_code) {
                    case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                        decode_request_getmultivar(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                        decode_request_setmultivar(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                        decode_request_setvariable(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                        decode_request_deleteobject(dc, frame);
                        frame.body_decoded = true;
                        break;
                    default:
                        frame.notes.push_back(frame.function_name +
                                               " request body is recognized but not decoded in "
                                               "this release -- see LIMITATIONS in "
                                               "docs/MANUAL.md");
                        break;
                }
            } else if (frame.opcode == S7COMMP_OPCODE_RESPONSE ||
                       frame.opcode == S7COMMP_OPCODE_RESPONSE2) {
                dc.u8();  // unknown1

                switch (frame.function_code) {
                    case S7COMMP_FUNCTIONCODE_GETMULTIVAR:
                        decode_response_getmultivar(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETMULTIVAR:
                        decode_response_setmultivar(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_SETVARIABLE:
                        decode_response_setvariable(dc, frame);
                        frame.body_decoded = true;
                        break;
                    case S7COMMP_FUNCTIONCODE_DELETEOBJECT:
                        decode_response_deleteobject(dc, frame);
                        frame.body_decoded = true;
                        break;
                    default:
                        frame.notes.push_back(frame.function_name +
                                               " response body is recognized but not decoded in "
                                               "this release -- see LIMITATIONS in "
                                               "docs/MANUAL.md");
                        break;
                }
            }
        }

        // Integrity part: only attempted for the shapes this file understands (Tier-1 function
        // bodies just decoded above); left alone otherwise since a Tier-2 body's own undecoded
        // length means the integrity part's true position isn't known. (DataFW1_5's own integrity
        // is never found here -- it's always consumed per-fragment, before this function ever
        // runs -- see strip_fw1_5_fragment_integrity above.)
        if (!frame.is_fw1_5 && frame.body_decoded && dc.remaining() >= 32) {
            decode_integrity(dc, frame);
        }
    } catch (const ParseError& e) {
        frame.notes.push_back(std::string("S7comm-Plus Data part decoding stopped: ") + e.what());
    }
}

}  // namespace

std::optional<S7CommPlusFrame> try_parse_s7comm_plus(ByteSpan data) {
    if (data.empty()) return std::nullopt;
    if (data.at(0) != S7COMM_PLUS_PROTOCOL_ID) return std::nullopt;

    if (data.size() < 4) {
        throw ParseError("S7comm-Plus header is truncated (need 4 bytes, have " +
                          std::to_string(data.size()) + ")");
    }

    S7CommPlusFrame frame;
    Cursor c(data);
    c.u8();  // protocol id, already checked
    frame.pdu_type = c.u8();
    frame.pdu_type_name = s7commplus_pdu_type_name(frame.pdu_type);
    frame.is_fw1_5 = (frame.pdu_type == S7COMMP_PDUTYPE_DATAFW1_5);

    if (frame.pdu_type == S7COMMP_PDUTYPE_KEEPALIVE) {
        frame.is_keepalive = true;
        frame.keepalive_seq = c.u8();
        c.u8();  // reserved
        frame.summary = "Keep Alive (seq=" + std::to_string(static_cast<unsigned>(frame.keepalive_seq)) + ")";
        return frame;
    }

    uint16_t data_length = c.u16be();
    constexpr size_t kHeaderLen = 4;
    bool has_trailer = data.size() > kHeaderLen + static_cast<size_t>(data_length);
    frame.has_trailer = has_trailer;

    // This fragment's own Data-part bytes, exactly `data_length` bytes clamped to what's actually
    // available -- populated unconditionally (every non-KeepAlive PDU type, trailer present or
    // not) so that finalize_s7comm_plus_fragment (S7CommPlusDecoder::decode's reassembly-driving
    // wrapper, below) can buffer it when there's no trailer, without re-deriving it itself.
    size_t available_after_header = data.size() - kHeaderLen;  // safe: data.size() >= 4, checked above
    size_t data_take = std::min<size_t>(data_length, available_after_header);
    ByteSpan data_part = data.subspan(kHeaderLen, data_take);
    frame.body_region = data_part;

    if (!has_trailer) {
        // Above-COTP, trailer-based reassembly (ROADMAP item 147, docs/DEVELOPMENT.md): this
        // fragment alone isn't a complete telegram. try_parse_s7comm_plus itself stays ctx-free
        // and single-fragment-only (its own documented contract, relied on directly by
        // fuzz/fuzz_s7comm_plus.cpp) -- actually buffering and reassembling fragments across
        // frames is S7CommPlusDecoder::decode's job, via finalize_s7comm_plus_fragment below.
        frame.notes.push_back(
            "S7comm-Plus telegram has no trailer in this frame -- it continues in a further "
            "TPKT/COTP frame; reassembled once a later frame's trailer completes it (see "
            "S7CommPlusReassemblyState in s7commplus.hpp)");
        frame.summary = frame.pdu_type_name + " (fragment, awaiting further data)";
        return frame;
    }

    ByteSpan pure_data = strip_fw1_5_fragment_integrity(data_part, frame.is_fw1_5, frame);
    decode_s7comm_plus_body(pure_data, frame.pdu_type, frame);

    // frame.has_trailer is already true here (the !has_trailer branch above returned early) --
    // its position is known directly from the header's own Data Length field, independent of
    // whether the Data part itself decoded successfully.

    frame.summary = build_s7comm_plus_summary(frame);

    return frame;
}

// Resets every field decode_s7comm_plus_body (and the strip_fw1_5_fragment_integrity /
// decode_integrity it calls) can populate, back to S7CommPlusFrame's own defaults. Used only by
// finalize_s7comm_plus_fragment below, immediately before re-decoding a just-completed
// reassembled buffer from scratch -- mirrors OPC UA chunk reassembly's own reset-then-redecode
// pattern (see OpcUaReassemblyState's own finalize_chunk in opcua.cpp) so a reassembled telegram's
// frame ends up indistinguishable from one that had arrived whole in a single fragment.
static void reset_s7comm_plus_body_fields(S7CommPlusFrame& frame) {
    frame.has_data_part = false;
    frame.is_notification = false;
    frame.opcode = 0;
    frame.opcode_name.clear();
    frame.has_function = false;
    frame.function_code = 0;
    frame.function_name.clear();
    frame.has_sequence_number = false;
    frame.sequence_number = 0;
    frame.has_session_id = false;
    frame.session_id = 0;
    frame.body_decoded = false;
    frame.has_return_value = false;
    frame.return_code = 0;
    frame.return_code_name.clear();
    frame.item_addresses.clear();
    frame.id_values.clear();
    frame.item_errors.clear();
    frame.has_integrity = false;
    frame.integrity_digest_present = false;
    frame.integrity_digest_length = 0;
    frame.summary.clear();
}

// Drives the above-COTP, trailer-based reassembly FSM (ROADMAP item 147, docs/DEVELOPMENT.md;
// S7CommPlusReassemblyState in s7commplus.hpp) for one already-parsed, single-fragment frame.
// Called only from S7CommPlusDecoder::decode, immediately after try_parse_s7comm_plus -- never
// from try_parse_s7comm_plus itself (which stays ctx-free, per fuzz/fuzz_s7comm_plus.cpp's own
// direct-call contract) and never from fuzz harnesses. Mutates `frame` in place: a fragment that
// completes a reassembly gets its body-decode fields replaced with the reassembled result; every
// other case leaves try_parse_s7comm_plus's own already-correct standalone decode untouched,
// aside from an added note.
static void finalize_s7comm_plus_fragment(S7CommPlusFrame& frame, DecodeContext& ctx) {
    if (frame.is_keepalive) return;  // KeepAlive never has a Data part at all -- nothing to do.

    auto& state = ctx.flow_state<S7CommPlusReassemblyState>(FlowStateKeying::Session);

    if (!state.in_progress) {
        if (frame.has_trailer) return;  // common case -- already fully decoded, nothing to do
        // Begin a new reassembly. No safety-cap check on this first fragment -- same posture
        // OPC UA chunk reassembly's own finalize_chunk (opcua.cpp) takes on its own first ('C')
        // chunk: the cap exists to bound CONTINUED accumulation, not to reject a lone first
        // fragment outright.
        state = S7CommPlusReassemblyState{};
        state.in_progress = true;
        state.pdu_type = frame.pdu_type;
        state.is_fw1_5 = frame.is_fw1_5;
        ByteSpan pure = strip_fw1_5_fragment_integrity(frame.body_region, frame.is_fw1_5, frame);
        state.buffered_data.assign(pure.data(), pure.data() + pure.size());
        state.fragment_count = 1;
        frame.notes.push_back(
            "buffering an S7comm-Plus telegram split across TPKT/COTP frames -- " +
            std::to_string(state.buffered_data.size()) + " byte(s) buffered across " +
            std::to_string(state.fragment_count) + " fragment(s) so far on this TCP session");
        return;
    }

    // A reassembly is already in progress -- this fragment must match the PDU type and firmware
    // shape (Data vs. DataFW1_5) the first fragment set, to be accepted as its continuation.
    bool matches = state.pdu_type == frame.pdu_type && state.is_fw1_5 == frame.is_fw1_5;
    if (!matches) {
        frame.notes.push_back(
            (frame.has_trailer ? "a complete S7comm-Plus telegram (PDU type "
                                : "a new S7comm-Plus fragment (PDU type ") +
            frame.pdu_type_name +
            ") arrived while a previous above-COTP reassembly was in progress (" +
            std::to_string(state.buffered_data.size()) + " byte(s) buffered across " +
            std::to_string(state.fragment_count) + " fragment(s)) -- abandoned" +
            (frame.has_trailer ? "; this telegram's own standalone decode above is unaffected" : ""));
        state = S7CommPlusReassemblyState{};
        finalize_s7comm_plus_fragment(frame, ctx);  // re-run this same fragment with nothing in progress
        return;
    }

    ByteSpan pure = strip_fw1_5_fragment_integrity(frame.body_region, frame.is_fw1_5, frame);
    state.buffered_data.insert(state.buffered_data.end(), pure.data(), pure.data() + pure.size());
    ++state.fragment_count;

    // Safety caps against a pathological/malformed capture stalling a reassembly open forever --
    // same caps DNP3's and OPC UA's own reassembly already use (CLI-configurable via
    // --max-reassembly-bytes/--max-reassembly-segments; 0/unset keeps these literal defaults).
    const size_t kMaxBufferedBytes = resource_limits().max_reassembly_bytes.value_or(65536);
    const size_t kMaxFragmentsPerTelegram = resource_limits().max_reassembly_segments.value_or(500);
    if (state.buffered_data.size() > kMaxBufferedBytes || state.fragment_count > kMaxFragmentsPerTelegram) {
        frame.notes.push_back(
            "above-COTP S7comm-Plus reassembly exceeded this release's safety limits (" +
            std::to_string(state.buffered_data.size()) + " byte(s) across " +
            std::to_string(state.fragment_count) + " fragment(s)) -- abandoned");
        state = S7CommPlusReassemblyState{};
        return;
    }

    if (!frame.has_trailer) {
        frame.notes.push_back(
            "buffering an S7comm-Plus telegram split across TPKT/COTP frames -- " +
            std::to_string(state.buffered_data.size()) + " byte(s) buffered across " +
            std::to_string(state.fragment_count) + " fragment(s) so far on this TCP session");
        return;
    }

    // frame.has_trailer == true: reassembly complete. try_parse_s7comm_plus already decoded this
    // last fragment's own bytes as a (incomplete/misleading) standalone telegram -- replace that
    // with a fresh decode of the full reassembled buffer instead.
    size_t total_fragments = state.fragment_count;
    std::vector<uint8_t> reassembled = std::move(state.buffered_data);
    state = S7CommPlusReassemblyState{};

    reset_s7comm_plus_body_fields(frame);
    if (frame.is_fw1_5) {
        // decode_s7comm_plus_body never attempts a tail Integrity decode for DataFW1_5 (its own
        // Integrity is always front-loaded, per fragment, already consumed into `pure` above).
        // Re-run the strip once more, now against the just-reset frame, purely so its own
        // has_integrity/integrity_digest_present end up reflecting this last fragment's leading
        // Integrity block -- exactly as a single, unfragmented DataFW1_5 telegram's own
        // try_parse_s7comm_plus path already shows it. (Idempotent: decode_integrity_fw1_5 reads
        // the same bytes deterministically either time; nothing is double-consumed since this
        // works off frame.body_region, not the cursor already spent above.)
        strip_fw1_5_fragment_integrity(frame.body_region, true, frame);
    }
    decode_s7comm_plus_body(ByteSpan(reassembled.data(), reassembled.size()), frame.pdu_type, frame);
    frame.notes.push_back(
        "S7comm-Plus telegram reassembled from " + std::to_string(total_fragments) +
        " fragment(s) across this TCP session, " + std::to_string(reassembled.size()) +
        " byte(s) of Data part total");
    frame.summary = build_s7comm_plus_summary(frame);
}

std::optional<ProtocolResult> S7CommPlusDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto parsed = try_parse_s7comm_plus(payload);
    if (!parsed) return std::nullopt;
    finalize_s7comm_plus_fragment(*parsed, ctx);
    return ProtocolResult::make<S7CommPlusFrame>("s7comm-plus", std::move(*parsed));
}

const ProtocolDecoder& s7comm_plus_decoder() {
    static const S7CommPlusDecoder instance;
    return instance;
}

}  // namespace conduitscope
