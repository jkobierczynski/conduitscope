// SPDX-License-Identifier: MIT
#include "conduitscope/s7commplus.hpp"

#include <cmath>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

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
    std::tm* tm_utc = std::gmtime(&tt);
    std::ostringstream s;
    if (tm_utc) {
        s << std::put_time(tm_utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms
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

constexpr int kMaxStructDepth = 16;         // mirrors mms.cpp's own recursion-depth cap posture
constexpr uint32_t kMaxArrayIterations = 10000;  // defense-in-depth only -- Cursor's own bounds
                                                   // checks already stop a genuinely-truncated
                                                   // buffer well before this
constexpr size_t kMaxRenderedElements = 20;
constexpr size_t kMaxRenderedItems = 50;    // matches DecodedPacket's own s7comm_item_tags cap
constexpr size_t kMaxBlobDisplay = 64;

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
            return truncate_display(hex, kMaxBlobDisplay * 2);
        }
        case 0x15: {  // WString: varuint32 length (characters, UTF-8 encoded) + bytes
            uint32_t len = read_varuint32(c);
            ByteSpan bytes = c.bytes(std::min<size_t>(len, c.remaining()));
            std::string text(reinterpret_cast<const char*>(bytes.data()), bytes.size());
            return "\"" + truncate_display(text, kMaxBlobDisplay) + "\"";
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
        array_size = kMaxArrayIterations;  // null-terminated on the wire, see loop below
    }
    v.array_size = (is_sparsearray ? 0 : array_size);  // filled in as elements are actually found

    std::vector<std::string> elements;
    bool saw_struct = false;
    uint32_t bound = std::min(array_size, kMaxArrayIterations);
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
        if (elements.size() < kMaxRenderedElements) elements.push_back(elem);
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
    if (depth > kMaxStructDepth) {
        throw ParseError("S7comm-Plus id-value-list nesting exceeded the safety depth cap (" +
                          std::to_string(kMaxStructDepth) + ") -- decoding stops here");
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
        if (result.size() < kMaxRenderedItems) result.push_back(iv);
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

    for (uint32_t i = 2; i <= addr.lid_nesting_depth && i <= kMaxArrayIterations; ++i) {
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
            if (frame.item_addresses.size() < kMaxRenderedItems) frame.item_addresses.push_back(addr);
        }
    } else {
        uint32_t addr_count = read_varuint32(c);
        for (uint32_t i = 0; i < addr_count; ++i) {
            uint32_t id = read_varuint32(c);
            S7CommPlusItemAddress a;
            a.is_object_id_style = true;
            a.crc_or_rid = 0;
            a.tag = "by subscribed Link-Id=" + std::to_string(link_id) + ", ID=" + std::to_string(id);
            if (frame.item_addresses.size() < kMaxRenderedItems) frame.item_addresses.push_back(a);
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
        if (frame.id_values.size() < kMaxRenderedItems) frame.id_values.push_back(iv);
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
        if (frame.item_errors.size() < kMaxRenderedItems) frame.item_errors.push_back(ie);
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
            if (frame.item_addresses.size() < kMaxRenderedItems) frame.item_addresses.push_back(addr);
        }
    } else {
        item_count = read_varuint32(c);
        uint32_t addr_count = read_varuint32(c);
        for (uint32_t i = 0; i < addr_count; ++i) {
            uint32_t id = read_varuint32(c);
            S7CommPlusItemAddress a;
            a.is_object_id_style = true;
            a.tag = "in Object Id=" + hex_u32(marker) + ", ID=" + std::to_string(id);
            if (frame.item_addresses.size() < kMaxRenderedItems) frame.item_addresses.push_back(a);
        }
    }
    for (uint32_t i = 0; i < item_count; ++i) {
        auto one = decode_id_value_list(c, /*looping=*/false, 0);
        for (auto& iv : one) {
            if (frame.id_values.size() < kMaxRenderedItems) frame.id_values.push_back(iv);
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
        if (frame.item_errors.size() < kMaxRenderedItems) frame.item_errors.push_back(ie);
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
            if (frame.id_values.size() < kMaxRenderedItems) frame.id_values.push_back(iv);
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

    if (!has_trailer) {
        frame.notes.push_back(
            "S7comm-Plus telegram has no trailer in this frame -- it continues in a further "
            "TPKT/COTP frame (this protocol's own above-COTP fragmentation is not reassembled "
            "in this release, see LIMITATIONS in docs/MANUAL.md)");
        frame.summary = frame.pdu_type_name + " (fragment, awaiting further data)";
        return frame;
    }

    size_t available_after_header = data.size() - kHeaderLen;  // safe: data.size() >= 4, checked above
    size_t data_take = std::min<size_t>(data_length, available_after_header);
    ByteSpan data_part = data.subspan(kHeaderLen, data_take);

    if (frame.pdu_type == S7COMMP_PDUTYPE_CONNECT) {
        frame.notes.push_back("Connect PDU (session establishment handshake) is recognized but "
                               "not decoded in this release -- see LIMITATIONS in docs/MANUAL.md");
        frame.summary = "Connect";
    } else if (frame.is_fw1_5) {
        frame.notes.push_back("DataFW1_5 PDU (firmware >= V1.5) moves its Integrity part to a "
                               "position this decoder does not model with confidence -- its Data "
                               "part is not decoded in this release, see LIMITATIONS in "
                               "docs/MANUAL.md");
        frame.summary = "DataFW1_5 (" + std::to_string(data_length) + " byte(s) data, not decoded)";
    } else {
        // PDU type Data (0x02) -- the Tier-1 target. Any ParseError anywhere below (a truncated
        // capture, or hitting an unrecognized value datatype -- see decode_value_element) is
        // caught here and degrades to a clear note rather than losing the whole packet.
        try {
            Cursor dc(data_part);
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

            // Integrity part: only attempted for the shapes this file understands (Tier-1
            // function bodies just decoded above); left alone otherwise since a Tier-2 body's
            // own undecoded length means the integrity part's true position isn't known.
            if (frame.body_decoded && dc.remaining() >= 32) {
                decode_integrity(dc, frame);
            }
        } catch (const ParseError& e) {
            frame.notes.push_back(std::string("S7comm-Plus Data part decoding stopped: ") + e.what());
        }
    }

    // frame.has_trailer is already true here (the !has_trailer branch above returned early) --
    // its position is known directly from the header's own Data Length field, independent of
    // whether the Data part itself decoded successfully.

    std::ostringstream s;
    if (!frame.summary.empty()) {
        s << frame.summary;
    } else {
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
    }
    frame.summary = s.str();

    return frame;
}

}  // namespace conduitscope
