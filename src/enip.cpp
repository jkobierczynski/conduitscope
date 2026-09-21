// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/enip.hpp"

#include <algorithm>
#include <cstring>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// --- small local byte-reading helpers (little-endian; byteio.hpp's Cursor has u8/u16le/u32le but
// not u64/float/double) --------------------------------------------------------------------------

uint64_t read_u64le(Cursor& c) {
    uint64_t v = 0;
    for (int i = 0; i < 8; ++i) v |= (static_cast<uint64_t>(c.u8()) << (8 * i));
    return v;
}

float read_float_le(Cursor& c) {
    uint32_t bits = c.u32le();
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

double read_double_le(Cursor& c) {
    uint64_t bits = read_u64le(c);
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

// --- encapsulation header naming -------------------------------------------

// Empty return means "not one of the nine standard encapsulation commands this decoder
// recognizes" -- used both for display and, in try_parse_enip/enip_declared_length, as the
// primary structural detection check. NOP (0x0000) is deliberately excluded: unlike every other
// command, it (and a real NOP message's `length` field, typically also 0) is all-zero bytes, so
// treating it as a detection signal made a short run of zero-padded/malformed bytes on unrelated
// traffic misdetect as EtherNet/IP in real-capture testing (a Digital Bond Modbus test fixture
// deliberately exercising traffic outside Modbus's own scope, see tests/real_captures/enip/
// ATTRIBUTION.md) -- the same reasoning already applied once before for Modbus's own function-
// code-0 exclusion (see modbus.cpp's try_parse_modbus_tcp). NOP also carries essentially no
// real-world detection value: it is a vestigial keep-alive vanishingly rarely sent in practice.
std::string enip_command_name(uint16_t cmd) {
    switch (cmd) {
        case 0x0004: return "ListServices";
        case 0x0063: return "ListIdentity";
        case 0x0064: return "ListInterfaces";
        case 0x0065: return "RegisterSession";
        case 0x0066: return "UnRegisterSession";
        case 0x006F: return "SendRRData";
        case 0x0070: return "SendUnitData";
        case 0x0072: return "IndicateStatus";
        case 0x0073: return "Cancel";
        default: return "";
    }
}

// Empty return means "not one of the documented encapsulation-level status codes" -- used as a
// second, independent structural detection check (see try_parse_enip's header comment).
std::string enip_status_name(uint32_t status) {
    switch (status) {
        case 0x0000: return "Success";
        case 0x0001: return "Invalid or unsupported encapsulation command";
        case 0x0002: return "Insufficient memory";
        case 0x0003: return "Poorly formed or incorrect data in the encapsulated message";
        case 0x0064: return "Invalid session handle";
        case 0x0065: return "Invalid message length";
        case 0x0069: return "Unsupported encapsulation protocol revision";
        default: return "";
    }
}

// --- CIP naming tables -------------------------------------------------------

std::string cip_class_name(uint32_t class_id) {
    switch (class_id) {
        case 0x01: return "Identity";
        case 0x02: return "Message Router";
        case 0x03: return "DeviceNet";
        case 0x04: return "Assembly";
        case 0x05: return "Connection";
        case 0x06: return "Connection Manager";
        case 0x07: return "Register";
        case 0x0F: return "Parameter";
        case 0x37: return "File";
        case 0x6B: return "Symbol";    // Rockwell-specific: the Logix5000 tag database object
        case 0x6C: return "Template";  // Rockwell-specific: UDT template object
        case 0xF5: return "TCP/IP Interface";
        case 0xF6: return "Ethernet Link";
        default: return "";
    }
}

// cip_service_name is declared in enip.hpp (not anonymous-namespace-local) and defined below,
// after this anonymous namespace closes, specifically so devicenet.cpp can call it directly to
// resolve DeviceNet's own Group 3 explicit-messaging CIP service codes without duplicating this
// table -- see enip.hpp's own comment on it and devicenet.hpp's file header comment.

// CIP Volume 1 Appendix B general status codes.
std::string cip_general_status_name(uint8_t status) {
    switch (status) {
        case 0x00: return "Success";
        case 0x01: return "Connection failure";
        case 0x02: return "Resource unavailable";
        case 0x03: return "Invalid parameter value";
        case 0x04: return "Path segment error";
        case 0x05: return "Path destination unknown";
        case 0x06: return "Partial transfer";
        case 0x07: return "Connection lost";
        case 0x08: return "Service not supported";
        case 0x09: return "Invalid attribute value";
        case 0x0A: return "Attribute list error";
        case 0x0B: return "Already in requested mode/state";
        case 0x0C: return "Object state conflict";
        case 0x0D: return "Object already exists";
        case 0x0E: return "Attribute not settable";
        case 0x0F: return "Permission denied";
        case 0x10: return "Device state conflict";
        case 0x11: return "Reply data too large";
        case 0x12: return "Fragmentation of a primitive value";
        case 0x13: return "Not enough data";
        case 0x14: return "Attribute not supported";
        case 0x15: return "Too much data";
        case 0x16: return "Object does not exist";
        case 0x17: return "Service fragmentation sequence not in progress";
        case 0x18: return "No stored attribute data";
        case 0x19: return "Store operation failure";
        case 0x1A: return "Routing failure, request packet too large";
        case 0x1B: return "Routing failure, response packet too large";
        case 0x1C: return "Missing attribute list entry data";
        case 0x1D: return "Invalid attribute value list";
        case 0x1E: return "Embedded service error";
        case 0x1F: return "Vendor specific error";
        case 0x20: return "Invalid parameter";
        case 0x21: return "Write-once value or medium already written";
        case 0x22: return "Invalid reply received";
        case 0x23: return "Buffer overflow";
        case 0x24: return "Invalid message format";
        case 0x25: return "Key failure in path";
        case 0x26: return "Path size invalid";
        case 0x27: return "Unexpected attribute in list";
        case 0x28: return "Invalid member ID";
        case 0x29: return "Member not settable";
        case 0x2A: return "Group 2 only server general failure";
        case 0x2B: return "Unknown Modbus error";
        case 0x2C: return "Attribute not gettable";
        default:
            if (status >= 0xD1) {
                std::ostringstream s;
                s << "Object class specific error (0x" << std::hex << std::uppercase
                  << static_cast<unsigned>(status) << ")";
                return s.str();
            }
            std::ostringstream s;
            s << "Unknown/reserved (0x" << std::hex << std::uppercase << static_cast<unsigned>(status) << ")";
            return s.str();
    }
}

// --- CIP elementary data types (ODVA CIP Vol 1 Appendix C) ------------------

struct CipTypeInfo {
    const char* name;
    size_t size;
};

// The "first pass" decoded subset: the common fixed-size numeric types. STRING (0xD0)/
// SHORT_STRING (0xDA) and structured/UDT/array types (>= 0x02A0) are recognized by code (see
// cip_type_is_variable_length_string/cip_type_is_structured) and ARE value-decoded, but via their
// own dedicated decode paths (decode_cip_string_elements/decode_cip_structured_element) rather
// than through this fixed-{name,size} table, since neither fits its model -- see those functions'
// own comments. STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value remain out of scope; see
// decode_cip_structured_element's comment.
std::optional<CipTypeInfo> cip_type_info(uint16_t type_code) {
    switch (type_code) {
        case 0xC1: return CipTypeInfo{"BOOL", 1};
        case 0xC2: return CipTypeInfo{"SINT", 1};
        case 0xC3: return CipTypeInfo{"INT", 2};
        case 0xC4: return CipTypeInfo{"DINT", 4};
        case 0xC5: return CipTypeInfo{"LINT", 8};
        case 0xC6: return CipTypeInfo{"USINT", 1};
        case 0xC7: return CipTypeInfo{"UINT", 2};
        case 0xC8: return CipTypeInfo{"UDINT", 4};
        case 0xC9: return CipTypeInfo{"ULINT", 8};
        case 0xCA: return CipTypeInfo{"REAL", 4};
        case 0xCB: return CipTypeInfo{"LREAL", 8};
        case 0xD1: return CipTypeInfo{"BYTE", 1};
        case 0xD2: return CipTypeInfo{"WORD", 2};
        case 0xD3: return CipTypeInfo{"DWORD", 4};
        case 0xD4: return CipTypeInfo{"LWORD", 8};
        default: return std::nullopt;
    }
}

// STRING (0xD0) and SHORT_STRING (0xDA) are self-length-prefixed on the wire (see
// decode_cip_string_elements), unlike every type cip_type_info knows about -- there is no fixed
// per-element byte size to multiply a count by, so they need their own dedicated decode path
// rather than fitting cip_type_info's {name, size} model.
bool cip_type_is_variable_length_string(uint16_t type_code) {
    return type_code == 0xD0 || type_code == 0xDA;
}

// A CIP type code >= 0x02A0 is Rockwell/ODVA's "Structured Data Type" sentinel -- see
// decode_cip_structured_element's own comment for the full reasoning and wire format.
bool cip_type_is_structured(uint16_t type_code) { return type_code >= 0x02A0; }

std::string cip_type_display_name(uint16_t type_code) {
    if (cip_type_is_structured(type_code)) {
        return "Structured Data Type (" + hex4(type_code) + ")";
    }
    static const std::pair<uint16_t, const char*> kNames[] = {
        {0xC1, "BOOL"},         {0xC2, "SINT"},   {0xC3, "INT"},          {0xC4, "DINT"},
        {0xC5, "LINT"},         {0xC6, "USINT"},  {0xC7, "UINT"},         {0xC8, "UDINT"},
        {0xC9, "ULINT"},        {0xCA, "REAL"},   {0xCB, "LREAL"},        {0xCC, "STIME"},
        {0xCD, "DATE"},         {0xCE, "TIME_OF_DAY"}, {0xCF, "DATE_AND_TIME"}, {0xD0, "STRING"},
        {0xD1, "BYTE"},         {0xD2, "WORD"},   {0xD3, "DWORD"},        {0xD4, "LWORD"},
        {0xD5, "STRING2"},      {0xD6, "FTIME"},  {0xD7, "LTIME"},        {0xD8, "ITIME"},
        {0xD9, "STRINGN"},      {0xDA, "SHORT_STRING"}, {0xDB, "TIME"},   {0xDC, "EPATH"},
        {0xDD, "ENGUNIT"},      {0xDE, "STRINGI"},
    };
    for (const auto& kv : kNames) {
        if (kv.first == type_code) return kv.second;
    }
    return "Unknown (" + hex4(type_code) + ")";
}

// The whole ODVA elementary-type code range, PLUS the >= 0x02A0 Structured Data Type range (see
// cip_type_is_structured) -- used as a plausibility gate for the Read Tag(Fragmented) response
// heuristic (see decode_cip_response_data): a real elementary type code always falls in
// 0xC1-0xDE, and a genuine UDT (or array-of-UDT) tag read always falls in the structured range --
// together still a strong signal (both are Rockwell/ODVA-reserved sentinel ranges no unrelated
// object class's reply would coincidentally start with), so a response outside BOTH ranges is not
// a Rockwell tag read at all, but some other object class's reuse of the same service number
// against a class/instance-addressed path.
bool cip_is_plausible_type_code(uint16_t type_code) {
    return (type_code >= 0xC1 && type_code <= 0xDE) || cip_type_is_structured(type_code);
}

// --- EPATH walking ------------------------------------------------------------

// Decodes `path_len_bytes` worth of CIP EPATH segments starting at `c`'s current position into a
// human-readable summary, and records the class/instance/attribute logical-segment values (if
// any) for callers that need to recognize a specific well-known object/service (Identity,
// Connection Manager, ...). Stops early (without consuming the rest of `path_len_bytes`) on a
// segment type this "first pass" doesn't know how to size -- safe because the caller only ever
// uses the already-consumed byte count to skip past the whole path field, not this function's own
// early return.
CipPath decode_cip_path(Cursor& c, size_t path_len_bytes) {
    CipPath path;
    size_t end = c.position() + path_len_bytes;
    std::ostringstream summary;
    bool first = true;

    while (c.position() < end) {
        uint8_t seg = c.u8();
        if ((seg & 0xE0) == 0x20) {
            // Logical segment: bits7-5=001, bits4-2=logical type, bits1-0=logical format
            // (8/16/32-bit; see the padded-EPATH pad-byte handling below).
            unsigned ltype = (seg >> 2) & 0x07;
            unsigned lformat = seg & 0x03;
            uint32_t value;
            if (lformat == 0) {
                value = c.u8();
            } else if (lformat == 1) {
                c.u8();  // pad byte (padded EPATH word-alignment)
                value = c.u16le();
            } else if (lformat == 2) {
                c.u8();  // pad byte
                value = c.u32le();
            } else {
                if (!first) summary << " ";
                summary << "[reserved logical segment format]";
                break;
            }
            const char* name = "Logical?";
            switch (ltype) {
                case 0: name = "Class"; path.class_id = value; break;
                case 1: name = "Instance"; path.instance_id = value; break;
                case 2: name = "Member"; break;
                case 3: name = "ConnPt"; break;
                case 4: name = "Attribute"; path.attribute_id = value; break;
                case 5: name = "Special"; break;
                case 6: name = "ServiceID"; break;
                default: break;
            }
            if (!first) summary << " ";
            summary << name << "=0x" << std::hex << value << std::dec;
            if (ltype == 0) {
                std::string cn = cip_class_name(value);
                if (!cn.empty()) summary << " (" << cn << ")";
            }
            first = false;
        } else if (seg == 0x91) {
            // ANSI Extended Symbol segment -- the Rockwell Logix5000 named-tag convention.
            uint8_t len = c.u8();
            std::string text;
            text.reserve(len);
            for (uint8_t i = 0; i < len; ++i) text += static_cast<char>(c.u8());
            if (len % 2 != 0) c.u8();  // pad byte to keep the path word-aligned
            if (first) {
                path.is_symbolic = true;
                summary << text;
            } else {
                // A later symbol segment after the first is how Logix5000 encodes UDT member
                // access, e.g. "Program:Main.Timer1.ACC" is two consecutive symbol segments.
                summary << "." << text;
            }
            first = false;
        } else if ((seg & 0xE0) == 0x00) {
            // Port segment (routing, e.g. Unconnected_Send's own route path to a backplane
            // slot) -- not object addressing, rendered generically.
            unsigned port = seg & 0x0F;
            bool extended_link = (seg & 0x10) != 0;
            std::string link;
            if (extended_link) {
                uint8_t link_len = c.u8();
                link.reserve(link_len);
                for (uint8_t i = 0; i < link_len; ++i) link += static_cast<char>(c.u8());
                if (link_len % 2 != 0) c.u8();
            } else {
                link = std::to_string(static_cast<unsigned>(c.u8()));
            }
            if (!first) summary << " ";
            summary << "Port=" << port << "/" << link;
            first = false;
        } else {
            if (!first) summary << " ";
            summary << "[segment 0x" << std::hex << static_cast<unsigned>(seg) << std::dec << " not decoded]";
            break;
        }
    }

    path.summary = summary.str();
    return path;
}

// --- CIP explicit message decoding ------------------------------------------

constexpr int kMaxCipRecursionDepth = 4;      // Multiple_Service_Packet / Unconnected_Send nesting
constexpr size_t kMaxEmbeddedMessages = 25;   // per Multiple_Service_Packet
constexpr size_t kMaxCipElements = 25;        // per Read Tag / Write Tag element array

CipMessage decode_cip_message(ByteSpan bytes, int depth);  // forward declaration (mutually recursive)

// Decodes up to kMaxCipElements array elements of `type_code` starting at `c`'s current position,
// appending one rendered value per element to msg.values. For a type outside the decoded subset
// (cip_type_info returns nullopt), shows the remaining bytes as hex instead -- a recognized-but-
// out-of-scope elementary type (STRING2/STRINGN/STRINGI/EPATH/ENGUNIT-as-a-value/time-family
// types/...; STRING/SHORT_STRING and structured/UDT types are handled by their own dedicated
// decode paths before this function is ever called -- see decode_cip_string_elements/
// decode_cip_structured_element and their callers). When `type_code` isn't even a plausible
// elementary type code at all, the caller has already noted that separately and this function is
// not reached for that case (see decode_cip_response_data).
void decode_cip_typed_elements(Cursor& c, uint16_t type_code, uint16_t count, CipMessage& msg) {
    auto info = cip_type_info(type_code);
    if (!info) {
        msg.notes.push_back(cip_type_display_name(type_code) +
                             " is not value-decoded in this groundwork release -- showing "
                             "remaining bytes as hex: " +
                             to_hex(c.rest()));
        msg.data_decoded = true;
        return;
    }
    size_t decoded_count = 0;
    try {
        for (uint16_t i = 0; i < count && decoded_count < kMaxCipElements; ++i) {
            std::ostringstream s;
            switch (type_code) {
                case 0xC1: s << (c.u8() != 0 ? "1" : "0"); break;
                case 0xC2: s << static_cast<int>(static_cast<int8_t>(c.u8())); break;
                case 0xC3: s << static_cast<int16_t>(c.u16le()); break;
                case 0xC4: s << static_cast<int32_t>(c.u32le()); break;
                case 0xC5: s << static_cast<int64_t>(read_u64le(c)); break;
                case 0xC6: s << static_cast<unsigned>(c.u8()); break;
                case 0xC7: s << c.u16le(); break;
                case 0xC8: s << c.u32le(); break;
                case 0xC9: s << read_u64le(c); break;
                case 0xCA: s << read_float_le(c); break;
                case 0xCB: s << read_double_le(c); break;
                case 0xD1: s << "0x" << std::hex << std::setw(2) << std::setfill('0') << static_cast<unsigned>(c.u8()); break;
                case 0xD2: s << "0x" << std::hex << std::setw(4) << std::setfill('0') << c.u16le(); break;
                case 0xD3: s << "0x" << std::hex << std::setw(8) << std::setfill('0') << c.u32le(); break;
                case 0xD4: s << "0x" << std::hex << std::setw(16) << std::setfill('0') << read_u64le(c); break;
                default: s << "?"; break;
            }
            msg.values.push_back(s.str());
            ++decoded_count;
        }
        if (count > kMaxCipElements) {
            msg.notes.push_back("stopped after " + std::to_string(kMaxCipElements) + " of " +
                                 std::to_string(count) + " element(s) (safety cap)");
        }
        msg.data_decoded = true;
    } catch (const ParseError&) {
        msg.notes.push_back("truncated while decoding element " + std::to_string(decoded_count + 1) + " of " +
                             std::to_string(count));
    }
}

// Decodes up to `count` STRING (0xD0)/SHORT_STRING (0xDA) elements starting at `c`'s current
// position, appending one rendered value per element to msg.values -- plain decoded text, matching
// how bacnet.cpp's Character String decode embeds recognized-charset text directly with no
// quoting/escaping wrapper (JSON-format output already runs every values[] entry through
// output.cpp's own json_escape, so control bytes/quotes inside the text are handled safely there,
// not here). Unlike decode_cip_typed_elements's fixed-size types, there is no fixed per-element
// size to multiply `count` by -- each element's own length prefix says how many bytes it (and
// therefore where the next element starts) occupies. `count` is an upper bound, not a guarantee:
// a Write_Tag(_Fragmented) request carries a real, wire-declared element_count (see
// decode_write_tag_request), but a Read_Tag(_Fragmented) RESPONSE carries no element count at all
// (see decode_cip_response_data's own comment on why) -- for that caller, `count` is passed as
// 0xFFFF, a sentinel meaning "however many fit" rather than a real declared bound, and this simply
// stops when kMaxCipElements or the available bytes run out (the overwhelmingly common case being
// exactly one string).
void decode_cip_string_elements(Cursor& c, uint16_t type_code, uint16_t count, CipMessage& msg) {
    constexpr uint16_t kUnknownCount = 0xFFFF;
    size_t decoded_count = 0;
    bool truncated = false;
    try {
        for (uint16_t i = 0; i < count && decoded_count < kMaxCipElements; ++i) {
            if (c.remaining() == 0) break;
            size_t len = (type_code == 0xDA) ? c.u8() : c.u16le();
            if (len > c.remaining()) {
                truncated = true;
                break;
            }
            std::string text;
            text.reserve(len);
            for (size_t j = 0; j < len; ++j) text += static_cast<char>(c.u8());
            msg.values.push_back(text);
            ++decoded_count;
        }
    } catch (const ParseError&) {
        truncated = true;
    }
    if (truncated) {
        msg.notes.push_back("truncated while decoding " + cip_type_display_name(type_code) + " element " +
                             std::to_string(decoded_count + 1));
    }
    if (count != kUnknownCount && count > kMaxCipElements) {
        msg.notes.push_back("stopped after " + std::to_string(kMaxCipElements) + " of " + std::to_string(count) +
                             " element(s) (safety cap)");
    }
    msg.data_decoded = true;
}

// A CIP "Structured Data Type" response/request value (Rockwell Logix5000's encoding for
// reading/writing a UDT-typed -- or array-of-UDT-typed -- tag): the type code itself
// (cip_type_is_structured) is just a sentinel meaning "what follows is a 2-byte Structure Handle,
// then the raw struct instance bytes" -- it carries no size/member information on its own. This
// decoder has no access to the UDT's Template definition (member names/types/offsets), which is
// obtained separately, out of band, via a Get_Attribute_List against the Template object -- not
// something tracked across packets here -- so it stops at extracting the Structure Handle (real,
// useful metadata: it's effectively a fingerprint of the UDT's member layout) and shows the
// remaining bytes as hex rather than guessing at member boundaries. This also means an array of
// struct instances can't be split into one entry per element -- there's no way to know where one
// instance ends and the next begins without that same missing per-instance size information -- so
// the whole remaining byte range is shown as a single block. STRING2 (0xD5, double-byte character
// sets), STRINGN (0xD9), STRINGI (0xDE, international string), and EPATH/ENGUNIT (0xDC/0xDD) as an
// elementary value remain deliberately out of scope -- only STRING/SHORT_STRING and structured/UDT
// are covered.
void decode_cip_structured_element(Cursor& c, CipMessage& msg) {
    if (c.remaining() < 2) {
        msg.notes.push_back("Structured Data Type value too short for a structure handle");
        msg.data_decoded = true;
        return;
    }
    uint16_t structure_handle = c.u16le();
    msg.values.push_back("structure_handle=" + hex4(structure_handle));
    if (c.remaining() > 0) {
        msg.notes.push_back("UDT/structured member data (" + std::to_string(c.remaining()) +
                             " byte(s)) not value-decoded -- this decoder has no access to the tag's "
                             "Template definition (member names/types/offsets), obtained separately via "
                             "Get_Attribute_List against the Template object: " + to_hex(c.rest()));
    }
    msg.data_decoded = true;
}

// Shared by Multiple_Service_Packet's request AND response: the envelope (a 16-bit member/reply
// count, then that many 16-bit offsets, relative to the start of the count field, then the
// members themselves back to back) is byte-for-byte identical either way -- decode_cip_message
// itself tells a member's own request/response apart via its service byte's top bit.
void decode_multiple_service_members(CipMessage& msg, ByteSpan data, int depth) {
    if (data.size() < 2) return;
    Cursor c(data);
    uint16_t n = c.u16le();
    if (static_cast<size_t>(n) * 2 > c.remaining()) {
        msg.notes.push_back("Multiple_Service_Packet declares " + std::to_string(n) +
                             " member(s) but not enough bytes remain for the offset table");
        return;
    }
    std::vector<uint16_t> offsets;
    offsets.reserve(n);
    for (uint16_t i = 0; i < n; ++i) offsets.push_back(c.u16le());

    if (depth >= kMaxCipRecursionDepth) {
        msg.notes.push_back("Multiple_Service_Packet nesting depth cap reached -- embedded messages not decoded");
        msg.data_decoded = true;
        return;
    }

    size_t decoded = 0;
    for (uint16_t i = 0; i < n && decoded < kMaxEmbeddedMessages; ++i) {
        size_t start = offsets[i];
        size_t seg_end = (static_cast<size_t>(i) + 1 < n) ? offsets[i + 1] : data.size();
        if (start > data.size() || seg_end > data.size() || seg_end < start) {
            msg.notes.push_back("member " + std::to_string(i) + "'s offset is out of range -- skipped");
            continue;
        }
        ByteSpan member = data.subspan(start, seg_end - start);
        CipMessage sub = decode_cip_message(member, depth + 1);
        msg.values.push_back("member " + std::to_string(i) + ": " + sub.summary);
        for (const auto& note : sub.notes) {
            msg.notes.push_back("member " + std::to_string(i) + ": " + note);
        }
        ++decoded;
    }
    if (n > kMaxEmbeddedMessages) {
        msg.notes.push_back("stopped after " + std::to_string(kMaxEmbeddedMessages) + " of " + std::to_string(n) +
                             " member(s) (safety cap)");
    }
    msg.data_decoded = true;
}

void decode_write_tag_request(CipMessage& msg, ByteSpan data, bool fragmented) {
    if (data.size() < 4) return;
    Cursor c(data);
    uint16_t type_code = c.u16le();
    uint16_t count = c.u16le();
    std::ostringstream head;
    head << "type=" << cip_type_display_name(type_code) << " element_count=" << count;
    if (fragmented && c.remaining() >= 4) {
        head << " byte_offset=" << c.u32le();
    }
    msg.values.push_back(head.str());
    if (cip_type_is_structured(type_code)) {
        decode_cip_structured_element(c, msg);
    } else if (cip_type_is_variable_length_string(type_code)) {
        decode_cip_string_elements(c, type_code, count, msg);
    } else {
        decode_cip_typed_elements(c, type_code, count, msg);
    }
}

// Unconnected_Send (Connection Manager service 0x52): Priority/Time_Tick(1) + Timeout_Ticks(1) +
// Message_Request_Size(2) + that many embedded-message bytes (+1 pad byte if odd) + Route_Path_
// Size(1, words) + Reserved(1) + Route_Path(Route_Path_Size*2 bytes). The embedded message is a
// complete CIP request in its own right (usually directed at a specific backplane slot via the
// route path) -- decoded recursively with the same decode_cip_message this file uses everywhere
// else.
void decode_unconnected_send_request(CipMessage& msg, ByteSpan data, int depth) {
    if (data.size() < 4) return;
    Cursor c(data);
    uint8_t priority_time_tick = c.u8();
    uint8_t timeout_ticks = c.u8();
    uint16_t msg_req_size = c.u16le();
    if (msg_req_size > c.remaining()) {
        msg.notes.push_back("Unconnected_Send's embedded message size (" + std::to_string(msg_req_size) +
                             ") exceeds the bytes available");
        return;
    }
    ByteSpan embedded = c.bytes(msg_req_size);
    if (msg_req_size % 2 != 0 && c.remaining() > 0) c.u8();  // pad byte, word-alignment

    std::ostringstream head;
    head << "priority/time_tick=0x" << std::hex << static_cast<unsigned>(priority_time_tick) << std::dec
         << " timeout_ticks=" << static_cast<unsigned>(timeout_ticks);
    msg.values.push_back(head.str());

    if (depth < kMaxCipRecursionDepth) {
        CipMessage embedded_msg = decode_cip_message(embedded, depth + 1);
        msg.values.push_back("embedded: " + embedded_msg.summary);
        for (const auto& note : embedded_msg.notes) {
            msg.notes.push_back("embedded: " + note);
        }
    } else {
        msg.notes.push_back("Unconnected_Send nesting depth cap reached -- embedded message not decoded");
    }

    if (c.remaining() >= 2) {
        uint8_t route_path_size_words = c.u8();
        c.u8();  // reserved
        size_t route_bytes = static_cast<size_t>(route_path_size_words) * 2;
        if (route_bytes <= c.remaining()) {
            CipPath route = decode_cip_path(c, route_bytes);
            if (!route.summary.empty()) msg.values.push_back("route=" + route.summary);
        }
    }
    msg.data_decoded = true;
}

void decode_cip_request_data(uint8_t base, CipMessage& msg, ByteSpan data, int depth) {
    bool is_symbolic = msg.path.is_symbolic;
    bool is_conn_mgr = msg.path.class_id.has_value() && *msg.path.class_id == 0x06;

    if (base == 0x0A) {
        decode_multiple_service_members(msg, data, depth);
        return;
    }
    if (base == 0x52 && is_conn_mgr) {
        decode_unconnected_send_request(msg, data, depth);
        return;
    }
    if (is_symbolic && (base == 0x4C || base == 0x52)) {  // Read_Tag / Read_Tag_Fragmented
        if (data.size() >= 2) {
            Cursor c(data);
            uint16_t count = c.u16le();
            std::ostringstream s;
            s << "element_count=" << count;
            if (base == 0x52 && c.remaining() >= 4) {
                s << " byte_offset=" << c.u32le();
            }
            msg.values.push_back(s.str());
            msg.data_decoded = true;
        }
        return;
    }
    if (is_symbolic && (base == 0x4D || base == 0x53)) {  // Write_Tag / Write_Tag_Fragmented
        decode_write_tag_request(msg, data, /*fragmented=*/base == 0x53);
        return;
    }
    if (is_symbolic && base == 0x4E) {  // Read_Modify_Write_Tag: Mask_Length(2) + OR_mask + AND_mask
        if (data.size() >= 2) {
            Cursor c(data);
            uint16_t mask_len = c.u16le();
            if (static_cast<size_t>(mask_len) * 2 <= c.remaining()) {
                ByteSpan or_mask = c.bytes(mask_len);
                ByteSpan and_mask = c.bytes(mask_len);
                msg.values.push_back("OR_mask=" + to_hex(or_mask, "") + " AND_mask=" + to_hex(and_mask, ""));
                msg.data_decoded = true;
            }
        }
        return;
    }
    if (base == 0x03 && data.size() >= 2) {  // Get_Attribute_List request: count + attribute IDs
        Cursor c(data);
        uint16_t n = c.u16le();
        std::ostringstream s;
        s << "attributes=[";
        for (uint16_t i = 0; i < n && i < 50 && c.remaining() >= 2; ++i) {
            if (i != 0) s << ",";
            s << c.u16le();
        }
        s << "]";
        msg.values.push_back(s.str());
        msg.data_decoded = true;
        return;
    }
    if (!data.empty()) {
        msg.notes.push_back("request data (" + std::to_string(data.size()) +
                             " byte(s), service-specific format not decoded in this groundwork release): " +
                             to_hex(data));
    }
}

void decode_cip_response_data(uint8_t base, CipMessage& msg, ByteSpan data, int depth) {
    if (msg.general_status != 0) {
        // A non-success response's data (if any) is error/service-specific in shape -- shown as
        // hex rather than guessed at.
        if (!data.empty()) {
            msg.notes.push_back("error response data: " + to_hex(data));
        }
        return;
    }
    if (base == 0x0A) {
        decode_multiple_service_members(msg, data, depth);
        return;
    }
    if (base == 0x4C || base == 0x52) {
        // Read_Tag / Read_Tag_Fragmented reply -- see enip.hpp's file header comment's scoping
        // note: a bare response carries no request path, so whether this is really a Rockwell tag
        // read (vs. some other object class's reuse of the same service number against a
        // class/instance-addressed path) is inferred from whether the data actually starts with a
        // plausible CIP elementary type code -- a payload-shape heuristic, the same idea
        // modbus.cpp uses for request/response disambiguation (see its own header comment).
        if (data.size() >= 2) {
            Cursor c(data);
            uint16_t type_code = c.u16le();
            if (cip_is_plausible_type_code(type_code)) {
                msg.values.push_back("type=" + cip_type_display_name(type_code));
                if (cip_type_is_structured(type_code)) {
                    decode_cip_structured_element(c, msg);
                } else if (cip_type_is_variable_length_string(type_code)) {
                    decode_cip_string_elements(c, type_code, /*count=*/0xFFFF, msg);
                } else {
                    auto info = cip_type_info(type_code);
                    if (info && info->size > 0) {
                        uint16_t count = static_cast<uint16_t>(std::min<size_t>(c.remaining() / info->size, 0xFFFFu));
                        decode_cip_typed_elements(c, type_code, count, msg);
                    } else {
                        msg.notes.push_back(cip_type_display_name(type_code) +
                                             " is not value-decoded in this groundwork release -- showing "
                                             "remaining bytes as hex: " +
                                             to_hex(c.rest()));
                        msg.data_decoded = true;
                    }
                }
                return;
            }
            msg.notes.push_back(
                "response data does not start with a recognized CIP elementary type code (" + hex4(type_code) +
                ") -- this service code is likely addressed at an object other than the Rockwell Symbol "
                "object here, so its reply shape isn't known; showing raw hex: " +
                to_hex(data));
            return;
        }
        return;
    }
    if (base == 0x4E) {
        // Read_Modify_Write_Tag / Forward_Close reply: both return no data on success (confirmed
        // against a real capture -- see tests/real_captures/enip/ATTRIBUTION.md) -- nothing to decode.
        return;
    }
    if (!data.empty()) {
        msg.notes.push_back("response data (" + std::to_string(data.size()) +
                             " byte(s), service-specific format not decoded in this groundwork release): " +
                             to_hex(data));
    }
}

CipMessage decode_cip_message(ByteSpan bytes, int depth) {
    CipMessage msg;
    if (bytes.empty()) {
        msg.note = "empty CIP message";
        msg.notes.push_back(msg.note);
        msg.summary = msg.note;
        return msg;
    }

    Cursor c(bytes);
    uint8_t svc = c.u8();
    msg.service = svc;
    msg.is_response = (svc & 0x80) != 0;
    uint8_t base = svc & 0x7F;

    if (!msg.is_response) {
        if (c.remaining() < 1) {
            msg.note = "request too short for a path-size byte";
            msg.notes.push_back(msg.note);
            msg.summary = msg.note;
            return msg;
        }
        uint8_t path_size_words = c.u8();
        size_t path_bytes = static_cast<size_t>(path_size_words) * 2;
        if (path_bytes > c.remaining()) {
            msg.note = "request path size (" + std::to_string(path_bytes) + " byte(s)) exceeds the bytes available (" +
                        std::to_string(c.remaining()) + ")";
            msg.notes.push_back(msg.note);
            msg.summary = msg.note;
            return msg;
        }
        msg.path = decode_cip_path(c, path_bytes);
        msg.service_name = cip_service_name(base, /*have_path=*/true, msg.path.is_symbolic,
                                             msg.path.class_id.has_value() && *msg.path.class_id == 0x06);
        msg.decoded = true;

        std::ostringstream s;
        s << msg.service_name << " request";
        if (!msg.path.summary.empty()) s << " path=" << msg.path.summary;
        msg.summary = s.str();

        decode_cip_request_data(base, msg, c.rest(), depth);
        return msg;
    }

    // Response.
    if (c.remaining() < 3) {
        msg.note = "response too short for reserved+status+additional-status-size bytes";
        msg.notes.push_back(msg.note);
        msg.summary = msg.note;
        return msg;
    }
    c.u8();  // reserved, always 0
    msg.general_status = c.u8();
    msg.status_name = cip_general_status_name(msg.general_status);
    msg.additional_status_words = c.u8();
    size_t addl_bytes = static_cast<size_t>(msg.additional_status_words) * 2;
    if (addl_bytes > c.remaining()) {
        msg.note = "additional status size (" + std::to_string(addl_bytes) + " byte(s)) exceeds the bytes available (" +
                    std::to_string(c.remaining()) + ")";
        msg.notes.push_back(msg.note);
        msg.summary = msg.note;
        return msg;
    }
    c.skip(addl_bytes);  // additional status code(s) -- vendor/service-specific, not decoded
    msg.service_name = cip_service_name(base, /*have_path=*/false, false, false);
    msg.decoded = true;

    std::ostringstream s;
    s << msg.service_name << " response: " << msg.status_name;
    msg.summary = s.str();

    decode_cip_response_data(base, msg, c.rest(), depth);
    return msg;
}

// --- ListIdentity response decoding -----------------------------------------

// Decodes a ListIdentity response's single List Identity Item (CPF item type 0x000C): protocol
// version, a "socket address" structure (network/big-endian byte order -- the one documented
// exception to EtherNet/IP's otherwise all-little-endian wire format, same as a raw BSD
// sockaddr_in; not surfaced, since it's redundant with this packet's own source IP/port), then
// the same vendor ID/device type/product code/revision/status/serial number/product name fields
// as the Identity object's Get_Attributes_All response -- see enip.hpp's file header comment.
void decode_list_identity_response(ByteSpan encap_data, EnipFrame& frame) {
    Cursor c(encap_data);
    if (c.remaining() < 2) return;
    uint16_t item_count = c.u16le();
    if (item_count == 0 || c.remaining() < 4) return;
    uint16_t item_type = c.u16le();
    uint16_t item_len = c.u16le();
    if (item_len > c.remaining()) return;
    ByteSpan item = c.bytes(item_len);

    if (item_type != 0x000C) {
        frame.notes.push_back("ListIdentity response's first item is type " + hex4(item_type) +
                               ", not the expected List Identity Item (0x000C) -- not decoded");
        return;
    }

    try {
        Cursor ic(item);
        ic.u16le();  // protocol version -- not surfaced
        ic.u16be();  // sin_family -- not surfaced (always AF_INET=2)
        ic.u16be();  // sin_port -- not surfaced (redundant with this packet's own TCP source port)
        ic.u32be();  // sin_addr -- not surfaced (redundant with this packet's own source IP)
        ic.skip(8);  // sin_zero
        uint16_t vendor_id = ic.u16le();
        uint16_t device_type = ic.u16le();
        uint16_t product_code = ic.u16le();
        uint8_t rev_major = ic.u8();
        uint8_t rev_minor = ic.u8();
        uint16_t status = ic.u16le();
        uint32_t serial = ic.u32le();
        uint8_t name_len = ic.u8();
        std::string name;
        name.reserve(name_len);
        for (uint8_t i = 0; i < name_len && !ic.at_end(); ++i) name += static_cast<char>(ic.u8());

        frame.has_identity = true;
        frame.identity_vendor_id = vendor_id;
        frame.identity_device_type = device_type;
        frame.identity_product_code = product_code;
        frame.identity_revision = std::to_string(static_cast<unsigned>(rev_major)) + "." +
                                   std::to_string(static_cast<unsigned>(rev_minor));
        frame.identity_status = status;
        frame.identity_serial_number = serial;
        frame.identity_product_name = name;

        std::ostringstream s;
        s << "; identity: vendor=" << vendor_id << " device_type=" << device_type << " product_code=" << product_code
          << " rev=" << frame.identity_revision << " serial=0x" << std::hex << serial << std::dec << " name=\""
          << name << "\"";
        frame.summary += s.str();
    } catch (const ParseError& e) {
        frame.notes.push_back("truncated while decoding the List Identity item: " + std::string(e.what()));
    }
}

// --- Common Packet Format (CPF) + CIP dispatch ------------------------------

void decode_cpf_and_cip(ByteSpan encap_data, EnipFrame& frame) {
    if (encap_data.size() < 6) {
        frame.notes.push_back(
            "SendRRData/SendUnitData encapsulated data too short for interface handle + timeout + item count");
        return;
    }
    Cursor c(encap_data);
    c.u32le();  // interface handle -- always 0 for CIP, not surfaced
    c.u16le();  // timeout -- informational only, not surfaced
    uint16_t item_count = c.u16le();

    constexpr size_t kMaxCpfItems = 20;
    ByteSpan cip_bytes;
    bool have_cip_bytes = false;

    for (uint16_t i = 0; i < item_count && i < kMaxCpfItems; ++i) {
        if (c.remaining() < 4) break;
        uint16_t type = c.u16le();
        uint16_t len = c.u16le();
        if (len > c.remaining()) {
            frame.notes.push_back("CPF item type " + hex4(type) + " declares " + std::to_string(len) +
                                   " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan item = c.bytes(len);
        switch (type) {
            case 0x0000:  // Null Address Item
                break;
            case 0x00A1:  // Connected Address Item -- 4-byte connection ID
                if (item.size() >= 4) {
                    Cursor ic(item);
                    frame.connection_id = ic.u32le();
                }
                break;
            case 0x00B2:  // Unconnected Data Item -- the CIP message itself
                cip_bytes = item;
                have_cip_bytes = true;
                break;
            case 0x00B1:  // Connected Data Item -- 2-byte sequence number, then the CIP message
                if (item.size() >= 2) {
                    cip_bytes = item.from(2);
                    have_cip_bytes = true;
                }
                break;
            case 0x8000:
            case 0x8001:
                frame.notes.push_back("CPF item " + hex4(type) + " (Sockaddr Info) present, not decoded");
                break;
            case 0x8002:
                frame.notes.push_back("CPF item 0x8002 (Sequenced Address) present, not decoded");
                break;
            default:
                frame.notes.push_back("CPF item type " + hex4(type) + " (" + std::to_string(len) +
                                       " byte(s)) not decoded");
                break;
        }
    }
    if (item_count > kMaxCpfItems) {
        frame.notes.push_back("stopped after " + std::to_string(kMaxCpfItems) + " CPF item(s) (safety cap)");
    }

    if (!have_cip_bytes || cip_bytes.empty()) {
        return;
    }

    frame.cip = decode_cip_message(cip_bytes, /*depth=*/0);
    frame.has_cip = true;
    if (!frame.cip.summary.empty()) {
        frame.summary += "; " + frame.cip.summary;
    }
}

// --- CIP I/O (implicit messaging) decoding, UDP port 2222 -------------------

constexpr size_t kMaxCipIoCpfItems = 20;  // same cap as decode_cpf_and_cip's kMaxCpfItems

std::optional<CipIoFrame> try_parse_cip_io_impl(ByteSpan udp_payload) {
    // Item count (2) + first item's type (2) + length (2) + the Sequenced Address Item's own
    // 8-byte body -- the minimum for this function's structural detection anchor to even be
    // checkable at all (see try_parse_cip_io's header comment in enip.hpp).
    if (udp_payload.size() < 14) {
        return std::nullopt;
    }
    Cursor c(udp_payload);
    uint16_t item_count = c.u16le();
    if (item_count == 0) {
        return std::nullopt;
    }
    uint16_t first_type = c.u16le();
    uint16_t first_len = c.u16le();
    if (first_type != 0x8002 || first_len != 8) {
        // Not a Sequenced Address Item of the exact fixed size ODVA mandates -- either not CIP I/O
        // at all, or a shape this "first pass" doesn't recognize (see enip.hpp's file header
        // comment's CIP implicit messaging section). Deliberately declines to guess.
        return std::nullopt;
    }

    CipIoFrame frame;
    frame.connection_id = c.u32le();
    frame.sequence_number = c.u32le();

    for (uint16_t i = 1; i < item_count && i < kMaxCipIoCpfItems; ++i) {
        if (c.remaining() < 4) break;
        uint16_t type = c.u16le();
        uint16_t len = c.u16le();
        if (len > c.remaining()) {
            frame.notes.push_back("CPF item type " + hex4(type) + " declares " + std::to_string(len) +
                                   " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan item = c.bytes(len);
        switch (type) {
            case 0x00B1:  // Connected Data Item -- the I/O/assembly data itself
                frame.has_io_data = true;
                frame.io_data_hex = to_hex(item, "");
                frame.io_data_length = item.size();
                break;
            case 0x8000:
            case 0x8001:
                frame.notes.push_back("CPF item " + hex4(type) + " (Sockaddr Info) present, not decoded");
                break;
            case 0x00B2:  // Unconnected Data Item -- not expected on connected I/O traffic, but
                           // handled the same generic way rather than mis-parsed as I/O data
                frame.notes.push_back("CPF item 0x00B2 (Unconnected Data) present, not expected for "
                                       "connected I/O traffic -- not decoded");
                break;
            default:
                frame.notes.push_back("CPF item type " + hex4(type) + " (" + std::to_string(len) +
                                       " byte(s)) not decoded");
                break;
        }
    }
    if (item_count > kMaxCipIoCpfItems) {
        frame.notes.push_back("stopped after " + std::to_string(kMaxCipIoCpfItems) + " CPF item(s) (safety cap)");
    }

    std::ostringstream s;
    s << "CIP I/O (implicit messaging): connection_id=0x" << std::hex << std::uppercase << frame.connection_id
      << std::dec << " sequence=" << frame.sequence_number;
    if (frame.has_io_data) {
        s << " data=" << frame.io_data_length << " byte(s)";
    } else {
        s << " (no Connected Data Item present)";
    }
    frame.summary = s.str();
    return frame;
}

}  // namespace

// CIP service codes above the generic-common-services range (0x32+) are class-specific -- the
// same number means different things to different object classes. `have_path`/`is_symbolic`/
// `is_conn_mgr` disambiguate the two collisions this decoder's "first pass" scope actually cares
// about (see enip.hpp's file header comment's scoping note): 0x4E (Forward_Close for the
// Connection Manager object vs. Read_Modify_Write_Tag for a Rockwell Symbol-object tag) and 0x52
// (Unconnected_Send for the Connection Manager object vs. Read_Tag_Fragmented for a tag). For a
// response (have_path == false, since a response never repeats the request's path on the wire),
// only those two ambiguous codes are called out as such; every other tag-service/Connection-
// Manager-service code is unambiguous even without a path.
//
// Moved out of this file's own anonymous namespace (it used to live there, alongside every other
// enip.cpp-local naming table) and declared in enip.hpp specifically so devicenet.cpp can call it
// directly -- see enip.hpp's own comment on this function. devicenet.cpp always passes
// have_path=true, is_symbolic=false, is_conn_mgr=false (DeviceNet's own Group 3 explicit
// messaging has no EtherNet/IP-style embedded request path for this decoder to have parsed --
// see devicenet.hpp's file header comment's CIP scoping note), which -- by this function's own
// control flow -- skips both the is_symbolic and is_conn_mgr tag/Connection-Manager-specific
// tables entirely and falls straight through to the generic common-services switch below. That is
// deliberate: it means DeviceNet never accidentally picks up an EtherNet/IP-Rockwell-specific name
// (e.g. "Read_Tag" for 0x4C) for a service code DeviceNet itself defines completely differently
// (0x4C is "Close Connection Request" in DeviceNet -- see devicenet.hpp) -- devicenet.cpp checks
// its own small DeviceNet-specific table FIRST, before ever calling this function at all.
std::string cip_service_name(uint8_t base, bool have_path, bool is_symbolic, bool is_conn_mgr) {
    if (have_path) {
        if (is_symbolic) {
            switch (base) {
                case 0x4C: return "Read_Tag";
                case 0x4D: return "Write_Tag";
                case 0x4E: return "Read_Modify_Write_Tag";
                case 0x52: return "Read_Tag_Fragmented";
                case 0x53: return "Write_Tag_Fragmented";
                case 0x55: return "Get_Instance_Attribute_List";
                default: break;
            }
        }
        if (is_conn_mgr) {
            switch (base) {
                case 0x52: return "Unconnected_Send";
                case 0x54: return "Forward_Open";
                case 0x4E: return "Forward_Close";
                case 0x5B: return "Large_Forward_Open";
                default: break;
            }
        }
    } else {
        if (base == 0x52) return "Unconnected_Send/Read_Tag_Fragmented (reply)";
        if (base == 0x4E) return "Forward_Close/Read_Modify_Write_Tag (reply)";
        switch (base) {
            case 0x4C: return "Read_Tag";
            case 0x4D: return "Write_Tag";
            case 0x53: return "Write_Tag_Fragmented";
            case 0x55: return "Get_Instance_Attribute_List";
            case 0x54: return "Forward_Open";
            case 0x5B: return "Large_Forward_Open";
            default: break;
        }
    }
    switch (base) {
        case 0x01: return "Get_Attributes_All";
        case 0x02: return "Set_Attributes_All";
        case 0x03: return "Get_Attribute_List";
        case 0x04: return "Set_Attribute_List";
        case 0x05: return "Reset";
        case 0x06: return "Start";
        case 0x07: return "Stop";
        case 0x08: return "Create";
        case 0x09: return "Delete";
        case 0x0A: return "Multiple_Service_Packet";
        case 0x0D: return "Apply_Attributes";
        case 0x0E: return "Get_Attribute_Single";
        case 0x10: return "Set_Attribute_Single";
        case 0x11: return "Find_Next_Object_Instance";
        case 0x15: return "Restore";
        case 0x16: return "Save";
        case 0x17: return "No_Op";
        case 0x18: return "Get_Member";
        case 0x19: return "Set_Member";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << std::uppercase << static_cast<unsigned>(base) << ")";
            return s.str();
        }
    }
}

std::vector<std::string> enip_known_cip_service_names() {
    std::vector<std::string> out;
    auto add_unique = [&](const std::string& name) {
        if (std::find(out.begin(), out.end(), name) == out.end()) out.push_back(name);
    };
    // Rockwell Symbol-object (named-tag) request services -- have_path=true, is_symbolic=true.
    for (uint8_t base : {uint8_t{0x4C}, uint8_t{0x4D}, uint8_t{0x4E}, uint8_t{0x52}, uint8_t{0x53}, uint8_t{0x55}}) {
        add_unique(cip_service_name(base, /*have_path=*/true, /*is_symbolic=*/true, /*is_conn_mgr=*/false));
    }
    // Connection Manager-directed request services -- have_path=true, is_conn_mgr=true.
    for (uint8_t base : {uint8_t{0x52}, uint8_t{0x54}, uint8_t{0x4E}, uint8_t{0x5B}}) {
        add_unique(cip_service_name(base, /*have_path=*/true, /*is_symbolic=*/false, /*is_conn_mgr=*/true));
    }
    // Reply-direction names (have_path=false) -- includes the two genuinely ambiguous "A/B
    // (reply)" strings alongside the unambiguous reply-side names; see this function's own header
    // comment in enip.hpp's KNOWN LIMITATION paragraph.
    for (uint8_t base : {uint8_t{0x52}, uint8_t{0x4E}, uint8_t{0x4C}, uint8_t{0x4D}, uint8_t{0x53}, uint8_t{0x55},
                          uint8_t{0x54}, uint8_t{0x5B}}) {
        add_unique(cip_service_name(base, /*have_path=*/false, false, false));
    }
    // Generic common services (CIP Volume 1) -- unambiguous regardless of path/object.
    for (uint8_t base : {uint8_t{0x01}, uint8_t{0x02}, uint8_t{0x03}, uint8_t{0x04}, uint8_t{0x05}, uint8_t{0x06},
                          uint8_t{0x07}, uint8_t{0x08}, uint8_t{0x09}, uint8_t{0x0A}, uint8_t{0x0D}, uint8_t{0x0E},
                          uint8_t{0x10}, uint8_t{0x11}, uint8_t{0x15}, uint8_t{0x16}, uint8_t{0x17}, uint8_t{0x18},
                          uint8_t{0x19}}) {
        add_unique(cip_service_name(base, /*have_path=*/false, /*is_symbolic=*/false, /*is_conn_mgr=*/false));
    }
    return out;
}

std::optional<size_t> enip_declared_length(ByteSpan payload) {
    if (payload.size() < 4) {
        return std::nullopt;
    }
    Cursor c(payload);
    uint16_t command = c.u16le();
    if (enip_command_name(command).empty()) {
        return std::nullopt;
    }
    uint16_t length = c.u16le();
    return 24 + static_cast<size_t>(length);
}

std::optional<EnipFrame> try_parse_enip(ByteSpan tcp_payload) {
    if (tcp_payload.size() < 24) {
        return std::nullopt;
    }

    Cursor c(tcp_payload);
    EnipHeader h;
    h.command = c.u16le();
    h.command_name = enip_command_name(h.command);
    if (h.command_name.empty()) {
        return std::nullopt;
    }
    h.length = c.u16le();
    h.session_handle = c.u32le();
    h.status = c.u32le();
    h.status_name = enip_status_name(h.status);
    if (h.status_name.empty()) {
        // Not one of the documented encapsulation status codes -- the second of the two
        // independent structural checks (alongside the command enum) that make this detection
        // strong even though it, like every other protocol here, runs port-independently. See
        // this function's header comment in enip.hpp.
        return std::nullopt;
    }
    h.sender_context = read_u64le(c);
    h.options = c.u32le();
    if (h.options != 0) {
        // Reserved, spec-mandated 0 -- the third independent structural check.
        return std::nullopt;
    }

    EnipFrame frame;
    frame.header = h;
    frame.wire_length = 24 + static_cast<size_t>(h.length);

    std::ostringstream s;
    s << h.command_name;
    if (h.status != 0) s << " [status=" << h.status_name << "]";
    frame.summary = s.str();

    size_t available = tcp_payload.size() >= 24 ? tcp_payload.size() - 24 : 0;
    size_t encap_len = std::min(static_cast<size_t>(h.length), available);
    if (encap_len < h.length) {
        frame.notes.push_back("declared length (" + std::to_string(h.length) + ") exceeds the bytes actually "
                               "available (" + std::to_string(available) + ") -- decoding what's present");
    }
    ByteSpan encap_data = tcp_payload.subspan(24, encap_len);

    try {
        if (h.command == 0x0063 && !encap_data.empty()) {  // ListIdentity response (a request carries no data)
            decode_list_identity_response(encap_data, frame);
        } else if ((h.command == 0x006F || h.command == 0x0070) && !encap_data.empty()) {  // SendRRData/SendUnitData
            decode_cpf_and_cip(encap_data, frame);
        } else if (h.command == 0x0065 && encap_data.size() >= 4) {  // RegisterSession
            Cursor rc(encap_data);
            uint16_t proto_version = rc.u16le();
            uint16_t options_flags = rc.u16le();
            std::ostringstream rs;
            rs << "; protocol version " << proto_version << ", options flags " << hex4(options_flags);
            frame.summary += rs.str();
        }
    } catch (const ParseError& e) {
        frame.notes.push_back("truncated while decoding encapsulated data: " + std::string(e.what()));
    }

    return frame;
}

std::optional<CipIoFrame> try_parse_cip_io(ByteSpan udp_payload) {
    try {
        return try_parse_cip_io_impl(udp_payload);
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // try_parse_enip's own dispatch takes around decode_cpf_and_cip/decode_list_identity_response.
        return std::nullopt;
    }
}

// --- Migration batch 2: EnipTcpDecoder/EnipUdpDecoder (registration-model interface) -----------
//
// decode() is an exact behavioral transplant of the removed decoder.cpp `if (want_enip) { ... }`
// (TCP) call site's body -- the same-payload multi-message coalescing loop (it's normal for a
// sender/OS to coalesce several small encapsulation messages into one TCP segment before
// flushing, like IEC104/DNP3's own APDUs/frames) plus the merge-CIP-fields logic, both moved here
// unchanged, INCLUDING the legacy asymmetry noted in EnipResult's own comment: only the first
// message's top-level `notes` are folded in, every message's `cip.notes` are. `ctx` is unused:
// EtherNet/IP explicit messaging is purely stateless, unlike Dnp3Decoder/CotpDecoder.
std::optional<ProtocolResult> EnipTcpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_enip(payload);
    if (!frame) {
        return std::nullopt;
    }

    EnipResult result;
    result.summary = frame->summary;
    for (const auto& n : frame->notes) result.notes.push_back(n);

    constexpr size_t kMaxCipValues = 50;
    std::vector<std::string> merged_values;
    auto merge_cip = [&](const EnipFrame& f) {
        if (!f.has_cip) return;
        for (const auto& n : f.cip.notes) result.notes.push_back(n);
        for (const auto& v : f.cip.values) {
            if (merged_values.size() >= kMaxCipValues) break;
            merged_values.push_back(v);
        }
    };
    merge_cip(*frame);

    // Like IEC104/DNP3, one encapsulation message is small and it's normal for a sender or the OS
    // to coalesce several into one TCP segment before flushing.
    constexpr size_t kMaxEnipMessagesPerPayload = 50;
    size_t offset = frame->wire_length;
    size_t message_count = 1;
    while (offset < payload.size() && message_count < kMaxEnipMessagesPerPayload) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_enip(rest);
        if (!next) break;  // remaining bytes aren't another EtherNet/IP message -- stop, don't guess
        ++message_count;
        std::string note = "additional EtherNet/IP message " + std::to_string(message_count) +
                            " found in the same TCP payload at byte offset " + std::to_string(offset) +
                            " (coalesced by the sender/OS): " + next->summary;
        result.notes.push_back(note);
        merge_cip(*next);
        offset += next->wire_length;
    }
    if (message_count >= kMaxEnipMessagesPerPayload) {
        result.notes.push_back("stopped after " + std::to_string(kMaxEnipMessagesPerPayload) +
                                " EtherNet/IP message(s) in this one TCP payload, more may remain "
                                "(safety cap)");
    }

    result.first = *frame;
    result.first.cip.values = merged_values;  // cumulative across every coalesced message, capped

    return ProtocolResult::make<EnipResult>("enip", std::move(result));
}

// CIP I/O (UDP) needs no coalescing or per-field merging of its own -- see this class's own
// comment in enip.hpp -- so decode() is a direct pass-through onto try_parse_cip_io. `ctx` is
// unused for the same reason EnipTcpDecoder's is.
std::optional<ProtocolResult> EnipUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto io = try_parse_cip_io(payload);
    if (!io) {
        return std::nullopt;
    }
    return ProtocolResult::make<CipIoFrame>("enip", std::move(*io));
}

const ProtocolDecoder& enip_tcp_decoder() {
    static const EnipTcpDecoder instance;
    return instance;
}

const ProtocolDecoder& enip_udp_decoder() {
    static const EnipUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
