// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/mqtt.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Small formatting helpers (mirrors opcua.cpp's own format_double/bits_to_* style).

std::string format_double(double v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

float bits_to_float(uint32_t bits) {
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

double bits_to_double(uint64_t bits) {
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

std::string to_hex_byte(uint8_t b) {
    std::ostringstream s;
    s << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(b);
    return s.str();
}

// format_millis_epoch is declared in mqtt.hpp (not anonymous-namespace-local) and defined below,
// after this anonymous namespace closes, specifically so dnp3.cpp can call it directly to render
// DNP3's own milliseconds-since-epoch absolute time format -- see mqtt.hpp's own comment on it.

// ------------------------------------------------------------------------------------------
// MQTT Variable Byte Integer (VBI) -- 7 payload bits/byte, MSB continuation flag, least-
// significant byte first, 1-4 bytes -- see mqtt.hpp's file header comment. Used for Remaining
// Length, MQTT5 Property Length, and (per spec, though practically always a single byte) each
// Property Identifier.

// Non-throwing variant over a raw ByteSpan/offset, for mqtt_declared_length's own use before a
// Cursor-worthy amount of the message is even known to be present.
bool decode_vbi_raw(ByteSpan payload, size_t start, uint32_t& value, size_t& consumed) {
    value = 0;
    uint32_t multiplier = 1;
    consumed = 0;
    for (int i = 0; i < 4; ++i) {
        if (start + consumed >= payload.size()) return false;  // not enough bytes yet
        uint8_t b = payload.at(start + consumed);
        value += static_cast<uint32_t>(b & 0x7F) * multiplier;
        ++consumed;
        if ((b & 0x80) == 0) return true;
        multiplier *= 128;
    }
    return false;  // 4 bytes read, still continuing -- malformed (exceeds the 268,435,455 max)
}

uint32_t read_mqtt_vbi(Cursor& c) {
    uint32_t value = 0;
    uint32_t multiplier = 1;
    for (int i = 0; i < 4; ++i) {
        uint8_t b = c.u8();
        value += static_cast<uint32_t>(b & 0x7F) * multiplier;
        if ((b & 0x80) == 0) return value;
        multiplier *= 128;
    }
    throw ParseError("MQTT variable byte integer exceeds 4 bytes (malformed)");
}

std::string read_utf8_string(Cursor& c) {
    uint16_t len = c.u16be();
    ByteSpan s = c.bytes(len);
    return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

ByteSpan read_binary(Cursor& c) {
    uint16_t len = c.u16be();
    return c.bytes(len);
}

// ------------------------------------------------------------------------------------------
// Fixed header gate -- see mqtt.hpp's "structural detection gate" paragraph.

std::string mqtt_packet_type_name(uint8_t type) {
    switch (type) {
        case 1: return "CONNECT";
        case 2: return "CONNACK";
        case 3: return "PUBLISH";
        case 4: return "PUBACK";
        case 5: return "PUBREC";
        case 6: return "PUBREL";
        case 7: return "PUBCOMP";
        case 8: return "SUBSCRIBE";
        case 9: return "SUBACK";
        case 10: return "UNSUBSCRIBE";
        case 11: return "UNSUBACK";
        case 12: return "PINGREQ";
        case 13: return "PINGRESP";
        case 14: return "DISCONNECT";
        case 15: return "AUTH";
        default: return "unknown(" + std::to_string(type) + ")";
    }
}

bool flags_valid_for_type(uint8_t type, uint8_t flags) {
    switch (type) {
        case 3: return true;  // PUBLISH: DUP/QoS/RETAIN -- every value structurally valid
        case 6: case 8: case 10: return flags == 0x02;  // PUBREL/SUBSCRIBE/UNSUBSCRIBE: fixed
        case 1: case 2: case 4: case 5: case 7: case 9: case 11: case 12: case 13: case 14: case 15:
            return flags == 0x00;
        default: return false;  // 0 is always reserved; >15 impossible from a 4-bit nibble anyway
    }
}

// ------------------------------------------------------------------------------------------
// Reason/return code names. v3.1.1 CONNACK uses its own small, unrelated numbering; every other
// packet type shares MQTT5's single unified Reason Code namespace (OASIS MQTT5 OS ~Table 2-4 area/
// per-packet-type sections cited in mqtt.hpp's file header comment) -- a v3.1.1 SUBACK/PUBACK/etc
// never actually reaches this table anyway, since those only carry a byte beyond the packet
// identifier when the message is v5-shaped (Remaining Length > the v3.1.1-only minimum) in the
// first place -- see mqtt.hpp's "Version disambiguation" section.

std::string connack_return_code_name_v311(uint8_t code) {
    switch (code) {
        case 0: return "Connection Accepted";
        case 1: return "Connection Refused, unacceptable protocol version";
        case 2: return "Connection Refused, identifier rejected";
        case 3: return "Connection Refused, Server unavailable";
        case 4: return "Connection Refused, bad user name or password";
        case 5: return "Connection Refused, not authorized";
        default: return "invalid(" + std::to_string(code) + ")";
    }
}

std::string suback_code_name(uint8_t code, bool v5) {
    if (!v5) {
        switch (code) {
            case 0x00: return "Granted QoS 0";
            case 0x01: return "Granted QoS 1";
            case 0x02: return "Granted QoS 2";
            case 0x80: return "Failure";
            default: return "invalid(" + std::to_string(code) + ")";
        }
    }
    switch (code) {
        case 0x00: return "Granted QoS 0";
        case 0x01: return "Granted QoS 1";
        case 0x02: return "Granted QoS 2";
        case 0x80: return "Unspecified error";
        case 0x83: return "Implementation specific error";
        case 0x87: return "Not authorized";
        case 0x8F: return "Topic Filter invalid";
        case 0x91: return "Packet Identifier in use";
        case 0x97: return "Quota exceeded";
        case 0x9E: return "Shared Subscriptions not supported";
        case 0xA1: return "Subscription Identifiers not supported";
        case 0xA2: return "Wildcard Subscriptions not supported";
        default: return "unrecognized(0x" + to_hex_byte(code) + ")";
    }
}

std::string mqtt5_reason_code_name(uint8_t code) {
    switch (code) {
        case 0x00: return "Success";  // also "Normal disconnection" (DISCONNECT) / "Granted QoS 0" (SUBACK)
        case 0x01: return "Granted QoS 1";
        case 0x02: return "Granted QoS 2";
        case 0x04: return "Disconnect with Will Message";
        case 0x10: return "No matching subscribers";
        case 0x11: return "No subscription existed";
        case 0x18: return "Continue authentication";
        case 0x19: return "Re-authenticate";
        case 0x80: return "Unspecified error";
        case 0x81: return "Malformed Packet";
        case 0x82: return "Protocol Error";
        case 0x83: return "Implementation specific error";
        case 0x84: return "Unsupported Protocol Version";
        case 0x85: return "Client Identifier not valid";
        case 0x86: return "Bad User Name or Password";
        case 0x87: return "Not authorized";
        case 0x88: return "Server unavailable";
        case 0x89: return "Server busy";
        case 0x8A: return "Banned";
        case 0x8B: return "Server shutting down";
        case 0x8C: return "Bad authentication method";
        case 0x8D: return "Keep Alive timeout";
        case 0x8E: return "Session taken over";
        case 0x8F: return "Topic Filter invalid";
        case 0x90: return "Topic Name invalid";
        case 0x91: return "Packet Identifier in use";
        case 0x92: return "Packet Identifier not found";
        case 0x93: return "Receive Maximum exceeded";
        case 0x94: return "Topic Alias invalid";
        case 0x95: return "Packet too large";
        case 0x96: return "Message rate too high";
        case 0x97: return "Quota exceeded";
        case 0x98: return "Administrative action";
        case 0x99: return "Payload format invalid";
        case 0x9A: return "Retain not supported";
        case 0x9B: return "QoS not supported";
        case 0x9C: return "Use another server";
        case 0x9D: return "Server moved";
        case 0x9E: return "Shared Subscriptions not supported";
        case 0x9F: return "Connection rate exceeded";
        case 0xA0: return "Maximum connect time";
        case 0xA1: return "Subscription Identifiers not supported";
        case 0xA2: return "Wildcard Subscriptions not supported";
        default: return "unrecognized(0x" + to_hex_byte(code) + ")";
    }
}

// ------------------------------------------------------------------------------------------
// MQTT5 Properties -- one generic, table-driven decoder covers every Property Identifier this
// decoder recognizes (all 27 defined in the spec, per mqtt.hpp's file header comment) so no
// property needs its own hand-written decode function.

enum class PropType { Byte, U16, U32, Vbi, Str, StrPair, Bin };

struct PropertyDef {
    uint32_t id;
    const char* name;
    PropType type;
};

constexpr PropertyDef kPropertyTable[] = {
    {1, "PayloadFormatIndicator", PropType::Byte},
    {2, "MessageExpiryInterval", PropType::U32},
    {3, "ContentType", PropType::Str},
    {8, "ResponseTopic", PropType::Str},
    {9, "CorrelationData", PropType::Bin},
    {11, "SubscriptionIdentifier", PropType::Vbi},
    {17, "SessionExpiryInterval", PropType::U32},
    {18, "AssignedClientIdentifier", PropType::Str},
    {19, "ServerKeepAlive", PropType::U16},
    {21, "AuthenticationMethod", PropType::Str},
    {22, "AuthenticationData", PropType::Bin},
    {23, "RequestProblemInformation", PropType::Byte},
    {24, "WillDelayInterval", PropType::U32},
    {25, "RequestResponseInformation", PropType::Byte},
    {26, "ResponseInformation", PropType::Str},
    {28, "ServerReference", PropType::Str},
    {31, "ReasonString", PropType::Str},
    {33, "ReceiveMaximum", PropType::U16},
    {34, "TopicAliasMaximum", PropType::U16},
    {35, "TopicAlias", PropType::U16},
    {36, "MaximumQoS", PropType::Byte},
    {37, "RetainAvailable", PropType::Byte},
    {38, "UserProperty", PropType::StrPair},
    {39, "MaximumPacketSize", PropType::U32},
    {40, "WildcardSubscriptionAvailable", PropType::Byte},
    {41, "SubscriptionIdentifiersAvailable", PropType::Byte},
    {42, "SharedSubscriptionAvailable", PropType::Byte},
};

const PropertyDef* lookup_property(uint32_t id) {
    for (const auto& def : kPropertyTable) {
        if (def.id == id) return &def;
    }
    return nullptr;
}

// Reads a Property Length VBI followed by that many bytes of Property Identifier + Property Value
// pairs, appending one "Name=value" (or "Name: \"key\"=\"value\"" for a UserProperty pair) string
// per property to `out`. An unrecognized Property Identifier means this decoder cannot know that
// property's own value shape, so it CANNOT safely keep parsing the rest of the block byte-aligned
// -- rather than guessing, it stops there and shows the remainder as raw hex (an honest, contained
// failure, mirroring this codebase's other "can't proceed past an unknown length-bearing field"
// fallbacks).
void decode_properties(Cursor& c, std::vector<std::string>& out) {
    uint32_t prop_len = read_mqtt_vbi(c);
    if (prop_len == 0) return;
    ByteSpan prop_bytes = c.bytes(prop_len);
    Cursor pc(prop_bytes);
    while (!pc.at_end()) {
        uint32_t id = read_mqtt_vbi(pc);
        const PropertyDef* def = lookup_property(id);
        if (!def) {
            ByteSpan rest = pc.bytes(pc.remaining());
            out.push_back("(unknown property id " + std::to_string(id) + ", " +
                           std::to_string(rest.size()) + " remaining properties byte(s) not decoded: " +
                           to_hex(rest) + ")");
            return;
        }
        switch (def->type) {
            case PropType::Byte:
                out.push_back(std::string(def->name) + "=" + std::to_string(static_cast<unsigned>(pc.u8())));
                break;
            case PropType::U16:
                out.push_back(std::string(def->name) + "=" + std::to_string(pc.u16be()));
                break;
            case PropType::U32:
                out.push_back(std::string(def->name) + "=" + std::to_string(pc.u32be()));
                break;
            case PropType::Vbi:
                out.push_back(std::string(def->name) + "=" + std::to_string(read_mqtt_vbi(pc)));
                break;
            case PropType::Str:
                out.push_back(std::string(def->name) + "=\"" + read_utf8_string(pc) + "\"");
                break;
            case PropType::StrPair: {
                std::string key = read_utf8_string(pc);
                std::string value = read_utf8_string(pc);
                out.push_back(std::string(def->name) + ": \"" + key + "\"=\"" + value + "\"");
                break;
            }
            case PropType::Bin: {
                ByteSpan bin = read_binary(pc);
                out.push_back(std::string(def->name) + "=<" + std::to_string(bin.size()) + " byte(s)>");
                break;
            }
        }
    }
}

// ------------------------------------------------------------------------------------------
// SUBSCRIBE/UNSUBSCRIBE topic-filter list parsing (also used by the SUBSCRIBE/UNSUBSCRIBE version-
// disambiguation heuristic below to validate a candidate shape -- see mqtt.hpp's "Version
// disambiguation" section).

struct TopicFilterList {
    bool ok = false;
    std::vector<std::string> rendered;
};

TopicFilterList try_read_topic_filters(Cursor& c, bool is_v5) {
    TopicFilterList result;
    std::vector<std::string> out;
    try {
        if (c.at_end()) return result;  // a SUBSCRIBE always carries at least one filter
        while (!c.at_end()) {
            std::string filter = read_utf8_string(c);
            uint8_t opts = c.u8();
            std::ostringstream s;
            s << "TopicFilter=\"" << filter << "\" QoS=" << static_cast<unsigned>(opts & 0x03);
            if (is_v5) {
                if (opts & 0x04) s << " NoLocal";
                if (opts & 0x08) s << " RetainAsPublished";
                s << " RetainHandling=" << static_cast<unsigned>((opts >> 4) & 0x03);
            }
            out.push_back(s.str());
        }
    } catch (const ParseError&) {
        return result;
    }
    result.ok = true;
    result.rendered = out;
    return result;
}

std::vector<std::string> try_read_plain_strings(Cursor& c) {
    std::vector<std::string> out;
    try {
        if (c.at_end()) return {};  // an UNSUBSCRIBE always carries at least one filter
        while (!c.at_end()) {
            out.push_back(read_utf8_string(c));
        }
    } catch (const ParseError&) {
        return {};
    }
    return out;
}

// ------------------------------------------------------------------------------------------
// Sparkplug B -- topic namespace parsing. See mqtt.hpp's file header comment's "Sparkplug B"
// section.

struct SparkplugTopicParts {
    std::string group_id, message_type, edge_node_id, device_id;
    bool is_state = false;
    std::string state_host_id;
};

std::optional<SparkplugTopicParts> parse_sparkplug_topic(const std::string& topic) {
    std::vector<std::string> parts;
    size_t start = 0;
    while (true) {
        size_t slash = topic.find('/', start);
        if (slash == std::string::npos) {
            parts.push_back(topic.substr(start));
            break;
        }
        parts.push_back(topic.substr(start, slash - start));
        start = slash + 1;
    }
    if (parts.empty() || parts[0] != "spBv1.0") return std::nullopt;

    if (parts.size() >= 2 && parts[1] == "STATE") {
        if (parts.size() != 3) return std::nullopt;  // spBv1.0/STATE/{host_id}, exactly 3 segments
        SparkplugTopicParts p;
        p.is_state = true;
        p.message_type = "STATE";
        p.state_host_id = parts[2];
        return p;
    }

    static const std::vector<std::string> kTypes = {"NBIRTH", "NDEATH", "DBIRTH", "DDEATH",
                                                      "NDATA",  "DDATA",  "NCMD",   "DCMD"};
    if (parts.size() != 4 && parts.size() != 5) return std::nullopt;
    const std::string& mtype = parts[2];
    if (std::find(kTypes.begin(), kTypes.end(), mtype) == kTypes.end()) return std::nullopt;
    bool is_device_type = mtype[0] == 'D';
    if (is_device_type != (parts.size() == 5)) return std::nullopt;

    SparkplugTopicParts p;
    p.group_id = parts[1];
    p.message_type = mtype;
    p.edge_node_id = parts[3];
    if (parts.size() == 5) p.device_id = parts[4];
    return p;
}

// ------------------------------------------------------------------------------------------
// Sparkplug B -- hand-rolled protobuf wire-format reader. Covers exactly the wire types Sparkplug's
// own schema uses (0=varint, 1=64-bit fixed, 2=length-delimited, 5=32-bit fixed) -- see mqtt.hpp's
// file header comment. No external protobuf library.

uint64_t read_pb_varint(Cursor& c) {
    uint64_t value = 0;
    for (int i = 0; i < 10; ++i) {
        uint8_t b = c.u8();
        value |= static_cast<uint64_t>(b & 0x7F) << (7 * i);
        if ((b & 0x80) == 0) return value;
    }
    throw ParseError("protobuf varint exceeds 10 bytes (malformed)");
}

struct PbTag {
    uint32_t field_number;
    uint32_t wire_type;
};

PbTag read_pb_tag(Cursor& c) {
    uint64_t raw = read_pb_varint(c);
    PbTag t;
    t.wire_type = static_cast<uint32_t>(raw & 0x7);
    t.field_number = static_cast<uint32_t>(raw >> 3);
    return t;
}

ByteSpan read_pb_bytes(Cursor& c) {
    uint64_t len = read_pb_varint(c);
    return c.bytes(static_cast<size_t>(len));
}

void skip_pb_field(Cursor& c, uint32_t wire_type) {
    switch (wire_type) {
        case 0: read_pb_varint(c); break;
        case 1: c.bytes(8); break;
        case 2: { uint64_t len = read_pb_varint(c); c.bytes(static_cast<size_t>(len)); break; }
        case 5: c.bytes(4); break;
        default:
            throw ParseError("protobuf wire type " + std::to_string(wire_type) +
                              " not supported (group encoding -- unused anywhere in Sparkplug B's "
                              "own proto2 schema)");
    }
}

std::string sparkplug_datatype_name(uint32_t dt) {
    switch (dt) {
        case 0: return "Unknown";
        case 1: return "Int8";
        case 2: return "Int16";
        case 3: return "Int32";
        case 4: return "Int64";
        case 5: return "UInt8";
        case 6: return "UInt16";
        case 7: return "UInt32";
        case 8: return "UInt64";
        case 9: return "Float";
        case 10: return "Double";
        case 11: return "Boolean";
        case 12: return "String";
        case 13: return "DateTime";
        case 14: return "Text";
        case 15: return "UUID";
        case 16: return "DataSet";
        case 17: return "Bytes";
        case 18: return "File";
        case 19: return "Template";
        case 20: return "PropertySet";
        case 21: return "PropertySetList";
        case 22: return "Int8Array";
        case 23: return "Int16Array";
        case 24: return "Int32Array";
        case 25: return "Int64Array";
        case 26: return "UInt8Array";
        case 27: return "UInt16Array";
        case 28: return "UInt32Array";
        case 29: return "UInt64Array";
        case 30: return "FloatArray";
        case 31: return "DoubleArray";
        case 32: return "BooleanArray";
        case 33: return "StringArray";
        case 34: return "DateTimeArray";
        default: return "unrecognized(" + std::to_string(dt) + ")";
    }
}

// One Payload.Metric's raw decoded fields -- see mqtt.hpp's "Sparkplug B" section for the field
// number table and the int_value/long_value sign-handling rationale.
struct SparkplugMetricRaw {
    std::optional<std::string> name;
    std::optional<uint64_t> alias;
    std::optional<uint64_t> timestamp;
    std::optional<uint32_t> datatype;
    std::optional<bool> is_historical, is_transient, is_null;
    bool has_metadata = false, has_properties = false;
    std::optional<uint32_t> int_value;
    std::optional<uint64_t> long_value;
    std::optional<float> float_value;
    std::optional<double> double_value;
    std::optional<bool> boolean_value;
    std::optional<std::string> string_value;
    std::optional<size_t> bytes_value_length;
    bool has_dataset = false, has_template = false, has_extension = false;
};

SparkplugMetricRaw parse_sparkplug_metric_fields(ByteSpan bytes) {
    SparkplugMetricRaw m;
    Cursor c(bytes);
    while (!c.at_end()) {
        PbTag tag = read_pb_tag(c);
        switch (tag.field_number) {
            case 1:
                if (tag.wire_type == 2) {
                    ByteSpan s = read_pb_bytes(c);
                    m.name = std::string(reinterpret_cast<const char*>(s.data()), s.size());
                } else skip_pb_field(c, tag.wire_type);
                break;
            case 2:
                if (tag.wire_type == 0) m.alias = read_pb_varint(c);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 3:
                if (tag.wire_type == 0) m.timestamp = read_pb_varint(c);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 4:
                if (tag.wire_type == 0) m.datatype = static_cast<uint32_t>(read_pb_varint(c));
                else skip_pb_field(c, tag.wire_type);
                break;
            case 5:
                if (tag.wire_type == 0) m.is_historical = (read_pb_varint(c) != 0);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 6:
                if (tag.wire_type == 0) m.is_transient = (read_pb_varint(c) != 0);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 7:
                if (tag.wire_type == 0) m.is_null = (read_pb_varint(c) != 0);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 8:
                if (tag.wire_type == 2) { read_pb_bytes(c); m.has_metadata = true; }
                else skip_pb_field(c, tag.wire_type);
                break;
            case 9:
                if (tag.wire_type == 2) { read_pb_bytes(c); m.has_properties = true; }
                else skip_pb_field(c, tag.wire_type);
                break;
            case 10:
                if (tag.wire_type == 0) m.int_value = static_cast<uint32_t>(read_pb_varint(c));
                else skip_pb_field(c, tag.wire_type);
                break;
            case 11:
                if (tag.wire_type == 0) m.long_value = read_pb_varint(c);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 12:
                if (tag.wire_type == 5) m.float_value = bits_to_float(c.u32le());
                else skip_pb_field(c, tag.wire_type);
                break;
            case 13:
                if (tag.wire_type == 1) m.double_value = bits_to_double(c.u64le());
                else skip_pb_field(c, tag.wire_type);
                break;
            case 14:
                if (tag.wire_type == 0) m.boolean_value = (read_pb_varint(c) != 0);
                else skip_pb_field(c, tag.wire_type);
                break;
            case 15:
                if (tag.wire_type == 2) {
                    ByteSpan s = read_pb_bytes(c);
                    m.string_value = std::string(reinterpret_cast<const char*>(s.data()), s.size());
                } else skip_pb_field(c, tag.wire_type);
                break;
            case 16:
                if (tag.wire_type == 2) m.bytes_value_length = read_pb_bytes(c).size();
                else skip_pb_field(c, tag.wire_type);
                break;
            case 17:
                if (tag.wire_type == 2) { read_pb_bytes(c); m.has_dataset = true; }
                else skip_pb_field(c, tag.wire_type);
                break;
            case 18:
                if (tag.wire_type == 2) { read_pb_bytes(c); m.has_template = true; }
                else skip_pb_field(c, tag.wire_type);
                break;
            case 19:
                if (tag.wire_type == 2) { read_pb_bytes(c); m.has_extension = true; }
                else skip_pb_field(c, tag.wire_type);
                break;
            default:
                skip_pb_field(c, tag.wire_type);
                break;
        }
    }
    return m;
}

std::string render_sparkplug_metric(const SparkplugMetricRaw& m) {
    std::ostringstream s;
    s << (m.name ? ("\"" + *m.name + "\"") : std::string("(no name)"));
    if (m.alias) s << " alias=" << *m.alias;
    uint32_t dt = m.datatype.value_or(0);
    s << " type=" << sparkplug_datatype_name(dt);

    if (m.is_null && *m.is_null) {
        s << " value=null";
    } else {
        switch (dt) {
            case 1:  // Int8
                s << " value=" << (m.int_value
                                        ? std::to_string(static_cast<int32_t>(static_cast<int8_t>(*m.int_value & 0xFFu)))
                                        : "<missing>");
                break;
            case 2:  // Int16
                s << " value="
                  << (m.int_value ? std::to_string(static_cast<int32_t>(static_cast<int16_t>(*m.int_value & 0xFFFFu)))
                                   : "<missing>");
                break;
            case 3:  // Int32
                s << " value=" << (m.int_value ? std::to_string(static_cast<int32_t>(*m.int_value)) : "<missing>");
                break;
            case 4:  // Int64
                s << " value=" << (m.long_value ? std::to_string(static_cast<int64_t>(*m.long_value)) : "<missing>");
                break;
            case 5:  // UInt8
                s << " value=" << (m.int_value ? std::to_string(*m.int_value & 0xFFu) : "<missing>");
                break;
            case 6:  // UInt16
                s << " value=" << (m.int_value ? std::to_string(*m.int_value & 0xFFFFu) : "<missing>");
                break;
            case 7:  // UInt32
                s << " value=" << (m.int_value ? std::to_string(*m.int_value) : "<missing>");
                break;
            case 8:  // UInt64
                s << " value=" << (m.long_value ? std::to_string(*m.long_value) : "<missing>");
                break;
            case 9:  // Float
                s << " value=" << (m.float_value ? format_double(static_cast<double>(*m.float_value)) : "<missing>");
                break;
            case 10:  // Double
                s << " value=" << (m.double_value ? format_double(*m.double_value) : "<missing>");
                break;
            case 11:  // Boolean
                s << " value=" << (m.boolean_value ? (*m.boolean_value ? "true" : "false") : "<missing>");
                break;
            case 12:  // String
            case 14:  // Text
            case 15:  // UUID
                s << " value=" << (m.string_value ? ("\"" + *m.string_value + "\"") : "<missing>");
                break;
            case 13:  // DateTime
                s << " value=" << (m.long_value ? format_millis_epoch(*m.long_value) : "<missing>");
                break;
            case 17:  // Bytes
            case 18:  // File
                s << " value=<" << (m.bytes_value_length ? *m.bytes_value_length : size_t{0})
                  << " byte(s), not decoded further>";
                break;
            case 16:  // DataSet
                s << " value=<DataSet" << (m.has_dataset ? "" : " (missing)") << ", not decoded further>";
                break;
            case 19:  // Template
                s << " value=<Template" << (m.has_template ? "" : " (missing)") << ", not decoded further>";
                break;
            case 20:  // PropertySet
            case 21:  // PropertySetList
                s << " value=<PropertySet(List), not decoded further>";
                break;
            default:
                if (dt >= 22 && dt <= 34) s << " value=<array, not decoded further>";
                else s << " value=<unrecognized datatype, not decoded further>";
                break;
        }
    }

    if (m.timestamp) s << " ts=" << format_millis_epoch(*m.timestamp);
    if (m.is_historical && *m.is_historical) s << " [historical]";
    if (m.is_transient && *m.is_transient) s << " [transient]";
    if (m.has_extension) s << " [extension value present, not decoded]";
    return s.str();
}

// Top-level Payload message -- see mqtt.hpp's "Sparkplug B" section.
SparkplugPayload decode_sparkplug_payload(ByteSpan payload, std::vector<std::string>& notes) {
    SparkplugPayload result;
    Cursor c(payload);
    std::vector<ByteSpan> metric_spans;
    // Safety cap against a pathological/malformed capture claiming an unbounded number of metrics
    // -- generous relative to any real Sparkplug NBIRTH (which enumerates every metric a node will
    // ever report, but real deployments are nowhere near this size).
    constexpr size_t kMaxMetricsParsed = 2000;

    try {
        while (!c.at_end()) {
            PbTag tag = read_pb_tag(c);
            switch (tag.field_number) {
                case 1:
                    if (tag.wire_type == 0) {
                        result.timestamp = read_pb_varint(c);
                        result.has_timestamp = true;
                    } else skip_pb_field(c, tag.wire_type);
                    break;
                case 2:
                    if (tag.wire_type == 2) {
                        ByteSpan m = read_pb_bytes(c);
                        if (metric_spans.size() < kMaxMetricsParsed) metric_spans.push_back(m);
                    } else skip_pb_field(c, tag.wire_type);
                    break;
                case 3:
                    if (tag.wire_type == 0) {
                        result.seq = read_pb_varint(c);
                        result.has_seq = true;
                    } else skip_pb_field(c, tag.wire_type);
                    break;
                case 4:
                    if (tag.wire_type == 2) {
                        ByteSpan s = read_pb_bytes(c);
                        result.uuid = std::string(reinterpret_cast<const char*>(s.data()), s.size());
                        result.has_uuid = true;
                    } else skip_pb_field(c, tag.wire_type);
                    break;
                case 5:
                    if (tag.wire_type == 2) {
                        ByteSpan s = read_pb_bytes(c);
                        result.has_body = true;
                        result.body_length = s.size();
                    } else skip_pb_field(c, tag.wire_type);
                    break;
                default:
                    skip_pb_field(c, tag.wire_type);
                    break;
            }
        }
        result.parse_ok = true;
    } catch (const ParseError& e) {
        notes.push_back(std::string("Sparkplug B protobuf Payload could not be fully decoded: ") + e.what() +
                         " -- whatever metrics were found before the failure are still shown below");
    }

    result.metric_count = metric_spans.size();
    if (metric_spans.size() >= kMaxMetricsParsed) {
        notes.push_back("stopped collecting Sparkplug B metrics after " + std::to_string(kMaxMetricsParsed) +
                         ", more may remain in this Payload (safety cap)");
    }
    constexpr size_t kMaxRenderedMetrics = 50;  // same cap convention as every other "list of
                                                  // decoded sub-values" field in this codebase
    for (size_t i = 0; i < metric_spans.size() && result.metrics.size() < kMaxRenderedMetrics; ++i) {
        try {
            SparkplugMetricRaw raw = parse_sparkplug_metric_fields(metric_spans[i]);
            result.metrics.push_back(render_sparkplug_metric(raw));
        } catch (const ParseError&) {
            result.metrics.push_back("<unparseable metric, " + std::to_string(metric_spans[i].size()) + " byte(s)>");
        }
    }
    return result;
}

// ------------------------------------------------------------------------------------------
// Per-packet-type body decoders. See mqtt.hpp's file header comment for the byte layout each of
// these implements and the version-disambiguation strategy for the three genuinely ambiguous types.

void decode_connect(Cursor& c, MqttMessage& msg) {
    std::string proto_name = read_utf8_string(c);
    uint8_t level = c.u8();
    msg.values.push_back("ProtocolName=\"" + proto_name + "\"");
    std::string version_name = (level == 5)   ? "5.0"
                                : (level == 4) ? "3.1.1"
                                : (level == 3) ? "3.1"
                                               : ("unknown(" + std::to_string(level) + ")");
    msg.protocol_version_name = version_name;
    msg.connect_discovered_version = level;
    msg.values.push_back("ProtocolLevel=" + std::to_string(level) + " (" + version_name + ")");
    if (proto_name != "MQTT" && proto_name != "MQIsdp") {
        msg.notes.push_back("CONNECT Protocol Name is \"" + proto_name +
                             "\", neither \"MQTT\" (v3.1.1/v5.0) nor \"MQIsdp\" (pre-OASIS v3.1) -- "
                             "decoding continues opportunistically");
    }

    uint8_t connect_flags = c.u8();
    bool reserved = (connect_flags & 0x01) != 0;
    bool clean = (connect_flags & 0x02) != 0;
    bool will_flag = (connect_flags & 0x04) != 0;
    uint8_t will_qos = (connect_flags >> 3) & 0x03;
    bool will_retain = (connect_flags & 0x20) != 0;
    bool password_flag = (connect_flags & 0x40) != 0;
    bool username_flag = (connect_flags & 0x80) != 0;
    if (reserved) {
        msg.notes.push_back("CONNECT Flags reserved bit 0 is set (must be 0 per spec) -- ignored");
    }
    msg.values.push_back(std::string(level == 5 ? "CleanStart=" : "CleanSession=") + (clean ? "true" : "false"));
    msg.values.push_back(std::string("WillFlag=") + (will_flag ? "true" : "false"));
    if (will_flag) {
        msg.values.push_back("WillQoS=" + std::to_string(static_cast<unsigned>(will_qos)));
        msg.values.push_back(std::string("WillRetain=") + (will_retain ? "true" : "false"));
    }
    msg.values.push_back(std::string("UsernameFlag=") + (username_flag ? "true" : "false"));
    msg.values.push_back(std::string("PasswordFlag=") + (password_flag ? "true" : "false"));

    uint16_t keep_alive = c.u16be();
    msg.values.push_back("KeepAlive=" + std::to_string(keep_alive) + "s");

    if (level == 5) decode_properties(c, msg.values);

    std::string client_id = read_utf8_string(c);
    msg.values.push_back("ClientId=\"" + client_id + "\"");

    if (will_flag) {
        if (level == 5) {
            std::vector<std::string> will_props;
            decode_properties(c, will_props);
            for (auto& p : will_props) msg.values.push_back("Will." + p);
        }
        std::string will_topic = read_utf8_string(c);
        msg.values.push_back("WillTopic=\"" + will_topic + "\"");
        ByteSpan will_payload = read_binary(c);
        msg.values.push_back("WillPayload=<" + std::to_string(will_payload.size()) +
                              " byte(s), not decoded further>");
    }

    // Username/Password decoded in cleartext deliberately -- see mqtt.hpp's file header comment:
    // unlike OPC UA's own conditionally-encrypted UserNameIdentityToken, MQTT's CONNECT Username/
    // Password fields have no encryption option of their own at all -- if this decoder can see a
    // CONNECT on the wire, these bytes ARE plaintext on that wire. A genuine, directly actionable
    // OT-security finding (MQTT broker credentials sent in cleartext), the same reasoning already
    // documented for OPC UA's own decision.
    if (username_flag) {
        std::string username = read_utf8_string(c);
        msg.values.push_back("Username=\"" + username + "\"");
    }
    if (password_flag) {
        ByteSpan password = read_binary(c);
        std::string password_text(reinterpret_cast<const char*>(password.data()), password.size());
        msg.values.push_back("Password=\"" + password_text + "\"");
    }
}

void decode_connack(Cursor& c, MqttMessage& msg) {
    uint8_t ack_flags = c.u8();
    bool session_present = (ack_flags & 0x01) != 0;
    if ((ack_flags & 0xFE) != 0) {
        msg.notes.push_back("CONNACK Connect Acknowledge Flags reserved bits (7-1) are non-zero -- ignored");
    }
    msg.values.push_back(std::string("SessionPresent=") + (session_present ? "true" : "false"));

    // Self-describing regardless of session tracking -- see mqtt.hpp's "Version disambiguation".
    if (msg.remaining_length == 2) {
        uint8_t code = c.u8();
        msg.protocol_version_name = "3.1.1";
        msg.values.push_back("ReturnCode=" + std::to_string(code) + " (" + connack_return_code_name_v311(code) + ")");
    } else {
        uint8_t code = c.u8();
        msg.protocol_version_name = "5.0";
        msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + mqtt5_reason_code_name(code) + ")");
        decode_properties(c, msg.values);
    }
}

void decode_publish(Cursor& c, MqttMessage& msg, uint8_t session_version_hint) {
    msg.topic = read_utf8_string(c);
    if (msg.qos > 0) {
        msg.has_packet_id = true;
        msg.packet_id = c.u16be();
    }
    if (session_version_hint == 5) {
        decode_properties(c, msg.values);
        msg.protocol_version_name = "5.0";
    } else if (session_version_hint == 4) {
        msg.protocol_version_name = "3.1.1";
    } else {
        msg.notes.push_back(
            "MQTT protocol version for this TCP session is not known (no CONNECT seen on it in "
            "this capture) -- PUBLISH is assumed to carry no MQTT5 Properties section; if this is "
            "actually a v5 session, a leading Properties block would be misread as the start of "
            "the application payload");
    }

    ByteSpan payload = c.bytes(c.remaining());
    msg.has_payload = true;
    msg.payload_length = payload.size();
    msg.payload_hex = to_hex(payload, "");

    if (auto topic_parts = parse_sparkplug_topic(msg.topic)) {
        msg.is_sparkplug = true;
        msg.sparkplug_group_id = topic_parts->group_id;
        msg.sparkplug_message_type = topic_parts->message_type;
        msg.sparkplug_edge_node_id = topic_parts->edge_node_id;
        msg.sparkplug_device_id = topic_parts->device_id;
        msg.sparkplug_is_state = topic_parts->is_state;
        if (topic_parts->is_state) {
            msg.sparkplug_state_host_id = topic_parts->state_host_id;
            msg.sparkplug_state_text = std::string(reinterpret_cast<const char*>(payload.data()), payload.size());
            msg.payload_hex.clear();
        } else {
            msg.sparkplug_payload = decode_sparkplug_payload(payload, msg.notes);
            if (msg.sparkplug_payload.parse_ok) msg.payload_hex.clear();
        }
    }
}

// PUBACK/PUBREC/PUBREL/PUBCOMP all share this exact shape -- see mqtt.hpp's "Version
// disambiguation" section for why these four need no session-tracking hint at all.
void decode_ack_with_optional_reason(Cursor& c, MqttMessage& msg) {
    msg.has_packet_id = true;
    msg.packet_id = c.u16be();
    if (msg.remaining_length >= 3) {
        uint8_t code = c.u8();
        msg.protocol_version_name = "5.0";
        msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + mqtt5_reason_code_name(code) + ")");
        if (msg.remaining_length >= 4) decode_properties(c, msg.values);
    } else {
        msg.values.push_back("ReasonCode=0x00 (Success, implicit)");
    }
}

void decode_subscribe(Cursor& c, MqttMessage& msg, uint8_t session_version_hint) {
    msg.has_packet_id = true;
    msg.packet_id = c.u16be();

    bool use_v5;
    std::string version_source;
    if (session_version_hint == 5) {
        use_v5 = true;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else if (session_version_hint == 4) {
        use_v5 = false;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else {
        Cursor try_a = c;
        bool a_ok = false;
        try {
            std::vector<std::string> props_a;
            decode_properties(try_a, props_a);
            TopicFilterList tf = try_read_topic_filters(try_a, /*is_v5=*/true);
            a_ok = tf.ok;
        } catch (const ParseError&) {
        }
        Cursor try_b = c;
        TopicFilterList tf_b = try_read_topic_filters(try_b, /*is_v5=*/false);
        bool b_ok = tf_b.ok;

        if (a_ok && !b_ok) {
            use_v5 = true;
            version_source = "heuristic (only the v5-with-Properties shape parsed cleanly)";
        } else if (b_ok && !a_ok) {
            use_v5 = false;
            version_source = "heuristic (only the v3.1.1-without-Properties shape parsed cleanly)";
        } else if (a_ok && b_ok) {
            use_v5 = false;
            version_source = "heuristic, genuinely ambiguous (both shapes parsed cleanly) -- defaulted to v3.1.1";
        } else {
            use_v5 = false;
            version_source = "heuristic, neither shape parsed cleanly -- best-effort v3.1.1-shape decode below";
        }
    }
    msg.protocol_version_name = use_v5 ? "5.0" : "3.1.1";
    msg.notes.push_back("MQTT version for this SUBSCRIBE determined via " + version_source);

    if (use_v5) decode_properties(c, msg.values);
    TopicFilterList tf = try_read_topic_filters(c, use_v5);
    if (tf.ok) {
        for (auto& f : tf.rendered) msg.values.push_back(f);
    } else {
        msg.notes.push_back("could not cleanly decode this SUBSCRIBE's topic filter list -- shown as raw hex");
        ByteSpan rest = c.bytes(c.remaining());
        msg.values.push_back("<undecoded topic filter list, " + std::to_string(rest.size()) +
                              " byte(s): " + to_hex(rest) + ">");
    }
}

void decode_suback(Cursor& c, MqttMessage& msg, uint8_t session_version_hint) {
    msg.has_packet_id = true;
    msg.packet_id = c.u16be();

    bool use_v5;
    std::string version_source;
    if (session_version_hint == 5) {
        use_v5 = true;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else if (session_version_hint == 4) {
        use_v5 = false;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else {
        // SUBACK's own remaining bytes (a flat list of single reason-code bytes) give this
        // heuristic much weaker evidence than SUBSCRIBE's topic-filter strings do -- almost any
        // byte value is a "valid" reason code byte structurally, whichever shape is assumed. This
        // decoder still checks whether a Properties block parses cleanly within the declared
        // Remaining Length, but documents this as the least reliable of the three ambiguous types.
        Cursor try_a = c;
        bool a_ok = false;
        try {
            std::vector<std::string> dummy;
            decode_properties(try_a, dummy);
            a_ok = true;
        } catch (const ParseError&) {
        }
        use_v5 = a_ok;
        version_source = a_ok ? "heuristic (a Properties block parsed cleanly within the declared "
                                 "Remaining Length -- the weakest-evidence heuristic of the three "
                                 "ambiguous MQTT packet types, see mqtt.hpp)"
                               : "heuristic (no Properties block could be parsed -- assumed v3.1.1)";
    }
    msg.protocol_version_name = use_v5 ? "5.0" : "3.1.1";
    msg.notes.push_back("MQTT version for this SUBACK determined via " + version_source);

    if (use_v5) decode_properties(c, msg.values);
    while (!c.at_end()) {
        uint8_t code = c.u8();
        msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + suback_code_name(code, use_v5) + ")");
    }
}

void decode_unsubscribe(Cursor& c, MqttMessage& msg, uint8_t session_version_hint) {
    msg.has_packet_id = true;
    msg.packet_id = c.u16be();

    bool use_v5;
    std::string version_source;
    if (session_version_hint == 5) {
        use_v5 = true;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else if (session_version_hint == 4) {
        use_v5 = false;
        version_source = "this TCP session's own CONNECT (tracked)";
    } else {
        Cursor try_a = c;
        bool a_ok = false;
        try {
            std::vector<std::string> dummy;
            decode_properties(try_a, dummy);
            a_ok = !try_read_plain_strings(try_a).empty();
        } catch (const ParseError&) {
        }
        Cursor try_b = c;
        bool b_ok = !try_read_plain_strings(try_b).empty();

        if (a_ok && !b_ok) {
            use_v5 = true;
            version_source = "heuristic (only the v5-with-Properties shape parsed cleanly)";
        } else if (b_ok && !a_ok) {
            use_v5 = false;
            version_source = "heuristic (only the v3.1.1-without-Properties shape parsed cleanly)";
        } else if (a_ok && b_ok) {
            use_v5 = false;
            version_source = "heuristic, genuinely ambiguous (both shapes parsed cleanly) -- defaulted to v3.1.1";
        } else {
            use_v5 = false;
            version_source = "heuristic, neither shape parsed cleanly -- best-effort v3.1.1-shape decode below";
        }
    }
    msg.protocol_version_name = use_v5 ? "5.0" : "3.1.1";
    msg.notes.push_back("MQTT version for this UNSUBSCRIBE determined via " + version_source);

    if (use_v5) decode_properties(c, msg.values);
    try {
        if (c.at_end()) throw ParseError("no topic filters present");
        while (!c.at_end()) {
            std::string filter = read_utf8_string(c);
            msg.values.push_back("TopicFilter=\"" + filter + "\"");
        }
    } catch (const ParseError&) {
        msg.notes.push_back("could not cleanly decode this UNSUBSCRIBE's topic filter list -- shown as raw hex");
        ByteSpan rest = c.bytes(c.remaining());
        msg.values.push_back("<undecoded topic filter list, " + std::to_string(rest.size()) +
                              " byte(s): " + to_hex(rest) + ">");
    }
}

void decode_unsuback(Cursor& c, MqttMessage& msg) {
    msg.has_packet_id = true;
    msg.packet_id = c.u16be();
    // Self-describing regardless of session tracking -- see mqtt.hpp's "Version disambiguation".
    if (msg.remaining_length == 2) {
        msg.protocol_version_name = "3.1.1";
        return;
    }
    msg.protocol_version_name = "5.0";
    decode_properties(c, msg.values);
    while (!c.at_end()) {
        uint8_t code = c.u8();
        msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + mqtt5_reason_code_name(code) + ")");
    }
}

void decode_disconnect(Cursor& c, MqttMessage& msg) {
    if (msg.remaining_length == 0) {
        msg.values.push_back("ReasonCode=0x00 (Normal disconnection, implicit)");
        return;  // identical shape/meaning for v3.1.1 (always 0) and a v5 "nothing to say" DISCONNECT
    }
    msg.protocol_version_name = "5.0";
    uint8_t code = c.u8();
    msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + mqtt5_reason_code_name(code) + ")");
    if (msg.remaining_length > 1) decode_properties(c, msg.values);
}

void decode_auth(Cursor& c, MqttMessage& msg) {
    // Packet type 15 does not exist in v3.1.1 at all -- seeing it is itself an unambiguous
    // version=5 signal, see mqtt.hpp's "Version disambiguation" section.
    msg.protocol_version_name = "5.0";
    if (msg.remaining_length == 0) {
        msg.values.push_back("ReasonCode=0x00 (Success, implicit)");
        return;
    }
    uint8_t code = c.u8();
    msg.values.push_back("ReasonCode=0x" + to_hex_byte(code) + " (" + mqtt5_reason_code_name(code) + ")");
    if (msg.remaining_length > 1) decode_properties(c, msg.values);
}

std::string build_summary(const MqttMessage& msg) {
    std::ostringstream s;
    s << msg.packet_type_name;
    if (!msg.protocol_version_name.empty()) s << " (MQTT " << msg.protocol_version_name << ")";
    if (msg.packet_type_name == "PUBLISH") {
        s << " topic=\"" << msg.topic << "\" qos=" << static_cast<unsigned>(msg.qos);
        if (msg.retain) s << " retain";
        if (msg.dup) s << " dup";
        if (msg.has_packet_id) s << " id=" << msg.packet_id;
        s << " payload=" << msg.payload_length << " byte(s)";
        if (msg.is_sparkplug) {
            s << " [Sparkplug B " << msg.sparkplug_message_type;
            if (msg.sparkplug_is_state) {
                s << " host=\"" << msg.sparkplug_state_host_id << "\"";
            } else {
                s << " group=\"" << msg.sparkplug_group_id << "\" node=\"" << msg.sparkplug_edge_node_id << "\"";
                if (!msg.sparkplug_device_id.empty()) s << " device=\"" << msg.sparkplug_device_id << "\"";
                if (msg.sparkplug_payload.parse_ok) {
                    s << ", " << msg.sparkplug_payload.metric_count << " metric(s)";
                } else {
                    s << ", payload not fully decoded";
                }
            }
            s << "]";
        }
    } else if (msg.has_packet_id) {
        s << " id=" << msg.packet_id;
    }
    return s.str();
}

}  // namespace

// milliseconds since the Unix epoch -- Sparkplug's own DateTime/timestamp convention (Payload's
// top-level `timestamp` and Metric's own `timestamp`/DateTime-typed values all share it), and,
// since dnp3.cpp now calls this directly too, DNP3's own Group 50 "Time and Date"/absolute-time-
// trailer format as well (see mqtt.hpp's comment on this declaration).
std::string format_millis_epoch(uint64_t millis) {
    std::time_t tt = static_cast<std::time_t>(millis / 1000);
    std::tm* tm_utc = std::gmtime(&tt);
    if (!tm_utc) {
        return std::to_string(millis) + " (raw epoch millisecond value -- out of range for calendar display)";
    }
    std::ostringstream s;
    s << std::put_time(tm_utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3)
      << (millis % 1000) << 'Z';
    return s.str();
}

std::optional<size_t> mqtt_declared_length(ByteSpan payload) {
    if (payload.size() < 2) return std::nullopt;
    uint8_t byte0 = payload.at(0);
    uint8_t type = byte0 >> 4;
    uint8_t flags = byte0 & 0x0F;
    if (type == 0 || !flags_valid_for_type(type, flags)) return std::nullopt;
    uint32_t remaining_length = 0;
    size_t vbi_consumed = 0;
    if (!decode_vbi_raw(payload, 1, remaining_length, vbi_consumed)) return std::nullopt;
    return 1 + vbi_consumed + remaining_length;
}

std::optional<MqttMessage> try_parse_mqtt_message(ByteSpan payload, uint8_t session_version_hint) {
    if (payload.size() < 2) return std::nullopt;
    uint8_t byte0 = payload.at(0);
    uint8_t type = byte0 >> 4;
    uint8_t flags = byte0 & 0x0F;
    if (type == 0 || !flags_valid_for_type(type, flags)) return std::nullopt;

    uint32_t remaining_length = 0;
    size_t vbi_consumed = 0;
    if (!decode_vbi_raw(payload, 1, remaining_length, vbi_consumed)) return std::nullopt;

    MqttMessage msg;
    msg.packet_type = type;
    msg.packet_type_name = mqtt_packet_type_name(type);
    msg.flags = flags;
    if (type == 3) {
        msg.dup = (flags & 0x08) != 0;
        msg.qos = (flags >> 1) & 0x03;
        msg.retain = (flags & 0x01) != 0;
        if (msg.qos == 3) {
            msg.notes.push_back(
                "PUBLISH fixed header flags declare QoS=3, which is invalid (MQTT-3.3.1-4 reserves "
                "QoS to 0-2) -- decoding continues treating it as-is");
        }
    }
    msg.remaining_length = remaining_length;
    msg.header_length = 1 + vbi_consumed;
    size_t declared_total = msg.header_length + remaining_length;
    msg.wire_length = std::min(declared_total, payload.size());

    if (declared_total > payload.size()) {
        msg.notes.push_back("declares Remaining Length " + std::to_string(remaining_length) + " (" +
                             std::to_string(declared_total) + " byte(s) total including the fixed "
                             "header) but only " + std::to_string(payload.size()) +
                             " byte(s) are available -- truncated");
    }

    // For CONNECT specifically, require the Protocol Name to read as a real MQTT/MQIsdp magic
    // string with a structurally sane Protocol Level -- a materially stronger, near-OPC-UA-strength
    // signal for this one packet type -- see mqtt.hpp's "structural detection gate" paragraph.
    if (type == 1) {
        size_t body_end = std::min(declared_total, payload.size());
        if (msg.header_length + 2 > body_end) return std::nullopt;
        uint16_t name_len = (static_cast<uint16_t>(payload.at(msg.header_length)) << 8) |
                             payload.at(msg.header_length + 1);
        if (msg.header_length + 2 + static_cast<size_t>(name_len) + 1 > body_end) return std::nullopt;
        std::string proto_name(reinterpret_cast<const char*>(payload.data() + msg.header_length + 2), name_len);
        if (proto_name != "MQTT" && proto_name != "MQIsdp") return std::nullopt;
        uint8_t level = payload.at(msg.header_length + 2 + name_len);
        if (level != 3 && level != 4 && level != 5) return std::nullopt;
    }

    size_t body_len = std::min(declared_total, payload.size()) - msg.header_length;
    ByteSpan whole_body = payload.subspan(msg.header_length, body_len);
    Cursor bc(whole_body);

    try {
        switch (type) {
            case 1: decode_connect(bc, msg); break;
            case 2: decode_connack(bc, msg); break;
            case 3: decode_publish(bc, msg, session_version_hint); break;
            case 4: case 5: case 6: case 7: decode_ack_with_optional_reason(bc, msg); break;
            case 8: decode_subscribe(bc, msg, session_version_hint); break;
            case 9: decode_suback(bc, msg, session_version_hint); break;
            case 10: decode_unsubscribe(bc, msg, session_version_hint); break;
            case 11: decode_unsuback(bc, msg); break;
            case 12: case 13: break;  // PINGREQ/PINGRESP -- no variable header, no payload
            case 14: decode_disconnect(bc, msg); break;
            case 15: decode_auth(bc, msg); break;
            default: break;
        }
        if (type != 3 && bc.remaining() > 0) {
            // PUBLISH legitimately consumes everything as application payload (see decode_publish).
            // For every other type, leftover bytes mean either a malformed message or this
            // decoder's own version disambiguation got the shape wrong -- noted, not dropped.
            msg.notes.push_back(std::to_string(bc.remaining()) +
                                 " trailing byte(s) after this message's own decoded fields (ignored)");
        }
    } catch (const ParseError& e) {
        msg.notes.push_back(std::string("could not fully decode this ") + msg.packet_type_name +
                             " packet's own body: " + e.what());
    }

    msg.summary = build_summary(msg);
    return msg;
}

}  // namespace conduitscope
