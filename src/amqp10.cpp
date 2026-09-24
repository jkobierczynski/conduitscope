// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/amqp10.hpp"

#include <algorithm>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {
namespace {

size_t amqp10_max_nesting_depth() { return resource_limits().max_recursion_depth.value_or(16); }

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << static_cast<unsigned>(v);
    return s.str();
}

std::string hex_u64(uint64_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << v;
    return s.str();
}

// --- the generic type-system walk -------------------------------------------------------------

Amqp10Value read_amqp10_value_body(Cursor& c, uint8_t ctor, size_t depth);

Amqp10Value read_amqp10_value(Cursor& c, size_t depth) {
    uint8_t ctor = c.u8();
    return read_amqp10_value_body(c, ctor, depth);
}

Amqp10Value read_amqp10_list_or_map(Cursor& c, size_t depth, int size_width, bool is_map_type) {
    if (depth > amqp10_max_nesting_depth()) {
        throw ParseError("AMQP 1.0 list/map nesting exceeded safety cap");
    }
    // The size field counts bytes AFTER itself (the count field plus every element) -- NOT
    // including the size field's own width. See amqp10.hpp's own TYPE SYSTEM section.
    uint32_t size_val = size_width == 1 ? c.u8() : c.u32be();
    ByteSpan region = c.bytes(size_val);
    Cursor lc(region);
    // The count field is TWICE the real entry count for a map (each key AND value counts) --
    // this function doesn't need to know that distinction itself: it just reads `count` back-to-
    // back values into `elements`, and callers that care about map semantics (application-
    // properties) read `elements` in (key, value) pairs themselves.
    uint32_t count = size_width == 1 ? lc.u8() : lc.u32be();

    Amqp10Value v;
    v.is_list = !is_map_type;
    v.is_map = is_map_type;
    for (uint32_t i = 0; i < count; ++i) {
        if (lc.at_end()) break;  // fewer elements physically present than the declared count --
                                   // tolerate, matching this codebase's universal "decode what's
                                   // decodable" posture, rather than treating it as fatal.
        v.elements.push_back(read_amqp10_value(lc, depth + 1));
    }

    std::ostringstream s;
    s << (is_map_type ? "{" : "[");
    if (is_map_type) {
        for (size_t i = 0; i + 1 < v.elements.size(); i += 2) {
            if (i) s << ", ";
            s << v.elements[i].rendered << "=" << v.elements[i + 1].rendered;
        }
    } else {
        for (size_t i = 0; i < v.elements.size(); ++i) {
            if (i) s << ", ";
            s << v.elements[i].rendered;
        }
    }
    s << (is_map_type ? "}" : "]");
    v.rendered = s.str();
    return v;
}

Amqp10Value read_amqp10_array(Cursor& c, size_t depth, int size_width) {
    if (depth > amqp10_max_nesting_depth()) {
        throw ParseError("AMQP 1.0 array nesting exceeded safety cap");
    }
    uint32_t size_val = size_width == 1 ? c.u8() : c.u32be();
    ByteSpan region = c.bytes(size_val);
    Cursor ac(region);
    uint32_t count = size_width == 1 ? ac.u8() : ac.u32be();
    // Every element shares ONE constructor, read once here -- see amqp10.hpp's own TYPE SYSTEM
    // section for why this needs its own reader rather than reusing read_amqp10_value per element.
    uint8_t elem_ctor = ac.at_end() ? 0 : ac.u8();

    Amqp10Value v;
    v.is_array = true;
    for (uint32_t i = 0; i < count; ++i) {
        if (ac.at_end()) break;
        v.elements.push_back(read_amqp10_value_body(ac, elem_ctor, depth + 1));
    }
    std::ostringstream s;
    s << "[";
    for (size_t i = 0; i < v.elements.size(); ++i) {
        if (i) s << ", ";
        s << v.elements[i].rendered;
    }
    s << "]";
    v.rendered = s.str();
    return v;
}

// The full primitive/described-type constructor table -- see amqp10.hpp's own TYPE SYSTEM section
// for the sourcing note. `ctor` has already been consumed from `c` by the caller (read_amqp10_value
// above, or read_amqp10_array's own shared-constructor path).
Amqp10Value read_amqp10_value_body(Cursor& c, uint8_t ctor, size_t depth) {
    if (depth > amqp10_max_nesting_depth()) {
        throw ParseError("AMQP 1.0 value nesting exceeded safety cap");
    }
    Amqp10Value v;
    switch (ctor) {
        case 0x00: {  // described type
            if (depth > amqp10_max_nesting_depth()) throw ParseError("AMQP 1.0 nesting exceeded cap");
            Amqp10Value descriptor = read_amqp10_value(c, depth + 1);
            Amqp10Value value = read_amqp10_value(c, depth + 1);
            v.is_described = true;
            if (descriptor.as_uint) v.descriptor_code = descriptor.as_uint;
            v.rendered = "descriptor(" + descriptor.rendered + ")=" + value.rendered;
            v.elements.push_back(std::move(value));
            return v;
        }
        case 0x40:
            v.is_null = true;
            v.rendered = "null";
            return v;
        case 0x41:
            v.as_bool = true;
            v.rendered = "true";
            return v;
        case 0x42:
            v.as_bool = false;
            v.rendered = "false";
            return v;
        case 0x56:
            v.as_bool = (c.u8() != 0);
            v.rendered = *v.as_bool ? "true" : "false";
            return v;
        case 0x50: {
            uint8_t x = c.u8();
            v.as_uint = x;
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x60: {
            uint16_t x = c.u16be();
            v.as_uint = x;
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x70: {
            uint32_t x = c.u32be();
            v.as_uint = x;
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x52: {
            uint8_t x = c.u8();
            v.as_uint = x;
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x43:
            v.as_uint = 0;
            v.as_int = 0;
            v.rendered = "0";
            return v;
        case 0x80: {
            uint64_t x = amqp_read_u64be(c);
            v.as_uint = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x53: {
            uint8_t x = c.u8();
            v.as_uint = x;
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x44:
            v.as_uint = 0;
            v.rendered = "0";
            return v;
        case 0x51: {
            int8_t x = static_cast<int8_t>(c.u8());
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x61: {
            int16_t x = static_cast<int16_t>(c.u16be());
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x71: {
            int32_t x = static_cast<int32_t>(c.u32be());
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x54: {
            int8_t x = static_cast<int8_t>(c.u8());
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x81: {
            int64_t x = static_cast<int64_t>(amqp_read_u64be(c));
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x55: {
            int8_t x = static_cast<int8_t>(c.u8());
            v.as_int = x;
            v.rendered = std::to_string(x);
            return v;
        }
        case 0x72:
            v.rendered = std::to_string(amqp_read_f32be(c));
            return v;
        case 0x82:
            v.rendered = std::to_string(amqp_read_f64be(c));
            return v;
        case 0x74:  // decimal32 -- opaque hex, never numerically decoded (see amqp10.hpp SCOPE).
            v.rendered = to_hex(c.bytes(4)) + " (decimal32, opaque)";
            return v;
        case 0x84:  // decimal64
            v.rendered = to_hex(c.bytes(8)) + " (decimal64, opaque)";
            return v;
        case 0x94:  // decimal128
            v.rendered = to_hex(c.bytes(16)) + " (decimal128, opaque)";
            return v;
        case 0x73: {  // char, UTF-32BE codepoint
            uint32_t cp = c.u32be();
            std::ostringstream s;
            s << "U+" << std::hex << std::uppercase << cp;
            v.as_uint = cp;
            v.rendered = s.str();
            return v;
        }
        case 0x83: {  // timestamp, signed ms since epoch
            int64_t ms = static_cast<int64_t>(amqp_read_u64be(c));
            v.as_int = ms;
            v.rendered = std::to_string(ms) + " ms since epoch";
            return v;
        }
        case 0x98:  // uuid
            v.rendered = to_hex(c.bytes(16), "");
            return v;
        case 0xa0: {  // binary vbin8
            uint8_t len = c.u8();
            ByteSpan b = c.bytes(len);
            v.as_string = std::string(reinterpret_cast<const char*>(b.data()), b.size());
            v.rendered = to_hex(b);
            return v;
        }
        case 0xb0: {  // binary vbin32
            uint32_t len = c.u32be();
            ByteSpan b = c.bytes(len);
            v.as_string = std::string(reinterpret_cast<const char*>(b.data()), b.size());
            v.rendered = to_hex(b);
            return v;
        }
        case 0xa1: {  // string str8
            uint8_t len = c.u8();
            ByteSpan b = c.bytes(len);
            std::string s(reinterpret_cast<const char*>(b.data()), b.size());
            v.as_string = s;
            v.rendered = s;
            return v;
        }
        case 0xb1: {  // string str32
            uint32_t len = c.u32be();
            ByteSpan b = c.bytes(len);
            std::string s(reinterpret_cast<const char*>(b.data()), b.size());
            v.as_string = s;
            v.rendered = s;
            return v;
        }
        case 0xa3: {  // symbol sym8
            uint8_t len = c.u8();
            ByteSpan b = c.bytes(len);
            std::string s(reinterpret_cast<const char*>(b.data()), b.size());
            v.as_string = s;
            v.rendered = s;
            return v;
        }
        case 0xb3: {  // symbol sym32
            uint32_t len = c.u32be();
            ByteSpan b = c.bytes(len);
            std::string s(reinterpret_cast<const char*>(b.data()), b.size());
            v.as_string = s;
            v.rendered = s;
            return v;
        }
        case 0x45:  // list0
            v.is_list = true;
            v.rendered = "[]";
            return v;
        case 0xc0:
            return read_amqp10_list_or_map(c, depth, 1, false);
        case 0xd0:
            return read_amqp10_list_or_map(c, depth, 4, false);
        case 0xc1:
            return read_amqp10_list_or_map(c, depth, 1, true);
        case 0xd1:
            return read_amqp10_list_or_map(c, depth, 4, true);
        case 0xe0:
            return read_amqp10_array(c, depth, 1);
        case 0xf0:
            return read_amqp10_array(c, depth, 4);
        default:
            throw ParseError("unrecognized AMQP 1.0 primitive type constructor " + hex_u8(ctor));
    }
}

// --- field-position accessors -------------------------------------------------------------------

std::optional<std::string> list_str(const Amqp10Value& list, size_t idx) {
    if (idx >= list.elements.size() || list.elements[idx].is_null) return std::nullopt;
    const auto& e = list.elements[idx];
    return e.as_string ? e.as_string : std::make_optional(e.rendered);
}

std::optional<uint64_t> list_uint(const Amqp10Value& list, size_t idx) {
    if (idx >= list.elements.size() || list.elements[idx].is_null) return std::nullopt;
    return list.elements[idx].as_uint;
}

std::optional<bool> list_bool(const Amqp10Value& list, size_t idx) {
    if (idx >= list.elements.size() || list.elements[idx].is_null) return std::nullopt;
    return list.elements[idx].as_bool;
}

std::vector<Amqp10Field> extract_fields(const Amqp10Value& list, const std::vector<const char*>& names) {
    std::vector<Amqp10Field> out;
    for (size_t i = 0; i < names.size(); ++i) {
        std::string rendered = "<omitted>";
        if (i < list.elements.size() && !list.elements[i].is_null) rendered = list.elements[i].rendered;
        out.push_back({names[i], rendered});
    }
    return out;
}

// `described` is expected to be a described-type value (source=0x28/target=0x29) wrapping a list
// whose own first field is `address` -- see amqp10.hpp's own WIRE FORMAT section.
std::optional<std::string> extract_described_list_field(const Amqp10Value& described, size_t index) {
    if (!described.is_described || described.elements.empty()) return std::nullopt;
    const Amqp10Value& inner = described.elements[0];
    if (!inner.is_list || index >= inner.elements.size()) return std::nullopt;
    const Amqp10Value& field = inner.elements[index];
    if (field.is_null) return std::nullopt;
    return field.as_string ? field.as_string : std::make_optional(field.rendered);
}

struct AmqpErrorInfo {
    std::optional<std::string> condition;
    std::optional<std::string> description;
};

// `v` is expected to be a described-type value whose descriptor is `error` (0x1d) wrapping a
// 3-field list: condition(symbol,mandatory) description(string) info(map) -- see amqp10.hpp's own
// WIRE FORMAT section.
AmqpErrorInfo extract_error(const Amqp10Value& v) {
    AmqpErrorInfo info;
    if (!v.is_described || v.elements.empty()) return info;
    const Amqp10Value& inner = v.elements[0];
    if (!inner.is_list) return info;
    if (!inner.elements.empty() && !inner.elements[0].is_null) info.condition = inner.elements[0].rendered;
    if (inner.elements.size() > 1 && !inner.elements[1].is_null) info.description = inner.elements[1].rendered;
    return info;
}

// --- message-section walk (transfer only) ---------------------------------------------------

void parse_amqp10_message_sections(Cursor& body, Amqp10Performative& p) {
    while (!body.at_end()) {
        Amqp10Value section;
        try {
            section = read_amqp10_value(body, 0);
        } catch (const ParseError&) {
            p.notes.push_back("message-section walk stopped: parse error partway through the frame body");
            break;
        }
        if (!section.is_described) {
            p.notes.push_back("unexpected non-described value found where a message section was "
                               "expected -- stopped walking this frame's remaining body");
            break;
        }
        uint64_t code = section.descriptor_code.value_or(0);
        const char* name = amqp10_message_section_name(code);
        std::string label = name ? std::string(name) : ("section " + hex_u64(code));
        if (section.elements.empty()) {
            p.message_sections.push_back({label, "<empty>"});
            continue;
        }
        const Amqp10Value& inner = section.elements[0];

        if (name && label == "header" && inner.is_list) {
            static const std::vector<const char*> kNames = {"durable", "priority", "ttl", "first-acquirer",
                                                              "delivery-count"};
            auto fields = extract_fields(inner, kNames);
            std::ostringstream s;
            for (size_t i = 0; i < fields.size(); ++i) {
                if (i) s << ", ";
                s << fields[i].name << "=" << fields[i].rendered;
            }
            p.message_sections.push_back({"header", s.str()});
        } else if (name && label == "properties" && inner.is_list) {
            static const std::vector<const char*> kNames = {
                "message-id",  "user-id",         "to",           "subject",          "reply-to",
                "correlation-id", "content-type", "content-encoding", "absolute-expiry-time",
                "creation-time", "group-id",      "group-sequence", "reply-to-group-id"};
            auto fields = extract_fields(inner, kNames);
            if (auto v = list_str(inner, 0)) p.message_id = *v;
            if (auto v = list_str(inner, 2)) p.message_to = *v;
            if (auto v = list_str(inner, 3)) p.subject = *v;
            if (auto v = list_str(inner, 5)) p.correlation_id = *v;
            if (auto v = list_str(inner, 6)) p.content_type = *v;
            std::ostringstream s;
            for (size_t i = 0; i < fields.size(); ++i) {
                if (i) s << ", ";
                s << fields[i].name << "=" << fields[i].rendered;
            }
            p.message_sections.push_back({"properties", s.str()});
        } else if (name && label == "application-properties" && inner.is_map) {
            for (size_t i = 0; i + 1 < inner.elements.size(); i += 2) {
                std::string key =
                    inner.elements[i].as_string ? *inner.elements[i].as_string : inner.elements[i].rendered;
                p.application_properties.push_back({key, inner.elements[i + 1].rendered});
            }
            p.message_sections.push_back(
                {"application-properties", std::to_string(inner.elements.size() / 2) + " entrie(s)"});
        } else if (name && label == "data") {
            std::string rendered =
                inner.as_string ? (std::to_string(inner.as_string->size()) + " byte(s)") : inner.rendered;
            p.message_sections.push_back({"data", rendered});
        } else {
            p.message_sections.push_back({label, inner.rendered});
        }
    }
}

// --- performative/SASL-method dispatch --------------------------------------------------------

void build_amqp10_performative(uint64_t code, bool is_sasl_frame, const Amqp10Value& list,
                                Amqp10Performative& p) {
    if (!is_sasl_frame) {
        if (code == 0x10) {  // open
            static const std::vector<const char*> kNames = {
                "container-id", "hostname", "max-frame-size", "channel-max", "idle-time-out",
                "outgoing-locales", "incoming-locales", "offered-capabilities", "desired-capabilities",
                "properties"};
            p.fields = extract_fields(list, kNames);
            p.name = "open";
            p.container_id = list_str(list, 0).value_or(std::string());
            if (auto v = list_str(list, 1)) p.hostname = *v;
            p.summary = "container-id=\"" + p.container_id.value_or("") + "\"" +
                        (p.hostname ? (", hostname=\"" + *p.hostname + "\"") : std::string());
            return;
        }
        if (code == 0x11) {  // begin
            static const std::vector<const char*> kNames = {
                "remote-channel", "next-outgoing-id", "incoming-window", "outgoing-window",
                "handle-max",     "offered-capabilities", "desired-capabilities", "properties"};
            p.fields = extract_fields(list, kNames);
            p.name = "begin";
            p.summary = "";
            return;
        }
        if (code == 0x12) {  // attach
            static const std::vector<const char*> kNames = {
                "name",   "handle", "role", "snd-settle-mode", "rcv-settle-mode", "source", "target",
                "unsettled", "incomplete-unsettled", "initial-delivery-count", "max-message-size",
                "offered-capabilities", "desired-capabilities", "properties"};
            p.fields = extract_fields(list, kNames);
            p.name = "attach";
            if (auto v = list_str(list, 0)) p.link_name = *v;
            if (auto v = list_uint(list, 1)) p.handle = *v;
            if (auto v = list_bool(list, 2)) p.role = *v;
            if (list.elements.size() > 5) p.source_address = extract_described_list_field(list.elements[5], 0);
            if (list.elements.size() > 6) p.target_address = extract_described_list_field(list.elements[6], 0);
            std::string role_text = p.role ? (*p.role ? "receiver" : "sender") : "?";
            p.summary = "name=\"" + p.link_name.value_or("") + "\", role=" + role_text +
                        (p.source_address ? (", source=\"" + *p.source_address + "\"") : std::string()) +
                        (p.target_address ? (", target=\"" + *p.target_address + "\"") : std::string());
            return;
        }
        if (code == 0x13) {  // flow
            static const std::vector<const char*> kNames = {
                "next-incoming-id", "incoming-window", "next-outgoing-id", "outgoing-window", "handle",
                "delivery-count",   "link-credit",     "available",       "drain",           "echo",
                "properties"};
            p.fields = extract_fields(list, kNames);
            p.name = "flow";
            if (auto v = list_uint(list, 4)) p.handle = *v;
            p.summary = p.handle ? ("handle=" + std::to_string(*p.handle)) : std::string();
            return;
        }
        if (code == 0x14) {  // transfer
            static const std::vector<const char*> kNames = {
                "handle", "delivery-id", "delivery-tag", "message-format", "settled", "more",
                "rcv-settle-mode", "state", "resume", "aborted", "batchable"};
            p.fields = extract_fields(list, kNames);
            p.name = "transfer";
            if (auto v = list_uint(list, 0)) p.handle = *v;
            if (auto v = list_uint(list, 1)) p.delivery_id = *v;
            if (auto v = list_bool(list, 4)) p.settled = *v;
            p.summary = "handle=" + (p.handle ? std::to_string(*p.handle) : std::string("?"));
            return;
        }
        if (code == 0x15) {  // disposition
            static const std::vector<const char*> kNames = {"role", "first", "last", "settled", "state",
                                                              "batchable"};
            p.fields = extract_fields(list, kNames);
            p.name = "disposition";
            if (auto v = list_bool(list, 0)) p.role = *v;
            if (auto v = list_uint(list, 1)) p.delivery_id = *v;
            if (auto v = list_bool(list, 3)) p.settled = *v;
            if (list.elements.size() > 4 && !list.elements[4].is_null) {
                const Amqp10Value& state = list.elements[4];
                const char* state_name =
                    state.descriptor_code ? amqp10_delivery_state_name(*state.descriptor_code) : nullptr;
                if (state_name && std::string(state_name) == "rejected" && state.is_described &&
                    !state.elements.empty() && state.elements[0].is_list &&
                    !state.elements[0].elements.empty()) {
                    auto err = extract_error(state.elements[0].elements[0]);
                    p.error_condition = err.condition;
                    p.error_description = err.description;
                }
            }
            p.summary = "first=" + (p.delivery_id ? std::to_string(*p.delivery_id) : std::string("?"));
            return;
        }
        if (code == 0x16) {  // detach
            static const std::vector<const char*> kNames = {"handle", "closed", "error"};
            p.fields = extract_fields(list, kNames);
            p.name = "detach";
            if (auto v = list_uint(list, 0)) p.handle = *v;
            if (list.elements.size() > 2 && !list.elements[2].is_null) {
                auto err = extract_error(list.elements[2]);
                p.error_condition = err.condition;
                p.error_description = err.description;
            }
            p.summary = "handle=" + (p.handle ? std::to_string(*p.handle) : std::string("?"));
            if (p.error_condition) p.summary += ", error=" + *p.error_condition;
            return;
        }
        if (code == 0x17) {  // end
            static const std::vector<const char*> kNames = {"error"};
            p.fields = extract_fields(list, kNames);
            p.name = "end";
            if (!list.elements.empty() && !list.elements[0].is_null) {
                auto err = extract_error(list.elements[0]);
                p.error_condition = err.condition;
                p.error_description = err.description;
            }
            p.summary = p.error_condition ? ("error=" + *p.error_condition) : std::string();
            return;
        }
        if (code == 0x18) {  // close
            static const std::vector<const char*> kNames = {"error"};
            p.fields = extract_fields(list, kNames);
            p.name = "close";
            if (!list.elements.empty() && !list.elements[0].is_null) {
                auto err = extract_error(list.elements[0]);
                p.error_condition = err.condition;
                p.error_description = err.description;
            }
            p.summary = p.error_condition ? ("error=" + *p.error_condition) : std::string();
            return;
        }
        p.summary = "unrecognized performative code " + hex_u64(code);
        return;
    }

    // SASL
    p.is_sasl = true;
    if (code == 0x40) {  // sasl-mechanisms
        static const std::vector<const char*> kNames = {"sasl-server-mechanisms"};
        p.fields = extract_fields(list, kNames);
        p.name = "sasl-mechanisms";
        p.summary = list.elements.empty() ? std::string() : ("mechanisms=" + list.elements[0].rendered);
        return;
    }
    if (code == 0x41) {  // sasl-init -- the credential-bearing performative, see SECURITY.
        p.name = "sasl-init";
        std::string mechanism = list_str(list, 0).value_or(std::string());
        p.sasl_mechanism = mechanism;
        p.cleartext_credentials = (mechanism == "PLAIN");
        std::optional<std::string> raw_resp = list_str(list, 1);
        if (raw_resp) {
            p.sasl_response_length = raw_resp->size();
            if (mechanism == "PLAIN") p.sasl_username = amqp_extract_plain_username(*raw_resp);
        }
        if (auto v = list_str(list, 2)) p.hostname = *v;
        p.fields.push_back({"mechanism", mechanism});
        p.fields.push_back(
            {"initial-response", p.sasl_response_length
                                      ? (std::string(kRedactedSecretPlaceholder) + " (" +
                                         std::to_string(*p.sasl_response_length) + " byte(s))")
                                      : std::string("<omitted>")});
        p.fields.push_back({"hostname", p.hostname.value_or("<omitted>")});
        p.summary = "mechanism=" + mechanism;
        return;
    }
    if (code == 0x42) {  // sasl-challenge
        static const std::vector<const char*> kNames = {"challenge"};
        p.fields = extract_fields(list, kNames);
        p.name = "sasl-challenge";
        p.summary = "";
        return;
    }
    if (code == 0x43) {  // sasl-response -- treated as sensitive defensively, see SECURITY.
        p.name = "sasl-response";
        std::optional<std::string> raw_resp = list_str(list, 0);
        if (raw_resp) p.sasl_response_length = raw_resp->size();
        p.fields.push_back(
            {"response", p.sasl_response_length
                             ? (std::string(kRedactedSecretPlaceholder) + " (" +
                                std::to_string(*p.sasl_response_length) + " byte(s))")
                             : std::string("<omitted>")});
        p.summary = "";
        return;
    }
    if (code == 0x44) {  // sasl-outcome
        static const std::vector<const char*> kNames = {"code", "additional-data"};
        p.fields = extract_fields(list, kNames);
        p.name = "sasl-outcome";
        if (auto v = list_uint(list, 0)) p.sasl_outcome_code = static_cast<uint8_t>(*v);
        std::string code_name = "unknown";
        if (p.sasl_outcome_code) {
            switch (*p.sasl_outcome_code) {
                case 0: code_name = "ok"; break;
                case 1: code_name = "auth"; break;
                case 2: code_name = "sys"; break;
                case 3: code_name = "sys-perm"; break;
                case 4: code_name = "sys-temp"; break;
                default: code_name = hex_u8(*p.sasl_outcome_code); break;
            }
        }
        p.summary = "code=" + code_name;
        return;
    }
    p.summary = "unrecognized SASL method code " + hex_u64(code);
}

}  // namespace

const char* amqp10_performative_name(uint64_t code) {
    switch (code) {
        case 0x10: return "open";
        case 0x11: return "begin";
        case 0x12: return "attach";
        case 0x13: return "flow";
        case 0x14: return "transfer";
        case 0x15: return "disposition";
        case 0x16: return "detach";
        case 0x17: return "end";
        case 0x18: return "close";
        default: return nullptr;
    }
}

const char* amqp10_sasl_performative_name(uint64_t code) {
    switch (code) {
        case 0x40: return "sasl-mechanisms";
        case 0x41: return "sasl-init";
        case 0x42: return "sasl-challenge";
        case 0x43: return "sasl-response";
        case 0x44: return "sasl-outcome";
        default: return nullptr;
    }
}

const char* amqp10_message_section_name(uint64_t descriptor_code) {
    switch (descriptor_code) {
        case 0x70: return "header";
        case 0x71: return "delivery-annotations";
        case 0x72: return "message-annotations";
        case 0x73: return "properties";
        case 0x74: return "application-properties";
        case 0x75: return "data";
        case 0x76: return "amqp-sequence";
        case 0x77: return "amqp-value";
        case 0x78: return "footer";
        default: return nullptr;
    }
}

const char* amqp10_delivery_state_name(uint64_t descriptor_code) {
    switch (descriptor_code) {
        case 0x23: return "received";
        case 0x24: return "accepted";
        case 0x25: return "rejected";
        case 0x26: return "released";
        case 0x27: return "modified";
        case 0x28: return "source";
        case 0x29: return "target";
        case 0x1d: return "error";
        case 0x30: return "coordinator";
        case 0x31: return "declare";
        case 0x32: return "discharge";
        case 0x33: return "declared";
        case 0x34: return "transactional-state";
        default: return nullptr;
    }
}

std::optional<Amqp10Frame> try_parse_amqp10_frame(ByteSpan candidate) {
    if (candidate.size() < 8) return std::nullopt;
    try {
        Cursor hc(candidate);
        uint32_t size_field = hc.u32be();
        uint8_t doff = hc.u8();
        uint8_t type_raw = hc.u8();
        uint16_t channel = hc.u16be();

        Amqp10Frame frame;
        frame.size_field = size_field;
        frame.doff = doff;
        frame.frame_type_raw = type_raw;
        frame.frame_type_name = type_raw == 0 ? "AMQP" : type_raw == 1 ? "SASL" : type_raw == 2 ? "TLS" : nullptr;
        frame.channel = channel;

        if (size_field < 8 || doff < 2) {
            frame.notes.push_back("malformed frame header (size=" + std::to_string(size_field) +
                                   ", doff=" + std::to_string(doff) + ")");
            frame.summary = "AMQP 1.0 frame (malformed header)";
            frame.wire_length = candidate.size();
            return frame;
        }

        bool have_full = candidate.size() >= size_field;
        frame.truncated = !have_full;
        frame.wire_length = have_full ? size_field : candidate.size();

        size_t body_offset = static_cast<size_t>(doff) * 4;
        size_t declared_total = have_full ? size_field : candidate.size();
        size_t clamped_offset = std::min(body_offset, candidate.size());
        size_t body_len = declared_total > body_offset ? declared_total - body_offset : 0;
        body_len = std::min(body_len, candidate.size() - clamped_offset);
        ByteSpan body_region = candidate.subspan(clamped_offset, body_len);

        const char* type_label = frame.frame_type_name ? frame.frame_type_name : "AMQP 1.0";

        if (body_region.empty()) {
            frame.is_empty = true;
            frame.summary = std::string(type_label) + " empty frame (keepalive), channel " +
                             std::to_string(channel);
            return frame;
        }

        Cursor bc(body_region);
        uint64_t code = 0;
        Amqp10Value list;
        bool have_fastpath = false;
        if (bc.remaining() >= 3) {
            uint8_t b0 = bc.u8();
            if (b0 == 0x00) {
                uint8_t b1 = bc.u8();
                if (b1 == 0x53) {
                    code = bc.u8();
                    list = read_amqp10_value(bc, 0);
                    have_fastpath = true;
                }
            }
        }

        if (!have_fastpath) {
            frame.notes.push_back("frame body does not begin with the expected described-type/"
                                   "smallulong performative prefix (0x00 0x53) -- not further decoded");
            frame.summary = std::string(type_label) + " frame, channel " + std::to_string(channel) + " (" +
                             std::to_string(body_region.size()) + " byte(s), not further decoded)";
            return frame;
        }

        Amqp10Performative p;
        p.code = code;
        build_amqp10_performative(code, type_raw == 1, list, p);
        if (!p.name) {
            p.name = type_raw == 1 ? amqp10_sasl_performative_name(code) : amqp10_performative_name(code);
        }

        if (code == 0x14 && type_raw != 1) {  // transfer -- walk the rest of the frame body.
            parse_amqp10_message_sections(bc, p);
        }

        if (p.name && std::string(p.name) == "sasl-init" && p.cleartext_credentials) {
            std::string note = "cleartext credential exchange: SASL mechanism \"PLAIN\" carries the "
                                "password in the clear on this connection";
            if (p.sasl_username) note += " (username: \"" + *p.sasl_username + "\")";
            p.notes.push_back(note);
        }
        if (p.name && std::string(p.name) == "sasl-outcome" && p.sasl_outcome_code &&
            *p.sasl_outcome_code != 0) {
            p.notes.push_back("SASL negotiation failed (code=" + std::to_string(*p.sasl_outcome_code) +
                               ") -- possible credential-probing when seen repeatedly from one peer");
        }
        if (p.name &&
            (std::string(p.name) == "detach" || std::string(p.name) == "end" ||
             std::string(p.name) == "close") &&
            p.error_condition) {
            p.notes.push_back(std::string(p.name) + " error condition: " + *p.error_condition +
                               (p.error_description ? (" (" + *p.error_description + ")") : std::string()));
        }

        std::string name_text = p.name ? p.name : ("0x" + hex_u64(code));
        frame.summary = std::string(type_label) + " " + name_text +
                         (p.summary.empty() ? std::string() : (" (" + p.summary + ")")) + ", channel " +
                         std::to_string(channel);
        for (const auto& n : p.notes) frame.notes.push_back(n);
        frame.performative = std::move(p);
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> amqp10_tcp_declared_length(ByteSpan candidate) {
    try {
        if (candidate.size() >= 4 && candidate.at(0) == 'A' && candidate.at(1) == 'M' &&
            candidate.at(2) == 'Q' && candidate.at(3) == 'P') {
            if (candidate.size() < 8) return std::nullopt;  // see amqp_common.hpp's own DETECTION
                                                               // POSTURE for why a split preamble is
                                                               // deliberately not buffered here.
            auto pre = try_parse_amqp_preamble(candidate);
            if (pre && pre->version == AmqpVersion::V10) return 8;
            return std::nullopt;  // not 1.0's own preamble pattern -- let amqp091 claim it instead.
        }
        if (candidate.size() < 4) return candidate.size() + 1;  // need the SIZE field itself first.
        Cursor c(candidate);
        uint32_t size_field = c.u32be();
        if (size_field < 8) return std::nullopt;  // below the minimum legal frame size.
        if (candidate.size() < 6) return 6;  // two-phase: need DOFF/TYPE too, same shape
                                                // ge_srtp_tcp_declared_length established.
        uint8_t doff = candidate.at(4);
        uint8_t type_raw = candidate.at(5);
        if (doff < 2 || type_raw > 2) return std::nullopt;
        return static_cast<size_t>(size_field);
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> Amqp10Decoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto& state = ctx.flow_state<AmqpFlowState>();

    if (auto pre = try_parse_amqp_preamble(payload)) {
        if (pre->version != AmqpVersion::V10) return std::nullopt;  // let Amqp091Decoder claim it.
        state.version = AmqpVersion::V10;
        Amqp10Result result;
        result.first.wire_length = 8;
        result.first.frame_type_name = pre->layer_name;
        result.first.summary = pre->summary;
        result.summary = pre->summary;
        return ProtocolResult::make<Amqp10Result>("amqp10", std::move(result));
    }

    // See amqp_common.hpp's own DETECTION POSTURE: decline entirely for a session whose preamble
    // this codebase never saw.
    if (state.version != AmqpVersion::V10) return std::nullopt;

    auto first = try_parse_amqp10_frame(payload);
    if (!first) return std::nullopt;

    Amqp10Result result;
    result.summary = first->summary;
    for (const auto& n : first->notes) result.notes.push_back(n);
    result.first = *first;

    const size_t kMax = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = first->wire_length;
    size_t count = 1;
    while (offset < payload.size() && count < kMax && !first->truncated && first->wire_length >= 8) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_amqp10_frame(rest);
        if (!next) break;
        ++count;
        result.notes.push_back("additional AMQP 1.0 frame " + std::to_string(count) +
                                " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                " (coalesced by the sender/OS): " + next->summary);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
        if (next->truncated || next->wire_length < 8) break;
    }
    if (count >= kMax) {
        result.notes.push_back("stopped after " + std::to_string(kMax) +
                                " AMQP 1.0 frame(s) in this one TCP payload, more may remain (safety cap)");
    }

    return ProtocolResult::make<Amqp10Result>("amqp10", std::move(result));
}

const ProtocolDecoder& amqp10_tcp_decoder() {
    static const Amqp10Decoder instance;
    return instance;
}

}  // namespace conduitscope
