// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/amqp091.hpp"

#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {
namespace {

size_t amqp091_max_nesting_depth() { return resource_limits().max_recursion_depth.value_or(16); }

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << static_cast<unsigned>(v);
    return s.str();
}

std::string read_amqp091_shortstr(Cursor& c) {
    uint8_t len = c.u8();
    ByteSpan b = c.bytes(len);
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

std::string read_amqp091_longstr(Cursor& c) {
    uint32_t len = c.u32be();
    ByteSpan b = c.bytes(len);
    return std::string(reinterpret_cast<const char*>(b.data()), b.size());
}

std::string render_amqp091_decimal(uint8_t scale, uint32_t mantissa) {
    std::string digits = std::to_string(mantissa);
    if (scale == 0) return digits;
    while (digits.size() <= static_cast<size_t>(scale)) digits = "0" + digits;
    digits.insert(digits.size() - scale, ".");
    return digits;
}

std::string render_table_inline(const std::vector<Amqp091Value>& entries) {
    std::ostringstream s;
    s << "{";
    bool first = true;
    for (const auto& e : entries) {
        if (!first) s << ", ";
        first = false;
        s << e.name << "=" << e.rendered;
    }
    s << "}";
    return s.str();
}

std::string render_amqp091_value(Cursor& c, size_t depth);

std::vector<Amqp091Value> parse_amqp091_table_entries(Cursor& c, size_t depth) {
    std::vector<Amqp091Value> entries;
    while (!c.at_end()) {
        uint8_t name_len = c.u8();
        ByteSpan name_bytes = c.bytes(name_len);
        std::string name(reinterpret_cast<const char*>(name_bytes.data()), name_bytes.size());
        std::string rendered = render_amqp091_value(c, depth + 1);
        entries.push_back({std::move(name), std::move(rendered)});
    }
    return entries;
}

std::vector<Amqp091Value> read_amqp091_table(Cursor& c, size_t depth) {
    uint32_t table_len = c.u32be();
    ByteSpan table_bytes = c.bytes(table_len);
    Cursor tc(table_bytes);
    return parse_amqp091_table_entries(tc, depth);
}

std::string render_amqp091_value(Cursor& c, size_t depth) {
    if (depth > amqp091_max_nesting_depth()) {
        throw ParseError("AMQP 0-9-1 field-table/array nesting exceeded safety cap");
    }
    uint8_t tag = c.u8();
    switch (tag) {
        case 't':
            return c.u8() != 0 ? "true" : "false";
        case 'b':
            return std::to_string(static_cast<int8_t>(c.u8()));
        case 'B':
            return std::to_string(c.u8());
        case 's':
            return std::to_string(static_cast<int16_t>(c.u16be()));
        case 'u':
            return std::to_string(c.u16be());
        case 'I':
            return std::to_string(static_cast<int32_t>(c.u32be()));
        case 'i':
            return std::to_string(c.u32be());
        case 'l':
            return std::to_string(static_cast<int64_t>(amqp_read_u64be(c)));
        case 'f':
            return std::to_string(amqp_read_f32be(c));
        case 'd':
            return std::to_string(amqp_read_f64be(c));
        case 'D': {
            uint8_t scale = c.u8();
            uint32_t mantissa = c.u32be();
            return render_amqp091_decimal(scale, mantissa);
        }
        case 'S':
            return read_amqp091_longstr(c);
        case 'A': {
            uint32_t arr_len = c.u32be();
            ByteSpan ab = c.bytes(arr_len);
            Cursor ac(ab);
            std::ostringstream s;
            s << "[";
            bool first = true;
            while (!ac.at_end()) {
                if (!first) s << ", ";
                first = false;
                s << render_amqp091_value(ac, depth + 1);
            }
            s << "]";
            return s.str();
        }
        case 'T':
            return std::to_string(amqp_read_u64be(c)) + " (unix timestamp)";
        case 'F':
            return render_table_inline(read_amqp091_table(c, depth + 1));
        case 'V':
            return "null";
        case 'x': {
            uint32_t len = c.u32be();
            ByteSpan b = c.bytes(len);
            return to_hex(b);
        }
        default:
            throw ParseError("unrecognized AMQP 0-9-1 field-table type tag " + hex_u8(tag));
    }
}

std::string amqp091_label(const Amqp091Method& m) {
    std::string cls = m.class_name ? std::string(m.class_name) : hex_u8(static_cast<uint8_t>(m.class_id));
    std::string mth = m.method_name ? std::string(m.method_name) : hex_u8(static_cast<uint8_t>(m.method_id));
    return cls + "." + mth;
}

// Decodes the argument list for every method whose exact byte layout this file's own sourcing
// pass confirmed (see amqp091.hpp's own WIRE FORMAT/SCOPE sections) -- returns true and fully
// populates `m.fields`/`m.summary` (plus any curated fields) when it did; returns false, leaving
// the cursor untouched, for every method this decoder deliberately leaves argument-undecoded.
bool decode_amqp091_method_arguments(Cursor& c, Amqp091Method& m) {
    const uint16_t class_id = m.class_id;
    const uint16_t method_id = m.method_id;

    if (class_id == 10) {  // Connection
        if (method_id == 10) {  // Start
            uint8_t vmaj = c.u8();
            uint8_t vmin = c.u8();
            auto props = read_amqp091_table(c, 0);
            std::string mechanisms = read_amqp091_longstr(c);
            std::string locales = read_amqp091_longstr(c);
            m.fields.push_back({"version-major", std::to_string(vmaj)});
            m.fields.push_back({"version-minor", std::to_string(vmin)});
            m.fields.push_back({"server-properties", render_table_inline(props)});
            m.fields.push_back({"mechanisms", mechanisms});
            m.fields.push_back({"locales", locales});
            m.summary = amqp091_label(m) + " (server-supported mechanisms: " + mechanisms + ")";
            return true;
        }
        if (method_id == 11) {  // Start-Ok -- the credential-bearing method, see REDACTION.
            auto props = read_amqp091_table(c, 0);
            std::string mechanism = read_amqp091_shortstr(c);
            uint32_t resp_len = c.u32be();
            ByteSpan resp = c.bytes(resp_len);
            std::string locale = read_amqp091_shortstr(c);

            m.is_start_ok = true;
            m.sasl_mechanism = mechanism;
            m.sasl_response_length = resp_len;
            m.cleartext_credentials = (mechanism == "PLAIN" || mechanism == "AMQPLAIN");

            if (mechanism == "PLAIN") {
                // RFC 4616-style: \x00 authcid \x00 passwd -- only the authcid (username) is ever
                // extracted, via the shared helper (amqp_common.hpp) amqp10.cpp's own sasl-init
                // handling reuses; the password's own byte range past its own \x00 separator is
                // never even looked at.
                std::string resp_str(reinterpret_cast<const char*>(resp.data()), resp.size());
                m.sasl_username = amqp_extract_plain_username(resp_str);
            } else if (mechanism == "AMQPLAIN") {
                // A field-table containing exactly LOGIN(longstr)/PASSWORD(longstr) -- only LOGIN
                // is ever surfaced. Parsed leniently: a malformed response just leaves
                // sasl_username unset (the password stays redacted regardless).
                try {
                    Cursor rc(resp);
                    for (const auto& e : parse_amqp091_table_entries(rc, 0)) {
                        if (e.name == "LOGIN") m.sasl_username = e.rendered;
                    }
                } catch (const ParseError&) {
                    // Leave sasl_username unset.
                }
            }

            m.fields.push_back({"client-properties", render_table_inline(props)});
            m.fields.push_back({"mechanism", mechanism});
            m.fields.push_back({"response", std::string(kRedactedSecretPlaceholder) + " (" +
                                                 std::to_string(resp_len) + " byte(s))"});
            m.fields.push_back({"locale", locale});
            m.summary = amqp091_label(m) + " (mechanism=" + mechanism + ")";
            return true;
        }
        if (method_id == 30 || method_id == 31) {  // Tune / Tune-Ok -- identical layout.
            uint16_t channel_max = c.u16be();
            uint32_t frame_max = c.u32be();
            uint16_t heartbeat = c.u16be();
            m.fields.push_back({"channel-max", std::to_string(channel_max)});
            m.fields.push_back({"frame-max", std::to_string(frame_max)});
            m.fields.push_back({"heartbeat", std::to_string(heartbeat)});
            m.summary = amqp091_label(m) + " (channel-max=" + std::to_string(channel_max) +
                        ", frame-max=" + std::to_string(frame_max) + ", heartbeat=" +
                        std::to_string(heartbeat) + ")";
            return true;
        }
        if (method_id == 40) {  // Open
            std::string vhost = read_amqp091_shortstr(c);
            std::string capabilities = read_amqp091_shortstr(c);  // reserved.
            uint8_t flags = c.u8();
            bool insist = (flags & 0x01) != 0;
            (void)capabilities;
            m.fields.push_back({"virtual-host", vhost});
            m.fields.push_back({"insist", insist ? "true" : "false"});
            m.summary = amqp091_label(m) + " (virtual-host=\"" + vhost + "\")";
            return true;
        }
        if (method_id == 41) {  // Open-Ok
            std::string known_hosts = read_amqp091_shortstr(c);  // reserved.
            (void)known_hosts;
            m.summary = amqp091_label(m);
            return true;
        }
        if (method_id == 50) {  // Close
            uint16_t reply_code = c.u16be();
            std::string reply_text = read_amqp091_shortstr(c);
            uint16_t close_class = c.u16be();
            uint16_t close_method = c.u16be();
            m.is_close = true;
            m.reply_code = reply_code;
            m.reply_text = reply_text;
            m.fields.push_back({"reply-code", std::to_string(reply_code)});
            m.fields.push_back({"reply-text", reply_text});
            m.fields.push_back({"class-id", std::to_string(close_class)});
            m.fields.push_back({"method-id", std::to_string(close_method)});
            m.summary = amqp091_label(m) + " (reply-code=" + std::to_string(reply_code) +
                        ", reply-text=\"" + reply_text + "\")";
            return true;
        }
        if (method_id == 51) {  // Close-Ok -- zero-argument.
            m.summary = amqp091_label(m);
            return true;
        }
        return false;
    }

    if (class_id == 20) {  // Channel
        if (method_id == 10) {  // Open
            std::string oob = read_amqp091_shortstr(c);  // reserved.
            (void)oob;
            m.summary = amqp091_label(m);
            return true;
        }
        if (method_id == 11) {  // Open-Ok
            std::string channel_id = read_amqp091_longstr(c);  // reserved.
            (void)channel_id;
            m.summary = amqp091_label(m);
            return true;
        }
        if (method_id == 40) {  // Close
            uint16_t reply_code = c.u16be();
            std::string reply_text = read_amqp091_shortstr(c);
            uint16_t close_class = c.u16be();
            uint16_t close_method = c.u16be();
            m.is_close = true;
            m.reply_code = reply_code;
            m.reply_text = reply_text;
            m.fields.push_back({"reply-code", std::to_string(reply_code)});
            m.fields.push_back({"reply-text", reply_text});
            m.fields.push_back({"class-id", std::to_string(close_class)});
            m.fields.push_back({"method-id", std::to_string(close_method)});
            m.summary = amqp091_label(m) + " (reply-code=" + std::to_string(reply_code) +
                        ", reply-text=\"" + reply_text + "\")";
            return true;
        }
        if (method_id == 41) {  // Close-Ok -- explicit "no args" in this file's own sourcing.
            m.summary = amqp091_label(m);
            return true;
        }
        return false;
    }

    if (class_id == 40) {  // Exchange
        if (method_id == 10) {  // Declare
            c.u16be();  // ticket, vestigial.
            std::string exchange = read_amqp091_shortstr(c);
            std::string type = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool passive = (flags & 0x01) != 0, durable = (flags & 0x02) != 0,
                 auto_delete = (flags & 0x04) != 0, internal = (flags & 0x08) != 0,
                 nowait = (flags & 0x10) != 0;
            auto args = read_amqp091_table(c, 0);
            m.fields.push_back({"exchange", exchange});
            m.fields.push_back({"type", type});
            m.fields.push_back({"passive", passive ? "true" : "false"});
            m.fields.push_back({"durable", durable ? "true" : "false"});
            m.fields.push_back({"auto-delete", auto_delete ? "true" : "false"});
            m.fields.push_back({"internal", internal ? "true" : "false"});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.fields.push_back({"arguments", render_table_inline(args)});
            m.summary = amqp091_label(m) + " (exchange=\"" + exchange + "\", type=" + type + ")";
            return true;
        }
        if (method_id == 11) {  // Declare-Ok -- explicit "no args".
            m.summary = amqp091_label(m);
            return true;
        }
        if (method_id == 20) {  // Delete
            c.u16be();  // ticket.
            std::string exchange = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool if_unused = (flags & 0x01) != 0, nowait = (flags & 0x02) != 0;
            m.fields.push_back({"exchange", exchange});
            m.fields.push_back({"if-unused", if_unused ? "true" : "false"});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.summary = amqp091_label(m) + " (exchange=\"" + exchange + "\")";
            return true;
        }
        if (method_id == 21) {  // Delete-Ok -- explicit "no args".
            m.summary = amqp091_label(m);
            return true;
        }
        return false;
    }

    if (class_id == 50) {  // Queue
        if (method_id == 10) {  // Declare
            c.u16be();  // ticket.
            std::string queue = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool passive = (flags & 0x01) != 0, durable = (flags & 0x02) != 0,
                 exclusive = (flags & 0x04) != 0, auto_delete = (flags & 0x08) != 0,
                 nowait = (flags & 0x10) != 0;
            auto args = read_amqp091_table(c, 0);
            m.fields.push_back({"queue", queue.empty() ? std::string("<auto-generate>") : queue});
            m.fields.push_back({"passive", passive ? "true" : "false"});
            m.fields.push_back({"durable", durable ? "true" : "false"});
            m.fields.push_back({"exclusive", exclusive ? "true" : "false"});
            m.fields.push_back({"auto-delete", auto_delete ? "true" : "false"});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.fields.push_back({"arguments", render_table_inline(args)});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\")";
            if (exclusive) {
                m.notes.push_back("queue declared exclusive -- only this connection may use it "
                                   "(a long-lived exclusive queue can be a leader-election/mutex pattern)");
            }
            return true;
        }
        if (method_id == 11) {  // Declare-Ok
            std::string queue = read_amqp091_shortstr(c);
            uint32_t message_count = c.u32be();
            uint32_t consumer_count = c.u32be();
            m.fields.push_back({"queue", queue});
            m.fields.push_back({"message-count", std::to_string(message_count)});
            m.fields.push_back({"consumer-count", std::to_string(consumer_count)});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\", message-count=" +
                        std::to_string(message_count) + ")";
            return true;
        }
        if (method_id == 20) {  // Bind
            c.u16be();  // ticket.
            std::string queue = read_amqp091_shortstr(c);
            std::string exchange = read_amqp091_shortstr(c);
            std::string routing_key = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool nowait = (flags & 0x01) != 0;
            auto args = read_amqp091_table(c, 0);
            m.fields.push_back({"queue", queue});
            m.fields.push_back({"exchange", exchange});
            m.fields.push_back({"routing-key", routing_key});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.fields.push_back({"arguments", render_table_inline(args)});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\", exchange=\"" + exchange +
                        "\", routing-key=\"" + routing_key + "\")";
            return true;
        }
        if (method_id == 40) {  // Delete
            c.u16be();  // ticket.
            std::string queue = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool if_unused = (flags & 0x01) != 0, if_empty = (flags & 0x02) != 0,
                 nowait = (flags & 0x04) != 0;
            m.fields.push_back({"queue", queue});
            m.fields.push_back({"if-unused", if_unused ? "true" : "false"});
            m.fields.push_back({"if-empty", if_empty ? "true" : "false"});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\")";
            return true;
        }
        if (method_id == 41) {  // Delete-Ok
            uint32_t message_count = c.u32be();
            m.fields.push_back({"message-count", std::to_string(message_count)});
            m.summary = amqp091_label(m) + " (message-count=" + std::to_string(message_count) + ")";
            return true;
        }
        return false;
    }

    if (class_id == 60) {  // Basic
        if (method_id == 10) {  // Qos
            uint32_t prefetch_size = c.u32be();
            uint16_t prefetch_count = c.u16be();
            bool global = c.u8() != 0;
            m.fields.push_back({"prefetch-size", std::to_string(prefetch_size)});
            m.fields.push_back({"prefetch-count", std::to_string(prefetch_count)});
            m.fields.push_back({"global", global ? "true" : "false"});
            m.summary = amqp091_label(m) + " (prefetch-count=" + std::to_string(prefetch_count) + ")";
            return true;
        }
        if (method_id == 20) {  // Consume
            c.u16be();  // ticket.
            std::string queue = read_amqp091_shortstr(c);
            std::string consumer_tag = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool no_local = (flags & 0x01) != 0, no_ack = (flags & 0x02) != 0,
                 exclusive = (flags & 0x04) != 0, nowait = (flags & 0x08) != 0;
            auto args = read_amqp091_table(c, 0);
            m.fields.push_back({"queue", queue});
            m.fields.push_back({"consumer-tag", consumer_tag});
            m.fields.push_back({"no-local", no_local ? "true" : "false"});
            m.fields.push_back({"no-ack", no_ack ? "true" : "false"});
            m.fields.push_back({"exclusive", exclusive ? "true" : "false"});
            m.fields.push_back({"nowait", nowait ? "true" : "false"});
            m.fields.push_back({"arguments", render_table_inline(args)});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\")";
            return true;
        }
        if (method_id == 21) {  // Consume-Ok
            std::string consumer_tag = read_amqp091_shortstr(c);
            m.fields.push_back({"consumer-tag", consumer_tag});
            m.summary = amqp091_label(m) + " (consumer-tag=\"" + consumer_tag + "\")";
            return true;
        }
        if (method_id == 40) {  // Publish
            c.u16be();  // ticket.
            std::string exchange = read_amqp091_shortstr(c);
            std::string routing_key = read_amqp091_shortstr(c);
            uint8_t flags = c.u8();
            bool mandatory = (flags & 0x01) != 0, immediate = (flags & 0x02) != 0;
            m.is_basic_publish = true;
            m.publish_immediate = immediate;
            m.fields.push_back({"exchange", exchange.empty() ? std::string("<default exchange>") : exchange});
            m.fields.push_back({"routing-key", routing_key});
            m.fields.push_back({"mandatory", mandatory ? "true" : "false"});
            m.fields.push_back({"immediate", immediate ? "true" : "false"});
            m.summary = amqp091_label(m) + " (exchange=\"" + exchange + "\", routing-key=\"" +
                        routing_key + "\")";
            return true;
        }
        if (method_id == 60) {  // Deliver
            std::string consumer_tag = read_amqp091_shortstr(c);
            uint64_t delivery_tag = amqp_read_u64be(c);
            bool redelivered = c.u8() != 0;
            std::string exchange = read_amqp091_shortstr(c);
            std::string routing_key = read_amqp091_shortstr(c);
            m.fields.push_back({"consumer-tag", consumer_tag});
            m.fields.push_back({"delivery-tag", std::to_string(delivery_tag)});
            m.fields.push_back({"redelivered", redelivered ? "true" : "false"});
            m.fields.push_back({"exchange", exchange});
            m.fields.push_back({"routing-key", routing_key});
            m.summary = amqp091_label(m) + " (consumer-tag=\"" + consumer_tag + "\", routing-key=\"" +
                        routing_key + "\")";
            return true;
        }
        if (method_id == 70) {  // Get
            c.u16be();  // ticket.
            std::string queue = read_amqp091_shortstr(c);
            bool no_ack = c.u8() != 0;
            m.fields.push_back({"queue", queue});
            m.fields.push_back({"no-ack", no_ack ? "true" : "false"});
            m.summary = amqp091_label(m) + " (queue=\"" + queue + "\")";
            return true;
        }
        if (method_id == 71) {  // Get-Ok
            uint64_t delivery_tag = amqp_read_u64be(c);
            bool redelivered = c.u8() != 0;
            std::string exchange = read_amqp091_shortstr(c);
            std::string routing_key = read_amqp091_shortstr(c);
            uint32_t message_count = c.u32be();
            m.fields.push_back({"delivery-tag", std::to_string(delivery_tag)});
            m.fields.push_back({"redelivered", redelivered ? "true" : "false"});
            m.fields.push_back({"exchange", exchange});
            m.fields.push_back({"routing-key", routing_key});
            m.fields.push_back({"message-count", std::to_string(message_count)});
            m.summary = amqp091_label(m) + " (routing-key=\"" + routing_key + "\")";
            return true;
        }
        if (method_id == 72) {  // Get-Empty
            std::string cluster_id = read_amqp091_shortstr(c);  // reserved.
            (void)cluster_id;
            m.summary = amqp091_label(m);
            return true;
        }
        if (method_id == 80) {  // Ack
            uint64_t delivery_tag = amqp_read_u64be(c);
            bool multiple = c.u8() != 0;
            m.fields.push_back({"delivery-tag", std::to_string(delivery_tag)});
            m.fields.push_back({"multiple", multiple ? "true" : "false"});
            m.summary = amqp091_label(m) + " (delivery-tag=" + std::to_string(delivery_tag) + ")";
            return true;
        }
        if (method_id == 90) {  // Reject
            uint64_t delivery_tag = amqp_read_u64be(c);
            bool requeue = c.u8() != 0;
            m.fields.push_back({"delivery-tag", std::to_string(delivery_tag)});
            m.fields.push_back({"requeue", requeue ? "true" : "false"});
            m.summary = amqp091_label(m) + " (delivery-tag=" + std::to_string(delivery_tag) + ")";
            return true;
        }
        if (method_id == 120) {  // Nack (RabbitMQ extension)
            uint64_t delivery_tag = amqp_read_u64be(c);
            uint8_t flags = c.u8();
            bool multiple = (flags & 0x01) != 0, requeue = (flags & 0x02) != 0;
            m.fields.push_back({"delivery-tag", std::to_string(delivery_tag)});
            m.fields.push_back({"multiple", multiple ? "true" : "false"});
            m.fields.push_back({"requeue", requeue ? "true" : "false"});
            m.summary = amqp091_label(m) + " (delivery-tag=" + std::to_string(delivery_tag) + ")";
            return true;
        }
        return false;
    }

    if (class_id == 90 &&  // Tx -- all six confirmed zero-argument.
        (method_id == 10 || method_id == 11 || method_id == 20 || method_id == 21 || method_id == 30 ||
         method_id == 31)) {
        m.summary = amqp091_label(m);
        return true;
    }

    return false;
}

Amqp091ContentHeader parse_amqp091_content_header(ByteSpan payload_region) {
    Cursor c(payload_region);
    Amqp091ContentHeader ch;
    ch.class_id = c.u16be();
    ch.weight = c.u16be();
    ch.body_size = amqp_read_u64be(c);
    ch.property_flags = c.u16be();

    struct PropBit {
        uint16_t mask;
        const char* name;
    };
    static const PropBit kBits[] = {
        {0x8000, "content-type"}, {0x4000, "content-encoding"}, {0x2000, "headers"},
        {0x1000, "delivery-mode"}, {0x0800, "priority"},         {0x0400, "correlation-id"},
        {0x0200, "reply-to"},      {0x0100, "expiration"},       {0x0080, "message-id"},
        {0x0040, "timestamp"},     {0x0020, "type"},             {0x0010, "user-id"},
        {0x0008, "app-id"},        {0x0004, "cluster-id"},
    };
    for (const auto& bit : kBits) {
        if (!(ch.property_flags & bit.mask)) continue;
        std::string name = bit.name;
        if (name == "headers") {
            ch.properties.push_back({name, render_table_inline(read_amqp091_table(c, 0))});
        } else if (name == "delivery-mode") {
            uint8_t dm = c.u8();
            std::string r = dm == 2 ? "2 (persistent)" : dm == 1 ? "1 (non-persistent)" : std::to_string(dm);
            ch.properties.push_back({name, r});
        } else if (name == "priority") {
            ch.properties.push_back({name, std::to_string(c.u8())});
        } else if (name == "timestamp") {
            ch.properties.push_back({name, std::to_string(amqp_read_u64be(c))});
        } else {
            ch.properties.push_back({name, read_amqp091_shortstr(c)});
        }
    }

    const char* class_name = amqp091_class_name(ch.class_id);
    ch.summary = "class=" + std::string(class_name ? class_name : hex_u8(static_cast<uint8_t>(ch.class_id))) +
                 " body-size=" + std::to_string(ch.body_size);
    return ch;
}

}  // namespace

const char* amqp091_class_name(uint16_t class_id) {
    switch (class_id) {
        case 10: return "Connection";
        case 20: return "Channel";
        case 30: return "Access";
        case 40: return "Exchange";
        case 50: return "Queue";
        case 60: return "Basic";
        case 70: return "File";
        case 80: return "Stream";
        case 85: return "Confirm";
        case 90: return "Tx";
        case 100: return "Dtx";
        case 110: return "Tunnel";
        default: return nullptr;
    }
}

const char* amqp091_method_name(uint16_t class_id, uint16_t method_id) {
    switch (class_id) {
        case 10:
            switch (method_id) {
                case 10: return "Start";
                case 11: return "Start-Ok";
                case 20: return "Secure";
                case 21: return "Secure-Ok";
                case 30: return "Tune";
                case 31: return "Tune-Ok";
                case 40: return "Open";
                case 41: return "Open-Ok";
                case 42: return "Redirect";
                case 50: return "Close";
                case 51: return "Close-Ok";
                case 60: return "Blocked";
                case 61: return "Unblocked";
                default: return nullptr;
            }
        case 20:
            switch (method_id) {
                case 10: return "Open";
                case 11: return "Open-Ok";
                case 20: return "Flow";
                case 21: return "Flow-Ok";
                case 40: return "Close";
                case 41: return "Close-Ok";
                case 50: return "Resume";
                case 60: return "Ping";
                case 70: return "Pong";
                case 80: return "Ok";
                default: return nullptr;
            }
        case 40:
            switch (method_id) {
                case 10: return "Declare";
                case 11: return "Declare-Ok";
                case 20: return "Delete";
                case 21: return "Delete-Ok";
                case 30: return "Bind";
                case 31: return "Bind-Ok";
                case 40: return "Unbind";
                case 51: return "Unbind-Ok";
                default: return nullptr;
            }
        case 50:
            switch (method_id) {
                case 10: return "Declare";
                case 11: return "Declare-Ok";
                case 20: return "Bind";
                case 21: return "Bind-Ok";
                case 30: return "Purge";
                case 31: return "Purge-Ok";
                case 40: return "Delete";
                case 41: return "Delete-Ok";
                case 50: return "Unbind";
                case 51: return "Unbind-Ok";
                default: return nullptr;
            }
        case 60:
            switch (method_id) {
                case 10: return "Qos";
                case 11: return "Qos-Ok";
                case 20: return "Consume";
                case 21: return "Consume-Ok";
                case 30: return "Cancel";
                case 31: return "Cancel-Ok";
                case 40: return "Publish";
                case 50: return "Return";
                case 60: return "Deliver";
                case 70: return "Get";
                case 71: return "Get-Ok";
                case 72: return "Get-Empty";
                case 80: return "Ack";
                case 90: return "Reject";
                case 100: return "Recover-Async";
                case 110: return "Recover";
                case 111: return "Recover-Ok";
                case 120: return "Nack";
                default: return nullptr;
            }
        case 85:
            switch (method_id) {
                case 10: return "Select";
                case 11: return "Select-Ok";
                default: return nullptr;
            }
        case 90:
            switch (method_id) {
                case 10: return "Select";
                case 11: return "Select-Ok";
                case 20: return "Commit";
                case 21: return "Commit-Ok";
                case 30: return "Rollback";
                case 31: return "Rollback-Ok";
                default: return nullptr;
            }
        default:
            return nullptr;
    }
}

const char* amqp091_frame_type_name(uint8_t type_raw) {
    switch (type_raw) {
        case 1: return "METHOD";
        case 2: return "HEADER";
        case 3: return "BODY";
        case 4: return "OOB_METHOD";
        case 5: return "OOB_CONTENT_HEADER";
        case 6: return "OOB_CONTENT_BODY";
        case 7: return "TRACE";
        case 8: return "HEARTBEAT";
        default: return nullptr;
    }
}

std::optional<Amqp091Frame> try_parse_amqp091_frame(ByteSpan candidate) {
    if (candidate.size() < 7) return std::nullopt;
    try {
        Cursor hc(candidate);
        uint8_t type_raw = hc.u8();
        uint16_t channel = hc.u16be();
        uint32_t size = hc.u32be();

        Amqp091Frame frame;
        frame.type_raw = type_raw;
        frame.type_name = amqp091_frame_type_name(type_raw);
        frame.channel = channel;
        frame.declared_payload_size = size;

        size_t full_wire_length = 7 + static_cast<size_t>(size) + 1;
        bool have_full = candidate.size() >= full_wire_length;
        size_t payload_avail = have_full ? size : (candidate.size() > 7 ? candidate.size() - 7 : 0);
        frame.truncated = !have_full;
        frame.wire_length = have_full ? full_wire_length : candidate.size();
        ByteSpan payload_region = candidate.subspan(7, payload_avail);

        if (have_full) {
            uint8_t frame_end = candidate.at(7 + size);
            frame.frame_end_valid = (frame_end == 0xCE);
            if (!frame.frame_end_valid) {
                frame.notes.push_back("frame-end octet mismatch (expected 0xCE, got " + hex_u8(frame_end) +
                                       ") -- trailer not verified, decoding what's present anyway");
            }
        } else {
            frame.notes.push_back("frame truncated: only " + std::to_string(candidate.size()) + " of " +
                                   std::to_string(full_wire_length) + " declared byte(s) available");
        }

        switch (type_raw) {
            case 1: {  // METHOD
                if (payload_region.size() < 4) {
                    frame.notes.push_back("METHOD frame too short for class-id/method-id");
                    frame.summary = "AMQP 0-9-1 METHOD (channel " + std::to_string(channel) +
                                     ", truncated before class-id/method-id)";
                    break;
                }
                Cursor mc(payload_region);
                uint16_t class_id = mc.u16be();
                uint16_t method_id = mc.u16be();
                Amqp091Method m;
                m.class_id = class_id;
                m.method_id = method_id;
                m.class_name = amqp091_class_name(class_id);
                m.method_name = amqp091_method_name(class_id, method_id);

                bool decoded = false;
                try {
                    decoded = decode_amqp091_method_arguments(mc, m);
                } catch (const ParseError&) {
                    decoded = false;
                    m.notes.push_back("argument parse error -- truncated or malformed, arguments left "
                                       "undecoded");
                }
                m.arguments_decoded = decoded;
                if (!decoded) {
                    m.undecoded_argument_bytes = mc.remaining();
                    m.summary = amqp091_label(m) + " (arguments not decoded -- layout not confirmed by "
                                                    "this decoder's sourcing pass, " +
                                std::to_string(m.undecoded_argument_bytes) + " byte(s))";
                }

                // Curated findings -- see this file's own SECURITY section.
                if (m.is_start_ok && m.cleartext_credentials) {
                    std::string note = "cleartext credential exchange: SASL mechanism \"" +
                                        *m.sasl_mechanism + "\" carries the password in the clear on "
                                        "this connection";
                    if (m.sasl_username) note += " (username: \"" + *m.sasl_username + "\")";
                    m.notes.push_back(note);
                } else if (m.is_start_ok && m.sasl_mechanism && *m.sasl_mechanism == "EXTERNAL") {
                    m.notes.push_back("EXTERNAL mechanism selected -- normally used only over a "
                                       "TLS-secured connection, but no TLS handshake is visible in this "
                                       "capture; may simply mean the capture doesn't include the TLS setup");
                }
                if (m.is_close && m.reply_code && *m.reply_code >= 400) {
                    m.notes.push_back("closed with reply-code " + std::to_string(*m.reply_code) +
                                       " (>= 400, a client-error-class close) -- possibly a "
                                       "credential-probing or access-control rejection");
                }
                if (m.is_basic_publish && m.publish_immediate) {
                    m.notes.push_back("Basic.Publish with immediate=true -- RabbitMQ >= 3.0 rejects this "
                                       "(NOT_IMPLEMENTED); seeing it set suggests an old broker/client or "
                                       "probing");
                }

                frame.summary = "AMQP 0-9-1 METHOD (channel " + std::to_string(channel) + "): " + m.summary;
                for (const auto& n : m.notes) frame.notes.push_back(n);
                frame.method = std::move(m);
                break;
            }
            case 2: {  // HEADER
                try {
                    Amqp091ContentHeader ch = parse_amqp091_content_header(payload_region);
                    frame.summary = "AMQP 0-9-1 HEADER (channel " + std::to_string(channel) + "): " +
                                     ch.summary;
                    frame.content_header = std::move(ch);
                } catch (const ParseError&) {
                    frame.notes.push_back("content-header truncated or malformed");
                    frame.summary = "AMQP 0-9-1 HEADER (channel " + std::to_string(channel) +
                                     ", truncated/malformed)";
                }
                break;
            }
            case 3: {  // BODY
                frame.body_bytes = payload_region.size();
                frame.summary = "AMQP 0-9-1 BODY (channel " + std::to_string(channel) + "): " +
                                 std::to_string(payload_region.size()) + " byte(s)";
                break;
            }
            case 8: {  // HEARTBEAT
                frame.summary = "AMQP 0-9-1 HEARTBEAT";
                break;
            }
            default: {
                frame.summary = "AMQP 0-9-1 " +
                                 std::string(frame.type_name ? frame.type_name : "Unrecognized frame type") +
                                 " (channel " + std::to_string(channel) + ", " +
                                 std::to_string(payload_region.size()) + " byte(s), not further decoded)";
                break;
            }
        }

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> amqp091_tcp_declared_length(ByteSpan candidate) {
    try {
        if (candidate.size() >= 4 && candidate.at(0) == 'A' && candidate.at(1) == 'M' &&
            candidate.at(2) == 'Q' && candidate.at(3) == 'P') {
            // A connection preamble -- see amqp_common.hpp's own DETECTION POSTURE for why a split
            // preamble is deliberately NOT buffered here (a genuine, documented scope limit; a real
            // preamble is 8 bytes and essentially never split across TCP segments in practice).
            if (candidate.size() < 8) return std::nullopt;
            auto pre = try_parse_amqp_preamble(candidate);
            if (pre && pre->version == AmqpVersion::V091) return 8;
            return std::nullopt;  // not 0-9-1's own preamble pattern -- let amqp10 try it instead.
        }
        if (candidate.empty()) return std::nullopt;
        uint8_t type_raw = candidate.at(0);
        if (type_raw < 1 || type_raw > 8) return std::nullopt;
        if (candidate.size() < 7) return candidate.size() + 1;  // two-phase, same shape
                                                                   // ge_srtp_tcp_declared_length
                                                                   // established for its own header.
        Cursor c(candidate);
        c.u8();
        c.u16be();
        uint32_t size = c.u32be();
        return static_cast<size_t>(size) + 8;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> Amqp091Decoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto& state = ctx.flow_state<AmqpFlowState>();

    if (auto pre = try_parse_amqp_preamble(payload)) {
        if (pre->version != AmqpVersion::V091) return std::nullopt;  // let Amqp10Decoder claim it.
        state.version = AmqpVersion::V091;
        Amqp091Result result;
        result.first.wire_length = 8;
        result.first.summary = pre->summary;
        result.summary = pre->summary;
        return ProtocolResult::make<Amqp091Result>("amqp091", std::move(result));
    }

    // See amqp_common.hpp's own DETECTION POSTURE: decline entirely for a session whose preamble
    // this codebase never saw, rather than guessing from a byte-coincidence heuristic.
    if (state.version != AmqpVersion::V091) return std::nullopt;

    auto first = try_parse_amqp091_frame(payload);
    if (!first) return std::nullopt;

    Amqp091Result result;
    result.summary = first->summary;
    for (const auto& n : first->notes) result.notes.push_back(n);
    result.first = *first;

    const size_t kMax = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = first->wire_length;
    size_t count = 1;
    while (offset < payload.size() && count < kMax && !first->truncated) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_amqp091_frame(rest);
        if (!next) break;
        ++count;
        result.notes.push_back("additional AMQP 0-9-1 frame " + std::to_string(count) +
                                " found in the same TCP payload at byte offset " + std::to_string(offset) +
                                " (coalesced by the sender/OS): " + next->summary);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
        if (next->truncated) break;
    }
    if (count >= kMax) {
        result.notes.push_back("stopped after " + std::to_string(kMax) +
                                " AMQP 0-9-1 frame(s) in this one TCP payload, more may remain (safety cap)");
    }

    return ProtocolResult::make<Amqp091Result>("amqp091", std::move(result));
}

const ProtocolDecoder& amqp091_tcp_decoder() {
    static const Amqp091Decoder instance;
    return instance;
}

}  // namespace conduitscope
