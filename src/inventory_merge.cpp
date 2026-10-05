// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/inventory_merge.hpp"

#include <algorithm>
#include <cctype>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "conduitscope/ipv4.hpp"
#include "conduitscope/policy.hpp"  // CidrBlock/parse_cidr -- zone re-derivation, see this file's
                                    // own merge_inventory_reports header comment

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// A tiny hand-rolled, TOLERANT JSON reader -- see inventory_merge.hpp's own file header comment
// for why this is deliberately more permissive than baseline.cpp's own JsonCursor (which rejects
// any field it doesn't recognize): an inventory report can legitimately carry extra,
// resolver-derived fields this merge has no use for, and needs to just skip over them rather than
// fail. Modeled directly on baseline.cpp's own JsonCursor for the parts that ARE shared (string/
// integer/bool parsing, the expect/consume_if/fail idiom); adds parse_double (inventory's
// first_seen/last_seen are epoch-seconds floats, unlike anything baseline.cpp's own schema needs)
// and skip_value (recursively consumes and discards one JSON value of any shape, for every field
// this merge doesn't read).
// ------------------------------------------------------------------------------------------
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

    bool consume_if(char c) {
        skip_ws();
        if (pos_ < text_.size() && text_[pos_] == c) {
            ++pos_;
            return true;
        }
        return false;
    }

    // True and consumes the literal if it's next (after whitespace); false and consumes nothing
    // otherwise. Used for "null" (mac's nullable value) -- see parse_asset below.
    bool consume_literal(const char* literal) {
        skip_ws();
        size_t len = std::char_traits<char>::length(literal);
        if (text_.compare(pos_, len, literal) == 0) {
            pos_ += len;
            return true;
        }
        return false;
    }

    // F5 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 137, DEVELOPMENT.md):
    // encodes one Unicode code point -- already resolved from a single \uXXXX escape, or from a
    // combined UTF-16 surrogate pair (see parse_string()'s own 'u' case below) -- as UTF-8 bytes
    // appended to `out`. Standard 1/2/3/4-byte UTF-8 encoding; by the time this is called,
    // parse_string() has already rejected any unpaired surrogate, so `code` is always a valid
    // Unicode scalar value here and no further validation happens in this function.
    static void append_utf8(unsigned code, std::string& out) {
        if (code <= 0x7F) {
            out += static_cast<char>(code);
        } else if (code <= 0x7FF) {
            out += static_cast<char>(0xC0 | (code >> 6));
            out += static_cast<char>(0x80 | (code & 0x3F));
        } else if (code <= 0xFFFF) {
            out += static_cast<char>(0xE0 | (code >> 12));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (code & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (code >> 18));
            out += static_cast<char>(0x80 | ((code >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((code >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (code & 0x3F));
        }
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
                        // F5 fix: real UTF-16 surrogate-pair handling and UTF-8 encoding, replacing
                        // the old `static_cast<char>(code & 0xFF)` truncation -- confirmed, before
                        // this fix, that e.g. "é" ('e'-acute) became the single raw byte 0xE9
                        // (not valid UTF-8 on its own) instead of 'e'-acute's actual 2-byte UTF-8
                        // encoding (0xC3 0xA9). A lone/unpaired surrogate is rejected outright
                        // rather than silently producing a nonsense byte for it: RFC 8259 itself
                        // doesn't define \u surrogate-pair semantics, but every real-world JSON
                        // producer -- including this project's own baseline.cpp json_escape --
                        // emits any codepoint above the Basic Multilingual Plane as two consecutive
                        // \uXXXX escapes (a high surrogate 0xD800-0xDBFF immediately followed by a
                        // low surrogate 0xDC00-0xDFFF), so anything else is malformed input.
                        if (code >= 0xD800 && code <= 0xDBFF) {
                            if (pos_ + 6 > text_.size() || text_[pos_] != '\\' || text_[pos_ + 1] != 'u') {
                                fail("unpaired UTF-16 high surrogate in \\u escape (not followed by "
                                     "a low surrogate)");
                            }
                            pos_ += 2;  // consume the second escape's leading "\u"
                            unsigned low = 0;
                            for (int i = 0; i < 4; ++i) {
                                char h = text_[pos_++];
                                low <<= 4;
                                if (h >= '0' && h <= '9') low |= static_cast<unsigned>(h - '0');
                                else if (h >= 'a' && h <= 'f') low |= static_cast<unsigned>(h - 'a' + 10);
                                else if (h >= 'A' && h <= 'F') low |= static_cast<unsigned>(h - 'A' + 10);
                                else fail("invalid \\u escape digit");
                            }
                            if (low < 0xDC00 || low > 0xDFFF) {
                                fail("UTF-16 high surrogate in \\u escape not followed by a valid "
                                     "low surrogate");
                            }
                            unsigned codepoint = 0x10000u + ((code - 0xD800u) << 10) + (low - 0xDC00u);
                            append_utf8(codepoint, out);
                        } else if (code >= 0xDC00 && code <= 0xDFFF) {
                            fail("unpaired UTF-16 low surrogate in \\u escape");
                        } else {
                            append_utf8(code, out);
                        }
                        break;
                    }
                    default: fail("unrecognized string escape");
                }
            } else {
                // F5 fix: RFC 8259 section 7 forbids an unescaped control character (U+0000-U+001F)
                // appearing literally inside a JSON string -- it must be escaped (\n, \t, \u0000,
                // ...) instead. Confirmed, before this fix, that this parser silently accepted one
                // verbatim into the resulting string, exactly as the finding describes.
                if (static_cast<unsigned char>(c) <= 0x1F) {
                    static const char kHexDigits[] = "0123456789ABCDEF";
                    unsigned char uc = static_cast<unsigned char>(c);
                    std::string hex;
                    hex += kHexDigits[(uc >> 4) & 0xF];
                    hex += kHexDigits[uc & 0xF];
                    fail("unescaped control character 0x" + hex + " in string literal");
                }
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
        std::string literal = text_.substr(start, pos_ - start);
        try {
            return std::stoll(literal);
        } catch (const std::exception&) {
            // A JSON number with more digits than fit in a `long long` (e.g.
            // "99999999999999999999999999999999") is syntactically a perfectly fine JSON number,
            // but std::stoll throws std::out_of_range on it -- confirmed, before this fix, to
            // crash the whole process (an uncaught C++ exception, SIGABRT) rather than fail
            // cleanly, since only InventoryMergeError/ResolverError are caught around
            // `merge inventory`'s own call stack (run_merge_inventory, cli_main.cpp). Found
            // incidentally while hardening this same function for patch295 finding F2 (item 134,
            // DEVELOPMENT.md) and fixed in the same pass rather than left as a separate crash.
            fail("integer literal '" + literal + "' is out of range");
        }
    }

    // F2 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 134, DEVELOPMENT.md):
    // wraps parse_integer() above with the non-negativity check the finding's own "Recommended
    // fix" list asks for (packet_count/skipped_packets/total_packets) -- confirmed, before this
    // fix, that a crafted "packet_count": -1 silently became 18446744073709551615 (SIZE_MAX) via
    // the unguarded `static_cast<size_t>` narrowing conversion the finding points at, rather than
    // being rejected. `field_name` is folded into the thrown InventoryMergeError so the operator
    // can tell which field/value tripped it.
    size_t parse_non_negative_integer(const char* field_name) {
        long long v = parse_integer();
        if (v < 0) {
            fail_semantic(std::string(field_name) + " must not be negative, got " + std::to_string(v));
        }
        return static_cast<size_t>(v);
    }

    // F2 fix: the same idea as parse_non_negative_integer above, specifically for `server_port` --
    // semantically a 16-bit TCP/UDP port even though the JSON wire format carries it as a plain
    // number. Confirmed, before this fix, that a crafted "server_port": -1 silently became 65535
    // via the unguarded `static_cast<uint16_t>` narrowing conversion the finding's own example
    // shows, exactly as described; rejects anything outside [0, 65535] instead of truncating it.
    uint16_t parse_port(const char* field_name) {
        long long v = parse_integer();
        if (v < 0 || v > 65535) {
            fail_semantic(std::string(field_name) + " must be a port number in [0, 65535], got " +
                          std::to_string(v));
        }
        return static_cast<uint16_t>(v);
    }

    double parse_double() {
        skip_ws();
        size_t start = pos_;
        if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
        bool saw_digit = false;
        while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
            ++pos_;
            saw_digit = true;
        }
        if (pos_ < text_.size() && text_[pos_] == '.') {
            ++pos_;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) {
                ++pos_;
                saw_digit = true;
            }
        }
        if (!saw_digit) fail("expected a number");
        if (pos_ < text_.size() && (text_[pos_] == 'e' || text_[pos_] == 'E')) {
            size_t exp_start = pos_;
            ++pos_;
            if (pos_ < text_.size() && (text_[pos_] == '-' || text_[pos_] == '+')) ++pos_;
            size_t exp_digits_start = pos_;
            while (pos_ < text_.size() && std::isdigit(static_cast<unsigned char>(text_[pos_]))) ++pos_;
            if (pos_ == exp_digits_start) pos_ = exp_start;  // not actually an exponent -- back off
        }
        return std::stod(text_.substr(start, pos_ - start));
    }

    bool parse_bool() {
        skip_ws();
        if (consume_literal("true")) return true;
        if (consume_literal("false")) return false;
        fail("expected true or false");
        return false;  // unreachable
    }

    // F3 fix (docs/reviews/2026-10-chatgpt-security-review-patch295.md; item 135,
    // DEVELOPMENT.md): skip_value() just below is the one place in this whole parser that
    // recurses arbitrarily deep -- once per nesting level of whatever object/array structure it's
    // asked to discard. The existing 256 MiB per-file byte ceiling (item 122/F5) bounds how much
    // JSON TEXT there can be, but says nothing about how DEEPLY NESTED it is: a tiny, compact,
    // nowhere-near-the-ceiling file shaped like {"x":{"x":{"x": ... }}} can still recurse
    // arbitrarily deep. Confirmed, before this fix, that a 12 MB file with 2,000,000 nesting
    // levels crashes the whole process outright (a real stack overflow, SIGSEGV) rather than
    // failing cleanly -- the exact "256 MiB file-size limit != bounded parser recursion"
    // distinction the finding names. Same shape, same constant name and value, as
    // display_filter_parser.cpp's own kMaxNestingDepth (128, item 112/patch282 F2) -- the
    // "earlier parser hardening" this finding itself points back to.
    static constexpr size_t kMaxNestingDepth = 128;

    size_t skip_value_depth_ = 0;

    // Recursively consumes and discards exactly one JSON value (string/number/object/array/bool/
    // null) of whatever shape is next -- used for every field this merge doesn't need to read back.
    void skip_value() {
        char c = peek();
        if (c == '"') {
            parse_string();
        } else if (c == '{') {
            if (++skip_value_depth_ > kMaxNestingDepth) {
                fail("JSON nesting is deeper than the " + std::to_string(kMaxNestingDepth) +
                     "-level limit this parser allows");
            }
            expect('{');
            if (!consume_if('}')) {
                while (true) {
                    parse_string();  // key
                    expect(':');
                    skip_value();
                    if (consume_if(',')) continue;
                    break;
                }
                expect('}');
            }
            --skip_value_depth_;
        } else if (c == '[') {
            if (++skip_value_depth_ > kMaxNestingDepth) {
                fail("JSON nesting is deeper than the " + std::to_string(kMaxNestingDepth) +
                     "-level limit this parser allows");
            }
            expect('[');
            if (!consume_if(']')) {
                while (true) {
                    skip_value();
                    if (consume_if(',')) continue;
                    break;
                }
                expect(']');
            }
            --skip_value_depth_;
        } else if (c == 't' || c == 'f') {
            parse_bool();
        } else if (c == 'n') {
            if (!consume_literal("null")) fail("expected null");
        } else {
            parse_double();
        }
    }

    [[noreturn]] void fail(const std::string& what) {
        throw InventoryMergeError("inventory report: malformed JSON (" + what + ", at byte offset " +
                                   std::to_string(pos_) + ")");
    }

    // F2 fix: distinct from fail() above on purpose -- this is for a value that IS well-formed
    // JSON but semantically invalid for the field it's in (a negative count, an out-of-range port,
    // a malformed IP address string, last_seen before first_seen), so the thrown message doesn't
    // claim the JSON ITSELF is malformed, only that one field's value doesn't pass this merge's own
    // semantic checks.
    [[noreturn]] void fail_semantic(const std::string& what) {
        throw InventoryMergeError("inventory report: " + what + " (at byte offset " + std::to_string(pos_) + ")");
    }

private:
    const std::string& text_;
    size_t pos_ = 0;
};

std::vector<std::string> parse_string_array(JsonCursor& c) {
    std::vector<std::string> out;
    c.expect('[');
    if (!c.consume_if(']')) {
        while (true) {
            out.push_back(c.parse_string());
            if (c.consume_if(',')) continue;
            c.expect(']');
            break;
        }
    }
    return out;
}

DirectionSource parse_direction_source(const std::string& text) {
    if (text == "handshake") return DirectionSource::Handshake;
    if (text == "content") return DirectionSource::Content;
    return DirectionSource::PortHeuristic;  // "port-heuristic", or anything unrecognized -- the
                                             // least-authoritative tier is the safe fallback here,
                                             // never silently upgrading an unknown value.
}

// Handshake=0 (most authoritative) .. PortHeuristic=2 (least) -- see DirectionSource's own comment
// (decoder.hpp) for why this exact ordering. Used by merge_inventory_reports to keep the most
// authoritative direction_source across every input that observed the same edge.
int direction_source_rank(DirectionSource source) {
    switch (source) {
        case DirectionSource::Handshake: return 0;
        case DirectionSource::Content: return 1;
        case DirectionSource::PortHeuristic: return 2;
    }
    return 2;
}

InventoryAsset parse_asset(JsonCursor& c) {
    InventoryAsset a;
    bool have_ip = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "ip") {
                a.ip = c.parse_string();
                // F2 fix ("ideally validate... IP addresses are syntactically valid"): reuses
                // ipv4.hpp's own parse_ipv4_string, the single already-exported IPv4-syntax
                // validator this codebase has, rather than hand-rolling a second one that could
                // drift from it -- a real report's own `ip` is always a dotted-quad written by
                // write_inventory_report_json (format_ipv4), so this only ever rejects a crafted/
                // corrupted value, never a genuine one.
                if (!parse_ipv4_string(a.ip)) {
                    c.fail_semantic("asset 'ip' is not a syntactically valid IPv4 address: '" + a.ip + "'");
                }
                have_ip = true;
            } else if (key == "mac") {
                if (c.peek() == 'n') {
                    if (!c.consume_literal("null")) c.fail("expected null");
                    a.has_mac = false;
                } else {
                    a.mac = c.parse_string();
                    a.has_mac = true;
                }
            } else if (key == "protocols") {
                a.protocols = parse_string_array(c);
            } else if (key == "packet_count") {
                a.packet_count = c.parse_non_negative_integer("asset packet_count");
            } else if (key == "first_seen") {
                a.first_seen = c.parse_double();
            } else if (key == "last_seen") {
                a.last_seen = c.parse_double();
            } else if (key == "vendor") {
                a.vendor = c.parse_string();
            } else if (key == "product") {
                a.product = c.parse_string();
            } else if (key == "firmware_revision") {
                a.firmware_revision = c.parse_string();
            } else if (key == "serial_number") {
                a.serial_number = c.parse_string();
            } else if (key == "security_posture") {
                a.security_posture = c.parse_string();
            } else if (key == "plant_identification") {
                a.plant_identification = c.parse_string();
            } else if (key == "inferred_role") {
                a.inferred_role = c.parse_string();
            } else {
                // hostname/mac_vendor/role/first_seen_text/last_seen_text, or any future addition
                // this merge doesn't read back -- see this file's own header comment.
                c.skip_value();
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_ip) c.fail("asset object missing required field 'ip'");
    // F2 fix ("ideally validate... first_seen <= last_seen"): checked here, once the whole object
    // is parsed, rather than inline above, because JSON object field order isn't guaranteed --
    // last_seen can legally appear before first_seen on the wire. A genuine report's own first/
    // last-seen are always a real min/max pair by construction (asset_inventory.cpp), so this only
    // ever rejects a crafted/corrupted value.
    if (a.first_seen > a.last_seen) {
        c.fail_semantic("asset '" + a.ip + "' has first_seen (" + std::to_string(a.first_seen) +
                         ") after last_seen (" + std::to_string(a.last_seen) + ")");
    }
    return a;
}

InventoryEdge parse_edge(JsonCursor& c) {
    InventoryEdge e;
    bool have_client = false, have_server = false, have_protocol = false, have_port = false;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "client_ip") {
                e.client_ip = c.parse_string();
                // F2 fix -- see parse_asset's own identical check (and comment) above for why.
                if (!parse_ipv4_string(e.client_ip)) {
                    c.fail_semantic("edge 'client_ip' is not a syntactically valid IPv4 address: '" +
                                    e.client_ip + "'");
                }
                have_client = true;
            } else if (key == "server_ip") {
                e.server_ip = c.parse_string();
                if (!parse_ipv4_string(e.server_ip)) {
                    c.fail_semantic("edge 'server_ip' is not a syntactically valid IPv4 address: '" +
                                    e.server_ip + "'");
                }
                have_server = true;
            } else if (key == "protocol") {
                e.protocol = c.parse_string();
                have_protocol = true;
            } else if (key == "server_port") {
                e.server_port = c.parse_port("edge server_port");
                have_port = true;
            } else if (key == "observed_functions") {
                e.observed_functions = parse_string_array(c);
            } else if (key == "packet_count") {
                e.packet_count = c.parse_non_negative_integer("edge packet_count");
            } else if (key == "direction_source") {
                e.direction_source = parse_direction_source(c.parse_string());
            } else if (key == "first_seen") {
                e.first_seen = c.parse_double();
            } else if (key == "last_seen") {
                e.last_seen = c.parse_double();
            } else {
                // client_hostname/server_hostname/server_port_service/first_seen_text/
                // last_seen_text/top_touched_addresses/touched_addresses_total_distinct/
                // touched_addresses_truncated -- see this file's own header comment on why
                // top_touched_addresses specifically can never be merged from this JSON alone.
                c.skip_value();
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    if (!have_client || !have_server || !have_protocol || !have_port) {
        c.fail("edge object missing a required field (client_ip/server_ip/protocol/server_port)");
    }
    // F2 fix -- see parse_asset's own identical check (and comment) above for why this runs here,
    // once the whole object is parsed, rather than inline above.
    if (e.first_seen > e.last_seen) {
        c.fail_semantic("edge " + e.client_ip + " -> " + e.server_ip + ":" + std::to_string(e.server_port) +
                         " (" + e.protocol + ") has first_seen (" + std::to_string(e.first_seen) +
                         ") after last_seen (" + std::to_string(e.last_seen) + ")");
    }
    return e;
}

uint32_t cidr_mask(uint8_t prefix_len) {
    if (prefix_len == 0) return 0;
    if (prefix_len >= 32) return 0xFFFFFFFFu;
    return ~uint32_t(0) << (32 - prefix_len);
}

// Deterministic zone name from the network itself -- byte-for-byte the same naming scheme
// asset_inventory.cpp's own (anonymous-namespace, not exported) zone_name_for uses, reimplemented
// here rather than shared -- see this file's own header comment for why merge_inventory_reports
// re-derives zones/conduits independently instead of depending on AssetInventoryEngine internals.
std::string zone_name_for(const CidrBlock& block) {
    std::string addr = format_ipv4(block.network);
    for (char& c : addr) {
        if (c == '.') c = '_';
    }
    return "zone_" + addr + "_" + std::to_string(block.prefix_len);
}

// Shared, cross-file asset/edge budget for read_inventory_report_files_for_merge's F1 aggregate
// checks below -- a single instance is threaded through every file in one merge call, so the
// moment the COMBINED count across every file parsed so far would exceed either ceiling, parsing
// throws immediately, mid-array, rather than finishing that array or that file first (see this
// file's own kDefaultMaxMergedInventoryAssets/Edges comment, inventory_merge.hpp, for why checking
// DURING parsing rather than after is what actually matters here). `nullptr` fields in a
// MergeCountBudget (used for the public, single-file, unlimited-by-definition
// parse_inventory_report_json_for_merge below) mean "no ceiling" -- never decremented, never
// checked.
struct MergeCountBudget {
    size_t* remaining_assets = nullptr;
    size_t max_assets_for_message = 0;
    size_t* remaining_edges = nullptr;
    size_t max_edges_for_message = 0;
};

AssetInventoryReport parse_inventory_report_json_impl(const std::string& text, MergeCountBudget& budget) {
    JsonCursor c(text);
    AssetInventoryReport report;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "total_packets") {
                report.total_packets = c.parse_non_negative_integer("total_packets");
            } else if (key == "skipped_packets") {
                report.skipped_packets = c.parse_non_negative_integer("skipped_packets");
            } else if (key == "observation_truncated") {
                report.observation_truncated = c.parse_bool();
            } else if (key == "observation_reasons") {
                // patch282 finding 6 fix (item 123, docs/DEVELOPMENT.md) -- "observation_status" is
                // not read back here: it's a redundant, human/SIEM-convenience echo of
                // observation_truncated this report format already carries (see
                // write_inventory_report_json's own comment), so an unrecognized key here falls
                // through to the generic c.skip_value() branch below the same as any other field
                // this merge doesn't need. An unrecognized reason TOKEN inside this array (e.g. one
                // a newer/older build emitted) is silently dropped rather than failing the parse --
                // see parse_observation_incomplete_reason_name's own comment (resource_limits.hpp).
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        std::optional<ObservationIncompleteReason> parsed =
                            parse_observation_incomplete_reason_name(c.parse_string());
                        if (parsed) report.observation_incomplete_reasons.push_back(*parsed);
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else if (key == "truncation_reasons") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        report.truncation_reasons.push_back(c.parse_string());
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else if (key == "assets") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        // F1 fix: checked BEFORE parsing the next element, not after, so an
                        // oversized array is caught mid-array rather than fully materialized
                        // first -- see MergeCountBudget's own comment just above.
                        if (budget.remaining_assets) {
                            if (*budget.remaining_assets == 0) {
                                throw InventoryMergeError(
                                    "merge inventory: combined asset count across all input reports "
                                    "exceeds the " + std::to_string(budget.max_assets_for_message) +
                                    " asset limit (--max-inventory-total-assets to override)");
                            }
                            --(*budget.remaining_assets);
                        }
                        report.assets.push_back(parse_asset(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else if (key == "edges") {
                c.expect('[');
                if (!c.consume_if(']')) {
                    while (true) {
                        if (budget.remaining_edges) {
                            if (*budget.remaining_edges == 0) {
                                throw InventoryMergeError(
                                    "merge inventory: combined edge count across all input reports "
                                    "exceeds the " + std::to_string(budget.max_edges_for_message) +
                                    " edge limit (--max-inventory-total-edges to override)");
                            }
                            --(*budget.remaining_edges);
                        }
                        report.edges.push_back(parse_edge(c));
                        if (c.consume_if(',')) continue;
                        c.expect(']');
                        break;
                    }
                }
            } else {
                // capture/zones/conduits/notable_protocols -- always ignored, see this file's own
                // header comment (zones/conduits are always re-derived, never read back).
                c.skip_value();
            }
            if (c.consume_if(',')) continue;
            break;
        }
        c.expect('}');
    }
    return report;
}

// Opens `path`, checks its size against `max_file_bytes` BEFORE reading it into memory, and
// returns its raw content -- the shared first half of both read_inventory_report_file_for_merge
// and read_inventory_report_files_for_merge below, factored out so the F1 fix's new aggregate
// path reuses the exact same per-file check/error text rather than a second, drifting copy of it.
std::string read_and_size_check_inventory_report_file(const std::string& path, size_t max_file_bytes) {
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        throw InventoryMergeError("report file '" + path + "': cannot open for reading");
    }
    // Size ceiling BEFORE reading anything into memory (finding 5, docs/reviews/2026-09-chatgpt-
    // security-review-patch282.md; item 122, docs/DEVELOPMENT.md) -- seek-to-end/tellg, exactly
    // mirroring load_baseline_store's own identical check (baseline.cpp) for the identical reason:
    // a truncated or oversized report would fail parse_inventory_report_json_for_merge's own
    // structural checks anyway, so there is no partial-success case worth preserving by reading it
    // first.
    in.seekg(0, std::ios::end);
    std::streamoff size = in.tellg();
    if (size < 0) {
        throw InventoryMergeError("report file '" + path + "': read error (could not determine size)");
    }
    if (static_cast<size_t>(size) > max_file_bytes) {
        throw InventoryMergeError("report file '" + path + "': " + std::to_string(size) +
                                   " byte(s) exceeds the " + std::to_string(max_file_bytes) +
                                   " byte limit (--max-inventory-file-bytes to override)");
    }
    in.seekg(0, std::ios::beg);
    std::ostringstream buf;
    buf << in.rdbuf();
    if (!in.good() && !in.eof()) {
        throw InventoryMergeError("report file '" + path + "': read error");
    }
    return buf.str();
}

}  // namespace

AssetInventoryReport parse_inventory_report_json_for_merge(const std::string& text) {
    MergeCountBudget unlimited;  // both pointers null -- no ceiling, see MergeCountBudget's comment
    return parse_inventory_report_json_impl(text, unlimited);
}

AssetInventoryReport read_inventory_report_file_for_merge(const std::string& path, size_t max_file_bytes) {
    std::string text = read_and_size_check_inventory_report_file(path, max_file_bytes);
    return parse_inventory_report_json_for_merge(text);
}

std::vector<AssetInventoryReport> read_inventory_report_files_for_merge(const std::vector<std::string>& paths,
                                                                         size_t max_file_bytes,
                                                                         size_t max_total_bytes,
                                                                         size_t max_input_files, size_t max_assets,
                                                                         size_t max_edges) {
    // Cheapest, least-revealing check first: the input-file COUNT, before a single file is opened.
    if (paths.size() > max_input_files) {
        throw InventoryMergeError("merge inventory: " + std::to_string(paths.size()) +
                                   " input file(s) exceeds the " + std::to_string(max_input_files) +
                                   " file limit (--max-inventory-input-files to override)");
    }

    std::vector<AssetInventoryReport> reports;
    reports.reserve(paths.size());
    size_t total_bytes_so_far = 0;
    size_t remaining_assets = max_assets;
    size_t remaining_edges = max_edges;
    MergeCountBudget budget;
    budget.remaining_assets = &remaining_assets;
    budget.max_assets_for_message = max_assets;
    budget.remaining_edges = &remaining_edges;
    budget.max_edges_for_message = max_edges;

    for (const auto& path : paths) {
        // Per-file size check (unchanged, see read_and_size_check_inventory_report_file), THEN the
        // aggregate byte check, before this file's content is parsed -- so the file that would
        // cross the aggregate ceiling, and every file after it, is never read.
        std::string text = read_and_size_check_inventory_report_file(path, max_file_bytes);
        total_bytes_so_far += text.size();
        if (total_bytes_so_far > max_total_bytes) {
            throw InventoryMergeError("report file '" + path + "': reading it brings the combined input "
                                       "size across all " + std::to_string(paths.size()) + " merge input(s) to " +
                                       std::to_string(total_bytes_so_far) + " byte(s), exceeding the " +
                                       std::to_string(max_total_bytes) +
                                       " byte aggregate limit (--max-inventory-total-bytes to override)");
        }
        reports.push_back(parse_inventory_report_json_impl(text, budget));
    }
    return reports;
}

AssetInventoryReport merge_inventory_reports(const std::vector<AssetInventoryReport>& reports,
                                              uint8_t zone_prefix_len) {
    AssetInventoryReport merged;
    merged.zone_prefix_len = zone_prefix_len;

    // --- assets: union by IP, first-occurrence-wins for identity fields (see this file's own
    // header comment on merge_inventory_reports) ---------------------------------------------
    std::unordered_map<std::string, InventoryAsset> asset_by_ip;
    std::vector<std::string> asset_order;  // first-seen-across-inputs order; final report is
                                            // re-sorted numerically below regardless.
    for (const auto& report : reports) {
        merged.total_packets += report.total_packets;
        merged.skipped_packets += report.skipped_packets;
        // patch257 finding 3 fix: a site-level report truncated by AssetInventoryEngine's own
        // growth ceilings stays truncated once merged -- merging can only ever combine partial
        // views into a still-partial whole, never repair one, so this propagates rather than
        // silently drops the signal. Reasons are unioned (deduplicated) across every input report.
        if (report.observation_truncated) {
            merged.observation_truncated = true;
            for (const std::string& reason : report.truncation_reasons) {
                bool already = false;
                for (const std::string& existing : merged.truncation_reasons) {
                    if (existing == reason) {
                        already = true;
                        break;
                    }
                }
                if (!already) merged.truncation_reasons.push_back(reason);
            }
            // patch282 finding 6 fix (item 123, docs/DEVELOPMENT.md): the categorized reasons
            // union the identical way the free-text reasons just above do.
            for (ObservationIncompleteReason category : report.observation_incomplete_reasons) {
                append_observation_incomplete_reason(merged.observation_incomplete_reasons, category);
            }
        }
        for (const auto& a : report.assets) {
            auto it = asset_by_ip.find(a.ip);
            if (it == asset_by_ip.end()) {
                asset_by_ip.emplace(a.ip, a);
                asset_order.push_back(a.ip);
                continue;
            }
            InventoryAsset& merged_a = it->second;
            if (!merged_a.has_mac && a.has_mac) {
                merged_a.has_mac = true;
                merged_a.mac = a.mac;
            }
            std::set<std::string> proto_union(merged_a.protocols.begin(), merged_a.protocols.end());
            proto_union.insert(a.protocols.begin(), a.protocols.end());
            merged_a.protocols.assign(proto_union.begin(), proto_union.end());
            merged_a.packet_count += a.packet_count;
            if (a.first_seen > 0.0 && (merged_a.first_seen <= 0.0 || a.first_seen < merged_a.first_seen)) {
                merged_a.first_seen = a.first_seen;
            }
            if (a.last_seen > merged_a.last_seen) merged_a.last_seen = a.last_seen;
            if (merged_a.vendor.empty()) merged_a.vendor = a.vendor;
            if (merged_a.product.empty()) merged_a.product = a.product;
            if (merged_a.firmware_revision.empty()) merged_a.firmware_revision = a.firmware_revision;
            if (merged_a.serial_number.empty()) merged_a.serial_number = a.serial_number;
            if (merged_a.security_posture.empty()) merged_a.security_posture = a.security_posture;
            if (merged_a.plant_identification.empty()) merged_a.plant_identification = a.plant_identification;
            if (merged_a.inferred_role.empty() || merged_a.inferred_role == "Unknown") {
                if (!a.inferred_role.empty() && a.inferred_role != "Unknown") {
                    merged_a.inferred_role = a.inferred_role;
                }
            }
        }
    }

    // --- edges: union by (client_ip, server_ip, protocol, server_port) -----------------------
    struct EdgeKey {
        std::string client_ip, server_ip, protocol;
        uint16_t server_port;
        bool operator<(const EdgeKey& o) const {
            return std::tie(client_ip, server_ip, protocol, server_port) <
                   std::tie(o.client_ip, o.server_ip, o.protocol, o.server_port);
        }
    };
    std::map<EdgeKey, InventoryEdge> edge_by_key;
    std::vector<EdgeKey> edge_order;
    for (const auto& report : reports) {
        for (const auto& e : report.edges) {
            EdgeKey key{e.client_ip, e.server_ip, e.protocol, e.server_port};
            auto it = edge_by_key.find(key);
            if (it == edge_by_key.end()) {
                edge_by_key.emplace(key, e);
                edge_order.push_back(key);
                continue;
            }
            InventoryEdge& merged_e = it->second;
            std::set<std::string> func_union(merged_e.observed_functions.begin(),
                                              merged_e.observed_functions.end());
            func_union.insert(e.observed_functions.begin(), e.observed_functions.end());
            merged_e.observed_functions.assign(func_union.begin(), func_union.end());
            merged_e.packet_count += e.packet_count;
            if (e.first_seen > 0.0 && (merged_e.first_seen <= 0.0 || e.first_seen < merged_e.first_seen)) {
                merged_e.first_seen = e.first_seen;
            }
            if (e.last_seen > merged_e.last_seen) merged_e.last_seen = e.last_seen;
            if (direction_source_rank(e.direction_source) < direction_source_rank(merged_e.direction_source)) {
                merged_e.direction_source = e.direction_source;
            }
        }
    }

    // --- assets, sorted numerically by address (same convention AssetInventoryEngine::finish
    // itself uses -- see its own comment) -----------------------------------------------------
    std::vector<std::pair<uint32_t, std::string>> sortable_assets;
    sortable_assets.reserve(asset_order.size());
    for (const auto& ip : asset_order) {
        auto addr = parse_ipv4_string(ip);
        sortable_assets.emplace_back(addr.value_or(0), ip);
    }
    std::sort(sortable_assets.begin(), sortable_assets.end());
    for (const auto& [addr, ip] : sortable_assets) {
        merged.assets.push_back(asset_by_ip.at(ip));
        (void)addr;
    }

    // --- edges, first-occurrence-across-inputs order (matches AssetInventoryEngine::finish's own
    // "first-seen order" convention for InventoryEdge -- see AssetInventoryReport::edges' own
    // comment) -----------------------------------------------------------------------------------
    for (const auto& key : edge_order) {
        merged.edges.push_back(edge_by_key.at(key));
    }

    // --- ever_client/ever_server: recomputed from the merged edge set (never read from JSON, which
    // doesn't carry them at all -- see this file's own header comment) --------------------------
    for (const auto& e : merged.edges) {
        auto client_it = asset_by_ip.find(e.client_ip);
        if (client_it != asset_by_ip.end()) client_it->second.ever_client = true;
        auto server_it = asset_by_ip.find(e.server_ip);
        if (server_it != asset_by_ip.end()) server_it->second.ever_server = true;
    }
    for (auto& a : merged.assets) {
        a.ever_client = asset_by_ip.at(a.ip).ever_client;
        a.ever_server = asset_by_ip.at(a.ip).ever_server;
    }

    // --- zones: group every merged asset IP by its zone_prefix_len-bit network -- identical
    // grouping logic to AssetInventoryEngine::finish's own (asset_inventory.cpp), reimplemented
    // here against already-merged data (see this file's own header comment) --------------------
    uint32_t mask = cidr_mask(zone_prefix_len);
    std::map<uint32_t, std::vector<std::string>> by_network;
    std::unordered_map<uint32_t, std::string> zone_name_for_network;
    for (const auto& a : merged.assets) {
        auto addr = parse_ipv4_string(a.ip);
        if (!addr) continue;  // can't happen -- every asset IP came from write_inventory_report_
                               // json's own json_escape(a.ip), always a valid dotted-quad
        by_network[*addr & mask].push_back(a.ip);
    }
    for (const auto& [network, ips] : by_network) {
        InventoryZone iz;
        auto block = parse_cidr(format_ipv4(network) + "/" + std::to_string(zone_prefix_len));
        iz.network = block.value_or(CidrBlock{});
        iz.name = zone_name_for(iz.network);
        iz.member_ips = ips;
        zone_name_for_network[network] = iz.name;
        merged.zones.push_back(std::move(iz));
    }

    // --- conduits: one per distinct (from_zone, to_zone, protocol, port) tuple at least one merged
    // edge exercises -- same grouping as AssetInventoryEngine::finish's own ---------------------
    struct ConduitKey {
        std::string from_zone, to_zone, protocol;
        uint16_t port;
        bool operator<(const ConduitKey& o) const {
            return std::tie(from_zone, to_zone, protocol, port) <
                   std::tie(o.from_zone, o.to_zone, o.protocol, o.port);
        }
    };
    struct ConduitAgg {
        size_t edge_count = 0;
        size_t packet_count = 0;
    };
    std::map<ConduitKey, ConduitAgg> conduit_agg;
    for (const auto& e : merged.edges) {
        auto cip = parse_ipv4_string(e.client_ip);
        auto sip = parse_ipv4_string(e.server_ip);
        if (!cip || !sip) continue;
        // Bug fix (item 123, docs/DEVELOPMENT.md, found while verifying patch282 finding 6):
        // AssetInventoryEngine's own assets_/edges_ containers are capped INDEPENDENTLY (two
        // separate growth ceilings, each refusing further growth on its own -- see
        // AssetInventoryEngineLimits' own comment, asset_inventory.hpp), so a TRUNCATED
        // AssetInventoryReport's edges array can legitimately name a client_ip/server_ip that
        // never made it into that same report's own (also-truncated) assets array, and therefore
        // never made it into merged.assets / by_network / zone_name_for_network above either.
        // AssetInventoryEngine::finish's own, original version of this exact grouping
        // (asset_inventory.cpp) already handles this with find()-and-skip; this reimplementation
        // used .at() instead, which threw std::out_of_range (an unhandled exception -> SIGABRT)
        // the moment ANY truncated report -- even a single one, merge's own one-input "just
        // re-derive zones" legal use (see merge_inventory_cmd's own --help text) -- was ever fed
        // through `merge inventory`. Fixed by matching the original's own safe pattern exactly:
        // an edge whose endpoint's network has no corresponding zone (because that endpoint's own
        // asset was never admitted) contributes no conduit for this edge, rather than crashing the
        // whole merge over a gap this report's own observation_truncated/truncation_reasons
        // already disclose.
        auto cz = zone_name_for_network.find(*cip & mask);
        auto sz = zone_name_for_network.find(*sip & mask);
        if (cz == zone_name_for_network.end() || sz == zone_name_for_network.end()) continue;
        ConduitKey key{cz->second, sz->second, e.protocol, e.server_port};
        ConduitAgg& agg = conduit_agg[key];
        ++agg.edge_count;
        agg.packet_count += e.packet_count;
    }
    for (const auto& [key, agg] : conduit_agg) {
        InventoryConduit ic;
        ic.from_zone = key.from_zone;
        ic.to_zone = key.to_zone;
        ic.protocol = key.protocol;
        ic.port = key.port;
        ic.edge_count = agg.edge_count;
        ic.packet_count = agg.packet_count;
        std::ostringstream name;
        name << key.from_zone << " -> " << key.to_zone << " (" << key.protocol << "/" << key.port << ")";
        ic.name = name.str();
        merged.conduits.push_back(std::move(ic));
    }

    return merged;
}

}  // namespace conduitscope
