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

    // Recursively consumes and discards exactly one JSON value (string/number/object/array/bool/
    // null) of whatever shape is next -- used for every field this merge doesn't need to read back.
    void skip_value() {
        char c = peek();
        if (c == '"') {
            parse_string();
        } else if (c == '{') {
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
        } else if (c == '[') {
            expect('[');
            if (!consume_if(']')) {
                while (true) {
                    skip_value();
                    if (consume_if(',')) continue;
                    break;
                }
                expect(']');
            }
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
                a.packet_count = static_cast<size_t>(c.parse_integer());
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
                have_client = true;
            } else if (key == "server_ip") {
                e.server_ip = c.parse_string();
                have_server = true;
            } else if (key == "protocol") {
                e.protocol = c.parse_string();
                have_protocol = true;
            } else if (key == "server_port") {
                e.server_port = static_cast<uint16_t>(c.parse_integer());
                have_port = true;
            } else if (key == "observed_functions") {
                e.observed_functions = parse_string_array(c);
            } else if (key == "packet_count") {
                e.packet_count = static_cast<size_t>(c.parse_integer());
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

}  // namespace

AssetInventoryReport parse_inventory_report_json_for_merge(const std::string& text) {
    JsonCursor c(text);
    AssetInventoryReport report;
    c.expect('{');
    if (!c.consume_if('}')) {
        while (true) {
            std::string key = c.parse_string();
            c.expect(':');
            if (key == "total_packets") {
                report.total_packets = static_cast<size_t>(c.parse_integer());
            } else if (key == "skipped_packets") {
                report.skipped_packets = static_cast<size_t>(c.parse_integer());
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

AssetInventoryReport read_inventory_report_file_for_merge(const std::string& path, size_t max_file_bytes) {
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
    return parse_inventory_report_json_for_merge(buf.str());
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
