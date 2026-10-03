// SPDX-License-Identifier: Apache-2.0
// display_filter.hpp - Wireshark-style post-decode display filters for `decode -Y/--display-filter`.
//
// Unlike -f/--filter (a BPF filter compiled by libpcap and applied to raw bytes before/during
// decode -- see bpf_filter.hpp), a display filter is evaluated PER PACKET AFTER Decoder::decode()
// has already produced a DecodedPacket, against the same dissected fields this run's own -T json
// output would show -- mirrors tshark's own -Y. Expressions look like
// `modbus.func_code == 16 && ip.src == 10.1.2.3`, `s7comm.param.func == 0x05`,
// `goose.simulation == 1`.
//
// Scope (v1, see docs/USER_GUIDE.md's own "Display filters" subsection for the full, current
// list): universal eth/ip/tcp/udp fields plus a curated batch of protocols (Modbus, S7comm,
// S7comm-Plus, DNP3, EtherNet/IP, BACnet, IEC104, GOOSE, SV, HART-IP, OPC UA, MMS, UMAS). A bare
// protocol-name existence test (e.g. `modbus` alone) works for ANY protocol name
// DecodedPacket::protocol can hold, even outside this curated set -- see FieldRegistry's own
// comment. Grammar: comparisons (== != < <= > >=), &&/and, ||/or, !/not, parentheses,
// contains/matches (substring/regex against a string-kind field), bare field-existence tests, and
// `in {a,b,c}` set membership. Deliberately NOT supported in v1: byte-slicing (field[0:4]) and
// bitwise field tests (flags & 0x02).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace conduitscope {

struct DecodedPacket;  // decoder.hpp

// A filterable field's value, or an expression's literal operand. Deliberately NOT a variant over
// every concrete C++ type DecodedPacket/ProtocolResult structs use (uint8_t/uint16_t/uint32_t/
// bool/string/...) -- every numeric field this engine exposes (function/type/service codes,
// ports, ttl, vlan_id) widens losslessly into one int64_t, which keeps the evaluator's comparison
// logic branch-free per kind rather than per concrete C++ type.
enum class FilterValueKind { Int, Bool, String, Ip };

struct FilterValue {
    FilterValueKind kind = FilterValueKind::Int;
    int64_t int_value = 0;
    bool bool_value = false;
    // Also backs Ip: an Ip-kind FilterValue's own dotted-decimal/colon-hex text, taken verbatim
    // from DecodedPacket::src_ip/dst_ip. See this file's header comment on why Ip is compared as
    // exact text in v1, not as a parsed/CIDR-aware address.
    std::string string_value;

    static FilterValue make_int(int64_t v);
    static FilterValue make_bool(bool v);
    static FilterValue make_string(std::string v);
    static FilterValue make_ip(std::string v);
};

// One field's extractor over one decoded packet. Returns std::nullopt when that field's own
// owning protocol layer isn't present on this packet (e.g. `modbus.func_code` on a non-Modbus
// packet) -- the same "optional field" contract std::optional<ProtocolResult> already models, not
// a sentinel value. A comparison against a nullopt field is simply false, never an error -- see
// display_filter_parser.cpp's evaluator.
using FieldExtractor = std::function<std::optional<FilterValue>(const DecodedPacket&)>;

// Maps a dotted field name (e.g. "modbus.func_code", "ip.src", "s7comm.param.func") to its
// extractor and declared value kind, plus tracks the set of bare protocol names ("modbus",
// "s7comm", ...) a field-existence test can name on its own. Built once, at static-init time, by
// display_filter_fields.cpp; organized there by protocol section, mirroring output.cpp's own
// per-protocol write_X_json_fields organization as a style model (not reused/refactored).
//
// A bare-name existence test (`modbus` alone, no dot) is handled as a DISTINCT path from the
// field table -- checked against protocol_names_ (-> DecodedPacket::protocol == name) rather than
// synthesizing a fake field entry. This means bare-name existence works for ANY of this project's
// ~115 decoded protocol names, not just the curated batch with real field entries below --
// deliberate, and stated in docs/USER_GUIDE.md.
class FieldRegistry {
public:
    static const FieldRegistry& instance();

    // nullptr if `dotted_name` is not a known field.
    const FieldExtractor* lookup(const std::string& dotted_name) const;
    // Only valid when lookup() would succeed for the same name.
    FilterValueKind kind_of(const std::string& dotted_name) const;
    bool is_bare_protocol_name(const std::string& name) const;

    void register_field(const std::string& dotted_name, FilterValueKind kind, FieldExtractor extractor);
    void register_protocol_name(const std::string& name);

private:
    std::unordered_map<std::string, FieldExtractor> fields_;
    std::unordered_map<std::string, FilterValueKind> kinds_;
    std::unordered_set<std::string> protocol_names_;
};

class FilterNode;  // display_filter_parser.cpp -- opaque AST node

// One compiled, ready-to-evaluate display filter. Cheap to copy (a shared_ptr to an immutable
// AST); safe to compile once, before the packet loop, and reuse across a whole capture.
class CompiledDisplayFilter {
public:
    CompiledDisplayFilter() = default;
    CompiledDisplayFilter(std::shared_ptr<const FilterNode> root, std::string source_text);

    bool matches(const DecodedPacket& dp) const;
    const std::string& source_text() const { return source_text_; }

private:
    std::shared_ptr<const FilterNode> root_;
    std::string source_text_;
};

// Lexes, parses, and type-checks `expr` against FieldRegistry::instance(). On success returns the
// compiled filter. On failure returns std::nullopt and writes a fully-formed, ready-to-print error
// into *error (must not be null), following this project's established CLI error-message
// convention (see cli_main.cpp's parse_decode_as_rules):
//   "error: display filter '<expr>' <what's wrong> at '<offending text>' (expected <hint>, e.g.
//   <concrete example>)\n"
// Type-checking happens once here, immediately after parsing succeeds: every field_ref in the
// expression is looked up in the registry and any operator/literal-kind mismatch (comparing a
// numeric field to a string literal, ordering-comparing a String/Bool/Ip field, an unknown field
// name) is rejected here, before a single packet is read -- the same "fail fast, once, before the
// loop" posture as -d/--decode-as's own parse_decode_as_rules.
//
// `warnings`, when non-null, collects non-fatal advisories discovered during type-checking --
// currently just the F4/item 136 catastrophic-backtracking heuristic on `matches` patterns (see
// looks_like_nested_quantifier_redos's own comment in display_filter_parser.cpp). A warning never
// causes compilation to fail: the expression still compiles and `warnings` is populated alongside
// a non-nullopt return. Callers that pass nullptr simply get the pre-item-136 behavior back.
std::optional<CompiledDisplayFilter> compile_display_filter(const std::string& expr, std::string* error,
                                                              std::vector<std::string>* warnings = nullptr);

}  // namespace conduitscope
