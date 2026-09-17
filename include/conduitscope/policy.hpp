// SPDX-License-Identifier: Apache-2.0
// policy.hpp - zone/conduit policy file parsing for `policy validate`.
//
// A policy file declares named zones (each a set of IPv4 CIDR blocks) and
// named conduits (an allowed protocol+port relationship from a set of zones
// to a set of zones -- many-to-many, not just one zone to one zone). See
// docs/MANUAL.md's POLICY FILE FORMAT section for the full
// schema, worked examples, and the reasoning behind each validation rule
// below. PolicyEngine (policy_engine.hpp) is what actually evaluates decoded
// traffic against a Policy parsed here; this file only parses and validates
// the policy document itself, independent of any capture.
//
// The file format is YAML-*compatible* but deliberately not general YAML --
// see yaml_mini.hpp for exactly which subset is parsed, and why a purpose-
// built parser rather than a vendored YAML library.
#pragma once

#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <vector>

namespace conduitscope {

// One IPv4 CIDR block, e.g. "10.10.10.0/24" (or a bare "10.10.10.5",
// equivalent to "/32"). `network` is already masked down to `prefix_len`
// bits -- parse_cidr silently clears any host bits in the input rather than
// rejecting them (e.g. "10.10.10.5/24" becomes network 10.10.10.0/24),
// matching how most IP tooling (e.g. `ip route`) treats a host address given
// with a shorter prefix. `text` keeps the original, as-written string for
// error messages and reports.
struct CidrBlock {
    uint32_t network = 0;
    uint8_t prefix_len = 32;
    std::string text;
};

// True if `ip` (host order) falls inside `block`.
bool cidr_contains(const CidrBlock& block, uint32_t ip);

// True if `a` and `b` describe any address in common (used by
// parse_policy_text to reject a policy where the same address could belong
// to two different zones -- see the "each address belongs to at most one
// zone" validation rule below).
bool cidr_overlaps(const CidrBlock& a, const CidrBlock& b);

// Parses "a.b.c.d" or "a.b.c.d/N" (N in [0,32]) into a CidrBlock. Returns
// std::nullopt (never throws) for anything else -- including a bare address
// with no "/", which is accepted and treated as /32, but not e.g. a hostname
// or an IPv6 address (this tool is IPv4-only throughout, matching ipv4.hpp).
std::optional<CidrBlock> parse_cidr(const std::string& text);

struct Zone {
    std::string name;
    std::string description;  // optional; empty if not given
    std::vector<CidrBlock> networks;
    int line = 0;  // policy-file line the zone was declared on, for PolicyEngine reports
};

// One allowed conduit between a set of zones. `from_zones`/`to_zones` each
// name one or more declared zones (the policy file's `from`/`to` keys accept
// either a single scalar zone name or a list of them -- see as_scalar_list in
// policy.cpp for the shared single-or-list parsing, also used by `networks`,
// `protocols`, and `ports`), and the conduit is many-to-many: it permits
// traffic from ANY zone in `from_zones` to ANY zone in `to_zones`, not just
// one specific pair. This lets e.g. "permit traffic from either the
// corporate zone or the remote-access zone into either of two PLC zones" be
// written as one conduit, instead of one conduit per zone pair. `protocols`
// holds lowercased values from {"modbus", "dnp3", "s7comm", "iec104", "enip",
// "bacnet", "hartip", "opcua", "mms", "mqtt", "ffhse", "any"}
// (parse_policy_text rejects anything else) -- "any" matches every protocol
// conduitscope recognizes. Of the six named after "enip", only
// hartip/opcua/mms/mqtt/ffhse can ever actually match a flow today: `policy
// validate` only ever evaluates TCP flows (see PolicyEngine::observe), and
// "bacnet" names BACnet/IP, which this decoder only ever recognizes over UDP
// (see decoder.cpp) -- so a conduit naming "bacnet" parses and validates
// fine but can never be exercised by real traffic yet; see docs/MANUAL.md's
// POLICY FILE FORMAT "Addressing scope" section. `ports` is the set of TCP ports this conduit
// covers on the RESPONDING (server) side of the connection; empty means "any
// port" (parse_policy_text allows omitting the field entirely for that).
// `bidirectional` additionally allows the same protocol/port set initiated
// the opposite way (a `to_zones` member -> a `from_zones` member) -- most
// real OT conduits are one-directional (an HMI/engineering zone reaching
// into a control-network zone), which is why this defaults to false; see
// docs/MANUAL.md's POLICY FILE FORMAT section for why direction is modeled
// this way rather than tracked per-packet.
struct Conduit {
    std::string name;
    std::string description;
    std::vector<std::string> from_zones;
    std::vector<std::string> to_zones;
    std::vector<std::string> protocols;
    std::vector<uint16_t> ports;
    bool bidirectional = false;

    // Optional allow-list of function/service names this conduit permits WITHIN its single
    // protocol -- e.g. only "Read Holding Registers" on an otherwise-permitted Modbus conduit, not
    // "Write Multiple Registers" too. Empty (the default -- omitted, or 'functions'/'function' not
    // given) means fully unrestricted, exactly the behavior before this field existed: every
    // function/service the protocol decodes is permitted. Non-empty only ever appears alongside
    // `protocols` resolving to exactly one concrete protocol (parse_policy_text rejects any other
    // combination -- see its own comment below) -- each string is stored in the CANONICAL casing
    // that protocol's decoder itself emits (modbus_function_name/dnp3_function_name/
    // s7comm_function_name/iec104_type_short_name/enip_cip_service_name -- see each protocol's own
    // *_known_*_names() function), regardless of how the policy file capitalized it, since matching
    // (PolicyEngine) is case-insensitive but display (error messages, report reasons) always uses
    // the decoder's own casing. See docs/MANUAL.md's POLICY FILE FORMAT section for the full
    // schema and PolicyEngine::finish (policy_engine.cpp) for exactly how a flow's observed
    // functions are checked against this list.
    std::vector<std::string> functions;

    int line = 0;
};

struct Policy {
    std::vector<Zone> zones;
    std::vector<Conduit> conduits;

    // Returns the zone whose CIDR list contains `ip`, or nullptr if no
    // declared zone does. Because parse_policy_text already rejects any
    // policy where two zones' networks overlap (see cidr_overlaps above), at
    // most one zone can ever match -- this returns the first (only) one.
    const Zone* zone_for(uint32_t ip) const;
};

struct PolicyError : std::runtime_error {
    explicit PolicyError(const std::string& msg) : std::runtime_error(msg) {}
};

// Parses already-read policy file text into a fully validated Policy.
// `source_name` (typically the file path) is used only to prefix error
// messages, in "<source_name>:<line>: <message>" form when a line number is
// known, else "<source_name>: <message>". Throws PolicyError on:
//   - a YAML-subset syntax problem (propagated from yaml_mini::YamlError)
//   - a missing top-level 'zones' or 'conduits' key, or either being empty
//   - a zone with no 'networks', or a network that isn't a valid CIDR/address
//   - two zones whose networks overlap (see cidr_overlaps)
//   - a zone literally named "unclassified" -- that name is reserved for
//     traffic PolicyEngine finds matches no declared zone; declaring it
//     explicitly would make that reporting ambiguous
//   - a duplicate zone or conduit name
//   - a conduit missing 'name'/'from'/'to'/'protocols', or whose 'from'/'to'
//     contains a zone name that isn't declared in 'zones' (each entry of a
//     list 'from'/'to' is checked, not just the first)
//   - a conduit's 'from'/'to' list being empty (e.g. 'from: []')
//   - a conduit's protocol not in {modbus, dnp3, s7comm, iec104, enip, bacnet, hartip, opcua, mms,
//     mqtt, ffhse, any}
//   - a conduit's port outside [1, 65535]
//   - a conduit's 'bidirectional' value that isn't a recognizable boolean
//   - a conduit's 'functions'/'function' given while 'protocols'/'protocol' resolves to anything
//     other than exactly one concrete protocol (i.e. it's 'any', or a list of more than one) --
//     the function/service name tables the entries are validated against are entirely separate per
//     protocol (see modbus_known_function_names/dnp3_known_function_names/
//     s7comm_known_function_names/iec104_known_asdu_short_names/enip_known_cip_service_names), so
//     there would be no single table to validate/match against otherwise
//   - a conduit's 'functions'/'function' given for one of the six protocols widened into
//     'protocols' most recently (bacnet/hartip/opcua/mms/mqtt/ffhse) -- none of them has a known-
//     function/service-name table yet (see known_function_names_for in policy.cpp), so there is
//     nothing to validate a 'functions' entry against; write the conduit without 'functions' for
//     now (see ROADMAP)
//   - a conduit's 'functions'/'function' entry that isn't one of its protocol's own known function/
//     service names (case-insensitively) -- the error names the closest known name ("did you mean
//     '...'?") when one is a plausible typo, and omits the suggestion when nothing is close enough
Policy parse_policy_text(const std::string& text, const std::string& source_name);

// Reads `path` and calls parse_policy_text with its contents. Throws
// PolicyError (not a filesystem exception) if the file can't be opened,
// applying the same validation as parse_policy_text otherwise.
Policy parse_policy_file(const std::string& path);

}  // namespace conduitscope
