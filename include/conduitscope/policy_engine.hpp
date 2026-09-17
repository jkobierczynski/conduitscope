// SPDX-License-Identifier: Apache-2.0
// policy_engine.hpp - evaluates decoded packets (DecodedPacket, from
// Decoder) against a parsed zone/conduit Policy (policy.hpp), for the
// `policy validate` command.
//
// This is a separate layer built entirely on top of Decoder's already-public
// output -- it doesn't change how packets are decoded, and Decoder/
// DecodedPacket have no knowledge of it. PolicyEngine aggregates the
// decoded-packet stream into TCP flows (one per distinct 4-tuple, direction-
// agnostic) and, once the whole capture has been fed through, checks each
// flow's (client zone, server zone, protocol(s) observed, server port)
// against the policy's conduits. Feed it one DecodedPacket at a time, in
// capture order, via observe(); call finish() once to get the final
// PolicyReport. See docs/MANUAL.md's POLICY FILE FORMAT and 'policy
// validate' sections for the semantics in prose, and cli_main.cpp for how
// this is wired into the command.
#pragma once

#include <cstddef>
#include <cstdint>
#include <iosfwd>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "conduitscope/decoder.hpp"
#include "conduitscope/policy.hpp"

namespace conduitscope {

enum class FlowVerdict {
    Allowed,        // a conduit permits this flow's protocol(s) at this port, in this direction,
                    // and (if that conduit restricts 'functions') every function/service observed
                    // on the flow
    Violation,      // both endpoints are zone-classified, but no conduit permits this flow -- OR
                    // one does on protocol/port/direction, but restricts 'functions' and at least
                    // one function/service observed on the flow isn't in its allow-list
    Unclassified,   // at least one endpoint matched no declared zone, or no app-layer protocol was
                    // ever recognized on this flow -- there's nothing to check against a conduit
};

// One observed TCP flow (both directions of one 4-tuple, aggregated), summarized for reporting.
// "client"/"server" are PolicyEngine's best determination of which endpoint initiated the
// connection -- see PolicyEngine::observe's doc comment for exactly how that's decided.
struct FlowReport {
    std::string client_ip, server_ip;
    uint16_t server_port = 0;
    std::string client_zone, server_zone;  // "unclassified" when Policy::zone_for found nothing
    std::vector<std::string> protocols;    // distinct app protocols observed: "modbus"/"dnp3"/"s7comm"/
                                            // "iec104"/"enip"/"hartip"/"opcua"/"mms"/"mqtt"/"ffhse"
                                            // (never "bacnet" -- see PolicyEngine::observe)
    // Distinct, non-empty function/service names observed on this flow, sorted -- whichever of
    // modbus_function_name/dnp3_function_name/s7comm_function_name/iec104_asdu_type_short_name/
    // enip_cip_service_name/hartip_message_type/opcua_service_name/mms_service_name/
    // mqtt_packet_type_name/ffhse_message_name each contributing packet's own protocol populates
    // (see PolicyEngine::observe). Populated regardless of whether the matched conduit (if any)
    // actually restricts 'functions' -- purely informational/scriptable via the JSON report when it
    // doesn't (see write_policy_report_json), and exactly what a functions-restricted conduit's
    // match (or the reason it didn't match) is computed from when it does -- though today that
    // restriction mechanism (a conduit's own 'functions' list) only ever validates against modbus/
    // dnp3/s7comm/iec104/enip (see policy.cpp's protocol_has_known_function_table); the last five
    // protocols above still populate this field for reporting, just can't be filtered by it yet.
    std::vector<std::string> observed_functions;
    size_t packet_count = 0;
    FlowVerdict verdict = FlowVerdict::Unclassified;
    std::string matched_conduit;  // set (non-empty) only when verdict == Allowed
    std::string reason;           // set (non-empty) when verdict != Allowed: why, for the report
};

struct PolicyReport {
    std::vector<FlowReport> flows;  // one per observed TCP flow, in first-seen order
    // Conduits declared in the policy that no observed flow ever matched -- informational only
    // (doesn't affect compliant()); useful for pruning a policy file or noticing a conduit that
    // was supposed to be exercised by this capture but wasn't.
    std::vector<std::string> unexercised_conduits;
    size_t skipped_non_tcp = 0;  // packets with has_ip==false or has_tcp==false (including UDP):
                                  // not part of any evaluated flow -- see PolicyEngine::observe
    size_t total_packets = 0;

    size_t allowed_count() const;
    size_t violation_count() const;
    size_t unclassified_count() const;
    // True only when every observed flow was explicitly Allowed -- any Violation OR any
    // Unclassified flow makes this false, since "traffic between addresses this policy doesn't
    // even classify" is itself a finding worth surfacing in an audit, not something to pass
    // silently. See cli_main.cpp for how this maps to `policy validate`'s exit code.
    bool compliant() const { return violation_count() == 0 && unclassified_count() == 0; }
};

class PolicyEngine {
public:
    explicit PolicyEngine(const Policy& policy) : policy_(policy) {}

    // Folds one already-decoded packet into this engine's per-flow state. Call once per packet, in
    // capture order (same discipline as Decoder::decode).
    //
    // Packets with has_ip==false or has_tcp==false (non-IP, non-TCP -- including UDP, which
    // `decode` now recognizes and reports on but this engine does not yet evaluate against any
    // conduit, see docs/MANUAL.md's ROADMAP -- or a parse-error packet) aren't part of any TCP
    // flow and are only counted toward PolicyReport::skipped_non_tcp -- this tool only ever
    // checks TCP-based OT protocols against a policy's conduits, so there's nothing further to
    // evaluate for them yet.
    //
    // Client (initiator) vs. server is decided, per flow, the first time that flow is seen able to
    // decide it:
    //   1. A pure SYN packet (tcp_flags == "SYN") authoritatively marks its source as the client.
    //   2. A SYN-ACK packet (tcp_flags starts with "SYN,ACK") authoritatively marks its
    //      DESTINATION as the client (it's the server's reply to a SYN this engine may not have
    //      seen, e.g. a capture that starts mid-handshake).
    //   3. Otherwise, whichever endpoint's port is one of the five IANA-registered OT protocol
    //      ports (502/20000/2404/102/44818) is assumed to be the server; if neither or both are, the endpoint
    //      with the lower port number is assumed to be the server (a common networking convention:
    //      ephemeral client ports are almost always higher).
    // If the first packet seen for a flow can't be decided by (1) or (2) and falls back to (3), a
    // LATER packet on the same flow that does carry a SYN/SYN-ACK still upgrades the flow's
    // client/server assignment to the authoritative answer -- (3) is a first-packet fallback, not
    // a decision this engine sticks with once it can do better.
    void observe(const DecodedPacket& packet);

    // Produces the final report from everything observed so far. Safe to call more than once (e.g.
    // to print a summary and then a detailed report from the same run); does not reset state.
    PolicyReport finish() const;

private:
    struct FlowState {
        std::string client_ip, server_ip;
        uint16_t server_port = 0;
        bool initiator_known = false;  // true once decided by an actual SYN/SYN-ACK, not the port guess
        std::unordered_set<std::string> protocols;
        // Distinct, non-empty function/service names observed on this flow so far -- see
        // FlowReport::observed_functions' comment for exactly which DecodedPacket field feeds this
        // per protocol.
        std::unordered_set<std::string> functions;
        size_t packet_count = 0;
    };

    const Policy& policy_;
    std::unordered_map<std::string, FlowState> flows_;  // keyed by canonical session key
    std::vector<std::string> flow_order_;                // session keys, first-seen order
    size_t skipped_non_tcp_ = 0;
    size_t total_packets_ = 0;
};

// Renders `report` as a human-readable, colorless text report to `out`. `capture_path`/
// `policy_path` are shown in the report header purely for context (this function performs no I/O
// of its own). `policy` supplies zone/conduit counts and names referenced in the report.
void write_policy_report_text(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path);

// Renders `report` as JSON to `out`, for scripting/automation (e.g. feeding a NIS2/IEC 62443 audit
// pipeline). See docs/MANUAL.md's POLICY FILE FORMAT section for the exact schema.
void write_policy_report_json(std::ostream& out, const PolicyReport& report, const Policy& policy,
                               const std::string& capture_path, const std::string& policy_path);

}  // namespace conduitscope
