// SPDX-License-Identifier: Apache-2.0
// resource_limits.hpp - process-wide, CLI-configurable overrides for the resource-exhaustion/DoS-
// protection constants scattered across decoder.cpp and the individual protocol files (see
// docs/DEVELOPMENT.md's "External code review and engineering priorities" section, item 7).
//
// WHY THIS EXISTS: this codebase has ~60 individually-named `constexpr` caps -- cross-segment
// reassembly buffering caps, recursive-decode depth caps, per-message decoded-object/list-entry
// caps, and "N application messages coalesced into one payload" caps -- none of them tunable
// without a rebuild. Item 7 asked for a way to tighten these for a more paranoid audit of
// untrusted captures, or loosen them for a capture that legitimately needs more headroom, the
// same "documented default, explicit override" posture --modbus-port and its siblings already
// give port lists. Exposing all ~60 individually would add 60+ CLI options; this instead groups
// them into categories, one flag per category (see cli_main.cpp's `--max-*` options), each
// overriding every constant in that category uniformly. See docs/DEVELOPMENT.md's own item 7
// "Update: implemented" entry for the full constant-by-constant mapping, including the handful
// deliberately left compile-time (protocol-native field-width bounds and the pcap-file-format
// plausibility checks, a different trust boundary from in-flight payload reassembly). Two more
// fields (max_active_flows/max_flow_state_entries) were added later, for a DIFFERENT category of
// problem than the original five -- bounding the NUMBER of distinct flows/sessions tracked at
// once, not the cost of any single one -- see each field's own comment below and
// docs/reviews/2026-09-chatgpt-security-review-patch160.md's finding 1.
//
// WHY A GLOBAL ACCESSOR, NOT A PARAMETER THREADED THROUGH DecodeContext/ProtocolDecoder: many
// in-scope constants live in places with no DecodeContext at all -- most of the "50-entry list
// cap" protocols (OSPF/PIM/IGMP/ICMP/IGRP/RIP/VRRP/HSRP) are still plain
// `try_parse_X(ByteSpan) -> optional<XMessage>` legacy free functions with zero extra parameters,
// and the recursion-depth helpers (mms.cpp/s7commplus.cpp/goose.cpp/enip.cpp/mpls.hpp) recurse
// many levels deep carrying only a local depth counter. Retrofitting a parameter through every one
// of those call chains would be far more invasive than this feature justifies. Unlike
// FlowStateMap/DecodeContext (genuinely per-packet/per-flow state that must never leak across
// packets), a ResourceLimits value is process-run CONFIGURATION -- parsed once from CLI arguments,
// then read-only for the rest of the process's life -- so a plain, explicitly-named "set once,
// read anywhere" accessor is the right shape for it, not per-call parameter threading.
#pragma once

#include <cstddef>
#include <optional>

namespace conduitscope {

// Every field here corresponds to one CLI flag (cli_main.cpp) and one whole category of
// constants (see this file's header comment and docs/DEVELOPMENT.md's item 7 mapping table).
// std::nullopt (the default -- i.e. the CLI flag was never passed, or `set_resource_limits` was
// never called at all) means every site in that category keeps using ITS OWN current
// documented default, byte-identical to this feature's absence -- this is what keeps every
// existing regression test passing unchanged when no new flag is used.
struct ResourceLimits {
    // Overrides decoder.cpp's general TCP reassembly cap (16 MiB), dnp3.cpp's fragment
    // reassembly cap (64 KiB), cotp.cpp's TSDU reassembly cap (1 MiB), and OPC UA's/FF-HSE's own
    // declared-length plausibility ceiling (16 MiB each -- the same "implausible" magic number
    // the general TCP cap uses) -- uniformly, all five at once.
    std::optional<size_t> max_reassembly_bytes;

    // Overrides decoder.cpp's general TCP reassembly segment-count cap (20,000), dnp3.cpp's
    // frame-count cap (500), and cotp.cpp's frame-count cap (2,000) -- uniformly.
    std::optional<size_t> max_reassembly_segments;

    // Overrides all five recursive-decode depth caps: MMS's Data-value nesting (32), CIP's
    // Multiple_Service_Packet/Unconnected_Send nesting (4), MPLS's label-stack depth (16),
    // S7comm-Plus's struct/item nesting (16), and GOOSE's Data ASN.1 nesting (6) -- uniformly.
    std::optional<size_t> max_recursion_depth;

    // Overrides every per-message decoded-object/value/list-entry cap this codebase has -- the
    // ~34 individually-named per-protocol caps (DNP3 object headers/points, IEC104 objects/
    // values, GOOSE data values, EtherNet/IP CIP values/embedded messages/CPF items, S7comm-Plus
    // rendered elements/array iterations, MQTT metrics, decoder.cpp's own summary-list caps, and
    // more) plus the 9 duplicated "50-entry list" constants shared by EIGRP/OSPF/PIM/IGMP/ICMP/
    // IGRP/RIP/VRRP/HSRP -- uniformly, all ~43 at once. See docs/DEVELOPMENT.md's item 7 mapping
    // table for the full constant-by-constant list; too long to enumerate in --help text.
    std::optional<size_t> max_decoded_objects;

    // Overrides every "N application-layer messages found coalesced in one TCP/UDP payload" cap
    // -- FF-HSE, HART-IP, MQTT, EtherNet/IP, and OPC UA, all already 50 by default -- uniformly.
    std::optional<size_t> max_coalesced_messages;

    // Added in response to docs/reviews/2026-09-chatgpt-security-review-patch160.md's finding 1
    // ("Unbounded lifetime of TCP/decoder flow state"): the five caps above all bound how much a
    // SINGLE flow/reassembly/message can cost; nothing bounded how many DISTINCT flows/sessions
    // the Decoder could accumulate state for at once, across the whole capture. A capture with
    // many distinct src-ip:port->dst-ip:port tuples grew memory linearly in flow count with no
    // ceiling -- see decoder.cpp's Decoder::reassemble_tcp_payload for the two-part fix (stop
    // creating an entry for a flow that never needed one; cap what's left with this field).
    //
    // Bounds Decoder::tcp_reassembly_'s size -- the general cross-TCP-segment PDU/frame reassembly
    // map every one of Modbus/TCP, IEC 104, EtherNet/IP, TPKT/S7comm/S7comm-Plus/MMS, HART-IP,
    // OPC UA, MQTT, and FF-HSE shares. Checked only when a flow that doesn't already have an entry
    // is about to get one; an existing flow's own entry being updated never counts against this.
    // std::nullopt (the default) leaves the map genuinely unbounded in entry COUNT, same as every
    // other field here when unset -- but see decoder.cpp's own comment: the "don't retain empty
    // entries" half of the fix already applies unconditionally, cap configured or not.
    std::optional<size_t> max_active_flows;

    // Bounds the TOTAL entry count summed across every protocol's own map inside
    // Decoder::registry_flow_state_ (protocol_decoder.hpp's DecodeContext::flow_state<T>()) --
    // the same "many distinct flows/sessions" shape as max_active_flows above, but for the
    // registration-model decoders' (SMB pipes, DCE/RPC interfaces, Kerberos, LDAP, WinRM, DCOM,
    // Modbus/TwinCAT/MELSEC/MQTT sessions, DNP3/COTP reassembly, and every future protocol built
    // on this interface) own per-session/per-flow state, which -- unlike tcp_reassembly_ -- has no
    // natural "fully consumed, safe to drop" moment for most of these protocols (a Kerberos or
    // LDAP session's own state is meant to persist for the connection's whole life), so this is a
    // pure ceiling rather than a "don't create it in the first place" fix. std::nullopt (the
    // default) leaves it unbounded, same as every other field here.
    std::optional<size_t> max_flow_state_entries;
};

// Returns the currently active process-wide limits (default-constructed, i.e. every field
// std::nullopt, until set_resource_limits has been called at least once). Callable from
// anywhere -- every in-scope constant site reads this directly rather than receiving it as a
// parameter; see this file's header comment for why.
const ResourceLimits& resource_limits();

// Sets the process-wide active limits, replacing whatever was set before. Called once by
// Decoder's constructor (decoder.hpp) from the DecodeOptions it was built with -- see that
// constructor's own comment for why that's the right, single place to call this from. Safe under
// this codebase's actual usage pattern (every real entry point -- the three CLI subcommands,
// every fuzz harness -- constructs exactly one Decoder per process); not designed for
// concurrently running multiple differently-configured Decoders within one process.
void set_resource_limits(const ResourceLimits& limits);

}  // namespace conduitscope
