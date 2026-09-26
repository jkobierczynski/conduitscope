// SPDX-License-Identifier: Apache-2.0
// resource_limits_selftest.cpp - a small, standalone executable (not the `conduitscope` CLI
// itself), modeled directly on tools/protocol_result_selftest.cpp's own shape, that exercises the
// ScopedResourceLimits fix for finding 5 (docs/reviews/2026-09-chatgpt-security-review-
// patch160.md, "ResourceLimits is process-global mutable state" -- see resource_limits.hpp's own
// header comment for the full rationale).
//
// WHY THIS EXISTS AS ITS OWN TOOL, RATHER THAN A PCAP FIXTURE PLUS A CLI-DRIVEN CTest
// PASS_REGULAR_EXPRESSION (this project's usual discipline for a security-review finding): the
// bug this closes is only observable across MULTIPLE Decoder instances sharing one process --
// either interleaved on one thread or run concurrently on separate threads. The `conduitscope`
// CLI itself only ever constructs one Decoder per process (see decoder.hpp's own constructor
// comment), so no CLI invocation, and therefore no CLI-driven CTest case, can even construct the
// scenario the review's finding describes. A dedicated small executable that constructs two
// differently-configured Decoder instances directly is the only way to exercise this.
//
// Reuses tests/sample_dnp3.pcap (the same fixture CMakeLists.txt's own
// max_decoded_objects_dnp3_truncates_headers_and_points CLI test already relies on) -- packet #3
// in that capture, a DNP3 Response carrying two object headers (g1v2 with 3 points, g30v1 with 1
// point) whose point values are capped CUMULATIVELY across both headers (see dnp3.cpp's own
// Dnp3Decoder::decode comment): 4 total point values at the compile-time/unset default (50), and
// exactly 1 when max_decoded_objects is overridden to 1 (the same "only the first 1 of 3" the
// existing CLI test's own PASS_REGULAR_EXPRESSION confirms for g1v2's own point loop, plus zero
// more from g30v1 since the cumulative cap is already hit). That 4-vs-1 difference is what each
// check below uses to prove which Decoder's own configured limit was actually in effect during
// its own decode() call.
//
// Checks 5-6 below (finding 3, docs/reviews/2026-09-chatgpt-security-review-patch209.md,
// "--max-active-flows 0 can cause invalid iterator erasure") reuse two more fixtures CMakeLists.txt's
// own CLI-driven max_active_flows_evicts_other_flow_entry/max_flow_state_entries_evicts_other_
// session_state tests already rely on: tests/sample_resource_exhaustion_active_flows.pcap (two
// distinct TCP flows, each left "waiting for more" mid-reassembly) and tests/sample_resource_
// exhaustion_flow_state.pcap (two distinct Modbus TCP sessions, each opening with a request). Those
// two CLI tests only ever exercise a NONZERO cap (1) -- cli_main.cpp's own build_resource_limits
// treats a `--max-active-flows 0`/`--max-flow-state-entries 0` CLI argument as "flag not passed",
// so the CLI can never construct the ResourceLimits{max_active_flows = 0} scenario finding 3 is
// about at all, the same "only a direct library/API caller can reach this" gap the review itself
// notes. A dedicated check against the library API directly, exactly like checks 1-4 above, is the
// only way to exercise it.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as protocol_result_selftest/crypto_selftest; wired into CMakeLists.txt's own
// "ResourceLimits scoping self-test" section as its own CTest case, unconditionally (like those
// two, this needs no separate toolchain or opt-in flag).
#include <atomic>
#include <cstdio>
#include <string>
#include <thread>
#include <vector>

#include "conduitscope/decoder.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/pcap_reader.hpp"
#include "conduitscope/resource_limits.hpp"

namespace {

int g_failures = 0;

void check_bool(const char* name, bool ok) {
    if (ok) {
        std::printf("PASS  %s\n", name);
    } else {
        std::printf("FAIL  %s\n", name);
        ++g_failures;
    }
}

// Returns the number of DNP3 point values decode() reported for the fixture's one packet, or -1
// if the packet didn't decode as DNP3 at all (a hard error for this tool -- the fixture is
// expected to always be DNP3, so -1 always fails whatever check called this).
long dnp3_point_value_count(const conduitscope::Decoder& decoder,
                             const conduitscope::PcapPacket& packet, uint32_t link_type) {
    conduitscope::DecodedPacket out = decoder.decode(packet, link_type, 1);
    if (out.protocol != "dnp3" || !out.result) {
        return -1;
    }
    return static_cast<long>(out.result->as<conduitscope::Dnp3Result>().dnp3_point_values.size());
}

}  // namespace

int main(int argc, char** argv) {
    using namespace conduitscope;

    if (argc != 4) {
        std::fprintf(stderr,
                      "usage: %s <path to tests/sample_dnp3.pcap> "
                      "<path to tests/sample_resource_exhaustion_active_flows.pcap> "
                      "<path to tests/sample_resource_exhaustion_flow_state.pcap>\n",
                      argv[0]);
        return 1;
    }
    const char* active_flows_pcap_path = argv[2];
    const char* flow_state_pcap_path = argv[3];

    // Load the fixture once and keep only packet #3 -- the DNP3 Response frame with multiple
    // object headers/point values described above (the fixture's other packets are link-layer-
    // only frames, mid-fragment continuations, or single-point reads, none of which exercise a
    // cumulative multi-header cap the way this one does). Every check below decodes this same
    // packet repeatedly, through different Decoder instances, never mutating it.
    PcapReader reader(argv[1]);
    PcapPacket packet;
    bool found = false;
    for (size_t index = 1; reader.next(packet); ++index) {
        if (index == 3) {
            found = true;
            break;
        }
    }
    if (!found) {
        std::fprintf(stderr, "fixture pcap does not have a packet #3\n");
        return 1;
    }
    const uint32_t link_type = reader.info().linktype;

    // Baseline: confirm this tool's own understanding of the fixture matches the existing CLI
    // test's own expectation (4 point values unset/default, 1 when capped) before trusting either
    // number in the actual race checks below -- if this fixture or dnp3.cpp's own behavior ever
    // changes, this fails loudly here rather than the real checks below failing for a confusing
    // reason.
    {
        DecodeOptions unset_options;
        Decoder unset_decoder(unset_options);
        long unset_count = dnp3_point_value_count(unset_decoder, packet, link_type);
        check_bool("baseline: fixture decodes as DNP3 with 4 point values at the unset/default cap",
                   unset_count == 4);

        DecodeOptions capped_options;
        capped_options.limits.max_decoded_objects = 1;
        Decoder capped_decoder(capped_options);
        long capped_count = dnp3_point_value_count(capped_decoder, packet, link_type);
        check_bool("baseline: fixture truncates to 1 point value when max_decoded_objects=1",
                   capped_count == 1);
    }

    // 1. The review's own literal example: two Decoder instances, differently configured,
    // constructed on the same thread -- `Decoder paranoid_decoder(options_a); Decoder
    // normal_decoder(options_b);`. Before the fix, the SECOND constructor's set_resource_limits
    // call would silently reconfigure the FIRST decoder's every subsequent decode() call too
    // (a plain process-wide static, last writer wins). After the fix, each decode() call installs
    // its own instance's limits via ScopedResourceLimits, so construction order and interleaving
    // order no longer matter at all.
    {
        DecodeOptions paranoid_options;
        paranoid_options.limits.max_decoded_objects = 1;
        Decoder paranoid_decoder(paranoid_options);

        DecodeOptions normal_options;  // unset -- default cap (50), decodes all 4 point values
        Decoder normal_decoder(normal_options);

        // Interleave: paranoid, normal, paranoid, normal -- exactly the shape a real caller
        // holding two Decoder instances and switching between them per-packet would produce.
        long p1 = dnp3_point_value_count(paranoid_decoder, packet, link_type);
        long n1 = dnp3_point_value_count(normal_decoder, packet, link_type);
        long p2 = dnp3_point_value_count(paranoid_decoder, packet, link_type);
        long n2 = dnp3_point_value_count(normal_decoder, packet, link_type);

        check_bool("paranoid_decoder (max_decoded_objects=1) truncates to 1 on its first call",
                   p1 == 1);
        check_bool("normal_decoder (unset) still decodes all 4 on its first call, right after "
                   "paranoid_decoder's own call",
                   n1 == 4);
        check_bool("paranoid_decoder truncates to 1 again on its second call, unaffected by "
                   "normal_decoder's intervening call",
                   p2 == 1);
        check_bool("normal_decoder still decodes all 4 again on its second call, unaffected by "
                   "paranoid_decoder's intervening calls",
                   n2 == 4);
    }

    // 2. Construction order reversed from check 1 (normal built first, paranoid built second) --
    // proves this isn't just "whichever constructor ran last wins" in a different disguise; each
    // decode() call's own instance is what determines the limit in effect, never construction
    // order.
    {
        DecodeOptions normal_options;
        Decoder normal_decoder(normal_options);

        DecodeOptions paranoid_options;
        paranoid_options.limits.max_decoded_objects = 1;
        Decoder paranoid_decoder(paranoid_options);

        long n = dnp3_point_value_count(normal_decoder, packet, link_type);
        long p = dnp3_point_value_count(paranoid_decoder, packet, link_type);
        check_bool("construction-order-reversed: normal_decoder (built first) still decodes all "
                   "4, even though paranoid_decoder was constructed after it",
                   n == 4);
        check_bool("construction-order-reversed: paranoid_decoder (built second) still truncates "
                   "to 1",
                   p == 1);
    }

    // 3. resource_limits() read immediately after Decoder construction (outside of any decode()
    // call) still reflects that instance's own limits -- the constructor's own
    // set_resource_limits call, kept for backward compatibility (see decoder.hpp's own comment).
    // This is the one place construction order still matters post-fix: the constructor call is
    // NOT scoped/restored the way decode()'s own ScopedResourceLimits guard is, so constructing a
    // second Decoder does change what resource_limits() reports outside of any decode() call --
    // exactly like before this fix. That's fine: no call site in this codebase ever reads
    // resource_limits() from outside a decode() call, and decode() itself never relies on
    // whatever the constructor left behind, since it re-asserts its own instance's limits via
    // ScopedResourceLimits at its own entry regardless. The check below proves that half:
    // ScopedResourceLimits restores whatever was ACTUALLY active before its own call started
    // (here, normal_decoder's own unset limits, left behind by its own constructor a moment
    // earlier) -- not paranoid_decoder's limits, and not some other fixed default -- confirming
    // it is a genuine save/restore guard, not a "reset to the first decoder ever built" guard.
    {
        DecodeOptions paranoid_options;
        paranoid_options.limits.max_decoded_objects = 1;
        Decoder paranoid_decoder(paranoid_options);  // sets thread-local limits to max=1

        check_bool("resource_limits() reflects the constructing Decoder's own limits right after "
                   "construction",
                   resource_limits().max_decoded_objects == 1);

        DecodeOptions normal_options;
        Decoder normal_decoder(normal_options);  // sets thread-local limits to unset, right now
        (void)dnp3_point_value_count(normal_decoder, packet, link_type);  // scoped to unset, then restored

        check_bool("resource_limits() is restored to whatever was active before decode() was "
                   "called (normal_decoder's own unset limits, left by its own constructor), not "
                   "some other decoder's limits",
                   !resource_limits().max_decoded_objects.has_value());
    }

    // 4. Genuine cross-thread concurrency: two real threads, each looping many decode() calls on
    // its own Decoder instance with a different max_decoded_objects, running concurrently. Before
    // the fix (a plain process-wide static with no synchronization at all) this would be an
    // outright data race -- UB, not just wrong output -- caught by ThreadSanitizer if built with
    // it and prone to visibly wrong/inconsistent counts even without it. After the fix
    // (thread_local storage), each thread's own decode() calls only ever see that thread's own
    // ScopedResourceLimits value; there is nothing shared to race over.
    {
        constexpr int kIterations = 2000;
        std::atomic<int> paranoid_wrong{0};
        std::atomic<int> normal_wrong{0};

        std::thread paranoid_thread([&] {
            DecodeOptions options;
            options.limits.max_decoded_objects = 1;
            Decoder decoder(options);
            for (int i = 0; i < kIterations; ++i) {
                if (dnp3_point_value_count(decoder, packet, link_type) != 1) {
                    ++paranoid_wrong;
                }
            }
        });
        std::thread normal_thread([&] {
            DecodeOptions options;  // unset
            Decoder decoder(options);
            for (int i = 0; i < kIterations; ++i) {
                if (dnp3_point_value_count(decoder, packet, link_type) != 4) {
                    ++normal_wrong;
                }
            }
        });
        paranoid_thread.join();
        normal_thread.join();

        check_bool("concurrent thread with max_decoded_objects=1 saw the correct truncated count "
                   "on every one of 2000 decode() calls, never affected by the other thread",
                   paranoid_wrong.load() == 0);
        check_bool("concurrent thread with unset limits saw the correct full count on every one "
                   "of 2000 decode() calls, never affected by the other thread",
                   normal_wrong.load() == 0);
    }

    // 5. Finding 3 (docs/reviews/2026-09-chatgpt-security-review-patch209.md): set_resource_limits
    // normalizes a literal max_active_flows=0/max_flow_state_entries=0 to std::nullopt (no cap) --
    // see resource_limits.cpp's own comment for why this is the fix, rather than trying to give a
    // literal zero cap real "evict to make room" semantics. Checked directly against
    // resource_limits() after set_resource_limits(), independent of any decode() call, so a
    // regression here is caught even if some future change to Decoder/DecodeContext stopped
    // routing through set_resource_limits for some other reason.
    {
        ResourceLimits baseline;  // reset thread-local state to a known "everything unset" value
        set_resource_limits(baseline);

        ResourceLimits zero_active_flows;
        zero_active_flows.max_active_flows = 0;
        set_resource_limits(zero_active_flows);
        check_bool("set_resource_limits normalizes an explicit max_active_flows=0 to no cap "
                   "(std::nullopt) rather than storing a literal zero",
                   !resource_limits().max_active_flows.has_value());

        set_resource_limits(baseline);

        ResourceLimits zero_flow_state_entries;
        zero_flow_state_entries.max_flow_state_entries = 0;
        set_resource_limits(zero_flow_state_entries);
        check_bool("set_resource_limits normalizes an explicit max_flow_state_entries=0 to no cap "
                   "(std::nullopt) rather than storing a literal zero",
                   !resource_limits().max_flow_state_entries.has_value());

        // A nonzero value is never touched by the normalization -- confirms the fix is specific to
        // exactly 0, not an off-by-one that also clobbers legitimate small caps like 1.
        ResourceLimits one_of_each;
        one_of_each.max_active_flows = 1;
        one_of_each.max_flow_state_entries = 1;
        set_resource_limits(one_of_each);
        check_bool("set_resource_limits leaves a real max_active_flows=1 cap alone (normalization "
                   "is specific to exactly 0)",
                   resource_limits().max_active_flows == 1);
        check_bool("set_resource_limits leaves a real max_flow_state_entries=1 cap alone "
                   "(normalization is specific to exactly 0)",
                   resource_limits().max_flow_state_entries == 1);

        set_resource_limits(baseline);  // leave thread-local state clean for the checks below
    }

    // 6. Finding 3's actual regression target: before this fix, a Decoder configured with
    // max_active_flows=0 hit undefined behavior (Decoder::reassemble_tcp_payload erasing
    // tcp_reassembly_.begin() from an already-empty map) on literally the first packet that needed
    // TCP reassembly, and one configured with max_flow_state_entries=0 silently inserted a
    // registry flow-state entry past its own configured zero cap. Replaying the same two fixtures
    // CMakeLists.txt's own CLI-driven eviction tests use (with a cap of 1, where eviction is
    // supposed to happen) proves both that this no longer crashes -- especially meaningful under
    // the sanitizer-enabled build, which would otherwise report the erase-from-empty-map UB
    // directly -- and that the normalization from check 5 gives a configured 0 the same "unlimited"
    // behavior as leaving the cap unset entirely, not some other, half-enforced in-between state.
    {
        DecodeOptions active_flows_options;
        active_flows_options.limits.max_active_flows = 0;
        Decoder active_flows_decoder(active_flows_options);

        PcapReader active_flows_reader(active_flows_pcap_path);
        PcapPacket p;
        uint32_t lt = active_flows_reader.info().linktype;
        bool saw_waiting = false;
        bool saw_eviction_note = false;
        for (size_t index = 1; active_flows_reader.next(p); ++index) {
            DecodedPacket out = active_flows_decoder.decode(p, lt, index);
            if (out.summary.find("waiting for more") != std::string::npos) saw_waiting = true;
            for (const auto& n : out.notes) {
                if (n.find("active TCP flow-reassembly limit") != std::string::npos) {
                    saw_eviction_note = true;
                }
            }
        }
        check_bool("Decoder configured with max_active_flows=0 decodes the two-distinct-flow "
                   "resource-exhaustion fixture without crashing (the erase-from-an-empty-map UB "
                   "this fix closes) and both flows' reassembly states coexist with no eviction, "
                   "the same behavior an unset cap already has",
                   saw_waiting && !saw_eviction_note);

        DecodeOptions flow_state_options;
        flow_state_options.limits.max_flow_state_entries = 0;
        Decoder flow_state_decoder(flow_state_options);

        PcapReader flow_state_reader(flow_state_pcap_path);
        uint32_t lt2 = flow_state_reader.info().linktype;
        bool saw_authoritative = false;
        bool saw_no_outstanding = false;
        for (size_t index = 1; flow_state_reader.next(p); ++index) {
            DecodedPacket out = flow_state_decoder.decode(p, lt2, index);
            for (const auto& n : out.notes) {
                if (n.find("authoritative pairing: response to transaction id 100") !=
                    std::string::npos) {
                    saw_authoritative = true;
                }
                if (n.find("no outstanding request found on this TCP session for transaction id "
                            "100") != std::string::npos) {
                    saw_no_outstanding = true;
                }
            }
        }
        check_bool("Decoder configured with max_flow_state_entries=0 decodes the "
                   "two-distinct-session resource-exhaustion fixture without silently inserting "
                   "past the configured zero cap (the registry-side correctness bug this fix also "
                   "closes) -- session 1's response still pairs authoritatively instead of being "
                   "evicted, the same behavior an unset cap already has",
                   saw_authoritative && !saw_no_outstanding);
    }

    std::printf("\n%d check(s) failed\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
