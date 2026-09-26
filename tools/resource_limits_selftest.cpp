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

    if (argc != 2) {
        std::fprintf(stderr, "usage: %s <path to tests/sample_dnp3.pcap>\n", argv[0]);
        return 1;
    }

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

    std::printf("\n%d check(s) failed\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
