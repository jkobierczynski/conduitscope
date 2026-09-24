// SPDX-License-Identifier: Apache-2.0
// protocol_result_selftest.cpp - a small, standalone executable (not the `conduitscope` CLI
// itself), modeled directly on tools/crypto_selftest.cpp's own shape, that exercises
// ProtocolResult::as<T>()'s type-safety fix (finding 3,
// docs/reviews/2026-09-chatgpt-security-review-patch160.md, rated Medium -- "type safety"; see
// protocol_decoder.hpp's own ProtocolResultTypeMismatch/ProtocolResult comments for the full
// rationale).
//
// WHY THIS EXISTS AS ITS OWN TOOL, RATHER THAN A PCAP FIXTURE PLUS A CTest PASS_REGULAR_EXPRESSION
// (this project's usual discipline for a security-review finding -- see e.g. the terminal-escape-
// injection and pcapng-tsresol fixtures/tests this same review round already added): the bug this
// closes is a mismatch between the protocol_id string and the C++ type T requested at an
// `as<T>()` call site, and every one of those call sites lives in this codebase's own source code
// (decoder.cpp, output.cpp), never in anything a capture file's bytes can influence. There is no
// wire-format input that can make today's ~44 real call sites pass the wrong T -- they're all
// correct today, which is exactly why the review calls this "not attacker-reachable... but a real
// landmine for a future migration that gets the association wrong." A pcap fixture can't exercise
// a bug that lives in source code, not packet bytes, so this tool constructs the mismatch directly
// instead, using two deliberately-fake result types that stand in for a real pair like EnipResult/
// CipIoFrame (see test 3 below, which mirrors that exact real scenario --
// output.cpp's write_enip_json_fields/write_enip_io_json_fields comment).
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as crypto_selftest.cpp; wired into CMakeLists.txt's own "Protocol result type safety
// self-test" section as its own CTest case, unconditionally (like crypto_selftest, this needs no
// separate toolchain or opt-in flag).
#include <cstdio>
#include <stdexcept>
#include <string>

#include "conduitscope/protocol_decoder.hpp"

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

// Two deliberately unrelated, deliberately fake "protocol result" structs -- not any real
// decoder's own type -- so this tool never has to reach into or depend on a real protocol's
// header. Standing in for a pair like EnipResult/CipIoFrame (real, and genuinely different C++
// types that legitimately share one protocol_id -- see output.cpp's own comment) in test 3 below.
struct DummyFrameA {
    int value = 0;
    std::string tag;
};

struct DummyFrameB {
    double value = 0.0;
};

}  // namespace

int main() {
    using namespace conduitscope;

    // 1. Happy path: as<T>() with the T a result was actually constructed with must still work
    // exactly as before this fix -- the check this adds must cost correctness nothing on the path
    // every one of today's real call sites actually takes.
    {
        ProtocolResult r = ProtocolResult::make<DummyFrameA>("dummy-a", DummyFrameA{42, "hello"});
        bool ok = false;
        try {
            const DummyFrameA& a = r.as<DummyFrameA>();
            ok = (a.value == 42 && a.tag == "hello");
        } catch (...) {
            ok = false;
        }
        check_bool("as<T>() with the correct T still returns the value unchanged", ok);
    }

    // 2. The actual fix: as<T>() with the WRONG T must throw ProtocolResultTypeMismatch -- a
    // diagnosable, catchable failure -- rather than silently reinterpreting DummyFrameA's bytes as
    // a DummyFrameB (undefined behavior, the exact defect finding 3 describes).
    {
        ProtocolResult r = ProtocolResult::make<DummyFrameA>("dummy-a", DummyFrameA{7, "x"});
        bool threw_right_type = false;
        std::string message;
        try {
            (void)r.as<DummyFrameB>();
            // If this line is ever reached, the fix regressed back to unchecked UB -- fall
            // through to the check below reporting failure (threw_right_type stays false).
        } catch (const ProtocolResultTypeMismatch& e) {
            threw_right_type = true;
            message = e.what();
        } catch (...) {
            threw_right_type = false;
        }
        check_bool("as<T>() with the wrong T throws ProtocolResultTypeMismatch instead of UB",
                   threw_right_type);
        check_bool("the thrown message names the mismatched result's own protocol_id",
                   message.find("dummy-a") != std::string::npos);
    }

    // 3. The real landmine this fix actually guards, reproduced directly: ONE protocol_id
    // legitimately backed by TWO different C++ types depending on which decoder produced it (the
    // real EnipResult-vs-CipIoFrame situation -- see output.cpp's write_enip_json_fields/
    // write_enip_io_json_fields comment, which discriminates via DecodedPacket::has_tcp/has_udp,
    // not via protocol_id alone). Confirms each result still reads correctly as its own real type,
    // AND that cross-casting either one to the other's type is caught in both directions.
    {
        ProtocolResult tcp_side = ProtocolResult::make<DummyFrameA>("dummy-enip-like", DummyFrameA{1, "tcp"});
        ProtocolResult udp_side = ProtocolResult::make<DummyFrameB>("dummy-enip-like", DummyFrameB{2.5});

        bool tcp_as_a_ok = false, udp_as_b_ok = false;
        try {
            tcp_as_a_ok = (tcp_side.as<DummyFrameA>().value == 1);
        } catch (...) {
        }
        try {
            udp_as_b_ok = (udp_side.as<DummyFrameB>().value == 2.5);
        } catch (...) {
        }
        check_bool("same-protocol_id result #1 (the 'TCP side') still reads correctly as its own real type",
                   tcp_as_a_ok);
        check_bool("same-protocol_id result #2 (the 'UDP side') still reads correctly as its own real type",
                   udp_as_b_ok);

        bool cross_cast_1_caught = false, cross_cast_2_caught = false;
        try {
            (void)tcp_side.as<DummyFrameB>();
        } catch (const ProtocolResultTypeMismatch&) {
            cross_cast_1_caught = true;
        }
        try {
            (void)udp_side.as<DummyFrameA>();
        } catch (const ProtocolResultTypeMismatch&) {
            cross_cast_2_caught = true;
        }
        check_bool("cross-casting the 'TCP side' result to the 'UDP side' type is caught, not silently wrong",
                   cross_cast_1_caught);
        check_bool("cross-casting the 'UDP side' result to the 'TCP side' type is caught, not silently wrong",
                   cross_cast_2_caught);
    }

    // 4. ProtocolResultTypeMismatch derives from std::logic_error (see protocol_decoder.hpp) --
    // confirms it stays catchable via that coarser base too, the same "specific type, catchable
    // generically as well" shape this codebase's other exception types (ParseError/ResolverError/
    // CaptureError, all std::runtime_error) already have.
    {
        ProtocolResult r = ProtocolResult::make<DummyFrameA>("dummy-a", DummyFrameA{});
        bool caught_as_logic_error = false;
        try {
            (void)r.as<DummyFrameB>();
        } catch (const std::logic_error&) {
            caught_as_logic_error = true;
        }
        check_bool("ProtocolResultTypeMismatch is catchable as std::logic_error", caught_as_logic_error);
    }

    std::printf("\n%d check(s) failed\n", g_failures);
    return g_failures == 0 ? 0 : 1;
}
