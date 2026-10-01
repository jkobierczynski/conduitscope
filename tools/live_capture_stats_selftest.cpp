// SPDX-License-Identifier: Apache-2.0
// live_capture_stats_selftest.cpp - a small, standalone executable (not the `conduitscope` CLI
// itself), modeled directly on tools/protocol_result_selftest.cpp's/tools/resource_limits_
// selftest.cpp's own shape, that exercises format_live_capture_drop_reason (live_capture.hpp) --
// the pure decision+wording half of this project's fix for docs/reviews/2026-09-chatgpt-security-
// review-patch257.md section 4, "Detection completeness" ("Packet loss... must be distinguishable
// from a clean capture with no findings").
//
// WHY THIS EXISTS AS ITS OWN TOOL, RATHER THAN A PCAP FIXTURE PLUS A CTest PASS_REGULAR_EXPRESSION
// (this project's usual discipline -- see e.g. every --max-* resource-ceiling test this codebase
// already has): a REAL OS-level pcap_stats() drop (ps_drop/ps_ifdrop) can't be deterministically
// constructed through the CLI/CTest the way an engine's own --max-detect-findings-style ceiling
// can. It depends on genuine kernel/driver buffer timing under real traffic load outpacing this
// process's own read rate -- not anything a fixed capture file replayed through PcapReader can
// reproduce on demand, and not anything a CI runner should be trying to race against. Exactly the
// same reasoning tools/resource_limits_selftest.cpp's own file header already gives for why IT
// exists as a dedicated executable rather than a CLI-driven CTest case.
//
// This is why live_capture.hpp splits LiveCapture::stats() (the actual, untestable-on-demand
// pcap_stats() call) from format_live_capture_drop_reason() (pure string formatting over an
// already-extracted LiveCaptureStats value, with no pcap.h dependency at all) -- the latter is
// exactly as testable as any other pure function in this codebase, and this tool is what actually
// tests it: every cli_main.cpp call site (decode/policy validate/inventory/detect/capture) shares
// this one function, so proving its own decision logic and wording correct here covers all five at
// once, the same "one shared helper, one set of tests, used five times" reasoning
// append_flow_state_eviction_reason's own callers already rely on.
//
// Prints one PASS/FAIL line per check to stdout and exits 0 only if every check passed, same
// contract as every other *_selftest tool in this project; wired into CMakeLists.txt's own "Live
// capture drop-statistics self-test" section as its own CTest case, unconditionally built and run
// regardless of whether THIS build actually has live-capture support
// (CONDUITSCOPE_HAVE_PCAP) -- format_live_capture_drop_reason itself has no pcap.h dependency, so
// it exists and behaves identically either way (see live_capture.hpp's own doc comment on it).
#include <cstdio>
#include <optional>
#include <string>

#include "conduitscope/live_capture.hpp"

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

bool contains(const std::string& haystack, const std::string& needle) {
    return haystack.find(needle) != std::string::npos;
}

}  // namespace

int main() {
    using namespace conduitscope;

    // 1. All-zero stats (the overwhelmingly common case -- a live run with no drops at all) must
    // produce std::nullopt, not an empty-but-present string -- every call site treats
    // "has_value()" itself as the "was anything dropped" signal (see append_live_capture_drop_
    // reason/run_decode/run_capture's own print_drop_stats_if_any, cli_main.cpp), so a non-nullopt
    // return here would wrongly flag every ordinary, clean live run as degraded.
    {
        LiveCaptureStats stats;  // every field defaults to 0
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        check_bool("zero drops -> nullopt (no false positive on a clean live run)", !reason.has_value());
    }

    // 2. packets_received alone, with both drop counters still zero, must ALSO be nullopt --
    // ps_recv is "how many packets libpcap itself saw", not itself evidence of loss (e.g. a
    // capture stopped early via --duration/--max-packets/Ctrl+C while packets were still queued
    // is completely normal and not a drop at all). Only the two *_dropped_by_* fields matter here.
    {
        LiveCaptureStats stats;
        stats.packets_received = 50000;
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        check_bool("packets_received alone (no drops) -> still nullopt", !reason.has_value());
    }

    // 3. libpcap-level drops only (the overwhelmingly common real-world case: this process's own
    // read rate falling behind, not a driver/NIC-level problem) -- must produce a reason that
    // names the libpcap/buffer cause and must NOT mention the interface/driver at all (a message
    // naming a cause that didn't apply would misdirect an operator's own troubleshooting).
    {
        LiveCaptureStats stats;
        stats.packets_received = 10000;
        stats.packets_dropped_by_libpcap = 37;
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        bool ok = reason.has_value() && contains(*reason, "37") && contains(*reason, "buffer") &&
                  !contains(*reason, "interface/driver itself");
        check_bool("libpcap-only drops -> reason names the count and the buffer cause, not the interface", ok);
    }

    // 4. Interface-level drops only (ps_ifdrop nonzero, ps_drop zero -- rarer, but the struct
    // allows it, e.g. a driver reporting NIC-ring drops libpcap's own ring never saw) -- the
    // reason must still mention the interface-level count even though packets_dropped_by_libpcap
    // itself is 0.
    {
        LiveCaptureStats stats;
        stats.packets_received = 10000;
        stats.packets_dropped_by_interface = 5;
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        bool ok = reason.has_value() && contains(*reason, "5") && contains(*reason, "interface/driver itself");
        check_bool("interface-only drops -> reason still surfaces the interface-level count", ok);
    }

    // 5. Both nonzero -- the reason must mention both counts, not just one silently winning over
    // the other (an operator needs the full picture to tell a congested-process problem (ps_drop)
    // apart from a congested-NIC problem (ps_ifdrop) -- they call for different fixes).
    {
        LiveCaptureStats stats;
        stats.packets_received = 10000;
        stats.packets_dropped_by_libpcap = 12;
        stats.packets_dropped_by_interface = 3;
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        bool ok = reason.has_value() && contains(*reason, "12") && contains(*reason, "3") &&
                  contains(*reason, "interface/driver itself");
        check_bool("both libpcap and interface drops -> reason mentions both counts", ok);
    }

    // 6. The reason text explicitly says these packets never reached conduitscope at all -- the
    // single most important fact for an operator reading an "observation incomplete" banner to
    // understand (see live_capture.hpp's own doc comment on LiveCaptureStats for why this is a
    // categorically different kind of incompleteness than every other truncation reason this
    // codebase already produces, every one of which involves a packet this process DID receive).
    {
        LiveCaptureStats stats;
        stats.packets_dropped_by_libpcap = 1;
        std::optional<std::string> reason = format_live_capture_drop_reason(stats);
        bool ok = reason.has_value() && contains(*reason, "never reached conduitscope");
        check_bool("reason text states plainly that dropped packets never reached conduitscope", ok);
    }

    std::printf("\n%s\n", g_failures == 0 ? "ALL CHECKS PASSED" : "SOME CHECKS FAILED");
    return g_failures == 0 ? 0 : 1;
}
