// SPDX-License-Identifier: Apache-2.0
// fuzz_pcap_reader.cpp - libFuzzer harness for PcapReader (see pcap_reader.hpp): classic pcap
// AND pcapng file-format parsing, auto-detected from the first four bytes exactly as it is for
// a real `--read somefile.pcap` invocation. This is the first-listed priority in
// docs/DEVELOPMENT.md's fuzzing plan -- PcapReader is the very first untrusted-byte boundary
// every capture file crosses, before any protocol decoding even begins.
//
// PcapReader's public interface takes a file path (std::ifstream internally), not an in-memory
// buffer -- rather than changing that production interface just to make it fuzzer-friendly, this
// harness writes each fuzzer-provided input to a small scratch file and constructs a real
// PcapReader against it, then drains it with next() exactly as cli_main.cpp's decode command
// does. One scratch file per process (named with the PID, so parallel `-jobs=N` workers never
// collide) is reused/overwritten across iterations rather than creating a fresh file per run --
// this keeps each iteration's I/O overhead to one open+write+reopen instead of a filesystem churn
// per input, which matters because libFuzzer expects each LLVMFuzzerTestOneInput call to be fast.
#include <cstdint>
#include <cstdio>
#include <cstddef>
#include <fstream>
#include <string>
#include <unistd.h>  // getpid() -- POSIX only; this fuzz harness is not built on Windows

#include "conduitscope/pcap_reader.hpp"

namespace {

std::string ScratchPath() {
    // getpid() keeps this unique per libFuzzer worker process; a fixed name would let parallel
    // `-jobs=N` workers stomp on each other's scratch file mid-write.
    return "/tmp/conduitscope_fuzz_pcap_reader_" + std::to_string(getpid()) + ".pcap";
}

}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    static const std::string path = ScratchPath();

    {
        std::ofstream out(path, std::ios::binary | std::ios::trunc);
        if (!out) return 0;
        out.write(reinterpret_cast<const char*>(data), static_cast<std::streamsize>(size));
    }

    try {
        conduitscope::PcapReader reader(path);
        conduitscope::PcapPacket packet;
        // A malformed/adversarial file could in principle declare an enormous number of
        // zero-or-near-zero-length records; cap iterations so one input can't turn into an
        // effectively infinite loop and starve the fuzzer's per-run time budget instead of
        // surfacing a real bug.
        constexpr int kMaxPackets = 100000;
        int count = 0;
        while (count < kMaxPackets && reader.next(packet)) {
            ++count;
        }
    } catch (const conduitscope::ParseError&) {
        // Expected and correct for a truncated/malformed capture -- exactly what real callers
        // (cli_main.cpp) already catch and report per-file, not a bug in itself.
    } catch (const std::exception&) {
        // Any other std::exception (e.g. std::bad_alloc from a huge declared length) is also not
        // itself a crash worth reporting via libFuzzer's own crash mechanism -- ASan/UBSan still
        // catch the actual memory-safety bugs this harness exists to find; a clean C++ exception
        // is PcapReader behaving as designed.
    }

    return 0;
}
