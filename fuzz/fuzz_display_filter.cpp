// SPDX-License-Identifier: Apache-2.0
// fuzz_display_filter.cpp - libFuzzer harness for the -Y/--display-filter lexer/parser
// (display_filter.hpp/display_filter_parser.cpp) -- this codebase's first hand-rolled TEXT parser
// over untrusted-shaped input (every other fuzz_*.cpp here targets a binary wire-format decoder).
// Extends this project's own "every decoder gets fuzzed" convention to "every hand-rolled
// untrusted-shaped-text parser gets fuzzed": a malformed filter expression is fed straight to
// compile_display_filter, exactly the same string a user's own -Y argument would carry.
//
// No DecodedPacket is needed at all -- this exercises only the lexer/parser/type-checker, not the
// evaluator (which runs against an already-compiled, already-valid filter and a real packet; its
// own correctness is covered by CTest's decode_display_filter_* cases instead). A successful parse
// or a compile_display_filter failure (std::nullopt + an error string) are both expected, valid
// outcomes here -- only a crash, an unbounded loop, or a leaked/undefined-behavior read is a find.
#include <cstdint>
#include <cstddef>
#include <string>

#include "conduitscope/display_filter.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    std::string expr(reinterpret_cast<const char*>(data), size);

    std::string error;
    (void)conduitscope::compile_display_filter(expr, &error);

    return 0;
}
