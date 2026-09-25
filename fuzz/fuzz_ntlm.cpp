// SPDX-License-Identifier: Apache-2.0
// fuzz_ntlm.cpp - libFuzzer harness for NTLM (MS-NLMP) authentication message decoding (ntlm.hpp),
// embedded inside SMB2 NEGOTIATE/SESSION_SETUP messages (see ntlm.hpp's own file header comment:
// "NTLM's own wire format is BYTE-IDENTICAL wherever it is embedded", so one shared parser covers
// every embedding, and smb.cpp's own scan_for_ntlm is the only real caller). NTLM's own fixed 8-byte
// "NTLMSSP\0" signature + 4-byte MessageType selects among three structurally different message
// shapes (NEGOTIATE/CHALLENGE/AUTHENTICATE), each addressing its own variable-length fields through
// an 8-byte Len/MaxLen/Offset "field descriptor" -- exactly the hand-rolled offset/length parsing
// this fuzzing pass targets, on a format this codebase had zero prior recognition of before smb.hpp
// landed.
//
// Calls try_parse_ntlm directly on the raw fuzzer bytes, exactly like fuzz_smb.cpp's own
// try_parse_smb call and every other single-entry-point harness in this codebase -- `message` must
// start at the "NTLMSSP\0" signature itself (ntlm.hpp's own doc comment: try_parse_ntlm does not
// search for it, smb.cpp's own scan_for_ntlm signature-scan is a separate, already-covered step via
// fuzz_smb.cpp's own try_parse_smb call), so this harness's corpus is seeded starting exactly at
// that signature (see fuzz/corpus/ntlm/'s own extraction, which slices each seed from the genuine
// signature offset found in a real captured SESSION_SETUP Buffer, not from the start of the
// enclosing SMB2 message).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ntlm.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ntlm(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
