// SPDX-License-Identifier: Apache-2.0
// fuzz_drsuapi.cpp - libFuzzer harness for DRSUAPI (MS-DRSR) opnum decoding (drsuapi.hpp), the
// interface DRSGetNCChanges/DCSync-style directory replication rides on -- see drsuapi.hpp's own
// file header comment, in particular its own EMPIRICALLY-DISCOVERED SCOPE CAVEAT that this codebase
// only ever sees DRSUAPI traffic that happens to ride an SMB named pipe (not DRSUAPI's own default
// RPC-over-TCP/dynamic-port transport) -- irrelevant to this harness itself, which fuzzes the opnum-
// level stub decode directly, same as every other interface harness in this batch.
//
// Calls try_parse_drsuapi_request/try_parse_drsuapi_response directly on the raw fuzzer bytes as the
// `stub` ByteSpan (the DCE/RPC PDU envelope is already stripped by the time smb.cpp reaches these
// entry points -- see fuzz_netlogon.cpp's identical note; dcerpc.hpp's own envelope framing is
// fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's own
// drsuapi_opnum_name_raw table names (drsuapi.cpp) -- deliberately the narrowest curated table of
// any interface in this batch: DRSBind(0)/DRSUnbind(1)/DRSGetNCChanges(3)/DRSCrackNames(12) -- both
// request and response for each, and sealed={true,false} for each of those, exercising this file's
// own header-only tier (DRSBind's own puuidClientDsa GUID and phDrs handle, including
// skip_drs_extensions' own DRS_EXTENSIONS-blob-skipping padding logic on the response side --
// drsuapi.hpp's own header comment notes this was empirically verified against a deliberately non-
// 4-byte-aligned DRS_EXTENSIONS payload during planning, exactly the kind of alignment edge case
// this fuzzing pass is meant to stress; DRSUnbind's own direct, non-pointer-indirected phDrs decode)
// and the always-noted structural-only tier (DRSGetNCChanges, DRSCrackNames) -- the same "loop over
// a small set of representative values against the same input" shape fuzz_mqtt.cpp's own
// session_version_hint loop establishes, scaled to this file's own opnum table (see this harness's
// own entry in fuzz/README.md for why this reaches far more distinct opnum-specific code paths per
// input than a typical harness here). `call_id` is fixed at 1 throughout -- see
// try_parse_samr_request's own doc comment (samr.hpp), which try_parse_drsuapi_request's own doc
// comment (drsuapi.hpp) explicitly shares: a pure caller-side correlation label this file's own
// field decode never itself branches on.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/drsuapi.hpp"

namespace {
constexpr uint16_t kOpnums[] = {0, 1, 3, 12};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_drsuapi_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_drsuapi_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
