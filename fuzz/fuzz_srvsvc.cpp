// SPDX-License-Identifier: Apache-2.0
// fuzz_srvsvc.cpp - libFuzzer harness for SRVSVC (MS-SRVS) opnum decoding (srvsvc.hpp), riding
// DCE/RPC (dcerpc.hpp) on the \PIPE\srvsvc named pipe -- the interface `net view \\host` and every
// share/session/connection enumeration tool actually drives. See srvsvc.hpp's own file header
// comment for the full OPNUM COVERAGE breakdown this harness drives every entry of.
//
// Calls try_parse_srvsvc_request/try_parse_srvsvc_response directly on the raw fuzzer bytes as the
// `stub` ByteSpan (the DCE/RPC PDU envelope is already stripped by the time smb.cpp reaches these
// entry points -- see fuzz_netlogon.cpp's identical note; dcerpc.hpp's own envelope framing is
// fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's own
// srvsvc_opnum_name_raw table names (srvsvc.cpp) -- NetrConnectionEnum(8)/NetrFileEnum(9)/
// NetrSessionEnum(12)/NetrShareAdd(14)/NetrShareEnum(15)/NetrShareGetInfo(16)/NetrShareDel(18) --
// both request and response for each, and sealed={true,false} for each of those, exercising this
// file's own full-decode tier (NetrShareEnum/NetrShareGetInfo, scoped to SHARE_INFO level 1, the
// redundant Level+union-tag wrinkle and the batched-array SHARE_INFO_1_ARRAY shape this file's own
// header comment documents), header-only-request/structural-response tier (NetrConnectionEnum/
// NetrFileEnum/NetrSessionEnum, deliberately NOT decoding the level-dependent response array this
// file's own header comment explains was never independently verified), and the always-noted
// structural-only tier (NetrShareAdd/NetrShareDel) -- the same "loop over a small set of
// representative values against the same input" shape fuzz_mqtt.cpp's own session_version_hint loop
// establishes, scaled to this file's own opnum table (see this harness's own entry in
// fuzz/README.md for why this reaches far more distinct opnum-specific code paths per input than a
// typical harness here). `call_id` is fixed at 1 throughout -- see try_parse_samr_request's own doc
// comment (samr.hpp), which try_parse_srvsvc_request's own doc comment (srvsvc.hpp) explicitly
// shares: a pure caller-side correlation label this file's own field decode never itself branches
// on.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/srvsvc.hpp"

namespace {
constexpr uint16_t kOpnums[] = {8, 9, 12, 14, 15, 16, 18};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_srvsvc_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_srvsvc_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
