// SPDX-License-Identifier: Apache-2.0
// fuzz_wkssvc.cpp - libFuzzer harness for WKSSVC (MS-WKST) opnum decoding (wkssvc.hpp), riding
// DCE/RPC (dcerpc.hpp) on the \PIPE\wkssvc named pipe -- the interface that answers "what is this
// machine, and who is logged into it" (NetrWkstaGetInfo/NetrWkstaUserEnum). See wkssvc.hpp's own
// file header comment for the full OPNUM COVERAGE breakdown this harness drives every entry of.
//
// Calls try_parse_wkssvc_request/try_parse_wkssvc_response directly on the raw fuzzer bytes as the
// `stub` ByteSpan (the DCE/RPC PDU envelope is already stripped by the time smb.cpp reaches these
// entry points -- see fuzz_netlogon.cpp's identical note; dcerpc.hpp's own envelope framing is
// fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's own
// wkssvc_opnum_name_raw table names (wkssvc.cpp) -- NetrWkstaGetInfo(0)/NetrWkstaUserEnum(2)/
// NetrWkstaTransportEnum(5)/NetrJoinDomain2(22)/NetrUnjoinDomain2(23) -- both request and response
// for each, and sealed={true,false} for each of those, exercising this file's own full-decode tier
// (NetrWkstaGetInfo scoped to WKSTA_INFO level 100, the nested-struct-batches-its-own-pointers shape
// this file's own header comment documents; NetrWkstaUserEnum scoped to WKSTA_USER_INFO level 1, the
// batched-array WKSTA_USER_INFO_1_ARRAY shape shared with srvsvc.hpp's own SHARE_INFO_1_ARRAY),
// header-only-request/structural-response tier (NetrWkstaTransportEnum, deliberately not decoding
// its own response array for the same "never guess at an unverified per-level shape" reason
// srvsvc.hpp's own enumeration opnums draw), and the always-noted, credential-adjacent structural-
// only tier (NetrJoinDomain2/NetrUnjoinDomain2, whose own PJOINPR_ENCRYPTED_USER_PASSWORD field this
// file never attempts to parse) -- the same "loop over a small set of representative values against
// the same input" shape fuzz_mqtt.cpp's own session_version_hint loop establishes, scaled to this
// file's own opnum table (see this harness's own entry in fuzz/README.md for why this reaches far
// more distinct opnum-specific code paths per input than a typical harness here). `call_id` is fixed
// at 1 throughout -- see try_parse_samr_request's own doc comment (samr.hpp), which
// try_parse_wkssvc_request's own doc comment (wkssvc.hpp) explicitly shares: a pure caller-side
// correlation label this file's own field decode never itself branches on.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/wkssvc.hpp"

namespace {
constexpr uint16_t kOpnums[] = {0, 2, 5, 22, 23};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_wkssvc_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_wkssvc_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
