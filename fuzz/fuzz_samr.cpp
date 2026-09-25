// SPDX-License-Identifier: Apache-2.0
// fuzz_samr.cpp - libFuzzer harness for SAMR (MS-SAMR) opnum decoding (samr.hpp), riding DCE/RPC
// (dcerpc.hpp) on the \PIPE\samr named pipe -- the interface account/group/domain enumeration
// tooling (net.exe, PowerView, SharpHound, enum4linux, rpcclient) drives. See samr.hpp's own file
// header comment for the full OPNUM COVERAGE breakdown this harness drives every entry of.
//
// Calls try_parse_samr_request/try_parse_samr_response directly on the raw fuzzer bytes as the
// `stub` ByteSpan (the DCE/RPC PDU envelope is already stripped by the time smb.cpp reaches these
// entry points -- see samr.hpp's own doc comment and fuzz_netlogon.cpp's identical note; dcerpc.hpp's
// own envelope framing is fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's
// own samr_opnum_name_raw table names (samr.cpp) -- SamrConnect(0)/SamrClose(1)/SamrOpenDomain(7)/
// SamrEnumerateUsersInDomain(13)/SamrEnumerateAliasesInDomain(15)/SamrGetAliasMembership(16)/
// SamrLookupNamesInDomain(17)/SamrLookupIdsInDomain(18)/SamrOpenGroup(19)/SamrOpenAlias(27)/
// SamrOpenUser(34)/SamrSetInformationUser(37)/SamrChangePasswordUser(38)/
// SamrOemChangePasswordUser2(54)/SamrConnect2(57)/SamrConnect4(62)/SamrConnect5(64) -- both request
// and response for each, and sealed={true,false} for each of those, exercising this file's own full-
// decode tier (the SamrLookupNamesInDomain/SamrLookupIdsInDomain RID<->name pair, the four-variant
// SamrConnect family, SamrEnumerateUsersInDomain/SamrEnumerateAliasesInDomain/
// SamrGetAliasMembership), header-only tier (SamrOpenDomain's DomainId SID / SamrOpenUser/OpenAlias/
// OpenGroup's target RID), and the fully-silent credential-material tier
// (SamrChangePasswordUser/SamrOemChangePasswordUser2/SamrSetInformationUser, which this file never
// even attempts to parse) -- the same "loop over a small set of representative values against the
// same input" shape fuzz_mqtt.cpp's own session_version_hint loop establishes, scaled to this file's
// own opnum table (see this harness's own entry in fuzz/README.md for why this reaches far more
// distinct opnum-specific code paths per input than a typical harness here). `call_id` is fixed at 1
// throughout -- see try_parse_samr_request's own doc comment (samr.hpp): it is copied straight
// through to SamrCall::call_id, a pure caller-side correlation label this file's own field decode
// never itself branches on.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/samr.hpp"

namespace {
constexpr uint16_t kOpnums[] = {0, 1, 7, 13, 15, 16, 17, 18, 19, 27, 34, 37, 38, 54, 57, 62, 64};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_samr_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_samr_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
