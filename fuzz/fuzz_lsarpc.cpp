// SPDX-License-Identifier: Apache-2.0
// fuzz_lsarpc.cpp - libFuzzer harness for LSARPC (MS-LSAD + MS-LSAT) opnum decoding (lsarpc.hpp),
// riding DCE/RPC (dcerpc.hpp) on the \PIPE\lsarpc named pipe -- SID<->name translation and trust-
// domain/account enumeration, the direct complement to SAMR's own RID<->name resolution. See
// lsarpc.hpp's own file header comment for the full OPNUM COVERAGE breakdown this harness drives
// every entry of.
//
// Calls try_parse_lsarpc_request/try_parse_lsarpc_response directly on the raw fuzzer bytes as the
// `stub` ByteSpan (the DCE/RPC PDU envelope is already stripped by the time smb.cpp reaches these
// entry points -- see fuzz_netlogon.cpp's identical note; dcerpc.hpp's own envelope framing is
// fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's own
// lsarpc_opnum_name_raw table names (lsarpc.cpp) -- LsarClose(0)/LsarOpenPolicy(6)/
// LsarQueryInformationPolicy(7)/LsarEnumerateAccounts(11)/LsarEnumerateTrustedDomains(13)/
// LsarLookupNames(14)/LsarLookupSids(15)/LsarOpenPolicy2(44)/LsarEnumerateTrustedDomainsEx(50)/
// LsarLookupSids2(57)/LsarLookupNames2(58)/LsarLookupNames3(68)/LsarLookupSids3(76)/
// LsarLookupNames4(77) -- both request and response for each, and sealed={true,false} for each of
// those, exercising this file's own full-decode tier (LsarLookupNames/LsarLookupSids, the referenced-
// domain-list-behind-an-extra-pointer-indirection wrinkle this file's own header comment flags,
// LsarEnumerateAccounts/LsarEnumerateTrustedDomains), header-only tier (LsarOpenPolicy/OpenPolicy2's
// policy handle, deliberately without its own ObjectAttributes field), and the named-but-unparsed
// tier (the _2/_3/_4 LookupNames/LookupSids variants, LsarEnumerateTrustedDomainsEx, each flagged in
// this file's own header comment as an unverified-shape opnum this file deliberately does not risk
// silently misdecoding) -- the same "loop over a small set of representative values against the same
// input" shape fuzz_mqtt.cpp's own session_version_hint loop establishes, scaled to this file's own
// opnum table (see this harness's own entry in fuzz/README.md for why this reaches far more distinct
// opnum-specific code paths per input than a typical harness here). `call_id` is fixed at 1
// throughout -- see try_parse_samr_request's own doc comment (samr.hpp), which try_parse_lsarpc_
// request's own doc comment (lsarpc.hpp) explicitly shares: a pure caller-side correlation label
// this file's own field decode never itself branches on.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/lsarpc.hpp"

namespace {
constexpr uint16_t kOpnums[] = {0, 6, 7, 11, 13, 14, 15, 44, 50, 57, 58, 68, 76, 77};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_lsarpc_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_lsarpc_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
