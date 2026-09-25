// SPDX-License-Identifier: Apache-2.0
// fuzz_netlogon.cpp - libFuzzer harness for Netlogon (MS-NRPC) opnum decoding (netlogon.hpp), riding
// DCE/RPC (dcerpc.hpp) on the \PIPE\netlogon named pipe -- the interface CVE-2020-1472 ("Zerologon")
// lives on. See netlogon.hpp's own file header comment for the full OPNUM COVERAGE breakdown this
// harness drives every entry of.
//
// Calls try_parse_netlogon_request/try_parse_netlogon_response directly on the raw fuzzer bytes as
// the `stub` ByteSpan (dcerpc.hpp's own DCE/RPC PDU envelope has already been stripped by the time
// smb.cpp reaches these entry points -- see netlogon.hpp's own doc comment: `stub` is "the request
// PDU's own stub bytes ... re-sliced by the caller", not raw TCP/SMB bytes -- dcerpc.hpp's own
// envelope framing is fuzzed separately by fuzz_dcerpc.cpp), looped over EVERY opnum this file's own
// netlogon_opnum_name_raw table names (netlogon.cpp) -- NetrLogonUasLogon(0)/NetrLogonUasLogoff(1)/
// NetrLogonSamLogon(2)/NetrServerReqChallenge(4)/NetrServerAuthenticate(5)/NetrServerPasswordSet(6)/
// NetrServerAuthenticate2(15)/NetrLogonGetCapabilities(21)/NetrServerAuthenticate3(26)/
// NetrLogonGetDomainInfo(29)/NetrServerPasswordSet2(30)/NetrServerPasswordGet(31)/
// NetrLogonSamLogonEx(39)/NetrServerTrustPasswordsGet(42)/NetrLogonSamLogonWithFlags(45)/
// NetrServerAuthenticateKerberos(59) -- both BOTH request and response for each, and sealed={true,
// false} for each of those, so a single fuzzer input reaches every full-decode/header-only opnum
// path (NetrServerReqChallenge/NetrServerAuthenticate family fully, NetrServerPasswordSet2's own
// header-only tier, curated note 2's Zerologon all-zero-credential pattern check) as well as every
// structural-only opnum's fallback path, all against the SAME mutated bytes -- the same "loop over a
// small set of representative values against the same input" shape fuzz_mqtt.cpp's own
// session_version_hint loop and fuzz_opcua.cpp's own redact loop already establish, scaled up to
// this file's own much larger opnum table (see this file's own header comment in the repo's
// fuzz/README.md entry for why this reaches far more distinct opnum-specific code paths per input
// than a typical harness here). `call_id` is fixed at 1 throughout: netlogon.hpp's own
// try_parse_netlogon_request/_response doc comments make clear call_id is copied straight through to
// NetlogonCall::call_id and never itself branches on -- it is a pure correlation label consumed by a
// caller wiring request/response pairs together (smb.cpp), not read by this file's own field decode
// at all.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/netlogon.hpp"

namespace {
constexpr uint16_t kOpnums[] = {0, 1, 2, 4, 5, 6, 15, 21, 26, 29, 30, 31, 39, 42, 45, 59};
constexpr uint32_t kCallId = 1;
}  // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan stub(data, size);

    for (uint16_t opnum : kOpnums) {
        for (bool sealed : {false, true}) {
            try {
                (void)conduitscope::try_parse_netlogon_request(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
            }
            try {
                (void)conduitscope::try_parse_netlogon_response(kCallId, opnum, sealed, stub);
            } catch (const conduitscope::ParseError&) {
                // Expected, handled outcome.
            }
        }
    }

    return 0;
}
