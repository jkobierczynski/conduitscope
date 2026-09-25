// SPDX-License-Identifier: Apache-2.0
// fuzz_winrm.cpp - libFuzzer harness for WinRM (WS-Management over plaintext HTTP/1.1, TCP port
// 5985), winrm.hpp: this codebase first hand-rolled HTTP/SOAP parser. Two layers of hand-rolled
// state machine are exercised by one entry point: an HTTP/1.1 start-line plus header-block parser
// (method/target or status/reason, Content-Type, Transfer-Encoding, Content-Length, Authorization/
// WWW-Authenticate scheme extraction) feeding a SOAP/WS-Man envelope walk on top when the body is
// application/soap+xml (Action URI, ResourceURI, CIM/PSRP resource-path recognition, ShellId/
// CommandId, CommandLine Command+Arguments XML-unescaping, a WQL Filter element own text, a SOAP
// Fault Reason/Text) -- exactly the kind of layered, hand-rolled framing-then-application parsing
// this fuzzing pass targets, and genuinely different in shape from every binary protocol the first
// two fuzzing waves cover.
//
// ONE ENTRY POINT, BOTH REQUEST AND RESPONSE: unlike s7comm_plus own distinct
// framing-then-application two-call shape, WinRM handles both directions through a single function
// -- try_parse_winrm_http(message, redact) -- since an HTTP message start-line already
// self-identifies as a request (method + target) or a response (status code + reason) with no
// separate framing stage needed first; this mirrors decoder.cpp own call shape exactly (see
// WinRmTcpDecoder::decode, winrm.cpp), which calls this same function directly on the raw TCP
// payload with no further unwrapping.
//
// REDACT CALLED BOTH WAYS: `redact` gates whether CommandLine own text is replaced with the
// redaction placeholder, both in the returned field and in every summary/notes string it would
// otherwise appear in (redact_secret_occurrences, protocol_decoder.hpp) -- real production code
// always passes ctx.redact_secrets (true by default), but that string-replacement logic is itself
// real, fuzzable code, not just a flag read once, so this harness calls try_parse_winrm_http twice
// against the very same input, once with redact=true and once redact=false, to reach both paths
// through the same coverage-guided mutation, for free, the same "one input, more than one call"
// shape fuzz_enip.cpp own header comment establishes for its own two entry points.
//
// Documented as never throwing (returns std::nullopt on a structural mismatch) in
// try_parse_winrm_http own doc comment -- still wrapped in try/catch below, the same defensive
// posture every harness in this suite takes in case a future edit introduces a throwing code path
// this comment does not yet reflect.
//
// Does not cover: TCP-segment-split HTTP messages (winrm_tcp_declared_length own Content-Length-
// bounded reassembly, which needs Decoder::reassemble_tcp_payload and a live flow) -- that
// multi-packet path is covered by fuzz_packet_decode instead. Port 5986 (TLS-wrapped WinRM) is out
// of scope for this whole decoder, per winrm.hpp own file header, and therefore out of scope here
// too.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/winrm.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_winrm_http(payload, /*redact=*/true);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    try {
        (void)conduitscope::try_parse_winrm_http(payload, /*redact=*/false);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome, see fuzz_dnp3.cpp identical comment.
    }

    return 0;
}
