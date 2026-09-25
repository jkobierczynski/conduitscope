// SPDX-License-Identifier: Apache-2.0
// fuzz_dcerpc.cpp - libFuzzer harness for the shared, interface-agnostic DCE/RPC (MS-RPCE)
// connection-oriented PDU envelope framing (dcerpc.hpp) -- the layer netlogon.hpp/samr.hpp/
// lsarpc.hpp/srvsvc.hpp/wkssvc.hpp/drsuapi.hpp all ride on top of (see dcerpc.hpp's own file
// header comment for the full split rationale: this file decodes the common header, bind/
// bind_ack/alter_context/alter_context_resp context negotiation, request/response/fault headers,
// and the sec_trailer -- IDENTICAL regardless of which interface is riding inside it -- while each
// interface module owns only its own opnum-level semantics on top).
//
// Calls both public entry points directly on the raw fuzzer bytes, exactly like fuzz_cotp_s7comm's
// own two-call shape:
//   - try_parse_dcerpc: a single PDU starting at byte 0 of its own 16-byte common header.
//   - parse_dcerpc_chain: zero or more PDUs packed back-to-back in one buffer (a single SMB2
//     WRITE/IOCTL/READ body can carry more than one, e.g. a bind immediately followed by a
//     request) -- this is the same self-describing frag_length chain-walk dcom.hpp's own
//     try_parse_dcom builds on (see fuzz_dcom.cpp's own file header comment: "fuzzing try_parse_dcom
//     already exercises parse_dcerpc_chain as a side effect" -- true for DCOM's own bind/request
//     bookkeeping, but this harness is the one that reaches parse_dcerpc_chain SATURATED, with no
//     DCOM-specific interface/opnum filtering downstream of it at all).
// No Ethernet/IPv4/TCP framing needed -- both entry points already take a ByteSpan over exactly
// the bytes an SMB2 WRITE Data buffer (or DCOM's own raw TCP/135 payload) would carry.
//
// Also exercises dcerpc_tcp_declared_length -- the raw-TCP declared-length probe DCOM's own
// tcp_declared_length() uses (dcerpc.hpp's own doc comment: "the raw-TCP mirror of
// smb_tcp_declared_length's role... for interfaces that ride DCE/RPC over a named pipe" -- DCOM
// itself is the one exception that rides it directly), on the same input, for a third independent
// code path over the identical 16-byte common-header prefix logic.
//
// This is the one dedicated harness for dcerpc.hpp's own envelope parsing (see fuzz/README.md's own
// third-wave note on why DCOM needed no separate ninth harness for the AMQP preamble it shares --
// same reasoning inverted here: dcerpc.hpp has no dedicated harness of its own in the DCOM/DRSUAPI-
// adjacent batches that came before this one, so this is genuinely new coverage, not a duplicate of
// fuzz_dcom.cpp's own incidental exercise of parse_dcerpc_chain).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dcerpc.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_dcerpc(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::parse_dcerpc_chain(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome.
    }

    try {
        (void)conduitscope::dcerpc_tcp_declared_length(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome.
    }

    return 0;
}
