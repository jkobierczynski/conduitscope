// SPDX-License-Identifier: Apache-2.0
// fuzz_dcom.cpp - libFuzzer harness for structural DCOM activation/OXID-resolution recognition
// (dcom.hpp), riding raw DCE/RPC directly over TCP/135 -- the last phase of the Windows RPC/
// remote-management batch (see dcom.hpp's own file header comment for the full REDUCED SCOPE/
// TRANSPORT/STATE rationale). Unlike every earlier interface in that batch (SAMR/LSARPC/SRVSVC/
// WKSSVC/DRSUAPI), DCOM activation traffic is NOT SMB-wrapped: it is raw DCE/RPC-over-TCP framing
// straight off the wire, so this harness -- like fuzz_cotp_s7comm's own two-stage framing/
// application shape -- needs no Ethernet/IPv4/TCP unwrapping of its own, just dcom.hpp's own entry
// point on the raw TCP payload.
//
// TWO-STAGE SHAPE, MIRRORING COTP+S7COMM: dcom.hpp does not parse its own PDU envelope -- it reuses
// dcerpc.hpp's interface-agnostic parse_dcerpc_chain() completely unchanged (see dcom.hpp's own
// TRANSPORT section: "this file adds no PDU-envelope parsing of its own") and layers its own
// interface-name/opnum recognition (dcom_interface_name_for_uuid/dcom_opnum_name) and bind/bind_ack/
// request/response bookkeeping (DcomFlowState) on top, exactly the "generic DCE/RPC framing first,
// protocol-specific interface-opnum logic on top" split cotp.hpp/s7comm.hpp establish for TPKT/COTP
// and S7comm. try_parse_dcom(payload, state) is the single public entry point that does both stages
// in one call (it invokes parse_dcerpc_chain() internally, then walks bind/bind_ack/request/response
// PDUs against `state`) -- there is no separate "framing-only" free function to call first the way
// fuzz_cotp_s7comm.cpp's try_parse_tpkt_cotp/try_parse_s7comm split requires, since dcerpc.hpp's own
// parse_dcerpc_chain has no dedicated fuzz harness of its own (it has no OT/ICS-specific hand-rolled
// state beyond ordinary DCE/RPC PDU-header parsing, unlike every protocol this fuzzing pass targets)
// -- fuzzing try_parse_dcom already exercises parse_dcerpc_chain as a side effect, on every input.
//
// STATE: try_parse_dcom takes a mutable DcomFlowState& (bind/bind_ack/request-response correlation
// -- see dcom.hpp's own STATE section for why this can hold more than one bound interface per
// session, unlike every earlier interface in this batch). A fresh DcomFlowState is constructed for
// every LLVMFuzzerTestOneInput call rather than reused across calls or held static: libFuzzer
// requires a given input to behave deterministically regardless of call order/coverage history, and
// a persistent cross-call session would make DCOM PDUs that only make sense as a bind-then-request
// sequence unreachable from a single mutated input anyway (real multi-PDU sequences are exercised by
// dcom.hpp's own coalescing loop -- more than one PDU in ONE payload already reaches bind->bind_ack->
// request->response wiring within a single call, since parse_dcerpc_chain walks every PDU present in
// one TCP payload back-to-back).
//
// Documented "Never throws" in dcom.hpp's own try_parse_dcom doc comment (each PDU's own stub is
// individually try/catch-wrapped inside dcom.cpp, mirroring decode_dcerpc_and_drsuapi's own per-PDU
// posture) -- still wrapped here in try/catch, the same defensive posture every other harness in
// this codebase takes in case a future edit introduces a throwing code path this comment doesn't yet
// reflect.
//
// Does not cover: any request/response BODY field decode (dcom.hpp deliberately never decodes one --
// see its own REDUCED SCOPE section), or the dynamically negotiated OXID-resolution DATA channel a
// ResolveOxid/ResolveOxid2 call negotiates (never followed by this decoder at all, on any input).
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dcom.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);
    conduitscope::DcomFlowState state;

    try {
        (void)conduitscope::try_parse_dcom(payload, state);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
