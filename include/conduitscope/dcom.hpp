// SPDX-License-Identifier: Apache-2.0
// dcom.hpp - structural DCOM activation/OXID-resolution recognition, riding DCE/RPC (dcerpc.hpp)
// directly over raw TCP/135 -- phase 5 (the last) of the Windows RPC/remote-management batch
// (SAMR/LSARPC -> SRVSVC/WKSSVC -> DRSUAPI -> WinRM -> WMI/DCOM; see smb.hpp's file header comment
// for the full plan-level context). Named dcom.hpp/"dcom", not wmi.hpp/"wmi": full WMI/CIM query
// visibility deliberately does NOT live here -- see "REDUCED SCOPE" below -- it lives in
// winrm.hpp instead.
//
// ---------------------------------------------------------------------------------------------
// REDUCED SCOPE -- confirmed with Jurgen before this file was written
//
// Full IWbemServices/CIM decode (real `Get-WmiObject`/legacy WMI query visibility) needs OXID
// resolution -- correlating a control-channel exchange on TCP/135 against a SEPARATE data channel
// on a dynamically negotiated port, something no decoder in this codebase attempts anywhere else
// (every existing stateful decoder assumes one statically-portable flow) -- plus COM object-
// reference marshaling and CIM's own generic property-bag type system: the same "large, generic,
// no OT-specific structure" shape that already got OPC Classic declined in docs/DEVELOPMENT.md.
// This file is scoped instead to structural DCOM ACTIVATION recognition only: which of three
// well-known interfaces (below) a session bound to, and which opnum it called -- opnum named,
// never a request/response BODY field decoded. Real CIM/WMI query visibility instead comes from
// winrm.hpp's Phase 4 (`Get-CimInstance`'s modern default transport is WS-Management, not DCOM,
// so that decoder's is_cim_query/wql_filter fields already give the higher-value visibility this
// batch wants for WMI activity) -- this file's job is narrower: naming DCOM activation traffic
// when seen at all, and being honest about what it can't follow past that.
//
// ---------------------------------------------------------------------------------------------
// TRANSPORT -- why this file has its own TCP framing rather than reusing smb.hpp's pipe dispatch
//
// Every earlier interface in this batch (Netlogon/SAMR/LSARPC/SRVSVC/WKSSVC, and DRSUAPI when it
// happens to ride SMB at all -- see drsuapi.hpp's transport-scope caveat) is carried inside an
// already-decoded SMB2 WRITE/READ/IOCTL body, over a named pipe smb.cpp itself tracks. DCOM
// activation traffic is NOT SMB-wrapped: [MS-DCOM] itself specifies TCP/135 (the RPC endpoint
// mapper's well-known port) as where all three interfaces below are reached, directly over raw
// DCE/RPC-over-TCP framing, no named pipe or SMB envelope involved at all. So this file needs its
// own GateKind::TcpPort decoder (DcomTcpDecoder below) and its own declared-length TCP-reassembly
// probe (dcerpc_tcp_declared_length, dcerpc.hpp) -- the raw-TCP mirror of
// smb_tcp_declared_length's role -- rather than plugging into smb.hpp's pipe-state maps the way
// every other RPC interface in this batch does. Port 135 itself IS static and well-known (this is
// NOT the same "dynamically negotiated port" problem DRSUAPI's real-world transport has -- see
// drsuapi.hpp); what IS dynamically negotiated, and explicitly NOT followed by this file, is the
// separate OXID-resolution DATA channel a ResolveOxid/ResolveOxid2 call negotiates -- see
// "DELIBERATELY NOT IMPLEMENTED" below.
//
// dcerpc.hpp's try_parse_dcerpc/parse_dcerpc_chain are reused completely unchanged -- this file
// adds no PDU-envelope parsing of its own, the same "interface-agnostic envelope, interface-
// specific semantics on top" split every other file in this batch already establishes.
//
// ---------------------------------------------------------------------------------------------
// KNOWN INTERFACES -- empirically corrected against the plan's recollected UUID
//
// Three interface UUIDs are named, opnum-only (no request/response BODY field decode at all --
// narrower even than DRSUAPI's structural-only bar, which at least decodes DRSBind's handle/GUID
// fields; here, only WHICH interface and WHICH opnum are ever reported):
//
//   - IObjectExporter    99fcfec4-5260-101b-bbcb-00aa0021347a, version 0.0 -- the OXID Resolver
//     interface (ResolveOxid/ResolveOxid2/SimplePing/ComplexPing/ServerAlive/ServerAlive2).
//     A CRITICAL, EMPIRICALLY-CORRECTED DETAIL: this codebase's original implementation plan
//     recollected this UUID as 99fcfec4-5260-101b-bc6c-04021c009c02 -- THAT VALUE IS WRONG, and was
//     never independently verified before being written into the plan. Corrected two independent
//     ways during this phase's planning, before any code was written: (1) impacket's
//     dcerpc/v5/dcomrt.py hardcodes IID_IObjectExporter = uuidtup_to_bin(('99fcfec4-5260-101b-bbcb-
//     00aa0021347a','0.0')), the exact literal value impacket's real DCOM client code binds
//     against; (2) an independent third-party DCE/RPC interface package (unrelated to impacket) is
//     itself titled/keyed by this same corrected UUID string. The plan's recollected value is used
//     NOWHERE in this file -- only the corrected one below is.
//   - IRemoteSCMActivator 000001a0-0000-0000-c000-000000000046, version 0.0 -- the modern (DCOM 1.0+)
//     remote activation interface (RemoteGetClassObject/RemoteCreateInstance). Matched the plan's
//     recollected value exactly; independently confirmed against impacket's dcomrt.py.
//   - IActivation          4d9f4ab8-7d1c-11cf-861e-0020af6e7c57, version 0.0 -- the legacy (NT4-era)
//     activation interface (RemoteActivation). Matched the plan's recollected value exactly;
//     independently confirmed against impacket's dcomrt.py.
//
// Opnum tables below, verified against impacket's dcerpc/v5/dcomrt.py source (each opnum class
// there cites its own [MS-DCOM] section number in an inline comment, cross-checked against that):
//   IObjectExporter (MS-DCOM 3.1.2.5.1.x):      ResolveOxid=0, SimplePing=1, ComplexPing=2,
//                                                 ServerAlive=3, ResolveOxid2=4, ServerAlive2=5
//   IActivation (MS-DCOM 3.1.2.5.2.3.1):        RemoteActivation=0
//   IRemoteSCMActivator (MS-DCOM 3.1.2.5.2.3.2/.3): RemoteGetClassObject=3, RemoteCreateInstance=4
// Any opnum outside these tables, on a recognized interface, is reported as "opnum N" -- this
// codebase's usual "flag rather than guess" bar (see netlogon.hpp's header comment for the origin
// of that convention).
//
// ---------------------------------------------------------------------------------------------
// STATE -- why this file does NOT use dcerpc.hpp's resolve_dcerpc_bind_bookkeeping template
//
// Every earlier interface in this batch tracks bind->bind_ack bookkeeping for exactly ONE target
// interface per pipe/session (dcerpc.hpp's resolve_dcerpc_bind_bookkeeping<PipeState> template,
// added in Phase 0 specifically to factor that single-target shape out once). DCOM is genuinely
// different: a real DCOM client routinely binds MORE THAN ONE of the three interfaces above on the
// SAME TCP connection at once (e.g. a bind PDU whose context list offers both IRemoteSCMActivator
// and IObjectExporter as separate context elements in one PDU, or two separate bind/alter_context
// PDUs on the same connection each targeting a different interface) -- a session-wide, multi-target
// binding shape the single-target template cannot express. DcomFlowState (below) therefore tracks
// its bind/bind_ack bookkeeping inline, in dcom.cpp, rather than reusing that template:
//   - pending_binds: keyed by call_id, holding the bind PDU's FULL ordered list of (context_id,
//     interface_name_or_empty) pairs -- one entry per context element the bind PDU actually offered,
//     in wire order, regardless of whether its abstract syntax UUID was recognized. This ordered
//     list is what lets the eventual bind_ack be correlated POSITIONALLY: MS-RPCE's bind_ack result
//     list is positionally parallel to the bind's context list (result[i] answers context element
//     i), not keyed by context_id itself -- so bind_ack decoding must walk both lists together, in
//     lockstep, to know which accepted result belongs to which candidate interface. An unrecognized
//     context element still occupies its own position in this list (with an empty interface_name),
//     so the positional alignment against bind_ack's result list stays correct even when a bind PDU
//     mixes known and unknown interfaces in one context list.
//   - bound_interfaces: context_id -> interface_name, populated once bind_ack confirms acceptance
//     for that position -- this is the map a later request/response PDU's request_context_id/
//     response_context_id is looked up against, and it can (unlike every earlier interface's single
//     interface_context_id field) hold more than one entry at once.
//   - pending_calls: call_id -> PendingDceRpcCall (dcerpc.hpp's shared shape, reused as-is here
//     since request/response call_id-keyed pairing IS the same shape regardless of how many
//     interfaces are bound) -- tracks a request PDU awaiting its response/fault, the same way every
//     earlier interface's pipe state does.
// Session-keyed (DecodeContext::FlowStateKeying::Session, not DirectionalFlow) -- bind, bind_ack,
// request, and response can each legitimately travel in either direction of one DCOM TCP session,
// the same "answerable from either direction" reasoning Modbus's/TwinCAT's/MQTT's session-keyed
// state already established (see protocol_decoder.hpp's FlowStateKeying doc comment).
//
// ---------------------------------------------------------------------------------------------
// CURATED NOTES
//   1. DCOM activation/OXID-resolution traffic observed -- fires on every recognized-interface
//      request, naming the interface and the opnum (e.g. "DCOM activation: IRemoteSCMActivator
//      RemoteCreateInstance").
//   2. ResolveOxid/ResolveOxid2 scope boundary -- fires when the opnum is ResolveOxid (0) or
//      ResolveOxid2 (4) on IObjectExporter, stating explicitly that the dynamic data-channel port
//      this call negotiates for the OBJECT's later method calls is NOT followed by this decoder --
//      a stated scope boundary, not a silent gap, the same posture DRSUAPI's DRS_EXTENSIONS-
//      skipping and WinRM's PSRP-recognized-but-not-decoded note already establish elsewhere in
//      this batch.
//
// ---------------------------------------------------------------------------------------------
// COLLISION SURVEY: port 135 has no pre-existing recognition anywhere in this codebase (confirmed
// by grep across it_protocols.hpp/it_protocols.cpp/notable_it_protocols.hpp/notable_it_protocols.cpp
// before this file was written -- zero matches for "135") -- unlike WinRM's genuine collision with
// Tier 2's generic "http" recognition, DCOM activation traffic has no existing recognizer to
// collide with at all, so no fix (only ordinary GateKind::TcpPort port-gating in Auto mode, the
// same posture DoH/WinRM already established for this gate kind) is needed here.
//
// DELIBERATELY NOT IMPLEMENTED:
//   - The OXID-resolution data channel ResolveOxid/ResolveOxid2 negotiates (see curated note 2
//     above) -- this decoder never follows a dynamically negotiated port to a second flow.
//   - Any request/response BODY field decode for any of the three interfaces' opnums (contrast
//     DRSUAPI's DRSBind handle/GUID decode) -- see "REDUCED SCOPE" above for why.
//   - Full IWbemServices/CIM query decode -- see "REDUCED SCOPE" above; real CIM/WMI query
//     visibility lives in winrm.hpp instead.
//   - COM object reference (OBJREF/MInterfacePointer) marshaling -- this file never looks past the
//     DCE/RPC stub boundary at all, so no OBJREF this codebase might see is ever parsed.
#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dcerpc.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// TCP port 135 -- the DCE/RPC endpoint mapper's well-known port, where all three known interfaces
// are reached (see TRANSPORT section above).
constexpr uint16_t DCOM_PORT = 135;

// The three interface UUIDs this file recognizes -- see KNOWN INTERFACES above for the empirical
// corrections and cross-checks behind each value. Compared as plain strings against
// DceRpcContextElement::abstract_syntax_uuid (dcerpc.hpp), which is already rendered lowercase.
constexpr const char* kIObjectExporterUuid = "99fcfec4-5260-101b-bbcb-00aa0021347a";
constexpr const char* kIRemoteScmActivatorUuid = "000001a0-0000-0000-c000-000000000046";
constexpr const char* kIActivationUuid = "4d9f4ab8-7d1c-11cf-861e-0020af6e7c57";

// Returns "IObjectExporter"/"IRemoteSCMActivator"/"IActivation" for a recognized abstract syntax
// UUID (case-insensitive-safe since dcerpc.hpp always renders lowercase; compared as-is), or an
// empty string for any other UUID -- mirrors is_drsuapi_interface_uuid's shape (drsuapi.hpp) but
// returns the NAME directly (rather than a bool) since DcomFlowState needs to remember which of
// three interfaces a context bound to, not just whether it recognized one at all.
std::string dcom_interface_name_for_uuid(const std::string& abstract_syntax_uuid);

// Returns the curated opnum name for `interface_name`+`opnum` (e.g. "ResolveOxid2"), or
// "opnum N" if that combination isn't one of the six (IObjectExporter) / one (IActivation) / two
// (IRemoteSCMActivator) values KNOWN INTERFACES above names -- see drsuapi_opnum_name's doc
// comment (drsuapi.hpp) for the shared "never guess" convention.
std::string dcom_opnum_name(const std::string& interface_name, uint16_t opnum);

// One decoded, structural-only DCOM activation call -- see DrsuapiCall's doc comment (drsuapi.hpp)
// for the shared "fields not meaningful for this call left at default" convention. Deliberately
// carries NO request/response body fields of any kind -- see REDUCED SCOPE above for why.
struct DcomCall {
    uint32_t call_id = 0;
    uint16_t context_id = 0;
    std::string interface_name;  // "IObjectExporter" / "IRemoteSCMActivator" / "IActivation"
    uint16_t opnum = 0;
    std::string opnum_name;
    bool is_response = false;
    bool sealed = false;

    std::string summary;
};

// One decoded raw-TCP DCE/RPC message on port 135 -- may carry zero or more DcomCall entries (a
// single reassembled TCP payload can hold more than one PDU back-to-back, e.g. a bind immediately
// followed by a request -- see dcerpc.hpp's dcerpc_tcp_declared_length doc comment) plus whatever
// bind/bind_ack/fault bookkeeping produced no call. Every PDU present is walked via dcerpc.hpp's
// parse_dcerpc_chain; only request/response PDUs on a context bound to one of this file's three
// known interfaces become a DcomCall.
struct DcomMessage {
    std::vector<DceRpcMessage> dcerpc_messages;  // every PDU parsed from this payload, unfiltered --
                                                   // mirrors SmbMessage::dcerpc_messages' role
    std::vector<DcomCall> calls;

    std::string summary;   // built via the same " + "/" (compounded)" join SmbFrame::summary uses
    std::vector<std::string> notes;
};

// Cross-packet DCOM bind/bind_ack/request-response correlation state for one TCP session -- see
// the STATE section above for the full design and why it doesn't reuse dcerpc.hpp's
// resolve_dcerpc_bind_bookkeeping template. Session-keyed (DecodeContext::FlowStateKeying::Session)
// -- see STATE above for why.
class DcomFlowState : public DecoderFlowState {
public:
    // Bind PDU's full ordered context-element list, call_id-keyed, awaiting its bind_ack -- see
    // STATE above for why the full list (not just recognized entries) is needed to correlate
    // positionally against bind_ack's result list.
    std::unordered_map<uint32_t, std::vector<std::pair<uint16_t, std::string>>> pending_binds;

    // context_id -> interface_name, populated once bind_ack confirms acceptance for that position.
    // Can hold more than one entry at once for a multi-interface DCOM session -- see STATE above.
    std::unordered_map<uint16_t, std::string> bound_interfaces;

    // call_id -> outstanding request awaiting its response/fault (dcerpc.hpp's shared
    // PendingDceRpcCall shape, same as every earlier interface's pipe state).
    std::unordered_map<uint32_t, PendingDceRpcCall> pending_calls;
};

// Decodes one raw-TCP payload on port 135 -- the caller (DcomTcpDecoder::decode) has already sized
// this payload against dcerpc_tcp_declared_length via decoder.cpp's TCP reassembly cascade. Never
// throws (a malformed individual PDU's stub is simply skipped, the same per-PDU try/catch posture
// decode_dcerpc_and_drsuapi's loop already establishes); returns std::nullopt only when payload is
// empty or parse_dcerpc_chain finds no PDU in it at all.
std::optional<DcomMessage> try_parse_dcom(ByteSpan payload, DcomFlowState& state);

// DCOM activation over TCP/135 -- id()=="dcom", GateKind::TcpPort (port-gated in Auto mode, the
// same posture DoH/WinRM already establish for this gate kind -- see protocol_decoder.hpp's
// comment on TcpPort and the COLLISION SURVEY section above). Session-scoped state (DcomFlowState
// above), unlike WinRmTcpDecoder's stateless design -- ctx.flow_state<DcomFlowState>(
// FlowStateKeying::Session) is looked up once per decode() call.
class DcomTcpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "dcom"; }
    GateKind gate_kind() const override { return GateKind::TcpPort; }
    std::optional<uint16_t> tcp_port() const override { return DCOM_PORT; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return dcerpc_tcp_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& dcom_tcp_decoder();

}  // namespace conduitscope
