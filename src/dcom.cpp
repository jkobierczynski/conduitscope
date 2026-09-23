// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/dcom.hpp"

#include <algorithm>
#include <sstream>

namespace conduitscope {

std::string dcom_interface_name_for_uuid(const std::string& abstract_syntax_uuid) {
    if (abstract_syntax_uuid == kIObjectExporterUuid) return "IObjectExporter";
    if (abstract_syntax_uuid == kIRemoteScmActivatorUuid) return "IRemoteSCMActivator";
    if (abstract_syntax_uuid == kIActivationUuid) return "IActivation";
    return std::string();
}

std::string dcom_opnum_name(const std::string& interface_name, uint16_t opnum) {
    if (interface_name == "IObjectExporter") {
        switch (opnum) {
            case 0: return "ResolveOxid";
            case 1: return "SimplePing";
            case 2: return "ComplexPing";
            case 3: return "ServerAlive";
            case 4: return "ResolveOxid2";
            case 5: return "ServerAlive2";
            default: break;
        }
    } else if (interface_name == "IActivation") {
        if (opnum == 0) return "RemoteActivation";
    } else if (interface_name == "IRemoteSCMActivator") {
        switch (opnum) {
            case 3: return "RemoteGetClassObject";
            case 4: return "RemoteCreateInstance";
            default: break;
        }
    }
    return "opnum " + std::to_string(opnum);
}

namespace {

std::string dcom_call_summary(const DcomCall& call) {
    std::ostringstream s;
    s << call.interface_name << " " << call.opnum_name << (call.is_response ? " response" : " request");
    if (call.sealed) s << " (sealed)";
    return s.str();
}

// Fallback per-PDU summary text for a bind/bind_ack/fault (or any other) PDU that produced no
// DcomCall of its own -- built from whatever this dcom.cpp-local pass learned about it, falling
// back to dcerpc.hpp's own generic DceRpcMessage::summary for anything this file doesn't have a
// more specific description for (fault, an unrecognized PTYPE, ...).
std::string dcom_bind_summary(const DceRpcMessage& dm,
                               const std::vector<std::pair<uint16_t, std::string>>& offered) {
    std::ostringstream s;
    s << "DCOM bind";
    std::vector<std::string> names;
    for (const auto& [context_id, name] : offered) {
        (void)context_id;
        if (!name.empty()) names.push_back(name);
    }
    if (!names.empty()) {
        s << " (candidates:";
        for (size_t i = 0; i < names.size(); ++i) s << (i == 0 ? " " : ", ") << names[i];
        s << ")";
    }
    (void)dm;
    return s.str();
}

std::string dcom_bind_ack_summary(const std::vector<std::string>& bound_this_ack) {
    std::ostringstream s;
    s << "DCOM bind_ack";
    if (!bound_this_ack.empty()) {
        s << " (bound:";
        for (size_t i = 0; i < bound_this_ack.size(); ++i) s << (i == 0 ? " " : ", ") << bound_this_ack[i];
        s << ")";
    }
    return s.str();
}

}  // namespace

std::optional<DcomMessage> try_parse_dcom(ByteSpan payload, DcomFlowState& state) {
    if (payload.empty()) return std::nullopt;
    DcomMessage message;
    message.dcerpc_messages = parse_dcerpc_chain(payload);
    if (message.dcerpc_messages.empty()) return std::nullopt;

    std::vector<std::string> parts;
    parts.reserve(message.dcerpc_messages.size());

    for (const DceRpcMessage& dm : message.dcerpc_messages) {
        try {
            if (dm.has_bind) {
                // Record the FULL ordered context-element list (recognized or not) -- see
                // dcom.hpp's own STATE section for why positional alignment against the eventual
                // bind_ack's own result list requires every offered position, not just the ones
                // this file recognizes.
                std::vector<std::pair<uint16_t, std::string>> offered;
                offered.reserve(dm.bind_contexts.size());
                for (const DceRpcContextElement& ctx_elem : dm.bind_contexts) {
                    offered.emplace_back(ctx_elem.context_id, dcom_interface_name_for_uuid(ctx_elem.abstract_syntax_uuid));
                }
                parts.push_back(dcom_bind_summary(dm, offered));
                state.pending_binds[dm.call_id] = std::move(offered);
                continue;
            }
            if (dm.has_bind_ack) {
                std::vector<std::string> bound_this_ack;
                auto it = state.pending_binds.find(dm.call_id);
                if (it != state.pending_binds.end()) {
                    const std::vector<std::pair<uint16_t, std::string>>& offered = it->second;
                    size_t n = std::min(offered.size(), dm.bind_ack_results.size());
                    for (size_t i = 0; i < n; ++i) {
                        if (dm.bind_ack_results[i].result_name == "acceptance" && !offered[i].second.empty()) {
                            state.bound_interfaces[offered[i].first] = offered[i].second;
                            bound_this_ack.push_back(offered[i].second);
                        }
                    }
                    state.pending_binds.erase(it);
                }
                parts.push_back(dcom_bind_ack_summary(bound_this_ack));
                continue;
            }
            if (dm.has_fault) {
                state.pending_calls.erase(dm.call_id);
                parts.push_back(dm.summary);
                continue;
            }
            if (dm.has_request) {
                auto bit = state.bound_interfaces.find(dm.request_context_id);
                if (bit != state.bound_interfaces.end()) {
                    DcomCall call;
                    call.call_id = dm.call_id;
                    call.context_id = dm.request_context_id;
                    call.interface_name = bit->second;
                    call.opnum = dm.opnum;
                    call.opnum_name = dcom_opnum_name(call.interface_name, call.opnum);
                    call.is_response = false;
                    call.sealed = dm.sealed;
                    call.summary = dcom_call_summary(call);
                    state.pending_calls[dm.call_id] = PendingDceRpcCall{dm.opnum, dm.request_context_id};
                    parts.push_back(call.summary);
                    message.calls.push_back(std::move(call));
                } else {
                    parts.push_back(dm.summary);
                }
                continue;
            }
            if (dm.has_response) {
                auto it = state.pending_calls.find(dm.call_id);
                if (it != state.pending_calls.end()) {
                    uint16_t opnum = it->second.opnum;
                    uint16_t context_id = it->second.context_id;
                    auto bit = state.bound_interfaces.find(context_id);
                    if (bit != state.bound_interfaces.end()) {
                        DcomCall call;
                        call.call_id = dm.call_id;
                        call.context_id = context_id;
                        call.interface_name = bit->second;
                        call.opnum = opnum;
                        call.opnum_name = dcom_opnum_name(call.interface_name, call.opnum);
                        call.is_response = true;
                        call.sealed = dm.sealed;
                        call.summary = dcom_call_summary(call);
                        parts.push_back(call.summary);
                        message.calls.push_back(std::move(call));
                    } else {
                        parts.push_back(dm.summary);
                    }
                    state.pending_calls.erase(it);
                } else {
                    parts.push_back(dm.summary);
                }
                continue;
            }
            // Every other PTYPE (bind_nak, shutdown, ...) -- header-only, this file's own scope
            // never decodes a body for it; fall back to dcerpc.hpp's own generic summary.
            parts.push_back(dm.summary);
        } catch (const ParseError&) {
            // A malformed stub for this one PDU doesn't invalidate the rest of the chain -- same
            // posture decode_dcerpc_and_drsuapi's own loop already establishes (smb.cpp).
            parts.push_back(dm.summary);
        }
    }

    std::ostringstream s;
    for (size_t i = 0; i < parts.size(); ++i) {
        if (i != 0) s << " + ";
        s << parts[i];
    }
    if (parts.size() > 1) s << " (compounded)";
    message.summary = s.str();

    // Curated note 1: DCOM activation/OXID-resolution traffic observed -- fires on every
    // recognized-interface REQUEST (the response carries no opnum of its own on the wire; the
    // request is where the call itself actually happens), same "note on the request, not the
    // response" posture DRSUAPI's own DRSGetNCChanges note already establishes.
    for (const DcomCall& call : message.calls) {
        if (call.is_response) continue;
        message.notes.push_back("DCOM activation/OXID-resolution traffic observed: " + call.interface_name +
                                 " " + call.opnum_name + " (opnum " + std::to_string(call.opnum) + ")");
        // Curated note 2: ResolveOxid/ResolveOxid2's own scope boundary -- stated explicitly rather
        // than silently, see dcom.hpp's own header comment.
        if (call.interface_name == "IObjectExporter" && (call.opnum == 0 || call.opnum == 4)) {
            message.notes.push_back(
                "ResolveOxid/ResolveOxid2 observed -- this decoder does not follow the dynamically "
                "negotiated data-channel port this call resolves for the object's own later method "
                "calls; only this control-channel exchange on TCP/135 is visible here");
        }
    }

    return message;
}

std::optional<ProtocolResult> DcomTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    DcomFlowState& state = ctx.flow_state<DcomFlowState>(FlowStateKeying::Session);
    auto parsed = try_parse_dcom(payload, state);
    if (!parsed) return std::nullopt;
    return ProtocolResult::make(std::string("dcom"), std::move(*parsed));
}

const ProtocolDecoder& dcom_tcp_decoder() {
    static const DcomTcpDecoder instance;
    return instance;
}

}  // namespace conduitscope
