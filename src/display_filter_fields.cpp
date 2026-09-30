// SPDX-License-Identifier: Apache-2.0
// display_filter_fields.cpp - the field registry backing display_filter.hpp's FieldRegistry:
// dotted field name -> typed extractor over a DecodedPacket, for universal eth/ip/tcp/udp fields
// plus the curated 13-protocol batch (Modbus, S7comm, S7comm-Plus, DNP3, EtherNet/IP, BACnet,
// IEC104, GOOSE, SV, HART-IP, OPC UA, MMS, UMAS) -- see display_filter.hpp's own file header
// comment for the full scope statement. Organized by protocol section, one register_X_fields()
// function per protocol, mirroring output.cpp's own per-protocol write_X_json_fields
// organization as a style model (not reused/refactored -- this file has its own, independent
// dispatch).
//
// UMAS is a special case: unlike the other twelve curated protocols, it is not a top-level
// DecodedPacket::protocol value at all -- it is Schneider's own protocol riding as a Modbus/TCP
// function-code-0x5A sub-frame, decoded into ModbusFrame::umas (see modbus.hpp/umas.hpp). Its
// fields are registered here as "umas.*", but gated on dp.protocol == "modbus" and
// ModbusFrame::umas having a value, not on a (nonexistent) dp.protocol == "umas". A bare `umas`
// existence test (no dot) therefore isn't registered as a protocol name -- it would never match --
// but `umas.function_code` alone (a dotted field-existence test) works correctly as "this packet
// carries a UMAS sub-frame", since Exists on a dotted name just checks the extractor returns a
// value. See docs/USER_GUIDE.md's Display filters subsection for this caveat stated plainly.
#include "conduitscope/display_filter.hpp"

#include "conduitscope/bacnet.hpp"
#include "conduitscope/decoder.hpp"
#include "conduitscope/dnp3.hpp"
#include "conduitscope/enip.hpp"
#include "conduitscope/goose.hpp"
#include "conduitscope/hartip.hpp"
#include "conduitscope/iec104.hpp"
#include "conduitscope/mms.hpp"
#include "conduitscope/modbus.hpp"
#include "conduitscope/opcua.hpp"
#include "conduitscope/protocol_decoder.hpp"
#include "conduitscope/s7comm.hpp"
#include "conduitscope/s7commplus.hpp"
#include "conduitscope/sv.hpp"
#include "conduitscope/umas.hpp"

namespace conduitscope {

const FieldExtractor* FieldRegistry::lookup(const std::string& dotted_name) const {
    auto it = fields_.find(dotted_name);
    return it == fields_.end() ? nullptr : &it->second;
}

FilterValueKind FieldRegistry::kind_of(const std::string& dotted_name) const {
    auto it = kinds_.find(dotted_name);
    return it == kinds_.end() ? FilterValueKind::String : it->second;
}

bool FieldRegistry::is_bare_protocol_name(const std::string& name) const {
    return protocol_names_.count(name) != 0;
}

void FieldRegistry::register_field(const std::string& dotted_name, FilterValueKind kind, FieldExtractor extractor) {
    fields_[dotted_name] = std::move(extractor);
    kinds_[dotted_name] = kind;
}

void FieldRegistry::register_protocol_name(const std::string& name) {
    protocol_names_.insert(name);
}

namespace {

void register_universal_fields(FieldRegistry& reg) {
    reg.register_field("eth.src", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ethernet) return std::nullopt;
        return FilterValue::make_string(dp.src_mac);
    });
    reg.register_field("eth.dst", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ethernet) return std::nullopt;
        return FilterValue::make_string(dp.dst_mac);
    });
    reg.register_field("vlan.id", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_vlan_tag) return std::nullopt;
        return FilterValue::make_int(dp.vlan_id);
    });
    reg.register_field("ip.src", FilterValueKind::Ip, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ip) return std::nullopt;
        return FilterValue::make_ip(dp.src_ip);
    });
    reg.register_field("ip.dst", FilterValueKind::Ip, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ip) return std::nullopt;
        return FilterValue::make_ip(dp.dst_ip);
    });
    reg.register_field("ip.proto", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ip) return std::nullopt;
        return FilterValue::make_int(dp.ip_protocol);
    });
    reg.register_field("ip.ttl", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_ip) return std::nullopt;
        return FilterValue::make_int(dp.ttl);
    });
    reg.register_field("tcp.srcport", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_tcp) return std::nullopt;
        return FilterValue::make_int(dp.src_port);
    });
    reg.register_field("tcp.dstport", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_tcp) return std::nullopt;
        return FilterValue::make_int(dp.dst_port);
    });
    reg.register_field("tcp.flags", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_tcp) return std::nullopt;
        return FilterValue::make_string(dp.tcp_flags);
    });
    reg.register_field("udp.srcport", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_udp) return std::nullopt;
        return FilterValue::make_int(dp.src_port);
    });
    reg.register_field("udp.dstport", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (!dp.has_udp) return std::nullopt;
        return FilterValue::make_int(dp.dst_port);
    });
}

void register_modbus_fields(FieldRegistry& reg) {
    reg.register_protocol_name("modbus");
    reg.register_field("modbus.func_code", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "modbus" || !dp.result) return std::nullopt;
        return FilterValue::make_int(dp.result->as<ModbusFrame>().function_code);
    });
    reg.register_field("modbus.func_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "modbus" || !dp.result) return std::nullopt;
        return FilterValue::make_string(dp.result->as<ModbusFrame>().function_name);
    });
    reg.register_field("modbus.exception", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "modbus" || !dp.result) return std::nullopt;
        return FilterValue::make_bool(dp.result->as<ModbusFrame>().is_exception);
    });
    // UMAS -- see this file's own header comment for why this is gated on dp.protocol == "modbus"
    // rather than a (nonexistent) dp.protocol == "umas".
    reg.register_field("umas.function_code", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "modbus" || !dp.result) return std::nullopt;
        const auto& mb = dp.result->as<ModbusFrame>();
        if (!mb.umas || mb.umas->is_response) return std::nullopt;  // function_code is only
                                                                      // meaningful on the request
                                                                      // side -- see UmasFrame's own
                                                                      // comment in umas.hpp
        return FilterValue::make_int(mb.umas->function_code);
    });
    reg.register_field("umas.is_response", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "modbus" || !dp.result) return std::nullopt;
        const auto& mb = dp.result->as<ModbusFrame>();
        if (!mb.umas) return std::nullopt;
        return FilterValue::make_bool(mb.umas->is_response);
    });
}

void register_s7comm_fields(FieldRegistry& reg) {
    reg.register_protocol_name("s7comm");
    reg.register_field("s7comm.param.func", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<S7CommResult>();
        if (!r.has_function) return std::nullopt;
        return FilterValue::make_int(r.function_code);
    });
    reg.register_field("s7comm.func_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<S7CommResult>();
        if (!r.has_function) return std::nullopt;
        return FilterValue::make_string(r.function_name);
    });
    reg.register_field("s7comm.plc_stop", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm" || !dp.result) return std::nullopt;
        return FilterValue::make_bool(!dp.result->as<S7CommResult>().plc_stop_message.empty());
    });
}

void register_s7commplus_fields(FieldRegistry& reg) {
    reg.register_protocol_name("s7comm-plus");
    reg.register_field("s7commplus.opcode", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm-plus" || !dp.result) return std::nullopt;
        return FilterValue::make_int(dp.result->as<S7CommPlusFrame>().opcode);
    });
    reg.register_field("s7commplus.function", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm-plus" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<S7CommPlusFrame>();
        if (!f.has_function) return std::nullopt;
        return FilterValue::make_int(f.function_code);
    });
    reg.register_field("s7commplus.function_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "s7comm-plus" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<S7CommPlusFrame>();
        if (!f.has_function) return std::nullopt;
        return FilterValue::make_string(f.function_name);
    });
}

void register_dnp3_fields(FieldRegistry& reg) {
    reg.register_protocol_name("dnp3");
    reg.register_field("dnp3.function", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "dnp3" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<Dnp3Result>();
        if (!r.dnp3_has_function) return std::nullopt;
        return FilterValue::make_int(r.dnp3_function_code);
    });
    reg.register_field("dnp3.function_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "dnp3" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<Dnp3Result>();
        if (!r.dnp3_has_function) return std::nullopt;
        return FilterValue::make_string(r.dnp3_function_name);
    });
}

void register_enip_fields(FieldRegistry& reg) {
    reg.register_protocol_name("enip");
    reg.register_field("enip.service", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "enip" || !dp.result || !dp.has_tcp) return std::nullopt;
        const auto& ef = dp.result->as<EnipResult>().first;
        if (!ef.has_cip) return std::nullopt;
        return FilterValue::make_int(ef.cip.service);
    });
    reg.register_field("enip.service_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "enip" || !dp.result || !dp.has_tcp) return std::nullopt;
        const auto& ef = dp.result->as<EnipResult>().first;
        if (!ef.has_cip) return std::nullopt;
        return FilterValue::make_string(ef.cip.service_name);
    });
    reg.register_field("enip.is_io", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "enip") return std::nullopt;
        // CIP I/O (implicit messaging) always runs on UDP, explicit messaging always on TCP -- see
        // EnipTcpDecoder/EnipUdpDecoder's own gate_kind()s in enip.hpp.
        return FilterValue::make_bool(dp.has_udp);
    });
}

void register_bacnet_fields(FieldRegistry& reg) {
    reg.register_protocol_name("bacnet");
    reg.register_field("bacnet.service", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "bacnet" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<BacnetFrame>();
        if (!f.has_npdu || !f.npdu.has_apdu || !f.npdu.apdu.has_service_choice) return std::nullopt;
        return FilterValue::make_int(f.npdu.apdu.service_choice);
    });
    reg.register_field("bacnet.service_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "bacnet" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<BacnetFrame>();
        if (!f.has_npdu || !f.npdu.has_apdu || !f.npdu.apdu.has_service_choice) return std::nullopt;
        return FilterValue::make_string(f.npdu.apdu.service_choice_name);
    });
}

void register_iec104_fields(FieldRegistry& reg) {
    reg.register_protocol_name("iec104");
    reg.register_field("iec104.type_id", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "iec104" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<Iec104Result>();
        if (!r.iec104_has_asdu) return std::nullopt;
        return FilterValue::make_int(r.iec104_asdu_type_id);
    });
    reg.register_field("iec104.cot", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "iec104" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<Iec104Result>();
        if (!r.iec104_has_asdu) return std::nullopt;
        return FilterValue::make_string(r.iec104_cot_name);
    });
    reg.register_field("iec104.common_addr", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "iec104" || !dp.result) return std::nullopt;
        const auto& r = dp.result->as<Iec104Result>();
        if (!r.iec104_has_asdu) return std::nullopt;
        return FilterValue::make_int(r.iec104_common_address);
    });
}

void register_goose_fields(FieldRegistry& reg) {
    reg.register_protocol_name("goose");
    reg.register_field("goose.simulation", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "goose" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<GooseFrame>();
        if (!f.has_pdu || !f.simulation.has_value()) return std::nullopt;
        return FilterValue::make_bool(*f.simulation);
    });
    reg.register_field("goose.st_num", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "goose" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<GooseFrame>();
        if (!f.has_pdu) return std::nullopt;
        return FilterValue::make_int(static_cast<int64_t>(f.st_num));
    });
    reg.register_field("goose.sq_num", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "goose" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<GooseFrame>();
        if (!f.has_pdu) return std::nullopt;
        return FilterValue::make_int(static_cast<int64_t>(f.sq_num));
    });
}

void register_sv_fields(FieldRegistry& reg) {
    reg.register_protocol_name("sv");
    reg.register_field("sv.appid", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "sv" || !dp.result) return std::nullopt;
        return FilterValue::make_int(dp.result->as<SvFrame>().appid);
    });
    reg.register_field("sv.svid", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "sv" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<SvFrame>();
        if (f.asdus.empty()) return std::nullopt;
        return FilterValue::make_string(f.asdus.front().sv_id);
    });
    reg.register_field("sv.smp_cnt", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "sv" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<SvFrame>();
        if (f.asdus.empty()) return std::nullopt;
        return FilterValue::make_int(static_cast<int64_t>(f.asdus.front().smp_cnt));
    });
}

void register_hartip_fields(FieldRegistry& reg) {
    reg.register_protocol_name("hartip");
    reg.register_field("hartip.command", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "hartip" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<HartIpResult>().first;
        if (!f.has_pass_through) return std::nullopt;
        return FilterValue::make_int(f.pass_through.command);
    });
    reg.register_field("hartip.command_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "hartip" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<HartIpResult>().first;
        if (!f.has_pass_through || !f.pass_through.command_recognized) return std::nullopt;
        return FilterValue::make_string(f.pass_through.command_name);
    });
    reg.register_field("hartip.is_response", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "hartip" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<HartIpResult>().first;
        if (!f.has_pass_through) return std::nullopt;
        return FilterValue::make_bool(f.pass_through.is_response);
    });
}

void register_opcua_fields(FieldRegistry& reg) {
    reg.register_protocol_name("opcua");
    reg.register_field("opcua.service_type", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "opcua" || !dp.result) return std::nullopt;
        const auto& m = dp.result->as<OpcUaResult>().first;
        if (!m.service_recognized) return std::nullopt;
        return FilterValue::make_int(static_cast<int64_t>(m.service_type_id));
    });
    reg.register_field("opcua.service_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "opcua" || !dp.result) return std::nullopt;
        const auto& m = dp.result->as<OpcUaResult>().first;
        if (!m.service_recognized) return std::nullopt;
        return FilterValue::make_string(m.service_name);
    });
    reg.register_field("opcua.message_type", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "opcua" || !dp.result) return std::nullopt;
        return FilterValue::make_string(dp.result->as<OpcUaResult>().first.message_type);
    });
}

void register_mms_fields(FieldRegistry& reg) {
    reg.register_protocol_name("mms");
    reg.register_field("mms.service_tag", FilterValueKind::Int, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "mms" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<MmsFrame>();
        if (!f.service_recognized) return std::nullopt;
        return FilterValue::make_int(static_cast<int64_t>(f.service_tag));
    });
    reg.register_field("mms.service_name", FilterValueKind::String, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "mms" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<MmsFrame>();
        if (!f.service_recognized) return std::nullopt;
        return FilterValue::make_string(f.service_name);
    });
    reg.register_field("mms.is_response", FilterValueKind::Bool, [](const DecodedPacket& dp) -> std::optional<FilterValue> {
        if (dp.protocol != "mms" || !dp.result) return std::nullopt;
        const auto& f = dp.result->as<MmsFrame>();
        if (!f.has_pdu) return std::nullopt;
        return FilterValue::make_bool(f.is_response);
    });
}

}  // namespace

const FieldRegistry& FieldRegistry::instance() {
    static const FieldRegistry* registry = [] {
        auto* r = new FieldRegistry();
        register_universal_fields(*r);
        register_modbus_fields(*r);
        register_s7comm_fields(*r);
        register_s7commplus_fields(*r);
        register_dnp3_fields(*r);
        register_enip_fields(*r);
        register_bacnet_fields(*r);
        register_iec104_fields(*r);
        register_goose_fields(*r);
        register_sv_fields(*r);
        register_hartip_fields(*r);
        register_opcua_fields(*r);
        register_mms_fields(*r);
        return r;
    }();
    return *registry;
}

}  // namespace conduitscope
