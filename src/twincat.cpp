// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/twincat.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

constexpr size_t kAmsTcpHeaderSize = 6;
constexpr size_t kAmsHeaderSize = 32;
constexpr size_t kMinFrameSize = kAmsTcpHeaderSize + kAmsHeaderSize;  // 38

// A real ADS payload realistically never approaches this; guards against a coincidentally
// plausible but wildly large Data Length being mistaken for a genuine frame split across TCP
// segments and buffered forever -- same defense-in-depth posture modbus.cpp's own
// kMaxPlausibleMbapLength takes for Modbus/TCP.
constexpr uint32_t kMaxPlausibleAdsDataLength = 65536;  // 64 KiB

constexpr uint16_t kAdsCommandStateFlag = 0x0004;
constexpr uint16_t kResponseStateFlag = 0x0001;

std::string format_ams_net_id(ByteSpan bytes) {
    std::ostringstream s;
    for (size_t i = 0; i < 6; ++i) {
        if (i != 0) s << ".";
        s << static_cast<unsigned>(bytes.at(i));
    }
    return s.str();
}

// AMS ReadDeviceInfo's DeviceName field is a fixed 16-byte buffer, null-padded ASCII.
std::string trim_null_padded(ByteSpan bytes) {
    std::string s(reinterpret_cast<const char*>(bytes.data()), bytes.size());
    auto pos = s.find('\0');
    if (pos != std::string::npos) s.resize(pos);
    return s;
}

// Decodes the command-specific payload (`body`, exactly `frame`'s AMS Data Length bytes) into
// frame.summary/notes and, for Read/Write/ReadWrite, frame.index_group/index_offset. See
// twincat.hpp's file header comment for each command's wire shape. Never throws -- a payload
// shorter than its command's expected shape is caught (ParseError from the bounds-checked Cursor)
// and reported as a note rather than aborting the whole frame; the AMS header itself (already
// fully decoded by the time this runs) is never in doubt either way.
void decode_payload(TwinCatFrame& frame, TwinCatCommand cmd, bool is_response, ByteSpan body) {
    std::ostringstream summary;
    summary << frame.command_name << " " << (is_response ? "response" : "request");
    try {
        Cursor c(body);
        switch (cmd) {
            case TwinCatCommand::ReadDeviceInfo: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    uint8_t major = c.u8();
                    uint8_t minor = c.u8();
                    uint16_t build = c.u16le();
                    std::string device_name = trim_null_padded(c.bytes(16));
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec << ", version "
                            << static_cast<unsigned>(major) << "." << static_cast<unsigned>(minor)
                            << " build " << build << ", device \"" << device_name << "\"";
                } else {
                    summary << " (no payload)";
                }
                break;
            }
            case TwinCatCommand::Read: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    uint32_t length = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec << ", " << length
                            << " byte(s) of data";
                } else {
                    frame.has_index_addressing = true;
                    frame.index_group = c.u32le();
                    frame.index_offset = c.u32le();
                    uint32_t length = c.u32le();
                    summary << ": group=0x" << std::hex << frame.index_group << " offset=0x"
                            << frame.index_offset << std::dec << ", requesting " << length << " byte(s)";
                }
                break;
            }
            case TwinCatCommand::Write: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec;
                } else {
                    frame.has_index_addressing = true;
                    frame.index_group = c.u32le();
                    frame.index_offset = c.u32le();
                    uint32_t length = c.u32le();
                    summary << ": group=0x" << std::hex << frame.index_group << " offset=0x"
                            << frame.index_offset << std::dec << ", writing " << length << " byte(s)";
                }
                break;
            }
            case TwinCatCommand::ReadWrite: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    uint32_t length = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec << ", " << length
                            << " byte(s) of data";
                } else {
                    frame.has_index_addressing = true;
                    frame.index_group = c.u32le();
                    frame.index_offset = c.u32le();
                    uint32_t read_length = c.u32le();
                    uint32_t write_length = c.u32le();
                    summary << ": group=0x" << std::hex << frame.index_group << " offset=0x"
                            << frame.index_offset << std::dec << ", reading " << read_length
                            << " byte(s), writing " << write_length << " byte(s)";
                }
                break;
            }
            case TwinCatCommand::ReadState: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    uint16_t ads_state = c.u16le();
                    uint16_t device_state = c.u16le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec << ", ADS state "
                            << ads_state << ", device state " << device_state;
                } else {
                    summary << " (no payload)";
                }
                break;
            }
            case TwinCatCommand::WriteControl: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec;
                } else {
                    uint16_t ads_state = c.u16le();
                    uint16_t device_state = c.u16le();
                    uint32_t length = c.u32le();
                    summary << ": requested ADS state " << ads_state << ", device state " << device_state
                            << ", " << length << " byte(s) of associated data";
                }
                break;
            }
            case TwinCatCommand::AddDeviceNotification: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    uint32_t handle = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << " handle=0x" << handle
                            << std::dec;
                } else {
                    frame.has_index_addressing = true;
                    frame.index_group = c.u32le();
                    frame.index_offset = c.u32le();
                    uint32_t length = c.u32le();
                    uint32_t transmission_mode = c.u32le();
                    uint32_t max_delay = c.u32le();
                    uint32_t cycle_time = c.u32le();
                    summary << ": group=0x" << std::hex << frame.index_group << " offset=0x"
                            << frame.index_offset << std::dec << ", " << length << " byte(s), mode "
                            << transmission_mode << ", max delay " << max_delay
                            << " (100ns units), cycle time " << cycle_time << " (100ns units)";
                }
                break;
            }
            case TwinCatCommand::DeleteDeviceNotification: {
                if (is_response) {
                    frame.has_ads_result = true;
                    frame.ads_result = c.u32le();
                    summary << ": result=0x" << std::hex << frame.ads_result << std::dec;
                } else {
                    uint32_t handle = c.u32le();
                    summary << ": handle=0x" << std::hex << handle << std::dec;
                }
                break;
            }
            case TwinCatCommand::DeviceNotification: {
                // Unsolicited push, no Result field at all -- structural decode only (stamp/
                // sample counts), never per-sample values. See twincat.hpp's file header comment
                // for why: a sample's own bytes have no fixed shape without knowing which
                // symbol's data type it represents, which needs ADS symbol-table resolution this
                // pass deliberately leaves for a follow-up.
                uint32_t length = c.u32le();
                uint32_t stamp_count = c.u32le();
                size_t total_samples = 0;
                for (uint32_t i = 0; i < stamp_count && !c.at_end(); ++i) {
                    c.skip(8);  // TimeStamp (Windows FILETIME), not decoded further
                    uint32_t sample_count = c.u32le();
                    total_samples += sample_count;
                    for (uint32_t j = 0; j < sample_count; ++j) {
                        c.skip(4);  // NotificationHandle
                        uint32_t sample_size = c.u32le();
                        c.skip(sample_size);  // raw sample data, not decoded -- see above
                    }
                }
                summary << ": " << length << " byte(s), " << stamp_count << " stamp(s), " << total_samples
                        << " sample(s) total (values not decoded, see twincat.hpp)";
                frame.notes.push_back(
                    "DeviceNotification sample values are not decoded (no symbolic type information "
                    "without ADS symbol-table resolution, deliberately out of scope for this pass -- see "
                    "twincat.hpp's file header comment)");
                break;
            }
        }
    } catch (const ParseError&) {
        summary.str("");
        summary << frame.command_name << " " << (is_response ? "response" : "request")
                << " (payload shorter than this command's expected shape -- not fully decoded)";
        frame.notes.push_back("payload truncated or malformed relative to " + frame.command_name +
                               "'s expected shape; only the AMS header was decoded");
    }
    frame.summary = summary.str();
}

}  // namespace

std::optional<std::string> twincat_command_name(uint16_t command_id) {
    switch (static_cast<TwinCatCommand>(command_id)) {
        case TwinCatCommand::ReadDeviceInfo: return "ReadDeviceInfo";
        case TwinCatCommand::Read: return "Read";
        case TwinCatCommand::Write: return "Write";
        case TwinCatCommand::ReadState: return "ReadState";
        case TwinCatCommand::WriteControl: return "WriteControl";
        case TwinCatCommand::AddDeviceNotification: return "AddDeviceNotification";
        case TwinCatCommand::DeleteDeviceNotification: return "DeleteDeviceNotification";
        case TwinCatCommand::DeviceNotification: return "DeviceNotification";
        case TwinCatCommand::ReadWrite: return "ReadWrite";
    }
    return std::nullopt;
}

std::optional<size_t> twincat_declared_length(ByteSpan payload) {
    // This used to check only the 6-byte AMS/TCP prefix (reserved + Data Length, range-capped at
    // kMaxPlausibleAdsDataLength) -- far weaker than try_parse_twincat's own full structural gate
    // below. That weaker check is a coincidentally-plausible match for a wide range of unrelated
    // TCP traffic (confirmed empirically: it was mis-buffering MQTT, FF-HSE, SMB, TACACS+ and
    // OpenVPN test traffic as candidate AMS/TCP frames, starving their own real dispatch of the
    // bytes it needed). A real AMS/TCP frame's full 32-byte AMS header realistically always
    // arrives in the same TCP segment as its 6-byte prefix (the whole thing is 38 bytes, far under
    // any real MTU), so this now requires the complete header before declaring a length at all,
    // and re-applies the SAME three structural checks try_parse_twincat uses (Data Length
    // cross-check, ADS command state flag, valid Command ID) -- not just the plausibility cap.
    // The cost is that a TwinCAT frame whose 38-byte header is itself split across TCP segments
    // won't be recognized as needing buffering; that is an acceptable, documented gap (the
    // collision this fixes was real and reproducible; that edge case is neither).
    if (payload.size() < kMinFrameSize) return std::nullopt;
    Cursor c(payload);
    c.skip(2);  // reserved
    uint32_t ams_tcp_data_length = c.u32le();
    if (ams_tcp_data_length > kMaxPlausibleAdsDataLength) return std::nullopt;
    c.skip(6 + 2 + 6 + 2);  // target AmsNetId+port, source AmsNetId+port
    uint16_t command_id = c.u16le();
    uint16_t state_flags = c.u16le();
    uint32_t ams_data_length = c.u32le();
    if (ams_tcp_data_length != kAmsHeaderSize + ams_data_length) return std::nullopt;
    if ((state_flags & kAdsCommandStateFlag) == 0) return std::nullopt;
    if (!twincat_command_name(command_id)) return std::nullopt;
    return kAmsTcpHeaderSize + ams_tcp_data_length;
}

std::optional<TwinCatFrame> try_parse_twincat(ByteSpan tcp_payload) {
    if (tcp_payload.size() < kMinFrameSize) return std::nullopt;
    try {
        Cursor c(tcp_payload);
        c.skip(2);  // reserved
        uint32_t ams_tcp_data_length = c.u32le();
        if (ams_tcp_data_length > kMaxPlausibleAdsDataLength) return std::nullopt;

        ByteSpan target_net_id = c.bytes(6);
        uint16_t target_port = c.u16le();
        ByteSpan source_net_id = c.bytes(6);
        uint16_t source_port = c.u16le();
        uint16_t command_id = c.u16le();
        uint16_t state_flags = c.u16le();
        uint32_t ams_data_length = c.u32le();
        uint32_t error_code = c.u32le();
        uint32_t invoke_id = c.u32le();

        // Structural detection gate -- see twincat.hpp's file header comment for the full
        // collision survey this is based on. Every check below must pass before anything is
        // trusted as real AMS/TCP.
        if (ams_tcp_data_length != kAmsHeaderSize + ams_data_length) return std::nullopt;
        if ((state_flags & kAdsCommandStateFlag) == 0) return std::nullopt;
        auto name = twincat_command_name(command_id);
        if (!name) return std::nullopt;
        if (tcp_payload.size() < kMinFrameSize + ams_data_length) return std::nullopt;

        TwinCatFrame frame;
        frame.target_ams_net_id = format_ams_net_id(target_net_id);
        frame.target_ams_port = target_port;
        frame.source_ams_net_id = format_ams_net_id(source_net_id);
        frame.source_ams_port = source_port;
        frame.command_id = command_id;
        frame.command_name = *name;
        frame.is_response = (state_flags & kResponseStateFlag) != 0;
        frame.error_code = error_code;
        frame.invoke_id = invoke_id;

        ByteSpan body = c.bytes(ams_data_length);
        decode_payload(frame, static_cast<TwinCatCommand>(command_id), frame.is_response, body);

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> TwinCatDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto parsed = try_parse_twincat(payload);
    if (!parsed) return std::nullopt;
    TwinCatFrame frame = std::move(*parsed);

    // Invoke-ID pairing -- the TwinCAT analog of ModbusDecoder::decode's own transaction-ID
    // pairing (modbus.cpp), proving DecodeContext::flow_state<T>() generalizes to a second,
    // independently-designed stateful protocol. DeviceNotification is an unsolicited push with no
    // matching request at all, so it's excluded, the same way Modbus's own pairing only ever
    // applies to a real request/response function code.
    if (frame.command_id != static_cast<uint16_t>(TwinCatCommand::DeviceNotification)) {
        TwinCatFlowState& state = ctx.flow_state<TwinCatFlowState>();
        auto it = state.pending.find(frame.invoke_id);
        if (it != state.pending.end()) {
            TwinCatPendingRequest& pending = it->second;
            if (pending.flow_key != ctx.flow_key) {
                // Opposite direction: authoritatively the response to that specific request.
                frame.paired_response = true;
                frame.paired_request_index = pending.packet_index;
                std::ostringstream s;
                s << "authoritative pairing: response to Invoke ID " << frame.invoke_id
                  << " -- matches the request seen in packet #" << pending.packet_index << " ("
                  << pending.command_name << ": " << pending.request_summary << ")";
                frame.notes.push_back(s.str());
                state.pending.erase(it);
            } else {
                // Same direction: Invoke ID reused before its previous request was ever paired.
                frame.notes.push_back(
                    "Invoke ID " + std::to_string(frame.invoke_id) +
                    " reused on this AMS session before its previous outstanding request (packet #" +
                    std::to_string(pending.packet_index) +
                    ") was matched with a response -- possibly a retry, an orphaned request, or "
                    "out-of-order capture; treating this as a new outstanding request");
                pending =
                    TwinCatPendingRequest{ctx.packet_index, ctx.flow_key, frame.command_name, frame.summary};
            }
        } else if (frame.is_response) {
            frame.notes.push_back(
                "no outstanding request found on this AMS session for Invoke ID " +
                std::to_string(frame.invoke_id) +
                " -- its request was never seen on this session (capture may have started after it "
                "was sent, or it used a different Invoke ID/session)");
        } else {
            // Capacity guard against a pathological/malformed capture leaking memory -- same
            // kMaxTrackedTransactionsPerSession=2000 cap ModbusDecoder::decode applies.
            constexpr size_t kMaxTrackedInvocationsPerSession = 2000;
            if (state.pending.size() < kMaxTrackedInvocationsPerSession) {
                state.pending[frame.invoke_id] =
                    TwinCatPendingRequest{ctx.packet_index, ctx.flow_key, frame.command_name, frame.summary};
            }
        }
    }

    return ProtocolResult::make<TwinCatFrame>("twincat", std::move(frame));
}

const ProtocolDecoder& twincat_decoder() {
    static const TwinCatDecoder instance;
    return instance;
}

}  // namespace conduitscope
