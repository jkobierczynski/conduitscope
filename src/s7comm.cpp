// SPDX-License-Identifier: MIT
#include "conduitscope/s7comm.hpp"

#include <sstream>

namespace conduitscope {

std::string s7comm_rosctr_name(uint8_t rosctr) {
    switch (rosctr) {
        case 0x01: return "Job";
        case 0x02: return "Ack";
        case 0x03: return "Ack_Data";
        case 0x07: return "Userdata";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(rosctr) << ")";
            return out.str();
        }
    }
}

std::string s7comm_function_name(uint8_t fc) {
    switch (fc) {
        case 0x00: return "CPU services";
        case 0x04: return "Read Var";
        case 0x05: return "Write Var";
        case 0x1A: return "Request Download";
        case 0x1B: return "Download Block";
        case 0x1C: return "Download Ended";
        case 0x1D: return "Start Upload";
        case 0x1E: return "Upload";
        case 0x1F: return "End Upload";
        case 0x28: return "PLC Control";
        case 0x29: return "PLC Stop";
        case 0xF0: return "Setup Communication";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(fc) << ")";
            return out.str();
        }
    }
}

std::optional<S7CommFrame> try_parse_s7comm(ByteSpan cotp_user_data) {
    if (cotp_user_data.empty()) {
        return std::nullopt;
    }
    uint8_t protocol_id = cotp_user_data.at(0);
    if (protocol_id != S7COMM_PROTOCOL_ID && protocol_id != S7COMM_PLUS_PROTOCOL_ID) {
        return std::nullopt;  // not S7comm at all -- some other protocol inside this COTP Data frame
    }

    S7CommFrame frame;

    if (protocol_id == S7COMM_PLUS_PROTOCOL_ID) {
        frame.is_plus = true;
        frame.summary = "S7comm-Plus (TIA Portal S7-1200/1500 protocol) detected, not decoded in this "
                         "groundwork release";
        return frame;
    }

    // Fixed header: protocol_id(1) + rosctr(1) + redundancy(2) + pdu_ref(2) +
    // param_len(2) + data_len(2) = 10 bytes total.
    if (cotp_user_data.size() < 10) {
        throw ParseError("S7comm header is truncated (need 10 bytes, have " +
                          std::to_string(cotp_user_data.size()) + ")");
    }

    Cursor c(cotp_user_data);
    c.u8();  // protocol id, already checked above
    frame.rosctr = c.u8();
    frame.rosctr_name = s7comm_rosctr_name(frame.rosctr);
    c.u16be();  // redundancy identification -- always 0x0000 in practice, not currently surfaced
    frame.pdu_reference = c.u16be();
    frame.param_length = c.u16be();
    frame.data_length = c.u16be();

    if (frame.rosctr == 0x02 || frame.rosctr == 0x03) {
        if (c.remaining() < 2) {
            throw ParseError("S7comm Ack/Ack_Data header is missing its error class/code bytes");
        }
        frame.has_error = true;
        frame.error_class = c.u8();
        frame.error_code = c.u8();
    }

    if ((frame.rosctr == 0x01 || frame.rosctr == 0x03) && frame.param_length >= 1 && c.remaining() >= 1) {
        frame.has_function = true;
        frame.function_code = c.u8();
        frame.function_name = s7comm_function_name(frame.function_code);

        if (frame.function_code == 0xF0 && frame.param_length >= 8 && c.remaining() >= 7) {
            // Setup Communication: reserved(1) + max AmQ calling(2) + max AmQ called(2) + PDU length(2).
            // Fixed shape, sent once per session, and the PDU length in particular (the max frame size
            // the two sides negotiate) is genuinely useful context -- worth fully decoding.
            c.u8();  // reserved
            frame.has_setup_comm_details = true;
            frame.max_amq_calling = c.u16be();
            frame.max_amq_called = c.u16be();
            frame.negotiated_pdu_length = c.u16be();
        }
    } else if (frame.rosctr == 0x07) {
        frame.notes.push_back("Userdata parameter block (vendor-specific extensions -- diagnostics, "
                               "CPU functions, etc.) is not decoded in this groundwork release");
    } else if (frame.rosctr == 0x01 || frame.rosctr == 0x03) {
        frame.notes.push_back("no function code decoded (empty or too-short parameter block)");
    }

    std::ostringstream s;
    s << frame.rosctr_name;
    if (frame.has_function) {
        s << ": " << frame.function_name;
        if (frame.has_setup_comm_details) {
            s << " (negotiated PDU length=" << frame.negotiated_pdu_length
              << ", max AmQ calling=" << frame.max_amq_calling << ", max AmQ called=" << frame.max_amq_called
              << ")";
        }
    }
    if (frame.has_error && (frame.error_class != 0 || frame.error_code != 0)) {
        s << " [error class=0x" << std::hex << static_cast<unsigned>(frame.error_class) << " code=0x"
          << static_cast<unsigned>(frame.error_code) << std::dec << "]";
    }
    frame.summary = s.str();

    return frame;
}

}  // namespace conduitscope
