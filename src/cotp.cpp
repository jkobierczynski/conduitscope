// SPDX-License-Identifier: MIT
#include "conduitscope/cotp.hpp"

#include <sstream>

namespace conduitscope {

namespace {

// Bytes consumed by the fixed TPKT header (version, reserved, 2-byte length)
// plus the one-byte COTP length indicator that always follows it.
constexpr size_t kTpktHeaderSize = 4;

}  // namespace

std::optional<size_t> tpkt_declared_length(ByteSpan payload) {
    if (payload.size() < 4) {
        return std::nullopt;
    }
    if (payload.at(0) != 0x03 || payload.at(1) != 0x00) {
        return std::nullopt;
    }
    Cursor c(payload);
    c.u8();  // version
    c.u8();  // reserved
    uint16_t tpkt_length = c.u16be();
    if (tpkt_length < kTpktHeaderSize + 2) {
        // Same lower-bound sanity check try_parse_tpkt_cotp applies -- an implausibly short
        // declared length (can't even hold LI+PDU-type) means this isn't really TPKT, not that
        // it's a truncated one waiting for more bytes.
        return std::nullopt;
    }
    return tpkt_length;
}

std::optional<CotpFrame> try_parse_tpkt_cotp(ByteSpan tcp_payload) {
    // TPKT(4) + COTP length-indicator(1) + COTP PDU-type(1) + at least one more
    // header/data byte is the smallest plausible frame worth trusting as TPKT/COTP.
    if (tcp_payload.size() < 7) {
        return std::nullopt;
    }
    if (tcp_payload.at(0) != 0x03 || tcp_payload.at(1) != 0x00) {
        return std::nullopt;
    }

    Cursor header_peek(tcp_payload);
    header_peek.u8();  // version
    header_peek.u8();  // reserved
    uint16_t tpkt_length = header_peek.u16be();
    if (tpkt_length < kTpktHeaderSize + 2 || tpkt_length > tcp_payload.size()) {
        // Either an implausibly short frame (can't even hold LI+PDU-type) or one
        // that claims to be longer than the bytes we actually have -- in both
        // cases we're not confident enough to call this TPKT/COTP at all.
        return std::nullopt;
    }

    // Clamp all further parsing to exactly this TPKT frame's declared length, so
    // a second, pipelined TPKT frame in the same TCP segment (S7 sessions do
    // sometimes batch requests) can't be misread as part of this one's payload.
    ByteSpan pdu_span = tcp_payload.subspan(0, tpkt_length);
    Cursor c(pdu_span);
    uint8_t version = c.u8();
    c.u8();  // reserved, already validated as 0 above
    c.u16be();  // length, already read via header_peek

    uint8_t li = c.u8();
    if (li < 1) {
        throw ParseError("COTP length indicator is zero");
    }
    size_t after_li_pos = c.position();          // == kTpktHeaderSize + 1
    size_t header_end_pos = after_li_pos + li;    // absolute position where the COTP header ends
    if (header_end_pos > pdu_span.size()) {
        throw ParseError("COTP length indicator (" + std::to_string(li) +
                          ") extends past the TPKT frame it's declared inside");
    }

    uint8_t pdu_type_raw = c.u8();
    uint8_t pdu_family = static_cast<uint8_t>(pdu_type_raw >> 4);

    CotpFrame frame;
    frame.tpkt_version = version;
    frame.tpkt_length = tpkt_length;
    frame.cotp_length_indicator = li;
    frame.cotp_pdu_type_raw = pdu_type_raw;

    if (pdu_family == 0xF) {  // Data (DT)
        frame.kind = CotpPduKind::Data;
        frame.pdu_type_name = "Data (DT)";
        if (li >= 2) {
            uint8_t tpdu_nr_eot = c.u8();
            frame.eot = (tpdu_nr_eot & 0x80) != 0;
            frame.tpdu_nr = tpdu_nr_eot & 0x7F;
        }
        if (header_end_pos > c.position()) c.skip(header_end_pos - c.position());
        frame.user_data = c.rest();

        std::ostringstream s;
        s << "COTP Data (DT)" << (frame.eot ? " [EOT]" : " [fragment]") << ", " << frame.user_data.size()
          << " byte(s) user data";
        frame.summary = s.str();

    } else if (pdu_family == 0xE || pdu_family == 0xD) {  // Connection Request / Confirm
        frame.kind = (pdu_family == 0xE) ? CotpPduKind::ConnectionRequest : CotpPduKind::ConnectionConfirm;
        frame.pdu_type_name = (pdu_family == 0xE) ? "Connection Request (CR)" : "Connection Confirm (CC)";

        if (header_end_pos - c.position() >= 5) {
            c.u16be();  // destination reference
            c.u16be();  // source reference
            c.u8();     // class/options
        }

        // Walk the variable-length parameter list: 1-byte code, 1-byte length,
        // then that many value bytes. 0xC1/0xC2 (calling/called TSAP) are the
        // ones worth surfacing; 0xC0 (TPDU size) and anything else are skipped.
        while (c.position() + 2 <= header_end_pos) {
            uint8_t param_code = c.u8();
            uint8_t param_len = c.u8();
            if (c.position() + param_len > header_end_pos) {
                frame.notes.push_back("COTP parameter list truncated (a parameter's declared length runs "
                                       "past the header) -- stopped walking it early");
                break;
            }
            ByteSpan value = c.bytes(param_len);
            if (param_code == 0xC1) {
                frame.has_calling_tsap = true;
                frame.calling_tsap_hex = to_hex(value, "");
            } else if (param_code == 0xC2) {
                frame.has_called_tsap = true;
                frame.called_tsap_hex = to_hex(value, "");
            }
        }
        if (header_end_pos > c.position()) c.skip(header_end_pos - c.position());

        std::ostringstream s;
        s << frame.pdu_type_name;
        if (frame.has_calling_tsap) s << " calling-TSAP=0x" << frame.calling_tsap_hex;
        if (frame.has_called_tsap) s << " called-TSAP=0x" << frame.called_tsap_hex;
        frame.summary = s.str();

    } else if (pdu_family == 0x8 || pdu_family == 0xC) {  // Disconnect Request / Confirm
        frame.kind = CotpPduKind::Disconnect;
        frame.pdu_type_name = (pdu_family == 0x8) ? "Disconnect Request (DR)" : "Disconnect Confirm (DC)";
        frame.summary = frame.pdu_type_name;
        if (header_end_pos > c.position()) c.skip(header_end_pos - c.position());

    } else {
        frame.kind = CotpPduKind::Other;
        std::ostringstream s;
        s << "COTP PDU type 0x" << std::hex << static_cast<unsigned>(pdu_type_raw) << std::dec
          << " (not decoded further)";
        frame.pdu_type_name = s.str();
        frame.summary = s.str();
        if (header_end_pos > c.position()) c.skip(header_end_pos - c.position());
    }

    if (tpkt_length < tcp_payload.size()) {
        frame.notes.push_back(std::to_string(tcp_payload.size() - tpkt_length) +
                               " additional byte(s) remain in this TCP segment after this TPKT frame "
                               "(possible pipelined TPKT frames; only the first is decoded in this "
                               "groundwork release)");
    }

    return frame;
}

}  // namespace conduitscope
