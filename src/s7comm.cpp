// SPDX-License-Identifier: MIT
#include "conduitscope/s7comm.hpp"

#include <algorithm>
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

std::string s7comm_return_code_name(uint8_t code) {
    switch (code) {
        case 0x00: return "Reserved";
        case 0x01: return "Hardware error";
        case 0x03: return "Accessing the object not allowed";
        case 0x05: return "Invalid address";
        case 0x06: return "Data type not supported";
        case 0x0A: return "Object does not exist";
        case 0xFF: return "Success";
        default: {
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(code) << ")";
            return out.str();
        }
    }
}

namespace {

// --- Read Var / Write Var item-level addressing -----------------------
//
// Reference behavior for the tables and encodings below is the S7ANY
// addressing scheme documented (with slightly varying terminology) across
// several independent open-source implementations -- the Wireshark
// packet-s7comm.c dissector, the Arkime s7comm.c parser, snap7, and
// python-snap7 -- which all agree on the wire layout. This is an
// independent implementation, not a port of any of them.

std::string hex8(uint8_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << static_cast<unsigned>(v);
    return out.str();
}

std::string s7_area_name(uint8_t area, std::string& letter) {
    switch (area) {
        case 0x81: letter = "I"; return "Inputs (I)";
        case 0x82: letter = "Q"; return "Outputs (Q)";
        case 0x83: letter = "M"; return "Merkers/Flags (M)";
        case 0x84: letter = "DB"; return "Data Block (DB)";
        case 0x85: letter = "DI"; return "Instance Data Block (DI)";
        case 0x86: letter = "L"; return "Local Data (L)";
        case 0x87: letter = "V"; return "Previous Local Data (V)";
        case 0x1C: letter = "C"; return "Counters (C)";
        case 0x1D: letter = "T"; return "Timers (T)";
        default: {
            letter.clear();
            std::ostringstream out;
            out << "Unknown area (0x" << std::hex << static_cast<unsigned>(area) << ")";
            return out.str();
        }
    }
}

// suffix_letter is set to the Step7 data-size suffix (B/W/D) used in tags
// like "IB0"/"QW1"/"MD50", or '\0' when transport_size doesn't map to one
// (BIT gets its own ".bit" notation instead, handled by the caller).
std::string s7_transport_size_name(uint8_t ts, char& suffix_letter) {
    switch (ts) {
        case 0x01: suffix_letter = 'X'; return "BIT";
        case 0x02: suffix_letter = 'B'; return "BYTE";
        case 0x03: suffix_letter = 'B'; return "CHAR";
        case 0x04: suffix_letter = 'W'; return "WORD";
        case 0x05: suffix_letter = 'W'; return "INT";
        case 0x06: suffix_letter = 'D'; return "DWORD";
        case 0x07: suffix_letter = 'D'; return "DINT";
        case 0x08: suffix_letter = 'D'; return "REAL";
        case 0x09: suffix_letter = '\0'; return "DATE";
        case 0x0A: suffix_letter = '\0'; return "TOD";
        case 0x0B: suffix_letter = '\0'; return "TIME";
        case 0x0E: suffix_letter = '\0'; return "DATE_AND_TIME";
        default: {
            suffix_letter = '\0';
            std::ostringstream out;
            out << "Unknown (0x" << std::hex << static_cast<unsigned>(ts) << ")";
            return out.str();
        }
    }
}

std::string s7_build_tag(const S7Item& item, const std::string& area_letter, char suffix_letter) {
    std::ostringstream tag;
    if (item.area == 0x1C || item.area == 0x1D) {
        // Counters/timers: the wire address IS the counter/timer number, no byte/bit split.
        tag << area_letter << item.byte_address;
        return tag.str();
    }
    if (area_letter.empty()) {
        return "";  // unrecognized area -- caller falls back to area_name
    }
    bool is_db_area = (item.area == 0x84 || item.area == 0x85);
    if (is_db_area) {
        tag << area_letter << item.db_number << ".";
    }
    if (item.transport_size == 0x01) {
        tag << (is_db_area ? "DBX" : area_letter) << item.byte_address << "."
            << static_cast<unsigned>(item.bit_offset);
    } else if (suffix_letter != '\0') {
        tag << (is_db_area ? std::string("DB") + suffix_letter : area_letter + suffix_letter) << item.byte_address;
    } else {
        // Uncommon transport size (DATE/TOD/TIME/...) with no single-letter Step7 suffix --
        // fall back to a byte-oriented tag rather than guessing at one.
        tag << (is_db_area ? "DBB" : area_letter + "B") << item.byte_address;
    }
    return tag.str();
}

// Parses one S7ANY (or unsupported-syntax) item out of a Read Var / Write
// Var request's parameter block. Advances `c` past the item's declared
// length regardless of whether the syntax was understood, so the caller can
// keep walking subsequent items. Throws ParseError only when the item's own
// declared length doesn't fit in what's left of the buffer (structural
// truncation); an unrecognized syntax id is not an error, just unparsed.
S7Item parse_s7_item(Cursor& c, std::vector<std::string>& notes, size_t item_index) {
    if (c.remaining() < 2) {
        throw ParseError("S7comm item " + std::to_string(item_index) +
                          " is truncated (need at least 2 bytes for spec type/length, have " +
                          std::to_string(c.remaining()) + ")");
    }
    uint8_t spec_type = c.u8();
    uint8_t spec_len = c.u8();
    if (spec_type != 0x12) {
        notes.push_back("item " + std::to_string(item_index) + " has variable-specification type " +
                         hex8(spec_type) + " (expected 0x12); not decoded");
        if (spec_len <= c.remaining()) c.skip(spec_len);
        return S7Item{};
    }
    if (spec_len > c.remaining()) {
        throw ParseError("S7comm item " + std::to_string(item_index) + " declares a " +
                          std::to_string(spec_len) + "-byte address spec but only " +
                          std::to_string(c.remaining()) + " byte(s) remain");
    }
    ByteSpan item_span = c.bytes(spec_len);

    S7Item item;
    Cursor ic(item_span);
    if (ic.remaining() < 1) {
        notes.push_back("item " + std::to_string(item_index) + " address spec is empty");
        return item;
    }
    item.syntax_id = ic.u8();
    if (item.syntax_id != 0x10) {
        item.syntax_supported = false;
        std::string syntax_label = (item.syntax_id == 0xB2) ? " (S7-1200/1500 symbolic addressing)" : "";
        notes.push_back("item " + std::to_string(item_index) + " uses syntax id " + hex8(item.syntax_id) +
                         syntax_label + ", not decoded in this groundwork release -- raw bytes: " +
                         to_hex(item_span));
        return item;
    }
    if (ic.remaining() < 9) {
        notes.push_back("item " + std::to_string(item_index) +
                         " is a truncated S7ANY address spec (need 9 more bytes, have " +
                         std::to_string(ic.remaining()) + ")");
        return item;
    }

    item.syntax_supported = true;
    item.transport_size = ic.u8();
    char suffix = '\0';
    item.transport_size_name = s7_transport_size_name(item.transport_size, suffix);
    item.count = ic.u16be();
    item.db_number = ic.u16be();
    item.area = ic.u8();
    std::string area_letter;
    item.area_name = s7_area_name(item.area, area_letter);

    uint32_t raw_addr = (static_cast<uint32_t>(ic.u8()) << 16) | (static_cast<uint32_t>(ic.u8()) << 8) | ic.u8();
    item.bit_address = raw_addr;
    if (item.area == 0x1C || item.area == 0x1D) {
        item.byte_address = raw_addr;  // counter/timer number, not byte*8+bit
        item.bit_offset = 0;
    } else {
        item.byte_address = raw_addr >> 3;
        item.bit_offset = static_cast<uint8_t>(raw_addr & 0x7);
    }
    item.tag = s7_build_tag(item, area_letter, suffix);

    return item;
}

// Reads the transport_size(1) + length(2) + data tail shared by a Read Var
// response's value and a Write Var request's value -- the two data-item
// shapes that actually carry a value on the wire (a Write Var *response*
// item is just a bare return code, handled separately below). `is_last`
// disables the inter-item fill-byte skip, since S7comm only pads between
// items, not after the final one. Never throws: a length field that claims
// more data than is available is clamped, with a note recording the
// mismatch, mirroring how the rest of this codebase treats an untrustworthy
// length field as a warning rather than a hard failure when it can.
void parse_s7_value_tail(Cursor& c, S7DataItem& di, bool is_last, size_t item_index,
                          std::vector<std::string>& notes) {
    if (c.remaining() < 3) {
        // Some PLCs omit the transport-size/length/data fields entirely on an error return code.
        return;
    }
    di.has_value_fields = true;
    di.transport_size = c.u8();
    di.length_field = c.u16be();

    size_t byte_count;
    if (di.transport_size == 0x03) {
        byte_count = 1;  // BIT: always a single byte on the wire regardless of the length field
    } else if (di.transport_size == 0x04 || di.transport_size == 0x05) {
        // BYTE/WORD/DWORD and INTEGER family: length field counts bits, not bytes.
        byte_count = (static_cast<size_t>(di.length_field) + 7) / 8;
    } else {
        // DINTEGER/REAL/OCTET STRING and anything else: treat the length field as a byte
        // count directly. This matches the common cases seen in practice, but is a
        // best-effort guess for the less-common transport sizes.
        byte_count = di.length_field;
        if (di.transport_size != 0x06 && di.transport_size != 0x07 && di.transport_size != 0x09) {
            notes.push_back("data item " + std::to_string(item_index) + " has uncommon transport size " +
                             hex8(di.transport_size) +
                             "; treating its length field as a byte count, which is a best-effort guess");
        }
    }
    if (byte_count > c.remaining()) {
        notes.push_back("data item " + std::to_string(item_index) + " declares " + std::to_string(byte_count) +
                         " byte(s) of data but only " + std::to_string(c.remaining()) +
                         " remain; showing truncated data");
        byte_count = c.remaining();
    }
    di.data = c.bytes(byte_count);

    // Items are padded to an even byte boundary when another item follows.
    if (!is_last && (byte_count % 2 == 1) && c.remaining() >= 1) {
        c.skip(1);
    }
}

// Read Var response data item: return_code(1) + [value tail, present on success].
S7DataItem parse_s7_read_result_item(Cursor& c, bool is_last, size_t item_index,
                                      std::vector<std::string>& notes) {
    S7DataItem di;
    if (c.remaining() < 1) {
        notes.push_back("data item " + std::to_string(item_index) + " is missing (data block ran out)");
        return di;
    }
    di.return_code = c.u8();
    di.return_code_name = s7comm_return_code_name(di.return_code);
    parse_s7_value_tail(c, di, is_last, item_index, notes);
    return di;
}

// Write Var request data item: reserved(1, always 0 on the wire -- not a return code,
// there's nothing to report yet) + value tail (always present; this is what's being written).
S7DataItem parse_s7_write_value_item(Cursor& c, bool is_last, size_t item_index,
                                      std::vector<std::string>& notes) {
    S7DataItem di;
    if (c.remaining() < 1) {
        notes.push_back("data item " + std::to_string(item_index) + " is missing (data block ran out)");
        return di;
    }
    c.u8();  // reserved
    parse_s7_value_tail(c, di, is_last, item_index, notes);
    return di;
}

// Write Var response data item: a bare return code, nothing else on the wire.
S7DataItem parse_s7_write_result_item(Cursor& c, size_t item_index, std::vector<std::string>& notes) {
    S7DataItem di;
    if (c.remaining() < 1) {
        notes.push_back("data item " + std::to_string(item_index) + " is missing (data block ran out)");
        return di;
    }
    di.return_code = c.u8();
    di.return_code_name = s7comm_return_code_name(di.return_code);
    return di;
}

std::string brief_item_list(const std::vector<S7Item>& items) {
    std::ostringstream out;
    size_t shown = std::min<size_t>(items.size(), 3);
    for (size_t i = 0; i < shown; ++i) {
        if (i) out << ", ";
        const auto& it = items[i];
        if (!it.tag.empty()) {
            out << it.tag;
        } else if (it.syntax_supported) {
            out << it.area_name;
        } else {
            out << "unsupported addressing";
        }
    }
    if (items.size() > shown) out << ", +" << (items.size() - shown) << " more";
    return out.str();
}

// return_code_name is only set for items that actually carry a return code on the wire
// (Read Var responses, Write Var responses) -- a Write Var request's value item has no
// return code at all (see parse_s7_write_value_item), so return_code_name is empty there
// and this renders the value directly instead of a misleading "Reserved"/error label.
std::string brief_value_list(const std::vector<S7DataItem>& items) {
    std::ostringstream out;
    size_t shown = std::min<size_t>(items.size(), 3);
    for (size_t i = 0; i < shown; ++i) {
        if (i) out << ", ";
        const auto& di = items[i];
        if (!di.return_code_name.empty() && di.return_code != 0xFF) {
            out << di.return_code_name;
        } else if (di.has_value_fields && di.transport_size == 0x03 && di.data.size() == 1) {
            out << (di.data.at(0) != 0 ? "1" : "0");
        } else if (di.has_value_fields && !di.data.empty()) {
            out << to_hex(di.data);
        } else if (!di.return_code_name.empty()) {
            out << "ok";
        } else {
            out << "(no data)";
        }
    }
    if (items.size() > shown) out << ", +" << (items.size() - shown) << " more";
    return out.str();
}

// Appends one detailed line per item/value to `notes` (capped so a heavily
// batched real-world request -- e.g. 20 items in one Read Var call, which
// is common -- doesn't blow up the notes list without bound).
constexpr size_t kMaxDetailedNotes = 20;

void append_item_notes(const std::vector<S7Item>& items, std::vector<std::string>& notes) {
    for (size_t i = 0; i < items.size() && i < kMaxDetailedNotes; ++i) {
        const auto& it = items[i];
        std::ostringstream line;
        line << "item " << i << ": ";
        if (!it.tag.empty()) {
            line << it.tag << " [" << it.transport_size_name << " x" << it.count << "]";
        } else if (it.syntax_supported) {
            line << it.area_name << " (address not decoded)";
        } else {
            line << "unsupported/undecoded addressing (syntax id " << hex8(it.syntax_id) << ")";
        }
        notes.push_back(line.str());
    }
    if (items.size() > kMaxDetailedNotes) {
        notes.push_back("... and " + std::to_string(items.size() - kMaxDetailedNotes) +
                         " more item(s) not listed individually");
    }
}

void append_value_notes(const std::vector<S7DataItem>& items, std::vector<std::string>& notes) {
    for (size_t i = 0; i < items.size() && i < kMaxDetailedNotes; ++i) {
        const auto& di = items[i];
        std::ostringstream line;
        line << "value " << i << ": ";
        bool wrote_something = false;
        if (!di.return_code_name.empty()) {
            line << di.return_code_name;
            wrote_something = true;
        }
        if (di.has_value_fields && !di.data.empty()) {
            if (wrote_something) line << " = ";
            line << to_hex(di.data);
            wrote_something = true;
        }
        if (!wrote_something) line << "(no data)";
        notes.push_back(line.str());
    }
    if (items.size() > kMaxDetailedNotes) {
        notes.push_back("... and " + std::to_string(items.size() - kMaxDetailedNotes) +
                         " more value(s) not listed individually");
    }
}

}  // namespace

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

    // The parameter and data blocks are addressed independently from here on (rather than
    // continuing to read off the shared cursor `c`), because Read Var / Write Var item
    // decoding needs to walk exactly param_length bytes of parameter and exactly
    // data_length bytes of data regardless of how much of the parameter block the
    // simpler function codes above choose to consume. Both spans are clamped to what
    // was actually captured, so a truncated capture degrades gracefully instead of
    // throwing out of subspan().
    size_t header_len = 10 + (frame.has_error ? 2 : 0);
    size_t avail_after_header = cotp_user_data.size() > header_len ? cotp_user_data.size() - header_len : 0;
    size_t param_take = std::min(static_cast<size_t>(frame.param_length), avail_after_header);
    ByteSpan param_span = cotp_user_data.subspan(header_len, param_take);
    size_t data_offset = header_len + param_take;
    size_t avail_after_param = cotp_user_data.size() > data_offset ? cotp_user_data.size() - data_offset : 0;
    size_t data_take = std::min(static_cast<size_t>(frame.data_length), avail_after_param);
    ByteSpan data_span = cotp_user_data.subspan(data_offset, data_take);

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
        } else if (frame.function_code == 0x04 || frame.function_code == 0x05) {
            // Read Var / Write Var: parameter block is function_code(1) + item_count(1) +
            // (Job only) item_count address items; re-read from param_span rather than the
            // shared cursor `c` so this is unaffected by how many bytes `c` has consumed so far.
            Cursor pc(param_span);
            if (pc.remaining() >= 1) pc.u8();  // function code, already known
            if (pc.remaining() >= 1) {
                uint8_t item_count = pc.u8();

                if (frame.rosctr == 0x01) {
                    for (uint8_t i = 0; i < item_count; ++i) {
                        try {
                            frame.items.push_back(parse_s7_item(pc, frame.notes, i));
                        } catch (const ParseError& e) {
                            frame.notes.push_back("item " + std::to_string(i) +
                                                   " address decoding failed: " + e.what());
                            break;
                        }
                    }
                }

                Cursor dc(data_span);
                if (frame.rosctr == 0x01 && frame.function_code == 0x05) {
                    // Write Var request: data block carries the values being written.
                    for (uint8_t i = 0; i < item_count; ++i) {
                        frame.data_items.push_back(parse_s7_write_value_item(dc, i + 1 == item_count, i, frame.notes));
                    }
                } else if (frame.rosctr == 0x03 && frame.function_code == 0x04) {
                    // Read Var response: data block carries the returned values.
                    for (uint8_t i = 0; i < item_count; ++i) {
                        frame.data_items.push_back(parse_s7_read_result_item(dc, i + 1 == item_count, i, frame.notes));
                    }
                } else if (frame.rosctr == 0x03 && frame.function_code == 0x05) {
                    // Write Var response: one bare return code per item, no value payload.
                    for (uint8_t i = 0; i < item_count; ++i) {
                        frame.data_items.push_back(parse_s7_write_result_item(dc, i, frame.notes));
                    }
                }

                append_item_notes(frame.items, frame.notes);
                append_value_notes(frame.data_items, frame.notes);
            }
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
        if (!frame.items.empty()) {
            s << " (" << frame.items.size() << " item(s): " << brief_item_list(frame.items) << ")";
        }
        if (!frame.data_items.empty()) {
            s << (frame.items.empty() ? " (" : ", ") << frame.data_items.size()
              << (frame.items.empty() ? " value(s): " : " value(s)=[") << brief_value_list(frame.data_items)
              << (frame.items.empty() ? ")" : "]");
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
