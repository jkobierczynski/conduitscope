// SPDX-License-Identifier: Apache-2.0
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

namespace {

// The single table backing both s7comm_function_name(uint8_t) and s7comm_known_function_names()
// -- see s7comm.hpp's own comment on s7comm_known_function_names() for why this was refactored
// out of a plain switch: one place ("code N means this name") asserts the mapping, not two.
struct S7CommFunctionEntry {
    uint8_t code;
    const char* name;
};

constexpr S7CommFunctionEntry kS7CommFunctions[] = {
    {0x00, "CPU services"},
    {0x04, "Read Var"},
    {0x05, "Write Var"},
    {0x1A, "Request Download"},
    {0x1B, "Download Block"},
    {0x1C, "Download Ended"},
    {0x1D, "Start Upload"},
    {0x1E, "Upload"},
    {0x1F, "End Upload"},
    {0x28, "PLC Control"},
    {0x29, "PLC Stop"},
    {0xF0, "Setup Communication"},
};

}  // namespace

std::string s7comm_function_name(uint8_t fc) {
    for (const auto& entry : kS7CommFunctions) {
        if (entry.code == fc) return entry.name;
    }
    std::ostringstream out;
    out << "Unknown (0x" << std::hex << static_cast<unsigned>(fc) << ")";
    return out.str();
}

std::vector<std::string> s7comm_known_function_names() {
    std::vector<std::string> out;
    out.reserve(sizeof(kS7CommFunctions) / sizeof(kS7CommFunctions[0]));
    for (const auto& entry : kS7CommFunctions) out.push_back(entry.name);
    return out;
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

std::string hex16(uint16_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << static_cast<unsigned>(v);
    return out.str();
}

std::string hex32(uint32_t v) {
    std::ostringstream out;
    out << "0x" << std::hex << v;
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

// --- 0xB2 (S7-1200/1500 "symbolic" addressing) -- EXPERIMENTAL -----------
//
// Unlike S7ANY, this addressing mode doesn't carry a plain byte/bit address
// at all: TIA Portal compiles each symbolic tag reference down to an opaque
// CRC-like value (not independently recoverable to a name from the wire)
// plus one or more "LID" (local id) fields. The layout below is a
// best-effort reconstruction from public sources -- Wireshark's
// S7COMM_SYNTAXID_1200SYM field list and its documented TIA1200 area-code
// constants (S7COMM_TIA1200_VAR_ITEM_AREA1_DB=0x8a0e,
// AREA1_IQMCT=0x0000, AREA2_I/Q/M/C/T=0x50-0x54), cross-checked against an
// independent third-party parser's 14-byte minimum item length -- and it
// has been validated against real capture traffic for exactly one shape:
// a single LID entry addressing the Merker (M) area. It has NOT been
// confirmed against real DB-area 1200SYM traffic, nor against an item with
// more than one LID entry (structured/nested symbol access presumably
// produces one, but the chaining format is unverified). Every tag this
// produces is marked is_experimental so callers show it as a reconstruction,
// not a certainty; anything that doesn't match the single-LID shape falls
// back to the generic "not decoded" path rather than guessing further.
//
// `body` is everything in the item's address spec after the syntax id byte.
// Returns false (leaving `item` untouched) when the shape doesn't match what
// this experimental decode covers, so the caller falls back gracefully.
bool try_decode_tia1200_sym(ByteSpan body, S7Item& item, std::vector<std::string>& notes, size_t item_index) {
    Cursor bc(body);
    if (bc.remaining() < 9) {  // reserved(2) + area1(2) + at least area2(1) + crc(4)
        return false;
    }
    uint16_t reserved1 = bc.u16be();
    uint16_t area1 = bc.u16be();

    std::string area_letter;
    uint16_t db_number = 0;
    bool is_db = false;

    if (area1 == 0x0000) {  // AREA1_IQMCT: a 1-byte area2 code follows
        uint8_t area2 = bc.u8();
        switch (area2) {
            case 0x50: area_letter = "I"; item.area_name = "Inputs (I)"; break;
            case 0x51: area_letter = "Q"; item.area_name = "Outputs (Q)"; break;
            case 0x52: area_letter = "M"; item.area_name = "Merkers/Flags (M)"; break;
            case 0x53: area_letter = "C"; item.area_name = "Counters (C)"; break;
            case 0x54: area_letter = "T"; item.area_name = "Timers (T)"; break;
            default:
                notes.push_back("item " + std::to_string(item_index) +
                                 " is a 1200SYM (0xB2) item with an unrecognized area2 byte " + hex8(area2) +
                                 "; the experimental decode doesn't cover this, showing raw hex instead");
                return false;
        }
    } else if (area1 == 0x8A0E) {  // AREA1_DB: a 2-byte DB number follows
        if (bc.remaining() < 6) return false;  // dbnumber(2) + crc(4)
        is_db = true;
        db_number = bc.u16be();
        area_letter = "DB";
        item.area_name = "Data Block (DB)";
    } else {
        notes.push_back("item " + std::to_string(item_index) +
                         " is a 1200SYM (0xB2) item with an unrecognized area1 value " + hex16(area1) +
                         "; the experimental decode doesn't cover this, showing raw hex instead");
        return false;
    }

    if (bc.remaining() < 4) return false;
    uint32_t crc = bc.u32be();

    if (bc.remaining() != 4) {
        // Not the single-LID (flags(1) + 3-byte value) shape this experimental decode covers --
        // most likely more than one LID entry (nested/structured symbol access), whose chaining
        // format isn't verified. Bail out rather than guess at it.
        notes.push_back("item " + std::to_string(item_index) + " is a 1200SYM (0xB2) item with " +
                         std::to_string(bc.remaining()) +
                         " byte(s) left after its CRC (the experimental decode only covers exactly 4, "
                         "one LID entry) -- crc=" + hex32(crc) + "; showing raw hex instead");
        return false;
    }

    uint8_t lid_flags = bc.u8();
    uint32_t lid_raw = (static_cast<uint32_t>(bc.u8()) << 16) | (static_cast<uint32_t>(bc.u8()) << 8) | bc.u8();
    uint32_t byte_addr = lid_raw >> 3;
    uint8_t bit_off = static_cast<uint8_t>(lid_raw & 0x7);

    std::ostringstream tag;
    if (is_db) {
        item.db_number = db_number;
        tag << "DB" << db_number << ".DBX" << byte_addr << "." << static_cast<unsigned>(bit_off);
    } else {
        tag << area_letter << byte_addr << "." << static_cast<unsigned>(bit_off);
    }
    item.tag = tag.str();
    item.bit_address = lid_raw;
    item.byte_address = byte_addr;
    item.bit_offset = bit_off;
    item.is_experimental = true;
    item.syntax_supported = true;
    item.tia1200_reserved = reserved1;
    item.tia1200_crc = crc;
    item.tia1200_lid_flags = lid_flags;
    return true;
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
    if (item.syntax_id == 0xB2) {
        if (try_decode_tia1200_sym(ic.rest(), item, notes, item_index)) {
            return item;  // tag + is_experimental set; detail note already pushed
        }
        // Recognized shape didn't match what the experimental decode covers -- fall through
        // to the generic "not decoded" path below (try_decode_tia1200_sym already noted why).
    }
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
            out << it.tag << (it.is_experimental ? " [EXPERIMENTAL]" : "");
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
        if (it.is_experimental) {
            line << it.tag << " [EXPERIMENTAL 1200SYM (0xB2) decode, unverified -- reserved="
                 << hex16(it.tia1200_reserved) << " crc=" << hex32(it.tia1200_crc)
                 << " lid_flags=" << hex8(it.tia1200_lid_flags)
                 << "; crc is an opaque TIA Portal-computed value, not resolvable to a symbol name]";
        } else if (!it.tag.empty()) {
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

// --- PLC Control (0x28) / PLC Stop (0x29) parameter decoding ----------
//
// Reference behavior for the wire layout and the PI service name table below is Wireshark's own
// packet-s7comm.c dissector (its pi_service_names[] array) -- see s7comm.hpp's file header for
// the scope boundary around the _N_* Sinumerik/CNC-specific services (name+description lookup
// only, no parameter-block decode) and why a handful of bytes in both function codes' fixed
// layout are left as unknown/reserved rather than guessed at.

// Copies raw bytes into a std::string verbatim, with no printability filtering -- matching this
// codebase's existing convention (see goose.cpp/sv.cpp's own ascii_text) of showing whatever
// ASCII text is actually on the wire rather than second-guessing it.
std::string ascii_text(ByteSpan s) {
    std::string text;
    text.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) text += static_cast<char>(s.at(i));
    return text;
}

struct PiServiceEntry {
    const char* name;
    const char* description;
};

// The first six entries are the ones whose parameter block gets a full structural decode
// (see try_parse_s7comm's 0x28 branch); every entry after that is looked up for a name+
// description only. This is a partial transcription of Wireshark's ~65-entry pi_service_names[]
// table (packet-s7comm.c, around line 1516) -- covering the six PLC-control services plus the
// most commonly-seen/clearly-documented _N_* Sinumerik/CNC services -- not the full table: several
// of Wireshark's own _N_* descriptions are terse or unclear enough that transcribing them here
// would just be copying uncertainty, and the _N_* family is out of this decoder's scope anyway
// (see s7comm.hpp's file header). A PI service name that isn't in this table still gets shown
// (pi_service_name is always set), just with an empty pi_service_description.
constexpr PiServiceEntry kPiServiceNames[] = {
    {"_INSE", "Activates a PLC module"},
    {"_INS2", "Activates a PLC module"},
    {"_DELE", "Removes module from the PLC's passive file system"},
    {"P_PROGRAM", "PLC Start / Stop"},
    {"_MODU", "PLC Copy Ram to Rom"},
    {"_GARB", "Compress PLC memory"},
    {"_N_LOGIN_", "Login"},
    {"_N_LOGOUT", "Logout"},
    {"_N_CANCEL", "Cancels NC alarm"},
    {"_N_DASAVE", "Copying data from SRAM to FLASH"},
    {"_N_DIGIOF", "Turns off digitizing"},
    {"_N_DIGION", "Turns on digitizing"},
    {"_N_DZERO_", "Set all D nos. invalid for function \"unique D no.\""},
    {"_N_ENDEXT", "(no further description available)"},
    {"_N_F_OPER", "Opens a file read-only"},
    {"_N_OST_OF", "Overstore OFF"},
    {"_N_OST_ON", "Overstore ON"},
    {"_N_SCALE_", "Unit of measurement setting (metric<->INCH)"},
    {"_N_SETUFR", "Activates user frame"},
    {"_N_STRTLK", "The global start disable is set"},
    {"_N_STRTUL", "The global start disable is reset"},
    {"_N_TMRASS", "Resets the Active status"},
    {"_N_F_DELE", "Deletes file"},
    {"_N_EXTERN", "Selects external program for execution"},
    {"_N_EXTMOD", "Selects external program for execution"},
    {"_N_F_DELR", "Delete file even without access rights"},
    {"_N_F_XFER", "Selects file for uploading"},
    {"_N_LOCKE_", "Locks the active file for editing"},
    {"_N_SELECT", "(selects a program/file)"},
    {"_N_SRTEXT", "(selects external program)"},
    {"_N_F_CLOS", "(closes a file)"},
    {"_N_F_OPEN", "(opens a file)"},
    {"_N_F_SEEK", "(seeks within a file)"},
    {"_N_ASUP__", "(interrupt/ASUP-related)"},
    {"_N_CHEKDM", "(tool/magazine check)"},
    {"_N_CHKDNO", "(tool D-number check)"},
};

std::string pi_service_description_lookup(const std::string& name) {
    for (const auto& entry : kPiServiceNames) {
        if (name == entry.name) return entry.description;
    }
    return "";
}

// _INSE / _INS2 / _DELE parameter block: count(1) + reserved(1) + count * an 8-byte block
// descriptor (2 ASCII block-type chars + 5 ASCII decimal block-number chars + 1 ASCII destination
// filesystem char). Never throws -- a truncated descriptor is noted and parsing stops there,
// matching this file's existing tolerant-parsing convention.
void parse_pi_control_blocks(ByteSpan block_span, std::vector<std::string>& out,
                              std::vector<std::string>& notes) {
    Cursor bc(block_span);
    if (bc.remaining() < 2) {
        if (bc.remaining() > 0) {
            notes.push_back("PLC Control block-activate/delete parameter block is too short to "
                             "contain its block-count and reserved bytes");
        }
        return;
    }
    uint8_t count = bc.u8();
    bc.u8();  // reserved, typically 0x00 -- not otherwise documented

    for (uint8_t i = 0; i < count; ++i) {
        if (bc.remaining() < 8) {
            notes.push_back("PLC Control block descriptor " + std::to_string(i) +
                             " is truncated (need 8 bytes, have " + std::to_string(bc.remaining()) + ")");
            break;
        }
        ByteSpan desc = bc.bytes(8);
        std::string type = ascii_text(desc.subspan(0, 2));
        std::string number_str = ascii_text(desc.subspan(2, 5));
        char dest = static_cast<char>(desc.at(7));

        bool numeric = !number_str.empty();
        for (char ch : number_str) {
            if (ch < '0' || ch > '9') {
                numeric = false;
                break;
            }
        }
        std::string number_display = numeric ? std::to_string(std::stoi(number_str))
                                              : ("non-numeric block number (" + number_str + ")");

        std::string dest_name;
        switch (dest) {
            case 'P': dest_name = "Passive"; break;
            case 'A': dest_name = "Active"; break;
            case 'B': dest_name = "Active as well as passive"; break;
            default: dest_name = std::string(1, dest); break;
        }

        out.push_back(type + number_display + " (" + dest_name + ")");
    }
}

void append_pi_control_block_notes(const std::vector<std::string>& blocks, std::vector<std::string>& notes) {
    for (size_t i = 0; i < blocks.size() && i < kMaxDetailedNotes; ++i) {
        notes.push_back("block " + std::to_string(i) + ": " + blocks[i]);
    }
    if (blocks.size() > kMaxDetailedNotes) {
        notes.push_back("... and " + std::to_string(blocks.size() - kMaxDetailedNotes) +
                         " more block(s) not listed individually");
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
    if (protocol_id != S7COMM_PROTOCOL_ID) {
        // Not classic S7comm. Note this deliberately also excludes S7COMM_PLUS_PROTOCOL_ID
        // (0x72) -- S7comm-Plus is a wholly different application protocol that merely shares
        // this same COTP Data / TCP port 102 transport; see s7commplus.hpp/try_parse_s7comm_plus,
        // called separately from decoder.cpp, for that decode.
        return std::nullopt;
    }

    S7CommFrame frame;

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
        } else if (frame.function_code == 0x29) {
            // PLC Stop: Job (request) side only -- see S7CommFrame::plc_stop_message in
            // s7comm.hpp for the wire layout and why the Ack/Ack_Data side is deliberately left
            // undecorated (Wireshark's own dissector doesn't special-case it either). Re-read from
            // param_span, same convention as the Read/Write Var branch above.
            if (frame.rosctr == 0x01) {
                Cursor pc(param_span);
                if (pc.remaining() >= 1) pc.u8();  // function code, already known
                if (pc.remaining() >= 6) {
                    pc.skip(5);  // unknown/reserved -- see s7comm.hpp's file header
                    uint8_t len = pc.u8();
                    size_t take = std::min<size_t>(len, pc.remaining());
                    if (take < len) {
                        frame.notes.push_back("PLC Stop message string is truncated (declares " +
                                               std::to_string(len) + " byte(s), only " +
                                               std::to_string(take) + " available)");
                    }
                    frame.plc_stop_message = ascii_text(pc.bytes(take));
                } else {
                    frame.notes.push_back("PLC Stop parameter block is too short to contain its "
                                           "reserved bytes and message-length field");
                }
            }
        } else if (frame.function_code == 0x28) {
            // PLC Control (PI-Service): see S7CommFrame's pi_* fields and s7comm.hpp's file header
            // for the wire layout and the deliberate _N_* Sinumerik/CNC scope boundary. Re-read
            // from param_span, same convention as the branches above.
            Cursor pc(param_span);
            if (pc.remaining() >= 1) pc.u8();  // function code, already known

            if (frame.rosctr == 0x01) {
                if (pc.remaining() >= 9) {  // reserved(7) + paramlen(2)
                    pc.skip(7);  // unknown/reserved -- see s7comm.hpp's file header
                    uint16_t pi_param_len = pc.u16be();
                    size_t pi_param_take = std::min<size_t>(pi_param_len, pc.remaining());
                    if (pi_param_take < pi_param_len) {
                        frame.notes.push_back("PLC Control PI parameter block is truncated (declares " +
                                               std::to_string(pi_param_len) + " byte(s), only " +
                                               std::to_string(pi_param_take) + " available)");
                    }
                    ByteSpan pi_param_span = pc.bytes(pi_param_take);

                    if (pc.remaining() >= 1) {
                        uint8_t name_len = pc.u8();
                        size_t name_take = std::min<size_t>(name_len, pc.remaining());
                        if (name_take < name_len) {
                            frame.notes.push_back("PLC Control PI service name is truncated (declares " +
                                                   std::to_string(name_len) + " byte(s), only " +
                                                   std::to_string(name_take) + " available)");
                        }
                        frame.has_pi_service = true;
                        frame.pi_service_name = ascii_text(pc.bytes(name_take));
                        frame.pi_service_description = pi_service_description_lookup(frame.pi_service_name);

                        if (frame.pi_service_name == "_INSE" || frame.pi_service_name == "_INS2" ||
                            frame.pi_service_name == "_DELE") {
                            parse_pi_control_blocks(pi_param_span, frame.pi_control_blocks, frame.notes);
                            append_pi_control_block_notes(frame.pi_control_blocks, frame.notes);
                        } else if (frame.pi_service_name == "P_PROGRAM" || frame.pi_service_name == "_MODU" ||
                                   frame.pi_service_name == "_GARB") {
                            if (!pi_param_span.empty()) {
                                frame.pi_control_argument = ascii_text(pi_param_span);
                            }
                        } else if (!pi_param_span.empty()) {
                            // The _N_* Sinumerik/CNC family (and anything else this table doesn't
                            // name) is a deliberate scope boundary -- name+description lookup
                            // only, no attempt to decode the parameter block's own structure. See
                            // s7comm.hpp's file header for why.
                            frame.notes.push_back(
                                "PLC Control PI service \"" + frame.pi_service_name + "\"" +
                                (frame.pi_service_description.empty()
                                     ? ""
                                     : " (" + frame.pi_service_description + ")") +
                                " has a " + std::to_string(pi_param_span.size()) +
                                "-byte parameter block that is not decoded -- Sinumerik/CNC-specific "
                                "and other non-PLC-control PI services are a deliberate scope boundary "
                                "here, see s7comm.hpp's file header");
                        }
                    } else {
                        frame.notes.push_back(
                            "PLC Control parameter block is missing its PI service name length byte");
                    }
                } else {
                    frame.notes.push_back("PLC Control parameter block is too short to contain its "
                                           "reserved bytes and PI parameter-length field");
                }
            } else if (frame.rosctr == 0x03) {
                // Ack_Data: a single status byte with two flag bits, present only when the
                // parameter block holds at least the function code plus that byte.
                if (frame.param_length >= 2 && pc.remaining() >= 1) {
                    uint8_t status = pc.u8();
                    frame.has_pi_control_status = true;
                    frame.pi_control_has_more_data = (status & 0x01) != 0;
                    frame.pi_control_has_error = (status & 0x02) != 0;
                }
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
        if (!frame.plc_stop_message.empty()) {
            s << " (\"" << frame.plc_stop_message << "\")";
        }
        if (frame.has_pi_service) {
            s << " (" << frame.pi_service_name;
            if (!frame.pi_service_description.empty()) {
                s << " - " << frame.pi_service_description;
            }
            if (!frame.pi_control_argument.empty()) {
                s << ", arg=\"" << frame.pi_control_argument << "\"";
            }
            if (!frame.pi_control_blocks.empty()) {
                s << ", " << frame.pi_control_blocks.size() << " block(s): ";
                size_t shown = std::min<size_t>(frame.pi_control_blocks.size(), 3);
                for (size_t i = 0; i < shown; ++i) {
                    if (i) s << ", ";
                    s << frame.pi_control_blocks[i];
                }
                if (frame.pi_control_blocks.size() > shown) {
                    s << ", +" << (frame.pi_control_blocks.size() - shown) << " more";
                }
            }
            s << ")";
        }
        if (frame.has_pi_control_status) {
            s << " (more data=" << (frame.pi_control_has_more_data ? "yes" : "no")
              << ", error=" << (frame.pi_control_has_error ? "yes" : "no") << ")";
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
