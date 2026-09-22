// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/goose.hpp"

#include "conduitscope/resource_limits.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

// Safety caps against a malformed/adversarial capture -- see goose.hpp's file header comment's
// allData paragraph. max_goose_data_depth() bounds array/structure recursion; max_goose_data_values()
// bounds the total flattened entry count across one allData (decoder.cpp imposes its own,
// separate 50-entry cap when copying into DecodedPacket::goose_all_data, the same two-tier-cap
// pattern PROFINET RT's DCP blocks use -- see profinet.cpp's kMaxDcpBlocks vs decoder.cpp's
// kMaxDcpBlockValues).
// CLI-configurable via --max-recursion-depth/--max-decoded-objects -- see resource_limits.hpp.
// 0/unset keeps each literal default below. Functions rather than constexpr/const namespace-
// scope values, since they now read process-wide configuration.
int max_goose_data_depth() { return static_cast<int>(resource_limits().max_recursion_depth.value_or(6)); }
size_t max_goose_data_values() { return resource_limits().max_decoded_objects.value_or(200); }

std::string ascii_text(ByteSpan s) {
    std::string text;
    text.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) text += static_cast<char>(s.at(i));
    return text;
}

// Reads one BER length (short form: a single byte 0-127; long form: a byte with the top bit set
// whose low 7 bits give how many big-endian length bytes follow). Returns std::nullopt for the
// indefinite-length form (a length byte of exactly 0x80) -- not supported, see goose.hpp's file
// header comment -- or for an implausibly large length-of-length (>4 bytes, i.e. claiming a
// length that can't fit in a 32-bit count anyway), or if the buffer doesn't hold as many length
// bytes as claimed.
std::optional<size_t> read_ber_length(Cursor& c) {
    if (c.remaining() < 1) return std::nullopt;
    uint8_t first = c.u8();
    if ((first & 0x80) == 0) return static_cast<size_t>(first);
    uint8_t n = first & 0x7F;
    if (n == 0 || n > 4) return std::nullopt;
    if (c.remaining() < n) return std::nullopt;
    size_t val = 0;
    for (uint8_t i = 0; i < n; ++i) val = (val << 8) | c.u8();
    return val;
}

// Arbitrary-length big-endian two's-complement BER INTEGER, up to 8 bytes (sign-extended from the
// first content byte's high bit). std::nullopt for an empty or >8-byte value -- see goose.hpp's
// file header comment's allData paragraph (integer/unsigned/bcd all decode this way).
std::optional<int64_t> decode_ber_integer(ByteSpan content) {
    if (content.empty() || content.size() > 8) return std::nullopt;
    bool negative = (content.at(0) & 0x80) != 0;
    uint64_t uv = 0;
    for (size_t i = 0; i < content.size(); ++i) uv = (uv << 8) | content.at(i);
    if (negative && content.size() < 8) {
        uint64_t mask = ~((uint64_t(1) << (content.size() * 8)) - 1);
        uv |= mask;
    }
    return static_cast<int64_t>(uv);
}

std::string decode_integer_str(ByteSpan content) {
    auto v = decode_ber_integer(content);
    if (!v) return "(too long to decode, " + std::to_string(content.size()) + " byte(s)) raw=" + to_hex(content);
    return std::to_string(*v);
}

bool decode_boolean(ByteSpan content) { return !content.empty() && content.at(0) != 0; }

std::string decode_boolean_str(ByteSpan content) {
    if (content.empty()) return "(empty, malformed)";
    return decode_boolean(content) ? "true" : "false";
}

// BER BIT STRING: first content byte = count of unused bits (0-7) in the last content byte,
// remaining bytes = the bit data itself, MSB-first -- see goose.hpp's file header comment's
// allData paragraph. Rendered as both the total bit count and a binary-digit string (real GOOSE
// BIT STRING values are almost always a short, individually-meaningful IEC 61850-7-3 status
// field -- see that comment).
std::string decode_bitstring_str(ByteSpan content) {
    if (content.empty()) return "(empty, malformed)";
    uint8_t unused = content.at(0);
    size_t data_bytes = content.size() - 1;
    if (unused > 7 || (data_bytes == 0 && unused != 0)) {
        return "(malformed unused-bit count " + hex2(unused) + ") raw=" + to_hex(content);
    }
    size_t total_bits = data_bytes * 8 - unused;
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 256 default.
    const size_t kMaxRenderedBits = resource_limits().max_decoded_objects.value_or(256);
    std::ostringstream s;
    size_t bits_to_render = std::min(total_bits, kMaxRenderedBits);
    for (size_t i = 0; i < bits_to_render; ++i) {
        size_t byte_idx = 1 + i / 8;
        int bit_in_byte = 7 - static_cast<int>(i % 8);
        bool bit = (content.at(byte_idx) >> bit_in_byte) & 1;
        s << (bit ? '1' : '0');
    }
    std::ostringstream out;
    out << total_bits << "-bit 0b" << s.str();
    if (total_bits > kMaxRenderedBits) out << "...(truncated)";
    return out.str();
}

// IEC 61850-7-2 FloatingPoint: an OCTET STRING whose first byte is the IEEE 754 exponent width in
// bits, followed by the value itself, big-endian. See goose.hpp's file header comment's allData
// paragraph for which of the two cases below is Wireshark-confirmed (single) vs. extended from the
// same documented rule but not independently confirmed (double).
std::string decode_floating_point_str(ByteSpan content) {
    if (content.size() == 5 && content.at(0) == 8) {
        uint32_t bits = 0;
        for (size_t i = 1; i < 5; ++i) bits = (bits << 8) | content.at(i);
        float f;
        std::memcpy(&f, &bits, sizeof(f));
        std::ostringstream s;
        s << f << "f (single precision)";
        return s.str();
    }
    if (content.size() == 9 && content.at(0) == 11) {
        uint64_t bits = 0;
        for (size_t i = 1; i < 9; ++i) bits = (bits << 8) | content.at(i);
        double d;
        std::memcpy(&d, &bits, sizeof(d));
        std::ostringstream s;
        s << d << " (double precision)";
        return s.str();
    }
    return "(unrecognized floating-point encoding, exponent-width byte=" + hex2(content.at(0)) +
           " len=" + std::to_string(content.size()) + ") raw=" + to_hex(content);
}

struct UtcTimeFields {
    uint32_t seconds = 0;
    uint32_t fraction_ns = 0;
    bool leap_seconds_known = false;
    bool clock_failure = false;
    bool clock_not_synchronized = false;
    uint8_t time_accuracy = 0;
};

// UtcTime: Seconds(4, big-endian) + Fraction-of-second(3, big-endian) + TimeQuality(1) -- see
// goose.hpp's file header comment's UtcTime paragraph for the TimeQuality bit layout and its
// provenance. Fraction-to-nanoseconds scaling matches Wireshark's own dissect_goose_UtcTime.
bool decode_utctime(ByteSpan content, UtcTimeFields& out) {
    if (content.size() != 8) return false;
    Cursor c(content);
    out.seconds = c.u32be();
    uint32_t fraction24 = (static_cast<uint32_t>(c.u8()) << 16) | (static_cast<uint32_t>(c.u8()) << 8) | c.u8();
    uint64_t fraction32 = static_cast<uint64_t>(fraction24) * 256ULL;
    out.fraction_ns = static_cast<uint32_t>((fraction32 * 1000000000ULL) / 4294967296ULL);
    uint8_t q = c.u8();
    out.leap_seconds_known = (q & 0x80) != 0;
    out.clock_failure = (q & 0x40) != 0;
    out.clock_not_synchronized = (q & 0x20) != 0;
    out.time_accuracy = q & 0x1F;
    return true;
}

std::string render_utctime(const UtcTimeFields& t) {
    std::ostringstream s;
    s << t.seconds << "." << std::setw(9) << std::setfill('0') << t.fraction_ns << "s accuracy="
      << static_cast<unsigned>(t.time_accuracy) << "-bit";
    std::vector<std::string> flags;
    if (t.leap_seconds_known) flags.push_back("LeapSecondsKnown");
    if (t.clock_failure) flags.push_back("ClockFailure");
    if (t.clock_not_synchronized) flags.push_back("ClockNotSynchronized");
    if (!flags.empty()) {
        s << " [";
        for (size_t i = 0; i < flags.size(); ++i) {
            if (i != 0) s << ",";
            s << flags[i];
        }
        s << "]";
    }
    return s.str();
}

std::string decode_utctime_str(ByteSpan content) {
    UtcTimeFields t;
    if (!decode_utctime(content, t)) {
        return "(malformed, expected 8 bytes, got " + std::to_string(content.size()) + ") raw=" + to_hex(content);
    }
    return render_utctime(t);
}

// Renders the human-readable "GOOSE Data choice" type name for a Data-choice tag byte (see
// goose.hpp's file header comment's allData paragraph) -- empty for a tag this decoder doesn't
// recognize at all (the value is then raw hex, never guessed at).
std::string data_type_name(uint8_t tag) {
    switch (tag) {
        case 0xA1: return "array";
        case 0xA2: return "structure";
        case 0x83: return "boolean";
        case 0x84: return "bit-string";
        case 0x85: return "integer";
        case 0x86: return "unsigned";
        case 0x87: return "floating-point";
        case 0x88: return "real";
        case 0x89: return "octet-string";
        case 0x8A: return "visible-string";
        case 0x8C: return "binary-time";
        case 0x8D: return "bcd";
        case 0x8E: return "booleanArray";
        case 0x8F: return "objId";
        case 0x90: return "mMSString";
        case 0x91: return "utc-time";
        default: return "";
    }
}

bool is_container_tag(uint8_t tag) { return tag == 0xA1 || tag == 0xA2; }

// Renders a non-container Data value's content -- see goose.hpp's file header comment's allData
// paragraph for which tags are fully value-decoded vs. named-but-raw-hex vs. entirely unrecognized.
std::string render_data_value(uint8_t tag, ByteSpan content) {
    switch (tag) {
        case 0x83: return decode_boolean_str(content);
        case 0x84:
        case 0x8E: return decode_bitstring_str(content);
        case 0x85:
        case 0x86:
        case 0x8D: return decode_integer_str(content);
        case 0x87: return decode_floating_point_str(content);
        case 0x8A:
        case 0x90: return ascii_text(content);
        case 0x91: return decode_utctime_str(content);
        // 0x88 (real), 0x89 (octet-string), 0x8C (binary-time), 0x8F (objId), and anything
        // unrecognized: named (if recognized at all) but never value-decoded -- see this file's
        // header comment's allData paragraph for why.
        default: return to_hex(content);
    }
}

// Recursively walks one allData (or nested array/structure) region, appending one flattened
// GooseDataValue per entry -- see goose.hpp's file header comment's allData paragraph and
// GooseDataValue's own comment for the dotted `path` scheme. `budget` is shared across the whole
// recursion (max_goose_data_values()) so a deeply-nested or very wide dataset can't blow past it.
void decode_data_sequence(ByteSpan region, const std::string& path_prefix, int depth,
                            std::vector<GooseDataValue>& out, size_t& budget, std::vector<std::string>& notes) {
    Cursor c(region);
    int index = 0;
    while (c.remaining() >= 2 && budget > 0) {
        uint8_t tag = c.u8();
        auto length = read_ber_length(c);
        if (!length) {
            notes.push_back("allData entry at " + path_prefix + (path_prefix.empty() ? "" : ".") +
                             std::to_string(index) + ": malformed/unsupported BER length -- stopping this level");
            break;
        }
        if (*length > c.remaining()) {
            notes.push_back("allData entry at " + path_prefix + (path_prefix.empty() ? "" : ".") +
                             std::to_string(index) + " declares " + std::to_string(*length) +
                             " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping this level");
            break;
        }
        ByteSpan content = c.bytes(*length);
        std::string path = path_prefix.empty() ? std::to_string(index) : path_prefix + "." + std::to_string(index);
        --budget;

        GooseDataValue v;
        v.path = path;
        v.type_name = data_type_name(tag);
        bool container = is_container_tag(tag);
        if (!container) v.value = render_data_value(tag, content);
        size_t container_index = out.size();
        out.push_back(v);

        if (container) {
            if (depth + 1 <= max_goose_data_depth()) {
                size_t children_before = out.size();
                decode_data_sequence(content, path, depth + 1, out, budget, notes);
                size_t children_added = out.size() - children_before;
                out[container_index].value = "(" + std::to_string(children_added) + " flattened value(s) follow)";
            } else {
                out[container_index].value = "(nesting exceeds max depth " + std::to_string(max_goose_data_depth()) +
                                              " -- not decoded further)";
                notes.push_back("allData[" + path + "]: nesting exceeds max depth (" +
                                 std::to_string(max_goose_data_depth()) + ") -- not decoded further");
            }
        }
        ++index;
    }
    if (budget == 0 && c.remaining() >= 2) {
        notes.push_back("allData: stopped after " + std::to_string(max_goose_data_values()) +
                         " value(s) (safety cap)");
    }
}

void decode_goose_pdu(ByteSpan pdu_content, GooseFrame& frame) {
    Cursor c(pdu_content);
    size_t budget = max_goose_data_values();
    while (c.remaining() >= 2) {
        uint8_t tag = c.u8();
        auto length = read_ber_length(c);
        if (!length) {
            frame.notes.push_back("GOOSE PDU field tag=" + hex2(tag) +
                                   ": malformed/unsupported BER length -- stopping");
            break;
        }
        if (*length > c.remaining()) {
            frame.notes.push_back("GOOSE PDU field tag=" + hex2(tag) + " declares " + std::to_string(*length) +
                                   " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan content = c.bytes(*length);
        switch (tag) {
            case 0x80: frame.gocb_ref = ascii_text(content); break;
            case 0x81: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.time_allowed_to_live = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("timeAllowedtoLive too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0x82: frame.dat_set = ascii_text(content); break;
            case 0x83: frame.go_id = ascii_text(content); break;
            case 0x84: {
                UtcTimeFields t;
                if (decode_utctime(content, t)) {
                    frame.has_timestamp = true;
                    frame.t_seconds = t.seconds;
                    frame.t_fraction_ns = t.fraction_ns;
                    frame.t_leap_seconds_known = t.leap_seconds_known;
                    frame.t_clock_failure = t.clock_failure;
                    frame.t_clock_not_synchronized = t.clock_not_synchronized;
                    frame.t_time_accuracy = t.time_accuracy;
                } else {
                    frame.notes.push_back("timestamp field 't' malformed (expected 8 bytes, got " +
                                           std::to_string(content.size()) + ") -- not decoded");
                }
                break;
            }
            case 0x85: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.st_num = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("stNum too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0x86: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.sq_num = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("sqNum too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0x87: frame.simulation = decode_boolean(content); break;
            case 0x88: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.conf_rev = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("confRev too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0x89: frame.nds_com = decode_boolean(content); break;
            case 0x8A: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.num_dat_set_entries = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("numDatSetEntries too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0xAB: decode_data_sequence(content, "", 0, frame.all_data, budget, frame.notes); break;
            default:
                frame.notes.push_back("unrecognized GOOSE PDU field tag=" + hex2(tag) + " len=" +
                                       std::to_string(content.size()) + " -- skipped, raw hex: " + to_hex(content));
                break;
        }
    }

    size_t top_level_count = 0;
    for (const auto& v : frame.all_data) {
        if (v.path.find('.') == std::string::npos) ++top_level_count;
    }
    if (frame.num_dat_set_entries != top_level_count) {
        frame.notes.push_back("numDatSetEntries declares " + std::to_string(frame.num_dat_set_entries) + " but " +
                               std::to_string(top_level_count) + " top-level Data value(s) were actually found in allData");
    }
    for (const auto& v : frame.all_data) {
        if (v.type_name.empty()) {
            frame.notes.push_back("allData[" + v.path + "]: tag not recognized -- raw hex: " + v.value);
        }
    }
}

}  // namespace

std::optional<GooseFrame> try_parse_goose(ByteSpan eth_payload) {
    if (eth_payload.size() < 8 + 2) {
        return std::nullopt;
    }
    try {
        Cursor c(eth_payload);
        uint16_t appid = c.u16be();
        uint16_t declared_length = c.u16be();
        uint16_t reserved1 = c.u16be();
        c.u16be();  // Reserved2 -- not surfaced, see goose.hpp's file header comment

        size_t available = eth_payload.size();
        size_t apdu_region_end;
        std::vector<std::string> pending_notes;
        if (declared_length >= 8 && declared_length <= available) {
            apdu_region_end = declared_length;
        } else {
            apdu_region_end = available;
            pending_notes.push_back("Length field (" + std::to_string(declared_length) +
                                     ") is implausible (must be >= 8 and <= the " + std::to_string(available) +
                                     " byte(s) actually present) -- using all available bytes instead");
        }
        if (apdu_region_end < 10) {
            return std::nullopt;  // not even room for an outer tag + a length byte
        }

        ByteSpan apdu_area = eth_payload.subspan(8, apdu_region_end - 8);
        uint8_t outer_tag = apdu_area.at(0);
        if (outer_tag != 0x61 && outer_tag != 0xA0) {
            return std::nullopt;  // not GOOSE -- see try_parse_goose's own header comment
        }

        Cursor ac(apdu_area);
        ac.u8();  // outer_tag, re-read through the cursor
        auto len = read_ber_length(ac);
        if (!len) {
            return std::nullopt;  // can't even read a length -- not confidently GOOSE
        }

        GooseFrame frame;
        frame.appid = appid;
        frame.declared_length = declared_length;
        frame.header_simulated = (reserved1 & 0x8000) != 0;
        for (auto& n : pending_notes) frame.notes.push_back(n);

        // The outer APDU TLV's own declared length may exceed what's actually present -- most
        // plausibly a snaplen-truncated real capture, not evidence this isn't GOOSE at all (the
        // outer tag byte already matched with high specificity). Decode what's present and note
        // the truncation, the same tolerant "note and decode what's present" posture PROFINET
        // RT's DCP decoder takes for its own DCPDataLength (see profinet.cpp's decode_dcp).
        size_t effective_len = std::min(*len, ac.remaining());
        if (effective_len < *len) {
            frame.notes.push_back("GOOSE APDU declares " + std::to_string(*len) + " byte(s) but only " +
                                   std::to_string(ac.remaining()) + " remain -- decoding what's present");
        }
        ByteSpan pdu_content = ac.bytes(effective_len);

        if (outer_tag == 0xA0) {
            frame.is_gse_management = true;
            frame.summary = "GOOSE: GSE Management PDU (appid=" + hex4(appid) + ") -- not decoded further";
        } else {
            frame.has_pdu = true;
            decode_goose_pdu(pdu_content, frame);

            if (frame.header_simulated && frame.simulation.has_value() && !*frame.simulation) {
                frame.notes.push_back(
                    "header S-bit (Reserved1 0x8000, \"Simulated\") is set but the PDU's own simulation field is "
                    "false -- inconsistent, possibly a malformed or spoofed frame (cross-checked against "
                    "Wireshark's own ei_goose_invalid_sim check -- see goose.hpp's file header comment)");
            }

            std::ostringstream s;
            s << "GOOSE " << frame.gocb_ref;
            if (frame.go_id) s << " goID=\"" << *frame.go_id << "\"";
            s << " stNum=" << frame.st_num << " sqNum=" << frame.sq_num << " confRev=" << frame.conf_rev;
            if (frame.header_simulated || (frame.simulation && *frame.simulation)) s << " [SIMULATED]";
            frame.summary = s.str();
        }

        if (ac.position() < apdu_area.size()) {
            frame.notes.push_back(std::to_string(apdu_area.size() - ac.position()) +
                                   " byte(s) remain inside this frame's declared Length after the first GOOSE "
                                   "APDU -- more than one APDU packed into one frame is out of this release's "
                                   "scope (see goose.hpp's file header comment), not decoded");
        }

        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // profinet.cpp's try_parse_profinet takes.
        return std::nullopt;
    }
}

std::optional<ProtocolResult> GooseDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    if (auto gs = try_parse_goose(payload)) {
        return ProtocolResult::make<GooseFrame>("goose", std::move(*gs));
    }
    return std::nullopt;
}

const ProtocolDecoder& goose_decoder() {
    static const GooseDecoder instance;
    return instance;
}

}  // namespace conduitscope
