// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/sv.hpp"

#include "conduitscope/resource_limits.hpp"

#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

std::string hex4(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(4) << std::setfill('0') << v;
    return s.str();
}

std::string hex2(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setw(2) << std::setfill('0') << static_cast<unsigned>(v);
    return s.str();
}

// Safety cap against a malformed/adversarial capture declaring an implausible number of ASDUs --
// see sv.hpp's file header comment. There is no per-ASDU nesting (unlike GOOSE's allData), so a
// single flat cap on the ASDU count is enough.
// CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
// literal 200 default.
size_t max_sv_asdus() { return resource_limits().max_decoded_objects.value_or(200); }

std::string ascii_text(ByteSpan s) {
    std::string text;
    text.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) text += static_cast<char>(s.at(i));
    return text;
}

// Identical BER length reader to goose.cpp's -- see that file's comment for the exact rules
// (short/long form, indefinite-length and >4-byte length-of-length rejected).
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

// Identical arbitrary-length big-endian two's-complement BER INTEGER reader to goose.cpp's --
// every SV integer field (noASDU, smpCnt, confRev, smpSynch, smpRate, smpMod) decodes this way.
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

struct UtcTimeFields {
    uint32_t seconds = 0;
    uint32_t fraction_ns = 0;
    bool leap_seconds_known = false;
    bool clock_failure = false;
    bool clock_not_synchronized = false;
    uint8_t time_accuracy = 0;
};

// Identical UtcTime decode to goose.cpp's -- see sv.hpp's file header comment's refrTm paragraph
// and goose.hpp's UtcTime paragraph for the encoding and its provenance.
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

// smpSynch's rendered name -- cross-checked against packet-sv.c's sv_T_smpSynch_vals. See
// sv.hpp's file header comment's ASDU field table.
std::string smp_synch_name(int64_t v) {
    switch (v) {
        case 0: return "none";
        case 1: return "local";
        case 2: return "global";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// smpMod's rendered name -- cross-checked against packet-sv.c's sv_T_smpMod_vals.
std::string smp_mod_name(int64_t v) {
    switch (v) {
        case 0: return "samplesPerNormalPeriod";
        case 1: return "samplesPerSecond";
        case 2: return "secondsPerSample";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// Decodes one ASDU's own fields (ASDU_sequence -- see sv.hpp's file header comment's ASDU field
// table) from `content`, the bytes inside one 0x30-tagged SEQUENCE element of seqASDU.
SvAsdu decode_asdu(ByteSpan content, std::vector<std::string>& notes) {
    SvAsdu asdu;
    Cursor c(content);
    while (c.remaining() >= 2) {
        uint8_t tag = c.u8();
        auto length = read_ber_length(c);
        if (!length) {
            notes.push_back("ASDU field tag=" + hex2(tag) + ": malformed/unsupported BER length -- stopping");
            break;
        }
        if (*length > c.remaining()) {
            notes.push_back("ASDU field tag=" + hex2(tag) + " declares " + std::to_string(*length) +
                             " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan field = c.bytes(*length);
        switch (tag) {
            case 0x80: asdu.sv_id = ascii_text(field); break;
            case 0x81: asdu.dat_set = ascii_text(field); break;
            case 0x82: {
                auto v = decode_ber_integer(field);
                if (v) {
                    asdu.smp_cnt = static_cast<uint64_t>(*v);
                } else {
                    notes.push_back("smpCnt too long to decode (" + std::to_string(field.size()) +
                                     " byte(s)) -- raw hex: " + to_hex(field));
                }
                break;
            }
            case 0x83: {
                auto v = decode_ber_integer(field);
                if (v) {
                    asdu.conf_rev = static_cast<uint64_t>(*v);
                } else {
                    notes.push_back("confRev too long to decode (" + std::to_string(field.size()) +
                                     " byte(s)) -- raw hex: " + to_hex(field));
                }
                break;
            }
            case 0x84: {
                UtcTimeFields t;
                if (decode_utctime(field, t)) {
                    asdu.has_refr_tm = true;
                    asdu.refr_tm_seconds = t.seconds;
                    asdu.refr_tm_fraction_ns = t.fraction_ns;
                    asdu.refr_tm_leap_seconds_known = t.leap_seconds_known;
                    asdu.refr_tm_clock_failure = t.clock_failure;
                    asdu.refr_tm_clock_not_synchronized = t.clock_not_synchronized;
                    asdu.refr_tm_time_accuracy = t.time_accuracy;
                } else {
                    notes.push_back("refrTm malformed (expected 8 bytes, got " + std::to_string(field.size()) +
                                     ") -- not decoded");
                }
                break;
            }
            case 0x85: {
                auto v = decode_ber_integer(field);
                if (v) {
                    asdu.smp_synch = smp_synch_name(*v);
                } else {
                    notes.push_back("smpSynch too long to decode (" + std::to_string(field.size()) +
                                     " byte(s)) -- raw hex: " + to_hex(field));
                }
                break;
            }
            case 0x86: {
                auto v = decode_ber_integer(field);
                if (v) {
                    asdu.smp_rate = static_cast<uint64_t>(*v);
                } else {
                    notes.push_back("smpRate too long to decode (" + std::to_string(field.size()) +
                                     " byte(s)) -- raw hex: " + to_hex(field));
                }
                break;
            }
            case 0x87:
                asdu.seq_data_hex = to_hex(field, "");
                asdu.seq_data_length = field.size();
                break;
            case 0x88: {
                auto v = decode_ber_integer(field);
                if (v) {
                    asdu.smp_mod = smp_mod_name(*v);
                } else {
                    notes.push_back("smpMod too long to decode (" + std::to_string(field.size()) +
                                     " byte(s)) -- raw hex: " + to_hex(field));
                }
                break;
            }
            case 0x89:
                if (field.size() != 8) {
                    notes.push_back("gmidData malformed (expected 8 bytes, got " + std::to_string(field.size()) +
                                     ") -- shown as raw hex anyway");
                }
                asdu.gmid_hex = to_hex(field, "");
                break;
            default:
                notes.push_back("unrecognized ASDU field tag=" + hex2(tag) + " len=" + std::to_string(field.size()) +
                                 " -- skipped, raw hex: " + to_hex(field));
                break;
        }
    }
    return asdu;
}

// Decodes SavPdu's own two fields (noASDU, seqASDU -- see sv.hpp's file header comment) from
// `pdu_content`. Each seqASDU element carries its own standard ASN.1 UNIVERSAL SEQUENCE tag
// (0x30), unlike GOOSE's allData Data-choice entries which nest directly with no per-item wrapper
// -- see sv.hpp's file header comment for why.
void decode_sav_pdu(ByteSpan pdu_content, SvFrame& frame) {
    Cursor c(pdu_content);
    while (c.remaining() >= 2) {
        uint8_t tag = c.u8();
        auto length = read_ber_length(c);
        if (!length) {
            frame.notes.push_back("SavPdu field tag=" + hex2(tag) + ": malformed/unsupported BER length -- stopping");
            break;
        }
        if (*length > c.remaining()) {
            frame.notes.push_back("SavPdu field tag=" + hex2(tag) + " declares " + std::to_string(*length) +
                                   " byte(s) but only " + std::to_string(c.remaining()) + " remain -- stopping");
            break;
        }
        ByteSpan content = c.bytes(*length);
        switch (tag) {
            case 0x80: {
                auto v = decode_ber_integer(content);
                if (v) {
                    frame.no_asdu = static_cast<uint64_t>(*v);
                } else {
                    frame.notes.push_back("noASDU too long to decode (" + std::to_string(content.size()) +
                                           " byte(s)) -- raw hex: " + to_hex(content));
                }
                break;
            }
            case 0xA2: {
                Cursor sc(content);
                while (sc.remaining() >= 2 && frame.asdus.size() < max_sv_asdus()) {
                    uint8_t element_tag = sc.u8();
                    auto element_length = read_ber_length(sc);
                    if (!element_length) {
                        frame.notes.push_back("seqASDU element: malformed/unsupported BER length -- stopping");
                        break;
                    }
                    if (*element_length > sc.remaining()) {
                        frame.notes.push_back("seqASDU element declares " + std::to_string(*element_length) +
                                               " byte(s) but only " + std::to_string(sc.remaining()) +
                                               " remain -- stopping");
                        break;
                    }
                    ByteSpan element_content = sc.bytes(*element_length);
                    if (element_tag != 0x30) {
                        frame.notes.push_back("seqASDU element tag=" + hex2(element_tag) +
                                               " is not the expected UNIVERSAL SEQUENCE tag (0x30) -- skipped");
                        continue;
                    }
                    frame.asdus.push_back(decode_asdu(element_content, frame.notes));
                }
                if (frame.asdus.size() >= max_sv_asdus() && sc.remaining() >= 2) {
                    frame.notes.push_back("seqASDU: stopped after " + std::to_string(max_sv_asdus()) +
                                           " ASDU(s) (safety cap)");
                }
                break;
            }
            default:
                frame.notes.push_back("unrecognized SavPdu field tag=" + hex2(tag) + " len=" +
                                       std::to_string(content.size()) + " -- skipped, raw hex: " + to_hex(content));
                break;
        }
    }

    if (frame.no_asdu != frame.asdus.size()) {
        frame.notes.push_back("noASDU declares " + std::to_string(frame.no_asdu) + " but " +
                               std::to_string(frame.asdus.size()) + " ASDU(s) were actually found in seqASDU");
    }
}

}  // namespace

std::optional<SvFrame> try_parse_sv(ByteSpan eth_payload) {
    if (eth_payload.size() < 8 + 2) {
        return std::nullopt;
    }
    try {
        Cursor c(eth_payload);
        uint16_t appid = c.u16be();
        uint16_t declared_length = c.u16be();
        uint16_t reserved1 = c.u16be();
        c.u16be();  // Reserved2 -- not surfaced, see sv.hpp's file header comment

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
        if (outer_tag != 0x60) {
            return std::nullopt;  // not SV -- see try_parse_sv's own header comment
        }

        Cursor ac(apdu_area);
        ac.u8();  // outer_tag, re-read through the cursor
        auto len = read_ber_length(ac);
        if (!len) {
            return std::nullopt;  // can't even read a length -- not confidently SV
        }

        SvFrame frame;
        frame.appid = appid;
        frame.declared_length = declared_length;
        frame.header_simulated = (reserved1 & 0x8000) != 0;
        for (auto& n : pending_notes) frame.notes.push_back(n);

        // Same tolerant truncation handling as GOOSE (see goose.cpp's try_parse_goose): a matched
        // outer tag is already strong evidence this is SV, so a length mismatch here is far more
        // likely a snaplen-truncated real capture than a false positive.
        size_t effective_len = std::min(*len, ac.remaining());
        if (effective_len < *len) {
            frame.notes.push_back("SV APDU declares " + std::to_string(*len) + " byte(s) but only " +
                                   std::to_string(ac.remaining()) + " remain -- decoding what's present");
        }
        ByteSpan pdu_content = ac.bytes(effective_len);

        decode_sav_pdu(pdu_content, frame);

        std::ostringstream s;
        if (frame.asdus.empty()) {
            s << "SV appid=" << hex4(appid) << " noASDU=" << frame.no_asdu << " (0 ASDU(s) decoded)";
        } else {
            const SvAsdu& first = frame.asdus[0];
            s << "SV " << first.sv_id;
            if (first.dat_set) s << " datSet=\"" << *first.dat_set << "\"";
            s << " smpCnt=" << first.smp_cnt << " confRev=" << first.conf_rev;
            if (first.smp_synch) s << " smpSynch=" << *first.smp_synch;
            if (frame.asdus.size() > 1) s << " (+" << (frame.asdus.size() - 1) << " more ASDU(s))";
        }
        if (frame.header_simulated) s << " [SIMULATED]";
        frame.summary = s.str();

        if (ac.position() < apdu_area.size()) {
            frame.notes.push_back(std::to_string(apdu_area.size() - ac.position()) +
                                   " byte(s) remain inside this frame's declared Length after the first SV "
                                   "APDU -- more than one APDU packed into one frame is out of this release's "
                                   "scope (see sv.hpp's file header comment), not decoded");
        }

        return frame;
    } catch (const ParseError&) {
        // Every read above is preceded by an explicit bounds check, so this should be
        // unreachable -- caught defensively anyway, the same belt-and-suspenders posture
        // goose.cpp's try_parse_goose and profinet.cpp's try_parse_profinet take.
        return std::nullopt;
    }
}

}  // namespace conduitscope
