// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/iec104.hpp"

#include "conduitscope/resource_limits.hpp"

#include <cstring>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// --- APCI helpers ---------------------------------------------------------

std::string u_function_name(uint8_t c0) {
    switch (c0) {
        case 0x07: return "STARTDT act";
        case 0x0B: return "STARTDT con";
        case 0x13: return "STOPDT act";
        case 0x23: return "STOPDT con";
        case 0x43: return "TESTFR act";
        case 0x83: return "TESTFR con";
        default: {
            std::ostringstream s;
            s << "Unknown (0x" << std::hex << std::uppercase << static_cast<unsigned>(c0) << ")";
            return s.str();
        }
    }
}

// --- ASDU header naming tables --------------------------------------------

// The single table backing iec104_type_name(uint8_t) (this file, anonymous-namespace-internal),
// the exported iec104_type_short_name(uint8_t), and iec104_known_asdu_short_names() -- one place
// ("type ID N means this mnemonic/description") asserts the mapping, not several. `short_name` is
// the mnemonic conduitscope's policy-matching feature (policy.cpp/PolicyEngine) matches a
// 'functions:' entry against; `description` is only ever shown composed into type_name's
// parenthetical, never on its own.
struct Iec104TypeEntry {
    uint8_t type_id;
    const char* short_name;
    const char* description;
};

constexpr Iec104TypeEntry kIec104Types[] = {
    {1, "M_SP_NA_1", "Single-point information"},
    {2, "M_SP_TA_1", "Single-point information with time tag"},
    {30, "M_SP_TB_1", "Single-point information with time tag CP56Time2a"},
    {3, "M_DP_NA_1", "Double-point information"},
    {4, "M_DP_TA_1", "Double-point information with time tag"},
    {31, "M_DP_TB_1", "Double-point information with time tag CP56Time2a"},
    {5, "M_ST_NA_1", "Step position information"},
    {6, "M_ST_TA_1", "Step position information with time tag"},
    {32, "M_ST_TB_1", "Step position information with time tag CP56Time2a"},
    {7, "M_BO_NA_1", "Bitstring of 32 bit"},
    {8, "M_BO_TA_1", "Bitstring of 32 bit with time tag"},
    {33, "M_BO_TB_1", "Bitstring of 32 bit with time tag CP56Time2a"},
    {9, "M_ME_NA_1", "Measured value, normalized value"},
    {34, "M_ME_TD_1", "Measured value, normalized value with time tag CP56Time2a"},
    {10, "M_ME_TA_1", "Measured value, normalized value with time tag"},
    {11, "M_ME_NB_1", "Measured value, scaled value"},
    {35, "M_ME_TE_1", "Measured value, scaled value with time tag CP56Time2a"},
    {12, "M_ME_TB_1", "Measured value, scaled value with time tag"},
    {13, "M_ME_NC_1", "Measured value, short floating point"},
    {36, "M_ME_TF_1", "Measured value, short floating point with time tag CP56Time2a"},
    {14, "M_ME_TC_1", "Measured value, short floating point with time tag"},
    {21, "M_ME_ND_1", "Measured value, normalized value without quality descriptor"},
    {15, "M_IT_NA_1", "Integrated totals"},
    {37, "M_IT_TB_1", "Integrated totals with time tag CP56Time2a"},
    {16, "M_IT_TA_1", "Integrated totals with time tag"},
    {45, "C_SC_NA_1", "Single command"},
    {58, "C_SC_TA_1", "Single command with time tag CP56Time2a"},
    {46, "C_DC_NA_1", "Double command"},
    {59, "C_DC_TA_1", "Double command with time tag CP56Time2a"},
    {47, "C_RC_NA_1", "Regulating step command"},
    {60, "C_RC_TA_1", "Regulating step command with time tag CP56Time2a"},
    {48, "C_SE_NA_1", "Set point command, normalized value"},
    {61, "C_SE_TA_1", "Set point command, normalized value with time tag CP56Time2a"},
    {49, "C_SE_NB_1", "Set point command, scaled value"},
    {62, "C_SE_TB_1", "Set point command, scaled value with time tag CP56Time2a"},
    {50, "C_SE_NC_1", "Set point command, short floating point"},
    {63, "C_SE_TC_1", "Set point command, short floating point with time tag CP56Time2a"},
    {51, "C_BO_NA_1", "Bitstring of 32 bit command"},
    {64, "C_BO_TA_1", "Bitstring of 32 bit command with time tag CP56Time2a"},
    {70, "M_EI_NA_1", "End of initialization"},
    {100, "C_IC_NA_1", "Interrogation command"},
    {101, "C_CI_NA_1", "Counter interrogation command"},
    {102, "C_RD_NA_1", "Read command"},
    {103, "C_CS_NA_1", "Clock synchronization command"},
    {105, "C_RP_NA_1", "Reset process command"},
    {106, "C_CD_NA_1", "Delay acquisition command"},
    {107, "C_TS_TA_1", "Test command with time tag CP56Time2a"},
    {110, "P_ME_NA_1", "Parameter of measured value, normalized value"},
    {111, "P_ME_NB_1", "Parameter of measured value, scaled value"},
    {112, "P_ME_NC_1", "Parameter of measured value, short floating point"},
    {113, "P_AC_NA_1", "Parameter activation"},
};

const Iec104TypeEntry* find_iec104_type(uint8_t type_id) {
    for (const auto& entry : kIec104Types) {
        if (entry.type_id == type_id) return &entry;
    }
    return nullptr;
}

std::string iec104_type_name(uint8_t type_id) {
    if (const auto* entry = find_iec104_type(type_id)) {
        return std::string(entry->short_name) + " (" + entry->description + ")";
    }
    std::ostringstream s;
    s << "Unknown (type " << static_cast<unsigned>(type_id) << ")";
    return s.str();
}

std::string iec104_cot_name(uint8_t cot) {
    switch (cot) {
        case 1: return "periodic, cyclic";
        case 2: return "background scan";
        case 3: return "spontaneous";
        case 4: return "initialized";
        case 5: return "request or requested";
        case 6: return "activation";
        case 7: return "activation confirmation";
        case 8: return "deactivation";
        case 9: return "deactivation confirmation";
        case 10: return "activation termination";
        case 11: return "return information caused by a remote command";
        case 12: return "return information caused by a local command";
        case 13: return "file transfer";
        case 20: return "interrogated by station interrogation";
        case 37: return "requested by general counter request";
        case 44: return "unknown type identification";
        case 45: return "unknown cause of transmission";
        case 46: return "unknown common address of ASDU";
        case 47: return "unknown information object address";
        default:
            if (cot >= 21 && cot <= 36) {
                return "interrogated by group " + std::to_string(cot - 20) + " interrogation";
            }
            if (cot >= 38 && cot <= 41) {
                return "requested by group " + std::to_string(cot - 37) + " counter request";
            }
            return "Unknown/reserved (" + std::to_string(static_cast<unsigned>(cot)) + ")";
    }
}

// True for every ASDU type ID whose information elements this file knows how to decode -- see
// decode_iec104_element below and the file header comment for the type list.
bool iec104_type_is_decoded(uint8_t type_id) {
    switch (type_id) {
        case 1: case 2: case 30: case 3: case 4: case 31: case 5: case 6: case 32: case 7:
        case 8: case 33: case 9: case 34: case 10: case 11: case 35: case 12: case 13: case 36:
        case 14: case 21: case 15: case 37: case 16: case 45: case 58: case 46: case 59: case 47:
        case 60: case 48: case 61: case 49: case 62: case 50: case 63: case 51: case 64: case 70:
        case 100: case 103: case 105: case 106: case 107: case 110: case 111: case 112: case 113:
            return true;
        default:
            return false;
    }
}

// --- Information-element field decoding -----------------------------------

uint32_t read_u24le(Cursor& c) {
    uint32_t b0 = c.u8();
    uint32_t b1 = c.u8();
    uint32_t b2 = c.u8();
    return b0 | (b1 << 8) | (b2 << 16);
}

float read_float_le(Cursor& c) {
    uint8_t b0 = c.u8(), b1 = c.u8(), b2 = c.u8(), b3 = c.u8();
    uint32_t bits = static_cast<uint32_t>(b0) | (static_cast<uint32_t>(b1) << 8) |
                    (static_cast<uint32_t>(b2) << 16) | (static_cast<uint32_t>(b3) << 24);
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// Renders a 32-bit bitstring (BSI/command-bitstring information elements) as an 8-hex-digit,
// zero-padded, uppercase "0x"-prefixed string -- the raw bit pattern IS the value for these
// types (there's no further semantic decode without point-specific documentation of what each
// bit means), matching how u_function_name already renders an unrecognized control byte as
// "0x" + hex elsewhere in this file.
std::string format_bitstring32(uint32_t bits) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(8) << bits;
    return s.str();
}

// Shared quality bits, used by SIQ/DIQ (bits4-7 only) and QDS (bits0,4-7 -- OV only applies to
// measured values, not single/double-point information, per the spec).
void append_quality_flags(std::vector<std::string>& flags, uint8_t b, bool has_overflow) {
    if (has_overflow && (b & 0x01)) flags.push_back("OV");
    if (b & 0x10) flags.push_back("BL");
    if (b & 0x20) flags.push_back("SB");
    if (b & 0x40) flags.push_back("NT");
    if (b & 0x80) flags.push_back("IV");
}

std::string format_cp24time2a(Cursor& c) {
    uint16_t ms = c.u16le();
    uint8_t b = c.u8();
    unsigned minute = b & 0x3F;
    bool iv = (b & 0x80) != 0;
    std::ostringstream s;
    s << std::setfill('0') << std::setw(2) << minute << ":" << std::setfill('0') << std::setw(2) << (ms / 1000)
      << "." << std::setfill('0') << std::setw(3) << (ms % 1000);
    if (iv) s << " [IV]";
    return s.str();
}

std::string format_cp56time2a(Cursor& c) {
    uint16_t ms = c.u16le();
    uint8_t b_min = c.u8();
    unsigned minute = b_min & 0x3F;
    bool iv = (b_min & 0x80) != 0;
    uint8_t b_hour = c.u8();
    unsigned hour = b_hour & 0x1F;
    bool su = (b_hour & 0x80) != 0;
    uint8_t b_day = c.u8();
    unsigned day = b_day & 0x1F;
    uint8_t b_month = c.u8();
    unsigned month = b_month & 0x0F;
    uint8_t b_year = c.u8();
    unsigned year = 2000u + (b_year & 0x7F);
    std::ostringstream s;
    s << year << "-" << std::setfill('0') << std::setw(2) << month << "-" << std::setfill('0') << std::setw(2)
      << day << " " << std::setfill('0') << std::setw(2) << hour << ":" << std::setfill('0') << std::setw(2)
      << minute << ":" << std::setfill('0') << std::setw(2) << (ms / 1000) << "." << std::setfill('0')
      << std::setw(3) << (ms % 1000);
    if (su) s << " [SU]";
    if (iv) s << " [IV]";
    return s.str();
}

std::string iec104_qu_name(unsigned qu) {
    switch (qu) {
        case 0: return "no additional definition";
        case 1: return "short pulse duration";
        case 2: return "long pulse duration";
        case 3: return "persistent output";
        default: return "reserved (" + std::to_string(qu) + ")";
    }
}

// Decodes SCO (types 45/58) / DCO (46/59) / RCO (47) -- all three share the same 1-byte layout:
// a command-state field in the low bits (1 bit for SCO, 2 for DCO/RCO), a 5-bit qualifier (bits
// 2-6), and the Select/Execute bit (bit7).
std::string decode_command_byte(uint8_t b, const char* on_name, const char* off_name,
                                 const char* not_permitted_name, bool two_bit_state) {
    unsigned state = two_bit_state ? (b & 0x03) : (b & 0x01);
    std::string state_name;
    if (two_bit_state) {
        switch (state) {
            case 1: state_name = off_name; break;
            case 2: state_name = on_name; break;
            default: state_name = not_permitted_name; break;
        }
    } else {
        state_name = state ? on_name : off_name;
    }
    unsigned qu = (b >> 2) & 0x1F;
    bool select = (b & 0x80) != 0;
    return state_name + " qualifier=" + std::to_string(qu) + " (" + iec104_qu_name(qu) + ")" +
           (select ? " [Select]" : " [Execute]");
}

std::string format_qos_suffix(uint8_t qos) {
    unsigned ql = qos & 0x7F;
    bool select = (qos & 0x80) != 0;
    return " ql=" + std::to_string(ql) + (select ? " [Select]" : " [Execute]");
}

// QPM (Qualifier of Parameter of Measured values, types 110/111/112): bits0-5 = KPA "kind of
// parameter", bit6 = LPC "local parameter change", bit7 = POP "parameter operation".
std::string qpm_kpa_name(unsigned kpa) {
    switch (kpa) {
        case 0: return "not used";
        case 1: return "threshold value";
        case 2: return "smoothing factor";
        case 3: return "low limit for transmission";
        case 4: return "high limit for transmission";
        default: return "reserved/other (" + std::to_string(kpa) + ")";
    }
}

std::string format_qpm_suffix(uint8_t qpm) {
    unsigned kpa = qpm & 0x3F;
    bool lpc = (qpm & 0x40) != 0;
    bool pop = (qpm & 0x80) != 0;
    std::string s = " KPA=" + std::to_string(kpa) + " (" + qpm_kpa_name(kpa) + ")";
    if (lpc) s += " [LPC]";
    if (pop) s += " [POP]";
    return s;
}

std::ostringstream make_fixed(int precision) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(precision);
    return s;
}

// Decodes one information element (everything after the 3-byte IOA already consumed by the
// caller) for a type ID that iec104_type_is_decoded() has already confirmed is supported.
void decode_iec104_element(uint8_t type_id, Cursor& c, std::string& value, std::vector<std::string>& flags) {
    switch (type_id) {
        case 1:   // M_SP_NA_1
        case 2:   // M_SP_TA_1
        case 30: {  // M_SP_TB_1
            uint8_t siq = c.u8();
            value = (siq & 0x01) ? "ON" : "OFF";
            append_quality_flags(flags, siq, /*has_overflow=*/false);
            if (type_id == 2) value += " @ " + format_cp24time2a(c);
            if (type_id == 30) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 3:   // M_DP_NA_1
        case 4:   // M_DP_TA_1
        case 31: {  // M_DP_TB_1
            uint8_t diq = c.u8();
            switch (diq & 0x03) {
                case 1: value = "OFF"; break;
                case 2: value = "ON"; break;
                default: value = "Indeterminate"; break;
            }
            append_quality_flags(flags, diq, /*has_overflow=*/false);
            if (type_id == 4) value += " @ " + format_cp24time2a(c);
            if (type_id == 31) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 5:   // M_ST_NA_1
        case 6:   // M_ST_TA_1
        case 32: {  // M_ST_TB_1
            uint8_t vti = c.u8();
            int position = vti & 0x7F;
            if (position & 0x40) position -= 0x80;  // sign-extend the 7-bit two's complement value
            bool transient = (vti & 0x80) != 0;
            uint8_t qds = c.u8();
            value = "position=" + std::to_string(position);
            if (transient) flags.push_back("T");
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            if (type_id == 6) value += " @ " + format_cp24time2a(c);
            if (type_id == 32) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 7:   // M_BO_NA_1
        case 8:   // M_BO_TA_1
        case 33: {  // M_BO_TB_1
            uint32_t bits = c.u32le();
            uint8_t qds = c.u8();
            value = format_bitstring32(bits);
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            if (type_id == 8) value += " @ " + format_cp24time2a(c);
            if (type_id == 33) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 9:   // M_ME_NA_1
        case 34: {  // M_ME_TD_1
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qds = c.u8();
            auto s = make_fixed(4);
            s << raw << " (" << (raw / 32768.0) << ")";
            value = s.str();
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            if (type_id == 34) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 10: {  // M_ME_TA_1 -- same layout as case 9 (M_ME_NA_1), + CP24Time2a
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qds = c.u8();
            auto s = make_fixed(4);
            s << raw << " (" << (raw / 32768.0) << ")";
            value = s.str();
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            value += " @ " + format_cp24time2a(c);
            break;
        }
        case 11:  // M_ME_NB_1
        case 35: {  // M_ME_TE_1
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qds = c.u8();
            value = std::to_string(raw);
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            if (type_id == 35) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 12: {  // M_ME_TB_1 -- same layout as case 11 (M_ME_NB_1), + CP24Time2a
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qds = c.u8();
            value = std::to_string(raw);
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            value += " @ " + format_cp24time2a(c);
            break;
        }
        case 13:  // M_ME_NC_1
        case 36: {  // M_ME_TF_1
            float f = read_float_le(c);
            uint8_t qds = c.u8();
            auto s = make_fixed(6);
            s << f;
            value = s.str();
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            if (type_id == 36) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 14: {  // M_ME_TC_1 -- same layout as case 13 (M_ME_NC_1), + CP24Time2a
            float f = read_float_le(c);
            uint8_t qds = c.u8();
            auto s = make_fixed(6);
            s << f;
            value = s.str();
            append_quality_flags(flags, qds, /*has_overflow=*/true);
            value += " @ " + format_cp24time2a(c);
            break;
        }
        case 21: {  // M_ME_ND_1 -- same value formula as case 9, but genuinely no QDS byte follows
            int16_t raw = static_cast<int16_t>(c.u16le());
            auto s = make_fixed(4);
            s << raw << " (" << (raw / 32768.0) << ")";
            value = s.str();
            break;
        }
        case 15:  // M_IT_NA_1
        case 37: {  // M_IT_TB_1
            int32_t raw = static_cast<int32_t>(c.u32le());
            uint8_t sq = c.u8();
            value = std::to_string(raw) + " seq=" + std::to_string(sq & 0x1F);
            if (sq & 0x20) flags.push_back("CY");
            if (sq & 0x40) flags.push_back("CA");
            if (sq & 0x80) flags.push_back("IV");
            if (type_id == 37) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 16: {  // M_IT_TA_1 -- same layout as case 15 (M_IT_NA_1), + CP24Time2a
            int32_t raw = static_cast<int32_t>(c.u32le());
            uint8_t sq = c.u8();
            value = std::to_string(raw) + " seq=" + std::to_string(sq & 0x1F);
            if (sq & 0x20) flags.push_back("CY");
            if (sq & 0x40) flags.push_back("CA");
            if (sq & 0x80) flags.push_back("IV");
            value += " @ " + format_cp24time2a(c);
            break;
        }
        case 45:  // C_SC_NA_1
        case 58: {  // C_SC_TA_1
            uint8_t sco = c.u8();
            value = decode_command_byte(sco, "ON", "OFF", "OFF", /*two_bit_state=*/false);
            if (type_id == 58) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 46:  // C_DC_NA_1
        case 59: {  // C_DC_TA_1
            uint8_t dco = c.u8();
            value = decode_command_byte(dco, "ON", "OFF", "not permitted", /*two_bit_state=*/true);
            if (type_id == 59) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 47: {  // C_RC_NA_1
            uint8_t rco = c.u8();
            value = decode_command_byte(rco, "step up/higher", "step down/lower", "not permitted",
                                         /*two_bit_state=*/true);
            break;
        }
        case 60: {  // C_RC_TA_1 -- same RCO layout as case 47 (C_RC_NA_1), + CP56Time2a
            uint8_t rco = c.u8();
            value = decode_command_byte(rco, "step up/higher", "step down/lower", "not permitted",
                                         /*two_bit_state=*/true);
            value += " @ " + format_cp56time2a(c);
            break;
        }
        case 48:  // C_SE_NA_1
        case 61: {  // C_SE_TA_1
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qos = c.u8();
            auto s = make_fixed(4);
            s << raw << " (" << (raw / 32768.0) << ")" << format_qos_suffix(qos);
            value = s.str();
            if (type_id == 61) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 49: {  // C_SE_NB_1
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qos = c.u8();
            value = std::to_string(raw) + format_qos_suffix(qos);
            break;
        }
        case 62: {  // C_SE_TB_1 -- same layout as case 49 (C_SE_NB_1), + CP56Time2a
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qos = c.u8();
            value = std::to_string(raw) + format_qos_suffix(qos);
            value += " @ " + format_cp56time2a(c);
            break;
        }
        case 50:  // C_SE_NC_1
        case 63: {  // C_SE_TC_1
            float f = read_float_le(c);
            uint8_t qos = c.u8();
            auto s = make_fixed(6);
            s << f << format_qos_suffix(qos);
            value = s.str();
            if (type_id == 63) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 51:  // C_BO_NA_1
        case 64: {  // C_BO_TA_1
            uint32_t bits = c.u32le();
            value = format_bitstring32(bits);
            if (type_id == 64) value += " @ " + format_cp56time2a(c);
            break;
        }
        case 70: {  // M_EI_NA_1
            uint8_t coi = c.u8();
            unsigned cause = coi & 0x7F;
            bool changed = (coi & 0x80) != 0;
            switch (cause) {
                case 0: value = "local power switch on"; break;
                case 1: value = "local manual reset"; break;
                case 2: value = "remote reset"; break;
                default: value = "reserved/other (" + std::to_string(cause) + ")"; break;
            }
            if (changed) flags.push_back("parameters changed");
            break;
        }
        case 100: {  // C_IC_NA_1
            uint8_t qoi = c.u8();
            if (qoi == 20) {
                value = "station interrogation (general)";
            } else if (qoi >= 21 && qoi <= 36) {
                value = "group " + std::to_string(qoi - 20) + " interrogation";
            } else {
                value = "Unknown/reserved (" + std::to_string(static_cast<unsigned>(qoi)) + ")";
            }
            break;
        }
        case 103: {  // C_CS_NA_1
            value = format_cp56time2a(c);
            break;
        }
        case 105: {  // C_RP_NA_1
            uint8_t qrp = c.u8();
            switch (qrp) {
                case 0: value = "not used"; break;
                case 1: value = "general reset"; break;
                case 2: value = "reset pending time-tagged information"; break;
                default: value = "reserved (" + std::to_string(static_cast<unsigned>(qrp)) + ")"; break;
            }
            break;
        }
        case 106: {  // C_CD_NA_1
            uint16_t delay_ms = c.u16le();
            value = std::to_string(delay_ms) + " ms";
            break;
        }
        case 107: {  // C_TS_TA_1
            uint16_t tsc = c.u16le();
            std::ostringstream s;
            s << "test sequence=0x" << std::hex << std::uppercase << std::setfill('0') << std::setw(4) << tsc;
            value = s.str();
            value += " @ " + format_cp56time2a(c);
            break;
        }
        case 110: {  // P_ME_NA_1 -- same value formula as case 9 (M_ME_NA_1), + QPM
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qpm = c.u8();
            auto s = make_fixed(4);
            s << raw << " (" << (raw / 32768.0) << ")" << format_qpm_suffix(qpm);
            value = s.str();
            break;
        }
        case 111: {  // P_ME_NB_1 -- same value formula as case 11 (M_ME_NB_1), + QPM
            int16_t raw = static_cast<int16_t>(c.u16le());
            uint8_t qpm = c.u8();
            value = std::to_string(raw) + format_qpm_suffix(qpm);
            break;
        }
        case 112: {  // P_ME_NC_1 -- same value formula as case 13 (M_ME_NC_1), + QPM
            float f = read_float_le(c);
            uint8_t qpm = c.u8();
            auto s = make_fixed(6);
            s << f << format_qpm_suffix(qpm);
            value = s.str();
            break;
        }
        case 113: {  // P_AC_NA_1
            uint8_t qpa = c.u8();
            switch (qpa) {
                case 0: value = "not used"; break;
                case 1: value = "act/deact of previously loaded parameters"; break;
                case 2: value = "act/deact of the parameter of the addressed object"; break;
                case 3: value = "act/deact of persistent cyclic or periodic transmission of the addressed object"; break;
                default: value = "reserved/other (" + std::to_string(static_cast<unsigned>(qpa)) + ")"; break;
            }
            break;
        }
        default:
            // Unreachable: decode_iec104_asdu only calls this once iec104_type_is_decoded() is true.
            value = "(unsupported)";
            break;
    }
}

}  // namespace

std::string iec104_type_short_name(uint8_t type_id) {
    if (const auto* entry = find_iec104_type(type_id)) return entry->short_name;
    std::ostringstream s;
    s << "Unknown(" << static_cast<unsigned>(type_id) << ")";
    return s.str();
}

std::vector<std::string> iec104_known_asdu_short_names() {
    std::vector<std::string> out;
    out.reserve(sizeof(kIec104Types) / sizeof(kIec104Types[0]));
    for (const auto& entry : kIec104Types) out.push_back(entry.short_name);
    return out;
}

std::optional<Iec104Apci> try_parse_iec104_apci(ByteSpan tcp_payload) {
    if (tcp_payload.size() < 6) {
        return std::nullopt;
    }
    if (tcp_payload.at(0) != 0x68) {
        return std::nullopt;
    }
    uint8_t length = tcp_payload.at(1);
    if (length < 4 || length > 253) {
        return std::nullopt;
    }

    uint8_t c0 = tcp_payload.at(2);
    uint8_t c1 = tcp_payload.at(3);
    uint8_t c2 = tcp_payload.at(4);
    uint8_t c3 = tcp_payload.at(5);

    Iec104Apci apci;
    apci.wire_length = 2 + static_cast<size_t>(length);

    if ((c0 & 0x01) == 0) {
        // I-format: bit1 of the first control byte is 0. The low bit of N(R)'s low byte (c2) is
        // fixed 0 by the spec -- rejecting on it here is what keeps this check meaningfully
        // stronger than a single magic byte (see the header comment on the Modbus collision risk).
        if ((c2 & 0x01) != 0) {
            return std::nullopt;
        }
        apci.frame_type = Iec104FrameType::I;
        apci.send_seq = static_cast<uint16_t>((static_cast<uint16_t>(c1) << 7) | (c0 >> 1));
        apci.recv_seq = static_cast<uint16_t>((static_cast<uint16_t>(c3) << 7) | (c2 >> 1));
        apci.asdu_length = static_cast<size_t>(length) - 4;
        std::ostringstream s;
        s << "I-format N(S)=" << apci.send_seq << " N(R)=" << apci.recv_seq;
        apci.summary = s.str();
        return apci;
    }

    if ((c0 & 0x03) == 0x01) {
        // S-format: fixed 0x01/0x00 first two control bytes, N(R) low bit fixed 0, and no ASDU
        // ever follows (length is always exactly 4).
        if (c0 != 0x01 || c1 != 0x00 || (c2 & 0x01) != 0 || length != 4) {
            return std::nullopt;
        }
        apci.frame_type = Iec104FrameType::S;
        apci.recv_seq = static_cast<uint16_t>((static_cast<uint16_t>(c3) << 7) | (c2 >> 1));
        std::ostringstream s;
        s << "S-format (supervisory) N(R)=" << apci.recv_seq;
        apci.summary = s.str();
        return apci;
    }

    // U-format: bits1-2 of the first control byte are both 1. The other three control bytes are
    // always all zero, and no ASDU ever follows (length is always exactly 4).
    if (c1 != 0x00 || c2 != 0x00 || c3 != 0x00 || length != 4) {
        return std::nullopt;
    }
    apci.frame_type = Iec104FrameType::U;
    apci.u_function_name = u_function_name(c0);
    apci.summary = "U-format " + apci.u_function_name;
    return apci;
}

std::optional<size_t> iec104_apdu_declared_length(ByteSpan payload) {
    if (payload.size() < 2) {
        return std::nullopt;
    }
    if (payload.at(0) != 0x68) {
        return std::nullopt;
    }
    uint8_t length = payload.at(1);
    if (length < 4 || length > 253) {
        return std::nullopt;
    }
    return 2 + static_cast<size_t>(length);
}

Iec104Asdu decode_iec104_asdu(ByteSpan asdu_bytes) {
    Iec104Asdu asdu;

    // Type ID (1) + VSQ (1) + COT (2) + Common Address (2) = 6 bytes, the minimum for any ASDU
    // regardless of object count.
    if (asdu_bytes.size() < 6) {
        asdu.decoded = false;
        asdu.note = "ASDU too short (" + std::to_string(asdu_bytes.size()) +
                    " byte(s), need at least 6 for type ID + VSQ + COT + common address)";
        asdu.notes.push_back(asdu.note);
        asdu.summary = asdu.note;
        return asdu;
    }

    Cursor c(asdu_bytes);
    asdu.type_id = c.u8();
    asdu.type_name = iec104_type_name(asdu.type_id);
    asdu.type_short_name = iec104_type_short_name(asdu.type_id);

    uint8_t vsq = c.u8();
    asdu.sq = (vsq & 0x80) != 0;
    asdu.object_count = vsq & 0x7F;

    uint8_t cot0 = c.u8();
    asdu.test = (cot0 & 0x80) != 0;
    asdu.negative = (cot0 & 0x40) != 0;
    asdu.cot_code = cot0 & 0x3F;
    asdu.cot_name = iec104_cot_name(asdu.cot_code);
    asdu.originator_address = c.u8();
    asdu.common_address = c.u16le();

    std::ostringstream s;
    s << asdu.type_name << " COT=" << asdu.cot_name;
    if (asdu.test) s << " [TEST]";
    if (asdu.negative) s << " [NEG]";
    s << " CASDU=" << asdu.common_address << " objects=" << static_cast<unsigned>(asdu.object_count);
    if (asdu.sq) s << " (sequential)";
    asdu.summary = s.str();

    if (!iec104_type_is_decoded(asdu.type_id)) {
        asdu.decoded = false;
        asdu.note = "ASDU type " + std::to_string(static_cast<unsigned>(asdu.type_id)) + " (" + asdu.type_name +
                    ") is not decoded in this groundwork release";
        asdu.notes.push_back(asdu.note);
        return asdu;
    }

    if (asdu.object_count == 0) {
        // Not an error -- e.g. a general interrogation activation confirmation legitimately
        // carries no addressed objects.
        return asdu;
    }

    // Safety cap against a pathological/malformed ASDU claiming an enormous object count --
    // same order of magnitude as DNP3's kMaxDecodedPointsPerHeader.
    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 200 default.
    const size_t kMaxDecodedObjects = resource_limits().max_decoded_objects.value_or(200);

    try {
        if (asdu.sq) {
            uint32_t base_ioa = read_u24le(c);
            for (uint8_t i = 0; i < asdu.object_count; ++i) {
                if (asdu.objects.size() >= kMaxDecodedObjects) break;
                Iec104InformationObject obj;
                obj.ioa = base_ioa + i;
                decode_iec104_element(asdu.type_id, c, obj.value, obj.flags);
                asdu.objects.push_back(std::move(obj));
            }
        } else {
            for (uint8_t i = 0; i < asdu.object_count; ++i) {
                uint32_t ioa = read_u24le(c);
                if (asdu.objects.size() >= kMaxDecodedObjects) break;
                Iec104InformationObject obj;
                obj.ioa = ioa;
                decode_iec104_element(asdu.type_id, c, obj.value, obj.flags);
                asdu.objects.push_back(std::move(obj));
            }
        }
        if (asdu.object_count > kMaxDecodedObjects) {
            asdu.notes.push_back("stopped after " + std::to_string(kMaxDecodedObjects) + " of " +
                                  std::to_string(static_cast<unsigned>(asdu.object_count)) +
                                  " information object(s) (safety cap)");
        }
    } catch (const ParseError& e) {
        asdu.decoded = false;
        asdu.note = "truncated while decoding information object " + std::to_string(asdu.objects.size() + 1) +
                    " of " + std::to_string(static_cast<unsigned>(asdu.object_count)) + ": " + e.what();
        asdu.notes.push_back(asdu.note);
    }

    return asdu;
}

// --- Migration batch 2: Iec104Decoder (registration-model interface) --------------------------
//
// decode() is an exact behavioral transplant of the removed decoder.cpp `if (want_iec104) { ... }`
// call site's body -- the same-payload multi-APDU coalescing loop (APDUs are small and it's normal
// for a sender/OS to flush several into one TCP segment, S-format acks/U-format handshakes
// especially) plus the merge-ASDU-fields-into-the-result logic, both moved here unchanged so
// decoder.cpp's own call site can shrink to gate+call+dual-write. `ctx` is unused: IEC 104 is
// purely stateless (see this file's own opening comment), unlike Dnp3Decoder/CotpDecoder.
std::optional<ProtocolResult> Iec104Decoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto apci = try_parse_iec104_apci(payload);
    if (!apci) {
        return std::nullopt;
    }

    Iec104Result result;
    result.summary = apci->summary;

    // CLI-configurable via --max-decoded-objects -- see resource_limits.hpp. 0/unset keeps the
    // literal 50 default.
    const size_t kMaxObjectValues = resource_limits().max_decoded_objects.value_or(50);
    auto merge_asdu = [&](const Iec104Asdu& asdu, bool is_first_apdu) {
        if (is_first_apdu) {
            result.summary += "; " + asdu.summary;
            result.iec104_has_asdu = true;
            result.iec104_asdu_type_name = asdu.type_name;
            result.iec104_asdu_type_short_name = asdu.type_short_name;
            result.iec104_cot_name = asdu.cot_name;
            result.iec104_common_address = asdu.common_address;
        }
        for (const auto& n : asdu.notes) result.notes.push_back(n);
        for (const auto& obj : asdu.objects) {
            if (result.iec104_object_values.size() >= kMaxObjectValues) break;
            std::string entry = "ioa=" + std::to_string(obj.ioa) + ": " + obj.value;
            if (!obj.flags.empty()) {
                entry += " [";
                for (size_t f = 0; f < obj.flags.size(); ++f) {
                    if (f != 0) entry += ",";
                    entry += obj.flags[f];
                }
                entry += "]";
            }
            result.iec104_object_values.push_back(entry);
        }
    };

    if (apci->frame_type == Iec104FrameType::I) {
        ByteSpan asdu_bytes = payload.subspan(6, apci->asdu_length);
        Iec104Asdu asdu = decode_iec104_asdu(asdu_bytes);
        merge_asdu(asdu, /*is_first_apdu=*/true);
    }

    // Like DNP3, an APDU is small and it's normal for a sender or the OS to coalesce several into
    // one TCP segment before flushing (S-format acks and U-format STARTDT/TESTFR handshakes are
    // especially likely to arrive alongside an I-format APDU). Keep looking for more, immediately
    // after the first APDU's own wire bytes, rather than silently stopping at the first one.
    // CLI-configurable via --max-coalesced-messages -- see resource_limits.hpp (folded in
    // alongside dnp3.cpp's kMaxDnp3FramesPerPayload -- see that constant's own comment). 0/unset
    // keeps the literal 50 default.
    const size_t kMaxApdusPerPayload = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = apci->wire_length;
    size_t apdu_count = 1;
    while (offset < payload.size() && apdu_count < kMaxApdusPerPayload) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_iec104_apci(rest);
        if (!next) break;  // remaining bytes aren't another APDU -- stop, don't guess
        ++apdu_count;
        std::string note = "additional IEC 104 APDU " + std::to_string(apdu_count) +
                            " found in the same TCP payload at byte offset " + std::to_string(offset) +
                            " (coalesced by the sender/OS): " + next->summary;
        if (next->frame_type == Iec104FrameType::I) {
            ByteSpan next_asdu_bytes = rest.subspan(6, next->asdu_length);
            Iec104Asdu next_asdu = decode_iec104_asdu(next_asdu_bytes);
            note += " | " + next_asdu.summary;
            if (apdu_count == 2) {
                note += " -- only the first I-format APDU's ASDU is reflected in the "
                        "summary line above and the iec104_asdu_type_name/iec104_cot_name "
                        "fields; every APDU's own ASDU is still fully decoded and included "
                        "here and in iec104_object_values";
            }
            result.notes.push_back(note);
            merge_asdu(next_asdu, /*is_first_apdu=*/false);
        } else {
            result.notes.push_back(note);
        }
        offset += next->wire_length;
    }
    if (apdu_count >= kMaxApdusPerPayload) {
        result.notes.push_back("stopped after " + std::to_string(kMaxApdusPerPayload) +
                                " IEC 104 APDU(s) in this one TCP payload, more may remain "
                                "(safety cap)");
    }

    return ProtocolResult::make<Iec104Result>("iec104", std::move(result));
}

const ProtocolDecoder& iec104_decoder() {
    static const Iec104Decoder instance;
    return instance;
}

}  // namespace conduitscope
