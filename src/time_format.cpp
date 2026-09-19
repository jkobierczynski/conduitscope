// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/time_format.hpp"

#include <cctype>
#include <cmath>
#include <cstdio>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace conduitscope {

std::optional<TimeFormat> parse_time_format(const std::string& text) {
    if (text == "e" || text == "epoch") return TimeFormat::Epoch;
    if (text == "r" || text == "relative") return TimeFormat::Relative;
    if (text == "d" || text == "delta") return TimeFormat::Delta;
    if (text == "a" || text == "absolute") return TimeFormat::Absolute;
    if (text == "ad" || text == "absolute-date") return TimeFormat::AbsoluteDate;
    return std::nullopt;
}

std::optional<TimeOffset> parse_time_offset(const std::string& text) {
    if (text.empty() || text == "utc" || text == "UTC") return TimeOffset{false, 0};
    if (text == "local") return TimeOffset{true, 0};

    // Fixed offset: "+HH:MM", "-HH:MM", "+HHMM", "-HHMM", or a bare "+H"/"-H" hour count -- the
    // sign is mandatory (bare "2" is ambiguous between "+2" and a malformed input, so it's
    // rejected rather than guessed at).
    if (text.size() < 2 || (text[0] != '+' && text[0] != '-')) return std::nullopt;
    bool negative = text[0] == '-';
    std::string digits;
    for (size_t i = 1; i < text.size(); ++i) {
        if (text[i] == ':') continue;
        if (!std::isdigit(static_cast<unsigned char>(text[i]))) return std::nullopt;
        digits += text[i];
    }
    if (digits.empty() || digits.size() > 4) return std::nullopt;

    int hh = 0, mm = 0;
    if (digits.size() <= 2) {
        hh = std::stoi(digits);
    } else {
        mm = std::stoi(digits.substr(digits.size() - 2));
        hh = std::stoi(digits.substr(0, digits.size() - 2));
    }
    if (hh > 23 || mm > 59) return std::nullopt;

    int total_seconds = hh * 3600 + mm * 60;
    return TimeOffset{false, negative ? -total_seconds : total_seconds};
}

namespace {

std::string format_seconds_fixed6(double seconds) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << seconds;
    return s.str();
}

// "Z" for plain UTC, "+HH:MM"/"-HH:MM" for a fixed non-zero offset, or "" for local system time
// (deliberately unlabeled, same as tshark/tcpdump's own local-time rendering -- the zone is
// whatever the analysis machine's own clock says, which isn't a fixed value to print).
std::string offset_suffix(const TimeOffset& offset) {
    if (offset.use_local_tz) return "";
    if (offset.offset_seconds == 0) return "Z";
    char sign = offset.offset_seconds < 0 ? '-' : '+';
    int abs_seconds = offset.offset_seconds < 0 ? -offset.offset_seconds : offset.offset_seconds;
    int hh = abs_seconds / 3600;
    int mm = (abs_seconds % 3600) / 60;
    // 16, not the tight 8 this always actually needs ("+HH:MM\0" is 7): GCC's -Wformat-truncation
    // sizes %02d against int's full range, not parse_time_offset's actual 0-23/0-59 clamp, so a
    // snug buffer here trips a truncation warning despite never truncating in practice.
    char buf[16];
    std::snprintf(buf, sizeof(buf), "%c%02d:%02d", sign, hh, mm);
    return std::string(buf);
}

// Shared by Absolute/AbsoluteDate -- everything except the strftime pattern itself (date+time vs
// time-only) is identical between the two.
std::string format_calendar(double ts, const TimeOffset& offset, const char* pattern) {
    double whole_d = std::floor(ts);
    std::time_t tt = static_cast<std::time_t>(whole_d);
    long micros = static_cast<long>(std::llround((ts - whole_d) * 1e6));
    if (micros >= 1000000) {
        // Rounding carried into the next second (e.g. ts == 1.9999996).
        micros -= 1000000;
        tt += 1;
    }

    std::tm* tmv = nullptr;
    if (offset.use_local_tz) {
        tmv = std::localtime(&tt);
    } else {
        std::time_t shifted = tt + offset.offset_seconds;
        tmv = std::gmtime(&shifted);
    }
    if (!tmv) {
        // Same graceful "never fabricate a date" fallback format_millis_epoch (mqtt.hpp/mqtt.cpp)
        // already uses elsewhere in this codebase, for a `ts` too far in the past/future for
        // std::gmtime/std::localtime's platform-defined struct tm to represent.
        return format_seconds_fixed6(ts) + " (raw epoch value -- out of range for calendar display)";
    }

    std::ostringstream s;
    s << std::put_time(tmv, pattern) << '.' << std::setfill('0') << std::setw(6) << micros
      << offset_suffix(offset);
    return s.str();
}

}  // namespace

std::string format_timestamp(double ts, TimeFormat format, const TimeOffset& offset, double first_ts,
                              double prev_ts) {
    switch (format) {
        case TimeFormat::Epoch: return format_seconds_fixed6(ts);
        case TimeFormat::Relative: return format_seconds_fixed6(ts - first_ts);
        case TimeFormat::Delta: return format_seconds_fixed6(ts - prev_ts);
        case TimeFormat::Absolute: return format_calendar(ts, offset, "%H:%M:%S");
        case TimeFormat::AbsoluteDate: return format_calendar(ts, offset, "%Y-%m-%d %H:%M:%S");
    }
    return format_seconds_fixed6(ts);  // unreachable -- silences -Wreturn-type on some compilers
}

}  // namespace conduitscope
