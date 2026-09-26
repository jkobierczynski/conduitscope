// SPDX-License-Identifier: Apache-2.0
// portable_time.hpp - reentrant gmtime/localtime wrappers used by every calendar-timestamp
// renderer in this codebase (opcua.cpp, s7commplus.cpp, mms.cpp, mqtt.cpp, time_format.cpp).
//
// std::gmtime/std::localtime write into a shared static buffer and return a pointer to it --
// MSVC's real /W4 build flags both as C4996 ("this function or variable may be unsafe"),
// steering callers toward its own gmtime_s/localtime_s. Rather than either reproducing that
// non-portable pair one call site at a time or blanket-disabling the warning class with
// _CRT_SECURE_NO_WARNINGS (which would silence genuinely useful deprecation warnings elsewhere
// too), this header gives every call site a single portable, reentrant, thread-safe entry point:
// glibc/POSIX's own reentrant gmtime_r/localtime_r off Windows, MSVC's gmtime_s/localtime_s on
// it. Same contract everywhere: returns false (leaving `out` unspecified) exactly when the
// platform's own gmtime/localtime would have returned nullptr -- the "ts out of representable
// range" case every existing caller already handles -- true otherwise, with `out` populated.
#pragma once

#include <ctime>

namespace conduitscope {

inline bool portable_gmtime(std::time_t t, std::tm& out) {
#if defined(_WIN32)
    return gmtime_s(&out, &t) == 0;
#else
    return gmtime_r(&t, &out) != nullptr;
#endif
}

inline bool portable_localtime(std::time_t t, std::tm& out) {
#if defined(_WIN32)
    return localtime_s(&out, &t) == 0;
#else
    return localtime_r(&t, &out) != nullptr;
#endif
}

}  // namespace conduitscope
