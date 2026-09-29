// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/security_event_format.hpp"

#include <sstream>

#include "conduitscope/version.hpp"

namespace conduitscope {

std::string cef_header_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        if (c == '\\' || c == '|') out += '\\';
        out += c;
    }
    return out;
}

std::string cef_extension_escape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (char c : s) {
        switch (c) {
            case '\\': out += "\\\\"; break;
            case '=': out += "\\="; break;
            case '\n': out += "\\n"; break;
            case '\r': out += "\\r"; break;
            default: out += c;
        }
    }
    return out;
}

int cef_severity_to_rfc5424_severity(int cef_severity_0_10) {
    if (cef_severity_0_10 >= 9) return 2;  // Very-High -> Critical
    if (cef_severity_0_10 >= 7) return 3;  // High -> Error
    if (cef_severity_0_10 >= 4) return 4;  // Medium -> Warning
    return 5;                              // Low -> Notice
}

std::string render_cef_line(const std::string& device_product, const std::string& device_event_class_id,
                             const std::string& name, int severity_0_10,
                             const std::vector<std::pair<std::string, std::string>>& extension_fields) {
    std::ostringstream out;
    out << "CEF:0|conduitscope|" << cef_header_escape(device_product) << "|" << kVersion << "|"
        << cef_header_escape(device_event_class_id) << "|" << cef_header_escape(name) << "|" << severity_0_10
        << "|";
    bool first = true;
    for (const auto& field : extension_fields) {
        if (!first) out << " ";
        first = false;
        out << field.first << "=" << cef_extension_escape(field.second);
    }
    return out.str();
}

std::string render_leef_line(const std::string& device_product, const std::string& event_id,
                              const std::vector<std::pair<std::string, std::string>>& extension_fields) {
    std::ostringstream out;
    out << "LEEF:2.0|conduitscope|" << cef_header_escape(device_product) << "|" << kVersion << "|"
        << cef_header_escape(event_id) << "|";
    bool first = true;
    for (const auto& field : extension_fields) {
        if (!first) out << "\t";
        first = false;
        out << field.first << "=" << cef_extension_escape(field.second);
    }
    return out.str();
}

std::string render_rfc5424_line(int severity_0_10, const std::string& msgid, const std::string& cef_payload) {
    constexpr int kFacilityLogAudit = 13;  // RFC 5424 section 6.2.1 -- see this file's header's own comment
    int pri = kFacilityLogAudit * 8 + cef_severity_to_rfc5424_severity(severity_0_10);
    // HEADER = PRI VERSION SP TIMESTAMP SP HOSTNAME SP APP-NAME SP PROCID SP MSGID, then SP
    // STRUCTURED-DATA, then SP MSG -- TIMESTAMP/HOSTNAME/PROCID/STRUCTURED-DATA are all RFC 5424's
    // own NILVALUE "-" (see this file's header's own comment for why), APP-NAME is fixed
    // "conduitscope".
    std::ostringstream out;
    out << "<" << pri << ">1 - - conduitscope - " << msgid << " - " << cef_payload;
    return out.str();
}

}  // namespace conduitscope
