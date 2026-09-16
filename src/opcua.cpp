// SPDX-License-Identifier: MIT
#include "conduitscope/opcua.hpp"

#include <algorithm>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace conduitscope {

namespace {

// ------------------------------------------------------------------------------------------
// Small formatting helpers (mirrors hartip.cpp's own format_float/hex_byte style).

std::string format_double(double v) {
    std::ostringstream s;
    s << std::fixed << std::setprecision(6) << v;
    return s.str();
}

// Bit-reinterprets a uint32_t as a signed Int32 -- portable, no UB, no implementation-defined
// static_cast, the same memcpy-based posture hartip.cpp's own read_float32 already documents.
int32_t to_i32(uint32_t v) {
    int32_t r;
    std::memcpy(&r, &v, sizeof(r));
    return r;
}

double bits_to_double(uint64_t bits) {
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

// ticks: 100-nanosecond intervals since 1601-01-01T00:00:00Z (the Win32 FILETIME epoch) -- see
// opcua.hpp's "Primitive encoding" section for why OPC UA's own DateTime uses this epoch.
std::string format_opcua_datetime(int64_t ticks) {
    if (ticks <= 0) return "0 (start-of-time sentinel)";
    constexpr int64_t kTicksPerSecond = 10000000LL;
    constexpr int64_t kEpochDiffSeconds = 11644473600LL;  // 1601-01-01 -> 1970-01-01
    int64_t unix_seconds = ticks / kTicksPerSecond - kEpochDiffSeconds;
    int ms = static_cast<int>((ticks % kTicksPerSecond) / 10000);
    std::time_t tt = static_cast<std::time_t>(unix_seconds);
    std::tm* tm_utc = std::gmtime(&tt);
    if (!tm_utc) {
        return std::to_string(ticks) + " (raw FILETIME ticks -- out of range for calendar display)";
    }
    std::ostringstream s;
    s << std::put_time(tm_utc, "%Y-%m-%dT%H:%M:%S") << '.' << std::setfill('0') << std::setw(3) << ms
      << 'Z';
    return s.str();
}

// ------------------------------------------------------------------------------------------
// Primitive readers -- see opcua.hpp's "Primitive encoding" section for the byte layout each of
// these implements, cross-checked against python-opcua's own generated (de)serializers.

std::optional<std::string> read_string(Cursor& c) {
    int32_t len = to_i32(c.u32le());
    if (len < 0) return std::nullopt;
    if (len == 0) return std::string();
    ByteSpan s = c.bytes(static_cast<size_t>(len));
    return std::string(reinterpret_cast<const char*>(s.data()), s.size());
}

struct OpcUaByteString {
    bool present = false;  // false only for a null (-1 length) ByteString
    size_t length = 0;
    ByteSpan data;  // valid only when length > 0
};

OpcUaByteString read_bytestring(Cursor& c) {
    int32_t len = to_i32(c.u32le());
    OpcUaByteString bs;
    if (len < 0) return bs;
    bs.present = true;
    bs.length = static_cast<size_t>(len);
    if (len > 0) bs.data = c.bytes(static_cast<size_t>(len));
    return bs;
}

int32_t read_array_count(Cursor& c) { return std::max<int32_t>(to_i32(c.u32le()), 0); }

// A decoded NodeId (see opcua.hpp's "Primitive encoding" -- NodeId). Throws ParseError when the
// encoding byte's low 6 bits aren't one of the 6 valid shapes (0x00-0x05): unlike an ordinary
// missing/short field, an unrecognized NodeId shape means this decoder has no way to know how
// many bytes the Identifier occupies, so nothing after it in the same message can be located
// either -- the caller's own try/catch (see try_parse_opcua_message) treats that the same as any
// other structural parse failure, falling back to raw hex for the remainder.
struct OpcUaNodeIdInfo {
    uint8_t encoding = 0;  // low 6 bits -- 0x00 Two-Byte, 0x01 Four-Byte, 0x02 Numeric, 0x03
                            // String, 0x04 Guid, 0x05 ByteString
    uint16_t ns = 0;
    uint32_t numeric_id = 0;    // meaningful for encoding 0x00/0x01/0x02
    std::string string_id;      // meaningful for encoding 0x03
    std::string guid_id;        // meaningful for encoding 0x04, formatted as 8-4-4-4-12 hex
    OpcUaByteString bytestring_id;  // meaningful for encoding 0x05
};

OpcUaNodeIdInfo read_node_id(Cursor& c) {
    uint8_t mask = c.u8();
    bool ns_uri_flag = (mask & 0x80) != 0;       // ExpandedNodeId only
    bool server_index_flag = (mask & 0x40) != 0;  // ExpandedNodeId only
    uint8_t shape = mask & 0x3F;

    OpcUaNodeIdInfo id;
    id.encoding = shape;
    switch (shape) {
        case 0x00:  // Two-Byte
            id.numeric_id = c.u8();
            break;
        case 0x01:  // Four-Byte
            id.ns = c.u8();
            id.numeric_id = c.u16le();
            break;
        case 0x02:  // Numeric
            id.ns = c.u16le();
            id.numeric_id = c.u32le();
            break;
        case 0x03:  // String
            id.ns = c.u16le();
            id.string_id = read_string(c).value_or("");
            break;
        case 0x04: {  // Guid -- Data1(UInt32 LE) + Data2(UInt16 LE) + Data3(UInt16 LE) +
                       // Data4(8 raw bytes, network order) -- see opcua.hpp
            id.ns = c.u16le();
            uint32_t d1 = c.u32le();
            uint16_t d2 = c.u16le();
            uint16_t d3 = c.u16le();
            ByteSpan d4 = c.bytes(8);
            std::ostringstream g;
            g << std::hex << std::setfill('0') << std::setw(8) << d1 << "-" << std::setw(4) << d2 << "-"
              << std::setw(4) << d3 << "-";
            for (size_t i = 0; i < 2; ++i) g << std::setw(2) << static_cast<unsigned>(d4.at(i));
            g << "-";
            for (size_t i = 2; i < 8; ++i) g << std::setw(2) << static_cast<unsigned>(d4.at(i));
            id.guid_id = g.str();
            break;
        }
        case 0x05:  // ByteString
            id.ns = c.u16le();
            id.bytestring_id = read_bytestring(c);
            break;
        default:
            throw ParseError("NodeId encoding byte 0x" + std::to_string(static_cast<unsigned>(mask)) +
                              " is not a valid NodeId shape (low 6 bits must be 0x00-0x05)");
    }
    if (ns_uri_flag) read_string(c);  // ExpandedNodeId's NamespaceUri -- consumed, not surfaced
    if (server_index_flag) c.u32le();  // ExpandedNodeId's ServerIndex -- consumed, not surfaced
    return id;
}

std::string node_id_display(const OpcUaNodeIdInfo& id) {
    std::ostringstream s;
    s << "ns=" << id.ns << ";";
    switch (id.encoding) {
        case 0x00:
        case 0x01:
        case 0x02:
            s << "i=" << id.numeric_id;
            break;
        case 0x03:
            s << "s=" << id.string_id;
            break;
        case 0x04:
            s << "g=" << id.guid_id;
            break;
        case 0x05:
            s << "b=<" << id.bytestring_id.length << " byte(s)>";
            break;
        default:
            s << "?";
            break;
    }
    return s.str();
}

// LocalizedText -- a 1-byte encoding mask (0x01=Locale present, 0x02=Text present) then whichever
// of Locale(String)/Text(String) that mask flags. See opcua.hpp.
std::string read_localized_text(Cursor& c) {
    uint8_t mask = c.u8();
    std::string locale, text;
    bool has_locale = (mask & 0x01) != 0;
    bool has_text = (mask & 0x02) != 0;
    if (has_locale) locale = read_string(c).value_or("");
    if (has_text) text = read_string(c).value_or("");
    if (has_text && has_locale) return text + " [" + locale + "]";
    if (has_text) return text;
    if (has_locale) return "[" + locale + "]";
    return "";
}

struct OpcUaExtensionObjectInfo {
    OpcUaNodeIdInfo type_id;
    uint8_t encoding = 0;  // 0x00 no body, 0x01 ByteString body, 0x02 XML body
    ByteSpan body;         // meaningful only when encoding == 0x01
};

OpcUaExtensionObjectInfo read_extension_object(Cursor& c) {
    OpcUaExtensionObjectInfo eo;
    eo.type_id = read_node_id(c);
    eo.encoding = c.u8();
    if (eo.encoding == 0x01 || eo.encoding == 0x02) {
        int32_t len = to_i32(c.u32le());
        if (len > 0) eo.body = c.bytes(static_cast<size_t>(len));
    }
    return eo;
}

// DiagnosticInfo -- structurally consumed (so byte alignment for whatever follows stays correct)
// but never surfaced as a decoded value; see opcua.hpp's "Deliberately NOT implemented" section.
void skip_diagnostic_info(Cursor& c, int depth = 0) {
    if (depth > 10) throw ParseError("DiagnosticInfo nested more than 10 levels deep");
    uint8_t mask = c.u8();
    if (mask & 0x01) c.u32le();               // SymbolicId
    if (mask & 0x02) c.u32le();                // NamespaceUri
    if (mask & 0x04) c.u32le();                // LocalizedText
    if (mask & 0x08) c.u32le();                // Locale
    if (mask & 0x10) read_string(c);           // AdditionalInfo
    if (mask & 0x20) c.u32le();                // InnerStatusCode
    if (mask & 0x40) skip_diagnostic_info(c, depth + 1);  // InnerDiagnosticInfo -- recursive
}

void skip_extension_object(Cursor& c) { read_extension_object(c); }

void skip_signature_data(Cursor& c) {
    read_string(c);      // Algorithm
    read_bytestring(c);  // Signature
}

void skip_signed_software_certificate(Cursor& c) {
    read_bytestring(c);  // CertificateData
    read_bytestring(c);  // Signature
}

// ------------------------------------------------------------------------------------------
// StatusCode decode -- see opcua.hpp's "StatusCode decode" section. This first-pass table is
// cross-checked directly against the OPC Foundation's own published StatusCode.csv
// (github.com/OPCFoundation/UA-Nodeset); it covers the subset most relevant to an OT security
// audit's own concerns, not an attempt at all ~700 named codes the full spec defines.
std::string status_code_name(uint32_t code) {
    static const std::pair<uint32_t, const char*> kNamed[] = {
        {0x00000000, "Good"},
        {0x40000000, "Uncertain"},
        {0x80010000, "BadUnexpectedError"},
        {0x800A0000, "BadTimeout"},
        {0x800B0000, "BadServiceUnsupported"},
        {0x80120000, "BadCertificateInvalid"},
        {0x80130000, "BadSecurityChecksFailed"},
        {0x801F0000, "BadUserAccessDenied"},
        {0x80200000, "BadIdentityTokenInvalid"},
        {0x80210000, "BadIdentityTokenRejected"},
        {0x80220000, "BadSecureChannelIdInvalid"},
        {0x80250000, "BadSessionIdInvalid"},
        {0x80260000, "BadSessionClosed"},
        {0x80330000, "BadNodeIdInvalid"},
        {0x80340000, "BadNodeIdUnknown"},
        {0x803A0000, "BadNotReadable"},
        {0x803B0000, "BadNotWritable"},
        {0x80530000, "BadRequestTypeInvalid"},
        {0x80550000, "BadSecurityPolicyRejected"},
        {0x80740000, "BadTypeMismatch"},
    };
    for (const auto& [value, name] : kNamed) {
        if (value == code) return name;
    }
    uint32_t severity = code & 0xC0000000u;
    std::ostringstream s;
    s << (severity == 0x80000000u ? "Bad" : severity == 0x40000000u ? "Uncertain" : "Good") << " (0x"
      << std::hex << std::setfill('0') << std::setw(8) << code << ")";
    return s.str();
}

std::string security_mode_name(uint32_t v) {
    switch (v) {
        case 0: return "Invalid";
        case 1: return "None";
        case 2: return "Sign";
        case 3: return "SignAndEncrypt";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

std::string application_type_name(uint32_t v) {
    switch (v) {
        case 0: return "Server";
        case 1: return "Client";
        case 2: return "ClientAndServer";
        case 3: return "DiscoveryServer";
        default: return "unknown(" + std::to_string(v) + ")";
    }
}

// ------------------------------------------------------------------------------------------
// RequestHeader / ResponseHeader -- shared by every service (Tier 1 and Tier 2 alike); see
// opcua.hpp's "Service identification" section for why this codebase always decodes this much
// even for a Tier-2 (body-not-decoded) service.

OpcUaServiceHeader read_request_header(Cursor& c, std::vector<std::string>& values) {
    read_node_id(c);  // AuthenticationToken -- the session's own secret; consumed, not surfaced
    int64_t ts_ticks = static_cast<int64_t>(c.u64le());
    OpcUaServiceHeader h;
    h.is_response = false;
    h.request_handle = c.u32le();
    c.u32le();          // ReturnDiagnostics -- a client-requested bitmask, consumed, not surfaced
    read_string(c);      // AuditEntryId -- consumed, not surfaced
    c.u32le();          // TimeoutHint
    skip_extension_object(c);  // AdditionalHeader
    values.push_back("timestamp=" + format_opcua_datetime(ts_ticks));
    values.push_back("request-handle=" + std::to_string(h.request_handle));
    return h;
}

OpcUaServiceHeader read_response_header(Cursor& c, std::vector<std::string>& values) {
    int64_t ts_ticks = static_cast<int64_t>(c.u64le());
    OpcUaServiceHeader h;
    h.is_response = true;
    h.request_handle = c.u32le();
    h.status_code = c.u32le();
    h.status_code_name = status_code_name(h.status_code);
    h.status_is_good = (h.status_code & 0xC0000000u) == 0;
    skip_diagnostic_info(c);  // ServiceDiagnostics
    int32_t n = read_array_count(c);
    for (int32_t i = 0; i < n; ++i) read_string(c);  // StringTable -- consumed, not surfaced
    skip_extension_object(c);                         // AdditionalHeader
    values.push_back("timestamp=" + format_opcua_datetime(ts_ticks));
    values.push_back("request-handle=" + std::to_string(h.request_handle));
    values.push_back("service-result=" + h.status_code_name);
    return h;
}

// ------------------------------------------------------------------------------------------
// ApplicationDescription / EndpointDescription / UserTokenPolicy -- shared by GetEndpoints,
// FindServers, and CreateSession; see opcua.hpp.

struct AppDescInfo {
    std::string application_uri;
    uint32_t application_type = 0;
};

AppDescInfo read_application_description(Cursor& c) {
    AppDescInfo a;
    a.application_uri = read_string(c).value_or("");
    read_string(c);            // ProductUri -- consumed, not surfaced
    read_localized_text(c);    // ApplicationName -- consumed, not surfaced (ApplicationUri is the
                                 // stable identifier this decoder surfaces instead)
    a.application_type = c.u32le();
    read_string(c);  // GatewayServerUri
    read_string(c);  // DiscoveryProfileUri
    int32_t n = read_array_count(c);
    for (int32_t i = 0; i < n; ++i) read_string(c);  // DiscoveryUrls -- consumed, not surfaced
    return a;
}

struct EndpointDescInfo {
    std::string endpoint_url;
    AppDescInfo server;
    uint32_t security_mode = 0;
    std::string security_policy_uri;
};

EndpointDescInfo read_endpoint_description(Cursor& c) {
    EndpointDescInfo e;
    e.endpoint_url = read_string(c).value_or("");
    e.server = read_application_description(c);
    read_bytestring(c);  // ServerCertificate -- consumed, not surfaced (see opcua.hpp's own
                           // certificate-handling convention)
    e.security_mode = c.u32le();
    e.security_policy_uri = read_string(c).value_or("");
    int32_t n = read_array_count(c);
    for (int32_t i = 0; i < n; ++i) {  // UserTokenPolicy array -- consumed, not surfaced (the
                                         // ACTUAL identity token used is surfaced separately, from
                                         // a real ActivateSessionRequest -- see "Identity token
                                         // decode" in opcua.hpp)
        read_string(c);   // PolicyId
        c.u32le();         // TokenType
        read_string(c);   // IssuedTokenType
        read_string(c);   // IssuerEndpointUrl
        read_string(c);   // SecurityPolicyUri
    }
    read_string(c);  // TransportProfileUri
    c.u8();           // SecurityLevel
    return e;
}

// ------------------------------------------------------------------------------------------
// Tier 1 service-specific decoders -- each is called with the Cursor already positioned right
// after that message's RequestHeader/ResponseHeader (see read_request_header/read_response_header
// above), and appends "key=value" entries to `values`.

void decode_hello(Cursor& c, std::vector<std::string>& values) {
    uint32_t proto = c.u32le(), recv_buf = c.u32le(), send_buf = c.u32le(), max_msg = c.u32le(),
             max_chunk = c.u32le();
    auto url = read_string(c);
    values.push_back("protocol-version=" + std::to_string(proto));
    values.push_back("receive-buffer-size=" + std::to_string(recv_buf));
    values.push_back("send-buffer-size=" + std::to_string(send_buf));
    values.push_back("max-message-size=" + std::to_string(max_msg));
    values.push_back("max-chunk-count=" + std::to_string(max_chunk));
    values.push_back("endpoint-url=" + url.value_or(""));
}

void decode_acknowledge(Cursor& c, std::vector<std::string>& values) {
    uint32_t proto = c.u32le(), recv_buf = c.u32le(), send_buf = c.u32le(), max_msg = c.u32le(),
             max_chunk = c.u32le();
    values.push_back("protocol-version=" + std::to_string(proto));
    values.push_back("receive-buffer-size=" + std::to_string(recv_buf));
    values.push_back("send-buffer-size=" + std::to_string(send_buf));
    values.push_back("max-message-size=" + std::to_string(max_msg));
    values.push_back("max-chunk-count=" + std::to_string(max_chunk));
}

void decode_error(Cursor& c, std::vector<std::string>& values) {
    uint32_t status = c.u32le();
    auto reason = read_string(c);
    values.push_back("error=" + status_code_name(status));
    values.push_back("reason=" + reason.value_or(""));
}

void decode_reverse_hello(Cursor& c, std::vector<std::string>& values) {
    auto server_uri = read_string(c);
    auto endpoint_url = read_string(c);
    values.push_back("server-uri=" + server_uri.value_or(""));
    values.push_back("endpoint-url=" + endpoint_url.value_or(""));
}

void decode_open_secure_channel_request_params(Cursor& c, std::vector<std::string>& values) {
    uint32_t client_protocol_version = c.u32le();
    uint32_t request_type = c.u32le();
    uint32_t security_mode = c.u32le();
    auto nonce = read_bytestring(c);
    uint32_t requested_lifetime_ms = c.u32le();
    values.push_back("client-protocol-version=" + std::to_string(client_protocol_version));
    values.push_back(std::string("request-type=") +
                      (request_type == 0 ? "Issue" : request_type == 1 ? "Renew"
                                                                        : "unknown(" +
                                                                              std::to_string(request_type) +
                                                                              ")"));
    values.push_back("security-mode=" + security_mode_name(security_mode));
    values.push_back("client-nonce-length=" + std::to_string(nonce.length));
    values.push_back("requested-lifetime-ms=" + std::to_string(requested_lifetime_ms));
}

void decode_open_secure_channel_response_params(Cursor& c, std::vector<std::string>& values) {
    uint32_t server_protocol_version = c.u32le();
    uint32_t channel_id = c.u32le();
    uint32_t token_id = c.u32le();
    int64_t created_at = static_cast<int64_t>(c.u64le());
    uint32_t revised_lifetime_ms = c.u32le();
    auto server_nonce = read_bytestring(c);
    values.push_back("server-protocol-version=" + std::to_string(server_protocol_version));
    values.push_back("security-token-channel-id=" + std::to_string(channel_id));
    values.push_back("security-token-id=" + std::to_string(token_id));
    values.push_back("security-token-created-at=" + format_opcua_datetime(created_at));
    values.push_back("revised-lifetime-ms=" + std::to_string(revised_lifetime_ms));
    values.push_back("server-nonce-length=" + std::to_string(server_nonce.length));
}

void decode_get_endpoints_request_params(Cursor& c, std::vector<std::string>& values) {
    auto url = read_string(c);
    int32_t n_locale = read_array_count(c);
    for (int32_t i = 0; i < n_locale; ++i) read_string(c);
    int32_t n_profile = read_array_count(c);
    for (int32_t i = 0; i < n_profile; ++i) read_string(c);
    values.push_back("endpoint-url=" + url.value_or(""));
}

void decode_get_endpoints_response_params(Cursor& c, std::vector<std::string>& values) {
    int32_t n = read_array_count(c);
    values.push_back("endpoint-count=" + std::to_string(n));
    for (int32_t i = 0; i < n; ++i) {
        EndpointDescInfo e = read_endpoint_description(c);
        values.push_back("endpoint[" + std::to_string(i) + "]=" + e.endpoint_url +
                          " (security=" + security_mode_name(e.security_mode) +
                          ", policy=" + e.security_policy_uri + ")");
    }
}

void decode_find_servers_request_params(Cursor& c, std::vector<std::string>& values) {
    auto url = read_string(c);
    int32_t n_locale = read_array_count(c);
    for (int32_t i = 0; i < n_locale; ++i) read_string(c);
    int32_t n_server = read_array_count(c);
    for (int32_t i = 0; i < n_server; ++i) read_string(c);
    values.push_back("endpoint-url=" + url.value_or(""));
}

void decode_find_servers_response_params(Cursor& c, std::vector<std::string>& values) {
    int32_t n = read_array_count(c);
    values.push_back("server-count=" + std::to_string(n));
    for (int32_t i = 0; i < n; ++i) {
        AppDescInfo a = read_application_description(c);
        values.push_back("server[" + std::to_string(i) + "]=" + a.application_uri + " (" +
                          application_type_name(a.application_type) + ")");
    }
}

void decode_create_session_request_params(Cursor& c, std::vector<std::string>& values) {
    AppDescInfo client = read_application_description(c);
    read_string(c);  // ServerUri
    auto endpoint_url = read_string(c);
    auto session_name = read_string(c);
    read_bytestring(c);  // ClientNonce
    read_bytestring(c);  // ClientCertificate
    double requested_timeout_ms = bits_to_double(c.u64le());
    uint32_t max_response_size = c.u32le();
    values.push_back("client-application-uri=" + client.application_uri);
    values.push_back("endpoint-url=" + endpoint_url.value_or(""));
    values.push_back("session-name=" + session_name.value_or(""));
    values.push_back("requested-session-timeout-ms=" + format_double(requested_timeout_ms));
    values.push_back("max-response-message-size=" + std::to_string(max_response_size));
}

void decode_create_session_response_params(Cursor& c, std::vector<std::string>& values) {
    OpcUaNodeIdInfo session_id = read_node_id(c);
    read_node_id(c);  // AuthenticationToken -- the session's own secret; consumed, not surfaced
    double revised_timeout_ms = bits_to_double(c.u64le());
    read_bytestring(c);  // ServerNonce
    read_bytestring(c);  // ServerCertificate
    int32_t n_ep = read_array_count(c);
    for (int32_t i = 0; i < n_ep; ++i) read_endpoint_description(c);  // already surfaced by
                                                                        // GetEndpoints when present
    int32_t n_cert = read_array_count(c);
    for (int32_t i = 0; i < n_cert; ++i) skip_signed_software_certificate(c);
    skip_signature_data(c);  // ServerSignature
    uint32_t max_request_size = c.u32le();
    values.push_back("session-id=" + node_id_display(session_id));
    values.push_back("revised-session-timeout-ms=" + format_double(revised_timeout_ms));
    values.push_back("server-endpoint-count=" + std::to_string(n_ep));
    values.push_back("max-request-message-size=" + std::to_string(max_request_size));
}

// Identity token TypeIds (namespace 0, _Encoding_DefaultBinary) -- see opcua.hpp's "Identity
// token decode" section.
constexpr uint32_t kAnonymousIdentityToken = 321;
constexpr uint32_t kUserNameIdentityToken = 324;
constexpr uint32_t kX509IdentityToken = 327;
constexpr uint32_t kIssuedIdentityToken = 940;

void decode_activate_session_request_params(Cursor& c, std::vector<std::string>& values,
                                             std::vector<std::string>& notes) {
    skip_signature_data(c);  // ClientSignature
    int32_t n_cert = read_array_count(c);
    for (int32_t i = 0; i < n_cert; ++i) skip_signed_software_certificate(c);
    int32_t n_locale = read_array_count(c);
    for (int32_t i = 0; i < n_locale; ++i) read_string(c);

    OpcUaExtensionObjectInfo eo = read_extension_object(c);
    if (eo.encoding != 0x01 || eo.body.empty()) {
        values.push_back("identity=<token body not present/decodable, encoding=" +
                          std::to_string(static_cast<unsigned>(eo.encoding)) + ">");
    } else {
        Cursor tc(eo.body);
        bool is_ns0 = eo.type_id.ns == 0;
        uint32_t id = eo.type_id.numeric_id;
        if (is_ns0 && id == kAnonymousIdentityToken) {
            auto policy_id = read_string(tc);
            values.push_back("identity=anonymous (policy-id=" + policy_id.value_or("") + ")");
        } else if (is_ns0 && id == kUserNameIdentityToken) {
            auto policy_id = read_string(tc);
            auto username = read_string(tc);
            OpcUaByteString password = read_bytestring(tc);
            auto enc_alg = read_string(tc);
            values.push_back("identity=username (policy-id=" + policy_id.value_or("") + ")");
            values.push_back("username=" + username.value_or(""));
            bool cleartext = !enc_alg.has_value() || enc_alg->empty();
            if (cleartext && password.present && password.length > 0) {
                std::string pw(reinterpret_cast<const char*>(password.data.data()), password.data.size());
                values.push_back("password=" + pw);
                notes.push_back(
                    "SECURITY FINDING: UserNameIdentityToken's own EncryptionAlgorithm field is "
                    "empty, meaning the password above was placed on the wire UNENCRYPTED -- see "
                    "opcua.hpp's own \"Identity token decode\" section");
            } else if (password.present) {
                values.push_back("password=<" + std::to_string(password.length) +
                                  " encrypted byte(s), algorithm=" + enc_alg.value_or("") + ">");
            } else {
                values.push_back("password=<absent>");
            }
        } else if (is_ns0 && id == kX509IdentityToken) {
            auto policy_id = read_string(tc);
            OpcUaByteString cert = read_bytestring(tc);
            values.push_back("identity=certificate (policy-id=" + policy_id.value_or("") +
                              ", certificate-length=" + std::to_string(cert.length) + ")");
        } else if (is_ns0 && id == kIssuedIdentityToken) {
            auto policy_id = read_string(tc);
            values.push_back("identity=issued-token (policy-id=" + policy_id.value_or("") + ")");
        } else {
            values.push_back("identity=<unrecognized token type, " + node_id_display(eo.type_id) + ">");
        }
    }
    skip_signature_data(c);  // UserTokenSignature
}

void decode_activate_session_response_params(Cursor& c, std::vector<std::string>& values) {
    OpcUaByteString nonce = read_bytestring(c);
    values.push_back("server-nonce-length=" + std::to_string(nonce.length));
    int32_t n = read_array_count(c);
    int good = 0;
    for (int32_t i = 0; i < n; ++i) {
        uint32_t sc = c.u32le();
        if ((sc & 0xC0000000u) == 0) ++good;
    }
    values.push_back("results=" + std::to_string(n) + " status code(s) (" + std::to_string(good) +
                      " Good)");
    int32_t n_diag = read_array_count(c);
    for (int32_t i = 0; i < n_diag; ++i) skip_diagnostic_info(c);
}

void decode_close_session_request_params(Cursor& c, std::vector<std::string>& values) {
    uint8_t del = c.u8();
    values.push_back(std::string("delete-subscriptions=") + (del != 0 ? "true" : "false"));
}

// ------------------------------------------------------------------------------------------
// Service dispatch table -- see opcua.hpp's "Service identification" section for Tier 1 vs.
// Tier 2. Every numeric id below is this service's own "_Encoding_DefaultBinary" NodeId,
// cross-checked against the OPC Foundation's own published NodeIds.csv (see this file's own
// header comment's "Sourcing" paragraph) -- not guessed, not taken from any single secondary
// source alone.
struct ServiceInfo {
    uint32_t id;
    const char* name;
    bool is_response;
    bool full_decode;  // true = Tier 1 (this decoder field-decodes the body); false = Tier 2
                        // (header only, body shown as raw hex)
};

constexpr ServiceInfo kServices[] = {
    // Tier 1
    {397, "ServiceFault", true, true},
    {446, "OpenSecureChannelRequest", false, true},
    {449, "OpenSecureChannelResponse", true, true},
    {452, "CloseSecureChannelRequest", false, true},
    {455, "CloseSecureChannelResponse", true, true},
    {428, "GetEndpointsRequest", false, true},
    {431, "GetEndpointsResponse", true, true},
    {422, "FindServersRequest", false, true},
    {425, "FindServersResponse", true, true},
    {461, "CreateSessionRequest", false, true},
    {464, "CreateSessionResponse", true, true},
    {467, "ActivateSessionRequest", false, true},
    {470, "ActivateSessionResponse", true, true},
    {473, "CloseSessionRequest", false, true},
    {476, "CloseSessionResponse", true, true},
    // Tier 2 -- see opcua.hpp: these all need the Variant/DataValue encoding this first-pass
    // release does not implement, so only RequestHeader/ResponseHeader is decoded.
    {479, "CancelRequest", false, false},
    {482, "CancelResponse", true, false},
    {488, "AddNodesRequest", false, false},
    {491, "AddNodesResponse", true, false},
    {527, "BrowseRequest", false, false},
    {530, "BrowseResponse", true, false},
    {533, "BrowseNextRequest", false, false},
    {536, "BrowseNextResponse", true, false},
    {554, "TranslateBrowsePathsToNodeIdsRequest", false, false},
    {557, "TranslateBrowsePathsToNodeIdsResponse", true, false},
    {560, "RegisterNodesRequest", false, false},
    {563, "RegisterNodesResponse", true, false},
    {566, "UnregisterNodesRequest", false, false},
    {569, "UnregisterNodesResponse", true, false},
    {631, "ReadRequest", false, false},
    {634, "ReadResponse", true, false},
    {664, "HistoryReadRequest", false, false},
    {667, "HistoryReadResponse", true, false},
    {673, "WriteRequest", false, false},
    {676, "WriteResponse", true, false},
    {712, "CallRequest", false, false},
    {715, "CallResponse", true, false},
    {751, "CreateMonitoredItemsRequest", false, false},
    {754, "CreateMonitoredItemsResponse", true, false},
    {763, "ModifyMonitoredItemsRequest", false, false},
    {766, "ModifyMonitoredItemsResponse", true, false},
    {781, "DeleteMonitoredItemsRequest", false, false},
    {784, "DeleteMonitoredItemsResponse", true, false},
    {787, "CreateSubscriptionRequest", false, false},
    {790, "CreateSubscriptionResponse", true, false},
    {793, "ModifySubscriptionRequest", false, false},
    {796, "ModifySubscriptionResponse", true, false},
    {799, "SetPublishingModeRequest", false, false},
    {802, "SetPublishingModeResponse", true, false},
    {826, "PublishRequest", false, false},
    {829, "PublishResponse", true, false},
    {832, "RepublishRequest", false, false},
    {835, "RepublishResponse", true, false},
    {847, "DeleteSubscriptionsRequest", false, false},
    {850, "DeleteSubscriptionsResponse", true, false},
};

const ServiceInfo* lookup_service(uint32_t id) {
    for (const auto& s : kServices) {
        if (s.id == id) return &s;
    }
    return nullptr;
}

// Dispatches to the right Tier-1 decoder by service name. ServiceFault, CloseSecureChannelRequest,
// CloseSecureChannelResponse, and CloseSessionResponse have no Parameters struct at all beyond
// RequestHeader/ResponseHeader (confirmed against python-opcua's own generated bindings -- see
// this file's header comment), so they fall through with nothing further to decode.
void call_tier1_decoder(const std::string& name, Cursor& c, std::vector<std::string>& values,
                         std::vector<std::string>& notes) {
    if (name == "OpenSecureChannelRequest") decode_open_secure_channel_request_params(c, values);
    else if (name == "OpenSecureChannelResponse") decode_open_secure_channel_response_params(c, values);
    else if (name == "GetEndpointsRequest") decode_get_endpoints_request_params(c, values);
    else if (name == "GetEndpointsResponse") decode_get_endpoints_response_params(c, values);
    else if (name == "FindServersRequest") decode_find_servers_request_params(c, values);
    else if (name == "FindServersResponse") decode_find_servers_response_params(c, values);
    else if (name == "CreateSessionRequest") decode_create_session_request_params(c, values);
    else if (name == "CreateSessionResponse") decode_create_session_response_params(c, values);
    else if (name == "ActivateSessionRequest") decode_activate_session_request_params(c, values, notes);
    else if (name == "ActivateSessionResponse") decode_activate_session_response_params(c, values);
    else if (name == "CloseSessionRequest") decode_close_session_request_params(c, values);
}

// ------------------------------------------------------------------------------------------
// UA-TCP common header identification.

struct MessageTypeInfo {
    bool valid = false;
    std::string name;
    bool is_secure_conversation = false;  // true for OPN/CLO/MSG (12-byte header, security+
                                            // sequence headers follow); false for HEL/ACK/ERR/RHE
                                            // (8-byte header, body follows directly)
};

MessageTypeInfo message_type_from_bytes(ByteSpan payload) {
    char a = static_cast<char>(payload.at(0));
    char b = static_cast<char>(payload.at(1));
    char d = static_cast<char>(payload.at(2));
    std::string code{a, b, d};
    if (code == "HEL") return {true, "Hello", false};
    if (code == "ACK") return {true, "Acknowledge", false};
    if (code == "ERR") return {true, "Error", false};
    if (code == "RHE") return {true, "ReverseHello", false};
    if (code == "OPN") return {true, "OpenSecureChannel", true};
    if (code == "CLO") return {true, "CloseSecureChannel", true};
    if (code == "MSG") return {true, "Message", true};
    return {};
}

std::string build_summary(const OpcUaMessage& msg) {
    std::ostringstream s;
    if (!msg.has_secure_channel) {
        s << msg.message_type;
        for (const auto& v : msg.values) s << ' ' << v;
        return s.str();
    }
    s << msg.message_type;
    if (msg.chunk_type != 'F') s << " (chunk '" << msg.chunk_type << "')";
    if (msg.is_asymmetric) {
        s << " policy=" << (msg.security_policy_uri.empty() ? "?" : msg.security_policy_uri);
    } else {
        s << " channel=" << msg.secure_channel_id << " token=" << msg.token_id;
    }
    if (msg.service_recognized) {
        s << ' ' << msg.service_name;
        if (msg.has_header && msg.header.is_response) s << " result=" << msg.header.status_code_name;
    } else if (msg.message_type == "Message") {
        s << " (service type-id " << msg.service_type_id << ", ns=" << msg.service_namespace
          << " -- not in this decoder's dispatch table)";
    }
    return s.str();
}

}  // namespace

std::optional<size_t> opcua_declared_length(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    if (!message_type_from_bytes(payload).valid) return std::nullopt;
    uint8_t chunk = payload.at(3);
    if (chunk != 'F' && chunk != 'C' && chunk != 'A') return std::nullopt;
    uint32_t size = static_cast<uint32_t>(payload.at(4)) | (static_cast<uint32_t>(payload.at(5)) << 8) |
                    (static_cast<uint32_t>(payload.at(6)) << 16) |
                    (static_cast<uint32_t>(payload.at(7)) << 24);
    if (size < 8) return std::nullopt;
    return size;
}

std::optional<OpcUaMessage> try_parse_opcua_message(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    MessageTypeInfo mt = message_type_from_bytes(payload);
    if (!mt.valid) return std::nullopt;
    uint8_t chunk = payload.at(3);
    if (chunk != 'F' && chunk != 'C' && chunk != 'A') return std::nullopt;
    uint32_t declared_size = static_cast<uint32_t>(payload.at(4)) |
                              (static_cast<uint32_t>(payload.at(5)) << 8) |
                              (static_cast<uint32_t>(payload.at(6)) << 16) |
                              (static_cast<uint32_t>(payload.at(7)) << 24);
    if (declared_size < 8) return std::nullopt;

    OpcUaMessage msg;
    msg.message_type = mt.name;
    msg.chunk_type = static_cast<char>(chunk);
    msg.message_size = declared_size;
    msg.wire_length = std::min(static_cast<size_t>(declared_size), payload.size());
    if (msg.chunk_type != 'F') {
        msg.notes.push_back(std::string("chunk type '") + msg.chunk_type +
                             "' -- this decoder does not reassemble a message split across "
                             "multiple OPC UA chunks, see opcua.hpp's \"Chunking\" section");
    }

    size_t available = payload.size();
    size_t body_end = std::min(static_cast<size_t>(declared_size), available);
    if (static_cast<size_t>(declared_size) > available) {
        msg.notes.push_back("OPC UA message declares MessageSize " + std::to_string(declared_size) +
                             " but only " + std::to_string(available) + " byte(s) are available -- "
                             "truncated");
    }
    ByteSpan whole_body = payload.subspan(8, body_end - 8);

    try {
        if (!mt.is_secure_conversation) {
            if (msg.chunk_type == 'F') {
                Cursor bc(whole_body);
                if (mt.name == "Hello") decode_hello(bc, msg.values);
                else if (mt.name == "Acknowledge") decode_acknowledge(bc, msg.values);
                else if (mt.name == "Error") decode_error(bc, msg.values);
                else if (mt.name == "ReverseHello") decode_reverse_hello(bc, msg.values);
                if (bc.remaining() > 0) {
                    msg.notes.push_back(std::to_string(bc.remaining()) +
                                         " trailing byte(s) after this message's own decoded fields "
                                         "(ignored)");
                }
            } else {
                msg.body_shown_as_hex = true;
                msg.body_hex = to_hex(whole_body);
                msg.body_length = whole_body.size();
            }
        } else {
            Cursor bc(whole_body);
            msg.has_secure_channel = true;
            msg.secure_channel_id = bc.u32le();
            if (mt.name == "OpenSecureChannel") {
                msg.is_asymmetric = true;
                msg.security_policy_uri = read_string(bc).value_or("");
                OpcUaByteString sender_cert = read_bytestring(bc);
                msg.has_sender_certificate = sender_cert.present && sender_cert.length > 0;
                msg.sender_certificate_length = sender_cert.length;
                OpcUaByteString recv_thumb = read_bytestring(bc);
                msg.has_receiver_certificate_thumbprint = recv_thumb.present && recv_thumb.length > 0;
                msg.receiver_certificate_thumbprint_length = recv_thumb.length;
            } else {
                msg.token_id = bc.u32le();
            }
            msg.sequence_number = bc.u32le();
            msg.request_id = bc.u32le();

            if (msg.chunk_type != 'F') {
                ByteSpan rest = bc.rest();
                msg.body_shown_as_hex = true;
                msg.body_hex = to_hex(rest);
                msg.body_length = rest.size();
            } else {
                // See opcua.hpp's "Opportunistic MSG/OPN/CLO body decode" section: a failure
                // anywhere in this inner block is caught here (not by the outer catch below) so a
                // service-body decode failure still leaves the already-decoded SecureChannelId/
                // security header/sequence header above intact in the returned message.
                size_t service_start = bc.position();
                try {
                    OpcUaNodeIdInfo type_id = read_node_id(bc);
                    msg.service_namespace = type_id.ns;
                    msg.service_type_id = type_id.numeric_id;
                    const ServiceInfo* svc =
                        (type_id.ns == 0 && type_id.encoding <= 0x02) ? lookup_service(type_id.numeric_id)
                                                                       : nullptr;
                    if (!svc) {
                        msg.service_recognized = false;
                        ByteSpan rest = bc.rest();
                        msg.body_shown_as_hex = !rest.empty();
                        msg.body_hex = to_hex(rest);
                        msg.body_length = rest.size();
                    } else {
                        msg.service_recognized = true;
                        msg.service_name = svc->name;
                        msg.has_header = true;
                        msg.header = svc->is_response ? read_response_header(bc, msg.values)
                                                       : read_request_header(bc, msg.values);
                        if (svc->full_decode) {
                            msg.service_body_decoded = true;
                            call_tier1_decoder(msg.service_name, bc, msg.values, msg.notes);
                            if (bc.remaining() > 0) {
                                msg.notes.push_back(std::to_string(bc.remaining()) +
                                                     " trailing byte(s) after this service's own "
                                                     "decoded fields (ignored)");
                            }
                        } else {
                            msg.service_body_decoded = false;
                            ByteSpan rest = bc.rest();
                            msg.body_shown_as_hex = !rest.empty();
                            msg.body_hex = to_hex(rest);
                            msg.body_length = rest.size();
                        }
                    }
                } catch (const ParseError&) {
                    msg.service_recognized = false;
                    msg.service_body_decoded = false;
                    msg.has_header = false;
                    msg.values.clear();
                    ByteSpan rest = whole_body.from(service_start);
                    msg.body_shown_as_hex = true;
                    msg.body_hex = to_hex(rest);
                    msg.body_length = rest.size();
                }
            }
        }
    } catch (const ParseError&) {
        // Failed while reading the SecureChannelId/security header/sequence header itself (OPN/
        // CLO/MSG), or the HEL/ACK/ERR/RHE body -- fall back to raw hex for everything after the
        // 8-byte common header, which the structural detection gate above already validated.
        msg.has_secure_channel = false;
        msg.is_asymmetric = false;
        msg.service_recognized = false;
        msg.has_header = false;
        msg.values.clear();
        msg.body_shown_as_hex = true;
        msg.body_hex = to_hex(whole_body);
        msg.body_length = whole_body.size();
    }

    msg.summary = build_summary(msg);
    return msg;
}

}  // namespace conduitscope
