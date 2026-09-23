// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/winrm.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>

#include "conduitscope/it_protocols.hpp"

namespace conduitscope {

namespace {

std::string span_to_string(ByteSpan span) {
    return std::string(reinterpret_cast<const char*>(span.data()), span.size());
}

bool iequals(std::string_view a, std::string_view b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        if (std::tolower(static_cast<unsigned char>(a[i])) != std::tolower(static_cast<unsigned char>(b[i]))) {
            return false;
        }
    }
    return true;
}

std::string to_lower(std::string s) {
    for (char& c : s) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

// Decodes the handful of XML entities a WS-Man envelope's own text content actually needs
// (&lt; &gt; &amp; &quot; &apos;, plus decimal/hex numeric character references) into UTF-8. Not a
// full XML entity decoder (no named-entity table beyond the five predefined ones, matching this
// file's own "structural signature, not full grammar" bar) -- see winrm.hpp's own "XML EXTRACTION"
// section.
std::string xml_unescape(std::string_view text) {
    std::string out;
    out.reserve(text.size());
    for (size_t i = 0; i < text.size();) {
        if (text[i] != '&') {
            out += text[i++];
            continue;
        }
        size_t semi = text.find(';', i);
        if (semi == std::string_view::npos || semi - i > 10) {
            out += text[i++];
            continue;
        }
        std::string_view entity = text.substr(i + 1, semi - i - 1);
        if (entity == "lt") {
            out += '<';
        } else if (entity == "gt") {
            out += '>';
        } else if (entity == "amp") {
            out += '&';
        } else if (entity == "quot") {
            out += '"';
        } else if (entity == "apos") {
            out += '\'';
        } else if (!entity.empty() && entity[0] == '#') {
            long code = 0;
            bool ok = false;
            try {
                if (entity.size() > 1 && (entity[1] == 'x' || entity[1] == 'X')) {
                    code = std::stol(std::string(entity.substr(2)), nullptr, 16);
                } else {
                    code = std::stol(std::string(entity.substr(1)), nullptr, 10);
                }
                ok = true;
            } catch (...) {
                ok = false;
            }
            if (ok && code > 0 && code < 0x80) {
                out += static_cast<char>(code);
            } else if (ok) {
                out += '?';  // outside ASCII -- not worth a full UTF-8 encoder for this narrow field
            } else {
                out += text.substr(i, semi - i + 1);
            }
        } else {
            // Unrecognized entity -- keep the raw text rather than guessing.
            out += text.substr(i, semi - i + 1);
            i = semi + 1;
            continue;
        }
        i = semi + 1;
    }
    return out;
}

// One matched XML start-tag -- see winrm.hpp's own "XML EXTRACTION" section for the deliberate
// scope limits this whole family of helpers shares.
struct XmlTag {
    size_t name_end;    // index right after the local name (start of attributes, or '>'/'/')
    size_t tag_close;   // index of the tag's own '>'
    bool self_closing;
};

// Finds the next start-tag (not a closing tag, processing instruction, or comment) whose LOCAL
// name -- the part after an optional "prefix:" -- exactly equals `local_name`, searching from
// `from`. The character immediately after the candidate name must be whitespace, '>', or '/' (an
// exact tag-name boundary), so "Command" can never match inside "CommandId"/"CommandLine"/
// "CommandState". Returns std::nullopt if no such tag exists.
std::optional<XmlTag> find_start_tag(std::string_view xml, std::string_view local_name, size_t from) {
    size_t pos = from;
    while (pos < xml.size()) {
        size_t lt = xml.find('<', pos);
        if (lt == std::string_view::npos) return std::nullopt;
        size_t i = lt + 1;
        if (i >= xml.size()) return std::nullopt;
        char c0 = xml[i];
        if (c0 == '/' || c0 == '?' || c0 == '!') {
            pos = lt + 1;
            continue;
        }
        size_t j = i;
        size_t name_start = i;
        while (j < xml.size()) {
            char c = xml[j];
            if (c == ':') {
                name_start = j + 1;
                ++j;
                continue;
            }
            if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '>' || c == '/') break;
            ++j;
        }
        std::string_view candidate = xml.substr(name_start, j - name_start);
        if (candidate == local_name) {
            size_t k = j;
            bool in_squote = false, in_dquote = false;
            while (k < xml.size()) {
                char c = xml[k];
                if (in_squote) {
                    if (c == '\'') in_squote = false;
                } else if (in_dquote) {
                    if (c == '"') in_dquote = false;
                } else if (c == '\'') {
                    in_squote = true;
                } else if (c == '"') {
                    in_dquote = true;
                } else if (c == '>') {
                    break;
                }
                ++k;
            }
            if (k >= xml.size()) return std::nullopt;  // unterminated tag -- truncated capture
            XmlTag tag;
            tag.name_end = j;
            tag.tag_close = k;
            tag.self_closing = k > 0 && xml[k - 1] == '/';
            return tag;
        }
        pos = lt + 1;
    }
    return std::nullopt;
}

// The text content of the FIRST element whose local name equals `local_name`, XML-unescaped, or
// std::nullopt if none exists. A self-closing element (`<x:Foo/>`) yields an empty string, not
// nullopt -- present but empty, the same distinction every other bool-guarded optional field in
// this codebase's decoders makes (see e.g. drsuapi.hpp's has_* flags).
std::optional<std::string> find_xml_element_text(std::string_view xml, std::string_view local_name) {
    auto tag = find_start_tag(xml, local_name, 0);
    if (!tag) return std::nullopt;
    if (tag->self_closing) return std::string();
    size_t text_start = tag->tag_close + 1;
    size_t text_end = xml.find('<', text_start);
    if (text_end == std::string_view::npos) text_end = xml.size();
    return xml_unescape(xml.substr(text_start, text_end - text_start));
}

// Every element whose local name equals `local_name`, in wire order -- used for CommandLine's own
// `Arguments` elements (MS-WSMV's ArgumentType allows more than one, one per command-line argument).
std::vector<std::string> find_all_xml_element_texts(std::string_view xml, std::string_view local_name) {
    std::vector<std::string> out;
    size_t pos = 0;
    while (true) {
        auto tag = find_start_tag(xml, local_name, pos);
        if (!tag) break;
        if (tag->self_closing) {
            out.emplace_back();
            pos = tag->tag_close + 1;
            continue;
        }
        size_t text_start = tag->tag_close + 1;
        size_t text_end = xml.find('<', text_start);
        if (text_end == std::string_view::npos) text_end = xml.size();
        out.push_back(xml_unescape(xml.substr(text_start, text_end - text_start)));
        pos = text_end;
    }
    return out;
}

bool has_xml_element(std::string_view xml, std::string_view local_name) {
    return find_start_tag(xml, local_name, 0).has_value();
}

// The text content of the first element carrying an attribute `attr_name="attr_value"` (or with
// single quotes) anywhere in its own start-tag -- the shape ShellId always travels in
// (`<w:Selector Name="ShellId">the-actual-id</w:Selector>`, both in a Create response's body and in
// every later request's own header SelectorSet -- see winrm.hpp's own file header comment).
std::optional<std::string> find_element_text_by_attribute(std::string_view xml, std::string_view attr_name,
                                                            std::string_view attr_value) {
    std::string needle_dq = std::string(attr_name) + "=\"" + std::string(attr_value) + "\"";
    std::string needle_sq = std::string(attr_name) + "='" + std::string(attr_value) + "'";
    size_t pos = xml.find(needle_dq);
    if (pos == std::string_view::npos) pos = xml.find(needle_sq);
    if (pos == std::string_view::npos) return std::nullopt;

    size_t k = pos;
    bool in_squote = false, in_dquote = false;
    while (k < xml.size()) {
        char c = xml[k];
        if (in_squote) {
            if (c == '\'') in_squote = false;
        } else if (in_dquote) {
            if (c == '"') in_dquote = false;
        } else if (c == '\'') {
            in_squote = true;
        } else if (c == '"') {
            in_dquote = true;
        } else if (c == '>') {
            break;
        }
        ++k;
    }
    if (k >= xml.size()) return std::nullopt;
    if (k > 0 && xml[k - 1] == '/') return std::string();  // self-closing -- present but empty
    size_t text_start = k + 1;
    size_t text_end = xml.find('<', text_start);
    if (text_end == std::string_view::npos) text_end = xml.size();
    return xml_unescape(xml.substr(text_start, text_end - text_start));
}

// The value of the first `attr_name="..."` (or '...') found ANYWHERE in `xml`, regardless of which
// element it sits on -- the fallback shape CommandId travels in on a Send/Receive/Signal request
// (an attribute directly on that request's own body element, not a separate ShellId-style
// Name="..." selector) -- see winrm.hpp's own file header comment.
std::optional<std::string> find_attribute_anywhere(std::string_view xml, std::string_view attr_name) {
    std::string needle_dq = std::string(attr_name) + "=\"";
    size_t pos = xml.find(needle_dq);
    if (pos != std::string_view::npos) {
        pos += needle_dq.size();
        size_t end = xml.find('"', pos);
        if (end == std::string_view::npos) return std::nullopt;
        return xml_unescape(xml.substr(pos, end - pos));
    }
    std::string needle_sq = std::string(attr_name) + "='";
    pos = xml.find(needle_sq);
    if (pos == std::string_view::npos) return std::nullopt;
    pos += needle_sq.size();
    size_t end = xml.find('\'', pos);
    if (end == std::string_view::npos) return std::nullopt;
    return xml_unescape(xml.substr(pos, end - pos));
}

// One "Name: Value" HTTP header line, name as spelled on the wire (comparisons are
// case-insensitive, see header_value below -- real captures spell these inconsistently).
using HeaderLine = std::pair<std::string, std::string>;

// Splits an HTTP header BLOCK (start-line + header lines, CRLF-separated -- exactly
// find_header_terminator's own [0, header_end) range) into its individual header lines, skipping
// the start-line itself (the caller already parsed that separately).
std::vector<HeaderLine> split_header_lines(std::string_view header_block) {
    std::vector<HeaderLine> out;
    size_t pos = 0;
    bool first = true;
    while (pos <= header_block.size()) {
        size_t eol = header_block.find("\r\n", pos);
        std::string_view line =
            (eol == std::string_view::npos) ? header_block.substr(pos) : header_block.substr(pos, eol - pos);
        if (first) {
            first = false;
        } else if (!line.empty()) {
            size_t colon = line.find(':');
            if (colon != std::string_view::npos) {
                std::string name(line.substr(0, colon));
                size_t vstart = colon + 1;
                while (vstart < line.size() && (line[vstart] == ' ' || line[vstart] == '\t')) ++vstart;
                out.emplace_back(std::move(name), std::string(line.substr(vstart)));
            }
        }
        if (eol == std::string_view::npos) break;
        pos = eol + 2;
    }
    return out;
}

std::optional<std::string> header_value(const std::vector<HeaderLine>& headers, std::string_view name) {
    for (const auto& [n, v] : headers) {
        if (iequals(n, name)) return v;
    }
    return std::nullopt;
}

// Index right after the header block's own terminating blank line ('\r\n\r\n', the start of the
// body), or std::nullopt if that terminator hasn't appeared in `payload` yet.
std::optional<size_t> find_header_terminator(ByteSpan payload) {
    if (payload.size() < 4) return std::nullopt;
    for (size_t i = 0; i + 4 <= payload.size(); ++i) {
        if (payload.at(i) == '\r' && payload.at(i + 1) == '\n' && payload.at(i + 2) == '\r' &&
            payload.at(i + 3) == '\n') {
            return i + 4;
        }
    }
    return std::nullopt;
}

void build_summary_and_notes(WinRmMessage& msg) {
    std::ostringstream s;
    if (msg.is_response) {
        s << "HTTP/1.1 " << msg.http_status;
        if (!msg.http_status_text.empty()) s << " " << msg.http_status_text;
    } else {
        s << (msg.http_method.empty() ? std::string("HTTP") : msg.http_method) << " "
          << (msg.http_target.empty() ? std::string("?") : msg.http_target);
    }
    if (msg.has_envelope && !msg.wsa_action_name.empty()) {
        s << " -- WS-Man " << msg.wsa_action_name;
        if (!msg.is_response && msg.has_command_line) {
            s << " (" << msg.command_line << ")";
        }
    } else if (msg.chunked) {
        s << " (chunked body, not decoded)";
    }
    msg.summary = s.str();

    if (msg.chunked) {
        msg.notes.push_back(
            "Transfer-Encoding: chunked body -- this decoder does not reassemble or decode a "
            "chunked WS-Man body (see winrm.hpp's own scope limitation); only the HTTP start-line "
            "and headers above were decoded for this message");
    }

    // Flagship note 1: a remote shell was actually opened -- only on the RESPONSE that proves it
    // (carries the newly-allocated ShellId), never the request, which can't yet know whether
    // Create will succeed.
    if (msg.is_response && msg.has_shell_id && msg.wsa_action_name.find("Create") != std::string::npos) {
        msg.notes.push_back("remote shell opened (ShellId " + msg.shell_id + ")");
    }

    // Flagship note 2: a command was executed -- the request is where the command text actually
    // lives on the wire (the matching response only ever carries a CommandId, no command text).
    if (!msg.is_response && msg.wsa_action_name == "Command" && msg.has_command_line) {
        msg.notes.push_back("command executed: " + msg.command_line);
    }

    if (msg.is_cim_query && msg.has_wql_filter) {
        msg.notes.push_back("CIM/WMI query riding WinRM transport (ResourceURI: " + msg.resource_uri +
                             ", WQL: " + msg.wql_filter + ")");
    }

    if (msg.is_psrp) {
        msg.notes.push_back(
            "PowerShell Remoting (PSRP) endpoint (ResourceURI: " + msg.resource_uri +
            ") -- this decoder does not decode PSRP's own nested binary fragment protocol; only "
            "the outer WS-Man envelope fields above are visible");
    }

    if (msg.has_auth_header && msg.auth_scheme == "Basic") {
        msg.notes.push_back(
            "HTTP Basic authentication observed over plaintext WinRM (TCP port 5985) -- the "
            "credential is base64-encoded, not encrypted, and trivially reversible to anyone who "
            "can see this traffic");
    }

    if (msg.has_fault) {
        msg.notes.push_back("WS-Man SOAP Fault" +
                             (msg.fault_reason.empty() ? std::string() : (": " + msg.fault_reason)));
    }
}

}  // namespace

std::optional<size_t> winrm_tcp_declared_length(ByteSpan candidate) {
    if (!match_http(candidate)) return std::nullopt;
    auto term = find_header_terminator(candidate);
    if (!term) {
        // Ask decoder.cpp's own TCP reassembly cascade to buffer and wait for one more byte -- see
        // winrm.hpp's own "FRAMING / TCP REASSEMBLY" section for why this is genuinely necessary
        // (unlike every fixed-size-prefix protocol elsewhere in this cascade).
        return candidate.size() + 1;
    }
    std::string header_block = span_to_string(candidate.subspan(0, *term));
    auto headers = split_header_lines(header_block);
    if (auto te = header_value(headers, "Transfer-Encoding")) {
        if (to_lower(*te).find("chunked") != std::string::npos) return *term;
    }
    if (auto cl = header_value(headers, "Content-Length")) {
        try {
            return *term + static_cast<size_t>(std::stoull(*cl));
        } catch (...) {
            return *term;
        }
    }
    return *term;
}

std::optional<WinRmMessage> try_parse_winrm_http(ByteSpan message, bool redact) {
    if (!match_http(message)) return std::nullopt;
    auto term = find_header_terminator(message);
    if (!term) return std::nullopt;  // caller should only ever pass a complete message

    std::string header_block = span_to_string(message.subspan(0, *term));
    size_t first_eol = header_block.find("\r\n");
    std::string start_line = header_block.substr(0, first_eol == std::string::npos ? header_block.size() : first_eol);
    auto headers = split_header_lines(header_block);

    WinRmMessage msg;

    if (start_line.compare(0, 5, "HTTP/") == 0) {
        msg.is_response = true;
        size_t sp1 = start_line.find(' ');
        if (sp1 != std::string::npos) {
            size_t sp2 = start_line.find(' ', sp1 + 1);
            std::string code_str =
                (sp2 == std::string::npos) ? start_line.substr(sp1 + 1) : start_line.substr(sp1 + 1, sp2 - sp1 - 1);
            try {
                msg.http_status = static_cast<uint16_t>(std::stoi(code_str));
            } catch (...) {
            }
            if (sp2 != std::string::npos) msg.http_status_text = start_line.substr(sp2 + 1);
        }
    } else {
        msg.is_response = false;
        size_t sp1 = start_line.find(' ');
        size_t sp2 = (sp1 == std::string::npos) ? std::string::npos : start_line.find(' ', sp1 + 1);
        if (sp1 != std::string::npos) msg.http_method = start_line.substr(0, sp1);
        if (sp1 != std::string::npos && sp2 != std::string::npos) {
            msg.http_target = start_line.substr(sp1 + 1, sp2 - sp1 - 1);
        }
    }

    if (auto ct = header_value(headers, "Content-Type")) {
        msg.has_content_type = true;
        msg.content_type = *ct;
        msg.is_soap_xml = to_lower(*ct).rfind("application/soap+xml", 0) == 0;
    }
    if (auto te = header_value(headers, "Transfer-Encoding")) {
        msg.chunked = to_lower(*te).find("chunked") != std::string::npos;
    }
    if (!msg.chunked) {
        if (auto cl = header_value(headers, "Content-Length")) {
            try {
                msg.declared_content_length = static_cast<size_t>(std::stoull(*cl));
                msg.has_content_length = true;
            } catch (...) {
            }
        }
    }
    std::string_view auth_header_name = msg.is_response ? "WWW-Authenticate" : "Authorization";
    if (auto auth = header_value(headers, auth_header_name)) {
        msg.has_auth_header = true;
        size_t sp = auth->find(' ');
        msg.auth_scheme = (sp == std::string::npos) ? *auth : auth->substr(0, sp);
    }

    if (!msg.chunked && msg.is_soap_xml) {
        size_t body_start = *term;
        size_t body_len = message.size() - body_start;
        if (msg.has_content_length) body_len = std::min(body_len, msg.declared_content_length);
        std::string body = span_to_string(message.subspan(body_start, body_len));

        if (auto action = find_xml_element_text(body, "Action")) {
            msg.wsa_action = *action;
            size_t slash = msg.wsa_action.find_last_of('/');
            msg.wsa_action_name = (slash == std::string::npos) ? msg.wsa_action : msg.wsa_action.substr(slash + 1);
        }
        if (auto ru = find_xml_element_text(body, "ResourceURI")) {
            msg.resource_uri = *ru;
            msg.is_cim_query =
                msg.resource_uri.find("/cim-schema/") != std::string::npos || msg.resource_uri.find("/wmi/") != std::string::npos;
            msg.is_psrp = msg.resource_uri.find("/powershell") != std::string::npos;
        }
        if (auto sid = find_element_text_by_attribute(body, "Name", "ShellId")) {
            msg.has_shell_id = !sid->empty();
            msg.shell_id = *sid;
        }
        if (auto cid = find_xml_element_text(body, "CommandId")) {
            msg.has_command_id = !cid->empty();
            msg.command_id = *cid;
        } else if (auto cid_attr = find_attribute_anywhere(body, "CommandId")) {
            msg.has_command_id = !cid_attr->empty();
            msg.command_id = *cid_attr;
        }
        if (auto cmd = find_xml_element_text(body, "Command")) {
            std::string combined = *cmd;
            for (const std::string& arg : find_all_xml_element_texts(body, "Arguments")) {
                if (!arg.empty()) combined += " " + arg;
            }
            msg.has_command_line = true;
            msg.command_line = combined;
        }
        if (auto filt = find_xml_element_text(body, "Filter")) {
            msg.has_wql_filter = !filt->empty();
            msg.wql_filter = *filt;
        }
        if (has_xml_element(body, "Fault")) {
            msg.has_fault = true;
            if (auto txt = find_xml_element_text(body, "Text")) msg.fault_reason = *txt;
        }
        msg.has_envelope = !msg.wsa_action.empty();
    }

    // Redact BEFORE building the summary/notes below, so both already reflect the masked value --
    // see winrm.hpp's own file header comment on why command_line, unlike every other field here,
    // carries this treatment (DecodeContext::redact_secrets's default, decoder.hpp).
    if (redact && msg.has_command_line && !msg.command_line.empty()) {
        msg.command_line = kRedactedSecretPlaceholder;
    }

    build_summary_and_notes(msg);
    return msg;
}

std::optional<ProtocolResult> WinRmTcpDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto parsed = try_parse_winrm_http(payload, ctx.redact_secrets);
    if (!parsed) return std::nullopt;
    return ProtocolResult::make(std::string("winrm"), std::move(*parsed));
}

const ProtocolDecoder& winrm_tcp_decoder() {
    static const WinRmTcpDecoder instance;
    return instance;
}

}  // namespace conduitscope
