// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/yaml_mini.hpp"

#include <cctype>

namespace conduitscope::yaml_mini {

const Node* Node::find(const std::string& key) const {
    if (type != NodeType::Mapping) {
        return nullptr;
    }
    for (const auto& [k, v] : mapping) {
        if (k == key) {
            return &v;
        }
    }
    return nullptr;
}

namespace {

std::string rtrim(const std::string& s) {
    size_t end = s.find_last_not_of(" \t");
    return end == std::string::npos ? std::string() : s.substr(0, end + 1);
}

std::string trim(const std::string& s) {
    size_t start = s.find_first_not_of(" \t");
    if (start == std::string::npos) {
        return std::string();
    }
    size_t end = s.find_last_not_of(" \t");
    return s.substr(start, end - start + 1);
}

// One pre-processed source line: leading whitespace stripped into `indent` (spaces only -- a tab
// anywhere in the leading whitespace is rejected at construction time, see build_lines below), any
// "#" comment (outside quotes) and trailing whitespace stripped from `content`. Blank and
// comment-only lines are never materialized -- build_lines() skips them entirely, since neither
// indentation nor sequencing has anything to check against on a line with no real content.
struct RawLine {
    int line_no = 0;
    int indent = 0;
    std::string content;
};

// Strips a "#" comment from `s`, honoring single/double quotes (a "#" inside either is literal
// text, not a comment start) and requiring the "#" to be at the start of the line or preceded by
// whitespace (so a bare scalar containing "#" without a preceding space, while unusual for this
// tool's schema, isn't silently truncated). Does not validate quote balance -- an unterminated
// quote is caught later, when the resulting content is interpreted as a scalar/key.
std::string strip_comment(const std::string& s) {
    bool in_squote = false;
    bool in_dquote = false;
    for (size_t i = 0; i < s.size(); ++i) {
        char c = s[i];
        if (in_squote) {
            if (c == '\'') in_squote = false;
            continue;
        }
        if (in_dquote) {
            if (c == '\\' && i + 1 < s.size()) {
                ++i;  // skip the escaped character
            } else if (c == '"') {
                in_dquote = false;
            }
            continue;
        }
        if (c == '\'') {
            in_squote = true;
        } else if (c == '"') {
            in_dquote = true;
        } else if (c == '#' && (i == 0 || s[i - 1] == ' ' || s[i - 1] == '\t')) {
            return s.substr(0, i);
        }
    }
    return s;
}

// Splits `text` into RawLines, discarding blank and comment-only lines. Throws YamlError on a tab
// used for indentation (tabs later in a line, e.g. inside a quoted scalar, are left alone -- only
// leading-whitespace tabs are ambiguous enough to reject) and on a document marker ("---"/"..."),
// which this parser doesn't support (policy files are always a single document).
std::vector<RawLine> build_lines(const std::string& text) {
    std::vector<RawLine> lines;
    size_t pos = 0;
    int line_no = 0;
    while (pos <= text.size()) {
        size_t nl = text.find('\n', pos);
        std::string raw = (nl == std::string::npos) ? text.substr(pos) : text.substr(pos, nl - pos);
        ++line_no;
        if (!raw.empty() && raw.back() == '\r') {
            raw.pop_back();
        }

        // A leading tab is only truly ambiguous as indentation if it comes before any non-space
        // content; check the leading whitespace run specifically rather than the whole line (a
        // tab inside a later quoted scalar, while unusual, isn't an indentation problem).
        size_t leading_ws_end = raw.find_first_not_of(" \t");
        if (leading_ws_end != std::string::npos && raw.substr(0, leading_ws_end).find('\t') != std::string::npos) {
            throw YamlError("tab characters are not supported for indentation -- use spaces", line_no);
        }

        std::string stripped = strip_comment(raw);
        if (trim(stripped).empty()) {
            // Blank line, or nothing left after stripping a "#" comment -- neither indentation
            // nor sequencing needs to see this line at all.
            if (nl == std::string::npos) break;
            pos = nl + 1;
            continue;
        }
        size_t indent_pos = stripped.find_first_not_of(' ');
        int indent = static_cast<int>(indent_pos);
        std::string content = rtrim(stripped.substr(indent_pos));

        if (content == "---" || content == "...") {
            throw YamlError("multi-document markers ('---'/'...') are not supported -- a policy "
                             "file is always a single document",
                             line_no);
        }
        lines.push_back(RawLine{line_no, indent, content});

        if (nl == std::string::npos) break;
        pos = nl + 1;
    }
    return lines;
}

bool starts_with_dash_item(const std::string& s) { return !s.empty() && s[0] == '-' && (s.size() == 1 || s[1] == ' '); }

std::string unquote_scalar(const std::string& raw, int line_no) {
    if (raw.empty()) {
        return raw;
    }
    if (raw.front() == '"') {
        if (raw.size() < 2 || raw.back() != '"') {
            throw YamlError("unterminated quoted scalar", line_no);
        }
        std::string out;
        size_t content_end = raw.size() - 1;  // index of the closing quote
        for (size_t i = 1; i < content_end; ++i) {
            if (raw[i] == '\\' && i + 1 < content_end) {
                char next = raw[i + 1];
                if (next == '"' || next == '\\') {
                    out += next;
                    ++i;
                    continue;
                }
            }
            out += raw[i];
        }
        return out;
    }
    if (raw.front() == '\'') {
        if (raw.size() < 2 || raw.back() != '\'') {
            throw YamlError("unterminated quoted scalar", line_no);
        }
        return raw.substr(1, raw.size() - 2);
    }
    return raw;
}

// Splits a flow sequence's inside ("a, b, c" -- the text between "[" and "]") on top-level commas,
// respecting quotes (a comma inside a quoted element is literal). No nested "[" / "{" is
// supported inside a flow sequence -- see the class-level doc comment.
std::vector<std::string> split_flow_items(const std::string& inside, int line_no) {
    std::vector<std::string> items;
    std::string current;
    bool in_squote = false, in_dquote = false;
    for (size_t i = 0; i < inside.size(); ++i) {
        char c = inside[i];
        if (in_squote) {
            current += c;
            if (c == '\'') in_squote = false;
            continue;
        }
        if (in_dquote) {
            current += c;
            if (c == '\\' && i + 1 < inside.size()) {
                current += inside[++i];
            } else if (c == '"') {
                in_dquote = false;
            }
            continue;
        }
        if (c == '\'') {
            in_squote = true;
            current += c;
        } else if (c == '"') {
            in_dquote = true;
            current += c;
        } else if (c == '[' || c == '{') {
            throw YamlError("nested flow sequences/mappings ('[' / '{' inside a flow sequence) are "
                             "not supported",
                             line_no);
        } else if (c == ',') {
            items.push_back(trim(current));
            current.clear();
        } else {
            current += c;
        }
    }
    if (in_squote || in_dquote) {
        throw YamlError("unterminated quoted scalar inside a flow sequence", line_no);
    }
    // A trailing comma ("[a, b,]") leaves `current` empty here -- that's a separator, not a
    // fourth element, so only a genuinely non-empty final item is pushed. (An empty flow sequence,
    // "[]", never reaches this function at all -- parse_scalar_token handles it before calling
    // split_flow_items -- so there's no legitimate case where an empty trailing item belongs.)
    std::string last = trim(current);
    if (!last.empty()) {
        items.push_back(last);
    }
    return items;
}

Node parse_scalar_token(const std::string& text, int line_no) {
    std::string t = trim(text);
    if (t.empty()) {
        return Node{NodeType::Null, "", {}, {}, line_no};
    }
    if (t.front() == '[') {
        if (t.back() != ']') {
            throw YamlError("flow sequence is missing its closing ']'", line_no);
        }
        Node node{NodeType::Sequence, "", {}, {}, line_no};
        std::string inside = t.substr(1, t.size() - 2);
        if (trim(inside).empty()) {
            return node;  // "[]" -- empty list
        }
        for (const auto& item_text : split_flow_items(inside, line_no)) {
            Node item{NodeType::Scalar, unquote_scalar(item_text, line_no), {}, {}, line_no};
            node.sequence.push_back(std::move(item));
        }
        return node;
    }
    if (t.front() == '{') {
        throw YamlError("flow mappings ('{...}') are not supported", line_no);
    }
    if (t.front() == '&' || t.front() == '*') {
        throw YamlError("anchors/aliases ('&'/'*') are not supported", line_no);
    }
    if (t.front() == '|' || t.front() == '>') {
        throw YamlError("block scalars ('|'/'>') are not supported", line_no);
    }
    return Node{NodeType::Scalar, unquote_scalar(t, line_no), {}, {}, line_no};
}

// Finds the first top-level (outside quotes) ": " or line-ending ":" in `content`, treating
// everything before it as a mapping key. Returns false if no such colon exists (content is not a
// "key: value" / "key:" line). `has_value` distinguishes "key:" (value comes from an indented
// block on following lines, or is genuinely empty) from "key: something" (has_value=true,
// value_text=the trimmed remainder).
bool split_key_value(const std::string& content, std::string& key, std::string& value_text, bool& has_value) {
    bool in_squote = false, in_dquote = false;
    for (size_t i = 0; i < content.size(); ++i) {
        char c = content[i];
        if (in_squote) {
            if (c == '\'') in_squote = false;
            continue;
        }
        if (in_dquote) {
            if (c == '\\' && i + 1 < content.size()) ++i;
            else if (c == '"') in_dquote = false;
            continue;
        }
        if (c == '\'') { in_squote = true; continue; }
        if (c == '"') { in_dquote = true; continue; }
        if (c == ':' && (i + 1 == content.size() || content[i + 1] == ' ')) {
            key = trim(content.substr(0, i));
            if (key.empty()) return false;
            if (i + 1 == content.size()) {
                value_text.clear();
                has_value = false;
            } else {
                value_text = trim(content.substr(i + 2));
                has_value = !value_text.empty();
            }
            return true;
        }
    }
    return false;
}

struct Cursor {
    const std::vector<RawLine>& lines;
    size_t pos = 0;
    bool done() const { return pos >= lines.size(); }
    const RawLine& peek() const { return lines[pos]; }
    void advance() { ++pos; }
};

Node parse_node_at(Cursor& cur, int indent);

// Consumes "key: value" / "key:" lines at exactly `indent`, appending each to `node.mapping`,
// until the cursor runs out or hits a line at a different indent or a sequence item ("-") at this
// indent (which would mean `indent` is actually a sequence's level, not this mapping's -- callers
// only reach here already knowing that's not the case for the line they're about to consume).
void consume_mapping_pairs(Cursor& cur, int indent, Node& node) {
    while (!cur.done() && cur.peek().indent == indent && !starts_with_dash_item(cur.peek().content)) {
        int line_no = cur.peek().line_no;
        std::string content = cur.peek().content;
        cur.advance();

        std::string key, value_text;
        bool has_value = false;
        if (!split_key_value(content, key, value_text, has_value)) {
            throw YamlError("expected 'key: value' or 'key:' (a mapping entry)", line_no);
        }
        for (const auto& [existing_key, existing_val] : node.mapping) {
            (void)existing_val;
            if (existing_key == key) {
                throw YamlError("duplicate key '" + key + "' in the same mapping", line_no);
            }
        }

        Node value;
        if (has_value) {
            value = parse_scalar_token(value_text, line_no);
        } else if (!cur.done() && cur.peek().indent > indent) {
            value = parse_node_at(cur, cur.peek().indent);
            // parse_node_at/parse_mapping/parse_sequence stamp a block's .line from its first
            // CHILD line, not the key's own line -- override it here so a value node's .line
            // means "where this key was declared", matching what callers actually want it for
            // (e.g. Zone::line/Conduit::line, used in PolicyEngine error/report messages).
            value.line = line_no;
        } else {
            value = Node{NodeType::Null, "", {}, {}, line_no};
        }
        node.mapping.emplace_back(key, std::move(value));
    }
}

Node parse_sequence(Cursor& cur, int indent) {
    Node node{NodeType::Sequence, "", {}, {}, cur.peek().line_no};
    while (!cur.done() && cur.peek().indent == indent && starts_with_dash_item(cur.peek().content)) {
        int line_no = cur.peek().line_no;
        std::string content = cur.peek().content;
        cur.advance();

        std::string rest = content.size() > 1 ? content.substr(1) : "";
        size_t lead = rest.find_first_not_of(' ');
        if (lead == std::string::npos) {
            // Bare "-": the item is a nested block starting on a following, more-indented line.
            if (!cur.done() && cur.peek().indent > indent) {
                Node item = parse_node_at(cur, cur.peek().indent);
                item.line = line_no;  // see the matching override in consume_mapping_pairs
                node.sequence.push_back(std::move(item));
            } else {
                node.sequence.push_back(Node{NodeType::Null, "", {}, {}, line_no});
            }
            continue;
        }
        int item_indent = indent + 1 + static_cast<int>(lead);
        std::string item_content = rest.substr(lead);

        std::string key, value_text;
        bool has_value = false;
        if (split_key_value(item_content, key, value_text, has_value)) {
            Node item{NodeType::Mapping, "", {}, {}, line_no};
            Node first_value;
            if (has_value) {
                first_value = parse_scalar_token(value_text, line_no);
            } else if (!cur.done() && cur.peek().indent > item_indent) {
                first_value = parse_node_at(cur, cur.peek().indent);
                first_value.line = line_no;  // see the matching override in consume_mapping_pairs
            } else {
                first_value = Node{NodeType::Null, "", {}, {}, line_no};
            }
            item.mapping.emplace_back(key, std::move(first_value));
            consume_mapping_pairs(cur, item_indent, item);
            node.sequence.push_back(std::move(item));
        } else {
            node.sequence.push_back(parse_scalar_token(item_content, line_no));
        }
    }
    return node;
}

Node parse_mapping(Cursor& cur, int indent) {
    Node node{NodeType::Mapping, "", {}, {}, cur.peek().line_no};
    consume_mapping_pairs(cur, indent, node);
    return node;
}

Node parse_node_at(Cursor& cur, int indent) {
    if (cur.done() || cur.peek().indent != indent) {
        return Node{NodeType::Null, "", {}, {}, cur.done() ? 0 : cur.peek().line_no};
    }
    if (starts_with_dash_item(cur.peek().content)) {
        return parse_sequence(cur, indent);
    }
    return parse_mapping(cur, indent);
}

}  // namespace

Node parse(const std::string& text) {
    std::vector<RawLine> lines = build_lines(text);
    if (lines.empty()) {
        return Node{};
    }
    Cursor cur{lines, 0};
    int top_indent = cur.peek().indent;
    if (top_indent != 0) {
        throw YamlError("the first line of a policy file must not be indented", cur.peek().line_no);
    }
    Node root = parse_node_at(cur, 0);
    if (!cur.done()) {
        throw YamlError("indentation does not match any enclosing block here", cur.peek().line_no);
    }
    return root;
}

}  // namespace conduitscope::yaml_mini
