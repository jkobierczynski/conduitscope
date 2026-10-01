// SPDX-License-Identifier: Apache-2.0
// display_filter_parser.cpp - lexer, recursive-descent parser, and evaluator for the display-
// filter grammar described in display_filter.hpp's own file header comment.
//
// No existing boolean-expression lexer/parser exists elsewhere in this codebase (confirmed by
// direct grep across the source tree before writing this file) -- this is new, from-scratch, hand-
// rolled text parsing over an expression string, in the "hand-rolled, one function per construct"
// style already used by src/yaml_mini.cpp, the closest style precedent in this codebase. Operates
// purely on the compiled filter's own source text; never touches capture or BPF (see bpf_filter.cpp
// for that, unrelated, code path).
#include "conduitscope/display_filter.hpp"

#include <cctype>
#include <regex>
#include <sstream>

#include "conduitscope/decoder.hpp"

namespace conduitscope {

// ---------------------------------------------------------------------------------------------
// Lexer
// ---------------------------------------------------------------------------------------------

namespace {

enum class TokenKind {
    Ident,        // a dotted field name, e.g. modbus.func_code, ip.src -- lexed as ONE token since
                  // every real field name is matched against the registry as a whole string anyway
    IntLiteral,
    StringLiteral,
    Eq, Ne, Lt, Le, Gt, Ge,
    AndAnd, OrOr, Bang,
    LParen, RParen, LBrace, RBrace, Comma,
    KwAnd, KwOr, KwNot, KwIn, KwContains, KwMatches, KwTrue, KwFalse,
    End,
};

struct Token {
    TokenKind kind = TokenKind::End;
    std::string text;    // raw source text of this token (identifier text, or the literal's own
                          // spelling) -- used both by the parser and for error messages
    int64_t int_value = 0;
    size_t pos = 0;       // source offset this token started at, for error messages
};

// A simple index-and-peek cursor over the filter's source std::string, modeled on byteio.hpp's
// Cursor API shape (position/remaining/at_end/throw-on-overrun) but over `char` rather than a
// binary ByteSpan -- untrusted, variable-length text deserves the same bounds discipline this
// project's binary parsers already apply.
class Lexer {
public:
    explicit Lexer(const std::string& src) : src_(src) {}

    // Throws std::runtime_error with a message already following this project's "error: display
    // filter '<expr>' <what's wrong> at '<token>' (expected <hint>, e.g. <example>)" convention --
    // compile_display_filter (below) catches this and returns it via the *error out-parameter.
    Token next() {
        skip_whitespace();
        size_t start = pos_;
        if (at_end()) return Token{TokenKind::End, "", 0, start};

        char c = peek();
        if (c == '(') { advance(); return Token{TokenKind::LParen, "(", 0, start}; }
        if (c == ')') { advance(); return Token{TokenKind::RParen, ")", 0, start}; }
        if (c == '{') { advance(); return Token{TokenKind::LBrace, "{", 0, start}; }
        if (c == '}') { advance(); return Token{TokenKind::RBrace, "}", 0, start}; }
        if (c == ',') { advance(); return Token{TokenKind::Comma, ",", 0, start}; }
        if (c == '!') {
            advance();
            if (!at_end() && peek() == '=') { advance(); return Token{TokenKind::Ne, "!=", 0, start}; }
            return Token{TokenKind::Bang, "!", 0, start};
        }
        if (c == '=') {
            advance();
            if (!at_end() && peek() == '=') { advance(); return Token{TokenKind::Eq, "==", 0, start}; }
            fail("unexpected '='", "=", start, "== for equality");
        }
        if (c == '<') {
            advance();
            if (!at_end() && peek() == '=') { advance(); return Token{TokenKind::Le, "<=", 0, start}; }
            return Token{TokenKind::Lt, "<", 0, start};
        }
        if (c == '>') {
            advance();
            if (!at_end() && peek() == '=') { advance(); return Token{TokenKind::Ge, ">=", 0, start}; }
            return Token{TokenKind::Gt, ">", 0, start};
        }
        if (c == '&') {
            advance();
            if (!at_end() && peek() == '&') { advance(); return Token{TokenKind::AndAnd, "&&", 0, start}; }
            fail("unexpected '&'", "&", start, "&& for logical AND");
        }
        if (c == '|') {
            advance();
            if (!at_end() && peek() == '|') { advance(); return Token{TokenKind::OrOr, "||", 0, start}; }
            fail("unexpected '|'", "|", start, "|| for logical OR");
        }
        if (c == '"') return lex_string(start);
        if (std::isdigit(static_cast<unsigned char>(c))) return lex_number(start);
        if (std::isalpha(static_cast<unsigned char>(c)) || c == '_') return lex_ident(start);

        fail(std::string("unexpected character '") + c + "'", std::string(1, c), start,
             "a field name, literal, or operator");
        return Token{};  // unreachable -- fail() always throws
    }

private:
    const std::string& src_;
    size_t pos_ = 0;

    bool at_end() const { return pos_ >= src_.size(); }
    char peek() const { return src_[pos_]; }
    void advance() { ++pos_; }

    void skip_whitespace() {
        while (!at_end() && std::isspace(static_cast<unsigned char>(peek()))) advance();
    }

    [[noreturn]] void fail(const std::string& what, const std::string& offending, size_t /*pos*/,
                            const std::string& hint) const {
        throw std::runtime_error("'" + offending + "' " + what + " (expected " + hint + ")");
    }

    Token lex_string(size_t start) {
        advance();  // opening quote
        std::string value;
        while (true) {
            if (at_end()) {
                fail("has an unterminated string literal", src_.substr(start), start,
                     "a closing '\"', e.g. \"read\"");
            }
            char c = peek();
            if (c == '"') { advance(); break; }
            if (c == '\\' ) {
                advance();
                if (at_end()) {
                    fail("has an unterminated string literal", src_.substr(start), start,
                         "a closing '\"', e.g. \"read\"");
                }
                char esc = peek();
                if (esc == '"' || esc == '\\') {
                    value.push_back(esc);
                    advance();
                } else {
                    // Unknown escape: keep the backslash and the character verbatim, matching this
                    // project's general "don't silently drop unrecognized input" posture.
                    value.push_back('\\');
                    value.push_back(esc);
                    advance();
                }
                continue;
            }
            value.push_back(c);
            advance();
        }
        Token t{TokenKind::StringLiteral, value, 0, start};
        return t;
    }

    Token lex_number(size_t start) {
        std::string text;
        bool is_hex = false;
        if (peek() == '0') {
            text.push_back(peek());
            advance();
            if (!at_end() && (peek() == 'x' || peek() == 'X')) {
                is_hex = true;
                text.push_back(peek());
                advance();
            }
        }
        while (!at_end()) {
            char c = peek();
            bool ok = is_hex ? std::isxdigit(static_cast<unsigned char>(c))
                              : std::isdigit(static_cast<unsigned char>(c));
            if (!ok) break;
            text.push_back(c);
            advance();
        }
        // A bare, unquoted IPv4-dotted-decimal literal (e.g. `ip.src == 10.1.2.3`, matching the
        // user's own example) -- distinguished from a plain integer by a '.' immediately followed
        // by a digit, which a plain integer literal never has. Lexed as a StringLiteral token: an
        // Ip-kind field's type-check already accepts a String-kind literal (see type_check's
        // Compare case), so this needs no separate FilterValueKind of its own. An IPv6 literal, or
        // any other non-dotted-decimal address text, needs an explicit "quoted string" instead --
        // see docs/USER_GUIDE.md's Display filters subsection.
        if (!is_hex && !at_end() && peek() == '.') {
            size_t save = pos_;
            std::string ip_text = text;
            bool looks_like_ip = true;
            while (!at_end() && peek() == '.') {
                ip_text.push_back('.');
                advance();
                if (at_end() || !std::isdigit(static_cast<unsigned char>(peek()))) {
                    looks_like_ip = false;
                    break;
                }
                while (!at_end() && std::isdigit(static_cast<unsigned char>(peek()))) {
                    ip_text.push_back(peek());
                    advance();
                }
            }
            if (looks_like_ip) {
                return Token{TokenKind::StringLiteral, ip_text, 0, start};
            }
            pos_ = save;  // not actually IP-shaped after all -- rewind and fall through as a plain int
        }
        int64_t value = 0;
        try {
            value = std::stoll(text, nullptr, is_hex ? 16 : 10);
        } catch (const std::exception&) {
            fail("is not a valid integer literal", text, start, "a decimal or 0x-hex integer, e.g. 16 or 0x10");
        }
        return Token{TokenKind::IntLiteral, text, value, start};
    }

    Token lex_ident(size_t start) {
        std::string text;
        while (!at_end()) {
            char c = peek();
            // '-' is included so a bare protocol-name existence test can name a hyphenated
            // protocol verbatim (e.g. `s7comm-plus`, matching DecodedPacket::protocol's own
            // spelling) -- safe since the grammar has no subtraction/unary-minus operator to
            // collide with.
            if (std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '.' || c == '-') {
                text.push_back(c);
                advance();
            } else {
                break;
            }
        }
        if (text == "and") return Token{TokenKind::KwAnd, text, 0, start};
        if (text == "or") return Token{TokenKind::KwOr, text, 0, start};
        if (text == "not") return Token{TokenKind::KwNot, text, 0, start};
        if (text == "in") return Token{TokenKind::KwIn, text, 0, start};
        if (text == "contains") return Token{TokenKind::KwContains, text, 0, start};
        if (text == "matches") return Token{TokenKind::KwMatches, text, 0, start};
        if (text == "true") return Token{TokenKind::KwTrue, text, 0, start};
        if (text == "false") return Token{TokenKind::KwFalse, text, 0, start};
        return Token{TokenKind::Ident, text, 0, start};
    }
};

}  // namespace

// ---------------------------------------------------------------------------------------------
// AST
// ---------------------------------------------------------------------------------------------

enum class FilterNodeKind { And, Or, Not, Compare, Contains, Matches, InSet, Exists };
enum class CompareOp { Eq, Ne, Lt, Le, Gt, Ge };

}  // namespace conduitscope

// FilterNode is only forward-declared in display_filter.hpp (an opaque AST node -- callers never
// touch it directly, only through CompiledDisplayFilter::matches). Its complete definition lives
// here, the only translation unit that needs to see inside it.
class conduitscope::FilterNode {
public:
    FilterNodeKind kind = FilterNodeKind::Exists;
    std::shared_ptr<FilterNode> lhs, rhs;   // And/Or/Not
    std::string field_name;                  // Compare/Contains/Matches/InSet/Exists
    CompareOp cmp_op = CompareOp::Eq;        // Compare only
    FilterValue literal;                     // Compare/Contains/Matches rhs
    std::vector<FilterValue> literal_set;    // InSet
    // patch-282 security review finding F2 ("matches regex is compiled once per packet, not once
    // per filter"): Matches only. Compiled exactly once, in type_check() below, at
    // compile_display_filter() time -- before a single packet is read, let alone the capture
    // opened -- rather than reconstructed from `literal.string_value` on every evaluate() call.
    // std::nullopt for every OTHER node kind, and for a Matches node whose regex failed to compile
    // (type_check() throws in that case, so compile_display_filter() returns std::nullopt and no
    // CompiledDisplayFilter holding this node is ever handed back to a caller -- see evaluate()'s
    // own Matches case for why it can therefore dereference this unconditionally).
    std::optional<std::regex> compiled_regex;
};

namespace conduitscope {

// ---------------------------------------------------------------------------------------------
// Parser (recursive descent; grammar in display_filter.hpp's own file header comment)
// ---------------------------------------------------------------------------------------------

namespace {

// patch-282 security review finding F3 ("Display-filter parser has no explicit complexity
// limits"): fixed, non-CLI-configurable ceilings on a -Y expression's own size/shape, each checked
// once at compile time (the same "fail before packet processing" posture every other display-
// filter validation already has -- type mismatch, unknown field, now these too). Deliberately NOT
// exposed as --max-* flags the way --max-reassembly-bytes/-segments/--max-recursion-depth/--max-
// decoded-objects/--max-coalesced-messages are (decode.hpp's own resource-exhaustion family,
// cli_main.cpp): those bound processing of UNTRUSTED, attacker-shaped network traffic at scale,
// where different deployments legitimately need different ceilings; a -Y expression is operator-
// authored on the local command line, the same trust boundary -f/BPF and --policy YAML already sit
// inside (see this file's own type_check() Matches case, patch-282 finding F2, for the identical
// reasoning). These five numbers exist purely so a typo or a script-generated huge expression fails
// fast and cleanly -- a named CLI error -- instead of hanging, ballooning memory, or (nested
// parens/`!`/`not` chains specifically) overflowing this process's own call stack via unbounded
// recursive descent. Values match the review's own suggested starting point exactly.
constexpr size_t kMaxExpressionLength = 64 * 1024;  // bytes of -Y source text
constexpr size_t kMaxAstNodes = 4096;               // FilterNode instances one compiled filter may hold
constexpr int kMaxNestingDepth = 128;                // combined '(' / '!'/'not' recursion depth
constexpr size_t kMaxSetMembers = 512;              // literals in one `in {...}` clause
constexpr size_t kMaxRegexLength = 4096;             // characters in one `matches "..."` pattern

class Parser {
public:
    explicit Parser(const std::string& source) : lexer_(source) {
        advance();
    }

    std::shared_ptr<FilterNode> parse_expression() {
        auto node = parse_or_expr();
        if (current_.kind != TokenKind::End) {
            fail_token(current_, "was not expected here", "end of the expression, or a boolean operator (&& / and / || / or)");
        }
        return node;
    }

private:
    Lexer lexer_;
    Token current_;

    // F3's own node-count and nesting-depth ceilings -- see this file's own kMaxAstNodes/
    // kMaxNestingDepth comment above. node_count_ is incremented once per FilterNode this parser
    // ever allocates (every call site below goes through make_node(), never std::make_shared
    // directly); depth_ is incremented/decremented around the two actual recursive-descent entry
    // points that can nest arbitrarily deep on crafted input -- parse_primary()'s '(' handling and
    // parse_unary_expr()'s '!'/'not' handling. (A long chain of `a && b && c && ...` does NOT
    // increase depth_ -- parse_and_expr()/parse_or_expr() consume repeated same-precedence
    // operators in a plain `while` loop, not recursively -- but it does grow node_count_ linearly,
    // which kMaxAstNodes alone is enough to bound.) Neither counter is ever reset mid-parse; both
    // are scoped to one Parser instance, i.e. one compile_display_filter() call.
    size_t node_count_ = 0;
    int depth_ = 0;

    void advance() { current_ = lexer_.next(); }

    [[noreturn]] void fail_token(const Token& t, const std::string& what, const std::string& hint) const {
        std::string offending = t.kind == TokenKind::End ? "<end of expression>" : t.text;
        throw std::runtime_error("'" + offending + "' " + what + " (expected " + hint + ")");
    }

    bool at(TokenKind k) const { return current_.kind == k; }

    void expect(TokenKind k, const std::string& hint) {
        if (!at(k)) fail_token(current_, "was unexpected", hint);
        advance();
    }

    // Every FilterNode this parser allocates goes through here -- see node_count_'s own comment.
    std::shared_ptr<FilterNode> make_node() {
        if (++node_count_ > kMaxAstNodes) {
            throw std::runtime_error("is too complex (more than " + std::to_string(kMaxAstNodes) +
                " expression nodes) -- simplify it, e.g. by combining repeated clauses");
        }
        return std::make_shared<FilterNode>();
    }

    // Called immediately after consuming a '(' or a '!'/'not' token, before recursing -- see
    // depth_'s own comment. Returning nothing on success (rather than an RAII guard that
    // decrements on scope exit) is deliberate: a thrown std::runtime_error here unwinds straight
    // out through compile_display_filter()'s own catch, abandoning this Parser (and therefore
    // depth_) entirely, so there is no later call on the same Parser that could ever observe a
    // stale, un-decremented depth_ -- the matching `--depth_;` after each successful recursive
    // call below is reached, and only reached, exactly when that recursion genuinely returned.
    void enter_nesting() {
        if (++depth_ > kMaxNestingDepth) {
            throw std::runtime_error("is nested too deeply (more than " +
                std::to_string(kMaxNestingDepth) + " levels of '(' / '!'/'not' combined) -- "
                "simplify the expression");
        }
    }

    std::shared_ptr<FilterNode> parse_or_expr() {
        auto lhs = parse_and_expr();
        while (at(TokenKind::OrOr) || at(TokenKind::KwOr)) {
            advance();
            auto rhs = parse_and_expr();
            auto node = make_node();
            node->kind = FilterNodeKind::Or;
            node->lhs = lhs;
            node->rhs = rhs;
            lhs = node;
        }
        return lhs;
    }

    std::shared_ptr<FilterNode> parse_and_expr() {
        auto lhs = parse_unary_expr();
        while (at(TokenKind::AndAnd) || at(TokenKind::KwAnd)) {
            advance();
            auto rhs = parse_unary_expr();
            auto node = make_node();
            node->kind = FilterNodeKind::And;
            node->lhs = lhs;
            node->rhs = rhs;
            lhs = node;
        }
        return lhs;
    }

    std::shared_ptr<FilterNode> parse_unary_expr() {
        if (at(TokenKind::Bang) || at(TokenKind::KwNot)) {
            advance();
            enter_nesting();  // F3: bounds '!'/'not' chain depth -- see enter_nesting()'s own comment
            auto operand = parse_unary_expr();
            --depth_;
            auto node = make_node();
            node->kind = FilterNodeKind::Not;
            node->lhs = operand;
            return node;
        }
        return parse_primary();
    }

    FilterValue parse_literal() {
        if (at(TokenKind::IntLiteral)) {
            FilterValue v = FilterValue::make_int(current_.int_value);
            advance();
            return v;
        }
        if (at(TokenKind::StringLiteral)) {
            FilterValue v = FilterValue::make_string(current_.text);
            advance();
            return v;
        }
        if (at(TokenKind::KwTrue)) { advance(); return FilterValue::make_bool(true); }
        if (at(TokenKind::KwFalse)) { advance(); return FilterValue::make_bool(false); }
        fail_token(current_, "is not a valid literal",
                   "a decimal/0x-hex integer, a \"quoted string\", or true/false");
    }

    std::shared_ptr<FilterNode> parse_primary() {
        if (at(TokenKind::LParen)) {
            advance();
            enter_nesting();  // F3: bounds '(' nesting depth -- see enter_nesting()'s own comment
            auto inner = parse_or_expr();
            --depth_;
            expect(TokenKind::RParen, "a closing ')'");
            return inner;
        }
        if (!at(TokenKind::Ident)) {
            fail_token(current_, "was not expected here",
                       "a field name (e.g. modbus.func_code), '(' or '!'/'not'");
        }
        std::string field_name = current_.text;
        advance();

        if (at(TokenKind::KwIn)) {
            advance();
            expect(TokenKind::LBrace, "'{' to start a set, e.g. in {1,2,3}");
            auto node = make_node();
            node->kind = FilterNodeKind::InSet;
            node->field_name = field_name;
            node->literal_set.push_back(parse_literal());
            while (at(TokenKind::Comma)) {
                advance();
                // F3: bounds `in {...}` membership -- see kMaxSetMembers's own comment. Checked
                // before each additional literal is parsed/pushed, so a set at exactly the limit
                // (kMaxSetMembers members) is still accepted; the (kMaxSetMembers + 1)-th is not.
                if (node->literal_set.size() >= kMaxSetMembers) {
                    throw std::runtime_error("'in {...}' for '" + field_name + "' has too many "
                        "members (more than " + std::to_string(kMaxSetMembers) + ") -- simplify "
                        "the expression");
                }
                node->literal_set.push_back(parse_literal());
            }
            expect(TokenKind::RBrace, "a closing '}'");
            return node;
        }

        if (at(TokenKind::KwContains) || at(TokenKind::KwMatches)) {
            bool is_matches = at(TokenKind::KwMatches);
            advance();
            if (!at(TokenKind::StringLiteral)) {
                fail_token(current_, "was not expected here",
                           std::string("a \"quoted string\" for ") + (is_matches ? "matches" : "contains"));
            }
            // F3: bounds a `matches` pattern's own length -- see kMaxRegexLength's own comment.
            // Checked here, at the source-text level, independent of (and ahead of) type_check()'s
            // own regex-compilation step (F2, item 111) -- a `contains` string has no such limit,
            // since it's a plain substring search with no construction cost to bound.
            if (is_matches && current_.text.size() > kMaxRegexLength) {
                throw std::runtime_error("'" + field_name + "' matches a regular expression longer "
                    "than " + std::to_string(kMaxRegexLength) + " characters -- simplify the "
                    "pattern");
            }
            auto node = make_node();
            node->kind = is_matches ? FilterNodeKind::Matches : FilterNodeKind::Contains;
            node->field_name = field_name;
            node->literal = FilterValue::make_string(current_.text);
            advance();
            return node;
        }

        CompareOp op;
        bool has_op = true;
        switch (current_.kind) {
            case TokenKind::Eq: op = CompareOp::Eq; break;
            case TokenKind::Ne: op = CompareOp::Ne; break;
            case TokenKind::Lt: op = CompareOp::Lt; break;
            case TokenKind::Le: op = CompareOp::Le; break;
            case TokenKind::Gt: op = CompareOp::Gt; break;
            case TokenKind::Ge: op = CompareOp::Ge; break;
            default: has_op = false; op = CompareOp::Eq; break;
        }
        if (!has_op) {
            // Bare field-existence test: `modbus` alone, or `modbus.func_code` alone.
            auto node = make_node();
            node->kind = FilterNodeKind::Exists;
            node->field_name = field_name;
            return node;
        }
        advance();
        auto node = make_node();
        node->kind = FilterNodeKind::Compare;
        node->field_name = field_name;
        node->cmp_op = op;
        node->literal = parse_literal();
        return node;
    }
};

const char* op_text(CompareOp op) {
    switch (op) {
        case CompareOp::Eq: return "==";
        case CompareOp::Ne: return "!=";
        case CompareOp::Lt: return "<";
        case CompareOp::Le: return "<=";
        case CompareOp::Gt: return ">";
        case CompareOp::Ge: return ">=";
    }
    return "?";
}

// A literal's own Bool-kind value, also accepting the grammar's "1"/"0" Int-literal spelling of
// true/false (see the int_as_bool allowance in type_check's Compare case below, and
// display_filter.hpp's BOOL_LITERAL grammar production) -- only ever called once a literal has
// already been confirmed usable against a Bool-kind field.
bool literal_as_bool(const FilterValue& lit) {
    return lit.kind == FilterValueKind::Bool ? lit.bool_value : (lit.int_value != 0);
}

const char* kind_text(FilterValueKind k) {
    switch (k) {
        case FilterValueKind::Int: return "numeric";
        case FilterValueKind::Bool: return "boolean";
        case FilterValueKind::String: return "string";
        case FilterValueKind::Ip: return "address";
    }
    return "?";
}

// Type-checks one AST node (recursively) against the field registry, AND -- for a Matches node
// only -- compiles its regex into node.compiled_regex (patch-282 security review finding F2: a
// regex literal is compiled here, exactly once, rather than reconstructed from source text on
// every evaluate() call in the packet loop; an invalid regex is therefore also rejected here,
// before a single packet is read, rather than merely caught-and-silently-failed per packet as it
// used to be). Throws std::runtime_error with an already-formatted message on any mismatch -- see
// this file's own compile_display_filter for how the message is finished and returned to the
// caller. Takes `node` by non-const reference specifically so the Matches case below can write
// into it -- every caller (this function's own recursive calls, and compile_display_filter()'s
// initial call against the still-mutable `root` before it is wrapped in `shared_ptr<const
// FilterNode>`) already holds a non-const FilterNode at this point, so this costs nothing.
void type_check(FilterNode& node, const FieldRegistry& registry, const std::string& expr) {
    switch (node.kind) {
        case FilterNodeKind::And:
        case FilterNodeKind::Or:
            type_check(*node.lhs, registry, expr);
            type_check(*node.rhs, registry, expr);
            return;
        case FilterNodeKind::Not:
            type_check(*node.lhs, registry, expr);
            return;
        case FilterNodeKind::Exists: {
            bool has_dot = node.field_name.find('.') != std::string::npos;
            if (has_dot) {
                if (!registry.lookup(node.field_name)) {
                    throw std::runtime_error("field '" + node.field_name + "' is not a recognized "
                        "display-filter field (see 'conduitscope decode --help's -Y/--display-filter "
                        "entry, or docs/USER_GUIDE.md's Display filters section, for the full list)");
                }
            } else if (!registry.is_bare_protocol_name(node.field_name)) {
                throw std::runtime_error("'" + node.field_name + "' is neither a known protocol name "
                    "nor a dotted field name (expected e.g. 'modbus' or 'modbus.func_code')");
            }
            return;
        }
        case FilterNodeKind::Contains: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) {
                throw std::runtime_error("field '" + node.field_name + "' is not a recognized "
                    "display-filter field");
            }
            FilterValueKind fk = registry.kind_of(node.field_name);
            if (fk != FilterValueKind::String) {
                throw std::runtime_error("'" + node.field_name + "' is a " + std::string(kind_text(fk)) +
                    " field and does not support contains/matches (only a string field does, e.g. "
                    "modbus.func_name contains \"Read\")");
            }
            return;
        }
        case FilterNodeKind::Matches: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) {
                throw std::runtime_error("field '" + node.field_name + "' is not a recognized "
                    "display-filter field");
            }
            FilterValueKind fk = registry.kind_of(node.field_name);
            if (fk != FilterValueKind::String) {
                throw std::runtime_error("'" + node.field_name + "' is a " + std::string(kind_text(fk)) +
                    " field and does not support contains/matches (only a string field does, e.g. "
                    "modbus.func_name contains \"Read\")");
            }
            // F2 fix: compile the regex HERE, once, rather than leaving it to be reconstructed from
            // node.literal.string_value on every evaluate() call in the packet loop (the actual bug
            // this finding names) -- and, as a direct consequence, an invalid regex is now rejected
            // right here, before compile_display_filter() ever returns successfully, rather than
            // surviving compilation and then silently failing (via evaluate()'s old per-packet
            // try/catch) on every single packet for the rest of the run.
            try {
                node.compiled_regex.emplace(node.literal.string_value);
            } catch (const std::regex_error& e) {
                throw std::runtime_error("'" + node.field_name + "' matches \"" +
                    node.literal.string_value + "\" is not a valid regular expression (" +
                    e.what() + ")");
            }
            return;
        }
        case FilterNodeKind::InSet: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) {
                throw std::runtime_error("field '" + node.field_name + "' is not a recognized "
                    "display-filter field");
            }
            FilterValueKind fk = registry.kind_of(node.field_name);
            for (const auto& lit : node.literal_set) {
                bool int_as_bool = fk == FilterValueKind::Bool && lit.kind == FilterValueKind::Int &&
                                    (lit.int_value == 0 || lit.int_value == 1);
                bool ok = (lit.kind == fk) || (fk == FilterValueKind::Ip && lit.kind == FilterValueKind::String) ||
                          int_as_bool;
                if (!ok) {
                    throw std::runtime_error("cannot test " + std::string(kind_text(fk)) + " field '" +
                        node.field_name + "' against a " + std::string(kind_text(lit.kind)) +
                        " literal in 'in {...}' (expected every value in the set to be a " +
                        std::string(kind_text(fk)) + ", e.g. " + node.field_name + " in {1,2,3})");
                }
            }
            return;
        }
        case FilterNodeKind::Compare: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) {
                throw std::runtime_error("field '" + node.field_name + "' is not a recognized "
                    "display-filter field (see 'conduitscope decode --help's -Y/--display-filter "
                    "entry, or docs/USER_GUIDE.md's Display filters section, for the full list)");
            }
            FilterValueKind fk = registry.kind_of(node.field_name);
            bool ordering = node.cmp_op != CompareOp::Eq && node.cmp_op != CompareOp::Ne;
            if (ordering && (fk == FilterValueKind::Ip || fk == FilterValueKind::Bool || fk == FilterValueKind::String)) {
                throw std::runtime_error("'" + node.field_name + "' does not support ordering "
                    "comparisons (" + std::string(op_text(node.cmp_op)) + ") -- only == and != apply to "
                    "a " + std::string(kind_text(fk)) + " field");
            }
            // A bare 1/0 integer literal against a Bool-kind field is allowed -- the grammar's own
            // BOOL_LITERAL production (display_filter.hpp's file header comment) treats "1"/"0" as
            // boolean spellings alongside "true"/"false", matching the user's own literal example
            // `goose.simulation == 1`.
            bool int_as_bool = fk == FilterValueKind::Bool && node.literal.kind == FilterValueKind::Int &&
                                (node.literal.int_value == 0 || node.literal.int_value == 1);
            bool kind_ok = (node.literal.kind == fk) ||
                           (fk == FilterValueKind::Ip && node.literal.kind == FilterValueKind::String) ||
                           int_as_bool;
            if (!kind_ok) {
                throw std::runtime_error("cannot compare " + std::string(kind_text(fk)) + " field '" +
                    node.field_name + "' against a " + std::string(kind_text(node.literal.kind)) +
                    " literal (expected a " + std::string(kind_text(fk)) + " value, e.g. " +
                    node.field_name + " " + std::string(op_text(node.cmp_op)) +
                    (fk == FilterValueKind::Int ? " 16" : fk == FilterValueKind::Bool ? " true" : " \"...\"") + ")");
            }
            return;
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Evaluator
// ---------------------------------------------------------------------------------------------

bool evaluate(const FilterNode& node, const DecodedPacket& dp, const FieldRegistry& registry) {
    switch (node.kind) {
        case FilterNodeKind::And:
            return evaluate(*node.lhs, dp, registry) && evaluate(*node.rhs, dp, registry);
        case FilterNodeKind::Or:
            return evaluate(*node.lhs, dp, registry) || evaluate(*node.rhs, dp, registry);
        case FilterNodeKind::Not:
            return !evaluate(*node.lhs, dp, registry);
        case FilterNodeKind::Exists: {
            bool has_dot = node.field_name.find('.') != std::string::npos;
            if (!has_dot) {
                return registry.is_bare_protocol_name(node.field_name) && dp.protocol == node.field_name;
            }
            const FieldExtractor* ext = registry.lookup(node.field_name);
            return ext && (*ext)(dp).has_value();
        }
        case FilterNodeKind::Contains: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) return false;
            std::optional<FilterValue> v = (*ext)(dp);
            if (!v) return false;
            return v->string_value.find(node.literal.string_value) != std::string::npos;
        }
        case FilterNodeKind::Matches: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) return false;
            std::optional<FilterValue> v = (*ext)(dp);
            if (!v) return false;
            // F2 fix: node.compiled_regex was compiled exactly once, in type_check(), at
            // compile_display_filter() time -- never reconstructed here, in the packet loop.
            // Unconditionally set for any Matches node reachable here: type_check() throws (so
            // compile_display_filter() returns std::nullopt, and no CompiledDisplayFilter wrapping
            // this node is ever produced) if the regex failed to compile, and FilterNode has no
            // public constructor outside this translation unit for a caller to fabricate one that
            // skipped type_check() -- see CompiledDisplayFilter's own constructor comment.
            return std::regex_search(v->string_value, *node.compiled_regex);
        }
        case FilterNodeKind::InSet: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) return false;
            std::optional<FilterValue> v = (*ext)(dp);
            if (!v) return false;
            for (const auto& lit : node.literal_set) {
                if (v->kind == FilterValueKind::Int && lit.kind == FilterValueKind::Int &&
                    v->int_value == lit.int_value) return true;
                if (v->kind == FilterValueKind::Bool && v->bool_value == literal_as_bool(lit)) return true;
                if ((v->kind == FilterValueKind::String || v->kind == FilterValueKind::Ip) &&
                    lit.kind == FilterValueKind::String && v->string_value == lit.string_value) return true;
            }
            return false;
        }
        case FilterNodeKind::Compare: {
            const FieldExtractor* ext = registry.lookup(node.field_name);
            if (!ext) return false;
            std::optional<FilterValue> v = (*ext)(dp);
            if (!v) return false;
            const FilterValue& lit = node.literal;
            switch (v->kind) {
                case FilterValueKind::Int: {
                    int64_t a = v->int_value, b = lit.int_value;
                    switch (node.cmp_op) {
                        case CompareOp::Eq: return a == b;
                        case CompareOp::Ne: return a != b;
                        case CompareOp::Lt: return a < b;
                        case CompareOp::Le: return a <= b;
                        case CompareOp::Gt: return a > b;
                        case CompareOp::Ge: return a >= b;
                    }
                    return false;
                }
                case FilterValueKind::Bool: {
                    bool lit_bool = literal_as_bool(lit);
                    return node.cmp_op == CompareOp::Ne ? (v->bool_value != lit_bool)
                                                          : (v->bool_value == lit_bool);
                }
                case FilterValueKind::String:
                case FilterValueKind::Ip:
                    return node.cmp_op == CompareOp::Ne ? (v->string_value != lit.string_value)
                                                          : (v->string_value == lit.string_value);
            }
            return false;
        }
    }
    return false;
}

}  // namespace

// ---------------------------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------------------------

FilterValue FilterValue::make_int(int64_t v) {
    FilterValue r;
    r.kind = FilterValueKind::Int;
    r.int_value = v;
    return r;
}
FilterValue FilterValue::make_bool(bool v) {
    FilterValue r;
    r.kind = FilterValueKind::Bool;
    r.bool_value = v;
    return r;
}
FilterValue FilterValue::make_string(std::string v) {
    FilterValue r;
    r.kind = FilterValueKind::String;
    r.string_value = std::move(v);
    return r;
}
FilterValue FilterValue::make_ip(std::string v) {
    FilterValue r;
    r.kind = FilterValueKind::Ip;
    r.string_value = std::move(v);
    return r;
}

CompiledDisplayFilter::CompiledDisplayFilter(std::shared_ptr<const FilterNode> root, std::string source_text)
    : root_(std::move(root)), source_text_(std::move(source_text)) {}

bool CompiledDisplayFilter::matches(const DecodedPacket& dp) const {
    if (!root_) return true;  // an empty/default-constructed filter matches everything
    return evaluate(*root_, dp, FieldRegistry::instance());
}

std::optional<CompiledDisplayFilter> compile_display_filter(const std::string& expr, std::string* error) {
    // F3: the one complexity ceiling checked here rather than inside Parser -- see kMaxExpressionLength's
    // own comment above (this file's complexity-limits block). It has to be checked before anything else
    // touches `expr`, for two reasons: (1) it bounds the cost of every later step (lexing, parsing,
    // type-checking) in proportion to input size, the same "fail before doing any real work" posture
    // Parser::make_node()/enter_nesting() give the other four limits; (2) unlike every other rejection in
    // this function, the error message below deliberately does NOT echo `expr` back in full the way the
    // catch block's standard wrapper does -- an operator who passed a 200KB `-Y` string by mistake (a
    // shell glob expansion gone wrong, a pasted file instead of an expression) doesn't need that string
    // reproduced in its entirety in the error output; the first 80 characters are enough to recognize
    // what was passed and confirm the length, without ballooning the CLI's own stderr/log output to match
    // the oversized input that triggered the rejection in the first place.
    if (expr.size() > kMaxExpressionLength) {
        if (error) {
            *error = "error: display filter is " + std::to_string(expr.size()) + " bytes long, "
                "more than the " + std::to_string(kMaxExpressionLength) + "-byte limit -- simplify "
                "the expression (it starts with: '" + expr.substr(0, 80) + "...')\n";
        }
        return std::nullopt;
    }
    try {
        const FieldRegistry& registry = FieldRegistry::instance();
        Parser parser(expr);
        std::shared_ptr<FilterNode> root = parser.parse_expression();
        type_check(*root, registry, expr);
        return CompiledDisplayFilter(root, expr);
    } catch (const std::exception& e) {
        if (error) {
            *error = "error: display filter '" + expr + "' " + e.what() + "\n";
        }
        return std::nullopt;
    }
}

}  // namespace conduitscope
