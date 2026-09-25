// SPDX-License-Identifier: Apache-2.0
// fox.cpp - see fox.hpp for the full sourcing/confidence/scope/security writeup.
#include "conduitscope/fox.hpp"

#include <cctype>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// --- terminator byte-scan, shared by fox_tcp_declared_length and try_parse_fox_pdu -------------
// Scans `span` for the literal 5-byte sequence 0x0A 0x7D 0x3B 0x3B 0x0A ("\n};;\n" -- see fox.hpp's
// own FRAMING section for why the leading \n is always present). Returns the byte offset of the
// FIRST match's own first byte (the \n), or std::nullopt if no match is found anywhere in `span`.
std::optional<size_t> find_fox_terminator(ByteSpan span) {
    static constexpr uint8_t kTerm[5] = {0x0A, 0x7D, 0x3B, 0x3B, 0x0A};
    if (span.size() < 5) return std::nullopt;
    for (size_t i = 0; i + 5 <= span.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < 5; ++j) {
            if (span.at(i + j) != kTerm[j]) {
                match = false;
                break;
            }
        }
        if (match) return i;
    }
    return std::nullopt;
}

bool starts_with_fox_magic(ByteSpan span) {
    static constexpr uint8_t kMagic[4] = {'f', 'o', 'x', ' '};
    if (span.size() < 4) return false;
    for (size_t i = 0; i < 4; ++i) {
        if (span.at(i) != kMagic[i]) return false;
    }
    return true;
}

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << static_cast<unsigned>(v);
    return s.str();
}

// --- a small, textual, arbitrary-lookahead reader over one frame's own bytes -------------------
// Fox's line-oriented, delimiter-scanned grammar (read-until-'=', read-until-space, read-until-\n,
// a raw byte count with no separator before the bytes it counts) doesn't fit byteio.hpp's Cursor
// (which offers only fixed-width/fixed-count reads, no scan-for-delimiter or peek), so this
// decoder -- like several others in this codebase with their own bespoke grammars (e.g. LDAP's own
// BER walker) -- writes a small local helper instead. Every read throws ParseError on running past
// `span_`'s own end, exactly like Cursor, so the same try/catch-at-the-top-level convention this
// codebase already uses everywhere else applies here too.
class FoxReader {
public:
    explicit FoxReader(ByteSpan span) : span_(span), pos_(0) {}

    bool at_end() const { return pos_ >= span_.size(); }
    size_t remaining() const { return span_.size() - pos_; }

    uint8_t peek() const {
        if (pos_ >= span_.size()) {
            throw ParseError("Fox frame: attempted to peek past end of buffer");
        }
        return span_.at(pos_);
    }

    uint8_t next() {
        uint8_t v = peek();
        ++pos_;
        return v;
    }

    // True (and consumes `lit`) only if the next literal_len bytes match `lit` exactly; otherwise
    // leaves the position unchanged and returns false.
    bool try_consume_literal(const char* lit, size_t literal_len) {
        if (remaining() < literal_len) return false;
        for (size_t i = 0; i < literal_len; ++i) {
            if (span_.at(pos_ + i) != static_cast<uint8_t>(lit[i])) return false;
        }
        pos_ += literal_len;
        return true;
    }

    // Reads bytes up to (not including) the next occurrence of `delim`, then consumes `delim`
    // itself. Throws ParseError if `delim` is never found before the end of `span_`.
    std::string read_until(char delim) {
        size_t start = pos_;
        while (pos_ < span_.size() && span_.at(pos_) != static_cast<uint8_t>(delim)) ++pos_;
        if (pos_ >= span_.size()) {
            throw ParseError(std::string("Fox frame: delimiter '") + delim + "' not found");
        }
        std::string s(reinterpret_cast<const char*>(span_.data()) + start, pos_ - start);
        ++pos_;  // consume the delimiter itself
        return s;
    }

    // Reads a run of bytes for which `pred` is true (never crossing the end of `span_` -- a
    // caller-supplied predicate, so this never throws on its own; the caller decides whether an
    // empty result or an unexpected following byte is itself an error).
    template <typename Pred>
    std::string read_while(Pred pred) {
        size_t start = pos_;
        while (pos_ < span_.size() && pred(span_.at(pos_))) ++pos_;
        return std::string(reinterpret_cast<const char*>(span_.data()) + start, pos_ - start);
    }

    ByteSpan read_n(size_t n) {
        ByteSpan s = span_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

private:
    ByteSpan span_;
    size_t pos_;
};

bool is_ascii_digit(uint8_t c) { return c >= '0' && c <= '9'; }
bool is_hex_digit(uint8_t c) {
    return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

// Renders a 't' (time) tuple's raw hex-digit string into a best-effort human-readable value -- see
// fox.hpp's own TUPLE VALUE GRAMMAR section: this decoder was NOT able to source a confirmed
// definition of what epoch/semantic a Fox 't' value actually represents (elapsed-since-boot
// duration? Unix-epoch-ish timestamp? something Niagara-internal?) from either reference source.
// The heuristic below (render as a duration when the resulting second count is small enough to
// plausibly be one, else as a raw millisecond-since-epoch value) is this decoder's OWN best-effort
// guess, explicitly flagged as unconfirmed in the rendered text itself so a reader never mistakes
// it for a sourced fact.
std::string render_fox_time_value(const std::string& hex_digits) {
    if (hex_digits.empty()) return "(empty)";
    uint64_t ms = 0;
    bool overflowed = false;
    for (char c : hex_digits) {
        uint8_t nibble;
        if (c >= '0' && c <= '9') {
            nibble = static_cast<uint8_t>(c - '0');
        } else if (c >= 'a' && c <= 'f') {
            nibble = static_cast<uint8_t>(c - 'a' + 10);
        } else {
            nibble = static_cast<uint8_t>(c - 'A' + 10);
        }
        // 16 hex digits is 64 bits exactly -- anything longer would overflow uint64_t; treated as
        // "too large to render meaningfully" rather than silently truncating/wrapping.
        if (ms > (UINT64_MAX >> 4)) {
            overflowed = true;
            break;
        }
        ms = (ms << 4) | nibble;
    }
    std::ostringstream out;
    out << "0x" << hex_digits << " (" << ms << " ms";
    if (overflowed) {
        out << ", too large to interpret further";
    } else {
        uint64_t seconds = ms / 1000;
        constexpr uint64_t kOneYearSeconds = 31557600;  // ~365.25 days
        if (seconds < kOneYearSeconds) {
            out << " -- best-effort, UNCONFIRMED: rendered as a duration since seconds < ~1yr: "
                << seconds << "s";
        } else {
            out << " -- best-effort, UNCONFIRMED: rendered as a Unix-epoch-ish timestamp: "
                << seconds << "s since epoch";
        }
    }
    out << ")";
    return out.str();
}

size_t fox_max_nesting_depth() { return resource_limits().max_recursion_depth.value_or(16); }

// Parses tuple lines from `r` until either the outer terminator "};;\n" (depth == 0) or a nested
// message's own plain closer "}\n" (depth > 0, i.e. we're inside an 'm' value) is reached. Returns
// true and consumes the closer on success; returns false (and sets `stop_reason`, WITHOUT
// consuming anything further) the moment an unrecognized type tag or the nesting-depth cap is
// encountered -- see fox.hpp's own TUPLE VALUE GRAMMAR section for why extraction honestly stops
// rather than guessing past either condition. Throws ParseError (caught by the top-level caller)
// on any other structural malformation (a missing '=' or ':' delimiter, a value that runs past the
// end of `r`, ...).
bool parse_fox_tuples(FoxReader& r, std::vector<FoxTuple>& out_tuples, size_t depth,
                       std::optional<std::string>& stop_reason) {
    while (true) {
        if (r.peek() == '}') {
            if (depth == 0) {
                if (!r.try_consume_literal("};;\n", 4)) {
                    throw ParseError("Fox frame: malformed outer terminator");
                }
            } else {
                if (!r.try_consume_literal("}\n", 2)) {
                    throw ParseError("Fox frame: malformed nested message closer");
                }
            }
            return true;
        }

        FoxTuple tuple;
        tuple.key = r.read_until('=');
        tuple.type_raw = static_cast<char>(r.next());
        if (r.next() != ':') throw ParseError("Fox frame: expected ':' after tuple type tag");

        switch (tuple.type_raw) {
            case 's': {
                tuple.type_name = "string";
                tuple.rendered = r.read_until('\n');
                break;
            }
            case 'i': {
                tuple.type_name = "int";
                tuple.rendered = r.read_while([](uint8_t c) { return c == '-' || is_ascii_digit(c); });
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 'i' tuple value");
                break;
            }
            case 'f': {
                tuple.type_name = "float";
                tuple.rendered =
                    r.read_while([](uint8_t c) { return c == '-' || c == '.' || is_ascii_digit(c); });
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 'f' tuple value");
                break;
            }
            case 't': {
                tuple.type_name = "time";
                std::string hex_digits = r.read_while([](uint8_t c) { return is_hex_digit(c); });
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 't' tuple value");
                tuple.rendered = render_fox_time_value(hex_digits);
                break;
            }
            case 'z': {
                tuple.type_name = "bool";
                uint8_t c = r.next();
                if (c != 't' && c != 'f') throw ParseError("Fox frame: malformed 'z' tuple value");
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 'z' tuple value");
                tuple.rendered = (c == 't') ? "true" : "false";
                break;
            }
            case 'b': {
                tuple.type_name = "blob";
                // See fox.hpp's own KNOWN, UNCONFIRMED ASSUMPTION note: no delimiter between the
                // decimal size and the raw bytes that follow it.
                std::string size_digits = r.read_while([](uint8_t c) { return is_ascii_digit(c); });
                if (size_digits.empty()) throw ParseError("Fox frame: malformed 'b' tuple size");
                size_t size;
                try {
                    size = static_cast<size_t>(std::stoull(size_digits));
                } catch (const std::exception&) {
                    // A digit run std::stoull can't represent (e.g. more digits than fit in an
                    // unsigned long long) throws std::out_of_range, not a ParseError -- caught and
                    // re-thrown as one here, mirroring parse_one_fox_frame's own seq/reply guard
                    // just below, so this frame is reported as malformed exactly like any other
                    // structurally invalid Fox frame rather than crashing the process outright.
                    throw ParseError("Fox frame: malformed 'b' tuple size (unrepresentable number)");
                }
                r.read_n(size);  // raw bytes -- never rendered, only their count (see fox.hpp).
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 'b' tuple trailer");
                tuple.rendered = std::to_string(size) + " byte(s) (blob)";
                break;
            }
            case 'o': {
                tuple.type_name = "object";
                std::string type_token = r.read_until(' ');
                std::string size_digits = r.read_while([](uint8_t c) { return is_ascii_digit(c); });
                if (size_digits.empty()) throw ParseError("Fox frame: malformed 'o' tuple size");
                size_t size;
                try {
                    size = static_cast<size_t>(std::stoull(size_digits));
                } catch (const std::exception&) {
                    // Same unrepresentable-digit-run guard as the 'b' (blob) case just above --
                    // see its own comment for why this is caught and re-thrown as a ParseError.
                    throw ParseError("Fox frame: malformed 'o' tuple size (unrepresentable number)");
                }
                r.read_n(size);  // raw bytes -- never rendered, only their count (see fox.hpp).
                if (r.next() != '\n') throw ParseError("Fox frame: malformed 'o' tuple trailer");
                tuple.rendered = "type=\"" + type_token + "\", " + std::to_string(size) + " byte(s) (object)";
                break;
            }
            case 'm': {
                tuple.type_name = "message";
                if (!r.try_consume_literal("{\n", 2)) {
                    throw ParseError("Fox frame: malformed 'm' tuple opener");
                }
                if (depth + 1 >= fox_max_nesting_depth()) {
                    stop_reason = "Fox nested message ('m') recursion depth cap reached (" +
                                  std::to_string(fox_max_nesting_depth()) +
                                  ") -- tuple extraction stopped for the rest of this frame "
                                  "(--max-recursion-depth)";
                    out_tuples.push_back(std::move(tuple));
                    return false;
                }
                if (!parse_fox_tuples(r, tuple.nested, depth + 1, stop_reason)) {
                    out_tuples.push_back(std::move(tuple));
                    return false;
                }
                break;
            }
            default: {
                tuple.type_name = "Unknown (" + hex_u8(static_cast<uint8_t>(tuple.type_raw)) + " char)";
                stop_reason = "Fox frame: unrecognized tuple type tag " + tuple.type_name +
                              " for key \"" + tuple.key +
                              "\" -- its value's own framing is unknown, so tuple extraction "
                              "stopped for the rest of this frame (structure beyond this point not "
                              "decoded)";
                out_tuples.push_back(std::move(tuple));
                return false;
            }
        }

        out_tuples.push_back(std::move(tuple));
    }
}

const FoxTuple* find_top_level_tuple(const std::vector<FoxTuple>& tuples, const char* key) {
    for (const auto& t : tuples) {
        if (t.key == key) return &t;
    }
    return nullptr;
}

void set_if_present(const std::vector<FoxTuple>& tuples, const char* key,
                     std::optional<std::string>& field) {
    if (const FoxTuple* t = find_top_level_tuple(tuples, key)) field = t->rendered;
}

FoxHelloFields extract_hello_fields(const std::vector<FoxTuple>& tuples) {
    FoxHelloFields f;
    set_if_present(tuples, "fox.version", f.fox_version);
    set_if_present(tuples, "id", f.id);
    set_if_present(tuples, "hostName", f.host_name);
    set_if_present(tuples, "hostAddress", f.host_address);
    set_if_present(tuples, "app.name", f.app_name);
    set_if_present(tuples, "app.version", f.app_version);
    set_if_present(tuples, "vm.name", f.vm_name);
    set_if_present(tuples, "vm.version", f.vm_version);
    set_if_present(tuples, "os.name", f.os_name);
    set_if_present(tuples, "os.version", f.os_version);
    set_if_present(tuples, "lang", f.lang);
    set_if_present(tuples, "timeZone", f.time_zone);
    set_if_present(tuples, "hostId", f.host_id);
    set_if_present(tuples, "vmUuid", f.vm_uuid);
    set_if_present(tuples, "brandId", f.brand_id);
    return f;
}

std::string describe_hello(const FoxFrame& frame) {
    const FoxHelloFields& h = *frame.hello;
    std::ostringstream s;
    s << "Fox hello " << (frame.reply == -1 ? "request" : "reply") << ":";
    bool any = false;
    auto add = [&](const char* label, const std::optional<std::string>& v) {
        if (!v) return;
        s << (any ? ", " : " ") << label << "=\"" << *v << "\"";
        any = true;
    };
    add("hostName", h.host_name);
    add("hostAddress", h.host_address);
    add("id", h.id);
    add("app.name", h.app_name);
    add("app.version", h.app_version);
    add("os.name", h.os_name);
    if (!any) s << " (no curated fields present)";
    return s.str();
}

// Builds a whole FoxFrame from the header line + tuple body found within `pdu` -- `pdu` is scoped
// to EXACTLY this one frame's own bytes (offset 0 through wire_length, inclusive of the "};;\n"
// terminator), never more, so a read that runs past its own end (a malformed/truncated frame)
// throws ParseError exactly at that frame's own boundary rather than reading into a next coalesced
// frame's bytes.
FoxFrame parse_one_fox_frame(ByteSpan pdu, size_t wire_length) {
    FoxFrame frame;
    frame.wire_length = wire_length;

    FoxReader r(pdu);
    if (!r.try_consume_literal("fox ", 4)) throw ParseError("Fox frame: missing 'fox ' magic");
    frame.frame_type_raw = static_cast<char>(r.next());
    frame.frame_type_name = fox_frame_type_name(frame.frame_type_raw);
    if (r.next() != ' ') throw ParseError("Fox frame: malformed header (frame type)");
    std::string seq_str = r.read_until(' ');
    std::string reply_str = r.read_until(' ');
    frame.channel = r.read_until(' ');
    frame.command = r.read_until('\n');
    try {
        frame.seq = std::stoll(seq_str);
        frame.reply = std::stoll(reply_str);
    } catch (const std::exception&) {
        throw ParseError("Fox frame: malformed seq/reply number");
    }
    frame.is_reply = (frame.reply != -1);

    if (!r.try_consume_literal("{\n", 2)) throw ParseError("Fox frame: missing tuple block opener");

    std::optional<std::string> stop_reason;
    parse_fox_tuples(r, frame.tuples, 0, stop_reason);
    frame.stopped_reason = stop_reason;

    frame.is_hello = (frame.channel == "fox" && frame.command == "hello");
    if (frame.is_hello) frame.hello = extract_hello_fields(frame.tuples);

    std::ostringstream s;
    if (frame.is_hello) {
        s << describe_hello(frame);
    } else {
        s << "Fox " << frame.frame_type_name << " frame, " << frame.channel << "/" << frame.command
          << " (seq=" << frame.seq << ", reply=" << frame.reply << "): " << frame.tuples.size()
          << " tuple(s)";
    }
    frame.summary = s.str();

    if (frame.is_hello) {
        frame.notes.push_back(
            "unauthenticated Fox hello exchange -- a real Niagara station answers ANY "
            "syntactically valid hello frame from ANY unauthenticated TCP peer with a full dump "
            "of its own system identity (fox.version/hostName/hostAddress/app/vm/os/etc.); no "
            "session or credential check precedes this (CISA ICSA-12-228-01A / FBI PIN, actively "
            "exploited by fox-info.nse)");
    }
    if (frame.stopped_reason) frame.notes.push_back(*frame.stopped_reason);

    return frame;
}

}  // namespace

std::string fox_frame_type_name(char frame_type_raw) {
    switch (frame_type_raw) {
        case 'a': return "Asynchronous";
        case 's': return "Synchronous";
        case 'k': return "Keep-alive";
        case 'r': return "Reply";
        case 'e': return "Error";
        case 'n': return "F_NULL";
        default: return "Unknown (" + hex_u8(static_cast<uint8_t>(frame_type_raw)) + " char)";
    }
}

std::optional<FoxFrame> try_parse_fox_pdu(ByteSpan candidate) {
    if (!starts_with_fox_magic(candidate)) return std::nullopt;
    auto term = find_fox_terminator(candidate);
    if (!term) return std::nullopt;  // no complete frame within `candidate` yet.
    size_t wire_length = *term + 5;
    try {
        ByteSpan pdu = candidate.subspan(0, wire_length);
        return parse_one_fox_frame(pdu, wire_length);
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> fox_tcp_declared_length(ByteSpan candidate) {
    if (!starts_with_fox_magic(candidate)) return std::nullopt;
    auto term = find_fox_terminator(candidate);
    if (!term) {
        // Terminator not found yet -- standard "ask for one more byte, keep buffering" idiom (see
        // amqp091_tcp_declared_length/dicom_tcp_declared_length for the same shape); a literal
        // std::nullopt here would instead tell Decoder::reassemble_tcp_payload "this candidate
        // isn't Fox at all," which would be wrong once the "fox " magic has already matched -- see
        // fox.hpp's own tcp_declared_length doc comment.
        return candidate.size() + 1;
    }
    return *term + 5;
}

std::optional<ProtocolResult> FoxDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto first = try_parse_fox_pdu(payload);
    if (!first) return std::nullopt;

    FoxResult result;
    result.first = *first;
    result.summary = result.first.summary;
    for (const auto& n : result.first.notes) result.notes.push_back(n);

    // Coalescing loop -- multiple frames (keep-alives in particular) very plausibly arrive
    // back-to-back in one TCP payload, the same MqttResult/DicomResult/Amqp091Result shape
    // mqtt.hpp/dicom.hpp/amqp091.hpp already establish.
    const size_t kMax = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = first->wire_length;
    size_t count = 1;
    while (offset < payload.size() && count < kMax) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_fox_pdu(rest);
        if (!next) break;
        ++count;
        result.notes.push_back("additional Fox frame " + std::to_string(count) +
                                " found in the same TCP payload at byte offset " +
                                std::to_string(offset) + " (coalesced by the sender/OS): " +
                                next->summary);
        for (const auto& n : next->notes) result.notes.push_back(n);
        offset += next->wire_length;
    }
    if (count >= kMax) {
        result.notes.push_back("stopped after " + std::to_string(kMax) +
                                " Fox frame(s) in this one TCP payload, more may remain (safety cap)");
    }

    return ProtocolResult::make<FoxResult>("fox", std::move(result));
}

const ProtocolDecoder& fox_tcp_decoder() {
    static const FoxDecoder instance;
    return instance;
}

}  // namespace conduitscope
