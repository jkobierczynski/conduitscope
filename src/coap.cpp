// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/coap.hpp"

#include <algorithm>
#include <iomanip>
#include <sstream>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

// Caps the number of options this decoder will walk per message -- resource-exhaustion
// protection against a pathological/malicious capture with an enormous option chain, the same
// CLI-configurable-via---max-decoded-objects pattern codesys.cpp's own max_codesys_top_level_tags
// already established. 64 is generous headroom over anything a real CoAP message needs (a deep
// Uri-Path/Uri-Query with a dozen segments, plus a handful of other options, is still well under
// this).
size_t max_coap_options() { return resource_limits().max_decoded_objects.value_or(64); }

std::string hex(ByteSpan span) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (size_t i = 0; i < span.size(); ++i) {
        oss << std::setw(2) << static_cast<int>(span.at(i));
    }
    return oss.str();
}

// RFC 7252 Section 3.1's option-number extension scheme, shared identically by both the Option
// Delta and Option Length nibbles: 0-12 is the value itself, 13 reads one more byte and adds 13,
// 14 reads two more bytes (network byte order) and adds 269. Nibble value 15 is the caller's own
// responsibility (Payload Marker / message format error, see coap.hpp's WIRE FORMAT comment) --
// this helper is never called with 15.
uint32_t read_coap_extended_nibble(Cursor& cur, uint8_t nibble) {
    if (nibble <= 12) return nibble;
    if (nibble == 13) return static_cast<uint32_t>(cur.u8()) + 13;
    // nibble == 14
    return static_cast<uint32_t>(cur.u16be()) + 269;
}

struct CodeEntry {
    uint8_t code_raw;
    const char* name;
};

// RFC 7252 Section 12.1.1 (Method Codes) + RFC 8132 (FETCH/PATCH/iPATCH).
constexpr CodeEntry kMethodCodes[] = {
    {0x01, "GET"}, {0x02, "POST"}, {0x03, "PUT"}, {0x04, "DELETE"},
    {0x05, "FETCH"}, {0x06, "PATCH"}, {0x07, "iPATCH"},
};

// RFC 7252 Section 12.1.2 (Response Codes) + RFC 7959 (2.31 Continue, 4.08/4.13 blockwise) +
// RFC 8132 (4.09 Conflict, 4.22 Unprocessable Entity) + RFC 8516 (4.29 Too Many Requests) +
// RFC 8768 (5.08 Hop Limit Reached).
constexpr CodeEntry kResponseCodes[] = {
    {0x41, "Created"}, {0x42, "Deleted"}, {0x43, "Valid"}, {0x44, "Changed"}, {0x45, "Content"},
    {0x5F, "Continue"},
    {0x80, "Bad Request"}, {0x81, "Unauthorized"}, {0x82, "Bad Option"}, {0x83, "Forbidden"},
    {0x84, "Not Found"}, {0x85, "Method Not Allowed"}, {0x86, "Not Acceptable"},
    {0x88, "Request Entity Incomplete"}, {0x89, "Conflict"}, {0x8C, "Precondition Failed"},
    {0x8D, "Request Entity Too Large"}, {0x8F, "Unsupported Content-Format"},
    {0x96, "Unprocessable Entity"}, {0x9D, "Too Many Requests"},
    {0xA0, "Internal Server Error"}, {0xA1, "Not Implemented"}, {0xA2, "Bad Gateway"},
    {0xA3, "Service Unavailable"}, {0xA4, "Gateway Timeout"}, {0xA5, "Proxying Not Supported"},
    {0xA8, "Hop Limit Reached"},
};
// Response Code bytes above are pre-computed as (class << 5) | detail, e.g. 2.05 Content ==
// (2 << 5) | 5 == 0x45, 4.04 Not Found == (4 << 5) | 4 == 0x84, 5.03 Service Unavailable ==
// (5 << 5) | 3 == 0xA3 -- cross-checked against RFC 7252 Section 12.1.2's own "c.dd" table one
// entry at a time.

struct OptionEntry {
    uint16_t number;
    const char* name;
    char format;  // 's' string, 'u' uint, 'o' opaque, 'e' empty
};

// RFC 7252 Section 12.2 (base options) + RFC 7641 (6, Observe) + RFC 7959 (23/27/28, Block2/
// Block1/Size2) -- see coap.hpp's own SCOPE paragraph for why exactly these three RFCs.
constexpr OptionEntry kOptions[] = {
    {1, "If-Match", 'o'},
    {3, "Uri-Host", 's'},
    {4, "ETag", 'o'},
    {5, "If-None-Match", 'e'},
    {6, "Observe", 'u'},
    {7, "Uri-Port", 'u'},
    {8, "Location-Path", 's'},
    {11, "Uri-Path", 's'},
    {12, "Content-Format", 'u'},
    {14, "Max-Age", 'u'},
    {15, "Uri-Query", 's'},
    {17, "Accept", 'u'},
    {20, "Location-Query", 's'},
    {23, "Block2", 'u'},
    {27, "Block1", 'u'},
    {28, "Size2", 'u'},
    {35, "Proxy-Uri", 's'},
    {39, "Proxy-Scheme", 's'},
    {60, "Size1", 'u'},
};

struct ContentFormatEntry {
    uint16_t id;
    const char* name;
};

// IANA CoAP Content-Formats registry, the entries most likely to actually appear in real traffic
// (RFC 7252 Section 12.3's own initial registrations, plus RFC 6690/RFC 8949/RFC 8259's own
// later registrations for link-format/CBOR/JSON, which are ubiquitous in real CoRE/CoAP use).
// Any Content-Format ID not in this table is shown as a raw number only -- see coap.hpp's own
// SCOPE paragraph; this is not the full registry, which is open-ended and vendor-extensible.
constexpr ContentFormatEntry kContentFormats[] = {
    {0, "text/plain"},
    {40, "application/link-format"},
    {41, "application/xml"},
    {42, "application/octet-stream"},
    {47, "application/exi"},
    {50, "application/json"},
    {60, "application/cbor"},
    {110, "application/senml+json"},
    {112, "application/senml+cbor"},
};

}  // namespace

const char* coap_type_name(uint8_t type_raw) {
    switch (type_raw & 0x3) {
        case 0: return "CON";
        case 1: return "NON";
        case 2: return "ACK";
        case 3: return "RST";
    }
    return nullptr;  // unreachable -- (type_raw & 0x3) is always 0-3.
}

const char* coap_code_class_name(uint8_t code_class) {
    switch (code_class) {
        case 0: return "Method";
        case 2: return "Success";
        case 4: return "Client Error";
        case 5: return "Server Error";
        case 7: return "Signaling";  // RFC 8323, CoAP-over-TCP only -- see coap.hpp's SCOPE.
        default: return nullptr;     // classes 1, 3, 6 are reserved, never used.
    }
}

const char* coap_code_name(uint8_t code_raw) {
    if (code_raw == 0x00) return "Empty";
    for (const auto& e : kMethodCodes) {
        if (e.code_raw == code_raw) return e.name;
    }
    for (const auto& e : kResponseCodes) {
        if (e.code_raw == code_raw) return e.name;
    }
    return nullptr;
}

const char* coap_option_name(uint16_t option_number) {
    for (const auto& e : kOptions) {
        if (e.number == option_number) return e.name;
    }
    return nullptr;
}

const char* coap_content_format_name(uint16_t content_format_id) {
    for (const auto& e : kContentFormats) {
        if (e.id == content_format_id) return e.name;
    }
    return nullptr;
}

namespace {

char coap_option_format(uint16_t option_number) {
    for (const auto& e : kOptions) {
        if (e.number == option_number) return e.format;
    }
    return 'o';  // unrecognized options are always shown as opaque/raw -- see coap.hpp's SCOPE.
}

std::string coap_code_text(uint8_t code_raw) {
    std::ostringstream oss;
    oss << static_cast<int>(code_raw >> 5) << "." << std::setfill('0') << std::setw(2)
        << static_cast<int>(code_raw & 0x1F);
    return oss.str();
}

}  // namespace

std::optional<CoapFrame> try_parse_coap(ByteSpan udp_payload) {
    if (udp_payload.size() < 4) return std::nullopt;

    try {
        Cursor cur(udp_payload);
        uint8_t b0 = cur.u8();
        uint8_t version_raw = (b0 >> 6) & 0x3;
        if (version_raw != 1) return std::nullopt;  // RFC 7252 Section 3: MUST be 1.

        CoapFrame frame;
        frame.version_raw = version_raw;
        frame.type_raw = (b0 >> 4) & 0x3;
        frame.type_name = coap_type_name(frame.type_raw);
        frame.token_length_raw = b0 & 0xF;
        if (frame.token_length_raw > 8) return std::nullopt;  // 9-15 reserved, message format
                                                                // error per the RFC -- see
                                                                // coap.hpp's DETECTION/DISPATCH.

        frame.code_raw = cur.u8();
        frame.code_class = frame.code_raw >> 5;
        frame.code_detail = frame.code_raw & 0x1F;
        frame.code_class_name = coap_code_class_name(frame.code_class);
        if (const char* name = coap_code_name(frame.code_raw)) frame.code_name = name;
        frame.is_empty_message = (frame.code_raw == 0x00);

        frame.message_id = cur.u16be();

        if (frame.token_length_raw > 0) {
            if (cur.remaining() < frame.token_length_raw) return std::nullopt;  // truncated token.
            frame.token_hex = hex(cur.bytes(frame.token_length_raw));
        }

        uint32_t running_option_number = 0;
        while (!cur.at_end()) {
            if (frame.options.size() >= max_coap_options()) {
                frame.notes.push_back("option count reached this decoder's own cap (" +
                                       std::to_string(max_coap_options()) +
                                       ") -- remaining bytes not walked as options");
                break;
            }

            uint8_t marker_peek = udp_payload.at(cur.position());
            if (marker_peek == 0xFF) {
                cur.u8();  // consume the Payload Marker byte itself.
                if (cur.at_end()) {
                    frame.notes.push_back(
                        "Payload Marker (0xFF) present with no payload following -- a message "
                        "format error per RFC 7252 Section 3.1, not an empty payload");
                    break;
                }
                frame.payload_present = true;
                frame.payload_length = cur.remaining();
                break;
            }

            uint8_t option_byte = cur.u8();
            uint8_t delta_nibble = (option_byte >> 4) & 0xF;
            uint8_t length_nibble = option_byte & 0xF;
            if (delta_nibble == 15 || length_nibble == 15) {
                // Only a full 0xFF byte (both nibbles 15) is the legitimate Payload Marker,
                // handled above via marker_peek before this byte was even consumed as an option
                // header -- reaching here with only one nibble at 15 is a genuine message format
                // error (RFC 7252 Section 3.1).
                frame.notes.push_back(
                    "malformed option: reserved nibble value 15 used outside the Payload Marker "
                    "at byte offset " + std::to_string(cur.position() - 1) +
                    " -- remaining bytes not walked as options");
                break;
            }

            uint32_t delta;
            uint32_t length;
            try {
                delta = read_coap_extended_nibble(cur, delta_nibble);
                length = read_coap_extended_nibble(cur, length_nibble);
            } catch (const ParseError&) {
                frame.notes.push_back(
                    "malformed option: extended delta/length byte(s) truncated -- remaining "
                    "bytes not walked as options");
                break;
            }

            if (cur.remaining() < length) {
                frame.notes.push_back(
                    "malformed option: declared length (" + std::to_string(length) +
                    " byte(s)) exceeds the bytes remaining in this message -- remaining bytes "
                    "not walked as options");
                break;
            }

            running_option_number += delta;
            CoapOption opt;
            opt.number = static_cast<uint16_t>(running_option_number);
            if (const char* name = coap_option_name(opt.number)) opt.name = name;
            ByteSpan value_span = cur.bytes(length);
            opt.value = value_span.to_vector();

            char fmt = coap_option_format(opt.number);
            if (opt.name) {
                if (fmt == 's') {
                    opt.decoded_text = opt.value.empty()
                        ? std::string()
                        : std::string(reinterpret_cast<const char*>(opt.value.data()),
                                       opt.value.size());
                } else if (fmt == 'u' && opt.value.size() <= 8) {
                    uint64_t v = 0;
                    for (uint8_t b : opt.value) v = (v << 8) | b;
                    opt.decoded_uint = v;
                }
            }

            if (opt.number == 12 /* Content-Format */ && opt.decoded_uint) {
                frame.content_format_id = static_cast<uint16_t>(*opt.decoded_uint);
                if (const char* cf = coap_content_format_name(*frame.content_format_id)) {
                    frame.content_format_name = cf;
                }
            }
            if (opt.number == 6 /* Observe */) {
                frame.observe_value = opt.decoded_uint.value_or(0);
                frame.observe_register = (*frame.observe_value == 0);
            }

            frame.options.push_back(std::move(opt));
        }

        // Uri-Path is carried as one option PER PATH SEGMENT on the wire (RFC 7252 Section
        // 5.10), joined here into a single "a/b/c" string for both the summary line and the
        // CoRE Resource Discovery note below.
        std::string joined_uri_path;
        for (const auto& opt : frame.options) {
            if (opt.number == 11 && opt.decoded_text) {
                if (!joined_uri_path.empty()) joined_uri_path += "/";
                joined_uri_path += *opt.decoded_text;
            }
        }

        std::ostringstream summary;
        summary << "CoAP " << (frame.type_name ? frame.type_name : "?") << " ";
        if (frame.code_name) {
            summary << *frame.code_name;
        } else {
            summary << coap_code_text(frame.code_raw);
        }
        summary << " Message-ID=" << frame.message_id;
        if (!frame.token_hex.empty()) summary << " Token=" << frame.token_hex;
        if (!joined_uri_path.empty()) summary << " /" << joined_uri_path;

        // CoRE Resource Discovery (RFC 6690): GET .well-known/core enumerates the resources this
        // device itself hosts -- the CoAP analogue of CC-Link IE's own "node search: passive
        // asset-discovery broadcast" note.
        if (joined_uri_path == ".well-known/core" && frame.code_name &&
            *frame.code_name == "GET") {
            frame.notes.push_back(
                "CoRE Resource Discovery (RFC 6690): GET .well-known/core enumerates this "
                "device's own hosted resources");
        }

        if (frame.observe_value) {
            summary << (frame.observe_register ? " Observe=register" : " Observe=notify");
        }
        if (frame.content_format_id) {
            summary << " Content-Format=";
            if (frame.content_format_name) {
                summary << *frame.content_format_name;
            } else {
                summary << *frame.content_format_id;
            }
        }
        if (frame.payload_present) {
            summary << " (" << frame.payload_length << " byte(s) of payload)";
        }
        frame.summary = summary.str();

        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<ProtocolResult> CoapUdpDecoder::decode(ByteSpan payload, DecodeContext& /*ctx*/) const {
    auto frame = try_parse_coap(payload);
    if (!frame) return std::nullopt;
    return ProtocolResult::make<CoapFrame>("coap", std::move(*frame));
}

const ProtocolDecoder& coap_udp_decoder() {
    static const CoapUdpDecoder instance;
    return instance;
}

}  // namespace conduitscope
