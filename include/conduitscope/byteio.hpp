// SPDX-License-Identifier: Apache-2.0
// byteio.hpp - bounds-checked, endianness-explicit byte reading helpers.
//
// Network/capture data is untrusted and variable-length, so every read here
// is bounds-checked and throws ParseError on truncation rather than relying
// on struct-overlay + reinterpret_cast (which is both undefined behavior on
// unaligned/mismatched-endianness data and not portable between MSVC and
// GCC/Clang). This keeps the whole parsing stack portable across Windows and
// Linux with zero platform-specific code.
#pragma once

#include <cstdint>
#include <cstddef>
#include <stdexcept>
#include <string>
#include <vector>

namespace conduitscope {

// Thrown whenever a parser cannot make sense of the bytes it was given,
// most commonly because the buffer is shorter than the structure being
// decoded requires. Callers decide whether that is fatal (--strict) or a
// per-packet warning to skip past.
class ParseError : public std::runtime_error {
public:
    explicit ParseError(const std::string& what) : std::runtime_error(what) {}
};

// A non-owning, bounds-checked view over a byte buffer. Every subspan/byte
// access is range-checked; out-of-range access throws ParseError instead of
// reading past the end of the buffer.
class ByteSpan {
public:
    ByteSpan() : data_(nullptr), size_(0) {}
    ByteSpan(const uint8_t* data, size_t size) : data_(data), size_(size) {}

    const uint8_t* data() const { return data_; }
    size_t size() const { return size_; }
    bool empty() const { return size_ == 0; }

    uint8_t at(size_t index) const {
        if (index >= size_) {
            throw ParseError("byte offset " + std::to_string(index) +
                              " is out of range (buffer size " + std::to_string(size_) + ")");
        }
        return data_[index];
    }

    // Returns a sub-view [offset, offset+len). Throws if that range does not
    // fit inside this span.
    ByteSpan subspan(size_t offset, size_t len) const {
        if (offset > size_ || len > size_ - offset) {
            throw ParseError("requested " + std::to_string(len) + " bytes at offset " +
                              std::to_string(offset) + " but only " + std::to_string(size_) +
                              " bytes are available");
        }
        return ByteSpan(data_ + offset, len);
    }

    // Everything from offset to the end of the span.
    ByteSpan from(size_t offset) const {
        if (offset > size_) {
            throw ParseError("requested offset " + std::to_string(offset) +
                              " is past the end of a " + std::to_string(size_) + "-byte buffer");
        }
        return ByteSpan(data_ + offset, size_ - offset);
    }

    std::vector<uint8_t> to_vector() const { return std::vector<uint8_t>(data_, data_ + size_); }

private:
    const uint8_t* data_;
    size_t size_;
};

// A stateful cursor over a ByteSpan: every read advances the position and
// range-checks against the underlying span. This is the workhorse used by
// every protocol parser (Ethernet, IPv4, TCP, Modbus, DNP3).
class Cursor {
public:
    explicit Cursor(ByteSpan span) : span_(span), pos_(0) {}

    size_t position() const { return pos_; }
    size_t remaining() const { return span_.size() - pos_; }
    bool at_end() const { return pos_ >= span_.size(); }

    uint8_t u8() {
        uint8_t v = span_.at(pos_);
        pos_ += 1;
        return v;
    }

    uint16_t u16be() {
        uint16_t hi = u8();
        uint16_t lo = u8();
        return static_cast<uint16_t>((hi << 8) | lo);
    }

    uint16_t u16le() {
        uint16_t lo = u8();
        uint16_t hi = u8();
        return static_cast<uint16_t>((hi << 8) | lo);
    }

    uint32_t u32be() {
        uint32_t a = u8(), b = u8(), c = u8(), d = u8();
        return (a << 24) | (b << 16) | (c << 8) | d;
    }

    uint32_t u32le() {
        uint32_t a = u8(), b = u8(), c = u8(), d = u8();
        return (d << 24) | (c << 16) | (b << 8) | a;
    }

    uint64_t u64le() {
        uint64_t lo = u32le();
        uint64_t hi = u32le();
        return (hi << 32) | lo;
    }

    ByteSpan bytes(size_t n) {
        ByteSpan s = span_.subspan(pos_, n);
        pos_ += n;
        return s;
    }

    void skip(size_t n) {
        if (n > remaining()) {
            throw ParseError("attempted to skip " + std::to_string(n) + " bytes with only " +
                              std::to_string(remaining()) + " remaining");
        }
        pos_ += n;
    }

    // Everything from the current position to the end of the span, without
    // advancing further (useful for "rest is the payload" reads).
    ByteSpan rest() const { return span_.from(pos_); }

private:
    ByteSpan span_;
    size_t pos_;
};

// Small helper used throughout the text/JSON writers to render a byte
// buffer as lowercase hex, e.g. for unrecognized Modbus PDUs.
std::string to_hex(ByteSpan span, const char* separator = " ");

}  // namespace conduitscope
