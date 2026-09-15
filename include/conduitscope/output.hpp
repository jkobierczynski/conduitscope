// SPDX-License-Identifier: MIT
// output.hpp - renders a stream of DecodedPacket values as text, JSON, or
// CSV, plus a StatsWriter that accumulates a summary instead of per-packet
// lines (used by `decode --stats` and the `info` command).
#pragma once

#include <map>
#include <ostream>
#include <string>

#include "conduitscope/decoder.hpp"

namespace conduitscope {

class OutputWriter {
public:
    virtual ~OutputWriter() = default;
    virtual void begin() {}
    virtual void write_packet(const DecodedPacket& packet) = 0;
    virtual void end() {}
};

class TextWriter : public OutputWriter {
public:
    explicit TextWriter(std::ostream& out, bool color) : out_(out), color_(color) {}
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
    bool color_;
};

class JsonWriter : public OutputWriter {
public:
    explicit JsonWriter(std::ostream& out) : out_(out) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;
    void end() override;

private:
    std::ostream& out_;
    bool wrote_any_ = false;
};

class CsvWriter : public OutputWriter {
public:
    explicit CsvWriter(std::ostream& out) : out_(out) {}
    void begin() override;
    void write_packet(const DecodedPacket& packet) override;

private:
    std::ostream& out_;
};

// Accumulates counts instead of printing per packet; call begin()/write_packet()
// as usual, then print_summary(out) once at the end (that's separate from
// OutputWriter::end() so `info` and `decode --stats` can share this class
// while formatting their headers differently).
class StatsWriter : public OutputWriter {
public:
    void write_packet(const DecodedPacket& packet) override;
    void print_summary(std::ostream& out) const;

    size_t total_packets() const { return total_packets_; }

private:
    size_t total_packets_ = 0;
    std::map<std::string, size_t> protocol_counts_;
    std::map<std::string, size_t> modbus_function_counts_;
    size_t modbus_exceptions_ = 0;
    // Count of responses authoritatively paired (by MBAP transaction ID + TCP session, not the
    // payload-shape heuristic) to a specific earlier request -- see Decoder::pair_modbus_transaction.
    size_t modbus_paired_responses_ = 0;
    std::map<std::string, size_t> s7comm_function_counts_;
    std::map<std::string, size_t> dnp3_function_counts_;
    std::map<std::string, size_t> iec104_asdu_type_counts_;
    std::map<std::string, size_t> enip_command_counts_;
    std::map<std::string, size_t> enip_cip_service_counts_;
    bool has_ts_ = false;
    double first_ts_ = 0.0, last_ts_ = 0.0;
};

std::string json_escape(const std::string& s);
std::string csv_escape(const std::string& s);

}  // namespace conduitscope
