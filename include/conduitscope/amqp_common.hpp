// SPDX-License-Identifier: Apache-2.0
// amqp_common.hpp - the small amount of machinery genuinely shared between AMQP 0-9-1
// (amqp091.hpp/.cpp) and AMQP 1.0 (amqp10.hpp/.cpp): the 8-byte connection-preamble parser and the
// per-TCP-session sticky version-detection state both decoders read and write. EVERYTHING ELSE
// (frame framing, field/type systems, method/performative tables) is version-specific and lives in
// its own file pair -- the two wire formats share NOTHING past this one preamble, per Jurgen's own
// framing of the request ("two genuinely separate protocols... that happen to usually share TCP
// port 5672").
//
// WHY TWO SEPARATE PROTOCOLS, NOT ONE FILE: AMQP 0-9-1 (the JMS-era, RabbitMQ-popularized wire
// format standardized by the OASIS-adjacent AMQP Working Group's own 0-9-1 revision) and AMQP 1.0
// (the OASIS-standardized, ISO/IEC 19464 wire format most brokers -- Qpid, ActiveMQ Artemis, Azure
// Service Bus, Solace -- actually speak today) are wire-INCOMPATIBLE despite sharing a name and a
// conventional port: different frame headers, different type systems, different method/performative
// numbering, no shared PDU shape anywhere past the connection preamble below. Jurgen was asked to
// pick between them and chose both, so this codebase treats them exactly like DNS/mDNS/LLMNR or
// ASF/IPMI/RMCP -- one shared framing/detection concern (here: the preamble), two fully independent
// decoders with their own --protocol values (amqp091/amqp10), sharing one port-configuration surface
// (--amqp-port/extra_amqp_ports, the RMCP precedent: "a single shared list... since RMCP/ASF/IPMI
// always ride the exact same UDP port by wire-format construction" -- AMQP 0-9-1/1.0 are the TCP-side
// analog of that exact reasoning, negotiated in-band via the very preamble this file parses).
//
// SOURCING: this file's own preamble byte values (and everything else about both protocols) come
// from a dedicated research pass that cross-confirmed them directly against Wireshark's own
// packet-amqp.c dissector source, RabbitMQ's own server source (rabbit_reader.erl/
// rabbit_framing.hrl), the OASIS AMQP 1.0 specification, and RabbitMQ's own 0-9-1 reference
// documentation -- treated as authoritative for this whole feature; see amqp091.hpp's and
// amqp10.hpp's own file header comments for the per-protocol sourcing detail this file doesn't
// duplicate.
//
// THE CONNECTION PREAMBLE (8 bytes, sent once by the client at the very start of a TCP connection,
// and RE-SENT by an AMQP 1.0 client before each negotiated layer -- see below):
//   'A' 'M' 'Q' 'P'  <protocol-id byte>  <byte5>  <byte6>  <byte7>
//   - AMQP 0-9-1 (primary/modern form): protocol-id=0x00, byte5=0x00, byte6=0x09, byte7=0x01.
//   - AMQP 0-9-1 (rare historical variant -- RabbitMQ's own source comment: "This is the protocol
//     header for 0-9, which we can safely treat as though it were 0-9-1"): protocol-id=0x01,
//     byte5=0x01, byte6=0x00, byte7=0x09. Recognized as the SAME family (AmqpVersion::V091), not a
//     third version.
//   - AMQP 1.0, plain transport layer: protocol-id=0x00, byte5=0x01, byte6=0x00, byte7=0x00.
//   - AMQP 1.0, layered negotiation (the SAME 8 bytes re-sent with a different protocol-id byte
//     before each layer -- byte5/6/7 always 0x01/0x00/0x00 regardless of which layer): 0x02 = TLS,
//     0x03 = SASL, 0x00 = the AMQP transport proper (same value as the plain-transport case above --
//     a bare "AMQP\x00\x01\x00\x00" is ambiguous between "no security negotiated at all" and "the
//     AMQP-transport re-send after SASL/TLS completed"; this decoder doesn't need to tell those
//     apart, since either way the very next bytes on the wire are ordinary AMQP performative frames).
//     A secured connection's real sequence: client sends AMQP\x03\x01\x00\x00 (SASL) -> SASL frames
//     flow -> after sasl-outcome succeeds, client re-sends AMQP\x00\x01\x00\x00 -> AMQP performatives
//     flow. Every one of these re-sends is still exactly this same 8-byte shape, parsed by the same
//     try_parse_amqp_preamble() below -- only the protocol-id byte (and therefore layer_name) differs.
//   - AMQP 0-9-1 has NO equivalent in-band security-layer header of its own -- SASL-like negotiation
//     happens entirely inside ordinary METHOD frames (Connection.Start/Start-Ok/Secure/Secure-Ok),
//     decoded in amqp091.hpp/.cpp, not here.
//
// DETECTION POSTURE -- READ THIS BEFORE CHANGING ANYTHING BELOW: the preamble bytes above are the
// ONLY fully reliable way to tell AMQP 0-9-1 apart from AMQP 1.0, or either apart from non-AMQP
// traffic on port 5672. There is no self-describing tag anywhere in an ORDINARY (post-preamble)
// frame that distinguishes the two wire formats from each other with anything like the preamble's
// own certainty (0-9-1's per-frame Type byte and 1.0's per-frame TYPE byte occupy entirely different
// offsets and mean entirely different things -- see amqp091.hpp's/amqp10.hpp's own file header
// comments for each format's own, much weaker, structural per-frame gate). Port 5672/5671 alone
// never distinguishes the two versions either -- both are negotiated in-band via this exact header,
// on the exact same conventional port.
//
// Consequently: version detection happens ONCE PER TCP SESSION, the first time this session's own
// preamble is observed, cached in TCP-session-scoped flow state (AmqpFlowState below) for every
// later packet on that same session -- mirroring this codebase's existing per-session sticky-state
// pattern (ModbusFlowState's outstanding-transaction table, SMB's pipe-state maps, IPMI's own
// Cipher-Suite-0 stickiness in rmcp.hpp). A session whose opening preamble was never captured (a
// mid-stream-only capture, e.g. a rolling/ring-buffer capture that started recording after the TCP
// handshake and preamble had already gone by) is NOT guessed at via a byte-coincidence heuristic on
// its later frames -- both Amqp091Decoder::decode and Amqp10Decoder::decode DECLINE to classify such
// a session at all (return std::nullopt, falling through to this codebase's generic, unclassified
// "tcp" output) until/unless this same session's own preamble is eventually seen. This is a
// deliberate, honestly-documented scope boundary, not a gap to silently work around -- the same
// posture DeviceNet/CANopen's own dispatch-collision writeup (canopen.hpp) and Modbus's own
// request/response-pairing heuristic (modbus.hpp) already establish elsewhere in this codebase:
// decode confidently only where the wire format is unambiguous, and say so plainly where it isn't.
//
// STATEFULNESS / SHARED FLOW STATE: AmqpFlowState is genuinely shared between Amqp091Decoder and
// Amqp10Decoder -- both need to read AND write the exact same "which version is this session"
// fact, so both must resolve to the SAME entry in DecodeContext::flow_states, not two independent
// ones each keyed by its own id() (which is how DecodeContext::flow_state<T>() normally scopes
// state -- see protocol_decoder.hpp's own comment on ctx.protocol_id driving the outer map key).
// decoder.cpp's own AMQP call site achieves this deliberately: it sets ctx.protocol_id to the fixed
// string "amqp" (NOT to whichever decoder's own id(), "amqp091"/"amqp10", is about to be called)
// before invoking EITHER decoder, so ctx.flow_state<AmqpFlowState>() inside both Amqp091Decoder::
// decode and Amqp10Decoder::decode reads and writes the exact same per-TCP-session bucket. This is
// the one deliberate exception to this codebase's usual "ctx.protocol_id always equals this
// decoder's own id()" convention, and it exists purely because AMQP 0-9-1/1.0 are the first pair of
// registration-model decoders in this codebase that must share cross-packet session state despite
// having distinct ids() and distinct --protocol filter values -- decoder.cpp's own AMQP call site
// comment repeats this note at the one place it actually matters.
#pragma once

#include <cstdint>
#include <cstring>
#include <optional>
#include <string>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// Conventional AMQP TCP ports. 5671 (TLS-wrapped, implicit -- no in-protocol STARTTLS) is named
// here purely for documentation, the same "named but not decoded" posture rmcp.hpp's own
// RMCP_SECURE_UDP_PORT takes for RSP -- a TLS-wrapped AMQP session is out of scope past whatever
// generic TLS ClientHello/SNI recognition this codebase already gives any TLS-wrapped port (the
// same posture already established for RDP/WinRM's own port 3389/5986, see winrm.hpp), since this
// decoder never sees past the ClientHello on that port.
constexpr uint16_t AMQP_PORT = 5672;
constexpr uint16_t AMQP_TLS_PORT = 5671;  // named only, see above -- never decoded past this file.

enum class AmqpVersion : uint8_t {
    Unknown,  // no preamble observed yet on this session -- see DETECTION POSTURE above.
    V091,
    V10,
};

// Cross-packet, per-TCP-session state -- see this file's own STATEFULNESS section above for
// exactly how both Amqp091Decoder and Amqp10Decoder come to share ONE instance of this per
// session.
class AmqpFlowState : public DecoderFlowState {
public:
    AmqpVersion version = AmqpVersion::Unknown;
};

// One recognized 8-byte connection-preamble observation -- see this file's own header comment for
// the full byte-value table. `layer_name` is set only for an AMQP 1.0 preamble ("TLS"/"SASL"/
// "AMQP"); always nullptr for AMQP 0-9-1, which has no equivalent layered-negotiation concept.
struct AmqpPreamble {
    uint8_t protocol_id_raw = 0;
    uint8_t byte5 = 0, byte6 = 0, byte7 = 0;
    AmqpVersion version = AmqpVersion::Unknown;  // always V091 or V10 -- never Unknown once this
                                                   // struct is actually returned (see
                                                   // try_parse_amqp_preamble's own contract below).
    const char* layer_name = nullptr;   // AMQP 1.0 only: "TLS" / "SASL" / "AMQP".
    bool is_historical_091_variant = false;  // the rare 0x01/0x01/0x00/0x09 form.
    std::string summary;
};

// Recognizes `payload` (the very first bytes of a TCP flow, or any later re-send of this same
// 8-byte shape on an AMQP 1.0 session -- see this file's header comment) as one of the five legal
// connection-preamble byte patterns. Returns std::nullopt when `payload` is shorter than 8 bytes,
// does not begin with the literal ASCII bytes "AMQP", or begins with "AMQP" but the remaining four
// bytes don't match any of the five patterns this file's header comment enumerates -- this
// decoder never guesses at a sixth, unrecognized pattern; it is simply not a preamble this codebase
// knows how to name. Never throws.
std::optional<AmqpPreamble> try_parse_amqp_preamble(ByteSpan payload);

// Extracts the username (authcid) from an RFC 4616-style SASL PLAIN response/initial-response --
// `\x00` + authcid + `\x00` + passwd -- WITHOUT ever reading the password's own byte range past its
// own length. Returns std::nullopt when `plain_bytes` doesn't begin with the expected leading NUL
// or has no second NUL separator (malformed/truncated input -- never guessed at). Shared between
// amqp091.cpp's Connection.Start-Ok handling and amqp10.cpp's sasl-init handling, since the wire
// shape is byte-identical between the two protocols' own PLAIN mechanism -- see amqp091.hpp's and
// amqp10.hpp's own REDACTION sections.
inline std::optional<std::string> amqp_extract_plain_username(const std::string& plain_bytes) {
    if (plain_bytes.empty() || plain_bytes[0] != '\0') return std::nullopt;
    size_t i = 1;
    while (i < plain_bytes.size() && plain_bytes[i] != '\0') ++i;
    if (i >= plain_bytes.size()) return std::nullopt;  // no second NUL found.
    return plain_bytes.substr(1, i - 1);
}

// Small, generic big-endian 64-bit helpers -- byteio.hpp's own Cursor has u64le (Modbus/DNP3's own
// convention) but no u64be, and AMQP needs one on both sides (0-9-1's longlong delivery-tag/
// timestamp property; 1.0's ulong/long/timestamp primitives) -- the same "read_u64be as a small
// local helper, not a byteio.hpp addition" precedent s7commplus.cpp's own read_u64be already
// established for its own big-endian 64-bit needs. Shared here rather than duplicated in both
// amqp091.cpp and amqp10.cpp.
inline uint64_t amqp_read_u64be(Cursor& c) {
    uint64_t hi = c.u32be();
    uint64_t lo = c.u32be();
    return (hi << 32) | lo;
}

inline float amqp_read_f32be(Cursor& c) {
    uint32_t bits = c.u32be();
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

inline double amqp_read_f64be(Cursor& c) {
    uint64_t bits = amqp_read_u64be(c);
    double d;
    std::memcpy(&d, &bits, sizeof(d));
    return d;
}

}  // namespace conduitscope
