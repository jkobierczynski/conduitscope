// SPDX-License-Identifier: Apache-2.0
#include "conduitscope/amqp_common.hpp"

#include <sstream>

namespace conduitscope {

std::optional<AmqpPreamble> try_parse_amqp_preamble(ByteSpan payload) {
    if (payload.size() < 8) return std::nullopt;
    if (payload.at(0) != 'A' || payload.at(1) != 'M' || payload.at(2) != 'Q' || payload.at(3) != 'P') {
        return std::nullopt;
    }
    uint8_t protocol_id = payload.at(4);
    uint8_t b5 = payload.at(5), b6 = payload.at(6), b7 = payload.at(7);

    AmqpPreamble pre;
    pre.protocol_id_raw = protocol_id;
    pre.byte5 = b5;
    pre.byte6 = b6;
    pre.byte7 = b7;

    if (protocol_id == 0x00 && b5 == 0x00 && b6 == 0x09 && b7 == 0x01) {
        pre.version = AmqpVersion::V091;
        pre.summary = "AMQP connection preamble: version 0-9-1";
    } else if (protocol_id == 0x01 && b5 == 0x01 && b6 == 0x00 && b7 == 0x09) {
        pre.version = AmqpVersion::V091;
        pre.is_historical_091_variant = true;
        pre.summary = "AMQP connection preamble: version 0-9 (historical variant, treated as 0-9-1)";
    } else if (protocol_id == 0x00 && b5 == 0x01 && b6 == 0x00 && b7 == 0x00) {
        pre.version = AmqpVersion::V10;
        pre.layer_name = "AMQP";
        pre.summary = "AMQP connection preamble: version 1.0 (AMQP transport layer)";
    } else if (protocol_id == 0x02 && b5 == 0x01 && b6 == 0x00 && b7 == 0x00) {
        pre.version = AmqpVersion::V10;
        pre.layer_name = "TLS";
        pre.summary = "AMQP connection preamble: version 1.0 (TLS layer negotiation)";
    } else if (protocol_id == 0x03 && b5 == 0x01 && b6 == 0x00 && b7 == 0x00) {
        pre.version = AmqpVersion::V10;
        pre.layer_name = "SASL";
        pre.summary = "AMQP connection preamble: version 1.0 (SASL layer negotiation)";
    } else {
        return std::nullopt;
    }
    return pre;
}

}  // namespace conduitscope
