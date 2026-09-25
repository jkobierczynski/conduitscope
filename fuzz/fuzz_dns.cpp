// SPDX-License-Identifier: Apache-2.0
// fuzz_dns.cpp - libFuzzer harness for the shared DNS-message-shaped parser (dns.hpp) behind three
// registered decoders -- DNS (UDP port 53), mDNS (5353), and LLMNR (5355). All three dispatch
// through the one try_parse_dns_message entry point, differing only in the `DnsFlavor` argument
// (dns.hpp's own file header: "One shared parser ... covers" all three, and its own comment on
// DnsDecoder/MdnsDecoder/LlmnrDecoder: "each class below differs only in id()/udp_port()/which
// DnsFlavor it passes"). DNS's own compressed-name-pointer walk, the RDATA field-by-field decode
// for the "first pass" record types (A/AAAA/NS/CNAME/PTR/MX/SOA/TXT/SRV), and EDNS0 OPT
// pseudo-record handling (which repurposes the class/ttl fields entirely, dns.hpp's own
// DnsResourceRecordEntry comment) are all real hand-rolled length/offset parsing over a
// self-describing wire format, and the exact same code path additionally carries mDNS's own
// QU/cache-flush top-bit stripping and LLMNR's own stricter reserved-Z-bits rejection depending on
// which `flavor` is passed -- all reachable from the identical byte sequence.
//
// Mirrors fuzz_mqtt.cpp's own `session_version_hint` loop: rather than picking one DnsFlavor value,
// this calls try_parse_dns_message once per flavor against the SAME fuzzer input, since the flavor
// argument measurably changes both detection (LLMNR's own reserved-Z-bits gate) and rendering
// (mDNS's cache-flush/QU-bit handling) for otherwise-identical bytes -- exactly the "both are real,
// reachable values for the exact same wire bytes" reasoning fuzz_mqtt.cpp's own header comment
// gives for its hint parameter. No cross-packet state exists for any of the three flavors (dns.hpp
// documents no session tracking), so there is nothing else to reach.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dns.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    for (auto flavor : {conduitscope::DnsFlavor::Dns, conduitscope::DnsFlavor::Mdns,
                         conduitscope::DnsFlavor::Llmnr}) {
        try {
            (void)conduitscope::try_parse_dns_message(payload, flavor);
        } catch (const conduitscope::ParseError&) {
            // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
        }
    }

    return 0;
}
