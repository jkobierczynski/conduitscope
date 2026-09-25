// SPDX-License-Identifier: Apache-2.0
// fuzz_ldap.cpp - libFuzzer harness for Windows Active Directory LDAP (RFC 4511) parsing
// (ldap.hpp), over TCP/389 and TCP/3268 (Global Catalog -- see ldap.hpp's own file header). LDAP's
// wire format is a hand-rolled BER/DER reader (ldap.cpp) using RFC 4511's IMPLICIT TAGS convention
// -- the OPPOSITE of Kerberos's EXPLICIT TAGS, per ldap.hpp's own "WIRE FORMAT" paragraph, meaning
// this decoder's tag/length walk cannot simply reuse kerberos.cpp's BER reader shape and is its own
// from-scratch length/state-machine parser, exactly the kind of hand-rolled parsing this fuzzing
// pass targets.
//
// Calls try_parse_ldap directly on the raw fuzzer bytes, exactly like try_parse_kerberos/
// try_parse_twincat in the other single-entry-point harnesses -- no Ethernet/IPv4/TCP framing
// needed, since it already takes a ByteSpan over what would be a TCP payload (LdapTcpDecoder::decode
// calls it the same way). Does not cover LdapFlowState's own cross-packet bind/search correlation
// (LdapPendingBind/LdapPendingSearch), which needs a live DecodeContext and flow key -- that
// multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/ldap.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_ldap(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
