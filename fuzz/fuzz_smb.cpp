// SPDX-License-Identifier: Apache-2.0
// fuzz_smb.cpp - libFuzzer harness for SMB2/SMB3 (MS-SMB2) parsing (smb.hpp), over TCP/445
// (direct hosting) and TCP/139 (NetBIOS Session Service), including embedded NTLM (MS-NLMP)
// authentication decoding. try_parse_smb (smb.cpp) structurally walks a compounded SMB2
// request/response chain -- more than one SMB2 message glued back-to-back via NextCommand offsets
// -- on top of the 4-byte Zero+StreamProtocolLength prefix framing, exactly the kind of hand-
// rolled length/chaining logic this fuzzing pass targets, and NTLM's own Type 1/2/3 message
// decoding (embedded inside SESSION_SETUP) adds a second, unrelated binary format reached through
// the same entry point.
//
// Calls try_parse_smb directly on the raw fuzzer bytes, exactly like try_parse_ldap/
// try_parse_kerberos in the other single-entry-point harnesses -- no Ethernet/IPv4/TCP framing
// needed, since it already takes a ByteSpan over what would be a TCP payload (payload must start
// with the 4-byte Zero+StreamProtocolLength prefix, per try_parse_smb's own doc comment).
// `tracked_rpc_pipe_file_ids` is left at its default nullptr, the same "no live SmbFlowState"
// posture a standalone/context-free caller takes per smb.hpp's own comment on that parameter --
// this means no WRITE/READ/IOCTL message here ever gets a populated dcerpc_raw_payload, which is
// exactly correct for this harness and does not gate try_parse_smb's own structural parsing at all.
// Does not cover SmbFlowState's own cross-packet session/tree/file-handle correlation (the
// Netlogon/SAMR/LSARPC/SRVSVC/WKSSVC/DRSUAPI per-interface pipe-state maps, or NTLM handshake
// pairing), which needs a live DecodeContext and flow key -- that multi-packet path is covered by
// fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/smb.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_smb(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
