// SPDX-License-Identifier: Apache-2.0
// fuzz_dicom.cpp - libFuzzer harness for DICOM (DICOM PS3.8 upper-layer PDUs, ASSOCIATE-RQ/AC/RJ,
// P-DATA-TF, A-RELEASE/A-ABORT) plus the two Data-Set-shaped decoders it hands complete, reassembled
// buffers to (Command Set / Data Set tag decoding) -- dicom.hpp. Like s7comm_plus.hpp, DICOM's own
// wire format is genuinely complex (an association-negotiated Presentation Context table, a
// per-context Transfer Syntax that changes how the SAME bytes are interpreted downstream, PDV
// fragmentation across P-DATA-TF PDUs and across PDUs themselves), making it one of the highest
// hand-rolled-parsing-complexity decoders in this codebase and a natural next target after the
// second-wave four (bacnet/iec104/enip/s7comm_plus).
//
// THREE ENTRY POINTS, ONE HARNESS -- the same "independent entry points, same input, one harness"
// shape fuzz_enip.cpp already establishes for explicit/implicit CIP messaging:
//
//   1. try_parse_dicom_pdu(ByteSpan candidate) -- parses exactly ONE PDU's own structural shape
//      (fixed 6-byte common header, PDU-type-keyed body: ASSOCIATE-RQ/AC's Presentation Context/User
//      Information item walk, P-DATA-TF's PDV list, ASSOCIATE-RJ/A-ABORT's fixed reason/source
//      fields). This is exactly the entry point DicomDecoder::decode itself calls first (see
//      dicom.cpp), including its own "coalesce every further PDU in the same payload into notes"
//      loop -- mirrored here by calling it once against the raw fuzzer bytes, the same "one call,
//      whatever the real dispatch site's own first call looks like" shape every harness in this
//      suite uses. Does NOT decode a P-DATA-TF's own Command Set/Data Set content (that needs
//      cross-packet DicomAssociationState/DicomDimseReassemblyState this free function has no access
//      to -- see its own doc comment) -- only PDV structure (length, presentation-context-ID,
//      Command/Data flag, last-fragment flag).
//
//   2/3. decode_dicom_command_set(ByteSpan bytes) / decode_dicom_data_set(ByteSpan bytes, bool
//      explicit_vr, bool big_endian, bool redact_secrets) -- the two tag-table decoders
//      DicomDecoder::decode calls DIRECTLY (dicom.cpp, once DicomDimseReassemblyState's own
//      buffering has assembled a complete Command Set or Data Set from one or more PDV fragments) --
//      genuinely independent entry points from try_parse_dicom_pdu's own per-PDU parsing: a fuzzer
//      driving only try_parse_dicom_pdu would need a PDV whose own bytes are ALSO a complete,
//      correctly length-prefixed tag stream before this tag-walking logic (DicomDataSet's own
//      length-prefixed-tag loop, VR-keyed length-field-width switch, the three curated-PHI-tag
//      redaction paths) is ever reached at all -- calling both decoders directly on the same raw
//      input, with no PDV/PDU framing required first, reaches that logic in far fewer iterations,
//      the same reasoning fuzz_enip.cpp's own header comment gives for its own two-entry-point shape.
//      Real production code derives explicit_vr/big_endian from DicomAssociationState's own
//      negotiated Transfer Syntax UID (see dicom.cpp) -- state this free function, and this
//      standalone harness, has no access to; instead this harness derives all three booleans from
//      one spare input byte, so every input deterministically drives all eight explicit_vr/
//      big_endian/redact_secrets combinations across the corpus rather than only ever the
//      production-derived (false, false) pair a hand-picked constant would fix in place.
//
// Both 2/3 are documented "Never throws" (returning DicomCommandSet/DicomDataSet by value, not
// std::optional) -- still wrapped in try/catch below, the same defensive posture every harness in
// this suite takes.
//
// Does not cover: cross-packet association negotiation (DicomAssociationState -- which Presentation
// Context/Transfer Syntax a later P-DATA-TF's own presentation-context-ID actually resolves to) or
// DIMSE fragment reassembly across PDV/PDU boundaries (DicomDimseReassemblyState) -- both need a live
// DecodeContext and flow key; that multi-packet path is covered by fuzz_packet_decode instead.
#include <cstdint>
#include <cstddef>

#include "conduitscope/byteio.hpp"
#include "conduitscope/dicom.hpp"

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    conduitscope::ByteSpan payload(data, size);

    try {
        (void)conduitscope::try_parse_dicom_pdu(payload);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    if (payload.empty()) {
        return 0;
    }
    uint8_t flags = payload.at(0);
    conduitscope::ByteSpan body = payload.from(1);
    bool explicit_vr = (flags & 0x01) != 0;
    bool big_endian = (flags & 0x02) != 0;
    bool redact_secrets = (flags & 0x04) != 0;

    try {
        (void)conduitscope::decode_dicom_command_set(body);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    try {
        (void)conduitscope::decode_dicom_data_set(body, explicit_vr, big_endian, redact_secrets);
    } catch (const conduitscope::ParseError&) {
        // Expected, handled outcome -- see fuzz_dnp3.cpp's identical comment.
    }

    return 0;
}
