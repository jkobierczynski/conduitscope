// SPDX-License-Identifier: Apache-2.0
// dicom.cpp - see dicom.hpp for the full sourcing/scope/security/stateful design writeup.
#include "conduitscope/dicom.hpp"

#include <algorithm>
#include <sstream>
#include <unordered_map>
#include <unordered_set>

#include "conduitscope/resource_limits.hpp"

namespace conduitscope {

namespace {

std::string hex_u16(uint16_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << static_cast<unsigned>(v);
    return s.str();
}

std::string hex_u8(uint8_t v) {
    std::ostringstream s;
    s << "0x" << std::hex << std::uppercase << static_cast<unsigned>(v);
    return s.str();
}

std::string name_or_hex(const char* name, uint8_t raw) {
    return name ? std::string(name) : hex_u8(raw);
}

std::string ascii_string(ByteSpan span) {
    return std::string(reinterpret_cast<const char*>(span.data()), span.size());
}

// AE-titles are space-padded (PS3.8) -- trims trailing spaces (and, defensively, any trailing
// NUL a malformed sender might have used instead).
std::string trim_trailing_ae(std::string s) {
    while (!s.empty() && (s.back() == ' ' || s.back() == '\0')) s.pop_back();
    return s;
}

// UID strings are NUL-padded to even length (PS3.5), NOT space-padded -- but this decoder trims
// trailing spaces too, defensively, since some real-world senders get this wrong.
std::string ascii_trim(ByteSpan span) {
    std::string s = ascii_string(span);
    while (!s.empty() && (s.back() == '\0' || s.back() == ' ')) s.pop_back();
    return s;
}

std::string sop_class_display(const std::string& uid) {
    const char* n = dicom_sop_class_name(uid);
    return n ? std::string(n) : ("Unknown SOP Class (" + uid + ")");
}

std::string transfer_syntax_display(const std::string& uid) {
    const char* n = dicom_transfer_syntax_name(uid);
    return n ? std::string(n) : ("Unknown Transfer Syntax (" + uid + ")");
}

std::string dicom_user_identity_type_name(uint8_t t) {
    switch (t) {
        case 1: return "username";
        case 2: return "username+passcode";
        case 3: return "Kerberos ticket";
        case 4: return "SAML assertion";
        default: return "unknown (" + std::to_string(t) + ")";
    }
}

// Presentation Context Result/Reason (AC form) -- distinct from A-ASSOCIATE-RJ's own Result table
// below despite similar wording, see dicom.hpp's own WIRE FORMAT section.
const char* dicom_pc_result_name_raw(uint8_t r) {
    switch (r) {
        case 0: return "Acceptance";
        case 1: return "User-rejection";
        case 2: return "No-reason-given";
        case 3: return "Abstract-syntax-not-supported";
        case 4: return "Transfer-syntaxes-not-supported";
        default: return nullptr;
    }
}

// Generic variable-item sub-TLV: item-type(1) reserved(1) item-length(2,BE) value(item-length
// bytes) -- used at every nesting level (top-level RQ/AC items, Presentation Context sub-items,
// User Information sub-items). Never throws: a malformed/truncated trailing item simply stops the
// scan early, matching this codebase's universal "decode what's decodable" posture.
struct RawItem {
    uint8_t type = 0;
    uint16_t length = 0;
    ByteSpan value;
};

std::vector<RawItem> read_items(ByteSpan region) {
    std::vector<RawItem> items;
    Cursor c(region);
    while (c.remaining() >= 4) {
        uint8_t type = c.u8();
        c.u8();  // reserved, not validated
        uint16_t len = c.u16be();
        if (len > c.remaining()) break;  // truncated trailing item -- stop, don't guess
        RawItem item;
        item.type = type;
        item.length = len;
        item.value = c.bytes(len);
        items.push_back(item);
    }
    return items;
}

// Curated data-set tags this decoder extracts -- see dicom.hpp's own REDACTION section for the
// full table and the rationale behind which three are redacted by default.
struct CuratedTag {
    uint16_t group;
    uint16_t element;
    const char* name;
    bool is_pn;    // Person Name -- gets the extra caret-trim (see render below).
    bool redact;
};

constexpr CuratedTag kCuratedTags[] = {
    {0x0010, 0x0010, "Patient's Name", true, true},
    {0x0010, 0x0020, "Patient ID", false, true},
    {0x0010, 0x0030, "Patient's Birth Date", false, true},
    {0x0010, 0x0040, "Patient's Sex", false, false},
    {0x0020, 0x000D, "Study Instance UID", false, false},
    {0x0020, 0x000E, "Series Instance UID", false, false},
    {0x0008, 0x0018, "SOP Instance UID", false, false},
    {0x0008, 0x0050, "Accession Number", false, false},
    {0x0008, 0x0060, "Modality", false, false},
    {0x0008, 0x0080, "Institution Name", false, false},
    {0x0008, 0x1010, "Station Name", false, false},
    {0x0008, 0x0070, "Manufacturer", false, false},
    {0x0008, 0x1090, "Manufacturer's Model Name", false, false},
    {0x0008, 0x0020, "Study Date", false, false},
    {0x0008, 0x1030, "Study Description", false, false},
};

const CuratedTag* find_curated_tag(uint16_t group, uint16_t element) {
    for (const auto& t : kCuratedTags) {
        if (t.group == group && t.element == element) return &t;
    }
    return nullptr;
}

std::string render_curated_value(const CuratedTag& tag, ByteSpan value) {
    std::string s = ascii_trim(value);
    if (tag.is_pn) {
        while (!s.empty() && s.back() == '^') s.pop_back();
    }
    return s;
}

// Skips one undefined-length element's own content, by walking a flat sequence of definite-length
// Items (FFFE,E000) up to the Sequence Delimitation Item (FFFE,E0DD) -- see dicom.hpp's own WIRE
// FORMAT section for exactly what this does and doesn't handle, and why. Returns false (an honest,
// documented bail-out, never a guess) when it cannot safely bound the element this way: truncation,
// an unexpected tag, or an Item that is ITSELF undefined-length (genuinely nested undefined-length
// structure, out of scope).
bool skip_undefined_length_element(Cursor& c, bool big_endian) {
    while (true) {
        if (c.remaining() < 8) return false;
        uint16_t group = big_endian ? c.u16be() : c.u16le();
        uint16_t element = big_endian ? c.u16be() : c.u16le();
        uint32_t len = big_endian ? c.u32be() : c.u32le();
        if (group == 0xFFFE && element == 0xE0DD) {
            if (len > 0) {
                if (c.remaining() < len) return false;
                c.skip(len);
            }
            return true;
        }
        if (group == 0xFFFE && element == 0xE000) {
            if (len == 0xFFFFFFFFu) return false;  // nested undefined-length item -- honest bail-out
            if (c.remaining() < len) return false;
            c.skip(len);
            continue;
        }
        return false;  // unexpected tag inside an undefined-length element's own item stream
    }
}

std::string tag_hex(uint16_t group, uint16_t element) {
    std::ostringstream s;
    s << "(" << std::hex << std::uppercase;
    s.width(4); s.fill('0'); s << group << ",";
    s.width(4); s.fill('0'); s << element << ")";
    return s.str();
}

const std::unordered_set<std::string>& long_form_vrs() {
    static const std::unordered_set<std::string> kSet = {"OB", "OD", "OF", "OL", "OW",
                                                            "SQ", "UC", "UR", "UT", "UN"};
    return kSet;
}

}  // namespace

const char* dicom_pdu_type_name(uint8_t t) {
    switch (t) {
        case 0x01: return "A-ASSOCIATE-RQ";
        case 0x02: return "A-ASSOCIATE-AC";
        case 0x03: return "A-ASSOCIATE-RJ";
        case 0x04: return "P-DATA-TF";
        case 0x05: return "A-RELEASE-RQ";
        case 0x06: return "A-RELEASE-RP";
        case 0x07: return "A-ABORT";
        default: return nullptr;
    }
}

const char* dicom_item_type_name(uint8_t t) {
    switch (t) {
        case 0x10: return "Application Context";
        case 0x20: return "Presentation Context (RQ)";
        case 0x21: return "Presentation Context (AC)";
        case 0x30: return "Abstract Syntax";
        case 0x40: return "Transfer Syntax";
        case 0x50: return "User Information";
        case 0x51: return "Maximum Length";
        case 0x52: return "Implementation Class UID";
        case 0x53: return "Asynchronous Operations Window Negotiation";
        case 0x54: return "SCP/SCU Role Selection";
        case 0x55: return "Implementation Version Name";
        case 0x56: return "SOP Class Extended Negotiation";
        case 0x57: return "SOP Class Common Extended Negotiation";
        case 0x58: return "User Identity Negotiation";
        case 0x59: return "User Identity Negotiation Reply";
        default: return nullptr;
    }
}

// Curated SOP Class UID table -- see dicom.hpp's own SCOPE section for why this is curated, not
// exhaustive (DICOM registers hundreds of SOP classes; a full data-dictionary port is out of scope
// for a security-inventory tool).
const char* dicom_sop_class_name(const std::string& uid) {
    static const std::unordered_map<std::string, const char*> kTable = {
        {"1.2.840.10008.1.1", "Verification SOP Class"},
        {"1.2.840.10008.5.1.4.1.1.2", "CT Image Storage"},
        {"1.2.840.10008.5.1.4.1.1.4", "MR Image Storage"},
        {"1.2.840.10008.5.1.4.1.1.6.1", "Ultrasound Image Storage"},
        {"1.2.840.10008.5.1.4.1.1.7", "Secondary Capture Image Storage"},
        {"1.2.840.10008.5.1.4.1.2.1.1", "Patient Root Query/Retrieve Information Model - FIND"},
        {"1.2.840.10008.5.1.4.1.2.1.2", "Patient Root Query/Retrieve Information Model - MOVE"},
        {"1.2.840.10008.5.1.4.1.2.1.3", "Patient Root Query/Retrieve Information Model - GET"},
        {"1.2.840.10008.5.1.4.1.2.2.1", "Study Root Query/Retrieve Information Model - FIND"},
        {"1.2.840.10008.5.1.4.1.2.2.2", "Study Root Query/Retrieve Information Model - MOVE"},
        {"1.2.840.10008.5.1.4.1.2.2.3", "Study Root Query/Retrieve Information Model - GET"},
        {"1.2.840.10008.5.1.4.31", "Modality Worklist Information Model - FIND"},
    };
    auto it = kTable.find(uid);
    return it == kTable.end() ? nullptr : it->second;
}

// Curated Transfer Syntax UID table -- see dicom.hpp's own SCOPE/WIRE FORMAT sections.
const char* dicom_transfer_syntax_name(const std::string& uid) {
    static const std::unordered_map<std::string, const char*> kTable = {
        {"1.2.840.10008.1.2", "Implicit VR Little Endian"},
        {"1.2.840.10008.1.2.1", "Explicit VR Little Endian"},
        {"1.2.840.10008.1.2.1.99", "Deflated Explicit VR Little Endian"},
        {"1.2.840.10008.1.2.2", "Explicit VR Big Endian (Retired)"},
        {"1.2.840.10008.1.2.4.50", "JPEG Baseline (Process 1)"},
        {"1.2.840.10008.1.2.4.90", "JPEG 2000 Image Compression (Lossless Only)"},
        {"1.2.840.10008.1.2.4.91", "JPEG 2000 Image Compression"},
        {"1.2.840.10008.1.2.5", "RLE Lossless"},
    };
    auto it = kTable.find(uid);
    return it == kTable.end() ? nullptr : it->second;
}

bool dicom_transfer_syntax_is_compressed(const std::string& uid) {
    return uid.rfind("1.2.840.10008.1.2.4.", 0) == 0 || uid == "1.2.840.10008.1.2.5";
}

const char* dicom_command_field_name(uint16_t c) {
    switch (c) {
        case 0x0001: return "C-STORE-RQ";
        case 0x8001: return "C-STORE-RSP";
        case 0x0010: return "C-GET-RQ";
        case 0x8010: return "C-GET-RSP";
        case 0x0020: return "C-FIND-RQ";
        case 0x8020: return "C-FIND-RSP";
        case 0x0021: return "C-MOVE-RQ";
        case 0x8021: return "C-MOVE-RSP";
        case 0x0030: return "C-ECHO-RQ";
        case 0x8030: return "C-ECHO-RSP";
        case 0x0FFF: return "C-CANCEL-RQ";
        case 0x0100: return "N-EVENT-REPORT-RQ";
        case 0x8100: return "N-EVENT-REPORT-RSP";
        case 0x0110: return "N-GET-RQ";
        case 0x8110: return "N-GET-RSP";
        case 0x0120: return "N-SET-RQ";
        case 0x8120: return "N-SET-RSP";
        case 0x0130: return "N-ACTION-RQ";
        case 0x8130: return "N-ACTION-RSP";
        case 0x0140: return "N-CREATE-RQ";
        case 0x8140: return "N-CREATE-RSP";
        case 0x0150: return "N-DELETE-RQ";
        case 0x8150: return "N-DELETE-RSP";
        default: return nullptr;
    }
}

DicomStatusClass dicom_status_class(uint16_t s) {
    if (s == 0x0000) return DicomStatusClass::Success;
    if ((s & 0xFF00) == 0xFF00) return DicomStatusClass::Pending;
    if (s == 0xFE00) return DicomStatusClass::Cancel;
    if (s == 0xB000 || s == 0xB007) return DicomStatusClass::Warning;
    return DicomStatusClass::Failure;
}

const char* dicom_status_name(uint16_t s) {
    switch (s) {
        case 0x0000: return "Success";
        case 0xFF00: return "Pending";
        case 0xFF01: return "Pending (with warning)";
        case 0xFE00: return "Cancel";
        case 0x0105: return "No such attribute";
        case 0x0106: return "Invalid attribute value";
        case 0x0110: return "Processing failure";
        case 0x0111: return "Duplicate SOP instance";
        case 0x0112: return "No such object instance";
        case 0x0118: return "No such SOP class";
        case 0x0122: return "Refused: SOP class not supported";
        case 0x0210: return "Duplicate invocation";
        case 0x0211: return "Unrecognized operation";
        case 0x0213: return "Resource limitation";
        case 0xA700: case 0xA701: case 0xA702: return "Refused: Out of Resources";
        case 0xA801: return "Refused: Move Destination unknown";
        case 0xB000: return "Sub-operations Complete - One or more Failures";
        case 0xB007: return "Data Set does not match SOP Class";
        case 0xC000: return "Error: Cannot understand / Unable to process";
        default: return nullptr;
    }
}

const char* dicom_rj_result_name(uint8_t r) {
    switch (r) {
        case 1: return "Rejected-permanent";
        case 2: return "Rejected-transient";
        default: return nullptr;
    }
}

const char* dicom_rj_source_name(uint8_t s) {
    switch (s) {
        case 1: return "DICOM-UL-service-user";
        case 2: return "DICOM-UL-service-provider (ACSE)";
        case 3: return "DICOM-UL-service-provider (Presentation)";
        default: return nullptr;
    }
}

const char* dicom_rj_reason_name(uint8_t source, uint8_t reason) {
    if (source == 1) {
        switch (reason) {
            case 1: return "no-reason-given";
            case 2: return "application-context-name-not-supported";
            case 3: return "calling-AE-title-not-recognized";
            case 7: return "called-AE-title-not-recognized";
            default: return nullptr;
        }
    }
    if (source == 2) {
        switch (reason) {
            case 1: return "no-reason-given";
            case 2: return "protocol-version-not-supported";
            default: return nullptr;
        }
    }
    if (source == 3) {
        switch (reason) {
            case 1: return "temporary-congestion";
            case 2: return "local-limit-exceeded";
            default: return nullptr;
        }
    }
    return nullptr;
}

const char* dicom_abort_source_name(uint8_t s) {
    switch (s) {
        case 0: return "DICOM-UL-service-user";
        case 2: return "DICOM-UL-service-provider";
        default: return nullptr;
    }
}

const char* dicom_abort_reason_name(uint8_t r) {
    switch (r) {
        case 0: return "reason-not-specified";
        case 1: return "unrecognized-PDU";
        case 2: return "unexpected-PDU";
        case 4: return "unrecognized-PDU-parameter";
        case 5: return "unexpected-PDU-parameter";
        case 6: return "invalid-PDU-parameter-value";
        default: return nullptr;
    }
}

// ---------------------------------------------------------------------------------------------
// Command Set decode (always Implicit VR Little Endian -- see dicom.hpp's own CRITICAL RULE note).

DicomCommandSet decode_dicom_command_set(ByteSpan bytes) {
    DicomCommandSet cs;
    Cursor c(bytes);
    while (c.remaining() >= 8) {
        uint16_t group = c.u16le();
        uint16_t element = c.u16le();
        uint32_t length = c.u32le();
        if (length == 0xFFFFFFFFu || c.remaining() < length) break;  // never legal in a Command Set
        ByteSpan value = c.bytes(length);
        if (group != 0x0000) continue;  // every curated command tag is group 0000

        uint16_t u16v = 0;
        bool has_u16 = length >= 2;
        if (has_u16) {
            Cursor vc(value);
            u16v = vc.u16le();
        }
        switch (element) {
            case 0x0100:
                if (has_u16) {
                    cs.command_field_raw = u16v;
                    const char* n = dicom_command_field_name(u16v);
                    if (n) cs.command_field_name = n;
                }
                break;
            case 0x0110: if (has_u16) cs.message_id = u16v; break;
            case 0x0120: if (has_u16) cs.message_id_being_responded_to = u16v; break;
            case 0x0800: if (has_u16) cs.data_set_type_raw = u16v; break;
            case 0x0900:
                if (has_u16) {
                    cs.status_raw = u16v;
                    cs.status_class = dicom_status_class(u16v);
                    const char* n = dicom_status_name(u16v);
                    if (n) cs.status_name = n;
                }
                break;
            case 0x0002: cs.affected_sop_class_uid = ascii_trim(value); break;
            case 0x0003: cs.requested_sop_class_uid = ascii_trim(value); break;
            case 0x1000: cs.affected_sop_instance_uid = ascii_trim(value); break;
            case 0x1001: cs.requested_sop_instance_uid = ascii_trim(value); break;
            case 0x1020: if (has_u16) cs.remaining_suboperations = u16v; break;
            case 0x1021: if (has_u16) cs.completed_suboperations = u16v; break;
            case 0x1022: if (has_u16) cs.failed_suboperations = u16v; break;
            case 0x1023: if (has_u16) cs.warning_suboperations = u16v; break;
            default: break;
        }
    }
    return cs;
}

// ---------------------------------------------------------------------------------------------
// Data Set decode (curated tag extraction only -- see dicom.hpp's own SCOPE/WIRE FORMAT sections).

DicomDataSet decode_dicom_data_set(ByteSpan bytes, bool explicit_vr, bool big_endian,
                                    bool redact_secrets) {
    DicomDataSet ds;
    Cursor c(bytes);
    while (c.remaining() >= 8) {
        uint16_t group = big_endian ? c.u16be() : c.u16le();
        uint16_t element = big_endian ? c.u16be() : c.u16le();

        uint32_t length;
        if (explicit_vr) {
            if (c.remaining() < 2) break;
            ByteSpan vr_bytes = c.bytes(2);
            std::string vr = ascii_string(vr_bytes);
            if (long_form_vrs().count(vr)) {
                if (c.remaining() < 6) break;
                c.u8(); c.u8();  // reserved(2) -- value not meaningful, endianness irrelevant
                length = big_endian ? c.u32be() : c.u32le();
            } else {
                if (c.remaining() < 2) break;
                length = big_endian ? c.u16be() : c.u16le();
            }
        } else {
            if (c.remaining() < 4) break;
            length = big_endian ? c.u32be() : c.u32le();
        }

        bool is_pixel_data = (group == 0x7FE0 && element == 0x0010);

        if (length == 0xFFFFFFFFu) {
            if (!skip_undefined_length_element(c, big_endian)) {
                ds.stopped_reason = "data set extraction stopped: undefined-length element of "
                                     "unrecognized structure encountered at tag " +
                                     tag_hex(group, element);
                return ds;
            }
            continue;
        }

        if (c.remaining() < length) break;  // truncated trailing element -- stop, don't guess

        if (is_pixel_data) {
            c.skip(length);
            continue;
        }

        const CuratedTag* curated = find_curated_tag(group, element);
        if (!curated) {
            c.skip(length);
            continue;
        }

        ByteSpan value = c.bytes(length);
        DicomDataElement de;
        de.tag_name = curated->name;
        if (curated->redact && redact_secrets) {
            de.rendered = std::string(kRedactedSecretPlaceholder) + " (" + std::to_string(length) +
                           " byte(s))";
            de.redacted = true;
        } else {
            de.rendered = render_curated_value(*curated, value);
        }
        ds.elements.push_back(std::move(de));
    }
    return ds;
}

// ---------------------------------------------------------------------------------------------
// PDU parsing.

std::optional<DicomFrame> try_parse_dicom_pdu(ByteSpan candidate) {
    if (candidate.size() < 6) return std::nullopt;
    uint8_t type_raw = candidate.at(0);
    if (type_raw < 0x01 || type_raw > 0x07) return std::nullopt;

    try {
        Cursor hc(candidate);
        hc.u8();
        hc.u8();  // reserved -- PS3.8 says NOT to validate this on receive, see dicom.hpp
        uint32_t length = hc.u32be();

        DicomFrame frame;
        frame.pdu_type_raw = type_raw;
        frame.pdu_type_name = dicom_pdu_type_name(type_raw);

        frame.pdu_length = length;
        size_t full_wire_length = 6 + static_cast<size_t>(length);
        bool have_full = candidate.size() >= full_wire_length;
        frame.truncated = !have_full;
        frame.wire_length = have_full ? full_wire_length : candidate.size();

        if (!have_full) {
            frame.notes.push_back("PDU truncated: only " + std::to_string(candidate.size()) +
                                   " of " + std::to_string(full_wire_length) +
                                   " declared byte(s) available");
            frame.summary = frame.pdu_type_name + " (truncated)";
            return frame;
        }

        ByteSpan body = candidate.subspan(6, length);

        switch (type_raw) {
            case 0x01:
            case 0x02: {
                DicomAssociateRqAc assoc;
                assoc.is_request = (type_raw == 0x01);
                if (body.size() < 68) {
                    frame.notes.push_back(frame.pdu_type_name + " too short for its fixed fields");
                    frame.summary = frame.pdu_type_name;
                    break;
                }
                Cursor bc(body);
                assoc.protocol_version_raw = bc.u16be();
                bc.u16be();  // reserved
                assoc.called_ae_title = trim_trailing_ae(ascii_string(bc.bytes(16)));
                assoc.calling_ae_title = trim_trailing_ae(ascii_string(bc.bytes(16)));
                bc.bytes(32);  // reserved

                for (const auto& item : read_items(bc.rest())) {
                    switch (item.type) {
                        case 0x10: {
                            std::string uid = ascii_trim(item.value);
                            assoc.application_context_is_well_known =
                                (uid == "1.2.840.10008.3.1.1.1");
                            assoc.application_context_uid = std::move(uid);
                            if (!assoc.application_context_is_well_known) {
                                frame.notes.push_back("Application Context UID \"" +
                                                       *assoc.application_context_uid +
                                                       "\" is not the well-known DICOM UL value "
                                                       "(1.2.840.10008.3.1.1.1)");
                            }
                            break;
                        }
                        case 0x20: {
                            if (item.value.size() < 4) break;
                            Cursor pc(item.value);
                            DicomPresentationContextRq ctxrq;
                            ctxrq.id = pc.u8();
                            pc.u8(); pc.u8(); pc.u8();  // 3 reserved bytes
                            for (const auto& sub : read_items(pc.rest())) {
                                if (sub.type == 0x30) {
                                    DicomAbstractSyntax as;
                                    as.uid = ascii_trim(sub.value);
                                    as.name = sop_class_display(as.uid);
                                    ctxrq.abstract_syntax = std::move(as);
                                } else if (sub.type == 0x40) {
                                    DicomTransferSyntax ts;
                                    ts.uid = ascii_trim(sub.value);
                                    ts.name = transfer_syntax_display(ts.uid);
                                    ts.compressed = dicom_transfer_syntax_is_compressed(ts.uid);
                                    ctxrq.transfer_syntaxes.push_back(std::move(ts));
                                }
                            }
                            assoc.presentation_contexts_rq.push_back(std::move(ctxrq));
                            break;
                        }
                        case 0x21: {
                            if (item.value.size() < 4) break;
                            Cursor pc(item.value);
                            DicomPresentationContextAc ctxac;
                            ctxac.id = pc.u8();
                            pc.u8();
                            ctxac.result_raw = pc.u8();
                            pc.u8();
                            ctxac.result_name = name_or_hex(dicom_pc_result_name_raw(ctxac.result_raw),
                                                             ctxac.result_raw);
                            ctxac.accepted = (ctxac.result_raw == 0);
                            for (const auto& sub : read_items(pc.rest())) {
                                if (sub.type == 0x40) {
                                    DicomTransferSyntax ts;
                                    ts.uid = ascii_trim(sub.value);
                                    ts.name = transfer_syntax_display(ts.uid);
                                    ts.compressed = dicom_transfer_syntax_is_compressed(ts.uid);
                                    ctxac.transfer_syntax = std::move(ts);
                                }
                            }
                            assoc.presentation_contexts_ac.push_back(std::move(ctxac));
                            break;
                        }
                        case 0x50: {
                            for (const auto& sub : read_items(item.value)) {
                                switch (sub.type) {
                                    case 0x51:
                                        if (sub.value.size() >= 4) {
                                            Cursor mc(sub.value);
                                            assoc.user_information.max_length_received = mc.u32be();
                                        }
                                        break;
                                    case 0x52:
                                        assoc.user_information.implementation_class_uid =
                                            ascii_trim(sub.value);
                                        break;
                                    case 0x55:
                                        assoc.user_information.implementation_version_name =
                                            ascii_trim(sub.value);
                                        break;
                                    case 0x53:
                                        if (sub.value.size() >= 4) {
                                            Cursor mc(sub.value);
                                            assoc.user_information.max_ops_invoked = mc.u16be();
                                            assoc.user_information.max_ops_performed = mc.u16be();
                                        }
                                        break;
                                    case 0x54: {
                                        if (sub.value.size() < 2) break;
                                        Cursor rc(sub.value);
                                        uint16_t m = rc.u16be();
                                        if (rc.remaining() < static_cast<size_t>(m) + 2) break;
                                        DicomRoleSelection rs;
                                        rs.sop_class_uid = ascii_trim(rc.bytes(m));
                                        rs.sop_class_name = sop_class_display(rs.sop_class_uid);
                                        rs.scu_role = rc.u8() != 0;
                                        rs.scp_role = rc.u8() != 0;
                                        assoc.user_information.role_selections.push_back(std::move(rs));
                                        break;
                                    }
                                    case 0x58: {
                                        if (sub.value.size() < 4) break;
                                        Cursor uc(sub.value);
                                        DicomUserIdentity ui;
                                        ui.type_raw = uc.u8();
                                        ui.type_name = dicom_user_identity_type_name(ui.type_raw);
                                        ui.positive_response_requested = uc.u8() != 0;
                                        if (uc.remaining() < 2) break;
                                        uint16_t plen = uc.u16be();
                                        if (uc.remaining() < plen) break;
                                        ByteSpan primary = uc.bytes(plen);
                                        ui.primary_field_length = plen;
                                        if (ui.type_raw == 1 || ui.type_raw == 2) {
                                            ui.primary_field = ascii_trim(primary);
                                        }
                                        if (ui.type_raw == 2 && uc.remaining() >= 2) {
                                            uint16_t slen = uc.u16be();
                                            ui.secondary_present = true;
                                            ui.secondary_field_length = slen;
                                            // Deliberately never read into `ui` -- length only, see
                                            // dicom.hpp's own REDACTION section.
                                            if (uc.remaining() >= slen) uc.skip(slen);
                                            frame.notes.push_back(
                                                "cleartext credential exchange: User Identity "
                                                "Negotiation type=2 (username+passcode) carries the "
                                                "passcode in the clear on the wire (username: \"" +
                                                ui.primary_field + "\")");
                                        }
                                        assoc.user_information.user_identity = ui;
                                        assoc.has_user_identity = true;
                                        break;
                                    }
                                    case 0x59: {
                                        DicomUserIdentityReply reply;
                                        if (sub.value.size() >= 2) {
                                            Cursor rc(sub.value);
                                            reply.server_response_length = rc.u16be();
                                        }
                                        assoc.user_information.user_identity_reply = reply;
                                        break;
                                    }
                                    default:
                                        break;  // 0x56/0x57 and anything else: structural-only
                                }
                            }
                            break;
                        }
                        default:
                            break;
                    }
                }

                if (assoc.is_request && !assoc.has_user_identity) {
                    frame.notes.push_back(
                        "no User Identity Negotiation item -- this association relies on AE-title "
                        "alone (unauthenticated trust)");
                }

                std::ostringstream s;
                s << (assoc.is_request ? "A-ASSOCIATE-RQ" : "A-ASSOCIATE-AC") << " (called=\""
                  << assoc.called_ae_title << "\", calling=\"" << assoc.calling_ae_title << "\")";
                frame.summary = s.str();
                frame.associate = std::move(assoc);
                break;
            }
            case 0x03: {
                if (body.size() < 4) {
                    frame.notes.push_back("A-ASSOCIATE-RJ too short for its fixed fields");
                    frame.summary = frame.pdu_type_name;
                    break;
                }
                Cursor bc(body);
                bc.u8();  // reserved
                DicomAssociateRj rj;
                rj.result_raw = bc.u8();
                rj.result_name = name_or_hex(dicom_rj_result_name(rj.result_raw), rj.result_raw);
                rj.source_raw = bc.u8();
                rj.source_name = name_or_hex(dicom_rj_source_name(rj.source_raw), rj.source_raw);
                rj.reason_raw = bc.u8();
                rj.reason_name = name_or_hex(dicom_rj_reason_name(rj.source_raw, rj.reason_raw),
                                              rj.reason_raw);
                frame.summary = "A-ASSOCIATE-RJ (result=" + rj.result_name +
                                 ", source=" + rj.source_name + ", reason=" + rj.reason_name + ")";
                frame.reject = std::move(rj);
                break;
            }
            case 0x07: {
                if (body.size() < 4) {
                    frame.notes.push_back("A-ABORT too short for its fixed fields");
                    frame.summary = frame.pdu_type_name;
                    break;
                }
                Cursor bc(body);
                bc.u8(); bc.u8();  // 2 reserved
                DicomAbort ab;
                ab.source_raw = bc.u8();
                ab.source_name = name_or_hex(dicom_abort_source_name(ab.source_raw), ab.source_raw);
                ab.reason_raw = bc.u8();
                std::ostringstream s;
                s << "A-ABORT (source=" << ab.source_name;
                if (ab.source_raw == 2) {
                    ab.reason_name =
                        name_or_hex(dicom_abort_reason_name(ab.reason_raw), ab.reason_raw);
                    s << ", reason=" << ab.reason_name;
                }
                s << ")";
                frame.summary = s.str();
                frame.abort = std::move(ab);
                break;
            }
            case 0x05:
            case 0x06:
                frame.summary = frame.pdu_type_name;
                break;
            case 0x04: {
                DicomPDataTf pdt;
                Cursor pc(body);
                while (pc.remaining() >= 6) {
                    uint32_t item_len = pc.u32be();
                    if (item_len < 2 || pc.remaining() < item_len) {
                        frame.notes.push_back(
                            "PDV item truncated or malformed -- stopping PDV parse for this PDU");
                        break;
                    }
                    DicomPdvInfo pdv;
                    pdv.item_length = item_len;
                    pdv.presentation_context_id = pc.u8();
                    pdv.message_control_header_raw = pc.u8();
                    pdv.is_command = (pdv.message_control_header_raw & 0x01) != 0;
                    pdv.is_last_fragment = (pdv.message_control_header_raw & 0x02) != 0;
                    pdv.data = pc.bytes(item_len - 2);
                    pdt.pdvs.push_back(pdv);
                }
                frame.summary = "P-DATA-TF: " + std::to_string(pdt.pdvs.size()) + " PDV(s)";
                frame.p_data = std::move(pdt);
                break;
            }
            default:
                break;
        }
        return frame;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

std::optional<size_t> dicom_tcp_declared_length(ByteSpan candidate) {
    if (candidate.empty()) return std::nullopt;
    uint8_t type_raw = candidate.at(0);
    if (type_raw < 0x01 || type_raw > 0x07) return std::nullopt;
    if (candidate.size() < 6) return candidate.size() + 1;  // two-phase, same shape
                                                               // amqp091_tcp_declared_length/
                                                               // ge_srtp_tcp_declared_length use
    try {
        Cursor c(candidate);
        c.u8();
        c.u8();
        uint32_t length = c.u32be();
        return static_cast<size_t>(length) + 6;
    } catch (const ParseError&) {
        return std::nullopt;
    }
}

// ---------------------------------------------------------------------------------------------
// Human-readable one-line renderings appended to DicomFrame::notes for text output -- see
// dicom.hpp's own STATEFULNESS section for the two-layer reassembly these are produced from.

namespace {

const char* status_class_name(DicomStatusClass c) {
    switch (c) {
        case DicomStatusClass::Success: return "Success";
        case DicomStatusClass::Pending: return "Pending";
        case DicomStatusClass::Warning: return "Warning";
        case DicomStatusClass::Failure: return "Failure";
        case DicomStatusClass::Cancel: return "Cancel";
    }
    return "Failure";
}

std::string describe_command_set(const DicomCommandSet& cs) {
    std::ostringstream s;
    s << "DIMSE Command: ";
    if (!cs.command_field_name.empty()) {
        s << cs.command_field_name;
    } else if (cs.command_field_raw) {
        s << hex_u16(*cs.command_field_raw);
    } else {
        s << "(no Command Field)";
    }
    std::vector<std::string> parts;
    if (cs.message_id) parts.push_back("message-id=" + std::to_string(*cs.message_id));
    if (cs.message_id_being_responded_to) {
        parts.push_back("message-id-being-responded-to=" +
                         std::to_string(*cs.message_id_being_responded_to));
    }
    if (cs.affected_sop_class_uid) {
        parts.push_back("affected-sop-class=" + sop_class_display(*cs.affected_sop_class_uid));
    }
    if (cs.requested_sop_class_uid) {
        parts.push_back("requested-sop-class=" + sop_class_display(*cs.requested_sop_class_uid));
    }
    if (cs.affected_sop_instance_uid) {
        parts.push_back("affected-sop-instance=" + *cs.affected_sop_instance_uid);
    }
    if (cs.status_raw) {
        std::string sn = cs.status_name.empty() ? hex_u16(*cs.status_raw) : cs.status_name;
        parts.push_back("status=" + sn + " (" + status_class_name(cs.status_class) + ")");
    }
    if (cs.remaining_suboperations) {
        parts.push_back("remaining=" + std::to_string(*cs.remaining_suboperations));
    }
    if (cs.completed_suboperations) {
        parts.push_back("completed=" + std::to_string(*cs.completed_suboperations));
    }
    if (cs.failed_suboperations) {
        parts.push_back("failed=" + std::to_string(*cs.failed_suboperations));
    }
    if (cs.warning_suboperations) {
        parts.push_back("warning=" + std::to_string(*cs.warning_suboperations));
    }
    if (!parts.empty()) {
        s << " (";
        for (size_t i = 0; i < parts.size(); ++i) {
            if (i) s << ", ";
            s << parts[i];
        }
        s << ")";
    }
    return s.str();
}

std::string describe_data_set(const DicomDataSet& ds) {
    std::ostringstream s;
    s << "Data Set: " << ds.elements.size() << " curated element(s)";
    if (!ds.elements.empty()) {
        s << ":";
        for (size_t i = 0; i < ds.elements.size(); ++i) {
            s << (i == 0 ? " " : ", ") << ds.elements[i].tag_name << "=" << ds.elements[i].rendered;
        }
    }
    return s.str();
}

// Both cross-packet layers this feature needs -- see dicom.hpp's own STATEFULNESS section.
// Mutates `frame` in place (fills in association-derived notes/content), reading and updating
// `ctx`'s own per-session/per-direction flow state.
void process_dicom_pdu_stateful(DicomFrame& frame, DecodeContext& ctx) {
    if (frame.associate) {
        DicomAssociationState& state = ctx.flow_state<DicomAssociationState>();
        const DicomAssociateRqAc& a = *frame.associate;
        if (a.is_request) {
            state.rq_seen = true;
            state.called_ae_title = a.called_ae_title;
            state.calling_ae_title = a.calling_ae_title;
            for (const auto& pcrq : a.presentation_contexts_rq) {
                auto& info = state.presentation_contexts[pcrq.id];
                info.abstract_syntax = pcrq.abstract_syntax;
                info.accepted = false;
                info.transfer_syntax.reset();
            }
        } else {
            state.ac_seen = true;
            for (const auto& pcac : a.presentation_contexts_ac) {
                auto& info = state.presentation_contexts[pcac.id];
                info.accepted = pcac.accepted;
                if (pcac.accepted) info.transfer_syntax = pcac.transfer_syntax;
            }
        }
        return;
    }

    if (!frame.p_data) return;

    DicomAssociationState& astate = ctx.flow_state<DicomAssociationState>();
    DicomPDataTf& pdt = *frame.p_data;

    bool all_known = !pdt.pdvs.empty();
    for (const auto& pdv : pdt.pdvs) {
        auto it = astate.presentation_contexts.find(pdv.presentation_context_id);
        if (it == astate.presentation_contexts.end()) {
            all_known = false;
            break;
        }
        if (!pdv.is_command && (!it->second.accepted || !it->second.transfer_syntax)) {
            all_known = false;
            break;
        }
    }
    pdt.association_captured = all_known;

    if (!all_known) {
        frame.notes.push_back("P-DATA-TF observed, " + std::to_string(pdt.pdvs.size()) +
                               " PDV(s), association context not captured on this session -- "
                               "cannot decode content");
        return;
    }

    DicomDimseReassemblyState& rstate =
        ctx.flow_state<DicomDimseReassemblyState>(FlowStateKeying::DirectionalFlow);
    const size_t kMaxBufferedBytes = resource_limits().max_reassembly_bytes.value_or(1 << 20);
    const size_t kMaxFragments = resource_limits().max_reassembly_segments.value_or(2000);

    for (const auto& pdv : pdt.pdvs) {
        if (pdv.is_command) {
            if (!rstate.command_in_progress) {
                rstate.command_in_progress = true;
                rstate.command_buffer.clear();
                rstate.command_pc_id = pdv.presentation_context_id;
                rstate.command_fragment_count = 0;
            }
            rstate.command_buffer.insert(rstate.command_buffer.end(), pdv.data.data(),
                                          pdv.data.data() + pdv.data.size());
            ++rstate.command_fragment_count;
            if (rstate.command_buffer.size() > kMaxBufferedBytes ||
                rstate.command_fragment_count > kMaxFragments) {
                frame.notes.push_back(
                    "DIMSE Command Set reassembly on this TCP flow exceeded its safety cap (" +
                    std::to_string(rstate.command_buffer.size()) + " byte(s) across " +
                    std::to_string(rstate.command_fragment_count) + " fragment(s)) -- abandoning it");
                rstate.command_in_progress = false;
                rstate.command_buffer.clear();
                rstate.command_fragment_count = 0;
                continue;
            }
            if (pdv.is_last_fragment) {
                ByteSpan complete(rstate.command_buffer.data(), rstate.command_buffer.size());
                DicomCommandSet cs = decode_dicom_command_set(complete);
                if (rstate.command_fragment_count > 1) {
                    frame.notes.push_back(
                        "DIMSE Command Set reassembled from " +
                        std::to_string(rstate.command_buffer.size()) + " byte(s) across " +
                        std::to_string(rstate.command_fragment_count) + " PDV fragment(s)");
                }
                frame.p_data->command_set = std::move(cs);
                rstate.command_in_progress = false;
                rstate.command_buffer.clear();
                rstate.command_fragment_count = 0;
            }
        } else {
            if (!rstate.data_in_progress) {
                rstate.data_in_progress = true;
                rstate.data_buffer.clear();
                rstate.data_pc_id = pdv.presentation_context_id;
                rstate.data_fragment_count = 0;
            }
            rstate.data_buffer.insert(rstate.data_buffer.end(), pdv.data.data(),
                                       pdv.data.data() + pdv.data.size());
            ++rstate.data_fragment_count;
            if (rstate.data_buffer.size() > kMaxBufferedBytes ||
                rstate.data_fragment_count > kMaxFragments) {
                frame.notes.push_back(
                    "DIMSE Data Set reassembly on this TCP flow exceeded its safety cap (" +
                    std::to_string(rstate.data_buffer.size()) + " byte(s) across " +
                    std::to_string(rstate.data_fragment_count) + " fragment(s)) -- abandoning it");
                rstate.data_in_progress = false;
                rstate.data_buffer.clear();
                rstate.data_fragment_count = 0;
                continue;
            }
            if (pdv.is_last_fragment) {
                bool explicit_vr = false;
                bool big_endian = false;
                auto it = astate.presentation_contexts.find(rstate.data_pc_id);
                if (it != astate.presentation_contexts.end() && it->second.transfer_syntax) {
                    const std::string& uid = it->second.transfer_syntax->uid;
                    explicit_vr = (uid != "1.2.840.10008.1.2");
                    big_endian = (uid == "1.2.840.10008.1.2.2");
                }
                ByteSpan complete(rstate.data_buffer.data(), rstate.data_buffer.size());
                DicomDataSet ds =
                    decode_dicom_data_set(complete, explicit_vr, big_endian, ctx.redact_secrets);
                if (rstate.data_fragment_count > 1) {
                    frame.notes.push_back(
                        "DIMSE Data Set reassembled from " + std::to_string(rstate.data_buffer.size()) +
                        " byte(s) across " + std::to_string(rstate.data_fragment_count) +
                        " PDV fragment(s)");
                }
                if (ds.stopped_reason) frame.notes.push_back(*ds.stopped_reason);
                frame.p_data->data_set = std::move(ds);
                rstate.data_in_progress = false;
                rstate.data_buffer.clear();
                rstate.data_fragment_count = 0;
            }
        }
    }

    if (frame.p_data->command_set) {
        frame.notes.push_back(describe_command_set(*frame.p_data->command_set));
    }
    if (frame.p_data->data_set) {
        frame.notes.push_back(describe_data_set(*frame.p_data->data_set));
    }
}

}  // namespace

std::optional<ProtocolResult> DicomDecoder::decode(ByteSpan payload, DecodeContext& ctx) const {
    auto first = try_parse_dicom_pdu(payload);
    if (!first) return std::nullopt;

    DicomResult result;
    result.first = *first;
    process_dicom_pdu_stateful(result.first, ctx);
    result.summary = result.first.summary;
    for (const auto& n : result.first.notes) result.notes.push_back(n);

    // Coalescing loop -- multiple PDUs (especially back-to-back P-DATA-TF) very often arrive in one
    // TCP payload, the same MqttResult/Amqp091Result shape mqtt.hpp/amqp091.hpp already establish.
    const size_t kMax = resource_limits().max_coalesced_messages.value_or(50);
    size_t offset = first->wire_length;
    size_t count = 1;
    while (offset < payload.size() && count < kMax && !first->truncated) {
        ByteSpan rest = payload.from(offset);
        auto next = try_parse_dicom_pdu(rest);
        if (!next) break;
        DicomFrame next_frame = *next;
        process_dicom_pdu_stateful(next_frame, ctx);
        ++count;
        result.notes.push_back("additional DICOM PDU " + std::to_string(count) +
                                " found in the same TCP payload at byte offset " +
                                std::to_string(offset) + " (coalesced by the sender/OS): " +
                                next_frame.summary);
        for (const auto& n : next_frame.notes) result.notes.push_back(n);
        offset += next_frame.wire_length;
        if (next_frame.truncated) break;
    }
    if (count >= kMax) {
        result.notes.push_back("stopped after " + std::to_string(kMax) +
                                " DICOM PDU(s) in this one TCP payload, more may remain (safety cap)");
    }

    return ProtocolResult::make<DicomResult>("dicom", std::move(result));
}

const ProtocolDecoder& dicom_tcp_decoder() {
    static const DicomDecoder instance;
    return instance;
}

}  // namespace conduitscope
