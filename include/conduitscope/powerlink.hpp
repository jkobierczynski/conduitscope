// SPDX-License-Identifier: Apache-2.0
// powerlink.hpp -- Ethernet POWERLINK (EPL, EtherType 0x88AB) decoding: the common MessageType/
// Destination/Source header every EPL frame shares, and, per message type, SoC/PReq/PRes/SoA
// fields, ASnd's five named service payloads (IdentResponse/StatusResponse/NMTRequest/NMTCommand/
// SDO), and AInv (Asynchronous Invite, a rarer ASnd-service-carrying frame). Also covers the
// standalone SDO-over-UDP variant (UDP port 3819) -- see "UDP:3819 SDO variant" below for why that
// is NOT a separate, stripped-down Sequence+Command-Layer-only parser but literally the same frame
// shape this file already decodes, reached through the same try_parse_powerlink entry point.
//
// Like PROFINET RT, EtherCAT, and IEC 61850 GOOSE/SV, POWERLINK rides directly on raw Ethernet for
// its cyclic real-time traffic -- there is no IPv4/UDP/TCP layer at all for that path (see
// link_layer.hpp's ETHERTYPE_* constants). POWERLINK is "CANopen over Ethernet": its SDO (Service
// Data Object) Sequence+Command Layer reuses CANopen's (CiA 301) numeric SDO Abort Code space
// verbatim (confirmed byte-for-byte against canopen.hpp/canopen.cpp's own curated table below), and
// like this codebase's existing CANopen decoder, POWERLINK's Object Dictionary values (the actual
// Data bytes an SDO WriteByIndex/ReadByIndex carries) are shown only as raw hex -- there is no
// XDD/EDS device-profile machinery here to interpret them, the same scope decision canopen.hpp
// documents for its own PDO/SDO data (see that file's "Out of scope" section) and CANopen's own
// upstream Wireshark dissector's `object_lookup`/EDS-file machinery, which this port deliberately
// does not replicate.
//
// SOURCING: every byte offset, bit mask, and named enum value below is cross-checked directly
// against Wireshark's own `epan/dissectors/packet-epl.c` (fetched in full from
// raw.githubusercontent.com/wireshark/wireshark/master during this task's own research phase --
// itself sourced from the EPSG (Ethernet POWERLINK Standardization Group) DS301 Communication
// Profile Specification, credited in that file's own header), not from the EPSG PDF spec directly
// (network access to that PDF was not available in this environment) -- the same "Wireshark
// dissector as primary source when the vendor/SDO spec PDF itself can't be fetched" posture this
// codebase already used for BSAP (see bsap.hpp) and, partially, EtherCAT (see ethercat.hpp).
// Because the actual dissector source (not a summary) was read line-by-line for every field this
// file decodes, confidence here is HIGH relative to this codebase's usual "Wireshark source assumed
// but not independently re-derived" caveat -- but it is still one source, not cross-checked against
// a second independent implementation or a real capture (no real POWERLINK pcap was available during
// this task), so genuinely obscure/rare paths (AInv's UnspecifiedInvite sub-shape, NMTDNA's full
// field breakdown, StatusResponse's ErrorCodeList entries) are decoded more conservatively -- named/
// structural, not exhaustively value-decoded -- exactly where the dissector source itself does
// little beyond raw field extraction.
//
// ONE CONFIRMED CORRECTION TO THIS TASK'S OWN BRIEFING, found only by reading the source: MessageType
// (byte 0) carries NO reserved top bit in the reference dissector -- `hf_epl_mtyp` is read and
// compared as a full, unmasked byte (`mtyp_vals[]` matches 0x01/0x03/0x04/0x05/0x06/0x07/0x0D
// exactly, nothing masks off bit 7 anywhere in `dissect_eplpdu`). This file therefore treats the
// WHOLE byte as MessageType, not `byte0 & 0x7F` -- the task's own "bit 7 reserved/unused" premise is
// NOT borne out by the reference implementation and is not applied here. If a real capture is later
// found with bit 7 set on an otherwise-valid frame, that would show up simply as an "unrecognized
// message type 0x8N" report (see kMessageTypeUnknown below) -- never silently masked away.
//
// MessageType values (`EPL_SOC`/`EPL_PREQ`/.../`mtyp_vals`, packet-epl.c lines ~154-171): SoC=0x01,
// PReq=0x03, PRes=0x04, SoA=0x05, ASnd=0x06, AMNI=0x07 (ActiveManagingNodeIndication -- per the
// reference dissector's own comment, "Currently all fields in the AMNI frame are reserved", so this
// decoder names it and decodes nothing further, matching that source exactly), AInv=0x0D
// (Asynchronous Invite -- CONFIRMED at this exact value directly from source, resolving the task's
// own flagged uncertainty about it). 0x02 has no entry in `mtyp_vals` at all -- neither this decoder
// nor the reference dissector assigns it any name; it falls through to the generic "unrecognized
// message type" path below, exactly like every other value not in the list above (0x00, 0x06's
// neighbors, 0x08-0x0C, 0x0E-0xFF) -- never guessed at.
//
// Common header (every message type, EPL_MTYP_OFFSET/EPL_DEST_OFFSET/EPL_SRC_OFFSET == 0/1/2):
// MessageType(1) + Destination NodeID(1) + Source NodeID(1). Node ID conventions (`addr_str_vals`,
// EPL_*_NODEID): 0 = dynamically assigned, 240 (0xF0) = the Managing Node (MN) -- EPL_MN_NODEID --
// 253 = Diagnostic Device, 254 = "to legacy Ethernet Router", 255 (0xFF) = broadcast. A Controlled
// Node (CN) is any value 1-239.
//
// UDP:3819 SDO variant -- ARCHITECTURE NOTE: the reference dissector's own `dissect_epludp` (the
// UDP/3819 entry point) calls the EXACT SAME core dissection function (`dissect_eplpdu`) the raw-
// Ethernet path uses, with one cosmetic-only difference: the Destination/Source NodeID bytes are
// still consumed (`offset += 2`) but not rendered as separate tree fields when running over UDP.
// This means a UDP:3819 POWERLINK frame is NOT a bare Sequence+Command-Layer-only payload -- it is
// the SAME MessageType+Destination+Source+body shape this file already decodes end to end (in
// practice, almost always an ASnd frame with ServiceID==SDO, used for non-cyclic/out-of-band SDO
// access outside the realtime cyclic frame -- but the UDP path does not itself require that; any
// EPL message type is structurally valid over UDP too, matching the reference dissector's own
// unconditional call). This file's shared entry point, try_parse_powerlink, is therefore reused
// UNCHANGED for both gates -- PowerlinkDecoder (EtherType 0x88AB) and PowerlinkSdoUdpDecoder (UDP
// port 3819) each call it directly on their own payload, with ZERO duplicated Sequence/Command-Layer
// decode logic between them, exactly as this task's own brief asked for.
//
// SDO Sequence Layer (4 bytes, immediately after ASnd's own 1-byte ServiceID, or AInv's own 1-byte
// ServiceID at the same relative offset -- `EPL_ASND_SDO_SEQ_RECEIVE_SEQUENCE_NUMBER_OFFSET`/
// `..SEND_SEQUENCE_NUMBER_OFFSET` == 4/5 in the full-frame absolute offset space, confirmed against
// `dissect_epl_sdo_sequence`'s own byte-by-byte offset arithmetic): byte0 = ReceiveSequenceNumber
// (top 6 bits, `>> EPL_ASND_SDO_SEQ_MASK` i.e. `>> 2`) + ReceiveCon (bottom 2 bits, `EPL_ASND_SDO_
// SEQ_CON_MASK` == 0x03); byte1 = SendSequenceNumber (top 6 bits) + SendCon (bottom 2 bits, same
// masks); bytes 2-3 = reserved/unused (read by neither `dissect_epl_sdo_sequence` nor any other
// function -- the dissector's own grouping tree node spans 5 bytes for cosmetic reasons, but the
// actual byte consumption, confirmed by tracing `offset`'s value across the function, is exactly 4).
// Con values (0-3, `epl_sdo_receive_con_vals`/`epl_sdo_send_con_vals`, identical value space for
// both Receive/Send): 0 No connection, 1 Initialization, 2 Connection valid, 3 Error Response
// (Receive side) / Connection valid with acknowledge request (Send side, same numeric value, an
// intentionally direction-dependent meaning the reference source itself documents this way).
//
// SDO Command Layer (immediately after the Sequence Layer, i.e. absolute offset 8 for an ASnd/AInv
// frame; confirmed directly from `dissect_epl_sdo_command`'s own `offset` arithmetic, traced
// instruction by instruction): the FIRST byte after the Sequence Layer is itself reserved/unused
// (the function's very first statement is `offset += 1;`, before anything is read -- this decoder
// preserves that exactly, rather than guessing it means something) -- then TransactionID(1) +
// Flags(1: bit7 Response `EPL_ASND_SDO_CMD_RESPONSE_FILTER`==0x80, bit6 Abort `..ABORT_FILTER`==
// 0x40, bits5-4 Segmentation `..SEGMENTATION_FILTER`==0x30 [0 Expedited, 1 Initiate, 2 Segment, 3
// Transfer Complete], bits3-0 unused) + CommandID(1) + SegmentSize(2, LE) + 2 more reserved/unused
// bytes (the segment-size field is read as 2 bytes but the offset advances by 4, confirmed the same
// way) -- 8 bytes total from the byte right after the Sequence Layer to the first byte of whatever
// command-specific content follows. CommandID values (`EPL_ASND_SDO_COMMAND_*`, every one the
// reference source defines): WriteByIndex=0x01, ReadByIndex=0x02, WriteAllByIndex=0x03,
// ReadAllByIndex=0x04, WriteByName=0x05, ReadByName=0x06, FileWrite=0x20, FileRead=0x21,
// WriteMultipleParameterByIndex=0x31, ReadMultipleParameterByIndex=0x32, MaximumSegmentSize=0x70,
// LinkNameToIndex=0x71 -- NOTE these numeric values are POWERLINK-specific and differ from
// canopen.hpp's own CANopen CiA 301 SDO command-specifier space (a 3-bit ccs/scs field, not a full
// byte CommandID) -- the two protocols' SDO framing is NOT wire-identical beyond sharing the Abort
// Code number space, so this file's CommandID table is its own, not borrowed from canopen.hpp.
// WriteByIndex/ReadByIndex are decoded in full (see below); every other CommandID is named only
// (CommandID + whatever bytes remain shown as raw hex), matching this task's own stated scope.
//
// WriteByIndex/ReadByIndex payload shape (Expedited [segmentation==0] or Initiate [==1] only --
// Segment [==2]/Transfer Complete [==3] continuation frames carry NO Index/SubIndex at all, only
// continuation data, confirmed by `dissect_epl_sdo_command_write_by_index`'s own segmentation-value
// branch structure): for Initiate, a 4-byte little-endian DataSize precedes Index/SubIndex (the
// total, cross-frame transfer size -- NOT this frame's own data length, which remains SegmentSize).
// Then Index(2, LE) + SubIndex(1) -- and here the two commands genuinely diverge, confirmed by
// tracing each dissector function's own `offset` arithmetic separately: WriteByIndex's own request
// path advances `offset` by 2 after reading the 1-byte SubIndex (i.e. one padding/reserved byte
// after SubIndex, word-aligning Index+SubIndex+pad to 4 bytes -- the same DCP/CANopen-style
// alignment pattern profinet.hpp/canopen.hpp already document elsewhere in this codebase), while
// ReadByIndex's own request path advances `offset` by only 1 (no padding byte at all). This decoder
// preserves that asymmetry exactly rather than assuming symmetry between the two commands. Whatever
// bytes remain after Index/SubIndex(+pad, for WriteByIndex) are the Data field -- opaque, raw hex
// only, never semantically interpreted (see this file's own header comment's Object Dictionary
// scope note above). A Segment/Transfer-Complete continuation frame (segmentation 2/3) carries only
// continuation Data, no Index/SubIndex of its own -- this decoder does not attempt cross-frame
// reassembly of a segmented SDO transfer's full value, the same "no cross-packet SDO session
// tracking" scope boundary canopen.hpp already documents for its own segmented/block transfers.
//
// Abort Transfer (the Abort flag bit set, regardless of CommandID): a 4-byte little-endian Abort
// Code follows the 8-byte Command Layer header directly (no Index/SubIndex read for the ordinary
// single-abort case this decoder handles -- WriteMultipleParameterByIndex's own multi-abort-code
// response shape, one abort code per failed sub-transfer, is named/counted but not walked entry by
// entry, a deliberate scope cut given how rare that specific command is). The Abort Code's numeric
// space is CONFIRMED identical to CANopen's own (canopen.hpp/canopen.cpp) -- packet-epl.c's own
// `sdo_cmd_abort_code[]` table and canopen.cpp's own `sdo_abort_code_name` table were compared
// value-by-value during this task's research and use the exact same 32-bit codes (0x05030000,
// 0x05040000, 0x06010000, 0x06020000, 0x08000000, etc.) -- this file therefore calls canopen.hpp's
// now-shared `canopen_sdo_abort_code_name` free function (exposed from canopen.cpp specifically for
// this reuse -- see that file's own comment on it) rather than maintaining a second, duplicate copy
// of the same table, per this task's own "prefer sharing if easy and low-risk" guidance.
//
// SoC (Start of Cyclic, byte 0 immediately after the 3-byte common header -- confirmed against
// `dissect_epl_soc`): 1 reserved/unused byte, then Flags(1: bit7 MC "Multiplexed Cycle Completed"
// `EPL_SOC_MC_MASK`==0x80, bit6 PS "Prescaled Slot" `EPL_SOC_PS_MASK`==0x40, bit3 AN(Global)
// `EPL_SOC_AN_MASK`==0x08 -- part of POWERLINK's Dynamic Node Allocation mechanism, named "AN
// (Global)" in the reference source's own field label; no further semantics decoded here, matching
// this file's own "named, not over-asserted" posture for DNA-related bits generally), 1 more
// reserved/unused byte, NetTime(8, LE, `ENC_TIME_SECS_NSECS` -- 4-byte seconds + 4-byte nanoseconds,
// shown here as raw hex rather than reconstructed into a synthesized timestamp value, the same
// "component fields shown, not a derived epoch value invented" posture canopen.hpp's own TIME STAMP
// handling already established), RelativeTime(8, LE, same raw-hex posture).
//
// PReq (Poll Request, MN->CN): 1 reserved byte, Flags(1: bit4 MS "Multiplexed Slot"==0x20, bit2 EA
// "Exception Acknowledge"==`EPL_PDO_EA_MASK`(0x04), bit0 RD "Ready"==`EPL_PDO_RD_MASK`(0x01)),
// FLS/SLS(1: bit7 FLS "First Link Status"==0x80, bit6 SLS "Second Link Status"==0x40 -- cable-
// redundancy link-state bits), PDOVersion(1) + 1 reserved byte, Size(2, LE, the Payload's own byte
// length), Payload (opaque process-data bytes, never value-decoded -- this codebase has no XDD/EDS
// device-description machinery, the same posture profinet.hpp's own cyclic RT IO data and
// ethercat.hpp's own Data field already establish for their respective protocols).
//
// PRes (Poll Response, CN->MN or MN->MN): NMTStatus(1, see the NMT state table below -- the
// reference dissector picks the CN or MN value_string table by comparing the FRAME'S OWN SOURCE
// PORT against `EPL_MN_NODEID` (240) when running over UDP; this decoder instead compares the
// frame's own Source NodeID field directly, the equivalent signal for the raw-Ethernet path this
// file is primarily built for -- see NMT state section below), Flags(1: bit5 MS==0x20, bit4 EN
// "Exception New"==`EPL_PDO_EN_MASK`(0x10), bit0 RD==0x01), FLS/SLS/PR/RS(1: bit7 FLS==0x80, bit6
// SLS==0x40, bits5-3 PR "Priority" 0-7==`EPL_PDO_PR_MASK`(0x38), bits2-0 RS "RequestToSend" 0-7==
// `EPL_PDO_RS_MASK`(0x07)), PDOVersion(1) + 1 reserved byte, Size(2, LE), Payload (opaque, same
// posture as PReq above).
//
// SoA (Start of Asynchronous, MN only): NMTStatus(1, the MN's own state) + 1 reserved byte, then a
// Flags/RequestedServiceID lookahead byte pair (EA "Exception Acknowledge"==`EPL_SOA_EA_MASK`(0x04),
// ER "Exception Reset"==`EPL_SOA_ER_MASK`(0x02), plus AN(Global)==0x08 and, only when
// RequestedServiceID==IdentRequest, AN(Local)==0x10 -- both DNA-related, named only, same posture as
// SoC's own AN bit) + 1 reserved byte, RequestedServiceID(1, see the table below), RequestedService
// Target(1, a NodeID), EPLVersion(1, BCD-nibble-encoded major.minor per the reference source's own
// `elp_version` custom formatter -- shown here as the two raw nibbles), RedundancyFlags(1: bit0 MR
// "MN Redundancy"==0x01, bit1 CR "Cable Redundancy"==0x02, bit2 RR "Ring Redundancy"==0x04, bit3
// "Ring Status" (open/closed)==0x08). RequestedServiceID values (`soa_svid_vals`/`EPL_SOA_*`, a
// DIFFERENT numeric space from ASnd's own ServiceID below despite some overlapping small integers --
// confirmed by reading both tables directly, not assumed to be "the same enum" as this task's own
// initial framing suggested): NoService=0, IdentRequest=1, StatusRequest=2, NMTRequestInvite=3,
// (4-5 reserved), SyncRequest=6, (7-0x9F reserved), (0xA0-0xFE Manufacturer Specific),
// UnspecifiedInvite=255. SyncRequest's own extended SyncControl/PRes-timing sub-fields (30 further
// bytes, cross-redundancy timing configuration) are recognized (RequestedServiceID named) but not
// decoded field-by-field -- a deliberate scope cut, this being a rare, deployment-specific
// configuration message with no OT-security-relevant content of its own.
//
// ASnd (Asynchronous Send): ServiceID(1, see the table below -- note this is genuinely DIFFERENT
// from SoA's own RequestedServiceID number space just above, despite superficial similarity),
// then a service-specific payload starting at the same relative offset AInv's own embedded ASnd-
// style body uses (see AInv below) -- IdentResponse/StatusResponse/NMTRequest/NMTCommand/SDO/
// SyncResponse(named-only)/anything else (named "ServiceID 0xNN (unrecognized/vendor-specific)",
// raw hex). ServiceID values (`asnd_svid_vals`/`EPL_ASND_*`): Reserved=0, IdentResponse=1,
// StatusResponse=2, NMTRequest=3, NMTCommand=4, SDO=5, SyncResponse=6, (7-0x9F reserved), (0xA0-0xFE
// Manufacturer Specific), 0xFF reserved.
//
// IdentResponse -- EVERY field below decoded at its own confirmed byte offset (traced field-by-
// field through `dissect_epl_asnd_ires`; relative to the byte immediately after ASnd's own 1-byte
// ServiceID, called D below): EN/EC flags(1)@D [bit4 EN "Exception New"==0x10, bit3 EC "Exception
// Clear"==0x08 -- same masks PRes/StatusResponse's own EN/EC-shaped bits use], FLS/SLS/PR/RS(1)@D+1
// [same bit layout as PRes's own second flags byte], NMTStatus(1)@D+2 + 1 reserved byte, EPLVersion
// (1)@D+4 + 1 reserved byte, FeatureFlags(4, LE)@D+6 [shown as a raw 32-bit hex value -- the
// reference source itself decodes 23 individual named bits here, none of which this codebase's
// existing OT-inventory-focused decoders (profinet.hpp's DCP, canopen.hpp) have a precedent for
// value-decoding at this granularity; matches this codebase's "curated depth, not exhaustive" scope
// posture rather than porting all 23], MTU(2, LE)@D+10, PollInSize(2, LE)@D+12, PollOutSize(2, LE)
// @D+14, ResponseTime(4, LE, microseconds)@D+16 + 2 reserved bytes, DeviceType(2, LE)@D+22 +
// DeviceTypeAdditionalInfo(2, LE)@D+24, VendorID(4, LE)@D+26, ProductCode(4, LE)@D+30,
// RevisionNumber(4, LE)@D+34, SerialNumber(4, LE)@D+38, VendorSpecificExtension1(8, LE, raw)@D+42,
// VerifyConfigurationDate(4, LE)@D+50, VerifyConfigurationTime(4, LE)@D+54, ApplicationSwDate(4, LE)
// @D+58, ApplicationSwTime(4, LE)@D+62, IPAddress(4, `tvb_get_ntohl` -- i.e. ordinary network/big-
// endian dotted-quad, UNLIKE every other multi-byte field in this frame, which is little-endian; the
// reference source is explicit about this asymmetry via its own separate `ENC_NA`+`tvb_get_ntohl`
// call, not a copy-paste oversight)@D+66, SubnetMask(4, same big-endian convention)@D+70,
// DefaultGateway(4, same)@D+74, HostName(32, ASCII, NUL-padded)@D+78, VendorSpecificExtension2(48,
// raw)@D+110. Total 158 bytes from D. Given the field-by-field confirmation above, this is decoded
// with HIGH confidence, not the "approximate/best-effort" posture this task's own brief anticipated
// might be needed.
//
// StatusResponse -- also traced field-by-field (`dissect_epl_asnd_sres`, offsets relative to D as
// above): EN/EC(1)@D, FLS/SLS/PR/RS(1)@D+1, NMTStatus(1)@D+2 + 3 reserved bytes, then an 8-byte
// "StaticErrorBitfield" region@D+6: byte0 = an error-register-shaped bitmask (bits 0,1,2,3,4,5,7
// named by the reference source with generic field names this decoder maps onto CANopen's own,
// semantically-equivalent Error Register bit names for readability -- CiA 301's Error Register IS
// what POWERLINK's own StaticErrorBitfield first byte represents, per the shared CANopen heritage
// this file's own header already establishes; bit 6 is not named by the reference source either),
// 1 reserved byte, then 6 bytes of device-specific error data (raw hex, no further structure). Then
// an ErrorCodeList@D+14: `(remaining bytes) / 20` entries, each 20 bytes -- EntryType(2, LE, a
// bitfield: bits0-13 Profile number, bit14/bit15 named-but-not-further-decoded flags -- shown as raw
// hex), ErrorCode(2, LE), TimeStamp(8, LE, same SECS_NSECS shape as SoC's own NetTime -- raw hex,
// not reconstructed), AddInfo(8, LE, raw hex). Bounded by this codebase's own
// `resource_limits().max_decoded_objects` safety cap (see decode_error_code_list in powerlink.cpp),
// the same pattern ethercat.hpp's own datagram-chain cap and canopen.hpp's own bounded decodes use.
//
// NMTRequest (ASnd ServiceID==3): RequestedCommandID(1)@D, RequestedCommandTarget(1)@D+1 (a NodeID
// -- CONFIRMED present and named exactly "NMTRequestedCommandTarget" in the reference source's own
// field table, resolving this task's own uncertainty about whether this field exists),
// RequestedCommandData(rest of the frame, opaque, raw hex)@D+2.
//
// NMTCommand (ASnd ServiceID==4): NMTCommandID(1)@D + 1 reserved byte, then command-specific data@
// D+2 (see the NMT Command ID table below for which of the ~29 named values get further field-level
// decode -- NMTNetHostNameSet's 32-byte ASCII hostname, NMTFlushArpEntry's 1-byte target NodeID,
// NMTPublishTime's 6-byte raw timestamp, and NMTResetNode's optional 2-byte little-endian reason
// code are all decoded; NMTDNA -- Dynamic Node Allocation, a 27-byte structure the reference source
// itself decodes field-by-field -- is recognized and its own fixed 27-byte region is shown as raw
// hex rather than individually broken out, a deliberate scope cut given how rarely this command
// appears in practice; every other named command's own data, and any unrecognized CommandID's data,
// is shown as raw hex). This frame's own top-level Destination NodeID field (the common header's own
// byte 1) IS the command's target -- there is no separate "NMTCommandTarget" field inside the
// NMTCommand payload itself, confirmed by the absence of any such field in `dissect_epl_asnd_nmtcmd`
// (unlike NMTRequest, which does carry its own explicit target byte, see above); this decoder
// therefore reads the target off PowerlinkFrame::dst_node_id directly rather than inventing a
// duplicate field.
//
// AInv (Asynchronous Invite, MessageType==0x0D): a rarer variant that carries an SoA-shaped header
// (NMTStatus(1) + 1 reserved byte, then EA/ER flags(1)) followed by an ASnd-style ServiceID(1) and
// then the EXACT SAME service-specific body ASnd's own five decoded ServiceIDs use, at the same D
// offset (confirmed via `dissect_epl_ainv`'s own identical switch/case dispatch into
// `dissect_epl_asnd_ires`/`_sres`/`_nmtreq`/`_nmtcmd`/`dissect_epl_asnd_sdo`) -- this decoder
// therefore shares its own ASnd-service-body decode function between the two message types rather
// than duplicating it, the same "one decode path, two call sites" shape this file's own UDP:3819
// architecture note above already establishes for the Sequence+Command Layer. AInv's own
// UnspecifiedInvite sub-case (RequestedServiceTarget + EPLVersion, no further body) is named/
// structural only.
//
// NMT state values -- CN and MN share the exact same 10 wire values (confirmed: `EPL_NMT_GS_OFF`/
// `_INITIALIZING`/`_RESET_APPLICATION`/`_RESET_COMMUNICATION` are IDENTICAL constants reused
// verbatim in both `epl_nmt_cs_vals`/`epl_nmt_ms_vals`), but the reference source gives CN and MN
// each their own separate, differently-prefixed name for the remaining 6 values that DO differ
// between the two roles -- this decoder follows that exact convention: shared "NMT_GS_" prefix for
// the four generic/reset states, "NMT_CS_" for a Controlled Node's own PreOperational1/
// PreOperational2/ReadyToOperate/Operational/Stopped/BasicEthernet, "NMT_MS_" for a Managing Node's
// same six states (see powerlink.cpp's nmt_state_name for the exact wire values -- Off=0x00,
// Initialising=0x19, ResetApplication=0x29, ResetCommunication=0x39, then CS/MS-prefixed
// NotActive=0x1C, PreOperational1=0x1D, PreOperational2=0x5D, ReadyToOperate=0x6D, Operational=0xFD,
// Stopped=0x4D, BasicEthernet=0x1E). NOTE: the reference source has NO separate wire value for a
// "ResetConfiguration" state at all -- only the four generic reset states above exist on the wire
// (this mirrors CiA 301's own NMT state machine, where "reset configuration" is a COMMAND, not a
// distinct state CNs/MNs ever report themselves as being in) -- this decoder therefore does NOT
// invent a NMT_GS_RESET_CONFIGURATION wire value the task's own briefing mentioned, since no source
// (Wireshark's own dissector included) confirms one exists; an unrecognized NMTStatus byte falls
// back to "NMT state 0xNN (unrecognized)" rather than guessing, the same defensive-fallback posture
// this codebase's every other enumerated-byte field already uses.
//
// NMT Command ID table (ASnd ServiceID==4, `EPL_ASND_NMTCOMMAND_*`/`asnd_cid_vals`) -- every value
// the reference source defines, 29 in total: NMTStartNode=0x21, NMTStopNode=0x22,
// NMTEnterPreOperational2=0x23, NMTEnableReadyToOperate=0x24, NMTResetNode=0x28,
// NMTResetCommunication=0x29, NMTResetConfiguration=0x2A, NMTSwReset=0x2B, NMTDNA=0x2D,
// NMTStartNodeEx=0x41, NMTStopNodeEx=0x42, NMTEnterPreOperational2Ex=0x43,
// NMTEnableReadyToOperateEx=0x44, NMTResetNodeEx=0x48, NMTResetCommunicationEx=0x49 (named
// "NMTCommunicationEx" in the reference source's own table -- reproduced verbatim, not "corrected",
// in case that exact string is relied on elsewhere), NMTResetConfigurationEx=0x4A,
// NMTSwResetEx=0x4B, NMTNetHostNameSet=0x62, NMTFlushArpEntry=0x63, NMTPublishConfiguredNodes=0x80
// (named "NMTPublishConfiguredNodes" in the reference source -- this task's own briefing called it
// "NMTPublishConfiguredCN", reproduced here as the source actually spells it), NMTPublishActiveNodes
// =0x90, NMTPublishPreOperational1=0x91, NMTPublishPreOperational2=0x92,
// NMTPublishReadyToOperate=0x93, NMTPublishOperational=0x94, NMTPublishStopped=0x95,
// NMTPublishEmergencyNew=0xA0, NMTPublishTime=0xB0, NMTInvalidService=0xFF. Any other byte value is
// rendered "NMT command 0xNN (unrecognized)", never guessed at.
//
// CURATED FINDINGS (see output.cpp/output.hpp): (1) an NMTCommand (NMTResetNode/NMTStopNode/
// NMTResetCommunication/NMTResetConfiguration/NMTSwReset and their _Ex variants) targeting a NodeID
// this decoder has separately observed reporting NMTStatus NMT_CS_OPERATIONAL/NMT_MS_OPERATIONAL in
// an earlier PRes/StatusResponse/SoA on the SAME capture -- a plausible disruption signature (an
// Operational node being knocked out of service); (2) rogue-MN / MN-identity tracking: (source MAC,
// source NodeID) pairs observed sourcing SoC/PReq/SoA (MN-only message types per the POWERLINK spec
// -- a CN never sends any of these three), flagged when more than one distinct identity is seen on
// one capture; (3) SDO WriteByIndex operations observed -- a straightforward count, the same
// "surface every write" posture this task's own brief asked for (CANopen's own decoder, canopen.hpp,
// does NOT currently have a dedicated SDO-write --stats counter of its own to mirror -- this finding
// was designed fresh for POWERLINK, not ported from an existing one); (4) a CN sourcing an ASnd/
// NMTCommand (ServiceID==4) --
// only the MN should ever issue NMTCommand, so a non-MN NodeID (per EPL_IS_CN_NODEID, i.e. strictly
// between 0 and 240) doing so is anomalous.
//
// Out of scope for this first pass, matching this codebase's own "recognized but not this release's
// problem" posture: Object Dictionary interpretation of Payload/SDO Data content (see this file's
// own header comment's opening paragraph); cross-frame SDO segmented-transfer reassembly (Segment/
// Transfer-Complete continuation frames are decoded as opaque continuation data, not stitched back
// together into the larger value being transferred -- the same scope boundary canopen.hpp's own SDO
// segmented/block transfer handling already documents); SoA's own SyncRequest sub-fields beyond
// naming the RequestedServiceID; NMTDNA's own 27-byte structure beyond recognizing it and showing it
// as raw hex; WriteMultipleParameterByIndex's own multiple-abort-code response walking (named,
// count of remaining bytes shown, not walked entry by entry); FeatureFlags' own 23 named bits (shown
// as one raw 32-bit value); IdentResponse's DeviceType-to-profile-name lookup (the reference source
// cross-references a small `epl_device_profiles` table -- Generic I/O/Drive/HMI/Measuring/PLC/
// Encoder -- this decoder shows the raw DeviceType value only, since profile-name lookup is exactly
// the kind of device-description enrichment this codebase's "no XDD/EDS, opaque OD values" scope
// decision already excludes elsewhere).
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/link_layer.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

constexpr uint16_t POWERLINK_SDO_UDP_PORT = 3819;  // UDP_PORT_EPL in the reference source

// One decoded SDO Sequence Layer + Command Layer pair -- shared, byte-identical decode used by
// ASnd/SDO, AInv/SDO, and the standalone UDP:3819 path. See this file's header comment's "SDO
// Sequence Layer"/"SDO Command Layer" sections for the full field-by-field citation.
struct PowerlinkSdo {
    // --- Sequence Layer ---
    uint8_t seq_receive_sequence_number = 0;  // top 6 bits of byte 0
    uint8_t seq_receive_con = 0;               // bottom 2 bits of byte 0 (0-3)
    std::string seq_receive_con_name;
    uint8_t seq_send_sequence_number = 0;      // top 6 bits of byte 1
    uint8_t seq_send_con = 0;                  // bottom 2 bits of byte 1 (0-3)
    std::string seq_send_con_name;

    // --- Command Layer ---
    bool has_command = false;  // false when fewer bytes remain than the 8-byte Command Layer header
                                 // needs -- an empty/sequence-only SDO message, matching the
                                 // reference source's own "Empty CommandLayer" case
    uint8_t transaction_id = 0;
    bool is_response = false;   // Response bit (0x80)
    bool is_abort = false;      // Abort bit (0x40)
    uint8_t segmentation = 0;   // bits 5-4: 0 Expedited, 1 Initiate, 2 Segment, 3 Transfer Complete
    std::string segmentation_name;
    uint8_t command_id_raw = 0;
    std::string command_id_name;  // empty when command_id_raw isn't one of the 12 named values
    uint16_t segment_size = 0;

    bool has_data_size = false;  // Initiate (segmentation==1) + WriteByIndex/ReadByIndex only
    uint32_t data_size = 0;

    bool has_index = false;  // WriteByIndex/ReadByIndex, Expedited or Initiate only (not Segment/
                               // Transfer Complete continuation frames -- see file header comment)
    uint16_t index = 0;
    uint8_t sub_index = 0;

    bool has_abort_code = false;
    uint32_t abort_code = 0;
    std::string abort_code_name;  // via canopen_sdo_abort_code_name -- empty when uncurated

    bool has_data = false;
    ByteSpan data;  // opaque -- Object Dictionary content, never value-decoded (see file header)

    std::string summary;
};

// One decoded ErrorCodeList entry (ASnd/StatusResponse only) -- see file header comment.
struct PowerlinkStatusResponseEntry {
    uint16_t entry_type_raw = 0;
    uint16_t error_code = 0;
    std::string time_stamp_hex;  // raw 8 bytes -- LE seconds(4)+nanoseconds(4), not reconstructed
    std::string add_info_hex;    // raw 8 bytes
};

// ASnd ServiceID==1 (IdentResponse) -- see file header comment for the full byte-offset citation.
struct PowerlinkIdentResponse {
    bool en = false;
    bool ec = false;
    bool fls = false;
    bool sls = false;
    uint8_t pr = 0;
    uint8_t rs = 0;
    uint8_t nmt_status_raw = 0;
    std::string nmt_status_name;
    uint8_t epl_version_raw = 0;
    uint32_t feature_flags = 0;  // raw -- see file header comment's FeatureFlags scope note
    uint16_t mtu = 0;
    uint16_t poll_in_size = 0;
    uint16_t poll_out_size = 0;
    uint32_t response_time_us = 0;
    uint16_t device_type = 0;
    uint16_t device_type_additional_info = 0;
    uint32_t vendor_id = 0;
    uint32_t product_code = 0;
    uint32_t revision_number = 0;
    uint32_t serial_number = 0;
    std::string vendor_specific_extension1_hex;  // 8 bytes raw
    uint32_t verify_configuration_date = 0;
    uint32_t verify_configuration_time = 0;
    uint32_t application_sw_date = 0;
    uint32_t application_sw_time = 0;
    std::string ip_address;      // dotted-quad, big-endian on the wire (see file header comment)
    std::string subnet_mask;
    std::string default_gateway;
    std::string host_name;                        // 32 bytes ASCII, NUL-trimmed
    std::string vendor_specific_extension2_hex;    // 48 bytes raw
};

// ASnd ServiceID==2 (StatusResponse) -- see file header comment.
struct PowerlinkStatusResponse {
    bool en = false;
    bool ec = false;
    bool fls = false;
    bool sls = false;
    uint8_t pr = 0;
    uint8_t rs = 0;
    uint8_t nmt_status_raw = 0;
    std::string nmt_status_name;
    uint8_t error_register_raw = 0;  // StaticErrorBitfield's own first byte -- CANopen Error
                                       // Register-equivalent bits, see file header comment
    std::vector<std::string> error_register_bits;
    std::string device_specific_error_hex;  // 6 bytes raw
    std::vector<PowerlinkStatusResponseEntry> error_entries;  // bounded, see file header comment
    bool error_entries_truncated = false;
};

// ASnd ServiceID==3 (NMTRequest) -- see file header comment.
struct PowerlinkNmtRequest {
    uint8_t requested_command_id_raw = 0;
    std::string requested_command_id_name;
    uint8_t requested_command_target = 0;
    ByteSpan requested_command_data;  // opaque, raw hex
};

// ASnd ServiceID==4 (NMTCommand) -- see file header comment. The command's TARGET is
// PowerlinkFrame::dst_node_id (the frame's own common-header Destination NodeID), not a field here.
struct PowerlinkNmtCommand {
    uint8_t command_id_raw = 0;
    std::string command_id_name;  // empty when not one of the 29 named values
    // Special-cased command data (see file header comment) -- at most one of these is set.
    bool has_host_name = false;
    std::string host_name;           // NMTNetHostNameSet, 32 bytes ASCII, NUL-trimmed
    bool has_flush_arp_target = false;
    uint8_t flush_arp_target = 0;     // NMTFlushArpEntry
    bool has_publish_time_raw = false;
    std::string publish_time_hex;     // NMTPublishTime, 6 bytes raw
    bool has_reset_node_reason = false;
    uint16_t reset_node_reason = 0;   // NMTResetNode, optional 2-byte LE reason code
    ByteSpan command_data;            // opaque raw hex for every other case (including NMTDNA,
                                        // shown as its own fixed-length raw region, see file header)
};

struct PowerlinkFrame {
    uint8_t message_type_raw = 0;   // the FULL byte -- see file header comment's MessageType
                                      // correction (no bit-7 masking)
    std::string message_type_name;  // "SoC"/"PReq"/"PRes"/"SoA"/"ASnd"/"AMNI"/"AInv"/"unrecognized"
    bool message_type_recognized = false;

    uint8_t dst_node_id = 0;
    uint8_t src_node_id = 0;
    std::string dst_node_id_note;  // e.g. " (broadcast)"/" (Managing Node)", empty otherwise
    std::string src_node_id_note;

    // --- SoC (0x01) ---
    bool has_soc = false;
    bool soc_mc = false;
    bool soc_ps = false;
    bool soc_an_global = false;
    std::string soc_net_time_hex;       // 8 bytes raw, LE secs(4)+nsecs(4) -- see file header
    std::string soc_relative_time_hex;  // 8 bytes raw

    // --- PReq (0x03) ---
    bool has_preq = false;
    bool preq_ms = false;
    bool preq_ea = false;
    bool preq_rd = false;
    bool preq_fls = false;
    bool preq_sls = false;
    uint8_t preq_pdo_version_raw = 0;
    uint16_t preq_size = 0;
    ByteSpan preq_payload;  // opaque, trimmed to min(preq_size, bytes actually available)
    bool preq_payload_truncated = false;

    // --- PRes (0x04) ---
    bool has_pres = false;
    uint8_t pres_nmt_status_raw = 0;
    std::string pres_nmt_status_name;
    bool pres_ms = false;
    bool pres_en = false;
    bool pres_rd = false;
    bool pres_fls = false;
    bool pres_sls = false;
    uint8_t pres_pr = 0;
    uint8_t pres_rs = 0;
    uint8_t pres_pdo_version_raw = 0;
    uint16_t pres_size = 0;
    ByteSpan pres_payload;
    bool pres_payload_truncated = false;

    // --- SoA (0x05) ---
    bool has_soa = false;
    uint8_t soa_nmt_status_raw = 0;
    std::string soa_nmt_status_name;
    bool soa_ea = false;
    bool soa_er = false;
    bool soa_an_global = false;
    bool soa_an_local = false;  // only meaningful when soa_requested_service_id_raw == IdentRequest
    uint8_t soa_requested_service_id_raw = 0;
    std::string soa_requested_service_id_name;
    uint8_t soa_requested_service_target = 0;
    uint8_t soa_epl_version_raw = 0;
    uint8_t soa_redundancy_flags_raw = 0;
    bool soa_mn_redundancy = false;
    bool soa_cable_redundancy = false;
    bool soa_ring_redundancy = false;
    bool soa_ring_closed = false;

    // --- ASnd (0x06) and AInv (0x0D, which wraps the same service body -- see file header) ---
    bool has_asnd = false;  // true for ASnd
    bool has_ainv = false;  // true for AInv (has its own NMTStatus/EA/ER header, see below)
    uint8_t ainv_nmt_status_raw = 0;
    std::string ainv_nmt_status_name;
    bool ainv_ea = false;
    bool ainv_er = false;
    uint8_t asnd_service_id_raw = 0;
    std::string asnd_service_id_name;  // empty when not one of the 6 named values

    bool has_ident_response = false;
    PowerlinkIdentResponse ident_response;
    bool has_status_response = false;
    PowerlinkStatusResponse status_response;
    bool has_nmt_request = false;
    PowerlinkNmtRequest nmt_request;
    bool has_nmt_command = false;
    PowerlinkNmtCommand nmt_command;
    bool has_sdo = false;
    PowerlinkSdo sdo;

    // --- AMNI (0x07) ---
    bool has_amni = false;  // every field reserved per the reference source -- named only

    std::string summary;
    std::vector<std::string> notes;
};

// Attempts to interpret `payload` -- the bytes immediately after EtherType 0x88AB (or after a
// single 802.1Q VLAN tag, already unwrapped by parse_ethernet), OR a standalone UDP:3819 datagram's
// payload, which is the SAME frame shape (see file header comment's "UDP:3819 SDO variant"
// architecture note) -- as one POWERLINK frame. Returns std::nullopt (never throws) only when there
// aren't even 3 bytes for the common MessageType+Destination+Source header; a MessageType byte not
// in the 7-value named table above still returns a value (message_type_recognized == false,
// message_type_name == "unrecognized"), the same "never silently drop, never guess a name" posture
// this task's own brief asked for.
std::optional<PowerlinkFrame> try_parse_powerlink(ByteSpan payload);

// Anomalous-NMT-command curated finding helper (see output.cpp's --stats item (1), and this file's
// own header comment's CURATED FINDINGS section) -- true for the NMTCommand names that plausibly
// disrupt a running node (resets/stops, and their _Ex variants). Exposed (rather than kept
// powerlink.cpp-local) specifically so output.cpp's StatsWriter can share it.
bool nmt_command_is_disruptive(const std::string& name);

// True for an NMT state name meaning "Operational" (CN or MN) -- see this file's own header
// comment's "NMT state values" section. Exposed for the same StatsWriter-sharing reason as
// nmt_command_is_disruptive above.
bool nmt_state_is_operational(const std::string& name);

// registration-model wrapper -- id()=="powerlink", GateKind::EtherType, EtherType 0x88AB. See
// profinet.hpp/ethercat.hpp's own identically-shaped classes for the template this follows exactly.
class PowerlinkDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "powerlink"; }
    GateKind gate_kind() const override { return GateKind::EtherType; }
    std::optional<uint16_t> ethertype() const override { return ETHERTYPE_POWERLINK; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& powerlink_decoder();

// The UDP:3819 SDO-over-UDP variant -- see file header comment's "UDP:3819 SDO variant"
// architecture note for why this shares id() with PowerlinkDecoder above (the exact same "one
// protocol_id backed by two decoders/gates" pattern EtherNet/IP's CIP I/O UDP path, HART-IP's UDP
// path, and several others in this codebase already establish) and calls try_parse_powerlink
// directly rather than any separate/stripped-down parser.
class PowerlinkSdoUdpDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "powerlink"; }
    GateKind gate_kind() const override { return GateKind::UdpPort; }
    std::optional<uint16_t> udp_port() const override { return POWERLINK_SDO_UDP_PORT; }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& powerlink_sdo_udp_decoder();

}  // namespace conduitscope
