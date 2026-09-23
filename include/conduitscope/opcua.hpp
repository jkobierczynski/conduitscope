// SPDX-License-Identifier: Apache-2.0
// opcua.hpp - OPC UA Binary (UA-TCP / OPC UA Secure Conversation) decoding: the 8-byte UA-TCP
// connection-protocol messages (Hello, Acknowledge, Error, ReverseHello), the 12-byte
// SecureConversation chunk header used by OpenSecureChannel/CloseSecureChannel/Message, their
// security and sequence headers, and, for the service-layer Message body, a "first pass" set of
// the most common OPC UA services -- session lifecycle, endpoint/server discovery, identity
// (including, deliberately, cleartext-credential exposure when a client authenticates with
// UserName/Password over an unencrypted SecureChannel -- see "Identity token decode" below), and
// data access (Read/Write/Call, full Variant/DataValue self-describing value decoding included --
// see "Variant/DataValue value decoding" below).
//
// OPC UA rides over plain TCP only (no UDP mapping exists in the spec), conventionally port 4840
// -- see try_parse_opcua_message's own "structural detection gate" paragraph below for why this
// decoder is confident applying that check port-independently. Every multi-byte field is
// LITTLE-endian -- unlike every other protocol this codebase decodes except EtherNet/IP/CIP, OPC
// UA's own binary encoding (OPC 10000-6) is little-endian throughout, a legacy of its DCOM/OLE
// lineage predating the pure-Ethernet-fieldbus protocols this codebase otherwise covers.
//
// Sourcing: this file's wire-format description is cross-checked against three independent
// sources that all had to agree before a field was trusted: (1) the OPC Foundation's own published
// reference documentation (reference.opcfoundation.org/Core/Part4 "Services" and Part6 "Mappings"
// -- the primary specification text), (2) the OPC Foundation's own published, machine-readable
// NodeIds.csv and StatusCode.csv (github.com/OPCFoundation/UA-Nodeset) for every numeric
// "_Encoding_DefaultBinary" service identifier and named StatusCode value this file asserts --
// the single most error-prone part of implementing OPC UA Binary by hand, so this decoder never
// guesses one, and (3) python-opcua's own machine-generated protocol bindings
// (github.com/FreeOpcUa/python-opcua, generated directly from the OPC Foundation's schema) as an
// independent, interoperability-tested cross-check on field order and type for every structure
// below -- the same "generated from the vendor's own schema, so it can't have transcribed a field
// wrong without breaking real interop" sourcing standard this codebase already leans on elsewhere
// (e.g. Wireshark's own dissector source for HART-IP/BACnet/GOOSE/SV/EtherCAT/PROFINET).
//
// ---------------------------------------------------------------------------------------------
// UA-TCP common header (8 bytes, the first 8 bytes of every message on the wire, whichever of the
// two shapes below follows it):
//   MessageType(3)   -- ASCII: "HEL"=Hello, "ACK"=Acknowledge, "ERR"=Error, "RHE"=ReverseHello (all
//                        four are plain UA Connection Protocol messages, always exactly one 'F'
//                        chunk), "OPN"=OpenSecureChannel, "CLO"=CloseSecureChannel, "MSG"=Message
//                        (all three are OPC UA Secure Conversation messages, carrying 4 more bytes
//                        of header -- SecureChannelId -- plus a security header and sequence header
//                        before their own body; see below).
//   ChunkType(1)     -- ASCII 'F' (final/only chunk), 'C' (intermediate chunk, more to follow), 'A'
//                        (abort -- the chunk's body is an error code + reason, not that message's
//                        usual body). Only meaningful for MSG; the spec requires 'F' for every other
//                        MessageType, and this decoder notes rather than silently ignores an 'C'/'A'
//                        chunk type on a non-MSG message.
//   MessageSize(4)   -- little-endian; this ONE CHUNK's own total byte length, header included (NOT
//                        the reassembled multi-chunk message's total length -- see "Chunking" below).
//                        Used both as this decoder's own plausibility check and as the declared
//                        length that drives this codebase's usual TCP stream reassembly (see
//                        opcua_declared_length below, mirroring hartip_declared_length/
//                        enip_declared_length).
//
// Structural detection gate: MessageType must be one of exactly 7 fixed 3-byte ASCII strings, and
// ChunkType must be one of 3 fixed ASCII characters ('F'/'C'/'A' -- this decoder accepts all three
// even on a non-MSG message, rather than rejecting on the spec's stricter "always F" requirement,
// so it stays maximally permissive about what it MERELY DETECTS rather than what it considers
// well-formed) -- effectively a 4-byte magic-string check against a small allowlist, plus a
// MessageSize plausibility check (>= 8, the header's own fixed size). This is a materially
// STRONGER structural signal than most of this codebase's own gates: unlike, say, HART-IP's own
// two adjacent bytes each independently landing on one of a handful of small numeric values (see
// hartip.hpp's own honest "weakest gate in this codebase" framing), a 3-byte ASCII match against 7
// specific strings has an effective collision space of roughly 1 in 16 million per candidate
// offset before the ChunkType/MessageSize checks even apply -- closer in spirit to Modbus/TCP's
// own protocol-id==0 check or BACnet's Type+Function pair than to HART-IP's. No collision with any
// other protocol this codebase decodes was found during this decoder's own research (checked
// byte-by-byte against every other protocol's own leading-bytes gate: none of the 7 ASCII
// MessageType strings' constituent bytes can satisfy Modbus's protocol-id==0 check, IEC104's
// 0x68 start byte, TPKT's version==3 byte, DNP3's 0x0564 sync bytes, or EtherNet/IP's small
// enumerated command-code set -- see opcua.cpp's own dispatch-order comment for the one-line
// summary). Applied port-independently in Auto mode; port 4840 is recorded as an "expected port"
// annotation only, never a gate, the same posture this codebase already uses for every other
// protocol's own port.
//
// ---------------------------------------------------------------------------------------------
// Hello body (MessageType HEL, client->server, always the first message on a new TCP connection):
//   ProtocolVersion(4), ReceiveBufferSize(4), SendBufferSize(4), MaxMessageSize(4),
//   MaxChunkCount(4) -- all UInt32 -- then EndpointUrl (a UA String: Int32 length prefix, -1=null,
//   else that many UTF-8 bytes -- see "Primitive encoding" below).
// Acknowledge body (MessageType ACK, server->client, in reply to Hello): the same first 5 UInt32
//   fields (ProtocolVersion/ReceiveBufferSize/SendBufferSize/MaxMessageSize/MaxChunkCount), no
//   EndpointUrl.
// Error body (MessageType ERR, either direction, terminates the connection): Error(4, a StatusCode
//   -- see "StatusCode decode" below) + Reason (a UA String).
// ReverseHello body (MessageType RHE, used only for the "reverse connect" pattern where a Server
//   initiates the TCP connection to a Client): ServerUri (String) + EndpointUrl (String).
//
// ---------------------------------------------------------------------------------------------
// OPC UA Secure Conversation header (MessageType OPN/CLO/MSG only, immediately after the 8-byte
// UA-TCP common header above):
//   SecureChannelId(4, UInt32) -- 0 on the very first OpenSecureChannel request of a new channel
//                                  (the server assigns and returns the real id in its response).
// Security header -- shape depends on MessageType:
//   OPN (Asymmetric Algorithm Security Header): SecurityPolicyUri (String, e.g.
//     "http://opcfoundation.org/UA/SecurityPolicy#None") + SenderCertificate (ByteString, -1/empty
//     when the policy is None) + ReceiverCertificateThumbprint (ByteString). This decoder surfaces
//     SecurityPolicyUri in full (it is itself the single most useful security-audit signal this
//     file can offer -- see "Security posture is visible even when the body is not" below) and the
//     two certificate fields only as presence + byte length, never the certificate bytes
//     themselves (a DER-encoded X.509 cert is not meaningfully summarizable as a handful of
//     decoded fields, the same reasoning this codebase already applies to HART-IP's Data-Link
//     Checksum or SV's seqData -- shown as a fact about the message, not value-decoded).
//   CLO/MSG (Symmetric Algorithm Security Header): TokenId(4, UInt32) only -- the previously
//     negotiated security token this message claims to use.
// Sequence header (present on OPN/CLO/MSG alike, immediately after the security header):
//   SequenceNumber(4, UInt32), RequestId(4, UInt32).
//
// Security posture is visible even when the body is not: this decoder does NOT track
// SecureChannel/Session state across messages (no correlation table keyed by SecureChannelId --
// see "Deliberately NOT implemented: stateful channel/session tracking" below), so it has no way
// to know, from a MSG message alone, what SecurityMode a TokenId corresponds to. But the
// OpenSecureChannel exchange that negotiated that token is, itself, always fully decoded by this
// file (when readable at all -- see next paragraph), and its own SecurityPolicyUri +
// MessageSecurityMode fields are exactly the two values that determine whether every later MSG
// message on that same SecureChannelId is even readable in the first place. A capture showing
// SecurityPolicyUri "...#None" and MessageSecurityMode "None" on the OpenSecureChannel exchange is
// itself the audit finding (an OPC UA endpoint accepting no security at all) independent of
// whether this decoder goes on to successfully read any later MSG body.
//
// Opportunistic MSG/OPN/CLO body decode: this decoder does not know, a priori, whether a given
// OPN/CLO/MSG chunk's body is plaintext (SecurityMode None), signed-but-not-encrypted (Sign -- the
// body IS still plaintext, only a trailing signature is added), or genuinely encrypted
// (SignAndEncrypt). Rather than tracking channel state to know in advance, this decoder simply
// ATTEMPTS to parse the body as a NodeId-prefixed service structure (see "Service identification"
// below) and accepts the result only if it is fully self-consistent (a structurally valid NodeId
// encoding byte, a numeric identifier this file recognizes or at least can bounds-check, and
// enough remaining bytes for whatever it then tries to read) -- exactly the same
// try-and-fall-back-to-raw-hex posture this codebase already uses for chunked/multi-frame content
// elsewhere. An encrypted body's essentially-random leading byte will, in the overwhelming
// majority of cases, simply fail this file's own NodeId-encoding-byte check (only 6 of 256 values,
// plus the two ExpandedNodeId flag bits, are valid) and fall straight to "body shown as raw hex,
// service unrecognized" -- the same honest, no-hidden-state fallback this file already documents
// for S7comm-Plus elsewhere in this codebase.
//
// ---------------------------------------------------------------------------------------------
// Primitive encoding (OPC UA Binary, per OPC 10000-6 5.2 -- cross-checked against python-opcua's
// own generated (de)serializers, which must match byte-for-byte or real clients/servers using that
// library could not interoperate with anything else):
//   Boolean(1), SByte/Byte(1), Int16/UInt16(2), Int32/UInt32(4), Int64/UInt64(8), Float(4,
//   IEEE754), Double(8, IEEE754) -- all little-endian.
//   String / ByteString(variable) -- Int32 length prefix (little-endian); -1 means null (no bytes
//     follow); 0 means empty (no bytes follow either, but is a distinct, non-null empty
//     string/bytestring); otherwise that many bytes follow (UTF-8 for String).
//   DateTime(8) -- Int64 little-endian, 100-nanosecond intervals since 1601-01-01T00:00:00Z (the
//     Win32 FILETIME epoch) -- decoded to a calendar date/time the same way this codebase already
//     renders GOOSE/SV timestamps.
//   Guid(16) -- NOT 16 raw bytes in wire order: Data1(UInt32, little-endian) + Data2(UInt16,
//     little-endian) + Data3(UInt16, little-endian) + Data4(8 raw bytes, network/big-endian order)
//     -- the same mixed-endianness layout Microsoft's own GUID wire format uses, confirmed against
//     python-opcua's own pack/unpack pair (which round-trips through Python's stdlib uuid.UUID).
//   NodeId(variable) -- a 1-byte encoding mask, low 6 bits selecting the shape (the top 2 bits are
//     ExpandedNodeId-only flags -- see below -- and are masked off before reading this list):
//       0x00 Two-Byte   -- Identifier(1, Byte); namespace is implicitly 0.
//       0x01 Four-Byte  -- Namespace(1, Byte) + Identifier(2, UInt16).
//       0x02 Numeric    -- Namespace(2, UInt16) + Identifier(4, UInt32).
//       0x03 String     -- Namespace(2, UInt16) + Identifier(String).
//       0x04 Guid       -- Namespace(2, UInt16) + Identifier(16, Guid).
//       0x05 ByteString -- Namespace(2, UInt16) + Identifier(ByteString).
//     Any other low-6-bits value is not a valid NodeId encoding -- this decoder treats it as a
//     structural parse failure (see "Opportunistic MSG/OPN/CLO body decode" above).
//   ExpandedNodeId -- a NodeId (above) whose encoding-mask byte may additionally have bit 0x80 set
//     (a NamespaceUri String follows the NodeId's own fields) and/or bit 0x40 set (a ServerIndex
//     UInt32 follows). This decoder reads and skips both when present (needed to correctly locate
//     whatever comes next in the message) but does not surface NamespaceUri/ServerIndex as
//     separate decoded fields -- every service this file dispatches on uses a plain, unflagged
//     NodeId for its own TypeId in practice (an ExpandedNodeId with either flag set on a
//     service's own TypeId would be spec-non-conformant), so this handling exists purely for
///    correctness/robustness, not because any real capture was found needing it.
//   QualifiedName(variable) -- NamespaceIndex(2, UInt16) + Name(String).
//   LocalizedText(variable) -- a 1-byte encoding mask (bit 0x01 = Locale field present, bit 0x02 =
//     Text field present, either/both/neither) + Locale(String, only when its bit is set) +
//     Text(String, only when its bit is set).
//   ExtensionObject(variable) -- TypeId(NodeId, the DataTypeEncoding node) + Encoding(1, Byte:
//     0x00=no body, 0x01=ByteString body, 0x02=XML body) + [Int32 length + that many body bytes,
//     only when Encoding != 0x00]. This decoder uses this to identify a handful of specific
//     structured types by their own TypeId (see "Identity token decode" below) and otherwise skips
//     it structurally.
//   StatusCode(4, UInt32) -- see "StatusCode decode" below.
//   Arrays -- for any of the above (except NodeId's own ExpandedNodeId flags, which are per-value,
//     not array-level): an Int32 element count prefix (-1 means a null/absent array, distinct from
//     0 meaning a present-but-empty array) followed by that many encoded elements back-to-back, no
//     further framing between elements.
//
// StatusCode decode: the top 2 bits (0xC0000000) are the severity -- 00=Good(0x00000000),
// 01=Uncertain(0x40000000), 10=Bad(0x80000000), 11 unused/reserved -- always decodable regardless
// of whether the specific value is one this file names (cross-checked against the OPC
// Foundation's own published StatusCode.csv, which enumerates ~700 named codes; this decoder's own
// table below is deliberately a "first pass" -- the handful most relevant to an OT security
// audit's own concerns (auth/certificate/session/timeout failures) rather than an attempt at all
// ~700):
//   Good(0x00000000) Uncertain(0x40000000)
//   BadUnexpectedError(0x80010000)          BadTimeout(0x800A0000)
//   BadServiceUnsupported(0x800B0000)       BadCertificateInvalid(0x80120000)
//   BadSecurityChecksFailed(0x80130000)     BadUserAccessDenied(0x801F0000)
//   BadIdentityTokenInvalid(0x80200000)     BadIdentityTokenRejected(0x80210000)
//   BadSecureChannelIdInvalid(0x80220000)   BadSessionIdInvalid(0x80250000)
//   BadSessionClosed(0x80260000)            BadNodeIdInvalid(0x80330000)
//   BadNodeIdUnknown(0x80340000)            BadNotReadable(0x803A0000)
//   BadNotWritable(0x803B0000)              BadRequestTypeInvalid(0x80530000)
//   BadSecurityPolicyRejected(0x80550000)   BadTypeMismatch(0x80740000)
// Any other 32-bit value is rendered as its decoded severity word plus the raw hex value, e.g.
// "Bad (0x80af0000)" -- never guessed at.
//
// ---------------------------------------------------------------------------------------------
// Service identification: every OPC UA service request/response, and ServiceFault, begins with
// its own NodeId "TypeId" (see "Primitive encoding" above) whose numeric Identifier (this decoder
// only recognizes the plain Numeric or Four-Byte/Two-Byte encodings in namespace 0 -- every
// standard service TypeId is namespace 0 by definition) is looked up against the OPC Foundation's
// own published NodeIds.csv (specifically, each service's own "_Encoding_DefaultBinary" entry --
// see this file's own header comment's "Sourcing" paragraph). This decoder's own dispatch table
// covers two tiers:
//
// Tier 1 ("full decode" -- RequestHeader/ResponseHeader plus every service-specific field is
// decoded): the UA Connection Protocol handshake (Hello/Acknowledge/Error/ReverseHello, covered
// above, which have no TypeId/RequestHeader of their own) plus, at the service layer,
// OpenSecureChannel, CloseSecureChannel, GetEndpoints, FindServers, CreateSession,
// ActivateSession, CloseSession, ServiceFault, and -- now that Variant/DataValue value decoding
// (below) exists to give their own service-specific fields somewhere to go -- Read, Write, and
// Call. This is itself a deliberate first-pass scope decision, not an oversight: the
// lifecycle+discovery services were (a) universally present in every real OPC UA capture
// regardless of what the client/server actually do with the connection afterward, (b)
// individually simple enough (no Variant/DataValue encoding anywhere in any of them) to decode
// with full confidence in this file's own "verify every field against a primary or
// schema-generated source, never guess" discipline, and (c) collectively the highest
// OT-security-audit value of any OPC UA service group: SecurityPolicyUri/MessageSecurityMode
// (is this endpoint accepting no security at all?), the full endpoint/server inventory
// (EndpointDescription's own SecurityMode/SecurityPolicyUri per endpoint -- an OPC UA analog of
// this codebase's existing BACnet I-Am / EtherNet/IP ListIdentity / HART-IP Read-Unique-Identifier
// "device fingerprinting" framing), and -- deliberately -- the UserIdentityToken carried in every
// ActivateSession request (see "Identity token decode" below). Read/Write/Call are promoted
// alongside them for a different, equally deliberate reason: they are the three OPC UA services
// whose entire reason for existing IS carrying a Variant or DataValue -- ReadResponse's own
// Results, WriteRequest's own NodesToWrite, and CallRequest/CallResponse's own Input/Output
// Arguments are, respectively, an array of DataValue, an array of DataValue, and arrays of
// Variant -- so once the value-decoding machinery existed at all, leaving these three at Tier 2
// would have meant showing exactly the fields an OT-security audit of live process values most
// needs as raw hex. Browse and the subscription/MonitoredItem-management services are
// DELIBERATELY still Tier 2 even though value decoding now exists: Browse's own
// BrowseDescription/ReferenceDescription deal in NodeId/BrowseDirection/ReferenceTypeId, and
// MonitoredItem creation's own MonitoringFilter is an ExtensionObject -- neither carries a
// Variant/DataValue anywhere in its own body, so promoting them would be a separate, unrelated
// decode effort, not a natural extension of this one (see ROADMAP in docs/MANUAL.md). HistoryRead
// DOES carry DataValue/Variant in its own HistoryReadResult, but its own HistoryReadDetails
// ExtensionObject dispatches across five different sub-structures (ReadRawModifiedDetails/
// ReadAtTimeDetails/ReadProcessedDetails/ReadEventDetails/ReadAnnotationDataDetails) -- enough
// additional scope of its own that this first pass leaves it at Tier 2 too.
//
// Tier 2 ("header only" -- RequestHeader/ResponseHeader is decoded exactly as in Tier 1, giving at
// minimum a request handle and, for a response, the ServiceResult StatusCode -- but every
// service-specific field after the header is shown only as raw hex, not decoded): Browse,
// BrowseNext, TranslateBrowsePathsToNodeIds, CreateSubscription, ModifySubscription,
// DeleteSubscriptions, CreateMonitoredItems, ModifyMonitoredItems, DeleteMonitoredItems,
// SetPublishingMode, Publish, Republish, Cancel, RegisterNodes, UnregisterNodes, AddNodes,
// HistoryRead -- see the Tier 1 paragraph above for why each of these specifically stays here even
// though Variant/DataValue value decoding now exists. Even without their own bodies decoded, this
// tier is still genuinely useful: the service NAME itself (what kind of operation this is), the
// request handle, and -- for a response -- whether the overall call succeeded (ServiceResult) are
// all visible, which is often enough to answer "is this conduit doing OPC UA browsing/
// subscriptions at all, and are they succeeding" without needing the actual values.
//
// Variant/DataValue value decoding: OPC 10000-6 5.2.2.16/5.2.2.17 define two self-describing,
// recursive value containers used throughout the OPC UA data model -- Variant (any one of 25
// BuiltInTypes, either a scalar or an array, optionally with ArrayDimensions) and DataValue (a
// Variant plus up to five optional metadata fields: StatusCode, SourceTimestamp,
// SourcePicoseconds, ServerTimestamp, ServerPicoseconds). A Variant is a 1-byte EncodingMask (low
// 6 bits = the BuiltInType numeric id, 1-25; bit 0x80 = an array, not a scalar, follows; bit 0x40
// = an ArrayDimensions field follows) followed by either one scalar value or an Int32 ArrayLength
// plus that many elements, followed (if the dims bit is set) by an Int32 count plus that many
// Int32 dimension sizes. A DataValue is a 1-byte EncodingMask (bit 0x01 Value, 0x02 StatusCode,
// 0x04 SourceTimestamp, 0x08 ServerTimestamp, 0x10 SourcePicoseconds, 0x20 ServerPicoseconds)
// followed by whichever fields it flags -- in WIRE order, which this decoder cross-checked against
// the OPC Foundation's own reference documentation and is NOT simply ascending bit order:
// SourcePicoseconds (mask bit 0x10) is encoded BEFORE ServerTimestamp (mask bit 0x08), even though
// its own bit is numerically after ServerTimestamp's. A BuiltInType id this decoder does not
// recognize (0 is the reserved Null sentinel, meaning "no value" for a Variant; ids outside 1-25
// are not valid at all) is treated as a decode failure for that Variant, the same "don't guess"
// posture this file already takes for an unrecognized NodeId encoding shape. Recursion (a
// Variant's own BuiltInType 24 is Variant-of-Variant; type 23 is Variant-of-DataValue) is bounded
// to 10 levels deep, mirroring this file's own DiagnosticInfo recursion guard below. Two small,
// closed value tables ride alongside this decoding: AttributeId (Read/Write's own attribute
// selector -- the 22 attributes defined since OPC UA 1.03, cross-checked against open62541's own
// published UA_AttributeId constants; the four attributes 1.04/1.05 later added --
// DataTypeDefinition/RolePermissions/UserRolePermissions/AccessRestrictions/AccessLevelEx -- were
// not corroborated with the same confidence and are rendered as a bare number instead of a guessed
// name, this file's own "don't guess a numeric table entry" discipline) and TimestampsToReturn
// (Read/HistoryRead's own request parameter, cross-checked against OPC 10000-4 7.39).
//
// A TypeId this file's dispatch table does not recognize AT ALL (any numeric identifier not
// covering-Tier1-or-Tier2's ~40 known values) is reported by its raw namespace+numeric-identifier
// only ("service type-id N, namespace M -- not in this decoder's dispatch table"); this decoder
// does not attempt to guess whether it is even shaped like a Request or a Response (RequestHeader
// and ResponseHeader have genuinely different leading fields -- a NodeId vs. a DateTime -- and
// blindly assuming one would risk mis-parsing), so its ENTIRE body, RequestHeader/ResponseHeader
// included, is shown as raw hex.
//
// Identity token decode: ActivateSessionRequest's own UserIdentityToken field is an
// ExtensionObject (see "Primitive encoding" above) wrapping one of four standard structures,
// identified by that ExtensionObject's own TypeId:
//   AnonymousIdentityToken  -- PolicyId(String) only. No credential of any kind.
//   UserNameIdentityToken   -- PolicyId(String), UserName(String), Password(ByteString),
//                               EncryptionAlgorithm(String).
//   X509IdentityToken       -- PolicyId(String), CertificateData(ByteString, shown as presence +
//                               length only, per this file's own certificate-handling convention).
//   IssuedIdentityToken     -- PolicyId(String), TokenData(ByteString, shown as presence + length
//                               only), EncryptionAlgorithm(String).
// UserNameIdentityToken is decoded in full, DELIBERATELY, including the Password field: per OPC
// 10000-4 7.41, EncryptionAlgorithm empty/null means Password was NOT encrypted with the server's
// public key before being placed on the wire -- i.e. it is either (a) already plaintext, when the
// entire SecureChannel itself is also unencrypted (SecurityMode None, the same posture this file's
// own "Security posture is visible even when the body is not" paragraph above already lets this
// decoder flag), or (b) plaintext regardless of SecureChannel security, on any implementation that
// (non-conformantly, but not rarely, in this decoder's own research) omits password encryption
// even when a SecurityPolicy is in use. Either way, an EncryptionAlgorithm-empty UserName+Password
// pair on the wire IS a real, actionable, documented OPC UA security finding (credential exposure
// via anonymous/no-security ActivateSession), not a hypothetical this decoder invented -- decoding
// it plainly serves this whole tool's stated purpose as an OT-security-auditing decoder (the same
// reasoning already stated for this codebase's HART-IP Response-Code naming choice in hartip.hpp).
// When EncryptionAlgorithm is instead a non-empty string, the Password bytes ARE genuinely
// encrypted ciphertext (not a password this decoder could show even if it wanted to) and are
// therefore shown only as a byte length, never as hex/text -- this decoder does not pretend
// otherwise. UserName itself is always decoded as plain text regardless of EncryptionAlgorithm
// (the spec never encrypts UserName, only Password), since a leaked USERNAME alone -- even with an
// encrypted password -- is still a legitimate account-enumeration finding.
//
// ---------------------------------------------------------------------------------------------
// Chunking: a single logical OPC UA Message-layer request/response CAN be split across multiple
// MSG chunks (ChunkType 'C' for every chunk but the last, 'F' for the last) when it exceeds the
// negotiated SendBufferSize/MaxMessageSize -- the OPC UA analog of this codebase's own COTP EOT-
// bit reassembly for S7comm, or DNP3's multi-frame application-fragment reassembly. This first-
// pass release does NOT implement that cross-chunk reassembly: only a single, complete 'F'-chunk
// message has its service body decoded (Tier 1) or even attempted (Tier 2/unrecognized); a 'C'
// (intermediate) or 'A' (abort) chunk is fully decoded at the UA-TCP/SecureConversation HEADER
// level (MessageType, ChunkType, SecureChannelId, security header, sequence header -- everything
// that does NOT require knowing the reassembled message boundary) but its own body is always shown
// as raw hex, regardless of what service TypeId a fully-reassembled version of it might carry --
// see LIMITATIONS in docs/MANUAL.md. In this decoder's own experience building this feature's test
// fixtures, a chunked message is the exception rather than the rule for the session/discovery/
// lifecycle services this file's own Tier 1 targets (their own bodies are all small, fixed, or
// short-array-bounded) -- chunking matters most for the very services (bulk Browse/Read results,
// large Publish notifications) this first pass already leaves at Tier 2 raw-hex depth, so this
// scope decision costs relatively little of this release's own practical coverage.
//
// Deliberately NOT implemented: stateful channel/session tracking (correlating a MSG message's own
// TokenId back to the OpenSecureChannel exchange that negotiated it, or a Request's
// AuthenticationToken back to the CreateSession response that issued it) -- this decoder is, like
// every other protocol in this codebase, a stateless-per-message decoder with TCP-stream-level
// reassembly only (see "Chunking" above), not a full conversation-tracking OPC UA stack;
// Browse/subscription/MonitoredItem-management and HistoryRead body decoding (see the Tier 1/Tier
// 2 paragraphs above -- Variant/DataValue value decoding itself IS implemented; these specific
// services simply don't need it, or need additional scope of their own); multi-level
// DiagnosticInfo's own optional
// SymbolicId/NamespaceUri/LocalizedText/Locale/AdditionalInfo/InnerStatusCode/InnerDiagnosticInfo
// fields are structurally skipped (the EncodingMask byte and, when set, each flagged field are all
// correctly consumed so byte alignment for whatever follows in the same message stays correct --
// this decoder DOES need this to be byte-accurate, unlike the fields it merely doesn't surface --
// but none of those seven fields is itself surfaced as a decoded value); and OPC UA's separate
// PubSub/UADP mapping (an entirely different, connectionless UDP/MQTT/AMQP-based wire format used
// for telemetry publishing, unrelated to the client/server UA-TCP mapping this file decodes) is
// out of scope entirely, not merely undecoded.
//
// Validation: see this file's own real-capture search record in tests/real_captures/opcua/
// ATTRIBUTION.md (if present) or this decoder's own Validation paragraph in opcua.cpp for the
// current state of that search.
#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "conduitscope/byteio.hpp"
#include "conduitscope/protocol_decoder.hpp"

namespace conduitscope {

// The IANA-registered OPC UA Connection Protocol port -- recorded as an "expected port"
// annotation only, never a detection gate (this decoder's own structural detection gate is
// port-independent -- see opcua.hpp's file header comment).
constexpr uint16_t OPCUA_PORT = 4840;

// One decoded Request/ResponseHeader pair's worth of always-present bookkeeping -- see opcua.hpp's
// file header comment's "Service identification" section. Populated for both Tier 1 and Tier 2
// services (and left default/unset for a completely unrecognized TypeId).
struct OpcUaServiceHeader {
    uint32_t request_handle = 0;
    bool is_response = false;      // true when this is the ResponseHeader shape, false for Request
    uint32_t status_code = 0;      // ResponseHeader's own ServiceResult -- meaningful only when is_response
    std::string status_code_name;  // "Good"/"Uncertain"/"Bad (0xNNNNNNNN)" -- see "StatusCode decode"
    bool status_is_good = false;
};

// One decoded OPC UA message (one UA-TCP/SecureConversation chunk) -- see opcua.hpp's file header
// comment for the full byte layout and service-dispatch scope.
struct OpcUaMessage {
    std::string message_type;  // "Hello"/"Acknowledge"/"Error"/"ReverseHello"/"OpenSecureChannel"/
                                 // "CloseSecureChannel"/"Message" -- spelled out, not the raw 3-byte code
    char chunk_type = 'F';      // 'F'/'C'/'A' -- see file header comment
    uint32_t message_size = 0;  // this chunk's own declared total length, header included

    bool has_secure_channel = false;  // true for OpenSecureChannel/CloseSecureChannel/Message
    uint32_t secure_channel_id = 0;
    bool is_asymmetric = false;  // true only for OpenSecureChannel (AsymmetricAlgorithmSecurityHeader)
    std::string security_policy_uri;             // asymmetric only
    bool has_sender_certificate = false;          // asymmetric only
    size_t sender_certificate_length = 0;
    bool has_receiver_certificate_thumbprint = false;  // asymmetric only
    size_t receiver_certificate_thumbprint_length = 0;
    uint32_t token_id = 0;  // symmetric only (CloseSecureChannel/Message)
    uint32_t sequence_number = 0;
    uint32_t request_id = 0;

    bool service_recognized = false;  // TypeId matched a name in this decoder's dispatch table
    std::string service_name;         // e.g. "OpenSecureChannelRequest" -- empty when !service_recognized
    uint16_t service_namespace = 0;
    uint32_t service_type_id = 0;  // the raw numeric identifier
    bool service_body_decoded = false;  // true for Tier 1 (full decode); false for Tier 2/unrecognized

    bool has_header = false;  // RequestHeader/ResponseHeader was itself decoded (Tier 1 and Tier 2 alike)
    OpcUaServiceHeader header;

    std::vector<std::string> values;  // Tier 1 service-specific decoded fields, "key=value" each

    bool body_shown_as_hex = false;
    std::string body_hex;
    size_t body_length = 0;

    // The full wire length of this one chunk (== message_size when it was trustworthy, else
    // clamped to the bytes actually available) -- lets a caller find where the next chunk, if
    // any, starts in the same TCP payload (mirrors HartIpFrame::wire_length/EnipFrame::wire_length's
    // own role for those protocols' own coalesced-messages handling).
    size_t wire_length = 0;

    std::string summary;
    std::vector<std::string> notes;
};

// Returns this chunk's own declared total length (MessageSize, offset 4-7, little-endian) when the
// first 8 bytes structurally look like a UA-TCP header (see try_parse_opcua_message's "structural
// detection gate"), for TCP stream reassembly purposes -- mirrors hartip_declared_length/
// enip_declared_length. Returns std::nullopt when there aren't even 8 bytes, or the MessageType/
// ChunkType check fails.
std::optional<size_t> opcua_declared_length(ByteSpan payload);

// Attempts to interpret `payload` (TCP application-layer bytes) as one OPC UA UA-TCP/Secure
// Conversation message (one chunk). Returns std::nullopt (never throws) when there aren't even 8
// bytes for the header, when the leading 3 bytes aren't one of the 7 recognized MessageType
// strings, when ChunkType isn't 'F'/'C'/'A', or when MessageSize is implausibly small (< 8) -- see
// this file's header comment's "structural detection gate" paragraph. `redact` (default true, the
// same "safe by construction" default DecodeContext::redact_secrets/DecodeOptions::redact_secrets
// both use -- see decoder.hpp) governs whether an ActivateSessionRequest's own cleartext
// UserNameIdentityToken password is masked with a fixed placeholder or shown as its literal value
// -- see decode_activate_session_request_params's own comment (opcua.cpp).
std::optional<OpcUaMessage> try_parse_opcua_message(ByteSpan payload, bool redact = true);

// Migration batch 2 (see protocol_decoder.hpp/protocol_registry.hpp): everything decoder.cpp's
// OPC UA call site dual-writes into DecodedPacket, gathered from however many chunks were
// coalesced in one TCP payload (see OpcUaDecoder::decode below) -- mirrors exactly what the
// pre-migration call site computed locally. `summary`/`notes` are the fully-assembled headline
// summary and note list, in the same order the legacy call site produced them (every coalesced
// chunk contributes a note, but only the first chunk's own fields feed the rest of
// DecodedPacket); `first` is that first chunk's full OpcUaMessage, unmodified, since the legacy
// call site's per-field dual-write was already a straight field-by-field copy with no reduction
// of its own worth re-deriving here.
struct OpcUaResult {
    std::string summary;
    std::vector<std::string> notes;
    OpcUaMessage first;
};

// id() == "opcua", gate_kind() == TcpPortIndependent. Wraps try_parse_opcua_message plus the
// same-TCP-payload multi-chunk-coalescing loop that used to live directly in decoder.cpp's
// `if (want_opcua)` call site -- OPC UA is purely stateless (no fragment reassembly of its own;
// SecureConversation chunking is handled entirely within try_parse_opcua_message/wire_length), so
// unlike Dnp3Decoder/CotpDecoder there is no per-flow reassembly state here at all.
class OpcUaDecoder : public ProtocolDecoder {
public:
    std::string_view id() const override { return "opcua"; }
    GateKind gate_kind() const override { return GateKind::TcpPortIndependent; }
    std::optional<size_t> tcp_declared_length(ByteSpan candidate) const override {
        return opcua_declared_length(candidate);
    }
    std::optional<ProtocolResult> decode(ByteSpan payload, DecodeContext& ctx) const override;
};

const ProtocolDecoder& opcua_decoder();

}  // namespace conduitscope
