# OPC UA real-capture attribution

One real OPC UA Binary (UA-TCP / Secure Conversation) capture, unmodified.

| File in this directory                          | Source |
|--------------------------------------------------|--------|
| `opc-ua-ap-method-wireshark-freeze.pcap`          | `https://raw.githubusercontent.com/w3h/icsmaster/master/pcap/opc/opc-ua-ap-method-wireshark-freeze.pcap` -- copied verbatim, unmodified. Independently cross-checked byte-for-byte (identical SHA256) against a second mirror, `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/OPC/opc-ua-ap-method-wireshark-freeze.pcap`. |

## How it was found

A `WebSearch` for OPC UA sample/pcap captures surfaced `w3h/icsmaster`'s `pcap/opc/` directory
(a general ICS-security resource collection, not OPC-UA-specific), listing a single file:
`opc-ua-ap-method-wireshark-freeze.pcap`. Its name alone was reason enough to track down the
original source before trusting it: a further search found it is **Wireshark Bug 3986**'s own
attachment (filed 2009-09-06, subject "some malformed OPC UA traffic causes wireshark to
'freeze'" -- `https://lists.wireshark.org/archives/wireshark-bugs/200909/msg00104.html`), meaning
this file has been a known, stable, widely-mirrored reference capture in the Wireshark/ICS-security
community for over 15 years, not an anonymous or unverifiable upload. `api.github.com` and
`codeload.github.com` remain blocked in this project's own sandboxed environment (see this
project's other ATTRIBUTION.md files for the same finding), and `bugs.wireshark.org` itself is
blocked by this environment's egress policy outright, so the original Bugzilla attachment could
not be fetched directly -- but `raw.githubusercontent.com` (unaffected, as in every other
real-capture search this project has done) served both independent mirrors above, and their
SHA256 hashes (`2a7bc18fc97829db65d04be564ef8db4d4e3950d0b0b07f77197449fbc9300de`) match exactly,
the same "verify by independent mirror" discipline this project falls back to whenever the
original hosting location itself isn't reachable.

## What this capture actually contains

90 frames over a 1.844-second window, captured 2009-09-01 (`libpcap`, microsecond resolution) --
**two back-to-back OPC UA sessions**, each a complete UA-TCP/Secure Conversation lifecycle: a TCP
client at `192.168.41.176` (ports 58674 and 58675, one per session) against an OPC UA server at
`192.168.41.212:12001` (a **non-standard, non-4840** TCP port -- see "Port-independent detection
confirmed on real traffic" below). Decoding the whole file with this decoder's own
`--protocol opcua` awareness (a genuine, independent decode, not a grep for a byte pattern) finds:

- **24 frames** recognized as `opcua` (the remaining 66 are ACK-only/handshake TCP segments with
  no application payload, correctly reported as generic `tcp`, or intermediate segments of a
  larger message still being reassembled -- see below), split across the two sessions as **Hello,
  Acknowledge, OpenSecureChannel Request/Response, GetEndpointsRequest/Response,
  CreateSessionRequest/Response, ActivateSessionRequest/Response, CallRequest, and Error** --
  between them, every Tier 1 service this decoder's own dispatch table covers except FindServers
  and CloseSession/CloseSecureChannel (this capture's own two sessions never call those; see
  opcua.hpp's own Tier-1/Tier-2 scope rationale) actually appears on the wire.
- The client identifies itself (`ApplicationUri`) as
  `uri://AchillesSatellite/Opc.Ua.ServerTestTool/55ea864a-2be8-4bc6-bb73-1123c54d0fc4` against a
  server endpoint named `StackTestServer` -- consistent with this file's own Wireshark-bug
  provenance: Achilles Satellite is a well-known ICS/OT robustness-and-fuzz-testing platform
  (Wurldtech, now GE/Baker Hughes), and this capture is exactly the kind of traffic that tool
  produces -- a conformance/fuzz test harness exercising an OPC UA reference stack, not production
  field traffic. Genuinely useful for this decoder's own stated purpose even so: real wire bytes
  from a real, independent OPC UA stack implementation, not hand-built fixtures.
- Both sessions open with `SecurityPolicyUri` **"http://opcfoundation.org/UA/SecurityPolicy#None"**
  -- this decoder's own "Security posture is visible even when the body is not" framing
  (opcua.hpp) applies literally here: this is a real capture of an OPC UA endpoint accepting no
  security at all, not a hypothetical.
- **GetEndpoints** returns 5 endpoints per session, spanning None/Basic128Rsa15/Basic256 security
  policies and None/Sign/SignAndEncrypt modes -- decoded identically to `tshark`'s own dissector
  (see below), confirming `read_endpoint_description`'s array-of-`EndpointDescription` handling
  against a real, independently-generated response rather than only this project's own synthetic
  fixture.
- **ActivateSession** in both sessions uses an **Anonymous** identity token (`PolicyId: "0"`) --
  no credential-exposure finding on this particular capture (this decoder's own
  UserName/Password-cleartext "SECURITY FINDING" logic is exercised on real bytes not by this
  capture but by its own synthetic fixture -- see `tests/sample_opcua.pcap`'s own packets 13-14 --
  since no real capture containing that specific identity-token shape happened to turn up in this
  search).
- Both sessions send exactly one **CallRequest**, and this decoder correctly leaves each at Tier 2
  (RequestHeader decoded, the rest shown as raw hex; see opcua.hpp's own Tier 2 scope -- Call needs
  the Variant/DataValue encoding this first-pass release does not implement). The two are strikingly
  different in size: the first session's is 5,224 bytes on the wire (a 5,165-byte body, reassembled
  from 4 TCP segments -- see "TCP reassembly" below), while the second session's is a mere 110 bytes
  (a 51-byte body, fitting in one segment). Per Wireshark Bug 3986's own report, it is specifically
  the SECOND (smaller) one that triggers the ~2-minute dissector freeze -- a small, malformed input
  causing a disproportionate hang is a classic algorithmic-complexity bug pattern, not something
  this file's own bulk suggested. The SERVER agrees both are malformed: neither session gets a
  CallResponse back -- both instead get an **Error** message -- `Bad (0x80020000)`
  (`BadInternalError`) for the first session, `Bad (0x80070000)` (`BadDecodingError`) for the
  second, both correctly decoded by this file's `decode_error`/`status_code_name` even though
  neither code happens to be one of this decoder's own first-pass ~20-entry named table (both fall
  back, correctly and honestly, to their decoded severity word plus raw hex -- exactly the "never
  guessed at" posture opcua.hpp's own "StatusCode decode" section documents). Because this decoder's
  own Tier 2 scope never attempts to
  parse CallRequest's own malformed body at all, it is structurally immune to whatever specific
  malformation caused Wireshark's C dissector to freeze for two minutes on the same bytes -- a
  small, real-world illustration of why this project's own "decode only what can be verified,
  raw-hex the rest" discipline is also a robustness property, not merely an honesty one.

### TCP reassembly exercised on real, multi-segment traffic

Both sessions' **GetEndpointsResponse** (7,008 bytes across 5 TCP segments) and
**CreateSessionResponse** (8,086 bytes across 6 TCP segments) are large enough to be split by the
sender across multiple TCP segments -- genuinely exercising `opcua_declared_length`'s own
TCP-stream reassembly (mirroring `hartip_declared_length`/`enip_declared_length`) against a real,
independently-generated multi-segment message, not only this project's own synthetic
`sample_opcua.pcap` coalescing fixture (which exercises the *opposite* direction -- multiple
complete messages coalesced into one segment, not one message split across several). The first
session's own CallRequest (5,224 bytes) is similarly reassembled across 4 segments before this
decoder discovers it is Tier 2. Every reassembly in this capture completes and decodes correctly;
none of the 66 `tcp`-reported frames are a reassembly this decoder gave up on -- they are ordinary
ACK-only segments carrying no application payload.

### Port-independent detection confirmed on real traffic

This capture uses TCP port **12001** for OPC UA, not the IANA-registered 4840 -- `tshark` (4.2.2,
installed specifically to validate this capture; this project does not otherwise depend on it)
does **not** recognize any of this traffic as OPC UA by default (`tshark -q -z io,phs` shows only
bare `tcp`/`data`), because its own OPC UA dissector chain is applied by default port only. This
decoder recognizes all 24 OPC UA frames without any `--opcua-port` hint at all, confirming on real,
independently-generated traffic (not merely by source-code inspection of the two protocols' own
detection gates) the port-independent design opcua.hpp's own "structural detection gate" paragraph
and decoder.cpp's own dispatch-order comment describe -- and, notably, doing so where Wireshark's
own *default* configuration does not (a real capture needing an explicit "Decode As" to be
recognized at all is exactly the class of traffic conduitscope's own auto-detection is meant to
catch without the analyst having to already suspect OPC UA and configure for it).

### Cross-validated against Wireshark/tshark's own OPC UA dissector

`tshark -d tcp.port==12001,opcua` (the "Decode As" step Bug 3986's own reproduction steps
describe) makes `tshark` recognize and dissect all 24 frames. Spot-checking several packets'
full protocol trees (`tshark -V`) against this decoder's own JSON output confirms an exact,
field-by-field match on every value checked: MessageType/ChunkType/MessageSize,
SecureChannelId/SecurityPolicyUri/SequenceNumber/RequestId, every service TypeId (446, 449, 428,
431, 461, 464, 467, 470, 712 -- this decoder's own `kServices` table entries for all of them match
Wireshark's own dissector's numeric IDs exactly), RequestHandle/Timestamp, the full
`EndpointDescription` array (URLs, SecurityMode, SecurityPolicyUri for all 5 endpoints),
`CreateSessionResponse`'s own `session-id=ns=10;i=365457`, `ActivateSessionRequest`'s own
`AnonymousIdentityToken` (`PolicyId: "0"`), and both sessions' own Error StatusCode values -- the
same "verify against the reference implementation's own dissector on real bytes" discipline this
project's HART-IP real-capture validation already established, now applied to OPC UA.
