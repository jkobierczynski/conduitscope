# IEC 61850 MMS real-capture attribution

Four files: three genuine real-world historical captures, and one this project generated itself
by running an independent, real, open-source IEC 61850 stack (`libiec61850`) against itself --
kept and labeled separately from the other three, since "this decoder's own research" and "a
capture this decoder's own research found in the wild" are different kinds of evidence and this
file says so honestly rather than blurring them together.

| File in this directory | Source |
|---|---|
| `iec61850_read.pcap` | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/MMS%20-%20Specific%20Commands/iec61850_read.pcap` -- copied verbatim, unmodified. |
| `mms-takeControl.pcap` | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/MMS%20-%20Specific%20Commands/mms-takeControl.pcap` -- copied verbatim, unmodified. |
| `mms-cancelRequest.pcap` | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/MMS%20-%20Specific%20Commands/mms-cancelRequest.pcap` -- copied verbatim, unmodified. |
| `libiec61850_loopback_capture.pcap` | Self-generated (see "Independent-stack validation traffic" below) -- **not** a found-in-the-wild capture. |

SHA256, for anyone who wants to independently re-verify against the URLs above:

```
81ac83a1ec8a40914a8dab5e39d29b0862fb092e692b9a2a897bc51af11912bb  iec61850_read.pcap
54a4255c7674b7d22b246ebdb915291778f2834584f7720e1b3f6f4fbc178c68  mms-takeControl.pcap
db11493d82456b9ccec8e569ab79aa4e003b9ce31a9564b0250a86cd87740346  mms-cancelRequest.pcap
```

## How the three real captures were found

`ITI/ICS-Security-Tools` is a general ICS-security resource collection this project has already
used for real captures in earlier protocol additions (see e.g. `tests/real_captures/dnp3/
ATTRIBUTION.md` for the general notes on that source repository -- no explicit license accompanies
it; included here as real, non-sensitive protocol test vectors, on the same basis this project
already established). Its `pcaps/IEC61850/MMS - Specific Commands/` directory (found via a targeted
web search, since `api.github.com`/`codeload.github.com` remain blocked in this project's own
sandboxed environment but `raw.githubusercontent.com` is not -- the same access pattern every other
ATTRIBUTION.md in this project documents) contains exactly these three MMS-specific files plus a
fourth, `mms-takeRelease.pcap`-shaped sibling this search did not need. A fourth file at
`pcaps/IEC61850/m-send-req.mms.pcap` (directly under `IEC61850/`, not the `MMS - Specific Commands`
subdirectory) was also examined and **discarded**: despite its name, `tshark -q -z io,phs` shows it
is HTTP/MMSE traffic -- MMS here means Multimedia Messaging Service, the SMS-adjacent mobile
protocol, completely unrelated to IEC 61850 MMS. A filename match alone is not enough to trust a
source; this file is not included here for that reason.

## What each real capture actually contains

All three share the same loopback-traffic shape: `127.0.0.1` talking to itself on TCP port 102,
2008-11-26 (`libpcap`, microsecond resolution) -- almost certainly generated with an early, now
long-superseded open-source MMS/IEC 61850 stack's own client/server test programs, based on the
timestamps and the minimal, single-exchange-per-file shape. Decoding each with this decoder's own
`--protocol mms` finds:

- **`iec61850_read.pcap`** (20 frames) -- a **full association**: COTP Connection Request/Confirm,
  then a Session `CONNECT (CN)` SPDU carrying an ACSE `AARQ` (application-context-name
  `1.0.9506.2.3 (MMS)`, a `presentation-context-definition-list` this decoder decodes into
  `context 1 = 2.2.1.0.1 (ACSE)` / `context 3 = 1.0.9506.2.1 (mms-abstract-syntax-version1)`)
  wrapping an `initiate-RequestPDU` (full capability negotiation: `proposedVersionNumber=1`,
  `parameterCBB=[str1,str2,vnam,valt,vadr,tpy,vlis]`, and every one of the 78 confirmed services
  plus `unsolicitedStatus`/`informationReport`/`eventNotification`/`conclude`/`cancel` set in
  `servicesSupported`), a `read` `confirmed-RequestPDU`/`confirmed-ResponsePDU` pair (
  `variable=mu`, an empty `listOfAccessResult` -- genuinely zero-length on the wire, not a decode
  gap, hand-verified byte-for-byte), and a `conclude-RequestPDU`/response pair. **One frame (the
  server's own ACCEPT response, frame 10) is genuinely malformed** -- its own declared Session-layer
  length (137) does not match the 122 bytes actually remaining in the frame, hand-verified against
  the raw bytes, not a misunderstanding on this decoder's part (also independently flagged
  `[Malformed Packet]` by `tshark` 4.2.2 on the same frame) -- this decoder degrades gracefully
  (falls back to the generic `cotp` protocol label rather than guessing at the missing bytes),
  consistent with this project's established "never guess, degrade honestly" posture (the same one
  already documented for a different malformed real S7comm frame elsewhere in this project). A
  second frame (18, the response to `conclude-RequestPDU`) carries a `confirmed-ResponsePDU` whose
  own `confirmedServiceResponse` field is entirely missing after `invokeID` -- again hand-verified
  against the raw bytes (7 content bytes total: `02 01 00` is the whole PDU body), and again
  reported as a note (`confirmedServiceResponse field missing (malformed or truncated PDU)`) rather
  than guessed at.
- **`mms-takeControl.pcap`** (24 frames) and **`mms-cancelRequest.pcap`** (20 frames) are both
  **"bare MMS"** -- no Session/Presentation/ACSE at all, the COTP Data frame's own user data begins
  directly with an MMS PDU's own tag byte -- the real-world shape that motivated this decoder's own
  "Bare MMS" fallback path (see mms.hpp). `mms-takeControl.pcap` contains a bare
  `initiate-RequestPDU` followed by `takeControl`/`relinquishControl` `confirmed-RequestPDU`s (both
  Tier 2 -- named and invokeID-decoded, body shown as raw hex, per this decoder's own documented
  scope). `mms-cancelRequest.pcap` contains a bare `initiate-RequestPDU`, then a genuine
  `cancel-RequestPDU` (`invokeID=1`) and a genuine `conclude-RequestPDU` -- both **primitive**
  MMSpdu alternatives (`Cancel-RequestPDU ::= Unsigned32`, `Conclude-RequestPDU ::= NULL`), which
  is what caught a real bug in this decoder's own first-pass "Bare MMS" structural gate during this
  validation pass (see "A real bug this validation pass caught" below).

Both bare-MMS files also contain COTP Data frames whose own declared length indicator is `0`
(frames 10/14 in each) -- genuinely malformed per COTP's own framing rules (a Data PDU's length
indicator can never be legitimately zero -- it must cover at least the PDU-type byte), reported
honestly as `parse-error` by this decoder's own pre-existing COTP layer (`cotp.cpp`, unmodified by
this MMS work) -- confirmed to be a pre-existing characteristic of these capture files themselves,
not something this MMS work introduced, by reproducing the identical warning with
`--protocol s7comm` (which never touches any MMS code) against the same files.

## A real bug this validation pass caught

This decoder's first-pass "Bare MMS" structural detection gate (`looks_like_bare_mms_pdu`) required
the leading byte's constructed bit to be set, reasoning (correctly, but incompletely) that 11 of the
14 `MMSpdu` alternatives are `SEQUENCE`-typed and so constructed on the wire. The remaining 3 --
`cancel-RequestPDU`/`cancel-ResponsePDU` (`::= Unsigned32`) and `conclude-RequestPDU`/
`conclude-ResponsePDU` (`::= NULL`) -- are primitive, and `mms-cancelRequest.pcap`'s own genuine
`cancel-RequestPDU`/`conclude-RequestPDU` frames were silently missed by that first-pass gate
(falling back to the generic `cotp` label) until this validation pass caught it. Fixed by dropping
the constructed-bit requirement entirely (context-class, tag number 0-13 is sufficient -- there is
no primitive/constructed ambiguity risk, since every alternative's own shape is fixed by its type,
not chosen per-message).

A second, related bug this same validation pass caught: the Session-layer SPDU-walking loop's own
"is this byte a plausible SPDU type" check originally accepted any value below `0x80`. Real traffic
in `iec61850_read.pcap`'s own ongoing Data-Transfer frames turned out to send **two** concatenated
`SI=1/LI=0` ("Give Tokens" then "Data Transfer") pairs before the Presentation layer's own bytes
begin -- and the Presentation layer's own `fully-encoded-data` tag, `0x61` (97 decimal), is less
than `0x80` and was genuinely mistaken by that looser check for a third, bogus SPDU. Fixed by
tightening the bound to the real ISO 8327-1 range (1-64, `CLSES_UNIT_DATA(64)` being the highest
one-byte SPDU type the standard defines) -- both fixes, and this whole finding, informed directly by
real, byte-verified capture traffic, not theorized in the abstract.

## Independent-stack validation traffic: `libiec61850_loopback_capture.pcap`

This file is **not** a found-in-the-wild capture -- it was generated by this project itself,
building and running [`mz-automation/libiec61850`](https://github.com/mz-automation/libiec61850)
(commit `96d69e9c`, a real, independent, widely-used open-source IEC 61850 stack -- not code written
or influenced by this decoder in any way) entirely inside this project's own development
environment, and capturing the resulting loopback traffic with `tshark -i lo`. The server side ran
`examples/server_example_basic_io`'s own generic IO model; the client side ran four of
libiec61850's own bundled example client programs in sequence against it
(`iec61850_client_example1`, `client_example_control`, `iec61850_client_example_array`, and
`mms_utility` with `-i`/`-d`/`-t simpleIOGenericIO`), covering model browsing, reads, writes,
control operations, and periodic report generation.

The purpose of generating this traffic is distinct from either hand-built synthetic fixtures
(`tests/sample_mms.pcap`, this decoder's own crafted test vectors -- exhaustive but, by
construction, only as correct as this decoder's own understanding of the spec) or the three
found-in-the-wild captures above (real, but narrow in scope -- a handful of services each): running
a genuinely independent, real stack's own client and server against each other produces real wire
bytes this decoder had no hand in shaping, at a scale (224 frames, 101.8 seconds) and service
breadth no single found-in-the-wild capture in this search offered. Decoding it with
`--protocol mms` recognizes **117 of 224 frames** as `mms` (the rest are TCP handshake/ACK-only
segments and the loopback COTP Connection Request/Confirm, correctly reported as `tcp`/`cotp`) --
**zero parse warnings, zero parse errors, zero crashes** -- across a full association (`AARQ`/`AARE`,
8 of each), `read` (24 request/response pairs), `write` (13 pairs), `getNameList` (3 pairs),
`identify` (1 pair), `getVariableAccessAttributes` (4 pairs), and 17 `informationReport`s (periodic
Report Control Block traffic). One genuine `informationReport` (frame 24) decodes a real,
independently-encoded `Data` value of every kind this decoder implements in one message:
`mMSString` (`"Events1"`), `bit-string` (`bits[1,2,3,4,8]`), `integer`, `binary-time` (correctly
shown as raw hex -- this decoder's own documented scope does not implement `binary-time`'s BCD-like
encoding), a domain-qualified `visible-string` dataset reference
(`"simpleIOGenericIO/LLN0$Events"`), `boolean`s, and further `bit-string`s -- independent,
byte-for-byte confirmation that `decode_data_value`'s own understanding of the `Data` CHOICE (see
mms.hpp) matches a real, independent encoder's output, not only this decoder's own synthetic
fixture.

### A real robustness bug found in `tshark` itself during this validation

Cross-checking this same capture against `tshark` 4.2.2's own MMS dissector (`packet-mms.c`) for
ground truth turned up a genuine, independently-reproducible bug: `tshark` hits its own internal
`failed assertion "recursion_depth <= 100"` and aborts dissection entirely on roughly 43 of the 224
frames -- mostly the periodic `informationReport` frames, plus one `write` frame. This is
**not** attacker-controlled or malformed traffic -- it is ordinary, non-malicious output from a
real, well-behaved IEC 61850 stack -- and it is a concrete, observed instance of exactly the
denial-of-service surface this decoder's own `Data` value decoder defends against by design (a
hard-capped recursion depth on the `array`/`structure` alternatives, see mms.hpp's own "Recursion
depth cap" section, directly motivated by this finding). This decoder never hit that limit, and
never will on this traffic (its own cap is 32, well above anything this real stack's own nesting
ever produced) -- but the finding stands on its own as a reminder that unbounded recursion on a
self-describing, recursive value type is a real bug class other MMS parsers have actually shipped,
this codebase's own OPC UA-adjacent precedent (Wireshark Bug 3986, see
`tests/real_captures/opcua/ATTRIBUTION.md`) for the exact same class of finding in a sibling
protocol.
