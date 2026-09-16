# Provenance of these fixtures

Four real IEC 61850-8-1 GOOSE captures, all sourced from the same public collection as the
PROFINET RT/DCP real fixtures (see the sibling `tests/real_captures/profinet/ATTRIBUTION.md`) --
`ITI/ICS-Security-Tools`'s own `pcaps/IEC61850/` directory attributes its contents further
upstream to `http://www.pcapr.net/browse?q=mms+%26+NOT+mmse+or+goose` (pcapr.net, a now-defunct
public pcap-sharing site).

| File in this directory                  | Source |
|------------------------------------------|--------|
| `goose_ge_f650_retransmissions.pcap`     | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/GOOSE/GOOSE.pcap` -- copied verbatim, unmodified. |
| `goose_demo_full_fields.pcap`            | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/GOOSE/GOOSE_DEMO.pcap` -- copied verbatim, unmodified. |
| `sample_file_goose.pcap`                 | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/Sample_File_GOOSE.pcap` -- copied verbatim, unmodified. |
| `sample_file_mms_and_goose.pcap`         | `https://raw.githubusercontent.com/ITI/ICS-Security-Tools/master/pcaps/IEC61850/Sample_File_MMS_and_GOOSE.pcap` -- copied verbatim, unmodified. |

`ITI/ICS-Security-Tools`'s IEC61850 pcaps directory listing isn't reachable through GitHub's
directory-browsing UI in the way `PROFINET-RT-DCP`'s was (see the PROFINET ATTRIBUTION.md) --
these four were found by cloning the repository directly (`git clone --filter=blob:none --sparse`)
and scanning every `.pcap` file under `pcaps/IEC61850/` for EtherType 0x88B8 frames (accounting
for a possible 802.1Q tag first, the same way `try_parse_goose`'s caller unwraps one). That same
scan also checked `mrhenrike/PCAPTrafficAnalysis` (the source of PROFINET's third mirrored
capture) and found no GOOSE-specific file there beyond what overlaps this same ITI collection.

## `goose_ge_f650_retransmissions.pcap` (1420 bytes, 8 frames, unmodified)

Eight real GOOSE frames from a GE F650 protection relay (`gocbRef` =
`GEDeviceF650/LLN0$GO$gcb01`), all one continuous retransmission sequence at `stNum=1` (no real
state change occurs in this short capture) with `sqNum` counting 10, 11, 12, then resetting to 1
through 5 (a publisher restart or GOOSE Control Block re-enable mid-capture, inferred from the
`sqNum` reset with `stNum` unchanged) -- exactly the monotonic-within-a-state-then-reset pattern
`stNum`/`sqNum` are supposed to follow (see goose.hpp's file header comment). This is the fixture
this decoder's own tag table was hand-verified against byte-by-byte before any Wireshark
cross-check was trusted at face value: a Python BER walker was written from scratch and run
against this capture's raw bytes, confirming the corrected 0x80-0x8A/0xAB top-level tag table
(several secondary/AI-summarized sources initially suggested 0xA0-0xAA, which is wrong for every
field except the genuinely-constructed `allData` -- see goose.cpp's `decode_ber_integer`/
`data_type_name` and the direct `packet-goose.c` source grep that corrected it), the `allData`
`boolean`(0x83)/`bit-string`(0x84) tags, and the BIT STRING unused-bit-count encoding (each
frame's dataset alternates a `boolean` with a 13-bit `bit-string` -- almost certainly a status
value and its IEC 61850-7-3 `quality` attribute).

## `goose_demo_full_fields.pcap` (166 bytes, 1 frame, unmodified)

One real frame, but a maximally useful one: 802.1Q priority-tagged (VLAN ID 10, priority 4 --
real GOOSE traffic's common framing, see goose.hpp's file header comment), multicast to
`01:0C:CD:01:00:01` (IEC 61850's well-known default GOOSE multicast MAC range), APPID `0x2000`,
and every single GOOSE PDU field present, including all three OPTIONAL ones (`goID`,
`simulation`, `ndsCom` -- every real frame across all four captures in this directory carries all
three; see the "gaps" section below for what that means for this decoder's optional-field-absence
coverage). Confirms `parse_ethernet`'s single-VLAN-tag unwrap composes correctly with
`try_parse_goose`'s detection, and that a 5-byte `timeAllowedtoLive`/`numDatSetEntries` INTEGER
encoding (this frame pads several fields to 5 bytes each rather than the minimal encoding) decodes
correctly -- multi-byte BER INTEGER support (`decode_ber_integer`, up to 8 bytes) exists
specifically because a single/double/four-byte-only reader would have mishandled this frame.

## `sample_file_goose.pcap` (117736 bytes, 451 frames, unmodified)

The bulk-validation fixture: 451 real GOOSE frames (three distinct APPIDs, `0x0001`/`0x2000`/
`0x3001`; every one 802.1Q priority-tagged) spanning what looks like two real substation
protection schemes (`gocbRef`s under `AA1C1Q01A1LD0`/`AA1C1Q05A1LD0`/`AA1C1Q07A1LD0`, all
publishing an `InterlockingA` dataset). All 451 decode with zero notes/warnings -- no truncation,
no malformed BER, no field-count mismatch. Every frame in this file uses only `boolean` and
`bit-string` `allData` values (a 2-bit and a 13-bit BIT STRING recur throughout -- almost
certainly double-point status values and their IEC 61850-7-3 quality attributes); see the "gaps"
section below for what this means for this decoder's real-capture coverage.

## `sample_file_mms_and_goose.pcap` (43379 bytes, 301 frames total, 34 GOOSE, unmodified)

A mixed capture -- MMS (client/server engineering-tool traffic over TPKT/COTP/session/
presentation, decoded by this tool only up to the COTP layer; full MMS decoding is out of scope,
see goose.hpp's file header comment's "explicitly out of scope" paragraph) alongside 34 real GOOSE
frames from the same `AA1C1Q0{1,5,7}A1LD0` protection scheme as `sample_file_goose.pcap` above,
at much higher `stNum`/`sqNum` values (a longer-running capture). Included specifically as a
crash-safety/non-interference check: decoding this file exercises `cotp`/`tcp`/`udp`/`non-tcp`/
`non-ip`/`goose` protocol classification all in the same pass, confirming GOOSE detection doesn't
misfire on any of the non-GOOSE traffic mixed in alongside it (and vice versa).

## Gaps: what these real captures do NOT exercise

Every real GOOSE frame found across all four files above happens to use the *same* narrow shape:
every field (including all three optional ones -- `goID`, `simulation`, `ndsCom`) is always
present, and every `allData` value is only ever `boolean` or `bit-string` (never `integer`/
`unsigned`/`floating-point`/`octet-string`/`visible-string`/`bcd`/`utc-time`, and never a nested
`array`/`structure`). So this decoder's optional-PDU-field-ABSENCE handling (spec-legal --
`goID`/`simulation`/`ndsCom` are all OPTIONAL per IEC 61850-8-1) is validated only against the
hand-built `tests/sample_goose.pcap`, never a real one. No real capture found anywhere (this
collection, `mrhenrike/PCAPTrafficAnalysis`, a search of `automayt/ICS-pcap` and the Wireshark
SampleCaptures wiki) contains a GSE Management PDU (outer APDU tag 0xA0), a header S-bit/
PDU-simulation mismatch, a frame with more than one APDU packed into its declared Length, or a
truncated/malformed frame. All of those paths -- and every `allData` type beyond boolean/
bit-string -- are validated only against `tests/sample_goose.pcap` (see `tools/
make_sample_pcap.py`'s `build_goose_sample`), cross-checked against Wireshark's `packet-goose.c`
source rather than an independent real capture. This mirrors the same honest gap already
documented for PROFINET RT's cyclic IO data and EtherNet/IP's CIP I/O implicit messaging.
