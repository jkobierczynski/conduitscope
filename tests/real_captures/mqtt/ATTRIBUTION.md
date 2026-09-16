# MQTT real-capture attribution

Three real MQTT captures, unmodified, plus an honest account of a Sparkplug B search that came up
empty.

| File in this directory                  | Source |
|------------------------------------------|--------|
| `mqtt_packets_tcpdump.pcap`               | `https://raw.githubusercontent.com/pradeesi/MQTT-Wireshark-Capture/master/mqtt_packets_tcpdump.pcap` -- copied verbatim, unmodified. |
| `mqtt_packets.pcapng`                     | `https://raw.githubusercontent.com/pradeesi/MQTT-Wireshark-Capture/master/mqtt_packets.pcapng` -- copied verbatim, unmodified. |
| `mqtt_packets_RedHat61_tcpdump.pcap`      | `https://raw.githubusercontent.com/pradeesi/MQTT-Wireshark-Capture/master/mqtt_packets_RedHat61_tcpdump.pcap` -- copied verbatim, unmodified (genuinely corrupt -- see below). |

## How it was found

Unlike this project's other real-capture fixtures (mostly `automayt/ICS-pcap` and
`ITI/ICS-Security-Tools`, both squarely ICS/OT-protocol collections), those two repositories have
no MQTT captures at all -- MQTT is a general IIoT/web transport, not an ICS-specific one, so the
usual sources didn't apply here. Web search turned up `pradeesi/MQTT-Wireshark-Capture`
(github.com/pradeesi/MQTT-Wireshark-Capture), a small personal repo of MQTT captures made for a
blog post on reading MQTT traffic in Wireshark. It has four files: the three above (plain files,
fetched directly, no Git LFS involved) plus `mqtt_packets_Windows.cap`, which `file` identifies as
**NetXRay/Sniffer** format (`NetXRay capture file - version 002.001`), not pcap or pcapng -- this
decoder only reads pcap/pcapng (see `src/pcap_reader.cpp`), so that fourth file is out of scope and
was not copied here.

The Wireshark Wiki's own `SampleCaptures` page (wiki.wireshark.org/SampleCaptures) was also
checked directly and has no MQTT entries at all, confirming this isn't a case of missing an
obvious, better-known source.

## What these captures actually contain

19 frames over a 27.6-second window: a real Eclipse Paho ("blocking client") Python/C client
talking MQTT **3.1** (not 3.1.1!) to a broker at `198.41.30.241:1883` from `10.0.1.4`, across two
separate TCP connections (ports 49327 and 49330). `mqtt_packets_tcpdump.pcap` and
`mqtt_packets.pcapng` are two different container formats of the **exact same capture** -- this
decoder's own JSON output is byte-for-byte identical between the two, which is itself a small
independent regression check that this decoder's pcap and pcapng readers agree on real,
third-party-produced input (not just this project's own synthetic pcapng fixtures).

All 19 frames decode as `mqtt`, with **zero** "could not fully decode" or malformed-payload notes:

- Two full CONNECT/CONNACK handshakes (one per TCP connection), each a genuine **MQTT 3.1**
  CONNECT -- `ProtocolName="MQIsdp"`, `ProtocolLevel=3 (3.1)` -- the pre-OASIS Eclipse/IBM-era wire
  format that predates the "MQTT"/level-4 name OASIS standardized as 3.1.1. This decoder's CONNECT
  parser already handled `ProtocolLevel=3` correctly (it was written to per the MQTT 3.1 spec
  alongside 3.1.1/5.0, not added in response to this finding), and it's a good thing this capture
  exists: without a real MQTT 3.1 client in the validation set, this decoder's version-string
  labeling ("3.1" vs "3.1.1") and the bug fixed below would both have gone unexercised by anything
  but the synthetic fixture's own (necessarily self-consistent) encode/decode round trip.
- One SUBSCRIBE/SUBACK pair, three PUBLISH messages (topic `SampleTopic`, one with a human-readable
  payload -- `"Hello from the Paho blocking client"` -- confirming this is genuine client library
  traffic, not synthetic or fuzzed bytes), one coalesced PUBLISH+DISCONNECT in a single TCP segment
  (the second connection's client publishes and immediately disconnects, and the OS/client flushed
  both as one write -- this decoder's existing "additional MQTT packet found... coalesced by the
  sender/OS" handling, previously only exercised by this project's own synthetic Flow F, correctly
  recognizes it here too), and ten PINGREQ/PINGRESP keepalive exchanges.

## A genuine bug this validation found and fixed

The first pass through this capture (before any fix) showed the SUBACK on the first connection
resolving to **`SUBACK (MQTT 5.0)`** via the weakest-evidence heuristic, and the PUBLISH frames on
both connections carrying the "MQTT protocol version for this TCP session is not known (no CONNECT
seen on it in this capture)" note -- even though a CONNECT genuinely *was* seen on both sessions,
right there in frame 1 and frame 8.

The cause: `Decoder`'s per-session version-tracking map (`mqtt_session_version_` in
`decoder.hpp`/`decoder.cpp`) only ever learned a session's version from a CONNECT whose
`connect_discovered_version` was `4` (3.1.1) or `5` (5.0) -- see the `maybe_learn_version` lambda in
`decoder.cpp`'s MQTT dispatch block. A `ProtocolLevel=3` (MQTT 3.1) CONNECT -- like every CONNECT in
this real capture -- fell through that check entirely, so the session was never marked as known,
and every later SUBSCRIBE/SUBACK/UNSUBSCRIBE/PUBLISH on it fell back to the weaker per-packet
heuristic (or, for PUBLISH, to the "version not known" fallback) instead of using the CONNECT that
was actually right there. The synthetic fixture's own `build_mqtt_sample()` never exercises this
path because every CONNECT scenario it builds uses `ProtocolLevel` 4 or 5, never 3 -- exactly the
kind of gap real, independently-produced traffic is good at finding.

**The fix** (in `decoder.cpp`'s `maybe_learn_version` lambda): a CONNECT with `connect_discovered_version
== 3` is now tracked the same way as `== 4`. This is correct, not just a workaround -- MQTT 3.1 and
3.1.1's own wire shapes for SUBSCRIBE/SUBACK/UNSUBSCRIBE/PUBLISH are identical (the only wire-visible
difference between the two versions is the CONNECT packet's own Protocol Name/Level fields; neither
adds the unconditional Properties section that makes v5 different), so a session already known to be
"MQTT 3.1" is exactly as safe to decode with the "pre-v5 shape" assumption as one already known to be
"MQTT 3.1.1". After the fix, this capture's SUBACK correctly reports "MQTT 3.1.1" via session
tracking (CONNACK/SUBACK have no wire-visible way to distinguish 3.1 from 3.1.1, so "3.1.1" is used
as the generic non-v5 label there, same as for the synthetic fixture) and the "version not known"
note no longer appears on either PUBLISH. Re-running the entire synthetic fixture
(`tests/sample_mqtt.pcap`) after the fix showed no change in its own expected output, confirming the
fix is additive, not a regression.

## The RedHat61 file: genuinely corrupt, and this decoder is right to reject it

`mqtt_packets_RedHat61_tcpdump.pcap` is presumably meant to be the same capture as
`mqtt_packets_tcpdump.pcap`, taken on a RedHat 6.1 system instead (per its filename) -- but the file
itself is corrupt starting from the very first packet, not merely a different capture. Byte-for-byte
comparison against the (good) `mqtt_packets_tcpdump.pcap` shows that **8 extra `0x00` bytes are
spliced in immediately after every pcap record's own 16-byte header**, throughout the file: frame 1's
payload starts with 8 zero bytes it shouldn't have (which pushes its real Ethernet header — normally
`24:a2:e1:e6:ee:9b` \> `28:cf:e9:21:14:8f`, ethertype `0x0800` — 8 bytes later than the record's own
`incl_len`/`orig_len` account for, so the frame is read 8 bytes short at the end and its EtherType
field is misread), and the corruption compounds from there: frame 2's own 16-byte record header is
itself partially overwritten by more spliced-in zero bytes, so its `incl_len` field decodes as
`1461170590` (nonsensical -- it's actually reading frame 1's own *timestamp* digits, shifted into
the wrong field by the accumulated misalignment).

This decoder's pcap reader (`src/pcap_reader.cpp`, not MQTT-specific) correctly refuses to treat
that `1461170590`-byte `incl_len` as real: it hits the same `kMaxPlausibleCapturedLength`-style sanity
check this project has relied on before for other corrupt/truncated files, and raises a clear
`'<path>' reports an implausible captured length (...) -- the file is likely truncated or corrupt`
error rather than trying to read a gigabyte of nonexistent packet data or silently producing
garbage. Frame 1 itself doesn't decode as MQTT either (the corruption starts immediately, not on
frame 2) -- this decoder correctly reports it as `[non-ip] Ethernet frame with ethertype 0xee9b (not
IPv4)`, which is the honest, correct reading of those specific (corrupted) bytes.

This is treated as a genuine finding, not swept under the rug: the file is kept in this directory
exactly as downloaded, and `real_mqtt_redhat61_corrupt_file_reports_clear_error` (see
`CMakeLists.txt`) asserts this decoder's own error message stays exactly this clear if the pcap
reader's behavior ever changes. Whether the corruption originates from the capturing RedHat 6.1
tcpdump/libpcap itself (there are known historical alignment/padding quirks in that era) or from
however the file was later transferred/stored is not something this project can determine from the
bytes alone, and no attempt was made to "fix" or reconstruct the file -- doing so would defeat the
point of an unmodified real-capture fixture.

## Sparkplug B: no real capture found

This project searched specifically for a real Sparkplug B capture (protobuf-encoded MQTT payloads
under the `spBv1.0/...` topic namespace) to validate `src/mqtt.cpp`'s hand-rolled protobuf decoder
against genuine Eclipse Tahu/Ignition/Chariot traffic, not just this project's own synthetic
fixture. None was found: the usual ICS pcap collections (`automayt/ICS-pcap`,
`ITI/ICS-Security-Tools`) predate Sparkplug B's popularity and have no IIoT/MQTT material at all;
web search for public Sparkplug B `.pcap` files, Eclipse Tahu's own repository, and the Wireshark
Sample Captures wiki all came up empty. Sparkplug B decoding therefore remains validated only
against this project's own synthetic, hand-built protobuf fixture (`tests/sample_mqtt.pcap`'s Flow
C/C5 -- see `tools/make_sample_pcap.py`'s `sparkplug_metric`/`sparkplug_payload` helpers) --
a regression test for this decoder's own encode/decode round trip, not independent validation. If a
real Sparkplug B capture becomes available later, it should be added here and this section updated
accordingly, the same way this project has handled every other protocol where independent traffic
was eventually found after an earlier empty search.
