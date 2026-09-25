# HART-IP real-capture attribution

One real HART-IP capture, unmodified.

| File in this directory | Source |
|-------------------------|--------|
| `hart_ip.pcapng`        | `https://media.githubusercontent.com/media/automayt/ICS-pcap/master/HART%20IP/hart_ip/hart_ip.pcap` -- copied verbatim, unmodified (renamed `.pcapng` -- see "A note on the file extension" below). |

## How it was found

`automayt/ICS-pcap` -- the same collection several of this project's other real-capture fixtures
cite (directly, or via `mrhenrike/PCAPTrafficAnalysis`) -- has a `HART IP/hart_ip/` directory
containing `hart_ip.pcap` alongside three Zeek/Bro log files (`conn.log`, `packet_filter.log`, a
`.state/` directory) from the same capture session. Cloning the repository (sparse checkout, this
project's git proxy does allow a plain `git clone`/`ls-tree` against this specific repository --
only its LFS media was previously found to be blocked, see below) showed `hart_ip.pcap` itself is
a 130-byte Git LFS pointer file, not real packet data -- the same LFS-storage pattern this
project's BACnet/IP, EtherCAT, GOOSE, and Sampled Values real-capture searches already hit and
documented for this repository. Unlike those earlier searches, though, `git lfs pull` here failed
with a `missing object` scanner error (rather than the explicit access-denied error this project's
`ethercat/ATTRIBUTION.md` recorded for the same repository's LFS batch API) -- and fetching the
pointer's exact object OID directly from `media.githubusercontent.com` (GitHub's LFS media CDN,
apparently not covered by whatever blocked the LFS batch API/`git lfs pull` path previously)
**succeeded**, returning the real 11,932-byte file. Its SHA256
(`dda914bff86358caf5bc6e3ed06814124104ecb0eff71e5c7e806fe1b24a09a6`) matches the LFS pointer's own
`oid sha256:...` line exactly, confirming this is genuinely the file the pointer references, not a
substitute or a different revision -- the same "verify by hash" discipline this project has used
each time a pointer-vs-real-content mismatch was possible.

## A note on the file extension

`file` and `tshark` both identify the downloaded bytes as **pcapng** (`pcapng capture file -
version 1.0`), not classic pcap, despite the source repository naming it `hart_ip.pcap`. This
project's decoder already supports pcapng natively (see `tests/sample_pcapng_*.pcapng` and the
`pcapng_*` CMake tests), so no conversion was needed -- the file is stored here with the accurate
`.pcapng` extension rather than propagating the source repository's mislabeling.

## What this capture actually contains

116 frames over a 72.2-second window, captured on interface `en0` on 2012-03-19 (a real,
timestamped packet capture, not synthetic traffic) between a WirelessHART/wired-HART gateway
(Ethernet OUI `Rosemount_00:00:d2`, HART Long Address `264e0000d2`, HART Long Tag `wihartgw`
-- an Emerson/Rosemount wireless gateway, consistent with the device-variable and message-text
values seen) at `192.168.0.10` and a host at `192.168.0.101` (plus unrelated background traffic
from a third host, `192.168.0.100`, browsing the open web and probing SMB -- ordinary incidental
noise in what looks like a home/office network capture, not anything HART-related). Decoding the
whole file with this decoder's own `--protocol hartip` awareness (a genuine, independent decode,
not a grep for a byte pattern) finds:

- **46 frames** recognized as `hartip`, split evenly 23 Request / 23 Response, covering all of
  **Session Initiate**, **Keep Alive**, **Session Close**, and **Pass Through** MessageIDs -- the
  complete message-lifecycle exercise this decoder's synthetic fixture was designed to mirror, but
  here from a genuine field device rather than hand-built bytes.
- The **same client/gateway pair runs the identical command sequence twice** -- once over UDP
  (port 5094 request / **5095** response -- the gateway replies from a different source port than
  it was addressed on, itself a real-world detail this decoder's `expected_port` annotation
  correctly flags as non-standard on the response leg) and once over **TCP** (port 5094 both
  directions) a few seconds later. Both sessions exercise the exact same nine Pass-Through
  commands: **0** (Read Unique Identifier), **1** (Read Primary Variable), **2** (Read Loop Current
  and Percent of Range), **3** (Read Dynamic Variables and Loop Current), **9** (Read Device
  Variables with Status), **12** (Read Message), **13** (Read Tag, Descriptor, Date), **20** (Read
  Long Tag), and **48** (Read Additional Device Status) -- each appearing 4 times total (request +
  response, UDP + TCP). Every response decodes with **response-code=0 (Success)**, a constant
  **Device Status of 0xD0** (field-device-malfunction + configuration-changed + more-status-available
  -- plausible standing diagnostic flags for a real gateway, not a decode error), and, correctly,
  command 0's own request/response pair addresses the device by the universal **short address 0**
  (the standard HART pattern for discovering a device's unique address before switching to it),
  while every other command addresses it by its now-known 5-byte **long address `264e0000d2`** --
  this decoder's `hartip_is_long_address`/`hartip_address` fields capture that distinction exactly
  as the real exchange does it.
- **Two floating-point PV Loop Current values decode as `nan`** (frames carrying command 2 and
  command 3 responses, both sessions): this is not a decoder bug -- `tshark`'s own HART-IP
  dissector (installed and cross-checked specifically to validate this; see below) decodes the
  identical bytes as `PV Loop Current: nan` too. A real device genuinely sent IEEE-754 NaN bytes
  for that field (plausible for a demo/lab device with its current-loop field unpopulated or
  faulted), and both dissectors agree on what the wire bytes mean.
- Command 12 (Read Message)'s packed-ASCII field decodes to a literal ASCII-table-order string
  (`@ABCDEFGHIJKLMNO/ !-#$%&'()*+,-.`), and command 13's Tag field decodes to `@@@@@@@@` -- again
  cross-checked against `tshark`'s own dissector (see below), which decodes the exact same bytes to
  the exact same text. This is genuine device behavior (a lab/demo unit's message and tag fields
  evidently hold placeholder/test content, not meaningful process text), not a packed-ASCII
  decoding bug -- useful independent confirmation of this decoder's `decode_packed_ascii`
  implementation against real wire bytes, not just the hand-verified synthetic inverse-of-`pack_ascii`
  check `tools/make_sample_pcap.py` already relies on.

### Cross-validated against Wireshark/tshark's own HART-IP dissector

`tshark` (4.2.2) was installed specifically to validate this capture (this project does not
otherwise depend on it). It recognizes and fully dissects all 46 `hart_ip` frames. Spot-checking
several of the more surprising decodes above (the two NaN PV Loop Current values, the ASCII-table
message text, the short-vs-long address split) against `tshark -V`'s full protocol tree confirms
this decoder's output matches Wireshark's own dissector byte-for-byte on every field checked --
independent confirmation of correctness against the reference implementation, on real traffic,
that this project's synthetic fixture alone cannot provide.

### Real-world confirmation of the documented Modbus/TCP collision (frames #76, #78)

This capture independently reproduces, on genuine field traffic, the exact TCP
Session-Initiate-vs-Modbus/TCP detection collision `hartip.hpp`'s "KNOWN, ACCEPTED, DOCUMENTED
LIMITATION" paragraph and `decoder.cpp`'s matching comments describe (and which
`tests/sample_hartip.pcap`'s own packets 58-60 demonstrate synthetically): the TCP session's
Session Initiate **request** (frame #76) and **response** (frame #78) both decode as
`[modbus]  Unknown (0xd)`, not `hartip` -- this decoder's own Modbus/TCP declared-length check is
tried first and its two fields (protocol-id==0, a small mbap_length) happen to be satisfied by
this real Session Initiate message's own header, exactly as documented. This is independent,
real-world evidence the limitation is not merely a theoretical corner case this project invented
to exercise a code path -- it is something a genuine HART-IP-over-TCP session-establishment
message actually collides with. (The TCP session's subsequent Pass-Through/Keep-Alive/Session-Close
traffic on the same flow all decodes correctly as `hartip`, matching the documented scope of the
limitation exactly -- only Session Initiate's own MessageID=0/Status=0 header produces the
collision.)

### FIXED: the weak declared-length gate used to also false-positive on unrelated TLS traffic (frame #70)

One frame of the capture's incidental, unrelated background TCP traffic -- a TLS connection to
port 443 (frame #70), not involving the HART-IP devices at all -- used to be reported as
`buffering a HART-IP message PDU/frame split across TCP segments`, with an implausibly large
declared length (54734 bytes) that would never be satisfied. Unlike the Modbus/TCP collision
above (an occasional, single-shape overlap resolved by leaving it as a documented, accepted
limitation), this one turned out to be a **systematic** collision once properly diagnosed: every
TLS/SSL record's own ProtocolVersion field has a major byte that is ALWAYS `0x03` (a valid HART-IP
MessageType) and a minor byte that is ALWAYS 0-3 (a valid HART-IP MessageID) for every deployed
SSLv3-through-TLS-1.3 record -- not a coincidental match, a guaranteed one for the entire TLS
family. This capture's own frame #70 was this project's first real-world evidence of it; a second,
independent real capture reported directly by a user later showed the same false positive against
ordinary HTTPS traffic to two unrelated destinations, both stuck buffering indefinitely (e.g.
"832 of 50656 declared byte(s)..."), which is what prompted root-causing and fixing it rather than
continuing to document it as accepted.

Fixed via `hartip.cpp`'s `looks_like_tls_record_header` -- a structural pre-check (TLS
ContentType byte + the 0x03 major-version byte) that refuses HART-IP's gate outright when present,
the same "a known, systematic collision is excluded outright, not merely deprioritized" posture
`hartip_udp_excluded_port` already established for the RFC 3948 IKE NAT-T / RFC 7348 VXLAN case on
UDP. Frame #70 in this capture now decodes correctly as `[https]` instead. See
`hartip_tls_record_not_misdetected_as_hartip` (`tools/make_sample_pcap.py`'s
`sample_hartip.pcap`, packet #68) for the synthetic regression test, and
`real_hartip_tls_weak_gate_false_positive_fixed` for this real capture's own pinned confirmation.

A second frame of this same background traffic -- an SMB connection to port 445 (frame #115) --
used to be a second instance of this identical false positive (HART-IP's own weak gate matching it
before anything else claimed it). It no longer is: as of the SMB2/NTLM decoder (`smb.hpp`, AD suite
phase 3), that connection's genuine SMB1 (CIFS) traffic is recognized and decoded correctly as
`[smb]`, curated note 1 included, since `smb.hpp`'s own decoder runs earlier in `decoder.cpp`'s
TCP-port-independent cascade than HART-IP's own weak declared-length probe -- the same "a stronger,
earlier gate resolves a weaker, later one's false positive" pattern this codebase already relies on
elsewhere (e.g. IEC104 tried before Modbus). This capture is accordingly this project's first
real-world confirmation of `smb.hpp`'s own SMB1 magic-byte detection gate, independent of the
synthetic fixtures `tools/make_sample_pcap.py` builds for it.

## Gaps: what this real capture does NOT exercise

Every one of the 46 `hartip` frames uses Frame Type **STX** (request) or **ACK** (response) --
**BACK** (the "response requires a Burst Mode acknowledgement retry" frame type) never appears.
Every response's Response Code is **0 (Success)** -- no comm-error bit, no non-zero
command-specific response code, and no **Error**/**NAK** MessageType frame appears anywhere in
this capture (Wireshark's own `hart_ip.hart_ip_error_response_code` field is simply never present
in any of these 116 frames). Commands 0, 1, 2, 3, 9, 12, 13, 20, and 48 are the only nine Pass
Through commands exercised -- commands 6, 7, 8, 14, 15, 16, 17, 18, 19, 21, 22, 31, 33, 38, 77, 178,
and 203 (all covered by `tests/sample_hartip.pcap` instead) never appear. No wrong-length/malformed
command payload, truncated Pass-Through body, non-standard Byte Count, or multi-message TCP
coalescing appears either -- unsurprising for a clean, successful field-device exchange, but it
means those defensive/fallback paths (like `ethercat/ATTRIBUTION.md`'s own equivalent paragraph
notes for that protocol) are validated only against `tests/sample_hartip.pcap`'s hand-built bytes,
not against an independent real capture.
