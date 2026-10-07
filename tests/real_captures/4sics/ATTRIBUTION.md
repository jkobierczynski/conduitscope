# Provenance of these fixtures

Three real ICS/OT captures from the 4SICS Geek Lounge (the hands-on lab area of the 4SICS/
CS3STHLM industrial-security conference, Stockholm, 2015-10-20 to 2015-10-22), hosted by
Netresec at `https://www.netresec.com/network/pcap/4sics-geek-lounge/`. Netresec's own stated
terms for this release permit redistribution with attribution to CS3Sthlm -- per that
requirement: **these captures originate from the 4SICS/CS3Sthlm Geek Lounge network, made
available via Netresec.**

| File in this directory              | Source | Size | Packets | Capture span (UTC) |
|--------------------------------------|--------|------|---------|---------------------|
| `4SICS-GeekLounge-151020.pcap`       | Netresec 4SICS Geek Lounge release, day 1 | 25,711,082 bytes | 246,137 | 2015-10-20 15:10:34 -- 22:10:32 |
| `4SICS-GeekLounge-151021.pcap`       | Netresec 4SICS Geek Lounge release, day 2 | 139,998,821 bytes | 1,253,100 | 2015-10-20 22:10:32 -- 2015-10-21 22:10:34 |
| `4SICS-GeekLounge-151022.pcap`       | Netresec 4SICS Geek Lounge release, day 3 | 209,236,002 bytes | 2,274,747 | 2015-10-21 22:10:34 -- 2015-10-22 13:17:37 |

SHA-256:

```
8c6ee02dc26b1b5298a7c9b4dc83cc779bd2a3219d5c5cbc51e3d4d325763bc2  4SICS-GeekLounge-151020.pcap
7365b0ea475b76bf79b207fd8f83baa45e4449aead5da6a9214bbcffbc5fa7de  4SICS-GeekLounge-151021.pcap
82529c23906416dc73d7f1926a0d38b82527f1f2a7ff8c6f755ce3208feb9643  4SICS-GeekLounge-151022.pcap
```

This sandbox's own outbound network access could not reach `share.netresec.com` directly
(blocked by the environment's egress proxy policy, same category of restriction already noted in
`tests/real_captures/iec104/ATTRIBUTION.md`'s Industroyer2 entry); these three files were instead
downloaded through Jurgen's own linked desktop browser, from Netresec's PCAP4SICS landing page, and
staged into this sandbox from there.

## What this capture actually is

This is a TAP-mirrored network from the 4SICS conference's own "Geek Lounge" -- a real, physically
wired ICS lab set up for conference attendees to probe and attack, not a production OT network and
not a synthetic/hand-built fixture either. It contains real PLC and industrial-networking hardware
(a Koyo/DirectLogic 205 PLC, a Siemens SIMATIC S7-1200, a Beckhoff CX1010 PC-based controller, plus
Hirschmann/Moxa/Cisco/Westermo networking gear) generating genuine S7comm/COTP traffic against real
silicon, alongside a heavy, continuous background of IT noise and active scanning/fingerprinting
traffic from conference attendees testing the lab network throughout the three days -- exactly the
"mirrored-switch-port capture of a real network, including the IT noise a real OT perimeter
actually sees" validation this project's docs/DEVELOPMENT.md ROADMAP item 1 has been asking for
since before this project's own synthetic fixtures were written. It is explicitly NOT a production
OT network (a conference lab, generating only S7comm/COTP traffic against the real PLCs -- day 1's
own inventory finds zero other OT protocols active at all), so it validates this project's *parser
correctness and false-positive resistance against real wire bytes and real background noise*, not
production-scale protocol diversity or attack realism; see `tests/real_captures/iec104/
ATTRIBUTION.md`'s own Industroyer2 entry for this project's one capture that IS real attack
traffic, and contrast with that.

## Why these specific fixtures, and what they found

These were the first real, mirrored-switch-port-style captures brought in specifically against
docs/DEVELOPMENT.md's ROADMAP item 1 (every previously-validated real capture in `tests/
real_captures/` is either a small, protocol-specific test vector or a narrowly-scoped attack
sample -- see that ROADMAP item's own text). Running this project's `inventory` command against
all three files surfaced two real, previously-undetected decode-accuracy bugs that no synthetic
fixture had ever exercised, both now fixed (see docs/DEVELOPMENT.md's ROADMAP item 149 for the
full account):

- **A COTP/HTTP collision** (day 3 only): one ordinary HTTP response's binary (GIF) body happened
  to begin with the exact bytes `03 00 00 ff`, coincidentally clearing the TPKT/COTP opportunistic
  entry gate (`try_parse_tpkt_cotp`'s own loose check -- TPKT magic plus a declared length that
  merely fits inside the payload) before COTP's own internal length-indicator consistency check
  correctly rejected it as malformed -- but, before this fix, that rejection was a hard
  `ParseError` that killed this packet's entire decode cascade rather than letting the generic HTTP
  recognizer have its turn, as it otherwise would have.
- **A much larger MQTT/background-traffic collision** (day 2 and day 3 both): MQTT's own
  documented "HONESTLY WEAK" structural gate (`mqtt.hpp`'s file header -- only 30 of 256 possible
  leading bytes excluded) was badly over-triggering against this capture's genuine Nmap-style
  service-fingerprinting probe/response traffic, an HTTP OPTIONS request, a TLS ClientHello, an SMB
  Negotiate, a SIP OPTIONS message, and an LDAP BER-encoded message all happened, by sheer
  bad luck, to pass MQTT's gate. Before the fix, this misclassified 52 of 84 (62%) of day 2's own
  inventoried communication edges and 135 of 229 (59%) of day 3's as spurious "mqtt" traffic; after
  the fix, both captures show exactly zero `mqtt`-tagged packets (there is no genuine MQTT traffic
  anywhere in this lab network at all -- every single one of those matches was a false positive).

Day 1 (`4SICS-GeekLounge-151020.pcap`) is unaffected by either bug -- its own traffic is pure,
genuine S7comm/COTP session activity between the real PLCs, with no HTTP or MQTT-gate-colliding
traffic present at all -- and its `inventory` output is byte-for-byte identical before and after
the fix, confirming the fix doesn't touch traffic it has no business touching. Day 3 also still
carries 5 genuinely unrelated `parse-error` packets after the fix (truncated/malformed IP and TCP
headers -- Ethernet-padding trim edge cases and one impossibly-small TCP data-offset field,
nothing to do with COTP or MQTT), left completely unchanged by this round, confirming the fix is
narrowly scoped rather than papering over every parse failure in the capture.

## Validation posture, stated honestly

These are lab-network, not production-network, captures -- see "What this capture actually is"
above. They are also, as of this writing, the *only* real captures in this project's own test
suite large enough and noisy enough to have ever surfaced a false-positive opportunistic-dispatch
bug like either one above (every other real-capture fixture in `tests/real_captures/` is either
small and protocol-pure, or a narrowly-scoped attack sample with little IT-noise diversity). They
do not substitute for a genuine production OT network capture -- docs/DEVELOPMENT.md's ROADMAP
item 1 remains open for that reason -- but they are real evidence that this project's own
"opportunistic, port-independent dispatch" design (deliberately chosen for recall over precision --
see docs/DEVELOPMENT.md's PROTOCOL DETECTION section) needs exactly the kind of noisy, real-world
IT background traffic these captures provide to be tested against at all; a synthetic fixture,
built by the same author who wrote the decoder, essentially never contains a byte sequence its own
author didn't anticipate.
