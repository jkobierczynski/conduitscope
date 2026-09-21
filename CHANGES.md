# conduitscope -- ICMP decoding, FF-HSE false-positive fix, generic-TCP-fallback cleanup

Drop this into your existing checkout (it overwrites the same relative
paths) and re-run `python3 tools/make_sample_pcap.py` followed by your usual
CMake configure/build/`ctest` -- everything below is already verified green
(1124/1124 tests) on this end, but re-running confirms it in your own tree.

## 1. Full ICMP decoding (your request)

`icmp.hpp`/`icmp.cpp` are new. ICMP traffic used to show up only as an
opaque `[non-tcp]  IPv4 protocol number 1 (ICMP) (not TCP)` line -- exactly
what you pasted from your real Windows capture. It now gets full field
decoding for the message types that matter for OT diagnostics and security
review:

- Echo Reply/Request (id, sequence, data length)
- Destination Unreachable -- all 16 codes named, plus the RFC 1191
  Next-Hop MTU field for the "Fragmentation Needed" case
- Redirect -- gateway address
- Time Exceeded, Parameter Problem
- Timestamp Request/Reply
- Address Mask Request/Reply
- Router Advertisement (RFC 1256) -- every address/preference pair

Destination Unreachable/Redirect/Time Exceeded/Parameter Problem messages
also get a one-line summary of the original datagram they're quoting (RFC
792 guarantees the IP header plus the first 8 bytes of payload -- enough to
recover TCP/UDP ports even without a full transport header). The checksum
is genuinely verified (RFC 1071), not just surfaced -- unlike IPv4's own
header checksum, which this project has never validated -- since a bad
checksum on a Redirect or Destination Unreachable is itself a real spoofing
signal on a flat OT network.

Try it: `conduitscope decode --protocol icmp -f json -r capture.pcap`, or
just run a normal `decode` and look for the `[icmp]` tag. New dedicated
fixture `tests/sample_icmp.pcap` (17 packets, every message type above plus
a checksum-mismatch case and the too-short-to-be-ICMP edge) and a matching
CTest suite (`icmp_*` -- 16 new tests) exercise it, plus a fuzzer seed drawn
from that same fixture and a 60s/4-worker ASan/UBSan smoke burst against
`fuzz_packet_decode` (0 crashes).

## 2. A real false-positive bug, found on your own capture

Your "this is definitely wrong" packet -- a UDP/443 QUIC/TLS response
misdetected as `[ffhse]  SM confirmed service 8` with a nonsensical
"truncated by 4 billion bytes" note -- was a genuine bug. FF-HSE's own
weakest structural gate (documented as such in this project's own docs) had
no upper bound on the header's declared Message Length field, so random
non-FF-HSE bytes that happened to match that gate could "detect" as FF-HSE
with an absurd length instead of being rejected. Fixed by applying FF-HSE's
existing 16 MiB plausibility ceiling (already used elsewhere for TCP-
reassembly bookkeeping) to its own detection gate too. A new regression
packet in `tests/sample_ffhse.pcap` mirrors your exact scenario (same port
pairing, an implausible declared length) and is now a permanent CTest case.
This narrows the exposure; it doesn't close FF-HSE's underlying weak-gate
problem, which is why FF-HSE is still dispatched last of every protocol in
Auto mode -- see `docs/DEVELOPMENT.md`.

## 3. The generic TCP fallback line, shortened (your request just now)

`[tcp]  TCP payload of N byte(s) on port X->Y did not match OPC UA,
EtherNet/IP, IEC 104, ... or the OpenVPN/STT tunnel-VPN family` is gone.
It's now just `[tcp]  TCP payload of N byte(s) on port X->Y`, matching the
already-terse `[udp]` fallback. Every protocol this decoder knows was
already tried by the time that line prints -- spelling the whole list out
on every single unmatched packet was noise, not information.

## 4. Two small things found along the way (real Windows/Npcap validation)

- `conduitscope version` reported a cosmetic double space
  (`Windows,  build`) on your MSVC build -- `CMAKE_BUILD_TYPE` is always
  empty for a multi-config CMake generator like Visual Studio (the actual
  configuration is picked at *build* time via `--config`, not configure
  time). Now reports `multi-config` instead of a blank. Your Linux build is
  unaffected (still reports `Release`).
- `tests/sample_link_transport_layers.pcap`'s "recognized-but-not-decoded"
  IP-protocol-number example packet used plain ICMP, which obviously no
  longer fits now that ICMP is fully decoded -- switched to ICMPv6
  (protocol 58, still named-only) so that test keeps testing what it was
  meant to test.
- While regenerating fixtures, found that `tools/make_sample_pcap.py`'s
  HART-IP Pass-Through fixture generator had always left its checksum byte
  at a placeholder `0x00` rather than computing the real value -- every
  Pass-Through packet in `tests/sample_hartip.pcap` was decoding with a
  checksum-mismatch note that the tests didn't actually check for (they
  passed anyway, since most of them don't assert on `notes`). Fixed the
  generator to compute the real longitudinal XOR checksum by default, same
  "compute the real value, allow an explicit override" convention this
  patch also uses for ICMP's own checksum in the new fixture.

## Files in this drop

```
CMakeLists.txt                                    -- new/updated tests throughout
README.md                                         -- Status section: new bullets
docs/PROTOCOL_COVERAGE.md                         -- new ICMP section, link-layer section updated
docs/USER_GUIDE.md                                -- new ICMP jq recipe
docs/DEVELOPMENT.md                               -- PROTOCOL DETECTION + ROADMAP item 1 updated
include/conduitscope/icmp.hpp                     -- new
src/icmp.cpp                                       -- new
include/conduitscope/decoder.hpp                  -- ICMP wired into dispatch/DecodedPacket
src/decoder.cpp                                    -- ICMP dispatch, generic TCP fallback shortened
src/cli_main.cpp                                   -- --protocol icmp
include/conduitscope/output.hpp                   -- icmp_type_counts_ stats member
src/output.cpp                                     -- ICMP color/JSON/stats output
include/conduitscope/ffhse.hpp                    -- structural-gate doc update
src/ffhse.cpp                                       -- the false-positive fix
include/conduitscope/version.hpp.in               -- multi-config build-type fix
tools/make_sample_pcap.py                          -- ICMP fixture builder, HART-IP checksum fix,
                                                       ICMPv6 swap in the link/transport fixture
tests/sample_icmp.pcap                             -- new
tests/sample_ffhse.pcap                            -- regenerated (new regression packet)
tests/sample_link_transport_layers.pcap            -- regenerated (ICMP -> ICMPv6 swap)
tests/sample_hartip.pcap                           -- regenerated (real checksums)
fuzz/corpus/packet_decode/*                        -- 2 new seeds (ICMP, link/transport fixtures)
```

Verified: full CTest suite 1124/1124 passing; 60s/4-worker ASan/UBSan
`fuzz_packet_decode` smoke burst, 0 crashes.

# Windows release CI hang -- root cause and fix

## What was actually happening

Not a "never-ending capture" -- the 4 stuck tests (`decode_modbus_sample`,
`decode_dnp3_sample`, `dnp3_no_user_data_stays_link_only`,
`dnp3_transport_and_read_class0_decoded`) are plain offline `decode --read
some.pcap` commands. They never touch a network interface or any pcap
function at all. (Every test that *does* open a live interface is gated
`if(UNIX)` in CMakeLists.txt, so on Windows there weren't even any of those
in the suite yet -- ruled that out early.)

Root cause: `conduitscope.exe` links against `wpcap.lib` (the Npcap SDK's
*build-time* import library) so it can call `pcap_*()` when live capture is
actually used. But the CI job only ever downloaded and extracted the Npcap
**SDK** zip -- it never installed the separate Npcap **runtime** (the
driver/service that provides the actual `wpcap.dll`). On Windows, a normal
(non-delay-loaded) DLL import is resolved by the OS loader before your
program's `main()` even runs -- so with `wpcap.dll` nowhere on the runner,
*every single invocation* of `conduitscope.exe` failed at process-load time,
including ones like `decode_modbus_sample` that never call a single pcap
function. Each `ctest` worker slot was just waiting on a process that could
never actually start; `--output-on-failure` had nothing to report because
nothing ever finished (or FAILED) in the normal sense.

This also would have been a real problem for actual users: anyone who
downloaded the released Windows binary just to run `conduitscope decode` on
a .pcap file, with no interest in live capture, would have needed to install
the full Npcap runtime first -- which the SDK-only build-time dependency
never should have required.

## The fix

1. **`CMakeLists.txt`**: on Windows/MSVC, link with `/DELAYLOAD:wpcap.dll`
   (+ `delayimp.lib`). This defers resolving `wpcap.dll` until the first
   actual `pcap_*()` call instead of at process startup, so the binary now
   starts and runs fine with zero Npcap runtime installed -- only
   `-i/--interface` and `conduitscope interfaces` need it.
2. **`src/live_capture.cpp`**: added `ensure_pcap_runtime_available()`,
   called at the top of `list_interfaces()` and the `LiveCapture`
   constructor (the only two real pcap entry points) on Windows. It does a
   `LoadLibraryA("wpcap.dll")` probe and throws the same kind of clear,
   actionable `CaptureError` this file already throws for "not built with
   pcap support" -- pointing the user at https://npcap.com/#download --
   instead of letting a missing-DLL delay-load failure surface as a raw,
   unfriendly structured exception deep inside `pcap_create`/
   `pcap_findalldevs`.
3. **`.github/workflows/ci.yml`**: added `--timeout 120` to the `ctest`
   invocation in `release-windows` as a safety net, independent of this
   specific root cause -- so any future genuine hang fails fast and loud
   instead of eating the whole job's time budget.
4. **`docs/USER_GUIDE.md`**: corrected the "Windows / Npcap notes" section,
   which previously (incorrectly) claimed a live-capture-enabled binary
   "still runs fine on a machine with no Npcap runtime installed at all" --
   that was aspirational, not yet true, until this fix. Updated to describe
   the actual delay-load mechanism.

## Verified

- Reconfigured and rebuilt clean on Linux (this fix is Windows-only code
  behind `#ifdef _WIN32`, but exercises the new no-op stub path on Linux).
- Full CTest suite: **1124/1124 passing**, including
  `live_capture_interfaces_command_lists_loopback` and friends.
- `.github/workflows/ci.yml`: valid YAML (`yaml.safe_load`) and clean
  `actionlint` (v1.7.12) run.

I can't run an actual `pwsh`/MSVC toolchain here to build-verify the
`/DELAYLOAD` linker flag itself -- that only gets a real check on your next
tag push. If it does fail to link (unlikely; `/DELAYLOAD` + `delayimp.lib`
is the standard, decades-old MSVC pattern for this), the error will be a
normal, clear linker error rather than another silent hang.

## Files in this drop

```
CMakeLists.txt                  -- /DELAYLOAD:wpcap.dll wiring (Windows/MSVC only)
src/live_capture.cpp            -- ensure_pcap_runtime_available() friendly-error check
.github/workflows/ci.yml        -- ctest --timeout 120 safety net
docs/USER_GUIDE.md              -- Windows/Npcap notes corrected
```
